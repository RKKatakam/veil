//! Maintenance of the object store (`docs/design/scale/4-background-cleanup-streaming.md`)
//! and how gc coexists with lock-free transactions.
//!
//! **The gc lease.** gc and maintenance on a lock-free repository (format
//! ≥ 6, opened as a project) do not take `.veil/lock`, which writers
//! never take either: they take `.veil/gc.lock` ([`GcLease`]), so only
//! one runs at a time. Elsewhere (format ≤ 5, remotes) gc keeps
//! `.veil/lock` for its whole run, as their transactions hold it.
//!
//! **The deletion fence (BUG-811).** A lock-free transaction references
//! objects nothing names yet: what it staged and has renamed into the store
//! but not named by an op head, what it found already present and reused,
//! and its base view. gc's inventory and marking run beside it, so
//! everything gc *deletes* is deleted under a fence:
//! * every lock-free transaction registers itself
//!   (`objects/incoming/live-<owner>`, [`Registration`]) before it reads
//!   the heads, and stays registered until it has published its operation
//!   or given up (opening and reloading a repository register too, while
//!   they read the op log);
//! * gc raises `.veil/local/gc/fence` (`Fence`) only once no live
//!   transaction is registered, then reads its roots again and marks what
//!   they reach before it deletes anything; a transaction that meets a
//!   raised fence waits for it to be lowered before it registers.
//!
//! * with the fence raised and no transaction registered, gc also takes
//!   `.veil/lock`: writers that take it instead of registering (a push
//!   over SSH into a bare repository collected with `vl -R <hub> gc`, any
//!   transaction over a network backend) are then finished or not
//!   started either (BUG-814). If it is held for long, nothing is
//!   deleted that run.
//!
//! The two sides write first and read second (registration, then fence;
//! fence, then registrations), so whichever order they run in, one sees
//! the other. A transaction is therefore either finished before the
//! deletion step (its operation is a head, read by the second marking) or
//! starts after it (the objects it finds are the ones that survived). What
//! a transaction carries from before it started (an id from an older view)
//! is checked at commit (`Transaction::commit`). A registration or fence
//! whose owner is provably gone ([`crate::lock::owner_gone`]) is ignored.

use std::{cell::Cell, sync::Arc, time::Duration};

use crate::{
    error::{Result, VeilError},
    id::ObjectId,
    lock::{owner_gone, LockContext, Owner},
    store::ObjectStore,
    vfs::{NodeKind, StorageBackend},
    vpath::VPath,
};

/// The prefix of a live transaction's registration under
/// `objects/incoming/` (a directory, so that registering costs one
/// `mkdir` and nothing to sync).
pub const LIVE_PREFIX: &str = "live-";

/// gc's device-local files: the fence, the prune epoch (a random token
/// written under the fence whenever gc deleted something) and when the
/// last prune completed.
const FENCE_FILE: &str = ".veil/local/gc/fence";
const EPOCH_FILE: &str = ".veil/local/gc/epoch";
const LAST_PRUNE_FILE: &str = ".veil/local/gc/last-prune";

fn local(path: &str) -> VPath {
    VPath::new(path).expect("static path")
}

/// The gc lease (relative to the repository root).
pub const GC_LEASE_PATH: &str = ".veil/gc.lock";

/// How long a transaction waits for gc to lower its fence.
#[cfg(feature = "os")]
const FENCE_WAIT: Duration = Duration::from_secs(600);
/// How long gc waits for a moment with no live transaction before it
/// raises its fence anyway (new transactions then wait for it).
#[cfg(feature = "os")]
const QUIET_WAIT: Duration = Duration::from_secs(5);
/// How long gc waits, fence raised, for the transactions still running to
/// finish. After that it lowers the fence and deletes nothing this run.
#[cfg(feature = "os")]
const DRAIN_WAIT: Duration = Duration::from_secs(60);

thread_local! {
    /// Registrations held by this thread: a gc running on a thread that
    /// holds a transaction cannot wait for it.
    static HELD: Cell<usize> = const { Cell::new(0) };
}

fn incoming(store: &ObjectStore) -> VPath {
    store.root().join("incoming")
}

fn fence_path(_store: &ObjectStore) -> VPath {
    local(FENCE_FILE)
}

#[cfg(feature = "os")]
fn pause(backoff: &mut Duration) {
    std::thread::sleep(*backoff);
    *backoff = (*backoff * 2).min(Duration::from_millis(100));
}

/// The owner of a raised fence, unless there is none or its owner is
/// provably gone. Without an operating system (WASM) nothing runs beside
/// gc, so a fence is never waited for.
fn fence_owner(store: &ObjectStore) -> Result<Option<String>> {
    if cfg!(not(feature = "os")) {
        return Ok(None);
    }
    let Some(raw) = store.backend().read_opt(&fence_path(store))? else { return Ok(None) };
    let tag = String::from_utf8_lossy(&raw).trim().to_string();
    Ok((!owner_gone(&tag, &LockContext::default())).then_some(tag))
}

/// gc's prune epoch on `store` ([`EPOCH_FILE`]), `None` before any.
pub(crate) fn prune_epoch(store: &ObjectStore) -> Result<Option<Vec<u8>>> {
    store.backend().read_opt(&local(EPOCH_FILE))
}

/// Mark that gc deleted objects (under the fence).
pub(crate) fn bump_prune_epoch(store: &ObjectStore) -> Result<()> {
    let token = hex::encode(crate::crypto::random_bytes::<16>());
    store.backend().write(&local(EPOCH_FILE), token.as_bytes())
}

/// A live lock-free transaction, as gc sees it: see the module docs.
#[derive(Debug)]
pub struct Registration {
    backend: Arc<dyn StorageBackend>,
    dir: VPath,
    owner: Owner,
}

impl Registration {
    /// Register a new transaction on `store`, waiting while gc's fence is
    /// raised.
    pub(crate) fn enter(store: &ObjectStore) -> Result<Registration> {
        let owner = Owner::new();
        let backend = store.backend().clone();
        let dir = incoming(store).join(&format!("{LIVE_PREFIX}{}", owner.tag()));
        // A transaction this thread already holds (a merge started by a
        // transaction's reload) keeps the deletion step out already, and a
        // gc waiting for it would wait for us.
        let nested = HELD.with(|h| h.get()) > 0;
        #[cfg(feature = "os")]
        let started = crate::clock::monotonic();
        #[cfg(feature = "os")]
        let mut backoff = Duration::from_millis(1);
        loop {
            backend.create_dir_all(&dir)?;
            if nested {
                break;
            }
            let Some(_gc) = fence_owner(store)? else { break };
            backend.remove_dir_all(&dir)?;
            #[cfg(feature = "os")]
            {
                if crate::clock::monotonic().saturating_sub(started) >= FENCE_WAIT {
                    return Err(VeilError::Locked(format!(
                        "`vl gc` has been deleting objects for {} minutes ({} is still there); run the command again",
                        FENCE_WAIT.as_secs() / 60,
                        fence_path(store)
                    )));
                }
                pause(&mut backoff);
            }
        }
        HELD.with(|h| h.set(h.get() + 1));
        Ok(Registration { backend, dir, owner })
    }

    /// The owner tag (also naming the transaction's staging directory).
    pub(crate) fn tag(&self) -> &str {
        self.owner.tag()
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        let _ = self.backend.remove_dir_all(&self.dir);
        HELD.with(|h| h.set(h.get().saturating_sub(1)));
    }
}

/// The registrations of live transactions on `store` (owner tags).
#[cfg(feature = "os")]
fn live(store: &ObjectStore, ctx: &LockContext) -> Result<Vec<String>> {
    let entries = match store.backend().list_dir(&incoming(store)) {
        Ok(e) => e,
        Err(e) if e.is_not_found() => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    Ok(entries
        .into_iter()
        .filter(|e| e.kind == NodeKind::Dir)
        .filter_map(|e| e.name.strip_prefix(LIVE_PREFIX).map(str::to_string))
        .filter(|tag| !owner_gone(tag, ctx))
        .collect())
}

/// Remove the registrations whose owner is provably gone (a transaction
/// killed before it unregistered). Returns how many.
pub fn sweep_registrations(store: &ObjectStore, ctx: &LockContext) -> Result<usize> {
    let entries = match store.backend().list_dir(&incoming(store)) {
        Ok(e) => e,
        Err(e) if e.is_not_found() => return Ok(0),
        Err(e) => return Err(e),
    };
    let mut n = 0;
    for e in entries.into_iter().filter(|e| e.kind == NodeKind::Dir) {
        if e.name.strip_prefix(LIVE_PREFIX).is_some_and(|tag| owner_gone(tag, ctx)) {
            store.backend().remove_dir_all(&incoming(store).join(&e.name))?;
            n += 1;
        }
    }
    Ok(n)
}

/// gc's fence, raised: no lock-free transaction runs while it is held.
/// Lowered on drop.
#[derive(Debug)]
pub(crate) struct Fence {
    backend: Arc<dyn StorageBackend>,
    path: VPath,
    _owner: Owner,
    /// `.veil/lock`, for the writers that take it instead of registering.
    lock: Option<crate::lock::RepoLock>,
}

impl Drop for Fence {
    fn drop(&mut self) {
        let _ = self.backend.remove_file(&self.path);
    }
}

/// Why gc could not raise its fence (and so deletes nothing this run).
pub(crate) const FENCE_REFUSED_SELF: &str =
    "this thread holds a transaction, so gc cannot wait for it to finish";

/// Raise the fence once no lock-free transaction is running ([`drain`]),
/// then take `.veil/lock` (BUG-814: writers that do not register take it
/// for their whole transaction). `Err(why)` if either did not happen in
/// time (the fence is lowered again).
pub(crate) fn raise_fence(store: &ObjectStore) -> Result<std::result::Result<Fence, String>> {
    let mut fence = match drain(store)? {
        Ok(f) => f,
        Err(why) => return Ok(Err(why)),
    };
    match crate::lock::RepoLock::acquire(store.backend().clone()) {
        Ok(l) => fence.lock = Some(l),
        Err(VeilError::Locked(_)) => {
            return Ok(Err(
                "another command held the repository lock (`.veil/lock`), so nothing was deleted; run `vl gc` again".into(),
            ))
        }
        Err(e) => return Err(e),
    }
    Ok(Ok(fence))
}

/// Raise the fence once no lock-free transaction is running: wait up to
/// [`QUIET_WAIT`] for a moment with none, then raise it anyway and wait up
/// to [`DRAIN_WAIT`] for those still running. `Err(why)` if they did not
/// finish (the fence is lowered again).
fn drain(store: &ObjectStore) -> Result<std::result::Result<Fence, String>> {
    if HELD.with(|h| h.get()) > 0 {
        return Ok(Err(FENCE_REFUSED_SELF.into()));
    }
    #[cfg(feature = "os")]
    {
        let ctx = LockContext::default();
        let started = crate::clock::monotonic();
        let mut backoff = Duration::from_millis(1);
        while crate::clock::monotonic().saturating_sub(started) < QUIET_WAIT {
            if live(store, &ctx)?.is_empty() {
                let fence = raise(store)?;
                if live(store, &ctx)?.is_empty() {
                    return Ok(Ok(fence));
                }
                drop(fence);
            }
            pause(&mut backoff);
        }
        let fence = raise(store)?;
        let started = crate::clock::monotonic();
        loop {
            let running = live(store, &ctx)?;
            if running.is_empty() {
                return Ok(Ok(fence));
            }
            if crate::clock::monotonic().saturating_sub(started) >= DRAIN_WAIT {
                return Ok(Err(format!(
                    "{} other command(s) kept running for {} s, so nothing was deleted; run `vl gc` again",
                    running.len(),
                    (QUIET_WAIT + DRAIN_WAIT).as_secs()
                )));
            }
            pause(&mut backoff);
        }
    }
    #[cfg(not(feature = "os"))]
    Ok(Ok(raise(store)?))
}

/// Write the fence file, naming a fresh [`Owner`] that the returned
/// [`Fence`] keeps alive.
fn raise(store: &ObjectStore) -> Result<Fence> {
    let owner = Owner::new();
    let path = fence_path(store);
    store.backend().write(&path, owner.tag().as_bytes())?;
    Ok(Fence {
        backend: store.backend().clone(),
        path,
        _owner: owner,
        lock: None,
    })
}

// ---- the gc lease -------------------------------------------------------------

/// The gc lease: one gc or maintenance run at a time on a lock-free
/// repository, without taking `.veil/lock` (so writers never wait for
/// it). On a local disk it is an `flock` on [`GC_LEASE_PATH`], released by
/// the kernel when its holder dies, so it is never stale. Elsewhere
/// (memory, tests) it is held within this process only, which is all that
/// can reach such a store.
#[derive(Debug)]
pub struct GcLease {
    #[cfg(all(feature = "os", unix))]
    _file: Option<std::fs::File>,
    key: Option<usize>,
}

fn in_process_leases() -> std::sync::MutexGuard<'static, std::collections::BTreeSet<usize>> {
    static HELD: std::sync::Mutex<std::collections::BTreeSet<usize>> = std::sync::Mutex::new(std::collections::BTreeSet::new());
    HELD.lock().unwrap_or_else(|e| e.into_inner())
}

/// How long `vl gc` waits for another gc's lease.
#[cfg(feature = "os")]
const LEASE_WAIT: Duration = Duration::from_secs(15);

impl GcLease {
    /// Take the lease of the repository on `backend`. With `wait`, wait up
    /// 15 seconds for another holder; `Ok(None)` if it is held.
    pub fn acquire(backend: &Arc<dyn StorageBackend>, wait: bool) -> Result<Option<GcLease>> {
        #[cfg(all(feature = "os", unix))]
        if let Some(os) = backend.local_path(&VPath::new(GC_LEASE_PATH)?) {
            return Self::flock(&os, wait);
        }
        let key = Arc::as_ptr(backend) as *const () as usize;
        let take = || {
            // Lazily: a lease built and dropped would release the holder's.
            in_process_leases().insert(key).then(|| GcLease {
                #[cfg(all(feature = "os", unix))]
                _file: None,
                key: Some(key),
            })
        };
        #[cfg(feature = "os")]
        {
            let started = crate::clock::monotonic();
            let mut backoff = Duration::from_millis(1);
            loop {
                if let Some(l) = take() {
                    return Ok(Some(l));
                }
                if !wait || crate::clock::monotonic().saturating_sub(started) >= LEASE_WAIT {
                    return Ok(None);
                }
                pause(&mut backoff);
            }
        }
        #[cfg(not(feature = "os"))]
        {
            // One thread: a held lease cannot be released while we wait.
            let _ = wait;
            Ok(take())
        }
    }

    /// The lease as an `flock` on `os` (see [`GcLease`]).
    #[cfg(all(feature = "os", unix))]
    fn flock(os: &std::path::Path, wait: bool) -> Result<Option<GcLease>> {
        use std::os::unix::io::AsRawFd;
        let io = |e: std::io::Error| VeilError::Io {
            path: os.display().to_string(),
            source: e,
        };
        let file = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(os).map_err(io)?;
        let started = crate::clock::monotonic();
        let mut backoff = Duration::from_millis(1);
        loop {
            // SAFETY: a valid descriptor we own; `flock` only takes a lock.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                return Ok(Some(GcLease { _file: Some(file), key: None }));
            }
            let e = std::io::Error::last_os_error();
            match e.kind() {
                std::io::ErrorKind::Interrupted => continue,
                std::io::ErrorKind::WouldBlock => {}
                _ => return Err(io(e)),
            }
            if !wait || crate::clock::monotonic().saturating_sub(started) >= LEASE_WAIT {
                return Ok(None);
            }
            pause(&mut backoff);
        }
    }
}

impl Drop for GcLease {
    fn drop(&mut self) {
        if let Some(k) = self.key {
            in_process_leases().remove(&k);
        }
    }
}

/// What a gc run holds for its whole run: the gc lease on a lock-free
/// repository, `.veil/lock` elsewhere (their transactions take it).
#[derive(Debug)]
#[allow(dead_code)] // held for what dropping it releases
pub(crate) enum GcHold {
    Lease(GcLease),
    Lock(Box<crate::lock::RepoLock>),
}

impl GcHold {
    /// Take what `repo` needs ([`GcHold`]); with `wait`, wait for another
    /// holder as `vl gc` does, else `Ok(None)` if it is held.
    pub(crate) fn take(repo: &crate::repo::Repo, wait: bool) -> Result<Option<GcHold>> {
        if repo.lock_free() {
            return Ok(GcLease::acquire(&repo.backend, wait)?.map(GcHold::Lease));
        }
        match crate::lock::RepoLock::acquire(repo.backend.clone()) {
            Ok(l) => Ok(Some(GcHold::Lock(Box::new(l)))),
            Err(VeilError::Locked(_)) if !wait => Ok(None),
            Err(e) => Err(e),
        }
    }
}

// ---- consolidation and geometric merging -------------------------------------------

/// What [`consolidate`] or [`merge_packs`] did.
#[derive(Debug, Default)]
pub(crate) struct Packed {
    /// Loose objects packed (or removed as already packed).
    pub objects: usize,
    /// Packs merged.
    pub merged: usize,
    pub packs: Vec<String>,
    pub stats: crate::pack::PackStats,
}

/// How old a loose object must be before `vl gc --auto` packs it.
pub const CONSOLIDATE_AFTER: Duration = Duration::from_secs(10 * 60);

const HINT_DIR: u8 = 0;
const HINT_FILE: u8 = 1;

/// Pack every loose object last written at least `min_age` ago into one
/// new pack (reachable or not: pruning decides that), then remove the
/// loose copies, **in this order**: the pack (fsynced, renamed, its
/// directory fsynced), its index written durably, and only then each
/// loose file (threat 1 of the design). Loose objects already in a pack
/// are only removed. Successive versions of a path, found by walking the
/// new snapshots' new trees, are delta candidates (the newest stored
/// whole). Those in `apart` (what a prune just found unreachable) go into
/// a pack of their own, which a later prune drops whole.
pub(crate) fn consolidate(
    store: &ObjectStore,
    min_age: Duration,
    level: i32,
    deltas: bool,
    apart: &std::collections::HashSet<ObjectId>,
) -> Result<Packed> {
    let backend = store.backend().clone();
    let packs = store.packs()?;
    let mut loose = store.list_loose()?;
    loose.sort();
    loose.dedup();
    if !min_age.is_zero() {
        // Ages on the backend's own clock (nanoseconds on disk); a store
        // whose stamps are not times (memory) packs everything.
        if let Some(clock) = backend.stat_clock().filter(|c| !c.exact) {
            let cutoff = clock.now.saturating_sub(min_age.as_nanos() as i64);
            loose.retain(|id| {
                backend.metadata(&store.loose_path(id)).ok().flatten().and_then(|m| m.mtime).is_some_and(|t| t <= cutoff)
            });
        }
    }
    if loose.is_empty() {
        return Ok(Packed::default());
    }
    let (already, fresh): (Vec<ObjectId>, Vec<ObjectId>) = loose.into_iter().partition(|id| packs.iter().any(|p| p.contains(id)));
    let mut out = crate::gc::GcPacks::new(level, &*backend, store.pack_dir());
    if deltas {
        let set: std::collections::HashSet<ObjectId> = fresh.iter().filter(|id| !apart.contains(id)).copied().collect();
        for ids in path_hints(store, &fresh, &set)?.values() {
            let mut prev: Option<(ObjectId, Vec<u8>)> = None;
            for id in ids {
                if out.contains(id) {
                    continue;
                }
                let raw = match store.read_raw(id) {
                    Ok(r) => r,
                    Err(VeilError::Missing(_)) => continue,
                    Err(e) => return Err(e),
                };
                let base = match &prev {
                    Some((b, r)) if out.current_has(b) => Some((b, r.as_slice())),
                    _ => None,
                };
                out.add(*id, &raw, base)?;
                prev = Some((*id, raw));
            }
        }
    }
    let mut done = Vec::with_capacity(fresh.len());
    let mut garbage = crate::gc::GcPacks::new(level, &*backend, store.pack_dir());
    for id in fresh {
        if !out.contains(&id) {
            let to = if apart.contains(&id) { &mut garbage } else { &mut out };
            match store.read_raw(&id) {
                Ok(raw) => to.add(id, &raw, None)?,
                Err(VeilError::Missing(_)) => continue,
                Err(e) => return Err(e),
            }
        }
        done.push(id);
    }
    let (mut names, mut stats) = out.finish()?;
    let (more, s) = garbage.finish()?;
    names.extend(more);
    stats.objects += s.objects;
    stats.stored += s.stored;
    stats.compressed += s.compressed;
    stats.deltas += s.deltas;
    stats.raw_bytes += s.raw_bytes;
    stats.pack_bytes += s.pack_bytes;
    // Durable now: the loose copies can go.
    for id in done.iter().chain(&already) {
        backend.remove_file(&store.loose_path(id))?;
    }
    Ok(Packed {
        objects: done.len() + already.len(),
        merged: 0,
        packs: names,
        stats,
    })
}

/// Paths of the loose objects, from the loose snapshots' trees (only the
/// trees that are themselves loose are entered): `(kind, path)` → ids,
/// newest snapshot first.
fn path_hints(
    store: &ObjectStore,
    loose: &[ObjectId],
    set: &std::collections::HashSet<ObjectId>,
) -> Result<std::collections::BTreeMap<(u8, String), Vec<ObjectId>>> {
    use crate::object::{EntryKind, Object};
    let backend = store.backend();
    let mut snaps = Vec::new();
    for id in loose {
        let path = store.loose_path(id);
        let Some(len) = backend.metadata(&path)?.map(|m| m.len) else { continue };
        let head = match backend.read_range(&path, 0, len.min(16) as usize) {
            Ok(h) => h,
            Err(e) if e.is_not_found() => continue,
            Err(e) => return Err(e),
        };
        if Object::is_snapshot_raw(&head) {
            if let Ok(s) = store.snapshot(id) {
                snaps.push((s.timestamp, *id, s.tree));
            }
        }
    }
    snaps.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    let mut hints: std::collections::BTreeMap<(u8, String), Vec<ObjectId>> = Default::default();
    let mut walked = std::collections::HashSet::new();
    for (_, _, tree) in snaps {
        let mut stack = vec![(tree, String::new())];
        while let Some((id, path)) = stack.pop() {
            if !set.contains(&id) || !walked.insert(id) {
                continue;
            }
            hints.entry((HINT_DIR, path.clone())).or_default().push(id);
            let Ok(t) = store.tree_object(&id) else { continue };
            for e in &t.entries {
                let sub = match path.is_empty() {
                    true => e.name.clone(),
                    false => format!("{path}/{}", e.name),
                };
                match e.kind {
                    EntryKind::Dir => stack.push((e.id, sub)),
                    _ => {
                        for f in std::iter::once(e.id).chain(e.fallback) {
                            if set.contains(&f) && walked.insert(f) {
                                hints.entry((HINT_FILE, sub.clone())).or_default().push(f);
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(hints)
}

/// Where geometric merging splits packs sorted by size (ascending):
/// everything before the result is merged, so that each remaining pack is
/// at least twice the size of the next smaller one, the merged one
/// included (Git's `repack --geometric=2`). The largest pack is merged
/// only if it is less than twice the size of all the others together.
pub fn geometric_split(sizes: &[u64]) -> usize {
    let n = sizes.len();
    if n < 2 {
        return 0;
    }
    let mut i = n - 1;
    while i > 0 && sizes[i] >= sizes[i - 1].saturating_mul(2) {
        i -= 1;
    }
    let mut split = if i > 0 { i + 1 } else { 0 };
    let mut total: u64 = sizes[..split].iter().sum();
    while split < n && sizes[split] < total.saturating_mul(2) {
        total += sizes[split];
        split += 1;
    }
    split
}

/// Merge the smallest packs into one ([`geometric_split`]), copying every
/// entry as stored (no new deltas), then remove the merged packs (index
/// first): the big old pack is never rewritten unless it is no longer
/// big. The new pack and its index are durable before anything goes.
pub(crate) fn merge_packs(store: &ObjectStore, level: i32) -> Result<Packed> {
    let mut packs = store.packs()?;
    packs.sort_by_key(|p| (p.disk_size(), p.name().to_string()));
    let sizes: Vec<u64> = packs.iter().map(|p| p.disk_size()).collect();
    let split = geometric_split(&sizes);
    if split < 2 {
        return Ok(Packed::default());
    }
    let backend = store.backend().clone();
    let mut out = crate::gc::GcPacks::new(level, &*backend, store.pack_dir());
    let none = std::collections::HashSet::new();
    for p in &packs[..split] {
        for id in p.ids_in_pack_order() {
            crate::gc::copy_entry(store, p, &id, &mut out, &none)?;
        }
    }
    let (names, stats) = out.finish()?;
    for p in &packs[..split] {
        if names.iter().any(|n| n == p.name()) {
            continue;
        }
        backend.remove_file(&crate::pack::index_file(&store.pack_dir(), p.name()))?;
        backend.remove_file(&crate::pack::pack_file(&store.pack_dir(), p.name()))?;
    }
    Ok(Packed {
        objects: 0,
        merged: split,
        packs: names,
        stats,
    })
}

// ---- crash debris -------------------------------------------------------------

/// How old a temp file without an owner must be before it is removed.
const OWNERLESS_TEMP_AGE: Duration = Duration::from_secs(24 * 3600);

/// Remove what crashed writers left in the object store, never a live
/// owner's: stream temp files (`.stream-<owner>.vltmp…`, BUG-800) whose
/// owner is provably gone, and owner-less temp files (an interrupted
/// atomic write, or a stream of an older vl) not touched for a day, in
/// `pack/`, `incoming/` and the loose fan-out directories; the staging
/// directories, pull spools and registrations of dead transactions.
/// Returns how many were removed.
pub fn sweep_debris(store: &ObjectStore) -> Result<usize> {
    let ctx = LockContext::default();
    let mut n = store.sweep_staging(&ctx)? + sweep_registrations(store, &ctx)?;
    let backend = store.backend();
    let clock = backend.stat_clock().filter(|c| !c.exact);
    let mut dirs = vec![store.pack_dir(), incoming(store)];
    match backend.list_dir(store.root()) {
        Ok(entries) => dirs.extend(
            entries
                .into_iter()
                .filter(|e| e.kind == NodeKind::Dir && e.name.len() == 2 && e.name.bytes().all(|b| b.is_ascii_hexdigit()))
                .map(|e| store.root().join(&e.name)),
        ),
        Err(e) if e.is_not_found() => {}
        Err(e) => return Err(e),
    }
    dirs.push(VPath::new(PUSH_JOURNALS)?);
    for dir in dirs {
        n += remove_temps(&**backend, &dir, &ctx, clock.as_ref().map(|c| c.now))?;
    }
    Ok(n)
}

/// Where pushes keep their journals (device-local).
const PUSH_JOURNALS: &str = ".veil/local/push";

/// Remove the temp files in `dir` that a dead writer left: those naming
/// an owner that is provably gone, and (when `now` is a time on the
/// backend's stat clock) owner-less ones not touched for a day.
fn remove_temps(backend: &dyn StorageBackend, dir: &VPath, ctx: &LockContext, now: Option<i64>) -> Result<usize> {
    let entries = match backend.list_dir(dir) {
        Ok(e) => e,
        Err(e) if e.is_not_found() => return Ok(0),
        Err(e) => return Err(e),
    };
    let mut n = 0;
    for e in entries.into_iter().filter(|e| e.kind == NodeKind::File && crate::vfs::is_temp_name(&e.name)) {
        let path = dir.join(&e.name);
        let stale = match crate::vfs::temp_owner(&e.name) {
            Some(tag) => owner_gone(tag, ctx),
            None => now.is_some_and(|now| {
                backend
                    .metadata(&path)
                    .ok()
                    .flatten()
                    .and_then(|m| m.mtime)
                    .is_some_and(|t| now.saturating_sub(t) > OWNERLESS_TEMP_AGE.as_nanos() as i64)
            }),
        };
        if stale {
            backend.remove_file(&path)?;
            n += 1;
        }
    }
    Ok(n)
}

/// Remove the stream temp files in `dir` whose writer is provably gone
/// (owner-less ones are left to [`sweep_debris`]).
pub(crate) fn remove_dead_temps(backend: &dyn StorageBackend, dir: &VPath) -> Result<usize> {
    remove_temps(backend, dir, &LockContext::default(), None)
}

// ---- background maintenance ---------------------------------------------------------

/// `vl gc --auto` runs when more loose objects than this exist (Git's
/// `gc.auto`)…
pub const AUTO_LOOSE: usize = 6_700;
/// …or more packs than this…
pub const AUTO_PACKS: usize = 50;
/// …or this long has passed since the last prune, which `--auto` then
/// runs too…
pub const AUTO_PRUNE_AFTER: Duration = Duration::from_secs(7 * 24 * 3600);
/// …as it does when the operations since the last prune rewrote more
/// snapshots than this.
pub const AUTO_PRUNE_REWRITES: usize = 10_000;

/// When the last prune completed (ms since the epoch), if known.
pub fn last_prune(store: &ObjectStore) -> Option<i64> {
    let raw = store.backend().read_opt(&local(LAST_PRUNE_FILE)).ok()??;
    String::from_utf8_lossy(&raw).trim().parse().ok()
}

pub(crate) fn record_prune(store: &ObjectStore, now: i64) -> Result<()> {
    store.backend().write(&local(LAST_PRUNE_FILE), now.to_string().as_bytes())
}

/// The loose objects in the store, estimated from 16 of the 256 fan-out
/// directories (`00`–`0f`), so that every command can afford the check.
fn estimate_loose(store: &ObjectStore) -> Result<usize> {
    let mut n = 0;
    for i in 0..16u8 {
        match store.backend().list_dir(&store.root().join(&format!("{i:02x}"))) {
            Ok(e) => n += e.iter().filter(|e| e.kind == NodeKind::File && e.name.len() == 62).count(),
            Err(e) if e.is_not_found() => {}
            Err(e) => return Err(e),
        }
    }
    Ok(n * 16)
}

/// Why background maintenance is due on `repo`, if it is: too many loose
/// objects or packs, or no prune for [`AUTO_PRUNE_AFTER`] since the last
/// one (a repository never pruned waits for one of the others). Cheap: 17
/// directory listings and one small file, writing nothing. The rewrite
/// estimate ([`AUTO_PRUNE_REWRITES`]) needs the op log, so `vl gc --auto`
/// checks it itself; rewriting that much leaves more loose objects than
/// [`AUTO_LOOSE`] anyway. Only lock-free repositories (format ≥ 6, local)
/// are maintained in the background.
pub fn auto_due(repo: &crate::repo::Repo, now: i64) -> Result<Option<String>> {
    if !repo.lock_free() {
        return Ok(None);
    }
    let store = &repo.store;
    let loose = estimate_loose(store)?;
    if loose > AUTO_LOOSE {
        return Ok(Some(format!("about {loose} loose objects")));
    }
    let packs = match store.backend().list_dir(&store.pack_dir()) {
        Ok(e) => e.iter().filter(|e| crate::pack::name_from_index_file(&e.name).is_some()).count(),
        Err(e) if e.is_not_found() => 0,
        Err(e) => return Err(e),
    };
    if packs > AUTO_PACKS {
        return Ok(Some(format!("{packs} packs")));
    }
    match last_prune(store) {
        Some(t) if now.saturating_sub(t) > AUTO_PRUNE_AFTER.as_millis() as i64 => Ok(Some("no prune for a week".into())),
        _ => Ok(None),
    }
}

/// Snapshots rewritten by the operations since the last prune (format 6's
/// `Operation::rewritten`).
fn rewrites_since(repo: &crate::repo::Repo, since: i64) -> Result<usize> {
    let mut n = 0;
    let dir = VPath::new(".veil/ops")?;
    let entries = match repo.backend.list_dir(&dir) {
        Ok(e) => e,
        Err(e) if e.is_not_found() => return Ok(0),
        Err(e) => return Err(e),
    };
    for e in entries {
        let Ok(id) = crate::id::ObjectId::from_hex(&e.name) else { continue };
        if let Some(op) = repo.ops.try_get(&id)? {
            if op.timestamp > since {
                n += op.rewritten.len();
            }
        }
    }
    Ok(n)
}

/// What `vl gc --auto` did: `None` if another gc holds the lease.
#[derive(Debug)]
pub struct AutoReport {
    /// Whether the prune estimate was reached (and pruning ran).
    pub pruned: bool,
    pub gc: crate::gc::GcReport,
}

/// `vl gc --auto`: under the gc lease, without waiting for it, pack loose
/// objects older than [`CONSOLIDATE_AFTER`] and merge packs, and prune
/// (with the default grace period, keeping the whole op log) when the
/// estimate is reached: [`AUTO_PRUNE_AFTER`] since the last prune, or
/// [`AUTO_PRUNE_REWRITES`] snapshots rewritten since. Only lock-free
/// repositories.
pub fn auto(repo: &mut crate::repo::Repo, now: i64) -> Result<Option<AutoReport>> {
    if !repo.lock_free() {
        return Ok(None);
    }
    let Some(_lease) = GcHold::take(repo, false)? else { return Ok(None) };
    let pruned = match last_prune(&repo.store) {
        Some(t) => now.saturating_sub(t) > AUTO_PRUNE_AFTER.as_millis() as i64 || rewrites_since(repo, t)? > AUTO_PRUNE_REWRITES,
        None => rewrites_since(repo, i64::MIN)? > AUTO_PRUNE_REWRITES,
    };
    let opts = crate::gc::GcOptions {
        now: Some(now),
        ..Default::default()
    };
    let gc = crate::gc::run(repo, &opts, pruned, CONSOLIDATE_AFTER)?;
    Ok(Some(AutoReport { pruned, gc }))
}
