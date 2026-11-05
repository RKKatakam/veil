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
//!   or given up;
//! * gc raises `objects/gc/fence` ([`Fence`]) only once no live
//!   transaction is registered, then reads its roots again and marks what
//!   they reach before it deletes anything; a transaction that meets a
//!   raised fence waits for it to be lowered before it registers.
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
    lock::{owner_gone, LockContext, Owner},
    store::ObjectStore,
    vfs::{NodeKind, StorageBackend},
    vpath::VPath,
};

/// The prefix of a live transaction's registration under
/// `objects/incoming/` (a directory, so that registering costs one
/// `mkdir` and nothing to sync).
pub const LIVE_PREFIX: &str = "live-";

/// The fence file, under the object store's `gc/` directory.
const FENCE_FILE: &str = "fence";
/// gc's prune epoch, under `gc/`: a random token written under the fence
/// whenever gc deleted something.
const EPOCH_FILE: &str = "epoch";

/// The gc lease (relative to the repository root).
pub const GC_LEASE_PATH: &str = ".veil/gc.lock";

/// How long a transaction waits for gc to lower its fence.
const FENCE_WAIT: Duration = Duration::from_secs(600);
/// How long gc waits for a moment with no live transaction before it
/// raises its fence anyway (new transactions then wait for it).
const QUIET_WAIT: Duration = Duration::from_secs(5);
/// How long gc waits, fence raised, for the transactions still running to
/// finish. After that it lowers the fence and deletes nothing this run.
const DRAIN_WAIT: Duration = Duration::from_secs(60);

thread_local! {
    /// Registrations held by this thread: a gc running on a thread that
    /// holds a transaction cannot wait for it.
    static HELD: Cell<usize> = const { Cell::new(0) };
}

fn incoming(store: &ObjectStore) -> VPath {
    store.root().join("incoming")
}

fn fence_path(store: &ObjectStore) -> VPath {
    store.gc_dir().join(FENCE_FILE)
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
    store.backend().read_opt(&store.gc_dir().join(EPOCH_FILE))
}

/// Mark that gc deleted objects (under the fence).
pub(crate) fn bump_prune_epoch(store: &ObjectStore) -> Result<()> {
    let token = hex::encode(crate::crypto::random_bytes::<16>());
    store.backend().write(&store.gc_dir().join(EPOCH_FILE), token.as_bytes())
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
}

impl Drop for Fence {
    fn drop(&mut self) {
        let _ = self.backend.remove_file(&self.path);
    }
}

/// Why gc could not raise its fence (and so deletes nothing this run).
pub(crate) const FENCE_REFUSED_SELF: &str =
    "this thread holds a transaction, so gc cannot wait for it to finish";

/// Raise the fence once no lock-free transaction is running: wait up to
/// [`QUIET_WAIT`] for a moment with none, then raise it anyway and wait up
/// to [`DRAIN_WAIT`] for those still running. `Err(why)` if they did not
/// finish (the fence is lowered again).
pub(crate) fn raise_fence(store: &ObjectStore) -> Result<std::result::Result<Fence, String>> {
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
const LEASE_WAIT: Duration = Duration::from_secs(15);

impl GcLease {
    /// Take the lease of the repository on `backend`. With `wait`, wait up
    /// to [`LEASE_WAIT`] for another holder; `Ok(None)` if it is held.
    pub fn acquire(backend: &Arc<dyn StorageBackend>, wait: bool) -> Result<Option<GcLease>> {
        let path = VPath::new(GC_LEASE_PATH)?;
        #[cfg(feature = "os")]
        let started = crate::clock::monotonic();
        #[cfg(feature = "os")]
        let mut backoff = Duration::from_millis(1);
        #[cfg(all(feature = "os", unix))]
        if let Some(os) = backend.local_path(&path) {
            use std::os::unix::io::AsRawFd;
            let io = |e: std::io::Error| VeilError::Io {
                path: os.display().to_string(),
                source: e,
            };
            let file = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(&os).map_err(io)?;
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
        let key = Arc::as_ptr(backend) as *const () as usize;
        loop {
            if in_process_leases().insert(key) {
                return Ok(Some(GcLease {
                    #[cfg(all(feature = "os", unix))]
                    _file: None,
                    key: Some(key),
                }));
            }
            #[cfg(feature = "os")]
            if wait && crate::clock::monotonic().saturating_sub(started) < LEASE_WAIT {
                pause(&mut backoff);
                continue;
            }
            return Ok(None);
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
    Lock(crate::lock::RepoLock),
}

impl GcHold {
    /// Take what `repo` needs ([`GcHold`]); with `wait`, wait for another
    /// holder as `vl gc` does, else `Ok(None)` if it is held.
    pub(crate) fn take(repo: &crate::repo::Repo, wait: bool) -> Result<Option<GcHold>> {
        if repo.lock_free() {
            return Ok(GcLease::acquire(&repo.backend, wait)?.map(GcHold::Lease));
        }
        match crate::lock::RepoLock::acquire(repo.backend.clone()) {
            Ok(l) => Ok(Some(GcHold::Lock(l))),
            Err(VeilError::Locked(_)) if !wait => Ok(None),
            Err(e) => Err(e),
        }
    }
}
