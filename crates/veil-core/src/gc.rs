//! Garbage collection: op-log pruning and reachability. `vl gc` prunes
//! (here), then packs loose objects and merges small packs
//! ([`crate::maintenance`]).
//!
//! gc holds the gc lease on a lock-free repository and `.veil/lock`
//! elsewhere (format ≤ 5, remotes), for its whole run
//! (`maintenance::GcHold`). Pruning:
//!
//! 1. **Inventory**, strictly before marking: every pack index and the
//!    loose listing. Each copy of an object has a *position* (pack by
//!    pack in index order, then the sorted loose ids), found by a binary
//!    search of each pack's ids and of the loose list; nothing is copied
//!    into one big set. Objects written later are outside the inventory
//!    and never touched.
//! 2. **Operations to retain** (`keep_ops`): those inside the window,
//!    plus every head file's operation and its parents (so `vl undo`
//!    always works). The others are pruned.
//! 3. **Mark into a bitmap**, one bit per position (objects outside the
//!    inventory in a small set of their own), from the views of every
//!    retained operation, the universal root, the project directory's
//!    checkout pointer, keep markers and `extra_roots`: snapshot →
//!    parents, attempts and tree; tree → entries, and a subtree already marked is
//!    not entered again; file entry → object.
//!    Snapshot `predecessors` (the evolution log) are weak references.
//!    Memory is the bitmap, the walk stack, the packs' index tables and
//!    the store's cache limits, never the objects' content.
//! 4. **Grace period.** An unreachable object is first recorded in
//!    `objects/gc/pending` with when gc first saw it unreachable; a later
//!    run deletes it once it stayed unreachable for `grace`. Any process
//!    that touches a pending object (see [`crate::store`]) writes a keep
//!    marker `objects/gc/keep/<id>` and makes sure there is a loose copy.
//!    Markers are roots for the next run, and gc re-checks the marker
//!    *after* deleting each loose object, restoring it if one appeared.
//! 5. **Packed garbage** goes by rewriting the packs where deletable
//!    garbage is more than [`REWRITE_SHARE`] of the bytes (any share with
//!    grace 0, or in a pack of at most [`REWRITE_SMALL`]): their other
//!    entries are copied as stored into a new pack, and a delta whose base
//!    goes is stored whole. Other packs (the big old one) are left as they
//!    are, and their garbage stays pending.
//! 6. **Deletion under the fence** (lock-free repositories, BUG-811): no
//!    transaction runs while gc deletes; the roots are read and marked
//!    again first, and what became reachable survives
//!    ([`crate::maintenance`]).
//!
//! If any part of the graph cannot be read (a missing or undecryptable
//! snapshot or tree, an unreadable operation), gc deletes nothing and
//! says why: it never guesses about what an unreadable node references.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

use crate::{
    error::{Result, VeilError},
    id::ObjectId,
    now_millis,
    object::{EntryKind, Object},
    pack::{index_file, pack_file, Pack, PackStats, PackWriter, DEFAULT_LEVEL},
    repo::Repo,
    store::ObjectStore,
    vfs::{NodeKind, StorageBackend},
    vpath::VPath,
};

pub const DEFAULT_GRACE: Duration = Duration::from_secs(60 * 60);

const PENDING_MAGIC: &[u8; 8] = b"VEILGCP1";

#[derive(Clone, Debug)]
pub struct GcOptions {
    /// Prune operations older than this. `None` keeps the whole op log.
    pub keep_ops: Option<Duration>,
    /// How long an object must have been unreachable before it is deleted.
    /// `Duration::ZERO` deletes immediately; on a lock-free repository
    /// still only under the deletion fence ([`crate::maintenance`]), so
    /// never under a running transaction.
    pub grace: Duration,
    /// zstd level for packed objects.
    pub level: i32,
    /// Delta-compress successive versions of the same path.
    pub deltas: bool,
    /// Additional snapshots to treat as live.
    pub extra_roots: Vec<ObjectId>,
    /// Clock override in ms since the epoch (tests).
    pub now: Option<i64>,
}

impl Default for GcOptions {
    fn default() -> Self {
        GcOptions {
            keep_ops: None,
            grace: DEFAULT_GRACE,
            level: DEFAULT_LEVEL,
            deltas: true,
            extra_roots: Vec::new(),
            now: None,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct GcReport {
    pub ops_before: usize,
    pub ops_pruned: usize,
    pub loose_before: usize,
    pub packs_before: usize,
    pub objects_before: usize,
    pub reachable: usize,
    /// Unreachable but still inside the grace period (kept, packed).
    pub pending: usize,
    pub deleted: usize,
    /// Deleted-then-restored because another process started using them.
    pub rescued: usize,
    pub bytes_before: u64,
    pub bytes_after: u64,
    /// Name of the (first) pack written, if any.
    pub pack: Option<String>,
    /// Every pack written (consolidation, rewrites, a merge; each streamed,
    /// BUG-800).
    pub packs: Vec<String>,
    /// Totals over [`GcReport::packs`].
    pub pack_stats: PackStats,
    /// Why nothing was deleted, if the graph could not be fully read.
    pub incomplete: Vec<String>,
    /// Why nothing was deleted although the graph was read: other commands
    /// kept running past gc's wait for its deletion fence (BUG-811).
    pub deferred: Option<String>,
    /// Loose objects packed (consolidation, `maintenance.rs`).
    pub consolidated: usize,
    /// Packs merged into one (geometric merging, `maintenance.rs`).
    pub merged: usize,
    /// Packs rewritten to drop their garbage.
    pub rewritten: usize,
    /// Crash debris removed: temp files and the staging of dead
    /// transactions ([`crate::maintenance::sweep_debris`]).
    pub debris_removed: usize,
}

/// One pack a gc task writes, streamed ([`PackWriter`], BUG-800), so its
/// size never bounds memory. One pack per task, whatever its size: split
/// packs would only be merged again by the next geometric merge.
pub(crate) struct GcPacks<'a> {
    level: i32,
    backend: &'a dyn StorageBackend,
    dir: VPath,
    current: Option<PackWriter<'a>>,
    /// Every object in a pack written (or being written) by this gc.
    packed: HashSet<ObjectId>,
    names: Vec<String>,
    stats: PackStats,
}

impl<'a> GcPacks<'a> {
    pub(crate) fn new(level: i32, backend: &'a dyn StorageBackend, dir: VPath) -> Self {
        GcPacks {
            level,
            backend,
            dir,
            current: None,
            packed: HashSet::new(),
            names: Vec::new(),
            stats: PackStats::default(),
        }
    }

    pub(crate) fn contains(&self, id: &ObjectId) -> bool {
        self.packed.contains(id)
    }

    /// Is `id` in the pack being built (so it can be a delta base)?
    pub(crate) fn current_has(&self, id: &ObjectId) -> bool {
        self.current.as_ref().is_some_and(|b| b.contains(id))
    }

    fn writer(&mut self) -> Result<&mut PackWriter<'a>> {
        if self.current.is_none() {
            self.current = Some(PackWriter::new(self.backend.create_stream(&self.dir, true)?, self.level)?);
        }
        Ok(self.current.as_mut().expect("just created"))
    }

    pub(crate) fn add(&mut self, id: ObjectId, raw: &[u8], base: Option<(&ObjectId, &[u8])>) -> Result<()> {
        self.writer()?.add(id, raw, base)?;
        self.packed.insert(id);
        Ok(())
    }

    /// Add an entry as another pack stored it ([`PackWriter::add_entry`]);
    /// false (nothing added) if it is a delta whose base is not in the
    /// pack being written.
    pub(crate) fn add_entry(&mut self, id: ObjectId, e: &crate::pack::Entry) -> Result<bool> {
        if !self.writer()?.add_entry(id, e)? {
            return Ok(false);
        }
        self.packed.insert(id);
        Ok(true)
    }

    fn close(&mut self) -> Result<()> {
        if let Some(b) = self.current.take() {
            if let Some((name, s)) = b.finish(self.backend, &self.dir)? {
                self.names.push(name);
                self.stats.objects += s.objects;
                self.stats.stored += s.stored;
                self.stats.compressed += s.compressed;
                self.stats.deltas += s.deltas;
                self.stats.raw_bytes += s.raw_bytes;
                self.stats.pack_bytes += s.pack_bytes;
            }
        }
        Ok(())
    }

    pub(crate) fn finish(mut self) -> Result<(Vec<String>, PackStats)> {
        self.close()?;
        Ok((self.names, self.stats))
    }
}

// ---- pending list -------------------------------------------------------------

fn pending_path(gc_dir: &VPath) -> VPath {
    gc_dir.join("pending")
}

/// The pending list: unreachable objects and when gc first saw them
/// unreachable. A missing or damaged file reads as empty, which is safe: it
/// only restarts the grace period.
pub(crate) fn read_pending(backend: &dyn StorageBackend, gc_dir: &VPath) -> Result<HashMap<ObjectId, i64>> {
    let raw = match backend.read(&pending_path(gc_dir)) {
        Ok(r) => r,
        Err(e) if e.is_not_found() => return Ok(HashMap::new()),
        Err(e) => return Err(e),
    };
    let damaged = || VeilError::Corrupt("gc pending list".into(), "damaged".into());
    if raw.len() < 12 + 32 || &raw[..8] != PENDING_MAGIC {
        return Err(damaged());
    }
    let n = u32::from_le_bytes(raw[8..12].try_into().unwrap()) as usize;
    if raw.len() != 12 + n * 40 + 32 || blake3::hash(&raw[..raw.len() - 32]).as_bytes() != &raw[raw.len() - 32..] {
        return Err(damaged());
    }
    Ok((0..n)
        .map(|i| {
            let at = 12 + i * 40;
            let id = ObjectId(raw[at..at + 32].try_into().unwrap());
            (id, i64::from_le_bytes(raw[at + 32..at + 40].try_into().unwrap()))
        })
        .collect())
}

fn write_pending(backend: &dyn StorageBackend, gc_dir: &VPath, pending: &HashMap<ObjectId, i64>) -> Result<()> {
    if pending.is_empty() {
        return backend.remove_file(&pending_path(gc_dir));
    }
    let mut entries: Vec<_> = pending.iter().collect();
    entries.sort();
    let mut out = Vec::with_capacity(12 + entries.len() * 40 + 32);
    out.extend_from_slice(PENDING_MAGIC);
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for (id, t) in entries {
        out.extend_from_slice(&id.0);
        out.extend_from_slice(&t.to_le_bytes());
    }
    let sum = blake3::hash(&out);
    out.extend_from_slice(sum.as_bytes());
    backend.write(&pending_path(gc_dir), &out)
}

// ---- helpers --------------------------------------------------------------------

fn list_hex_files(backend: &dyn StorageBackend, dir: &VPath) -> Result<Vec<ObjectId>> {
    match backend.list_dir(dir) {
        Ok(entries) => Ok(entries
            .into_iter()
            .filter(|e| e.kind == NodeKind::File)
            .filter_map(|e| ObjectId::from_hex(&e.name).ok())
            .collect()),
        Err(e) if e.is_not_found() => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

fn op_path(id: &ObjectId) -> VPath {
    VPath::new(".veil/ops").unwrap().join(&id.hex())
}

/// Snapshots recorded in the project directory's checkout pointer: the one
/// last materialised and the target of an unfinished move (its journal).
/// The CLI diffs the working copy against them, so they must survive gc even
/// if no retained view references them any more.
fn checkout_snapshots(backend: &dyn StorageBackend) -> Vec<ObjectId> {
    let Some(raw) = VPath::new(crate::working_copy::CHECKOUT_STATE_PATH)
        .ok()
        .and_then(|p| backend.read_opt(&p).ok().flatten())
    else {
        return Vec::new();
    };
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&raw) else {
        return Vec::new();
    };
    let id = |v: Option<&serde_json::Value>| v.and_then(|s| s.as_str()).and_then(|s| ObjectId::from_hex(s).ok());
    [id(v.get("snapshot")), id(v.get("pending").and_then(|p| p.get("snapshot")))]
        .into_iter()
        .flatten()
        .collect()
}

/// A pack is rewritten to drop its deletable garbage once that is more
/// than this share of its bytes (a quarter), or with any share when the
/// grace period is zero (`--prune-now` deletes at once) or the pack is at
/// most [`REWRITE_SMALL`] bytes.
pub const REWRITE_SHARE: (u64, u64) = (1, 4);

/// Packs this small are cheap to rewrite: any deletable garbage in one
/// goes (after geometric merging, small packs mix garbage with the rest).
pub const REWRITE_SMALL: u64 = 16 << 20;

// ---- the inventory and its bitmap -------------------------------------------------

/// Every object copy in the store when gc started: the packs and the loose
/// ids. A position is a pack's start plus the index of the id in that
/// pack's (sorted) index, or the loose start plus its index in `loose`.
pub(crate) struct Inventory {
    pub(crate) packs: Vec<Arc<Pack>>,
    starts: Vec<usize>,
    pub(crate) loose: Vec<ObjectId>,
    loose_start: usize,
    len: usize,
}

impl Inventory {
    pub(crate) fn take(store: &ObjectStore) -> Result<Inventory> {
        let packs = store.packs()?;
        let mut loose = store.list_loose()?;
        loose.sort();
        loose.dedup();
        let mut starts = Vec::with_capacity(packs.len());
        let mut n = 0;
        for p in &packs {
            starts.push(n);
            n += p.index().len();
        }
        let loose_start = n;
        n += loose.len();
        Ok(Inventory {
            packs,
            starts,
            loose,
            loose_start,
            len: n,
        })
    }

    /// Every position holding a copy of `id`.
    fn positions<'a>(&'a self, id: &ObjectId) -> impl Iterator<Item = usize> + 'a {
        let id = *id;
        self.packs
            .iter()
            .zip(&self.starts)
            .filter_map(move |(p, s)| p.index().find(&id).map(|i| s + i))
            .chain(self.loose.binary_search(&id).ok().map(|i| self.loose_start + i))
    }

    fn id_at(&self, pos: usize) -> ObjectId {
        if pos >= self.loose_start {
            return self.loose[pos - self.loose_start];
        }
        let p = self.starts.partition_point(|s| *s <= pos) - 1;
        self.packs[p].index().ids()[pos - self.starts[p]]
    }

    /// Whether `pos` is the first copy of its object (to count objects once).
    fn is_first(&self, pos: usize) -> bool {
        self.positions(&self.id_at(pos)).next() == Some(pos)
    }
}

/// What the mark reached: one bit per inventory position, every copy of an
/// object set together, and a set for objects outside the inventory.
struct Reach<'a> {
    inv: &'a Inventory,
    bits: Vec<u64>,
    outside: HashSet<ObjectId>,
}

impl<'a> Reach<'a> {
    fn new(inv: &'a Inventory) -> Self {
        Reach {
            inv,
            bits: vec![0; inv.len.div_ceil(64)],
            outside: HashSet::new(),
        }
    }

    fn bit(&self, pos: usize) -> bool {
        self.bits[pos / 64] & (1 << (pos % 64)) != 0
    }

    /// Mark `id`; false if it already was.
    fn insert(&mut self, id: ObjectId) -> bool {
        let inv = self.inv;
        let (mut any, mut new) = (false, false);
        for pos in inv.positions(&id) {
            any = true;
            if !self.bit(pos) {
                new = true;
                self.bits[pos / 64] |= 1 << (pos % 64);
            }
        }
        if !any {
            return self.outside.insert(id);
        }
        new
    }

    fn contains(&self, id: &ObjectId) -> bool {
        match self.inv.positions(id).next() {
            Some(pos) => self.bit(pos),
            None => self.outside.contains(id),
        }
    }
}

// ---- marking ----------------------------------------------------------------------

struct Mark<'a> {
    store: &'a ObjectStore,
    /// A thin clone: the server's history as the clone holds it. A gap in
    /// it is on the server; a gap only this clone's own snapshots name is
    /// lost work, and stops the sweep as in a full clone (BUG-1143).
    server: Option<std::collections::HashSet<ObjectId>>,
    /// The snapshot whose tree is being marked.
    walking: Option<ObjectId>,
    reach: Reach<'a>,
    incomplete: Vec<String>,
}

impl Mark<'_> {
    fn snapshots(&mut self, roots: impl IntoIterator<Item = ObjectId>) {
        // The flag marks the merged-in parent of an unreleased embargoed
        // merge, which a public remote (and its clones) legitimately lacks.
        let mut stack: Vec<(ObjectId, bool)> = roots.into_iter().map(|id| (id, false)).collect();
        while let Some((id, withheld)) = stack.pop() {
            if !self.reach.insert(id) {
                continue;
            }
            match self.store.snapshot(&id) {
                Ok(s) => {
                    let embargoed = s.embargo.as_deref().is_some_and(|e| !self.store.keys.embargo_released(e));
                    stack.extend(s.parents.iter().enumerate().map(|(i, p)| (*p, embargoed && i > 0)));
                    // Attempts are strong references (format 10): kept as
                    // long as the change that lists them.
                    stack.extend(s.attempts.iter().map(|a| (*a, false)));
                    self.walking = Some(id);
                    self.tree(s.tree, String::new());
                    self.walking = None;
                }
                Err(VeilError::Missing(_)) if withheld || self.server.as_ref().is_some_and(|h| h.contains(&id)) => {}
                Err(e) => self.incomplete.push(format!("snapshot {}: {e}", id.short())),
            }
        }
    }

    /// A thin clone: is `id`, missing at `path` of the snapshot being
    /// marked, the server's (not fetched)?
    fn servers(&self, id: &ObjectId, path: &str) -> bool {
        match (&self.server, self.walking) {
            (Some(server), Some(snap)) => self.store.classify_gap(server, &snap, path, id) == crate::promisor::Gap::Server,
            _ => false,
        }
    }

    fn tree(&mut self, root: ObjectId, root_path: String) {
        let mut stack = vec![(root, root_path)];
        while let Some((id, path)) = stack.pop() {
            if !self.reach.insert(id) {
                continue;
            }
            let t = match self.store.tree_object(&id) {
                Ok(t) => t,
                Err(VeilError::Missing(_)) if self.servers(&id, &path) => continue,
                Err(e) => {
                    self.incomplete.push(format!("tree {} at '{path}': {e}", id.short()));
                    continue;
                }
            };
            for e in &t.entries {
                let sub = || match path.is_empty() {
                    true => e.name.clone(),
                    false => format!("{path}/{}", e.name),
                };
                match e.kind {
                    EntryKind::Dir => stack.push((e.id, sub())),
                    // Symlink targets are blobs too.
                    EntryKind::File | EntryKind::Symlink => {
                        self.reach.insert(e.id);
                    }
                    EntryKind::Conflict => self.conflict(e.id, &sub()),
                }
            }
        }
    }

    /// An annotated tag object (format 5): kept, and its target returned
    /// as a root.
    fn atag(&mut self, id: ObjectId) -> Option<ObjectId> {
        if !self.reach.insert(id) {
            return None;
        }
        match self.store.get(&id) {
            Ok(Object::Atag(a)) => Some(a.target),
            Ok(other) => {
                self.incomplete
                    .push(format!("annotated tag {} is a {}", id.short(), other.kind_name()));
                None
            }
            Err(e) => {
                self.incomplete.push(format!("annotated tag {}: {e}", id.short()));
                None
            }
        }
    }

    /// A conflict object and every version it names.
    fn conflict(&mut self, id: ObjectId, path: &str) {
        if !self.reach.insert(id) {
            return;
        }
        match self.store.conflict(&id) {
            Ok(c) => {
                for t in c.referenced_ids() {
                    self.reach.insert(t);
                }
            }
            Err(VeilError::Missing(_)) if self.servers(&id, path) => {}
            Err(e) => self.incomplete.push(format!("conflict {} at '{path}': {e}", id.short())),
        }
    }

    /// A keep marker names an object of unknown kind.
    fn any(&mut self, id: ObjectId) {
        if self.reach.contains(&id) {
            return;
        }
        let raw = match self.store.read_raw(&id) {
            Ok(r) => r,
            Err(VeilError::Missing(_)) => return,
            Err(e) => {
                self.incomplete.push(format!("kept object {}: {e}", id.short()));
                return;
            }
        };
        match Object::decode(&raw) {
            Ok(Object::Snapshot(_)) => self.snapshots([id]),
            Ok(Object::Tree(_)) => self.tree(id, String::new()),
            Ok(Object::Conflict(_)) => self.conflict(id, ""),
            Ok(Object::Atag(_)) => {
                if let Some(t) = self.atag(id) {
                    self.snapshots([t]);
                }
            }
            Ok(Object::Blob(_)) => {
                self.reach.insert(id);
            }
            Ok(Object::Sealed(_)) => match self.store.open(&id) {
                Ok(Object::Tree(_)) => self.tree(id, String::new()),
                Ok(Object::Blob(_)) => {
                    self.reach.insert(id);
                }
                Ok(_) => {
                    self.reach.insert(id);
                    self.incomplete
                        .push(format!("kept object {} is a sealed non-tree", id.short()));
                }
                Err(e) => {
                    self.reach.insert(id);
                    self.incomplete
                        .push(format!("kept object {} cannot be opened: {e}", id.short()));
                }
            },
            Err(e) => self.incomplete.push(format!("kept object {}: {e}", id.short())),
        }
    }
}

struct FresheningOff<'a>(&'a ObjectStore);

impl Drop for FresheningOff<'_> {
    fn drop(&mut self) {
        self.0.set_freshening(true);
    }
}

// ---- gc -----------------------------------------------------------------------

/// Collect garbage in `repo`: prune, then pack loose objects and merge
/// small packs. See the module docs.
pub fn gc(repo: &mut Repo, opts: &GcOptions) -> Result<GcReport> {
    let _hold = crate::maintenance::GcHold::take(repo, true)?
        .ok_or_else(|| VeilError::Locked("another `vl gc` is running".into()))?;
    run(repo, opts, true, Duration::ZERO)
}

/// The tasks of a gc run, its hold taken by the caller: prune (if
/// `prune`), then consolidate loose objects older than `loose_age`, then
/// merge packs geometrically.
pub(crate) fn run(repo: &mut Repo, opts: &GcOptions, prune: bool, loose_age: Duration) -> Result<GcReport> {
    // A thin clone: gc never fetches. What it does not hold is on the
    // server, and nothing local sits only below it (threat 5 of the
    // partial-clone design), so the mark stops there.
    let store = repo.store.clone();
    store.without_fetching(|| run_here(repo, opts, prune, loose_age))
}

fn run_here(repo: &mut Repo, opts: &GcOptions, prune: bool, loose_age: Duration) -> Result<GcReport> {
    let backend = repo.backend.clone();
    // Re-read under the hold: an upgrade since the repository was opened
    // (it takes the gc lease too) changed what this run would write.
    if crate::repo::read_config(&*backend)?.format != repo.config.format {
        return Err(VeilError::repo("the repository was upgraded meanwhile; run `vl gc` again"));
    }
    repo.reload()?;
    let store = repo.store.clone();
    store.set_freshening(false);
    let _restore = FresheningOff(&store);
    store.invalidate()?;
    let now = opts.now.unwrap_or_else(now_millis);
    let before = store.stats()?;
    let mut report = GcReport {
        loose_before: before.loose_objects,
        packs_before: before.packs,
        bytes_before: before.loose_bytes + before.pack_bytes,
        ..GcReport::default()
    };
    report.debris_removed = crate::maintenance::sweep_debris(&store)?;
    if let Some((name, why)) = store.broken_packs()?.first() {
        return Err(VeilError::Corrupt(
            format!("pack {}", &name[..12]),
            format!("{why}; refusing to gc a damaged store (run fsck first)"),
        ));
    }
    let mut written = Written::default();
    let mut unreachable = HashSet::new();
    if prune {
        unreachable = prune_store(repo, &store, opts, now, &mut report, &mut written)?;
        store.invalidate()?;
    }
    let c = crate::maintenance::consolidate(&store, loose_age, opts.level, opts.deltas, &unreachable)?;
    report.consolidated = c.objects;
    written.add(c.packs, c.stats);
    store.invalidate()?;
    let m = crate::maintenance::merge_packs(&store, opts.level)?;
    report.merged = m.merged;
    written.add(m.packs, m.stats);
    store.invalidate()?;
    report.pack = written.names.first().cloned();
    report.packs = written.names;
    report.pack_stats = written.stats;
    let stats = store.stats()?;
    report.bytes_after = stats.loose_bytes + stats.pack_bytes;
    Ok(report)
}

/// The packs a run wrote, with their totals.
#[derive(Default)]
pub(crate) struct Written {
    names: Vec<String>,
    stats: PackStats,
}

impl Written {
    pub(crate) fn add(&mut self, names: Vec<String>, s: PackStats) {
        self.names.extend(names);
        self.stats.objects += s.objects;
        self.stats.stored += s.stored;
        self.stats.compressed += s.compressed;
        self.stats.deltas += s.deltas;
        self.stats.raw_bytes += s.raw_bytes;
        self.stats.pack_bytes += s.pack_bytes;
    }
}

/// Copy `id` from `pack` into `out` as stored, its delta base first; a
/// delta whose base is in `drop` (or does not fit) is stored decoded.
pub(crate) fn copy_entry(
    store: &ObjectStore,
    pack: &Pack,
    id: &ObjectId,
    out: &mut GcPacks<'_>,
    drop: &HashSet<ObjectId>,
) -> Result<()> {
    if out.contains(id) {
        return Ok(());
    }
    let backend = &**store.backend();
    let Some(e) = pack.entry(backend, id)? else {
        return Err(VeilError::Corrupt(id.hex(), format!("missing from pack {}", &pack.name()[..12])));
    };
    if let Some(b) = e.base.filter(|b| !drop.contains(b) && pack.contains(b)) {
        copy_entry(store, pack, &b, out, drop)?;
    }
    if !out.add_entry(*id, &e)? {
        let raw = pack
            .get(backend, id, &crate::cache::LruCache::new(32 << 20))?
            .ok_or_else(|| VeilError::Corrupt(id.hex(), "vanished from its pack".into()))?;
        out.add(*id, &raw, None)?;
    }
    Ok(())
}

/// Prune (the module docs' steps 1–6). Returns the objects left pending.
fn prune_store(
    repo: &Repo,
    store: &Arc<ObjectStore>,
    opts: &GcOptions,
    now: i64,
    report: &mut GcReport,
    written: &mut Written,
) -> Result<HashSet<ObjectId>> {
    let backend = repo.backend.clone();
    // 1. Inventory, strictly before the roots are read.
    let inv = Inventory::take(store)?;
    report.objects_before = (0..inv.len).filter(|&p| inv.is_first(p)).count();
    let markers = list_hex_files(&*backend, &store.gc_dir().join("keep"))?;

    // 2. Operations to retain: every head file's operation and its
    // parents, and (with `keep_ops`) those inside the window.
    let op_ids = list_hex_files(&*backend, &VPath::new(".veil/ops")?)?;
    report.ops_before = op_ids.len();
    let heads: Vec<ObjectId> = repo.ops.raw_heads()?.all.into_iter().chain(repo.ops.heads()?).collect();
    let mut retained: HashSet<ObjectId> = HashSet::new();
    let mut incomplete = Vec::new();
    for h in &heads {
        retained.insert(*h);
        retained.extend(repo.ops.get(h)?.parents);
    }
    // A staged release's operation, and everything newer, stays: the push
    // reads the op log down to it to tell whether the release is in force
    // (BUG-1532).
    let (_, staged_ops) = repo.staged_release_standing()?;
    retained.extend(staged_ops);
    let cutoff = opts.keep_ops.map(|keep| now.saturating_sub(keep.as_millis() as i64));
    let mut roots: Vec<ObjectId> = vec![repo.root_id];
    let mut annotations = Vec::new();
    // Each operation's timestamp, so that the second marking (under the
    // fence, while writers wait) reads only what is new.
    let mut stamps: HashMap<ObjectId, i64> = HashMap::new();
    for id in &op_ids {
        match repo.ops.get(id) {
            Ok(op) => {
                stamps.insert(*id, op.timestamp);
                if retained.contains(id) || cutoff.is_none_or(|c| op.timestamp >= c) {
                    retained.insert(*id);
                    roots.extend(op.view.refs());
                    annotations.extend(op.view.annotations());
                }
            }
            Err(e) => {
                incomplete.push(format!("operation {}: {e}", id.short()));
                retained.insert(*id);
            }
        }
    }
    // A head (or a head's parent) not in the listing: written since.
    for id in retained.iter().filter(|id| !op_ids.contains(id)) {
        if let Some(op) = repo.ops.try_get(id)? {
            roots.extend(op.view.refs());
            annotations.extend(op.view.annotations());
        }
    }
    let mut pruned_ops: Vec<ObjectId> = op_ids.iter().filter(|id| !retained.contains(id)).copied().collect();

    // 3. Mark.
    roots.extend(opts.extra_roots.iter().copied());
    roots.extend(checkout_snapshots(&*backend));
    // A thin clone: snapshots any retained operation saw on a remote.
    let server = store.is_partial().then(|| {
        let remote = repo.config.partial.as_ref().map_or(String::new(), |p| p.remote.clone());
        let mut tips: Vec<ObjectId> = crate::promisor::own_tips(&repo.view.remote_tags, &remote).collect();
        for id in &retained {
            if let Ok(Some(op)) = repo.ops.try_get(id) {
                tips.extend(crate::promisor::own_tips(&op.view.remote_tags, &remote));
            }
        }
        store.server_history(&tips)
    });
    let mut mark = Mark {
        server,
        walking: None,
        store,
        reach: Reach::new(&inv),
        incomplete,
    };
    annotations.sort();
    annotations.dedup();
    for a in annotations {
        roots.extend(mark.atag(a));
    }
    roots.sort();
    roots.dedup();
    mark.snapshots(roots);
    for m in &markers {
        mark.any(*m);
    }
    report.incomplete = std::mem::take(&mut mark.incomplete);

    // 4. Classify the unreachable: delete, or keep for the grace period.
    let old_pending = read_pending(&*backend, &store.gc_dir()).unwrap_or_default();
    let grace = opts.grace.as_millis() as i64;
    let may_delete = report.incomplete.is_empty();
    let mut delete: HashSet<ObjectId> = HashSet::new();
    let mut pending: HashMap<ObjectId, i64> = HashMap::new();
    for pos in 0..inv.len {
        if !inv.is_first(pos) {
            continue;
        }
        if mark.reach.bit(pos) {
            report.reachable += 1;
            continue;
        }
        let id = inv.id_at(pos);
        let first_seen = old_pending.get(&id).copied().unwrap_or(now).min(now);
        if may_delete && now - first_seen >= grace {
            delete.insert(id);
        } else {
            pending.insert(id, first_seen);
        }
    }

    // 5. Rewrite the packs whose deletable garbage is worth it.
    let mut dropped: Vec<Arc<Pack>> = Vec::new();
    for p in &inv.packs {
        let garbage: u64 = p.index().ids().iter().filter(|id| delete.contains(id)).map(|id| p.entry_len(id)).sum();
        let total = p.entries_len().max(1);
        let worth = garbage > 0 && (grace == 0 || total <= REWRITE_SMALL || garbage * REWRITE_SHARE.1 > total * REWRITE_SHARE.0);
        if !worth {
            continue;
        }
        let mut out = GcPacks::new(opts.level, &*backend, store.pack_dir());
        for id in p.ids_in_pack_order() {
            if !delete.contains(&id) {
                copy_entry(store, p, &id, &mut out, &delete)?;
            }
        }
        let (names, stats) = out.finish()?;
        written.add(names, stats);
        report.rewritten += 1;
        dropped.push(p.clone());
    }

    // 6. Lock-free repositories delete only under the fence (BUG-811):
    //    no transaction runs then, so the roots are read again and what
    //    they reach now (published or reused since the first marking)
    //    survives. Objects to delete that must survive are `kept_back`.
    let mut kept_back: HashSet<ObjectId> = HashSet::new();
    let fence = match repo.lock_free() && (!delete.is_empty() || !pruned_ops.is_empty()) {
        true => Some(crate::maintenance::raise_fence(store)?),
        false => None,
    };
    match &fence {
        Some(Err(why)) => {
            report.deferred = Some(why.clone());
            kept_back = std::mem::take(&mut delete);
            pruned_ops.clear();
        }
        Some(Ok(_)) => {
            let heads2: Vec<ObjectId> = repo.ops.raw_heads()?.all.into_iter().chain(repo.ops.heads()?).collect();
            let op_ids2 = list_hex_files(&*backend, &VPath::new(".veil/ops")?)?;
            // Read only the heads and what the first listing did not have.
            let mut ops2: HashMap<ObjectId, crate::oplog::Operation> = HashMap::new();
            let to_read: Vec<ObjectId> = heads2.iter().chain(op_ids2.iter().filter(|id| !stamps.contains_key(id))).copied().collect();
            for id in &to_read {
                if ops2.contains_key(id) {
                    continue;
                }
                match repo.ops.try_get(id) {
                    Ok(Some(op)) => {
                        stamps.insert(*id, op.timestamp);
                        ops2.insert(*id, op);
                    }
                    Ok(None) => {}
                    Err(e) => mark.incomplete.push(format!("operation {}: {e}", id.short())),
                }
            }
            let mut retained2: HashSet<ObjectId> = HashSet::new();
            for h in &heads2 {
                retained2.insert(*h);
                if let Some(op) = ops2.get(h) {
                    retained2.extend(op.parents.iter().copied());
                }
            }
            for id in &op_ids2 {
                if stamps.get(id).is_some_and(|t| cutoff.is_none_or(|c| *t >= c)) {
                    retained2.insert(*id);
                }
            }
            // Only what the first listing saw is pruned, and every
            // operation that stays has its view marked: those the first
            // marking did not (new, or retained only now) are read.
            pruned_ops.retain(|id| !retained2.contains(id));
            let mut roots2: Vec<ObjectId> = Vec::new();
            let mut annotations2 = Vec::new();
            let mut unmarked: Vec<ObjectId> = op_ids2
                .iter()
                .chain(&heads2)
                .filter(|id| !retained.contains(id) && !pruned_ops.contains(id))
                .copied()
                .collect();
            unmarked.sort();
            unmarked.dedup();
            for id in unmarked {
                let op = match ops2.remove(&id) {
                    Some(op) => Some(op),
                    None => match repo.ops.try_get(&id) {
                        Ok(op) => op,
                        Err(e) => {
                            mark.incomplete.push(format!("operation {}: {e}", id.short()));
                            None
                        }
                    },
                };
                if let Some(op) = op {
                    roots2.extend(op.view.refs());
                    annotations2.extend(op.view.annotations());
                }
            }
            roots2.extend(checkout_snapshots(&*backend));
            for a in annotations2 {
                roots2.extend(mark.atag(a));
            }
            mark.snapshots(roots2);
            for m in list_hex_files(&*backend, &store.gc_dir().join("keep"))? {
                mark.any(m);
            }
            if mark.incomplete.is_empty() {
                kept_back = delete.iter().filter(|id| mark.reach.contains(id)).copied().collect();
                delete.retain(|id| !kept_back.contains(id));
            } else {
                report.incomplete.append(&mut mark.incomplete);
                kept_back = std::mem::take(&mut delete);
                pruned_ops.clear();
            }
        }
        None => {}
    }
    // What survives this way and was only in a pack that goes gets a loose
    // copy (the old pack's bytes) first.
    let in_kept_pack = |id: &ObjectId| inv.packs.iter().any(|p| p.contains(id) && !dropped.iter().any(|d| d.name() == p.name()));
    for id in &kept_back {
        if inv.loose.binary_search(id).is_err() && !in_kept_pack(id) {
            backend.write(&store.loose_path(id), &store.read_raw(id)?)?;
        }
        if !mark.reach.contains(id) {
            pending.insert(*id, old_pending.get(id).copied().unwrap_or(now).min(now));
        }
    }

    // 7. Delete: pruned operations (recorded first, so fsck can tell the
    // pruning apart from loss), loose garbage, then the dropped packs. The
    // prune epoch moves first: a gc that dies part-way (`kill -9`, EIO)
    // has still told every command carrying an older view to check what
    // it brought in (BUG-815).
    if matches!(fence, Some(Ok(_))) && (!delete.is_empty() || !pruned_ops.is_empty()) {
        crate::maintenance::bump_prune_epoch(store)?;
    }
    crate::oplog::record_pruned_ops(&*backend, &pruned_ops)?;
    for id in &pruned_ops {
        backend.remove_file(&op_path(id))?;
    }
    report.ops_pruned = pruned_ops.len();
    let loose_garbage: Vec<ObjectId> = inv.loose.iter().filter(|id| delete.contains(id)).copied().collect();
    for id in &loose_garbage {
        let path = store.loose_path(id);
        // Read, delete, then look for a keep marker: a process that started
        // using the object before the delete has written its marker by now.
        let raw = backend.read_opt(&path)?;
        backend.remove_file(&path)?;
        if backend.exists(&store.keep_marker(id))? {
            if let Some(raw) = raw {
                backend.write(&path, &raw)?;
                report.rescued += 1;
                delete.remove(id);
            }
        }
    }
    for p in &dropped {
        if written.names.iter().any(|n| n == p.name()) {
            continue; // identical rewrite
        }
        backend.remove_file(&index_file(&store.pack_dir(), p.name()))?;
        backend.remove_file(&pack_file(&store.pack_dir(), p.name()))?;
    }
    // Garbage in a pack that stays is not deleted: it stays pending.
    for id in &delete {
        if in_kept_pack(id) {
            pending.insert(*id, old_pending.get(id).copied().unwrap_or(now).min(now));
        } else {
            report.deleted += 1;
        }
    }
    for m in &markers {
        backend.remove_file(&store.keep_marker(m))?;
    }
    report.pending = pending.len();
    write_pending(&*backend, &store.gc_dir(), &pending)?;
    drop(fence);
    if report.deferred.is_none() && report.incomplete.is_empty() {
        crate::maintenance::record_prune(store, now)?;
    }
    Ok(pending.into_keys().collect())
}
