//! Garbage collection: op-log pruning, reachability, packing.
//!
//! `gc` runs under the repository lock and:
//!
//! 1. **Takes an inventory** of every object (loose and packed) *before*
//!    scanning reachability. Objects written later, e.g. by a concurrent
//!    `vl` process building a snapshot, are not in the inventory and are
//!    never touched.
//! 2. **Prunes the op log** (optional, `keep_ops`): operations older than the
//!    retention window are deleted, except the current operation and its
//!    parents (so `vl undo` always works).
//! 3. **Marks** everything reachable from the views of all retained
//!    operations, from the project directory's checkout pointer, and from
//!    keep markers: snapshot → parents and tree; tree → entries; file entry →
//!    object and embargo `fallback`. Snapshot `predecessors` (the evolution
//!    log) are weak references: they are kept only while otherwise reachable.
//! 4. **Grace period.** An unreachable object is not deleted the first time
//!    it is seen. Its first-seen time is recorded in `objects/gc/pending`, and
//!    it is deleted by a later gc once it has stayed unreachable for at least
//!    `grace`. Any process that touches a pending object (see
//!    [`crate::store`]) writes a keep marker `objects/gc/keep/<id>` and makes
//!    sure there is a loose copy. Markers are roots for the next gc, and gc
//!    re-checks the marker *after* deleting each loose object, restoring it
//!    if a marker appeared. So an object that another process starts using
//!    while gc runs survives.
//! 5. **Repacks** everything it keeps into one new pack (zstd, with deltas
//!    between successive versions of the same path), then deletes the old
//!    packs and loose objects.
//!
//! If any part of the graph cannot be read (a missing or undecryptable
//! snapshot or tree, an unreadable operation), gc still packs but deletes
//! nothing and says why: it never guesses about what an unreadable node
//! references.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    time::Duration,
};

use crate::{
    error::{Result, VeilError},
    id::ObjectId,
    lock::RepoLock,
    now_millis,
    object::{EntryKind, Object},
    oplog::Operation,
    pack::{index_file, pack_file, PackBuilder, PackStats, DEFAULT_LEVEL},
    repo::Repo,
    store::ObjectStore,
    vfs::{NodeKind, StorageBackend},
    vpath::VPath,
};

/// Default grace period before unreachable objects are deleted.
pub const DEFAULT_GRACE: Duration = Duration::from_secs(60 * 60);

const PENDING_MAGIC: &[u8; 8] = b"VEILGCP1";

#[derive(Clone, Debug)]
pub struct GcOptions {
    /// Prune operations older than this. `None` keeps the whole op log.
    pub keep_ops: Option<Duration>,
    /// How long an object must have been unreachable before it is deleted.
    /// `Duration::ZERO` deletes immediately (unsafe with concurrent writers).
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
    /// Every pack written: the kept objects go into packs of at most about
    /// [`GC_PACK_LIMIT`] bytes each (BUG-800).
    pub packs: Vec<String>,
    /// Totals over [`GcReport::packs`].
    pub pack_stats: PackStats,
    /// Why nothing was deleted, if the graph could not be fully read.
    pub incomplete: Vec<String>,
}

/// The raw bytes gc puts into one pack before it starts the next (BUG-800):
/// a pack is built in memory, so this bounds gc's memory, whatever the
/// size of the store.
pub const GC_PACK_LIMIT: u64 = 128 << 20;

/// The packs one gc writes (see [`GC_PACK_LIMIT`]).
struct GcPacks<'a> {
    level: i32,
    backend: &'a dyn StorageBackend,
    dir: VPath,
    current: Option<PackBuilder>,
    current_bytes: u64,
    /// Every object in a pack written (or being written) by this gc.
    packed: HashSet<ObjectId>,
    names: Vec<String>,
    stats: PackStats,
}

impl<'a> GcPacks<'a> {
    fn new(level: i32, backend: &'a dyn StorageBackend, dir: VPath) -> Self {
        GcPacks {
            level,
            backend,
            dir,
            current: None,
            current_bytes: 0,
            packed: HashSet::new(),
            names: Vec::new(),
            stats: PackStats::default(),
        }
    }

    fn contains(&self, id: &ObjectId) -> bool {
        self.packed.contains(id)
    }

    /// Is `id` in the pack being built (so it can be a delta base)?
    fn current_has(&self, id: &ObjectId) -> bool {
        self.current.as_ref().is_some_and(|b| b.contains(id))
    }

    fn add(&mut self, id: ObjectId, raw: &[u8], base: Option<(&ObjectId, &[u8])>) -> Result<()> {
        if self.current.is_none() {
            self.current = Some(PackBuilder::new(self.level)?);
        }
        let b = self.current.as_mut().expect("just created");
        b.add(id, raw, base)?;
        self.packed.insert(id);
        self.current_bytes += raw.len() as u64;
        if self.current_bytes >= GC_PACK_LIMIT {
            self.close()?;
        }
        Ok(())
    }

    fn close(&mut self) -> Result<()> {
        self.current_bytes = 0;
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

    fn finish(mut self) -> Result<(Vec<String>, PackStats)> {
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

const HINT_DIR: u8 = 0;
const HINT_FILE: u8 = 1;

/// Mark phase state.
struct Mark<'a> {
    store: &'a ObjectStore,
    reach: HashSet<ObjectId>,
    /// (kind, path) → ids in first-visit order, newest snapshots first.
    /// Successive versions of one path are good delta candidates.
    hints: BTreeMap<(u8, String), Vec<ObjectId>>,
    snaps: Vec<(i64, ObjectId, ObjectId)>,
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
                    self.snaps.push((s.timestamp, id, s.tree));
                }
                Err(VeilError::Missing(_)) if withheld => {}
                Err(e) => self.incomplete.push(format!("snapshot {}: {e}", id.short())),
            }
        }
    }

    fn trees_of_snapshots(&mut self) {
        let mut snaps = std::mem::take(&mut self.snaps);
        snaps.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        for (_, _, tree) in snaps {
            self.tree(tree, String::new());
        }
    }

    fn hint(&mut self, kind: u8, path: &str, id: ObjectId) {
        self.hints.entry((kind, path.to_string())).or_default().push(id);
    }

    fn tree(&mut self, root: ObjectId, root_path: String) {
        let mut stack = vec![(root, root_path)];
        while let Some((id, path)) = stack.pop() {
            if !self.reach.insert(id) {
                continue;
            }
            self.hint(HINT_DIR, &path, id);
            let t = match self.store.tree_object(&id) {
                Ok(t) => t,
                Err(e) => {
                    self.incomplete.push(format!("tree {} at '{path}': {e}", id.short()));
                    continue;
                }
            };
            // An embargo wrapper lists every object reachable only through its
            // sealed side (which gc may be unable to open); the rest is
            // reachable through the fallback.
            if let Some(w) = crate::embargo::wrapper_parts(&t) {
                self.reach.insert(id);
                self.reach.insert(w.inner);
                self.reach.extend(w.listed.iter().copied());
                stack.push((w.fallback, path));
                continue;
            }
            for e in &t.entries {
                let p = if path.is_empty() {
                    e.name.clone()
                } else {
                    format!("{path}/{}", e.name)
                };
                match e.kind {
                    EntryKind::Dir => stack.push((e.id, p)),
                    // Symlink targets are blobs too.
                    EntryKind::File | EntryKind::Symlink => {
                        if self.reach.insert(e.id) {
                            self.hint(HINT_FILE, &p, e.id);
                        }
                        if let Some(fb) = e.fallback {
                            if self.reach.insert(fb) {
                                self.hint(HINT_FILE, &p, fb);
                            }
                        }
                    }
                    EntryKind::Conflict => self.conflict(e.id, &p),
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
                    if self.reach.insert(t) {
                        self.hint(HINT_FILE, path, t);
                    }
                }
            }
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
            Ok(Object::Snapshot(_)) => {
                self.snapshots([id]);
                self.trees_of_snapshots();
            }
            Ok(Object::Tree(_)) => self.tree(id, String::new()),
            Ok(Object::Conflict(_)) => self.conflict(id, ""),
            Ok(Object::Atag(_)) => {
                if let Some(t) = self.atag(id) {
                    self.snapshots([t]);
                    self.trees_of_snapshots();
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

/// Collect garbage in `repo`. See the module docs for the algorithm.
pub fn gc(repo: &mut Repo, opts: &GcOptions) -> Result<GcReport> {
    let backend = repo.backend.clone();
    let _lock = RepoLock::acquire(backend.clone())?;
    repo.reload()?;
    let store = repo.store.clone();
    store.set_freshening(false);
    let _restore = FresheningOff(&store);
    store.invalidate()?;
    let now = opts.now.unwrap_or_else(now_millis);
    let mut report = GcReport::default();

    // 1. Inventory, strictly before the reachability scan.
    if let Some((name, why)) = store.broken_packs()?.first() {
        return Err(VeilError::Corrupt(
            format!("pack {}", &name[..12]),
            format!("{why}; refusing to gc a damaged store (run fsck first)"),
        ));
    }
    let loose = store.list_loose()?;
    let loose_set: HashSet<ObjectId> = loose.iter().copied().collect();
    let old_packs = store.packs()?;
    let mut inventory = loose_set.clone();
    for p in &old_packs {
        inventory.extend(p.index().ids().iter().copied());
    }
    for id in &loose {
        report.bytes_before += backend.metadata(&store.loose_path(id))?.map_or(0, |m| m.len);
    }
    report.bytes_before += old_packs.iter().map(|p| p.disk_size()).sum::<u64>();
    report.loose_before = loose.len();
    report.packs_before = old_packs.len();
    report.objects_before = inventory.len();
    let markers = list_hex_files(&*backend, &store.gc_dir().join("keep"))?;

    // 2. Operations to retain.
    let op_ids = list_hex_files(&*backend, &VPath::new(".veil/ops")?)?;
    report.ops_before = op_ids.len();
    let head = repo.ops.head()?;
    let mut ops: HashMap<ObjectId, Operation> = HashMap::new();
    let mut retained: HashSet<ObjectId> = HashSet::new();
    let mut incomplete = Vec::new();
    for id in &op_ids {
        match repo.ops.get(id) {
            Ok(op) => {
                ops.insert(*id, op);
            }
            Err(e) => {
                incomplete.push(format!("operation {}: {e}", id.short()));
                retained.insert(*id);
            }
        }
    }
    let head_op = match ops.get(&head) {
        Some(op) => op.clone(),
        None => repo.ops.get(&head)?,
    };
    retained.insert(head);
    retained.extend(head_op.parents.iter().copied());
    match opts.keep_ops {
        None => retained.extend(ops.keys().copied()),
        Some(keep) => {
            let cutoff = now.saturating_sub(keep.as_millis() as i64);
            retained.extend(ops.iter().filter(|(_, op)| op.timestamp >= cutoff).map(|(id, _)| *id));
        }
    }
    let pruned_ops: Vec<ObjectId> = op_ids.iter().filter(|id| !retained.contains(id)).copied().collect();

    // 3. Mark.
    let mut roots: Vec<ObjectId> = vec![repo.root_id];
    roots.extend(head_op.view.refs());
    for (id, op) in &ops {
        if retained.contains(id) {
            roots.extend(op.view.refs());
        }
    }
    roots.extend(opts.extra_roots.iter().copied());
    roots.extend(checkout_snapshots(&*backend));
    // Annotated tags (format 5) are kept with their targets.
    let mut annotations = head_op.view.annotations();
    for (id, op) in &ops {
        if retained.contains(id) {
            annotations.extend(op.view.annotations());
        }
    }
    annotations.sort();
    annotations.dedup();
    let mut mark = Mark {
        store: &store,
        reach: HashSet::new(),
        hints: BTreeMap::new(),
        snaps: Vec::new(),
        incomplete,
    };
    for a in annotations {
        roots.extend(mark.atag(a));
    }
    roots.sort();
    roots.dedup();
    mark.snapshots(roots);
    mark.trees_of_snapshots();
    for m in &markers {
        mark.any(*m);
    }
    report.reachable = inventory.iter().filter(|id| mark.reach.contains(id)).count();
    report.incomplete = std::mem::take(&mut mark.incomplete);

    // 4. Classify the unreachable: delete, or keep for the grace period.
    let old_pending = read_pending(&*backend, &store.gc_dir()).unwrap_or_default();
    let grace = opts.grace.as_millis() as i64;
    let may_delete = report.incomplete.is_empty();
    let mut delete: HashSet<ObjectId> = HashSet::new();
    let mut pending: HashMap<ObjectId, i64> = HashMap::new();
    for id in &inventory {
        if mark.reach.contains(id) {
            continue;
        }
        let first_seen = old_pending.get(id).copied().unwrap_or(now).min(now);
        if may_delete && now - first_seen >= grace {
            delete.insert(*id);
        } else {
            pending.insert(*id, first_seen);
        }
    }

    // 5. Write packs with everything kept: by path first (delta chains,
    //    newest version as the base of older ones), then everything else.
    //    A pack is closed once it holds GC_PACK_LIMIT bytes, so that a
    //    builder never holds the whole store in memory (BUG-800); a delta
    //    base is always in its own pack.
    let mut packs = GcPacks::new(opts.level, &*backend, store.pack_dir());
    let keep = |id: &ObjectId| inventory.contains(id) && !delete.contains(id);
    for ids in mark.hints.values() {
        let mut prev: Option<(ObjectId, Vec<u8>)> = None;
        for id in ids {
            if !keep(id) || packs.contains(id) {
                continue;
            }
            let raw = store.read_raw(id)?;
            let base = match (opts.deltas, &prev) {
                (true, Some((b, r))) if packs.current_has(b) => Some((b, r.as_slice())),
                _ => None,
            };
            packs.add(*id, &raw, base)?;
            prev = Some((*id, raw));
        }
    }
    let mut rest: Vec<ObjectId> = inventory
        .iter()
        .filter(|id| keep(id) && !packs.contains(id))
        .copied()
        .collect();
    rest.sort();
    for id in rest {
        packs.add(id, &store.read_raw(&id)?, None)?;
    }
    let (names, stats) = packs.finish()?;
    report.pack = names.first().cloned();
    report.packs = names;
    report.pack_stats = stats;

    // 6. The new pack is in place: delete pruned ops, then old objects.
    // Record the pruning first so fsck can tell it apart from loss.
    crate::oplog::record_pruned_ops(&*backend, &pruned_ops)?;
    for id in &pruned_ops {
        backend.remove_file(&op_path(id))?;
    }
    report.ops_pruned = pruned_ops.len();
    for id in &loose {
        let path = store.loose_path(id);
        if !delete.contains(id) {
            backend.remove_file(&path)?; // now packed
            continue;
        }
        // Read, delete, then look for a keep marker: a process that started
        // using the object before the delete has written its marker by now.
        let raw = backend.read_opt(&path)?;
        backend.remove_file(&path)?;
        if backend.exists(&store.keep_marker(id))? {
            if let Some(raw) = raw {
                backend.write(&path, &raw)?;
                report.rescued += 1;
                continue;
            }
        }
        report.deleted += 1;
    }
    report.deleted += delete.iter().filter(|id| !loose_set.contains(id)).count();
    for p in &old_packs {
        if report.packs.iter().any(|n| n == p.name()) {
            continue; // identical repack
        }
        backend.remove_file(&index_file(&store.pack_dir(), p.name()))?;
        backend.remove_file(&pack_file(&store.pack_dir(), p.name()))?;
    }
    for m in &markers {
        backend.remove_file(&store.keep_marker(m))?;
    }
    report.pending = pending.len();
    write_pending(&*backend, &store.gc_dir(), &pending)?;

    store.invalidate()?;
    let stats = store.stats()?;
    report.bytes_after = stats.loose_bytes + stats.pack_bytes;
    Ok(report)
}
