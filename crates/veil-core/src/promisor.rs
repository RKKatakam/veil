//! Fetch on demand for a thin clone (milestone S3, `docs/HUB.md` §13.21;
//! the client design of `docs/design/scale/6-partial-clone.md` as amended by
//! `docs/design/server/phase-2-thin-clients.md` §4.2).
//!
//! A thin clone (repository format [`crate::repo::PARTIAL_FORMAT`], the
//! `partial` marker in `repo.json`) holds the snapshots it has fetched and
//! the objects it has read. Everything else is on the Veil server.
//!
//! **Two areas.** The main store (`.veil/objects/`) holds what this
//! repository created and every snapshot it fetched; it is never evicted.
//! The cache store (`.veil/cache/`, an [`ObjectStore`] of its own) holds the
//! trees and files fetched from the server, and is the only area ever
//! evicted ([`ObjectStore::trim_cache`]). Local writes never go to the
//! cache: [`ObjectStore::put_raw`] always writes the main store.
//!
//! **The read path.** When neither area holds an object:
//! 1. its *location* is looked up: the snapshot and path where this process
//!    met it, recorded when the tree naming it was decoded (the locator).
//!    The server checks every request against that path in the person's
//!    projection of that snapshot, so the client never asks for anything
//!    it did not meet in a tree the server gave it;
//! 2. the [`Promisor`] asks the server. What arrives is checked against its
//!    BLAKE3 id, decoded, checked storable, then written to the cache;
//! 3. the server's answer "no such object there that you can see" is
//!    [`VeilError::Missing`] (a real redaction). A server that cannot be
//!    reached, or a command with no connection to it, is
//!    [`VeilError::Unavailable`], which no caller takes for a redaction
//!    (threat 1 of the partial-clone design).
//!
//! **Snapshots are never fetched by the read path.** The history index
//! computes a snapshot's generation from all its ancestors, so a snapshot
//! fetched on a miss would make the first graph query fetch the whole
//! history, one request at a time. A snapshot this clone does not hold is
//! beyond its *boundary*: the read is `Missing`, as for every snapshot a
//! replica lacks, and the id is recorded ([`ObjectStore::take_boundary_hits`]).
//! The graph queries whose answer can depend on what lies beyond
//! (`Repo::is_ancestor`, `merge_bases`, `common_ancestor`, `vl log`) run
//! through [`crate::repo::Exact::run`], which fetches the next page of history
//! from the server when a walk reached the boundary and runs the query
//! again.

use std::{
    cell::Cell,
    collections::{HashMap, HashSet},
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex, RwLock,
    },
};

use crate::{
    error::{Result, VeilError},
    id::ObjectId,
    object::{EntryKind, Object},
    store::ObjectStore,
    vfs::NodeKind,
    vpath::VPath,
};

/// Where the cache store lives.
pub const CACHE_DIR: &str = ".veil/cache";

/// Snapshots per page of history a graph query fetches when it reaches
/// the boundary.
pub const HISTORY_PAGE: usize = 2_000;

/// Objects per request when a checkout fetches ahead, and about the most
/// bytes (by the sizes tree entries carry).
const PREFETCH_BATCH: usize = 1_000;
const PREFETCH_BYTES: u64 = 8 << 20;

/// Most places and parents the locator holds together (BUG-1149). Measured
/// with a counting allocator (`core_security` `thin_locator_memory`): about
/// 70 MiB held and 100 MiB at the peak of a rehash, whatever the entries per
/// tree. Every tree met is recorded (a location is the chain of trees
/// above an object); a file is not when the main store's packs hold it
/// (never evicted, BUG-1147). Past the bound, objects met later have no
/// location, and reading one that is not held fails with
/// [`VeilError::Unavailable`], never as hidden.
pub(crate) const LOCATOR_CAP: usize = 1_500_000;

/// Nearest ancestors on the server an object met under a local commit is
/// asked for under.
const SERVER_ANCESTORS: usize = 8;

/// Entry index of a root tree (its parent is a snapshot).
const ROOT: u32 = u32::MAX;
/// Entry index of a conflict's term (its parent is the conflict object,
/// and the term is served at the conflict's path).
const TERM: u32 = u32::MAX - 1;

/// One object to fetch: its id, and where the client met it (a snapshot as
/// the person sees it, and the path in that snapshot's tree).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Located {
    pub id: ObjectId,
    pub snapshot: ObjectId,
    pub path: String,
    /// The same place as a chain of tree ids (S6, the Veil daemon): from
    /// the snapshot's root tree down to the tree (or conflict) naming `id`,
    /// empty for the root tree itself (`hub::grant::Chains`). `None` where
    /// the place was not met in trees (an ancestor's or a tip's path).
    pub chain: Option<Vec<ObjectId>>,
}

/// The connection of a thin clone to its server (`vl` implements it over
/// S1's `fetch` and `history` routes).
pub trait Promisor: Send + Sync {
    /// The objects of `wants`, in order: `Some(bytes)` as received (the
    /// store checks them), `None` where the server answers that it has no
    /// such object at that place that this person may see. An error
    /// ([`VeilError::Unavailable`]) when the server cannot be reached.
    fn fetch(&self, wants: &[Located]) -> Result<Vec<Option<Vec<u8>>>>;

    /// One page of this person's projected history: `tips` and their
    /// ancestors, newest first, at most `limit` snapshots (and every tip).
    /// Tips the server has no snapshot of for this person are left out.
    fn history(&self, tips: &[ObjectId], limit: usize) -> Result<Vec<(ObjectId, Vec<u8>)>>;

    /// Snapshots known to be on the server: the remote's tips as last
    /// pulled. An object met only under a snapshot of this repository's own
    /// (a local commit) is asked for at the same path under these.
    fn server_tips(&self) -> Vec<ObjectId>;

    /// The snapshots of this person's history whose id, or change id,
    /// starts with `prefix` (S3 cycle 3: names held history cannot decide),
    /// as the server's branches reach it, and the snapshots `from` (this
    /// clone's own refs on the server, BUG-1319). `None`: the server cannot
    /// answer (older than protocol revision 5).
    fn resolve(&self, _prefix: &str, _from: &[ObjectId]) -> Result<Option<crate::hub::wire::Resolved>> {
        Ok(None)
    }

    /// The generations of `snapshots` in this person's history, as the
    /// server's viewer graph computes them (the history index's own
    /// arithmetic), each `None` where its history has no such snapshot.
    /// `None`: the server cannot answer (older than protocol revision 6).
    fn generations(&self, _snapshots: &[ObjectId]) -> Result<Option<Vec<Option<u64>>>> {
        Ok(None)
    }
}

/// The location of every object met in a decoded tree, compactly (16 bytes
/// a place): the first 8 bytes of the object's id → the parent (a tree, a
/// snapshot for a root tree, a conflict for its terms) and the entry's index
/// in it. Ids are BLAKE3 hashes, so 8 bytes tell them apart; a collision is
/// harmless: `ObjectStore::locate` checks that the parent names the object
/// there, and treats a mismatch as no place.
///
/// One place an object (the first met, or the one a reader by path set,
/// [`ObjectStore::place_along`]): a reader that knows an entry's path asks
/// at that path itself (`prefetch_diff`, `read_at`), never through here
/// (BUG-1460, BUG-1462, BUG-1463).
#[derive(Default)]
pub(crate) struct Locator {
    parents: Vec<ObjectId>,
    handles: HashMap<u64, u32>,
    at: HashMap<u64, u64>,
}

fn short_key(id: &ObjectId) -> u64 {
    u64::from_le_bytes(id.0[..8].try_into().expect("8 bytes"))
}

impl Locator {
    fn full(&self) -> bool {
        self.at.len() + self.parents.len() >= LOCATOR_CAP
    }

    fn packed(&mut self, parent: ObjectId, index: u32) -> u64 {
        let parents = &mut self.parents;
        let h = *self.handles.entry(short_key(&parent)).or_insert_with(|| {
            parents.push(parent);
            (parents.len() - 1) as u32
        });
        (u64::from(h) << 32) | u64::from(index)
    }

    fn note(&mut self, child: ObjectId, parent: ObjectId, index: u32) {
        let key = short_key(&child);
        if self.full() || self.at.contains_key(&key) {
            return;
        }
        let place = self.packed(parent, index);
        self.at.insert(key, place);
    }

    /// Make `(parent, index)` `child`'s place (a reader by path).
    fn place(&mut self, child: ObjectId, parent: ObjectId, index: u32) {
        let key = short_key(&child);
        if !self.at.contains_key(&key) && self.full() {
            return;
        }
        let place = self.packed(parent, index);
        self.at.insert(key, place);
    }

    fn get(&self, id: &ObjectId) -> Option<(ObjectId, u32)> {
        self.at.get(&short_key(id)).map(|v| (self.parents[(v >> 32) as usize], *v as u32))
    }

    pub(crate) fn len(&self) -> usize {
        self.at.len()
    }
}

/// A locator filled to its bound with `per_tree` entries a tree, for the
/// memory test (`core_security` `thin_locator_memory`).
#[doc(hidden)]
pub struct LocatorProbe(#[allow(dead_code)] Locator);

impl LocatorProbe {
    pub fn fill(per_tree: u64) -> LocatorProbe {
        let id = |i: u64, tag: u8| {
            let mut x = [0u8; 32];
            x[..8].copy_from_slice(&blake3::hash(&i.to_le_bytes()).as_bytes()[..8]);
            x[8..16].copy_from_slice(&i.to_le_bytes());
            x[31] = tag;
            ObjectId(x)
        };
        let mut l = Locator::default();
        let mut i = 0u64;
        while l.at.len() + l.parents.len() < LOCATOR_CAP {
            l.note(id(i, 0), id(i / per_tree + (1 << 40), 1), (i % per_tree) as u32);
            i += 1;
        }
        LocatorProbe(l)
    }

    pub fn places(&self) -> usize {
        self.0.len()
    }
}

/// The thin-clone state of a main store.
pub(crate) struct Partial {
    pub(crate) cache: Arc<ObjectStore>,
    limit: AtomicU64,
    promisor: RwLock<Option<Arc<dyn Promisor>>>,
    locator: Mutex<Locator>,
    /// Snapshots a read missed since the last [`ObjectStore::take_boundary_hits`].
    hits: Mutex<HashSet<ObjectId>>,
    /// Store-wide "never fetch" (gc, fsck and maintenance, which run alone).
    no_fetch: AtomicUsize,
    /// Bytes in the cache area, once measured.
    bytes: Mutex<Option<u64>>,
    /// Snapshots whose trees are pinned: each workspace's working copy
    /// (set by the repository from its view).
    anchors: RwLock<Vec<ObjectId>>,
    /// The view's heads and tags, and the remotes' tips: the server-side
    /// bases of the snapshots only this clone holds have their *trees*
    /// pinned, so that gc and fsck can always tell a gap of the server's
    /// from lost work (BUG-1148).
    local: RwLock<(Vec<ObjectId>, Vec<ObjectId>)>,
    /// Snapshots found to be on the server (memo of `on_server`), and
    /// whether that set is whole for the snapshots held now.
    server: Mutex<HashSet<ObjectId>>,
    server_walked: std::sync::atomic::AtomicBool,
    /// Objects fetched on demand by this process.
    fetched: AtomicU64,
    /// Bytes fetched into a batch not yet on disk: counted in the bound.
    in_flight: AtomicU64,
    /// Snapshots the server has no page of history for (no further asks).
    refused: Mutex<HashSet<ObjectId>>,
    /// Parents of the held snapshots this process decoded that the main
    /// store did not hold then: history *below* what the clone holds, which
    /// a page may always bring (BUG-1319). Any other snapshot read is a
    /// name ([`crate::Repo::deepen`]).
    below: Mutex<HashSet<ObjectId>>,
}

thread_local! {
    /// Per-thread "never fetch" (the anchor walk of an eviction).
    static NO_FETCH: Cell<u32> = const { Cell::new(0) };
}

/// What [`ObjectStore::cache_usage`] reports.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CacheUsage {
    pub bytes: u64,
    pub limit: u64,
    pub loose: usize,
    pub packs: usize,
    /// Bytes of the cache's objects that what is checked out pins.
    pub pinned: u64,
}

/// What [`ObjectStore::trim_cache`] did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Trim {
    pub before: u64,
    pub after: u64,
    pub removed: usize,
    /// Over the limit with nothing left to evict: everything left is pinned.
    pub full: bool,
}

/// One file of the cache area.
enum Unit {
    Loose(ObjectId),
    Pack(String),
}

impl ObjectStore {
    /// Make this (main) store a thin clone's: objects it lacks are read
    /// from the cache store at `cache_root`, then fetched through the
    /// promisor once one is attached ([`ObjectStore::set_promisor`]).
    pub fn set_partial(&self, cache_root: VPath, limit: u64) {
        let cache = Arc::new(ObjectStore::new(self.backend().clone(), cache_root, self.keys.clone()));
        cache.set_format(self.format());
        let _ = self.partial.set(Arc::new(Partial {
            cache,
            limit: AtomicU64::new(limit),
            promisor: RwLock::new(None),
            locator: Mutex::new(Locator::default()),
            hits: Mutex::new(HashSet::new()),
            no_fetch: AtomicUsize::new(0),
            bytes: Mutex::new(None),
            anchors: RwLock::new(Vec::new()),
            local: RwLock::new((Vec::new(), Vec::new())),
            server: Mutex::new(HashSet::new()),
            server_walked: std::sync::atomic::AtomicBool::new(false),
            fetched: AtomicU64::new(0),
            in_flight: AtomicU64::new(0),
            refused: Mutex::new(HashSet::new()),
            below: Mutex::new(HashSet::new()),
        }));
    }

    /// Is this a thin clone's store?
    pub fn is_partial(&self) -> bool {
        self.partial.get().is_some()
    }

    /// The cache store of a thin clone (where fetched objects go).
    pub fn cache(&self) -> Option<&Arc<ObjectStore>> {
        self.partial.get().map(|p| &p.cache)
    }

    /// Attach the connection to the server. Without one, a read that needs
    /// the server fails with [`VeilError::Unavailable`].
    pub fn set_promisor(&self, promisor: Arc<dyn Promisor>) {
        if let Some(p) = self.partial.get() {
            *p.promisor.write().unwrap_or_else(|e| e.into_inner()) = Some(promisor);
            self.forget_server_walk();
        }
    }

    pub fn promisor(&self) -> Option<Arc<dyn Promisor>> {
        self.partial.get().and_then(|p| p.promisor.read().unwrap_or_else(|e| e.into_inner()).clone())
    }

    /// The cache's bound in bytes.
    pub fn cache_limit(&self) -> Option<u64> {
        self.partial.get().map(|p| p.limit.load(Ordering::Relaxed))
    }

    pub fn set_cache_limit(&self, limit: u64) {
        if let Some(p) = self.partial.get() {
            p.limit.store(limit, Ordering::Relaxed);
        }
    }

    /// Objects fetched on demand by this process.
    pub fn fetched_on_demand(&self) -> u64 {
        self.partial.get().map_or(0, |p| p.fetched.load(Ordering::Relaxed))
    }

    /// Run `f` with fetching off on this thread: its reads of what neither
    /// area holds are `Missing` (gc and maintenance, for which an unfetched
    /// object is on the server, never local work; a look at what the clone
    /// holds). **This thread only** (BUG-1366): another thread reading the
    /// same store meanwhile fetches as ever, and never takes a file the
    /// server serves for hidden. Every caller reads the store on the thread
    /// that called it (gc's packing threads only encode what they are
    /// handed).
    pub fn without_fetching<R>(&self, f: impl FnOnce() -> R) -> R {
        NO_FETCH.with(|c| c.set(c.get() + 1));
        struct Undo;
        impl Drop for Undo {
            fn drop(&mut self) {
                NO_FETCH.with(|c| c.set(c.get() - 1));
            }
        }
        let _undo = Undo;
        f()
    }

    /// Never fetch from this store, on any thread: only for a store no one
    /// else reads (`fsck`'s own, opened for the check).
    pub fn never_fetch(&self) {
        if let Some(p) = self.partial.get() {
            p.no_fetch.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn fetching(&self, p: &Partial) -> bool {
        p.no_fetch.load(Ordering::SeqCst) == 0 && NO_FETCH.with(|c| c.get() == 0)
    }

    /// May a read of this thin clone's store fetch now (not in gc, fsck,
    /// maintenance or an eviction's walk)? `false` for any other store.
    pub fn may_fetch(&self) -> bool {
        self.partial.get().is_some_and(|p| self.fetching(p))
    }

    /// Has the server said it has no history for snapshot `id` (so a read
    /// of it is not asked again)? Records the answer with `refused`.
    pub(crate) fn history_refused(&self, id: &ObjectId, refused: bool) -> bool {
        let Some(p) = self.partial.get() else { return false };
        let mut r = p.refused.lock().unwrap_or_else(|e| e.into_inner());
        if refused {
            r.insert(*id);
        }
        r.contains(id)
    }

    /// A held snapshot was decoded: its parents the main store lacks are
    /// below what the clone holds.
    pub(crate) fn note_held_snapshot(&self, s: &crate::object::Snapshot) {
        let Some(p) = self.partial.get() else { return };
        let lacking: Vec<ObjectId> = s.parents.iter().filter(|x| !self.has_main(x)).copied().collect();
        if !lacking.is_empty() {
            p.below.lock().unwrap_or_else(|e| e.into_inner()).extend(lacking);
        }
    }

    /// Is `id` a parent of a held snapshot (history below what the clone
    /// holds, [`ObjectStore::note_held_snapshot`])?
    pub(crate) fn is_below_held(&self, id: &ObjectId) -> bool {
        self.partial.get().is_some_and(|p| p.below.lock().unwrap_or_else(|e| e.into_inner()).contains(id))
    }

    /// Put back boundary hits taken for a nested walk.
    pub(crate) fn restore_boundary_hits(&self, ids: Vec<ObjectId>) {
        if let Some(p) = self.partial.get() {
            p.hits.lock().unwrap_or_else(|e| e.into_inner()).extend(ids);
        }
    }

    /// The snapshots reads missed since the last call: the boundary a graph
    /// walk reached ([`crate::repo::Exact::run`]).
    pub fn take_boundary_hits(&self) -> Vec<ObjectId> {
        let Some(p) = self.partial.get() else { return Vec::new() };
        let mut h = p.hits.lock().unwrap_or_else(|e| e.into_inner());
        let mut out: Vec<ObjectId> = h.drain().collect();
        out.sort();
        out
    }

    /// The snapshots whose working copies are pinned (never evicted).
    pub fn set_anchor_snapshots(&self, ids: Vec<ObjectId>) {
        if let Some(p) = self.partial.get() {
            *p.anchors.write().unwrap_or_else(|e| e.into_inner()) = ids;
        }
    }

    /// The view's heads and tags (`heads`) and the remotes' tips
    /// (`server`), for the trees eviction pins (BUG-1148).
    pub fn set_local_heads(&self, heads: Vec<ObjectId>, server: Vec<ObjectId>) {
        if let Some(p) = self.partial.get() {
            let changed = p.local.read().unwrap_or_else(|e| e.into_inner()).1 != server;
            *p.local.write().unwrap_or_else(|e| e.into_inner()) = (heads, server);
            if changed {
                self.forget_server_walk();
            }
        }
    }

    /// The heads, working copies and tags of every operation's view (gc's
    /// roots; read here, at an eviction, which is rare).
    pub(crate) fn op_log_heads(&self) -> Vec<ObjectId> {
        let ops = crate::oplog::OpStore::new(self.backend().clone());
        ops.set_format(self.format());
        let Ok(raw) = ops.raw_heads() else { return Vec::new() };
        let mut out = Vec::new();
        for op in ops.walk(&raw.all) {
            let Ok((_, op)) = op else { continue };
            out.extend(op.view.heads.iter().copied());
            out.extend(op.view.workspaces.values().map(|w| w.wc));
            out.extend(op.view.tags.values().map(|t| t.target));
        }
        out.sort();
        out.dedup();
        out
    }

    /// The snapshots on the server that this clone's own snapshots (those
    /// `heads` reach outside `server`'s history) build on.
    fn server_bases(&self, heads: &[ObjectId], server: &HashSet<ObjectId>) -> Vec<ObjectId> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        let mut stack: Vec<ObjectId> = heads.iter().filter(|h| !server.contains(h)).copied().collect();
        while let Some(x) = stack.pop() {
            if !seen.insert(x) || seen.len() > 10_000 {
                continue;
            }
            let Ok(s) = self.snapshot(&x) else { continue };
            for parent in &s.parents {
                match server.contains(parent) {
                    true if !out.contains(parent) => out.push(*parent),
                    true => {}
                    false => stack.push(*parent),
                }
            }
        }
        self.take_boundary_hits_of(&seen);
        out
    }

    /// Record where the objects `obj` names were met (thin clones only).
    pub(crate) fn note_decoded(&self, id: &ObjectId, obj: &Object) {
        let Some(p) = self.partial.get() else { return };
        if let Object::Tree(_) = obj {
            let _ = (self.ensure_packs(), p.cache.ensure_packs());
        }
        let mut l = p.locator.lock().unwrap_or_else(|e| e.into_inner());
        match obj {
            Object::Tree(t) => {
                for (i, e) in t.entries.iter().enumerate() {
                    // A file the main store's packs hold (never evicted)
                    // needs no place; one in the cache may be evicted and
                    // read again (BUG-1147); a tree always needs one (it is
                    // on the way to what is below it).
                    if e.kind != EntryKind::Dir && self.in_loaded_packs(&e.id) {
                        continue;
                    }
                    l.note(e.id, *id, i as u32);
                }
            }
            Object::Snapshot(s) => l.note(s.tree, *id, ROOT),
            Object::Conflict(c) => {
                for t in c.referenced_ids() {
                    l.note(t, *id, TERM);
                }
            }
            _ => {}
        }
    }

    /// Where `id` was met: a snapshot, the path in its tree, and the chain
    /// of trees from its root ([`Located::chain`]).
    fn locate(&self, p: &Partial, id: &ObjectId) -> Result<Option<(ObjectId, String, Vec<ObjectId>)>> {
        let first = p.locator.lock().unwrap_or_else(|e| e.into_inner()).get(id);
        match first {
            Some(place) => self.climb(p, *id, place),
            None => Ok(None),
        }
    }

    /// The `(snapshot, path, chain)` of `id` met at `first`: up through its
    /// parents' first places.
    fn climb(&self, p: &Partial, id: ObjectId, first: (ObjectId, u32)) -> Result<Option<(ObjectId, String, Vec<ObjectId>)>> {
        let mut names: Vec<String> = Vec::new();
        let mut chain: Vec<ObjectId> = Vec::new();
        let mut cur = id;
        let mut next = Some(first);
        for _ in 0..=crate::tree::MAX_TREE_DEPTH + 2 {
            let found = match next.take() {
                Some(f) => Some(f),
                None => p.locator.lock().unwrap_or_else(|e| e.into_inner()).get(&cur),
            };
            let Some((parent, index)) = found else { return Ok(None) };
            match index {
                ROOT => {
                    // The snapshot names this root tree (an 8-byte key may
                    // name another object).
                    if self.snapshot(&parent).map_or(true, |s| s.tree != cur) {
                        return Ok(None);
                    }
                    names.reverse();
                    chain.reverse();
                    return Ok(Some((parent, names.join("/"), chain)));
                }
                TERM => {
                    if self.conflict(&parent).map_or(true, |c| !c.referenced_ids().contains(&cur)) {
                        return Ok(None);
                    }
                    chain.push(parent);
                    cur = parent
                }
                i => {
                    // The parent tree was decoded here; it may have been
                    // evicted since, and is fetched again from its own
                    // location.
                    let t = self.tree_object(&parent)?;
                    let Some(e) = t.entries.get(i as usize).filter(|e| e.id == cur) else { return Ok(None) };
                    names.push(e.name.clone());
                    chain.push(parent);
                    cur = parent;
                }
            }
        }
        Ok(None)
    }

    /// Is snapshot `s` on the server: one of its tips as last pulled, or
    /// an ancestor of one that this clone holds?
    fn on_server(&self, p: &Partial, promisor: &dyn Promisor, s: &ObjectId) -> bool {
        if p.server.lock().unwrap_or_else(|e| e.into_inner()).contains(s) {
            return true;
        }
        // Walked since the last snapshots arrived: the set is whole for
        // what the tips reach; the server may still know it.
        if p.server_walked.load(Ordering::SeqCst) {
            return self.server_knows(p, promisor, s);
        }
        let mut seen = HashSet::new();
        let mut stack = self.server_tips_now(p, promisor);
        let mut found = false;
        while let Some(x) = stack.pop() {
            if !seen.insert(x) {
                continue;
            }
            found |= x == *s;
            if let Ok(snap) = self.snapshot(&x) {
                stack.extend(snap.parents.iter().copied());
            }
        }
        // The walk read only snapshots this clone holds: no boundary hits
        // for the queries that are running.
        let _ = self.take_boundary_hits_of(&seen);
        p.server.lock().unwrap_or_else(|e| e.into_inner()).extend(seen);
        p.server_walked.store(true, Ordering::SeqCst);
        found || self.server_knows(p, promisor, s)
    }

    /// Does the server know snapshot `s` for this person, whatever the view
    /// this clone met it in? The tips reach only the current view's history:
    /// after an access change (and a pull), snapshots of the view before it
    /// are reached by no tip, yet the server resolves them through the real
    /// snapshot and answers for them, so an empty answer under one is its
    /// refusal there, never "the server has no copy" (BUG-1530). Its history
    /// answers for a snapshot it knows; nothing for a commit only this clone
    /// holds. One request a snapshot, remembered for the process.
    fn server_knows(&self, p: &Partial, promisor: &dyn Promisor, s: &ObjectId) -> bool {
        if p.refused.lock().unwrap_or_else(|e| e.into_inner()).contains(s) {
            return false;
        }
        match promisor.history(&[*s], 1) {
            Ok(page) if !page.is_empty() => {
                p.server.lock().unwrap_or_else(|e| e.into_inner()).insert(*s);
                true
            }
            Ok(_) => {
                p.refused.lock().unwrap_or_else(|e| e.into_inner()).insert(*s);
                false
            }
            // Not reached: not known, and the read that asked says so.
            Err(_) => false,
        }
    }

    /// The remotes' tips as the view has them now (every view change sets
    /// them: a pull in a long-lived process is seen at once), else the
    /// promisor's.
    fn server_tips_now(&self, p: &Partial, promisor: &dyn Promisor) -> Vec<ObjectId> {
        let tips = p.local.read().unwrap_or_else(|e| e.into_inner()).1.clone();
        match tips.is_empty() {
            true => promisor.server_tips(),
            false => tips,
        }
    }

    /// Snapshots arrived (history pages, a pull): `on_server` walks again.
    pub fn forget_server_walk(&self) {
        if let Some(p) = self.partial.get() {
            p.server_walked.store(false, Ordering::SeqCst);
        }
    }

    /// The nearest ancestors of local snapshot `s` (this clone's own
    /// commits) that are on the server, from what this clone holds.
    fn server_ancestors(&self, p: &Partial, promisor: &dyn Promisor, s: &ObjectId) -> Vec<ObjectId> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        let mut queue = std::collections::VecDeque::from([*s]);
        while let Some(x) = queue.pop_front() {
            if out.len() >= SERVER_ANCESTORS || !seen.insert(x) || seen.len() > 10_000 {
                break;
            }
            let Ok(snap) = self.snapshot(&x) else { continue };
            for parent in &snap.parents {
                if self.on_server(p, promisor, parent) {
                    out.push(*parent);
                } else {
                    queue.push_back(*parent);
                }
            }
        }
        self.take_boundary_hits_of(&seen);
        out
    }

    /// Forget the boundary hit of `id` (fetched where it was read).
    pub(crate) fn take_boundary_hits_of_one(&self, id: &ObjectId) -> usize {
        self.take_boundary_hits_of(&HashSet::from([*id]))
    }

    fn take_boundary_hits_of(&self, ids: &HashSet<ObjectId>) -> usize {
        let Some(p) = self.partial.get() else { return 0 };
        let mut h = p.hits.lock().unwrap_or_else(|e| e.into_inner());
        let before = h.len();
        h.retain(|x| !ids.contains(x));
        before - h.len()
    }

    /// A read neither area of a thin clone's store could answer.
    /// `snapshot`: the reader asked for a snapshot.
    ///
    /// **Where `Missing` comes from** (BUG-1142): only (1) the server's own
    /// answer that it has nothing at the object's place that this person may
    /// see, under a snapshot that is on the server, and (2) a snapshot this
    /// clone does not hold (its boundary, recorded for [`crate::repo::Exact::run`];
    /// [`crate::repo::Exact::snapshot`] fetches history there). A tree or file
    /// whose place this process does not know is `Unavailable`.
    pub(crate) fn read_partial(&self, id: &ObjectId, snapshot: bool) -> Result<Vec<u8>> {
        let p = self.partial.get().expect("a thin clone's store");
        match p.cache.read_raw(id) {
            Ok(raw) => return Ok(raw),
            Err(VeilError::Missing(_)) => {}
            // A damaged cached copy (a torn write, a flipped byte) is
            // dropped and fetched again: the cache holds only what the
            // server has.
            Err(VeilError::Corrupt(..)) => {
                let _ = p.cache.backend().remove_file(&p.cache.loose_path(id));
            }
            Err(e) => return Err(e),
        }
        if !self.fetching(p) {
            return Err(VeilError::Missing(*id));
        }
        let wanted_snapshot = snapshot;
        let Some((snapshot, path, chain)) = self.locate(p, id)? else {
            if wanted_snapshot {
                // A snapshot beyond the boundary: recorded for `Repo::exact`.
                p.hits.lock().unwrap_or_else(|e| e.into_inner()).insert(*id);
                return Err(VeilError::Missing(*id));
            }
            // Never hidden for want of a place: the server may well serve it.
            return Err(VeilError::Unavailable(
                "an object this thin clone has not fetched, met where this command did not record its place; run the command again"
                    .into(),
            ));
        };
        let shown = if path.is_empty() { "/".to_string() } else { path.clone() };
        let Some(promisor) = self.promisor() else {
            return Err(VeilError::Unavailable(format!(
                "'{shown}' is not fetched yet, and this command has no connection to the server of this thin clone"
            )));
        };
        let mut got = promisor.fetch(&[Located { id: *id, snapshot, path: path.clone(), chain: Some(chain) }])?.pop().flatten();
        // Refused at a place on the server whose own tree (as this clone
        // holds it) names this very object there: the server's "not yours"
        // for it, as much as under a snapshot on the server (milestone S8:
        // access removed while a workspace on a local change was mounted).
        let mut refused_there = false;
        if got.is_none() && !self.on_server(p, &*promisor, &snapshot) {
            // Met under a snapshot the server does not have (a local
            // commit): ask at the same path under its nearest ancestors on
            // the server (BUG-1144), then under the server's tips.
            let mut places = self.server_ancestors(p, &*promisor, &snapshot);
            for t in self.server_tips_now(p, &*promisor) {
                if !places.contains(&t) {
                    places.push(t);
                }
            }
            for t in places {
                got = promisor.fetch(&[Located { id: *id, snapshot: t, path: path.clone(), chain: self.chain_held(&t, &path, id) }])?.pop().flatten();
                if got.is_some() {
                    break;
                }
                refused_there |= self.names_held(&t, &path, id);
            }
        }
        let Some(raw) = got else {
            if refused_there || self.on_server(p, &*promisor, &snapshot) {
                // The server's own answer: nothing there that this person
                // may see.
                return Err(VeilError::Missing(*id));
            }
            return Err(VeilError::Unavailable(format!(
                "'{shown}' is not fetched, and the server has no copy of it where this clone met it; run `vl pull`, or `vl partial full`"
            )));
        };
        self.keep_fetched(p, id, &raw)?;
        p.fetched.fetch_add(1, Ordering::Relaxed);
        Ok(raw)
    }

    /// The chain of trees from snapshot `snap`'s root to the tree naming
    /// `id` at `path` ([`Located::chain`]), as far as this clone holds its
    /// trees (nothing is fetched to tell); `None` if they do not name it.
    fn chain_held(&self, snap: &ObjectId, path: &str, id: &ObjectId) -> Option<Vec<ObjectId>> {
        self.without_fetching(|| {
            let s = self.snapshot(snap).ok()?;
            let mut chain = Vec::new();
            let mut cur = s.tree;
            if !path.is_empty() {
                for name in VPath::new(path).ok()?.components() {
                    let t = self.tree_object(&cur).ok()?;
                    let e = t.entries.iter().find(|e| e.name == name)?;
                    chain.push(cur);
                    cur = e.id;
                }
            }
            if cur == *id {
                return Some(chain);
            }
            // A conflict's term, served at the conflict's path: the chain
            // ends with the conflict object.
            let c = self.conflict(&cur).ok()?;
            c.referenced_ids().contains(id).then(|| {
                chain.push(cur);
                chain
            })
        })
    }

    /// Does snapshot `snap`'s tree name `id` at `path`, as far as this clone
    /// holds its trees (nothing is fetched to tell)?
    fn names_held(&self, snap: &ObjectId, path: &str, id: &ObjectId) -> bool {
        self.without_fetching(|| {
            let Ok(s) = self.snapshot(snap) else { return false };
            if path.is_empty() {
                return s.tree == *id;
            }
            let Ok(vp) = VPath::new(path) else { return false };
            matches!(crate::tree::lookup(self, &s.tree, &vp), Ok(Some(e)) if e.id == *id)
        })
    }

    /// Before a thin clone's working copy moves from tree `from` to `to`:
    /// fetch what the move reads (the trees and files that differ, by
    /// path, a level at a time, in batches), so that a server that cannot
    /// be reached fails the move before it writes anything, even its
    /// journal (threat 12). Nothing for any other store.
    pub fn prefetch_diff(&self, from: Option<&ObjectId>, to: &ObjectId) -> Result<()> {
        let Some(p) = self.partial.get() else { return Ok(()) };
        if !self.fetching(p) {
            return Ok(());
        }
        let at = self.locate(p, to)?.map(|(snapshot, path, _)| (snapshot, path));
        self.prefetch_diff_from(p, from, to, at)
    }

    /// [`ObjectStore::prefetch_diff`] of `to`, the folder at `path` below
    /// `root` (a snapshot's tree): asked for at that path, wherever the
    /// locator met the same folder first (a sparse sandbox's `--only`).
    pub fn prefetch_diff_below(&self, from: Option<&ObjectId>, to: &ObjectId, root: &ObjectId, path: &VPath) -> Result<()> {
        let Some(p) = self.partial.get() else { return Ok(()) };
        if !self.fetching(p) {
            return Ok(());
        }
        let at = self
            .locate(p, root)?
            .map(|(snapshot, base, _)| (snapshot, if base.is_empty() { path.as_str().to_string() } else { format!("{base}/{path}") }));
        self.prefetch_diff_from(p, from, to, at)
    }

    /// The walk knows every entry's path below `to`'s place `at`: each
    /// object is asked for at its own paths, never at the place the locator
    /// met it first (BUG-1460, BUG-1462, BUG-1463). Without a place for
    /// `to`, by id, through the locator.
    fn prefetch_diff_from(&self, p: &Partial, from: Option<&ObjectId>, to: &ObjectId, at: Option<(ObjectId, String)>) -> Result<()> {
        let mut level: Vec<(Option<ObjectId>, ObjectId, String)> = vec![(from.copied(), *to, at.as_ref().map(|(_, b)| b.clone()).unwrap_or_default())];
        let ensure = |items: Vec<(ObjectId, u64, String)>| -> Result<()> {
            match &at {
                Some((snapshot, _)) => self.ensure_at_paths(p, *snapshot, items),
                None => self.ensure_held(p, items.into_iter().map(|(id, size, _)| (id, size)).collect()),
            }
        };
        let join = |dir: &str, name: &str| if dir.is_empty() { name.to_string() } else { format!("{dir}/{name}") };
        while !level.is_empty() {
            ensure(level.iter().map(|(_, t, path)| (*t, 0, path.clone())).collect())?;
            let mut next = Vec::new();
            let mut files = Vec::new();
            for (f, t, path) in level {
                if Some(t) == f {
                    continue;
                }
                let tt = match self.tree_object(&t) {
                    Ok(tt) => tt,
                    // Not there for this person: the checkout leaves it out.
                    Err(VeilError::Missing(_)) => continue,
                    Err(e) => return Err(e),
                };
                let ft = f.and_then(|f| self.tree_object(&f).ok());
                for e in &tt.entries {
                    let old = ft.as_ref().and_then(|ft| ft.get(&e.name));
                    if old.is_some_and(|o| o.id == e.id) {
                        continue;
                    }
                    match e.kind {
                        EntryKind::Dir => next.push((old.filter(|o| o.kind == EntryKind::Dir).map(|o| o.id), e.id, join(&path, &e.name))),
                        _ => files.push((e.id, e.size, join(&path, &e.name))),
                    }
                }
            }
            ensure(files.clone())?;
            // A conflict's terms are read too.
            let mut terms = Vec::new();
            for (id, _, _) in files {
                if let Ok(Object::Conflict(c)) = self.get(&id) {
                    terms.extend(c.referenced_ids().into_iter().map(|t| (t, 0)));
                }
            }
            self.ensure_held(p, terms)?;
            level = next;
        }
        Ok(())
    }

    /// Fetch `items` (`(id, size, path)`, all under `snapshot`) that neither
    /// area holds, each at its own path: the same object at several paths
    /// is asked for at the first of them, and, refused there, at the next,
    /// round after round, in batches. One refused at every path is left for
    /// its reader, who finds it hidden.
    fn ensure_at_paths(&self, p: &Partial, snapshot: ObjectId, items: Vec<(ObjectId, u64, String)>) -> Result<()> {
        let _ = (self.ensure_packs(), p.cache.ensure_packs());
        let mut by_id: Vec<(ObjectId, u64, Vec<String>)> = Vec::new();
        let mut index: HashMap<ObjectId, usize> = HashMap::new();
        for (id, size, path) in items {
            if self.in_loaded_packs(&id) || p.cache.in_loaded_packs(&id) || self.has(&id) {
                continue;
            }
            match index.get(&id) {
                Some(i) => by_id[*i].2.push(path),
                None => {
                    index.insert(id, by_id.len());
                    by_id.push((id, size, vec![path]));
                }
            }
        }
        if by_id.is_empty() {
            return Ok(());
        }
        let Some(promisor) = self.promisor() else {
            return Err(VeilError::Unavailable(
                "this checkout needs what this thin clone has not fetched, and this command has no connection to its server".into(),
            ));
        };
        let mut round = 0;
        while !by_id.is_empty() {
            let wants: Vec<(Located, u64)> = by_id
                .iter()
                .filter_map(|(id, size, paths)| paths.get(round).map(|path| (Located { id: *id, snapshot, path: path.clone(), chain: None }, *size)))
                .collect();
            if wants.is_empty() {
                break;
            }
            let refused: HashSet<ObjectId> = self.fetch_batches(p, &*promisor, wants)?.into_iter().map(|w| w.id).collect();
            by_id.retain(|(id, _, _)| refused.contains(id));
            round += 1;
        }
        Ok(())
    }

    /// Can this reader materialise entry `e`? As
    /// [`ObjectStore::entry_readable`], except that in a thin clone a folder,
    /// or a file not labelled secret, that is not fetched yet counts as
    /// shown, without fetching it to decide: the tree is the server's
    /// projection for this person, and the object decides when something
    /// reads it (a secret this reader cannot open is refused then). A file
    /// labelled secret is decided by its object, as everywhere. Mounts,
    /// sparse sandboxes and the builder's carrying of what a working copy
    /// does not show use this one rule (milestone S8).
    pub fn entry_shown(&self, e: &crate::object::TreeEntry) -> bool {
        if self.is_partial() && !self.has(&e.id) {
            match e.kind {
                EntryKind::Dir => return true,
                EntryKind::File | EntryKind::Symlink if e.visibility.key_scope().is_none() => return true,
                _ => {}
            }
        }
        self.entry_readable(e)
    }

    /// Read what is at `path` below `root` (a tree of this clone) at that
    /// place: record each tree on the way, and the entry at its end, at
    /// this path, replacing where they were met first. The same object
    /// can be at several paths (an empty `__init__.py`, a copied folder),
    /// and the server decides by path: one refused at the place it was met
    /// first is asked for where it is read (BUG-1367). Trees on the way are
    /// read as held (nothing is fetched to tell).
    pub fn place_along(&self, root: &ObjectId, path: &VPath) {
        let Some(p) = self.partial.get() else { return };
        let mut tree = *root;
        for name in path.components() {
            let Ok(t) = self.without_fetching(|| self.tree_object(&tree)) else { return };
            let Some((i, e)) = t.entries.iter().enumerate().find(|(_, e)| e.name == name) else { return };
            p.locator.lock().unwrap_or_else(|e| e.into_inner()).place(e.id, tree, i as u32);
            if e.kind != EntryKind::Dir {
                return;
            }
            tree = e.id;
        }
    }

    /// Fetch the entries at `paths` below `root` (a tree of this clone)
    /// that neither area holds, in batches, each asked for at its own path
    /// (a mounted workspace's folder, when one of its files is first read;
    /// a sparse sandbox's paths). One the server refuses there is left for
    /// its reader, who finds it hidden. Nothing for any other store.
    pub fn prefetch_at(&self, root: &ObjectId, paths: &[(VPath, ObjectId, u64)]) -> Result<()> {
        let Some(p) = self.partial.get() else { return Ok(()) };
        if !self.fetching(p) {
            return Ok(());
        }
        match self.locate(p, root)? {
            Some((snapshot, base, _)) => {
                let join = |rel: &VPath| if base.is_empty() { rel.as_str().to_string() } else { format!("{base}/{rel}") };
                self.ensure_at_paths(p, snapshot, paths.iter().map(|(path, id, size)| (*id, *size, join(path))).collect())
            }
            None => {
                for (path, _, _) in paths {
                    self.place_along(root, path);
                }
                self.ensure_held(p, paths.iter().map(|(_, id, size)| (*id, *size)).collect())
            }
        }
    }

    /// `id` asked for at `(snapshot, path)` only: under the snapshot, or, if
    /// it is a local change, at the same path under its nearest ancestors
    /// on the server (BUG-1144). The object, or whether the server refused
    /// it there.
    fn fetch_here(&self, p: &Partial, promisor: &dyn Promisor, id: &ObjectId, snapshot: ObjectId, path: &str) -> Result<(Option<Vec<u8>>, bool)> {
        let mut got = promisor.fetch(&[Located { id: *id, snapshot, path: path.to_string(), chain: self.chain_held(&snapshot, path, id) }])?.pop().flatten();
        let mut refused = got.is_none() && self.on_server(p, promisor, &snapshot);
        if got.is_none() && !refused {
            for t in self.server_ancestors(p, promisor, &snapshot) {
                got = promisor.fetch(&[Located { id: *id, snapshot: t, path: path.to_string(), chain: self.chain_held(&t, path, id) }])?.pop().flatten();
                if got.is_some() {
                    break;
                }
                refused |= self.names_held(&t, path, id);
            }
        }
        Ok((got, refused))
    }

    /// The object at `path` below `root` (a tree of this clone): held, as
    /// it is (content already on this machine reads at every path naming
    /// it, BUG-1464); else asked of the server at that place and nowhere
    /// else (the mount's read: the server decides by path, BUG-1460). The
    /// server's refusal there is `Missing`; no answer is `Unavailable`.
    pub fn read_at(&self, id: &ObjectId, root: &ObjectId, path: &VPath) -> Result<Vec<u8>> {
        let Some(p) = self.partial.get() else { return self.read_raw(id) };
        if self.has(id) {
            return self.read_raw(id);
        }
        if !self.fetching(p) {
            return Err(VeilError::Missing(*id));
        }
        self.place_along(root, path);
        let Some((snapshot, at, _)) = self.locate(p, id)?.filter(|(_, at, _)| at == path.as_str()) else {
            return Err(VeilError::Unavailable(format!("'{path}': its place could not be told; run the command again")));
        };
        let Some(promisor) = self.promisor() else {
            return Err(VeilError::Unavailable(format!("'{path}' needs the server of this thin clone, and this command has no connection to it")));
        };
        let (got, refused) = self.fetch_here(p, &*promisor, id, snapshot, &at)?;
        match got {
            Some(raw) => {
                if !self.has(id) {
                    self.keep_fetched(p, id, &raw)?;
                    p.fetched.fetch_add(1, Ordering::Relaxed);
                }
                Ok(raw)
            }
            None if refused => Err(VeilError::Missing(*id)),
            None => Err(VeilError::Unavailable(format!(
                "'{path}' is not fetched, and the server has no copy of it there; run `vl pull`, or `vl partial full`"
            ))),
        }
    }

    /// Fetch those of `ids` neither area holds, in batches of their
    /// locations; one the server refuses is left for its reader (who finds
    /// it hidden), one without a location is read the ordinary way.
    /// `ids` with the sizes tree entries give them (0 where unknown).
    fn ensure_held(&self, p: &Partial, ids: Vec<(ObjectId, u64)>) -> Result<()> {
        let _ = (self.ensure_packs(), p.cache.ensure_packs());
        let missing: Vec<(ObjectId, u64)> = ids
            .into_iter()
            .filter(|(id, _)| !(self.in_loaded_packs(id) || p.cache.in_loaded_packs(id) || self.has(id)))
            .collect();
        if missing.is_empty() {
            return Ok(());
        }
        let Some(promisor) = self.promisor() else {
            return Err(VeilError::Unavailable(
                "this checkout needs what this thin clone has not fetched, and this command has no connection to its server".into(),
            ));
        };
        let mut wants = Vec::new();
        for (id, size) in missing {
            match self.locate(p, &id)? {
                Some((snapshot, path, chain)) => wants.push((Located { id, snapshot, path, chain: Some(chain) }, size)),
                // Read the ordinary way: `Unavailable` (never hidden).
                None => {
                    self.read_raw(&id)?;
                }
            }
        }
        // Asked again the ordinary way (under a local commit's other
        // ancestors and the server's tips), then `Missing` (hidden) or
        // `Unavailable`.
        for w in self.fetch_batches(p, &*promisor, wants)? {
            match self.read_raw(&w.id) {
                Ok(_) | Err(VeilError::Missing(_)) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Fetch `wants` (each at its place, with the size its tree entry
    /// gives) in batches: what the server refused there. A place under a
    /// local change (a workspace's own `@`) is asked for under its nearest
    /// ancestor on the server whose held tree names the same object there:
    /// the server answers the batch at once instead of refusing it.
    fn fetch_batches(&self, p: &Partial, promisor: &dyn Promisor, wants: Vec<(Located, u64)>) -> Result<Vec<Located>> {
        let mut on_server: HashMap<ObjectId, Vec<ObjectId>> = HashMap::new();
        let mut wants: Vec<(Located, u64)> = wants
            .into_iter()
            .map(|(w, size)| {
                let ancestors = on_server.entry(w.snapshot).or_insert_with(|| match self.on_server(p, promisor, &w.snapshot) {
                    true => vec![w.snapshot],
                    false => self.server_ancestors(p, promisor, &w.snapshot),
                });
                let snapshot = ancestors.iter().copied().find(|a| *a == w.snapshot || self.names_held(a, &w.path, &w.id)).unwrap_or(w.snapshot);
                // The chain the Veil daemon checks (S6), from the snapshot
                // asked under, as this clone holds its trees.
                let chain = match (&w.chain, snapshot == w.snapshot) {
                    (Some(c), true) => Some(c.clone()),
                    _ => self.chain_held(&snapshot, &w.path, &w.id),
                };
                (Located { snapshot, chain, ..w }, size)
            })
            .collect();
        wants.sort_by_key(|(w, _)| w.snapshot);
        // Batches of at most PREFETCH_BATCH objects and about
        // PREFETCH_BYTES (BUG-1145: a batch is held in memory and counted
        // in the bound until its pack is on disk).
        let mut batches: Vec<(Vec<Located>, u64)> = Vec::new();
        for (w, size) in wants {
            match batches.last_mut() {
                Some((b, bytes)) if b.len() < PREFETCH_BATCH && (b.is_empty() || *bytes + size <= PREFETCH_BYTES) => {
                    b.push(w);
                    *bytes += size;
                }
                _ => batches.push((vec![w], size)),
            }
        }
        let mut refused = Vec::new();
        for (batch, bytes) in batches {
            // Room first: a batch that cannot fit fails before it is asked.
            self.room_for(p, bytes)?;
            let flight = InFlight { p, bytes: AtomicU64::new(0) };
            // One pack per batch (one barrier), not a durable file each.
            let mut incoming = crate::remote::Incoming::new(&p.cache);
            let answers = promisor.fetch(&batch)?;
            for (w, got) in batch.into_iter().zip(answers) {
                match got {
                    Some(raw) => {
                        let len = raw.len() as u64;
                        self.check_object(&w.id, &raw)?;
                        self.charge(p, len, true)?;
                        flight.bytes.fetch_add(len, Ordering::Relaxed);
                        incoming.put(w.id, raw, &w.path)?;
                        p.fetched.fetch_add(1, Ordering::Relaxed);
                    }
                    None => refused.push(w),
                }
            }
            incoming.finish()?;
            flight.landed();
        }
        Ok(refused)
    }

    /// Check an object fetched from the server and write it to the cache:
    /// its BLAKE3 id, a canonical decoding, storable in this format, and
    /// room under the cache's bound.
    fn keep_fetched(&self, p: &Partial, id: &ObjectId, raw: &[u8]) -> Result<()> {
        self.check_object(id, raw)?;
        self.charge(p, raw.len() as u64, false)?;
        p.cache.put_raw(id, raw)?;
        Ok(())
    }

    /// The checks of [`ObjectStore::keep_fetched`].
    fn check_object(&self, id: &ObjectId, raw: &[u8]) -> Result<()> {
        if ObjectId::hash(raw) != *id {
            return Err(VeilError::Corrupt(id.hex(), "the server sent an object that does not match its id".into()));
        }
        let obj = Object::decode(raw)?;
        if matches!(obj, Object::Snapshot(_)) {
            return Err(VeilError::Corrupt(id.hex(), "the server sent a snapshot where a tree entry was asked for".into()));
        }
        self.check_storable(raw)
    }

    /// Make room for `need` more bytes in the cache, evicting if needed:
    /// what is on disk, what batches hold in flight, and `need` together
    /// stay under the bound. Fails cleanly when what is left is all pinned
    /// (threat 11: never an eviction loop).
    fn room_for(&self, p: &Partial, need: u64) -> Result<()> {
        let limit = p.limit.load(Ordering::Relaxed);
        let flying = p.in_flight.load(Ordering::SeqCst);
        if self.cache_bytes(p)? + flying + need > limit {
            let t = self.trim_cache_to(p, need + flying)?;
            if t.after + flying + need > limit {
                return Err(cache_full(limit, t.after + flying));
            }
        }
        Ok(())
    }

    /// [`ObjectStore::room_for`] `need` bytes, and count them: on disk now,
    /// or (`batch`) in flight until the batch's pack lands.
    fn charge(&self, p: &Partial, need: u64, batch: bool) -> Result<()> {
        self.room_for(p, need)?;
        match batch {
            true => {
                p.in_flight.fetch_add(need, Ordering::SeqCst);
            }
            false => {
                if let Some(b) = p.bytes.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
                    *b += need;
                }
            }
        }
        Ok(())
    }

    fn cache_bytes(&self, p: &Partial) -> Result<u64> {
        if let Some(b) = *p.bytes.lock().unwrap_or_else(|e| e.into_inner()) {
            return Ok(b);
        }
        let total = self.cache_files(p)?.iter().map(|(_, len, _)| *len).sum();
        *p.bytes.lock().unwrap_or_else(|e| e.into_inner()) = Some(total);
        Ok(total)
    }

    /// Forget the measured size of the cache (after a pull wrote packs to it).
    pub fn recount_cache(&self) {
        if let Some(p) = self.partial.get() {
            *p.bytes.lock().unwrap_or_else(|e| e.into_inner()) = None;
        }
    }

    /// The cache area's files: what they hold, their size and modification
    /// stamp.
    fn cache_files(&self, p: &Partial) -> Result<Vec<(Unit, u64, i64)>> {
        let c = &p.cache;
        let mut out = Vec::new();
        for id in c.list_loose()? {
            if let Some(m) = c.backend().metadata(&c.loose_path(&id))? {
                out.push((Unit::Loose(id), m.len, m.mtime.unwrap_or(0)));
            }
        }
        let dir = c.pack_dir();
        let entries = match c.backend().list_dir(&dir) {
            Ok(e) => e,
            Err(e) if e.is_not_found() => Vec::new(),
            Err(e) => return Err(e),
        };
        for e in entries.iter().filter(|e| e.kind == NodeKind::File) {
            let Some(name) = crate::pack::name_from_index_file(&e.name) else { continue };
            let mut len = 0;
            let mut stamp = 0;
            for f in [crate::pack::index_file(&dir, name), crate::pack::pack_file(&dir, name)] {
                if let Some(m) = c.backend().metadata(&f)? {
                    len += m.len;
                    stamp = stamp.max(m.mtime.unwrap_or(0));
                }
            }
            out.push((Unit::Pack(name.to_string()), len, stamp));
        }
        Ok(out)
    }

    /// Every object the working copies pin: the trees of each workspace's
    /// working-copy snapshot and of the project directory's checkout record
    /// (and the target of an unfinished move), as far as either area holds
    /// them. Nothing is fetched.
    fn pinned(&self, p: &Partial) -> Result<HashSet<ObjectId>> {
        let mut roots: Vec<ObjectId> = p.anchors.read().unwrap_or_else(|e| e.into_inner()).clone();
        if let Some(st) = crate::working_copy::CheckoutState::load(&**self.backend())? {
            roots.push(st.snapshot);
            roots.extend(st.pending.map(|x| x.snapshot));
        }
        self.without_fetching(|| self.pinned_from(p, roots))
    }

    fn pinned_from(&self, p: &Partial, roots: Vec<ObjectId>) -> Result<HashSet<ObjectId>> {
        let mut out = HashSet::new();
        let mut stack = Vec::new();
        for r in roots {
            if let Ok(s) = self.snapshot(&r) {
                stack.push(s.tree);
            }
        }
        while let Some(t) = stack.pop() {
            if !out.insert(t) {
                continue;
            }
            let tree = match self.tree_object(&t) {
                Ok(tree) => tree,
                Err(VeilError::Missing(_)) => continue,
                Err(e) => return Err(e),
            };
            for e in &tree.entries {
                match e.kind {
                    EntryKind::Dir => stack.push(e.id),
                    EntryKind::Conflict => {
                        out.insert(e.id);
                        if let Ok(c) = self.conflict(&e.id) {
                            out.extend(c.referenced_ids());
                        }
                    }
                    _ => {
                        out.insert(e.id);
                    }
                }
            }
        }
        // The trees (not the files) of the server-side bases of this
        // clone's own snapshots (BUG-1148).
        let (mut heads, tips) = p.local.read().unwrap_or_else(|e| e.into_inner()).clone();
        // gc's roots are every operation the op log keeps, not the view
        // alone: a local commit's earlier version on an old server tip, a
        // working copy an operation remembers (BUG-1264).
        heads.extend(self.op_log_heads());
        if !heads.is_empty() {
            let server = self.server_history(&tips);
            let mut trees = Vec::new();
            for b in self.server_bases(&heads, &server) {
                if let Ok(s) = self.snapshot(&b) {
                    trees.push(s.tree);
                }
            }
            let mut seen = HashSet::new();
            while let Some(t) = trees.pop() {
                if !seen.insert(t) {
                    continue;
                }
                let Ok(tree) = self.tree_object(&t) else { continue };
                out.insert(t);
                trees.extend(tree.entries.iter().filter(|e| e.kind == EntryKind::Dir).map(|e| e.id));
            }
        }
        // Only the anchors' own snapshots were read as snapshots.
        let roots: HashSet<ObjectId> = p.anchors.read().unwrap_or_else(|e| e.into_inner()).iter().copied().collect();
        self.take_boundary_hits_of(&roots);
        Ok(out)
    }

    /// Evict the cache down to 80 % of its bound (least recently written
    /// first). Never evicted: anything in the main store, and what the
    /// working copies pin. A pack holding pinned objects is rewritten with
    /// them first, then removed (write, then switch, then delete: a reader
    /// whose pack vanished finds the objects again, or fetches them).
    pub fn trim_cache(&self) -> Result<Trim> {
        let Some(p) = self.partial.get() else { return Ok(Trim::default()) };
        self.trim_cache_to(p, 0)
    }

    fn trim_cache_to(&self, p: &Partial, need: u64) -> Result<Trim> {
        let limit = p.limit.load(Ordering::Relaxed);
        let target = (limit / 10 * 8).saturating_sub(need);
        let mut files = self.cache_files(p)?;
        let before: u64 = files.iter().map(|(_, len, _)| *len).sum();
        let mut out = Trim { before, after: before, ..Trim::default() };
        if before <= target {
            *p.bytes.lock().unwrap_or_else(|e| e.into_inner()) = Some(before);
            return Ok(out);
        }
        let pinned = self.pinned(p)?;
        files.sort_by_key(|(_, _, stamp)| *stamp);
        let c = &p.cache;
        let dir = c.pack_dir();
        for (unit, len, _) in files {
            if out.after <= target {
                break;
            }
            match unit {
                Unit::Loose(id) => {
                    if pinned.contains(&id) {
                        continue;
                    }
                    match c.backend().remove_file(&c.loose_path(&id)) {
                        Ok(()) => {}
                        Err(e) if e.is_not_found() => {}
                        Err(e) => return Err(e),
                    }
                    out.after -= len;
                    out.removed += 1;
                }
                Unit::Pack(name) => {
                    let Some(pack) = c.packs()?.into_iter().find(|x| x.name() == name) else { continue };
                    let keep: Vec<ObjectId> = pack.index().ids().iter().filter(|i| pinned.contains(i)).copied().collect();
                    if keep.len() == pack.index().ids().len() {
                        continue;
                    }
                    let mut added = 0u64;
                    if !keep.is_empty() {
                        let bases = crate::cache::LruCache::new(16 << 20);
                        let mut objects = Vec::with_capacity(keep.len());
                        for id in &keep {
                            if let Some(raw) = pack.get(&**c.backend(), id, &bases)? {
                                added += raw.len() as u64;
                                objects.push((*id, raw));
                            }
                        }
                        let mut incoming = crate::remote::Incoming::new(c);
                        for (id, raw) in objects {
                            incoming.put(id, raw, "")?;
                        }
                        incoming.finish()?;
                    }
                    // Index first (readers find a pack by it); another
                    // process may have removed either already.
                    for f in [crate::pack::index_file(&dir, &name), crate::pack::pack_file(&dir, &name)] {
                        match c.backend().remove_file(&f) {
                            Ok(()) => {}
                            Err(e) if e.is_not_found() => {}
                            Err(e) => return Err(e),
                        }
                    }
                    out.after = out.after.saturating_sub(len) + added;
                    out.removed += 1;
                }
            }
        }
        c.reload_packs()?;
        out.full = out.after > target;
        *p.bytes.lock().unwrap_or_else(|e| e.into_inner()) = Some(out.after);
        Ok(out)
    }

    /// Size, bound and pinned share of the cache.
    pub fn cache_usage(&self) -> Result<Option<CacheUsage>> {
        let Some(p) = self.partial.get() else { return Ok(None) };
        let files = self.cache_files(p)?;
        let pinned_ids = self.pinned(p)?;
        let mut u = CacheUsage { limit: p.limit.load(Ordering::Relaxed), ..CacheUsage::default() };
        for (unit, len, _) in &files {
            u.bytes += len;
            match unit {
                Unit::Loose(id) => {
                    u.loose += 1;
                    if pinned_ids.contains(id) {
                        u.pinned += len;
                    }
                }
                Unit::Pack(name) => {
                    u.packs += 1;
                    if let Some(pack) = p.cache.packs()?.into_iter().find(|x| x.name() == name) {
                        let ids = pack.index().ids();
                        let n = ids.iter().filter(|i| pinned_ids.contains(i)).count();
                        if !ids.is_empty() {
                            u.pinned += len * n as u64 / ids.len() as u64;
                        }
                    }
                }
            }
        }
        Ok(Some(u))
    }
}

/// The tips of remote `remote` in `remote_tags` (`<remote>/<branch>`): what
/// a thin clone takes for its server's (its own remote's, never another's:
/// BUG-1265).
pub fn own_tips<'a>(remote_tags: &'a std::collections::BTreeMap<String, ObjectId>, remote: &'a str) -> impl Iterator<Item = ObjectId> + 'a {
    remote_tags
        .iter()
        .filter(move |(k, _)| k.len() > remote.len() && k.starts_with(remote) && k.as_bytes()[remote.len()] == b'/')
        .map(|(_, v)| *v)
}

/// What a missing object of a thin clone is ([`ObjectStore::classify_gap`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gap {
    /// An object of the server's history this clone has not fetched.
    Server,
    /// Only this clone's own snapshots name it: lost local work.
    Lost,
    /// The trees that would tell are not held either.
    Unknown,
}

impl ObjectStore {
    /// The snapshots on the server as this clone holds them: those
    /// reachable from `tips` (the remote's tips), and the parents beyond its
    /// boundary that they name. Never fetches.
    pub fn server_history(&self, tips: &[ObjectId]) -> HashSet<ObjectId> {
        let mut seen = HashSet::new();
        let mut stack = tips.to_vec();
        while let Some(x) = stack.pop() {
            if !seen.insert(x) {
                continue;
            }
            if let Ok(s) = self.snapshot(&x) {
                stack.extend(s.parents.iter().copied());
            }
        }
        self.take_boundary_hits_of(&seen);
        seen
    }

    /// fsck and gc in a thin clone (BUG-1143): object `id`, missing at
    /// `path` of snapshot `snap`'s tree. It is the server's when `snap` is
    /// in `server` (its history), or when a parent, through this clone's own
    /// snapshots down to one in `server`, names the same object at the same
    /// path. It is lost when no parent does. Reads only what is held.
    pub fn classify_gap(&self, server: &HashSet<ObjectId>, snap: &ObjectId, path: &str, id: &ObjectId) -> Gap {
        if server.contains(snap) {
            return Gap::Server;
        }
        let mut unknown = false;
        let mut seen = HashSet::new();
        let mut stack = vec![*snap];
        while let Some(s) = stack.pop() {
            if !seen.insert(s) || seen.len() > 256 {
                continue;
            }
            let Ok(snapshot) = self.snapshot(&s) else {
                unknown = true;
                continue;
            };
            for parent in &snapshot.parents {
                let Ok(ps) = self.snapshot(parent) else {
                    // Beyond the boundary: on the server if its child is.
                    unknown |= server.contains(parent);
                    continue;
                };
                match self.entry_held(&ps.tree, path) {
                    Some(Some(e)) if e == *id => match server.contains(parent) {
                        true => return Gap::Server,
                        false => stack.push(*parent),
                    },
                    Some(_) => {}
                    None => unknown = true,
                }
            }
        }
        self.take_boundary_hits_of(&seen);
        if unknown {
            Gap::Unknown
        } else {
            Gap::Lost
        }
    }

    /// The id at `path` in tree `root`, from what is held: `Some(None)` if
    /// nothing is there, `None` if a tree on the way is not held.
    fn entry_held(&self, root: &ObjectId, path: &str) -> Option<Option<ObjectId>> {
        if path.is_empty() {
            return Some(Some(*root));
        }
        let mut cur = *root;
        let mut parts = path.split('/').peekable();
        while let Some(name) = parts.next() {
            let t = match self.tree_object(&cur) {
                Ok(t) => t,
                Err(_) => return None,
            };
            let Some(e) = t.get(name) else { return Some(None) };
            if parts.peek().is_none() {
                return Some(Some(e.id));
            }
            if e.kind != EntryKind::Dir {
                return Some(None);
            }
            cur = e.id;
        }
        Some(None)
    }
}

/// A batch's bytes in flight: on disk once it lands, dropped if it fails.
struct InFlight<'a> {
    p: &'a Partial,
    bytes: AtomicU64,
}

impl InFlight<'_> {
    /// The batch's pack is on disk: its bytes count there now.
    fn landed(self) {
        let n = self.bytes.swap(0, Ordering::SeqCst);
        self.p.in_flight.fetch_sub(n, Ordering::SeqCst);
        if let Some(b) = self.p.bytes.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
            *b += n;
        }
    }
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        self.p.in_flight.fetch_sub(self.bytes.swap(0, Ordering::SeqCst), Ordering::SeqCst);
    }
}

fn cache_full(limit: u64, used: u64) -> VeilError {
    VeilError::Repo(format!(
        "the object cache of this thin clone is full: {} of its {} are pinned by what is checked out. \
         Raise the bound (`vl partial limit SIZE`), or check out less",
        human(used),
        human(limit)
    ))
}

/// `bytes` for people (GiB, MiB, KiB).
pub fn human(bytes: u64) -> String {
    match bytes {
        b if b >= 1 << 30 => format!("{:.1} GiB", b as f64 / (1u64 << 30) as f64),
        b if b >= 1 << 20 => format!("{:.1} MiB", b as f64 / (1u64 << 20) as f64),
        b if b >= 1 << 10 => format!("{:.1} KiB", b as f64 / 1024.0),
        b => format!("{b} B"),
    }
}

/// A size as `vl clone --cache-size` takes it: bytes, or with a `K`, `M`
/// or `G` suffix (powers of 1024).
pub fn parse_size(s: &str) -> Result<u64> {
    let t = s.trim();
    let (num, shift) = match t.char_indices().last() {
        Some((i, c)) if c.eq_ignore_ascii_case(&'k') => (&t[..i], 10),
        Some((i, c)) if c.eq_ignore_ascii_case(&'m') => (&t[..i], 20),
        Some((i, c)) if c.eq_ignore_ascii_case(&'g') => (&t[..i], 30),
        _ => (t, 0),
    };
    let n: u64 = num.trim().parse().map_err(|_| VeilError::repo(format!("not a size: {s:?} (bytes, or a number with K, M or G)")))?;
    n.checked_mul(1u64 << shift).ok_or_else(|| VeilError::repo(format!("size too large: {s:?}")))
}

#[cfg(test)]
mod s3r2_tests {
    use super::*;

    /// BUG-1149: the locator at its bound. `LOCATOR_CAP` says "about 46
    /// bytes each: at most about 90 MiB" (and `docs/HUB.md` "under the
    /// 512 MiB client gate"); the maps' own capacity at the bound is more
    /// than half again (a hash map grows by doubling, to 7/8 full at most),
    /// before the parents' map and vector. A scratch run with a counting
    /// allocator held 166 to 376 MiB at the bound (peak 248 to 458 MiB),
    /// for 100 to 1 entries per tree.
    #[test]
    fn s3r2_the_locator_at_its_bound_is_about_90_mib() {
        let id = |i: u64, tag: u8| {
            let mut x = [0u8; 32];
            x[..8].copy_from_slice(&i.to_le_bytes());
            x[31] = tag;
            ObjectId(x)
        };
        for per_tree in [1u64, 10, 100] {
            let mut l = Locator::default();
            for i in 0..LOCATOR_CAP as u64 + 10 {
                l.note(id(i, 0), id(i / per_tree + (1 << 40), 1), (i % per_tree) as u32);
            }
            assert_eq!(l.at.len() + l.parents.len(), LOCATOR_CAP);
            // Capacity, not length: a map's room (and one control byte a
            // bucket), the parents' map and vector.
            let bytes = l.at.capacity() * (std::mem::size_of::<(u64, u64)>() + 1)
                + l.handles.capacity() * (std::mem::size_of::<(u64, u32)>() + 1)
                + l.parents.capacity() * std::mem::size_of::<ObjectId>();
            assert!(bytes <= 90 << 20, "{per_tree} a tree: the locator at its bound holds at least {} MiB", bytes >> 20);
        }
    }
}
