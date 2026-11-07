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
//! through [`crate::Repo::exact`], which fetches the next page of history
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
}

/// The location of every object met in a decoded tree, compactly (16 bytes
/// a place): the first 8 bytes of the object's id → the parent (a tree, a
/// snapshot for a root tree, a conflict for its terms) and the entry's index
/// in it. Ids are BLAKE3 hashes, so 8 bytes tell them apart; a collision is
/// harmless: `ObjectStore::locate` checks that the parent names the object
/// there, and treats a mismatch as no place.
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
    fn note(&mut self, child: ObjectId, parent: ObjectId, index: u32) {
        let key = short_key(&child);
        if self.at.len() + self.parents.len() >= LOCATOR_CAP || self.at.contains_key(&key) {
            return;
        }
        let parents = &mut self.parents;
        let h = *self.handles.entry(short_key(&parent)).or_insert_with(|| {
            parents.push(parent);
            (parents.len() - 1) as u32
        });
        self.at.insert(key, (u64::from(h) << 32) | u64::from(index));
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

    /// Run `f` with fetching off for the whole store: reads of what neither
    /// area holds are `Missing` (gc, fsck and maintenance, for which an
    /// unfetched object is on the server, never local work).
    pub fn without_fetching<R>(&self, f: impl FnOnce() -> R) -> R {
        let Some(p) = self.partial.get() else { return f() };
        p.no_fetch.fetch_add(1, Ordering::SeqCst);
        struct Undo<'a>(&'a AtomicUsize);
        impl Drop for Undo<'_> {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::SeqCst);
            }
        }
        let _undo = Undo(&p.no_fetch);
        f()
    }

    /// Never fetch from this store (a checker that only reads what is
    /// local).
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

    /// The snapshots reads missed since the last call: the boundary a graph
    /// walk reached ([`crate::Repo::exact`]).
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

    /// Where `id` was met: a snapshot and the path in its tree.
    fn locate(&self, p: &Partial, id: &ObjectId) -> Result<Option<(ObjectId, String)>> {
        let mut names: Vec<String> = Vec::new();
        let mut cur = *id;
        for _ in 0..=crate::tree::MAX_TREE_DEPTH + 2 {
            let found = p.locator.lock().unwrap_or_else(|e| e.into_inner()).get(&cur);
            let Some((parent, index)) = found else { return Ok(None) };
            match index {
                ROOT => {
                    // The snapshot names this root tree (an 8-byte key may
                    // name another object).
                    if self.snapshot(&parent).map_or(true, |s| s.tree != cur) {
                        return Ok(None);
                    }
                    names.reverse();
                    return Ok(Some((parent, names.join("/"))));
                }
                TERM => {
                    if self.conflict(&parent).map_or(true, |c| !c.referenced_ids().contains(&cur)) {
                        return Ok(None);
                    }
                    cur = parent
                }
                i => {
                    // The parent tree was decoded here; it may have been
                    // evicted since, and is fetched again from its own
                    // location.
                    let t = self.tree_object(&parent)?;
                    let Some(e) = t.entries.get(i as usize).filter(|e| e.id == cur) else { return Ok(None) };
                    names.push(e.name.clone());
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
        // Walked since the last snapshots arrived: the set is whole.
        if p.server_walked.load(Ordering::SeqCst) {
            return false;
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
        found
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
    /// clone does not hold (its boundary, recorded for [`crate::Repo::exact`];
    /// [`crate::Repo::snapshot_opt`] fetches history there). A tree or file
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
        let Some((snapshot, path)) = self.locate(p, id)? else {
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
        let mut got = promisor.fetch(&[Located { id: *id, snapshot, path: path.clone() }])?.pop().flatten();
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
                got = promisor.fetch(&[Located { id: *id, snapshot: t, path: path.clone() }])?.pop().flatten();
                if got.is_some() {
                    break;
                }
            }
        }
        let Some(raw) = got else {
            if self.on_server(p, &*promisor, &snapshot) {
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
        let mut level: Vec<(Option<ObjectId>, ObjectId)> = vec![(from.copied(), *to)];
        while !level.is_empty() {
            self.ensure_held(p, level.iter().map(|(_, t)| (*t, 0)).collect())?;
            let mut next = Vec::new();
            let mut files = Vec::new();
            for (f, t) in level {
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
                        EntryKind::Dir => next.push((old.filter(|o| o.kind == EntryKind::Dir).map(|o| o.id), e.id)),
                        _ => files.push((e.id, e.size)),
                    }
                }
            }
            self.ensure_held(p, files.clone())?;
            // A conflict's terms are read too.
            let mut terms = Vec::new();
            for (id, _) in files {
                if let Ok(Object::Conflict(c)) = self.get(&id) {
                    terms.extend(c.referenced_ids().into_iter().map(|t| (t, 0)));
                }
            }
            self.ensure_held(p, terms)?;
            level = next;
        }
        Ok(())
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
                Some((snapshot, path)) => wants.push((Located { id, snapshot, path }, size)),
                // Read the ordinary way: `Unavailable` (never hidden).
                None => {
                    self.read_raw(&id)?;
                }
            }
        }
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
        for (batch, bytes) in batches {
            // Room first: a batch that cannot fit fails before it is asked.
            self.room_for(p, bytes)?;
            let mut refused = Vec::new();
            let flight = InFlight { p, bytes: AtomicU64::new(0) };
            // One pack per batch (one barrier), not a durable file each.
            let mut incoming = crate::remote::Incoming::new(&p.cache);
            for (w, got) in batch.iter().zip(promisor.fetch(&batch)?) {
                match got {
                    Some(raw) => {
                        let len = raw.len() as u64;
                        self.check_object(&w.id, &raw)?;
                        self.charge(p, len, true)?;
                        flight.bytes.fetch_add(len, Ordering::Relaxed);
                        incoming.put(w.id, raw, &w.path)?;
                        p.fetched.fetch_add(1, Ordering::Relaxed);
                    }
                    None => refused.push(w.id),
                }
            }
            incoming.finish()?;
            flight.landed();
            // Asked again the ordinary way: other places, then `Missing`
            // (hidden) or `Unavailable`.
            for id in refused {
                match self.read_raw(&id) {
                    Ok(_) | Err(VeilError::Missing(_)) => {}
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(())
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
        NO_FETCH.with(|c| c.set(c.get() + 1));
        struct Undo;
        impl Drop for Undo {
            fn drop(&mut self) {
                NO_FETCH.with(|c| c.set(c.get() - 1));
            }
        }
        let _undo = Undo;
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
        let (heads, tips) = p.local.read().unwrap_or_else(|e| e.into_inner()).clone();
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
