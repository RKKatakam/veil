//! Fetch on demand for a thin clone (milestone S3, `docs/HUB.md` §13.18;
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

/// Objects per request when a checkout fetches ahead.
const PREFETCH_BATCH: usize = 1_000;

/// Most locations one process records (about 45 bytes each). Past it,
/// objects met later have no location and their reads fail with
/// [`VeilError::Unavailable`], never as hidden.
const LOCATOR_CAP: usize = 8_000_000;

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

/// The location of every object met in a decoded tree, compactly: the
/// parent (a tree, a snapshot for a root tree, a conflict for its terms)
/// and the entry's index in it.
#[derive(Default)]
struct Locator {
    parents: Vec<ObjectId>,
    handles: HashMap<ObjectId, u32>,
    at: HashMap<ObjectId, (u32, u32)>,
}

impl Locator {
    fn note(&mut self, child: ObjectId, parent: ObjectId, index: u32) {
        if self.at.len() >= LOCATOR_CAP || self.at.contains_key(&child) {
            return;
        }
        let parents = &mut self.parents;
        let h = *self.handles.entry(parent).or_insert_with(|| {
            parents.push(parent);
            (parents.len() - 1) as u32
        });
        self.at.insert(child, (h, index));
    }

    fn get(&self, id: &ObjectId) -> Option<(ObjectId, u32)> {
        self.at.get(id).map(|(h, i)| (self.parents[*h as usize], *i))
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
    /// Snapshots found to be on the server (memo of `on_server`).
    server: Mutex<HashSet<ObjectId>>,
    /// Objects fetched on demand by this process.
    fetched: AtomicU64,
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
            server: Mutex::new(HashSet::new()),
            fetched: AtomicU64::new(0),
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

    /// Record where the objects `obj` names were met (thin clones only).
    pub(crate) fn note_decoded(&self, id: &ObjectId, obj: &Object) {
        let Some(p) = self.partial.get() else { return };
        let mut l = p.locator.lock().unwrap_or_else(|e| e.into_inner());
        match obj {
            Object::Tree(t) => {
                for (i, e) in t.entries.iter().enumerate() {
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
                    names.reverse();
                    return Ok(Some((parent, names.join("/"))));
                }
                TERM => cur = parent,
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
        let mut seen = HashSet::new();
        let mut stack = promisor.server_tips();
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
        found
    }

    fn take_boundary_hits_of(&self, ids: &HashSet<ObjectId>) -> usize {
        let Some(p) = self.partial.get() else { return 0 };
        let mut h = p.hits.lock().unwrap_or_else(|e| e.into_inner());
        let before = h.len();
        h.retain(|x| !ids.contains(x));
        before - h.len()
    }

    /// A read neither area of a thin clone's store could answer.
    pub(crate) fn read_partial(&self, id: &ObjectId) -> Result<Vec<u8>> {
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
        let Some((snapshot, path)) = self.locate(p, id)? else {
            // Not met in any tree: a snapshot beyond the boundary (or an id
            // named some other way). Recorded for `Repo::exact`.
            p.hits.lock().unwrap_or_else(|e| e.into_inner()).insert(*id);
            return Err(VeilError::Missing(*id));
        };
        let shown = if path.is_empty() { "/".to_string() } else { path.clone() };
        let Some(promisor) = self.promisor() else {
            return Err(VeilError::Unavailable(format!(
                "'{shown}' is not fetched yet, and this command has no connection to the server of this thin clone"
            )));
        };
        let mut got = promisor.fetch(&[Located { id: *id, snapshot, path: path.clone() }])?.pop().flatten();
        if got.is_none() {
            // Met under a snapshot the server may not have (a local
            // commit): ask at the same path under the server's tips.
            for t in promisor.server_tips() {
                if t == snapshot {
                    continue;
                }
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
            self.ensure_held(p, level.iter().map(|(_, t)| *t).collect())?;
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
                        _ => files.push(e.id),
                    }
                }
            }
            self.ensure_held(p, files.clone())?;
            // A conflict's terms are read too.
            let mut terms = Vec::new();
            for id in files {
                if let Ok(Object::Conflict(c)) = self.get(&id) {
                    terms.extend(c.referenced_ids());
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
    fn ensure_held(&self, p: &Partial, ids: Vec<ObjectId>) -> Result<()> {
        let _ = (self.ensure_packs(), p.cache.ensure_packs());
        let missing: Vec<ObjectId> = ids
            .into_iter()
            .filter(|id| !(self.in_loaded_packs(id) || p.cache.in_loaded_packs(id) || self.has(id)))
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
        for id in missing {
            match self.locate(p, &id)? {
                Some((snapshot, path)) => wants.push(Located { id, snapshot, path }),
                None => match self.read_raw(&id) {
                    Ok(_) | Err(VeilError::Missing(_)) => {}
                    Err(e) => return Err(e),
                },
            }
        }
        wants.sort_by_key(|w| w.snapshot);
        for batch in wants.chunks(PREFETCH_BATCH) {
            let mut refused = Vec::new();
            // One pack per batch (one barrier), not a durable file each.
            let mut incoming = crate::remote::Incoming::new(&p.cache);
            for (w, got) in batch.iter().zip(promisor.fetch(batch)?) {
                match got {
                    Some(raw) => {
                        self.check_fetched(p, &w.id, &raw)?;
                        incoming.put(w.id, raw, &w.path)?;
                        p.fetched.fetch_add(1, Ordering::Relaxed);
                    }
                    None => refused.push(w.id),
                }
            }
            incoming.finish()?;
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
        self.check_fetched(p, id, raw)?;
        p.cache.put_raw(id, raw)?;
        Ok(())
    }

    /// The checks of [`ObjectStore::keep_fetched`], and the room it takes.
    fn check_fetched(&self, p: &Partial, id: &ObjectId, raw: &[u8]) -> Result<()> {
        if ObjectId::hash(raw) != *id {
            return Err(VeilError::Corrupt(id.hex(), "the server sent an object that does not match its id".into()));
        }
        let obj = Object::decode(raw)?;
        if matches!(obj, Object::Snapshot(_)) {
            return Err(VeilError::Corrupt(id.hex(), "the server sent a snapshot where a tree entry was asked for".into()));
        }
        self.check_storable(raw)?;
        self.charge(p, raw.len() as u64)
    }

    /// Make room for `need` more bytes in the cache, evicting if needed;
    /// fails cleanly when what is left is all pinned (threat 11: never an
    /// eviction loop).
    fn charge(&self, p: &Partial, need: u64) -> Result<()> {
        let limit = p.limit.load(Ordering::Relaxed);
        let now = self.cache_bytes(p)?;
        if now + need > limit {
            let t = self.trim_cache_to(p, need)?;
            if t.after + need > limit {
                return Err(cache_full(limit, t.after));
            }
        }
        let mut b = p.bytes.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(b) = b.as_mut() {
            *b += need;
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
