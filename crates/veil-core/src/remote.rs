//! Synchronisation between repositories (any two `StorageBackend`s).
//!
//! Visibility is enforced *in the transfer itself*:
//!
//! | content                         | team remote | public remote |
//! |---------------------------------|-------------|---------------|
//! | public objects                  | ✓           | ✓             |
//! | cloaked objects (ciphertext)    | ✓           | ✗ redacted    |
//! | unreleased embargoed objects    | ✓           | ✗ (fallback ✓)|
//! | released embargoed objects      | ✓           | ✓             |
//! | merged-in history of an unreleased embargoed merge | cloaked under the embargo's scope, not building on withheld history | ✗ |
//! | cloaked tags                    | ✓           | ✗             |
//! | annotated tag objects (`veil:atag`, format 5) | ✓ with their tag | ✓ with their tag, never one with a sealed message |
//! | key rings                       | ✓           | ✗ (they name the members) |
//! | embargo records                 | ✓           | ✓ (encrypted, signed) |
//! | team vault (`vl secret --scope`) | ✓ (sealed, signed records) | ✗ |
//! | isolated files, vault, `local`  | never — not in the graph at all |
//!
//! Redacted tree entries keep their names and ids, so a later push to a
//! team remote or a key grant fills them in without any history rewrite.
//!
//! An unreleased embargoed merge reaches a remote with its extra parents
//! *redacted*: the snapshots only those parents reach (the fix, and how it
//! was made) stay local until the embargo is released, and a tag that would
//! publish them by another route (a tag on the fix, a commit building on
//! it) is skipped with a reason. Graph walks treat a missing parent as
//! absent, so clones of such a remote work normally; the next push after
//! the release fills the parents in, with unchanged snapshot ids.
//!
//! # Incremental transfer
//!
//! Over a WAN the cost of sync is round trips, not bytes, so neither side
//! re-walks or re-checks what the other provably has:
//!
//! * **The receiver's committed view is a complete closure.** Every
//!   transaction writes its objects, then a durability barrier, then the
//!   operation, so everything reachable from the receiver's *committed*
//!   view is there. Mere presence of an object proves nothing (a crashed
//!   transfer leaves snapshots without their trees), so only reachability
//!   from the committed view counts. Two refinements keep this exact: the
//!   non-first parents of an embargoed merge may have been redacted when it
//!   was sent, so they count only if the receiver holds them in a pack; and
//!   on a public receiver an embargo wrapper may hold content that was
//!   withheld then and is releasable now, so wrappers are always revisited.
//! * **Push** walks, on the local graph, the snapshots the remote's view
//!   reaches; those are not sent. Of the trees of the remaining snapshots,
//!   every subtree reachable from a known parent snapshot is skipped.
//!   Everything left goes into **one pack** (plus index), written to the
//!   remote's pack directory pack first, index second, each made durable
//!   before the next, inside the remote transaction. A crash leaves at
//!   worst a pack nobody can see (no index) or a complete pack whose
//!   operation never landed; both are harmless.
//! * **Pull** lists the remote's objects (pack indexes and loose fan-out
//!   directories, many requests in flight at once), skips every snapshot
//!   the local committed view reaches, and at the first object it lacks
//!   downloads, in parallel, every remote pack and loose object it lacks:
//!   a few round trips instead of one per object. The walk then runs
//!   locally. Objects already present locally are read locally (and their
//!   subtrees checked), never fetched. Content the local view references
//!   but lacks (a clone of a public mirror that now pulls from a team
//!   remote, or embargoed content released since) is found by a local walk
//!   whenever the remote holds objects the walk did not need. More than a
//!   few hundred objects are written locally as a pack too.
//! * Filtering is unchanged: every object that crosses goes through the
//!   same checks (`allowed`, canonical decoding, tree depth) as before.
//! * [`SyncOptions::full`] (`vl push --full`, `vl pull --full`) is the old
//!   object-by-object walk of everything, which re-verifies the receiver's
//!   copies: it repairs a damaged object, and fills content a receiver
//!   lacks below snapshots it already has (on push, such gaps are not
//!   detected otherwise).

use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

use crate::{
    cache::LruCache,
    commands::validate_tag_name,
    embargo::wrapper_parts,
    error::{Result, VeilError},
    id::ObjectId,
    keychain::{Keychain, RingMerge, LOCAL_SCOPE},
    object::{EntryKind, Object},
    oplog::Tag,
    pack::{index_file, name_from_index_file, pack_file, Pack, PackBuilder, PackIndex, DEFAULT_LEVEL},
    repo::{is_repo, Repo},
    store::ObjectStore,
    tree::MAX_TREE_DEPTH,
    vfs::{MemoryBackend, NodeKind, StorageBackend},
    vpath::VPath,
};

#[derive(Debug, Default, Clone)]
pub struct SyncReport {
    pub objects_copied: usize,
    pub redacted: usize,
    pub missing: usize,
    pub tags_updated: Vec<(String, ObjectId)>,
    pub tags_skipped: Vec<(String, String)>,
    /// The tags of `tags_skipped` that the remote refused: it holds a
    /// version that is not an ancestor of ours (push without `force`).
    /// The others were held back by design (a cloaked tag on a public
    /// remote, an unreleased embargo).
    pub tags_rejected: Vec<String>,
    pub warnings: Vec<String>,
    /// Packs written on the receiving side.
    pub packs_written: usize,
    /// Object bytes that crossed: packs written (push), packs and loose
    /// objects downloaded (pull).
    pub bytes_transferred: u64,
    /// Embargo releases staged here that this push published (written into
    /// their records and sent): from now on they cannot be taken back.
    pub releases_published: Vec<String>,
    /// Push: every pushed tag the remote holds at our target now (updated
    /// or already there), for [`record_pushed_tags`].
    pub remote_tags: Vec<(String, ObjectId)>,
    /// Tags deleted on the remote ([`delete_remote_tags`]).
    pub tags_deleted: Vec<String>,
    /// Remote tags `<remote>/<tag>` removed because the remote no longer
    /// has the tag (pull), or because this push deleted it there.
    pub remote_tags_removed: Vec<String>,
    /// Local tags that a pull did not recreate: deleted here, and not
    /// moved on the remote since ([`deleted_tags`]).
    pub tags_kept_deleted: Vec<String>,
    /// Pull: local release tags (annotated) the remote holds at another
    /// target, as (tag, local target, remote target). Release tags never
    /// move on a pull; the remote's target is `<remote>/<tag>`.
    pub release_tags_kept: Vec<(String, ObjectId, ObjectId)>,
}

/// How to synchronise.
#[derive(Clone, Debug, Default)]
pub struct SyncOptions {
    /// Walk and re-verify everything object by object instead of skipping
    /// what the receiver provably has (see the module documentation).
    pub full: bool,
    /// Push: move release tags (annotated, format 5) that the remote holds
    /// with another target (BUG-710: a release is immutable; replacing one
    /// takes this).
    pub force_tags: bool,
}

/// Raw objects for a transfer: `New` must be written to the receiver,
/// `Have` is already there (read only to look inside it).
enum Fetched {
    New(Vec<u8>),
    Have(Vec<u8>),
}

trait Source {
    /// The verified canonical encoding of `id`; [`VeilError::Missing`] if
    /// the sending side does not have it.
    fn fetch(&self, id: &ObjectId) -> Result<Fetched>;
}

/// Everything from one store, all of it new to the receiver.
struct StoreSource<'a>(&'a ObjectStore);

impl Source for StoreSource<'_> {
    fn fetch(&self, id: &ObjectId) -> Result<Fetched> {
        self.0.get_raw(id).map(Fetched::New)
    }
}

/// Where transferred objects go.
enum Sink<'a> {
    /// Loose objects through `put_raw` (which re-verifies existing copies).
    Store(&'a ObjectStore),
    Pack(Box<PackSink<'a>>),
    /// A dry run (`vl push --dry-run`, [`crate::push_plan`]): every object
    /// is recorded, and packed exactly as [`Sink::Pack`] would pack it
    /// (so the byte count is the real one), into a backend that drops
    /// what it is given.
    Plan(Box<PackSink<'a>>, &'a RefCell<Vec<PlannedObject>>),
}

impl Sink<'_> {
    fn put(&mut self, id: ObjectId, raw: Vec<u8>, path: &str) -> Result<bool> {
        match self {
            Sink::Store(s) => s.put_raw(&id, &raw),
            Sink::Pack(p) => p.put(id, raw, path),
            Sink::Plan(p, record) => {
                record.borrow_mut().push(PlannedObject {
                    id,
                    bytes: raw.len() as u64,
                    sealed: Object::sealed_scope(&raw).is_some(),
                    blob: Object::is_blob_raw(&raw),
                    path: path.to_string(),
                });
                p.put(id, raw, path)
            }
        }
    }

    fn finish(self, report: &mut SyncReport) -> Result<()> {
        if let Sink::Pack(p) | Sink::Plan(p, _) = self {
            p.finish(report)?;
        }
        Ok(())
    }
}

/// One object a push would send (recorded by a dry run).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannedObject {
    pub id: ObjectId,
    /// Size of its canonical encoding (before packing).
    pub bytes: u64,
    /// Ciphertext (cloaked or embargoed content, or a sealed tree).
    pub sealed: bool,
    /// A plaintext file's content.
    pub blob: bool,
    /// Where the transfer met it first (`""` for snapshots and root trees).
    pub path: String,
}

/// What a dry run of [`push_incremental`] collects besides the report.
#[derive(Default)]
pub(crate) struct PlanRecord {
    pub objects: RefCell<Vec<PlannedObject>>,
    /// Snapshots the remote's committed view reaches (never sent).
    pub known_snapshots: HashSet<ObjectId>,
    /// The snapshots that would be sent, in transfer order.
    pub sent_snapshots: Vec<ObjectId>,
}

/// The backend a dry run's packs are "written" to: nothing is kept.
#[derive(Debug)]
struct Discard;

impl StorageBackend for Discard {
    fn kind(&self) -> &'static str {
        "discard"
    }
    fn read(&self, path: &VPath) -> Result<Vec<u8>> {
        Err(VeilError::NotFound(path.to_string()))
    }
    fn write(&self, _: &VPath, _: &[u8]) -> Result<()> {
        Ok(())
    }
    fn create_new(&self, _: &VPath, _: &[u8]) -> Result<bool> {
        Ok(true)
    }
    fn remove_file(&self, _: &VPath) -> Result<()> {
        Ok(())
    }
    fn remove_dir_all(&self, _: &VPath) -> Result<()> {
        Ok(())
    }
    fn create_dir_all(&self, _: &VPath) -> Result<()> {
        Ok(())
    }
    fn list_dir(&self, _: &VPath) -> Result<Vec<crate::vfs::DirEntry>> {
        Ok(Vec::new())
    }
    fn metadata(&self, _: &VPath) -> Result<Option<crate::vfs::Metadata>> {
        Ok(None)
    }
    fn set_executable(&self, _: &VPath, _: bool) -> Result<()> {
        Ok(())
    }
}

static DISCARD: Discard = Discard;

/// A pack holding at most about this much (uncompressed) data is written
/// before the next one is started.
const PACK_LIMIT: u64 = 128 << 20;

/// Collects objects into packs on `backend`. Below `threshold` objects
/// (and with a `loose` store) they are written as loose objects instead,
/// so a small pull does not leave a tiny pack behind.
struct PackSink<'a> {
    /// The destination store: decides what its repository format may hold
    /// (packs bypass `put_raw`, so the check happens here).
    dest: &'a ObjectStore,
    backend: &'a dyn StorageBackend,
    dir: VPath,
    loose: Option<&'a ObjectStore>,
    threshold: usize,
    pending: Vec<(ObjectId, Vec<u8>, String)>,
    builder: Option<PackBuilder>,
    builder_bytes: u64,
    /// The last object packed at each path: the delta base for the next
    /// version found there.
    last: HashMap<String, (ObjectId, Vec<u8>)>,
    packs: usize,
    bytes: u64,
}

impl<'a> PackSink<'a> {
    fn new(dest: &'a ObjectStore, dir: VPath, loose: Option<&'a ObjectStore>, threshold: usize) -> Self {
        PackSink {
            dest,
            backend: &**dest.backend(),
            dir,
            loose,
            threshold,
            pending: Vec::new(),
            builder: None,
            builder_bytes: 0,
            last: HashMap::new(),
            packs: 0,
            bytes: 0,
        }
    }

    fn put(&mut self, id: ObjectId, raw: Vec<u8>, path: &str) -> Result<bool> {
        // A format-1 repository must never receive binary trees.
        self.dest.check_storable(&raw)?;
        if self.builder.is_none() && self.pending.len() < self.threshold {
            self.pending.push((id, raw, path.to_string()));
            return Ok(true);
        }
        for (id, raw, path) in std::mem::take(&mut self.pending) {
            self.pack(id, raw, path)?;
        }
        self.pack(id, raw, path.to_string())?;
        Ok(true)
    }

    fn pack(&mut self, id: ObjectId, raw: Vec<u8>, path: String) -> Result<()> {
        let builder = match &mut self.builder {
            Some(b) => b,
            None => self.builder.insert(PackBuilder::new(DEFAULT_LEVEL)?),
        };
        let base = self
            .last
            .get(&path)
            .filter(|(bid, braw)| builder.contains(bid) && Object::is_blob_raw(braw) == Object::is_blob_raw(&raw));
        builder.add(id, &raw, base.map(|(bid, braw)| (bid, &braw[..])))?;
        self.builder_bytes += raw.len() as u64;
        self.last.insert(path, (id, raw));
        if self.builder_bytes >= PACK_LIMIT {
            self.flush()?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        if let Some(b) = self.builder.take() {
            // `finish` writes the pack, then its index: the pack unsynced,
            // then a barrier, then the index durably. A crash before the
            // index leaves a pack nobody finds; the index is never torn.
            if let Some((_, stats)) = b.finish(&PackWrites(self.backend, self.dest), &self.dir)? {
                self.packs += 1;
                self.bytes += stats.pack_bytes;
            }
        }
        self.builder_bytes = 0;
        self.last.clear();
        Ok(())
    }

    fn finish(mut self, report: &mut SyncReport) -> Result<()> {
        if self.builder.is_none() {
            if let Some(store) = self.loose {
                for (id, raw, _) in std::mem::take(&mut self.pending) {
                    store.put_raw(&id, &raw)?;
                }
            }
            for (id, raw, path) in std::mem::take(&mut self.pending) {
                self.pack(id, raw, path)?;
            }
        }
        self.flush()?;
        report.packs_written += self.packs;
        if self.loose.is_none() {
            report.bytes_transferred += self.bytes;
        }
        Ok(())
    }
}

/// The backend as `PackBuilder::finish` sees it: data files are written
/// unsynced, and an index only after a barrier, durably. The barrier is the
/// destination store's, which voids its own unsynced objects if it fails.
#[derive(Debug)]
struct PackWrites<'a>(&'a dyn StorageBackend, &'a ObjectStore);

impl StorageBackend for PackWrites<'_> {
    fn kind(&self) -> &'static str {
        self.0.kind()
    }
    fn read(&self, path: &VPath) -> Result<Vec<u8>> {
        self.0.read(path)
    }
    fn write(&self, path: &VPath, data: &[u8]) -> Result<()> {
        if path.as_str().ends_with(".idx") {
            self.1.sync_barrier()?;
            self.0.write(path, data)
        } else {
            self.0.write_unsynced(path, data)
        }
    }
    fn create_new(&self, path: &VPath, data: &[u8]) -> Result<bool> {
        self.0.create_new(path, data)
    }
    fn remove_file(&self, path: &VPath) -> Result<()> {
        self.0.remove_file(path)
    }
    fn remove_dir_all(&self, path: &VPath) -> Result<()> {
        self.0.remove_dir_all(path)
    }
    fn create_dir_all(&self, path: &VPath) -> Result<()> {
        self.0.create_dir_all(path)
    }
    fn list_dir(&self, path: &VPath) -> Result<Vec<crate::vfs::DirEntry>> {
        self.0.list_dir(path)
    }
    fn metadata(&self, path: &VPath) -> Result<Option<crate::vfs::Metadata>> {
        self.0.metadata(path)
    }
    fn set_executable(&self, path: &VPath, executable: bool) -> Result<()> {
        self.0.set_executable(path, executable)
    }
}

struct Transfer<'a> {
    src: &'a dyn Source,
    sink: Sink<'a>,
    src_keys: &'a Keychain,
    public: bool,
    /// Objects the receiver provably has: not visited at all.
    known: Box<dyn Fn(&ObjectId) -> bool + 'a>,
    seen: HashSet<ObjectId>,
    /// Tree height of every object copied so far (0 for non-trees).
    heights: HashMap<ObjectId, usize>,
    report: SyncReport,
}

impl Transfer<'_> {
    fn allowed(&self, raw: &[u8]) -> bool {
        // An annotated tag's message is sealed for a cloaked tag: such an
        // atag never reaches a public remote, whichever route names it.
        if self.public && raw.starts_with(crate::object::ATAG_TAG) {
            return matches!(Object::decode(raw), Ok(Object::Atag(a)) if !a.is_sealed());
        }
        match Object::sealed_scope(raw) {
            None => true,
            Some(scope) if scope == LOCAL_SCOPE => false,
            Some(_) if !self.public => true,
            Some(scope) => match scope.strip_prefix("embargo/") {
                Some(id) => self.src_keys.embargo_released(id),
                None => false,
            },
        }
    }

    /// Copy one object and everything it references (not snapshot parents).
    ///
    /// The walk is iterative (the remote controls the depth) and rejects
    /// trees nested deeper than [`MAX_TREE_DEPTH`]. Depth is measured as
    /// each tree's *height* (longest chain of trees below it, memoised per
    /// id), because content-addressed trees are shared: the same subtree
    /// may first be met shallowly and later deep inside another tree.
    /// `path` (where the object was found) only picks delta bases.
    fn copy(&mut self, root: ObjectId, path: &str) -> Result<()> {
        struct Frame {
            id: ObjectId,
            is_tree: bool,
            children: Vec<(ObjectId, String)>,
            next: usize,
            height: usize,
        }
        let mut stack: Vec<Frame> = Vec::new();
        let mut trees_on_stack = 0usize;
        let mut pending = Some((root, path.to_string()));
        loop {
            if let Some((id, path)) = pending.take() {
                if let Some(frame) = self.enter(id, &path)? {
                    if frame.0 {
                        trees_on_stack += 1;
                        if trees_on_stack > MAX_TREE_DEPTH {
                            return Err(too_deep(root));
                        }
                    }
                    stack.push(Frame {
                        id,
                        is_tree: frame.0,
                        children: frame.1,
                        next: 0,
                        height: 0,
                    });
                } else if let Some(top) = stack.last_mut() {
                    let h = self.heights.get(&id).copied().unwrap_or(0);
                    top.height = top.height.max(h);
                }
            }
            let Some(top) = stack.last_mut() else {
                return Ok(());
            };
            if let Some(child) = top.children.get_mut(top.next) {
                top.next += 1;
                pending = Some((child.0, std::mem::take(&mut child.1)));
                continue;
            }
            let done = stack.pop().unwrap();
            let height = done.height + usize::from(done.is_tree);
            if done.is_tree {
                trees_on_stack -= 1;
                if height > MAX_TREE_DEPTH {
                    return Err(too_deep(root));
                }
            }
            self.heights.insert(done.id, height);
            if let Some(parent) = stack.last_mut() {
                parent.height = parent.height.max(height);
            }
        }
    }

    /// Fetch, check and store one object. Returns `None` if there is
    /// nothing to descend into (already seen, known to the receiver,
    /// missing or redacted), else whether it is a tree and the ids it
    /// references, with their paths.
    #[allow(clippy::type_complexity)]
    fn enter(&mut self, id: ObjectId, path: &str) -> Result<Option<(bool, Vec<(ObjectId, String)>)>> {
        if !self.seen.insert(id) || (self.known)(&id) {
            return Ok(None);
        }
        // Every source verifies the content against `id`.
        let (raw, new) = match self.src.fetch(&id) {
            Ok(Fetched::New(r)) => (r, true),
            Ok(Fetched::Have(r)) => (r, false),
            Err(VeilError::Missing(_)) => {
                self.report.missing += 1;
                return Ok(None);
            }
            Err(e) => return Err(e),
        };
        if new && !self.allowed(&raw) {
            self.report.redacted += 1;
            return Ok(None);
        }
        if !new && (Object::is_blob_raw(&raw) || Object::sealed_scope(&raw).is_some()) {
            return Ok(None); // already there, and nothing below it
        }
        // Decoding validates structure: canonical trees with safe names.
        let obj = Object::decode(&raw)?;
        if new && self.sink.put(id, raw, path)? {
            self.report.objects_copied += 1;
        }
        Ok(Some(match obj {
            Object::Snapshot(s) => {
                if new && s.signature_valid() == Some(false) {
                    self.report
                        .warnings
                        .push(format!("snapshot {} carries an invalid signature", id.short()));
                }
                (false, vec![(s.tree, String::new())])
            }
            Object::Tree(t) => {
                let mut children = Vec::with_capacity(t.entries.len());
                for e in &t.entries {
                    let p = if path.is_empty() {
                        e.name.clone()
                    } else {
                        format!("{path}/{}", e.name)
                    };
                    // File fallbacks, and the pre-merge tree of an embargo
                    // wrapper's marker entry.
                    if let Some(fb) = e.fallback {
                        children.push((fb, p.clone()));
                    }
                    children.push((e.id, p));
                }
                (true, children)
            }
            // Every version a conflict names: each is checked like any
            // object (`allowed`), so a public receiver never gets a sealed
            // side, only the conflict naming it.
            Object::Conflict(c) => (false, c.referenced_ids().into_iter().map(|id| (id, path.to_string())).collect()),
            // An annotated tag is sent with its tag ([`copy_annotations`]),
            // whose target went through the tag checks; nothing below it
            // is reached through it.
            Object::Blob(_) | Object::Sealed(_) | Object::Atag(_) => (false, Vec::new()),
        }))
    }
}

/// `f` over `items` on up to `threads` threads, results in order. Network
/// backends answer many requests at once (the SFTP client pipelines
/// whatever several threads send). Without the `os` feature (WASM has no
/// threads) always on the calling thread.
fn par_map<T: Sync, R: Send>(items: &[T], threads: usize, f: impl Fn(&T) -> R + Sync) -> Vec<R> {
    if threads <= 1 || items.len() <= 1 || cfg!(not(feature = "os")) {
        return items.iter().map(f).collect();
    }
    let next = AtomicUsize::new(0);
    let out: Vec<Mutex<Option<R>>> = items.iter().map(|_| Mutex::new(None)).collect();
    std::thread::scope(|s| {
        for _ in 0..threads.min(items.len()) {
            s.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                if i >= items.len() {
                    break;
                }
                let r = f(&items[i]);
                *out[i].lock().unwrap() = Some(r);
            });
        }
    });
    out.into_iter().map(|m| m.into_inner().unwrap().expect("every item mapped")).collect()
}

fn threads_for(backend: &dyn StorageBackend) -> usize {
    if backend.is_network() {
        16
    } else {
        4
    }
}

// ---- the other side's object inventory ---------------------------------------------

/// Every object id a (remote) store holds, from its pack indexes and its
/// loose fan-out directories, listed with many requests in flight.
struct Inventory {
    backend: Arc<dyn StorageBackend>,
    pack_dir: VPath,
    /// Pack name, raw index, parsed index.
    packs: Vec<(String, Vec<u8>, PackIndex)>,
    packed: HashMap<ObjectId, usize>,
    loose: HashSet<ObjectId>,
}

fn is_hex(s: &str) -> bool {
    s.bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

impl Inventory {
    fn load(backend: Arc<dyn StorageBackend>, warnings: &mut Vec<String>) -> Result<Inventory> {
        let threads = threads_for(&*backend);
        let root = VPath::new(".veil/objects")?;
        let pack_dir = root.join("pack");
        let listing = |p: &VPath| match backend.list_dir(p) {
            Ok(l) => Ok(l),
            Err(e) if e.is_not_found() => Ok(Vec::new()),
            Err(e) => Err(e),
        };
        let fanout: Vec<String> = listing(&root)?
            .into_iter()
            .filter(|d| d.kind == NodeKind::Dir && d.name.len() == 2 && is_hex(&d.name))
            .map(|d| d.name)
            .collect();
        let mut loose = HashSet::new();
        for (dir, entries) in fanout.iter().zip(par_map(&fanout, threads, |d| listing(&root.join(d)))) {
            for f in entries? {
                if f.kind == NodeKind::File && f.name.len() == 62 && is_hex(&f.name) {
                    loose.insert(ObjectId::from_hex(&format!("{dir}{}", f.name))?);
                }
            }
        }
        let names: Vec<String> = listing(&pack_dir)?
            .into_iter()
            .filter(|e| e.kind == NodeKind::File)
            .filter_map(|e| name_from_index_file(&e.name).map(str::to_string))
            .collect();
        let idx = par_map(&names, threads, |n| backend.read(&index_file(&pack_dir, n)));
        let mut packs = Vec::new();
        let mut packed = HashMap::new();
        for (name, raw) in names.into_iter().zip(idx) {
            let raw = match raw {
                Ok(r) => r,
                Err(e) if e.is_not_found() => continue, // removed meanwhile
                Err(e) => return Err(e),
            };
            match PackIndex::decode(&raw) {
                Ok(i) if i.name() == name => {
                    for id in i.ids() {
                        packed.insert(*id, packs.len());
                    }
                    packs.push((name, raw, i));
                }
                // Its objects are fetched one by one (and verified) instead.
                _ => warnings.push(format!("remote pack {} has an unreadable index", &name[..12])),
            }
        }
        Ok(Inventory {
            backend,
            pack_dir,
            packs,
            packed,
            loose,
        })
    }

    fn contains(&self, id: &ObjectId) -> bool {
        self.packed.contains_key(id) || self.loose.contains(id)
    }

    fn ids(&self) -> impl Iterator<Item = &ObjectId> {
        self.packed.keys().chain(self.loose.iter())
    }
}

/// Most pack data one pull downloads into memory in bulk (BUG-490): packs
/// past it are read one object at a time instead (ranged reads), so a
/// remote listing many or huge packs cannot make a pull hold them all.
/// Each pack is read to the size its index implies, never further.
const PREFETCH_LIMIT: u64 = 2 << 30;

/// Remote objects downloaded in bulk.
#[derive(Default)]
struct Prefetched {
    loaded: bool,
    packs: HashMap<usize, (MemoryBackend, Pack)>,
    loose: HashMap<ObjectId, Vec<u8>>,
}

/// Pull's view of the objects: local copies first, then the bulk download
/// of everything the remote has and we lack, then the remote one by one.
struct PullSource<'a> {
    local: &'a ObjectStore,
    local_ids: &'a HashSet<ObjectId>,
    remote: &'a ObjectStore,
    inv: &'a Inventory,
    got: RefCell<Prefetched>,
    bases: LruCache<Arc<Vec<u8>>>,
    bytes: RefCell<u64>,
}

impl PullSource<'_> {
    /// Download, in parallel, every remote pack holding an object we lack
    /// and every loose object we lack.
    fn prefetch(&self) -> Result<()> {
        let mut got = self.got.borrow_mut();
        if got.loaded {
            return Ok(());
        }
        got.loaded = true;
        let inv = self.inv;
        let threads = threads_for(&*inv.backend);
        let mut held = 0u64;
        let packs: Vec<usize> = (0..inv.packs.len())
            .filter(|&i| inv.packs[i].2.ids().iter().any(|id| !self.local_ids.contains(id)))
            .filter(|&i| {
                let len = inv.packs[i].2.pack_len();
                let fits = held.saturating_add(len) <= PREFETCH_LIMIT;
                if fits {
                    held += len;
                }
                fits
            })
            .collect();
        let data = par_map(&packs, threads, |&i| {
            let len = usize::try_from(inv.packs[i].2.pack_len()).map_err(|_| VeilError::Corrupt("pack".into(), "too large".into()))?;
            inv.backend.read_range(&pack_file(&inv.pack_dir, &inv.packs[i].0), 0, len)
        });
        let dir = VPath::new("p")?;
        let mut bytes = 0u64;
        for (i, data) in packs.into_iter().zip(data) {
            let (name, idx, _) = &inv.packs[i];
            let Ok(data) = data else { continue }; // fetched one by one instead
            bytes += (data.len() + idx.len()) as u64;
            let mem = MemoryBackend::new();
            mem.write(&pack_file(&dir, name), &data)?;
            mem.write(&index_file(&dir, name), idx)?;
            if let Ok(p) = Pack::open(&mem, &dir, name) {
                got.packs.insert(i, (mem, p));
            }
        }
        let loose: Vec<ObjectId> = inv.loose.iter().filter(|id| !self.local_ids.contains(id)).copied().collect();
        let data = par_map(&loose, threads, |id| {
            let h = id.hex();
            inv.backend.read(&VPath::new(&format!(".veil/objects/{}/{}", &h[..2], &h[2..]))?)
        });
        for (id, d) in loose.into_iter().zip(data) {
            if let Ok(d) = d {
                bytes += d.len() as u64;
                // Unverified copies are simply not used.
                if ObjectId::hash(&d) == id {
                    got.loose.insert(id, d);
                }
            }
        }
        *self.bytes.borrow_mut() += bytes;
        Ok(())
    }

    fn prefetched(&self, id: &ObjectId) -> Result<Option<Vec<u8>>> {
        let got = self.got.borrow();
        if let Some(d) = got.loose.get(id) {
            return Ok(Some(d.clone()));
        }
        if let Some((mem, p)) = self.inv.packed.get(id).and_then(|i| got.packs.get(i)) {
            // `Pack::get` re-hashes what it returns.
            return p.get(mem, id, &self.bases);
        }
        Ok(None)
    }
}

impl Source for PullSource<'_> {
    fn fetch(&self, id: &ObjectId) -> Result<Fetched> {
        if self.local_ids.contains(id) {
            match self.local.get_raw(id) {
                Ok(raw) => return Ok(Fetched::Have(raw)),
                // A damaged local copy is replaced from the remote.
                Err(VeilError::Corrupt(..)) | Err(VeilError::Missing(_)) => {}
                Err(e) => return Err(e),
            }
        }
        if self.inv.contains(id) {
            self.prefetch()?;
            if let Some(raw) = self.prefetched(id)? {
                return Ok(Fetched::New(raw));
            }
        }
        let raw = self.remote.get_raw(id)?;
        *self.bytes.borrow_mut() += raw.len() as u64;
        Ok(Fetched::New(raw))
    }
}

// ---- what the receiver provably has ------------------------------------------------

/// Snapshots in the closure of `refs`, walked on `store` (only those
/// `store` holds). Non-first parents of embargoed merges count only if
/// `parent_ok` says the receiver has them: they may have been redacted.
fn committed_closure(
    store: &ObjectStore,
    refs: &[ObjectId],
    mut parent_ok: impl FnMut(&ObjectId) -> bool,
) -> Result<HashSet<ObjectId>> {
    let mut known = HashSet::new();
    let mut seen = HashSet::new();
    let mut stack = refs.to_vec();
    while let Some(id) = stack.pop() {
        if !seen.insert(id) {
            continue;
        }
        let s = match store.snapshot(&id) {
            Ok(s) => s,
            Err(VeilError::Missing(_)) => continue,
            Err(e) => return Err(e),
        };
        known.insert(id);
        for (i, p) in s.parents.iter().enumerate() {
            if i == 0 || s.embargo.is_none() || parent_ok(p) {
                stack.push(*p);
            }
        }
    }
    Ok(known)
}

/// Plaintext trees reachable from `roots` (through directory entries and
/// embargo fallbacks), each once.
fn local_trees(store: &ObjectStore, roots: impl IntoIterator<Item = ObjectId>, mut visit: impl FnMut(&ObjectId, &crate::object::Tree) -> bool) -> Result<()> {
    let mut seen = HashSet::new();
    let mut stack: Vec<ObjectId> = roots.into_iter().collect();
    while let Some(id) = stack.pop() {
        if !seen.insert(id) {
            continue;
        }
        let t = match store.tree_object(&id) {
            Ok(t) => t,
            Err(e) if e.is_unreadable() || matches!(e, VeilError::Corrupt(..) | VeilError::Json(_)) => continue,
            Err(e) => return Err(e),
        };
        if !visit(&id, &t) {
            continue;
        }
        for e in &t.entries {
            if e.kind == EntryKind::Dir && e.visibility.is_public() {
                stack.push(e.id);
            }
            if let Some(fb) = e.fallback {
                if e.kind == EntryKind::Dir {
                    stack.push(fb);
                }
            }
        }
    }
    Ok(())
}

/// Every object reachable from the trees of `snaps`, as far as a receiver
/// holding those snapshots provably has it. On a public receiver embargo
/// wrappers (and their entries) are left out: what they hold may have
/// been withheld when they were sent and be releasable now.
fn known_objects(store: &ObjectStore, snaps: &HashSet<ObjectId>, public: bool) -> Result<HashSet<ObjectId>> {
    let mut roots = Vec::new();
    for s in snaps {
        match store.snapshot(s) {
            Ok(s) => roots.push(s.tree),
            Err(VeilError::Missing(_)) => {}
            Err(e) => return Err(e),
        }
    }
    let mut known = HashSet::new();
    local_trees(store, roots, |id, t| {
        if public && wrapper_parts(t).is_some() {
            return true; // descend (into the fallback), but know nothing here
        }
        known.insert(*id);
        for e in &t.entries {
            known.insert(e.id);
            if let Some(fb) = e.fallback {
                known.insert(fb);
            }
        }
        true
    })?;
    Ok(known)
}

fn too_deep(root: ObjectId) -> VeilError {
    VeilError::Corrupt(
        root.hex(),
        format!("directory nesting exceeds {MAX_TREE_DEPTH} levels; refusing hostile tree"),
    )
}

pub(crate) fn ancestors_in(store: &ObjectStore, tips: &[ObjectId]) -> Result<Vec<ObjectId>> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    let mut stack: Vec<ObjectId> = tips.to_vec();
    while let Some(id) = stack.pop() {
        if !seen.insert(id) {
            continue;
        }
        match store.snapshot(&id) {
            Ok(s) => stack.extend(s.parents.iter().copied()),
            Err(VeilError::Missing(_)) => continue,
            Err(e) => return Err(e),
        }
        out.push(id);
    }
    Ok(out)
}

/// The snapshots that unreleased embargo `embargo` withholds from a
/// public remote (its fix history): what releasing it publishes, beside
/// the merge's content.
pub fn withheld_by_embargo(local: &Repo, embargo: &str) -> Result<Vec<ObjectId>> {
    let mut out: Vec<ObjectId> = embargo_withheld(local, true)?
        .into_iter()
        .filter(|(_, e)| e == embargo)
        .map(|(id, _)| id)
        .collect();
    out.sort();
    Ok(out)
}

/// History that must not leave this repository yet: for every unreleased
/// embargoed merge in the local graph, the snapshots reachable only through
/// its merged-in (non-first) parents — the fix itself, and how it was made.
/// Maps each to the embargo that withholds it.
///
/// A public remote receives none of it before release. A team remote may
/// receive the part that is cloaked under **the embargo's own scope** (its
/// content and descriptions are sealed for exactly the readers the embargo
/// allows). Everything else is withheld there too, because team remotes are
/// also read by people outside the embargo's scope:
/// * plaintext snapshots;
/// * snapshots cloaked under another scope, even a wider one (BUG-043);
/// * snapshots that build on withheld ones (BUG-054): their trees carry the
///   withheld content, and sending them would leave a dangling parent that
///   blocks the push.
pub(crate) fn embargo_withheld(local: &Repo, public: bool) -> Result<HashMap<ObjectId, String>> {
    let mut out = HashMap::new();
    for id in local.visible_snapshots()? {
        let s = local.snapshot(&id)?;
        let Some(e) = &s.embargo else { continue };
        if s.parents.len() < 2 || local.keys().embargo_released(e) {
            continue;
        }
        // An unknown record (no scope to compare with) withholds everything.
        let scope = local.keys().load_embargo(e).ok().flatten().map(|r| r.scope);
        let mainline = local.ancestors(&s.parents[0])?;
        let mut merged_in: HashMap<ObjectId, Option<Arc<crate::object::Snapshot>>> = HashMap::new();
        for p in &s.parents[1..] {
            for a in local.ancestors(p)? {
                if !mainline.contains(&a) {
                    let snap = local.snapshot_opt(&a)?;
                    merged_in.insert(a, snap);
                }
            }
        }
        // Withheld: everything on a public remote; on a team remote, what
        // is not cloaked under the embargo's scope, and whatever has a
        // withheld parent. Post-order walk (parents first), iterative.
        let own = |snap: &Arc<crate::object::Snapshot>| public || scope.is_none() || snap.cloak != scope;
        let mut state: HashMap<ObjectId, bool> = HashMap::new();
        for start in merged_in.keys() {
            let mut stack = vec![(*start, false)];
            while let Some((a, expanded)) = stack.pop() {
                if state.contains_key(&a) {
                    continue;
                }
                let snap = &merged_in[&a];
                let parents = snap.iter().flat_map(|s| s.parents.iter()).filter(|p| merged_in.contains_key(*p));
                if !expanded {
                    stack.push((a, true));
                    stack.extend(parents.filter(|p| !state.contains_key(*p)).map(|p| (*p, false)));
                } else {
                    let w = snap.as_ref().is_some_and(own) || parents.into_iter().any(|p| state.get(p) == Some(&true));
                    state.insert(a, w);
                }
            }
        }
        let withheld = state.into_iter().filter(|(_, w)| *w).map(|(a, _)| a);
        for a in withheld {
            out.entry(a).or_insert_with(|| e.clone());
        }
    }
    Ok(out)
}

/// The snapshots to send for `tips`: every ancestor, except the withheld
/// merged-in history of unreleased embargoed merges (those merges reach the
/// remote with their extra parents redacted). Fails with a reason if the
/// tips reach withheld history any other way, i.e. some snapshot *builds
/// on* the embargoed fix and would publish it.
pub(crate) fn push_closure(
    store: &ObjectStore,
    keys: &Keychain,
    tips: &[ObjectId],
    withheld: &HashMap<ObjectId, String>,
) -> Result<Result<Vec<ObjectId>, String>> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    let mut stack: Vec<ObjectId> = tips.to_vec();
    while let Some(id) = stack.pop() {
        if !seen.insert(id) {
            continue;
        }
        if let Some(e) = withheld.get(&id) {
            return Ok(Err(format!(
                "{} is part of the history merged under unreleased embargo {e}; it is pushed when the embargo is released",
                id.short()
            )));
        }
        let s = match store.snapshot(&id) {
            Ok(s) => s,
            Err(VeilError::Missing(_)) => continue,
            Err(e) => return Err(e),
        };
        let embargoed_merge = s.embargo.as_deref().is_some_and(|e| !keys.embargo_released(e));
        for (i, p) in s.parents.iter().enumerate() {
            match withheld.get(p) {
                None => stack.push(*p),
                Some(_) if embargoed_merge && i > 0 => {} // redacted parent
                Some(e) => {
                    return Ok(Err(format!(
                        "snapshot {} builds on {}, which is withheld by unreleased embargo {e}; release the embargo first",
                        id.short(),
                        p.short()
                    )))
                }
            }
        }
        out.push(id);
    }
    Ok(Ok(out))
}

/// Merge key rings and embargo records from `src` into `dst`.
///
/// Nothing is merged as a union any more: each ring is a signed, hash-chained
/// log that only ever fast-forwards (see [`Keychain::merge_ring`]), so a
/// revocation cannot be undone by syncing with a replica that still lists
/// the member. Rings are merged before embargo records because the records'
/// signatures are checked against ring membership. Runs inside the
/// destination's transaction: each merge is a read-modify-write under its
/// lock (the keychain takes it reentrantly).
///
/// A public destination gets no rings (they name every member, BUG-077).
/// Its readers hold no scope key, so they only need embargo records, whose
/// released keys they check against the record's fingerprint
/// ([`Keychain::merge_embargo`]). Rings an earlier vl pushed there are left
/// alone (removing them would lock members out of a team remote that was
/// added as public by mistake), with a warning.
///
/// Team-vault records follow the rings: team destinations only, checked
/// against the destination's (just merged) ring ([`crate::team_vault`]).
/// `local` is the keychain holding this identity (the source on push, the
/// destination on pull); `pulling` turns on warnings about records that are
/// refused or will not count.
fn sync_meta(src: &Keychain, dst: &Keychain, public: bool, pulling: bool, warnings: &mut Vec<String>) -> Result<()> {
    if public {
        let records = crate::team_vault::record_count(&**dst.backend())?;
        if records > 0 {
            warnings.push(format!(
                "this public remote holds {records} team-vault record(s) (encrypted), which vl never pushes to \
                 public remotes. If it really is public, delete .veil/meta/vault/ there"
            ));
        }
        let left = dst.rings()?.len();
        if left > 0 {
            warnings.push(format!(
                "this public remote holds {left} key ring(s), pushed by an earlier vl, that name the members of \
                 their scopes; vl no longer pushes rings to public remotes. If it really is public, delete \
                 .veil/meta/keyrings/ there"
            ));
        }
    } else {
        for ring in src.rings()? {
            if let RingMerge::Rejected(w) = dst.merge_ring(&ring)? {
                warnings.push(w);
            }
        }
        dst.invalidate();
        let local = if pulling { dst } else { src };
        crate::team_vault::sync(src, dst, local, pulling, warnings)?;
    }
    for rec in src.embargoes()? {
        if let Some(w) = dst.merge_embargo(&rec)? {
            warnings.push(w);
        }
    }
    dst.invalidate();
    Ok(())
}

/// Fast-forward `local`'s key ring of `scope` to a team remote's, as a pull
/// would, without pulling anything else. `vl secret set --scope` runs it
/// first, so a value is sealed under the scope's current generation even
/// when this device has not pulled a revocation yet (BUG-524). `Ok(None)`:
/// the remote has no ring for the scope. `NotFound` if there is no Veil
/// repository there (not pushed to yet, or not reachable as a path).
pub fn refresh_ring(local: &Repo, remote_backend: Arc<dyn StorageBackend>, scope: &str) -> Result<Option<RingMerge>> {
    if !remote_backend.exists(&crate::repo::config_path())? {
        return Err(VeilError::NotFound("a Veil repository there".into()));
    }
    let remote_keys = Keychain::new(remote_backend, None, "remote".into());
    let Some(ring) = remote_keys.load_ring(scope)? else {
        return Ok(None);
    };
    let merged = local.keys().merge_ring(&ring)?;
    local.keys().invalidate();
    Ok(Some(merged))
}

// ---- remotes -----------------------------------------------------------------

/// Check a remote name: it becomes the first component of the remote tags
/// `<remote>/<tag>`. ASCII letters,
/// digits, `-`, `_` and `.`; not empty, no leading `-` or `.`, no `..`, not
/// ending in `.lock` (BUG-286). A `/` would make `origin/main/<tag>`
/// collide with remote `origin`'s tag `main/<tag>`.
pub fn validate_remote_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && !name.starts_with(['-', '.'])
        && !name.ends_with(".lock")
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        && !name.contains("..");
    if ok {
        Ok(())
    } else {
        Err(VeilError::repo(format!(
            "invalid remote name {name:?}: use letters, digits, '-', '_' and '.' (not first), as in `origin`"
        )))
    }
}

/// `url` with any credentials it embeds (`https://user:token@host/…`)
/// replaced by `***`, for messages and hooks.
pub fn redact_url(url: &str) -> String {
    match secret_of(url) {
        Some(secret) => url.replace(secret, "***"),
        None => url.to_string(),
    }
}

/// The credentials part of `url` that must never be printed: the whole
/// `user[:password]` of an `http(s)://` URL (a token is often passed as
/// the user name), the password of any other `scheme://user:password@`.
fn secret_of(url: &str) -> Option<&str> {
    let (scheme, rest) = url.split_once("://")?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let userinfo = &rest[..rest[..end].rfind('@')?];
    let web = matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https");
    match userinfo.split_once(':') {
        _ if web => Some(userinfo),
        Some((_, password)) => Some(password),
        None => None,
    }
    .filter(|s| !s.is_empty())
}

/// Add Veil remote `name` for `url` (`vl remote add`). Refuses an invalid
/// name and an existing remote.
pub fn add_remote(repo: &mut Repo, name: &str, url: &str, public: bool) -> Result<()> {
    validate_remote_name(name)?;
    // Under the repository lock (`update_config`): a concurrent `vl remote
    // add` must not be lost to this read-modify-write of repo.json.
    repo.update_config(|config| {
        if config.remotes.contains_key(name) {
            return Err(VeilError::repo(format!("remote '{name}' already exists")));
        }
        config.remotes.insert(
            name.to_string(),
            crate::repo::RemoteConfig {
                url: url.to_string(),
                public,
            },
        );
        Ok(())
    })?;
    repo.record_outside_view(
        format!("add remote {name}"),
        format!("remotes live in .veil/repo.json, outside the operation log; run `vl remote rm {name}`"),
    )?;
    Ok(())
}

/// Remove Veil remote `name` and its remote tags `<name>/*` (`vl remote
/// rm`, BUG-282). The remote tags go first, in one operation; the remote
/// itself last, so that an interruption leaves the remote configured (a
/// retry finishes the job), never remote tags of a remote that is gone.
pub fn remove_remote(repo: &mut Repo, name: &str) -> Result<crate::repo::RemoteConfig> {
    let removed = crate::repo::read_config(&**repo.backend())?
        .remotes
        .get(name)
        .cloned()
        .ok_or_else(|| VeilError::repo(format!("no remote named '{name}'")))?;
    let mut tx = repo.transaction(format!("remove remote {name}"))?;
    let prefix = format!("{name}/");
    tx.view.remote_tags.retain(|k, _| !k.starts_with(&prefix));
    tx.manual_undo(format!(
        "remotes live in .veil/repo.json, outside the operation log; add it back with `vl remote add {name} {}{}` \
         (its remote tags come back with the next pull)",
        removed.url,
        if removed.public { " --public" } else { "" }
    ));
    tx.commit()?;
    repo.update_config(|config| {
        config.remotes.remove(name);
        Ok(())
    })?;
    Ok(removed)
}

// ---- tag deletion ---------------------------------------------------------------

/// Where [`deleted_tags`] are recorded: repository-local, outside the view
/// and the operation log, so no repository format changes (an older vl
/// ignores the file and never rewrites it).
fn deleted_tags_path() -> VPath {
    VPath::new(".veil/local/deleted_tags.json").expect("valid path")
}

/// Tags deleted in this repository with `vl tag delete`: name → the
/// snapshot it named then.
///
/// A pull creates a local tag for every remote tag it has no local tag
/// for. Without this record the next pull would bring a deleted tag right
/// back (BUG-280). With it, a pull leaves the tag deleted as long as the
/// remote's tag is still where it was (or behind it): the deletion is the
/// newer decision. Once somebody moves the tag on the remote to work this
/// repository has not seen, the pull recreates it and says so: new work is
/// never hidden by an old deletion. Like jj's remote-bookmark tracking, the
/// remote tag `<remote>/<tag>` itself always shows what the remote holds.
///
/// An entry is dropped once the tag exists here again (set again, or
/// brought back by `vl undo`) and a pull sees it, or when a pull recreates
/// it.
pub fn deleted_tags(backend: &dyn StorageBackend) -> Result<std::collections::BTreeMap<String, ObjectId>> {
    match backend.read_opt(&deleted_tags_path())? {
        Some(raw) => serde_json::from_slice(&raw).map_err(|e| {
            VeilError::repo(format!(
                "{} is damaged ({e}); delete it (tags deleted here may then come back with the next pull)",
                deleted_tags_path()
            ))
        }),
        None => Ok(Default::default()),
    }
}

fn save_deleted_tags(backend: &dyn StorageBackend, map: &std::collections::BTreeMap<String, ObjectId>) -> Result<()> {
    if map.is_empty() {
        if backend.exists(&deleted_tags_path())? {
            backend.remove_file(&deleted_tags_path())?;
        }
        return Ok(());
    }
    backend.write(&deleted_tags_path(), &serde_json::to_vec_pretty(map)?)
}

/// Record that tag `name`, naming `target`, was deleted here (see
/// [`deleted_tags`]). Called under the repository lock.
pub(crate) fn record_tag_deletion(backend: &dyn StorageBackend, name: &str, target: ObjectId) -> Result<()> {
    let mut map = deleted_tags(backend)?;
    map.insert(name.to_string(), target);
    save_deleted_tags(backend, &map)
}

/// What a pull does about a remote tag `name` (at `remote_target`) that
/// has no local tag: `true` to leave it deleted here (see
/// [`deleted_tags`]). Drops the record when the remote moved past it.
fn stays_deleted(
    repo: &Repo,
    deleted: &mut std::collections::BTreeMap<String, ObjectId>,
    name: &str,
    remote_target: &ObjectId,
) -> Result<bool> {
    let Some(was) = deleted.get(name) else { return Ok(false) };
    if repo.is_ancestor(remote_target, was)? {
        return Ok(true);
    }
    deleted.remove(name);
    Ok(false)
}

/// Apply the pull rules of [`deleted_tags`] for `remote_tags` (name →
/// target, as the remote has them) in transaction `tx`: returns the names
/// that stay deleted, and those deleted here that the pull recreates
/// because the remote moved past the deletion; saves the updated record.
/// Also drops entries for tags that exist here again.
pub(crate) fn tags_staying_deleted(
    tx: &crate::transaction::Transaction<'_>,
    remote_tags: &[(String, ObjectId)],
) -> Result<(HashSet<String>, Vec<String>)> {
    let backend = tx.repo().backend().clone();
    let mut deleted = deleted_tags(&*backend)?;
    let mut stay = HashSet::new();
    let mut recreated = Vec::new();
    if deleted.is_empty() {
        return Ok((stay, recreated));
    }
    let before = deleted.clone();
    deleted.retain(|name, _| !tx.view.tags.contains_key(name));
    for (name, target) in remote_tags {
        if tx.view.tags.contains_key(name) || !deleted.contains_key(name) {
            continue;
        }
        if stays_deleted(tx.repo(), &mut deleted, name, target)? {
            stay.insert(name.clone());
        } else {
            recreated.push(name.clone());
        }
    }
    if deleted != before {
        save_deleted_tags(&*backend, &deleted)?;
    }
    Ok((stay, recreated))
}

/// Delete tags `names` on a Veil remote (`vl push --delete`), and the
/// remote tags `<remote_name>/<name>` here.
///
/// Each tag must already be deleted here (`vl tag delete`): otherwise the
/// next `vl push` would publish it again. A deletion is refused (listed in
/// `tags_rejected`) when the remote's tag has moved to work beyond what it
/// named here when it was deleted (a teammate pushed to it since), or, for
/// a tag never deleted here, to a snapshot this repository does not hold;
/// `force` deletes it regardless. A tag the remote does not have is
/// reported in `warnings`, and is not an error.
///
/// History is not deleted: the remote's snapshots stay until nothing
/// references them and `vl -R <remote> gc` prunes them after its grace
/// period, and every clone keeps what it pulled.
pub fn delete_remote_tags(
    local: &mut Repo,
    remote_name: &str,
    remote_backend: Arc<dyn StorageBackend>,
    names: &[String],
    force: bool,
) -> Result<SyncReport> {
    for n in names {
        if local.view().tags.contains_key(n) {
            return Err(VeilError::repo(format!(
                "tag '{n}' still exists here; delete it first with `vl tag delete {n}` (a later `vl push` would publish it again)"
            )));
        }
    }
    if !is_repo(&*remote_backend) {
        return Err(VeilError::NotFound(format!("Veil repository at remote '{remote_name}'")));
    }
    let deleted = deleted_tags(&**local.backend())?;
    let mut remote = Repo::open(remote_backend, None, "remote")?;
    let mut report = SyncReport::default();
    let mut tx = remote.transaction(format!("delete tags from {}", local.repo_id()))?;
    for n in names {
        let Some(existing) = tx.view.tags.get(n).cloned() else {
            report.warnings.push(format!("tag '{n}' is not on {remote_name}; nothing to delete there"));
            report.tags_deleted.push(n.clone());
            continue;
        };
        let safe = match deleted.get(n) {
            Some(was) => local.is_ancestor(&existing.target, was)?,
            None => local.snapshot_opt(&existing.target)?.is_some(),
        };
        if !force && !safe {
            report.tags_rejected.push(n.clone());
            report.tags_skipped.push((
                n.clone(),
                format!(
                    "{remote_name} has moved it to {}, which you have not seen; pull first, or use --force",
                    existing.target.short()
                ),
            ));
            continue;
        }
        tx.view.tags.remove(n);
        // Its history stops being visible there unless something else
        // reaches it, so that `gc` on the remote can prune an experiment
        // pushed by mistake.
        tx.view.heads.remove(&existing.target);
        report.tags_deleted.push(n.clone());
    }
    tx.commit()?;
    if !report.tags_deleted.is_empty() {
        let mut ltx = local.transaction(format!("delete tags on {remote_name}"))?;
        for n in &report.tags_deleted {
            let key = format!("{remote_name}/{n}");
            if ltx.view.remote_tags.remove(&key).is_some() {
                report.remote_tags_removed.push(key);
            }
        }
        ltx.commit()?;
    }
    Ok(report)
}

/// Push tags (all by default) and their history to `remote`.
pub fn push(
    local: &mut Repo,
    remote_backend: Arc<dyn StorageBackend>,
    public: bool,
    only_tags: &[String],
    force: bool,
) -> Result<SyncReport> {
    push_with(local, remote_backend, public, only_tags, force, &SyncOptions::default())
}

/// [`push`] with options.
pub fn push_with(
    local: &mut Repo,
    remote_backend: Arc<dyn StorageBackend>,
    public: bool,
    only_tags: &[String],
    force: bool,
    opts: &SyncOptions,
) -> Result<SyncReport> {
    let mut remote = open_or_init_remote(&remote_backend)?;
    let mut report = SyncReport::default();
    let (sendable, withheld) = sendable_tags(local, public, only_tags, &mut report)?;
    // Objects and metadata are copied under the remote's lock: metadata
    // merges are read-modify-writes, and objects must land before the
    // operation that references them.
    let mut tx = remote.transaction(format!("push from {}", local.repo_id()))?;
    let selected = accepted_tags(local, sendable, &tx.view.tags, force, opts.force_tags, &mut report)?;
    let tips: Vec<ObjectId> = selected.iter().map(|(_, t)| t.target).collect();
    let ids = push_closure(local.store(), local.keys(), &tips, &withheld)?
        .map_err(|why| VeilError::repo(format!("push: {why}")))?;
    {
        let dst = tx.repo().store().clone();
        let src = StoreSource(local.store());
        if opts.full {
            let mut xfer = Transfer {
                src: &src,
                sink: Sink::Store(&dst),
                src_keys: local.keys(),
                public,
                known: Box::new(|_| false),
                seen: HashSet::new(),
                heights: HashMap::new(),
                report,
            };
            for id in ids {
                xfer.copy(id, "")?;
            }
            report = xfer.report;
        } else {
            report = push_incremental(local, &tx.view.refs(), &dst, ids, public, report, None)?;
        }
    }
    // Annotated tag objects of the tags sent (format 5): after the history
    // they point at, before the operation that names them.
    let annotations: Vec<ObjectId> = selected.iter().filter_map(|(_, t)| t.annotation).collect();
    copy_annotations(local.store(), tx.repo().store(), &annotations, public)?;
    // Releases staged by `vl embargo release` reach the record only now,
    // as it leaves: before this, `vl undo` could still take them back
    // (BUG-109). Objects sealed under their keys may already have been
    // sent above; without the key they are unreadable.
    report.releases_published = local.keys().publish_staged_releases()?;
    sync_meta(local.keys(), tx.repo().keys(), public, false, &mut report.warnings)?;
    for (name, tag) in selected {
        // A push never strips the annotation the remote's tag has for the
        // same target (a clone that has not received it yet).
        let existing = tx.view.tags.get(&name).cloned();
        let annotation = tag
            .annotation
            .or(existing.as_ref().filter(|e| e.target == tag.target).and_then(|e| e.annotation));
        if existing.as_ref().is_some_and(|e| e.target == tag.target && e.annotation == annotation) {
            report.remote_tags.push((name, tag.target));
            continue;
        }
        for p in &local.snapshot(&tag.target)?.parents {
            tx.view.heads.remove(p);
        }
        tx.view.heads.insert(tag.target);
        let cloak = if public { None } else { tag.cloak };
        tx.view.tags.insert(
            name.clone(),
            Tag {
                target: tag.target,
                cloak,
                annotation,
            },
        );
        report.remote_tags.push((name.clone(), tag.target));
        report.tags_updated.push((name, tag.target));
    }
    tx.commit()?;
    Ok(report)
}

/// The tags a push of `only_tags` (all if empty) may send, before the
/// remote is consulted, and the embargo-withheld history. Cloaked tags
/// (on a public remote) and tags that would publish withheld history are
/// recorded in `report.tags_skipped` with the reason. Shared by
/// [`push_with`] and its dry run ([`crate::push_plan`]), so the two agree.
#[allow(clippy::type_complexity)]
pub(crate) fn sendable_tags(
    local: &Repo,
    public: bool,
    only_tags: &[String],
    report: &mut SyncReport,
) -> Result<(Vec<(String, Tag)>, HashMap<ObjectId, String>)> {
    let mut selected: Vec<(String, Tag)> = Vec::new();
    for (name, tag) in &local.view().tags {
        if !only_tags.is_empty() && !only_tags.contains(name) {
            continue;
        }
        if public && tag.cloak.is_some() {
            report
                .tags_skipped
                .push((name.clone(), "cloaked tag is never pushed to a public remote".into()));
            continue;
        }
        if let Some(why) = annotation_problem(local.store(), name, tag, public)? {
            report.tags_skipped.push((name.clone(), why));
            continue;
        }
        selected.push((name.clone(), tag.clone()));
    }
    for t in only_tags {
        if !local.view().tags.contains_key(t) {
            return Err(VeilError::NotFound(format!("tag '{t}'")));
        }
    }
    // The merged-in history of an unreleased embargoed merge stays here, and
    // so does any tag that would publish it by another route.
    let withheld = embargo_withheld(local, public)?;
    let mut sendable = Vec::new();
    for (name, tag) in selected {
        match push_closure(local.store(), local.keys(), &[tag.target], &withheld)? {
            Ok(_) => sendable.push((name, tag)),
            Err(why) => report.tags_skipped.push((name, why)),
        }
    }
    Ok((sendable, withheld))
}

/// Why the tag `name` may not be pushed because of its annotation (format
/// 5), if it may not: the atag is missing or not an atag, names another tag
/// or target (a transplanted or re-targeted annotation, which would
/// publish a release tag the signer never made), or (`public`) has a
/// sealed message, which only a cloaked tag has.
pub(crate) fn annotation_problem(store: &ObjectStore, name: &str, tag: &Tag, public: bool) -> Result<Option<String>> {
    let Some(a) = tag.annotation else { return Ok(None) };
    let atag = match store.get(&a) {
        Ok(Object::Atag(atag)) => atag,
        Ok(other) => return Ok(Some(format!("its annotation {} is a {}, not an annotated tag", a.short(), other.kind_name()))),
        Err(VeilError::Missing(_)) => return Ok(Some(format!("its annotation {} is missing", a.short()))),
        Err(VeilError::Corrupt(..) | VeilError::Json(_)) => {
            return Ok(Some(format!("its annotation {} is damaged", a.short())))
        }
        Err(e) => return Err(e),
    };
    if atag.name != name || atag.target != tag.target {
        return Ok(Some(format!(
            "its annotation {} belongs to another tag or target ({})",
            a.short(),
            atag.verify(name, &tag.target).describe()
        )));
    }
    if public && atag.is_sealed() {
        return Ok(Some("its annotation's message is sealed; it is never pushed to a public remote".into()));
    }
    Ok(None)
}

/// Copy the annotated tag objects `ids` (format 5) from `src` to `dst`
/// with `put_raw`, so a destination below format 5 refuses them with the
/// upgrade hint. On a `public` destination an atag with a sealed message
/// is never written (the tag checks already skip its tag; this is the
/// second line).
fn copy_annotations(src: &ObjectStore, dst: &ObjectStore, ids: &[ObjectId], public: bool) -> Result<usize> {
    let mut copied = 0;
    for id in ids {
        if dst.has(id) {
            continue;
        }
        let raw = src.get_raw(id)?;
        match Object::decode(&raw)? {
            Object::Atag(a) if public && a.is_sealed() => continue,
            Object::Atag(_) => {}
            other => {
                return Err(VeilError::Corrupt(
                    id.hex(),
                    format!("expected an annotated tag, found a {}", other.kind_name()),
                ))
            }
        }
        if dst.put_raw(id, &raw)? {
            copied += 1;
        }
    }
    Ok(copied)
}

/// Fetch the annotation `id` of the remote tag `name → target` from
/// `remote` into `local`, checking it on the way: hash, canonical atag,
/// and the same name and target as the tag (a hostile remote cannot
/// transplant a signed annotation onto another tag). `Ok(None)` with a
/// warning in `warnings` when the annotation is not usable; the tag is
/// then received without it.
fn fetch_annotation(
    local: &ObjectStore,
    remote: &ObjectStore,
    name: &str,
    tag: &Tag,
    warnings: &mut Vec<String>,
) -> Result<Option<ObjectId>> {
    let Some(id) = tag.annotation else { return Ok(None) };
    let raw = match local.get_raw(&id) {
        Ok(raw) => raw,
        Err(VeilError::Missing(_)) => match remote.get_raw(&id) {
            Ok(raw) => raw,
            Err(VeilError::Missing(_)) => {
                warnings.push(format!("remote tag '{name}': its annotation {} is missing; received without it", id.short()));
                return Ok(None);
            }
            Err(e) => return Err(e),
        },
        Err(e) => return Err(e),
    };
    if ObjectId::hash(&raw) != id {
        warnings.push(format!("remote tag '{name}': its annotation {} is damaged; received without it", id.short()));
        return Ok(None);
    }
    let atag = match Object::decode(&raw) {
        Ok(Object::Atag(a)) => a,
        Ok(_) | Err(VeilError::Corrupt(..)) | Err(VeilError::Json(_)) => {
            warnings.push(format!("remote tag '{name}': its annotation {} is not a valid annotated tag; received without it", id.short()));
            return Ok(None);
        }
        Err(e) => return Err(e),
    };
    if atag.name != name || atag.target != tag.target {
        warnings.push(format!(
            "remote tag '{name}': its annotation {} belongs to another tag or target; received without it",
            id.short()
        ));
        return Ok(None);
    }
    local.put_raw(&id, &raw)?;
    Ok(Some(id))
}

/// Of `sendable`, the tags the remote (holding `remote_tags`) takes; the
/// others are rejected (non-fast-forward without `force`) in `report`.
///
/// Which tags the remote takes is decided before anything is sent: the
/// history of a rejected tag is not uploaded (BUG-288). Nothing the
/// remote's committed view does not reach would tell a retry that the
/// remote already holds it, so every retry would send it again as one
/// more pack. Decided on the local graph: it holds the whole history of
/// each tag, and walking the remote's would cost a round trip per
/// snapshot.
pub(crate) fn accepted_tags(
    local: &Repo,
    sendable: Vec<(String, Tag)>,
    remote_tags: &std::collections::BTreeMap<String, Tag>,
    force: bool,
    force_tags: bool,
    report: &mut SyncReport,
) -> Result<Vec<(String, Tag)>> {
    let mut accepted = Vec::new();
    for (name, tag) in sendable {
        if let Some(existing) = remote_tags.get(&name) {
            // A release tag (annotated, on either side) is never moved on
            // the remote without `--force-tags` (BUG-710), even forward.
            // With it, the release is replaced.
            let release = existing.annotation.is_some() || tag.annotation.is_some();
            if existing.target != tag.target && release {
                if !force_tags {
                    report.tags_rejected.push(name.clone());
                    report.tags_skipped.push((
                        name,
                        format!(
                            "release tag: the remote's is at {}; replacing a release takes --force-tags",
                            existing.target.short()
                        ),
                    ));
                    continue;
                }
                accepted.push((name, tag));
                continue;
            }
            if existing.target != tag.target && !force && !local.is_ancestor(&existing.target, &tag.target)? {
                report.tags_rejected.push(name.clone());
                report
                    .tags_skipped
                    .push((name, "remote has diverged (non-fast-forward; use --force)".into()));
                continue;
            }
        }
        accepted.push((name, tag));
    }
    Ok(accepted)
}

/// After a push to the remote named `remote_name`, record the tags it now
/// holds (`report.remote_tags`) as `<remote_name>/<tag>`, as `vl pull` does
/// and as Git and jj update remote-tracking refs on push (BUG-248). One
/// local operation, `push to <remote_name>`, if anything changed. Rejected
/// tags are not recorded: the remote's version may not even be here.
pub fn record_pushed_tags(local: &mut Repo, remote_name: &str, report: &SyncReport) -> Result<()> {
    if report.remote_tags.is_empty() {
        return Ok(());
    }
    let mut tx = local.transaction(format!("push to {remote_name}"))?;
    for (name, target) in &report.remote_tags {
        tx.view.remote_tags.insert(format!("{remote_name}/{name}"), *target);
    }
    tx.commit()?;
    Ok(())
}

/// Send `ids` (snapshots) and what they reference, except what the
/// remote's committed view (`remote_refs`) provably holds, as packs.
///
/// With `plan` (a dry run), nothing is written: the same objects are
/// recorded there and packed into [`Discard`], and `dst` is only read.
pub(crate) fn push_incremental(
    local: &Repo,
    remote_refs: &[ObjectId],
    dst: &ObjectStore,
    ids: Vec<ObjectId>,
    public: bool,
    report: SyncReport,
    mut plan: Option<&mut PlanRecord>,
) -> Result<SyncReport> {
    let store = local.store();
    let mut warnings = Vec::new();
    let inventory: RefCell<Option<Inventory>> = RefCell::new(None);
    let load_inventory = || -> Result<()> {
        if inventory.borrow().is_none() {
            *inventory.borrow_mut() = Some(Inventory::load(dst.backend().clone(), &mut Vec::new())?);
        }
        Ok(())
    };
    // An embargoed merge's extra parents count only if they reached the
    // remote in a pack (complete by construction): they may have been
    // redacted when the merge was pushed.
    let mut inv_err = None;
    let known_snaps = committed_closure(store, remote_refs, |p| match load_inventory() {
        Ok(()) => inventory.borrow().as_ref().is_some_and(|i| i.packed.contains_key(p)),
        Err(e) => {
            inv_err.get_or_insert(e);
            false
        }
    })?;
    if let Some(e) = inv_err {
        return Err(e);
    }
    let to_send: Vec<ObjectId> = ids.into_iter().filter(|i| !known_snaps.contains(i)).collect();
    if let Some(p) = plan.as_deref_mut() {
        p.known_snapshots = known_snaps.clone();
        p.sent_snapshots = to_send.clone();
    }
    // Trees of the known snapshots the new ones build on.
    let mut boundary = HashSet::new();
    for id in &to_send {
        for p in &store.snapshot(id)?.parents {
            if known_snaps.contains(p) {
                boundary.insert(*p);
            }
        }
    }
    let known = known_objects(store, &boundary, public)?;
    // On a public remote, released embargoes may have made content under
    // already-pushed snapshots sendable: revisit their wrappers (sending
    // only what the remote does not hold yet).
    let mut rewalk = Vec::new();
    if public && local.keys().embargoes()?.iter().any(|r| local.keys().embargo_released(&r.id)) {
        for s in &known_snaps {
            let tree = store.snapshot(s)?.tree;
            if let Ok(t) = store.tree_object(&tree) {
                if wrapper_parts(&t).is_some() {
                    rewalk.push(tree);
                }
            }
        }
    }
    if !rewalk.is_empty() {
        load_inventory()?;
    }
    let inventory = inventory.into_inner();
    let src = StoreSource(store);
    let pack_dir = dst.pack_dir();
    let sink = match plan {
        None => Sink::Pack(Box::new(PackSink::new(dst, pack_dir, None, 0))),
        Some(p) => {
            let mut pack = PackSink::new(dst, pack_dir, None, 0);
            pack.backend = &DISCARD;
            Sink::Plan(Box::new(pack), &p.objects)
        }
    };
    let mut xfer = Transfer {
        src: &src,
        sink,
        src_keys: local.keys(),
        public,
        known: Box::new(|id| known.contains(id)),
        seen: HashSet::new(),
        heights: HashMap::new(),
        report,
    };
    for id in &to_send {
        xfer.copy(*id, "")?;
    }
    if let Some(inv) = inventory.as_ref().filter(|_| !rewalk.is_empty()) {
        xfer.known = Box::new(|id| known.contains(id) || inv.contains(id));
        let mut wrappers = Vec::new();
        local_trees(store, rewalk, |_, t| {
            if wrapper_parts(t).is_some() {
                wrappers.push(t.clone());
            }
            true
        })?;
        for w in wrappers {
            for e in &w.entries {
                xfer.copy(e.id, &e.name)?;
                if let Some(fb) = e.fallback {
                    xfer.copy(fb, "")?;
                }
            }
        }
    }
    let Transfer { sink, mut report, .. } = xfer;
    sink.finish(&mut report)?;
    report.warnings.append(&mut warnings);
    // Nothing reads the remote store after this (the tag checks run on the
    // local graph), so its pack list is not reloaded: that would download
    // every remote index.
    Ok(report)
}

/// Why `target` cannot be the target of a tag, if it cannot.
fn unusable_target(store: &ObjectStore, target: &ObjectId) -> Result<Option<&'static str>> {
    match store.snapshot(target) {
        Ok(_) => Ok(None),
        Err(VeilError::Missing(_)) => Ok(Some("is missing")),
        Err(VeilError::Corrupt(..)) | Err(VeilError::Json(_)) => Ok(Some("is not a valid snapshot")),
        Err(e) if e.is_unreadable() => Ok(Some("is not readable")),
        Err(e) => Err(e),
    }
}

/// Open the repository a push goes to, creating an empty bare one first if
/// there is none.
///
/// Initialisation happens under the remote's lock, re-checked once the
/// lock is held: when several first pushes reach an empty remote at once,
/// one initialises it and the others find a repository and push to it
/// normally (BUG-120). Without the lock the losers failed with
/// "already exists", or, worse, a late loser could reset `op_head` to its
/// own empty view after the winner had already pushed. An error while
/// checking (a flaky connection) is an error, never a reason to initialise
/// over what may be an existing repository.
fn open_or_init_remote(backend: &Arc<dyn StorageBackend>) -> Result<Repo> {
    let config = crate::repo::config_path();
    if backend.exists(&config)? {
        return Repo::open(backend.clone(), None, "remote");
    }
    refuse_foreign_directory(&**backend)?;
    let lock = crate::lock::RepoLock::acquire(backend.clone())?;
    let repo = if backend.exists(&config)? {
        Repo::open(backend.clone(), None, "remote")
    } else {
        Repo::init_bare(backend.clone())
    };
    drop(lock);
    match repo {
        // Initialised meanwhile by a client that did not take the lock
        // (an older version): push to it like to any other repository.
        Err(VeilError::AlreadyExists(_)) => Repo::open(backend.clone(), None, "remote"),
        r => r,
    }
}

/// A push creates a repository only where there is nothing yet: a missing
/// or empty directory (or one holding only a `.veil/` an interrupted first
/// push left). Anything else is somebody's files, most likely a typo in the
/// remote's URL (`../proj` for `../proj.veil`), and turning it into a bare
/// repository would break every `vl` command run there (BUG-283).
pub(crate) fn refuse_foreign_directory(backend: &dyn StorageBackend) -> Result<()> {
    let listing = match backend.list_dir_full(&VPath::root()) {
        Ok(listing) => listing,
        Err(e) if e.is_not_found() => return Ok(()),
        Err(e) => return Err(e),
    };
    let foreign: Vec<&str> = listing
        .entries
        .iter()
        .map(|e| e.name.as_str())
        .chain(listing.special.iter().map(String::as_str))
        .chain(listing.unrepresentable.iter().map(String::as_str))
        .filter(|n| *n != crate::repo::VEIL_DIR)
        .collect();
    if foreign.is_empty() {
        return Ok(());
    }
    Err(VeilError::repo(format!(
        "the remote is a directory that is not empty and not a Veil repository (it holds {}{}); \
         a push only creates a repository in a new or empty directory. Check the remote's URL (`vl remote list`)",
        foreign.iter().take(3).map(|n| format!("'{n}'")).collect::<Vec<_>>().join(", "),
        if foreign.len() > 3 { ", …" } else { "" }
    )))
}

/// Fetch every tag from `remote`, record them as `<remote_name>/<tag>`, and
/// create or fast-forward local tags.
pub fn pull(local: &mut Repo, remote_name: &str, remote_backend: Arc<dyn StorageBackend>) -> Result<SyncReport> {
    pull_with(local, remote_name, remote_backend, &SyncOptions::default())
}

/// [`pull`] with options.
pub fn pull_with(
    local: &mut Repo,
    remote_name: &str,
    remote_backend: Arc<dyn StorageBackend>,
    opts: &SyncOptions,
) -> Result<SyncReport> {
    if !is_repo(&*remote_backend) {
        return Err(VeilError::NotFound(format!("Veil repository at remote '{remote_name}'")));
    }
    let remote = Repo::open(remote_backend.clone(), None, "remote")?;
    let tags: Vec<(String, Tag)> = remote.view().tags.clone().into_iter().collect();
    // Under the local lock, like push (see there).
    let mut tx = local.transaction(format!("pull from {remote_name}"))?;
    let mut report = SyncReport::default();
    if opts.full {
        // Only snapshot targets are fetched; tags on anything else (missing,
        // a tree, a blob) are skipped with a warning below.
        let mut tips = Vec::new();
        for (_, t) in &tags {
            match remote.store().get(&t.target) {
                Ok(Object::Snapshot(_)) => tips.push(t.target),
                Ok(_) | Err(VeilError::Missing(_)) => {}
                Err(e) => return Err(e),
            }
        }
        let src = StoreSource(remote.store());
        let mut xfer = Transfer {
            src: &src,
            sink: Sink::Store(tx.repo().store()),
            src_keys: remote.keys(),
            public: false,
            known: Box::new(|_| false),
            seen: HashSet::new(),
            heights: HashMap::new(),
            report,
        };
        for id in ancestors_in(remote.store(), &tips)? {
            xfer.copy(id, "")?;
        }
        report = xfer.report;
    } else {
        let local_refs = tx.view.refs();
        report = pull_incremental(tx.repo().store(), &local_refs, &remote, &remote_backend, &tags, report)?;
    }
    sync_meta(remote.keys(), tx.repo().keys(), false, true, &mut report.warnings)?;
    tx.repo().keys().invalidate();
    // Change and snapshot ids a new local tag must not shadow: those of
    // local history and of everything this pull brings in (a teammate's
    // change, tagged after its id by someone else, BUG-105).
    let mut revisions = crate::revset::RevisionNames::default();
    let mut incoming = Vec::new();
    for (_, tag) in &tags {
        if unusable_target(tx.repo().store(), &tag.target)?.is_none() {
            incoming.push(tag.target);
        }
    }
    // Remote tags of tags the remote no longer has are pruned (as Git's
    // `fetch --prune` and jj do). A local tag of that name is kept: a
    // teammate's deletion never deletes your tag (BUG-280).
    let prefix = format!("{remote_name}/");
    let on_remote: HashSet<&str> = tags.iter().map(|(n, _)| n.as_str()).collect();
    let gone: Vec<String> = tx
        .view
        .remote_tags
        .keys()
        .filter(|k| k.strip_prefix(&prefix).is_some_and(|t| !on_remote.contains(t)))
        .cloned()
        .collect();
    for key in gone {
        tx.view.remote_tags.remove(&key);
        let name = &key[prefix.len()..];
        if tx.view.tags.contains_key(name) {
            report.warnings.push(format!(
                "tag '{name}' was deleted on {remote_name}; your tag '{name}' is kept. Delete it with \
                 `vl tag delete {name}`, or the next `vl push {remote_name}` publishes it again"
            ));
        }
        report.remote_tags_removed.push(key);
    }
    let usable: Vec<(String, ObjectId)> = tags
        .iter()
        .filter(|(_, t)| incoming.contains(&t.target))
        .map(|(n, t)| (n.clone(), t.target))
        .collect();
    let (stay_deleted, recreated) = tags_staying_deleted(&tx, &usable)?;
    for name in recreated {
        report.warnings.push(format!(
            "tag '{name}', deleted here, has moved on {remote_name} to work you had not seen: it is back. \
             Delete it again, or delete it there too with `vl push {remote_name} --delete {name}`"
        ));
    }
    for (name, mut tag) in tags {
        // Tag names and targets come from the remote: a name may carry
        // terminal escapes or path tricks, and a target may be missing or
        // not a snapshot, which would break every later graph query.
        if validate_tag_name(&name).is_err() {
            report
                .warnings
                .push(format!("skipped remote tag {name:?}: invalid tag name"));
            continue;
        }
        if let Some(why) = unusable_target(tx.repo().store(), &tag.target)? {
            report
                .warnings
                .push(format!("skipped remote tag '{name}': target {} {why}", tag.target.short()));
            continue;
        }
        // Its annotation (format 5), checked against the tag.
        tag.annotation = fetch_annotation(tx.repo().store(), remote.store(), &name, &tag, &mut report.warnings)?;
        tx.view.remote_tags.insert(format!("{remote_name}/{name}"), tag.target);
        match tx.view.tags.get(&name).cloned() {
            None if stay_deleted.contains(&name) => report.tags_kept_deleted.push(name),
            None => {
                let refs = || {
                    let mut r = tx.view.refs();
                    r.extend(incoming.iter().copied());
                    r
                };
                if revisions.shadows(tx.repo(), refs, &name)? {
                    report.warnings.push(format!(
                        "no local tag created for remote tag '{name}': the name is also a change or snapshot id of this repository; use {remote_name}/{name}"
                    ));
                    continue;
                }
                tx.view.tags.insert(name.clone(), tag.clone());
                report.tags_updated.push((name, tag.target));
            }
            Some(existing) if existing.target == tag.target => {
                // The remote's annotation for the same target, if this tag
                // has none yet.
                if existing.annotation.is_none() && tag.annotation.is_some() {
                    tx.view.tags.insert(
                        name.clone(),
                        Tag {
                            annotation: tag.annotation,
                            ..existing
                        },
                    );
                }
            }
            // A release tag (annotated, format 5) is immutable: a remote
            // that holds it elsewhere (a teammate's `--force`, or a hostile
            // remote) never moves the local one, nor swaps its annotation.
            // The remote's target is recorded as `<remote>/<name>` above.
            Some(existing) if existing.annotation.is_some() => {
                report.release_tags_kept.push((name, existing.target, tag.target));
            }
            Some(existing) => {
                if tx.repo().is_ancestor(&existing.target, &tag.target)? {
                    tx.view.tags.insert(
                        name.clone(),
                        Tag {
                            target: tag.target,
                            cloak: existing.cloak,
                            annotation: tag.annotation,
                        },
                    );
                    report.tags_updated.push((name, tag.target));
                } else if !tx.repo().is_ancestor(&tag.target, &existing.target)? {
                    report.warnings.push(format!(
                        "tag '{name}' has diverged from {remote_name}/{name}; merge with `vl merge {remote_name}/{name}`"
                    ));
                }
            }
        }
    }
    tx.commit()?;
    Ok(report)
}

/// Fetch what the remote's tags reach and the local committed view
/// (`local_refs`) does not, with bulk downloads (module documentation).
fn pull_incremental(
    local: &Arc<ObjectStore>,
    local_refs: &[ObjectId],
    remote: &Repo,
    remote_backend: &Arc<dyn StorageBackend>,
    tags: &[(String, Tag)],
    mut report: SyncReport,
) -> Result<SyncReport> {
    let inv = Inventory::load(remote_backend.clone(), &mut report.warnings)?;
    let local_ids: HashSet<ObjectId> = local.list_objects()?.into_iter().collect();
    let src = PullSource {
        local,
        local_ids: &local_ids,
        remote: remote.store(),
        inv: &inv,
        got: RefCell::default(),
        bases: LruCache::new(64 << 20),
        bytes: RefCell::new(0),
    };
    // Locally, everything the committed view reaches is complete, except
    // possibly redacted extra parents of embargoed merges: ask for those.
    let mut redacted_parents = Vec::new();
    let known = committed_closure(local, local_refs, |p| {
        if !local_ids.contains(p) {
            redacted_parents.push(*p);
        }
        true
    })?;
    // Only snapshot targets are fetched; tags on anything else (missing,
    // a tree, a blob) are skipped with a warning by the caller.
    let mut tips = redacted_parents;
    for (_, t) in tags {
        let raw = match src.fetch(&t.target) {
            Ok(Fetched::New(r) | Fetched::Have(r)) => r,
            Err(VeilError::Missing(_)) => continue,
            Err(e) => return Err(e),
        };
        if let Ok(Object::Snapshot(_)) = Object::decode(&raw) {
            tips.push(t.target);
        }
    }
    // The remote's snapshots that the local view does not reach.
    let mut snaps = Vec::new();
    let mut seen = HashSet::new();
    let mut stack = tips;
    while let Some(id) = stack.pop() {
        if known.contains(&id) || !seen.insert(id) {
            continue;
        }
        let raw = match src.fetch(&id) {
            Ok(Fetched::New(r) | Fetched::Have(r)) => r,
            Err(VeilError::Missing(_)) => continue,
            Err(e) => return Err(e),
        };
        match Object::decode(&raw)? {
            Object::Snapshot(s) => stack.extend(s.parents.iter().copied()),
            other => {
                return Err(VeilError::Corrupt(
                    id.hex(),
                    format!("expected a snapshot, found a {}", other.kind_name()),
                ))
            }
        }
        snaps.push(id);
    }
    let mut xfer = Transfer {
        src: &src,
        sink: Sink::Pack(Box::new(PackSink::new(local, local.pack_dir(), Some(&**local), 256))),
        src_keys: remote.keys(),
        public: false,
        known: Box::new(|_| false),
        seen: HashSet::new(),
        heights: HashMap::new(),
        report,
    };
    for id in snaps {
        xfer.copy(id, "")?;
    }
    // The remote holds objects we lack that the walk did not need: maybe
    // content our committed view references but lacks (a clone of a public
    // mirror pulling from a team remote, embargoed content released since).
    let remaining: HashSet<ObjectId> = inv
        .ids()
        .filter(|id| !local_ids.contains(id) && !xfer.seen.contains(id))
        .copied()
        .collect();
    if !remaining.is_empty() {
        let mut roots = Vec::new();
        for s in &known {
            if let Ok(s) = local.snapshot(s) {
                roots.push(s.tree);
            }
        }
        let mut gaps = Vec::new();
        local_trees(local, roots, |_, t| {
            for e in &t.entries {
                for c in std::iter::once(e.id).chain(e.fallback) {
                    if remaining.contains(&c) {
                        gaps.push((c, e.name.clone()));
                    }
                }
            }
            true
        })?;
        for (id, name) in gaps {
            xfer.copy(id, &name)?;
        }
    }
    let Transfer { sink, mut report, .. } = xfer;
    sink.finish(&mut report)?;
    report.bytes_transferred += *src.bytes.borrow();
    local.reload_packs()?;
    Ok(report)
}
