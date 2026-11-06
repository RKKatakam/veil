//! Content-addressable store with transparent decryption of sealed nodes.
//!
//! Objects live either *loose* (`<root>/ab/cdef…`, the canonical encoding
//! as-is) or in *packs* (`<root>/pack/pack-<sum>.{pack,idx}`, see
//! [`crate::pack`]). Lookups check loose objects first, then packs. Ids are
//! always the BLAKE3 of the canonical, uncompressed encoding, and
//! [`ObjectStore::get_raw`] / [`ObjectStore::put_raw`] always speak that
//! encoding, wherever the object is stored.
//!
//! Decoded trees and snapshots, and decompressed delta bases, are kept in
//! weight-bounded LRU caches (see [`CacheLimits`]).
//!
//! **Formats.** Reads accept every object encoding this build knows. Writes
//! use the encoding of the repository's format ([`ObjectStore::set_format`]):
//! a format-1 repository writes JSON trees and refuses binary ones, also
//! from [`ObjectStore::put_raw`], so it stays readable by every vl that can
//! read format 1. See `docs/FORMAT.md`.
//!
//! **Cooperation with `gc`.** Objects that the last `vl gc` found
//! unreachable are listed in `<root>/gc/pending`. If this process touches
//! such an object (`has`, `get_raw`, `put`, `put_raw`), it *freshens* it:
//! it writes a keep marker `<root>/gc/keep/<id>` and makes sure a loose copy
//! exists. A concurrent or later `gc` then keeps the object. See
//! [`crate::gc`] for the full protocol.

use std::{
    collections::HashSet,
    fmt,
    sync::{
        atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
        Arc, Mutex, RwLock,
    },
    time::Duration,
};

use crate::{
    cache::{CacheStats, LruCache},
    crypto::Envelope,
    error::{Result, VeilError},
    id::ObjectId,
    keychain::Keychain,
    object::{Conflict, EntryKind, Object, Snapshot, Text, Tree, TreeEncoding, TreeEntry, Visibility},
    pack::{name_from_index_file, Pack},
    vfs::{NodeKind, StorageBackend},
    vpath::VPath,
};

/// Bounds for the in-memory caches of one [`ObjectStore`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CacheLimits {
    /// Total tree entries held across cached trees (each tree weighs
    /// `entries + 1`).
    pub tree_entries: usize,
    /// Number of cached snapshots.
    pub snapshots: usize,
    /// Bytes of decompressed delta bases.
    pub delta_base_bytes: usize,
}

impl Default for CacheLimits {
    fn default() -> Self {
        CacheLimits {
            tree_entries: 200_000,
            snapshots: 20_000,
            delta_base_bytes: 64 << 20,
        }
    }
}

/// Where and how objects are stored right now.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StoreStats {
    pub loose_objects: usize,
    pub loose_bytes: u64,
    pub packs: usize,
    pub packed_objects: usize,
    pub pack_bytes: u64,
    pub trees: CacheStats,
    pub snapshots: CacheStats,
    pub delta_bases: CacheStats,
}

#[derive(Default)]
struct PackSet {
    loaded: bool,
    packs: Vec<Arc<Pack>>,
    /// Packs whose index or data could not be opened: name → reason.
    broken: Vec<(String, String)>,
}

/// How long a loaded copy of the gc pending list is trusted before re-reading.
const PENDING_TTL: Duration = Duration::from_secs(30);

struct GcHints {
    enabled: AtomicBool,
    /// (when loaded, on [`crate::clock::monotonic`]; the set)
    pending: RwLock<Option<(Duration, Arc<HashSet<ObjectId>>)>>,
    freshened: RwLock<HashSet<ObjectId>>,
}

pub struct ObjectStore {
    backend: Arc<dyn StorageBackend>,
    root: VPath,
    pub keys: Arc<Keychain>,
    trees: LruCache<Arc<Tree>>,
    snapshots: LruCache<Arc<Snapshot>>,
    bases: LruCache<Arc<Vec<u8>>>,
    packs: RwLock<PackSet>,
    gc: GcHints,
    /// Open [`ObjectStore::begin_unsynced`] scopes (see there).
    unsynced: AtomicUsize,
    /// Loose objects written unsynced since the last successful barrier.
    not_durable: Mutex<Vec<ObjectId>>,
    /// A failed barrier left objects behind that could not be removed (see
    /// [`ObjectStore::sync_barrier`]).
    needs_recovery: AtomicBool,
    /// Repository format: decides the tree encoding written and accepted.
    format: AtomicU32,
    /// The transaction staging directory new loose objects go to (format 6,
    /// see [`ObjectStore::begin_tx_staging`]).
    tx: Mutex<Option<TxStaging>>,
    /// This device's diff and merge drivers (`.veilattributes` only names
    /// them; see [`crate::attributes::DeviceDrivers`]).
    drivers: RwLock<Option<Arc<dyn crate::attributes::DeviceDrivers>>>,
}

impl fmt::Debug for ObjectStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ObjectStore({} at {})", self.backend.kind(), self.root)
    }
}

enum Loose {
    Good(Vec<u8>),
    Absent,
    Corrupt,
}

fn loose_mismatch(id: &ObjectId) -> VeilError {
    VeilError::Corrupt(id.hex(), "content does not match its hash".into())
}

fn is_hex(s: &str) -> bool {
    s.bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

/// The most a [`Staged`] scope holds in memory before it gives up
/// ([`Staged::overflowed`]): a snapshot with more new content than this is
/// built under the repository lock, as before.
pub const STAGING_BUDGET: usize = 32 << 20;

/// A transaction's staging directory (format 6): `<root>/incoming/tx-<owner>`.
#[derive(Debug)]
struct TxStaging {
    dir: VPath,
    /// The owner tag (`lock::Owner`), also naming a pull's spool.
    owner: String,
    /// Objects this transaction staged: written there, buffered, or packed.
    staged: HashSet<ObjectId>,
    /// Small new objects not written anywhere yet (see [`TX_BUFFER`]).
    buffered: std::collections::HashMap<ObjectId, Vec<u8>>,
    buffered_bytes: usize,
    /// Staged objects already in a published pack (the buffer spilled).
    packed: HashSet<ObjectId>,
    /// Those that may name other objects (neither blobs nor sealed): the
    /// commit checks what they name is present (BUG-811).
    naming: HashSet<ObjectId>,
    /// Fan-out directories (`ab`) holding an object this transaction found
    /// already published instead of writing it: synced at publication.
    present: std::collections::BTreeSet<String>,
    /// The backend's failed barriers when the staging began: one failing
    /// since (another transaction's, on a shared backend value) may have
    /// covered these writes, which are then void.
    failures_at: u64,
}

/// A transaction keeps its new file contents (blobs, sealed or not) of at
/// most [`TX_BUFFER_OBJECT`] bytes in memory, up to this many bytes in all; past that they are
/// written as a pack (not in memory, see
/// `ObjectStore::packs_new_objects`); its trees and snapshots are staged
/// loose as before. At publication, [`TX_PACK_MIN`] contents or more
/// become one pack (compressed on several threads), fewer are written as
/// loose objects: an import of 10,000 files makes one pack and its index
/// durable instead of 10,000 files and their renames (a fsync and a
/// rename each).
const TX_BUFFER: usize = 32 << 20;
const TX_BUFFER_OBJECT: usize = 1 << 20;
const TX_PACK_MIN: usize = 256;

/// The prefix of transaction staging directories under `<root>/incoming/`.
pub const TX_STAGING_PREFIX: &str = "tx-";
/// The prefix of pull spools under `<root>/incoming/`.
pub const PULL_SPOOL_PREFIX: &str = "pull-";

/// New objects of one thread's [`ObjectStore::begin_staging`] scope.
struct Staging {
    /// The store they are for (`ObjectStore` address).
    store: usize,
    objects: std::collections::HashMap<ObjectId, Vec<u8>>,
    bytes: usize,
    overflowed: bool,
}

thread_local! {
    static STAGING: std::cell::RefCell<Option<Staging>> = const { std::cell::RefCell::new(None) };
}

/// An open [`ObjectStore::begin_staging`] scope: [`StagingScope::finish`]
/// ends it; dropping it (a panic in the build) ends it too, discarding
/// what was staged, so the thread never stays in staging.
pub(crate) struct StagingScope<'a> {
    store: &'a ObjectStore,
    done: bool,
}

impl StagingScope<'_> {
    /// End the scope; what it staged.
    pub(crate) fn finish(mut self) -> Staged {
        self.done = true;
        let me = self.store as *const ObjectStore as usize;
        STAGING.with(|s| match s.borrow_mut().take() {
            Some(st) if st.store == me => Staged {
                objects: st.objects.into_iter().collect(),
                overflowed: st.overflowed,
            },
            _ => Staged {
                objects: Vec::new(),
                overflowed: true,
            },
        })
    }
}

impl Drop for StagingScope<'_> {
    fn drop(&mut self) {
        if !self.done {
            STAGING.with(|s| s.borrow_mut().take());
        }
    }
}

/// What a `ObjectStore::begin_staging` scope staged: objects written
/// nowhere yet. `ObjectStore::publish_staged` writes them (under the
/// repository lock, in a transaction); dropping it discards them.
#[derive(Debug, Default)]
pub struct Staged {
    objects: Vec<(ObjectId, Vec<u8>)>,
    overflowed: bool,
}

impl Staged {
    /// More than [`STAGING_BUDGET`] was put: the objects were not all
    /// kept, so what was built must be built again.
    pub fn overflowed(&self) -> bool {
        self.overflowed
    }

    pub fn len(&self) -> usize {
        self.objects.len()
    }

    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }
}

impl ObjectStore {
    pub fn new(backend: Arc<dyn StorageBackend>, root: VPath, keys: Arc<Keychain>) -> Self {
        let limits = CacheLimits::default();
        ObjectStore {
            backend,
            root,
            keys,
            trees: LruCache::new(limits.tree_entries),
            snapshots: LruCache::new(limits.snapshots),
            bases: LruCache::new(limits.delta_base_bytes),
            packs: RwLock::new(PackSet::default()),
            gc: GcHints {
                enabled: AtomicBool::new(true),
                pending: RwLock::new(None),
                freshened: RwLock::new(HashSet::new()),
            },
            unsynced: AtomicUsize::new(0),
            not_durable: Mutex::new(Vec::new()),
            needs_recovery: AtomicBool::new(false),
            format: AtomicU32::new(crate::repo::REPO_FORMAT),
            tx: Mutex::new(None),
            drivers: RwLock::new(None),
        }
    }

    /// Register this device's diff and merge drivers (the CLI does, from
    /// its own configuration; never from anything in a tree).
    pub fn set_device_drivers(&self, d: Arc<dyn crate::attributes::DeviceDrivers>) {
        *self.drivers.write().expect("drivers lock") = Some(d);
    }

    /// This device's drivers, if any were registered.
    pub fn device_drivers(&self) -> Option<Arc<dyn crate::attributes::DeviceDrivers>> {
        self.drivers.read().expect("drivers lock").clone()
    }

    /// The device-local attributes file of the repository this store
    /// belongs to ([`crate::attributes::LOCAL_ATTRIBUTES`]), if there is one
    /// (a regular file, never followed through a link).
    pub fn local_attributes(&self) -> Option<Vec<u8>> {
        let path = VPath::new(crate::attributes::LOCAL_ATTRIBUTES).ok()?;
        match self.backend.metadata(&path) {
            Ok(Some(m)) if m.kind == crate::vfs::NodeKind::File && m.len <= crate::attributes::MAX_FILE as u64 => self.backend.read(&path).ok(),
            // Too large: parsed as such (ignored, with a warning).
            Ok(Some(m)) if m.kind == crate::vfs::NodeKind::File => Some(vec![b'#'; crate::attributes::MAX_FILE + 1]),
            _ => None,
        }
    }

    /// Set the repository format this store writes (default: the newest,
    /// [`crate::repo::REPO_FORMAT`]). `Repo::open` sets it from `repo.json`.
    pub fn set_format(&self, repo_format: u32) {
        self.format.store(repo_format, Ordering::SeqCst);
        // Key wrapping and ring formats follow the repository format too.
        self.keys.set_format(repo_format);
    }

    /// The repository format this store writes.
    pub fn format(&self) -> u32 {
        self.format.load(Ordering::Relaxed)
    }

    /// The tree encoding this store writes.
    pub fn tree_encoding(&self) -> TreeEncoding {
        TreeEncoding::for_repo_format(self.format())
    }

    /// The canonical encoding `obj` has in this repository (its id is the
    /// BLAKE3 of these bytes).
    pub fn encode(&self, obj: &Object) -> Vec<u8> {
        obj.encode_with(self.tree_encoding())
    }

    /// Refuse objects this repository's format may not hold (a format-1
    /// repository must stay readable by every vl that reads format 1): binary
    /// trees below format 2, AES-SIV sealed objects below format 3.
    /// The `Unsupported` error for a format-5 object in an older repository.
    fn format_5_refusal(&self) -> VeilError {
        let need = crate::object::GIT_PARITY_REPO_FORMAT;
        VeilError::Unsupported(format!(
            "this repository is at format {} and cannot store format-{need} symlinks or annotated tags; \
             upgrade it with `vl upgrade` (a remote: `vl upgrade --remote <name>`) once everyone who uses it runs vl {} or later",
            self.format(),
            crate::repo::min_vl_for_format(need)
        ))
    }

    pub(crate) fn check_storable(&self, raw: &[u8]) -> Result<()> {
        let need = Object::min_repo_format(raw);
        let have = self.format();
        if need > have && need >= crate::object::GIT_PARITY_REPO_FORMAT {
            return Err(self.format_5_refusal());
        }
        if need > have {
            let what = if need >= crate::object::CONFLICT_REPO_FORMAT {
                "conflicts (conflict objects, trees with conflict entries)"
            } else if Object::tree_encoding(raw).is_some() {
                "(binary) trees"
            } else {
                "(AES-SIV) sealed objects"
            };
            return Err(VeilError::Unsupported(format!(
                "this repository is at format {have} and cannot store format-{need} {what}; \
                 upgrade it with `vl upgrade` (a remote: `vl upgrade --remote <name>`) once everyone who uses it runs vl {} or later",
                crate::repo::min_vl_for_format(need)
            )));
        }
        Ok(())
    }

    /// Deterministic envelope of this repository's format: AES-SIV from
    /// format 3, the legacy XChaCha20-Poly1305 construction before (which
    /// older vl must keep reading).
    fn seal_deterministic(&self, key: &crate::crypto::Key, label: &str, plaintext: &[u8]) -> Result<Envelope> {
        if self.format() >= crate::object::AES_SIV_REPO_FORMAT {
            Envelope::seal_deterministic(key, label, plaintext)
        } else {
            Envelope::seal_deterministic_legacy(key, label, plaintext)
        }
    }

    /// From now until the matching [`ObjectStore::end_unsynced`], new loose
    /// objects are written with [`StorageBackend::write_unsynced`]. The
    /// caller must call [`ObjectStore::sync_barrier`] before writing
    /// anything that references them, and before releasing the repository
    /// lock (transactions do both; see `lock.rs` for crash recovery).
    pub(crate) fn begin_unsynced(&self) {
        self.unsynced.fetch_add(1, Ordering::SeqCst);
    }

    pub(crate) fn end_unsynced(&self) {
        self.unsynced.fetch_sub(1, Ordering::SeqCst);
    }

    /// Make every object written so far durable.
    ///
    /// If the barrier fails, the objects it covered are *void*: they still
    /// read back intact (from the page cache), but may never reach the
    /// disk, and no later barrier changes that. On Linux a failed `fsync`
    /// marks the pages clean, so a retried one succeeds without writing
    /// them ("fsyncgate"). Reusing such an object in a later, successful
    /// transaction would lose acknowledged data at the next power loss
    /// (BUG-044). Nothing references them yet (an operation is only written
    /// after its barrier), so they are removed, and a retry writes fresh
    /// copies. If they cannot be removed, `ObjectStore::take_needs_recovery`
    /// reports it: the transaction then leaves the repository lock behind
    /// for crash recovery, which rewrites them as new files.
    pub fn sync_barrier(&self) -> Result<()> {
        let covered = std::mem::take(&mut *self.not_durable_list());
        match self.backend.sync_barrier() {
            Ok(()) => Ok(()),
            Err(e) => {
                // Also whatever was written while the barrier ran: it may
                // have been in the failed batch.
                let mut void = covered;
                void.extend(std::mem::take(&mut *self.not_durable_list()));
                self.discard(&void);
                Err(e)
            }
        }
    }

    fn not_durable_list(&self) -> std::sync::MutexGuard<'_, Vec<ObjectId>> {
        self.not_durable.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Remove the loose objects of a failed barrier, durably.
    fn discard(&self, void: &[ObjectId]) {
        if void.is_empty() {
            return;
        }
        let mut ok = true;
        for id in void {
            ok &= self.backend.remove_file(&self.loose_path(id)).is_ok();
        }
        // The removals must survive a power loss too, or a torn copy could
        // reappear. (The backend still has the failed files queued; they are
        // gone now, so this only syncs their directories.)
        ok = ok && self.backend.sync_barrier().is_ok();
        if !ok {
            self.needs_recovery.store(true, Ordering::SeqCst);
        }
    }

    /// Whether a failed barrier left objects that could not be removed
    /// (and clears the flag). The repository lock must then not be released
    /// normally but left for recovery ([`crate::lock::RepoLock::abandon`]).
    pub(crate) fn take_needs_recovery(&self) -> bool {
        self.needs_recovery.swap(false, Ordering::SeqCst)
    }

    fn tx_list(&self) -> std::sync::MutexGuard<'_, Option<TxStaging>> {
        self.tx.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// From now until [`ObjectStore::publish_tx_staging`] or
    /// [`ObjectStore::abort_tx_staging`], new loose objects are written
    /// (unsynced) to `<root>/incoming/tx-<owner>/ab/cdef…` and read from
    /// there first; nobody else ever looks in it (format 6). A staged
    /// object is published only after a successful barrier, so another
    /// process never adopts one that may not reach the disk (BUG-044's
    /// class across processes).
    pub(crate) fn begin_tx_staging(&self, owner: &str) -> Result<()> {
        let mut t = self.tx_list();
        if t.is_some() {
            return Err(VeilError::repo("a transaction is already staging objects in this store"));
        }
        *t = Some(TxStaging {
            dir: self.root.join("incoming").join(&format!("{TX_STAGING_PREFIX}{owner}")),
            owner: owner.to_string(),
            staged: HashSet::new(),
            buffered: Default::default(),
            buffered_bytes: 0,
            packed: HashSet::new(),
            naming: HashSet::new(),
            present: Default::default(),
            failures_at: self.backend.barrier_failures(),
        });
        Ok(())
    }

    /// The owner tag of the transaction staging in this store, if any.
    pub(crate) fn tx_owner(&self) -> Option<String> {
        self.tx_list().as_ref().map(|t| t.owner.clone())
    }

    /// Objects staged so far by the current transaction.
    pub(crate) fn tx_staged(&self) -> Vec<ObjectId> {
        let mut v: Vec<ObjectId> = self.tx_list().as_ref().map(|t| t.staged.iter().copied().collect()).unwrap_or_default();
        v.sort();
        v
    }

    /// The staged objects that may name others (trees, snapshots,
    /// conflicts, annotated tags; not blobs, not sealed objects).
    pub(crate) fn tx_staged_naming(&self) -> Vec<ObjectId> {
        let mut v: Vec<ObjectId> = self.tx_list().as_ref().map(|t| t.naming.iter().copied().collect()).unwrap_or_default();
        v.sort();
        v
    }

    /// The bytes of `id` if the current transaction holds it in memory.
    fn tx_buffered(&self, id: &ObjectId) -> Option<Vec<u8>> {
        self.tx_list().as_ref()?.buffered.get(id).cloned()
    }

    fn staged_path(&self, id: &ObjectId) -> Option<VPath> {
        let t = self.tx_list();
        let t = t.as_ref()?;
        (t.staged.contains(id) && !t.buffered.contains_key(id) && !t.packed.contains(id)).then(|| {
            let h = id.hex();
            t.dir.join(&h[..2]).join(&h[2..])
        })
    }

    /// Publish the transaction's staged objects. Those still in memory
    /// become one pack, made durable before its index (enough of them,
    /// see [`TX_PACK_MIN`]), or loose objects staged like the rest. One
    /// barrier makes the staged ones durable where they are (if it fails, the staging directory is
    /// removed and nothing is published); each is renamed over its final
    /// name (content-addressed, so replacing a concurrent identical copy is
    /// harmless); a second barrier makes the renames durable, and the
    /// directories of objects this transaction found already published
    /// (another process's rename may not be durable yet). Ends the staging.
    pub(crate) fn publish_tx_staging(&self) -> Result<()> {
        let Some(mut t) = self.tx_list().take() else { return Ok(()) };
        // What is still buffered: one pack (durable, then its index,
        // durably: readers find packs by their index), or, if few, loose
        // objects staged as any other.
        let buffered: Vec<(ObjectId, Vec<u8>)> = std::mem::take(&mut t.buffered).into_iter().collect();
        let written = match buffered.len() >= TX_PACK_MIN {
            true => {
                t.packed.extend(buffered.iter().map(|(id, _)| *id));
                self.write_pack(buffered)
            }
            false => buffered.into_iter().try_for_each(|(id, raw)| {
                let h = id.hex();
                self.backend.write_unsynced(&t.dir.join(&h[..2]).join(&h[2..]), &raw)
            }),
        };
        if let Err(e) = written {
            self.drop_staging_dir(&t.dir);
            return Err(e);
        }
        if let Err(e) = self.backend.sync_barrier() {
            self.drop_staging_dir(&t.dir);
            return Err(e);
        }
        if self.backend.barrier_failures() != t.failures_at {
            // A barrier failed meanwhile, possibly over our writes.
            self.drop_staging_dir(&t.dir);
            return Err(VeilError::Io {
                path: t.dir.to_string(),
                source: std::io::Error::other("a write barrier failed while this command ran; its writes may not be on disk: run it again"),
            });
        }
        let res = (|| -> Result<()> {
            let mut staged: Vec<&ObjectId> = t.staged.iter().filter(|id| !t.packed.contains(id)).collect();
            staged.sort();
            for id in staged {
                let h = id.hex();
                self.backend.rename_unsynced(&t.dir.join(&h[..2]).join(&h[2..]), &self.loose_path(id))?;
            }
            for d in &t.present {
                self.backend.sync_dir_later(&self.root.join(d))?;
            }
            self.backend.sync_barrier()
        })();
        self.drop_staging_dir(&t.dir);
        res
    }

    /// New objects of a transaction may become a pack ([`TX_BUFFER`]),
    /// except in memory, where a loose object costs nothing (on a disk, a
    /// fsync and a rename) and compressing a pack would.
    fn packs_new_objects(&self) -> bool {
        self.backend.kind() != "memory"
    }

    /// Write `objects` (canonical encodings) as one pack in the pack
    /// directory: compressed on several threads, then the pack made
    /// durable and only then its index (as a pull writes its packs).
    fn write_pack(&self, mut objects: Vec<(ObjectId, Vec<u8>)>) -> Result<()> {
        // A few MiB at a time: compressed, added to the streamed pack and
        // freed, so a pack costs little more memory than what it holds.
        const CHUNK: usize = 4 << 20;
        objects.sort_by_key(|o| o.0);
        let threads = match cfg!(feature = "os") {
            true => std::thread::available_parallelism().map_or(1, |n| n.get()).min(8),
            false => 1,
        };
        let dir = self.pack_dir();
        let mut w = crate::pack::PackWriter::new(self.backend.create_stream(&dir, true)?, crate::pack::DEFAULT_LEVEL)?;
        let mut objects = std::collections::VecDeque::from(objects);
        while !objects.is_empty() {
            let mut bytes = 0;
            let n = objects.iter().take_while(|(_, raw)| {
                bytes += raw.len();
                bytes <= CHUNK
            });
            let n = n.count().max(1);
            let chunk: Vec<(ObjectId, Vec<u8>)> = objects.drain(..n).collect();
            let entries = crate::pack::encode_entries(&chunk, crate::pack::DEFAULT_LEVEL, threads)?;
            for ((id, _), e) in chunk.iter().zip(&entries) {
                w.add_entry(*id, e)?;
            }
        }
        w.finish(&*self.backend, &dir)?;
        self.reload_packs()?;
        Ok(())
    }

    fn drop_staging_dir(&self, dir: &VPath) {
        let _ = self.backend.remove_dir_all(dir);
    }

    /// Remove the staging directories and pull spools under
    /// `<root>/incoming/` whose owner is provably gone
    /// ([`crate::lock::owner_gone`]): nothing in them was ever published,
    /// so no recovery is needed. Others are kept. Returns how many were
    /// removed.
    pub fn sweep_staging(&self, ctx: &crate::lock::LockContext) -> Result<usize> {
        let mut n = 0;
        for (name, tag) in self.staging_dirs()? {
            if crate::lock::owner_gone(&tag, ctx) {
                self.backend.remove_dir_all(&self.root.join("incoming").join(&name))?;
                n += 1;
            }
        }
        Ok(n)
    }

    /// Every transaction staging directory and pull spool under
    /// `<root>/incoming/`: `(directory name, owner tag)`.
    pub fn staging_dirs(&self) -> Result<Vec<(String, String)>> {
        let entries = match self.backend.list_dir(&self.root.join("incoming")) {
            Ok(e) => e,
            Err(e) if e.is_not_found() => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        Ok(entries
            .into_iter()
            .filter(|e| e.kind == NodeKind::Dir)
            .filter_map(|e| {
                let tag = e.name.strip_prefix(TX_STAGING_PREFIX).or_else(|| e.name.strip_prefix(PULL_SPOOL_PREFIX))?.to_string();
                Some((e.name, tag))
            })
            .collect())
    }

    /// From now until the scope returned ends, objects this thread
    /// puts into this store are kept in memory instead of written, and
    /// reads see them (BUG-801: a snapshot is built outside the repository
    /// lock, and published under it only if nothing moved meanwhile) and
    /// [`StagingScope::finish`] says what was staged. An
    /// object already present is not adopted either: another process's
    /// transaction may have written it and not made it durable yet (the
    /// stream-O threat 5), so only [`ObjectStore::publish_staged`], under
    /// the lock, decides. Beyond [`STAGING_BUDGET`] bytes, puts fail
    /// ([`Staged::overflowed`]).
    pub(crate) fn begin_staging(&self) -> StagingScope<'_> {
        let me = self as *const ObjectStore as usize;
        STAGING.with(|s| {
            *s.borrow_mut() = Some(Staging {
                store: me,
                objects: Default::default(),
                bytes: 0,
                overflowed: false,
            })
        });
        StagingScope { store: self, done: false }
    }

    /// Write what a staging scope kept, as any put would (inside a
    /// transaction: unsynced, made durable by its barrier).
    pub(crate) fn publish_staged(&self, staged: Staged) -> Result<()> {
        for (id, raw) in staged.objects {
            if ObjectId::hash(&raw) != id {
                return Err(VeilError::Corrupt(id.hex(), "hash mismatch".into()));
            }
            self.write_if_absent(&id, &raw)?;
        }
        Ok(())
    }

    /// Stage `raw` if this thread has a staging scope for this store:
    /// `Some(result)` then, `None` otherwise.
    fn stage(&self, id: &ObjectId, raw: &[u8]) -> Option<Result<bool>> {
        let me = self as *const ObjectStore as usize;
        STAGING.with(|s| {
            let mut s = s.borrow_mut();
            let st = s.as_mut().filter(|st| st.store == me)?;
            if st.objects.contains_key(id) {
                return Some(Ok(false));
            }
            if st.overflowed || st.bytes + raw.len() > STAGING_BUDGET {
                st.overflowed = true;
                return Some(Err(VeilError::repo("too much new content to stage; recording under the lock")));
            }
            st.bytes += raw.len();
            st.objects.insert(*id, raw.to_vec());
            Some(Ok(true))
        })
    }

    /// The bytes of `id` if this thread staged it.
    fn staged(&self, id: &ObjectId) -> Option<Vec<u8>> {
        let me = self as *const ObjectStore as usize;
        STAGING.with(|s| s.borrow().as_ref().filter(|st| st.store == me).and_then(|st| st.objects.get(id).cloned()))
    }

    fn write_loose(&self, id: &ObjectId, raw: &[u8]) -> Result<()> {
        if let Some(r) = self.stage(id, raw) {
            return r.map(|_| ());
        }
        let staging = self.tx_list().as_ref().map(|t| t.dir.clone());
        if let Some(dir) = staging {
            // File contents only (blobs, sealed or not): trees and
            // snapshots stay loose until gc, as before, so status, log and
            // other history reads find them uncompressed (and the scale
            // benchmark still counts snapshot reads by their opens).
            let content = Object::is_blob_raw(raw) || Object::sealed_scope(raw).is_some();
            if content && raw.len() <= TX_BUFFER_OBJECT && self.packs_new_objects() {
                let spill = {
                    let mut t = self.tx_list();
                    let Some(t) = t.as_mut() else { return Err(VeilError::repo("the transaction ended while it wrote")) };
                    if t.staged.insert(*id) {
                        t.buffered.insert(*id, raw.to_vec());
                        t.buffered_bytes += raw.len();
                    }
                    match t.buffered_bytes > TX_BUFFER {
                        true => {
                            t.buffered_bytes = 0;
                            let b: Vec<(ObjectId, Vec<u8>)> = std::mem::take(&mut t.buffered).into_iter().collect();
                            t.packed.extend(b.iter().map(|(id, _)| *id));
                            b
                        }
                        false => Vec::new(),
                    }
                };
                if !spill.is_empty() {
                    self.write_pack(spill)?;
                }
                return Ok(());
            }
            let h = id.hex();
            self.backend.write_unsynced(&dir.join(&h[..2]).join(&h[2..]), raw)?;
            if let Some(t) = self.tx_list().as_mut() {
                t.staged.insert(*id);
                if !Object::is_blob_raw(raw) && Object::sealed_scope(raw).is_none() {
                    t.naming.insert(*id);
                }
            }
            return Ok(());
        }
        if self.unsynced.load(Ordering::SeqCst) > 0 {
            self.backend.write_unsynced(&self.loose_path(id), raw)?;
            self.not_durable_list().push(*id);
            Ok(())
        } else {
            self.backend.write(&self.loose_path(id), raw)
        }
    }

    pub fn set_cache_limits(&self, limits: CacheLimits) {
        self.trees.set_capacity(limits.tree_entries);
        self.snapshots.set_capacity(limits.snapshots);
        self.bases.set_capacity(limits.delta_base_bytes);
    }

    pub fn backend(&self) -> &Arc<dyn StorageBackend> {
        &self.backend
    }

    /// The store's directory on its backend (`.veil/objects`).
    pub fn root(&self) -> &VPath {
        &self.root
    }

    pub fn pack_dir(&self) -> VPath {
        self.root.join("pack")
    }

    pub(crate) fn gc_dir(&self) -> VPath {
        self.root.join("gc")
    }

    pub(crate) fn keep_marker(&self, id: &ObjectId) -> VPath {
        self.gc_dir().join("keep").join(&id.hex())
    }

    pub(crate) fn loose_path(&self, id: &ObjectId) -> VPath {
        let h = id.hex();
        self.root.join(&h[..2]).join(&h[2..])
    }

    // ---- packs -----------------------------------------------------------

    fn ensure_packs(&self) -> Result<()> {
        if !self.packs.read().unwrap().loaded {
            self.reload_packs()?;
        }
        Ok(())
    }

    /// Re-scan the pack directory: open new packs, forget removed ones.
    /// Returns true if the set of packs changed.
    pub fn reload_packs(&self) -> Result<bool> {
        let dir = self.pack_dir();
        let names: Vec<String> = match self.backend.list_dir(&dir) {
            Ok(entries) => entries
                .into_iter()
                .filter(|e| e.kind == NodeKind::File)
                .filter_map(|e| name_from_index_file(&e.name).map(str::to_string))
                .collect(),
            Err(e) if e.is_not_found() => Vec::new(),
            Err(e) => return Err(e),
        };
        let mut set = self.packs.write().unwrap();
        let unchanged = set.loaded
            && names.len() == set.packs.len() + set.broken.len()
            && names
                .iter()
                .all(|n| set.packs.iter().any(|p| p.name() == n) || set.broken.iter().any(|(b, _)| b == n));
        if unchanged {
            return Ok(false);
        }
        let mut packs = Vec::new();
        let mut broken = Vec::new();
        for name in names {
            if let Some(p) = set.packs.iter().find(|p| p.name() == name) {
                packs.push(p.clone());
                continue;
            }
            match Pack::open(&*self.backend, &dir, &name) {
                Ok(p) => packs.push(Arc::new(p)),
                // Removed by a concurrent gc between listing and opening.
                Err(e) if e.is_not_found() => {}
                // Its data file went after its index was read: removed
                // meanwhile too (index first), if the index is gone now.
                Err(_) if !self.backend.exists(&crate::pack::index_file(&dir, &name)).unwrap_or(true) => {}
                Err(e) => broken.push((name, e.to_string())),
            }
        }
        *set = PackSet {
            loaded: true,
            packs,
            broken,
        };
        Ok(true)
    }

    /// Re-scan the pack directory if this store has listed it already (a
    /// list that has not been loaded yet will be fresh when it is).
    pub(crate) fn refresh_packs(&self) -> Result<()> {
        if self.packs.read().unwrap().loaded {
            self.reload_packs()?;
        }
        Ok(())
    }

    /// Currently known packs (loading them if needed).
    pub fn packs(&self) -> Result<Vec<Arc<Pack>>> {
        self.ensure_packs()?;
        Ok(self.packs.read().unwrap().packs.clone())
    }

    /// Packs that could not be opened, with the reason.
    pub fn broken_packs(&self) -> Result<Vec<(String, String)>> {
        self.ensure_packs()?;
        Ok(self.packs.read().unwrap().broken.clone())
    }

    fn in_loaded_packs(&self, id: &ObjectId) -> bool {
        self.packs.read().unwrap().packs.iter().any(|p| p.contains(id))
    }

    /// Look `id` up in the packs. A pack that vanished (a concurrent gc
    /// replaced it) triggers one rescan.
    fn read_packed(&self, id: &ObjectId) -> Result<Option<Vec<u8>>> {
        self.ensure_packs()?;
        let mut corrupt = None;
        for attempt in 0..2 {
            let packs = self.packs.read().unwrap().packs.clone();
            for p in packs.iter().filter(|p| p.contains(id)) {
                match p.get(&*self.backend, id, &self.bases) {
                    Ok(Some(raw)) => return Ok(Some(raw)),
                    Ok(None) => {}
                    Err(e) if e.is_not_found() => {}
                    Err(e) => corrupt = Some(e),
                }
            }
            if attempt == 0 && !self.reload_packs()? {
                break;
            }
        }
        if let Some(e) = corrupt {
            return Err(e);
        }
        if let Some((name, why)) = self.packs.read().unwrap().broken.first() {
            return Err(VeilError::Corrupt(
                id.hex(),
                format!("not found, and pack {} is unreadable: {why}", &name[..12]),
            ));
        }
        Ok(None)
    }

    // ---- raw access ------------------------------------------------------

    fn loose_exists(&self, id: &ObjectId) -> bool {
        if self.staged_path(id).is_some() || self.tx_list().as_ref().is_some_and(|t| t.buffered.contains_key(id)) {
            return true;
        }
        self.backend.exists(&self.loose_path(id)).unwrap_or(false)
    }

    pub fn has(&self, id: &ObjectId) -> bool {
        if self.staged(id).is_some() {
            return true;
        }
        self.freshen(id);
        if self.loose_exists(id) {
            return true;
        }
        if self.ensure_packs().is_err() {
            return false;
        }
        self.in_loaded_packs(id) || (self.reload_packs().unwrap_or(false) && self.in_loaded_packs(id)) || self.loose_exists(id)
    }

    /// [`ObjectStore::has`], freshening `id` for gc even if this process
    /// already did (a long transaction re-marks what it references).
    pub(crate) fn has_fresh(&self, id: &ObjectId) -> bool {
        self.gc.freshened.write().unwrap().remove(id);
        self.has(id)
    }

    /// Like `has`, without rescanning packs: used to skip redundant writes,
    /// where a false negative only costs a duplicate loose copy.
    fn has_cached(&self, id: &ObjectId) -> bool {
        self.staged(id).is_some() || self.loose_exists(id) || (self.ensure_packs().is_ok() && self.in_loaded_packs(id))
    }

    pub fn get_raw(&self, id: &ObjectId) -> Result<Vec<u8>> {
        self.freshen(id);
        self.read_raw(id)
    }

    /// `get_raw` without gc freshening (used by gc itself).
    ///
    /// Every read is verified: the bytes returned always hash to `id`.
    /// Loose objects are re-hashed here; packed objects are re-hashed by
    /// [`Pack::get`]. A loose copy that fails verification is skipped in
    /// favour of a packed copy, if there is a good one. Decoded trees and
    /// snapshots are cached, so the hash is paid once per object and
    /// process for those; blobs are hashed on every read (BLAKE3, typically
    /// well above 1 GiB/s, so small next to the I/O and decryption).
    pub(crate) fn read_raw(&self, id: &ObjectId) -> Result<Vec<u8>> {
        if let Some(b) = self.staged(id).or_else(|| self.tx_buffered(id)) {
            return Ok(b);
        }
        // In a pack already open, on a local disk: no probe for a loose
        // copy first (a clone's checkout reads ten thousand packed files;
        // over a network a loose copy is the cheaper read). Anything but a
        // good copy takes the full path below.
        if !self.backend.is_network() {
            self.ensure_packs()?;
            if self.packs.read().unwrap().packs.iter().any(|p| p.contains(id)) {
                if let Ok(Some(raw)) = self.read_packed(id) {
                    return Ok(raw);
                }
            }
        }
        let loose_corrupt = match self.read_loose_verified(id)? {
            Loose::Good(b) => return Ok(b),
            Loose::Absent => false,
            Loose::Corrupt => true,
        };
        match self.read_packed(id) {
            Ok(Some(raw)) => Ok(raw),
            Ok(None) if loose_corrupt => Err(loose_mismatch(id)),
            // `Missing` means redacted to the engine: only after a loose
            // probe, a reload of the pack list (in `read_packed`) and a
            // second loose probe, so that a reader racing maintenance
            // (a pack replaced, a copy moved) never takes an object for
            // redacted (threat 2 of the maintenance design).
            Ok(None) => match self.read_loose_verified(id)? {
                Loose::Good(b) => Ok(b),
                _ => Err(VeilError::Missing(*id)),
            },
            Err(e) if loose_corrupt && e.is_not_found() => Err(loose_mismatch(id)),
            Err(e) => Err(e),
        }
    }

    fn read_loose_verified(&self, id: &ObjectId) -> Result<Loose> {
        if let Some(p) = self.staged_path(id) {
            if let Some(b) = self.backend.read_opt(&p)? {
                if ObjectId::hash(&b) == *id {
                    return Ok(Loose::Good(b));
                }
            }
        }
        match self.backend.read(&self.loose_path(id)) {
            Ok(b) if ObjectId::hash(&b) == *id => Ok(Loose::Good(b)),
            Ok(_) => Ok(Loose::Corrupt),
            Err(e) if e.is_not_found() => Ok(Loose::Absent),
            Err(e) => Err(e),
        }
    }

    /// Is there a copy of `id` that passes verification? Errors other than
    /// "absent" or "corrupt" (I/O) are passed on.
    fn has_verified(&self, id: &ObjectId) -> Result<bool> {
        match self.read_raw(id) {
            Ok(_) => Ok(true),
            Err(VeilError::Missing(_)) | Err(VeilError::Corrupt(..)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Store `raw` (already verified to hash to `id`) unless a good copy
    /// exists. Returns whether it was written.
    ///
    /// An existing copy is re-read and re-hashed rather than trusted, so a
    /// damaged object is *repaired* by putting it again (for example by
    /// pulling it from a remote): the new loose copy replaces a corrupt
    /// loose one and shadows a corrupt packed one. That costs one read of
    /// the existing copy whenever an object is put twice.
    fn write_if_absent(&self, id: &ObjectId, raw: &[u8]) -> Result<bool> {
        if let Some(r) = self.stage(id, raw) {
            return r;
        }
        if self.is_gc_candidate(id) {
            // A gc may be about to delete the existing copy: mark it, then
            // make sure we have our own good loose copy (in that order).
            self.write_keep_marker(id);
            if matches!(self.read_loose_verified(id)?, Loose::Good(_)) {
                self.note_present(id);
                return Ok(false);
            }
            self.write_loose(id, raw)?;
            return Ok(true);
        }
        if self.has_cached(id) && self.has_verified(id)? {
            self.note_present(id);
            return Ok(false);
        }
        self.write_loose(id, raw)?;
        Ok(true)
    }

    /// A transaction found `id` already present instead of writing it: if
    /// it is a published loose object, its directory is synced at
    /// publication (another process may have just renamed it there).
    fn note_present(&self, id: &ObjectId) {
        let mut t = self.tx_list();
        let Some(t) = t.as_mut() else { return };
        if t.staged.contains(id) {
            return;
        }
        t.present.insert(id.hex()[..2].to_string());
    }

    /// Insert an already-encoded object, verifying its address. Returns
    /// whether a copy was written (false if a verified copy was present).
    pub fn put_raw(&self, id: &ObjectId, raw: &[u8]) -> Result<bool> {
        if ObjectId::hash(raw) != *id {
            return Err(VeilError::Corrupt(id.hex(), "hash mismatch".into()));
        }
        self.check_storable(raw)?;
        self.write_if_absent(id, raw)
    }

    /// Store `obj` in this repository's encoding (see [`ObjectStore::encode`]).
    /// Format-5 objects (trees holding a symlink, conflicts with
    /// such a term, annotated tags) are refused below format 5, as by
    /// [`ObjectStore::put_raw`] (checked on the value, without decoding).
    pub fn put(&self, obj: &Object) -> Result<ObjectId> {
        let format5 = match obj {
            Object::Tree(t) => t.has_special_entries(),
            Object::Conflict(c) => c.has_special_terms(),
            Object::Atag(_) => true,
            _ => false,
        };
        if format5 && self.format() < crate::object::GIT_PARITY_REPO_FORMAT {
            return Err(self.format_5_refusal());
        }
        let raw = self.encode(obj);
        let id = ObjectId::hash(&raw);
        self.write_if_absent(&id, &raw)?;
        Ok(id)
    }

    /// Every loose object id (`<root>/ab/cdef…`).
    pub fn list_loose(&self) -> Result<Vec<ObjectId>> {
        let mut out = Vec::new();
        let dirs = match self.backend.list_dir(&self.root) {
            Ok(d) => d,
            Err(e) if e.is_not_found() => return Ok(out),
            Err(e) => return Err(e),
        };
        for d in dirs {
            if d.kind != NodeKind::Dir || d.name.len() != 2 || !is_hex(&d.name) {
                continue;
            }
            for f in self.backend.list_dir(&self.root.join(&d.name))? {
                if f.kind == NodeKind::File && f.name.len() == 62 && is_hex(&f.name) {
                    out.push(ObjectId::from_hex(&format!("{}{}", d.name, f.name))?);
                }
            }
        }
        Ok(out)
    }

    /// Every object id in the store, loose or packed, sorted.
    pub fn list_objects(&self) -> Result<Vec<ObjectId>> {
        let mut ids = self.list_loose()?;
        for p in self.packs()? {
            ids.extend_from_slice(p.index().ids());
        }
        ids.sort();
        ids.dedup();
        Ok(ids)
    }

    /// Fully verify every pack (checksums and every object's hash). Returns
    /// one `(pack, problem)` per damaged pack; empty means all good.
    pub fn verify_packs(&self) -> Result<Vec<(String, String)>> {
        self.reload_packs()?;
        let mut problems = self.broken_packs()?;
        for p in self.packs()? {
            if let Err(e) = p.verify(&*self.backend) {
                problems.push((p.name().to_string(), e.to_string()));
            }
        }
        Ok(problems)
    }

    pub fn stats(&self) -> Result<StoreStats> {
        let loose = self.list_loose()?;
        let mut loose_bytes = 0;
        for id in &loose {
            loose_bytes += self.backend.metadata(&self.loose_path(id))?.map_or(0, |m| m.len);
        }
        let packs = self.packs()?;
        Ok(StoreStats {
            loose_objects: loose.len(),
            loose_bytes,
            packs: packs.len(),
            packed_objects: packs.iter().map(|p| p.index().len()).sum(),
            pack_bytes: packs.iter().map(|p| p.disk_size()).sum(),
            trees: self.trees.stats(),
            snapshots: self.snapshots.stats(),
            delta_bases: self.bases.stats(),
        })
    }

    /// Drop every cache and re-scan packs (after gc changed the store).
    pub fn invalidate(&self) -> Result<()> {
        self.trees.clear();
        self.snapshots.clear();
        self.bases.clear();
        *self.gc.pending.write().unwrap() = None;
        self.gc.freshened.write().unwrap().clear();
        *self.packs.write().unwrap() = PackSet::default();
        self.reload_packs()?;
        Ok(())
    }

    // ---- gc cooperation --------------------------------------------------

    /// Disable freshening while gc itself walks the store.
    pub(crate) fn set_freshening(&self, on: bool) {
        self.gc.enabled.store(on, Ordering::SeqCst);
    }

    fn is_gc_candidate(&self, id: &ObjectId) -> bool {
        if !self.gc.enabled.load(Ordering::Relaxed) {
            return false;
        }
        {
            let p = self.gc.pending.read().unwrap();
            if let Some((at, set)) = &*p {
                if crate::clock::monotonic().saturating_sub(*at) < PENDING_TTL {
                    return set.contains(id);
                }
            }
        }
        let set = Arc::new(
            crate::gc::read_pending(&*self.backend, &self.gc_dir())
                .map(|m| m.into_keys().collect::<HashSet<ObjectId>>())
                .unwrap_or_default(),
        );
        let hit = set.contains(id);
        *self.gc.pending.write().unwrap() = Some((crate::clock::monotonic(), set));
        hit
    }

    fn write_keep_marker(&self, id: &ObjectId) {
        let _ = self.backend.write(&self.keep_marker(id), b"");
    }

    /// If `id` is a gc candidate, mark it as in use and make sure a loose copy
    /// exists, so that no gc deletes it from under us.
    fn freshen(&self, id: &ObjectId) {
        if !self.is_gc_candidate(id) || self.gc.freshened.read().unwrap().contains(id) {
            return;
        }
        self.write_keep_marker(id);
        if !self.loose_exists(id) {
            if let Ok(Some(raw)) = self.read_packed(id) {
                let _ = self.backend.write(&self.loose_path(id), &raw);
            }
        }
        self.gc.freshened.write().unwrap().insert(*id);
    }

    // ---- typed access ----------------------------------------------------

    /// Decode without decrypting.
    pub fn get(&self, id: &ObjectId) -> Result<Object> {
        Object::decode(&self.get_raw(id)?)
    }

    /// Decode and peel any sealed layers using the keychain.
    pub fn open(&self, id: &ObjectId) -> Result<Object> {
        let mut obj = self.get(id)?;
        while let Object::Sealed(env) = obj {
            let key = self.keys.require(&env.scope)?;
            let plain = env.open(&key).map_err(|_| VeilError::Redacted {
                scope: env.scope.clone(),
            })?;
            obj = Object::decode(&plain)?;
        }
        Ok(obj)
    }

    /// The tree `id` as this reader sees it. An embargo wrapper (see
    /// [`crate::embargo`]) resolves to its sealed content for key holders
    /// and to its fallback for everyone else; any other tree is returned as
    /// stored. The resolution is not cached: it depends on keys and release
    /// state, which change.
    pub fn tree(&self, id: &ObjectId) -> Result<Arc<Tree>> {
        let t = self.tree_object(id)?;
        match crate::embargo::wrapper_parts(&t) {
            None => Ok(t),
            Some(w) => {
                if self.keys.has(&w.key_label()) {
                    match self.tree(&w.inner) {
                        Err(e) if e.is_unreadable() => {}
                        r => return r,
                    }
                }
                self.tree(&w.fallback)
            }
        }
    }

    /// The tree object `id` exactly as stored (unsealed, but an embargo
    /// wrapper is *not* resolved). For code that walks raw objects.
    pub fn tree_object(&self, id: &ObjectId) -> Result<Arc<Tree>> {
        if let Some(t) = self.trees.get(id) {
            return Ok(t);
        }
        let t = match self.open(id)? {
            Object::Tree(t) => Arc::new(t),
            o => {
                return Err(VeilError::Corrupt(
                    id.hex(),
                    format!("expected tree, found {}", o.kind_name()),
                ))
            }
        };
        self.trees.insert(*id, t.clone(), t.entries.len() + 1);
        Ok(t)
    }

    /// Store a tree. It must be valid ([`Tree::validate`]): the store never
    /// writes a tree that it would refuse to read back.
    pub fn put_tree(&self, t: &Tree) -> Result<ObjectId> {
        t.validate()?;
        self.put(&Object::Tree(t.clone()))
    }

    /// Store a conflict object (repository format 4). Refused below format 4:
    /// such repositories record conflicts as markers in the file.
    pub fn put_conflict(&self, c: &Conflict) -> Result<ObjectId> {
        c.validate()?;
        if self.format() < crate::object::CONFLICT_REPO_FORMAT {
            return Err(VeilError::Unsupported(format!(
                "this repository is at format {} and cannot store conflicts as data; upgrade it with `vl upgrade`",
                self.format()
            )));
        }
        self.put(&Object::Conflict(c.clone()))
    }

    /// Store an annotated tag (format 5; refused below, see
    /// [`ObjectStore::put`]). Validated first, as every reader does.
    pub fn put_atag(&self, a: &crate::tag_object::Atag) -> Result<ObjectId> {
        a.validate()?;
        self.put(&Object::Atag(a.clone()))
    }

    /// The annotated tag `id` (format 5).
    pub fn atag(&self, id: &ObjectId) -> Result<crate::tag_object::Atag> {
        match self.get(id)? {
            Object::Atag(a) => Ok(a),
            o => Err(VeilError::Corrupt(
                id.hex(),
                format!("expected annotated tag, found {}", o.kind_name()),
            )),
        }
    }

    /// The conflict object `id`.
    pub fn conflict(&self, id: &ObjectId) -> Result<Conflict> {
        match self.open(id)? {
            Object::Conflict(c) => Ok(c),
            o => Err(VeilError::Corrupt(
                id.hex(),
                format!("expected conflict, found {}", o.kind_name()),
            )),
        }
    }

    pub fn empty_tree(&self) -> Result<ObjectId> {
        self.put_tree(&Tree::default())
    }

    pub fn snapshot(&self, id: &ObjectId) -> Result<Arc<Snapshot>> {
        if let Some(s) = self.snapshots.get(id) {
            return Ok(s);
        }
        let s = match self.get(id)? {
            Object::Snapshot(s) => Arc::new(s),
            o => {
                return Err(VeilError::Corrupt(
                    id.hex(),
                    format!("expected snapshot, found {}", o.kind_name()),
                ))
            }
        };
        self.snapshots.insert(*id, s.clone(), 1);
        Ok(s)
    }

    pub fn put_snapshot(&self, s: &Snapshot) -> Result<ObjectId> {
        self.put(&Object::Snapshot(s.clone()))
    }

    /// Seal `inner` under `scope` (deterministically, for dedup). A bare
    /// scope name seals under its current key generation (`scope#key-id`);
    /// a label that already names a generation is used as is.
    pub fn seal(&self, inner: &Object, scope: &str) -> Result<Object> {
        let (label, key) = self.keys.sealing_key(scope)?;
        let key = zeroize::Zeroizing::new(key);
        Ok(Object::Sealed(self.seal_deterministic(&key, &label, &self.encode(inner))?))
    }

    /// Store file content with the given visibility, returning its id.
    pub fn store_file(&self, data: &[u8], vis: &Visibility) -> Result<ObjectId> {
        let blob = Object::Blob(data.to_vec());
        match vis.key_scope() {
            None => self.put(&blob),
            Some(scope) => self.put(&self.seal(&blob, &scope)?),
        }
    }

    pub fn read_blob(&self, id: &ObjectId) -> Result<Vec<u8>> {
        match self.open(id)? {
            Object::Blob(b) => Ok(b),
            o => Err(VeilError::Corrupt(
                id.hex(),
                format!("expected blob, found {}", o.kind_name()),
            )),
        }
    }

    /// Read a file entry, falling back to the embargo fallback when the
    /// primary content is unreadable.
    pub fn read_entry(&self, e: &TreeEntry) -> Result<Vec<u8>> {
        match self.read_blob(&e.id) {
            Err(err) if err.is_unreadable() => match &e.fallback {
                Some(fb) => self.read_blob(fb),
                None => Err(err),
            },
            r => r,
        }
    }

    fn id_readable(&self, id: &ObjectId) -> bool {
        match self.get_raw(id) {
            Ok(raw) => match Object::sealed_scope(&raw) {
                Some(scope) => self.keys.has(&scope),
                None => true,
            },
            Err(_) => false,
        }
    }

    /// Can this reader materialise the entry?
    pub fn entry_readable(&self, e: &TreeEntry) -> bool {
        match e.kind {
            // A conflict is always materialised (unreadable sides redacted).
            EntryKind::Dir | EntryKind::Conflict => self.has(&e.id),
            EntryKind::File | EntryKind::Symlink => {
                self.id_readable(&e.id) || e.fallback.is_some_and(|f| self.id_readable(&f))
            }
        }
    }

    /// Would `data` encode to exactly `reference` (same plaintext, same
    /// sealing scope)? Used to recognise unchanged fallback content.
    pub fn matches_encoding(&self, reference: &ObjectId, data: &[u8]) -> Result<bool> {
        let raw = match self.get_raw(reference) {
            Ok(r) => r,
            Err(e) if e.is_unreadable() => return Ok(false),
            Err(e) => return Err(e),
        };
        if Object::is_blob_raw(&raw) {
            return Ok(Object::blob_id(data) == *reference);
        }
        match Object::sealed_scope(&raw) {
            Some(label) if self.keys.has(&label) => {
                // Open the reference and compare plaintexts: sealing is
                // deterministic per construction, so equal plaintext under
                // the same label means the reference is what this repository
                // would write (or an older construction's equivalent, which
                // is kept rather than re-sealed: same content, same id).
                let Ok(Object::Sealed(env)) = Object::decode(&raw) else {
                    return Ok(false);
                };
                let key = zeroize::Zeroizing::new(self.keys.require(&label)?);
                let Ok(plain) = env.open(&key) else { return Ok(false) };
                let plain = zeroize::Zeroizing::new(plain);
                Ok(plain.strip_prefix(&b"veil:blob\n"[..]) == Some(data))
            }
            _ => Ok(false),
        }
    }

    pub fn make_text(&self, text: &str, cloak: Option<&str>) -> Result<Text> {
        match cloak {
            None => Ok(Text::Plain(text.to_string())),
            Some(scope) => {
                let (label, key) = self.keys.sealing_key(scope)?;
                let key = zeroize::Zeroizing::new(key);
                Ok(Text::Sealed(Envelope::seal_random(&key, &label, text.as_bytes())?))
            }
        }
    }

    /// Plaintext of a description, or `None` if cloaked and unreadable.
    pub fn read_text(&self, t: &Text) -> Option<String> {
        match t {
            Text::Plain(s) => Some(s.clone()),
            Text::Sealed(env) => {
                let key = self.keys.key(&env.scope)?;
                String::from_utf8(env.open(&key).ok()?).ok()
            }
        }
    }
}
