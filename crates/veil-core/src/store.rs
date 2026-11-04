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
        Arc, RwLock,
    },
    time::{Duration, Instant},
};

use crate::{
    cache::{CacheStats, LruCache},
    crypto::Envelope,
    error::{Result, VeilError},
    id::ObjectId,
    keychain::Keychain,
    object::{EntryKind, Object, Snapshot, Text, Tree, TreeEncoding, TreeEntry, Visibility},
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
    pending: RwLock<Option<(Instant, Arc<HashSet<ObjectId>>)>>,
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
    /// Repository format: decides the tree encoding written and accepted.
    format: AtomicU32,
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
            format: AtomicU32::new(crate::repo::REPO_FORMAT),
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
    pub(crate) fn check_storable(&self, raw: &[u8]) -> Result<()> {
        let need = Object::min_repo_format(raw);
        let have = self.format();
        if need > have {
            let what = if Object::tree_encoding(raw).is_some() {
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
    pub fn sync_barrier(&self) -> Result<()> {
        self.backend.sync_barrier()
    }

    fn write_loose(&self, id: &ObjectId, raw: &[u8]) -> Result<()> {
        if self.unsynced.load(Ordering::SeqCst) > 0 {
            self.backend.write_unsynced(&self.loose_path(id), raw)
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
        self.backend.exists(&self.loose_path(id)).unwrap_or(false)
    }

    pub fn has(&self, id: &ObjectId) -> bool {
        self.freshen(id);
        if self.loose_exists(id) {
            return true;
        }
        if self.ensure_packs().is_err() {
            return false;
        }
        self.in_loaded_packs(id) || (self.reload_packs().unwrap_or(false) && self.in_loaded_packs(id))
    }

    /// Like `has`, without rescanning packs: used to skip redundant writes,
    /// where a false negative only costs a duplicate loose copy.
    fn has_cached(&self, id: &ObjectId) -> bool {
        self.loose_exists(id) || (self.ensure_packs().is_ok() && self.in_loaded_packs(id))
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
        let loose_corrupt = match self.read_loose_verified(id)? {
            Loose::Good(b) => return Ok(b),
            Loose::Absent => false,
            Loose::Corrupt => true,
        };
        match self.read_packed(id) {
            Ok(Some(raw)) => Ok(raw),
            Ok(None) if loose_corrupt => Err(loose_mismatch(id)),
            Ok(None) => Err(VeilError::Missing(*id)),
            Err(e) if loose_corrupt && e.is_not_found() => Err(loose_mismatch(id)),
            Err(e) => Err(e),
        }
    }

    fn read_loose_verified(&self, id: &ObjectId) -> Result<Loose> {
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
        if self.is_gc_candidate(id) {
            // A gc may be about to delete the existing copy: mark it, then
            // make sure we have our own good loose copy (in that order).
            self.write_keep_marker(id);
            if matches!(self.read_loose_verified(id)?, Loose::Good(_)) {
                return Ok(false);
            }
            self.write_loose(id, raw)?;
            return Ok(true);
        }
        if self.has_cached(id) && self.has_verified(id)? {
            return Ok(false);
        }
        self.write_loose(id, raw)?;
        Ok(true)
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
    pub fn put(&self, obj: &Object) -> Result<ObjectId> {
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
                if at.elapsed() < PENDING_TTL {
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
        *self.gc.pending.write().unwrap() = Some((Instant::now(), set));
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
            EntryKind::Dir => self.has(&e.id),
            EntryKind::File => self.id_readable(&e.id) || e.fallback.is_some_and(|f| self.id_readable(&f)),
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
