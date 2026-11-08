//! The daemon's store (`docs/HUB.md` §13.29): objects fetched by anyone on
//! the machine, as the server sent them (plain-text code; secret files as
//! their ciphertext), one file each under `objects/`, named by a hash of the
//! server, the project and the object's id, so projects never share an entry
//! and no file name says which project it is of.
//!
//! * **Every read is checked** against the object's id: a damaged file is
//!   removed and read as absent (the request goes to the server).
//! * **Bounded:** at most `limit` bytes of objects and [`MAX_ENTRIES`]
//!   objects; past either, the least recently used are removed first, down
//!   to 80 %, except what is **pinned**: the trees a working copy registered
//!   and everything below them that the store holds. When what is pinned
//!   alone fills the bound, a new object is not kept (never an eviction
//!   loop): the daemon still passes it on.
//! * **The index** (in memory, about 56 bytes an object, so at most 28 MiB)
//!   is rebuilt from the directory at start, in the background; until it is
//!   ready nothing is served from the store or kept.
//! * Nothing here is local work: a repository's own objects are in its own
//!   store, never here, so eviction can only cost a second download.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use veil_core::{
    object::{EntryKind, Object},
    ObjectId,
};

use super::proto::MAX_OBJECT;

/// Most objects the store keeps (its index holds about 56 bytes each).
pub const MAX_ENTRIES: usize = 500_000;
/// Most objects one eviction marks as pinned (a 32-byte id each, about
/// 48 MiB at the most); past it, the rest may be evicted (they cost only a
/// second download: every working copy holds its own).
const MAX_PINNED: usize = 1_000_000;
/// Most working copies with pins.
const MAX_PINS: usize = 1024;

/// A store entry's key: a hash of the server, the project and the id.
pub type Key = [u8; 32];

pub fn key(upstream: &str, project: &str, id: &ObjectId) -> Key {
    let mut h = blake3::Hasher::new();
    h.update(b"veil-daemon-object\0");
    h.update(upstream.as_bytes());
    h.update(b"\0");
    h.update(project.as_bytes());
    h.update(b"\0");
    h.update(&id.0);
    *h.finalize().as_bytes()
}

#[derive(Clone, Copy)]
struct Entry {
    size: u32,
    tick: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Pin {
    upstream: String,
    project: String,
    roots: Vec<ObjectId>,
}

#[derive(Default)]
struct Index {
    map: HashMap<Key, Entry>,
    bytes: u64,
    tick: u64,
    pins: BTreeMap<String, Pin>,
}

#[derive(Default)]
pub struct Counters {
    pub damaged: AtomicU64,
    pub evicted: AtomicU64,
    pub not_kept: AtomicU64,
    pub pinned_bytes: AtomicU64,
}

pub struct Store {
    dir: PathBuf,
    limit: AtomicU64,
    max_entries: usize,
    index: Mutex<Index>,
    ready: AtomicBool,
    evicting: Mutex<()>,
    pub counters: Counters,
}

/// What [`Store::usage`] reports.
pub struct Usage {
    pub bytes: u64,
    pub objects: usize,
    pub limit: u64,
    pub pins: usize,
    pub ready: bool,
}

impl Store {
    /// The store in `dir` (made 0700), with a bound of `limit` bytes; its
    /// index is read in the background.
    pub fn open(dir: &Path, limit: u64) -> Result<Arc<Store>> {
        Store::open_with(dir, limit, MAX_ENTRIES)
    }

    pub fn open_with(dir: &Path, limit: u64, max_entries: usize) -> Result<Arc<Store>> {
        // Below the daemon's own folder, which `Paths::prepare` made: never
        // its parents (BUG-1513).
        super::private_subdir(dir)?;
        super::private_subdir(&dir.join("objects"))?;
        let pins: BTreeMap<String, Pin> = std::fs::read(dir.join("pins.json")).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
        let s = Arc::new(Store {
            dir: dir.to_path_buf(),
            limit: AtomicU64::new(limit),
            max_entries,
            index: Mutex::new(Index { pins, ..Default::default() }),
            ready: AtomicBool::new(false),
            evicting: Mutex::new(()),
            counters: Counters::default(),
        });
        let bg = s.clone();
        std::thread::spawn(move || bg.scan());
        Ok(s)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Index> {
        self.index.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn path(&self, key: &Key) -> PathBuf {
        let h = hex::encode(key);
        self.dir.join("objects").join(&h[..2]).join(&h[2..])
    }

    /// Rebuild the index from the directory (oldest first by modification
    /// time), dropping unfinished writes and what exceeds the entry bound.
    fn scan(&self) {
        let mut found: Vec<(std::time::SystemTime, Key, u32)> = Vec::new();
        for d in std::fs::read_dir(self.dir.join("objects")).into_iter().flatten().flatten() {
            let prefix = d.file_name().to_string_lossy().to_string();
            for f in std::fs::read_dir(d.path()).into_iter().flatten().flatten() {
                let name = f.file_name().to_string_lossy().to_string();
                let parsed = hex::decode(format!("{prefix}{name}")).ok().and_then(|k| <Key>::try_from(k).ok());
                let meta = f.metadata().ok();
                match (parsed, meta) {
                    (Some(k), Some(m)) if m.is_file() && m.len() <= MAX_OBJECT as u64 => {
                        found.push((m.modified().unwrap_or(std::time::UNIX_EPOCH), k, m.len() as u32))
                    }
                    _ => {
                        let _ = std::fs::remove_file(f.path());
                    }
                }
            }
        }
        found.sort_by_key(|f| f.0);
        let excess = found.len().saturating_sub(self.max_entries);
        for (_, k, _) in found.drain(..excess) {
            let _ = std::fs::remove_file(self.path(&k));
        }
        let mut ix = self.lock();
        for (_, k, size) in found {
            ix.tick += 1;
            let tick = ix.tick;
            // Written meanwhile: already indexed.
            if let std::collections::hash_map::Entry::Vacant(v) = ix.map.entry(k) {
                v.insert(Entry { size, tick });
                ix.bytes += u64::from(size);
            }
        }
        drop(ix);
        self.ready.store(true, Ordering::SeqCst);
    }

    pub fn ready(&self) -> bool {
        self.ready.load(Ordering::SeqCst)
    }

    pub fn set_limit(&self, limit: u64) {
        self.limit.store(limit, Ordering::Relaxed);
    }

    pub fn limit(&self) -> u64 {
        self.limit.load(Ordering::Relaxed)
    }

    /// The size of the object under `key`, if the store holds it.
    pub fn size(&self, key: &Key) -> Option<u64> {
        if !self.ready() {
            return None;
        }
        self.lock().map.get(key).map(|e| u64::from(e.size))
    }

    /// The object `id` under `key`, checked against its id; a damaged copy
    /// is removed and read as absent. The caller holds a budget share of
    /// [`Store::size`].
    pub fn read(&self, key: &Key, id: &ObjectId) -> Option<Vec<u8>> {
        self.size(key)?;
        let raw = std::fs::read(self.path(key)).ok();
        match raw {
            Some(raw) if ObjectId::hash(&raw) == *id => {
                let mut ix = self.lock();
                ix.tick += 1;
                let tick = ix.tick;
                if let Some(e) = ix.map.get_mut(key) {
                    e.tick = tick;
                }
                Some(raw)
            }
            Some(_) => {
                self.counters.damaged.fetch_add(1, Ordering::Relaxed);
                self.remove(key);
                None
            }
            None => {
                self.forget(key);
                None
            }
        }
    }

    fn forget(&self, key: &Key) {
        let mut ix = self.lock();
        if let Some(e) = ix.map.remove(key) {
            ix.bytes -= u64::from(e.size);
        }
    }

    fn remove(&self, key: &Key) {
        self.forget(key);
        let _ = std::fs::remove_file(self.path(key));
    }

    /// Keep `raw` (already checked against `id`) under `key`, making room
    /// if needed; not kept when it is too large, the index is not ready, or
    /// what is pinned leaves no room.
    pub fn put(&self, key: &Key, id: &ObjectId, raw: &[u8]) {
        debug_assert_eq!(ObjectId::hash(raw), *id);
        if raw.len() > MAX_OBJECT || !self.ready() || self.lock().map.contains_key(key) {
            return;
        }
        let need = raw.len() as u64;
        if !self.room_for(need) {
            self.counters.not_kept.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let path = self.path(key);
        static WRITES: AtomicU64 = AtomicU64::new(0);
        let tmp = path.with_extension(format!("tmp{}-{}", std::process::id(), WRITES.fetch_add(1, Ordering::Relaxed)));
        // The fan-out folder alone (`objects/` exists from `open`): a store
        // removed meanwhile (its Veil home) fails the write, and nothing is
        // made again (BUG-1513).
        let fan_out = path.parent().map_or(Ok(()), |d| match std::fs::create_dir(d) {
            Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => Err(e),
            _ => Ok(()),
        });
        let written = fan_out.and_then(|_| std::fs::write(&tmp, raw)).and_then(|_| std::fs::rename(&tmp, &path));
        if written.is_err() {
            let _ = std::fs::remove_file(&tmp);
            self.counters.not_kept.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let mut ix = self.lock();
        ix.tick += 1;
        let tick = ix.tick;
        if ix.map.insert(*key, Entry { size: raw.len() as u32, tick }).is_none() {
            ix.bytes += need;
        }
    }

    /// Is there room for `need` more bytes and one more object, after
    /// evicting if needed?
    fn room_for(&self, need: u64) -> bool {
        let fits = |ix: &Index, limit: u64| ix.bytes + need <= limit && ix.map.len() < self.max_entries;
        let limit = self.limit();
        if fits(&self.lock(), limit) {
            return true;
        }
        if need > limit {
            return false;
        }
        // One eviction at a time; a writer that finds one running does
        // not keep its object (it is passed on all the same).
        let Ok(_one) = self.evicting.try_lock() else { return false };
        self.evict(need);
        fits(&self.lock(), limit)
    }

    /// Remove the least recently used unpinned objects until `need` more
    /// bytes fit within 80 % of the bound (and 80 % of the entries).
    fn evict(&self, need: u64) {
        let pinned = self.pinned();
        let limit = self.limit();
        let (target_bytes, target_entries) = ((limit / 10 * 8).saturating_sub(need), self.max_entries / 10 * 8);
        let mut order: Vec<(u64, Key, u32)> = {
            let ix = self.lock();
            ix.map.iter().filter(|(k, _)| !pinned.contains(*k)).map(|(k, e)| (e.tick, *k, e.size)).collect()
        };
        order.sort_unstable_by_key(|o| o.0);
        let pinned_bytes: u64 = {
            let ix = self.lock();
            pinned.iter().filter_map(|k| ix.map.get(k)).map(|e| u64::from(e.size)).sum()
        };
        self.counters.pinned_bytes.store(pinned_bytes, Ordering::Relaxed);
        for (_, k, _) in order {
            {
                let ix = self.lock();
                if ix.bytes <= target_bytes && ix.map.len() <= target_entries {
                    break;
                }
            }
            self.remove(&k);
            self.counters.evicted.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// The keys of everything the pins reach in the store: each pinned
    /// tree, and what it names, down every folder the store holds.
    fn pinned(&self) -> HashSet<Key> {
        let pins: Vec<Pin> = self.lock().pins.values().cloned().collect();
        let mut out = HashSet::new();
        for pin in pins {
            let mut stack: Vec<ObjectId> = pin.roots.clone();
            let mut seen = HashSet::new();
            while let Some(id) = stack.pop() {
                if out.len() >= MAX_PINNED {
                    return out;
                }
                if !seen.insert(id) {
                    continue;
                }
                let k = key(&pin.upstream, &pin.project, &id);
                if !out.insert(k) {
                    continue;
                }
                let Some(raw) = self.read_quiet(&k, &id) else { continue };
                match Object::decode(&raw) {
                    Ok(Object::Tree(t)) => {
                        for e in &t.entries {
                            match e.kind {
                                EntryKind::Dir | EntryKind::Conflict => stack.push(e.id),
                                _ => {
                                    out.insert(key(&pin.upstream, &pin.project, &e.id));
                                }
                            }
                        }
                    }
                    Ok(Object::Conflict(c)) => stack.extend(c.referenced_ids()),
                    _ => {}
                }
            }
        }
        out
    }

    /// [`Store::read`] without touching the object's use (the pins' walk).
    fn read_quiet(&self, key: &Key, id: &ObjectId) -> Option<Vec<u8>> {
        self.lock().map.get(key)?;
        std::fs::read(self.path(key)).ok().filter(|raw| ObjectId::hash(raw) == *id)
    }

    /// Set (or, with no roots, remove) the pins of working copy `pin_key`.
    pub fn set_pin(&self, pin_key: &str, upstream: &str, project: &str, roots: Vec<ObjectId>) -> Result<()> {
        // Written under the lock: one writer of `pins.json` at a time (pins
        // change rarely; an unchanged one writes nothing).
        let mut ix = self.lock();
        {
            let same = match ix.pins.get(pin_key) {
                Some(p) => p.upstream == upstream && p.project == project && p.roots == roots,
                None => roots.is_empty(),
            };
            if same {
                return Ok(());
            }
            if roots.is_empty() {
                ix.pins.remove(pin_key);
            } else {
                if !ix.pins.contains_key(pin_key) && ix.pins.len() >= MAX_PINS {
                    anyhow::bail!("at most {MAX_PINS} working copies pin objects");
                }
                ix.pins.insert(pin_key.to_string(), Pin { upstream: upstream.to_string(), project: project.to_string(), roots });
            }
        }
        let tmp = self.dir.join(format!("pins.json.tmp{}", std::process::id()));
        std::fs::write(&tmp, serde_json::to_vec(&ix.pins)?)?;
        std::fs::rename(&tmp, self.dir.join("pins.json"))?;
        drop(ix);
        Ok(())
    }

    pub fn usage(&self) -> Usage {
        let ix = self.lock();
        Usage {
            bytes: ix.bytes,
            objects: ix.map.len(),
            limit: self.limit(),
            pins: ix.pins.len(),
            ready: self.ready(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wait_ready(s: &Store) {
        let t = std::time::Instant::now();
        while !s.ready() {
            assert!(t.elapsed() < std::time::Duration::from_secs(10));
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    fn blob(n: usize, size: usize) -> (ObjectId, Vec<u8>) {
        let mut raw = format!("veil:blob\n{n}:").into_bytes();
        raw.resize(size, b'x');
        (ObjectId::hash(&raw), raw)
    }

    #[test]
    fn the_store_keeps_to_its_bound_and_its_pins() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open_with(&dir.path().join("store"), 64 << 10, 1000).unwrap();
        wait_ready(&s);
        // A pinned tree with two files, kept first.
        let (fa, ra) = blob(1_000_000, 4096);
        let (fb, rb) = blob(1_000_001, 4096);
        let entry = |name: &str, id: ObjectId| veil_core::TreeEntry { name: name.into(), kind: EntryKind::File, id, size: 4096, executable: false, visibility: Default::default() };
        let tree = Object::Tree(veil_core::object::Tree { entries: vec![entry("a", fa), entry("b", fb)] }).encode();
        let tid = ObjectId::hash(&tree);
        for (id, raw) in [(tid, &tree), (fa, &ra), (fb, &rb)] {
            s.put(&key("h", "p", &id), &id, raw);
        }
        s.set_pin("wc", "h", "p", vec![tid]).unwrap();
        let mut kept = Vec::new();
        for n in 0..200 {
            let (id, raw) = blob(n, 4096);
            s.put(&key("h", "p", &id), &id, &raw);
            kept.push(id);
            let u = s.usage();
            assert!(u.bytes <= 64 << 10, "{} bytes over the bound", u.bytes);
        }
        for id in [tid, fa, fb] {
            assert!(s.read(&key("h", "p", &id), &id).is_some(), "a pinned object was evicted");
        }
        assert!(s.read(&key("h", "p", &kept[199]), &kept[199]).is_some(), "the newest is kept");
        assert!(s.read(&key("h", "p", &kept[0]), &kept[0]).is_none(), "the oldest is evicted");
        assert!(s.counters.evicted.load(Ordering::Relaxed) > 0);
        // Another project's key never reads it.
        assert!(s.read(&key("h", "q", &kept[199]), &kept[199]).is_none());
        // Pins that fill the bound: nothing more is kept, nothing loops.
        let small = Store::open_with(&dir.path().join("small"), 10_000, 1000).unwrap();
        wait_ready(&small);
        for (id, raw) in [(tid, &tree), (fa, &ra), (fb, &rb)] {
            small.put(&key("h", "p", &id), &id, raw);
        }
        small.set_pin("wc", "h", "p", vec![tid]).unwrap();
        let (x, rx) = blob(7, 4096);
        small.put(&key("h", "p", &x), &x, &rx);
        assert!(small.read(&key("h", "p", &x), &x).is_none());
        assert!(small.counters.not_kept.load(Ordering::Relaxed) > 0);
    }

    /// The daemon never makes a Veil home (§13.29): an object kept while
    /// its home is being removed (a request in flight in the second before
    /// the daemon sees the home gone) is not kept, and nothing is made
    /// again.
    #[test]
    fn keeping_an_object_never_makes_a_removed_veil_home_again() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("veil-home");
        // As `Paths::prepare` leaves it: the home and the daemon's folder.
        std::fs::create_dir_all(home.join("daemon")).unwrap();
        let s = Store::open(&home.join("daemon").join("store"), 1 << 30).unwrap();
        wait_ready(&s);
        let (id, raw) = blob(1, 100);
        let k = key("h", "p", &id);
        s.put(&k, &id, &raw);
        assert_eq!(s.read(&k, &id).as_deref(), Some(&raw[..]), "the object was not kept");
        std::fs::remove_dir_all(&home).unwrap();
        let (id2, raw2) = blob(2, 100);
        s.put(&key("h", "p", &id2), &id2, &raw2);
        assert!(!home.exists(), "keeping an object made the removed Veil home again");
    }

    #[test]
    fn a_damaged_object_is_removed_and_never_read() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(&dir.path().join("store"), 1 << 30).unwrap();
        wait_ready(&s);
        let (id, raw) = blob(1, 100);
        let k = key("h", "p", &id);
        s.put(&k, &id, &raw);
        assert_eq!(s.read(&k, &id).as_deref(), Some(&raw[..]));
        let mut bad = raw.clone();
        bad[50] ^= 1;
        std::fs::write(s.path(&k), bad).unwrap();
        assert!(s.read(&k, &id).is_none());
        assert!(!s.path(&k).exists() && s.usage().objects == 0);
        assert_eq!(s.counters.damaged.load(Ordering::Relaxed), 1);
        // A restart rebuilds the index from the files.
        s.put(&k, &id, &raw);
        let again = Store::open(&dir.path().join("store"), 1 << 30).unwrap();
        wait_ready(&again);
        assert_eq!(again.read(&k, &id).as_deref(), Some(&raw[..]));
        assert_eq!(again.usage().bytes, 100);
    }
}
