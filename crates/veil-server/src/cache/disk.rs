//! A regional cache's objects on disk: immutable objects by `(project,
//! id)`, bounded in bytes and in number, least recently used out first
//! (`docs/HUB.md` §13.18).
//!
//! Every object is checked against its id when it is written and again
//! each time it is read: a file that does not match (a flipped byte, a torn
//! write) is removed and read as absent, so the cache asks the server
//! again and never serves wrong bytes. Objects are kept as the server sends
//! them (their canonical encodings); secret files are ciphertext, as the
//! server holds them. Nothing else is kept: losing the directory loses
//! nothing but warmth. Files are named by a hash of the project's name and
//! the id, so the directory names no project.

use std::{
    collections::{BTreeMap, HashMap},
    io::Write,
    path::{Path, PathBuf},
    sync::Mutex,
};

use veil_core::ObjectId;

type Key = [u8; 32];

/// What the store holds in memory per object (its index entry and its
/// place in the recency order), for its bound on entries.
pub const ENTRY_BYTES: u64 = 128;

/// The store's key of object `id` of project `project`.
pub(crate) fn key(project: &str, id: &ObjectId) -> Key {
    let mut h = blake3::Hasher::new_derive_key("veil regional cache 2026-11-07 object key");
    h.update(&(project.len() as u64).to_le_bytes());
    h.update(project.as_bytes());
    h.update(&id.0);
    *h.finalize().as_bytes()
}

#[derive(Default)]
struct Index {
    map: HashMap<Key, (u32, u64)>,
    order: BTreeMap<u64, Key>,
    tick: u64,
    bytes: u64,
}

impl Index {
    fn touch(&mut self, k: &Key) -> Option<u32> {
        let (size, tick) = self.map.get_mut(k)?;
        self.order.remove(tick);
        self.tick += 1;
        *tick = self.tick;
        self.order.insert(self.tick, *k);
        Some(*size)
    }

    fn remove(&mut self, k: &Key) -> bool {
        let Some((size, tick)) = self.map.remove(k) else { return false };
        self.order.remove(&tick);
        self.bytes -= size as u64;
        true
    }
}

pub struct Store {
    dir: PathBuf,
    index: Mutex<Index>,
    /// Most bytes of objects, and most objects.
    max_bytes: u64,
    max_entries: usize,
    /// Largest object kept (larger ones pass through, not kept).
    pub max_object: u64,
}

impl Store {
    /// The store in `dir` (made if missing), holding at most `max_bytes` of
    /// objects and `max_entries` of them. What an earlier run left there is
    /// kept, up to the bounds; anything else in it is removed.
    pub fn open(dir: &Path, max_bytes: u64, max_entries: usize, max_object: u64) -> std::io::Result<Store> {
        let objects = dir.join("objects");
        let tmp = dir.join("tmp");
        std::fs::create_dir_all(&objects)?;
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp)?;
        let s = Store {
            dir: dir.to_path_buf(),
            index: Mutex::new(Index::default()),
            max_bytes,
            max_entries,
            max_object,
        };
        let mut stale = Vec::new();
        for sub in std::fs::read_dir(&objects)?.flatten() {
            let Ok(files) = std::fs::read_dir(sub.path()) else {
                stale.push(sub.path());
                continue;
            };
            for f in files.flatten() {
                let k: Option<Key> = f.file_name().to_str().and_then(|n| hex::decode(n).ok()).and_then(|b| b.try_into().ok());
                let len = f.metadata().map(|m| m.len()).unwrap_or(u64::MAX);
                match k {
                    Some(k) if len <= max_object && s.path(&k) == f.path() => s.insert(k, len as u32),
                    _ => stale.push(f.path()),
                }
            }
        }
        for p in stale {
            let _ = std::fs::remove_file(&p).or_else(|_| std::fs::remove_dir_all(&p));
        }
        s.evict();
        Ok(s)
    }

    fn path(&self, k: &Key) -> PathBuf {
        let h = hex::encode(k);
        self.dir.join("objects").join(&h[..2]).join(h)
    }

    fn insert(&self, k: Key, size: u32) {
        let mut ix = self.index.lock().unwrap();
        ix.remove(&k);
        ix.tick += 1;
        let t = ix.tick;
        ix.map.insert(k, (size, t));
        ix.order.insert(t, k);
        ix.bytes += size as u64;
    }

    /// Remove least recently used objects until within the bounds.
    fn evict(&self) {
        let mut gone = Vec::new();
        {
            let mut ix = self.index.lock().unwrap();
            while ix.bytes > self.max_bytes || ix.map.len() > self.max_entries {
                let Some((_, k)) = ix.order.pop_first() else { break };
                if let Some((size, _)) = ix.map.remove(&k) {
                    ix.bytes -= size as u64;
                }
                gone.push(k);
            }
        }
        for k in gone {
            let _ = std::fs::remove_file(self.path(&k));
        }
    }

    /// The size of object `id` of `project` if the store holds it (it may
    /// still turn out unreadable: [`Store::get`]).
    pub fn has(&self, project: &str, id: &ObjectId) -> Option<u64> {
        self.index.lock().unwrap().map.get(&key(project, id)).map(|e| e.0 as u64)
    }

    /// Object `id` of `project`, checked against its id; `None` if not
    /// held, or if its file does not match (then it is removed).
    pub fn get(&self, project: &str, id: &ObjectId) -> Option<Vec<u8>> {
        let k = key(project, id);
        self.index.lock().unwrap().touch(&k)?;
        let raw = std::fs::read(self.path(&k)).ok();
        match raw {
            Some(raw) if ObjectId::hash(&raw) == *id => Some(raw),
            other => {
                if other.is_some() {
                    eprintln!("veil-server cache: an object in the store does not match its id; removed");
                }
                self.index.lock().unwrap().remove(&k);
                let _ = std::fs::remove_file(self.path(&k));
                None
            }
        }
    }

    /// Keep `raw` as object `id` of `project` if it is that object and no
    /// larger than [`Store::max_object`]; `true` if kept. Written whole to a
    /// temporary file, then renamed into place.
    pub fn put(&self, project: &str, id: &ObjectId, raw: &[u8]) -> bool {
        if raw.len() as u64 > self.max_object || ObjectId::hash(raw) != *id {
            return false;
        }
        let k = key(project, id);
        if self.index.lock().unwrap().map.contains_key(&k) {
            return true;
        }
        let path = self.path(&k);
        let written = (|| {
            std::fs::create_dir_all(path.parent().expect("a parent"))?;
            let mut f = tempfile::NamedTempFile::new_in(self.dir.join("tmp"))?;
            f.write_all(raw)?;
            f.persist(&path).map_err(|e| e.error)?;
            std::io::Result::Ok(())
        })();
        if let Err(e) = written {
            eprintln!("veil-server cache: writing an object: {e}");
            return false;
        }
        self.insert(k, raw.len() as u32);
        self.evict();
        true
    }

    /// Objects held and their bytes.
    pub fn usage(&self) -> (usize, u64) {
        let ix = self.index.lock().unwrap();
        (ix.map.len(), ix.bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obj(n: usize, len: usize) -> (ObjectId, Vec<u8>) {
        let mut raw = format!("veil:blob\n{n}:").into_bytes();
        raw.resize(len, b'x');
        (ObjectId::hash(&raw), raw)
    }

    fn files(dir: &Path) -> (usize, u64) {
        let (mut n, mut bytes) = (0, 0);
        for sub in std::fs::read_dir(dir.join("objects")).unwrap().flatten() {
            for f in std::fs::read_dir(sub.path()).unwrap().flatten() {
                n += 1;
                bytes += f.metadata().unwrap().len();
            }
        }
        (n, bytes)
    }

    #[test]
    fn the_store_keeps_its_bounds_and_evicts_the_least_recently_used() {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(d.path(), 10_000, 1000, 2000).unwrap();
        let objs: Vec<_> = (0..30).map(|i| obj(i, 1000)).collect();
        for (i, (id, raw)) in objs.iter().enumerate() {
            assert!(s.put("p", id, raw));
            // Keep the first one in use.
            assert!(s.get("p", &objs[0].0).is_some(), "after {i}");
            assert!(s.usage().1 <= 10_000 && files(d.path()).1 <= 10_000);
        }
        assert_eq!(s.usage(), (10, 10_000));
        assert_eq!(files(d.path()), (10, 10_000));
        assert!(s.get("p", &objs[1].0).is_none(), "evicted");
        assert_eq!(s.get("p", &objs[29].0).as_deref(), Some(&objs[29].1[..]));
        // Not the object its id names, or too large: not kept.
        assert!(!s.put("p", &objs[3].0, &objs[4].1));
        let big = obj(99, 2001);
        assert!(!s.put("p", &big.0, &big.1));
        // Projects never share an entry.
        assert!(s.get("q", &objs[29].0).is_none());
        // A bound on entries alone.
        let d2 = tempfile::tempdir().unwrap();
        let s2 = Store::open(d2.path(), u64::MAX, 3, 2000).unwrap();
        for (id, raw) in &objs[..8] {
            s2.put("p", id, raw);
        }
        assert_eq!(s2.usage().0, 3);
        assert_eq!(files(d2.path()).0, 3);
    }

    #[test]
    fn a_damaged_object_is_never_served_and_a_reopened_store_keeps_its_objects() {
        let d = tempfile::tempdir().unwrap();
        let (id, raw) = obj(1, 500);
        let (id2, raw2) = obj(2, 500);
        {
            let s = Store::open(d.path(), 1 << 20, 100, 1 << 20).unwrap();
            assert!(s.put("p", &id, &raw) && s.put("p", &id2, &raw2));
            let path = s.path(&key("p", &id));
            let mut b = std::fs::read(&path).unwrap();
            b[100] ^= 1;
            std::fs::write(&path, b).unwrap();
            assert!(s.get("p", &id).is_none(), "flipped byte");
            assert!(!path.exists(), "removed");
            assert!(s.has("p", &id).is_none());
            assert!(s.put("p", &id, &raw), "written again");
            assert_eq!(s.get("p", &id).unwrap(), raw);
            // A file removed under it reads as absent.
            std::fs::remove_file(s.path(&key("p", &id2))).unwrap();
            assert!(s.get("p", &id2).is_none() && s.has("p", &id2).is_none());
        }
        // Junk in the directory is removed at open; objects stay.
        std::fs::write(d.path().join("objects").join("zz"), b"junk").unwrap();
        std::fs::create_dir_all(d.path().join("objects/ab")).unwrap();
        std::fs::write(d.path().join("objects/ab/not-a-key"), b"junk").unwrap();
        let s = Store::open(d.path(), 1 << 20, 100, 1 << 20).unwrap();
        assert_eq!(s.get("p", &id).unwrap(), raw);
        assert_eq!(s.usage(), (1, 500));
        assert!(!d.path().join("objects/zz").exists() && !d.path().join("objects/ab/not-a-key").exists());
    }
}
