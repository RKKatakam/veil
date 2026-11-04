//! Device-local stat cache: lets snapshots skip re-reading and re-hashing
//! files whose stat data has not changed.
//!
//! A cache belongs to one working copy (the CLI keeps one per workspace under
//! `.veil/local/statcache/`). It maps each file path to its *stamp* (mtime,
//! ctime, inode, size, executable bit) and to **content facts** learned the
//! last time the file was read:
//!
//! * `content`: the BLAKE3 blob id of the plaintext;
//! * `scanned_clean`: the secret scanner ran on that content and found
//!   nothing;
//! * `sealed`: under scope `s` (with the current key), the content seals to
//!   object `id`.
//!
//! Records hold facts, not policy decisions. The builder still classifies
//! every path against the current policy on every run and only uses a fact
//! where it would otherwise have needed the bytes. As a second line of
//! defence the whole cache is keyed on the `.veilpolicy` content id and on a
//! fingerprint of the key and embargo state, and it is dropped when either
//! changes.
//!
//! **Racy mtime.** A file written in the same timestamp tick in which it was
//! verified could change again without its stamp moving. Each record stores
//! the clock reading taken *before* the file was stat'ed and read
//! (`verified_at`). A record is trusted only if its stamp is older than
//! `verified_at` by more than the backend's timestamp granularity, otherwise
//! the file is re-read (and the re-read records a later `verified_at`). For
//! [`MemoryBackend`](crate::MemoryBackend) the stamp is a generation counter
//! and there is no window at all.

use std::collections::HashMap;

use crate::{
    error::Result,
    id::ObjectId,
    keychain::{key_fingerprint, Keychain},
    object::Object,
    policy::POLICY_FILE,
    vfs::{Metadata, NodeKind, StatClock, StorageBackend},
    vpath::VPath,
};

const MAGIC: &[u8] = b"veil:statcache\n";
const VERSION: u32 = 1;
/// Racy window when stamps have whole-second precision (ext3, HFS+, FAT's
/// 2 s mtime, many network filesystems).
const COARSE_WINDOW_NS: i64 = 2_000_000_000;
/// Racy window when stamps have sub-second precision. Covers the kernel's
/// coarse timestamp clock lagging the precise wall clock (one tick, at most
/// 10 ms at HZ=100) and 10 ms granularity filesystems (exFAT), with margin.
const FINE_WINDOW_NS: i64 = 100_000_000;

/// Where the CLI keeps the cache for workspace `ws` (device-local).
pub fn cache_path(ws: &str) -> VPath {
    // Workspace names are `[A-Za-z0-9._-]{1,64}`, so the suffix keeps even
    // `.` and `..` from being path components.
    VPath::new(&format!(".veil/local/statcache/{ws}.cache")).expect("validated workspace name")
}

/// What a cached record can be compared against: everything `stat` tells us.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stamp {
    pub mtime: i64,
    pub ctime: Option<i64>,
    pub inode: Option<u64>,
    pub size: u64,
    pub executable: bool,
}

impl Stamp {
    /// `None` for directories and for backends without stamps.
    pub fn of(m: &Metadata) -> Option<Stamp> {
        if m.kind != NodeKind::File {
            return None;
        }
        Some(Stamp {
            mtime: m.mtime?,
            ctime: m.ctime,
            inode: m.inode,
            size: m.len,
            executable: m.executable,
        })
    }

    fn latest(&self) -> i64 {
        self.ctime.map_or(self.mtime, |c| c.max(self.mtime))
    }

    fn whole_seconds(&self) -> bool {
        self.mtime % 1_000_000_000 == 0 && !matches!(self.ctime, Some(c) if c % 1_000_000_000 != 0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub stamp: Stamp,
    /// Clock reading taken before `stamp` was observed and the file read.
    pub verified_at: i64,
    /// Blob id of the plaintext content.
    pub content: ObjectId,
    /// The secret scanner ran on `content` and found nothing.
    pub scanned_clean: bool,
    /// `(scope, id)`: `content` sealed under `scope` is object `id`.
    pub sealed: Option<(String, ObjectId)>,
}

impl Record {
    /// Can this record vouch for a file currently stat'ing as `stamp`?
    fn vouches_for(&self, stamp: &Stamp, exact: bool) -> bool {
        if self.stamp != *stamp {
            return false;
        }
        let latest = self.stamp.latest();
        if exact {
            return latest <= self.verified_at;
        }
        let window = if self.stamp.whole_seconds() {
            COARSE_WINDOW_NS
        } else {
            FINE_WINDOW_NS
        };
        latest.saturating_add(window) <= self.verified_at
    }

    /// Facts about the same content accumulate across runs.
    fn absorb(&mut self, old: &Record) {
        if old.content != self.content {
            return;
        }
        self.scanned_clean |= old.scanned_clean;
        if self.sealed.is_none() {
            self.sealed = old.sealed.clone();
        }
    }
}

/// What the whole cache is only valid for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheKey {
    /// Blob id of `.veilpolicy`, `None` if there is none.
    pub policy: Option<ObjectId>,
    /// Fingerprint of identity, scope keys and embargo states.
    pub keys: ObjectId,
    /// Kind of clock the stamps were taken on.
    pub exact: bool,
}

impl CacheKey {
    pub fn compute(fs: &dyn StorageBackend, keys: &Keychain, clock: StatClock) -> Result<CacheKey> {
        let policy = fs.read_opt(&VPath::new(POLICY_FILE)?)?.map(|b| Object::blob_id(&b));
        Ok(CacheKey {
            policy,
            keys: key_state(keys)?,
            exact: clock.exact,
        })
    }
}

/// Fingerprint of everything in the keychain that can change what a file's
/// tree entry looks like: who we are, which scope keys we hold (and which
/// key), and which embargoes exist, are released, or are readable.
pub fn key_state(keys: &Keychain) -> Result<ObjectId> {
    let mut h = blake3::Hasher::new();
    h.update(b"veil statcache key-state v1\0");
    // "Scanned clean" facts only hold for the scanner that produced them.
    h.update(&crate::secrets::RULES_VERSION.to_le_bytes());
    if let Some(id) = keys.identity() {
        h.update(id.public_hex().as_bytes());
    }
    h.update(b"\0rings\0");
    let mut rings = keys.rings()?;
    rings.sort_by(|a, b| a.scope.cmp(&b.scope));
    for r in rings {
        h.update(r.scope.as_bytes());
        h.update(b"=");
        h.update(
            keys.key(&r.scope)
                .map(|k| key_fingerprint(&k))
                .unwrap_or_default()
                .as_bytes(),
        );
        h.update(b"\0");
    }
    h.update(b"embargoes\0");
    for e in keys.embargoes()? {
        h.update(e.id.as_bytes());
        h.update(&[keys.embargo_released(&e.id) as u8, keys.has(&format!("embargo/{}", e.id)) as u8, 0]);
    }
    Ok(ObjectId(*h.finalize().as_bytes()))
}

/// A working copy's stat cache. See the module docs.
#[derive(Clone, Debug, Default)]
pub struct StatCache {
    key: Option<CacheKey>,
    records: HashMap<VPath, Record>,
    dirty: bool,
}

impl StatCache {
    pub fn new() -> StatCache {
        StatCache::default()
    }

    /// Load from `fs`. A missing, unreadable or corrupt cache is simply empty.
    pub fn load(fs: &dyn StorageBackend, path: &VPath) -> StatCache {
        match fs.read_opt(path) {
            Ok(Some(raw)) => decode(&raw).unwrap_or_default(),
            _ => StatCache::default(),
        }
    }

    /// Persist if anything changed since the last load or save.
    pub fn save(&mut self, fs: &dyn StorageBackend, path: &VPath) -> Result<()> {
        if self.dirty {
            fs.write(path, &encode(self))?;
            self.dirty = false;
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn key(&self) -> Option<&CacheKey> {
        self.key.as_ref()
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    pub fn get(&self, path: &VPath) -> Option<&Record> {
        self.records.get(path)
    }

    /// The record for `path` if it can vouch for a file stat'ing as `meta`.
    pub fn trusted(&self, path: &VPath, meta: &Metadata) -> Option<&Record> {
        let exact = self.key.as_ref()?.exact;
        let stamp = Stamp::of(meta)?;
        self.records.get(path).filter(|r| r.vouches_for(&stamp, exact))
    }

    /// Forget `path` and everything below it (called for every path a
    /// checkout writes or removes).
    pub fn invalidate(&mut self, path: &VPath) {
        let before = self.records.len();
        if path.is_root() {
            self.records.clear();
        } else {
            self.records.remove(path);
            let prefix = path.child_prefix();
            self.records.retain(|p, _| !p.as_str().starts_with(&prefix));
        }
        self.dirty |= self.records.len() != before;
    }

    pub fn clear(&mut self) {
        self.dirty |= !self.records.is_empty();
        self.records.clear();
    }

    /// Start a build: drop everything if the key changed, then hand the
    /// records to a [`CacheRun`]. Finish with [`StatCache::end_run`].
    pub(crate) fn begin_run(&mut self, key: CacheKey, clock: StatClock) -> CacheRun {
        if self.key.as_ref() != Some(&key) {
            self.records.clear();
            self.key = Some(key);
            self.dirty = true;
        }
        CacheRun {
            old: std::mem::take(&mut self.records),
            new: HashMap::new(),
            verified_at: clock.now,
            exact: clock.exact,
            changed: false,
        }
    }

    pub(crate) fn end_run(&mut self, run: CacheRun) {
        self.dirty |= run.changed || run.new.len() != run.old.len();
        self.records = run.new;
    }
}

/// One build's view of the cache: lookups go to the records from the last
/// run, and only paths seen in this run survive into the next one.
pub(crate) struct CacheRun {
    old: HashMap<VPath, Record>,
    new: HashMap<VPath, Record>,
    verified_at: i64,
    exact: bool,
    changed: bool,
}

impl CacheRun {
    /// The record for `path` if it can vouch for the file's current stat.
    pub(crate) fn trusted(&self, path: &VPath, meta: &Metadata) -> Option<&Record> {
        let stamp = Stamp::of(meta)?;
        self.old.get(path).filter(|r| r.vouches_for(&stamp, self.exact))
    }

    /// Carry a record that was just used for a hit into the next run.
    pub(crate) fn keep(&mut self, path: &VPath, rec: Record) {
        self.new.insert(path.clone(), rec);
    }

    /// Record facts learned by reading a file that stat'ed as `meta` (stat
    /// taken before the read).
    pub(crate) fn learn(
        &mut self,
        path: &VPath,
        meta: &Metadata,
        content: ObjectId,
        scanned_clean: bool,
        sealed: Option<(String, ObjectId)>,
    ) {
        let Some(stamp) = Stamp::of(meta) else { return };
        let mut rec = Record {
            stamp,
            verified_at: self.verified_at,
            content,
            scanned_clean,
            sealed,
        };
        if let Some(old) = self.old.get(path) {
            rec.absorb(old);
        }
        self.changed |= self.old.get(path) != Some(&rec);
        self.new.insert(path.clone(), rec);
    }
}

// ---- encoding --------------------------------------------------------------
//
// A small binary format: with ~20k entries JSON costs more to parse than the
// stat calls the cache saves. Integrity is checked with a trailing BLAKE3
// hash; any mismatch just yields an empty cache.

fn encode(c: &StatCache) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + c.records.len() * 128);
    out.extend_from_slice(MAGIC);
    put_u32(&mut out, VERSION);
    match &c.key {
        Some(k) => {
            out.push(1);
            put_opt_id(&mut out, k.policy.as_ref());
            out.extend_from_slice(&k.keys.0);
            out.push(k.exact as u8);
        }
        None => out.push(0),
    }
    let mut paths: Vec<&VPath> = c.records.keys().collect();
    paths.sort();
    put_u64(&mut out, paths.len() as u64);
    for p in paths {
        let r = &c.records[p];
        put_bytes(&mut out, p.as_str().as_bytes());
        put_i64(&mut out, r.stamp.mtime);
        put_opt_i64(&mut out, r.stamp.ctime);
        match r.stamp.inode {
            Some(i) => {
                out.push(1);
                put_u64(&mut out, i);
            }
            None => out.push(0),
        }
        put_u64(&mut out, r.stamp.size);
        out.push(r.stamp.executable as u8 | (r.scanned_clean as u8) << 1);
        put_i64(&mut out, r.verified_at);
        out.extend_from_slice(&r.content.0);
        match &r.sealed {
            Some((scope, id)) => {
                out.push(1);
                put_bytes(&mut out, scope.as_bytes());
                out.extend_from_slice(&id.0);
            }
            None => out.push(0),
        }
    }
    let sum = blake3::hash(&out);
    out.extend_from_slice(sum.as_bytes());
    out
}

fn decode(raw: &[u8]) -> Option<StatCache> {
    let (body, sum) = raw.split_at(raw.len().checked_sub(32)?);
    if blake3::hash(body).as_bytes() != sum {
        return None;
    }
    let mut r = Reader(body);
    if r.take(MAGIC.len())? != MAGIC || r.u32()? != VERSION {
        return None;
    }
    let key = match r.u8()? {
        0 => None,
        1 => Some(CacheKey {
            policy: r.opt_id()?,
            keys: r.id()?,
            exact: r.u8()? != 0,
        }),
        _ => return None,
    };
    let n = r.u64()?;
    let mut records = HashMap::with_capacity(n.min(1 << 20) as usize);
    for _ in 0..n {
        let path = VPath::new(std::str::from_utf8(r.bytes()?).ok()?).ok()?;
        let mtime = r.i64()?;
        let ctime = r.opt_i64()?;
        let inode = match r.u8()? {
            0 => None,
            1 => Some(r.u64()?),
            _ => return None,
        };
        let size = r.u64()?;
        let flags = r.u8()?;
        let verified_at = r.i64()?;
        let content = r.id()?;
        let sealed = match r.u8()? {
            0 => None,
            1 => Some((String::from_utf8(r.bytes()?.to_vec()).ok()?, r.id()?)),
            _ => return None,
        };
        let stamp = Stamp {
            mtime,
            ctime,
            inode,
            size,
            executable: flags & 1 != 0,
        };
        records.insert(
            path,
            Record {
                stamp,
                verified_at,
                content,
                scanned_clean: flags & 2 != 0,
                sealed,
            },
        );
    }
    if !r.0.is_empty() {
        return None;
    }
    Some(StatCache {
        key,
        records,
        dirty: false,
    })
}

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn put_i64(out: &mut Vec<u8>, v: i64) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn put_opt_i64(out: &mut Vec<u8>, v: Option<i64>) {
    match v {
        Some(v) => {
            out.push(1);
            put_i64(out, v);
        }
        None => out.push(0),
    }
}
fn put_opt_id(out: &mut Vec<u8>, v: Option<&ObjectId>) {
    match v {
        Some(id) => {
            out.push(1);
            out.extend_from_slice(&id.0);
        }
        None => out.push(0),
    }
}
fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    put_u32(out, b.len() as u32);
    out.extend_from_slice(b);
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Some(a)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
    fn i64(&mut self) -> Option<i64> {
        Some(i64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
    fn opt_i64(&mut self) -> Option<Option<i64>> {
        match self.u8()? {
            0 => Some(None),
            1 => Some(Some(self.i64()?)),
            _ => None,
        }
    }
    fn id(&mut self) -> Option<ObjectId> {
        Some(ObjectId(self.take(32)?.try_into().ok()?))
    }
    fn opt_id(&mut self) -> Option<Option<ObjectId>> {
        match self.u8()? {
            0 => Some(None),
            1 => Some(Some(self.id()?)),
            _ => None,
        }
    }
    fn bytes(&mut self) -> Option<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(mtime: i64, verified_at: i64) -> Record {
        Record {
            stamp: Stamp {
                mtime,
                ctime: Some(mtime),
                inode: Some(7),
                size: 3,
                executable: false,
            },
            verified_at,
            content: ObjectId::hash(b"x"),
            scanned_clean: true,
            sealed: Some(("team".into(), ObjectId::hash(b"y"))),
        }
    }

    #[test]
    fn racy_window_depends_on_stamp_precision() {
        let fine = 1_700_000_000_123_456_789;
        let r = rec(fine, fine + 50_000_000);
        assert!(!r.vouches_for(&r.stamp, false), "verified 50 ms after the write: racy");
        let r = rec(fine, fine + FINE_WINDOW_NS);
        assert!(r.vouches_for(&r.stamp, false));
        let coarse = 1_700_000_000_000_000_000;
        let r = rec(coarse, coarse + 1_500_000_000);
        assert!(!r.vouches_for(&r.stamp, false), "whole-second stamps get a 2 s window");
        let r = rec(coarse, coarse + COARSE_WINDOW_NS);
        assert!(r.vouches_for(&r.stamp, false));
        // Exact (generation) clocks have no window.
        let r = rec(10, 10);
        assert!(r.vouches_for(&r.stamp, true));
        let r = rec(11, 10);
        assert!(!r.vouches_for(&r.stamp, true));
        // Any stamp difference is a miss.
        let r = rec(fine, fine + COARSE_WINDOW_NS);
        let mut other = r.stamp.clone();
        other.inode = Some(8);
        assert!(!r.vouches_for(&other, false));
    }

    #[test]
    fn encoding_round_trips_and_rejects_corruption() {
        let mut c = StatCache {
            key: Some(CacheKey {
                policy: Some(ObjectId::hash(b"p")),
                keys: ObjectId::hash(b"k"),
                exact: false,
            }),
            ..Default::default()
        };
        c.records.insert(VPath::new("a/b.txt").unwrap(), rec(5, 9));
        let mut r2 = rec(6, 9);
        r2.sealed = None;
        r2.stamp.ctime = None;
        r2.stamp.inode = None;
        c.records.insert(VPath::new("c").unwrap(), r2);
        let raw = encode(&c);
        let back = decode(&raw).unwrap();
        assert_eq!(back.key, c.key);
        assert_eq!(back.records, c.records);
        let mut bad = raw.clone();
        bad[MAGIC.len() + 10] ^= 1;
        assert!(decode(&bad).is_none());
        assert!(decode(&raw[..raw.len() - 1]).is_none());
        assert!(decode(b"").is_none());
    }

    #[test]
    fn invalidate_removes_subtrees() {
        let mut c = StatCache::default();
        for p in ["a", "a/x", "a/y/z", "ab", "b"] {
            c.records.insert(VPath::new(p).unwrap(), rec(1, 2));
        }
        c.invalidate(&VPath::new("a").unwrap());
        let mut left: Vec<_> = c.records.keys().map(|p| p.to_string()).collect();
        left.sort();
        assert_eq!(left, vec!["ab", "b"]);
        assert!(c.dirty);
    }
}
