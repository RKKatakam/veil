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
//!   object `id`;
//! * `eol`: for content holding a CR, the line-ending facts
//!   (`.veilattributes`, see [`EolFact`]): a fingerprint of the attributes
//!   files in force when it was read, whether `vl renormalize` would record it otherwise, and the
//!   blob recorded for it when that is not the content itself (a file
//!   checkout wrote with CRLF for an LF version).
//!
//! Records hold facts, not policy decisions. The builder still classifies
//! every path against the current policy on every run and only uses a fact
//! where it would otherwise have needed the bytes. As a second line of
//! defence the whole cache is keyed on the `.veilpolicy` content id and on a
//! fingerprint of the key state, and it is dropped when either
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

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, OnceLock},
};

use crate::{
    error::Result,
    id::ObjectId,
    keychain::{key_fingerprint, Keychain},
    object::Object,
    policy::{PolicyFile, POLICY_FILE},
    vfs::{Metadata, NodeKind, StatClock, StorageBackend},
    vpath::VPath,
};

const MAGIC: &[u8] = b"veil:statcache\n";
const VERSION: u32 = 2;
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

    /// The earliest clock reading at which a record of a file stat'ing
    /// as this, verified then, is trusted (see the racy-mtime rule in the
    /// module documentation).
    pub fn trusted_from(&self, exact: bool) -> i64 {
        let window = match (exact, self.whole_seconds()) {
            (true, _) => 0,
            (false, true) => COARSE_WINDOW_NS,
            (false, false) => FINE_WINDOW_NS,
        };
        self.latest().saturating_add(window)
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
    /// `(scope, id)`: the recorded version of `content` sealed under
    /// `scope` is object `id`.
    pub sealed: Option<(String, ObjectId)>,
    /// Line-ending facts, for content that holds a CR (`None`: it holds
    /// none, so no attribute can change how it is recorded).
    pub eol: Option<EolFact>,
}

/// What `.veilattributes` made of a file's content when it was read (see
/// [`crate::attributes`]). Only valid for the parent entry it was learned
/// against: the builder trusts such a record only where the parent entry
/// is still the recorded version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EolFact {
    /// The attributes in force ([`crate::attributes::Attrs::fingerprint`]
    /// of the files the path is under).
    pub attributes: crate::attributes::Fingerprint,
    /// `vl renormalize` would record other bytes.
    pub renormalize: bool,
    /// The blob recorded for this content when it is not `content` itself
    /// (checkout wrote it with CRLF, or it was normalised).
    pub recorded: Option<ObjectId>,
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
        if old.eol != self.eol {
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
    /// Fingerprint of identity and scope keys.
    pub keys: ObjectId,
    /// Kind of clock the stamps were taken on.
    pub exact: bool,
}

impl CacheKey {
    pub fn compute(fs: &dyn StorageBackend, keys: &Keychain, clock: StatClock) -> Result<CacheKey> {
        let policy = match crate::policy::read_policy_file(fs)? {
            PolicyFile::File(b) | PolicyFile::Linked(b) => Some(Object::blob_id(&b)),
            PolicyFile::Absent => None,
            PolicyFile::Unavailable(why) => Some(Object::blob_id(format!("\0unreadable {POLICY_FILE}: {why}").as_bytes())),
        };
        Ok(CacheKey {
            policy,
            keys: key_state(keys)?,
            exact: clock.exact,
        })
    }
}

/// Fingerprint of everything in the keychain that can change what a file's
/// tree entry looks like: who we are, which scope keys we hold (and which
/// key).
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
    Ok(ObjectId(*h.finalize().as_bytes()))
}

/// A working copy's stat cache. See the module docs.
///
/// A loaded cache keeps its records encoded until something needs them
/// all: a build the file watcher narrows decodes only the directories it
/// inspects (`StatCache::begin_watched_run`), and a command that records
/// nothing new decodes none. (Decoding 35,000 records
/// is 10 ms, and dropping them 4 ms, of every command; BUG-1944.)
#[derive(Clone, Debug, Default)]
pub struct StatCache {
    key: Option<CacheKey>,
    /// Every record, decoded from `loaded` when first needed.
    records: OnceLock<HashMap<VPath, Record>>,
    /// The cache file's records, not decoded yet (`records` is unset), with
    /// what watched builds found since.
    loaded: Option<Loaded>,
    dirty: bool,
}

/// The records of a cache file, encoded. Its header (the key) is read at
/// load; its checksum, which covers the whole file, is verified before
/// any record is decoded (`Loaded::intact`), so a command that decodes
/// none (the file watcher vouching that nothing changed) never hashes it
/// (BUG-1944). Records of a file that fails it are no records.
#[derive(Clone, Debug)]
struct Loaded {
    file: Arc<Vec<u8>>,
    /// The checksum's verdict, once verified (shared by clones).
    intact: Arc<OnceLock<bool>>,
    /// Where the first record starts in `file` (the last ends at its
    /// checksum).
    start: usize,
    count: u64,
    /// What watched builds that left the cache as it is on disk replaced,
    /// oldest first: applied when the records are decoded.
    patches: Vec<Patch>,
}

impl Loaded {
    fn encoded(&self) -> &[u8] {
        &self.file[self.start..self.file.len() - 32]
    }

    /// Does the file's checksum hold? Verified once, before the first
    /// record is decoded.
    fn intact(&self) -> bool {
        *self.intact.get_or_init(|| {
            let (body, sum) = self.file.split_at(self.file.len() - 32);
            blake3::hash(body).as_bytes() == sum
        })
    }

    /// Every record, as the builds since the load left them. Records that
    /// do not decode, or of a file whose checksum fails, are no records:
    /// an empty cache.
    fn decode(&self) -> HashMap<VPath, Record> {
        let mut records = match self.intact() {
            true => decode_records(self.encoded(), self.count, None).unwrap_or_default(),
            false => HashMap::new(),
        };
        for p in &self.patches {
            p.apply(&mut records);
        }
        records
    }
}

/// What one watched build ([`StatCache::begin_watched_run`]) found: the
/// records of the directories it listed, and of the directories that are
/// gone, are replaced by `new`.
#[derive(Clone, Debug)]
struct Patch {
    visited: HashSet<VPath>,
    deleted: Vec<VPath>,
    new: HashMap<VPath, Record>,
}

impl Patch {
    fn apply(&self, records: &mut HashMap<VPath, Record>) {
        let visited: HashSet<&str> = self.visited.iter().map(VPath::as_str).collect();
        records.retain(|path, _| kept_by_watched_run(path.as_str(), &visited, &self.deleted));
        records.extend(self.new.iter().map(|(p, r)| (p.clone(), r.clone())));
    }
}

/// The directory of `path`, as text (the root: empty).
fn dir_of(path: &str) -> &str {
    path.rfind('/').map_or("", |i| &path[..i])
}

/// [`VPath::starts_with`], on text.
fn below(path: &str, prefix: &str) -> bool {
    prefix.is_empty() || path == prefix || (path.len() > prefix.len() && path.starts_with(prefix) && path.as_bytes()[prefix.len()] == b'/')
}

/// Does a watched build that listed the directories `visited` and found
/// the directories `deleted` gone keep the last run's record for `path`?
/// (Not one in a directory it listed: those it carried over itself.)
fn kept_by_watched_run(path: &str, visited: &HashSet<&str>, deleted: &[VPath]) -> bool {
    !visited.contains(dir_of(path)) && !deleted.iter().any(|p| below(path, p.as_str()))
}

/// The records a watched build looks up: of the files directly in `dirs`,
/// and of everything below `subtrees` (`WatchPlan::inspect_leaves`).
pub(crate) struct Lookups<'a> {
    pub(crate) dirs: HashSet<&'a str>,
    pub(crate) subtrees: Vec<&'a str>,
}

impl Lookups<'_> {
    fn is_empty(&self) -> bool {
        self.dirs.is_empty() && self.subtrees.is_empty()
    }

    fn covers(&self, path: &str) -> bool {
        let dir = dir_of(path);
        self.dirs.contains(dir) || self.subtrees.iter().any(|s| below(dir, s))
    }
}

impl StatCache {
    pub fn new() -> StatCache {
        StatCache::default()
    }

    /// Load from `fs`. A missing, unreadable or corrupt cache is simply empty.
    pub fn load(fs: &dyn StorageBackend, path: &VPath) -> StatCache {
        match fs.read_opt(path) {
            Ok(Some(raw)) => decode(raw).unwrap_or_default(),
            _ => StatCache::default(),
        }
    }

    /// Every record (decoded now, if the cache was loaded and nothing
    /// needed them all yet).
    fn all(&self) -> &HashMap<VPath, Record> {
        self.records.get_or_init(|| self.loaded.as_ref().map(Loaded::decode).unwrap_or_default())
    }

    fn all_mut(&mut self) -> &mut HashMap<VPath, Record> {
        self.all();
        self.loaded = None;
        self.records.get_mut().expect("decoded by `all`")
    }

    /// Forget every record, decoding none.
    fn drop_all(&mut self) {
        self.loaded = None;
        self.records = OnceLock::new();
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
        self.all().len()
    }

    pub fn is_empty(&self) -> bool {
        self.all().is_empty()
    }

    pub fn key(&self) -> Option<&CacheKey> {
        self.key.as_ref()
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    pub fn get(&self, path: &VPath) -> Option<&Record> {
        self.all().get(path)
    }

    /// The record for `path` if it can vouch for a file stat'ing as `meta`.
    pub fn trusted(&self, path: &VPath, meta: &Metadata) -> Option<&Record> {
        let exact = self.key.as_ref()?.exact;
        let stamp = Stamp::of(meta)?;
        self.all().get(path).filter(|r| r.vouches_for(&stamp, exact))
    }

    /// Forget `path` and everything below it (called for every path a
    /// checkout writes or removes).
    pub fn invalidate(&mut self, path: &VPath) {
        let records = self.all_mut();
        let before = records.len();
        if path.is_root() {
            records.clear();
        } else {
            records.remove(path);
            let prefix = path.child_prefix();
            records.retain(|p, _| !p.as_str().starts_with(&prefix));
        }
        self.dirty |= self.all().len() != before;
    }

    /// Every record, in no particular order.
    pub fn records(&self) -> impl Iterator<Item = (&VPath, &Record)> {
        self.all().iter()
    }

    /// Vouch for files whose content the caller knows without reading them
    /// (a sandbox's checkout just wrote them, and nothing else can have
    /// written them since). Each record must be one the racy-mtime rule
    /// trusts at once: its `verified_at` a clock reading taken after
    /// [`Stamp::trusted_from`] and before the file was stat'ed as `stamp`.
    /// Records kept under another key are dropped first, as at the start
    /// of a build.
    pub fn vouch(&mut self, key: CacheKey, records: impl IntoIterator<Item = (VPath, Record)>) {
        if self.key.as_ref() != Some(&key) {
            self.drop_all();
            self.key = Some(key);
        }
        let exact = self.key.as_ref().is_some_and(|k| k.exact);
        let all = self.all_mut();
        for (path, rec) in records {
            if rec.vouches_for(&rec.stamp, exact) {
                all.insert(path, rec);
            }
        }
        self.dirty = true;
    }

    pub fn clear(&mut self) {
        self.dirty |= !self.all().is_empty();
        self.drop_all();
    }

    /// Start a build: drop everything if the key changed, then hand the
    /// records to a [`CacheRun`]. Finish with [`StatCache::end_run`].
    pub(crate) fn begin_run(&mut self, key: CacheKey, clock: StatClock) -> CacheRun {
        let key_changed = self.key.as_ref() != Some(&key);
        if key_changed {
            self.drop_all();
            self.key = Some(key);
            self.dirty = true;
        }
        let old = std::mem::take(self.all_mut());
        CacheRun {
            new: HashMap::new(),
            old_len: old.len(),
            old,
            verified_at: clock.now,
            exact: clock.exact,
            changed: false,
            visited_dirs: None,
            encoded: None,
        }
    }

    /// [`StatCache::begin_run`] for a build the file watcher narrows to
    /// `lookups`, under an unchanged `key`: only the directories the build
    /// lists are replaced at [`StatCache::end_run`], the records of every
    /// other stay. When the cache is as it was loaded, only the records
    /// the build can look up are decoded, and the others stay encoded
    /// unless the build ends with something to save.
    pub(crate) fn begin_watched_run(&mut self, key: CacheKey, clock: StatClock, lookups: &Lookups<'_>) -> CacheRun {
        let narrowed = match &self.loaded {
            Some(l) if self.records.get().is_none() && l.patches.is_empty() && self.key.as_ref() == Some(&key) => match lookups.is_empty() {
                true => Some((HashMap::new(), l.count as usize)),
                false if !l.intact() => None,
                false => decode_records(l.encoded(), l.count, Some(lookups)).map(|m| (m, l.count as usize)),
            },
            _ => None,
        };
        let Some((old, old_len)) = narrowed else {
            let mut run = self.begin_run(key, clock);
            run.visited_dirs = Some(Default::default());
            return run;
        };
        CacheRun {
            new: HashMap::new(),
            old_len,
            encoded: Some(old.keys().cloned().collect()),
            old,
            verified_at: clock.now,
            exact: clock.exact,
            changed: false,
            visited_dirs: Some(Default::default()),
        }
    }

    pub(crate) fn end_run(&mut self, mut run: CacheRun) {
        if let Some((visited, deleted)) = run.visited_dirs.take() {
            let untouched = visited.is_empty() && deleted.is_empty() && run.new.is_empty() && !run.changed;
            if let Some(decoded) = run.encoded.take() {
                // The other records are still encoded (`self.loaded`).
                if untouched {
                    return;
                }
                // How many records the run leaves: those it decoded are all
                // the cache holds for the directories it listed. A
                // directory that is gone may hold others: counted below.
                let names: HashSet<&str> = visited.iter().map(VPath::as_str).collect();
                let replaced = decoded.iter().filter(|p| !kept_by_watched_run(p.as_str(), &names, &deleted)).count();
                let same = !run.changed && deleted.is_empty() && run.old_len - replaced + run.new.len() == run.old_len;
                let patch = Patch { visited, deleted, new: run.new };
                match (&mut self.loaded, same) {
                    // Nothing to save: the file stays the cache, with what
                    // this run found for this process.
                    (Some(l), true) => l.patches.push(patch),
                    _ => {
                        let records = self.all_mut();
                        patch.apply(records);
                        self.dirty |= run.changed || self.all().len() != run.old_len;
                    }
                }
                return;
            }
            if untouched {
                self.records = OnceLock::from(run.old);
                return;
            }
            let names: HashSet<&str> = visited.iter().map(VPath::as_str).collect();
            run.old.retain(|path, _| kept_by_watched_run(path.as_str(), &names, &deleted));
            run.old.extend(run.new);
            self.dirty |= run.changed || run.old.len() != run.old_len;
            self.records = OnceLock::from(run.old);
            return;
        }
        self.dirty |= run.changed || run.new.len() != run.old_len;
        self.records = OnceLock::from(run.new);
    }
}

/// One build's view of the cache: lookups go to the records from the last
/// run, and only paths seen in this run survive into the next one.
pub(crate) struct CacheRun {
    /// The last run's records not yet used by this one.
    old: HashMap<VPath, Record>,
    /// How many records the last run left.
    old_len: usize,
    new: HashMap<VPath, Record>,
    verified_at: i64,
    exact: bool,
    changed: bool,
    /// When set (a watched partial build): the directories actually listed
    /// during this run, and the directory prefixes deleted from the tree.
    /// Records in `old` outside these directories are kept untouched.
    pub(crate) visited_dirs: Option<(std::collections::HashSet<VPath>, Vec<VPath>)>,
    /// A watched build on a cache still encoded
    /// ([`StatCache::begin_watched_run`]): the paths whose records were
    /// decoded into `old` (all it holds for the directories the build can
    /// list).
    encoded: Option<Vec<VPath>>,
}

impl CacheRun {
    /// How many records the last run left (about the working copy's files).
    #[cfg(feature = "os")]
    pub(crate) fn len(&self) -> usize {
        self.old_len
    }

    pub(crate) fn note_visited_dir(&mut self, dir: &VPath) {
        if let Some((visited, _)) = &mut self.visited_dirs {
            visited.insert(dir.clone());
        }
    }

    pub(crate) fn note_deleted_dir(&mut self, dir: VPath) {
        if let Some((_, deleted)) = &mut self.visited_dirs {
            deleted.push(dir);
        }
    }

    /// For a subtree built on another thread (a full scan's, see
    /// `builder::Ahead`): runs of their own, one per subtree whose `n`th
    /// path component (`n` from 1) is the key of `subtrees`, holding the
    /// last run's records below it, moved out of this one.
    #[cfg_attr(not(feature = "os"), allow(dead_code))]
    pub(crate) fn split_below(&mut self, depth: usize, subtrees: &HashMap<VPath, usize>, count: usize) -> Vec<CacheRun> {
        let mut runs: Vec<CacheRun> = (0..count).map(|_| self.empty_like()).collect();
        let by_name: HashMap<&str, usize> = subtrees.iter().map(|(p, &i)| (p.as_str(), i)).collect();
        let task_of = |path: &VPath| {
            let s = path.as_str();
            let cut = s.match_indices('/').nth(depth - 1).map(|(i, _)| i)?;
            by_name.get(&s[..cut]).copied()
        };
        for (path, rec) in self.old.extract_if(|path, _| task_of(path).is_some()) {
            let t = task_of(&path).expect("taken for its subtree");
            runs[t].old.insert(path, rec);
        }
        for r in &mut runs {
            r.old_len = r.old.len();
        }
        runs
    }

    #[cfg_attr(not(feature = "os"), allow(dead_code))]
    fn empty_like(&self) -> CacheRun {
        CacheRun {
            old: HashMap::new(),
            old_len: 0,
            new: HashMap::new(),
            verified_at: self.verified_at,
            exact: self.exact,
            changed: false,
            visited_dirs: None,
            encoded: None,
        }
    }

    /// What a subtree's run (`split_below`) learnt, as this run would have
    /// learnt it building the subtree itself: what it carries to the next
    /// run, and whether that changed. The last run's records it did not
    /// use are dropped, as this run drops those of paths it never saw.
    pub(crate) fn absorb(&mut self, sub: CacheRun) {
        self.new.extend(sub.new);
        self.changed |= sub.changed;
    }

    /// A subtree's run (`split_below`) whose build is not used: its records
    /// back, for this run to build the subtree itself.
    pub(crate) fn give_back_run(&mut self, sub: CacheRun) {
        self.old.extend(sub.old);
        self.old.extend(sub.new);
    }

    /// [`CacheRun::trusted`], moved out of the last run's records: carried
    /// into the next run with [`CacheRun::keep_taken`] once used, or given
    /// back with [`CacheRun::give_back`] (no copy of the path or the record).
    pub(crate) fn take_trusted(&mut self, path: &VPath, meta: &Metadata) -> Option<(VPath, Record)> {
        let stamp = Stamp::of(meta)?;
        let (path, rec) = self.old.remove_entry(path)?;
        if rec.vouches_for(&stamp, self.exact) {
            return Some((path, rec));
        }
        self.old.insert(path, rec);
        None
    }

    /// Carry a record taken by [`CacheRun::take_trusted`] into the next run.
    pub(crate) fn keep_taken(&mut self, path: VPath, rec: Record) {
        self.new.insert(path, rec);
    }

    /// A record taken by [`CacheRun::take_trusted`] and not used.
    pub(crate) fn give_back(&mut self, path: VPath, rec: Record) {
        self.old.insert(path, rec);
    }

    /// The record for `path` if it can vouch for the file's current stat.
    pub(crate) fn trusted(&self, path: &VPath, meta: &Metadata) -> Option<&Record> {
        let stamp = Stamp::of(meta)?;
        self.old.get(path).filter(|r| r.vouches_for(&stamp, self.exact))
    }

    /// Carry a record that was just used for a hit into the next run.
    pub(crate) fn keep(&mut self, path: &VPath, rec: Record) {
        self.new.insert(path.clone(), rec);
    }

    /// Drop what this run learnt about `path` (the builder recorded it
    /// otherwise than the facts say, e.g. sealed after a move).
    pub(crate) fn forget(&mut self, path: &VPath) {
        self.changed |= self.new.remove(path).is_some();
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
        eol: Option<EolFact>,
    ) {
        let Some(stamp) = Stamp::of(meta) else { return };
        let mut rec = Record {
            stamp,
            verified_at: self.verified_at,
            content,
            scanned_clean,
            sealed,
            eol,
        };
        if let Some(old) = self.old.get(path) {
            rec.absorb(old);
        }
        // A record verified within the racy window of the file's last
        // change (a file edited just before the command, as in every `vl
        // commit` right after an edit) can never vouch for it: both
        // stamps are fixed. It is kept for this run, but is no reason to
        // rewrite the whole cache (a 1 MB fsynced write at 10,000 files);
        // the next run reads the file again either way.
        let useful = rec.vouches_for(&rec.stamp, self.exact);
        self.changed |= useful && self.old.get(path) != Some(&rec);
        self.new.insert(path.clone(), rec);
    }
}

// ---- encoding --------------------------------------------------------------
//
// A small binary format: with ~20k entries JSON costs more to parse than the
// stat calls the cache saves. Integrity is checked with a trailing BLAKE3
// hash; any mismatch just yields an empty cache.

fn encode(c: &StatCache) -> Vec<u8> {
    let records = c.all();
    let mut out = Vec::with_capacity(64 + records.len() * 128);
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
    let mut paths: Vec<&VPath> = records.keys().collect();
    paths.sort();
    put_u64(&mut out, paths.len() as u64);
    for p in paths {
        let r = &records[p];
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
        match &r.eol {
            Some(f) => {
                out.push(1 | (f.renormalize as u8) << 1 | (f.recorded.is_some() as u8) << 2);
                out.extend_from_slice(&f.attributes);
                if let Some(id) = &f.recorded {
                    out.extend_from_slice(&id.0);
                }
            }
            None => out.push(0),
        }
    }
    let sum = blake3::hash(&out);
    out.extend_from_slice(sum.as_bytes());
    out
}

/// The cache in file `raw`: its checksum, header and key are checked now,
/// its records when they are decoded ([`Loaded::decode`]).
fn decode(raw: Vec<u8>) -> Option<StatCache> {
    // The checksum is verified before any record is read (`Loaded::intact`).
    let (body, _) = raw.split_at(raw.len().checked_sub(32)?);
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
    let count = r.u64()?;
    let start = body.len() - r.0.len();
    Some(StatCache {
        key,
        records: OnceLock::new(),
        loaded: Some(Loaded {
            file: Arc::new(raw),
            intact: Arc::default(),
            start,
            count,
            patches: Vec::new(),
        }),
        dirty: false,
    })
}

/// The `n` records encoded in `raw`: all of them, or those `only` covers
/// (the others are checked for their shape, and skipped). `None` if they
/// are not `n` well-formed records and nothing else.
fn decode_records(raw: &[u8], n: u64, only: Option<&Lookups<'_>>) -> Option<HashMap<VPath, Record>> {
    let mut r = Reader(raw);
    let mut records = HashMap::with_capacity(if only.is_some() { 0 } else { n.min(1 << 20) as usize });
    for _ in 0..n {
        let path = std::str::from_utf8(r.bytes()?).ok()?;
        let wanted = only.is_none_or(|l| l.covers(path));
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
        let eol = match r.u8()? {
            0 => None,
            f if f & !7 == 0 && f & 1 == 1 => {
                let attributes: crate::attributes::Fingerprint = r.take(16)?.try_into().ok()?;
                let recorded = if f & 4 != 0 { Some(r.id()?) } else { None };
                Some(EolFact {
                    attributes,
                    renormalize: f & 2 != 0,
                    recorded,
                })
            }
            _ => return None,
        };
        let stamp = Stamp {
            mtime,
            ctime,
            inode,
            size,
            executable: flags & 1 != 0,
        };
        if !wanted {
            continue;
        }
        records.insert(
            VPath::new(path).ok()?,
            Record {
                stamp,
                verified_at,
                content,
                scanned_clean: flags & 2 != 0,
                sealed,
                eol,
            },
        );
    }
    if !r.0.is_empty() {
        return None;
    }
    Some(records)
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
            eol: None,
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
        c.all_mut().insert(VPath::new("a/b.txt").unwrap(), rec(5, 9));
        let mut r2 = rec(6, 9);
        r2.sealed = None;
        r2.stamp.ctime = None;
        r2.stamp.inode = None;
        c.all_mut().insert(VPath::new("c").unwrap(), r2);
        let mut r3 = rec(7, 9);
        r3.eol = Some(EolFact {
            attributes: [2; 16],
            renormalize: true,
            recorded: Some(ObjectId::hash(b"lf")),
        });
        c.all_mut().insert(VPath::new("d.bat").unwrap(), r3);
        let mut r4 = rec(8, 9);
        r4.eol = Some(EolFact {
            attributes: [0; 16],
            renormalize: false,
            recorded: None,
        });
        c.all_mut().insert(VPath::new("e.png").unwrap(), r4);
        let raw = encode(&c);
        let back = decode(raw.clone()).unwrap();
        assert_eq!(back.key, c.key);
        // Decoded when first needed, not when the file is read.
        assert!(back.records.get().is_none());
        assert_eq!(back.all(), c.all());
        assert_eq!(back.len(), 4);
        // A flipped bit anywhere is no records: a cache refused at load
        // (its header), or one whose checksum fails when its records are
        // first needed.
        for at in [MAGIC.len() + 10, raw.len() / 2, raw.len() - 40, raw.len() - 1] {
            let mut bad = raw.clone();
            bad[at] ^= 1;
            assert!(decode(bad).is_none_or(|c| c.is_empty()), "byte {at}");
        }
        assert!(decode(raw[..raw.len() - 1].to_vec()).is_none_or(|c| c.is_empty()));
        assert!(decode(Vec::new()).is_none());
    }

    /// A file whose checksum holds but whose records are not records (only
    /// a writer of `.veil/local` makes one): an empty cache under its key,
    /// for a full build and for a watched one.
    #[test]
    fn records_that_do_not_decode_are_no_records() {
        let c = sample();
        let raw = encode(&c);
        // The count says one record more than there are.
        let at = MAGIC.len() + 4 + 1 + 1 + 32 + 32 + 1;
        let mut body = raw[..raw.len() - 32].to_vec();
        let n = u64::from_le_bytes(body[at..at + 8].try_into().unwrap());
        assert_eq!(n, c.len() as u64, "the count is where this test expects it");
        body[at..at + 8].copy_from_slice(&(n + 1).to_le_bytes());
        let sum = blake3::hash(&body);
        body.extend_from_slice(sum.as_bytes());
        let back = decode(body.clone()).unwrap();
        assert_eq!(back.key, c.key);
        assert!(back.is_empty());
        let mut back = decode(body).unwrap();
        let lookups = Lookups { dirs: HashSet::from(["a"]), subtrees: vec![] };
        let run = back.begin_watched_run(c.key.clone().unwrap(), CLOCK, &lookups);
        assert!(run.old.is_empty());
        back.end_run(run);
        assert!(back.is_empty());
    }

    /// The checksum covers the whole file and is verified before any
    /// record is decoded, never skipped: a watched build that looks up
    /// nothing never hashes the file, one that looks up a directory of a
    /// file whose records were corrupted (the checksum fails) finds no
    /// records, and so do a full build and a save (BUG-1944).
    #[test]
    fn the_checksum_is_verified_before_the_first_record_is_read() {
        let c = sample();
        let raw = encode(&c);
        // Nothing looked up: nothing hashed, nothing decoded, nothing to save.
        let mut back = decode(raw.clone()).unwrap();
        let run = back.begin_watched_run(c.key.clone().unwrap(), CLOCK, &Lookups { dirs: HashSet::new(), subtrees: vec![] });
        back.end_run(run);
        assert!(back.loaded.as_ref().unwrap().intact.get().is_none(), "the file was hashed for a build that read no record");
        assert!(!back.dirty);
        // A record's byte flipped, the header intact: the key loads, the
        // records do not.
        let mut bad = raw.clone();
        bad[raw.len() - 40] ^= 1;
        let lookups = Lookups { dirs: HashSet::from(["a"]), subtrees: vec![] };
        let mut back = decode(bad.clone()).unwrap();
        assert_eq!(back.key, c.key);
        let run = back.begin_watched_run(c.key.clone().unwrap(), CLOCK, &lookups);
        assert!(run.old.is_empty(), "a watched run read records of a file whose checksum fails");
        back.end_run(run);
        assert!(back.is_empty());
        assert!(decode(bad.clone()).unwrap().get(&vp("a/x")).is_none());
        let mut back = decode(bad).unwrap();
        let run = back.begin_run(c.key.clone().unwrap(), CLOCK);
        assert!(run.old.is_empty(), "a full run read records of a file whose checksum fails");
        back.end_run(run);
        assert!(decode(encode(&back)).unwrap().is_empty());
        // Intact: the same lookups find the records.
        let mut back = decode(raw).unwrap();
        let run = back.begin_watched_run(c.key.clone().unwrap(), CLOCK, &lookups);
        assert_eq!(run.old.len(), 2);
        back.end_run(run);
        assert_eq!(back.loaded.as_ref().map(|l| l.intact.get().copied()), Some(Some(true)));
    }

    const CLOCK: StatClock = StatClock { now: 9, exact: false };

    /// Records in the root, in `a`, below it, beside it (`ab`), and in `b`.
    fn sample() -> StatCache {
        let mut c = StatCache {
            key: Some(CacheKey {
                policy: Some(ObjectId::hash(b"p")),
                keys: ObjectId::hash(b"k"),
                exact: false,
            }),
            ..Default::default()
        };
        for (i, p) in ["top", "a/x", "a/y", "a/s/t", "a/s/u/v", "ab/x", "b/z", "b/c/w"].into_iter().enumerate() {
            c.all_mut().insert(VPath::new(p).unwrap(), rec(i as i64, 9));
        }
        c
    }

    fn vp(s: &str) -> VPath {
        VPath::new(s).unwrap()
    }

    #[test]
    fn lookups_cover_the_files_of_their_directories_and_everything_below_their_subtrees() {
        let l = Lookups { dirs: HashSet::from(["a", ""]), subtrees: vec!["b/c"] };
        for (path, covered) in [
            ("top", true),
            ("a/x", true),
            ("a/s/t", false),
            ("ab/x", false),
            ("b/z", false),
            ("b/c/w", true),
            ("b/c/d/e", true),
            ("b/cd/e", false),
        ] {
            assert_eq!(l.covers(path), covered, "{path}");
        }
        let all = Lookups { dirs: HashSet::new(), subtrees: vec![""] };
        assert!(all.covers("top") && all.covers("a/s/t"));
        assert!(!Lookups { dirs: HashSet::new(), subtrees: vec![] }.covers("top"));
    }

    /// A watched build on a cache as loaded (its records encoded, only
    /// those it can look up decoded) ends exactly as on a cache whose
    /// records were all decoded first: the same records, and the same
    /// answer to "is there something to save".
    #[test]
    fn a_watched_run_on_a_loaded_cache_ends_as_one_on_decoded_records() {
        type Script = fn(&mut CacheRun);
        // Each build does what the builder does in a directory it lists:
        // notes it, takes the records it trusts and carries them over,
        // learns the others.
        let scripts: Vec<(&str, Lookups<'static>, Script, bool, bool)> = vec![
            // name, what the plan inspects, the build, something to save?, still encoded after?
            ("nothing changed anywhere", Lookups { dirs: HashSet::new(), subtrees: vec![] }, |_| {}, false, true),
            (
                "a directory listed, every record carried over",
                Lookups { dirs: HashSet::from(["a"]), subtrees: vec![] },
                |run| {
                    run.note_visited_dir(&vp("a"));
                    for p in ["a/x", "a/y"] {
                        let (path, kept) = run.old.remove_entry(&vp(p)).unwrap();
                        run.keep_taken(path, kept);
                    }
                },
                false,
                true,
            ),
            (
                "a record replaced by one that is not worth a save (a file edited just before the commit)",
                Lookups { dirs: HashSet::from(["a"]), subtrees: vec![] },
                |run| {
                    run.note_visited_dir(&vp("a"));
                    let (path, kept) = run.old.remove_entry(&vp("a/x")).unwrap();
                    run.keep_taken(path, kept);
                    // `a/y` read again: its old record stays behind in `old`.
                    run.new.insert(vp("a/y"), rec(77, 9));
                },
                false,
                true,
            ),
            (
                "a record learnt that is worth a save",
                Lookups { dirs: HashSet::from(["a"]), subtrees: vec![] },
                |run| {
                    run.note_visited_dir(&vp("a"));
                    let (path, kept) = run.old.remove_entry(&vp("a/x")).unwrap();
                    run.keep_taken(path, kept);
                    run.new.insert(vp("a/y"), rec(78, 9));
                    run.changed = true;
                },
                true,
                false,
            ),
            (
                "a file gone from a listed directory",
                Lookups { dirs: HashSet::from(["a"]), subtrees: vec![] },
                |run| {
                    run.note_visited_dir(&vp("a"));
                    let (path, kept) = run.old.remove_entry(&vp("a/x")).unwrap();
                    run.keep_taken(path, kept);
                },
                true,
                false,
            ),
            (
                "a new file in the root",
                Lookups { dirs: HashSet::from([""]), subtrees: vec![] },
                |run| {
                    run.note_visited_dir(&VPath::root());
                    let (path, kept) = run.old.remove_entry(&vp("top")).unwrap();
                    run.keep_taken(path, kept);
                    run.new.insert(vp("new"), rec(79, 9));
                    run.changed = true;
                },
                true,
                false,
            ),
            (
                "a directory gone, with records the run never decoded below it",
                Lookups { dirs: HashSet::from([""]), subtrees: vec![] },
                |run| {
                    run.note_visited_dir(&VPath::root());
                    let (path, kept) = run.old.remove_entry(&vp("top")).unwrap();
                    run.keep_taken(path, kept);
                    run.note_deleted_dir(vp("b"));
                },
                true,
                false,
            ),
            (
                "a subtree walked whole",
                Lookups { dirs: HashSet::new(), subtrees: vec!["a"] },
                |run| {
                    for d in ["a", "a/s", "a/s/u"] {
                        run.note_visited_dir(&vp(d));
                    }
                    for p in ["a/x", "a/y", "a/s/t"] {
                        let (path, kept) = run.old.remove_entry(&vp(p)).unwrap();
                        run.keep_taken(path, kept);
                    }
                    run.new.insert(vp("a/s/u/v"), rec(80, 9));
                },
                false,
                true,
            ),
        ];
        for (name, lookups, script, saves, encoded_after) in scripts {
            let raw = encode(&sample());
            let key = sample().key.unwrap();
            // As loaded.
            let mut loaded = decode(raw.clone()).unwrap();
            let mut run = loaded.begin_watched_run(key.clone(), CLOCK, &lookups);
            assert!(run.encoded.is_some(), "{name}: the run decodes only what it looks up");
            assert!(run.old.keys().all(|p| lookups.covers(p.as_str())), "{name}");
            script(&mut run);
            loaded.end_run(run);
            assert_eq!(loaded.records.get().is_none(), encoded_after, "{name}: records still encoded after the run");
            // With every record decoded first.
            let mut decoded = decode(raw).unwrap();
            assert_eq!(decoded.len(), 8);
            let mut run = decoded.begin_watched_run(key, CLOCK, &lookups);
            assert!(run.encoded.is_none(), "{name}");
            script(&mut run);
            decoded.end_run(run);
            assert_eq!(loaded.dirty, saves, "{name}: something to save");
            assert_eq!(decoded.dirty, saves, "{name}: something to save (decoded first)");
            assert_eq!(loaded.all(), decoded.all(), "{name}");
            // And what is saved, or kept for the next build of this
            // process, reads back the same.
            assert_eq!(decode(encode(&loaded)).unwrap().all(), decoded.all(), "{name}");
            // A second watched build of the process sees what the first left.
            let mut again = loaded.clone();
            let run = again.begin_watched_run(sample().key.unwrap(), CLOCK, &Lookups { dirs: HashSet::from(["a"]), subtrees: vec![] });
            let seen: HashSet<&VPath> = run.old.keys().collect();
            let expect: HashSet<&VPath> = decoded.all().keys().filter(|p| run.encoded.is_none() || p.as_str().starts_with("a/") && !p.as_str()[2..].contains('/')).collect();
            assert_eq!(seen, expect, "{name}: a second build");
            again.end_run(run);
            assert_eq!(again.all(), decoded.all(), "{name}: after a second build that changed nothing");
        }
    }

    #[test]
    fn invalidate_removes_subtrees() {
        let mut c = StatCache::default();
        for p in ["a", "a/x", "a/y/z", "ab", "b"] {
            c.all_mut().insert(VPath::new(p).unwrap(), rec(1, 2));
        }
        c.invalidate(&VPath::new("a").unwrap());
        let mut left: Vec<_> = c.all().keys().map(|p| p.to_string()).collect();
        left.sort();
        assert_eq!(left, vec!["ab", "b"]);
        assert!(c.dirty);
    }
}
