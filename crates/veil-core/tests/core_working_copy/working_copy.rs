//! Working-copy behaviour: the stat cache, racy mtimes, and quarantined
//! edits (which must never be recorded as deletions or overwritten).

use std::sync::{
    atomic::{AtomicI64, Ordering},
    Arc,
};

use veil_core::{
    object::Visibility,
    statcache::StatCache,
    tree::lookup,
    vfs::{DirEntry, Metadata, StatClock},
    Identity, MemoryBackend, ObjectId, Repo, StorageBackend, TreeEntry, VPath,
};

const WS: &str = "default";

fn p(s: &str) -> VPath {
    VPath::new(s).unwrap()
}

/// A repository in memory, plus a separate working-copy backend.
fn repo_with<B: StorageBackend + 'static>(wc: B) -> (Repo, Arc<B>) {
    let repo = Repo::init(
        Arc::new(MemoryBackend::new()),
        Some(Identity::generate("alice")),
        "alice",
    )
    .unwrap();
    (repo, Arc::new(wc))
}

fn entry(repo: &Repo, tree: &ObjectId, path: &str) -> Option<TreeEntry> {
    lookup(repo.store(), tree, &p(path)).unwrap()
}

fn wc_tree(repo: &Repo) -> ObjectId {
    repo.snapshot(&repo.workspace_wc(WS).unwrap()).unwrap().tree
}

/// Snapshot `fs` into the default workspace through `cache`.
fn snap(repo: &mut Repo, fs: &dyn StorageBackend, cache: &mut StatCache) -> veil_core::builder::BuildReport {
    repo.snapshot_workspace_cached(WS, fs, Some(cache)).unwrap().report
}

/// A backend with *coarse, controllable* stamps over a `MemoryBackend`:
/// every file reports `mtime = tick` (whole seconds, no ctime, no inode),
/// and the stat clock reads `now`. This models a filesystem with 1 s
/// granularity, or one whose stamps lie.
#[derive(Debug, Default)]
struct CoarseStamps {
    inner: MemoryBackend,
    tick: AtomicI64,
    now: AtomicI64,
}

const SEC: i64 = 1_000_000_000;

impl CoarseStamps {
    fn at(&self, tick_s: i64, now_ns: i64) {
        self.tick.store(tick_s * SEC, Ordering::SeqCst);
        self.now.store(now_ns, Ordering::SeqCst);
    }
}

impl StorageBackend for CoarseStamps {
    fn kind(&self) -> &'static str {
        "coarse"
    }
    fn read(&self, path: &VPath) -> veil_core::Result<Vec<u8>> {
        self.inner.read(path)
    }
    fn write(&self, path: &VPath, data: &[u8]) -> veil_core::Result<()> {
        self.inner.write(path, data)
    }
    fn create_new(&self, path: &VPath, data: &[u8]) -> veil_core::Result<bool> {
        self.inner.create_new(path, data)
    }
    fn remove_file(&self, path: &VPath) -> veil_core::Result<()> {
        self.inner.remove_file(path)
    }
    fn remove_dir_all(&self, path: &VPath) -> veil_core::Result<()> {
        self.inner.remove_dir_all(path)
    }
    fn create_dir_all(&self, path: &VPath) -> veil_core::Result<()> {
        self.inner.create_dir_all(path)
    }
    fn list_dir(&self, path: &VPath) -> veil_core::Result<Vec<DirEntry>> {
        self.inner.list_dir(path)
    }
    fn metadata(&self, path: &VPath) -> veil_core::Result<Option<Metadata>> {
        Ok(self.inner.metadata(path)?.map(|m| Metadata {
            mtime: Some(self.tick.load(Ordering::SeqCst)),
            ctime: None,
            inode: None,
            ..m
        }))
    }
    fn set_executable(&self, path: &VPath, executable: bool) -> veil_core::Result<()> {
        self.inner.set_executable(path, executable)
    }
    fn stat_clock(&self) -> Option<StatClock> {
        Some(StatClock {
            now: self.now.load(Ordering::SeqCst),
            exact: false,
        })
    }
}

// ---- stat cache ------------------------------------------------------------

#[test]
fn stat_cache_skips_unchanged_files_and_matches_uncached_builds() {
    let (mut repo, fs) = repo_with(MemoryBackend::new());
    fs.write(&p(".veilpolicy"), b"vault/ cloak team\n").unwrap();
    for i in 0..20 {
        fs.write(&p(&format!("src/f{i}.rs")), format!("fn f{i}() {{}}\n").as_bytes())
            .unwrap();
    }
    fs.write(&p("vault/.env.plan"), b"secret plans\n").unwrap();
    let mut cache = StatCache::new();

    let r = snap(&mut repo, &*fs, &mut cache);
    assert_eq!((r.hashed, r.cache_hits), (22, 0), "cold cache reads everything");
    assert_eq!(cache.len(), 22);
    assert!(cache.get(&p("vault/.env.plan")).unwrap().sealed.is_some());
    let first = repo.workspace_wc(WS).unwrap();
    cache.save(&*fs, &veil_core::statcache::cache_path(WS)).unwrap();

    let r = snap(&mut repo, &*fs, &mut cache);
    assert_eq!((r.hashed, r.cache_hits), (0, 22), "warm cache reads nothing");
    assert_eq!(repo.workspace_wc(WS).unwrap(), first, "no spurious snapshot");
    assert!(!cache.is_dirty(), "an all-hit run does not rewrite the cache");

    fs.write(&p("src/f3.rs"), b"fn f3() { changed() }\n").unwrap();
    fs.write(&p("vault/.env.plan"), b"new secret plans\n").unwrap();
    fs.remove_file(&p("src/f7.rs")).unwrap();
    let r = snap(&mut repo, &*fs, &mut cache);
    assert_eq!((r.hashed, r.cache_hits), (2, 19));
    assert!(cache.get(&p("src/f7.rs")).is_none(), "deleted files leave the cache");

    // Exactly what a cache-less build of the same directory produces.
    let tree = wc_tree(&repo);
    let (uncached, _) = repo.build_from(&*fs, Some(tree)).unwrap();
    assert_eq!(uncached, tree);
    let e = entry(&repo, &tree, "vault/.env.plan").unwrap();
    assert_eq!(e.visibility, Visibility::Cloaked { scope: "team".into() });
    assert_eq!(repo.store().read_entry(&e).unwrap(), b"new secret plans\n");

    // Executable-bit changes are stat changes too.
    fs.set_executable(&p("src/f1.rs"), true).unwrap();
    let r = snap(&mut repo, &*fs, &mut cache);
    assert_eq!(r.hashed, 1);
    assert!(entry(&repo, &wc_tree(&repo), "src/f1.rs").unwrap().executable);
}

#[test]
fn stat_cache_round_trips_through_the_backend() {
    let (mut repo, fs) = repo_with(MemoryBackend::new());
    fs.write(&p("a.txt"), b"a\n").unwrap();
    fs.write(&p("b/c.txt"), b"c\n").unwrap();
    let path = veil_core::statcache::cache_path(WS);
    let mut cache = StatCache::load(&*fs, &path);
    snap(&mut repo, &*fs, &mut cache);
    cache.save(&*fs, &path).unwrap();
    assert!(fs.exists(&p(".veil/local/statcache/default.cache")).unwrap());

    let mut reloaded = StatCache::load(&*fs, &path);
    assert_eq!(reloaded.len(), 2);
    let r = snap(&mut repo, &*fs, &mut reloaded);
    assert_eq!((r.hashed, r.cache_hits), (0, 2));

    // A corrupt cache is just an empty one.
    let mut raw = fs.read(&path).unwrap();
    let mid = raw.len() / 2;
    raw[mid] ^= 0xff;
    fs.write(&path, &raw).unwrap();
    assert!(StatCache::load(&*fs, &path).is_empty());
}

#[test]
fn racy_mtime_is_treated_as_dirty() {
    let (mut repo, fs) = repo_with(CoarseStamps::default());
    let mut cache = StatCache::new();
    let base = 1_800_000_000;

    // Written and snapshotted within the same one-second tick.
    fs.at(base, base * SEC + SEC / 2);
    fs.write(&p("a.txt"), b"v1\n").unwrap();
    fs.write(&p("old.txt"), b"old\n").unwrap();
    snap(&mut repo, &*fs, &mut cache);

    // Same size, same (coarse) mtime: only the racy rule can tell.
    fs.write(&p("a.txt"), b"v2\n").unwrap();
    let r = snap(&mut repo, &*fs, &mut cache);
    assert_eq!(
        r.cache_hits, 0,
        "records verified inside the stamp's tick are not trusted"
    );
    let e = entry(&repo, &wc_tree(&repo), "a.txt").unwrap();
    assert_eq!(repo.store().read_entry(&e).unwrap(), b"v2\n");

    // Still racy while the clock is within the window of the stamp...
    fs.at(base, base * SEC + SEC + SEC / 2);
    assert_eq!(snap(&mut repo, &*fs, &mut cache).cache_hits, 0);
    // ...and trusted once a verification happened well after it.
    fs.at(base, (base + 3) * SEC);
    assert_eq!(snap(&mut repo, &*fs, &mut cache).hashed, 2, "re-verified now");
    let r = snap(&mut repo, &*fs, &mut cache);
    assert_eq!((r.hashed, r.cache_hits), (0, 2));
}

#[test]
fn racy_files_on_disk_are_reread_until_they_age() {
    let dir = tempfile::tempdir().unwrap();
    let disk = veil_core::DiskBackend::new(dir.path());
    let (mut repo, fs) = repo_with(disk);
    let mut cache = StatCache::new();
    fs.write(&p("aged.txt"), b"aged\n").unwrap();
    fs.write(&p("future.txt"), b"from the future\n").unwrap();
    // A stamp in the future can never be older than a verification.
    let f = std::fs::File::options()
        .write(true)
        .open(dir.path().join("future.txt"))
        .unwrap();
    f.set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(3600))
        .unwrap();
    drop(f);
    // Let `aged.txt` (and the ctime of `future.txt`) age past the window.
    std::thread::sleep(std::time::Duration::from_millis(250));
    snap(&mut repo, &*fs, &mut cache);
    let r = snap(&mut repo, &*fs, &mut cache);
    assert_eq!(
        (r.hashed, r.cache_hits),
        (1, 1),
        "aged file hits, future-stamped file is re-read"
    );

    // Same-size rewrite right after a snapshot is always seen.
    fs.write(&p("aged.txt"), b"AGED\n").unwrap();
    snap(&mut repo, &*fs, &mut cache);
    let e = entry(&repo, &wc_tree(&repo), "aged.txt").unwrap();
    assert_eq!(repo.store().read_entry(&e).unwrap(), b"AGED\n");
}

/// A file edited just before a snapshot (every `vl commit` right after an
/// edit) is recorded, but its record falls in the racy window and can
/// never vouch for it: it is no reason to rewrite the cache (a 1 MB fsynced
/// write at 10,000 files). Once the file stats older, the record learnt
/// for it can vouch, and the cache is written again.
#[test]
fn a_record_that_can_never_vouch_does_not_rewrite_the_cache() {
    let dir = tempfile::tempdir().unwrap();
    let (mut repo, fs) = repo_with(veil_core::DiskBackend::new(dir.path()));
    let age = |name: &str| {
        let f = std::fs::File::options().write(true).open(dir.path().join(name)).unwrap();
        f.set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(3600)).unwrap();
    };
    let mut cache = StatCache::new();
    for name in ["a.txt", "b.txt"] {
        fs.write(&p(name), name.as_bytes()).unwrap();
        age(name);
    }
    // The ctimes are recent too: let them age past the window.
    std::thread::sleep(std::time::Duration::from_millis(250));
    snap(&mut repo, &*fs, &mut cache);
    assert!(cache.is_dirty(), "new records are written");
    cache.save(&*fs, &veil_core::statcache::cache_path(WS)).unwrap();

    fs.write(&p("a.txt"), b"edited").unwrap();
    let r = snap(&mut repo, &*fs, &mut cache);
    assert_eq!((r.hashed, r.cache_hits), (1, 1));
    let e = entry(&repo, &wc_tree(&repo), "a.txt").unwrap();
    assert_eq!(repo.store().read_entry(&e).unwrap(), b"edited", "the edit is recorded");
    assert!(!cache.is_dirty(), "a racy record alone does not rewrite the cache");

    std::thread::sleep(std::time::Duration::from_millis(250));
    let r = snap(&mut repo, &*fs, &mut cache);
    assert_eq!((r.hashed, r.cache_hits), (1, 1), "the racy record never vouched: read again");
    assert!(cache.is_dirty(), "the record learnt now can vouch: written");
    cache.save(&*fs, &veil_core::statcache::cache_path(WS)).unwrap();
    let r = snap(&mut repo, &*fs, &mut cache);
    assert_eq!((r.hashed, r.cache_hits), (0, 2));
}

#[test]
fn policy_change_invalidates_the_cache_and_reclassifies() {
    let (mut repo, fs) = repo_with(MemoryBackend::new());
    fs.write(&p(".veilpolicy"), b"fixtures/ public!\ndocs/ cloak team\n").unwrap();
    fs.write(&p("fixtures/key.js"), b"const k = 'AKIAIOSFODNN7EXAMPLE';\n")
        .unwrap();
    fs.write(&p("docs/.env.a"), b"hello\n").unwrap();
    let mut cache = StatCache::new();
    snap(&mut repo, &*fs, &mut cache);
    assert!(
        entry(&repo, &wc_tree(&repo), "fixtures/key.js").is_some(),
        "public! exposes it"
    );
    assert_eq!(snap(&mut repo, &*fs, &mut cache).cache_hits, 3);
    let old_key = cache.key().cloned().unwrap();

    // Dropping `public!` must re-scan content that has not changed.
    fs.write(&p(".veilpolicy"), b"docs/ cloak team\n").unwrap();
    let r = snap(&mut repo, &*fs, &mut cache);
    assert_eq!(r.cache_hits, 0, "a new policy drops every record");
    assert_ne!(cache.key().unwrap().policy, old_key.policy);
    assert_eq!(r.quarantined.len(), 1);
    assert!(
        r.quarantine_kept.is_empty(),
        "the previous version holds the secret: not kept"
    );
    let tree = wc_tree(&repo);
    assert!(entry(&repo, &tree, "fixtures/key.js").is_none());
    let doc = entry(&repo, &tree, "docs/.env.a").unwrap();
    assert_eq!(
        doc.visibility,
        Visibility::Cloaked { scope: "team".into() },
        "reclassified"
    );

    // Steady state under the new policy: hits again, same classification.
    let r = snap(&mut repo, &*fs, &mut cache);
    assert_eq!(
        r.cache_hits, 2,
        "policy file and docs/.env.a; the quarantined file is re-read"
    );
    assert_eq!(wc_tree(&repo), tree);
}

#[test]
fn key_state_is_part_of_the_cache_key() {
    let (mut repo, fs) = repo_with(MemoryBackend::new());
    fs.write(&p("a.txt"), b"a\n").unwrap();
    let mut cache = StatCache::new();
    snap(&mut repo, &*fs, &mut cache);
    assert_eq!(snap(&mut repo, &*fs, &mut cache).cache_hits, 1);
    repo.keys().create_scope("ops").unwrap();
    assert_eq!(
        snap(&mut repo, &*fs, &mut cache).cache_hits,
        0,
        "new key state drops the records"
    );
    assert_eq!(snap(&mut repo, &*fs, &mut cache).cache_hits, 1);
}

#[test]
fn checkout_invalidates_the_paths_it_writes() {
    // Stamps that never move: only invalidation by checkout keeps the
    // cache honest here.
    let (mut repo, fs) = repo_with(CoarseStamps::default());
    fs.at(1, 100 * SEC);
    fs.write(&p("x.txt"), b"v1\n").unwrap();
    fs.write(&p("gone.txt"), b"bye\n").unwrap();
    fs.write(&p("same.txt"), b"same\n").unwrap();
    let mut cache = StatCache::new();
    snap(&mut repo, &*fs, &mut cache);
    let (v1, _) = repo.commit_working_copy(WS, "v1").unwrap();
    let v1_tree = repo.snapshot(&v1).unwrap().tree;

    fs.write(&p("x.txt"), b"v2\n").unwrap(); // same size, same stamp
    fs.remove_file(&p("gone.txt")).unwrap();
    cache.invalidate(&p("x.txt")); // (pretend we noticed it some other way)
    snap(&mut repo, &*fs, &mut cache);
    let v2_tree = wc_tree(&repo);
    assert_eq!(
        repo.store()
            .read_entry(&entry(&repo, &v2_tree, "x.txt").unwrap())
            .unwrap(),
        b"v2\n"
    );

    // Go back to v1: checkout rewrites x.txt (same size, same stamp) and
    // re-creates gone.txt.
    repo.edit(WS, v1).unwrap();
    let co = repo
        .checkout_tree_cached(&*fs, Some(&v2_tree), &v1_tree, Some(&mut cache))
        .unwrap();
    assert_eq!((co.written, co.removed), (2, 0));
    assert!(cache.get(&p("x.txt")).is_none(), "written path invalidated");
    assert!(cache.get(&p("same.txt")).is_some(), "untouched records survive");

    let r = snap(&mut repo, &*fs, &mut cache);
    assert_eq!(r.hashed, 2, "only the checked-out files are re-read");
    assert_eq!(
        wc_tree(&repo),
        v1_tree,
        "the next snapshot sees exactly what was checked out"
    );
}

// ---- quarantine --------------------------------------------------------------

const SECRET: &[u8] = b"const key = 'AKIAIOSFODNN7EXAMPLE';\n";

#[test]
fn quarantined_edit_of_a_tracked_file_keeps_the_previous_version() {
    let (mut repo, fs) = repo_with(MemoryBackend::new());
    fs.write(&p("config.js"), b"const key = process.env.KEY;\n").unwrap();
    let mut cache = StatCache::new();
    snap(&mut repo, &*fs, &mut cache);
    let (base, _) = repo.commit_working_copy(WS, "base").unwrap();
    let before = entry(&repo, &repo.snapshot(&base).unwrap().tree, "config.js").unwrap();
    let wc = repo.workspace_wc(WS).unwrap();

    fs.write(&p("config.js"), SECRET).unwrap();
    let out = repo.snapshot_workspace_cached(WS, &*fs, Some(&mut cache)).unwrap();
    assert_eq!(out.report.quarantined[0].0, p("config.js"));
    assert_eq!(out.report.quarantine_kept, vec![p("config.js")]);
    assert!(out.report.local_only().contains(&p("config.js")));
    assert!(!out.changed, "history is not touched: no deletion recorded");
    assert_eq!(out.snapshot, wc);
    assert_eq!(entry(&repo, &wc_tree(&repo), "config.js"), Some(before.clone()));
    assert!(repo.is_empty_change(&wc).unwrap());

    // Again (the quarantined file is never trusted from the cache).
    let out = repo.snapshot_workspace_cached(WS, &*fs, Some(&mut cache)).unwrap();
    assert_eq!(out.report.quarantine_kept, vec![p("config.js")]);

    // Fixing the file records the edit normally.
    fs.write(&p("config.js"), b"const key = loadKey();\n").unwrap();
    let out = repo.snapshot_workspace_cached(WS, &*fs, Some(&mut cache)).unwrap();
    assert!(out.changed && out.report.quarantined.is_empty());
    let e = entry(&repo, &wc_tree(&repo), "config.js").unwrap();
    assert_eq!(repo.store().read_entry(&e).unwrap(), b"const key = loadKey();\n");
}

#[test]
fn quarantined_new_file_stays_out_of_the_tree() {
    let (mut repo, fs) = repo_with(MemoryBackend::new());
    fs.write(&p("main.rs"), b"fn main() {}\n").unwrap();
    fs.write(&p("leak.js"), SECRET).unwrap();
    let out = repo
        .snapshot_workspace_cached(WS, &*fs, Some(&mut StatCache::new()))
        .unwrap();
    assert_eq!(out.report.quarantined[0].0, p("leak.js"));
    assert!(out.report.quarantine_kept.is_empty());
    assert!(entry(&repo, &wc_tree(&repo), "leak.js").is_none());
    assert!(entry(&repo, &wc_tree(&repo), "main.rs").is_some());
}

#[test]
fn checkout_never_overwrites_a_quarantined_edit() {
    let (mut repo, fs) = repo_with(MemoryBackend::new());
    fs.write(&p("config.js"), b"v1\n").unwrap();
    fs.write(&p("other.txt"), b"1\n").unwrap();
    let mut cache = StatCache::new();
    snap(&mut repo, &*fs, &mut cache);
    let (v1, _) = repo.commit_working_copy(WS, "v1").unwrap();
    fs.write(&p("config.js"), b"v2\n").unwrap();
    fs.write(&p("other.txt"), b"2\n").unwrap();
    snap(&mut repo, &*fs, &mut cache);
    let (v2, _) = repo.commit_working_copy(WS, "v2").unwrap();
    let v2_tree = repo.snapshot(&v2).unwrap().tree;
    let v1_tree = repo.snapshot(&v1).unwrap().tree;

    // Quarantined local edit on top of v2, then move to v1.
    fs.write(&p("config.js"), SECRET).unwrap();
    let r = snap(&mut repo, &*fs, &mut cache);
    assert_eq!(r.quarantine_kept, vec![p("config.js")]);
    repo.edit(WS, v1).unwrap();
    let co = repo
        .checkout_tree_cached(&*fs, Some(&v2_tree), &v1_tree, Some(&mut cache))
        .unwrap();
    assert_eq!(co.kept_local, vec![p("config.js")]);
    assert_eq!(fs.read(&p("config.js")).unwrap(), SECRET, "local edit survives");
    assert_eq!(
        fs.read(&p("other.txt")).unwrap(),
        b"1\n",
        "everything else is checked out"
    );

    // The next snapshot quarantines it again, on top of v1's version.
    let r = snap(&mut repo, &*fs, &mut cache);
    assert_eq!(r.quarantine_kept, vec![p("config.js")]);
    assert_eq!(wc_tree(&repo), v1_tree);

    // A target that deletes the file does not delete the local edit either.
    let root = repo.root_id();
    let empty = repo.snapshot(&root).unwrap().tree;
    let co = repo
        .checkout_tree_cached(&*fs, Some(&v1_tree), &empty, Some(&mut cache))
        .unwrap();
    assert_eq!(co.kept_local, vec![p("config.js")]);
    assert!(fs.exists(&p("config.js")).unwrap());
    assert!(!fs.exists(&p("other.txt")).unwrap());
}

/// A large working copy on a disk is listed, stat'ed and classified ahead
/// of the walk, on other threads (`prefetch`, from 250 cached files): the
/// snapshot it makes is exactly the one a full read makes, whatever the
/// directory holds (ignored and nested directories, crash debris, a link
/// to a directory, an executable, edits, deletions, new directories).
#[test]
fn a_snapshot_listed_ahead_records_what_a_full_read_records() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut repo, fs) = repo_with(veil_core::DiskBackend::new(tmp.path()));
    fs.write(&p(".veilpolicy"), b"build/ ignore\n").unwrap();
    for d in 0..40 {
        for f in 0..10 {
            fs.write(&p(&format!("d{d:02}/sub{}/f{f}.txt", d % 3)), format!("{d} {f}\n").as_bytes()).unwrap();
        }
    }
    fs.write(&p("build/out.o"), b"ignored\n").unwrap();
    fs.write(&p("vendored/.veil/repo.json"), b"{}\n").unwrap();
    fs.write(&p("vendored/lib.rs"), b"another repository's\n").unwrap();
    fs.write(&p("d01/.f1.txt.vltmp0badf00d"), b"crash debris\n").unwrap();
    std::os::unix::fs::symlink("d02", tmp.path().join("link")).unwrap();
    fs.write(&p("d03/run.sh"), b"#!/bin/sh\n").unwrap();
    fs.set_executable(&p("d03/run.sh"), true).unwrap();
    // Older than the racy window: the next runs' cache vouches for them.
    std::thread::sleep(std::time::Duration::from_millis(250));
    let mut cache = StatCache::new();
    snap(&mut repo, &*fs, &mut cache);
    let r = snap(&mut repo, &*fs, &mut cache);
    assert!(cache.len() >= 400 && r.cache_hits >= 400, "{} records, {} hits", cache.len(), r.cache_hits);
    // Edits, a deletion, a new file in a new directory, a removed directory.
    fs.write(&p("d05/sub2/f3.txt"), b"edited\n").unwrap();
    fs.remove_file(&p("d06/sub0/f4.txt")).unwrap();
    fs.write(&p("new/dir/file.txt"), b"new\n").unwrap();
    std::fs::remove_dir_all(tmp.path().join("d07")).unwrap();
    let ahead = repo.snapshot_workspace_cached(WS, &*fs, Some(&mut cache)).unwrap();
    assert!(ahead.changed);
    let tree = wc_tree(&repo);
    assert_eq!(entry(&repo, &tree, "d05/sub2/f3.txt").map(|e| e.size), Some(7));
    assert!(entry(&repo, &tree, "d06/sub0/f4.txt").is_none() && entry(&repo, &tree, "d07").is_none());
    assert!(entry(&repo, &tree, "new/dir/file.txt").is_some() && entry(&repo, &tree, "d03/run.sh").unwrap().executable);
    assert!(entry(&repo, &tree, "build").is_none() && entry(&repo, &tree, "vendored").is_none());
    assert!(entry(&repo, &tree, "d01/.f1.txt.vltmp0badf00d").is_none());
    // A full read, nothing from any cache: nothing to record.
    let full = repo.snapshot_workspace_cached(WS, &*fs, Some(&mut StatCache::new())).unwrap();
    assert!(!full.changed, "the full read found something the listing ahead missed");
    assert_eq!(wc_tree(&repo), tree);
    let r = (&ahead.report, &full.report);
    assert_eq!((r.0.files, r.0.ignored, &r.0.nested, &r.0.ignored_paths), (r.1.files, r.1.ignored, &r.1.nested, &r.1.ignored_paths));
}
