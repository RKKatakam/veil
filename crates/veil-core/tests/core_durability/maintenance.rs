//! Incremental maintenance (scale stream G2,
//! `docs/design/scale/4-background-cleanup-streaming.md`): consolidation,
//! geometric merging, the bitmap prune, the gc lease, crash debris and
//! background runs. One test (or more) per item of the design's threat
//! review that the engine can show; the crash sweeps are in `crash.rs`.

use crate::adversarial_support;
use crate::oplog_concurrency::{assert_fsck_clean, open};

use std::{
    collections::BTreeSet,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use adversarial_support::*;
use veil_core::{
    gc::{gc, GcOptions},
    maintenance::{self, geometric_split, GcLease},
    object::Object,
    remote,
    vfs::{DirEntry, Metadata},
    DiskBackend, Identity, MemoryBackend, ObjectId, Repo, Result, StorageBackend, VPath, VeilError,
};

fn pack_names(fs: &dyn StorageBackend) -> BTreeSet<String> {
    fs.list_dir(&p(".veil/objects/pack"))
        .map(|v| v.into_iter().filter(|e| e.name.ends_with(".idx")).map(|e| e.name).collect())
        .unwrap_or_default()
}

fn loose_count(fs: &dyn StorageBackend) -> usize {
    let mut n = 0;
    for d in fs.list_dir(&p(".veil/objects")).unwrap() {
        if d.name.len() == 2 && d.name.bytes().all(|b| b.is_ascii_hexdigit()) {
            n += fs.list_dir(&p(&format!(".veil/objects/{}", d.name))).unwrap().len();
        }
    }
    n
}

/// Every object id in the store, by listing (no freshening).
fn ids(repo: &Repo) -> Vec<ObjectId> {
    repo.store().list_objects().unwrap()
}

// ---- geometric merging ------------------------------------------------------------

#[test]
fn geometric_split_merges_only_what_breaks_the_progression() {
    // Already a progression: nothing to merge.
    assert_eq!(geometric_split(&[]), 0);
    assert_eq!(geometric_split(&[100]), 0);
    assert_eq!(geometric_split(&[10, 1000]), 0);
    assert_eq!(geometric_split(&[1, 2, 4, 8, 16]), 0);
    // Two small packs merge; the big one stays.
    assert_eq!(geometric_split(&[10, 15, 1000]), 2);
    // Merging them would make the result too close to the next one: that
    // one joins too.
    assert_eq!(geometric_split(&[10, 15, 40, 1000]), 3);
    // Two of a size merge (the big old pack only when it is no longer big).
    assert_eq!(geometric_split(&[600, 1000]), 2);
    // Many tiny packs below one big pack.
    let mut many = vec![1u64; 60];
    many.push(1 << 20);
    assert_eq!(geometric_split(&many), 60);
}

/// The gate: the big old pack is never rewritten by later runs, which
/// pack the new loose objects and merge the small packs among themselves.
#[test]
fn gc_never_rewrites_the_big_old_pack() {
    let (mut repo, fs, id) = new_repo("alice");
    // Content that does not compress, so that the first pack is big.
    let files: Vec<(String, String)> = (0..1500)
        .map(|i: u32| (format!("src/f{i}.txt"), (0..16).map(|k: u32| ObjectId::hash(&(i * 16 + k).to_le_bytes()).hex()).collect()))
        .collect();
    let refs: Vec<(&str, &str)> = files.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
    commit_files(&mut repo, &*fs, &refs, "big");
    gc(&mut repo, &GcOptions::default()).unwrap();
    let big = pack_names(&*fs);
    assert_eq!(big.len(), 1);
    for round in 0..12 {
        commit_files(&mut repo, &*fs, &[(&format!("small{round}.txt"), &format!("small {round}\n"))], "small");
        let r = gc(&mut repo, &GcOptions::default()).unwrap();
        assert!(big.is_subset(&pack_names(&*fs)), "round {round}: the big pack was rewritten ({r:?})");
        assert_eq!(loose_count(&*fs), 0);
    }
    // The small packs were merged as they came: few remain.
    assert!(pack_names(&*fs).len() <= 6, "{:?}", pack_names(&*fs));
    assert_fsck_clean(fs.clone(), &id, "after rounds of gc");
}

/// Merging copies entries as stored: deltas stay deltas (their bases come
/// along), and everything reads back.
#[test]
fn merging_copies_deltas_as_stored() {
    let (mut repo, fs, id) = new_repo("alice");
    let body: String = (0..400).map(|l| format!("line {l} of a long file\n")).collect();
    let mut snaps = Vec::new();
    for round in 0..3 {
        for v in 0..4 {
            let text = format!("{body}round {round} version {v}\n");
            snaps.push(commit_files(&mut repo, &*fs, &[("long.txt", &text)], "edit"));
        }
        let r = gc(&mut repo, &GcOptions::default()).unwrap();
        assert!(r.pack_stats.deltas > 0 || r.merged > 0, "round {round}: {r:?}");
    }
    let r = gc(&mut repo, &GcOptions::default()).unwrap();
    let stats = repo.store().stats().unwrap();
    assert!(stats.packs <= 2, "{stats:?} {r:?}");
    for s in &snaps {
        assert!(read_at(&repo, s, "long.txt").starts_with(body.as_bytes()));
    }
    assert!(repo.store().verify_packs().unwrap().is_empty());
    assert_fsck_clean(fs.clone(), &id, "after merging");
}

// ---- threat 1: a loose file deleted before its pack is durable --------------------

/// A disk that records the order of the mutations it sees.
#[derive(Debug)]
struct Recorder {
    inner: Arc<MemoryBackend>,
    log: Mutex<Vec<String>>,
}

impl StorageBackend for Recorder {
    fn kind(&self) -> &'static str {
        "recorder"
    }
    fn read(&self, path: &VPath) -> Result<Vec<u8>> {
        self.inner.read(path)
    }
    fn write(&self, path: &VPath, data: &[u8]) -> Result<()> {
        self.log.lock().unwrap().push(format!("write {path}"));
        self.inner.write(path, data)
    }
    fn create_new(&self, path: &VPath, data: &[u8]) -> Result<bool> {
        self.inner.create_new(path, data)
    }
    fn remove_file(&self, path: &VPath) -> Result<()> {
        self.log.lock().unwrap().push(format!("remove {path}"));
        self.inner.remove_file(path)
    }
    fn remove_dir_all(&self, path: &VPath) -> Result<()> {
        self.inner.remove_dir_all(path)
    }
    fn create_dir_all(&self, path: &VPath) -> Result<()> {
        self.inner.create_dir_all(path)
    }
    fn list_dir(&self, path: &VPath) -> Result<Vec<DirEntry>> {
        self.inner.list_dir(path)
    }
    fn metadata(&self, path: &VPath) -> Result<Option<Metadata>> {
        self.inner.metadata(path)
    }
    fn set_executable(&self, path: &VPath, x: bool) -> Result<()> {
        self.inner.set_executable(path, x)
    }
}

/// Every loose object is removed only after the `.pack` and then the
/// `.idx` holding it were written (durably: `write` is durable).
#[test]
fn consolidation_removes_a_loose_copy_only_after_its_pack_and_index() {
    let rec = Arc::new(Recorder {
        inner: Arc::new(MemoryBackend::new()),
        log: Mutex::new(Vec::new()),
    });
    let fs: Arc<dyn StorageBackend> = rec.clone();
    let id = Identity::generate("alice");
    let mut repo = Repo::init(fs.clone(), Some(id.clone()), "alice").unwrap();
    for i in 0..5 {
        commit_files(&mut repo, &*fs, &[(&format!("f{i}.txt"), &format!("{i}\n"))], "c");
    }
    rec.log.lock().unwrap().clear();
    gc(&mut repo, &GcOptions::default()).unwrap();
    let log = rec.log.lock().unwrap().clone();
    let first_loose_removal = log
        .iter()
        .position(|l| l.starts_with("remove .veil/objects/") && l.split('/').nth(2).is_some_and(|d| d.len() == 2 && d != "gc"))
        .expect("loose objects were removed");
    let pack = log.iter().position(|l| l.starts_with("write .veil/objects/pack/") && l.ends_with(".pack")).expect("a pack was written");
    let idx = log.iter().position(|l| l.starts_with("write .veil/objects/pack/") && l.ends_with(".idx")).expect("an index was written");
    assert!(pack < idx && idx < first_loose_removal, "{log:#?}");
    assert_fsck_clean(fs, &id, "after consolidation");
}

// ---- threat 2: a reader racing consolidation and merging ----------------------------

/// One thread commits and runs gc in a loop (consolidation, merging,
/// rewrites); eight threads, each with its own store and caches, read
/// random reachable objects. No read ever says `Missing` (to the engine:
/// redacted).
#[test]
fn readers_never_take_an_object_for_missing_during_maintenance() {
    let tmp = tempfile::tempdir().unwrap();
    let fs: Arc<dyn StorageBackend> = Arc::new(DiskBackend::new(tmp.path()));
    let id = Identity::generate("alice");
    let mut repo = Repo::init(fs.clone(), Some(id.clone()), "alice").unwrap();
    for i in 0..20 {
        commit_files(&mut repo, &*fs, &[(&format!("d{}/f{i}.txt", i % 4), &format!("version {i}\n").repeat(50))], "c");
        if i % 5 == 4 {
            gc(&mut repo, &GcOptions::default()).unwrap();
        }
    }
    let wanted: Arc<Vec<ObjectId>> = Arc::new(ids(&repo));
    let stop = Arc::new(AtomicBool::new(false));
    let reads = Arc::new(AtomicUsize::new(0));
    let mut readers = Vec::new();
    for t in 0..8u64 {
        let (fs, id, wanted, stop, reads) = (fs.clone(), id.clone(), wanted.clone(), stop.clone(), reads.clone());
        readers.push(std::thread::spawn(move || {
            let r = Repo::open(fs, Some(id), "alice").unwrap();
            let mut x = t.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
            while !stop.load(Ordering::SeqCst) {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                let want = wanted[(x % wanted.len() as u64) as usize];
                match r.store().get_raw(&want) {
                    Ok(raw) => assert_eq!(ObjectId::hash(&raw), want),
                    Err(e) => panic!("reader {t}: {} read as {e:?}", want.short()),
                }
                assert!(r.store().has(&want), "reader {t}: has({}) said no", want.short());
                reads.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }
    for i in 0..30 {
        commit_files(&mut repo, &*fs, &[(&format!("e/g{i}.txt"), &format!("more {i}\n"))], "more");
        gc(&mut repo, &GcOptions::default()).unwrap();
    }
    stop.store(true, Ordering::SeqCst);
    for r in readers {
        r.join().unwrap();
    }
    assert!(reads.load(Ordering::Relaxed) > 1000, "too few reads to mean anything");
    assert_fsck_clean(fs, &id, "after reading through maintenance");
}

// ---- threat 3: prune beside lock-free writers, with the clock stepping --------------

/// Random lock-free commits, abandons and gc runs (default grace, with
/// the clock stepping 0–90 minutes between runs): every object reachable
/// from any head stays present, and `fsck` is clean.
#[test]
fn prune_with_clock_steps_beside_writers_keeps_everything_reachable() {
    let (repo, fs, id) = new_repo("alice");
    drop(repo);
    let fs: Arc<dyn StorageBackend> = fs;
    let stop = Arc::new(AtomicBool::new(false));
    let mut writers = Vec::new();
    for w in 0..3u64 {
        let (fs, id, stop) = (fs.clone(), id.clone(), stop.clone());
        writers.push(std::thread::spawn(move || {
            let mut x = (w + 1).wrapping_mul(0x2545_f491_4f6c_dd1d);
            let mut k = 0;
            while !stop.load(Ordering::SeqCst) && k < 40 {
                k += 1;
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                let mut r = Repo::open(fs.clone(), Some(id.clone()), "alice").unwrap();
                let ws = format!("w{w}");
                if !r.view().workspaces.contains_key(&ws) {
                    let root = r.root_id();
                    r.create_workspace(&ws, vec![root]).unwrap();
                }
                let ov = r.workspace_overlay(&ws).unwrap();
                ov.write(&p(&format!("f{}.txt", x % 5)), format!("{w} {k} {x}\n").as_bytes()).unwrap();
                let s = match r.snapshot_workspace_with(&ws, &ov, Default::default()) {
                    Ok(s) => s.snapshot,
                    Err(e) => {
                        assert!(e.to_string().contains("run the command again"), "{e}");
                        continue;
                    }
                };
                if x % 3 == 0 {
                    let _ = r.commit_working_copy(&ws, "c");
                }
                if x % 7 == 0 {
                    let _ = r.abandon(s);
                }
            }
        }));
    }
    let mut now = veil_core::now_millis();
    let mut runs = 0;
    while writers.iter().any(|w| !w.is_finished()) {
        runs += 1;
        now += (runs * 37 % 91) * 60_000;
        let mut g = Repo::open(fs.clone(), Some(id.clone()), "alice").unwrap();
        gc(&mut g, &GcOptions { now: Some(now), keep_ops: Some(Duration::from_secs(3600)), ..GcOptions::default() }).unwrap();
    }
    stop.store(true, Ordering::SeqCst);
    for w in writers {
        w.join().unwrap();
    }
    assert!(runs > 1);
    let r = Repo::open(fs.clone(), Some(id.clone()), "alice").unwrap();
    for h in r.visible_snapshots().unwrap() {
        let tree = r.snapshot(&h).unwrap().tree;
        veil_core::tree::walk_files(r.store(), &tree).unwrap();
    }
    drop(r);
    assert_fsck_clean(fs, &id, "after pruning beside writers");
}

// ---- threat 4: memory -------------------------------------------------------------

/// Peak resident memory of this process (Linux `VmHWM`), in KiB.
#[cfg(target_os = "linux")]
fn peak_kib() -> u64 {
    let s = std::fs::read_to_string("/proc/self/status").unwrap();
    s.lines().find(|l| l.starts_with("VmHWM:")).and_then(|l| l.split_whitespace().nth(1)).unwrap().parse().unwrap()
}

/// Pruning a store of 2^16 reachable objects costs memory for the
/// inventory's bits and the packs' index tables (48 bytes per object,
/// loaded by any reader), never a set of ids or paths per object, and
/// never their content. (The old gc held several hash sets and a path per
/// object: about 300 bytes each.)
#[cfg(target_os = "linux")]
#[test]
fn pruning_memory_is_the_inventory_bits_not_the_objects() {
    // The peak is the process's: alone in one, so no other test's threads
    // add to it (BUG-970).
    if !crate::in_own_process("maintenance::pruning_memory_is_the_inventory_bits_not_the_objects") {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let fs: Arc<dyn StorageBackend> = Arc::new(DiskBackend::new(tmp.path()));
    let id = Identity::generate("alice");
    let mut repo = Repo::init(fs.clone(), Some(id.clone()), "alice").unwrap();
    const N: usize = 1 << 16;
    // 256 directories of 256 files, built straight into the store (in one
    // transaction: one barrier, not one fsync per object).
    let mut tx = repo.transaction("many").unwrap();
    let mut dirs = Vec::new();
    for d in 0..256 {
        let mut entries = Vec::new();
        for f in 0..256 {
            entries.push(file(&format!("f{f:03}"), blob(tx.repo(), format!("{d}/{f}").as_bytes())));
        }
        dirs.push(dir(&format!("d{d:03}"), raw_tree(tx.repo(), entries)));
    }
    let root = raw_tree(tx.repo(), dirs);
    let snap = raw_snapshot(tx.repo(), vec![tx.repo().root_id()], root, "many");
    tx.add_head(snap).unwrap();
    tx.view.tags.insert("many".into(), veil_core::oplog::Tag::new(snap));
    tx.commit().unwrap();
    gc(&mut repo, &GcOptions::default()).unwrap();
    assert!(ids(&repo).len() > N);
    let mut g = Repo::open(fs.clone(), Some(id.clone()), "alice").unwrap();
    g.store().packs().unwrap();
    // Reset the peak to what the process holds now.
    std::fs::write("/proc/self/clear_refs", "5").unwrap();
    let before = peak_kib();
    let r = gc(&mut g, &GcOptions::default()).unwrap();
    let grew = peak_kib().saturating_sub(before) * 1024;
    assert!(r.reachable > N, "{r:?}");
    let per_object = grew / N as u64;
    assert!(per_object <= 80, "pruning grew the peak by {} MiB, {per_object} bytes per object", grew >> 20);
}

// ---- threat 5: content gc cannot read -----------------------------------------------

/// Bob's clone holds a secret sealed for a scope he lacks: his gc deletes
/// nothing it still needs, and after Alice grants him the scope he reads
/// it.
#[test]
fn gc_that_cannot_open_a_sealed_tree_deletes_nothing() {
    let (mut alice, fs, _) = new_repo("alice");
    fs.write(&p(".veilpolicy"), b"secrets/.env.key cloak team\n").unwrap();
    let c = commit_files(&mut alice, &*fs, &[("secrets/.env.key", "s3cr3t-811\n"), ("open.txt", "open\n")], "sealed");
    alice.set_tag("main", c, false).unwrap();
    let team = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, team.clone(), false, &[], false).unwrap();
    let bob_id = Identity::generate("bob");
    let bfs = Arc::new(MemoryBackend::new());
    let mut bob = Repo::init_for_clone(bfs.clone(), Some(bob_id.clone()), "bob").unwrap();
    remote::pull(&mut bob, "origin", team.clone()).unwrap();
    let garbage = bob.store().put(&Object::Blob(b"bob's garbage".to_vec())).unwrap();
    let before = ids(&bob);
    let r = gc(&mut bob, &GcOptions { grace: Duration::ZERO, keep_ops: Some(Duration::ZERO), ..GcOptions::default() }).unwrap();
    if !r.incomplete.is_empty() {
        assert_eq!(r.deleted, 0, "{r:?}");
        assert!(ids(&bob).contains(&garbage));
    }
    for i in before.iter().filter(|i| **i != garbage) {
        assert!(ids(&bob).contains(i), "{} was deleted", i.short());
    }
    alice.keys().grant("team", &bob_id.public_id(), "bob").unwrap();
    remote::push(&mut alice, team.clone(), false, &[], false).unwrap();
    remote::pull(&mut bob, "origin", team).unwrap();
    assert_eq!(read_at(&bob, &c, "secrets/.env.key"), b"s3cr3t-811\n");
}

// ---- threat 10: maintenance during `vl upgrade` ------------------------------------

/// `repo.json` of the repository on `fs` set to `format` (a repository an
/// older vl wrote, holding nothing format 8 removed).
fn mark_format(fs: &MemoryBackend, format: u32) {
    let mut cfg = veil_core::repo::read_config(fs).unwrap();
    cfg.format = format;
    fs.write(&p(".veil/repo.json"), &serde_json::to_vec_pretty(&cfg).unwrap()).unwrap();
}

/// `vl upgrade` takes the gc lease: while maintenance holds it (paused
/// mid-run), the upgrade waits, and goes on once it is released.
#[test]
fn upgrade_waits_for_running_maintenance() {
    let (repo, fs, id) = new_repo("alice");
    drop(repo);
    mark_format(&fs, 7);
    let backend: Arc<dyn StorageBackend> = fs.clone();
    let lease = GcLease::acquire(&backend, false).unwrap().expect("free");
    let up = {
        let backend = backend.clone();
        let id = id.clone();
        std::thread::spawn(move || veil_core::upgrade::upgrade(backend, Some(id), &Default::default()))
    };
    std::thread::sleep(Duration::from_millis(300));
    assert!(!up.is_finished(), "the upgrade did not wait for the lease");
    drop(lease);
    up.join().unwrap().unwrap();
    assert_fsck_clean(fs.clone(), &id, "after the upgrade");
}

/// A gc opened before the format changed re-reads it under its hold and
/// stops instead of writing for another one. (No repository this build
/// opens can be upgraded under it, so the change is written by hand, then
/// upgraded back.)
#[test]
fn gc_stops_if_the_repository_was_upgraded_since_it_opened() {
    let (mut repo, fs, id) = new_repo("alice");
    commit_files(&mut repo, &*fs, &[("f", "1\n")], "c");
    mark_format(&fs, 7);
    let e = gc(&mut repo, &GcOptions::default()).unwrap_err();
    veil_core::upgrade::upgrade(fs.clone(), Some(id.clone()), &Default::default()).unwrap();
    assert!(e.to_string().contains("upgraded"), "{e}");
    let mut fresh = open(&fs, &id);
    gc(&mut fresh, &GcOptions::default()).unwrap();
    assert_fsck_clean(fs.clone(), &id, "after gc on the upgraded repository");
}

// ---- the gc lease ------------------------------------------------------------------

/// One gc at a time: a second waits for the lease (and `--auto` does not).
#[test]
fn the_gc_lease_lets_one_run_at_a_time() {
    let tmp = tempfile::tempdir().unwrap();
    let fs: Arc<dyn StorageBackend> = Arc::new(DiskBackend::new(tmp.path()));
    let id = Identity::generate("alice");
    let mut repo = Repo::init(fs.clone(), Some(id.clone()), "alice").unwrap();
    commit_files(&mut repo, &*fs, &[("f", "1\n")], "c");
    let lease = GcLease::acquire(&fs, false).unwrap().expect("free");
    assert!(GcLease::acquire(&fs, false).unwrap().is_none(), "a second lease");
    let mut auto = Repo::open(fs.clone(), Some(id.clone()), "alice").unwrap();
    assert!(maintenance::auto(&mut auto, veil_core::now_millis()).unwrap().is_none(), "--auto ran beside a held lease");
    drop(lease);
    assert!(maintenance::auto(&mut auto, veil_core::now_millis()).unwrap().is_some());
    // The same within one process, on a store that is not a directory:
    // failed attempts never release the holder's lease.
    let mem: Arc<dyn StorageBackend> = Arc::new(MemoryBackend::new());
    let held = GcLease::acquire(&mem, false).unwrap().expect("free");
    for _ in 0..3 {
        assert!(GcLease::acquire(&mem, false).unwrap().is_none(), "a second in-process lease");
    }
    drop(held);
    assert!(GcLease::acquire(&mem, false).unwrap().is_some());
    // `.veil/lock` is not taken: a metadata writer does not wait for gc.
    let _hold = GcLease::acquire(&fs, false).unwrap().unwrap();
    veil_core::lock::RepoLock::acquire(fs.clone()).unwrap();
}

// ---- background runs ------------------------------------------------------------------

#[test]
fn auto_packs_and_merges_and_prunes_only_when_due() {
    let (mut repo, fs, id) = new_repo("alice");
    let now = veil_core::now_millis();
    assert!(maintenance::auto_due(&repo, now).unwrap().is_none());
    // Over the loose threshold (the estimate samples 16 of 256 fan-outs).
    for i in 0..(maintenance::AUTO_LOOSE + 2000) {
        repo.store().put(&Object::Blob(format!("loose {i}").into_bytes())).unwrap();
    }
    assert!(maintenance::auto_due(&repo, now).unwrap().is_some_and(|w| w.contains("loose")));
    let r = maintenance::auto(&mut repo, now).unwrap().unwrap();
    assert!(!r.pruned, "no prune before any was recorded: {r:?}");
    assert!(r.gc.consolidated > maintenance::AUTO_LOOSE);
    assert_eq!(r.gc.deleted, 0);
    assert!(maintenance::auto_due(&repo, now).unwrap().is_none());
    // A week after an explicit gc's prune, `--auto` prunes too.
    gc(&mut repo, &GcOptions { now: Some(now), ..GcOptions::default() }).unwrap();
    let later = now + 8 * 24 * 3600 * 1000;
    assert!(maintenance::auto_due(&repo, later).unwrap().is_some());
    let r = maintenance::auto(&mut repo, later).unwrap().unwrap();
    assert!(r.pruned, "{r:?}");
    assert!(r.gc.deleted > maintenance::AUTO_LOOSE, "{r:?}");
    assert_fsck_clean(fs.clone(), &id, "after background runs");
}

// ---- crash debris ---------------------------------------------------------------------

/// Stream temp files name their writer: gc removes those of writers that
/// are provably gone (and owner-less ones a day old), never a live one's.
#[test]
fn stale_temp_files_go_but_never_a_live_writers() {
    let tmp = tempfile::tempdir().unwrap();
    let fs: Arc<dyn StorageBackend> = Arc::new(DiskBackend::new(tmp.path()));
    let id = Identity::generate("alice");
    let mut repo = Repo::init(fs.clone(), Some(id.clone()), "alice").unwrap();
    commit_files(&mut repo, &*fs, &[("f", "1\n")], "c");
    let me = veil_core::lock::HostIdentity::current();
    let dead = veil_core::lock::owner_tag(&me, 999_999, 0, veil_core::now_millis());
    let live = veil_core::lock::process_owner().to_string();
    let other_host = veil_core::lock::owner_tag(&veil_core::lock::HostIdentity::simulated("elsewhere"), 1, 0, 0);
    let pack = tmp.path().join(".veil/objects/pack");
    std::fs::create_dir_all(&pack).unwrap();
    let plant = |dir: &std::path::Path, name: &str| {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join(name), b"partial").unwrap();
        dir.join(name)
    };
    let gone = plant(&pack, &format!(".stream-{dead}.vltmp0000aaaa"));
    let mine = plant(&pack, &format!(".stream-{live}.vltmp0000bbbb"));
    let theirs = plant(&pack, &format!(".stream-{other_host}.vltmp0000cccc"));
    let journal = plant(&tmp.path().join(".veil/local/push"), &format!(".stream-{dead}.vltmp0000dddd"));
    let fresh_ownerless = plant(&tmp.path().join(".veil/objects/ab"), ".cdef.vltmp0000eeee");
    let old_ownerless = plant(&pack, ".stream.vltmp0000ffff");
    let day_ago = std::time::SystemTime::now() - Duration::from_secs(2 * 24 * 3600);
    std::fs::File::options().write(true).open(&old_ownerless).unwrap().set_modified(day_ago).unwrap();
    let r = gc(&mut repo, &GcOptions::default()).unwrap();
    assert!(!gone.exists() && !journal.exists() && !old_ownerless.exists(), "{r:?}");
    assert!(mine.exists() && theirs.exists() && fresh_ownerless.exists());
    assert_eq!(r.debris_removed, 3);
    assert_fsck_clean(fs, &id, "after removing debris");
}

/// A transaction killed before it unregistered leaves its registration:
/// gc does not wait for it, and removes it.
#[test]
fn a_dead_transactions_registration_neither_blocks_nor_stays() {
    let (mut repo, fs, id) = new_repo("alice");
    let old = commit_files(&mut repo, &*fs, &[("f", "old\n")], "old");
    repo.abandon(old).unwrap();
    let dead = veil_core::lock::owner_tag(&veil_core::lock::HostIdentity::current(), 999_999, 0, veil_core::now_millis());
    fs.create_dir_all(&p(&format!(".veil/objects/incoming/{}{dead}", maintenance::LIVE_PREFIX))).unwrap();
    let mut g = open(&fs, &id);
    let r = gc(&mut g, &GcOptions { grace: Duration::ZERO, keep_ops: Some(Duration::ZERO), now: Some(veil_core::now_millis() + 60_000), ..GcOptions::default() }).unwrap();
    // A live registration would have kept the fence down until gc gave up
    // and deferred (BUG-970: no wall-clock bound needed).
    assert!(r.deleted > 0 && r.deferred.is_none(), "gc waited for a dead transaction: {r:?}");
    assert!(fs.list_dir(&p(".veil/objects/incoming")).map(|v| v.is_empty()).unwrap_or(true));
}

// ---- EIO during each maintenance step ------------------------------------------------

/// A disk on which mutation number `fail_at` fails with EIO (once): the
/// command reports it and nothing else goes wrong.
#[derive(Debug)]
struct OneEio {
    inner: Arc<MemoryBackend>,
    fail_at: usize,
    seen: AtomicUsize,
    failed: AtomicBool,
}

impl OneEio {
    fn tick(&self, path: &VPath) -> Result<()> {
        if self.seen.fetch_add(1, Ordering::SeqCst) == self.fail_at {
            self.failed.store(true, Ordering::SeqCst);
            return Err(VeilError::Io {
                path: path.to_string(),
                source: std::io::Error::from_raw_os_error(5),
            });
        }
        Ok(())
    }
}

impl StorageBackend for OneEio {
    fn kind(&self) -> &'static str {
        "eio"
    }
    fn read(&self, path: &VPath) -> Result<Vec<u8>> {
        self.inner.read(path)
    }
    fn write(&self, path: &VPath, data: &[u8]) -> Result<()> {
        self.tick(path)?;
        self.inner.write(path, data)
    }
    fn create_new(&self, path: &VPath, data: &[u8]) -> Result<bool> {
        self.tick(path)?;
        self.inner.create_new(path, data)
    }
    fn remove_file(&self, path: &VPath) -> Result<()> {
        self.tick(path)?;
        self.inner.remove_file(path)
    }
    fn remove_dir_all(&self, path: &VPath) -> Result<()> {
        self.tick(path)?;
        self.inner.remove_dir_all(path)
    }
    fn create_dir_all(&self, path: &VPath) -> Result<()> {
        self.inner.create_dir_all(path)
    }
    fn list_dir(&self, path: &VPath) -> Result<Vec<DirEntry>> {
        self.inner.list_dir(path)
    }
    fn metadata(&self, path: &VPath) -> Result<Option<Metadata>> {
        self.inner.metadata(path)
    }
    fn set_executable(&self, path: &VPath, x: bool) -> Result<()> {
        self.inner.set_executable(path, x)
    }
}

/// Each mutation of a gc run (prune with a pack rewrite, consolidation, a
/// merge) fails in turn: the run reports the error or completes, every
/// object reachable before is readable, `fsck` is clean, and the next gc
/// succeeds.
#[test]
fn eio_at_any_step_of_maintenance_loses_nothing() {
    let base = Arc::new(MemoryBackend::new());
    let id = Identity::generate("alice");
    let mut repo = Repo::init(base.clone(), Some(id.clone()), "alice").unwrap();
    let mut snaps = Vec::new();
    for i in 0..4 {
        snaps.push(commit_files(&mut repo, &*base, &[(&format!("f{i}.txt"), &format!("{i}\n").repeat(30))], "c"));
        gc(&mut repo, &GcOptions::default()).unwrap();
    }
    let gone = commit_files(&mut repo, &*base, &[("tmp.txt", "garbage soon\n")], "tmp");
    repo.abandon(gone).unwrap();
    for i in 0..4 {
        repo.store().put(&Object::Blob(format!("unreferenced {i}").into_bytes())).unwrap();
    }
    drop(repo);
    let opts = GcOptions { grace: Duration::ZERO, keep_ops: Some(Duration::ZERO), now: Some(veil_core::now_millis() + 60_000), ..GcOptions::default() };
    let mut failures = 0;
    for fail_at in 0..400 {
        let disk = Arc::new(base.fork());
        let eio = Arc::new(OneEio { inner: disk.clone(), fail_at, seen: AtomicUsize::new(0), failed: AtomicBool::new(false) });
        let fs: Arc<dyn StorageBackend> = eio.clone();
        let mut r = Repo::open(fs.clone(), Some(id.clone()), "alice").unwrap();
        let out = gc(&mut r, &opts);
        drop(r);
        if !eio.failed.load(Ordering::SeqCst) {
            out.unwrap();
            break;
        }
        failures += 1;
        let ctx = format!("EIO at mutation {fail_at} ({out:?})");
        let plain: Arc<dyn StorageBackend> = disk.clone();
        let r = Repo::open(plain.clone(), Some(id.clone()), "alice").unwrap_or_else(|e| panic!("{ctx}: {e}"));
        for s in &snaps {
            assert!(!read_at(&r, s, "f0.txt").is_empty(), "{ctx}");
        }
        drop(r);
        assert_fsck_clean(plain.clone(), &id, &ctx);
        let mut r = Repo::open(plain.clone(), Some(id.clone()), "alice").unwrap();
        gc(&mut r, &opts).unwrap_or_else(|e| panic!("{ctx}: the next gc failed: {e}"));
        assert_fsck_clean(plain, &id, &format!("{ctx}, after the next gc"));
    }
    assert!(failures > 10, "too few mutations to sweep ({failures})");
}

// ---- remote loose objects ---------------------------------------------------------------

/// A remote's loose objects are spooled to disk for a pull, not held in
/// memory, and each is checked against its id: a corrupt one is never
/// used. The spool is gone afterwards.
#[test]
fn a_pulls_remote_loose_objects_are_spooled_and_checked() {
    let (mut alice, fs, id) = new_repo("alice");
    let c = commit_files(&mut alice, &*fs, &[("a.txt", "a\n"), ("b.txt", "b\n")], "c");
    alice.set_tag("main", c, false).unwrap();
    let hub = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, hub.clone(), false, &[], false).unwrap();
    // Unpack the hub: every object loose.
    let hub_repo = Repo::open_remote(hub.clone()).unwrap();
    let all = hub_repo.store().list_objects().unwrap();
    for o in &all {
        let raw = hub_repo.store().get_raw(o).unwrap();
        plant_raw_object(&*hub, o, &raw);
    }
    drop(hub_repo);
    for f in hub.list_dir(&p(".veil/objects/pack")).unwrap_or_default() {
        hub.remove_file(&p(&format!(".veil/objects/pack/{}", f.name))).unwrap();
    }
    let (mut bob, bfs) = repo_for("bob", &id);
    remote::pull(&mut bob, "origin", hub.clone()).unwrap();
    assert_eq!(read_at(&bob, &c, "a.txt"), b"a\n");
    assert!(bfs.list_dir(&p(".veil/objects/incoming")).map(|v| v.is_empty()).unwrap_or(true));
    // A corrupt loose object on the remote is not taken.
    let c2 = commit_files(&mut alice, &*fs, &[("c.txt", "c-811\n")], "c2");
    alice.set_tag("main", c2, false).unwrap();
    remote::push(&mut alice, hub.clone(), false, &[], false).unwrap();
    let blob_id = ObjectId::hash(&Object::Blob(b"c-811\n".to_vec()).encode());
    let path = p(&format!(".veil/objects/{}/{}", &blob_id.hex()[..2], &blob_id.hex()[2..]));
    assert!(hub.exists(&path).unwrap(), "control: the pushed blob is a loose object on the remote");
    hub.write(&path, b"veil:blob\nnot what it should be").unwrap();
    let err = remote::pull(&mut bob, "origin", hub.clone()).unwrap_err().to_string();
    assert!(err.contains("content does not match its hash"), "{err}");
    assert!(bob.store().get_raw(&blob_id).map_or(true, |raw| ObjectId::hash(&raw) == blob_id));
    assert_fsck_clean(bfs, &id, "after pulling loose objects");
}

// ---- threat 14: two gcs on a format-5 repository --------------------------------------
