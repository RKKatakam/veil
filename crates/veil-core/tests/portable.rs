//! The portable engine: what the WASM build runs, tested on the host.
//!
//! Every test here runs in both configurations CI builds:
//!
//! * the default features (`cargo test -p veil-core --test portable`);
//! * the WASM feature set, natively
//!   (`cargo test -p veil-core --no-default-features --features wasm --test portable`):
//!   no `os` (no `DiskBackend`, no threads, no process checks), no zstd C
//!   library (packs read with `ruzstd`, written with stored entries).
//!
//! The scenario itself is `examples/wasm_smoke.rs`, which
//! `scripts/check-wasm.sh` also runs on `wasm32-unknown-unknown` under node.

#[allow(dead_code)]
#[path = "../examples/wasm_smoke.rs"]
mod wasm_smoke;

use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

use veil_core::{
    clock,
    fsck::{fsck, Severity},
    gc::{gc, GcOptions},
    lock::RepoLock,
    tree::lookup,
    Identity, MemoryBackend, ObjectId, Repo, StorageBackend, VPath, VeilError,
};

/// Tests that install a clock run one at a time (the clock is per process).
static CLOCK: Mutex<()> = Mutex::new(());

fn p(s: &str) -> VPath {
    VPath::new(s).unwrap()
}

fn fixtures() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures"))
}

/// Load a host directory into a fresh `MemoryBackend` (the harness may use
/// the disk; the engine under test never does).
fn load_dir(from: &Path) -> Arc<MemoryBackend> {
    fn walk(root: &Path, dir: &Path, into: &MemoryBackend) {
        for e in std::fs::read_dir(dir).unwrap() {
            let e = e.unwrap();
            let path = e.path();
            if e.file_type().unwrap().is_dir() {
                walk(root, &path, into);
            } else {
                let rel = path.strip_prefix(root).unwrap().to_str().unwrap().replace('\\', "/");
                into.write(&p(&rel), &std::fs::read(&path).unwrap()).unwrap();
            }
        }
    }
    let fs = Arc::new(MemoryBackend::new());
    walk(from, from, &fs);
    fs
}

fn read_at(repo: &Repo, rev: &ObjectId, path: &str) -> Option<Vec<u8>> {
    let tree = repo.snapshot(rev).unwrap().tree;
    let e = lookup(repo.store(), &tree, &p(path)).unwrap()?;
    repo.store().read_entry(&e).ok()
}

/// Entry kinds (0 stored, 1 zstd, 2 delta) of every pack in a backend, read
/// straight from the files (see `pack.rs` for the layout).
fn pack_entry_kinds(fs: &MemoryBackend) -> [usize; 3] {
    let mut kinds = [0; 3];
    let dir = p(".veil/objects/pack");
    for e in fs.list_dir(&dir).unwrap() {
        let Some(stem) = e.name.strip_suffix(".idx") else { continue };
        let idx = fs.read(&dir.join(&e.name)).unwrap();
        let pack = fs.read(&dir.join(&format!("{stem}.pack"))).unwrap();
        let count = u32::from_le_bytes(idx[8..12].try_into().unwrap()) as usize;
        let offsets = 12 + 256 * 4 + count * 32;
        for i in 0..count {
            let at = offsets + i * 8;
            let off = u64::from_le_bytes(idx[at..at + 8].try_into().unwrap()) as usize;
            kinds[pack[off] as usize] += 1;
        }
    }
    kinds
}

#[test]
fn the_smoke_scenario_runs() {
    let _c = CLOCK.lock().unwrap_or_else(|e| e.into_inner());
    clock::set_clock(Arc::new(|| 1_750_000_000_000i64));
    let report = wasm_smoke::smoke();
    clock::reset_clock();
    let report = report.unwrap_or_else(|e| panic!("{e}"));
    for step in ["init:", "read back:", "log:", "diff:", "seal:", "merge:", "pull:", "gc:"] {
        assert!(report.contains(step), "{step} missing from:\n{report}");
    }
    // Without zstd every packed entry is stored.
    if !cfg!(feature = "zstd") {
        assert!(report.contains("0 compressed, 0 deltas"), "{report}");
    }
}

/// Packs written by native vl (zstd frames and dictionary deltas) read
/// back exactly, also through the pure-Rust decoder.
#[test]
fn repositories_written_by_native_vl_read_and_verify() {
    for format in [veil_core::repo::REPO_FORMAT] {
        let set = fixtures().join(format!("format-{format}"));
        let fs = load_dir(&set.join("alice"));
        let kinds = pack_entry_kinds(&fs);
        assert!(kinds[1] > 0 && kinds[2] > 0, "format {format}: the fixture has compressed and delta entries: {kinds:?}");
        let id = Identity::from_json(&std::fs::read_to_string(set.join("home-alice/identity.json")).unwrap()).unwrap();
        let repo = Repo::open(fs.clone(), Some(id.clone()), "alice").unwrap();
        assert_eq!(repo.format(), format);
        assert!(repo.store().verify_packs().unwrap().is_empty(), "format {format}");
        let main = repo.view().tags["main"].target;
        assert_eq!(read_at(&repo, &main, "README.md").as_deref(), Some(&b"Fixture project\n"[..]));
        assert!(String::from_utf8(read_at(&repo, &main, "docs/big.txt").unwrap()).is_ok());
        assert_eq!(
            read_at(&repo, &main, "secrets/.env.notes").as_deref(),
            Some(&b"team-only notes v2\n"[..]),
            "format {format}: sealed content unseals"
        );
        // Every object, packed or loose, decodes to its id; the history
        // and signatures check out.
        for oid in repo.store().list_objects().unwrap() {
            repo.store().get_raw(&oid).unwrap_or_else(|e| panic!("format {format}: {}: {e}", oid.short()));
        }
        let report = fsck(fs, Some(id)).unwrap();
        let bad: Vec<String> = report
            .findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::Corrupt | Severity::Warning))
            .map(|f| f.to_string())
            .collect();
        assert!(bad.is_empty(), "format {format}: fsck: {bad:#?}");
    }
}

#[test]
fn the_installed_clock_stamps_snapshots_and_operations() {
    let _c = CLOCK.lock().unwrap_or_else(|e| e.into_inner());
    let t = 1_234_567_890_123i64;
    clock::set_clock(Arc::new(move || t));
    assert!(clock::clock_installed());
    let fs = Arc::new(MemoryBackend::new());
    let mut repo = Repo::init(fs.clone(), Some(Identity::generate("t")), "t").unwrap();
    fs.write(&p("a.txt"), b"a\n").unwrap();
    let wc = repo.snapshot_workspace("default", &*fs).unwrap().snapshot;
    let snap_ts = repo.snapshot(&wc).unwrap().timestamp;
    let op_ts = repo.op_log(1).unwrap()[0].1.timestamp;
    clock::reset_clock();
    assert_eq!(snap_ts, t);
    // The clock stands still: the snapshot's operation is a millisecond
    // after its parent, the init's (never at or before a parent's time).
    assert_eq!(op_ts, t + 1);
    assert!(!clock::clock_installed());
}

#[test]
fn gc_packs_read_back_after_reopening() {
    let fs = Arc::new(MemoryBackend::new());
    let mut repo = Repo::init(fs.clone(), Some(Identity::generate("g")), "g").unwrap();
    let mut text = String::new();
    for i in 0..5 {
        for j in 0..200 {
            text.push_str(&format!("line {j} of version {i}\n"));
        }
        fs.write(&p("big.txt"), text.as_bytes()).unwrap();
        repo.snapshot_workspace("default", &*fs).unwrap();
        repo.commit_working_copy("default", &format!("v{i}")).unwrap();
    }
    let opts = GcOptions {
        grace: Duration::ZERO,
        ..GcOptions::default()
    };
    let report = gc(&mut repo, &opts).unwrap();
    if cfg!(feature = "zstd") {
        assert!(report.pack_stats.compressed + report.pack_stats.deltas > 0, "{:?}", report.pack_stats);
    } else {
        assert_eq!(report.pack_stats.stored, report.pack_stats.objects, "{:?}", report.pack_stats);
        assert_eq!(pack_entry_kinds(&fs)[1..], [0, 0]);
    }
    let id = repo.identity().cloned();
    drop(repo);
    let repo = Repo::open(fs.clone(), id, "g").unwrap();
    assert!(repo.store().verify_packs().unwrap().is_empty());
    let wc = repo.workspace_wc("default").unwrap();
    let parent = repo.snapshot(&wc).unwrap().parents[0];
    assert_eq!(read_at(&repo, &parent, "big.txt").unwrap(), text.as_bytes());
    // A second gc repacks the pack it wrote.
    let mut repo = repo;
    gc(&mut repo, &opts).unwrap();
    assert_eq!(read_at(&repo, &parent, "big.txt").unwrap(), text.as_bytes());
}

/// Without `os`: a held lock fails at once (no thread can release it while
/// we wait, and there is no clock to wait on), a lock this instance leaked
/// is reclaimed, and another instance's lock is never taken.
#[cfg(not(feature = "os"))]
#[test]
fn without_os_locks_fail_fast_reclaim_leaks_and_never_rob_others() {
    use veil_core::lock::LOCK_PATH;
    let fs: Arc<dyn StorageBackend> = Arc::new(MemoryBackend::new());
    let held = RepoLock::acquire(fs.clone()).unwrap();
    let raw = fs.read(&p(LOCK_PATH)).unwrap();
    let text = String::from_utf8(raw.clone()).unwrap();
    assert!(text.contains("\"host\":\"instance-"), "{text}");
    assert!(text.contains("\"pid\":0"), "{text}");
    let started = std::time::Instant::now();
    match RepoLock::acquire(fs.clone()) {
        Err(VeilError::Locked(_)) => {}
        other => panic!("expected Locked, got {other:?}"),
    }
    assert!(started.elapsed() < Duration::from_secs(2));

    // Leaked: our own host, a token no live lock of this instance holds.
    drop(held);
    fs.write(&p(LOCK_PATH), &raw).unwrap();
    let again = RepoLock::acquire(fs.clone()).expect("a leaked lock of this instance is reclaimed");
    drop(again);

    // Another instance (another random host name): never robbed.
    let foreign = text.replacen("\"host\":\"instance-", "\"host\":\"instance-other", 1);
    fs.write(&p(LOCK_PATH), foreign.as_bytes()).unwrap();
    assert!(matches!(RepoLock::acquire(fs.clone()), Err(VeilError::Locked(_))));
    assert_eq!(fs.read(&p(LOCK_PATH)).unwrap(), foreign.as_bytes(), "left alone");
}

/// The same lock protocol with `os`, for comparison: a held lock is waited
/// for (and here, given up on after the configured wait).
#[cfg(feature = "os")]
#[test]
fn with_os_a_held_lock_is_waited_for() {
    let fs: Arc<dyn StorageBackend> = Arc::new(MemoryBackend::new());
    let _held = RepoLock::acquire(fs.clone()).unwrap();
    let opts = veil_core::lock::LockOptions {
        wait: Duration::from_millis(200),
        ..Default::default()
    };
    let started = std::time::Instant::now();
    assert!(matches!(RepoLock::acquire_with(fs.clone(), &opts), Err(VeilError::Locked(_))));
    assert!(started.elapsed() >= Duration::from_millis(200));
}

/// With `VEIL_PORTABLE_EXPORT=<dir>`: write a repository built by this
/// engine (with a gc pack, a sealed file, a merge) to `<dir>/repo`, and its
/// owner's identity to `<dir>/home/identity.json`, for native `vl` to open
/// (`scripts/check-wasm.sh` runs `vl fsck`, `log` and `cat` on it). Without
/// the variable, the same repository is built and checked in memory.
#[test]
fn a_repository_for_native_vl() {
    let fs = Arc::new(MemoryBackend::new());
    let id = Identity::generate("alice");
    let mut repo = Repo::init(fs.clone(), Some(id.clone()), "alice").unwrap();
    fs.write(&p(".veilpolicy"), b"secrets/ cloak team\n").unwrap();
    fs.write(&p("secrets/.env.plan"), b"team-only plan\n").unwrap();
    fs.write(&p("README.md"), b"written without an operating system\n").unwrap();
    repo.snapshot_workspace("default", &*fs).unwrap();
    let (first, _) = repo.commit_working_copy("default", "portable: first").unwrap();
    let ws = repo.ephemeral_workspace(first).unwrap();
    ws.write("src/lib.rs", "pub fn portable() {}\n").unwrap();
    let (side, _) = repo.commit_ephemeral(&ws, "portable: side").unwrap();
    let wc = repo.workspace_wc("default").unwrap();
    repo.merge("default", wc, vec![side], "portable: merge", None).unwrap();
    gc(
        &mut repo,
        &GcOptions {
            grace: Duration::ZERO,
            ..GcOptions::default()
        },
    )
    .unwrap();
    // Loose objects after the pack, too. (The engine's merge does not
    // check out: put the merged-in file into the working copy as well.)
    fs.write(&p("src/lib.rs"), b"pub fn portable() {}\n").unwrap();
    fs.write(&p("NOTES.txt"), b"after gc\n").unwrap();
    repo.snapshot_workspace("default", &*fs).unwrap();
    repo.commit_working_copy("default", "portable: after gc").unwrap();
    assert!(repo.store().stats().unwrap().packs >= 1);
    drop(repo);

    let Some(dir) = std::env::var_os("VEIL_PORTABLE_EXPORT") else { return };
    let dir = Path::new(&dir);
    fn export(fs: &MemoryBackend, from: &VPath, to: &Path) {
        for e in fs.list_dir(from).unwrap() {
            let child = from.join(&e.name);
            let path = to.join(&e.name);
            match e.kind {
                veil_core::vfs::NodeKind::Dir => {
                    std::fs::create_dir_all(&path).unwrap();
                    export(fs, &child, &path);
                }
                veil_core::vfs::NodeKind::File => std::fs::write(&path, fs.read(&child).unwrap()).unwrap(),
                veil_core::vfs::NodeKind::Symlink => {}
            }
        }
    }
    std::fs::create_dir_all(dir.join("repo")).unwrap();
    std::fs::create_dir_all(dir.join("home")).unwrap();
    export(&fs, &VPath::root(), &dir.join("repo"));
    std::fs::write(dir.join("home/identity.json"), id.to_json()).unwrap();
}

/// S27: the web client reads the server's compressed objects. A frame the
/// `zstd` tool wrote (level 3) decodes to its object, bounded by the
/// limit, with the pure decoder as with the C library; a plain object is
/// its own encoding.
#[test]
fn compressed_objects_from_the_server_decode() {
    use veil_core::hub::encoding;
    let raw = [&b"veil:blob\n"[..], &b"portable ".repeat(40)].concat();
    let id = ObjectId::hash(&raw);
    let enc = [
        &[encoding::ZSTD][..],
        &[
            0x28, 0xb5, 0x2f, 0xfd, 0x64, 0x72, 0x00, 0xd5, 0x00, 0x00, 0x98, 0x76, 0x65, 0x69, 0x6c, 0x3a, 0x62, 0x6c, 0x6f, 0x62, 0x0a,
            0x70, 0x6f, 0x72, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x20, 0x01, 0x00, 0xb9, 0xa8, 0x96, 0x30, 0x0c, 0xca, 0xa2, 0xb4,
        ],
    ]
    .concat();
    assert_eq!(&*encoding::decode(&id, &enc, 1 << 20).unwrap(), &raw[..]);
    assert!(encoding::decode(&id, &enc, raw.len() as u64 - 1).is_err());
    assert!(encoding::decode(&ObjectId::hash(b"veil:blob\n"), &enc, 1 << 20).is_err());
    assert_eq!(&*encoding::decode(&id, &raw, 1 << 20).unwrap(), &raw[..]);
    // Every encoding decodes back, whichever form `encode` keeps.
    assert_eq!(&*encoding::decode(&id, &encoding::encode(&raw), 1 << 20).unwrap(), &raw[..]);
}

// ---- op log merges review: operation times and the clock ---------------------------

/// Install a clock that reads `now` (milliseconds), settable while it runs.
fn settable_clock(start: i64) -> Arc<std::sync::atomic::AtomicI64> {
    let now = Arc::new(std::sync::atomic::AtomicI64::new(start));
    let n = now.clone();
    clock::set_clock(Arc::new(move || n.load(std::sync::atomic::Ordering::SeqCst)));
    now
}

/// Put what `side` (a fork taken with head files `heads_at_fork`) wrote on
/// `disk`: new files of the shared directories, and the head files it removed.
fn land_fork(disk: &MemoryBackend, side: &MemoryBackend, heads_at_fork: &[String]) {
    for f in side.files() {
        let s = f.as_str();
        let shared = [".veil/objects/", ".veil/ops/", ".veil/op_heads/", ".veil/meta/"].iter().any(|d| s.starts_with(d));
        if shared && !s.contains("/incoming/") && !disk.exists(&f).unwrap() {
            disk.write(&f, &side.read(&f).unwrap()).unwrap();
        }
    }
    let now: Vec<String> = side.list_dir(&p(".veil/op_heads")).unwrap().into_iter().map(|e| e.name).collect();
    for h in heads_at_fork.iter().filter(|h| !now.contains(h)) {
        disk.remove_file(&p(&format!(".veil/op_heads/{h}"))).unwrap();
    }
}

fn head_names(fs: &MemoryBackend) -> Vec<String> {
    fs.list_dir(&p(".veil/op_heads")).unwrap().into_iter().map(|e| e.name).collect()
}

/// The `base_time` clamp (BUG-1297 fix): with the clock set back, the next
/// operations take a millisecond after the newest parent's time (strictly
/// later, so times still separate a command from its parents, BUG-1485,
/// BUG-1486); a clock set forward moves them on. Operations stay newest first in the op log either way, and
/// `vl undo` undoes the last one.
#[test]
fn operation_times_never_go_back_and_the_log_stays_in_order() {
    let _c = CLOCK.lock().unwrap_or_else(|e| e.into_inner());
    let t = 1_800_000_000_000i64;
    let now = settable_clock(t + 3_600_000);
    let fs = Arc::new(MemoryBackend::new());
    let mut repo = Repo::init(fs.clone(), Some(Identity::generate("t")), "t").unwrap();
    let root = repo.root_id();
    repo.set_tag("a", root, false).unwrap();
    let ahead = repo.op_log(1).unwrap()[0].1.timestamp;
    // Set back an hour: every later operation is a millisecond after its parent.
    now.store(t, std::sync::atomic::Ordering::SeqCst);
    for n in ["b", "c", "d"] {
        repo.set_tag(n, root, false).unwrap();
    }
    let log = repo.op_log(4).unwrap();
    let times: Vec<i64> = log.iter().map(|(_, o)| o.timestamp).collect();
    let descs: Vec<String> = log.iter().map(|(_, o)| o.description.clone()).collect();
    // Set forward: time moves on.
    now.store(t + 7_200_000, std::sync::atomic::Ordering::SeqCst);
    repo.set_tag("e", root, false).unwrap();
    let last = repo.op_log(1).unwrap()[0].1.timestamp;
    repo.undo().unwrap();
    let undone = !repo.view().tags.contains_key("e") && repo.view().tags.contains_key("d");
    clock::reset_clock();
    assert_eq!(times, vec![ahead + 3, ahead + 2, ahead + 1, ahead], "a millisecond after the newest parent's time");
    assert!(descs[0].contains("'d'") || descs[0].contains(" d"), "the newest first: {descs:?}");
    assert!(descs[3].contains("'a'") || descs[3].contains(" a"), "the oldest last: {descs:?}");
    assert_eq!(last, t + 7_200_000);
    assert!(undone, "undo undid the last operation");
}

/// Two identical commands (same user, same heads, same millisecond) write
/// one operation: they had one effect. A command that saw the first, and
/// moved the tag on, keeps its move when the second lands later (its
/// head file comes back for an operation already merged).
#[test]
fn identical_commands_in_one_millisecond_are_one_operation() {
    let _c = CLOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _now = settable_clock(1_800_000_000_000);
    let me = Identity::generate("alice");
    let disk = Arc::new(MemoryBackend::new());
    let (x, y) = {
        let mut repo = Repo::init(disk.clone(), Some(me.clone()), "alice").unwrap();
        let root = repo.root_id();
        repo.create_workspace("w", vec![root]).unwrap();
        let ov = repo.workspace_overlay("w").unwrap();
        ov.write(&p("x"), b"x\n").unwrap();
        repo.snapshot_workspace("w", &ov).unwrap();
        let (x, y) = repo.commit_working_copy("w", "x").unwrap();
        repo.set_tag("t", root, false).unwrap();
        (x, y)
    };
    let heads = head_names(&disk);
    let (f1, f2) = (Arc::new(disk.fork()), Arc::new(disk.fork()));
    let mut ids = Vec::new();
    for f in [&f1, &f2] {
        let mut r = Repo::open(f.clone(), Some(me.clone()), "alice").unwrap();
        r.set_tag("t", x, true).unwrap();
        ids.push(r.op_id());
    }
    let one_op = ids[0] == ids[1];
    land_fork(&disk, &f1, &heads);
    // A later command saw the first and moves the tag on.
    let heads2 = head_names(&disk);
    let f3 = Arc::new(disk.fork());
    {
        let mut r = Repo::open(f3.clone(), Some(me.clone()), "alice").unwrap();
        assert_eq!(r.view().tags["t"].target, x);
        r.set_tag("t", y, true).unwrap();
    }
    land_fork(&disk, &f3, &heads2);
    land_fork(&disk, &f2, &heads);
    let mut r = Repo::open(disk.clone(), Some(me.clone()), "alice").unwrap();
    let (target, settled, warnings) = (r.view().tags["t"].target, r.heads().len(), r.take_warnings());
    clock::reset_clock();
    assert!(one_op, "two identical commands wrote one operation");
    assert_eq!(settled, 1, "settled");
    assert_eq!(target, y, "the later move, which saw the first, stays");
    assert!(warnings.is_empty(), "no conflict: {warnings:?}");
}

/// `vl op restore` takes back a release staged after the operation it
/// restores (BUG-109), even when the clock was set back before. The
/// `base_time` clamp stamps operations with a parent's time, later than
/// the clock, while a release is stamped with the clock: comparing the
/// two misses a release staged after the operation, which then stays
/// staged and goes out with the next push.
#[test]
fn bug_1400_restore_takes_back_a_release_staged_after_it_with_the_clock_set_back() {
    let _c = CLOCK.lock().unwrap_or_else(|e| e.into_inner());
    let t = 1_800_000_000_000i64;
    // The clock an hour ahead, then set right.
    let now = settable_clock(t + 3_600_000);
    let fs = Arc::new(MemoryBackend::new());
    let mut repo = Repo::init(fs.clone(), Some(Identity::generate("alice")), "alice").unwrap();
    fs.write(&p("auth.rs"), b"fn check() -> bool { true }\n").unwrap();
    repo.snapshot_workspace("default", &*fs).unwrap();
    let (main, _) = repo.commit_working_copy("default", "v1").unwrap();
    repo.create_workspace("fix", vec![main]).unwrap();
    let ov = repo.workspace_overlay("fix").unwrap();
    ov.write(&p("auth.rs"), b"fn check() -> bool { verify_signature() }\n").unwrap();
    let fix = repo.snapshot_workspace("fix", &ov).unwrap().snapshot;
    let merged = repo.merge("default", main, vec![fix], "merge", Some(veil_core::commands::EmbargoSpec { scope: "team".into(), until: None }));
    now.store(t, std::sync::atomic::Ordering::SeqCst);
    repo.set_tag("main", main, false).unwrap();
    let before = repo.op_id();
    now.store(t + 60_000, std::sync::atomic::Ordering::SeqCst);
    let e = merged.as_ref().ok().and_then(|m| m.embargo.clone());
    let released = e.as_ref().map(|e| repo.release_embargo(e));
    let staged = e.as_ref().map(|e| repo.keys().release_state(e));
    let restored = repo.restore_operation(before);
    let after = e.as_ref().map(|e| repo.keys().release_state(e));
    clock::reset_clock();
    let e = merged.unwrap().embargo.expect("an embargo");
    released.unwrap().unwrap();
    assert_eq!(staged, Some(veil_core::keychain::ReleaseState::Staged), "{e}: the release is staged");
    restored.unwrap();
    assert_eq!(after, Some(veil_core::keychain::ReleaseState::Unreleased), "the restore to before the release took it back");
}

/// BUG-1400's other direction: a release staged with the clock ahead, then
/// an operation after it with the clock set right. Restoring that
/// operation keeps the release (it came before), though its time is the
/// later one.
#[test]
fn restore_keeps_a_release_staged_before_it_with_the_clock_ahead() {
    let _c = CLOCK.lock().unwrap_or_else(|e| e.into_inner());
    let t = 1_800_000_000_000i64;
    let now = settable_clock(t);
    let fs = Arc::new(MemoryBackend::new());
    let mut repo = Repo::init(fs.clone(), Some(Identity::generate("alice")), "alice").unwrap();
    fs.write(&p("auth.rs"), b"fn check() -> bool { true }\n").unwrap();
    repo.snapshot_workspace("default", &*fs).unwrap();
    let (main, _) = repo.commit_working_copy("default", "v1").unwrap();
    repo.create_workspace("fix", vec![main]).unwrap();
    let ov = repo.workspace_overlay("fix").unwrap();
    ov.write(&p("auth.rs"), b"fn check() -> bool { verify_signature() }\n").unwrap();
    let fix = repo.snapshot_workspace("fix", &ov).unwrap().snapshot;
    let merged = repo.merge("default", main, vec![fix], "merge", Some(veil_core::commands::EmbargoSpec { scope: "team".into(), until: None }));
    let e = merged.as_ref().ok().and_then(|m| m.embargo.clone());
    // The clock an hour ahead for the release, then set right.
    now.store(t + 3_600_000, std::sync::atomic::Ordering::SeqCst);
    let released = e.as_ref().map(|e| repo.release_embargo(e));
    now.store(t + 60_000, std::sync::atomic::Ordering::SeqCst);
    let tagged = repo.set_tag("main", main, false);
    let after_release = repo.op_id();
    now.store(t + 120_000, std::sync::atomic::Ordering::SeqCst);
    let tagged2 = repo.set_tag("next", main, false);
    let restored = repo.restore_operation(after_release);
    let state = e.as_ref().map(|e| repo.keys().release_state(e));
    clock::reset_clock();
    let e = merged.unwrap().embargo.expect("an embargo");
    released.unwrap().unwrap();
    tagged.unwrap();
    tagged2.unwrap();
    restored.unwrap();
    assert_eq!(state, Some(veil_core::keychain::ReleaseState::Staged), "{e}: the release, staged before the restored operation, stays");
}

/// BUG-1402 through `vl undo`: with one time for every operation (the
/// clock set back, so each takes its parent's), the operation `vl undo`
/// undoes is the newest by the op log, not the one whose id sorts first.
/// `a` then `b` are tags set in turn (repository-wide); `o`, concurrent
/// with `b`, is another workspace's. Merged, undo in `w` undoes `b`.
#[test]
fn undo_with_the_clock_set_back_undoes_the_newest_command() {
    let _c = CLOCK.lock().unwrap_or_else(|e| e.into_inner());
    let t = 1_800_000_000_000i64;
    let mut cases = 0;
    for _ in 0..200 {
        let now = settable_clock(t + 3_600_000);
        let me = Identity::generate("alice");
        let disk = Arc::new(MemoryBackend::new());
        let root = {
            let mut repo = Repo::init(disk.clone(), Some(me.clone()), "alice").unwrap();
            let root = repo.root_id();
            repo.create_workspace("w", vec![root]).unwrap();
            repo.create_workspace("v", vec![root]).unwrap();
            root
        };
        now.store(t, std::sync::atomic::Ordering::SeqCst);
        let (a, b, o);
        {
            let mut repo = Repo::open(disk.clone(), Some(me.clone()), "alice").unwrap();
            repo.set_tag("a", root, false).unwrap();
            a = repo.op_id();
        }
        let heads = head_names(&disk);
        let (f1, f2) = (Arc::new(disk.fork()), Arc::new(disk.fork()));
        {
            let mut repo = Repo::open(f1.clone(), Some(me.clone()), "alice").unwrap();
            repo.set_tag("b", root, false).unwrap();
            b = repo.op_id();
        }
        {
            let mut repo = Repo::open(f2.clone(), Some(me.clone()), "alice").unwrap();
            repo.set_command_workspace(Some("v".into()));
            let ov = repo.workspace_overlay("v").unwrap();
            ov.write(&p("v.txt"), b"v\n").unwrap();
            repo.snapshot_workspace("v", &ov).unwrap();
            repo.commit_working_copy("v", "v").unwrap();
            o = repo.op_id();
        }
        // The id order that walked `a` before `b`.
        if !(a > b && o > b) {
            continue;
        }
        cases += 1;
        land_fork(&disk, &f1, &heads);
        land_fork(&disk, &f2, &heads);
        let mut repo = Repo::open(disk.clone(), Some(me.clone()), "alice").unwrap();
        let settled = repo.heads().len();
        let undone = repo.undo_keeping_edits("w").map(|(_, d)| d);
        let tags: Vec<String> = repo.view().tags.keys().cloned().collect();
        clock::reset_clock();
        assert_eq!(settled, 1, "settled");
        let undone = undone.unwrap();
        assert!(undone.contains("'b'") || undone.contains(" b"), "undid the newest command, not {undone:?}");
        assert_eq!(tags, vec!["a".to_string()], "b undone, a kept");
        if cases == 3 {
            break;
        }
    }
    clock::reset_clock();
    assert!(cases > 0, "the id order ran");
}

/// BUG-1404 (op log merges review, cycle 2): `vl op restore` reads which
/// releases came after the restored operation from the heads this process
/// read when it opened (`Repo::releases_after`), and the restore's own
/// transaction reads them again. A release another process (a second
/// terminal, an agent) staged in between is reached by the restore, which
/// takes the view back to before it, but is not taken back: it stays
/// staged and goes out with the next push. Before the fix (times compared)
/// it was taken back.
#[test]
fn bug_1404_restore_takes_back_a_release_staged_meanwhile_by_another_process() {
    let _c = CLOCK.lock().unwrap_or_else(|e| e.into_inner());
    let t = 1_800_000_000_000i64;
    let now = settable_clock(t);
    let fs = Arc::new(MemoryBackend::new());
    let me = Identity::generate("alice");
    let mut repo = Repo::init(fs.clone(), Some(me.clone()), "alice").unwrap();
    fs.write(&p("auth.rs"), b"fn check() -> bool { true }\n").unwrap();
    repo.snapshot_workspace("default", &*fs).unwrap();
    let (main, _) = repo.commit_working_copy("default", "v1").unwrap();
    repo.create_workspace("fix", vec![main]).unwrap();
    let ov = repo.workspace_overlay("fix").unwrap();
    ov.write(&p("auth.rs"), b"fn check() -> bool { verify_signature() }\n").unwrap();
    let fix = repo.snapshot_workspace("fix", &ov).unwrap().snapshot;
    let merged = repo.merge("default", main, vec![fix], "merge", Some(veil_core::commands::EmbargoSpec { scope: "team".into(), until: None }));
    let e = merged.as_ref().ok().and_then(|m| m.embargo.clone());
    now.store(t + 60_000, std::sync::atomic::Ordering::SeqCst);
    let tagged = repo.set_tag("main", main, false);
    let before = repo.op_id();
    // `repo` has read the op log; another process releases the embargo now.
    now.store(t + 120_000, std::sync::atomic::Ordering::SeqCst);
    let released = e.as_ref().map(|e| Repo::open(fs.clone(), Some(me.clone()), "alice").and_then(|mut other| other.release_embargo(e)));
    let staged = e.as_ref().map(|e| repo.keys().release_state(e));
    now.store(t + 180_000, std::sync::atomic::Ordering::SeqCst);
    let restored = repo.restore_operation(before);
    let after = e.as_ref().map(|e| repo.keys().release_state(e));
    // The restore descends from the release (its view is from before it).
    let reaches = restored.as_ref().ok().map(|r| {
        let since = repo.ops().split(&[*r], &[before]).unwrap().only_a;
        since.iter().any(|o| repo.ops().get(o).unwrap().description.starts_with(veil_core::commands::RELEASE_OP_PREFIX))
    });
    clock::reset_clock();
    let e = merged.unwrap().embargo.expect("an embargo");
    tagged.unwrap();
    released.unwrap().unwrap();
    assert_eq!(staged, Some(veil_core::keychain::ReleaseState::Staged), "{e}: the release is staged");
    restored.unwrap();
    assert_eq!(reaches, Some(true), "the restore reaches the release operation");
    assert_eq!(after, Some(veil_core::keychain::ReleaseState::Unreleased), "the restore to before the release took it back");
}

/// Op log merges review, cycle 3 (guarantee: a staged release is never
/// published early): a release another process staged, taken back by an
/// op restore past it (the CLI's path: `restore_operation_keeping_edits`,
/// then `releases_restored`), stays taken back through an undo of the
/// restore, a redo of that undo, and their merge with a concurrent
/// command: undo, redo and merges never release.
#[test]
fn a_release_taken_back_by_a_restore_stays_taken_back_through_undo_redo_and_merges() {
    let _c = CLOCK.lock().unwrap_or_else(|e| e.into_inner());
    clock::reset_clock();
    let fs = Arc::new(MemoryBackend::new());
    let me = Identity::generate("alice");
    let mut repo = Repo::init(fs.clone(), Some(me.clone()), "alice").unwrap();
    fs.write(&p("auth.rs"), b"fn check() -> bool { true }\n").unwrap();
    repo.snapshot_workspace("default", &*fs).unwrap();
    let (main, _) = repo.commit_working_copy("default", "v1").unwrap();
    repo.create_workspace("fix", vec![main]).unwrap();
    let ov = repo.workspace_overlay("fix").unwrap();
    ov.write(&p("auth.rs"), b"fn check() -> bool { verify_signature() }\n").unwrap();
    let fix = repo.snapshot_workspace("fix", &ov).unwrap().snapshot;
    let merged = repo.merge("default", main, vec![fix], "merge", Some(veil_core::commands::EmbargoSpec { scope: "team".into(), until: None })).unwrap();
    let e = merged.embargo.expect("an embargo");
    repo.set_tag("main", main, false).unwrap();
    let before = repo.op_id();
    // Another process releases it; this one restores past the release.
    Repo::open(fs.clone(), Some(me.clone()), "alice").unwrap().release_embargo(&e).unwrap();
    assert_eq!(repo.keys().release_state(&e), veil_core::keychain::ReleaseState::Staged, "staged");
    let restore = repo.restore_operation_keeping_edits("default", before).unwrap();
    let (staged, published) = repo.releases_restored(&restore).unwrap();
    assert_eq!((staged.clone(), published), (vec![e.clone()], vec![]), "the restore took the view back past the staged release");
    for s in &staged {
        repo.keys().take_back_release(s).unwrap();
    }
    let unreleased = veil_core::keychain::ReleaseState::Unreleased;
    assert_eq!(repo.keys().release_state(&e), unreleased, "taken back");
    // Undo of the restore and a redo of that undo, while another process
    // runs a command; then the merge.
    let heads = head_names(&fs);
    let side = Arc::new(fs.fork());
    Repo::open(side.clone(), Some(me.clone()), "alice").unwrap().set_tag("other", main, false).unwrap();
    let (_, undone) = repo.undo_keeping_edits("default").unwrap();
    assert!(undone.starts_with("restore to operation"), "undid the restore: {undone}");
    assert_eq!(repo.keys().release_state(&e), unreleased, "the undo of the restore does not release");
    let (_, redone) = repo.redo_keeping_edits("default").unwrap();
    assert!(redone.contains("restore to operation"), "redid the restore's undo: {redone}");
    assert_eq!(repo.keys().release_state(&e), unreleased, "nor the redo");
    land_fork(&fs, &side, &heads);
    let repo = Repo::open(fs.clone(), Some(me.clone()), "alice").unwrap();
    assert_eq!(repo.heads().len(), 1, "merged");
    assert!(repo.view().tags.contains_key("other"), "the concurrent command stays");
    assert_eq!(repo.keys().release_state(&e), unreleased, "nor the merge");
}

/// BUG-1487 (op log merges review, cycle 3; pre-existing): `vl op restore`
/// and `vl undo` commit the restored view first and take back the staged
/// releases it went back past afterwards (`releases_restored`, then
/// `take_back_release`; `check_undo_release`, then `finish_undo_release`).
/// A process that stops between the two (killed, a crash, the machine
/// off) leaves the release staged although the op log records the restore
/// past it, and nothing takes it back later: the next push publishes the
/// embargoed fix. Here the restore is committed as `vl op restore`
/// records it, and the process stops there.
#[test]
fn bug_1487_a_restore_that_stops_before_taking_back_a_release_still_takes_it_back() {
    let _c = CLOCK.lock().unwrap_or_else(|e| e.into_inner());
    clock::reset_clock();
    let fs = Arc::new(MemoryBackend::new());
    let me = Identity::generate("alice");
    let mut repo = Repo::init(fs.clone(), Some(me.clone()), "alice").unwrap();
    fs.write(&p("auth.rs"), b"fn check() -> bool { true }\n").unwrap();
    repo.snapshot_workspace("default", &*fs).unwrap();
    let (main, _) = repo.commit_working_copy("default", "v1").unwrap();
    repo.create_workspace("fix", vec![main]).unwrap();
    let ov = repo.workspace_overlay("fix").unwrap();
    ov.write(&p("auth.rs"), b"fn check() -> bool { verify_signature() }\n").unwrap();
    let fix = repo.snapshot_workspace("fix", &ov).unwrap().snapshot;
    let merged = repo.merge("default", main, vec![fix], "merge", Some(veil_core::commands::EmbargoSpec { scope: "team".into(), until: None })).unwrap();
    let e = merged.embargo.expect("an embargo");
    repo.set_tag("main", main, false).unwrap();
    let before = repo.op_id();
    repo.release_embargo(&e).unwrap();
    assert_eq!(repo.keys().release_state(&e), veil_core::keychain::ReleaseState::Staged, "staged");
    // The restore's operation, as `vl op restore` commits it; then the
    // process stops.
    let view = repo.ops().get(&before).unwrap().view;
    let mut tx = repo.transaction(format!("restore to operation {}", before.short())).unwrap();
    tx.view = view;
    tx.restore_of(before);
    let restore = tx.commit().unwrap().expect("recorded");
    let (staged, _) = repo.releases_restored(&restore).unwrap();
    assert_eq!(staged, vec![e.clone()], "the op log says the restore went back past the staged release");
    drop(repo);
    // The next process pushes: the push checks the staged release against
    // the op log, which says the restore took it back, so it is not
    // published, and the push says so (BUG-1487, BUG-1533: checked at the
    // push, where the guarantee lives, not at every open).
    let mut next = Repo::open(fs.clone(), Some(me.clone()), "alice").unwrap();
    next.set_tag("later", main, false).unwrap();
    let report = veil_core::remote::push(&mut next, Arc::new(MemoryBackend::new()), true, &[], false).unwrap();
    assert!(report.releases_published.is_empty(), "the taken-back release was published: {:?}", report.releases_published);
    assert!(report.warnings.iter().any(|w| w.contains(&e) && w.contains("not published")), "the push said so: {:?}", report.warnings);
    assert_eq!(next.keys().release_state(&e), veil_core::keychain::ReleaseState::Unreleased, "taken back");
}

/// BUG-1535 (op log merges review, cycle 5): a retractor stopped before
/// its take-back, then itself taken back, revives the release. `vl op
/// restore` past a staged release (or `vl undo` of the release) commits
/// first and takes the release back after; the process stops between the
/// two. The next command takes the retractor back (an undo of the
/// restore; an op restore to just after the release, past the undo).
/// Run to the end, the first command took the release back for good, and
/// undo and restore never release (`a_release_taken_back_by_a_restore_
/// stays_taken_back_through_undo_redo_and_merges`). Stopped, the push's
/// check reads the retractor as not in force (`retracted_commands`), so
/// the release counts as in force and the push publishes the embargoed
/// fix the user took back.
#[test]
fn bug_1535_a_stopped_take_back_whose_retractor_is_taken_back_still_takes_the_release_back() {
    let _c = CLOCK.lock().unwrap_or_else(|e| e.into_inner());
    for shape in ["undo of the restore", "restore past the undo"] {
        clock::reset_clock();
        let fs = Arc::new(MemoryBackend::new());
        let me = Identity::generate("alice");
        let mut repo = Repo::init(fs.clone(), Some(me.clone()), "alice").unwrap();
        fs.write(&p("auth.rs"), b"fn check() -> bool { true }\n").unwrap();
        repo.snapshot_workspace("default", &*fs).unwrap();
        let (main, _) = repo.commit_working_copy("default", "v1").unwrap();
        repo.create_workspace("fix", vec![main]).unwrap();
        let ov = repo.workspace_overlay("fix").unwrap();
        ov.write(&p("auth.rs"), b"fn check() -> bool { verify_signature() }\n").unwrap();
        let fix = repo.snapshot_workspace("fix", &ov).unwrap().snapshot;
        let merged = repo.merge("default", main, vec![fix], "merge", Some(veil_core::commands::EmbargoSpec { scope: "team".into(), until: None })).unwrap();
        let e = merged.embargo.expect("an embargo");
        repo.set_tag("main", main, false).unwrap();
        let before = repo.op_id();
        repo.release_embargo(&e).unwrap();
        let release = repo.op_id();
        assert_eq!(repo.keys().release_state(&e), veil_core::keychain::ReleaseState::Staged, "{shape}: staged");
        // The retractor's operation, as `vl op restore` or `vl undo`
        // commits it; then the process stops, before the take-back.
        let view = repo.ops().get(&before).unwrap().view;
        let desc = match shape {
            "undo of the restore" => format!("restore to operation {}", before.short()),
            _ => format!("undo: release embargo {e}"),
        };
        let mut tx = repo.transaction(desc).unwrap();
        tx.view = view;
        match shape {
            "undo of the restore" => tx.restore_of(before),
            _ => tx.undo_of(release),
        }
        tx.commit().unwrap().expect("recorded");
        drop(repo);
        // The next process takes the retractor back.
        let mut next = Repo::open(fs.clone(), Some(me.clone()), "alice").unwrap();
        match shape {
            "undo of the restore" => {
                let (_, undone) = next.undo_keeping_edits("default").unwrap();
                assert!(undone.starts_with("restore to operation"), "undid the restore: {undone}");
            }
            _ => {
                next.restore_operation_keeping_edits("default", release).unwrap();
            }
        }
        let report = veil_core::remote::push(&mut next, Arc::new(MemoryBackend::new()), true, &[], false).unwrap();
        assert!(report.releases_published.is_empty(), "{shape}: the release taken back was published: {:?}", report.releases_published);
        assert_eq!(next.keys().release_state(&e), veil_core::keychain::ReleaseState::Unreleased, "{shape}: taken back");
    }
}

/// A memory backend that counts the operations read (`.veil/ops/`).
#[derive(Debug, Default)]
struct CountingOps {
    inner: MemoryBackend,
    reads: std::sync::atomic::AtomicUsize,
}

impl StorageBackend for CountingOps {
    fn kind(&self) -> &'static str {
        "counting"
    }
    fn read(&self, path: &VPath) -> veil_core::Result<Vec<u8>> {
        if path.as_str().starts_with(".veil/ops/") {
            self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
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
    fn list_dir(&self, path: &VPath) -> veil_core::Result<Vec<veil_core::vfs::DirEntry>> {
        self.inner.list_dir(path)
    }
    fn metadata(&self, path: &VPath) -> veil_core::Result<Option<veil_core::vfs::Metadata>> {
        self.inner.metadata(path)
    }
    fn set_executable(&self, path: &VPath, x: bool) -> veil_core::Result<()> {
        self.inner.set_executable(path, x)
    }
}

/// An op log of `n` tag moves made with the clock set back an hour (the
/// `base_time` clamp then stamps them with their parents' time), and two
/// concurrent commands on it, one from each of two processes: the
/// repository, with the two heads not merged yet.
fn same_time_run_with_two_heads(n: usize) -> (Arc<MemoryBackend>, Identity) {
    let t = 1_800_000_000_000i64;
    let now = settable_clock(t + 3_600_000);
    let me = Identity::generate("alice");
    let disk = Arc::new(MemoryBackend::new());
    let (root, other) = {
        let mut repo = Repo::init(disk.clone(), Some(me.clone()), "alice").unwrap();
        disk.write(&p("x"), b"x\n").unwrap();
        repo.snapshot_workspace("default", &*disk).unwrap();
        let (c, _) = repo.commit_working_copy("default", "x").unwrap();
        (repo.root_id(), c)
    };
    now.store(t, std::sync::atomic::Ordering::SeqCst);
    {
        let mut repo = Repo::open(disk.clone(), Some(me.clone()), "alice").unwrap();
        for i in 0..n {
            repo.set_tag("t", if i % 2 == 0 { other } else { root }, true).unwrap();
        }
        assert_eq!(repo.op_log(n).unwrap().len(), n, "every move recorded");
    }
    let heads = head_names(&disk);
    let (f1, f2) = (Arc::new(disk.fork()), Arc::new(disk.fork()));
    for (f, name) in [(&f1, "a"), (&f2, "b")] {
        Repo::open(f.clone(), Some(me.clone()), "alice").unwrap().set_tag(name, root, true).unwrap();
    }
    land_fork(&disk, &f1, &heads);
    land_fork(&disk, &f2, &heads);
    assert_eq!(head_names(&disk).len(), 2, "two heads");
    (disk, me)
}

/// BUG-1486 (op log merges review, cycle 3): with the clock set back, a
/// merge reads the whole run of operations of one time. The clamp stamps
/// every command with its parents' time while the clock is behind (an
/// hour set back, an hour of operations), and BUG-1297's fix ends the
/// split of two heads only below every operation walked as one side's,
/// which a common operation of the same time never is: merging two heads
/// on a run of 500 reads all 500, once per head. On `integration` the
/// split of the same two heads reads a handful.
#[test]
fn bug_1486_merging_two_heads_with_the_clock_set_back_reads_a_few_operations() {
    let _c = CLOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (disk, me) = same_time_run_with_two_heads(500);
    let counting = Arc::new(CountingOps { inner: disk.fork(), reads: Default::default() });
    let repo = Repo::open(counting.clone(), Some(me.clone()), "alice");
    let reads = counting.reads.load(std::sync::atomic::Ordering::SeqCst);
    clock::reset_clock();
    let repo = repo.unwrap();
    assert_eq!(repo.heads().len(), 1, "merged");
    assert!(repo.view().tags.contains_key("a") && repo.view().tags.contains_key("b"), "both commands kept");
    assert!(reads <= 60, "merging two heads on a run of 500 operations of one time read {reads} operations");
}

/// BUG-1485 (op log merges review, cycle 3): with the clock set back, the
/// first operations of the op log below a merge cost the whole run of one
/// time. Once the merge of two concurrent commands is listed, both are
/// queued with one time, and the walk searches below each for the other,
/// through every operation of that time: `vl op log -n 5`, `vl undo`,
/// `vl redo` and `resolve_prefix` read all 500 on every call. BUG-1433's
/// fix covers a line of operations, not a merge on one.
#[test]
fn bug_1485_the_op_log_below_a_merge_with_the_clock_set_back_reads_a_few_operations() {
    let _c = CLOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (disk, me) = same_time_run_with_two_heads(500);
    let merged = Repo::open(disk.clone(), Some(me.clone()), "alice");
    let counting = Arc::new(CountingOps { inner: disk.fork(), reads: Default::default() });
    let repo = Repo::open(counting.clone(), Some(me.clone()), "alice");
    let opened = counting.reads.load(std::sync::atomic::Ordering::SeqCst);
    let log = repo.as_ref().map(|r| r.op_log(5));
    let reads = counting.reads.load(std::sync::atomic::Ordering::SeqCst) - opened;
    clock::reset_clock();
    assert_eq!(merged.unwrap().heads().len(), 1, "merged");
    let log = log.unwrap().unwrap();
    assert_eq!(log.len(), 5, "five listed");
    assert!(log[0].1.parents.len() == 2, "the merge first");
    assert!(reads <= 20, "the first five operations, below a merge on a run of 500 of one time, read {reads} operations");
}

/// BUG-1533 (op log merges review, cycle 4; introduced by BUG-1487's
/// fix): while a release is staged, every open walks the op log from the
/// heads down to the release's operation (`take_back_releases_out_of_force`,
/// run at open whenever a release is staged), reading each operation with
/// its view: a release staged and not pushed for 1,000 commands makes
/// every later command read 1,000 operations. Without a staged release the
/// same open reads a handful.
#[test]
fn bug_1533_an_open_with_a_staged_release_reads_a_few_operations() {
    let _c = CLOCK.lock().unwrap_or_else(|e| e.into_inner());
    clock::reset_clock();
    let fs = Arc::new(MemoryBackend::new());
    let me = Identity::generate("alice");
    let mut repo = Repo::init(fs.clone(), Some(me.clone()), "alice").unwrap();
    fs.write(&p("auth.rs"), b"fn check() -> bool { true }\n").unwrap();
    repo.snapshot_workspace("default", &*fs).unwrap();
    let (main, _) = repo.commit_working_copy("default", "v1").unwrap();
    repo.create_workspace("fix", vec![main]).unwrap();
    let ov = repo.workspace_overlay("fix").unwrap();
    ov.write(&p("auth.rs"), b"fn check() -> bool { verify_signature() }\n").unwrap();
    let fix = repo.snapshot_workspace("fix", &ov).unwrap().snapshot;
    let merged = repo.merge("default", main, vec![fix], "merge", Some(veil_core::commands::EmbargoSpec { scope: "team".into(), until: None })).unwrap();
    let e = merged.embargo.expect("an embargo");
    repo.release_embargo(&e).unwrap();
    let root = repo.root_id();
    for i in 0..1000 {
        repo.set_tag("t", if i % 2 == 0 { main } else { root }, true).unwrap();
    }
    drop(repo);
    let reads_at_open = |staged: bool| {
        let counting = Arc::new(CountingOps { inner: fs.fork(), reads: Default::default() });
        if !staged {
            Repo::open(counting.clone(), Some(me.clone()), "alice").unwrap().keys().take_back_release(&e).unwrap();
            counting.reads.store(0, std::sync::atomic::Ordering::SeqCst);
        }
        let repo = Repo::open(counting.clone(), Some(me.clone()), "alice").unwrap();
        let state = repo.keys().release_state(&e);
        (counting.reads.load(std::sync::atomic::Ordering::SeqCst), state)
    };
    let (without, state) = reads_at_open(false);
    assert_eq!(state, veil_core::keychain::ReleaseState::Unreleased, "taken back by hand");
    let (with, state) = reads_at_open(true);
    assert_eq!(state, veil_core::keychain::ReleaseState::Staged, "the release stands");
    assert!(with <= without + 20, "an open with a release staged 1,000 commands ago read {with} operations ({without} without it)");
}

/// BUG-1485 and BUG-1486 with eight heads (op log merges review, cycle 4):
/// on a run of 500 operations made with the clock set back, merging eight
/// concurrent commands at open, and the op log's first operations below
/// the merge, read a few operations per head, not the run.
#[test]
fn merging_eight_heads_with_the_clock_set_back_reads_a_few_operations_per_head() {
    let _c = CLOCK.lock().unwrap_or_else(|e| e.into_inner());
    let t = 1_800_000_000_000i64;
    let now = settable_clock(t + 3_600_000);
    let me = Identity::generate("alice");
    let disk = Arc::new(MemoryBackend::new());
    let (root, other) = {
        let mut repo = Repo::init(disk.clone(), Some(me.clone()), "alice").unwrap();
        disk.write(&p("x"), b"x\n").unwrap();
        repo.snapshot_workspace("default", &*disk).unwrap();
        let (c, _) = repo.commit_working_copy("default", "x").unwrap();
        (repo.root_id(), c)
    };
    now.store(t, std::sync::atomic::Ordering::SeqCst);
    {
        let mut repo = Repo::open(disk.clone(), Some(me.clone()), "alice").unwrap();
        for i in 0..500 {
            repo.set_tag("t", if i % 2 == 0 { other } else { root }, true).unwrap();
        }
    }
    let heads = head_names(&disk);
    let names = ["ha", "hb", "hc", "hd", "he", "hf", "hg", "hh"];
    let forks: Vec<Arc<MemoryBackend>> = names.iter().map(|_| Arc::new(disk.fork())).collect();
    for (f, name) in forks.iter().zip(names) {
        Repo::open(f.clone(), Some(me.clone()), "alice").unwrap().set_tag(name, root, true).unwrap();
    }
    for f in &forks {
        land_fork(&disk, f, &heads);
    }
    assert_eq!(head_names(&disk).len(), 8, "eight heads");
    let counting = Arc::new(CountingOps { inner: disk.fork(), reads: Default::default() });
    let repo = Repo::open(counting.clone(), Some(me.clone()), "alice");
    let merge_reads = counting.reads.load(std::sync::atomic::Ordering::SeqCst);
    let log = repo.as_ref().ok().map(|r| r.op_log(10).map(|l| l.len()));
    let log_reads = counting.reads.load(std::sync::atomic::Ordering::SeqCst) - merge_reads;
    clock::reset_clock();
    let repo = repo.unwrap();
    assert_eq!(repo.heads().len(), 1, "merged");
    for n in names {
        assert!(repo.view().tags.contains_key(n), "{n} kept");
    }
    assert_eq!(log.unwrap().unwrap(), 10, "ten listed");
    assert!(merge_reads <= 8 * 60, "merging eight heads on a run of 500 read {merge_reads} operations");
    assert!(log_reads <= 8 * 20, "the first ten operations below the merge read {log_reads} operations");
    // Nine processes wrote with the clock set back: every command is
    // strictly later than its parents, a merge at its newest parent's time.
    let all: Vec<ObjectId> = repo.ops().walk(repo.heads()).map(|r| r.unwrap().0).collect();
    assert!(all.len() > 500, "the whole log walked: {}", all.len());
    for id in &all {
        let op = repo.ops().get(id).unwrap();
        let Some(newest) = op.parents.iter().map(|p| repo.ops().get(p).unwrap().timestamp).max() else { continue };
        if op.is_merge() {
            assert_eq!(op.timestamp, newest, "a merge has its newest parent's time");
        } else {
            assert!(op.timestamp > newest, "'{}' at {} is not after its parent at {newest}", op.description, op.timestamp);
        }
    }
    eprintln!("eight heads: the merge read {merge_reads}, the log {log_reads}");
}

#[test]
fn web_client_portable_helpers_have_no_secret_decryption_and_verify_signatures() {
    use veil_core::{
        crypto::Envelope,
        hub::{
            grant::{Grant, GrantBody},
            project::empty_tree_id,
            web::{
                classify_file_meta, diff_text_bounded, inspect_object_no_secrets, seal_new_browser_device, verify_grant_token,
                WebFileState, WebObjectSummary,
            },
        },
        identity::SeedSigner,
        object::{Object, Snapshot},
    };

    let _c = CLOCK.lock().unwrap_or_else(|e| e.into_inner());
    clock::set_clock(Arc::new(|| 1_750_000_000_000i64));
    let alice = Identity::generate("alice");

    // 1. Sealed objects and sealed/non-content metadata are strictly Sealed and never leak markers.
    let marker = b"PORTABLE_WEB_SECRET_CANARY_99887766";
    let env = Envelope::seal_deterministic(&[9u8; 32], "team#0102030405060708", marker).unwrap();
    let raw_sealed = Object::Sealed(env).encode();
    let summary = inspect_object_no_secrets(&raw_sealed).unwrap();
    assert_eq!(summary, WebObjectSummary::Sealed);
    let json = serde_json::to_string(&summary).unwrap();
    assert!(!json.contains("PORTABLE_WEB_SECRET_CANARY_99887766"));
    assert_eq!(classify_file_meta(r#"{"sealed":true,"encoding":"object","kind":"file"}"#).unwrap(), WebFileState::Sealed);
    assert_eq!(classify_file_meta(r#"{"sealed":false,"encoding":"object","kind":"file"}"#).unwrap(), WebFileState::Sealed);

    // 2. Signed snapshots verify, tampered snapshots fail signature_valid.
    let mut snap = Snapshot::root(empty_tree_id());
    snap.author = "alice".into();
    snap.timestamp = 1_750_000_000_000;
    snap.sign(&alice);
    let raw_snap = Object::Snapshot(snap.clone()).encode();
    match inspect_object_no_secrets(&raw_snap).unwrap() {
        WebObjectSummary::Snapshot { signature_valid, .. } => assert_eq!(signature_valid, Some(true)),
        other => panic!("expected Snapshot summary, got {other:?}"),
    }
    let mut tampered = snap;
    tampered.author = "mallory".into();
    let raw_tampered = Object::Snapshot(tampered).encode();
    match inspect_object_no_secrets(&raw_tampered).unwrap() {
        WebObjectSummary::Snapshot { signature_valid, .. } => assert_eq!(signature_valid, Some(false)),
        other => panic!("expected Snapshot summary, got {other:?}"),
    }

    // 3. Grant verification and bounded diffing.
    let signer = SeedSigner::from_seed(&[3u8; 32]);
    let grant = Grant::issue(
        &signer,
        &GrantBody {
            project: "acme".into(),
            device: Some(alice.verifying_hex()),
            root: empty_tree_id(),
            epoch: 1,
            person_epoch: 2,
            expires: 2_000_000_000_000,
        },
    );
    assert!(verify_grant_token(&grant, &signer.verifying_hex(), 1_750_000_000_000).is_some());
    assert!(verify_grant_token(&grant, &signer.verifying_hex(), 2_000_000_000_000).is_none());

    let diff = diff_text_bounded("line 1\nold\n", "line 1\nnew\n", 1024);
    assert!(!diff.binary && !diff.too_large);
    assert_eq!(diff.hunks.len(), 1);
    assert!(diff_text_bounded("a\0b", "a\0c", 1024).binary);
    assert!(diff_text_bounded("1234567890", "1234567899", 4).too_large);

    // 4. Passkey-PRF browser device generation produces a separate device with encrypted private keys.
    let bundle = seal_new_browser_device("alice", "cred-portable-1", &[0x33; 32]).unwrap();
    assert!(bundle.public_identity.starts_with("veil1"));
    assert_ne!(bundle.signing_key, alice.verifying_hex());
    assert!(!bundle.sealed_identity_hex.contains("signing_seed"));
    clock::reset_clock();
}

#[test]
fn web_browser_device_prf_sealing_and_worker_secret_decryption() {
    use std::collections::BTreeMap;
    use veil_core::{
        crypto::Envelope,
        hub::{
            access::AccessPolicy,
            web::seal_new_browser_device,
            web_secrets::{open_secret_in_worker, verify_sealed_browser_device},
        },
        keychain::{project_fingerprint, Keychain},
        object::Object,
        policy::rule_scope,
        vfs::MemoryBackend,
        ObjectId,
    };

    let _c = CLOCK.lock().unwrap_or_else(|e| e.into_inner());
    clock::set_clock(Arc::new(|| 1_750_000_000_000i64));

    let bob_vl = Identity::generate("bob");
    let prf = [0xa5u8; 32];
    let cred_id = "cred-bob-passkey-1";
    let browser = seal_new_browser_device("bob", cred_id, &prf).unwrap();
    assert_ne!(browser.signing_key, bob_vl.verifying_hex(), "browser device must never copy vl keys");
    assert_ne!(browser.member_id, bob_vl.public_hex());

    let verified = verify_sealed_browser_device(cred_id, &prf, &browser.sealed_identity_hex).unwrap();
    assert_eq!(verified.public_identity, browser.public_identity);
    assert_eq!(verified.fingerprint, browser.fingerprint);
    assert!(verify_sealed_browser_device(cred_id, &[0x11; 32], &browser.sealed_identity_hex).is_err());
    assert!(verify_sealed_browser_device("other-cred", &prf, &browser.sealed_identity_hex).is_err());

    // Admin creates a project with `team`, `billing/` (readable to bob), and `infra/` (not readable to bob).
    let admin = Identity::generate("alice");
    let backend = Arc::new(MemoryBackend::new());
    let kc = Keychain::new(backend, Some(admin), "repo-portable-s26".into());
    kc.set_format(8);
    kc.create_scope("team").unwrap();
    let team_ring = kc.load_ring("team").unwrap().unwrap();
    let proj_id = team_ring.verify().unwrap().project.unwrap();
    let proj_fp = project_fingerprint(&proj_id);

    let access = AccessPolicy::parse("billing/ finance\ninfra/ ops\n");
    let billing_scope = rule_scope(&access, "billing");
    let infra_scope = rule_scope(&access, "infra");
    kc.create_scope(&billing_scope).unwrap();
    kc.create_scope(&infra_scope).unwrap();

    kc.grant(&billing_scope, &browser.public_identity, "bob").unwrap();

    let (bill_label_g0, bill_key_g0) = kc.sealing_key(&billing_scope).unwrap();
    let bill_blob_g0 = Object::Blob(b"STRIPE_KEY=sk_live_portable_g0\n".to_vec()).encode();
    let bill_env_g0 = Envelope::seal_deterministic(&bill_key_g0, &bill_label_g0, &bill_blob_g0).unwrap();
    let bill_raw_g0 = Object::Sealed(bill_env_g0).encode();
    let bill_oid_g0 = ObjectId::hash(&bill_raw_g0).hex();

    // Rotate while keeping browser device: browser device must open both g0 (via backward walk) and g1.
    kc.rotate(&billing_scope).unwrap();
    let (bill_label_g1, bill_key_g1) = kc.sealing_key(&billing_scope).unwrap();
    let bill_blob_g1 = Object::Blob(b"STRIPE_KEY=sk_live_portable_g1\n".to_vec()).encode();
    let bill_env_g1 = Envelope::seal_deterministic(&bill_key_g1, &bill_label_g1, &bill_blob_g1).unwrap();
    let bill_raw_g1 = Object::Sealed(bill_env_g1).encode();
    let bill_oid_g1 = ObjectId::hash(&bill_raw_g1).hex();

    let (infra_label, infra_key) = kc.sealing_key(&infra_scope).unwrap();
    let infra_blob = Object::Blob(b"ROOT_KEY=secret\n".to_vec()).encode();
    let infra_raw = Object::Sealed(Envelope::seal_deterministic(&infra_key, &infra_label, &infra_blob).unwrap()).encode();
    let infra_oid = ObjectId::hash(&infra_raw).hex();

    // Browser receives ONLY `billing` ring (no `team`, no `infra`).
    let billing_ring = kc.load_ring(&billing_scope).unwrap().unwrap();
    let mut rings = BTreeMap::new();
    rings.insert(billing_scope.clone(), serde_json::to_string(&billing_ring).unwrap());
    let rings_json = serde_json::to_string(&rings).unwrap();

    let opened_g0 = open_secret_in_worker(
        cred_id,
        &prf,
        &browser.sealed_identity_hex,
        &rings_json,
        Some(&proj_fp),
        Some(&bill_oid_g0),
        &bill_raw_g0,
    )
    .unwrap();
    assert_eq!(opened_g0.text.as_deref(), Some("STRIPE_KEY=sk_live_portable_g0\n"));

    let opened_g1 = open_secret_in_worker(
        cred_id,
        &prf,
        &browser.sealed_identity_hex,
        &rings_json,
        Some(&proj_fp),
        Some(&bill_oid_g1),
        &bill_raw_g1,
    )
    .unwrap();
    assert_eq!(opened_g1.text.as_deref(), Some("STRIPE_KEY=sk_live_portable_g1\n"));

    // Unreadable scope (`infra`), wrong project fingerprint, wrong PRF, and non-file labels all fail closed.
    assert!(open_secret_in_worker(
        cred_id,
        &prf,
        &browser.sealed_identity_hex,
        &rings_json,
        Some(&proj_fp),
        Some(&infra_oid),
        &infra_raw,
    )
    .is_err());
    assert!(open_secret_in_worker(
        cred_id,
        &prf,
        &browser.sealed_identity_hex,
        &rings_json,
        Some("1111-2222-3333-4444-5555"),
        Some(&bill_oid_g1),
        &bill_raw_g1,
    )
    .is_err());
    let vault_forged = Object::Sealed(Envelope::seal_random(&bill_key_g1, &format!("vault:{bill_label_g1}"), &Object::Blob(b"forged".to_vec()).encode()).unwrap()).encode();
    let vault_oid = ObjectId::hash(&vault_forged).hex();
    assert!(open_secret_in_worker(
        cred_id,
        &prf,
        &browser.sealed_identity_hex,
        &rings_json,
        Some(&proj_fp),
        Some(&vault_oid),
        &vault_forged,
    )
    .is_err());

    // Revoke browser device -> rotates to g2; browser device cannot open g2, and empty rings open nothing.
    kc.revoke(&billing_scope, &browser.public_identity).unwrap();
    let (bill_label_g2, bill_key_g2) = kc.sealing_key(&billing_scope).unwrap();
    let bill_blob_g2 = Object::Blob(b"STRIPE_KEY=post_revoke\n".to_vec()).encode();
    let bill_raw_g2 = Object::Sealed(
        Envelope::seal_deterministic(&bill_key_g2, &bill_label_g2, &bill_blob_g2).unwrap(),
    )
    .encode();
    let bill_oid_g2 = ObjectId::hash(&bill_raw_g2).hex();
    let revoked_ring = kc.load_ring(&billing_scope).unwrap().unwrap();
    let mut rev_rings = BTreeMap::new();
    rev_rings.insert(billing_scope, serde_json::to_string(&revoked_ring).unwrap());
    let rev_rings_json = serde_json::to_string(&rev_rings).unwrap();
    assert!(open_secret_in_worker(
        cred_id,
        &prf,
        &browser.sealed_identity_hex,
        &rev_rings_json,
        Some(&proj_fp),
        Some(&bill_oid_g2),
        &bill_raw_g2,
    )
    .is_err());
    assert!(open_secret_in_worker(
        cred_id,
        &prf,
        &browser.sealed_identity_hex,
        &rev_rings_json,
        Some(&proj_fp),
        Some(&bill_oid_g1),
        &bill_raw_g1,
    )
    .is_err());
    assert!(open_secret_in_worker(
        cred_id,
        &prf,
        &browser.sealed_identity_hex,
        "{}",
        Some(&proj_fp),
        Some(&bill_oid_g1),
        &bill_raw_g1,
    )
    .is_err());

    clock::reset_clock();
}

/// Review `rv-s26` (S26, `docs/HUB.md` §13.40): how the browser device's
/// private keys are sealed under the passkey's PRF output. The seal is
/// authenticated (any changed byte, and a changed label, fail closed), uses
/// a new nonce and a new device each time, is keyed by a key derived from
/// the PRF output under its own domain (never the PRF output itself), holds
/// nothing readable, and is not a repository secret: the Worker never opens
/// a `web-device:` envelope as a file.
#[test]
fn web_browser_device_sealing_is_authenticated_randomised_and_domain_separated() {
    use veil_core::{
        crypto::{domains, Envelope, Suite},
        hub::{
            web::{browser_device_label, seal_new_browser_device},
            web_secrets::{open_secret_in_worker, verify_sealed_browser_device},
        },
        object::Object,
    };

    let _c = CLOCK.lock().unwrap_or_else(|e| e.into_inner());
    let prf = [0x3cu8; 32];
    let cred = "cred-rv-s26";
    let a = seal_new_browser_device("carol", cred, &prf).unwrap();
    let b = seal_new_browser_device("carol", cred, &prf).unwrap();
    // The action: both open under the passkey that sealed them.
    assert_eq!(verify_sealed_browser_device(cred, &prf, &a.sealed_identity_hex).unwrap().public_identity, a.public_identity);
    assert_eq!(verify_sealed_browser_device(cred, &prf, &b.sealed_identity_hex).unwrap().public_identity, b.public_identity);

    // A new device and a new nonce each time.
    assert_ne!(a.public_identity, b.public_identity);
    let raw_a = hex::decode(&a.sealed_identity_hex).unwrap();
    let raw_b = hex::decode(&b.sealed_identity_hex).unwrap();
    let (env_a, env_b) = (Envelope::from_bytes(&raw_a).unwrap(), Envelope::from_bytes(&raw_b).unwrap());
    let nonce = |e: &Envelope| match e.suite {
        Suite::XChaCha20Poly1305 { nonce } => nonce,
        _ => panic!("the browser device is sealed with XChaCha20-Poly1305"),
    };
    assert_ne!(nonce(&env_a), nonce(&env_b), "a nonce was used twice under one key");
    assert_eq!(env_a.scope, browser_device_label(cred).unwrap());
    assert!(env_a.scope.starts_with(domains::WEB_DEVICE_IDENTITY_LABEL_PREFIX));

    // Nothing readable in what IndexedDB holds: no field name, no name, and
    // none of the public keys (so nothing says which device it is).
    for needle in ["signing_seed", "secret", "carol", &a.signing_key, &a.member_id["veil1".len()..]] {
        assert!(!raw_a.windows(needle.len()).any(|w| w == needle.as_bytes()), "the sealed record shows '{needle}'");
    }

    // Authenticated: any changed byte fails closed, in the label, the nonce
    // or the ciphertext; so does a cut record.
    for at in [0, 1, 2, raw_a.len() / 2, raw_a.len() - 1] {
        let mut bad = raw_a.clone();
        bad[at] ^= 0x01;
        assert!(verify_sealed_browser_device(cred, &prf, &hex::encode(&bad)).is_err(), "byte {at} changed and the record opened");
    }
    assert!(verify_sealed_browser_device(cred, &prf, &hex::encode(&raw_a[..raw_a.len() - 1])).is_err());
    assert!(verify_sealed_browser_device(cred, &prf, "").is_err());
    // The label is authenticated, not only compared: a record moved to
    // another credential's label does not open under that credential.
    let mut moved = Envelope::from_bytes(&raw_a).unwrap();
    moved.scope = browser_device_label("another-cred").unwrap();
    assert!(verify_sealed_browser_device("another-cred", &prf, &hex::encode(moved.to_bytes())).is_err());
    // A wrong passkey (another PRF output), also one bit away.
    let mut near = prf;
    near[31] ^= 1;
    assert!(verify_sealed_browser_device(cred, &near, &a.sealed_identity_hex).is_err());

    // Domain separation: the key is derived from the PRF output under
    // `HUB_WEB_PRF_KEY`, so a record sealed under the PRF output itself, or
    // under a key derived from it for another purpose, does not open.
    let label = browser_device_label(cred).unwrap();
    let plain = Identity::generate("carol").to_json();
    let raw_key = Envelope::seal_random(&prf, &label, plain.as_bytes()).unwrap();
    assert!(verify_sealed_browser_device(cred, &prf, &hex::encode(raw_key.to_bytes())).is_err());
    let other = blake3::derive_key(domains::HUB_WEB_SESSION, &prf);
    let other_domain = Envelope::seal_random(&other, &label, plain.as_bytes()).unwrap();
    assert!(verify_sealed_browser_device(cred, &prf, &hex::encode(other_domain.to_bytes())).is_err());
    let right = blake3::derive_key(domains::HUB_WEB_PRF_KEY, &prf);
    let same_domain = Envelope::seal_random(&right, &label, plain.as_bytes()).unwrap();
    assert!(verify_sealed_browser_device(cred, &prf, &hex::encode(same_domain.to_bytes())).is_ok(), "the documented derivation");

    // The sealed record is not a repository secret: served as a file's
    // bytes, the Worker refuses its label before any key is tried.
    let as_file = Object::Sealed(Envelope::from_bytes(&raw_a).unwrap()).encode();
    let refused = open_secret_in_worker(cred, &prf, &a.sealed_identity_hex, "{}", None, None, &as_file).unwrap_err();
    assert!(matches!(refused, VeilError::Policy(_)), "{refused:?}");
}
