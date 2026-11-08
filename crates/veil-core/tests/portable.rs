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
    // The next process, before anything is pushed.
    let mut next = Repo::open(fs.clone(), Some(me.clone()), "alice").unwrap();
    next.set_tag("later", main, false).unwrap();
    assert_eq!(next.keys().release_state(&e), veil_core::keychain::ReleaseState::Unreleased, "the restore's take-back is not lost with the process");
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
