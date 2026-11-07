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
    assert_eq!(op_ts, t);
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
    fs.write(&p("secrets/plan.txt"), b"team-only plan\n").unwrap();
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
