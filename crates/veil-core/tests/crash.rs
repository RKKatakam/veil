//! Crash-injection tests.
//!
//! `FaultyBackend` wraps a `MemoryBackend` (the "disk") and lets the first N
//! mutations through. Mutation N+1 "crashes": it fails (optionally after
//! being applied, the way a write can reach the disk just before the process
//! dies), and so does every later mutation, as if the process was gone.
//! `MemoryBackend` writes are atomic, which models `DiskBackend`'s durable
//! temp-file + fsync + rename + fsync-dir writes.
//!
//! Each operation is swept across every N until it completes. After every
//! simulated crash the "disk" is reopened and must:
//!
//! * open as a repository;
//! * pass `fsck` with no corruption and no warnings (notes about leftovers
//!   are fine);
//! * show the operation either not at all or completely (the op head is the
//!   old head or one new operation on top of it);
//! * still hold every snapshot that was visible before, with identical
//!   content;
//! * accept the same operation again (the crashed process's lock is
//!   reclaimed), after which `fsck` still passes.

use std::{
    collections::BTreeMap,
    io,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

use veil_core::{
    commands::EmbargoSpec,
    fsck::{fsck, Severity},
    remote,
    repo::is_repo,
    tree::walk_files,
    vfs::{DirEntry, Metadata},
    Identity, MemoryBackend, ObjectId, Repo, Result, StorageBackend, VPath, VeilError,
};

const WS: &str = "default";

fn p(s: &str) -> VPath {
    VPath::new(s).unwrap()
}

// ---- the faulty backend --------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Crash {
    /// The fatal write never reaches the disk.
    BeforeWrite,
    /// The fatal write reaches the disk, then the process dies.
    AfterWrite,
}

#[derive(Debug)]
struct FaultyBackend {
    inner: Arc<MemoryBackend>,
    mode: Crash,
    /// Mutations still allowed before the crash.
    left: Mutex<usize>,
    crashed: AtomicBool,
    mutations: AtomicUsize,
}

impl FaultyBackend {
    fn new(inner: Arc<MemoryBackend>, budget: usize, mode: Crash) -> Self {
        FaultyBackend {
            inner,
            mode,
            left: Mutex::new(budget),
            crashed: AtomicBool::new(false),
            mutations: AtomicUsize::new(0),
        }
    }

    fn crashed(&self) -> bool {
        self.crashed.load(Ordering::SeqCst)
    }

    fn crash_error() -> VeilError {
        VeilError::Io {
            path: "<simulated crash>".into(),
            source: io::Error::other("simulated crash"),
        }
    }

    fn mutate<T>(&self, f: impl FnOnce() -> Result<T>) -> Result<T> {
        let mut left = self.left.lock().unwrap();
        if self.crashed() {
            return Err(Self::crash_error());
        }
        if *left == 0 {
            self.crashed.store(true, Ordering::SeqCst);
            if self.mode == Crash::AfterWrite {
                let _ = f();
            }
            return Err(Self::crash_error());
        }
        *left -= 1;
        self.mutations.fetch_add(1, Ordering::SeqCst);
        f()
    }
}

impl StorageBackend for FaultyBackend {
    fn kind(&self) -> &'static str {
        "faulty"
    }
    fn read(&self, path: &VPath) -> Result<Vec<u8>> {
        self.inner.read(path)
    }
    fn write(&self, path: &VPath, data: &[u8]) -> Result<()> {
        self.mutate(|| self.inner.write(path, data))
    }
    fn create_new(&self, path: &VPath, data: &[u8]) -> Result<bool> {
        self.mutate(|| self.inner.create_new(path, data))
    }
    fn remove_file(&self, path: &VPath) -> Result<()> {
        self.mutate(|| self.inner.remove_file(path))
    }
    fn remove_dir_all(&self, path: &VPath) -> Result<()> {
        self.mutate(|| self.inner.remove_dir_all(path))
    }
    fn create_dir_all(&self, path: &VPath) -> Result<()> {
        self.mutate(|| self.inner.create_dir_all(path))
    }
    fn list_dir(&self, path: &VPath) -> Result<Vec<DirEntry>> {
        self.inner.list_dir(path)
    }
    fn metadata(&self, path: &VPath) -> Result<Option<Metadata>> {
        self.inner.metadata(path)
    }
    fn set_executable(&self, path: &VPath, executable: bool) -> Result<()> {
        self.mutate(|| self.inner.set_executable(path, executable))
    }
}

// ---- the world the operations run in ---------------------------------------------

/// Prepared "disks". Every sweep step works on fresh forks of these.
struct World {
    id: Identity,
    /// Alice's repository: history v1 → v2 → v3 (tag `main`), a side branch
    /// off v1, cloaked files, and unsnapshotted edits in the working copy.
    local: MemoryBackend,
    /// Alice's repository before v3 (for `pull`).
    stale: MemoryBackend,
    /// A team remote that has v2 but not v3 (for `push`).
    remote_old: MemoryBackend,
    /// A team remote that has v3 (for `pull`).
    remote: MemoryBackend,
    v3: ObjectId,
    side: ObjectId,
}

fn world() -> World {
    let id = Identity::generate("alice");
    let fs = Arc::new(MemoryBackend::new());
    let mut repo = Repo::init(fs.clone(), Some(id.clone()), "alice").unwrap();
    fs.write(&p(".veilpolicy"), b"secrets/ cloak team\n").unwrap();
    fs.write(&p("src/a.rs"), b"fn a() {}\n").unwrap();
    fs.write(&p("secrets/key.txt"), b"s3cr3t\n").unwrap();
    repo.snapshot_workspace(WS, &*fs).unwrap();
    let (v1, _) = repo.commit_working_copy(WS, "v1").unwrap();
    repo.set_tag("main", v1, None, false).unwrap();
    fs.write(&p("src/b.rs"), b"fn b() {}\n").unwrap();
    repo.snapshot_workspace(WS, &*fs).unwrap();
    repo.commit_working_copy(WS, "v2").unwrap();

    let ws = repo.ephemeral_workspace(v1).unwrap();
    ws.write("side.txt", "side\n").unwrap();
    ws.write("secrets/key.txt", "rotated\n").unwrap();
    let (side, _) = repo.commit_ephemeral(&ws, "side").unwrap();
    repo.set_tag("side", side, None, false).unwrap();

    let remote_old = Arc::new(MemoryBackend::new());
    remote::push(&mut repo, remote_old.clone(), false, &[], false).unwrap();
    let stale = fs.fork();

    fs.write(&p("src/c.rs"), b"fn c() {}\n").unwrap();
    repo.snapshot_workspace(WS, &*fs).unwrap();
    let (v3, _) = repo.commit_working_copy(WS, "v3").unwrap();
    let remote = Arc::new(remote_old.fork());
    remote::push(&mut repo, remote.clone(), false, &[], false).unwrap();

    // Pending, unsnapshotted working-copy edits.
    fs.write(&p("src/a.rs"), b"fn a() { edited() }\n").unwrap();
    fs.write(&p("notes.txt"), b"todo\n").unwrap();
    World {
        id,
        local: fs.fork(),
        stale,
        remote_old: remote_old.fork(),
        remote: remote.fork(),
        v3,
        side,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Target {
    Local,
    Stale,
    RemoteOld,
}

/// The backends one sweep step runs against; the target is the faulty one.
struct Env {
    id: Identity,
    local: Arc<dyn StorageBackend>,
    stale: Arc<dyn StorageBackend>,
    remote_old: Arc<dyn StorageBackend>,
    remote: Arc<dyn StorageBackend>,
    v3: ObjectId,
    side: ObjectId,
}

impl Env {
    fn open(&self, fs: &Arc<dyn StorageBackend>) -> Result<Repo> {
        Repo::open(fs.clone(), Some(self.id.clone()), "alice")
    }
}

type Op = fn(&Env) -> Result<()>;

/// Path → content (`None` if unreadable to this identity).
type Files = Vec<(String, Option<Vec<u8>>)>;

/// Every readable file of every snapshot visible in `repo`.
fn history(repo: &Repo) -> BTreeMap<ObjectId, Files> {
    let mut out = BTreeMap::new();
    for id in repo.visible_snapshots().unwrap() {
        out.insert(id, files_of(repo, &id));
    }
    out
}

fn files_of(repo: &Repo, id: &ObjectId) -> Files {
    let tree = repo.snapshot(id).unwrap().tree;
    walk_files(repo.store(), &tree)
        .unwrap()
        .into_iter()
        .map(|(path, e)| (path.to_string(), repo.store().read_entry(&e).ok()))
        .collect()
}

fn assert_healthy(fs: Arc<dyn StorageBackend>, id: &Identity, ctx: &str) {
    let report = fsck(fs, Some(id.clone())).unwrap();
    let bad: Vec<String> = report
        .findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::Corrupt | Severity::Warning))
        .map(|f| f.to_string())
        .collect();
    assert!(bad.is_empty(), "{ctx}: fsck found {bad:#?}");
}

/// Sweep `op` across every crash point, in both crash modes.
fn sweep(name: &str, target: Target, op: Op) {
    let w = world();
    let mut crashes = 0;
    for mode in [Crash::BeforeWrite, Crash::AfterWrite] {
        for budget in 0..10_000 {
            let local = Arc::new(w.local.fork());
            let stale = Arc::new(w.stale.fork());
            let remote_old = Arc::new(w.remote_old.fork());
            let target_disk = match target {
                Target::Local => local.clone(),
                Target::Stale => stale.clone(),
                Target::RemoteOld => remote_old.clone(),
            };
            let faulty = Arc::new(FaultyBackend::new(target_disk.clone(), budget, mode));
            let pick = |t: Target, plain: Arc<MemoryBackend>| -> Arc<dyn StorageBackend> {
                if t == target {
                    faulty.clone()
                } else {
                    plain
                }
            };
            let env = Env {
                id: w.id.clone(),
                local: pick(Target::Local, local.clone()),
                stale: pick(Target::Stale, stale.clone()),
                remote_old: pick(Target::RemoteOld, remote_old.clone()),
                remote: Arc::new(w.remote.fork()),
                v3: w.v3,
                side: w.side,
            };
            let ctx = format!("{name}: {mode:?} after {budget} writes");

            let disk: Arc<dyn StorageBackend> = target_disk.clone();
            let before = env.open(&disk).unwrap();
            let before_head = before.op_id();
            let before_history = history(&before);
            drop(before);

            let result = op(&env);
            drop(env);
            match result {
                Ok(()) if !faulty.crashed() => {
                    assert!(budget > 0, "{name}: the operation wrote nothing");
                    assert_healthy(disk.clone(), &w.id, &ctx);
                    break;
                }
                // Completed, then crashed while releasing the lock (which
                // `Drop` cannot report): still a crash point.
                Ok(()) => {}
                Err(e) => assert!(faulty.crashed(), "{ctx}: failed without a crash: {e}"),
            }
            crashes += 1;

            // Reboot: the process is gone, the disk is what it is.
            let repo = Repo::open(disk.clone(), Some(w.id.clone()), "alice")
                .unwrap_or_else(|e| panic!("{ctx}: repository does not open: {e}"));
            assert_healthy(disk.clone(), &w.id, &ctx);
            let head = repo.op_id();
            if head != before_head {
                let op = repo.ops().get(&head).unwrap();
                assert_eq!(
                    op.parents,
                    vec![before_head],
                    "{ctx}: exactly one operation is recorded"
                );
            }
            for (id, files) in &before_history {
                assert_eq!(&files_of(&repo, id), files, "{ctx}: snapshot {} changed", id.short());
            }
            drop(repo);

            // The same operation succeeds after recovery.
            let env = Env {
                id: w.id.clone(),
                local: local.clone(),
                stale: stale.clone(),
                remote_old: remote_old.clone(),
                remote: Arc::new(w.remote.fork()),
                v3: w.v3,
                side: w.side,
            };
            op(&env).unwrap_or_else(|e| panic!("{ctx}: retry after recovery failed: {e}"));
            assert_healthy(disk.clone(), &w.id, &format!("{ctx}, after retry"));
        }
    }
    assert!(crashes >= 2, "{name}: too few crash points ({crashes})");
}

// ---- the operations --------------------------------------------------------------

#[test]
fn crash_during_snapshot() {
    sweep("snapshot", Target::Local, |env| {
        let mut repo = env.open(&env.local)?;
        let out = repo.snapshot_workspace(WS, &*env.local)?;
        assert!(out.changed || out.report.files > 0);
        Ok(())
    });
}

#[test]
fn crash_during_commit() {
    sweep("commit", Target::Local, |env| {
        let mut repo = env.open(&env.local)?;
        repo.commit_working_copy(WS, "commit under fire")?;
        Ok(())
    });
}

#[test]
fn crash_during_rebase() {
    sweep("rebase", Target::Local, |env| {
        let mut repo = env.open(&env.local)?;
        repo.rebase(env.side, vec![env.v3])?;
        Ok(())
    });
}

#[test]
fn crash_during_merge() {
    sweep("merge", Target::Local, |env| {
        let mut repo = env.open(&env.local)?;
        repo.merge(WS, env.v3, vec![env.side], "merge side", None)?;
        Ok(())
    });
}

#[test]
fn crash_during_embargoed_merge() {
    sweep("embargoed merge", Target::Local, |env| {
        let mut repo = env.open(&env.local)?;
        let spec = EmbargoSpec {
            scope: "team".into(),
            until: None,
        };
        repo.merge(WS, env.v3, vec![env.side], "embargoed", Some(spec))?;
        Ok(())
    });
}

#[test]
fn crash_during_push() {
    sweep("push", Target::RemoteOld, |env| {
        let mut repo = env.open(&env.local)?;
        let report = remote::push(&mut repo, env.remote_old.clone(), false, &[], false)?;
        assert!(report.tags_skipped.is_empty(), "{report:?}");
        Ok(())
    });
}

#[test]
fn crash_during_public_push() {
    sweep("public push", Target::RemoteOld, |env| {
        let mut repo = env.open(&env.local)?;
        remote::push(&mut repo, env.remote_old.clone(), true, &[], false)?;
        Ok(())
    });
}

#[test]
fn crash_during_pull() {
    sweep("pull", Target::Stale, |env| {
        let mut repo = env.open(&env.stale)?;
        let report = remote::pull(&mut repo, "origin", env.remote.clone())?;
        assert!(report.warnings.is_empty(), "{report:?}");
        assert_eq!(repo.view().tags["main"].target, env.v3);
        Ok(())
    });
}

/// `init` writes `repo.json` last: after a crash the directory is either not
/// a repository at all (and `init` works again) or a complete, healthy one.
#[test]
fn crash_during_init() {
    let id = Identity::generate("alice");
    for mode in [Crash::BeforeWrite, Crash::AfterWrite] {
        for budget in 0..1000 {
            let disk = Arc::new(MemoryBackend::new());
            let faulty = Arc::new(FaultyBackend::new(disk.clone(), budget, mode));
            if Repo::init(faulty.clone(), Some(id.clone()), "alice").is_ok() {
                assert!(!faulty.crashed());
                break;
            }
            let disk: Arc<dyn StorageBackend> = disk;
            if is_repo(&*disk) {
                Repo::open(disk.clone(), Some(id.clone()), "alice").unwrap();
                assert_healthy(disk, &id, &format!("init {mode:?} {budget}"));
            } else {
                let repo = Repo::init(disk.clone(), Some(id.clone()), "alice")
                    .unwrap_or_else(|e| panic!("re-init after crash {mode:?} {budget}: {e}"));
                assert!(repo.keys().has("team"), "the default scope is usable");
                assert_healthy(disk, &id, &format!("re-init {mode:?} {budget}"));
            }
        }
    }
}
