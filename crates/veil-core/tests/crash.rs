//! Crash-injection tests.
//!
//! `FaultyBackend` wraps a `MemoryBackend` (the "disk") and lets the first N
//! mutations through. Mutation N+1 "crashes": it fails (optionally after
//! being applied, the way a write can reach the disk just before the process
//! dies), and so does every later mutation, as if the process was gone.
//! `MemoryBackend` writes are atomic, which models `DiskBackend`'s durable
//! temp-file + fsync + rename + fsync-dir writes.
//!
//! Transactions write objects with `write_unsynced` and make them durable
//! with one `sync_barrier` (itself a mutation that can crash) before writing
//! the operation. The third crash mode, `PowerLoss`, models the machine
//! losing power: besides losing the fatal write, every unsynced write since
//! the last barrier is torn (removed, emptied or truncated, in turn) under
//! its final name. The retry must then not build on a torn object: the lock
//! takeover discards them first (`fsck::recover_interrupted_writes`).
//!
//! A fourth fault is not a crash: a barrier that fails with EIO
//! (`EioBackend`), with Linux's semantics afterwards (the failed files stay
//! readable but never reach the disk, and a retried barrier succeeds without
//! writing them). The command reports the error, the user runs it again, then
//! the power fails: nothing the retry acknowledged may be lost. Swept over
//! every barrier of every operation, also with a disk that refuses to remove
//! files right after the failure (the lock is then left for recovery).
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
    collections::{BTreeMap, HashSet},
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
    vfs::{DirEntry, Metadata, StatClock},
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
    /// The fatal write is lost and so is every write not yet covered by a
    /// sync barrier: those files are torn.
    PowerLoss,
}

#[derive(Debug)]
struct FaultyBackend {
    inner: Arc<MemoryBackend>,
    mode: Crash,
    /// Mutations still allowed before the crash.
    left: Mutex<usize>,
    crashed: AtomicBool,
    mutations: AtomicUsize,
    /// Unsynced writes since the last barrier.
    volatile: Mutex<Vec<VPath>>,
    tore: AtomicBool,
}

impl FaultyBackend {
    fn new(inner: Arc<MemoryBackend>, budget: usize, mode: Crash) -> Self {
        FaultyBackend {
            inner,
            mode,
            left: Mutex::new(budget),
            crashed: AtomicBool::new(false),
            mutations: AtomicUsize::new(0),
            volatile: Mutex::new(Vec::new()),
            tore: AtomicBool::new(false),
        }
    }

    fn tore_anything(&self) -> bool {
        self.tore.load(Ordering::SeqCst)
    }

    /// Power loss: what never reached stable storage is torn.
    fn tear_volatile(&self) {
        let mut volatile = self.volatile.lock().unwrap();
        self.tore.fetch_or(!volatile.is_empty(), Ordering::SeqCst);
        for (i, path) in volatile.drain(..).enumerate() {
            match i % 3 {
                0 => self.inner.remove_file(&path).unwrap(),
                1 => self.inner.write(&path, b"").unwrap(),
                _ => {
                    let data = self.inner.read(&path).unwrap();
                    self.inner.write(&path, &data[..data.len() / 2]).unwrap();
                }
            }
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
            match self.mode {
                Crash::AfterWrite => {
                    let _ = f();
                }
                Crash::PowerLoss => self.tear_volatile(),
                Crash::BeforeWrite => {}
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
    fn write_unsynced(&self, path: &VPath, data: &[u8]) -> Result<()> {
        self.mutate(|| {
            self.inner.write(path, data)?;
            self.volatile.lock().unwrap().push(path.clone());
            Ok(())
        })
    }
    fn sync_barrier(&self) -> Result<()> {
        self.mutate(|| {
            self.volatile.lock().unwrap().clear();
            Ok(())
        })
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

// ---- failing barriers ----------------------------------------------------------

/// A disk whose `fail_at`-th barrier (counting from 0) fails once with EIO.
/// Like Linux since 4.13, the error is reported once and the failed pages
/// are marked clean: the files read back fine but are not on disk, and no
/// later barrier writes them. Only rewriting a file (a new copy) makes it
/// durable again. `power_loss` tears whatever is not durable.
#[derive(Debug)]
struct EioBackend {
    inner: Arc<MemoryBackend>,
    fail_at: usize,
    barriers: AtomicUsize,
    failed: AtomicBool,
    /// While set, removing an object fails too (the lock file can still be
    /// removed, so only a lock deliberately left behind triggers recovery).
    refuse_removes: AtomicBool,
    /// Written unsynced since the last successful barrier.
    volatile: Mutex<HashSet<VPath>>,
    /// Covered by the failed barrier: never durable unless rewritten.
    lost: Mutex<HashSet<VPath>>,
}

impl EioBackend {
    fn new(inner: Arc<MemoryBackend>, fail_at: usize, refuse_removes: bool) -> Self {
        EioBackend {
            inner,
            fail_at,
            barriers: AtomicUsize::new(0),
            failed: AtomicBool::new(false),
            refuse_removes: AtomicBool::new(refuse_removes),
            volatile: Mutex::default(),
            lost: Mutex::default(),
        }
    }

    fn durable(&self, path: &VPath) {
        self.volatile.lock().unwrap().remove(path);
        self.lost.lock().unwrap().remove(path);
    }

    fn eio() -> VeilError {
        VeilError::Io {
            path: "<simulated disk>".into(),
            source: io::Error::other("EIO: writeback failed"),
        }
    }

    /// Tear every file that is not durable, as `FaultyBackend` does.
    fn power_loss(&self) {
        let mut gone: Vec<VPath> = self.volatile.lock().unwrap().drain().collect();
        gone.extend(self.lost.lock().unwrap().drain());
        gone.sort();
        for (i, path) in gone.iter().enumerate() {
            let Some(data) = self.inner.read_opt(path).unwrap() else { continue };
            match i % 3 {
                0 => self.inner.remove_file(path).unwrap(),
                1 => self.inner.write(path, b"").unwrap(),
                _ => self.inner.write(path, &data[..data.len() / 2]).unwrap(),
            }
        }
    }
}

impl StorageBackend for EioBackend {
    fn kind(&self) -> &'static str {
        "eio"
    }
    fn read(&self, path: &VPath) -> Result<Vec<u8>> {
        self.inner.read(path)
    }
    fn write(&self, path: &VPath, data: &[u8]) -> Result<()> {
        self.inner.write(path, data)?;
        self.durable(path);
        Ok(())
    }
    fn write_unsynced(&self, path: &VPath, data: &[u8]) -> Result<()> {
        self.inner.write(path, data)?;
        self.lost.lock().unwrap().remove(path);
        self.volatile.lock().unwrap().insert(path.clone());
        Ok(())
    }
    fn sync_barrier(&self) -> Result<()> {
        let mut volatile = self.volatile.lock().unwrap();
        if self.barriers.fetch_add(1, Ordering::SeqCst) == self.fail_at {
            self.failed.store(true, Ordering::SeqCst);
            self.lost.lock().unwrap().extend(volatile.drain());
            return Err(Self::eio());
        }
        volatile.clear();
        Ok(())
    }
    fn create_new(&self, path: &VPath, data: &[u8]) -> Result<bool> {
        let created = self.inner.create_new(path, data)?;
        if created {
            self.durable(path);
        }
        Ok(created)
    }
    fn remove_file(&self, path: &VPath) -> Result<()> {
        if self.refuse_removes.load(Ordering::SeqCst) && path.as_str().starts_with(".veil/objects/") {
            return Err(Self::eio());
        }
        self.inner.remove_file(path)?;
        self.durable(path);
        Ok(())
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
    fn set_executable(&self, path: &VPath, executable: bool) -> Result<()> {
        self.inner.set_executable(path, executable)
    }
    fn stat_clock(&self) -> Option<StatClock> {
        self.inner.stat_clock()
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
    let mut torn = 0;
    for mode in [Crash::BeforeWrite, Crash::AfterWrite, Crash::PowerLoss] {
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
            torn += usize::from(mode == Crash::PowerLoss && faulty.crashed() && faulty.tore_anything());
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
    assert!(torn > 0, "{name}: no power loss ever tore an unsynced write");
}

/// Sweep `op` across every barrier failing in turn (see `EioBackend`): the
/// command may fail, the user runs it again, which must succeed, then the
/// power fails. The repository must be healthy, with every earlier snapshot
/// intact, and everything the retry recorded must still be readable (a
/// reachable torn object is corruption for `fsck`).
fn eio_sweep(name: &str, target: Target, op: Op) {
    let w = world();
    for refuse_removes in [false, true] {
        let mut failures = 0;
        for fail_at in 0..1000 {
            let local = Arc::new(w.local.fork());
            let stale = Arc::new(w.stale.fork());
            let remote_old = Arc::new(w.remote_old.fork());
            let target_disk = match target {
                Target::Local => local.clone(),
                Target::Stale => stale.clone(),
                Target::RemoteOld => remote_old.clone(),
            };
            let eio = Arc::new(EioBackend::new(target_disk.clone(), fail_at, refuse_removes));
            let pick = |t: Target, plain: Arc<MemoryBackend>| -> Arc<dyn StorageBackend> {
                if t == target {
                    eio.clone()
                } else {
                    plain
                }
            };
            let env = Env {
                id: w.id.clone(),
                local: pick(Target::Local, local),
                stale: pick(Target::Stale, stale),
                remote_old: pick(Target::RemoteOld, remote_old),
                remote: Arc::new(w.remote.fork()),
                v3: w.v3,
                side: w.side,
            };
            let ctx = format!("{name}: barrier {fail_at} fails (removals refused: {refuse_removes})");
            let disk: Arc<dyn StorageBackend> = eio.clone();
            let before = env.open(&disk).unwrap();
            let before_history = history(&before);
            drop(before);

            let first = op(&env);
            if !eio.failed.load(Ordering::SeqCst) {
                first.unwrap_or_else(|e| panic!("{ctx}: failed without a fault: {e}"));
                break;
            }
            failures += 1;
            eio.refuse_removes.store(false, Ordering::SeqCst);
            op(&env).unwrap_or_else(|e| panic!("{ctx}: the retry failed: {e}"));
            drop(env);

            eio.power_loss();
            let repo = Repo::open(disk.clone(), Some(w.id.clone()), "alice")
                .unwrap_or_else(|e| panic!("{ctx}: repository does not open after power loss: {e}"));
            for (id, files) in &before_history {
                assert_eq!(&files_of(&repo, id), files, "{ctx}: snapshot {} changed", id.short());
            }
            let _ = history(&repo);
            drop(repo);
            assert_healthy(disk, &w.id, &ctx);
        }
        assert!(failures >= 1, "{name}: no barrier ever failed");
    }
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

#[test]
fn eio_during_snapshot() {
    eio_sweep("snapshot", Target::Local, |env| {
        let mut repo = env.open(&env.local)?;
        repo.snapshot_workspace(WS, &*env.local)?;
        Ok(())
    });
}

#[test]
fn eio_during_merge() {
    eio_sweep("merge", Target::Local, |env| {
        let mut repo = env.open(&env.local)?;
        repo.merge(WS, env.v3, vec![env.side], "merge side", None)?;
        Ok(())
    });
}

#[test]
fn eio_during_push() {
    eio_sweep("push", Target::RemoteOld, |env| {
        let mut repo = env.open(&env.local)?;
        remote::push(&mut repo, env.remote_old.clone(), false, &[], false)?;
        Ok(())
    });
}

#[test]
fn eio_during_pull() {
    eio_sweep("pull", Target::Stale, |env| {
        let mut repo = env.open(&env.stale)?;
        remote::pull(&mut repo, "origin", env.remote.clone())?;
        assert_eq!(repo.view().tags["main"].target, env.v3);
        Ok(())
    });
}

/// `init` writes `repo.json` last: after a crash the directory is either not
/// a repository at all (and `init` works again) or a complete, healthy one.
#[test]
fn crash_during_init() {
    let id = Identity::generate("alice");
    for mode in [Crash::BeforeWrite, Crash::AfterWrite, Crash::PowerLoss] {
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
