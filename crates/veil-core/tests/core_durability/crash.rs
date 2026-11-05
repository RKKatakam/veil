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
    keychain::current_key_has_legacy_wraps,
    remote,
    repo::{is_repo, read_config},
    upgrade::{upgrade, UpgradeOptions, JOURNAL_PATH},
    working_copy::CheckoutState,
    workspace::SnapshotOptions,
    tree::{lookup, walk_files},
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
    /// Unsynced renames since the last barrier (`from`, `to`): the content
    /// is durable, the new name is not. A power loss undoes them.
    renamed: Mutex<Vec<(VPath, VPath)>>,
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
            renamed: Mutex::new(Vec::new()),
            tore: AtomicBool::new(false),
        }
    }

    fn tore_anything(&self) -> bool {
        self.tore.load(Ordering::SeqCst)
    }

    /// Power loss: what never reached stable storage is torn.
    fn tear_volatile(&self) {
        // A rename whose directory was never synced did not happen.
        for (from, to) in self.renamed.lock().unwrap().drain(..).rev() {
            if let Some(data) = self.inner.read_opt(&to).unwrap() {
                self.inner.write(&from, &data).unwrap();
                self.inner.remove_file(&to).unwrap();
            }
        }
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
            self.renamed.lock().unwrap().clear();
            Ok(())
        })
    }
    fn rename_unsynced(&self, from: &VPath, to: &VPath) -> Result<()> {
        self.mutate(|| {
            let data = self.inner.read(from)?;
            self.inner.write(to, &data)?;
            self.inner.remove_file(from)?;
            let mut volatile = self.volatile.lock().unwrap();
            match volatile.iter().position(|p| p == from) {
                // Never synced: torn under its new name instead.
                Some(i) => volatile[i] = to.clone(),
                None => self.renamed.lock().unwrap().push((from.clone(), to.clone())),
            }
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
    /// Renamed since the last successful barrier: the content is durable,
    /// the name is not (a power loss removes it).
    renamed: Mutex<HashSet<VPath>>,
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
            renamed: Mutex::default(),
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
        for p in self.renamed.lock().unwrap().drain() {
            self.inner.remove_file(&p).unwrap();
        }
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
        self.renamed.lock().unwrap().clear();
        Ok(())
    }
    fn rename_unsynced(&self, from: &VPath, to: &VPath) -> Result<()> {
        let data = self.inner.read(from)?;
        self.inner.write(to, &data)?;
        self.inner.remove_file(from)?;
        let was_volatile = self.volatile.lock().unwrap().remove(from);
        let was_lost = self.lost.lock().unwrap().remove(from);
        if was_volatile {
            self.volatile.lock().unwrap().insert(to.clone());
        } else if was_lost {
            self.lost.lock().unwrap().insert(to.clone());
        } else {
            self.renamed.lock().unwrap().insert(to.clone());
        }
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
        .map(|(path, e)| (path.to_string(), veil_core::conflict::read_file_like(repo.store(), &e).ok()))
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
    // A push writes nothing unsynced on the remote: each pack is a durable
    // stream (BUG-800), then its index, then the tags.
    if target != Target::RemoteOld {
        assert!(torn > 0, "{name}: no power loss ever tore an unsynced write");
    }
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

/// A two-phase push in packs of one object each, journalled: a crash at
/// any write (each staged pack and index, the journal's `touched` marks,
/// each rename into `objects/pack/`, the metadata, the operation) leaves no
/// visible partial push, and the retry resumes from the journal.
#[test]
fn crash_during_resumable_push() {
    sweep("resumable push", Target::RemoteOld, |env| {
        let mut repo = env.open(&env.local)?;
        let opts = remote::SyncOptions {
            journal: Some("ssh://hub/remote_old".into()),
            chunk: 1,
            ..Default::default()
        };
        let report = remote::push_with(&mut repo, env.remote_old.clone(), false, &[], false, &opts)?;
        assert!(report.tags_skipped.is_empty(), "{report:?}");
        Ok(())
    });
}

#[test]
fn eio_during_resumable_push() {
    eio_sweep("resumable push", Target::RemoteOld, |env| {
        let mut repo = env.open(&env.local)?;
        let opts = remote::SyncOptions {
            journal: Some("ssh://hub/remote_old".into()),
            chunk: 1,
            ..Default::default()
        };
        remote::push_with(&mut repo, env.remote_old.clone(), false, &[], false, &opts)?;
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

// ---- `vl ws switch`: the project directory moves to another workspace -------------

/// What one `vl` command does with the project directory, as the CLI's
/// `Ctx` does it: finish an interrupted move, record the directory into the
/// workspace it belongs to (only if that workspace still points where the
/// directory came from), then, for `vl ws switch TO`, record the switch and
/// move the directory, journalled.
fn wc_session(disk: Arc<dyn StorageBackend>, id: &Identity, switch_to: Option<&str>) -> Result<()> {
    let mut repo = Repo::open(disk.clone(), Some(id.clone()), "alice")?;
    let mut st = CheckoutState::load(&*disk)?.expect("a checkout record");
    repo.resume_working_copy(&*disk, &mut st, None)?;
    let ws = st.attached().to_string();
    let wc = repo.workspace_wc(&ws)?;
    if st.snapshot != wc {
        // The last command recorded the directory and died before saving
        // the pointer (the CLI's "stale, but the directory already
        // matches" case). Anything else would be a real stale directory,
        // which nothing here produces.
        let base = repo.snapshot(&st.snapshot)?.tree;
        let (tree, _) = repo.build_from_recorded(&*disk, Some(base), None, None, Some(&st.materialised))?;
        assert_eq!(tree, repo.snapshot(&wc)?.tree, "the directory is behind its workspace");
        st.snapshot = wc;
        st.save(&*disk)?;
    }
    let out = repo.snapshot_workspace_with(
        &ws,
        &*disk,
        SnapshotOptions {
            materialised: Some(&st.materialised),
            expected_wc: Some(wc),
            ..Default::default()
        },
    )?;
    assert!(!out.superseded);
    if out.snapshot != st.snapshot {
        st.snapshot = out.snapshot;
        st.save(&*disk)?;
    }
    if let Some(to) = switch_to {
        repo.record_workspace_switch(&ws, to)?;
        let target = repo.workspace_wc(to)?;
        repo.move_working_copy(&*disk, &mut st, to, target, None)?;
    }
    Ok(())
}

/// Files of the working copy (`.veil/` aside), with their content.
fn disk_files(fs: &dyn StorageBackend) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![VPath::root()];
    while let Some(dir) = stack.pop() {
        for e in fs.list_dir(&dir).unwrap() {
            let path = dir.join(&e.name);
            if path.as_str() == ".veil" {
                continue;
            }
            match fs.metadata(&path).unwrap().unwrap().kind {
                veil_core::vfs::NodeKind::Dir => stack.push(path),
                _ => {
                    out.insert(path.to_string(), fs.read(&path).unwrap());
                }
            }
        }
    }
    out
}

fn wc_files(repo: &Repo, ws: &str) -> BTreeMap<String, Vec<u8>> {
    files_of(repo, &repo.workspace_wc(ws).unwrap())
        .into_iter()
        .map(|(p, d)| (p, d.expect("readable")))
        .collect()
}

/// BUG-113: `vl ws switch` killed at any point (before, during or after the
/// checkout that replaces the directory's files) never records a mix of
/// both workspaces into either of them, never loses the edits of the
/// workspace it leaves or a local-only file, and the next command leaves
/// the directory holding exactly the workspace it is attached to.
#[test]
fn crash_during_workspace_switch() {
    let id = Identity::generate("alice");
    let base_disk = Arc::new(MemoryBackend::new());
    let mut repo = Repo::init(base_disk.clone(), Some(id.clone()), "alice").unwrap();
    for (path, data) in [("a.txt", "shared\n"), ("dir/old.txt", "default only\n"), ("cfg", "plain file\n")] {
        base_disk.write(&p(path), data.as_bytes()).unwrap();
    }
    repo.snapshot_workspace(WS, &*base_disk).unwrap();
    let (base, _) = repo.commit_working_copy(WS, "base").unwrap();
    repo.create_workspace("agent", vec![base], None).unwrap();
    let overlay = repo.workspace_overlay("agent").unwrap();
    overlay.write(&p("agent.txt"), b"agent only\n").unwrap();
    overlay.remove_file(&p("dir/old.txt")).unwrap();
    overlay.remove_file(&p("cfg")).unwrap();
    overlay.write(&p("cfg/settings.json"), b"{}\n").unwrap();
    overlay.write(&p("a.txt"), b"shared, edited by the agent\n").unwrap();
    repo.snapshot_workspace("agent", &overlay).unwrap();
    let agent_files = wc_files(&repo, "agent");
    // Default's unrecorded edits, and a local-only file.
    base_disk.write(&p("default.txt"), b"default work\n").unwrap();
    base_disk.write(&p(".env"), b"TOKEN=local\n").unwrap();
    let wc = repo.workspace_wc(WS).unwrap();
    CheckoutState::new(WS, wc, Default::default()).save(&*base_disk).unwrap();
    drop(repo);
    let mut default_files = disk_files(&*base_disk);
    default_files.remove(".env");

    let mut crashes = 0;
    for mode in [Crash::BeforeWrite, Crash::AfterWrite, Crash::PowerLoss] {
        for budget in 0..10_000 {
            let disk = Arc::new(base_disk.fork());
            let faulty = Arc::new(FaultyBackend::new(disk.clone(), budget, mode));
            let ctx = format!("ws switch: {mode:?} after {budget} writes");
            let result = wc_session(faulty.clone(), &id, Some("agent"));
            let completed = result.is_ok() && !faulty.crashed();
            if let Err(e) = &result {
                assert!(faulty.crashed(), "{ctx}: failed without a crash: {e}");
            }
            crashes += usize::from(!completed);
            let disk: Arc<dyn StorageBackend> = disk;
            // Reboot, then the next command; twice, so a recovery that is
            // itself interrupted later is covered by the second.
            for _ in 0..2 {
                wc_session(disk.clone(), &id, None).unwrap_or_else(|e| panic!("{ctx}: the next command fails: {e}"));
            }
            assert_healthy(disk.clone(), &id, &ctx);
            let repo = Repo::open(disk.clone(), Some(id.clone()), "alice").unwrap();
            let st = CheckoutState::load(&*disk).unwrap().unwrap();
            assert!(st.pending.is_none(), "{ctx}: the move was not finished");
            assert_eq!(wc_files(&repo, WS), default_files, "{ctx}: default's working copy");
            assert_eq!(wc_files(&repo, "agent"), agent_files, "{ctx}: agent's working copy");
            let mut expect = if st.workspace == "agent" { agent_files.clone() } else { default_files.clone() };
            expect.insert(".env".into(), b"TOKEN=local\n".to_vec());
            assert_eq!(disk_files(&*disk), expect, "{ctx}: the directory, attached to '{}'", st.workspace);
            if completed {
                assert_eq!(st.workspace, "agent", "{ctx}");
                break;
            }
            // The user runs the switch again: it completes.
            drop(repo);
            wc_session(disk.clone(), &id, Some("agent")).unwrap_or_else(|e| panic!("{ctx}: switching again: {e}"));
            let repo = Repo::open(disk.clone(), Some(id.clone()), "alice").unwrap();
            assert_eq!(wc_files(&repo, WS), default_files, "{ctx}: default after switching again");
            let mut expect = agent_files.clone();
            expect.insert(".env".into(), b"TOKEN=local\n".to_vec());
            assert_eq!(disk_files(&*disk), expect, "{ctx}: the directory after switching again");
        }
    }
    assert!(crashes > 10, "the sweep crashed only {crashes} times");
}

/// First-class conflicts: `vl ws switch` onto a workspace whose change holds
/// conflict entries, killed at any point. The markers are only rendered
/// when checkout writes the files; after recovery the directory holds
/// exactly the rendering, and the workspace's change still holds the
/// conflicts as data (the copy on disk never turns into a marker file, a
/// resolution or a deletion), with the other workspace's edits intact.
#[test]
fn crash_during_switch_onto_conflict_entries() {
    let id = Identity::generate("alice");
    let base_disk = Arc::new(MemoryBackend::new());
    let mut repo = Repo::init(base_disk.clone(), Some(id.clone()), "alice").unwrap();
    base_disk.write(&p("a.txt"), b"one\ntwo\nthree\n").unwrap();
    base_disk.write(&p("gone.txt"), b"modified on one side, deleted on the other\n").unwrap();
    repo.snapshot_workspace(WS, &*base_disk).unwrap();
    let (base, _) = repo.commit_working_copy(WS, "base").unwrap();
    let side = |repo: &mut Repo, name: &str, text: &[u8], gone: Option<&[u8]>| {
        repo.create_workspace(name, vec![base], None).unwrap();
        let o = repo.workspace_overlay(name).unwrap();
        o.write(&p("a.txt"), text).unwrap();
        match gone {
            Some(g) => o.write(&p("gone.txt"), g).unwrap(),
            None => o.remove_file(&p("gone.txt")).unwrap(),
        }
        repo.snapshot_workspace(name, &o).unwrap();
        repo.workspace_wc(name).unwrap()
    };
    let x = side(&mut repo, "x", b"one\nTWO-X\nthree\n", Some(b"edited\n"));
    let y = side(&mut repo, "y", b"one\nTWO-Y\nthree\n", None);
    repo.create_workspace("agent", vec![x, y], None).unwrap();
    let agent_wc = repo.workspace_wc("agent").unwrap();
    let agent_tree = repo.snapshot(&agent_wc).unwrap().tree;
    for f in ["a.txt", "gone.txt"] {
        let e = lookup(repo.store(), &agent_tree, &p(f)).unwrap().unwrap();
        assert_eq!(e.kind, veil_core::EntryKind::Conflict, "{f}");
    }
    let agent_files = wc_files(&repo, "agent");
    assert!(String::from_utf8_lossy(&agent_files["a.txt"]).contains("<<<<<<<"));
    base_disk.write(&p("default.txt"), b"default work\n").unwrap();
    let wc = repo.workspace_wc(WS).unwrap();
    CheckoutState::new(WS, wc, Default::default()).save(&*base_disk).unwrap();
    drop(repo);
    let default_files = disk_files(&*base_disk);

    let mut crashes = 0;
    for mode in [Crash::BeforeWrite, Crash::AfterWrite, Crash::PowerLoss] {
        for budget in 0..10_000 {
            let disk = Arc::new(base_disk.fork());
            let faulty = Arc::new(FaultyBackend::new(disk.clone(), budget, mode));
            let ctx = format!("switch onto conflicts: {mode:?} after {budget} writes");
            let result = wc_session(faulty.clone(), &id, Some("agent"));
            let completed = result.is_ok() && !faulty.crashed();
            if let Err(e) = &result {
                assert!(faulty.crashed(), "{ctx}: failed without a crash: {e}");
            }
            crashes += usize::from(!completed);
            let disk: Arc<dyn StorageBackend> = disk;
            for _ in 0..2 {
                wc_session(disk.clone(), &id, None).unwrap_or_else(|e| panic!("{ctx}: the next command fails: {e}"));
            }
            assert_healthy(disk.clone(), &id, &ctx);
            let repo = Repo::open(disk.clone(), Some(id.clone()), "alice").unwrap();
            let st = CheckoutState::load(&*disk).unwrap().unwrap();
            assert!(st.pending.is_none(), "{ctx}: the move was not finished");
            assert_eq!(wc_files(&repo, WS), default_files, "{ctx}: default's working copy");
            assert_eq!(wc_files(&repo, "agent"), agent_files, "{ctx}: agent's working copy");
            let tree = repo.snapshot(&repo.workspace_wc("agent").unwrap()).unwrap().tree;
            for f in ["a.txt", "gone.txt"] {
                let e = lookup(repo.store(), &tree, &p(f)).unwrap().unwrap_or_else(|| panic!("{ctx}: {f} lost"));
                assert_eq!(e.kind, veil_core::EntryKind::Conflict, "{ctx}: {f} is no longer a conflict");
            }
            let expect = if st.workspace == "agent" { agent_files.clone() } else { default_files.clone() };
            assert_eq!(disk_files(&*disk), expect, "{ctx}: the directory, attached to '{}'", st.workspace);
            if completed {
                assert_eq!(st.workspace, "agent", "{ctx}");
                break;
            }
        }
    }
    assert!(crashes > 5, "the sweep crashed only {crashes} times");
}

// ---- vl upgrade ------------------------------------------------------------------

/// A repository at `format` (1 or 2): history with cloaked files under
/// `team`, which Alice administers and Bob is a member of, so the upgrade
/// to format 3 runs `verify`, `set-format` and `3:hpke-ring-keys`.
fn upgrade_world(format: u32, alice: &Identity, bob: &Identity) -> MemoryBackend {
    let fs = Arc::new(MemoryBackend::new());
    let mut repo = Repo::init_for_clone_at(fs.clone(), Some(alice.clone()), "alice", format).unwrap();
    repo.keys().create_scope("team").unwrap();
    repo.keys().grant("team", &bob.public_id(), "bob").unwrap();
    fs.write(&p(".veilpolicy"), b"secrets/ cloak team\n").unwrap();
    fs.write(&p("src/a.rs"), b"fn a() {}\n").unwrap();
    fs.write(&p("secrets/key.txt"), b"s3cr3t\n").unwrap();
    repo.snapshot_workspace(WS, &*fs).unwrap();
    let (v1, _) = repo.commit_working_copy(WS, "v1").unwrap();
    repo.set_tag("main", v1, None, false).unwrap();
    fs.write(&p("secrets/key.txt"), b"rotated\n").unwrap();
    repo.snapshot_workspace(WS, &*fs).unwrap();
    repo.commit_working_copy(WS, "v2").unwrap();
    drop(repo);
    fs.fork()
}

/// The upgrade finished: format 3, no journal, the ring's current key
/// HPKE-wrapped (Bob still holds it), history unchanged and readable.
fn assert_upgraded(disk: &Arc<dyn StorageBackend>, alice: &Identity, bob: &Identity, before: &BTreeMap<ObjectId, Files>, ctx: &str) {
    assert_eq!(read_config(&**disk).unwrap().format, veil_core::repo::REPO_FORMAT, "{ctx}");
    assert!(!disk.exists(&p(JOURNAL_PATH)).unwrap(), "{ctx}: journal left behind");
    let repo = Repo::open(disk.clone(), Some(alice.clone()), "alice").unwrap();
    let ring = repo.keys().load_ring("team").unwrap().unwrap();
    let st = ring.verify().unwrap();
    assert!(!current_key_has_legacy_wraps(&ring, &st), "{ctx}: ring not moved to HPKE");
    assert_eq!(&history(&repo), before, "{ctx}: history changed");
    drop(repo);
    let bobs = Repo::open(disk.clone(), Some(bob.clone()), "bob").unwrap();
    assert!(bobs.keys().is_member("team"), "{ctx}: Bob lost the key");
    assert_healthy(disk.clone(), alice, ctx);
}

/// Crash `vl upgrade` at every write, in every crash mode, from format 1 and
/// from format 2. After each crash the repository opens at the old or the new
/// format with its history intact and `fsck` clean; running the upgrade
/// again finishes it, including the ring step.
fn upgrade_sweep(from: u32) {
    let alice = Identity::generate("alice");
    let bob = Identity::generate("bob");
    let world = upgrade_world(from, &alice, &bob);
    let before = {
        let disk: Arc<dyn StorageBackend> = Arc::new(world.fork());
        history(&Repo::open(disk, Some(alice.clone()), "alice").unwrap())
    };
    let mut crashes = 0;
    // Crashes past the commit point with the ring step still to do.
    let mut in_ring_step = 0;
    for mode in [Crash::BeforeWrite, Crash::AfterWrite, Crash::PowerLoss] {
        for budget in 0..10_000 {
            let mem = Arc::new(world.fork());
            let faulty = Arc::new(FaultyBackend::new(mem.clone(), budget, mode));
            let ctx = format!("upgrade {from}→3: {mode:?} after {budget} writes");
            let result = upgrade(faulty.clone(), Some(alice.clone()), &UpgradeOptions::default());
            let disk: Arc<dyn StorageBackend> = mem;
            match result {
                Ok(r) if !faulty.crashed() => {
                    assert!(budget > 0 && r.steps.iter().any(|s| s == "3:hpke-ring-keys"), "{ctx}: {r:?}");
                    assert_upgraded(&disk, &alice, &bob, &before, &ctx);
                    break;
                }
                Ok(_) => {}
                Err(e) => assert!(faulty.crashed(), "{ctx}: failed without a crash: {e}"),
            }
            crashes += 1;

            // Reboot: either format, never anything in between.
            let format = read_config(&*disk).unwrap().format;
            assert!(format == from || format == veil_core::repo::REPO_FORMAT, "{ctx}: format {format}");
            let repo = Repo::open(disk.clone(), Some(alice.clone()), "alice")
                .unwrap_or_else(|e| panic!("{ctx}: repository does not open: {e}"));
            assert_eq!(history(&repo), before, "{ctx}: history changed");
            let ring = repo.keys().load_ring("team").unwrap().unwrap();
            if format == veil_core::repo::REPO_FORMAT && current_key_has_legacy_wraps(&ring, &ring.verify().unwrap()) {
                in_ring_step += 1;
            }
            drop(repo);
            assert_healthy(disk.clone(), &alice, &ctx);

            // `vl upgrade` again resumes and finishes.
            let r = upgrade(disk.clone(), Some(alice.clone()), &UpgradeOptions::default())
                .unwrap_or_else(|e| panic!("{ctx}: resuming failed: {e}"));
            assert!(!r.up_to_date || format == veil_core::repo::REPO_FORMAT, "{ctx}: {r:?}");
            assert_upgraded(&disk, &alice, &bob, &before, &format!("{ctx}, after resuming"));
        }
    }
    assert!(crashes >= 5, "upgrade {from}→3: too few crash points ({crashes})");
    assert!(in_ring_step >= 3, "upgrade {from}→3: no crash between the commit point and the ring rotation");
}

#[test]
fn crash_during_upgrade_from_format_1() {
    upgrade_sweep(1);
}

#[test]
fn crash_during_upgrade_from_format_2() {
    upgrade_sweep(2);
}

/// The lock-free op log (format 6, threat 6): two heads left by concurrent
/// operations (an amend on one side, a child of the amended change on the
/// other), merged by the next `Repo::open`, which writes rebased snapshots
/// (staged, renamed into place), the merge operation and its head file. A
/// crash at any mutation, in every mode, leaves a repository that opens
/// and passes `fsck`, with both sides' work and both heads or the merge,
/// never half of it; the next open completes the merge.
#[test]
fn crash_during_settle() {
    use crate::oplog_concurrency::{head_files, land};
    let id = Identity::generate("alice");
    let disk = Arc::new(MemoryBackend::new());
    let mut repo = Repo::init(disk.clone(), Some(id.clone()), "alice").unwrap();
    let wc = MemoryBackend::new();
    wc.write(&p("f"), b"1\n").unwrap();
    repo.snapshot_workspace(WS, &wc).unwrap();
    let (x, _) = repo.commit_working_copy(WS, "x").unwrap();
    drop(repo);
    let heads = head_files(&*disk);
    let (fa, fb) = (Arc::new(disk.fork()), Arc::new(disk.fork()));
    Repo::open(fa.clone(), Some(id.clone()), "alice").unwrap().describe(x, "x, amended").unwrap();
    let mut b = Repo::open(fb.clone(), Some(id.clone()), "alice").unwrap();
    b.create_workspace("side", vec![x], None).unwrap();
    b.set_tag("from-b", x, None, false).unwrap();
    drop(b);
    land(&disk, &fa, &heads);
    land(&disk, &fb, &heads);
    let two = head_files(&*disk);
    assert_eq!(two.len(), 2);
    let check = |fs: Arc<dyn StorageBackend>, ctx: &str| {
        let r = Repo::open(fs.clone(), Some(id.clone()), "alice").unwrap_or_else(|e| panic!("{ctx}: does not open: {e}"));
        assert_healthy(fs.clone(), &id, ctx);
        assert!(r.view().tags.contains_key("from-b"), "{ctx}: B's tag was lost");
        let side = r.snapshot(&r.workspace_wc("side").unwrap()).unwrap();
        let parent = r.snapshot(&side.parents[0]).unwrap();
        assert_eq!(r.description(&parent), "x, amended", "{ctx}: the child is not on the amended change");
        assert_eq!(r.heads().len(), 1, "{ctx}");
    };
    let mut crashes = 0;
    for mode in [Crash::BeforeWrite, Crash::AfterWrite, Crash::PowerLoss] {
        for budget in 0..10_000 {
            let fork = Arc::new(disk.fork());
            let faulty = Arc::new(FaultyBackend::new(fork.clone(), budget, mode));
            let ctx = format!("settle: {mode:?} after {budget} writes");
            let res = Repo::open(faulty.clone(), Some(id.clone()), "alice");
            if res.is_ok() && !faulty.crashed() {
                check(fork.clone(), &ctx);
                break;
            }
            crashes += 1;
            // Reboot: the heads are both originals, or the merge (with
            // the head file of a parent it had not removed yet, which is
            // its ancestor and dropped by readers).
            let now = head_files(&*fork);
            assert!(now.len() <= 3 && now.iter().filter(|h| !two.contains(*h)).count() <= 1, "{ctx}: heads {now:?}");
            check(fork.clone(), &ctx);
        }
    }
    assert!(crashes >= 3, "too few crash points ({crashes})");
}
