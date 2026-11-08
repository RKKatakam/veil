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

/// Where `DiskBackend::write_staged` would put the staged copy of `path`:
/// a temp file beside it, a name snapshots ignore.
fn staged_name(path: &VPath) -> VPath {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let tmp = format!(".{}.vltmp{:08x}", path.file_name(), NEXT.fetch_add(1, Ordering::Relaxed));
    path.parent().unwrap().join(&tmp)
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
    /// Files created never to be synced (`create_new_unsynced`: the
    /// history index's layers): no barrier covers them, a power loss tears
    /// them.
    never_synced: Mutex<Vec<VPath>>,
    /// Written by `stage_unsynced` and not published yet: a barrier makes
    /// the content durable, never the name (as on disk, where the staging
    /// directory is never synced), so a power loss removes them.
    staged: Mutex<Vec<VPath>>,
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
            never_synced: Mutex::new(Vec::new()),
            staged: Mutex::new(Vec::new()),
            tore: AtomicBool::new(false),
        }
    }

    fn tore_anything(&self) -> bool {
        self.tore.load(Ordering::SeqCst)
    }

    /// Power loss: what never reached stable storage is torn.
    fn tear_volatile(&self) {
        // A rename whose directory was never synced may or may not have
        // happened. Directories are independent of each other (a journal
        // keeps the renames into one directory in order): those into every
        // other directory, by first appearance, are undone, so that a name
        // made durable before what it depends on (in another directory) is
        // caught.
        let renamed: Vec<(VPath, VPath)> = self.renamed.lock().unwrap().drain(..).collect();
        let mut dirs: Vec<VPath> = Vec::new();
        for (_, to) in &renamed {
            let d = to.parent().unwrap_or_else(VPath::root);
            if !dirs.contains(&d) {
                dirs.push(d);
            }
        }
        for (from, to) in renamed.into_iter().rev() {
            let d = to.parent().unwrap_or_else(VPath::root);
            if dirs.iter().position(|x| *x == d).is_some_and(|i| i % 2 == 1) {
                continue;
            }
            if let Some(data) = self.inner.read_opt(&to).unwrap() {
                self.inner.write(&from, &data).unwrap();
                self.inner.remove_file(&to).unwrap();
            }
        }
        // Staged files whose names never became durable: gone, synced or not.
        for path in self.staged.lock().unwrap().drain(..) {
            if self.inner.read_opt(&path).unwrap().is_some() {
                self.inner.remove_file(&path).unwrap();
                self.tore.store(true, Ordering::SeqCst);
            }
        }
        let mut volatile = self.volatile.lock().unwrap();
        volatile.extend(self.never_synced.lock().unwrap().drain(..));
        self.tore.fetch_or(!volatile.is_empty(), Ordering::SeqCst);
        for (i, path) in volatile.drain(..).enumerate() {
            // Already removed (a merged-away index layer): nothing to tear.
            let Some(data) = self.inner.read_opt(&path).unwrap() else { continue };
            match i % 3 {
                0 => self.inner.remove_file(&path).unwrap(),
                1 => self.inner.write(&path, b"").unwrap(),
                _ => self.inner.write(&path, &data[..data.len() / 2]).unwrap(),
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
    /// As `DiskBackend` stages a working-copy file (BUG-818): unsynced, at
    /// a temp name, so a power loss tears the temp file, never `path`.
    fn write_staged(&self, path: &VPath, data: &[u8]) -> Result<VPath> {
        let tmp = staged_name(path);
        self.write_unsynced(&tmp, data)?;
        Ok(tmp)
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
    /// As `DiskBackend` stages a transaction's file: the content waits for
    /// the next barrier, the name for none (see `staged`).
    fn stage_unsynced(&self, path: &VPath, data: &[u8]) -> Result<()> {
        self.write_unsynced(path, data)?;
        self.staged.lock().unwrap().push(path.clone());
        Ok(())
    }
    /// A staged file renamed into place: the new name waits for the next
    /// barrier (a power loss before it undoes the rename, and the staged
    /// name is not durable either).
    fn publish_unsynced(&self, from: &VPath, to: &VPath) -> Result<()> {
        self.rename_unsynced(from, to)?;
        let mut staged = self.staged.lock().unwrap();
        staged.retain(|p| p != from);
        // The undone rename brings it back under its staged name only.
        if self.renamed.lock().unwrap().iter().any(|(f, _)| f == from) {
            staged.push(from.clone());
        }
        Ok(())
    }
    fn create_new(&self, path: &VPath, data: &[u8]) -> Result<bool> {
        self.mutate(|| self.inner.create_new(path, data))
    }
    fn create_new_unsynced(&self, path: &VPath, data: &[u8]) -> Result<bool> {
        self.mutate(|| {
            let created = self.inner.create_new(path, data)?;
            if created {
                self.never_synced.lock().unwrap().push(path.clone());
            }
            Ok(created)
        })
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
    fn write_staged(&self, path: &VPath, data: &[u8]) -> Result<VPath> {
        let tmp = staged_name(path);
        self.write_unsynced(&tmp, data)?;
        Ok(tmp)
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
    repo.set_tag("main", v1, false).unwrap();
    fs.write(&p("src/b.rs"), b"fn b() {}\n").unwrap();
    repo.snapshot_workspace(WS, &*fs).unwrap();
    repo.commit_working_copy(WS, "v2").unwrap();

    let ws = repo.ephemeral_workspace(v1).unwrap();
    ws.write("side.txt", "side\n").unwrap();
    ws.write("secrets/key.txt", "rotated\n").unwrap();
    let (side, _) = repo.commit_ephemeral(&ws, "side").unwrap();
    repo.set_tag("side", side, false).unwrap();

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
    for id in repo.exact().visible().unwrap() {
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
    sweep_with(name, target, op, target != Target::RemoteOld)
}

/// [`sweep`]; `unsynced` says whether the operation writes anything not
/// yet covered by a barrier (gc writes everything durably).
fn sweep_with(name: &str, target: Target, op: Op, unsynced: bool) {
    sweep_in(world(), name, target, op, unsynced)
}

/// [`world`] with [`LARGE`] more new files in Alice's working copy: a
/// snapshot of it writes its new objects as one pack.
fn large_world() -> World {
    let w = world();
    for i in 0..LARGE {
        w.local.write(&p(&format!("bulk/d{}/f{i}.txt", i % 7)), format!("bulk file {i}\n").as_bytes()).unwrap();
    }
    w
}

/// More new objects than a transaction writes loose (`TX_PACK_MIN`).
const LARGE: usize = 300;

/// [`sweep_with`] in world `w`.
fn sweep_in(w: World, name: &str, target: Target, op: Op, unsynced: bool) {
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
    if unsynced {
        assert!(torn > 0, "{name}: no power loss ever tore an unsynced write");
    }
}

/// Sweep `op` across every barrier failing in turn (see `EioBackend`): the
/// command may fail, the user runs it again, which must succeed, then the
/// power fails. The repository must be healthy, with every earlier snapshot
/// intact, and everything the retry recorded must still be readable (a
/// reachable torn object is corruption for `fsck`).
fn eio_sweep(name: &str, target: Target, op: Op) {
    eio_sweep_in(world(), name, target, op)
}

/// [`eio_sweep`] in world `w`.
fn eio_sweep_in(w: World, name: &str, target: Target, op: Op) {
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

/// A snapshot with many new files publishes them as one pack (made
/// durable, then its index) instead of loose objects: a crash at any point
/// leaves the snapshot recorded completely or not at all, with every new
/// file readable.
#[test]
fn crash_during_large_snapshot() {
    // Nothing is written unsynced: the pack and its index are durable
    // writes, then the operation's.
    sweep_in(large_world(), "large snapshot", Target::Local, large_snapshot, false);
}

#[test]
fn eio_during_large_snapshot() {
    eio_sweep_in(large_world(), "large snapshot", Target::Local, large_snapshot);
}

fn large_snapshot(env: &Env) -> Result<()> {
    let mut repo = env.open(&env.local)?;
    repo.snapshot_workspace(WS, &*env.local)?;
    let tree = repo.snapshot(&repo.workspace_wc(WS)?)?.tree;
    for i in [0, LARGE / 2, LARGE - 1] {
        let path = p(&format!("bulk/d{}/f{i}.txt", i % 7));
        let e = lookup(repo.store(), &tree, &path)?.expect("recorded");
        assert_eq!(repo.store().read_entry(&e)?, format!("bulk file {i}\n").into_bytes());
    }
    Ok(())
}

#[test]
fn crash_during_commit() {
    sweep("commit", Target::Local, |env| {
        let mut repo = env.open(&env.local)?;
        repo.commit_working_copy(WS, "commit under fire")?;
        Ok(())
    });
}

/// `vl commit`: the working copy recorded and committed as one operation
/// (`SnapshotOptions::commit`). Its operation and head file are staged with
/// its objects and made durable by their barrier, then named in turn, each
/// after a barrier (a power loss tears what no barrier covered, and takes
/// the staged names with it): a crash at any point leaves the commit
/// recorded completely or not at all.
#[test]
fn crash_during_one_operation_commit() {
    sweep("one-operation commit", Target::Local, |env| {
        let mut repo = env.open(&env.local)?;
        let out = repo.snapshot_workspace_with(
            WS,
            &*env.local,
            SnapshotOptions {
                commit: Some(("committed under fire", true)),
                ..Default::default()
            },
        )?;
        assert!(out.committed.is_some());
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

/// Maintenance (scale stream G2, threat 1): consolidation of the loose
/// objects, then a garbage pack and geometric merging. A loose copy goes
/// only after the pack and index holding it are durable.
#[test]
fn crash_during_gc() {
    sweep_with(
        "gc",
        Target::Local,
        |env| {
            let mut repo = env.open(&env.local)?;
            veil_core::gc::gc(&mut repo, &Default::default())?;
            for i in 0..30 {
                repo.store().put(&veil_core::object::Object::Blob(format!("unreferenced {i}\n").repeat(40).into_bytes()))?;
            }
            veil_core::gc::gc(&mut repo, &Default::default())?;
            Ok(())
        },
        false,
    );
}

/// Pruning with grace 0 and the op log cut: loose garbage deleted, a pack
/// rewritten without its garbage, operations pruned.
#[test]
fn crash_during_gc_prune_now() {
    sweep_with(
        "gc --prune-now",
        Target::Local,
        |env| {
            let mut repo = env.open(&env.local)?;
            for i in 0..10 {
                repo.store().put(&veil_core::object::Object::Blob(format!("garbage {i}\n").into_bytes()))?;
            }
            veil_core::gc::gc(&mut repo, &Default::default())?;
            let now = veil_core::now_millis() + 60_000;
            let opts = veil_core::gc::GcOptions {
                grace: std::time::Duration::ZERO,
                keep_ops: Some(std::time::Duration::ZERO),
                now: Some(now),
                ..Default::default()
            };
            veil_core::gc::gc(&mut repo, &opts)?;
            Ok(())
        },
        false,
    );
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
        let (tree, _) = repo.build_from_recorded(&*disk, Some(base), None, Some(&st.materialised))?;
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

/// The project directory of `default`, with unrecorded edits and a
/// local-only file, and a workspace `agent` that edits, adds, removes and
/// swaps a file for a directory: the "disk", with what each workspace
/// records (`default`, `agent`).
struct SwitchWorld {
    id: Identity,
    disk: Arc<MemoryBackend>,
    default_files: BTreeMap<String, Vec<u8>>,
    agent_files: BTreeMap<String, Vec<u8>>,
}

fn switch_world() -> SwitchWorld {
    let id = Identity::generate("alice");
    let base_disk = Arc::new(MemoryBackend::new());
    let mut repo = Repo::init(base_disk.clone(), Some(id.clone()), "alice").unwrap();
    for (path, data) in [("a.txt", "shared\n"), ("dir/old.txt", "default only\n"), ("cfg", "plain file\n")] {
        base_disk.write(&p(path), data.as_bytes()).unwrap();
    }
    repo.snapshot_workspace(WS, &*base_disk).unwrap();
    let (base, _) = repo.commit_working_copy(WS, "base").unwrap();
    repo.create_workspace("agent", vec![base]).unwrap();
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
    SwitchWorld {
        id,
        disk: base_disk,
        default_files,
        agent_files,
    }
}

/// After a crash and the commands that follow it: the move is finished,
/// neither workspace recorded anything of the other (nor a torn file),
/// and the directory holds exactly the workspace it is attached to, with
/// the local-only file and no staged debris.
fn assert_switch_recovered(w: &SwitchWorld, disk: &Arc<dyn StorageBackend>, ctx: &str) -> CheckoutState {
    assert_healthy(disk.clone(), &w.id, ctx);
    let repo = Repo::open(disk.clone(), Some(w.id.clone()), "alice").unwrap();
    let st = CheckoutState::load(&**disk).unwrap().unwrap();
    assert!(st.pending.is_none(), "{ctx}: the move was not finished");
    assert_eq!(wc_files(&repo, WS), w.default_files, "{ctx}: default's working copy");
    assert_eq!(wc_files(&repo, "agent"), w.agent_files, "{ctx}: agent's working copy");
    let mut expect = if st.workspace == "agent" { w.agent_files.clone() } else { w.default_files.clone() };
    expect.insert(".env".into(), b"TOKEN=local\n".to_vec());
    assert_eq!(disk_files(&**disk), expect, "{ctx}: the directory, attached to '{}'", st.workspace);
    st
}

/// Is any file of the working copy a staged copy checkout left behind?
fn has_debris(fs: &dyn StorageBackend) -> bool {
    disk_files(fs).keys().any(|p| veil_core::vfs::is_temp_name(p.rsplit('/').next().unwrap()))
}

/// BUG-113: `vl ws switch` killed at any point (before, during or after the
/// checkout that replaces the directory's files) never records a mix of
/// both workspaces into either of them, never loses the edits of the
/// workspace it leaves or a local-only file, and the next command leaves
/// the directory holding exactly the workspace it is attached to.
///
/// BUG-818: checkout stages every file and makes them durable with one
/// barrier. A power loss before it tears staged copies, never a file under
/// its own name, so nothing torn is recorded as an edit; the next command
/// removes the staged debris.
#[test]
fn crash_during_workspace_switch() {
    let w = switch_world();
    let (id, base_disk, agent_files, default_files) = (&w.id, &w.disk, &w.agent_files, &w.default_files);
    let mut crashes = 0;
    let mut debris = 0;
    for mode in [Crash::BeforeWrite, Crash::AfterWrite, Crash::PowerLoss] {
        for budget in 0..10_000 {
            let disk = Arc::new(base_disk.fork());
            let faulty = Arc::new(FaultyBackend::new(disk.clone(), budget, mode));
            let ctx = format!("ws switch: {mode:?} after {budget} writes");
            let result = wc_session(faulty.clone(), id, Some("agent"));
            let completed = result.is_ok() && !faulty.crashed();
            if let Err(e) = &result {
                assert!(faulty.crashed(), "{ctx}: failed without a crash: {e}");
            }
            crashes += usize::from(!completed);
            let disk: Arc<dyn StorageBackend> = disk;
            debris += usize::from(has_debris(&*disk));
            // Reboot, then the next command; twice, so a recovery that is
            // itself interrupted later is covered by the second.
            for _ in 0..2 {
                wc_session(disk.clone(), id, None).unwrap_or_else(|e| panic!("{ctx}: the next command fails: {e}"));
            }
            let st = assert_switch_recovered(&w, &disk, &ctx);
            let repo = Repo::open(disk.clone(), Some(id.clone()), "alice").unwrap();
            if completed {
                assert_eq!(st.workspace, "agent", "{ctx}");
                break;
            }
            // The user runs the switch again: it completes.
            drop(repo);
            wc_session(disk.clone(), id, Some("agent")).unwrap_or_else(|e| panic!("{ctx}: switching again: {e}"));
            let repo = Repo::open(disk.clone(), Some(id.clone()), "alice").unwrap();
            assert_eq!(&wc_files(&repo, WS), default_files, "{ctx}: default after switching again");
            let mut expect = agent_files.clone();
            expect.insert(".env".into(), b"TOKEN=local\n".to_vec());
            assert_eq!(disk_files(&*disk), expect, "{ctx}: the directory after switching again");
        }
    }
    assert!(crashes > 10, "the sweep crashed only {crashes} times");
    assert!(debris > 0, "no crash ever found a file staged by checkout");
}

/// BUG-818: a barrier of `vl ws switch` fails with EIO, at each barrier in
/// turn (the snapshot's, then the checkout's: after staging, after the
/// renames). What a failed barrier covered reads back fine but never
/// reaches the disk. The command fails; the next command finishes the
/// move, rewriting every file whose write may not be durable; then the
/// power fails. Nothing torn or missing is recorded into either
/// workspace, and the directory holds exactly the workspace it is
/// attached to.
#[test]
fn eio_during_workspace_switch() {
    let w = switch_world();
    let mut failures = 0;
    for fail_at in 0..1000 {
        let disk = Arc::new(w.disk.fork());
        let eio = Arc::new(EioBackend::new(disk.clone(), fail_at, false));
        let ctx = format!("ws switch: barrier {fail_at} fails");
        let first = wc_session(eio.clone(), &w.id, Some("agent"));
        if !eio.failed.load(Ordering::SeqCst) {
            first.unwrap_or_else(|e| panic!("{ctx}: failed without a fault: {e}"));
            // No barrier failed, and the power fails as soon as the switch
            // returns: everything it recorded is already on disk.
            eio.power_loss();
            let disk: Arc<dyn StorageBackend> = disk;
            wc_session(disk.clone(), &w.id, None).unwrap_or_else(|e| panic!("{ctx}: the command after the power loss fails: {e}"));
            let st = assert_switch_recovered(&w, &disk, "power loss right after the switch");
            assert_eq!(st.workspace, "agent");
            break;
        }
        failures += 1;
        wc_session(eio.clone(), &w.id, None).unwrap_or_else(|e| panic!("{ctx}: the next command fails: {e}"));
        eio.power_loss();
        let disk: Arc<dyn StorageBackend> = disk;
        wc_session(disk.clone(), &w.id, None).unwrap_or_else(|e| panic!("{ctx}: the command after the power loss fails: {e}"));
        assert_switch_recovered(&w, &disk, &ctx);
    }
    // The snapshot's barrier, and the checkout's two.
    assert!(failures >= 3, "only {failures} barriers failed");
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
        repo.create_workspace(name, vec![base]).unwrap();
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
    repo.create_workspace("agent", vec![x, y]).unwrap();
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
    b.create_workspace("side", vec![x]).unwrap();
    b.set_tag("from-b", x, false).unwrap();
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

/// The history index's layers are never synced (a cache, `graph_index`):
/// a power loss tears them (missing, empty, half written). The checksum
/// catches each torn layer, the index is dropped (a new epoch) and computed
/// again from the store, and every graph query answers as before.
#[test]
fn a_power_loss_tears_history_index_layers_and_they_are_rebuilt() {
    let disk = Arc::new(MemoryBackend::new());
    let faulty = Arc::new(FaultyBackend::new(disk.clone(), usize::MAX, Crash::PowerLoss));
    let backend: Arc<dyn StorageBackend> = faulty.clone();
    let mut repo = Repo::init(backend.clone(), None, "t").unwrap();
    let mut line = Vec::new();
    for i in 0..40 {
        repo.describe(repo.workspace_wc(WS).unwrap(), &format!("change {i}")).unwrap();
        let described = repo.workspace_wc(WS).unwrap();
        repo.new_change(WS, vec![described], "").unwrap();
        line.push(described);
    }
    line.push(repo.workspace_wc(WS).unwrap());
    let tip = *line.last().unwrap();
    let visible = repo.exact().visible().unwrap();
    drop(repo);
    let layers = |d: &MemoryBackend| -> Vec<(String, Vec<u8>)> {
        let dir = VPath::new(".veil/index/graph").unwrap();
        let mut v: Vec<(String, Vec<u8>)> = d
            .list_dir(&dir)
            .unwrap_or_default()
            .into_iter()
            .filter(|e| e.name.starts_with("L-"))
            .map(|e| (e.name.clone(), d.read(&dir.join(&e.name)).unwrap()))
            .collect();
        v.sort();
        v
    };
    let before = layers(&disk);
    assert!(!before.is_empty(), "commits wrote index layers");
    faulty.tear_volatile();
    let after = layers(&disk);
    assert_ne!(before, after, "the power loss tore some layer");
    assert!(
        after.iter().any(|(n, d)| before.iter().any(|(m, e)| m == n && e != d)),
        "a layer is still there, torn under its name: {:?} → {:?}",
        before.iter().map(|l| (&l.0, l.1.len())).collect::<Vec<_>>(),
        after.iter().map(|l| (&l.0, l.1.len())).collect::<Vec<_>>()
    );
    // Reboot: every query answers as the full walk does.
    let repo = Repo::open(disk.clone(), None, "t").unwrap();
    assert_eq!(repo.exact().visible().unwrap(), visible);
    for (i, a) in line.iter().enumerate() {
        assert!(repo.is_ancestor(a, &tip).unwrap(), "{i} is below the tip");
        if *a != tip {
            assert!(!repo.is_ancestor(&tip, a).unwrap(), "the tip is not below {i}");
        }
        let (g, gt) = (repo.held().index().generation(&repo, a).unwrap(), repo.held().index().generation(&repo, &tip).unwrap());
        assert!(*a == tip || g < gt, "{i}: generation {g:?} below the tip's {gt:?}");
    }
    repo.held().index().persist(&repo);
    drop(repo);
    // The torn epoch is gone: what is left was written again, and parses.
    let torn_epoch = |n: &str| n.split('-').nth(1).map(str::to_string);
    let epochs: HashSet<Option<String>> = before.iter().map(|(n, _)| torn_epoch(n)).collect();
    let rebuilt = layers(&disk);
    assert!(!rebuilt.is_empty(), "the index was written again");
    assert!(rebuilt.iter().all(|(n, _)| !epochs.contains(&torn_epoch(n))), "{rebuilt:?}");
    let reopened = Repo::open(disk.clone(), None, "t").unwrap();
    assert_eq!(reopened.exact().visible().unwrap(), visible);
    assert!(reopened.is_ancestor(&line[0], &tip).unwrap());
}

