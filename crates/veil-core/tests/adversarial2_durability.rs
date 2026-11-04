//! Round-2 adversarial tests: batched fsync, crash recovery and the lock
//! protocol (takeover guard, pid reuse).
//!
//! Every `#[ignore = "BUG-NNN: …"]` test asserts the correct behaviour and
//! currently fails; see `docs/BUGS.md`.

mod adversarial_support;

use std::{
    collections::HashSet,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Condvar, Mutex,
    },
    time::{Duration, Instant},
};

use adversarial_support::{p, WS};
use veil_core::{
    lock::{LockInfo, LockOptions, RepoLock, LOCK_PATH, STEAL_PATH},
    vfs::{DirEntry, Metadata, StatClock},
    Identity, MemoryBackend, ObjectId, Repo, Result, StorageBackend, VPath, VeilError,
};

// ---- an fsync model with Linux error semantics ----------------------------------

/// `MemoryBackend` plus a model of what is durable.
///
/// * `write` / `create_new` are durable when they return.
/// * `write_unsynced` data is only durable after a *successful* barrier.
/// * A failing barrier models Linux (since 4.13) writeback errors: `fsync`
///   reports EIO **once**, and the kernel marks the dirty pages clean. The
///   data stays readable from the page cache, but it is not on disk, and a
///   retried `fsync` succeeds without writing anything ("fsyncgate";
///   PostgreSQL, MySQL and others treat an fsync failure as fatal for
///   exactly this reason).
/// * `power_loss` truncates every file whose data never reached the disk.
#[derive(Debug, Default)]
struct FsyncModel {
    inner: MemoryBackend,
    dirty: Mutex<HashSet<VPath>>,
    lost: Mutex<HashSet<VPath>>,
    fail_next_barrier: AtomicBool,
}

impl FsyncModel {
    fn power_loss(&self) {
        let mut gone: Vec<VPath> = self.dirty.lock().unwrap().drain().collect();
        gone.extend(self.lost.lock().unwrap().drain());
        for path in gone {
            if self.inner.exists(&path).unwrap() {
                self.inner.write(&path, b"").unwrap();
            }
        }
    }

    fn durable(&self, path: &VPath) {
        self.dirty.lock().unwrap().remove(path);
        self.lost.lock().unwrap().remove(path);
    }
}

impl StorageBackend for FsyncModel {
    fn kind(&self) -> &'static str {
        "fsync-model"
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
        self.dirty.lock().unwrap().insert(path.clone());
        Ok(())
    }
    fn sync_barrier(&self) -> Result<()> {
        let mut dirty = self.dirty.lock().unwrap();
        if self.fail_next_barrier.swap(false, Ordering::SeqCst) {
            // EIO is reported once; the pages are now "clean" but not on disk.
            self.lost.lock().unwrap().extend(dirty.drain());
            return Err(VeilError::Io {
                path: "objects".into(),
                source: std::io::Error::other("EIO: writeback failed"),
            });
        }
        dirty.clear();
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
        self.durable(path);
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
    fn set_executable(&self, path: &VPath, executable: bool) -> Result<()> {
        self.inner.set_executable(path, executable)
    }
    fn stat_clock(&self) -> Option<StatClock> {
        self.inner.stat_clock()
    }
}

/// A command whose durability barrier fails reports the error, and the user
/// runs it again. The second run must not reuse the objects of the failed
/// barrier: they are readable (page cache) but were never made durable, and
/// the retried barrier has nothing left to sync. After a power loss the
/// acknowledged snapshot must still be readable.
#[test]
fn a_retried_command_after_an_fsync_failure_loses_no_acknowledged_data() {
    let backend = Arc::new(FsyncModel::default());
    let mut repo = Repo::init(backend.clone(), Some(Identity::generate("alice")), "alice").unwrap();
    let wc = MemoryBackend::new();
    wc.write(&p("thesis.tex"), b"chapter 1: months of work\n").unwrap();

    backend.fail_next_barrier.store(true, Ordering::SeqCst);
    let err = repo.snapshot_workspace(WS, &wc).unwrap_err();
    assert!(err.to_string().contains("EIO"), "{err}");

    // The user retries; this time it succeeds and is acknowledged.
    repo.snapshot_workspace(WS, &wc).unwrap();
    let (committed, _) = repo.commit_working_copy(WS, "chapter 1").unwrap();
    drop(repo);

    backend.power_loss();
    let repo = Repo::open(backend.clone(), Some(Identity::generate("alice")), "alice").unwrap();
    let tree = repo.snapshot(&committed).unwrap().tree;
    let e = veil_core::tree::lookup(repo.store(), &tree, &p("thesis.tex"));
    let content = e.and_then(|e| repo.store().read_entry(&e.expect("entry")));
    match content {
        Ok(c) => assert_eq!(c, b"chapter 1: months of work\n"),
        Err(e) => panic!("acknowledged commit lost after power loss: {e}"),
    }
}

/// Control: without a failure, the batched barrier makes the commit durable.
#[test]
fn a_committed_snapshot_survives_power_loss() {
    let backend = Arc::new(FsyncModel::default());
    let mut repo = Repo::init(backend.clone(), Some(Identity::generate("alice")), "alice").unwrap();
    let wc = MemoryBackend::new();
    wc.write(&p("thesis.tex"), b"chapter 1\n").unwrap();
    repo.snapshot_workspace(WS, &wc).unwrap();
    let (committed, _) = repo.commit_working_copy(WS, "chapter 1").unwrap();
    drop(repo);
    backend.power_loss();
    let repo = Repo::open(backend, None, "x").unwrap();
    let tree = repo.snapshot(&committed).unwrap().tree;
    let e = veil_core::tree::lookup(repo.store(), &tree, &p("thesis.tex")).unwrap().unwrap();
    assert_eq!(repo.store().read_entry(&e).unwrap(), b"chapter 1\n");
}

// ---- lock files written by "other processes" -------------------------------------

fn host_and_boot() -> (String, String) {
    let host = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap().trim().to_string();
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap().trim().to_string();
    let ns = std::fs::read_link("/proc/self/ns/pid").unwrap();
    (host, format!("{boot}/{}", ns.to_string_lossy()))
}

fn lock_of(pid: u32, acquired: i64) -> Vec<u8> {
    let (host, boot) = host_and_boot();
    let info = LockInfo {
        token: format!("{:032x}", rand_u128()),
        pid,
        host,
        boot,
        acquired,
        renewed: acquired,
        lease_ms: 10_000,
    };
    serde_json::to_vec(&info).unwrap()
}

fn rand_u128() -> u128 {
    let mut b = [0u8; 16];
    getrandom(&mut b);
    u128::from_le_bytes(b)
}

fn getrandom(b: &mut [u8]) {
    // Good enough for unique tokens in tests.
    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let id = ObjectId::hash(format!("{t}{:?}", std::thread::current().id()).as_bytes());
    b.copy_from_slice(&id.0[..b.len()]);
}

fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64
}

/// The pid of a process that has exited.
fn dead_pid() -> u32 {
    let mut c = std::process::Command::new("true").spawn().unwrap();
    let pid = c.id();
    c.wait().unwrap();
    pid
}

#[cfg(target_os = "linux")]
#[test]
fn a_dead_holders_lock_is_taken_over_at_once() {
    let backend: Arc<dyn StorageBackend> = Arc::new(MemoryBackend::new());
    backend.write(&p(LOCK_PATH), &lock_of(dead_pid(), now_ms())).unwrap();
    let opts = LockOptions {
        wait: Duration::from_millis(500),
        ..LockOptions::default()
    };
    RepoLock::acquire_with(backend, &opts).unwrap();
}

/// The holder was killed long ago; its pid now belongs to an unrelated
/// process that started *after* the lock was taken (pid reuse, common in
/// containers with small pid namespaces). That process cannot be the
/// holder, but it keeps the repository locked until someone deletes the
/// lock file by hand.
#[cfg(target_os = "linux")]
#[test]
fn a_reused_pid_does_not_keep_a_dead_holders_lock() {
    let acquired = now_ms() - 120_000;
    let mut unrelated = std::process::Command::new("sleep").arg("30").spawn().unwrap();
    let backend: Arc<dyn StorageBackend> = Arc::new(MemoryBackend::new());
    backend.write(&p(LOCK_PATH), &lock_of(unrelated.id(), acquired)).unwrap();
    let opts = LockOptions {
        wait: Duration::from_millis(1500),
        ..LockOptions::default()
    };
    let res = RepoLock::acquire_with(backend, &opts);
    let _ = unrelated.kill();
    let _ = unrelated.wait();
    assert!(res.is_ok(), "{:?}", res.err());
}

// ---- the takeover guard: deterministic interleaving --------------------------------

/// A `MemoryBackend` that lets a test pause chosen threads at chosen calls.
#[derive(Debug)]
struct Hooked {
    inner: MemoryBackend,
    gate: Gate,
}

#[derive(Debug, Default)]
struct Gate {
    state: Mutex<Vec<&'static str>>,
    cv: Condvar,
}

impl Gate {
    fn signal(&self, ev: &'static str) {
        self.state.lock().unwrap().push(ev);
        self.cv.notify_all();
    }
    fn wait_for(&self, ev: &'static str, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let mut s = self.state.lock().unwrap();
        while !s.contains(&ev) {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            s = self.cv.wait_timeout(s, left).unwrap().0;
        }
        true
    }
    fn seen(&self, ev: &'static str) -> bool {
        self.state.lock().unwrap().contains(&ev)
    }
    fn index(&self, ev: &'static str) -> Option<usize> {
        self.state.lock().unwrap().iter().position(|e| *e == ev)
    }
}

impl Hooked {
    fn before(&self, op: &str, path: &VPath) {
        let thread = std::thread::current();
        let name = thread.name().unwrap_or("");
        let t = Duration::from_secs(10);
        // c2 pauses just before removing what it judged to be a dead
        // contender's guard, until c3 is inside its own takeover.
        if name == "c2" && op == "remove" && path.as_str() == STEAL_PATH && !self.gate.seen("c2-paused") {
            self.gate.signal("c2-paused");
            // (A correct implementation may never let c3 get there.)
            self.gate.wait_for("c3-in-guard", t);
        }
        // c3 pauses holding its guard, right before replacing the lock,
        // until c2 has returned from acquire.
        if name == "c3" && op == "write" && path.as_str() == LOCK_PATH && !self.gate.seen("c3-in-guard") {
            self.gate.signal("c3-in-guard");
            self.gate.wait_for("c2-acquired", t);
        }
    }
}

impl StorageBackend for Hooked {
    fn kind(&self) -> &'static str {
        "hooked"
    }
    fn read(&self, path: &VPath) -> Result<Vec<u8>> {
        self.inner.read(path)
    }
    fn write(&self, path: &VPath, data: &[u8]) -> Result<()> {
        self.before("write", path);
        self.inner.write(path, data)
    }
    fn create_new(&self, path: &VPath, data: &[u8]) -> Result<bool> {
        self.inner.create_new(path, data)
    }
    fn remove_file(&self, path: &VPath) -> Result<()> {
        self.before("remove", path);
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
    fn set_executable(&self, path: &VPath, executable: bool) -> Result<()> {
        self.inner.set_executable(path, executable)
    }
}

/// A holder died, and so did a contender in the middle of its takeover
/// (leaving `.veil/lock.steal`). Two live contenders now race. Clearing the
/// dead contender's guard is check-then-remove, so contender 2 can remove
/// contender 3's *live* guard; both then pass the guard and both replace the
/// lock. "Two contenders can never both win" (ARCHITECTURE §9) is violated:
/// both `acquire` calls return a lock, and both run crash recovery and a
/// transaction at the same time.
#[cfg(target_os = "linux")]
#[test]
fn two_contenders_never_both_take_over_a_dead_lock() {
    let backend = Arc::new(Hooked {
        inner: MemoryBackend::new(),
        gate: Gate::default(),
    });
    backend.inner.write(&p(LOCK_PATH), &lock_of(dead_pid(), now_ms() - 1000)).unwrap();
    backend.inner.write(&p(STEAL_PATH), &lock_of(dead_pid(), now_ms() - 1000)).unwrap();
    let opts = LockOptions {
        wait: Duration::from_secs(8),
        ..LockOptions::default()
    };
    let (b2, o2) = (backend.clone(), opts.clone());
    let c2 = std::thread::Builder::new()
        .name("c2".into())
        .spawn(move || {
            if let Ok(lock) = RepoLock::acquire_with(b2.clone(), &o2) {
                b2.gate.signal("c2-acquired");
                std::thread::sleep(Duration::from_millis(500));
                b2.gate.signal("c2-releasing");
                drop(lock);
            } else {
                b2.gate.signal("c2-acquired"); // (failed) unblock c3
            }
        })
        .unwrap();
    backend.gate.wait_for("c2-paused", Duration::from_secs(5));
    let (b3, o3) = (backend.clone(), opts);
    let c3 = std::thread::Builder::new()
        .name("c3".into())
        .spawn(move || {
            if let Ok(lock) = RepoLock::acquire_with(b3.clone(), &o3) {
                b3.gate.signal("c3-acquired");
                drop(lock);
            }
        })
        .unwrap();
    c2.join().unwrap();
    c3.join().unwrap();
    let g = &backend.gate;
    let overlap = match (g.index("c2-acquired"), g.index("c2-releasing"), g.index("c3-acquired")) {
        (Some(a), Some(r), Some(c)) => a < c && c < r,
        _ => false,
    };
    assert!(
        !overlap,
        "c3 acquired the lock while c2 still held it (c2 removed c3's live takeover guard): {:?}",
        g.state.lock().unwrap()
    );
}
