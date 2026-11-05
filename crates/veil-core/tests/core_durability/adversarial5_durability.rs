//! Round-5 adversarial tests: durability and locks after the latest fixes
//! (failed barriers, `"recover": true` locks, `since_stamp`-bounded crash
//! recovery, process liveness checks).
//!
//! Every `#[ignore = "BUG-NNN: …"]` test asserts the secure behaviour and
//! currently fails; see `docs/BUGS.md` ("Round 5 findings").

use std::{
    collections::{BTreeSet, HashSet},
    io,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use veil_core::{
    fsck::{fsck, Severity},
    lock::{needs_recovery, LockInfo, LockOptions, RepoLock, LOCK_PATH},
    vfs::{DirEntry, Metadata, StatClock},
    Identity, MemoryBackend, Repo, Result, StorageBackend, VPath, VeilError,
};

const WS: &str = "default";

fn p(s: &str) -> VPath {
    VPath::new(s).unwrap()
}

// ---- a disk with Linux's failure semantics ---------------------------------------

/// A "disk" over a `MemoryBackend`, shared by several simulated processes.
///
/// * Unsynced writes are volatile until a barrier succeeds.
/// * A barrier listed in `fail_barriers` fails with EIO, and (Linux since
///   4.13) the files it covered read back fine but never reach the disk,
///   unless they are rewritten.
/// * While `refuse_removes` is set, removing an object fails.
/// * `fail_unsynced_writes` makes that many later `write_unsynced` calls
///   fail (ENOSPC), without writing.
/// * `power_loss` tears every file that is not durable.
/// * [`Disk::arm`] makes the k-th mutation from now fail once
///   ([`Fault::Fail`]: ENOSPC for a write, EIO for a removal, a barrier
///   with the semantics above) or crash the process ([`Fault::Crash`]:
///   that mutation and every later one fails, nothing more is applied,
///   unsynced files stay volatile) until [`Disk::disarm`].
#[derive(Debug)]
struct Disk {
    inner: Arc<MemoryBackend>,
    barriers: AtomicUsize,
    fail_barriers: Mutex<BTreeSet<usize>>,
    refuse_removes: AtomicBool,
    fail_unsynced_writes: AtomicUsize,
    volatile: Mutex<HashSet<VPath>>,
    lost: Mutex<HashSet<VPath>>,
    mutations: AtomicUsize,
    fault: Mutex<Option<(usize, Fault)>>,
    fired: AtomicBool,
    crashed: AtomicBool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    Fail,
    Crash,
}

impl Disk {
    fn new(inner: Arc<MemoryBackend>) -> Disk {
        Disk {
            inner,
            barriers: AtomicUsize::new(0),
            fail_barriers: Mutex::default(),
            refuse_removes: AtomicBool::new(false),
            fail_unsynced_writes: AtomicUsize::new(0),
            volatile: Mutex::default(),
            lost: Mutex::default(),
            mutations: AtomicUsize::new(0),
            fault: Mutex::default(),
            fired: AtomicBool::new(false),
            crashed: AtomicBool::new(false),
        }
    }

    fn arm(&self, at: usize, fault: Fault) {
        self.mutations.store(0, Ordering::SeqCst);
        self.fired.store(false, Ordering::SeqCst);
        self.crashed.store(false, Ordering::SeqCst);
        *self.fault.lock().unwrap() = Some((at, fault));
    }

    /// Stop injecting (a new process); whether the fault was reached.
    fn disarm(&self) -> bool {
        *self.fault.lock().unwrap() = None;
        self.crashed.store(false, Ordering::SeqCst);
        self.fired.load(Ordering::SeqCst)
    }

    /// Count one mutation; whether it fails.
    fn faulted(&self) -> bool {
        if self.crashed.load(Ordering::SeqCst) {
            return true;
        }
        let n = self.mutations.fetch_add(1, Ordering::SeqCst);
        match *self.fault.lock().unwrap() {
            Some((at, fault)) if at == n => {
                self.fired.store(true, Ordering::SeqCst);
                self.crashed.store(fault == Fault::Crash, Ordering::SeqCst);
                true
            }
            _ => false,
        }
    }

    /// Fail the next barrier.
    fn fail_next_barrier(&self) {
        let next = self.barriers.load(Ordering::SeqCst);
        self.fail_barriers.lock().unwrap().insert(next);
    }

    fn durable(&self, path: &VPath) {
        self.volatile.lock().unwrap().remove(path);
        self.lost.lock().unwrap().remove(path);
    }

    fn err(what: &str) -> VeilError {
        VeilError::Io {
            path: "<simulated disk>".into(),
            source: io::Error::other(what.to_string()),
        }
    }

    /// Tear (remove, empty, truncate in turn) every file not on disk.
    fn power_loss(&self) -> usize {
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
        gone.len()
    }
}

impl StorageBackend for Disk {
    fn kind(&self) -> &'static str {
        "simulated-disk"
    }
    fn read(&self, path: &VPath) -> Result<Vec<u8>> {
        self.inner.read(path)
    }
    fn write(&self, path: &VPath, data: &[u8]) -> Result<()> {
        if self.faulted() {
            return Err(Self::err("ENOSPC: no space left on device"));
        }
        self.inner.write(path, data)?;
        self.durable(path);
        Ok(())
    }
    fn write_unsynced(&self, path: &VPath, data: &[u8]) -> Result<()> {
        let fail = {
            let left = self.fail_unsynced_writes.load(Ordering::SeqCst);
            left > 0 && self.fail_unsynced_writes.compare_exchange(left, left - 1, Ordering::SeqCst, Ordering::SeqCst).is_ok()
        };
        if fail || self.faulted() {
            return Err(Self::err("ENOSPC: no space left on device"));
        }
        self.inner.write(path, data)?;
        self.lost.lock().unwrap().remove(path);
        self.volatile.lock().unwrap().insert(path.clone());
        Ok(())
    }
    fn sync_barrier(&self) -> Result<()> {
        if self.crashed.load(Ordering::SeqCst) {
            return Err(Self::err("the process is gone"));
        }
        let mut volatile = self.volatile.lock().unwrap();
        let n = self.barriers.fetch_add(1, Ordering::SeqCst);
        let injected = self.faulted();
        if injected && self.crashed.load(Ordering::SeqCst) {
            return Err(Self::err("the process is gone"));
        }
        if injected || self.fail_barriers.lock().unwrap().contains(&n) {
            self.lost.lock().unwrap().extend(volatile.drain());
            return Err(Self::err("EIO: writeback failed"));
        }
        volatile.clear();
        Ok(())
    }
    fn create_new(&self, path: &VPath, data: &[u8]) -> Result<bool> {
        if self.faulted() {
            return Err(Self::err("ENOSPC: no space left on device"));
        }
        let created = self.inner.create_new(path, data)?;
        if created {
            self.durable(path);
        }
        Ok(created)
    }
    fn remove_file(&self, path: &VPath) -> Result<()> {
        if self.faulted() {
            return Err(Self::err("EIO: cannot remove"));
        }
        if self.refuse_removes.load(Ordering::SeqCst) && path.as_str().starts_with(".veil/objects/") {
            return Err(Self::err("EIO: cannot remove"));
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

fn corruption(mem: &Arc<MemoryBackend>, id: &Identity) -> Vec<String> {
    let report = fsck(mem.clone(), Some(id.clone())).unwrap();
    report
        .findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::Corrupt))
        .map(|f| f.to_string())
        .collect()
}

/// A repository with one committed file, and twelve new files (spread over
/// many fanout directories once stored) waiting in the working copy.
fn world() -> (Arc<MemoryBackend>, Arc<Disk>, Identity) {
    let id = Identity::generate("alice");
    let (mem, disk) = world_of(&id);
    (mem, disk, id)
}

fn world_of(id: &Identity) -> (Arc<MemoryBackend>, Arc<Disk>) {
    let mem = Arc::new(MemoryBackend::new());
    // The unsynced-object protocol and lock recovery: formats ≤ 5.
    let mut repo = Repo::init_for_clone_at(mem.clone(), Some(id.clone()), "alice", 5).unwrap();
    mem.write(&p("README"), b"hello\n").unwrap();
    repo.snapshot_workspace(WS, &*mem).unwrap();
    repo.commit_working_copy(WS, "base").unwrap();
    for i in 0..12 {
        mem.write(&p(&format!("src/file{i}.rs")), format!("pub fn f{i}() -> u32 {{ {i} }}\n").as_bytes()).unwrap();
    }
    let disk = Arc::new(Disk::new(mem.clone()));
    (mem, disk)
}

/// Process A snapshots the twelve files; its barrier fails with EIO and
/// the disk refuses to remove the voided objects, so A leaves the lock
/// behind flagged for recovery (the documented path).
fn a_fails_and_leaves_the_lock_for_recovery(disk: &Arc<Disk>, id: &Identity) {
    let backend: Arc<dyn StorageBackend> = disk.clone();
    let mut a = Repo::open(backend.clone(), Some(id.clone()), "alice").unwrap();
    disk.fail_next_barrier();
    disk.refuse_removes.store(true, Ordering::SeqCst);
    assert!(a.snapshot_workspace(WS, &*backend).is_err(), "A's barrier should fail");
    disk.refuse_removes.store(false, Ordering::SeqCst);
    let lock = disk.read(&p(LOCK_PATH)).expect("A left its lock behind");
    assert!(needs_recovery(&lock), "A's lock is flagged for recovery");
    assert!(!disk.lost.lock().unwrap().is_empty(), "A's voided objects are still there");
}

/// Control: when the next holder's recovery succeeds, the retried snapshot
/// survives a power loss.
#[test]
fn a_successful_recovery_makes_the_retry_durable() {
    let (mem, disk, id) = world();
    a_fails_and_leaves_the_lock_for_recovery(&disk, &id);
    let backend: Arc<dyn StorageBackend> = disk.clone();
    let mut c = Repo::open(backend.clone(), Some(id.clone()), "alice").unwrap();
    c.snapshot_workspace(WS, &*backend).expect("retry");
    c.commit_working_copy(WS, "add files").expect("acknowledged");
    disk.power_loss();
    assert_eq!(corruption(&mem, &id), Vec::<String>::new());
}

/// When crash recovery itself fails (here the first rewrite hits ENOSPC),
/// `RepoLock::acquire_in` abandons the new holder's lock (`lock.rs` ≈712).
/// `Drop` writes it back flagged `"recover": true` but with the *new*
/// holder's `since_stamp` (`self.extra`, set in `held()` at its own
/// acquisition). The next contender's recovery window therefore starts
/// after the failed recoverer took over, and skips every object the
/// original holder voided that the failed recovery had not reached yet.
/// Those objects read back intact, so the retried snapshot reuses them,
/// its barrier succeeds and the operation is acknowledged; the next power
/// loss tears them and the head operation references corrupt blobs.
/// (Here the stamp clock is a generation counter; on disk the window has a
/// five-minute margin, which a retry after the user frees space easily
/// exceeds.)
#[test]
fn a_failed_recovery_does_not_narrow_the_next_recovery_window() {
    let (mem, disk, id) = world();
    a_fails_and_leaves_the_lock_for_recovery(&disk, &id);
    let voided = disk.lost.lock().unwrap().len();

    // Process B takes the lock over; its recovery fails on the first
    // rewrite (disk full).
    let backend: Arc<dyn StorageBackend> = disk.clone();
    let mut b = Repo::open(backend.clone(), Some(id.clone()), "alice").unwrap();
    disk.fail_unsynced_writes.store(1, Ordering::SeqCst);
    assert!(b.snapshot_workspace(WS, &*backend).is_err(), "B's recovery should fail");
    assert!(needs_recovery(&disk.read(&p(LOCK_PATH)).unwrap()), "B left the lock for recovery");

    // Process C (space freed): takes over, recovers, retries, commits.
    let mut c = Repo::open(backend.clone(), Some(id.clone()), "alice").unwrap();
    c.snapshot_workspace(WS, &*backend).expect("retry");
    c.commit_working_copy(WS, "add files").expect("acknowledged");
    let still_not_durable = disk.lost.lock().unwrap().len();

    disk.power_loss();
    let bad = corruption(&mem, &id);
    assert!(
        bad.is_empty(),
        "{voided} objects voided by A, {still_not_durable} still not durable after C's acknowledged commit; \
         after a power loss fsck reports:\n{}",
        bad.join("\n")
    );
}

/// BUG-096, swept: after A leaves its lock for recovery, B's takeover and
/// recovery (and the snapshot after it) fail once, or B crashes, at every
/// mutation in turn; optionally the power fails before the next process
/// runs. C then takes over, retries and commits, the power fails, and
/// nothing C's acknowledged commit references may be torn. A third
/// variant fails B *and* C at the same point before D succeeds.
#[test]
fn every_failed_or_interrupted_recovery_still_ends_durable() {
    let id = Identity::generate("alice");
    let mut points = 0;
    let mut recovery_failures = 0;
    for (fault, power_loss_between, chained) in [
        (Fault::Fail, false, false),
        (Fault::Fail, true, false),
        (Fault::Crash, false, false),
        (Fault::Crash, true, false),
        (Fault::Fail, false, true),
    ] {
        for k in 0.. {
            let ctx = format!("{fault:?} at mutation {k}, power loss between: {power_loss_between}, chained: {chained}");
            let (mem, disk) = world_of(&id);
            a_fails_and_leaves_the_lock_for_recovery(&disk, &id);
            let backend: Arc<dyn StorageBackend> = disk.clone();
            let mut fired = false;
            for _ in 0..if chained { 2 } else { 1 } {
                disk.arm(k, fault);
                let result = Repo::open(backend.clone(), Some(id.clone()), "alice")
                    .and_then(|mut b| b.snapshot_workspace(WS, &*backend).map(drop));
                fired = disk.disarm();
                if fired && disk.read_opt(&p(LOCK_PATH)).unwrap().is_some_and(|l| needs_recovery(&l)) {
                    recovery_failures += 1;
                }
                assert!(fired || result.is_ok(), "{ctx}: failed without a fault: {:?}", result.err());
                if power_loss_between {
                    disk.power_loss();
                }
            }
            let mut c = Repo::open(backend.clone(), Some(id.clone()), "alice").unwrap();
            c.snapshot_workspace(WS, &*backend).unwrap_or_else(|e| panic!("{ctx}: retry: {e}"));
            c.commit_working_copy(WS, "add files").unwrap_or_else(|e| panic!("{ctx}: commit: {e}"));
            drop(c);
            disk.power_loss();
            let bad = corruption(&mem, &id);
            assert!(bad.is_empty(), "{ctx}: after a power loss fsck reports:\n{}", bad.join("\n"));
            let repo = Repo::open(mem.clone(), Some(id.clone()), "alice").unwrap();
            let head = repo.op_id();
            assert!(repo.ops().get(&head).is_ok(), "{ctx}: head operation readable");
            if !fired {
                break;
            }
            points += 1;
        }
    }
    assert!(points > 100, "too few fault points: {points}");
    assert!(recovery_failures > 20, "too few failed recoveries: {recovery_failures}");
}

// ---- process liveness ---------------------------------------------------------------

/// Control: a holder that was killed *and reaped* is taken over at once.
#[cfg(target_os = "linux")]
#[test]
fn a_killed_and_reaped_holder_is_taken_over() {
    let backend: Arc<dyn StorageBackend> = Arc::new(MemoryBackend::new());
    let mut child = std::process::Command::new("sleep").arg("60").spawn().unwrap();
    plant_lock_of(&*backend, child.id());
    child.kill().unwrap();
    child.wait().unwrap();
    let opts = LockOptions {
        wait: Duration::from_secs(3),
        ..LockOptions::default()
    };
    RepoLock::acquire_with(backend, &opts).expect("dead holder's lock taken over");
}

/// Plant the lock a `vl` running as `pid` writes (current format, with its
/// process start time), last renewed a minute ago.
#[cfg(target_os = "linux")]
fn plant_lock_of(backend: &dyn StorageBackend, pid: u32) {
    let fresh = Arc::new(MemoryBackend::new());
    drop(RepoLock::acquire(fresh.clone()).map(|l| {
        let raw = fresh.read(&p(LOCK_PATH)).unwrap();
        std::mem::forget(l);
        let mut v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        let info: LockInfo = serde_json::from_slice(&raw).unwrap();
        v["pid"] = pid.into();
        v["token"] = "00112233445566778899aabbccddeeff".into();
        v["acquired"] = (info.acquired - 60_000).into();
        v["renewed"] = (info.renewed - 60_000).into();
        v["pid_start"] = veil_core::lock::process_start(pid).expect("start time").id.into();
        backend.write(&p(LOCK_PATH), &serde_json::to_vec(&v).unwrap()).unwrap();
    }));
}

/// A holder killed by `kill -9` (or a crash) whose parent has not reaped
/// it yet is a zombie: `/proc/<pid>` still exists and its `starttime` is
/// unchanged. `process_alive` (`lock.rs` ≈1388) counts zombies as running
/// ("zombies count as running"), `pid_reused` sees the same start time, so
/// the expired lock is judged "still running but no longer renews its
/// lease" (`Verdict::Stuck`) and is never taken over: the repository stays
/// locked for as long as the parent lives (an IDE, an agent harness or a
/// script that killed a hung `vl` and does not wait for it), not the
/// "instant" recovery from `kill -9` that ARCHITECTURE §9 promises.
#[cfg(target_os = "linux")]
#[test]
fn a_killed_but_unreaped_holder_is_taken_over() {
    let backend: Arc<dyn StorageBackend> = Arc::new(MemoryBackend::new());
    let mut child = std::process::Command::new("sleep").arg("60").spawn().unwrap();
    plant_lock_of(&*backend, child.id());
    child.kill().unwrap();
    // Not reaped yet: the parent is busy elsewhere.
    std::thread::sleep(Duration::from_millis(200));
    let state = std::fs::read_to_string(format!("/proc/{}/stat", child.id())).unwrap_or_default();
    let opts = LockOptions {
        wait: Duration::from_secs(3),
        ..LockOptions::default()
    };
    let res = RepoLock::acquire_with(backend, &opts);
    let _ = child.wait();
    assert!(res.is_ok(), "holder is a zombie ({}); acquire failed: {:?}", state.trim(), res.err());
}
