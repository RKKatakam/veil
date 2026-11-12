//! The repository lock: mutual exclusion, lease renewal, and stealing only
//! from holders that are provably gone.

use std::{
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use veil_core::{
    lock::{LockContext, LockInfo, LockOptions, ProcEntry, ProcessProbe, RepoLock, Signal, SystemProbe, LOCK_PATH},
    now_millis, DiskBackend, MemoryBackend, StorageBackend, VPath, VeilError,
};

fn lock_path() -> VPath {
    VPath::new(LOCK_PATH).unwrap()
}

fn quick(wait_ms: u64) -> LockOptions {
    LockOptions {
        lease: Duration::from_millis(200),
        renew_every: Duration::from_millis(40),
        wait: Duration::from_millis(wait_ms),
    }
}

/// A lock file as another process on this machine would have written it.
fn foreign_lock(pid: u32, renewed_ago_ms: i64) -> LockInfo {
    // Take host and boot identity from a real lock written by this process.
    let fs = MemoryBackend::new();
    let fs: Arc<dyn StorageBackend> = Arc::new(fs);
    let me = {
        let _l = RepoLock::acquire(fs.clone()).unwrap();
        RepoLock::holder(&*fs).unwrap().unwrap()
    };
    let now = now_millis();
    LockInfo {
        token: "0123456789abcdef0123456789abcdef".into(),
        pid,
        acquired: now - renewed_ago_ms,
        renewed: now - renewed_ago_ms,
        lease_ms: 200,
        ..me
    }
}

fn plant(fs: &dyn StorageBackend, info: &LockInfo) {
    fs.write(&lock_path(), &serde_json::to_vec(info).unwrap()).unwrap();
}

/// A process id that is certainly not running any more.
#[cfg(unix)]
fn dead_pid() -> u32 {
    let mut child = std::process::Command::new("true").spawn().expect("spawn `true`");
    let pid = child.id();
    child.wait().unwrap();
    pid
}

fn backends() -> Vec<(Arc<dyn StorageBackend>, Option<tempfile::TempDir>)> {
    let tmp = tempfile::tempdir().unwrap();
    vec![
        (Arc::new(MemoryBackend::new()), None),
        (Arc::new(DiskBackend::new(tmp.path())), Some(tmp)),
    ]
}

#[test]
fn acquire_and_release() {
    for (fs, _tmp) in backends() {
        let l = RepoLock::acquire(fs.clone()).unwrap();
        let holder = RepoLock::holder(&*fs).unwrap().expect("lock file written");
        assert_eq!(holder.pid, std::process::id());
        l.ensure_held().unwrap();
        drop(l);
        assert!(!fs.exists(&lock_path()).unwrap(), "released on drop ({})", fs.kind());
    }
}

#[test]
fn contended_lock_waits_then_times_out_then_succeeds() {
    for (fs, _tmp) in backends() {
        let held = RepoLock::acquire(fs.clone()).unwrap();
        let start = Instant::now();
        let err = RepoLock::acquire_with(fs.clone(), &quick(150)).unwrap_err();
        assert!(matches!(err, VeilError::Locked(_)), "{err}");
        assert!(start.elapsed() >= Duration::from_millis(150));

        // A waiter gets the lock as soon as the holder lets go.
        let fs2 = fs.clone();
        let waiter = thread::spawn(move || RepoLock::acquire_with(fs2, &quick(5000)).map(|_| Instant::now()));
        thread::sleep(Duration::from_millis(100));
        let released = Instant::now();
        drop(held);
        let got = waiter.join().unwrap().unwrap();
        assert!(got >= released);
    }
}

#[test]
fn mutual_exclusion_under_contention() {
    for (fs, _tmp) in backends() {
        let counter = VPath::new("counter").unwrap();
        fs.write(&counter, b"0").unwrap();
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let fs = fs.clone();
                let counter = counter.clone();
                thread::spawn(move || {
                    for _ in 0..15 {
                        let _l = RepoLock::acquire_with(fs.clone(), &quick(20_000)).unwrap();
                        let n: u32 = String::from_utf8(fs.read(&counter).unwrap()).unwrap().parse().unwrap();
                        thread::yield_now();
                        fs.write(&counter, (n + 1).to_string().as_bytes()).unwrap();
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(fs.read(&counter).unwrap(), b"120", "no lost updates on {}", fs.kind());
    }
}

/// Threads that keep asking for the lock take turns: one that releases and
/// asks again queues behind those already waiting, so no waiter sees more
/// than one acquisition by each other thread while it waits (BUG-1986: a
/// releaser took the lock straight back, about 110 times in a row, and one
/// waiter gave up after its 20 s wait on a loaded machine). Counted in
/// acquisitions, not time, so load cannot make it flaky; the bound has
/// slack for a thread descheduled between counting and asking.
#[test]
fn contenders_take_turns_and_none_starves() {
    use std::sync::atomic::{AtomicU64, Ordering};
    const THREADS: u64 = 8;
    for (fs, _tmp) in backends() {
        let done = Arc::new(AtomicU64::new(0));
        let threads: Vec<_> = (0..THREADS)
            .map(|_| {
                let fs = fs.clone();
                let done = done.clone();
                thread::spawn(move || {
                    let mut spans = Vec::new();
                    for _ in 0..15 {
                        let before = done.load(Ordering::SeqCst);
                        let l = RepoLock::acquire_with(fs.clone(), &quick(20_000));
                        let l = l.expect("acquired within the wait");
                        spans.push(done.load(Ordering::SeqCst) - before);
                        thread::yield_now();
                        done.fetch_add(1, Ordering::SeqCst);
                        drop(l);
                    }
                    spans
                })
            })
            .collect();
        let spans: Vec<Vec<u64>> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        assert_eq!(done.load(Ordering::SeqCst), THREADS * 15, "every acquisition succeeded on {}", fs.kind());
        let worst = spans.iter().flatten().max().copied().unwrap();
        assert!(
            worst <= 3 * (THREADS - 1),
            "on {}, a waiter saw {worst} acquisitions by others while it waited (at most {} with turns); per thread: {spans:?}",
            fs.kind(),
            THREADS - 1
        );
    }
}

#[test]
fn long_transaction_keeps_its_lock() {
    // The old scheme stole any lock older than a fixed age. Now the holder
    // renews its lease, so it outlives many lease periods.
    let fs: Arc<dyn StorageBackend> = Arc::new(MemoryBackend::new());
    let held = RepoLock::acquire_with(fs.clone(), &quick(0)).unwrap();
    thread::sleep(Duration::from_millis(700)); // > 3 leases
    let info = RepoLock::holder(&*fs).unwrap().unwrap();
    assert!(!info.lease_expired(now_millis()), "lease kept fresh by the heartbeat");
    assert!(RepoLock::acquire_with(fs.clone(), &quick(300)).is_err());
    held.ensure_held().unwrap();
}

/// A holder on this machine whose pid no longer runs is gone for good (the
/// pid may be reused, but never by the process that wrote the token), so its
/// lock is taken over at once, whatever its lease says (BUG-026).
#[test]
#[cfg(unix)]
fn dead_holder_is_stolen_immediately() {
    for (fs, _tmp) in backends() {
        let pid = dead_pid();
        for renewed_ago in [0, 60_000] {
            plant(&*fs, &foreign_lock(pid, renewed_ago));
            let (l, waited) = crate::acquire_counting_wait(&fs, &quick(5000));
            let l = l.unwrap();
            assert_eq!(waited, Duration::ZERO, "did not wait for the lease");
            assert_eq!(RepoLock::holder(&*fs).unwrap().unwrap().pid, std::process::id());
            drop(l);
        }
    }
}

#[test]
#[cfg(unix)]
fn live_holder_is_never_robbed_even_with_an_expired_lease() {
    let mut child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("spawn `sleep`");
    let fs: Arc<dyn StorageBackend> = Arc::new(MemoryBackend::new());
    plant(&*fs, &foreign_lock(child.id(), 60_000));
    let err = RepoLock::acquire_with(fs.clone(), &quick(300)).unwrap_err();
    child.kill().unwrap();
    child.wait().unwrap();
    let msg = err.to_string();
    assert!(
        msg.contains(&format!("pid {}", child.id())) && msg.contains("still running"),
        "{msg}"
    );
    assert_eq!(
        RepoLock::holder(&*fs).unwrap().unwrap().pid,
        child.id(),
        "lock untouched"
    );
}

#[test]
#[cfg(unix)]
fn holder_on_another_host_is_never_robbed() {
    let fs: Arc<dyn StorageBackend> = Arc::new(MemoryBackend::new());
    let mut info = foreign_lock(dead_pid(), 3_600_000);
    info.host = "build-server.invalid".into();
    info.boot = "elsewhere".into();
    plant(&*fs, &info);
    let err = RepoLock::acquire_with(fs.clone(), &quick(200)).unwrap_err();
    assert!(err.to_string().contains("build-server.invalid"), "{err}");
}

#[test]
fn lock_leaked_by_this_process_is_reclaimed_immediately() {
    // A crashed transaction in this process could not delete its lock file.
    let fs: Arc<dyn StorageBackend> = Arc::new(MemoryBackend::new());
    plant(&*fs, &foreign_lock(std::process::id(), 0));
    let (l, waited) = crate::acquire_counting_wait(&fs, &quick(5000));
    drop(l.unwrap());
    assert_eq!(waited, Duration::ZERO, "no need to wait for the lease");
}

#[test]
#[cfg(unix)]
fn legacy_and_garbage_lock_files() {
    let fs: Arc<dyn StorageBackend> = Arc::new(MemoryBackend::new());
    // Old "<pid> <millis>" format from a dead process, long expired.
    fs.write(
        &lock_path(),
        format!("{} {}", dead_pid(), now_millis() - 600_000).as_bytes(),
    )
    .unwrap();
    drop(RepoLock::acquire_with(fs.clone(), &quick(2000)).unwrap());

    // Unreadable content is only reclaimed after staying unchanged a lease.
    fs.write(&lock_path(), b"").unwrap();
    let start = Instant::now();
    drop(RepoLock::acquire_with(fs.clone(), &quick(2000)).unwrap());
    assert!(start.elapsed() >= Duration::from_millis(200));
}

#[test]
#[cfg(unix)]
fn concurrent_stealers_never_both_win() {
    for round in 0..5 {
        let fs: Arc<dyn StorageBackend> = Arc::new(MemoryBackend::new());
        let counter = VPath::new("counter").unwrap();
        fs.write(&counter, b"0").unwrap();
        plant(&*fs, &foreign_lock(dead_pid(), 60_000));
        let threads: Vec<_> = (0..6)
            .map(|_| {
                let fs = fs.clone();
                let counter = counter.clone();
                thread::spawn(move || {
                    let _l = RepoLock::acquire_with(fs.clone(), &quick(20_000)).unwrap();
                    let n: u32 = String::from_utf8(fs.read(&counter).unwrap()).unwrap().parse().unwrap();
                    thread::sleep(Duration::from_millis(2));
                    fs.write(&counter, (n + 1).to_string().as_bytes()).unwrap();
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(fs.read(&counter).unwrap(), b"6", "round {round}");
    }
}

#[test]
fn a_taken_over_lock_cannot_commit() {
    let fs: Arc<dyn StorageBackend> = Arc::new(MemoryBackend::new());
    let l = RepoLock::acquire(fs.clone()).unwrap();
    // Someone forcibly replaces the lock (e.g. a user deleting it by hand
    // and another process acquiring it).
    plant(&*fs, &foreign_lock(1, 0));
    assert!(matches!(l.ensure_held(), Err(VeilError::Locked(_))));
    drop(l);
    assert_eq!(
        RepoLock::holder(&*fs).unwrap().unwrap().pid,
        1,
        "drop leaves the new holder's lock alone"
    );
}

#[test]
fn disk_create_new_is_exclusive_and_complete() {
    let tmp = tempfile::tempdir().unwrap();
    let fs = DiskBackend::new(tmp.path());
    let path = VPath::new("a/b/c").unwrap();
    assert!(fs.create_new(&path, b"first").unwrap());
    assert!(!fs.create_new(&path, b"second").unwrap());
    assert_eq!(fs.read(&path).unwrap(), b"first");
    let leftovers: Vec<_> = std::fs::read_dir(tmp.path().join("a/b")).unwrap().collect();
    assert_eq!(leftovers.len(), 1, "no temp files left behind");
    fs.write(&path, b"third").unwrap();
    assert_eq!(fs.read(&path).unwrap(), b"third");
}

// ---- pid reuse, locks left for recovery, takeover guards, recovery window ----

/// `info` with extra lock-file fields (`pid_start`, `since_stamp`,
/// `recover`), as the current version writes them.
fn plant_with(fs: &dyn StorageBackend, path: &VPath, info: &LockInfo, extra: serde_json::Value) {
    let mut v = serde_json::to_value(info).unwrap();
    for (k, x) in extra.as_object().unwrap() {
        v[k] = x.clone();
    }
    fs.write(path, &serde_json::to_vec(&v).unwrap()).unwrap();
}

/// A current lock records its holder's start time: a live process under
/// the holder's pid that started at another time is someone else (the pid
/// was reused), and the lock is taken over at once, even with a fresh lease.
/// With the right start time, the same lock is waited for.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn a_recorded_start_time_tells_a_reused_pid_from_the_holder() {
    let mut alive = std::process::Command::new("sleep").arg("30").spawn().unwrap();
    let start = veil_core::lock::process_start(alive.id()).expect("start time of a live child");
    for (fs, _tmp) in backends() {
        let info = LockInfo {
            lease_ms: 60_000,
            ..foreign_lock(alive.id(), 0)
        };
        plant_with(&*fs, &lock_path(), &info, serde_json::json!({ "pid_start": start.id }));
        let err = RepoLock::acquire_with(fs.clone(), &quick(300)).unwrap_err();
        assert!(matches!(err, VeilError::Locked(_)), "{err}");

        plant_with(&*fs, &lock_path(), &info, serde_json::json!({ "pid_start": start.id + 1 }));
        let (lock, waited) = crate::acquire_counting_wait(&fs, &quick(5_000));
        drop(lock.unwrap());
        assert_eq!(waited, Duration::ZERO, "taken over at once");
    }
    let _ = alive.kill();
    let _ = alive.wait();
}

/// A lock left behind for recovery (`RepoLock::abandon`) is taken over at
/// once, from any host and whatever its lease says, and the new holder runs
/// crash recovery first: a torn object is removed, an intact one kept.
#[test]
fn a_lock_left_for_recovery_is_taken_over_at_once_and_recovered() {
    for (fs, _tmp) in backends() {
        let good = b"intact object".to_vec();
        let good_path = object_path(&veil_core::ObjectId::hash(&good));
        let torn_path = object_path(&veil_core::ObjectId::hash(b"whole object"));
        let info = LockInfo {
            host: "elsewhere".into(),
            boot: "simulated-elsewhere".into(),
            lease_ms: 600_000,
            ..foreign_lock(1, 0)
        };
        plant_with(&*fs, &lock_path(), &info, serde_json::json!({ "recover": true }));
        fs.write_unsynced(&good_path, &good).unwrap();
        fs.write_unsynced(&torn_path, b"whole").unwrap();
        let lock = RepoLock::acquire_with(fs.clone(), &quick(300)).unwrap();
        assert_eq!(RepoLock::holder(&*fs).unwrap().unwrap().pid, std::process::id());
        assert!(!fs.exists(&torn_path).unwrap(), "torn object removed ({})", fs.kind());
        assert_eq!(fs.read(&good_path).unwrap(), good);
        drop(lock);
    }
}

/// `abandon` leaves the lock behind, flagged; the next acquisition, in this
/// process too, takes it over at once.
#[test]
fn an_abandoned_lock_is_left_flagged_and_reclaimed() {
    for (fs, _tmp) in backends() {
        let mut lock = RepoLock::acquire(fs.clone()).unwrap();
        lock.abandon();
        drop(lock);
        let raw = fs.read(&lock_path()).expect("left behind");
        assert!(veil_core::lock::needs_recovery(&raw));
        let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert!(v["since_stamp"].is_i64(), "acquisition stamp recorded: {v}");
        if cfg!(any(target_os = "linux", target_os = "macos")) {
            assert!(v["pid_start"].is_u64(), "holder start time recorded: {v}");
        }
        let (lock, waited) = crate::acquire_counting_wait(&fs, &quick(5_000));
        drop(lock.unwrap());
        assert_eq!(waited, Duration::ZERO, "taken over at once");
        assert!(!fs.exists(&lock_path()).unwrap());
    }
}

fn object_path(id: &veil_core::ObjectId) -> VPath {
    let hex = id.hex();
    VPath::new(&format!(".veil/objects/{}/{}", &hex[..2], &hex[2..])).unwrap()
}

/// A contender crashed holding the takeover guard, and another one crashed
/// while replacing that guard (holding its sub-guard). Both are cleared
/// without ever removing a guard file of someone else, and nothing is
/// left behind.
#[cfg(unix)]
#[test]
fn crashed_takeover_guards_at_two_levels_are_cleared() {
    for (fs, _tmp) in backends() {
        plant(&*fs, &foreign_lock(dead_pid(), 0));
        let guard = foreign_lock(dead_pid(), 0);
        let steal = VPath::new(veil_core::lock::STEAL_PATH).unwrap();
        plant_with(&*fs, &steal, &guard, serde_json::json!({}));
        let raw = fs.read(&steal).unwrap();
        let sub = VPath::new(&format!(
            "{}.{}",
            veil_core::lock::STEAL_PATH,
            &veil_core::ObjectId::hash(&raw).hex()[..16]
        ))
        .unwrap();
        plant_with(&*fs, &sub, &foreign_lock(dead_pid(), 0), serde_json::json!({}));
        let lock = RepoLock::acquire_with(fs.clone(), &quick(2_000)).unwrap();
        let left: Vec<String> = fs
            .list_dir(&VPath::new(".veil").unwrap())
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .filter(|n| n.starts_with("lock.steal"))
            .collect();
        assert!(left.is_empty(), "{left:?} ({})", fs.kind());
        drop(lock);
    }
}

/// A backend that counts reads of loose objects.
#[derive(Debug)]
struct CountingReads {
    inner: MemoryBackend,
    object_reads: std::sync::atomic::AtomicUsize,
}

impl StorageBackend for CountingReads {
    fn kind(&self) -> &'static str {
        "counting"
    }
    fn read(&self, path: &VPath) -> veil_core::Result<Vec<u8>> {
        if path.as_str().starts_with(".veil/objects/") {
            self.object_reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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
    fn set_executable(&self, path: &VPath, executable: bool) -> veil_core::Result<()> {
        self.inner.set_executable(path, executable)
    }
    fn stat_clock(&self) -> Option<veil_core::vfs::StatClock> {
        self.inner.stat_clock()
    }
}

/// Crash recovery after a takeover only re-reads the objects written since
/// the dead holder took the lock (recorded on the backend's own clock), not
/// every object of the last hour or of the whole repository.
#[cfg(unix)]
#[test]
fn recovery_after_a_takeover_reads_only_the_dead_holders_writes() {
    let fs = Arc::new(CountingReads {
        inner: MemoryBackend::new(),
        object_reads: Default::default(),
    });
    for i in 0..200 {
        let data = format!("old object {i}");
        fs.write(&object_path(&veil_core::ObjectId::hash(data.as_bytes())), data.as_bytes())
            .unwrap();
    }
    // A holder takes the lock (its first renewal records when, on the
    // backend's clock), writes three objects unsynced, and dies.
    let holder = foreign_lock(dead_pid(), 0);
    plant(&*fs, &holder);
    let since = fs.metadata(&lock_path()).unwrap().unwrap().mtime.unwrap();
    let renewed = LockInfo {
        renewed: holder.renewed + 2500,
        ..holder
    };
    plant_with(&*fs, &lock_path(), &renewed, serde_json::json!({ "since_stamp": since }));
    for i in 0..3 {
        let data = format!("new object {i}");
        fs.write_unsynced(&object_path(&veil_core::ObjectId::hash(data.as_bytes())), data.as_bytes())
            .unwrap();
    }
    fs.object_reads.store(0, std::sync::atomic::Ordering::SeqCst);
    let counter = fs.clone();
    drop(RepoLock::acquire_with(fs, &quick(2_000)).unwrap());
    let reads = counter.object_reads.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(reads, 3, "only the dead holder's objects are re-read");
}

/// The same holder, crashed before its first renewal (no recorded stamp):
/// the lock file is still the one written at acquisition, and its own
/// stamp bounds the window.
#[cfg(unix)]
#[test]
fn a_holder_that_crashed_before_renewing_is_recovered_from_its_lock_stamp() {
    let fs = Arc::new(CountingReads {
        inner: MemoryBackend::new(),
        object_reads: Default::default(),
    });
    for i in 0..50 {
        let data = format!("old object {i}");
        fs.write(&object_path(&veil_core::ObjectId::hash(data.as_bytes())), data.as_bytes())
            .unwrap();
    }
    plant(&*fs, &foreign_lock(dead_pid(), 0));
    let data = b"new object";
    fs.write_unsynced(&object_path(&veil_core::ObjectId::hash(data)), data).unwrap();
    fs.object_reads.store(0, std::sync::atomic::Ordering::SeqCst);
    let counter = fs.clone();
    drop(RepoLock::acquire_with(fs, &quick(2_000)).unwrap());
    assert_eq!(counter.object_reads.load(std::sync::atomic::Ordering::SeqCst), 1);
}

// ---- restricted /proc (hidepid, foreign pid namespaces) -----------------------------
//
// `hidepid=2` / `ProtectProc=invisible` and a `/proc` of another pid
// namespace cannot be set up without root here, so these tests inject what
// such a `/proc` shows through `LockContext::probe`. The decision
// (`process_alive_with`) is the production code; only the observations of
// `/proc/<pid>` for the holder are simulated, `kill(pid, 0)` is real unless
// stated otherwise.

/// What a restricted `/proc` shows about one pid.
#[derive(Debug)]
struct Restricted {
    pid: u32,
    entry: ProcEntry,
    /// `None`: the real `kill(pid, 0)`.
    signal: Option<Signal>,
}

impl ProcessProbe for Restricted {
    fn entry(&self, pid: u32) -> ProcEntry {
        if pid == self.pid {
            self.entry.clone()
        } else {
            SystemProbe.entry(pid)
        }
    }
    fn signal(&self, pid: u32) -> Signal {
        match self.signal {
            Some(s) if pid == self.pid => s,
            _ => SystemProbe.signal(pid),
        }
    }
}

/// Plant the expired lock of `pid` (a current `vl`, start time recorded)
/// and try to take it over through `probe`. `Ok(true)`: taken over.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn taken_over_through(pid: u32, start: u64, probe: Restricted) -> bool {
    let fs: Arc<dyn StorageBackend> = Arc::new(MemoryBackend::new());
    plant_with(&*fs, &lock_path(), &foreign_lock(pid, 60_000), serde_json::json!({ "pid_start": start }));
    let before = fs.read(&lock_path()).unwrap();
    let ctx = LockContext {
        probe: Arc::new(probe),
        ..LockContext::default()
    };
    match RepoLock::acquire_in(fs.clone(), &quick(300), &ctx) {
        Ok(lock) => {
            drop(lock);
            true
        }
        Err(e) => {
            assert!(matches!(e, VeilError::Locked(_)), "{e}");
            assert_eq!(fs.read(&lock_path()).unwrap(), before, "the lock was left alone");
            false
        }
    }
}

/// Under `hidepid=2` another user's live holder has no `/proc/<pid>`; it
/// used to be judged dead at once and robbed. `kill(pid, 0)` answers
/// `EPERM` for it, so it is running: waited for, never taken over. The
/// same holder, gone (`ESRCH`), is still taken over at once.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn a_holder_hidden_by_hidepid_is_not_taken_over() {
    let mut alive = std::process::Command::new("sleep").arg("30").spawn().unwrap();
    let start = veil_core::lock::process_start(alive.id()).expect("start time").id;
    let hidden = |signal| Restricted {
        pid: alive.id(),
        entry: ProcEntry::Absent,
        signal: Some(signal),
    };
    assert!(!taken_over_through(alive.id(), start, hidden(Signal::NotPermitted)), "another user's live holder");
    assert!(taken_over_through(alive.id(), start, hidden(Signal::NoProcess)), "a holder that is gone");
    // `hidepid=1`: the entry is visible, its files are not.
    let unreadable = Restricted {
        pid: alive.id(),
        entry: ProcEntry::Present {
            zombie: None,
            start: None,
        },
        signal: None,
    };
    assert!(!taken_over_through(alive.id(), start, unreadable), "an entry whose state cannot be read");
    alive.kill().unwrap();
    alive.wait().unwrap();
}

/// With a `/proc` of another pid namespace (`unshare -p` without
/// `--mount-proc`), `/proc/<pid>` names some other process; the probe then
/// reports no usable entry (`/proc/self` is not our pid) and `kill`, which
/// works in our own namespace, decides.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn a_foreign_proc_falls_back_to_kill() {
    let mut alive = std::process::Command::new("sleep").arg("30").spawn().unwrap();
    let start = veil_core::lock::process_start(alive.id()).expect("start time").id;
    let foreign = |pid| Restricted {
        pid,
        entry: ProcEntry::Unavailable,
        signal: None,
    };
    assert!(!taken_over_through(alive.id(), start, foreign(alive.id())), "live holder");
    alive.kill().unwrap();
    alive.wait().unwrap();
    assert!(taken_over_through(alive.id(), start, foreign(alive.id())), "holder gone (ESRCH)");
}

/// The decision table, including what the real `/proc` shows this process.
#[test]
fn liveness_needs_proof_of_death() {
    use veil_core::lock::process_alive_with;
    let probe = |entry, signal| Restricted {
        pid: 4242,
        entry,
        signal: Some(signal),
    };
    let zombie = |z| ProcEntry::Present { zombie: z, start: None };
    let cases = [
        (zombie(Some(true)), Signal::Delivered, Some(false)),
        (zombie(Some(false)), Signal::NoProcess, Some(true)),
        (zombie(None), Signal::Unknown, Some(true)),
        (ProcEntry::Absent, Signal::NotPermitted, Some(true)),
        (ProcEntry::Absent, Signal::NoProcess, Some(false)),
        (ProcEntry::Absent, Signal::Unknown, None),
        (ProcEntry::Unavailable, Signal::Delivered, Some(true)),
        (ProcEntry::Unavailable, Signal::NotPermitted, Some(true)),
        (ProcEntry::Unavailable, Signal::NoProcess, Some(false)),
        (ProcEntry::Unavailable, Signal::Unknown, None),
    ];
    for (entry, signal, want) in cases {
        let p = probe(entry.clone(), signal);
        assert_eq!(process_alive_with(&p, 4242), want, "{entry:?}, {signal:?}");
    }
    #[cfg(target_os = "linux")]
    assert!(matches!(
        SystemProbe.entry(std::process::id()),
        ProcEntry::Present {
            zombie: Some(false),
            start: Some(_)
        }
    ));
}

// ---- leftover takeover sub-guards ------------------------------------------------------

fn guard_names(fs: &dyn StorageBackend) -> Vec<String> {
    let mut names: Vec<String> = fs
        .list_dir(&VPath::new(".veil").unwrap())
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .filter(|n| n.starts_with("lock.steal"))
        .collect();
    names.sort();
    names
}

/// A contender that crashed after winning a dead guard but before
/// releasing the sub-guard it used leaves `lock.steal.<hash>` behind, which
/// no later takeover contends for. It is reported, and the next takeover
/// clears it through the takeover protocol; a sub-guard whose holder still
/// runs is left alone.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn orphaned_sub_guards_are_reported_and_cleared_by_the_next_takeover() {
    let mut alive = std::process::Command::new("sleep").arg("30").spawn().unwrap();
    let start = veil_core::lock::process_start(alive.id()).expect("start time").id;
    for (fs, _tmp) in backends() {
        let dead = |s: &str| VPath::new(&format!("{}.{s}", veil_core::lock::STEAL_PATH)).unwrap();
        plant(&*fs, &foreign_lock(dead_pid(), 0));
        plant_with(&*fs, &dead("0123456789abcdef"), &foreign_lock(dead_pid(), 0), serde_json::json!({}));
        plant_with(
            &*fs,
            &dead("0123456789abcdef.fedcba9876543210"),
            &foreign_lock(dead_pid(), 0),
            serde_json::json!({}),
        );
        let live = dead("00000000ffffffff");
        plant_with(&*fs, &live, &foreign_lock(alive.id(), 0), serde_json::json!({ "pid_start": start }));
        fs.write(&dead("not-a-guard"), b"x").unwrap();

        let guards = veil_core::lock::takeover_guards(&*fs).unwrap();
        let stale: Vec<(&str, bool)> = guards.iter().map(|g| (g.path.as_str(), g.stale.is_some())).collect();
        assert_eq!(
            stale,
            [
                (".veil/lock.steal.00000000ffffffff", false),
                (".veil/lock.steal.0123456789abcdef", true),
                (".veil/lock.steal.0123456789abcdef.fedcba9876543210", true),
            ],
            "({})",
            fs.kind()
        );
        let lock = RepoLock::acquire_with(fs.clone(), &quick(2_000)).unwrap();
        assert_eq!(
            guard_names(&*fs),
            ["lock.steal.00000000ffffffff", "lock.steal.not-a-guard"],
            "({})",
            fs.kind()
        );
        drop(lock);
    }
    alive.kill().unwrap();
    alive.wait().unwrap();
}

/// `vl doctor` clears stale guards without any takeover (the lock is free):
/// a dead top-level guard and a dead orphan, nothing else left behind.
#[cfg(unix)]
#[test]
fn stale_guards_are_cleared_without_a_takeover() {
    for (fs, _tmp) in backends() {
        let steal = VPath::new(veil_core::lock::STEAL_PATH).unwrap();
        plant_with(&*fs, &steal, &foreign_lock(dead_pid(), 0), serde_json::json!({}));
        let orphan = VPath::new(&format!("{}.abcdefabcdefabcd", veil_core::lock::STEAL_PATH)).unwrap();
        plant_with(&*fs, &orphan, &foreign_lock(dead_pid(), 0), serde_json::json!({}));
        let n = veil_core::lock::clear_stale_guards(&*fs, &LockContext::default()).unwrap();
        assert_eq!(n, 2, "({})", fs.kind());
        assert!(guard_names(&*fs).is_empty(), "{:?} ({})", guard_names(&*fs), fs.kind());
        assert!(!fs.exists(&lock_path()).unwrap());
    }
}

/// `vl fsck` names leftover sub-guards, not only `.veil/lock.steal`.
#[cfg(unix)]
#[test]
fn fsck_reports_leftover_sub_guards() {
    let fs: Arc<dyn StorageBackend> = Arc::new(MemoryBackend::new());
    let id = veil_core::Identity::generate("alice");
    drop(veil_core::Repo::init(fs.clone(), Some(id.clone()), "alice").unwrap());
    let orphan = VPath::new(&format!("{}.abcdefabcdefabcd", veil_core::lock::STEAL_PATH)).unwrap();
    plant_with(&*fs, &orphan, &foreign_lock(dead_pid(), 0), serde_json::json!({}));
    let report = veil_core::fsck::fsck(fs.clone(), Some(id)).unwrap();
    let notes: Vec<String> = report.findings.iter().map(|f| f.to_string()).collect();
    assert!(
        notes.iter().any(|n| n.contains(".veil/lock.steal.abcdefabcdefabcd present") && n.contains("stale")),
        "{notes:#?}"
    );
}
