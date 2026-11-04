//! The repository lock: mutual exclusion, lease renewal, and stealing only
//! from holders that are provably gone.

use std::{
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use veil_core::{
    lock::{LockInfo, LockOptions, RepoLock, LOCK_PATH},
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
            let start = Instant::now();
            let l = RepoLock::acquire_with(fs.clone(), &quick(5000)).unwrap();
            assert!(
                start.elapsed() < Duration::from_millis(150),
                "did not wait for the lease ({:?})",
                start.elapsed()
            );
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
    let start = Instant::now();
    drop(RepoLock::acquire_with(fs.clone(), &quick(5000)).unwrap());
    assert!(
        start.elapsed() < Duration::from_millis(150),
        "no need to wait for the lease"
    );
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
