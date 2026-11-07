//! Round-5 adversarial tests: durability and locks after the latest fixes
//! (failed barriers, `"recover": true` locks, `since_stamp`-bounded crash
//! recovery, process liveness checks).
//!
//! Every `#[ignore = "BUG-NNN: …"]` test asserts the secure behaviour and
//! currently fails; see `docs/BUGS.md` ("Round 5 findings").

use std::{
    sync::Arc,
    time::Duration,
};

use veil_core::{
    lock::{LockInfo, LockOptions, RepoLock, LOCK_PATH}, MemoryBackend, StorageBackend, VPath,
};


fn p(s: &str) -> VPath {
    VPath::new(s).unwrap()
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
