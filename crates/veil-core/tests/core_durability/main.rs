//! Durability: the repository lock, crash injection and the durability barrier.
//!
//! One test binary for several suites, to save linking time and disk: each
//! module was its own binary before (`tests/<module>.rs`, or a directory
//! with a `main.rs`), and is unchanged apart from where its shared support
//! module comes from. No test changes process-wide state (environment,
//! umask, current directory, signal handlers), so the suites can share a
//! process; `cargo nextest` runs every test in its own process anyway.

#[path = "../adversarial_support/mod.rs"]
mod adversarial_support;

mod adversarial2_durability;
mod adversarial5_durability;
mod adversarial6_lock;
mod adversarial_lock;
mod crash;
mod durability;
mod gc_concurrency;
mod lock;
mod maintenance;
mod metadata_lock;
mod oplog_concurrency;
mod oplog_adversarial;

use std::{sync::Arc, time::Duration};

use veil_core::{
    lock::{LockClock, LockContext, LockOptions, RepoLock, SimClock},
    now_millis, StorageBackend,
};

/// Acquire `.veil/lock` on a simulated clock that only the acquisition's own
/// back-off moves: what it returns, and how long it waited, whatever the
/// machine's load (BUG-970: "at once" asserted on the wall clock failed
/// under load).
pub fn acquire_counting_wait(fs: &Arc<dyn StorageBackend>, opts: &LockOptions) -> (veil_core::Result<RepoLock>, Duration) {
    let clock = Arc::new(SimClock::new(now_millis()));
    let ctx = LockContext { clock: clock.clone(), ..LockContext::for_backend(&**fs) };
    let start = clock.now();
    let r = RepoLock::acquire_in(fs.clone(), opts, &ctx);
    (r, clock.now() - start)
}

/// Run the calling test, `test` (its path in this binary), in a process of
/// its own: `true` in that child, where the test's body runs; in the parent,
/// `false` once the child passed. For what is measured per process (its
/// peak memory), which the other tests' threads in this one share
/// (BUG-970).
pub fn in_own_process(test: &str) -> bool {
    const CHILD: &str = "VEIL_TEST_IN_OWN_PROCESS";
    if std::env::var_os(CHILD).is_some() {
        return true;
    }
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args([test, "--exact", "--nocapture", "--test-threads=1"])
        .env(CHILD, "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("1 passed"),
        "{test} in its own process:\n{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    false
}
