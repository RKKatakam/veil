//! Lease-based takeover of locks on network remotes, with simulated hosts
//! and simulated clocks: a crashed holder on another host is taken over
//! once its lease has expired by a margin, a live holder never is (even
//! with a skewed clock), and a stalled holder that wakes up later is
//! fenced off.

use std::{
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use veil_core::{
    lock::{HostIdentity, LockClock, LockContext, LockInfo, LockOptions, RepoLock, SimClock, LOCK_PATH, STEAL_PATH},
    MemoryBackend, StorageBackend, VPath, VeilError,
};

const LEASE: Duration = Duration::from_secs(30);
const GRACE: Duration = Duration::from_secs(15);
const SKEW: Duration = Duration::from_secs(120);

fn opts(wait: Duration) -> LockOptions {
    LockOptions {
        lease: LEASE,
        renew_every: Duration::from_secs(5),
        wait,
    }
}

fn ctx(host: &str, clock: Arc<dyn LockClock>) -> LockContext {
    LockContext {
        fencing: true,
        grace: GRACE,
        skew: SKEW,
        clock,
        host: Some(HostIdentity::simulated(host)),
    }
}

fn fs() -> Arc<dyn StorageBackend> {
    Arc::new(MemoryBackend::new())
}

fn lock_path() -> VPath {
    VPath::new(LOCK_PATH).unwrap()
}

/// The lock file a holder on `host` leaves behind when it crashes (no
/// renewal ever again), written at the clock's current time.
fn crashed_lock(fs: &Arc<dyn StorageBackend>, host: &str, clock: &Arc<SimClock>) -> Vec<u8> {
    let l = RepoLock::acquire_in(fs.clone(), &opts(LEASE), &ctx(host, clock.clone())).unwrap();
    let raw = fs.read(&lock_path()).unwrap();
    drop(l);
    fs.write(&lock_path(), &raw).unwrap();
    raw
}

/// A clock that shares another's time but reads the wall clock `offset_ms` off.
#[derive(Debug)]
struct Skewed(Arc<SimClock>, i64);

impl LockClock for Skewed {
    fn wall_ms(&self) -> i64 {
        self.0.wall_ms() + self.1
    }
    fn now(&self) -> Duration {
        self.0.now()
    }
    fn sleep(&self, d: Duration) {
        self.0.sleep(d)
    }
    fn poll_interval(&self, every: Duration) -> Duration {
        self.0.poll_interval(every)
    }
}

#[test]
fn crashed_holder_on_another_host_is_taken_over_after_lease_plus_grace() {
    let fs = fs();
    let clock = Arc::new(SimClock::new(1_800_000_000_000));
    let crashed = crashed_lock(&fs, "laptop", &clock);
    assert!(veil_core::lock::is_fencing(&crashed));

    let t0 = clock.now();
    let lock = RepoLock::acquire_in(fs.clone(), &opts(Duration::from_secs(5)), &ctx("desktop", clock.clone())).unwrap();
    let waited = clock.now() - t0;
    assert!(waited >= LEASE + GRACE, "taken over too early: {waited:?}");
    assert!(waited < LEASE + GRACE + Duration::from_secs(2), "taken over too late: {waited:?}");
    let holder = RepoLock::holder(&*fs).unwrap().unwrap();
    assert_eq!(holder.host, "desktop");
    lock.ensure_held().unwrap();
}

#[test]
fn a_lease_expired_long_ago_is_taken_over_at_once() {
    let fs = fs();
    let clock = Arc::new(SimClock::new(1_800_000_000_000));
    crashed_lock(&fs, "laptop", &clock);
    // The laptop crashed an hour ago.
    clock.step_wall(3_600_000);
    let t0 = clock.now();
    let _lock = RepoLock::acquire_in(fs.clone(), &opts(LEASE), &ctx("desktop", clock.clone())).unwrap();
    assert!(clock.now() - t0 < Duration::from_secs(1));
}

#[test]
fn wall_clock_age_alone_needs_the_skew_allowance() {
    let fs = fs();
    let clock = Arc::new(SimClock::new(1_800_000_000_000));
    crashed_lock(&fs, "laptop", &clock);
    // Older than lease + grace, but not by the skew allowance: the
    // contender cannot tell this from a holder whose clock is behind, so
    // it has to watch for renewals itself.
    clock.step_wall((LEASE + GRACE).as_millis() as i64 + 1000);
    let t0 = clock.now();
    let _lock = RepoLock::acquire_in(fs.clone(), &opts(LEASE), &ctx("desktop", clock.clone())).unwrap();
    let waited = clock.now() - t0;
    assert!(waited >= LEASE + GRACE && waited < LEASE + GRACE + Duration::from_secs(2), "{waited:?}");
}

#[test]
fn a_live_holder_is_never_taken_over_even_with_a_skewed_clock() {
    let fs = fs();
    let clock = Arc::new(SimClock::new(1_800_000_000_000));
    // The holder's wall clock is 100 s behind: its renewals look old.
    let holder_clock: Arc<dyn LockClock> = Arc::new(Skewed(clock.clone(), -100_000));
    let held = RepoLock::acquire_in(fs.clone(), &opts(LEASE), &ctx("laptop", holder_clock)).unwrap();
    let err = RepoLock::acquire_in(fs.clone(), &opts(Duration::from_secs(180)), &ctx("desktop", clock.clone()))
        .unwrap_err();
    assert!(matches!(err, VeilError::Locked(ref m) if m.contains("laptop")), "{err}");
    held.ensure_held().unwrap();
    assert_eq!(RepoLock::holder(&*fs).unwrap().unwrap().host, "laptop");
}

#[test]
fn a_stalled_holder_fences_itself_and_cannot_overwrite_its_successor() {
    let fs = fs();
    let clock = Arc::new(SimClock::new(1_800_000_000_000));
    let stalled = RepoLock::acquire_in(fs.clone(), &opts(LEASE), &ctx("laptop", clock.clone())).unwrap();
    stalled.pause_renewal();
    stalled.ensure_held().unwrap();
    // Suspended for a whole lease: it may no longer publish, even though
    // nobody has taken the lock yet.
    clock.advance(LEASE);
    assert!(matches!(stalled.ensure_held(), Err(VeilError::Locked(_))));

    let successor =
        RepoLock::acquire_in(fs.clone(), &opts(Duration::from_secs(5)), &ctx("desktop", clock.clone())).unwrap();
    successor.ensure_held().unwrap();
    // The stalled process wakes up: still fenced, and dropping it leaves
    // the successor's lock alone.
    assert!(stalled.ensure_held().is_err());
    drop(stalled);
    successor.ensure_held().unwrap();
    assert_eq!(RepoLock::holder(&*fs).unwrap().unwrap().host, "desktop");
}

#[test]
fn a_lapsed_heartbeat_never_renews_again() {
    let fs = fs();
    let clock = Arc::new(SimClock::new(1_800_000_000_000));
    let held = RepoLock::acquire_in(fs.clone(), &opts(LEASE), &ctx("laptop", clock.clone())).unwrap();
    let before = fs.read(&lock_path()).unwrap();
    // The process was suspended for longer than its lease: on waking, its
    // heartbeat must not "renew" what may be somebody else's lock by now.
    clock.advance(LEASE + Duration::from_secs(1));
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(fs.read(&lock_path()).unwrap(), before, "lapsed lease was renewed");
    assert!(held.ensure_held().is_err());
}

#[test]
fn non_fencing_locks_from_other_hosts_are_still_never_stolen() {
    let fs = fs();
    let clock = Arc::new(SimClock::new(1_800_000_000_000));
    let local_ctx = LockContext {
        fencing: false,
        ..ctx("server", clock.clone())
    };
    let l = RepoLock::acquire_in(fs.clone(), &opts(LEASE), &local_ctx).unwrap();
    let raw = fs.read(&lock_path()).unwrap();
    drop(l);
    fs.write(&lock_path(), &raw).unwrap();
    clock.step_wall(3_600_000);
    let err = RepoLock::acquire_in(fs.clone(), &opts(Duration::from_secs(120)), &ctx("desktop", clock.clone()))
        .unwrap_err();
    assert!(matches!(err, VeilError::Locked(_)), "{err}");
    assert_eq!(fs.read(&lock_path()).unwrap(), raw);
}

#[test]
fn a_crashed_takeover_guard_from_another_host_is_cleared() {
    let fs = fs();
    let clock = Arc::new(SimClock::new(1_800_000_000_000));
    crashed_lock(&fs, "laptop", &clock);
    // A third host crashed in the middle of its own takeover.
    let guard = LockInfo {
        token: "ab".repeat(16),
        pid: 1,
        host: "tablet".into(),
        boot: "simulated-tablet".into(),
        acquired: clock.wall_ms(),
        renewed: clock.wall_ms(),
        lease_ms: 5000,
    };
    let mut raw: serde_json::Value = serde_json::to_value(&guard).unwrap();
    raw["fencing"] = true.into();
    fs.write(&VPath::new(STEAL_PATH).unwrap(), &serde_json::to_vec(&raw).unwrap()).unwrap();
    clock.step_wall(3_600_000);
    let _lock = RepoLock::acquire_in(fs.clone(), &opts(LEASE), &ctx("desktop", clock.clone())).unwrap();
    assert_eq!(RepoLock::holder(&*fs).unwrap().unwrap().host, "desktop");
    assert!(!fs.exists(&VPath::new(STEAL_PATH).unwrap()).unwrap());
}

#[test]
fn contenders_from_several_hosts_take_turns() {
    let fs = fs();
    let clock = Arc::new(SimClock::new(1_800_000_000_000));
    crashed_lock(&fs, "laptop", &clock);
    clock.step_wall(3_600_000);
    let inside = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicUsize::new(0));
    std::thread::scope(|s| {
        for h in ["a", "b", "c", "d"] {
            let (fs, clock, inside, done) = (fs.clone(), clock.clone(), inside.clone(), done.clone());
            s.spawn(move || {
                for _ in 0..3 {
                    let l = RepoLock::acquire_in(fs.clone(), &opts(Duration::from_secs(600)), &ctx(h, clock.clone()))
                        .unwrap();
                    assert!(!inside.swap(true, Ordering::SeqCst), "two holders at once");
                    std::thread::sleep(Duration::from_millis(2));
                    l.ensure_held().unwrap();
                    inside.store(false, Ordering::SeqCst);
                    drop(l);
                    done.fetch_add(1, Ordering::SeqCst);
                }
            });
        }
    });
    assert_eq!(done.load(Ordering::SeqCst), 12);
}

#[test]
fn network_backends_get_fencing_locks() {
    let fs = fs();
    assert!(!LockContext::for_backend(&*fs).fencing);
    assert_eq!(LockOptions::for_backend(&*fs).lease, LockOptions::default().lease);
}
