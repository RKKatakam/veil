//! The repository lock: a renewed lease that is only stolen from a holder
//! that is provably gone.
//!
//! The lock is a single file, `.veil/lock`, created with
//! [`StorageBackend::create_new`], so it works the same on disk and in memory.
//! It holds a JSON [`LockInfo`]: a random per-acquisition token, the holder's
//! pid, host name and boot identity, and a lease.
//!
//! * **Lease renewal.** While a [`RepoLock`] is alive, a heartbeat thread
//!   rewrites the file every `renew_every` with a fresh `renewed` time. A
//!   long transaction (snapshotting a huge working copy) therefore never
//!   looks stale, however long it takes.
//! * **Stealing.** A contender only takes over someone else's lock when the
//!   holder is provably gone: same host, boot and pid namespace with a pid
//!   that no longer runs (taken over at once, whatever the lease says: the
//!   pid may be reused, but never by the process that wrote the token), or
//!   an expired lease last renewed before this machine booted. A holder on
//!   another host, or a live but stuck process, is never robbed; the
//!   contender times out with a message naming the holder instead. Legacy
//!   `"<pid> <millis>"` files (written by local-only earlier versions) are
//!   read as locks of this machine.
//! * **Same process.** Every token held by a live `RepoLock` in this process
//!   is in a registry, with the thread holding it. A lock file carrying this
//!   process's pid but an unregistered token was leaked (its owner dropped
//!   without being able to remove the file, e.g. after a simulated crash),
//!   so it is reclaimed immediately, without waiting for the lease.
//! * **Reentrancy.** [`RepoLock::acquire_reentrant`] returns a nested handle
//!   when the calling thread already holds the lock, so metadata writers can
//!   run both on their own and inside a transaction. Plain
//!   [`RepoLock::acquire`] never nests.
//! * **Atomic takeover.** Takeovers are serialised through a second
//!   `create_new` file, `.veil/lock.steal`. Under it, the contender re-reads
//!   the lock and, only if it still holds the exact bytes that were judged
//!   stale, replaces it with its own in one atomic write, so two contenders
//!   can never both win and no third one slips in between.
//! * **Crash recovery.** The previous holder may have died between writing
//!   objects unsynced and its durability barrier. Right after a takeover,
//!   still under the lock, the new holder runs
//!   [`crate::fsck::recover_interrupted_writes`]: torn objects are removed
//!   and intact ones made durable, before anyone can reuse them.
//! * **Fencing.** [`RepoLock::ensure_held`] re-reads the file and fails if the
//!   token is no longer ours. Transactions call it right before moving the
//!   operation head.
//!
//! **Network remotes: leases with self-fencing.** A repository on an
//! [`StorageBackend::is_network`] backend (SFTP) is shared by clients on
//! other hosts, which can never prove each other gone: under the rules
//! above, a client that crashed mid-push would lock the remote forever.
//! Locks on such a backend are *fencing* locks (`"fencing": true` in the
//! file, [`LockOptions::for_backend`] timings: lease 30 s, renewed every
//! 5 s):
//!
//! * **The holder fences itself.** It remembers, on its own monotonic
//!   clock, when its last successful renewal *started*. Once that is a
//!   whole lease ago it stops renewing and [`RepoLock::ensure_held`]
//!   fails, so it never publishes after its lease ran out, even if it was
//!   suspended, stuck on the network or had its clock changed.
//! * **Anyone may take over an expired fencing lock**, from any host, in
//!   one of two ways. *Observed:* the contender saw the same lock bytes
//!   (no renewal) for `lease + grace` on its own monotonic clock. Clocks
//!   are never compared, so this is immune to skew. *Wall clock:* the
//!   `renewed` time is older than `lease + grace + skew` by the contender's
//!   clock (default skew allowance 2 minutes), for locks abandoned long ago.
//!   A contender facing a fencing lock waits at least `lease + grace`
//!   before giving up, so a crashed pusher's lock is recovered by the next
//!   push (in at most 45 s).
//! * **Why it is safe.** The holder's last renewal started before the
//!   contender first saw its bytes, and the holder stops publishing a lease
//!   after that start; the contender takes over `grace` (15 s) later
//!   still. The residual risk is a holder that stalls for longer than
//!   `grace` *between* its final check and the single write that moves the
//!   operation head (SFTP has no compare-and-swap). Its token check then
//!   catches every later step.
//! * Locks without the flag (local holders, older versions) keep the
//!   provably-gone rule: they are never taken over from another host.
//!
//! [`LockContext`] carries the clock and host identity, so tests simulate
//! hosts and time (see [`SimClock`]).
//!
//! Detecting a dead pid, the host name and the boot id requires asking the
//! host OS. That is process introspection, not repository storage, so it
//! lives here rather than behind the VFS:
//!
//! | | Linux | macOS | other Unix |
//! |---|---|---|---|
//! | host | `/proc/sys/kernel/hostname` | `LocalHostName` (stable across networks), else `gethostname` | `gethostname` |
//! | boot identity | `boot_id` + pid namespace | `kern.bootsessionuuid` | none (host name only) |
//! | boot time | `btime` in `/proc/stat` | `kern.boottime` | unknown |
//! | pid alive | `/proc/<pid>` | `kill(pid, 0)` | `kill(pid, 0)` |

use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex, OnceLock,
    },
    thread::{JoinHandle, ThreadId},
    time::Duration,
};

pub use clock::{LockClock, SimClock, SystemClock};

use serde::{Deserialize, Serialize};

use crate::{
    crypto::random_bytes,
    error::{Result, VeilError},
    now_millis,
    vfs::StorageBackend,
    vpath::VPath,
};

pub const LOCK_PATH: &str = ".veil/lock";
pub const STEAL_PATH: &str = ".veil/lock.steal";

/// Timing parameters of the lock. [`Default`] is what repositories use.
#[derive(Clone, Debug)]
pub struct LockOptions {
    /// How long a lock stays valid without renewal.
    pub lease: Duration,
    /// How often the holder renews its lease.
    pub renew_every: Duration,
    /// How long `acquire` waits for a held lock before giving up.
    pub wait: Duration,
}

impl Default for LockOptions {
    fn default() -> Self {
        LockOptions {
            lease: Duration::from_secs(10),
            renew_every: Duration::from_millis(2500),
            wait: Duration::from_secs(15),
        }
    }
}

impl LockOptions {
    /// Timings for a lock on `backend`. Network backends get a longer
    /// lease (a renewal is several round trips), and contenders wait long
    /// enough to take over an expired one.
    pub fn for_backend(backend: &dyn StorageBackend) -> LockOptions {
        if backend.is_network() {
            LockOptions {
                lease: Duration::from_secs(30),
                renew_every: Duration::from_secs(5),
                wait: Duration::from_secs(90),
            }
        } else {
            LockOptions::default()
        }
    }
}

/// Who is locking, by which clock, and under which takeover rules.
#[derive(Clone, Debug)]
pub struct LockContext {
    /// Write a fencing lock (see the module documentation): renew it, stop
    /// publishing once its lease lapses, and let any host take it over
    /// after expiry. On for network backends.
    pub fencing: bool,
    /// Extra time beyond the lease before an unrenewed fencing lock is
    /// taken over: covers the holder's last write being in flight.
    pub grace: Duration,
    /// Clock skew tolerated between hosts when judging a fencing lock by
    /// its `renewed` wall-clock time.
    pub skew: Duration,
    pub clock: Arc<dyn LockClock>,
    /// Pretend to be this machine (tests); `None`: the real one.
    pub host: Option<HostIdentity>,
}

impl Default for LockContext {
    fn default() -> Self {
        LockContext {
            fencing: false,
            grace: Duration::from_secs(15),
            skew: Duration::from_secs(120),
            clock: Arc::new(SystemClock),
            host: None,
        }
    }
}

impl LockContext {
    pub fn for_backend(backend: &dyn StorageBackend) -> LockContext {
        LockContext {
            fencing: backend.is_network(),
            ..LockContext::default()
        }
    }

    fn me(&self) -> &HostIdentity {
        self.host.as_ref().unwrap_or_else(|| host_identity())
    }
}

/// Content of the lock file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockInfo {
    /// Random, unique per acquisition.
    pub token: String,
    pub pid: u32,
    pub host: String,
    /// Boot id plus pid namespace; empty when the platform cannot tell.
    #[serde(default)]
    pub boot: String,
    pub acquired: i64,
    pub renewed: i64,
    pub lease_ms: i64,
}

/// The lock file: [`LockInfo`] plus the fencing flag (kept out of
/// `LockInfo` so its shape stays what older versions and callers know).
#[derive(Serialize, Deserialize)]
struct LockFile {
    #[serde(flatten)]
    info: LockInfo,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    fencing: bool,
}

fn encode(info: &LockInfo, fencing: bool) -> Vec<u8> {
    if !fencing {
        return info.encode();
    }
    serde_json::to_vec(&LockFile {
        info: info.clone(),
        fencing,
    })
    .expect("lock info serialises")
}

/// Whether a lock file is a fencing lock.
pub fn is_fencing(raw: &[u8]) -> bool {
    serde_json::from_slice::<LockFile>(raw).is_ok_and(|f| f.fencing)
}

impl LockInfo {
    fn new_in(lease: Duration, ctx: &LockContext) -> LockInfo {
        let h = ctx.me();
        let now = ctx.clock.wall_ms();
        LockInfo {
            token: hex::encode(random_bytes::<16>()),
            pid: std::process::id(),
            host: h.host.clone(),
            boot: h.boot.clone(),
            acquired: now,
            renewed: now,
            lease_ms: lease.as_millis() as i64,
        }
    }

    fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("lock info serialises")
    }

    /// Parse a lock file. Also accepts the legacy `"<pid> <millis>"` format
    /// written by earlier versions, which were local-only and used a fixed
    /// 120-second staleness window.
    pub fn parse(raw: &[u8]) -> Option<LockInfo> {
        if let Ok(info) = serde_json::from_slice::<LockInfo>(raw) {
            return Some(info);
        }
        let text = std::str::from_utf8(raw).ok()?;
        let mut parts = text.split_whitespace();
        let pid = parts.next()?.parse().ok()?;
        let ts = parts.next()?.parse().ok()?;
        if parts.next().is_some() {
            return None;
        }
        let h = host_identity();
        Some(LockInfo {
            token: String::new(),
            pid,
            host: h.host.clone(),
            boot: h.boot.clone(),
            acquired: ts,
            renewed: ts,
            lease_ms: 120_000,
        })
    }

    pub fn lease_expired(&self, now: i64) -> bool {
        now.saturating_sub(self.renewed) > self.lease_ms
    }

    pub fn describe(&self) -> String {
        self.describe_at(now_millis())
    }

    fn describe_at(&self, now: i64) -> String {
        format!(
            "pid {} on {} (lease renewed {:.1}s ago)",
            self.pid,
            if self.host.is_empty() {
                "an unknown host"
            } else {
                &self.host
            },
            (now - self.renewed) as f64 / 1000.0
        )
    }
}

/// What a contender may do about a lock file it found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The holder is (or may be) working: wait.
    Wait,
    /// The holder is provably gone: the lock may be removed.
    Steal(String),
    /// The lease expired but the holder cannot be proven gone: wait, and if
    /// the wait times out report this reason.
    Stuck(String),
}

/// Decide whether the (non-fencing) lock described by `info` may be stolen
/// at time `now`.
pub fn assess(info: &LockInfo, now: i64) -> Verdict {
    assess_in(info, false, now, None, &LockContext::default())
}

/// [`assess`] with the fencing flag, how long the contender has seen these
/// exact lock bytes unchanged (`unchanged_for`), and its context.
pub fn assess_in(
    info: &LockInfo,
    fencing: bool,
    now: i64,
    unchanged_for: Option<Duration>,
    ctx: &LockContext,
) -> Verdict {
    let me = ctx.me();
    // On platforms without a boot id both sides are empty and the host name
    // alone identifies the machine.
    let same_machine = !me.host.is_empty() && info.host == me.host && info.boot == me.boot;
    if same_machine && info.pid == std::process::id() {
        return if live_tokens().contains_key(&info.token) {
            Verdict::Wait
        } else {
            Verdict::Steal("left behind by this process".into())
        };
    }
    // A holder on this machine whose pid no longer runs is gone for good:
    // the pid can be reused, but never by the process that wrote this token,
    // so there is nothing to wait for (this is what makes recovery from
    // `kill -9` or Ctrl-C instant). Checked before the lease on purpose.
    if same_machine && process_alive(info.pid) == Some(false) {
        return Verdict::Steal(format!("holder pid {} is no longer running", info.pid));
    }
    if fencing {
        // The holder stops publishing once its lease lapses (it measures
        // that itself), so an expired lease may be taken over from any host.
        let lease = Duration::from_millis(info.lease_ms.max(0) as u64);
        if let Some(seen) = unchanged_for {
            if seen >= lease + ctx.grace {
                return Verdict::Steal(format!("lease not renewed for {}s", seen.as_secs()));
            }
        }
        let limit = lease + ctx.grace + ctx.skew;
        if now.saturating_sub(info.renewed) > limit.as_millis() as i64 {
            return Verdict::Steal(format!(
                "lease expired {}s ago",
                (now.saturating_sub(info.renewed) - info.lease_ms) / 1000
            ));
        }
        return Verdict::Stuck(format!(
            "held by {}; taken over if it is not renewed for {}s",
            info.describe_at(now),
            (lease + ctx.grace).as_secs()
        ));
    }
    if !info.lease_expired(now) {
        return Verdict::Wait;
    }
    if same_machine {
        return match process_alive(info.pid) {
            Some(false) => Verdict::Steal(format!("holder pid {} is no longer running", info.pid)),
            Some(true) => Verdict::Stuck(format!(
                "held by {}, which is still running but no longer renews its lease",
                info.describe()
            )),
            None => Verdict::Stuck(format!("held by {}; cannot check whether it is alive", info.describe())),
        };
    }
    if info.host == me.host {
        if let Some(boot) = boot_time_ms() {
            if info.renewed < boot {
                return Verdict::Steal("last renewed before this machine booted".into());
            }
        }
    }
    Verdict::Stuck(format!(
        "held by {}, which cannot be proven gone from this machine; if it is, remove {LOCK_PATH}",
        info.describe()
    ))
}

// ---- the lock ---------------------------------------------------------------

/// Advisory repository lock, held for the duration of a transaction and
/// released on drop. See the module documentation for the protocol.
#[derive(Debug)]
pub struct RepoLock {
    backend: Arc<dyn StorageBackend>,
    path: VPath,
    token: String,
    lost: Arc<AtomicBool>,
    heartbeat: Option<Heartbeat>,
    /// A handle from [`RepoLock::acquire_reentrant`] inside an outer one:
    /// dropping it releases nothing.
    nested: bool,
    /// Fencing locks only: the lease, and when (holder's monotonic clock)
    /// the last successful renewal started.
    fence: Option<Fence>,
}

#[derive(Clone, Debug)]
struct Fence {
    lease: Duration,
    clock: Arc<dyn LockClock>,
    confirmed: Arc<Mutex<Duration>>,
    /// Tests: stop renewing, as a suspended or partitioned holder would.
    paused: Arc<AtomicBool>,
}

impl Fence {
    fn lapsed(&self) -> bool {
        let confirmed = *self.confirmed.lock().unwrap_or_else(|e| e.into_inner());
        self.clock.now().saturating_sub(confirmed) >= self.lease
    }
}

#[derive(Debug)]
struct Heartbeat {
    stop: mpsc::Sender<()>,
    thread: JoinHandle<()>,
}

/// What a contender has seen of one lock file: the bytes, and since when
/// (its monotonic clock) they have not changed.
#[derive(Default)]
struct Observed(Option<(Vec<u8>, Duration)>);

impl Observed {
    fn see(&mut self, raw: &[u8], now: Duration) -> Duration {
        match &self.0 {
            Some((seen, since)) if seen == raw => now.saturating_sub(*since),
            _ => {
                self.0 = Some((raw.to_vec(), now));
                Duration::ZERO
            }
        }
    }
}

impl RepoLock {
    /// Acquire the lock with the timings and takeover rules for this kind
    /// of backend ([`LockOptions::for_backend`], [`LockContext::for_backend`]).
    pub fn acquire(backend: Arc<dyn StorageBackend>) -> Result<RepoLock> {
        let opts = LockOptions::for_backend(&*backend);
        let ctx = LockContext::for_backend(&*backend);
        Self::acquire_in(backend, &opts, &ctx)
    }

    /// Like [`RepoLock::acquire`], but when the calling *thread* already
    /// holds the lock (an open transaction, say), returns a nested handle
    /// that neither renews nor releases it. Used by the metadata writers
    /// (key rings, embargo records, the vault), which run both on their own
    /// and inside transactions. Transactions themselves never nest.
    pub fn acquire_reentrant(backend: Arc<dyn StorageBackend>) -> Result<RepoLock> {
        let path = VPath::new(LOCK_PATH)?;
        if let Some(info) = backend.read_opt(&path)?.and_then(|raw| LockInfo::parse(&raw)) {
            if held_by_this_thread(&info.token) {
                return Ok(RepoLock {
                    backend,
                    path,
                    token: info.token,
                    lost: Arc::new(AtomicBool::new(false)),
                    heartbeat: None,
                    nested: true,
                    fence: None,
                });
            }
        }
        Self::acquire(backend)
    }

    /// Acquire with explicit timings, and this backend's takeover rules.
    pub fn acquire_with(backend: Arc<dyn StorageBackend>, opts: &LockOptions) -> Result<RepoLock> {
        let ctx = LockContext::for_backend(&*backend);
        Self::acquire_in(backend, opts, &ctx)
    }

    /// Acquire with explicit timings and context (clock, host, fencing).
    pub fn acquire_in(backend: Arc<dyn StorageBackend>, opts: &LockOptions, ctx: &LockContext) -> Result<RepoLock> {
        let path = VPath::new(LOCK_PATH)?;
        let clock = &ctx.clock;
        let start = clock.now();
        let mut wait = opts.wait;
        let mut backoff = Duration::from_millis(1);
        // Unparseable content (a crash of a non-atomic writer) is only
        // reclaimed once it has stayed unchanged for a whole lease; a
        // fencing lock once it has not been renewed for lease + grace.
        let mut observed = Observed::default();
        let mut guard_observed = Observed::default();
        let mut reason = String::from("another process holds the lock");
        loop {
            let info = LockInfo::new_in(opts.lease, ctx);
            // Register before creating the file so no thread of this process
            // ever sees our fresh lock with an unregistered token.
            let token = Registered::new(info.token.clone());
            // The lease runs from before the write that may grant it.
            let attempt = clock.now();
            if backend.create_new(&path, &encode(&info, ctx.fencing))? {
                return Ok(Self::held(backend, path, info, token, opts, ctx, attempt));
            }
            let Some(raw) = backend.read_opt(&path)? else {
                continue; // released between our attempts
            };
            let unchanged_for = observed.see(&raw, clock.now());
            // `Some(since)`: the stale lock may be replaced by ours. Its
            // holder may have died half-way through a batch of unsynced
            // writes made after `since` (`None`: unknown).
            let mut takeover: Option<Option<i64>> = None;
            match LockInfo::parse(&raw) {
                Some(holder) => {
                    let fencing = is_fencing(&raw);
                    if fencing {
                        // Wait long enough to see an expired lease through.
                        let lease = Duration::from_millis(holder.lease_ms.clamp(0, 600_000) as u64);
                        wait = wait.max(lease + ctx.grace + Duration::from_secs(2));
                    }
                    match assess_in(&holder, fencing, clock.wall_ms(), Some(unchanged_for), ctx) {
                        Verdict::Wait => {}
                        Verdict::Stuck(r) => reason = r,
                        Verdict::Steal(_) => takeover = Some(Some(holder.acquired)),
                    }
                }
                None => {
                    if unchanged_for >= opts.lease {
                        takeover = Some(None);
                    }
                    reason = format!("{LOCK_PATH} holds unreadable content");
                }
            }
            if let Some(since) = takeover {
                let attempt = clock.now();
                let ours = encode(&info, ctx.fencing);
                match take_over(&*backend, &path, &raw, &ours, ctx, &mut guard_observed)? {
                    TakeOver::Ours => {
                        let lock = Self::held(backend, path, info, token, opts, ctx, attempt);
                        // Under our lock, before anyone builds on what the
                        // previous holder left: discard its torn objects and
                        // make its intact ones durable.
                        crate::fsck::recover_interrupted_writes(&*lock.backend, since)?;
                        return Ok(lock);
                    }
                    TakeOver::Retry => continue,
                    TakeOver::Busy => {}
                }
            }
            drop(token);
            if clock.now().saturating_sub(start) >= wait {
                return Err(VeilError::Locked(reason));
            }
            clock.sleep(backoff);
            backoff = (backoff * 2).min(Duration::from_millis(50));
        }
    }

    fn held(
        backend: Arc<dyn StorageBackend>,
        path: VPath,
        info: LockInfo,
        token: Registered,
        opts: &LockOptions,
        ctx: &LockContext,
        attempt: Duration,
    ) -> RepoLock {
        let lost = Arc::new(AtomicBool::new(false));
        let fence = ctx.fencing.then(|| Fence {
            lease: opts.lease,
            clock: ctx.clock.clone(),
            confirmed: Arc::new(Mutex::new(attempt)),
            paused: Arc::new(AtomicBool::new(false)),
        });
        let heartbeat = Heartbeat::spawn(
            backend.clone(),
            path.clone(),
            info,
            opts.renew_every,
            lost.clone(),
            ctx.clock.clone(),
            fence.clone(),
        );
        RepoLock {
            backend,
            path,
            token: token.keep(),
            lost,
            heartbeat,
            nested: false,
            fence,
        }
    }

    /// The current holder of the repository lock, if any.
    pub fn holder(backend: &dyn StorageBackend) -> Result<Option<LockInfo>> {
        Ok(backend
            .read_opt(&VPath::new(LOCK_PATH)?)?
            .and_then(|raw| LockInfo::parse(&raw)))
    }

    /// Fail unless the lock file still carries our token (and, for a
    /// fencing lock, our lease has not lapsed). Call right before
    /// publishing the result of a transaction.
    pub fn ensure_held(&self) -> Result<()> {
        let lapsed = || self.fence.as_ref().is_some_and(Fence::lapsed);
        if !self.lost.load(Ordering::SeqCst) {
            if lapsed() {
                self.lost.store(true, Ordering::SeqCst);
                return Err(VeilError::Locked(
                    "this process's lease on the repository lock lapsed (stalled or disconnected for too long); the operation was not recorded".into(),
                ));
            }
            if let Some(raw) = self.backend.read_opt(&self.path)? {
                // Checked again after the round trip: the publication that
                // follows must start inside the lease.
                if LockInfo::parse(&raw).is_some_and(|i| i.token == self.token) && !lapsed() {
                    return Ok(());
                }
            }
            self.lost.store(true, Ordering::SeqCst);
        }
        Err(VeilError::Locked(
            "this process's repository lock was taken over; the operation was not recorded".into(),
        ))
    }

    /// Tests: stop renewing the lease, as a suspended or partitioned holder
    /// would, while the handle stays alive.
    #[doc(hidden)]
    pub fn pause_renewal(&self) {
        if let Some(f) = &self.fence {
            f.paused.store(true, Ordering::SeqCst);
        } else if let Some(hb) = &self.heartbeat {
            let _ = hb.stop.send(());
        }
    }
}

impl Drop for RepoLock {
    fn drop(&mut self) {
        if self.nested {
            return;
        }
        if let Some(hb) = self.heartbeat.take() {
            drop(hb.stop);
            let _ = hb.thread.join();
        }
        // Only remove the file if it is still ours. The token stays
        // registered until then, so no thread of this process can steal it
        // between the check and the removal.
        if let Ok(Some(raw)) = self.backend.read_opt(&self.path) {
            if LockInfo::parse(&raw).is_some_and(|i| i.token == self.token) {
                let _ = self.backend.remove_file(&self.path);
            }
        }
        unregister(&self.token);
    }
}

impl Heartbeat {
    fn spawn(
        backend: Arc<dyn StorageBackend>,
        path: VPath,
        mut info: LockInfo,
        every: Duration,
        lost: Arc<AtomicBool>,
        clock: Arc<dyn LockClock>,
        fence: Option<Fence>,
    ) -> Option<Heartbeat> {
        let (stop, rx) = mpsc::channel::<()>();
        let fencing = fence.is_some();
        let thread = std::thread::Builder::new()
            .name("veil-lock-heartbeat".into())
            .spawn(move || {
                let mut next = clock.now() + every;
                // Disconnection (the lock was dropped) ends the loop; an
                // explicit message pauses renewal for good.
                while let Err(mpsc::RecvTimeoutError::Timeout) = rx.recv_timeout(clock.poll_interval(every)) {
                    let started = clock.now();
                    if started < next {
                        continue;
                    }
                    if let Some(f) = &fence {
                        if f.paused.load(Ordering::SeqCst) {
                            continue;
                        }
                        // A lapsed lease may already belong to someone else:
                        // renewing it now could overwrite their lock.
                        if f.lapsed() {
                            lost.store(true, Ordering::SeqCst);
                            return;
                        }
                    }
                    match backend.read_opt(&path) {
                        Ok(Some(raw)) if LockInfo::parse(&raw).is_some_and(|i| i.token == info.token) => {
                            info.renewed = clock.wall_ms();
                            // A failed renewal is retried on the next tick;
                            // a fencing holder's lease runs out meanwhile.
                            if backend.write(&path, &encode(&info, fencing)).is_ok() {
                                if let Some(f) = &fence {
                                    *f.confirmed.lock().unwrap_or_else(|e| e.into_inner()) = started;
                                }
                                next = started + every;
                            }
                        }
                        Ok(_) => {
                            lost.store(true, Ordering::SeqCst);
                            return;
                        }
                        Err(_) => {}
                    }
                }
            })
            .ok()?;
        Some(Heartbeat { stop, thread })
    }
}

enum TakeOver {
    /// `path` now holds our lock.
    Ours,
    /// The stale lock was gone or changed: try to acquire again at once.
    Retry,
    /// Another contender is taking over: wait.
    Busy,
}

/// How long a takeover guard may be held; a fencing guard older than this
/// (plus grace) is cleared by other contenders.
const GUARD_LEASE: Duration = Duration::from_secs(5);

/// Replace `path` by `ours` if it still holds exactly `observed`, serialised
/// against other contenders through [`STEAL_PATH`]. The stale lock is
/// replaced in one atomic write rather than removed, so no third process can
/// slip in between and skip the crash recovery the new holder performs.
fn take_over(
    backend: &dyn StorageBackend,
    path: &VPath,
    observed: &[u8],
    ours: &[u8],
    ctx: &LockContext,
    guard_seen: &mut Observed,
) -> Result<TakeOver> {
    let guard_path = VPath::new(STEAL_PATH)?;
    let guard = LockInfo::new_in(GUARD_LEASE, ctx);
    let token = Registered::new(guard.token.clone());
    let started = ctx.clock.now();
    if !backend.create_new(&guard_path, &encode(&guard, ctx.fencing))? {
        // Another contender is stealing. If it crashed mid-steal, clear its
        // guard (only when it is provably gone or, for a fencing guard,
        // expired, like any other lock).
        if let Some(raw) = backend.read_opt(&guard_path)? {
            let unchanged = guard_seen.see(&raw, ctx.clock.now());
            if let Some(other) = LockInfo::parse(&raw) {
                let verdict = assess_in(&other, is_fencing(&raw), ctx.clock.wall_ms(), Some(unchanged), ctx);
                if let Verdict::Steal(_) = verdict {
                    if backend.read_opt(&guard_path)?.as_deref() == Some(&raw[..]) {
                        backend.remove_file(&guard_path)?;
                    }
                }
            }
        }
        return Ok(TakeOver::Busy);
    }
    let result = (|| {
        if backend.read_opt(path)?.as_deref() == Some(observed) {
            // A contender that stalled inside its guard may have lost it.
            if ctx.fencing && ctx.clock.now().saturating_sub(started) >= GUARD_LEASE {
                return Ok(TakeOver::Retry);
            }
            backend.write(path, ours)?;
            return Ok(TakeOver::Ours);
        }
        Ok(TakeOver::Retry)
    })();
    backend.remove_file(&guard_path)?;
    drop(token);
    result
}

// ---- process-local registry of live tokens ----------------------------------

/// Token → the thread that holds it.
static LIVE: Mutex<BTreeMap<String, ThreadId>> = Mutex::new(BTreeMap::new());

fn live_tokens() -> std::sync::MutexGuard<'static, BTreeMap<String, ThreadId>> {
    LIVE.lock().unwrap_or_else(|e| e.into_inner())
}

fn unregister(token: &str) {
    live_tokens().remove(token);
}

/// Tokens are random, so a registered token in the lock file proves that
/// this process wrote it; the thread decides reentrancy.
fn held_by_this_thread(token: &str) -> bool {
    !token.is_empty() && live_tokens().get(token) == Some(&std::thread::current().id())
}

/// A token registered as live for as long as this guard exists (or forever,
/// once handed to a `RepoLock` with [`Registered::keep`]).
struct Registered(Option<String>);

impl Registered {
    fn new(token: String) -> Registered {
        live_tokens().insert(token.clone(), std::thread::current().id());
        Registered(Some(token))
    }

    fn keep(mut self) -> String {
        self.0.take().expect("token")
    }
}

impl Drop for Registered {
    fn drop(&mut self) {
        if let Some(t) = &self.0 {
            unregister(t);
        }
    }
}

// ---- clocks -------------------------------------------------------------------

mod clock {
    use std::{
        sync::{Mutex, OnceLock},
        time::{Duration, Instant},
    };

    /// The two clocks a lock needs: wall time (written into the lock file
    /// for other hosts, compared only with a skew allowance) and monotonic
    /// time (leases, waits and observations on this host).
    pub trait LockClock: Send + Sync + std::fmt::Debug {
        /// Milliseconds since the Unix epoch.
        fn wall_ms(&self) -> i64;
        /// Monotonic time since an arbitrary origin.
        fn now(&self) -> Duration;
        fn sleep(&self, d: Duration);
        /// How long (real time) the heartbeat waits between checks of
        /// [`LockClock::now`].
        fn poll_interval(&self, every: Duration) -> Duration {
            every
        }
    }

    #[derive(Debug, Default)]
    pub struct SystemClock;

    impl LockClock for SystemClock {
        fn wall_ms(&self) -> i64 {
            crate::now_millis()
        }
        fn now(&self) -> Duration {
            static ORIGIN: OnceLock<Instant> = OnceLock::new();
            ORIGIN.get_or_init(Instant::now).elapsed()
        }
        fn sleep(&self, d: Duration) {
            std::thread::sleep(d)
        }
    }

    /// Simulated time for tests: `sleep` advances it (after yielding
    /// briefly in real time, so other threads on the same clock run), and
    /// [`SimClock::advance`] jumps it. Share one between simulated hosts,
    /// or give each its own to simulate skew.
    #[derive(Debug)]
    pub struct SimClock {
        state: Mutex<(i64, Duration)>,
    }

    impl SimClock {
        pub fn new(wall_ms: i64) -> SimClock {
            SimClock {
                state: Mutex::new((wall_ms, Duration::from_secs(1_000_000))),
            }
        }

        pub fn advance(&self, d: Duration) {
            let mut s = self.state.lock().unwrap();
            s.0 += d.as_millis() as i64;
            s.1 += d;
        }

        /// Step the wall clock only (an NTP correction, or skew).
        pub fn step_wall(&self, delta_ms: i64) {
            self.state.lock().unwrap().0 += delta_ms;
        }
    }

    impl LockClock for SimClock {
        fn wall_ms(&self) -> i64 {
            self.state.lock().unwrap().0
        }
        fn now(&self) -> Duration {
            self.state.lock().unwrap().1
        }
        fn sleep(&self, d: Duration) {
            std::thread::sleep(Duration::from_micros(500));
            self.advance(d);
        }
        fn poll_interval(&self, _every: Duration) -> Duration {
            Duration::from_micros(200)
        }
    }
}

// ---- host introspection -----------------------------------------------------

/// Which machine (and boot, and pid namespace) a lock holder runs on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostIdentity {
    pub host: String,
    pub boot: String,
}

impl HostIdentity {
    /// This machine.
    pub fn current() -> HostIdentity {
        host_identity().clone()
    }

    /// A made-up machine, for simulating other hosts in tests.
    pub fn simulated(host: &str) -> HostIdentity {
        HostIdentity {
            host: host.to_string(),
            boot: format!("simulated-{host}"),
        }
    }
}

fn host_identity() -> &'static HostIdentity {
    static ID: OnceLock<HostIdentity> = OnceLock::new();
    ID.get_or_init(|| HostIdentity {
        host: host_name(),
        boot: boot_identity(),
    })
}

fn read_trimmed(path: &str) -> Option<String> {
    let s = std::fs::read_to_string(path).ok()?;
    let s = s.trim();
    (!s.is_empty()).then(|| s.to_string())
}

fn command_output(cmd: &str, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new(cmd).args(args).output().ok()?;
    let s = String::from_utf8(out.stdout).ok()?;
    let s = s.trim();
    (out.status.success() && !s.is_empty()).then(|| s.to_string())
}

fn host_name() -> String {
    #[cfg(target_os = "macos")]
    {
        // The kernel host name follows DHCP and VPNs on macOS; a lock must
        // not look foreign because the network changed. `LocalHostName`
        // (the Bonjour name) only changes when the user renames the Mac.
        if let Some(h) = command_output("/usr/sbin/scutil", &["--get", "LocalHostName"]) {
            return h;
        }
    }
    read_trimmed("/proc/sys/kernel/hostname")
        .or_else(gethostname)
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .or_else(|| {
            if cfg!(unix) {
                command_output("uname", &["-n"])
            } else {
                None
            }
        })
        .unwrap_or_default()
}

#[cfg(unix)]
fn gethostname() -> Option<String> {
    let mut buf = [0u8; 256];
    // SAFETY: the buffer is valid for its length; the result is NUL-terminated
    // unless truncated, which the `position` below copes with.
    if unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) } != 0 {
        return None;
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let s = String::from_utf8_lossy(&buf[..end]).trim().to_string();
    (!s.is_empty()).then_some(s)
}

#[cfg(not(unix))]
fn gethostname() -> Option<String> {
    None
}

/// Identifies one boot of one machine *and* the pid namespace, so a pid is
/// only compared against processes it could actually refer to.
fn boot_identity() -> String {
    #[cfg(target_os = "linux")]
    {
        let boot = read_trimmed("/proc/sys/kernel/random/boot_id");
        let ns = std::fs::read_link("/proc/self/ns/pid")
            .ok()
            .map(|p| p.to_string_lossy().into_owned());
        match (boot, ns) {
            (Some(b), Some(n)) => format!("{b}/{n}"),
            _ => String::new(),
        }
    }
    #[cfg(target_os = "macos")]
    {
        // A random UUID per boot (macOS has no pid namespaces).
        sysctl_bytes("kern.bootsessionuuid")
            .map(|b| String::from_utf8_lossy(&b).trim_end_matches('\0').trim().to_string())
            .map(|u| if u.is_empty() { u } else { format!("macos-boot/{u}") })
            .unwrap_or_default()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        String::new()
    }
}

/// When this machine booted (ms since the epoch), if known.
fn boot_time_ms() -> Option<i64> {
    #[cfg(target_os = "macos")]
    {
        let raw = sysctl_bytes("kern.boottime")?;
        if raw.len() < std::mem::size_of::<libc::timeval>() {
            return None;
        }
        // SAFETY: `kern.boottime` is a `struct timeval`; the length was checked.
        let tv: libc::timeval = unsafe { std::ptr::read_unaligned(raw.as_ptr().cast()) };
        Some(i64::from(tv.tv_sec) * 1000 + i64::from(tv.tv_usec) / 1000)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let stat = std::fs::read_to_string("/proc/stat").ok()?;
        let secs: i64 = stat
            .lines()
            .find_map(|l| l.strip_prefix("btime "))?
            .trim()
            .parse()
            .ok()?;
        Some(secs * 1000)
    }
}

/// Raw value of a `sysctl` by name.
#[cfg(target_os = "macos")]
fn sysctl_bytes(name: &str) -> Option<Vec<u8>> {
    let cname = std::ffi::CString::new(name).ok()?;
    let mut len: libc::size_t = 0;
    // SAFETY: size query with a null buffer, then a read into a buffer of
    // exactly the reported size; `len` is updated to what was written.
    unsafe {
        if libc::sysctlbyname(cname.as_ptr(), std::ptr::null_mut(), &mut len, std::ptr::null_mut(), 0) != 0 {
            return None;
        }
        let mut buf = vec![0u8; len];
        if libc::sysctlbyname(cname.as_ptr(), buf.as_mut_ptr().cast(), &mut len, std::ptr::null_mut(), 0) != 0 {
            return None;
        }
        buf.truncate(len);
        Some(buf)
    }
}

/// Whether `pid` is a running process on this machine (zombies count as
/// running); `None` if that cannot be told.
pub fn process_alive(pid: u32) -> Option<bool> {
    #[cfg(target_os = "linux")]
    if std::path::Path::new("/proc/self").exists() {
        return Some(std::path::Path::new(&format!("/proc/{pid}")).exists());
    }
    #[cfg(unix)]
    {
        // pid 0 and negative values address process groups, not a process.
        let Ok(raw) = libc::pid_t::try_from(pid) else { return None };
        if raw <= 0 {
            return None;
        }
        // SAFETY: signal 0 performs only the existence and permission checks.
        if unsafe { libc::kill(raw, 0) } == 0 {
            return Some(true);
        }
        return match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::ESRCH) => Some(false),
            // Exists, but belongs to someone else.
            Some(libc::EPERM) => Some(true),
            _ => None,
        };
    }
    #[allow(unreachable_code)]
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vfs::MemoryBackend;

    fn info(pid: u32, host: &str, boot: &str, renewed_ago_ms: i64) -> LockInfo {
        let now = now_millis();
        LockInfo {
            token: hex::encode(random_bytes::<16>()),
            pid,
            host: host.into(),
            boot: boot.into(),
            acquired: now - renewed_ago_ms,
            renewed: now - renewed_ago_ms,
            lease_ms: 1000,
        }
    }

    fn me() -> &'static HostIdentity {
        host_identity()
    }

    #[test]
    fn legacy_format_parses() {
        let i = LockInfo::parse(b"4242 1700000000000").unwrap();
        assert_eq!((i.pid, i.renewed, i.lease_ms), (4242, 1_700_000_000_000, 120_000));
        assert!(LockInfo::parse(b"").is_none());
        assert!(LockInfo::parse(b"garbage here now").is_none());
    }

    #[test]
    fn fresh_leases_are_never_stolen() {
        let foreign = info(1, "elsewhere", "x", 0);
        assert_eq!(assess(&foreign, now_millis()), Verdict::Wait);
    }

    #[test]
    fn expired_lease_on_another_host_is_stuck_not_stolen() {
        let foreign = info(1, "some-other-host.invalid", "x", 60_000);
        assert!(matches!(assess(&foreign, now_millis()), Verdict::Stuck(_)));
    }

    #[test]
    fn same_process_unregistered_token_is_reclaimed_but_live_one_is_not() {
        let mut i = info(std::process::id(), &me().host, &me().boot, 0);
        if me().host.is_empty() {
            return; // platform cannot identify the machine; nothing is stolen
        }
        assert!(matches!(assess(&i, now_millis()), Verdict::Steal(_)));
        let reg = Registered::new(i.token.clone());
        assert_eq!(assess(&i, now_millis()), Verdict::Wait);
        drop(reg);
        i.renewed = 0;
        assert!(matches!(assess(&i, now_millis()), Verdict::Steal(_)));
    }

    #[test]
    fn heartbeat_renews_the_lease() {
        let fs: Arc<dyn StorageBackend> = Arc::new(MemoryBackend::new());
        let opts = LockOptions {
            lease: Duration::from_millis(150),
            renew_every: Duration::from_millis(20),
            wait: Duration::from_millis(100),
        };
        let lock = RepoLock::acquire_with(fs.clone(), &opts).unwrap();
        let first = RepoLock::holder(&*fs).unwrap().unwrap();
        std::thread::sleep(Duration::from_millis(400));
        let later = RepoLock::holder(&*fs).unwrap().unwrap();
        assert_eq!(first.token, later.token);
        assert!(later.renewed > first.renewed, "lease was renewed");
        assert!(
            !later.lease_expired(now_millis()),
            "a live holder's lease never expires"
        );
        lock.ensure_held().unwrap();
        drop(lock);
        assert!(RepoLock::holder(&*fs).unwrap().is_none());
    }
}
