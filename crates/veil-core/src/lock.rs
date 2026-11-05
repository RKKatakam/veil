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
//! * **Reused pids.** The lock records its holder's start time
//!   (`pid_start`, see [`process_start`]). A live process under the
//!   holder's pid with another start time is someone else: the holder is
//!   gone and the lock is taken over at once. For locks without it (older
//!   versions), a live process that started more than a minute after the
//!   lock's `acquired` time, once the lease has expired, cannot be the
//!   holder either.
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
//!   can never both win and no third one slips in between. A guard left by
//!   a contender that crashed is never removed by others (check-then-remove
//!   could delete a live contender's fresh guard, BUG-049) but replaced the
//!   same way, under a sub-guard named after its bytes (see `claim`).
//! * **Crash recovery.** The previous holder may have died between writing
//!   objects unsynced and its durability barrier. Right after a takeover,
//!   still under the lock, the new holder runs
//!   [`crate::fsck::recover_interrupted_writes`]: torn objects are removed
//!   and intact ones made durable, before anyone can reuse them. Only
//!   objects modified since the dead holder took the lock are read: the
//!   lock records that moment on the backend's own stamp clock
//!   (`since_stamp`, or the lock file's stamp if it was never renewed).
//!   If recovery fails, the lock is left behind for the next contender.
//!   Until it succeeds, the new holder's lock file also records the window
//!   it is recovering (`recover_window`), so a recovery that fails or dies
//!   hands the next holder the dead holder's objects too, not only its own
//!   writes (BUG-096).
//! * **Left for recovery.** A holder whose objects may not be durable and
//!   could not be removed (a failed write barrier, see
//!   [`crate::store::ObjectStore::sync_barrier`]) leaves the lock file
//!   behind flagged `"recover": true` ([`RepoLock::abandon`]). Any
//!   contender takes such a lock over at once and recovers.
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
//! * **Renewal and release are fenced too.** A renewal reads the file,
//!   checks the token, then rewrites it; a takeover landing in between
//!   would be overwritten. That can only happen to a write that lands
//!   `lease + grace` after the previous renewal started, so a renewal that
//!   returns after the holder's lease lapsed counts as losing the lock
//!   (both sides then fail rather than both publish), and a lapsed holder
//!   never removes the file on release.
//! * **Clock skew beyond the allowance.** The wall-clock rule assumes the
//!   holder's and the contender's clocks agree within `skew`. A contender
//!   whose clock runs more than `lease + grace + skew` (165 s) ahead of a
//!   live holder's takes its lock over at once. The holder notices at its
//!   next renewal or [`RepoLock::ensure_held`] and fails, so the expected
//!   result is a failed push, not a double publish. Two races remain, and
//!   neither needs a stall any more: a takeover that lands between a
//!   renewal's check and its write is overwritten (the contender then
//!   fails instead of the holder), and one that lands between the
//!   holder's final check and its operation-head write lets both publish
//!   (the residual window above). `vl doctor --remotes` measures this
//!   machine's clock against each SSH remote's and warns about large
//!   differences.
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
//! | pid alive | `/proc/<pid>/stat` (not a zombie), else `kill(pid, 0)` | `proc_pidinfo` (not a zombie), else `kill(pid, 0)` | `kill(pid, 0)` |
//! | process start | `starttime` in `/proc/<pid>/stat` | `proc_pidinfo` | unknown |
//!
//! **Without the `os` feature** (WASM) there is no host to ask: every
//! engine instance is its own "host" with a random name and pid 0, so a
//! lock is only ever taken over by the instance that wrote it (leaked or
//! left for recovery), never by another; a held lock fails at once (the
//! default wait is zero) and there is no heartbeat thread
//! (docs/ARCHITECTURE.md §13).
//!
//! "Not running" needs proof (see [`process_alive_with`]): a zombie, or
//! `kill` answering `ESRCH`. A `/proc/<pid>` that is missing because
//! `/proc` hides other users' processes (`hidepid=2`,
//! `ProtectProc=invisible`) or belongs to another pid namespace never
//! counts: such a holder is treated as running, waited for and never
//! robbed.

use std::{
    collections::{BTreeMap, HashMap},
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
    fsck::RecoveryWindow,
    id::ObjectId,
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
            // Without an operating system (WASM) the engine runs on one
            // thread: a held lock is held by an instance that cannot
            // release it while we wait, so fail at once.
            wait: if cfg!(feature = "os") {
                Duration::from_secs(15)
            } else {
                Duration::ZERO
            },
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
    /// How holders' processes are looked up ([`SystemProbe`]; tests
    /// simulate restricted `/proc` setups).
    pub probe: Arc<dyn ProcessProbe>,
    /// When this machine booted (ms since the epoch); `None`: ask the
    /// operating system. Tests simulate a reboot with it.
    pub boot_ms: Option<i64>,
}

impl Default for LockContext {
    fn default() -> Self {
        LockContext {
            fencing: false,
            grace: Duration::from_secs(15),
            skew: Duration::from_secs(120),
            clock: Arc::new(SystemClock),
            host: None,
            probe: Arc::new(SystemProbe),
            boot_ms: None,
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

/// What the lock file records beyond [`LockInfo`] (kept out of `LockInfo`
/// so its shape stays what older versions and callers know; every field is
/// omitted when unset, and older versions ignore them).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Extras {
    /// A fencing lock (see the module documentation).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    fencing: bool,
    /// The holder process's start time, as [`process_start`] reports it:
    /// with the pid, it identifies the process, so a reused pid is told
    /// apart from the holder.
    #[serde(default, rename = "pid_start", skip_serializing_if = "Option::is_none")]
    start: Option<u64>,
    /// When the lock was acquired, on the *backend's* stamp clock (the
    /// lock file's own modification stamp right after it was written).
    /// Crash recovery after a takeover only re-checks objects modified
    /// since then.
    #[serde(default, rename = "since_stamp", skip_serializing_if = "Option::is_none")]
    since: Option<i64>,
    /// The holder left the lock behind on purpose because objects it wrote
    /// may not be durable (a failed write barrier, or a failed recovery):
    /// the next contender takes it over at once and recovers.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    recover: bool,
    /// A crash recovery this holder took on and has not finished: the
    /// window of objects a holder before it may have left unsynced. Set
    /// from the takeover write on, and cleared once the recovery succeeds,
    /// so that the next holder still checks them when this one dies or
    /// fails mid-recovery (BUG-096); `since` only covers this holder's own
    /// writes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recover_window: Option<RecoveryWindow>,
}

/// The lock file: [`LockInfo`] plus [`Extras`].
#[derive(Serialize, Deserialize)]
struct LockFile {
    #[serde(flatten)]
    info: LockInfo,
    #[serde(flatten)]
    extra: Extras,
}

fn encode(info: &LockInfo, extra: &Extras) -> Vec<u8> {
    serde_json::to_vec(&LockFile {
        info: info.clone(),
        extra: extra.clone(),
    })
    .expect("lock info serialises")
}

/// Parse a lock file, legacy formats included (their extras are empty).
fn parse_file(raw: &[u8]) -> Option<(LockInfo, Extras)> {
    if let Ok(f) = serde_json::from_slice::<LockFile>(raw) {
        return Some((f.info, f.extra));
    }
    LockInfo::parse(raw).map(|i| (i, Extras::default()))
}

/// Whether a lock file is a fencing lock.
pub fn is_fencing(raw: &[u8]) -> bool {
    serde_json::from_slice::<LockFile>(raw).is_ok_and(|f| f.extra.fencing)
}

/// Whether a lock file was left behind for crash recovery (see
/// [`RepoLock::abandon`]).
pub fn needs_recovery(raw: &[u8]) -> bool {
    serde_json::from_slice::<LockFile>(raw).is_ok_and(|f| f.extra.recover)
}

impl LockInfo {
    fn new_in(lease: Duration, ctx: &LockContext) -> LockInfo {
        let h = ctx.me();
        let now = ctx.clock.wall_ms();
        LockInfo {
            token: hex::encode(random_bytes::<16>()),
            pid: my_pid(),
            host: h.host.clone(),
            boot: h.boot.clone(),
            acquired: now,
            renewed: now,
            lease_ms: lease.as_millis() as i64,
        }
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
            "pid {} on {} ({}{})",
            self.pid,
            if self.host.is_empty() {
                "an unknown host"
            } else {
                &self.host
            },
            lease_age(self.renewed, now),
            // Only the legacy `"<pid> <millis>"` format has no token.
            if self.token.is_empty() { "; legacy lock file" } else { "" }
        )
    }
}

/// When a lease was last renewed, relative to `now`, for messages. A time
/// no version of `vl` writes (before 2000, or more than a day ahead: a
/// damaged or hand-written lock file, a timestamp in another unit) is said
/// to be unreadable rather than turned into a nonsense age.
fn lease_age(renewed: i64, now: i64) -> String {
    const Y2000_MS: i64 = 946_684_800_000;
    const DAY_MS: i64 = 86_400_000;
    if renewed < Y2000_MS || renewed > now.saturating_add(DAY_MS) {
        return format!("lease renewal time unreadable: {renewed}");
    }
    match now - renewed {
        age if age >= 0 => format!("lease renewed {} ago", fmt_age(age)),
        ahead => format!("lease renewed {} in the future; the clocks differ", fmt_age(-ahead)),
    }
}

/// `4.2s`, `3m 05s`, `2h 10m`, `3d 4h`.
fn fmt_age(ms: i64) -> String {
    let s = ms / 1000;
    match s {
        _ if ms < 60_000 => format!("{:.1}s", ms as f64 / 1000.0),
        _ if s < 3_600 => format!("{}m {:02}s", s / 60, s % 60),
        _ if s < 86_400 => format!("{}h {:02}m", s / 3_600, s / 60 % 60),
        _ => format!("{}d {}h", s / 86_400, s / 3_600 % 24),
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
    let extra = Extras {
        fencing,
        ..Extras::default()
    };
    assess_full(info, &extra, now, unchanged_for, ctx)
}

/// Decide about the lock file `raw` (any format) at time `now`; `None` if
/// it cannot be parsed. Unlike [`assess`], this sees everything the file
/// records, such as the holder's process start time.
pub fn assess_raw(raw: &[u8], now: i64) -> Option<Verdict> {
    let (info, extra) = parse_file(raw)?;
    Some(assess_full(&info, &extra, now, None, &LockContext::default()))
}

/// How much later than the lock's `acquired` time a process must have
/// started before it is taken not to be the holder, for locks that do not
/// record the holder's start time (older versions). Generous, because both
/// times are wall-clock readings, which NTP may have stepped in between.
const REUSED_PID_SLACK_MS: i64 = 60_000;

fn assess_full(info: &LockInfo, extra: &Extras, now: i64, unchanged_for: Option<Duration>, ctx: &LockContext) -> Verdict {
    // Its holder gave it up on purpose, for the next holder to recover.
    if extra.recover {
        return Verdict::Steal("left behind for crash recovery".into());
    }
    let fencing = extra.fencing;
    let me = ctx.me();
    // On platforms without a boot id both sides are empty and the host name
    // alone identifies the machine.
    let same_machine = !me.host.is_empty() && info.host == me.host && info.boot == me.boot;
    if same_machine && info.pid == my_pid() {
        if extra.start.is_some() && process_start_with(&*ctx.probe, info.pid).is_some_and(|s| Some(s.id) != extra.start) {
            return Verdict::Steal(format!("holder pid {} was reused by this process", info.pid));
        }
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
    if same_machine {
        match process_alive_with(&*ctx.probe, info.pid) {
            Some(false) => return Verdict::Steal(format!("holder pid {} is no longer running", info.pid)),
            Some(true) => {
                if let Some(why) = pid_reused(info, extra, now, &*ctx.probe) {
                    return Verdict::Steal(why);
                }
            }
            None => {}
        }
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
        return match process_alive_with(&*ctx.probe, info.pid) {
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
    /// What the lock file says (as first written; the heartbeat renews its
    /// own copy). [`RepoLock::abandon`] rewrites it.
    info: LockInfo,
    /// Shared with the heartbeat, which writes it at every renewal.
    extra: Arc<Mutex<Extras>>,
    lost: Arc<AtomicBool>,
    heartbeat: Option<Heartbeat>,
    /// A handle from [`RepoLock::acquire_reentrant`] inside an outer one:
    /// dropping it releases nothing.
    nested: bool,
    /// Fencing locks only: the lease, and when (holder's monotonic clock)
    /// the last successful renewal started.
    fence: Option<Fence>,
    /// Leave the lock file behind, flagged for recovery, instead of
    /// removing it (see [`RepoLock::abandon`]).
    abandoned: bool,
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

/// [`Observed`] for each takeover guard file, by path.
type GuardsSeen = HashMap<String, Observed>;

/// The modification stamp of `path` on the backend's stat clock, if the
/// backend has a usable one.
fn stamp_of(backend: &dyn StorageBackend, path: &VPath) -> Option<i64> {
    backend.stat_clock()?;
    backend.metadata(path).ok()??.mtime
}

/// Which loose objects the holder of the stale lock `info` may have left
/// unsynced, for [`crate::fsck::recover_interrupted_writes`].
fn recovery_window(backend: &dyn StorageBackend, path: &VPath, info: &LockInfo, extra: &Extras) -> RecoveryWindow {
    let own = own_window(backend, path, info, extra);
    // A recovery the holder had not finished is still owed.
    extra.recover_window.map_or(own, |pending| own.union(pending))
}

/// The objects the holder of `info` itself may have written unsynced.
fn own_window(backend: &dyn StorageBackend, path: &VPath, info: &LockInfo, extra: &Extras) -> RecoveryWindow {
    if let Some(since) = extra.since {
        return RecoveryWindow::Stamp(since);
    }
    // Never renewed: the file is still the one written when the lock was
    // acquired, so its own stamp is the acquisition time. (The caller
    // replaces it only if it still holds the bytes it judged, so this is
    // the stamp of that version.)
    if info.renewed == info.acquired {
        if let Some(stamp) = stamp_of(backend, path) {
            return RecoveryWindow::Stamp(stamp);
        }
    }
    RecoveryWindow::Wall(info.acquired)
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
        if let Some((info, extra)) = backend.read_opt(&path)?.and_then(|raw| parse_file(&raw)) {
            if held_by_this_thread(&info.token) {
                return Ok(RepoLock {
                    backend,
                    path,
                    token: info.token.clone(),
                    info,
                    extra: Arc::new(Mutex::new(extra)),
                    lost: Arc::new(AtomicBool::new(false)),
                    heartbeat: None,
                    nested: true,
                    fence: None,
                    abandoned: false,
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
        let mut guards_seen = GuardsSeen::new();
        let mut reason = String::from("another process holds the lock");
        let extra = Extras {
            fencing: ctx.fencing,
            start: my_start(),
            ..Extras::default()
        };
        let mut first = true;
        loop {
            // Every way round the loop (including `continue`) passes the
            // deadline and the back-off: a lock path that keeps defeating
            // `create_new` without reading back as a lock must never spin
            // (BUG-119).
            if !first {
                if clock.now().saturating_sub(start) >= wait {
                    return Err(VeilError::Locked(reason));
                }
                clock.sleep(backoff);
                backoff = (backoff * 2).min(Duration::from_millis(50));
            }
            first = false;
            let info = LockInfo::new_in(opts.lease, ctx);
            // Register before creating the file so no thread of this process
            // ever sees our fresh lock with an unregistered token.
            let token = Registered::new(info.token.clone());
            // The lease runs from before the write that may grant it.
            let attempt = clock.now();
            if backend.create_new(&path, &encode(&info, &extra))? {
                return Ok(Self::held(backend, path, info, extra, token, opts, ctx, attempt));
            }
            let Some(raw) = backend.read_opt(&path)? else {
                // Released between our attempts, or something that is not a
                // file (a symlink: invisible to `read`, yet `create_new`
                // fails on it) that would make us spin for ever (BUG-119).
                if let Some(what) = backend.special_at(&path)? {
                    return Err(not_a_lock_file(LOCK_PATH, what));
                }
                reason = format!("{LOCK_PATH} exists but cannot be read");
                continue;
            };
            let unchanged_for = observed.see(&raw, clock.now());
            // `Some(window)`: the stale lock may be replaced by ours. Its
            // holder may have died half-way through a batch of unsynced
            // writes, made within `window`.
            let mut takeover: Option<RecoveryWindow> = None;
            match parse_file(&raw) {
                Some((holder, holder_extra)) => {
                    if holder_extra.fencing {
                        // Wait long enough to see an expired lease through.
                        let lease = Duration::from_millis(holder.lease_ms.clamp(0, 600_000) as u64);
                        wait = wait.max(lease + ctx.grace + Duration::from_secs(2));
                    }
                    match assess_full(&holder, &holder_extra, clock.wall_ms(), Some(unchanged_for), ctx) {
                        Verdict::Wait => reason = String::from("another process holds the lock"),
                        Verdict::Stuck(r) => reason = r,
                        Verdict::Steal(_) => {
                            takeover = Some(recovery_window(&*backend, &path, &holder, &holder_extra));
                        }
                    }
                }
                None => {
                    if unchanged_for >= opts.lease {
                        takeover = Some(RecoveryWindow::All);
                    }
                    reason = format!("{LOCK_PATH} holds unreadable content");
                }
            }
            if let Some(window) = takeover {
                let attempt = clock.now();
                // The window stays in our lock file until the recovery has
                // succeeded: if we fail or die before that, the next holder
                // recovers it too, not only what we wrote (BUG-096).
                let extra = Extras {
                    recover_window: Some(window),
                    ..extra.clone()
                };
                let ours = encode(&info, &extra);
                match take_over(&*backend, &path, &raw, &ours, ctx, &mut guards_seen)? {
                    TakeOver::Ours => {
                        let mut lock = Self::held(backend, path, info, extra, token, opts, ctx, attempt);
                        // Under our lock, before anyone builds on what the
                        // previous holder left: discard its torn objects and
                        // make its intact ones durable. Until that succeeds
                        // the lock is marked to be left for the next holder
                        // (also if recovery panics).
                        lock.abandon();
                        crate::fsck::recover_interrupted_writes(&*lock.backend, window)?;
                        lock.abandoned = false;
                        lock.extras().recover_window = None;
                        // A contender that crashed mid-takeover may have
                        // left takeover sub-guards nobody will contend for
                        // again; clear those that are provably stale.
                        let _ = clear_stale_guards(&*lock.backend, ctx);
                        return Ok(lock);
                    }
                    TakeOver::Retry => continue,
                    TakeOver::Busy => {}
                }
            }
            drop(token);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn held(
        backend: Arc<dyn StorageBackend>,
        path: VPath,
        info: LockInfo,
        mut extra: Extras,
        token: Registered,
        opts: &LockOptions,
        ctx: &LockContext,
        attempt: Duration,
    ) -> RepoLock {
        // Our acquisition time on the backend's own clock: renewals record
        // it, so a takeover after our crash knows which objects to check.
        extra.since = stamp_of(&*backend, &path);
        let lost = Arc::new(AtomicBool::new(false));
        let fence = ctx.fencing.then(|| Fence {
            lease: opts.lease,
            clock: ctx.clock.clone(),
            confirmed: Arc::new(Mutex::new(attempt)),
            paused: Arc::new(AtomicBool::new(false)),
        });
        let extra = Arc::new(Mutex::new(extra));
        let heartbeat = Heartbeat::spawn(
            backend.clone(),
            path.clone(),
            info.clone(),
            extra.clone(),
            opts.renew_every,
            lost.clone(),
            ctx.clock.clone(),
            fence.clone(),
        );
        RepoLock {
            backend,
            path,
            token: token.keep(),
            info,
            extra,
            lost,
            heartbeat,
            nested: false,
            fence,
            abandoned: false,
        }
    }

    fn extras(&self) -> std::sync::MutexGuard<'_, Extras> {
        self.extra.lock().unwrap_or_else(|e| e.into_inner())
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

    /// On release, leave the lock file behind, flagged for crash recovery,
    /// instead of removing it: objects written under this lock may not be
    /// durable and could not be cleaned up (a failed write barrier whose
    /// files could not be removed, or a failed recovery). The next
    /// contender, in this process or another, on any host, takes it over
    /// at once and runs [`crate::fsck::recover_interrupted_writes`] before
    /// anything else. No effect on a nested handle (it releases nothing).
    pub fn abandon(&mut self) {
        self.abandoned = true;
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
        // A fencing holder whose lease lapsed cannot tell whether a file
        // carrying its token is still its lock (a late renewal may have
        // replaced a successor's): it leaves the file alone, and the next
        // contender takes it over (with crash recovery) once it expires.
        let fenced = || self.fence.as_ref().is_some_and(|f| self.lost.load(Ordering::SeqCst) || f.lapsed());
        if let Ok(Some(raw)) = self.backend.read_opt(&self.path) {
            if LockInfo::parse(&raw).is_some_and(|i| i.token == self.token) && !fenced() {
                if self.abandoned {
                    // Durably flagged; if even that fails, the file stays as
                    // it is, which a contender reclaims once this process
                    // is gone (or at once, within this process).
                    let mut info = self.info.clone();
                    info.renewed = now_millis().max(info.acquired);
                    let extra = Extras {
                        recover: true,
                        ..self.extras().clone()
                    };
                    let _ = self.backend.write(&self.path, &encode(&info, &extra));
                } else {
                    let _ = self.backend.remove_file(&self.path);
                }
            }
        }
        unregister(&self.token);
    }
}

impl Heartbeat {
    #[allow(clippy::too_many_arguments)]
    fn spawn(
        backend: Arc<dyn StorageBackend>,
        path: VPath,
        mut info: LockInfo,
        extra: Arc<Mutex<Extras>>,
        every: Duration,
        lost: Arc<AtomicBool>,
        clock: Arc<dyn LockClock>,
        fence: Option<Fence>,
    ) -> Option<Heartbeat> {
        // No threads without an operating system (WASM): the lease is not
        // renewed. Harmless there: nobody else ever takes over this
        // instance's lock (see `host_identity`).
        if cfg!(not(feature = "os")) {
            return None;
        }
        let (stop, rx) = mpsc::channel::<()>();
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
                            let extra = extra.lock().unwrap_or_else(|e| e.into_inner()).clone();
                            // A failed renewal is retried on the next tick;
                            // a fencing holder's lease runs out meanwhile.
                            if backend.write(&path, &encode(&info, &extra)).is_ok() {
                                if let Some(f) = &fence {
                                    // The check above and this write are not
                                    // atomic (SFTP has no compare-and-swap),
                                    // so the write may have replaced a
                                    // takeover that landed in between. No
                                    // contender takes over before our previous
                                    // renewal is `lease + grace` old; a write
                                    // that returned before our lease lapsed
                                    // landed before that. One that returned
                                    // later may have overwritten a successor:
                                    // the lease is then treated as lost, so
                                    // neither side publishes.
                                    if f.lapsed() {
                                        lost.store(true, Ordering::SeqCst);
                                        return;
                                    }
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

/// How many crashed guard holders in a row [`claim`] works through.
const MAX_GUARD_DEPTH: usize = 8;

/// Replace `path` by `ours` if it still holds exactly `observed`, serialised
/// against other contenders through the guard [`STEAL_PATH`]. The stale
/// lock is replaced in one atomic write rather than removed, so no third
/// process can slip in between and skip the crash recovery the new holder
/// performs.
fn take_over(
    backend: &dyn StorageBackend,
    path: &VPath,
    observed: &[u8],
    ours: &[u8],
    ctx: &LockContext,
    seen: &mut GuardsSeen,
) -> Result<TakeOver> {
    let guard_path = VPath::new(STEAL_PATH)?;
    let started = ctx.clock.now();
    let Some(guard) = claim(backend, &guard_path, ctx, seen, 0)? else {
        return Ok(TakeOver::Busy);
    };
    let result = (|| -> Result<TakeOver> {
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
    let released = guard.release(backend, &guard_path);
    let result = result?;
    released?;
    Ok(result)
}

/// The error for a lock or guard path occupied by something that is not a
/// file, such as a symlink (`what`: "a symlink", …). Nothing reads through
/// or removes it on the user's behalf: it may be tampering, or a restore
/// that turned files into links, and only the user can tell (BUG-119).
fn not_a_lock_file(path: &str, what: &str) -> VeilError {
    VeilError::Locked(format!(
        "{path} is {what}, not a lock file; nothing can lock this repository until it is removed \
         (check that no Veil command is running, then remove {path})"
    ))
}

/// A takeover guard this contender holds: its bytes, and its token
/// (registered as live until the guard is released).
struct Guard {
    raw: Vec<u8>,
    _token: Registered,
}

impl Guard {
    /// Remove the guard file if it is still ours. Nobody replaces a live
    /// holder's guard (see [`claim`]), so the check cannot race.
    fn release(self, backend: &dyn StorageBackend, path: &VPath) -> Result<()> {
        if backend.read_opt(path)?.as_deref() == Some(&self.raw[..]) {
            backend.remove_file(path)?;
        }
        Ok(())
    }
}

/// Take the guard file `path`: create it, or replace a guard whose holder
/// is provably gone (a contender that crashed mid-takeover). `None`: held
/// by someone else, try later.
///
/// A dead holder's guard is never *removed*: with check-then-remove, two
/// contenders that both judged it dead could each remove it, the second one
/// deleting the guard the first had meanwhile created, and both would take
/// over (BUG-049). Instead it is replaced in one write, under a guard of
/// its own, `<path>.<hash of the dead guard's bytes>`, claimed the same way
/// (a crashed holder of that one is handled one level further down). Only
/// a contender holding that sub-guard writes `path`, and only while `path`
/// still holds those exact dead bytes, which no one ever writes again
/// (they contain a random token). So at most one contender wins each dead
/// guard, and every guard is removed only by its own holder.
///
/// Sub-guards are removed by their holders too; one is left behind only
/// when a contender crashes while holding it. It is harmless (no later
/// guard hashes to its name once the guard it was named after is gone);
/// [`clear_stale_guards`] removes it through this same protocol.
fn claim(
    backend: &dyn StorageBackend,
    path: &VPath,
    ctx: &LockContext,
    seen: &mut GuardsSeen,
    depth: usize,
) -> Result<Option<Guard>> {
    let mine = LockInfo::new_in(GUARD_LEASE, ctx);
    let token = Registered::new(mine.token.clone());
    let raw_mine = encode(
        &mine,
        &Extras {
            fencing: ctx.fencing,
            start: my_start(),
            ..Extras::default()
        },
    );
    let guard = Guard {
        raw: raw_mine,
        _token: token,
    };
    let started = ctx.clock.now();
    if backend.create_new(path, &guard.raw)? {
        return Ok(Some(guard));
    }
    if depth >= MAX_GUARD_DEPTH {
        return Ok(None);
    }
    let Some(theirs) = backend.read_opt(path)? else {
        // A symlink there would keep every takeover busy (BUG-119).
        if let Some(what) = backend.special_at(path)? {
            return Err(not_a_lock_file(path.as_str(), what));
        }
        return Ok(None); // released meanwhile: the caller retries
    };
    let unchanged = seen
        .entry(path.as_str().to_string())
        .or_default()
        .see(&theirs, ctx.clock.now());
    let dead = match parse_file(&theirs) {
        Some((other, extra)) => matches!(
            assess_full(&other, &extra, ctx.clock.wall_ms(), Some(unchanged), ctx),
            Verdict::Steal(_)
        ),
        // A torn guard (non-atomic fallback of `create_new`).
        None => unchanged >= GUARD_LEASE * 2,
    };
    if !dead {
        return Ok(None);
    }
    let sub_path = VPath::new(&format!("{}.{}", path.as_str(), &ObjectId::hash(&theirs).hex()[..16]))?;
    let Some(sub) = claim(backend, &sub_path, ctx, seen, depth + 1)? else {
        return Ok(None);
    };
    let won = (|| -> Result<bool> {
        if backend.read_opt(path)?.as_deref() != Some(&theirs[..]) {
            return Ok(false);
        }
        // A contender that stalled holding the sub-guard may have lost it.
        if ctx.fencing && ctx.clock.now().saturating_sub(started) >= GUARD_LEASE {
            return Ok(false);
        }
        backend.write(path, &guard.raw)?;
        Ok(true)
    })();
    let released = sub.release(backend, &sub_path);
    let won = won?;
    released?;
    Ok(won.then_some(guard))
}

/// A takeover guard file found in `.veil/` (see [`takeover_guards`]).
#[derive(Clone, Debug)]
pub struct GuardFile {
    /// `.veil/lock.steal`, or a sub-guard `.veil/lock.steal.<hash>…`.
    pub path: VPath,
    /// How many `.<hash>` levels below [`STEAL_PATH`] it is.
    pub depth: usize,
    /// Who holds it, if its content parses.
    pub holder: Option<LockInfo>,
    /// Whether its holder is provably gone (so the guard is stale), with
    /// the reason; `None` while it may still be in use.
    pub stale: Option<String>,
}

/// The takeover guard and sub-guards present in `.veil/`, shallowest
/// first, each judged by the takeover rules (for `vl fsck` and
/// `vl doctor`). A guard is only ever held for the few milliseconds of a
/// takeover; one that stays was left by a contender that crashed. A
/// leftover top-level guard is cleared by the next takeover, and stale
/// sub-guards by [`clear_stale_guards`].
pub fn takeover_guards(backend: &dyn StorageBackend) -> Result<Vec<GuardFile>> {
    takeover_guards_in(backend, &LockContext::for_backend(backend))
}

fn takeover_guards_in(backend: &dyn StorageBackend, ctx: &LockContext) -> Result<Vec<GuardFile>> {
    let dir = VPath::new(".veil")?;
    let Some(base) = STEAL_PATH.strip_prefix(".veil/") else { return Ok(Vec::new()) };
    let mut out = Vec::new();
    let entries = match backend.list_dir(&dir) {
        Ok(e) => e,
        Err(_) if !backend.exists(&dir)? => return Ok(out),
        Err(e) => return Err(e),
    };
    for e in entries {
        let Some(rest) = e.name.strip_prefix(base) else { continue };
        // `""` or `.<16 hex>` repeated: anything else is not ours.
        let levels: Vec<&str> = rest.split('.').skip(1).collect();
        let well_formed = rest.is_empty()
            || (rest.starts_with('.') && levels.iter().all(|l| l.len() == 16 && l.bytes().all(|b| b.is_ascii_hexdigit())));
        if !well_formed || e.kind != crate::vfs::NodeKind::File {
            continue;
        }
        let path = dir.join(&e.name);
        let Some(raw) = backend.read_opt(&path)? else { continue };
        let parsed = parse_file(&raw);
        let stale = match &parsed {
            Some((info, extra)) => match assess_full(info, extra, ctx.clock.wall_ms(), None, ctx) {
                Verdict::Steal(why) => Some(why),
                Verdict::Wait | Verdict::Stuck(_) => None,
            },
            None => None,
        };
        out.push(GuardFile {
            path,
            depth: levels.len(),
            holder: parsed.map(|(i, _)| i),
            stale,
        });
    }
    out.sort_by(|a, b| (a.depth, a.path.as_str()).cmp(&(b.depth, b.path.as_str())));
    Ok(out)
}

/// Remove the takeover guards whose holders are provably gone (see
/// [`takeover_guards`]); returns how many. Run after every takeover.
///
/// A guard is never removed by check-then-remove (BUG-049): each one is
/// *claimed* by the takeover protocol (replaced in one write under a
/// sub-guard named after its bytes, see `claim`), and then released like
/// any guard its holder is done with. So a guard a live contender holds,
/// or claims meanwhile, is never touched.
pub fn clear_stale_guards(backend: &dyn StorageBackend, ctx: &LockContext) -> Result<usize> {
    let mut seen = GuardsSeen::new();
    let mut cleared = 0;
    for g in takeover_guards_in(backend, ctx)? {
        if g.stale.is_none() || !backend.exists(&g.path)? {
            continue; // in use, or already cleared through a parent
        }
        if let Some(guard) = claim(backend, &g.path, ctx, &mut seen, g.depth)? {
            guard.release(backend, &g.path)?;
            cleared += 1;
        }
    }
    Ok(cleared)
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

// ---- owners of private directories ---------------------------------------------

static LIVE_OWNERS: Mutex<BTreeMap<String, ()>> = Mutex::new(BTreeMap::new());

fn live_owners() -> std::sync::MutexGuard<'static, BTreeMap<String, ()>> {
    LIVE_OWNERS.lock().unwrap_or_else(|e| e.into_inner())
}

fn short_hash(s: &str) -> String {
    hex::encode(&blake3::hash(s.as_bytes()).as_bytes()[..4])
}

/// The owner of a private directory (a transaction's object staging, a
/// pull's spool): a name that says which process made it, so that others
/// remove it only when that process is provably gone ([`owner_gone`]),
/// by the lock's rules. Registered in this process while the value lives.
///
/// The tag is `<host>-<boot>-<pid>-<pid start>-<ms>-<random>`: short hashes
/// of the host name and of the boot identity (which includes the pid
/// namespace), the pid, its start time (0 if unknown), the creation time
/// and a random part.
#[derive(Debug)]
pub struct Owner {
    tag: String,
}

impl Owner {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Owner {
        Owner::with_context(&LockContext::default())
    }

    /// An owner tag for this process as `ctx` sees it (tests simulate other
    /// hosts with it).
    pub fn with_context(ctx: &LockContext) -> Owner {
        let me = ctx.me();
        let tag = format!(
            "{}-{}-{}-{}-{}-{}",
            short_hash(&me.host),
            short_hash(&me.boot),
            my_pid(),
            my_start().unwrap_or(0),
            now_millis().max(0),
            hex::encode(random_bytes::<4>())
        );
        live_owners().insert(tag.clone(), ());
        Owner { tag }
    }

    pub fn tag(&self) -> &str {
        &self.tag
    }
}

impl Drop for Owner {
    fn drop(&mut self) {
        live_owners().remove(&self.tag);
    }
}

/// Whether the owner named by `tag` ([`Owner`]) is provably gone, by the
/// lock's takeover rules:
/// * this process (same host, boot, namespace, pid and start time): gone
///   once its [`Owner`] was dropped;
/// * same host, boot and pid namespace: its pid is provably not running
///   (a zombie, `ESRCH`), or runs with another start time (a reused pid);
/// * same host, another boot identity: made before this machine booted.
///
/// Everything else is kept: another host (a `.veil` shared over NFS),
/// another pid namespace of this boot, a pid whose state cannot be told,
/// or a tag that does not parse.
pub fn owner_gone(tag: &str, ctx: &LockContext) -> bool {
    let parts: Vec<&str> = tag.split('-').collect();
    let [host, boot, pid, start, ms, _rand] = parts.as_slice() else { return false };
    let (Ok(pid), Ok(start), Ok(ms)) = (pid.parse::<u32>(), start.parse::<u64>(), ms.parse::<i64>()) else {
        return false;
    };
    let me = ctx.me();
    if *host != short_hash(&me.host) || me.host.is_empty() {
        return false;
    }
    if *boot != short_hash(&me.boot) {
        let booted = ctx.boot_ms.or_else(boot_time_ms);
        return booted.is_some_and(|b| ms < b);
    }
    if pid == my_pid() && (start == 0 || my_start().is_none_or(|s| s == start)) {
        return !live_owners().contains_key(tag);
    }
    match process_alive_with(&*ctx.probe, pid) {
        Some(false) => true,
        Some(true) => start != 0 && process_start_with(&*ctx.probe, pid).is_some_and(|s| s.id != start),
        None => false,
    }
}

// ---- the working-copy lock -------------------------------------------------------

/// One recorder per workspace (stream O, threat 4): an exclusive `flock` on
/// `.veil/local/wc/ws-<name>.lock`, held while a command records a
/// workspace's directory and while it checks it out, so that two processes
/// never snapshot or materialise one workspace at once (the BUG-361/362
/// and BUG-117 class); the compare-and-swap at commit catches the rest.
/// Device-local, released by the kernel when the process dies, and
/// re-entrant within a process (a command that records its own workspace
/// through another route does not wait for itself).
#[cfg(all(feature = "os", unix))]
#[derive(Debug)]
pub struct WcLock {
    key: std::path::PathBuf,
}

#[cfg(all(feature = "os", unix))]
type WcHeld = BTreeMap<std::path::PathBuf, (usize, std::fs::File)>;

#[cfg(all(feature = "os", unix))]
fn wc_held() -> std::sync::MutexGuard<'static, WcHeld> {
    static HELD: Mutex<WcHeld> = Mutex::new(BTreeMap::new());
    HELD.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(all(feature = "os", unix))]
impl WcLock {
    /// Lock workspace `ws` of the repository whose `.veil` directory is
    /// `veil_dir`, waiting for another process that holds it.
    pub fn acquire(veil_dir: &std::path::Path, ws: &str) -> Result<WcLock> {
        use std::os::unix::io::AsRawFd;
        crate::workspace::validate_workspace_name(ws)?;
        let dir = veil_dir.join("local").join("wc");
        // `ws-` keeps `.` and `..` from naming a directory.
        let key = dir.join(format!("ws-{ws}.lock"));
        {
            let mut held = wc_held();
            if let Some((n, _)) = held.get_mut(&key) {
                *n += 1;
                return Ok(WcLock { key });
            }
        }
        let io = |e: std::io::Error| VeilError::Io {
            path: key.display().to_string(),
            source: e,
        };
        std::fs::create_dir_all(&dir).map_err(io)?;
        let file = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(&key).map_err(io)?;
        loop {
            // SAFETY: a valid descriptor we own; `flock` only takes a lock.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
                break;
            }
            let e = std::io::Error::last_os_error();
            if e.kind() != std::io::ErrorKind::Interrupted {
                return Err(io(e));
            }
        }
        let mut held = wc_held();
        match held.get_mut(&key) {
            // Another thread of this process took it meanwhile (it waited
            // for nobody: the lock is per process).
            Some((n, _)) => *n += 1,
            None => {
                held.insert(key.clone(), (1, file));
            }
        }
        Ok(WcLock { key })
    }
}

#[cfg(all(feature = "os", unix))]
impl Drop for WcLock {
    fn drop(&mut self) {
        let mut held = wc_held();
        if let Some((n, _)) = held.get_mut(&self.key) {
            *n -= 1;
            if *n == 0 {
                // Closing the descriptor releases the lock.
                held.remove(&self.key);
            }
        }
    }
}

// ---- clocks -------------------------------------------------------------------

mod clock {
    use std::{sync::Mutex, time::Duration};

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
            crate::clock::monotonic()
        }
        /// Without the `os` feature there is nothing to wait for (no other
        /// thread can release the lock on WASM) and no way to sleep: a
        /// no-op (lock waits are then zero, see [`super::LockOptions`]).
        fn sleep(&self, d: Duration) {
            #[cfg(feature = "os")]
            std::thread::sleep(d);
            #[cfg(not(feature = "os"))]
            let _ = d;
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
            #[cfg(feature = "os")]
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

#[cfg(feature = "os")]
fn host_identity() -> &'static HostIdentity {
    static ID: OnceLock<HostIdentity> = OnceLock::new();
    ID.get_or_init(|| HostIdentity {
        host: host_name(),
        boot: boot_identity(),
    })
}

/// Without an operating system (WASM) there is no host name, boot or pid to
/// tell holders apart: every instance of the engine is its own "host", with
/// a random name. Its locks are therefore never taken over by another
/// instance sharing the same storage (a lock of another host is never
/// robbed, see the module documentation), only by itself, through the
/// same-process rules (a leaked token, a lock left for recovery).
#[cfg(not(feature = "os"))]
fn host_identity() -> &'static HostIdentity {
    static ID: OnceLock<HostIdentity> = OnceLock::new();
    ID.get_or_init(|| {
        let name = format!("instance-{}", hex::encode(random_bytes::<8>()));
        HostIdentity {
            host: name.clone(),
            boot: name,
        }
    })
}

/// This process's pid; 0 without the `os` feature (a WASM instance has
/// none, `std::process::id()` panics there; see [`host_identity`]).
fn my_pid() -> u32 {
    #[cfg(feature = "os")]
    {
        std::process::id()
    }
    #[cfg(not(feature = "os"))]
    {
        0
    }
}

#[cfg(feature = "os")]
fn read_trimmed(path: &str) -> Option<String> {
    let s = std::fs::read_to_string(path).ok()?;
    let s = s.trim();
    (!s.is_empty()).then(|| s.to_string())
}

#[cfg(feature = "os")]
fn command_output(cmd: &str, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new(cmd).args(args).output().ok()?;
    let s = String::from_utf8(out.stdout).ok()?;
    let s = s.trim();
    (out.status.success() && !s.is_empty()).then(|| s.to_string())
}

#[cfg(feature = "os")]
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

#[cfg(all(feature = "os", unix))]
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

#[cfg(all(feature = "os", not(unix)))]
fn gethostname() -> Option<String> {
    None
}

#[cfg(feature = "os")]
/// Identifies one boot of one machine *and* the pid namespace, so a pid is
/// only compared against processes it could actually refer to.
pub fn boot_identity() -> String {
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
    #[cfg(all(feature = "os", target_os = "macos"))]
    {
        let raw = sysctl_bytes("kern.boottime")?;
        if raw.len() < std::mem::size_of::<libc::timeval>() {
            return None;
        }
        // SAFETY: `kern.boottime` is a `struct timeval`; the length was checked.
        let tv: libc::timeval = unsafe { std::ptr::read_unaligned(raw.as_ptr().cast()) };
        Some(i64::from(tv.tv_sec) * 1000 + i64::from(tv.tv_usec) / 1000)
    }
    #[cfg(all(feature = "os", not(target_os = "macos")))]
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
    #[cfg(not(feature = "os"))]
    {
        None
    }
}

/// Raw value of a `sysctl` by name.
#[cfg(all(feature = "os", target_os = "macos"))]
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

// ---- process liveness ---------------------------------------------------------

/// What this machine's process table shows about one pid (see
/// [`ProcessProbe::entry`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProcEntry {
    /// No process table that describes this process's own pid namespace:
    /// not Linux or macOS, no `/proc`, or a `/proc` mounted for another
    /// pid namespace (`unshare -p` without `--mount-proc`), whose
    /// `/proc/<pid>` names some other process.
    Unavailable,
    /// The table has no entry for the pid: the process is gone, *or* it is
    /// hidden from this user (`/proc` mounted with `hidepid=2`, systemd's
    /// `ProtectProc=invisible`). Not proof of death on its own.
    Absent,
    /// An entry. `zombie`: the process has exited and only waits to be
    /// reaped by its parent (`None`: cannot tell, e.g. `hidepid=1`);
    /// `start`: when it started, if readable.
    Present {
        zombie: Option<bool>,
        start: Option<ProcessStart>,
    },
}

/// The answer to `kill(pid, 0)`, which asks the kernel directly, in this
/// process's own pid namespace, whatever `/proc` shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signal {
    /// The pid exists (possibly as a zombie).
    Delivered,
    /// `ESRCH`: no process with this pid.
    NoProcess,
    /// `EPERM`: a process with this pid exists but belongs to another user.
    NotPermitted,
    /// Not asked (no `kill` on this platform, an invalid pid) or another
    /// error.
    Unknown,
}

/// How the lock asks the operating system about other processes:
/// [`SystemProbe`] in production; tests substitute what restricted setups
/// (`hidepid`, foreign pid namespaces, zombies) show, so that the decision
/// in [`process_alive_with`] is tested as it runs.
pub trait ProcessProbe: Send + Sync + std::fmt::Debug {
    /// The process table's entry for `pid`: `/proc/<pid>` on Linux,
    /// `proc_pidinfo` on macOS.
    fn entry(&self, pid: u32) -> ProcEntry;
    /// `kill(pid, 0)`.
    fn signal(&self, pid: u32) -> Signal;
}

/// The real operating system.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemProbe;

impl ProcessProbe for SystemProbe {
    fn entry(&self, pid: u32) -> ProcEntry {
        system_entry(pid)
    }
    fn signal(&self, pid: u32) -> Signal {
        system_signal(pid)
    }
}

/// Whether `pid` is a running process on this machine; `None` if that
/// cannot be told. A zombie (killed or exited, not yet reaped) is not
/// running (BUG-097): it can never renew its lease or touch the
/// repository again.
///
/// Only proof counts as "not running": an entry that is a zombie, or
/// `kill(pid, 0)` failing with `ESRCH`. A missing `/proc/<pid>` alone is
/// not, since `/proc` may hide other users' processes or belong to another
/// pid namespace; `kill` then decides (`EPERM` means another user's live
/// process), so the lock falls back to its lease instead of being taken
/// from a live holder.
pub fn process_alive_with(probe: &dyn ProcessProbe, pid: u32) -> Option<bool> {
    match probe.entry(pid) {
        ProcEntry::Present { zombie: Some(true), .. } => Some(false),
        ProcEntry::Present { .. } => Some(true),
        ProcEntry::Absent | ProcEntry::Unavailable => match probe.signal(pid) {
            Signal::NoProcess => Some(false),
            Signal::Delivered | Signal::NotPermitted => Some(true),
            Signal::Unknown => None,
        },
    }
}

/// [`process_alive_with`] the real operating system.
pub fn process_alive(pid: u32) -> Option<bool> {
    process_alive_with(&SystemProbe, pid)
}

/// When a process started: `id` identifies the process together with its
/// pid (exact, never compared across machines or boots), `wall_ms` is an
/// approximate wall-clock time, if known.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessStart {
    pub id: u64,
    pub wall_ms: Option<i64>,
}

/// When `pid` started, if it runs and the platform can tell (Linux: clock
/// ticks since boot from `/proc/<pid>/stat`; macOS: the start time
/// `proc_pidinfo` reports). `None` too when `/proc` belongs to another
/// pid namespace, where it would describe another process.
pub fn process_start(pid: u32) -> Option<ProcessStart> {
    process_start_with(&SystemProbe, pid)
}

/// [`process_start`] through `probe`.
pub fn process_start_with(probe: &dyn ProcessProbe, pid: u32) -> Option<ProcessStart> {
    match probe.entry(pid) {
        ProcEntry::Present { start, .. } => start,
        ProcEntry::Absent | ProcEntry::Unavailable => None,
    }
}

/// Whether `/proc` describes this process's own pid namespace: then
/// `/proc/self` names our own pid. In a `/proc` of an ancestor namespace
/// it names our pid there, in one of another namespace nothing.
#[cfg(all(feature = "os", target_os = "linux"))]
fn proc_is_ours() -> bool {
    std::fs::read_link("/proc/self")
        .ok()
        .and_then(|p| p.to_str()?.parse::<u32>().ok())
        == Some(std::process::id())
}

/// The state letter and `starttime` of a `/proc/<pid>/stat` line.
#[cfg(all(feature = "os", target_os = "linux"))]
fn parse_stat(stat: &str) -> (Option<char>, Option<u64>) {
    // Field 2, `comm`, is parenthesised and may contain spaces and
    // parentheses; field 3 is the state and field 22, `starttime`, the
    // 20th after it.
    let Some(close) = stat.rfind(')') else { return (None, None) };
    let mut fields = stat[close + 1..].split_whitespace();
    let state = fields.next().and_then(|s| s.chars().next());
    let ticks = fields.nth(18).and_then(|t| t.parse().ok());
    (state, ticks)
}

#[cfg(all(feature = "os", target_os = "linux"))]
fn exited(state: Option<char>) -> bool {
    matches!(state, Some('Z' | 'X'))
}

#[cfg(all(feature = "os", target_os = "linux"))]
fn system_entry(pid: u32) -> ProcEntry {
    if !proc_is_ours() {
        return ProcEntry::Unavailable;
    }
    let dir = format!("/proc/{pid}");
    let Ok(stat) = std::fs::read_to_string(format!("{dir}/stat")) else {
        // Visible but unreadable (`hidepid=1`), or gone (or hidden).
        return if std::path::Path::new(&dir).exists() {
            ProcEntry::Present {
                zombie: None,
                start: None,
            }
        } else {
            ProcEntry::Absent
        };
    };
    let (state, ticks) = parse_stat(&stat);
    // The main thread of a process whose other threads still run shows
    // `Z` too (it called `pthread_exit`): only a process none of whose
    // threads runs is a zombie.
    let zombie = match state {
        None => None,
        Some(_) if !exited(state) => Some(false),
        Some(_) => std::fs::read_dir(format!("{dir}/task")).ok().map(|tasks| {
            tasks.flatten().all(|t| {
                // A task that vanished meanwhile has exited too.
                std::fs::read_to_string(t.path().join("stat")).map_or(true, |s| exited(parse_stat(&s).0))
            })
        }),
    };
    let start = ticks.map(|ticks| {
        // SAFETY: `sysconf` only reads a configuration value.
        let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        let hz = u64::try_from(hz).ok().filter(|&h| h > 0).unwrap_or(100);
        let wall_ms = boot_time_ms().and_then(|b| b.checked_add(i64::try_from(ticks.checked_mul(1000)? / hz).ok()?));
        ProcessStart { id: ticks, wall_ms }
    });
    ProcEntry::Present { zombie, start }
}

#[cfg(all(feature = "os", target_os = "macos"))]
fn system_entry(pid: u32) -> ProcEntry {
    /// `SZOMB` in XNU's `<sys/proc.h>`.
    const SZOMB: u32 = 5;
    let Some(raw) = libc::c_int::try_from(pid).ok().filter(|&p| p > 0) else {
        return ProcEntry::Unavailable;
    };
    // SAFETY: `proc_bsdinfo` is plain data; all-zero is a valid value.
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let Ok(size) = libc::c_int::try_from(std::mem::size_of::<libc::proc_bsdinfo>()) else {
        return ProcEntry::Unavailable;
    };
    // SAFETY: the buffer is a writable `proc_bsdinfo` of exactly `size`
    // bytes. XNU answers this flavour for zombies too.
    let n = unsafe {
        libc::proc_pidinfo(
            raw,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut libc::proc_bsdinfo).cast(),
            size,
        )
    };
    if n != size {
        // Gone, or not ours to inspect: `kill` decides.
        return ProcEntry::Unavailable;
    }
    let start = info
        .pbi_start_tvsec
        .checked_mul(1_000_000)
        .and_then(|s| s.checked_add(info.pbi_start_tvusec))
        .map(|us| ProcessStart {
            id: us,
            wall_ms: i64::try_from(us / 1000).ok(),
        });
    ProcEntry::Present {
        zombie: Some(info.pbi_status == SZOMB),
        start,
    }
}

#[cfg(not(all(feature = "os", any(target_os = "linux", target_os = "macos"))))]
fn system_entry(_pid: u32) -> ProcEntry {
    ProcEntry::Unavailable
}

#[cfg(all(feature = "os", unix))]
fn system_signal(pid: u32) -> Signal {
    // pid 0 and negative values address process groups, not a process.
    let Ok(raw) = libc::pid_t::try_from(pid) else { return Signal::Unknown };
    if raw <= 0 {
        return Signal::Unknown;
    }
    // SAFETY: signal 0 performs only the existence and permission checks.
    if unsafe { libc::kill(raw, 0) } == 0 {
        return Signal::Delivered;
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::ESRCH) => Signal::NoProcess,
        Some(libc::EPERM) => Signal::NotPermitted,
        _ => Signal::Unknown,
    }
}

#[cfg(not(all(feature = "os", unix)))]
fn system_signal(_pid: u32) -> Signal {
    Signal::Unknown
}

/// This process's [`ProcessStart::id`], recorded in its lock files.
fn my_start() -> Option<u64> {
    static START: OnceLock<Option<u64>> = OnceLock::new();
    *START.get_or_init(|| process_start(my_pid()).map(|s| s.id))
}

/// Whether the live process running under the holder's pid is someone
/// else: it started at another time than the holder (locks that record
/// it), or, for locks that do not (older versions), well after the lock was
/// acquired and the lease has expired. `Some(reason)` if so.
fn pid_reused(info: &LockInfo, extra: &Extras, now: i64, probe: &dyn ProcessProbe) -> Option<String> {
    let running = process_start_with(probe, info.pid)?;
    let reused = match extra.start {
        Some(start) => start != running.id,
        None => {
            info.lease_expired(now)
                && running
                    .wall_ms
                    .is_some_and(|w| w > info.acquired.saturating_add(REUSED_PID_SLACK_MS))
        }
    };
    reused.then(|| {
        format!(
            "holder pid {} now belongs to another process, started after the lock was taken",
            info.pid
        )
    })
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

    /// BUG-082: a legacy or damaged lock file used to read
    /// `lease renewed -1793763700901071.5s ago`.
    #[test]
    fn lock_descriptions_never_show_nonsense_ages() {
        let now = 1_793_000_000_000;
        let at = |raw: &[u8]| LockInfo::parse(raw).unwrap().describe_at(now);
        // Legacy file, millis: a readable age, and marked legacy.
        let d = at(format!("4242 {}", now - 125_000).as_bytes());
        assert!(d.contains("lease renewed 2m 05s ago; legacy lock file"), "{d}");
        // Legacy file written with nanoseconds, or garbage numbers.
        for raw in [b"4242 1793763700901071512".as_slice(), b"4242 -5", b"4242 12"] {
            let d = at(raw);
            assert!(d.contains("lease renewal time unreadable"), "{d}");
            assert!(!d.contains("ago"), "{d}");
        }
        // Current format: a few hours, and a clock slightly ahead.
        let mut i = info(7, "h", "b", 0);
        i.renewed = now - 3 * 3_600_000 - 60_000;
        assert!(i.describe_at(now).ends_with("(lease renewed 3h 01m ago)"), "{}", i.describe_at(now));
        i.renewed = now + 4_000;
        assert!(i.describe_at(now).contains("lease renewed 4.0s in the future"), "{}", i.describe_at(now));
        i.renewed = now - 1_500;
        assert!(i.describe_at(now).contains("lease renewed 1.5s ago"), "{}", i.describe_at(now));
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
