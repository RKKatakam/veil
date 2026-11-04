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
//! Detecting a dead pid, the host name and the boot id requires asking the
//! host OS (`/proc` on Linux, `ps` elsewhere). That is process introspection,
//! not repository storage, so it lives here rather than behind the VFS.

use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex, OnceLock,
    },
    thread::{JoinHandle, ThreadId},
    time::{Duration, Instant},
};

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

impl LockInfo {
    fn new_local(lease: Duration) -> LockInfo {
        let h = host_identity();
        let now = now_millis();
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
        format!(
            "pid {} on {} (lease renewed {:.1}s ago)",
            self.pid,
            if self.host.is_empty() {
                "an unknown host"
            } else {
                &self.host
            },
            (now_millis() - self.renewed) as f64 / 1000.0
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

/// Decide whether the lock described by `info` may be stolen at time `now`.
pub fn assess(info: &LockInfo, now: i64) -> Verdict {
    let me = host_identity();
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
}

#[derive(Debug)]
struct Heartbeat {
    stop: mpsc::Sender<()>,
    thread: JoinHandle<()>,
}

impl RepoLock {
    pub fn acquire(backend: Arc<dyn StorageBackend>) -> Result<RepoLock> {
        Self::acquire_with(backend, &LockOptions::default())
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
                });
            }
        }
        Self::acquire(backend)
    }

    pub fn acquire_with(backend: Arc<dyn StorageBackend>, opts: &LockOptions) -> Result<RepoLock> {
        let path = VPath::new(LOCK_PATH)?;
        let start = Instant::now();
        let mut backoff = Duration::from_millis(1);
        // Unparseable content (a crash of a non-atomic writer) is only
        // reclaimed once it has stayed unchanged for a whole lease.
        let mut garbage: Option<(Vec<u8>, Instant)> = None;
        let mut reason = String::from("another process holds the lock");
        loop {
            let info = LockInfo::new_local(opts.lease);
            // Register before creating the file so no thread of this process
            // ever sees our fresh lock with an unregistered token.
            let token = Registered::new(info.token.clone());
            if backend.create_new(&path, &info.encode())? {
                return Ok(Self::held(backend, path, info, token, opts));
            }
            let Some(raw) = backend.read_opt(&path)? else {
                continue; // released between our attempts
            };
            // `Some(since)`: the stale lock may be replaced by ours. Its
            // holder may have died half-way through a batch of unsynced
            // writes made after `since` (`None`: unknown).
            let mut takeover: Option<Option<i64>> = None;
            match LockInfo::parse(&raw) {
                Some(holder) => match assess(&holder, now_millis()) {
                    Verdict::Wait => {}
                    Verdict::Stuck(r) => reason = r,
                    Verdict::Steal(_) => takeover = Some(Some(holder.acquired)),
                },
                None => match &garbage {
                    Some((seen, since)) if *seen == raw => {
                        if since.elapsed() >= opts.lease {
                            takeover = Some(None);
                        }
                        reason = format!("{LOCK_PATH} holds unreadable content");
                    }
                    _ => garbage = Some((raw.clone(), Instant::now())),
                },
            }
            if let Some(since) = takeover {
                match take_over(&*backend, &path, &raw, &info.encode())? {
                    TakeOver::Ours => {
                        let lock = Self::held(backend, path, info, token, opts);
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
            if start.elapsed() >= opts.wait {
                return Err(VeilError::Locked(reason));
            }
            std::thread::sleep(backoff);
            backoff = (backoff * 2).min(Duration::from_millis(50));
        }
    }

    fn held(
        backend: Arc<dyn StorageBackend>,
        path: VPath,
        info: LockInfo,
        token: Registered,
        opts: &LockOptions,
    ) -> RepoLock {
        let lost = Arc::new(AtomicBool::new(false));
        let heartbeat = Heartbeat::spawn(backend.clone(), path.clone(), info, opts.renew_every, lost.clone());
        RepoLock {
            backend,
            path,
            token: token.keep(),
            lost,
            heartbeat,
            nested: false,
        }
    }

    /// The current holder of the repository lock, if any.
    pub fn holder(backend: &dyn StorageBackend) -> Result<Option<LockInfo>> {
        Ok(backend
            .read_opt(&VPath::new(LOCK_PATH)?)?
            .and_then(|raw| LockInfo::parse(&raw)))
    }

    /// Fail unless the lock file still carries our token. Call right before
    /// publishing the result of a transaction.
    pub fn ensure_held(&self) -> Result<()> {
        if !self.lost.load(Ordering::SeqCst) {
            if let Some(raw) = self.backend.read_opt(&self.path)? {
                if LockInfo::parse(&raw).is_some_and(|i| i.token == self.token) {
                    return Ok(());
                }
            }
            self.lost.store(true, Ordering::SeqCst);
        }
        Err(VeilError::Locked(
            "this process's repository lock was taken over; the operation was not recorded".into(),
        ))
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
    ) -> Option<Heartbeat> {
        let (stop, rx) = mpsc::channel::<()>();
        let thread = std::thread::Builder::new()
            .name("veil-lock-heartbeat".into())
            .spawn(move || {
                // Disconnection (the lock was dropped) ends the loop.
                while let Err(mpsc::RecvTimeoutError::Timeout) = rx.recv_timeout(every) {
                    match backend.read_opt(&path) {
                        Ok(Some(raw)) if LockInfo::parse(&raw).is_some_and(|i| i.token == info.token) => {
                            info.renewed = now_millis();
                            // A failed renewal is retried on the next tick;
                            // the lease is only a hint to other processes.
                            let _ = backend.write(&path, &info.encode());
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

/// Replace `path` by `ours` if it still holds exactly `observed`, serialised
/// against other contenders through [`STEAL_PATH`]. The stale lock is
/// replaced in one atomic write rather than removed, so no third process can
/// slip in between and skip the crash recovery the new holder performs.
fn take_over(backend: &dyn StorageBackend, path: &VPath, observed: &[u8], ours: &[u8]) -> Result<TakeOver> {
    let guard_path = VPath::new(STEAL_PATH)?;
    let guard = LockInfo::new_local(Duration::from_secs(5));
    let token = Registered::new(guard.token.clone());
    if !backend.create_new(&guard_path, &guard.encode())? {
        // Another contender is stealing. If it crashed mid-steal, clear its
        // guard (only when it is provably gone, like any other lock).
        if let Some(raw) = backend.read_opt(&guard_path)? {
            if let Some(other) = LockInfo::parse(&raw) {
                if let Verdict::Steal(_) = assess(&other, now_millis()) {
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

// ---- host introspection -----------------------------------------------------

#[derive(Debug)]
struct HostIdentity {
    host: String,
    boot: String,
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
    read_trimmed("/proc/sys/kernel/hostname")
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

/// Identifies one boot of one machine *and* the pid namespace, so a pid is
/// only compared against processes it could actually refer to.
fn boot_identity() -> String {
    if !cfg!(target_os = "linux") {
        return String::new();
    }
    let boot = read_trimmed("/proc/sys/kernel/random/boot_id");
    let ns = std::fs::read_link("/proc/self/ns/pid")
        .ok()
        .map(|p| p.to_string_lossy().into_owned());
    match (boot, ns) {
        (Some(b), Some(n)) => format!("{b}/{n}"),
        _ => String::new(),
    }
}

/// When this machine booted (ms since the epoch), if known.
fn boot_time_ms() -> Option<i64> {
    let stat = std::fs::read_to_string("/proc/stat").ok()?;
    let secs: i64 = stat
        .lines()
        .find_map(|l| l.strip_prefix("btime "))?
        .trim()
        .parse()
        .ok()?;
    Some(secs * 1000)
}

/// Whether `pid` is a running process on this machine; `None` if unknown.
fn process_alive(pid: u32) -> Option<bool> {
    if cfg!(target_os = "linux") && std::path::Path::new("/proc/self").exists() {
        return Some(std::path::Path::new(&format!("/proc/{pid}")).exists());
    }
    if cfg!(unix) {
        // `ps -p` exits 0 iff the process exists, whoever owns it.
        let status = std::process::Command::new("ps")
            .args(["-p", &pid.to_string()])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .ok()?;
        return Some(status.success());
    }
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
