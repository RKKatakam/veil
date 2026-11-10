//! The Veil daemon (milestone S6, `docs/HUB.md` §13.29; design:
//! `docs/design/server/phase-2-thin-clients.md` §4.6): one shared object
//! cache for every thin clone and workspace of a Veil home on a machine.
//!
//! * **One per Veil home**: by default one per OS user, its socket in
//!   `$XDG_RUNTIME_DIR/veil/` and its store in `~/.cache/veil/daemon/`
//!   (both 0700); with `VEIL_HOME` set, both in `$VEIL_HOME/daemon/`. Only
//!   processes of its own user may connect (the directory's mode and the
//!   peer's uid, checked on every connection).
//! * **It runs by default** (product decision 5): a thin clone's `vl`
//!   starts it when it first needs an object. `vl daemon stop` stops it and
//!   keeps it off (vl then reads from the server directly) until `vl daemon
//!   start`.
//! * **No key, no session**: it serves an object only as the server would
//!   serve it to the requester's device now ([`serve`]), and holds only
//!   objects. Its follower, `vl daemon follow`, is a `vl` of the Veil home
//!   like any other (it signs its own requests) and keeps the top trees of
//!   followed projects warm ([`follow`]).
//! * **A `vl` without it works as before**: the client asks the daemon
//!   first and the server for whatever did not arrive ([`fetch`]); only the
//!   server's own answer ever reads as hidden.

#[cfg(unix)]
mod follow;
pub mod proto;
#[cfg(unix)]
mod serve;
#[cfg(unix)]
pub mod store;
#[cfg(unix)]
pub mod watch;

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use veil_core::ObjectId;

use crate::render::{dim, green};

/// Where a Veil home's daemon keeps its socket, its store and its state.
#[derive(Clone, Debug)]
pub struct Paths {
    /// Its settings (`config.json`), the off switch (`off`), the followed
    /// projects, its lock and its log.
    pub state: PathBuf,
    /// The directory of its socket.
    pub run: PathBuf,
    pub socket: PathBuf,
    pub store: PathBuf,
    pub off: PathBuf,
    /// `VEIL_HOME`, when the daemon lives in it: never created by the
    /// daemon (one whose home was removed must not bring it back).
    pub home: Option<PathBuf>,
}

impl Paths {
    /// Make the daemon's directories (0700). Inside a Veil home, only below
    /// one that exists: a daemon or `vl` racing the removal of its Veil
    /// home never makes it again.
    pub fn prepare(&self) -> Result<()> {
        match &self.home {
            // `state` and `run` are one folder, in the home.
            Some(h) => private_subdir(&self.state).map_err(|e| anyhow::anyhow!("the Veil home {} is not there ({e:#})", h.display())),
            None => {
                private_dir(&self.state)?;
                private_dir(&self.run)
            }
        }
    }
}

pub fn paths() -> Paths {
    if let Some(home) = std::env::var_os("VEIL_HOME").filter(|h| !h.is_empty()) {
        // Absolute, so that the daemon (started in its own folder) and
        // every `vl` agree on it.
        let home = absolute(PathBuf::from(home));
        let d = home.join("daemon");
        return Paths { socket: d.join("sock"), store: d.join("store"), off: d.join("off"), run: d.clone(), state: d, home: Some(home) };
    }
    let home = user_home().unwrap_or_else(|| PathBuf::from("/nonexistent"));
    let cache = xdg_var("XDG_CACHE_HOME").unwrap_or_else(|| home.join(".cache")).join("veil").join("daemon");
    let run = match runtime_dir() {
        Some(r) => r.join("veil"),
        None => cache.join("run"),
    };
    Paths { socket: run.join("daemon.sock"), store: cache.join("store"), off: cache.join("off"), run, state: cache, home: None }
}

fn absolute(p: PathBuf) -> PathBuf {
    match p.is_absolute() {
        true => p,
        false => std::env::current_dir().map(|d| d.join(&p)).unwrap_or(p),
    }
}

/// A directory an XDG variable names, as the XDG rules take it: set and
/// absolute; empty or relative counts as unset (BUG-1515: an empty one put
/// the daemon in whatever directory `vl` ran in).
fn xdg_var(name: &str) -> Option<PathBuf> {
    std::env::var_os(name).map(PathBuf::from).filter(|p| p.is_absolute())
}

/// This user's home: `HOME` if absolute, else the account's.
fn user_home() -> Option<PathBuf> {
    if let Some(h) = std::env::var_os("HOME").map(PathBuf::from).filter(|p| p.is_absolute()) {
        return Some(h);
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let mut buf = vec![0 as libc::c_char; 16 << 10];
        // SAFETY: `pw` and `buf` are valid for writes of the sizes given;
        // `res` is set to null or to `pw`.
        let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
        let mut res: *mut libc::passwd = std::ptr::null_mut();
        let r = unsafe { libc::getpwuid_r(my_uid(), &mut pw, buf.as_mut_ptr(), buf.len(), &mut res) };
        if r == 0 && !res.is_null() && !pw.pw_dir.is_null() {
            // SAFETY: `pw_dir` points into `buf`, NUL-terminated.
            let dir = unsafe { std::ffi::CStr::from_ptr(pw.pw_dir) };
            let p = PathBuf::from(std::ffi::OsStr::from_bytes(dir.to_bytes()));
            return p.is_absolute().then_some(p);
        }
    }
    None
}

/// `XDG_RUNTIME_DIR`, only as the XDG rules allow it: absolute, a folder
/// owned by this user, mode 0700 (BUG-1515: a shared one, `/tmp`, let
/// another user listen where `vl` connects). Else none: the daemon's
/// socket then goes in its own folder (`~/.cache/veil/daemon/run`).
fn runtime_dir() -> Option<PathBuf> {
    let r = xdg_var("XDG_RUNTIME_DIR")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::symlink_metadata(&r).ok()?;
        (m.is_dir() && m.uid() == my_uid() && m.mode() & 0o777 == 0o700).then_some(r)
    }
    #[cfg(not(unix))]
    Some(r)
}

/// Make `dir` (and its parents) and check it is this user's and no one
/// else's: owned by this user, mode 0700 (set if it was wider). Only for
/// the default layout's folders (`~/.cache/veil/daemon`, the runtime
/// folder); inside a Veil home, [`private_subdir`].
pub fn private_dir(dir: &Path) -> Result<()> {
    make_private(dir, true)
}

/// [`private_dir`], making `dir` alone: its parent must exist, so a folder
/// removed meanwhile (a Veil home being removed) is never made again
/// (BUG-1513).
pub fn private_subdir(dir: &Path) -> Result<()> {
    make_private(dir, false)
}

fn make_private(dir: &Path, parents: bool) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
        match std::fs::DirBuilder::new().recursive(parents).mode(0o700).create(dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e).with_context(|| format!("creating {}", dir.display())),
        }
        let m = std::fs::symlink_metadata(dir)?;
        if !m.is_dir() || m.uid() != my_uid() {
            bail!("{} is not a directory of this user's: the daemon will not use it", dir.display());
        }
        if m.mode() & 0o077 != 0 {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    #[cfg(not(unix))]
    match parents {
        true => std::fs::create_dir_all(dir)?,
        false => match std::fs::create_dir(dir) {
            Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => return Err(e.into()),
            _ => {}
        },
    }
    Ok(())
}

#[cfg(unix)]
pub fn my_uid() -> u32 {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() }
}

/// The uid of the process at the other end of `s`.
#[cfg(unix)]
pub fn peer_uid(s: &std::os::unix::net::UnixStream) -> Option<u32> {
    use std::os::fd::AsRawFd;
    #[cfg(target_os = "linux")]
    {
        let mut c = libc::ucred { pid: 0, uid: 0, gid: 0 };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: `c` and `len` are valid for writes of the sizes given.
        let r = unsafe { libc::getsockopt(s.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED, &mut c as *mut _ as *mut libc::c_void, &mut len) };
        (r == 0).then_some(c.uid)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let (mut uid, mut gid) = (0, 0);
        // SAFETY: `uid` and `gid` are valid for writes.
        let r = unsafe { libc::getpeereid(s.as_raw_fd(), &mut uid, &mut gid) };
        (r == 0).then_some(uid)
    }
}

/// The store's bound: `vl daemon start --cache-size`, else 20 GiB or a
/// tenth of the disk, whichever is less.
pub fn configured_limit(p: &Paths) -> Option<u64> {
    let set = std::fs::read(p.state.join("config.json"))
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .and_then(|v| v["cache_size"].as_u64());
    set.or_else(|| default_limit(&p.store))
}

fn default_limit(dir: &Path) -> Option<u64> {
    let cap = 20u64 << 30;
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let c = std::ffi::CString::new(dir.as_os_str().as_bytes()).ok()?;
        // SAFETY: `c` is a valid C string and `s` valid for writes.
        let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statvfs(c.as_ptr(), &mut s) } == 0 {
            return Some(cap.min((s.f_blocks as u64).saturating_mul(s.f_frsize as u64) / 10));
        }
    }
    Some(cap)
}

/// Start `vl ARGS` in the background, detached from the terminal and this
/// process's pipes (its errors go to the daemon's log).
#[cfg(unix)]
pub(crate) fn spawn_self(args: &[&str], p: &Paths) -> Result<std::process::Child> {
    use std::os::unix::process::CommandExt;
    let log = std::fs::OpenOptions::new().create(true).append(true).open(p.state.join("daemon.log"))?;
    let mut c = std::process::Command::new(std::env::current_exe()?);
    c.args(args).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(log).current_dir(&p.state);
    // The Veil home as this process resolved it (it runs elsewhere).
    if let Some(h) = &p.home {
        c.env("VEIL_HOME", h);
    }
    // SAFETY: setsid is async-signal-safe.
    unsafe {
        c.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    Ok(c.spawn()?)
}

// ---- the client side -----------------------------------------------------------------

#[cfg(unix)]
pub use client::*;

#[cfg(unix)]
mod client {
    use std::{
        os::unix::net::UnixStream,
        sync::atomic::{AtomicBool, Ordering},
        time::{Duration, Instant},
    };

    use anyhow::{bail, Result};
    use veil_core::{hub::grant::BatchRequest, ObjectId};

    use super::{
        paths,
        proto::{self, Head, Request, MAX_OBJECT},
        spawn_self, Paths,
    };

    /// Longest socket path a `sockaddr_un` holds.
    const MAX_SOCKET_PATH: usize = 100;

    /// The running daemon of this Veil home, if any.
    pub fn connect() -> Option<UnixStream> {
        connect_at(&paths())
    }

    /// A connection to the daemon at `p`'s socket, only if this user's
    /// process listens there (BUG-1515: whoever listens receives the
    /// device's signed requests). Every caller goes through it: requests,
    /// pins, status, stops.
    fn connect_at(p: &Paths) -> Option<UnixStream> {
        let s = UnixStream::connect(&p.socket).ok()?;
        if super::peer_uid(&s) != Some(super::my_uid()) {
            return None;
        }
        s.set_write_timeout(Some(Duration::from_secs(2))).ok()?;
        Some(s)
    }

    /// Stop the running daemon ([`proto::S`]): `older_than` `None` stops
    /// any (`vl daemon stop`); `Some(v)` only one whose version is older
    /// than `v` (BUG-1517: the stop meant for an older daemon must not stop
    /// the newer one that may have replaced it since).
    pub fn stop_running(older_than: Option<u8>) {
        if let Some(mut s) = connect() {
            let _ = proto::write_msg(&mut s, proto::S, older_than.as_slice());
        }
    }

    /// The daemon failed this process once (no acknowledgement within
    /// [`ACK_WAIT`], an answer that stalled or made no sense, another
    /// protocol version): the process reads from the server directly from
    /// then on (BUG-1514: a stalled daemon cost every request a full wait).
    static UNUSABLE: AtomicBool = AtomicBool::new(false);
    /// The longest a request waits for any message of the daemon's: the
    /// acknowledgement, an object, the end, or the progress message the
    /// daemon sends every 0.1 s while it works (its store, the server, its
    /// budgets). Any gap longer than this, whatever the daemon is doing
    /// (stopped, wedged, its store on a hung disk), costs the process this
    /// once (BUG-1518).
    const ACK_WAIT: Duration = Duration::from_millis(500);
    /// The longest a request waits between two whole objects (or from the
    /// acknowledgement to the first object or the end), whatever progress
    /// messages or partial bytes arrive meanwhile: the daemon's own 30 s
    /// read of the server and a margin (BUG-1582).
    const BETWEEN_OBJECTS: Duration = Duration::from_secs(35);

    fn give_up() {
        UNUSABLE.store(true, Ordering::SeqCst);
    }

    /// The daemon, started if it is not running and not turned off
    /// (`vl daemon stop`). `None`: read from the server directly.
    pub fn connect_or_start() -> Option<UnixStream> {
        static TRIED: AtomicBool = AtomicBool::new(false);
        let p = paths();
        if p.off.exists() || UNUSABLE.load(Ordering::SeqCst) {
            return None;
        }
        if let Some(s) = connect_at(&p) {
            return Some(s);
        }
        // One attempt per process: a daemon that does not come up is not
        // waited for again.
        if TRIED.swap(true, Ordering::SeqCst) {
            return None;
        }
        start(&p).ok()?;
        connect_at(&p)
    }

    /// Start the daemon of `p` and wait (at most 2 s) for its socket.
    pub fn start(p: &Paths) -> Result<()> {
        if p.socket.as_os_str().len() > MAX_SOCKET_PATH {
            bail!("the daemon's socket path {} is too long for a socket", p.socket.display());
        }
        p.prepare()?;
        let mut child = spawn_self(&["daemon", "run"], p)?;
        let t = Instant::now();
        while t.elapsed() < Duration::from_secs(2) {
            if connect_at(p).is_some() {
                return Ok(());
            }
            if let Ok(Some(_)) = child.try_wait() {
                // Another daemon took the lock first; it may still be
                // binding its socket.
                if connect_at(p).is_some() {
                    return Ok(());
                }
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        bail!("the daemon did not start within 2 s (see {})", p.state.join("daemon.log").display())
    }

    /// Send `req`; the objects that arrived (each checked against its id
    /// and asked for), and the answer's end if it arrived (`None`: the
    /// answer is unfinished).
    ///
    /// A daemon that leaves a gap of more than [`ACK_WAIT`] before any
    /// message (its acknowledgement included), takes longer than
    /// [`BETWEEN_OBJECTS`] between whole objects (or the end), sends
    /// anything but what was asked, or speaks another version, is not asked
    /// again by this process; one older than this `vl` is stopped, so the
    /// next `vl` starts its own.
    pub fn request(mut s: UnixStream, req: &Request, wanted: &dyn Fn(&ObjectId) -> bool) -> (Vec<(ObjectId, Vec<u8>)>, Option<Head>) {
        let mut got = Vec::new();
        let Ok(json) = serde_json::to_vec(req) else { return (got, None) };
        let mut body = vec![proto::PROTOCOL];
        body.extend_from_slice(&json);
        if proto::write_msg(&mut s, proto::Q, &body).is_err() || s.set_read_timeout(Some(ACK_WAIT)).is_err() {
            give_up();
            return (got, None);
        }
        let mut r = std::io::BufReader::with_capacity(64 << 10, s);
        match proto::read_head(&mut r, 1).and_then(|(kind, len)| Ok((kind, proto::read_payload(&mut r, len)?))) {
            Ok((proto::A, v)) if v == [proto::PROTOCOL] => {}
            Ok((proto::A, v)) => {
                if v.first().is_some_and(|d| *d < proto::PROTOCOL) {
                    stop_running(Some(proto::PROTOCOL));
                }
                give_up();
                return (got, None);
            }
            _ => {
                give_up();
                return (got, None);
            }
        }
        let mut seen = std::collections::HashSet::new();
        let mut since_object = Instant::now();
        let step_wait = match req {
            Request::Batch { .. } => BETWEEN_OBJECTS,
            _ => Duration::from_secs(2),
        };
        let failed = |got| {
            give_up();
            (got, None)
        };
        loop {
            if since_object.elapsed() > step_wait {
                return failed(got);
            }
            let Ok((kind, len)) = proto::read_head(&mut r, MAX_OBJECT + 32) else { return failed(got) };
            let Ok(payload) = proto::read_object(&mut r, len, since_object + step_wait) else { return failed(got) };
            match kind {
                proto::P => {}
                proto::O => {
                    let Ok((id, raw)) = proto::object_of(payload) else { return failed(got) };
                    // Never wrong bytes: an object that is not what was
                    // asked for, or sent twice, ends the answer.
                    if !wanted(&id) || !seen.insert(id) || ObjectId::hash(&raw) != id {
                        return failed(got);
                    }
                    got.push((id, raw));
                    since_object = Instant::now();
                }
                proto::E => match serde_json::from_slice(&payload) {
                    Ok(h) => return (got, Some(h)),
                    Err(_) => return failed(got),
                },
                _ => return failed(got),
            }
        }
    }

    /// What the daemon serves of `batch` for `project` of the server at
    /// `authority` (starting the daemon if needed): the objects that
    /// arrived, each checked. Empty when there is no daemon.
    pub fn fetch(authority: &str, project: &str, batch: BatchRequest) -> Vec<(ObjectId, Vec<u8>)> {
        let Some(s) = connect_or_start() else { return Vec::new() };
        let wanted: std::collections::HashSet<ObjectId> = batch.wants.iter().map(|w| w.id).collect();
        let req = Request::Batch { upstream: authority.to_string(), project: project.to_string(), batch };
        request(s, &req, &|id| wanted.contains(id)).0
    }

    /// Ask the daemon (starting it if needed, unless turned off with `vl
    /// daemon stop`) to watch working copy `root` and report what changed
    /// since `token`.
    pub fn watch(root: & std::path::Path, token: Option<&str>) -> Option<super::watch::WatchReply> {
        let s = connect_or_start()?;
        let max_dirs = std::env::var("VEIL_WATCH_MAX_DIRS").ok().and_then(|v| v.parse().ok());
        let max_dirty_paths = std::env::var("VEIL_WATCH_MAX_DIRTY").ok().and_then(|v| v.parse().ok());
        let req = Request::Watch {
            root: root.to_path_buf(),
            token: token.map(str::to_string),
            max_dirs,
            max_dirty_paths,
        };
        let body = request(s, &req, &|_| false).1?.body?;
        serde_json::from_value(body).ok()
    }

    /// Ask the running daemon (never started for this) to pin `roots` for
    /// working copy `key`.
    pub fn pin(authority: &str, project: &str, key: &str, roots: Vec<ObjectId>) {
        if UNUSABLE.load(Ordering::SeqCst) {
            return;
        }
        let Some(s) = connect() else { return };
        let req = Request::Pin { upstream: authority.to_string(), project: project.to_string(), key: key.to_string(), roots };
        let _ = request(s, &req, &|_| false);
    }

    /// The running daemon's status.
    pub fn status() -> Option<serde_json::Value> {
        let s = connect()?;
        request(s, &Request::Status, &|_| false).1?.body
    }
}

// ---- `vl daemon` ---------------------------------------------------------------------

/// `vl daemon`.
#[derive(clap::Subcommand, Debug)]
pub enum DaemonCmd {
    /// Show the daemon: its object store, what it served and the servers
    /// it reads from.
    Status,
    /// Start the daemon, and let `vl` start it again whenever a thin clone
    /// needs it (the default).
    Start {
        /// Bound of the daemon's object store (bytes, or with K, M or G);
        /// default 20G or a tenth of the disk, whichever is less.
        #[arg(long)]
        cache_size: Option<String>,
    },
    /// Stop the daemon and keep it off: `vl` reads from the server
    /// directly until `vl daemon start`.
    Stop,
    /// Run the daemon in this process (what `vl` starts in the background).
    #[command(hide = true)]
    Run,
    /// Keep the top trees of followed projects in the daemon's store
    /// (started by the daemon).
    #[command(hide = true)]
    Follow,
}

pub fn run(cmd: &DaemonCmd) -> Result<std::process::ExitCode> {
    #[cfg(not(unix))]
    {
        let _ = cmd;
        bail!("the Veil daemon runs on Linux and macOS");
    }
    #[cfg(unix)]
    {
        let p = paths();
        match cmd {
            DaemonCmd::Run => run_daemon(&p)?,
            DaemonCmd::Follow => follow::run(&p)?,
            DaemonCmd::Start { cache_size } => {
                p.prepare()?;
                if let Some(s) = cache_size {
                    let limit = veil_core::promisor::parse_size(s)?;
                    if limit == 0 {
                        bail!("give the daemon's store a size above 0");
                    }
                    write_config(&p, limit)?;
                }
                let _ = std::fs::remove_file(&p.off);
                if connect().is_none() {
                    start(&p)?;
                }
                let s = status().ok_or_else(|| anyhow::anyhow!("the daemon started but does not answer"))?;
                println!("{} the Veil daemon runs (pid {}); vl starts it when a thin clone needs it", green("on:"), s["pid"]);
            }
            DaemonCmd::Stop => {
                p.prepare()?;
                std::fs::write(&p.off, b"off\n")?;
                stop_running(None);
                let t = std::time::Instant::now();
                while connect().is_some() {
                    if t.elapsed() > std::time::Duration::from_secs(5) {
                        bail!("the daemon did not stop within 5 s");
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                println!("{} the Veil daemon is stopped and stays off; vl reads from the server directly (`vl daemon start` turns it on)", green("off:"));
            }
            DaemonCmd::Status => print_status(&p),
        }
        Ok(std::process::ExitCode::SUCCESS)
    }
}

fn write_config(p: &Paths, limit: u64) -> Result<()> {
    let tmp = p.state.join(format!("config.json.tmp{}", std::process::id()));
    std::fs::write(&tmp, serde_json::to_vec(&serde_json::json!({ "cache_size": limit }))?)?;
    std::fs::rename(&tmp, p.state.join("config.json"))?;
    Ok(())
}

#[cfg(unix)]
fn print_status(p: &Paths) {
    use veil_core::promisor::human;
    let Some(s) = status() else {
        if connect().is_some() {
            println!("Veil daemon: one this vl cannot read runs (another version, or not answering); `vl daemon stop` stops it");
            return;
        }
        match p.off.exists() {
            true => println!("Veil daemon: off (`vl daemon start` turns it on)"),
            false => println!("Veil daemon: not running (vl starts it when a thin clone needs it)"),
        }
        return;
    };
    let n = |v: &serde_json::Value| v.as_u64().unwrap_or(0);
    let st = &s["store"];
    println!("Veil daemon: running (pid {}), socket {}", s["pid"], crate::render::safe(&p.socket.display().to_string()));
    println!(
        "  store     {} of {} ({} object(s), {} working copies pin what they check out){}",
        human(n(&st["bytes"])),
        human(n(&st["limit"])),
        n(&st["objects"]),
        n(&st["pins"]),
        if st["ready"].as_bool() == Some(true) { "" } else { "; reading its index" }
    );
    let (local, up) = (n(&s["from_store"]), n(&s["from_upstream"]));
    let rate = if local + up == 0 { 0.0 } else { 100.0 * local as f64 / (local + up) as f64 };
    println!("  served    {local} object(s) from the store, {up} from the server ({rate:.1} % from the store)");
    let ups: Vec<String> = s["upstreams"].as_array().map(|a| a.iter().filter_map(|u| u.as_str().map(|x| crate::render::safe(x).to_string())).collect()).unwrap_or_default();
    println!("  servers   {}", if ups.is_empty() { "none yet".into() } else { ups.join(", ") });
    println!("  following {} project(s); access confirmed for {} grant(s)", n(&s["follows"]), n(&s["confirmed"]));
    let watched_wcs = s["watching"].as_array().map_or(0, Vec::len);
    println!("  watching  {} working cop(ies), {} director(ies)", watched_wcs, n(&s["watched_dirs"]));
    println!("  {}", dim("objects only: tips, grants, history and pushes always go to the server"));
}

/// `vl daemon run`: one daemon per Veil home (a lock), its socket made
/// private, then serve.
#[cfg(unix)]
fn run_daemon(p: &Paths) -> Result<()> {
    use std::os::{fd::AsRawFd, unix::fs::PermissionsExt};
    p.prepare()?;
    if p.off.exists() {
        return Ok(());
    }
    let lock = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(p.state.join("lock"))?;
    // SAFETY: a valid descriptor.
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Ok(()); // another daemon of this Veil home runs
    }
    let _ = std::fs::remove_file(&p.socket);
    // SAFETY: umask has no preconditions; this process makes only private files.
    unsafe { libc::umask(0o077) };
    // What the budgets count is what the process holds: glibc would keep
    // each thread's freed buffers (an object of up to 16 MiB each) in
    // arenas of their own. Allocations of 256 KiB and more are mapped and
    // given back when freed, and there are at most 4 arenas.
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    // SAFETY: mallopt only changes the allocator's tuning, before any thread starts.
    unsafe {
        libc::mallopt(libc::M_MMAP_THRESHOLD, 256 << 10);
        libc::mallopt(libc::M_ARENA_MAX, 4);
    }
    let listener = std::os::unix::net::UnixListener::bind(&p.socket).with_context(|| format!("binding {}", p.socket.display()))?;
    std::fs::set_permissions(&p.socket, std::fs::Permissions::from_mode(0o600))?;
    let store = store::Store::open(&p.store, configured_limit(p).unwrap_or(20 << 30))?;
    let d = std::sync::Arc::new(serve::Daemon::new(p.clone(), store));
    eprintln!("vl daemon {}: serving on {}", std::process::id(), p.socket.display());
    let r = d.serve(listener);
    drop(lock);
    r
}

/// The objects of `wants` (chain, id) under `grant` that the daemon serves,
/// signed by `identity` (a thin clone's reads, `crate::thin`).
#[cfg(unix)]
pub(crate) fn fetch_under(
    authority: &str,
    project: &str,
    identity: &veil_core::Identity,
    grant: &veil_core::hub::grant::Grant,
    token: &str,
    wants: Vec<(Vec<ObjectId>, ObjectId)>,
) -> Vec<(ObjectId, Vec<u8>)> {
    use veil_core::hub::grant::{sign_request, BatchRequest, ChainWant};
    if wants.is_empty() {
        return Vec::new();
    }
    let ids: Vec<ObjectId> = wants.iter().map(|w| w.1).collect();
    let ts = veil_core::now_millis();
    let signature = grant.body.device.as_ref().map(|_| sign_request(identity, grant, ts, &ids));
    let batch = BatchRequest { grant: token.to_string(), ts, signature, wants: wants.into_iter().map(|(chain, id)| ChainWant { chain, id }).collect(), skip: Vec::new() };
    fetch(authority, project, batch)
}

#[cfg(not(unix))]
pub(crate) fn fetch_under(
    _: &str,
    _: &str,
    _: &veil_core::Identity,
    _: &veil_core::hub::grant::Grant,
    _: &str,
    _: Vec<(Vec<ObjectId>, ObjectId)>,
) -> Vec<(ObjectId, Vec<u8>)> {
    Vec::new()
}
