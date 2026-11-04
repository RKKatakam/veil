//! `vl serve --local`: the repository over a Unix socket, for editors and
//! agents that would otherwise spawn one `vl` per question.
//!
//! **Protocol.** Newline-delimited JSON-RPC 2.0 on `.veil/local/sock`: one
//! request (or batch) per line, one response per line. Documented in
//! `docs/reference/json-rpc.md`.
//!
//! * The read methods answer with exactly the document the command prints
//!   with `--json`: the same `api` function builds it, and it is serialised
//!   by the same writer (`api::to_json`), so the bytes are the CLI's.
//! * The write methods (`snapshot`, `describe`, `new`, `commit`) call the
//!   same `api` functions as the commands, which call the same `Repo`
//!   methods: each takes the repository lock for its transaction, exactly
//!   as the CLI does, and records the same operation, so `vl undo` works.
//!
//! **Freshness and locking.** Every request opens the repository afresh
//! (`Ctx::open`), exactly as a `vl` process would, so nothing is cached
//! between requests and nothing a CLI command did in between is missed.
//! The repository lock is only ever held inside a request's transactions.
//! Requests that touch the working copy (a snapshot, a write) are also
//! serialised inside this server; pure reads (`"snapshot": false`) run in
//! parallel.
//!
//! **Access.** Only the user running the server can connect: the socket is
//! created `0600` in `.veil/local` (`0700`, owned by the user, never a
//! symlink), and every connection's peer credentials (`SO_PEERCRED`,
//! `getpeereid`) must name the same user. The client checks the server's
//! credentials the same way. A request is at most [`MAX_REQUEST`] bytes,
//! and at most [`MAX_CONNECTIONS`] clients are served at once. No parameter
//! names a path outside the repository: methods take revisions, messages
//! and limits, and `scan`'s `policy_from` must lie inside the repository.
//!
//! **One server per repository.** The server holds an exclusive `flock` on
//! `.veil/local/serve.lock` while it runs; a second one refuses to start. A
//! socket left by a server that died is therefore stale and replaced. On
//! SIGINT, SIGTERM or SIGHUP the server stops accepting, removes its socket
//! (only if it is still its own), and waits for requests in flight.

use std::{
    ffi::CString,
    fs::File,
    io::{self, BufRead, BufReader, Write},
    os::unix::{
        fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        io::{AsRawFd, FromRawFd, IntoRawFd},
        net::{UnixListener, UnixStream},
    },
    panic::AssertUnwindSafe,
    path::{Path, PathBuf},
    process::ExitCode,
    sync::{
        atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering},
        Arc, Mutex, MutexGuard,
    },
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Context, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{value::RawValue, Value};
use veil_core::{oplog::OpStore, repo::VEIL_DIR, DiskBackend};

use crate::{
    api,
    cli::{Cmd, JsonOut, OpCmd, SecretCmd, TagCmd, WsCmd},
    ctx::{find_root, Ctx},
    render::{dim, green, safe, warn},
};

/// The socket's name in `.veil/local`.
pub const SOCKET: &str = "sock";
/// Held (`flock`) by the running server.
const LOCK_FILE: &str = "serve.lock";
/// The largest request line, in bytes (without its newline).
pub const MAX_REQUEST: usize = 1 << 20;
/// Clients served at once; more are told so and disconnected.
pub const MAX_CONNECTIONS: usize = 32;
/// Requests in one batch.
pub const MAX_BATCH: usize = 64;
/// How long an answer may wait for its client to read it.
const WRITE_TIMEOUT: Duration = Duration::from_secs(60);
/// How long a stopping server waits for requests in flight.
const DRAIN: Duration = Duration::from_secs(30);

pub const SERVER_INFO_SCHEMA: &str = "veil.server.info/1";
pub const WATCH_SCHEMA: &str = "veil.watch/1";
pub const CHANGED_SCHEMA: &str = "veil.changed/1";

/// Every method, in the order `server.info` lists them.
pub const METHODS: &[&str] = &[
    "status",
    "log",
    "diff",
    "show",
    "ws.list",
    "tag.list",
    "op.log",
    "scan",
    "secret.list",
    "snapshot",
    "describe",
    "new",
    "commit",
    "watch",
    "unwatch",
    "server.info",
];

// ---- JSON-RPC error codes ------------------------------------------------------------

pub const PARSE_ERROR: i64 = -32700;
pub const INVALID_REQUEST: i64 = -32600;
pub const METHOD_NOT_FOUND: i64 = -32601;
pub const INVALID_PARAMS: i64 = -32602;
pub const INTERNAL_ERROR: i64 = -32603;
/// The command failed; `data` is its `veil.error/1` document.
pub const COMMAND_FAILED: i64 = -32000;
/// [`MAX_CONNECTIONS`] clients are connected already.
pub const SERVER_BUSY: i64 = -32001;

fn euid() -> u32 {
    unsafe { libc::geteuid() }
}

fn cstr(s: &str) -> CString {
    CString::new(s).expect("no NUL")
}

fn last_os_error<T>(what: &str) -> Result<T> {
    Err(io::Error::last_os_error()).with_context(|| what.to_string())
}

// ---- the socket's directory ------------------------------------------------------------

/// `.veil/local`, opened (never through a symlink) and checked: a directory
/// owned by this user. The server creates it if missing and makes it `0700`;
/// the client only checks the owner (the peer check is what it relies on).
fn local_dir(root: &Path, server: bool) -> Result<File> {
    let veil = root.join(VEIL_DIR);
    let m = std::fs::symlink_metadata(&veil).with_context(|| format!("reading {}", veil.display()))?;
    if !m.is_dir() {
        bail!("{} is not a directory", veil.display());
    }
    if m.uid() != euid() {
        bail!("{} belongs to uid {}, not to you (uid {}): serve only your own repositories", veil.display(), m.uid(), euid());
    }
    let local = veil.join("local");
    if server {
        match std::fs::DirBuilder::new().mode(0o700).create(&local) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e).with_context(|| format!("creating {}", local.display())),
        }
    }
    let dir = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&local)
        .with_context(|| format!("opening {} (it must be a directory, not a symlink)", local.display()))?;
    let m = dir.metadata()?;
    if m.uid() != euid() {
        bail!("{} belongs to uid {}, not to you (uid {})", local.display(), m.uid(), euid());
    }
    if server && m.mode() & 0o077 != 0 {
        dir.set_permissions(std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("making {} private (0700)", local.display()))?;
        eprintln!("{} {} is now private (mode 0700)", dim("note:"), local.display());
    }
    Ok(dir)
}

/// Run `f` with `dir` as the current directory, so a socket is named by its
/// short relative name (a socket path is limited to about 100 bytes, and
/// the directory, already checked, cannot be swapped under us). Only called
/// while the process has a single thread: at server start, and in the
/// client.
fn in_dir<T>(dir: &File, f: impl FnOnce() -> io::Result<T>) -> Result<T> {
    let back = std::env::current_dir().ok();
    if unsafe { libc::fchdir(dir.as_raw_fd()) } != 0 {
        return last_os_error("entering .veil/local");
    }
    let r = f();
    match back {
        Some(b) => {
            let _ = std::env::set_current_dir(b);
        }
        None => {
            let _ = std::env::set_current_dir("/");
        }
    }
    Ok(r?)
}

/// `(dev, ino, is a socket)` of `name` in `dir`, without following a
/// symlink; `None` if absent.
fn stat_at(dir: &File, name: &str) -> Result<Option<(u64, u64, bool)>> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let c = cstr(name);
    if unsafe { libc::fstatat(dir.as_raw_fd(), c.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        let e = io::Error::last_os_error();
        if e.kind() == io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(e).with_context(|| format!("reading .veil/local/{name}"));
    }
    #[allow(clippy::unnecessary_cast)]
    Ok(Some((st.st_dev as u64, st.st_ino as u64, (st.st_mode as u32 & libc::S_IFMT as u32) == libc::S_IFSOCK as u32)))
}

fn unlink_at(dir: &File, name: &str) -> io::Result<()> {
    let c = cstr(name);
    if unsafe { libc::unlinkat(dir.as_raw_fd(), c.as_ptr(), 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

// ---- peer credentials ----------------------------------------------------------------

/// The user id of the process at the other end of `s`.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn peer_uid(s: &UnixStream) -> io::Result<u32> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let r = unsafe {
        libc::getsockopt(s.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED, (&mut cred as *mut libc::ucred).cast(), &mut len)
    };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    if len as usize != std::mem::size_of::<libc::ucred>() {
        return Err(io::Error::other("short SO_PEERCRED answer"));
    }
    Ok(cred.uid)
}

/// The user id of the process at the other end of `s`.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn peer_uid(s: &UnixStream) -> io::Result<u32> {
    let (mut uid, mut gid): (libc::uid_t, libc::gid_t) = (0, 0);
    if unsafe { libc::getpeereid(s.as_raw_fd(), &mut uid, &mut gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(uid)
}

/// Is the peer of `s` the user `owner`? Any failure to tell is a no.
fn peer_is(s: &UnixStream, owner: u32) -> bool {
    matches!(peer_uid(s), Ok(uid) if uid == owner)
}

// ---- signals ---------------------------------------------------------------------------

/// The write end of the self-pipe the signal handler writes to.
static SIGNAL_FD: AtomicI32 = AtomicI32::new(-1);

extern "C" fn on_signal(_: libc::c_int) {
    let fd = SIGNAL_FD.load(Ordering::Relaxed);
    if fd >= 0 {
        // Async-signal-safe; a full pipe already holds a wake-up.
        unsafe { libc::write(fd, b"x".as_ptr().cast(), 1) };
    }
}

/// SIGINT, SIGTERM and SIGHUP wake the accept loop through the returned
/// socket instead of killing the process.
fn install_signals() -> Result<UnixStream> {
    let (r, w) = UnixStream::pair()?;
    r.set_nonblocking(true)?;
    w.set_nonblocking(true)?;
    SIGNAL_FD.store(w.into_raw_fd(), Ordering::Relaxed);
    for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };
        sa.sa_sigaction = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
        sa.sa_flags = libc::SA_RESTART;
        unsafe { libc::sigemptyset(&mut sa.sa_mask) };
        if unsafe { libc::sigaction(sig, &sa, std::ptr::null_mut()) } != 0 {
            return last_os_error("installing a signal handler");
        }
    }
    Ok(r)
}

// ---- the server ----------------------------------------------------------------------

fn repo_root(repo_arg: Option<&Path>) -> Result<PathBuf> {
    let start = match repo_arg {
        Some(p) => p.to_path_buf(),
        None => std::env::current_dir()?,
    };
    let root = find_root(&start)
        .ok_or_else(|| anyhow!("no Veil repository found in {} or its parents (run `vl init`)", start.display()))?;
    Ok(root.canonicalize().unwrap_or(root))
}

pub fn socket_path(root: &Path) -> PathBuf {
    root.join(VEIL_DIR).join("local").join(SOCKET)
}

struct Server {
    root: PathBuf,
    /// Requests snapshot the working copy first unless they say otherwise
    /// (`vl --no-snapshot serve --local` flips the default).
    snapshot_default: bool,
    /// Serialises the requests that touch the working copy.
    writes: Mutex<()>,
    connections: AtomicUsize,
    in_flight: AtomicUsize,
    stopping: AtomicBool,
}

/// Decrements a counter when dropped.
struct Count<'a>(&'a AtomicUsize);

impl<'a> Count<'a> {
    fn up(c: &'a AtomicUsize) -> Count<'a> {
        c.fetch_add(1, Ordering::SeqCst);
        Count(c)
    }
}

impl Drop for Count<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// `vl serve --local`.
pub fn run(repo_arg: Option<&Path>, snapshot_default: bool) -> Result<ExitCode> {
    let root = repo_root(repo_arg)?;
    let sock = socket_path(&root);
    let dir = local_dir(&root, true)?;
    // A first use creates the identity now, not in two racing requests.
    crate::ctx::load_identity()?;

    // One server per repository: the lock lives as long as this process.
    let c = cstr(LOCK_FILE);
    let fd = unsafe {
        libc::openat(dir.as_raw_fd(), c.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC, 0o600)
    };
    if fd < 0 {
        return last_os_error("opening .veil/local/serve.lock");
    }
    let mut lock = unsafe { File::from_raw_fd(fd) };
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::EWOULDBLOCK) {
            let pid = std::fs::read_to_string(sock.with_file_name(LOCK_FILE)).unwrap_or_default();
            let pid = pid.trim();
            bail!(
                "another `vl serve --local`{} is already serving {} on {}",
                if pid.is_empty() { String::new() } else { format!(" (pid {})", safe(pid)) },
                root.display(),
                sock.display()
            );
        }
        return Err(e).context("locking .veil/local/serve.lock");
    }
    lock.set_len(0)?;
    writeln!(lock, "{}", std::process::id())?;

    // Under the lock, a socket left behind is a dead server's. Something
    // that is not a socket is not ours to remove.
    // From here a signal stops the server cleanly (the accept loop sees it
    // at once).
    let signals = install_signals()?;
    if let Some((_, _, is_socket)) = stat_at(&dir, SOCKET)? {
        if !is_socket {
            bail!("{} exists and is not a socket; move it away", sock.display());
        }
        if in_dir(&dir, || Ok(UnixStream::connect(SOCKET).is_ok()))? {
            bail!("a server is already listening on {}", sock.display());
        }
        unlink_at(&dir, SOCKET).with_context(|| format!("removing the stale socket {}", sock.display()))?;
        eprintln!("{} the stale socket {}", green("Replaced"), sock.display());
    }
    let listener = in_dir(&dir, || {
        // Created `0600` from the start: no moment where it is wider.
        let old = unsafe { libc::umask(0o177) };
        let l = UnixListener::bind(SOCKET);
        unsafe { libc::umask(old) };
        let l = l?;
        std::fs::set_permissions(SOCKET, std::fs::Permissions::from_mode(0o600))?;
        Ok(l)
    })
    .with_context(|| format!("listening on {}", sock.display()))?;
    let ours = match stat_at(&dir, SOCKET) {
        Ok(Some((d, i, true))) => Some((d, i)),
        _ => bail!("{} vanished right after it was created", sock.display()),
    };
    if let Err(e) = listener.set_nonblocking(true) {
        let _ = unlink_at(&dir, SOCKET);
        return Err(e.into());
    }

    let server = Arc::new(Server {
        root: root.clone(),
        snapshot_default,
        writes: Mutex::new(()),
        connections: AtomicUsize::new(0),
        in_flight: AtomicUsize::new(0),
        stopping: AtomicBool::new(false),
    });
    eprintln!(
        "{} {} on {} (JSON-RPC 2.0, one request per line; Ctrl-C to stop)",
        green("Serving"),
        root.display(),
        sock.display()
    );

    let why = accept_loop(&server, &listener, &signals, &dir, ours);
    server.stopping.store(true, Ordering::SeqCst);
    drop(listener);
    // Remove the socket only if it is still the one we bound.
    let still_ours = stat_at(&dir, SOCKET).ok().flatten().map(|(d, i, _)| (d, i)) == ours;
    if still_ours {
        let _ = unlink_at(&dir, SOCKET);
    }
    let start = Instant::now();
    while server.in_flight.load(Ordering::SeqCst) > 0 && start.elapsed() < DRAIN {
        std::thread::sleep(Duration::from_millis(20));
    }
    eprintln!("{} ({why})", green("Stopped"));
    drop(lock);
    Ok(ExitCode::SUCCESS)
}

/// Accept clients until a signal arrives or the socket is taken away.
/// Returns why it stopped.
fn accept_loop(server: &Arc<Server>, listener: &UnixListener, signals: &UnixStream, dir: &File, ours: Option<(u64, u64)>) -> String {
    let owner = euid();
    let mut last_check = Instant::now();
    loop {
        let mut fds = [
            libc::pollfd { fd: listener.as_raw_fd(), events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: signals.as_raw_fd(), events: libc::POLLIN, revents: 0 },
        ];
        let n = unsafe { libc::poll(fds.as_mut_ptr(), 2, 1000) };
        if n < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return format!("poll failed: {}", io::Error::last_os_error());
        }
        if fds[1].revents != 0 {
            return "signal".into();
        }
        if last_check.elapsed() >= Duration::from_secs(1) {
            last_check = Instant::now();
            // Removed or replaced (the repository deleted, `rm sock`): no
            // client can reach this server any more.
            if stat_at(dir, SOCKET).ok().flatten().map(|(d, i, _)| (d, i)) != ours {
                return "the socket was removed or replaced".into();
            }
        }
        loop {
            let stream = match listener.accept() {
                Ok((s, _)) => s,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    warn(&format!("accepting a client: {e}"));
                    break;
                }
            };
            // Accepted sockets inherit non-blocking mode on BSD and macOS.
            if stream.set_nonblocking(false).is_err() {
                continue;
            }
            // A client that stops reading its answers loses its connection
            // instead of holding a thread (and a slot) forever.
            let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));
            // Another user: told nothing, disconnected.
            if !peer_is(&stream, owner) {
                continue;
            }
            if server.connections.load(Ordering::SeqCst) >= MAX_CONNECTIONS {
                let mut s = stream;
                let _ = s.set_write_timeout(Some(Duration::from_secs(1)));
                let line = error_line("null", SERVER_BUSY, &format!("too many clients (at most {MAX_CONNECTIONS})"), None);
                let _ = s.write_all(format!("{line}\n").as_bytes());
                // Off the accept loop: hanging up takes a moment.
                let _ = std::thread::Builder::new().spawn(move || hang_up(s));
                continue;
            }
            let server = server.clone();
            server.connections.fetch_add(1, Ordering::SeqCst);
            let spawned = std::thread::Builder::new().name("vl-serve-client".into()).spawn({
                let server = server.clone();
                move || {
                    let _count = Count(&server.connections);
                    serve_client(&server, stream);
                }
            });
            if spawned.is_err() {
                server.connections.fetch_sub(1, Ordering::SeqCst);
            }
        }
    }
}

// ---- one client ------------------------------------------------------------------------

/// What reading one request line gave.
enum Line {
    Request(Vec<u8>),
    TooLong,
    Closed,
}

/// Read up to the next `\n`, refusing (without buffering it) a line over
/// `max` bytes.
fn read_line(r: &mut impl BufRead, max: usize) -> io::Result<Line> {
    let mut line = Vec::new();
    loop {
        let buf = match r.fill_buf() {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if buf.is_empty() {
            // A last request without its newline still counts.
            return Ok(if line.is_empty() { Line::Closed } else { Line::Request(line) });
        }
        let (chunk, done) = match buf.iter().position(|&b| b == b'\n') {
            Some(i) => (&buf[..i], Some(i + 1)),
            None => (buf, None),
        };
        if line.len() + chunk.len() > max {
            return Ok(Line::TooLong);
        }
        line.extend_from_slice(chunk);
        let used = done.unwrap_or(buf.len());
        r.consume(used);
        if done.is_some() {
            return Ok(Line::Request(line));
        }
    }
}

/// The connection's writer, shared with its watch thread.
type Writer = Arc<Mutex<UnixStream>>;

fn send(w: &Writer, line: &str) -> io::Result<()> {
    let mut s = w.lock().unwrap_or_else(|e| e.into_inner());
    s.write_all(line.as_bytes())?;
    s.write_all(b"\n")
}

/// A running `watch` subscription.
struct Watch {
    stop: Arc<AtomicBool>,
    thread: std::thread::JoinHandle<()>,
}

impl Watch {
    fn end(self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = self.thread.join();
    }
}

struct Client {
    server: Arc<Server>,
    writer: Writer,
    watch: Option<Watch>,
}

fn serve_client(server: &Arc<Server>, stream: UnixStream) {
    let Ok(w) = stream.try_clone() else { return };
    let mut client = Client { server: server.clone(), writer: Arc::new(Mutex::new(w)), watch: None };
    let mut reader = BufReader::new(stream);
    loop {
        let line = match read_line(&mut reader, MAX_REQUEST) {
            Ok(Line::Request(l)) => l,
            Ok(Line::TooLong) => {
                // Where the next request starts is unknown: hang up.
                let msg = format!("request too large (more than {MAX_REQUEST} bytes)");
                let _ = send(&client.writer, &error_line("null", INVALID_REQUEST, &msg, None));
                hang_up(reader.into_inner());
                return end(client);
            }
            Ok(Line::Closed) | Err(_) => break,
        };
        if server.stopping.load(Ordering::SeqCst) {
            break;
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let response = {
            let _busy = Count::up(&server.in_flight);
            server.handle_line(&line, &mut client)
        };
        if let Some(r) = response {
            if send(&client.writer, &r).is_err() {
                break;
            }
        }
    }
    end(client);
}

fn end(mut client: Client) {
    if let Some(w) = client.watch.take() {
        w.end();
    }
}

/// Close a connection whose client may still be sending: stop writing,
/// then read and drop what it sends for a moment, so that the close does
/// not reset the connection (and lose the error just sent) because unread
/// data was left behind.
fn hang_up(mut s: UnixStream) {
    let _ = s.shutdown(std::net::Shutdown::Write);
    let _ = s.set_read_timeout(Some(Duration::from_millis(200)));
    let start = Instant::now();
    let mut buf = [0u8; 64 * 1024];
    let mut total = 0usize;
    while start.elapsed() < Duration::from_secs(2) && total < 64 * MAX_REQUEST {
        match io::Read::read(&mut s, &mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => total += n,
        }
    }
}

// ---- JSON-RPC framing ------------------------------------------------------------------

/// An error to answer with.
#[derive(Debug)]
pub struct RpcError {
    code: i64,
    message: String,
    /// Serialised JSON.
    data: Option<String>,
}

impl RpcError {
    fn new(code: i64, message: impl Into<String>) -> RpcError {
        RpcError { code, message: message.into(), data: None }
    }

    /// A failed command: its message, and its `veil.error/1` document.
    fn failed(e: anyhow::Error) -> RpcError {
        let message = format!("{e:#}");
        let doc = api::ErrorDoc::new(message.clone(), crate::error_hint(&e).map(String::from));
        RpcError { code: COMMAND_FAILED, data: api::to_json(&doc).ok(), message }
    }
}

impl From<anyhow::Error> for RpcError {
    fn from(e: anyhow::Error) -> RpcError {
        RpcError::failed(e)
    }
}

fn json<T: Serialize>(v: &T) -> String {
    api::to_json(v).unwrap_or_else(|_| "null".into())
}

fn error_line(id: &str, code: i64, message: &str, data: Option<&str>) -> String {
    let data = data.map(|d| format!(",\"data\":{d}")).unwrap_or_default();
    format!("{{\"jsonrpc\":\"2.0\",\"id\":{id},\"error\":{{\"code\":{code},\"message\":{}{data}}}}}", json(&message))
}

/// The request's `id`: a string, a number or null.
fn valid_id(id: &Value) -> bool {
    matches!(id, Value::String(_) | Value::Number(_) | Value::Null)
}

impl Server {
    /// Answer one line: a request, or a batch of them. `None`: nothing to
    /// send (only notifications).
    fn handle_line(&self, line: &[u8], client: &mut Client) -> Option<String> {
        let v: Value = match std::str::from_utf8(line).ok().and_then(|s| serde_json::from_str(s).ok()) {
            Some(v) => v,
            None => return Some(error_line("null", PARSE_ERROR, "parse error: not one JSON value in UTF-8", None)),
        };
        match v {
            Value::Array(reqs) if reqs.is_empty() => Some(error_line("null", INVALID_REQUEST, "empty batch", None)),
            Value::Array(reqs) if reqs.len() > MAX_BATCH => {
                Some(error_line("null", INVALID_REQUEST, &format!("batch too large (at most {MAX_BATCH} requests)"), None))
            }
            Value::Array(reqs) => {
                let out: Vec<String> = reqs.into_iter().filter_map(|r| self.handle_request(r, client)).collect();
                (!out.is_empty()).then(|| format!("[{}]", out.join(",")))
            }
            v => self.handle_request(v, client),
        }
    }

    fn handle_request(&self, v: Value, client: &mut Client) -> Option<String> {
        let Value::Object(mut req) = v else {
            return Some(error_line("null", INVALID_REQUEST, "a request is a JSON object", None));
        };
        let id = req.remove("id");
        let notification = id.is_none();
        let id_text = match &id {
            Some(i) if valid_id(i) => json(i),
            Some(_) => return Some(error_line("null", INVALID_REQUEST, "id must be a string, a number or null", None)),
            None => "null".into(),
        };
        let reply = |r: Result<String, RpcError>| -> Option<String> {
            if notification {
                return None;
            }
            Some(match r {
                Ok(doc) => format!("{{\"jsonrpc\":\"2.0\",\"id\":{id_text},\"result\":{doc}}}"),
                Err(e) => error_line(&id_text, e.code, &e.message, e.data.as_deref()),
            })
        };
        if req.get("jsonrpc") != Some(&Value::String("2.0".into())) {
            return reply(Err(RpcError::new(INVALID_REQUEST, "\"jsonrpc\" must be \"2.0\"")));
        }
        let method = match req.remove("method") {
            Some(Value::String(m)) => m,
            _ => return reply(Err(RpcError::new(INVALID_REQUEST, "\"method\" must be a string"))),
        };
        if let Some(k) = req.keys().find(|k| *k != "jsonrpc" && *k != "params") {
            return reply(Err(RpcError::new(INVALID_REQUEST, format!("unknown member {}", json(k)))));
        }
        let params = match req.remove("params") {
            None | Some(Value::Null) => Value::Object(Default::default()),
            Some(p @ Value::Object(_)) => p,
            Some(_) => return reply(Err(RpcError::new(INVALID_PARAMS, "params must be an object (named parameters)")))
        };
        // A bug here must not take the server down with it.
        let r = std::panic::catch_unwind(AssertUnwindSafe(|| self.call(&method, params, client)))
            .unwrap_or_else(|_| Err(RpcError::new(INTERNAL_ERROR, "internal error (see the server's standard error)")));
        reply(r)
    }
}

// ---- methods ---------------------------------------------------------------------------

fn params<T: DeserializeOwned>(p: Value) -> Result<T, RpcError> {
    serde_json::from_value(p).map_err(|e| RpcError::new(INVALID_PARAMS, format!("invalid params: {e}")))
}

/// Parameters of a method that takes nothing but `snapshot`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plain {
    snapshot: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LogParams {
    limit: Option<usize>,
    snapshot: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DiffParams {
    rev: Option<String>,
    from: Option<String>,
    to: Option<String>,
    #[serde(default)]
    stat: bool,
    snapshot: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ShowParams {
    rev: Option<String>,
    #[serde(default)]
    stat: bool,
    snapshot: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScanParams {
    policy_from: Option<String>,
    snapshot: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NoParams {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DescribeParams {
    rev: Option<String>,
    message: String,
    snapshot: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewParams {
    #[serde(default)]
    revs: Vec<String>,
    #[serde(default)]
    message: String,
    snapshot: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CommitParams {
    message: String,
    #[serde(default)]
    no_advance: bool,
    snapshot: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WatchParams {
    interval_ms: Option<u64>,
    #[serde(default)]
    working_copy: bool,
}

/// A write method: what it does to the repository.
enum WriteOp {
    Snapshot,
    Describe { rev: String, message: String },
    New { revs: Vec<String>, message: String },
    Commit { message: String, advance: bool },
}

const JSON: JsonOut = JsonOut { json: true };

/// `veil.server.info/1`.
#[derive(Serialize)]
struct ServerInfo {
    schema: &'static str,
    version: &'static str,
    root: String,
    socket: String,
    pid: u32,
    methods: &'static [&'static str],
    max_request_bytes: usize,
    max_connections: usize,
    max_batch: usize,
}

/// `veil.watch/1`.
#[derive(Serialize)]
struct WatchDoc {
    schema: &'static str,
    watching: bool,
    /// The head of the operation log when the subscription started.
    operation: Option<api::OpRef>,
    interval_ms: Option<u64>,
    working_copy: bool,
}

/// `veil.changed/1`, the params of a `changed` notification.
#[derive(Serialize)]
struct Changed {
    schema: &'static str,
    /// The new head of the operation log, as `op.log` shows it.
    operation: api::OpEntry,
}

impl Server {
    fn call(&self, method: &str, p: Value, client: &mut Client) -> Result<String, RpcError> {
        let read = |cmd: Cmd, snapshot: Option<bool>| self.read(cmd, snapshot);
        match method {
            "status" => {
                let p: Plain = params(p)?;
                read(Cmd::Status { out: JSON }, p.snapshot)
            }
            "log" => {
                let p: LogParams = params(p)?;
                read(Cmd::Log { limit: p.limit, out: JSON }, p.snapshot)
            }
            "diff" => {
                let p: DiffParams = params(p)?;
                if p.rev.is_some() && (p.from.is_some() || p.to.is_some()) {
                    return Err(RpcError::new(INVALID_PARAMS, "invalid params: `rev` cannot be used with `from` or `to`"));
                }
                read(Cmd::Diff { rev: p.rev, from: p.from, to: p.to, stat: p.stat, out: JSON }, p.snapshot)
            }
            "show" => {
                let p: ShowParams = params(p)?;
                read(Cmd::Show { rev: p.rev.unwrap_or_else(|| "@".into()), stat: p.stat, out: JSON }, p.snapshot)
            }
            "ws.list" | "workspace.list" => {
                let p: Plain = params(p)?;
                read(Cmd::Workspace(WsCmd::List { out: JSON }), p.snapshot)
            }
            "tag.list" => {
                let p: Plain = params(p)?;
                read(Cmd::Tag(TagCmd::List { out: JSON }), p.snapshot)
            }
            "op.log" => {
                let p: LogParams = params(p)?;
                read(Cmd::Op(OpCmd::Log { limit: p.limit.unwrap_or(20), out: JSON }), p.snapshot)
            }
            "scan" => {
                let p: ScanParams = params(p)?;
                match p.policy_from {
                    Some(f) => {
                        if p.snapshot.is_some() {
                            // As on the command line, the gate never snapshots.
                            return Err(RpcError::new(INVALID_PARAMS, "invalid params: a `policy_from` scan never snapshots"));
                        }
                        self.scan_gate(&f)
                    }
                    None => read(Cmd::Scan { policy_from: None, out: JSON }, p.snapshot),
                }
            }
            "secret.list" => {
                let p: Plain = params(p)?;
                read(Cmd::Secret(SecretCmd::List { out: JSON }), p.snapshot)
            }
            "snapshot" => {
                let _: NoParams = params(p)?;
                self.write(WriteOp::Snapshot, true)
            }
            "describe" => {
                let p: DescribeParams = params(p)?;
                self.write(WriteOp::Describe { rev: p.rev.unwrap_or_else(|| "@".into()), message: p.message }, self.snap(p.snapshot))
            }
            "new" => {
                let p: NewParams = params(p)?;
                self.write(WriteOp::New { revs: p.revs, message: p.message }, self.snap(p.snapshot))
            }
            "commit" => {
                let p: CommitParams = params(p)?;
                self.write(WriteOp::Commit { message: p.message, advance: !p.no_advance }, self.snap(p.snapshot))
            }
            "watch" => {
                let p: WatchParams = params(p)?;
                self.watch(p, client)
            }
            "unwatch" => {
                let _: NoParams = params(p)?;
                if let Some(w) = client.watch.take() {
                    w.end();
                }
                Ok(json(&WatchDoc { schema: WATCH_SCHEMA, watching: false, operation: None, interval_ms: None, working_copy: false }))
            }
            "server.info" => {
                let _: NoParams = params(p)?;
                Ok(json(&ServerInfo {
                    schema: SERVER_INFO_SCHEMA,
                    version: crate::cli::VERSION,
                    root: self.root.display().to_string(),
                    socket: socket_path(&self.root).display().to_string(),
                    pid: std::process::id(),
                    methods: METHODS,
                    max_request_bytes: MAX_REQUEST,
                    max_connections: MAX_CONNECTIONS,
                    max_batch: MAX_BATCH,
                }))
            }
            _ => Err(RpcError::new(METHOD_NOT_FOUND, format!("no method {}", json(&method)))),
        }
    }

    fn snap(&self, asked: Option<bool>) -> bool {
        asked.unwrap_or(self.snapshot_default)
    }

    fn serialise(&self) -> MutexGuard<'_, ()> {
        self.writes.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Open the repository as a `vl` process would, refusing what a bare
    /// repository cannot do.
    fn open(&self, snapshot: bool, runs_bare: bool) -> Result<Ctx> {
        let ctx = Ctx::open(Some(&self.root), snapshot)?;
        crate::refuse_bare(&ctx, runs_bare)?;
        Ok(ctx)
    }

    /// A read method: `cmd --json`, through the same `api` function.
    fn read(&self, cmd: Cmd, snapshot: Option<bool>) -> Result<String, RpcError> {
        let snapshot = self.snap(snapshot);
        let _serial = snapshot.then(|| self.serialise());
        let mut ctx = self.open(snapshot, crate::runs_in_a_bare_repository(&cmd))?;
        let doc = read_document(&ctx, &cmd)?;
        // Like the command: the directory follows the repository. A pure
        // read (no snapshot) never writes to the working copy.
        if snapshot {
            ctx.finish()?;
        }
        Ok(doc)
    }

    /// `scan` with `policy_from`: the CI gate, with a policy file that must
    /// lie inside the repository (and outside `.veil`).
    fn scan_gate(&self, file: &str) -> Result<String, RpcError> {
        let given = Path::new(file);
        let full = if given.is_absolute() { given.to_path_buf() } else { self.root.join(given) };
        let real = full.canonicalize().with_context(|| format!("reading the trusted policy {}", safe(file)))?;
        let inside = real.strip_prefix(&self.root).ok().filter(|r| !r.starts_with(VEIL_DIR) && real.is_file());
        if inside.is_none() {
            return Err(RpcError::new(
                INVALID_PARAMS,
                format!("invalid params: `policy_from` must name a file inside the repository ({})", self.root.display()),
            ));
        }
        Ok(json(&crate::scan_gate(&self.root, &real, file)?))
    }

    fn write(&self, w: WriteOp, snapshot: bool) -> Result<String, RpcError> {
        let _serial = self.serialise();
        let mut ctx = self.open(snapshot, false)?;
        let doc = match w {
            WriteOp::Snapshot => json(&api::recorded(&ctx)?),
            WriteOp::Describe { rev, message } => json(&api::describe(&mut ctx, &rev, &message)?),
            WriteOp::New { revs, message } => json(&api::new_change(&mut ctx, &revs, &message)?),
            WriteOp::Commit { message, advance } => json(&api::commit(&mut ctx, &message, advance)?),
        };
        ctx.finish()?;
        Ok(doc)
    }

    /// Subscribe this connection to `changed` notifications: one whenever
    /// the head of the operation log moves (any command, from any process).
    /// With `working_copy`, the server also snapshots the directory every
    /// interval, as `vl watch` does, so edits on disk become operations.
    fn watch(&self, p: WatchParams, client: &mut Client) -> Result<String, RpcError> {
        let interval = p.interval_ms.unwrap_or(500);
        if !(50..=60_000).contains(&interval) {
            return Err(RpcError::new(INVALID_PARAMS, "invalid params: `interval_ms` must be between 50 and 60000"));
        }
        if let Some(w) = client.watch.take() {
            w.end();
        }
        if p.working_copy {
            // A bare repository has no working copy to watch: say so now,
            // not on every tick.
            drop(self.open(false, false)?);
        }
        let ops = OpStore::new(Arc::new(DiskBackend::new(&self.root)));
        let head = ops.head().map_err(|e| RpcError::failed(e.into()))?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread = std::thread::Builder::new()
            .name("vl-serve-watch".into())
            .spawn({
                let stop = stop.clone();
                let writer = client.writer.clone();
                let server = client.server.clone();
                move || watch_loop(&server, ops, head, interval, p.working_copy, &stop, &writer)
            })
            .map_err(|e| RpcError::new(INTERNAL_ERROR, format!("starting the watch: {e}")))?;
        client.watch = Some(Watch { stop, thread });
        let op = api::OpRef { op_id: head.hex(), op_short: head.short() };
        Ok(json(&WatchDoc {
            schema: WATCH_SCHEMA,
            watching: true,
            operation: Some(op),
            interval_ms: Some(interval),
            working_copy: p.working_copy,
        }))
    }
}

fn watch_loop(
    server: &Server,
    ops: OpStore,
    mut head: veil_core::ObjectId,
    interval: u64,
    working_copy: bool,
    stop: &AtomicBool,
    writer: &Writer,
) {
    let mut ctx: Option<Ctx> = None;
    let mut behind_since = None;
    let mut last_error = String::new();
    let mut next = Instant::now() + Duration::from_millis(interval);
    while !stop.load(Ordering::SeqCst) && !server.stopping.load(Ordering::SeqCst) {
        if Instant::now() < next {
            std::thread::sleep(Duration::from_millis(interval.min(25)));
            continue;
        }
        next = Instant::now() + Duration::from_millis(interval);
        if working_copy {
            let _busy = Count::up(&server.in_flight);
            let _serial = server.serialise();
            let step = (|| -> Result<()> {
                let c = match ctx.as_mut() {
                    Some(c) => c,
                    None => ctx.insert(server.open(false, false)?),
                };
                crate::watch_step(c, &mut behind_since, interval)?;
                Ok(())
            })();
            match step {
                // Said once, not on every tick.
                Err(e) if format!("{e:#}") != last_error => {
                    last_error = format!("{e:#}");
                    warn(&format!("watch: {}", safe(&last_error)));
                    ctx = None;
                }
                Err(_) => ctx = None,
                Ok(()) => last_error.clear(),
            }
        }
        let Ok(now) = ops.head() else { continue };
        if now == head {
            continue;
        }
        head = now;
        let Ok(op) = ops.get(&now) else { continue };
        let entry = api::OpEntry {
            op_id: now.hex(),
            op_short: now.short(),
            timestamp: api::rfc3339(op.timestamp),
            user: op.user,
            description: op.description,
            timestamp_ms: op.timestamp,
        };
        let note = format!(
            "{{\"jsonrpc\":\"2.0\",\"method\":\"changed\",\"params\":{}}}",
            json(&Changed { schema: CHANGED_SCHEMA, operation: entry })
        );
        if send(writer, &note).is_err() {
            return;
        }
    }
}

/// The `--json` document of a read command: the same `api` call `vl`
/// makes for `cmd --json` (`dispatch` in `main.rs`).
fn read_document(ctx: &Ctx, cmd: &Cmd) -> Result<String> {
    match cmd {
        Cmd::Status { .. } => api::to_json(&api::status(ctx)?),
        Cmd::Log { limit, .. } => api::to_json(&api::log(&ctx.repo, &ctx.ws, *limit)?),
        Cmd::Show { rev, stat, .. } => api::to_json(&api::show(ctx, rev, *stat)?),
        Cmd::Diff { rev, from, to, stat, .. } => {
            let (a, b) = api::diff_trees_for(ctx, rev.as_deref(), from.as_deref(), to.as_deref())?;
            api::to_json(&api::diff(&ctx.repo, &a, &b, *stat)?)
        }
        Cmd::Workspace(WsCmd::List { .. }) => api::to_json(&api::workspace_list(&ctx.repo, &ctx.ws)),
        Cmd::Tag(TagCmd::List { .. }) => api::to_json(&api::tag_list(&ctx.repo)),
        Cmd::Op(OpCmd::Log { limit, .. }) => api::to_json(&api::op_log(&ctx.repo, *limit)?),
        Cmd::Scan { policy_from: None, .. } => api::to_json(&api::scan(ctx)?),
        Cmd::Secret(SecretCmd::List { .. }) => api::to_json(&api::secret_list(&ctx.repo)?),
        _ => unreachable!("not a read method"),
    }
}

// ---- the client ------------------------------------------------------------------------

/// A response, its result kept as the server's exact bytes.
#[derive(Deserialize)]
struct Response<'a> {
    #[serde(borrow)]
    result: Option<&'a RawValue>,
    error: Option<ResponseError<'a>>,
}

/// A notification, its params kept as sent.
#[derive(Deserialize)]
struct Notification<'a> {
    method: Option<String>,
    #[serde(borrow)]
    params: Option<&'a RawValue>,
}

#[derive(Deserialize)]
struct ResponseError<'a> {
    message: String,
    #[serde(borrow)]
    data: Option<&'a RawValue>,
}

/// Connect to the server of the repository at (or above) `repo_arg`,
/// checking that it runs as this user.
pub fn connect(repo_arg: Option<&Path>) -> Result<UnixStream> {
    let root = repo_root(repo_arg)?;
    let sock = socket_path(&root);
    let dir = local_dir(&root, false)?;
    let s = in_dir(&dir, || UnixStream::connect(SOCKET))
        .with_context(|| format!("connecting to {} (is `vl serve --local` running?)", sock.display()))?;
    if !peer_is(&s, euid()) {
        bail!("{} is served by another user: refusing to talk to it", sock.display());
    }
    Ok(s)
}

/// `vl serve --call METHOD [PARAMS]`: one request; the result on stdout,
/// exactly as the server sent it. For `watch`, then every notification's
/// params, one per line, until the server goes away.
pub fn call(repo_arg: Option<&Path>, method: &str, params: Option<&str>) -> Result<ExitCode> {
    let params: Value = match params {
        None => Value::Object(Default::default()),
        Some(p) => match serde_json::from_str(p) {
            Ok(v @ Value::Object(_)) => v,
            Ok(_) => bail!("PARAMS must be a JSON object, e.g. '{{\"limit\": 5}}'"),
            Err(e) => bail!("PARAMS is not JSON: {e}"),
        },
    };
    let mut s = connect(repo_arg)?;
    let req = serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
    let mut line = serde_json::to_string(&req)?;
    line.push('\n');
    s.write_all(line.as_bytes())?;
    let mut r = BufReader::new(s);
    let mut first = String::new();
    if r.read_line(&mut first)? == 0 {
        bail!("the server closed the connection without answering");
    }
    let resp: Response = serde_json::from_str(first.trim_end()).context("the server's answer is not a JSON-RPC response")?;
    if let Some(e) = resp.error {
        if let Some(d) = e.data {
            println!("{}", d.get());
        }
        bail!("{}", e.message);
    }
    let result = resp.result.ok_or_else(|| anyhow!("the server's answer has neither a result nor an error"))?;
    println!("{}", result.get());
    // `vl scan --json` exits 1 when something would be exposed; so does this.
    let failed_scan = serde_json::from_str::<Value>(result.get())
        .is_ok_and(|v| v["schema"] == api::SCAN_SCHEMA && v["clean"] == Value::Bool(false));
    if method == "watch" {
        let mut l = String::new();
        while r.read_line(&mut l)? > 0 {
            if let Ok(n) = serde_json::from_str::<Notification>(l.trim_end()) {
                if let (Some(_), Some(p)) = (n.method, n.params) {
                    println!("{}", p.get());
                }
            }
            if crate::render::stdout_closed() {
                break;
            }
            l.clear();
        }
    }
    Ok(if failed_scan { ExitCode::from(1) } else { ExitCode::SUCCESS })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_credentials_name_this_user() {
        let (a, b) = UnixStream::pair().unwrap();
        assert_eq!(peer_uid(&a).unwrap(), euid());
        assert!(peer_is(&b, euid()));
        // Anyone else is refused.
        assert!(!peer_is(&b, euid().wrapping_add(1)));
        assert!(!peer_is(&b, 0) || euid() == 0);
    }

    #[test]
    fn lines_are_capped_without_being_buffered() {
        let mut r = io::Cursor::new(b"{\"a\":1}\n\nxyz".to_vec());
        assert!(matches!(read_line(&mut r, 100).unwrap(), Line::Request(l) if l == b"{\"a\":1}"));
        assert!(matches!(read_line(&mut r, 100).unwrap(), Line::Request(l) if l.is_empty()));
        assert!(matches!(read_line(&mut r, 100).unwrap(), Line::Request(l) if l == b"xyz"));
        assert!(matches!(read_line(&mut r, 100).unwrap(), Line::Closed));
        let mut big = io::BufReader::with_capacity(16, io::Cursor::new(vec![b'x'; 1000]));
        assert!(matches!(read_line(&mut big, 100).unwrap(), Line::TooLong));
        let mut exact = io::Cursor::new([vec![b'x'; 100], b"\n".to_vec()].concat());
        assert!(matches!(read_line(&mut exact, 100).unwrap(), Line::Request(l) if l.len() == 100));
    }

    #[test]
    fn errors_are_json_rpc_errors() {
        let l = error_line("7", INVALID_PARAMS, "bad \"x\"\u{1b}", Some("{\"schema\":\"veil.error/1\"}"));
        let v: Value = serde_json::from_str(&l).unwrap();
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["id"], 7);
        assert_eq!(v["error"]["code"], INVALID_PARAMS);
        assert_eq!(v["error"]["message"], "bad \"x\"\u{1b}");
        assert_eq!(v["error"]["data"]["schema"], "veil.error/1");
        assert!(!l.contains('\u{1b}'));
    }

    #[test]
    fn every_method_is_listed_once() {
        let mut m = METHODS.to_vec();
        m.sort();
        m.dedup();
        assert_eq!(m.len(), METHODS.len());
    }
}
