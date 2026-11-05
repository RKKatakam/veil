//! [`SftpBackend`]: a repository on any machine reachable over SSH.
//!
//! This is a "dumb" transport in the style of restic or borg: the server
//! only needs SSH and its `sftp` subsystem, no `vl`. Every remote is a
//! [`StorageBackend`], so push, pull and clone work unchanged; cloaked
//! content is already encrypted before it leaves the client.
//!
//! **The user's own `ssh`.** The backend runs the system `ssh` binary
//! (`ssh … -s -- host sftp`, the way `sftp(1)` does) and speaks SFTP over
//! its stdin/stdout, so `~/.ssh/config`, the agent, `known_hosts`,
//! ProxyJump, ControlMaster and hardware keys all work exactly as they do
//! for `git` or `sftp`. `VEIL_SSH` replaces the `ssh` command (split on
//! whitespace, like a simple `GIT_SSH_COMMAND`).
//!
//! **Atomicity and durability**, mapped onto SFTP:
//!
//! | `StorageBackend` | SFTP |
//! |---|---|
//! | `write` | temp file (`O_EXCL`), writes, `fsync@openssh.com`, close, `posix-rename@openssh.com` |
//! | `write_unsynced` | the same without the fsync; the path is queued for the barrier |
//! | `sync_barrier` | open + `fsync@openssh.com` + close of every queued file, all pipelined |
//! | `create_new` | durable temp file, then `hardlink@openssh.com` (fails if the target exists); without it, `OPEN` with `CREAT|EXCL` |
//! | `read` / `read_range` | pipelined `READ`s of up to 255 KiB, short reads re-requested |
//!
//! SFTP cannot fsync a directory, so a rename is as durable as the
//! server's file system makes it after the file itself was synced. A server
//! without `fsync@openssh.com` gives no durability guarantee at all, and
//! one without `posix-rename@openssh.com` replaces files by remove plus
//! rename (a reader can briefly find the file missing). OpenSSH has all of
//! these extensions.
//!
//! Errors: "no such file" is [`VeilError::NotFound`] like everywhere
//! else; other statuses become [`VeilError::Io`] with a matching
//! [`std::io::ErrorKind`]; a dead connection is `ConnectionAborted`.
//!
//! **Limits** (BUG-065, BUG-066). The server is not trusted to be finite or
//! responsive. [`SftpOptions`] holds the limits; the environment overrides
//! the defaults:
//!
//! | limit | default | override |
//! |---|---|---|
//! | request timeout (see `sftp_client.rs`; also the handshake) | 300 s | `VEIL_SFTP_TIMEOUT` (seconds) |
//! | one file read: the size the server stated plus [`READ_SLACK`], and never more than | 4 GiB | `VEIL_SFTP_MAX_FILE` (bytes, or `K`/`M`/`G` suffix) |
//! | one directory listing | 1,000,000 entries, [`MAX_LISTING_BYTES`] of names | `VEIL_SFTP_MAX_LISTING` (entries) |
//! | one packet from the server | 1 MiB (`MAX_PACKET`) | – |
//! | replies to requests never made | 16 per connection (`MAX_STRAY`) | – |
//!
//! A read stops, and fails with `InvalidData`, as soon as the data passes
//! its limit; a listing likewise. The stated size is only a hint (a file
//! replaced between the stat and the open is read to its end), so a file
//! may outgrow it by [`READ_SLACK`]: Veil's mutable files (operation head,
//! lock, configuration, key rings) are small, and packs and objects never
//! change. `read_range` reads exactly what was asked, which callers derive
//! from pack indexes, and is held to the same ceiling.

use std::{
    collections::{HashSet, VecDeque},
    io::{self, Read, Write},
    process::{Child, Command, Stdio},
    sync::Mutex,
    time::Duration,
};

use super::{
    sftp_client::{
        io_error, Attrs, Client, FileType, Pending, Reply, FXF_CREAT, FXF_EXCL,
        FXF_READ, FXF_TRUNC, FXF_WRITE, FXP_CLOSE, FXP_EXTENDED, FXP_LSTAT, FXP_MKDIR, FXP_OPEN, FXP_OPENDIR,
        FXP_READ, FXP_READDIR, FXP_REMOVE, FXP_RENAME, FXP_RMDIR, FXP_SETSTAT, FXP_WRITE, FX_EOF, FX_NO_SUCH_FILE,
    },
    sftp_url::SshUrl,
    parse_size, DirEntry, Metadata, NodeKind, StorageBackend,
};
pub use super::sftp_client::SftpStats;
use crate::{
    error::{Result, VeilError},
    vpath::VPath,
};

/// Requests one operation keeps in flight (reads, writes, fsyncs).
const WINDOW: usize = 64;
/// How long a request may go unanswered (see `sftp_client.rs`) by default.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(300);
/// Largest file one `read` accepts by default.
pub const DEFAULT_MAX_FILE: u64 = 4 << 30;
/// Most entries one directory listing accepts by default. A repository's
/// largest directories are its pack directory (two files per push) and its
/// loose-object fan-out directories.
pub const DEFAULT_MAX_LISTING: usize = 1_000_000;
/// How much longer than the server said a file read by `read` may turn
/// out to be (it was replaced between the stat and the open).
pub const READ_SLACK: u64 = 16 << 20;
/// Most bytes of names one directory listing accepts.
pub const MAX_LISTING_BYTES: u64 = 256 << 20;
/// Empty `READDIR` batches in a row accepted before a listing fails.
const MAX_EMPTY_BATCHES: u32 = 4;
/// Deepest directory tree `remove_dir_all` descends into.
const MAX_REMOVE_DEPTH: usize = 256;

/// Limits and timing of an SFTP connection (see the module documentation).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SftpOptions {
    /// A request unanswered for this long fails and closes the connection.
    pub timeout: Duration,
    /// Largest file one read accepts.
    pub max_file: u64,
    /// Most entries one directory listing accepts.
    pub max_listing: usize,
}

impl Default for SftpOptions {
    fn default() -> Self {
        SftpOptions {
            timeout: DEFAULT_TIMEOUT,
            max_file: DEFAULT_MAX_FILE,
            max_listing: DEFAULT_MAX_LISTING,
        }
    }
}

impl SftpOptions {
    /// The defaults, overridden by `VEIL_SFTP_TIMEOUT`, `VEIL_SFTP_MAX_FILE`
    /// and `VEIL_SFTP_MAX_LISTING`.
    pub fn from_env() -> Result<SftpOptions> {
        let var = |name: &str| std::env::var(name).ok().filter(|v| !v.trim().is_empty());
        let bad = |name: &str, v: &str, what: &str| VeilError::repo(format!("{name}={v:?}: expected {what}"));
        let mut o = SftpOptions::default();
        if let Some(v) = var("VEIL_SFTP_TIMEOUT") {
            o.timeout = v
                .trim()
                .parse::<f64>()
                .ok()
                .filter(|s| *s > 0.0)
                .and_then(|s| Duration::try_from_secs_f64(s).ok())
                .ok_or_else(|| bad("VEIL_SFTP_TIMEOUT", &v, "a positive number of seconds"))?;
        }
        if let Some(v) = var("VEIL_SFTP_MAX_FILE") {
            o.max_file = parse_size(&v).ok_or_else(|| bad("VEIL_SFTP_MAX_FILE", &v, "a size such as 8G"))?;
        }
        if let Some(v) = var("VEIL_SFTP_MAX_LISTING") {
            o.max_listing = v
                .trim()
                .parse::<usize>()
                .ok()
                .filter(|n| *n > 0)
                .ok_or_else(|| bad("VEIL_SFTP_MAX_LISTING", &v, "a number of entries"))?;
        }
        Ok(o)
    }
}

/// The error for a read or listing that passed one of the limits.
fn too_big(path: &str, what: String) -> VeilError {
    io_error(path, io::Error::new(io::ErrorKind::InvalidData, format!("sftp: {what}")))
}

fn fmt_bytes(n: u64) -> String {
    const UNITS: [(u64, &str); 4] = [(1 << 40, "TiB"), (1 << 30, "GiB"), (1 << 20, "MiB"), (1 << 10, "KiB")];
    for (size, unit) in UNITS {
        if n >= size {
            return if n.is_multiple_of(size) {
                format!("{} {unit}", n / size)
            } else {
                format!("{:.1} {unit}", n as f64 / size as f64)
            };
        }
    }
    format!("{n} bytes")
}

pub struct SftpBackend {
    client: Client,
    opts: SftpOptions,
    /// Directory on the server, without a trailing `/` (`""`: the login
    /// directory, `"/"`: the server root).
    root: String,
    label: String,
    unsynced: Mutex<Vec<String>>,
    barrier: Mutex<()>,
    /// Directories known to exist, to skip `mkdir` round trips.
    dirs: Mutex<HashSet<String>>,
    child: Mutex<Option<Child>>,
}

impl std::fmt::Debug for SftpBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SftpBackend")
            .field("remote", &self.label)
            .field("extensions", &self.client.ext)
            .finish_non_exhaustive()
    }
}

fn conn_err(what: &str, e: io::Error) -> VeilError {
    io_error(what, e)
}

/// The `ssh` command to run: `$VEIL_SSH` (split on whitespace) or `ssh`.
fn ssh_command() -> Command {
    let spec = std::env::var("VEIL_SSH").ok().filter(|s| !s.trim().is_empty());
    let spec = spec.as_deref().unwrap_or("ssh");
    let mut parts = spec.split_whitespace();
    let mut cmd = Command::new(parts.next().unwrap_or("ssh"));
    cmd.args(parts);
    cmd
}

impl SftpBackend {
    /// Connect to `url` with the user's `ssh`.
    pub fn connect(url: &SshUrl) -> Result<SftpBackend> {
        let mut cmd = ssh_command();
        cmd.args(url.ssh_args());
        let label = url.to_string();
        Self::spawn(cmd, &url.path, &label)
    }

    /// Run `cmd`, which must speak SFTP on its stdin/stdout (`ssh -s host
    /// sftp`, or a local `sftp-server` in tests), and use `root` on that
    /// server. The command's stderr is inherited, so `ssh` can report
    /// authentication problems and ask for passwords on the terminal.
    pub fn spawn(mut cmd: Command, root: &str, label: &str) -> Result<SftpBackend> {
        let opts = SftpOptions::from_env()?;
        cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit());
        let program = cmd.get_program().to_string_lossy().into_owned();
        let mut child = cmd.spawn().map_err(|e| conn_err(&program, e))?;
        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");
        match Self::from_streams_with(stdout, stdin, root, label, opts) {
            Ok(b) => {
                *b.child.lock().unwrap() = Some(child);
                Ok(b)
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                Err(e)
            }
        }
    }

    /// Speak SFTP over an existing pair of streams (`reader` carries the
    /// server's replies). Used by tests to interpose latency or faults.
    pub fn from_streams(
        reader: impl Read + Send + 'static,
        writer: impl Write + Send + 'static,
        root: &str,
        label: &str,
    ) -> Result<SftpBackend> {
        Self::from_streams_with(reader, writer, root, label, SftpOptions::from_env()?)
    }

    /// [`SftpBackend::from_streams`] with explicit limits and timeout.
    pub fn from_streams_with(
        reader: impl Read + Send + 'static,
        writer: impl Write + Send + 'static,
        root: &str,
        label: &str,
        opts: SftpOptions,
    ) -> Result<SftpBackend> {
        let client = Client::start(Box::new(reader), Box::new(io::BufWriter::new(writer)), opts.timeout)
            .map_err(|e| conn_err(label, e))?;
        let root = if root == "/" {
            "/".to_string()
        } else {
            root.trim_end_matches('/').to_string()
        };
        Ok(SftpBackend {
            client,
            opts,
            root,
            label: label.to_string(),
            unsynced: Mutex::default(),
            barrier: Mutex::default(),
            dirs: Mutex::default(),
            child: Mutex::default(),
        })
    }

    /// Request counters since the connection was opened.
    pub fn stats(&self) -> SftpStats {
        self.client.stats()
    }

    /// Whether the server supports durable writes (`fsync@openssh.com`).
    pub fn durable(&self) -> bool {
        self.client.ext.fsync
    }

    fn rp(&self, p: &VPath) -> String {
        match (self.root.as_str(), p.is_root()) {
            ("", true) => ".".into(),
            (r, true) => r.into(),
            ("", false) => p.as_str().into(),
            ("/", false) => format!("/{}", p.as_str()),
            (r, false) => format!("{r}/{}", p.as_str()),
        }
    }

    fn send(&self, path: &str, kind: u8, build: impl FnOnce(&mut super::sftp_client::Body)) -> Result<Pending> {
        self.client.send(kind, build).map_err(|e| io_error(path, e))
    }

    fn wait(&self, path: &str, p: Pending) -> Result<Reply> {
        p.wait().map_err(|e| io_error(path, e))
    }

    fn call(&self, path: &str, kind: u8, build: impl FnOnce(&mut super::sftp_client::Body)) -> Result<Reply> {
        let p = self.send(path, kind, build)?;
        self.wait(path, p)
    }

    fn lstat(&self, path: &str) -> Result<Option<Attrs>> {
        match self.call(path, FXP_LSTAT, |b| {
            b.str(path);
        })? {
            Reply::Status(FX_NO_SUCH_FILE, _) => Ok(None),
            r => r.attrs(path).map(Some),
        }
    }

    fn open(&self, path: &str, flags: u32) -> Result<Pending> {
        self.send(path, FXP_OPEN, |b| {
            b.str(path).u32(flags).no_attrs();
        })
    }

    /// Close without waiting for the reply (reads only: nothing depends on
    /// the close having happened).
    fn close_detached(&self, path: &str, handle: &[u8]) {
        let _ = self.send(path, FXP_CLOSE, |b| {
            b.bytes(handle);
        });
    }

    fn close(&self, path: &str, handle: &[u8]) -> Result<()> {
        self.call(path, FXP_CLOSE, |b| {
            b.bytes(handle);
        })?
        .ok(path)
    }

    /// Read `[offset, offset + len)` (`exact`), or from `offset` to the end
    /// of the file with `len` as a size hint, failing once more than `limit`
    /// bytes arrive. Up to [`WINDOW`] reads are in flight; short reads are
    /// re-requested. Data goes straight into the result buffer, which never
    /// grows past `limit`.
    fn read_handle(
        &self,
        path: &str,
        handle: &[u8],
        offset: u64,
        len: u64,
        exact: bool,
        limit: u64,
    ) -> Result<Vec<u8>> {
        let bad = |m: &str| io_error(path, io::Error::new(io::ErrorKind::InvalidData, format!("sftp: {m}")));
        let chunk = u64::from(self.client.max_read);
        let end = offset.checked_add(len).ok_or_else(|| bad("read range overflows"))?;
        // Past `cap` is too much: the requested end when exact, else the limit.
        let cap = if exact { end } else { offset.saturating_add(limit) };
        // Short-read remainders, served before new ranges.
        let mut retry: VecDeque<(u64, u64)> = VecDeque::new();
        // Next offset to ask for. Until EOF, the reader probes past the
        // expected end (two requests at a time), so a file that is longer
        // than its size hint is still read completely, up to `cap`; one
        // probe past `cap` shows whether the file goes on.
        let mut next = offset;
        let mut eof: Option<u64> = if exact { Some(end) } else { None };
        // The size is the server's word: reserve it if the system lets us,
        // else grow as data actually arrives.
        let mut out: Vec<u8> = Vec::new();
        let _ = out.try_reserve_exact(len.min(limit) as usize);
        // Every piece placed: (offset, length). They never overlap.
        let mut pieces: Vec<(u64, u64)> = Vec::new();
        let mut inflight: VecDeque<(u64, u64, Pending)> = VecDeque::new();
        loop {
            while inflight.len() < WINDOW {
                let (o, n) = if let Some(r) = retry.pop_front() {
                    r
                } else if next < end {
                    let n = chunk.min(end - next);
                    (next, n)
                } else if eof.is_none() && inflight.len() < 2 && next <= cap {
                    (next, chunk)
                } else {
                    break;
                };
                if o >= next {
                    next = o + n;
                }
                if eof.is_some_and(|e| o >= e) {
                    continue;
                }
                let p = self.send(path, FXP_READ, |b| {
                    b.bytes(handle).u64(o).u32(n as u32);
                })?;
                inflight.push_back((o, n, p));
            }
            let Some((o, n, p)) = inflight.pop_front() else { break };
            match self.wait(path, p)? {
                Reply::Data(d) if d.is_empty() || d.len() as u64 > n => return Err(bad("bad read reply")),
                Reply::Data(d) => {
                    let k = d.len() as u64;
                    if o + k > cap {
                        return Err(too_big(
                            path,
                            format!(
                                "the server sent more than {} for this file (limit: the size it stated plus {}, at most {}; VEIL_SFTP_MAX_FILE raises it)",
                                fmt_bytes(cap - offset),
                                fmt_bytes(READ_SLACK),
                                fmt_bytes(self.opts.max_file)
                            ),
                        ));
                    }
                    let at = (o - offset) as usize;
                    if out.len() < at + d.len() {
                        out.resize(at + d.len(), 0);
                    }
                    out[at..at + d.len()].copy_from_slice(&d);
                    pieces.push((o, k));
                    if k < n {
                        retry.push_front((o + k, n - k));
                    }
                }
                Reply::Status(FX_EOF, _) => {
                    if exact {
                        return Err(io_error(
                            path,
                            io::Error::new(io::ErrorKind::UnexpectedEof, "read past the end of the file"),
                        ));
                    }
                    eof = Some(eof.map_or(o, |e| e.min(o)));
                }
                r => return Err(r.ok(path).err().unwrap_or_else(|| io_error(path, io::Error::other("bad reply")))),
            }
        }
        let stop = eof.unwrap_or(end);
        // Pieces are disjoint, so the bytes they cover below `stop` add up
        // to its distance from `offset` exactly when nothing is missing.
        let covered: u64 = pieces
            .iter()
            .map(|&(o, k)| (o + k).min(stop).saturating_sub(o.min(stop)))
            .sum();
        if covered != stop - offset {
            return Err(io_error(path, io::Error::new(io::ErrorKind::UnexpectedEof, "sftp: short read")));
        }
        out.truncate((stop - offset) as usize);
        Ok(out)
    }

    /// Write `data` into an open handle, every write in flight at once
    /// (within the window), and wait for all of them.
    fn write_handle(&self, path: &str, handle: &[u8], data: &[u8]) -> Result<()> {
        let chunk = self.client.max_write as usize;
        let mut inflight: VecDeque<Pending> = VecDeque::new();
        let mut first_err = None;
        for (i, part) in data.chunks(chunk).enumerate() {
            if inflight.len() >= WINDOW {
                let p = inflight.pop_front().unwrap();
                if let Err(e) = self.wait(path, p).and_then(|r| r.ok(path)) {
                    first_err.get_or_insert(e);
                }
            }
            if first_err.is_some() {
                break;
            }
            inflight.push_back(self.send(path, FXP_WRITE, |b| {
                b.bytes(handle).u64((i * chunk) as u64).bytes(part);
            })?);
        }
        for p in inflight {
            if let Err(e) = self.wait(path, p).and_then(|r| r.ok(path)) {
                first_err.get_or_insert(e);
            }
        }
        first_err.map_or(Ok(()), Err)
    }

    fn fsync_handle(&self, path: &str, handle: &[u8]) -> Result<()> {
        if !self.client.ext.fsync {
            return Ok(());
        }
        self.call(path, FXP_EXTENDED, |b| {
            b.str("fsync@openssh.com").bytes(handle);
        })?
        .ok(path)
    }

    fn remove(&self, path: &str) -> Result<()> {
        match self.call(path, FXP_REMOVE, |b| {
            b.str(path);
        })? {
            Reply::Status(FX_NO_SUCH_FILE, _) => Ok(()),
            r => r.ok(path),
        }
    }

    fn mkdir_all(&self, path: &str) -> Result<()> {
        if path.is_empty() || path == "." || path == "/" || self.dirs.lock().unwrap().contains(path) {
            return Ok(());
        }
        let mkdir = || {
            self.call(path, FXP_MKDIR, |b| {
                b.str(path).no_attrs();
            })
        };
        let mut r = mkdir()?;
        if matches!(r, Reply::Status(FX_NO_SUCH_FILE, _)) {
            if let Some((parent, _)) = path.rsplit_once('/') {
                self.mkdir_all(if parent.is_empty() { "/" } else { parent })?;
                r = mkdir()?;
            }
        }
        if let Err(e) = r.ok(path) {
            // Usually "already exists" (a plain failure in version 3).
            match self.lstat(path)? {
                Some(a) if a.file_type() == FileType::Dir => {}
                _ => return Err(e),
            }
        }
        self.dirs.lock().unwrap().insert(path.to_string());
        Ok(())
    }

    fn parent_of(path: &str) -> Option<&str> {
        match path.rsplit_once('/') {
            Some(("", _)) => Some("/"),
            Some((p, _)) => Some(p),
            None => None,
        }
    }

    fn temp_name(path: &str) -> String {
        let (dir, name) = match path.rsplit_once('/') {
            Some((d, n)) => (Some(d), n),
            None => (None, path),
        };
        let t = format!(".{name}.vltmp{}", hex::encode(crate::crypto::random_bytes::<4>()));
        match dir {
            Some(d) => format!("{d}/{t}"),
            None => t,
        }
    }

    /// Open `path` with `flags`, creating missing parent directories once.
    fn open_creating(&self, path: &str, flags: u32) -> Result<std::result::Result<Vec<u8>, Reply>> {
        let p = self.open(path, flags)?;
        match self.wait(path, p)? {
            Reply::Handle(h) => Ok(Ok(h)),
            Reply::Status(FX_NO_SUCH_FILE, _) if Self::parent_of(path).is_some() => {
                self.mkdir_all(Self::parent_of(path).unwrap())?;
                let p = self.open(path, flags)?;
                match self.wait(path, p)? {
                    Reply::Handle(h) => Ok(Ok(h)),
                    r => Ok(Err(r)),
                }
            }
            r => Ok(Err(r)),
        }
    }

    /// One exclusive create of `path`: `Ok(Ok(true))` if it was created,
    /// `Ok(Err(e))` if the server refused (often because it exists).
    fn try_create_new(&self, path: &str, data: &[u8]) -> Result<std::result::Result<bool, VeilError>> {
        if self.client.ext.hardlink {
            // Never expose a partly written file: the content is complete
            // and synced before the link makes it visible.
            let tmp = self.write_temp(path, data, true)?;
            let linked = self.call(path, FXP_EXTENDED, |b| {
                b.str("hardlink@openssh.com").str(&tmp).str(path);
            });
            let _ = self.remove(&tmp);
            return Ok(linked?.ok(path).map(|()| true));
        }
        let h = match self.open_creating(path, FXF_WRITE | FXF_CREAT | FXF_EXCL)? {
            Ok(h) => h,
            Err(r) => return Ok(Err(r.ok(path).err().unwrap_or_else(|| io_error(path, io::Error::other("open failed"))))),
        };
        let res = self.write_handle(path, &h, data).and_then(|()| self.fsync_handle(path, &h));
        let closed = self.close(path, &h);
        res.and(closed).map(|()| Ok(true))
    }

    /// Write `data` to a fresh temp file next to `path` (synced if
    /// `durable`) and return the temp file's name.
    fn write_temp(&self, path: &str, data: &[u8], durable: bool) -> Result<String> {
        let tmp = Self::temp_name(path);
        let h = match self.open_creating(&tmp, FXF_WRITE | FXF_CREAT | FXF_EXCL | FXF_TRUNC)? {
            Ok(h) => h,
            Err(r) => return Err(r.ok(path).err().unwrap_or_else(|| io_error(path, io::Error::other("open failed")))),
        };
        let res = self
            .write_handle(&tmp, &h, data)
            .and_then(|()| if durable { self.fsync_handle(&tmp, &h) } else { Ok(()) });
        let closed = self.close(&tmp, &h);
        if let Err(e) = res.and(closed) {
            let _ = self.remove(&tmp);
            return Err(e);
        }
        Ok(tmp)
    }

    fn rename_over(&self, from: &str, to: &str) -> Result<()> {
        if self.client.ext.posix_rename {
            return self
                .call(to, FXP_EXTENDED, |b| {
                    b.str("posix-rename@openssh.com").str(from).str(to);
                })?
                .ok(to);
        }
        let rename = || {
            self.call(to, FXP_RENAME, |b| {
                b.str(from).str(to);
            })
        };
        // Version-3 rename refuses an existing target: remove it first
        // (not atomic; only servers without posix-rename get here).
        match rename()?.ok(to) {
            Ok(()) => Ok(()),
            Err(_) => {
                self.remove(to)?;
                rename()?.ok(to)
            }
        }
    }

    fn put(&self, p: &VPath, data: &[u8], durable: bool) -> Result<()> {
        if p.is_root() {
            return Err(VeilError::InvalidPath("cannot write to the root".into()));
        }
        let path = self.rp(p);
        let tmp = self.write_temp(&path, data, durable)?;
        if let Err(e) = self.rename_over(&tmp, &path) {
            let _ = self.remove(&tmp);
            return Err(e);
        }
        if !durable && self.client.ext.fsync {
            self.unsynced.lock().unwrap().push(path);
        }
        Ok(())
    }

    /// Raw directory listing (names other than `.` and `..`), failing once
    /// it passes [`SftpOptions::max_listing`] entries or
    /// [`MAX_LISTING_BYTES`] of names.
    fn readdir(&self, path: &str) -> Result<Vec<(String, Attrs)>> {
        let p = self.send(path, FXP_OPENDIR, |b| {
            b.str(path);
        })?;
        let h = self.wait(path, p)?.handle(path)?;
        let mut out = Vec::new();
        let (mut entries, mut bytes, mut empty) = (0usize, 0u64, 0u32);
        let res = loop {
            match self.call(path, FXP_READDIR, |b| {
                b.bytes(&h);
            }) {
                Ok(Reply::Name(names)) if names.is_empty() => {
                    // Not EOF, and no progress either: tolerated a few times.
                    empty += 1;
                    if empty > MAX_EMPTY_BATCHES {
                        break Err(too_big(path, "the server keeps sending empty directory batches".into()));
                    }
                }
                Ok(Reply::Name(names)) => {
                    empty = 0;
                    entries += names.len();
                    bytes += names.iter().map(|(n, _)| n.len() as u64).sum::<u64>();
                    if entries > self.opts.max_listing || bytes > MAX_LISTING_BYTES {
                        break Err(too_big(
                            path,
                            format!(
                                "directory listing passed {} entries or {} of names (VEIL_SFTP_MAX_LISTING raises the entry limit)",
                                self.opts.max_listing,
                                fmt_bytes(MAX_LISTING_BYTES)
                            ),
                        ));
                    }
                    out.extend(names.into_iter().filter(|(n, _)| n != "." && n != ".."));
                }
                Ok(Reply::Status(FX_EOF, _)) => break Ok(()),
                Ok(r) => break r.ok(path),
                Err(e) => break Err(e),
            }
        };
        self.close_detached(path, &h);
        res.map(|()| out)
    }

    /// Kind of each entry, asking the server (many requests in flight) for
    /// entries whose listing carried no permissions.
    fn typed(&self, dir: &str, entries: Vec<(String, Attrs)>) -> Result<Vec<(String, FileType)>> {
        let mut out: Vec<(String, FileType)> = entries.into_iter().map(|(n, a)| (n, a.file_type())).collect();
        let unknown: Vec<usize> = (0..out.len()).filter(|&i| out[i].1 == FileType::Unknown).collect();
        for group in unknown.chunks(WINDOW) {
            let asked = group
                .iter()
                .map(|&i| {
                    let child = format!("{dir}/{}", out[i].0);
                    let p = self.send(&child, FXP_LSTAT, |b| {
                        b.str(&child);
                    })?;
                    Ok((i, child, p))
                })
                .collect::<Result<Vec<_>>>()?;
            for (i, child, p) in asked {
                out[i].1 = match self.wait(&child, p)? {
                    Reply::Status(FX_NO_SUCH_FILE, _) => FileType::Unknown,
                    r => r.attrs(&child)?.file_type(),
                };
            }
        }
        Ok(out)
    }

    fn remove_tree(&self, path: &str, depth: usize) -> Result<()> {
        if depth > MAX_REMOVE_DEPTH || path.len() > 4096 {
            return Err(too_big(path, format!("directory tree deeper than {MAX_REMOVE_DEPTH} levels")));
        }
        let entries = self.readdir(path)?;
        let entries = self.typed(path, entries)?;
        let mut pending = Vec::new();
        for (name, t) in entries {
            let child = format!("{path}/{name}");
            if t == FileType::Dir {
                self.remove_tree(&child, depth + 1)?;
            } else {
                pending.push((
                    child.clone(),
                    self.send(&child, FXP_REMOVE, |b| {
                        b.str(&child);
                    })?,
                ));
            }
        }
        for (child, p) in pending {
            match self.wait(&child, p)? {
                Reply::Status(FX_NO_SUCH_FILE, _) => {}
                r => r.ok(&child)?,
            }
        }
        self.dirs.lock().unwrap().retain(|d| d != path && !d.starts_with(&format!("{path}/")));
        match self.call(path, FXP_RMDIR, |b| {
            b.str(path);
        })? {
            Reply::Status(FX_NO_SUCH_FILE, _) => Ok(()),
            r => r.ok(path),
        }
    }
}

impl Drop for SftpBackend {
    fn drop(&mut self) {
        self.client.close();
        if let Some(mut child) = self.child.lock().unwrap_or_else(|e| e.into_inner()).take() {
            // ssh (or sftp-server) exits once its stdin is closed.
            for _ in 0..100 {
                if let Ok(Some(_)) = child.try_wait() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl StorageBackend for SftpBackend {
    fn kind(&self) -> &'static str {
        "sftp"
    }

    fn is_network(&self) -> bool {
        true
    }

    fn read(&self, p: &VPath) -> Result<Vec<u8>> {
        let path = self.rp(p);
        // Stat and open in one round trip; then all reads in the next.
        let st = self.send(&path, FXP_LSTAT, |b| {
            b.str(&path);
        })?;
        let op = self.open(&path, FXF_READ)?;
        let st = self.wait(&path, st);
        let op = self.wait(&path, op)?;
        let handle = match op {
            Reply::Handle(h) => h,
            r => {
                return Err(r
                    .ok(&path)
                    .err()
                    .unwrap_or_else(|| io_error(&path, io::Error::other("open failed"))))
            }
        };
        let res = (|| {
            let size = match st? {
                Reply::Attrs(a) => match a.file_type() {
                    // Symlinks are invisible, as on disk.
                    FileType::Special => return Err(VeilError::NotFound(path.clone())),
                    FileType::Dir => {
                        return Err(io_error(&path, io::Error::other("is a directory")));
                    }
                    _ => a.size.unwrap_or(0),
                },
                // Replaced between the stat and the open: read to the end.
                _ => 0,
            };
            if size > self.opts.max_file {
                return Err(too_big(
                    &path,
                    format!(
                        "the server says this file is {}, more than the {} limit (VEIL_SFTP_MAX_FILE raises it)",
                        fmt_bytes(size),
                        fmt_bytes(self.opts.max_file)
                    ),
                ));
            }
            let limit = size.saturating_add(READ_SLACK).min(self.opts.max_file);
            self.read_handle(&path, &handle, 0, size, false, limit)
        })();
        self.close_detached(&path, &handle);
        res
    }

    fn read_range(&self, p: &VPath, offset: u64, len: usize) -> Result<Vec<u8>> {
        let path = self.rp(p);
        if len as u64 > self.opts.max_file {
            return Err(too_big(
                &path,
                format!(
                    "a read of {} is more than the {} limit (VEIL_SFTP_MAX_FILE raises it)",
                    fmt_bytes(len as u64),
                    fmt_bytes(self.opts.max_file)
                ),
            ));
        }
        let op = self.open(&path, FXF_READ)?;
        let handle = self.wait(&path, op)?.handle(&path)?;
        let res = if len == 0 {
            Ok(Vec::new())
        } else {
            self.read_handle(&path, &handle, offset, len as u64, true, len as u64)
        };
        self.close_detached(&path, &handle);
        res
    }

    fn write(&self, p: &VPath, data: &[u8]) -> Result<()> {
        self.put(p, data, true)
    }

    fn write_unsynced(&self, p: &VPath, data: &[u8]) -> Result<()> {
        self.put(p, data, false)
    }

    /// One `posix-rename@openssh.com` (after creating `to`'s directory):
    /// a push publishes its staged packs this way, without copying them.
    /// SFTP cannot sync a directory; the content was synced when written.
    fn rename_unsynced(&self, from: &VPath, to: &VPath) -> Result<()> {
        let (from, to) = (self.rp(from), self.rp(to));
        if let Some(parent) = Self::parent_of(&to) {
            self.mkdir_all(parent)?;
        }
        self.rename_over(&from, &to)
    }

    fn sync_barrier(&self) -> Result<()> {
        let _serial = self.barrier.lock().unwrap_or_else(|e| e.into_inner());
        let batch = std::mem::take(&mut *self.unsynced.lock().unwrap());
        if batch.is_empty() {
            return Ok(());
        }
        let res = (|| {
            for group in batch.chunks(WINDOW) {
                let opens = group
                    .iter()
                    .map(|f| self.open(f, FXF_READ).map(|p| (f, p)))
                    .collect::<Result<Vec<_>>>()?;
                let mut handles = Vec::new();
                for (f, p) in opens {
                    match self.wait(f, p)? {
                        Reply::Handle(h) => handles.push((f, h)),
                        // Removed since (gc, crash recovery): nothing to sync.
                        Reply::Status(FX_NO_SUCH_FILE, _) => {}
                        r => r.ok(f)?,
                    }
                }
                let syncs = handles
                    .iter()
                    .map(|(f, h)| {
                        self.send(f, FXP_EXTENDED, |b| {
                            b.str("fsync@openssh.com").bytes(h);
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                let mut first_err = None;
                for ((f, _), p) in handles.iter().zip(syncs) {
                    if let Err(e) = self.wait(f, p).and_then(|r| r.ok(f)) {
                        first_err.get_or_insert(e);
                    }
                }
                for (f, h) in &handles {
                    self.close_detached(f, h);
                }
                if let Some(e) = first_err {
                    return Err(e);
                }
            }
            Ok(())
        })();
        if res.is_err() {
            // As on disk: retried later, but the caller must rewrite or
            // remove what failed (a retried fsync may prove nothing).
            self.unsynced.lock().unwrap().extend(batch);
        }
        res
    }

    fn create_new(&self, p: &VPath, data: &[u8]) -> Result<bool> {
        if p.is_root() {
            return Err(VeilError::InvalidPath("cannot write to the root".into()));
        }
        let path = self.rp(p);
        // SFTP version 3 reports "exists" as a plain failure, so a failed
        // create is told apart by looking. A file that existed when the
        // create failed may be gone when we look (a lock released in
        // between): that is a lost race, tried again a few times, not an
        // error (BUG-120: brief locks made it common).
        let mut attempts = 0;
        loop {
            attempts += 1;
            let failed = match self.try_create_new(&path, data)? {
                Ok(created) => return Ok(created),
                Err(e) => e,
            };
            match self.lstat(&path)? {
                Some(_) => return Ok(false),
                None if attempts < 4 => continue,
                None => return Err(failed),
            }
        }
    }

    fn remove_file(&self, p: &VPath) -> Result<()> {
        self.remove(&self.rp(p))
    }

    fn remove_dir_all(&self, p: &VPath) -> Result<()> {
        if p.is_root() {
            return Err(VeilError::InvalidPath("refusing to remove the backend root".into()));
        }
        let path = self.rp(p);
        match self.lstat(&path)? {
            None => Ok(()),
            Some(a) if a.file_type() == FileType::Dir => self.remove_tree(&path, 0),
            Some(_) => self.remove(&path),
        }
    }

    fn create_dir_all(&self, p: &VPath) -> Result<()> {
        self.mkdir_all(&self.rp(p))
    }

    fn list_dir(&self, p: &VPath) -> Result<Vec<DirEntry>> {
        let path = self.rp(p);
        let entries = self.readdir(&path)?;
        let mut out: Vec<DirEntry> = self
            .typed(&path, entries)?
            .into_iter()
            .filter_map(|(name, t)| {
                let kind = match t {
                    FileType::File => NodeKind::File,
                    FileType::Dir => NodeKind::Dir,
                    _ => return None,
                };
                // Names a `VPath` cannot hold are not ours.
                (!name.contains(['/', '\0'])).then_some(DirEntry { name, kind })
            })
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    fn special_at(&self, p: &VPath) -> Result<Option<&'static str>> {
        Ok(match self.lstat(&self.rp(p))? {
            Some(a) if a.is_symlink() => Some("a symlink"),
            Some(a) if a.file_type() == FileType::Special => Some("neither a file nor a directory"),
            _ => None,
        })
    }

    fn metadata(&self, p: &VPath) -> Result<Option<Metadata>> {
        let Some(a) = self.lstat(&self.rp(p))? else {
            return Ok(None);
        };
        let kind = match a.file_type() {
            FileType::File => NodeKind::File,
            FileType::Dir => NodeKind::Dir,
            _ => return Ok(None),
        };
        let exec = a.perms.is_some_and(|m| m & 0o111 != 0);
        // Remote stamps come from another machine's clock: unstamped, and
        // `stat_clock` stays `None`, so nothing caches on them.
        Ok(Some(Metadata::unstamped(kind, a.size.unwrap_or(0), exec)))
    }

    /// A temp file created with `O_EXCL`, written with up to `WINDOW`
    /// `WRITE`s in flight, then (when `durable`) `fsync@openssh.com`, and
    /// renamed into place (`posix-rename@openssh.com` where offered), as
    /// [`StorageBackend::write`] does.
    fn create_stream<'a>(&'a self, dir: &VPath, durable: bool) -> Result<Box<dyn super::StreamWriter + 'a>> {
        let dir = self.rp(dir);
        let tmp = format!("{dir}/{}", super::stream_temp_name());
        let handle = match self.open_creating(&tmp, FXF_WRITE | FXF_CREAT | FXF_EXCL | FXF_TRUNC)? {
            Ok(h) => h,
            Err(r) => return Err(r.ok(&tmp).err().unwrap_or_else(|| io_error(&tmp, io::Error::other("open failed")))),
        };
        Ok(Box::new(SftpStream {
            b: self,
            dir,
            tmp,
            handle: Some(handle),
            len: 0,
            inflight: VecDeque::new(),
            durable,
        }))
    }

    fn set_executable(&self, p: &VPath, executable: bool) -> Result<()> {
        let path = self.rp(p);
        let a = self.lstat(&path)?.ok_or_else(|| VeilError::NotFound(path.clone()))?;
        let mode = a.perms.unwrap_or(0o644) & 0o7777;
        let new = if executable {
            mode | ((mode & 0o444) >> 2)
        } else {
            mode & !0o111
        };
        if new != mode {
            self.call(&path, FXP_SETSTAT, |b| {
                b.str(&path).perms(new);
            })?
            .ok(&path)?;
        }
        Ok(())
    }
}

/// [`SftpBackend::create_stream`]'s writer.
struct SftpStream<'a> {
    b: &'a SftpBackend,
    dir: String,
    tmp: String,
    /// `None` once closed.
    handle: Option<Vec<u8>>,
    len: u64,
    inflight: VecDeque<Pending>,
    durable: bool,
}

impl SftpStream<'_> {
    /// Send `data` at `offset` in `max_write` pieces, waiting for the
    /// oldest reply whenever [`WINDOW`] are in flight.
    fn send_at(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        let handle = self.handle.as_deref().ok_or_else(|| VeilError::repo("stream: already closed"))?;
        let chunk = self.b.client.max_write as usize;
        for (i, part) in data.chunks(chunk).enumerate() {
            if self.inflight.len() >= WINDOW {
                let p = self.inflight.pop_front().unwrap();
                self.b.wait(&self.tmp, p)?.ok(&self.tmp)?;
            }
            let at = offset + (i * chunk) as u64;
            self.inflight.push_back(self.b.send(&self.tmp, FXP_WRITE, |b| {
                b.bytes(handle).u64(at).bytes(part);
            })?);
        }
        Ok(())
    }

    fn drain(&mut self) -> Result<()> {
        let mut first_err = None;
        for p in std::mem::take(&mut self.inflight) {
            if let Err(e) = self.b.wait(&self.tmp, p).and_then(|r| r.ok(&self.tmp)) {
                first_err.get_or_insert(e);
            }
        }
        first_err.map_or(Ok(()), Err)
    }
}

impl super::StreamWriter for SftpStream<'_> {
    fn write_all(&mut self, data: &[u8]) -> Result<()> {
        self.send_at(self.len, data)?;
        self.len += data.len() as u64;
        Ok(())
    }

    fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        if offset.checked_add(data.len() as u64).is_none_or(|end| end > self.len) {
            return Err(VeilError::repo("stream: write past the end"));
        }
        // Never in flight beside an earlier write of the same bytes.
        self.drain()?;
        self.send_at(offset, data)
    }

    fn finish(mut self: Box<Self>, name: &str) -> Result<()> {
        let to = format!("{}/{name}", self.dir);
        let handle = self.handle.take().ok_or_else(|| VeilError::repo("stream: already closed"))?;
        let res = self
            .drain()
            .and_then(|()| if self.durable { self.b.fsync_handle(&self.tmp, &handle) } else { Ok(()) });
        let closed = self.b.close(&self.tmp, &handle);
        res.and(closed)?;
        self.b.rename_over(&self.tmp, &to)?;
        // Published: nothing for `drop` to remove.
        self.tmp.clear();
        Ok(())
    }
}

impl Drop for SftpStream<'_> {
    fn drop(&mut self) {
        if self.tmp.is_empty() {
            return;
        }
        let _ = self.drain();
        if let Some(h) = self.handle.take() {
            let _ = self.b.close(&self.tmp, &h);
        }
        let _ = self.b.remove(&self.tmp);
    }
}

impl SftpBackend {
    /// Is the connection gone (server exited, network failure)?
    pub fn is_disconnected(&self) -> bool {
        self.client.is_dead()
    }

    /// The limits and timeout this connection runs with.
    pub fn options(&self) -> &SftpOptions {
        &self.opts
    }

    /// How far the server's clock is ahead of this machine's, in
    /// milliseconds (negative: behind). Measured with the modification
    /// time of an empty probe file created in `dir` and removed again; it
    /// is named like a temp file (`.clock.vltmp…`), so Veil treats it as
    /// crash debris if it is ever left behind. Precise to about a second
    /// (SFTP version 3 times are whole seconds) plus half the round trip.
    pub fn clock_offset(&self, dir: &VPath) -> Result<i64> {
        let tmp = Self::temp_name(&self.rp(&dir.join("clock")));
        let before = crate::now_millis();
        let p = self.open(&tmp, FXF_WRITE | FXF_CREAT | FXF_EXCL)?;
        let h = self.wait(&tmp, p)?.handle(&tmp)?;
        let after = crate::now_millis();
        let closed = self.close(&tmp, &h);
        let stat = closed.and_then(|()| self.lstat(&tmp));
        let _ = self.remove(&tmp);
        let mtime = stat?
            .and_then(|a| a.mtime)
            .ok_or_else(|| io_error(&tmp, io::Error::other("the server reports no modification time")))?;
        // The file was created between `before` and `after`; `mtime` is
        // that moment rounded down to the second.
        Ok(i64::from(mtime) * 1000 + 500 - (before + after) / 2)
    }
}
