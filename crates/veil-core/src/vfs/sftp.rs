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

use std::{
    collections::{BTreeMap, HashSet, VecDeque},
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
    DirEntry, Metadata, NodeKind, StorageBackend,
};
pub use super::sftp_client::SftpStats;
use crate::{
    error::{Result, VeilError},
    vpath::VPath,
};

/// Requests one operation keeps in flight (reads, writes, fsyncs).
const WINDOW: usize = 64;
/// A request with no reply and no other traffic for this long fails.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(300);

pub struct SftpBackend {
    client: Client,
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
        cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit());
        let program = cmd.get_program().to_string_lossy().into_owned();
        let mut child = cmd.spawn().map_err(|e| conn_err(&program, e))?;
        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");
        match Self::from_streams(stdout, stdin, root, label) {
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
        let client = Client::start(Box::new(reader), Box::new(io::BufWriter::new(writer)), DEFAULT_TIMEOUT)
            .map_err(|e| conn_err(label, e))?;
        let root = if root == "/" {
            "/".to_string()
        } else {
            root.trim_end_matches('/').to_string()
        };
        Ok(SftpBackend {
            client,
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
    /// of the file with `len` as a size hint. Up to [`WINDOW`] reads are in
    /// flight; short reads are re-requested.
    fn read_handle(&self, path: &str, handle: &[u8], offset: u64, len: u64, exact: bool) -> Result<Vec<u8>> {
        let chunk = u64::from(self.client.max_read);
        let mut want: VecDeque<(u64, u64)> = VecDeque::new();
        let end = offset + len;
        let mut o = offset;
        while o < end {
            let n = chunk.min(end - o);
            want.push_back((o, n));
            o += n;
        }
        // Until EOF: always probe past the expected end, so a file that is
        // longer than its size hint is still read completely.
        let mut next = end;
        let mut eof: Option<u64> = if exact { Some(end) } else { None };
        let mut got: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
        let mut inflight: VecDeque<(u64, u64, Pending)> = VecDeque::new();
        loop {
            if !exact && eof.is_none() && want.is_empty() && inflight.len() < 2 {
                want.push_back((next, chunk));
                next += chunk;
            }
            while inflight.len() < WINDOW {
                let Some((o, n)) = want.pop_front() else { break };
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
                Reply::Data(d) if d.is_empty() || d.len() as u64 > n => {
                    return Err(io_error(path, io::Error::new(io::ErrorKind::InvalidData, "sftp: bad read reply")));
                }
                Reply::Data(d) => {
                    let k = d.len() as u64;
                    got.insert(o, d);
                    if k < n {
                        want.push_front((o + k, n - k));
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
        let mut out = Vec::with_capacity((stop - offset) as usize);
        let mut pos = offset;
        for (o, d) in got {
            if o >= stop {
                break;
            }
            if o != pos {
                return Err(io_error(path, io::Error::new(io::ErrorKind::InvalidData, "sftp: gap in read")));
            }
            let take = (stop - o).min(d.len() as u64) as usize;
            out.extend_from_slice(&d[..take]);
            pos += take as u64;
        }
        if pos != stop {
            return Err(io_error(path, io::Error::new(io::ErrorKind::UnexpectedEof, "sftp: short read")));
        }
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

    /// Raw directory listing (names other than `.` and `..`).
    fn readdir(&self, path: &str) -> Result<Vec<(String, Attrs)>> {
        let p = self.send(path, FXP_OPENDIR, |b| {
            b.str(path);
        })?;
        let h = self.wait(path, p)?.handle(path)?;
        let mut out = Vec::new();
        let res = loop {
            match self.call(path, FXP_READDIR, |b| {
                b.bytes(&h);
            }) {
                Ok(Reply::Name(names)) => out.extend(names.into_iter().filter(|(n, _)| n != "." && n != "..")),
                Ok(Reply::Status(FX_EOF, _)) => break Ok(()),
                Ok(r) => break r.ok(path),
                Err(e) => break Err(e),
            }
        };
        self.close_detached(path, &h);
        res.map(|()| out)
    }

    /// Kind of each entry, asking the server for entries whose listing
    /// carried no permissions.
    fn typed(&self, dir: &str, entries: Vec<(String, Attrs)>) -> Result<Vec<(String, FileType)>> {
        let mut out = Vec::with_capacity(entries.len());
        for (name, a) in entries {
            let t = match a.file_type() {
                FileType::Unknown => self
                    .lstat(&format!("{dir}/{name}"))?
                    .map_or(FileType::Unknown, |a| a.file_type()),
                t => t,
            };
            out.push((name, t));
        }
        Ok(out)
    }

    fn remove_tree(&self, path: &str) -> Result<()> {
        let entries = self.readdir(path)?;
        let entries = self.typed(path, entries)?;
        let mut pending = Vec::new();
        for (name, t) in entries {
            let child = format!("{path}/{name}");
            if t == FileType::Dir {
                self.remove_tree(&child)?;
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
            self.read_handle(&path, &handle, 0, size, false)
        })();
        self.close_detached(&path, &handle);
        res
    }

    fn read_range(&self, p: &VPath, offset: u64, len: usize) -> Result<Vec<u8>> {
        let path = self.rp(p);
        let op = self.open(&path, FXF_READ)?;
        let handle = self.wait(&path, op)?.handle(&path)?;
        let res = if len == 0 {
            Ok(Vec::new())
        } else {
            self.read_handle(&path, &handle, offset, len as u64, true)
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
        let exists = |e: VeilError| -> Result<bool> {
            match self.lstat(&path)? {
                Some(_) => Ok(false),
                None => Err(e),
            }
        };
        if self.client.ext.hardlink {
            // Never expose a partly written file: the content is complete
            // and synced before the link makes it visible.
            let tmp = self.write_temp(&path, data, true)?;
            let linked = self.call(&path, FXP_EXTENDED, |b| {
                b.str("hardlink@openssh.com").str(&tmp).str(&path);
            });
            let _ = self.remove(&tmp);
            return match linked?.ok(&path) {
                Ok(()) => Ok(true),
                Err(e) => exists(e),
            };
        }
        let h = match self.open_creating(&path, FXF_WRITE | FXF_CREAT | FXF_EXCL)? {
            Ok(h) => h,
            Err(r) => {
                return exists(r.ok(&path).err().unwrap_or_else(|| io_error(&path, io::Error::other("open failed"))))
            }
        };
        let res = self.write_handle(&path, &h, data).and_then(|()| self.fsync_handle(&path, &h));
        let closed = self.close(&path, &h);
        res.and(closed).map(|()| true)
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
            Some(a) if a.file_type() == FileType::Dir => self.remove_tree(&path),
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

impl SftpBackend {
    /// Is the connection gone (server exited, network failure)?
    pub fn is_disconnected(&self) -> bool {
        self.client.is_dead()
    }
}
