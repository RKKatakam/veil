//! A small, pipelined SFTP version 3 client (draft-ietf-secsh-filexfer-02,
//! the version OpenSSH speaks) over any pair of byte streams, normally the
//! stdin/stdout of the user's own `ssh` running the `sftp` subsystem.
//!
//! Requests carry ids, and a reader thread routes each reply to whoever is
//! waiting for that id, so any number of threads can have any number of
//! requests in flight at once: [`Client::send`] returns a [`Pending`]
//! reply, and callers send a whole batch before waiting for the first
//! answer. That is what turns "one round trip per request" into "one round
//! trip per batch" on a WAN.
//!
//! The protocol is small enough to implement here: the alternatives
//! (`openssh-sftp-client`, `russh-sftp`, `ssh2`) either need an async
//! runtime under a synchronous `StorageBackend`, or bring their own SSH
//! implementation instead of the user's `ssh` (see `sftp.rs`).

use std::{
    collections::HashMap,
    io::{self, Read, Write},
    sync::{
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
        mpsc, Arc, Mutex,
    },
    time::{Duration, Instant},
};

use crate::error::VeilError;

// ---- protocol constants -------------------------------------------------------

pub(crate) const FXP_INIT: u8 = 1;
pub(crate) const FXP_VERSION: u8 = 2;
pub(crate) const FXP_OPEN: u8 = 3;
pub(crate) const FXP_CLOSE: u8 = 4;
pub(crate) const FXP_READ: u8 = 5;
pub(crate) const FXP_WRITE: u8 = 6;
pub(crate) const FXP_LSTAT: u8 = 7;
pub(crate) const FXP_SETSTAT: u8 = 9;
pub(crate) const FXP_OPENDIR: u8 = 11;
pub(crate) const FXP_READDIR: u8 = 12;
pub(crate) const FXP_REMOVE: u8 = 13;
pub(crate) const FXP_MKDIR: u8 = 14;
pub(crate) const FXP_RMDIR: u8 = 15;
pub(crate) const FXP_RENAME: u8 = 18;
pub(crate) const FXP_EXTENDED: u8 = 200;

const FXP_STATUS: u8 = 101;
const FXP_HANDLE: u8 = 102;
const FXP_DATA: u8 = 103;
const FXP_NAME: u8 = 104;
const FXP_ATTRS: u8 = 105;
const FXP_EXTENDED_REPLY: u8 = 201;

pub(crate) const FXF_READ: u32 = 0x01;
pub(crate) const FXF_WRITE: u32 = 0x02;
pub(crate) const FXF_CREAT: u32 = 0x08;
pub(crate) const FXF_TRUNC: u32 = 0x10;
pub(crate) const FXF_EXCL: u32 = 0x20;

const ATTR_SIZE: u32 = 0x01;
const ATTR_UIDGID: u32 = 0x02;
const ATTR_PERMISSIONS: u32 = 0x04;
const ATTR_ACMODTIME: u32 = 0x08;
const ATTR_EXTENDED: u32 = 0x8000_0000;

pub(crate) const FX_OK: u32 = 0;
pub(crate) const FX_EOF: u32 = 1;
pub(crate) const FX_NO_SUCH_FILE: u32 = 2;
const FX_PERMISSION_DENIED: u32 = 3;
const FX_NO_CONNECTION: u32 = 6;
const FX_CONNECTION_LOST: u32 = 7;
const FX_OP_UNSUPPORTED: u32 = 8;
/// Not in version 3, but some servers send it.
const FX_FILE_ALREADY_EXISTS: u32 = 11;

const S_IFMT: u32 = 0o170_000;
const S_IFDIR: u32 = 0o040_000;
const S_IFREG: u32 = 0o100_000;

/// Largest reply accepted from the server. OpenSSH never sends more than
/// 256 KiB; anything far bigger is a broken or hostile server.
const MAX_PACKET: usize = 8 << 20;

/// What a reply looked like when its kind could not be used.
fn unexpected(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("sftp: unexpected reply ({what})"))
}

// ---- wire encoding ------------------------------------------------------------

pub(crate) struct Body(pub(crate) Vec<u8>);

impl Body {
    pub(crate) fn u32(&mut self, v: u32) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub(crate) fn u64(&mut self, v: u64) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }
    pub(crate) fn bytes(&mut self, v: &[u8]) -> &mut Self {
        self.u32(v.len() as u32);
        self.0.extend_from_slice(v);
        self
    }
    pub(crate) fn str(&mut self, v: &str) -> &mut Self {
        self.bytes(v.as_bytes())
    }
    /// Attributes with nothing set.
    pub(crate) fn no_attrs(&mut self) -> &mut Self {
        self.u32(0)
    }
    pub(crate) fn perms(&mut self, mode: u32) -> &mut Self {
        self.u32(ATTR_PERMISSIONS).u32(mode)
    }
}

struct Cursor<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> io::Result<&'a [u8]> {
        let end = self.at.checked_add(n).filter(|e| *e <= self.buf.len()).ok_or_else(|| unexpected("truncated"))?;
        let s = &self.buf[self.at..end];
        self.at = end;
        Ok(s)
    }
    fn u32(&mut self) -> io::Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> io::Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn bytes(&mut self) -> io::Result<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }
    fn string(&mut self) -> io::Result<String> {
        Ok(String::from_utf8_lossy(self.bytes()?).into_owned())
    }
    fn rest(&mut self) -> &'a [u8] {
        let s = &self.buf[self.at..];
        self.at = self.buf.len();
        s
    }
    fn is_empty(&self) -> bool {
        self.at >= self.buf.len()
    }
}

/// File attributes, as far as Veil needs them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Attrs {
    pub size: Option<u64>,
    pub perms: Option<u32>,
    pub mtime: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FileType {
    File,
    Dir,
    /// Symlinks, sockets, devices: never followed or recorded.
    Special,
    Unknown,
}

impl Attrs {
    fn parse(c: &mut Cursor) -> io::Result<Attrs> {
        let flags = c.u32()?;
        let mut a = Attrs::default();
        if flags & ATTR_SIZE != 0 {
            a.size = Some(c.u64()?);
        }
        if flags & ATTR_UIDGID != 0 {
            c.u32()?;
            c.u32()?;
        }
        if flags & ATTR_PERMISSIONS != 0 {
            a.perms = Some(c.u32()?);
        }
        if flags & ATTR_ACMODTIME != 0 {
            c.u32()?;
            a.mtime = Some(c.u32()?);
        }
        if flags & ATTR_EXTENDED != 0 {
            for _ in 0..c.u32()? {
                c.bytes()?;
                c.bytes()?;
            }
        }
        Ok(a)
    }

    pub(crate) fn file_type(&self) -> FileType {
        match self.perms.map(|p| p & S_IFMT) {
            Some(S_IFREG) => FileType::File,
            Some(S_IFDIR) => FileType::Dir,
            Some(_) => FileType::Special,
            None => FileType::Unknown,
        }
    }
}

/// A decoded reply.
#[derive(Debug)]
pub(crate) enum Reply {
    Status(u32, String),
    Handle(Vec<u8>),
    Data(Vec<u8>),
    Name(Vec<(String, Attrs)>),
    Attrs(Attrs),
    Extended(Vec<u8>),
}

fn parse_reply(kind: u8, c: &mut Cursor) -> io::Result<Reply> {
    Ok(match kind {
        FXP_STATUS => {
            let code = c.u32()?;
            // Some servers omit the message and language tag.
            let msg = if c.is_empty() { String::new() } else { c.string()? };
            Reply::Status(code, msg)
        }
        FXP_HANDLE => Reply::Handle(c.bytes()?.to_vec()),
        FXP_DATA => Reply::Data(c.bytes()?.to_vec()),
        FXP_NAME => {
            let n = c.u32()? as usize;
            let mut out = Vec::with_capacity(n.min(4096));
            for _ in 0..n {
                let name = c.string()?;
                c.bytes()?; // long name, for humans
                out.push((name, Attrs::parse(c)?));
            }
            Reply::Name(out)
        }
        FXP_ATTRS => Reply::Attrs(Attrs::parse(c)?),
        FXP_EXTENDED_REPLY => Reply::Extended(c.rest().to_vec()),
        other => return Err(unexpected(&format!("packet type {other}"))),
    })
}

/// The error for a non-OK status about `path`. "No such file" becomes
/// [`VeilError::NotFound`], as on every other backend.
pub(crate) fn status_error(path: &str, code: u32, msg: &str) -> VeilError {
    if code == FX_NO_SUCH_FILE {
        return VeilError::NotFound(path.to_string());
    }
    let kind = match code {
        FX_EOF => io::ErrorKind::UnexpectedEof,
        FX_PERMISSION_DENIED => io::ErrorKind::PermissionDenied,
        FX_NO_CONNECTION | FX_CONNECTION_LOST => io::ErrorKind::ConnectionAborted,
        FX_OP_UNSUPPORTED => io::ErrorKind::Unsupported,
        FX_FILE_ALREADY_EXISTS => io::ErrorKind::AlreadyExists,
        _ => io::ErrorKind::Other,
    };
    let msg = if msg.is_empty() { "failure" } else { msg };
    io_error(path, io::Error::new(kind, format!("sftp: {msg} (status {code})")))
}

pub(crate) fn io_error(path: &str, e: io::Error) -> VeilError {
    VeilError::Io {
        path: path.to_string(),
        source: e,
    }
}

impl Reply {
    /// `Ok(())` for an OK status, else the error it describes.
    pub(crate) fn ok(self, path: &str) -> crate::Result<()> {
        match self {
            Reply::Status(FX_OK, _) => Ok(()),
            Reply::Status(code, msg) => Err(status_error(path, code, &msg)),
            _ => Err(io_error(path, unexpected("wanted a status"))),
        }
    }

    pub(crate) fn handle(self, path: &str) -> crate::Result<Vec<u8>> {
        match self {
            Reply::Handle(h) => Ok(h),
            Reply::Status(code, msg) => Err(status_error(path, code, &msg)),
            _ => Err(io_error(path, unexpected("wanted a handle"))),
        }
    }

    pub(crate) fn attrs(self, path: &str) -> crate::Result<Attrs> {
        match self {
            Reply::Attrs(a) => Ok(a),
            Reply::Status(code, msg) => Err(status_error(path, code, &msg)),
            _ => Err(io_error(path, unexpected("wanted attributes"))),
        }
    }
}

// ---- the client -----------------------------------------------------------------

/// Server extensions Veil uses, as advertised in the version reply.
#[derive(Clone, Debug, Default)]
pub(crate) struct Extensions {
    /// `posix-rename@openssh.com`: rename that atomically replaces the target.
    pub posix_rename: bool,
    /// `fsync@openssh.com`: fsync an open handle.
    pub fsync: bool,
    /// `hardlink@openssh.com`: link(2), which fails if the target exists.
    pub hardlink: bool,
    /// `limits@openssh.com`: packet and read/write size limits.
    pub limits: bool,
}

/// Request counters, for benchmarks and tests.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SftpStats {
    pub requests: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

type Waiter = mpsc::Sender<io::Result<Reply>>;

#[derive(Default)]
struct Shared {
    pending: Mutex<HashMap<u32, Waiter>>,
    /// Why the connection is gone, once it is.
    dead: Mutex<Option<String>>,
    last_rx: Mutex<Option<Instant>>,
    requests: AtomicU64,
    sent: AtomicU64,
    received: AtomicU64,
}

impl Shared {
    fn kill(&self, why: String) {
        let mut d = self.dead.lock().unwrap_or_else(|e| e.into_inner());
        if d.is_none() {
            *d = Some(why);
        }
        drop(d);
        // Dropping the senders wakes every waiter.
        self.pending.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }

    fn dead_reason(&self) -> Option<String> {
        self.dead.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

pub(crate) struct Client {
    writer: Mutex<Option<Box<dyn Write + Send>>>,
    shared: Arc<Shared>,
    next_id: AtomicU32,
    pub(crate) ext: Extensions,
    pub(crate) max_read: u32,
    pub(crate) max_write: u32,
    /// A request with no reply and no other traffic for this long fails.
    timeout: Duration,
    closed: AtomicBool,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client").field("ext", &self.ext).finish_non_exhaustive()
    }
}

/// A reply that has been asked for and not yet received.
pub(crate) struct Pending {
    rx: mpsc::Receiver<io::Result<Reply>>,
    shared: Arc<Shared>,
    sent: Instant,
    timeout: Duration,
}

impl Pending {
    pub(crate) fn wait(self) -> io::Result<Reply> {
        loop {
            match self.rx.recv_timeout(Duration::from_millis(500)) {
                Ok(r) => return r,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(lost(self.shared.dead_reason()));
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    // Time out only when the server has gone quiet: replies
                    // to other requests (a big batch ahead of us) count.
                    let last = (*self.shared.last_rx.lock().unwrap_or_else(|e| e.into_inner()))
                        .map_or(self.sent, |t| t.max(self.sent));
                    if last.elapsed() >= self.timeout {
                        let why = format!("no reply from the SFTP server for {}s", self.timeout.as_secs());
                        self.shared.kill(why.clone());
                        return Err(lost(Some(why)));
                    }
                }
            }
        }
    }
}

fn lost(why: Option<String>) -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        format!("SFTP connection lost: {}", why.unwrap_or_else(|| "closed".into())),
    )
}

fn read_packet(r: &mut dyn Read) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > MAX_PACKET {
        return Err(unexpected(&format!("packet of {len} bytes")));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

impl Client {
    /// Run the version handshake over `reader`/`writer`, then start the
    /// reader thread.
    pub(crate) fn start(
        mut reader: Box<dyn Read + Send>,
        mut writer: Box<dyn Write + Send>,
        timeout: Duration,
    ) -> io::Result<Client> {
        let mut init = Vec::with_capacity(9);
        init.extend_from_slice(&5u32.to_be_bytes());
        init.push(FXP_INIT);
        init.extend_from_slice(&3u32.to_be_bytes());
        writer.write_all(&init)?;
        writer.flush()?;
        let pkt = read_packet(&mut *reader).map_err(|e| {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "the SFTP server closed the connection during the handshake (is SSH access and the sftp subsystem available?)",
                )
            } else {
                e
            }
        })?;
        let mut c = Cursor { buf: &pkt, at: 0 };
        if c.take(1)?[0] != FXP_VERSION {
            return Err(unexpected("wanted the version reply"));
        }
        let version = c.u32()?;
        if version < 3 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("SFTP server speaks protocol version {version}; 3 is required"),
            ));
        }
        let mut ext = Extensions::default();
        while !c.is_empty() {
            let name = c.string()?;
            let _data = c.bytes()?;
            match name.as_str() {
                "posix-rename@openssh.com" => ext.posix_rename = true,
                "fsync@openssh.com" => ext.fsync = true,
                "hardlink@openssh.com" => ext.hardlink = true,
                "limits@openssh.com" => ext.limits = true,
                _ => {}
            }
        }
        let shared = Arc::new(Shared::default());
        let rx_shared = shared.clone();
        std::thread::Builder::new()
            .name("veil-sftp-reader".into())
            .spawn(move || reader_loop(&mut *reader, &rx_shared))?;
        let mut client = Client {
            writer: Mutex::new(Some(writer)),
            shared,
            next_id: AtomicU32::new(1),
            ext,
            // Every server must handle 32 KiB.
            max_read: 32 * 1024,
            max_write: 32 * 1024,
            timeout,
            closed: AtomicBool::new(false),
        };
        if client.ext.limits {
            if let Ok(Reply::Extended(data)) = client
                .send(FXP_EXTENDED, |b| {
                    b.str("limits@openssh.com");
                })
                .and_then(Pending::wait)
            {
                let mut c = Cursor { buf: &data, at: 0 };
                if let (Ok(_packet), Ok(read), Ok(write)) = (c.u64(), c.u64(), c.u64()) {
                    // Leave room for the packet header; never go absurdly big.
                    let clamp = |v: u64| v.clamp(4096, 255 * 1024) as u32;
                    if read > 0 {
                        client.max_read = clamp(read);
                    }
                    if write > 0 {
                        client.max_write = clamp(write);
                    }
                }
            }
        }
        Ok(client)
    }

    /// Send one request; the reply arrives through the returned [`Pending`].
    /// Requests are written in call order.
    pub(crate) fn send(&self, kind: u8, build: impl FnOnce(&mut Body)) -> io::Result<Pending> {
        if let Some(why) = self.shared.dead_reason() {
            return Err(lost(Some(why)));
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut body = Body(Vec::with_capacity(64));
        body.u32(0).0.push(kind);
        body.u32(id);
        build(&mut body);
        let len = (body.0.len() - 4) as u32;
        body.0[..4].copy_from_slice(&len.to_be_bytes());
        let (tx, rx) = mpsc::channel();
        self.shared.pending.lock().unwrap_or_else(|e| e.into_inner()).insert(id, tx);
        let sent = Instant::now();
        let res = {
            let mut w = self.writer.lock().unwrap_or_else(|e| e.into_inner());
            match w.as_mut() {
                Some(w) => w.write_all(&body.0).and_then(|()| w.flush()),
                None => Err(io::Error::new(io::ErrorKind::NotConnected, "SFTP connection closed")),
            }
        };
        if let Err(e) = res {
            self.shared.pending.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
            self.shared.kill(format!("write failed: {e}"));
            return Err(lost(self.shared.dead_reason()));
        }
        // A connection that died while we registered would never answer.
        if let Some(why) = self.shared.dead_reason() {
            self.shared.pending.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
            return Err(lost(Some(why)));
        }
        self.shared.requests.fetch_add(1, Ordering::Relaxed);
        self.shared.sent.fetch_add(body.0.len() as u64, Ordering::Relaxed);
        Ok(Pending {
            rx,
            shared: self.shared.clone(),
            sent,
            timeout: self.timeout,
        })
    }

    pub(crate) fn stats(&self) -> SftpStats {
        SftpStats {
            requests: self.shared.requests.load(Ordering::Relaxed),
            bytes_sent: self.shared.sent.load(Ordering::Relaxed),
            bytes_received: self.shared.received.load(Ordering::Relaxed),
        }
    }

    pub(crate) fn is_dead(&self) -> bool {
        self.shared.dead_reason().is_some()
    }

    /// Close our end; the server (or `ssh`) exits when it sees EOF.
    pub(crate) fn close(&self) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            self.writer.lock().unwrap_or_else(|e| e.into_inner()).take();
            self.shared.kill("closed".into());
        }
    }
}

fn reader_loop(reader: &mut dyn Read, shared: &Shared) {
    loop {
        let pkt = match read_packet(reader) {
            Ok(p) => p,
            Err(e) => {
                let why = if e.kind() == io::ErrorKind::UnexpectedEof {
                    "the server closed the connection".to_string()
                } else {
                    format!("read failed: {e}")
                };
                shared.kill(why);
                return;
            }
        };
        *shared.last_rx.lock().unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());
        shared.received.fetch_add(pkt.len() as u64 + 4, Ordering::Relaxed);
        let mut c = Cursor { buf: &pkt, at: 0 };
        let parsed = c.take(1).and_then(|k| Ok((k[0], c.u32()?)));
        let Ok((kind, id)) = parsed else {
            shared.kill("malformed packet".into());
            return;
        };
        let reply = parse_reply(kind, &mut c);
        let waiter = shared.pending.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
        if let Some(w) = waiter {
            // The waiter may have given up (fire-and-forget close).
            let _ = w.send(reply);
        }
    }
}
