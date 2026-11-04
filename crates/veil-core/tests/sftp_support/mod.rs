//! Offline SFTP for tests: a local OpenSSH `sftp-server` spawned over a
//! pipe, the very protocol `ssh -s host sftp` carries, with optional
//! latency and fault injection between client and server.
//!
//! Tests call [`server`] and return early, with a message, when no
//! `sftp-server` binary is installed (`VEIL_TEST_SFTP_SERVER` overrides
//! the search).

#![allow(dead_code)]

use std::{
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicI64, Ordering},
        mpsc, Arc, Mutex,
    },
    time::{Duration, Instant},
};

use veil_core::SftpBackend;

const CANDIDATES: &[&str] = &[
    "/usr/lib/openssh/sftp-server",
    "/usr/libexec/openssh/sftp-server",
    "/usr/libexec/sftp-server",
    "/usr/lib/ssh/sftp-server",
    "/usr/local/libexec/sftp-server",
    "/opt/homebrew/libexec/sftp-server",
];

/// Path of a usable `sftp-server`, or `None` (with a message) to skip.
pub fn server() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("VEIL_TEST_SFTP_SERVER") {
        return Some(PathBuf::from(p));
    }
    let found = CANDIDATES.iter().map(PathBuf::from).find(|p| p.exists());
    if found.is_none() {
        eprintln!("SKIPPED: no sftp-server binary found (set VEIL_TEST_SFTP_SERVER to run SFTP tests)");
    }
    found
}

/// Run `sftp-server` and connect to it, with `root` as the repository
/// directory.
pub fn connect(server: &Path, root: &Path) -> SftpBackend {
    let cmd = Command::new(server);
    SftpBackend::spawn(cmd, root.to_str().unwrap(), &format!("sftp-server:{}", root.display())).unwrap()
}

/// Shims between client and server.
#[derive(Clone, Default)]
pub struct Shim {
    /// One-way delay in each direction (round trip = twice this).
    pub delay: Duration,
    /// Cut the connection once the client has sent this many bytes.
    pub cut_after: Option<Arc<AtomicI64>>,
}

/// Like [`connect`], through `shim`. The returned child is the server.
pub fn connect_with(server: &Path, root: &Path, shim: Shim) -> (SftpBackend, Arc<Mutex<Child>>) {
    let mut child = Command::new(server)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let child = Arc::new(Mutex::new(child));
    let reader: Box<dyn Read + Send> = if shim.delay.is_zero() {
        Box::new(stdout)
    } else {
        Box::new(DelayedReader::new(stdout, shim.delay))
    };
    let writer: Box<dyn Write + Send> = match (&shim.cut_after, shim.delay.is_zero()) {
        (Some(budget), _) => Box::new(CutWriter {
            inner: Some(Box::new(stdin)),
            budget: budget.clone(),
            child: child.clone(),
        }),
        (None, true) => Box::new(stdin),
        (None, false) => Box::new(DelayedWriter::new(stdin, shim.delay)),
    };
    let b = SftpBackend::from_streams(reader, writer, root.to_str().unwrap(), "shimmed sftp-server").unwrap();
    (b, child)
}

// ---- latency ------------------------------------------------------------------

/// Delivers each chunk `delay` after it was produced. Deadlines are
/// absolute, so pipelined traffic is delayed, not serialised.
struct DelayedReader {
    rx: mpsc::Receiver<(Instant, Vec<u8>)>,
    buf: Vec<u8>,
    at: usize,
}

impl DelayedReader {
    fn new(mut inner: impl Read + Send + 'static, delay: Duration) -> Self {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut b = vec![0u8; 256 * 1024];
            loop {
                match inner.read(&mut b) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => {
                        if tx.send((Instant::now() + delay, b[..n].to_vec())).is_err() {
                            return;
                        }
                    }
                }
            }
        });
        DelayedReader { rx, buf: Vec::new(), at: 0 }
    }
}

impl Read for DelayedReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.at >= self.buf.len() {
            let Ok((due, data)) = self.rx.recv() else { return Ok(0) };
            let now = Instant::now();
            if due > now {
                std::thread::sleep(due - now);
            }
            self.buf = data;
            self.at = 0;
        }
        let n = out.len().min(self.buf.len() - self.at);
        out[..n].copy_from_slice(&self.buf[self.at..self.at + n]);
        self.at += n;
        Ok(n)
    }
}

struct DelayedWriter {
    tx: Option<mpsc::Sender<(Instant, Vec<u8>)>>,
    delay: Duration,
}

impl DelayedWriter {
    fn new(mut inner: impl Write + Send + 'static, delay: Duration) -> Self {
        let (tx, rx) = mpsc::channel::<(Instant, Vec<u8>)>();
        std::thread::spawn(move || {
            while let Ok((due, data)) = rx.recv() {
                let now = Instant::now();
                if due > now {
                    std::thread::sleep(due - now);
                }
                if inner.write_all(&data).and_then(|()| inner.flush()).is_err() {
                    return;
                }
            }
        });
        DelayedWriter { tx: Some(tx), delay }
    }
}

impl Write for DelayedWriter {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        let tx = self.tx.as_ref().ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?;
        tx.send((Instant::now() + self.delay, b.to_vec()))
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// ---- faults ---------------------------------------------------------------------

/// Passes bytes through until the budget is spent, then kills the server:
/// the network drops in the middle of whatever the client was doing.
struct CutWriter {
    inner: Option<Box<dyn Write + Send>>,
    budget: Arc<AtomicI64>,
    child: Arc<Mutex<Child>>,
}

impl Write for CutWriter {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        let left = self.budget.fetch_sub(b.len() as i64, Ordering::SeqCst);
        let Some(w) = self.inner.as_mut() else {
            return Err(io::ErrorKind::BrokenPipe.into());
        };
        if left < b.len() as i64 {
            // Deliver a prefix (a torn request), then drop the link.
            let keep = left.max(0) as usize;
            let _ = w.write_all(&b[..keep]);
            let _ = w.flush();
            self.inner = None;
            let mut c = self.child.lock().unwrap();
            let _ = c.kill();
            let _ = c.wait();
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        w.write_all(b)?;
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        match self.inner.as_mut() {
            Some(w) => w.flush(),
            None => Err(io::ErrorKind::BrokenPipe.into()),
        }
    }
}

pub fn budget(n: i64) -> Arc<AtomicI64> {
    Arc::new(AtomicI64::new(n))
}
