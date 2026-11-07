//! A release `veil-server` started for a benchmark: on `127.0.0.1` over TLS
//! (its self-signed certificate), with the PostgreSQL the caller names and
//! objects in S3 (MinIO; credentials in `VEIL_S3_ACCESS_KEY` and
//! `VEIL_S3_SECRET_KEY`) or in a local directory. Killed when dropped.
//!
//! The server's peak RSS is read per case from `/proc/PID/status`
//! (`VmHWM`), reset before each run by writing `5` to
//! `/proc/PID/clear_refs`, with its RSS at that moment (the peak cannot
//! restart below it).

use std::{
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};

use anyhow::{bail, Context, Result};

/// How to start the server (flattened into the subcommands that start one).
#[derive(clap::Args, Clone, Debug, Default)]
pub struct ServerArgs {
    /// The `veil-server` binary (a release build).
    #[arg(long)]
    pub server: Option<PathBuf>,
    /// PostgreSQL (or YugabyteDB) for the server.
    #[arg(long)]
    pub database_url: Option<String>,
    /// Keep the server's objects in S3 at this endpoint (MinIO); else in
    /// a local directory.
    #[arg(long, requires = "s3_bucket")]
    pub s3_endpoint: Option<String>,
    #[arg(long)]
    pub s3_bucket: Option<String>,
}

pub struct Server {
    child: Child,
    /// `127.0.0.1:PORT`.
    pub authority: String,
    /// Its self-signed certificate (PEM file).
    pub cert: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Server {
    /// Migrate the database, start the server with its data in `data`
    /// (its log beside it, `data.log`), and wait until it listens.
    pub fn start(a: &ServerArgs, data: &Path, db_connections: u32) -> Result<Server> {
        let (Some(bin), Some(url)) = (&a.server, &a.database_url) else {
            bail!("starting a server needs --server and --database-url");
        };
        std::fs::create_dir_all(data)?;
        let st = Command::new(bin).args(["migrate", "--database-url", url]).stdout(Stdio::null()).status().context("veil-server migrate")?;
        if !st.success() {
            bail!("veil-server migrate failed ({st})");
        }
        // The server binds port 0 itself and prints the address it got: a
        // port picked here and released could be taken before the server
        // binds it, and binding one fails outright when the previous
        // curve's closed connections hold the ephemeral range (BUG-1001).
        let mut cmd = Command::new(bin);
        cmd.args(["--listen", "127.0.0.1:0", "--data"])
            .arg(data)
            .args(["--database-url", url, "--db-connections", &db_connections.to_string()]);
        if let (Some(e), Some(b)) = (&a.s3_endpoint, &a.s3_bucket) {
            cmd.args(["--s3-endpoint", e, "--s3-bucket", b]);
        }
        let log = data.with_extension("log");
        let mut child = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(std::fs::File::create(&log)?))
            .spawn()
            .context("starting veil-server")?;
        let stdout = child.stdout.take().context("veil-server's stdout")?;
        let (tx, rx) = std::sync::mpsc::channel();
        // Reads the whole of stdout, so the server never blocks on a full pipe.
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if let Some(addr) = line.strip_prefix("veil-server listening on https://") {
                    let _ = tx.send(addr.to_string());
                }
            }
        });
        let mut s = Server { child, authority: String::new(), cert: data.join("self-signed-cert.pem") };
        match rx.recv_timeout(Duration::from_secs(30)) {
            Ok(addr) if s.cert.exists() => s.authority = addr,
            _ => bail!("veil-server did not start (log: {})", log.display()),
        }
        Ok(s)
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// `veil://127.0.0.1:PORT/PROJECT`.
    pub fn url(&self, project: &str) -> String {
        format!("veil://{}/{project}", self.authority)
    }

    /// `https://127.0.0.1:PORT`.
    pub fn https(&self) -> String {
        format!("https://{}", self.authority)
    }
}

/// Start a new peak-RSS window for process `pid` (Linux: `clear_refs` 5);
/// its RSS now, in KiB. The peak restarts at this RSS, not below it: a
/// server keeps the memory it has used (its caches, the allocator's).
pub fn reset_peak(pid: u32) -> Option<u64> {
    let _ = std::fs::write(format!("/proc/{pid}/clear_refs"), "5");
    status_kib(pid, "VmRSS:")
}

/// Peak RSS of `pid` since the last [`reset_peak`], in KiB.
pub fn peak_kib(pid: u32) -> Option<u64> {
    status_kib(pid, "VmHWM:")
}

/// Bytes `pid` has read and written through system calls so far (`rchar`
/// and `wchar` of `/proc/PID/io`). For the server, nearly all of it is
/// network traffic: requests in and answers out, and the object store's
/// requests (with MinIO, a push's writes are the bytes stored).
pub fn io_bytes(pid: u32) -> Option<(u64, u64)> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/io")).ok()?;
    let field = |f: &str| s.lines().find_map(|l| l.strip_prefix(f))?.trim().parse().ok();
    Some((field("rchar:")?, field("wchar:")?))
}

/// A `/proc/PID/status` field in KiB.
fn status_kib(pid: u32, field: &str) -> Option<u64> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    s.lines().find(|l| l.starts_with(field))?.split_whitespace().nth(1)?.parse().ok()
}
