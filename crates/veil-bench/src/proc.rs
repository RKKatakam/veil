//! Running `vl` as a child process: wall time, CPU time and peak RSS (from
//! `wait4`'s `rusage`, the child's own `ru_maxrss`), optionally under
//! `strace` for the walk and lock analysis (see `trace.rs`).

use std::{
    os::unix::process::ExitStatusExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};

/// Set by SIGINT/SIGTERM: the harness stops after the current command and
/// cleans up.
pub static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

pub fn install_signal_handlers() {
    // SAFETY: the handler only stores to an atomic, which is async-signal-safe.
    unsafe {
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
    }
}

pub fn check_stop() -> Result<()> {
    if STOP.load(Ordering::SeqCst) {
        return Err(anyhow!("interrupted"));
    }
    Ok(())
}

/// The syscalls the analysis needs: object opens, lock creation (link or
/// `O_EXCL`) and release.
pub const STRACE_SYSCALLS: &str = "openat,openat2,open,linkat,link,unlinkat,unlink";

/// Where a command's environment comes from.
#[derive(Clone)]
pub struct VlEnv {
    pub vl: PathBuf,
    pub home: PathBuf,
    pub tmp: PathBuf,
    /// Scratch directory for captured output and traces.
    pub logs: PathBuf,
}

static SEQ: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Default)]
pub struct Outcome {
    pub secs: f64,
    pub user_secs: f64,
    pub sys_secs: f64,
    pub maxrss_kib: u64,
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
    /// Bytes written to stdout (it is kept on disk, not in memory, when
    /// large).
    pub stdout_bytes: u64,
    /// The trace file, when run under strace.
    pub trace: Option<PathBuf>,
}

impl Outcome {
    pub fn ok(&self) -> bool {
        self.code == 0
    }
}

impl VlEnv {
    pub fn command(&self, cwd: &Path, args: &[&str]) -> Command {
        let mut c = Command::new(&self.vl);
        c.args(args)
            .current_dir(cwd)
            .env("VEIL_HOME", &self.home)
            .env("VEIL_USER", "bench")
            .env("TMPDIR", &self.tmp)
            .env("NO_COLOR", "1")
            // No background maintenance inside the benchmark: it measures
            // `vl gc` and `vl gc --auto` as cases of their own.
            .env("VEIL_GC_AUTO", "0")
            .stdin(Stdio::null());
        c
    }

    /// Run `vl args` in `cwd`; `strace` puts it under strace.
    pub fn run(&self, cwd: &Path, args: &[&str], strace: bool) -> Result<Outcome> {
        self.run_with(cwd, args, strace, &[])
    }

    pub fn run_with(&self, cwd: &Path, args: &[&str], strace: bool, env: &[(&str, &str)]) -> Result<Outcome> {
        self.run_full(cwd, args, strace, env, None)
    }

    /// [`VlEnv::run_with`], killing the command after `timeout`
    /// (`code` is then 137).
    pub fn run_full(&self, cwd: &Path, args: &[&str], strace: bool, env: &[(&str, &str)], timeout: Option<Duration>) -> Result<Outcome> {
        let n = SEQ.fetch_add(1, Ordering::SeqCst);
        let out_path = self.logs.join(format!("{n}.out"));
        let err_path = self.logs.join(format!("{n}.err"));
        let trace = strace.then(|| self.logs.join(format!("{n}.trace")));
        let mut cmd = match &trace {
            Some(t) => {
                let mut c = Command::new("strace");
                c.arg("-f")
                    .arg("-qq")
                    .arg("-ttt")
                    .arg("-y")
                    .arg("-e")
                    .arg(format!("trace={STRACE_SYSCALLS}"))
                    .arg("-e")
                    .arg("signal=none")
                    .arg("-o")
                    .arg(t)
                    .arg("--")
                    .arg(&self.vl)
                    .args(args)
                    .current_dir(cwd)
                    .env("VEIL_HOME", &self.home)
                    .env("VEIL_USER", "bench")
                    .env("TMPDIR", &self.tmp)
                    .env("NO_COLOR", "1")
                    .stdin(Stdio::null());
                c
            }
            None => self.command(cwd, args),
        };
        for (k, v) in env {
            cmd.env(k, v);
        }
        cmd.stdout(std::fs::File::create(&out_path)?).stderr(std::fs::File::create(&err_path)?);
        let o = spawn_measured(&mut cmd, timeout).with_context(|| format!("vl {args:?}"))?;
        let stdout_bytes = std::fs::metadata(&out_path).map(|m| m.len()).unwrap_or(0);
        let stdout = read_head(&out_path, 64 * 1024);
        let stderr = read_head(&err_path, 64 * 1024);
        let _ = std::fs::remove_file(&out_path);
        let _ = std::fs::remove_file(&err_path);
        Ok(Outcome {
            stdout,
            stderr,
            stdout_bytes,
            trace,
            ..o
        })
    }

    /// Run and fail unless it succeeded.
    pub fn ok(&self, cwd: &Path, args: &[&str]) -> Result<Outcome> {
        let o = self.run(cwd, args, false)?;
        if !o.ok() {
            return Err(anyhow!("vl {args:?} failed ({}):\n{}{}", o.code, o.stdout, o.stderr));
        }
        Ok(o)
    }
}

fn read_head(p: &Path, max: usize) -> String {
    use std::io::Read;
    let mut s = Vec::new();
    if let Ok(f) = std::fs::File::open(p) {
        let _ = f.take(max as u64).read_to_end(&mut s);
    }
    String::from_utf8_lossy(&s).into_owned()
}

/// Spawn `cmd` and reap it with `wait4`, keeping its `rusage`.
pub fn spawn_measured(cmd: &mut Command, timeout: Option<Duration>) -> Result<Outcome> {
    let t = Instant::now();
    let child = cmd.spawn()?;
    let pid = child.id() as libc::pid_t;
    // The watchdog kills only under `reaped`'s lock, and the pid is reaped
    // only after `reaped` is set under it: it never signals a reused pid.
    let reaped = Arc::new(std::sync::Mutex::new(false));
    if let Some(limit) = timeout {
        let reaped = reaped.clone();
        std::thread::spawn(move || {
            let start = Instant::now();
            loop {
                std::thread::sleep(Duration::from_millis(100));
                let g = reaped.lock().unwrap();
                if *g {
                    return;
                }
                if start.elapsed() >= limit {
                    // SAFETY: `pid` is our child, not reaped yet (see above).
                    unsafe { libc::kill(pid, libc::SIGKILL) };
                    return;
                }
            }
        });
    }
    // Wait for the exit without reaping, then reap with `wait4` for the
    // rusage.
    loop {
        // SAFETY: `siginfo_t` is plain old data, filled in by the call.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: waits for our own child; WNOWAIT leaves it reapable.
        let r = unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut info, libc::WEXITED | libc::WNOWAIT) };
        if r == 0 {
            break;
        }
        let e = std::io::Error::last_os_error();
        if e.kind() != std::io::ErrorKind::Interrupted {
            return Err(anyhow!("waitid: {e}"));
        }
    }
    let mut guard = reaped.lock().unwrap();
    *guard = true;
    let mut status: libc::c_int = 0;
    // SAFETY: `rusage` is plain old data; wait4 fills it in.
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    loop {
        // SAFETY: we own `pid` (our child, not yet reaped: `child` is never
        // waited on through std).
        let r = unsafe { libc::wait4(pid, &mut status, 0, &mut ru) };
        if r == pid {
            break;
        }
        let e = std::io::Error::last_os_error();
        if e.kind() != std::io::ErrorKind::Interrupted {
            return Err(anyhow!("wait4: {e}"));
        }
    }
    drop(guard);
    let secs = t.elapsed().as_secs_f64();
    drop(child);
    let st = std::process::ExitStatus::from_raw(status);
    let code = st.code().unwrap_or_else(|| 128 + st.signal().unwrap_or(0));
    let tv = |t: libc::timeval| t.tv_sec as f64 + t.tv_usec as f64 / 1e6;
    Ok(Outcome {
        secs,
        user_secs: tv(ru.ru_utime),
        sys_secs: tv(ru.ru_stime),
        // Linux reports kilobytes.
        maxrss_kib: ru.ru_maxrss as u64,
        code,
        ..Outcome::default()
    })
}

/// Free bytes on the file system holding `p`.
pub fn free_bytes(p: &Path) -> Result<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(p.as_os_str().as_bytes())?;
    // SAFETY: `statvfs` is plain old data, filled in by the call.
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c` is a valid NUL-terminated path.
    if unsafe { libc::statvfs(c.as_ptr(), &mut s) } != 0 {
        return Err(anyhow!("statvfs {}: {}", p.display(), std::io::Error::last_os_error()));
    }
    Ok(s.f_bavail as u64 * s.f_frsize as u64)
}

/// Disk usage (allocated bytes) and file count under `p`.
pub fn du(p: &Path) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    let (mut bytes, mut files) = (0u64, 0u64);
    let mut stack = vec![p.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let Ok(m) = e.metadata() else { continue };
            if m.is_dir() {
                stack.push(e.path());
            } else {
                bytes += m.blocks() * 512;
                files += 1;
            }
        }
    }
    (bytes, files)
}

/// Remove a directory tree the harness created (always under the bench
/// directory: refuses anything else).
pub fn remove_tree(p: &Path, bench_root: &Path) -> Result<()> {
    let dotdot = p.components().any(|c| matches!(c, std::path::Component::ParentDir));
    if dotdot || !p.starts_with(bench_root) || p == bench_root {
        return Err(anyhow!("refusing to remove {} (outside {})", p.display(), bench_root.display()));
    }
    if p.exists() {
        // Sandboxes may hold read-only directories.
        let _ = Command::new("chmod").arg("-R").arg("u+w").arg(p).status();
        std::fs::remove_dir_all(p).with_context(|| format!("remove {}", p.display()))?;
    }
    Ok(())
}

/// This process's peak RSS (VmHWM, KiB). A child spawned with vfork and
/// exec starts its `ru_maxrss` at this value (Linux keeps the high-water
/// mark of the mm it replaces at exec), so no measured RSS can read below
/// it: the report states it as the floor.
pub fn own_hwm_kib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmHWM:"))
                .and_then(|l| l.split_whitespace().nth(1).and_then(|n| n.parse().ok()))
        })
        .unwrap_or(0)
}
