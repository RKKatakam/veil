//! The throwaway directory `vl ws exec` materialises a workspace into.
//!
//! It holds plaintext: cloaked files, and with `--with-isolated` the
//! isolated secrets from the vault. So it is private and never outlives us:
//!
//! * The directory is created `0700` under `$TMPDIR` (an exclusive create:
//!   nobody can pre-plant it), and before the command runs everything in it
//!   is restricted to the user (directories and executables `0700`, files
//!   `0600`).
//! * A tiny **reaper** process (this binary, re-executed with
//!   [`REAPER_ARG`]) watches a pipe whose only writer is this process. When
//!   `vl` exits for any reason, `kill -9` included, the kernel closes the
//!   pipe and the reaper removes the directory. It runs in its own process
//!   group, so a Ctrl-C aimed at the command does not kill it too.
//! * As a last resort (reaper killed as well, power loss), every `ws exec`
//!   first sweeps sandboxes of the same user whose owning `vl` process no
//!   longer exists. The owner's pid is part of the directory name.

use std::{
    io::Read,
    path::{Path, PathBuf},
    process::{Child, Command, ExitCode, Stdio},
};

use anyhow::{Context, Result};

/// Hidden first argument that turns `vl` into a sandbox reaper.
pub const REAPER_ARG: &str = "__veil-sandbox-reaper";

const PREFIX: &str = "veil-ws-";

pub struct Sandbox {
    dir: PathBuf,
    reaper: Option<Child>,
}

impl Sandbox {
    pub fn create(label: &str) -> Result<Sandbox> {
        let base = std::env::temp_dir();
        std::fs::create_dir_all(&base).with_context(|| format!("creating {}", base.display()))?;
        sweep_stale(&base);
        let dir = base.join(format!(
            "{PREFIX}{label}-{}-{}",
            std::process::id(),
            hex::encode(veil_core::crypto::random_bytes::<4>())
        ));
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(&dir)
            .with_context(|| format!("creating sandbox {}", dir.display()))?;
        let reaper = spawn_reaper(&dir);
        Ok(Sandbox { dir, reaper })
    }

    pub fn path(&self) -> &Path {
        &self.dir
    }

    /// Restrict everything materialised so far to the current user.
    pub fn make_private(&self) -> Result<()> {
        #[cfg(unix)]
        restrict(&self.dir)?;
        Ok(())
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
        if let Some(mut r) = self.reaper.take() {
            drop(r.stdin.take()); // EOF: the reaper finds nothing left and exits
            let _ = r.wait();
        }
    }
}

#[cfg(unix)]
fn restrict(dir: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let set = |p: &Path, mode: u32| {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).with_context(|| format!("chmod {}", p.display()))
    };
    set(dir, 0o700)?;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let meta = std::fs::symlink_metadata(&path)?;
        if meta.is_dir() {
            restrict(&path)?;
        } else if meta.is_file() {
            let exec = meta.permissions().mode() & 0o100 != 0;
            set(&path, if exec { 0o700 } else { 0o600 })?;
        }
    }
    Ok(())
}

/// Start the reaper for `dir`. Best effort: without it, cleanup still
/// happens in-process and through [`sweep_stale`].
fn spawn_reaper(dir: &Path) -> Option<Child> {
    let exe = std::env::current_exe().ok()?;
    let mut cmd = Command::new(exe);
    cmd.arg(REAPER_ARG)
        .arg(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    cmd.spawn().ok()
}

/// Is `dir` one of our sandboxes (a `veil-ws-*` directory directly in the
/// temp directory)? The reaper and the sweep never remove anything else.
fn is_sandbox_path(dir: &Path) -> bool {
    dir.parent() == Some(std::env::temp_dir().as_path())
        && dir
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with(PREFIX))
}

/// Body of the reaper process: wait for the parent to go away, then remove
/// the sandbox.
pub fn reaper_main(dir: Option<&std::ffi::OsStr>) -> ExitCode {
    let mut buf = [0u8; 64];
    let mut stdin = std::io::stdin().lock();
    while let Ok(n) = stdin.read(&mut buf) {
        if n == 0 {
            break;
        }
    }
    if let Some(dir) = dir.map(Path::new) {
        if is_sandbox_path(dir) {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
    ExitCode::SUCCESS
}

/// Remove sandboxes of this user whose owning `vl` process is gone (only
/// where that can be told reliably: Linux `/proc`).
fn sweep_stale(base: &Path) {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        let Ok(me) = std::fs::metadata("/proc/self") else { return };
        let Ok(entries) = std::fs::read_dir(base) else { return };
        for entry in entries.flatten() {
            let Some(name) = entry.file_name().to_str().map(str::to_string) else { continue };
            let Some(rest) = name.strip_prefix(PREFIX) else { continue };
            let mut parts = rest.rsplitn(3, '-');
            let (Some(_rand), Some(pid), Some(_label)) = (parts.next(), parts.next(), parts.next()) else { continue };
            let Ok(pid) = pid.parse::<u32>() else { continue };
            if pid == std::process::id() || Path::new(&format!("/proc/{pid}")).exists() {
                continue;
            }
            let path = entry.path();
            match std::fs::symlink_metadata(&path) {
                Ok(m) if m.is_dir() && m.uid() == me.uid() => {
                    let _ = std::fs::remove_dir_all(&path);
                }
                _ => {}
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = base;
}
