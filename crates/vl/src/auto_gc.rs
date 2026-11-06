//! Background maintenance (`docs/design/scale/4-background-cleanup-streaming.md`):
//! after a command, start `vl gc --auto` detached when the store needs it
//! ([`veil_core::maintenance::auto_due`]), and print what such a run did.
//!
//! Never inside `vl serve` or a mount (they do not finish through here),
//! never for a bare repository (an old path remote), never when `VEIL_GC_AUTO=0`,
//! and by default not when `CI` is set (`VEIL_GC_AUTO=1` turns it on
//! there). The child runs in its own process group at `nice 10` (and, on
//! Linux, idle I/O priority), and writes to `.veil/local/maintenance.log`
//! (0600, kept to 1 MiB).

use std::{io::Write, path::Path, time::Duration};

use anyhow::Result;

use crate::ctx::Ctx;

/// The log of background runs, under `.veil/`.
const LOG: &str = "local/maintenance.log";
/// The log is started afresh beyond this.
const LOG_LIMIT: u64 = 1 << 20;
/// No second run is started this soon after one (loose objects younger
/// than this are not packed by it anyway).
const AGAIN_AFTER: Duration = veil_core::maintenance::CONSOLIDATE_AFTER;

/// Whether this environment allows background runs.
fn allowed() -> bool {
    match std::env::var("VEIL_GC_AUTO").ok().as_deref() {
        Some("0") => false,
        Some("1") => true,
        _ => std::env::var_os("CI").is_none(),
    }
}

/// After a command: start `vl gc --auto` if maintenance is due. Best
/// effort: nothing here fails the command.
pub fn maybe_spawn(ctx: &Ctx) {
    if ctx.bare || !allowed() {
        return;
    }
    let Ok(Some(why)) = veil_core::maintenance::auto_due(&ctx.repo, veil_core::now_millis()) else { return };
    let veil = ctx.root.join(".veil");
    let log = veil.join(LOG);
    let recent = std::fs::metadata(&log)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.elapsed().ok())
        .is_some_and(|age| age < AGAIN_AFTER);
    if recent {
        return;
    }
    let _ = spawn(&ctx.root, &log, &why);
}

fn spawn(root: &Path, log: &Path, why: &str) -> std::io::Result<()> {
    let mut out = open_log(log)?;
    writeln!(out, "[{}] vl gc --auto: {why}", epoch_secs())?;
    let err = out.try_clone()?;
    let exe = std::env::current_exe()?;
    let mut cmd = std::process::Command::new(exe);
    cmd.args(["gc", "--auto"])
        .current_dir(root)
        // The child must not start another one.
        .env("VEIL_GC_AUTO", "0")
        .stdin(std::process::Stdio::null())
        .stdout(out)
        .stderr(err);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
        // SAFETY: only async-signal-safe calls (`setpriority`, `syscall`)
        // between fork and exec; failures are ignored.
        unsafe {
            cmd.pre_exec(|| {
                libc::setpriority(libc::PRIO_PROCESS, 0, 10);
                #[cfg(target_os = "linux")]
                {
                    // IOPRIO_WHO_PROCESS, this process, IOPRIO_CLASS_IDLE.
                    libc::syscall(libc::SYS_ioprio_set, 1, 0, 3 << 13);
                }
                Ok(())
            });
        }
    }
    cmd.spawn().map(drop)
}

/// The log, opened for appending (0600), emptied first once it passed
/// [`LOG_LIMIT`].
fn open_log(log: &Path) -> std::io::Result<std::fs::File> {
    if let Some(dir) = log.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut o = std::fs::OpenOptions::new();
    o.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let f = o.open(log)?;
    if f.metadata()?.len() > LOG_LIMIT {
        f.set_len(0)?;
    }
    Ok(f)
}

/// Seconds since the epoch, for the log's lines.
fn epoch_secs() -> String {
    format!("{}", veil_core::now_millis() / 1000)
}

/// `vl gc --auto`: run maintenance as the background does and say what
/// it did (into the log).
pub fn run(ctx: &mut Ctx) -> Result<()> {
    match veil_core::maintenance::auto(&mut ctx.repo, veil_core::now_millis())? {
        None => println!("another gc is running, or the repository is not maintained in the background"),
        Some(r) => {
            let g = &r.gc;
            println!(
                "packed {} loose object(s), merged {} pack(s), removed {} leftover(s){}",
                g.consolidated,
                g.merged,
                g.debris_removed,
                if r.pruned {
                    format!("; pruned: {} deleted, {} pending deletion", g.deleted, g.pending)
                } else {
                    String::new()
                }
            );
        }
    }
    Ok(())
}
