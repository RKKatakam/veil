//! The directories `vl ws exec` runs commands in.
//!
//! **A named workspace** has one persistent sandbox,
//! `.veil/local/sandboxes/<ws>/files` ([`veil_core::sandbox`]): kept between
//! runs, synced to the workspace's tree before each run (only what changed
//! is rewritten, by copy-on-write clones where the filesystem has them) and
//! removed by `vl ws rm`. A run holds the sandbox's lock from start to end:
//! a second `vl ws exec` in the same workspace waits for it. A run that
//! cannot finish (an error, `kill -9`, a crash) leaves the sandbox marked as
//! running, and it is wiped: by this process on an error, by the reaper (see
//! below) when the process dies, or by the next run when both died. Ctrl-C
//! reaches the command only; `vl` then records what it left, like any other
//! exit.
//!
//! **`--ephemeral`** gets a throwaway directory under `$TMPDIR`, removed
//! when `vl` exits:
//!
//! * The directory is created `0700` under `$TMPDIR` (an exclusive create:
//!   nobody can pre-plant it), and before the command runs everything in it
//!   is restricted to the user (directories and executables `0700`, files
//!   `0600`).
//! * As a last resort (reaper killed as well, power loss), every `ws exec`
//!   first sweeps throwaway sandboxes of the same user whose owning `vl`
//!   process no longer exists. The owner's pid is part of the directory
//!   name; liveness is `/proc/<pid>` on Linux and `kill(pid, 0)` on macOS
//!   ([`veil_core::lock::process_alive`]). `vl doctor` lists them too.
//!
//! On macOS `$TMPDIR` is a per-user directory under `/var/folders` (which
//! the system cleans after three days without access) rather than `/tmp`.
//!
//! Both hold plaintext: cloaked files, and with `--with-isolated` the
//! isolated secrets from the vault. A tiny **reaper** process (this binary,
//! re-executed with [`REAPER_ARG`]) watches a pipe whose only writer is this
//! process. When `vl` exits for any reason, `kill -9` included, the kernel
//! closes the pipe; unless `vl` said it finished cleanly, the reaper removes
//! the throwaway directory, or wipes the persistent sandbox if the run that
//! died still owns it. It runs in its own process group, so a Ctrl-C aimed
//! at the command does not kill it too.

use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, ExitCode, Stdio},
};

use anyhow::{anyhow, bail, Context, Result};
use veil_core::{
    builder::{BuildReport, INJECTED_RULE},
    checkout::CheckoutReport,
    sandbox::{self as core, Loaded, Manifest, SandboxPaths},
    statcache::StatCache,
    vfs::{private_dir, CloneSources, SandboxFs, SandboxLock, StorageBackend},
    workspace::SnapshotOptions,
    Repo, VPath,
};

use crate::{
    ctx::{print_checkout_problems, print_working_copy_warnings, Ctx},
    render::{dim, one_line, print_build_warnings, safe, warn, yellow},
};

/// Hidden first argument that turns `vl` into a sandbox reaper.
pub const REAPER_ARG: &str = "__veil-sandbox-reaper";
/// Reaper mode for a persistent sandbox: `REAPER_ARG --persistent <dir> <run>`.
const PERSISTENT_ARG: &str = "--persistent";
/// What `vl` writes to the reaper when the run finished cleanly.
const KEEP: u8 = b'K';

const PREFIX: &str = "veil-ws-";

/// `vl ws exec`.
pub struct Exec<'a> {
    pub name: Option<&'a str>,
    pub ephemeral: bool,
    pub rev: &'a str,
    pub message: &'a str,
    pub with_isolated: bool,
    pub command: &'a [String],
}

pub fn exec(ctx: &mut Ctx, a: &Exec<'_>) -> Result<ExitCode> {
    if a.ephemeral {
        return exec_ephemeral(ctx, a);
    }
    let name = a.name.ok_or_else(|| anyhow!("give a workspace name or --ephemeral"))?;
    if name == ctx.ws {
        bail!("workspace '{name}' is attached to the project directory; just run the command");
    }
    ctx.repo.workspace_wc(name)?;
    exec_persistent(ctx, name, a)
}

// ---- persistent sandboxes --------------------------------------------------

/// A run of a persistent sandbox. Unless [`PersistentRun::finish`] is called
/// it wipes the sandbox when dropped (an error part way: the files may be
/// anything, injected secrets included).
struct PersistentRun {
    paths: SandboxPaths,
    reaper: Option<Child>,
    lock: Option<SandboxLock>,
    done: bool,
}

impl PersistentRun {
    fn finish(&mut self) {
        self.done = true;
        self.release(true);
    }

    /// Tell the reaper (with `KEEP` if nothing is left for it to do) and
    /// let the lock go.
    fn release(&mut self, keep: bool) {
        if let Some(mut r) = self.reaper.take() {
            if let Some(mut stdin) = r.stdin.take() {
                if keep {
                    let _ = stdin.write_all(&[KEEP]);
                }
            }
            if keep {
                let _ = r.wait();
            }
        }
        self.lock = None;
    }
}

impl Drop for PersistentRun {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        match core::wipe(&self.paths) {
            Ok(()) => self.release(true),
            Err(e) => {
                warn(&format!(
                    "could not remove the sandbox {} after a failed run: {e}; the next `vl ws exec` rebuilds it",
                    self.paths.files.display()
                ));
                // Lock first: the reaper takes it before trying again.
                self.lock = None;
                if let Some(mut r) = self.reaper.take() {
                    drop(r.stdin.take());
                }
            }
        }
    }
}

/// Restricts the files created while it lives to the user (`umask 077`).
struct PrivateUmask(#[cfg(unix)] libc::mode_t);

impl PrivateUmask {
    fn set() -> PrivateUmask {
        // SAFETY: umask has no preconditions and cannot fail.
        #[cfg(unix)]
        return PrivateUmask(unsafe { libc::umask(0o077) });
        #[cfg(not(unix))]
        PrivateUmask()
    }
}

impl Drop for PrivateUmask {
    fn drop(&mut self) {
        // SAFETY: as above.
        #[cfg(unix)]
        unsafe {
            libc::umask(self.0);
        }
    }
}

fn vault_files(repo: &Repo) -> Result<Vec<(String, Vec<u8>)>> {
    let mut files = Vec::new();
    for (p, hexdata) in repo.vault_load()?.files {
        files.push((p, hex::decode(hexdata)?));
    }
    Ok(files)
}

fn exec_persistent(ctx: &mut Ctx, name: &str, a: &Exec<'_>) -> Result<ExitCode> {
    // Throwaway sandboxes of dead `vl` processes may hold secrets.
    sweep_stale(&std::env::temp_dir());
    let paths = SandboxPaths::new(&ctx.root, name);
    let base_dir = core::sandboxes_dir(&ctx.root);
    private_dir(&base_dir).with_context(|| format!("creating {}", base_dir.display()))?;
    private_dir(&paths.dir).with_context(|| format!("creating {}", paths.dir.display()))?;
    let lock = SandboxLock::acquire(&paths.lock, || {
        eprintln!(
            "{} another `vl ws exec` is running in workspace {}; waiting for it to finish",
            dim("waiting:"),
            safe(name)
        )
    })
    .with_context(|| format!("locking {}", paths.lock.display()))?;
    // The workspace may have moved, or gone, while we waited.
    ctx.repo.reload()?;
    let base = ctx.repo.workspace_wc(name)?;

    let loaded = paths.load_manifest();
    let (mut m, mut cache) = match core::rebuild_reason(&ctx.repo, &paths, name, &loaded) {
        None => match loaded {
            Loaded::Found(m) => (*m, paths.load_cache()),
            _ => unreachable!("only a found manifest is reused"),
        },
        Some(why) => {
            if !why.is_empty() {
                eprintln!("{} the sandbox of workspace {}: {why}", yellow("Rebuilding"), safe(name));
            }
            core::wipe(&paths).with_context(|| format!("removing {}", paths.files.display()))?;
            (Manifest::new(name), StatCache::new())
        }
    };
    let run_id = hex::encode(veil_core::crypto::random_bytes::<8>());
    m.running = Some(run_id.clone());
    m.boot = veil_core::lock::boot_identity();
    paths.save_manifest(&m)?;
    let mut run = PersistentRun {
        reaper: spawn_reaper(&[PERSISTENT_ARG.as_ref(), paths.dir.as_os_str(), run_id.as_ref()]),
        paths: paths.clone(),
        lock: Some(lock),
        done: false,
    };

    let fs = SandboxFs::new(
        &paths.files,
        Some(CloneSources::new((*ctx.fs).clone(), ctx.stat_cache().clone())),
        true,
    );
    let synced = ctx.repo.snapshot(&base)?.tree;
    let (co, injection) = {
        let _umask = PrivateUmask::set();
        private_dir(&paths.files)?;
        let co = core::sync(&ctx.repo, &fs, &mut m, &synced, &mut cache)?;
        core::vouch_written(ctx.repo.store(), &fs, &synced, &co, &mut cache, core::VouchWait::IfCheaper)?;
        let injection = match a.with_isolated {
            true => Some(core::inject(&fs, &vault_files(&ctx.repo)?)?),
            false => None,
        };
        (co, injection)
    };
    print_sync(&co, &fs);
    if let Some(inj) = &injection {
        for (p, why) in &inj.skipped {
            warn(&format!("{} was not injected: {why}", safe(p)));
        }
    }

    eprintln!("{} {} in {}", dim("running"), a.command.join(" "), paths.files.display());
    let code = match run_command(&paths.files, &paths.dir, a.command) {
        Ok(code) => code,
        Err(e) => {
            // Nothing ran: the sandbox is still the workspace's tree. Take
            // the injected files out again and keep it.
            if let Some(inj) = &injection {
                let c = core::remove_injected(ctx.repo.store(), &fs, &synced, &synced, inj, &BuildReport::default(), &mut cache)?;
                if !c.failed.is_empty() {
                    return Err(e);
                }
            }
            m.snapshot = Some(base);
            m.running = None;
            paths.save_manifest(&m)?;
            let _ = paths.save_cache(&mut cache);
            run.finish();
            return Err(e);
        }
    };

    let injected = injection.as_ref().map(|i| &i.secrets);
    let out = ctx.repo.snapshot_workspace_with(
        name,
        &fs,
        SnapshotOptions {
            cache: Some(&mut cache),
            injected,
            materialised: Some(&m.materialised),
            expected_wc: Some(base),
            ..Default::default()
        },
    )?;
    let (recorded, report, changed) = if out.superseded {
        // Someone moved the workspace while the command ran: recording the
        // sandbox now would revert what they did. Keep the result as a
        // change of its own, on top of what the command started from.
        let desc = if a.message.is_empty() { "`vl ws exec` result" } else { a.message };
        let (id, report) = ctx.repo.commit_fs_as_child_injected(base, &fs, desc, injected)?;
        let change = ctx.repo.snapshot(&id)?.change_id.short();
        warn(&format!(
            "workspace '{}' moved while the command ran; its result was saved as change {change} on top of the snapshot it started from, \
             not into the workspace",
            safe(name)
        ));
        (id, report, false)
    } else {
        (out.snapshot, out.report, out.changed)
    };
    print_build_warnings(&report);
    print_working_copy_warnings(&report);
    let recorded_tree = ctx.repo.snapshot(&recorded)?.tree;
    if !out.superseded && !a.message.is_empty() {
        ctx.repo.describe(recorded, a.message)?;
    }

    if let Some(inj) = &injection {
        let c = core::remove_injected(ctx.repo.store(), &fs, &synced, &recorded_tree, inj, &report, &mut cache)?;
        if let Some((p, why)) = c.failed.first() {
            // The secret may still be there: the sandbox goes (`run` drops
            // unfinished).
            bail!(
                "could not take the injected file {} out of the sandbox again ({why}); the sandbox was removed",
                safe(p.as_str())
            );
        }
        let copies: Vec<String> = c
            .removed
            .iter()
            .chain(&c.restored)
            .filter(|p| !inj.paths.contains(p))
            .map(|p| safe(p.as_str()).into_owned())
            .collect();
        if !copies.is_empty() {
            eprintln!(
                "  {} {} (they held an injected secret; quarantined and taken out of the sandbox)",
                yellow("cleaned"),
                copies.join(", ")
            );
        }
    }

    m.tree = Some(recorded_tree);
    // After a superseded run the files are the saved change's: the next run
    // syncs them to the workspace.
    m.snapshot = Some(if out.superseded { recorded } else { ctx.repo.workspace_wc(name)? });
    m.quarantined = report
        .quarantined
        .iter()
        .filter(|(_, f)| !f.iter().any(|f| f.rule == INJECTED_RULE))
        .map(|(p, _)| p.as_str().to_string())
        .collect();
    m.running = None;
    paths.save_manifest(&m)?;
    if let Err(e) = paths.save_cache(&mut cache) {
        warn(&format!("could not save the sandbox's stat cache: {e}"));
    }
    run.finish();

    let wc = ctx.repo.workspace_wc(name)?;
    // stderr: stdout belongs to the sandboxed command.
    if out.superseded {
        eprintln!("Saved {}", one_line(&ctx.repo, &recorded));
    } else {
        eprintln!("{} {}", if changed { "Recorded" } else { "No changes in" }, one_line(&ctx.repo, &wc));
    }
    Ok(ExitCode::from(code.clamp(0, 255) as u8))
}

fn print_sync(r: &CheckoutReport, fs: &SandboxFs) {
    if r.written + r.removed > 0 {
        let (cloned, _) = fs.cloned();
        let clones = if cloned > 0 { format!(" ({cloned} as copy-on-write clones)") } else { String::new() };
        eprintln!("{} sandbox: {} files written{clones}, {} removed", dim("synced"), r.written, r.removed);
    }
    print_checkout_problems(r);
}

/// `vl ws rm`: the workspace's sandbox goes with it. Refused while a
/// `vl ws exec` runs in it, and (without `force`) while it holds files the
/// builder quarantined, which are in no snapshot.
pub fn remove_workspace(ctx: &mut Ctx, name: &str, force: bool) -> Result<bool> {
    let paths = SandboxPaths::new(&ctx.root, name);
    let exists = std::fs::symlink_metadata(&paths.dir).is_ok();
    let lock = if exists {
        match SandboxLock::try_acquire(&paths.lock) {
            Ok(Some(l)) => Some(l),
            Ok(None) => bail!(
                "a `vl ws exec` is running in workspace '{}'; let it finish, then remove the workspace",
                safe(name)
            ),
            Err(e) => bail!("cannot lock the sandbox of workspace '{}': {e}", safe(name)),
        }
    } else {
        None
    };
    if let (true, false, Loaded::Found(m)) = (exists, force, paths.load_manifest()) {
        if m.running.is_none() && !m.quarantined.is_empty() {
            let shown: Vec<String> = m.quarantined.iter().take(10).map(|p| safe(p).into_owned()).collect();
            bail!(
                "the sandbox of workspace '{n}' holds files that were quarantined (they look like they contain a secret) and are in no snapshot: {}. \
                 Look at them with `vl ws exec {n} -- cat <file>`; `vl ws rm --force {n}` removes the workspace and them",
                shown.join(", "),
                n = safe(name)
            );
        }
    }
    ctx.repo.remove_workspace(name)?;
    if exists {
        if let Err(e) = core::remove(&paths) {
            warn(&format!(
                "could not remove the sandbox {}: {e}; delete it with `rm -rf`",
                paths.dir.display()
            ));
            return Ok(false);
        }
    }
    drop(lock);
    Ok(exists)
}

// ---- running the command ---------------------------------------------------

/// Run `command` in `dir` and return its exit status (128 + n for a
/// signal). Git never looks above `ceiling` for a repository (the sandbox
/// lives inside the project directory). Ctrl-C and Ctrl-\ go to the command
/// only: `vl` waits for it and records what it left.
fn run_command(dir: &Path, ceiling: &Path, command: &[String]) -> Result<i32> {
    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..]).current_dir(dir);
    let mut ceilings = ceiling.as_os_str().to_owned();
    if let Some(old) = std::env::var_os("GIT_CEILING_DIRECTORIES").filter(|v| !v.is_empty()) {
        ceilings.push(":");
        ceilings.push(old);
    }
    cmd.env("GIT_CEILING_DIRECTORIES", ceilings);
    let interrupts = Interrupts::to_child(&mut cmd);
    let status = cmd.status().with_context(|| format!("failed to run {}", command[0]));
    drop(interrupts);
    let status = status?;
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            return Ok(128 + sig);
        }
    }
    Ok(status.code().unwrap_or(1))
}

/// While it lives, `vl` ignores SIGINT and SIGQUIT; the child gets the
/// dispositions `vl` had.
struct Interrupts {
    #[cfg(unix)]
    old: [(libc::c_int, libc::sighandler_t); 2],
}

impl Interrupts {
    fn to_child(cmd: &mut Command) -> Interrupts {
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            let mut old = [(libc::SIGINT, libc::SIG_DFL), (libc::SIGQUIT, libc::SIG_DFL)];
            for (sig, prev) in old.iter_mut() {
                // SAFETY: installs SIG_IGN, restored on drop; no handler code runs.
                let p = unsafe { libc::signal(*sig, libc::SIG_IGN) };
                *prev = if p == libc::SIG_ERR { libc::SIG_DFL } else { p };
            }
            let restore = old;
            // SAFETY: the closure only calls signal(2), which is
            // async-signal-safe, between fork and exec.
            unsafe {
                cmd.pre_exec(move || {
                    for (sig, prev) in restore {
                        libc::signal(sig, prev);
                    }
                    Ok(())
                });
            }
            Interrupts { old }
        }
        #[cfg(not(unix))]
        {
            let _ = cmd;
            Interrupts {}
        }
    }
}

impl Drop for Interrupts {
    fn drop(&mut self) {
        #[cfg(unix)]
        for (sig, prev) in self.old {
            // SAFETY: restores the disposition saved above.
            unsafe {
                libc::signal(sig, prev);
            }
        }
    }
}

// ---- ephemeral sandboxes ---------------------------------------------------

fn exec_ephemeral(ctx: &mut Ctx, a: &Exec<'_>) -> Result<ExitCode> {
    let base_snapshot = ctx.rev(a.rev)?;
    let sb = Sandbox::create("ephemeral")?;
    let dir = sb.path().to_path_buf();
    let sandbox = SandboxFs::new(&dir, None, false);
    let result = (|| -> Result<i32> {
        let tree = ctx.repo.snapshot(&base_snapshot)?.tree;
        ctx.repo.checkout_tree(&sandbox, None, &tree)?;
        let mut injected = None;
        if a.with_isolated {
            let files = vault_files(&ctx.repo)?;
            for (p, data) in &files {
                sandbox.write(&VPath::new(p)?, data)?;
            }
            // Whatever the command does with these, they must not be
            // recorded under another name.
            injected = Some(veil_core::builder::InjectedSecrets::from_files(
                files.iter().map(|(p, d)| (p.as_str(), d.as_slice())),
            ));
        }
        sb.make_private()?;
        eprintln!("{} {} in {}", dim("running"), a.command.join(" "), dir.display());
        let code = run_command(&dir, &dir, a.command)?;
        let (id, report) = ctx
            .repo
            .commit_fs_as_child_injected(base_snapshot, &sandbox, a.message, injected.as_ref())?;
        print_build_warnings(&report);
        print_working_copy_warnings(&report);
        eprintln!("Recorded {}", one_line(&ctx.repo, &id));
        Ok(code)
    })();
    drop(sb);
    let code = result?;
    Ok(ExitCode::from(code.clamp(0, 255) as u8))
}

/// A throwaway sandbox directory under `$TMPDIR` (`--ephemeral`).
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
        let reaper = spawn_reaper(&[dir.as_os_str()]);
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
        let _ = veil_core::vfs::remove_tree(&self.dir);
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

// ---- the reaper ------------------------------------------------------------

/// Start a reaper with `args` (after [`REAPER_ARG`]). Best effort: without
/// it, cleanup still happens in-process, through [`sweep_stale`] and, for
/// persistent sandboxes, at the next run.
fn spawn_reaper(args: &[&std::ffi::OsStr]) -> Option<Child> {
    let exe = std::env::current_exe().ok()?;
    let mut cmd = Command::new(exe);
    cmd.arg(REAPER_ARG)
        .args(args)
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

/// Is `dir` one of our throwaway sandboxes (a `veil-ws-*` directory
/// directly in the temp directory)? The reaper and the sweep never remove
/// anything else.
fn is_sandbox_path(dir: &Path) -> bool {
    dir.parent() == Some(std::env::temp_dir().as_path())
        && dir
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with(PREFIX))
}

/// Is `dir` a persistent sandbox (`<repo>/.veil/local/sandboxes/<ws>`, a
/// real directory of ours)? The reaper never wipes anything else.
fn is_persistent_sandbox(dir: &Path) -> bool {
    let shape = dir.parent().is_some_and(core::is_sandboxes_dir)
        && dir
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| core::workspace_of(n).is_some());
    if !shape {
        return false;
    }
    match std::fs::symlink_metadata(dir) {
        #[cfg(unix)]
        Ok(m) => {
            use std::os::unix::fs::MetadataExt;
            // SAFETY: geteuid has no preconditions and cannot fail.
            m.is_dir() && m.uid() == unsafe { libc::geteuid() }
        }
        #[cfg(not(unix))]
        Ok(m) => m.is_dir(),
        Err(_) => false,
    }
}

/// Body of the reaper process: wait for the parent to go away, then clean
/// up unless it said it finished cleanly.
pub fn reaper_main(args: Vec<std::ffi::OsString>) -> ExitCode {
    let mut buf = [0u8; 64];
    let mut keep = false;
    let mut stdin = std::io::stdin().lock();
    while let Ok(n) = stdin.read(&mut buf) {
        if n == 0 {
            break;
        }
        keep |= buf[..n].contains(&KEEP);
    }
    if keep {
        return ExitCode::SUCCESS;
    }
    match args.as_slice() {
        [mode, dir, run] if mode == PERSISTENT_ARG => {
            let dir = Path::new(dir);
            if is_persistent_sandbox(dir) {
                reap_persistent(dir, &run.to_string_lossy());
            }
        }
        [dir] => {
            let dir = Path::new(dir);
            if is_sandbox_path(dir) {
                let _ = veil_core::vfs::remove_tree(dir);
            }
        }
        _ => {}
    }
    ExitCode::SUCCESS
}

/// The run `run` of the sandbox in `dir` died: wipe the sandbox, unless a
/// later run has already taken it over (it rebuilds it itself).
fn reap_persistent(dir: &Path, run: &str) {
    let paths = SandboxPaths::at(dir.to_path_buf());
    let Ok(_lock) = SandboxLock::acquire(&paths.lock, || {}) else { return };
    if let Loaded::Found(m) = paths.load_manifest() {
        if m.running.as_deref() == Some(run) {
            let _ = core::wipe(&paths);
        }
    }
}

/// A throwaway sandbox directory left behind by a `vl` process that no
/// longer runs.
#[derive(Debug)]
pub struct StaleSandbox {
    pub path: PathBuf,
    pub pid: u32,
}

/// Sandboxes in `base` owned by this user whose owning `vl` process is gone
/// (only where that can be told: a Unix with a working pid check).
pub fn stale_sandboxes(base: &Path) -> Vec<StaleSandbox> {
    let mut out = Vec::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no preconditions and cannot fail.
        let me = unsafe { libc::geteuid() };
        let Ok(entries) = std::fs::read_dir(base) else { return out };
        for entry in entries.flatten() {
            let Some(name) = entry.file_name().to_str().map(str::to_string) else { continue };
            let Some(rest) = name.strip_prefix(PREFIX) else { continue };
            let mut parts = rest.rsplitn(3, '-');
            let (Some(_rand), Some(pid), Some(_label)) = (parts.next(), parts.next(), parts.next()) else { continue };
            let Ok(pid) = pid.parse::<u32>() else { continue };
            if pid == std::process::id() || veil_core::lock::process_alive(pid) != Some(false) {
                continue;
            }
            let path = entry.path();
            match std::fs::symlink_metadata(&path) {
                Ok(m) if m.is_dir() && m.uid() == me => out.push(StaleSandbox { path, pid }),
                _ => {}
            }
        }
    }
    #[cfg(not(unix))]
    let _ = base;
    out
}

/// Remove sandboxes of this user whose owning `vl` process is gone.
fn sweep_stale(base: &Path) {
    for s in stale_sandboxes(base) {
        let _ = veil_core::vfs::remove_tree(&s.path);
    }
}

/// What `vl doctor` says about the persistent sandboxes of the repository
/// at `root`: `(problem, line)` per sandbox.
pub fn persistent_status(root: &Path, repo: Option<&Repo>) -> Vec<(bool, String)> {
    let mut out = Vec::new();
    for (ws, paths) in core::list(root) {
        let shown = paths.dir.display();
        let Some(ws) = ws else {
            out.push((true, format!("{shown}: not the name of a workspace; delete it with `rm -rf`")));
            continue;
        };
        if let Some(repo) = repo {
            if !repo.view().workspaces.contains_key(&ws) {
                out.push((
                    true,
                    format!(
                        "{shown}: sandbox of workspace '{}', which no longer exists; it may hold plaintext of cloaked files. Delete it with `rm -rf`",
                        safe(&ws)
                    ),
                ));
                continue;
            }
        }
        let busy = matches!(SandboxLock::try_acquire(&paths.lock), Ok(None));
        match paths.load_manifest() {
            Loaded::Found(m) if m.running.is_some() && !busy => out.push((
                true,
                format!("{shown}: a run was interrupted; the next `vl ws exec {}` rebuilds it", safe(&ws)),
            )),
            Loaded::Found(m) if !m.quarantined.is_empty() => out.push((
                false,
                format!("{shown}: holds {} quarantined file(s) that are in no snapshot", m.quarantined.len()),
            )),
            Loaded::Corrupt(why) => out.push((true, format!("{shown}: unreadable manifest ({why}); the next run rebuilds it"))),
            _ => out.push((false, format!("{shown}: workspace '{}'{}", safe(&ws), if busy { " (a run is in progress)" } else { "" }))),
        }
    }
    out
}
