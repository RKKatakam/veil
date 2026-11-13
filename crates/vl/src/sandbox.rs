//! The directories `vl ws exec` runs commands in.
//!
//! **A named workspace** has one persistent sandbox,
//! `.veil/local/sandboxes/<ws>/files` ([`veil_core::sandbox`]): kept between
//! runs, synced to the workspace's tree before each run (only what changed
//! is rewritten, by copy-on-write clones where the filesystem has them) and
//! removed by `vl ws rm`. A run holds the sandbox's lock from start to end:
//! a second `vl ws exec` in the same workspace waits for it.
//!
//! **No failure deletes the command's output.** Just before the command
//! starts, the manifest says (durably) that the files hold unrecorded
//! output ([`Pending`]). Whatever happens next (recording fails because the
//! repository is busy, `vl` is killed, the machine restarts), the files
//! stay: the next run, or `vl ws exec NAME --record-only`, records them
//! first. A sandbox that must be rebuilt keeps its unrecorded work
//! ([`core::set_aside`]). Ctrl-C, Ctrl-\, SIGTERM and SIGHUP reach the
//! command only (`vl` forwards the last two to it); `vl` then records what
//! it left, like any other exit.
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
//! closes the pipe; unless `vl` said it finished cleanly, the reaper stops
//! what the confined run left running ([`stop_dead_run`]), then removes
//! the throwaway directory, or, for a persistent sandbox whose run injected
//! secrets, takes the injected files that are still unchanged out again
//! (it never deletes anything else: the rest is the command's output). It
//! runs in its own process group, so a Ctrl-C aimed at the command does not
//! kill it too.
//!
//! **Background processes** a command leaves running (a dev server, a
//! watcher) are not killed when it exits: that is often the point. They
//! can keep writing into the sandbox. A sandbox that was ever given
//! injected secrets keeps its guard ([`core::Guard`]) and applies it to
//! every later recording, and checks every file changed since for copies
//! of them ([`core::scrub`]), so nothing such a process writes can be
//! recorded or stay for a later command to read.

use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, ExitCode, Stdio},
};

use anyhow::{anyhow, bail, Context, Result};
use veil_core::{
    builder::{BuildReport, INJECTED_RULE},
    checkout::CheckoutReport,
    policy::{Policy, POLICY_FILE},
    sandbox::{self as core, Loaded, Manifest, Pending, SandboxPaths, SetAside},
    statcache::StatCache,
    tree::TreeView,
    vfs::{private_dir, restrict as restrict_tree, CloneSources, SandboxFs, SandboxLock, SparseSet, SparseView, StorageBackend},
    workspace::SnapshotOptions,
    ObjectId, Repo, VPath,
};

use crate::{
    confine::Confine,
    ctx::{print_checkout_problems, print_working_copy_warnings, Ctx},
    render::{
        dim, left_out, one_line, policy_edit_held_message, print_build_warnings, print_left_out, safe, warn, yellow, LeftOut,
        QUARANTINE_STATUS,
    },
};

/// Hidden first argument that turns `vl` into a sandbox reaper.
pub const REAPER_ARG: &str = "__veil-sandbox-reaper";
/// Reaper mode for a persistent sandbox: `REAPER_ARG --persistent <dir> <run>`.
const PERSISTENT_ARG: &str = "--persistent";
/// What `vl` writes to the reaper when the run finished cleanly.
const KEEP: u8 = b'K';
/// First byte of the line telling a persistent run's reaper what it
/// injected ([`tell_reaper`]).
const INJECTED: u8 = b'I';

const PREFIX: &str = "veil-ws-";

/// `vl ws exec`.
pub struct Exec<'a> {
    pub name: Option<&'a str>,
    pub ephemeral: bool,
    pub rev: &'a str,
    pub message: &'a str,
    pub with_isolated: bool,
    /// `--only`: the paths of a sparse sandbox, as the user gave them.
    pub only: &'a [String],
    /// `--record-only`: record what an earlier run left unrecorded, run nothing.
    pub record_only: bool,
    /// `--mount`: run over a mount of the workspace ([`crate::mount::for_exec`]).
    pub mount: bool,
    /// Confinement and limits ([`crate::confine`]).
    pub confine: &'a crate::confine::ConfineArgs,
    pub command: &'a [String],
}

/// The `--only` paths as a set of `tree` (`what` names it in errors):
/// repository paths by the CLI's rules (relative to the current directory,
/// never outside the repository), each naming something in `tree`. `None`
/// for none, or for one that is the whole tree.
fn sparse_set(ctx: &Ctx, only: &[String], tree: &ObjectId, what: &str) -> Result<Option<SparseSet>> {
    let mut paths = Vec::new();
    for user in only {
        let p = ctx.repo_path(user).with_context(|| format!("--only {}", safe(user)))?;
        if !p.is_root() && veil_core::tree::lookup(ctx.repo.store(), tree, &p)?.is_none() {
            bail!(
                "--only {}: there is no file or directory {} in {what}",
                safe(user),
                safe(p.as_str())
            );
        }
        paths.push(p);
    }
    Ok(SparseSet::new(paths))
}

/// How a sparse set is shown: `src, tests/unit.rs`.
fn show_set(set: Option<&SparseSet>) -> String {
    match set {
        Some(s) => s.paths().iter().map(|p| safe(p.as_str()).into_owned()).collect::<Vec<_>>().join(", "),
        None => "the whole tree".into(),
    }
}

/// Say which files the command wrote outside the `--only` paths (they are
/// not recorded).
fn warn_strays(set: &SparseSet, strays: &[VPath], removed: bool) {
    if strays.is_empty() {
        return;
    }
    const SHOWN: usize = 20;
    let mut list: Vec<String> = strays.iter().take(SHOWN).map(|p| safe(p.as_str()).into_owned()).collect();
    if strays.len() > SHOWN {
        list.push(format!("and {} more", strays.len() - SHOWN));
    }
    warn(&format!(
        "not recorded: {} file(s) written outside --only {}{}: {}",
        strays.len(),
        show_set(Some(set)),
        if removed { " (removed from the sandbox)" } else { "" },
        list.join(", ")
    ));
}

/// The exit status of a `vl ws exec` whose command exited `code` and whose
/// recording left out the files `left` as secrets (BUG-2171): the
/// command's own status, but [`QUARANTINE_STATUS`] for a 0, so a harness
/// that checks it notices; the files are named on standard error either
/// way, with `hint` (where they are and how to resolve them; `until`: the
/// next run exits 3 while they are there).
fn exec_status(code: i32, left: &[LeftOut], hint: &str, until: bool) -> ExitCode {
    if left.is_empty() {
        return ExitCode::from(code.clamp(0, 255) as u8);
    }
    print_left_out(left, "recorded", hint, until && code == 0);
    match code {
        0 => ExitCode::from(QUARANTINE_STATUS),
        c => ExitCode::from(c.clamp(0, 255) as u8),
    }
}

/// Where a persistent sandbox's quarantined files are, and how to resolve them.
fn persistent_hint(name: &str, paths: &SandboxPaths) -> String {
    format!(
        "they stay in the sandbox of workspace {n} ({}), on this machine only, and are never recorded or pushed. Fix a \
         file there and run again; or, in that workspace (`vl ws switch {n}`), `vl isolate <file>` keeps it local on \
         purpose and, if it is not a secret, `vl expose --force <file>` has the next run record it",
        paths.files.display(),
        n = safe(name)
    )
}

pub fn exec(ctx: &mut Ctx, a: &Exec<'_>) -> Result<ExitCode> {
    // Checked before anything is touched: a run that cannot be confined
    // fails here, with the sandbox and its manifest as they were.
    let confine = |ctx: &Ctx| match a.record_only {
        true => Ok(None),
        false => Confine::prepare(&ctx.root, a.confine),
    };
    if a.ephemeral {
        let c = confine(ctx)?;
        return exec_ephemeral(ctx, a, c.as_ref());
    }
    let name = a.name.ok_or_else(|| anyhow!("give a workspace name or --ephemeral"))?;
    if name == ctx.ws {
        bail!("workspace '{name}' is attached to the project directory; just run the command");
    }
    ctx.repo.workspace_wc(name)?;
    let c = confine(ctx)?;
    if a.mount {
        match crate::mount::fuse_available() {
            Ok(()) => return exec_mounted(ctx, name, a, c.as_ref()),
            Err(why) => eprintln!(
                "{} no mount here ({why}): the sandbox is checked out instead (in a thin clone, fetched from the server; \
                 `--only PATHS` checks out less)",
                yellow("note:")
            ),
        }
    }
    exec_persistent(ctx, name, a, c.as_ref())
}

// ---- mounted sandboxes ------------------------------------------------------

/// `vl ws exec --mount`: the command runs over a mount of the workspace
/// (at the project's path when confined). Nothing is checked out: a file is
/// read, and in a thin clone fetched, when the command reads it. The
/// mount's overlay sees every write, so what is recorded afterwards is
/// exactly what the command changed. The sandbox's lock is held throughout,
/// as for a checked-out run.
fn exec_mounted(ctx: &mut Ctx, name: &str, a: &Exec<'_>, confine: Option<&Confine>) -> Result<ExitCode> {
    let paths = SandboxPaths::new(&ctx.root, name);
    let base_dir = core::sandboxes_dir(&ctx.root);
    private_dir(&base_dir).with_context(|| format!("creating {}", base_dir.display()))?;
    private_dir(&paths.dir).with_context(|| format!("creating {}", paths.dir.display()))?;
    let _lock = SandboxLock::acquire(&paths.lock, || {
        eprintln!(
            "{} another `vl ws exec` is running in workspace {}; waiting for it to finish",
            dim("waiting:"),
            safe(name)
        )
    })
    .with_context(|| format!("locking {}", paths.lock.display()))?;
    ctx.repo.reload()?;
    ctx.repo.workspace_wc(name)?;
    if let Loaded::Found(m) = paths.load_manifest() {
        if m.pending.is_some() {
            bail!(
                "the sandbox of workspace {n} holds the output of an earlier run that is not recorded; `vl ws exec {n} --record-only` records it first",
                n = safe(name)
            );
        }
    }
    let mount = crate::mount::for_exec(&ctx.root, name)?;
    if mount.recovered {
        mount.record().with_context(|| format!("recording what an earlier run left in the mount of workspace {}", safe(name)))?;
        ctx.repo.reload()?;
        eprintln!(
            "{} the output of an earlier `vl ws exec` in workspace {} that did not finish (vl was killed), from its mount: {}",
            yellow("Recorded"),
            safe(name),
            one_line(&ctx.repo, &ctx.repo.workspace_wc(name)?)
        );
    }
    let before = ctx.repo.workspace_wc(name)?;
    print_running(a.command, &mount.dir, confine);
    let layers_dir = paths.dir.join(crate::confine::layers_dir(core::workspace_id(&ctx.repo, name).as_deref()));
    // From here on the mount is recorded (and, if this run made it,
    // unmounted) whatever happens.
    let server = match crate::ws_socket::Server::start(&ctx.root, name, &mount.dir, None, Box::new(crate::ws_socket::Mounted)) {
        Ok(s) => s,
        Err(e) => {
            if let Err(f) = mount.finish() {
                warn(&format!("{f:#}"));
            }
            return Err(e);
        }
    };
    let code = run_command(&mount.dir, &paths.dir, a.command, confine, Some(&layers_dir), Some(&server));
    drop(server);
    let (notes, left) = mount.finish()?;
    for n in notes.iter().filter(|n| !n.starts_with("Recorded ")) {
        warn(&format!("mount of workspace {}: {n}", safe(name)));
    }
    ctx.repo.reload()?;
    let after = ctx.repo.workspace_wc(name)?;
    if after == before {
        eprintln!("No changes in {}", one_line(&ctx.repo, &after));
    } else {
        if !a.message.is_empty() {
            if let Err(e) = ctx.repo.describe(after, a.message) {
                warn(&format!("the result was recorded, but could not be described: {e}"));
            }
        }
        eprintln!("Recorded {}", one_line(&ctx.repo, &ctx.repo.workspace_wc(name)?));
    }
    let hint = format!(
        "they stay in the mount of workspace {n}, on this machine only, and are never recorded or pushed. Fix a file \
         there and run again; or, in that workspace (`vl ws switch {n}`), `vl isolate <file>` keeps it local on purpose \
         and, if it is not a secret, `vl expose --force <file>` has the next run record it",
        n = safe(name)
    );
    Ok(exec_status(code?, &left, &hint, true))
}

// ---- persistent sandboxes --------------------------------------------------

/// A run of a persistent sandbox: holds its lock, and the reaper of a run
/// that injected secrets. Dropped without [`PersistentRun::finish`] (an
/// error, a panic), it deletes nothing: the manifest says what is left to
/// do (`running`: the sync did not finish, the next run rebuilds keeping
/// unrecorded work; `pending`: the command's output is not recorded yet,
/// the next run records it), and the reaper only takes injected files
/// that are still unchanged out again.
struct PersistentRun {
    reaper: Option<Child>,
    lock: Option<SandboxLock>,
}

impl PersistentRun {
    fn finish(&mut self) {
        if let Some(mut r) = self.reaper.take() {
            if let Some(mut stdin) = r.stdin.take() {
                let _ = stdin.write_all(&[KEEP]);
            }
            let _ = r.wait();
        }
        self.lock = None;
    }
}

impl Drop for PersistentRun {
    fn drop(&mut self) {
        // Lock first: the reaper takes it before cleaning up.
        self.lock = None;
        if let Some(mut r) = self.reaper.take() {
            drop(r.stdin.take());
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

/// Did this process's `vl ws exec` fail on the server's refusal of its
/// workspace's tree, before its command ran or its sandbox was written?
/// Only then is a `vl ws exec` run again after the clone moved to its
/// person's current view (BUG-1573).
static NOT_RUN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn refused_before_its_command() -> bool {
    NOT_RUN.load(std::sync::atomic::Ordering::SeqCst)
}

fn exec_persistent(ctx: &mut Ctx, name: &str, a: &Exec<'_>, confine: Option<&Confine>) -> Result<ExitCode> {
    // Throwaway sandboxes of dead `vl` processes may hold secrets.
    sweep_stale(&std::env::temp_dir());
    let started = core::now_ns();
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
    let mut run = PersistentRun { reaper: None, lock: Some(lock) };
    // The workspace may have moved, or gone, while we waited.
    ctx.repo.reload()?;
    ctx.repo.workspace_wc(name)?;

    let loaded = paths.load_manifest();
    if dead_run(&loaded) {
        stop_dead_run(&paths.files);
    }
    let (mut m, mut cache, aside) = match core::rebuild_reason(&ctx.repo, &paths, name, &loaded) {
        None => match loaded {
            Loaded::Found(m) => (*m, paths.load_cache(), SetAside::Nothing),
            _ => unreachable!("only a found manifest is reused"),
        },
        Some(why) if a.record_only => {
            let what = match &loaded {
                Loaded::Found(m) if m.pending.is_some() => format!(
                    "it cannot be recorded ({why}); the next run keeps its files aside, whole"
                ),
                // Whether it holds a run cannot be told (BUG-1574).
                Loaded::Corrupt(_) => format!("{why}, so whether it holds an unrecorded run cannot be told; the next run keeps its files aside, whole"),
                _ => "it holds no unrecorded run".to_string(),
            };
            eprintln!("Nothing to record in the sandbox of workspace {}: {what}", safe(name));
            run.finish();
            return Ok(ExitCode::SUCCESS);
        }
        Some(why) => {
            if !why.is_empty() {
                eprintln!("{} the sandbox of workspace {}: {why}", yellow("Rebuilding"), safe(name));
            }
            let target = ctx.repo.snapshot(&ctx.repo.workspace_wc(name)?)?.tree;
            let aside = core::set_aside(&ctx.repo, &paths, name, &loaded, Some(&target))
                .with_context(|| format!("setting the files of {} aside", paths.files.display()))?;
            if let SetAside::Kept { dir } = &aside {
                warn(&format!(
                    "the sandbox's previous files may hold work that is in no snapshot (the output of a run that was \
                     interrupted by a restart, files that differ from its snapshot, or a sandbox whose manifest cannot be \
                     read); they were moved, whole, to {}. Copy back what you need, then delete it",
                    dir.display()
                ));
            }
            (Manifest::for_workspace(&ctx.repo, name), StatCache::new(), aside)
        }
    };
    let fs = SandboxFs::new(
        &paths.files,
        Some(CloneSources::new((*ctx.fs).clone(), ctx.stat_cache().clone())),
        true,
    )
    .with_forbidden_targets(std::iter::once(ctx.root.clone()).chain(crate::ctx::veil_private_dirs()));
    // The output of an earlier run that was never recorded (`vl` was
    // killed, or recording it failed) is recorded first, as it is.
    let recovered = m.pending.is_some();
    if recovered {
        eprintln!(
            "{} the output of an earlier run in workspace {}, which was not recorded",
            yellow("Recording"),
            safe(name)
        );
        let left = finish(ctx, name, &paths, &mut m, &mut cache, &fs, None, None)?;
        if a.record_only {
            run.finish();
            return Ok(exec_status(0, &left, &persistent_hint(name, &paths), true));
        }
    }
    if a.record_only {
        eprintln!("Nothing to record: the sandbox of workspace {} holds no unrecorded run", safe(name));
        run.finish();
        return Ok(ExitCode::SUCCESS);
    }

    let base = ctx.repo.workspace_wc(name)?;
    let synced = ctx.repo.snapshot(&base)?.tree;
    // The tree's root, before anything is written or run: one the server
    // refuses is of a view this person no longer has (the workspace stands
    // on a snapshot this thin clone never fetched). The command has not
    // run and nothing names a run, so after the clone's move it runs, once,
    // on the current view (BUG-1573); never in a sandbox of no files.
    if let Err(e) = ctx.repo.store().tree(&synced) {
        NOT_RUN.store(veil_core::tree::refused_tree(ctx.repo.store(), &e), std::sync::atomic::Ordering::SeqCst);
        return Err(e.into());
    }
    let set = sparse_set(ctx, a.only, &synced, &format!("workspace '{}'", safe(name)))?;
    let run_id = hex::encode(veil_core::crypto::random_bytes::<8>());
    m.running = Some(run_id.clone());
    m.boot = veil_core::lock::boot_identity();
    paths.save_manifest(&m)?;

    let was = m.tree.map(|_| m.only.clone());
    let (co, kept, injection) = {
        let _umask = PrivateUmask::set();
        private_dir(&paths.files)?;
        prefetch_sync(&ctx.repo, m.tree.as_ref(), &synced, set.as_ref())?;
        let synced_slice = match &set {
            Some(s) => restrict_tree(ctx.repo.store(), &synced, s)?,
            None => synced,
        };
        let sealed = core::sealed_files_in_tree(ctx.repo.store(), &synced_slice, None);
        if !sealed.is_empty() {
            let mut guard = paths.load_guard(&ctx.repo)?.unwrap_or_default();
            let prev = guard.files.len();
            guard.add(&sealed);
            if guard.files.len() != prev {
                paths.save_guard(&ctx.repo, &guard)?;
            }
        }
        let co = core::sync_to(&ctx.repo, &fs, &mut m, &synced, set.as_ref(), &mut cache)?;
        core::vouch_written(ctx.repo.store(), &fs, &synced, &co, &mut cache, core::VouchWait::IfCheaper)?;
        let sealed_fs = core::sealed_files_in_tree(ctx.repo.store(), &synced_slice, Some(&fs));
        if !sealed_fs.is_empty() {
            let mut guard = paths.load_guard(&ctx.repo)?.unwrap_or_default();
            let prev = guard.files.len();
            guard.add(&sealed_fs);
            if guard.files.len() != prev {
                paths.save_guard(&ctx.repo, &guard)?;
            }
        }
        if let SetAside::Reimport {
            from,
            paths: keep,
            quarantined,
            keep_whole,
        } = &aside
        {
            let (failed, left) = core::reimport(&fs, from, keep, *keep_whole, &mut cache);
            let shown: Vec<String> = keep.iter().take(10).map(|p| safe(p.as_str()).into_owned()).collect();
            eprintln!(
                "  {} {} file(s) of unrecorded work across the rebuild: {}{}",
                yellow("kept"),
                keep.len() - failed.len(),
                shown.join(", "),
                if keep.len() > 10 { ", …" } else { "" }
            );
            for (p, why) in &failed {
                warn(&format!("{} could not be put back into the rebuilt sandbox ({why})", safe(p.as_str())));
            }
            if let Some(dir) = left {
                let why = match keep_whole {
                    true => "other files of the sandbox differed from its snapshot (hand edits, or files a crash tore)",
                    false => "not everything could be put back",
                };
                warn(&format!(
                    "{why}; the previous files were kept, whole, in {}: copy back what you need, then delete it",
                    dir.display()
                ));
            }
            m.quarantined = quarantined.clone();
        }
        // Files outside the set before the command runs are not its output:
        // edits made in the sandbox by hand, or kept by a narrower set
        // because they held something else. They stay (unrecorded).
        let kept = match &set {
            Some(s) => {
                let pin = core::PolicyPin::new(&fs, ctx.repo.store(), &synced)?;
                core::strays(&fs, s, &[&Policy::load_or_accepted(&pin, None)?.0])?
            }
            None => Vec::new(),
        };
        let injection = match a.with_isolated {
            true => {
                let files = vault_files(&ctx.repo)?;
                let mut inj = core::plan_injection(&fs, &files)?;
                // Durably, before anything is written: the guard every later
                // recording of this sandbox applies, and what the injection
                // replaces (for a cleanup after `vl` dies).
                let mut guard = paths.load_guard(&ctx.repo)?.unwrap_or_default();
                guard.add(&files);
                guard.injection = Some(inj.to_saved(&run_id));
                paths.save_guard(&ctx.repo, &guard)?;
                run.reaper = spawn_reaper(&[PERSISTENT_ARG.as_ref(), paths.dir.as_os_str(), run_id.as_ref()]);
                if let Some(r) = &mut run.reaper {
                    tell_reaper(r, &inj, &files);
                }
                core::write_injection(&fs, &mut inj, &files);
                Some(inj)
            }
            false => None,
        };
        (co, kept, injection)
    };
    // From here on the files are the command's output: never wiped, recorded
    // by this run or, if it cannot, by the next one.
    m.pending = Some(Pending {
        run: run_id,
        base,
        message: a.message.to_string(),
        started,
        kept: kept.iter().map(|p| p.as_str().to_string()).collect(),
        injected: injection.is_some(),
        recorded: None,
    });
    m.running = None;
    m.snapshot = Some(base);
    paths.save_manifest(&m)?;
    if was.as_ref() != Some(&m.only) && (set.is_some() || was.is_some()) {
        eprintln!("{} sandbox holds {}", dim("sparse:"), show_set(set.as_ref()));
    }
    print_sync(&co, &fs);
    if let Some(inj) = &injection {
        for (p, why) in &inj.skipped {
            warn(&format!("{} was not injected: {why}", safe(p)));
        }
    }

    print_running(a.command, &paths.files, confine);
    // What the command writes to the allow-list stays for the workspace's
    // later runs (this very workspace's: an earlier one of the same name
    // has its own), unless it was given secrets: then nothing it wrote
    // outside its files outlives it.
    let layers_dir = paths.dir.join(crate::confine::layers_dir(core::workspace_id(&ctx.repo, name).as_deref()));
    let layers = injection.is_none().then_some(layers_dir.as_path());
    // The command's own `vl` asks this one (the workspace socket); before
    // each of its commands the sandbox's files are recorded, so the record
    // on disk, not `m`, is the run's from here on.
    if let Err(e) = paths.save_cache(&mut cache) {
        warn(&format!("could not save the sandbox's stat cache: {e}"));
    }
    let server = crate::ws_socket::Server::start(
        &ctx.root,
        name,
        &paths.files,
        set.clone(),
        Box::new(MidRun { root: ctx.root.clone(), name: name.to_string() }),
    )?;
    let code = run_command(&paths.files, &paths.dir, a.command, confine, layers, Some(&server));
    drop(server);
    if let Loaded::Found(saved) = paths.load_manifest() {
        m = *saved;
    }
    cache = paths.load_cache();
    // Nothing may have run (the command was not found): recording finds no
    // change and the injected files are taken out as after any run.
    let left = finish(ctx, name, &paths, &mut m, &mut cache, &fs, injection.as_ref(), Some(&kept))?;
    run.finish();
    Ok(exec_status(code?, &left, &persistent_hint(name, &paths), true))
}

/// The workspace socket's recording of a checked-out sandbox while its
/// command runs: before each command from inside, the sandbox's files are
/// recorded into the workspace, as the run's end would (the policy, the
/// secret scanner and the guard of injected secrets apply), and the run's
/// record is moved on to what was recorded; after it, a working copy that
/// moved to the same tree (`vl commit`, `vl new`, `vl describe`) is what
/// the run continues from.
struct MidRun {
    root: std::path::PathBuf,
    name: String,
}

impl MidRun {
    fn open(&self) -> Result<(Ctx, SandboxPaths, veil_core::lock::WcLock)> {
        let ctx = Ctx::open(Some(&self.root), false)?;
        let wc = veil_core::lock::WcLock::acquire(&veil_core::repo::state_dir(&self.root), &self.name)?;
        let paths = SandboxPaths::new(&self.root, &self.name);
        Ok((ctx, paths, wc))
    }
}

impl crate::ws_socket::Around for MidRun {
    fn before(&self) -> Result<()> {
        let (mut ctx, paths, _wc) = self.open()?;
        ctx.repo.set_command_workspace(Some(self.name.clone()));
        let Loaded::Found(mut m) = paths.load_manifest() else { bail!("the sandbox's manifest cannot be read") };
        let Some(p) = m.pending.clone() else { return Ok(()) };
        let store = ctx.repo.store().clone();
        let synced = m.tree.ok_or_else(|| anyhow!("the sandbox's manifest names no tree"))?;
        let set = m.only_set()?;
        let mut guard = paths.load_guard(&ctx.repo)?;
        let fs = SandboxFs::new(&paths.files, None, false).with_forbidden_targets(std::iter::once(self.root.clone()).chain(crate::ctx::veil_private_dirs()));
        let synced_slice = match &set {
            Some(s) => restrict_tree(&store, &synced, s)?,
            None => synced,
        };
        let sealed = core::sealed_files_in_tree(&store, &synced_slice, Some(&fs));
        if !sealed.is_empty() {
            let g = guard.get_or_insert_with(core::Guard::default);
            let prev = g.files.len();
            g.add(&sealed);
            if g.files.len() != prev {
                paths.save_guard(&ctx.repo, g)?;
            }
        }
        let secrets = guard.as_ref().map(core::Guard::secrets);
        let mut cache = paths.load_cache();
        let pin = core::PolicyPin::new(&fs, &store, &synced)?;
        let view = set.as_ref().map(|s| SparseView::new(&pin, store.clone(), synced, s));
        let recorded_fs: &dyn StorageBackend = match &view {
            Some(v) => v,
            None => &pin,
        };
        let out = ctx.repo.snapshot_workspace_with(
            &self.name,
            recorded_fs,
            SnapshotOptions {
                cache: Some(&mut cache),
                injected: secrets.as_ref(),
                materialised: Some(&m.materialised),
                expected_wc: Some(p.base),
                policy_from_command: true,
                ..Default::default()
            },
        )?;
        if out.superseded {
            bail!(
                "workspace '{}' moved outside the sandbox while the command ran; its files are recorded when the command ends",
                safe(&self.name)
            );
        }
        print_build_warnings(&out.report);
        print_working_copy_warnings(&out.report);
        let tree = ctx.repo.snapshot(&out.snapshot)?.tree;
        let recorded_slice = match &set {
            Some(s) => restrict_tree(&store, &tree, s)?,
            None => tree,
        };
        let new_sealed = core::sealed_files_in_tree(&store, &recorded_slice, Some(&fs));
        if !new_sealed.is_empty() {
            let g = guard.get_or_insert_with(core::Guard::default);
            let prev = g.files.len();
            g.add(&new_sealed);
            if g.files.len() != prev {
                paths.save_guard(&ctx.repo, g)?;
            }
        }
        if let Some(pp) = &mut m.pending {
            pp.base = out.snapshot;
        }
        m.tree = Some(tree);
        m.snapshot = Some(out.snapshot);
        paths.save_manifest(&m)?;
        let _ = paths.save_cache(&mut cache);
        Ok(())
    }

    fn after(&self) {
        let Ok((ctx, paths, _wc)) = self.open() else { return };
        let Loaded::Found(mut m) = paths.load_manifest() else { return };
        let (Some(p), Some(tree), Ok(wc)) = (m.pending.as_mut(), m.tree, ctx.repo.workspace_wc(&self.name)) else { return };
        // Only a move to the very tree the files hold: anything else is
        // a move from outside, which the run's end deals with.
        if wc != p.base && ctx.repo.snapshot(&wc).is_ok_and(|s| s.tree == tree) {
            p.base = wc;
            m.snapshot = Some(wc);
            let _ = paths.save_manifest(&m);
        }
    }
}

/// In a thin clone, fetch what syncing the sandbox from tree `from` to `to`
/// reads, in batches (as a checkout of the project directory does), and
/// only within the sparse set: a lost server fails here, before the sandbox
/// is touched, and a large sandbox is not fetched a file per request.
fn prefetch_sync(repo: &Repo, from: Option<&ObjectId>, to: &ObjectId, set: Option<&SparseSet>) -> Result<()> {
    let store = repo.store();
    if !store.is_partial() {
        return Ok(());
    }
    let Some(set) = set else {
        return Ok(store.prefetch_diff(from, to)?);
    };
    let mut files = Vec::new();
    for p in set.paths() {
        let old = match from {
            Some(f) => veil_core::tree::lookup(store, f, p)?,
            None => None,
        };
        match veil_core::tree::lookup(store, to, p)? {
            Some(e) if e.kind == veil_core::object::EntryKind::Dir => {
                let old = old.filter(|o| o.kind == veil_core::object::EntryKind::Dir).map(|o| o.id);
                store.prefetch_diff_below(old.as_ref(), &e.id, to, p)?;
            }
            Some(e) if old.as_ref().map(|o| o.id) != Some(e.id) => files.push((p.clone(), e.id, e.size)),
            _ => {}
        }
    }
    Ok(store.prefetch_at(to, &files)?)
}

/// The error of a run whose output could not be recorded: it stays.
fn not_recorded(name: &str, paths: &SandboxPaths, e: impl std::fmt::Display) -> anyhow::Error {
    anyhow!(
        "the command's output was not recorded: {e}. It stays in the sandbox ({}); the next `vl ws exec {n}` records it \
         first, or run `vl ws exec {n} --record-only`",
        paths.files.display(),
        n = safe(name)
    )
}

/// Record the command's output ([`Manifest::pending`]) and clean up after
/// it: injected files and every copy of an injected value taken out,
/// files written outside a sparse set removed. `injection`: the run's own
/// (else the one the guard file saved, for a run that died); `kept`: the
/// files outside the set before the command (else the manifest's).
///
/// Never deletes unrecorded output: whatever fails, the manifest still
/// says `pending` (recorded or not), and the next run, or
/// `vl ws exec --record-only`, finishes the job.
#[allow(clippy::too_many_arguments)]
fn finish(
    ctx: &mut Ctx,
    name: &str,
    paths: &SandboxPaths,
    m: &mut Manifest,
    cache: &mut StatCache,
    fs: &SandboxFs,
    injection: Option<&core::Injection>,
    kept: Option<&[VPath]>,
) -> Result<Vec<LeftOut>> {
    let p = m.pending.clone().expect("a pending run");
    // One recorder of the workspace at a time, and its operations are the
    // workspace's (`vl undo` there undoes them).
    let _wc = veil_core::lock::WcLock::acquire(&veil_core::repo::state_dir(&ctx.root), name)?;
    let attached = ctx.repo.command_workspace().map(str::to_string);
    ctx.repo.set_command_workspace(Some(name.to_string()));
    let res = finish_recording(ctx, name, paths, m, cache, fs, injection, kept, p);
    ctx.repo.set_command_workspace(attached);
    res
}

#[allow(clippy::too_many_arguments)]
fn finish_recording(
    ctx: &mut Ctx,
    name: &str,
    paths: &SandboxPaths,
    m: &mut Manifest,
    cache: &mut StatCache,
    fs: &SandboxFs,
    injection: Option<&core::Injection>,
    kept: Option<&[VPath]>,
    p: Pending,
) -> Result<Vec<LeftOut>> {
    let store = ctx.repo.store().clone();
    let synced = m.tree.ok_or_else(|| anyhow!("the sandbox's manifest names no tree"))?;
    let set = m.only_set()?;
    let mut guard = paths.load_guard(&ctx.repo).map_err(|e| not_recorded(name, paths, e))?;
    let synced_slice = match &set {
        Some(s) => restrict_tree(&store, &synced, s)?,
        None => synced,
    };
    let sealed = core::sealed_files_in_tree(&store, &synced_slice, Some(fs));
    if !sealed.is_empty() {
        let g = guard.get_or_insert_with(core::Guard::default);
        let prev = g.files.len();
        g.add(&sealed);
        if g.files.len() != prev {
            paths.save_guard(&ctx.repo, g).map_err(|e| not_recorded(name, paths, e))?;
        }
    }
    let mut secrets = guard.as_ref().map(core::Guard::secrets);

    let pin = core::PolicyPin::new(fs, &store, &synced)?;
    let (recorded, recorded_tree, report, outcome) = {
        // Sparse: everything outside the set is recorded as `synced` has it.
        let view = set.as_ref().map(|s| SparseView::new(&pin, store.clone(), synced, s));
        let recorded_fs: &dyn StorageBackend = match &view {
            Some(v) => v,
            None => &pin,
        };
        match p.recorded {
            Some((snap, tree)) => (snap, tree, None, Outcome::Resumed),
            None => {
                let out = ctx
                    .repo
                    .snapshot_workspace_with(
                        name,
                        recorded_fs,
                        SnapshotOptions {
                            cache: Some(&mut *cache),
                            injected: secrets.as_ref(),
                            materialised: Some(&m.materialised),
                            expected_wc: Some(p.base),
                            // The command edited the files, not the member
                            // (BUG-560).
                            policy_from_command: true,
                            ..Default::default()
                        },
                    )
                    .map_err(|e| not_recorded(name, paths, e))?;
                let (recorded, report, outcome) = if out.superseded {
                    // Someone moved the workspace while the command ran:
                    // recording the sandbox now would revert what they did.
                    // Keep the result as a change of its own, on top of what
                    // the command started from.
                    let desc = if p.message.is_empty() { "`vl ws exec` result" } else { p.message.as_str() };
                    let (id, report) = ctx
                        .repo
                        .commit_fs_as_child_with(p.base, recorded_fs, desc, secrets.as_ref(), None, &[], true)
                        .map_err(|e| not_recorded(name, paths, e))?;
                    (id, report, Outcome::Saved)
                } else {
                    let outcome = if out.changed { Outcome::Recorded } else { Outcome::Unchanged };
                    (out.snapshot, out.report, outcome)
                };
                let tree = ctx.repo.snapshot(&recorded)?.tree;
                // Durably recorded: from here on only the cleanup is left.
                if let Some(pp) = &mut m.pending {
                    pp.recorded = Some((recorded, tree));
                }
                paths.save_manifest(m)?;
                print_build_warnings(&report);
                print_working_copy_warnings(&report);
                let place = format!("the sandbox ({})", paths.files.display());
                if let Some(msg) = policy_edit_held_message(&report, Some((&place, name))) {
                    warn(&msg);
                }
                if outcome == Outcome::Saved {
                    let change = ctx.repo.snapshot(&recorded)?.change_id.short();
                    warn(&format!(
                        "workspace '{}' moved while the command ran; its result was saved as change {change} on top of the snapshot it started from, \
                         not into the workspace",
                        safe(name)
                    ));
                } else if !p.message.is_empty() {
                    if let Err(e) = ctx.repo.describe(recorded, &p.message) {
                        warn(&format!("the result was recorded, but could not be described: {e}"));
                    }
                }
                (recorded, tree, Some(report), outcome)
            }
        }
    };

    if let Some(why) = &pin.why {
        warn(&format!(
            "{POLICY_FILE} {why} in the sandbox: workspace '{}' keeps its recorded policy (in a sandbox, only a regular, readable \
             {POLICY_FILE} is an edit of it; a deleted or unreadable one never lifts protection)",
            safe(name)
        ));
        if let (true, Some(text)) = (pin.deleted, pin.pinned_text()) {
            let vp = VPath::new(POLICY_FILE)?;
            if !veil_core::checkout::behind_special(fs, &vp)? && fs.metadata(&vp)?.is_none() && fs.write(&vp, text).is_ok() {
                cache.invalidate(&vp);
                eprintln!("  {} {POLICY_FILE} in the sandbox", yellow("put back"));
            }
        }
    }

    let recorded_slice = match &set {
        Some(s) => restrict_tree(&store, &recorded_tree, s)?,
        None => recorded_tree,
    };
    let new_sealed = core::sealed_files_in_tree(&store, &recorded_slice, Some(fs));
    if !new_sealed.is_empty() {
        let g = guard.get_or_insert_with(core::Guard::default);
        let prev = g.files.len();
        g.add(&new_sealed);
        if g.files.len() != prev {
            paths.save_guard(&ctx.repo, g)?;
            secrets = Some(g.secrets());
        }
    }

    // Injected paths (skipped by the scrub) and the copies taken out.
    let mut scrub: Option<(Vec<VPath>, Vec<String>)> = None;
    if let (Some(g), Some(_)) = (&mut guard, &secrets) {
        let saved;
        let empty = core::Injection::default();
        let inj = match injection {
            Some(i) => i,
            None => match g.injection.as_ref().filter(|s| s.run == p.run) {
                Some(s) => {
                    saved = core::Injection::from_saved(s, Default::default());
                    &saved
                }
                None => &empty,
            },
        };
        let none = BuildReport::default();
        let c = core::remove_injected(&store, fs, &synced, &recorded_tree, inj, report.as_ref().unwrap_or(&none), cache)?;
        if let Some((q, why)) = c.failed.first() {
            bail!(
                "could not take the injected file {} out of the sandbox again ({why}); the run is recorded, and the next \
                 `vl ws exec {n}` (or `vl ws exec {n} --record-only`) tries again",
                safe(q.as_str()),
                n = safe(name)
            );
        }
        let copies: Vec<String> = c
            .removed
            .iter()
            .chain(&c.restored)
            .filter(|q| !inj.paths.contains(q))
            .map(|q| safe(q.as_str()).into_owned())
            .collect();
        scrub = Some((inj.paths.clone(), copies));
        if g.injection.is_some() {
            g.injection = None;
            paths.save_guard(&ctx.repo, g)?;
        }
    }

    // Quarantined files of earlier runs that are now outside the set stay
    // (they are in no snapshot), and so does `vl ws rm`'s guard for them.
    let mut quarantined: Vec<String> = match (&set, &report) {
        (_, None) => m.quarantined.clone(),
        (Some(set), _) => m
            .quarantined
            .iter()
            .filter(|q| VPath::new(q).is_ok_and(|p| !set.contains(&p) && fs.metadata(&p).ok().flatten().is_some()))
            .cloned()
            .collect(),
        (None, _) => Vec::new(),
    };
    if let Some(set) = &set {
        // What the command wrote outside the set is not the workspace's.
        // Ignored or isolated under the policy it started with or the one
        // it left: not its output to remove (BUG-549).
        let before = Policy::load_or_accepted(&TreeView::new(store.clone(), synced), None)?.0;
        let after = Policy::load_or_accepted(&pin, None)?.0;
        let kept_before: Vec<VPath> = match kept {
            Some(k) => k.to_vec(),
            None => p.kept.iter().filter_map(|k| VPath::new(k).ok()).collect(),
        };
        let (strays, left): (Vec<VPath>, Vec<VPath>) = core::strays(fs, set, &[&before, &after])?
            .into_iter()
            .filter(|q| !quarantined.iter().any(|x| x == q.as_str()))
            .partition(|q| !kept_before.contains(q));
        if !left.is_empty() {
            let shown: Vec<String> = left.iter().take(20).map(|q| safe(q.as_str()).into_owned()).collect();
            warn(&format!(
                "not recorded: {} file(s) in the sandbox outside --only {} that the command did not write (kept; a run whose paths hold them records them): {}",
                left.len(),
                show_set(Some(set)),
                shown.join(", ")
            ));
        }
        let failed = core::remove_strays(fs, set, &strays, cache);
        // An injected file outside the set, put back as recorded, is ours.
        let by_command: Vec<VPath> = strays
            .into_iter()
            .filter(|q| !injection.is_some_and(|i| i.paths.contains(q)))
            .collect();
        warn_strays(set, &by_command, true);
        for (q, why) in &failed {
            warn(&format!(
                "could not remove {} from the sandbox ({why}); it is outside --only and is not recorded",
                safe(q.as_str())
            ));
        }
    }
    if let (Some((skip, mut copies)), Some(secrets)) = (scrub, &secrets) {
        // Copies the builder never saw: ignored and isolated files, outside
        // a sparse set, written after an earlier injected run (BUG-546/547).
        let since = m.guard_checked.map_or(p.started, |g| g.min(p.started));
        let found = core::scrub(fs, since, secrets, cache, &skip);
        let c = core::clean_copies(&store, fs, &recorded_tree, secrets, &found.found, cache);
        if let Some((_, why)) = c.failed.first() {
            bail!(
                "could not take a copy of an injected secret out of the sandbox ({why}); the run is recorded, and the next \
                 `vl ws exec {n}` (or `vl ws exec {n} --record-only`) tries again",
                n = safe(name)
            );
        }
        for (q, why) in &found.unchecked {
            warn(&format!(
                "{} in the sandbox could not be checked for copies of injected secrets ({why})",
                safe(&q.to_string_lossy())
            ));
        }
        copies.extend(
            c.removed
                .iter()
                .chain(&c.restored)
                .map(|q| safe(q.as_str()).into_owned()),
        );
        for q in &found.found {
            let is_vp = q
                .to_str()
                .and_then(|s| VPath::new(&s.replace(std::path::MAIN_SEPARATOR, "/")).ok())
                .is_some();
            if !is_vp && !fs.root().join(q).exists() {
                copies.push(safe(&q.to_string_lossy()).into_owned());
            }
        }
        copies.sort();
        copies.dedup();
        if !copies.is_empty() {
            eprintln!(
                "  {} {} (they held an injected secret; taken out of the sandbox)",
                yellow("cleaned"),
                copies.join(", ")
            );
        }
        m.guard_checked = Some(p.started);
    }
    drop(pin);

    m.tree = Some(recorded_tree);
    // After a superseded run the files are the saved change's: the next run
    // syncs them to the workspace.
    m.snapshot = Some(match outcome {
        Outcome::Saved => recorded,
        _ => ctx.repo.workspace_wc(name)?,
    });
    if let Some(report) = &report {
        quarantined.extend(
            report
                .quarantined
                .iter()
                .filter(|(_, f)| !f.iter().any(|f| f.rule == INJECTED_RULE))
                .map(|(q, _)| q.as_str().to_string()),
        );
    }
    quarantined.sort();
    quarantined.dedup();
    m.quarantined = quarantined;
    m.pending = None;
    m.running = None;
    paths.save_manifest(m)?;
    if let Err(e) = paths.save_cache(cache) {
        warn(&format!("could not save the sandbox's stat cache: {e}"));
    }

    // stderr: stdout belongs to the sandboxed command.
    match outcome {
        Outcome::Saved => eprintln!("Saved {}", one_line(&ctx.repo, &recorded)),
        Outcome::Recorded => eprintln!("Recorded {}", one_line(&ctx.repo, &ctx.repo.workspace_wc(name)?)),
        Outcome::Unchanged => eprintln!("No changes in {}", one_line(&ctx.repo, &ctx.repo.workspace_wc(name)?)),
        Outcome::Resumed => eprintln!("Finished cleaning up after the run recorded as {}", one_line(&ctx.repo, &recorded)),
    }
    Ok(report.as_ref().map(|r| left_out(r, true)).unwrap_or_default())
}

/// What recording a run did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    Recorded,
    Unchanged,
    /// Saved as a change of its own (the workspace moved).
    Saved,
    /// Recorded by an earlier attempt; only the cleanup was left.
    Resumed,
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
    if exists && dead_run(&paths.load_manifest()) {
        stop_dead_run(&paths.files);
    }
    if let (true, false) = (exists, force) {
        let kept = core::kept_dirs(&paths);
        if let Some(d) = kept.first() {
            bail!(
                "the sandbox of workspace '{n}' holds files a rebuild kept because they may be work that is in no snapshot ({}). \
                 Look at them, copy back what you need; `vl ws rm --force {n}` removes the workspace and them",
                d.display(),
                n = safe(name)
            );
        }
    }
    if let (true, false, Loaded::Found(m)) = (exists, force, paths.load_manifest()) {
        if m.pending.is_some() {
            bail!(
                "the sandbox of workspace '{n}' holds the output of a run that was not recorded. \
                 `vl ws exec {n} --record-only` records it; `vl ws rm --force {n}` removes the workspace and it",
                n = safe(name)
            );
        }
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

fn print_running(command: &[String], dir: &Path, confine: Option<&Confine>) {
    let how = confine.map(|c| format!(" ({})", c.describe(dir))).unwrap_or_default();
    eprintln!("{} {} in {}{how}", dim("running"), command.join(" "), dir.display());
}

/// Run `command` in `dir` and return its exit status (128 + n for a
/// signal). Git never looks above `ceiling` for a repository (the sandbox
/// lives inside the project directory). Ctrl-C and Ctrl-\ go to the command
/// only, and SIGTERM and SIGHUP sent to `vl` (an IDE stopping a task, a
/// closed terminal) are forwarded to it: `vl` waits for it and records what
/// it left (BUG-550). With `confine`, `dir` appears at the project's path
/// inside the confinement ([`crate::confine`], which forwards the signals),
/// and the allow-list's writes are kept in the layers directory `layers` (a
/// persistent sandbox's) or thrown away (`None`).
fn run_command(dir: &Path, ceiling: &Path, command: &[String], confine: Option<&Confine>, layers: Option<&Path>, socket: Option<&crate::ws_socket::Server>) -> Result<i32> {
    let mut ceilings = ceiling.as_os_str().to_owned();
    if let Some(old) = std::env::var_os("GIT_CEILING_DIRECTORIES").filter(|v| !v.is_empty()) {
        ceilings.push(":");
        ceilings.push(old);
    }
    if let Some(c) = confine {
        return crate::confine::run(c, dir, command, &[("GIT_CEILING_DIRECTORIES", ceilings)], layers, socket.map(|s| s.path()));
    }
    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..]).current_dir(dir);
    cmd.env("GIT_CEILING_DIRECTORIES", ceilings);
    match socket {
        Some(s) => cmd.env(crate::ws_socket::ENV, s.path()).env("PATH", s.path_env()),
        None => cmd.env_remove(crate::ws_socket::ENV),
    };
    let interrupts = Interrupts::to_child(&mut cmd);
    let status = cmd
        .spawn()
        .with_context(|| format!("failed to run {}", command[0]))
        .and_then(|mut child| {
            interrupts.started(child.id());
            let s = child.wait().context("waiting for the command");
            interrupts.started(0);
            s
        });
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

/// The command a SIGTERM or SIGHUP to `vl` is forwarded to (0: none).
#[cfg(unix)]
static FORWARD_TO: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);
/// The last signal forwarded (or received before the command started).
#[cfg(unix)]
static FORWARDED: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

#[cfg(unix)]
extern "C" fn forward_signal(sig: libc::c_int) {
    use std::sync::atomic::Ordering;
    FORWARDED.store(sig, Ordering::SeqCst);
    let pid = FORWARD_TO.load(Ordering::SeqCst);
    if pid > 0 {
        // SAFETY: kill(2) is async-signal-safe.
        unsafe {
            libc::kill(pid, sig);
        }
    }
}

/// While it lives, `vl` ignores SIGINT and SIGQUIT (the terminal sends them
/// to the command too) and forwards SIGTERM and SIGHUP to the command; the
/// child gets the dispositions `vl` had.
struct Interrupts {
    #[cfg(unix)]
    old: Vec<(libc::c_int, libc::sigaction)>,
}

#[cfg(unix)]
const IGNORED: [libc::c_int; 2] = [libc::SIGINT, libc::SIGQUIT];
#[cfg(unix)]
const FORWARDED_SIGNALS: [libc::c_int; 2] = [libc::SIGTERM, libc::SIGHUP];

impl Interrupts {
    fn to_child(cmd: &mut Command) -> Interrupts {
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            FORWARDED.store(0, std::sync::atomic::Ordering::SeqCst);
            let mut old = Vec::new();
            let mut restore = Vec::new();
            for sig in IGNORED.into_iter().chain(FORWARDED_SIGNALS) {
                // SAFETY: plain sigaction(2) calls on a zeroed struct; the
                // handler only touches atomics and calls kill(2).
                unsafe {
                    let mut new: libc::sigaction = std::mem::zeroed();
                    new.sa_sigaction = if IGNORED.contains(&sig) {
                        libc::SIG_IGN
                    } else {
                        forward_signal as extern "C" fn(libc::c_int) as libc::sighandler_t
                    };
                    new.sa_flags = libc::SA_RESTART;
                    libc::sigemptyset(&mut new.sa_mask);
                    let mut prev: libc::sigaction = std::mem::zeroed();
                    if libc::sigaction(sig, &new, &mut prev) == 0 {
                        // A handler does not survive exec anyway: the child
                        // gets SIG_IGN if `vl` had it (`nohup`), else the default.
                        let child = if prev.sa_sigaction == libc::SIG_IGN { libc::SIG_IGN } else { libc::SIG_DFL };
                        restore.push((sig, child));
                        old.push((sig, prev));
                    }
                }
            }
            // SAFETY: the closure only calls signal(2), which is
            // async-signal-safe, between fork and exec.
            unsafe {
                cmd.pre_exec(move || {
                    for (sig, disp) in &restore {
                        libc::signal(*sig, *disp);
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

    /// The command runs as `pid` (0: it has exited): forward to it, and
    /// pass on a signal that came before it started.
    fn started(&self, pid: u32) {
        #[cfg(unix)]
        {
            use std::sync::atomic::Ordering;
            FORWARD_TO.store(pid as i32, Ordering::SeqCst);
            let sig = FORWARDED.load(Ordering::SeqCst);
            if pid > 0 && sig != 0 {
                // SAFETY: signals our own child.
                unsafe {
                    libc::kill(pid as i32, sig);
                }
            }
        }
        #[cfg(not(unix))]
        let _ = pid;
    }
}

impl Drop for Interrupts {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            FORWARD_TO.store(0, std::sync::atomic::Ordering::SeqCst);
            for (sig, prev) in &self.old {
                // SAFETY: restores the disposition saved above.
                unsafe {
                    libc::sigaction(*sig, prev, std::ptr::null_mut());
                }
            }
        }
    }
}

// ---- ephemeral sandboxes ---------------------------------------------------

fn exec_ephemeral(ctx: &mut Ctx, a: &Exec<'_>, confine: Option<&Confine>) -> Result<ExitCode> {
    let base_snapshot = ctx.rev(a.rev)?;
    let tree = ctx.repo.snapshot(&base_snapshot)?.tree;
    let set = sparse_set(ctx, a.only, &tree, &safe(a.rev))?;
    let sb = Sandbox::create("ephemeral")?;
    let dir = sb.path().to_path_buf();
    let sandbox = SandboxFs::new(&dir, None, false).with_forbidden_targets(std::iter::once(ctx.root.clone()).chain(crate::ctx::veil_private_dirs()));
    let result = (|| -> Result<(i32, Vec<LeftOut>, String)> {
        let to = match &set {
            Some(s) => restrict_tree(ctx.repo.store(), &tree, s)?,
            None => tree,
        };
        // What could not be materialised (a link the sandbox refuses, a
        // file it cannot hold) is recorded as such, so recording the run
        // carries it instead of deleting it.
        let mut record = veil_core::checkout::Materialised::default();
        let checked_out = ctx.repo.checkout_tree_recorded(&sandbox, None, &to, &mut record, None)?;
        crate::ctx::print_failed(&checked_out.failed);
        let mut guard_files = core::sealed_files_in_tree(ctx.repo.store(), &to, Some(&sandbox));
        if a.with_isolated {
            let files = vault_files(&ctx.repo)?;
            for (p, data) in &files {
                sandbox.write_secret(&VPath::new(p)?, data, false)?;
            }
            guard_files.extend(files);
        }
        // Whatever the command does with these, they must not be recorded
        // in another file.
        let injected = (!guard_files.is_empty()).then(|| {
            veil_core::builder::InjectedSecrets::from_files(guard_files.iter().map(|(p, d)| (p.as_str(), d.as_slice())))
        });
        sb.make_private()?;
        print_running(a.command, &dir, confine);
        let code = run_command(&dir, &dir, a.command, confine, None, None)?;
        // A deleted or unreadable `.veilpolicy` keeps the recorded one.
        let pin = core::PolicyPin::new(&sandbox, ctx.repo.store(), &tree)?;
        let view = set.as_ref().map(|s| SparseView::new(&pin, ctx.repo.store().clone(), tree, s));
        let recorded_fs: &dyn StorageBackend = match &view {
            Some(v) => v,
            None => &pin,
        };
        let (id, report) = ctx
            .repo
            .commit_fs_as_child_with(base_snapshot, recorded_fs, a.message, injected.as_ref(), Some(&record), &[], true)?;
        if let Some(why) = &pin.why {
            warn(&format!(
                "{POLICY_FILE} {why} in the sandbox: the recorded policy is kept (in a sandbox, only a regular, readable \
                 {POLICY_FILE} is an edit of it)"
            ));
        }
        if let Some(set) = &set {
            let injected_paths: Vec<VPath> = match a.with_isolated {
                true => vault_files(&ctx.repo)?.iter().filter_map(|(p, _)| VPath::new(p).ok()).collect(),
                false => Vec::new(),
            };
            let before = Policy::load_or_accepted(&TreeView::new(ctx.repo.store().clone(), tree), None)?.0;
            let after = Policy::load_or_accepted(&pin, None)?.0;
            let strays: Vec<VPath> = core::strays(&sandbox, set, &[&before, &after])?
                .into_iter()
                .filter(|p| !injected_paths.contains(p))
                .collect();
            warn_strays(set, &strays, false);
        }
        print_build_warnings(&report);
        print_working_copy_warnings(&report);
        if let Some(msg) = policy_edit_held_message(&report, None) {
            warn(&msg);
        }
        eprintln!("Recorded {}", one_line(&ctx.repo, &id));
        // What the recording left out as a secret goes with the throwaway
        // directory unless it is moved out first (BUG-2171).
        let left = left_out(&report, true);
        let hint = match left.is_empty() {
            true => String::new(),
            false => keep_left_out(&ctx.root, &dir, &left, &one_line(&ctx.repo, &id)),
        };
        Ok((code, left, hint))
    })();
    drop(sb);
    let (code, left, hint) = result?;
    Ok(exec_status(code, &left, &hint, false))
}

/// `.veil/local/ephemeral-kept`: the files `--ephemeral` runs left out as
/// secrets, one directory per run (BUG-2171). Local, like the vault: never
/// recorded, synced or pushed; `vl doctor` lists what is there.
pub const EPHEMERAL_KEPT_DIR: &str = ".veil/local/ephemeral-kept";

/// Move the files `left` out of the throwaway sandbox `dir` into a new
/// directory of [`EPHEMERAL_KEPT_DIR`], each at its path in the sandbox and
/// with its permissions, and say where (the hint of the run's message;
/// `change`: the change recorded without them). A file that cannot be
/// moved is named as lost with the sandbox.
fn keep_left_out(root: &Path, dir: &Path, left: &[LeftOut], change: &str) -> String {
    let mut to = root.to_path_buf();
    to.extend(EPHEMERAL_KEPT_DIR.split('/'));
    to.push(format!("{}-{}", veil_core::now_millis(), hex::encode(veil_core::crypto::random_bytes::<2>())));
    let mut failed = Vec::new();
    for f in left {
        if let Err(e) = keep_one(dir, &to, &f.path) {
            failed.push(format!("{} ({e})", safe(f.path.as_str())));
        }
    }
    if !failed.is_empty() {
        warn(&format!(
            "could not move {} out of the throwaway sandbox: lost with it. Run the command again in a workspace \
             (`vl ws exec NAME`), whose sandbox keeps such files",
            failed.join(", ")
        ));
    }
    format!(
        "moved out of the throwaway sandbox, with the same permissions, to {}: on this machine only, never recorded or \
         pushed (`vl doctor` lists it until you delete it). The change recorded without them is {change}: to add one, \
         put it in a working copy of that change (`vl edit <change>`), then fix it, `vl isolate` it or, if it is not a \
         secret, `vl expose --force` it",
        to.display()
    )
}

/// Move `path` of the sandbox `dir` to the same path under `to`: renamed,
/// or copied (with its permissions) across filesystems, then synced.
fn keep_one(dir: &Path, to: &Path, path: &VPath) -> std::io::Result<()> {
    let rel: PathBuf = path.as_str().split('/').collect();
    let (from, dest) = (dir.join(&rel), to.join(&rel));
    if !std::fs::symlink_metadata(&from)?.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    let mut made = Vec::new();
    for d in dest.ancestors().skip(1) {
        if d.exists() {
            break;
        }
        made.push(d.to_path_buf());
    }
    for d in made.iter().rev() {
        private_dir(d)?;
    }
    if std::fs::rename(&from, &dest).is_err() {
        std::fs::copy(&from, &dest)?;
    }
    std::fs::File::open(&dest)?.sync_all()?;
    if let Some(parent) = dest.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

/// The directories of [`EPHEMERAL_KEPT_DIR`] under the project at `root`.
pub fn ephemeral_kept(root: &Path) -> Vec<PathBuf> {
    let mut base = root.to_path_buf();
    base.extend(EPHEMERAL_KEPT_DIR.split('/'));
    let mut out: Vec<PathBuf> = std::fs::read_dir(&base)
        .map(|rd| rd.flatten().map(|e| e.path()).collect())
        .unwrap_or_default();
    out.sort();
    out
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

/// Did a run of the sandbox `loaded` describes not finish (its `vl`
/// died, or failed, after the run started)?
fn dead_run(loaded: &Loaded) -> bool {
    match loaded {
        Loaded::Found(m) => m.pending.is_some() || m.running.is_some(),
        Loaded::Corrupt(_) => true,
        Loaded::Missing => false,
    }
}

/// Stop what a dead `vl` left of a confined run in `files`: the command,
/// if `vl` was killed while `bwrap` started the sandbox, and its systemd
/// scope (BUG-852). Only under the sandbox's lock, or for a throwaway
/// sandbox whose owner is gone: no live run is ever touched.
fn stop_dead_run(files: &Path) {
    crate::confine::stop_leftovers(files);
    crate::confine::clear_dead_scopes();
}

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

/// Tell the reaper of a persistent run which files it injected (one line
/// on its pipe, before the files are written): if `vl` dies, it takes out
/// those that still hold what was injected, putting back what they replaced.
fn tell_reaper(r: &mut Child, inj: &core::Injection, files: &[(String, Vec<u8>)]) {
    let entries: Vec<serde_json::Value> = inj
        .paths
        .iter()
        .filter_map(|p| {
            let (_, data) = files.iter().find(|(f, _)| VPath::new(f).is_ok_and(|q| q == *p))?;
            let stash = inj.stashed(p).map(|(d, x)| serde_json::json!([hex::encode(d), x]));
            Some(serde_json::json!([p.as_str(), veil_core::object::Object::blob_id(data).hex(), stash]))
        })
        .collect();
    if let Some(stdin) = r.stdin.as_mut() {
        let mut line = vec![INJECTED];
        line.extend(serde_json::to_vec(&entries).unwrap_or_default());
        line.push(b'\n');
        let _ = stdin.write_all(&line);
    }
}

/// The injected files a reaper was told about ([`tell_reaper`]).
fn reaper_entries(line: &[u8]) -> Vec<core::ReaperEntry> {
    let Ok(v) = serde_json::from_slice::<Vec<serde_json::Value>>(line) else { return Vec::new() };
    v.iter()
        .filter_map(|e| {
            let p = VPath::new(e.get(0)?.as_str()?).ok()?;
            let id = ObjectId::from_hex(e.get(1)?.as_str()?).ok()?;
            let stash = match e.get(2) {
                Some(serde_json::Value::Array(s)) => Some((hex::decode(s.first()?.as_str()?).ok()?, s.get(1)?.as_bool()?)),
                _ => None,
            };
            Some((p, id, stash))
        })
        .collect()
}

/// Body of the reaper process: wait for the parent to go away, then clean
/// up unless it said it finished cleanly.
pub fn reaper_main(args: Vec<std::ffi::OsString>) -> ExitCode {
    let mut all = Vec::new();
    let _ = std::io::stdin().lock().read_to_end(&mut all);
    let mut keep = false;
    let mut injected = Vec::new();
    for line in all.split(|b| *b == b'\n') {
        match line.first() {
            Some(&INJECTED) => injected = reaper_entries(&line[1..]),
            Some(_) => keep |= line.contains(&KEEP),
            None => {}
        }
    }
    if keep {
        return ExitCode::SUCCESS;
    }
    match args.as_slice() {
        [mode, dir, run] if mode == PERSISTENT_ARG => {
            let dir = Path::new(dir);
            if is_persistent_sandbox(dir) {
                reap_persistent(dir, &run.to_string_lossy(), &injected);
            }
        }
        [dir] => {
            let dir = Path::new(dir);
            // A run that ended removed its directory itself.
            if is_sandbox_path(dir) && std::fs::symlink_metadata(dir).is_ok() {
                stop_dead_run(dir);
                let _ = veil_core::vfs::remove_tree(dir);
            }
        }
        _ => {}
    }
    ExitCode::SUCCESS
}

/// The run `run` of the sandbox in `dir`, which injected `injected`, died
/// (or failed): stop what it left running, then take the injected files
/// that are unchanged out again, unless a later run has already taken the
/// sandbox over (it cleans up itself). Nothing else is touched: the rest is
/// the command's output, which the next run records (under the guard).
fn reap_persistent(dir: &Path, run: &str, injected: &[core::ReaperEntry]) {
    let paths = SandboxPaths::at(dir.to_path_buf());
    let Ok(_lock) = SandboxLock::acquire(&paths.lock, || {}) else { return };
    stop_dead_run(&paths.files);
    if injected.is_empty() {
        return;
    }
    if let Loaded::Found(m) = paths.load_manifest() {
        let ours = m.running.as_deref() == Some(run) || m.pending.as_ref().is_some_and(|p| p.run == run);
        if ours && std::fs::symlink_metadata(&paths.files).is_ok_and(|md| md.is_dir()) {
            core::take_out_unchanged(&SandboxFs::new(&paths.files, None, false), injected);
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
        stop_dead_run(&s.path);
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
        for d in core::kept_dirs(&paths) {
            out.push((
                true,
                format!(
                    "{}: files a rebuild of the sandbox of workspace '{}' kept, because they may be work that is in no snapshot; \
                     copy back what you need, then delete it",
                    d.display(),
                    safe(&ws)
                ),
            ));
        }
        match paths.load_manifest() {
            Loaded::Found(m) if m.pending.is_some() && !busy => out.push((
                true,
                format!(
                    "{shown}: holds the output of a run that was not recorded; `vl ws exec {} --record-only` records it",
                    safe(&ws)
                ),
            )),
            Loaded::Found(m) if m.running.is_some() && !busy => out.push((
                true,
                format!(
                    "{shown}: a run was interrupted before its command started; the next `vl ws exec {}` rebuilds it \
                     (keeping unrecorded work)",
                    safe(&ws)
                ),
            )),
            Loaded::Found(m) if !m.quarantined.is_empty() => out.push((
                false,
                format!("{shown}: holds {} quarantined file(s) that are in no snapshot", m.quarantined.len()),
            )),
            Loaded::Corrupt(why) => out.push((true, format!("{shown}: unreadable manifest ({why}); the next run rebuilds it"))),
            loaded => {
                let sparse = match loaded {
                    Loaded::Found(m) => m.only.map(|o| format!(" (sparse: {})", o.iter().map(|p| safe(p).into_owned()).collect::<Vec<_>>().join(", "))),
                    _ => None,
                };
                out.push((
                    false,
                    format!(
                        "{shown}: workspace '{}'{}{}",
                        safe(&ws),
                        sparse.unwrap_or_default(),
                        if busy { " (a run is in progress)" } else { "" }
                    ),
                ))
            }
        }
    }
    out
}
