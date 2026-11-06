//! `vl doctor`: check this machine's setup and explain every problem.
//!
//! Doctor never changes anything a user cares about: it does not create an
//! identity, take the repository lock or snapshot the working copy. The only
//! thing it writes is a short-lived probe directory under `.veil/local/`
//! (or the temp directory outside a repository) to measure the filesystem.
//! It works on a damaged repository and reports what it cannot check.

use std::{
    path::{Path, PathBuf},
    process::ExitCode,
    time::{Duration, Instant},
};

use anyhow::Result;
use veil_core::{
    lock::{assess, assess_raw, LockContext, RepoLock, Verdict, LOCK_PATH, STEAL_PATH},
    now_millis,
    repo::{is_repo, RepoConfig, REPO_FORMAT_VERSION, VEIL_DIR},
    statcache::{cache_path, StatCache},
    vfs::{NameFolding, FOLDING_ENV},
    DiskBackend, Identity, Repo, SftpBackend, SshUrl, StorageBackend, VPath,
};

use crate::{
    cli::VERSION,
    ctx::{checkout_path, find_root, identity_path, veil_home, CheckoutState},
    render::{bold, dim, green, red, safe, yellow},
    sandbox,
};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Level {
    Ok,
    Note,
    Warn,
    Fail,
}

#[derive(Default)]
struct Report {
    warnings: usize,
    failures: usize,
}

impl Report {
    fn section(&self, title: &str) {
        println!("\n{}", bold(title));
    }

    fn item(&mut self, level: Level, what: &str, detail: &[String]) {
        let tag = match level {
            Level::Ok => green("ok  "),
            Level::Note => dim("note"),
            Level::Warn => {
                self.warnings += 1;
                yellow("warn")
            }
            Level::Fail => {
                self.failures += 1;
                red("FAIL")
            }
        };
        println!("  {tag}  {}", safe(what));
        for line in detail {
            println!("        {}", safe(line));
        }
    }

    fn ok(&mut self, what: impl AsRef<str>) {
        self.item(Level::Ok, what.as_ref(), &[]);
    }
    fn note(&mut self, what: impl AsRef<str>, detail: &[String]) {
        self.item(Level::Note, what.as_ref(), detail);
    }
    fn warn(&mut self, what: impl AsRef<str>, detail: &[String]) {
        self.item(Level::Warn, what.as_ref(), detail);
    }
    fn fail(&mut self, what: impl AsRef<str>, detail: &[String]) {
        self.item(Level::Fail, what.as_ref(), detail);
    }
}

pub fn run(repo_arg: Option<&Path>, remotes: bool) -> Result<ExitCode> {
    let mut r = Report::default();
    println!("vl {VERSION} on {}", env!("VL_TARGET"));

    r.section("Setup");
    check_veil_home(&mut r);
    let identity = check_identity(&mut r);
    check_sandboxes(&mut r);

    let start = match repo_arg {
        Some(p) => p.to_path_buf(),
        None => std::env::current_dir()?,
    };
    // Never a `bwrap` or `systemd-run` from inside the project.
    check_confinement(&mut r, find_root(&start).and_then(|r| r.canonicalize().ok()).as_deref());
    match find_root(&start) {
        None => {
            r.section("Repository");
            r.note(
                format!("no repository at or above {}; repository checks skipped", start.display()),
                &[],
            );
            r.section("Filesystem");
            check_filesystem(&mut r, &std::env::temp_dir(), None);
            check_clock(&mut r, None);
        }
        Some(root) => {
            r.section(&format!("Repository {}", root.display()));
            let fs = std::sync::Arc::new(DiskBackend::new(&root));
            let repo = check_repo(&mut r, &fs, identity);
            check_lock(&mut r, &*fs);
            check_stat_cache(&mut r, &*fs, repo.as_ref());
            check_ws_sandboxes(&mut r, &root, repo.as_ref());
            check_mounts(&mut r, &root, repo.as_ref());
            if let Some(repo) = &repo {
                check_vault(&mut r, repo);
            }
            r.section("Filesystem");
            check_filesystem(&mut r, &veil_core::repo::state_dir(&root).join("local"), Some(&fs));
            check_clock(&mut r, repo.as_ref());
            if remotes {
                r.section("Remotes");
                match &repo {
                    Some(repo) => check_remotes(&mut r, &root, repo.config()),
                    None => r.note("skipped: the repository does not open", &[]),
                }
            }
        }
    }

    println!();
    match (r.failures, r.warnings) {
        (0, 0) => println!("{}", green("Everything looks good.")),
        (0, w) => println!("{}", yellow(&format!("{w} warning(s); nothing is broken."))),
        (f, w) => println!("{}", red(&format!("{f} problem(s) and {w} warning(s) need attention."))),
    }
    Ok(if r.failures > 0 { ExitCode::FAILURE } else { ExitCode::SUCCESS })
}

// ---- setup ----------------------------------------------------------------------

fn check_veil_home(r: &mut Report) {
    let home = veil_home();
    let source = if std::env::var_os("VEIL_HOME").is_some() {
        "$VEIL_HOME"
    } else if std::env::var_os("XDG_CONFIG_HOME").is_some() {
        "$XDG_CONFIG_HOME/veil"
    } else {
        "default ~/.config/veil"
    };
    match std::fs::metadata(&home) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => r.note(
            format!("VEIL_HOME {} ({source}) does not exist yet", home.display()),
            &["it is created with your identity by the first `vl init` or `vl identity new`".into()],
        ),
        Err(e) => r.fail(format!("VEIL_HOME {} ({source}) cannot be read: {e}", home.display()), &[]),
        Ok(m) if !m.is_dir() => r.fail(
            format!("VEIL_HOME {} ({source}) is not a directory", home.display()),
            &["point $VEIL_HOME at a directory, or move the file away".into()],
        ),
        Ok(m) => {
            let mut problems = Vec::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::{MetadataExt, PermissionsExt};
                // Group-writable is the norm with per-user groups (umask 002).
                if m.permissions().mode() & 0o002 != 0 {
                    problems.push(format!(
                        "it is writable by every user (mode {:o}), who could replace your identity: chmod o-w {}",
                        m.permissions().mode() & 0o777,
                        home.display()
                    ));
                }
                // SAFETY: geteuid has no preconditions.
                if m.uid() != unsafe { libc::geteuid() } {
                    problems.push("it is owned by another user".into());
                }
            }
            #[cfg(not(unix))]
            let _ = m;
            if problems.is_empty() {
                r.ok(format!("VEIL_HOME {} ({source})", home.display()));
            } else {
                r.warn(format!("VEIL_HOME {} ({source})", home.display()), &problems);
            }
        }
    }
}

fn check_identity(r: &mut Report) -> Option<Identity> {
    let path = identity_path();
    let raw = match std::fs::read_to_string(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            r.warn(
                format!("no identity at {}", path.display()),
                &["one is created on first use; run `vl identity new` to create it now".into()],
            );
            return None;
        }
        Err(e) => {
            r.fail(format!("identity {} cannot be read: {e}", path.display()), &[]);
            return None;
        }
        Ok(raw) => raw,
    };
    let id = match Identity::from_json(&raw) {
        Ok(id) => id,
        Err(e) => {
            r.fail(
                format!("identity {} is not valid: {e}", path.display()),
                &["restore it from a backup; `vl identity new --force` replaces it (cloaked content shared with the old one stays unreadable until re-granted)".into()],
            );
            return None;
        }
    };
    let what = format!("identity '{}' {} ({})", id.name, short_key(&id.public_hex()), path.display());
    match private_file_problem(&path) {
        Some(problem) => r.fail(what, &[problem]),
        None => r.ok(what),
    }
    let retired = veil_home().join("retired");
    if let Ok(entries) = std::fs::read_dir(&retired) {
        let exposed: Vec<String> = entries
            .flatten()
            .filter_map(|e| private_file_problem(&e.path()))
            .collect();
        if !exposed.is_empty() {
            r.fail(format!("retired identities in {}", retired.display()), &exposed);
        }
    }
    Some(id)
}

fn short_key(hex: &str) -> String {
    match hex.char_indices().nth(16) {
        Some((i, _)) => format!("{}…", &hex[..i]),
        None => hex.to_string(),
    }
}

/// Why a file holding a secret key is not private (mode 0600, ours), if it
/// is not.
fn private_file_problem(path: &Path) -> Option<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let m = std::fs::symlink_metadata(path).ok()?;
        if !m.is_file() {
            return Some(format!("{} is not a regular file", path.display()));
        }
        let mode = m.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Some(format!(
                "{} has mode {mode:o}: other users can read your secret key. Fix: chmod 600 {}",
                path.display(),
                path.display()
            ));
        }
        // SAFETY: geteuid has no preconditions.
        if m.uid() != unsafe { libc::geteuid() } {
            return Some(format!("{} is owned by another user", path.display()));
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    None
}

/// Whether `vl ws exec` can confine its command here, and how limits apply.
fn check_confinement(r: &mut Report, root: Option<&Path>) {
    for (works, line, detail) in crate::confine::doctor(root) {
        match works {
            true => r.item(Level::Ok, &line, &detail),
            false => r.warn(line, &detail),
        }
    }
}

fn check_sandboxes(r: &mut Report) {
    let base = std::env::temp_dir();
    let stale = sandbox::stale_sandboxes(&base);
    if stale.is_empty() {
        r.ok(format!("no leftover `ws exec` sandboxes in {}", base.display()));
        return;
    }
    let mut detail: Vec<String> = stale
        .iter()
        .map(|s| format!("{} (owner pid {} is gone)", s.path.display(), s.pid))
        .collect();
    detail.push("they may hold plaintext of cloaked files or injected secrets; the next `vl ws exec` removes them, or delete them with `rm -rf`".into());
    r.warn(format!("{} leftover `ws exec` sandbox(es)", stale.len()), &detail);
}

/// The repository's persistent `ws exec` sandboxes.
fn check_ws_sandboxes(r: &mut Report, root: &Path, repo: Option<&Repo>) {
    let status = sandbox::persistent_status(root, repo);
    if status.is_empty() {
        return;
    }
    let (problems, fine): (Vec<_>, Vec<_>) = status.into_iter().partition(|(p, _)| *p);
    if !fine.is_empty() {
        r.ok(format!("{} `ws exec` sandbox(es) in .veil/local/sandboxes", fine.len()));
    }
    if !problems.is_empty() {
        let detail: Vec<String> = problems.into_iter().map(|(_, l)| l).collect();
        r.warn(format!("{} `ws exec` sandbox(es) need attention", detail.len()), &detail);
    }
}

/// The repository's `vl ws mount`s.
fn check_mounts(r: &mut Report, root: &Path, repo: Option<&Repo>) {
    for (problem, line) in crate::mount::doctor_status(root, repo) {
        match problem {
            true => r.warn(line, &[]),
            false => r.ok(line),
        }
    }
}

// ---- repository -------------------------------------------------------------------

fn check_repo(r: &mut Report, fs: &std::sync::Arc<DiskBackend>, identity: Option<Identity>) -> Option<Repo> {
    let raw = match fs.read(&VPath::new(".veil/repo.json").expect("valid path")) {
        Ok(raw) => raw,
        Err(e) => {
            r.fail(format!(".veil/repo.json cannot be read: {e}"), &[]);
            return None;
        }
    };
    let config: RepoConfig = match serde_json::from_slice(&raw) {
        Ok(c) => c,
        Err(e) => {
            r.fail(format!(".veil/repo.json is not valid: {e}"), &[]);
            return None;
        }
    };
    match config.format.cmp(&REPO_FORMAT_VERSION) {
        std::cmp::Ordering::Greater => r.fail(
            format!("repository format {} is newer than this vl supports ({REPO_FORMAT_VERSION})", config.format),
            &["upgrade vl before using this repository".into()],
        ),
        std::cmp::Ordering::Less => r.warn(
            format!("repository format {} is older than this vl's ({REPO_FORMAT_VERSION})", config.format),
            &[],
        ),
        std::cmp::Ordering::Equal => {}
    }
    let user = identity.as_ref().map(|i| i.name.clone()).unwrap_or_else(|| "doctor".into());
    let repo = match Repo::open(fs.clone(), identity, &user) {
        Ok(repo) => repo,
        Err(e) => {
            r.fail(
                format!("the repository does not open: {e}"),
                &["`vl fsck` shows what is damaged".into()],
            );
            return None;
        }
    };
    let ws = match fs.read_opt(&checkout_path()) {
        Ok(Some(raw)) => match serde_json::from_slice::<CheckoutState>(&raw) {
            Ok(st) if repo.view().workspaces.contains_key(&st.workspace) => Some(st.workspace),
            Ok(st) => {
                r.warn(
                    format!("the project directory is attached to workspace '{}', which no longer exists", st.workspace),
                    &["the next command attaches it to another workspace".into()],
                );
                None
            }
            Err(e) => {
                r.fail(
                    format!(".veil/local/checkout.json is not valid: {e}"),
                    &["remove it; the next command treats the directory as the default workspace".into()],
                );
                None
            }
        },
        _ => None,
    };
    r.ok(format!(
        "opens: format {}, id {}, operation {}, workspace '{}'",
        config.format,
        config.repo_id,
        repo.op_id().short(),
        ws.as_deref().unwrap_or("default")
    ));
    Some(repo)
}

fn check_lock(r: &mut Report, fs: &dyn StorageBackend) {
    match RepoLock::holder(fs) {
        Ok(None) => r.ok("not locked"),
        // The raw file also tells a reused pid from its holder (pid_start).
        Ok(Some(info)) => match fs
            .read_opt(&VPath::new(LOCK_PATH).expect("valid path"))
            .ok()
            .flatten()
            .and_then(|raw| assess_raw(&raw, now_millis()))
            .unwrap_or_else(|| assess(&info, now_millis()))
        {
            Verdict::Wait => r.note(
                format!("locked by {}", info.describe()),
                &["another vl command is running; it is waited for".into()],
            ),
            Verdict::Steal(why) => r.note(
                format!("a stale lock from {} is left ({why})", info.describe()),
                &["the next command reclaims it automatically".into()],
            ),
            Verdict::Stuck(why) => r.fail(
                format!("the lock is {why}"),
                &["commands will time out waiting for it. If no vl process holds this repository any more, remove .veil/lock".into()],
            ),
        },
        Err(e) => r.fail(format!(".veil/lock cannot be read: {e}"), &[]),
    }
    check_takeover_guards(r, fs);
}

/// Takeover guards (`.veil/lock.steal`, sub-guards `.veil/lock.steal.<hash>`)
/// are held for milliseconds; one that stays was left by a `vl` that
/// crashed mid-takeover. Provably stale ones are removed (by the takeover
/// protocol, so a live contender's guard is never touched).
fn check_takeover_guards(r: &mut Report, fs: &dyn StorageBackend) {
    let guards = match veil_core::lock::takeover_guards(fs) {
        Ok(g) => g,
        Err(e) => return r.warn(format!("takeover guards cannot be listed: {e}"), &[]),
    };
    if guards.is_empty() {
        return;
    }
    let stale = guards.iter().filter(|g| g.stale.is_some()).count();
    let cleared = if stale > 0 {
        veil_core::lock::clear_stale_guards(fs, &LockContext::for_backend(fs)).unwrap_or(0)
    } else {
        0
    };
    let left = veil_core::lock::takeover_guards(fs).unwrap_or_default();
    if cleared > 0 {
        r.note(
            format!("removed {cleared} stale lock takeover guard(s) left by an interrupted vl"),
            &guards
                .iter()
                .filter(|g| g.stale.is_some() && !left.iter().any(|l| l.path == g.path))
                .map(|g| format!("{} ({})", g.path, g.stale.as_deref().unwrap_or_default()))
                .collect::<Vec<_>>(),
        );
    }
    for g in &left {
        let holder = g.holder.as_ref().map_or_else(|| "unreadable content".into(), |h| h.describe());
        let name = if g.path.as_str() == STEAL_PATH { "" } else { " sub-guard" };
        r.warn(
            format!("lock takeover{name} {} is left ({holder})", g.path),
            &["left by a takeover that was interrupted; harmless, but if no vl process runs on any machine sharing this repository, you may remove it".into()],
        );
    }
}

fn check_stat_cache(r: &mut Report, fs: &dyn StorageBackend, repo: Option<&Repo>) {
    let ws = fs
        .read_opt(&checkout_path())
        .ok()
        .flatten()
        .and_then(|raw| serde_json::from_slice::<CheckoutState>(&raw).ok())
        .map(|s| s.workspace)
        .unwrap_or_else(|| "default".into());
    let path = cache_path(&ws);
    match fs.read_opt(&path) {
        Ok(None) => r.note(
            format!("no stat cache for workspace '{ws}' yet"),
            &["the next command reads every file once and creates it".into()],
        ),
        Ok(Some(raw)) => {
            let cache = StatCache::load(fs, &path);
            if cache.is_empty() && raw.len() > 64 {
                r.warn(
                    format!("stat cache {path} is unreadable (corrupt, or written by another version)"),
                    &["harmless: the next command re-reads every file once and rewrites it".into()],
                );
            } else {
                r.ok(format!("stat cache: {} files, {} KiB", cache.len(), raw.len().div_ceil(1024)));
            }
        }
        Err(e) => r.warn(format!("stat cache {path} cannot be read: {e}"), &[]),
    }
    // Caches of workspaces that are gone only take space.
    if let (Some(repo), Ok(entries)) = (repo, fs.list_dir(&VPath::new(".veil/local/statcache").expect("valid path"))) {
        let orphans: Vec<String> = entries
            .iter()
            .filter_map(|e| e.name.strip_suffix(".cache"))
            .filter(|w| !repo.view().workspaces.contains_key(*w))
            .map(str::to_string)
            .collect();
        if !orphans.is_empty() {
            r.note(
                format!("stat caches of removed workspaces: {}", orphans.join(", ")),
                &["they can be deleted from .veil/local/statcache/".into()],
            );
        }
    }
}

fn check_vault(r: &mut Report, repo: &Repo) {
    if repo.identity().is_none() {
        r.note("vault not checked: no identity", &[]);
        return;
    }
    match repo.vault_unreadable() {
        Ok(true) => r.fail(
            "the vault was sealed by another identity",
            &["re-key it with `vl identity recover-vault` (it looks for your retired identity in $VEIL_HOME/retired)".into()],
        ),
        Ok(false) => match repo.vault_load() {
            Ok(v) => r.ok(format!("vault opens: {} files, {} secrets", v.files.len(), v.secrets.len())),
            Err(e) => r.fail(format!("the vault does not open: {e}"), &[]),
        },
        Err(e) => r.fail(format!("the vault cannot be read: {e}"), &[]),
    }
}

fn check_remotes(r: &mut Report, root: &Path, config: &RepoConfig) {
    if config.remotes.is_empty() {
        r.note("no remotes configured", &[]);
        return;
    }
    for (name, remote) in &config.remotes {
        if let Some(url) = SshUrl::parse(&remote.url) {
            check_ssh_remote(r, name, &remote.url, url);
            continue;
        }
        if remote.url.contains("://") {
            r.note(
                format!("{name} ({}): not a local path; `vl pull {name}` checks it", remote.url),
                &[],
            );
            continue;
        }
        let path = PathBuf::from(&remote.url);
        let path = if path.is_absolute() { path } else { root.join(path) };
        let started = Instant::now();
        let backend = DiskBackend::new(&path);
        let reachable = path.is_dir() && is_repo(&backend);
        let took = started.elapsed();
        if reachable {
            r.ok(format!("{name} ({}) reachable in {}", remote.url, fmt_duration(took)));
            check_push_staging(r, name, &backend);
        } else if path.exists() {
            r.fail(format!("{name} ({}) is not a Veil repository", remote.url), &[]);
        } else {
            r.fail(
                format!("{name} ({}) is not reachable", remote.url),
                &[format!("{} does not exist (an unmounted drive or share?)", path.display())],
            );
        }
    }
}

/// Push uploads on remote `name` left unpublished for more than a day
/// (an interrupted push that was not retried): a later push or
/// `vl -R <remote> gc` removes them once a week old.
fn check_push_staging(r: &mut Report, name: &str, backend: &dyn StorageBackend) {
    const DAY_MS: i64 = 24 * 3600 * 1000;
    let staged = match veil_core::remote::push_staging(backend) {
        Ok(s) => s,
        Err(e) => return r.note(format!("{name}: cannot list its push staging"), &[e.to_string()]),
    };
    let now = now_millis();
    let old: Vec<_> = staged.iter().filter(|s| s.touched.is_none_or(|t| now.saturating_sub(t) > DAY_MS)).collect();
    if old.is_empty() {
        return;
    }
    let bytes: u64 = old.iter().map(|s| s.bytes).sum();
    let mut lines: Vec<String> = old
        .iter()
        .map(|s| {
            let age = s.touched.map_or("unknown age".to_string(), |t| format!("{} days old", now.saturating_sub(t) / DAY_MS));
            format!(".veil/objects/incoming/{}: {} bytes, {age}", s.name, s.bytes)
        })
        .collect();
    lines.push("uploads of interrupted pushes: `vl push` again resumes yours; anything a week old is removed by the next push or `vl -R <remote> gc`".into());
    r.note(format!("{name}: {} unpublished push upload(s), {bytes} bytes, untouched for over a day", old.len()), &lines);
}

/// Connect to an SSH remote, check that it holds a repository, and compare
/// its clock with ours: fencing locks on network remotes judge abandoned
/// locks partly by wall-clock age, assuming hosts agree within the skew
/// allowance (see `lock.rs`).
fn check_ssh_remote(r: &mut Report, name: &str, shown: &str, url: veil_core::Result<SshUrl>) {
    let url = match url {
        Ok(u) => u,
        Err(e) => {
            r.fail(format!("{name} ({shown}) is not a valid SSH URL"), &[e.to_string()]);
            return;
        }
    };
    let started = Instant::now();
    let backend = match SftpBackend::connect(&url) {
        Ok(b) => b,
        Err(e) => {
            r.fail(format!("{name} ({shown}) is not reachable"), &[e.to_string()]);
            return;
        }
    };
    let took = started.elapsed();
    if !is_repo(&backend) {
        r.fail(
            format!("{name} ({shown}) is not a Veil repository"),
            &["`vl push` creates one there".into()],
        );
        return;
    }
    r.ok(format!("{name} ({shown}) reachable in {}", fmt_duration(took)));
    check_push_staging(r, name, &backend);
    let allowance = LockContext::default().skew;
    match backend.clock_offset(&VPath::new(VEIL_DIR).expect("valid path")) {
        Ok(offset) => {
            let ahead = if offset >= 0 { "ahead of" } else { "behind" };
            let secs = offset.unsigned_abs() as f64 / 1000.0;
            if offset.unsigned_abs() > (allowance / 2).as_millis() as u64 {
                r.warn(
                    format!("{name}'s clock is {secs:.0} s {ahead} this machine's"),
                    &[
                        format!(
                            "locks on a shared remote are taken over by wall-clock age with a {} s allowance for clock differences between clients; a client whose clock runs ahead of another's by more than that can take over the other's live lock, and a push then fails (or, rarely, both publish)",
                            allowance.as_secs()
                        ),
                        "keep every client's clock in sync (NTP: `timedatectl`, or System Settings → Date & Time on macOS)".into(),
                    ],
                );
            } else {
                r.ok(format!("{name}'s clock is within {:.0} s of this machine's", secs.max(1.0)));
            }
        }
        Err(e) => r.note(format!("{name}: cannot compare clocks"), &[e.to_string()]),
    }
}

// ---- filesystem and clock ---------------------------------------------------------

/// A scratch directory removed on drop.
struct Probe(PathBuf);

impl Drop for Probe {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn check_filesystem(r: &mut Report, base: &Path, repo_fs: Option<&DiskBackend>) {
    let fs_type = filesystem_type(base);
    match &fs_type {
        Some(FsType { name, network: true }) => r.warn(
            format!("{} is on a network filesystem ({name})", base.display()),
            &[
                "locks can only be proven stale on the machine that took them, fsync may not reach the server's disk, and file stamps come from the server's clock".into(),
                "Veil works, but keep the working copy on a local disk if you can".into(),
            ],
        ),
        Some(FsType { name, network: false }) => r.ok(format!("filesystem: {name}")),
        None => r.note("filesystem type unknown", &[]),
    }

    let dir = base.join(format!("doctor-{}-{}", std::process::id(), hex::encode(veil_core::crypto::random_bytes::<4>())));
    if let Err(e) = std::fs::create_dir_all(&dir) {
        r.fail(format!("cannot create a probe directory in {}: {e}", base.display()), &[]);
        return;
    }
    let probe = Probe(dir);
    let disk = DiskBackend::new(&probe.0);

    // Durable write: temp file, fsync, rename, directory fsync.
    let started = Instant::now();
    let wrote = disk.write(&VPath::new("durable").expect("valid path"), &[0u8; 4096]);
    let took = started.elapsed();
    match wrote {
        Err(e) => r.fail(format!("a durable write failed: {e}"), &["Veil cannot store data safely here".into()]),
        Ok(()) if took < Duration::from_micros(50) && fs_type.as_ref().is_some_and(|t| t.name != "tmpfs") => r.warn(
            format!("a durable write took {}: fsync seems to be a no-op", fmt_duration(took)),
            &["data may be lost on power failure (a disk or VM that ignores flushes, or eatmydata)".into()],
        ),
        Ok(()) if took > Duration::from_millis(200) => r.warn(
            format!("a durable write took {}", fmt_duration(took)),
            &["commands that write many objects will be slow on this disk".into()],
        ),
        Ok(()) => r.ok(format!("durable write (fsync) in {}", fmt_duration(took))),
    }

    // Name folding, measured with real files.
    let measured = measure_folding(&probe.0);
    let probed = DiskBackend::new(probe.0.clone()).name_folding();
    let used = repo_fs.map(|f| f.name_folding()).unwrap_or(probed);
    match measured {
        Some(m) => {
            let mut detail = Vec::new();
            if m.folds() {
                detail.push("two tracked paths that differ only in case or Unicode normalisation cannot be checked out here: Veil refuses such snapshots instead of overwriting one file with the other".into());
                if m.case_insensitive {
                    detail.push("a rename that only changes case is not recorded; rename through an intermediate name".into());
                }
            }
            if m != used {
                detail.push(format!(
                    "but Veil assumes {} here{}; set {FOLDING_ENV}={} if that is wrong",
                    used.describe(),
                    if std::env::var_os(FOLDING_ENV).is_some() { format!(" (from ${FOLDING_ENV})") } else { String::new() },
                    folding_env_value(m)
                ));
                r.warn(format!("names: {}", m.describe()), &detail);
            } else {
                r.ok(format!("names: {}", m.describe()));
                for d in detail {
                    println!("        {}", dim(&d));
                }
            }
        }
        None => r.note(format!("could not measure name folding; assuming {}", used.describe()), &[]),
    }
}

fn folding_env_value(f: NameFolding) -> &'static str {
    match (f.case_insensitive, f.unicode_insensitive) {
        (false, false) => "exact",
        (true, false) => "case",
        (false, true) => "unicode",
        (true, true) => "macos",
    }
}

fn measure_folding(dir: &Path) -> Option<NameFolding> {
    let same = |a: &Path, b: &Path| -> Option<bool> {
        let ma = std::fs::symlink_metadata(a).ok()?;
        Some(match std::fs::symlink_metadata(b) {
            #[cfg(unix)]
            Ok(mb) => {
                use std::os::unix::fs::MetadataExt;
                ma.dev() == mb.dev() && ma.ino() == mb.ino()
            }
            #[cfg(not(unix))]
            Ok(_) => true,
            Err(_) => false,
        })
    };
    let upper = dir.join("CaseProbe");
    std::fs::write(&upper, b"").ok()?;
    let case_insensitive = same(&upper, &dir.join("caseprobe"))?;
    let composed = dir.join("probe-\u{e9}");
    // Some filesystems refuse non-UTF-8-normalised names outright.
    let unicode_insensitive = match std::fs::write(&composed, b"") {
        Ok(()) => same(&composed, &dir.join("probe-e\u{301}"))?,
        Err(_) => false,
    };
    Some(NameFolding {
        case_insensitive,
        unicode_insensitive,
    })
}

fn check_clock(r: &mut Report, repo: Option<&Repo>) {
    let now = now_millis();
    // 2020-01-01: anything earlier is a clock that was never set.
    if now < 1_577_836_800_000 {
        r.fail(
            format!("the system clock reads {}", crate::render::fmt_time(now)),
            &["set the clock (enable NTP); expiring embargoes and lock leases depend on it".into()],
        );
        return;
    }
    let mut problems = Vec::new();
    if let Some(repo) = repo {
        if let Ok(ops) = repo.op_log(1) {
            if let Some((_, op)) = ops.first() {
                if op.timestamp > now + 60_000 {
                    problems.push(format!(
                        "the last operation was recorded {} in the future ({})",
                        fmt_duration(Duration::from_millis((op.timestamp - now) as u64)),
                        crate::render::fmt_time(op.timestamp)
                    ));
                }
            }
        }
    }
    // File stamps come from the filesystem's clock (a server's, on a
    // network share); the stat cache compares them against this machine's.
    if let Ok(file) = tempfile_stamp() {
        let skew = (file - now).abs();
        if skew > 2_000 {
            problems.push(format!(
                "a file just written in {} is stamped {} away from the system clock",
                std::env::temp_dir().display(),
                fmt_duration(Duration::from_millis(skew as u64))
            ));
        }
    }
    if problems.is_empty() {
        r.ok(format!("clock: {}", crate::render::fmt_time(now)));
    } else {
        problems.push("a clock that jumps makes embargo deadlines and lock leases unreliable; enable NTP".into());
        r.warn("clock looks wrong", &problems);
    }
}

fn tempfile_stamp() -> std::io::Result<i64> {
    let path = std::env::temp_dir().join(format!("vl-doctor-clock-{}", std::process::id()));
    std::fs::write(&path, b"")?;
    let m = std::fs::metadata(&path);
    let _ = std::fs::remove_file(&path);
    let t = m?.modified()?;
    Ok(t.duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0))
}

fn fmt_duration(d: Duration) -> String {
    if d < Duration::from_millis(1) {
        format!("{} µs", d.as_micros())
    } else if d < Duration::from_secs(10) {
        format!("{:.1} ms", d.as_secs_f64() * 1000.0)
    } else {
        format!("{:.0} s", d.as_secs_f64())
    }
}

struct FsType {
    name: String,
    network: bool,
}

#[cfg(target_os = "linux")]
fn filesystem_type(path: &Path) -> Option<FsType> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(existing_ancestor(path)?.as_os_str().as_bytes()).ok()?;
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: a valid NUL-terminated path and a zeroed out-parameter.
    if unsafe { libc::statfs(c.as_ptr(), &mut st) } != 0 {
        return None;
    }
    #[allow(clippy::unnecessary_cast)]
    let magic = st.f_type as u64 & 0xFFFF_FFFF;
    let (name, network) = match magic {
        0xEF53 => ("ext2/3/4", false),
        0x5846_5342 => ("xfs", false),
        0x9123_683E => ("btrfs", false),
        0x0102_1994 => ("tmpfs", false),
        0x2FC1_2FC1 => ("zfs", false),
        0xF2F5_2010 => ("f2fs", false),
        0x794C_7630 => ("overlayfs", false),
        0x4D44 => ("vfat", false),
        0x2011_BAB0 => ("exfat", false),
        0x5346_544E | 0x7366_746E => ("ntfs", false),
        0x6969 => ("nfs", true),
        0x517B => ("smbfs", true),
        0xFF53_4D42 => ("cifs", true),
        0xFE53_4D42 => ("smb2", true),
        0x0102_1997 => ("9p", true),
        0x6573_5546 => ("fuse (possibly a network mount such as sshfs)", true),
        0x00C3_6400 => ("ceph", true),
        0x5346_414F => ("afs", true),
        0x7375_7245 => ("coda", true),
        0x0BD0_0BD0 => ("lustre", true),
        0x0116_1970 => ("gfs2", true),
        other => return Some(FsType { name: format!("type 0x{other:x}"), network: false }),
    };
    Some(FsType { name: name.into(), network })
}

#[cfg(target_os = "macos")]
fn filesystem_type(path: &Path) -> Option<FsType> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(existing_ancestor(path)?.as_os_str().as_bytes()).ok()?;
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: a valid NUL-terminated path and a zeroed out-parameter.
    if unsafe { libc::statfs(c.as_ptr(), &mut st) } != 0 {
        return None;
    }
    let raw: Vec<u8> = st.f_fstypename.iter().take_while(|&&b| b != 0).map(|&b| b as u8).collect();
    let name = String::from_utf8_lossy(&raw).into_owned();
    let network = st.f_flags & (libc::MNT_LOCAL as u32) == 0;
    Some(FsType { name, network })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn filesystem_type(_path: &Path) -> Option<FsType> {
    None
}

#[cfg(unix)]
fn existing_ancestor(path: &Path) -> Option<&Path> {
    path.ancestors().find(|p| p.exists())
}
