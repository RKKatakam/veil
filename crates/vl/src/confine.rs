//! Confinement of `vl ws exec` on Linux, and its resource limits
//! (`docs/design/scale/9-confinement.md`).
//!
//! The command runs through **bubblewrap** (`bwrap`), which builds a
//! confined view of the machine without root:
//!
//! * the sandbox is bound read-write **at the project's real path**, and
//!   the command starts in the sub-folder `vl` was run from;
//! * the computer's tools (`/usr`, `/etc`, …) are bound read-only;
//! * `HOME`, `/tmp` and `/var/tmp` are empty and private; the Veil home is
//!   always hidden;
//! * an **allow-list** of toolchain and agent folders from the home is
//!   bound read-only (defaults, `--allow`, and `[exec.confine] allow` in
//!   the device-local configuration);
//! * the command gets its own pid, IPC and UTS namespaces, no
//!   capabilities, no further user namespaces, and with `--no-network`
//!   its own network namespace.
//!
//! Limits (`--memory`, `--cpus`, `--cpu-time`, `--pids`, `--timeout`) go
//! through a systemd user scope where there is one (`systemd-run --user
//! --scope`, which execs `bwrap` in place, so `vl` waits for `bwrap`
//! itself), else through `RLIMIT_CPU` and polling. `vl` and its reaper
//! are never inside the limits.
//!
//! `bwrap` runs in its own process group, and `--new-session` detaches the
//! command from the terminal, so `vl` forwards SIGINT and SIGQUIT to the
//! command's process group and SIGTERM and SIGHUP to the command, through a
//! pidfd.

// Elsewhere the run is unconfined: building the command line goes unused.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::{
    collections::BTreeMap,
    ffi::OsString,
    path::{Component, Path, PathBuf},
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use clap::Args;

use crate::render::{safe, warn};

/// `vl ws exec`'s confinement and limit flags.
#[derive(Args, Debug, Clone, Default)]
pub struct ConfineArgs {
    /// Run without confinement: the command can read and change everything your user can.
    #[arg(long, conflicts_with_all = ["allow", "no_network", "memory", "cpus", "cpu_time", "pids", "timeout", "limits"])]
    pub unconfined: bool,
    /// Also show PATH (a folder or file of this machine) to the command, read-only. Repeatable.
    #[arg(long, value_name = "PATH")]
    pub allow: Vec<String>,
    /// No network: the command gets only a private loopback.
    #[arg(long)]
    pub no_network: bool,
    /// Memory limit, e.g. 4G or 512M.
    #[arg(long, value_name = "SIZE")]
    pub memory: Option<String>,
    /// CPU rate limit, in CPUs, e.g. 2 or 0.5.
    #[arg(long, value_name = "N")]
    pub cpus: Option<String>,
    /// Total CPU-time limit, e.g. 30m or 90s.
    #[arg(long, value_name = "DURATION")]
    pub cpu_time: Option<String>,
    /// Limit on the number of processes and threads.
    #[arg(long, value_name = "N")]
    pub pids: Option<String>,
    /// Wall-clock limit, e.g. 45m: at the deadline everything in the sandbox is stopped.
    #[arg(long, value_name = "DURATION")]
    pub timeout: Option<String>,
    /// best-effort (the default): run, saying which limits are soft here; strict: refuse unless the kernel enforces every limit.
    #[arg(long, value_name = "MODE", value_parser = ["best-effort", "strict"])]
    pub limits: Option<String>,
}

/// Folders and files of the home shown to the command (read-only) by
/// default, when they exist: toolchains, and coding agents' own
/// configuration. Never `~/.ssh`, `~/.gnupg` or the Veil home.
pub const DEFAULT_ALLOW: &[&str] = &[
    ".cargo",
    ".rustup",
    ".local/bin",
    ".local/share/claude",
    ".nvm",
    ".pyenv",
    ".volta",
    ".bun",
    ".deno",
    ".claude",
    ".claude.json",
    ".codex",
    ".gemini",
];

/// Credential files of cargo's home (`~/.cargo`, `$CARGO_HOME`) that stay
/// hidden when an allowed folder holds them.
const MASKED: &[&str] = &["credentials", "credentials.toml"];

/// What `vl` says when there is no `bwrap`.
const INSTALL: &str = "install bubblewrap (`apt install bubblewrap`, `dnf install bubblewrap` or `pacman -S bubblewrap`)";
/// The opt-out, as offered in errors.
const OPT_OUT: &str =
    "or run with --unconfined (the command can then read and change everything your user can)";

const LIMIT_KEYS: [&str; 6] = ["memory", "cpus", "cpu-time", "pids", "timeout", "mode"];

/// The device-local `[exec]` configuration.
#[derive(Default, Debug)]
struct Config {
    allow: Vec<PathBuf>,
    limits: BTreeMap<String, String>,
}

/// `[exec.confine]` and `[exec.limits]` from `$VEIL_HOME/config.toml`, then
/// `.veil/local/config.toml` (whose limits win). Nothing tracked in the
/// repository is read. A file that cannot be read or parsed is an error:
/// a limit or a hidden path is never silently dropped.
fn load_config(root: &Path, home: Option<&Path>) -> Result<Config> {
    let mut c = Config::default();
    let files = [
        crate::ctx::veil_home().join(crate::attr_cmd::CONFIG_FILE),
        veil_core::repo::state_dir(root).join("local").join(crate::attr_cmd::CONFIG_FILE),
    ];
    for file in files {
        let Ok(meta) = std::fs::symlink_metadata(&file) else { continue };
        if !meta.is_file() || meta.len() > 1 << 20 {
            bail!("{} is not a regular file under 1 MiB", file.display());
        }
        let text = std::fs::read_to_string(&file).with_context(|| format!("reading {}", file.display()))?;
        let doc = text
            .parse::<toml_edit::DocumentMut>()
            .with_context(|| format!("parsing {}", file.display()))?;
        let Some(exec) = doc.get("exec") else { continue };
        let exec = exec.as_table_like().ok_or_else(|| anyhow!("{}: [exec] must be a table", file.display()))?;
        for (key, item) in exec.iter() {
            let table = item
                .as_table_like()
                .ok_or_else(|| anyhow!("{}: [exec.{key}] must be a table", file.display()))?;
            match key {
                "confine" => {
                    for (k, v) in table.iter() {
                        if k != "allow" {
                            bail!("{}: unknown setting exec.confine.{k} (only `allow`)", file.display());
                        }
                        let list = v
                            .as_array()
                            .ok_or_else(|| anyhow!("{}: exec.confine.allow must be a list of paths", file.display()))?;
                        for p in list.iter() {
                            let s = p
                                .as_str()
                                .ok_or_else(|| anyhow!("{}: exec.confine.allow must be a list of paths", file.display()))?;
                            let path = expand_home(s, home).ok_or_else(|| {
                                anyhow!("{}: exec.confine.allow: {} is not an absolute path or ~/…", file.display(), safe(s))
                            })?;
                            c.allow.push(path);
                        }
                    }
                }
                "limits" => {
                    for (k, v) in table.iter() {
                        if !LIMIT_KEYS.contains(&k) {
                            bail!("{}: unknown setting exec.limits.{k} (one of {})", file.display(), LIMIT_KEYS.join(", "));
                        }
                        let value = match v.as_value() {
                            Some(toml_edit::Value::String(s)) => s.value().clone(),
                            Some(toml_edit::Value::Integer(i)) => i.value().to_string(),
                            Some(toml_edit::Value::Float(f)) => f.value().to_string(),
                            _ => bail!("{}: exec.limits.{k} must be a string or a number", file.display()),
                        };
                        c.limits.insert(k.to_string(), value);
                    }
                }
                _ => {}
            }
        }
    }
    Ok(c)
}

/// `~` and `~/x` against `home`; otherwise only an absolute path.
fn expand_home(s: &str, home: Option<&Path>) -> Option<PathBuf> {
    if s == "~" {
        return home.map(Path::to_path_buf);
    }
    if let Some(rest) = s.strip_prefix("~/") {
        return home.map(|h| h.join(rest));
    }
    let p = PathBuf::from(s);
    p.is_absolute().then_some(p)
}

/// `p` without `.` components; `None` if it has `..` or is not absolute.
fn normal(p: &Path) -> Option<PathBuf> {
    if !p.is_absolute() {
        return None;
    }
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::RootDir => out.push("/"),
            Component::Normal(n) => out.push(n),
            Component::CurDir => {}
            Component::ParentDir | Component::Prefix(_) => return None,
        }
    }
    Some(out)
}

// ---- limits ----------------------------------------------------------------

/// One limit: its value, and how the user wrote it (for messages).
#[derive(Clone, Debug)]
struct Limit<T> {
    value: T,
    shown: String,
}

/// The resource limits of a run.
#[derive(Clone, Debug, Default)]
struct Limits {
    memory: Option<Limit<u64>>,
    cpus: Option<Limit<f64>>,
    cpu_time: Option<Limit<Duration>>,
    pids: Option<Limit<u64>>,
    timeout: Option<Limit<Duration>>,
    strict: bool,
}

impl Limits {
    /// The flags, else the configuration.
    fn new(a: &ConfineArgs, cfg: &BTreeMap<String, String>) -> Result<Limits> {
        let pick = |flag: &Option<String>, key: &str| flag.clone().or_else(|| cfg.get(key).cloned());
        fn parsed<T>(v: Option<String>, what: &str, f: fn(&str) -> Option<T>) -> Result<Option<Limit<T>>> {
            match v {
                None => Ok(None),
                Some(s) => match f(s.trim()) {
                    Some(value) => Ok(Some(Limit { value, shown: s.trim().to_string() })),
                    None => bail!("--{what} {}: not a valid value", safe(&s)),
                },
            }
        }
        let mode = pick(&a.limits, "mode");
        let strict = match mode.as_deref() {
            None | Some("best-effort") => false,
            Some("strict") => true,
            Some(m) => bail!("exec.limits.mode {}: one of best-effort, strict", safe(m)),
        };
        Ok(Limits {
            memory: parsed(pick(&a.memory, "memory"), "memory", parse_size)?,
            cpus: parsed(pick(&a.cpus, "cpus"), "cpus", parse_cpus)?,
            cpu_time: parsed(pick(&a.cpu_time, "cpu-time"), "cpu-time", parse_duration)?,
            pids: parsed(pick(&a.pids, "pids"), "pids", parse_pids)?,
            timeout: parsed(pick(&a.timeout, "timeout"), "timeout", parse_duration)?,
            strict,
        })
    }

    fn any(&self) -> bool {
        self.memory.is_some() || self.cpus.is_some() || self.cpu_time.is_some() || self.pids.is_some() || self.timeout.is_some()
    }

    /// Limits only the kernel, through a cgroup, enforces hard.
    fn wants_cgroup(&self) -> bool {
        self.memory.is_some() || self.cpus.is_some() || self.pids.is_some()
    }
}

/// `4G`, `512M`, `64KiB`, `1048576`: bytes (1024-based units).
fn parse_size(s: &str) -> Option<u64> {
    let digits = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (n, unit) = s.split_at(digits);
    let n: u64 = n.parse().ok()?;
    let unit = unit.trim().to_ascii_lowercase();
    let unit = unit.strip_suffix("ib").or_else(|| unit.strip_suffix('b')).unwrap_or(&unit);
    let shift = match unit {
        "" => 0,
        "k" => 10,
        "m" => 20,
        "g" => 30,
        "t" => 40,
        _ => return None,
    };
    let v = n.checked_mul(1u64 << shift)?;
    (v > 0).then_some(v)
}

/// `90s`, `30m`, `2h`, `500ms`, `45` (seconds).
fn parse_duration(s: &str) -> Option<Duration> {
    let digits = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (n, unit) = s.split_at(digits);
    let n: u64 = n.parse().ok()?;
    let d = match unit.trim() {
        "ms" => Duration::from_millis(n),
        "" | "s" => Duration::from_secs(n),
        "m" | "min" => Duration::from_secs(n.checked_mul(60)?),
        "h" => Duration::from_secs(n.checked_mul(3600)?),
        _ => return None,
    };
    (!d.is_zero()).then_some(d)
}

fn parse_cpus(s: &str) -> Option<f64> {
    let v: f64 = s.parse().ok()?;
    (v.is_finite() && v > 0.0 && v <= 4096.0).then_some(v)
}

fn parse_pids(s: &str) -> Option<u64> {
    let v: u64 = s.parse().ok()?;
    (1..=1 << 22).contains(&v).then_some(v)
}

fn show_size(n: u64) -> String {
    match n {
        n if n >= 1 << 30 && n % (1 << 30) == 0 => format!("{} GiB", n >> 30),
        n if n >= 1 << 20 && n % (1 << 20) == 0 => format!("{} MiB", n >> 20),
        n if n >= 1 << 10 && n % (1 << 10) == 0 => format!("{} KiB", n >> 10),
        n => format!("{n} bytes"),
    }
}

// ---- preparing a confined run ----------------------------------------------

/// How the kernel-enforced limits are applied.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Backend {
    /// A systemd user scope (`systemd-run`, `systemctl`). `verbatim`:
    /// `systemd-run` takes `--expand-environment=no` (systemd 254 and
    /// later, which otherwise expand `$VAR` and `$$` in the command).
    Systemd { run: PathBuf, ctl: PathBuf, verbatim: bool },
    /// `RLIMIT_CPU` and polling.
    Poll,
}

/// A confined run, ready to start: everything is checked before the
/// sandbox is touched.
#[derive(Debug)]
pub struct Confine {
    bwrap: PathBuf,
    /// Namespaces and every mount but the sandbox's.
    base: Vec<OsString>,
    /// The project's canonical path, where the sandbox appears.
    root: PathBuf,
    /// The sub-folder `vl` was run from, relative to `root`.
    rel: PathBuf,
    home: PathBuf,
    limits: Limits,
    backend: Backend,
}

/// Whether this build confines `vl ws exec` at all.
pub const BUILT: bool = cfg!(target_os = "linux");

impl Confine {
    /// The confinement of a `vl ws exec` in the project at `root` (`None`:
    /// unconfined). Fails, before anything is touched, when confinement or a
    /// strict limit cannot be had here.
    pub fn prepare(root: &Path, a: &ConfineArgs) -> Result<Option<Confine>> {
        let home = home_dir();
        let cfg = load_config(root, home.as_deref())?;
        if a.unconfined {
            warn("running unconfined (--unconfined): the command can read and change everything your user can");
            if cfg.limits.keys().any(|k| k != "mode") {
                warn("the limits in [exec.limits] are not applied to an unconfined run");
            }
            return Ok(None);
        }
        if !BUILT {
            let asked = !a.allow.is_empty() || a.no_network || Limits::new(a, &BTreeMap::new())?.any();
            if asked {
                bail!("confinement and limits are only built for Linux so far; run without --allow, --no-network and the limits");
            }
            return Ok(None);
        }
        let limits = Limits::new(a, &cfg.limits)?;
        let root = root.canonicalize().with_context(|| format!("resolving {}", root.display()))?;
        let rel = std::env::current_dir()
            .ok()
            .and_then(|d| d.canonicalize().ok())
            .and_then(|d| d.strip_prefix(&root).ok().map(Path::to_path_buf))
            .unwrap_or_default();
        let mut allow = Vec::new();
        for user in &a.allow {
            let p = Path::new(user);
            let p = if p.is_absolute() { p.to_path_buf() } else { std::env::current_dir()?.join(p) };
            allow.push((p, true));
        }
        allow.extend(cfg.allow.into_iter().map(|p| (p, true)));
        allow.extend(default_allow(home.as_deref()));
        let home = home.unwrap_or_else(|| PathBuf::from("/tmp/home"));
        let bwrap = find_program("bwrap", Some(&root)).ok_or_else(|| anyhow!("confinement needs bubblewrap, which is not installed: {INSTALL}, {OPT_OUT}"))?;
        let base = base_args(&home, Some(&root), &allow, a.no_network)?;
        probe(&bwrap, &base)?;
        let backend = backend(&limits, &root)?;
        let (soft, unavailable) = weak_limits(&limits, &backend);
        if !soft.is_empty() || !unavailable.is_empty() {
            let mut parts = Vec::new();
            if !soft.is_empty() {
                parts.push(format!("{} soft (polled every 100 ms)", soft.join(", ")));
            }
            if !unavailable.is_empty() {
                parts.push(format!("{} not available", unavailable.join(", ")));
            }
            let why = "without a systemd user scope";
            if limits.strict {
                bail!("--limits strict: {} ({why}); nothing was run", parts.join("; "));
            }
            warn(&format!("limits: {} ({why})", parts.join("; ")));
        }
        Ok(Some(Confine { bwrap, base, root, rel, home, limits, backend }))
    }

    /// Where the command starts, inside the confinement: the sub-folder
    /// `vl` was run from if `sandbox` has it, else the project root.
    pub fn start_dir(&self, sandbox: &Path) -> PathBuf {
        if !self.rel.as_os_str().is_empty() && sandbox.join(&self.rel).is_dir() {
            self.root.join(&self.rel)
        } else {
            self.root.clone()
        }
    }

    /// The whole command line for running `command` with `sandbox` at the
    /// project's path: `(program, args)`.
    fn argv(&self, sandbox: &Path, command: &[String], unit: &str) -> (PathBuf, Vec<OsString>) {
        let dir = self.start_dir(sandbox);
        let mut args: Vec<OsString> = Vec::new();
        let program = match &self.backend {
            Backend::Systemd { run, verbatim, .. } if self.limits.wants_cgroup() || self.limits.cpu_time.is_some() => {
                args.extend(["--user", "--scope", "--quiet", "--unit", unit].map(OsString::from));
                if *verbatim {
                    args.push("--expand-environment=no".into());
                }
                let mut prop = |p: String| {
                    args.push("-p".into());
                    args.push(p.into());
                };
                if let Some(m) = &self.limits.memory {
                    prop(format!("MemoryMax={}", m.value));
                    prop("MemorySwapMax=0".into());
                    prop("OOMPolicy=kill".into());
                }
                if let Some(c) = &self.limits.cpus {
                    prop(format!("CPUQuota={}%", (c.value * 100.0).round().max(1.0) as u64));
                }
                if let Some(p) = &self.limits.pids {
                    // `bwrap` itself is two of the scope's tasks.
                    prop(format!("TasksMax={}", p.value + 2));
                }
                args.push("--".into());
                args.push(self.bwrap.clone().into());
                run.clone()
            }
            _ => self.bwrap.clone(),
        };
        args.extend(self.base.iter().cloned());
        for a in [
            "--bind".into(),
            sandbox.as_os_str().to_owned(),
            self.root.as_os_str().to_owned(),
            "--chdir".into(),
            dir.as_os_str().to_owned(),
            "--setenv".into(),
            "PWD".into(),
            dir.as_os_str().to_owned(),
            "--setenv".into(),
            "HOME".into(),
            self.home.as_os_str().to_owned(),
            "--setenv".into(),
            "TMPDIR".into(),
            "/tmp".into(),
            "--".into(),
        ] {
            args.push(a);
        }
        args.extend(command.iter().map(OsString::from));
        (program, args)
    }

    /// One line for `running … in …`.
    pub fn describe(&self, sandbox: &Path) -> String {
        let mut what = vec![format!("confined at {}", self.start_dir(sandbox).display())];
        if self.base.iter().any(|a| a == "--unshare-net") {
            what.push("no network".into());
        }
        let l = &self.limits;
        if let Some(m) = &l.memory {
            what.push(format!("memory {}", m.shown));
        }
        if let Some(c) = &l.cpus {
            what.push(format!("cpus {}", c.shown));
        }
        if let Some(c) = &l.cpu_time {
            what.push(format!("cpu-time {}", c.shown));
        }
        if let Some(p) = &l.pids {
            what.push(format!("pids {}", p.shown));
        }
        if let Some(t) = &l.timeout {
            what.push(format!("timeout {}", t.shown));
        }
        what.join(", ")
    }
}

/// The default allow-list under `home`, as `(path, explicit)`. None
/// without a usable `HOME`: the stand-in `/tmp/home` is anyone's to create.
fn default_allow(home: Option<&Path>) -> Vec<(PathBuf, bool)> {
    home.map(|h| DEFAULT_ALLOW.iter().map(|d| (h.join(d), false)).collect()).unwrap_or_default()
}

/// `$HOME`, when it is a usable absolute path.
fn home_dir() -> Option<PathBuf> {
    let h = PathBuf::from(std::env::var_os("HOME")?);
    let h = normal(&h)?;
    (h != Path::new("/")).then_some(h)
}

/// `name` in `$PATH`: absolute entries only, and never inside the project
/// at `root` (a repository cannot supply its own `bwrap`, as for hooks and
/// drivers).
fn find_program(name: &str, root: Option<&Path>) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    let inside = |p: &Path| {
        root.is_some_and(|r| p.starts_with(r) || p.canonicalize().is_ok_and(|c| c.starts_with(r)))
    };
    std::env::split_paths(&path)
        .filter(|d| d.is_absolute() && !inside(d))
        .map(|d| d.join(name))
        .find(|p| !inside(p) && is_executable(p))
}

fn is_executable(p: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        p.is_file()
    }
}

/// The namespaces and every mount but the sandbox's. `allow`: `(path,
/// explicit)`; a missing default is skipped, a missing explicit entry is an
/// error. `root`: the project's canonical path, where the sandbox appears.
///
/// The Veil home, the real project (its `.veil`: the store and the other
/// workspaces' sandboxes) and cargo's credentials stay hidden whatever the
/// allow-list holds: under their own names, and under every other name an
/// allowed link gives them (an allowed `~/src` that links to the disk
/// holding the project). An allowed path inside the Veil home or the
/// project is refused.
fn base_args(home: &Path, root: Option<&Path>, allow: &[(PathBuf, bool)], no_network: bool) -> Result<Vec<OsString>> {
    let mut a: Vec<OsString> = Vec::new();
    let mut push = |items: &[&std::ffi::OsStr]| a.extend(items.iter().map(|s| s.to_os_string()));
    for f in [
        "--die-with-parent",
        "--new-session",
        "--unshare-user",
        "--disable-userns",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-cgroup-try",
    ] {
        push(&[f.as_ref()]);
    }
    if no_network {
        push(&["--unshare-net".as_ref()]);
    }
    // The computer's tools, read-only.
    for d in ["/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/etc", "/opt", "/nix", "/sys"] {
        match std::fs::symlink_metadata(d) {
            Ok(m) if m.file_type().is_symlink() => {
                if let Ok(t) = std::fs::read_link(d) {
                    push(&["--symlink".as_ref(), t.as_os_str(), d.as_ref()]);
                }
            }
            Ok(m) if m.is_dir() => push(&["--ro-bind".as_ref(), d.as_ref(), d.as_ref()]),
            _ => {}
        }
    }
    for f in [["--proc", "/proc"], ["--dev", "/dev"], ["--tmpfs", "/tmp"], ["--tmpfs", "/var/tmp"], ["--dir", "/run"]] {
        push(&[f[0].as_ref(), f[1].as_ref()]);
    }
    // DNS: `/etc/resolv.conf` often points into `/run`.
    if let Ok(t) = std::fs::read_link("/etc/resolv.conf") {
        let t = Path::new("/etc").join(t);
        if let Some(dir) = t.canonicalize().ok().and_then(|t| t.parent().map(Path::to_path_buf)) {
            if dir.starts_with("/run/") {
                push(&["--ro-bind".as_ref(), dir.as_os_str(), dir.as_os_str()]);
            }
        }
    }
    push(&["--tmpfs".as_ref(), home.as_os_str()]);
    let vh = crate::ctx::veil_home();
    let vh_real = vh.canonicalize().ok().filter(|v| v.is_dir() && v != Path::new("/"));
    // What an allowed path may not be inside of.
    let inside: Vec<(&Path, &str)> = [(vh_real.as_deref(), "inside the Veil home, which stays hidden"), (root, "inside the project, where the command sees its sandbox")]
        .into_iter()
        .filter_map(|(p, why)| Some((p?, why)))
        .collect();
    // `(dest, src)`: where each allowed path appears, and what it shows.
    let mut bound: Vec<(PathBuf, PathBuf)> = Vec::new();
    'allow: for (p, explicit) in allow {
        // Where it appears: the path as given (a symlinked `~/.local/bin`
        // stays where `PATH` names it), else resolved (`..`).
        let dest = match normal(p).or_else(|| p.canonicalize().ok()) {
            Some(d) if d != Path::new("/") => d,
            Some(_) if *explicit => bail!("--allow {}: that is the whole machine", safe(&p.to_string_lossy())),
            None if *explicit => bail!("--allow {}: no such file or directory", safe(&p.to_string_lossy())),
            _ => continue,
        };
        let src = match dest.canonicalize() {
            Ok(s) if s != Path::new("/") => s,
            Ok(_) if *explicit => bail!("--allow {}: that is the whole machine", safe(&p.to_string_lossy())),
            Err(e) if *explicit => bail!("--allow {}: {e}", safe(&p.to_string_lossy())),
            _ => continue,
        };
        for (h, why) in &inside {
            if src.starts_with(h) {
                match explicit {
                    true => bail!("--allow {}: that is {why}", safe(&p.to_string_lossy())),
                    false => continue 'allow,
                }
            }
        }
        if bound.iter().any(|(d, _)| *d == dest) {
            continue;
        }
        push(&["--ro-bind".as_ref(), src.as_os_str(), dest.as_os_str()]);
        bound.push((dest, src));
    }
    // Every name under which the allow-list shows `real` (canonical).
    let aliases = |real: &Path| -> Vec<PathBuf> {
        bound.iter().filter_map(|(dest, src)| real.strip_prefix(src).ok().map(|rel| dest.join(rel))).collect()
    };
    let mut masks: Vec<(&str, PathBuf)> = Vec::new();
    // Credential files, as named and wherever an allowed path shows them.
    let cargo_home = std::env::var_os("CARGO_HOME").map(PathBuf::from).filter(|c| c.is_absolute());
    for p in [Some(home.join(".cargo")), cargo_home].iter().flatten().flat_map(|c| MASKED.iter().map(|m| c.join(m))) {
        if !std::fs::metadata(&p).is_ok_and(|m| m.is_file()) {
            continue;
        }
        if bound.iter().any(|(d, _)| p.starts_with(d)) {
            masks.push(("/dev/null", p.clone()));
        }
        masks.extend(p.canonicalize().iter().flat_map(|c| aliases(c)).map(|a| ("/dev/null", a)));
    }
    // The Veil identity and keys, and the real project.
    if let Some(v) = &vh_real {
        masks.extend(normal(&vh).into_iter().chain([v.clone()]).chain(aliases(v)).map(|v| ("", v)));
    }
    if let Some(r) = root {
        masks.extend(aliases(r).into_iter().filter(|a| a != r).map(|a| ("", a)));
    }
    let mut done: Vec<PathBuf> = Vec::new();
    for (with, at) in masks {
        if at == Path::new("/") || done.contains(&at) {
            continue;
        }
        match with {
            "" => push(&["--tmpfs".as_ref(), at.as_os_str()]),
            file => push(&["--ro-bind".as_ref(), file.as_ref(), at.as_os_str()]),
        }
        done.push(at);
    }
    Ok(a)
}

/// Run the confinement once with `true`: a missing or unusable `bwrap`
/// fails here, before the sandbox is touched.
fn probe(bwrap: &Path, base: &[OsString]) -> Result<()> {
    let out = std::process::Command::new(bwrap)
        .args(base)
        .args(["--", "true"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output();
    match out {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr);
            let err = err.lines().find(|l| !l.trim().is_empty()).unwrap_or("it failed without a message");
            bail!(
                "confinement does not work on this machine ({}). Check that bubblewrap works here ({INSTALL}; its AppArmor profile lets it create namespaces), {OPT_OUT}",
                safe(err.trim())
            )
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            bail!("confinement needs bubblewrap, which is not installed: {INSTALL}, {OPT_OUT}")
        }
        Err(e) => bail!("confinement does not work on this machine (running {}: {e}), {OPT_OUT}", bwrap.display()),
    }
}

/// The mechanism for `limits` (`VEIL_EXEC_LIMITS_BACKEND=systemd|poll`
/// forces one, for tests).
fn backend(limits: &Limits, root: &Path) -> Result<Backend> {
    let forced = std::env::var("VEIL_EXEC_LIMITS_BACKEND").ok();
    match forced.as_deref() {
        Some("poll") => return Ok(Backend::Poll),
        Some("systemd") | None => {}
        Some(other) => bail!("VEIL_EXEC_LIMITS_BACKEND={}: one of systemd, poll", safe(other)),
    }
    if !limits.wants_cgroup() && limits.cpu_time.is_none() && forced.is_none() {
        return Ok(Backend::Poll);
    }
    match systemd(Some(root)) {
        Some(b) => Ok(b),
        None if forced.is_some() => bail!("VEIL_EXEC_LIMITS_BACKEND=systemd: no systemd user manager answers here"),
        None => Ok(Backend::Poll),
    }
}

/// How long a `systemd-run` or `systemctl` call may take before `vl` gives
/// up on it: a user manager that does not answer must not hang `vl`.
const SYSTEMD_WAIT: Duration = Duration::from_secs(5);

/// `cmd`'s output (stdin closed, stderr dropped), or `None` if it cannot
/// run or outlives `limit`, when it is killed.
fn output_within(cmd: &mut std::process::Command, limit: Duration) -> Option<std::process::Output> {
    use std::process::Stdio;
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().ok()?;
    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return child.wait_with_output().ok(),
            Ok(None) if start.elapsed() < limit => std::thread::sleep(Duration::from_millis(5)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

/// A working systemd user manager: `systemd-run --user --scope` runs `true`
/// in time.
fn systemd(root: Option<&Path>) -> Option<Backend> {
    let run = find_program("systemd-run", root)?;
    let ctl = find_program("systemctl", root)?;
    let works = |extra: &[&str]| {
        let mut c = std::process::Command::new(&run);
        c.args(["--user", "--scope", "--quiet", "--collect"]).args(extra).args(["--", "true"]);
        output_within(&mut c, SYSTEMD_WAIT).is_some_and(|o| o.status.success())
    };
    let verbatim = match works(&["--expand-environment=no"]) {
        true => true,
        false if works(&[]) => false,
        false => return None,
    };
    Some(Backend::Systemd { run, ctl, verbatim })
}

/// `(soft, unavailable)` limit names with `backend`.
fn weak_limits(l: &Limits, backend: &Backend) -> (Vec<&'static str>, Vec<&'static str>) {
    let (mut soft, mut none) = (Vec::new(), Vec::new());
    if *backend == Backend::Poll {
        if l.memory.is_some() {
            soft.push("memory");
        }
        if l.pids.is_some() {
            soft.push("pids");
        }
        if l.cpu_time.is_some() {
            soft.push("cpu-time");
        }
        if l.cpus.is_some() {
            none.push("cpus");
        }
    }
    (soft, none)
}

/// What `vl doctor` says about confinement here: `(works, line, detail)`.
pub fn doctor(root: Option<&Path>) -> Vec<(bool, String, Vec<String>)> {
    let mut out = Vec::new();
    if !BUILT {
        out.push((true, "confinement: not built for this OS yet; `vl ws exec` runs unconfined".to_string(), Vec::new()));
        return out;
    }
    let home = home_dir().unwrap_or_else(|| PathBuf::from("/tmp/home"));
    match find_program("bwrap", root) {
        None => out.push((
            false,
            "confinement: bubblewrap is not installed; `vl ws exec` refuses to run without --unconfined".into(),
            vec![format!("Fix: {INSTALL}")],
        )),
        Some(bwrap) => {
            let version = std::process::Command::new(&bwrap)
                .arg("--version")
                .output()
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_default();
            let probe = base_args(&home, None, &[], false).and_then(|base| probe(&bwrap, &base));
            match probe {
                Ok(()) => out.push((true, format!("confinement works ({}): `vl ws exec` runs confined", safe(&version)), Vec::new())),
                Err(e) => out.push((false, "confinement does not work here".into(), vec![safe(&e.to_string()).into_owned()])),
            }
        }
    }
    match systemd(root) {
        Some(_) => out.push((true, "resource limits: a systemd user scope (enforced by the kernel)".into(), Vec::new())),
        None => out.push((
            true,
            "resource limits: no systemd user manager; --memory, --pids and --cpu-time are polled (soft), --cpus is not available".into(),
            Vec::new(),
        )),
    }
    out
}

// ---- running ---------------------------------------------------------------

#[cfg(target_os = "linux")]
pub use run::run;

#[cfg(not(target_os = "linux"))]
pub fn run(_: &Confine, _: &Path, _: &[String], _: &[(&str, OsString)]) -> Result<i32> {
    bail!("confinement is only built for Linux")
}

#[cfg(target_os = "linux")]
mod run {
    use std::{
        ffi::OsString,
        os::unix::process::{CommandExt, ExitStatusExt},
        path::Path,
        process::Command,
        sync::atomic::{AtomicI32, Ordering},
        time::{Duration, Instant},
    };

    use anyhow::{Context, Result};

    use super::{show_size, Backend, Confine};
    use crate::render::{dim, warn};

    /// Signals `vl` forwards to a confined command.
    const SIGNALS: [libc::c_int; 4] = [libc::SIGINT, libc::SIGQUIT, libc::SIGTERM, libc::SIGHUP];
    /// How often limits are checked.
    const TICK: Duration = Duration::from_millis(100);
    /// From SIGTERM to SIGKILL when a limit stops the sandbox.
    const GRACE: Duration = Duration::from_secs(10);

    /// The write end of the pipe the signal handler writes to (-1: none).
    static SIGNAL_PIPE: AtomicI32 = AtomicI32::new(-1);

    extern "C" fn on_signal(sig: libc::c_int) {
        let fd = SIGNAL_PIPE.load(Ordering::SeqCst);
        if fd >= 0 {
            let b = sig as u8;
            // SAFETY: write(2) is async-signal-safe; the pipe is non-blocking.
            unsafe {
                libc::write(fd, &b as *const u8 as *const libc::c_void, 1);
            }
        }
    }

    /// While it lives, SIGINT, SIGQUIT, SIGTERM and SIGHUP to `vl` are
    /// written to a pipe (those `vl` was ignoring stay ignored).
    struct Signals {
        read: libc::c_int,
        write: libc::c_int,
        old: Vec<(libc::c_int, libc::sigaction)>,
        /// The dispositions the command gets.
        child: Vec<(libc::c_int, libc::sighandler_t)>,
    }

    impl Signals {
        fn install() -> Result<Signals> {
            let mut fds = [0; 2];
            // SAFETY: pipe2 writes two descriptors into `fds`.
            if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
                return Err(std::io::Error::last_os_error()).context("creating a pipe");
            }
            SIGNAL_PIPE.store(fds[1], Ordering::SeqCst);
            let mut s = Signals { read: fds[0], write: fds[1], old: Vec::new(), child: Vec::new() };
            for sig in SIGNALS {
                // SAFETY: plain sigaction(2) calls on zeroed structs; the
                // handler only calls write(2).
                unsafe {
                    let mut prev: libc::sigaction = std::mem::zeroed();
                    if libc::sigaction(sig, std::ptr::null(), &mut prev) != 0 {
                        continue;
                    }
                    if prev.sa_sigaction == libc::SIG_IGN {
                        s.child.push((sig, libc::SIG_IGN));
                        continue;
                    }
                    let mut new: libc::sigaction = std::mem::zeroed();
                    new.sa_sigaction = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
                    new.sa_flags = libc::SA_RESTART;
                    libc::sigemptyset(&mut new.sa_mask);
                    if libc::sigaction(sig, &new, std::ptr::null_mut()) == 0 {
                        s.old.push((sig, prev));
                        s.child.push((sig, libc::SIG_DFL));
                    }
                }
            }
            Ok(s)
        }

        /// The signals received since the last call.
        fn take(&self) -> Vec<libc::c_int> {
            let mut buf = [0u8; 64];
            let mut out = Vec::new();
            loop {
                // SAFETY: reads into a local buffer.
                let n = unsafe { libc::read(self.read, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
                if n <= 0 {
                    return out;
                }
                out.extend(buf[..n as usize].iter().map(|b| *b as libc::c_int));
            }
        }
    }

    impl Drop for Signals {
        fn drop(&mut self) {
            for (sig, prev) in &self.old {
                // SAFETY: restores the disposition saved above.
                unsafe {
                    libc::sigaction(*sig, prev, std::ptr::null_mut());
                }
            }
            SIGNAL_PIPE.store(-1, Ordering::SeqCst);
            // SAFETY: our own descriptors.
            unsafe {
                libc::close(self.read);
                libc::close(self.write);
            }
        }
    }

    /// A process pinned by a pidfd: a reused pid is never signalled.
    struct Pinned {
        pid: i32,
        fd: libc::c_int,
    }

    impl Pinned {
        fn open(pid: i32) -> Option<Pinned> {
            // SAFETY: pidfd_open(2) takes a pid and flags.
            let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as libc::c_int;
            (fd >= 0).then_some(Pinned { pid, fd })
        }

        fn signal(&self, sig: libc::c_int) -> bool {
            // SAFETY: pidfd_send_signal(2) on our own pidfd.
            unsafe { libc::syscall(libc::SYS_pidfd_send_signal, self.fd, sig, std::ptr::null::<libc::siginfo_t>(), 0) == 0 }
        }
    }

    impl Drop for Pinned {
        fn drop(&mut self) {
            // SAFETY: our own descriptor.
            unsafe {
                libc::close(self.fd);
            }
        }
    }

    /// The children of `pid` (every thread's).
    fn children(pid: i32) -> Vec<i32> {
        let mut out = Vec::new();
        let Ok(tasks) = std::fs::read_dir(format!("/proc/{pid}/task")) else { return out };
        for t in tasks.flatten() {
            if let Ok(s) = std::fs::read_to_string(t.path().join("children")) {
                out.extend(s.split_whitespace().filter_map(|n| n.parse::<i32>().ok()));
            }
        }
        out
    }

    /// `pid` and its descendants, with their parents.
    fn tree(pid: i32) -> Vec<(i32, i32)> {
        let mut out = vec![(pid, 0)];
        let mut i = 0;
        while i < out.len() && out.len() < 1 << 20 {
            let p = out[i].0;
            out.extend(children(p).into_iter().map(|c| (c, p)));
            i += 1;
        }
        out
    }

    /// The fields of `/proc/<pid>/stat` after the command name (field 3 on).
    fn stat(pid: i32) -> Option<Vec<i64>> {
        let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let rest = &s[s.rfind(')')? + 1..];
        Some(rest.split_whitespace().skip(1).map(|f| f.parse().unwrap_or(0)).collect())
    }

    /// `pid`'s parent (`stat` field 4).
    fn parent(pid: i32) -> Option<i32> {
        stat(pid)?.first().map(|p| *p as i32)
    }

    /// Signal `pid` if it is still `parent`'s child.
    fn signal_checked(pid: i32, parent_pid: i32, sig: libc::c_int) {
        if let Some(p) = Pinned::open(pid) {
            if parent(pid) == Some(parent_pid) {
                p.signal(sig);
            }
        }
    }

    /// The command: the child of the namespace's init whose pid in the
    /// namespace is 2.
    fn find_command(outer: i32) -> Option<Pinned> {
        let init = *children(outer).first()?;
        for c in children(init) {
            let status = std::fs::read_to_string(format!("/proc/{c}/status")).ok()?;
            let ns = status.lines().find_map(|l| l.strip_prefix("NSpid:"))?;
            if ns.split_whitespace().last() == Some("2") {
                return Pinned::open(c).filter(|_| parent(c) == Some(init));
            }
        }
        None
    }

    /// What the sandbox's processes use, from `/proc`.
    #[derive(Default)]
    struct Usage {
        rss: u64,
        tasks: u64,
        cpu: Duration,
    }

    fn usage(outer: i32) -> Usage {
        // SAFETY: sysconf has no preconditions.
        let (page, hz) = unsafe { (libc::sysconf(libc::_SC_PAGESIZE).max(1) as u64, libc::sysconf(libc::_SC_CLK_TCK).max(1) as u64) };
        let mut u = Usage::default();
        for (pid, _) in tree(outer) {
            if let Ok(s) = std::fs::read_to_string(format!("/proc/{pid}/statm")) {
                u.rss += s.split_whitespace().nth(1).and_then(|r| r.parse::<u64>().ok()).unwrap_or(0) * page;
            }
            u.tasks += std::fs::read_dir(format!("/proc/{pid}/task")).map(|d| d.count() as u64).unwrap_or(0);
            if let Some(f) = stat(pid) {
                // utime, stime, cutime, cstime: fields 14 to 17 (`stat`
                // starts at field 4).
                let ticks: i64 = f.get(10..14).map(|x| x.iter().sum()).unwrap_or(0);
                u.cpu += Duration::from_millis(ticks.max(0) as u64 * 1000 / hz);
            }
        }
        u
    }

    /// The scope's cgroup directory, once `systemd-run` has moved into it.
    fn cgroup_of(pid: i32, unit: &str) -> Option<std::path::PathBuf> {
        let s = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
        let path = s.lines().find_map(|l| l.strip_prefix("0::"))?;
        path.ends_with(&format!("/{unit}.scope"))
            .then(|| Path::new("/sys/fs/cgroup").join(path.trim_start_matches('/')))
    }

    /// A counter from a cgroup `*.events` or `*.stat` file.
    fn cgroup_value(dir: &Path, file: &str, key: &str) -> Option<u64> {
        let s = std::fs::read_to_string(dir.join(file)).ok()?;
        s.lines().find_map(|l| l.strip_prefix(key)?.strip_prefix(' ')?.trim().parse().ok())
    }

    /// Run `command` confined by `c`, with `sandbox` at the project's path
    /// and `env` added. The exit status is the command's (128 + n for a
    /// signal); a limit that stopped it is reported.
    pub fn run(c: &Confine, sandbox: &Path, command: &[String], env: &[(&str, OsString)]) -> Result<i32> {
        let unit = format!("veil-exec-{}-{}", std::process::id(), hex::encode(veil_core::crypto::random_bytes::<4>()));
        let (program, args) = c.argv(sandbox, command, &unit);
        let scoped = program != c.bwrap;
        let signals = Signals::install()?;
        let mut cmd = Command::new(&program);
        cmd.args(&args).process_group(0);
        for (k, v) in env {
            cmd.env(k, v);
        }
        let child_dispositions = signals.child.clone();
        let rlimit_cpu = match (&c.backend, &c.limits.cpu_time, scoped) {
            (_, Some(t), false) => Some(t.value.as_secs().max(1)),
            _ => None,
        };
        let vl = std::process::id() as libc::pid_t;
        // SAFETY: only prctl(2), getppid(2), signal(2) and setrlimit(2),
        // which are async-signal-safe, between fork and exec.
        unsafe {
            cmd.pre_exec(move || {
                // `vl` dying at any moment kills `systemd-run` or `bwrap`
                // (and so the sandbox): `bwrap`'s own `--die-with-parent`
                // only holds once it has started. It survives both execs.
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 || libc::getppid() != vl {
                    return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
                }
                for (sig, d) in &child_dispositions {
                    libc::signal(*sig, *d);
                }
                if let Some(secs) = rlimit_cpu {
                    let r = libc::rlimit { rlim_cur: secs, rlim_max: secs + 1 };
                    libc::setrlimit(libc::RLIMIT_CPU, &r);
                }
                Ok(())
            });
        }
        let mut child = cmd.spawn().with_context(|| format!("failed to run {}", program.display()))?;
        let outer = child.id() as i32;
        let pidfd = Pinned::open(outer);
        let started = Instant::now();
        let l = &c.limits;
        let polls = l.cpu_time.is_some() || (!scoped && (l.memory.is_some() || l.pids.is_some())) || (scoped && l.pids.is_some());
        let mut target: Option<Pinned> = None;
        let mut pending: Vec<libc::c_int> = Vec::new();
        let mut cgroup: Option<std::path::PathBuf> = None;
        let mut stopped: Option<String> = None;
        let mut kill_at: Option<Instant> = None;
        let mut forks_refused = false;
        let status = loop {
            if let Some(s) = child.try_wait()? {
                break s;
            }
            let now = Instant::now();
            let mut wait = if polls { Some(TICK) } else { None };
            let mut at = |t: Instant| {
                let d = t.saturating_duration_since(now);
                wait = Some(wait.map_or(d, |w| w.min(d)));
            };
            if let (Some(t), None) = (&l.timeout, &stopped) {
                at(started + t.value);
            }
            if let Some(k) = kill_at {
                at(k);
            }
            if !pending.is_empty() {
                at(now + Duration::from_millis(10));
            }
            let ms = wait.map_or(-1, |w| w.as_millis().min(i32::MAX as u128) as i32);
            let mut fds = vec![libc::pollfd { fd: signals.read, events: libc::POLLIN, revents: 0 }];
            if let Some(p) = &pidfd {
                fds.push(libc::pollfd { fd: p.fd, events: libc::POLLIN, revents: 0 });
            }
            // SAFETY: polls our own descriptors.
            unsafe {
                // Without a pidfd (Linux before 5.3) the exit is noticed by polling.
                let ms = match (&pidfd, ms) {
                    (Some(_), ms) => ms,
                    (None, ms) if ms < 0 => 50,
                    (None, ms) => ms.min(50),
                };
                libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, ms);
            }
            pending.extend(signals.take());
            if !pending.is_empty() {
                if target.is_none() {
                    target = find_command(outer);
                }
                if let Some(t) = &target {
                    for sig in pending.drain(..) {
                        match sig {
                            // As the terminal would: the command's process group.
                            libc::SIGINT | libc::SIGQUIT => {
                                if let Some(pg) = stat(t.pid).and_then(|f| f.get(1).copied()).filter(|g| *g > 1) {
                                    // SAFETY: kill(2) of the sandbox's process group.
                                    unsafe {
                                        libc::kill(-(pg as i32), sig);
                                    }
                                }
                            }
                            _ => {
                                t.signal(sig);
                            }
                        }
                    }
                }
            }
            if scoped && cgroup.is_none() {
                cgroup = cgroup_of(outer, &unit);
            }
            // Limits.
            let now = Instant::now();
            if stopped.is_none() {
                let mut reason = None;
                let mut hard = false;
                if let Some(t) = &l.timeout {
                    if now >= started + t.value {
                        reason = Some(format!("time limit ({})", t.shown));
                    }
                }
                if polls && reason.is_none() {
                    let u = usage(outer);
                    let cpu = match (&cgroup, scoped) {
                        (Some(dir), true) => cgroup_value(dir, "cpu.stat", "usage_usec").map(Duration::from_micros).unwrap_or(u.cpu),
                        _ => u.cpu,
                    };
                    if let Some(t) = l.cpu_time.as_ref().filter(|t| cpu >= t.value) {
                        reason = Some(format!("CPU-time limit ({})", t.shown));
                    } else if let Some(m) = l.memory.as_ref().filter(|m| !scoped && u.rss > m.value) {
                        reason = Some(format!("memory limit ({})", show_size(m.value)));
                        hard = true;
                    } else if let Some(p) = l.pids.as_ref().filter(|p| !scoped && u.tasks.saturating_sub(2) > p.value) {
                        reason = Some(format!("process limit ({})", p.shown));
                        hard = true;
                    }
                    if let (Some(dir), true) = (&cgroup, scoped) {
                        forks_refused |= cgroup_value(dir, "pids.events", "max").is_some_and(|n| n > 0);
                    }
                }
                if let Some(r) = reason {
                    if hard {
                        let _ = child.kill();
                    } else {
                        let init = children(outer).first().copied();
                        for (pid, parent_pid) in tree(outer) {
                            if pid != outer && Some(pid) != init {
                                signal_checked(pid, parent_pid, libc::SIGTERM);
                            }
                        }
                        kill_at = Some(now + GRACE);
                    }
                    stopped = Some(r);
                }
            } else if kill_at.is_some_and(|k| now >= k) {
                // Killing `bwrap` takes its whole pid namespace with it.
                let _ = child.kill();
                kill_at = None;
            }
        };
        drop(signals);
        if let (Backend::Systemd { ctl, .. }, true) = (&c.backend, scoped) {
            // A scope the kernel's OOM killer stopped stays, failed, for
            // systemd to say why: read it, then clear it.
            if status.signal().is_some() || status.code().is_some_and(|c| c > 128) {
                // systemd learns of the OOM kill a moment after `vl` sees the
                // exit: wait (up to a second) for the scope to settle.
                let deadline = Instant::now() + super::SYSTEMD_WAIT;
                let show = || {
                    let mut c = Command::new(ctl);
                    c.args(["--user", "show", "-p", "ActiveState", "-p", "Result", &format!("{unit}.scope")]);
                    super::output_within(&mut c, deadline.saturating_duration_since(Instant::now()))
                        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
                        .unwrap_or_default()
                };
                let mut result = String::new();
                for _ in 0..20 {
                    if Instant::now() >= deadline {
                        break;
                    }
                    let out = show();
                    let get = |k: &str| out.lines().find_map(|l| l.strip_prefix(k)).unwrap_or("").to_string();
                    result = get("Result=");
                    if !matches!(get("ActiveState=").as_str(), "active" | "activating" | "deactivating") {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                if result == "oom-kill" && stopped.is_none() {
                    stopped = l.memory.as_ref().map(|m| format!("memory limit ({})", show_size(m.value)));
                }
                let mut c = Command::new(ctl);
                c.args(["--user", "reset-failed", &format!("{unit}.scope")]);
                let _ = super::output_within(&mut c, super::SYSTEMD_WAIT);
            }
            if forks_refused && stopped.is_none() {
                if let Some(p) = &l.pids {
                    warn(&format!("the command reached its process limit ({}): some of its forks were refused", p.shown));
                }
            }
        }
        // `RLIMIT_CPU`: SIGXCPU, then SIGKILL a second later (`bwrap` passes
        // the command's signal on as 128 + n).
        let sig = status.signal().or_else(|| status.code().filter(|c| *c > 128).map(|c| c - 128));
        if let (Some(t), None, Some(libc::SIGXCPU | libc::SIGKILL)) = (&l.cpu_time, &stopped, sig) {
            if rlimit_cpu.is_some() {
                stopped = Some(format!("CPU-time limit ({})", t.shown));
            }
        }
        if let Some(r) = &stopped {
            eprintln!("{} {r} reached; everything in the sandbox was stopped", dim("stopped:"));
        }
        if let Some(sig) = status.signal() {
            return Ok(128 + sig);
        }
        Ok(status.code().unwrap_or(1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_durations_and_counts_parse_strictly() {
        assert_eq!(parse_size("4G"), Some(4 << 30));
        assert_eq!(parse_size("512M"), Some(512 << 20));
        assert_eq!(parse_size("64KiB"), Some(64 << 10));
        assert_eq!(parse_size("1048576"), Some(1 << 20));
        for bad in ["", "0", "G", "4X", "-1G", "99999999999999999999G", "1.5G", "4 G G"] {
            assert_eq!(parse_size(bad), None, "{bad}");
        }
        assert_eq!(parse_duration("90s"), Some(Duration::from_secs(90)));
        assert_eq!(parse_duration("30m"), Some(Duration::from_secs(1800)));
        assert_eq!(parse_duration("2h"), Some(Duration::from_secs(7200)));
        assert_eq!(parse_duration("500ms"), Some(Duration::from_millis(500)));
        assert_eq!(parse_duration("45"), Some(Duration::from_secs(45)));
        for bad in ["", "0", "0s", "s", "1d", "-1s", "18446744073709551615h"] {
            assert_eq!(parse_duration(bad), None, "{bad}");
        }
        assert_eq!(parse_cpus("0.5"), Some(0.5));
        for bad in ["0", "-1", "NaN", "inf", "x"] {
            assert_eq!(parse_cpus(bad), None, "{bad}");
        }
        assert_eq!(parse_pids("64"), Some(64));
        for bad in ["0", "-1", "x", "99999999999"] {
            assert_eq!(parse_pids(bad), None, "{bad}");
        }
    }

    #[test]
    fn paths_are_absolute_and_without_dot_dot() {
        let home = Path::new("/home/u");
        assert_eq!(expand_home("~/.cargo", Some(home)), Some(PathBuf::from("/home/u/.cargo")));
        assert_eq!(expand_home("~", Some(home)), Some(PathBuf::from("/home/u")));
        assert_eq!(expand_home("relative", Some(home)), None);
        assert_eq!(expand_home("~/x", None), None);
        assert_eq!(normal(Path::new("/a/./b")), Some(PathBuf::from("/a/b")));
        assert_eq!(normal(Path::new("/a/../b")), None);
        assert_eq!(normal(Path::new("a/b")), None);
    }

    #[test]
    fn without_a_home_there_is_no_default_allow_list() {
        assert!(default_allow(None).is_empty());
        assert_eq!(default_allow(Some(Path::new("/home/u"))).len(), DEFAULT_ALLOW.len());
    }

    #[test]
    fn the_defaults_never_include_keys() {
        for d in DEFAULT_ALLOW {
            for k in [".ssh", ".gnupg", ".config", ".aws", ".kube", ".docker", ".netrc", ".npmrc", ".pki"] {
                assert!(*d != k && !d.starts_with(&format!("{k}/")), "{d} shows {k}");
            }
            assert!(*d != ".local/share" && *d != ".local", "{d} shows keyrings");
        }
    }
}
