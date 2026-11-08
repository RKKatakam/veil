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
//! * an **allow-list** of toolchain and agent folders from the home
//!   (defaults, `--allow`, and `[exec.confine] allow` in the device-local
//!   configuration) is shown through overlays: the real folders are never
//!   written; the command's writes go to the workspace's own layers
//!   ([`Layers`], BUG-1025), or are thrown away after the run;
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
    #[arg(long, conflicts_with_all = ["allow", "no_network", "private_ports", "seed", "memory", "cpus", "cpu_time", "pids", "timeout", "limits"])]
    pub unconfined: bool,
    /// Also show PATH (a folder or file of this machine) to the command; its writes go to the workspace's own layer, never to PATH. Repeatable.
    #[arg(long, value_name = "PATH")]
    pub allow: Vec<String>,
    /// No network: the command gets only a private loopback.
    #[arg(long)]
    pub no_network: bool,
    /// A private loopback that keeps outbound access: the command gets its own network, so every run can bind 127.0.0.1:5432 or :8080 at once, and reaches the outside through pasta (from passt). The host's loopback is not reachable from it.
    #[arg(long, conflicts_with = "no_network")]
    pub private_ports: bool,
    /// Mount the directory SRC at DEST (absolute paths) with a writable layer of this run's own on top: every run starts from SRC as it is, nothing is copied, SRC is never written, and the run's writes vanish when it exits. Repeatable.
    #[arg(long, value_name = "SRC:DEST")]
    pub seed: Vec<String>,
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

/// Folders and files of the home shown to the command by default, when
/// they exist: toolchains, and coding agents' own
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
/// The computer's folders the sandbox shows read-only (and what bwrap makes
/// of `/proc` and `/dev`): nothing can be mounted inside them.
const READ_ONLY: [&str; 11] = ["/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/etc", "/opt", "/nix", "/sys"];

/// What `vl` says when `--private-ports` finds no `pasta`.
const INSTALL_PASTA: &str =
    "--private-ports needs pasta (from passt), which is not installed: install passt (`apt install passt`, `dnf install passt` or `pacman -S passt`); nothing was run";
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

/// One `--seed SRC:DEST`, checked: `SRC` an existing directory of its own,
/// never the whole machine, the home or anything holding it, the Veil home
/// or the project (inside or holding them); `DEST` an absolute path
/// without `..`, never `/` and never where the sandbox appears.
fn seed(spec: &str, root: &Path, home: Option<&Path>) -> Result<(PathBuf, PathBuf)> {
    let shown = safe(spec);
    let (src, dest) = match spec.split(':').collect::<Vec<_>>()[..] {
        [s, d] if !s.is_empty() && !d.is_empty() => (Path::new(s), Path::new(d)),
        _ => bail!("--seed {shown}: give SRC:DEST, two absolute paths (neither may hold ':')"),
    };
    if !src.is_absolute() {
        bail!("--seed {shown}: SRC must be an absolute path");
    }
    let src = match src.canonicalize() {
        Ok(s) if s.is_dir() => s,
        Ok(_) => bail!("--seed {shown}: SRC is not a directory"),
        Err(_) => bail!("--seed {shown}: SRC: no such directory"),
    };
    let overlaps = |p: &Path| src.starts_with(p) || p.starts_with(&src);
    if src == Path::new("/") {
        bail!("--seed {shown}: SRC is the whole machine");
    }
    if home.and_then(|h| h.canonicalize().ok()).is_some_and(|h| h.starts_with(&src)) {
        bail!("--seed {shown}: SRC is your home, or holds it (keys, other projects); seed a directory of its own");
    }
    let vh = crate::ctx::veil_home();
    if [Some(vh.clone()), vh.canonicalize().ok()].iter().flatten().any(|v| overlaps(v)) {
        bail!("--seed {shown}: SRC is the Veil home, inside it, or holds it");
    }
    if overlaps(root) {
        bail!("--seed {shown}: SRC is the project, inside it, or holds it; the sandbox already shows the project's files");
    }
    let dest = normal(dest).ok_or_else(|| anyhow!("--seed {shown}: DEST must be an absolute path without '..'"))?;
    if dest == Path::new("/") {
        bail!("--seed {shown}: DEST is the whole machine");
    }
    if dest.starts_with(root) || root.starts_with(&dest) {
        bail!("--seed {shown}: DEST is where the sandbox shows the project, inside it, or holds it");
    }
    // Nothing can be made there (BUG-1364).
    if let Some(ro) = READ_ONLY.iter().chain(&["/proc", "/dev"]).find(|r| dest.starts_with(r)) {
        bail!(
            "--seed {shown}: DEST is inside {ro}, which the sandbox shows read-only (or as the system's): give a place such as /tmp/NAME, /srv/NAME or ~/NAME"
        );
    }
    Ok((src, dest))
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
    mounts: Mounts,
    /// The project's canonical path, where the sandbox appears.
    root: PathBuf,
    /// The sub-folder `vl` was run from, relative to `root`.
    rel: PathBuf,
    home: PathBuf,
    limits: Limits,
    backend: Backend,
    /// `--private-ports`: the `pasta` that gives the run its network.
    pasta: Option<PathBuf>,
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
            let asked = !a.allow.is_empty() || a.no_network || a.private_ports || !a.seed.is_empty() || Limits::new(a, &BTreeMap::new())?.any();
            if asked {
                bail!(
                    "confinement and limits are only built for Linux so far; run without --allow, --no-network, --private-ports, --seed and the limits"
                );
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
        let seeds = a.seed.iter().map(|s| seed(s, &root, home.as_deref())).collect::<Result<Vec<_>>>()?;
        for (i, (_, d)) in seeds.iter().enumerate() {
            if let Some((_, e)) = seeds[..i].iter().find(|(_, e)| d.starts_with(e) || e.starts_with(d)) {
                bail!("--seed: {} and {} overlap; give each seed a place of its own", d.display(), e.display());
            }
        }
        let home = home.unwrap_or_else(|| PathBuf::from("/tmp/home"));
        let bwrap = find_program("bwrap", Some(&root)).ok_or_else(|| anyhow!("confinement needs bubblewrap, which is not installed: {INSTALL}, {OPT_OUT}"))?;
        // Looked for before anything is touched: without it the run would
        // either have no network or share the host's loopback, and neither
        // is what was asked.
        let pasta = match a.private_ports {
            true => Some(find_program("pasta", Some(&root)).ok_or_else(|| anyhow!(INSTALL_PASTA))?),
            false => None,
        };
        let mounts = base_args(&home, Some(&root), &allow, &seeds, a.no_network || a.private_ports)?;
        if !mounts.seeds.is_empty() && overlay_probe(&bwrap, mounts.head.clone()).map_or(true, |r| r.is_err()) {
            bail!("--seed needs overlayfs, which does not work here; nothing was run");
        }
        probe(&bwrap, &mounts.args(&Layers::ReadOnly)?)?;
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
        Ok(Some(Confine { bwrap, mounts, root, rel, home, limits, backend, pasta }))
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
    fn argv(&self, mounts: Vec<OsString>, sandbox: &Path, command: &[String], unit: &str) -> (PathBuf, Vec<OsString>) {
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
        args.extend(mounts);
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
        if self.pasta.is_some() {
            what.push("private ports".into());
        } else if self.mounts.head.iter().any(|a| a == "--unshare-net") {
            what.push("no network".into());
        }
        for (src, dest) in &self.mounts.seeds {
            what.push(format!("seed {} at {}", src.display(), dest.display()));
        }
        let read_only: Vec<String> = self.mounts.allowed.iter().filter(|a| !a.layer).map(|a| a.dest.display().to_string()).collect();
        if !read_only.is_empty() {
            what.push(format!("read-only: {}", read_only.join(", ")));
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

/// Every mount but the sandbox's ([`base_args`]).
#[derive(Debug)]
struct Mounts {
    /// Namespaces, the computer's tools, and the private `HOME` and `/tmp`.
    head: Vec<OsString>,
    /// The allow-list.
    allowed: Vec<Allowed>,
    /// What stays hidden whatever the allow-list shows, mounted last.
    masks: Vec<OsString>,
    /// Where the masks are.
    hidden: Vec<PathBuf>,
    /// `--seed`: `(SRC, DEST)`, mounted last, each with a throwaway layer.
    seeds: Vec<(PathBuf, PathBuf)>,
}

/// What an allowed path is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Dir,
    /// A regular file.
    File,
    /// A socket, FIFO or device: bound as it is, never opened or copied.
    Other,
}

/// A folder or file of the allow-list.
#[derive(Debug)]
struct Allowed {
    /// Where it appears.
    dest: PathBuf,
    /// The real folder or file it shows (canonical).
    src: PathBuf,
    kind: Kind,
    /// Writes to it go to a layer ([`Layers`]). Only for a folder or a
    /// regular file (BUG-1032). Not for a folder that holds
    /// the project (whose `.veil` holds the layers), nor for one with
    /// anything hidden below its top level: a hidden path must stay a
    /// mount point the command cannot rename or delete.
    layer: bool,
}

/// Where writes to the allow-list go. The real folders and files are never
/// written: a folder is the lower layer of an overlay, a file is copied.
#[derive(Debug)]
enum Layers<'a> {
    /// Nowhere: the allow-list is read-only (the probe, and where overlayfs
    /// does not work).
    ReadOnly,
    /// Thrown away after the run: `--tmp-overlay`, and file copies in this
    /// directory.
    Throwaway(&'a Path),
    /// Kept for the workspace's later runs, in this directory of its
    /// sandbox's private state ([`layers_dir`]).
    Workspace(&'a Path),
}

/// The name of the directory of a workspace's layers, in its sandbox's
/// directory (`.veil/local/sandboxes/<ws>`, removed with it by `vl ws rm`):
/// `layers-<hash of its id>`, so an earlier workspace of the same name (one
/// `vl undo` removed) never lends its layers to a new one, and gets its
/// own back after `vl redo` (BUG-1031); `layers` for a workspace without an
/// id.
pub fn layers_dir(workspace_id: Option<&str>) -> String {
    match workspace_id {
        Some(id) => format!("layers-{}", &blake3::hash(id.as_bytes()).to_hex()[..16]),
        None => "layers".to_string(),
    }
}

/// The longest any step of setting up a confined run may take (a `bwrap`
/// probe, copying an allowed file): a hung filesystem must not hang `vl`
/// while it holds the workspace's lock.
const SETUP_WAIT: Duration = Duration::from_secs(30);

/// Copies of allowed files are made under this prefix, then renamed.
const COPY_PREFIX: &str = ".copy-";

/// The name of the layer of the allowed path `dest` in a layers directory:
/// its last component, readable, and a hash of the whole path.
fn layer_name(dest: &Path) -> String {
    use std::os::unix::ffi::OsStrExt;
    let last = dest.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let mut name: String = last
        .trim_start_matches('.')
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') { c } else { '_' })
        .take(32)
        .collect();
    if name.is_empty() {
        name.push_str("layer");
    }
    let hash = blake3::hash(dest.as_os_str().as_bytes());
    format!("{name}-{}", &hash.to_hex()[..16])
}

/// The mode of a copy of `src`: `0700` if it is executable, else `0600`.
fn copy_mode(src: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    if src.permissions().mode() & 0o100 != 0 { 0o700 } else { 0o600 }
}

/// A private copy of the real file `src` at `at` (mode [`copy_mode`],
/// applied again at every run): kept if `keep` and it is already a regular
/// file, else made afresh. Never written through a link: whatever is at
/// `at` is removed first, and the copy is created exclusively, then renamed
/// into place. Only a regular file is copied: it is opened without
/// blocking (a FIFO swapped in is never waited on) and checked; the copy
/// gives up after [`SETUP_WAIT`].
fn file_copy(src: &Path, at: &Path, keep: bool) -> Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    if keep && std::fs::symlink_metadata(at).is_ok_and(|m| m.is_file()) {
        let mode = copy_mode(&std::fs::metadata(src).with_context(|| format!("reading {}", src.display()))?);
        return std::fs::set_permissions(at, std::fs::Permissions::from_mode(mode)).with_context(|| format!("chmod {}", at.display()));
    }
    veil_core::vfs::remove_tree(at).with_context(|| format!("removing {}", at.display()))?;
    let dir = at.parent().ok_or_else(|| anyhow!("{} has no parent", at.display()))?;
    let tmp = dir.join(format!("{COPY_PREFIX}{}", hex::encode(veil_core::crypto::random_bytes::<8>())));
    let (from, to) = (src.to_path_buf(), tmp.clone());
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let copied = (|| -> std::io::Result<()> {
            let mut f = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW).open(&from)?;
            let meta = f.metadata()?;
            if !meta.is_file() {
                return Err(std::io::Error::other("not a regular file"));
            }
            let mut t = std::fs::OpenOptions::new().write(true).create_new(true).mode(copy_mode(&meta)).open(&to)?;
            std::io::copy(&mut f, &mut t).map(drop)
        })();
        let _ = tx.send(copied);
    });
    let made = match rx.recv_timeout(SETUP_WAIT) {
        Ok(r) => r.and_then(|()| std::fs::rename(&tmp, at)),
        Err(_) => Err(std::io::Error::other(format!("it took longer than {} s", SETUP_WAIT.as_secs()))),
    };
    if made.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    made.with_context(|| format!("copying {} to {}", src.display(), at.display()))
}

impl Mounts {
    /// The `bwrap` arguments, with writes to the allow-list going to
    /// `layers` (whose directories and copies this makes).
    fn args(&self, layers: &Layers<'_>) -> Result<Vec<OsString>> {
        let mut a = self.head.clone();
        for al in &self.allowed {
            let (src, dest) = (al.src.as_os_str().to_owned(), al.dest.as_os_str().to_owned());
            let at = match (layers, al.layer) {
                (Layers::Throwaway(d) | Layers::Workspace(d), true) => d.join(layer_name(&al.dest)),
                _ => {
                    a.extend(["--ro-bind".into(), src, dest]);
                    continue;
                }
            };
            let keep = matches!(layers, Layers::Workspace(_));
            if al.kind == Kind::File {
                if let Some(d) = at.parent() {
                    veil_core::vfs::private_dir(d).with_context(|| format!("creating {}", d.display()))?;
                }
                file_copy(&al.src, &at, keep)?;
                a.extend(["--bind".into(), at.into_os_string(), dest]);
            } else if !keep {
                a.extend(["--overlay-src".into(), src, "--tmp-overlay".into(), dest]);
            } else {
                if !std::fs::symlink_metadata(&at).is_ok_and(|m| m.is_dir()) {
                    veil_core::vfs::remove_tree(&at).with_context(|| format!("removing {}", at.display()))?;
                }
                let (upper, work) = (at.join("upper"), at.join("work"));
                for d in [&at, &upper, &work] {
                    veil_core::vfs::private_dir(d).with_context(|| format!("creating {}", d.display()))?;
                }
                // Whatever an earlier run left at a masked path (a folder,
                // a link, a FIFO where the real file has appeared since)
                // goes: the mask then lies on the real entry, whatever its
                // shape, and always mounts (BUG-1030). Links are removed,
                // never followed.
                for h in self.hidden.iter().filter(|h| h.parent() == Some(al.dest.as_path())) {
                    if let Some(name) = h.file_name() {
                        let entry = upper.join(name);
                        veil_core::vfs::remove_tree(&entry).with_context(|| format!("removing {}", entry.display()))?;
                    }
                }
                a.extend(["--overlay-src".into(), src, "--overlay".into(), upper.into_os_string(), work.into_os_string(), dest]);
            }
        }
        // Seeds: the source is the lower layer of an overlay whose upper
        // layer is a tmpfs of this run's own mount namespace, so the source
        // is never written, no other run sees the layer, and nothing of it
        // outlives the run (whatever kills it). Mounted before the masks,
        // which cover what they show too.
        for (src, dest) in &self.seeds {
            a.extend(["--overlay-src".into(), src.as_os_str().to_owned(), "--tmp-overlay".into(), dest.as_os_str().to_owned()]);
        }
        a.extend(self.masks.iter().cloned());
        Ok(a)
    }

    /// Does any allowed path take writes?
    fn any_layer(&self) -> bool {
        self.allowed.iter().any(|a| a.layer)
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
fn base_args(home: &Path, root: Option<&Path>, allow: &[(PathBuf, bool)], seeds: &[(PathBuf, PathBuf)], no_network: bool) -> Result<Mounts> {
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
    for d in READ_ONLY {
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
        bound.push((dest, src));
    }
    // Every name under which the sandbox shows `real` (canonical): through
    // the allow-list and through every seed. The masks below apply to every
    // way a host path enters the sandbox (BUG-1363).
    let shown: Vec<(PathBuf, PathBuf)> = bound.iter().cloned().chain(seeds.iter().map(|(src, dest)| (dest.clone(), src.clone()))).collect();
    let aliases = |real: &Path| -> Vec<PathBuf> {
        shown.iter().filter_map(|(dest, src)| real.strip_prefix(src).ok().map(|rel| dest.join(rel))).collect()
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
    let mut hide: Vec<OsString> = Vec::new();
    for (with, at) in masks {
        if at == Path::new("/") || done.contains(&at) {
            continue;
        }
        match with {
            "" => hide.extend(["--tmpfs".into(), at.as_os_str().to_owned()]),
            file => hide.extend(["--ro-bind".into(), file.into(), at.as_os_str().to_owned()]),
        }
        done.push(at);
    }
    let allowed = bound
        .into_iter()
        .map(|(dest, src)| {
            let holds_project = root.is_some_and(|r| r.starts_with(&src));
            let hidden_below = done.iter().any(|m| m.starts_with(&dest) && m.parent() != Some(dest.as_path()));
            let kind = match std::fs::metadata(&src) {
                Ok(m) if m.is_dir() => Kind::Dir,
                Ok(m) if m.is_file() => Kind::File,
                _ => Kind::Other,
            };
            Allowed { kind, layer: kind != Kind::Other && !holds_project && !hidden_below, dest, src }
        })
        .collect();
    Ok(Mounts { head: a, allowed, masks: hide, hidden: done, seeds: seeds.to_vec() })
}

/// Run the confinement once with `true`: a missing or unusable `bwrap`
/// fails here, before the sandbox is touched.
fn probe(bwrap: &Path, base: &[OsString]) -> Result<()> {
    match try_true(bwrap, base) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => bail!(
            "confinement does not work on this machine ({}). Check that bubblewrap works here ({INSTALL}; its AppArmor profile lets it create namespaces), {OPT_OUT}",
            safe(&err)
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            bail!("confinement needs bubblewrap, which is not installed: {INSTALL}, {OPT_OUT}")
        }
        Err(e) => bail!("confinement does not work on this machine (running {}: {e}), {OPT_OUT}", bwrap.display()),
    }
}

/// `bwrap ARGS -- true`: `Err` if it cannot be run, `Ok(Err(first line of
/// its error))` if it fails or outlives [`SETUP_WAIT`] (then it is killed).
fn try_true(bwrap: &Path, args: &[OsString]) -> std::io::Result<std::result::Result<(), String>> {
    use std::process::Stdio;
    let mut child = std::process::Command::new(bwrap)
        .args(args)
        .args(["--", "true"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    let start = std::time::Instant::now();
    while child.try_wait()?.is_none() {
        if start.elapsed() >= SETUP_WAIT {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(Err(format!("bwrap did not finish within {} s", SETUP_WAIT.as_secs())));
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    let o = child.wait_with_output()?;
    if o.status.success() {
        return Ok(Ok(()));
    }
    let err = String::from_utf8_lossy(&o.stderr);
    Ok(Err(err.lines().find(|l| !l.trim().is_empty()).unwrap_or("it failed without a message").trim().to_string()))
}

/// What a read-only allow-list breaks, for the warning when overlayfs does
/// not work.
const READ_ONLY_BREAKS: &str = "cargo cannot download crates, and coding agents cannot save their settings or sessions";

impl Confine {
    /// The mounts of a run: writes to the allow-list are kept in the
    /// layers directory `state` (a persistent sandbox's [`layers_dir`]; the
    /// caller holds its lock), or thrown away after the run (`None`), with
    /// the throwaway directory of file copies. Where the layers cannot be
    /// mounted, the allow-list is read-only, and `vl` says why and what
    /// that breaks.
    fn layered(&self, state: Option<&Path>) -> Result<(Vec<OsString>, Option<crate::sandbox::Sandbox>)> {
        let read_only = || self.mounts.args(&Layers::ReadOnly);
        if !self.mounts.any_layer() {
            return Ok((read_only()?, None));
        }
        let mut copies = None;
        let layered = match state {
            Some(dir) => veil_core::vfs::private_dir(dir)
                .with_context(|| format!("creating {}", dir.display()))
                .and_then(|()| {
                    // Copies a timed-out copy left behind.
                    for e in std::fs::read_dir(dir)?.flatten() {
                        if e.file_name().to_string_lossy().starts_with(COPY_PREFIX) {
                            let _ = veil_core::vfs::remove_tree(&e.path());
                        }
                    }
                    self.mounts.args(&Layers::Workspace(dir))
                }),
            None => {
                if self.mounts.allowed.iter().any(|a| a.layer && a.kind == Kind::File) {
                    copies = Some(crate::sandbox::Sandbox::create("home")?);
                }
                let dir = copies.as_ref().map_or(Path::new("/nonexistent"), |c| c.path());
                self.mounts.args(&Layers::Throwaway(dir))
            }
        };
        let why = match layered {
            Ok(args) => match try_true(&self.bwrap, &args) {
                Ok(Ok(())) => return Ok((args, copies)),
                // Say which: overlayfs itself, or these layers.
                Ok(Err(e)) if !self.overlay_works() => format!("overlayfs does not work here: {e}"),
                Ok(Err(e)) => match state {
                    Some(dir) => format!("the workspace's layers could not be mounted: {e}; deleting {} starts them over", dir.display()),
                    None => format!("the allowed folders could not be layered: {e}"),
                },
                Err(e) => e.to_string(),
            },
            Err(e) => format!("{e:#}"),
        };
        warn(&format!(
            "the allow-list is read-only in this run ({}); {READ_ONLY_BREAKS}",
            safe(&why)
        ));
        Ok((read_only()?, None))
    }

    /// Does an overlay of a folder every machine has mount here?
    fn overlay_works(&self) -> bool {
        overlay_probe(&self.bwrap, self.mounts.head.clone()).is_ok_and(|r| r.is_ok())
    }
}

/// `bwrap` with `head` and a throwaway overlay of `/usr`: does overlayfs
/// work here at all?
fn overlay_probe(bwrap: &Path, mut head: Vec<OsString>) -> std::io::Result<std::result::Result<(), String>> {
    head.extend(["--overlay-src", "/usr", "--tmp-overlay", "/usr"].map(OsString::from));
    try_true(bwrap, &head)
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
            let base = base_args(&home, None, &[], &[], false).and_then(|m| m.args(&Layers::ReadOnly));
            match base.as_ref().map_err(|e| anyhow!("{e:#}")).and_then(|b| probe(&bwrap, b)) {
                Ok(()) => out.push((true, format!("confinement works ({}): `vl ws exec` runs confined", safe(&version)), Vec::new())),
                Err(e) => out.push((false, "confinement does not work here".into(), vec![safe(&e.to_string()).into_owned()])),
            }
            // Writes to the allow-list: an overlay of a folder every machine has.
            if let Ok(b) = base {
                match overlay_probe(&bwrap, b) {
                    Ok(Ok(())) => out.push((true, "allow-list: writable, each workspace's writes kept in its own layer (overlayfs)".into(), Vec::new())),
                    Ok(Err(e)) => out.push((
                        false,
                        format!("allow-list: read-only, overlayfs does not work here ({})", safe(&e)),
                        vec![format!("{READ_ONLY_BREAKS} (a Linux kernel of 5.11 or later, and bubblewrap 0.10 or later, have it)")],
                    )),
                    Err(_) => {}
                }
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
pub use run::{run, stop_leftovers};
#[cfg(target_os = "linux")]
pub use net::hold_main;

/// Hidden first argument that turns `vl` into the holder of a confined
/// run's user namespace while `pasta` joins it ([`net`]).
pub const HOLD_ARG: &str = "__veil-netns-hold";

#[cfg(not(target_os = "linux"))]
pub fn run(_: &Confine, _: &Path, _: &[String], _: &[(&str, OsString)], _: Option<&Path>, _: Option<&Path>) -> Result<i32> {
    bail!("confinement is only built for Linux")
}

#[cfg(not(target_os = "linux"))]
pub fn stop_leftovers(_: &Path) {}

/// Stop and clear the `veil-exec-<pid>-*` scopes of `vl` processes that
/// are gone (BUG-852): `systemd-run` killed while systemd starts its scope
/// can leave it active, empty, or failed. Best effort, each call within
/// [`SYSTEMD_WAIT`]; nothing without a systemd user manager.
pub fn clear_dead_scopes() {
    if !BUILT {
        return;
    }
    let Some(ctl) = find_program("systemctl", None) else { return };
    let mut c = std::process::Command::new(&ctl);
    c.args(["--user", "list-units", "--all", "--plain", "--no-legend", "--full", "veil-exec-*"]);
    let Some(out) = output_within(&mut c, SYSTEMD_WAIT) else { return };
    let dead: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .filter(|u| {
            let pid = u.strip_prefix("veil-exec-").and_then(|r| r.split('-').next()).and_then(|p| p.parse::<u32>().ok());
            pid.is_some_and(|p| p != std::process::id() && veil_core::lock::process_alive(p) == Some(false))
        })
        .map(str::to_string)
        .collect();
    if dead.is_empty() {
        return;
    }
    for verb in [&["kill", "--signal=SIGKILL"][..], &["stop"], &["reset-failed"]] {
        let mut c = std::process::Command::new(&ctl);
        c.arg("--user").args(verb).args(&dead);
        let _ = output_within(&mut c, SYSTEMD_WAIT);
    }
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

    /// Does `cmdline` (`/proc/<pid>/cmdline`) start a confined run of
    /// `sandbox` (`want`: its canonical path)? Our `bwrap` (or the
    /// `systemd-run` that execs it) binds it read-write, and only it.
    fn runs_sandbox(cmdline: &[u8], sandbox: &Path, want: Option<&Path>) -> bool {
        use std::os::unix::ffi::OsStrExt;
        let args: Vec<&[u8]> = cmdline.split(|b| *b == 0).collect();
        let ours = ["--die-with-parent", "--unshare-pid"].iter().all(|f| args.contains(&f.as_bytes()));
        ours && args.windows(2).any(|w| {
            let at = Path::new(std::ffi::OsStr::from_bytes(w[1]));
            w[0] == b"--bind" && (at == sandbox || want.is_some_and(|c| at.canonicalize().is_ok_and(|a| a == c)))
        })
    }

    /// Stop every process still running a confined run of `sandbox`, for a
    /// `vl` that died (BUG-852). Its parent-death signal kills `bwrap`, and
    /// `--die-with-parent` the sandbox's init, but only once that init has
    /// armed it: `vl` killed in the moment between leaves the init, and so
    /// the command, running. Killing the init ends its pid namespace,
    /// everything in it included. Callers make sure no live run can be
    /// starting the sandbox (its lock, or a dead owner's throwaway
    /// directory). Until none is left, or five seconds.
    pub fn stop_leftovers(sandbox: &Path) {
        let want = sandbox.canonicalize().ok();
        let me = std::process::id();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let mut found = false;
            let Ok(procs) = std::fs::read_dir("/proc") else { return };
            for e in procs.flatten() {
                let Some(pid) = e.file_name().to_str().and_then(|n| n.parse::<i32>().ok()) else { continue };
                let cmdline = |pid: i32| std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
                if pid as u32 == me || !runs_sandbox(&cmdline(pid), sandbox, want.as_deref()) {
                    continue;
                }
                // Pinned first, then checked again: never a reused pid.
                if let Some(p) = Pinned::open(pid).filter(|_| runs_sandbox(&cmdline(pid), sandbox, want.as_deref())) {
                    found |= p.signal(libc::SIGKILL);
                }
            }
            if !found || Instant::now() >= deadline {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
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
    /// and `env` added; writes to the allow-list kept in the layers of
    /// `state` (a persistent sandbox's directory), or thrown away (`None`).
    /// `socket`: the workspace socket ([`crate::ws_socket`]), shown to the
    /// command at [`crate::ws_socket::INSIDE`].
    /// The exit status is the command's (128 + n for a
    /// signal); a limit that stopped it is reported.
    pub fn run(c: &Confine, sandbox: &Path, command: &[String], env: &[(&str, OsString)], state: Option<&Path>, socket: Option<&Path>) -> Result<i32> {
        let unit = format!("veil-exec-{}-{}", std::process::id(), hex::encode(veil_core::crypto::random_bytes::<4>()));
        // The throwaway file copies live until the command has exited.
        let (mut mounts, _copies) = c.layered(state)?;
        // `--private-ports`: `bwrap` says the sandbox's pid on one pipe and
        // waits on another until `pasta` has given it its network.
        let mut net = match &c.pasta {
            Some(_) => Some(super::net::Pending::new()?),
            None => None,
        };
        if let Some(n) = &net {
            mounts.extend(n.bwrap_args());
        }
        if let Some(sock) = socket {
            // The socket, and this `vl` (read-only) first on `PATH`, so the
            // command's `vl` is one that talks to the socket wherever `vl`
            // is installed.
            let inside = std::path::Path::new(crate::ws_socket::INSIDE);
            let dir = inside.parent().expect("an absolute path");
            let bin = dir.join("bin");
            let mut path = bin.as_os_str().to_owned();
            if let Some(p) = std::env::var_os("PATH").filter(|p| !p.is_empty()) {
                path.push(":");
                path.push(p);
            }
            mounts.extend([
                "--dir".into(),
                dir.as_os_str().to_owned(),
                "--bind".into(),
                sock.as_os_str().to_owned(),
                inside.as_os_str().to_owned(),
                "--setenv".into(),
                crate::ws_socket::ENV.into(),
                inside.as_os_str().to_owned(),
            ]);
            if let Ok(exe) = std::env::current_exe() {
                mounts.extend(["--ro-bind".into(), exe.into_os_string(), bin.join("vl").into_os_string(), "--setenv".into(), "PATH".into(), path]);
            }
        }
        let (program, args) = c.argv(mounts, sandbox, command, &unit);
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
        let keep: Vec<libc::c_int> = net.as_ref().map(|n| n.child_fds()).unwrap_or_default();
        // SAFETY: only prctl(2), getppid(2), signal(2), setrlimit(2) and
        // fcntl(2), which are async-signal-safe, between fork and exec.
        unsafe {
            cmd.pre_exec(move || {
                for fd in &keep {
                    if libc::fcntl(*fd, libc::F_SETFD, 0) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
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
        // The run's own network, before the command starts; any failure
        // stops the sandbox before its command ran (never a run on the
        // host's network).
        let _network = match net.take() {
            Some(n) => match n.start(c.pasta.as_deref().expect("pasta with a pending network"), &mut child) {
                Ok(d) => Some(d),
                Err(e) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(e.context("--private-ports: the run's own network could not be set up; nothing was run"));
                }
            },
            None => None,
        };
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

/// `--private-ports`: the run's own network namespace (`bwrap
/// --unshare-net`, with its private loopback), given outbound access by
/// `pasta` before the command starts.
///
/// `bwrap` makes two user namespaces: the network namespace belongs to the
/// outer one, which no process stays in. `pasta` must join that one, by a
/// `/proc/PID/ns/user` path: a holder (this binary, [`HOLD_ARG`]) joins it
/// (`NS_GET_USERNS` on the network namespace) and lives until `pasta` has
/// set the network up. `pasta` is told to forward nothing in either
/// direction (`-t none -u none -T none -U none`) and not to map its gateway
/// to the host (`--no-map-gw`), so the host's loopback is not reachable from
/// the run and the run's ports are not reachable from the host or from any
/// other run. Name lookups go to `pasta`'s DNS forwarder (a private
/// `resolv.conf` naming it), which asks the host's resolver.
#[cfg(target_os = "linux")]
mod net {
    use std::{
        ffi::OsString,
        io::{Read, Write},
        os::{
            fd::{AsRawFd, FromRawFd, OwnedFd},
            unix::process::CommandExt,
        },
        path::{Path, PathBuf},
        process::{Child, Command, Stdio},
        time::{Duration, Instant},
    };

    use anyhow::{anyhow, bail, Context, Result};

    /// The address the run's `resolv.conf` names: `pasta` forwards DNS
    /// sent to it to the host's resolver.
    const DNS: &str = "169.254.1.1";
    /// The longest setting the network up may take.
    const WAIT: Duration = Duration::from_secs(20);
    /// `ioctl(NS_GET_USERNS)`: the user namespace owning a namespace.
    const NS_GET_USERNS: libc::c_ulong = 0xb701;

    fn pipe() -> Result<(OwnedFd, OwnedFd)> {
        let mut fds = [0; 2];
        // SAFETY: pipe2 fills both descriptors, which we then own.
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: both were just created.
        Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
    }

    /// The pipes and files of a network about to be set up.
    pub struct Pending {
        info: (OwnedFd, OwnedFd),
        block: (OwnedFd, OwnedFd),
        /// Private: the run's `resolv.conf` and `pasta`'s pid file.
        dir: crate::sandbox::Sandbox,
        resolv: Option<(PathBuf, PathBuf)>,
    }

    impl Pending {
        pub fn new() -> Result<Pending> {
            let dir = crate::sandbox::Sandbox::create("net")?;
            // Where `/etc/resolv.conf` leads (often into `/run`, which the
            // sandbox binds read-only): over it, a file naming `pasta`'s
            // forwarder, with the host's search domains and options.
            let resolv = match std::fs::read_to_string("/etc/resolv.conf") {
                Ok(text) => {
                    let mut out = format!("nameserver {DNS}\n");
                    for l in text.lines().filter(|l| l.starts_with("search ") || l.starts_with("options ")) {
                        out.push_str(l);
                        out.push('\n');
                    }
                    let file = dir.path().join("resolv.conf");
                    std::fs::write(&file, out).with_context(|| format!("writing {}", file.display()))?;
                    let at = std::fs::canonicalize("/etc/resolv.conf").unwrap_or_else(|_| PathBuf::from("/etc/resolv.conf"));
                    Some((file, at))
                }
                Err(_) => None,
            };
            Ok(Pending { info: pipe()?, block: pipe()?, dir, resolv })
        }

        /// The descriptors `bwrap` inherits.
        pub fn child_fds(&self) -> Vec<libc::c_int> {
            vec![self.info.1.as_raw_fd(), self.block.0.as_raw_fd()]
        }

        pub fn bwrap_args(&self) -> Vec<OsString> {
            let mut a: Vec<OsString> = vec![
                "--info-fd".into(),
                self.info.1.as_raw_fd().to_string().into(),
                "--block-fd".into(),
                self.block.0.as_raw_fd().to_string().into(),
            ];
            if let Some((file, at)) = &self.resolv {
                a.extend(["--ro-bind".into(), file.as_os_str().to_owned(), at.as_os_str().to_owned()]);
            }
            a
        }

        /// `bwrap` was started: give its sandbox the network, then let its
        /// command start.
        pub fn start(self, pasta: &Path, bwrap: &mut Child) -> Result<Network> {
            let Pending { info: (info, info_w), block: (block_r, block), dir, .. } = self;
            drop((info_w, block_r));
            let pid = sandbox_pid(info, bwrap)?;
            let netns = std::fs::File::open(format!("/proc/{pid}/ns/net")).context("opening the sandbox's network namespace")?;
            // SAFETY: the ioctl returns a new descriptor (close-on-exec), or -1.
            let owner = unsafe { libc::ioctl(netns.as_raw_fd(), NS_GET_USERNS as _) };
            if owner < 0 {
                return Err(anyhow!(std::io::Error::last_os_error()).context("finding the user namespace of the sandbox's network"));
            }
            // SAFETY: just returned to us.
            let owner = unsafe { OwnedFd::from_raw_fd(owner) };
            let mut holder = hold(&owner)?;
            let pid_file = dir.path().join("pasta.pid");
            let got = run_pasta(pasta, holder.id(), pid, &pid_file, &dir.path().join("pasta.log"));
            drop(holder.stdin.take());
            let _ = holder.kill();
            let _ = holder.wait();
            got?;
            let daemon = std::fs::read_to_string(&pid_file).ok().and_then(|s| s.trim().parse::<i32>().ok());
            let network = Network { pasta: daemon.map(|p| (p, pasta.to_path_buf())), _dir: dir };
            std::fs::File::from(block).write_all(b"1").context("starting the command")?;
            Ok(network)
        }
    }

    /// The sandbox's pid, from `bwrap --info-fd`.
    fn sandbox_pid(info: OwnedFd, bwrap: &mut Child) -> Result<i32> {
        let mut f = std::fs::File::from(info);
        let mut text = String::new();
        let deadline = Instant::now() + super::SETUP_WAIT;
        let mut buf = [0u8; 512];
        loop {
            let mut fds = libc::pollfd { fd: f.as_raw_fd(), events: libc::POLLIN, revents: 0 };
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                bail!("the sandbox did not start within {} s", super::SETUP_WAIT.as_secs());
            }
            // SAFETY: polls our own descriptor.
            unsafe { libc::poll(&mut fds, 1, left.as_millis().min(500) as i32) };
            if fds.revents == 0 {
                if let Some(s) = bwrap.try_wait()? {
                    bail!("bubblewrap exited ({s}) before the sandbox started");
                }
                continue;
            }
            let n = f.read(&mut buf)?;
            text.push_str(&String::from_utf8_lossy(&buf[..n]));
            if let Some(pid) = child_pid(&text) {
                return Ok(pid);
            }
            if n == 0 {
                bail!("bubblewrap exited before the sandbox started");
            }
        }
    }

    /// `"child-pid": N` in `bwrap`'s info document.
    fn child_pid(text: &str) -> Option<i32> {
        let v: serde_json::Value = serde_json::from_str(text.trim()).ok()?;
        let pid = v.get("child-pid")?.as_i64()?;
        (pid > 1).then_some(pid as i32)
    }

    /// The holder: this binary, in the user namespace `owner`, until its
    /// stdin closes.
    fn hold(owner: &OwnedFd) -> Result<Child> {
        let fd = owner.as_raw_fd();
        let mut cmd = Command::new(std::env::current_exe()?);
        cmd.arg(super::HOLD_ARG).stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null());
        // SAFETY: setns(2) and prctl(2) are async-signal-safe; the forked
        // child is single-threaded, as setns into a user namespace needs.
        unsafe {
            cmd.pre_exec(move || {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
                if libc::setns(fd, libc::CLONE_NEWUSER) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        cmd.spawn().context("joining the sandbox's user namespace")
    }

    /// `pasta`, joined to the sandbox's network: it configures the network
    /// and goes to the background (its pid in `pid_file`, what it says in
    /// `log`).
    fn run_pasta(pasta: &Path, holder: u32, sandbox: i32, pid_file: &Path, log: &Path) -> Result<()> {
        let err = std::fs::File::create(log).with_context(|| format!("creating {}", log.display()))?;
        let mut cmd = Command::new(pasta);
        cmd.args(["--quiet", "--config-net", "-t", "none", "-u", "none", "-T", "none", "-U", "none", "--no-map-gw", "--dns-forward", DNS])
            .arg("--userns")
            .arg(format!("/proc/{holder}/ns/user"))
            .arg("--netns")
            .arg(format!("/proc/{sandbox}/ns/net"))
            .arg("--pid")
            .arg(pid_file)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(err);
        let mut child = cmd.spawn().with_context(|| format!("running {}", pasta.display()))?;
        let deadline = Instant::now() + WAIT;
        let status = loop {
            if let Some(s) = child.try_wait()? {
                break s;
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                bail!("pasta did not set the network up within {} s", WAIT.as_secs());
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        if !status.success() {
            let err = std::fs::read_to_string(log).unwrap_or_default();
            let last = err.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("it failed without a message");
            bail!("pasta failed ({status}): {}", crate::render::safe(last.trim()));
        }
        Ok(())
    }

    /// A run's network: `pasta`, stopped with the run.
    pub struct Network {
        pasta: Option<(i32, PathBuf)>,
        _dir: crate::sandbox::Sandbox,
    }

    impl Drop for Network {
        fn drop(&mut self) {
            // `pasta` also quits by itself once the sandbox is gone; this
            // stops it at once, and only if that pid is still our `pasta`.
            if let Some((pid, pasta)) = &self.pasta {
                // (`pasta` may run itself again as `pasta.avx2`.)
                let exe = std::fs::read_link(format!("/proc/{pid}/exe")).ok();
                let ours = exe.is_some_and(|e| {
                    pasta.canonicalize().is_ok_and(|p| {
                        let name = |x: &Path| x.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                        e.parent() == p.parent() && (name(&e) == name(&p) || name(&e).starts_with(&format!("{}.", name(&p))))
                    })
                });
                if ours {
                    // SAFETY: kill(2) of the pasta this run started.
                    unsafe {
                        libc::kill(*pid, libc::SIGTERM);
                    }
                }
            }
        }
    }

    /// The holder's whole life: wait for stdin to close.
    pub fn hold_main() -> std::process::ExitCode {
        let mut sink = [0u8; 64];
        while std::io::stdin().read(&mut sink).is_ok_and(|n| n > 0) {}
        std::process::ExitCode::SUCCESS
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
