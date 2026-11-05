//! Per-path attributes (`.veilattributes`) and line endings: `vl attr
//! check`, `vl renormalize`, and this device's diff and merge drivers.
//!
//! Feature 7 of the Git-parity round
//! (`docs/design/git-parity/7-attributes-line-endings.md`); the engine side
//! is `veil_core::attributes`.
//!
//! **Drivers are device-local.** `.veilattributes` only *names* a driver
//! (`diff=<name>`, `merge=<name>`). The definitions live in this device's
//! own configuration, never in a repository:
//!
//! ```toml
//! # $VEIL_HOME/config.toml, or .veil/local/config.toml (wins by name)
//! [merge.lockfile]
//! command = ["/usr/local/bin/merge-lock", "%O", "%A", "%B", "%P"]
//! [diff.sqlite]
//! textconv = ["sqlite3", "-batch", "/dev/stdin", ".dump"]
//! ```
//!
//! Following the hooks trust model (`hooks.rs`), a definition's program is
//! looked up on `PATH` without the entries inside the project, and never
//! resolves to a file inside it (a teammate can change those). It runs with
//! a scrubbed environment and a time limit, in `vl`'s process group (a
//! Ctrl-C stops both).
//!
//! * A merge driver gets three private files (mode 0600, in a fresh 0700
//!   directory under `.veil/local/tmp/`, removed afterwards): `%O` the base
//!   (empty when the base's audience is not the result's), `%A` ours (it
//!   writes the result there), `%B` theirs; `%P` is the path, `%L` the
//!   marker size. Exit 0 is a clean merge; anything else a conflict.
//! * A textconv gets the content on its standard input and prints the text
//!   to diff; nothing is written to disk and nothing is cached.
//!
//! A name this device does not define falls back to the built-in diff or
//! merge, with one warning per name.

use std::{
    collections::{BTreeMap, HashSet},
    ffi::OsString,
    io::{Read, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, ExitCode, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{bail, Result};
use clap::{Args, Subcommand};
use serde::Serialize;
use veil_core::{
    attributes::{self, Attrs, DeviceDrivers, DiffAttr, DriverInput, DriverMerge, MergeAttr, State},
    builder::LineEndings,
    VPath,
};

use crate::{
    cli::JsonOut,
    ctx::Ctx,
    render::{dim, safe, warn, warn_untrusted},
};

/// `vl attr check PATH…`.
#[derive(Args, Debug)]
pub struct AttrArgs {
    #[command(subcommand)]
    pub cmd: AttrCmd,
}

/// The `vl attr` subcommands.
#[derive(Subcommand, Debug)]
pub enum AttrCmd {
    /// Show the attributes that apply to each path (like `git check-attr
    /// -a`), what Veil does with them (line endings, diff, merge), and
    /// those Veil does not support.
    ///
    /// Read from the working copy's `.veilattributes` files and the
    /// device-local `.veil/local/attributes`.
    Check {
        /// Paths to check (they need not exist).
        #[arg(required = true)]
        paths: Vec<String>,
        #[command(flatten)]
        out: JsonOut,
    },
}

/// `vl renormalize [PATH…]`.
#[derive(Args, Debug)]
pub struct RenormalizeArgs {
    /// Files or directories to re-record (default: all).
    pub paths: Vec<String>,
}

// ---- vl attr check --------------------------------------------------------------------------

/// `vl attr check --json` (`veil.attr-check/1`).
#[derive(Serialize, Debug)]
pub struct AttrCheck {
    pub schema: &'static str,
    pub paths: Vec<PathAttrInfo>,
    /// Problems with the attributes files (unreadable, too large, ignored
    /// lines).
    pub warnings: Vec<String>,
}

#[derive(Serialize, Debug)]
pub struct PathAttrInfo {
    pub path: String,
    /// Every attribute assigned to the path (`!name` included, as
    /// `unspecified`).
    pub attributes: Vec<AttrInfo>,
    /// What Veil does with the path.
    pub line_endings: &'static str,
    /// `text`, `binary`, or the driver's name.
    pub diff: String,
    /// `text`, `binary`, `union`, or the driver's name.
    pub merge: String,
    /// Assigned attributes Veil does not act on, with why.
    pub unsupported: Vec<Unsupported>,
}

#[derive(Serialize, Debug)]
pub struct AttrInfo {
    pub name: String,
    /// `set`, `unset`, `value` or `unspecified`.
    pub state: &'static str,
    pub value: Option<String>,
}

#[derive(Serialize, Debug)]
pub struct Unsupported {
    pub name: String,
    pub note: &'static str,
}

fn conversion_word(c: attributes::Conversion) -> &'static str {
    use attributes::Conversion as C;
    match c {
        C::None => "none",
        C::Text { crlf: false } => "text-lf",
        C::Text { crlf: true } => "text-crlf",
        C::Auto { crlf: false } => "auto-lf",
        C::Auto { crlf: true } => "auto-crlf",
    }
}

/// The attribute check of `paths` (repository paths) in `ctx`'s working
/// copy.
pub fn check(ctx: &Ctx, paths: &[VPath]) -> AttrCheck {
    let attrs = Attrs::for_backend(ctx.repo.store(), &*ctx.fs);
    let drivers = ctx.repo.store().device_drivers();
    let mut out = Vec::new();
    for p in paths {
        let assigned = attrs.assigned(p);
        let pa = attributes::PathAttrs::from_assigned(&assigned);
        let mut unsupported = Vec::new();
        let mut list = Vec::new();
        for (name, st) in &assigned {
            let (state, value) = match st {
                State::Set => ("set", None),
                State::Unset => ("unset", None),
                State::Value(v) => ("value", Some(v.clone())),
                State::Unspecified => ("unspecified", None),
            };
            if *st != State::Unspecified {
                if let Some(note) = attributes::unsupported_note(name) {
                    unsupported.push(Unsupported { name: name.to_string(), note });
                }
            }
            list.push(AttrInfo { name: name.to_string(), state, value });
        }
        let defined = |kind: &str, n: &str| match &drivers {
            Some(d) if kind == "merge" => d.has_merge(n),
            Some(d) => d.has_textconv(n),
            None => false,
        };
        let diff = match &pa.diff {
            DiffAttr::Auto => "text".to_string(),
            DiffAttr::Binary => "binary".to_string(),
            DiffAttr::Driver(n) if defined("diff", n) => format!("driver {n}"),
            DiffAttr::Driver(n) => format!("text (driver {n} is not defined on this device)"),
        };
        let merge = match &pa.merge {
            MergeAttr::Text => "text".to_string(),
            MergeAttr::Binary => "binary".to_string(),
            MergeAttr::Union => "union".to_string(),
            MergeAttr::Driver(n) if defined("merge", n) => format!("driver {n}"),
            MergeAttr::Driver(n) => format!("text (driver {n} is not defined on this device)"),
        };
        out.push(PathAttrInfo {
            path: p.to_string(),
            attributes: list,
            line_endings: conversion_word(pa.conversion),
            diff,
            merge,
            unsupported,
        });
    }
    let mut warnings = attrs.warnings();
    warnings.extend(LocalDrivers::load(&ctx.root).problems().iter().cloned());
    AttrCheck {
        schema: "veil.attr-check/1",
        paths: out,
        warnings,
    }
}

/// `vl attr`.
pub fn attr(ctx: &mut Ctx, args: &AttrArgs) -> Result<ExitCode> {
    match &args.cmd {
        AttrCmd::Check { paths, out } => {
            let ps: Vec<VPath> = paths.iter().map(|p| ctx.repo_path(p)).collect::<Result<_>>()?;
            if let Some(p) = ps.iter().find(|p| p.is_root()) {
                bail!("'{}' is the repository root; name files", safe(p.as_str()));
            }
            let doc = check(ctx, &ps);
            if out.json {
                crate::api::emit_json(&doc)?;
                return Ok(ExitCode::SUCCESS);
            }
            for w in &doc.warnings {
                warn_untrusted(w);
            }
            for f in &doc.paths {
                let p = safe(&f.path);
                if f.attributes.is_empty() {
                    println!("{p}: {}", dim("no attributes"));
                }
                for a in &f.attributes {
                    let v = a.value.as_deref().unwrap_or(a.state);
                    match f.unsupported.iter().find(|u| u.name == a.name) {
                        Some(u) => println!("{p}: {}: {}  {}", safe(&a.name), safe(v), dim(&format!("({})", u.note))),
                        None => println!("{p}: {}: {}", safe(&a.name), safe(v)),
                    }
                }
                println!(
                    "  {} line endings: {} · diff: {} · merge: {}",
                    dim("veil"),
                    f.line_endings,
                    safe(&f.diff),
                    safe(&f.merge)
                );
                if f.unsupported.iter().any(|u| u.name == "filter") {
                    warn(&format!(
                        "{p}: `filter` is not supported by Veil: the file is recorded as it is on disk, unfiltered"
                    ));
                }
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

// ---- vl renormalize -------------------------------------------------------------------------

/// `vl renormalize`: re-record the selected files with the line endings
/// `.veilattributes` asks for now (an operation of its own, which `vl undo`
/// reverts). The working copy is not rewritten.
pub fn renormalize(ctx: &mut Ctx, args: &RenormalizeArgs) -> Result<ExitCode> {
    let ps: Vec<VPath> = args.paths.iter().map(|p| ctx.repo_path(p)).collect::<Result<_>>()?;
    let select = |p: &VPath| ps.is_empty() || ps.iter().any(|q| p.starts_with(q));
    let before = ctx.repo.snapshot(&ctx.wc()?)?.tree;
    let what = if ps.is_empty() {
        "renormalize".to_string()
    } else {
        format!("renormalize {}", ps.iter().map(|p| p.as_str()).collect::<Vec<_>>().join(" "))
    };
    let report = ctx.snapshot_with_line_endings(what, LineEndings::Renormalize(&select))?;
    let after = ctx.repo.snapshot(&ctx.wc()?)?.tree;
    let changed = veil_core::tree::diff_trees(ctx.repo.store(), Some(&before), Some(&after))?;
    for (p, why) in &report.line_endings {
        warn_untrusted(&format!("{p}: {why}"));
    }
    if changed.is_empty() {
        println!("Nothing to renormalize: every file is recorded as `.veilattributes` says.");
    } else {
        for c in &changed {
            println!("Renormalized {}", safe(c.path.as_str()));
        }
        println!("{} (`vl undo` reverts it)", dim(&format!("{} file(s) re-recorded", changed.len())));
    }
    Ok(ExitCode::SUCCESS)
}

// ---- device-local drivers -------------------------------------------------------------------

/// The configuration file holding driver definitions.
pub const CONFIG_FILE: &str = "config.toml";
/// How long a driver may run.
const DRIVER_TIMEOUT: Duration = Duration::from_secs(60);
/// Most bytes a driver's output may have.
const MAX_OUTPUT: u64 = 256 << 20;
/// Most arguments and bytes per argument of a definition.
const MAX_ARGS: usize = 64;
const MAX_ARG: usize = 4096;

/// This device's drivers, from `$VEIL_HOME/config.toml` and the
/// repository's `.veil/local/config.toml` (which wins by name).
pub struct LocalDrivers {
    root: PathBuf,
    merge: BTreeMap<String, Vec<String>>,
    textconv: BTreeMap<String, Vec<String>>,
    warned: Mutex<HashSet<(String, String)>>,
    problems: Vec<String>,
}

impl LocalDrivers {
    /// Load the definitions for the repository at `root`.
    pub fn load(root: &Path) -> LocalDrivers {
        let mut d = LocalDrivers {
            root: root.to_path_buf(),
            merge: BTreeMap::new(),
            textconv: BTreeMap::new(),
            warned: Mutex::new(HashSet::new()),
            problems: Vec::new(),
        };
        for file in [crate::ctx::veil_home().join(CONFIG_FILE), veil_core::repo::state_dir(root).join("local").join(CONFIG_FILE)] {
            d.read(&file);
        }
        d
    }

    /// Problems found in the configuration (shown by `vl attr check`).
    pub fn problems(&self) -> &[String] {
        &self.problems
    }

    fn read(&mut self, file: &Path) {
        let Ok(meta) = std::fs::symlink_metadata(file) else { return };
        if !meta.is_file() || meta.len() > 1 << 20 {
            self.problems.push(format!("{} is not a regular file under 1 MiB; ignored", file.display()));
            return;
        }
        let Ok(text) = std::fs::read_to_string(file) else { return };
        let doc = match text.parse::<toml_edit::DocumentMut>() {
            Ok(d) => d,
            Err(e) => {
                self.problems.push(format!("{}: {e}", file.display()));
                return;
            }
        };
        for (kind, key) in [("merge", "command"), ("diff", "textconv")] {
            let Some(table) = doc.get(kind).and_then(|t| t.as_table_like()) else { continue };
            for (name, def) in table.iter() {
                let argv = def.get(key).and_then(|v| v.as_array()).map(|a| a.iter().map(|x| x.as_str().map(str::to_string)).collect::<Option<Vec<String>>>());
                match argv {
                    Some(Some(argv)) if !argv.is_empty() && argv.len() <= MAX_ARGS && argv.iter().all(|a| a.len() <= MAX_ARG && !a.contains('\0')) => {
                        let map = if kind == "merge" { &mut self.merge } else { &mut self.textconv };
                        map.insert(name.to_string(), argv);
                    }
                    _ => self.problems.push(format!("{}: [{kind}.{name}] needs `{key} = [\"program\", \"arg\", …]`; ignored", file.display())),
                }
            }
        }
    }

    /// Run `argv` (placeholders already substituted), feeding `stdin`;
    /// `(exit success, stdout)`, or `None` if it could not run or timed
    /// out.
    fn run(&self, argv: &[String], stdin: Option<&[u8]>, capture: bool) -> Option<(bool, Vec<u8>)> {
        let path = clean_path(&self.root);
        let program = resolve_program(&self.root, &argv[0], &path)?;
        let mut cmd = Command::new(program);
        cmd.args(&argv[1..]).current_dir(&self.root).env_clear();
        for k in crate::hooks::ALLOWED_ENV {
            if let Some(v) = std::env::var_os(k) {
                cmd.env(k, v);
            }
        }
        cmd.env("PATH", path);
        cmd.stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() });
        cmd.stdout(if capture { Stdio::piped() } else { Stdio::null() });
        cmd.stderr(Stdio::inherit());
        // In `vl`'s own process group: Ctrl-C stops the driver with `vl`.
        let mut child = cmd.spawn().ok()?;
        let writer = stdin.map(|d| d.to_vec()).and_then(|data| {
            child.stdin.take().map(|mut s| {
                std::thread::spawn(move || {
                    let _ = s.write_all(&data);
                })
            })
        });
        let reader = child.stdout.take().map(|s| {
            std::thread::spawn(move || {
                let mut out = Vec::new();
                let _ = s.take(MAX_OUTPUT + 1).read_to_end(&mut out);
                out
            })
        });
        let deadline = Instant::now() + DRIVER_TIMEOUT;
        let status = loop {
            match child.try_wait() {
                Ok(Some(st)) => break Some(st),
                Ok(None) if Instant::now() >= deadline => break None,
                Ok(None) => std::thread::sleep(Duration::from_millis(5)),
                Err(_) => break None,
            }
        };
        if status.is_none() {
            let _ = child.kill();
        }
        let _ = child.wait();
        if let Some(w) = writer {
            let _ = w.join();
        }
        let out = reader.and_then(|r| r.join().ok()).unwrap_or_default();
        let status = status?;
        if out.len() as u64 > MAX_OUTPUT {
            return None;
        }
        Some((status.success(), out))
    }
}

/// `PATH` without relative entries or entries inside the project.
fn clean_path(root: &Path) -> OsString {
    let path = std::env::var_os("PATH").unwrap_or_else(|| "/usr/local/bin:/usr/bin:/bin".into());
    let kept: Vec<PathBuf> = std::env::split_paths(&path).filter(|p| p.is_absolute() && !inside(root, p)).collect();
    std::env::join_paths(kept).unwrap_or_default()
}

fn inside(root: &Path, p: &Path) -> bool {
    let canon_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let canon = p.canonicalize().unwrap_or_else(|_| p.to_path_buf());
    canon.starts_with(&canon_root) || p.starts_with(root)
}

/// The program a definition names: an absolute path or a name on `PATH`,
/// never a file inside the project.
fn resolve_program(root: &Path, name: &str, path: &OsString) -> Option<PathBuf> {
    let found = if name.starts_with('/') {
        Some(PathBuf::from(name)).filter(|p| p.is_file())
    } else if name.contains('/') {
        None
    } else {
        std::env::split_paths(path).map(|d| d.join(name)).find(|p| p.is_file())
    };
    let p = found?;
    if inside(root, &p) {
        warn_untrusted(&format!("driver program {} is inside the project; it is never run", p.display()));
        return None;
    }
    Some(p)
}

/// A private directory (0700) for one merge driver run, removed on drop.
struct RunDir(PathBuf);

impl Drop for RunDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn private_file(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    f.write_all(data)
}

impl DeviceDrivers for LocalDrivers {
    fn has_merge(&self, name: &str) -> bool {
        self.merge.contains_key(name)
    }

    fn merge(&self, name: &str, input: &DriverInput<'_>) -> DriverMerge {
        let Some(argv) = self.merge.get(name) else { return DriverMerge::Conflict };
        let tmp = veil_core::repo::state_dir(&self.root).join("local").join("tmp");
        if std::fs::create_dir_all(&tmp).is_err() {
            return DriverMerge::Conflict;
        }
        let mut rnd = [0u8; 8];
        if getrandom(&mut rnd).is_err() {
            return DriverMerge::Conflict;
        }
        let dir = RunDir(tmp.join(format!("merge-{}", hex::encode(rnd))));
        if std::fs::create_dir(&dir.0).is_err() || std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o700)).is_err() {
            return DriverMerge::Conflict;
        }
        let (o, a, b) = (dir.0.join("base"), dir.0.join("ours"), dir.0.join("theirs"));
        if private_file(&o, input.base).is_err() || private_file(&a, input.ours).is_err() || private_file(&b, input.theirs).is_err() {
            return DriverMerge::Conflict;
        }
        let sub = |s: &str| {
            s.replace("%O", &o.to_string_lossy())
                .replace("%A", &a.to_string_lossy())
                .replace("%B", &b.to_string_lossy())
                .replace("%P", input.path.as_str())
                .replace("%L", "7")
        };
        let argv: Vec<String> = argv.iter().map(|s| sub(s)).collect();
        match self.run(&argv, None, false) {
            Some((true, _)) => match std::fs::read(&a) {
                Ok(m) => DriverMerge::Clean(m),
                Err(_) => DriverMerge::Conflict,
            },
            _ => DriverMerge::Conflict,
        }
    }

    fn has_textconv(&self, name: &str) -> bool {
        self.textconv.contains_key(name)
    }

    fn textconv(&self, name: &str, path: &VPath, data: &[u8]) -> Option<Vec<u8>> {
        let argv: Vec<String> = self.textconv.get(name)?.iter().map(|s| s.replace("%P", path.as_str())).collect();
        match self.run(&argv, Some(data), true) {
            Some((true, out)) => Some(out),
            _ => {
                self.undefined("textconv-failed", name, path);
                None
            }
        }
    }

    fn undefined(&self, kind: &str, name: &str, path: &VPath) {
        let mut w = self.warned.lock().unwrap_or_else(|e| e.into_inner());
        if !w.insert((kind.to_string(), name.to_string())) {
            return;
        }
        let (name, path) = (safe(name), safe(path.as_str()));
        match kind {
            "textconv-failed" => warn_untrusted(&format!("the textconv of diff driver '{name}' failed on {path}; showing the plain diff")),
            _ => warn_untrusted(&format!(
                "{path}: .veilattributes names {kind} driver '{name}', which this device does not define; the built-in {kind} is used \
                 (drivers are defined only in $VEIL_HOME/config.toml or .veil/local/config.toml)"
            )),
        }
    }
}

fn getrandom(buf: &mut [u8]) -> std::io::Result<()> {
    std::fs::File::open("/dev/urandom")?.read_exact(buf)
}

/// Register this device's drivers on `ctx`'s repository.
pub fn register(repo: &veil_core::Repo, root: &Path) {
    repo.store().set_device_drivers(Arc::new(LocalDrivers::load(root)));
}
