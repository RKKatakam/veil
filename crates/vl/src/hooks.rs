//! Hooks: commands `vl` runs at fixed points of `commit`, `describe`,
//! `push` and `git push` (and after the working copy moves), the
//! repository's `.veilhooks` file and its per-device trust record, and
//! `vl hooks show|trust`.
//!
//! Feature 5a of the Git-parity round
//! (`docs/design/git-parity/5-hooks-submodules-signed-tags.md`). The rules:
//!
//! * **Device-local hooks** (`$VEIL_HOME/hooks/<name>`, then
//!   `.veil/hooks/<name>`) run without asking, as `.git/hooks` do: the user
//!   put them there, and nothing from a tree, a pull, a patch or a Git
//!   import can (`.veil` is never a tree entry, BUG-002).
//! * **Repository-suggested hooks** (`.veilhooks`, a tracked TOML file)
//!   run only once this device trusts them: `vl hooks trust` pins the
//!   BLAKE3 digest of `.veilhooks` and of every repository file its
//!   commands name, in any spelling (BUG-701), in
//!   `.veil/local/hooks-trust.json` (a directory the program may run, with
//!   every file below it: BUG-700). Any change makes them untrusted again:
//!   they do not run, and every command that would have run them warns.
//!   The record is never synced, and only `vl hooks trust` writes it (not a
//!   hook, not `vl serve`). What trust cannot pin is refused (`refusal`):
//!   code given as text (`sh -c`), arguments taken from input (`xargs`),
//!   paths through `..`, `/proc` or into `.veil`. Build tools are found
//!   behind launchers too (BUG-702).
//! * **Copy, then exec.** A repository file a trusted command runs or reads
//!   as an argument is read once, hashed, compared with the trusted digest,
//!   and written to `.veil/local/hooks-run/` (`0700`); the command is given
//!   that copy. Swapping the script after the check changes nothing.
//! * **No shell, a scrubbed environment.** Commands are argv arrays. The
//!   environment is an allowlist ([`ALLOWED_ENV`]): no vault secrets, no
//!   inherited `VEIL_*` or `GIT_*` variables. `PATH` loses its relative
//!   entries and those inside the project, so no repository file ever
//!   becomes a command by name.
//! * **Bounded.** `VEIL_HOOK_TIMEOUT` seconds (default 600); a hook that
//!   outlives it is killed with its process group, and the command fails.
//!   Whatever a hook leaves running in its process group is stopped when
//!   it exits. Ctrl-C, SIGTERM and SIGHUP reach the hook.
//! * **A hook cannot change what is recorded.** No repository lock is held
//!   while a hook runs. Afterwards the working copy is recorded again; if
//!   that, or anything the hook ran (`vl describe`), moved the operation
//!   log, the commit is refused and nothing is lost (the edits are in `@`).
//!   `push` likewise refuses if the hook moved a tag.
//! * **Output.** A hook's stdout and stderr both go to `vl`'s stderr, never
//!   to its stdout (where `--json` documents and `vl serve` replies go).
//! * **Input.** `pre-push` gets, on stdin, one line per tag the push sends:
//!   never a cloaked tag on a public remote, never a snapshot held back by
//!   an embargo. No hook input carries file content.

use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    ffi::OsString,
    io::{IsTerminal, Read, Write},
    os::{
        fd::AsFd,
        unix::{
            ffi::OsStrExt,
            fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::{Command, ExitCode, Stdio},
    sync::{
        atomic::{AtomicI32, AtomicU64, Ordering},
        Mutex,
    },
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use veil_core::{repo::VEIL_DIR, tree::lookup, ObjectId, Repo, VPath};

use crate::{
    cli::{Cmd, WsCmd},
    ctx::Ctx,
    render::{bold, dim, green, red, safe, warn, yellow},
};

/// `vl hooks show|trust`.
#[derive(Subcommand, Debug)]
pub enum HooksCmd {
    /// Show the hooks that would run: device-local ones, and the
    /// repository's `.veilhooks` with its digests and whether this device
    /// trusts them.
    Show,
    /// Trust the repository's `.veilhooks` and every script it names, as
    /// they are now (pinned by digest, recorded on this device only).
    Trust {
        /// Do not ask for confirmation (required when stdin is not a
        /// terminal).
        #[arg(long, short = 'y')]
        yes: bool,
        /// Also trust commands that run a build tool (make, npm, cargo, …),
        /// which read files the trust record cannot pin.
        #[arg(long)]
        i_understand_indirect: bool,
    },
}

/// `--no-verify`, on the commands that run hooks.
#[derive(Args, Debug, Clone, Copy, Default)]
pub struct NoVerifyArgs {
    /// Do not run hooks for this command (device-local or `.veilhooks`).
    #[arg(long)]
    pub no_verify: bool,
}

// ---- hook points ---------------------------------------------------------------------------

/// The points at which `vl` runs hooks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Hook {
    /// Before `vl commit`, `vl describe` of `@`, and `commit` over `vl
    /// serve`. A non-zero exit aborts.
    PreCommit,
    /// After `pre-commit`, with the message in a file (`$1`); an edited
    /// message is used. A non-zero exit aborts.
    CommitMsg,
    /// Before `vl push` and `vl git push`. A non-zero exit aborts.
    PrePush,
    /// After `vl new`, `vl edit` and `vl ws switch` moved the working copy
    /// (old and new snapshot ids). Its exit status is only reported.
    PostCheckout,
}

impl Hook {
    pub const ALL: [Hook; 4] = [Hook::PreCommit, Hook::CommitMsg, Hook::PrePush, Hook::PostCheckout];

    pub fn name(self) -> &'static str {
        match self {
            Hook::PreCommit => "pre-commit",
            Hook::CommitMsg => "commit-msg",
            Hook::PrePush => "pre-push",
            Hook::PostCheckout => "post-checkout",
        }
    }

    fn from_name(s: &str) -> Option<Hook> {
        Hook::ALL.into_iter().find(|h| h.name() == s)
    }
}

// ---- limits --------------------------------------------------------------------------------

/// The repository's suggested hooks.
pub const VEILHOOKS: &str = ".veilhooks";
const TRUST_FILE: &str = "hooks-trust.json";
const RUN_DIR: &str = "hooks-run";
const MAX_VEILHOOKS: u64 = 64 << 10;
const MAX_TRUST_FILE: u64 = 1 << 20;
/// A pinned repository file (a script, a Makefile), or all the files of a
/// pinned directory together.
const MAX_PINNED: u64 = 64 << 20;
/// Entries (files and directories) below a pinned directory.
const MAX_TREE_ENTRIES: usize = 1024;
const MAX_TREE_DEPTH: usize = 32;
const MAX_COMMANDS: usize = 16;
const MAX_ARGS: usize = 64;
const MAX_ARG: usize = 4096;
const MAX_FILES: usize = 64;
const MAX_MESSAGE: u64 = 1 << 20;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(600);
const MAX_TIMEOUT_SECS: u64 = 7 * 24 * 3600;
/// The environment a hook gets from `vl`'s (plus `LC_*`, `PATH` cleaned,
/// and the `VEIL_HOOK`, `VEIL_SNAPSHOT`, `VEIL_WORKSPACE` it sets).
/// `VEIL_HOME` is a location, not a secret: a `vl` the hook runs uses the
/// same identity.
pub const ALLOWED_ENV: &[&str] = &["HOME", "USER", "LOGNAME", "LANG", "TERM", "TMPDIR", "TZ", "VEIL_HOME"];

// ---- .veilhooks ----------------------------------------------------------------------------

/// One command of `.veilhooks`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Suggested {
    pub hook: Hook,
    /// The argv, as written.
    pub run: Vec<String>,
    /// Further repository files the command reads, pinned with it.
    pub files: Vec<String>,
}

/// `.veilhooks` as it is on disk.
pub struct Veilhooks {
    pub bytes: Vec<u8>,
    pub digest: String,
    pub commands: Vec<Suggested>,
}

fn digest(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

/// A repository path as `.veilhooks` may name one: relative, canonical
/// (no empty, `.` or `..` component), never in `.veil` or `.git`.
fn repo_path(s: &str) -> Option<VPath> {
    if s.is_empty() || s.starts_with('/') || s.contains(['\0', '\\']) {
        return None;
    }
    let parts: Vec<&str> = s.split('/').collect();
    if parts.iter().any(|c| c.is_empty() || *c == "." || *c == "..") {
        return None;
    }
    let first = parts[0].to_ascii_lowercase();
    if first == VEIL_DIR || first == ".git" {
        return None;
    }
    VPath::new(s).ok()
}

/// Parse `.veilhooks`. Strict: unknown hooks or keys, wrong types and
/// oversized lists are errors (nothing runs from a file that does not say
/// exactly what it means).
pub fn parse(text: &str) -> Result<Vec<Suggested>> {
    use toml_edit::{Item, Table, Value};
    let doc = toml_edit::Document::parse(text).map_err(|e| anyhow!("{VEILHOOKS} is not valid TOML: {}", e.message()))?;
    let strings = |v: &Value, what: &str| -> Result<Vec<String>> {
        let a = v.as_array().ok_or_else(|| anyhow!("{what} must be an array of strings"))?;
        a.iter()
            .map(|s| s.as_str().map(String::from).ok_or_else(|| anyhow!("{what} must be an array of strings")))
            .collect()
    };
    let command = |hook: Hook, t: &dyn Fn(&str) -> Option<Value>, keys: Vec<String>| -> Result<Suggested> {
        let what = format!("[{}]", hook.name());
        for k in &keys {
            if k != "run" && k != "files" {
                bail!("{what}: unknown key `{}` (a command has `run` and, optionally, `files`)", safe(k));
            }
        }
        let run = strings(&t("run").ok_or_else(|| anyhow!("{what}: `run` is missing"))?, &format!("{what} run"))?;
        let files = match t("files") {
            Some(v) => strings(&v, &format!("{what} files"))?,
            None => Vec::new(),
        };
        if run.is_empty() {
            bail!("{what}: `run` is empty");
        }
        if run.len() > MAX_ARGS || files.len() > MAX_FILES {
            bail!("{what}: at most {MAX_ARGS} arguments and {MAX_FILES} files");
        }
        for a in run.iter().chain(&files) {
            if a.len() > MAX_ARG || a.contains('\0') {
                bail!("{what}: an argument is longer than {MAX_ARG} bytes or holds a NUL");
            }
        }
        if run[0].is_empty() {
            bail!("{what}: the program name is empty");
        }
        if run[0].contains('/') && !run[0].starts_with('/') && repo_path(&run[0]).is_none() {
            bail!("{what}: a script must be named by its path in the repository, not `{}`", safe(&run[0]));
        }
        for f in &files {
            if repo_path(f).is_none() {
                bail!("{what}: `files` must name repository files by relative path, not `{}`", safe(f));
            }
        }
        Ok(Suggested { hook, run, files })
    };
    let from_table = |hook: Hook, t: &Table| -> Result<Suggested> {
        let get = |k: &str| t.get(k).and_then(Item::as_value).cloned();
        command(hook, &get, t.iter().map(|(k, _)| k.to_string()).collect())
    };
    let mut out = Vec::new();
    for (key, item) in doc.as_table().iter() {
        let hook = Hook::from_name(key).ok_or_else(|| {
            anyhow!(
                "unknown hook `{}` in {VEILHOOKS} (known: {})",
                safe(key),
                Hook::ALL.map(Hook::name).join(", ")
            )
        })?;
        match item {
            Item::Table(t) => out.push(from_table(hook, t)?),
            Item::ArrayOfTables(a) => {
                for t in a.iter() {
                    out.push(from_table(hook, t)?);
                }
            }
            Item::Value(Value::InlineTable(t)) => {
                let get = |k: &str| t.get(k).cloned();
                out.push(command(hook, &get, t.iter().map(|(k, _)| k.to_string()).collect())?);
            }
            _ => bail!("`{}` in {VEILHOOKS} must be a table: [{}] run = [\"…\"]", hook.name(), hook.name()),
        }
        if out.iter().filter(|c| c.hook == hook).count() > MAX_COMMANDS {
            bail!("at most {MAX_COMMANDS} commands per hook in {VEILHOOKS}");
        }
    }
    Ok(out)
}

/// The state of one repository path, as the trust record pins it.
#[derive(Clone, Debug, PartialEq, Eq)]
enum PathState {
    /// A regular file with this BLAKE3 digest (hex).
    File(String),
    /// Nothing there.
    Absent,
    /// A directory given to a command as data: only that it is one is
    /// pinned (see [`Pin::Plain`]).
    Dir,
    /// A directory pinned with everything below it ([`Pin::Tree`]): the
    /// BLAKE3 digest (hex) of [`tree_digest`]'s manifest.
    Tree(String),
    /// A symbolic link, a socket, unreadable, too large…
    Other,
}

impl PathState {
    fn word(&self) -> String {
        match self {
            PathState::File(d) => d.clone(),
            PathState::Absent => "absent".into(),
            PathState::Dir => "directory".into(),
            PathState::Tree(d) => format!("tree:{d}"),
            PathState::Other => "other".into(),
        }
    }

    fn from_word(s: &str) -> PathState {
        let hex = |d: &str| d.len() == 64 && d.bytes().all(|b| b.is_ascii_hexdigit());
        match s {
            "absent" => PathState::Absent,
            "directory" => PathState::Dir,
            d if hex(d) => PathState::File(d.to_string()),
            t if t.strip_prefix("tree:").is_some_and(hex) => PathState::Tree(t["tree:".len()..].to_string()),
            _ => PathState::Other,
        }
    }
}

/// How a repository path a command names is pinned.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Pin {
    /// A file by its content; a directory only as being one (it is data
    /// the command reads, as the project directory it runs in is).
    Plain,
    /// A file by its content; a directory by the content of every file
    /// below it (BUG-700): the command may run it (`python3 tools`), or
    /// `files` names it.
    Tree,
}

/// Read a regular repository file without following a final symbolic link,
/// at most `max` bytes. `Ok(None)`: not there.
fn read_regular(path: &Path, max: u64) -> std::io::Result<Option<Vec<u8>>> {
    let f = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let m = f.metadata()?;
    if !m.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    if m.len() > max {
        return Err(std::io::Error::other(format!("larger than {max} bytes")));
    }
    let mut data = Vec::with_capacity(m.len() as usize);
    f.take(max + 1).read_to_end(&mut data)?;
    if data.len() as u64 > max {
        return Err(std::io::Error::other(format!("larger than {max} bytes")));
    }
    Ok(Some(data))
}

/// A pinned directory, read whole: each entry below it (a path relative
/// to it, in order) with its content, `None` for a directory.
type TreeContent = Vec<(PathBuf, Option<Vec<u8>>)>;

/// Read every file below directory `dir`, never through a symbolic link:
/// a link, a special file, more than [`MAX_TREE_ENTRIES`] entries, more
/// than [`MAX_PINNED`] bytes in all or more than [`MAX_TREE_DEPTH`]
/// levels is an error (such a directory cannot be pinned).
fn read_tree(dir: &Path) -> std::io::Result<TreeContent> {
    fn walk(base: &Path, rel: &Path, depth: usize, out: &mut TreeContent, bytes: &mut u64) -> std::io::Result<()> {
        if depth > MAX_TREE_DEPTH {
            return Err(std::io::Error::other(format!("deeper than {MAX_TREE_DEPTH} levels")));
        }
        let mut names: Vec<std::ffi::OsString> =
            std::fs::read_dir(base.join(rel))?.map(|e| e.map(|e| e.file_name())).collect::<std::io::Result<_>>()?;
        names.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        for name in names {
            if out.len() >= MAX_TREE_ENTRIES {
                return Err(std::io::Error::other(format!("more than {MAX_TREE_ENTRIES} entries")));
            }
            let r = rel.join(&name);
            let full = base.join(&r);
            let m = std::fs::symlink_metadata(&full)?;
            if m.is_dir() {
                out.push((r.clone(), None));
                walk(base, &r, depth + 1, out, bytes)?;
            } else if m.is_file() {
                let data = read_regular(&full, MAX_PINNED.saturating_sub(*bytes))?
                    .ok_or_else(|| std::io::Error::other(format!("{} disappeared", r.display())))?;
                *bytes += data.len() as u64;
                out.push((r, Some(data)));
            } else {
                return Err(std::io::Error::other(format!("{} is a symbolic link or a special file", r.display())));
            }
        }
        Ok(())
    }
    if !std::fs::symlink_metadata(dir)?.is_dir() {
        return Err(std::io::Error::other("not a directory"));
    }
    let mut out = Vec::new();
    walk(dir, Path::new(""), 0, &mut out, &mut 0)?;
    Ok(out)
}

/// The digest a [`Pin::Tree`] directory is pinned by: of every entry
/// below it, its kind, its relative path and (for a file) its content's
/// digest, NUL-separated, in path order.
fn tree_digest(tree: &TreeContent) -> String {
    let mut h = blake3::Hasher::new();
    for (p, data) in tree {
        match data {
            None => {
                h.update(b"d\0");
                h.update(p.as_os_str().as_bytes());
                h.update(b"\0");
            }
            Some(d) => {
                h.update(b"f\0");
                h.update(p.as_os_str().as_bytes());
                h.update(b"\0");
                h.update(blake3::hash(d).as_bytes());
            }
        }
    }
    h.finalize().to_hex().to_string()
}

fn path_state(root: &Path, p: &str, pin: Pin) -> PathState {
    let full = root.join(p);
    match std::fs::symlink_metadata(&full) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => PathState::Absent,
        Err(_) => PathState::Other,
        Ok(m) if m.is_dir() => match pin {
            Pin::Plain => PathState::Dir,
            Pin::Tree => match read_tree(&full) {
                Ok(t) => PathState::Tree(tree_digest(&t)),
                Err(_) => PathState::Other,
            },
        },
        Ok(m) if m.is_file() => match read_regular(&full, MAX_PINNED) {
            Ok(Some(d)) => PathState::File(digest(&d)),
            Ok(None) => PathState::Absent,
            Err(_) => PathState::Other,
        },
        Ok(_) => PathState::Other,
    }
}

/// `.veilhooks` in the project directory. `Ok(None)`: there is none.
pub fn load(root: &Path) -> Result<Option<Veilhooks>> {
    let bytes = match read_regular(&root.join(VEILHOOKS), MAX_VEILHOOKS) {
        Ok(Some(b)) => b,
        Ok(None) => return Ok(None),
        Err(e) => bail!("cannot read {VEILHOOKS}: {e}"),
    };
    let text = std::str::from_utf8(&bytes).map_err(|_| anyhow!("{VEILHOOKS} is not UTF-8"))?;
    let commands = parse(text)?;
    Ok(Some(Veilhooks { digest: digest(&bytes), bytes, commands }))
}

// ---- what a command reads ------------------------------------------------------------------

/// Build tools (and the like) that read repository files the argv does not
/// name: trusting the command means trusting those files. The files listed
/// are pinned too, so a change to them untrusts the hook; anything they
/// pull in further is not (documented).
const INDIRECT: &[(&[&str], &[&str])] = &[
    (&["make", "gmake"], &["Makefile", "makefile", "GNUmakefile"]),
    (
        &["npm", "npx", "yarn", "pnpm", "bun", "corepack"],
        &["package.json", ".npmrc", ".yarnrc", ".yarnrc.yml", ".pnpmfile.cjs"],
    ),
    (
        &["cargo"],
        &["Cargo.toml", "build.rs", ".cargo/config.toml", ".cargo/config", "rust-toolchain.toml", "rust-toolchain"],
    ),
    (&["just"], &["justfile", "Justfile", ".justfile"]),
    (&["pre-commit"], &[".pre-commit-config.yaml"]),
    (
        &["gradle", "gradlew"],
        &["build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"],
    ),
    (&["mvn", "mvnw"], &["pom.xml"]),
    (&["rake"], &["Rakefile"]),
    (&["bundle"], &["Gemfile"]),
    (&["tox"], &["tox.ini", "pyproject.toml"]),
    (&["nox"], &["noxfile.py"]),
    (&["poetry", "pdm", "uv", "hatch"], &["pyproject.toml"]),
    (
        &["pytest", "py.test"],
        &["conftest.py", "pytest.ini", "pyproject.toml", "setup.cfg", "tox.ini"],
    ),
    (&["go"], &["go.mod"]),
    (&["task"], &["Taskfile.yml", "Taskfile.yaml"]),
    (&["invoke", "inv"], &["tasks.py"]),
    (&["cmake"], &["CMakeLists.txt"]),
    (&["ninja"], &["build.ninja"]),
    (&["meson"], &["meson.build"]),
    (&["deno"], &["deno.json", "deno.jsonc"]),
    (
        &["eslint"],
        &["eslint.config.js", "eslint.config.mjs", "eslint.config.cjs", ".eslintrc.js", ".eslintrc.cjs", "package.json"],
    ),
    (&["prettier"], &["prettier.config.js", ".prettierrc.js", ".prettierrc.cjs", "package.json"]),
    (&["composer"], &["composer.json"]),
    (&["mix"], &["mix.exs"]),
    (&["sbt"], &["build.sbt"]),
    (&["ant"], &["build.xml"]),
];

fn base_name(program: &str) -> &str {
    program.rsplit('/').next().unwrap_or(program)
}

/// Programs that run another command given in their arguments (BUG-702):
/// a command behind one of them is looked at as if it were the program,
/// and since their own options differ, every argument after a launcher
/// counts as a program that may run (see [`programs`]).
const LAUNCHERS: &[&str] = &[
    "env", "nice", "nohup", "timeout", "exec", "command", "builtin", "sudo", "doas", "su", "runuser", "setpriv",
    "stdbuf", "ionice", "chrt", "taskset", "setsid", "time", "caffeinate", "flock", "unbuffer", "chronic",
    "eatmydata", "faketime", "firejail", "bwrap", "unshare", "nsenter", "systemd-run", "script", "busybox", "vl",
    "uvx", "pipx", "dotenv", "direnv", "strace", "ltrace", "valgrind", "catchsegv", "rlwrap", "torsocks",
    "proxychains", "proxychains4", "dbus-run-session", "xvfb-run", "tini", "dumb-init", "gosu", "su-exec", "chpst",
    "setlock", "softlimit", "envdir", "nocache", "cpulimit", "prlimit", "numactl", "sg", "doppler", "op", "aws-vault",
];

/// Programs that run their arguments through a shell, or take them from
/// their input: what they run cannot be pinned, so they are refused.
const SHELL_RUNNERS: &[&str] = &["xargs", "watch", "parallel", "hyperfine", "entr", "eval", "source"];

const SHELLS: &[&str] = &["sh", "bash", "dash", "zsh", "ksh", "mksh", "ash", "yash", "fish", "csh", "tcsh", "rc", "es"];

/// Interpreters that run a directory given as their program
/// (`__main__.py`, `index.js`, `package.json`'s `main`).
fn runs_directories(b: &str) -> bool {
    b.starts_with("python") || b.starts_with("pypy") || matches!(b, "node" | "nodejs" | "bun")
}

/// The positions of `run` that may be a program it runs: the first, and,
/// once a launcher is among them, every later argument (BUG-702: `nice
/// make`, `timeout 60 make`, `env A=b sudo -u x make`).
fn programs(run: &[String]) -> Vec<usize> {
    match run.first() {
        None => Vec::new(),
        Some(p) if LAUNCHERS.contains(&base_name(p)) => (0..run.len()).collect(),
        Some(_) => vec![0],
    }
}

/// A short-option cluster (`-ec`, `-Im`): its letters. `None` for
/// anything else (`--long`, `-`, a non-option).
fn cluster(a: &str) -> Option<&str> {
    a.strip_prefix('-').filter(|r| !r.is_empty() && !r.starts_with('-'))
}

/// The letters of a cluster up to the first that takes the rest as its
/// value (`stop`).
fn letters<'a>(c: &'a str, stop: &str) -> &'a str {
    c.find(|ch| stop.contains(ch)).map_or(c, |i| &c[..=i])
}

/// Does the program at `run[j]` run code given as text in its arguments
/// (`sh -c "make lint"`, `python3 -c`, `node -e`, `perl -e`, …)? That
/// text can name any repository file, in a syntax `vl` does not parse,
/// so such a command is never trusted (BUG-702). Also: the programs of
/// [`SHELL_RUNNERS`], and `env -S`.
fn code_string(run: &[String], j: usize) -> Option<String> {
    let b = base_name(&run[j]);
    let after = &run[j + 1..];
    // Options before the first operand (the script, for interpreters), or
    // (`all`) every later argument.
    let flagged = |short: &str, stop: &str, long: &[&str], all: bool| -> Option<String> {
        let opts = after.iter().take_while(|a| all || (a.starts_with('-') && a.as_str() != "--"));
        let mut it = opts;
        it.find(|a| {
            cluster(a).is_some_and(|c| letters(c, stop).contains(|ch| short.contains(ch)))
                || long.iter().any(|l| a.as_str() == *l || a.strip_prefix(l).is_some_and(|r| r.starts_with('=')))
        })
        .map(|a| format!("`{b} {a}` runs code given as text, which can run repository files no trust pins"))
    };
    if SHELL_RUNNERS.contains(&b) {
        return Some(format!("`{b}` runs a command line, or arguments from its input, which no trust can pin"));
    }
    if SHELLS.contains(&b) {
        // Anywhere after the shell: `bash -o pipefail -c …`.
        return flagged("c", "", &["--command"], true);
    }
    match b {
        "su" | "runuser" | "flock" | "script" => flagged("c", "", &["--command"], true),
        "env" => flagged("S", "uC", &["--split-string"], false),
        b if b.starts_with("python") || b.starts_with("pypy") => flagged("c", "WX", &[], false),
        "node" | "nodejs" | "bun" => flagged("ep", "rC", &["--eval", "--print"], false),
        "deno" => after
            .iter()
            .find(|a| !a.starts_with('-'))
            .filter(|a| *a == "eval" || *a == "repl")
            .map(|_| "`deno eval` runs code given as text, which can run repository files no trust pins".to_string()),
        "perl" => flagged("eE", "IMmxiCDd", &[], false),
        "ruby" => flagged("e", "IrCExF0KTW", &[], false),
        "php" => flagged("rBRE", "cdzF", &[], false),
        "lua" | "luajit" | "Rscript" | "julia" | "osascript" | "tclsh" => flagged("eE", "l", &["--eval"], false),
        "awk" | "gawk" | "mawk" | "nawk" => {
            (!after.iter().any(|a| a == "-f" || a.starts_with("--file") || cluster(a).is_some_and(|c| c.ends_with('f'))))
                .then(|| format!("`{b}` runs a program given as text, which can run repository files no trust pins; put it in a file and use `-f`"))
        }
        _ => None,
    }
}

/// Does the command run something that reads repository files beyond its
/// argv? The files to pin with it, if so.
fn indirect(run: &[String]) -> Option<Vec<&'static str>> {
    let mut out: Vec<&'static str> = Vec::new();
    let mut any = false;
    for j in programs(run) {
        let b = base_name(&run[j]);
        // `python -m mod` imports from the current directory.
        if (b.starts_with("python") || b.starts_with("pypy"))
            && run[j + 1..].iter().any(|a| a == "-m" || cluster(a).is_some_and(|c| letters(c, "WX").contains('m')))
        {
            any = true;
            out.extend(["pyproject.toml", "setup.cfg"]);
        }
        if let Some((_, files)) = INDIRECT.iter().find(|(names, _)| names.contains(&b)) {
            any = true;
            out.extend(files.iter());
        }
    }
    let mut seen = HashSet::new();
    out.retain(|f| seen.insert(*f));
    any.then_some(out)
}

/// How each argument of a command is treated.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Arg {
    /// A program found on `PATH` (a bare name) or by absolute path.
    Program(String),
    /// `prefix` (`--opt=`, `VAR=` or nothing) and a repository path in any
    /// spelling (`./a`, `a//b` and `a/./b` are `a/b`; BUG-701), normalised,
    /// which may name nothing yet: pinned, and a file there (or a pinned
    /// directory) is given to the command as its trusted copy. The empty
    /// path is the project root, the command's working directory: never
    /// pinned, given as `.`. `whole`: for `VAR=value`, the whole argument
    /// as a path, which must name nothing (pinned absent). `spelled`: the
    /// path as written, given as is when no copy replaces it (a path with
    /// `..` is refused, so it names what `path` names).
    Repo { prefix: String, path: String, whole: Option<String>, spelled: String },
    /// Anything else, given as is.
    Literal(String),
    /// An argument trust refuses (why).
    Refused(String),
}

/// What a path written in an argument names.
enum Spelled {
    /// A repository path, normalised (`""`: the root).
    Repo(String),
    /// Not a repository path (outside the project, not a path at all).
    Outside,
    Refused(String),
}

fn under_proc(abs: &Path) -> bool {
    ["/proc", "/dev/fd", "/dev/stdin", "/dev/stdout", "/dev/stderr"].iter().any(|p| abs.starts_with(p))
}

/// Normalise `s`, a path as an argument spells it, against the project
/// `root` (BUG-701). In doubt, refused: a path through `..` that ends in
/// the project, an absolute path into the project (or through `/proc`,
/// which can name it), a path into `.veil` or `.git`.
fn spelled(root: &Path, s: &str) -> Spelled {
    if s.is_empty() {
        return Spelled::Outside;
    }
    let canon_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    if s.starts_with('/') {
        let p = Path::new(s);
        if under_proc(p) {
            return Spelled::Refused(format!("`{}` goes through /proc or /dev/fd, which can name the project", safe(s)));
        }
        if inside(root, p) || lexically(Path::new("/"), s).starts_with(&canon_root) {
            return Spelled::Refused(format!("`{}` is inside the project: name repository files by relative path", safe(s)));
        }
        return Spelled::Outside;
    }
    let parts: Vec<&str> = s.split('/').filter(|c| !c.is_empty() && *c != ".").collect();
    if parts.contains(&"..") {
        let full = lexically(&canon_root, s);
        let real = canon_root.join(s).canonicalize().ok();
        if full.starts_with(&canon_root) || real.is_some_and(|r| r.starts_with(&canon_root)) {
            return Spelled::Refused(format!(
                "`{}` names a project path through `..`: write it as its path in the repository",
                safe(s)
            ));
        }
        return Spelled::Outside;
    }
    if let Some(first) = parts.first() {
        let first = first.to_ascii_lowercase();
        if first == VEIL_DIR || first == ".git" {
            return Spelled::Refused(format!("`{}` is in {first}, which a hook's trust cannot pin", safe(s)));
        }
    }
    Spelled::Repo(parts.join("/"))
}

/// `base` joined with `s`, `..` and `.` resolved lexically.
fn lexically(base: &Path, s: &str) -> PathBuf {
    let mut out = base.to_path_buf();
    for c in s.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            c => out.push(c),
        }
    }
    out
}

/// `NAME=value`, as `env` and `make` read it: the value.
fn assignment(a: &str) -> Option<(&str, &str)> {
    let (name, value) = a.split_once('=')?;
    let mut ch = name.chars();
    let ok = ch.next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_') && ch.all(|c| c.is_ascii_alphanumeric() || c == '_');
    ok.then_some((name, value))
}

fn classify(root: &Path, run: &[String]) -> Vec<Arg> {
    let as_path = |prefix: &str, value: &str, whole: Option<String>, original: &str| match spelled(root, value) {
        Spelled::Repo(path) => Arg::Repo { prefix: prefix.to_string(), path, whole, spelled: value.to_string() },
        Spelled::Outside => Arg::Literal(original.to_string()),
        Spelled::Refused(why) => Arg::Refused(why),
    };
    run.iter()
        .enumerate()
        .map(|(i, a)| {
            if i == 0 {
                return if a.contains('/') && !a.starts_with('/') {
                    as_path("", a, None, a)
                } else {
                    Arg::Program(a.clone())
                };
            }
            if a.starts_with('-') {
                // `--opt=path`: the value is a path like any other.
                if let Some((opt, value)) = a.split_once('=') {
                    return as_path(&format!("{opt}="), value, None, a);
                }
                // `-Iscripts/x`, `--rcfile/x`: a path glued to an option.
                if a.contains('/') {
                    return Arg::Refused(format!(
                        "`{}` attaches a path to an option: write it as two arguments, or as `--opt=path`",
                        safe(a)
                    ));
                }
                return Arg::Literal(a.clone());
            }
            if let Some((name, value)) = assignment(a) {
                // `PYTHONPATH=lib:tools`: a list of paths.
                if value.contains(':') && value.split(':').any(|v| !matches!(spelled(root, v), Spelled::Outside)) {
                    return Arg::Refused(format!("`{}` names repository paths in a list: trust cannot pin them", safe(a)));
                }
                let whole = match spelled(root, a) {
                    Spelled::Repo(p) => Some(p),
                    _ => None,
                };
                return as_path(&format!("{name}="), value, whole, a);
            }
            as_path("", a, None, a)
        })
        .collect()
}

/// Why trust must refuse `c` whatever the files hold, if it must: an
/// argument it cannot pin, code given as text, the project root given to
/// an interpreter that would run it.
fn refusal(root: &Path, c: &Suggested) -> Option<String> {
    let progs = programs(&c.run);
    for &j in &progs {
        if let Some(why) = code_string(&c.run, j) {
            return Some(why);
        }
    }
    let interp = progs.iter().any(|&j| runs_directories(base_name(&c.run[j])));
    for a in classify(root, &c.run) {
        match a {
            Arg::Refused(why) => return Some(why),
            Arg::Repo { path, .. } if path.is_empty() && interp => {
                return Some("it gives the project directory to an interpreter that would run it (`__main__.py`, `index.js`), which trust cannot pin: name the script".into())
            }
            _ => {}
        }
    }
    None
}

/// Every repository path a command's trust pins, and how: its argv's, its
/// `files`, and a build tool's own files. A directory in `files`, or an
/// argument of a command whose program may run it (`python3 tools`), is
/// pinned with everything below it.
fn pinned_paths(root: &Path, c: &Suggested) -> BTreeMap<String, Pin> {
    let interp = programs(&c.run).into_iter().any(|j| runs_directories(base_name(&c.run[j])));
    let arg_pin = if interp { Pin::Tree } else { Pin::Plain };
    let mut out: BTreeMap<String, Pin> = BTreeMap::new();
    let mut add = |p: String, pin: Pin| {
        let e = out.entry(p).or_insert(pin);
        *e = (*e).max(pin);
    };
    for a in classify(root, &c.run) {
        if let Arg::Repo { path, whole, .. } = a {
            if !path.is_empty() {
                add(path, arg_pin);
            }
            if let Some(w) = whole {
                add(w, Pin::Plain);
            }
        }
    }
    for f in &c.files {
        add(f.clone(), Pin::Tree);
    }
    if let Some(files) = indirect(&c.run) {
        for f in files {
            add(f.to_string(), Pin::Plain);
        }
    }
    out
}

// ---- the trust record ----------------------------------------------------------------------

/// `.veil/local/hooks-trust.json`.
#[derive(Serialize, Deserialize, Debug, Default)]
struct TrustRecord {
    version: u32,
    /// BLAKE3 of `.veilhooks`.
    veilhooks: String,
    trusted: Vec<TrustedCommand>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
struct TrustedCommand {
    hook: String,
    command: Vec<String>,
    /// Repository path → BLAKE3 (hex), `absent`, or `directory`.
    digests: BTreeMap<String, String>,
    #[serde(default)]
    indirect: bool,
}

fn local_dir(root: &Path) -> PathBuf {
    veil_core::repo::state_dir(root).join("local")
}

fn trust_path(root: &Path) -> PathBuf {
    local_dir(root).join(TRUST_FILE)
}

fn load_trust(root: &Path) -> Result<Option<TrustRecord>> {
    let data = match read_regular(&trust_path(root), MAX_TRUST_FILE) {
        Ok(Some(d)) => d,
        Ok(None) => return Ok(None),
        Err(e) => bail!("cannot read {}: {e}", trust_path(root).display()),
    };
    let r: TrustRecord = serde_json::from_slice(&data).with_context(|| format!("{} is damaged", trust_path(root).display()))?;
    if r.version != 1 {
        bail!("{} has version {}; this vl reads version 1", trust_path(root).display(), r.version);
    }
    Ok(Some(r))
}

/// Create `dir` owner-only, refusing a symbolic link in its place.
fn private_dir(dir: &Path) -> Result<()> {
    match std::fs::symlink_metadata(dir) {
        Ok(m) if m.is_dir() => {}
        Ok(_) => bail!("{} is not a directory", dir.display()),
        Err(_) => {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(dir)
                .or_else(|e| if dir.is_dir() { Ok(()) } else { Err(e) })
                .with_context(|| format!("creating {}", dir.display()))?;
        }
    }
    if std::fs::symlink_metadata(dir)?.file_type().is_symlink() {
        bail!("{} is a symbolic link", dir.display());
    }
    Ok(())
}

static UNIQUE: AtomicU64 = AtomicU64::new(0);

fn unique(prefix: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("{prefix}{}-{nanos:08x}-{}", std::process::id(), UNIQUE.fetch_add(1, Ordering::Relaxed))
}

/// Write `data` as `path`, `mode`, never half-written.
fn write_atomic(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    let dir = path.parent().unwrap();
    let tmp = dir.join(unique(".tmp-"));
    let r = (|| -> std::io::Result<()> {
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(mode).open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)
    })();
    if r.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    r.with_context(|| format!("writing {}", path.display()))
}

fn save_trust(root: &Path, r: &TrustRecord) -> Result<()> {
    private_dir(&local_dir(root))?;
    let mut json = serde_json::to_vec_pretty(r)?;
    json.push(b'\n');
    write_atomic(&trust_path(root), &json, 0o600)
}

/// Whether this device trusts `.veilhooks` as it is now.
enum Trust {
    /// Trusted: each command with the states its paths were pinned at.
    Trusted(Vec<(Suggested, BTreeMap<String, PathState>)>),
    /// Never trusted on this device.
    NotTrusted,
    /// Trusted once, changed since: which paths differ (`.veilhooks`
    /// itself, or files its commands name).
    Changed(Vec<String>),
}

fn check_trust(root: &Path, hooks: &Veilhooks) -> Result<Trust> {
    let Some(rec) = load_trust(root)? else { return Ok(Trust::NotTrusted) };
    if rec.veilhooks != hooks.digest {
        return Ok(Trust::Changed(vec![VEILHOOKS.into()]));
    }
    let mut out = Vec::new();
    let mut changed = BTreeSet::new();
    for c in &hooks.commands {
        let Some(t) = rec.trusted.iter().find(|t| t.hook == c.hook.name() && t.command == c.run) else {
            changed.insert(VEILHOOKS.to_string());
            continue;
        };
        // The paths the trust pinned must be the ones this command reads
        // (a record for another vl's notion of them does not do).
        // A command this vl refuses is never trusted, whatever an older
        // record says.
        let want = pinned_paths(root, c);
        if refusal(root, c).is_some() || want.keys().any(|p| !t.digests.contains_key(p)) {
            changed.insert(VEILHOOKS.to_string());
            continue;
        }
        let mut states = BTreeMap::new();
        for (p, d) in &t.digests {
            let now = path_state(root, p, want.get(p).copied().unwrap_or(Pin::Plain));
            if now != PathState::from_word(d) || matches!(now, PathState::Other) {
                changed.insert(p.clone());
            }
            states.insert(p.clone(), PathState::from_word(d));
        }
        out.push((c.clone(), states));
    }
    if !changed.is_empty() {
        return Ok(Trust::Changed(changed.into_iter().collect()));
    }
    Ok(Trust::Trusted(out))
}

/// The change that last changed one of `paths`, walking first parents from
/// `@` (bounded): for "changed since you trusted it (by change X)".
fn changed_by(repo: &Repo, wc: ObjectId, paths: &[String]) -> Option<String> {
    let vpaths: Vec<VPath> = paths.iter().filter_map(|p| VPath::new(p).ok()).collect();
    let mut cur = wc;
    for _ in 0..500 {
        let s = repo.snapshot(&cur).ok()?;
        let parent = *s.parents.first()?;
        let ptree = repo.snapshot(&parent).ok()?.tree;
        for p in &vpaths {
            if lookup(repo.store(), &s.tree, p).ok()? != lookup(repo.store(), &ptree, p).ok()? {
                return Some(s.change_id.short());
            }
        }
        cur = parent;
    }
    None
}

// ---- which hooks run -----------------------------------------------------------------------

/// Something to run for a hook point.
enum Runnable {
    /// `$VEIL_HOME/hooks/<name>` or `.veil/hooks/<name>`.
    Local(PathBuf),
    /// A trusted `.veilhooks` command, with the states its paths were
    /// trusted at.
    Suggested(Suggested, BTreeMap<String, PathState>),
}

impl Runnable {
    fn label(&self, root: &Path) -> String {
        match self {
            Runnable::Local(p) => p.strip_prefix(root).unwrap_or(p).display().to_string(),
            Runnable::Suggested(c, _) => format!("{VEILHOOKS}: {}", c.run.join(" ")),
        }
    }
}

fn local_hooks(root: &Path, hook: Hook) -> Vec<PathBuf> {
    [crate::ctx::veil_home().join("hooks"), veil_core::repo::state_dir(root).join("hooks")]
        .into_iter()
        .map(|d| d.join(hook.name()))
        .filter(|p| p.is_file())
        // Run by absolute path: hooks run in the project root.
        .map(|p| std::path::absolute(&p).unwrap_or(p))
        .collect()
}

fn is_executable(p: &Path) -> bool {
    std::fs::metadata(p).is_ok_and(|m| m.permissions().mode() & 0o111 != 0)
}

/// Where hooks are being skipped by a hook: `vl` run from inside a hook
/// never runs hooks itself (no recursion through `vl commit` in a
/// pre-commit hook).
fn inside_hook() -> bool {
    std::env::var_os("VEIL_HOOK").is_some()
}

/// The hooks to run at each of `points`, warning (once) about suggested
/// ones that do not run because this device does not trust them as they
/// are now.
fn runnables(root: &Path, repo: &Repo, wc: Option<ObjectId>, points: &[Hook]) -> Vec<Vec<Runnable>> {
    let mut out: Vec<Vec<Runnable>> = points.iter().map(|_| Vec::new()).collect();
    for (i, hook) in points.iter().enumerate() {
        for p in local_hooks(root, *hook) {
            if is_executable(&p) {
                out[i].push(Runnable::Local(p));
            } else {
                warn(&format!(
                    "the {} hook {} is not executable; it did not run (`chmod +x` it)",
                    hook.name(),
                    safe(&p.display().to_string())
                ));
            }
        }
    }
    let hooks = match load(root) {
        Ok(Some(h)) => h,
        Ok(None) => return out,
        Err(e) => {
            warn(&format!("{}; no repository hook runs", safe(&format!("{e:#}"))));
            return out;
        }
    };
    let named: Vec<&str> = points
        .iter()
        .filter(|h| hooks.commands.iter().any(|c| c.hook == **h))
        .map(|h| h.name())
        .collect();
    if named.is_empty() {
        return out;
    }
    let which = match named.len() {
        1 => format!("{} hook", named[0]),
        _ => format!("{} hooks", named.join(" and ")),
    };
    let review = "review it with `vl hooks show`, then `vl hooks trust`";
    match check_trust(root, &hooks) {
        Ok(Trust::Trusted(cmds)) => {
            for (c, s) in cmds {
                if let Some(i) = points.iter().position(|h| *h == c.hook) {
                    out[i].push(Runnable::Suggested(c, s));
                }
            }
        }
        Ok(Trust::NotTrusted) => warn(&format!("{VEILHOOKS} suggests a {which} this device has not trusted; it did not run ({review})")),
        Ok(Trust::Changed(paths)) => {
            let by = wc.and_then(|wc| changed_by(repo, wc, &paths)).map(|c| format!(", by change {c}")).unwrap_or_default();
            let list = paths.iter().map(|p| safe(p).into_owned()).collect::<Vec<_>>().join(", ");
            warn(&format!("{VEILHOOKS} changed since you trusted it ({list}{by}); its {which} did not run ({review})"));
        }
        Err(e) => warn(&format!("{}; no repository hook runs", safe(&format!("{e:#}")))),
    }
    out
}

// ---- running one ---------------------------------------------------------------------------

/// What a hook is told.
#[derive(Default)]
pub struct Invocation {
    pub args: Vec<OsString>,
    pub stdin: Option<Vec<u8>>,
    pub env: Vec<(&'static str, String)>,
}

fn timeout() -> Result<Duration> {
    match std::env::var("VEIL_HOOK_TIMEOUT") {
        Err(std::env::VarError::NotPresent) => Ok(DEFAULT_TIMEOUT),
        Ok(s) => match s.trim().parse::<u64>() {
            Ok(n) if (1..=MAX_TIMEOUT_SECS).contains(&n) => Ok(Duration::from_secs(n)),
            _ => bail!("VEIL_HOOK_TIMEOUT must be a whole number of seconds from 1 to {MAX_TIMEOUT_SECS}, not {:?}", safe(&s)),
        },
        Err(_) => bail!("VEIL_HOOK_TIMEOUT is not valid UTF-8"),
    }
}

fn inside(root: &Path, p: &Path) -> bool {
    let canon_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let canon = p.canonicalize().unwrap_or_else(|_| p.to_path_buf());
    canon.starts_with(&canon_root) || p.starts_with(root)
}

/// `PATH` for a hook: absolute entries outside the project only.
fn clean_path(root: &Path) -> OsString {
    let path = std::env::var_os("PATH").unwrap_or_else(|| "/usr/local/bin:/usr/bin:/bin".into());
    let kept: Vec<PathBuf> = std::env::split_paths(&path)
        .filter(|p| p.is_absolute() && !inside(root, p))
        .collect();
    std::env::join_paths(kept).unwrap_or_default()
}

/// Resolve a program a `.veilhooks` command names: never a repository file.
fn resolve_program(root: &Path, name: &str, path: &OsString) -> Result<PathBuf> {
    let found = if name.starts_with('/') {
        Some(PathBuf::from(name)).filter(|p| p.is_file())
    } else {
        std::env::split_paths(path).map(|d| d.join(name)).find(|p| p.is_file() && is_executable(p))
    };
    let p = found.ok_or_else(|| anyhow!("`{}` was not found on PATH", safe(name)))?;
    if inside(root, &p) {
        bail!("`{}` resolves inside the project ({}): name repository scripts by relative path", safe(name), p.display());
    }
    Ok(p)
}

/// Read a pinned repository file, check it against its trusted digest and
/// write that very content to a private copy. The command gets the copy:
/// what runs is what was checked.
fn trusted_copy(root: &Path, rel: &str, want: &str, copies: &mut Vec<PathBuf>) -> Result<PathBuf> {
    let data = read_regular(&root.join(rel), MAX_PINNED)
        .ok()
        .flatten()
        .ok_or_else(|| anyhow!("`{}` changed since you trusted it", safe(rel)))?;
    if digest(&data) != want {
        bail!("`{}` changed since you trusted it", safe(rel));
    }
    let dir = local_dir(root).join(RUN_DIR);
    private_dir(&local_dir(root))?;
    private_dir(&dir)?;
    let ext = Path::new(rel)
        .extension()
        .and_then(|e| e.to_str())
        .filter(|e| e.len() <= 8 && e.bytes().all(|b| b.is_ascii_alphanumeric()))
        .map(|e| format!(".{e}"))
        .unwrap_or_default();
    let copy = dir.join(format!("{}{}{ext}", &want[..16], unique("-")));
    write_atomic(&copy, &data, 0o700)?;
    copies.push(copy.clone());
    Ok(copy)
}

/// [`trusted_copy`] for a directory pinned with everything below it
/// (BUG-700): read whole, checked against its trusted digest, and that
/// very content written to a private directory the command gets.
fn trusted_tree_copy(root: &Path, rel: &str, want: &str, copies: &mut Vec<PathBuf>) -> Result<PathBuf> {
    let changed = || anyhow!("`{}` changed since you trusted it", safe(rel));
    let tree = read_tree(&root.join(rel)).map_err(|_| changed())?;
    if tree_digest(&tree) != want {
        return Err(changed());
    }
    let dir = local_dir(root).join(RUN_DIR);
    private_dir(&local_dir(root))?;
    private_dir(&dir)?;
    let name = Path::new(rel).file_name().and_then(|n| n.to_str()).unwrap_or("dir");
    let name: String = name.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')).take(32).collect();
    let copy = dir.join(format!("{}{}-{name}", &want[..16], unique("-")));
    std::fs::DirBuilder::new().mode(0o700).create(&copy).with_context(|| format!("creating {}", copy.display()))?;
    copies.push(copy.clone());
    for (p, data) in &tree {
        let to = copy.join(p);
        match data {
            None => std::fs::DirBuilder::new().mode(0o700).create(&to),
            Some(d) => std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o700)
                .open(&to)
                .and_then(|mut f| f.write_all(d)),
        }
        .with_context(|| format!("writing {}", to.display()))?;
    }
    Ok(copy)
}

/// Remove a private copy (a file, or a directory [`trusted_tree_copy`]
/// made).
fn remove_copy(c: &Path) {
    match std::fs::symlink_metadata(c) {
        Ok(m) if m.is_dir() => {
            let _ = std::fs::remove_dir_all(c);
        }
        Ok(_) => {
            let _ = std::fs::remove_file(c);
        }
        Err(_) => {}
    }
}

/// The process group of the hook running now (0: none), for the signal
/// handler.
static HOOK_GROUP: AtomicI32 = AtomicI32::new(0);
/// The last signal received while a hook ran.
static HOOK_SIGNAL: AtomicI32 = AtomicI32::new(0);
/// One hook at a time per process (`vl serve` serialises writes anyway).
static RUNNING: Mutex<()> = Mutex::new(());

extern "C" fn forward(sig: libc::c_int) {
    HOOK_SIGNAL.store(sig, Ordering::SeqCst);
    let g = HOOK_GROUP.load(Ordering::SeqCst);
    if g > 0 {
        // SAFETY: kill(2) is async-signal-safe.
        unsafe {
            libc::kill(-g, sig);
        }
    }
}

const FORWARDED: [libc::c_int; 4] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT];

/// Forward Ctrl-C, SIGTERM, SIGHUP and SIGQUIT to the hook's process group
/// while it runs (it has its own group, so the terminal's Ctrl-C does not
/// reach it), and pass the signal on to `vl` once it is over.
struct Forwarding {
    old: Vec<(libc::c_int, libc::sigaction)>,
}

impl Forwarding {
    fn install() -> Forwarding {
        HOOK_SIGNAL.store(0, Ordering::SeqCst);
        let mut old = Vec::new();
        for sig in FORWARDED {
            // SAFETY: a plain sigaction(2) with a handler that only touches
            // atomics and calls kill(2).
            unsafe {
                let mut sa: libc::sigaction = std::mem::zeroed();
                sa.sa_sigaction = forward as extern "C" fn(libc::c_int) as libc::sighandler_t;
                libc::sigemptyset(&mut sa.sa_mask);
                let mut prev: libc::sigaction = std::mem::zeroed();
                if libc::sigaction(sig, &sa, &mut prev) == 0 {
                    old.push((sig, prev));
                }
            }
        }
        Forwarding { old }
    }
}

impl Drop for Forwarding {
    fn drop(&mut self) {
        HOOK_GROUP.store(0, Ordering::SeqCst);
        for (sig, prev) in &self.old {
            // SAFETY: restores the disposition saved above.
            unsafe {
                libc::sigaction(*sig, prev, std::ptr::null_mut());
            }
        }
        let sig = HOOK_SIGNAL.swap(0, Ordering::SeqCst);
        if sig != 0 {
            // SAFETY: re-raise what `vl` received, now under its own
            // disposition (default: terminate; `vl serve`: stop serving).
            unsafe {
                libc::raise(sig);
            }
        }
    }
}

enum Outcome {
    Exited(i32),
    Signalled(i32),
    TimedOut,
}

fn spawn(cmd: &mut Command) -> std::io::Result<std::process::Child> {
    // A copy just written may still be open for writing in a child another
    // thread is forking (ETXTBSY): try again shortly.
    let mut tries = 0;
    loop {
        match cmd.spawn() {
            Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) && tries < 20 => {
                tries += 1;
                std::thread::sleep(Duration::from_millis(5 * tries));
            }
            r => return r,
        }
    }
}

fn execute(program: &Path, args: &[OsString], root: &Path, hook: Hook, inv: &Invocation, limit: Duration) -> Result<Outcome> {
    let _one = RUNNING.lock().unwrap_or_else(|e| e.into_inner());
    let mut cmd = Command::new(program);
    cmd.args(args).current_dir(root).env_clear();
    for k in ALLOWED_ENV {
        if let Some(v) = std::env::var_os(k) {
            cmd.env(k, v);
        }
    }
    for (k, v) in std::env::vars_os() {
        if k.as_bytes().starts_with(b"LC_") {
            cmd.env(k, v);
        }
    }
    cmd.env("PATH", clean_path(root));
    cmd.env("VEIL_HOOK", hook.name());
    for (k, v) in &inv.env {
        cmd.env(k, v);
    }
    // Both streams to our stderr: stdout carries `--json` documents and
    // `vl serve --call` replies, and a hook could print anything.
    let err = std::io::stderr().as_fd().try_clone_to_owned()?;
    cmd.stdout(Stdio::from(err.try_clone()?)).stderr(Stdio::from(err));
    cmd.stdin(if inv.stdin.is_some() { Stdio::piped() } else { Stdio::null() });
    cmd.process_group(0);
    let forwarding = Forwarding::install();
    let mut child = spawn(&mut cmd).with_context(|| format!("starting the {} hook {}", hook.name(), program.display()))?;
    let group = child.id() as i32;
    HOOK_GROUP.store(group, Ordering::SeqCst);
    if HOOK_SIGNAL.load(Ordering::SeqCst) != 0 {
        // SAFETY: signals the hook's own process group.
        unsafe {
            libc::kill(-group, HOOK_SIGNAL.load(Ordering::SeqCst));
        }
    }
    let writer = inv.stdin.clone().and_then(|data| {
        child.stdin.take().map(|mut s| {
            // A hook that does not read its input is not an error.
            std::thread::spawn(move || {
                let _ = s.write_all(&data);
            })
        })
    });
    let deadline = Instant::now() + limit;
    let outcome = loop {
        if let Some(st) = child.try_wait()? {
            use std::os::unix::process::ExitStatusExt;
            break match (st.code(), st.signal()) {
                (Some(c), _) => Outcome::Exited(c),
                (None, Some(s)) => Outcome::Signalled(s),
                _ => Outcome::Exited(-1),
            };
        }
        let now = Instant::now();
        if now >= deadline {
            // SAFETY: kills the hook's own process group.
            unsafe {
                libc::kill(-group, libc::SIGKILL);
            }
            let _ = child.wait();
            break Outcome::TimedOut;
        }
        std::thread::sleep((deadline - now).min(Duration::from_millis(10)));
    };
    // Nothing the hook started outlives it in its group.
    // SAFETY: as above; ESRCH (nothing left) is fine.
    unsafe {
        libc::kill(-group, libc::SIGKILL);
    }
    if let Some(w) = writer {
        let _ = w.join();
    }
    drop(forwarding);
    Ok(outcome)
}

/// The program and arguments of trusted command `c`, given the states its
/// paths were trusted at: every repository file or pinned directory it
/// names is replaced by a private copy of the trusted bytes (written to
/// `copies`), whatever spelling named it (`./a`, `--opt=a`, `VAR=a`), and
/// every other pinned path is checked again. `Err` if anything changed
/// since the trust, or the command is one trust refuses.
fn suggested_argv(
    root: &Path,
    c: &Suggested,
    states: &BTreeMap<String, PathState>,
    copies: &mut Vec<PathBuf>,
    resolve: &dyn Fn(&str) -> Result<PathBuf>,
) -> Result<(PathBuf, Vec<OsString>)> {
    if let Some(why) = refusal(root, c) {
        bail!("{why}");
    }
    let pins = pinned_paths(root, c);
    let changed = |p: &str| anyhow!("`{}` changed since you trusted it", safe(p));
    let mut argv: Vec<OsString> = Vec::new();
    let mut program = None;
    let mut copied = BTreeSet::new();
    for a in classify(root, &c.run) {
        let v: OsString = match a {
            Arg::Program(name) => resolve(&name)?.into_os_string(),
            Arg::Repo { prefix, path, spelled, .. } if path.is_empty() => format!("{prefix}{spelled}").into(),
            Arg::Repo { prefix, path, spelled, .. } => {
                let pin = pins.get(&path).copied().unwrap_or(Pin::Plain);
                let target: OsString = match states.get(&path) {
                    Some(PathState::File(d)) => trusted_copy(root, &path, d, copies)?.into_os_string(),
                    Some(PathState::Tree(d)) => trusted_tree_copy(root, &path, d, copies)?.into_os_string(),
                    // The program itself is always a trusted copy.
                    Some(s) if program.is_some() && path_state(root, &path, pin) == *s => spelled.into(),
                    _ => return Err(changed(&path)),
                };
                copied.insert(path);
                let mut v = OsString::from(prefix);
                v.push(target);
                v
            }
            Arg::Literal(s) => {
                if s.starts_with('/') && (inside(root, Path::new(&s)) || under_proc(Path::new(&s))) {
                    bail!("`{}` is inside the project: name repository files by relative path", safe(&s));
                }
                s.into()
            }
            Arg::Refused(why) => bail!("{why}"),
        };
        if program.is_none() {
            program = Some(PathBuf::from(v));
        } else {
            argv.push(v);
        }
    }
    // Files the command reads but is not given (`files`, a build tool's):
    // checked now.
    for (p, pin) in &pins {
        if !copied.contains(p) && states.get(p).is_none_or(|s| path_state(root, p, *pin) != *s) {
            return Err(changed(p));
        }
    }
    Ok((program.expect("a command has a program"), argv))
}

/// Run one hook; `Err` if it failed (a non-zero exit, a signal, the
/// timeout, or it could not start).
fn run_one(root: &Path, hook: Hook, r: &Runnable, inv: &Invocation, limit: Duration) -> Result<()> {
    let label = safe(&r.label(root)).into_owned();
    let mut copies = Vec::new();
    let result = (|| -> Result<Outcome> {
        match r {
            Runnable::Local(p) => execute(p, &inv.args, root, hook, inv, limit),
            Runnable::Suggested(c, states) => {
                let (program, mut argv) = suggested_argv(root, c, states, &mut copies, &|name| resolve_program(root, name, &clean_path(root)))?;
                argv.extend(inv.args.iter().cloned());
                execute(&program, &argv, root, hook, inv, limit)
            }
        }
    })();
    for c in copies {
        remove_copy(&c);
    }
    let fail = |why: String| anyhow!("the {} hook `{label}` {why}", hook.name());
    match result {
        Ok(Outcome::Exited(0)) => Ok(()),
        Ok(Outcome::Exited(c)) => Err(fail(format!("failed (exit status {c})"))),
        Ok(Outcome::Signalled(s)) => Err(fail(format!("was killed by signal {s}"))),
        Ok(Outcome::TimedOut) => Err(fail(format!(
            "did not finish within {}s and was stopped (VEIL_HOOK_TIMEOUT)",
            limit.as_secs()
        ))),
        Err(e) => Err(fail(format!("could not run: {e:#}"))),
    }
}

/// Run every hook at `hook`, stopping at the first failure.
fn run_all(root: &Path, hook: Hook, rs: &[Runnable], inv: &Invocation) -> Result<()> {
    if rs.is_empty() {
        return Ok(());
    }
    let limit = timeout()?;
    for r in rs {
        run_one(root, hook, r, inv, limit)?;
    }
    Ok(())
}

// ---- the commands that run hooks -----------------------------------------------------------

/// `pre-commit` and `commit-msg`, for `vl commit`, `vl describe` of `@` and
/// `commit` / `describe` over `vl serve`. Returns the message to record
/// (the `commit-msg` hook may edit it).
///
/// Runs with no repository lock held. Afterwards the working copy is
/// recorded again (when `snapshot`, as the command's own snapshot was):
/// if that, or anything the hooks ran, moved the operation log, the
/// command is refused, with every edit kept in `@`.
pub fn before_commit(ctx: &mut Ctx, verify: &NoVerifyArgs, message: &str, snapshot: bool, what: &str) -> Result<String> {
    if verify.no_verify || ctx.bare {
        return Ok(message.to_string());
    }
    if inside_hook() {
        return Ok(message.to_string());
    }
    let wc = ctx.wc()?;
    let mut found = runnables(&ctx.root, &ctx.repo, Some(wc), &[Hook::PreCommit, Hook::CommitMsg]);
    let msg = found.pop().unwrap_or_default();
    let pre = found.pop().unwrap_or_default();
    if pre.is_empty() && msg.is_empty() {
        return Ok(message.to_string());
    }
    let op = ctx.repo.op_id();
    let env = vec![("VEIL_SNAPSHOT", wc.hex()), ("VEIL_WORKSPACE", ctx.ws.clone())];
    let skip = format!("the {what} was refused; fix it, or skip hooks with `--no-verify`");
    run_all(&ctx.root, Hook::PreCommit, &pre, &Invocation { env: env.clone(), ..Default::default() })
        .map_err(|e| anyhow!("{e:#}; {skip}"))?;
    let mut message = message.to_string();
    if !msg.is_empty() {
        message = commit_msg(&ctx.root, &msg, &message, env).map_err(|e| anyhow!("{e:#}; {skip}"))?;
    }
    // What the hooks did to the directory or the repository.
    ctx.refresh()?;
    if snapshot {
        ctx.snapshot()?;
    }
    if ctx.repo.op_id() != op {
        bail!(
            "the repository or the working copy changed while the {} hooks ran (a hook edited files or ran `vl`); \
             nothing was lost (the edits are in @): review them and {what} again",
            if msg.is_empty() { "pre-commit" } else { "pre-commit and commit-msg" }
        );
    }
    crate::api::check_message(&message)?;
    Ok(message)
}

fn commit_msg(root: &Path, rs: &[Runnable], message: &str, env: Vec<(&'static str, String)>) -> Result<String> {
    let dir = local_dir(root).join("tmp");
    private_dir(&local_dir(root))?;
    private_dir(&dir)?;
    let file = dir.join(unique("commit-msg-"));
    let written = if message.ends_with('\n') { message.to_string() } else { format!("{message}\n") };
    let r = (|| -> Result<String> {
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&file)?;
        f.write_all(written.as_bytes())?;
        drop(f);
        run_all(root, Hook::CommitMsg, rs, &Invocation { args: vec![file.clone().into()], env, stdin: None })?;
        let back = read_regular(&file, MAX_MESSAGE)
            .map_err(|e| anyhow!("the commit-msg hook left an unreadable message file: {e}"))?
            .ok_or_else(|| anyhow!("the commit-msg hook removed the message file"))?;
        let back = String::from_utf8(back).map_err(|_| anyhow!("the commit-msg hook wrote a message that is not UTF-8"))?;
        if back == written {
            return Ok(message.to_string());
        }
        Ok(back.trim_end_matches('\n').to_string())
    })();
    let _ = std::fs::remove_file(&file);
    r
}

/// `pre-push`, for `vl push` and `vl git push`. `lines` builds the hook's
/// stdin (only if a hook will run): one line per tag the push sends. If
/// the hook moved a tag, the push is refused (it would send something else
/// than the hook was shown).
pub fn before_push(
    ctx: &mut Ctx,
    verify: &NoVerifyArgs,
    remote: &str,
    url: &str,
    kind: &str,
    lines: impl FnOnce(&mut Ctx) -> Result<Vec<String>>,
) -> Result<()> {
    if verify.no_verify || ctx.bare || inside_hook() {
        return Ok(());
    }
    let wc = ctx.wc().ok();
    let rs = runnables(&ctx.root, &ctx.repo, wc, &[Hook::PrePush]).pop().unwrap_or_default();
    if rs.is_empty() {
        return Ok(());
    }
    let mut stdin = lines(ctx)?.join("\n");
    if !stdin.is_empty() {
        stdin.push('\n');
    }
    let tags = ctx.repo.view().tags.clone();
    let inv = Invocation {
        args: vec![remote.into(), veil_core::git::redact_url(url).into(), kind.into()],
        stdin: Some(stdin.into_bytes()),
        env: vec![("VEIL_WORKSPACE", ctx.ws.clone())],
    };
    run_all(&ctx.root, Hook::PrePush, &rs, &inv)
        .map_err(|e| anyhow!("{e:#}; nothing was pushed (skip hooks with `--no-verify`)"))?;
    ctx.refresh()?;
    if ctx.repo.view().tags != tags {
        bail!("tags changed while the pre-push hook ran (a hook ran `vl`); nothing was pushed: review them and push again");
    }
    Ok(())
}

/// The pre-push lines of a push to a Veil remote: `<tag> <snapshot>
/// <remote-snapshot-or-0>` for each tag it creates, moves or tries to
/// (rejected), and `<tag> 0 <remote-snapshot-or-0>` for each `--delete`.
/// Never a cloaked tag on a public remote, never a snapshot an unreleased
/// embargo holds back.
pub fn veil_push_lines(repo: &Repo, plan: &veil_core::push_plan::PushPlan, remote: &str, delete: &[String]) -> Vec<String> {
    let mut out = plan_lines(plan);
    out.extend(delete_lines(repo, remote, delete, plan.public, false));
    out
}

/// The tag lines of [`veil_push_lines`].
fn plan_lines(plan: &veil_core::push_plan::PushPlan) -> Vec<String> {
    use veil_core::push_plan::TagAction;
    let withheld: HashSet<ObjectId> = plan.withheld_snapshots.iter().map(|(id, _)| *id).collect();
    let mut out = Vec::new();
    for t in &plan.tags {
        if !matches!(t.action, TagAction::Create | TagAction::Update | TagAction::Rejected)
            || (plan.public && t.cloak.is_some())
            || withheld.contains(&t.target)
        {
            continue;
        }
        let there = t.remote.map(|r| r.hex()).unwrap_or_else(|| "0".into());
        out.push(format!("{} {} {there}", t.name, t.target.hex()));
    }
    out
}

/// `<tag> 0 <remote-snapshot-or-0>` (and ` 0` for a Git remote's commit)
/// for each tag `--delete` removes on `remote`.
pub fn delete_lines(repo: &Repo, remote: &str, delete: &[String], public: bool, git: bool) -> Vec<String> {
    let view = repo.view();
    delete
        .iter()
        .filter(|d| !(public && view.tags.get(*d).is_some_and(|t| t.cloak.is_some())))
        .map(|d| {
            let there = view.remote_tags.get(&format!("{remote}/{d}")).map(|r| r.hex()).unwrap_or_else(|| "0".into());
            format!("{d} 0 {there}{}", if git { " 0" } else { "" })
        })
        .collect()
}

/// The pre-push lines of `vl git push`: `<tag> <snapshot> <remote-or-0>
/// <git-commit>` per branch, from an export (exactly what the push then
/// sends). The snapshot is `-` when the commit is a projection (an
/// unreleased embargo's pre-merge tree), so a withheld snapshot id is never
/// shown. Then the Git tags the push sends (BUG-641), in Git's own format:
/// `refs/tags/<name> <local-object> refs/tags/<name> <remote-object-or-zeros>`,
/// and `(delete) <zeros> refs/tags/<name> <remote-object-or-zeros>` for
/// `--delete-tag`. Only exported release tags appear (never a cloaked one,
/// nor one an unreleased embargo holds back), and not one the push refuses
/// before sending (it exists there with another target, without
/// `--force-tags`). Mirrors `git::push_with`.
pub fn git_push_lines(ctx: &mut Ctx, git_dir: &Path, remote: &str, push: &veil_core::git::PushOptions) -> Result<Vec<String>> {
    use veil_core::git::GitBridge;
    let (tags, delete) = (&push.only_tags[..], &push.delete[..]);
    let mut out = Vec::new();
    let mut tag_lines = Vec::new();
    let zeros = |len: usize| "0".repeat(len);
    if (delete.is_empty() && push.delete_tags.is_empty()) || !tags.is_empty() {
        let mut bridge = GitBridge::open(&ctx.repo, git_dir)?;
        let export = bridge.export(&mut ctx.repo, tags)?;
        let view = ctx.repo.view();
        for (branch, commit) in &export.branches {
            let Some(t) = view.tags.get(branch) else { continue };
            if t.cloak.is_some() {
                continue;
            }
            let snap = match bridge.snapshot_of(commit) {
                Some(s) if s == t.target => s.hex(),
                _ => "-".into(),
            };
            let there = view.remote_tags.get(&format!("{remote}/{branch}")).map(|r| r.hex()).unwrap_or_else(|| "0".into());
            out.push(format!("{branch} {snap} {there} {commit}"));
        }
        for t in &export.tags {
            if view.tags.get(&t.name).is_some_and(|x| x.cloak.is_some()) {
                continue;
            }
            let fetched = bridge.remote_tag(remote, &t.name)?;
            if fetched.is_some_and(|f| f != t.git) && !push.force_tags {
                continue; // refused before anything is sent
            }
            let local = t.git.to_string();
            let there = fetched.map(|f| f.to_string()).unwrap_or_else(|| zeros(local.len()));
            tag_lines.push(format!("refs/tags/{0} {local} refs/tags/{0} {there}", t.name));
        }
    }
    out.extend(delete_lines(&ctx.repo, remote, delete, true, true));
    out.extend(tag_lines);
    if !push.delete_tags.is_empty() {
        let bridge = GitBridge::open(&ctx.repo, git_dir)?;
        for d in &push.delete_tags {
            let there = bridge.remote_tag(remote, d)?;
            let len = there.map(|f| f.to_string().len()).unwrap_or(40);
            let there = there.map(|f| f.to_string()).unwrap_or_else(|| zeros(len));
            out.push(format!("(delete) {} refs/tags/{d} {there}", zeros(len)));
        }
    }
    Ok(out)
}

/// Where the working copy is before a command, for `post-checkout`.
pub fn checkout_point(ctx: &Ctx) -> Option<(String, ObjectId)> {
    (!ctx.bare).then(|| ctx.wc().ok().map(|w| (ctx.ws.clone(), w))).flatten()
}

/// `post-checkout`, after `vl new`, `vl edit` and `vl ws switch` moved the
/// working copy (and the directory followed): old and new snapshot ids.
/// Only reported, never fatal.
pub fn post_checkout(ctx: &Ctx, cmd: &Cmd, before: Option<(String, ObjectId)>) {
    if !matches!(cmd, Cmd::New { .. } | Cmd::Edit { .. } | Cmd::Workspace(WsCmd::Switch { .. })) || inside_hook() {
        return;
    }
    let (Some((_, old)), Some((ws, new))) = (before, checkout_point(ctx)) else { return };
    if old == new {
        return;
    }
    let rs = runnables(&ctx.root, &ctx.repo, Some(new), &[Hook::PostCheckout]).pop().unwrap_or_default();
    let inv = Invocation {
        args: vec![old.hex().into(), new.hex().into()],
        stdin: None,
        env: vec![("VEIL_SNAPSHOT", new.hex()), ("VEIL_WORKSPACE", ws)],
    };
    if let Err(e) = run_all(&ctx.root, Hook::PostCheckout, &rs, &inv) {
        warn(&safe(&format!("{e:#}")));
    }
}

// ---- vl hooks ------------------------------------------------------------------------------

/// `vl hooks`.
pub fn run(ctx: &mut Ctx, cmd: &HooksCmd) -> Result<ExitCode> {
    match cmd {
        HooksCmd::Show => show(ctx),
        HooksCmd::Trust { yes, i_understand_indirect } => trust(ctx, *yes, *i_understand_indirect),
    }
}

fn print_local(root: &Path) {
    println!("{}", bold("Device-local hooks (run without asking):"));
    let mut any = false;
    for h in Hook::ALL {
        for p in local_hooks(root, h) {
            any = true;
            let note = if is_executable(&p) { String::new() } else { format!("  {}", yellow("(not executable: skipped)")) };
            println!("  {:<14} {}{note}", h.name(), safe(&p.display().to_string()));
        }
    }
    if !any {
        println!("  {}", dim("none (put executables in .veil/hooks/<name> or $VEIL_HOME/hooks/<name>)"));
    }
}

fn print_commands(root: &Path, hooks: &Veilhooks, trusted: &BTreeMap<String, String>) {
    for c in &hooks.commands {
        let ind = if indirect(&c.run).is_some() { format!("  {}", yellow("(runs a build tool: reads files it is not given)")) } else { String::new() };
        println!("  {:<14} {}{ind}", c.hook.name(), safe(&c.run.join(" ")));
        if let Some(why) = refusal(root, c) {
            println!("      {}", red(&format!("cannot be trusted: {}", safe(&why))));
        }
        for (p, pin) in pinned_paths(root, c) {
            let now = path_state(root, &p, pin);
            let mark = match trusted.get(&p) {
                Some(w) if PathState::from_word(w) == now => green("trusted"),
                Some(_) => red("changed since trusted"),
                None => dim("not trusted"),
            };
            println!("      {:<40} {}  {mark}", safe(&p), dim(&now.word()));
        }
    }
}

fn show(ctx: &mut Ctx) -> Result<ExitCode> {
    let root = ctx.root.clone();
    print_local(&root);
    println!();
    let hooks = match load(&root) {
        Ok(Some(h)) => h,
        Ok(None) => {
            println!("{}", bold("Repository hooks:"));
            println!("  {}", dim(&format!("none (no {VEILHOOKS} file)")));
            return Ok(ExitCode::SUCCESS);
        }
        Err(e) => {
            println!("{} {}", bold("Repository hooks:"), red(&safe(&format!("{e:#}"))));
            return Ok(ExitCode::FAILURE);
        }
    };
    let status = match check_trust(&root, &hooks) {
        Ok(Trust::Trusted(_)) => green("trusted on this device"),
        Ok(Trust::NotTrusted) => yellow("not trusted on this device: they do not run"),
        Ok(Trust::Changed(_)) => red("changed since you trusted them: they do not run"),
        Err(e) => red(&safe(&format!("{e:#}"))),
    };
    println!("{} {VEILHOOKS} (blake3 {}) — {status}", bold("Repository hooks:"), hooks.digest);
    let trusted: BTreeMap<String, String> = load_trust(&root)
        .ok()
        .flatten()
        .map(|r| r.trusted.into_iter().flat_map(|t| t.digests).collect())
        .unwrap_or_default();
    print_commands(&root, &hooks, &trusted);
    println!();
    println!("{}", dim(&format!("--- {VEILHOOKS} ---")));
    for line in String::from_utf8_lossy(&hooks.bytes).lines() {
        println!("{}", safe(line));
    }
    Ok(ExitCode::SUCCESS)
}

/// What `vl hooks trust` records for command `c`: the state of every
/// path it pins. `Err` if trust must refuse it.
fn trust_command(root: &Path, c: &Suggested) -> Result<TrustedCommand> {
    if let Some(why) = refusal(root, c) {
        bail!("the {} command `{}` cannot be trusted: {why}", c.hook.name(), safe(&c.run.join(" ")));
    }
    let args = classify(root, &c.run);
    if let Arg::Repo { path, .. } = &args[0] {
        if !matches!(path_state(root, path, Pin::Plain), PathState::File(_)) {
            bail!("the {} command runs `{}`, which is not a regular file here", c.hook.name(), safe(path));
        }
    }
    for a in &args {
        if let Arg::Repo { whole: Some(w), .. } = a {
            if path_state(root, w, Pin::Plain) != PathState::Absent {
                bail!(
                    "the {} command's argument `{}` is both a file of the project and an assignment: rename the file or the variable",
                    c.hook.name(),
                    safe(w)
                );
            }
        }
    }
    let mut digests = BTreeMap::new();
    for (p, pin) in pinned_paths(root, c) {
        let s = path_state(root, &p, pin);
        if s == PathState::Other {
            bail!(
                "`{}` (named by the {} command) is not a regular file, or a directory of at most {MAX_TREE_ENTRIES} entries and {} MiB without symbolic links",
                safe(&p),
                c.hook.name(),
                MAX_PINNED >> 20
            );
        }
        digests.insert(p, s.word());
    }
    Ok(TrustedCommand { hook: c.hook.name().into(), command: c.run.clone(), digests, indirect: indirect(&c.run).is_some() })
}

fn trust(ctx: &mut Ctx, yes: bool, i_understand_indirect: bool) -> Result<ExitCode> {
    if inside_hook() {
        bail!("a hook cannot trust hooks: run `vl hooks trust` yourself");
    }
    let root = ctx.root.clone();
    let hooks = load(&root)?.ok_or_else(|| anyhow!("there is no {VEILHOOKS} file to trust"))?;
    let mut trusted = Vec::new();
    let mut indirect_cmds = Vec::new();
    for c in &hooks.commands {
        let t = trust_command(&root, c)?;
        if t.indirect {
            indirect_cmds.push((c, indirect(&c.run).unwrap_or_default()));
        }
        trusted.push(t);
    }
    if !indirect_cmds.is_empty() && !i_understand_indirect {
        let mut msg = String::from("these commands run a tool that reads repository files it is not given:");
        for (c, files) in &indirect_cmds {
            msg.push_str(&format!("\n  {}: {} (pinned with it: {})", c.hook.name(), safe(&c.run.join(" ")), files.join(", ")));
        }
        msg.push_str(
            "\nTrusting it trusts whatever those files make it run, and files they pull in are not pinned. \
             Pass --i-understand-indirect to trust them anyway",
        );
        bail!(msg);
    }
    println!("{} {VEILHOOKS} (blake3 {}):", bold("Trusting"), hooks.digest);
    for line in String::from_utf8_lossy(&hooks.bytes).lines() {
        println!("  {}", safe(line));
    }
    println!("{}", bold("Pinned files:"));
    for t in &trusted {
        for (p, d) in &t.digests {
            println!("  {:<40} {d}", safe(p));
        }
    }
    if !yes {
        if !std::io::stdin().is_terminal() {
            bail!("stdin is not a terminal: read the above, then pass --yes to trust these hooks");
        }
        eprint!("These commands will run on this device at every commit or push. Trust them? [y/N] ");
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if !matches!(answer.trim(), "y" | "Y" | "yes") {
            println!("Not trusted.");
            return Ok(ExitCode::FAILURE);
        }
    }
    // The file may have changed while we asked: trust what was shown.
    let again = load(&root)?.ok_or_else(|| anyhow!("{VEILHOOKS} disappeared"))?;
    if again.digest != hooks.digest {
        bail!("{VEILHOOKS} changed while you were reviewing it; run `vl hooks trust` again");
    }
    for (t, c) in trusted.iter().zip(&hooks.commands) {
        let pins = pinned_paths(&root, c);
        for (p, d) in &t.digests {
            if path_state(&root, p, pins.get(p).copied().unwrap_or(Pin::Plain)).word() != *d {
                bail!("`{}` changed while you were reviewing it; run `vl hooks trust` again", safe(p));
            }
        }
    }
    save_trust(&root, &TrustRecord { version: 1, veilhooks: hooks.digest.clone(), trusted })?;
    println!("{} {VEILHOOKS} on this device ({})", green("Trusted"), dim(&trust_path(&root).display().to_string()));
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tables_arrays_and_inline_tables() {
        let c = parse(
            r#"
            [pre-commit]
            run = ["sh", "scripts/lint.sh"]
            files = ["scripts/common.sh"]

            [[pre-push]]
            run = ["scripts/check"]
            [[pre-push]]
            run = ["true"]
            commit-msg = { run = ["scripts/msg.sh"] }
            "#,
        );
        // `commit-msg = …` above sits inside the last [[pre-push]] table.
        assert!(c.is_err(), "{c:?}");
        let c = parse(
            "commit-msg = { run = [\"scripts/msg.sh\"] }\n[pre-commit]\nrun = [\"sh\", \"scripts/lint.sh\"]\nfiles = [\"a/b\"]\n[[pre-push]]\nrun = [\"x/y\"]\n[[pre-push]]\nrun = [\"true\"]\n",
        )
        .unwrap();
        assert_eq!(c.len(), 4);
        assert_eq!(c[0].hook, Hook::CommitMsg);
        assert_eq!(c[1].files, vec!["a/b".to_string()]);
        assert_eq!(c[3].run, vec!["true".to_string()]);
    }

    #[test]
    fn refuses_what_is_not_exactly_a_command() {
        for bad in [
            "[pre-commit]\nrun = \"sh lint.sh\"\n",
            "[pre-commit]\nrun = []\n",
            "[pre-commit]\nrun = [\"\"]\n",
            "[pre-commit]\nrun = [1]\n",
            "[pre-commit]\nrun = [\"x\"]\nshell = true\n",
            "[post-commit]\nrun = [\"x\"]\n",
            "pre-commit = 3\n",
            "[pre-commit]\nrun = [\"x\"]\nfiles = [\"../outside\"]\n",
            "[pre-commit]\nrun = [\"x\"]\nfiles = [\"/etc/passwd\"]\n",
            "[pre-commit]\nrun = [\"x\"]\nfiles = [\".veil/local/hooks-trust.json\"]\n",
            "[pre-commit]\nrun = [\"x\"]\nfiles = [\".git/config\"]\n",
            "[pre-commit]\nrun = [\"../outside.sh\"]\n",
            "[pre-commit]\nrun = [\".veil/hooks/pre-commit\"]\n",
            "[pre-commit]\nrun = [\"a//b\"]\n",
            "[pre-commit]\nrun = [\"x\\u0000\"]\n",
            "not toml at all [",
        ] {
            assert!(parse(bad).is_err(), "{bad:?} parsed");
        }
        let many = "[[pre-commit]]\nrun = [\"true\"]\n".repeat(MAX_COMMANDS + 1);
        assert!(parse(&many).is_err());
        let long = format!("[pre-commit]\nrun = [\"{}\"]\n", "a".repeat(MAX_ARG + 1));
        assert!(parse(&long).is_err());
        // Deep nesting is an error, not a stack overflow.
        let deep = format!("[pre-commit]\nrun = {}{}\n", "[".repeat(5000), "]".repeat(5000));
        assert!(parse(&deep).is_err());
    }

    #[test]
    fn repository_paths_are_canonical_and_outside_metadata() {
        for ok in ["a", "scripts/lint.sh", "a.b/c"] {
            assert!(repo_path(ok).is_some(), "{ok}");
        }
        for bad in ["", "/a", "a//b", "./a", "a/./b", "a/../b", "..", ".veil/x", ".VEIL/x", ".git/hooks/x", ".Git", "a\\b"] {
            assert!(repo_path(bad).is_none(), "{bad}");
        }
    }

    fn repo(prefix: &str, path: &str) -> Arg {
        Arg::Repo { prefix: prefix.into(), path: path.into(), whole: None, spelled: path.into() }
    }

    /// Only what pins and copies a path matters, not how it was written.
    fn norm(a: Arg) -> Arg {
        match a {
            Arg::Repo { prefix, path, whole, .. } => Arg::Repo { prefix, spelled: path.clone(), path, whole },
            a => a,
        }
    }

    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn classifies_arguments() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("proj");
        std::fs::create_dir(&root).unwrap();
        let run = v(&["sh", "scripts/lint.sh", "-x", "/abs", "lint", "../up"]);
        assert_eq!(
            classify(&root, &run),
            vec![
                Arg::Program("sh".into()),
                repo("", "scripts/lint.sh"),
                Arg::Literal("-x".into()),
                Arg::Literal("/abs".into()),
                repo("", "lint"),
                Arg::Literal("../up".into()),
            ]
        );
        assert_eq!(classify(&root, &v(&["bin/check"]))[0], repo("", "bin/check"));
        // BUG-701: every spelling of a repository path is that path.
        for a in ["./s/lint.sh", "s//lint.sh", "s/./lint.sh", ".//s/lint.sh/"] {
            assert_eq!(norm(classify(&root, &v(&["sh", a])).remove(1)), repo("", "s/lint.sh"), "{a}");
        }
        assert_eq!(norm(classify(&root, &v(&["sh", "--rcfile=./s/x"])).remove(1)), repo("--rcfile=", "s/x"));
        assert_eq!(
            norm(classify(&root, &v(&["env", "LD_PRELOAD=./lib/x.so", "true"])).remove(1)),
            Arg::Repo { prefix: "LD_PRELOAD=".into(), path: "lib/x.so".into(), whole: Some("LD_PRELOAD=./lib/x.so".into()), spelled: "lib/x.so".into() }
        );
        assert_eq!(norm(classify(&root, &v(&["ruff", "."])).remove(1)), repo("", ""));
        assert_eq!(norm(classify(&root, &v(&["ruff", "./"])).remove(1)), repo("", ""));
        // A path that names nothing is given as written.
        let states = BTreeMap::new();
        let c = Suggested { hook: Hook::PreCommit, run: v(&["curl", "https://example.com//x", "--url=a//b", "./"]), files: Vec::new() };
        assert!(suggested_argv(&root, &c, &states, &mut Vec::new(), &|n| Ok(PathBuf::from(n))).is_err(), "untrusted paths");
        let t = trust_command(&root, &c).unwrap();
        let states = t.digests.iter().map(|(p, d)| (p.clone(), PathState::from_word(d))).collect();
        let (_, argv) = suggested_argv(&root, &c, &states, &mut Vec::new(), &|n| Ok(PathBuf::from(n))).unwrap();
        assert_eq!(argv, vec![OsString::from("https://example.com//x"), "--url=a//b".into(), "./".into()]);
        // In doubt, refused.
        let abs = format!("{}/s/lint.sh", root.display());
        for a in ["s/../s/lint.sh", "../proj/s/lint.sh", abs.as_str(), "/proc/self/cwd/s/lint.sh", "-Is/lib", ".veil/local/x", ".git/hooks/x", "PYTHONPATH=lib:tools"] {
            assert!(matches!(classify(&root, &v(&["sh", a]))[1], Arg::Refused(_)), "{a}: {:?}", classify(&root, &v(&["sh", a])));
        }
    }

    #[test]
    fn launchers_and_code_strings() {
        let tmp = tempfile::tempdir().unwrap();
        let c = |run: &[&str]| Suggested { hook: Hook::PreCommit, run: v(run), files: Vec::new() };
        // BUG-702: a build tool behind a launcher is still a build tool.
        for run in [
            &["nice", "make", "-s"][..],
            &["timeout", "60", "make"],
            &["nohup", "make"],
            &["env", "-i", "A=b", "sudo", "-u", "x", "make"],
            &["vl", "run", "--", "npm", "test"],
            &["stdbuf", "-oL", "cargo", "test"],
        ] {
            assert!(indirect(&v(run)).is_some(), "{run:?}");
        }
        // Code given as text is refused.
        for run in [
            &["sh", "-c", "make lint"][..],
            &["bash", "-o", "pipefail", "-ec", "x"],
            &["nice", "sh", "-c", "x"],
            &["env", "bash", "-lc", "x"],
            &["python3", "-c", "import x"],
            &["python3", "-Ic", "import x"],
            &["node", "-e", "x"],
            &["node", "--eval=x"],
            &["perl", "-lne", "x"],
            &["ruby", "-e", "x"],
            &["xargs", "make"],
            &["env", "-S", "make lint"],
            &["awk", "{print}", "f"],
            &["su", "-c", "x"],
        ] {
            assert!(refusal(tmp.path(), &c(run)).is_some(), "{run:?}");
        }
        for run in [&["sh", "scripts/lint.sh"][..], &["python3", "-W", "error", "x.py"], &["perl", "-Ilib", "x.pl"], &["ruff", "check", "."], &["awk", "-f", "x.awk", "y"]] {
            assert!(refusal(tmp.path(), &c(run)).is_none(), "{run:?}: {:?}", refusal(tmp.path(), &c(run)));
        }
        // An interpreter given the project directory would run its
        // `__main__.py`; a directory it is given is pinned whole.
        assert!(refusal(tmp.path(), &c(&["python3", "."])).is_some());
        assert!(refusal(tmp.path(), &c(&["nice", "node", "./"])).is_some());
        assert_eq!(pinned_paths(tmp.path(), &c(&["python3", "tools"])).get("tools"), Some(&Pin::Tree));
        assert_eq!(pinned_paths(tmp.path(), &c(&["ruff", "src"])).get("src"), Some(&Pin::Plain));
    }

    #[test]
    fn build_tools_are_indirect() {
        assert!(indirect(&v(&["make", "lint"])).unwrap().contains(&"Makefile"));
        assert!(indirect(&v(&["/usr/bin/make"])).is_some());
        assert!(indirect(&v(&["env", "-i", "A=b", "npm", "run", "lint"])).unwrap().contains(&"package.json"));
        assert!(indirect(&v(&["python3", "-m", "lint"])).is_some());
        assert!(indirect(&v(&["sh", "scripts/lint.sh"])).is_none());
        assert!(indirect(&v(&["python3", "scripts/x.py"])).is_none());
        let c = Suggested { hook: Hook::PreCommit, run: v(&["make", "lint"]), files: v(&["extra"]) };
        let p = pinned_paths(Path::new("/nonexistent"), &c);
        for want in ["Makefile", "lint", "extra"] {
            assert!(p.contains_key(want), "{p:?}");
        }
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]

        /// The pre-push input of a public remote never names a cloaked tag
        /// or a snapshot an embargo withholds; it names only tags the push
        /// sends (or tries to), each once, and their targets.
        #[test]
        fn pre_push_input_hides_what_a_public_remote_does_not_get(
            tags in proptest::collection::vec((0u8..5, proptest::option::of(0u8..3), 0u8..8, proptest::option::of(0u8..8)), 0..12),
            withheld in proptest::collection::vec(0u8..8, 0..4),
            public: bool,
        ) {
            use veil_core::push_plan::{PlannedTag, PushPlan, TagAction};
            let id = |n: u8| ObjectId::hash(&[n]);
            let actions = [TagAction::Create, TagAction::Update, TagAction::Unchanged, TagAction::Rejected, TagAction::Skipped];
            let plan = PushPlan {
                public,
                tags: tags
                    .iter()
                    .enumerate()
                    .map(|(i, (a, cloak, target, remote))| PlannedTag {
                        name: format!("{}tag{i}", if cloak.is_some() { "cloaked" } else { "plain" }),
                        action: actions[*a as usize],
                        target: id(*target),
                        remote: remote.map(id),
                        reason: None,
                        cloak: cloak.map(|s| format!("scope{s}")),
                    })
                    .collect(),
                withheld_snapshots: withheld.iter().map(|w| (id(*w), "e1".to_string())).collect(),
                ..Default::default()
            };
            let lines = plan_lines(&plan);
            let text = lines.join("\n");
            for w in &withheld {
                let hex = id(*w).hex();
                let targeted = lines.iter().any(|l| l.split(' ').nth(1) == Some(hex.as_str()));
                proptest::prop_assert!(!targeted, "withheld {hex} named: {text}");
            }
            if public {
                proptest::prop_assert!(!text.contains("cloaked"), "{text}");
            }
            for l in &lines {
                let f: Vec<&str> = l.split(' ').collect();
                proptest::prop_assert_eq!(f.len(), 3);
                let t = plan.tags.iter().find(|t| t.name == f[0]).unwrap();
                proptest::prop_assert!(matches!(t.action, TagAction::Create | TagAction::Update | TagAction::Rejected));
                proptest::prop_assert_eq!(f[1], t.target.hex());
                proptest::prop_assert_eq!(lines.iter().filter(|x| x.starts_with(&format!("{} ", f[0]))).count(), 1);
            }
        }
    }

    /// A project for the argv property: a script, a directory an
    /// interpreter runs, a Makefile, `Cargo.toml`, `package.json`.
    fn argv_project() -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("proj");
        for (p, c) in [
            ("s/lint.sh", "echo lint\n"),
            ("tools/__main__.py", "print(1)\n"),
            ("tools/lib/helper.py", "X = 1\n"),
            ("Makefile", "all:\n\ttrue\n"),
            ("Cargo.toml", "[package]\n"),
            ("package.json", "{}\n"),
            ("pyproject.toml", "\n"),
        ] {
            std::fs::create_dir_all(root.join(p).parent().unwrap()).unwrap();
            std::fs::write(root.join(p), c).unwrap();
        }
        std::fs::create_dir(root.join(VEIL_DIR)).unwrap();
        (tmp, root)
    }

    /// How the argv property's generated arguments name repository files.
    const SPELLINGS: &[(&str, Option<&str>)] = &[
        ("s/lint.sh", Some("s/lint.sh")),
        ("./s/lint.sh", Some("s/lint.sh")),
        ("s//lint.sh", Some("s/lint.sh")),
        ("s/./lint.sh", Some("s/lint.sh")),
        ("s/lint.sh/", Some("s/lint.sh")),
        ("x/../s/lint.sh", Some("s/lint.sh")),
        ("../proj/s/lint.sh", Some("s/lint.sh")),
        ("--rcfile=./s/lint.sh", Some("s/lint.sh")),
        ("--rcfile=s/lint.sh", Some("s/lint.sh")),
        ("VAR=./s/lint.sh", Some("s/lint.sh")),
        ("LD_PRELOAD=s//lint.sh", Some("s/lint.sh")),
        ("-Is/lint.sh", Some("s/lint.sh")),
        ("PYTHONPATH=x:./s", Some("s")),
        ("/proc/self/cwd/s/lint.sh", Some("s/lint.sh")),
        ("ABS/s/lint.sh", Some("s/lint.sh")),
        ("Makefile", Some("Makefile")),
        ("./Makefile", Some("Makefile")),
        ("--file=Makefile", Some("Makefile")),
        ("tools", Some("tools")),
        ("./tools/", Some("tools")),
        ("tools/__main__.py", Some("tools/__main__.py")),
        (".", None),
        ("./", None),
        ("lint", None),
        ("-x", None),
        ("--check", None),
        ("make lint", None),
        ("import x", None),
    ];

    const PREFIXES: &[&[&str]] = &[
        &[],
        &["nice"],
        &["nice", "-n", "5"],
        &["timeout", "60"],
        &["env", "A=b"],
        &["env", "-i"],
        &["nohup"],
        &["sudo", "-u", "x"],
        &["xargs"],
        &["vl", "run", "--"],
        &["stdbuf", "-oL"],
        &["flock", "/tmp/l"],
    ];

    const PROGRAMS: &[&str] = &["sh", "bash", "python3", "node", "perl", "make", "cargo", "npm", "ruff", "true", "s/lint.sh", "/usr/bin/env"];
    const FLAGS: &[&str] = &["-c", "-e", "-x", "-m", "-Ic", "-ec", "-s"];

    fn is_interpreter(a: &str) -> bool {
        runs_directories(base_name(a))
    }

    /// Does `flag` right after `program` make it run code given as text?
    fn code_flag(program: &str, flag: &str) -> bool {
        let b = base_name(program);
        match b {
            "sh" | "bash" => flag.starts_with('-') && !flag.starts_with("--") && flag.contains('c'),
            "python3" => matches!(flag, "-c" | "-Ic"),
            "node" | "perl" => matches!(flag, "-e" | "-ec"),
            _ => false,
        }
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(512))]

        /// BUG-700/701/702: over generated argv shapes (launchers, programs,
        /// options, every spelling of a repository path), any repository
        /// file a trusted hook could execute or read as code is pinned, or
        /// trust refuses the command; and the argv a trusted command runs
        /// with never names a live repository file (only private copies of
        /// the trusted bytes), nor a directory an interpreter would run.
        #[test]
        fn every_repository_file_a_hook_runs_is_pinned_or_refused(
            prefix in 0..PREFIXES.len(),
            program in 0..PROGRAMS.len(),
            flag in proptest::option::of(0..FLAGS.len()),
            args in proptest::collection::vec(0..SPELLINGS.len(), 0..4),
        ) {
            let (_tmp, root) = argv_project();
            let canon_root = root.canonicalize().unwrap();
            let mut run: Vec<String> = PREFIXES[prefix].iter().map(|s| s.to_string()).collect();
            let prog = PROGRAMS[program];
            let launched = !run.is_empty();
            run.push(prog.to_string());
            if let Some(f) = flag {
                run.push(FLAGS[f].to_string());
            }
            for &a in &args {
                run.push(SPELLINGS[a].0.replace("ABS", &root.display().to_string()));
            }
            let c = Suggested { hook: Hook::PreCommit, run: run.clone(), files: Vec::new() };
            let interp = run.iter().any(|a| is_interpreter(a));
            let must_refuse = flag.is_some_and(|f| code_flag(prog, FLAGS[f]))
                || PREFIXES[prefix].contains(&"xargs")
                || (interp && args.iter().any(|&a| SPELLINGS[a].1.is_none() && SPELLINGS[a].0.starts_with('.')));
            let Ok(t) = trust_command(&root, &c) else { return Ok(()) };
            proptest::prop_assert!(!must_refuse, "trusted {run:?}");
            // Every repository file named, in any spelling, is pinned.
            let mut want: Vec<(&str, bool)> = args.iter().filter_map(|&a| SPELLINGS[a].1).map(|p| (p, interp)).collect();
            if prog.contains('/') && !prog.starts_with('/') && !launched {
                want.push((prog, false));
            }
            for (p, tree) in &want {
                let d = t.digests.get(*p);
                proptest::prop_assert!(d.is_some(), "{run:?}: `{p}` not pinned: {:?}", t.digests);
                let s = PathState::from_word(d.unwrap());
                if *tree || root.join(p).is_file() {
                    proptest::prop_assert!(matches!(s, PathState::File(_) | PathState::Tree(_)), "{run:?}: `{p}` pinned as {s:?}");
                }
            }
            // A build tool behind any launcher pins its files.
            for (tool, file) in [("make", "Makefile"), ("cargo", "Cargo.toml"), ("npm", "package.json")] {
                if prog == tool || (launched && run.iter().any(|a| a == tool)) {
                    proptest::prop_assert!(t.indirect && t.digests.contains_key(file), "{run:?}: {file} not pinned");
                }
            }
            if base_name(prog).starts_with("python") && flag.is_some_and(|f| FLAGS[f] == "-m") {
                proptest::prop_assert!(t.indirect && t.digests.contains_key("pyproject.toml"), "{run:?}");
            }
            // What would run: copies only.
            let states: BTreeMap<String, PathState> = t.digests.iter().map(|(p, d)| (p.clone(), PathState::from_word(d))).collect();
            let mut copies = Vec::new();
            let built = suggested_argv(&root, &c, &states, &mut copies, &|n| Ok(PathBuf::from("/usr/bin").join(base_name(n))));
            let (program_path, argv) = built.map_err(|e| proptest::test_runner::TestCaseError::fail(format!("{run:?}: {e:#}")))?;
            let run_dir = canon_root.join(VEIL_DIR);
            for o in std::iter::once(program_path.into_os_string()).chain(argv) {
                let o = o.into_string().unwrap();
                let mut cands = vec![o.clone()];
                if let Some((_, v)) = o.split_once('=') {
                    cands.push(v.to_string());
                }
                for cand in cands {
                    let full = if cand.starts_with('/') { PathBuf::from(&cand) } else { root.join(&cand) };
                    let Ok(real) = full.canonicalize() else { continue };
                    if !real.starts_with(&canon_root) || real.starts_with(&run_dir) {
                        continue;
                    }
                    proptest::prop_assert!(
                        !real.is_file() && !(interp && real != canon_root),
                        "{run:?} runs with the live `{}`", real.display()
                    );
                }
            }
            for c in copies {
                remove_copy(&c);
            }
        }
    }

    #[test]
    fn path_states_round_trip() {
        for s in [PathState::File("ab".repeat(32)), PathState::Absent, PathState::Dir, PathState::Tree("cd".repeat(32))] {
            assert_eq!(PathState::from_word(&s.word()), s);
        }
        assert_eq!(PathState::from_word("zz"), PathState::Other);
    }
}
