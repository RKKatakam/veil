//! Conformance tests: the working copy and everyday commands.
//!
//! Scenarios from Git's test suite (t0xxx basics, t15xx revision syntax,
//! t2xxx checkout/switch/restore/worktree, t3xxx ls-files/branch/add/rm/mv/
//! stash, t7xxx commit/status/reset/clean/tag) and from Jujutsu's CLI and
//! library tests, translated to Veil's model (no index, automatic
//! snapshots, change ids, an operation log, virtual workspaces, visibility
//! tiers). Each test names its source in a one-line comment; coverage is
//! documented in `docs/conformance/worktree.md`.
//!
//! Tests marked `#[ignore = "BUG-2NN: …"]` reproduce findings recorded in
//! `docs/BUGS.md` ("Conformance findings: working copy and everyday
//! commands"); they assert the documented or expected behaviour and fail
//! today.

#![allow(dead_code)]

mod add_rm_mv;
mod checkout;
mod clean;
mod commit;
mod files;
mod filesystem;
mod ignores;
mod init;
mod restore;
mod revisions;
mod snapshot;
mod stash;
mod status;
mod tags;
mod undo;
mod visibility;
mod workspaces;

use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

/// An isolated test environment: a temporary directory holding every
/// user's `VEIL_HOME` and every project.
pub struct Env {
    _tmp: tempfile::TempDir,
    pub root: PathBuf,
}

impl Env {
    pub fn new() -> Env {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        std::fs::create_dir_all(root.join("tmp")).unwrap();
        Env { _tmp: tmp, root }
    }

    pub fn dir(&self, name: &str) -> PathBuf {
        let d = self.root.join(name);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A `vl` command run as `user` in `cwd`.
    pub fn cmd_as<S: AsRef<OsStr>>(&self, user: &str, cwd: &Path, args: &[S]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_vl"));
        c.args(args)
            .current_dir(cwd)
            .env("VEIL_HOME", self.root.join(format!("home-{user}")))
            .env("VEIL_USER", user)
            .env("NO_COLOR", "1")
            .env("TMPDIR", self.root.join("tmp"))
            .env_remove("VEIL_FS_FOLDING")
            .stdin(Stdio::null());
        c
    }

    pub fn run_as<S: AsRef<OsStr>>(&self, user: &str, cwd: &Path, args: &[S]) -> Output {
        self.cmd_as(user, cwd, args).output().unwrap()
    }

    /// A fresh repository (`vl init`) owned by alice.
    pub fn repo(&self, name: &str) -> R<'_> {
        let r = self.bare_dir(name);
        r.ok(&["init"]);
        r
    }

    /// A directory for alice that is not a repository yet.
    pub fn bare_dir(&self, name: &str) -> R<'_> {
        R {
            env: self,
            dir: self.dir(name),
            user: "alice".into(),
        }
    }

    /// Bob's view of an existing directory (another identity).
    pub fn as_user<'a>(&'a self, user: &str, dir: &Path) -> R<'a> {
        R {
            env: self,
            dir: dir.to_path_buf(),
            user: user.into(),
        }
    }
}

/// A working copy driven as one user.
pub struct R<'a> {
    pub env: &'a Env,
    pub dir: PathBuf,
    pub user: String,
}

pub fn text(out: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr))
}

pub fn stdout_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Did the process end normally (an exit code, not a signal or a panic)?
pub fn clean_exit(out: &Output) -> bool {
    out.status.code().is_some_and(|c| c != 101) && !text(out).contains("panicked")
}

/// One line of `vl files`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileLine {
    pub vis: String,
    pub size: u64,
    pub path: String,
    pub exec: bool,
    pub redacted: bool,
}

impl<'a> R<'a> {
    pub fn cmd<S: AsRef<OsStr>>(&self, args: &[S]) -> Command {
        self.env.cmd_as(&self.user, &self.dir, args)
    }

    pub fn run<S: AsRef<OsStr>>(&self, args: &[S]) -> Output {
        self.env.run_as(&self.user, &self.dir, args)
    }

    /// Run with `input` on stdin.
    pub fn run_stdin<S: AsRef<OsStr>>(&self, args: &[S], input: &[u8]) -> Output {
        use std::io::Write;
        let mut c = self
            .cmd(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        c.stdin.take().unwrap().write_all(input).unwrap();
        c.wait_with_output().unwrap()
    }

    /// `vl ws write WS PATH` with `data`, which must succeed.
    pub fn ws_write(&self, ws: &str, path: &str, data: &str) -> String {
        let out = self.run_stdin(&["ws", "write", ws, path], data.as_bytes());
        assert!(out.status.success(), "vl ws write {ws} {path} failed:\n{}", text(&out));
        text(&out)
    }

    /// Run in a subdirectory of the working copy.
    pub fn run_in<S: AsRef<OsStr>>(&self, sub: &str, args: &[S]) -> Output {
        self.env.run_as(&self.user, &self.dir.join(sub), args)
    }

    /// stdout + stderr of a successful run.
    pub fn ok<S: AsRef<OsStr> + std::fmt::Debug>(&self, args: &[S]) -> String {
        let out = self.run(args);
        let t = text(&out);
        assert!(out.status.success(), "vl {args:?} failed:\n{t}");
        assert!(!t.contains("panicked"), "vl {args:?} panicked:\n{t}");
        t
    }

    /// stdout of a successful run.
    pub fn out<S: AsRef<OsStr> + std::fmt::Debug>(&self, args: &[S]) -> String {
        let out = self.run(args);
        assert!(out.status.success(), "vl {args:?} failed:\n{}", text(&out));
        stdout_of(&out)
    }

    /// stdout + stderr of a run that must fail cleanly (exit 1, no panic).
    pub fn fails<S: AsRef<OsStr> + std::fmt::Debug>(&self, args: &[S]) -> String {
        let out = self.run(args);
        let t = text(&out);
        assert!(!out.status.success(), "vl {args:?} unexpectedly succeeded:\n{t}");
        assert!(clean_exit(&out), "vl {args:?} crashed:\n{t}");
        t
    }

    pub fn path(&self, rel: &str) -> PathBuf {
        self.dir.join(rel)
    }

    pub fn write(&self, rel: &str, content: impl AsRef<[u8]>) {
        let p = self.path(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, content).unwrap();
    }

    pub fn read(&self, rel: &str) -> String {
        std::fs::read_to_string(self.path(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
    }

    pub fn read_bytes(&self, rel: &str) -> Vec<u8> {
        std::fs::read(self.path(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
    }

    pub fn exists(&self, rel: &str) -> bool {
        self.path(rel).symlink_metadata().is_ok()
    }

    pub fn rm(&self, rel: &str) {
        let p = self.path(rel);
        if p.is_dir() {
            std::fs::remove_dir_all(p).unwrap();
        } else {
            std::fs::remove_file(p).unwrap();
        }
    }

    pub fn mkdir(&self, rel: &str) {
        std::fs::create_dir_all(self.path(rel)).unwrap();
    }

    #[cfg(unix)]
    pub fn chmod(&self, rel: &str, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(self.path(rel), std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[cfg(unix)]
    pub fn is_exec(&self, rel: &str) -> bool {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(self.path(rel)).unwrap().permissions().mode() & 0o111 != 0
    }

    /// Every file and directory on disk, relative, sorted, without `.veil`.
    pub fn disk(&self) -> Vec<String> {
        fn go(base: &Path, d: &Path, out: &mut Vec<String>) {
            for e in std::fs::read_dir(d).unwrap() {
                let e = e.unwrap();
                let p = e.path();
                let rel = p.strip_prefix(base).unwrap().to_string_lossy().into_owned();
                if rel == ".veil" {
                    continue;
                }
                let ft = e.file_type().unwrap();
                if ft.is_dir() {
                    out.push(format!("{rel}/"));
                    go(base, &p, out);
                } else {
                    out.push(rel);
                }
            }
        }
        let mut v = Vec::new();
        go(&self.dir, &self.dir, &mut v);
        v.sort();
        v
    }

    /// Files on disk only (no directories), without `.veilpolicy`.
    pub fn disk_files(&self) -> Vec<String> {
        self.disk()
            .into_iter()
            .filter(|p| !p.ends_with('/') && p != ".veilpolicy")
            .collect()
    }

    /// `vl files -r REV`, parsed.
    pub fn files(&self, rev: &str) -> Vec<FileLine> {
        self.out(&["files", "-r", rev]).lines().map(parse_file_line).collect()
    }

    /// Paths of `vl files -r REV`, without `.veilpolicy`.
    pub fn paths(&self, rev: &str) -> Vec<String> {
        self.files(rev)
            .into_iter()
            .map(|f| f.path)
            .filter(|p| p != ".veilpolicy")
            .collect()
    }

    /// `vl cat PATH -r REV`, which must succeed.
    pub fn cat(&self, path: &str, rev: &str) -> String {
        self.out(&["cat", "-r", rev, "--", path])
    }

    /// `vl status` (stdout + stderr).
    pub fn status(&self) -> String {
        self.ok(&["status"])
    }

    /// The `X path` lines of `vl status`'s "Working copy changes" section.
    pub fn changes(&self) -> Vec<String> {
        let st = self.out(&["status"]);
        let mut out = Vec::new();
        let mut on = false;
        for l in st.lines() {
            if l == "Working copy changes:" {
                on = true;
                continue;
            }
            if on {
                if l.len() > 2 && matches!(&l[..2], "A " | "M " | "D ") {
                    out.push(l.to_string());
                } else {
                    break;
                }
            }
        }
        out.retain(|l| l != "A .veilpolicy");
        out
    }

    /// Full change id of REV (from `vl show`).
    pub fn change(&self, rev: &str) -> String {
        self.show_field(rev, "Change ID")
    }

    /// Full snapshot id of REV (from `vl show`).
    pub fn snap(&self, rev: &str) -> String {
        self.show_field(rev, "Snapshot")
    }

    fn show_field(&self, rev: &str, field: &str) -> String {
        let out = self.out(&["--no-snapshot", "show", "--stat", "--", rev]);
        out.lines()
            .find_map(|l| {
                let (k, v) = l.split_once(':')?;
                (k.trim() == field).then(|| v.trim().to_string())
            })
            .unwrap_or_else(|| panic!("no {field} in `vl show {rev}`:\n{out}"))
    }

    /// The description of REV, as `vl show` prints it (indented lines).
    pub fn description(&self, rev: &str) -> String {
        let out = self.out(&["--no-snapshot", "show", "--stat", "--", rev]);
        let mut lines = out.lines().skip_while(|l| !l.is_empty());
        lines.next();
        lines
            .take_while(|l| l.starts_with("    ") || l.is_empty())
            .map(|l| l.strip_prefix("    ").unwrap_or(l))
            .collect::<Vec<_>>()
            .join("\n")
            .trim_end()
            .to_string()
    }

    /// The number of operations in the op log.
    pub fn op_count(&self) -> usize {
        self.out(&["--no-snapshot", "op", "log", "-n", "100000"]).lines().count()
    }

    /// `vl tag list` as `name -> change id prefix` pairs (local tags only).
    pub fn tags(&self) -> Vec<(String, String)> {
        self.out(&["--no-snapshot", "tag", "list"])
            .lines()
            .filter_map(|l| {
                let (name, rest) = l.split_once(": ")?;
                let name = name.split(" [").next().unwrap().to_string();
                Some((name, rest.split_whitespace().next()?.to_string()))
            })
            .collect()
    }

    /// Commit with a message; returns the committed change id.
    pub fn commit(&self, msg: &str) -> String {
        self.ok(&["commit", "-m", msg]);
        self.change("@-")
    }
}

pub fn parse_file_line(l: &str) -> FileLine {
    let (vis, rest) = l.split_once(' ').unwrap_or_else(|| panic!("bad `vl files` line {l:?}"));
    let rest = rest.trim_start();
    let (size, rest) = rest.split_once("  ").unwrap_or_else(|| panic!("bad `vl files` line {l:?}"));
    let mut path = rest.to_string();
    let mut exec = false;
    let mut redacted = false;
    if let Some(p) = path.strip_suffix(" (redacted)") {
        path = p.to_string();
        redacted = true;
    } else if let Some(p) = path.strip_suffix(" *") {
        path = p.to_string();
        exec = true;
    }
    FileLine {
        vis: vis.to_string(),
        size: size.trim().parse().unwrap_or_else(|_| panic!("bad size in {l:?}")),
        path,
        exec,
        redacted,
    }
}

/// Text that must never appear in output or on a public surface.
pub const SECRET_PLAN: &str = "TOP-SECRET-merger-with-initech";
/// A dotenv value the scanner recognises.
pub const DOTENV: &str = "DB_URL=postgres://app:Xk29vLq8sPz@db.internal/prod\n";
/// A public-file credential the scanner quarantines.
pub const LEAKY: &str = "const key = 'AKIAIOSFODNN7EXAMPLE';\n";

/// Every file under `dir`, recursively, concatenated (to grep a whole
/// repository or remote for plaintext).
pub fn all_bytes(dir: &Path) -> Vec<u8> {
    let mut out = Vec::new();
    fn go(d: &Path, out: &mut Vec<u8>) {
        let Ok(rd) = std::fs::read_dir(d) else { return };
        for e in rd.flatten() {
            let p = e.path();
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_dir() {
                go(&p, out);
            } else if ft.is_file() {
                if let Ok(b) = std::fs::read(&p) {
                    out.extend_from_slice(&b);
                }
            }
        }
    }
    go(dir, &mut out);
    out
}

pub fn contains_bytes(hay: &[u8], needle: &str) -> bool {
    let n = needle.as_bytes();
    hay.windows(n.len()).any(|w| w == n)
}
