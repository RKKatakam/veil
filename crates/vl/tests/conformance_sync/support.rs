//! Helpers for the remotes, storage and Git-interop conformance suite: run
//! the real `vl` binary with an isolated `VEIL_HOME` per user, drive plain
//! `git`, stand in for `ssh` with a local `sftp-server`, and look inside
//! repositories (every object's bytes, metadata files) for leaks.

#![allow(dead_code)]

use std::{
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

use veil_core::{DiskBackend, Repo, StorageBackend};

pub struct Env {
    pub tmp: tempfile::TempDir,
    pub root: PathBuf,
    /// `VEIL_SSH` for every `vl` this environment runs (a stand-in).
    pub ssh: Option<String>,
    /// Extra environment variables for every `vl`.
    pub envs: Vec<(String, String)>,
}

impl Env {
    pub fn new() -> Env {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        Env {
            tmp,
            root,
            ssh: None,
            envs: Vec::new(),
        }
    }

    /// An environment whose `ssh` is a script serving the local
    /// `sftp-server` from `<root>/sshhome` (the "login directory"), logging
    /// its arguments to `<root>/ssh.log`. `None` (test skipped) without an
    /// `sftp-server`.
    pub fn with_sftp() -> Option<Env> {
        Self::with_sftp_wrapper("")
    }

    /// Like [`Env::with_sftp`], with `filter` spliced into the pipeline
    /// around the server, for example `| head -c 4000` (the connection
    /// drops after 4,000 bytes from the server).
    pub fn with_sftp_wrapper(filter: &str) -> Option<Env> {
        sftp_server()?;
        let mut env = Env::new();
        env.ssh = Some(env.sftp_script("fake-ssh", filter));
        Some(env)
    }

    /// Write a stand-in `ssh` script `<root>/<name>` (see [`Env::with_sftp`])
    /// and return its path, for `VEIL_SSH`.
    pub fn sftp_script(&self, name: &str, filter: &str) -> String {
        let server = sftp_server().expect("sftp-server");
        let home = self.dir("sshhome");
        let script = self.root.join(name);
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{log}'\ncd '{home}' || exit 255\nexec sh -c '{server} {filter}'\n",
                log = self.root.join("ssh.log").display(),
                home = home.display(),
                server = server.display(),
            ),
        )
        .unwrap();
        set_mode(&script, 0o755);
        script.display().to_string()
    }

    pub fn ssh_log(&self) -> String {
        std::fs::read_to_string(self.root.join("ssh.log")).unwrap_or_default()
    }

    pub fn dir(&self, name: &str) -> PathBuf {
        let d = self.root.join(name);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    pub fn home(&self, user: &str) -> PathBuf {
        self.root.join(format!("home-{user}"))
    }

    pub fn cmd(&self, user: &str, cwd: &Path, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_vl"));
        c.args(args)
            .current_dir(cwd)
            .env("VEIL_HOME", self.home(user))
            .env("VEIL_USER", user)
            .env("NO_COLOR", "1")
            .env("TMPDIR", self.dir("tmp"))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .stdin(Stdio::null());
        if let Some(ssh) = &self.ssh {
            c.env("VEIL_SSH", ssh);
        }
        c.envs(self.envs.iter().map(|(k, v)| (k.as_str(), v.as_str())));
        c
    }

    pub fn vl(&self, user: &str, cwd: &Path, args: &[&str]) -> Output {
        self.cmd(user, cwd, args).output().unwrap()
    }

    pub fn spawn(&self, user: &str, cwd: &Path, args: &[&str]) -> Child {
        self.cmd(user, cwd, args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    }

    /// stdout + stderr; asserts success.
    pub fn ok(&self, user: &str, cwd: &Path, args: &[&str]) -> String {
        let out = self.vl(user, cwd, args);
        let t = text(&out);
        assert!(out.status.success(), "vl {args:?} failed:\n{t}");
        assert!(!t.contains("panicked"), "vl {args:?} panicked:\n{t}");
        t
    }

    /// stdout + stderr; asserts a clean failure (non-zero exit, no panic).
    pub fn fails(&self, user: &str, cwd: &Path, args: &[&str]) -> String {
        let out = self.vl(user, cwd, args);
        let t = text(&out);
        assert!(
            !out.status.success(),
            "vl {args:?} unexpectedly succeeded:\n{t}"
        );
        assert!(exited_cleanly(&out), "vl {args:?} crashed:\n{t}");
        t
    }

    /// Exit code (asserting no panic) and the combined output.
    pub fn code(&self, user: &str, cwd: &Path, args: &[&str]) -> (i32, String) {
        let out = self.vl(user, cwd, args);
        let t = text(&out);
        assert!(exited_cleanly(&out), "vl {args:?} crashed:\n{t}");
        (out.status.code().unwrap(), t)
    }

    pub fn stdout(&self, user: &str, cwd: &Path, args: &[&str]) -> String {
        let out = self.vl(user, cwd, args);
        assert!(out.status.success(), "vl {args:?} failed: {}", text(&out));
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// A fresh project with one commit (the files given) tagged `main`.
    pub fn project(&self, user: &str, name: &str, files: &[(&str, &str)]) -> PathBuf {
        let proj = self.dir(name);
        self.ok(user, &proj, &["init"]);
        for (p, c) in files {
            write(&proj, p, c);
        }
        self.ok(user, &proj, &["commit", "-m", "initial"]);
        self.ok(user, &proj, &["tag", "set", "main", "-r", "@-"]);
        proj
    }

    /// `project` plus a team remote `origin` at `<root>/<hub>`, pushed.
    pub fn project_with_hub(
        &self,
        user: &str,
        name: &str,
        hub: &str,
        files: &[(&str, &str)],
    ) -> (PathBuf, PathBuf) {
        let proj = self.project(user, name, files);
        let hub = self.path(hub);
        self.ok(
            user,
            &proj,
            &["remote", "add", "origin", hub.to_str().unwrap()],
        );
        self.ok(user, &proj, &["push"]);
        (proj, hub)
    }

    /// Commit `files` in `dir` and move `main` there (commit moves tags at
    /// the parent, so `main` follows when `@-` was `main`).
    pub fn commit(&self, user: &str, dir: &Path, msg: &str, files: &[(&str, &str)]) {
        for (p, c) in files {
            write(dir, p, c);
        }
        self.ok(user, dir, &["commit", "-m", msg]);
    }

    /// Clone `src` to `<root>/<dest>` as `user`.
    pub fn clone(&self, user: &str, src: &Path, dest: &str) -> PathBuf {
        let d = self.path(dest);
        self.ok(
            user,
            &self.root,
            &["clone", src.to_str().unwrap(), d.to_str().unwrap()],
        );
        d
    }

    /// The public key (`veil1…`) of `user`, creating the identity if needed.
    pub fn pubkey(&self, user: &str) -> String {
        let out = self.ok(user, &self.root, &["identity", "show"]);
        out.split_whitespace()
            .find(|w| w.starts_with("veil1"))
            .expect("public key in `identity show`")
            .to_string()
    }

    /// The target id (short) of `tag` in `vl tag list`, if any.
    pub fn tag_target(&self, user: &str, dir: &Path, tag: &str) -> Option<String> {
        let list = self.stdout(user, dir, &["--no-snapshot", "tag", "list"]);
        list.lines().find_map(|l| {
            let (name, rest) = l.split_once(": ")?;
            (name == tag).then(|| rest.split_whitespace().nth(1).unwrap_or("").to_string())
        })
    }

    pub fn tags(&self, user: &str, dir: &Path) -> Vec<String> {
        self.stdout(user, dir, &["--no-snapshot", "tag", "list"])
            .lines()
            .filter_map(|l| l.split_once(": ").map(|(n, _)| n.to_string()))
            .collect()
    }
}

pub fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// Did the process end normally (exit code, no signal, no Rust panic)?
pub fn exited_cleanly(out: &Output) -> bool {
    out.status.code().is_some_and(|c| c != 101) && !text(out).contains("panicked")
}

pub fn write(dir: &Path, rel: &str, content: &str) {
    write_bytes(dir, rel, content.as_bytes());
}

pub fn write_bytes(dir: &Path, rel: &str, content: &[u8]) {
    let p = dir.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, content).unwrap();
}

pub fn read(dir: &Path, rel: &str) -> String {
    std::fs::read_to_string(dir.join(rel)).unwrap()
}

pub fn set_mode(p: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
}

pub fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).unwrap().permissions().mode() & 0o111 != 0
}

pub fn wait_for(timeout: Duration, mut f: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    false
}

/// Deterministic pseudo-random bytes (xorshift), incompressible enough
/// to defeat zstd and deltas.
pub fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        out.extend_from_slice(&x.to_le_bytes());
    }
    out.truncate(len);
    out
}

// ---- looking inside repositories ------------------------------------------

/// Every file under `dir` (recursive), relative, sorted.
pub fn listing(dir: &Path) -> Vec<String> {
    fn go(base: &Path, d: &Path, out: &mut Vec<String>) {
        let Ok(rd) = std::fs::read_dir(d) else { return };
        for e in rd {
            let e = e.unwrap();
            let p = e.path();
            if e.file_type().unwrap().is_dir() {
                go(base, &p, out);
            } else {
                out.push(p.strip_prefix(base).unwrap().to_string_lossy().into_owned());
            }
        }
    }
    let mut out = Vec::new();
    go(dir, dir, &mut out);
    out.sort();
    out
}

/// Open the Veil repository at `dir` in-process, without an identity.
pub fn open_repo(dir: &Path) -> Repo {
    let backend: Arc<dyn StorageBackend> = Arc::new(DiskBackend::new(dir));
    Repo::open(backend, None, "inspector").unwrap()
}

/// The decoded bytes of every object in the repository at `dir` (packed
/// objects decompressed), concatenated, followed by the raw bytes of every
/// file under `.veil/` that is not an object (metadata, ops, key rings).
/// What a reader of that directory can learn.
pub fn everything_in(dir: &Path) -> Vec<u8> {
    let repo = open_repo(dir);
    let mut all = Vec::new();
    for id in repo.store().list_objects().unwrap() {
        if let Ok(raw) = repo.store().get_raw(&id) {
            all.extend_from_slice(&raw);
        }
    }
    let veil = dir.join(".veil");
    for f in listing(&veil) {
        if !f.starts_with("objects/") {
            all.extend(std::fs::read(veil.join(&f)).unwrap_or_default());
        }
    }
    all
}

pub fn contains(hay: &[u8], needle: &str) -> bool {
    let n = needle.as_bytes();
    hay.windows(n.len()).any(|w| w == n)
}

/// Assert that nothing in the repository at `dir` contains `needle`.
pub fn assert_absent(dir: &Path, needle: &str, what: &str) {
    assert!(
        !contains(&everything_in(dir), needle),
        "{what}: '{needle}' found in {}",
        dir.display()
    );
}

/// Names of the key rings stored in a repository's `.veil/meta/keyrings`.
pub fn keyrings(dir: &Path) -> Vec<String> {
    listing(&dir.join(".veil/meta/keyrings"))
}

/// Loose object files of the repository at `dir`.
pub fn loose_objects(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir.join(".veil/objects")) else {
        return out;
    };
    for d in rd {
        let d = d.unwrap();
        if d.file_name().len() == 2 && d.file_type().unwrap().is_dir() {
            for f in std::fs::read_dir(d.path()).unwrap() {
                out.push(f.unwrap().path());
            }
        }
    }
    out.sort();
    out
}

pub fn packs(dir: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(dir.join(".veil/objects/pack"))
        .map(|rd| {
            rd.flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x == "pack"))
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out
}

/// The loose object file whose content contains `needle` (plaintext
/// blobs are stored raw when loose).
pub fn loose_object_containing(dir: &Path, needle: &str) -> Option<PathBuf> {
    loose_objects(dir)
        .into_iter()
        .find(|p| contains(&std::fs::read(p).unwrap(), needle))
}

/// Flip one bit of the byte at `pos` (negative: from the end).
pub fn flip_byte(p: &Path, pos: isize) {
    let mut b = std::fs::read(p).unwrap();
    let i = if pos < 0 {
        (b.len() as isize + pos) as usize
    } else {
        pos as usize
    };
    b[i] ^= 0x01;
    std::fs::write(p, b).unwrap();
}

pub fn truncate_file(p: &Path, len: u64) {
    let f = std::fs::OpenOptions::new().write(true).open(p).unwrap();
    f.set_len(len).unwrap();
}

/// A copy of a directory tree (no special files).
pub fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let dst = to.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_dir(&e.path(), &dst);
        } else {
            std::fs::copy(e.path(), &dst).unwrap();
        }
    }
}

pub fn repo_format(dir: &Path) -> u64 {
    let v: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join(".veil/repo.json")).unwrap()).unwrap();
    v["format"].as_u64().unwrap()
}

pub fn op_count(dir: &Path) -> usize {
    std::fs::read_dir(dir.join(".veil/ops"))
        .map(|d| d.count())
        .unwrap_or(0)
}

pub fn fixture(format: u32) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(format!("../veil-core/tests/fixtures/format-{format}"))
}

// ---- git -------------------------------------------------------------------

pub fn git_cmd(dir: &Path) -> Command {
    let mut c = Command::new("git");
    c.current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "Gita Hub")
        .env("GIT_AUTHOR_EMAIL", "gita@example.com")
        .env("GIT_COMMITTER_NAME", "Gita Hub")
        .env("GIT_COMMITTER_EMAIL", "gita@example.com")
        .args([
            "-c",
            "init.defaultBranch=main",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.quotePath=false",
        ]);
    c
}

/// Run git; assert success; trimmed stdout.
pub fn git(dir: &Path, args: &[&str]) -> String {
    let out = git_cmd(dir).args(args).output().unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

pub fn git_env(dir: &Path, envs: &[(&str, &str)], args: &[&str]) -> String {
    let out = git_cmd(dir)
        .envs(envs.iter().copied())
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

pub fn git_ok(dir: &Path, args: &[&str]) -> bool {
    git_cmd(dir).args(args).output().unwrap().status.success()
}

/// A bare repository `<root>/<name>` and a working clone `<root>/<name>-wc`
/// with one commit on `main` holding `files`, pushed.
pub fn git_upstream(env: &Env, name: &str, files: &[(&str, &str)]) -> (PathBuf, PathBuf) {
    let bare = env.path(name);
    git(&env.root, &["init", "-q", "--bare", bare.to_str().unwrap()]);
    let wc = env.path(&format!("{name}-wc"));
    git(&env.root, &["init", "-q", wc.to_str().unwrap()]);
    for (p, c) in files {
        write(&wc, p, c);
    }
    git(&wc, &["add", "-A"]);
    git(&wc, &["commit", "-q", "--allow-empty", "-m", "initial"]);
    git(&wc, &["remote", "add", "origin", bare.to_str().unwrap()]);
    git(&wc, &["push", "-q", "origin", "HEAD:refs/heads/main"]);
    (bare, wc)
}

/// Commit everything in a Git working copy and push `main`.
pub fn git_commit_push(wc: &Path, msg: &str) {
    git(wc, &["add", "-A"]);
    git(wc, &["commit", "-q", "--allow-empty", "-m", msg]);
    git(wc, &["push", "-q", "origin", "HEAD:refs/heads/main"]);
}

/// Every object of a Git repository, as `git cat-file --batch` prints it.
pub fn git_all_objects(repo: &Path) -> Vec<u8> {
    git_cmd(repo)
        .args(["cat-file", "--batch-all-objects", "--batch"])
        .output()
        .unwrap()
        .stdout
}

pub fn assert_absent_in_git(repo: &Path, needle: &str, what: &str) {
    assert!(
        !contains(&git_all_objects(repo), needle),
        "{what}: '{needle}' found in Git objects of {}",
        repo.display()
    );
}

/// A plain Veil `init` repository wired to a fresh bare Git remote `origin`.
pub fn veil_with_git_remote(env: &Env, user: &str, name: &str, bare: &str) -> (PathBuf, PathBuf) {
    let bare = env.path(bare);
    if !bare.exists() {
        git(&env.root, &["init", "-q", "--bare", bare.to_str().unwrap()]);
    }
    let proj = env.dir(name);
    env.ok(user, &proj, &["init"]);
    env.ok(
        user,
        &proj,
        &["git", "remote", "add", "origin", bare.to_str().unwrap()],
    );
    (proj, bare)
}

// ---- ssh -------------------------------------------------------------------

const SFTP_SERVERS: &[&str] = &[
    "/usr/lib/openssh/sftp-server",
    "/usr/libexec/openssh/sftp-server",
    "/usr/libexec/sftp-server",
    "/usr/lib/ssh/sftp-server",
    "/opt/homebrew/libexec/sftp-server",
];

pub fn sftp_server() -> Option<PathBuf> {
    let found = std::env::var("VEIL_TEST_SFTP_SERVER")
        .ok()
        .map(PathBuf::from)
        .or_else(|| SFTP_SERVERS.iter().map(PathBuf::from).find(|p| p.exists()));
    if found.is_none() {
        eprintln!("SKIPPED: no sftp-server binary found");
    }
    found
}
