//! Shared harness of the colocated Git mode tests: a `vl` and a `git` that
//! never read the user's configuration, and object dumps of a `.git`.

#![allow(dead_code)]

use std::{
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

pub struct Env {
    _tmp: tempfile::TempDir,
    pub root: PathBuf,
}

impl Env {
    pub fn new() -> Env {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        std::fs::create_dir_all(root.join("home")).unwrap();
        Env { _tmp: tmp, root }
    }

    fn base(&self, prog: &str, cwd: &Path) -> Command {
        let mut c = Command::new(prog);
        c.current_dir(cwd)
            .env("VEIL_HOME", self.root.join("home-alice"))
            .env("VEIL_USER", "alice")
            .env("NO_COLOR", "1")
            .env("HOME", self.root.join("home"))
            .env("XDG_CONFIG_HOME", self.root.join("home").join(".config"))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_AUTHOR_NAME", "Gita")
            .env("GIT_AUTHOR_EMAIL", "gita@example.com")
            .env("GIT_COMMITTER_NAME", "Gita")
            .env("GIT_COMMITTER_EMAIL", "gita@example.com")
            .env("TMPDIR", &self.root)
            .stdin(Stdio::null());
        for v in ["GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR", "VEIL_GIT"] {
            c.env_remove(v);
        }
        c
    }

    pub fn vl_cmd(&self, cwd: &Path, args: &[&str]) -> Command {
        let mut c = self.base(env!("CARGO_BIN_EXE_vl"), cwd);
        c.args(args);
        c
    }

    pub fn vl(&self, cwd: &Path, args: &[&str]) -> Output {
        self.vl_cmd(cwd, args).output().unwrap()
    }

    pub fn ok(&self, cwd: &Path, args: &[&str]) -> String {
        let out = self.vl(cwd, args);
        let text = text(&out);
        assert!(out.status.success(), "vl {args:?} failed:\n{text}");
        assert!(!text.contains("panicked"), "{text}");
        text
    }

    pub fn fails(&self, cwd: &Path, args: &[&str]) -> String {
        let out = self.vl(cwd, args);
        let text = text(&out);
        assert!(!out.status.success(), "vl {args:?} succeeded:\n{text}");
        assert!(!text.contains("panicked"), "{text}");
        text
    }

    pub fn git_cmd(&self, cwd: &Path, args: &[&str]) -> Command {
        let mut c = self.base("git", cwd);
        c.args(["-c", "init.defaultBranch=main", "-c", "commit.gpgsign=false", "-c", "protocol.file.allow=always"])
            .args(["-c", "advice.detachedHead=false", "-c", "core.pager=cat", "-c", "color.ui=false"])
            .args(args);
        c
    }

    pub fn git(&self, cwd: &Path, args: &[&str]) -> Output {
        self.git_cmd(cwd, args).output().unwrap()
    }

    pub fn git_ok(&self, cwd: &Path, args: &[&str]) -> String {
        let out = self.git(cwd, args);
        assert!(out.status.success(), "git {args:?} failed:\n{}", text(&out));
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    pub fn dir(&self, name: &str) -> PathBuf {
        let d = self.root.join(name);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A colocated project: `secrets/` cloaked, one public commit tagged
    /// `main`, `HEAD` on `main`.
    pub fn project(&self, name: &str) -> PathBuf {
        let dir = self.dir(name);
        self.ok(&dir, &["init", "--colocate", "--experimental"]);
        let mut policy = std::fs::read_to_string(dir.join(".veilpolicy")).unwrap();
        policy.push_str("secrets/ cloak\n");
        std::fs::write(dir.join(".veilpolicy"), policy).unwrap();
        std::fs::write(dir.join("README.md"), "hello\n").unwrap();
        std::fs::create_dir_all(dir.join("secrets")).unwrap();
        std::fs::write(dir.join("secrets/db.yml"), "password: CLOAKMARK-base\n").unwrap();
        self.ok(&dir, &["commit", "-m", "first"]);
        self.ok(&dir, &["tag", "set", "main", "-r", "@-"]);
        dir
    }

    pub fn bare(&self, name: &str) -> PathBuf {
        let d = self.root.join(name);
        self.git_ok(&self.root, &["init", "-q", "--bare", d.to_str().unwrap()]);
        d
    }

    /// Write `text` to `path` below `dir`, creating directories.
    pub fn write(&self, dir: &Path, path: &str, text: &str) {
        let p = dir.join(path);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, text).unwrap();
    }
}

pub fn text(out: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr))
}

/// Every object of the Git repository `git_dir` (loose and packed),
/// decompressed, concatenated.
pub fn objects(env: &Env, git_dir: &Path) -> Vec<u8> {
    let out = env
        .git_cmd(&env.root, &["--git-dir", git_dir.to_str().unwrap(), "cat-file", "--batch-all-objects", "--batch", "--unordered"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", text(&out));
    out.stdout
}

/// Does `hay` contain `needle`?
pub fn contains(hay: &[u8], needle: &str) -> bool {
    hay.windows(needle.len()).any(|w| w == needle.as_bytes())
}

/// Every ref name and the packed-refs file of `git_dir`, as text.
pub fn ref_names(env: &Env, git_dir: &Path) -> String {
    let mut s = env.git_ok(&env.root, &["--git-dir", git_dir.to_str().unwrap(), "for-each-ref", "--format=%(refname)"]);
    if let Ok(p) = std::fs::read_to_string(git_dir.join("packed-refs")) {
        s.push_str(&p);
    }
    s
}

/// Assert no object of `git_dir` holds any of `markers`.
pub fn assert_clean(env: &Env, git_dir: &Path, markers: &[&str], when: &str) {
    let dump = objects(env, git_dir);
    for m in markers {
        assert!(!contains(&dump, m), "{when}: an object of {} holds {m}", git_dir.display());
    }
}
