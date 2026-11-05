//! `vl git …` end to end: the real `vl` binary, a local bare repository as
//! the Git remote, and plain `git` playing GitHub. Runs offline.

use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
};

struct Env {
    _tmp: tempfile::TempDir,
    root: PathBuf,
}

impl Env {
    fn new() -> Env {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        Env { _tmp: tmp, root }
    }

    fn vl(&self, cwd: &Path, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_vl"))
            .args(args)
            .current_dir(cwd)
            .env("VEIL_HOME", self.root.join("home-alice"))
            .env("VEIL_USER", "alice")
            .env("NO_COLOR", "1")
            .output()
            .unwrap()
    }

    fn ok(&self, cwd: &Path, args: &[&str]) -> String {
        let out = self.vl(cwd, args);
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.status.success(), "vl {args:?} failed:\n{text}");
        text
    }

    fn stdout(&self, cwd: &Path, args: &[&str]) -> String {
        let out = self.vl(cwd, args);
        assert!(out.status.success(), "vl {args:?} failed: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).into_owned()
    }
}

fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .current_dir(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "Gita Hub")
        .env("GIT_AUTHOR_EMAIL", "gita@example.com")
        .env("GIT_COMMITTER_NAME", "Gita Hub")
        .env("GIT_COMMITTER_EMAIL", "gita@example.com")
        .args(["-c", "init.defaultBranch=main", "-c", "commit.gpgsign=false"])
        .args(args)
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn write(dir: &Path, rel: &str, content: &str) {
    let p = dir.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, content).unwrap();
}

#[test]
fn import_work_push_edit_on_github_pull() {
    let env = Env::new();
    let root = env.root.clone();
    // An existing Git project on "GitHub".
    let bare = root.join("github.git");
    git(&root, &["init", "-q", "--bare", bare.to_str().unwrap()]);
    let upstream = root.join("upstream");
    git(&root, &["init", "-q", upstream.to_str().unwrap()]);
    write(&upstream, "app.txt", "v1\n");
    git(&upstream, &["add", "-A"]);
    git(&upstream, &["commit", "-q", "-m", "initial import"]);
    git(&upstream, &["push", "-q", bare.to_str().unwrap(), "HEAD:refs/heads/main"]);

    // Adopt Veil.
    let proj = root.join("proj");
    env.ok(&root, &["init", proj.to_str().unwrap()]);
    let out = env.ok(&proj, &["git", "import", bare.to_str().unwrap()]);
    assert!(out.contains("Imported 1 commit(s) from origin"), "{out}");
    assert!(out.contains("Working copy is now a change on main"), "{out}");
    assert_eq!(std::fs::read_to_string(proj.join("app.txt")).unwrap(), "v1\n");
    assert!(env.stdout(&proj, &["git", "remote", "list"]).contains("origin"));
    assert!(env.stdout(&proj, &["log"]).contains("initial import"));

    // Work in Veil, with a cloaked file.
    env.ok(&proj, &["cloak", "secrets/"]);
    write(&proj, "secrets/token.txt", "CLOAKED-TOKEN-4242\n");
    write(&proj, "app.txt", "v2\n");
    env.ok(&proj, &["commit", "-m", "v2 from Veil"]);
    env.ok(&proj, &["tag", "set", "main", "-r", "@-"]);
    let out = env.ok(&proj, &["git", "push"]);
    assert!(out.contains("pushed main"), "{out}");
    let files = git(&bare, &["ls-tree", "-r", "--name-only", "main"]);
    assert_eq!(files.lines().collect::<Vec<_>>(), vec![".veilpolicy", "app.txt"]);
    let objects = Command::new("git")
        .current_dir(&bare)
        .args(["cat-file", "--batch-all-objects", "--batch"])
        .output()
        .unwrap()
        .stdout;
    assert!(!objects.windows(18).any(|w| w == b"CLOAKED-TOKEN-4242"));

    // Someone commits on GitHub; Veil pulls it without losing the cloaked file.
    let work = root.join("work");
    git(&root, &["clone", "-q", bare.to_str().unwrap(), work.to_str().unwrap()]);
    write(&work, "app.txt", "v3 from GitHub\n");
    git(&work, &["commit", "-q", "-am", "v3 from GitHub"]);
    git(&work, &["push", "-q", "origin", "main"]);
    let out = env.ok(&proj, &["git", "pull"]);
    assert!(out.contains("updated main"), "{out}");
    assert_eq!(env.stdout(&proj, &["cat", "app.txt", "-r", "main"]), "v3 from GitHub\n");
    assert_eq!(env.stdout(&proj, &["cat", "secrets/token.txt", "-r", "main"]), "CLOAKED-TOKEN-4242\n");
    assert!(env.stdout(&proj, &["cat", "secrets/token.txt", "-r", "origin/main"]).contains("CLOAKED-TOKEN"));

    // Nothing new to push: the imported commit is GitHub's own.
    let out = env.ok(&proj, &["git", "push"]);
    assert!(out.contains("up to date main"), "{out}");
}

#[test]
fn rejected_push_explains_how_to_recover() {
    let env = Env::new();
    let root = env.root.clone();
    let bare = root.join("github.git");
    git(&root, &["init", "-q", "--bare", bare.to_str().unwrap()]);
    let proj = root.join("proj");
    env.ok(&root, &["init", proj.to_str().unwrap()]);
    write(&proj, "a.txt", "a\n");
    env.ok(&proj, &["commit", "-m", "a"]);
    env.ok(&proj, &["tag", "set", "main", "-r", "@-"]);
    env.ok(&proj, &["git", "remote", "add", "github", bare.to_str().unwrap()]);
    env.ok(&proj, &["git", "push", "github"]);

    let work = root.join("work");
    git(&root, &["clone", "-q", bare.to_str().unwrap(), work.to_str().unwrap()]);
    write(&work, "b.txt", "b\n");
    git(&work, &["add", "-A"]);
    git(&work, &["commit", "-q", "-m", "b on GitHub"]);
    git(&work, &["push", "-q", "origin", "main"]);

    write(&proj, "c.txt", "c\n");
    env.ok(&proj, &["commit", "-m", "c in Veil"]);
    env.ok(&proj, &["tag", "set", "main", "-r", "@-"]);
    let out = env.vl(&proj, &["git", "push", "github"]);
    assert!(!out.status.success());
    let text = String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    assert!(text.contains("rejected main") && text.contains("vl git pull github"), "{text}");

    let out = env.ok(&proj, &["git", "pull", "github"]);
    assert!(out.contains("diverged"), "{out}");
    env.ok(&proj, &["merge", "github/main", "--into", "main", "-m", "merge GitHub"]);
    let out = env.ok(&proj, &["git", "push", "github"]);
    assert!(out.contains("pushed main"), "{out}");
    let files = git(&bare, &["ls-tree", "-r", "--name-only", "main"]);
    assert!(files.contains("b.txt") && files.contains("c.txt"), "{files}");
}
