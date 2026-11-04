//! End-to-end working-copy behaviour through the real `vl` binary:
//! quarantined edits and the stat cache.

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

    fn dir(&self, name: &str) -> PathBuf {
        let d = self.root.join(name);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn vl(&self, cwd: &Path, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_vl"))
            .args(args)
            .current_dir(cwd)
            .env("VEIL_HOME", self.root.join("home"))
            .env("VEIL_USER", "alice")
            .env("NO_COLOR", "1")
            .output()
            .unwrap()
    }

    /// stdout + stderr of a successful run.
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
        assert!(
            out.status.success(),
            "vl {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }
}

fn write(dir: &Path, rel: &str, content: &str) {
    let p = dir.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, content).unwrap();
}

fn read(dir: &Path, rel: &str) -> String {
    std::fs::read_to_string(dir.join(rel)).unwrap()
}

fn files(env: &Env, proj: &Path, rev: &str) -> Vec<String> {
    env.stdout(proj, &["files", "-r", rev])
        .lines()
        .filter_map(|l| l.split_whitespace().last().map(String::from))
        .collect()
}

const CLEAN: &str = "const key = process.env.KEY;\n";
const LEAKY: &str = "const key = 'AKIAIOSFODNN7EXAMPLE';\n";

#[test]
fn quarantined_edits_keep_history_and_survive_checkouts() {
    let env = Env::new();
    let proj = env.dir("proj");
    write(&proj, "cfg.js", CLEAN);
    write(&proj, "main.rs", "fn main() {}\n");
    env.ok(&proj, &["init"]);
    env.ok(&proj, &["commit", "-m", "v1"]);

    // Case 1: a tracked file gains a secret. History keeps v1; no deletion.
    write(&proj, "cfg.js", LEAKY);
    // Case 2: a never-tracked file with a secret stays out of the tree.
    write(&proj, "leak.js", LEAKY);
    let st = env.ok(&proj, &["status"]);
    assert!(
        st.contains("The working copy has no changes."),
        "no deletion recorded:\n{st}"
    );
    assert!(
        st.contains("Q cfg.js  (aws-access-key-id; edit held back; history keeps the previous version)"),
        "{st}"
    );
    assert!(st.contains("Q leak.js  (aws-access-key-id; never recorded)"), "{st}");
    assert!(
        st.contains("history keeps the previous version"),
        "warning explains it:\n{st}"
    );
    assert_eq!(files(&env, &proj, "@"), vec![".veilpolicy", "cfg.js", "main.rs"]);
    assert_eq!(env.stdout(&proj, &["cat", "cfg.js", "-r", "@"]), CLEAN);

    // Checking out a tree without the file must not delete the local edit...
    let out = env.ok(&proj, &["new", "root"]);
    assert!(out.contains("kept cfg.js"), "{out}");
    assert_eq!(read(&proj, "cfg.js"), LEAKY);
    assert!(!proj.join("main.rs").exists(), "everything else is checked out");
    // ...and neither must checking out one that has it (from a tree that does not).
    let out = env.ok(&proj, &["undo"]);
    assert!(out.contains("kept cfg.js"), "{out}");
    assert_eq!(read(&proj, "cfg.js"), LEAKY);
    assert_eq!(read(&proj, "main.rs"), "fn main() {}\n");
    let st = env.ok(&proj, &["status"]);
    assert!(st.contains("history keeps the previous version"), "{st}");
    assert_eq!(files(&env, &proj, "@"), vec![".veilpolicy", "cfg.js", "main.rs"]);

    // `vl restore` discards the quarantined edit.
    env.ok(&proj, &["restore", "cfg.js"]);
    assert_eq!(read(&proj, "cfg.js"), CLEAN);
    let st = env.ok(&proj, &["status"]);
    assert!(!st.contains("Q cfg.js"), "{st}");
    assert!(st.contains("Q leak.js"), "{st}");
}

#[test]
fn same_size_edits_are_seen_with_a_warm_cache() {
    let env = Env::new();
    let proj = env.dir("proj");
    write(&proj, "a.txt", "v0\n");
    write(&proj, "b/c.txt", "c\n");
    env.ok(&proj, &["init"]);
    env.ok(&proj, &["commit", "-m", "base"]);
    env.ok(&proj, &["status"]);
    assert!(proj.join(".veil/local/statcache/default.cache").is_file());
    for i in 1..=5 {
        // Same size as before, rewritten immediately after the last command.
        write(&proj, "a.txt", &format!("v{i}\n"));
        let st = env.ok(&proj, &["status"]);
        assert!(st.contains("M a.txt"), "edit {i} missed:\n{st}");
        assert_eq!(env.stdout(&proj, &["cat", "a.txt", "-r", "@"]), format!("v{i}\n"));
    }
    // Switching workspaces keeps the directory and its cache consistent.
    env.ok(&proj, &["ws", "new", "other", "-r", "@-"]);
    env.ok(&proj, &["ws", "switch", "other"]);
    assert_eq!(read(&proj, "a.txt"), "v0\n");
    write(&proj, "a.txt", "w1\n");
    assert!(env.ok(&proj, &["status"]).contains("M a.txt"));
    env.ok(&proj, &["ws", "switch", "default"]);
    assert_eq!(read(&proj, "a.txt"), "v5\n");
    assert!(proj.join(".veil/local/statcache/other.cache").is_file());
}
