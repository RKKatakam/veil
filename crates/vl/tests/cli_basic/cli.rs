//! Drives the real `vl` binary against temporary directories.

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

    /// Run `vl` as `user` (each user has their own VEIL_HOME / identity).
    fn vl(&self, user: &str, cwd: &Path, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_vl"))
            .env("VEIL_TEST_PATH_REMOTES", "1")
            .args(args)
            .current_dir(cwd)
            .env("VEIL_HOME", self.root.join(format!("home-{user}")))
            .env("VEIL_USER", user)
            .env("NO_COLOR", "1")
            .output()
            .unwrap()
    }

    fn stdout(&self, user: &str, cwd: &Path, args: &[&str]) -> String {
        let out = self.vl(user, cwd, args);
        assert!(out.status.success(), "vl {args:?} failed: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    fn ok(&self, user: &str, cwd: &Path, args: &[&str]) -> String {
        let out = self.vl(user, cwd, args);
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.status.success(), "vl {args:?} failed:\n{text}");
        text
    }
}

fn write(dir: &Path, rel: &str, content: &str) {
    let p = dir.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, content).unwrap();
}

#[test]
fn init_isolates_secrets_and_commits_without_staging() {
    let env = Env::new();
    let proj = env.dir("proj");
    write(&proj, "src/lib.rs", "pub fn f() {}\n");
    write(&proj, ".netrc", "SECRET=1\n");
    write(&proj, "leak.txt", "aws = AKIAIOSFODNN7EXAMPLE\n");
    let out = env.ok("alice", &proj, &["init"]);
    assert!(out.contains("local-only .netrc, leak.txt"), "{out}");
    let st = env.ok("alice", &proj, &["status"]);
    assert!(st.contains("A src/lib.rs"));
    assert!(st.contains("L .netrc"));
    assert!(st.contains("Q leak.txt"));
    env.ok("alice", &proj, &["commit", "-m", "first"]);
    let files = env.stdout("alice", &proj, &["files", "-r", "@-"]);
    let paths: Vec<&str> = files.lines().filter_map(|l| l.split_whitespace().last()).collect();
    assert_eq!(paths, vec![".veilpolicy", "src/lib.rs"], "{files}");
    assert!(env.ok("alice", &proj, &["log"]).contains("first"));
}

#[test]
fn undo_restores_files_on_disk() {
    let env = Env::new();
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    write(&proj, "a.txt", "one\n");
    env.ok("alice", &proj, &["commit", "-m", "a"]);
    env.ok("alice", &proj, &["new", "root"]);
    assert!(!proj.join("a.txt").exists(), "checking out root removes a.txt");
    env.ok("alice", &proj, &["undo"]);
    assert_eq!(std::fs::read_to_string(proj.join("a.txt")).unwrap(), "one\n");
}

#[test]
fn virtual_workspaces_never_touch_the_project_directory() {
    let env = Env::new();
    let proj = env.dir("proj");
    write(&proj, "main.rs", "fn main() {}\n");
    env.ok("alice", &proj, &["init"]);
    env.ok("alice", &proj, &["commit", "-m", "base"]);
    env.ok("alice", &proj, &["ws", "new", "agent"]);
    env.ok("alice", &proj, &["ws", "exec", "agent", "-m", "agent work", "--", "sh", "-c", "echo hi > agent.txt"]);
    assert!(!proj.join("agent.txt").exists());
    assert_eq!(env.ok("alice", &proj, &["ws", "cat", "agent", "agent.txt"]), "hi\n");
    let list = env.ok("alice", &proj, &["ws", "list"]);
    assert!(list.contains("agent: ") && list.contains("agent work"), "{list}");
    env.ok("alice", &proj, &["ws", "switch", "agent"]);
    assert!(proj.join("agent.txt").exists(), "switching materialises the workspace");
    env.ok("alice", &proj, &["ws", "switch", "default"]);
    assert!(!proj.join("agent.txt").exists());
}

#[test]
fn cloaked_content_and_public_mirrors() {
    let env = Env::new();
    let proj = env.dir("proj");
    write(&proj, "README.md", "hello\n");
    write(&proj, "internal/plan.md", "the secret plan\n");
    env.ok("alice", &proj, &["init"]);
    env.ok("alice", &proj, &["cloak", "internal/"]);
    env.ok("alice", &proj, &["commit", "-m", "v1"]);
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "@-"]);
    let mirror = env.root.join("mirror");
    let team = env.root.join("team");
    env.ok("alice", &proj, &["remote", "add", "public", mirror.to_str().unwrap(), "--public"]);
    env.ok("alice", &proj, &["remote", "add", "origin", team.to_str().unwrap()]);
    assert!(env.ok("alice", &proj, &["push", "public"]).contains("withheld"));

    // Bob clones the public mirror: no plaintext anywhere.
    let out = env.ok("bob", &env.root, &["clone", "mirror", "bob-public"]);
    assert!(out.contains("1 cloaked file(s)"), "{out}");
    assert!(env.root.join("bob-public/README.md").exists());
    assert!(!env.root.join("bob-public/internal/plan.md").exists());
    let grep = Command::new("grep").args(["-r", "secret plan"]).arg(&mirror).output().unwrap();
    assert!(grep.stdout.is_empty(), "plaintext leaked into the public mirror");
    // Pushed objects arrive zstd-packed, which grep cannot see into.
    assert!(packed_contains(&mirror, b"secret plan").is_empty(), "plaintext leaked into a pack on the public mirror");

    // Alice grants Bob; Bob clones the team remote and can read.
    let bob_key = env.ok("bob", &env.root, &["identity", "show"]);
    let bob_key = bob_key.lines().find(|l| l.starts_with("public key")).unwrap().split_whitespace().last().unwrap().to_string();
    env.ok("alice", &proj, &["scope", "grant", "team", &bob_key, "--name", "bob"]);
    env.ok("alice", &proj, &["push"]);
    env.ok("bob", &env.root, &["clone", "team", "bob-team"]);
    assert_eq!(
        std::fs::read_to_string(env.root.join("bob-team/internal/plan.md")).unwrap(),
        "the secret plan\n"
    );
}

#[test]
fn scan_fails_on_public_secrets() {
    let env = Env::new();
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    write(&proj, "cfg.py", "token = 'ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789'\n");
    let out = env.vl("alice", &proj, &["scan"]);
    assert_eq!(out.status.code(), Some(1));
    env.ok("alice", &proj, &["isolate", "cfg.py"]);
    assert!(env.vl("alice", &proj, &["scan"]).status.success());
}

#[test]
fn vault_secrets_are_injected_by_run() {
    let env = Env::new();
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    env.ok("alice", &proj, &["secret", "set", "API_TOKEN", "abc123"]);
    let out = env.ok("alice", &proj, &["run", "--", "sh", "-c", "echo token=$API_TOKEN"]);
    assert!(out.contains("token=abc123"));
    let grep = Command::new("grep").args(["-r", "abc123"]).arg(proj.join(".veil")).output().unwrap();
    assert!(grep.stdout.is_empty(), "vault must be encrypted at rest");
}

/// Packs on a Veil repository directory whose decoded objects contain `needle`.
fn packed_contains(repo: &Path, needle: &[u8]) -> Vec<String> {
    use veil_core::{cache::LruCache, pack, DiskBackend, StorageBackend, VPath};
    let fs = DiskBackend::new(repo);
    let dir = VPath::new(".veil/objects/pack").unwrap();
    let Ok(entries) = fs.list_dir(&dir) else { return Vec::new() };
    let bases = LruCache::new(64 << 20);
    let mut hits = Vec::new();
    for e in entries {
        let Some(name) = pack::name_from_index_file(&e.name) else { continue };
        let p = pack::Pack::open(&fs, &dir, name).unwrap();
        for id in p.index().ids() {
            let raw = p.get(&fs, id, &bases).unwrap().expect("indexed object is in its pack");
            if raw.windows(needle.len()).any(|w| w == needle) {
                hits.push(format!("{}#{}", e.name, id.short()));
            }
        }
    }
    hits
}
