//! Scope administration through the real `vl` binary: revocation survives
//! push/pull, rotation hides new content, and signatures show in log/show.

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

    fn public_key(&self, user: &str) -> String {
        let out = self.ok(user, &self.root, &["identity", "show"]);
        out.lines()
            .find(|l| l.starts_with("public key"))
            .unwrap()
            .split_whitespace()
            .last()
            .unwrap()
            .to_string()
    }
}

fn write(dir: &Path, rel: &str, content: &str) {
    let p = dir.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, content).unwrap();
}

#[test]
fn revoke_rotates_and_survives_push_and_pull() {
    let env = Env::new();
    let proj = env.root.join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    write(&proj, "internal/plan.md", "v1 plan\n");
    env.ok("alice", &proj, &["init"]);
    env.ok("alice", &proj, &["cloak", "internal/"]);
    env.ok("alice", &proj, &["commit", "-m", "v1"]);
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "@-"]);
    let team = env.root.join("team");
    env.ok("alice", &proj, &["remote", "add", "origin", team.to_str().unwrap()]);
    let bob = env.public_key("bob");
    // veil1 + X25519 + Ed25519 + the binding signature (BUG-069).
    assert_eq!(bob.len(), 5 + 256, "full public identity: {bob}");
    env.ok("alice", &proj, &["scope", "grant", "team", &bob, "--name", "bob"]);
    env.ok("alice", &proj, &["push"]);
    env.ok("bob", &env.root, &["clone", "team", "bob"]);
    let bob_dir = env.root.join("bob");

    // Bob cannot administer the scope.
    let carol = env.public_key("carol");
    let out = env.vl("bob", &bob_dir, &["scope", "grant", "team", &carol, "--name", "carol"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("only an admin"));

    // Alice revokes Bob, pulls from the remote that still lists him, pushes.
    let out = env.ok("alice", &proj, &["scope", "revoke", "team", &bob]);
    assert!(out.contains("generation 1"), "{out}");
    env.ok("alice", &proj, &["pull"]);
    let list = env.ok("alice", &proj, &["scope", "list"]);
    assert!(!list.contains("bob"), "pull resurrected the revoked member:\n{list}");
    write(&proj, "internal/plan.md", "v2 plan\n");
    env.ok("alice", &proj, &["commit", "-m", "v2"]);
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "@-"]);
    env.ok("alice", &proj, &["push"]);

    // Bob pulls: still revoked, history readable, new content is not.
    env.ok("bob", &bob_dir, &["pull"]);
    let list = env.ok("bob", &bob_dir, &["scope", "list"]);
    assert!(list.contains("revoked (history only)") && !list.contains("bob "), "{list}");
    assert_eq!(env.ok("bob", &bob_dir, &["cat", "internal/plan.md", "-r", "main-"]), "v1 plan\n");
    assert!(!env.vl("bob", &bob_dir, &["cat", "internal/plan.md", "-r", "main"]).status.success());

    let log = env.ok("alice", &proj, &["scope", "log", "team"]);
    assert!(log.contains("grant bob") && log.contains("revoke bob → generation 1"), "{log}");

    // Signatures are visible to both.
    let show = env.ok("bob", &bob_dir, &["show", "main"]);
    assert!(show.contains("Signature : good, signed by alice"), "{show}");
    let vlog = env.ok("alice", &proj, &["log"]);
    assert!(vlog.contains("alice ✓"), "{vlog}");
}
