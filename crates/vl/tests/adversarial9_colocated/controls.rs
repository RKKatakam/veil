//! Controls: guards that held up in round 9.

use crate::*;

#[test]
fn control_frozen_mode_keeps_sealed_edits_through_forced_checkouts() {
    need_git!();
    let env = Env::new();
    let dir = env.project("p");
    env.write(&dir, "README.md", "hello\nv2\n");
    env.ok(&dir, &["commit", "-m", "second"]);
    env.ok(&dir, &["tag", "set", "main", "-r", "@-"]);
    cloaked_ws(&env, &dir);
    env.write(&dir, "README.md", "hello\nv2\nCLOAKED-MARKER-11\n");
    env.ok(&dir, &["status"]);
    for cmd in [&["checkout", "-q", "HEAD~1"][..], &["checkout", "-q", "-f", "HEAD~1"], &["reset", "-q", "--hard", "HEAD~1"]] {
        let _ = env.git(&dir, cmd);
        let now = std::fs::read_to_string(dir.join("README.md")).unwrap();
        assert!(now.contains("CLOAKED-MARKER-11"), "git {cmd:?} overwrote the sealed edit");
    }
    assert_eq!(env.git_ok(&dir, &["status", "--porcelain"]), "");
    assert_clean(&env, &dir.join(".git"), &["CLOAKED-MARKER-11"], "forced checkouts in frozen mode");
}
