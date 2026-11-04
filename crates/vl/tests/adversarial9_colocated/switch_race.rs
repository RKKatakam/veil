//! BUG-748: moving onto a cloaked line while a Git command holds
//! `index.lock`, or while a rebase is paused, leaves Git unfrozen, and the
//! `pre-commit` guard trusts the stale `colocated.json`.

use crate::*;

/// `main` plus a cloaked line `c` holding a sealed README edit and a new
/// file, with the default workspace attached again.
fn with_cloaked_line(env: &Env) -> std::path::PathBuf {
    let dir = env.project("p");
    env.write(&dir, "README.md", "hello\nv2\n");
    env.ok(&dir, &["commit", "-m", "second"]);
    env.ok(&dir, &["tag", "set", "main", "-r", "@-"]);
    cloaked_ws(env, &dir);
    env.write(&dir, "README.md", "hello\nv2\nCLOAKED-MARKER-5\n");
    env.write(&dir, "plan.md", "CLOAKED-MARKER-6\n");
    env.ok(&dir, &["commit", "-m", "cloaked work"]);
    env.ok(&dir, &["ws", "switch", "default"]);
    dir
}

#[test]
#[ignore = "BUG-748: `vl ws switch` onto a cloaked line while Git holds index.lock leaves the index unfrozen and no `*` exclude; Git then sees and commits the cloaked work"]
fn bug748_a_switch_while_git_holds_the_index_lock_still_freezes() {
    need_git!();
    let env = Env::new();
    let dir = with_cloaked_line(&env);
    // A concurrent Git command (an IDE refresh) holds the lock meanwhile.
    std::fs::write(dir.join(".git/index.lock"), b"").unwrap();
    env.ok(&dir, &["ws", "switch", "c"]);
    std::fs::remove_file(dir.join(".git/index.lock")).unwrap();
    assert_eq!(env.git_ok(&dir, &["status", "--porcelain"]), "", "Git sees the cloaked line's work");
}

#[test]
#[ignore = "BUG-748: during a paused `git rebase`, `vl ws switch` onto a cloaked line is not frozen and `git commit -a` passes the pre-commit guard"]
fn bug748_a_switch_during_a_rebase_never_lets_git_commit_sealed_work() {
    need_git!();
    let env = Env::new();
    let dir = with_cloaked_line(&env);
    let out = env
        .git_cmd(&dir, &["rebase", "-i", "HEAD~1"])
        .env("GIT_SEQUENCE_EDITOR", "sed -i 1ibreak")
        .output()
        .unwrap();
    assert!(dir.join(".git/rebase-merge").is_dir(), "rebase did not pause: {}", text(&out));
    env.ok(&dir, &["ws", "switch", "c"]);
    let out = env.git(&dir, &["commit", "-a", "-m", "during the rebase"]);
    assert!(!out.status.success(), "git commit -a went through");
}
