//! BUG-748: moving onto a cloaked line while a Git command holds
//! `index.lock`, or while a rebase is paused, left Git unfrozen, and the
//! `pre-commit` guard trusted the stale `colocated.json`.
//!
//! Fixed: Git's index is frozen *before* cloaked work is written; while
//! Git is busy it cannot be, and the move is refused (nothing is written).
//! The tests used to expect the switch to succeed; they now expect the
//! refusal, then the switch once Git is done, frozen.

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

fn no_sealed_work_on_disk(dir: &std::path::Path) {
    let readme = std::fs::read_to_string(dir.join("README.md")).unwrap();
    assert!(!readme.contains("CLOAKED-MARKER"), "the cloaked work was written:\n{readme}");
    assert!(!dir.join("plan.md").exists(), "the cloaked work was written");
}

#[test]
fn bug748_a_switch_while_git_holds_the_index_lock_still_freezes() {
    need_git!();
    let env = Env::new();
    let dir = with_cloaked_line(&env);
    // A concurrent Git command (an IDE refresh) holds the lock meanwhile.
    std::fs::write(dir.join(".git/index.lock"), b"").unwrap();
    let out = env.fails(&dir, &["ws", "switch", "c"]);
    assert!(out.contains("Git is busy"), "{out}");
    no_sealed_work_on_disk(&dir);
    std::fs::remove_file(dir.join(".git/index.lock")).unwrap();
    assert_eq!(env.git_ok(&dir, &["status", "--porcelain"]), "", "Git sees the cloaked line's work");
    env.ok(&dir, &["ws", "switch", "c"]);
    assert!(std::fs::read_to_string(dir.join("README.md")).unwrap().contains("CLOAKED-MARKER-5"));
    assert_eq!(env.git_ok(&dir, &["status", "--porcelain"]), "", "Git sees the cloaked line's work");
    let _ = env.git(&dir, &["add", "-A"]);
    let out = env.git(&dir, &["commit", "-a", "-m", "leak"]);
    assert!(!out.status.success(), "git commit -a went through");
    assert_clean(&env, &dir.join(".git"), &["CLOAKED-MARKER"], "after the switch");
}

#[test]
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
    let out = env.fails(&dir, &["ws", "switch", "c"]);
    assert!(out.contains("Git is busy"), "{out}");
    no_sealed_work_on_disk(&dir);
    let _ = env.git(&dir, &["commit", "-a", "-m", "during the rebase"]);
    assert_clean(&env, &dir.join(".git"), &["CLOAKED-MARKER"], "a commit during the rebase");
    env.git_ok(&dir, &["rebase", "--abort"]);
    env.ok(&dir, &["ws", "switch", "c"]);
    let out = env.git(&dir, &["commit", "-a", "-m", "after the rebase"]);
    assert!(!out.status.success(), "git commit -a went through");
    assert_clean(&env, &dir.join(".git"), &["CLOAKED-MARKER"], "after the switch");
}

/// The `pre-commit` guard decides from the repository, not from
/// `colocated.json`: with the file saying "not frozen", a commit on a
/// cloaked line is still refused.
#[test]
fn bug748_pre_commit_decides_from_the_live_workspace() {
    need_git!();
    let env = Env::new();
    let dir = with_cloaked_line(&env);
    env.ok(&dir, &["ws", "switch", "c"]);
    let state_file = dir.join(".git/veil/git/colocated.json");
    let state = std::fs::read_to_string(&state_file).unwrap();
    std::fs::write(&state_file, state.replace("\"frozen\": true", "\"frozen\": false").replace("\"index_frozen\": true", "\"index_frozen\": false")).unwrap();
    env.git_ok(&dir, &["update-index", "--no-skip-worktree", "README.md"]);
    let _ = env.git(&dir, &["add", "README.md"]);
    let out = env.git(&dir, &["commit", "-m", "leak"]);
    assert!(!out.status.success(), "git commit went through: {}", text(&out));
    assert!(text(&out).contains("frozen"), "{}", text(&out));
}
