//! BUG-747: once Git clears skip-worktree, `git stash` stores a cloaked
//! line's edit as a stash commit, which `--prune` keeps.

use crate::*;

#[test]
#[ignore = "BUG-747: after `git sparse-checkout set` clears skip-worktree in frozen mode, `git stash` stores the cloaked line's edit in a stash commit that `vl git colocate --prune` keeps"]
fn bug747_a_stash_after_skip_worktree_is_cleared_holds_no_sealed_edit() {
    need_git!();
    let env = Env::new();
    let dir = env.project("p");
    env.write(&dir, "docs/a.md", "docs\n");
    env.ok(&dir, &["commit", "-m", "docs"]);
    env.ok(&dir, &["tag", "set", "main", "-r", "@-"]);
    cloaked_ws(&env, &dir);
    env.write(&dir, "README.md", "hello\nCLOAKED-MARKER-4\n");
    env.ok(&dir, &["status"]);
    let _ = env.git(&dir, &["sparse-checkout", "set", "--cone", "docs"]);
    let _ = env.git(&dir, &["stash"]);
    env.ok(&dir, &["status"]);
    env.ok(&dir, &["git", "colocate", "--prune"]);
    assert_clean(&env, &dir.join(".git"), &["CLOAKED-MARKER-4"], "git stash, then --prune");
}

