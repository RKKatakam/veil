//! BUG-743: `vl git colocate --prune` expires every reflog entry, not only
//! those of held commits, so the user's stashes and reflog-only commits go.

use crate::*;

#[test]
#[ignore = "BUG-743: `vl git colocate --prune` runs `git reflog expire --expire=now --all`: the user's older stashes and reflog-only commits are destroyed"]
fn bug743_prune_keeps_the_users_stashes_and_reflog() {
    need_git!();
    let env = Env::new();
    let dir = env.project("p");
    env.write(&dir, "a.txt", "first stash\n");
    env.git_ok(&dir, &["stash", "-u", "-q"]);
    env.write(&dir, "b.txt", "second stash\n");
    env.git_ok(&dir, &["stash", "-u", "-q"]);
    env.write(&dir, "README.md", "hello\nundone commit\n");
    env.git_ok(&dir, &["commit", "-q", "-am", "undone"]);
    let undone = env.git_ok(&dir, &["rev-parse", "HEAD"]);
    env.git_ok(&dir, &["reset", "-q", "--hard", "HEAD~1"]);
    env.ok(&dir, &["git", "colocate", "--prune"]);
    let list = env.git_ok(&dir, &["stash", "list"]);
    assert_eq!(list.lines().count(), 2, "stashes after --prune:\n{list}");
    let out = env.git(&dir, &["cat-file", "-e", &undone]);
    assert!(out.status.success(), "--prune removed a commit the user's reflog still held");
}
