//! BUG-750, BUG-751: the follow and the mirror lose Git branches (and, for
//! a cloaked tag's name, the tag's position in Veil).

use crate::*;

#[test]
#[ignore = "BUG-750: a Git branch named like a cloaked Veil tag retargets that cloaked tag to the public commit, and the mirror deletes the Git branch"]
fn bug750_a_branch_named_like_a_cloaked_tag_moves_neither() {
    need_git!();
    let env = Env::new();
    let dir = env.project("p");
    cloaked_ws(&env, &dir);
    env.write(&dir, "plan.md", "CLOAKED-MARKER-7\n");
    env.ok(&dir, &["commit", "-m", "cloaked plan"]);
    env.ok(&dir, &["tag", "set", "project-x", "--cloak", "-r", "@-"]);
    env.ok(&dir, &["ws", "switch", "default"]);
    env.git_ok(&dir, &["checkout", "-q", "-b", "project-x"]);
    env.write(&dir, "w.txt", "public\n");
    env.git_ok(&dir, &["add", "w.txt"]);
    env.git_ok(&dir, &["commit", "-q", "-m", "public work"]);
    env.ok(&dir, &["status"]);
    env.ok(&dir, &["status"]);
    let cat = text(&env.vl(&dir, &["cat", "plan.md", "-r", "project-x"]));
    assert!(cat.contains("CLOAKED-MARKER-7"), "the cloaked tag moved:\n{cat}");
    let out = env.git(&dir, &["rev-parse", "-q", "--verify", "refs/heads/project-x"]);
    assert!(out.status.success(), "the Git branch project-x was deleted");
}

#[test]
#[ignore = "BUG-751: a Git branch whose name is not a valid Veil tag (`issue#12`) is deleted from .git by the next vl command"]
fn bug751_a_branch_veil_cannot_follow_is_never_deleted() {
    need_git!();
    let env = Env::new();
    let dir = env.project("p");
    env.git_ok(&dir, &["checkout", "-q", "-b", "issue#12"]);
    env.write(&dir, "work.txt", "branch work\n");
    env.git_ok(&dir, &["add", "work.txt"]);
    env.git_ok(&dir, &["commit", "-q", "-m", "branch work"]);
    env.git_ok(&dir, &["checkout", "-q", "main"]);
    env.ok(&dir, &["status"]);
    env.ok(&dir, &["status"]);
    let out = env.git(&dir, &["rev-parse", "-q", "--verify", "refs/heads/issue#12"]);
    assert!(out.status.success(), "the Git branch issue#12 was deleted");
}
