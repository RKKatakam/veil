//! BUG-752: `refs/stash` (which `git stash -a` fills with ignored, so
//! isolated, files) leaves the machine in a bundle, with no guard.

use crate::*;

#[test]
#[ignore = "BUG-752 (limitation; reported, see below): `git bundle create --all` carries refs/stash, so the isolated file `git stash -a` stored goes into a file meant for sharing"]
fn bug752_a_bundle_of_all_refs_carries_no_isolated_file() {
    need_git!();
    let env = Env::new();
    let dir = env.project("p");
    env.write(&dir, ".env", "ISOLATED-MARKER-8\n");
    env.ok(&dir, &["status"]);
    env.git_ok(&dir, &["stash", "-a", "-q"]);
    let bundle = env.root.join("all.bundle");
    let _ = env.git(&dir, &["bundle", "create", "-q", bundle.to_str().unwrap(), "--all"]);
    let other = env.dir("receiver");
    env.git_ok(&other, &["init", "-q"]);
    let _ = env.git(&other, &["fetch", "-q", bundle.to_str().unwrap(), "refs/*:refs/remotes/b/*"]);
    assert_clean(&env, &other.join(".git"), &["ISOLATED-MARKER-8"], "a repository fetched from the bundle");
}

/// What is fixed: the next command finds the stash holding the isolated
/// file and says so, with what to do, before anyone bundles it.
#[test]
fn bug752_a_stash_of_ignored_protected_files_is_reported() {
    need_git!();
    let env = Env::new();
    let dir = env.project("p");
    env.write(&dir, ".env", "ISOLATED-MARKER-8\n");
    env.ok(&dir, &["status"]);
    env.git_ok(&dir, &["stash", "-a", "-q"]);
    let out = env.ok(&dir, &["status"]);
    assert!(out.contains("stash@{0} holds") && out.contains(".env"), "{out}");
    assert!(out.contains("git bundle"), "{out}");
}
