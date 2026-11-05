//! Policy fixes of the round 4 fix wave, through the real `vl` binary:
//! VCS metadata is never recorded (BUG-076), a `public` rule settled by a
//! later `public!` stops warning (BUG-083), and `vl cloak` by a non-member
//! of an existing scope says how to get a grant (BUG-085).

use crate::adversarial_support;

use std::path::Path;

use adversarial_support::*;

/// Paths recorded in `rev` (`vl files -r <rev>`).
fn files(env: &Env, proj: &Path, rev: &str) -> Vec<String> {
    env.stdout("alice", proj, &["files", "-r", rev])
        .lines()
        .filter_map(|l| l.rsplit("  ").next().map(|p| p.trim().to_string()))
        .collect()
}

/// Any recorded path with a VCS metadata component?
fn vcs_paths(paths: &[String]) -> Vec<&String> {
    paths
        .iter()
        .filter(|p| p.split('/').any(|c| [".git", ".jj", ".hg", ".svn"].contains(&c.to_ascii_lowercase().as_str())))
        .collect()
}

// ---- BUG-076: VCS metadata ---------------------------------------------------

#[test]
fn nested_vcs_metadata_and_git_files_are_ignored_at_any_depth() {
    let env = Env::new();
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    // A nested repository, a `.git` *file* (a worktree), and the metadata
    // of other VCSs.
    let nested = proj.join("vendor/lib");
    write(&nested, ".git/HEAD", "ref: refs/heads/main\n");
    write(&nested, ".git/config", "[core]\n");
    write(&nested, "lib.rs", "pub fn f() {}\n");
    write(&proj, "sub/.git", "gitdir: ../.git/modules/sub\n");
    write(&proj, "sub/readme.md", "worktree\n");
    write(&proj, ".hg/store/data", "hg\n");
    write(&proj, "deep/er/.jj/repo/op_heads", "jj\n");
    write(&proj, "old/.svn/entries", "svn\n");
    write(&proj, "x/.GIT/config", "case\n");
    // Broad rules do not bring them back.
    write(&proj, ".veilpolicy", "** public\nvendor/ public!\nold/ cloak\n");
    env.ok("alice", &proj, &["commit", "-m", "c"]);
    let recorded = files(&env, &proj, "@-");
    for want in ["vendor/lib/lib.rs", "sub/readme.md"] {
        assert!(recorded.iter().any(|p| p == want), "{want} missing: {recorded:?}");
    }
    assert!(vcs_paths(&recorded).is_empty(), "VCS metadata recorded: {:?}", vcs_paths(&recorded));
    let check = env.ok("alice", &proj, &["policy", "check", "sub/.git", "vendor/lib/.git", "old/.svn/entries"]);
    assert_eq!(check.matches("ignored").count(), 3, "{check}");
    let show = env.ok("alice", &proj, &["policy", "show"]);
    assert!(show.contains(".git") && show.contains(".jj"), "{show}");

    // Only a `public!` that names the directory records it.
    write(&proj, ".veilpolicy", "** public\nvendor/lib/.git/ public!\n");
    env.ok("alice", &proj, &["commit", "-m", "record the fixture repository"]);
    let recorded = files(&env, &proj, "@-");
    assert!(recorded.iter().any(|p| p == "vendor/lib/.git/HEAD"), "{recorded:?}");
    assert!(!recorded.iter().any(|p| p.starts_with("sub/.git") || p.starts_with(".hg")), "{recorded:?}");
}

// ---- BUG-083: a `public` rule settled by a later `public!` -------------------

#[test]
fn expose_force_after_expose_stops_the_ignored_rule_warning() {
    let env = Env::new();
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    write(&proj, "t.pem", "test fixture, not a key\n");
    let out = env.ok("alice", &proj, &["expose", "t.pem"]);
    assert!(out.contains("built-in secret path t.pem public; ignored"), "the plain rule is refused: {out}");
    env.ok("alice", &proj, &["expose", "--force", "t.pem"]);
    for args in [&["status"][..], &["commit", "-m", "fixture"], &["log"]] {
        let out = env.ok("alice", &proj, args);
        assert!(!out.contains("ignored (use `public!`"), "vl {args:?} still warns:\n{out}");
    }
    let check = env.ok("alice", &proj, &["policy", "check", "t.pem"]);
    assert!(check.contains("public") && check.contains("secret scanning disabled"), "{check}");
    assert!(!check.contains("was ignored"), "{check}");
    assert!(files(&env, &proj, "@-").iter().any(|p| p == "t.pem"));
}

// ---- BUG-085: `vl cloak` by a non-member ------------------------------------

#[test]
fn cloak_by_a_non_member_asks_for_a_grant_not_a_new_scope() {
    let env = Env::new();
    let alice = env.dir("alice");
    write(&alice, "README.md", "hello\n");
    env.ok("alice", &alice, &["init"]);
    env.ok("alice", &alice, &["commit", "-m", "v1"]);
    env.ok("alice", &alice, &["tag", "set", "main", "-r", "@-"]);
    let team = env.root.join("team");
    env.ok("alice", &alice, &["remote", "add", "origin", team.to_str().unwrap()]);
    env.ok("alice", &alice, &["push"]);
    env.ok("bob", &env.root, &["clone", "team", "bob"]);
    let bob = env.root.join("bob");
    write(&bob, "notes.md", "bob's notes\n");

    let out = env.vl("bob", &bob, &["cloak", "notes.md"]);
    let said = text(&out);
    assert!(!out.status.success(), "{said}");
    assert!(!said.contains("scope create"), "suggests creating a scope that exists: {said}");
    assert!(said.contains("vl scope grant team"), "{said}");
    assert!(said.contains("alice"), "names the admin: {said}");
    let key = env
        .ok("bob", &env.root, &["identity", "show"])
        .lines()
        .find(|l| l.starts_with("public key"))
        .and_then(|l| l.split_whitespace().last().map(str::to_string))
        .unwrap();
    assert!(said.contains(&key), "shows bob's public key {key}: {said}");
    assert!(!read(&bob, ".veilpolicy").contains("notes.md"), "no rule was added");

    // A scope that does not exist: create it.
    let out = env.vl("bob", &bob, &["cloak", "--scope", "ops", "notes.md"]);
    assert!(text(&out).contains("vl scope create ops"), "{}", text(&out));
}
