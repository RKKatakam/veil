//! BUG-742: a tracked `.gitignore` negation outranks the `info/exclude`
//! block (Git reads per-directory `.gitignore` files before
//! `info/exclude`), in normal and in frozen mode.
//!
//! Git cannot be stopped from hashing a negated file at add time (no
//! configuration outranks a `.gitignore`), so the two original
//! reproductions stay open as a documented limitation. What is fixed and
//! tested below: every command detects the negation and says so, Git
//! commits freeze while it is there, and the guards and superseding keep
//! the content out of commits, pushes and remotes; `--prune` removes what
//! `git add` hashed.

use crate::*;

#[test]
#[ignore = "BUG-742 (limitation): Git ranks a tracked .gitignore negation above info/exclude, so `git add -A` hashes the un-hidden files into .git; detected, frozen and kept out of commits and remotes (see the tests below)"]
fn bug742_a_negating_gitignore_never_unhides_protected_files() {
    need_git!();
    let env = Env::new();
    let dir = env.project("p");
    env.write(&dir, ".gitignore", "!secrets/\n!.env\n");
    env.ok(&dir, &["commit", "-m", "gitignore"]);
    env.write(&dir, "secrets/new.yml", "CLOAKED-MARKER-1\n");
    env.write(&dir, ".env", "ISOLATED-MARKER-1\n");
    let _ = env.git(&dir, &["add", "-A"]);
    assert_clean(&env, &dir.join(".git"), &["CLOAKED-MARKER", "ISOLATED-MARKER"], "git add -A");
}

#[test]
#[ignore = "BUG-742 (limitation): in frozen mode a tracked `!*.md` outranks the `*` exclude, so `git stash -u` stores a cloaked line's new file in a local stash and removes it from disk (`git stash pop` brings it back); detected and frozen in advance"]
fn bug742_frozen_mode_survives_a_negating_gitignore() {
    need_git!();
    let env = Env::new();
    let dir = env.project("p");
    env.write(&dir, ".gitignore", "!*.md\n");
    env.ok(&dir, &["commit", "-m", "gitignore"]);
    env.ok(&dir, &["tag", "set", "main", "-r", "@-"]);
    cloaked_ws(&env, &dir);
    env.write(&dir, "plan.md", "CLOAKED-MARKER-2\n");
    let _ = env.git(&dir, &["stash", "-u"]);
    assert!(dir.join("plan.md").exists(), "git stash -u took the cloaked line's file");
    assert_clean(&env, &dir.join(".git"), &["CLOAKED-MARKER-2"], "git stash -u in frozen mode");
}

#[test]
fn bug742_a_negation_is_detected_freezes_git_commits_and_never_reaches_a_remote() {
    need_git!();
    let env = Env::new();
    let dir = env.project("p");
    let (remote, _other) = upstream(&env, &dir, "p");
    env.write(&dir, ".gitignore", "!secrets/\n!.env\n");
    let out = env.ok(&dir, &["commit", "-m", "gitignore"]);
    assert!(out.contains("un-hides") && out.contains("secrets/"), "the negation was not reported:\n{out}");
    let st = env.ok(&dir, &["status"]);
    assert!(st.contains("un-hides"), "vl status does not repeat it:\n{st}");
    let st = env.ok(&dir, &["git", "colocate", "--status"]);
    assert!(st.contains("exposed"), "{st}");
    env.write(&dir, "secrets/new.yml", "CLOAKED-MARKER-1\n");
    env.write(&dir, ".env", "ISOLATED-MARKER-1\n");
    let _ = env.git(&dir, &["add", "-A"]);
    // Git took them (it cannot be stopped at add time) …
    let out = env.git(&dir, &["commit", "-m", "leak"]);
    assert!(!out.status.success(), "git commit went through: {}", text(&out));
    // … a commit forced past the guard is superseded …
    env.git_ok(&dir, &["commit", "-q", "--no-verify", "-m", "forced"]);
    let forced = env.git_ok(&dir, &["rev-parse", "HEAD"]);
    let out = env.ok(&dir, &["status"]);
    assert!(out.contains("held"), "{out}");
    let out = env.git(&dir, &["push", "-q", "origin", &format!("{forced}:refs/heads/leak")]);
    assert!(!out.status.success(), "git push of the held commit went through");
    env.git_ok(&dir, &["push", "-q", "origin", "main"]);
    env.ok(&dir, &["git", "push", "gh"]);
    assert_clean(&env, &remote, &["CLOAKED-MARKER", "ISOLATED-MARKER"], "the remote");
    // … and `--prune` removes what Git hashed.
    env.ok(&dir, &["git", "colocate", "--prune"]);
    assert_clean(&env, &dir.join(".git"), &["CLOAKED-MARKER", "ISOLATED-MARKER"], "after --prune");
    // The negation removed: Git commits work again.
    std::fs::remove_file(dir.join(".gitignore")).unwrap();
    env.ok(&dir, &["commit", "-m", "no negation"]);
    let st = env.ok(&dir, &["git", "colocate", "--status"]);
    assert!(!st.contains("exposed"), "{st}");
}

#[test]
fn bug742_frozen_mode_reports_a_negation_and_keeps_stashes_off_remotes() {
    need_git!();
    let env = Env::new();
    let dir = env.project("p");
    let (remote, _other) = upstream(&env, &dir, "p");
    env.write(&dir, ".gitignore", "!*.md\n");
    env.ok(&dir, &["commit", "-m", "gitignore"]);
    env.ok(&dir, &["tag", "set", "main", "-r", "@-"]);
    env.ok(&dir, &["ws", "new", "c", "-r", "main", "--cloak", "team"]);
    let out = env.ok(&dir, &["ws", "switch", "c"]);
    assert!(out.contains("un-hides"), "the negation was not reported:\n{out}");
    env.write(&dir, "plan.md", "CLOAKED-MARKER-2\n");
    let _ = env.git(&dir, &["add", "-A"]);
    let out = env.git(&dir, &["commit", "-m", "leak"]);
    assert!(!out.status.success(), "git commit went through");
    let _ = env.git(&dir, &["reset", "-q"]);
    let _ = env.git(&dir, &["stash", "-u"]);
    let out = env.git(&dir, &["push", "-q", "origin", "refs/stash:refs/heads/s"]);
    assert!(!out.status.success(), "git push of refs/stash went through");
    let _ = env.vl(&dir, &["git", "push", "gh"]);
    assert_clean(&env, &remote, &["CLOAKED-MARKER-2"], "the remote");
}
