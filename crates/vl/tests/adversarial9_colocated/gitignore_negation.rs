//! BUG-742: a tracked `.gitignore` negation outranks the `info/exclude`
//! block (Git reads per-directory `.gitignore` files before
//! `info/exclude`), in normal and in frozen mode.

use crate::*;

#[test]
#[ignore = "BUG-742: a tracked .gitignore negation (`!secrets/`, `!.env`) outranks info/exclude: `git add -A` hashes cloaked and isolated files into .git"]
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
#[ignore = "BUG-742: in frozen mode a tracked `!*.md` outranks the `*` exclude: `git stash -u` stores a cloaked line's new file in .git and removes it from disk"]
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
