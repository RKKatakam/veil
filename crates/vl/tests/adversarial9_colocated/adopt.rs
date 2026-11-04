//! BUG-745: adopting a Git checkout ignores the user's `skip-worktree` and
//! `assume-unchanged` bits, so local edits Git was told to hide become
//! public Veil changes.

use crate::*;

#[test]
#[ignore = "BUG-745: `vl init --colocate` records local edits hidden with skip-worktree/assume-unchanged as public changes, and `vl git push` publishes them"]
fn bug745_adoption_never_publishes_edits_git_was_told_to_hide() {
    need_git!();
    let env = Env::new();
    let dir = env.dir("p");
    let remote = env.bare("p-remote.git");
    env.git_ok(&dir, &["init", "-q"]);
    env.write(&dir, "config/database.yml", "host: localhost\n");
    env.write(&dir, "config/app.yml", "url: example\n");
    env.git_ok(&dir, &["add", "-A"]);
    env.git_ok(&dir, &["commit", "-q", "-m", "init"]);
    env.git_ok(&dir, &["push", "-q", remote.to_str().unwrap(), "main"]);
    // The usual idiom for keeping local config edits out of commits.
    env.write(&dir, "config/database.yml", "host: LOCAL-MARKER-1\n");
    env.write(&dir, "config/app.yml", "url: LOCAL-MARKER-2\n");
    env.git_ok(&dir, &["update-index", "--skip-worktree", "config/database.yml"]);
    env.git_ok(&dir, &["update-index", "--assume-unchanged", "config/app.yml"]);
    env.ok(&dir, &["init", "--colocate", "--experimental"]);
    env.ok(&dir, &["git", "remote", "add", "gh", remote.to_str().unwrap()]);
    let _ = env.vl(&dir, &["commit", "-m", "my work"]);
    let _ = env.vl(&dir, &["git", "push", "gh"]);
    assert_clean(&env, &remote, &["LOCAL-MARKER"], "the Git remote after adoption and vl git push");
}
