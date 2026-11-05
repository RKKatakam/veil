//! BUG-741: a Git tree entry named `.veil` replaces the Veil repository.
//!
//! Fixed by moving the repository of a colocated project into
//! `.git/veil`, which Git never checks out into. The test used to look for
//! `.veil/repo.json` right after the pull; `.veil` is now only a symlink
//! to `.git/veil`, which the pull may replace (Git treats it as an ignored
//! file), so it checks the repository itself, then that the next command
//! puts the marker back without reading what the pull wrote there.

use crate::*;

#[test]
fn bug741_a_pulled_dot_veil_file_never_deletes_the_repository() {
    need_git!();
    let env = Env::new();
    let dir = env.project("p");
    let (_remote, other) = upstream(&env, &dir, "p");
    env.ok(&dir, &["status"]);
    contributor_pushes(&env, &other, &[(".veil", "a plain file\n")]);
    let _ = env.git(&dir, &["pull", "-q", "--ff-only"]);
    assert!(dir.join(".git/veil/repo.json").is_file(), "git pull deleted the Veil repository");
    let cat = env.ok(&dir, &["cat", "secrets/db.yml", "-r", "main"]);
    assert!(cat.contains("CLOAKMARK-base"), "{cat}");
    // The marker is back, and the pulled file was set aside, never read.
    assert!(dir.join(".veil/repo.json").is_file(), "the .veil marker was not restored");
    assert_eq!(env.git_ok(&dir, &["status", "--porcelain"]), "", "Git sees a change at .veil");
}
