//! BUG-741: a Git tree entry named `.veil` replaces the Veil repository.

use crate::*;

#[test]
#[ignore = "BUG-741: a pulled Git commit that adds a file named .veil makes `git pull` delete the whole Veil repository"]
fn bug741_a_pulled_dot_veil_file_never_deletes_the_repository() {
    need_git!();
    let env = Env::new();
    let dir = env.project("p");
    let (_remote, other) = upstream(&env, &dir, "p");
    env.ok(&dir, &["status"]);
    contributor_pushes(&env, &other, &[(".veil", "a plain file\n")]);
    let _ = env.git(&dir, &["pull", "-q", "--ff-only"]);
    assert!(dir.join(".veil/repo.json").is_file(), "git pull replaced the .veil directory");
    let cat = env.ok(&dir, &["cat", "secrets/db.yml", "-r", "main"]);
    assert!(cat.contains("CLOAKMARK-base"), "{cat}");
}
