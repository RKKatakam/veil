//! BUG-746: the `.veil/.git` marker kept `git clean -fdx` away from
//! `.veil`, but not `git clean -ffdx`.
//!
//! Fixed by moving the repository into `.git/veil`, which `git clean`
//! never touches. `git clean -ffdx` still deletes the `.veil` symlink (an
//! ignored file to Git) and the ignored protected files; the next command
//! puts the marker back, and the files are in Veil's history.

use crate::*;

#[test]
fn bug746_git_clean_ffdx_never_deletes_the_veil_repository() {
    need_git!();
    let env = Env::new();
    let dir = env.project("p");
    env.ok(&dir, &["status"]);
    let _ = env.git(&dir, &["clean", "-q", "-ffdx"]);
    assert!(dir.join(".git/veil/repo.json").is_file(), "git clean -ffdx deleted the Veil repository");
    env.ok(&dir, &["status"]);
    assert!(dir.join(".veil/repo.json").is_file(), "the .veil marker was not restored");
    // What `git clean` deleted is in history (`vl restore` puts it back).
    let back = env.ok(&dir, &["cat", "secrets/db.yml", "-r", "@-"]);
    assert!(back.contains("CLOAKMARK-base"), "{back}");
}
