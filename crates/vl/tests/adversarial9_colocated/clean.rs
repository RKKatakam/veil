//! BUG-746: the `.veil/.git` marker keeps `git clean -fdx` away from
//! `.veil`, but not `git clean -ffdx`.

use crate::*;

#[test]
#[ignore = "BUG-746: `git clean -ffdx` deletes .veil (the whole Veil repository, unrecoverable) and the cloaked files"]
fn bug746_git_clean_ffdx_never_deletes_the_veil_repository() {
    need_git!();
    let env = Env::new();
    let dir = env.project("p");
    env.ok(&dir, &["status"]);
    let _ = env.git(&dir, &["clean", "-q", "-ffdx"]);
    assert!(dir.join(".veil/repo.json").is_file(), "git clean -ffdx deleted .veil");
}
