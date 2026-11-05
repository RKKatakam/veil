//! BUG-754: design threat 8's mitigation (an excluded path that some
//! exported commit has goes into the index as skip-worktree, so Git
//! refuses to overwrite it) is not implemented.

use crate::*;

#[test]
#[ignore = "BUG-754 (limitation, documented in the guide): `git checkout` of an old commit that had a now-cloaked file overwrites the member's file; the edit made since the last vl command is lost"]
fn bug754_an_old_checkout_never_overwrites_a_cloaked_file() {
    need_git!();
    let env = Env::new();
    let dir = env.dir("p");
    env.ok(&dir, &["init", "--colocate", "--experimental"]);
    env.write(&dir, "secrets/db.yml", "public before the cloak\n");
    env.ok(&dir, &["commit", "-m", "public db"]);
    env.ok(&dir, &["tag", "set", "main", "-r", "@-"]);
    let old = env.git_ok(&dir, &["rev-parse", "HEAD"]);
    let mut policy = std::fs::read_to_string(dir.join(".veilpolicy")).unwrap();
    policy.push_str("secrets/ cloak\n");
    std::fs::write(dir.join(".veilpolicy"), policy).unwrap();
    env.write(&dir, "secrets/db.yml", "CLOAKED-MARKER-9 recorded\n");
    env.ok(&dir, &["commit", "-m", "cloak db"]);
    env.ok(&dir, &["tag", "set", "main", "-r", "@-"]);
    env.write(&dir, "secrets/db.yml", "CLOAKED-MARKER-10 not yet recorded\n");
    let _ = env.git(&dir, &["checkout", "-q", &old]);
    let now = std::fs::read_to_string(dir.join("secrets/db.yml")).unwrap_or_default();
    assert!(now.contains("CLOAKED-MARKER-10"), "git checkout overwrote the cloaked file:\n{now}");
}
