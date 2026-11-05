//! BUG-740: Git checks out tracked paths under `.veil/` into Veil's own
//! state, including the accepted-policy pin.

use crate::*;

#[test]
fn bug740_a_pulled_commit_never_writes_veils_accepted_policy() {
    need_git!();
    let env = Env::new();
    let dir = env.project("p");
    let (remote, other) = upstream(&env, &dir, "p");
    env.ok(&dir, &["status"]);
    let pin = std::fs::read_to_string(dir.join(".veil/local/accepted-policy")).unwrap();
    let relaxed = std::fs::read_to_string(other.join(".veilpolicy"))
        .unwrap()
        .replace("secrets/ cloak", "secrets/ public!");
    contributor_pushes(
        &env,
        &other,
        &[(".veilpolicy", &relaxed), (".veil/local/accepted-policy", "secrets/ public!\n")],
    );
    let _ = env.git(&dir, &["pull", "-q", "--ff-only"]);
    let _ = env.vl(&dir, &["status"]);
    let _ = env.vl(&dir, &["commit", "-m", "more work"]);
    let _ = env.vl(&dir, &["git", "push", "gh"]);
    let now = std::fs::read_to_string(dir.join(".veil/local/accepted-policy")).unwrap_or_default();
    assert_eq!(now, pin, "git pull rewrote the accepted-policy pin");
    assert_clean(&env, &remote, &["CLOAKMARK"], "the Git remote after git pull and vl git push");
}
