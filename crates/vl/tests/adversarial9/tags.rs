//! Annotated (release) tags, format 5 (design 5c and 8).

use crate::{
    adversarial_support::{write, Env},
    U,
};

/// BUG-703: an annotated tag is a release tag, immutable here (`vl tag set`
/// over it needs `--force`, design 5c), and design 8 threat 7 says a
/// remote that re-points one never moves the local tag ("remote moved tag
/// v1.0 from X to Y"). `vl pull` from a Veil remote does: when the
/// remote's target descends from the local one, `remote::pull`
/// fast-forwards the local release tag and replaces its annotation with
/// whatever the remote holds (another member's atag, or none). A teammate
/// (or a hostile remote) moves everyone's `v1.0` to new code on their
/// next pull, silently.
#[test]
#[ignore = "BUG-703: vl pull silently moves a local annotated release tag and swaps its signed annotation"]
fn pull_never_moves_a_local_release_tag() {
    let env = Env::new();
    let alice = env.dir("alice");
    env.ok(U, &alice, &["init"]);
    write(&alice, "f.txt", "release\n");
    env.ok(U, &alice, &["commit", "-m", "release"]);
    env.ok(U, &alice, &["tag", "set", "v1.0", "-r", "@-", "-a", "-m", "Release 1.0"]);
    let before = env.stdout(U, &alice, &["tag", "verify", "v1.0"]);
    assert!(before.contains("good signature by alice"), "{before}");
    let remote = env.root.join("team");
    env.ok(U, &alice, &["remote", "add", "origin", remote.to_str().unwrap()]);
    env.ok(U, &alice, &["push", "origin"]);

    // The teammate moves the release tag to their own work.
    env.ok("mallory", &env.root, &["clone", "team", "mallory"]);
    let mallory = env.root.join("mallory");
    write(&mallory, "f.txt", "backdoor\n");
    env.ok("mallory", &mallory, &["commit", "-m", "harmless"]);
    env.ok("mallory", &mallory, &["tag", "set", "v1.0", "-r", "@-", "--force"]);
    env.ok("mallory", &mallory, &["push", "origin"]);

    let pull = env.ok(U, &alice, &["pull", "origin"]);
    let after = env.vl(U, &alice, &["tag", "verify", "v1.0"]);
    let shown = String::from_utf8_lossy(&after.stdout).into_owned();
    assert!(
        after.status.success() && shown.contains("good signature by alice"),
        "after `vl pull` ({pull}) the local release tag v1.0 is no longer alice's:\n{shown}{}",
        String::from_utf8_lossy(&after.stderr)
    );
    let content = env.stdout(U, &alice, &["cat", "-r", "v1.0", "f.txt"]);
    assert_eq!(content, "release\n", "v1.0 now points at the teammate's code");
}
