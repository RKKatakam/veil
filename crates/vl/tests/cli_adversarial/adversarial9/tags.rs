//! Annotated (release) tags, format 5 (design 5c and 8).

use super::{
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
    env.ok("mallory", &mallory, &["tag", "set", "work", "-r", "@-"]);
    move_on_remote(&env, &mallory, &remote, "v1.0");

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

/// A teammate (or a hostile remote) moves release tag `name` on the remote
/// to their own target: their other tags are pushed (the release is never
/// replaced by a push, BUG-710), then the remote's tag is re-pointed in
/// place.
fn move_on_remote(env: &Env, theirs: &std::path::Path, remote: &std::path::Path, name: &str) {
    let pushed = env.vl("mallory", theirs, &["push", "origin"]);
    let pushed_text = super::adversarial_support::text(&pushed);
    assert!(!pushed.status.success() && pushed_text.contains(&format!("rejected {name}")), "{pushed_text}");
    let target = veil_core::ObjectId::from_hex(&tag_target(env, theirs, "tags", name)).unwrap();
    let mut r = veil_core::Repo::open_remote(std::sync::Arc::new(veil_core::DiskBackend::new(remote))).unwrap();
    assert!(r.store().has(&target), "the teammate's snapshot reached the remote");
    let mut tx = r.transaction("move a release tag").unwrap();
    tx.view.tags.insert(name.to_string(), veil_core::oplog::Tag { target, annotation: None });
    tx.commit().unwrap();
}

/// The target of `name` in `vl tag list --json` (`tags` or `remote_tags`).
fn tag_target(env: &Env, proj: &std::path::Path, list: &str, name: &str) -> String {
    let v: serde_json::Value = serde_json::from_str(&env.stdout(U, proj, &["tag", "list", "--json"])).unwrap();
    let t = v[list].as_array().unwrap().iter().find(|t| t["name"] == name).unwrap_or_else(|| panic!("no {list} {name}: {v}"));
    t["target"]["snapshot_id"].as_str().unwrap().to_string()
}

/// BUG-703, the rest of the contract: the pull says the remote moved the
/// release tag (every time: it is not forgotten), records the remote's
/// target as `origin/v1.0`, still fast-forwards plain tags, and the local
/// release tag moves only with an explicit `vl tag set --force`.
#[test]
fn a_moved_release_tag_is_reported_recorded_and_taken_only_with_force() {
    let env = Env::new();
    let alice = env.project(U, "alice", &[("f.txt", "release\n")]);
    env.ok(U, &alice, &["tag", "set", "v1.0", "-r", "main", "-a", "-m", "Release 1.0"]);
    let remote = env.root.join("team");
    env.ok(U, &alice, &["remote", "add", "origin", remote.to_str().unwrap()]);
    env.ok(U, &alice, &["push", "origin"]);
    env.ok("mallory", &env.root, &["clone", "team", "mallory"]);
    let mallory = env.root.join("mallory");
    env.ok("mallory", &mallory, &["new", "main"]);
    write(&mallory, "f.txt", "backdoor\n");
    env.ok("mallory", &mallory, &["commit", "-m", "harmless"]);
    env.ok("mallory", &mallory, &["tag", "set", "main", "-r", "@-"]);
    env.ok("mallory", &mallory, &["tag", "set", "v1.0", "-r", "@-", "--force"]);
    move_on_remote(&env, &mallory, &remote, "v1.0");

    let ours = tag_target(&env, &alice, "tags", "v1.0");
    for _ in 0..2 {
        let pull = env.ok(U, &alice, &["pull", "origin"]);
        assert!(pull.contains("moved release tag v1.0") && pull.contains("stays at"), "{pull}");
        assert_eq!(tag_target(&env, &alice, "tags", "v1.0"), ours, "{pull}");
    }
    let theirs = tag_target(&env, &alice, "remote_tags", "origin/v1.0");
    assert_ne!(theirs, ours);
    // Plain tags still follow the remote.
    assert_eq!(tag_target(&env, &alice, "tags", "main"), theirs);
    // Only an explicit, forced command takes the remote's version.
    env.ok(U, &alice, &["tag", "set", "v1.0", "-r", "origin/v1.0", "--force"]);
    assert_eq!(env.stdout(U, &alice, &["cat", "-r", "v1.0", "f.txt"]), "backdoor\n");
}
