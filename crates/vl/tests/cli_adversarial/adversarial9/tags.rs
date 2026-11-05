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
    // (Replacing a release on the remote takes --force-tags, BUG-710.)
    env.ok("mallory", &mallory, &["push", "origin", "--force-tags"]);

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
    env.ok("mallory", &mallory, &["push", "origin", "--force-tags"]);

    let ours = tag_target(&env, &alice, "tags", "v1.0");
    for _ in 0..2 {
        let pull = super::adversarial_support::text(&env.vl(U, &alice, &["pull", "origin"]));
        assert!(pull.contains("moved release tag v1.0") && pull.contains("stays at"), "{pull}");
        assert_eq!(tag_target(&env, &alice, "tags", "v1.0"), ours, "{pull}");
    }
    let theirs = tag_target(&env, &alice, "remote_tags", "origin/v1.0");
    assert_ne!(theirs, ours);
    // Plain tags still follow the remote.
    assert_eq!(tag_target(&env, &alice, "tags", "main"), theirs);
    // Pushing does not quietly settle it either: the push names the choice.
    let push = env.vl(U, &alice, &["push", "origin"]);
    let shown = super::adversarial_support::text(&push);
    assert!(!push.status.success() && shown.contains("holds release tag v1.0 at another target"), "{shown}");
    // Only an explicit, forced command takes the remote's version.
    env.ok(U, &alice, &["tag", "set", "v1.0", "-r", "origin/v1.0", "--force"]);
    assert_eq!(env.stdout(U, &alice, &["cat", "-r", "v1.0", "f.txt"]), "backdoor\n");
}

/// BUG-703 through the Git bridge: a Git **branch** named like a local
/// release tag (`refs/heads/v1.0`) never fast-forwards the release tag on
/// `vl git pull` (it used to, dropping its signed annotation).
#[test]
fn a_git_branch_named_like_a_release_tag_never_moves_it() {
    use std::process::Command;
    let git = |dir: &std::path::Path, args: &[&str]| {
        let out = Command::new("git")
            .current_dir(dir)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("HOME", dir)
            .args(["-c", "user.name=Gita", "-c", "user.email=gita@example.com", "-c", "init.defaultBranch=main"])
            .args(["-c", "commit.gpgsign=false", "-c", "protocol.file.allow=always", "-c", "advice.detachedHead=false"])
            .args(args)
            .output()
            .unwrap();
        assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    };
    let env = Env::new();
    let alice = env.project(U, "alice", &[("f.txt", "release\n")]);
    env.ok(U, &alice, &["tag", "set", "v1.0", "-r", "main", "-a", "-m", "Release 1.0"]);
    let bare = env.root.join("hub.git");
    git(&env.root, &["init", "-q", "--bare", bare.to_str().unwrap()]);
    env.ok(U, &alice, &["git", "remote", "add", "origin", bare.to_str().unwrap()]);
    env.ok(U, &alice, &["git", "push"]);
    let work = env.root.join("work");
    git(&env.root, &["clone", "-q", bare.to_str().unwrap(), work.to_str().unwrap()]);
    git(&work, &["checkout", "-q", "-b", "topic-1", "main"]);
    write(&work, "f.txt", "backdoor\n");
    git(&work, &["commit", "-q", "-am", "harmless"]);
    git(&work, &["push", "-q", "origin", "topic-1:refs/heads/v1.0"]);

    let ours = tag_target(&env, &alice, "tags", "v1.0");
    let pull = super::adversarial_support::text(&env.vl(U, &alice, &["git", "pull"]));
    assert_eq!(tag_target(&env, &alice, "tags", "v1.0"), ours, "{pull}");
    assert!(pull.contains("has the name of release tag v1.0"), "{pull}");
    let verify = env.stdout(U, &alice, &["tag", "verify", "v1.0"]);
    assert!(verify.contains("good signature by alice"), "{verify}");
    assert_eq!(env.stdout(U, &alice, &["cat", "-r", "v1.0", "f.txt"]), "release\n");
}

/// BUG-710: `vl push` of a release tag moved here with `vl tag set --force`
/// (even forward) never moves it on a Veil remote without `--force-tags`,
/// as `vl git push` needs `--force-tags` for the Git tag. Plain tags still
/// fast-forward; the dry run says the same.
#[test]
fn a_veil_push_never_moves_a_release_tag_without_force_tags() {
    let env = Env::new();
    let alice = env.project(U, "alice", &[("f.txt", "release\n")]);
    env.ok(U, &alice, &["tag", "set", "v1.0", "-r", "main", "-a", "-m", "Release 1.0"]);
    let remote = env.root.join("team");
    env.ok(U, &alice, &["remote", "add", "origin", remote.to_str().unwrap()]);
    env.ok(U, &alice, &["push", "origin"]);
    let released = tag_target(&env, &alice, "remote_tags", "origin/v1.0");
    write(&alice, "f.txt", "later\n");
    env.ok(U, &alice, &["commit", "-m", "later"]);
    env.ok(U, &alice, &["tag", "set", "main", "-r", "@-"]);
    env.ok(U, &alice, &["tag", "set", "v1.0", "-r", "@-", "--force"]);
    let dry = env.vl(U, &alice, &["push", "origin", "--dry-run"]);
    assert!(!dry.status.success(), "{}", super::adversarial_support::text(&dry));
    let push = env.vl(U, &alice, &["push", "origin"]);
    let shown = super::adversarial_support::text(&push);
    assert!(!push.status.success() && shown.contains("--force-tags"), "{shown}");
    // `main` (a plain tag) went; the release stayed.
    assert!(shown.contains("pushed main"), "{shown}");
    assert_eq!(tag_target(&env, &alice, "remote_tags", "origin/v1.0"), released);
    env.ok("bob", &env.root, &["clone", "team", "bob"]);
    assert_eq!(env.stdout("bob", &env.root.join("bob"), &["cat", "-r", "v1.0", "f.txt"]), "release\n");
    // On purpose, it moves.
    env.ok(U, &alice, &["push", "origin", "--dry-run", "--force-tags"]);
    env.ok(U, &alice, &["push", "origin", "--force-tags"]);
    assert_ne!(tag_target(&env, &alice, "remote_tags", "origin/v1.0"), released);
}
