//! `vl push` / `vl pull` over path remotes: fast-forwards, rejection,
//! `--force`, tag selection, remote tags (tracking), deletion, a remote that
//! moved on, empty remotes.

use crate::support::*;

/// Alice's project with a hub and Bob's clone of it.
fn team(env: &Env) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let (alice, hub) = env.project_with_hub("alice", "alice", "hub", &[("a.txt", "a\n")]);
    let bob = env.clone("bob", &hub, "bob");
    (alice, hub, bob)
}

// Scenario from git t5516-fetch-push.sh: "push new branch" / fast-forward push.
#[test]
fn push_fast_forwards_a_tag_and_reports_it() {
    let env = Env::new();
    let (alice, hub, bob) = team(&env);
    env.commit("alice", &alice, "two", &[("a.txt", "a2\n")]);
    let out = env.ok("alice", &alice, &["push"]);
    assert!(out.contains("pushed main"), "{out}");
    let out = env.ok("bob", &bob, &["pull"]);
    assert!(out.contains("updated main"), "{out}");
    assert_eq!(
        env.stdout("bob", &bob, &["cat", "a.txt", "-r", "main"]),
        "a2\n"
    );
    let out = env.ok("alice", &alice, &["fsck", "-R", hub.to_str().unwrap()]);
    assert!(out.contains("No corruption found"), "{out}");
}

// Scenario from git t5516-fetch-push.sh: "push with no changes" is a no-op, exit 0.
#[test]
fn push_and_pull_with_nothing_new_are_no_ops() {
    let env = Env::new();
    let (alice, hub, bob) = team(&env);
    let ops = op_count(&hub);
    let (code, out) = env.code("alice", &alice, &["push"]);
    assert_eq!(code, 0, "{out}");
    assert!(
        out.contains("Pushed 0 object(s)") && !out.contains("pushed main"),
        "{out}"
    );
    let (code, out) = env.code("bob", &bob, &["pull"]);
    assert_eq!(code, 0, "{out}");
    assert!(
        out.contains("Pulled 0 object(s)") && !out.contains("updated"),
        "{out}"
    );
    assert!(
        op_count(&hub) <= ops + 1,
        "an empty push records at most one operation"
    );
}

// Scenario from git t5516-fetch-push.sh: "push to a remote that does not exist yet" (Veil creates it).
#[test]
fn the_first_push_creates_the_remote_including_parent_directories() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a", "a\n")]);
    env.ok(
        "alice",
        &proj,
        &["remote", "add", "origin", "../srv/deep/hub"],
    );
    env.ok("alice", &proj, &["push"]);
    assert!(env.path("srv/deep/hub/.veil/repo.json").exists());
    assert_eq!(repo_format(&env.path("srv/deep/hub")), repo_format(&proj));
}

// Scenario from git t5516-fetch-push.sh: "push to a non-repository" fails rather than creating one.
#[test]
fn push_to_a_non_empty_directory_that_is_not_a_repository_is_refused() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a", "a\n")]);
    let other = env.dir("other-project");
    write(&other, "notes.txt", "my own files\n");
    env.ok(
        "alice",
        &proj,
        &["remote", "add", "origin", other.to_str().unwrap()],
    );
    let out = env.vl("alice", &proj, &["push"]);
    assert!(
        !out.status.success(),
        "pushed into a non-Veil directory: {}",
        text(&out)
    );
    assert!(
        !other.join(".veil").exists(),
        "created .veil inside an unrelated directory"
    );
}

// Scenario from git t5516-fetch-push.sh: push to a path that is a regular file fails cleanly.
#[test]
fn push_to_a_path_that_is_a_file_fails_cleanly() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a", "a\n")]);
    write(&env.root, "afile", "x\n");
    env.ok("alice", &proj, &["remote", "add", "origin", "../afile"]);
    env.fails("alice", &proj, &["push"]);
    assert_eq!(read(&env.root, "afile"), "x\n");
}

// Scenario from git t5516-fetch-push.sh / t5405-send-pack-rewind.sh: "non forced push should die"
// on a non-fast-forward, and exit non-zero.
#[test]
fn a_diverged_push_is_rejected_with_exit_1_and_a_recovery_hint() {
    let env = Env::new();
    let (alice, hub, bob) = team(&env);
    env.commit("bob", &bob, "bob", &[("b.txt", "b\n")]);
    env.ok("bob", &bob, &["push"]);
    env.commit("alice", &alice, "alice", &[("c.txt", "c\n")]);
    let (code, out) = env.code("alice", &alice, &["push"]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("rejected main"), "{out}");
    assert!(
        out.contains("vl pull origin") && out.contains("vl merge origin/main"),
        "{out}"
    );
    // The remote still has Bob's main.
    let hub_main = open_repo(&hub).view().tags["main"].target;
    assert_eq!(
        env.tag_target("bob", &bob, "main").unwrap(),
        hub_main.short()
    );
}

// Scenario from git t5405-send-pack-rewind.sh: "forced push should succeed".
#[test]
fn force_push_overwrites_a_diverged_tag_and_keeps_the_old_history_on_the_remote() {
    let env = Env::new();
    let (alice, hub, bob) = team(&env);
    env.commit("bob", &bob, "bob's work", &[("b.txt", "b\n")]);
    env.ok("bob", &bob, &["push"]);
    let bobs = env.tag_target("bob", &bob, "main").unwrap();
    env.commit("alice", &alice, "alice", &[("c.txt", "c\n")]);
    let out = env.ok("alice", &alice, &["push", "--force"]);
    assert!(out.contains("pushed main"), "{out}");
    let remote = open_repo(&hub);
    assert_eq!(
        remote.view().tags["main"].target.short(),
        env.tag_target("alice", &alice, "main").unwrap()
    );
    // Bob's snapshot is still on the remote (a head), not lost.
    let heads: Vec<String> = remote.view().heads.iter().map(|h| h.short()).collect();
    assert!(
        heads.contains(&bobs),
        "Bob's overwritten work is gone from the remote: {heads:?}"
    );
    let out = env.ok("bob", &bob, &["pull"]);
    assert!(out.contains("diverged"), "{out}");
    assert_eq!(
        env.tag_target("bob", &bob, "main").unwrap(),
        bobs,
        "Bob's tag does not move backwards"
    );
}

// Scenario from git t5516-fetch-push.sh: "push rejected when the local branch is behind".
#[test]
fn a_tag_that_is_behind_the_remote_is_rejected_and_pull_fast_forwards_it() {
    let env = Env::new();
    let (alice, _hub, bob) = team(&env);
    env.commit("bob", &bob, "bob", &[("b.txt", "b\n")]);
    env.ok("bob", &bob, &["push"]);
    let (code, out) = env.code("alice", &alice, &["push"]);
    assert_eq!(code, 1, "{out}");
    let out = env.ok("alice", &alice, &["pull"]);
    assert!(out.contains("updated main"), "{out}");
    let (code, out) = env.code("alice", &alice, &["push"]);
    assert_eq!(code, 0, "{out}");
}

// Scenario from git t5404-tracking-branches.sh: "mixed-success push returns error" and the
// other tags are still pushed.
#[test]
fn a_partially_rejected_push_sends_the_other_tags_and_exits_1() {
    let env = Env::new();
    let (alice, hub, bob) = team(&env);
    env.commit("bob", &bob, "bob", &[("b.txt", "b\n")]);
    env.ok("bob", &bob, &["push"]);
    env.commit("alice", &alice, "alice", &[("c.txt", "c\n")]);
    env.ok("alice", &alice, &["tag", "set", "feature", "-r", "@-"]);
    let (code, out) = env.code("alice", &alice, &["push"]);
    assert_eq!(code, 1, "{out}");
    assert!(
        out.contains("pushed feature") && out.contains("rejected main"),
        "{out}"
    );
    assert!(open_repo(&hub).view().tags.contains_key("feature"));
}

// Scenario from git t5543-atomic-push.sh: Veil has no atomic push; a rejected tag does not
// stop the others (deliberate, documented). Rerunning after a merge completes the push.
#[test]
fn after_a_rejection_merge_and_push_again() {
    let env = Env::new();
    let (alice, _hub, bob) = team(&env);
    env.commit("bob", &bob, "bob", &[("b.txt", "b\n")]);
    env.ok("bob", &bob, &["push"]);
    env.commit("alice", &alice, "alice", &[("c.txt", "c\n")]);
    env.fails("alice", &alice, &["push"]);
    env.ok("alice", &alice, &["pull"]);
    env.ok(
        "alice",
        &alice,
        &["merge", "origin/main", "--into", "main", "-m", "merge bob"],
    );
    let out = env.ok("alice", &alice, &["push"]);
    assert!(out.contains("pushed main"), "{out}");
    env.ok("bob", &bob, &["pull"]);
    let files = env.stdout("bob", &bob, &["files", "-r", "main"]);
    assert!(
        files.contains("b.txt") && files.contains("c.txt"),
        "{files}"
    );
}

// Scenario from git t5404 / jj test_git_push.rs: a retried rejected push does not re-send
// what the first attempt already sent.
#[test]
fn a_retried_rejected_push_sends_nothing_new() {
    let env = Env::new();
    let (alice, hub, bob) = team(&env);
    env.commit("bob", &bob, "bob", &[("b.txt", "b\n")]);
    env.ok("bob", &bob, &["push"]);
    env.commit(
        "alice",
        &alice,
        "alice",
        &[("c.txt", &"alice's work\n".repeat(50))],
    );
    env.fails("alice", &alice, &["push"]);
    let packs_after_first = packs(&hub).len();
    let out = env.fails("alice", &alice, &["--no-snapshot", "push"]);
    assert!(out.contains("Pushed 0 object(s)"), "{out}");
    assert_eq!(packs(&hub).len(), packs_after_first, "a new pack per retry");
}

// Scenario from git t5516-fetch-push.sh: "push --force with no divergence" is an ordinary push.
#[test]
fn force_push_without_divergence_is_an_ordinary_push() {
    let env = Env::new();
    let (alice, _hub, _bob) = team(&env);
    env.commit("alice", &alice, "two", &[("a.txt", "a2\n")]);
    let out = env.ok("alice", &alice, &["push", "--force"]);
    assert!(out.contains("pushed main"), "{out}");
}

// Scenario from git t5516-fetch-push.sh: pushing a tag moved backwards needs --force.
#[test]
fn a_tag_moved_backwards_needs_force_to_reach_the_remote() {
    let env = Env::new();
    let (alice, hub, _bob) = team(&env);
    env.commit("alice", &alice, "two", &[("a.txt", "a2\n")]);
    env.ok("alice", &alice, &["push"]);
    env.ok(
        "alice",
        &alice,
        &["tag", "set", "main", "-r", "main-", "--allow-backwards"],
    );
    env.fails("alice", &alice, &["push"]);
    let before = open_repo(&hub).view().tags["main"].target;
    env.ok("alice", &alice, &["push", "--force"]);
    let after = open_repo(&hub).view().tags["main"].target;
    assert_ne!(before, after);
    assert_eq!(
        after.short(),
        env.tag_target("alice", &alice, "main").unwrap()
    );
}

// Scenario from git t5516-fetch-push.sh: "push with a refspec" pushes only that branch.
#[test]
fn push_dash_t_sends_only_the_named_tags() {
    let env = Env::new();
    let (alice, hub, _bob) = team(&env);
    env.ok("alice", &alice, &["tag", "set", "one", "-r", "main"]);
    env.ok("alice", &alice, &["tag", "set", "two", "-r", "main"]);
    env.ok("alice", &alice, &["push", "-t", "one"]);
    let tags = open_repo(&hub).view().tags.clone();
    assert!(
        tags.contains_key("one") && !tags.contains_key("two"),
        "{:?}",
        tags.keys()
    );
    env.ok("alice", &alice, &["push", "-t", "two", "-t", "one"]);
    assert!(open_repo(&hub).view().tags.contains_key("two"));
}

// Scenario from git t5529-push-errors.sh: "detect missing branches early".
#[test]
fn push_dash_t_with_an_unknown_tag_fails_before_touching_the_remote() {
    let env = Env::new();
    let (alice, hub, _bob) = team(&env);
    let ops = op_count(&hub);
    let out = env.fails("alice", &alice, &["push", "-t", "nope"]);
    assert!(out.contains("nope"), "{out}");
    assert_eq!(op_count(&hub), ops);
}

// Scenario from git t5529-push-errors.sh: "suggest <remote> <branch> for a <remote>/<branch> slip".
#[test]
fn push_dash_t_with_a_remote_tag_name_fails() {
    let env = Env::new();
    let (alice, _hub, _bob) = team(&env);
    env.ok("alice", &alice, &["pull"]);
    env.fails("alice", &alice, &["push", "-t", "origin/main"]);
}

// Scenario from git t5404-tracking-branches.sh: "check tracking branches updated correctly after push".
#[test]
#[ignore = "BUG-281: `vl push` does not update the REMOTE/TAG remote tags (`vl git push` does)"]
fn push_updates_the_remote_tags() {
    let env = Env::new();
    let (alice, _hub, _bob) = team(&env);
    env.ok("alice", &alice, &["pull"]);
    env.commit("alice", &alice, "two", &[("a.txt", "a2\n")]);
    env.ok("alice", &alice, &["push"]);
    assert_eq!(
        env.tag_target("alice", &alice, "origin/main"),
        env.tag_target("alice", &alice, "main")
    );
    env.ok("alice", &alice, &["tag", "set", "fresh", "-r", "main"]);
    env.ok("alice", &alice, &["push"]);
    assert!(env
        .tags("alice", &alice)
        .contains(&"origin/fresh".to_string()));
}

// Scenario from git t5404-tracking-branches.sh: "check tracking branches not updated for failed refs".
#[test]
fn a_rejected_push_leaves_the_remote_tag_alone() {
    let env = Env::new();
    let (alice, _hub, bob) = team(&env);
    env.ok("alice", &alice, &["pull"]);
    let before = env.tag_target("alice", &alice, "origin/main");
    env.commit("bob", &bob, "bob", &[("b.txt", "b\n")]);
    env.ok("bob", &bob, &["push"]);
    env.commit("alice", &alice, "alice", &[("c.txt", "c\n")]);
    env.fails("alice", &alice, &["push"]);
    assert_eq!(env.tag_target("alice", &alice, "origin/main"), before);
}

// Scenario from git t5404-tracking-branches.sh: "deleted branches have their tracking branches
// removed"; jj test_git_push.rs: `jj git push --deleted`. Deleting on the remote is explicit
// (`vl push --delete`, as `git push --delete`): a plain push never deletes there (control:
// `deleting_a_local_tag_never_removes_history_from_the_remote`).
#[test]
fn a_deleted_tag_stays_deleted_after_push_and_pull() {
    let env = Env::new();
    let (alice, hub, bob) = team(&env);
    env.ok("alice", &alice, &["tag", "set", "feature", "-r", "main"]);
    env.ok("alice", &alice, &["push"]);
    env.ok("bob", &bob, &["pull"]);
    env.ok("alice", &alice, &["tag", "delete", "feature"]);
    // A plain push and pull leave the remote's tag alone, and the local deletion sticks.
    env.ok("alice", &alice, &["push"]);
    let out = env.ok("alice", &alice, &["pull"]);
    assert!(
        !env.tags("alice", &alice).contains(&"feature".to_string()),
        "pull recreated the deleted tag: {out}"
    );
    assert!(open_repo(&hub).view().tags.contains_key("feature"));
    env.ok("alice", &alice, &["push", "--delete", "feature"]);
    assert!(!env
        .tags("alice", &alice)
        .contains(&"origin/feature".to_string()));
    env.ok("alice", &alice, &["pull"]);
    assert!(
        !env.tags("alice", &alice).contains(&"feature".to_string()),
        "pull recreated the deleted tag"
    );
    assert!(
        !open_repo(&hub).view().tags.contains_key("feature"),
        "the remote still has the deleted tag"
    );
    env.ok("bob", &bob, &["pull"]);
    assert!(
        !env.tags("bob", &bob)
            .contains(&"origin/feature".to_string()),
        "Bob's remote tag is never pruned"
    );
}

// Veil (BUG-280 design, after jj's deleted-but-tracked bookmarks): a tag deleted here comes
// back when a teammate moves it on the remote to work this repository has not seen.
#[test]
fn a_deleted_tag_comes_back_when_a_teammate_moves_it_on_the_remote() {
    let env = Env::new();
    let (alice, _hub, bob) = team(&env);
    env.ok("alice", &alice, &["tag", "set", "feature", "-r", "main"]);
    env.ok("alice", &alice, &["push"]);
    env.ok("bob", &bob, &["pull"]);
    env.ok("alice", &alice, &["tag", "delete", "feature"]);
    let out = env.ok("alice", &alice, &["pull"]);
    assert!(out.contains("kept deleted feature"), "{out}");
    env.commit("bob", &bob, "more", &[("f.txt", "f\n")]);
    env.ok("bob", &bob, &["tag", "set", "feature", "-r", "@-"]);
    env.ok("bob", &bob, &["push"]);
    let out = env.ok("alice", &alice, &["pull"]);
    assert!(out.contains("it is back"), "{out}");
    assert_eq!(
        env.tag_target("alice", &alice, "feature"),
        env.tag_target("bob", &bob, "feature")
    );
}

// Veil (BUG-280 design, like `git push --force-with-lease --delete`): deleting a tag that a
// teammate moved since is refused without --force.
#[test]
fn push_delete_is_refused_when_the_remote_moved_the_tag() {
    let env = Env::new();
    let (alice, hub, bob) = team(&env);
    env.ok("alice", &alice, &["tag", "set", "feature", "-r", "main"]);
    env.ok("alice", &alice, &["push"]);
    env.ok("bob", &bob, &["pull"]);
    env.commit("bob", &bob, "more", &[("f.txt", "f\n")]);
    env.ok("bob", &bob, &["tag", "set", "feature", "-r", "@-"]);
    env.ok("bob", &bob, &["push"]);
    env.ok("alice", &alice, &["tag", "delete", "feature"]);
    let (code, out) = env.code("alice", &alice, &["push", "--delete", "feature"]);
    assert_eq!(code, 1, "{out}");
    assert!(open_repo(&hub).view().tags.contains_key("feature"));
    env.ok("alice", &alice, &["push", "--delete", "feature", "--force"]);
    assert!(!open_repo(&hub).view().tags.contains_key("feature"));
    // Deleting again is not an error: the remote is as asked.
    env.ok("alice", &alice, &["push", "--delete", "feature"]);
}

// Veil: `vl push --delete` of a tag that still exists here is refused (the next push would
// publish it again), and touches nothing.
#[test]
fn push_delete_of_a_tag_that_still_exists_here_is_refused() {
    let env = Env::new();
    let (alice, hub, _bob) = team(&env);
    let out = env.fails("alice", &alice, &["push", "--delete", "main"]);
    assert!(out.contains("vl tag delete main"), "{out}");
    assert!(open_repo(&hub).view().tags.contains_key("main"));
}

// Scenario from git t5510-fetch.sh: "fetch --prune" removes remote-tracking refs gone on the remote.
// Here the remote is replaced by one without the tag.
#[test]
fn pull_prunes_remote_tags_that_are_gone_from_the_remote() {
    let env = Env::new();
    let (alice, _hub, _bob) = team(&env);
    env.ok("alice", &alice, &["tag", "set", "feature", "-r", "main"]);
    env.ok("alice", &alice, &["push"]);
    env.ok("alice", &alice, &["pull"]);
    // A second remote holding only main, and origin pointed at it.
    let other = env.project("carol", "carol", &[("c", "c\n")]);
    let _ = other;
    let fresh = env.path("hub2");
    env.ok(
        "alice",
        &alice,
        &["remote", "add", "tmp", fresh.to_str().unwrap()],
    );
    env.ok("alice", &alice, &["push", "tmp", "-t", "main"]);
    env.ok("alice", &alice, &["remote", "rm", "origin"]);
    env.ok(
        "alice",
        &alice,
        &["remote", "add", "origin", fresh.to_str().unwrap()],
    );
    env.ok("alice", &alice, &["pull"]);
    assert!(!env
        .tags("alice", &alice)
        .contains(&"origin/feature".to_string()));
}

// Scenario from jj test_bookmark_command.rs: deleting a local tag that exists on the remote,
// then pushing other work, never deletes data on the remote.
#[test]
fn deleting_a_local_tag_never_removes_history_from_the_remote() {
    let env = Env::new();
    let (alice, hub, _bob) = team(&env);
    env.ok("alice", &alice, &["tag", "delete", "main"]);
    env.ok("alice", &alice, &["push"]);
    let remote = open_repo(&hub);
    assert!(remote.view().tags.contains_key("main"));
    let out = env.ok("alice", &alice, &["fsck", "-R", hub.to_str().unwrap()]);
    assert!(out.contains("No corruption found"), "{out}");
}

// Scenario from git t5520-pull.sh / jj test_git_fetch.rs: pull never moves the working copy.
#[test]
fn pull_moves_tags_but_never_the_working_copy() {
    let env = Env::new();
    let (alice, _hub, bob) = team(&env);
    write(&alice, "wip.txt", "alice's unfinished work\n");
    env.ok("alice", &alice, &["status"]);
    env.commit("bob", &bob, "bob", &[("a.txt", "from bob\n")]);
    env.ok("bob", &bob, &["push"]);
    let out = env.ok("alice", &alice, &["pull"]);
    assert!(out.contains("updated main"), "{out}");
    assert_eq!(
        read(&alice, "a.txt"),
        "a\n",
        "the working copy was not moved"
    );
    assert_eq!(read(&alice, "wip.txt"), "alice's unfinished work\n");
    env.ok("alice", &alice, &["rebase", "-d", "main"]);
    assert_eq!(read(&alice, "a.txt"), "from bob\n");
    assert_eq!(read(&alice, "wip.txt"), "alice's unfinished work\n");
}

// Scenario from git t5510-fetch.sh: fetching a new branch creates its tracking ref (and,
// in Veil, a local tag).
#[test]
fn pull_creates_new_tags_and_remote_tags() {
    let env = Env::new();
    let (alice, _hub, bob) = team(&env);
    env.ok(
        "alice",
        &alice,
        &["tag", "set", "release/1.0", "-r", "main"],
    );
    env.ok(
        "alice",
        &alice,
        &["tag", "set", "v1.0.0-rc.1", "-r", "main"],
    );
    // Deliberate difference: Git allows any UTF-8 ref name; Veil tag names are ASCII.
    env.fails("alice", &alice, &["tag", "set", "ünï-tag", "-r", "main"]);
    env.ok("alice", &alice, &["push"]);
    let out = env.ok("bob", &bob, &["pull"]);
    assert!(out.contains("updated release/1.0"), "{out}");
    let tags = env.tags("bob", &bob);
    for t in [
        "release/1.0",
        "origin/release/1.0",
        "v1.0.0-rc.1",
        "origin/v1.0.0-rc.1",
    ] {
        assert!(tags.contains(&t.to_string()), "{t} missing: {tags:?}");
    }
    assert_eq!(
        env.stdout("bob", &bob, &["cat", "a.txt", "-r", "release/1.0"]),
        "a\n"
    );
}

// Scenario from git t5510-fetch.sh: a remote branch rewound by someone else; the local
// branch is not moved backwards, the tracking ref follows the remote.
#[test]
fn pull_after_the_remote_moved_backwards_keeps_the_local_tag() {
    let env = Env::new();
    let (alice, _hub, bob) = team(&env);
    env.commit("alice", &alice, "two", &[("a.txt", "a2\n")]);
    env.ok("alice", &alice, &["push"]);
    env.ok("bob", &bob, &["pull"]);
    let bobs = env.tag_target("bob", &bob, "main").unwrap();
    env.ok(
        "alice",
        &alice,
        &["tag", "set", "main", "-r", "main-", "--allow-backwards"],
    );
    env.ok("alice", &alice, &["push", "--force"]);
    let (code, out) = env.code("bob", &bob, &["pull"]);
    assert_eq!(code, 0, "{out}");
    assert_eq!(
        env.tag_target("bob", &bob, "main").unwrap(),
        bobs,
        "never moved backwards"
    );
    assert_eq!(
        env.tag_target("bob", &bob, "origin/main"),
        env.tag_target("alice", &alice, "main")
    );
}

// Scenario from git t5520-pull.sh: pull with diverged history warns, exits 0 and changes nothing local.
#[test]
fn pull_of_a_diverged_tag_warns_and_keeps_both_sides() {
    let env = Env::new();
    let (alice, _hub, bob) = team(&env);
    env.commit("bob", &bob, "bob", &[("b.txt", "b\n")]);
    env.ok("bob", &bob, &["push"]);
    env.commit("alice", &alice, "alice", &[("c.txt", "c\n")]);
    let mine = env.tag_target("alice", &alice, "main").unwrap();
    let (code, out) = env.code("alice", &alice, &["pull"]);
    assert_eq!(code, 0, "{out}");
    assert!(
        out.contains("diverged") && out.contains("vl merge origin/main"),
        "{out}"
    );
    assert_eq!(env.tag_target("alice", &alice, "main").unwrap(), mine);
    assert_eq!(
        env.tag_target("alice", &alice, "origin/main"),
        env.tag_target("bob", &bob, "main")
    );
}

// Scenario from git t5520-pull.sh: pulling from a remote that does not exist (any more).
#[test]
fn pull_from_a_vanished_remote_fails_and_changes_nothing() {
    let env = Env::new();
    let (alice, hub, _bob) = team(&env);
    std::fs::remove_dir_all(&hub).unwrap();
    let ops = op_count(&alice);
    let out = env.fails("alice", &alice, &["--no-snapshot", "pull"]);
    assert!(out.contains("origin"), "{out}");
    assert_eq!(op_count(&alice), ops);
    assert!(!hub.exists(), "pull does not create the remote");
}

// Scenario from git t5520-pull.sh: pull from an empty remote.
#[test]
fn pull_from_an_empty_remote_succeeds_with_nothing() {
    let env = Env::new();
    let empty = env.dir("empty-src");
    env.ok("carol", &empty, &["init"]);
    env.ok("carol", &empty, &["remote", "add", "origin", "../ehub"]);
    env.ok("carol", &empty, &["push"]);
    let proj = env.project("alice", "proj", &[("a", "a\n")]);
    env.ok("alice", &proj, &["remote", "add", "e", "../ehub"]);
    let out = env.ok("alice", &proj, &["pull", "e"]);
    assert!(out.contains("Pulled 0 object(s)"), "{out}");
    assert_eq!(env.tags("alice", &proj), vec!["main".to_string()]);
}

// Scenario from git t5514-fetch-multiple.sh: two remotes keep separate remote tags.
#[test]
fn two_remotes_have_separate_remote_tags() {
    let env = Env::new();
    let (alice, _hub, _bob) = team(&env);
    let p2 = env.project("carol", "carol", &[("c.txt", "carol\n")]);
    env.ok("carol", &p2, &["remote", "add", "origin", "../hub2"]);
    env.ok("carol", &p2, &["push"]);
    env.ok("alice", &alice, &["remote", "add", "other", "../hub2"]);
    env.ok("alice", &alice, &["pull"]);
    let out = env.ok("alice", &alice, &["pull", "other"]);
    assert!(out.contains("diverged"), "unrelated main: {out}");
    let tags = env.tags("alice", &alice);
    assert!(
        tags.contains(&"origin/main".to_string()) && tags.contains(&"other/main".to_string()),
        "{tags:?}"
    );
    assert_ne!(
        env.tag_target("alice", &alice, "origin/main"),
        env.tag_target("alice", &alice, "other/main")
    );
    assert_eq!(
        env.stdout("alice", &alice, &["cat", "c.txt", "-r", "other/main"]),
        "carol\n"
    );
}

// Scenario from git t5516-fetch-push.sh: push into a repository that has a working copy
// (git's receive.denyCurrentBranch); Veil moves only tags, the other working copy stays.
#[test]
fn push_into_a_repository_with_a_working_copy_moves_tags_only() {
    let env = Env::new();
    let (alice, _hub, bob) = team(&env);
    write(&bob, "bob-wip.txt", "bob is editing\n");
    env.ok("bob", &bob, &["status"]);
    env.commit("alice", &alice, "two", &[("a.txt", "a2\n")]);
    env.ok(
        "alice",
        &alice,
        &["remote", "add", "bob", bob.to_str().unwrap()],
    );
    env.ok("alice", &alice, &["push", "bob"]);
    assert_eq!(read(&bob, "a.txt"), "a\n");
    assert_eq!(read(&bob, "bob-wip.txt"), "bob is editing\n");
    assert_eq!(
        env.stdout("bob", &bob, &["cat", "a.txt", "-r", "main"]),
        "a2\n"
    );
    let st = env.ok("bob", &bob, &["status"]);
    assert!(st.contains("bob-wip.txt"), "{st}");
}

// Scenario from git t5516-fetch-push.sh: "fetch/push from a bare repository" with `-R`.
#[test]
fn read_only_commands_and_gc_work_on_a_bare_remote() {
    let env = Env::new();
    let (_alice, hub, _bob) = team(&env);
    let h = hub.to_str().unwrap();
    env.ok("alice", &env.root, &["-R", h, "fsck"]);
    let tags = env.ok("alice", &env.root, &["-R", h, "tag", "list"]);
    assert!(tags.contains("main"), "{tags}");
    env.ok("alice", &env.root, &["-R", h, "log"]);
    env.ok("alice", &env.root, &["-R", h, "gc"]);
}

// Veil (BUG-284): commands that need a working copy are refused in a bare repository with a
// clear message, and nothing is written there.
#[test]
fn working_copy_commands_are_refused_on_a_bare_remote() {
    let env = Env::new();
    let (_alice, hub, _bob) = team(&env);
    let h = hub.to_str().unwrap();
    let ops = op_count(&hub);
    for args in [
        &["status"][..],
        &["new", "main"],
        &["tag", "set", "x", "-r", "main"],
    ] {
        let mut full = vec!["-R", h];
        full.extend_from_slice(args);
        let out = env.fails("alice", &env.root, &full);
        assert!(out.contains("bare repository"), "{args:?}: {out}");
    }
    assert_eq!(op_count(&hub), ops);
    let out = env.ok("alice", &env.root, &["-R", h, "show", "main"]);
    assert!(out.contains("Change"), "{out}");
}

// Scenario from jj test_git_push.rs: pushing from two workspaces of one repository.
#[test]
fn push_of_a_tag_set_in_another_workspace() {
    let env = Env::new();
    let (alice, hub, _bob) = team(&env);
    env.ok("alice", &alice, &["ws", "new", "side", "-r", "main"]);
    env.ok("alice", &alice, &["ws", "write", "side", "side.txt"]);
    env.ok("alice", &alice, &["tag", "set", "side-tag", "-r", "side@"]);
    env.ok("alice", &alice, &["push", "-t", "side-tag"]);
    assert!(open_repo(&hub).view().tags.contains_key("side-tag"));
}

// Scenario from git t5516-fetch-push.sh: many tags in one push.
#[test]
fn push_and_pull_of_many_tags() {
    let env = Env::new();
    let (alice, hub, bob) = team(&env);
    for i in 0..60 {
        env.ok(
            "alice",
            &alice,
            &[
                "--no-snapshot",
                "tag",
                "set",
                &format!("t{i:02}"),
                "-r",
                "main",
            ],
        );
    }
    env.ok("alice", &alice, &["push"]);
    assert_eq!(open_repo(&hub).view().tags.len(), 61);
    env.ok("bob", &bob, &["pull"]);
    assert_eq!(env.tags("bob", &bob).len(), 122);
}

// Scenario from git t5516-fetch-push.sh: history with many commits pushes and pulls incrementally.
#[test]
fn incremental_push_and_pull_send_only_what_is_new() {
    let env = Env::new();
    let (alice, _hub, bob) = team(&env);
    for i in 0..10 {
        env.commit(
            "alice",
            &alice,
            &format!("c{i}"),
            &[(&format!("f{i}.txt"), &format!("{i}\n"))],
        );
    }
    env.ok("alice", &alice, &["push"]);
    env.ok("bob", &bob, &["pull"]);
    env.commit("alice", &alice, "one more", &[("new.txt", "n\n")]);
    let out = env.ok("alice", &alice, &["push"]);
    // One snapshot, one root tree, one blob.
    assert!(out.contains("Pushed 3 object(s)"), "{out}");
    let out = env.ok("bob", &bob, &["pull"]);
    assert!(out.contains("Pulled 3 object(s)"), "{out}");
}

// Scenario from git t5516-fetch-push.sh: `push --full` and `pull --full` on healthy repositories.
#[test]
fn full_push_and_pull_on_healthy_repositories_change_nothing() {
    let env = Env::new();
    let (alice, hub, bob) = team(&env);
    let tags_before = open_repo(&hub).view().tags.clone();
    env.ok("alice", &alice, &["push", "--full"]);
    env.ok("bob", &bob, &["pull", "--full"]);
    let tags_after = open_repo(&hub).view().tags.clone();
    assert_eq!(
        tags_before.keys().collect::<Vec<_>>(),
        tags_after.keys().collect::<Vec<_>>()
    );
    env.ok("bob", &bob, &["fsck"]);
}

// Scenario from git t5520-pull.sh: pull with uncommitted edits in the working copy.
#[test]
fn pull_with_unrecorded_edits_keeps_them() {
    let env = Env::new();
    let (alice, _hub, bob) = team(&env);
    env.commit("bob", &bob, "bob", &[("a.txt", "bob edit\n")]);
    env.ok("bob", &bob, &["push"]);
    write(&alice, "a.txt", "alice's local edit\n");
    env.ok("alice", &alice, &["--no-snapshot", "pull"]);
    assert_eq!(read(&alice, "a.txt"), "alice's local edit\n");
    let diff = env.ok("alice", &alice, &["diff"]);
    assert!(diff.contains("alice's local edit"), "{diff}");
}

// Scenario from jj test_operations.rs / test_git_fetch.rs ("undo a fetch"): a pull is an
// operation; undo puts the tags back, and pulling again redoes it.
#[test]
fn undo_reverts_a_pull_and_a_second_pull_redoes_it() {
    let env = Env::new();
    let (alice, _hub, bob) = team(&env);
    let before = env.tag_target("bob", &bob, "main");
    env.commit("alice", &alice, "two", &[("a.txt", "a2\n")]);
    env.ok("alice", &alice, &["push"]);
    env.ok("bob", &bob, &["pull"]);
    let after = env.tag_target("bob", &bob, "main");
    assert_ne!(before, after);
    let ops = env.stdout("bob", &bob, &["op", "log", "-n", "3"]);
    assert!(ops.contains("pull from origin"), "{ops}");
    let out = env.ok("bob", &bob, &["undo"]);
    assert!(out.contains("pull from origin"), "{out}");
    assert_eq!(env.tag_target("bob", &bob, "main"), before);
    env.ok("bob", &bob, &["pull"]);
    assert_eq!(env.tag_target("bob", &bob, "main"), after);
    env.ok("bob", &bob, &["fsck"]);
}
