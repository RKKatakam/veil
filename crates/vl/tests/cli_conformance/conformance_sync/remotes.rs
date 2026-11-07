//! `vl remote add|list|rm`: a remote is a Veil server project
//! (`veil://host/project`). Tests that push or pull use the path remotes
//! of the test fixture (`crates/vl/src/test_remotes.rs`).

use super::support::*;

// Scenario from git t5505-remote.sh: "add another remote" / "remote information for the origin".
#[test]
fn remote_add_list_shows_name_and_url() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a", "a\n")]);
    let out = env.ok("alice", &proj, &["remote", "add", "origin", "veil://hub.example/proj"]);
    assert!(out.contains("Added remote origin → veil://hub.example/proj"), "{out}");
    env.ok("alice", &proj, &["remote", "add", "mirror", "https://hub.example:8443/mirror"]);
    let list = env.stdout("alice", &proj, &["remote", "list"]);
    let lines: Vec<&str> = list.lines().collect();
    assert_eq!(lines.len(), 2, "{list}");
    assert!(lines.iter().any(|l| l.starts_with("mirror") && l.contains("https://hub.example:8443/mirror")), "{list}");
    assert!(lines.iter().any(|l| l.starts_with("origin") && l.contains("veil://hub.example/proj")), "{list}");
}

// Scenario from git t5505-remote.sh: adding a remote whose name already exists fails.
#[test]
fn remote_add_refuses_a_duplicate_name_and_keeps_the_original() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a", "a\n")]);
    env.ok("alice", &proj, &["remote", "add", "origin", "veil://hub.example/proj"]);
    let out = env.fails("alice", &proj, &["remote", "add", "origin", "veil://hub.example/other"]);
    assert!(out.contains("already exists"), "{out}");
    let list = env.stdout("alice", &proj, &["remote", "list"]);
    assert!(list.contains("veil://hub.example/proj") && !list.contains("other"), "{list}");
}

// Scenario from git t5505-remote.sh: "remove remote".
#[test]
fn remote_rm_removes_the_configuration_but_not_the_remote_data() {
    let env = Env::new();
    let (proj, hub) = env.project_with_hub("alice", "proj", "hub", &[("a", "a\n")]);
    env.ok("alice", &proj, &["remote", "rm", "origin"]);
    assert_eq!(env.stdout("alice", &proj, &["remote", "list"]).trim(), "");
    assert!(
        hub.join(".veil/repo.json").exists(),
        "the remote's data stays"
    );
    let out = env.fails("alice", &proj, &["push"]);
    assert!(out.contains("no remote named 'origin'"), "{out}");
}

// Scenario from git t5505-remote.sh: "remove errors out early when deleting non-existent branch".
#[test]
fn remote_rm_of_an_unknown_remote_fails() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a", "a\n")]);
    let out = env.fails("alice", &proj, &["remote", "rm", "nope"]);
    assert!(out.contains("nope"), "{out}");
}

// Scenario from git t5505-remote.sh: "remove remote" also removes its remote-tracking branches.
#[test]
fn remote_rm_drops_its_remote_tags() {
    let env = Env::new();
    let (proj, _hub) = env.project_with_hub("alice", "proj", "hub", &[("a", "a\n")]);
    env.ok("alice", &proj, &["pull"]);
    assert!(env
        .tags("alice", &proj)
        .contains(&"origin/main".to_string()));
    env.ok("alice", &proj, &["remote", "rm", "origin"]);
    let tags = env.tags("alice", &proj);
    assert!(
        !tags.iter().any(|t| t.starts_with("origin/")),
        "stale remote tags after `remote rm`: {tags:?}"
    );
}

// Scenario from git t5505-remote.sh: "rename errors out early when new name is invalid".
#[test]
fn remote_add_refuses_invalid_names() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a", "a\n")]);
    for bad in ["", "has space", "origin/main", "../evil", "-x"] {
        let out = env.vl("alice", &proj, &["remote", "add", "--", bad, "../hub"]);
        assert!(
            !out.status.success(),
            "remote name {bad:?} was accepted: {}",
            text(&out)
        );
    }
}

// Scenario from git t5505-remote.sh / t5528: pushing or pulling a remote that is not configured.
#[test]
fn push_and_pull_to_an_unknown_remote_fail_with_a_hint() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a", "a\n")]);
    let out = env.fails("alice", &proj, &["push"]);
    assert!(out.contains("vl remote add origin"), "{out}");
    let out = env.fails("alice", &proj, &["pull", "upstream"]);
    assert!(out.contains("upstream"), "{out}");
}

// Scenario from git t5505-remote.sh: remote commands outside a repository.
#[test]
fn remote_commands_outside_a_repository_fail() {
    let env = Env::new();
    let nowhere = env.dir("nowhere");
    env.fails("alice", &nowhere, &["remote", "list"]);
    env.fails("alice", &nowhere, &["push"]);
    env.fails("alice", &nowhere, &["pull"]);
    assert!(!nowhere.join(".veil").exists());
}

// Scenario from git t5505: a relative remote path is relative to the repository root, not the cwd.
#[test]
fn a_relative_remote_path_resolves_against_the_repository_root_from_a_subdirectory() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("sub/deep/a", "a\n")]);
    env.ok("alice", &proj, &["remote", "add", "origin", "../hub"]);
    env.ok("alice", &proj.join("sub/deep"), &["push"]);
    assert!(
        env.path("hub/.veil/repo.json").exists(),
        "created next to the repository"
    );
    assert!(!proj.join("sub/hub").exists() && !proj.join("hub").exists());
    env.ok("alice", &proj.join("sub"), &["pull"]);
}

// Scenario from git t9904-url-parse.sh / t5601: unsupported URLs are refused
// up front. Without the test fixture, as users run vl, a remote is a Veil
// server project and nothing else: no paths, no SSH or SFTP.
#[test]
fn anything_but_a_veil_server_project_is_refused() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a", "a\n")]);
    let product = |args: &[&str]| {
        let out = env.cmd("alice", &proj, args).env_remove("VEIL_TEST_PATH_REMOTES").output().unwrap();
        (out.status.success(), text(&out))
    };
    for url in [
        "../hub",
        "/abs/hub",
        "file:///tmp/x",
        "http://example.com/r",
        "ssh://host/abs/repo",
        "sftp://host/abs",
        "user@host:repo",
        "git://example.com/r",
    ] {
        let (ok, out) = product(&["remote", "add", "r", "--", url]);
        assert!(!ok && out.contains("is not a Veil server project"), "{url}: {out}");
    }
    let (ok, out) = product(&["remote", "add", "r", "veil://hub.example"]);
    assert!(!ok && out.contains("names a project"), "{out}");
    let (ok, out) = product(&["clone", "../hub", "copy"]);
    assert!(!ok && out.contains("is not a Veil server project"), "{out}");
    assert!(!env.path("copy").exists());
    assert_eq!(env.stdout("alice", &proj, &["remote", "list"]).trim(), "");
}

// Scenario from git t5505: `remote list` on a fresh repository is empty and succeeds.
#[test]
fn remote_list_is_empty_on_a_fresh_repository() {
    let env = Env::new();
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    assert_eq!(env.stdout("alice", &proj, &["remote", "list"]).trim(), "");
}

// Scenario from git t5505 ("add existing remote" after removal): a removed name can be reused.
#[test]
fn a_removed_remote_name_can_be_added_again() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a", "a\n")]);
    env.ok("alice", &proj, &["remote", "add", "origin", "veil://hub.example/proj"]);
    env.ok("alice", &proj, &["remote", "rm", "origin"]);
    env.ok("alice", &proj, &["remote", "add", "origin", "veil://other.example/proj"]);
    let list = env.stdout("alice", &proj, &["remote", "list"]);
    assert!(list.contains("veil://other.example/proj") && !list.contains("hub.example"), "{list}");
}
