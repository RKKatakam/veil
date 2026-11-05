//! `vl remote add|list|rm` and remote URL parsing (path, scp-style, ssh://).

use super::support::*;

// Scenario from git t5505-remote.sh: "add another remote" / "remote information for the origin".
#[test]
fn remote_add_list_shows_kind_and_url() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a", "a\n")]);
    let out = env.ok("alice", &proj, &["remote", "add", "origin", "../hub"]);
    assert!(out.contains("Added team remote origin"), "{out}");
    let out = env.ok(
        "alice",
        &proj,
        &["remote", "add", "mirror", "../mirror", "--public"],
    );
    assert!(out.contains("Added public remote mirror"), "{out}");
    let list = env.stdout("alice", &proj, &["remote", "list"]);
    let lines: Vec<&str> = list.lines().collect();
    assert_eq!(lines.len(), 2, "{list}");
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("mirror") && l.contains("public") && l.contains("../mirror")),
        "{list}"
    );
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("origin") && l.contains("team") && l.contains("../hub")),
        "{list}"
    );
}

// Scenario from git t5505-remote.sh: adding a remote whose name already exists fails.
#[test]
fn remote_add_refuses_a_duplicate_name_and_keeps_the_original() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a", "a\n")]);
    env.ok("alice", &proj, &["remote", "add", "origin", "../hub"]);
    let out = env.fails(
        "alice",
        &proj,
        &["remote", "add", "origin", "../other", "--public"],
    );
    assert!(out.contains("already exists"), "{out}");
    let list = env.stdout("alice", &proj, &["remote", "list"]);
    assert!(
        list.contains("../hub") && !list.contains("../other") && list.contains("team"),
        "{list}"
    );
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

// Scenario from git t9904-url-parse.sh / t5601: unsupported schemes are refused up front.
#[test]
fn unsupported_url_schemes_are_refused() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a", "a\n")]);
    for url in [
        "file:///tmp/x",
        "http://example.com/r",
        "https://example.com/r",
        "git://example.com/r",
    ] {
        let out = env.fails("alice", &proj, &["remote", "add", "r", url]);
        assert!(out.contains("unsupported scheme"), "{url}: {out}");
    }
    assert_eq!(env.stdout("alice", &proj, &["remote", "list"]).trim(), "");
}

// Scenario from git t9904-url-parse.sh: malformed ssh URLs (bad port, option-like host or user).
#[test]
fn malformed_ssh_urls_are_refused() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a", "a\n")]);
    for url in [
        "ssh://host:notaport/r",
        "ssh://host:0/r",
        "ssh://host:70000/r",
        "ssh://-oProxyCommand=evil/r",
        "-oProxyCommand=evil:r",
        "ssh://-l@host/r",
        "ssh://[::1/r",
        "ssh:///r",
        "@host:r",
    ] {
        let out = env.vl("alice", &proj, &["remote", "add", "r", "--", url]);
        assert!(!out.status.success(), "{url} accepted: {}", text(&out));
        assert!(exited_cleanly(&out));
    }
}

// Scenario from git t9904-url-parse.sh / t5601 ("clone ssh://... / host:path"): accepted forms.
#[test]
fn ssh_url_forms_are_accepted() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a", "a\n")]);
    for (i, url) in [
        "host:repo",
        "user@host:repo",
        "user@host:/abs/repo",
        "ssh://host/abs/repo",
        "ssh://user@host:2222/abs/repo",
        "ssh://host/~/rel",
        "sftp://host/abs",
        "[::1]:repo",
        "user@[::1]:repo",
        "ssh://[::1]:22/repo",
    ]
    .iter()
    .enumerate()
    {
        let name = format!("r{i}");
        env.ok("alice", &proj, &["remote", "add", &name, url]);
    }
    let list = env.stdout("alice", &proj, &["remote", "list"]);
    assert_eq!(list.lines().count(), 10, "{list}");
}

// Scenario from git t9904-url-parse.sh: a ':' after a '/' is a local path, not scp-style.
#[test]
fn a_colon_after_a_slash_is_a_local_path() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a", "a\n")]);
    env.ok("alice", &proj, &["remote", "add", "odd", "./odd:name"]);
    env.ok("alice", &proj, &["push", "odd"]);
    assert!(
        proj.join("odd:name/.veil/repo.json").exists(),
        "pushed to a local directory named odd:name"
    );
    let abs = env.path("abs:dir");
    env.ok(
        "alice",
        &proj,
        &["remote", "add", "abs", abs.to_str().unwrap()],
    );
    env.ok("alice", &proj, &["push", "abs"]);
    assert!(abs.join(".veil/repo.json").exists());
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
fn a_removed_remote_name_can_be_added_again_with_another_kind() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a", "a\n")]);
    env.ok("alice", &proj, &["remote", "add", "origin", "../hub"]);
    env.ok("alice", &proj, &["remote", "rm", "origin"]);
    env.ok(
        "alice",
        &proj,
        &["remote", "add", "origin", "../mirror", "--public"],
    );
    let list = env.stdout("alice", &proj, &["remote", "list"]);
    assert!(
        list.contains("public") && list.contains("../mirror"),
        "{list}"
    );
}
