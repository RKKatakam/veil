//! `vl git import|remote|fetch|pull|push|export` against local bare Git
//! repositories (plain `git` plays GitHub): remotes, divergence, force,
//! deletion, and what Git may see.

use crate::support::*;

// Scenario from jj test_git_init.rs / test_git_clone.rs: import an existing Git repository.
#[test]
fn git_import_brings_branches_as_tags_and_checks_out_main() {
    let env = Env::new();
    let (bare, wc) = git_upstream(&env, "gh.git", &[("app.txt", "v1\n")]);
    git(&wc, &["checkout", "-q", "-b", "feature/x"]);
    write(&wc, "f.txt", "feature\n");
    git(&wc, &["add", "-A"]);
    git(&wc, &["commit", "-q", "-m", "feature"]);
    git(&wc, &["push", "-q", "origin", "feature/x"]);
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    let out = env.ok("alice", &proj, &["git", "import", bare.to_str().unwrap()]);
    assert!(out.contains("Imported 2 commit(s)"), "{out}");
    assert_eq!(read(&proj, "app.txt"), "v1\n");
    assert!(!proj.join("f.txt").exists(), "the working copy is on main");
    let tags = env.tags("alice", &proj);
    for t in ["main", "origin/main", "feature/x", "origin/feature/x"] {
        assert!(tags.contains(&t.to_string()), "{t}: {tags:?}");
    }
    assert!(env
        .stdout("alice", &proj, &["git", "remote", "list"])
        .contains("origin"));
}

// Scenario from jj test_git_import_export.rs: importing twice imports nothing new.
#[test]
fn git_import_and_fetch_again_import_nothing() {
    let env = Env::new();
    let (bare, _wc) = git_upstream(&env, "gh.git", &[("a", "a\n")]);
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    env.ok("alice", &proj, &["git", "import", bare.to_str().unwrap()]);
    let log = env.stdout("alice", &proj, &["log"]);
    let out = env.ok("alice", &proj, &["git", "fetch"]);
    assert!(out.contains("Imported 0 commit(s)"), "{out}");
    let out = env.ok("alice", &proj, &["git", "pull"]);
    assert!(out.contains("Imported 0 commit(s)"), "{out}");
    assert_eq!(env.stdout("alice", &proj, &["log"]), log);
}

// Scenario from git t5605-clone-local.sh "clone empty repository" / jj test_git_clone.rs
// (empty remote): importing a Git repository with no branches.
#[test]
fn git_import_of_an_empty_git_repository() {
    let env = Env::new();
    let bare = env.path("empty.git");
    git(&env.root, &["init", "-q", "--bare", bare.to_str().unwrap()]);
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    let out = env.ok("alice", &proj, &["git", "import", bare.to_str().unwrap()]);
    assert!(out.contains("Imported 0 commit(s)"), "{out}");
    assert!(env.tags("alice", &proj).is_empty());
    // Then the first Veil push creates main there.
    write(&proj, "a.txt", "a\n");
    env.ok("alice", &proj, &["commit", "-m", "first"]);
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "@-"]);
    let out = env.ok("alice", &proj, &["git", "push"]);
    assert!(
        out.contains("pushed main") && out.contains("new branch"),
        "{out}"
    );
    assert_eq!(git(&bare, &["show", "main:a.txt"]), "a");
}

// Scenario from git t5600-clone-fail-cleanup.sh / jj test_git_clone.rs: import of a missing repo fails.
#[test]
fn git_import_of_a_missing_repository_fails_cleanly() {
    let env = Env::new();
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    env.fails(
        "alice",
        &proj,
        &["git", "import", env.path("nope.git").to_str().unwrap()],
    );
    assert!(env.tags("alice", &proj).is_empty());
    env.ok("alice", &proj, &["status"]);
}

// Scenario from git t5600-clone-fail-cleanup.sh ("failed clone should not leave a directory"):
// a failed import must not leave its remote behind, so that retrying with the right URL works.
#[test]
#[ignore = "BUG-292: a failed `vl git import` keeps the Git remote it added; retrying with the right URL is refused"]
fn a_failed_git_import_can_be_retried_with_the_right_url() {
    let env = Env::new();
    let (bare, _wc) = git_upstream(&env, "gh.git", &[("a", "a\n")]);
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    env.fails(
        "alice",
        &proj,
        &["git", "import", env.path("typo.git").to_str().unwrap()],
    );
    let list = env.stdout("alice", &proj, &["git", "remote", "list"]);
    assert!(
        !list.contains("typo"),
        "a failed import left a remote: {list}"
    );
    env.ok("alice", &proj, &["git", "import", bare.to_str().unwrap()]);
}

// Scenario from jj test_git_remotes.rs ("remove a remote"): removal works and drops its remote tags.
#[test]
#[ignore = "BUG-291: `vl git remote rm` deadlocks on its own lock: fails after 15 s, leaving the remote tags"]
fn git_remote_rm_removes_the_remote_and_its_remote_tags() {
    let env = Env::new();
    let (bare, _wc) = git_upstream(&env, "gh.git", &[("a", "a\n")]);
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    env.ok("alice", &proj, &["git", "import", bare.to_str().unwrap()]);
    assert!(env
        .tags("alice", &proj)
        .contains(&"origin/main".to_string()));
    let start = std::time::Instant::now();
    env.ok("alice", &proj, &["git", "remote", "rm", "origin"]);
    assert!(
        start.elapsed() < std::time::Duration::from_secs(5),
        "took {:?}",
        start.elapsed()
    );
    assert!(!env
        .stdout("alice", &proj, &["git", "remote", "list"])
        .contains("origin"));
    assert!(
        !env.tags("alice", &proj)
            .iter()
            .any(|t| t.starts_with("origin/")),
        "{:?}",
        env.tags("alice", &proj)
    );
    assert!(
        env.tags("alice", &proj).contains(&"main".to_string()),
        "local tags stay"
    );
}

// Scenario from jj test_git_remotes.rs: add, list, duplicate names, removing an unknown one.
#[test]
fn git_remote_add_list_rm_and_duplicates() {
    let env = Env::new();
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    let a = env.path("a.git");
    git(&env.root, &["init", "-q", "--bare", a.to_str().unwrap()]);
    env.ok(
        "alice",
        &proj,
        &["git", "remote", "add", "gh", a.to_str().unwrap()],
    );
    env.fails(
        "alice",
        &proj,
        &["git", "remote", "add", "gh", a.to_str().unwrap()],
    );
    env.ok(
        "alice",
        &proj,
        &[
            "git",
            "remote",
            "add",
            "lab",
            "https://gitlab.example.com/me/p.git",
        ],
    );
    let list = env.stdout("alice", &proj, &["git", "remote", "list"]);
    assert!(
        list.contains("gh") && list.contains("lab") && list.contains("gitlab.example.com"),
        "{list}"
    );
    env.fails("alice", &proj, &["git", "remote", "rm", "never-added"]);
}

// Scenario from jj test_git_remotes.rs: a relative path is stored absolute (works from anywhere).
#[test]
fn a_relative_git_remote_path_is_stored_absolute() {
    let env = Env::new();
    let (_bare, _wc) = git_upstream(&env, "gh.git", &[("a", "a\n")]);
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    write(&proj, "sub/x", "x\n");
    env.ok(
        "alice",
        &proj.join("sub"),
        &["git", "remote", "add", "origin", "../../gh.git"],
    );
    let list = env.stdout("alice", &proj, &["git", "remote", "list"]);
    assert!(
        list.contains(env.path("gh.git").to_str().unwrap()),
        "{list}"
    );
    env.ok("alice", &proj.join("sub"), &["git", "fetch"]);
}

// Scenario from git t5505 / jj test_git_remotes.rs: credentials in URLs are never printed.
#[test]
fn credentials_in_git_remote_urls_are_redacted() {
    let env = Env::new();
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    let out = env.ok(
        "alice",
        &proj,
        &[
            "git",
            "remote",
            "add",
            "gh",
            "https://bob:s3cr3t-tok@github.example.com/me/p.git",
        ],
    );
    assert!(!out.contains("s3cr3t-tok"), "{out}");
    let list = env.stdout("alice", &proj, &["git", "remote", "list"]);
    assert!(
        !list.contains("s3cr3t-tok") && list.contains("***"),
        "{list}"
    );
}

// Scenario from git t5505/t5601 (URLs that look like options): never reach `git` as options.
// Veil stores such a "URL" as a relative path made absolute, which git cannot misread.
#[test]
fn option_like_git_urls_never_reach_git_as_options() {
    let env = Env::new();
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    let marker = env.path("pwned");
    let url = format!("--upload-pack=touch {}", marker.display());
    let out = env.vl(
        "alice",
        &proj,
        &["git", "remote", "add", "evil", "--", &url],
    );
    if out.status.success() {
        let list = env.stdout("alice", &proj, &["git", "remote", "list"]);
        let stored = list
            .lines()
            .find(|l| l.starts_with("evil"))
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .to_string();
        assert!(stored.starts_with('/'), "stored as {stored}");
        let _ = env.vl("alice", &proj, &["git", "fetch", "evil"]);
    }
    assert!(!marker.exists(), "git ran the upload-pack option");
}

// Scenario from jj test_git_fetch.rs: fetch moves remote tags only; pull fast-forwards local tags.
#[test]
fn git_fetch_moves_remote_tags_and_pull_moves_local_tags() {
    let env = Env::new();
    let (bare, wc) = git_upstream(&env, "gh.git", &[("a", "a\n")]);
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    env.ok("alice", &proj, &["git", "import", bare.to_str().unwrap()]);
    let before = env.tag_target("alice", &proj, "main");
    write(&wc, "a", "a2\n");
    git_commit_push(&wc, "a2");
    env.ok("alice", &proj, &["git", "fetch"]);
    assert_eq!(
        env.tag_target("alice", &proj, "main"),
        before,
        "fetch moved a local tag"
    );
    assert_ne!(env.tag_target("alice", &proj, "origin/main"), before);
    let out = env.ok("alice", &proj, &["git", "pull"]);
    assert!(out.contains("updated main"), "{out}");
    assert_eq!(
        env.tag_target("alice", &proj, "main"),
        env.tag_target("alice", &proj, "origin/main")
    );
    // Never the working copy.
    assert_eq!(read(&proj, "a"), "a\n");
}

// Scenario from jj test_git_fetch.rs: a branch created on GitHub appears as a new tag.
#[test]
fn a_branch_created_on_github_becomes_a_tag_on_pull() {
    let env = Env::new();
    let (bare, wc) = git_upstream(&env, "gh.git", &[("a", "a\n")]);
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    env.ok("alice", &proj, &["git", "import", bare.to_str().unwrap()]);
    git(
        &wc,
        &["push", "-q", "origin", "HEAD:refs/heads/release/2.0"],
    );
    let out = env.ok("alice", &proj, &["git", "pull"]);
    assert!(out.contains("release/2.0"), "{out}");
    assert!(env
        .tags("alice", &proj)
        .contains(&"release/2.0".to_string()));
}

// Scenario from jj test_git_fetch.rs ("fetch after a branch was force-pushed upstream").
#[test]
fn a_branch_force_pushed_on_github_is_reported_and_local_tags_stay() {
    let env = Env::new();
    let (bare, wc) = git_upstream(&env, "gh.git", &[("a", "a\n")]);
    write(&wc, "a", "a2\n");
    git_commit_push(&wc, "a2");
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    env.ok("alice", &proj, &["git", "import", bare.to_str().unwrap()]);
    let mine = env.tag_target("alice", &proj, "main");
    git(&wc, &["reset", "-q", "--hard", "HEAD~1"]);
    write(&wc, "other", "rewritten\n");
    git(&wc, &["add", "-A"]);
    git(&wc, &["commit", "-q", "-m", "rewritten"]);
    git(
        &wc,
        &["push", "-q", "--force", "origin", "HEAD:refs/heads/main"],
    );
    let out = env.ok("alice", &proj, &["git", "pull"]);
    assert!(out.contains("force") || out.contains("diverged"), "{out}");
    assert_eq!(
        env.tag_target("alice", &proj, "main"),
        mine,
        "the local tag moved"
    );
    assert_eq!(
        env.stdout("alice", &proj, &["cat", "a", "-r", "main"]),
        "a2\n"
    );
    assert_eq!(
        env.stdout("alice", &proj, &["cat", "other", "-r", "origin/main"]),
        "rewritten\n"
    );
}

// Scenario from jj test_git_fetch.rs ("fetch with a branch deleted upstream").
#[test]
fn a_branch_deleted_on_github_is_reported_and_the_local_tag_kept() {
    let env = Env::new();
    let (bare, wc) = git_upstream(&env, "gh.git", &[("a", "a\n")]);
    git(&wc, &["push", "-q", "origin", "HEAD:refs/heads/doomed"]);
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    env.ok("alice", &proj, &["git", "import", bare.to_str().unwrap()]);
    git(&wc, &["push", "-q", "origin", "--delete", "doomed"]);
    let out = env.ok("alice", &proj, &["git", "fetch"]);
    assert!(out.contains("doomed") && out.contains("delete"), "{out}");
    let tags = env.tags("alice", &proj);
    assert!(tags.contains(&"doomed".to_string()), "{tags:?}");
    assert!(
        !tags.contains(&"origin/doomed".to_string()),
        "the remote tag is pruned: {tags:?}"
    );
}

// Scenario from jj test_git_push.rs ("push a deleted bookmark", `--deleted`).
#[test]
#[ignore = "BUG-280: a deleted tag is never deleted on the Git remote, and `vl git pull` recreates it"]
fn a_deleted_tag_deletes_the_git_branch_or_at_least_stays_deleted() {
    let env = Env::new();
    let (proj, bare) = veil_with_git_remote(&env, "alice", "proj", "gh.git");
    env.commit("alice", &proj, "a", &[("a", "a\n")]);
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "@-"]);
    env.ok("alice", &proj, &["tag", "set", "feature", "-r", "@-"]);
    env.ok("alice", &proj, &["git", "push"]);
    env.ok("alice", &proj, &["tag", "delete", "feature"]);
    env.ok("alice", &proj, &["git", "push"]);
    env.ok("alice", &proj, &["git", "pull"]);
    assert!(
        !env.tags("alice", &proj).contains(&"feature".to_string()),
        "git pull recreated the deleted tag"
    );
    assert!(
        !git_ok(
            &bare,
            &["rev-parse", "--verify", "-q", "refs/heads/feature"]
        ),
        "branch still on GitHub"
    );
}

// Scenario from git t5516 / jj test_git_push.rs: a push rejected because GitHub moved on.
#[test]
fn git_push_is_rejected_when_github_moved_on_then_merge_and_push() {
    let env = Env::new();
    let (bare, wc) = git_upstream(&env, "gh.git", &[("a", "a\n")]);
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    env.ok("alice", &proj, &["git", "import", bare.to_str().unwrap()]);
    env.commit("alice", &proj, "veil side", &[("v.txt", "veil\n")]);
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "@-"]);
    write(&wc, "g.txt", "github\n");
    git_commit_push(&wc, "github side");
    let (code, out) = env.code("alice", &proj, &["git", "push"]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("rejected main"), "{out}");
    let out = env.ok("alice", &proj, &["git", "pull"]);
    assert!(out.contains("diverged"), "{out}");
    env.ok(
        "alice",
        &proj,
        &[
            "merge",
            "origin/main",
            "--into",
            "main",
            "-m",
            "merge github",
        ],
    );
    env.ok("alice", &proj, &["git", "push"]);
    let files = git(&bare, &["ls-tree", "-r", "--name-only", "main"]);
    assert!(
        files.contains("g.txt") && files.contains("v.txt"),
        "{files}"
    );
    // GitHub's commit is an ancestor: nothing of theirs was overwritten.
    let theirs = git(&wc, &["rev-parse", "HEAD"]);
    assert!(git_ok(
        &bare,
        &["merge-base", "--is-ancestor", &theirs, "main"]
    ));
}

// Scenario from git t5533-push-cas.sh: "push to update (protected)" — --force only overwrites
// what was last fetched (force-with-lease).
#[test]
fn git_push_force_does_not_clobber_commits_never_fetched() {
    let env = Env::new();
    let (bare, wc) = git_upstream(&env, "gh.git", &[("a", "a\n")]);
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    env.ok("alice", &proj, &["git", "import", bare.to_str().unwrap()]);
    env.commit("alice", &proj, "veil", &[("v", "v\n")]);
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "@-"]);
    write(&wc, "unseen", "never fetched\n");
    git_commit_push(&wc, "unseen");
    let unseen = git(&wc, &["rev-parse", "HEAD"]);
    let (code, out) = env.code("alice", &proj, &["git", "push", "--force"]);
    assert_ne!(code, 0, "--force clobbered an unfetched commit: {out}");
    assert_eq!(git(&bare, &["rev-parse", "main"]), unseen);
}

// Scenario from git t5533-push-cas.sh: "push to update (allowed)" after fetching.
#[test]
fn git_push_force_overwrites_what_was_fetched() {
    let env = Env::new();
    let (bare, wc) = git_upstream(&env, "gh.git", &[("a", "a\n")]);
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    env.ok("alice", &proj, &["git", "import", bare.to_str().unwrap()]);
    env.commit("alice", &proj, "veil", &[("v", "v\n")]);
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "@-"]);
    write(&wc, "seen", "fetched\n");
    git_commit_push(&wc, "seen");
    env.ok("alice", &proj, &["git", "fetch"]);
    let out = env.ok("alice", &proj, &["git", "push", "--force"]);
    assert!(out.contains("pushed main"), "{out}");
    assert!(git(&bare, &["ls-tree", "--name-only", "main"]).contains('v'));
}

// Scenario from jj test_git_push.rs: push -t of one tag; unknown tag fails.
#[test]
fn git_push_dash_t_pushes_only_the_named_tags() {
    let env = Env::new();
    let (proj, bare) = veil_with_git_remote(&env, "alice", "proj", "gh.git");
    env.commit("alice", &proj, "a", &[("a", "a\n")]);
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "@-"]);
    env.ok("alice", &proj, &["tag", "set", "other", "-r", "@-"]);
    env.ok("alice", &proj, &["git", "push", "-t", "other"]);
    assert!(git_ok(
        &bare,
        &["rev-parse", "--verify", "-q", "refs/heads/other"]
    ));
    assert!(!git_ok(
        &bare,
        &["rev-parse", "--verify", "-q", "refs/heads/main"]
    ));
    env.fails("alice", &proj, &["git", "push", "-t", "nope"]);
}

// Scenario from git t5404-tracking-branches.sh, for the bridge: `vl git push` updates
// `origin/<branch>` (control for BUG-281).
#[test]
fn git_push_updates_the_remote_tags() {
    let env = Env::new();
    let (proj, _bare) = veil_with_git_remote(&env, "alice", "proj", "gh.git");
    env.commit("alice", &proj, "a", &[("a", "a\n")]);
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "@-"]);
    env.ok("alice", &proj, &["git", "push"]);
    assert_eq!(
        env.tag_target("alice", &proj, "origin/main"),
        env.tag_target("alice", &proj, "main")
    );
}

// Scenario from git t5516 / jj test_git_push.rs: pushing with nothing new is "up to date", exit 0.
#[test]
fn git_push_with_nothing_new_is_up_to_date() {
    let env = Env::new();
    let (proj, _bare) = veil_with_git_remote(&env, "alice", "proj", "gh.git");
    env.commit("alice", &proj, "a", &[("a", "a\n")]);
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "@-"]);
    env.ok("alice", &proj, &["git", "push"]);
    let (code, out) = env.code("alice", &proj, &["git", "push"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("up to date main"), "{out}");
}

// Scenario from jj test_git_import_export.rs: export without pushing prints each commit.
#[test]
fn git_export_writes_the_bridge_and_prints_commits_without_pushing() {
    let env = Env::new();
    let (proj, bare) = veil_with_git_remote(&env, "alice", "proj", "gh.git");
    env.commit("alice", &proj, "a", &[("a", "a\n")]);
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "@-"]);
    let out = env.ok("alice", &proj, &["git", "export"]);
    assert!(out.contains("main"), "{out}");
    let commit = out
        .split_whitespace()
        .find(|w| w.len() >= 10 && w.chars().all(|c| c.is_ascii_hexdigit()))
        .unwrap_or_else(|| panic!("no commit id in {out}"))
        .to_string();
    assert!(
        !git_ok(&bare, &["rev-parse", "--verify", "-q", "refs/heads/main"]),
        "export pushed"
    );
    let bridge = proj.join(".veil/git/repo.git");
    let exported = git(&bridge, &["rev-parse", "refs/heads/main"]);
    assert!(exported.starts_with(&commit), "{exported} vs {commit}");
}

// Veil: Git sees what a public remote sees — no cloaked, isolated, quarantined content, no
// cloaked descriptions, no cloaked tags, no key rings, no unreleased embargo.
#[test]
fn git_push_exports_only_the_public_view() {
    let env = Env::new();
    let (proj, bare) = veil_with_git_remote(&env, "alice", "proj", "gh.git");
    env.ok("alice", &proj, &["cloak", "secrets/"]);
    write(&proj, "secrets/plan.md", "GIT-CLOAKED-6610\n");
    write(&proj, ".env", "GIT-ISOLATED-6610=1\n");
    write(&proj, "app.txt", "app\n");
    env.ok("alice", &proj, &["commit", "-m", "base"]);
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "@-"]);
    env.ok(
        "alice",
        &proj,
        &["ws", "new", "hidden", "-r", "main", "--cloak", "team"],
    );
    env.ok(
        "alice",
        &proj,
        &[
            "ws",
            "exec",
            "hidden",
            "-m",
            "GIT-SECRET-MSG-6610",
            "--",
            "sh",
            "-c",
            "echo GIT-HIDDEN-6610 > h.txt",
        ],
    );
    env.ok(
        "alice",
        &proj,
        &["tag", "set", "roadmap", "-r", "hidden@", "--cloak", "team"],
    );
    env.ok(
        "alice",
        &proj,
        &["tag", "set", "hidden-public", "-r", "hidden@"],
    );
    let out = env.ok("alice", &proj, &["git", "push"]);
    assert!(out.contains("skipped roadmap"), "{out}");
    assert!(!git_ok(
        &bare,
        &["rev-parse", "--verify", "-q", "refs/heads/roadmap"]
    ));
    for needle in [
        "GIT-CLOAKED-6610",
        "GIT-ISOLATED-6610",
        "GIT-SECRET-MSG-6610",
        "GIT-HIDDEN-6610",
        "veil1",
    ] {
        assert_absent_in_git(&bare, needle, "public Git view");
        assert_absent_in_git(&proj.join(".veil/git/repo.git"), needle, "the local bridge");
    }
    let msg = git(&bare, &["log", "-1", "--format=%s", "hidden-public"]);
    assert_eq!(msg, "(description withheld: cloaked)");
    let files = git(&bare, &["ls-tree", "-r", "--name-only", "main"]);
    assert_eq!(
        files.lines().collect::<Vec<_>>(),
        vec![".veilpolicy", "app.txt"]
    );
}

// Veil: an unreleased embargo exports only the pre-merge tree; release publishes it as a
// fast-forward.
#[test]
fn git_push_of_an_embargo_before_and_after_release() {
    let env = Env::new();
    let (proj, bare) = veil_with_git_remote(&env, "alice", "proj", "gh.git");
    env.commit("alice", &proj, "base", &[("auth.rs", "old\n")]);
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "@-"]);
    env.ok("alice", &proj, &["ws", "new", "fix", "-r", "main"]);
    env.ok(
        "alice",
        &proj,
        &[
            "ws",
            "exec",
            "fix",
            "-m",
            "GIT-FIX-MSG-7720",
            "--",
            "sh",
            "-c",
            "echo GIT-FIX-7720 > auth.rs",
        ],
    );
    env.ok(
        "alice",
        &proj,
        &[
            "merge",
            "fix@",
            "--into",
            "main",
            "--embargo",
            "-m",
            "GIT-MERGE-7720",
        ],
    );
    env.ok("alice", &proj, &["git", "push"]);
    for needle in ["GIT-FIX-7720", "GIT-FIX-MSG-7720", "GIT-MERGE-7720"] {
        assert_absent_in_git(&bare, needle, "unreleased embargo");
    }
    assert_eq!(git(&bare, &["show", "main:auth.rs"]), "old");
    let pinned = git(&bare, &["rev-parse", "main"]);
    let id = env
        .stdout("alice", &proj, &["embargo", "list"])
        .split_whitespace()
        .next()
        .unwrap()
        .to_string();
    env.ok("alice", &proj, &["embargo", "release", &id]);
    env.ok("alice", &proj, &["git", "push"]);
    assert_eq!(git(&bare, &["show", "main:auth.rs"]), "GIT-FIX-7720");
    assert!(
        git_ok(&bare, &["merge-base", "--is-ancestor", &pinned, "main"]),
        "the release is a fast-forward"
    );
    assert!(
        contains(&git_all_objects(&bare), "GIT-FIX-MSG-7720"),
        "the fix's history follows"
    );
}

// Veil: a Git commit made on GitHub never deletes cloaked files on import.
#[test]
fn a_github_commit_does_not_delete_cloaked_files() {
    let env = Env::new();
    let (proj, bare) = veil_with_git_remote(&env, "alice", "proj", "gh.git");
    env.ok("alice", &proj, &["cloak", "secrets/"]);
    env.commit(
        "alice",
        &proj,
        "base",
        &[("secrets/s.txt", "sealed\n"), ("app.txt", "v1\n")],
    );
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "@-"]);
    env.ok("alice", &proj, &["git", "push"]);
    let wc = env.path("gh-wc");
    git(
        &env.root,
        &["clone", "-q", bare.to_str().unwrap(), wc.to_str().unwrap()],
    );
    write(&wc, "app.txt", "v2 from github\n");
    git(&wc, &["commit", "-q", "-am", "edit on github"]);
    git(
        &wc,
        &["rm", "-q", "-r", "--cached", "--ignore-unmatch", "secrets"],
    );
    git(&wc, &["push", "-q", "origin", "HEAD:main"]);
    env.ok("alice", &proj, &["git", "pull"]);
    assert_eq!(
        env.stdout("alice", &proj, &["cat", "app.txt", "-r", "main"]),
        "v2 from github\n"
    );
    assert_eq!(
        env.stdout("alice", &proj, &["cat", "secrets/s.txt", "-r", "main"]),
        "sealed\n"
    );
}

// Veil: a Git commit that adds a committed `.env` or a leaked credential: not recorded, stays in Git.
#[test]
fn files_veil_refuses_stay_in_git_and_survive_a_veil_push() {
    let env = Env::new();
    let (bare, wc) = git_upstream(&env, "gh.git", &[("app.txt", "v1\n")]);
    write(&wc, ".env", "COMMITTED=on-github\n");
    git_commit_push(&wc, "oops, a .env");
    let proj = env.dir("proj");
    env.ok("alice", &proj, &["init"]);
    let out = env.ok("alice", &proj, &["git", "import", bare.to_str().unwrap()]);
    assert!(out.contains("not recorded .env"), "{out}");
    let files = env.stdout("alice", &proj, &["files", "-r", "main"]);
    assert!(
        !files.contains(".env\n") && !files.lines().any(|l| l.ends_with(" .env")),
        "{files}"
    );
    env.ok("alice", &proj, &["new", "main"]);
    env.commit("alice", &proj, "veil edit", &[("app.txt", "v2\n")]);
    env.ok("alice", &proj, &["git", "push"]);
    assert_eq!(
        git(&bare, &["show", "main:.env"]),
        "COMMITTED=on-github",
        "Veil's push deleted the Git-only file"
    );
    assert_eq!(git(&bare, &["show", "main:app.txt"]), "v2");
}

// Veil: a Git commit widening a cloaked path's audience via `.veilpolicy` is not taken.
#[test]
fn a_github_policy_edit_cannot_publish_cloaked_files() {
    let env = Env::new();
    let (proj, bare) = veil_with_git_remote(&env, "alice", "proj", "gh.git");
    env.ok("alice", &proj, &["cloak", "secrets/"]);
    env.commit(
        "alice",
        &proj,
        "base",
        &[
            ("secrets/s.txt", "GIT-POLICY-SEALED\n"),
            ("app.txt", "v1\n"),
        ],
    );
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "@-"]);
    env.ok("alice", &proj, &["git", "push"]);
    let wc = env.path("gh-wc");
    git(
        &env.root,
        &["clone", "-q", bare.to_str().unwrap(), wc.to_str().unwrap()],
    );
    let policy =
        read(&wc, ".veilpolicy").replace("secrets/", "# was secrets/") + "\nsecrets/ public!\n";
    write(&wc, ".veilpolicy", &policy);
    git(&wc, &["commit", "-q", "-am", "publish secrets"]);
    git(&wc, &["push", "-q", "origin", "HEAD:main"]);
    let out = env.ok("alice", &proj, &["git", "pull"]);
    assert!(out.to_lowercase().contains("polic"), "{out}");
    env.ok("alice", &proj, &["new", "main"]);
    env.commit("alice", &proj, "next", &[("app.txt", "v2\n")]);
    env.ok("alice", &proj, &["git", "push"]);
    assert_absent_in_git(
        &bare,
        "GIT-POLICY-SEALED",
        "cloaked file after a GitHub policy edit",
    );
}

// Veil: a Veil remote and a Git remote together — the same tag reaches both, the
// public mirror and GitHub see the same tree.
#[test]
fn github_and_a_public_veil_mirror_see_the_same_files() {
    let env = Env::new();
    let (proj, bare) = veil_with_git_remote(&env, "alice", "proj", "gh.git");
    env.ok("alice", &proj, &["cloak", "secrets/"]);
    env.commit(
        "alice",
        &proj,
        "base",
        &[
            ("secrets/s.txt", "s\n"),
            ("a/b.txt", "b\n"),
            ("c.txt", "c\n"),
        ],
    );
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "@-"]);
    env.ok("alice", &proj, &["git", "push"]);
    env.ok(
        "alice",
        &proj,
        &["remote", "add", "mirror", "../mirror", "--public"],
    );
    env.ok("alice", &proj, &["push", "mirror"]);
    let carol = env.clone("carol", &env.path("mirror"), "carol");
    let veil_files: Vec<String> = listing(&carol)
        .into_iter()
        .filter(|f| !f.starts_with(".veil/"))
        .collect();
    let git_files: Vec<String> = git(&bare, &["ls-tree", "-r", "--name-only", "main"])
        .lines()
        .map(String::from)
        .collect();
    assert_eq!(veil_files, git_files);
}

// Scenario from jj test_concurrent_operations.rs for the bridge: two `vl git push` at once.
#[test]
fn concurrent_git_pushes_from_one_repository_are_safe() {
    let env = Env::new();
    let (proj, bare) = veil_with_git_remote(&env, "alice", "proj", "gh.git");
    env.commit("alice", &proj, "a", &[("a", "a\n")]);
    for t in ["main", "t1", "t2", "t3"] {
        env.ok("alice", &proj, &["tag", "set", t, "-r", "@-"]);
    }
    let kids: Vec<_> = ["main", "t1", "t2", "t3"]
        .iter()
        .map(|t| env.spawn("alice", &proj, &["--no-snapshot", "git", "push", "-t", t]))
        .collect();
    for k in kids {
        let out = k.wait_with_output().unwrap();
        assert!(exited_cleanly(&out), "{}", text(&out));
    }
    env.ok("alice", &proj, &["git", "push"]);
    for t in ["main", "t1", "t2", "t3"] {
        assert!(
            git_ok(
                &bare,
                &["rev-parse", "--verify", "-q", &format!("refs/heads/{t}")]
            ),
            "{t}"
        );
    }
    assert!(git_ok(&bare, &["fsck", "--no-progress"]));
    env.ok("alice", &proj, &["fsck"]);
}

// Scenario from jj test_git_init.rs: `vl git import` into a repository that already has history.
#[test]
fn git_import_into_a_repository_with_its_own_history() {
    let env = Env::new();
    let (bare, _wc) = git_upstream(&env, "gh.git", &[("upstream.txt", "u\n")]);
    let proj = env.project("alice", "proj", &[("local.txt", "l\n")]);
    let out = env.ok(
        "alice",
        &proj,
        &["git", "import", bare.to_str().unwrap(), "--remote", "up"],
    );
    assert!(out.contains("Imported 1 commit(s)"), "{out}");
    // Local main and the Git main are unrelated: the local tag is kept, the remote tag set.
    assert_eq!(
        env.stdout("alice", &proj, &["cat", "local.txt", "-r", "main"]),
        "l\n"
    );
    assert_eq!(
        env.stdout("alice", &proj, &["cat", "upstream.txt", "-r", "up/main"]),
        "u\n"
    );
    assert_eq!(read(&proj, "local.txt"), "l\n");
}
