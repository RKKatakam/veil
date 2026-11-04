//! Remotes in an older (or newer) repository format, using copies of the
//! golden fixtures in `crates/veil-core/tests/fixtures` (never the
//! originals).

use std::path::PathBuf;

use crate::support::*;

/// A copy of fixture `format-N` under the environment's root.
fn fx(env: &Env, n: u32) -> PathBuf {
    let dest = env.path(&format!("fx{n}"));
    copy_dir(&fixture(n), &dest);
    dest
}

fn vl_home(
    env: &Env,
    home: &std::path::Path,
    cwd: &std::path::Path,
    args: &[&str],
) -> std::process::Output {
    env.cmd("unused", cwd, args)
        .env("VEIL_HOME", home)
        .env("VEIL_USER", "alice")
        .output()
        .unwrap()
}

// Veil (jj test_load_repo.rs: loading a repository written by an older version): a new
// repository pushing to a format-1 remote is refused with the upgrade hint and writes nothing.
#[test]
fn a_new_repository_cannot_push_into_a_format_1_remote_and_leaves_it_untouched() {
    let env = Env::new();
    let root = fx(&env, 1);
    let remote = root.join("team-remote");
    let before = listing(&remote);
    let proj = env.project("zoe", "zoe", &[("z.txt", "z\n")]);
    env.ok(
        "zoe",
        &proj,
        &["remote", "add", "old", remote.to_str().unwrap()],
    );
    // A new tag: the remote's `main` is unrelated history, and a diverged tag is refused before
    // anything is sent (BUG-288), so it would never reach the format check.
    env.ok("zoe", &proj, &["tag", "set", "zoe-work", "-r", "main"]);
    let out = env.fails("zoe", &proj, &["push", "old", "-t", "zoe-work"]);
    assert!(out.contains("vl upgrade --remote"), "{out}");
    assert_eq!(
        listing(&remote),
        before,
        "a refused push wrote to the remote"
    );
    assert_eq!(repo_format(&remote), 1);
}

// jj test_load_repo.rs: an older remote is still readable by a newer client.
#[test]
fn a_current_clone_of_a_format_2_remote_reads_and_pushes_back() {
    let env = Env::new();
    let root = fx(&env, 2);
    let remote = root.join("team-remote");
    let home = root.join("home-bob");
    let out = vl_home(
        &env,
        &home,
        &env.root,
        &[
            "clone",
            remote.to_str().unwrap(),
            env.path("bob").to_str().unwrap(),
        ],
    );
    assert!(out.status.success(), "{}", text(&out));
    let bob = env.path("bob");
    assert_eq!(repo_format(&bob), 2);
    write(&bob, "from-bob.txt", "bob\n");
    for args in [
        vec!["commit", "-m", "bob on format 2"],
        vec!["tag", "set", "main", "-r", "@-", "--allow-backwards"],
        vec!["push"],
        vec!["fsck"],
    ] {
        let out = vl_home(&env, &home, &bob, &args);
        assert!(out.status.success(), "{args:?}: {}", text(&out));
    }
    assert_eq!(
        repo_format(&remote),
        2,
        "pushing does not upgrade the remote"
    );
    let out = vl_home(
        &env,
        &home,
        &env.root,
        &["fsck", "-R", remote.to_str().unwrap()],
    );
    assert!(out.status.success(), "{}", text(&out));
}

// Veil: old-format public mirrors hold no cloaked plaintext either.
#[test]
fn old_format_public_mirrors_hold_no_cloaked_plaintext() {
    let env = Env::new();
    for n in [1, 2, 3] {
        let root = fx(&env, n);
        let mirror = root.join("public-mirror");
        assert_absent(
            &mirror,
            "team-only notes",
            &format!("format-{n} public mirror"),
        );
        assert!(
            contains(&everything_in(&root.join("team-remote")), "veil:"),
            "control: objects were read"
        );
    }
}

// Veil: the Git bridge on a format-1 repository exports only the public view.
#[test]
fn git_push_from_a_format_1_repository_exports_the_public_view() {
    let env = Env::new();
    let root = fx(&env, 1);
    let alice = root.join("alice");
    let home = root.join("home-alice");
    let bare = env.path("gh.git");
    git(&env.root, &["init", "-q", "--bare", bare.to_str().unwrap()]);
    let out = vl_home(
        &env,
        &home,
        &alice,
        &["git", "remote", "add", "gh", bare.to_str().unwrap()],
    );
    assert!(out.status.success(), "{}", text(&out));
    let out = vl_home(&env, &home, &alice, &["git", "push", "gh"]);
    assert!(exited_cleanly(&out), "{}", text(&out));
    assert!(
        git_ok(&bare, &["rev-parse", "--verify", "-q", "refs/heads/main"]),
        "{}",
        text(&out)
    );
    assert_absent_in_git(&bare, "team-only notes", "format-1 export");
    assert_eq!(repo_format(&alice), 1, "exporting does not upgrade");
}

// Veil: a remote written by a newer vl (unknown format) is refused by clone, pull and push,
// and nothing is written to it.
#[test]
fn a_remote_in_a_newer_format_is_refused_without_writing() {
    let env = Env::new();
    let (alice, hub) = env.project_with_hub("alice", "alice", "hub", &[("a", "a\n")]);
    let cfg = hub.join(".veil/repo.json");
    let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(&cfg).unwrap()).unwrap();
    v["format"] = serde_json::json!(99);
    v["min_vl"] = serde_json::json!("99.0.0");
    std::fs::write(&cfg, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
    let before = listing(&hub);
    env.commit("alice", &alice, "two", &[("a", "a2\n")]);
    let out = env.fails("alice", &alice, &["push"]);
    assert!(out.contains("format") || out.contains("upgrade"), "{out}");
    env.fails("alice", &alice, &["pull"]);
    env.fails("bob", &env.root, &["clone", hub.to_str().unwrap(), "bob"]);
    assert!(!env.path("bob").exists());
    assert_eq!(listing(&hub), before);
}

// Veil: `vl upgrade --remote --dry-run` describes the upgrade and writes nothing.
#[test]
fn upgrade_remote_dry_run_writes_nothing() {
    let env = Env::new();
    let root = fx(&env, 1);
    let alice = root.join("alice");
    let home = root.join("home-alice");
    let remote = root.join("team-remote");
    let before = listing(&remote);
    let out = vl_home(
        &env,
        &home,
        &alice,
        &["upgrade", "--remote", "origin", "--dry-run"],
    );
    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("format 1"), "{}", text(&out));
    assert_eq!(listing(&remote), before);
}
