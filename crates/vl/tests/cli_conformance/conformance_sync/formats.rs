//! Remotes in an older (or newer) repository format, using copies of the
//! golden fixtures in `crates/veil-core/tests/fixtures` (never the
//! originals).

use std::path::PathBuf;

use super::support::*;

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
