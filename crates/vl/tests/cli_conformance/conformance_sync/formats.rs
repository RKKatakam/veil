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

// Veil: a remote in format 7 (which may hold encrypted descriptions, tags, embargoes or
// folders) is refused by a clone until it is upgraded, and nothing is written to it.
#[test]
fn a_clone_of_a_format_7_remote_is_refused_until_it_is_upgraded() {
    let env = Env::new();
    let root = fx(&env, 7);
    let remote = root.join("team-remote");
    let home = root.join("home-bob");
    let before = listing(&remote);
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
    assert!(!out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("format 7") && text(&out).contains("vl upgrade"), "{}", text(&out));
    assert!(!env.path("bob").join(".veil").exists());
    assert_eq!(repo_format(&remote), 7);
    assert_eq!(listing(&remote), before);
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
    assert!(out.contains("format 99"), "{out}");
    env.fails("alice", &alice, &["pull"]);
    env.fails("bob", &env.root, &["clone", hub.to_str().unwrap(), "bob"]);
    assert!(!env.path("bob").exists());
    assert_eq!(listing(&hub), before);
}
