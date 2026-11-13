//! Tiers on the command line: `vl ls` and the tier marks of `vl status`.

use crate::adversarial_support;

use std::{
    collections::BTreeMap,
    path::Path,
};

use adversarial_support::*;
use serde_json::Value;

const CLOAKED: &str = "CLOAKED-DB-PASSWORD-PLAN-5521";
const ISOLATED: &str = "ISOLATED-ENV-VALUE-7731";

fn json(env: &Env, user: &str, dir: &Path, args: &[&str]) -> (Value, i32) {
    let out = env.vl(user, dir, args);
    let v = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("vl {args:?}: {e}\n{}", text(&out)));
    (v, out.status.code().unwrap())
}

/// `path → tier label` from the text of `vl ls`.
fn ls(env: &Env, user: &str, dir: &Path, args: &[&str]) -> BTreeMap<String, String> {
    let mut a = vec!["ls"];
    a.extend_from_slice(args);
    env.stdout(user, dir, &a)
        .lines()
        .map(|l| {
            let mut it = l.split_whitespace();
            let tier = it.next().unwrap().to_string();
            let _size = it.next().unwrap();
            let path = it.next().unwrap().to_string();
            (path, tier)
        })
        .collect()
}

/// Alice's project: public, cloaked (a sealed secret file), isolated and
/// executable files; a team remote and a public mirror.
fn project(env: &Env) -> std::path::PathBuf {
    let dir = env.dir("alice");
    write(&dir, "src/main.rs", "fn main() {}\n");
    write(&dir, "secrets/.env.db", &format!("{CLOAKED}\n"));
    write(&dir, ".netrc", &format!("KEY={ISOLATED}\n"));
    env.ok("alice", &dir, &["init"]);
    env.ok("alice", &dir, &["cloak", "secrets/.env.db"]);
    env.ok("alice", &dir, &["commit", "-m", "one"]);
    env.ok("alice", &dir, &["tag", "set", "main", "-r", "@-"]);
    let team = env.root.join("team");
    let mirror = env.root.join("mirror");
    env.ok("alice", &dir, &["remote", "add", "origin", team.to_str().unwrap()]);
    env.ok("alice", &dir, &["remote", "add", "mirror", mirror.to_str().unwrap(), "--public"]);
    dir
}

#[test]
fn ls_shows_every_tier_and_status_marks_every_file() {
    let env = Env::new();
    let dir = project(&env);
    write(&dir, "cfg.js", "k = \"AKIAIOSFODNN7EXAMPLE\"\n");
    write(&dir, "target/debug/app", "binary\n");
    write(&dir, "secrets/.env.db", &format!("{CLOAKED} v2\n"));
    let files = ls(&env, "alice", &dir, &["--all"]);
    assert_eq!(files["src/main.rs"], "public");
    assert_eq!(files["secrets/.env.db"], "cloaked:team");
    assert_eq!(files[".netrc"], "isolated");
    assert_eq!(files["cfg.js"], "quarantined");
    assert_eq!(files["target/"], "ignored", "{files:?}");
    assert!(!ls(&env, "alice", &dir, &[]).contains_key("target/"), "ignored files need --all");
    // In tree order; filters by path, relative to the current directory.
    let only = ls(&env, "alice", &dir.join("src"), &["."]);
    assert_eq!(only.keys().collect::<Vec<_>>(), ["src/main.rs"]);
    let out = env.vl("alice", &dir, &["ls", "nope"]);
    assert!(!out.status.success() && text(&out).contains("matches no file"), "{}", text(&out));
    // An older snapshot has no local-only files.
    let old = ls(&env, "alice", &dir, &["-r", "main"]);
    assert!(!old.contains_key(".netrc") && !old.contains_key("cfg.js"), "{old:?}");
    // `vl files` keeps its format.
    let f = env.stdout("alice", &dir, &["files"]);
    assert!(f.lines().any(|l| l.starts_with("cloaked:team") && l.ends_with("secrets/.env.db")), "{f}");

    let st = env.stdout("alice", &dir, &["status"]);
    assert!(st.contains("M secrets/.env.db [cloaked:team]"), "{st}");
    assert!(st.contains("L .netrc [isolated]"), "{st}");
    assert!(st.contains("Q cfg.js [quarantined]  (aws-access-key-id; never recorded)"), "{st}");
    let (v, _) = json(&env, "alice", &dir, &["status", "--json"]);
    let change = v["changes"].as_array().unwrap().iter().find(|c| c["path"] == "secrets/.env.db").unwrap();
    assert_eq!(change["tier"], "cloaked");
    assert_eq!(v["quarantined"][0]["tier"], "quarantined");

    // Bob clones the team remote without a key for `team`.
    // Pushed; `cfg.js` stays quarantined, so the push exits 3 (BUG-2140).
    env.quarantined("alice", &dir, &["push"]);
    env.ok("bob", &env.root, &["clone", "team", "bob"]);
    let bob = env.root.join("bob");
    let files = ls(&env, "bob", &bob, &[]);
    assert_eq!(files["secrets/.env.db"], "redacted", "{files:?}");
    let line = env.stdout("bob", &bob, &["ls", "secrets"]);
    assert!(line.contains("(cloaked:team; no key)"), "{line}");
    assert!(!line.contains(CLOAKED));
    write(&bob, "src/main.rs", "fn main() { bob() }\n");
    let st = env.stdout("bob", &bob, &["status"]);
    assert!(st.contains("R secrets/.env.db [redacted]  (cloaked:team; no key)"), "{st}");
    assert!(st.contains("M src/main.rs\n"), "public files carry no mark: {st}");
}
