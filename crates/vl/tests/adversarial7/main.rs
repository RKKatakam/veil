//! Round-7 adversarial tests (Opus) through the real `vl` binary, against
//! the local-tooling features: `--json` and the API layer, `vl ls` and
//! `vl push --dry-run`, first-class conflicts (format 4), `vl serve --local`,
//! and `vl split` / `vl squash`.
//!
//! Every `#[ignore = "BUG-NNN: …"]` test asserts the secure (or correct)
//! behaviour and currently fails; see `docs/BUGS.md` ("Round 7 findings").
//! The tests without `ignore` are controls: the same flow through a route
//! that works, so a failure of the ignored test is the bug and not the
//! setup.

#[path = "../adversarial_support/mod.rs"]
mod adversarial_support;

mod conflicts;
mod plan;
mod serve;

use std::{
    io::Write,
    path::{Path, PathBuf},
    process::Stdio,
};

use adversarial_support::{write, Env};

pub const U: &str = "alice";

/// Write `content` to `path` in workspace `ws` (`vl ws write`, from stdin).
pub fn ws_write(env: &Env, proj: &Path, ws: &str, path: &str, content: &str) {
    let mut c = env.cmd(U, proj, &["ws", "write", ws, path]);
    c.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = c.spawn().unwrap();
    child.stdin.take().unwrap().write_all(content.as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "ws write: {}", String::from_utf8_lossy(&out.stderr));
}

/// The short change id of the (first) change whose description is `what`.
pub fn change_of(env: &Env, proj: &Path, what: &str) -> String {
    let log: serde_json::Value = serde_json::from_str(&env.stdout(U, proj, &["log", "--json"])).unwrap();
    log["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["description"].as_str().is_some_and(|d| d.trim() == what))
        .unwrap_or_else(|| panic!("no change described {what:?}"))["change_short"]
        .as_str()
        .unwrap()
        .to_string()
}

/// A project whose `main` holds `a.txt` = "one\ntwo\nthree\n", with a
/// workspace `sec` cloaked for `team` (Alice's own scope) whose working-copy
/// change, on `main`, rewrites line 2 as `SEALED-SIDE-0042`, and a public
/// change `public` on `main` that rewrites it as `PUBLIC`. Tag `conflicted`
/// is a merge of the two: `a.txt` is a conflict entry (format 4) whose
/// "theirs" side is sealed for `team`.
pub fn sealed_conflict(env: &Env) -> PathBuf {
    let proj = env.project(U, "proj", &[("a.txt", "one\ntwo\nthree\n")]);
    env.ok(U, &proj, &["ws", "new", "sec", "-r", "main", "--cloak", "team"]);
    ws_write(env, &proj, "sec", "a.txt", "one\nSEALED-SIDE-0042\nthree\n");
    write(&proj, "a.txt", "one\nPUBLIC\nthree\n");
    env.ok(U, &proj, &["commit", "--no-advance", "-m", "public"]);
    env.ok(U, &proj, &["new", "@-", "sec@", "-m", "conflicted"]);
    env.ok(U, &proj, &["tag", "set", "conflicted", "-r", "@"]);
    let ls = env.stdout(U, &proj, &["resolve", "--list", "-r", "conflicted", "--json"]);
    assert!(ls.contains("\"path\":\"a.txt\"") && ls.contains("\"scope\":\"team\""), "{ls}");
    proj
}

/// Push `rev` as tag `name` to a new public remote `pub`, clone it as Carol
/// (who holds no key) and return her clone.
pub fn publish(env: &Env, proj: &Path, rev: &str, name: &str) -> PathBuf {
    env.ok(U, proj, &["tag", "set", name, "-r", rev, "--allow-backwards"]);
    let pubdir = env.root.join("pub");
    if !pubdir.exists() {
        env.ok(U, proj, &["remote", "add", "pub", pubdir.to_str().unwrap(), "--public"]);
    }
    env.ok(U, proj, &["push", "pub", "-t", name]);
    let carol = env.root.join(format!("carol-{name}"));
    env.ok("carol", &env.root, &["clone", pubdir.to_str().unwrap(), carol.to_str().unwrap()]);
    env.ok("carol", &carol, &["new", name]);
    carol
}

/// Every file under `dir` (outside `.veil`) concatenated.
pub fn all_files(dir: &Path) -> String {
    let mut out = String::new();
    for p in adversarial_support::tree_listing(dir) {
        if p.starts_with(".veil") {
            continue;
        }
        let full = dir.join(&p);
        if full.is_file() {
            out.push_str(&String::from_utf8_lossy(&std::fs::read(&full).unwrap()));
        }
    }
    out
}
