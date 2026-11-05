//! Round-2 adversarial CLI tests: undo and op restore after commands that
//! only edit files and let the auto-snapshot record them.
//!
//! These were BUG-046 reproductions (fixed): commands that edit the working
//! copy record their own operation, so `vl undo` reverts them.

use crate::adversarial_support;

use std::path::Path;

use adversarial_support::*;

/// `vl files -r <rev>` as (path, tier label) pairs.
fn recorded(env: &Env, proj: &Path, rev: &str) -> Vec<(String, String)> {
    env.stdout("alice", proj, &["files", "-r", rev])
        .lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let tier = it.next()?.to_string();
            let path = l.rsplit("  ").next()?.trim().to_string();
            Some((path, tier))
        })
        .collect()
}

fn tier_of(files: &[(String, String)], path: &str) -> Option<String> {
    files.iter().find(|(p, _)| p.ends_with(path)).map(|(_, t)| t.clone())
}

/// `vl expose secrets/` by mistake, then `vl undo`. `expose` edits
/// `.veilpolicy` and lets the automatic snapshot record it, and undo skips
/// automatic snapshots by design. So undo reverts the *previous* command
/// (here the commit), says so, and the exposure stays: the next commit and
/// push publish the formerly cloaked files.
#[test]
fn undo_reverts_an_accidental_expose() {
    let env = Env::new();
    let proj = env.project(
        "alice",
        "proj",
        &[(".veilpolicy", "secrets/ cloak team\n"), ("secrets/db.yml", "db-pass-Xk9mQ2vL7pR4\n"), ("README", "hi\n")],
    );
    assert!(tier_of(&recorded(&env, &proj, "@-"), "secrets/db.yml").unwrap().starts_with("cloak"));
    write(&proj, "README", "hi there\n");
    env.ok("alice", &proj, &["commit", "-m", "readme"]);
    env.ok("alice", &proj, &["expose", "secrets/", "--force"]);
    assert_eq!(tier_of(&recorded(&env, &proj, "@"), "secrets/db.yml").as_deref(), Some("public"));

    let undo = env.ok("alice", &proj, &["undo"]);
    let after = recorded(&env, &proj, "@");
    assert!(
        tier_of(&after, "secrets/db.yml").is_some_and(|t| t.starts_with("cloak")),
        "after `vl undo` ({}): secrets/db.yml is {:?}; .veilpolicy = {:?}",
        undo.trim(),
        tier_of(&after, "secrets/db.yml"),
        read(&proj, ".veilpolicy")
    );
}

/// `vl restore` discards an edit; `vl undo` should bring it back (it is the
/// last command). Instead undo reverts an earlier command and the discarded
/// edit is gone.
#[test]
fn undo_reverts_a_restore() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("notes.txt", "v1\n")]);
    write(&proj, "other.txt", "o\n");
    env.ok("alice", &proj, &["commit", "-m", "other"]);
    write(&proj, "notes.txt", "two hours of edits\n");
    env.ok("alice", &proj, &["status"]);
    env.ok("alice", &proj, &["restore", "notes.txt"]);
    assert_eq!(read(&proj, "notes.txt"), "v1\n");
    let undo = env.ok("alice", &proj, &["undo"]);
    env.ok("alice", &proj, &["status"]);
    assert_eq!(
        read(&proj, "notes.txt"),
        "two hours of edits\n",
        "`vl undo` after `vl restore` said: {}",
        undo.trim()
    );
}

/// Control: undo of an ordinary command keeps uncommitted edits.
#[test]
fn undo_of_a_commit_keeps_later_edits() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a.txt", "1\n")]);
    write(&proj, "a.txt", "2\n");
    env.ok("alice", &proj, &["commit", "-m", "two"]);
    write(&proj, "b.txt", "uncommitted\n");
    env.ok("alice", &proj, &["status"]);
    env.ok("alice", &proj, &["undo"]);
    assert_eq!(read(&proj, "b.txt"), "uncommitted\n");
    assert_eq!(read(&proj, "a.txt"), "2\n");
}

/// `vl isolate` is undone like any command, and edits made after it stay.
#[test]
fn undo_reverts_an_isolate_and_keeps_later_edits() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("config.yml", "port: 1\n"), ("README", "hi\n")]);
    env.ok("alice", &proj, &["isolate", "config.yml"]);
    assert_eq!(tier_of(&recorded(&env, &proj, "@"), "config.yml"), None);
    write(&proj, "README", "edited after the isolate\n");
    let undo = env.ok("alice", &proj, &["undo"]);
    assert!(undo.contains("isolate config.yml"), "{undo}");
    assert_eq!(tier_of(&recorded(&env, &proj, "@"), "config.yml").as_deref(), Some("public"));
    assert!(!read(&proj, ".veilpolicy").contains("config.yml"));
    assert_eq!(read(&proj, "README"), "edited after the isolate\n");
}
