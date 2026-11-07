//! First-class conflicts from the command line: `vl merge` records a
//! conflict entry, the working copy shows markers, `vl status`, `vl log`,
//! `vl ls`, `vl diff` and `vl show` say so, `vl resolve` lists and resolves,
//! editing the markers away resolves, and `vl undo` brings a conflict back.

use crate::adversarial_support;

use adversarial_support::*;

/// A project whose `a.txt` conflicts after `vl merge other@` (ours edits
/// line 2 one way, the workspace `other` another way).
fn conflicted(env: &Env) -> std::path::PathBuf {
    let proj = env.project("alice", "proj", &[("a.txt", "one\ntwo\nthree\n"), ("b.txt", "b\n")]);
    env.ok("alice", &proj, &["ws", "new", "other", "-r", "main"]);
    let mut c = env.cmd("alice", &proj, &["ws", "write", "other", "a.txt"]);
    c.stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
    let mut child = c.spawn().unwrap();
    use std::io::Write;
    child.stdin.take().unwrap().write_all(b"one\nTHEIRS\nthree\n").unwrap();
    assert!(child.wait_with_output().unwrap().status.success());
    write(&proj, "a.txt", "one\nOURS\nthree\n");
    env.ok("alice", &proj, &["commit", "-m", "ours"]);
    let out = env.ok("alice", &proj, &["merge", "other@", "-m", "merge"]);
    assert!(out.contains("conflicts in: a.txt"), "{out}");
    proj
}

#[test]
fn a_conflict_is_listed_everywhere_and_resolved_by_editing() {
    let env = Env::new();
    let proj = conflicted(&env);
    let file = read(&proj, "a.txt");
    assert!(file.contains("<<<<<<< ours\nOURS\n||||||| original\ntwo\n=======\nTHEIRS\n>>>>>>> theirs"), "{file}");

    let st = env.stdout("alice", &proj, &["status"]);
    assert!(st.contains("Unresolved conflicts:") && st.contains("C a.txt"), "{st}");
    assert!(st.contains("vl resolve"), "{st}");
    let log = env.stdout("alice", &proj, &["log"]);
    assert!(log.contains("(conflict)"), "{log}");
    let ls = env.stdout("alice", &proj, &["ls"]);
    assert!(ls.lines().any(|l| l.contains("a.txt") && l.contains("conflict: 2 sides")), "{ls}");
    let files = env.stdout("alice", &proj, &["files"]);
    assert!(files.lines().any(|l| l.contains("a.txt") && l.contains("(conflict)")), "{files}");
    let list = env.stdout("alice", &proj, &["resolve", "--list"]);
    assert!(list.contains("C a.txt") && list.contains("ours") && list.contains("theirs") && list.contains("base"), "{list}");
    let show = env.stdout("alice", &proj, &["show", "@-"]);
    assert!(show.contains("Conflicts : a.txt"), "{show}");
    let diff = env.stdout("alice", &proj, &["diff", "--from", "root()", "--to", "@"]);
    assert!(diff.contains("unresolved conflict (2 sides)") && diff.contains("+<<<<<<< ours"), "{diff}");
    let cat = env.stdout("alice", &proj, &["cat", "a.txt"]);
    assert_eq!(cat, file);

    // Edited, markers left: still a conflict.
    write(&proj, "a.txt", &file.replace("one\n", "ONE\n"));
    let st = env.stdout("alice", &proj, &["status"]);
    assert!(st.contains("C a.txt"), "{st}");
    // Markers gone: resolved.
    write(&proj, "a.txt", "ONE\nBOTH\nthree\n");
    let st = env.stdout("alice", &proj, &["status"]);
    assert!(!st.contains("Unresolved conflicts"), "{st}");
    let diff = env.stdout("alice", &proj, &["diff"]);
    assert!(diff.contains("conflict resolved"), "{diff}");
    assert!(env.stdout("alice", &proj, &["resolve", "--list"]).contains("no conflicts"));
}

#[test]
fn resolve_keeps_a_side_and_undo_brings_the_conflict_back() {
    let env = Env::new();
    let proj = conflicted(&env);
    let out = env.vl("alice", &proj, &["resolve", "--ours"]);
    assert!(!out.status.success() && text(&out).contains("name the conflicted files"), "{}", text(&out));
    let out = env.vl("alice", &proj, &["resolve", "b.txt", "--ours"]);
    assert!(!out.status.success() && text(&out).contains("no conflict at b.txt"), "{}", text(&out));
    let out = env.vl("alice", &proj, &["resolve", "a.txt", "--ours", "--theirs"]);
    assert!(!out.status.success(), "two versions at once");

    let out = env.ok("alice", &proj, &["resolve", "a.txt", "--theirs"]);
    assert!(out.contains("Resolved a.txt"), "{out}");
    assert_eq!(read(&proj, "a.txt"), "one\nTHEIRS\nthree\n");
    assert!(!env.stdout("alice", &proj, &["status"]).contains("Unresolved"));
    env.ok("alice", &proj, &["undo"]);
    assert!(read(&proj, "a.txt").contains("<<<<<<<"));
    assert!(env.stdout("alice", &proj, &["status"]).contains("C a.txt"));
    env.ok("alice", &proj, &["resolve", ".", "--base"]);
    assert_eq!(read(&proj, "a.txt"), "one\ntwo\nthree\n");
    let out = env.vl("alice", &proj, &["resolve", "a.txt", "--side", "1"]);
    assert!(!out.status.success() && text(&out).contains("no conflict"), "{}", text(&out));
}

/// A conflict whose other side is sealed for `team`, as Bob sees it when he
/// is not in `team`: redacted, and he cannot resolve it by editing. (A
/// secret file, sealed on one line and exposed with `--force` on the other.)
#[test]
fn an_outsider_sees_a_sealed_side_redacted_and_cannot_resolve_it() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("README", "hi\n")]);
    write(&proj, ".env.app", "one\ntwo\nthree\n");
    env.ok("alice", &proj, &["cloak", ".env.app"]);
    env.ok("alice", &proj, &["commit", "-m", "sealed"]);
    env.ok("alice", &proj, &["ws", "new", "secret", "-r", "main"]);
    let mut c = env.cmd("alice", &proj, &["ws", "write", "secret", ".env.app"]);
    c.stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
    let mut child = c.spawn().unwrap();
    use std::io::Write;
    child.stdin.take().unwrap().write_all(b"one\nSEALED-SIDE-0042\nthree\n").unwrap();
    assert!(child.wait_with_output().unwrap().status.success());
    env.ok("alice", &proj, &["expose", "--force", ".env.app"]);
    write(&proj, ".env.app", "one\nPUBLIC\nthree\n");
    env.ok("alice", &proj, &["commit", "-m", "public"]);
    env.ok("alice", &proj, &["new", "@-", "secret@", "-m", "conflicted"]);
    env.ok("alice", &proj, &["tag", "set", "conflicted", "-r", "@"]);
    let team = env.root.join("team");
    env.ok("alice", &proj, &["remote", "add", "origin", team.to_str().unwrap()]);
    env.ok("alice", &proj, &["push"]);
    env.ok("bob", &env.root, &["clone", "team", "bob"]);
    let bob = env.root.join("bob");
    env.ok("bob", &bob, &["new", "conflicted"]);
    let shown = read(&bob, ".env.app");
    assert!(shown.contains("PUBLIC") && !shown.contains("SEALED-SIDE-0042") && shown.contains("not shown"), "{shown}");
    let list = env.stdout("bob", &bob, &["resolve", "--list"]);
    assert!(list.contains("not readable here"), "{list}");
    write(&bob, ".env.app", "one\nBOB\nthree\n");
    let st = env.ok("bob", &bob, &["status"]);
    assert!(st.contains("C .env.app"), "{st}");
}
