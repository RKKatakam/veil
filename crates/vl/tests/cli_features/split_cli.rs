//! `vl split` and `vl squash` with paths, hunks, plans and the interactive
//! picker, through the real binary: answers are piped on standard input,
//! the working copy never changes on disk, and `vl undo` takes each back.

use crate::adversarial_support;

use std::{io::Write as _, os::unix::fs::PermissionsExt, path::Path, process::Stdio};

use adversarial_support::*;
use serde_json::Value;

const OLD: &str = "1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n11\n12\n13\n14\n15\n16\n17\n18\n19\n20\n";
const NEW: &str = "1\nTWO\n3\n4\n5\nSIX\n7\n8\n9\n10\n11\n12\n13\n14\n15\n16\n17\n18\n19\n20\nextra\n";

/// `main` holds a.txt = OLD and b.txt; the working copy edits both and
/// adds c.txt.
fn project(env: &Env) -> std::path::PathBuf {
    let proj = env.project("alice", "proj", &[("a.txt", OLD), ("b.txt", "b\n")]);
    write(&proj, "a.txt", NEW);
    write(&proj, "b.txt", "B\n");
    write(&proj, "c.txt", "c\n");
    proj
}

/// Run `vl args` with `input` on standard input.
fn with_stdin(env: &Env, dir: &Path, args: &[&str], input: &str) -> std::process::Output {
    let mut c = env.cmd("alice", dir, args);
    c.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = c.spawn().unwrap();
    child.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
    child.wait_with_output().unwrap()
}

fn cat(env: &Env, dir: &Path, rev: &str, path: &str) -> String {
    env.stdout("alice", dir, &["cat", "-r", rev, path])
}

/// The change id of the visible change described `desc`.
fn change_named(env: &Env, dir: &Path, desc: &str) -> String {
    let log: Value = serde_json::from_str(&env.stdout("alice", dir, &["log", "--json"])).unwrap();
    let e = log["entries"].as_array().unwrap().iter().find(|e| e["description"] == desc).unwrap_or_else(|| panic!("no change {desc}: {log}"));
    e["change_id"].as_str().unwrap().to_string()
}

fn status_paths(env: &Env, dir: &Path) -> Vec<String> {
    let v: Value = serde_json::from_str(&env.stdout("alice", dir, &["status", "--json"])).unwrap();
    v["changes"].as_array().unwrap().iter().map(|c| c["path"].as_str().unwrap().to_string()).collect()
}

#[test]
fn interactive_split_from_piped_answers() {
    let env = Env::new();
    let proj = project(&env);
    // a.txt hunk 1: split it, take its first block (TWO) only; hunk 2: no;
    // b.txt: no; c.txt: yes.
    let out = with_stdin(&env, &proj, &["split", "-i", "-m", "part one"], "s\ny\nn\nn\nn\ny\n");
    assert!(out.status.success(), "{}", text(&out));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("diff a.txt (modified)") && err.contains("Split into 2 hunks."), "{err}");
    assert!(err.contains("Put this hunk in the first change [y,n,q,a,d,s,?]? s"), "answers are echoed: {err}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("First part:") && stdout.contains("part one"), "{stdout}");
    assert_eq!(cat(&env, &proj, "@-", "a.txt"), OLD.replacen("2\n", "TWO\n", 1));
    assert_eq!(cat(&env, &proj, "@-", "c.txt"), "c\n");
    assert_eq!(cat(&env, &proj, "@-", "b.txt"), "b\n");
    assert_eq!(cat(&env, &proj, "@", "a.txt"), NEW);
    assert_eq!(read(&proj, "a.txt"), NEW, "the working copy is unchanged");
    assert_eq!(status_paths(&env, &proj), ["a.txt", "b.txt"], "@ holds the rest");
    let log = env.stdout("alice", &proj, &["log", "-n", "3"]);
    assert!(log.contains("part one"), "{log}");

    // One operation: undo takes it back.
    env.ok("alice", &proj, &["undo"]);
    assert_eq!(status_paths(&env, &proj), ["a.txt", "b.txt", "c.txt"]);
    assert_eq!(read(&proj, "a.txt"), NEW);
}

#[test]
fn answers_that_run_out_change_nothing() {
    let env = Env::new();
    let proj = project(&env);
    let ops = env.stdout("alice", &proj, &["op", "log"]);
    let out = with_stdin(&env, &proj, &["split", "-i"], "y\n");
    assert!(!out.status.success());
    assert!(text(&out).contains("the answers ended before every hunk was decided"), "{}", text(&out));
    assert_eq!(env.stdout("alice", &proj, &["op", "log"]), ops);
    // `q` leaves the rest: y to the first hunk, then quit.
    let out = with_stdin(&env, &proj, &["split", "-i"], "y\nq\n");
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(cat(&env, &proj, "@-", "a.txt"), OLD.replacen("2\n", "TWO\n", 1).replacen("\n6\n", "\nSIX\n", 1));
}

#[test]
fn split_by_path_hunks_and_plan() {
    let env = Env::new();
    let proj = project(&env);
    env.ok("alice", &proj, &["split", "b.txt", "--hunks", "a.txt:2"]);
    assert_eq!(cat(&env, &proj, "@-", "b.txt"), "B\n");
    assert_eq!(cat(&env, &proj, "@-", "a.txt"), format!("{OLD}extra\n"));
    env.ok("alice", &proj, &["undo"]);

    let plan = proj.join("../plan.json");
    std::fs::write(&plan, r#"{"schema": "veil.plan/1", "files": [{"path": "a.txt", "hunks": ["1.2", "mode"]}, {"path": "c.txt"}]}"#).unwrap();
    let out = env.vl("alice", &proj, &["split", "--plan", plan.to_str().unwrap()]);
    assert!(!out.status.success());
    assert!(text(&out).contains("executable bit does not change"), "{}", text(&out));
    std::fs::write(&plan, r#"{"files": [{"path": "a.txt", "hunks": ["1.2"]}, {"path": "c.txt"}]}"#).unwrap();
    env.ok("alice", &proj, &["split", "--plan", plan.to_str().unwrap()]);
    assert_eq!(cat(&env, &proj, "@-", "a.txt"), OLD.replacen("\n6\n", "\nSIX\n", 1));
    env.ok("alice", &proj, &["undo"]);
    // From standard input.
    let out = with_stdin(&env, &proj, &["split", "--plan", "-"], r#"{"files": [{"path": "b.txt"}]}"#);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(cat(&env, &proj, "@-", "b.txt"), "B\n");
}

#[test]
fn refusals_say_why() {
    let env = Env::new();
    let proj = project(&env);
    for (args, want) in [
        (&["split"][..], "choose what goes in the first change"),
        (&["split", "."][..], "everything chosen: the second change would be empty"),
        (&["split", "nope.txt"][..], "changes at nope.txt"),
        (&["split", "--hunks", "a.txt:9"][..], "has no hunk 9"),
        (&["split", "--hunks", "a.txt"][..], "expected PATH:LIST"),
        (&["split", "-r", "root()", "a.txt"][..], "the root snapshot has no changes"),
        (&["squash", "-r", "@-", "a.txt"][..], "cannot squash into the root snapshot"),
        (&["squash", "--into", "@", "a.txt"][..], "into itself"),
    ] {
        let out = env.vl("alice", &proj, args);
        assert!(!out.status.success(), "{args:?}");
        assert!(text(&out).contains(want), "{args:?}: {}", text(&out));
    }
    assert!(!env.vl("alice", &proj, &["split", "-i", "--hunks", "a.txt:1"]).status.success(), "-i and --hunks exclude each other");
    // An empty change has nothing to split.
    env.ok("alice", &proj, &["commit", "-m", "work"]);
    let out = env.vl("alice", &proj, &["split", "a.txt"]);
    assert!(text(&out).contains("has no changes to split"), "{}", text(&out));
}

#[test]
fn squash_paths_and_hunks_into_parent_and_elsewhere() {
    let env = Env::new();
    let proj = project(&env);
    env.ok("alice", &proj, &["describe", "-m", "work"]);
    // Path-limited squash into the parent.
    let out = env.ok("alice", &proj, &["squash", "c.txt"]);
    assert!(out.contains("Squashed into") && out.contains("the rest stays in"), "{out}");
    assert_eq!(cat(&env, &proj, "@-", "c.txt"), "c\n");
    assert_eq!(status_paths(&env, &proj), ["a.txt", "b.txt"]);
    let log = env.stdout("alice", &proj, &["log", "-n", "2"]);
    assert!(log.contains("work") && log.contains("initial"), "both descriptions stay: {log}");
    // Interactive: move a.txt's second hunk only (mode first is absent).
    let out = with_stdin(&env, &proj, &["squash", "-i"], "n\ny\nn\n");
    assert!(out.status.success(), "{}", text(&out));
    assert!(String::from_utf8_lossy(&out.stderr).contains("Move this hunk to the destination"));
    assert_eq!(cat(&env, &proj, "@-", "a.txt"), format!("{OLD}extra\n"));
    assert_eq!(read(&proj, "a.txt"), NEW);
    // --into a new sibling change.
    let work = change_named(&env, &proj, "work");
    env.ok("alice", &proj, &["new", "main", "-m", "side"]);
    let side = change_named(&env, &proj, "side");
    env.ok("alice", &proj, &["edit", &work]);
    env.ok("alice", &proj, &["squash", "--into", &side, "b.txt"]);
    assert_eq!(cat(&env, &proj, &side, "b.txt"), "B\n");
    assert_eq!(cat(&env, &proj, "@", "b.txt"), "b\n", "b.txt's edit left this change");
    assert_eq!(read(&proj, "b.txt"), "b\n", "and the working copy follows");
    env.ok("alice", &proj, &["undo"]);
    assert_eq!(read(&proj, "b.txt"), "B\n");
}

#[test]
fn mode_changes_are_a_choice_of_their_own() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("run.sh", OLD)]);
    write(&proj, "run.sh", NEW);
    std::fs::set_permissions(proj.join("run.sh"), std::fs::Permissions::from_mode(0o755)).unwrap();
    // mode: yes; hunks: no, no.
    let out = with_stdin(&env, &proj, &["split", "-i"], "y\nn\nn\n");
    assert!(out.status.success(), "{}", text(&out));
    assert!(String::from_utf8_lossy(&out.stderr).contains("mode change 100644 → 100755"));
    let ls: Value = serde_json::from_str(&env.stdout("alice", &proj, &["ls", "-r", "@-", "--json"])).unwrap();
    let e = ls["entries"].as_array().unwrap().iter().find(|e| e["path"] == "run.sh").unwrap().clone();
    assert_eq!(e["executable"], true, "{e}");
    assert_eq!(cat(&env, &proj, "@-", "run.sh"), OLD);
    assert!(std::fs::metadata(proj.join("run.sh")).unwrap().permissions().mode() & 0o111 != 0);
}

#[test]
fn cloaked_hunks_stay_cloaked() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[(".veilpolicy", "secret/.env.s cloak team\n"), ("secret/.env.s", OLD)]);
    write(&proj, "secret/.env.s", NEW);
    env.ok("alice", &proj, &["split", "--hunks", "secret/.env.s:1.1"]);
    assert_eq!(cat(&env, &proj, "@-", "secret/.env.s"), OLD.replacen("2\n", "TWO\n", 1));
    let ls: Value = serde_json::from_str(&env.stdout("alice", &proj, &["ls", "-r", "@-", "--json"])).unwrap();
    let e = ls["entries"].as_array().unwrap().iter().find(|e| e["path"] == "secret/.env.s").unwrap().clone();
    assert_eq!(e["visibility"]["kind"], "cloaked", "{e}");
    assert_eq!(e["visibility"]["scope"], "team", "{e}");
    // No plaintext of the half anywhere in the store.
    let mut hits = Vec::new();
    let objects = proj.join(".veil/objects");
    for d in std::fs::read_dir(&objects).unwrap().flatten() {
        if d.path().is_dir() {
            for f in std::fs::read_dir(d.path()).unwrap().flatten() {
                let data = std::fs::read(f.path()).unwrap();
                if data.windows(4).any(|w| w == b"TWO\n") {
                    hits.push(f.path());
                }
            }
        }
    }
    assert!(hits.is_empty(), "{hits:?}");
}
