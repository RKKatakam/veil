//! `vl embargo release` through the real binary: a previewed, confirmed
//! release that `vl undo` takes back until the next push, and only until
//! then (BUG-109).

use crate::adversarial_support;

use std::path::{Path, PathBuf};

use adversarial_support::{text, write, Env};

const U: &str = "alice";

/// A project with `main` carrying an embargoed fix, a public mirror that
/// already has `main`, and the embargo id.
fn embargoed(env: &Env) -> (PathBuf, PathBuf, String) {
    let proj = env.dir("proj");
    env.ok(U, &proj, &["init"]);
    write(&proj, "auth.rs", "fn check() { true }\n");
    env.ok(U, &proj, &["commit", "-m", "v1"]);
    env.ok(U, &proj, &["tag", "set", "main", "-r", "@-"]);
    let mirror = env.dir("mirror");
    env.ok(U, &proj, &["remote", "add", "mirror", mirror.to_str().unwrap(), "--public"]);
    env.ok(U, &proj, &["push", "mirror"]);
    env.ok(U, &proj, &["ws", "new", "fix", "-r", "main"]);
    let mut c = env.cmd(U, &proj, &["ws", "write", "fix", "auth.rs"]);
    c.stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
    let mut child = c.spawn().unwrap();
    use std::io::Write as _;
    child.stdin.take().unwrap().write_all(b"fn check() { verify_signature_secretfix() }\n").unwrap();
    assert!(child.wait_with_output().unwrap().status.success());
    env.ok(U, &proj, &["merge", "fix@", "--into", "main", "--embargo", "-m", "Fix CVE"]);
    let id = env.stdout(U, &proj, &["embargo", "list"]).split_whitespace().next().unwrap().to_string();
    (proj, mirror, id)
}

fn released(env: &Env, proj: &Path) -> bool {
    env.stdout(U, proj, &["embargo", "list"]).contains("released")
}

#[test]
fn release_shows_what_becomes_public_and_needs_yes_off_a_terminal() {
    let env = Env::new();
    let (proj, _, id) = embargoed(&env);
    let out = env.vl(U, &proj, &["embargo", "release", &id]);
    let t = text(&out);
    assert!(!out.status.success(), "released without confirmation:\n{t}");
    assert!(t.contains("Fix CVE") && t.contains("main") && t.contains("mirror (public)"), "no preview:\n{t}");
    assert!(t.contains("--yes"), "{t}");
    assert!(!released(&env, &proj), "a refused release released the embargo");

    let out = env.ok(U, &proj, &["embargo", "release", &id, "--yes"]);
    assert!(out.contains("`vl undo` takes it back"), "{out}");
    let list = env.stdout(U, &proj, &["embargo", "list"]);
    assert!(list.contains("released") && list.contains("not pushed yet"), "{list}");
}

#[test]
fn undo_refuses_a_pushed_release_and_changes_nothing() {
    let env = Env::new();
    let (proj, _, id) = embargoed(&env);
    env.ok(U, &proj, &["embargo", "release", &id, "--yes"]);
    let push = env.ok(U, &proj, &["push", "mirror"]);
    assert!(push.contains(&format!("published embargo {id}")), "{push}");
    // The push is an operation of its own (it records `mirror/<tag>`,
    // BUG-248): the first undo takes back only that record, never the
    // published release.
    let out = env.ok(U, &proj, &["undo"]);
    assert!(out.contains("Undid: push to mirror") && out.contains("remote still has"), "{out}");
    assert!(!out.contains("unreleased"), "{out}");
    let ops_before = env.stdout(U, &proj, &["op", "log"]);
    let out = env.vl(U, &proj, &["undo"]);
    let t = text(&out);
    assert!(!out.status.success(), "undo claimed to undo a published release:\n{t}");
    assert!(t.contains("cannot undo") && t.contains("published"), "{t}");
    assert!(!t.contains("Undid"), "{t}");
    let list = env.stdout(U, &proj, &["embargo", "list"]);
    assert!(list.contains("released") && !list.contains("not pushed yet"), "{list}");
    // The refused undo recorded nothing (the automatic snapshot aside).
    let ops_after = env.stdout(U, &proj, &["op", "log"]);
    assert_eq!(ops_after.matches("undo:").count(), 1, "{ops_after}\n(before:\n{ops_before})");
}

#[test]
fn op_restore_before_a_staged_release_takes_it_back() {
    let env = Env::new();
    let (proj, _, id) = embargoed(&env);
    let log = env.stdout(U, &proj, &["op", "log"]);
    let before = log.lines().find(|l| l.contains("merge")).unwrap().split_whitespace().next().unwrap().to_string();
    env.ok(U, &proj, &["embargo", "release", &id, "--yes"]);
    let out = env.ok(U, &proj, &["op", "restore", &before]);
    assert!(out.contains("release taken back"), "{out}");
    assert!(!released(&env, &proj), "the release survived the restore");
}

/// Op log merges review, cycle 5: `vl op restore` past a staged release,
/// stopped before it takes the release back (the staged release written
/// back by hand, as the stopped process leaves it). Neither `vl embargo
/// list` nor `vl show --json` says the next push publishes it; the push
/// does not, and names it with what to run; `vl embargo release` releases
/// it again, and the next push publishes it.
#[test]
fn a_release_the_op_log_took_back_is_never_shown_as_publishing_and_releases_again() {
    for release_again in [false, true] {
        let env = Env::new();
        let (proj, _, id) = embargoed(&env);
        let log = env.stdout(U, &proj, &["op", "log"]);
        let before = log.lines().find(|l| l.contains("merge")).unwrap().split_whitespace().next().unwrap().to_string();
        env.ok(U, &proj, &["embargo", "release", &id, "--yes"]);
        let out = env.ok(U, &proj, &["op", "restore", &before]);
        assert!(out.contains("release taken back"), "{out}");
        std::fs::write(proj.join(".veil/local/releases").join(format!("{id}.json")), b"{\"released_at\": 1}").unwrap();
        let list = env.stdout(U, &proj, &["embargo", "list"]);
        assert!(list.contains("not released") && list.contains("does not publish") && !list.contains("not pushed yet"), "{list}");
        let show: serde_json::Value = serde_json::from_str(&env.stdout(U, &proj, &["show", "main", "--json"])).unwrap();
        assert_eq!(show["embargo"]["id"], id.as_str(), "{show}");
        assert_eq!(show["embargo"]["state"], "pending", "{show}");
        if release_again {
            let out = env.ok(U, &proj, &["embargo", "release", &id, "--yes"]);
            assert!(out.contains("`vl undo` takes it back"), "{out}");
            let list = env.stdout(U, &proj, &["embargo", "list"]);
            assert!(list.contains("not pushed yet") && !list.contains("not released"), "{list}");
            let push = env.ok(U, &proj, &["push", "mirror"]);
            assert!(push.contains(&format!("published embargo {id}")), "{push}");
        } else {
            let push = env.ok(U, &proj, &["push", "mirror"]);
            assert!(!push.contains("published embargo"), "{push}");
            assert!(push.contains(&format!("embargo {id} was not published")) && push.contains(&format!("vl embargo release {id}")), "{push}");
            assert!(!released(&env, &proj), "taken back");
        }
    }
}
