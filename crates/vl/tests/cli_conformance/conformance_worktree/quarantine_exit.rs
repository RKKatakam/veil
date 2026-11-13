//! BUG-2140: a quarantine at `vl commit`, `vl new` or `vl push` does not
//! look like a plain success. The work is done without the file, and the
//! command exits 3 naming it, until it is isolated, exposed or fixed
//! (BUG-1980: a script committed and pushed and never noticed a file was
//! left out).

use super::*;

const QUARANTINE: i32 = 3;

fn stderr_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn quarantined(r: &R<'_>, args: &[&str]) -> String {
    r.quarantined(args)
}

#[test]
fn commit_with_a_quarantined_file_exits_3_records_the_rest_and_names_it() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("app.py", "print('hi')\n");
    r.write("cfg.js", LEAKY);
    r.write(".env", DOTENV);
    let out = r.run(&["commit", "-m", "one"]);
    assert_eq!(out.status.code(), Some(QUARANTINE), "{}", text(&out));
    // The commit happened, without the file.
    assert!(stdout_of(&out).starts_with("Committed "), "{}", text(&out));
    assert_eq!(r.description("@-"), "one");
    let paths = r.paths("@-");
    assert!(paths.contains(&"app.py".to_string()), "{paths:?}");
    assert!(!paths.contains(&"cfg.js".to_string()), "{paths:?}");
    assert_eq!(r.read("cfg.js"), LEAKY);
    // Named on stderr with the way out; `.env` (isolated by default) is not.
    let err = stderr_of(&out);
    assert!(err.contains("error: committed, but without 1 quarantined file (it looks like a secret):\n  cfg.js (aws-access-key-id at line 1; never recorded)\n"), "{err}");
    assert!(err.contains("`vl isolate <file>`") && err.contains("`vl expose --force <file>`"), "{err}");
    assert!(!err.contains(".env ("), "{err}");

    // The same command again fails the same way while the file stays.
    let t = quarantined(&r, &["commit", "-m", "two"]);
    assert!(t.contains("  cfg.js (aws-access-key-id"), "{t}");

    // Kept local on purpose: exit 0, and still not recorded.
    r.ok(&["isolate", "cfg.js"]);
    let t = r.ok(&["commit", "-m", "three"]);
    assert!(!t.contains("quarantined"), "{t}");
    assert!(!r.paths("@-").contains(&"cfg.js".to_string()));
}

#[test]
fn commit_after_expose_force_records_the_file_and_exits_0() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("cfg.js", LEAKY);
    quarantined(&r, &["commit", "-m", "one"]);
    r.ok(&["expose", "--force", "cfg.js"]);
    let t = r.ok(&["commit", "-m", "two"]);
    assert!(!t.contains("quarantined"), "{t}");
    assert!(r.paths("@-").contains(&"cfg.js".to_string()));
}

#[test]
fn a_file_isolated_before_it_holds_a_secret_never_fails_a_commit() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("app.py", "print('hi')\n");
    r.ok(&["isolate", "cfg.js"]);
    r.write("cfg.js", LEAKY);
    let t = r.ok(&["commit", "-m", "one"]);
    assert!(!t.contains("quarantined"), "{t}");
    assert_eq!(r.paths("@-"), vec!["app.py"]);
    r.ok(&["new"]);
}

#[test]
fn a_held_back_edit_of_a_tracked_file_exits_3() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("cfg.js", "const key = process.env.KEY;\n");
    r.commit("one");
    r.write("cfg.js", LEAKY);
    let t = quarantined(&r, &["commit", "-m", "two"]);
    assert!(t.contains("  cfg.js (aws-access-key-id at line 1; edit held back)"), "{t}");
    // History keeps the clean version.
    assert_eq!(r.out(&["--no-snapshot", "cat", "-r", "@-", "cfg.js"]), "const key = process.env.KEY;\n");
}

#[test]
fn new_with_a_quarantined_file_exits_3_and_starts_the_change() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("cfg.js", LEAKY);
    r.ok(&["describe", "-m", "first"]);
    let before = r.change("@");
    let t = quarantined(&r, &["new"]);
    assert!(t.contains("error: started a new change, but without 1 quarantined file"), "{t}");
    assert_eq!(r.change("@-"), before);
    r.ok(&["isolate", "cfg.js"]);
    r.ok(&["new"]);
}

#[test]
fn read_only_commands_exit_0_and_list_the_quarantined_file() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("app.py", "print('hi')\n");
    r.write("cfg.js", LEAKY);
    quarantined(&r, &["commit", "-m", "one"]);
    let st = r.ok(&["status"]);
    assert!(st.contains("Q cfg.js [quarantined]"), "{st}");
    r.ok(&["log"]);
    r.ok(&["diff"]);
    let json: serde_json::Value = serde_json::from_str(&r.out(&["status", "--json"])).unwrap();
    assert_eq!(json["schema"], "veil.status/2", "{json}");
    let q = json["quarantined"].as_array().unwrap();
    assert_eq!(q.len(), 1, "{json}");
    assert_eq!(q[0]["path"], "cfg.js");
    assert_eq!(q[0]["rule"], "aws-access-key-id");
    assert_eq!(q[0]["state"], "never_recorded");
}

#[test]
fn push_of_a_change_left_without_a_quarantined_file_exits_3() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("app.py", "print('hi')\n");
    r.write("cfg.js", LEAKY);
    quarantined(&r, &["commit", "-m", "one"]);
    r.ok(&["tag", "set", "main", "-r", "@-"]);
    let remote = env.root.join("remote");
    r.ok(&["remote", "add", "origin", remote.to_str().unwrap()]);
    let t = quarantined(&r, &["push", "origin"]);
    assert!(t.contains("error: pushed, but without 1 quarantined file (it looks like a secret):\n  cfg.js (aws-access-key-id at line 1; never recorded)\n"), "{t}");
    // Pushed all the same, without the file.
    let bob_dir = env.root.join("bob");
    let out = env.run_as("bob", &env.root, &["clone", remote.to_str().unwrap(), bob_dir.to_str().unwrap()]);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(env.as_user("bob", &bob_dir).paths("main"), vec!["app.py"]);
    // Resolved: the push exits 0.
    r.ok(&["isolate", "cfg.js"]);
    r.ok(&["push", "origin"]);
}
