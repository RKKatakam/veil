//! Round 4 documentation findings about CLI output and exit codes
//! (BUG-078, 081, 082, 084, 086, 087), through the real `vl` binary.

use crate::adversarial_support;

use std::process::Stdio;

use adversarial_support::*;

/// A project with a public file and a cloaked secret file, tagged `main`, pushed
/// to a team remote (`team`) and a public mirror (`mirror`).
fn cloaked_project(env: &Env) -> std::path::PathBuf {
    let proj = env.project(
        "alice",
        "proj",
        &[(".veilpolicy", ".env.* cloak team\n"), ("internal/.env.plan", "the plan\n"), ("README", "hi\n")],
    );
    let team = env.root.join("team");
    let mirror = env.root.join("mirror");
    env.ok("alice", &proj, &["remote", "add", "origin", team.to_str().unwrap()]);
    env.ok("alice", &proj, &["remote", "add", "mirror", mirror.to_str().unwrap(), "--public"]);
    env.ok("alice", &proj, &["push", "origin"]);
    env.ok("alice", &proj, &["push", "mirror"]);
    proj
}

fn stderr(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

// ---- BUG-078: a closed pipe --------------------------------------------------

/// `vl … | head`: the reader goes away. `vl` must not panic (exit 101); it
/// exits 141 like Git killed by SIGPIPE, and leaves the repository usable.
#[test]
fn a_closed_stdout_pipe_exits_quietly_with_141() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a.txt", "a\n")]);
    for args in [&["log"][..], &["show", "@-"], &["files", "-r", "@-"], &["cat", "a.txt", "-r", "@-"], &["completions", "bash"]] {
        let mut child = env.cmd("alice", &proj, args).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        // Close the read end before `vl` writes anything: every write fails.
        drop(child.stdout.take());
        let out = child.wait_with_output().unwrap();
        let err = stderr(&out);
        assert_eq!(out.status.code(), Some(141), "vl {args:?}: {:?}\n{err}", out.status);
        assert!(!err.contains("panicked") && !err.contains("Broken pipe"), "vl {args:?}:\n{err}");
    }
    // Both streams gone (`vl log 2>&1 | head`).
    let mut child = env.cmd("alice", &proj, &["log"]).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    drop(child.stdout.take());
    drop(child.stderr.take());
    assert_eq!(child.wait().unwrap().code(), Some(141));
    // Nothing was left behind: no lock, and the next command works.
    assert!(!proj.join(".veil/lock").exists());
    env.ok("alice", &proj, &["status"]);
}

/// A failed command keeps its own status even if its output went nowhere.
#[test]
fn a_closed_pipe_does_not_hide_a_failure() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a.txt", "a\n")]);
    let mut child = env
        .cmd("alice", &proj, &["cat", "missing.txt"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
}

/// Any other write error (a full disk) is reported, not a panic.
#[cfg(target_os = "linux")]
#[test]
fn a_full_stdout_is_an_error_not_a_panic() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a.txt", "a\n")]);
    let full = std::fs::OpenOptions::new().write(true).open("/dev/full").unwrap();
    let out = env.cmd("alice", &proj, &["log"]).stdout(full).output().unwrap();
    let err = stderr(&out);
    assert_eq!(out.status.code(), Some(1), "{err}");
    assert!(err.contains("could not write to standard output") && !err.contains("panicked"), "{err}");
}

// ---- BUG-081: a push with rejected tags fails ---------------------------------

#[test]
fn a_push_with_a_diverged_tag_fails_but_still_pushes_the_others() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a.txt", "a\n")]);
    let team = env.root.join("team");
    env.ok("alice", &proj, &["remote", "add", "origin", team.to_str().unwrap()]);
    env.ok("alice", &proj, &["push"]);
    // Nothing to do: success.
    let out = env.vl("alice", &proj, &["push"]);
    assert!(out.status.success(), "{}", text(&out));

    // Bob moves `main` on the remote.
    env.ok("bob", &env.root, &["clone", "team", "bob"]);
    let bob = env.root.join("bob");
    write(&bob, "b.txt", "b\n");
    env.ok("bob", &bob, &["commit", "-m", "bob"]);
    env.ok("bob", &bob, &["tag", "set", "main", "-r", "@-"]);
    env.ok("bob", &bob, &["push"]);

    // Alice commits on her `main` and adds a new tag `dev`.
    write(&proj, "c.txt", "c\n");
    env.ok("alice", &proj, &["commit", "-m", "alice"]);
    env.ok("alice", &proj, &["tag", "set", "main", "-r", "@-"]);
    env.ok("alice", &proj, &["tag", "set", "dev", "-r", "@-"]);
    let out = env.vl("alice", &proj, &["push"]);
    let all = text(&out);
    assert_eq!(out.status.code(), Some(1), "{all}");
    assert!(all.contains("rejected main") && all.contains("pushed dev"), "{all}");
    assert!(stderr(&out).contains("error: 1 tag was rejected (main)"), "{all}");
    assert!(all.contains("vl pull origin") && all.contains("vl merge origin/main"), "{all}");
    // `dev` did reach the remote.
    let remote_log = env.ok("carol", &env.root, &["clone", "team", "carol"]);
    let carol = env.root.join("carol");
    assert!(env.ok("carol", &carol, &["log"]).contains("dev"), "{remote_log}");

    // Recovering as the message says makes the push succeed again.
    env.ok("alice", &proj, &["pull"]);
    env.ok("alice", &proj, &["merge", "origin/main", "--into", "main", "-m", "merge bob"]);
    env.ok("alice", &proj, &["push"]);
}

/// Tags held back by design (on an unreleased embargoed merge) do not fail
/// an all-tags push, but a tag asked for by name that is not pushed does.
#[test]
fn a_requested_tag_that_is_held_back_fails_the_push() {
    let env = Env::new();
    let proj = cloaked_project(&env);
    env.ok("alice", &proj, &["ws", "new", "fix", "-r", "main"]);
    env.ok("alice", &proj, &["ws", "exec", "fix", "-m", "fix", "--", "sh", "-c", "printf 'fixed\\n' > README"]);
    env.ok("alice", &proj, &["merge", "fix@", "--into", "main", "--embargo", "-m", "Fix"]);
    let out = env.vl("alice", &proj, &["push", "mirror"]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("skipped main"), "{}", text(&out));
    let out = env.vl("alice", &proj, &["push", "mirror", "-t", "main"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(stderr(&out).contains("requested tag was not pushed: main"), "{}", text(&out));
}

// ---- BUG-082: lock times ----------------------------------------------------

#[test]
fn doctor_describes_a_legacy_lock_with_a_bad_time_sensibly() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("a.txt", "a\n")]);
    // A legacy "<pid> <time>" file whose time is in nanoseconds.
    std::fs::write(proj.join(".veil/lock"), "999999999 1793763700901071512").unwrap();
    let out = env.vl("alice", &proj, &["doctor"]);
    let all = text(&out);
    assert!(all.contains("lease renewal time unreadable") && all.contains("legacy lock file"), "{all}");
    assert!(!all.contains("s ago") && !all.contains("-1793"), "{all}");
}

// ---- BUG-084 / BUG-086: cloaked content from a public remote ------------------

#[test]
fn reading_a_cloaked_file_from_a_public_clone_explains_why_it_is_withheld() {
    let env = Env::new();
    cloaked_project(&env);
    let out = env.ok("carol", &env.root, &["clone", "mirror", "carol"]);
    assert!(out.contains("public remotes never deliver") && out.contains("team remote"), "{out}");
    assert!(!out.contains("next `vl pull`"), "a pull from the mirror never brings them:\n{out}");
    let carol = env.root.join("carol");

    let out = env.vl("carol", &carol, &["cat", "internal/.env.plan", "-r", "main"]);
    let err = stderr(&out);
    assert!(!out.status.success());
    assert!(!err.contains("not present in this store"), "{err}");
    assert!(err.contains("cloaked under scope 'team' and its content never reached this repository") && err.contains("from the Veil server"), "{err}");

    let show = env.stdout("carol", &carol, &["show", "main"]);
    assert!(show.contains("(content hidden: cloaked:team; not received)"), "{show}");
    let diff = env.stdout("carol", &carol, &["diff", "-r", "main"]);
    assert!(diff.contains("cloaked:team; not received"), "{diff}");
}

#[test]
fn reading_a_cloaked_file_without_a_key_says_to_ask_for_a_grant() {
    let env = Env::new();
    cloaked_project(&env);
    let out = env.ok("bob", &env.root, &["clone", "team", "bob"]);
    assert!(out.contains("1 cloaked file(s) (scope 'team') you hold no key for"), "{out}");
    let bob = env.root.join("bob");
    let out = env.vl("bob", &bob, &["cat", "internal/.env.plan", "-r", "main"]);
    let err = stderr(&out);
    assert!(err.contains("you hold no key") && err.contains("vl scope grant team"), "{err}");
    let show = env.stdout("bob", &bob, &["show", "main"]);
    assert!(show.contains("(content hidden: cloaked:team; you hold no key)"), "{show}");
}

// ---- BUG-087: embargo merge wording and deadline -----------------------------

#[test]
fn an_embargoed_merge_reports_files_as_public_on_release_and_an_absolute_deadline() {
    let env = Env::new();
    let proj = env.project("alice", "proj", &[("auth.rs", "v1\n")]);
    env.ok("alice", &proj, &["ws", "new", "fix", "-r", "main"]);
    env.ok("alice", &proj, &["ws", "exec", "fix", "-m", "fix", "--", "sh", "-c", "printf 'v2\\n' > auth.rs"]);
    let out = env
        .cmd("alice", &proj, &["merge", "fix@", "--into", "main", "--embargo", "--until", "2099-12-01T09:00:00Z", "-m", "Fix"])
        // A POSIX TZ string needs no tz database.
        .env("TZ", "CET-1")
        .output()
        .unwrap();
    let all = text(&out);
    assert!(out.status.success(), "{all}");
    assert!(all.contains("until 2099-12-01 10:00:00 +01:00 (09:00:00 UTC)"), "{all}");
    assert!(all.contains("the merge and the history it brings in stay with") && all.contains("pushes hold them back"), "{all}");

    let out = env.cmd("alice", &proj, &["embargo", "list"]).env("TZ", "CET-1").output().unwrap();
    assert!(text(&out).contains("until 2099-12-01 10:00:00 +01:00 (09:00:00 UTC)"), "{}", text(&out));
    assert!(text(&out).lines().all(|l| l == l.trim_end()), "no trailing spaces: {:?}", text(&out));

    // A relative deadline is printed as a date, never as typed.
    env.ok("alice", &proj, &["undo"]);
    let out = env.ok("alice", &proj, &["merge", "fix@", "--into", "main", "--embargo", "--until", "+7d", "-m", "Fix"]);
    assert!(!out.contains("+7d") && out.contains("UTC"), "{out}");
}
