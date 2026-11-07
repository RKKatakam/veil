//! `vl duplicate`, `vl cherry-pick` and rename reports through the binary:
//! confidentiality (cloaked content, embargoed fixes and sealed text never
//! reach an outsider, an error message, the log or JSON) and hostile input
//! (names with terminal escapes, hostile revisions and environment
//! values, concurrent runs, a run killed half way).

#[path = "../cli_conformance/conformance_history/support.rs"]
mod support;

use std::{
    process::Stdio,
    time::{Duration, Instant},
};

use support::*;

fn lines10(prefix: &str) -> String {
    lines(prefix, 10)
}

fn no_escape(what: &str, t: &str) {
    assert!(!t.contains('\u{1b}'), "{what} printed a raw escape: {t:?}");
    assert!(!t.contains('\u{7}'), "{what} printed a raw BEL: {t:?}");
}

/// A cloaked secret file copied onto the public line: an outsider reads
/// none of it, and neither
/// `vl log`, `vl show --json` nor `vl duplicate --json` as an outsider
/// shows it.
#[test]
fn copies_of_cloaked_work_are_unreadable_to_outsiders() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("base", &[("a.txt", &lines10("a"))]);
    r.tag("main", "@-");
    r.ok(&["cloak", "secret/.env.key"]);
    r.write("secret/.env.key", "CLOAKED-DUP-SECRET-1\n");
    r.ok(&["commit", "--no-advance", "-m", "public words"]);
    r.tag("withsecret", "@-");
    r.ok(&["new", "main"]);
    let out = r.ok(&["duplicate", "withsecret", "-d", "main", "--json"]);
    assert!(!out.contains("CLOAKED-DUP-SECRET-1"));
    let out = r.ok(&["cherry-pick", "withsecret", "-x"]);
    assert!(!out.contains("CLOAKED-DUP-SECRET-1"));
    assert!(r.outsider_reads("CLOAKED-DUP-SECRET-1").is_empty(), "{:?}", r.outsider_reads("CLOAKED-DUP-SECRET-1"));
    assert!(r.store_contains("CLOAKED-DUP-SECRET-1").is_empty(), "sealed at rest");
    // The member reads the copy.
    assert_eq!(r.read("secret/.env.key"), "CLOAKED-DUP-SECRET-1\n");
    assert_eq!(r.visibility("@-", "secret/.env.key"), veil_core::Visibility::Cloaked { scope: "team".into() });
}

/// Threat review 11 through the binary: a copy of the fix outside the
/// embargo (onto the pre-merge line) is refused; the refusal names neither
/// the fix's files nor its description, and nothing is recorded.
#[test]
fn an_embargoed_fix_cannot_be_copied_out_and_the_refusal_names_nothing() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("v1", &[("a.c", &lines10("vuln"))]);
    r.tag("main", "@-");
    // Not a tag: `vl merge --into main` moves every tag at main.
    let v1 = r.sid("@-");
    r.ok(&["new", "main"]);
    r.commit("EMBARGOED-DESC-Z9", &[("FIX-NAME-Z9.c", "the fix\n")]);
    r.tag("fix", "@-");
    r.ok(&["merge", "fix", "--into", "main", "--embargo", "-m", "embargoed fix"]);
    let before = r.op_head();
    let t = r.fails(&["duplicate", "fix", "-d", &v1[..16]]);
    assert!(t.contains("withholds"), "{t}");
    assert!(!t.contains("Z9"), "{t}");
    let t = r.fails(&["duplicate", "fix", "-d", &v1[..16], "--json"]);
    assert!(!t.contains("Z9"), "{t}");
    r.ok(&["new", &v1[..16]]);
    let mid = r.op_head();
    let t = r.fails(&["cherry-pick", "fix"]);
    assert!(!t.contains("Z9"), "{t}");
    assert_eq!(r.op_head(), mid);
    assert_ne!(before, mid);
}

/// File names with terminal escapes: the rename reports of `vl merge`,
/// `vl rebase` and `vl cherry-pick` print them escaped, and JSON escapes
/// them too.
#[test]
fn hostile_names_in_rename_reports_are_escaped() {
    let env = Env::new();
    let r = env.repo("p");
    let evil_old = "old\u{1b}]52;c;cHduZWQ=\u{7}.txt";
    let evil_new = "new\u{1b}[2J\u{1b}[31m.txt";
    let base = lines10("l");
    r.commit("base", &[(evil_old, &base)]);
    r.tag("base", "@-");
    std::fs::rename(r.dir.join(evil_old), r.dir.join(evil_new)).unwrap();
    r.ok(&["commit", "--no-advance", "-m", "rename"]);
    r.tag("mv", "@-");
    r.ok(&["new", "base"]);
    let edited = format!("EDIT\n{base}");
    r.commit("edit", &[(evil_old, &edited)]);
    r.tag("edit", "@-");
    // merge
    let out = r.run(&["merge", "mv", "-m", "m"]);
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    assert!(t.contains("followed rename"), "{t}");
    no_escape("vl merge", &t);
    r.ok(&["undo"]);
    // cherry-pick (and its JSON)
    r.ok(&["new", "mv"]);
    let out = r.run(&["cherry-pick", "edit", "--json"]);
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    no_escape("vl cherry-pick --json", &t);
    let v: serde_json::Value = serde_json::from_str(t.lines().find(|l| l.starts_with('{')).unwrap()).unwrap();
    assert_eq!(v["duplicates"][0]["renames"][0]["to"], evil_new, "the JSON string decodes to the real name");
    assert_eq!(r.read(evil_new), edited);
    r.ok(&["undo"]);
    // rebase
    let out = r.run(&["rebase", "-s", "edit", "-d", "mv"]);
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    no_escape("vl rebase", &t);
}

/// Hostile revisions and descriptions: refused cleanly, escaped, nothing
/// recorded.
#[test]
fn hostile_revisions_and_descriptions_are_refused_cleanly() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("base", &[("a", "a\n")]);
    let before = r.op_head();
    for args in [
        &["duplicate", "\u{1b}]52;c;ZXZpbA==\u{7}"][..],
        &["duplicate", "@-", "-d", "\u{1b}[2Jnope"],
        &["cherry-pick", "zzzzzzzzzzzz\u{1b}[31m"],
        &["duplicate", "@-..@-"],
        &["duplicate", &"x".repeat(100_000)],
    ] {
        let out = r.run(args);
        let t = text(&out);
        assert!(!out.status.success(), "{args:?}: {t}");
        assert!(exited_cleanly(&out), "{args:?} crashed: {t}");
        no_escape("an error", &t);
    }
    assert_eq!(r.op_head(), before, "nothing recorded");
}

/// Concurrency: several `vl duplicate` at once each either succeed or fail
/// cleanly; every success is one operation and one copy.
#[test]
fn concurrent_duplicates_are_each_atomic() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("base", &[("a", "a\n")]);
    r.commit("src", &[("b", "b\n")]);
    r.tag("src", "@-");
    let before = r.visible_changes().len();
    let children: Vec<_> = (0..6)
        .map(|_| env.cmd("alice", &r.dir, &["--no-snapshot", "duplicate", "src"]).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap())
        .collect();
    let mut ok = 0;
    for c in children {
        let out = c.wait_with_output().unwrap();
        assert!(exited_cleanly(&out), "{}", text(&out));
        ok += usize::from(out.status.success());
    }
    assert!(ok >= 1);
    assert_eq!(r.visible_changes().len(), before + ok, "one copy per success");
    r.ok(&["fsck"]);
}

/// A run killed half way leaves a consistent repository (one transaction:
/// all or nothing).
#[test]
fn a_killed_duplicate_leaves_the_repository_consistent() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("base", &[("f", "0\n")]);
    r.tag("base", "@-");
    for i in 0..60 {
        r.commit(&format!("c{i}"), &[(&format!("f{i}"), &format!("{i}\n"))]);
    }
    r.tag("tip", "@-");
    r.ok(&["new", "base"]);
    let before = r.visible_changes().len();
    for delay in [5u64, 40, 120] {
        let mut c = env.cmd("alice", &r.dir, &["duplicate", "base..tip", "-d", "base"]).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
        std::thread::sleep(Duration::from_millis(delay));
        let _ = c.kill();
        let _ = c.wait();
        let now = r.visible_changes().len();
        assert!(now == before || (now - before).is_multiple_of(60), "all or nothing: {before} → {now}");
        r.ok(&["fsck"]);
        r.ok(&["status"]);
    }
    // Size: 60 changes copied in one go, quickly.
    let start = Instant::now();
    r.ok(&["duplicate", "base..tip", "-d", "base"]);
    eprintln!("duplicate of 60 changes: {:?}", start.elapsed());
}

/// BUG-680: `vl merge` printed its warnings unescaped, and they quote
/// paths from the merged trees. A teammate's file named with a terminal
/// escape, whose audience the merge refuses to move, reached the terminal
/// raw.
#[test]
fn merge_warnings_quoting_hostile_paths_are_escaped() {
    let env = Env::new();
    let r = env.repo("p");
    r.ok(&["scope", "create", "ops"]);
    r.ok(&["cloak", "secrets/*.pem"]);
    r.write("secrets/x\u{1b}[31mRED.pem", "pw\n");
    r.ok(&["commit", "-m", "base"]);
    r.tag("main", "@-");
    let policy: String = r
        .read(".veilpolicy")
        .lines()
        .map(|l| match l.starts_with("secrets/*.pem") {
            true => "secrets/*.pem cloak ops\n".to_string(),
            false => format!("{l}\n"),
        })
        .collect();
    assert!(policy.contains("secrets/*.pem cloak ops"), "{policy}");
    r.write(".veilpolicy", policy);
    r.ok(&["commit", "--no-advance", "-m", "rekey"]);
    r.tag("rekey", "@-");
    r.ok(&["new", "main"]);
    r.commit("other", &[("other", "y\n")]);
    let out = r.run(&["merge", "rekey", "-m", "m"]);
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    assert!(t.contains("kept the destination's .veilpolicy"), "{t}");
    no_escape("vl merge warnings", &t);
}

/// BUG-681 (found while building `vl duplicate`'s embargo rule, design 1
/// threat review 11, adversarial note): `vl restore --from <fix> PATH` on
/// a line outside the embargo copies a withheld fix's file as public
/// content, and the next public push publishes its name and content
/// before the release. `vl duplicate` refuses the same copy.
#[test]
fn restoring_from_an_embargoed_fix_onto_another_line_publishes_nothing() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("v1", &[("a.c", "v\n")]);
    r.tag("main", "@-");
    // Not a tag: `vl merge --into main` moves every tag at main.
    let v1 = r.sid("@-");
    r.ok(&["new", "main"]);
    r.commit("fix", &[("FIXNAME-K7.c", "FIXBODY-K7\n")]);
    r.tag("fix", "@-");
    r.ok(&["merge", "fix", "--into", "main", "--embargo", "-m", "embargoed"]);
    r.ok(&["new", &v1[..16]]);
    // Refused, or kept sealed under the embargo: either way not public.
    let out = r.run(&["restore", "--from", "fix", "FIXNAME-K7.c"]);
    if out.status.success() {
        r.ok(&["commit", "-m", "rel"]);
        r.tag("rel", "@-");
    }
    let mirror = env.dir("mirror");
    env.run("alice", &mirror, &["init", "--bare"]);
    r.ok(&["remote", "add", "pub", mirror.to_str().unwrap(), "--public"]);
    r.ok(&["push", "pub"]);
    assert!(store_contains(&mirror, b"FIXNAME-K7").is_empty(), "the fix's name reached the public remote");
    assert!(store_contains(&mirror, b"FIXBODY-K7").is_empty(), "the fix's content reached the public remote");
}

/// Design 2, threat review 1: renames are reported, never stored: not in
/// the snapshots, trees or operations a merge that followed one writes.
#[test]
fn followed_renames_are_never_recorded() {
    let env = Env::new();
    let r = env.repo("p");
    let base = lines10("l");
    r.commit("base", &[("before-RN7.txt", &base)]);
    r.tag("base", "@-");
    std::fs::rename(r.dir.join("before-RN7.txt"), r.dir.join("after-RN7.txt")).unwrap();
    r.ok(&["commit", "--no-advance", "-m", "mv"]);
    r.tag("mv", "@-");
    r.ok(&["new", "base"]);
    r.commit("edit", &[("before-RN7.txt", &format!("EDIT\n{base}"))]);
    let out = r.ok(&["merge", "mv", "-m", "plain message"]);
    assert!(out.contains("followed rename"), "{out}");
    let ops = r.ok(&["op", "log", "--json"]);
    assert!(!ops.contains("before-RN7") && !ops.contains("followed"), "{ops}");
    assert!(r.store_contains("followed").is_empty());
    assert!(r.store_contains("before-RN7.txt -> after-RN7.txt").is_empty());
}
