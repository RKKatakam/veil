//! `vl commit`, `vl describe`, `vl new -m`: git t7500–t7502 (commit),
//! t7509 (authorship), t7516 (races), t7518 (ident corner cases), t7524
//! (summary), t3900 (i18n messages), t0030 (stripspace); jj
//! test_commit_command, test_describe_command, test_advance_bookmarks.

use super::*;

// Scenario from git t7501-commit-basic-functionality.sh "commit message
// from -m": the change is described and a new empty change starts on it.
#[test]
fn commit_describes_the_change_and_starts_a_new_one() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("a.txt", "a\n");
    let wc = r.change("@");
    let out = r.ok(&["commit", "-m", "first"]);
    assert!(out.contains(&format!("Committed {}", &wc[..8])), "{out}");
    assert!(out.contains("Working copy now at:"), "{out}");
    assert_eq!(r.change("@-"), wc);
    assert_eq!(r.description("@-"), "first");
    assert!(r.changes().is_empty());
    assert!(r.out(&["log", "-n", "1"]).contains("(empty)"));
}

// Scenario from git t7501 "nothing to commit" / "--allow-empty": Veil
// commits an empty change (as `git commit --allow-empty` would).
#[test]
fn commit_of_an_empty_change_is_allowed() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("first");
    let c = r.commit("empty");
    let log = r.out(&["log"]);
    assert!(log.contains("(empty)"), "{log}");
    assert_eq!(r.description(c.as_str()), "empty");
    assert!(r.out(&["show", "--stat", c.as_str()]).contains("(no changes)") && r.out(&["show", c.as_str()]).contains("(no changes)"));
}

// Scenario from git t7501 "empty commit message": Git refuses; Veil
// records a change with no description (as jj does).
#[test]
fn commit_with_an_empty_message_has_no_description() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("a.txt", "a\n");
    r.ok(&["commit", "-m", ""]);
    assert_eq!(r.description("@-"), "(no description set)");
    assert_eq!(r.paths("@-"), vec!["a.txt"]);
}

// Scenario from git t7501 (no editor): `-m` is required.
#[test]
fn commit_and_describe_require_a_message() {
    let env = Env::new();
    let r = env.repo("p");
    let out = r.run(&["commit"]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    assert!(text(&out).contains("--message"), "{}", text(&out));
    let out = r.run(&["describe"]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
}

// Scenario from git t7502-commit-porcelain.sh / t0030-stripspace.sh: a
// multi-line message with a blank line keeps its body.
#[test]
fn multi_line_messages_are_kept() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("a.txt", "a\n");
    r.ok(&["commit", "-m", "Subject line\n\nBody paragraph one.\nSecond line."]);
    assert_eq!(r.description("@-"), "Subject line\n\nBody paragraph one.\nSecond line.");
    let log = r.out(&["log", "-n", "2"]);
    assert!(log.contains("Subject line"), "{log}");
    assert!(!log.contains("Body paragraph"), "log shows the first line only: {log}");
}

// Scenario from git t3900-i18n-commit.sh: non-ASCII messages round-trip.
#[test]
fn unicode_messages_round_trip() {
    let env = Env::new();
    let r = env.repo("p");
    let msg = "Ünïcödé: 日本語のコミット — ✓ emoji 🎉";
    r.write("a.txt", "a\n");
    r.ok(&["commit", "-m", msg]);
    assert_eq!(r.description("@-"), msg);
    assert!(r.out(&["log"]).contains(msg));
}

// Scenario from git t7502-commit-porcelain.sh (messages with control
// characters) and Veil's terminal-safety rule: escapes are printed escaped.
#[test]
fn control_characters_in_messages_are_printed_escaped() {
    let env = Env::new();
    let r = env.repo("p");
    r.ok(&["commit", "-m", "evil \u{1b}]0;title\u{7} \u{1b}[31mred"]);
    for args in [&["log"][..], &["show", "@-"], &["op", "log"], &["status"]] {
        let out = r.out(args);
        assert!(!out.contains('\u{1b}'), "{args:?} printed a raw escape: {out:?}");
    }
}

// Scenario from git t7501 "commit --amend" (message only) / jj
// test_describe_command.rs: describe another change; tags follow it.
#[test]
fn describe_rewrites_a_change_and_tags_follow() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("a.txt", "a\n");
    let one = r.commit("one");
    r.write("b.txt", "b\n");
    let two = r.commit("two");
    r.ok(&["tag", "set", "main", "-r", one.as_str()]);
    let old_snap = r.snap(one.as_str());
    let out = r.ok(&["describe", "-r", one.as_str(), "-m", "one, reworded"]);
    assert!(out.contains("Described"), "{out}");
    assert_eq!(r.description(one.as_str()), "one, reworded");
    assert_ne!(r.snap(one.as_str()), old_snap, "a new snapshot");
    assert_eq!(r.change("main"), one, "the tag follows the change");
    assert_eq!(r.change(&format!("{two}-")), one, "descendants are rebased");
    assert_eq!(r.read("a.txt"), "a\n");
}

// Scenario from jj test_describe_command.rs: describe does not start a
// new change; `describe` + `new` equals `commit` (except tags).
#[test]
fn describe_then_new_is_commit_without_moving_tags() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("a.txt", "a\n");
    let base = r.commit("base");
    r.ok(&["tag", "set", "main", "-r", base.as_str()]);
    r.write("b.txt", "b\n");
    let wc = r.change("@");
    r.ok(&["describe", "-m", "work"]);
    assert_eq!(r.change("@"), wc);
    r.ok(&["new"]);
    assert_eq!(r.change("@-"), wc);
    assert_eq!(r.change("main"), base, "describe + new moves no tag");
}

// Scenario from jj test_describe_command.rs: describing the root fails.
#[test]
fn describe_of_the_root_fails() {
    let env = Env::new();
    let r = env.repo("p");
    let err = r.fails(&["describe", "-r", "root", "-m", "x"]);
    assert!(err.contains("root snapshot"), "{err}");
}

// Scenario from jj test_advance_bookmarks.rs: `vl commit` moves every tag
// at the parent; `--no-advance` moves none.
#[test]
fn commit_advances_every_tag_at_the_parent() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("a.txt", "a\n");
    let base = r.commit("base");
    r.ok(&["tag", "set", "main", "-r", base.as_str()]);
    r.ok(&["tag", "set", "release", "-r", base.as_str()]);
    r.write("b.txt", "b\n");
    let c = r.commit("next");
    assert_eq!(r.change("main"), c);
    assert_eq!(r.change("release"), c);
    r.write("c.txt", "c\n");
    let d = r.change("@");
    r.ok(&["commit", "--no-advance", "-m", "held"]);
    assert_eq!(r.change("main"), c);
    assert_eq!(r.change("@-"), d);
}

// Scenario from jj test_advance_bookmarks.rs: a tag not at the parent
// (elsewhere in history) does not move.
#[test]
fn commit_does_not_move_tags_elsewhere() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("a.txt", "a\n");
    let one = r.commit("one");
    r.write("b.txt", "b\n");
    r.commit("two");
    r.ok(&["tag", "set", "old", "-r", one.as_str()]);
    r.write("c.txt", "c\n");
    r.commit("three");
    assert_eq!(r.change("old"), one);
}

// Scenario from git t7509-commit-authorship.sh: the author is
// `$VEIL_USER`, taken when the change is created.
#[test]
fn author_comes_from_veil_user_when_the_change_starts() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("a.txt", "a\n");
    r.commit("by alice");
    let out = r.cmd(&["new"]).env("VEIL_USER", "Alice Doe <alice@example.com>").output().unwrap();
    assert!(out.status.success());
    r.write("b.txt", "b\n");
    r.ok(&["commit", "-m", "by Alice Doe"]);
    let show = r.out(&["show", "--stat", "@-"]);
    assert!(show.contains("Author    : Alice Doe <alice@example.com>"), "{show}");
    let show = r.out(&["show", "--stat", "@---"]);
    assert!(show.contains("Author    : alice"), "{show}");
}

// Scenario from git t7518-ident-corner-cases.sh: odd author strings
// (newlines) cannot forge extra lines.
#[test]
fn author_with_a_newline_cannot_forge_output() {
    let env = Env::new();
    let r = env.bare_dir("p");
    let out = r.cmd(&["init"]).env("VEIL_USER", "mallory\nSignature : good").output().unwrap();
    assert!(out.status.success(), "{}", text(&out));
    let show = r.run(&["show", "--stat", "@"]);
    assert!(show.status.success(), "{}", text(&show));
    let s = stdout_of(&show);
    assert_eq!(s.lines().filter(|l| l.starts_with("Signature :")).count(), 1, "{s}");
    assert_eq!(s.lines().filter(|l| l.starts_with("Author    :")).count(), 1, "{s}");
}

// Scenario from git t7524-commit-summary.sh: the summary names the change.
#[test]
fn commit_summary_names_the_committed_and_the_new_change() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("a.txt", "a\n");
    let out = r.ok(&["commit", "-m", "summary test"]);
    let committed = r.change("@-");
    let wc = r.change("@");
    assert!(out.contains(&format!("Committed {}", &committed[..8])) && out.contains("summary test"), "{out}");
    assert!(out.contains(&format!("Working copy now at: {}", &wc[..8])), "{out}");
}

// Scenario from git t7516-commit-races.sh: a file edited during the
// command is recorded by the next one, never lost.
#[test]
fn an_edit_after_commit_belongs_to_the_next_change() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("a.txt", "v1\n");
    r.commit("one");
    r.write("a.txt", "v2\n");
    assert_eq!(r.changes(), vec!["M a.txt"]);
    assert_eq!(r.cat("a.txt", "@-"), "v1\n");
}

// Scenario from git t7501 "commit from a subdirectory" (paths are not
// limited to the subdirectory: Veil always records the whole tree).
#[test]
fn commit_from_a_subdirectory_records_the_whole_tree() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("top.txt", "t\n");
    r.write("sub/s.txt", "s\n");
    let out = r.run_in("sub", &["commit", "-m", "from sub"]);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(r.paths("@-"), vec!["sub/s.txt", "top.txt"]);
}

// Scenario from jj test_commit_command.rs: commit while `@` is a merge
// keeps both parents on the committed change.
#[test]
fn commit_of_a_merge_keeps_both_parents() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("a.txt", "a\n");
    let a = r.commit("a");
    r.ok(&["new", "root"]);
    r.write("b.txt", "b\n");
    let b = r.commit("b");
    r.ok(&["new", a.as_str(), b.as_str()]);
    r.commit("merge");
    let show = r.out(&["show", "--stat", "@-"]);
    assert_eq!(show.matches("Parent    :").count(), 2, "{show}");
    assert_eq!(r.paths("@-"), vec!["a.txt", "b.txt"]);
}

// Scenario from git t7501 "commit message from file" etc.: the message
// option takes text verbatim, including leading dashes after `=`.
#[test]
fn messages_that_look_like_options() {
    let env = Env::new();
    let r = env.repo("p");
    r.ok(&["commit", "--message=-m --no-advance"]);
    assert_eq!(r.description("@-"), "-m --no-advance");
}
