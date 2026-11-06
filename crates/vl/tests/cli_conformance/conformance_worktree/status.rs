//! `vl status`: git t7508-status, t7060-wtstatus, t7061 (ignored), t7062
//! (ignorecase), t7512 (status help), t7525 (rename), t7063 (untracked
//! cache, via the stat cache); jj test_status_command.

use super::*;

// Scenario from git t7508-status.sh "status (clean)".
#[test]
fn status_of_a_clean_working_copy() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("a.txt", "a\n");
    r.commit("one");
    let st = r.status();
    assert!(st.contains("The working copy has no changes."), "{st}");
    assert!(st.contains("Workspace    : default"), "{st}");
    assert!(st.contains("Working copy : @"), "{st}");
    assert!(st.contains("Parent       :") && st.contains("one"), "{st}");
}

// Scenario from git t7508-status.sh "status (basic)": added, modified and
// deleted paths, sorted, with letters.
#[test]
fn status_lists_added_modified_and_deleted_paths() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("mod.txt", "1\n");
    r.write("del.txt", "1\n");
    r.write("dir/keep.txt", "1\n");
    r.commit("base");
    r.write("mod.txt", "2\n");
    r.rm("del.txt");
    r.write("dir/new.txt", "n\n");
    r.write("aaa-new.txt", "n\n");
    assert_eq!(r.changes(), vec!["A aaa-new.txt", "D del.txt", "A dir/new.txt", "M mod.txt"]);
}

// Scenario from git t7060-wtstatus.sh: paths are shown from the root, also
// from a subdirectory (Git shows them relative to the current directory;
// a deliberate difference).
#[test]
fn status_paths_are_relative_to_the_root() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("top.txt", "t\n");
    r.write("sub/s.txt", "s\n");
    let out = r.run_in("sub", &["status"]);
    let s = stdout_of(&out);
    assert!(s.contains("A sub/s.txt") && s.contains("A top.txt"), "{s}");
}

// Scenario from jj test_status_command.rs: `vl st` is `vl status`.
#[test]
fn st_is_an_alias() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("a.txt", "a\n");
    assert_eq!(r.out(&["st"]), r.out(&["status"]));
}

// Scenario from git t7508-status.sh (exit code): status succeeds whatever
// the working copy holds.
#[test]
fn status_exits_zero_with_changes() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("a.txt", "a\n");
    r.write("leak.js", LEAKY);
    assert_eq!(r.run(&["status"]).status.code(), Some(0));
}

// Scenario from jj test_status_command.rs "status of a merge": both parents.
#[test]
fn status_of_a_merge_shows_both_parents() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("a.txt", "a\n");
    let a = r.commit("left");
    r.ok(&["new", "root"]);
    r.write("b.txt", "b\n");
    let b = r.commit("right");
    r.ok(&["new", a.as_str(), b.as_str()]);
    let st = r.status();
    assert_eq!(st.matches("Parent       :").count(), 2, "{st}");
    assert!(st.contains("The working copy has no changes."), "changes are against the merged parents: {st}");
}

// Scenario from git t7512-status-help.sh (status during a conflicted
// merge) / jj test_status_command.rs "conflicts".
#[test]
fn status_lists_unresolved_conflicts_and_clears_them_on_edit() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("a.txt", "base\n");
    let base = r.commit("base");
    r.write("a.txt", "left\n");
    let left = r.commit("left");
    r.ok(&["new", base.as_str()]);
    r.write("a.txt", "right\n");
    let right = r.commit("right");
    r.ok(&["new", left.as_str(), right.as_str()]);
    let st = r.status();
    assert!(st.contains("Unresolved conflicts:") && st.contains("C a.txt"), "{st}");
    let content = r.read("a.txt");
    assert!(content.contains("<<<<<<<") && content.contains("left") && content.contains("right"), "{content}");
    r.write("a.txt", "resolved\n");
    let st = r.status();
    assert!(!st.contains("Unresolved conflicts"), "{st}");
    assert!(st.contains("M a.txt"), "{st}");
}

// Scenario from git t7061-wtstatus-ignore.sh: ignored files are not shown.
#[test]
fn status_does_not_show_ignored_files() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("target/out.o", "o\n");
    r.write("x.txt", "x\n");
    let st = r.status();
    assert!(!st.contains("target"), "{st}");
    assert!(st.contains("A x.txt"), "{st}");
}

// Scenario from git t7508-status.sh with Veil's tiers: local-only and
// quarantined files have their own sections and are never "changes".
#[test]
fn status_reports_local_only_and_quarantined_files() {
    let env = Env::new();
    let r = env.repo("p");
    r.write(".netrc", DOTENV);
    r.write("cfg.js", LEAKY);
    r.write("app.py", "print(1)\n");
    let st = r.status();
    assert!(st.contains("Local-only (isolated; never snapshotted or pushed):\n  L .netrc"), "{st}");
    assert!(st.contains("Q cfg.js [quarantined]  (aws-access-key-id; never recorded)"), "{st}");
    assert!(st.contains("warning: cfg.js quarantined"), "{st}");
    assert_eq!(r.changes(), vec!["A app.py"]);
    assert!(!st.contains("Xk29vLq8sPz") && !st.contains("AKIAIOSFODNN7EXAMPLE"), "no secret values: {st}");
}

// Scenario from git t7525-status-rename.sh: a rename shows as one.
#[test]
fn status_shows_a_rename() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("old.txt", "same content\n");
    r.commit("one");
    std::fs::rename(r.path("old.txt"), r.path("new.txt")).unwrap();
    assert_eq!(r.changes(), vec!["R old.txt -> new.txt"]);
}

// Scenario from git t7508-status.sh (type change): a file replaced by a
// directory.
#[test]
fn status_of_a_file_replaced_by_a_directory() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("f", "file\n");
    r.commit("one");
    r.rm("f");
    r.write("f/g", "inside\n");
    let ch = r.changes();
    assert!(ch.contains(&"D f".to_string()) && ch.contains(&"A f/g".to_string()), "{ch:?}");
}

// Scenario from git t7062-wtstatus-ignorecase.sh: a case-only pair warns.
#[test]
fn status_warns_about_a_case_only_pair() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("Makefile", "a\n");
    r.write("makefile", "b\n");
    let st = r.status();
    assert!(st.contains("differ only in case"), "{st}");
}

// Scenario from jj test_status_command.rs in a cloaked workspace.
#[test]
fn status_names_a_cloaked_workspace() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("base");
    r.ok(&["ws", "new", "fix", "--cloak"]);
    r.ok(&["ws", "switch", "fix"]);
    let st = r.status();
    assert!(st.contains("Workspace    : fix [cloaked:team]"), "{st}");
}

// Scenario from git t7063-status-untracked-cache.sh / t0010-racy-git.sh: a
// same-size edit within the same second is noticed.
#[test]
fn same_size_edits_in_quick_succession_are_noticed() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("f", "aaa\n");
    r.commit("one");
    for _ in 0..5 {
        r.write("f", "bbb\n");
        assert_eq!(r.changes(), vec!["M f"]);
        r.write("f", "aaa\n");
        assert!(r.changes().is_empty());
    }
}

// Scenario from git t0010-racy-git.sh: a same-size edit with the mtime set
// back to the recorded value is still noticed.
#[test]
fn an_edit_that_restores_the_old_mtime_is_noticed() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("f", "aaa\n");
    r.commit("one");
    r.ok(&["status"]);
    let m = std::fs::metadata(r.path("f")).unwrap().modified().unwrap();
    r.write("f", "zzz\n");
    std::fs::File::options().write(true).open(r.path("f")).unwrap().set_modified(m).unwrap();
    assert_eq!(r.changes(), vec!["M f"]);
}

// Scenario from git t7508-status.sh with an executable-bit change only.
#[cfg(unix)]
#[test]
fn status_shows_a_mode_only_change() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("s.sh", "#!/bin/sh\n");
    r.commit("one");
    r.chmod("s.sh", 0o755);
    assert_eq!(r.changes(), vec!["M s.sh"]);
}

// Scenario from git t7508-status.sh (unreadable file): the file is
// reported, its last version kept, and the command still works.
#[cfg(unix)]
#[test]
fn status_with_an_unreadable_file() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("secret.txt", "v1\n");
    r.commit("one");
    r.write("secret.txt", "v2\n");
    r.chmod("secret.txt", 0o000);
    if std::fs::read(r.path("secret.txt")).is_ok() {
        r.chmod("secret.txt", 0o644);
        return; // running as root
    }
    let out = r.run(&["status"]);
    r.chmod("secret.txt", 0o644);
    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("cannot read"), "{}", text(&out));
    assert!(!text(&out).contains("D secret.txt"), "{}", text(&out));
}
