//! Adding, removing and moving files under automatic snapshots: git
//! t3700-add, t3600-rm, t7001-mv, t2200-add-update, t2201 (typechange),
//! t2202 (addremove), t2204 (add ignored); jj test_working_copy (new and
//! deleted files), test_file_track_untrack_commands.

use super::*;

// Scenario from git t3700-add.sh "Test of git add": no `add`; a new file
// is in the next snapshot.
#[test]
fn a_new_file_is_recorded_without_add() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("without-add.txt", "x\n");
    assert_eq!(r.changes(), vec!["A without-add.txt"]);
    assert_eq!(r.cat("without-add.txt", "@"), "x\n");
}

// Scenario from git t2202-add-addremove.sh: additions and deletions are
// recorded together.
#[test]
fn additions_and_deletions_are_recorded_together() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("old.txt", "o\n");
    r.commit("one");
    r.rm("old.txt");
    r.write("new.txt", "n\n");
    assert_eq!(r.changes(), vec!["A new.txt", "D old.txt"]);
}

// Scenario from git t3600-rm.sh "rm a file": deleting it records a
// deletion; history keeps it.
#[test]
fn deleting_a_file_records_a_deletion_and_history_keeps_it() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("gone.txt", "kept in history\n");
    let one = r.commit("one");
    r.rm("gone.txt");
    r.commit("rm");
    assert!(r.paths("@-").is_empty());
    assert_eq!(r.cat("gone.txt", one.as_str()), "kept in history\n");
}

// Scenario from git t3600-rm.sh "rm -r a directory".
#[test]
fn deleting_a_directory_records_every_file_in_it() {
    let env = Env::new();
    let r = env.repo("p");
    for p in ["d/a", "d/b", "d/e/f", "keep"] {
        r.write(p, "c\n");
    }
    r.commit("one");
    r.rm("d");
    assert_eq!(r.changes(), vec!["D d/a", "D d/b", "D d/e/f"]);
}

// Scenario from git t7001-mv.sh "moving the file out of subdirectory":
// a move is shown as a rename (detected, never stored), and the content
// is the same.
#[test]
fn moving_a_file_is_a_rename() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("path0/COPYING", "license text\n");
    r.commit("one");
    let wc = r.change("@");
    std::fs::rename(r.path("path0/COPYING"), r.path("COPYING")).unwrap();
    assert_eq!(r.changes(), vec!["R path0/COPYING -> COPYING"]);
    assert_eq!(r.cat("COPYING", "@"), "license text\n");
    assert_eq!(r.change("@"), wc, "the same change");
}

// Scenario from git t7001-mv.sh "moving a directory".
#[test]
fn moving_a_directory_moves_its_files() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("src/a.rs", "a\n");
    r.write("src/m/b.rs", "b\n");
    r.commit("one");
    std::fs::rename(r.path("src"), r.path("lib")).unwrap();
    assert_eq!(r.paths("@"), vec!["lib/a.rs", "lib/m/b.rs"]);
    r.commit("mv");
    assert_eq!(r.cat("lib/m/b.rs", "@-"), "b\n");
}

// Scenario from git t7001-mv.sh "git mv should overwrite a file": moving
// over an existing tracked file records the replacement.
#[test]
fn moving_over_an_existing_file() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("a", "A\n");
    r.write("b", "B\n");
    r.commit("one");
    std::fs::rename(r.path("a"), r.path("b")).unwrap();
    assert_eq!(r.changes(), vec!["D a", "M b"]);
    assert_eq!(r.cat("b", "@"), "A\n");
}

// Scenario from git t3700-add.sh "add an empty file" / an empty directory.
#[test]
fn an_empty_file_is_recorded_and_an_empty_directory_is_not() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("empty", "");
    r.mkdir("void/inner");
    assert_eq!(r.paths("@"), vec!["empty"]);
}

// Scenario from git t3700-add.sh "git add with filemode=0/1": the mode is
// recorded from the disk.
#[cfg(unix)]
#[test]
fn a_new_executable_is_recorded_as_executable() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("tool", "#!/bin/sh\n");
    r.chmod("tool", 0o700);
    assert!(r.files("@").iter().any(|f| f.path == "tool" && f.exec));
}

// Scenario from git t3700-add.sh "add ignored ones" / t2204: an ignored
// file is never recorded, and moving a tracked file into an ignored
// directory untracks it (on disk it stays).
#[test]
fn moving_a_file_into_an_ignored_directory_untracks_it() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("report.txt", "r\n");
    r.commit("one");
    r.mkdir("target");
    std::fs::rename(r.path("report.txt"), r.path("target/report.txt")).unwrap();
    assert_eq!(r.changes(), vec!["D report.txt"]);
    assert_eq!(r.read("target/report.txt"), "r\n");
}

// Scenario from git t7001-mv.sh with Veil's invariant: renaming a public
// file to a built-in secret name stops recording it (the old version
// stays in history, as for any cloak or isolate rule).
#[test]
fn renaming_a_file_to_a_secret_name_stops_recording_it() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("settings", "PORT=8080\n");
    r.commit("one");
    std::fs::rename(r.path("settings"), r.path(".env")).unwrap();
    r.write(".env", DOTENV);
    let st = r.status();
    assert!(st.contains("D settings") && st.contains("L .env"), "{st}");
    r.commit("rename");
    assert!(r.paths("@-").is_empty());
    assert!(!contains_bytes(&all_bytes(&r.path(".veil/objects")), "Xk29vLq8sPz"));
}

// Scenario from git t7001-mv.sh with Veil's invariant: moving a file into
// a cloaked directory records it cloaked.
#[test]
fn moving_a_file_into_a_cloaked_directory_cloaks_it() {
    let env = Env::new();
    let r = env.repo("p");
    r.ok(&["cloak", "private/"]);
    r.write("plan.txt", "draft\n");
    r.commit("one");
    r.mkdir("private");
    std::fs::rename(r.path("plan.txt"), r.path("private/plan.txt")).unwrap();
    let f = r.files("@").into_iter().find(|f| f.path == "private/plan.txt").unwrap();
    assert_eq!(f.vis, "cloaked:team");
}

// Scenario from git t2201-add-update-typechange.sh: a directory replaced
// by a file of the same name, recorded in one snapshot.
#[test]
fn a_directory_replaced_by_a_file() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("x/a", "a\n");
    r.write("x/b", "b\n");
    r.commit("dir");
    r.rm("x");
    r.write("x", "now a file\n");
    let mut ch = r.changes();
    ch.sort();
    assert_eq!(ch, vec!["A x", "D x/a", "D x/b"]);
    r.commit("file");
    assert_eq!(r.paths("@-"), vec!["x"]);
}

// Scenario from git t3700-add.sh "add a lot of files".
#[test]
fn many_new_files_in_one_snapshot() {
    let env = Env::new();
    let r = env.repo("p");
    for i in 0..500 {
        r.write(&format!("many/{:03}.txt", i), format!("{i}\n"));
    }
    assert_eq!(r.paths("@").len(), 500);
}

// Scenario from git t3600-rm.sh "rm of a modified file" (Git refuses
// without -f): an edit that was recorded before the deletion can be got
// back from the operation log.
#[test]
fn a_deleted_recorded_edit_is_recoverable_from_the_op_log() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("doc.txt", "v1\n");
    r.commit("one");
    r.write("doc.txt", "precious v2\n");
    r.ok(&["status"]);
    let op = r.out(&["op", "log", "-n", "1"]).split_whitespace().next().unwrap().to_string();
    r.rm("doc.txt");
    r.commit("deleted");
    r.ok(&["op", "restore", op.as_str()]);
    assert_eq!(r.read("doc.txt"), "precious v2\n");
}

// Scenario from git t3600-rm.sh "re-add a removed file".
#[test]
fn re_adding_a_removed_file() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("f", "same\n");
    r.commit("one");
    r.rm("f");
    r.commit("rm");
    r.write("f", "same\n");
    assert_eq!(r.changes(), vec!["A f"]);
}

// Scenario from git t2200-add-update.sh: edits to many tracked files at
// once, including in subdirectories.
#[test]
fn edits_everywhere_are_recorded_at_once() {
    let env = Env::new();
    let r = env.repo("p");
    for p in ["a", "d/b", "d/e/c"] {
        r.write(p, "1\n");
    }
    r.commit("one");
    for p in ["a", "d/b", "d/e/c"] {
        r.write(p, "2\n");
    }
    assert_eq!(r.changes(), vec!["M a", "M d/b", "M d/e/c"]);
}

// Scenario from git t3700-add.sh "add a secret by mistake" (Veil): a new
// public file with a credential is quarantined, never recorded.
#[test]
fn adding_a_credential_quarantines_the_file() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("config.js", LEAKY);
    let st = r.status();
    assert!(st.contains("Q config.js"), "{st}");
    assert!(r.paths("@").is_empty());
    r.commit("one");
    assert!(r.paths("@-").is_empty());
    assert!(!contains_bytes(&all_bytes(&r.path(".veil/objects")), "AKIAIOSFODNN7EXAMPLE"));
}
