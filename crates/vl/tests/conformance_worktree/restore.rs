//! `vl restore`: git t2070-restore, t2022-checkout-paths, t2025
//! (no-overlay), t7102-reset, t7104-reset-hard, t7101 (empty subdirs),
//! t7106 (unborn), t7111 (reset table); jj test_restore_command.

use crate::*;

fn base(env: &Env) -> (R<'_>, String) {
    let r = env.repo("p");
    r.write("a.txt", "a1\n");
    r.write("b.txt", "b1\n");
    r.write("sub/c.txt", "c1\n");
    r.write("subfile", "s1\n");
    let c = r.commit("base");
    (r, c)
}

// Scenario from git t2070-restore.sh "restore a file, ignoring branch".
#[test]
fn restore_one_path_discards_only_its_edit() {
    let env = Env::new();
    let (r, _) = base(&env);
    r.write("a.txt", "a2\n");
    r.write("b.txt", "b2\n");
    let out = r.ok(&["restore", "a.txt"]);
    assert!(out.contains("Restored 1 path(s)"), "{out}");
    assert_eq!(r.read("a.txt"), "a1\n");
    assert_eq!(r.read("b.txt"), "b2\n");
    assert_eq!(r.changes(), vec!["M b.txt"]);
}

// Scenario from git t7104-reset-hard.sh / t7102-reset.sh "--hard": every
// edit, addition and deletion is undone.
#[test]
fn restore_without_paths_resets_everything() {
    let env = Env::new();
    let (r, _) = base(&env);
    r.write("a.txt", "a2\n");
    r.rm("b.txt");
    r.write("new/added.txt", "n\n");
    r.ok(&["restore"]);
    assert_eq!(r.read("a.txt"), "a1\n");
    assert_eq!(r.read("b.txt"), "b1\n");
    assert!(!r.exists("new/added.txt"));
    assert!(r.changes().is_empty());
}

// Scenario from git t7101-reset-empty-subdirs.sh: directories that a
// restore leaves empty are removed (as a checkout removes them).
#[test]
#[ignore = "BUG-209: `vl restore` leaves the directories it empties behind"]
fn restore_removes_directories_it_empties() {
    let env = Env::new();
    let (r, _) = base(&env);
    r.write("new/deeper/added.txt", "n\n");
    r.ok(&["restore"]);
    assert!(!r.exists("new"), "{:?}", r.disk());
    r.ok(&["restore", "--from", "root", "sub"]);
    assert!(!r.exists("sub"), "{:?}", r.disk());
}

// Scenario from git t2070-restore.sh with a directory pathspec: prefixes
// match whole components (`sub` is not `subfile`).
#[test]
fn restore_of_a_directory_matches_whole_components() {
    let env = Env::new();
    let (r, _) = base(&env);
    r.write("sub/c.txt", "c2\n");
    r.write("sub/new.txt", "n\n");
    r.write("subfile", "s2\n");
    r.ok(&["restore", "sub"]);
    assert_eq!(r.read("sub/c.txt"), "c1\n");
    assert!(!r.exists("sub/new.txt"));
    assert_eq!(r.read("subfile"), "s2\n");
}

// Scenario from git t2022-checkout-paths.sh (`checkout REV -- path`).
#[test]
fn restore_from_another_revision() {
    let env = Env::new();
    let (r, base) = base(&env);
    r.write("a.txt", "a2\n");
    r.commit("two");
    r.write("a.txt", "a3\n");
    r.ok(&["restore", "--from", base.as_str(), "a.txt"]);
    assert_eq!(r.read("a.txt"), "a1\n");
    assert_eq!(r.changes(), vec!["M a.txt"], "a1 differs from @- (a2)");
}

// Scenario from git t2025-checkout-no-overlay.sh: paths absent from the
// source are removed.
#[test]
fn restore_from_a_revision_without_the_path_removes_it() {
    let env = Env::new();
    let (r, _) = base(&env);
    r.ok(&["restore", "--from", "root", "sub"]);
    assert!(!r.exists("sub/c.txt"));
    assert_eq!(r.changes(), vec!["D sub/c.txt"]);
}

// Scenario from git t7106-reset-unborn-branch.sh: in a fresh repository
// `@-` is the root, so restore empties the working copy.
#[test]
fn restore_in_a_fresh_repository_empties_it() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("a.txt", "a\n");
    r.ok(&["restore", "a.txt"]);
    assert!(!r.exists("a.txt"));
    // Undo brings it back.
    r.ok(&["undo"]);
    assert_eq!(r.read("a.txt"), "a\n");
}

// Scenario from git t2070-restore.sh run from a subdirectory: paths are
// relative to the current directory; `..` and absolute paths work.
#[test]
fn restore_paths_relative_to_the_current_directory() {
    let env = Env::new();
    let (r, _) = base(&env);
    r.write("sub/c.txt", "c2\n");
    r.write("a.txt", "a2\n");
    let out = r.run_in("sub", &["restore", "c.txt"]);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(r.read("sub/c.txt"), "c1\n");
    assert_eq!(r.read("a.txt"), "a2\n");
    let out = r.run_in("sub", &["restore", "../a.txt"]);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(r.read("a.txt"), "a1\n");
    r.write("b.txt", "b2\n");
    r.ok(&["restore", r.path("b.txt").to_str().unwrap()]);
    assert_eq!(r.read("b.txt"), "b1\n");
}

// Scenario from git t2070-restore.sh (pathspec outside the repository).
#[test]
fn restore_of_a_path_outside_the_repository_is_refused() {
    let env = Env::new();
    let (r, _) = base(&env);
    r.write("a.txt", "a2\n");
    let err = r.fails(&["restore", "../outside"]);
    assert!(err.contains("escapes"), "{err}");
    assert_eq!(r.read("a.txt"), "a2\n", "nothing was restored");
}

// Scenario from git t2070-restore.sh (an absolute pathspec outside the
// work tree is an error in Git). Veil takes `/etc/passwd` as the
// repository's own `etc/passwd`.
#[test]
#[ignore = "BUG-204: an absolute path outside the repository is taken relative to the repository root"]
fn restore_of_an_absolute_path_outside_the_repository_is_refused() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("etc/passwd", "recorded\n");
    r.commit("one");
    r.write("etc/passwd", "my edit\n");
    let out = r.run(&["restore", "/etc/passwd"]);
    assert!(!out.status.success(), "{}", text(&out));
    assert_eq!(r.read("etc/passwd"), "my edit\n", "an unrelated file was restored");
}

// Scenario from git t2070-restore.sh (pathspec matching nothing). Git
// reports an error; Veil restores nothing and says so (a documented,
// deliberate difference: `Restored 0 path(s)`).
#[test]
fn restore_of_a_path_that_matches_nothing_changes_nothing() {
    let env = Env::new();
    let (r, _) = base(&env);
    r.write("a.txt", "a2\n");
    let out = r.ok(&["restore", "nosuch.txt"]);
    assert!(out.contains("Restored 0 path(s)"), "{out}");
    assert_eq!(r.read("a.txt"), "a2\n");
}

// Scenario from jj test_restore_command.rs: restore is an operation, and
// `vl undo` brings the discarded edits back.
#[test]
fn undo_brings_back_what_restore_discarded() {
    let env = Env::new();
    let (r, _) = base(&env);
    r.write("a.txt", "precious edit\n");
    r.write("extra.txt", "extra\n");
    r.ok(&["restore"]);
    assert_eq!(r.read("a.txt"), "a1\n");
    let out = r.ok(&["undo"]);
    assert!(out.contains("restore"), "{out}");
    assert_eq!(r.read("a.txt"), "precious edit\n");
    assert_eq!(r.read("extra.txt"), "extra\n");
}

// Scenario from git t7104-reset-hard.sh (untracked and ignored files
// survive `reset --hard`): ignored and isolated files are not touched.
#[test]
fn restore_leaves_ignored_and_isolated_files_alone() {
    let env = Env::new();
    let (r, _) = base(&env);
    r.write("target/build.o", "obj\n");
    r.write(".env", DOTENV);
    r.write("a.txt", "a2\n");
    r.ok(&["restore"]);
    assert_eq!(r.read("target/build.o"), "obj\n");
    assert_eq!(r.read(".env"), DOTENV);
    assert_eq!(r.read("a.txt"), "a1\n");
}

// Scenario from the secrets guide ("has an edit you want to throw away"):
// restoring a quarantined edit puts the recorded version back.
#[test]
fn restore_puts_back_the_recorded_version_of_a_quarantined_edit() {
    let env = Env::new();
    let (r, _) = base(&env);
    r.write("a.txt", LEAKY);
    let st = r.ok(&["status"]);
    assert!(st.contains("Q a.txt"), "{st}");
    r.ok(&["restore", "a.txt"]);
    assert_eq!(r.read("a.txt"), "a1\n");
    assert!(!r.ok(&["status"]).contains("quarantined"));
}

// Scenario from git t2070-restore.sh with the executable bit.
#[cfg(unix)]
#[test]
fn restore_restores_the_executable_bit() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("run.sh", "#!/bin/sh\n");
    r.chmod("run.sh", 0o755);
    r.commit("exec");
    r.chmod("run.sh", 0o644);
    r.ok(&["restore", "run.sh"]);
    assert!(r.is_exec("run.sh"));
    assert!(r.changes().is_empty());
}

// Scenario from git t7111-reset-table.sh (the effect on each kind of
// path): modified, deleted, added, and unchanged at once, restored from a
// revision two steps back.
#[test]
fn restore_from_two_back_applies_the_whole_difference() {
    let env = Env::new();
    let (r, base) = base(&env);
    r.write("a.txt", "a2\n");
    r.rm("b.txt");
    r.write("d.txt", "d2\n");
    r.commit("two");
    r.write("e.txt", "wip\n");
    r.ok(&["restore", "--from", base.as_str()]);
    let mut want = vec!["a.txt", "b.txt", "sub/c.txt", "subfile"];
    want.sort();
    assert_eq!(r.disk_files(), want);
    assert_eq!(r.read("a.txt"), "a1\n");
}

// Scenario from git t2022-checkout-paths.sh / t2000: restoring a path
// that is a file in the working copy and a directory in the source.
#[test]
#[ignore = "BUG-201: `vl restore` fails half way when a path is a file on one side and a directory on the other"]
fn restore_a_directory_over_a_file() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("f/g.txt", "inside\n");
    r.commit("dir");
    r.rm("f");
    r.write("f", "now a file\n");
    let out = r.run(&["restore"]);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(r.read("f/g.txt"), "inside\n");
}

// The reverse of the previous scenario (git t2000): a directory in the
// working copy, a file in the source. Today the restore removes the
// directory's files, then fails to write the file, and every retry fails.
#[test]
#[ignore = "BUG-201: `vl restore` fails half way when a path is a file on one side and a directory on the other"]
fn restore_a_file_over_a_directory() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("f", "a file\n");
    r.commit("file");
    r.rm("f");
    r.write("f/g.txt", "inside\n");
    let out = r.run(&["restore"]);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(r.read("f"), "a file\n");
    assert!(r.changes().is_empty());
}

// Scenario from git t7110-reset-merge.sh / jj test_restore_command.rs
// "restore in a merge": with a merge as the working copy, restoring
// discards *edits*, i.e. goes back to the merged parents, which is what
// `vl status` compares against. Today it restores from the first parent
// only and deletes the other parent's files.
#[test]
#[ignore = "BUG-208: `vl restore` in a merge working copy restores from the first parent only, deleting the other parent's files"]
fn restore_in_a_merge_goes_back_to_the_merged_parents() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("a.txt", "a\n");
    let a = r.commit("A");
    r.ok(&["new", "root"]);
    r.write("b.txt", "b\n");
    let b = r.commit("B");
    r.ok(&["new", a.as_str(), b.as_str()]);
    assert!(r.changes().is_empty());
    r.write("a.txt", "stray edit\n");
    r.ok(&["restore"]);
    assert_eq!(r.read("a.txt"), "a\n");
    assert_eq!(r.read("b.txt"), "b\n", "the second parent's file is still there");
    assert!(r.changes().is_empty(), "{:?}", r.changes());
}

// Scenario from git t2070-restore.sh (`--source` + several pathspecs).
#[test]
fn restore_several_paths_at_once() {
    let env = Env::new();
    let (r, _) = base(&env);
    for p in ["a.txt", "b.txt", "sub/c.txt", "subfile"] {
        r.write(p, "edited\n");
    }
    r.ok(&["restore", "a.txt", "sub/c.txt"]);
    assert_eq!(r.read("a.txt"), "a1\n");
    assert_eq!(r.read("sub/c.txt"), "c1\n");
    assert_eq!(r.read("b.txt"), "edited\n");
    assert_eq!(r.read("subfile"), "edited\n");
}

// Scenario from jj test_restore_command.rs: restoring a file that the
// working copy deleted brings it back with its content.
#[test]
fn restore_brings_back_a_deleted_file_and_its_directory() {
    let env = Env::new();
    let (r, _) = base(&env);
    r.rm("sub");
    assert_eq!(r.changes(), vec!["D sub/c.txt"]);
    r.ok(&["restore", "sub/c.txt"]);
    assert_eq!(r.read("sub/c.txt"), "c1\n");
}
