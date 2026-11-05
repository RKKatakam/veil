//! Checking out other revisions with `vl new` and `vl edit`: git
//! t2000–t2027 (checkout), t2060 (switch), t2500 (untracked overwriting),
//! t2501 (cwd), t7201 (co); jj test_new_command, test_edit_command,
//! test_working_copy; lib test_local_working_copy*.

use super::*;

/// `base` has a, b, dir/c; `next` modifies a, deletes b, adds d.
fn two_states(env: &Env) -> (R<'_>, String, String) {
    let r = env.repo("p");
    r.write("a.txt", "a1\n");
    r.write("b.txt", "b1\n");
    r.write("dir/c.txt", "c1\n");
    let base = r.commit("base");
    r.write("a.txt", "a2\n");
    r.rm("b.txt");
    r.write("d.txt", "d2\n");
    let next = r.commit("next");
    (r, base, next)
}

// Scenario from git t7201-co.sh "checkout from non-HEAD branch": every
// file is updated, added or removed to match the target.
#[test]
fn new_on_another_revision_checks_out_its_tree() {
    let env = Env::new();
    let (r, base, next) = two_states(&env);
    let out = r.ok(&["new", base.as_str()]);
    assert!(out.contains("Working copy now at"), "{out}");
    assert_eq!(r.disk_files(), vec!["a.txt", "b.txt", "dir/c.txt"]);
    assert_eq!(r.read("a.txt"), "a1\n");
    r.ok(&["new", next.as_str()]);
    assert_eq!(r.disk_files(), vec!["a.txt", "d.txt", "dir/c.txt"]);
    assert_eq!(r.read("a.txt"), "a2\n");
    assert_eq!(r.change("@-"), next);
}

// Scenario from git t2014-checkout-switch.sh / t7201 "checkout with local
// changes" (Git refuses or carries them): Veil records them in the change
// being left, so switching never loses them.
#[test]
fn local_edits_stay_in_the_change_being_left() {
    let env = Env::new();
    let (r, base, next) = two_states(&env);
    r.write("a.txt", "wip edit\n");
    r.write("new-wip.txt", "wip\n");
    let wip = r.change("@");
    r.ok(&["new", base.as_str()]);
    assert_eq!(r.read("a.txt"), "a1\n");
    assert!(!r.exists("new-wip.txt"));
    assert_eq!(r.cat("a.txt", &wip), "wip edit\n");
    assert_eq!(r.cat("new-wip.txt", &wip), "wip\n");
    r.ok(&["edit", wip.as_str()]);
    assert_eq!(r.read("a.txt"), "wip edit\n");
    assert_eq!(r.change("@-"), next);
}

// Scenario from git t2017-checkout-orphan.sh: `vl new root` starts an
// unrelated line with an empty tree.
#[test]
fn new_on_root_is_an_orphan_with_an_empty_tree() {
    let env = Env::new();
    let (r, _, _) = two_states(&env);
    r.ok(&["new", "root"]);
    assert!(r.disk().is_empty(), "{:?}", r.disk());
    assert!(r.out(&["files"]).is_empty());
    r.write("fresh.txt", "x\n");
    r.commit("orphan");
    assert_eq!(r.snap("@--"), r.snap("root"));
}

// Scenario from git t2015-checkout-unborn.sh: switching away from a fresh
// repository's empty change and back.
#[test]
fn switching_in_a_fresh_repository() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("first.txt", "x\n");
    let first = r.change("@");
    r.ok(&["new", "root"]);
    assert!(!r.exists("first.txt"));
    r.ok(&["edit", first.as_str()]);
    assert_eq!(r.read("first.txt"), "x\n");
}

// Scenario from jj test_new_command.rs: `vl new` with no argument starts
// on `@`; `-m` describes the new change.
#[test]
fn new_without_arguments_starts_on_the_working_copy() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("a.txt", "a\n");
    let old = r.change("@");
    r.ok(&["new", "-m", "next step"]);
    assert_eq!(r.change("@-"), old);
    assert_eq!(r.description("@"), "next step");
    assert_eq!(r.read("a.txt"), "a\n", "files are unchanged");
    assert!(r.changes().is_empty());
}

// Scenario from jj test_new_command.rs "new merge": several parents make a
// merge whose tree combines them.
#[test]
fn new_with_several_parents_merges_their_trees() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("shared.txt", "s\n");
    let base = r.commit("base");
    r.write("left.txt", "l\n");
    let left = r.commit("left");
    r.ok(&["new", base.as_str()]);
    r.write("right.txt", "r\n");
    let right = r.commit("right");
    r.ok(&["new", left.as_str(), right.as_str()]);
    assert_eq!(r.disk_files(), vec!["left.txt", "right.txt", "shared.txt"]);
    let show = r.out(&["show", "--stat", "@"]);
    assert_eq!(show.matches("Parent    :").count(), 2, "{show}");
}

// Scenario from jj test_new_command.rs: an empty, undescribed working-copy
// change is discarded when you move away; a described one is kept.
#[test]
fn an_empty_undescribed_change_is_discarded_on_moving_away() {
    let env = Env::new();
    let (r, base, _) = two_states(&env);
    let empty = r.change("@");
    r.ok(&["new", base.as_str()]);
    assert!(r.fails(&["show", empty.as_str()]).contains("not found"));
    let described = r.change("@");
    r.ok(&["describe", "-m", "placeholder"]);
    r.ok(&["new", "root"]);
    assert_eq!(r.description(described.as_str()), "placeholder");
}

// Scenario from jj test_edit_command.rs: `vl edit` makes an older change
// the working copy; edits amend it and its descendants are rebased.
#[test]
fn edit_amends_an_older_change_and_rebases_descendants() {
    let env = Env::new();
    let (r, base, next) = two_states(&env);
    r.ok(&["edit", base.as_str()]);
    assert_eq!(r.change("@"), base);
    assert_eq!(r.read("a.txt"), "a1\n");
    r.write("dir/c.txt", "c-amended\n");
    r.ok(&["status"]);
    // The child keeps its own edits and sees the amended file.
    assert_eq!(r.cat("dir/c.txt", next.as_str()), "c-amended\n");
    assert_eq!(r.cat("a.txt", next.as_str()), "a2\n");
    assert_eq!(r.change(&format!("{next}-")), base);
}

// Scenario from jj test_edit_command.rs: editing the working copy itself
// changes nothing.
#[test]
fn edit_of_the_working_copy_is_a_no_op() {
    let env = Env::new();
    let (r, _, _) = two_states(&env);
    r.write("x.txt", "x\n");
    r.ok(&["status"]);
    let snap = r.snap("@");
    let ops = r.op_count();
    r.ok(&["edit", "@"]);
    assert!(r.op_count() <= ops + 1, "at most one operation");
    assert_eq!(r.snap("@"), snap);
    assert_eq!(r.read("x.txt"), "x\n");
}

// Scenario from git t2000-conflict-when-checking-files-out.sh /
// t2003-checkout-cache-mkdir.sh: a file becomes a directory and back.
#[test]
fn file_to_directory_and_back_on_checkout() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("path", "a file\n");
    let as_file = r.commit("file");
    r.rm("path");
    r.write("path/inner.txt", "inside\n");
    let as_dir = r.commit("dir");
    assert_eq!(r.paths("@-"), vec!["path/inner.txt"]);
    r.ok(&["new", as_file.as_str()]);
    assert_eq!(r.read("path"), "a file\n");
    r.ok(&["new", as_dir.as_str()]);
    assert_eq!(r.read("path/inner.txt"), "inside\n");
    r.ok(&["edit", as_file.as_str()]);
    assert!(r.path("path").is_file());
}

// Scenario from git t2000-conflict-when-checking-files-out.sh: a deep
// directory replaced by a file several levels up.
#[test]
fn deep_directory_replaced_by_a_file() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("a/b/c/d.txt", "deep\n");
    r.write("a/b/other.txt", "other\n");
    let deep = r.commit("deep");
    r.rm("a");
    r.write("a", "now a file\n");
    let flat = r.commit("flat");
    r.ok(&["new", deep.as_str()]);
    assert_eq!(r.read("a/b/c/d.txt"), "deep\n");
    r.ok(&["new", flat.as_str()]);
    assert_eq!(r.read("a"), "now a file\n");
}

// Scenario from jj test_local_working_copy_executable_bit.rs / git t2009:
// the executable bit is checked out, and a mode-only change is recorded.
#[cfg(unix)]
#[test]
fn executable_bit_follows_the_checked_out_revision() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("run.sh", "#!/bin/sh\necho hi\n");
    r.chmod("run.sh", 0o755);
    let exec = r.commit("exec");
    assert!(r.files("@-").iter().any(|f| f.path == "run.sh" && f.exec));
    r.chmod("run.sh", 0o644);
    assert_eq!(r.changes(), vec!["M run.sh"]);
    let plain = r.commit("plain");
    assert!(r.files("@-").iter().any(|f| f.path == "run.sh" && !f.exec));
    r.ok(&["new", exec.as_str()]);
    assert!(r.is_exec("run.sh"));
    r.ok(&["new", plain.as_str()]);
    assert!(!r.is_exec("run.sh"));
}

// Scenario from git t2009-checkout-statinfo.sh: files whose content does
// not change are not rewritten by a checkout.
#[test]
fn unchanged_files_are_not_rewritten() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("keep.txt", "k\n");
    r.write("a.txt", "a1\n");
    let one = r.commit("one");
    r.write("a.txt", "a2\n");
    r.commit("two");
    let old = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_600_000_000);
    std::fs::File::options().write(true).open(r.path("keep.txt")).unwrap().set_modified(old).unwrap();
    r.ok(&["new", one.as_str()]);
    let mtime = std::fs::metadata(r.path("keep.txt")).unwrap().modified().unwrap();
    assert_eq!(mtime, old);
    assert_eq!(r.read("a.txt"), "a1\n");
}

// Scenario from git t2021-checkout-overwrite.sh / t2500: an ignored file
// where the target revision tracks one is not overwritten.
#[test]
fn an_ignored_local_file_is_not_overwritten_by_a_tracked_one() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("log.txt", "tracked version\n");
    let tracked = r.commit("tracks log.txt");
    r.ok(&["new", "root"]);
    r.write(".veilpolicy", "log.txt ignore\n");
    r.commit("ignores log.txt");
    r.write("log.txt", "precious local\n");
    let out = r.ok(&["new", tracked.as_str()]);
    assert!(out.contains("kept log.txt"), "{out}");
    assert_eq!(r.read("log.txt"), "precious local\n");
}

// Scenario from git t2021-checkout-overwrite.sh with Veil's invariant: an
// isolated local file is not overwritten by a revision that tracks the
// same path, and stays protected there.
#[test]
fn an_isolated_local_file_is_not_overwritten_or_published() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("notes.txt", "public version\n");
    let public = r.commit("A");
    r.ok(&["new", "root"]);
    r.ok(&["isolate", "notes.txt"]);
    r.write("notes.txt", "my private notes\n");
    r.commit("B");
    let out = r.ok(&["new", public.as_str()]);
    assert!(out.contains("kept notes.txt"), "{out}");
    assert_eq!(r.read("notes.txt"), "my private notes\n");
    let st = r.ok(&["status"]);
    assert!(st.contains("P notes.txt"), "{st}");
    r.commit("on A");
    assert_eq!(r.cat("notes.txt", "@-"), "public version\n");
}

// Scenario from git t2021-checkout-overwrite.sh with a quarantined new
// file: it is never recorded, and a checkout keeps it.
#[test]
fn a_quarantined_file_survives_checkouts() {
    let env = Env::new();
    let (r, base, _) = two_states(&env);
    r.write("leak.js", LEAKY);
    let st = r.ok(&["status"]);
    assert!(st.contains("Q leak.js"), "{st}");
    r.ok(&["new", base.as_str()]);
    assert_eq!(r.read("leak.js"), LEAKY);
    r.ok(&["new", "root"]);
    assert_eq!(r.read("leak.js"), LEAKY);
}

// Scenario from git t2501-cwd-empty.sh: a command run from a directory the
// checkout removes still completes, and the files are right.
#[test]
fn checkout_from_a_directory_it_removes() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("sub/f.txt", "x\n");
    r.write("top.txt", "t\n");
    let one = r.commit("one");
    let out = r.run_in("sub", &["new", "root"]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(!r.exists("top.txt"));
    r.ok(&["new", one.as_str()]);
    assert_eq!(r.read("sub/f.txt"), "x\n");
}

// Scenario from git t2020-checkout-detach.sh: there is no detached state:
// working on an untagged change and on a tagged one are the same, and
// `vl new main` does not move `main`.
#[test]
fn new_on_a_tag_does_not_move_the_tag() {
    let env = Env::new();
    let (r, base, _) = two_states(&env);
    r.ok(&["tag", "set", "main", "-r", base.as_str()]);
    r.ok(&["new", "main"]);
    r.write("work.txt", "w\n");
    r.ok(&["describe", "-m", "work on main"]);
    r.ok(&["new", "root"]);
    assert_eq!(r.change("main"), base);
}

// Scenario from git t2018-checkout-branch.sh / t2060-switch.sh with a
// read-only tracked file: checkout replaces or removes it.
#[cfg(unix)]
#[test]
fn read_only_tracked_files_are_replaced_by_checkout() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("ro.txt", "v1\n");
    let one = r.commit("one");
    r.write("ro.txt", "v2\n");
    r.commit("two");
    r.chmod("ro.txt", 0o444);
    r.ok(&["new", one.as_str()]);
    assert_eq!(r.read("ro.txt"), "v1\n");
    r.chmod("ro.txt", 0o444);
    r.ok(&["new", "root"]);
    assert!(!r.exists("ro.txt"));
}

// Scenario from jj test_edit_command.rs: `vl edit` of another
// workspace's working copy shares it; both see the same change.
#[test]
fn edit_of_another_workspaces_working_copy() {
    let env = Env::new();
    let (r, _, _) = two_states(&env);
    r.ok(&["ws", "new", "w"]);
    r.ok(&["edit", "w@"]);
    assert_eq!(r.change("@"), r.change("w@"));
}

// Scenario from git t2010-checkout-ambiguous.sh / t2019 (ambiguous ref):
// a revision that names nothing leaves the working copy alone.
#[test]
fn a_failed_checkout_leaves_the_working_copy_alone() {
    let env = Env::new();
    let (r, _, _) = two_states(&env);
    r.write("wip.txt", "w\n");
    let before = r.disk();
    let wc = r.change("@");
    r.fails(&["new", "nosuch"]);
    r.fails(&["edit", "nosuch"]);
    assert_eq!(r.disk(), before);
    assert_eq!(r.change("@"), wc);
}

// Scenario from git t2080-parallel-checkout-basics.sh (many files at
// once): a checkout of a thousand files is complete.
#[test]
fn checkout_of_many_files() {
    let env = Env::new();
    let r = env.repo("p");
    for i in 0..1000 {
        r.write(&format!("d{}/f{i}.txt", i % 10), format!("{i}\n"));
    }
    let many = r.commit("many");
    r.ok(&["new", "root"]);
    assert!(r.disk_files().is_empty());
    r.ok(&["new", many.as_str()]);
    assert_eq!(r.disk_files().len(), 1000);
    assert_eq!(r.read("d7/f517.txt"), "517\n");
}

// Scenario from jj test_working_copy.rs (binary content, no trailing
// newline, empty files) through a checkout.
#[test]
fn binary_empty_and_unterminated_files_round_trip() {
    let env = Env::new();
    let r = env.repo("p");
    let bin: Vec<u8> = (0..=255u8).cycle().take(70_000).collect();
    r.write("bin.dat", &bin);
    r.write("empty", "");
    r.write("nonl", "no newline");
    r.write("crlf.txt", "a\r\nb\r\n");
    let c = r.commit("bytes");
    r.ok(&["new", "root"]);
    r.ok(&["new", c.as_str()]);
    assert_eq!(r.read_bytes("bin.dat"), bin);
    assert_eq!(r.read("empty"), "");
    assert_eq!(r.read("nonl"), "no newline");
    assert_eq!(r.read("crlf.txt"), "a\r\nb\r\n", "no line-ending conversion");
    assert_eq!(r.files("@").iter().find(|f| f.path == "empty").unwrap().size, 0);
}
