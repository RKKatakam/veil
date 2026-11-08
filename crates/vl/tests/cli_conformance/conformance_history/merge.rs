//! `vl merge` and `vl new A B`: Git t6xxx (merge-recursive/ort, conflicts,
//! criss-cross, D/F, binary, modes), jj test_merge_trees.rs,
//! test_merged_tree.rs, test_conflicts.rs and test_resolve_command.rs.

use super::support::*;

/// `base` → `left` and `base` → `right`, tagged; `@` is an empty change
/// on `right`, so `vl merge left` merges left ("theirs") into right
/// ("ours").
pub fn fork<'a>(
    env: &'a Env,
    base: &[(&str, &str)],
    left: impl FnOnce(&R),
    right: impl FnOnce(&R),
) -> R<'a> {
    let r = env.repo("p");
    r.commit("base", base);
    r.tag("base", "@-");
    left(&r);
    r.ok(&["commit", "--no-advance", "-m", "left"]);
    r.tag("left", "@-");
    r.ok(&["new", "base"]);
    right(&r);
    r.ok(&["commit", "--no-advance", "-m", "right"]);
    r.tag("right", "@-");
    r
}

fn w<'a>(files: &'a [(&'a str, &'a str)]) -> impl FnOnce(&R) + 'a {
    move |r: &R| {
        for (p, c) in files {
            r.write(p, c);
        }
    }
}

/// Resolve the merge at `@-` (or whatever `@` sits on): write the files in
/// `@` and fold them into the merge.
pub fn resolve(r: &R, files: &[(&str, &str)]) {
    for (p, c) in files {
        r.write(p, c);
    }
    r.ok(&["squash"]);
}

// Scenario from git t6403-merge-file.sh / jj test_merge_trees: edits to different lines of one file merge cleanly.
#[test]
fn disjoint_edits_in_one_file_merge_cleanly() {
    let env = Env::new();
    let base = lines("l", 12);
    let r = fork(
        &env,
        &[("f", &base)],
        w(&[("f", &base.replace("l2\n", "L2\n"))]),
        w(&[("f", &base.replace("l11\n", "L11\n"))]),
    );
    let (right, left) = (r.sid("right"), r.sid("left"));
    let out = r.ok(&["merge", "left", "-m", "merge left"]);
    assert!(!out.contains("conflict"), "{out}");
    let merged = base.replace("l2\n", "L2\n").replace("l11\n", "L11\n");
    assert_eq!(r.read("f"), merged);
    assert_eq!(r.cat("@-", "f"), merged);
    let m = r.snap("@-");
    assert!(m.conflicts.is_empty());
    assert_eq!(
        m.parents,
        vec![right, left],
        "first parent is the destination"
    );
    assert_eq!(m.description.as_deref(), Some("merge left"));
}

// Scenario from git t6430-merge-recursive.sh: changes to different files merge cleanly.
#[test]
fn changes_to_different_files_merge_cleanly() {
    let env = Env::new();
    let r = fork(
        &env,
        &[("a", "a\n"), ("b", "b\n")],
        w(&[("a", "A\n"), ("new-left", "nl\n")]),
        w(&[("b", "B\n")]),
    );
    r.ok(&["merge", "left"]);
    assert_eq!(r.read("a"), "A\n");
    assert_eq!(r.read("b"), "B\n");
    assert_eq!(r.read("new-left"), "nl\n");
    assert!(r.snap("@-").conflicts.is_empty());
}

// Scenario from git t6427-diff3-conflict-markers.sh / jj test_conflicts: same line changed on both sides.
#[test]
fn same_line_conflict_writes_diff3_markers() {
    let env = Env::new();
    let r = fork(
        &env,
        &[("f", "top\nmid\nend\n")],
        w(&[("f", "top\nLEFT\nend\n")]),
        w(&[("f", "top\nRIGHT\nend\n")]),
    );
    let out = r.ok(&["merge", "left"]);
    assert!(out.contains("conflicts in: f"), "{out}");
    let f = r.read("f");
    let o = f.find("<<<<<<< ours").expect("ours marker");
    let b = f.find("||||||| original").expect("base marker");
    let s = f.find("=======").expect("separator");
    let t = f.find(">>>>>>> theirs").expect("theirs marker");
    assert!(o < b && b < s && s < t, "{f}");
    assert!(
        f[o..b].contains("RIGHT") && f[b..s].contains("mid") && f[s..t].contains("LEFT"),
        "{f}"
    );
    assert!(f.starts_with("top\n") && f.ends_with("end\n"), "{f}");
    assert_eq!(r.snap("@-").conflicts, vec!["f".to_string()]);
    let log = r.out(&["log"]);
    assert!(log.contains("×") && log.contains("(conflict)"), "{log}");
}

// Scenario from jj test_resolve_command test_resolution: editing the file in the conflicted change clears it.
#[test]
fn editing_the_file_in_the_merge_clears_the_conflict() {
    let env = Env::new();
    let r = fork(
        &env,
        &[("f", "x\n")],
        w(&[("f", "left\n")]),
        w(&[("f", "right\n")]),
    );
    r.ok(&["merge", "left"]);
    let merge = r.cid("@-");
    r.ok(&["edit", &merge]);
    let st = r.out(&["status"]);
    assert!(st.contains("C f"), "{st}");
    r.write("f", "both\n");
    let st = r.out(&["status"]);
    assert!(!st.contains("C f"), "{st}");
    assert!(r.snap(&merge).conflicts.is_empty());
    assert_eq!(r.cat(&merge, "f"), "both\n");
}

// Scenario from jj test_resolve_command test_files_still_have_conflicts: editing another file keeps the conflict.
#[test]
fn editing_another_file_keeps_the_conflict() {
    let env = Env::new();
    let r = fork(
        &env,
        &[("f", "x\n"), ("g", "g\n")],
        w(&[("f", "left\n")]),
        w(&[("f", "right\n")]),
    );
    r.ok(&["merge", "left"]);
    let merge = r.cid("@-");
    r.ok(&["edit", &merge]);
    r.write("g", "G\n");
    r.ok(&["status"]);
    assert_eq!(r.snap(&merge).conflicts, vec!["f".to_string()]);
}

// Scenario from git t6427 / jj test_resolve: resolving in @ and squashing clears the merge's conflict.
#[test]
fn squashing_a_resolution_clears_the_conflict() {
    let env = Env::new();
    let r = fork(
        &env,
        &[("f", "x\n")],
        w(&[("f", "left\n")]),
        w(&[("f", "right\n")]),
    );
    r.ok(&["merge", "left"]);
    let st = r.out(&["status"]);
    assert!(st.contains("C f") && st.contains("recorded on"), "{st}");
    resolve(&r, &[("f", "resolved\n")]);
    let m = r.snap("@-");
    assert!(m.conflicts.is_empty(), "{m:?}");
    assert_eq!(r.cat("@-", "f"), "resolved\n");
    assert!(!r.out(&["log"]).contains("(conflict)"));
}

// Scenario from git t6430-merge-recursive.sh: add/add with identical content is clean.
#[test]
fn add_add_identical_is_clean() {
    let env = Env::new();
    let r = fork(
        &env,
        &[("a", "a\n")],
        w(&[("new", "same\n")]),
        w(&[("new", "same\n")]),
    );
    let out = r.ok(&["merge", "left"]);
    assert!(!out.contains("conflict"), "{out}");
    assert_eq!(r.read("new"), "same\n");
}

// Scenario from git t6430-merge-recursive.sh / jj test_baseless_conflict_input_files: add/add with different content.
#[test]
fn add_add_different_conflicts() {
    let env = Env::new();
    let r = fork(
        &env,
        &[("a", "a\n")],
        w(&[("new", "from left\n")]),
        w(&[("new", "from right\n")]),
    );
    let out = r.ok(&["merge", "left"]);
    assert!(out.contains("conflicts in: new"), "{out}");
    let f = r.read("new");
    assert!(
        f.contains("from left") && f.contains("from right") && f.contains("<<<<<<<"),
        "{f}"
    );
}

// Scenario from git t6430 / jj test_edit_delete_conflict_input_files: modify/delete keeps the modified file, flagged.
#[test]
fn modify_delete_conflict_keeps_the_modified_side() {
    let env = Env::new();
    let r = fork(
        &env,
        &[("f", "orig\n"), ("k", "k\n")],
        w(&[("f", "modified\n")]),
        |r: &R| r.rm("f"),
    );
    let out = r.ok(&["merge", "left"]);
    assert!(out.contains("conflicts in: f"), "{out}");
    assert_eq!(r.read("f"), "modified\n");
    assert_eq!(r.snap("@-").conflicts, vec!["f".to_string()]);
}

// Scenario from git t6430: delete/modify, the other way round.
#[test]
fn delete_modify_conflict_keeps_the_modified_side() {
    let env = Env::new();
    let r = fork(
        &env,
        &[("f", "orig\n"), ("k", "k\n")],
        |r: &R| r.rm("f"),
        w(&[("f", "modified\n")]),
    );
    let out = r.ok(&["merge", "left"]);
    assert!(out.contains("conflicts in: f"), "{out}");
    assert_eq!(r.read("f"), "modified\n");
}

// Scenario from jj test_description_with_dir_and_deletion: resolving a modify/delete by deleting.
#[test]
fn deleting_resolves_a_modify_delete_conflict() {
    let env = Env::new();
    let r = fork(
        &env,
        &[("f", "orig\n"), ("k", "k\n")],
        w(&[("f", "modified\n")]),
        |r: &R| r.rm("f"),
    );
    r.ok(&["merge", "left"]);
    r.rm("f");
    r.ok(&["squash"]);
    let m = r.snap("@-");
    assert!(m.conflicts.is_empty(), "{m:?}");
    assert!(!r.paths("@-").contains(&"f".to_string()));
}

// Scenario from git t6430: both sides delete the same file.
#[test]
fn delete_delete_is_clean() {
    let env = Env::new();
    let r = fork(
        &env,
        &[("f", "x\n"), ("k", "k\n")],
        |r: &R| r.rm("f"),
        |r: &R| r.rm("f"),
    );
    let out = r.ok(&["merge", "left"]);
    assert!(!out.contains("conflict"), "{out}");
    assert!(!r.exists("f"));
}

// Scenario from git t6408-merge-up-to-date.sh: the same change on both sides is clean.
#[test]
fn identical_changes_on_both_sides_are_clean() {
    let env = Env::new();
    let r = fork(
        &env,
        &[("f", "1\n2\n3\n")],
        w(&[("f", "1\nTWO\n3\n")]),
        w(&[("f", "1\nTWO\n3\n")]),
    );
    let out = r.ok(&["merge", "left"]);
    assert!(!out.contains("conflict"), "{out}");
    assert_eq!(r.read("f"), "1\nTWO\n3\n");
}

// Scenario from git t6408-merge-up-to-date.sh: merging an ancestor changes nothing.
#[test]
fn merging_an_ancestor_changes_no_content() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("one", &[("f", "1\n")]);
    r.tag("old", "@-");
    r.commit("two", &[("f", "2\n")]);
    let before = r.snap("@-").tree;
    let out = r.ok(&["merge", "old"]);
    assert!(!out.contains("conflict"), "{out}");
    assert_eq!(r.snap("@-").tree, before);
    assert_eq!(r.read("f"), "2\n");
}

// Scenario from git t6408 / t3432 (fast-forward): merging a descendant takes its content.
#[test]
fn merging_a_descendant_takes_its_content() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("one", &[("f", "1\n")]);
    r.tag("one", "@-");
    r.commit("two", &[("f", "2\n"), ("g", "g\n")]);
    r.tag("two", "@-");
    r.ok(&["new", "one"]);
    r.ok(&["merge", "two"]);
    assert_eq!(r.read("f"), "2\n");
    assert_eq!(r.read("g"), "g\n");
    assert_eq!(r.snap("@-").tree, r.snap("two").tree);
}

// Scenario from jj test_merge_trees (duplicate parents): merging a snapshot with itself.
#[test]
fn merging_a_snapshot_into_itself_records_no_duplicate_parent() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("one", &[("f", "1\n")]);
    r.tag("main", "@-");
    r.write("wip.txt", "keep me\n");
    let before = r.sid("main");
    let err = r.fails(&["merge", "main", "--into", "main"]);
    assert!(err.contains("nothing to merge"), "{err}");
    assert_eq!(r.sid("main"), before, "a refused merge moved main");
    assert_eq!(r.read("wip.txt"), "keep me\n");
}

// Scenario from jj test_new (duplicate parents): `vl new X X` with work in progress.
#[test]
fn new_with_a_repeated_parent_records_one_parent() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("one", &[("f", "1\n")]);
    r.tag("one", "@-");
    r.write("wip.txt", "keep me\n");
    r.ok(&["new", "one", "one"]);
    let s = r.snap("@");
    assert_eq!(s.parents, vec![r.sid("one")], "duplicate parents recorded: {s:?}");
}

// Scenario from git t6407-merge-binary.sh: conflicting binary edits keep ours and flag the file.
#[test]
fn binary_conflict_keeps_ours_without_markers() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("b.bin", [0u8, 1, 2, 3]);
    r.ok(&["commit", "--no-advance", "-m", "base"]);
    r.tag("base", "@-");
    r.write("b.bin", [0u8, 9, 9, 9]);
    r.ok(&["commit", "--no-advance", "-m", "left"]);
    r.tag("left", "@-");
    r.ok(&["new", "base"]);
    r.write("b.bin", [0u8, 7, 7, 7]);
    r.ok(&["commit", "--no-advance", "-m", "right"]);
    let out = r.ok(&["merge", "left"]);
    assert!(out.contains("conflicts in: b.bin"), "{out}");
    assert_eq!(
        r.read_bytes("b.bin"),
        vec![0u8, 7, 7, 7],
        "ours kept, unmarked"
    );
    assert_eq!(r.snap("@-").conflicts, vec!["b.bin".to_string()]);
}

// Scenario from git t6407-merge-binary.sh: a binary file changed on one side only merges cleanly.
#[test]
fn binary_changed_on_one_side_is_clean() {
    let env = Env::new();
    let r = env.repo("p");
    r.write("b.bin", [0u8, 1]);
    r.write("t", "t\n");
    r.ok(&["commit", "--no-advance", "-m", "base"]);
    r.tag("base", "@-");
    r.write("b.bin", [0u8, 2]);
    r.ok(&["commit", "--no-advance", "-m", "left"]);
    r.tag("left", "@-");
    r.ok(&["new", "base"]);
    r.write("t", "T\n");
    r.ok(&["commit", "--no-advance", "-m", "right"]);
    let out = r.ok(&["merge", "left"]);
    assert!(!out.contains("conflict"), "{out}");
    assert_eq!(r.read_bytes("b.bin"), vec![0u8, 2]);
    assert_eq!(r.read("t"), "T\n");
}

// Scenario from git t6411-merge-filemode.sh: mode change on one side, content change on the other.
#[test]
fn mode_change_and_content_change_combine() {
    let env = Env::new();
    let r = fork(
        &env,
        &[("run.sh", "echo 1\n")],
        |r: &R| r.chmod_x("run.sh", true),
        w(&[("run.sh", "echo 2\n")]),
    );
    let out = r.ok(&["merge", "left"]);
    assert!(!out.contains("conflict"), "{out}");
    let f = r
        .tree_files("@-")
        .into_iter()
        .find(|f| f.0 == "run.sh")
        .unwrap();
    assert_eq!(f.1.as_deref(), Some(&b"echo 2\n"[..]));
    assert!(f.3, "executable bit from the other side was lost");
}

// Scenario from git t6411-merge-filemode.sh: mode change on one side only.
#[test]
fn mode_change_on_one_side_merges() {
    let env = Env::new();
    let r = fork(
        &env,
        &[("run.sh", "x\n"), ("o", "o\n")],
        w(&[("o", "O\n")]),
        |r: &R| r.chmod_x("run.sh", true),
    );
    r.ok(&["merge", "left"]);
    let f = r
        .tree_files("@-")
        .into_iter()
        .find(|f| f.0 == "run.sh")
        .unwrap();
    assert!(f.3);
}

// Scenario from git t6400-merge-df.sh / jj test_file_vs_dir: file on one side, directory on the other.
#[test]
fn file_directory_conflict_is_flagged() {
    let env = Env::new();
    let r = fork(
        &env,
        &[("thing", "file\n"), ("k", "k\n")],
        |r: &R| {
            r.rm("thing");
            r.write("thing/inner.txt", "dir content\n");
        },
        w(&[("thing", "file edited\n")]),
    );
    let out = r.run(&["merge", "left"]);
    assert!(
        out.status.success() && exited_cleanly(&out),
        "{}",
        text(&out)
    );
    assert!(text(&out).contains("conflicts in: thing"), "{}", text(&out));
    assert!(r.snap("@-").conflicts.contains(&"thing".to_string()));
}

// Scenario from git t6400-merge-df.sh / t6438: a D/F conflict must not silently drop the other side's files.
#[test]
fn file_directory_conflict_keeps_both_sides_content() {
    let env = Env::new();
    let r = fork(
        &env,
        &[("thing", "file\n"), ("k", "k\n")],
        |r: &R| {
            r.rm("thing");
            r.write("thing/inner.txt", "dir content\n");
        },
        w(&[("thing", "file edited\n")]),
    );
    r.ok(&["merge", "left"]);
    let all: Vec<u8> = r
        .tree_files("@-")
        .into_iter()
        .filter_map(|f| f.1)
        .flatten()
        .collect();
    let all = String::from_utf8_lossy(&all);
    assert!(all.contains("file edited"), "ours lost");
    assert!(
        all.contains("dir content"),
        "the directory side's inner.txt vanished from the merge result"
    );
}

// Scenario from git t6400-merge-df.sh: directory on ours, file on theirs.
#[test]
fn directory_file_conflict_is_flagged() {
    let env = Env::new();
    let r = fork(
        &env,
        &[("thing", "file\n"), ("k", "k\n")],
        w(&[("thing", "file edited\n")]),
        |r: &R| {
            r.rm("thing");
            r.write("thing/inner.txt", "dir content\n");
        },
    );
    let out = r.ok(&["merge", "left"]);
    assert!(out.contains("conflicts in: thing"), "{out}");
    assert_eq!(r.read("thing/inner.txt"), "dir content\n");
}

// Scenario from git t6400-merge-df.sh: file removed on one side, directory of the same name added on the other (no conflict).
#[test]
fn deleted_file_replaced_by_directory_merges() {
    let env = Env::new();
    let r = fork(
        &env,
        &[("thing", "file\n"), ("k", "k\n")],
        |r: &R| {
            r.rm("thing");
            r.write("thing/inner.txt", "dir\n");
        },
        w(&[("k", "K\n")]),
    );
    let out = r.ok(&["merge", "left"]);
    assert!(!out.contains("conflict"), "{out}");
    assert_eq!(r.read("thing/inner.txt"), "dir\n");
    assert_eq!(r.read("k"), "K\n");
}

// Scenario from git t6430 / jj test_merge_trees: both sides add different files in a new directory.
#[test]
fn both_sides_add_files_in_the_same_new_directory() {
    let env = Env::new();
    let r = fork(
        &env,
        &[("k", "k\n")],
        w(&[("new/a", "a\n")]),
        w(&[("new/b", "b\n")]),
    );
    let out = r.ok(&["merge", "left"]);
    assert!(!out.contains("conflict"), "{out}");
    assert_eq!(r.read("new/a"), "a\n");
    assert_eq!(r.read("new/b"), "b\n");
}

// Scenario from jj test_merge_trees: deep trees merge recursively.
#[test]
fn deep_directories_merge_recursively() {
    let env = Env::new();
    let d = "a/b/c/d/e/f/g/h";
    let fa = format!("{d}/x.txt");
    let fb = format!("{d}/y.txt");
    let r = fork(
        &env,
        &[(&fa, "x\n"), (&fb, "y\n")],
        w(&[(&fa, "X\n")]),
        w(&[(&fb, "Y\n")]),
    );
    r.ok(&["merge", "left"]);
    assert_eq!(r.read(&fa), "X\n");
    assert_eq!(r.read(&fb), "Y\n");
}

// Scenario from git t6413-merge-crlf.sh: CRLF files merge line by line.
#[test]
fn crlf_files_merge() {
    let env = Env::new();
    let base = "a\r\nb\r\nc\r\nd\r\ne\r\n";
    let r = fork(
        &env,
        &[("f", base)],
        w(&[("f", "A\r\nb\r\nc\r\nd\r\ne\r\n")]),
        w(&[("f", "a\r\nb\r\nc\r\nd\r\nE\r\n")]),
    );
    r.ok(&["merge", "left"]);
    assert_eq!(r.read("f"), "A\r\nb\r\nc\r\nd\r\nE\r\n");
}

// Scenario from git t6403-merge-file.sh: a file without a trailing newline merges.
#[test]
fn no_trailing_newline_merges() {
    let env = Env::new();
    let r = fork(
        &env,
        &[("f", "1\n2\n3\n4\n5")],
        w(&[("f", "ONE\n2\n3\n4\n5")]),
        w(&[("f", "1\n2\n3\n4\nFIVE")]),
    );
    r.ok(&["merge", "left"]);
    assert_eq!(r.read("f"), "ONE\n2\n3\n4\nFIVE");
}

// Scenario from git t6403-merge-file.sh: conflict on the last line without newline.
#[test]
fn no_trailing_newline_conflict_has_markers() {
    let env = Env::new();
    let r = fork(
        &env,
        &[("f", "1\nlast")],
        w(&[("f", "1\nleft")]),
        w(&[("f", "1\nright")]),
    );
    let out = r.ok(&["merge", "left"]);
    assert!(out.contains("conflicts in: f"), "{out}");
    let f = r.read("f");
    assert!(
        f.contains("left") && f.contains("right") && f.contains(">>>>>>> theirs"),
        "{f:?}"
    );
}

// Scenario from git t6430 / jj test_merged_tree: conflicted file names with spaces and Unicode.
#[test]
fn conflicts_in_unusual_names() {
    let env = Env::new();
    let names = ["with space.txt", "ünï.txt", "-dash"];
    let base: Vec<(&str, &str)> = names.iter().map(|n| (*n, "base\n")).collect();
    let r = fork(
        &env,
        &base,
        |r: &R| names.iter().for_each(|n| r.write(n, "left\n")),
        |r: &R| names.iter().for_each(|n| r.write(n, "right\n")),
    );
    r.ok(&["merge", "left"]);
    let mut c = r.snap("@-").conflicts;
    c.sort();
    let mut want: Vec<String> = names.iter().map(|s| s.to_string()).collect();
    want.sort();
    assert_eq!(c, want);
}

// Scenario from git t6416-recursive-corner-cases.sh: an empty file on one side, edited on the other.
#[test]
fn emptied_file_against_an_edit_conflicts() {
    let env = Env::new();
    let r = fork(
        &env,
        &[("f", "content\n")],
        w(&[("f", "")]),
        w(&[("f", "content changed\n")]),
    );
    let out = r.ok(&["merge", "left"]);
    assert!(out.contains("conflicts in: f"), "{out}");
}

// Scenario from git t6401-merge-criss-cross.sh / t6431-merge-criscross.sh: two merge bases.
#[test]
fn criss_cross_merge_with_different_resolutions_conflicts() {
    let env = Env::new();
    let base = lines("l", 9);
    let r = fork(
        &env,
        &[("f", &base)],
        w(&[("f", &base.replace("l5\n", "B\n"))]),
        w(&[("f", &base.replace("l5\n", "C\n"))]),
    );
    // The merge below moves the `right` tag to R2: L2 must merge the
    // original `right`, or R2 would be L2's ancestor (no criss-cross).
    let right = r.sid("right");
    // right + left, resolved as "B".
    r.ok(&["merge", "left", "--into", "right", "-m", "R2"]);
    resolve(&r, &[("f", &base.replace("l5\n", "B\n"))]);
    r.tag("r2", "@-");
    // left + right, resolved as "C".
    r.ok(&["new", "left"]);
    r.ok(&["merge", &right, "--into", "left", "-m", "L2"]);
    resolve(&r, &[("f", &base.replace("l5\n", "C\n"))]);
    r.tag("l2", "@-");
    // Merge the two resolutions: they disagree, so this must conflict
    // (Git: the virtual merge base holds both; jj: the same).
    r.ok(&["new", "r2"]);
    let out = r.ok(&["merge", "l2", "-m", "final"]);
    let f = r.read("f");
    assert!(
        out.contains("conflicts in: f") || f.contains("<<<<<<<"),
        "criss-cross merge silently picked one resolution:\n{out}\n{f}"
    );
}

// Scenario from git t6401-merge-criss-cross.sh: criss-cross where both sides agree merges cleanly.
#[test]
fn criss_cross_merge_with_agreeing_resolutions_is_clean() {
    let env = Env::new();
    let base = lines("l", 9);
    let r = fork(
        &env,
        &[("f", &base)],
        w(&[("f", &base.replace("l2\n", "B\n"))]),
        w(&[("f", &base.replace("l8\n", "C\n"))]),
    );
    let right = r.sid("right");
    r.ok(&["merge", "left", "--into", "right", "-m", "R2"]);
    r.tag("r2", "@-");
    let left = r.sid("left");
    r.ok(&["new", "left"]);
    r.ok(&["merge", &right, "--into", "left", "-m", "L2"]);
    assert_eq!(r.snap("@-").parents, vec![left, right], "not a criss-cross");
    r.tag("l2", "@-");
    r.ok(&["new", "r2"]);
    r.write("other", "o\n");
    r.ok(&["commit", "--no-advance", "-m", "on r2"]);
    let out = r.ok(&["merge", "l2"]);
    assert!(!out.contains("conflict"), "{out}");
    assert_eq!(
        r.read("f"),
        base.replace("l2\n", "B\n").replace("l8\n", "C\n")
    );
    assert_eq!(r.read("other"), "o\n");
}

// Scenario from git t6000/t6430 (octopus) / jj test_merged_tree: three parents.
#[test]
fn octopus_merge_of_three_lines() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("base", &[("k", "k\n")]);
    r.tag("base", "@-");
    for name in ["a", "b", "c"] {
        r.ok(&["new", "base"]);
        r.commit(name, &[(name, name)]);
        r.tag(name, "@-");
    }
    r.ok(&["new", "a"]);
    let want = vec![r.sid("a"), r.sid("b"), r.sid("c")];
    let out = r.ok(&["merge", "b", "c", "-m", "octopus"]);
    assert!(!out.contains("conflict"), "{out}");
    let m = r.snap("@-");
    assert_eq!(
        m.parents, want,
        "parents in argument order, destination first"
    );
    for f in ["a", "b", "c", "k"] {
        assert!(r.exists(f), "{f} missing after the octopus merge");
    }
    let log = r.out(&["log"]);
    assert!(log.contains("⇠ merges"), "{log}");
}

// Scenario from git t6430 (octopus with conflict): conflicts are reported for an octopus too.
#[test]
fn octopus_merge_with_a_conflict() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("base", &[("f", "base\n")]);
    r.tag("base", "@-");
    for name in ["a", "b", "c"] {
        r.ok(&["new", "base"]);
        let content = if name == "c" {
            "c wins\n".to_string()
        } else {
            format!("{name}-{name}\n")
        };
        if name == "b" {
            r.commit(name, &[("only-b", "b\n")]);
        } else {
            r.commit(name, &[("f", &content)]);
        }
        r.tag(name, "@-");
    }
    r.ok(&["new", "a"]);
    let out = r.ok(&["merge", "b", "c"]);
    assert!(out.contains("conflicts in: f"), "{out}");
    assert!(r.exists("only-b"));
}

// Scenario from git t6430 (unrelated histories) / jj: two lines started from the root merge.
#[test]
fn unrelated_lines_from_the_root_merge() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("one", &[("a", "a\n")]);
    r.tag("one", "@-");
    r.ok(&["new", "root"]);
    r.commit("other", &[("b", "b\n")]);
    let out = r.ok(&["merge", "one"]);
    assert!(!out.contains("conflict"), "{out}");
    assert_eq!(r.read("a"), "a\n");
    assert_eq!(r.read("b"), "b\n");
}

// Scenario from git t6430: unrelated histories that both add the same path conflict (add/add).
#[test]
fn unrelated_lines_adding_the_same_path_conflict() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("one", &[("same", "from one\n")]);
    r.tag("one", "@-");
    r.ok(&["new", "root"]);
    r.commit("two", &[("same", "from two\n")]);
    let out = r.ok(&["merge", "one"]);
    assert!(out.contains("same"), "{out}");
}

// Scenario from jj test_new (merge) / git t6430: `vl new A B` also merges and records conflicts.
#[test]
fn new_with_two_parents_merges_and_records_conflicts() {
    let env = Env::new();
    let r = fork(
        &env,
        &[("f", "x\n"), ("k", "k\n")],
        w(&[("f", "left\n")]),
        w(&[("f", "right\n"), ("k", "K\n")]),
    );
    r.ok(&["new", "right", "left"]);
    let s = r.snap("@");
    assert_eq!(s.parents.len(), 2);
    assert_eq!(s.conflicts, vec!["f".to_string()]);
    assert_eq!(r.read("k"), "K\n");
    assert!(r.read("f").contains("<<<<<<<"));
    let st = r.out(&["status"]);
    assert!(st.contains("C f"), "{st}");
}

// Scenario from git t6430 (merge -m) and the Veil default message.
#[test]
fn merge_message_defaults_to_the_merged_revisions() {
    let env = Env::new();
    let r = fork(
        &env,
        &[("a", "a\n")],
        w(&[("l", "l\n")]),
        w(&[("r", "r\n")]),
    );
    r.ok(&["merge", "left"]);
    assert_eq!(r.snap("@-").description.as_deref(), Some("merge left"));
}

// Scenario from git t6430 / Veil: tags at the destination follow the merge; others stay.
#[test]
fn merge_moves_tags_at_the_destination_only() {
    let env = Env::new();
    let r = fork(
        &env,
        &[("a", "a\n")],
        w(&[("l", "l\n")]),
        w(&[("r", "r\n")]),
    );
    let left_before = r.tag_target("left");
    r.ok(&["merge", "left"]);
    let merge = r.sid("@-");
    assert_eq!(
        r.tag_target("right"),
        Some(merge),
        "the destination's tag did not follow the merge"
    );
    assert_eq!(r.tag_target("left"), left_before, "the merged-in tag moved");
}

// Scenario from Veil `vl merge` (into @ when @ has changes).
#[test]
fn merge_into_a_non_empty_working_copy_merges_into_it() {
    let env = Env::new();
    let r = fork(
        &env,
        &[("a", "a\n")],
        w(&[("l", "l\n")]),
        w(&[("r", "r\n")]),
    );
    r.write("wip", "work in progress\n");
    let wc_change = r.cid("@");
    r.ok(&["merge", "left"]);
    let m = r.snap("@-");
    assert_eq!(
        m.parent_changes[0], wc_change,
        "merged into something other than the non-empty @"
    );
    assert_eq!(r.read("wip"), "work in progress\n");
    assert_eq!(r.read("l"), "l\n");
}

// Scenario from git t6439-merge-co-error-msgs.sh / jj: bad merge arguments fail and record nothing.
#[test]
fn merge_of_an_unknown_revision_records_nothing() {
    let env = Env::new();
    let r = fork(
        &env,
        &[("a", "a\n")],
        w(&[("l", "l\n")]),
        w(&[("r", "r\n")]),
    );
    r.ok(&["status"]);
    let before = r.op_head();
    let err = r.fails(&["merge", "nosuch"]);
    assert!(err.contains("not found"), "{err}");
    assert_eq!(r.op_head(), before);
    r.fails(&["merge"]);
    r.fails(&["merge", "left", "--into", "nosuch"]);
    assert_eq!(r.op_head(), before);
}

// Scenario from git t6430 (merge -s ours not available) / jj: merge with a conflicted parent.
#[test]
fn merging_a_conflicted_snapshot_carries_the_markers() {
    let env = Env::new();
    let r = fork(
        &env,
        &[("f", "x\n"), ("g", "g\n")],
        w(&[("f", "left\n")]),
        w(&[("f", "right\n")]),
    );
    r.ok(&["merge", "left", "-m", "conflicted"]);
    r.tag("conflicted", "@-");
    r.ok(&["new", "base"]);
    r.commit("other", &[("g", "G\n")]);
    let out = r.ok(&["merge", "conflicted"]);
    assert!(!out.contains("panicked"), "{out}");
    assert!(r.read("f").contains("<<<<<<<"));
    assert_eq!(r.read("g"), "G\n");
}

// Scenario from git t6403-merge-file.sh: a large file with distant edits merges quickly.
#[test]
fn large_file_merge() {
    let env = Env::new();
    let base = lines("row ", 20_000);
    let r = fork(
        &env,
        &[("big", &base)],
        w(&[("big", &base.replace("row 10\n", "ROW 10\n"))]),
        w(&[("big", &base.replace("row 19990\n", "ROW 19990\n"))]),
    );
    let t = std::time::Instant::now();
    r.ok(&["merge", "left"]);
    assert!(t.elapsed().as_secs() < 30);
    assert_eq!(
        r.read("big"),
        base.replace("row 10\n", "ROW 10\n")
            .replace("row 19990\n", "ROW 19990\n")
    );
}

// Scenario from git t6436-merge-overwrite.sh: an untracked-but-ignored file in the way is not clobbered.
#[test]
fn ignored_file_in_the_way_is_not_clobbered() {
    let env = Env::new();
    let r = fork(
        &env,
        &[("a", "a\n")],
        w(&[("target/out.txt", "tracked?\n"), ("l", "l\n")]),
        w(&[("r", "r\n")]),
    );
    // target/ is ignored by the default policy: left never recorded it.
    assert!(!r.paths("left").contains(&"target/out.txt".to_string()));
    r.write("target/out.txt", "my local build output\n");
    r.ok(&["merge", "left"]);
    assert_eq!(r.read("target/out.txt"), "my local build output\n");
}

// Scenario from git t6436-merge-overwrite.sh: a local-only (isolated) file survives a merge.
#[test]
fn isolated_file_survives_a_merge() {
    let env = Env::new();
    let r = fork(
        &env,
        &[("a", "a\n")],
        w(&[("l", "l\n")]),
        w(&[("r", "r\n")]),
    );
    r.write(".env", "API_KEY=supersecret-local-value\n");
    r.ok(&["merge", "left"]);
    assert_eq!(r.read(".env"), "API_KEY=supersecret-local-value\n");
    assert!(r.store_contains("supersecret-local-value").is_empty());
}

// ---- merge wave regressions ------------------------------------------------

// BUG-243: the file side of a file/directory conflict is moved aside to `NAME~<side>`, both paths recorded.
#[test]
fn file_directory_conflict_moves_the_file_aside() {
    let env = Env::new();
    let r = fork(
        &env,
        &[("thing", "file\n"), ("k", "k\n")],
        |r: &R| {
            r.rm("thing");
            r.write("thing/inner.txt", "dir content\n");
        },
        w(&[("thing", "file edited\n")]),
    );
    let out = r.ok(&["merge", "left"]);
    assert!(out.contains("thing~ours"), "{out}");
    assert_eq!(r.read("thing/inner.txt"), "dir content\n");
    assert_eq!(r.read("thing~ours"), "file edited\n");
    let mut c = r.snap("@-").conflicts;
    c.sort();
    assert_eq!(c, vec!["thing".to_string(), "thing~ours".to_string()]);
    // Deleting the moved-aside copy resolves that path.
    r.ok(&["edit", "@-"]);
    r.rm("thing~ours");
    r.ok(&["status"]);
    assert_eq!(r.snap("@").conflicts, vec!["thing".to_string()]);
}

// BUG-243: the moved-aside name never overwrites an existing entry.
#[test]
fn file_directory_conflict_aside_name_avoids_existing_files() {
    let env = Env::new();
    let r = fork(
        &env,
        &[("thing", "file\n"), ("thing~theirs", "already here\n")],
        w(&[("thing", "file edited\n")]),
        |r: &R| {
            r.rm("thing");
            r.write("thing/inner.txt", "dir content\n");
        },
    );
    r.ok(&["merge", "left"]);
    assert_eq!(r.read("thing~theirs"), "already here\n");
    assert_eq!(r.read("thing~theirs~2"), "file edited\n");
    assert_eq!(r.read("thing/inner.txt"), "dir content\n");
}

// BUG-243: two directories merge as directories even where the base had a file of that name.
#[test]
fn directories_added_on_both_sides_over_a_file_merge() {
    let env = Env::new();
    let r = fork(
        &env,
        &[("thing", "file\n")],
        |r: &R| {
            r.rm("thing");
            r.write("thing/a.txt", "a\n");
        },
        |r: &R| {
            r.rm("thing");
            r.write("thing/b.txt", "b\n");
        },
    );
    let out = r.ok(&["merge", "left"]);
    assert!(!out.contains("conflict"), "{out}");
    assert_eq!(r.read("thing/a.txt"), "a\n");
    assert_eq!(r.read("thing/b.txt"), "b\n");
}

// BUG-240: merging the destination into itself is refused, and records nothing.
#[test]
fn merging_the_destination_into_itself_is_refused() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("one", &[("f", "1\n")]);
    r.tag("main", "@-");
    r.ok(&["status"]);
    let op = r.op_head();
    let err = r.fails(&["merge", "main", "--into", "main"]);
    assert!(err.contains("nothing to merge"), "{err}");
    assert_eq!(r.op_head(), op);
}

// BUG-244: a criss-cross where one side changed nothing since its merge base takes the other side.
#[test]
fn criss_cross_merge_takes_a_later_edit_cleanly() {
    let env = Env::new();
    let base = lines("l", 9);
    let r = fork(
        &env,
        &[("f", &base)],
        w(&[("f", &base.replace("l5\n", "B\n"))]),
        w(&[("f", &base.replace("l5\n", "C\n"))]),
    );
    let right = r.sid("right");
    r.ok(&["merge", "left", "--into", "right", "-m", "R2"]);
    resolve(&r, &[("f", &base.replace("l5\n", "B\n"))]);
    r.tag("r2", "@-");
    r.ok(&["new", "left"]);
    r.ok(&["merge", &right, "--into", "left", "-m", "L2"]);
    resolve(&r, &[("f", &base.replace("l5\n", "B\n"))]);
    // Both resolved as B; L2's line then edits l9.
    r.ok(&["new", "@-"]);
    r.write("f", base.replace("l5\n", "B\n").replace("l9\n", "NINE\n"));
    r.ok(&["commit", "--no-advance", "-m", "edit"]);
    r.tag("l3", "@-");
    r.ok(&["new", "r2"]);
    let out = r.ok(&["merge", "l3"]);
    assert!(!out.contains("conflict"), "{out}");
    assert_eq!(r.read("f"), base.replace("l5\n", "B\n").replace("l9\n", "NINE\n"));
}
