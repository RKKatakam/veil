//! Rename-aware merges and rebases: Git t6402 (merge-rename), t6412 (large
//! rename), t6414 (no cruft), t6422 (rename corner cases), t6425
//! (rename/delete), t6429 (sequences of rebases over a rename), t6434
//! (rename options), t3401 (rebase and rename). Directory renames (t6423,
//! Git's `ort` directory-rename detection) are out of scope in Veil 1.x:
//! each file of a renamed directory is followed on its own.

use crate::{merge::fork, support::*};

fn mv(r: &R, from: &str, to: &str) {
    let to_path = r.dir.join(to);
    std::fs::create_dir_all(to_path.parent().unwrap()).unwrap();
    std::fs::rename(r.dir.join(from), to_path).unwrap();
}

/// Line `i` of `text` replaced by `with`.
fn edit_line(text: &str, i: usize, with: &str) -> String {
    text.lines().enumerate().map(|(j, l)| if j == i { format!("{with}\n") } else { format!("{l}\n") }).collect()
}

// Scenario from git t6402-merge-rename.sh ("pull renaming branch into unrenaming one" and the reverse): one side renames, the other edits; the edit follows the rename.
#[test]
fn an_edit_follows_a_rename_in_either_direction() {
    for left_renames in [true, false] {
        let env = Env::new();
        let base = lines("l", 12);
        let edited = edit_line(&base, 9, "EDITED");
        let r = fork(
            &env,
            &[("a.txt", &base)],
            |r| match left_renames {
                true => mv(r, "a.txt", "b.txt"),
                false => r.write("a.txt", &edited),
            },
            |r| match left_renames {
                true => r.write("a.txt", &edited),
                false => mv(r, "a.txt", "b.txt"),
            },
        );
        let out = r.ok(&["merge", "left", "-m", "merge left"]);
        assert!(out.contains("followed rename a.txt -> b.txt"), "{out}");
        assert!(!out.contains("conflict"), "{out}");
        assert_eq!(r.cat("@-", "b.txt"), edited);
        assert!(!r.paths("@-").contains(&"a.txt".to_string()));
        // t6414-merge-rename-nocruft: the working copy holds no stale file.
        assert!(!r.exists("a.txt"));
        assert_eq!(r.read("b.txt"), edited);
    }
}

// Scenario from git t6402-merge-rename.sh ("rename and modify on one side, modify on the other"): an inexact rename merges with an edit of the old name.
#[test]
fn a_renamed_and_edited_file_merges_with_an_edit_of_the_old_name() {
    let env = Env::new();
    let base = lines("l", 12);
    let r = fork(
        &env,
        &[("a.txt", &base)],
        |r| {
            mv(r, "a.txt", "b.txt");
            r.write("b.txt", edit_line(&base, 0, "LEFT"));
        },
        |r| r.write("a.txt", edit_line(&base, 11, "RIGHT")),
    );
    r.ok(&["merge", "left", "-m", "merge"]);
    assert_eq!(r.cat("@-", "b.txt"), edit_line(&edit_line(&base, 0, "LEFT"), 11, "RIGHT"));
    assert!(r.snap("@-").conflicts.is_empty());
}

// Scenario from git t6422-merge-rename-corner-cases.sh (rename/rename(1to2)): both names are kept as conflicts; either can be chosen with `vl resolve`.
#[test]
fn rename_rename_to_two_names_conflicts_at_both() {
    let env = Env::new();
    let base = lines("l", 10);
    let r = fork(&env, &[("a.txt", &base)], |r| mv(r, "a.txt", "left.txt"), |r| mv(r, "a.txt", "right.txt"));
    let out = r.ok(&["merge", "left", "-m", "merge"]);
    assert!(out.contains("renamed to right.txt and to left.txt"), "{out}");
    let list = r.out(&["resolve", "--list"]);
    assert!(list.contains("left.txt") && list.contains("right.txt"), "{list}");
    // Keep ours' name (right.txt): its version at right.txt, nothing at
    // left.txt (ours had nothing there).
    r.ok(&["resolve", "right.txt", "left.txt", "--ours"]);
    assert_eq!(r.read("right.txt"), base);
    assert!(!r.exists("left.txt"));
    assert!(r.out(&["resolve", "--list"]).trim().is_empty() || !r.out(&["resolve", "--list"]).contains(".txt"));
}

// Scenario from git t6422-merge-rename-corner-cases.sh (rename/add): a rename onto a name the other side added is not followed; the merge does what it did before.
#[test]
fn rename_add_falls_back_to_modify_delete() {
    let env = Env::new();
    let base = lines("l", 10);
    let r = fork(
        &env,
        &[("a.txt", &base)],
        |r| mv(r, "a.txt", "b.txt"),
        |r| {
            r.write("a.txt", edit_line(&base, 3, "EDIT"));
            r.write("b.txt", "their own b\n");
        },
    );
    let out = r.ok(&["merge", "left", "-m", "merge"]);
    assert!(!out.contains("followed rename"), "{out}");
    let c = r.snap("@-").conflicts;
    assert!(c.contains(&"a.txt".to_string()) && c.contains(&"b.txt".to_string()), "{c:?}");
}

// Scenario from git t6425-merge-rename-delete.sh: rename/delete is a conflict at the new name, holding the renamed file against no file.
#[test]
fn rename_delete_is_a_conflict_at_the_new_name() {
    let env = Env::new();
    let base = lines("l", 10);
    let r = fork(&env, &[("a.txt", &base), ("k", "k\n")], |r| mv(r, "a.txt", "b.txt"), |r| r.rm("a.txt"));
    let out = r.ok(&["merge", "left", "-m", "merge"]);
    assert!(out.contains("renamed to b.txt on one side and deleted on the other"), "{out}");
    assert_eq!(r.snap("@-").conflicts, vec!["b.txt".to_string()]);
    // The modify/delete rendering: the renamed file as it is.
    assert_eq!(r.read("b.txt"), base);
    // Ours (the destination) deleted it; theirs (merged in) renamed it.
    r.ok(&["resolve", "b.txt", "--ours"]);
    assert!(!r.exists("b.txt"));
}

// Scenario from git t6412-merge-large-rename.sh: many files renamed at once (a directory moved file by file), a few edited on the other side; every edit follows.
#[test]
fn many_renamed_files_each_follow_their_edits() {
    let env = Env::new();
    let files: Vec<(String, String)> = (0..30).map(|i| (format!("src/m{i}.rs"), lines(&format!("m{i}"), 8))).collect();
    let base: Vec<(&str, &str)> = files.iter().map(|(p, c)| (p.as_str(), c.as_str())).collect();
    let r = fork(
        &env,
        &base,
        |r| {
            for i in 0..30 {
                mv(r, &format!("src/m{i}.rs"), &format!("lib/m{i}.rs"));
            }
        },
        |r| {
            for i in [3, 17, 29] {
                r.write(&format!("src/m{i}.rs"), edit_line(&lines(&format!("m{i}"), 8), 4, &format!("EDIT {i}")));
            }
        },
    );
    r.ok(&["merge", "left", "-m", "merge"]);
    assert!(r.snap("@-").conflicts.is_empty());
    for i in [3, 17, 29] {
        assert!(r.read(&format!("lib/m{i}.rs")).contains(&format!("EDIT {i}")));
    }
    assert!(!r.exists("src"), "no cruft left at the old names");
}

// Scenario from git t6429-merge-sequence-rename-caching.sh and t3401-rebase-and-am-rename.sh: a sequence of changes editing a file, rebased onto a rename of it; each edit follows (auto-rebase of the descendants included).
#[test]
fn rebasing_a_sequence_onto_a_rename_follows_it() {
    let env = Env::new();
    let r = env.repo("p");
    let base = lines("l", 20);
    r.commit("base", &[("a.txt", &base)]);
    r.tag("base", "@-");
    mv(&r, "a.txt", "renamed/a.txt");
    r.ok(&["commit", "--no-advance", "-m", "rename"]);
    r.tag("renamed", "@-");
    r.ok(&["new", "base"]);
    let one = edit_line(&base, 2, "ONE");
    r.commit("one", &[("a.txt", &one)]);
    r.tag("one", "@-");
    let two = edit_line(&one, 17, "TWO");
    r.commit("two", &[("a.txt", &two)]);
    let out = r.ok(&["rebase", "-s", "one", "-d", "renamed"]);
    assert!(out.contains("followed rename a.txt -> renamed/a.txt"), "{out}");
    assert_eq!(r.cat("one", "renamed/a.txt"), one);
    assert_eq!(r.cat("@-", "renamed/a.txt"), two, "the descendant follows too");
    assert!(!r.paths("@-").contains(&"a.txt".to_string()));
    assert_eq!(r.read("renamed/a.txt"), two);
    // t3401 in the other direction: a change that renamed the file, rebased
    // onto an edit of it.
    let env = Env::new();
    let r = env.repo("q");
    r.commit("base", &[("a.txt", &base)]);
    r.tag("base", "@-");
    r.commit("edit", &[("a.txt", &one)]);
    r.tag("edit", "@-");
    r.ok(&["new", "base"]);
    mv(&r, "a.txt", "b.txt");
    r.ok(&["commit", "--no-advance", "-m", "rename"]);
    r.tag("mv", "@-");
    r.ok(&["rebase", "-s", "mv", "-d", "edit"]);
    assert_eq!(r.cat("mv", "b.txt"), one);
    assert!(!r.paths("mv").contains(&"a.txt".to_string()));
}

// Scenario from git t6434-merge-recursive-rename-options.sh: `--no-renames` (`VEIL_MERGE_RENAMES=0`) and the similarity threshold.
#[test]
fn rename_following_can_be_switched_off_and_respects_the_threshold() {
    let env = Env::new();
    let base = lines("l", 12);
    let r = fork(&env, &[("a.txt", &base)], |r| mv(r, "a.txt", "b.txt"), |r| r.write("a.txt", edit_line(&base, 5, "E")));
    let out = env.cmd("alice", &r.dir, &["merge", "left", "-m", "merge"]).env("VEIL_MERGE_RENAMES", "0").output().unwrap();
    assert!(out.status.success(), "{}", text(&out));
    assert!(!text(&out).contains("followed rename"));
    assert!(r.snap("@-").conflicts.contains(&"a.txt".to_string()), "modify/delete, as before");
    // Any other value leaves it on (a hostile or mistyped value never
    // disables it silently).
    r.ok(&["undo"]);
    let out = env.cmd("alice", &r.dir, &["merge", "left", "-m", "merge"]).env("VEIL_MERGE_RENAMES", "\u{1b}[31mno").output().unwrap();
    assert!(text(&out).contains("followed rename"), "{}", text(&out));
    // A file rewritten past the threshold (50%) is not a rename.
    let env = Env::new();
    let r = fork(
        &env,
        &[("a.txt", &base)],
        |r| {
            mv(r, "a.txt", "b.txt");
            r.write("b.txt", format!("{}{}", lines("x", 9), lines("l", 3)));
        },
        |r| r.write("a.txt", edit_line(&base, 5, "E")),
    );
    let out = r.ok(&["merge", "left", "-m", "merge"]);
    assert!(!out.contains("followed rename"), "{out}");
}
