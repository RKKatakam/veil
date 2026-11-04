//! History rewriting: Git t34xx (rebase) mapped to `vl rebase`, `squash`,
//! `abandon`, `describe` and `edit`; jj test_rebase_command.rs,
//! test_squash_command.rs, test_abandon_command.rs, test_evolog_command.rs,
//! lib test_rewrite.rs, test_mut_repo.rs and test_evolution_predecessors.rs.

use crate::merge::fork;
use crate::support::*;

/// root ← a ← b ← c, each adding one file; tags a, b, c; `@` empty on c.
fn chain(env: &Env) -> R<'_> {
    let r = env.repo("p");
    for n in ["a", "b", "c"] {
        r.commit(n, &[(n, &format!("{n}\n"))]);
        r.tag(n, "@-");
    }
    r
}

// ---- rebase ----------------------------------------------------------------

// Scenario from git t3400-rebase.sh / jj test_rebase_single_revision: move a change onto another line.
#[test]
fn rebase_moves_a_change_and_keeps_its_change_id() {
    let env = Env::new();
    let r = fork(
        &env,
        &[("f", "1\n2\n3\n")],
        |r: &R| r.write("f", "1\n2\nLEFT3\n"),
        |r: &R| r.write("f", "RIGHT1\n2\n3\n"),
    );
    let change = r.cid("right");
    let old = r.sid("right");
    let out = r.ok(&["rebase", "-s", "right", "-d", "left"]);
    assert!(out.contains("Rebased"), "{out}");
    let s = r.snap("right");
    assert_eq!(s.change, change, "change id changed by rebase");
    assert_ne!(s.id, old);
    assert_eq!(s.parents, vec![r.sid("left")]);
    assert_eq!(s.predecessors, vec![old]);
    assert_eq!(r.cat("right", "f"), "RIGHT1\n2\nLEFT3\n");
    // The working copy sat on `right`: it followed, and the disk shows the result.
    assert_eq!(r.snap("@").parents, vec![s.id]);
    assert_eq!(r.read("f"), "RIGHT1\n2\nLEFT3\n");
}

// Scenario from jj test_rebase_with_descendants / git t3421-rebase-topology-linear.sh: descendants follow.
#[test]
fn rebase_source_brings_its_descendants() {
    let env = Env::new();
    let r = chain(&env);
    r.ok(&["new", "a"]);
    r.commit("side", &[("side", "s\n")]);
    r.tag("side", "@-");
    let (cb, cc) = (r.cid("b"), r.cid("c"));
    r.ok(&["rebase", "-s", "b", "-d", "side"]);
    assert_eq!(r.cid("b"), cb);
    assert_eq!(r.cid("c"), cc);
    assert_eq!(r.snap("b").parents, vec![r.sid("side")]);
    assert_eq!(r.snap("c").parents, vec![r.sid("b")]);
    let mut p = r.paths("c");
    p.retain(|x| x != ".veilpolicy");
    assert_eq!(p, vec!["a", "b", "c", "side"]);
}

// Scenario from jj test_rebase_revision_onto_descendant / git t3400: refusing a cycle.
#[test]
fn rebase_onto_a_descendant_or_itself_is_refused() {
    let env = Env::new();
    let r = chain(&env);
    r.ok(&["status"]);
    let before = r.op_head();
    let err = r.fails(&["rebase", "-s", "a", "-d", "c"]);
    assert!(err.contains("descendant"), "{err}");
    r.fails(&["rebase", "-s", "b", "-d", "b"]);
    assert_eq!(
        r.op_head(),
        before,
        "a refused rebase recorded an operation"
    );
}

// Scenario from git t3412-rebase-root.sh / jj test_rebase_invalid: the root cannot be moved.
#[test]
fn rebasing_the_root_is_refused() {
    let env = Env::new();
    let r = chain(&env);
    r.fails(&["rebase", "-s", "root", "-d", "a"]);
}

// Scenario from git t3412-rebase-root.sh / jj test_rebase_single_revision_merge_parent_on_root: onto the root.
#[test]
fn rebase_onto_the_root_keeps_only_the_changes_own_diff() {
    let env = Env::new();
    let r = chain(&env);
    r.ok(&["rebase", "-s", "c", "-d", "root"]);
    let s = r.snap("c");
    assert_eq!(s.parents.len(), 1);
    assert_eq!(s.parent_changes[0], "z".repeat(32));
    assert_eq!(r.paths("c"), vec!["c"]);
}

// Scenario from jj test_rebase_multiple_destinations: two destinations make a merge.
#[test]
fn rebase_onto_two_destinations_creates_a_merge() {
    let env = Env::new();
    let r = chain(&env);
    r.ok(&["new", "a"]);
    r.commit("side", &[("side", "s\n")]);
    r.tag("side", "@-");
    r.ok(&["rebase", "-s", "c", "-d", "b", "-d", "side"]);
    let s = r.snap("c");
    assert_eq!(s.parents, vec![r.sid("b"), r.sid("side")]);
    let mut p = r.paths("c");
    p.retain(|x| x != ".veilpolicy");
    assert_eq!(p, vec!["a", "b", "c", "side"]);
}

// Scenario from jj test_rebase_multiple_destinations (duplicate destination): one parent recorded.
#[test]
fn rebase_with_a_repeated_destination_records_one_parent() {
    let env = Env::new();
    let r = chain(&env);
    r.write("wip", "w\n");
    let out = r.run(&["rebase", "-s", "@", "-d", "a", "-d", "a"]);
    if out.status.success() {
        let s = r.snap("@");
        let mut uniq = s.parents.clone();
        uniq.dedup();
        assert_eq!(uniq.len(), s.parents.len(), "duplicate parents: {s:?}");
    }
}

// Scenario from git t3425-rebase-topology-merges.sh / jj test_rebase_single_revision_merge_parent: flatten a merge.
#[test]
fn rebase_a_merge_onto_one_destination() {
    let env = Env::new();
    let r = fork(
        &env,
        &[("k", "k\n")],
        |r: &R| r.write("l", "l\n"),
        |r: &R| r.write("r", "r\n"),
    );
    r.ok(&["merge", "left", "-m", "M"]);
    r.write("m-own", "m\n");
    r.ok(&["squash"]);
    let m = r.cid("@-");
    r.ok(&["rebase", "-s", &m, "-d", "base"]);
    let s = r.snap(&m);
    assert_eq!(s.parents, vec![r.sid("base")]);
    // The merge's own change (m-own) is kept; what came from its parents is not.
    let p = r.paths(&m);
    assert!(p.contains(&"m-own".to_string()), "{p:?}");
    assert!(
        !p.contains(&"l".to_string()) && !p.contains(&"r".to_string()),
        "{p:?}"
    );
}

// Scenario from git t3400 / jj test_rebase (conflicts): a conflicting rebase still succeeds and is recorded.
#[test]
fn conflicting_rebase_records_the_conflict() {
    let env = Env::new();
    let r = fork(
        &env,
        &[("f", "x\n")],
        |r: &R| r.write("f", "left\n"),
        |r: &R| r.write("f", "right\n"),
    );
    let out = r.ok(&["rebase", "-s", "right", "-d", "left"]);
    assert!(out.contains("conflicts in: f"), "{out}");
    let s = r.snap("right");
    assert_eq!(s.conflicts, vec!["f".to_string()]);
    let f = r.read("f");
    assert!(
        f.contains("<<<<<<<") && f.contains("left") && f.contains("right"),
        "{f}"
    );
    assert!(r.out(&["log"]).contains("(conflict)"));
}

// Scenario from jj test_rebase (descendants of a conflict): a child inherits the conflicted content.
#[test]
fn descendants_of_a_conflicted_rebase_follow() {
    let env = Env::new();
    let r = fork(
        &env,
        &[("f", "x\n"), ("g", "g\n")],
        |r: &R| r.write("f", "left\n"),
        |r: &R| r.write("f", "right\n"),
    );
    r.commit("child", &[("g", "G\n")]);
    let child = r.cid("@-");
    r.ok(&["rebase", "-s", "right", "-d", "left"]);
    assert!(r.cat(&child, "f").contains("<<<<<<<"));
    assert_eq!(r.cat(&child, "g"), "G\n");
    assert_eq!(r.snap(&child).parent_changes, vec![r.cid("right")]);
}

// Scenario from git t3424-rebase-empty.sh / jj test_rebase_skip_emptied: a change already upstream becomes empty, not lost.
#[test]
fn change_already_upstream_becomes_empty() {
    let env = Env::new();
    let r = fork(
        &env,
        &[("f", "x\n")],
        |r: &R| r.write("f", "same\n"),
        |r: &R| r.write("f", "same\n"),
    );
    let change = r.cid("right");
    r.ok(&["rebase", "-s", "right", "-d", "left"]);
    assert_eq!(r.cid("right"), change);
    assert!(r.snap("right").conflicts.is_empty());
    let log = r.out(&["log"]);
    let line = log
        .lines()
        .find(|l| l.contains("right ") || l.contains(" right"))
        .unwrap_or_default();
    assert!(line.contains("(empty)"), "{log}");
    assert_eq!(
        r.snap("right").description.as_deref(),
        Some("right"),
        "description kept"
    );
}

// Scenario from jj test_rebase_skip_if_on_destination: rebasing onto the current parent changes nothing.
#[test]
#[ignore = "BUG-246: a no-op rebase (onto the current parent) rewrites the change and all its descendants, re-signing them"]
fn rebase_onto_the_current_parent_is_a_no_op() {
    let env = Env::new();
    let r = chain(&env);
    let before = (r.sid("b"), r.sid("c"));
    r.ok(&["rebase", "-s", "b", "-d", "a"]);
    assert_eq!(
        (r.sid("b"), r.sid("c")),
        before,
        "snapshots rewritten by a rebase that moved nothing"
    );
}

// Scenario from jj test_rebase_bookmark: tags on rebased changes follow them.
#[test]
fn tags_follow_rebased_changes() {
    let env = Env::new();
    let r = chain(&env);
    r.ok(&["new", "a"]);
    r.commit("side", &[("side", "s\n")]);
    r.tag("side", "@-");
    r.ok(&["rebase", "-s", "b", "-d", "side"]);
    assert_eq!(
        r.snap("b").parents,
        vec![r.sid("side")],
        "tag b no longer points at the rebased change"
    );
    assert_eq!(r.snap("c").parents, vec![r.sid("b")]);
}

// Scenario from guide `vl rebase -d main` (default source @).
#[test]
fn rebase_without_source_moves_the_working_copy() {
    let env = Env::new();
    let r = chain(&env);
    r.ok(&["new", "a"]);
    r.write("wip", "w\n");
    r.ok(&["rebase", "-d", "c"]);
    assert_eq!(r.snap("@").parents, vec![r.sid("c")]);
    assert_eq!(r.read("wip"), "w\n");
    assert!(r.exists("b") && r.exists("c"));
}

// Scenario from jj test_rebase_error_revision_does_not_exist.
#[test]
fn rebase_with_unknown_revisions_fails() {
    let env = Env::new();
    let r = chain(&env);
    r.ok(&["status"]);
    let before = r.op_head();
    assert!(r
        .fails(&["rebase", "-s", "nosuch", "-d", "a"])
        .contains("not found"));
    assert!(r
        .fails(&["rebase", "-s", "a", "-d", "nosuch"])
        .contains("not found"));
    r.fails(&["rebase", "-s", "a"]);
    assert_eq!(r.op_head(), before);
}

// Scenario from git t3433-rebase-across-mode-change.sh: upstream chmod, rebased content edit.
#[test]
fn rebase_across_a_mode_change() {
    let env = Env::new();
    let r = fork(
        &env,
        &[("run.sh", "echo 1\n")],
        |r: &R| r.chmod_x("run.sh", true),
        |r: &R| r.write("run.sh", "echo 2\n"),
    );
    r.ok(&["rebase", "-s", "right", "-d", "left"]);
    let f = r
        .tree_files("right")
        .into_iter()
        .find(|f| f.0 == "run.sh")
        .unwrap();
    assert_eq!(f.1.as_deref(), Some(&b"echo 2\n"[..]));
    assert!(f.3, "the upstream chmod +x was lost by the rebase");
}

// Scenario from git t3400 / t6400 (D/F during rebase): upstream turned the file into a directory.
#[test]
fn rebase_across_a_file_directory_swap() {
    let env = Env::new();
    let r = fork(
        &env,
        &[("thing", "file\n")],
        |r: &R| {
            r.rm("thing");
            r.write("thing/x", "dir\n");
        },
        |r: &R| r.write("thing", "edited file\n"),
    );
    let out = r.run(&["rebase", "-s", "right", "-d", "left"]);
    assert!(
        out.status.success() && exited_cleanly(&out),
        "{}",
        text(&out)
    );
    assert!(
        r.snap("right").conflicts.contains(&"thing".to_string()),
        "{}",
        text(&out)
    );
}

// Scenario from jj test_rebase_with_child_and_descendant_bug_2600: a merge of a change and its own ancestor.
#[test]
fn rebase_and_abandon_with_a_merge_of_child_and_ancestor() {
    let env = Env::new();
    let r = chain(&env);
    // m has parents b and a (a is an ancestor of b).
    r.ok(&["new", "b", "a", "-m", "m"]);
    r.write("m", "m\n");
    r.ok(&["new"]);
    let m = r.cid("@-");
    r.ok(&["abandon", "b"]);
    let s = r.snap(&m);
    assert_eq!(
        s.parents,
        vec![r.sid("a")],
        "parents not simplified after abandoning b: {s:?}"
    );
    let mut p = r.paths(&m);
    p.retain(|x| x != ".veilpolicy");
    assert_eq!(p, vec!["a", "m"]);
}

// ---- squash ----------------------------------------------------------------

// Scenario from jj test_squash / git t3415 (fixup): fold @ into its parent.
#[test]
fn squash_folds_the_working_copy_into_its_parent() {
    let env = Env::new();
    let r = chain(&env);
    r.ok(&["edit", "c"]);
    r.ok(&["new"]);
    r.write("c", "c fixed\n");
    let parent_change = r.cid("@-");
    let wc_change = r.cid("@");
    let out = r.ok(&["squash"]);
    assert!(out.contains("Squashed into"), "{out}");
    assert_eq!(r.cid("@-"), parent_change, "the parent kept its change id");
    assert_ne!(r.cid("@"), wc_change, "@ is a fresh change");
    assert_eq!(r.cat("@-", "c"), "c fixed\n");
    assert_eq!(r.read("c"), "c fixed\n");
    assert!(
        r.try_snap(&wc_change).is_none(),
        "the squashed change is still visible"
    );
    assert_eq!(
        r.snap("@-").description.as_deref(),
        Some("c"),
        "an empty description adds nothing"
    );
}

// Scenario from jj test_squash_description: both descriptions are kept.
#[test]
fn squash_joins_descriptions() {
    let env = Env::new();
    let r = chain(&env);
    r.ok(&["describe", "-m", "fixup for c"]);
    r.write("c", "c2\n");
    r.ok(&["squash"]);
    assert_eq!(
        r.snap("@-").description.as_deref(),
        Some("c\n\nfixup for c")
    );
}

// Scenario from jj test_squash -r / git t3415-rebase-autosquash.sh: squash a middle change; descendants keep their content.
#[test]
fn squash_a_middle_change() {
    let env = Env::new();
    let r = chain(&env);
    let (ca, cc) = (r.cid("a"), r.cid("c"));
    let tree_c = r.paths("c");
    r.ok(&["squash", "-r", "b"]);
    assert_eq!(r.cid("a"), ca);
    let a = r.snap(&ca);
    let mut p = r.paths(&ca);
    p.retain(|x| x != ".veilpolicy");
    assert_eq!(p, vec!["a", "b"]);
    assert_eq!(a.description.as_deref(), Some("a\n\nb"));
    assert_eq!(r.snap(&cc).parents, vec![a.id]);
    assert_eq!(r.paths(&cc), tree_c);
    // The tag of the squashed change moved to the change it was folded into.
    assert_eq!(r.tag_target("b"), Some(r.sid(&ca)));
}

// Scenario from jj test_squash (merge): a merge cannot be squashed.
#[test]
fn squashing_a_merge_is_refused() {
    let env = Env::new();
    let r = fork(
        &env,
        &[("k", "k\n")],
        |r: &R| r.write("l", "l\n"),
        |r: &R| r.write("r", "r\n"),
    );
    r.ok(&["merge", "left"]);
    r.ok(&["status"]);
    let before = r.op_head();
    let err = r.fails(&["squash", "-r", "@-"]);
    assert!(err.contains("exactly one parent"), "{err}");
    assert_eq!(r.op_head(), before);
}

// Scenario from jj test_squash (into root) / git t3412-rebase-root.sh.
#[test]
fn squashing_into_the_root_is_refused() {
    let env = Env::new();
    let r = chain(&env);
    let err = r.fails(&["squash", "-r", "a"]);
    assert!(err.contains("root"), "{err}");
    r.fails(&["squash", "-r", "root"]);
}

// Scenario from jj test_squash (into a merge): squashing a child into a merge is fine.
#[test]
fn squash_into_a_merge() {
    let env = Env::new();
    let r = fork(
        &env,
        &[("k", "k\n")],
        |r: &R| r.write("l", "l\n"),
        |r: &R| r.write("r", "r\n"),
    );
    r.ok(&["merge", "left", "-m", "M"]);
    r.write("extra", "e\n");
    r.ok(&["squash"]);
    let m = r.snap("@-");
    assert_eq!(m.parents.len(), 2);
    assert!(r.paths("@-").contains(&"extra".to_string()));
    assert_eq!(m.description.as_deref(), Some("M"));
}

// Scenario from jj test_squash_empty: squashing an empty change keeps the parent's content.
#[test]
fn squash_of_an_empty_change() {
    let env = Env::new();
    let r = chain(&env);
    let tree = r.snap("c").tree;
    r.ok(&["squash"]);
    assert_eq!(r.snap("c").tree, tree);
    assert_eq!(r.snap("c").description.as_deref(), Some("c"));
}

// Scenario from jj test_squash (deletions): a deletion in the child is folded too.
#[test]
fn squash_folds_deletions() {
    let env = Env::new();
    let r = chain(&env);
    r.rm("a");
    r.ok(&["squash"]);
    assert!(!r.paths("c").contains(&"a".to_string()));
    assert!(r.paths("b").contains(&"a".to_string()));
}

// ---- abandon ---------------------------------------------------------------

// Scenario from jj test_abandon basics / git t3454-history-drop.sh: drop a middle change.
#[test]
fn abandon_a_middle_change_rebases_descendants() {
    let env = Env::new();
    let r = chain(&env);
    let cc = r.cid("c");
    let cb = r.cid("b");
    let out = r.ok(&["abandon", "b"]);
    assert!(out.contains("Abandoned"), "{out}");
    assert_eq!(r.cid("c"), cc);
    assert_eq!(r.snap("c").parents, vec![r.sid("a")]);
    let mut p = r.paths("c");
    p.retain(|x| x != ".veilpolicy");
    assert_eq!(p, vec!["a", "c"], "b's file survived its abandon");
    assert!(!r.exists("b"));
    assert!(r.try_snap(&cb).is_none(), "abandoned change still resolves");
    assert_eq!(
        r.tag_target("b"),
        Some(r.sid("a")),
        "tag on the abandoned change moves to its parent"
    );
}

// Scenario from jj test_abandon (working copy).
#[test]
fn abandon_the_working_copy_starts_a_fresh_change() {
    let env = Env::new();
    let r = chain(&env);
    r.write("scratch", "throw away\n");
    let wc = r.cid("@");
    r.ok(&["abandon"]);
    assert_ne!(r.cid("@"), wc);
    assert_eq!(r.snap("@").parents, vec![r.sid("c")]);
    assert!(
        !r.exists("scratch"),
        "abandoned working-copy file still on disk"
    );
}

// Scenario from jj test_abandon (root).
#[test]
fn abandoning_the_root_is_refused() {
    let env = Env::new();
    let r = chain(&env);
    let err = r.fails(&["abandon", "root"]);
    assert!(err.contains("root"), "{err}");
}

// Scenario from jj test_abandon_many (merge): abandoning a merge gives its child both parents.
#[test]
fn abandon_a_merge_reparents_its_child_onto_both_sides() {
    let env = Env::new();
    let r = fork(
        &env,
        &[("k", "k\n")],
        |r: &R| r.write("l", "l\n"),
        |r: &R| r.write("r", "r\n"),
    );
    let (right, left) = (r.sid("right"), r.sid("left"));
    r.ok(&["merge", "left", "-m", "M"]);
    r.commit("child", &[("c", "c\n")]);
    let child = r.cid("@-");
    let merge = r.cid("@--");
    r.ok(&["abandon", &merge]);
    assert_eq!(r.snap(&child).parents, vec![right, left]);
}

// Scenario from jj test_double_abandon: an abandoned change cannot be abandoned again.
#[test]
fn double_abandon_fails_the_second_time() {
    let env = Env::new();
    let r = chain(&env);
    let cb = r.cid("b");
    r.ok(&["abandon", &cb]);
    let err = r.fails(&["abandon", &cb]);
    assert!(err.contains("not found"), "{err}");
}

// Scenario from git t3454 / jj: dropping a change that a descendant edits again conflicts in the descendant.
#[test]
fn abandon_under_a_dependent_edit_conflicts() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("one", &[("f", "1\n")]);
    r.commit("two", &[("f", "2\n")]);
    let two = r.cid("@-");
    r.commit("three", &[("f", "3\n")]);
    let three = r.cid("@-");
    r.ok(&["abandon", &two]);
    let s = r.snap(&three);
    assert_eq!(s.conflicts, vec!["f".to_string()], "{s:?}");
}

// ---- describe / edit -------------------------------------------------------

// Scenario from git t3423-rebase-reword.sh / t3451-history-reword.sh: reword an ancestor.
#[test]
fn describe_an_ancestor_rebases_descendants_with_stable_ids() {
    let env = Env::new();
    let r = chain(&env);
    let ids: Vec<String> = ["a", "b", "c"].iter().map(|t| r.cid(t)).collect();
    let snaps: Vec<String> = ["a", "b", "c"].iter().map(|t| r.sid(t)).collect();
    r.ok(&["describe", "-r", "a", "-m", "A, reworded"]);
    let after: Vec<String> = ["a", "b", "c"].iter().map(|t| r.cid(t)).collect();
    assert_eq!(after, ids);
    for (t, old) in ["a", "b", "c"].iter().zip(&snaps) {
        assert_ne!(&r.sid(t), old, "{t} not rewritten");
    }
    assert_eq!(r.snap("a").description.as_deref(), Some("A, reworded"));
    assert_eq!(r.snap("c").description.as_deref(), Some("c"));
}

// Scenario from jj test_describe (no-op): the same message records nothing.
#[test]
#[ignore = "BUG-246: `vl describe` with the unchanged message rewrites the change and its descendants, and records an operation"]
fn describe_with_the_same_message_is_a_no_op() {
    let env = Env::new();
    let r = chain(&env);
    r.ok(&["status"]);
    let (op, s) = (r.op_head(), r.sid("b"));
    r.ok(&["describe", "-r", "b", "-m", "b"]);
    assert_eq!(r.sid("b"), s);
    assert_eq!(r.op_head(), op, "a no-op describe recorded an operation");
}

// Scenario from jj test_describe: the root has no description to set.
#[test]
fn describing_the_root_is_refused() {
    let env = Env::new();
    let r = env.repo("p");
    let err = r.fails(&["describe", "-r", "root", "-m", "x"]);
    assert!(err.contains("root"), "{err}");
}

// Scenario from git t3408-rebase-multi-line.sh: multi-line descriptions survive rewrites.
#[test]
fn multi_line_descriptions_survive_a_rebase() {
    let env = Env::new();
    let r = chain(&env);
    let msg = "Subject line\n\nBody paragraph one.\n  indented\n\nTrailer: x";
    r.ok(&["describe", "-r", "c", "-m", msg]);
    r.ok(&["rebase", "-s", "c", "-d", "a"]);
    assert_eq!(r.snap("c").description.as_deref(), Some(msg));
    let log = r.out(&["log"]);
    assert!(
        log.contains("Subject line") && !log.contains("Body paragraph"),
        "{log}"
    );
}

// Scenario from jj test_edit / git t3404 (edit): editing an older change rebases its descendants automatically.
#[test]
fn editing_an_older_change_rebases_descendants() {
    let env = Env::new();
    let r = chain(&env);
    r.ok(&["edit", "a"]);
    assert!(!r.exists("b"));
    r.write("a", "a, amended\n");
    r.ok(&["status"]);
    assert_eq!(r.cat("c", "a"), "a, amended\n");
    assert_eq!(r.cat("b", "a"), "a, amended\n");
    assert_eq!(r.snap("b").parents, vec![r.sid("a")]);
}

// Scenario from jj test_edit: the root cannot be edited.
#[test]
fn editing_the_root_is_refused() {
    let env = Env::new();
    let r = env.repo("p");
    let err = r.fails(&["edit", "root"]);
    assert!(err.contains("vl new root"), "{err}");
}

// ---- the op log --------------------------------------------------------------

/// Run `args`, check that the newest operation's description contains
/// `op_desc`, then `vl undo` and check the repository is exactly as before.
fn undo_restores(r: &R, args: &[&str], op_desc: &str) {
    r.ok(&["status"]);
    let before = r.state();
    let before_op = r.op_head();
    r.ok(args);
    assert_ne!(r.state(), before, "{args:?} changed nothing");
    let log = r.out(&["op", "log", "-n", "1"]);
    assert!(log.contains(op_desc), "op log for {args:?}:\n{log}");
    let out = r.ok(&["undo"]);
    assert!(out.contains(op_desc), "{out}");
    assert_eq!(
        r.state(),
        before,
        "undo of {args:?} did not restore the prior state"
    );
    assert_ne!(r.op_head(), before_op, "undo is itself an operation");
}

// Scenario from jj test_undo / test_op_revert (rebase).
#[test]
fn undo_restores_the_state_before_a_rebase() {
    let env = Env::new();
    let r = chain(&env);
    undo_restores(&r, &["rebase", "-s", "c", "-d", "a"], "rebase change");
    assert!(r.exists("b"));
}

// Scenario from jj test_undo (squash).
#[test]
fn undo_restores_the_state_before_a_squash() {
    let env = Env::new();
    let r = chain(&env);
    undo_restores(&r, &["squash", "-r", "b"], "squash");
}

// Scenario from jj test_undo (abandon).
#[test]
fn undo_restores_the_state_before_an_abandon() {
    let env = Env::new();
    let r = chain(&env);
    undo_restores(&r, &["abandon", "b"], "abandon change");
    assert!(
        r.exists("b"),
        "the abandoned file did not come back on disk"
    );
}

// Scenario from jj test_undo (describe).
#[test]
fn undo_restores_the_state_before_a_describe() {
    let env = Env::new();
    let r = chain(&env);
    undo_restores(&r, &["describe", "-r", "a", "-m", "new"], "describe change");
}

// Scenario from jj test_undo (merge).
#[test]
fn undo_restores_the_state_before_a_merge() {
    let env = Env::new();
    let r = fork(
        &env,
        &[("f", "x\n")],
        |r: &R| r.write("f", "left\n"),
        |r: &R| r.write("f", "right\n"),
    );
    undo_restores(&r, &["merge", "left"], "merge");
    assert_eq!(
        r.read("f"),
        "right\n",
        "conflict markers left on disk after undo"
    );
}

// Scenario from jj test_op_restore: restoring an older operation after several rewrites.
#[test]
fn op_restore_returns_to_an_exact_earlier_state() {
    let env = Env::new();
    let r = chain(&env);
    r.ok(&["status"]);
    let state = r.state();
    let op = r.op_head();
    r.ok(&["rebase", "-s", "c", "-d", "a"]);
    r.ok(&["squash", "-r", "b"]);
    r.ok(&["describe", "-r", "c", "-m", "renamed"]);
    r.ok(&["op", "restore", &op[..12]]);
    assert_eq!(r.state(), state);
    assert!(r.exists("a") && r.exists("b") && r.exists("c"));
}

// Scenario from guide "Undo anything" ("Run it again to go further back") / jj test_undo (repeated).
#[test]
#[ignore = "BUG-247: a second `vl undo` undoes the first undo (re-applying the operation) instead of going further back as the guide says"]
fn repeated_undo_walks_back_through_rewrites() {
    let env = Env::new();
    let r = chain(&env);
    r.ok(&["status"]);
    let s0 = r.state();
    r.ok(&["describe", "-r", "a", "-m", "one"]);
    let s1 = r.state();
    r.ok(&["describe", "-r", "a", "-m", "two"]);
    r.ok(&["undo"]);
    assert_eq!(r.state(), s1);
    r.ok(&["undo"]);
    assert_eq!(
        r.snap("a").description.as_deref(),
        Some("a"),
        "the second undo re-applied `two`"
    );
    assert_eq!(r.state(), s0);
}

// Scenario from jj test_op_restore: `vl op restore` reaches back several operations.
#[test]
fn op_restore_walks_back_several_rewrites() {
    let env = Env::new();
    let r = chain(&env);
    r.ok(&["status"]);
    let s0 = r.state();
    let op0 = r.op_head();
    r.ok(&["describe", "-r", "a", "-m", "one"]);
    r.ok(&["describe", "-r", "a", "-m", "two"]);
    r.ok(&["undo"]);
    r.ok(&["op", "restore", &op0]);
    assert_eq!(r.state(), s0);
}

// Scenario from guide "Undo anything": undo after a rewrite keeps unrecorded edits.
#[test]
fn undo_of_a_rewrite_keeps_uncommitted_edits() {
    let env = Env::new();
    let r = chain(&env);
    r.ok(&["describe", "-r", "a", "-m", "renamed"]);
    r.write("wip", "unsaved work\n");
    r.ok(&["undo"]);
    assert_eq!(r.read("wip"), "unsaved work\n");
    assert_eq!(r.snap("a").description.as_deref(), Some("a"));
}

// Scenario from jj test_mut_repo / test_rewrite: every rewrite is one operation, named after it.
#[test]
fn each_rewrite_records_one_named_operation() {
    let env = Env::new();
    let r = chain(&env);
    r.ok(&["status"]);
    let steps: Vec<(Vec<&str>, &str)> = vec![
        (vec!["describe", "-r", "a", "-m", "A"], "describe change"),
        (vec!["rebase", "-s", "c", "-d", "a"], "rebase change"),
        (vec!["squash", "-r", "c"], "squash"),
        (vec!["abandon", "b"], "abandon change"),
    ];
    for (args, desc) in steps {
        let before = r.core().op_log(1000).unwrap().len();
        r.ok(&args);
        let ops = r.core().op_log(1000).unwrap();
        assert_eq!(
            ops.len(),
            before + 1,
            "{args:?} recorded {} operations",
            ops.len() - before
        );
        assert!(
            ops[0].1.description.contains(desc),
            "{args:?}: {}",
            ops[0].1.description
        );
    }
}

// ---- evolog -------------------------------------------------------------------

// Scenario from jj test_evolog / test_evolution_predecessors: every version of a change.
#[test]
fn evolog_lists_each_version_newest_first() {
    let env = Env::new();
    let r = chain(&env);
    r.ok(&["describe", "-r", "c", "-m", "c v2"]);
    r.ok(&["rebase", "-s", "c", "-d", "a"]);
    let out = r.out(&["evolog", "-r", "c"]);
    let rows: Vec<&str> = out.lines().collect();
    assert!(rows.len() >= 3, "{out}");
    assert!(rows[0].contains("c v2"));
    let short = &r.cid("c")[..8];
    assert!(rows.iter().all(|l| l.contains(short)), "{out}");
    assert!(rows.iter().any(|l| l.ends_with(" c")), "{out}");
}

// Scenario from jj test_evolog_squash: the squash target's evolution shows its earlier version.
#[test]
fn evolog_after_squash_shows_the_parents_history() {
    let env = Env::new();
    let r = chain(&env);
    let before = r.sid("c");
    r.write("c", "c2\n");
    r.ok(&["squash"]);
    let out = r.out(&["evolog", "-r", "c"]);
    assert!(out.contains(&before[..8]), "{out}");
}

// Scenario from jj test_evolog (root).
#[test]
fn evolog_of_the_root() {
    let env = Env::new();
    let r = env.repo("p");
    let out = r.out(&["evolog", "-r", "root"]);
    assert_eq!(out.lines().count(), 1, "{out}");
}

// Scenario from jj test_abandon / test_rebase (workspaces): another workspace's working copy follows rewrites.
#[test]
fn another_workspaces_working_copy_follows_a_rebase() {
    let env = Env::new();
    let r = chain(&env);
    r.ok(&["ws", "new", "agent", "-r", "b"]);
    let agent = r.cid("agent@");
    r.ok(&["rebase", "-s", "b", "-d", "root"]);
    assert_eq!(r.cid("agent@"), agent);
    assert_eq!(r.snap("agent@").parents, vec![r.sid("b")]);
    r.ok(&["abandon", "b"]);
    let s = r.snap("agent@");
    assert_eq!(
        s.parent_changes,
        vec!["z".repeat(32)],
        "agent@ not moved onto b's parent"
    );
}

// Scenario from jj test_abandon (workspace working copy): abandoning another workspace's working copy gives it a new one.
#[test]
fn abandoning_another_workspaces_working_copy() {
    let env = Env::new();
    let r = chain(&env);
    r.ok(&["ws", "new", "agent", "-r", "c"]);
    let old = r.cid("agent@");
    r.ok(&["abandon", "agent@"]);
    let s = r.snap("agent@");
    assert_ne!(s.change, old);
    assert_eq!(s.parents, vec![r.sid("c")]);
}

// Scenario from git t3425-rebase-topology-merges.sh / jj test_rebase_with_descendants: a merge among the
// descendants is carried along, and still holds what its untouched other parent holds.
#[test]
#[ignore = "BUG-251: auto-rebasing a merge when one parent moves drops files the other parent still has (a merge's tree is rebased one parent at a time)"]
fn rebase_carries_a_descendant_merge() {
    let env = Env::new();
    let r = chain(&env);
    r.ok(&["new", "a"]);
    r.commit("side", &[("side", "s\n")]);
    r.tag("side", "@-");
    r.ok(&["new", "c", "side", "-m", "merge c+side"]);
    r.write("m", "m\n");
    r.ok(&["new"]);
    let m = r.cid("@-");
    r.ok(&["new", "root"]);
    r.commit("new base", &[("nb", "nb\n")]);
    r.tag("nb", "@-");
    r.ok(&["rebase", "-s", "b", "-d", "nb"]);
    let s = r.snap(&m);
    assert_eq!(s.parents, vec![r.sid("c"), r.sid("side")]);
    let p = r.paths(&m);
    for f in ["nb", "b", "c", "side", "m", "a"] {
        assert!(
            p.contains(&f.to_string()),
            "{f} missing from the carried merge: {p:?}"
        );
    }
}

// Same topology, files the moved line never touched: the carried merge keeps them.
#[test]
fn rebase_carries_a_descendant_merge_with_disjoint_files() {
    let env = Env::new();
    let r = chain(&env);
    r.ok(&["new", "a"]);
    r.commit("side", &[("side", "s\n")]);
    r.tag("side", "@-");
    r.ok(&["new", "c", "side", "-m", "merge c+side"]);
    r.write("m", "m\n");
    r.ok(&["new"]);
    let m = r.cid("@-");
    r.ok(&["new", "a"]);
    r.commit("new base", &[("nb", "nb\n")]);
    r.tag("nb", "@-");
    r.ok(&["rebase", "-s", "b", "-d", "nb"]);
    let s = r.snap(&m);
    assert_eq!(s.parents, vec![r.sid("c"), r.sid("side")]);
    let p = r.paths(&m);
    for f in ["nb", "b", "c", "side", "m", "a"] {
        assert!(
            p.contains(&f.to_string()),
            "{f} missing from the carried merge: {p:?}"
        );
    }
}

// Scenario from jj test_evolog (abandoned): an abandoned change has no visible evolution.
#[test]
fn evolog_of_an_abandoned_change_fails() {
    let env = Env::new();
    let r = chain(&env);
    let b = r.cid("b");
    r.ok(&["abandon", "b"]);
    r.fails(&["evolog", "-r", &b[..12]]);
}

// Scenario from git t3400 (rebase onto a conflicted base): conflicts propagate to the rebased change.
#[test]
fn rebase_onto_a_conflicted_change() {
    let env = Env::new();
    let r = fork(
        &env,
        &[("f", "x\n"), ("g", "g\n")],
        |r: &R| r.write("f", "left\n"),
        |r: &R| r.write("f", "right\n"),
    );
    r.ok(&["merge", "left", "-m", "conflicted"]);
    let m = r.cid("@-");
    r.ok(&["new", "base"]);
    r.commit("g edit", &[("g", "G\n")]);
    let g = r.cid("@-");
    r.ok(&["rebase", "-s", &g, "-d", &m]);
    assert!(r.cat(&g, "f").contains("<<<<<<<"));
    assert_eq!(r.cat(&g, "g"), "G\n");
}
