//! `vl duplicate` and `vl cherry-pick`: Git t3500–t3510 (cherry-pick:
//! basics, renames, merges, root, empty, conflicts, many, `-x`, ranges),
//! jj test_duplicate_command.rs and lib test_rewrite_duplicate.rs.

use super::support::*;

fn mv(r: &R, from: &str, to: &str) {
    std::fs::rename(r.dir.join(from), r.dir.join(to)).unwrap();
}

/// `base` (a.txt, b.txt); `feature` edits a.txt on top of it; `@` is a new
/// change on `base`.
fn setup(env: &Env) -> R<'_> {
    let r = env.repo("p");
    r.commit("base", &[("a.txt", &lines("a", 10)), ("b.txt", &lines("b", 10))]);
    r.tag("base", "@-");
    r.commit("feature", &[("a.txt", &format!("{}feature\n", lines("a", 10)))]);
    r.tag("feature", "@-");
    r.ok(&["new", "base"]);
    r
}

// Scenario from git t3501-revert-cherry-pick.sh ("cherry-pick after renaming branch"): the picked edit follows a rename on the receiving line.
#[test]
fn cherry_pick_onto_a_line_that_renamed_the_file() {
    let env = Env::new();
    let r = setup(&env);
    mv(&r, "a.txt", "renamed.txt");
    r.ok(&["commit", "-m", "rename"]);
    let out = r.ok(&["cherry-pick", "feature"]);
    assert!(out.contains("followed rename a.txt -> renamed.txt"), "{out}");
    assert_eq!(r.read("renamed.txt"), format!("{}feature\n", lines("a", 10)));
    assert!(!r.exists("a.txt"));
    assert_eq!(r.snap("@-").description.as_deref(), Some("feature"));
}

// Scenario from git t3500-cherry.sh / t3508-cherry-pick-many-commits.sh: several picks apply in order, one after the other, onto @-, and @ moves on top.
#[test]
fn cherry_pick_many_applies_them_in_order() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("base", &[("f", "0\n")]);
    r.tag("base", "@-");
    r.commit("one", &[("f", "0\n1\n")]);
    r.commit("two", &[("f", "0\n1\n2\n")]);
    r.commit("three", &[("f", "0\n1\n2\n3\n")]);
    r.tag("three", "@-");
    r.ok(&["new", "base"]);
    r.write("wip", "uncommitted\n");
    let wc_change = r.cid("@");
    let base = r.sid("base");
    // t3510-cherry-pick-sequence.sh: a range, oldest first.
    r.ok(&["cherry-pick", "base..three"]);
    assert_eq!(r.read("f"), "0\n1\n2\n3\n");
    assert_eq!(r.read("wip"), "uncommitted\n", "the working copy's own edits are kept");
    assert_eq!(r.cid("@"), wc_change, "@ is the same change, moved");
    assert_eq!(r.snap("@-").description.as_deref(), Some("three"));
    assert_eq!(r.snap("@--").description.as_deref(), Some("two"));
    assert_eq!(r.snap("@---").description.as_deref(), Some("one"));
    assert_eq!(r.sid("@----"), base);
    // The tag at @- moved to the last copy, as a commit there would move it.
    assert_eq!(r.sid("base"), r.sid("@-"));
    // One operation: undo takes all of it back.
    r.ok(&["undo"]);
    assert_eq!(r.snap("@-").id, base);
    assert_eq!(r.sid("base"), base);
}

// Scenario from git t3509-cherry-pick-merge-df.sh / t3502-cherry-pick-merge.sh: a merge change is duplicated against its own parents' merge.
#[test]
fn a_merge_change_can_be_duplicated() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("base", &[("f", "base\n")]);
    r.tag("base", "@-");
    r.commit("left", &[("l", "left\n")]);
    r.tag("left", "@-");
    r.ok(&["new", "base"]);
    r.commit("right", &[("r", "right\n")]);
    r.tag("right", "@-");
    r.ok(&["new", "left", "right", "-m", "merge"]);
    r.write("m", "made in the merge\n");
    r.ok(&["commit", "--no-advance", "-m", "merge"]);
    r.tag("merge", "@-");
    let out = r.ok(&["duplicate", "merge", "--json"]);
    let v: serde_json::Value = serde_json::from_str(out.lines().find(|l| l.starts_with('{')).unwrap()).unwrap();
    assert_eq!(v["schema"], "veil.duplicate/2");
    let dup = v["duplicates"][0]["duplicate"]["snapshot_id"].as_str().unwrap().to_string();
    let s = r.snap(&dup[..16]);
    assert_eq!(s.parents, r.snap("merge").parents, "beside the source: the same parents");
    assert_eq!(s.tree, r.snap("merge").tree);
    assert_ne!(s.change, r.cid("merge"));
}

// Scenario from git t3503-cherry-pick-root.sh: a change on the root can be copied anywhere; the root itself cannot.
#[test]
fn root_changes_and_the_root() {
    let env = Env::new();
    let r = setup(&env);
    r.ok(&["new", "root"]);
    r.commit("on root", &[("orphan.txt", "orphan\n")]);
    r.tag("orphan", "@-");
    r.ok(&["duplicate", "orphan", "-d", "feature"]);
    let t = r.fails(&["duplicate", "root"]);
    assert!(t.contains("root"), "{t}");
}

// Scenario from git t3505-cherry-pick-empty.sh: picking a change already applied gives an empty copy, not an error.
#[test]
fn picking_a_change_already_applied_is_empty() {
    let env = Env::new();
    let r = setup(&env);
    r.ok(&["edit", "feature"]);
    r.ok(&["new"]);
    r.ok(&["cherry-pick", "feature"]);
    assert_eq!(r.snap("@-").tree, r.snap("feature").tree);
}

// Scenario from git t3507-cherry-pick-conflict.sh: a conflicting pick records a first-class conflict; nothing is refused.
#[test]
fn a_conflicting_pick_records_a_conflict() {
    let env = Env::new();
    let r = setup(&env);
    r.commit("clash", &[("a.txt", &format!("{}clash\n", lines("a", 10)))]);
    let out = r.ok(&["cherry-pick", "feature"]);
    assert!(out.contains("conflicts in: a.txt"), "{out}");
    assert!(r.snap("@-").conflicts.contains(&"a.txt".to_string()));
    let list = r.out(&["resolve", "--list"]);
    assert!(list.contains("a.txt"), "{list}");
    r.ok(&["resolve", "a.txt", "--theirs"]);
    assert!(r.read("a.txt").ends_with("feature\n"));
}

// Scenario from git t3511-cherry-pick-x.sh: `-x` records where the copy came from.
#[test]
fn x_records_the_origin_and_m_replaces_the_description() {
    let env = Env::new();
    let r = setup(&env);
    let src = r.cid("feature");
    r.ok(&["cherry-pick", "-x", "feature"]);
    let d = r.snap("@-").description.unwrap();
    assert!(d.starts_with("feature\n\n(duplicated from change "), "{d}");
    assert!(src.starts_with(d.trim_end_matches(')').rsplit(' ').next().unwrap()));
    r.ok(&["duplicate", "feature", "-m", "a new text"]);
    let t = r.fails(&["duplicate", "feature", "-m", "x", "--keep-description"]);
    assert!(t.contains("cannot be used with"), "{t}");
}

// Scenario from jj test_duplicate_command.rs (duplicate several, onto a destination, keeping their structure) and lib test_rewrite_duplicate.rs.
#[test]
fn duplicate_keeps_the_structure_of_what_it_copies() {
    let env = Env::new();
    let r = env.repo("p");
    r.commit("base", &[("f", "0\n")]);
    r.tag("base", "@-");
    r.commit("a", &[("a", "a\n")]);
    r.tag("a", "@-");
    r.commit("b", &[("b", "b\n")]);
    r.tag("b", "@-");
    r.ok(&["new", "base"]);
    r.commit("other", &[("o", "o\n")]);
    r.tag("other", "@-");
    let before = r.state();
    let out = r.ok(&["duplicate", "b", "a", "-d", "other", "--json"]);
    let v: serde_json::Value = serde_json::from_str(out.lines().find(|l| l.starts_with('{')).unwrap()).unwrap();
    let ids: Vec<String> = v["duplicates"].as_array().unwrap().iter().map(|d| d["duplicate"]["snapshot_id"].as_str().unwrap().to_string()).collect();
    assert_eq!(ids.len(), 2);
    let a2 = r.snap(&ids[0][..16]);
    let b2 = r.snap(&ids[1][..16]);
    assert_eq!(a2.parents, vec![r.sid("other")]);
    assert_eq!(b2.parents, vec![a2.id.clone()], "b's copy sits on a's copy");
    assert_eq!(b2.description.as_deref(), Some("b"));
    // Duplicating onto two parents makes a merge.
    r.ok(&["duplicate", "a", "-d", "other", "-d", "b"]);
    // The JSON lists ids only (no descriptions).
    assert!(v["duplicates"][0].get("description").is_none());
    r.ok(&["undo"]);
    r.ok(&["undo"]);
    assert_eq!(r.state(), before);
}
