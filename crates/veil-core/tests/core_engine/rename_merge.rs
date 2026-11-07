//! Rename-aware merges (`merge.rs`, Git-parity feature 2, stream R): an edit
//! follows a rename made on the other side, rename/delete and
//! rename/rename are first-class conflicts, criss-cross merges follow
//! renames in their virtual base, and the threat review of
//! `docs/design/git-parity/2-renames.md` (points 2–6, 12): pairing never
//! crosses audiences, never reads what the merger cannot, and never
//! widens an audience. The property test runs random renames on one side
//! and edits on the other over public files and files sealed for two
//! scopes, and checks that no content is lost and that no line ever lands
//! in an object readable by a wider audience than it came from.

use crate::adversarial_support;

use std::{collections::BTreeMap, time::Instant};

use adversarial_support::*;
use proptest::prelude::*;
use veil_core::{
    conflict::Merge,
    merge::{merge_trees, RenameMerge, RenameSide},
    object::{EntryKind, Tree, TreeEntry, Visibility},
    tree::walk_files,
    ObjectId, Repo,
};

fn team() -> Visibility {
    Visibility::Cloaked { scope: "team".into() }
}

fn ops() -> Visibility {
    Visibility::Cloaked { scope: "ops".into() }
}

/// A repository whose identity holds `team` (the default scope) and `ops`.
fn repo() -> Repo {
    let (r, _, _) = new_repo("alice");
    r.keys().create_scope("ops").unwrap();
    r
}

/// A file entry holding `data`, sealed as `vis`.
fn fe(r: &Repo, data: &str, vis: &Visibility) -> TreeEntry {
    let id = r.store().store_file(data.as_bytes(), vis).unwrap();
    TreeEntry { size: data.len() as u64, visibility: vis.clone(), ..file("x", id) }
}

/// A tree holding `files` (paths with `/`), directories created as needed.
fn tree(r: &Repo, files: &[(&str, TreeEntry)]) -> ObjectId {
    fn build(r: &Repo, files: &BTreeMap<Vec<String>, TreeEntry>, prefix: &[String]) -> ObjectId {
        let mut t = Tree::default();
        let mut subdirs: BTreeMap<String, ()> = BTreeMap::new();
        for (path, e) in files {
            if path.len() <= prefix.len() || path[..prefix.len()] != *prefix {
                continue;
            }
            let rest = &path[prefix.len()..];
            if rest.len() == 1 {
                t.insert(TreeEntry { name: rest[0].clone(), ..e.clone() });
            } else {
                subdirs.insert(rest[0].clone(), ());
            }
        }
        for d in subdirs.keys() {
            let mut p = prefix.to_vec();
            p.push(d.clone());
            t.insert(TreeEntry::dir(d, build(r, files, &p)));
        }
        r.store().put_tree(&t).unwrap()
    }
    let map: BTreeMap<Vec<String>, TreeEntry> = files.iter().map(|(p, e)| (p.split('/').map(str::to_string).collect(), e.clone())).collect();
    build(r, &map, &[])
}

fn at(r: &Repo, t: &ObjectId, path: &str) -> Option<TreeEntry> {
    veil_core::tree::lookup(r.store(), t, &p(path)).unwrap()
}

fn content(r: &Repo, t: &ObjectId, path: &str) -> String {
    let e = at(r, t, path).unwrap_or_else(|| panic!("{path} missing"));
    assert_eq!(e.kind, EntryKind::File, "{path} is a file");
    String::from_utf8(r.store().read_blob(&e.id).unwrap()).unwrap()
}

fn lines(prefix: &str, n: usize) -> String {
    (0..n).map(|i| format!("{prefix} line {i}\n")).collect()
}

/// `text` with line `i` replaced by `with`.
fn edit_line(text: &str, i: usize, with: &str) -> String {
    text.lines().enumerate().map(|(j, l)| if j == i { format!("{with}\n") } else { format!("{l}\n") }).collect()
}

#[test]
fn an_edit_follows_a_rename_made_on_the_other_side() {
    let r = repo();
    let body = lines("a", 10);
    let base = tree(&r, &[("a.txt", fe(&r, &body, &Visibility::Public))]);
    let renamed = tree(&r, &[("dir/b.txt", fe(&r, &body, &Visibility::Public))]);
    let edited_body = edit_line(&body, 7, "EDITED");
    let edited = tree(&r, &[("a.txt", fe(&r, &edited_body, &Visibility::Public))]);
    for (ours, theirs, side) in [(renamed, edited, RenameSide::Ours), (edited, renamed, RenameSide::Theirs)] {
        let m = merge_trees(r.store(), Some(base), ours, theirs).unwrap();
        assert!(m.conflicts.is_empty(), "{:?}", m.conflicts);
        assert!(at(&r, &m.tree, "a.txt").is_none(), "nothing left at the old name");
        assert_eq!(content(&r, &m.tree, "dir/b.txt"), edited_body);
        assert_eq!(m.renames.len(), 1);
        let f = &m.renames[0];
        assert_eq!((f.from.as_str(), f.to.as_str(), f.side, &f.how, f.score), ("a.txt", "dir/b.txt", side, &RenameMerge::Followed, 100));
        assert!(f.sealed.is_none());
    }
}

#[test]
fn a_renamed_and_edited_file_merges_with_an_edit_of_the_old_name() {
    let r = repo();
    let body = lines("a", 12);
    let base = tree(&r, &[("a.txt", fe(&r, &body, &Visibility::Public))]);
    let ours_body = edit_line(&body, 1, "OURS");
    let theirs_body = edit_line(&body, 10, "THEIRS");
    let ours = tree(&r, &[("b.txt", fe(&r, &ours_body, &Visibility::Public))]);
    let theirs = tree(&r, &[("a.txt", fe(&r, &theirs_body, &Visibility::Public))]);
    let m = merge_trees(r.store(), Some(base), ours, theirs).unwrap();
    assert!(m.conflicts.is_empty(), "{:?}", m.conflicts);
    assert_eq!(content(&r, &m.tree, "b.txt"), edit_line(&ours_body, 10, "THEIRS"));
    assert!(m.renames[0].score < 100);
    // The same edits on the same lines conflict, as a first-class entry at
    // the new name.
    let clash = tree(&r, &[("a.txt", fe(&r, &edit_line(&body, 1, "CLASH"), &Visibility::Public))]);
    let m = merge_trees(r.store(), Some(base), ours, clash).unwrap();
    assert_eq!(m.conflicts, vec![p("b.txt")]);
    assert_eq!(at(&r, &m.tree, "b.txt").unwrap().kind, EntryKind::Conflict);
    assert!(at(&r, &m.tree, "a.txt").is_none());
}

#[test]
fn both_sides_renaming_the_same_way_merge_their_edits_there() {
    let r = repo();
    let body = lines("a", 12);
    let base = tree(&r, &[("a.txt", fe(&r, &body, &Visibility::Public))]);
    let ours = tree(&r, &[("b.txt", fe(&r, &edit_line(&body, 1, "OURS"), &Visibility::Public))]);
    let theirs = tree(&r, &[("b.txt", fe(&r, &edit_line(&body, 10, "THEIRS"), &Visibility::Public))]);
    let m = merge_trees(r.store(), Some(base), ours, theirs).unwrap();
    assert!(m.conflicts.is_empty(), "an add/add would conflict: {:?}", m.conflicts);
    assert_eq!(content(&r, &m.tree, "b.txt"), edit_line(&edit_line(&body, 1, "OURS"), 10, "THEIRS"));
    assert_eq!(m.renames[0].how, RenameMerge::Both);
}

/// The conflict entry at `path`, as (adds, removes) of present-or-not.
fn shape(r: &Repo, t: &ObjectId, path: &str) -> (Vec<bool>, Vec<bool>) {
    let e = at(r, t, path).unwrap();
    assert_eq!(e.kind, EntryKind::Conflict, "{path} is a conflict");
    let m = Merge::of_conflict(r.store().conflict(&e.id).unwrap());
    (m.adds.iter().map(Option::is_some).collect(), m.removes.iter().map(Option::is_some).collect())
}

#[test]
fn rename_delete_is_a_conflict_at_the_new_name() {
    let r = repo();
    let body = lines("a", 10);
    let base = tree(&r, &[("a.txt", fe(&r, &body, &Visibility::Public)), ("keep", fe(&r, "k\n", &Visibility::Public))]);
    let renamed = tree(&r, &[("b.txt", fe(&r, &body, &Visibility::Public)), ("keep", fe(&r, "k\n", &Visibility::Public))]);
    let deleted = tree(&r, &[("keep", fe(&r, "k\n", &Visibility::Public))]);
    let m = merge_trees(r.store(), Some(base), renamed, deleted).unwrap();
    assert_eq!(m.conflicts, vec![p("b.txt")]);
    assert_eq!(shape(&r, &m.tree, "b.txt"), (vec![true, false], vec![true]), "ours renamed, theirs deleted");
    assert_eq!(m.renames[0].how, RenameMerge::RenameDelete);
    let m = merge_trees(r.store(), Some(base), deleted, renamed).unwrap();
    assert_eq!(shape(&r, &m.tree, "b.txt"), (vec![false, true], vec![true]), "ours deleted, theirs renamed");
}

#[test]
fn rename_rename_keeps_both_names_as_conflicts() {
    let r = repo();
    let body = lines("a", 10);
    let base = tree(&r, &[("a.txt", fe(&r, &body, &Visibility::Public))]);
    let ours = tree(&r, &[("b.txt", fe(&r, &body, &Visibility::Public))]);
    let theirs = tree(&r, &[("c.txt", fe(&r, &edit_line(&body, 3, "THEIRS"), &Visibility::Public))]);
    let m = merge_trees(r.store(), Some(base), ours, theirs).unwrap();
    let mut c = m.conflicts.clone();
    c.sort();
    assert_eq!(c, vec![p("b.txt"), p("c.txt")]);
    assert_eq!(shape(&r, &m.tree, "b.txt"), (vec![true, false], vec![true]));
    assert_eq!(shape(&r, &m.tree, "c.txt"), (vec![false, true], vec![true]));
    assert!(at(&r, &m.tree, "a.txt").is_none());
    assert_eq!(m.renames[0].how, RenameMerge::RenameRename { other: p("c.txt") });
}

#[test]
fn a_rename_onto_a_name_the_other_side_took_is_not_followed() {
    let r = repo();
    let body = lines("a", 10);
    let base = tree(&r, &[("a.txt", fe(&r, &body, &Visibility::Public))]);
    let ours = tree(&r, &[("b.txt", fe(&r, &body, &Visibility::Public))]);
    let theirs = tree(&r, &[
        ("a.txt", fe(&r, &edit_line(&body, 3, "THEIRS"), &Visibility::Public)),
        ("b.txt", fe(&r, "their own b\n", &Visibility::Public)),
    ]);
    let m = merge_trees(r.store(), Some(base), ours, theirs).unwrap();
    assert!(m.renames.is_empty(), "rename/add: today's behaviour");
    assert!(m.conflicts.contains(&p("a.txt")), "modify/delete at the old name");
    // A file where the new name needs a directory: not followed either.
    let ours = tree(&r, &[("d/b.txt", fe(&r, &body, &Visibility::Public))]);
    let theirs = tree(&r, &[("a.txt", fe(&r, &edit_line(&body, 3, "THEIRS"), &Visibility::Public)), ("d", fe(&r, "a file\n", &Visibility::Public))]);
    let m = merge_trees(r.store(), Some(base), ours, theirs).unwrap();
    assert!(m.renames.is_empty());
}

/// Threat review 3: a sealed file moved (as sealed content) to a path the
/// policy makes public, edited at its old path on the other side: the
/// merged result stays sealed for its scope at the new path, and says so.
#[test]
fn a_cloaked_file_renamed_to_a_public_path_stays_sealed() {
    let r = repo();
    let body = lines("password", 10);
    let sealed = fe(&r, &body, &ops());
    let base = tree(&r, &[("secrets/db.yml", sealed.clone())]);
    let ours = tree(&r, &[("docs/db.yml", sealed)]);
    let theirs_body = edit_line(&body, 4, "password: rotated-SECRET-XYZ");
    let theirs = tree(&r, &[("secrets/db.yml", fe(&r, &theirs_body, &ops()))]);
    let m = merge_trees(r.store(), Some(base), ours, theirs).unwrap();
    assert!(m.conflicts.is_empty());
    let e = at(&r, &m.tree, "docs/db.yml").unwrap();
    assert_eq!(e.visibility, ops());
    let (vis, data) = versions(&r, &e).remove(0);
    assert_eq!(vis, ops(), "the object itself is sealed for ops");
    assert_eq!(String::from_utf8(data.unwrap()).unwrap(), theirs_body);
    assert_eq!(m.renames[0].sealed, Some(ops()));
    assert!(backend_contains(r.backend().as_ref(), b"rotated-SECRET-XYZ").is_empty(), "no plaintext anywhere");
}

/// Threat review 2 and 4: pairs never cross audiences. A public file and a
/// sealed copy of the same text at a new name are not a rename (the sealed
/// one is not read), so the public edit does not move into the sealed file
/// nor the sealed text into a public one.
#[test]
fn renames_never_pair_across_audiences() {
    let r = repo();
    let body = lines("cfg", 10);
    let base = tree(&r, &[("config.yml", fe(&r, &body, &Visibility::Public))]);
    // Ours moved it under a cloaked directory: re-sealed for team.
    let ours = tree(&r, &[("secrets/config.yml", fe(&r, &body, &team()))]);
    let theirs = tree(&r, &[("config.yml", fe(&r, &edit_line(&body, 2, "PUBLIC EDIT"), &Visibility::Public))]);
    let m = merge_trees(r.store(), Some(base), ours, theirs).unwrap();
    assert!(m.renames.is_empty());
    assert_eq!(at(&r, &m.tree, "secrets/config.yml").unwrap().visibility, team());
    assert!(m.conflicts.contains(&p("config.yml")), "modify/delete, as before");
    // The reverse: a sealed file published at a new name by ours (an
    // explicit exposure there), edited sealed by theirs: not paired, so
    // theirs' sealed edit never lands in the public file.
    let secret = lines("token", 10);
    let base = tree(&r, &[("secrets/k", fe(&r, &secret, &team()))]);
    let ours = tree(&r, &[("public/k", fe(&r, &secret, &Visibility::Public))]);
    let theirs = tree(&r, &[("secrets/k", fe(&r, &edit_line(&secret, 1, "SEALED-EDIT-QQQ"), &team()))]);
    let m = merge_trees(r.store(), Some(base), ours, theirs).unwrap();
    assert!(m.renames.is_empty());
    let pubk = at(&r, &m.tree, "public/k").unwrap();
    assert_eq!(pubk.visibility, Visibility::Public);
    assert!(!r.store().read_blob(&pubk.id).unwrap().windows(15).any(|w| w == b"SEALED-EDIT-QQQ"));
    // Two scopes: an exact object id but a label forged to another scope
    // is paired on what the object really is, never on the label.
    let s = fe(&r, &secret, &team());
    let forged = TreeEntry { visibility: ops(), ..s.clone() };
    let base = tree(&r, &[("a", s.clone())]);
    let ours = tree(&r, &[("b", forged)]);
    let theirs = tree(&r, &[("a", fe(&r, &edit_line(&secret, 1, "TEAM-EDIT"), &team()))]);
    let m = merge_trees(r.store(), Some(base), ours, theirs).unwrap();
    let b = at(&r, &m.tree, "b").unwrap();
    let (vis, _) = versions(&r, &b).remove(0);
    assert_eq!(vis, team(), "the edit stays sealed for team, whatever the label claims");
}

/// Threat review 5: a merger without the key merges an exact rename of a
/// sealed file and a sealed edit: no content is read (the result is the
/// edited object itself), and nothing fails.
#[test]
fn a_non_member_follows_sealed_renames_without_reading_them() {
    let (alice, _, _) = new_repo("alice");
    let body = lines("password", 10);
    let sealed = fe(&alice, &body, &team());
    let edited = fe(&alice, &edit_line(&body, 3, "NEW"), &team());
    // Bob's store: the same objects, none of the keys.
    let (bob, _, _) = new_repo("bob");
    for e in [&sealed, &edited] {
        let raw = alice.store().get_raw(&e.id).unwrap();
        plant_raw_object(bob.backend().as_ref(), &e.id, &raw);
    }
    assert!(bob.store().read_blob(&sealed.id).is_err(), "bob cannot read it");
    let base = tree(&bob, &[("secrets/a", sealed.clone())]);
    let ours = tree(&bob, &[("secrets/b", sealed.clone())]);
    let theirs = tree(&bob, &[("secrets/a", edited.clone())]);
    let m = merge_trees(bob.store(), Some(base), ours, theirs).unwrap();
    assert!(m.conflicts.is_empty());
    assert_eq!(at(&bob, &m.tree, "secrets/b").unwrap().id, edited.id, "the edited object, unread");
    assert_eq!(m.renames[0].how, RenameMerge::Followed);
}

/// Threat review 6: past the detection limits the merge does what it did
/// before (exact pairs still count; inexact ones are not looked for).
#[test]
fn over_the_limit_inexact_renames_fall_back_to_modify_delete() {
    let r = repo();
    let n = 1001; // 1001² > 1000² candidate pairs
    let mut base = Vec::new();
    let mut ours = Vec::new();
    for i in 0..n {
        let body = lines(&format!("f{i}"), 4);
        base.push((format!("old/{i}"), fe(&r, &body, &Visibility::Public)));
        ours.push((format!("new/{i}"), fe(&r, &edit_line(&body, 0, &format!("moved {i}")), &Visibility::Public)));
    }
    let body0 = lines("f0", 4);
    let mut theirs = base.clone();
    theirs[0].1 = fe(&r, &edit_line(&body0, 3, "THEIRS"), &Visibility::Public);
    let refs = |v: &Vec<(String, TreeEntry)>| -> Vec<(String, TreeEntry)> { v.clone() };
    let mk = |v: Vec<(String, TreeEntry)>| {
        let v: Vec<(&str, TreeEntry)> = v.iter().map(|(a, b)| (a.as_str(), b.clone())).collect();
        tree(&r, &v)
    };
    let (b, o, t) = (mk(refs(&base)), mk(refs(&ours)), mk(refs(&theirs)));
    let start = Instant::now();
    let m = merge_trees(r.store(), Some(b), o, t).unwrap();
    let took = start.elapsed();
    assert!(m.renames.is_empty());
    assert_eq!(m.conflicts, vec![p("old")], "modify/delete (of the directory ours deleted), as before");
    eprintln!("over-limit merge of {n} renames: {took:?}");
    // Within the limit the same shape is followed.
    let small_base = mk(base[..20].to_vec());
    let small_ours = mk(ours[..20].to_vec());
    let mut st = base[..20].to_vec();
    st[0].1 = theirs[0].1.clone();
    let m = merge_trees(r.store(), Some(small_base), small_ours, mk(st)).unwrap();
    assert!(m.conflicts.is_empty(), "{:?}", m.conflicts);
    assert_eq!(content(&r, &m.tree, "new/0"), edit_line(&edit_line(&body0, 0, "moved 0"), 3, "THEIRS"));
}

/// Criss-cross plus renames: two merges of the same rename and edit, each
/// then edited again. The virtual merge base follows the rename too, so
/// the final merge is clean.
#[test]
fn criss_cross_merges_follow_renames_in_the_virtual_base() {
    let r = repo();
    let body = lines("x", 20);
    let root = r.root_id();
    let t0 = tree(&r, &[("a.txt", fe(&r, &body, &Visibility::Public))]);
    let s0 = raw_snapshot(&r, vec![root], t0, "base");
    let tx = tree(&r, &[("b.txt", fe(&r, &body, &Visibility::Public))]);
    let x = raw_snapshot(&r, vec![s0], tx, "rename");
    let y_body = edit_line(&body, 10, "Y");
    let ty = tree(&r, &[("a.txt", fe(&r, &y_body, &Visibility::Public))]);
    let y = raw_snapshot(&r, vec![s0], ty, "edit");
    let merged = merge_trees(r.store(), Some(t0), tx, ty).unwrap();
    assert!(merged.conflicts.is_empty());
    let m1 = raw_snapshot(&r, vec![x, y], merged.tree, "m1");
    let m2 = raw_snapshot(&r, vec![y, x], merged.tree, "m2");
    let left = edit_line(&y_body, 1, "LEFT");
    let right = edit_line(&y_body, 18, "RIGHT");
    let l = raw_snapshot(&r, vec![m1], tree(&r, &[("b.txt", fe(&r, &left, &Visibility::Public))]), "left");
    let rt = raw_snapshot(&r, vec![m2], tree(&r, &[("b.txt", fe(&r, &right, &Visibility::Public))]), "right");
    assert_eq!(r.merge_bases(&[l], &[rt]).unwrap().len(), 2, "a criss-cross");
    let out = r.parents_tree(&[l, rt]).unwrap();
    assert!(out.conflicts.is_empty(), "{:?}", out.conflicts);
    assert_eq!(content(&r, &out.tree, "b.txt"), edit_line(&left, 18, "RIGHT"));
    assert!(at(&r, &out.tree, "a.txt").is_none());
}

/// Threat review 12: rebasing a change onto its own parent is still a no-op.
#[test]
fn rebasing_onto_the_same_parents_changes_nothing() {
    let (mut r, fs, _) = new_repo("alice");
    let base = commit_files(&mut r, &*fs, &[("a.txt", &lines("a", 5))], "base");
    let c = commit_files(&mut r, &*fs, &[("b.txt", "b\n")], "c");
    let before = r.op_id();
    assert_eq!(r.rebase(c, vec![base]).unwrap(), c);
    assert_eq!(r.op_id(), before);
}

// ---- property ------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Aud {
    Public,
    Team,
    Ops,
}

impl Aud {
    fn vis(self) -> Visibility {
        match self {
            Aud::Public => Visibility::Public,
            Aud::Team => team(),
            Aud::Ops => ops(),
        }
    }

    fn tag(self) -> &'static str {
        match self {
            Aud::Public => "pub",
            Aud::Team => "team",
            Aud::Ops => "ops",
        }
    }

    /// May a line from `self` be in an object readable by `v`?
    fn fits(self, v: &Visibility) -> bool {
        match v {
            Visibility::Public => self == Aud::Public,
            v => self == Aud::Public || self.vis() == *v,
        }
    }
}

/// What one side does to one file.
#[derive(Debug, Clone, Copy)]
enum Op {
    Keep,
    /// Replace one line (side A edits near the top, side B near the end).
    Edit,
    Delete,
    /// Move to a new name (`renamed/<i>` or `moved/x/<i>`), with or without
    /// an edit.
    Rename { edit: bool, deep: bool },
    /// Move and re-seal for another audience (a different object: never a
    /// rename).
    Reseal { to: Aud },
}

fn arb_aud() -> impl Strategy<Value = Aud> {
    prop_oneof![Just(Aud::Public), Just(Aud::Team), Just(Aud::Ops)]
}

fn arb_op() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => Just(Op::Keep),
        3 => Just(Op::Edit),
        1 => Just(Op::Delete),
        3 => (any::<bool>(), any::<bool>()).prop_map(|(edit, deep)| Op::Rename { edit, deep }),
        1 => arb_aud().prop_map(|to| Op::Reseal { to }),
    ]
}

/// Lines of file `i` (each names its audience, so a line in the wrong
/// object is recognised).
fn base_body(i: usize, a: Aud) -> String {
    (0..10).map(|l| format!("{}:f{i}:l{l}\n", a.tag())).collect()
}

/// A side's files (path, entry) and the tokens it wrote (with their
/// audience).
type Side = (Vec<(String, TreeEntry)>, Vec<(String, Aud)>);

/// Apply one side's ops; returns the tree and the tokens it introduced
/// with their audience.
fn side(r: &Repo, files: &[Aud], ops: &[Op], who: &str, line: usize) -> Side {
    let mut out = Vec::new();
    let mut tokens = Vec::new();
    for (i, (a, op)) in files.iter().zip(ops).enumerate() {
        let body = base_body(i, *a);
        let edited = |aud: Aud, tokens: &mut Vec<(String, Aud)>| {
            let tok = format!("{}:TOK-{who}-{i}", aud.tag());
            tokens.push((tok.clone(), aud));
            edit_line(&body, line, &tok)
        };
        match op {
            Op::Keep => out.push((format!("f/{i}"), fe(r, &body, &a.vis()))),
            Op::Edit => {
                let b = edited(*a, &mut tokens);
                out.push((format!("f/{i}"), fe(r, &b, &a.vis())))
            }
            Op::Delete => {}
            Op::Rename { edit, deep } => {
                let b = if *edit { edited(*a, &mut tokens) } else { body.clone() };
                let to = if *deep { format!("moved/{who}/{i}") } else { format!("renamed-{who}-{i}") };
                out.push((to, fe(r, &b, &a.vis())))
            }
            // Public content moved and sealed for a scope (a narrower
            // audience; a scope's content is never re-sealed for another).
            Op::Reseal { to } if *a == Aud::Public => {
                let to = if *to == Aud::Public { Aud::Team } else { *to };
                out.push((format!("resealed-{who}/{i}"), fe(r, &body, &to.vis())))
            }
            Op::Reseal { .. } => out.push((format!("f/{i}"), fe(r, &body, &a.vis()))),
        }
    }
    (out, tokens)
}

/// Every version stored in the result: (verified audience, content).
fn leaves(r: &Repo, t: &ObjectId) -> Vec<(String, Visibility, String)> {
    let mut out = Vec::new();
    for (path, e) in walk_files(r.store(), t).unwrap() {
        for (vis, data) in versions(r, &e) {
            let data = data.expect("the test holds every key");
            out.push((path.to_string(), vis, String::from_utf8(data).unwrap()));
        }
    }
    out
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, ..ProptestConfig::default() })]

    /// Random renames on one side and edits on the other (and some of
    /// everything on both): no token either side wrote is lost, and no line
    /// is ever in an object readable by a wider audience than the one it
    /// was written for (or moved between scopes).
    #[test]
    fn renames_lose_nothing_and_widen_no_audience(
        files in proptest::collection::vec(arb_aud(), 1..6),
        a_ops in proptest::collection::vec(arb_op(), 6),
        b_ops in proptest::collection::vec(arb_op(), 6),
        swap in any::<bool>(),
    ) {
        let r = repo();
        let n = files.len();
        let base: Vec<(String, TreeEntry)> = files.iter().enumerate().map(|(i, a)| (format!("f/{i}"), fe(&r, &base_body(i, *a), &a.vis()))).collect();
        let (a, ta) = side(&r, &files, &a_ops[..n], "A", 1);
        let (b, tb) = side(&r, &files, &b_ops[..n], "B", 8);
        let mk = |v: &[(String, TreeEntry)]| {
            let v: Vec<(&str, TreeEntry)> = v.iter().map(|(x, e)| (x.as_str(), e.clone())).collect();
            tree(&r, &v)
        };
        let (bt, at_, bt2) = (mk(&base), mk(&a), mk(&b));
        let (ours, theirs) = if swap { (bt2, at_) } else { (at_, bt2) };
        let m = merge_trees(r.store(), Some(bt), ours, theirs).unwrap();
        let got = leaves(&r, &m.tree);
        for (tok, _) in ta.iter().chain(&tb) {
            prop_assert!(got.iter().any(|(_, _, c)| c.contains(tok.as_str())), "token {tok} lost: {got:?}");
        }
        for (path, vis, c) in &got {
            for l in c.lines() {
                let aud = match l.split(':').next() {
                    Some("pub") => Aud::Public,
                    Some("team") => Aud::Team,
                    Some("ops") => Aud::Ops,
                    _ => continue,
                };
                prop_assert!(aud.fits(vis), "{path} ({vis:?}) holds `{l}`");
            }
        }
        // Every followed rename is between versions of one audience.
        for f in &m.renames {
            let i: usize = f.from.as_str().trim_start_matches("f/").parse().unwrap();
            if let Some(e) = at(&r, &m.tree, f.to.as_str()).filter(|e| e.kind == EntryKind::File) {
                let (vis, _) = versions(&r, &e).remove(0);
                prop_assert!(files[i].fits(&vis), "{f:?} → {vis:?}");
            }
        }
    }
}

/// Threat review 9: a conflict entry is renamed only as the very same
/// conflict object; the other side's resolution then follows it.
#[test]
fn conflict_entries_pair_only_by_their_own_id() {
    let r = repo();
    let body = lines("a", 10);
    let (b, o, t) = (
        tree(&r, &[("f", fe(&r, &body, &Visibility::Public))]),
        tree(&r, &[("f", fe(&r, &edit_line(&body, 1, "O"), &Visibility::Public))]),
        tree(&r, &[("f", fe(&r, &edit_line(&body, 1, "T"), &Visibility::Public))]),
    );
    let c = merge_trees(r.store(), Some(b), o, t).unwrap();
    let ce = at(&r, &c.tree, "f").unwrap();
    assert_eq!(ce.kind, EntryKind::Conflict);
    let base = tree(&r, &[("f", ce.clone())]);
    let renamed = tree(&r, &[("g", ce.clone())]);
    let resolved_body = edit_line(&body, 1, "RESOLVED");
    let resolved = tree(&r, &[("f", fe(&r, &resolved_body, &Visibility::Public))]);
    let m = merge_trees(r.store(), Some(base), renamed, resolved).unwrap();
    assert!(m.conflicts.is_empty(), "{:?}", m.conflicts);
    assert_eq!(content(&r, &m.tree, "g"), resolved_body, "the resolution followed the renamed conflict");
    // A file with the conflict's rendered text is not its rename.
    let rendered = veil_core::conflict::read_file_like(r.store(), &ce).unwrap();
    let as_file = tree(&r, &[("g", fe(&r, std::str::from_utf8(&rendered).unwrap(), &Visibility::Public))]);
    let m = merge_trees(r.store(), Some(base), as_file, resolved).unwrap();
    assert!(m.renames.is_empty());
}
