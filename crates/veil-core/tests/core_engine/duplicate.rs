//! `Repo::duplicate` and `Repo::cherry_pick` (`duplicate.rs`, Git-parity
//! feature 1, stream R) and the threat review of
//! `docs/design/git-parity/1-blame-bisect-duplicate.md`, points 11–16:
//! embargo-withheld sources stay inside their embargo, sealed secret files
//! stay sealed on a public line, conflicts keep their versions' audiences,
//! provenance is never spoofed, and `undo` takes a copy back exactly.

use crate::adversarial_support;

use std::sync::Arc;

use adversarial_support::*;
use proptest::prelude::*;
use veil_core::{
    commands::EmbargoSpec,
    conflict::Merge,
    duplicate::DuplicateOptions,
    object::Visibility,
    remote,
    EntryKind, MemoryBackend, ObjectId, Repo, StorageBackend,
};

fn team() -> Visibility {
    Visibility::Cloaked { scope: "team".into() }
}

fn keep() -> DuplicateOptions {
    DuplicateOptions::default()
}

fn tree_of(r: &Repo, id: &ObjectId) -> ObjectId {
    r.snapshot(id).unwrap().tree
}

fn lines(prefix: &str, n: usize) -> String {
    (0..n).map(|i| format!("{prefix} {i}\n")).collect()
}

fn read(r: &Repo, id: &ObjectId, path: &str) -> String {
    String::from_utf8(read_at(r, id, path)).unwrap()
}

/// `main` (a.txt, b.txt) with two children: `feature` edits a.txt, `other`
/// edits b.txt.
fn world() -> (Repo, Arc<MemoryBackend>, ObjectId, ObjectId, ObjectId) {
    let (mut r, fs, _) = new_repo("alice");
    let main = commit_files(&mut r, &*fs, &[("a.txt", &lines("a", 10)), ("b.txt", &lines("b", 10))], "main");
    let feature = commit_files(&mut r, &*fs, &[("a.txt", &format!("{}feature\n", lines("a", 10)))], "feature");
    r.new_change(WS, vec![main], "").unwrap();
    let ws = r.workspace_overlay(WS).unwrap();
    let _ = ws;
    fs.write(&p("b.txt"), format!("other\n{}", lines("b", 10)).as_bytes()).unwrap();
    // The working copy on disk still holds feature's a.txt: put main's back.
    fs.write(&p("a.txt"), lines("a", 10).as_bytes()).unwrap();
    snap(&mut r, &*fs);
    let other = r.commit_working_copy(WS, "other").unwrap().0;
    (r, fs, main, feature, other)
}

#[test]
fn a_duplicate_is_a_new_change_with_the_same_diff_on_new_parents() {
    let (mut r, _fs, main, feature, other) = world();
    let src = r.snapshot(&feature).unwrap();
    let before = r.view().clone();
    let done = r.duplicate(&[feature], &[other], &keep()).unwrap();
    assert_eq!(done.len(), 1);
    let d = r.snapshot(&done[0].duplicate).unwrap();
    assert_eq!(d.parents, vec![other]);
    assert_ne!(d.change_id, src.change_id, "a new change id");
    assert_eq!(d.author, src.author);
    assert!(d.predecessors.is_empty(), "a new change, not a rewrite");
    assert_eq!(r.description(&d), "feature");
    assert_eq!(read(&r, &done[0].duplicate, "a.txt"), format!("{}feature\n", lines("a", 10)));
    assert_eq!(read(&r, &done[0].duplicate, "b.txt"), format!("other\n{}", lines("b", 10)));
    // The source is untouched, and still visible.
    assert_eq!(r.snapshot(&feature).unwrap().tree, src.tree);
    assert!(r.view().heads.contains(&feature));
    // Threat review 16: one operation; undo restores the view exactly.
    r.undo().unwrap();
    assert_eq!(r.view().heads, before.heads);
    assert_eq!(r.view().tags, before.tags);
    assert_eq!(r.view().workspaces, before.workspaces);
    let _ = main;
}

#[test]
fn without_a_destination_the_copy_sits_beside_the_source() {
    let (mut r, _fs, main, feature, _) = world();
    let done = r.duplicate(&[feature], &[], &keep()).unwrap();
    let d = r.snapshot(&done[0].duplicate).unwrap();
    assert_eq!(d.parents, vec![main]);
    assert_eq!(d.tree, tree_of(&r, &feature), "the same tree");
}

#[test]
fn a_chain_is_copied_as_a_chain_and_one_undo_takes_it_all_back() {
    let (mut r, fs, _main, feature, other) = world();
    // feature → f2 (a chain).
    r.edit(WS, feature).unwrap();
    let _ = fs;
    let f2 = r.new_change(WS, vec![feature], "f2").unwrap();
    let c3 = r.new_change(WS, vec![f2], "").unwrap();
    let _ = c3;
    let before = r.view().clone();
    let done = r.duplicate(&[f2, feature], &[other], &keep()).unwrap();
    assert_eq!(done.len(), 2);
    assert_eq!(done[0].source, feature, "parents first, whatever the order given");
    let d1 = r.snapshot(&done[0].duplicate).unwrap();
    let d2 = r.snapshot(&done[1].duplicate).unwrap();
    assert_eq!(d1.parents, vec![other]);
    assert_eq!(d2.parents, vec![done[0].duplicate], "the child goes onto its parent's copy");
    let ops_before = r.op_log(100).unwrap().len();
    r.undo().unwrap();
    assert_eq!(r.view().heads, before.heads);
    assert_eq!(r.op_log(100).unwrap().len(), ops_before + 1, "one operation was undone by one");
}

#[test]
fn record_origin_appends_to_plain_descriptions_only() {
    let (mut r, _fs, _main, feature, other) = world();
    let o = DuplicateOptions { record_origin: true, ..keep() };
    let done = r.duplicate(&[feature], &[other], &o).unwrap();
    let d = r.snapshot(&done[0].duplicate).unwrap();
    let cid = r.snapshot(&feature).unwrap().change_id.short();
    assert_eq!(r.description(&d), format!("feature\n\n(duplicated from change {cid})"));
    let m = DuplicateOptions { message: Some("new words".into()), ..keep() };
    let done = r.duplicate(&[feature], &[other], &m).unwrap();
    assert_eq!(r.description(&r.snapshot(&done[0].duplicate).unwrap()), "new words");
    let bad = DuplicateOptions { message: Some("nul\0".into()), ..keep() };
    assert!(r.duplicate(&[feature], &[other], &bad).is_err());
    assert!(r.duplicate(&[r.root_id()], &[other], &keep()).is_err(), "the root is not a change to copy");
}

/// Threat review 15: the author is copied (a claim); the duplicate is
/// signed by whoever made it, never presented as the original signer's.
#[test]
fn the_duplicate_is_signed_by_the_duplicator() {
    let (mut r, _fs, main, _, other) = world();
    let mine = r.snapshot(&other).unwrap().signature.clone().expect("alice signs her commits");
    let tree = tree_of(&r, &main);
    let theirs = raw_snapshot(&r, vec![main], tree, "mallory's unsigned change");
    let mut tx = r.transaction("plant").unwrap();
    tx.add_head(theirs).unwrap();
    tx.commit().unwrap();
    let done = r.duplicate(&[theirs], &[other], &keep()).unwrap();
    let d = r.snapshot(&done[0].duplicate).unwrap();
    assert_eq!(d.author, "mallory", "the author is the source's claim");
    let sig = d.signature.clone().expect("signed");
    assert_eq!((sig.signer.as_str(), sig.key.as_str()), (mine.signer.as_str(), mine.key.as_str()), "signed by alice, who copied it");
}

/// Threat review 14: a conflict is copied as recorded; each version keeps
/// its own audience.
#[test]
fn a_conflict_is_copied_with_its_versions_audiences() {
    let (mut r, fs, _) = new_repo("alice");
    let base = commit_files(&mut r, &*fs, &[("f.txt", "base\n")], "base");
    let left = commit_files(&mut r, &*fs, &[("f.txt", "left\n")], "left");
    // A version sealed for `team` (as a secret file's is), stored as is.
    let store = r.store();
    let mut root = (*store.tree(&tree_of(&r, &base)).unwrap()).clone();
    let mut e = root.get("f.txt").unwrap().clone();
    e.id = store.store_file(b"right sealed\n", &team()).unwrap();
    e.size = "right sealed\n".len() as u64;
    e.visibility = team();
    root.insert(e);
    let right = raw_snapshot(&r, vec![base], store.put_tree(&root).unwrap(), "right");
    let m = r.merge(WS, left, vec![right], "merge", None).unwrap();
    let ce = file_entry(&r, &m.snapshot, "f.txt").unwrap();
    assert_eq!(ce.kind, EntryKind::Conflict);
    let onto = commit_files(&mut r, &*fs, &[("g.txt", "g\n")], "elsewhere");
    let _ = onto;
    let done = r.duplicate(&[m.snapshot], &[], &keep()).unwrap();
    let de = file_entry(&r, &done[0].duplicate, "f.txt").unwrap();
    assert_eq!(de.kind, EntryKind::Conflict);
    let terms: Vec<Visibility> = Merge::of_conflict(r.store().conflict(&de.id).unwrap())
        .adds
        .iter()
        .flatten()
        .map(|t| t.visibility.clone())
        .collect();
    assert!(terms.contains(&team()) && terms.contains(&Visibility::Public), "{terms:?}");
    assert!(r.snapshot(&done[0].duplicate).unwrap().conflicts.contains(&"f.txt".to_string()));
}

/// An embargoed fix: main, a fix line of two changes (`fix1`, `fix2`),
/// merged into main under an unreleased embargo.
fn embargoed() -> (Repo, Arc<MemoryBackend>, ObjectId, ObjectId, ObjectId, ObjectId) {
    let (mut r, fs, _) = new_repo("alice");
    let main = commit_files(&mut r, &*fs, &[("a.c", &lines("vuln", 10))], "v1");
    r.set_tag("main", main, false).unwrap();
    r.create_workspace("fix", vec![main]).unwrap();
    let o = r.workspace_overlay("fix").unwrap();
    o.write(&p("FIXFILE-secret-name.c"), b"the fix, part one\n").unwrap();
    r.snapshot_workspace("fix", &o).unwrap();
    let fix1 = r.commit("fix", "fix part one", false).unwrap().committed;
    let o = r.workspace_overlay("fix").unwrap();
    o.write(&p("a.c"), format!("{}patched\n", lines("vuln", 10)).as_bytes()).unwrap();
    r.snapshot_workspace("fix", &o).unwrap();
    let fix2 = r.commit("fix", "fix part two", false).unwrap().committed;
    let m = r.merge(WS, main, vec![fix2], "embargoed fix", Some(EmbargoSpec { scope: "team".into(), until: None })).unwrap();
    (r, fs, main, fix1, fix2, m.snapshot)
}

/// Threat review 11: a source an unreleased embargo withholds is never
/// copied out of the embargo (its file names would reach a public push);
/// inside the embargo it may be.
#[test]
fn embargo_withheld_changes_stay_inside_their_embargo() {
    let (mut r, _fs, main, fix1, fix2, merge) = embargoed();
    let before = r.op_id();
    let err = r.duplicate(&[fix2], &[main], &keep()).unwrap_err().to_string();
    assert!(err.contains("withholds"), "{err}");
    let err = r.duplicate(&[fix1, fix2], &[main], &keep()).unwrap_err().to_string();
    assert!(err.contains("withholds"), "{err}");
    let err = r.duplicate(&[merge], &[main], &keep()).unwrap_err().to_string();
    assert!(err.contains("unreleased embargo"), "{err}");
    assert_eq!(r.op_id(), before, "nothing recorded");
    // Cherry-picking it onto the public line is the same copy.
    r.new_change(WS, vec![main], "").unwrap();
    let before = r.op_id();
    assert!(r.cherry_pick(WS, &[fix2], &keep()).is_err());
    assert_eq!(r.op_id(), before);
    // Inside the embargo: onto another withheld change.
    let done = r.duplicate(&[fix2], &[fix1], &keep()).unwrap();
    assert_eq!(r.snapshot(&done[0].duplicate).unwrap().parents, vec![fix1]);
    // A public push carries none of the fix's names.
    let mirror = Arc::new(MemoryBackend::new());
    remote::push(&mut r, mirror.clone(), true, &[], false).unwrap();
    assert!(backend_contains(mirror.as_ref(), b"FIXFILE-secret-name").is_empty());
}

#[test]
fn cherry_pick_copies_onto_the_parent_and_moves_the_working_copy_and_tags() {
    let (mut r, fs, main, feature, _) = world();
    r.set_tag("main", main, false).unwrap();
    r.new_change(WS, vec![main], "").unwrap();
    fs.write(&p("a.txt"), lines("a", 10).as_bytes()).unwrap();
    fs.write(&p("b.txt"), lines("b", 10).as_bytes()).unwrap();
    fs.write(&p("wip.txt"), b"uncommitted\n").unwrap();
    snap(&mut r, &*fs);
    let wc_before = r.workspace_wc(WS).unwrap();
    let wc_change = r.snapshot(&wc_before).unwrap().change_id;
    let before = r.view().clone();
    let res = r.cherry_pick(WS, &[feature], &keep()).unwrap();
    let d = res.duplicates[0].duplicate;
    assert_eq!(r.snapshot(&d).unwrap().parents, vec![main]);
    let wc = r.workspace_wc(WS).unwrap();
    assert_eq!(wc, res.wc);
    let ws = r.snapshot(&wc).unwrap();
    assert_eq!(ws.parents, vec![d], "@ moved on top of the copy");
    assert_eq!(ws.change_id, wc_change, "the same change");
    assert_eq!(read(&r, &wc, "wip.txt"), "uncommitted\n", "uncommitted work kept");
    assert_eq!(read(&r, &wc, "a.txt"), format!("{}feature\n", lines("a", 10)));
    assert_eq!(res.advanced, vec!["main".to_string()]);
    assert_eq!(r.view().tags["main"].target, d);
    r.undo().unwrap();
    assert_eq!(r.view().heads, before.heads);
    assert_eq!(r.view().tags, before.tags);
    assert_eq!(r.view().workspaces, before.workspaces);
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 16, ..ProptestConfig::default() })]

    /// Threat review 12 (property): random edits of sealed secret files
    /// duplicated onto public lines and pushed to a public mirror; the
    /// mirror never holds any of their text.
    #[test]
    fn cloaked_copies_never_reach_a_public_mirror(
        edits in proptest::collection::vec((0usize..4, any::<bool>()), 1..5),
        in_place in any::<bool>(),
    ) {
        let (mut r, fs, _) = new_repo("alice");
        let names = [".env.a", ".env.b", "dir/.env.c", ".env.d"];
        let mut files: Vec<(&str, String)> = names.iter().map(|n| (*n, lines(n, 6))).collect();
        files.push((".veilpolicy", ".env.* cloak team\n".into()));
        let refs: Vec<(&str, &str)> = files.iter().map(|(n, b)| (*n, b.as_str())).collect();
        let main = commit_files(&mut r, &*fs, &refs, "main");
        prop_assert!(names.iter().all(|n| !file_entry(&r, &main, n).unwrap().visibility.is_public()));
        r.set_tag("main", main, false).unwrap();
        r.create_workspace("t", vec![main]).unwrap();
        let mut sources = Vec::new();
        for (k, (i, delete)) in edits.iter().enumerate() {
            let o = r.workspace_overlay("t").unwrap();
            let path = p(names[*i]);
            if *delete && k % 2 == 1 {
                let _ = o.remove_file(&path);
            } else {
                o.write(&path, format!("SECRET-PROP-{k}\n{}", lines(names[*i], 6)).as_bytes()).unwrap();
            }
            r.snapshot_workspace("t", &o).unwrap();
            sources.push(r.commit("t", &format!("edit {k}"), false).unwrap().committed);
        }
        let dest: Vec<ObjectId> = if in_place { vec![] } else { vec![main] };
        let done = r.duplicate(&sources, &dest, &keep()).unwrap();
        let tip = done.last().unwrap().duplicate;
        r.set_tag("main", tip, true).unwrap();
        let mirror = Arc::new(MemoryBackend::new());
        remote::push(&mut r, mirror.clone(), true, &[], false).unwrap();
        prop_assert!(backend_contains(mirror.as_ref(), b"SECRET-PROP").is_empty());
        let m = Repo::open(mirror, None, "carol").unwrap();
        prop_assert!(m.exact().snapshot(&tip).unwrap().is_some(), "the copies were pushed");
    }
}
