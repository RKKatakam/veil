//! Audiences across merges (BUG-123, BUG-126, BUG-127).
//!
//! * When the two sides of a file are sealed for different scopes, the
//!   merge never moves either side's content to the other audience
//!   (BUG-123).
//! * Conflict markers show the merge base's version only to the base's own
//!   audience (BUG-126).
//! * A criss-cross merge's virtual base never stores a sealed ancestor's
//!   text for a wider audience (BUG-127).

use crate::adversarial_support;

use std::sync::Arc;

use adversarial_support::*;
use veil_core::{
    object::Visibility,
    MemoryBackend, ObjectId, Repo, StorageBackend, TreeEntry,
};

fn team() -> Visibility {
    Visibility::Cloaked {
        scope: "team".into(),
    }
}

// ---- BUG-123 -------------------------------------------------------------

const OLD: &str = "password: old-team-secret\n";
const MINE: &str = "password: ALICE-ROTATED-4417\n";
const THEIRS: &str = "password: from-the-mal-scope\n";

/// `main` with `secrets/.env.db` cloaked under `team`; Alice is also a
/// member of `mal`. Returns the repo, its working copy and `main`.
fn two_scopes() -> (Repo, Arc<MemoryBackend>, ObjectId) {
    let (mut alice, fs, _) = new_repo("alice");
    alice.keys().create_scope("mal").unwrap();
    fs.write(&p(".veilpolicy"), b"secrets/ cloak team\n")
        .unwrap();
    let main = commit_files(
        &mut alice,
        &*fs,
        &[("secrets/.env.db", OLD), ("README", "hi\n")],
        "v1",
    );
    alice.set_tag("main", main, false).unwrap();
    (alice, fs, main)
}

/// `main` moved on by someone who replaced `secrets/.env.db` with a genuine
/// `mal`-sealed object.
fn mal_main(alice: &Repo, main: ObjectId) -> ObjectId {
    let store = alice.store();
    let mal = Visibility::Cloaked {
        scope: "mal".into(),
    };
    let mut root = (*store.tree(&alice.snapshot(&main).unwrap().tree).unwrap()).clone();
    let mut secrets = (*store.tree(&root.get("secrets").unwrap().id).unwrap()).clone();
    let mut e = secrets.get(".env.db").unwrap().clone();
    e.id = store.store_file(THEIRS.as_bytes(), &mal).unwrap();
    e.size = THEIRS.len() as u64;
    e.visibility = mal;
    secrets.insert(e);
    root.insert(TreeEntry::dir("secrets", store.put_tree(&secrets).unwrap()));
    raw_snapshot(alice, vec![main], store.put_tree(&root).unwrap(), "rotate")
}

/// Every version at `secrets/.env.db` holding Alice's edit is sealed for
/// `team` (a conflict keeps each version as it was).
fn assert_mine_stays_team(alice: &Repo, rev: &ObjectId) {
    let e = file_entry(alice, rev, "secrets/.env.db").unwrap();
    for (vis, data) in versions(alice, &e) {
        if data.is_some_and(|d| String::from_utf8_lossy(&d).contains("ALICE-ROTATED")) {
            assert_eq!(vis, team(), "Alice's edit moved to {}", vis.label());
        }
    }
}

/// The reported route: Alice's pending `team` edit, auto-rebased onto a
/// `main` whose file is sealed under `mal`, is never resealed under `mal`.
#[test]
fn a_rebase_never_moves_a_pending_edit_to_another_scope() {
    let (mut alice, fs, main) = two_scopes();
    fs.write(&p("secrets/.env.db"), MINE.as_bytes()).unwrap();
    let wc = snap(&mut alice, &*fs);
    let new_main = mal_main(&alice, main);
    let rebased = alice.rebase(wc, vec![new_main]).unwrap();
    assert_mine_stays_team(&alice, &rebased);
    let s = alice.snapshot(&rebased).unwrap();
    assert!(
        s.conflicts.iter().any(|c| c == "secrets/.env.db"),
        "no conflict recorded: {:?}",
        s.conflicts
    );
    // The edit is kept (it stays in its own audience), not dropped.
    assert_eq!(read_at(&alice, &rebased, "secrets/.env.db"), MINE.as_bytes());
}

/// Merging either way round: neither side's content ends up under the
/// other side's scope, and the clash is a conflict.
#[test]
fn a_merge_of_two_audiences_is_a_conflict_not_a_rekey() {
    for mine_is_ours in [true, false] {
        let (mut alice, fs, main) = two_scopes();
        let mine = commit_files(&mut alice, &*fs, &[("secrets/.env.db", MINE)], "rotate");
        let theirs = mal_main(&alice, main);
        let (into, other) = if mine_is_ours {
            (mine, theirs)
        } else {
            (theirs, mine)
        };
        let res = alice.merge(WS, into, vec![other], "merge", None).unwrap();
        assert!(
            res.conflicts.iter().any(|c| c == "secrets/.env.db"),
            "{mine_is_ours}: {:?}",
            res.conflicts
        );
        assert_mine_stays_team(&alice, &res.snapshot);
        let e = file_entry(&alice, &res.snapshot, "secrets/.env.db").unwrap();
        for (vis, data) in versions(&alice, &e) {
            if vis == team() {
                assert!(
                    !data.is_some_and(|d| String::from_utf8_lossy(&d).contains("from-the-mal-scope")),
                    "{mine_is_ours}: mal content moved to team"
                );
            }
        }
        // What Alice is shown holds one side only, as it is.
        let (vis, text) = seen(&alice, &e);
        let text = String::from_utf8_lossy(&text);
        assert!(!(text.contains("from-the-mal-scope") && text.contains("ALICE-ROTATED")), "{text}");
        assert!(vis == team() || !text.contains("ALICE-ROTATED"), "{text}");
    }
}

/// A merged-in line that only replaced the file with `mal` content (the
/// destination did not touch it): the destination keeps its `team` entry;
/// the `mal` content is not resealed for `team`.
#[test]
fn a_merge_never_reseals_another_scopes_content_for_the_destination() {
    let (mut alice, _fs, main) = two_scopes();
    let theirs = mal_main(&alice, main);
    // A line built on main that does not touch the file, so main is the
    // destination and the only change at the path comes from `theirs`.
    let res = alice.merge(WS, main, vec![theirs], "merge", None).unwrap();
    let e = file_entry(&alice, &res.snapshot, "secrets/.env.db").unwrap();
    let data = alice.store().read_blob(&e.id).unwrap();
    assert!(
        !(e.visibility == team() && String::from_utf8_lossy(&data).contains("from-the-mal-scope")),
        "mal content resealed under team"
    );
    assert!(
        res.warnings.iter().any(|w| w.contains("secrets/.env.db")),
        "{:?}",
        res.warnings
    );
}

// ---- BUG-126: the base section of conflict markers ----------------------

const BASE_LINE: &str = "BASE-ONLY-LINE-5521";

/// Merge a one-file tree whose `notes.txt` is `base` (sealed as `bv`)
/// against two sides that edit the same line (sealed as `ov` and `tv`):
/// the merged entry and its content.
fn conflict_over(bv: Visibility, ov: Visibility, tv: Visibility) -> (TreeEntry, String) {
    let (alice, _fs, _) = new_repo("alice");
    alice.keys().create_scope("ops").unwrap();
    let store = alice.store();
    let tree = |text: &str, v: &Visibility| {
        let id = store.store_file(text.as_bytes(), v).unwrap();
        let mut e = file("notes.txt", id);
        e.size = text.len() as u64;
        e.visibility = v.clone();
        raw_tree(&alice, vec![e])
    };
    let base = tree(&format!("intro\n{BASE_LINE}\noutro\n"), &bv);
    let ours = tree("intro\nOURS\noutro\n", &ov);
    let theirs = tree("intro\nTHEIRS\noutro\n", &tv);
    let out = veil_core::merge::merge_trees(store, Some(base), ours, theirs).unwrap();
    assert_eq!(out.conflicts.len(), 1, "a conflict");
    let e = store.tree(&out.tree).unwrap().get("notes.txt").unwrap().clone();
    // Format 4: a conflict entry keeping every version sealed as it was;
    // the markers are only rendered when the file is materialised.
    assert_eq!(e.kind, veil_core::EntryKind::Conflict);
    let vs = versions(&alice, &e);
    assert_eq!(vs.iter().map(|v| v.0.clone()).collect::<Vec<_>>(), vec![ov, bv, tv]);
    let (vis, text) = seen(&alice, &e);
    let text = String::from_utf8(text).unwrap();
    assert!(text.contains("OURS") && text.contains("THEIRS") && text.contains("<<<<<<<"), "{text}");
    (TreeEntry { visibility: vis, ..e }, text)
}

#[test]
fn a_conflict_never_shows_a_sealed_base_in_a_public_result() {
    let (e, text) = conflict_over(team(), Visibility::Public, Visibility::Public);
    assert!(e.visibility.is_public());
    assert!(!text.contains(BASE_LINE), "{text}");
    assert!(!text.contains("|||||||"), "{text}");
}

#[test]
fn a_conflict_never_shows_another_scopes_base() {
    let ops = Visibility::Cloaked { scope: "ops".into() };
    let (e, text) = conflict_over(ops, team(), team());
    assert_eq!(e.visibility, team());
    assert!(!text.contains(BASE_LINE), "{text}");
}

#[test]
fn a_conflict_shows_the_base_to_its_own_audience() {
    // Same audience: diff3 markers, as before.
    let (e, text) = conflict_over(team(), team(), team());
    assert_eq!(e.visibility, team());
    assert!(text.contains(BASE_LINE) && text.contains("|||||||"), "{text}");
    // A public base may show anywhere.
    let (e, text) = conflict_over(Visibility::Public, team(), Visibility::Public);
    assert_eq!(e.visibility, team());
    assert!(text.contains(BASE_LINE), "{text}");
    let (_, text) = conflict_over(Visibility::Public, Visibility::Public, Visibility::Public);
    assert!(text.contains(BASE_LINE), "{text}");
}

// ---- BUG-127: the virtual merge base of a criss-cross merge -------------

/// The virtual base of two merge bases `m1` and `m2` (sealed as `mv`) that
/// disagree on the line their common ancestor (sealed as `bv`) has: the
/// virtual base's entry and content.
fn virtual_over(bv: Visibility, mv: Visibility) -> (TreeEntry, String) {
    let (alice, _fs, _) = new_repo("alice");
    let store = alice.store();
    let tree = |text: &str, v: &Visibility| {
        let id = store.store_file(text.as_bytes(), v).unwrap();
        let mut e = file("notes.txt", id);
        e.size = text.len() as u64;
        e.visibility = v.clone();
        raw_tree(&alice, vec![e])
    };
    let base = tree(&format!("intro\n{BASE_LINE}\noutro\n"), &bv);
    let m1 = tree("intro\nFIRST\noutro\n", &mv);
    let m2 = tree("intro\nSECOND\noutro\n", &mv);
    let vb = veil_core::merge::virtual_merge_base(store, Some(base), m1, m2).unwrap();
    let e = store.tree(&vb).unwrap().get("notes.txt").unwrap().clone();
    let text = String::from_utf8(store.read_entry(&e).unwrap()).unwrap();
    (e, text)
}

#[test]
fn a_virtual_base_never_stores_a_sealed_ancestors_text_for_a_wider_audience() {
    // The two merge bases are public; their common ancestor was cloaked.
    // The virtual base is sealed as the merge bases are, so it must not
    // hold the ancestor's text where they disagree (it would show in the
    // markers of the criss-cross merge, and be stored as public).
    let (e, text) = virtual_over(team(), Visibility::Public);
    assert!(e.visibility.is_public());
    assert!(!text.contains(BASE_LINE), "{text}");
    assert!(!text.contains("FIRST") && !text.contains("SECOND"), "neither base's version is taken: {text}");
}

#[test]
fn a_virtual_base_keeps_a_public_ancestors_text() {
    // Control: a public ancestor's text is kept where the bases disagree.
    let (_, text) = virtual_over(Visibility::Public, Visibility::Public);
    assert!(text.contains(BASE_LINE), "{text}");
    let (e, text) = virtual_over(team(), team());
    assert_eq!(e.visibility, team());
    assert!(text.contains(BASE_LINE), "{text}");
}
