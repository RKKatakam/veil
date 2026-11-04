//! Audiences across merges (BUG-122, BUG-123, BUG-124).
//!
//! * A merge publishes only what the cloaked line being merged brings in,
//!   and only if that line is vouched for by members of its scope: a
//!   snapshot that merely *claims* `cloak: "team"` and rearranges Alice's
//!   genuine `team` objects cannot get them published (BUG-122).
//! * When the two sides of a file are sealed for different scopes, the
//!   merge never moves either side's content to the other audience
//!   (BUG-123).
//! * A cloaked workspace is cloaked under a scope, never an embargo or
//!   `local` (BUG-124).

mod adversarial_support;

use std::sync::Arc;

use adversarial_support::*;
use veil_core::{
    object::{Snapshot, Text, Visibility},
    remote, ChangeId, Identity, MemoryBackend, ObjectId, Repo, StorageBackend, TreeEntry,
};

const PLAN: &str = "ALICE-UNRELEASED-PLAN-7311\n";

fn team() -> Visibility {
    Visibility::Cloaked {
        scope: "team".into(),
    }
}

/// Alice's project: a public `main`, and a cloaked `team` workspace `exp`
/// holding her unreleased `plan.md`.
fn alice_with_plan() -> (Repo, Arc<MemoryBackend>, ObjectId, ObjectId) {
    let (mut alice, fs, _) = new_repo("alice");
    let main = commit_files(&mut alice, &*fs, &[("README", "hi\n")], "v1");
    alice.set_tag("main", main, None, false).unwrap();
    alice
        .create_workspace("exp", vec![main], Some("team".into()))
        .unwrap();
    let ov = alice.workspace_overlay("exp").unwrap();
    ov.write(&p("plan.md"), PLAN.as_bytes()).unwrap();
    let exp = alice.snapshot_workspace("exp", &ov).unwrap().snapshot;
    assert_eq!(
        file_entry(&alice, &exp, "plan.md").unwrap().visibility,
        team()
    );
    (alice, fs, main, exp)
}

/// A snapshot as Mallory would push it: `tree` is `parent`'s tree plus
/// Alice's genuine sealed `plan.md` entry at `at`, the `cloak` field says
/// what Mallory likes, and it is signed by Mallory (or by nobody).
fn mallory_line(
    alice: &Repo,
    parent: ObjectId,
    plan_from: ObjectId,
    at: &str,
    cloak: Option<&str>,
    signer: Option<&Identity>,
) -> ObjectId {
    let store = alice.store();
    let plan = file_entry(alice, &plan_from, "plan.md").unwrap();
    let mut root = (*store.tree(&store.snapshot(&parent).unwrap().tree).unwrap()).clone();
    root.insert(TreeEntry {
        name: at.to_string(),
        ..plan
    });
    let tree = store.put_tree(&root).unwrap();
    let mut s = Snapshot {
        parents: vec![parent],
        change_id: ChangeId::random(),
        tree,
        description: Text::Plain("docs: add notes".into()),
        author: "mallory".into(),
        timestamp: 2,
        predecessors: vec![],
        conflicts: vec![],
        cloak: cloak.map(str::to_string),
        signature: None,
        embargo: None,
    };
    if let Some(id) = signer {
        s.sign(id);
    }
    store.put_snapshot(&s).unwrap()
}

fn assert_not_published(alice: &Repo, rev: &ObjectId, path: &str) {
    if let Some(e) = file_entry(alice, rev, path) {
        assert!(!e.visibility.is_public(), "{path} was published");
        let raw = alice.store().get_raw(&e.id).unwrap();
        assert!(
            !String::from_utf8_lossy(&raw).contains(PLAN.trim()),
            "{path} is plaintext"
        );
    }
}

// ---- BUG-122 -------------------------------------------------------------

/// The reported attack: Mallory's "team line" (her own snapshot, claiming
/// `cloak: "team"`) puts Alice's sealed plan at a new path. Merging it into
/// the public `main` must not publish it, signed by Mallory or not, and
/// even when Mallory is a known member of another scope.
#[test]
fn a_claimed_team_line_cannot_declassify_a_teammates_sealed_objects() {
    for (i, how) in [
        "unsigned",
        "signed by an outsider",
        "signed by a member of another scope",
    ]
    .into_iter()
    .enumerate()
    {
        let (mut alice, _fs, main, exp) = alice_with_plan();
        let mallory = Identity::generate("mallory");
        if i == 2 {
            alice.keys().create_scope("mal").unwrap();
            alice
                .keys()
                .grant("mal", &mallory.public_id(), "mallory")
                .unwrap();
        }
        let evil = mallory_line(
            &alice,
            main,
            exp,
            "notes.md",
            Some("team"),
            (i > 0).then_some(&mallory),
        );
        let res = alice
            .merge(WS, main, vec![evil], "merge notes", None)
            .unwrap();
        assert!(
            res.declassified.is_empty(),
            "{how}: declassified {:?}",
            res.declassified
        );
        assert_not_published(&alice, &res.snapshot, "notes.md");
        assert!(
            res.warnings
                .iter()
                .any(|w| w.contains("signed by a current member of 'team'")),
            "{how}: {:?}",
            res.warnings
        );
    }
}

/// The same with Mallory's snapshot on top of Alice's genuine (signed)
/// line: one snapshot the merge brings in that no member signed is enough.
#[test]
fn an_unvouched_snapshot_on_a_genuine_team_line_blocks_declassification() {
    let (mut alice, _fs, main, exp) = alice_with_plan();
    let mallory = Identity::generate("mallory");
    let evil = mallory_line(&alice, exp, exp, "notes.md", Some("team"), Some(&mallory));
    let res = alice
        .merge(WS, main, vec![evil], "merge exp", None)
        .unwrap();
    assert!(res.declassified.is_empty(), "{:?}", res.declassified);
    assert_not_published(&alice, &res.snapshot, "notes.md");
    assert_not_published(&alice, &res.snapshot, "plan.md");
}

/// Mallory pushes `main` forward with Alice's plan at a public path (it
/// stays sealed there). Alice then merges a genuine cloaked line: its own
/// files are published, the planted one is not, because the line being
/// merged did not bring it in.
#[test]
fn a_genuine_declassifying_merge_publishes_only_what_its_line_brings_in() {
    let (mut alice, _fs, main, exp) = alice_with_plan();
    let evil_main = mallory_line(&alice, main, exp, "notes.md", None, None);
    // A second, unrelated cloaked line of Alice's, based on the old main.
    alice
        .create_workspace("exp2", vec![main], Some("team".into()))
        .unwrap();
    let ov = alice.workspace_overlay("exp2").unwrap();
    ov.write(&p("ship.md"), b"ship it\n").unwrap();
    let exp2 = alice.snapshot_workspace("exp2", &ov).unwrap().snapshot;
    let res = alice
        .merge(WS, evil_main, vec![exp2], "merge exp2", None)
        .unwrap();
    assert_eq!(res.declassified, vec!["ship.md".to_string()]);
    assert!(file_entry(&alice, &res.snapshot, "ship.md")
        .unwrap()
        .visibility
        .is_public());
    assert_not_published(&alice, &res.snapshot, "notes.md");
}

/// Control: a cloaked line written by another current member of `team`
/// (Bob, through the team remote) is still published when Alice merges it.
#[test]
fn a_teammates_cloaked_line_is_still_declassified_by_a_merge() {
    let (mut alice, fs, _) = new_repo("alice");
    let main = commit_files(&mut alice, &*fs, &[("README", "hi\n")], "v1");
    alice.set_tag("main", main, None, false).unwrap();
    let bob_id = Identity::generate("bob");
    alice
        .keys()
        .grant("team", &bob_id.public_id(), "bob")
        .unwrap();
    let hub = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, hub.clone(), false, &[], false).unwrap();

    let mut bob =
        Repo::init_for_clone(Arc::new(MemoryBackend::new()), Some(bob_id), "bob").unwrap();
    remote::pull(&mut bob, "origin", hub.clone()).unwrap();
    bob.create_workspace("feature", vec![main], Some("team".into()))
        .unwrap();
    let ov = bob.workspace_overlay("feature").unwrap();
    ov.write(&p("feature.md"), b"BOB-FEATURE-NOTES\n").unwrap();
    let f = bob.snapshot_workspace("feature", &ov).unwrap().snapshot;
    assert_eq!(
        file_entry(&bob, &f, "feature.md").unwrap().visibility,
        team()
    );
    bob.set_tag("feature", f, Some("team".into()), false)
        .unwrap();
    remote::push(&mut bob, hub.clone(), false, &[], false).unwrap();

    remote::pull(&mut alice, "origin", hub).unwrap();
    let f = alice.view().tags["feature"].target;
    let res = alice
        .merge(WS, main, vec![f], "merge Bob's feature", None)
        .unwrap();
    assert_eq!(
        res.declassified,
        vec!["feature.md".to_string()],
        "{:?}",
        res.warnings
    );
    assert_eq!(
        read_at(&alice, &res.snapshot, "feature.md"),
        b"BOB-FEATURE-NOTES\n"
    );
    assert!(file_entry(&alice, &res.snapshot, "feature.md")
        .unwrap()
        .visibility
        .is_public());
}

// ---- BUG-123 -------------------------------------------------------------

const OLD: &str = "password: old-team-secret\n";
const MINE: &str = "password: ALICE-ROTATED-4417\n";
const THEIRS: &str = "password: from-the-mal-scope\n";

/// `main` with `secrets/db.yml` cloaked under `team`; Alice is also a
/// member of `mal`. Returns the repo, its working copy and `main`.
fn two_scopes() -> (Repo, Arc<MemoryBackend>, ObjectId) {
    let (mut alice, fs, _) = new_repo("alice");
    alice.keys().create_scope("mal").unwrap();
    fs.write(&p(".veilpolicy"), b"secrets/ cloak team\n")
        .unwrap();
    let main = commit_files(
        &mut alice,
        &*fs,
        &[("secrets/db.yml", OLD), ("README", "hi\n")],
        "v1",
    );
    alice.set_tag("main", main, None, false).unwrap();
    (alice, fs, main)
}

/// `main` moved on by someone who replaced `secrets/db.yml` with a genuine
/// `mal`-sealed object.
fn mal_main(alice: &Repo, main: ObjectId) -> ObjectId {
    let store = alice.store();
    let mal = Visibility::Cloaked {
        scope: "mal".into(),
    };
    let mut root = (*store.tree(&store.snapshot(&main).unwrap().tree).unwrap()).clone();
    let mut secrets = (*store.tree(&root.get("secrets").unwrap().id).unwrap()).clone();
    let mut e = secrets.get("db.yml").unwrap().clone();
    e.id = store.store_file(THEIRS.as_bytes(), &mal).unwrap();
    e.size = THEIRS.len() as u64;
    e.visibility = mal;
    secrets.insert(e);
    root.insert(TreeEntry::dir("secrets", store.put_tree(&secrets).unwrap()));
    raw_snapshot(alice, vec![main], store.put_tree(&root).unwrap(), "rotate")
}

fn assert_mine_stays_team(alice: &Repo, rev: &ObjectId) {
    let e = file_entry(alice, rev, "secrets/db.yml").unwrap();
    let data = alice.store().read_blob(&e.id).unwrap();
    if String::from_utf8_lossy(&data).contains("ALICE-ROTATED") {
        assert_eq!(
            e.visibility,
            team(),
            "Alice's edit moved to {}",
            e.visibility.label()
        );
    }
}

/// The reported route: Alice's pending `team` edit, auto-rebased onto a
/// `main` whose file is sealed under `mal`, is never resealed under `mal`.
#[test]
fn a_rebase_never_moves_a_pending_edit_to_another_scope() {
    let (mut alice, fs, main) = two_scopes();
    fs.write(&p("secrets/db.yml"), MINE.as_bytes()).unwrap();
    let wc = snap(&mut alice, &*fs);
    let new_main = mal_main(&alice, main);
    let rebased = alice.rebase(wc, vec![new_main]).unwrap();
    assert_mine_stays_team(&alice, &rebased);
    let s = alice.snapshot(&rebased).unwrap();
    assert!(
        s.conflicts.iter().any(|c| c == "secrets/db.yml"),
        "no conflict recorded: {:?}",
        s.conflicts
    );
    // The edit is kept (it stays in its own audience), not dropped.
    assert_eq!(read_at(&alice, &rebased, "secrets/db.yml"), MINE.as_bytes());
}

/// Merging either way round: neither side's content ends up under the
/// other side's scope, and the clash is a conflict.
#[test]
fn a_merge_of_two_audiences_is_a_conflict_not_a_rekey() {
    for mine_is_ours in [true, false] {
        let (mut alice, fs, main) = two_scopes();
        let mine = commit_files(&mut alice, &*fs, &[("secrets/db.yml", MINE)], "rotate");
        let theirs = mal_main(&alice, main);
        let (into, other) = if mine_is_ours {
            (mine, theirs)
        } else {
            (theirs, mine)
        };
        let res = alice.merge(WS, into, vec![other], "merge", None).unwrap();
        assert!(
            res.conflicts.iter().any(|c| c == "secrets/db.yml"),
            "{mine_is_ours}: {:?}",
            res.conflicts
        );
        assert_mine_stays_team(&alice, &res.snapshot);
        let e = file_entry(&alice, &res.snapshot, "secrets/db.yml").unwrap();
        if e.visibility == team() {
            let data = alice.store().read_blob(&e.id).unwrap();
            assert!(
                !String::from_utf8_lossy(&data).contains("from-the-mal-scope"),
                "{mine_is_ours}: mal content moved to team"
            );
        }
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
    let e = file_entry(&alice, &res.snapshot, "secrets/db.yml").unwrap();
    let data = alice.store().read_blob(&e.id).unwrap();
    assert!(
        !(e.visibility == team() && String::from_utf8_lossy(&data).contains("from-the-mal-scope")),
        "mal content resealed under team"
    );
    assert!(
        res.warnings.iter().any(|w| w.contains("secrets/db.yml")),
        "{:?}",
        res.warnings
    );
}

// ---- BUG-124 -------------------------------------------------------------

#[test]
fn a_workspace_cannot_be_cloaked_under_an_embargo_or_a_reserved_name() {
    let (mut alice, fs, _) = new_repo("alice");
    let main = commit_files(&mut alice, &*fs, &[("README", "hi\n")], "v1");
    let embargo = alice.keys().create_embargo("team", None).unwrap();
    assert!(
        alice.keys().is_member(&format!("embargo/{embargo}"))
            || alice.keys().has(&format!("embargo/{embargo}"))
    );
    for (i, bad) in [
        format!("embargo/{embargo}"),
        "local".into(),
        "team#0000000000000000".into(),
        "".into(),
    ]
    .into_iter()
    .enumerate()
    {
        let err = alice.create_workspace(&format!("w{i}"), vec![main], Some(bad.clone()));
        assert!(err.is_err(), "--cloak {bad:?} accepted");
    }
    // A real scope still works.
    alice
        .create_workspace("ok", vec![main], Some("team".into()))
        .unwrap();
}
