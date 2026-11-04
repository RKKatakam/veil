//! BUG-103 property tests: visibility metadata from history (tree entry
//! labels, a snapshot's `cloak` field) is a claim, never authority.
//!
//! Mallory has write access to the team remote but is not in `team`. She
//! pushes `main` forward with Alice's tree, except that the entry of Alice's
//! cloaked `secrets/db.yml` carries a label of her choosing, and the
//! snapshot's `cloak` field one too. Whatever the labels, and whichever way
//! Alice brings her work onto the new `main` (`vl new`, `vl edit`, a
//! rebase of a pending edit, a merge), her next secret is never readable by
//! Mallory, by an anonymous reader of the team remote, or by anyone reading
//! the public mirror (checked on decoded packs with `backend_contains`).
//!
//! `Label::GenuineMal` is not a forged label but a genuine object: Mallory
//! replaces the file with her own content, really sealed under `mal`, a
//! scope Alice is also a member of. Merging and rebasing Alice's pending
//! `team` edit against it is a merge of two sides sealed for different
//! scopes, which must never move Alice's edit to `mal` (BUG-123). Editing
//! it after `vl new main` or `vl edit main` must not either (BUG-125): the
//! policy says `team`, the object says `mal`, and Alice's edit is held back
//! (the file stays local, history keeps Mallory's entry) rather than sealed
//! for either audience. `Label::GenuineMalPolicy` is the same object with
//! `.veilpolicy` re-keyed to `secrets/ cloak mal` as well, which Alice's
//! accepted policy holds back.

mod adversarial_support;

use std::sync::Arc;

use adversarial_support::*;
use proptest::prelude::*;
use veil_core::{
    object::{Text, Visibility},
    remote, ChangeId, Identity, MemoryBackend, ObjectId, Repo, Snapshot, StorageBackend,
};

const OLD: &[u8] = b"password: old-team-secret\n";
const MALLORYS: &[u8] = b"password: mallorys-own-mal-secret\n";

#[derive(Debug, Clone, Copy)]
enum Label {
    Public,
    Mal,
    CloakedReleasedEmbargo,
    EmbargoedReleased,
    EmbargoedUnreleased,
    OldGeneration,
    Local,
    Unchanged,
    GenuineMal,
    GenuineMalPolicy,
    /// Not a label but a planted conflict entry (repository format 4):
    /// Alice's genuine `team` object relabelled `public` as one side,
    /// Mallory's genuine `mal` object as the other, over Alice's old version
    /// labelled `public`. Whatever its labels claim, Alice's resolution
    /// (her edit of the file checkout shows) is sealed for `team`.
    ForgedConflict,
}

impl Label {
    /// Mallory's own content, genuinely sealed under `mal`.
    fn genuine(self) -> bool {
        matches!(self, Label::GenuineMal | Label::GenuineMalPolicy)
    }
}

#[derive(Debug, Clone, Copy)]
enum Cloak {
    None,
    ReleasedEmbargo,
    Mal,
    OldGeneration,
}

#[derive(Debug, Clone, Copy)]
enum Route {
    New,
    Edit,
    Rebase,
    Merge,
}

struct Ids {
    released: String,
    unreleased: String,
}

fn label_vis(l: Label, ids: &Ids) -> Visibility {
    let cloaked = |s: &str| Visibility::Cloaked { scope: s.to_string() };
    match l {
        Label::Public => Visibility::Public,
        Label::Mal => cloaked("mal"),
        Label::CloakedReleasedEmbargo => cloaked(&format!("embargo/{}", ids.released)),
        Label::EmbargoedReleased => Visibility::Embargoed {
            embargo: ids.released.clone(),
        },
        Label::EmbargoedUnreleased => Visibility::Embargoed {
            embargo: ids.unreleased.clone(),
        },
        Label::OldGeneration => cloaked("team#0000000000000000"),
        Label::Local => cloaked("local"),
        Label::Unchanged | Label::GenuineMal | Label::GenuineMalPolicy | Label::ForgedConflict => cloaked("team"),
    }
}

fn cloak_field(c: Cloak, ids: &Ids) -> Option<String> {
    match c {
        Cloak::None => None,
        Cloak::ReleasedEmbargo => Some(format!("embargo/{}", ids.released)),
        Cloak::Mal => Some("mal".into()),
        Cloak::OldGeneration => Some("team#0000000000000000".into()),
    }
}

/// Mallory relabels `secrets/db.yml` on the hub's `main`.
fn mallory_pushes(hub: Arc<MemoryBackend>, main: ObjectId, alice_pub: &str, mallory: &Identity, label: Label, cloak: Cloak) {
    let mut m = Repo::init_for_clone(Arc::new(MemoryBackend::new()), Some(mallory.clone()), "mallory").unwrap();
    remote::pull(&mut m, "origin", hub.clone()).unwrap();
    m.keys().create_scope("mal").unwrap();
    m.keys().grant("mal", alice_pub, "alice").unwrap();
    let released = m.keys().create_embargo("mal", None).unwrap();
    m.keys().release_embargo(&released).unwrap();
    let unreleased = m.keys().create_embargo("mal", None).unwrap();
    let ids = Ids { released, unreleased };

    let store = m.store().clone();
    let root_tree = store.snapshot(&main).unwrap().tree;
    let mut root = (*store.tree(&root_tree).unwrap()).clone();
    let secrets_id = root.get("secrets").unwrap().id;
    let mut secrets = (*store.tree(&secrets_id).unwrap()).clone();
    let mut e = secrets.get("db.yml").unwrap().clone();
    e.visibility = label_vis(label, &ids);
    if label.genuine() {
        let mal = Visibility::Cloaked { scope: "mal".into() };
        e.id = store.store_file(MALLORYS, &mal).unwrap();
        e.size = MALLORYS.len() as u64;
        e.visibility = mal;
    }
    if let Label::ForgedConflict = label {
        let mal = Visibility::Cloaked { scope: "mal".into() };
        let alices = veil_core::ConflictTerm {
            visibility: Visibility::Public,
            ..veil_core::ConflictTerm::of(&e)
        };
        let mallorys = veil_core::ConflictTerm {
            id: store.store_file(MALLORYS, &mal).unwrap(),
            size: MALLORYS.len() as u64,
            executable: false,
            visibility: Visibility::Public,
            fallback: None,
        };
        let c = veil_core::Conflict {
            adds: vec![Some(alices.clone()), Some(mallorys)],
            removes: vec![Some(veil_core::ConflictTerm { fallback: Some(e.id), ..alices })],
        };
        e = veil_core::TreeEntry::conflict("db.yml", store.put_conflict(&c).unwrap());
    }
    secrets.insert(e);
    root.insert(veil_core::TreeEntry::dir("secrets", store.put_tree(&secrets).unwrap()));
    if let Label::GenuineMalPolicy = label {
        let mut pe = root.get(".veilpolicy").unwrap().clone();
        let policy = b"secrets/ cloak mal\n";
        pe.id = store.store_file(policy, &Visibility::Public).unwrap();
        pe.size = policy.len() as u64;
        root.insert(pe);
    }
    let tree = store.put_tree(&root).unwrap();
    let evil = store
        .put_snapshot(&Snapshot {
            parents: vec![main],
            change_id: ChangeId::random(),
            tree,
            description: Text::Plain("chore: tidy up".into()),
            author: "mallory".into(),
            timestamp: 2,
            predecessors: vec![],
            conflicts: vec![],
            cloak: cloak_field(cloak, &ids),
            signature: None,
            embargo: None,
        })
        .unwrap();
    m.set_tag("main", evil, None, true).unwrap();
    remote::push(&mut m, hub, false, &["main".into()], false).unwrap();
}

fn checkout_wc(alice: &mut Repo, fs: &MemoryBackend, old_tree: ObjectId) {
    let to = alice.snapshot(&alice.workspace_wc(WS).unwrap()).unwrap().tree;
    alice.checkout_tree(fs, Some(&old_tree), &to).unwrap();
}

fn run(label: Label, cloak: Cloak, route: Route, n: u32) {
    let secret = format!("NEW-rotated-{n:04}-secret");
    let (mut alice, fs, _) = new_repo("alice");
    fs.write(&p(".veilpolicy"), b"secrets/ cloak team\n").unwrap();
    let main = commit_files(&mut alice, &*fs, &[("secrets/db.yml", std::str::from_utf8(OLD).unwrap()), ("README", "hi\n")], "v1");
    alice.set_tag("main", main, None, false).unwrap();
    let hub = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, hub.clone(), false, &[], false).unwrap();

    let mallory = Identity::generate("mallory");
    let alice_pub = alice.identity().unwrap().public_id();
    mallory_pushes(hub.clone(), main, &alice_pub, &mallory, label, cloak);

    let edited = format!("password: {secret}\n");
    let committed = match route {
        Route::New | Route::Edit => {
            remote::pull(&mut alice, "origin", hub.clone()).unwrap();
            let new_main = alice.view().tags["main"].target;
            let old = alice.snapshot(&alice.workspace_wc(WS).unwrap()).unwrap().tree;
            match route {
                Route::New => {
                    alice.new_change(WS, vec![new_main], "").unwrap();
                }
                _ => alice.edit(WS, new_main).unwrap(),
            }
            checkout_wc(&mut alice, &fs, old);
            // Alice does see the content change on checkout.
            let shown = if label.genuine() { MALLORYS } else { OLD };
            assert_eq!(fs.read(&p("secrets/db.yml")).unwrap(), shown);
            fs.write(&p("secrets/db.yml"), edited.as_bytes()).unwrap();
            let report = alice.snapshot_workspace(WS, &*fs).unwrap().report;
            let committed = alice.commit_working_copy(WS, "rotate").unwrap().0;
            if label.genuine() {
                // BUG-125: the policy (pinned by Alice's accepted policy)
                // says `team`, the parent object is sealed for `mal`. The
                // edit is sealed for neither: it stays local, reported, and
                // history keeps Mallory's entry as it is.
                assert!(
                    report.cloak_failures.iter().any(|(q, _)| q.as_str() == "secrets/db.yml"),
                    "{label:?}/{cloak:?}/{route:?}: the edit was not held back: {:?}",
                    report.cloak_failures
                );
                let e = file_entry(&alice, &committed, "secrets/db.yml").expect("recorded");
                assert_eq!(e.visibility, Visibility::Cloaked { scope: "mal".into() });
                assert_eq!(read_at(&alice, &committed, "secrets/db.yml"), MALLORYS);
                assert_eq!(fs.read(&p("secrets/db.yml")).unwrap(), edited.as_bytes(), "the edit stays local");
                leak_check(&mut alice, &hub, &mallory, &secret, committed, &format!("{label:?}/{cloak:?}/{route:?}"));
                // The way out the report names: `vl cloak --scope team
                // secrets/db.yml`, an edit of `.veilpolicy` that re-keys the
                // file deliberately.
                let mut policy = fs.read(&p(".veilpolicy")).unwrap();
                policy.extend_from_slice(b"secrets/db.yml cloak team\n");
                fs.write(&p(".veilpolicy"), &policy).unwrap();
                let report = alice.snapshot_workspace(WS, &*fs).unwrap().report;
                assert!(report.cloak_failures.is_empty(), "{label:?}/{cloak:?}/{route:?}: {:?}", report.cloak_failures);
                alice.commit_working_copy(WS, "re-key").unwrap().0
            } else {
                committed
            }
        }
        Route::Rebase => {
            // A pending edit, rebased onto the pulled main.
            fs.write(&p("secrets/db.yml"), edited.as_bytes()).unwrap();
            let wc = snap(&mut alice, &*fs);
            remote::pull(&mut alice, "origin", hub.clone()).unwrap();
            let new_main = alice.view().tags["main"].target;
            alice.rebase(wc, vec![new_main]).unwrap();
            snap(&mut alice, &*fs);
            alice.commit_working_copy(WS, "rotate").unwrap().0
        }
        Route::Merge => {
            fs.write(&p("secrets/db.yml"), edited.as_bytes()).unwrap();
            snap(&mut alice, &*fs);
            let mine = alice.commit_working_copy(WS, "rotate").unwrap().0;
            remote::pull(&mut alice, "origin", hub.clone()).unwrap();
            let new_main = alice.view().tags["main"].target;
            match alice.merge(WS, mine, vec![new_main], "merge main", None) {
                Ok(r) => r.snapshot,
                Err(_) => mine, // a refused merge publishes nothing new
            }
        }
    };

    // Alice's secret is sealed for `team`, whatever the labels said. A
    // merge of two scopes is a conflict entry (format 4): what Alice is
    // shown is her side, sealed for `team`, and every version holding her
    // secret is sealed for `team`.
    let e = file_entry(&alice, &committed, "secrets/db.yml").expect("recorded");
    assert_eq!(read_at(&alice, &committed, "secrets/db.yml"), edited.as_bytes(), "Alice reads her edit");
    let (shown_as, _) = seen(&alice, &e);
    assert_eq!(
        shown_as,
        Visibility::Cloaked { scope: "team".into() },
        "{label:?}/{cloak:?}/{route:?}: Alice's edit was sealed as {}",
        shown_as.label()
    );
    for (vis, data) in versions(&alice, &e) {
        if data.is_some_and(|d| String::from_utf8_lossy(&d).contains(&secret)) {
            assert_eq!(vis, Visibility::Cloaked { scope: "team".into() }, "{label:?}/{cloak:?}/{route:?}: a version holds the secret");
        }
    }

    leak_check(&mut alice, &hub, &mallory, &secret, committed, &format!("{label:?}/{cloak:?}/{route:?}"));
    // The commit message is never sealed under an embargo key.
    if let Text::Sealed(env) = &alice.snapshot(&committed).unwrap().description {
        assert!(!env.scope.starts_with("embargo/"), "message sealed under {}", env.scope);
    }
}

/// Publish Alice's `committed` to the team remote and a public mirror at
/// `main`: her new `secret` is readable on neither, by Mallory or anyone.
fn leak_check(alice: &mut Repo, hub: &Arc<MemoryBackend>, mallory: &Identity, secret: &str, committed: ObjectId, case: &str) {
    let e = file_entry(alice, &committed, "secrets/db.yml").expect("recorded");
    // Publish: the team remote, and a public mirror at `main`.
    remote::push(alice, hub.clone(), false, &[], false).unwrap();
    let _ = alice.set_tag("main", committed, None, true);
    let mirror = Arc::new(MemoryBackend::new());
    // A refused public push publishes nothing; either way, check.
    let _ = remote::push(alice, mirror.clone(), true, &["main".into()], false);

    for (what, backend) in [("team remote", hub), ("public mirror", &mirror)] {
        let hits = backend_contains(&**backend, secret.as_bytes());
        assert!(hits.is_empty(), "{case}: plaintext on the {what}: {hits:?}");
    }
    // Mallory (in `mal`, holding every embargo key she made) and an
    // anonymous reader open everything they can reach.
    for (who, id, backend) in [
        ("mallory@hub", mallory.clone(), hub.clone()),
        ("anon@mirror", Identity::generate("anon"), mirror.clone()),
    ] {
        let Ok(r) = Repo::open(backend, Some(id), who) else { continue };
        for (name, tag) in r.view().tags.clone() {
            let Ok(Some(e)) = veil_core::tree::lookup(r.store(), &r.snapshot(&tag.target).unwrap().tree, &p("secrets/db.yml")) else {
                continue;
            };
            if let Ok(data) = veil_core::conflict::read_file_like(r.store(), &e) {
                assert!(
                    !String::from_utf8_lossy(&data).contains(secret),
                    "{case}: {who} reads Alice's new secret at {name}"
                );
            }
            if e.kind == veil_core::EntryKind::Conflict {
                if let Ok(c) = r.store().conflict(&e.id) {
                    for t in c.interleaved().flatten() {
                        if let Ok(data) = r.store().read_blob(&t.id) {
                            assert!(!String::from_utf8_lossy(&data).contains(secret), "{case}: {who} reads a conflict version at {name}");
                        }
                    }
                }
            }
        }
        if let Ok(data) = veil_core::conflict::read_file_like(r.store(), &e) {
            assert!(
                !String::from_utf8_lossy(&data).contains(secret),
                "{case}: {who} reads Alice's committed entry"
            );
        }
    }
}

fn label() -> impl Strategy<Value = Label> {
    prop_oneof![
        Just(Label::Public),
        Just(Label::Mal),
        Just(Label::CloakedReleasedEmbargo),
        Just(Label::EmbargoedReleased),
        Just(Label::EmbargoedUnreleased),
        Just(Label::OldGeneration),
        Just(Label::Local),
        Just(Label::Unchanged),
        Just(Label::GenuineMal),
        Just(Label::GenuineMalPolicy),
        Just(Label::ForgedConflict),
    ]
}

fn cloak() -> impl Strategy<Value = Cloak> {
    prop_oneof![Just(Cloak::None), Just(Cloak::ReleasedEmbargo), Just(Cloak::Mal), Just(Cloak::OldGeneration)]
}

fn route() -> impl Strategy<Value = Route> {
    prop_oneof![Just(Route::New), Just(Route::Edit), Just(Route::Rebase), Just(Route::Merge)]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 40, ..ProptestConfig::default() })]

    #[test]
    fn hostile_labels_never_make_new_plaintext_readable_outside_its_audience(l in label(), c in cloak(), r in route(), n in 0u32..10_000) {
        run(l, c, r, n);
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 16, ..ProptestConfig::default() })]

    /// Two sides sealed for different scopes (Alice's `team` edit against
    /// Mallory's genuine `mal` object), through the routes that merge them.
    #[test]
    fn a_merge_of_two_scopes_never_moves_the_pending_edit(c in cloak(), r in prop_oneof![Just(Route::Rebase), Just(Route::Merge)], n in 0u32..10_000) {
        run(Label::GenuineMal, c, r, n);
    }
}

/// Both merging routes against a genuine `mal` object, on every run.
#[test]
fn a_genuine_other_scope_object_is_neutralised_by_rebase_and_merge() {
    let mut n = 200;
    for l in [Label::GenuineMal, Label::GenuineMalPolicy] {
        for r in [Route::Rebase, Route::Merge] {
            n += 1;
            run(l, Cloak::None, r, n);
        }
    }
}

/// Every label with the most direct route (`vl new` after a pull), so each
/// one is covered on every run.
#[test]
fn every_hostile_label_is_neutralised_after_pull_and_new() {
    for (i, l) in [
        Label::Public,
        Label::Mal,
        Label::CloakedReleasedEmbargo,
        Label::EmbargoedReleased,
        Label::EmbargoedUnreleased,
        Label::OldGeneration,
        Label::Local,
        Label::ForgedConflict,
    ]
    .into_iter()
    .enumerate()
    {
        run(l, Cloak::None, Route::New, i as u32);
    }
}

/// A planted conflict entry with forged labels, through every route.
#[test]
fn a_forged_conflict_entry_never_decides_the_audience_of_a_resolution() {
    for (i, r) in [Route::New, Route::Edit, Route::Rebase, Route::Merge].into_iter().enumerate() {
        run(Label::ForgedConflict, Cloak::None, r, 400 + i as u32);
    }
}

/// Every hostile cloak field, through every route.
#[test]
fn every_hostile_cloak_field_is_neutralised() {
    let mut n = 100;
    for c in [Cloak::ReleasedEmbargo, Cloak::Mal, Cloak::OldGeneration] {
        for r in [Route::New, Route::Edit, Route::Rebase, Route::Merge] {
            n += 1;
            run(Label::Unchanged, c, r, n);
        }
    }
}

/// BUG-125: Mallory's genuine `mal` object under a policy that says `team`
/// (and, with `GenuineMalPolicy`, a `.veilpolicy` re-keyed to `mal` that
/// Alice's accepted policy holds back), edited after `vl new main` or
/// `vl edit main`: the edit is never sealed for `mal`.
#[test]
fn a_genuine_other_scope_object_is_never_the_audience_of_an_edit() {
    let mut n = 300;
    for l in [Label::GenuineMal, Label::GenuineMalPolicy] {
        for c in [Cloak::None, Cloak::Mal] {
            for r in [Route::New, Route::Edit] {
                n += 1;
                run(l, c, r, n);
            }
        }
    }
}
