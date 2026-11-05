//! BUG-050 × stale working copies. After an embargo release, a file whose
//! content equals the pre-embargo version is a deliberate revert, unless
//! the working copy's materialisation record says that file was written
//! from the embargo fallback and never refreshed. In that case it is a
//! stale copy, and recording it would silently revert the released fix.

use crate::adversarial_support;

use std::sync::Arc;

use adversarial_support::*;
use veil_core::{
    checkout::Materialised,
    commands::EmbargoSpec,
    remote,
    tree::lookup,
    workspace::SnapshotOptions,
    MemoryBackend, ObjectId, Repo, StorageBackend, VPath,
};

struct World {
    bob: Repo,
    bob_fs: Arc<MemoryBackend>,
    record: Materialised,
    merged_entry: ObjectId,
}

/// Alice embargoes a fix and pushes to a public mirror; Bob (no key) checks
/// out the merge (he is shown the pre-merge file); Alice releases and pushes;
/// Bob pulls. Bob's working copy still holds the fallback.
fn world() -> World {
    let (mut alice, alice_fs, _) = new_repo("alice");
    let main = commit_files(&mut alice, &*alice_fs, &[("auth.rs", "fn check() -> bool { true }\n")], "v1");
    alice.set_tag("main", main, None, false).unwrap();
    let ws = alice.ephemeral_workspace(main).unwrap();
    ws.write("auth.rs", "fn check() -> bool { verify() }\n").unwrap();
    let (fix, _) = alice.commit_ephemeral(&ws, "fix").unwrap();
    let res = alice
        .merge(WS, main, vec![fix], "merge fix", Some(EmbargoSpec { scope: "team".into(), until: None }))
        .unwrap();
    let mirror = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, mirror.clone(), true, &[], false).unwrap();

    // As `vl clone` does: no default scope of Bob's own, so Alice's signed
    // rings and embargo records verify.
    let bob_fs = Arc::new(MemoryBackend::new());
    let mut bob = Repo::init_for_clone(bob_fs.clone(), Some(veil_core::Identity::generate("bob")), "bob").unwrap();
    remote::pull(&mut bob, "origin", mirror.clone()).unwrap();
    let wc = bob.new_change(WS, vec![res.snapshot], "").unwrap();
    let to = bob.snapshot(&wc).unwrap().tree;
    let mut record = Materialised::default();
    bob.checkout_tree_recorded(&*bob_fs, None, &to, &mut record, None).unwrap();
    assert_eq!(
        bob_fs.read(&p("auth.rs")).unwrap(),
        b"fn check() -> bool { true }\n",
        "without the key Bob is shown the pre-merge file"
    );

    alice.release_embargo(res.embargo.as_deref().unwrap()).unwrap();
    remote::push(&mut alice, mirror.clone(), true, &[], false).unwrap();
    remote::pull(&mut bob, "origin", mirror).unwrap();
    bob.keys().invalidate();
    let merged_entry = file_entry(&bob, &res.snapshot, "auth.rs").unwrap().id;
    World { bob, bob_fs, record, merged_entry }
}

fn recorded_auth(bob: &Repo) -> ObjectId {
    let wc = bob.workspace_wc(WS).unwrap();
    let tree = bob.snapshot(&wc).unwrap().tree;
    lookup(bob.store(), &tree, &VPath::new("auth.rs").unwrap()).unwrap().unwrap().id
}

#[test]
fn a_stale_fallback_copy_is_not_recorded_as_a_revert_of_the_released_fix() {
    let mut w = world();
    // Fill-in did not run (e.g. it failed, or a library caller skipped it):
    // the record still says auth.rs came from the fallback.
    w.bob
        .snapshot_workspace_with(
            WS,
            &*w.bob_fs,
            SnapshotOptions {
                materialised: Some(&w.record),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(recorded_auth(&w.bob), w.merged_entry, "the released fix was reverted by a stale copy");
}

#[test]
fn without_a_record_matching_the_pre_embargo_content_is_a_revert() {
    let mut w = world();
    // No record: the builder takes the working copy at its word (BUG-050).
    w.bob.snapshot_workspace_with(WS, &*w.bob_fs, SnapshotOptions::default()).unwrap();
    assert_ne!(recorded_auth(&w.bob), w.merged_entry);
}
