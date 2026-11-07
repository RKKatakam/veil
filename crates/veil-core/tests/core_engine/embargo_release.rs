//! Embargo releases: staged until they leave the repository, and undoable
//! until then and only then (BUG-109).

use crate::adversarial_support;

use std::sync::Arc;

use adversarial_support::*;
use veil_core::{
    commands::EmbargoSpec,
    keychain::{ReleaseState, TakeBack},
    remote, Identity, MemoryBackend, Repo, StorageBackend,
};

const WS: &str = "default";

/// Alice (admin of `team`) with `members` granted, `main` carrying an
/// embargoed fix of `auth.rs`, and everything pushed to a team hub.
fn embargoed(members: &[&Identity]) -> (Repo, String, Arc<MemoryBackend>) {
    let (mut alice, fs, _) = new_repo("alice");
    for m in members {
        alice.keys().grant("team", &m.public_id(), &m.name).unwrap();
    }
    let main = commit_files(&mut alice, &*fs, &[("auth.rs", "fn check() -> bool { true }\n")], "v1");
    alice.set_tag("main", main, false).unwrap();
    alice.create_workspace("fix", vec![main]).unwrap();
    let ov = alice.workspace_overlay("fix").unwrap();
    ov.write(&p("auth.rs"), b"fn check() -> bool { verify_signature() }\n").unwrap();
    let fix = alice.snapshot_workspace("fix", &ov).unwrap().snapshot;
    let r = alice
        .merge(WS, main, vec![fix], "merge", Some(EmbargoSpec { scope: "team".into(), until: None }))
        .unwrap();
    let hub = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, hub.clone(), false, &[], false).unwrap();
    (alice, r.embargo.unwrap(), hub)
}

/// Does an outsider reading `mirror` see the fix? (The embargoed history is
/// withheld, `main` with it, until the release.)
fn mirror_has_fix(mirror: &Arc<MemoryBackend>) -> bool {
    let anon = Repo::open(mirror.clone(), Some(Identity::generate("anon")), "anon").unwrap();
    let Some(main) = anon.view().tags.get("main").map(|t| t.target) else {
        return false;
    };
    let data = anon
        .store()
        .tree(&anon.snapshot(&main).unwrap().tree)
        .ok()
        .and_then(|t| t.get("auth.rs").cloned())
        .and_then(|e| anon.store().read_entry(&e).ok())
        .unwrap_or_default();
    data.windows(16).any(|w| w == b"verify_signature")
}

#[test]
fn a_staged_release_stays_in_the_repository_and_undo_takes_it_back() {
    let bob = Identity::generate("bob");
    let (mut alice, e, _) = embargoed(&[&bob]);
    alice.release_embargo(&e).unwrap();
    assert!(alice.keys().embargo_released(&e), "released here at once");
    assert_eq!(alice.keys().release_state(&e), ReleaseState::Staged);
    assert!(
        !alice.keys().load_embargo(&e).unwrap().unwrap().is_released(),
        "the synced record does not carry the key before a push"
    );

    // Even a member pulling straight from Alice's repository does not get it.
    let (bobs, _) = repo_for("bob", &bob);
    let mut bobs = bobs;
    remote::pull(&mut bobs, "alice", alice.backend().clone()).unwrap();
    assert!(!bobs.keys().embargo_released(&e), "a staged release left through a pull of the repository");

    alice.undo().unwrap();
    assert!(!alice.keys().embargo_released(&e));
    assert_eq!(alice.keys().release_state(&e), ReleaseState::Unreleased);
    let mirror = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, mirror.clone(), true, &[], false).unwrap();
    assert!(!mirror_has_fix(&mirror), "the fix was published after the release was taken back");
    let anon = Repo::open(mirror, Some(Identity::generate("anon")), "anon").unwrap();
    assert!(!anon.keys().embargo_released(&e));
}

#[test]
fn a_pushed_release_cannot_be_undone_and_undo_says_so() {
    let (mut alice, e, hub) = embargoed(&[]);
    alice.release_embargo(&e).unwrap();
    let rep = remote::push(&mut alice, hub, false, &[], false).unwrap();
    assert_eq!(rep.releases_published, vec![e.clone()]);
    assert_eq!(alice.keys().release_state(&e), ReleaseState::Released);
    let before = alice.op_id();
    let err = alice.undo().unwrap_err().to_string();
    assert!(err.contains("cannot undo") && err.contains("published"), "{err}");
    assert_eq!(alice.op_id(), before, "a refused undo records nothing");
    assert!(alice.keys().embargo_released(&e));
    assert_eq!(alice.keys().take_back_release(&e).unwrap(), TakeBack::Published);
}

#[test]
fn undoing_the_undo_of_a_release_does_not_release_it() {
    let (mut alice, e, _) = embargoed(&[]);
    alice.release_embargo(&e).unwrap();
    alice.undo().unwrap();
    let err = alice.undo().unwrap_err().to_string();
    assert!(err.contains("never releases"), "{err}");
    assert!(!alice.keys().embargo_released(&e));
}

#[test]
fn publishing_staged_releases_writes_each_record_once() {
    let (alice, e, _) = embargoed(&[]);
    alice.keys().stage_release(&e).unwrap();
    assert_eq!(alice.keys().publish_staged_releases().unwrap(), vec![e.clone()]);
    assert!(alice.keys().publish_staged_releases().unwrap().is_empty());
    assert_eq!(alice.keys().release_state(&e), ReleaseState::Released);
}

/// BUG-761: a line under an unreleased embargo stays under it when a
/// snapshot deletes every file of the fix and puts it back (`git stash
/// pop`, an editor's undo, a restore by hand): a commit on it and a push to
/// a public remote never publish the fix before the release.
#[test]
fn deleting_and_putting_back_the_fix_never_publishes_it() {
    let (mut alice, fs, _) = new_repo("alice");
    let main = commit_files(&mut alice, &*fs, &[("README.md", "hello\n")], "v1");
    alice.set_tag("main", main, false).unwrap();
    alice.create_workspace("fix", vec![main]).unwrap();
    let ov = alice.workspace_overlay("fix").unwrap();
    ov.write(&p("auth.rs"), b"fn check() -> bool { verify_signature() }\n").unwrap();
    let fix = alice.snapshot_workspace("fix", &ov).unwrap().snapshot;
    let r = alice
        .merge(WS, main, vec![fix], "merge", Some(EmbargoSpec { scope: "team".into(), until: None }))
        .unwrap();
    let e = r.embargo.unwrap();
    alice.new_change(WS, vec![r.snapshot], "").unwrap();
    // The directory does not have the fix (deleted): recorded as such …
    let _ = fs.remove_file(&p("auth.rs"));
    alice.snapshot_workspace(WS, &*fs).unwrap();
    // … then it is put back, with a new file beside it.
    fs.write(&p("auth.rs"), b"fn check() -> bool { verify_signature() }\n").unwrap();
    fs.write(&p("other.rs"), b"fn other() {}\n").unwrap();
    let wc = alice.snapshot_workspace(WS, &*fs).unwrap().snapshot;
    assert!(alice.carried_embargo(&wc).unwrap().is_some(), "the line left the embargo");
    let c = alice.commit(WS, "on the fix", false).unwrap();
    alice.set_tag("main", c.committed, true).unwrap();
    let mirror = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, mirror.clone(), true, &[], false).unwrap();
    assert!(!mirror_has_fix(&mirror), "the fix reached a public remote before its release");
    // The release still publishes all of it.
    alice.release_embargo(&e).unwrap();
    remote::push(&mut alice, mirror.clone(), true, &[], false).unwrap();
    assert!(mirror_has_fix(&mirror));
}
