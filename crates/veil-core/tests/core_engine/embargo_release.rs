//! Embargo releases: staged until they leave the repository, undoable until
//! then and only then (BUG-109), and accepted only from current members of
//! the scope (BUG-108).

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
    alice.set_tag("main", main, None, false).unwrap();
    alice.create_workspace("fix", vec![main], Some("team".into())).unwrap();
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

fn clone_of(id: &Identity, hub: &Arc<MemoryBackend>) -> Repo {
    let mut r = Repo::init_for_clone(Arc::new(MemoryBackend::new()), Some(id.clone()), &id.name).unwrap();
    remote::pull(&mut r, "origin", hub.clone()).unwrap();
    r
}

/// Does an outsider reading `mirror` see the fix? (Released content stays
/// sealed on disk; only the published key makes it readable.)
fn mirror_has_fix(mirror: &Arc<MemoryBackend>) -> bool {
    let anon = Repo::open(mirror.clone(), Some(Identity::generate("anon")), "anon").unwrap();
    let main = anon.view().tags["main"].target;
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

/// Carol accepted Bob's release while Bob was a member; once Bob's
/// revocation reaches her, it stops counting. A current member's release
/// then replaces it.
#[test]
fn a_release_stops_counting_when_the_releasers_revocation_arrives() {
    let (bob, carol) = (Identity::generate("bob"), Identity::generate("carol"));
    let (mut alice, e, hub) = embargoed(&[&bob, &carol]);
    let mut bobs = clone_of(&bob, &hub);
    let mut carols = clone_of(&carol, &hub);
    bobs.release_embargo(&e).unwrap();
    remote::push(&mut bobs, hub.clone(), false, &[], false).unwrap();
    remote::pull(&mut carols, "origin", hub.clone()).unwrap();
    assert!(carols.keys().embargo_released(&e), "control: a member's release is accepted");

    remote::pull(&mut alice, "origin", hub.clone()).unwrap();
    assert!(alice.keys().revoke("team", &bob.public_id()).unwrap());
    remote::push(&mut alice, hub.clone(), false, &[], false).unwrap();
    remote::pull(&mut carols, "origin", hub.clone()).unwrap();
    assert!(!carols.keys().embargo_released(&e), "a revoked member's release still counts");
    assert!(matches!(carols.keys().release_state(&e), ReleaseState::Rejected(_)));
    let mirror = Arc::new(MemoryBackend::new());
    remote::push(&mut carols, mirror.clone(), true, &[], false).unwrap();
    assert!(!mirror_has_fix(&mirror), "Carol published the fix on a revoked member's release");

    alice.release_embargo(&e).unwrap();
    remote::push(&mut alice, hub.clone(), false, &[], false).unwrap();
    remote::pull(&mut carols, "origin", hub).unwrap();
    assert_eq!(carols.keys().release_state(&e), ReleaseState::Released);
    remote::push(&mut carols, mirror.clone(), true, &[], false).unwrap();
    assert!(mirror_has_fix(&mirror), "control: a current member's release publishes the fix");
}

#[test]
fn a_revoked_member_who_knows_of_the_revocation_cannot_release() {
    let bob = Identity::generate("bob");
    let (alice, e, hub) = embargoed(&[&bob]);
    let mut bobs = clone_of(&bob, &hub);
    let mut alice = alice;
    assert!(alice.keys().revoke("team", &bob.public_id()).unwrap());
    remote::push(&mut alice, hub.clone(), false, &[], false).unwrap();
    remote::pull(&mut bobs, "origin", hub).unwrap();
    assert!(bobs.keys().has(&format!("embargo/{e}")), "control: Bob keeps the key");
    let err = bobs.release_embargo(&e).unwrap_err().to_string();
    assert!(err.contains("not a current member"), "{err}");
    assert!(!bobs.keys().embargo_released(&e));
}

/// BUG-761: a line under an unreleased embargo stays under it when a
/// snapshot deletes every file of the fix. `embargo::wrap` returned the bare
/// fallback for a tree equal to it, so the line left the embargo, and the
/// fix put back (`git stash pop`, an editor's undo, a restore by hand) was
/// recorded as a public edit: a commit and a push to a public remote
/// published it before the release.
#[test]
fn deleting_and_putting_back_the_fix_never_publishes_it() {
    let (mut alice, fs, _) = new_repo("alice");
    let main = commit_files(&mut alice, &*fs, &[("README.md", "hello\n")], "v1");
    alice.set_tag("main", main, None, false).unwrap();
    alice.create_workspace("fix", vec![main], Some("team".into())).unwrap();
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
    let tree = alice.snapshot(&wc).unwrap().tree;
    assert!(veil_core::embargo::unreleased_wrapper(alice.store(), &tree).unwrap().is_some(), "the line left the embargo");
    for f in ["auth.rs", "other.rs"] {
        let e = veil_core::tree::lookup(alice.store(), &veil_core::embargo::public_view(alice.store(), &tree).unwrap(), &p(f)).unwrap();
        assert!(e.is_none(), "{f} is in the public view before the release");
    }
    let c = alice.commit(WS, "on the fix", false).unwrap();
    alice.set_tag("main", c.committed, None, true).unwrap();
    let mirror = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, mirror.clone(), true, &[], false).unwrap();
    assert!(!mirror_has_fix(&mirror), "the fix reached a public remote before its release");
    // The release still publishes all of it.
    alice.release_embargo(&e).unwrap();
    remote::push(&mut alice, mirror.clone(), true, &[], false).unwrap();
    assert!(mirror_has_fix(&mirror));
}
