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

// ---- Op log merges review, cycle 4 (re-check of BUG-1487's fix): a
// staged release is published only if the user released it and nothing in
// force took it back; and nothing else takes it back.

/// [`embargoed`], with what reopening the repository needs: a public
/// mirror for the pushes, and Alice's identity.
fn embargoed_reopenable() -> (Repo, String, Arc<MemoryBackend>, Identity) {
    let (mut alice, fs, me) = new_repo("alice");
    let main = commit_files(&mut alice, &*fs, &[("auth.rs", "fn check() -> bool { true }\n")], "v1");
    alice.set_tag("main", main, false).unwrap();
    alice.create_workspace("fix", vec![main]).unwrap();
    let ov = alice.workspace_overlay("fix").unwrap();
    ov.write(&p("auth.rs"), b"fn check() -> bool { verify_signature() }\n").unwrap();
    let fix = alice.snapshot_workspace("fix", &ov).unwrap().snapshot;
    let r = alice
        .merge(WS, main, vec![fix], "merge", Some(EmbargoSpec { scope: "team".into(), until: None }))
        .unwrap();
    alice.set_tag("main", r.snapshot, true).unwrap();
    (alice, r.embargo.unwrap(), fs, me)
}

fn reopen(fs: &Arc<MemoryBackend>, me: &Identity) -> Repo {
    Repo::open(fs.clone(), Some(me.clone()), "alice").unwrap()
}

/// Push to a new public mirror: the published releases, and whether the
/// fix reached it.
fn push_public(repo: &mut Repo) -> (Vec<String>, bool) {
    let mirror = Arc::new(MemoryBackend::new());
    let rep = remote::push(repo, mirror.clone(), true, &[], false).unwrap();
    (rep.releases_published, mirror_has_fix(&mirror))
}

/// `vl embargo release` stopped after its operation, before it staged the
/// release: the embargo stays unreleased, nothing publishes it, and
/// releasing again works and publishes it.
#[test]
fn a_release_stopped_after_its_operation_is_never_published_and_can_be_released_again() {
    let (mut alice, e, fs, me) = embargoed_reopenable();
    let mut tx = alice.transaction(format!("{}{e}", veil_core::commands::RELEASE_OP_PREFIX)).unwrap();
    tx.repository_wide();
    tx.record_always();
    assert!(tx.commit().unwrap().is_some(), "the release's operation recorded");
    drop(alice);
    let mut next = reopen(&fs, &me);
    assert_eq!(next.keys().release_state(&e), ReleaseState::Unreleased, "stopped before staging: unreleased");
    let (published, fix) = push_public(&mut next);
    assert!(published.is_empty() && !fix, "published {published:?}, fix public: {fix}");
    next.release_embargo(&e).unwrap();
    assert_eq!(next.keys().release_state(&e), ReleaseState::Staged, "released again");
    let mut last = reopen(&fs, &me);
    assert_eq!(last.keys().release_state(&e), ReleaseState::Staged, "the open's check keeps it");
    let (published, fix) = push_public(&mut last);
    assert_eq!(published, vec![e.clone()]);
    assert!(fix, "the released fix is public");
}

/// `vl undo` of a release stopped after its operation, before taking the
/// release back: the next process takes it back; and a push by a process
/// that opened before the undo (so its open saw the release in force)
/// does not publish it either.
#[test]
fn an_undo_of_a_release_stopped_before_its_take_back_is_never_published() {
    for pusher_opened_first in [false, true] {
        let (mut alice, e, fs, me) = embargoed_reopenable();
        alice.release_embargo(&e).unwrap();
        let release = alice.op_id();
        let mut pusher = pusher_opened_first.then(|| reopen(&fs, &me));
        // The undo, as `Repo::undo` commits it; then the process stops.
        let parent = alice.ops().get(&release).unwrap().parents[0];
        let view = alice.ops().get(&parent).unwrap().view;
        let mut tx = alice.transaction(format!("undo: {}{e}", veil_core::commands::RELEASE_OP_PREFIX)).unwrap();
        tx.view = view;
        tx.undo_of(release);
        assert!(tx.commit().unwrap().is_some(), "the undo recorded");
        assert_eq!(alice.keys().release_state(&e), ReleaseState::Staged, "stopped before the take-back");
        drop(alice);
        let mut pusher = pusher.take().unwrap_or_else(|| reopen(&fs, &me));
        let (published, fix) = push_public(&mut pusher);
        assert!(published.is_empty() && !fix, "opened first: {pusher_opened_first}; published {published:?}, fix public: {fix}");
        assert_eq!(pusher.keys().release_state(&e), ReleaseState::Unreleased, "taken back");
    }
}

/// A release staged by an older `vl` (which staged it, then recorded its
/// operation) is published; one that stopped between the two (staged,
/// with no operation) is taken back, never published.
#[test]
fn a_release_staged_by_an_older_vl_is_published_only_with_its_operation() {
    for completed in [true, false] {
        let (alice, e, fs, me) = embargoed_reopenable();
        let mut alice = alice;
        assert_eq!(alice.keys().stage_release(&e).unwrap(), veil_core::keychain::StageOutcome::Staged);
        if completed {
            let mut tx = alice.transaction(format!("{}{e}", veil_core::commands::RELEASE_OP_PREFIX)).unwrap();
            tx.repository_wide();
            tx.record_always();
            assert!(tx.commit().unwrap().is_some(), "the release's operation recorded");
        }
        drop(alice);
        let mut next = reopen(&fs, &me);
        // Staged either way until a push checks it (BUG-1533: no check at
        // open); the push publishes it only with its operation.
        assert_eq!(next.keys().release_state(&e), ReleaseState::Staged, "completed: {completed}");
        let (published, fix) = push_public(&mut next);
        assert_eq!(published.is_empty(), !completed, "completed: {completed}: published {published:?}");
        assert_eq!(fix, completed, "completed: {completed}: the fix public");
        let after = if completed { ReleaseState::Released } else { ReleaseState::Unreleased };
        assert_eq!(next.keys().release_state(&e), after, "completed: {completed}: after the push");
    }
}

/// What the check never takes back: a release whose operation stands
/// after an undo and redo of a later command, an op restore to after it,
/// and a release made again after an undo or a restore took the first back.
#[test]
fn the_check_keeps_every_release_that_stands() {
    for case in 0..4 {
        let (mut alice, e, fs, me) = embargoed_reopenable();
        let main = alice.view().tags["main"].target;
        let before = alice.op_id();
        alice.release_embargo(&e).unwrap();
        match case {
            0 => {
                alice.set_tag("later", main, false).unwrap();
                alice.undo().unwrap();
                assert!(!alice.view().tags.contains_key("later"), "undone");
                let (_, redone) = alice.redo_keeping_edits(WS).unwrap();
                assert!(redone.contains("later"), "redid the tag: {redone}");
            }
            1 => {
                alice.set_tag("later", main, false).unwrap();
                let after_release = alice.ops().get(&alice.op_id()).unwrap().parents[0];
                alice.set_tag("later2", main, false).unwrap();
                alice.restore_operation(after_release).unwrap();
            }
            2 => {
                alice.undo().unwrap();
                assert_eq!(alice.keys().release_state(&e), ReleaseState::Unreleased, "the undo took it back");
                alice.release_embargo(&e).unwrap();
            }
            _ => {
                alice.restore_operation(before).unwrap();
                assert_eq!(alice.keys().release_state(&e), ReleaseState::Unreleased, "the restore took it back");
                alice.undo().unwrap();
                assert_eq!(alice.keys().release_state(&e), ReleaseState::Unreleased, "the undo of the restore does not release");
                alice.release_embargo(&e).unwrap();
            }
        }
        assert_eq!(alice.keys().release_state(&e), ReleaseState::Staged, "case {case}: staged");
        drop(alice);
        let mut next = reopen(&fs, &me);
        assert_eq!(next.keys().release_state(&e), ReleaseState::Staged, "case {case}: the open's check keeps it");
        let (published, fix) = push_public(&mut next);
        assert_eq!(published, vec![e.clone()], "case {case}");
        assert!(fix, "case {case}: the released fix is public");
    }
}

/// Two processes: one runs `vl embargo release` while the other opens the
/// repository over and over (each open runs the check). The release is
/// never taken back, and the next push publishes it.
#[test]
fn a_release_made_while_another_process_opens_the_repository_stands() {
    for round in 0..12 {
        let (alice, e, fs, me) = embargoed_reopenable();
        drop(alice);
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let opener = {
            let (fs, me, done) = (fs.clone(), me.clone(), done.clone());
            std::thread::spawn(move || {
                let mut opens = 0;
                while !done.load(std::sync::atomic::Ordering::SeqCst) || opens == 0 {
                    let _ = reopen(&fs, &me);
                    opens += 1;
                }
                opens
            })
        };
        let mut releaser = reopen(&fs, &me);
        releaser.release_embargo(&e).unwrap();
        done.store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(opener.join().unwrap() > 0, "the other process opened");
        assert_eq!(releaser.keys().release_state(&e), ReleaseState::Staged, "round {round}: staged");
        let mut next = reopen(&fs, &me);
        assert_eq!(next.keys().release_state(&e), ReleaseState::Staged, "round {round}: kept");
        let (published, fix) = push_public(&mut next);
        assert_eq!(published, vec![e.clone()], "round {round}");
        assert!(fix, "round {round}: public");
    }
}

/// BUG-1532 (op log merges review, cycle 4; introduced by BUG-1487's
/// fix): `vl gc --keep-ops-days` prunes the operation of a release staged
/// before the window, and the check at open, which looks for that
/// operation in the heads' history, takes the release back: the user's
/// release is lost without a word, and the next push leaves the fix
/// embargoed.
#[test]
fn bug_1532_a_staged_release_stays_staged_when_gc_prunes_its_operation() {
    let (mut alice, e, fs, me) = embargoed_reopenable();
    let main = alice.view().tags["main"].target;
    alice.release_embargo(&e).unwrap();
    for n in ["a", "b", "c"] {
        alice.set_tag(n, main, false).unwrap();
    }
    let report = veil_core::gc::gc(
        &mut alice,
        &veil_core::gc::GcOptions { keep_ops: Some(std::time::Duration::ZERO), now: Some(veil_core::now_millis() + 60_000), ..Default::default() },
    )
    .unwrap();
    assert!(report.ops_before > 3, "gc ran over the op log");
    assert_eq!(alice.keys().release_state(&e), ReleaseState::Staged, "staged after gc");
    drop(alice);
    let mut next = reopen(&fs, &me);
    assert_eq!(next.keys().release_state(&e), ReleaseState::Staged, "the release the user made is kept");
    let (published, fix) = push_public(&mut next);
    assert_eq!(published, vec![e.clone()]);
    assert!(fix, "the released fix is public");
}
