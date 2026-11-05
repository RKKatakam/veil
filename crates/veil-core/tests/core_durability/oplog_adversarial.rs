//! Adversarial pass on the lock-free op log (scale stream O): what the
//! threat-review tests in `oplog_concurrency` miss. Each test is the
//! reproduction of a `docs/BUGS.md` row ("Scale round: adversarial pass on
//! stream O").

use crate::adversarial_support;
use crate::oplog_concurrency::{assert_fsck_clean, concurrently, open};

use adversarial_support::*;
use veil_core::{
    oplog::{Operation, Tag, View, OP_HEADS_DIR},
    ObjectId, StorageBackend,
};

/// Write an operation with the given parents, timestamp and view, as a
/// process would publish it, and return its id.
fn put_op(repo: &veil_core::Repo, parents: Vec<ObjectId>, timestamp: i64, view: View, description: &str) -> ObjectId {
    repo.ops()
        .put(&Operation {
            parents,
            timestamp,
            user: "alice".into(),
            description: description.into(),
            view,
            manual_undo: None,
            undo_of: None,
            redo_of: None,
            workspace: None,
            rewritten: Default::default(),
        })
        .unwrap()
}

fn head_file(id: &ObjectId) -> veil_core::VPath {
    p(&format!("{OP_HEADS_DIR}/{}", id.hex()))
}

// ---- an undone rewrite is applied again by the next merge ----------------------------

/// `vl abandon X; vl undo` in one workspace while anything else (here a tag
/// set) lands concurrently: the merge re-applies the undone abandon, and the
/// working copy loses X again.
#[test]
#[ignore = "BUG-802: a merge re-applies a rewrite that its side undid"]
fn undone_abandon_is_not_redone_by_a_concurrent_merge() {
    let (mut repo, fs, id) = new_repo("alice");
    repo.set_command_workspace(Some(WS.into()));
    let base = commit_files(&mut repo, &*fs, &[("f", "1\n")], "base");
    let x = commit_files(&mut repo, &*fs, &[("x.txt", "X-CONTENT-ABANDONED-THEN-RESTORED\n")], "x");
    drop(repo);
    concurrently(
        &fs,
        &id,
        |r| {
            r.set_command_workspace(Some(WS.into()));
            r.abandon(x).unwrap();
            let (_, undone) = r.undo_keeping_edits(WS).unwrap();
            assert!(undone.starts_with("abandon"), "{undone}");
            let wc = r.workspace_wc(WS).unwrap();
            assert!(r.is_ancestor(&x, &wc).unwrap(), "the undo itself restored X");
        },
        |r| r.set_tag("unrelated", base, None, false).unwrap(),
    );
    let r = open(&fs, &id);
    let wc = r.workspace_wc(WS).unwrap();
    assert!(r.view().tags.contains_key("unrelated"));
    assert!(r.is_ancestor(&x, &wc).unwrap(), "the merge abandoned X again after its abandon was undone");
    assert_eq!(read_at(&r, &wc, "x.txt"), b"X-CONTENT-ABANDONED-THEN-RESTORED\n");
    assert_fsck_clean(fs.clone(), &id, "after the merge");
}

/// The same with an amend (`vl describe`): the undone rewrite comes back,
/// and the working copy moves onto the amended change the user undid.
#[test]
#[ignore = "BUG-802: a merge re-applies a rewrite that its side undid"]
fn undone_amend_is_not_redone_by_a_concurrent_merge() {
    let (mut repo, fs, id) = new_repo("alice");
    repo.set_command_workspace(Some(WS.into()));
    let base = commit_files(&mut repo, &*fs, &[("f", "1\n")], "base");
    let x = commit_files(&mut repo, &*fs, &[("x.txt", "x\n")], "x");
    drop(repo);
    concurrently(
        &fs,
        &id,
        |r| {
            r.set_command_workspace(Some(WS.into()));
            r.describe(x, "x, amended then undone").unwrap();
            r.undo_keeping_edits(WS).unwrap();
            let wc = r.workspace_wc(WS).unwrap();
            assert_eq!(r.snapshot(&wc).unwrap().parents, vec![x], "the undo itself restored X");
        },
        |r| r.set_tag("unrelated", base, None, false).unwrap(),
    );
    let r = open(&fs, &id);
    let wc = r.workspace_wc(WS).unwrap();
    assert_eq!(r.snapshot(&wc).unwrap().parents, vec![x], "the merge re-applied the undone amend");
}

// ---- the merge base is lost when one side's history spans more than an hour -------

/// A command that ran for over an hour (a long pull, a suspended `vl`)
/// lands beside a line of commands that started right after it did. The
/// ancestry walk gives up an hour below the newest heads, so the merge finds
/// no common operation and merges against an empty view: a tag deleted on
/// one side comes back (and is pushed by the next `vl push`).
#[test]
#[ignore = "BUG-803: the merge base is not found below the one-hour ancestry floor"]
fn merge_base_is_found_below_the_ancestry_slack() {
    let (mut repo, fs, id) = new_repo("alice");
    let base = commit_files(&mut repo, &*fs, &[("f", "1\n")], "base");
    repo.set_tag("withdrawn", base, None, false).unwrap();
    let h = repo.heads()[0];
    let hop = repo.ops().get(&h).unwrap();
    let t0 = hop.timestamp;
    const HOUR: i64 = 60 * 60 * 1000;
    // One side: a minute after H, the tag is deleted; two hours later,
    // another command.
    let mut v1 = hop.view.clone();
    v1.tags.remove("withdrawn");
    let a1 = put_op(&repo, vec![h], t0 + 60_000, v1.clone(), "delete tag withdrawn");
    let mut v2 = v1.clone();
    v2.tags.insert("a".into(), Tag::new(base, None));
    let o1 = put_op(&repo, vec![a1], t0 + 2 * HOUR, v2, "set tag a");
    // The other: one long command that started from H.
    let mut v3 = hop.view.clone();
    v3.tags.insert("b".into(), Tag::new(base, None));
    let o2 = put_op(&repo, vec![h], t0 + 2 * HOUR + 1, v3, "pull from origin");
    drop(repo);
    fs.remove_file(&head_file(&h)).unwrap();
    fs.write(&head_file(&o1), b"").unwrap();
    fs.write(&head_file(&o2), b"").unwrap();
    let r = open(&fs, &id);
    let tags = &r.view().tags;
    assert!(tags.contains_key("a") && tags.contains_key("b"), "{:?}", tags.keys());
    assert!(!tags.contains_key("withdrawn"), "a deleted tag came back: the merge used an empty base");
}

// ---- a merge that fails for a policy reason, forever --------------------------------

/// A side commit in `ws` on top of its working copy: write `files` there,
/// record and commit. Returns the commit.
fn commit_in(r: &mut veil_core::Repo, ws: &str, files: &[(&str, &str)], msg: &str) -> ObjectId {
    let ov = r.workspace_overlay(ws).unwrap();
    for (path, data) in files {
        ov.write(&p(path), data.as_bytes()).unwrap();
    }
    r.snapshot_workspace(ws, &ov).unwrap();
    r.commit_working_copy(ws, msg).unwrap().0
}

/// One side moves change Y onto an embargoed merge (Y joins embargo E1);
/// the other, at the same time, merges a second fix into Y's line under its
/// own embargo E2. Each is allowed on its own view. The merge's rebase of
/// E2's merge onto the moved Y then combines two unreleased embargoes,
/// which `merge_trees` refuses: the merge fails, and since every command
/// merges the heads first (at open), every command fails from then on.
#[test]
#[ignore = "BUG-805: a merge whose rebase is refused fails every later command"]
fn merge_combining_two_embargoes_degrades_instead_of_failing_forever() {
    let (mut repo, fs, id) = new_repo("alice");
    let v1 = commit_files(&mut repo, &*fs, &[("a.c", "v\n")], "v1");
    repo.set_tag("main", v1, None, false).unwrap();
    for ws in ["rel", "fix1", "fix2"] {
        repo.create_workspace(ws, vec![v1], None).unwrap();
    }
    let y = commit_in(&mut repo, "rel", &[("rel.c", "release line\n")], "y");
    let fix1 = commit_in(&mut repo, "fix1", &[("FIXONE-NAME-Q4.c", "FIXONE-BODY-Q4\n")], "fix one");
    let fix2 = commit_in(&mut repo, "fix2", &[("FIXTWO-NAME-Q4.c", "FIXTWO-BODY-Q4\n")], "fix two");
    drop(repo);
    let spec = || Some(veil_core::commands::EmbargoSpec { scope: "team".into(), until: None });
    concurrently(
        &fs,
        &id,
        |r| {
            let m1 = r.merge(WS, v1, vec![fix1], "embargoed one", spec()).unwrap().snapshot;
            r.rebase(y, vec![m1]).unwrap();
        },
        |r| {
            r.merge("rel", y, vec![fix2], "embargoed two", spec()).unwrap();
        },
    );
    let mut r = veil_core::Repo::open(fs.clone(), Some(id.clone()), &id.name).expect("every command fails: the merge of the heads fails");
    let w = r.take_warnings();
    assert!(w.iter().any(|w| w.contains("left on its old parents")), "{w:?}");
    for msg in &w {
        assert!(!msg.contains("FIXONE") && !msg.contains("FIXTWO"), "a warning names a fix: {msg}");
    }
    let (c, _) = r.commit_working_copy(WS, "later").unwrap();
    r.set_tag("later", c, None, false).unwrap();
    let mirror = std::sync::Arc::new(veil_core::MemoryBackend::new());
    veil_core::remote::push(&mut r, mirror.clone(), true, &[], false).unwrap();
    for n in ["FIXONE-NAME-Q4", "FIXONE-BODY-Q4", "FIXTWO-NAME-Q4", "FIXTWO-BODY-Q4"] {
        assert!(backend_contains(&*mirror, n.as_bytes()).is_empty(), "{n} reached the public remote");
    }
    assert_fsck_clean(fs.clone(), &id, "after the merge");
}

/// The same empty-base merge through pruning: a long command started from
/// operation H; meanwhile two commands landed (a tag deleted, a tag set) and
/// `vl gc --keep-ops-days 0` pruned H (it keeps the heads and their
/// parents only). The long command then publishes an operation whose parent
/// is gone, and the merge has no common operation: the deleted tag returns.
#[test]
#[ignore = "BUG-804: an operation whose base was pruned meanwhile is merged against an empty view"]
fn transaction_whose_base_was_pruned_does_not_merge_against_nothing() {
    let (mut repo, fs, id) = new_repo("alice");
    let base = commit_files(&mut repo, &*fs, &[("f", "1\n")], "base");
    repo.set_tag("withdrawn", base, None, false).unwrap();
    drop(repo);
    let mut long = open(&fs, &id);
    let mut tx = long.transaction("pull from origin").unwrap();
    tx.view.tags.insert("pulled".into(), Tag::new(base, None));
    {
        let mut other = open(&fs, &id);
        other.delete_tag("withdrawn").unwrap();
        other.set_tag("a", base, None, false).unwrap();
        let mut g = open(&fs, &id);
        let opts = veil_core::gc::GcOptions {
            keep_ops: Some(std::time::Duration::ZERO),
            // A minute later: every operation is older than the window.
            now: Some(veil_core::now_millis() + 60_000),
            ..Default::default()
        };
        veil_core::gc::gc(&mut g, &opts).unwrap();
    }
    let committed = tx.commit();
    if let Err(e) = &committed {
        assert!(e.to_string().contains("run the command again"), "{e}");
    }
    drop(long);
    let r = open(&fs, &id);
    let tags = &r.view().tags;
    assert!(!tags.contains_key("withdrawn"), "a deleted tag came back (commit: {committed:?})");
    assert!(tags.contains_key("a"));
}
