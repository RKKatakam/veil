//! What a `vl ws mount` records, at the engine level: its recordings are
//! never commands of the user's (`undo`, `redo` and `op restore` skip them
//! and keep what they recorded, BUG-538), and a working copy recorded on
//! top of an older snapshot judges what a command put back against the
//! entries it was written from (BUG-492).

use crate::adversarial_support;

use adversarial_support::*;
use veil_core::{
    object::Visibility,
    workspace::{mount_record_op_description, SnapshotOptions},
    ObjectId, Repo, StorageBackend,
};

/// Record `files` into workspace `ws` as its mount does.
fn mount_records(repo: &mut Repo, ws: &str, files: &[(&str, &str)]) -> ObjectId {
    let o = repo.workspace_overlay(ws).unwrap();
    for (path, data) in files {
        o.write(&p(path), data.as_bytes()).unwrap();
    }
    let out = repo
        .snapshot_workspace_with(
            ws,
            &o,
            SnapshotOptions {
                description: Some(mount_record_op_description(ws)),
                ..Default::default()
            },
        )
        .unwrap();
    assert!(out.changed);
    out.snapshot
}

fn has(repo: &Repo, ws: &str, path: &str) -> bool {
    file_entry(repo, &repo.workspace_wc(ws).unwrap(), path).is_some()
}

fn parent_has(repo: &Repo, path: &str) -> bool {
    let wc = repo.snapshot(&repo.workspace_wc(WS).unwrap()).unwrap();
    file_entry(repo, &wc.parents[0], path).is_some()
}

#[test]
fn undo_redo_and_op_restore_skip_mount_recordings_and_keep_them() {
    let (mut repo, fs, _) = new_repo("alice");
    let base = commit_files(&mut repo, &*fs, &[("a.txt", "a\n")], "base");
    repo.create_workspace("agent", vec![base], None).unwrap();
    let before_commit = repo.op_id();
    commit_files(&mut repo, &*fs, &[("c.txt", "c\n")], "project commit");
    assert!(parent_has(&repo, "c.txt"));

    // The mount records its work, then the user's `vl undo` runs (its own
    // automatic snapshot first).
    mount_records(&mut repo, "agent", &[("work.txt", "agent work\n")]);
    snap(&mut repo, &*fs);
    let (_, undone) = repo.undo_keeping_edits(WS).unwrap();
    assert_ne!(undone, mount_record_op_description("agent"), "undo undid the mount's recording");
    assert!(!parent_has(&repo, "c.txt"), "the commit the user meant to undo stays ({undone})");
    assert!(has(&repo, "agent", "work.txt"), "the mount's work was thrown away");

    // More work in the mount; redo re-applies the commit and keeps it.
    mount_records(&mut repo, "agent", &[("more.txt", "more\n")]);
    let (_, redone) = repo.redo_keeping_edits(WS).unwrap();
    assert_ne!(redone, mount_record_op_description("agent"));
    assert!(parent_has(&repo, "c.txt"), "redo did not re-apply the commit ({redone})");
    assert!(has(&repo, "agent", "work.txt") && has(&repo, "agent", "more.txt"));

    // `op restore` goes to the exact state picked, but what the mount
    // recorded since the last command (its recording before `op restore`
    // itself runs) is kept, as the project directory's edits are.
    mount_records(&mut repo, "agent", &[("last.txt", "last\n")]);
    repo.restore_operation_keeping_edits(WS, before_commit).unwrap();
    assert!(!parent_has(&repo, "c.txt"));
    assert!(has(&repo, "agent", "last.txt"), "op restore threw away the mount's new work");
}

/// A recording of any workspace's mount is skipped, whichever workspace
/// is attached; the automatic snapshot of *another* workspace is not (it
/// is a command there: `vl ws write`).
#[test]
fn only_mount_recordings_and_the_own_snapshot_are_skipped() {
    let (mut repo, fs, _) = new_repo("alice");
    let base = commit_files(&mut repo, &*fs, &[("a.txt", "a\n")], "base");
    repo.create_workspace("agent", vec![base], None).unwrap();
    let o = repo.workspace_overlay("agent").unwrap();
    o.write(&p("w.txt"), b"w\n").unwrap();
    repo.snapshot_workspace("agent", &o).unwrap();
    let (_, undone) = repo.undo_keeping_edits(WS).unwrap();
    assert_eq!(undone, "snapshot working copy of 'agent'");
    // A look-alike with an invalid workspace name is not a mount's.
    let o = repo.workspace_overlay("agent").unwrap();
    o.write(&p("x.txt"), b"x\n").unwrap();
    repo.snapshot_workspace_with(
        "agent",
        &o,
        SnapshotOptions {
            description: Some("record the mount of workspace 'a b'".into()),
            ..Default::default()
        },
    )
    .unwrap();
    let (_, undone) = repo.undo_keeping_edits(WS).unwrap();
    assert_eq!(undone, "record the mount of workspace 'a b'");
}

/// BUG-492: `vl restore` wrote a sealed version into the directory, and
/// another process moved the workspace before it was recorded. The
/// recovery records the directory on top of the snapshot it held; the
/// restored file must keep its audience there too.
#[test]
fn a_restored_sealed_version_stays_sealed_on_the_recovery_path() {
    let (mut repo, fs, _) = new_repo("alice");
    let base = commit_files(&mut repo, &*fs, &[("f.txt", "public\n")], "base");
    repo.create_workspace("sec", vec![base], Some("team".into())).unwrap();
    let o = repo.workspace_overlay("sec").unwrap();
    o.write(&p("f.txt"), b"SEALED-0492\n").unwrap();
    let sealed_at = repo.snapshot_workspace("sec", &o).unwrap().snapshot;
    let sealed = file_entry(&repo, &sealed_at, "f.txt").unwrap();
    assert_eq!(sealed.visibility, Visibility::Cloaked { scope: "team".into() });

    // What `vl restore -r sec@ f.txt` wrote.
    fs.write(&p("f.txt"), b"SEALED-0492\n").unwrap();
    let held = repo.workspace_wc(WS).unwrap();
    let carried = [(p("f.txt"), sealed.clone())];
    let entry_of = |repo: &Repo, tree: ObjectId| veil_core::tree::lookup(repo.store(), &tree, &p("f.txt")).unwrap().unwrap();

    // Control: without the restored entries the version reads as a public
    // edit of `f.txt`.
    let (tree, _) = repo.build_amending(&*fs, &held, None, None).unwrap();
    assert!(entry_of(&repo, tree).visibility.is_public());

    let (tree, _) = repo.build_amending_carried(&*fs, &held, None, None, &carried).unwrap();
    assert_eq!(entry_of(&repo, tree), sealed);
    let (saved, _) = repo
        .commit_fs_as_child_with(held, &*fs, "recovered working-copy edits", None, None, &carried, false)
        .unwrap();
    let saved_tree = repo.snapshot(&saved).unwrap().tree;
    assert_eq!(entry_of(&repo, saved_tree), sealed, "the recovered change made the sealed version public");
}
