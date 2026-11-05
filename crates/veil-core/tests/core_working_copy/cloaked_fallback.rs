//! A public file edited on a cloaked line is sealed with its **last public
//! version** as `fallback` (BUG-074). Readers without the key (public
//! remotes, members of other scopes) see that version, never a
//! deletion; the edit itself stays sealed. A file the policy cloaks
//! deliberately (`vl cloak`) carries no fallback.

use crate::adversarial_support;

use std::sync::Arc;

use adversarial_support::*;
use veil_core::{
    object::{TreeEntry, Visibility},
    remote,
    vfs::OverlayBackend,
    Identity, MemoryBackend, ObjectId, Repo, StorageBackend,
};

const TEAM: &str = "team";

fn cloaked() -> Visibility {
    Visibility::Cloaked { scope: TEAM.into() }
}

struct Setup {
    alice: Repo,
    fs: Arc<MemoryBackend>,
    main: ObjectId,
}

/// Alice: README.md and lib.rs public, committed and tagged `main`; a
/// cloaked workspace `p` on top of it.
fn setup() -> Setup {
    let (mut alice, fs, _) = new_repo("alice");
    let main = commit_files(&mut alice, &*fs, &[("README.md", "hello\n"), ("lib.rs", "fn a() {}\n")], "v1");
    alice.set_tag("main", main, None, false).unwrap();
    alice.create_workspace("p", vec![main], Some(TEAM.into())).unwrap();
    Setup { alice, fs, main }
}

/// Write `files` in workspace `ws` (an overlay over its working copy),
/// record them, and commit. Returns the commit.
fn commit_in(repo: &mut Repo, ws: &str, files: &[(&str, &str)], msg: &str) -> ObjectId {
    let overlay: OverlayBackend = repo.workspace_overlay(ws).unwrap();
    for (path, data) in files {
        overlay.write(&p(path), data.as_bytes()).unwrap();
    }
    repo.snapshot_workspace(ws, &overlay).unwrap();
    repo.commit(ws, msg, true).unwrap().committed
}

fn entry(repo: &Repo, rev: &ObjectId, path: &str) -> TreeEntry {
    file_entry(repo, rev, path).unwrap_or_else(|| panic!("{path} missing"))
}

/// A replica of `from` (pulled as a team remote) for `name`, who holds no
/// key for `team`.
fn outsider(name: &str, from: Arc<MemoryBackend>) -> (Repo, Arc<MemoryBackend>) {
    let fs = Arc::new(MemoryBackend::new());
    let mut r = Repo::init_for_clone(fs.clone(), Some(Identity::generate(name)), name).unwrap();
    remote::pull(&mut r, "origin", from).unwrap();
    (r, fs)
}

#[test]
fn a_cloaked_edit_of_a_public_file_keeps_its_last_public_version_as_fallback() {
    let Setup { mut alice, main, .. } = setup();
    let public = entry(&alice, &main, "README.md");
    let c1 = commit_in(&mut alice, "p", &[("README.md", "hello\nsecret plan\n")], "edit");
    let e = entry(&alice, &c1, "README.md");
    assert_eq!((e.visibility.clone(), e.fallback), (cloaked(), Some(public.id)));
    assert_eq!(read_at(&alice, &c1, "README.md"), b"hello\nsecret plan\n");
    // A new file of the cloaked line has no public version.
    let c2 = commit_in(&mut alice, "p", &[("README.md", "hello\nsecret plan 2\n"), ("new.rs", "x\n")], "more");
    assert_eq!(entry(&alice, &c2, "new.rs").fallback, None);
    // A second edit keeps the *public* version, not the first sealed one.
    assert_eq!(entry(&alice, &c2, "README.md").fallback, Some(public.id));
    // An untouched public file stays public.
    assert_eq!(entry(&alice, &c2, "lib.rs"), entry(&alice, &main, "lib.rs"));

    // Edited back to the public version: public again, nothing sealed.
    let c3 = commit_in(&mut alice, "p", &[("README.md", "hello\n")], "revert");
    let e = entry(&alice, &c3, "README.md");
    assert_eq!((e.visibility, e.id, e.fallback), (Visibility::Public, public.id, None));
}

#[test]
fn a_reader_without_the_key_sees_the_public_version_and_cannot_delete_or_overwrite_the_edit() {
    let Setup { mut alice, fs, .. } = setup();
    let c1 = commit_in(&mut alice, "p", &[("README.md", "hello\nCLOAKED-PLAN\n")], "edit");
    alice.set_tag("main", c1, None, false).unwrap();
    let sealed = entry(&alice, &c1, "README.md");

    let (mut bob, bob_fs) = outsider("bob", fs);
    bob.new_change(WS, vec![c1], "").unwrap();
    let tree = bob.snapshot(&c1).unwrap().tree;
    bob.checkout_tree(&*bob_fs, None, &tree).unwrap();
    assert_eq!(bob_fs.read(&p("README.md")).unwrap(), b"hello\n");
    let out = bob.snapshot_workspace(WS, &*bob_fs).unwrap();
    assert!(!out.changed, "{:?}", out.report);

    // An edit Bob cannot seal is held back; the sealed entry stays.
    bob_fs.write(&p("README.md"), b"hello from bob\n").unwrap();
    let out = bob.snapshot_workspace(WS, &*bob_fs).unwrap();
    assert!(out.report.cloak_failures.iter().any(|(p, _)| p.as_str() == "README.md"), "{:?}", out.report);
    assert_eq!(entry(&bob, &out.snapshot, "README.md"), sealed);

    // Deleting the copy he was shown does not delete the sealed content.
    bob_fs.remove_file(&p("README.md")).unwrap();
    let out = bob.snapshot_workspace(WS, &*bob_fs).unwrap();
    assert_eq!(entry(&bob, &out.snapshot, "README.md"), sealed);
}

#[test]
fn rebase_onto_a_public_edit_takes_the_newer_public_version_as_fallback() {
    let Setup { mut alice, fs, main } = setup();
    let c1 = commit_in(&mut alice, "p", &[("README.md", "hello\nsecret\n")], "edit");
    // Meanwhile main gets a public edit of the same file.
    let main2 = commit_files(&mut alice, &*fs, &[("README.md", "title\nhello\n")], "title");
    assert_eq!(alice.view().tags["main"].target, main2);
    let public2 = entry(&alice, &main2, "README.md");
    let r = alice.rebase(c1, vec![main2]).unwrap();
    let e = entry(&alice, &r, "README.md");
    assert_eq!((e.visibility.clone(), e.fallback), (cloaked(), Some(public2.id)));
    assert_eq!(read_at(&alice, &r, "README.md"), b"title\nhello\nsecret\n");
    let _ = main;
}

#[test]
fn squashing_into_a_cloaked_change_keeps_the_public_version_as_fallback() {
    let Setup { mut alice, main, .. } = setup();
    let x = alice.workspace_wc("p").unwrap();
    // A plain change on top of the cloaked one edits README.md.
    alice.create_workspace("q", vec![x], None).unwrap();
    let overlay = alice.workspace_overlay("q").unwrap();
    overlay.write(&p("README.md"), b"hello\nfrom q\n").unwrap();
    alice.snapshot_workspace("q", &overlay).unwrap();
    let child = alice.workspace_wc("q").unwrap();
    let folded = alice.squash(child).unwrap();
    let e = entry(&alice, &folded, "README.md");
    assert_eq!((e.visibility, e.fallback), (cloaked(), Some(entry(&alice, &main, "README.md").id)));
}

/// Write `files` in workspace `ws` and record them (no commit). Returns
/// the working-copy change.
fn record_in(repo: &mut Repo, ws: &str, files: &[(&str, &str)]) -> ObjectId {
    let overlay: OverlayBackend = repo.workspace_overlay(ws).unwrap();
    for (path, data) in files {
        overlay.write(&p(path), data.as_bytes()).unwrap();
    }
    repo.snapshot_workspace(ws, &overlay).unwrap().snapshot
}

/// The entry `path` has in the merged tree of `rev`'s parents.
fn base_entry(repo: &Repo, rev: &ObjectId, path: &str) -> Option<TreeEntry> {
    let parents = repo.snapshot(rev).unwrap().parents.clone();
    let base = repo.parents_tree(&parents).unwrap().tree;
    veil_core::tree::lookup(repo.store(), &base, &p(path)).unwrap()
}

/// Control for BUG-128: editing a sealed edit back to the public version
/// its base holds records nothing new; the entry is the base's again.
#[test]
fn a_cloaked_edit_reverted_to_the_bases_public_version_is_the_bases_entry() {
    let Setup { mut alice, main, .. } = setup();
    record_in(&mut alice, "p", &[("README.md", "hello\nsecret\n")]);
    let wc = record_in(&mut alice, "p", &[("README.md", "hello\n")]);
    assert_eq!(entry(&alice, &wc, "README.md"), entry(&alice, &main, "README.md"));
}

/// BUG-128: a sealed edit whose fallback is a public version its line's
/// base does *not* hold (the change was rebased onto a base without the
/// file), edited back to that version, stays sealed: a public entry there
/// would be public content the cloaked line introduces.
#[test]
fn a_cloaked_edit_reverted_to_a_fallback_its_base_lacks_stays_sealed() {
    let Setup { mut alice, fs, main } = setup();
    let public = entry(&alice, &main, "README.md");
    record_in(&mut alice, "p", &[("README.md", "hello\nsecret\n")]);
    let wc = alice.workspace_wc("p").unwrap();
    // Onto a public change that removed README.md.
    fs.remove_file(&p("README.md")).unwrap();
    let no_readme = commit_files(&mut alice, &*fs, &[], "drop the readme");
    assert!(file_entry(&alice, &no_readme, "README.md").is_none());
    let r = alice.rebase(wc, vec![no_readme]).unwrap();
    assert_eq!(alice.workspace_wc("p").unwrap(), r);
    let e = file_entry(&alice, &r, "README.md");
    // However the rebase settled it, editing back to the old public version
    // must not put a public entry on the line that its base lacks.
    let wc = record_in(&mut alice, "p", &[("README.md", "hello\n")]);
    let e2 = entry(&alice, &wc, "README.md");
    assert_eq!(base_entry(&alice, &wc, "README.md"), None);
    assert_eq!(e2.visibility, cloaked(), "before: {e:?}");
    assert_eq!(e2.fallback, Some(public.id));
    assert_eq!(read_at(&alice, &wc, "README.md"), b"hello\n");
}

#[test]
fn a_file_cloaked_by_policy_has_no_public_fallback() {
    let Setup { mut alice, fs, .. } = setup();
    let c = commit_files(&mut alice, &*fs, &[(".veilpolicy", "README.md cloak team\n"), ("README.md", "hello\nnow private\n")], "cloak it");
    let e = entry(&alice, &c, "README.md");
    assert_eq!((e.visibility, e.fallback), (cloaked(), None));
}
