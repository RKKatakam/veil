//! A public file edited on a cloaked line is sealed with its **last public
//! version** as `fallback` (BUG-074). Readers without the key (public
//! remotes, Git export, members of other scopes) see that version, never a
//! deletion; the edit itself stays sealed. A file the policy cloaks
//! deliberately (`vl cloak`) carries no fallback.

mod adversarial_support;

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

#[test]
fn a_file_cloaked_by_policy_has_no_public_fallback() {
    let Setup { mut alice, fs, .. } = setup();
    let c = commit_files(&mut alice, &*fs, &[(".veilpolicy", "README.md cloak team\n"), ("README.md", "hello\nnow private\n")], "cloak it");
    let e = entry(&alice, &c, "README.md");
    assert_eq!((e.visibility, e.fallback), (cloaked(), None));
}
