//! BUG-121: a recorded *directory* named `.veilpolicy`, pushed by a hostile
//! teammate, must never block checkout, snapshots or merges for everyone
//! who pulls it. Where a tree's policy cannot be read, the member's
//! accepted policy applies, with a warning.

use crate::adversarial_support;

use std::sync::Arc;

use adversarial_support::*;
use veil_core::{remote, Identity, MemoryBackend, ObjectId, Repo, StorageBackend};

const POLICY: &str = "*.secret isolate\n";

/// Alice's project (`.veilpolicy` isolating `*.secret`, a local-only
/// `db.secret`), pushed to `hub`; Mallory then pushes `main` forward by a
/// snapshot whose `.veilpolicy` is a directory. Returns (alice, her fs,
/// hub, her main, Mallory's main).
fn hostile_policy_dir() -> (Repo, Arc<MemoryBackend>, Arc<MemoryBackend>, ObjectId, ObjectId) {
    let (mut alice, fs, _) = new_repo("alice");
    fs.write(&p(".veilpolicy"), POLICY.as_bytes()).unwrap();
    fs.write(&p("db.secret"), b"password=hunter2-local-only\n").unwrap();
    let main = commit_files(&mut alice, &*fs, &[("README", "hi\n")], "v1");
    assert!(file_entry(&alice, &main, "db.secret").is_none());
    alice.set_tag("main", main, false).unwrap();
    let hub = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, hub.clone(), false, &[], false).unwrap();

    let mut m = Repo::init_for_clone(Arc::new(MemoryBackend::new()), Some(Identity::generate("mallory")), "mallory").unwrap();
    remote::pull(&mut m, "origin", hub.clone()).unwrap();
    let store = m.store().clone();
    let mut root = (*store.tree(&m.snapshot(&main).unwrap().tree).unwrap()).clone();
    let inner = raw_tree(&m, vec![file("rules", blob(&m, b"** public!\n"))]);
    root.insert(dir(".veilpolicy", inner));
    root.insert(file("NEWS", blob(&m, b"news\n")));
    let tree = store.put_tree(&root).unwrap();
    let evil = raw_snapshot(&m, vec![main], tree, "docs: news");
    m.set_tag("main", evil, true).unwrap();
    remote::push(&mut m, hub.clone(), false, &["main".into()], false).unwrap();
    (alice, fs, hub, main, evil)
}

#[test]
fn checkout_of_a_tree_whose_policy_is_a_directory_goes_ahead() {
    let (mut alice, fs, hub, _, _) = hostile_policy_dir();
    pull_and_checkout(&mut alice, &*fs, hub).expect("checkout of the hostile tree is blocked");
    assert_eq!(fs.read(&p("NEWS")).unwrap(), b"news\n");
    // Alice's local-only file is untouched, and still never recorded.
    assert_eq!(fs.read(&p("db.secret")).unwrap(), b"password=hunter2-local-only\n");
    fs.write(&p("README"), b"hi again\n").unwrap();
    let out = alice.snapshot_workspace(WS, &*fs).expect("snapshot after the checkout is blocked");
    assert!(file_entry(&alice, &out.snapshot, "db.secret").is_none(), "the hostile tree published db.secret");
    assert!(
        out.report.policy_warnings.iter().any(|w| w.contains(".veilpolicy")),
        "no warning about the unreadable policy: {:?}",
        out.report.policy_warnings
    );
}

#[test]
fn checkout_reports_the_unreadable_policy() {
    let (mut alice, fs, hub, _, _) = hostile_policy_dir();
    remote::pull(&mut alice, "origin", hub).unwrap();
    let main = alice.view().tags["main"].target;
    let old = alice.snapshot(&alice.workspace_wc(WS).unwrap()).unwrap().tree;
    let wc = alice.new_change(WS, vec![main], "").unwrap();
    let to = alice.snapshot(&wc).unwrap().tree;
    let report = alice.checkout_tree(&*fs, Some(&old), &to).unwrap();
    assert!(
        report.warnings.iter().any(|w| w.contains(".veilpolicy") && w.contains("directory")),
        "{:?}",
        report.warnings
    );
}

#[test]
fn merging_a_line_whose_policy_is_a_directory_goes_ahead() {
    let (mut alice, fs, hub, main, evil) = hostile_policy_dir();
    // `vl commit` moves `main` along; Mallory's `main` is `origin/main`.
    let mine = commit_files(&mut alice, &*fs, &[("mine.txt", "mine\n")], "mine");
    remote::pull(&mut alice, "origin", hub).unwrap();
    assert_eq!(alice.view().remote_tags.get("origin/main"), Some(&evil));
    assert_ne!(evil, main);
    let r = alice.merge(WS, mine, vec![evil], "merge main", None).expect("the merge is blocked");
    assert!(file_entry(&alice, &r.snapshot, "NEWS").is_some());
    assert!(file_entry(&alice, &r.snapshot, "mine.txt").is_some());
    assert!(r.warnings.iter().any(|w| w.contains(".veilpolicy")), "{:?}", r.warnings);
}
