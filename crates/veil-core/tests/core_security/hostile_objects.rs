//! Objects from remotes and from `.veil/` are hostile: structural validation
//! on decode, verified reads, repair of damaged objects, bounded tree depth
//! and tag targets. Complements `adversarial_remote.rs` (BUG-001, -002,
//! -021, -028 to -031 and -033 in `docs/BUGS.md`).

use crate::adversarial_support;

use std::{sync::Arc, time::Duration};

use adversarial_support::*;
use veil_core::{
    crypto::{random_key, Envelope, MAX_SCOPE_LEN},
    gc::{gc, GcOptions},
    object::{validate_entry_name, Object, Tree},
    remote,
    revset::resolve,
    tree::{diff_trees, walk_files, MAX_TREE_DEPTH},
    MemoryBackend, ObjectId, Repo, StorageBackend,
};

fn tree_bytes(json: &str) -> Vec<u8> {
    let mut raw = b"veil:tree\n".to_vec();
    raw.extend_from_slice(json.as_bytes());
    raw
}

// ---- tree validation on decode -----------------------------------------------

#[test]
fn entry_names_are_validated() {
    for bad in ["", ".", "..", "a/b", "/", "a\0b", ".veil", ".VEIL", ".Veil"] {
        assert!(validate_entry_name(bad).is_err(), "{bad:?} accepted");
    }
    for good in ["a", ".veilpolicy", "..a", "a..", "veil", ".veil.bak", "x\u{1b}y", "é"] {
        assert!(validate_entry_name(good).is_ok(), "{good:?} refused");
    }
}

#[test]
fn reserved_and_malformed_trees_are_refused_on_decode() {
    let (repo, _fs, _) = new_repo("v");
    let b = blob(&repo, b"x\n");
    for entries in [
        vec![dir(".veil", b)],
        vec![file(".VEIL", b)],
        vec![file("a", b), file("a", b)],
        vec![file("b", b), file("a", b)],
        vec![file("..", b)],
    ] {
        let t = Tree { entries };
        assert!(Object::decode(&Object::Tree(t.clone()).encode()).is_err(), "{t:?} decoded");
        assert!(repo.store().put_tree(&t).is_err(), "put_tree wrote {t:?}");
    }
}

#[test]
fn non_canonical_tree_encodings_are_refused() {
    let (repo, _fs, _) = new_repo("v");
    let b = blob(&repo, b"x\n");
    let canonical = Object::Tree(Tree { entries: vec![file("a", b)] }).encode();
    assert!(Object::decode(&canonical).is_ok());
    let json = std::str::from_utf8(&canonical[b"veil:tree\n".len()..]).unwrap();
    for variant in [
        json.replace(':', ": "),                                // whitespace
        json.replace("\"kind\":\"file\"", "\"kind\":\"file\",\"x\":1"), // unknown field
        json.replace("\"kind\":\"file\"", "\"kind\":\"file\",\"size\":0"), // explicit default
    ] {
        assert_ne!(variant, json);
        assert!(Object::decode(&tree_bytes(&variant)).is_err(), "{variant} decoded");
    }
}

#[test]
fn nested_dot_veil_is_refused_at_any_depth_on_pull() {
    let (remote, _) = evil_remote(|r| {
        let ring = blob(r, b"{}");
        let veil = raw_tree(r, vec![file("repo.json", ring)]);
        let sub = raw_tree(r, vec![dir(".veil", veil)]);
        raw_tree(r, vec![dir("sub", sub)])
    });
    let (mut victim, _fs, _) = new_repo("v");
    assert!(remote::pull(&mut victim, "origin", remote).is_err());
    assert!(!victim.view().tags.contains_key("main"));
}

#[test]
fn builder_never_records_dot_veil_directories() {
    let (mut repo, fs, _) = new_repo("v");
    fs.write(&p("sub/.veil/repo.json"), b"{}").unwrap();
    fs.write(&p("sub/.VEIL/x"), b"x").unwrap();
    fs.write(&p("sub/nested.txt"), b"nested\n").unwrap();
    fs.write(&p("sub/kept.txt"), b"kept\n").unwrap();
    // A directory holding a `.veil` is a repository of its own, left out
    // as a whole (BUG-200); a stray `.veil` file is skipped alone.
    fs.write(&p("other/.veil"), b"not a repository\n").unwrap();
    fs.write(&p("other/kept.txt"), b"kept\n").unwrap();
    let out = repo.snapshot_workspace(WS, &*fs).unwrap();
    assert_eq!(out.report.nested, vec![p("sub")]);
    let wc = out.snapshot;
    let tree = repo.snapshot(&wc).unwrap().tree;
    let files: Vec<String> = walk_files(repo.store(), &tree)
        .unwrap()
        .into_iter()
        .map(|(p, _)| p.as_str().to_string())
        .collect();
    assert!(files.contains(&"other/kept.txt".to_string()), "{files:?}");
    assert!(!files.iter().any(|f| f.starts_with("sub/")), "{files:?}");
    assert!(!files.iter().any(|f| f.to_ascii_lowercase().contains(".veil")), "{files:?}");
}

// ---- verified reads and repair --------------------------------------------------

#[test]
fn damaged_object_is_repaired_by_pulling_it_again() {
    let (mut alice, afs, _) = new_repo("alice");
    let c = commit_files(&mut alice, &*afs, &[("a.txt", "trusted\n")], "c");
    alice.set_tag("main", c, None, true).unwrap();
    let remote_fs = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, remote_fs.clone(), false, &[], false).unwrap();

    let (mut bob, bfs, _) = new_repo("bob");
    remote::pull(&mut bob, "origin", remote_fs.clone()).unwrap();
    let e = file_entry(&bob, &c, "a.txt").unwrap();
    plant_raw_object(&*bfs, &e.id, b"veil:blob\ntampered\n");
    let bob = Repo::open(bfs.clone(), None, "bob").unwrap();
    assert!(bob.store().read_blob(&e.id).is_err(), "tampered copy served");

    // A plain pull trusts what the local committed view reaches; repair is
    // the explicit full pull, which re-verifies every local copy.
    let mut bob = bob;
    remote::pull_with(&mut bob, "origin", remote_fs, &remote::SyncOptions { full: true, ..Default::default() }).unwrap();
    assert_eq!(bob.store().read_blob(&e.id).unwrap(), b"trusted\n");
}

#[test]
fn put_replaces_a_corrupt_loose_copy() {
    let (repo, fs, _) = new_repo("v");
    let id = repo.store().put(&Object::Blob(b"good\n".to_vec())).unwrap();
    plant_raw_object(&*fs, &id, b"veil:blob\nbad\n");
    assert!(repo.store().get_raw(&id).is_err());
    let raw = Object::Blob(b"good\n".to_vec()).encode();
    assert!(repo.store().put_raw(&id, &raw).unwrap(), "verified copy must be written");
    assert_eq!(repo.store().get_raw(&id).unwrap(), raw);
    assert!(!repo.store().put_raw(&id, &raw).unwrap(), "good copy is kept");
}

#[test]
fn corrupt_loose_copy_falls_back_to_a_good_packed_copy() {
    let (mut repo, fs, _) = new_repo("v");
    let c = commit_files(&mut repo, &*fs, &[("a.txt", "packed\n")], "c");
    let e = file_entry(&repo, &c, "a.txt").unwrap();
    gc(&mut repo, &GcOptions { grace: Duration::ZERO, ..GcOptions::default() }).unwrap();
    assert_eq!(repo.store().stats().unwrap().loose_objects, 0);
    plant_raw_object(&*fs, &e.id, b"veil:blob\nshadow\n");
    let reopened = Repo::open(fs.clone(), None, "v").unwrap();
    assert_eq!(reopened.store().read_blob(&e.id).unwrap(), b"packed\n");
}

// ---- tree depth ------------------------------------------------------------------

fn chain(r: &Repo, leaf: ObjectId, levels: usize) -> ObjectId {
    let mut t = leaf;
    for _ in 0..levels {
        t = raw_tree(r, vec![dir("d", t)]);
    }
    t
}

#[test]
fn trees_up_to_the_depth_limit_are_accepted_and_usable() {
    let (remote, main) = evil_remote(|r| {
        let leaf = raw_tree(r, vec![file("leaf", blob(r, b"x\n"))]);
        chain(r, leaf, MAX_TREE_DEPTH - 1)
    });
    let (mut victim, _fs, _) = new_repo("v");
    remote::pull(&mut victim, "origin", remote).unwrap();
    let tree = victim.snapshot(&main).unwrap().tree;
    assert_eq!(walk_files(victim.store(), &tree).unwrap().len(), 1);
    assert_eq!(diff_trees(victim.store(), None, Some(&tree)).unwrap().len(), 1);
}

#[test]
fn trees_deeper_than_the_limit_are_refused() {
    let (remote, _) = evil_remote(|r| {
        let leaf = raw_tree(r, vec![file("leaf", blob(r, b"x\n"))]);
        chain(r, leaf, MAX_TREE_DEPTH)
    });
    let (mut victim, _fs, _) = new_repo("v");
    let err = remote::pull(&mut victim, "origin", remote).unwrap_err();
    assert!(err.to_string().contains("nesting"), "{err}");
    assert!(!victim.view().tags.contains_key("main"));
}

#[test]
fn depth_limit_sees_through_shared_subtrees() {
    // `a` is a deep-ish subtree seen first at depth 1; `b` reaches the same
    // subtree again below a long chain. A depth check that skips objects
    // it has already seen would miss that the total exceeds the limit.
    let (remote, _) = evil_remote(|r| {
        let leaf = raw_tree(r, vec![file("leaf", blob(r, b"x\n"))]);
        let shared = chain(r, leaf, MAX_TREE_DEPTH / 2);
        let deep = chain(r, shared, MAX_TREE_DEPTH / 2 + 10);
        raw_tree(r, vec![dir("a", shared), dir("b", deep)])
    });
    let (mut victim, _fs, _) = new_repo("v");
    assert!(remote::pull(&mut victim, "origin", remote).is_err());
}

#[test]
fn deep_local_trees_do_not_overflow_the_stack_in_walks() {
    // Tampered `.veil/`: a local tree far deeper than any remote may send.
    // Walks must be iterative; run on a small stack to prove it.
    let (repo, _fs, _) = new_repo("v");
    let leaf = raw_tree(&repo, vec![file("leaf", blob(&repo, b"x\n"))]);
    let deep = chain(&repo, leaf, 20_000);
    let store = repo.store().clone();
    std::thread::Builder::new()
        .stack_size(256 << 10)
        .spawn(move || {
            assert_eq!(walk_files(&store, &deep).unwrap().len(), 1);
            assert_eq!(diff_trees(&store, None, Some(&deep)).unwrap().len(), 1);
            assert_eq!(diff_trees(&store, Some(&deep), None).unwrap().len(), 1);
        })
        .unwrap()
        .join()
        .unwrap();
}

// ---- tags --------------------------------------------------------------------------

#[test]
fn set_tag_refuses_trees_and_revsets_refuse_non_snapshots() {
    let (mut repo, fs, _) = new_repo("alice");
    let c = commit_files(&mut repo, &*fs, &[("a.txt", "a\n")], "c");
    let tree = repo.snapshot(&c).unwrap().tree;
    assert!(repo.set_tag("t", tree, None, true).is_err());
    let blob_id = file_entry(&repo, &c, "a.txt").unwrap().id;
    assert!(resolve(&repo, &blob_id.hex(), WS).is_err(), "a blob id resolved as a revision");
    assert_eq!(resolve(&repo, &c.hex(), WS).unwrap(), c);
}

#[test]
fn pull_skips_tags_with_hostile_names_or_non_snapshot_targets() {
    let (remote_fs, main) = evil_remote(|r| raw_tree(r, vec![file("a", blob(r, b"a\n"))]));
    let mut remote = Repo::open(remote_fs.clone(), None, "remote").unwrap();
    let tree = remote.snapshot(&main).unwrap().tree;
    set_remote_tag(&mut remote, "v1\x1b[2Kx", main);
    set_remote_tag(&mut remote, "points-at-tree", tree);
    let (mut victim, _fs, _) = new_repo("v");
    let report = remote::pull(&mut victim, "origin", remote_fs).unwrap();
    let tags: Vec<&String> = victim.view().tags.keys().collect();
    assert!(tags.iter().any(|t| *t == "main"), "{tags:?}");
    assert!(!tags.iter().any(|t| t.contains('\x1b') || *t == "points-at-tree"), "{tags:?}");
    assert!(!victim.view().remote_tags.keys().any(|t| t.contains('\x1b') || t.ends_with("points-at-tree")));
    assert!(victim.visible_snapshots().is_ok());
    assert!(report.warnings.iter().all(|w| !w.contains('\x1b')), "{:?}", report.warnings);
    assert_eq!(report.warnings.iter().filter(|w| w.contains("skipped remote tag")).count(), 2);
}

// ---- envelopes --------------------------------------------------------------------------

#[test]
fn envelope_scope_length_limit_is_exact() {
    let k = random_key();
    for deterministic in [true, false] {
        let env = Envelope::seal(&k, &"s".repeat(MAX_SCOPE_LEN), b"hi", deterministic).unwrap();
        // The object tag says which construction the bytes hold.
        let obj = Object::Sealed(env.clone());
        assert_eq!(Object::decode(&obj.encode()).unwrap(), obj);
        assert!(Envelope::seal(&k, &"s".repeat(MAX_SCOPE_LEN + 1), b"hi", deterministic).is_err());
    }
    let legacy = Envelope::seal_deterministic_legacy(&k, &"s".repeat(MAX_SCOPE_LEN), b"hi").unwrap();
    assert_eq!(Envelope::from_bytes(&legacy.to_bytes()).unwrap(), legacy);
    assert!(Envelope::seal_deterministic_legacy(&k, &"s".repeat(MAX_SCOPE_LEN + 1), b"hi").is_err());
}

#[test]
fn checkout_of_a_tree_naming_dot_veil_is_impossible_even_from_a_tampered_store() {
    // A tree planted locally (bypassing pull) still cannot be read.
    let (mut repo, fs, _) = new_repo("v");
    let b = blob(&repo, b"{\"evil\":true}");
    let veil = raw_tree(&repo, vec![file("repo.json", b)]);
    let root = raw_tree(&repo, vec![dir(".veil", veil)]);
    let before = fs.read(&p(".veil/repo.json")).unwrap();
    let old = repo.snapshot(&repo.workspace_wc(WS).unwrap()).unwrap().tree;
    assert!(repo.checkout_tree(&*fs, Some(&old), &root).is_err());
    assert_eq!(fs.read(&p(".veil/repo.json")).unwrap(), before);
    let _ = &mut repo;
}
