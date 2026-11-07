//! Adversarial tests: malicious remotes and tampered repositories.
//!
//! Every byte that comes from a remote, and every file under `.veil/`, is
//! treated as attacker-controlled. Tests assert the *secure* behaviour; tests
//! that currently fail are `#[ignore]`d with the BUG id from `docs/BUGS.md`.

use crate::adversarial_support;

use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    sync::Arc,
    time::Duration,
};

use adversarial_support::*;
use veil_core::{
    crypto::{random_key, Envelope},
    identity::wrap_key,
    keychain::{key_fingerprint, EmbargoRecord, KeyRing, RingMember},
    object::{Object, Visibility},
    oplog::Tag,
    remote,
    revset::resolve,
    tree::{lookup, walk_files},
    DiskBackend, Identity, MemoryBackend, ObjectId, Repo, StorageBackend,
};

// ---- hash verification ---------------------------------------------------

#[test]
fn pull_rejects_object_whose_content_does_not_match_its_id() {
    let (remote_fs, main) = evil_remote(|r| {
        let b = blob(r, b"honest content\n");
        raw_tree(r, vec![file("a.txt", b)])
    });
    // Replace the blob on the remote with different bytes at the same path.
    let remote = Repo::open(remote_fs.clone(), None, "x").unwrap();
    let tree = remote.snapshot(&main).unwrap().tree;
    let e = lookup(remote.store(), &tree, &p("a.txt")).unwrap().unwrap();
    plant_raw_object(&*remote_fs, &e.id, b"veil:blob\nmalicious content\n");

    let (mut victim, _fs, _) = new_repo("victim");
    let res = remote::pull(&mut victim, "origin", remote_fs);
    assert!(res.is_err(), "pull must fail on a hash mismatch");
    assert!(!victim.store().has(&e.id), "the forged object must not be stored");
    assert!(!victim.view().tags.contains_key("main"), "no tag may point at unverified history");
}

#[test]
fn pull_of_forged_cyclic_history_terminates_and_fails() {
    // Two snapshot "objects" planted under ids that claim each other as parent.
    let remote_fs = Arc::new(MemoryBackend::new());
    let mut remote = Repo::init_bare(remote_fs.clone()).unwrap();
    let a = ObjectId([0xaa; 32]);
    let b = ObjectId([0xbb; 32]);
    let empty = remote.store().empty_tree().unwrap();
    let mk = |parent: ObjectId| {
        format!(
            "veil:snap\n{{\"parents\":[\"{}\"],\"change_id\":\"{}\",\"tree\":\"{}\",\"description\":{{\"plain\":\"\"}},\"author\":\"m\",\"timestamp\":1}}",
            parent.hex(),
            "k".repeat(32),
            empty.hex()
        )
    };
    plant_raw_object(&*remote_fs, &a, mk(b).as_bytes());
    plant_raw_object(&*remote_fs, &b, mk(a).as_bytes());
    set_remote_tag(&mut remote, "main", a);

    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let (mut victim, _fs, _) = new_repo("victim");
        let r = remote::pull(&mut victim, "origin", remote_fs).map(|_| ());
        let _ = tx.send((r.is_err(), victim.view().tags.contains_key("main")));
    });
    let (failed, tagged) = rx.recv_timeout(Duration::from_secs(20)).expect("pull hung on a cyclic graph");
    assert!(failed, "forged history must be rejected");
    assert!(!tagged);
}

#[test]
fn local_cycle_in_tampered_store_does_not_hang_graph_queries() {
    let (mut repo, fs, _) = new_repo("alice");
    let a = ObjectId([0x11; 32]);
    let b = ObjectId([0x22; 32]);
    let empty = repo.store().empty_tree().unwrap();
    let mk = |parent: ObjectId| {
        format!(
            "veil:snap\n{{\"parents\":[\"{}\"],\"change_id\":\"{}\",\"tree\":\"{}\",\"description\":{{\"plain\":\"\"}},\"author\":\"m\",\"timestamp\":1}}",
            parent.hex(),
            "l".repeat(32),
            empty.hex()
        )
    };
    plant_raw_object(&*fs, &a, mk(b).as_bytes());
    plant_raw_object(&*fs, &b, mk(a).as_bytes());
    set_remote_tag(&mut repo, "loop", a);

    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = repo.visible_snapshots();
        let _ = repo.is_ancestor(&repo.root_id(), &a);
        let _ = resolve(&repo, "loop------------------", WS);
        let _ = repo.common_ancestor(&a, &repo.root_id());
        let _ = tx.send(());
    });
    rx.recv_timeout(Duration::from_secs(20)).expect("graph query hung on a cycle");
}

#[test]
fn tampered_local_object_is_detected_on_read() {
    let (mut repo, fs, _) = new_repo("alice");
    let c = commit_files(&mut repo, &*fs, &[("a.txt", "trusted\n")], "c");
    let e = file_entry(&repo, &c, "a.txt").unwrap();
    plant_raw_object(&*fs, &e.id, b"veil:blob\ntampered\n");
    let reopened = Repo::open(fs.clone(), None, "alice").unwrap();
    let r = reopened.store().read_blob(&e.id);
    assert!(r.is_err(), "content-addressed read returned bytes that do not hash to the id: {r:?}");
}

// ---- hostile tree entry names ---------------------------------------------

/// Repository + working copy on disk under a fresh temp dir. The working copy
/// lives in `<tmp>/wc`; anything appearing in `<tmp>` outside it escaped.
fn disk_victim() -> (tempfile::TempDir, Repo, Arc<DiskBackend>) {
    let tmp = tempfile::tempdir().unwrap();
    let wc = tmp.path().join("wc");
    std::fs::create_dir_all(&wc).unwrap();
    let fs = Arc::new(DiskBackend::new(&wc));
    let repo = Repo::init(fs.clone(), Some(Identity::generate("victim")), "victim").unwrap();
    (tmp, repo, fs)
}

fn escaped(tmp: &tempfile::TempDir) -> Vec<String> {
    std::fs::read_dir(tmp.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n != "wc")
        .collect()
}

fn try_pull_checkout(repo: &mut Repo, fs: &DiskBackend, remote: Arc<MemoryBackend>) -> Result<(), String> {
    match catch_unwind(AssertUnwindSafe(|| pull_and_checkout(repo, fs, remote))) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(format!("error: {e}")),
        Err(_) => Err("panic".into()),
    }
}

#[test]
fn dotdot_entry_cannot_escape_the_working_copy() {
    let (remote, _) = evil_remote(|r| {
        let payload = blob(r, b"owned\n");
        let inner = raw_tree(r, vec![file("PWNED", payload)]);
        raw_tree(r, vec![dir("..", inner)])
    });
    let (tmp, mut victim, fs) = disk_victim();
    let _ = try_pull_checkout(&mut victim, &fs, remote);
    assert_eq!(escaped(&tmp), Vec::<String>::new(), "checkout wrote outside the working copy");
}

#[test]
fn dotdot_file_entry_cannot_overwrite_a_sibling_file() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join("victim.txt"), "precious\n").unwrap();
    let (remote, _) = evil_remote(|r| {
        let payload = blob(r, b"clobbered\n");
        let inner = raw_tree(r, vec![file("victim.txt", payload)]);
        raw_tree(r, vec![dir("..", inner)])
    });
    let wc = tmp.path().join("wc");
    std::fs::create_dir_all(&wc).unwrap();
    let fs = Arc::new(DiskBackend::new(&wc));
    let mut victim = Repo::init(fs.clone(), Some(Identity::generate("v")), "v").unwrap();
    let _ = try_pull_checkout(&mut victim, &fs, remote);
    assert_eq!(std::fs::read_to_string(tmp.path().join("victim.txt")).unwrap(), "precious\n");
}

#[test]
fn remote_tree_cannot_write_into_dot_veil() {
    // Attacker ships `.veil/meta/keyrings/team.json` with a key ring of their
    // own (key substitution) and `.veil/repo.json` with a redirected remote.
    let (tmp, mut victim, fs) = disk_victim();
    let ring_before = std::fs::read(tmp.path().join("wc/.veil/meta/keyrings/team.json")).unwrap();
    let cfg_before = std::fs::read(tmp.path().join("wc/.veil/repo.json")).unwrap();
    let (remote, _) = evil_remote(|r| {
        let ring = blob(r, b"{\"scope\":\"team\",\"key_id\":\"\",\"members\":{}}");
        let cfg = blob(r, b"{\"format\":1,\"repo_id\":\"00\",\"remotes\":{\"origin\":{\"url\":\"/tmp/attacker\"}}}");
        let keyrings = raw_tree(r, vec![file("team.json", ring)]);
        let meta = raw_tree(r, vec![dir("keyrings", keyrings)]);
        let veil = raw_tree(r, vec![dir("meta", meta), file("repo.json", cfg)]);
        raw_tree(r, vec![dir(".veil", veil)])
    });
    let _ = try_pull_checkout(&mut victim, &fs, remote);
    assert_eq!(std::fs::read(tmp.path().join("wc/.veil/meta/keyrings/team.json")).unwrap(), ring_before);
    assert_eq!(std::fs::read(tmp.path().join("wc/.veil/repo.json")).unwrap(), cfg_before);
}

#[test]
fn slash_and_empty_entry_names_are_rejected_without_panicking() {
    for name in ["../../escaped", "a/../../escaped", "/abs", ""] {
        let (remote, _) = evil_remote(|r| {
            let payload = blob(r, b"x\n");
            raw_tree(r, vec![file(name, payload)])
        });
        let (tmp, mut victim, fs) = disk_victim();
        let r = try_pull_checkout(&mut victim, &fs, remote);
        assert_ne!(r, Err("panic".to_string()), "entry name {name:?} caused a panic");
        assert!(escaped(&tmp).is_empty(), "entry name {name:?} escaped");
        assert!(r.is_err(), "entry name {name:?} was accepted");
    }
}

#[test]
fn nul_in_entry_name_does_not_escape() {
    let (remote, _) = evil_remote(|r| {
        let payload = blob(r, b"x\n");
        raw_tree(r, vec![file("a\0b", payload)])
    });
    let (tmp, mut victim, fs) = disk_victim();
    let r = try_pull_checkout(&mut victim, &fs, remote);
    assert_ne!(r, Err("panic".to_string()));
    assert!(escaped(&tmp).is_empty());
}

#[test]
fn non_canonical_trees_are_rejected_or_consistent() {
    let (remote, main) = evil_remote(|r| {
        let a = blob(r, b"a\n");
        let b1 = blob(r, b"visible in listings\n");
        let b2 = blob(r, b"second\n");
        // unsorted: binary search can no longer find "c"
        raw_tree(r, vec![file("c", b1), file("b", b2), file("a", a)])
    });
    let (mut victim, _fs, _) = new_repo("v");
    if remote::pull(&mut victim, "origin", remote).is_err() {
        return; // rejecting is fine
    }
    let tree = victim.snapshot(&main).unwrap().tree;
    for (path, _) in walk_files(victim.store(), &tree).unwrap() {
        assert!(
            lookup(victim.store(), &tree, &path).unwrap().is_some(),
            "{path} is listed by walk_files but invisible to lookup/diff/checkout"
        );
    }
}

#[test]
fn entry_kind_contradicting_object_errors_cleanly() {
    // File entry pointing at a tree, dir entry pointing at a blob.
    for case in 0..2 {
        let (remote, _) = evil_remote(|r| {
            let b = blob(r, b"data\n");
            let t = raw_tree(r, vec![file("x", b)]);
            if case == 0 {
                raw_tree(r, vec![file("looks-like-file", t)])
            } else {
                raw_tree(r, vec![dir("looks-like-dir", b)])
            }
        });
        let (tmp, mut victim, fs) = disk_victim();
        let r = try_pull_checkout(&mut victim, &fs, remote);
        assert!(r.is_err(), "case {case}: contradictory entry kind accepted");
        assert_ne!(r, Err("panic".to_string()), "case {case}: panicked");
        assert!(escaped(&tmp).is_empty());
    }
}

// ---- forged key rings and embargo records ----------------------------------

fn remote_with_meta(meta: &[(&str, Vec<u8>)]) -> Arc<MemoryBackend> {
    let (remote, _) = evil_remote(|r| raw_tree(r, vec![]));
    for (path, data) in meta {
        remote.write(&p(path), data).unwrap();
    }
    remote
}

#[test]
fn ring_with_path_like_scope_does_not_crash_pull() {
    let ring = KeyRing {
        scope: "../../evil".into(),
        key_id: String::new(),
        members: Default::default(),
        ..Default::default()
    };
    let remote = remote_with_meta(&[(".veil/meta/keyrings/evil.json", serde_json::to_vec(&ring).unwrap())]);
    let (mut victim, _fs, _) = new_repo("v");
    let r = catch_unwind(AssertUnwindSafe(|| remote::pull(&mut victim, "origin", remote).map(|_| ())));
    assert!(r.is_ok(), "pull panicked on a forged key ring");
}

#[test]
fn embargo_record_with_path_like_id_does_not_crash_pull() {
    let rec = EmbargoRecord {
        format: veil_core::keychain::EMBARGO_FORMAT,
        id: "../../../x".into(),
        scope: "team".into(),
        until: None,
        released_at: Some(1),
        created: 1,
    };
    let remote = remote_with_meta(&[(".veil/meta/embargoes/x.json", serde_json::to_vec(&rec).unwrap())]);
    let (mut victim, _fs, _) = new_repo("v");
    let r = catch_unwind(AssertUnwindSafe(|| remote::pull(&mut victim, "origin", remote).map(|_| ())));
    assert!(r.is_ok(), "pull panicked on a forged embargo record");
}

#[test]
fn sealed_object_with_path_like_scope_does_not_crash_readers() {
    let (remote, main) = evil_remote(|r| {
        let env = Envelope::seal(&random_key(), "../../x", b"veil:blob\nhi", true).unwrap();
        let sealed = r.store().put(&Object::Sealed(env)).unwrap();
        let mut e = file("secret.txt", sealed);
        e.visibility = Visibility::Cloaked { scope: "../../x".into() };
        raw_tree(r, vec![e])
    });
    let (mut victim, fs, _) = new_repo("v");
    let r = catch_unwind(AssertUnwindSafe(|| {
        let _ = pull_and_checkout(&mut victim, &*fs, remote.clone());
        let _ = victim.store().read_entry(&file_entry(&victim, &main, "secret.txt").unwrap());
    }));
    assert!(r.is_ok(), "reading a sealed object with a hostile scope panicked");
}

#[test]
fn ring_with_different_key_for_existing_scope_is_not_merged() {
    let (mut victim, _fs, me) = new_repo("v");
    let before = victim.keys().load_ring("team").unwrap().unwrap();
    let evil_key = random_key();
    let mut ring = KeyRing {
        scope: "team".into(),
        key_id: key_fingerprint(&evil_key),
        members: Default::default(),
        ..Default::default()
    };
    ring.members.insert(
        me.public_hex(),
        RingMember {
            name: "v".into(),
            wrapped: wrap_key(&me.public_key(), &evil_key, "team").unwrap(),
        },
    );
    let remote = remote_with_meta(&[(".veil/meta/keyrings/team.json", serde_json::to_vec(&ring).unwrap())]);
    let rep = remote::pull(&mut victim, "origin", remote).unwrap();
    assert!(!rep.warnings.is_empty());
    assert_eq!(victim.keys().load_ring("team").unwrap().unwrap(), before);
}

#[test]
fn ring_with_empty_key_id_cannot_replace_existing_scope_key() {
    let (mut victim, _fs, me) = new_repo("v");
    let real = victim.keys().key("team").unwrap();
    let evil_key = random_key();
    let mut ring = KeyRing {
        scope: "team".into(),
        key_id: String::new(),
        members: Default::default(),
        ..Default::default()
    };
    ring.members.insert(
        me.public_hex(),
        RingMember {
            name: "v".into(),
            wrapped: wrap_key(&me.public_key(), &evil_key, "team").unwrap(),
        },
    );
    let remote = remote_with_meta(&[(".veil/meta/keyrings/team.json", serde_json::to_vec(&ring).unwrap())]);
    let _ = remote::pull(&mut victim, "origin", remote);
    victim.keys().invalidate();
    assert_eq!(victim.keys().key("team").unwrap(), real, "scope key was substituted");
}

/// Embargoed merge of a fix developed in its own workspace. Returns (alice,
/// wc fs, embargo id).
fn embargoed_setup() -> (Repo, Arc<MemoryBackend>, String) {
    use veil_core::commands::EmbargoSpec;
    let (mut alice, fs, _) = new_repo("alice");
    let main = commit_files(&mut alice, &*fs, &[("auth.rs", "fn check() -> bool { true }\n")], "v1");
    alice.set_tag("main", main, false).unwrap();
    alice.create_workspace("fix", vec![main]).unwrap();
    let ov = alice.workspace_overlay("fix").unwrap();
    ov.write(&p("auth.rs"), b"fn check() -> bool { verify_signature() }\n").unwrap();
    let fix = alice.snapshot_workspace("fix", &ov).unwrap().snapshot;
    let res = alice
        .merge(WS, main, vec![fix], "merge", Some(EmbargoSpec { scope: "team".into(), until: None }))
        .unwrap();
    // Alice's working copy shows the merged content.
    let wc = alice.workspace_wc(WS).unwrap();
    let to = alice.snapshot(&wc).unwrap().tree;
    alice.checkout_tree(&*fs, Some(&alice.snapshot(&main).unwrap().tree), &to).unwrap();
    (alice, fs, res.embargo.unwrap())
}

/// The embargoed merge, and a follow-up on it, stay off the mirror until
/// the release; then the mirror receives them.
#[test]
fn embargo_from_cloaked_branch_stays_hidden_until_release() {
    let (mut alice, fs, embargo) = embargoed_setup();
    snap(&mut alice, &*fs);
    alice.commit_working_copy(WS, "unrelated follow-up").unwrap();
    let mirror = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, mirror.clone(), true, &["main".to_string()], false).unwrap();
    assert!(backend_contains(&*mirror, b"verify_signature").is_empty());
    let pubrepo = Repo::open(mirror.clone(), Some(Identity::generate("anon")), "anon").unwrap();
    assert!(!pubrepo.view().tags.contains_key("main"), "main moved onto the embargoed merge was pushed");
    let main = alice.view().tags["main"].target;
    assert!(pubrepo.snapshot_opt(&main).unwrap().is_none());
    // after a genuine release the mirror sees the fix
    alice.release_embargo(&embargo).unwrap();
    remote::push(&mut alice, mirror.clone(), true, &["main".to_string()], false).unwrap();
    let pubrepo = Repo::open(mirror, Some(Identity::generate("anon")), "anon").unwrap();
    assert!(String::from_utf8(read_at(&pubrepo, &main, "auth.rs")).unwrap().contains("verify_signature"));
}

#[test]
fn pulled_tag_pointing_at_missing_object_does_not_brick_the_repo() {
    let remote_fs = Arc::new(MemoryBackend::new());
    let mut remote = Repo::init_bare(remote_fs.clone()).unwrap();
    let mut tx = remote.transaction("evil").unwrap();
    tx.view.tags.insert("main".into(), Tag::new(ObjectId([7; 32])));
    tx.commit().unwrap();
    let (mut victim, _fs, _) = new_repo("v");
    let pulled = remote::pull(&mut victim, "origin", remote_fs);
    if pulled.is_ok() {
        assert!(
            victim.visible_snapshots().is_ok(),
            "a dangling remote tag was accepted and now breaks every graph query"
        );
    }
}

#[test]
fn tag_cannot_point_at_a_non_snapshot_object() {
    let (mut repo, fs, _) = new_repo("alice");
    let c = commit_files(&mut repo, &*fs, &[("a.txt", "a\n")], "c");
    let blob_id = file_entry(&repo, &c, "a.txt").unwrap().id;
    let _ = repo.set_tag("bad", blob_id, false);
    assert!(repo.visible_snapshots().is_ok(), "view now references a blob as a tag target");
}

// ---- hostile snapshot metadata ---------------------------------------------
