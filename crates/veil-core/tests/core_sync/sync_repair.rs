//! Repository-to-repository sync (the engine's in-process transfer):
//! crash leftovers (objects present without their closure) are completed,
//! and a receiver that holds a snapshot without some of its content gets
//! that content from a sender that has it.

use crate::adversarial_support;

use std::sync::Arc;

use adversarial_support::*;
use veil_core::{remote, tree::walk_files, Identity, MemoryBackend, ObjectId, Repo, StorageBackend};

fn history(repo: &mut Repo, fs: &MemoryBackend, n: usize) -> ObjectId {
    let mut last = repo.root_id();
    for i in 0..n {
        let files: Vec<(String, String)> = (0..5)
            .map(|f| (format!("src/m{f}/file{}.rs", (i + f) % 7), format!("// rev {i}\n{}", "fn x() {}\n".repeat(40 + f))))
            .collect();
        let refs: Vec<(&str, &str)> = files.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
        last = commit_files(repo, fs, &refs, &format!("c{i}"));
    }
    repo.set_tag("main", last, None, true).unwrap();
    last
}

fn files(repo: &Repo, id: &ObjectId) -> Vec<(String, Vec<u8>)> {
    let tree = repo.snapshot(id).unwrap().tree;
    walk_files(repo.store(), &tree)
        .unwrap()
        .into_iter()
        .map(|(p, e)| (p.to_string(), repo.store().read_entry(&e).unwrap_or_default()))
        .collect()
}

fn fsck_ok(fs: Arc<dyn StorageBackend>) {
    let r = veil_core::fsck::fsck(fs, None).unwrap();
    assert!(r.is_ok(), "{:#?}", r.findings);
}

#[test]
fn a_crash_leftover_on_the_remote_is_not_mistaken_for_pushed_history() {
    let (mut alice, fs, _) = new_repo("alice");
    let main = history(&mut alice, &fs, 3);
    let remote = Arc::new(MemoryBackend::new());
    // A crashed push left the snapshot object behind, but not its tree.
    let r = Repo::init_bare(remote.clone()).unwrap();
    let raw = alice.store().get_raw(&main).unwrap();
    r.store().put_raw(&main, &raw).unwrap();
    drop(r);
    remote::push(&mut alice, remote.clone(), false, &[], false).unwrap();
    fsck_ok(remote.clone());
    let (mut bob, _, _) = new_repo("bob");
    remote::pull(&mut bob, "origin", remote).unwrap();
    assert_eq!(files(&bob, &main), files(&alice, &main));
}

#[test]
fn a_crash_leftover_locally_is_completed_by_pull() {
    let (mut alice, fs, _) = new_repo("alice");
    let main = history(&mut alice, &fs, 3);
    let remote = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, remote.clone(), false, &[], false).unwrap();
    // Bob's earlier pull crashed after writing the snapshot only.
    let (mut bob, bfs, _) = new_repo("bob");
    bob.store().put_raw(&main, &alice.store().get_raw(&main).unwrap()).unwrap();
    remote::pull(&mut bob, "origin", remote).unwrap();
    assert_eq!(files(&bob, &main), files(&alice, &main));
    fsck_ok(bfs);
}

#[test]
fn a_clone_of_a_public_mirror_gets_the_ciphertext_from_the_team_remote() {
    let (mut alice, fs, _) = new_repo("alice");
    let bob_id = Identity::generate("bob");
    alice.keys().grant("team", &bob_id.public_id(), "bob").unwrap();
    fs.write(&p(".veilpolicy"), b"secret/ cloak team\n").unwrap();
    let c = commit_files(&mut alice, &*fs, &[("secret/plan.md", "the plan\n"), ("README", "hi\n")], "c");
    alice.set_tag("main", c, None, true).unwrap();
    let mirror = Arc::new(MemoryBackend::new());
    let team = Arc::new(MemoryBackend::new());
    let pub_report = remote::push(&mut alice, mirror.clone(), true, &[], false).unwrap();
    assert!(pub_report.redacted > 0);
    remote::push(&mut alice, team.clone(), false, &[], false).unwrap();

    let bfs = Arc::new(MemoryBackend::new());
    let mut bob = Repo::init_for_clone(bfs.clone(), Some(bob_id), "bob").unwrap();
    remote::pull(&mut bob, "mirror", mirror).unwrap();
    assert!(read_entry_opt(&bob, &c, "secret/plan.md").is_none(), "the mirror has no ciphertext");
    // Same snapshots, so nothing new at the snapshot level: the gap below
    // already-known snapshots is still filled.
    remote::pull(&mut bob, "team", team).unwrap();
    assert_eq!(read_entry_opt(&bob, &c, "secret/plan.md").as_deref(), Some(&b"the plan\n"[..]));
}

fn read_entry_opt(repo: &Repo, rev: &ObjectId, path: &str) -> Option<Vec<u8>> {
    repo.store().read_entry(&file_entry(repo, rev, path)?).ok()
}
