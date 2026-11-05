//! Incremental push and pull: what the receiver's committed view reaches is
//! never sent again, new objects travel as one pack, and crash leftovers
//! (objects present without their closure) never count as "already there".

use crate::adversarial_support;

use std::sync::Arc;

use adversarial_support::*;
use veil_core::{
    object::Object,
    remote::{self, SyncOptions},
    tree::walk_files,
    Identity, MemoryBackend, ObjectId, Repo, StorageBackend,
};

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
fn a_second_push_sends_nothing_and_a_new_commit_sends_only_itself() {
    let (mut alice, fs, _) = new_repo("alice");
    let main = history(&mut alice, &fs, 30);
    let remote = Arc::new(MemoryBackend::new());
    let first = remote::push(&mut alice, remote.clone(), false, &[], false).unwrap();
    assert!(first.objects_copied > 100, "{first:?}");
    assert_eq!(first.packs_written, 1, "one push, one pack");
    let r = Repo::open(remote.clone(), None, "r").unwrap();
    let stats = r.store().stats().unwrap();
    assert_eq!(stats.packs, 1);
    assert!(stats.loose_objects <= 2, "only the bare repository's own objects are loose: {stats:?}");
    assert_eq!(r.view().tags["main"].target, main);
    fsck_ok(remote.clone());

    let again = remote::push(&mut alice, remote.clone(), false, &[], false).unwrap();
    assert_eq!((again.objects_copied, again.packs_written), (0, 0), "{again:?}");

    let next = commit_files(&mut alice, &*fs, &[("src/m0/file3.rs", "changed\n")], "one more");
    alice.set_tag("main", next, None, false).unwrap();
    let inc = remote::push(&mut alice, remote.clone(), false, &[], false).unwrap();
    // snapshot, root tree, src/, src/m0/, the blob
    assert_eq!(inc.objects_copied, 5, "{inc:?}");
    assert_eq!(inc.tags_updated, vec![("main".to_string(), next)]);
    fsck_ok(remote.clone());

    let (mut bob, _, _) = new_repo("bob");
    remote::pull(&mut bob, "origin", remote.clone()).unwrap();
    assert_eq!(files(&bob, &next), files(&alice, &next));
}

#[test]
fn pull_fetches_only_what_the_local_view_does_not_reach() {
    let (mut alice, fs, _) = new_repo("alice");
    history(&mut alice, &fs, 20);
    let remote = Arc::new(MemoryBackend::new());
    remote::push(&mut alice, remote.clone(), false, &[], false).unwrap();

    let (mut bob, bfs, _) = new_repo("bob");
    let clone = remote::pull(&mut bob, "origin", remote.clone()).unwrap();
    assert!(clone.objects_copied > 100);
    assert_eq!(clone.packs_written, 1, "a big pull is stored as a pack");
    fsck_ok(bfs.clone());
    assert_eq!(remote::pull(&mut bob, "origin", remote.clone()).unwrap().objects_copied, 0);

    let next = commit_files(&mut alice, &*fs, &[("README", "new\n")], "readme");
    alice.set_tag("main", next, None, false).unwrap();
    remote::push(&mut alice, remote.clone(), false, &[], false).unwrap();
    let inc = remote::pull(&mut bob, "origin", remote.clone()).unwrap();
    assert_eq!(inc.objects_copied, 3, "snapshot, root tree, blob: {inc:?}");
    assert_eq!(inc.packs_written, 0, "a small pull stays loose");
    assert_eq!(files(&bob, &next), files(&alice, &next));
    fsck_ok(bfs);
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

#[test]
fn versions_of_a_file_travel_as_deltas() {
    let (mut alice, fs, _) = new_repo("alice");
    // 200 lines of hex (plain zstd roughly halves it); each version edits one.
    let mut lines: Vec<String> = (0..200u32).map(|i| ObjectId::hash(&i.to_le_bytes()).hex()).collect();
    let mut last = alice.root_id();
    let versions = 40;
    for v in 0..versions {
        lines[(v * 7) % 200] = ObjectId::hash(format!("v{v}").as_bytes()).hex();
        last = commit_files(&mut alice, &*fs, &[("doc.txt", &lines.join("\n"))], &format!("v{v}"));
    }
    alice.set_tag("main", last, None, true).unwrap();
    let remote = Arc::new(MemoryBackend::new());
    let r = remote::push(&mut alice, remote.clone(), false, &[], false).unwrap();
    let raw = versions as u64 * 200 * 65;
    assert!(r.bytes_transferred < raw / 8, "{} bytes for {raw} bytes of versions", r.bytes_transferred);
    let (mut bob, _, _) = new_repo("bob");
    remote::pull(&mut bob, "origin", remote).unwrap();
    assert_eq!(files(&bob, &last), files(&alice, &last));
}

#[test]
fn full_sync_still_walks_and_verifies_everything() {
    let (mut alice, fs, _) = new_repo("alice");
    history(&mut alice, &fs, 5);
    let remote = Arc::new(MemoryBackend::new());
    let full = SyncOptions { full: true, ..Default::default() };
    let first = remote::push_with(&mut alice, remote.clone(), false, &[], false, &full).unwrap();
    assert!(first.objects_copied > 20);
    assert_eq!(first.packs_written, 0, "the full walk writes loose objects");
    // Damage one object on the remote: a full push repairs it.
    let r = Repo::open(remote.clone(), None, "r").unwrap();
    let victim = r
        .store()
        .list_loose()
        .unwrap()
        .into_iter()
        .find(|id| Object::is_blob_raw(&r.store().get_raw(id).unwrap()))
        .unwrap();
    let h = victim.hex();
    remote
        .write(&p(&format!(".veil/objects/{}/{}", &h[..2], &h[2..])), b"veil:blob\nbroken")
        .unwrap();
    let again = remote::push_with(&mut alice, remote.clone(), false, &[], false, &full).unwrap();
    assert_eq!(again.objects_copied, 1, "exactly the damaged object is rewritten");
    fsck_ok(remote);
}
