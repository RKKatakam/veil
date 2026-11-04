//! Push, pull and clone through `SftpBackend` against a real OpenSSH
//! `sftp-server`, including a connection cut at every stage of a push,
//! concurrent pushers, takeover of a crashed client's lock, and a public
//! remote that never receives a cloaked byte.

mod adversarial_support;
mod sftp_support;

use std::{path::Path, sync::Arc};

use adversarial_support::{commit_files, file_entry, new_repo, p, WS};
use sftp_support::{budget, connect, try_connect_with, Shim};
use veil_core::{
    commands::EmbargoSpec,
    lock::LOCK_PATH,
    object::Object,
    remote,
    tree::walk_files,
    DiskBackend, Identity, MemoryBackend, ObjectId, Repo, StorageBackend,
};

macro_rules! need_server {
    () => {
        match sftp_support::server() {
            Some(s) => s,
            None => return,
        }
    };
}

fn files(repo: &Repo, id: &ObjectId) -> Vec<(String, Vec<u8>)> {
    let tree = repo.snapshot(id).unwrap().tree;
    walk_files(repo.store(), &tree)
        .unwrap()
        .into_iter()
        .map(|(p, e)| (p.to_string(), repo.store().read_entry(&e).unwrap_or_default()))
        .collect()
}

fn history(repo: &mut Repo, fs: &MemoryBackend, from: usize, n: usize) -> ObjectId {
    let mut last = repo.root_id();
    for i in from..from + n {
        let a = format!("rev {i}\n{}", "data ".repeat(200 + i));
        let b = format!("other {i}\n");
        last = commit_files(repo, fs, &[(&format!("src/f{}.txt", i % 9), &a), ("README", &b)], &format!("c{i}"));
    }
    repo.set_tag("main", last, None, true).unwrap();
    last
}

/// The remote checked directly on disk: it opens, and `fsck` is clean.
fn assert_remote_healthy(dir: &Path, ctx: &str) -> Repo {
    let fs: Arc<dyn StorageBackend> = Arc::new(DiskBackend::new(dir));
    let r = veil_core::fsck::fsck(fs.clone(), None).unwrap();
    assert!(r.is_ok(), "{ctx}: {:#?}", r.findings);
    Repo::open(fs, None, "check").unwrap()
}

fn clone_over_sftp(server: &Path, dir: &Path, name: &str) -> Repo {
    let fs = Arc::new(MemoryBackend::new());
    let mut r = Repo::init_for_clone(fs, Some(Identity::generate(name)), name).unwrap();
    remote::pull(&mut r, "origin", Arc::new(connect(server, dir))).unwrap();
    r
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let t = to.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_dir(&e.path(), &t);
        } else {
            std::fs::copy(e.path(), t).unwrap();
        }
    }
}

#[test]
fn push_pull_and_clone_over_sftp() {
    let server = need_server!();
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("repos/proj"); // created by the first push
    let (mut alice, afs, _) = new_repo("alice");
    let main = history(&mut alice, &afs, 0, 12);

    let rep = remote::push(&mut alice, Arc::new(connect(&server, &root)), false, &[], false).unwrap();
    assert_eq!(rep.tags_updated, vec![("main".to_string(), main)]);
    assert_eq!(rep.packs_written, 1);
    assert!(!root.join(LOCK_PATH).exists(), "lock released");
    let on_disk = assert_remote_healthy(&root, "after push");
    assert_eq!(on_disk.view().tags["main"].target, main);

    let mut bob = clone_over_sftp(&server, &root, "bob");
    assert_eq!(files(&bob, &main), files(&alice, &main));

    // Bob commits and pushes; Alice pulls just that.
    let bfs = Arc::new(MemoryBackend::new());
    let mut bob2 = Repo::init_for_clone(bfs.clone(), Some(Identity::generate("bob")), "bob").unwrap();
    remote::pull(&mut bob2, "origin", Arc::new(connect(&server, &root))).unwrap();
    let wc = bob2.new_change(WS, vec![main], "").unwrap();
    let to = bob2.snapshot(&wc).unwrap().tree;
    bob2.checkout_tree(&*bfs, None, &to).unwrap();
    let next = commit_files(&mut bob2, &*bfs, &[("NEW", "from bob\n")], "bob's change");
    bob2.set_tag("main", next, None, false).unwrap();
    let pushed = remote::push(&mut bob2, Arc::new(connect(&server, &root)), false, &[], false).unwrap();
    assert!(pushed.objects_copied <= 4, "{pushed:?}");
    let conn = Arc::new(connect(&server, &root));
    let pulled = remote::pull(&mut alice, "origin", conn.clone()).unwrap();
    assert_eq!(pulled.tags_updated, vec![("main".to_string(), next)]);
    assert_eq!(files(&alice, &next), files(&bob2, &next));
    // An up-to-date pull costs a fixed number of requests (open the
    // remote, list its objects, merge metadata), not a few per object as
    // the full walk does.
    let before = conn.stats().requests;
    assert_eq!(remote::pull(&mut alice, "origin", conn.clone()).unwrap().objects_copied, 0);
    let incremental = conn.stats().requests - before;
    let before = conn.stats().requests;
    let full = remote::SyncOptions { full: true };
    remote::pull_with(&mut alice, "origin", conn.clone(), &full).unwrap();
    let walked = conn.stats().requests - before;
    assert!(incremental * 4 < walked, "{incremental} requests vs {walked} for the full walk");
    remote::pull(&mut bob, "origin", conn).unwrap();
    assert_remote_healthy(&root, "end");
}

#[test]
fn a_push_cut_off_at_any_point_recovers_on_the_next_push() {
    let server = need_server!();
    let base = tempfile::tempdir().unwrap();
    let (mut alice, afs, _) = new_repo("alice");
    history(&mut alice, &afs, 0, 6);
    remote::push(&mut alice, Arc::new(connect(&server, base.path())), false, &[], false).unwrap();
    let main = history(&mut alice, &afs, 6, 6);

    // How much a complete push sends.
    let probe = tempfile::tempdir().unwrap();
    copy_dir(base.path(), probe.path());
    let b = Arc::new(connect(&server, probe.path()));
    remote::push(&mut alice, b.clone(), false, &[], false).unwrap();
    let total = b.stats().bytes_sent as i64;

    let points = 40;
    let mut cut = 0;
    for k in 0..points {
        let at = total * k / points;
        let dir = tempfile::tempdir().unwrap();
        copy_dir(base.path(), dir.path());
        let shim = Shim {
            cut_after: Some(budget(at)),
            ..Shim::default()
        };
        let res = try_connect_with(&server, dir.path(), shim)
            .and_then(|(b, _child)| remote::push(&mut alice, Arc::new(b), false, &[], false));
        let ctx = format!("cut after {at} of {total} bytes");
        if res.is_err() {
            cut += 1;
        }
        // Every other time, pretend the client that crashed ran on another
        // machine long ago: its lock must then be taken over by lease.
        let lock = dir.path().join(LOCK_PATH);
        if k % 2 == 1 && lock.exists() {
            let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(&lock).unwrap()).unwrap();
            assert_eq!(v["fencing"], true, "{ctx}: SFTP locks are fencing locks");
            v["host"] = "crashed-laptop".into();
            v["boot"] = "elsewhere".into();
            v["renewed"] = (v["renewed"].as_i64().unwrap() - 3_600_000).into();
            std::fs::write(&lock, serde_json::to_vec(&v).unwrap()).unwrap();
        }
        // The remote is consistent as it is, before any recovery.
        let r = Repo::open(Arc::new(DiskBackend::new(dir.path())), None, "x").unwrap();
        let t = r.view().tags["main"].target;
        assert!(t == main || alice.is_ancestor(&t, &main).unwrap(), "{ctx}");
        drop(r);
        remote::push(&mut alice, Arc::new(connect(&server, dir.path())), false, &[], false)
            .unwrap_or_else(|e| panic!("{ctx}: retry failed: {e}"));
        let r = assert_remote_healthy(dir.path(), &ctx);
        assert_eq!(r.view().tags["main"].target, main, "{ctx}");
        assert!(!dir.path().join(LOCK_PATH).exists(), "{ctx}: lock left behind");
        let bob = clone_over_sftp(&server, dir.path(), "bob");
        assert_eq!(files(&bob, &main), files(&alice, &main), "{ctx}");
    }
    assert!(cut >= points / 2, "only {cut} pushes were actually cut");
}

#[test]
fn concurrent_pushers_serialise_on_the_remote_lock() {
    let server = need_server!();
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    let mut repos: Vec<Repo> = (0..4)
        .map(|i| {
            let (mut r, fs, _) = new_repo(&format!("dev{i}"));
            let c = commit_files(&mut r, &*fs, &[(&format!("dev{i}.txt"), &format!("{i}\n").repeat(500))], "work");
            r.set_tag(&format!("t{i}"), c, None, true).unwrap();
            // Everyone also races for the same tag.
            r.set_tag("main", c, None, true).unwrap();
            r
        })
        .collect();
    let reports: Vec<remote::SyncReport> = std::thread::scope(|s| {
        let hs: Vec<_> = repos
            .iter_mut()
            .map(|r| {
                let (server, root) = (server.clone(), root.clone());
                s.spawn(move || remote::push(r, Arc::new(connect(&server, &root)), false, &[], false).unwrap())
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let won_main = reports
        .iter()
        .filter(|r| r.tags_updated.iter().any(|(t, _)| t == "main"))
        .count();
    assert_eq!(won_main, 1, "exactly one pusher sets `main`; the others diverged");
    let r = assert_remote_healthy(&root, "after concurrent pushes");
    for (i, repo) in repos.iter().enumerate() {
        assert_eq!(r.view().tags[&format!("t{i}")].target, repo.view().tags[&format!("t{i}")].target);
    }
}

#[test]
fn a_fresh_lock_of_a_live_client_elsewhere_is_respected_and_a_dead_ones_is_taken_over() {
    let server = need_server!();
    let dir = tempfile::tempdir().unwrap();
    let (mut alice, afs, _) = new_repo("alice");
    let main = history(&mut alice, &afs, 0, 2);
    remote::push(&mut alice, Arc::new(connect(&server, dir.path())), false, &[], false).unwrap();
    // A client on another machine died ten minutes ago, mid-push.
    let now = veil_core::now_millis();
    let crashed = serde_json::json!({
        "token": "77".repeat(16), "pid": 4242, "host": "crashed-laptop", "boot": "b",
        "acquired": now - 600_000, "renewed": now - 600_000, "lease_ms": 30_000, "fencing": true
    });
    std::fs::write(dir.path().join(LOCK_PATH), serde_json::to_vec(&crashed).unwrap()).unwrap();
    let next = history(&mut alice, &afs, 2, 1);
    let rep = remote::push(&mut alice, Arc::new(connect(&server, dir.path())), false, &[], false).unwrap();
    assert_eq!(rep.tags_updated, vec![("main".to_string(), next)]);
    assert!(alice.is_ancestor(&main, &next).unwrap());
    assert_remote_healthy(dir.path(), "after takeover");
}

#[test]
fn a_public_remote_over_sftp_never_receives_cloaked_bytes() {
    let server = need_server!();
    let dir = tempfile::tempdir().unwrap();
    let (mut alice, fs, _) = new_repo("alice");
    fs.write(&p(".veilpolicy"), b"secret/ cloak team\n").unwrap();
    let main = commit_files(
        &mut alice,
        &*fs,
        &[
            ("secret/keys.txt", "TOP-SECRET-CLOAKED-CONTENT\n"),
            ("README", "public readme\n"),
            ("auth.rs", "fn check() -> bool { true }\n"),
        ],
        "v1",
    );
    alice.set_tag("main", main, None, true).unwrap();
    alice.set_tag("internal", main, Some("team".into()), true).unwrap();
    // An embargoed fix, unreleased.
    let ws = alice.ephemeral_workspace(main).unwrap();
    ws.write("auth.rs", "fn check() -> bool { EMBARGOED_FIX_MARKER() }\n").unwrap();
    let (fix, _) = alice.commit_ephemeral(&ws, "fix").unwrap();
    drop(ws);
    let spec = EmbargoSpec {
        scope: "team".into(),
        until: None,
    };
    alice.merge(WS, main, vec![fix], "merge fix", Some(spec)).unwrap();

    let rep = remote::push(&mut alice, Arc::new(connect(&server, dir.path())), true, &[], false).unwrap();
    assert!(rep.redacted > 0);
    assert!(rep.tags_skipped.iter().any(|(t, _)| t == "internal"));

    // Every object on the remote, loose or packed: nothing sealed except
    // released embargoes (none here), nothing cloaked in plaintext.
    let r = Repo::open(Arc::new(DiskBackend::new(dir.path())), None, "check").unwrap();
    assert!(!r.view().tags.contains_key("internal"));
    let ids = r.store().list_objects().unwrap();
    assert!(!ids.is_empty());
    for id in ids {
        let raw = r.store().get_raw(&id).unwrap();
        assert_eq!(Object::sealed_scope(&raw), None, "sealed object {} reached the public remote", id.short());
        for needle in [&b"TOP-SECRET-CLOAKED-CONTENT"[..], b"EMBARGOED_FIX_MARKER"] {
            assert!(!raw.windows(needle.len()).any(|w| w == needle), "plaintext leaked in {}", id.short());
        }
    }
    // And no file on the remote holds the plaintext either (ops, metadata).
    let mut stack = vec![dir.path().to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let e = e.unwrap();
            if e.file_type().unwrap().is_dir() {
                stack.push(e.path());
            } else {
                let b = std::fs::read(e.path()).unwrap();
                assert!(!b.windows(8).any(|w| w == b"TOP-SECR"), "{}", e.path().display());
            }
        }
    }
    // A clone sees the public parts only.
    let carol = clone_over_sftp(&server, dir.path(), "carol");
    let e = file_entry(&carol, &main, "secret/keys.txt").unwrap();
    assert!(carol.store().read_entry(&e).is_err());
    assert_eq!(carol.store().read_entry(&file_entry(&carol, &main, "README").unwrap()).unwrap(), b"public readme\n");
}
