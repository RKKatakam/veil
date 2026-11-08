//! Shared metadata (key rings, embargo records, the vault) is only ever
//! read-modified-written under the repository lock: concurrent writers in
//! separate handles (separate "processes") never lose an update, and the
//! writes that happen inside transactions (push, pull) do not deadlock.

use std::{sync::Arc, thread};

use veil_core::{
    oplog::Tag, remote, tree::walk_files, vfs::StorageBackend, DiskBackend, Identity, MemoryBackend, Repo, VPath,
};

fn backends() -> Vec<(Arc<dyn StorageBackend>, Option<tempfile::TempDir>)> {
    let tmp = tempfile::tempdir().unwrap();
    vec![
        (Arc::new(MemoryBackend::new()), None),
        (Arc::new(DiskBackend::new(tmp.path())), Some(tmp)),
    ]
}

/// A fresh handle on `root`, as a separate process would have (on disk, a
/// separate `DiskBackend` value, so no state is shared in memory).
fn handle(fs: &Arc<dyn StorageBackend>, disk: &Option<tempfile::TempDir>, id: &Identity) -> Repo {
    let fs: Arc<dyn StorageBackend> = match disk {
        Some(d) => Arc::new(DiskBackend::new(d.path())),
        None => fs.clone(),
    };
    Repo::open(fs, Some(id.clone()), &id.name).unwrap()
}

#[test]
fn concurrent_grants_never_lose_a_member() {
    for (fs, disk) in backends() {
        let alice = Identity::generate("alice");
        Repo::init(fs.clone(), Some(alice.clone()), "alice").unwrap();
        let disk = Arc::new(disk);
        let threads: Vec<_> = (0..4)
            .map(|t| {
                let (fs, disk, alice) = (fs.clone(), disk.clone(), alice.clone());
                thread::spawn(move || {
                    let mut granted = Vec::new();
                    for i in 0..3 {
                        let member = Identity::generate(&format!("m{t}-{i}"));
                        let repo = handle(&fs, &disk, &alice);
                        repo.keys().grant("team", &member.public_id(), &member.name).unwrap();
                        granted.push(member.public_hex());
                    }
                    granted
                })
            })
            .collect();
        let granted: Vec<String> = threads.into_iter().flat_map(|t| t.join().unwrap()).collect();
        let repo = handle(&fs, &disk, &alice);
        let state = repo.keys().ring_state("team").unwrap().unwrap().expect("ring verifies");
        for m in &granted {
            assert!(state.members.contains_key(m), "{}: grant of {m} was lost", fs.kind());
        }
        assert_eq!(state.members.len(), granted.len() + 1, "{}", fs.kind());
    }
}

/// Grants, rotations and embargo releases race pushes to the same remote
/// (whose ring merge runs inside the push transaction) and commits: nothing
/// deadlocks and nothing is lost.
#[test]
fn metadata_writes_inside_and_outside_transactions_interleave_safely() {
    let alice = Identity::generate("alice");
    let fs = Arc::new(MemoryBackend::new());
    let mut repo = Repo::init(fs.clone(), Some(alice.clone()), "alice").unwrap();
    fs.write(&VPath::new("a.txt").unwrap(), b"a\n").unwrap();
    repo.snapshot_workspace("default", &*fs).unwrap();
    let (base, _) = repo.commit_working_copy("default", "base").unwrap();
    repo.set_tag("main", base, false).unwrap();
    let remote_fs: Arc<dyn StorageBackend> = Arc::new(MemoryBackend::new());
    remote::push(&mut repo, remote_fs.clone(), false, &[], false).unwrap();
    let embargoes: Vec<String> = (0..4)
        .map(|_| repo.keys().create_embargo("team", None).unwrap())
        .collect();
    drop(repo);

    let open = |fs: &Arc<MemoryBackend>| Repo::open(fs.clone(), Some(alice.clone()), "alice").unwrap();
    let mut threads = Vec::new();
    // Grants and a rotation on the local ring.
    for t in 0..3 {
        let (fs, alice) = (fs.clone(), alice.clone());
        threads.push(thread::spawn(move || {
            let repo = Repo::open(fs, Some(alice), "alice").unwrap();
            let mut out = Vec::new();
            for i in 0..3 {
                let m = Identity::generate(&format!("g{t}-{i}"));
                repo.keys().grant("team", &m.public_id(), &m.name).unwrap();
                out.push(m.public_hex());
                if t == 0 && i == 1 {
                    repo.keys().rotate("team").unwrap();
                }
            }
            out
        }));
    }
    // Embargo releases (each a record read-modify-write plus a transaction).
    for e in embargoes.clone() {
        let (fs, alice) = (fs.clone(), alice.clone());
        threads.push(thread::spawn(move || {
            let mut repo = Repo::open(fs, Some(alice), "alice").unwrap();
            repo.release_embargo(&e).unwrap();
            vec![]
        }));
    }
    // Commits and pushes (ring merge into the remote under its lock).
    for t in 0..2 {
        let (fs, alice, remote_fs) = (fs.clone(), alice.clone(), remote_fs.clone());
        threads.push(thread::spawn(move || {
            let mut repo = Repo::open(fs, Some(alice), "alice").unwrap();
            for i in 0..3 {
                let mut tx = repo.transaction(format!("tag {t}-{i}")).unwrap();
                tx.view.tags.insert(format!("t{t}-{i}"), Tag::new(base));
                tx.commit().unwrap();
                remote::push(&mut repo, remote_fs.clone(), false, &[], false).unwrap();
            }
            vec![]
        }));
    }
    let granted: Vec<String> = threads.into_iter().flat_map(|t| t.join().unwrap()).collect();

    let repo = open(&fs);
    let state = repo.keys().ring_state("team").unwrap().unwrap().expect("ring verifies");
    assert_eq!(state.generation, 1, "the rotation was kept");
    for m in &granted {
        assert!(state.members.contains_key(m), "grant of {m} was lost");
    }
    for e in &embargoes {
        assert!(repo.keys().embargo_released(e), "release of {e} was lost");
    }
    assert_eq!(repo.view().tags.len(), 1 + 6);
    // A last push carries the final ring; the remote fast-forwards to it.
    let mut repo = open(&fs);
    remote::push(&mut repo, remote_fs.clone(), false, &[], false).unwrap();
    let remote = Repo::open(remote_fs, None, "remote").unwrap();
    let ring = remote.keys().load_ring("team").unwrap().unwrap();
    assert_eq!(ring, repo.keys().load_ring("team").unwrap().unwrap());
    assert!(!walk_files(remote.store(), &remote.snapshot(&base).unwrap().tree).unwrap().is_empty());
}

/// Two handles backing up isolated files and storing secrets at once: the
/// vault ends up with every secret.
#[test]
fn concurrent_vault_updates_never_lose_a_secret() {
    let alice = Identity::generate("alice");
    let fs = Arc::new(MemoryBackend::new());
    Repo::init(fs.clone(), Some(alice.clone()), "alice").unwrap();
    let threads: Vec<_> = (0..6)
        .map(|t| {
            let (fs, alice) = (fs.clone(), alice.clone());
            thread::spawn(move || {
                let repo = Repo::open(fs, Some(alice), "alice").unwrap();
                for i in 0..5 {
                    repo.vault_update(|v| {
                        v.secrets.insert(format!("S{t}-{i}"), "x".into());
                        Ok(())
                    })
                    .unwrap();
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    let repo = Repo::open(fs, Some(alice), "alice").unwrap();
    assert_eq!(repo.vault_load().unwrap().secrets.len(), 30);
}

/// The lock-free op log (format 6, threat 15): transactions no longer hold
/// `.veil/lock`, so metadata writers race them instead of queueing behind
/// them. Grants (key-ring read-modify-writes, under the lock), commits in
/// several workspaces and a pull run at once: no grant and no commit is
/// lost.
#[test]
fn grant_racing_lock_free_commits() {
    for (fs, disk) in backends() {
        grant_race(fs, disk);
    }
}

/// BUG-1294: under load (about 1 run in 70 with the machine's load near
/// 100), a lock-free commit's tag names a tree without the file the
/// commit wrote (`["f0-0", "f0-2"]` for `c0-1`), on the memory backend:
/// on `integration` as on this branch. Many rounds of the race above.
#[test]
#[ignore = "BUG-1294: a lock-free commit racing grants and a pull can lose its own file"]
fn bug_1294_lock_free_commits_keep_their_files() {
    for _ in 0..200 {
        grant_race(Arc::new(MemoryBackend::new()), None);
    }
}

fn grant_race(fs: Arc<dyn StorageBackend>, disk: Option<tempfile::TempDir>) {
    {
        let alice = Identity::generate("alice");
        let mut init = Repo::init(fs.clone(), Some(alice.clone()), "alice").unwrap();
        let root = init.root_id();
        for w in 0..3 {
            init.create_workspace(&format!("w{w}"), vec![root]).unwrap();
        }
        // A remote with something to pull.
        let remote: Arc<dyn StorageBackend> = Arc::new(MemoryBackend::new());
        let mut other = Repo::init(Arc::new(MemoryBackend::new()), Some(alice.clone()), "alice").unwrap();
        let ov = other.workspace_overlay("default").unwrap();
        ov.write(&VPath::new("pulled.txt").unwrap(), b"pulled\n").unwrap();
        other.snapshot_workspace("default", &ov).unwrap();
        let (c, _) = other.commit_working_copy("default", "to pull").unwrap();
        other.set_tag("main", c, false).unwrap();
        remote::push(&mut other, remote.clone(), false, &[], false).unwrap();
        drop(init);
        let disk = Arc::new(disk);
        let mut threads = Vec::new();
        for t in 0..3 {
            let (fs, disk, alice) = (fs.clone(), disk.clone(), alice.clone());
            threads.push(thread::spawn(move || {
                let mut granted = Vec::new();
                for i in 0..2 {
                    let member = Identity::generate(&format!("m{t}-{i}"));
                    let repo = handle(&fs, &disk, &alice);
                    repo.keys().grant("team", &member.public_id(), &member.name).unwrap();
                    granted.push(member.public_hex());
                }
                granted
            }));
        }
        for w in 0..3 {
            let (fs, disk, alice) = (fs.clone(), disk.clone(), alice.clone());
            threads.push(thread::spawn(move || {
                let mut repo = handle(&fs, &disk, &alice);
                let ws = format!("w{w}");
                for n in 0..3 {
                    let ov = repo.workspace_overlay(&ws).unwrap();
                    ov.write(&VPath::new(&format!("f{w}-{n}")).unwrap(), b"x\n").unwrap();
                    repo.snapshot_workspace(&ws, &ov).unwrap();
                    let (c, _) = repo.commit_working_copy(&ws, &format!("{ws} {n}")).unwrap();
                    repo.set_tag(&format!("c{w}-{n}"), c, true).unwrap();
                }
                Vec::new()
            }));
        }
        {
            let (fs, disk, alice, remote) = (fs.clone(), disk.clone(), alice.clone(), remote.clone());
            threads.push(thread::spawn(move || {
                let mut repo = handle(&fs, &disk, &alice);
                remote::pull(&mut repo, "origin", remote).unwrap();
                Vec::new()
            }));
        }
        let granted: Vec<String> = threads.into_iter().flat_map(|t| t.join().unwrap()).collect();
        let repo = handle(&fs, &disk, &alice);
        let state = repo.keys().ring_state("team").unwrap().unwrap().expect("ring verifies");
        for m in &granted {
            assert!(state.members.contains_key(m), "{}: grant of {m} was lost", fs.kind());
        }
        for w in 0..3 {
            for n in 0..3 {
                let t = repo.view().tags.get(&format!("c{w}-{n}")).unwrap_or_else(|| panic!("{}: commit c{w}-{n} was lost", fs.kind()));
                let files: Vec<String> = walk_files(repo.store(), &repo.snapshot(&t.target).unwrap().tree).unwrap().into_iter().map(|(p, _)| p.to_string()).collect();
                assert!(files.contains(&format!("f{w}-{n}")), "{}: {files:?}", fs.kind());
            }
        }
        assert_eq!(repo.view().remote_tags.get("origin/main"), Some(&c), "{}: the pull was lost", fs.kind());
        assert_eq!(repo.heads().len(), 1);
        let _ = Tag::new(c);
    }
}
