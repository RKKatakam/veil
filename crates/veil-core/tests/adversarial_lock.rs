//! Adversarial tests: repository lock, concurrent writers, stale locks.

mod adversarial_support;

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use adversarial_support::*;
use veil_core::{now_millis, MemoryBackend, Repo, StorageBackend};

const LOCK: &str = ".veil/lock";

/// A slow transaction (e.g. snapshotting a huge tree) holds the lock for more
/// than two minutes. A second process considers the lock stale purely by its
/// age, steals it, and both commit: one operation silently disappears from the
/// op log. (Simulated by back-dating the live holder's lock file.)
#[test]
#[ignore = "BUG-022: lock staleness is judged by age only (no liveness/heartbeat); a live holder's lock is stolen and an operation is lost"]
fn a_live_lock_holder_is_never_robbed() {
    let (mut a, fs, _) = new_repo("alice");
    let base = commit_files(&mut a, &*fs, &[("f", "1\n")], "base");
    let mut b = Repo::open(fs.clone(), None, "bob").unwrap();

    let mut tx_a = a.transaction("slow op by A").unwrap();
    // ...A is still working, 121 s later:
    let mine = fs.read(&p(LOCK)).unwrap();
    let pid = String::from_utf8_lossy(&mine).split_whitespace().next().unwrap().to_string();
    fs.write(&p(LOCK), format!("{pid} {}", now_millis() - 121_000).as_bytes()).unwrap();

    let start = Instant::now();
    let stolen = b.transaction("op by B").map(|mut tx_b| {
        tx_b.view.tags.insert("from-b".into(), veil_core::oplog::Tag { target: base, cloak: None });
        tx_b.commit().unwrap();
    });
    tx_a.view.tags.insert("from-a".into(), veil_core::oplog::Tag { target: base, cloak: None });
    tx_a.commit().unwrap();

    let head = Repo::open(fs.clone(), None, "x").unwrap();
    assert!(
        head.view().tags.contains_key("from-a") && head.view().tags.contains_key("from-b"),
        "an operation was lost: tags = {:?}",
        head.view().tags.keys().collect::<Vec<_>>()
    );
    assert!(stolen.is_err() || start.elapsed() >= Duration::from_secs(1), "B entered while A held the lock");
}

#[test]
#[ignore = "BUG-022: RepoLock::drop removes the lock file unconditionally, releasing a lock that belongs to someone else"]
fn dropping_a_lock_never_releases_someone_elses_lock() {
    let (mut a, fs, _) = new_repo("alice");
    let tx = a.transaction("A").unwrap();
    // A's lock was (wrongly) deemed stale and taken over by process 4242.
    fs.write(&p(LOCK), format!("4242 {}", now_millis()).as_bytes()).unwrap();
    drop(tx);
    assert!(fs.exists(&p(LOCK)).unwrap(), "A's drop deleted process 4242's lock");
}

#[test]
fn an_old_stale_lock_is_recovered() {
    let (mut a, fs, _) = new_repo("alice");
    fs.write(&p(LOCK), format!("999999 {}", now_millis() - 600_000).as_bytes()).unwrap();
    let start = Instant::now();
    a.transaction("after crash").unwrap().commit().unwrap();
    assert!(start.elapsed() < Duration::from_secs(5));
}

#[test]
fn garbage_lock_file_is_treated_as_stale() {
    let (mut a, fs, _) = new_repo("alice");
    fs.write(&p(LOCK), b"\xff\xfe not a lock").unwrap();
    a.transaction("x").unwrap().commit().unwrap();
}

/// After `kill -9` the lock of a dead process blocks every command for two
/// minutes (each command waits 15 s and then fails).
#[test]
#[ignore = "BUG-023: a lock left by a crashed process blocks the repository for 2 minutes (no PID liveness check)"]
fn lock_of_a_dead_process_does_not_block_for_minutes() {
    let (mut a, fs, _) = new_repo("alice");
    // PID 2^22+1 is above Linux's pid_max default and never alive.
    fs.write(&p(LOCK), format!("4194305 {}", now_millis()).as_bytes()).unwrap();
    let start = Instant::now();
    let r = a.transaction("after crash").map(|tx| tx.commit());
    assert!(r.is_ok() && start.elapsed() < Duration::from_secs(5), "blocked for {:?}: {:?}", start.elapsed(), r.err());
}

/// Many writers on one backend, each with its own `Repo` handle: every
/// operation must land in the (linear) op log exactly once.
#[test]
fn concurrent_writers_never_lose_operations() {
    let fs = Arc::new(MemoryBackend::new());
    let mut init = Repo::init(fs.clone(), Some(veil_core::Identity::generate("a")), "a").unwrap();
    let base = commit_files(&mut init, &*fs, &[("f", "1\n")], "base");
    let before = init.op_log(usize::MAX).unwrap().len();
    let threads = 8;
    let per = 10;
    let handles: Vec<_> = (0..threads)
        .map(|t| {
            let fs = fs.clone();
            std::thread::spawn(move || {
                let mut r = Repo::open(fs, None, &format!("t{t}")).unwrap();
                for i in 0..per {
                    let mut tx = r.transaction(format!("t{t}-{i}")).unwrap();
                    tx.view.tags.insert(format!("t{t}-{i}"), veil_core::oplog::Tag { target: base, cloak: None });
                    tx.commit().unwrap();
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    let r = Repo::open(fs.clone(), None, "check").unwrap();
    assert_eq!(r.view().tags.len(), threads * per, "tags: {}", r.view().tags.len());
    assert_eq!(r.op_log(usize::MAX).unwrap().len(), before + threads * per);
    assert!(!fs.exists(&p(LOCK)).unwrap(), "lock leaked");
}

/// Two handles snapshotting different workspaces and committing concurrently.
#[test]
fn concurrent_snapshots_of_different_workspaces_are_all_recorded() {
    let fs = Arc::new(MemoryBackend::new());
    let mut init = Repo::init(fs.clone(), Some(veil_core::Identity::generate("a")), "a").unwrap();
    let base = commit_files(&mut init, &*fs, &[("f", "1\n")], "base");
    for i in 0..4 {
        init.create_workspace(&format!("w{i}"), vec![base], None).unwrap();
    }
    let handles: Vec<_> = (0..4)
        .map(|i| {
            let fs = fs.clone();
            std::thread::spawn(move || {
                let mut r = Repo::open(fs, Some(veil_core::Identity::generate("x")), "x").unwrap();
                for n in 0..5 {
                    let ws = format!("w{i}");
                    let ov = r.workspace_overlay(&ws).unwrap();
                    ov.write(&p(&format!("file-{i}")), format!("{n}\n").as_bytes()).unwrap();
                    r.snapshot_workspace(&ws, &ov).unwrap();
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    let r = Repo::open(fs.clone(), None, "check").unwrap();
    for i in 0..4 {
        let wc = r.workspace_wc(&format!("w{i}")).unwrap();
        assert_eq!(read_at(&r, &wc, &format!("file-{i}")), b"4\n");
    }
}
