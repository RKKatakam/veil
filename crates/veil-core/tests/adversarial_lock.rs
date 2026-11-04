//! Adversarial tests: repository lock, concurrent writers, stale locks.

mod adversarial_support;

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use adversarial_support::*;
use veil_core::{
    lock::{LockInfo, LockOptions, RepoLock},
    now_millis, MemoryBackend, Repo, StorageBackend, VeilError,
};

const LOCK: &str = ".veil/lock";

/// A slow transaction (e.g. snapshotting a huge tree) holds the lock for more
/// than two minutes. The MVP judged staleness by age alone, so a second
/// process stole the lock and one operation silently disappeared.
///
/// Adapted to the renewed-lease lock (the original planted a legacy
/// `"<pid> <millis>"` file over the live lock, which the current lock
/// rightly treats as tampering; see the next test). Here A's lock file is
/// rewritten in the current format to look like a lease that expired two
/// minutes ago, held by another process on this machine that is still
/// running (a live child). B, a separate handle in its own thread, must
/// wait rather than steal, and both operations must be recorded.
#[test]
#[cfg(unix)]
fn a_live_lock_holder_is_never_robbed() {
    let (mut a, fs, _) = new_repo("alice");
    let base = commit_files(&mut a, &*fs, &[("f", "1\n")], "base");
    let mut alive = std::process::Command::new("sleep").arg("60").spawn().expect("spawn `sleep`");

    let mut tx_a = a.transaction("slow op by A").unwrap();
    // ...A is still working, 121 s after its lease was last renewed:
    let mut info = LockInfo::parse(&fs.read(&p(LOCK)).unwrap()).expect("current lock format");
    info.pid = alive.id();
    info.acquired = now_millis() - 121_000;
    info.renewed = info.acquired;
    fs.write(&p(LOCK), &serde_json::to_vec(&info).unwrap()).unwrap();

    let b = std::thread::spawn({
        let fs = fs.clone();
        move || {
            let mut b = Repo::open(fs, None, "bob").unwrap();
            let mut tx_b = b.transaction("op by B").unwrap();
            let entered = Instant::now();
            tx_b.view.tags.insert("from-b".into(), veil_core::oplog::Tag { target: base, cloak: None });
            tx_b.commit().unwrap();
            entered
        }
    });
    std::thread::sleep(Duration::from_millis(1500));
    assert!(!b.is_finished(), "B entered while A held the lock");
    tx_a.view.tags.insert("from-a".into(), veil_core::oplog::Tag { target: base, cloak: None });
    tx_a.commit().expect("A's lock was not taken over");
    let committed = Instant::now();
    let b_entered = b.join().unwrap();
    let _ = alive.kill();
    let _ = alive.wait();

    assert!(b_entered >= committed, "B entered before A released the lock");
    let head = Repo::open(fs.clone(), None, "x").unwrap();
    assert!(
        head.view().tags.contains_key("from-a") && head.view().tags.contains_key("from-b"),
        "an operation was lost: tags = {:?}",
        head.view().tags.keys().collect::<Vec<_>>()
    );
    let log: Vec<String> = head.op_log(3).unwrap().into_iter().map(|(_, op)| op.description).collect();
    assert_eq!(log[..2], ["op by B".to_string(), "slow op by A".to_string()], "linear op log");
}

/// A lock file replaced behind the holder's back (tampering, or a legacy
/// `"<pid> <millis>"` file naming this process with no token) may be
/// reclaimed. Nothing is lost silently: the original holder can no longer
/// commit and gets an error, and the new holder's operation is recorded.
/// A legacy lock naming a live process is never reclaimed.
#[test]
#[cfg(unix)]
fn a_tampered_lock_is_reclaimed_and_its_holder_cannot_commit() {
    let (mut a, fs, _) = new_repo("alice");
    let base = commit_files(&mut a, &*fs, &[("f", "1\n")], "base");
    let mut b = Repo::open(fs.clone(), None, "bob").unwrap();

    let mut tx_a = a.transaction("op by A").unwrap();
    fs.write(&p(LOCK), format!("{} {}", std::process::id(), now_millis() - 121_000).as_bytes()).unwrap();
    let mut tx_b = b.transaction("op by B").expect("a tokenless lock of this process is reclaimed");
    tx_b.view.tags.insert("from-b".into(), veil_core::oplog::Tag { target: base, cloak: None });
    tx_b.commit().unwrap();
    tx_a.view.tags.insert("from-a".into(), veil_core::oplog::Tag { target: base, cloak: None });
    let err = tx_a.commit().expect_err("A must notice that it lost the lock");
    assert!(matches!(err, VeilError::Locked(_)), "{err}");
    let head = Repo::open(fs.clone(), None, "x").unwrap();
    assert!(head.view().tags.contains_key("from-b") && !head.view().tags.contains_key("from-a"));

    // Legacy format, live holder on this machine: never robbed.
    let mut alive = std::process::Command::new("sleep").arg("60").spawn().expect("spawn `sleep`");
    let legacy = format!("{} {}", alive.id(), now_millis() - 600_000);
    fs.write(&p(LOCK), legacy.as_bytes()).unwrap();
    let quick = LockOptions {
        wait: Duration::from_millis(300),
        ..LockOptions::default()
    };
    let err = RepoLock::acquire_with(fs.clone(), &quick).unwrap_err();
    let _ = alive.kill();
    let _ = alive.wait();
    assert!(err.to_string().contains("still running"), "{err}");
    assert_eq!(fs.read(&p(LOCK)).unwrap(), legacy.as_bytes(), "lock untouched");
}

#[test]
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

/// A working copy that is slow to read (huge tree, network FS): the snapshot
/// holds the lock for its whole duration; a concurrent writer must wait, not
/// fail or interleave, and both operations must be recorded.
#[test]
fn slow_snapshot_serialises_with_a_concurrent_writer() {
    #[derive(Debug)]
    struct Slow(MemoryBackend);
    impl StorageBackend for Slow {
        fn kind(&self) -> &'static str {
            "slow"
        }
        fn read(&self, p: &veil_core::VPath) -> veil_core::Result<Vec<u8>> {
            std::thread::sleep(Duration::from_millis(15));
            self.0.read(p)
        }
        fn write(&self, p: &veil_core::VPath, d: &[u8]) -> veil_core::Result<()> {
            self.0.write(p, d)
        }
        fn create_new(&self, p: &veil_core::VPath, d: &[u8]) -> veil_core::Result<bool> {
            self.0.create_new(p, d)
        }
        fn remove_file(&self, p: &veil_core::VPath) -> veil_core::Result<()> {
            self.0.remove_file(p)
        }
        fn remove_dir_all(&self, p: &veil_core::VPath) -> veil_core::Result<()> {
            self.0.remove_dir_all(p)
        }
        fn create_dir_all(&self, p: &veil_core::VPath) -> veil_core::Result<()> {
            self.0.create_dir_all(p)
        }
        fn list_dir(&self, p: &veil_core::VPath) -> veil_core::Result<Vec<veil_core::vfs::DirEntry>> {
            self.0.list_dir(p)
        }
        fn metadata(&self, p: &veil_core::VPath) -> veil_core::Result<Option<veil_core::vfs::Metadata>> {
            self.0.metadata(p)
        }
        fn set_executable(&self, p: &veil_core::VPath, x: bool) -> veil_core::Result<()> {
            self.0.set_executable(p, x)
        }
    }
    let repo_fs = Arc::new(MemoryBackend::new());
    let mut repo = Repo::init(repo_fs.clone(), Some(veil_core::Identity::generate("a")), "a").unwrap();
    let wc = Slow(MemoryBackend::new());
    for i in 0..120 {
        wc.0.write(&p(&format!("dir{}/f{i}", i % 7)), format!("{i}\n").as_bytes()).unwrap();
    }
    let other = std::thread::spawn({
        let repo_fs = repo_fs.clone();
        move || {
            std::thread::sleep(Duration::from_millis(200));
            let mut r = Repo::open(repo_fs, None, "b").unwrap();
            let start = Instant::now();
            let mut tx = r.transaction("concurrent tag").unwrap();
            let root = tx.repo().root_id();
            tx.view.tags.insert("b".into(), veil_core::oplog::Tag { target: root, cloak: None });
            tx.commit().unwrap();
            start.elapsed()
        }
    });
    let start = Instant::now();
    let out = repo.snapshot_workspace(WS, &wc).unwrap();
    let snap_time = start.elapsed();
    let waited = other.join().unwrap();
    assert!(out.changed && snap_time > Duration::from_secs(1));
    assert!(waited > Duration::from_millis(500), "writer did not wait for the snapshot ({waited:?})");
    let r = Repo::open(repo_fs, None, "c").unwrap();
    assert!(r.view().tags.contains_key("b"));
    assert_eq!(r.workspace_wc(WS).unwrap(), out.snapshot, "snapshot lost");
    assert_eq!(read_at(&r, &out.snapshot, "dir3/f10"), b"10\n");
}
