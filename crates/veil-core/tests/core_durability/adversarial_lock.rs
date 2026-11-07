//! Adversarial tests: repository lock, concurrent writers, stale locks.

use crate::adversarial_support;

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use adversarial_support::*;
use veil_core::{
    lock::RepoLock,
    now_millis, MemoryBackend, Repo, StorageBackend,
};

const LOCK: &str = ".veil/lock";

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
                    tx.view.tags.insert(format!("t{t}-{i}"), veil_core::oplog::Tag::new(base));
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
    // Format 6: concurrent operations are merged (the merges are extra).
    let log = r.op_log(usize::MAX).unwrap();
    assert_eq!(log.iter().filter(|(_, op)| !op.is_merge()).count(), before + threads * per);
    assert_eq!(r.heads().len(), 1, "settled");
    assert!(!fs.exists(&p(LOCK)).unwrap(), "lock leaked");
}

/// Two handles snapshotting different workspaces and committing concurrently.
#[test]
fn concurrent_snapshots_of_different_workspaces_are_all_recorded() {
    let fs = Arc::new(MemoryBackend::new());
    let mut init = Repo::init(fs.clone(), Some(veil_core::Identity::generate("a")), "a").unwrap();
    let base = commit_files(&mut init, &*fs, &[("f", "1\n")], "base");
    for i in 0..4 {
        init.create_workspace(&format!("w{i}"), vec![base]).unwrap();
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

/// A working copy that is slow to read (huge tree, network FS). Up to format
/// 5 the snapshot held the lock for its whole duration and a concurrent
/// writer waited. From format 6 nothing holds a lock: the writer goes
/// through at once, and both operations are recorded (merged).
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
            tx.view.tags.insert("b".into(), veil_core::oplog::Tag::new(root));
            tx.commit().unwrap();
            start.elapsed()
        }
    });
    let start = Instant::now();
    let out = repo.snapshot_workspace(WS, &wc).unwrap();
    let snap_time = start.elapsed();
    let waited = other.join().unwrap();
    assert!(out.changed && snap_time > Duration::from_secs(1));
    assert!(waited < Duration::from_millis(500), "the writer waited for the snapshot ({waited:?})");
    let r = Repo::open(repo_fs, None, "c").unwrap();
    assert!(r.view().tags.contains_key("b"));
    assert_eq!(r.workspace_wc(WS).unwrap(), out.snapshot, "snapshot lost");
    assert_eq!(read_at(&r, &out.snapshot, "dir3/f10"), b"10\n");
}

/// BUG-801: a snapshot scans the working copy before it takes the lock, so
/// any number of clean `vl status` run at once without contending. The
/// scan may race other recorders of the same directory: it is used only if
/// the workspace did not move meanwhile; otherwise the tree is built again
/// under the lock. Eight handles on one directory, each editing its own
/// file and snapshotting in a loop: every snapshot follows the last one
/// (no fork, no lost edit), and the last records what the directory holds.
#[test]
fn racing_snapshots_of_one_directory_lose_nothing() {
    let fs = Arc::new(MemoryBackend::new());
    let mut init = Repo::init(fs.clone(), Some(veil_core::Identity::generate("a")), "a").unwrap();
    init.snapshot_workspace("default", &*fs).unwrap();
    const THREADS: usize = 8;
    const ROUNDS: usize = 12;
    let handles: Vec<_> = (0..THREADS)
        .map(|i| {
            let fs = fs.clone();
            std::thread::spawn(move || {
                let mut r = Repo::open(fs.clone(), Some(veil_core::Identity::generate("x")), "x").unwrap();
                for n in 0..ROUNDS {
                    fs.write(&p(&format!("file-{i}")), format!("{n}\n").as_bytes()).unwrap();
                    let out = r.snapshot_workspace("default", &*fs).unwrap();
                    assert!(!out.superseded);
                    // What this handle wrote is recorded by now (by it, or
                    // by a racer that scanned after the write).
                    let r2 = Repo::open(fs.clone(), None, "check").unwrap();
                    let wc = r2.workspace_wc("default").unwrap();
                    let got = String::from_utf8(read_at(&r2, &wc, &format!("file-{i}"))).unwrap();
                    assert_eq!(got, format!("{n}\n"), "file-{i} lost round {n}");
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    let mut r = Repo::open(fs.clone(), None, "check").unwrap();
    let before = r.workspace_wc("default").unwrap();
    let out = r.snapshot_workspace("default", &*fs).unwrap();
    assert!(!out.changed, "the last snapshot missed an edit");
    assert_eq!(out.snapshot, before);
    for i in 0..THREADS {
        assert_eq!(read_at(&r, &before, &format!("file-{i}")), format!("{}\n", ROUNDS - 1).as_bytes());
    }
    // One line of working-copy snapshots: each the successor of the last.
    let mut chain = 0;
    let mut at = before;
    loop {
        let s = r.snapshot(&at).unwrap();
        match s.predecessors.as_slice() {
            [prev] => {
                at = *prev;
                chain += 1;
            }
            [] => break,
            more => panic!("forked working copy: {more:?}"),
        }
    }
    assert!(chain >= ROUNDS, "{chain}");
    assert!(!fs.exists(&p(LOCK)).unwrap(), "lock leaked");
}

/// BUG-801: a clean snapshot never takes the lock (another holder does not
/// make it wait or fail), and content too large to stage in memory is
/// still recorded (under the lock).
#[test]
fn a_clean_snapshot_needs_no_lock_and_large_content_still_records() {
    let (mut a, fs, _) = new_repo("alice");
    commit_files(&mut a, &*fs, &[("f", "1\n")], "base");
    a.snapshot_workspace("default", &*fs).unwrap();
    // Someone holds the lock for longer than any wait.
    let held = RepoLock::acquire(fs.clone()).unwrap();
    let mut b = Repo::open(fs.clone(), None, "b").unwrap();
    let t = Instant::now();
    let out = b.snapshot_workspace("default", &*fs).unwrap();
    assert!(!out.changed);
    assert!(t.elapsed() < Duration::from_secs(5), "a clean snapshot waited for the lock");
    drop(held);
    // More new content than the staging budget: built under the lock.
    let big: Vec<u8> = (0..veil_core::store::STAGING_BUDGET + 4096).map(|i| (i * 7 % 251) as u8).collect();
    fs.write(&p("big.bin"), &big).unwrap();
    let out = b.snapshot_workspace("default", &*fs).unwrap();
    assert!(out.changed);
    assert_eq!(read_at(&b, &out.snapshot, "big.bin"), big);
    let mut c = Repo::open(fs.clone(), None, "c").unwrap();
    assert!(!c.snapshot_workspace("default", &*fs).unwrap().changed);
}
