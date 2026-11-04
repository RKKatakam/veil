//! `SftpBackend` against a real OpenSSH `sftp-server`: the
//! `StorageBackend` contract, atomic replace, exclusive create, ranged and
//! large reads, the durability barrier and error mapping.

mod sftp_support;

use std::{sync::Arc, time::Duration};

use sftp_support::{connect, connect_with, Shim};
use veil_core::{vfs::NodeKind, StorageBackend, VPath, VeilError};

fn p(s: &str) -> VPath {
    VPath::new(s).unwrap()
}

macro_rules! need_server {
    () => {
        match sftp_support::server() {
            Some(s) => s,
            None => return,
        }
    };
}

#[test]
fn storage_backend_contract() {
    let server = need_server!();
    let dir = tempfile::tempdir().unwrap();
    let b = connect(&server, dir.path());
    assert_eq!(b.kind(), "sftp");
    assert!(b.is_network());

    // write creates parents; read returns the bytes; metadata matches.
    b.write(&p("a/b/c.txt"), b"hello").unwrap();
    assert_eq!(b.read(&p("a/b/c.txt")).unwrap(), b"hello");
    assert_eq!(std::fs::read(dir.path().join("a/b/c.txt")).unwrap(), b"hello");
    let m = b.metadata(&p("a/b/c.txt")).unwrap().unwrap();
    assert_eq!((m.kind, m.len, m.executable), (NodeKind::File, 5, false));
    assert_eq!(b.metadata(&p("a")).unwrap().unwrap().kind, NodeKind::Dir);

    // Missing paths: NotFound / None, also below a file (ENOTDIR).
    assert!(matches!(b.read(&p("nope")), Err(VeilError::NotFound(_))));
    assert!(b.read_opt(&p("nope")).unwrap().is_none());
    assert!(b.metadata(&p("a/b/c.txt/below")).unwrap().is_none());
    assert!(b.metadata(&p("zzz")).unwrap().is_none());

    // Atomic replace, no temp files left behind.
    b.write(&p("a/b/c.txt"), b"replaced, and longer").unwrap();
    assert_eq!(b.read(&p("a/b/c.txt")).unwrap(), b"replaced, and longer");
    let names: Vec<String> = b.list_dir(&p("a/b")).unwrap().into_iter().map(|e| e.name).collect();
    assert_eq!(names, vec!["c.txt"]);

    // Exclusive create.
    assert!(b.create_new(&p("lock"), b"mine").unwrap());
    assert!(!b.create_new(&p("lock"), b"yours").unwrap());
    assert_eq!(b.read(&p("lock")).unwrap(), b"mine");
    assert!(b.create_new(&p("new/dir/lock"), b"x").unwrap());

    // Listing is sorted, files and dirs only (symlinks are invisible).
    std::os::unix::fs::symlink("/etc/passwd", dir.path().join("a/link")).unwrap();
    b.write(&p("a/0.txt"), b"").unwrap();
    let l = b.list_dir(&p("a")).unwrap();
    let got: Vec<(&str, NodeKind)> = l.iter().map(|e| (e.name.as_str(), e.kind)).collect();
    assert_eq!(got, vec![("0.txt", NodeKind::File), ("b", NodeKind::Dir)]);
    assert!(b.metadata(&p("a/link")).unwrap().is_none());
    assert!(matches!(b.read(&p("a/link")), Err(VeilError::NotFound(_))));
    assert_eq!(b.read(&p("a/0.txt")).unwrap(), b"");

    // Executable bit.
    b.set_executable(&p("a/0.txt"), true).unwrap();
    assert!(b.metadata(&p("a/0.txt")).unwrap().unwrap().executable);
    b.set_executable(&p("a/0.txt"), false).unwrap();
    assert!(!b.metadata(&p("a/0.txt")).unwrap().unwrap().executable);

    // Removal: missing is fine; whole trees go.
    b.remove_file(&p("a/0.txt")).unwrap();
    b.remove_file(&p("a/0.txt")).unwrap();
    b.remove_dir_all(&p("a")).unwrap();
    b.remove_dir_all(&p("a")).unwrap();
    assert!(!dir.path().join("a").exists());
    b.create_dir_all(&p("x/y/z")).unwrap();
    assert!(dir.path().join("x/y/z").is_dir());
    assert!(b.write(&VPath::root(), b"x").is_err());
}

#[test]
fn large_and_ranged_reads() {
    let server = need_server!();
    let dir = tempfile::tempdir().unwrap();
    let b = connect(&server, dir.path());
    let big: Vec<u8> = (0..5_000_000u32).map(|i| (i * 7 + i / 251) as u8).collect();
    b.write(&p("big"), &big).unwrap();
    assert_eq!(std::fs::read(dir.path().join("big")).unwrap(), big);
    assert_eq!(b.read(&p("big")).unwrap(), big);
    assert_eq!(b.read_range(&p("big"), 1_234_567, 777_777).unwrap(), &big[1_234_567..1_234_567 + 777_777]);
    assert_eq!(b.read_range(&p("big"), 4_999_990, 10).unwrap(), &big[4_999_990..]);
    assert!(b.read_range(&p("big"), 4_999_990, 11).is_err(), "past the end");
    // A file that grows behind the client's back is still read whole.
    std::fs::write(dir.path().join("grown"), &big[..10]).unwrap();
    assert_eq!(b.read(&p("grown")).unwrap(), &big[..10]);
}

#[test]
fn unsynced_writes_and_barrier() {
    let server = need_server!();
    let dir = tempfile::tempdir().unwrap();
    let b = connect(&server, dir.path());
    assert!(b.durable(), "OpenSSH supports fsync@openssh.com");
    for i in 0..200 {
        b.write_unsynced(&p(&format!("objects/{:02x}/{i}", i % 7)), format!("{i}").as_bytes()).unwrap();
    }
    let before = b.stats().requests;
    b.sync_barrier().unwrap();
    // open + fsync + close per file, nothing more.
    assert!(b.stats().requests - before <= 3 * 200, "{}", b.stats().requests - before);
    b.sync_barrier().unwrap();
    // A file removed before the barrier is skipped.
    b.write_unsynced(&p("gone"), b"x").unwrap();
    b.remove_file(&p("gone")).unwrap();
    b.sync_barrier().unwrap();
    assert_eq!(std::fs::read_to_string(dir.path().join("objects/03/10")).unwrap(), "10");
}

#[test]
fn concurrent_use_from_many_threads() {
    let server = need_server!();
    let dir = tempfile::tempdir().unwrap();
    let b = Arc::new(connect(&server, dir.path()));
    std::thread::scope(|s| {
        for t in 0..8 {
            let b = b.clone();
            s.spawn(move || {
                for i in 0..40 {
                    let path = p(&format!("t{t}/f{i}"));
                    let data = format!("{t}-{i}").repeat(i * 100);
                    b.write(&path, data.as_bytes()).unwrap();
                    assert_eq!(b.read(&path).unwrap(), data.as_bytes());
                }
            });
        }
    });
    let lock_winners = std::thread::scope(|s| {
        let hs: Vec<_> = (0..8)
            .map(|t| {
                let b = b.clone();
                s.spawn(move || b.create_new(&p("the-lock"), format!("{t}").as_bytes()).unwrap())
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).filter(|w| *w).count()
    });
    assert_eq!(lock_winners, 1, "exactly one exclusive create wins");
}

#[test]
fn latency_is_paid_per_batch_not_per_request() {
    let server = need_server!();
    let dir = tempfile::tempdir().unwrap();
    let (b, _child) = connect_with(&server, dir.path(), Shim { delay: Duration::from_millis(25), cut_after: None });
    let data = vec![7u8; 4 << 20];
    std::fs::write(dir.path().join("f"), &data).unwrap();
    let t = std::time::Instant::now();
    assert_eq!(b.read(&p("f")).unwrap(), data);
    // 4 MiB is ~17 reads of 255 KiB: pipelined, that is two round trips
    // (stat+open, then the reads), not seventeen.
    assert!(t.elapsed() < Duration::from_millis(400), "{:?}", t.elapsed());
}

#[test]
fn a_dead_connection_fails_cleanly() {
    let server = need_server!();
    let dir = tempfile::tempdir().unwrap();
    let (b, child) = connect_with(&server, dir.path(), Shim::default());
    b.write(&p("x"), b"1").unwrap();
    child.lock().unwrap().kill().unwrap();
    child.lock().unwrap().wait().unwrap();
    let e = b.write(&p("y"), b"2").unwrap_err();
    assert!(!e.is_not_found(), "{e}");
    assert!(b.read(&p("x")).is_err());
    assert!(b.is_disconnected());
}
