//! Round-6 adversarial tests (Fable): the repository lock against a lock
//! path that exists but reads back as absent.
//!
//! Every `#[ignore = "BUG-NNN: …"]` test asserts the secure behaviour and
//! currently fails; see `docs/BUGS.md` ("Round 6 findings (Fable)").

use std::{
    sync::{mpsc, Arc},
    time::Duration,
};

use veil_core::{lock::RepoLock, DiskBackend, Identity, Repo, StorageBackend, VPath};

/// Run `f` on a thread; `Some(result)` if it returned within `limit`.
fn within<T: Send + 'static>(limit: Duration, f: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(limit).ok()
}

/// Control: a lock file with unreadable content is reclaimed (after a
/// lease) or refused, within the documented wait.
#[test]
fn a_garbage_lock_file_is_handled_within_the_wait() {
    let dir = tempfile::tempdir().unwrap();
    let backend = Arc::new(DiskBackend::new(dir.path()));
    Repo::init(backend.clone(), Some(Identity::generate("alice")), "alice").unwrap();
    std::fs::write(dir.path().join(".veil/lock"), b"garbage{").unwrap();
    let b: Arc<dyn StorageBackend> = backend;
    let r = within(Duration::from_secs(60), move || RepoLock::acquire(b).map(|_| ()));
    assert!(r.is_some(), "acquire neither succeeded nor failed within 60 s");
}

/// `RepoLock::acquire_in` (`lock.rs`) loops: `create_new` fails because
/// the path exists, `read_opt` returns `None` because `DiskBackend` (and
/// `SftpBackend`) report nothing at a symlink, and the loop `continue`s
/// **before** the back-off sleep and the deadline check. A `.veil/lock`
/// that is a symlink (dangling or not) therefore spins every command at
/// full CPU for ever, with no error. On an SSH remote the same file wedges
/// every `vl push`/`vl pull` client the same way (`sftp-server` serves the
/// symlink's `lstat` as a symlink, `stat` fails), although the
/// architecture says a hostile or broken server "can neither hang the
/// client nor exhaust its memory". A plain unreadable lock file is
/// reclaimed after a lease (control above); a directory is refused at
/// once.
#[test]
fn a_symlinked_lock_file_does_not_spin_for_ever() {
    let dir = tempfile::tempdir().unwrap();
    let backend = Arc::new(DiskBackend::new(dir.path()));
    Repo::init(backend.clone(), Some(Identity::generate("alice")), "alice").unwrap();
    std::os::unix::fs::symlink("/nonexistent", dir.path().join(".veil/lock")).unwrap();
    assert!(backend.read_opt(&VPath::new(".veil/lock").unwrap()).unwrap().is_none());
    let b: Arc<dyn StorageBackend> = backend;
    let r = within(Duration::from_secs(60), move || RepoLock::acquire(b).map(|_| ()));
    assert!(r.is_some(), "acquire neither succeeded nor failed within 60 s (busy loop)");
}

/// BUG-119 follow-up: the symlink is diagnosed at once (not after the
/// whole wait), naming the path and what to do; the same for a symlinked
/// takeover guard, which would otherwise keep every takeover "busy".
#[test]
fn a_symlinked_lock_or_guard_is_diagnosed_at_once() {
    for name in ["lock", "lock.steal"] {
        let dir = tempfile::tempdir().unwrap();
        let backend = Arc::new(DiskBackend::new(dir.path()));
        Repo::init(backend.clone(), Some(Identity::generate("alice")), "alice").unwrap();
        if name == "lock.steal" {
            // A dead holder's lock, so that acquiring needs a takeover.
            std::fs::write(dir.path().join(".veil/lock"), b"garbage{").unwrap();
        }
        std::os::unix::fs::symlink("/nonexistent", dir.path().join(".veil").join(name)).unwrap();
        let b: Arc<dyn StorageBackend> = backend;
        let started = std::time::Instant::now();
        let opts = veil_core::lock::LockOptions {
            lease: Duration::from_millis(200),
            ..veil_core::lock::LockOptions::default()
        };
        let r = within(Duration::from_secs(60), move || RepoLock::acquire_with(b, &opts).map(|_| ()));
        let err = r.expect("acquire hung").expect_err("acquired through a symlink");
        let msg = err.to_string();
        assert!(msg.contains(&format!(".veil/{name} is a symlink")) && msg.contains("remove"), "{name}: {msg}");
        assert!(started.elapsed() < Duration::from_secs(5), "{name}: took {:?}", started.elapsed());
    }
}
