//! The durability barrier (ARCHITECTURE §9): transactions write objects
//! unsynced, sync them with one barrier, and only then write the operation
//! and the operation head. A lock taken over from a dead holder first
//! repairs what that holder may have left unsynced or torn.

use std::sync::{Arc, Mutex};

use veil_core::{
    lock::{LockInfo, RepoLock, LOCK_PATH},
    now_millis, remote,
    vfs::{DirEntry, Metadata},
    DiskBackend, Identity, MemoryBackend, ObjectId, Repo, Result, StorageBackend, VPath,
};

fn p(s: &str) -> VPath {
    VPath::new(s).unwrap()
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Call {
    Unsynced(String),
    Write(String),
    Barrier,
}

/// Records every mutation, in order.
#[derive(Debug)]
struct Recorder {
    inner: Arc<dyn StorageBackend>,
    calls: Mutex<Vec<Call>>,
}

impl Recorder {
    fn take(&self) -> Vec<Call> {
        std::mem::take(&mut *self.calls.lock().unwrap())
    }
}

impl StorageBackend for Recorder {
    fn kind(&self) -> &'static str {
        "recorder"
    }
    fn read(&self, path: &VPath) -> Result<Vec<u8>> {
        self.inner.read(path)
    }
    fn write(&self, path: &VPath, data: &[u8]) -> Result<()> {
        self.calls.lock().unwrap().push(Call::Write(path.to_string()));
        self.inner.write(path, data)
    }
    fn write_unsynced(&self, path: &VPath, data: &[u8]) -> Result<()> {
        self.calls.lock().unwrap().push(Call::Unsynced(path.to_string()));
        self.inner.write_unsynced(path, data)
    }
    fn sync_barrier(&self) -> Result<()> {
        self.calls.lock().unwrap().push(Call::Barrier);
        self.inner.sync_barrier()
    }
    fn create_new(&self, path: &VPath, data: &[u8]) -> Result<bool> {
        self.inner.create_new(path, data)
    }
    fn remove_file(&self, path: &VPath) -> Result<()> {
        self.inner.remove_file(path)
    }
    fn remove_dir_all(&self, path: &VPath) -> Result<()> {
        self.inner.remove_dir_all(path)
    }
    fn create_dir_all(&self, path: &VPath) -> Result<()> {
        self.inner.create_dir_all(path)
    }
    fn list_dir(&self, path: &VPath) -> Result<Vec<DirEntry>> {
        self.inner.list_dir(path)
    }
    fn metadata(&self, path: &VPath) -> Result<Option<Metadata>> {
        self.inner.metadata(path)
    }
    fn set_executable(&self, path: &VPath, executable: bool) -> Result<()> {
        self.inner.set_executable(path, executable)
    }
    fn stat_clock(&self) -> Option<veil_core::vfs::StatClock> {
        self.inner.stat_clock()
    }
}

/// Objects are written unsynced, then one barrier, then the operation, then
/// the head; no unsynced write follows the barrier.
fn assert_ordered(calls: &[Call], what: &str) {
    let pos = |pred: &dyn Fn(&Call) -> bool| calls.iter().position(pred);
    let op = pos(&|c| matches!(c, Call::Write(p) if p.starts_with(".veil/ops/")))
        .unwrap_or_else(|| panic!("{what}: no op written: {calls:?}"));
    let head = pos(&|c| matches!(c, Call::Write(p) if p == ".veil/op_head")).expect("head written");
    let barrier = calls[..op]
        .iter()
        .rposition(|c| *c == Call::Barrier)
        .unwrap_or_else(|| panic!("{what}: no barrier before the op: {calls:?}"));
    let unsynced: Vec<usize> = (0..calls.len()).filter(|i| matches!(calls[*i], Call::Unsynced(_))).collect();
    assert!(!unsynced.is_empty(), "{what}: objects were written durably one by one");
    assert!(unsynced.iter().all(|i| *i < barrier), "{what}: unsynced write after the barrier: {calls:?}");
    assert!(barrier < op && op < head, "{what}: order is objects, barrier, op, head: {calls:?}");
    for c in calls {
        if let Call::Unsynced(p) = c {
            assert!(p.starts_with(".veil/objects/"), "{what}: only objects are written unsynced ({p})");
        }
    }
}

#[test]
fn transactions_sync_objects_once_before_the_operation() {
    let tmp = tempfile::tempdir().unwrap();
    for inner in [
        Arc::new(MemoryBackend::new()) as Arc<dyn StorageBackend>,
        Arc::new(DiskBackend::new(tmp.path())),
    ] {
        let rec = Arc::new(Recorder {
            inner: inner.clone(),
            calls: Mutex::default(),
        });
        let id = Identity::generate("alice");
        let mut repo = Repo::init(rec.clone(), Some(id.clone()), "alice").unwrap();
        for i in 0..50 {
            inner.write(&p(&format!("src/d{}/f{i}.txt", i % 5)), format!("{i}\n").as_bytes()).unwrap();
        }
        rec.take();
        repo.snapshot_workspace("default", &*inner).unwrap();
        assert_ordered(&rec.take(), "snapshot");
        let (c, _) = repo.commit_working_copy("default", "c").unwrap();
        repo.set_tag("main", c, None, false).unwrap();

        // Pull into a fresh clone: the copied objects go through the barrier too.
        let clone_fs = Arc::new(Recorder {
            inner: Arc::new(MemoryBackend::new()),
            calls: Mutex::default(),
        });
        let mut clone = Repo::init_for_clone(clone_fs.clone(), Some(id.clone()), "alice").unwrap();
        clone_fs.take();
        remote::pull(&mut clone, "origin", rec.clone()).unwrap();
        assert_ordered(&clone_fs.take(), "pull");
        assert_eq!(clone.view().tags["main"].target, c);
    }
}

#[test]
fn disk_unsynced_writes_are_visible_and_complete() {
    let tmp = tempfile::tempdir().unwrap();
    let fs = DiskBackend::new(tmp.path());
    for i in 0..200 {
        fs.write_unsynced(&p(&format!("a/b{}/f{i}", i % 7)), format!("data {i}").as_bytes()).unwrap();
    }
    assert_eq!(fs.read(&p("a/b3/f10")).unwrap(), b"data 10");
    // Overwrites keep the mode, like `write`.
    fs.write(&p("x"), b"1").unwrap();
    fs.set_executable(&p("x"), true).unwrap();
    fs.write_unsynced(&p("x"), b"2").unwrap();
    assert!(fs.metadata(&p("x")).unwrap().unwrap().executable || cfg!(not(unix)));
    // A file removed before the barrier does not make it fail.
    fs.remove_file(&p("a/b0/f0")).unwrap();
    fs.sync_barrier().unwrap();
    fs.sync_barrier().unwrap(); // nothing left: a no-op
    let leftovers = walkdir(tmp.path()).into_iter().filter(|n| n.contains(".vltmp")).count();
    assert_eq!(leftovers, 0);
    // Clones share the pending set, and concurrent barriers are fine.
    let threads: Vec<_> = (0..4)
        .map(|t| {
            let fs = fs.clone();
            std::thread::spawn(move || {
                for i in 0..50 {
                    fs.write_unsynced(&p(&format!("c/{t}/{i}")), b"z").unwrap();
                    if i % 10 == 0 {
                        fs.sync_barrier().unwrap();
                    }
                }
                fs.sync_barrier().unwrap();
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    assert_eq!(fs.read(&p("c/3/49")).unwrap(), b"z");
}

fn walkdir(dir: &std::path::Path) -> Vec<String> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).unwrap() {
        let e = e.unwrap();
        if e.file_type().unwrap().is_dir() {
            out.extend(walkdir(&e.path()));
        } else {
            out.push(e.file_name().to_string_lossy().into_owned());
        }
    }
    out
}

/// After a power loss the lock of the dead holder is still on disk, and some
/// of its unsynced objects are torn. Taking the lock over removes exactly
/// those, so the next transaction rewrites them instead of trusting them.
#[test]
#[cfg(unix)]
fn taking_over_a_crashed_lock_discards_torn_objects() {
    let tmp = tempfile::tempdir().unwrap();
    let fs: Arc<dyn StorageBackend> = Arc::new(DiskBackend::new(tmp.path()));
    let id = Identity::generate("alice");
    let mut repo = Repo::init(fs.clone(), Some(id.clone()), "alice").unwrap();
    let good = repo.store().put(&veil_core::object::Object::Blob(b"kept".to_vec())).unwrap();
    let torn = ObjectId::hash(b"some object the dead holder was writing");
    let torn_path = p(&format!(".veil/objects/{}/{}", &torn.hex()[..2], &torn.hex()[2..]));
    fs.write(&torn_path, b"").unwrap();

    // A dead process's lock, from this machine, taken just before the crash.
    let mine = {
        let _l = RepoLock::acquire(fs.clone()).unwrap();
        RepoLock::holder(&*fs).unwrap().unwrap()
    };
    let mut child = std::process::Command::new("true").spawn().unwrap();
    let dead = child.id();
    child.wait().unwrap();
    let crashed = LockInfo {
        pid: dead,
        token: "00".repeat(16),
        acquired: now_millis() - 1000,
        renewed: now_millis() - 1000,
        ..mine
    };
    fs.write(&p(LOCK_PATH), &serde_json::to_vec(&crashed).unwrap()).unwrap();

    let report = veil_core::fsck::fsck(fs.clone(), Some(id.clone())).unwrap();
    assert!(report.is_ok(), "a torn unreachable object under a leftover lock is a note: {report:?}");

    let tx = repo.transaction("after the crash").unwrap();
    assert!(!fs.exists(&torn_path).unwrap(), "torn object removed");
    assert!(repo_has(&tx, &good), "intact object kept");
    drop(tx);
    let report = veil_core::fsck::fsck(fs, Some(id)).unwrap();
    assert!(report.is_ok() && report.findings.iter().all(|f| !f.message.contains("torn")), "{report:?}");
}

fn repo_has(tx: &veil_core::transaction::Transaction<'_>, id: &ObjectId) -> bool {
    tx.repo().store().has(id)
}
