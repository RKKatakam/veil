//! The durability barrier (ARCHITECTURE §9): transactions write objects
//! unsynced, sync them with one barrier, and only then write the operation
//! and the operation head. From format 6 the objects are staged in the
//! transaction's own directory and renamed into place after the barrier,
//! and a second barrier makes the renames durable before the operation.
//! Formats ≤ 5: a lock taken over from a dead holder first repairs what
//! that holder may have left unsynced or torn.

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
    Rename(String),
    CreateNew(String),
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
        self.calls.lock().unwrap().push(Call::CreateNew(path.to_string()));
        self.inner.create_new(path, data)
    }
    fn rename_unsynced(&self, from: &VPath, to: &VPath) -> Result<()> {
        self.calls.lock().unwrap().push(Call::Rename(to.to_string()));
        self.inner.rename_unsynced(from, to)
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
    fn create_stream<'a>(&'a self, dir: &VPath, durable: bool) -> Result<Box<dyn veil_core::vfs::StreamWriter + 'a>> {
        self.inner.create_stream(dir, durable)
    }
}

/// Formats ≤ 5: objects are written unsynced, then one barrier, then the
/// operation, then the head; no unsynced write follows the barrier.
/// Format 6: objects are written unsynced into the transaction's staging
/// directory, one barrier, renamed into place, a second barrier, then the
/// operation and its head file.
fn assert_ordered(calls: &[Call], what: &str, format: u32) {
    let pos = |pred: &dyn Fn(&Call) -> bool| calls.iter().position(pred);
    let op = pos(&|c| matches!(c, Call::Write(p) if p.starts_with(".veil/ops/")))
        .unwrap_or_else(|| panic!("{what}: no op written: {calls:?}"));
    let head = match format {
        6 => pos(&|c| matches!(c, Call::CreateNew(p) if p.starts_with(".veil/op_heads/"))).expect("head file created"),
        _ => pos(&|c| matches!(c, Call::Write(p) if p == ".veil/op_head")).expect("head written"),
    };
    let barrier = calls[..op]
        .iter()
        .rposition(|c| *c == Call::Barrier)
        .unwrap_or_else(|| panic!("{what}: no barrier before the op: {calls:?}"));
    let unsynced: Vec<usize> = (0..calls.len()).filter(|i| matches!(calls[*i], Call::Unsynced(_))).collect();
    assert!(!unsynced.is_empty(), "{what}: objects were written durably one by one");
    assert!(barrier < op && op < head, "{what}: order is objects, barrier, op, head: {calls:?}");
    if format == 6 {
        let renames: Vec<usize> = (0..calls.len()).filter(|i| matches!(calls[*i], Call::Rename(_))).collect();
        let first_barrier = calls.iter().position(|c| *c == Call::Barrier).unwrap();
        assert!(!renames.is_empty(), "{what}: nothing published: {calls:?}");
        assert!(unsynced.iter().all(|i| *i < first_barrier), "{what}: unsynced write after the staging barrier: {calls:?}");
        assert!(renames.iter().all(|i| *i > first_barrier && *i < barrier), "{what}: renames between the barriers: {calls:?}");
        for c in calls {
            match c {
                Call::Unsynced(p) => assert!(p.starts_with(".veil/objects/incoming/tx-"), "{what}: staged outside the transaction's directory ({p})"),
                Call::Rename(p) => assert!(p.starts_with(".veil/objects/") && !p.contains("incoming"), "{what}: renamed to {p}"),
                _ => {}
            }
        }
        return;
    }
    assert!(unsynced.iter().all(|i| *i < barrier), "{what}: unsynced write after the barrier: {calls:?}");
    for c in calls {
        if let Call::Unsynced(p) = c {
            assert!(p.starts_with(".veil/objects/"), "{what}: only objects are written unsynced ({p})");
        }
    }
}

#[test]
fn transactions_sync_objects_once_before_the_operation() {
    let tmp = tempfile::tempdir().unwrap();
    for (n, (format, inner)) in [
        (5, Arc::new(MemoryBackend::new()) as Arc<dyn StorageBackend>),
        (5, Arc::new(DiskBackend::new(tmp.path().join("5"))) as Arc<dyn StorageBackend>),
        (6, Arc::new(MemoryBackend::new()) as Arc<dyn StorageBackend>),
        (6, Arc::new(DiskBackend::new(tmp.path().join("6"))) as Arc<dyn StorageBackend>),
    ]
    .into_iter()
    .enumerate()
    {
        let _ = n;
        let rec = Arc::new(Recorder {
            inner: inner.clone(),
            calls: Mutex::default(),
        });
        let id = Identity::generate("alice");
        let mut repo = Repo::init_for_clone_at(rec.clone(), Some(id.clone()), "alice", format).unwrap();
        for i in 0..50 {
            inner.write(&p(&format!("src/d{}/f{i}.txt", i % 5)), format!("{i}\n").as_bytes()).unwrap();
        }
        rec.take();
        repo.snapshot_workspace("default", &*inner).unwrap();
        assert_ordered(&rec.take(), "snapshot", format);
        let (c, _) = repo.commit_working_copy("default", "c").unwrap();
        repo.set_tag("main", c, None, false).unwrap();

        // Pull into a fresh clone: the copied objects go through the barrier too.
        let clone_fs = Arc::new(Recorder {
            inner: Arc::new(MemoryBackend::new()),
            calls: Mutex::default(),
        });
        let mut clone = Repo::init_for_clone_at(clone_fs.clone(), Some(id.clone()), "alice", format).unwrap();
        clone_fs.take();
        remote::pull(&mut clone, "origin", rec.clone()).unwrap();
        assert_ordered(&clone_fs.take(), "pull", format);
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
    // The unsynced-object protocol and its recovery: formats ≤ 5 (and
    // network remotes); format 6 stages objects instead.
    let mut repo = Repo::init_for_clone_at(fs.clone(), Some(id.clone()), "alice", 5).unwrap();
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

/// Incompressible bytes, deterministic from `seed`.
fn noise(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

/// BUG-800: a pack streamed to disk (`PackWriter`) is invisible until it is
/// complete. Dropped part way (an error), or abandoned by a process that
/// dies (no destructor runs), or interrupted after the `.pack` and before
/// its `.idx`, it leaves no pack a reader finds, and `fsck` finds nothing
/// wrong. Finished, it publishes the `.pack` before the `.idx`, and leaves
/// no temp file.
#[test]
fn an_interrupted_pack_write_leaves_no_visible_pack() {
    use veil_core::{
        fsck::{fsck, Severity},
        object::Object,
        pack::{Pack, PackWriter},
        vfs::is_temp_name,
    };
    let tmp = tempfile::tempdir().unwrap();
    let fs: Arc<dyn StorageBackend> = Arc::new(DiskBackend::new(tmp.path()));
    let id = Identity::generate("alice");
    let repo = Repo::init(fs.clone(), Some(id.clone()), "alice").unwrap();
    let store = repo.store();
    let dir = store.pack_dir();
    // About 4 MiB: the writer has streamed most of it before `finish`.
    let blobs: Vec<(ObjectId, Vec<u8>)> = (0..64)
        .map(|i| {
            let raw = Object::Blob(noise(i + 1, 64 << 10)).encode();
            (ObjectId::hash(&raw), raw)
        })
        .collect();
    let writer = || {
        let mut w = PackWriter::new(fs.create_stream(&dir, true).unwrap(), 3).unwrap();
        for (id, raw) in &blobs {
            w.add(*id, raw, None).unwrap();
        }
        w
    };
    let on_disk = || -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(tmp.path().join(".veil/objects/pack"))
            .map(|d| d.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect())
            .unwrap_or_default();
        v.sort();
        v
    };
    let unseen = |what: &str| {
        store.reload_packs().unwrap();
        assert!(store.packs().unwrap().is_empty(), "{what}: a reader sees a pack: {:?}", on_disk());
        assert!(blobs.iter().all(|(id, _)| !store.has(id)), "{what}: an object is visible");
        let report = fsck(fs.clone(), Some(id.clone())).unwrap();
        assert!(report.is_ok() && report.count(Severity::Warning) == 0, "{what}: {report:?}");
    };

    // Dropped part way: nothing at all is left.
    drop(writer());
    assert!(on_disk().is_empty(), "{:?}", on_disk());
    unseen("dropped");

    // The process dies while writing: a temp file, nothing else.
    std::mem::forget(writer());
    let left = on_disk();
    assert!(left.len() == 1 && is_temp_name(&left[0]), "{left:?}");
    unseen("abandoned");
    std::fs::remove_file(tmp.path().join(".veil/objects/pack").join(&left[0])).unwrap();

    // It dies after publishing the `.pack`, before writing the `.idx`
    // (written here to a scratch backend instead).
    let (name, _) = writer().finish(&MemoryBackend::new(), &dir).unwrap().unwrap();
    assert_eq!(on_disk(), [format!("pack-{name}.pack")]);
    unseen("no index");

    // Finished: `.pack`, then `.idx`, both complete and nothing else.
    let rec = Recorder {
        inner: fs.clone(),
        calls: Mutex::default(),
    };
    let (name, stats) = writer().finish(&rec, &dir).unwrap().unwrap();
    assert_eq!(rec.take(), [Call::Write(format!(".veil/objects/pack/pack-{name}.idx"))]);
    assert_eq!(on_disk(), [format!("pack-{name}.idx"), format!("pack-{name}.pack")]);
    assert_eq!(stats.objects, blobs.len());
    let pack = Pack::open(&*fs, &dir, &name).unwrap();
    pack.verify(&*fs).unwrap();
    store.reload_packs().unwrap();
    for (id, raw) in &blobs {
        assert_eq!(&store.get_raw(id).unwrap(), raw);
    }
    let report = fsck(fs.clone(), Some(id)).unwrap();
    assert!(report.is_ok() && report.count(Severity::Warning) == 0, "{report:?}");
}

/// BUG-800: a pull that writes packs streams each `.pack`, then issues the
/// store's barrier, then writes the `.idx` durably, before the operation
/// and its head; the download spool is gone afterwards.
#[test]
fn pulled_packs_are_published_before_their_index_and_the_operation() {
    let tmp = tempfile::tempdir().unwrap();
    let id = Identity::generate("alice");
    let fs = Arc::new(DiskBackend::new(tmp.path().join("a")));
    let mut repo = Repo::init(fs.clone(), Some(id.clone()), "alice").unwrap();
    // More objects than a pull writes loose (256).
    for i in 0..300 {
        fs.write(&p(&format!("src/d{}/f{i}.txt", i % 7)), &noise(i, 3000)).unwrap();
    }
    repo.snapshot_workspace("default", &*fs).unwrap();
    let (c, _) = repo.commit_working_copy("default", "c").unwrap();
    repo.set_tag("main", c, None, false).unwrap();
    // A pack on the remote, so that the pull downloads (spools) it.
    let remote: Arc<dyn StorageBackend> = Arc::new(DiskBackend::new(tmp.path().join("r")));
    remote::push(&mut repo, remote.clone(), false, &[], false).unwrap();

    let rec = Arc::new(Recorder {
        inner: Arc::new(DiskBackend::new(tmp.path().join("b"))),
        calls: Mutex::default(),
    });
    let mut clone = Repo::init_for_clone(rec.clone(), Some(id), "alice").unwrap();
    rec.take();
    let report = remote::pull(&mut clone, "origin", remote).unwrap();
    assert_eq!(report.packs_written, 1);
    let calls = rec.take();
    let pos = |pred: &dyn Fn(&Call) -> bool| calls.iter().position(pred).unwrap_or_else(|| panic!("{calls:?}"));
    let idx = pos(&|c| matches!(c, Call::Write(p) if p.starts_with(".veil/objects/pack/") && p.ends_with(".idx")));
    let barrier = calls[..idx].iter().rposition(|c| *c == Call::Barrier).unwrap_or_else(|| panic!("no barrier before the index: {calls:?}"));
    let op = pos(&|c| matches!(c, Call::Write(p) if p.starts_with(".veil/ops/")));
    assert!(barrier < idx && idx < op, "{calls:?}");
    assert!(!calls.iter().any(|c| matches!(c, Call::Write(p) | Call::Unsynced(p) if p.ends_with(".pack"))), "the pack is streamed: {calls:?}");
    let incoming: Vec<String> = std::fs::read_dir(tmp.path().join("b/.veil/objects/incoming")).map(|d| d.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect()).unwrap_or_default();
    assert!(incoming.is_empty(), "the spool and the staging are removed: {incoming:?}");
    let packs: Vec<String> = std::fs::read_dir(tmp.path().join("b/.veil/objects/pack")).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    assert_eq!(packs.len(), 2, "{packs:?}");
    assert_eq!(clone.view().tags["main"].target, c);
}
