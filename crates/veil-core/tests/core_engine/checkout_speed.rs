//! BUG-818: checkout makes every file durable on its own (an `fsync` per
//! file and per directory entry), which dominates a large clone.

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use veil_core::{
    vfs::{DirEntry, Metadata},
    Identity, MemoryBackend, Repo, Result, StorageBackend, VPath,
};

/// A backend that counts durable writes (each one an fsync on disk).
#[derive(Debug)]
struct Counting {
    inner: MemoryBackend,
    durable: AtomicUsize,
}

impl StorageBackend for Counting {
    fn kind(&self) -> &'static str {
        "counting"
    }
    fn read(&self, p: &VPath) -> Result<Vec<u8>> {
        self.inner.read(p)
    }
    fn write(&self, p: &VPath, d: &[u8]) -> Result<()> {
        self.durable.fetch_add(1, Ordering::Relaxed);
        self.inner.write(p, d)
    }
    fn write_unsynced(&self, p: &VPath, d: &[u8]) -> Result<()> {
        self.inner.write(p, d)
    }
    fn create_new(&self, p: &VPath, d: &[u8]) -> Result<bool> {
        self.inner.create_new(p, d)
    }
    fn remove_file(&self, p: &VPath) -> Result<()> {
        self.inner.remove_file(p)
    }
    fn remove_dir_all(&self, p: &VPath) -> Result<()> {
        self.inner.remove_dir_all(p)
    }
    fn create_dir_all(&self, p: &VPath) -> Result<()> {
        self.inner.create_dir_all(p)
    }
    fn list_dir(&self, p: &VPath) -> Result<Vec<DirEntry>> {
        self.inner.list_dir(p)
    }
    fn metadata(&self, p: &VPath) -> Result<Option<Metadata>> {
        self.inner.metadata(p)
    }
    fn set_executable(&self, p: &VPath, x: bool) -> Result<()> {
        self.inner.set_executable(p, x)
    }
}

#[test]
#[ignore = "BUG-818: checkout makes each file durable on its own instead of one barrier"]
fn checkout_of_many_files_is_one_barrier_not_one_fsync_per_file() {
    let mut repo = Repo::init(Arc::new(MemoryBackend::new()), Some(Identity::generate("a")), "a").unwrap();
    let ws = repo.ephemeral_workspace(repo.root_id()).unwrap();
    for i in 0..200 {
        ws.write(&format!("d{}/f{i}.txt", i / 50), &format!("file {i}")).unwrap();
    }
    let (snap, _) = repo.commit_ephemeral(&ws, "many").unwrap();
    let tree = repo.snapshot(&snap).unwrap().tree;
    let wc = Counting {
        inner: MemoryBackend::new(),
        durable: AtomicUsize::new(0),
    };
    let mut record = veil_core::checkout::Materialised::default();
    let co = repo.checkout_tree_recorded(&wc, None, &tree, &mut record, None).unwrap();
    assert_eq!(co.written, 200);
    let durable = wc.durable.load(Ordering::Relaxed);
    assert!(durable <= 4, "{durable} durable writes for 200 files: one fsync each");
}
