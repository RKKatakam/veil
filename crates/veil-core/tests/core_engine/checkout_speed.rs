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
fn checkout_of_many_files_is_one_barrier_not_one_fsync_per_file() {
    let mut repo = Repo::init(Arc::new(MemoryBackend::new()), Some(Identity::generate("a")), "a").unwrap();
    let ws = repo.ephemeral_workspace(repo.root_id()).unwrap();
    for i in 0..200 {
        ws.write(&format!("d{}/f{i}.txt", i / 50), format!("file {i}")).unwrap();
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

/// BUG-818 on a real disk: checkout stages each file beside its path and
/// renames it into place after the barrier. What it leaves is what a
/// durable write per file left: the new content, a replaced file's mode
/// (an owner's `chmod 640` survives), the executable bit as the tree says,
/// and no staged copy anywhere.
#[cfg(unix)]
#[test]
fn staged_checkout_on_disk_keeps_modes_and_leaves_no_staged_copies() {
    use std::os::unix::fs::PermissionsExt;
    let mut repo = Repo::init(Arc::new(MemoryBackend::new()), Some(Identity::generate("a")), "a").unwrap();
    let ws = repo.ephemeral_workspace(repo.root_id()).unwrap();
    ws.write("kept-mode.txt", "v1\n").unwrap();
    ws.write("run.sh", "#!/bin/sh\n").unwrap();
    ws.fs().set_executable(&VPath::new("run.sh").unwrap(), true).unwrap();
    ws.write("gone/old.txt", "old\n").unwrap();
    let (v1, _) = repo.commit_ephemeral(&ws, "v1").unwrap();
    let ws = repo.ephemeral_workspace(v1).unwrap();
    ws.write("kept-mode.txt", "v2\n").unwrap();
    ws.write("run.sh", "not a script any more\n").unwrap();
    ws.fs().set_executable(&VPath::new("run.sh").unwrap(), false).unwrap();
    ws.remove("gone/old.txt").unwrap();
    ws.write("new/tool.sh", "#!/bin/sh\necho hi\n").unwrap();
    ws.fs().set_executable(&VPath::new("new/tool.sh").unwrap(), true).unwrap();
    let (v2, _) = repo.commit_ephemeral(&ws, "v2").unwrap();
    let (t1, t2) = (repo.snapshot(&v1).unwrap().tree, repo.snapshot(&v2).unwrap().tree);

    let dir = tempfile::tempdir().unwrap();
    let disk = veil_core::DiskBackend::new(dir.path());
    let mut record = veil_core::checkout::Materialised::default();
    repo.checkout_tree_recorded(&disk, None, &t1, &mut record, None).unwrap();
    let mode = |p: &str| std::fs::metadata(dir.path().join(p)).unwrap().permissions().mode() & 0o777;
    std::fs::set_permissions(dir.path().join("kept-mode.txt"), std::fs::Permissions::from_mode(0o640)).unwrap();
    assert_ne!(mode("run.sh") & 0o111, 0);
    let co = repo.checkout_tree_recorded(&disk, Some(&t1), &t2, &mut record, None).unwrap();
    assert_eq!((co.written, co.removed), (3, 1), "{co:?}");
    assert_eq!(std::fs::read(dir.path().join("kept-mode.txt")).unwrap(), b"v2\n");
    assert_eq!(mode("kept-mode.txt"), 0o640, "the replaced file's mode is kept");
    assert_eq!(mode("run.sh") & 0o111, 0, "no longer executable");
    assert_ne!(mode("new/tool.sh") & 0o111, 0, "a new executable");
    assert!(!dir.path().join("gone").exists(), "the emptied directory is removed");
    let names = walkdir(dir.path());
    assert!(
        !names.iter().any(|n| veil_core::vfs::is_temp_name(n)),
        "a staged copy was left behind: {names:?}"
    );
}

/// Every file name below `dir` (`.veil` aside).
#[cfg(unix)]
fn walkdir(dir: &std::path::Path) -> Vec<String> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).unwrap() {
        let e = e.unwrap();
        let name = e.file_name().into_string().unwrap();
        if name == ".veil" {
            continue;
        }
        if e.file_type().unwrap().is_dir() {
            out.extend(walkdir(&e.path()));
        }
        out.push(name);
    }
    out
}
