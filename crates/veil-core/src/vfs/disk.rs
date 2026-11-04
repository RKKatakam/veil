use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

use super::{DirEntry, Metadata, NodeKind, StorageBackend};
use crate::{
    error::{Result, VeilError},
    vpath::VPath,
};

/// Persistent storage rooted at a host directory. Writes are atomic and
/// durable: temp file, fsync, rename, fsync of the directory. When `write`
/// or `create_new` returns, the data survives a crash, so the order of
/// writes is the order in which they become durable (the engine relies on
/// this: objects, then the operation, then the operation head). Symlinks are
/// not followed and are invisible to the engine in this MVP.
#[derive(Debug, Clone)]
pub struct DiskBackend {
    root: PathBuf,
}

fn io_err(path: &Path, e: io::Error) -> VeilError {
    if e.kind() == io::ErrorKind::NotFound {
        VeilError::NotFound(path.display().to_string())
    } else {
        VeilError::Io {
            path: path.display().to_string(),
            source: e,
        }
    }
}

impl DiskBackend {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        DiskBackend { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn full_path(&self, p: &VPath) -> PathBuf {
        let mut f = self.root.clone();
        for c in p.components() {
            f.push(c);
        }
        f
    }
}

#[cfg(unix)]
fn is_exec(m: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    m.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_exec(_m: &fs::Metadata) -> bool {
    false
}

fn temp_path(parent: &Path, path: &VPath) -> PathBuf {
    parent.join(format!(
        ".{}.vltmp{}",
        path.file_name(),
        hex::encode(crate::crypto::random_bytes::<4>())
    ))
}

/// Create `path` with `data`, flushed to stable storage.
fn write_synced(path: &Path, data: &[u8]) -> io::Result<()> {
    let mut f = fs::OpenOptions::new().write(true).create_new(true).open(path)?;
    f.write_all(data)?;
    f.sync_all()
}

fn create_exclusive(full: &Path, data: &[u8]) -> io::Result<bool> {
    let mut f = match fs::OpenOptions::new().write(true).create_new(true).open(full) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => return Ok(false),
        Err(e) => return Err(e),
    };
    if let Err(e) = f.write_all(data).and_then(|_| f.sync_all()) {
        drop(f);
        let _ = fs::remove_file(full);
        return Err(e);
    }
    sync_dir(full.parent().expect("file has a parent"))?;
    Ok(true)
}

/// Flush a directory's entries (new names, renames) to stable storage.
#[cfg(unix)]
fn sync_dir(dir: &Path) -> io::Result<()> {
    match fs::File::open(dir).and_then(|d| d.sync_all()) {
        // Some filesystems cannot fsync directories; nothing more can be done.
        Err(e) if matches!(e.kind(), io::ErrorKind::InvalidInput | io::ErrorKind::Unsupported) => Ok(()),
        r => r,
    }
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> io::Result<()> {
    Ok(())
}

/// `create_dir_all` that also makes every newly created directory durable
/// by syncing its parent.
fn create_dir_all_durable(dir: &Path) -> io::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    let mut missing = Vec::new();
    let mut cur = Some(dir);
    while let Some(d) = cur {
        if d.is_dir() {
            break;
        }
        missing.push(d);
        cur = d.parent();
    }
    fs::create_dir_all(dir)?;
    for d in missing.iter().rev() {
        if let Some(p) = d.parent() {
            sync_dir(p)?;
        }
    }
    Ok(())
}

impl StorageBackend for DiskBackend {
    fn kind(&self) -> &'static str {
        "disk"
    }

    fn read(&self, path: &VPath) -> Result<Vec<u8>> {
        let full = self.full_path(path);
        fs::read(&full).map_err(|e| io_err(&full, e))
    }

    fn read_range(&self, path: &VPath, offset: u64, len: usize) -> Result<Vec<u8>> {
        use std::io::{Read, Seek, SeekFrom};
        let full = self.full_path(path);
        let mut f = fs::File::open(&full).map_err(|e| io_err(&full, e))?;
        f.seek(SeekFrom::Start(offset)).map_err(|e| io_err(&full, e))?;
        let mut buf = vec![0; len];
        f.read_exact(&mut buf).map_err(|e| io_err(&full, e))?;
        Ok(buf)
    }

    fn write(&self, path: &VPath, data: &[u8]) -> Result<()> {
        if path.is_root() {
            return Err(VeilError::InvalidPath("cannot write to the root".into()));
        }
        let full = self.full_path(path);
        let parent = full.parent().expect("non-root path has a parent");
        create_dir_all_durable(parent).map_err(|e| io_err(parent, e))?;
        let tmp = temp_path(parent, path);
        let res = (|| {
            write_synced(&tmp, data)?;
            #[cfg(unix)]
            if let Ok(old) = fs::metadata(&full) {
                fs::set_permissions(&tmp, old.permissions())?;
            }
            fs::rename(&tmp, &full)?;
            // The rename is only durable once the directory entry is.
            sync_dir(parent)
        })();
        if let Err(e) = res {
            let _ = fs::remove_file(&tmp);
            return Err(io_err(&full, e));
        }
        Ok(())
    }

    /// Exclusive create that never exposes a partially written file: the
    /// content is written and synced to a temp file, which is then
    /// hard-linked into place (`link` fails if the target exists). Readers,
    /// such as lock contenders, therefore always see the complete content.
    fn create_new(&self, path: &VPath, data: &[u8]) -> Result<bool> {
        if path.is_root() {
            return Err(VeilError::InvalidPath("cannot write to the root".into()));
        }
        let full = self.full_path(path);
        let parent = full.parent().expect("non-root path has a parent");
        create_dir_all_durable(parent).map_err(|e| io_err(parent, e))?;
        let tmp = temp_path(parent, path);
        if let Err(e) = write_synced(&tmp, data) {
            let _ = fs::remove_file(&tmp);
            return Err(io_err(&full, e));
        }
        let linked = fs::hard_link(&tmp, &full);
        let _ = fs::remove_file(&tmp);
        match linked {
            Ok(()) => {
                sync_dir(parent).map_err(|e| io_err(&full, e))?;
                Ok(true)
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(false),
            // Filesystems without hard links: fall back to O_EXCL. A crash
            // here can leave a short file, which the lock treats as garbage.
            Err(_) => create_exclusive(&full, data).map_err(|e| io_err(&full, e)),
        }
    }

    fn remove_file(&self, path: &VPath) -> Result<()> {
        let full = self.full_path(path);
        match fs::remove_file(&full) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(io_err(&full, e)),
            _ => Ok(()),
        }
    }

    fn remove_dir_all(&self, path: &VPath) -> Result<()> {
        if path.is_root() {
            return Err(VeilError::InvalidPath("refusing to remove the backend root".into()));
        }
        let full = self.full_path(path);
        match fs::remove_dir_all(&full) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(io_err(&full, e)),
            _ => Ok(()),
        }
    }

    fn create_dir_all(&self, path: &VPath) -> Result<()> {
        let full = self.full_path(path);
        fs::create_dir_all(&full).map_err(|e| io_err(&full, e))
    }

    fn list_dir(&self, path: &VPath) -> Result<Vec<DirEntry>> {
        let full = self.full_path(path);
        let mut out = Vec::new();
        for entry in fs::read_dir(&full).map_err(|e| io_err(&full, e))? {
            let entry = entry.map_err(|e| io_err(&full, e))?;
            let Ok(name) = entry.file_name().into_string() else {
                continue; // non-UTF-8 names are not representable in VPath
            };
            let ft = entry.file_type().map_err(|e| io_err(&full, e))?;
            let kind = if ft.is_dir() {
                NodeKind::Dir
            } else if ft.is_file() {
                NodeKind::File
            } else {
                continue; // symlinks, sockets, devices
            };
            out.push(DirEntry { name, kind });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    fn metadata(&self, path: &VPath) -> Result<Option<Metadata>> {
        let full = self.full_path(path);
        match fs::symlink_metadata(&full) {
            Ok(m) if m.is_dir() => Ok(Some(Metadata {
                kind: NodeKind::Dir,
                len: 0,
                executable: false,
            })),
            Ok(m) if m.is_file() => Ok(Some(Metadata {
                kind: NodeKind::File,
                len: m.len(),
                executable: is_exec(&m),
            })),
            Ok(_) => Ok(None),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io_err(&full, e)),
        }
    }

    #[allow(unused_variables)]
    fn set_executable(&self, path: &VPath, executable: bool) -> Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let full = self.full_path(path);
            let m = fs::metadata(&full).map_err(|e| io_err(&full, e))?;
            let mode = m.permissions().mode();
            let new = if executable {
                mode | ((mode & 0o444) >> 2)
            } else {
                mode & !0o111
            };
            if new != mode {
                fs::set_permissions(&full, fs::Permissions::from_mode(new)).map_err(|e| io_err(&full, e))?;
            }
        }
        Ok(())
    }
}
