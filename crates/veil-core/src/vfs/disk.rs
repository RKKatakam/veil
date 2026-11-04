use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

use super::{DirEntry, Metadata, NodeKind, StatClock, StorageBackend};
use crate::{
    error::{Result, VeilError},
    vpath::VPath,
};

/// Persistent storage rooted at a host directory. Writes are atomic
/// (temp file + rename). Symlinks are not followed and are invisible to the
/// engine in this MVP.
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

/// `(mtime, ctime, inode)` change-detection stamps, nanoseconds since the epoch.
#[cfg(unix)]
fn stamps(m: &fs::Metadata) -> (Option<i64>, Option<i64>, Option<u64>) {
    use std::os::unix::fs::MetadataExt;
    let ns = |s: i64, n: i64| s.checked_mul(1_000_000_000).and_then(|v| v.checked_add(n));
    (ns(m.mtime(), m.mtime_nsec()), ns(m.ctime(), m.ctime_nsec()), Some(m.ino()))
}

#[cfg(not(unix))]
fn stamps(m: &fs::Metadata) -> (Option<i64>, Option<i64>, Option<u64>) {
    let mtime = m
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .and_then(|d| i64::try_from(d.as_nanos()).ok());
    (mtime, None, None)
}

impl StorageBackend for DiskBackend {
    fn kind(&self) -> &'static str {
        "disk"
    }

    fn read(&self, path: &VPath) -> Result<Vec<u8>> {
        let full = self.full_path(path);
        fs::read(&full).map_err(|e| io_err(&full, e))
    }

    fn write(&self, path: &VPath, data: &[u8]) -> Result<()> {
        if path.is_root() {
            return Err(VeilError::InvalidPath("cannot write to the root".into()));
        }
        let full = self.full_path(path);
        let parent = full.parent().expect("non-root path has a parent");
        fs::create_dir_all(parent).map_err(|e| io_err(parent, e))?;
        let tmp = parent.join(format!(
            ".{}.vltmp{}",
            path.file_name(),
            hex::encode(crate::crypto::random_bytes::<4>())
        ));
        let res = (|| {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(data)?;
            f.sync_data().ok();
            drop(f);
            #[cfg(unix)]
            if let Ok(old) = fs::metadata(&full) {
                fs::set_permissions(&tmp, old.permissions())?;
            }
            fs::rename(&tmp, &full)
        })();
        if let Err(e) = res {
            let _ = fs::remove_file(&tmp);
            return Err(io_err(&full, e));
        }
        Ok(())
    }

    fn create_new(&self, path: &VPath, data: &[u8]) -> Result<bool> {
        let full = self.full_path(path);
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent).map_err(|e| io_err(parent, e))?;
        }
        match fs::OpenOptions::new().write(true).create_new(true).open(&full) {
            Ok(mut f) => {
                f.write_all(data).map_err(|e| io_err(&full, e))?;
                Ok(true)
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(false),
            Err(e) => Err(io_err(&full, e)),
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
            Ok(m) if m.is_dir() => Ok(Some(Metadata::unstamped(NodeKind::Dir, 0, false))),
            Ok(m) if m.is_file() => {
                let (mtime, ctime, inode) = stamps(&m);
                Ok(Some(Metadata {
                    kind: NodeKind::File,
                    len: m.len(),
                    executable: is_exec(&m),
                    mtime,
                    ctime,
                    inode,
                }))
            }
            Ok(_) => Ok(None),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io_err(&full, e)),
        }
    }

    fn stat_clock(&self) -> Option<StatClock> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?;
        Some(StatClock {
            now: i64::try_from(now.as_nanos()).ok()?,
            exact: false,
        })
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
