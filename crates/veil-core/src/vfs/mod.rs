//! The Virtual File System layer.
//!
//! The engine never talks to the host OS directly. Repositories, working
//! copies, remotes and agent sandboxes are all [`StorageBackend`]s:
//!
//! * [`DiskBackend`]    — persistent storage rooted at a host directory.
//! * [`MemoryBackend`]  — pure in-memory tree (tests, CI, WASM, agents).
//! * [`OverlayBackend`] — copy-on-write layer over any read-only lower
//!   backend (typically a [`crate::tree::TreeView`] of a snapshot), giving
//!   O(1) workspace creation and O(changes) snapshots.

mod disk;
mod memory;
mod overlay;

pub use disk::DiskBackend;
pub use memory::MemoryBackend;
pub use overlay::{OverlayBackend, OverlayChanges};

use crate::{error::Result, id::ObjectId, vpath::VPath};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeKind {
    File,
    Dir,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Metadata {
    pub kind: NodeKind,
    pub len: u64,
    pub executable: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    pub name: String,
    pub kind: NodeKind,
}

/// Abstract storage. All methods take `&self`; implementations use interior
/// mutability so a backend can be shared (`Arc<dyn StorageBackend>`) between
/// the repository, its working copies and concurrent tasks.
pub trait StorageBackend: Send + Sync + std::fmt::Debug {
    /// Human-readable backend kind (`disk`, `memory`, `overlay`, `tree`).
    fn kind(&self) -> &'static str;

    fn read(&self, path: &VPath) -> Result<Vec<u8>>;

    /// Write a file, creating parent directories as needed.
    fn write(&self, path: &VPath, data: &[u8]) -> Result<()>;

    /// Atomically create a file only if it does not exist. Returns `false`
    /// when the path already exists. Used for repository locks.
    fn create_new(&self, path: &VPath, data: &[u8]) -> Result<bool>;

    /// Remove a file. Removing a missing file is not an error.
    fn remove_file(&self, path: &VPath) -> Result<()>;

    /// Remove a directory and everything below it. Missing is not an error.
    fn remove_dir_all(&self, path: &VPath) -> Result<()>;

    fn create_dir_all(&self, path: &VPath) -> Result<()>;

    /// Direct children of a directory, sorted by name.
    fn list_dir(&self, path: &VPath) -> Result<Vec<DirEntry>>;

    /// `Ok(None)` when nothing exists at `path`.
    fn metadata(&self, path: &VPath) -> Result<Option<Metadata>>;

    fn set_executable(&self, path: &VPath, executable: bool) -> Result<()>;

    /// Optional fast-path hint: if the node at `path` is known to be byte-for-
    /// byte identical to an object already in the CAS, return that object's
    /// id. Tree views and overlays implement this so snapshotting an
    /// ephemeral workspace only touches what actually changed.
    fn known_id(&self, _path: &VPath) -> Option<ObjectId> {
        None
    }

    fn exists(&self, path: &VPath) -> Result<bool> {
        Ok(self.metadata(path)?.is_some())
    }

    /// Read `len` bytes starting at `offset` (used for packfiles). The
    /// default reads the whole file; backends override it to avoid that.
    /// Reading past the end of the file is an error.
    fn read_range(&self, path: &VPath, offset: u64, len: usize) -> Result<Vec<u8>> {
        let data = self.read(path)?;
        slice_range(path, &data, offset, len).map(<[u8]>::to_vec)
    }

    fn read_opt(&self, path: &VPath) -> Result<Option<Vec<u8>>> {
        match self.read(path) {
            Ok(d) => Ok(Some(d)),
            Err(e) if e.is_not_found() => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// Bounds-checked `data[offset..offset + len]` for [`StorageBackend::read_range`].
pub(crate) fn slice_range<'a>(path: &VPath, data: &'a [u8], offset: u64, len: usize) -> Result<&'a [u8]> {
    usize::try_from(offset)
        .ok()
        .and_then(|start| Some(start..start.checked_add(len)?))
        .and_then(|r| data.get(r))
        .ok_or_else(|| crate::error::VeilError::Io {
            path: path.to_string(),
            source: std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "read past the end of the file"),
        })
}

/// Recursively list every file below `dir` (depth-first, sorted), skipping
/// any directory for which `skip` returns true.
pub fn walk_files(
    fs: &dyn StorageBackend,
    dir: &VPath,
    skip: &dyn Fn(&VPath) -> bool,
) -> Result<Vec<VPath>> {
    let mut out = Vec::new();
    let mut stack = vec![dir.clone()];
    while let Some(d) = stack.pop() {
        let mut children = fs.list_dir(&d)?;
        children.reverse();
        for c in children {
            let p = d.join(&c.name);
            if skip(&p) {
                continue;
            }
            match c.kind {
                NodeKind::Dir => stack.push(p),
                NodeKind::File => out.push(p),
            }
        }
    }
    out.sort();
    Ok(out)
}
