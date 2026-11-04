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
    /// Modification stamp on the backend's [`StatClock`]: nanoseconds since
    /// the Unix epoch for [`DiskBackend`], a write-generation counter for
    /// [`MemoryBackend`]. `None` means "unknown": stat caches must re-read.
    pub mtime: Option<i64>,
    /// Inode-change stamp (Unix `ctime`, same clock as `mtime`), if known.
    /// Catches edits whose `mtime` was restored afterwards.
    pub ctime: Option<i64>,
    /// File identity (inode number), if the backend has one. Atomic
    /// replace-by-rename changes it even when size and mtime collide.
    pub inode: Option<u64>,
}

impl Metadata {
    /// Metadata with no change-detection stamps (always re-read).
    pub fn unstamped(kind: NodeKind, len: u64, executable: bool) -> Metadata {
        Metadata {
            kind,
            len,
            executable,
            mtime: None,
            ctime: None,
            inode: None,
        }
    }
}

/// The clock [`Metadata::mtime`] is measured on, read *now*. Stat caches use
/// it to recognise "racily clean" files: a file whose stamp is too close to
/// the moment it was verified could change again without its stamp moving.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatClock {
    pub now: i64,
    /// `true` when every write is guaranteed a strictly larger stamp (a
    /// generation counter): there is no racy window at all. `false` for wall
    /// clocks with filesystem-dependent granularity.
    pub exact: bool,
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

    /// Current reading of the clock `Metadata::mtime` stamps come from, or
    /// `None` if this backend's stamps cannot be trusted for change detection
    /// (which disables stat caching).
    fn stat_clock(&self) -> Option<StatClock> {
        None
    }

    fn exists(&self, path: &VPath) -> Result<bool> {
        Ok(self.metadata(path)?.is_some())
    }

    fn read_opt(&self, path: &VPath) -> Result<Option<Vec<u8>>> {
        match self.read(path) {
            Ok(d) => Ok(Some(d)),
            Err(e) if e.is_not_found() => Ok(None),
            Err(e) => Err(e),
        }
    }
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
