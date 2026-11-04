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
//! * [`SftpBackend`]    — a repository on another machine, reached through
//!   the user's `ssh` and its `sftp` subsystem (remotes).

mod disk;
mod memory;
mod overlay;
mod sftp;
mod sftp_client;
mod sftp_url;

pub use disk::{parse_folding, probe_folding, DiskBackend, FOLDING_ENV};
pub use memory::MemoryBackend;
pub use overlay::{OverlayBackend, OverlayChanges};
pub use sftp::{SftpBackend, SftpOptions, SftpStats};
pub use sftp_url::SshUrl;

pub use crate::vpath::NameFolding;
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

/// A directory listing that also reports what [`StorageBackend::list_dir`]
/// leaves out, so callers can warn about it instead of losing it silently.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DirListing {
    /// Files and directories, sorted by name (exactly `list_dir`).
    pub entries: Vec<DirEntry>,
    /// Names of entries that are neither regular files nor directories
    /// (symlinks, sockets, devices). The engine never follows or records
    /// them, and never writes through or over them.
    pub special: Vec<String>,
    /// Entries whose names are not valid UTF-8, escaped for display
    /// (`\xNN` per invalid byte). They cannot be represented as a [`VPath`].
    pub unrepresentable: Vec<String>,
}

/// Prefix and suffix of the temp files [`DiskBackend`] writes before the
/// atomic rename: `.<name>.vltmp<8 hex digits>`.
const TEMP_MARKER: &str = ".vltmp";

/// Is `name` a temp file left behind by an interrupted [`DiskBackend`]
/// write? Such leftovers are crash debris, never content: the builder skips
/// them.
pub fn is_temp_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix('.') else {
        return false;
    };
    let Some(pos) = rest.rfind(TEMP_MARKER) else {
        return false;
    };
    let suffix = &rest[pos + TEMP_MARKER.len()..];
    pos > 0 && suffix.len() == 8 && suffix.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Abstract storage. All methods take `&self`; implementations use interior
/// mutability so a backend can be shared (`Arc<dyn StorageBackend>`) between
/// the repository, its working copies and concurrent tasks.
pub trait StorageBackend: Send + Sync + std::fmt::Debug {
    /// Human-readable backend kind (`disk`, `memory`, `overlay`, `tree`, `sftp`).
    fn kind(&self) -> &'static str;

    /// Storage reached over a network and shared with clients on other
    /// hosts ([`SftpBackend`]). Its repository lock uses lease-based
    /// takeover with fencing (see `lock.rs`), and sync batches requests
    /// instead of probing object by object.
    fn is_network(&self) -> bool {
        false
    }

    fn read(&self, path: &VPath) -> Result<Vec<u8>>;

    /// Write a file, creating parent directories as needed.
    fn write(&self, path: &VPath, data: &[u8]) -> Result<()>;

    /// Like [`StorageBackend::write`] (atomic, immediately visible), except
    /// that the data only has to be durable once a later
    /// [`StorageBackend::sync_barrier`] returns. Until then a power loss may
    /// leave the file missing, empty or truncated under its final name.
    ///
    /// Transactions write objects this way and issue one barrier before
    /// writing the operation that references them. Backends whose writes
    /// are always durable (or never are) keep the default.
    fn write_unsynced(&self, path: &VPath, data: &[u8]) -> Result<()> {
        self.write(path, data)
    }

    /// Make every [`StorageBackend::write_unsynced`] that returned before
    /// this call durable: file contents, their names, and any directories
    /// created for them. Barriers on one backend value are serialised, so a
    /// caller never returns while writes it depends on are still being
    /// synced by another thread's barrier.
    ///
    /// After a failure, the writes it covered must be treated as lost even
    /// though they read back intact, and even if a later barrier succeeds:
    /// on Linux a failed `fsync` marks the pages clean, so the retry has
    /// nothing to write. Only a new copy (or removing the file) is safe.
    /// [`crate::store::ObjectStore::sync_barrier`] does that for objects.
    fn sync_barrier(&self) -> Result<()> {
        Ok(())
    }

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

    /// [`StorageBackend::list_dir`] plus the entries it cannot represent.
    /// Backends that only hold files and directories with UTF-8 names (all
    /// but [`DiskBackend`]) keep the default.
    fn list_dir_full(&self, path: &VPath) -> Result<DirListing> {
        Ok(DirListing {
            entries: self.list_dir(path)?,
            ..Default::default()
        })
    }

    /// `Ok(None)` when nothing exists at `path`, including when an ancestor
    /// of `path` is a file.
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

    /// How this backend compares names: whether `README` and `readme`, or
    /// NFC and NFD spellings of one name, refer to the same entry. The
    /// builder keeps recorded spellings stable across such aliases and
    /// checkout refuses trees whose names would collide (see
    /// [`NameFolding`]). Exact by default.
    fn name_folding(&self) -> NameFolding {
        NameFolding::EXACT
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
