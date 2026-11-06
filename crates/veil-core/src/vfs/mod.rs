//! The Virtual File System layer.
//!
//! The engine never talks to the host OS directly. Repositories, working
//! copies and agent sandboxes are all [`StorageBackend`]s:
//!
//! * [`DiskBackend`]    — persistent storage rooted at a host directory.
//! * [`MemoryBackend`]  — pure in-memory tree (tests, CI, WASM, agents).
//! * [`OverlayBackend`] — copy-on-write layer over any read-only lower
//!   backend (typically a [`crate::tree::TreeView`] of a snapshot), giving
//!   O(1) workspace creation and O(changes) snapshots.
//! * [`SandboxFs`]      — a `vl ws exec` sandbox directory: unsynced writes,
//!   copy-on-write clones of the project directory's files.
//! * [`SparseView`]     — a sparse working copy (a sandbox holding a
//!   [`SparseSet`] of paths) seen as the whole tree it was synced from.

#[cfg(all(feature = "os", unix))]
mod beneath;
#[cfg(feature = "os")]
mod disk;
mod memory;
mod overlay;
#[cfg(feature = "os")]
mod sandbox;
mod sparse;

#[cfg(feature = "os")]
pub use disk::{parse_folding, probe_folding, DiskBackend, FOLDING_ENV};
pub use memory::MemoryBackend;
pub use overlay::{OverlayBackend, OverlayChanges};
#[cfg(feature = "os")]
pub use sandbox::{clone_file, private_dir, reflink_supported, remove_tree, CloneSources, SandboxFs, SandboxLock, WrittenFile};
pub use sparse::{restrict, SparseSet, SparseView};

pub use crate::vpath::NameFolding;
use crate::{error::Result, id::ObjectId, vpath::VPath};

/// A size as the `VEIL_SFTP_MAX_FILE` and `VEIL_MAX_OBJECT` settings take
/// it: `123`, `64K`, `512M`, `8G`, `1T` (binary multiples; `KiB`, `MB` …
/// and lower case also accepted). Never 0.
pub fn parse_size(v: &str) -> Option<u64> {
    let v = v.trim();
    let digits = v.find(|c: char| !c.is_ascii_digit()).unwrap_or(v.len());
    let (n, unit) = v.split_at(digits);
    let n: u64 = n.parse().ok()?;
    let shift = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 0,
        "k" | "kb" | "kib" => 10,
        "m" | "mb" | "mib" => 20,
        "g" | "gb" | "gib" => 30,
        "t" | "tb" | "tib" => 40,
        _ => return None,
    };
    n.checked_mul(1u64 << shift).filter(|n| *n > 0)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeKind {
    File,
    Dir,
    /// A symbolic link, seen as itself (never followed): its
    /// [`Metadata::len`] is the length of its target, which
    /// [`StorageBackend::read_link`] returns. Recorded as a symlink entry
    /// in repository format 5; below format 5 the builder treats it as a
    /// special file (never recorded, never followed).
    Symlink,
}

/// Longest symlink target Veil records or writes, in bytes (`PATH_MAX` on
/// Linux and macOS, including the terminating NUL that is not stored).
pub const MAX_LINK_TARGET: usize = 4095;

/// Check a symlink target before it is written to a working copy or
/// recorded: not empty, no NUL byte, valid UTF-8 (a target that is not
/// is reported as unrepresentable, as names are, BUG-039), and at most
/// [`MAX_LINK_TARGET`] bytes. Returns the target as text.
pub fn check_link_target(target: &[u8]) -> Result<&str> {
    let bad = |why: &str| crate::error::VeilError::InvalidPath(format!("invalid symlink target: {why}"));
    if target.is_empty() {
        return Err(bad("it is empty"));
    }
    if target.len() > MAX_LINK_TARGET {
        return Err(bad(&format!("it is {} bytes long, more than {MAX_LINK_TARGET}", target.len())));
    }
    if target.contains(&0) {
        return Err(bad("it holds a NUL byte"));
    }
    std::str::from_utf8(target).map_err(|_| bad("it is not valid UTF-8"))
}

/// Does `target`, a symlink target found at `link` (a path relative to the
/// working copy's root), lead outside the working copy? Absolute targets
/// do; relative ones are resolved lexically against the link's directory,
/// and do when a `..` climbs above the root. Lexical resolution does not
/// follow other links on the way, so this is a property of the target
/// string alone (what `vl status` warns about, and what a sandbox refuses).
pub fn link_escapes(link: &VPath, target: &str) -> bool {
    if target.starts_with('/') {
        return true;
    }
    let mut depth = link.components().count().saturating_sub(1) as i64;
    for part in target.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                depth -= 1;
                if depth < 0 {
                    return true;
                }
            }
            _ => depth += 1,
        }
    }
    false
}

/// May a sandbox materialise the link at `link` (relative to the sandbox
/// root) with `target`, whatever other links the tree holds? `Err` says
/// why not. The rule (symlinks design, threat 7; BUG-708, BUG-709):
///
/// * **Never an absolute target.** Its meaning depends on the reader, not
///   on the string: `/proc/self/cwd/…`, `/proc/self/root/…`, `/dev/fd/N/…`
///   name the sandbox itself, and from there `..` climbs to the project.
/// * **A relative target is some `..` components, then names only**
///   (`.` and empty components aside), and its `..` components do not climb
///   above the root: `../../lib/tool.sh`, never `lib/../tool.sh`.
///
/// Why that is enough, with no knowledge of the other links: every link
/// the sandbox writes sits in a real directory at its own depth (writes
/// never go through a link), so its leading `..` components climb real
/// directories, staying beneath the root. From there, each name is a real
/// entry beneath the root or another link obeying the same rule, which (by
/// induction on the kernel's link expansions) resolves beneath the root.
/// A `..` after a name is what a chain needs (`x -> u/../../..`, where `u`
/// is itself a link: the kernel climbs from `u`'s target, not from `x`'s
/// directory), so it is refused.
pub fn sandbox_link_check(link: &VPath, target: &str) -> std::result::Result<(), &'static str> {
    if target.starts_with('/') {
        return Err("its target is absolute (what it names depends on who reads it, `/proc/self/cwd` names the sandbox)");
    }
    let mut up = 0usize;
    let mut named = false;
    for part in target.split('/') {
        match part {
            "" | "." => {}
            ".." if named => return Err("its target climbs with `..` after a name, which may itself be a link"),
            ".." => up += 1,
            _ => named = true,
        }
    }
    if up > link.components().count().saturating_sub(1) {
        return Err("it leads outside the sandbox");
    }
    Ok(())
}

/// The path (relative to the working copy's root) that relative `target`
/// of the link at `link` names, resolved lexically (see [`link_escapes`]);
/// `None` when it is absolute or leaves the root.
pub fn link_resolves_to(link: &VPath, target: &str) -> Option<Vec<String>> {
    if target.starts_with('/') {
        return None;
    }
    let mut parts: Vec<String> = link.components().map(str::to_string).collect();
    parts.pop();
    for part in target.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            p => parts.push(p.to_string()),
        }
    }
    Some(parts)
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
    /// Names of entries that are neither regular files, directories nor
    /// symlinks (sockets, FIFOs, devices, the root of a `vl ws mount`).
    /// The engine never follows or records them, and never writes through
    /// or over them. Symlinks are in `entries`, as [`NodeKind::Symlink`].
    pub special: Vec<String>,
    /// Entries whose names are not valid UTF-8, escaped for display
    /// (`\xNN` per invalid byte). They cannot be represented as a [`VPath`].
    pub unrepresentable: Vec<String>,
}

/// Prefix and suffix of the temp files [`DiskBackend`] writes before the
/// atomic rename: `.<name>.vltmp<8 hex digits>` (`<name>` cut to its first
/// 32 bytes).
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
    /// Human-readable backend kind (`disk`, `memory`, `overlay`, `tree`).
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

    /// Write `data` for `path` so that no crash can ever leave `path`
    /// torn, without making anything durable yet: the bytes go to a new
    /// temp file beside `path` (a name snapshots ignore, see
    /// [`is_temp_name`]), whose path is returned, with the permissions of
    /// the file at `path`. A [`StorageBackend::sync_barrier`] makes it
    /// durable, then [`StorageBackend::rename_unsynced`] moves it over
    /// `path`, and a second barrier makes the name durable. Checkout
    /// writes the working copy this way: one barrier for every file
    /// instead of an `fsync` each (BUG-818).
    ///
    /// The default writes `path` itself ([`StorageBackend::write_unsynced`])
    /// and returns it: right for backends that a power loss cannot tear
    /// (memory) or that are never durable (sandboxes). A backend whose
    /// unsynced writes can be torn under their final name must override it.
    fn write_staged(&self, path: &VPath, data: &[u8]) -> Result<VPath> {
        self.write_unsynced(path, data)?;
        Ok(path.clone())
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

    /// Rename the file `from` to `to`, replacing a file there and creating
    /// `to`'s parent directories, atomically: a reader sees the whole file
    /// under one name or the other. The new name is only durable once a
    /// later [`StorageBackend::sync_barrier`] returns (which syncs both
    /// directories). Transactions publish their staged objects this way
    /// (`ObjectStore`, format 6). The default copies (unsynced) and removes,
    /// for backends that are memory anyway, and for wrappers.
    fn rename_unsynced(&self, from: &VPath, to: &VPath) -> Result<()> {
        let data = self.read(from)?;
        self.write_unsynced(to, &data)?;
        self.remove_file(from)
    }

    /// How many [`StorageBackend::sync_barrier`] calls on this value failed
    /// so far. A barrier syncs every unsynced write made through this value,
    /// whoever made it: a transaction whose writes overlapped a failed
    /// barrier (another transaction's, on a shared value) treats them as
    /// lost, as the failed caller does. Backends whose barriers never fail
    /// keep the default.
    fn barrier_failures(&self) -> u64 {
        0
    }

    /// Make directory `dir`'s entries part of the next
    /// [`StorageBackend::sync_barrier`]: a name another process created
    /// there (a rename not yet synced) becomes durable before anything
    /// that relies on it is written. The default does nothing (backends
    /// whose names are always durable, or never).
    fn sync_dir_later(&self, _dir: &VPath) -> Result<()> {
        Ok(())
    }

    /// Atomically create a file only if it does not exist. Returns `false`
    /// when the path already exists. Used for repository locks.
    fn create_new(&self, path: &VPath, data: &[u8]) -> Result<bool>;

    /// [`StorageBackend::create_new`], never made durable: a power loss
    /// may leave the file missing, empty or torn under its name. Only for
    /// caches that check what they read (a checksum) and are rebuilt when
    /// it fails: the history index's layers (`graph_index`). The default
    /// is [`StorageBackend::create_new`].
    fn create_new_unsynced(&self, path: &VPath, data: &[u8]) -> Result<bool> {
        self.create_new(path, data)
    }

    /// Remove a file. Removing a missing file is not an error.
    fn remove_file(&self, path: &VPath) -> Result<()>;

    /// Remove a directory and everything below it. Missing is not an error.
    fn remove_dir_all(&self, path: &VPath) -> Result<()>;

    fn create_dir_all(&self, path: &VPath) -> Result<()>;

    /// Direct children of a directory, sorted by name: files, directories
    /// and symlinks ([`NodeKind::Symlink`], never followed).
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
    /// of `path` is a file or a symlink (nothing is ever looked up through
    /// a link). A symlink at `path` itself is [`NodeKind::Symlink`].
    fn metadata(&self, path: &VPath) -> Result<Option<Metadata>>;

    /// The target of the symlink at `path`, never followed. `NotFound`
    /// when nothing is there (or an ancestor is not a directory),
    /// `InvalidPath` when something other than a symlink is. Backends that
    /// cannot hold symlinks return `Unsupported`.
    fn read_link(&self, path: &VPath) -> Result<Vec<u8>> {
        Err(crate::error::VeilError::Unsupported(format!(
            "{path}: this storage ({}) cannot hold symlinks",
            self.kind()
        )))
    }

    /// Create (or atomically replace) a symlink at `path` pointing at
    /// `target`, which is written as it is and never resolved. Creates
    /// parent directories as needed, and like every write never goes
    /// through a symlink on the way (see [`DiskBackend`]). Replaces a file
    /// or symlink at `path`, never a directory. `target` must pass
    /// [`check_link_target`].
    fn write_link(&self, path: &VPath, target: &[u8]) -> Result<()> {
        let _ = target;
        Err(crate::error::VeilError::Unsupported(format!(
            "{path}: this storage ({}) cannot hold symlinks",
            self.kind()
        )))
    }

    /// Can this backend hold symlinks ([`StorageBackend::write_link`])?
    /// Checkout reports links it cannot write instead of trying each.
    fn supports_links(&self) -> bool {
        false
    }

    fn set_executable(&self, path: &VPath, executable: bool) -> Result<()>;

    /// Optional fast-path hint: if the node at `path` is known to be byte-for-
    /// byte identical to an object already in the CAS, return that object's
    /// id. Tree views and overlays implement this so snapshotting an
    /// ephemeral workspace only touches what actually changed.
    fn known_id(&self, _path: &VPath) -> Option<ObjectId> {
        None
    }

    /// Materialise at `path` the file whose content is object `id` (a blob,
    /// or the sealed object of a cloaked file) without being handed its
    /// bytes, if this backend knows an identical copy it can clone cheaply:
    /// a [`SandboxFs`] reflinks the project directory's file. `Ok(false)`
    /// means nothing was done and the bytes must be written as usual.
    /// Checkout only asks where it would otherwise write `id`'s content
    /// over nothing it needs to protect.
    fn clone_known(&self, _path: &VPath, _id: &ObjectId) -> Result<bool> {
        Ok(false)
    }

    /// Can [`StorageBackend::clone_known`] ever succeed here? Checkout
    /// reads nothing for a clone where it cannot.
    fn clones(&self) -> bool {
        false
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

    /// What occupies `path` if it is neither a file nor a directory (a
    /// symlink, socket, device): such an entry is never read through, yet
    /// makes [`StorageBackend::create_new`] fail. `Some("a symlink")` and
    /// the like, for diagnostics; `None` when nothing special is there (or
    /// the backend cannot hold such entries, the default). Sockets and
    /// devices are invisible to [`StorageBackend::metadata`]; a symlink is
    /// [`NodeKind::Symlink`] there.
    fn special_at(&self, _path: &VPath) -> Result<Option<&'static str>> {
        Ok(None)
    }

    /// Read `len` bytes starting at `offset` (used for packfiles). The
    /// default reads the whole file; backends override it to avoid that.
    /// Reading past the end of the file is an error.
    fn read_range(&self, path: &VPath, offset: u64, len: usize) -> Result<Vec<u8>> {
        let data = self.read(path)?;
        slice_range(path, &data, offset, len).map(<[u8]>::to_vec)
    }

    /// Read a symlink at `path` through to the regular file it leads to (at
    /// most `limit` bytes), with that file's resolved path (for display and
    /// checks): `Ok(None)` when nothing special is at `path`
    /// (read it as usual), `Err` for a symlink that dangles, loops, or does
    /// not lead to a regular file of at most `limit` bytes, and for any other
    /// special file (a FIFO, a socket). Only the working copy's policy file
    /// is read this way (see [`crate::policy::read_policy_file`]): every
    /// other read treats symlinks as invisible. Backends without symlinks
    /// keep the default.
    fn read_through_link(&self, _path: &VPath, _limit: u64) -> Result<Option<(String, Vec<u8>)>> {
        Ok(None)
    }

    fn read_opt(&self, path: &VPath) -> Result<Option<Vec<u8>>> {
        match self.read(path) {
            Ok(d) => Ok(Some(d)),
            Err(e) if e.is_not_found() => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Start a new file in `dir`, written piece by piece and named only
    /// when it is complete ([`StreamWriter::finish`]), so a file larger
    /// than memory can be written (packs, downloads; BUG-800). Nothing is
    /// visible under the final name before `finish`, and a writer dropped
    /// without it leaves nothing behind but, after a crash, a temp file
    /// (`.stream.vltmp…`, see [`is_temp_name`]).
    ///
    /// `durable`: `finish` returns only once the content and its name are
    /// on stable storage. Otherwise the file may be lost or torn at a
    /// power cut (a download spool, deleted after use).
    ///
    /// The default buffers in memory and publishes with
    /// [`StorageBackend::write`] (or [`StorageBackend::write_unsynced`]):
    /// backends that are memory anyway, and wrappers, keep it.
    fn create_stream<'a>(&'a self, dir: &VPath, durable: bool) -> Result<Box<dyn StreamWriter + 'a>> {
        Ok(Box::new(Buffered {
            backend: self,
            dir: dir.clone(),
            durable,
            buf: Vec::new(),
        }))
    }

    /// Bytes free for new files at `dir` (`statvfs`), if this backend can
    /// tell. A pull checks it before downloading.
    fn available_space(&self, _dir: &VPath) -> Option<u64> {
        None
    }

    /// The operating-system path of `path`, for a backend that is a local
    /// directory: the gc lease is an `flock` on it ([`crate::maintenance::GcLease`]).
    fn local_path(&self, _path: &VPath) -> Option<std::path::PathBuf> {
        None
    }
}

/// A file being written by [`StorageBackend::create_stream`].
pub trait StreamWriter {
    /// Append `data`.
    fn write_all(&mut self, data: &[u8]) -> Result<()>;
    /// Overwrite bytes already written, at `offset`.
    fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<()>;
    /// Publish the file as `name` in its directory, atomically (replacing
    /// a file of that name), and durably if it was created so.
    fn finish(self: Box<Self>, name: &str) -> Result<()>;
}

/// The default [`StreamWriter`]: everything in memory until `finish`.
struct Buffered<'a, B: ?Sized> {
    backend: &'a B,
    dir: VPath,
    durable: bool,
    buf: Vec<u8>,
}

impl<B: StorageBackend + ?Sized> StreamWriter for Buffered<'_, B> {
    fn write_all(&mut self, data: &[u8]) -> Result<()> {
        self.buf.extend_from_slice(data);
        Ok(())
    }

    fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        let at = usize::try_from(offset).ok().filter(|at| at.checked_add(data.len()).is_some_and(|end| end <= self.buf.len()));
        let Some(at) = at else {
            return Err(crate::error::VeilError::repo("stream: write past the end"));
        };
        self.buf[at..at + data.len()].copy_from_slice(data);
        Ok(())
    }

    fn finish(self: Box<Self>, name: &str) -> Result<()> {
        let path = self.dir.join(name);
        match self.durable {
            true => self.backend.write(&path, &self.buf),
            false => self.backend.write_unsynced(&path, &self.buf),
        }
    }
}

/// The temp file name a [`StreamWriter`] writes under until `finish`:
/// `.stream-<owner>.vltmp<8 hex digits>`, naming this process
/// ([`crate::lock::Owner`]), so that maintenance removes it only once its
/// writer is provably gone ([`temp_owner`]).
#[cfg(feature = "os")]
pub(crate) fn stream_temp_name() -> String {
    format!(
        ".stream-{}{TEMP_MARKER}{}",
        crate::lock::process_owner(),
        hex::encode(crate::crypto::random_bytes::<4>())
    )
}

/// The owner tag in a stream temp file's name (`.stream-<owner>.vltmp…`), if
/// it has one (older vl wrote `.stream.vltmp…`).
pub fn temp_owner(name: &str) -> Option<&str> {
    let rest = name.strip_prefix(".stream-")?;
    let end = rest.rfind(TEMP_MARKER)?;
    is_temp_name(name).then(|| &rest[..end])
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
/// any directory for which `skip` returns true. Symlinks are neither listed
/// nor followed ([`walk_leaves`] lists them too).
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
                // A leaf: never descended into.
                NodeKind::Symlink => {}
            }
        }
    }
    out.sort();
    Ok(out)
}

/// [`walk_files`], with symlinks listed too (never followed).
pub fn walk_leaves(fs: &dyn StorageBackend, dir: &VPath, skip: &dyn Fn(&VPath) -> bool) -> Result<Vec<(VPath, NodeKind)>> {
    let mut out = Vec::new();
    let mut stack = vec![dir.clone()];
    while let Some(d) = stack.pop() {
        for c in fs.list_dir(&d)? {
            let p = d.join(&c.name);
            if skip(&p) {
                continue;
            }
            match c.kind {
                NodeKind::Dir => stack.push(p),
                k => out.push((p, k)),
            }
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// Does a directory with this listing hold a Veil repository of its own: a
/// `.veil` that is a directory, or a symlink (to one, possibly)? Asked of
/// every directory but a working copy's root. Such a nested repository
/// (a vendored project, a monorepo member, `vl init` run in the wrong
/// place) is never recorded by the enclosing repository, as Git never
/// records an embedded repository's files: its cloaked files are plaintext
/// on disk, and only its own policy knows they are secret (BUG-200).
/// Checkout never writes or removes anything inside one either.
pub fn holds_repository(listing: &DirListing) -> bool {
    use crate::object::is_reserved_name;
    listing
        .entries
        .iter()
        .any(|e| matches!(e.kind, NodeKind::Dir | NodeKind::Symlink) && is_reserved_name(&e.name))
        || listing.special.iter().any(|n| is_reserved_name(n))
}

/// Is `dir` of `fs` (never the root) the top of a nested Veil repository
/// (see [`holds_repository`])? `false` for anything that is not a
/// directory, or that cannot be listed.
pub fn is_nested_repository(fs: &dyn StorageBackend, dir: &VPath) -> Result<bool> {
    if dir.is_root() || !matches!(fs.metadata(dir), Ok(Some(m)) if m.kind == NodeKind::Dir) {
        return Ok(false);
    }
    Ok(fs.list_dir_full(dir).is_ok_and(|l| holds_repository(&l)))
}
