//! The file system a `vl ws mount` serves, without the kernel.
//!
//! [`MountFs`] speaks in inode numbers, file handles and `errno` values,
//! as FUSE does, but knows nothing about FUSE: the adapter in
//! `mount/fuse.rs` only translates. So every operation is unit-tested here
//! over [`MemoryBackend`](veil_core::vfs::MemoryBackend)s.
//!
//! **Layers.** Reads come from an [`OverlayBackend`]: its lower layer is a
//! [`ReaderView`] of the workspace's tree (what *this* reader may see: a
//! secret file it cannot decrypt is absent, exactly as checkout writes
//! it), its upper layer holds every write, and
//! whiteouts hide what was deleted. The lower layer is never written. The
//! upper layer of a real mount is a directory on disk
//! (`.veil/local/mounts/<ws>/upper`) and whiteouts are appended to a
//! journal, so a crash of the mount loses nothing that was closed.
//!
//! **Open files** live on disk, not in memory (BUG-561): the first write
//! (or `truncate`) of a file only the lower layer has copies it up into
//! the upper layer (atomically and durably: temp file, fsync, rename), and
//! from then on reads and writes go straight to that upper file, opened
//! in place ([`UpperFiles`]); `flush` (every `close`), `fsync` and
//! `release` sync it. A `truncate` to any size is a hole, which costs
//! nothing until data is written. A file only the lower layer has is read
//! once while it is open (a read never decrypts a file twice). A file
//! never grows past the largest object Veil records ([`max_file_size`]): a
//! larger size or offset is `EFBIG`, never the end of the mount (BUG-536).
//! A rename moves an upper file (O(1), holes and all) instead of copying
//! it.
//!
//! **What the mount never showed.** Deleting a directory hides the lower
//! layer's whole subtree, including files this reader could not read and
//! so never saw. Those are remembered ([`MountFs::unseen`], persisted with
//! the whiteouts) and carried by every recording, never recorded as
//! deleted, even once a grant has made them readable (BUG-534).
//!
//! **Moving the base.** After the overlay was recorded, or when the
//! workspace moved under the mount, [`MountFs::record_with`] (which reconciles) and
//! [`MountFs::switch_lower`] put the overlay over the new tree, keeping
//! what it shows.

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    sync::{Arc, Mutex, MutexGuard},
    time::SystemTime,
};

use veil_core::{
    error::Result as VResult,
    id::ObjectId,
    object::{is_reserved_name, EntryKind, TreeEntry},
    store::ObjectStore,
    tree::{lookup, TreeView},
    vfs::{is_temp_name, walk_files, walk_leaves, DirEntry, Metadata, NodeKind, OverlayBackend, StorageBackend},
    VPath, VeilError,
};

/// An `errno` value.
pub type Errno = i32;
pub type FsResult<T> = std::result::Result<T, Errno>;

/// The root directory's inode number.
pub const ROOT: u64 = 1;

/// What `stat` says about a node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attr {
    pub ino: u64,
    pub kind: NodeKind,
    pub size: u64,
    pub executable: bool,
    pub mtime: SystemTime,
}

/// Where whiteouts are persisted (the mount's journal). An in-memory mount
/// (the unit tests) has none.
pub trait Journal: Send {
    /// `path` is hidden from the lower layer from now on.
    fn whiteout(&mut self, path: &VPath) -> std::io::Result<()>;
    /// The whiteouts are exactly `all` now (compaction, after a rebase).
    fn rewrite(&mut self, all: &[VPath]) -> std::io::Result<()>;
    /// The files the mount never showed are exactly `all` now (see
    /// [`MountFs::unseen`]). Written before the whiteout that hides them.
    fn unseen(&mut self, _all: &[VPath]) -> std::io::Result<()> {
        Ok(())
    }
}

/// A file of the upper layer, open for reading and writing in place: what
/// an open file of the mount is backed by once the upper layer has it
/// (BUG-561).
pub trait UpperFile: Send {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> std::io::Result<usize>;
    fn write_at(&mut self, data: &[u8], offset: u64) -> std::io::Result<()>;
    /// Grow (sparsely: a hole costs nothing) or shrink the file.
    fn set_len(&mut self, len: u64) -> std::io::Result<()>;
    fn len(&self) -> std::io::Result<u64>;
    /// Make what was written durable (`fsync`).
    fn sync(&mut self) -> std::io::Result<()>;
    /// Its path is about to be unlinked or replaced while the file is
    /// still open: it keeps its content for the handles still open, and
    /// what they write reaches no path from now on.
    fn unlinked(&mut self) {}
    /// It was renamed to `to`.
    fn moved(&mut self, _to: &VPath) {}
}

/// Opens the files of an upper layer in place.
pub trait UpperFiles: Send + Sync {
    /// The regular file at `path` of the upper layer.
    fn open(&self, path: &VPath) -> std::io::Result<Box<dyn UpperFile>>;
    /// Rename upper file `from` to `to`, whose directory the upper layer
    /// has: O(1), holes and all, and an open file follows it.
    fn rename(&self, from: &VPath, to: &VPath) -> std::io::Result<()>;
    /// Write `src`'s content as the upper file `path` (whose directory the
    /// upper layer has), atomically and durably, a piece at a time:
    /// `false` when this layer cannot (write it whole instead).
    fn put_from(&self, _path: &VPath, _src: &std::fs::File) -> std::io::Result<bool> {
        Ok(false)
    }
}

/// [`UpperFiles`] of an upper layer that is a directory on disk (a real
/// mount's `.veil/local/mounts/<ws>/upper`).
pub struct DiskFiles {
    root: std::path::PathBuf,
}

impl DiskFiles {
    pub fn new(root: impl Into<std::path::PathBuf>) -> DiskFiles {
        DiskFiles { root: root.into() }
    }

    fn full(&self, p: &VPath) -> std::path::PathBuf {
        let mut out = self.root.clone();
        out.extend(p.components());
        out
    }
}

struct DiskFile(std::fs::File);

impl UpperFile for DiskFile {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> std::io::Result<usize> {
        std::os::unix::fs::FileExt::read_at(&self.0, buf, offset)
    }
    fn write_at(&mut self, data: &[u8], offset: u64) -> std::io::Result<()> {
        std::os::unix::fs::FileExt::write_all_at(&self.0, data, offset)
    }
    fn set_len(&mut self, len: u64) -> std::io::Result<()> {
        self.0.set_len(len)
    }
    fn len(&self) -> std::io::Result<u64> {
        Ok(self.0.metadata()?.len())
    }
    fn sync(&mut self) -> std::io::Result<()> {
        self.0.sync_data()
    }
}

impl UpperFiles for DiskFiles {
    fn open(&self, path: &VPath) -> std::io::Result<Box<dyn UpperFile>> {
        use std::os::unix::fs::OpenOptionsExt;
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(self.full(path))?;
        if !f.metadata()?.is_file() {
            return Err(std::io::Error::from_raw_os_error(libc::EIO));
        }
        Ok(Box::new(DiskFile(f)))
    }

    fn rename(&self, from: &VPath, to: &VPath) -> std::io::Result<()> {
        let (a, b) = (self.full(from), self.full(to));
        std::fs::rename(&a, &b)?;
        // Durable once both directory entries are (best effort: a crash
        // before can only leave the file where it was).
        for dir in [a.parent(), b.parent()].into_iter().flatten() {
            if let Ok(d) = std::fs::File::open(dir) {
                let _ = d.sync_all();
            }
        }
        Ok(())
    }

    /// A private temporary file beside it, filled a piece at a time,
    /// synced, then renamed into place and its directory synced: a crash
    /// leaves the old state or the whole copy (BUG-1368).
    fn put_from(&self, path: &VPath, src: &std::fs::File) -> std::io::Result<bool> {
        use std::os::unix::fs::{FileExt, OpenOptionsExt};
        let to = self.full(path);
        let dir = to.parent().ok_or_else(|| std::io::Error::from_raw_os_error(libc::EINVAL))?;
        // A temporary name every listing skips (`is_temp_name`): a copy a
        // crash leaves is never taken for a file.
        let name = to.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let tmp = dir.join(format!(".{name}.vltmp{}", hex::encode(veil_core::crypto::random_bytes::<4>())));
        let done = (|| -> std::io::Result<()> {
            let out = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(&tmp)?;
            let mut buf = vec![0u8; 1 << 20];
            let mut at = 0u64;
            loop {
                let n = src.read_at(&mut buf, at)?;
                if n == 0 {
                    break;
                }
                out.write_all_at(&buf[..n], at)?;
                at += n as u64;
            }
            out.sync_all()?;
            std::fs::rename(&tmp, &to)?;
            std::fs::File::open(dir)?.sync_all()
        })();
        if done.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        done.map(|()| true)
    }
}

/// [`UpperFiles`] over any [`StorageBackend`]: every write rewrites the
/// whole file. For upper layers in memory (the unit tests).
pub struct BackendFiles(pub Arc<dyn StorageBackend>);

struct BackendFile {
    fs: Arc<dyn StorageBackend>,
    path: VPath,
    /// The content, once the path was unlinked.
    own: Option<Vec<u8>>,
}

fn veil_io(e: VeilError) -> std::io::Error {
    std::io::Error::from_raw_os_error(errno(&e))
}

impl BackendFile {
    fn data(&self) -> std::io::Result<Vec<u8>> {
        match &self.own {
            Some(d) => Ok(d.clone()),
            None => self.fs.read(&self.path).map_err(veil_io),
        }
    }
    fn store(&mut self, data: Vec<u8>) -> std::io::Result<()> {
        match &mut self.own {
            Some(d) => {
                *d = data;
                Ok(())
            }
            None => self.fs.write(&self.path, &data).map_err(veil_io),
        }
    }
}

/// Grow `data` to `len` bytes without aborting on a failed allocation.
fn grow(data: &mut Vec<u8>, len: u64) -> std::io::Result<()> {
    let len = usize::try_from(len).map_err(|_| std::io::Error::from_raw_os_error(libc::EFBIG))?;
    if len > data.len() {
        data.try_reserve_exact(len - data.len()).map_err(|_| std::io::Error::from_raw_os_error(libc::ENOMEM))?;
    }
    data.resize(len, 0);
    Ok(())
}

impl UpperFile for BackendFile {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> std::io::Result<usize> {
        let data = self.data()?;
        let start = usize::try_from(offset).unwrap_or(usize::MAX).min(data.len());
        let n = buf.len().min(data.len() - start);
        buf[..n].copy_from_slice(&data[start..start + n]);
        Ok(n)
    }
    fn write_at(&mut self, bytes: &[u8], offset: u64) -> std::io::Result<()> {
        let mut data = self.data()?;
        let end = offset + bytes.len() as u64;
        if (data.len() as u64) < end {
            grow(&mut data, end)?;
        }
        data[offset as usize..end as usize].copy_from_slice(bytes);
        self.store(data)
    }
    fn set_len(&mut self, len: u64) -> std::io::Result<()> {
        let mut data = self.data()?;
        grow(&mut data, len)?;
        self.store(data)
    }
    fn len(&self) -> std::io::Result<u64> {
        Ok(self.data()?.len() as u64)
    }
    fn sync(&mut self) -> std::io::Result<()> {
        Ok(())
    }
    fn unlinked(&mut self) {
        if self.own.is_none() {
            self.own = Some(self.data().unwrap_or_default());
        }
    }
    fn moved(&mut self, to: &VPath) {
        self.path = to.clone();
    }
}

impl UpperFiles for BackendFiles {
    fn open(&self, path: &VPath) -> std::io::Result<Box<dyn UpperFile>> {
        Ok(Box::new(BackendFile {
            fs: self.0.clone(),
            path: path.clone(),
            own: None,
        }))
    }

    fn rename(&self, from: &VPath, to: &VPath) -> std::io::Result<()> {
        let m = self.0.metadata(from).map_err(veil_io)?.ok_or_else(|| std::io::Error::from_raw_os_error(libc::ENOENT))?;
        let data = self.0.read(from).map_err(veil_io)?;
        self.0.write(to, &data).map_err(veil_io)?;
        self.0.set_executable(to, m.executable).map_err(veil_io)?;
        self.0.remove_file(from).map_err(veil_io)
    }
}

/// An open file that lost its path before anything was written to it (it
/// was unlinked while open): written in memory, reaching no path.
struct VecFile(Vec<u8>);

impl UpperFile for VecFile {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> std::io::Result<usize> {
        let start = usize::try_from(offset).unwrap_or(usize::MAX).min(self.0.len());
        let n = buf.len().min(self.0.len() - start);
        buf[..n].copy_from_slice(&self.0[start..start + n]);
        Ok(n)
    }
    fn write_at(&mut self, bytes: &[u8], offset: u64) -> std::io::Result<()> {
        let end = offset + bytes.len() as u64;
        if (self.0.len() as u64) < end {
            grow(&mut self.0, end)?;
        }
        self.0[offset as usize..end as usize].copy_from_slice(bytes);
        Ok(())
    }
    fn set_len(&mut self, len: u64) -> std::io::Result<()> {
        grow(&mut self.0, len)
    }
    fn len(&self) -> std::io::Result<u64> {
        Ok(self.0.len() as u64)
    }
    fn sync(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The largest file the mount holds: the largest object Veil records
/// (`VEIL_MAX_OBJECT`, 4 GiB by default).
pub fn max_file_size() -> u64 {
    veil_core::pack::max_object_size()
}

/// A mount's lower layer.
pub trait Lower: StorageBackend {
    /// The files of the tree at or below `path` that this layer does not
    /// show (a directory it cannot open stands for every file below it).
    fn unseen_under(&self, _path: &VPath) -> Vec<VPath> {
        Vec::new()
    }

    /// Does reading a file fetch it (a thin clone)? Then `open` reads it:
    /// the kernel turns any error of a later read into `EIO`, so only at
    /// `open` can the server's refusal (`EACCES`, and the file hidden from
    /// then on) be told from a server that cannot be reached (`EIO`).
    fn fetches(&self) -> bool {
        false
    }

    /// Copy the content of file `path` to `out` without holding it whole in
    /// memory, if this layer can: its length, or `None` (read it whole).
    fn copy_to(&self, _path: &VPath, _out: &mut std::fs::File) -> VResult<Option<u64>> {
        Ok(None)
    }
}

#[cfg(test)]
impl Lower for veil_core::vfs::MemoryBackend {}

/// The lower layer of a mount: a snapshot tree as this reader may see it.
///
/// A [`TreeView`] lists only what this reader can materialise, but answers
/// `metadata` (and `read`, with an error) for every entry. Here an entry
/// this reader cannot read is absent everywhere, as in a checkout.
///
/// **In a thin clone** (milestone S8) the tree is what the server gave this
/// person (their projection: hidden entries are not in it), and objects are
/// fetched when first needed:
/// * listing a folder and `stat` never fetch a file's content: sizes are in
///   the tree entries, and a file not fetched yet whose entry is not
///   labelled secret is shown (what its object really is decides when it
///   is read: a secret this reader cannot open reads as `EACCES`). A file
///   labelled secret is fetched to decide, as its object is the authority;
/// * listing a folder fetches its tree, and nothing below it (a folder not
///   fetched yet is shown without fetching it: one holding only secrets
///   this reader cannot open lists as empty); the first read of a file
///   fetches its folder's small files with it, in one request
///   ([`ReaderView::prefetch_folder`]);
/// * the server's own refusal (`Missing`) hides an entry, as everywhere; a
///   server that cannot be reached, or any other failure, is an error
///   (`EIO`), never an empty or absent file or folder.
#[derive(Debug)]
pub struct ReaderView {
    store: Arc<ObjectStore>,
    view: TreeView,
    /// The folders (by tree id) whose small files were fetched together.
    fetched_folders: Mutex<HashSet<ObjectId>>,
}

/// The paths whose file the server refused (not this person's: access
/// removed since the tree was listed), with when: absent from listings and
/// lookups for [`REFUSED_FOR`], whichever view of the tree asks (the
/// mount's lower layer is made afresh at each recording); asked again after
/// it, so access given back shows. By path, as the server decides
/// (BUG-1367): the same content elsewhere (an empty `__init__.py`) is
/// another file. One mount per process.
static REFUSED: std::sync::LazyLock<Mutex<HashMap<VPath, std::time::Instant>>> = std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));
const REFUSED_FOR: std::time::Duration = std::time::Duration::from_secs(10);

fn refused(path: &VPath) -> bool {
    let mut r = REFUSED.lock().unwrap_or_else(|p| p.into_inner());
    match r.get(path) {
        Some(at) if at.elapsed() < REFUSED_FOR => true,
        Some(_) => {
            r.remove(path);
            false
        }
        None => false,
    }
}

/// Large files known to be plain blobs (BUG-1461): decided once a process.
static PLAIN_LARGE: std::sync::LazyLock<Mutex<HashSet<ObjectId>>> = std::sync::LazyLock::new(|| Mutex::new(HashSet::new()));

/// Files up to this size are fetched with their folder (the first read of
/// one of them fetches the others in the same request).
pub const FOLDER_FILE_LIMIT: u64 = 256 << 10;

impl ReaderView {
    pub fn new(store: Arc<ObjectStore>, tree: ObjectId) -> ReaderView {
        ReaderView {
            view: TreeView::new(store.clone(), tree),
            store,
            fetched_folders: Mutex::new(HashSet::new()),
        }
    }

    /// The entry at `path`, if this reader can materialise it. A directory
    /// on the way that cannot be opened hides everything below it, and a
    /// directory holding nothing this reader can read is absent (checkout
    /// would not create it).
    fn entry(&self, path: &VPath) -> VResult<Option<TreeEntry>> {
        // What is fetched on the way is asked for at this path, wherever
        // the same content (a file, a copied folder) was met first: the
        // server decides by path (BUG-1367).
        if self.store.is_partial() {
            self.store.place_along(&self.view.root(), path);
        }
        match lookup(&self.store, &self.view.root(), path) {
            Ok(Some(e)) if path.is_root() => Ok(Some(e)),
            Ok(Some(e)) if e.kind == EntryKind::Dir => Ok(self.dir_visible(&e, path)?.then_some(e)),
            Ok(Some(e)) if self.visible_leaf(&e, path)? => Ok(Some(e)),
            Ok(_) => Ok(None),
            Err(e) if e.is_unreadable() => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Is leaf entry `e`, at `path`, shown to this reader, as checkout
    /// would write it? A conflict with a symlink side as that shown side.
    fn visible_leaf(&self, e: &TreeEntry, path: &VPath) -> VResult<bool> {
        let shown = match e.kind {
            EntryKind::Conflict => match self.store.conflict(&e.id) {
                Ok(c) if c.has_special_terms() => match veil_core::conflict::shown_side(&c) {
                    Some((_, t)) => t.entry(&e.name),
                    None => return Ok(false),
                },
                Err(err) if !(err.is_unreadable() || err.is_not_found()) => return Err(err),
                _ => return Ok(self.store.entry_readable(e)),
            },
            _ => e.clone(),
        };
        if self.store.is_partial() && refused(path) {
            return Ok(false);
        }
        match shown.kind {
            EntryKind::Dir => Ok(false),
            EntryKind::File | EntryKind::Symlink if self.store.is_partial() && !self.store.has(&shown.id) => {
                // Not fetched yet. A plain entry is shown without fetching
                // its content (`entry_shown`); a secret one is decided by its
                // object, fetched now, and a failure to fetch it is an error,
                // never "hidden".
                if shown.visibility.key_scope().is_none() {
                    return Ok(self.store.entry_shown(&shown));
                }
                match self.store.get_raw(&shown.id) {
                    Ok(_) => Ok(self.store.entry_readable(&shown)),
                    Err(err) if err.is_unreadable() => Ok(false),
                    Err(err) => Err(err),
                }
            }
            // A large plain file is not read whole to tell (BUG-1368): a
            // loose one by its first bytes; a packed one is read whole the
            // first time (BUG-1461, open), and its answer kept for the
            // process (a plain blob is plain for every reader).
            EntryKind::File if shown.size > SPILL_AT && shown.visibility.key_scope().is_none() => {
                if PLAIN_LARGE.lock().unwrap_or_else(|p| p.into_inner()).contains(&shown.id) || self.store.is_loose_blob(&shown.id) {
                    return Ok(true);
                }
                // One read decides: a plain blob is readable (and kept);
                // anything else as a checkout decides.
                match self.store.get_raw(&shown.id) {
                    Ok(raw) if veil_core::object::Object::is_blob_raw(&raw) => {
                        PLAIN_LARGE.lock().unwrap_or_else(|p| p.into_inner()).insert(shown.id);
                        Ok(true)
                    }
                    _ => Ok(self.store.entry_readable(&shown)),
                }
            }
            _ => Ok(self.store.entry_readable(&shown)),
        }
    }

    /// Does directory entry `dir` hold a file this reader can read?
    /// Depth first, stopping at the first one (usually the first entry).
    fn dir_visible(&self, dir: &TreeEntry, path: &VPath) -> VResult<bool> {
        // A folder of a thin clone not fetched yet is shown without fetching
        // it (`entry_shown`): one that turns out to hold only secrets this
        // reader cannot open lists as empty.
        if self.store.is_partial() && !self.store.has(&dir.id) {
            return Ok(self.store.entry_shown(dir));
        }
        let mut stack = vec![(dir.id, path.clone())];
        while let Some((id, at)) = stack.pop() {
            let tree = match self.store.tree(&id) {
                Ok(t) => t,
                Err(e) if e.is_unreadable() || e.is_not_found() => continue,
                Err(e) => return Err(e),
            };
            for c in tree.entries.iter().rev() {
                match c.kind {
                    EntryKind::Dir => stack.push((c.id, at.join(&c.name))),
                    _ if self.visible_leaf(c, &at.join(&c.name))? => return Ok(true),
                    _ => {}
                }
            }
        }
        Ok(false)
    }

    /// The server's own "not yours" for `e` at `path` (never an unreachable
    /// one): the file is hidden from now on, as a checkout would leave it
    /// out.
    fn note_refusal(&self, e: &TreeEntry, path: &VPath, err: &VeilError) {
        if err.is_unreadable() && self.store.is_partial() && !self.store.has(&e.id) && e.visibility.key_scope().is_none() {
            REFUSED.lock().unwrap_or_else(|p| p.into_inner()).insert(path.clone(), std::time::Instant::now());
        }
    }

    /// In a thin clone, fetch folder `dir`'s small files together, once per
    /// folder (the first read of one of them). Best effort: a failure here
    /// is the reader's to meet, at the object it reads.
    fn prefetch_folder(&self, dir: &VPath) {
        if !self.store.may_fetch() {
            return;
        }
        let Ok(Some(e)) = lookup(&self.store, &self.view.root(), dir) else { return };
        if e.kind != EntryKind::Dir || !self.fetched_folders.lock().unwrap_or_else(|p| p.into_inner()).insert(e.id) {
            return;
        }
        let Ok(t) = self.store.tree(&e.id) else { return };
        // Each at its own path, a refused one left (BUG-1460).
        let want: Vec<(VPath, ObjectId, u64)> = t
            .entries
            .iter()
            .filter(|c| matches!(c.kind, EntryKind::File | EntryKind::Symlink) && c.size <= FOLDER_FILE_LIMIT && !self.store.has(&c.id))
            .map(|c| (dir.join(&c.name), c.id, c.size))
            .collect();
        if !want.is_empty() {
            let _ = self.store.prefetch_at(&self.view.root(), &want);
        }
    }

    /// In a thin clone, have what is at `path` (BUG-1460): content already
    /// on this machine reads at every path naming it (the person holds
    /// those bytes; removal of access stops new fetches, BUG-1464); an
    /// object not held is asked for at this path and nowhere else, its
    /// folder's small files with it. A refusal hides the path (`EACCES`
    /// now, absent from then on).
    fn answer_for(&self, e: &TreeEntry, path: &VPath) -> VResult<()> {
        if !self.store.is_partial() || e.kind == EntryKind::Dir || self.store.has(&e.id) {
            return Ok(());
        }
        self.prefetch_folder(&path.parent().unwrap_or_else(VPath::root));
        match self.store.read_at(&e.id, &self.view.root(), path) {
            Ok(_) => Ok(()),
            Err(err) => {
                if err.is_unreadable() && e.visibility.key_scope().is_none() {
                    REFUSED.lock().unwrap_or_else(|p| p.into_inner()).insert(path.clone(), std::time::Instant::now());
                }
                Err(err)
            }
        }
    }
}

impl Lower for ReaderView {
    fn fetches(&self) -> bool {
        self.store.is_partial()
    }

    /// A plain file's content, streamed from its loose object (BUG-1368).
    /// In a thin clone one not fetched yet is fetched first (whole: the
    /// server sends an object at a time), then streamed from the cache.
    fn copy_to(&self, path: &VPath, out: &mut std::fs::File) -> VResult<Option<u64>> {
        let Some(e) = self.entry(path)? else { return Err(VeilError::NotFound(path.to_string())) };
        if e.kind != EntryKind::File || e.visibility.key_scope().is_some() {
            return Ok(None);
        }
        self.answer_for(&e, path)?;
        self.store.copy_loose_blob(&e.id, out)
    }

    /// Files of the tree this reader cannot read (when in doubt, the path
    /// itself: being carried is the safe side).
    fn unseen_under(&self, path: &VPath) -> Vec<VPath> {
        let top = match lookup(&self.store, &self.view.root(), path) {
            Ok(Some(e)) => e,
            Ok(None) => return Vec::new(),
            Err(_) => return vec![path.clone()],
        };
        let mut out = Vec::new();
        let mut stack = vec![(path.clone(), top)];
        while let Some((p, e)) = stack.pop() {
            match e.kind {
                EntryKind::Dir => match self.store.tree(&e.id) {
                    Ok(t) => stack.extend(t.entries.iter().map(|c| (p.join(&c.name), c.clone()))),
                    Err(_) => out.push(p),
                },
                _ if self.visible_leaf(&e, &p).unwrap_or(false) => {}
                _ => out.push(p),
            }
        }
        out.retain(|p| !p.is_root());
        out.sort();
        out
    }
}

impl StorageBackend for ReaderView {
    fn kind(&self) -> &'static str {
        "tree"
    }

    fn read(&self, path: &VPath) -> VResult<Vec<u8>> {
        match self.entry(path)? {
            Some(e) => {
                self.answer_for(&e, path)?;
                let r = self.view.read(path);
                if let Err(err) = &r {
                    self.note_refusal(&e, path, err);
                }
                r
            }
            None => Err(VeilError::NotFound(path.to_string())),
        }
    }

    fn write(&self, _: &VPath, _: &[u8]) -> VResult<()> {
        Err(VeilError::ReadOnly)
    }
    fn create_new(&self, _: &VPath, _: &[u8]) -> VResult<bool> {
        Err(VeilError::ReadOnly)
    }
    fn remove_file(&self, _: &VPath) -> VResult<()> {
        Err(VeilError::ReadOnly)
    }
    fn remove_dir_all(&self, _: &VPath) -> VResult<()> {
        Err(VeilError::ReadOnly)
    }
    fn create_dir_all(&self, _: &VPath) -> VResult<()> {
        Err(VeilError::ReadOnly)
    }
    fn set_executable(&self, _: &VPath, _: bool) -> VResult<()> {
        Err(VeilError::ReadOnly)
    }

    fn read_link(&self, path: &VPath) -> VResult<Vec<u8>> {
        match self.entry(path)? {
            Some(_) => self.view.read_link(path),
            None => Err(VeilError::NotFound(path.to_string())),
        }
    }

    fn list_dir(&self, path: &VPath) -> VResult<Vec<DirEntry>> {
        let Some(dir) = self.entry(path)? else {
            return Err(VeilError::NotFound(path.to_string()));
        };
        if dir.kind != EntryKind::Dir {
            return Err(VeilError::InvalidPath(format!("{path} is not a directory")));
        }
        // From the tree, by this view's rules ([`TreeView`]'s listing reads
        // every file to decide, which in a thin clone would fetch them).
        let mut out = Vec::new();
        for c in self.store.tree(&dir.id)?.entries.iter() {
            let kind = match c.kind {
                EntryKind::Dir if self.dir_visible(c, &path.join(&c.name))? => NodeKind::Dir,
                EntryKind::Dir => continue,
                _ if !self.visible_leaf(c, &path.join(&c.name))? => continue,
                EntryKind::Symlink => NodeKind::Symlink,
                EntryKind::Conflict => match self.store.conflict(&c.id) {
                    Ok(cf) if cf.has_special_terms() => match veil_core::conflict::shown_side(&cf) {
                        Some((_, t)) if t.entry(&c.name).kind == EntryKind::Symlink => NodeKind::Symlink,
                        _ => NodeKind::File,
                    },
                    _ => NodeKind::File,
                },
                _ => NodeKind::File,
            };
            out.push(DirEntry { name: c.name.clone(), kind });
        }
        Ok(out)
    }

    fn metadata(&self, path: &VPath) -> VResult<Option<Metadata>> {
        if self.entry(path)?.is_none() {
            return Ok(None);
        }
        self.view.metadata(path)
    }

    fn known_id(&self, path: &VPath) -> Option<ObjectId> {
        self.entry(path).ok().flatten().map(|e| e.id)
    }
}

struct Node {
    /// `None` once unlinked (or replaced by a rename) while still open.
    path: Option<VPath>,
    lookups: u64,
    open: u32,
    /// While open: the content of a file only the lower layer has, read
    /// once (a read never decrypts a file twice). Never written to.
    cache: Option<Lowered>,
    /// While open: the upper file, in place, once the upper layer has the
    /// file. Reads and writes go straight to it (BUG-561).
    file: Option<Box<dyn UpperFile>>,
    /// Written since `file` was last synced.
    dirty: bool,
}

/// Lower-layer content held for open files, in memory, across all of them
/// (BUG-1365): past it, or for a file larger than [`SPILL_AT`], the content
/// goes to an anonymous file of the mount's private directory instead.
pub const HELD: u64 = 64 << 20;
/// Files larger than this are never held in memory while open.
pub const SPILL_AT: u64 = 1 << 20;

/// The content of a file only the lower layer has, for an open node: in
/// memory, or in an anonymous file (no name: nothing of it outlives the
/// process, a crash included), read from in pieces.
enum Lowered {
    Bytes(Vec<u8>),
    Spilled { file: std::fs::File, len: u64 },
}

impl Lowered {
    fn len(&self) -> u64 {
        match self {
            Lowered::Bytes(b) => b.len() as u64,
            Lowered::Spilled { len, .. } => *len,
        }
    }

    fn held(&self) -> u64 {
        match self {
            Lowered::Bytes(b) => b.len() as u64,
            Lowered::Spilled { .. } => 0,
        }
    }

    /// At most `size` bytes from `offset`.
    fn read(&self, offset: u64, size: u32) -> std::io::Result<Vec<u8>> {
        match self {
            Lowered::Bytes(buf) => {
                let start = usize::try_from(offset).unwrap_or(usize::MAX).min(buf.len());
                let end = start.saturating_add(size as usize).min(buf.len());
                Ok(buf[start..end].to_vec())
            }
            Lowered::Spilled { file, len } => {
                let n = (size as u64).min(len.saturating_sub(offset)) as usize;
                let mut out = vec![0; n];
                let mut done = 0;
                while done < n {
                    match std::os::unix::fs::FileExt::read_at(file, &mut out[done..], offset + done as u64)? {
                        0 => break,
                        k => done += k,
                    }
                }
                out.truncate(done);
                Ok(out)
            }
        }
    }

    /// The whole content (a copy-up, a copy).
    fn bytes(&self) -> std::io::Result<Vec<u8>> {
        match self {
            Lowered::Bytes(b) => Ok(b.clone()),
            Lowered::Spilled { len, .. } => self.read(0, u32::try_from(*len).unwrap_or(u32::MAX)).and_then(|b| match b.len() as u64 == *len {
                true => Ok(b),
                false => Err(std::io::Error::from_raw_os_error(libc::EIO)),
            }),
        }
    }

    /// `data`, spilled to an anonymous file in `dir`.
    fn spill(dir: &std::path::Path, data: &[u8]) -> std::io::Result<Lowered> {
        use std::io::Write;
        let mut file = anonymous_file(dir)?;
        file.write_all(data)?;
        Ok(Lowered::Spilled { file, len: data.len() as u64 })
    }
}

/// A new file of `dir` (private) without a name, open for reading and
/// writing: nothing of it outlives its last handle, a crash included.
/// `O_TMPFILE` on Linux; where the filesystem has no such thing (NFS, some
/// FUSE ones) or elsewhere, a file created exclusively and removed at once.
fn anonymous_file(dir: &std::path::Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    #[cfg(target_os = "linux")]
    match std::fs::OpenOptions::new().read(true).write(true).mode(0o600).custom_flags(libc::O_TMPFILE).open(dir) {
        Ok(f) => return Ok(f),
        Err(e) if !matches!(e.raw_os_error(), Some(libc::EOPNOTSUPP) | Some(libc::EISDIR) | Some(libc::EINVAL) | Some(libc::ENOENT)) || !dir.is_dir() => {
            return Err(e)
        }
        Err(_) => {}
    }
    unlinked_file(dir)
}

/// [`anonymous_file`] where `O_TMPFILE` is not to be had: created
/// exclusively in `dir` (private), never through a link, then removed.
fn unlinked_file(dir: &std::path::Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let p = dir.join(format!(".spill-{}", hex::encode(veil_core::crypto::random_bytes::<8>())));
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&p)?;
    std::fs::remove_file(&p)?;
    Ok(f)
}

struct Handle {
    ino: u64,
    write: bool,
}

struct Inner {
    /// Where large open files' content goes ([`MountFs::with_spill`]).
    spill: Option<std::path::PathBuf>,
    overlay: OverlayBackend,
    /// The overlay's lower layer, as a [`Lower`].
    lower: Arc<dyn Lower>,
    /// Files of the lower layer that whiteouts hide and that the mount
    /// never showed (see the module documentation).
    unseen: BTreeSet<VPath>,
    /// Open directories: the listing each `opendir` handed out, so offsets
    /// stay put while entries are deleted (BUG-537).
    dirs: HashMap<u64, Vec<(u64, String, NodeKind)>>,
    journal: Option<Box<dyn Journal>>,
    /// Opens the upper layer's files in place.
    files: Arc<dyn UpperFiles>,
    nodes: HashMap<u64, Node>,
    by_path: HashMap<VPath, u64>,
    next_ino: u64,
    handles: HashMap<u64, Handle>,
    next_fh: u64,
    /// Modification times of paths changed since the mount started.
    times: HashMap<VPath, SystemTime>,
    /// The modification time of everything else.
    epoch: SystemTime,
    /// Bumped by every change of what the mount shows.
    generation: u64,
    /// `symlink()` creates links (repository format 5); below that it is
    /// refused, as Veil could not record them.
    links: bool,
}

/// The mounted file system (see the module documentation).
pub struct MountFs {
    inner: Mutex<Inner>,
}

impl std::fmt::Debug for MountFs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MountFs")
    }
}

/// `errno` for an engine error.
pub fn errno(e: &VeilError) -> Errno {
    match e {
        VeilError::NotFound(_) => libc::ENOENT,
        VeilError::AlreadyExists(_) => libc::EEXIST,
        VeilError::ReadOnly => libc::EROFS,
        VeilError::Io { source, .. } => source.raw_os_error().unwrap_or(match source.kind() {
            std::io::ErrorKind::NotFound => libc::ENOENT,
            std::io::ErrorKind::PermissionDenied => libc::EACCES,
            std::io::ErrorKind::StorageFull => libc::ENOSPC,
            _ => libc::EIO,
        }),
        VeilError::InvalidPath(m) if m.contains("is a directory") => libc::EISDIR,
        VeilError::InvalidPath(m) if m.contains("not a directory") || m.contains("is a file") => libc::ENOTDIR,
        VeilError::InvalidPath(_) => libc::EINVAL,
        e if e.is_unreadable() => libc::EACCES,
        _ => libc::EIO,
    }
}

fn io_errno(e: &std::io::Error) -> Errno {
    e.raw_os_error().unwrap_or(libc::EIO)
}

/// A name the mount may hold: one path component, valid UTF-8, never
/// `.veil` (Veil never records one, and `vl` must not take the mount for
/// a repository).
fn component(name: &std::ffi::OsStr) -> FsResult<&str> {
    let name = name.to_str().ok_or(libc::EINVAL)?;
    if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\0']) {
        return Err(libc::EINVAL);
    }
    if name.len() > 255 {
        return Err(libc::ENAMETOOLONG);
    }
    Ok(name)
}

fn creatable(name: &str) -> FsResult<()> {
    if is_reserved_name(name) {
        return Err(libc::EPERM);
    }
    Ok(())
}

impl Inner {
    fn path(&self, ino: u64) -> FsResult<VPath> {
        if ino == ROOT {
            return Ok(VPath::root());
        }
        self.nodes.get(&ino).and_then(|n| n.path.clone()).ok_or(libc::ENOENT)
    }

    fn ino_for(&mut self, path: &VPath) -> u64 {
        if path.is_root() {
            return ROOT;
        }
        if let Some(i) = self.by_path.get(path) {
            return *i;
        }
        let ino = self.next_ino;
        self.next_ino += 1;
        self.nodes.insert(
            ino,
            Node {
                path: Some(path.clone()),
                lookups: 0,
                open: 0,
                cache: None,
                file: None,
                dirty: false,
            },
        );
        self.by_path.insert(path.clone(), ino);
        ino
    }

    fn meta(&self, path: &VPath) -> FsResult<Option<Metadata>> {
        self.overlay.metadata(path).map_err(|e| errno(&e))
    }

    fn mtime(&self, path: &VPath) -> SystemTime {
        self.times.get(path).copied().unwrap_or(self.epoch)
    }

    fn touch(&mut self, path: &VPath) {
        self.times.insert(path.clone(), SystemTime::now());
        self.generation += 1;
    }

    fn attr(&self, ino: u64, path: &VPath) -> FsResult<Attr> {
        let m = self.meta(path)?.ok_or(libc::ENOENT)?;
        // An open upper file is written in place: the layer's size is its.
        Ok(Attr {
            ino,
            kind: m.kind,
            size: m.len,
            executable: m.executable,
            mtime: self.mtime(path),
        })
    }

    /// The attributes of an open node, which may no longer have a path.
    fn attr_of(&self, ino: u64) -> FsResult<Attr> {
        let unlinked = |size: u64| Attr {
            ino,
            kind: NodeKind::File,
            size,
            executable: false,
            mtime: SystemTime::now(),
        };
        match self.nodes.get(&ino) {
            Some(Node { path: None, file: Some(f), .. }) => Ok(unlinked(f.len().map_err(|e| io_errno(&e))?)),
            Some(Node { path: None, cache: Some(c), .. }) => Ok(unlinked(c.len())),
            _ => {
                let p = self.path(ino)?;
                self.attr(ino, &p)
            }
        }
    }

    /// The entries of directory `ino` (without `.` and `..`).
    fn listing(&mut self, ino: u64) -> FsResult<Vec<(u64, String, NodeKind)>> {
        let dir = self.path(ino)?;
        let entries = self.overlay.list_dir(&dir).map_err(|e| errno(&e))?;
        Ok(entries
            .into_iter()
            .filter(|e| !is_temp_name(&e.name) && !is_reserved_name(&e.name))
            .map(|e| {
                let p = dir.join(&e.name);
                (self.ino_for(&p), e.name, e.kind)
            })
            .collect())
    }

    fn child(&self, parent: u64, name: &std::ffi::OsStr) -> FsResult<VPath> {
        let dir = self.path(parent)?;
        let name = component(name)?;
        match self.meta(&dir)? {
            Some(m) if m.kind == NodeKind::Dir => Ok(dir.join(name)),
            Some(_) => Err(libc::ENOTDIR),
            None => Err(libc::ENOENT),
        }
    }

    /// Load the content of open node `ino` (a file only the lower layer
    /// has) into its cache.
    fn load(&mut self, ino: u64) -> FsResult<&Lowered> {
        let need = self.nodes.get(&ino).ok_or(libc::EBADF)?.cache.is_none();
        if need {
            let path = self.path(ino)?;
            // A large file straight to its spill file, never whole in
            // memory, where the lower layer can (BUG-1368).
            if let Some(dir) = self.spill.clone() {
                if self.meta(&path)?.is_some_and(|m| m.len > SPILL_AT) {
                    let mut file = anonymous_file(&dir).map_err(|e| io_errno(&e))?;
                    if let Some(len) = self.lower.copy_to(&path, &mut file).map_err(|e| errno(&e))? {
                        self.nodes.get_mut(&ino).ok_or(libc::EBADF)?.cache = Some(Lowered::Spilled { file, len });
                        return Ok(self.nodes.get(&ino).and_then(|n| n.cache.as_ref()).expect("loaded"));
                    }
                }
            }
            let data = self.overlay.read(&path).map_err(|e| errno(&e))?;
            // In memory only while small and under the bound across open
            // files (BUG-1365).
            let held: u64 = self.nodes.values().filter_map(|n| n.cache.as_ref()).map(Lowered::held).sum();
            let len = data.len() as u64;
            let content = match &self.spill {
                Some(dir) if len > SPILL_AT || held + len > HELD => Lowered::spill(dir, &data).map_err(|e| io_errno(&e))?,
                _ => Lowered::Bytes(data),
            };
            self.nodes.get_mut(&ino).ok_or(libc::EBADF)?.cache = Some(content);
        }
        Ok(self.nodes.get(&ino).and_then(|n| n.cache.as_ref()).expect("loaded"))
    }

    fn upper_has_file(&self, path: &VPath) -> bool {
        upper_kind(&**self.overlay.upper(), path) == Some(NodeKind::File)
    }

    /// Back node `ino` with its upper file, if the upper layer has one.
    /// Is it backed by a file now?
    fn open_upper(&mut self, ino: u64) -> FsResult<bool> {
        let node = self.nodes.get(&ino).ok_or(libc::EBADF)?;
        if node.file.is_some() {
            return Ok(true);
        }
        let Some(path) = node.path.clone() else { return Ok(false) };
        if !self.upper_has_file(&path) {
            return Ok(false);
        }
        let f = self.files.open(&path).map_err(|e| io_errno(&e))?;
        let n = self.nodes.get_mut(&ino).ok_or(libc::EBADF)?;
        n.file = Some(f);
        n.cache = None;
        Ok(true)
    }

    /// Node `ino`'s upper file, made writable: a file only the lower layer
    /// has is copied up first (atomically and durably), an unlinked one
    /// that was never written is written in memory.
    fn writable(&mut self, ino: u64) -> FsResult<&mut Box<dyn UpperFile>> {
        if !self.open_upper(ino)? {
            // A large lower file is spilled first (read a piece at a time),
            // then copied up from the spill file (BUG-1368).
            let unloaded = self.nodes.get(&ino).is_some_and(|n| n.path.is_some() && n.cache.is_none());
            if unloaded && self.spill.is_some() {
                self.load(ino)?;
            }
            let spill = self.spill.clone();
            let node = self.nodes.get_mut(&ino).ok_or(libc::EBADF)?;
            match node.path.clone() {
                // Unlinked while open: its content, and what is written to
                // it from now on, in an anonymous file where the mount has a
                // spill directory (never in memory: BUG-1368).
                None => match (spill, node.cache.take()) {
                    (_, Some(Lowered::Spilled { file, .. })) => node.file = Some(Box::new(DiskFile(file))),
                    (Some(dir), cache) => {
                        use std::io::Write;
                        let mut file = anonymous_file(&dir).map_err(|e| io_errno(&e))?;
                        if let Some(c) = cache {
                            file.write_all(&c.bytes().map_err(|e| io_errno(&e))?).map_err(|e| io_errno(&e))?;
                        }
                        node.file = Some(Box::new(DiskFile(file)));
                    }
                    (None, cache) => {
                        let data = match cache {
                            Some(c) => c.bytes().map_err(|e| io_errno(&e))?,
                            None => Vec::new(),
                        };
                        node.file = Some(Box::new(VecFile(data)));
                    }
                },
                Some(path) => {
                    let cache = node.cache.take();
                    let exec = self.meta(&path)?.is_some_and(|m| m.executable);
                    // A spilled file is copied up a piece at a time where
                    // the upper layer is on disk (BUG-1368).
                    let streamed = match &cache {
                        Some(Lowered::Spilled { file, .. }) => {
                            if let Some(dir) = path.parent().filter(|d| !d.is_root()) {
                                self.overlay.create_dir_all(&dir).map_err(|e| errno(&e))?;
                            }
                            self.files.put_from(&path, file).map_err(|e| io_errno(&e))?
                        }
                        _ => false,
                    };
                    if !streamed {
                        let data = match cache {
                            Some(d) => d.bytes().map_err(|e| io_errno(&e))?,
                            None => self.overlay.read(&path).map_err(|e| errno(&e))?,
                        };
                        self.overlay.write(&path, &data).map_err(|e| errno(&e))?;
                    }
                    self.overlay.set_executable(&path, exec).map_err(|e| errno(&e))?;
                    if !self.open_upper(ino)? {
                        return Err(libc::EIO);
                    }
                }
            }
        }
        Ok(self.nodes.get_mut(&ino).and_then(|n| n.file.as_mut()).expect("backed by a file"))
    }

    /// Make what was written to node `ino` durable.
    fn persist(&mut self, ino: u64) -> FsResult<()> {
        let Some(node) = self.nodes.get_mut(&ino) else { return Ok(()) };
        if !node.dirty {
            return Ok(());
        }
        if let Some(f) = node.file.as_mut() {
            f.sync().map_err(|e| io_errno(&e))?;
        }
        node.dirty = false;
        Ok(())
    }

    fn persist_under(&mut self, root: &VPath) -> FsResult<()> {
        let inos: Vec<u64> = self
            .nodes
            .iter()
            .filter(|(_, n)| n.dirty && n.path.as_ref().is_some_and(|p| p.starts_with(root)))
            .map(|(i, _)| *i)
            .collect();
        for i in inos {
            self.persist(i)?;
        }
        Ok(())
    }

    /// Would removing `path` hide something in the lower layer? (Then the
    /// overlay records a whiteout, which the journal must learn of.)
    fn lower_has(&self, path: &VPath) -> bool {
        !self.overlay.is_whited_out(path) && self.overlay.lower().metadata(path).ok().flatten().is_some()
    }

    fn journal_whiteout(&mut self, path: &VPath) -> FsResult<()> {
        if let Some(j) = self.journal.as_mut() {
            j.whiteout(path).map_err(|e| io_errno(&e))?;
        }
        Ok(())
    }

    fn remove(&mut self, path: &VPath, dir: bool) -> FsResult<()> {
        let hides = self.lower_has(path);
        if hides {
            // What the whiteout hides that the mount never showed is
            // remembered first: a crash in between carries it anyway.
            let unseen = self.lower.unseen_under(path);
            if unseen.iter().any(|u| !self.unseen.contains(u)) {
                self.unseen.extend(unseen);
                self.journal_unseen()?;
            }
            // Journal first: a crash in between resurrects nothing.
            self.journal_whiteout(path)?;
        }
        let r = if dir {
            self.overlay.remove_dir_all(path)
        } else {
            self.overlay.remove_file(path)
        };
        r.map_err(|e| errno(&e))?;
        self.touch(path);
        Ok(())
    }

    /// `path` (and everything below it) is gone: open nodes keep their
    /// content, the others are forgotten.
    fn detach(&mut self, path: &VPath) -> FsResult<()> {
        let inos: Vec<u64> = self.by_path.iter().filter(|(p, _)| p.starts_with(path)).map(|(_, i)| *i).collect();
        for ino in inos {
            let open = self.nodes.get(&ino).is_some_and(|n| n.open > 0);
            if open {
                // Keep reading what was there, wherever it came from: the
                // upper file (which keeps its content once unlinked), or
                // the lower layer's content.
                if self.open_upper(ino).unwrap_or(false) {
                    if let Some(f) = self.nodes.get_mut(&ino).and_then(|n| n.file.as_mut()) {
                        f.unlinked();
                    }
                } else if self.nodes.get(&ino).is_some_and(|n| n.cache.is_none()) && self.load(ino).is_err() {
                    if let Some(n) = self.nodes.get_mut(&ino) {
                        n.cache = Some(Lowered::Bytes(Vec::new()));
                    }
                }
            }
            if let Some(n) = self.nodes.get_mut(&ino) {
                if let Some(p) = n.path.take() {
                    self.by_path.remove(&p);
                }
            }
            if !open {
                self.nodes.remove(&ino);
            }
        }
        Ok(())
    }

    /// Put a copy of `from` at `to`, for a rename: an upper file is moved
    /// there (O(1), holes and all; an open one follows), a file only the
    /// lower layer has is copied up.
    fn copy_file(&mut self, from: &VPath, to: &VPath) -> FsResult<()> {
        let m = self.meta(from)?.ok_or(libc::ENOENT)?;
        if self.upper_has_file(from) {
            if let Some(dir) = to.parent() {
                self.overlay.create_dir_all(&dir).map_err(|e| errno(&e))?;
            }
            return self.files.rename(from, to).map_err(|e| io_errno(&e));
        }
        // A large lower file: a piece at a time, through a spill file
        // (BUG-1368).
        if let Some(dir) = self.spill.clone().filter(|_| m.len > SPILL_AT) {
            let mut file = anonymous_file(&dir).map_err(|e| io_errno(&e))?;
            if self.lower.copy_to(from, &mut file).map_err(|e| errno(&e))?.is_some() {
                if let Some(parent) = to.parent().filter(|d| !d.is_root()) {
                    self.overlay.create_dir_all(&parent).map_err(|e| errno(&e))?;
                }
                if self.files.put_from(to, &file).map_err(|e| io_errno(&e))? {
                    self.overlay.set_executable(to, m.executable).map_err(|e| errno(&e))?;
                    return Ok(());
                }
            }
        }
        let data = match self.by_path.get(from).and_then(|i| self.nodes.get(i)).and_then(|n| n.cache.as_ref()) {
            Some(b) => b.bytes().map_err(|e| io_errno(&e))?,
            None => self.overlay.read(from).map_err(|e| errno(&e))?,
        };
        self.overlay.write(to, &data).map_err(|e| errno(&e))?;
        // `write` keeps the bit of what it replaced: set it either way.
        self.overlay.set_executable(to, m.executable).map_err(|e| errno(&e))?;
        Ok(())
    }

    /// Put a copy of symlink `from` at `to` (its target as it is).
    fn copy_link(&mut self, from: &VPath, to: &VPath) -> FsResult<()> {
        let target = self.overlay.read_link(from).map_err(|e| errno(&e))?;
        self.overlay.write_link(to, &target).map_err(|e| errno(&e))
    }

    fn journal_unseen(&mut self) -> FsResult<()> {
        let all: Vec<VPath> = self.unseen.iter().cloned().collect();
        if let Some(j) = self.journal.as_mut() {
            j.unseen(&all).map_err(|e| io_errno(&e))?;
        }
        Ok(())
    }

    fn rewrite_journal(&mut self) -> FsResult<()> {
        // Unseen files no whiteout hides any more are shown again (or
        // gone): nothing to carry. Forgotten after the whiteouts are
        // rewritten, so a crash in between carries them once more.
        let all = self.overlay.whiteouts();
        if let Some(j) = self.journal.as_mut() {
            j.rewrite(&all).map_err(|e| io_errno(&e))?;
        }
        let before = self.unseen.len();
        self.unseen.retain(|u| all.iter().any(|w| u.starts_with(w)));
        if self.unseen.len() != before {
            self.journal_unseen()?;
        }
        Ok(())
    }

    /// Replace the lower layer, keeping the upper one and the whiteouts.
    fn set_lower(&mut self, lower: Arc<dyn Lower>) {
        let upper = self.overlay.upper().clone();
        let whiteouts = self.overlay.whiteouts();
        self.overlay = OverlayBackend::with_upper(lower.clone(), upper, whiteouts);
        self.lower = lower;
    }

    /// Resize node `ino` to `len` bytes (a hole when it grows), within
    /// [`max_file_size`].
    fn resize(&mut self, ino: u64, len: u64) -> FsResult<()> {
        if len > max_file_size() {
            return Err(libc::EFBIG);
        }
        let f = self.writable(ino)?;
        if f.len().map_err(|e| io_errno(&e))? != len {
            f.set_len(len).map_err(|e| io_errno(&e))?;
            if let Some(n) = self.nodes.get_mut(&ino) {
                n.dirty = true;
            }
        }
        Ok(())
    }

    /// Drop the cached lower-layer content of nodes at `paths` (it may have
    /// changed), and give the paths a new modification time.
    fn changed(&mut self, paths: &[VPath]) {
        for p in paths {
            self.touch(p);
            if let Some(ino) = self.by_path.get(p).copied() {
                if let Some(n) = self.nodes.get_mut(&ino) {
                    n.cache = None;
                }
            }
        }
    }
}

/// The upper layer's content at `path`: a file, a directory, or nothing.
fn upper_kind(upper: &dyn StorageBackend, path: &VPath) -> Option<NodeKind> {
    upper.metadata(path).ok().flatten().map(|m| m.kind)
}

/// Every directory below `dir` of `fs` (not `dir` itself), parents first.
fn walk_dirs(fs: &dyn StorageBackend, dir: &VPath) -> VResult<Vec<VPath>> {
    let mut out = Vec::new();
    let mut stack = vec![dir.clone()];
    while let Some(d) = stack.pop() {
        for e in fs.list_dir(&d)? {
            if e.kind == NodeKind::Dir {
                let p = d.join(&e.name);
                out.push(p.clone());
                stack.push(p);
            }
        }
    }
    out.sort();
    Ok(out)
}

impl MountFs {
    /// A mount over `lower` whose writes go to `upper`, hiding `whiteouts`
    /// of the lower layer. `journal` persists new whiteouts.
    pub fn new(
        lower: Arc<dyn Lower>,
        upper: Arc<dyn StorageBackend>,
        whiteouts: Vec<VPath>,
        journal: Option<Box<dyn Journal>>,
    ) -> MountFs {
        MountFs {
            inner: Mutex::new(Inner {
                spill: None,
                overlay: OverlayBackend::with_upper(lower.clone(), upper.clone(), whiteouts),
                lower,
                unseen: BTreeSet::new(),
                dirs: HashMap::new(),
                journal,
                files: Arc::new(BackendFiles(upper)),
                nodes: HashMap::new(),
                by_path: HashMap::new(),
                next_ino: ROOT + 1,
                handles: HashMap::new(),
                next_fh: 1,
                times: HashMap::new(),
                epoch: SystemTime::now(),
                generation: 0,
                links: false,
            }),
        }
    }

    /// Let `symlink()` create links (the repository records them: format
    /// 5 or later).
    pub fn with_links(self, links: bool) -> MountFs {
        self.lock().links = links;
        self
    }

    /// Open the upper layer's files with `files` (a real mount's:
    /// [`DiskFiles`], in place on disk) instead of through the upper
    /// backend.
    pub fn with_files(self, files: Arc<dyn UpperFiles>) -> MountFs {
        self.lock().files = files;
        self
    }

    /// Keep the content of large open files (and of open files past
    /// [`HELD`]) in anonymous files of `dir` (private), not in memory.
    pub fn with_spill(self, dir: std::path::PathBuf) -> MountFs {
        self.lock().spill = Some(dir);
        self
    }

    /// The files the whiteouts hide that the mount never showed, as
    /// persisted by an earlier mount process (see [`MountFs::unseen`]).
    pub fn with_unseen(self, unseen: Vec<VPath>) -> MountFs {
        self.lock().unseen.extend(unseen);
        self
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        // A panic in one request must not take the mount down with it.
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    // ---- requests ----------------------------------------------------------

    pub fn lookup(&self, parent: u64, name: &std::ffi::OsStr) -> FsResult<Attr> {
        let mut g = self.lock();
        let path = g.child(parent, name)?;
        if path.components().any(is_reserved_name) {
            return Err(libc::ENOENT);
        }
        g.meta(&path)?.ok_or(libc::ENOENT)?;
        let ino = g.ino_for(&path);
        let a = g.attr(ino, &path)?;
        if let Some(n) = g.nodes.get_mut(&ino) {
            n.lookups += 1;
        }
        Ok(a)
    }

    pub fn forget(&self, ino: u64, n: u64) {
        let mut g = self.lock();
        let gone = match g.nodes.get_mut(&ino) {
            Some(node) => {
                node.lookups = node.lookups.saturating_sub(n);
                node.lookups == 0 && node.open == 0
            }
            None => false,
        };
        if gone && ino != ROOT {
            if let Some(Node { path: Some(p), .. }) = g.nodes.remove(&ino) {
                g.by_path.remove(&p);
            }
        }
    }

    pub fn getattr(&self, ino: u64) -> FsResult<Attr> {
        self.lock().attr_of(ino)
    }

    /// The entries of directory `ino` (without `.` and `..`).
    #[cfg(test)]
    pub fn readdir(&self, ino: u64) -> FsResult<Vec<(u64, String, NodeKind)>> {
        self.lock().listing(ino)
    }

    /// Open directory `ino`: its listing is taken now, and every
    /// [`MountFs::readdir_at`] of the handle reads from it, so an offset
    /// means the same entry however many were deleted meanwhile (`rm -rf`,
    /// `remove_dir_all` delete while they read). Reading from offset 0
    /// again (`rewinddir`) takes a fresh listing.
    pub fn opendir(&self, ino: u64) -> FsResult<u64> {
        let mut g = self.lock();
        let listing = g.listing(ino)?;
        let fh = g.next_fh;
        g.next_fh += 1;
        g.dirs.insert(fh, listing);
        Ok(fh)
    }

    /// The entries of open directory `fh` from `offset` on (`.` and `..`
    /// first), each with the offset of the next one.
    pub fn readdir_at(&self, fh: u64, ino: u64, offset: u64) -> FsResult<Vec<(u64, u64, String, NodeKind)>> {
        let mut g = self.lock();
        if offset == 0 || !g.dirs.contains_key(&fh) {
            let listing = g.listing(ino)?;
            g.dirs.insert(fh, listing);
        }
        let parent = match g.path(ino)?.parent() {
            Some(p) => g.ino_for(&p),
            None => ROOT,
        };
        let entries = g.dirs.get(&fh).ok_or(libc::EBADF)?;
        let all = [(ino, ".".to_string(), NodeKind::Dir), (parent, "..".to_string(), NodeKind::Dir)]
            .into_iter()
            .chain(entries.iter().cloned());
        Ok(all
            .enumerate()
            .skip(usize::try_from(offset).unwrap_or(usize::MAX))
            .map(|(i, (child, name, kind))| (child, i as u64 + 1, name, kind))
            .collect())
    }

    pub fn releasedir(&self, fh: u64) {
        self.lock().dirs.remove(&fh);
    }

    pub fn open(&self, ino: u64, write: bool, truncate: bool) -> FsResult<u64> {
        let mut g = self.lock();
        let path = g.path(ino)?;
        match g.meta(&path)? {
            Some(m) if m.kind == NodeKind::Dir => return Err(libc::EISDIR),
            // The kernel follows links itself: an open of the link node
            // is `O_NOFOLLOW`'s.
            Some(m) if m.kind == NodeKind::Symlink => return Err(libc::ELOOP),
            Some(_) => {}
            None => return Err(libc::ENOENT),
        }
        if truncate && write {
            if g.open_upper(ino)? {
                let f = g.nodes.get_mut(&ino).and_then(|n| n.file.as_mut()).ok_or(libc::EBADF)?;
                f.set_len(0).map_err(|e| io_errno(&e))?;
                f.sync().map_err(|e| io_errno(&e))?;
            } else {
                // Durably empty (keeping a lower file's executable bit).
                g.overlay.write(&path, b"").map_err(|e| errno(&e))?;
                g.nodes.get_mut(&ino).ok_or(libc::ENOENT)?.cache = None;
            }
            g.touch(&path);
        } else if g.lower.fetches() && !g.open_upper(ino)? {
            g.load(ino)?;
        }
        g.nodes.get_mut(&ino).ok_or(libc::ENOENT)?.open += 1;
        let fh = g.next_fh;
        g.next_fh += 1;
        g.handles.insert(fh, Handle { ino, write });
        Ok(fh)
    }

    /// Create (and open) file `name` in `parent`.
    pub fn create(&self, parent: u64, name: &std::ffi::OsStr, executable: bool, exclusive: bool) -> FsResult<(Attr, u64)> {
        let mut g = self.lock();
        let path = g.child(parent, name)?;
        creatable(path.file_name())?;
        let exists = match g.meta(&path)? {
            Some(_) if exclusive => return Err(libc::EEXIST),
            Some(m) if m.kind == NodeKind::Dir => return Err(libc::EISDIR),
            // Never opened (let alone written) through a link.
            Some(m) if m.kind == NodeKind::Symlink => return Err(libc::EEXIST),
            m => m.is_some(),
        };
        // `O_CREAT` without `O_EXCL` on a file that exists opens it as it is.
        if !exists {
            g.overlay.write(&path, b"").map_err(|e| errno(&e))?;
            g.overlay.set_executable(&path, executable).map_err(|e| errno(&e))?;
            g.touch(&path);
        }
        let ino = g.ino_for(&path);
        let n = g.nodes.get_mut(&ino).expect("just made");
        n.lookups += 1;
        n.open += 1;
        let fh = g.next_fh;
        g.next_fh += 1;
        g.handles.insert(fh, Handle { ino, write: true });
        Ok((g.attr(ino, &path)?, fh))
    }

    pub fn read(&self, fh: u64, offset: u64, size: u32) -> FsResult<Vec<u8>> {
        let mut g = self.lock();
        let ino = g.handles.get(&fh).ok_or(libc::EBADF)?.ino;
        if g.open_upper(ino)? {
            let f = g.nodes.get(&ino).and_then(|n| n.file.as_ref()).ok_or(libc::EBADF)?;
            let len = f.len().map_err(|e| io_errno(&e))?;
            let n = (size as u64).min(len.saturating_sub(offset)) as usize;
            let mut out = vec![0; n];
            let mut done = 0;
            while done < n {
                match f.read_at(&mut out[done..], offset + done as u64).map_err(|e| io_errno(&e))? {
                    0 => break,
                    k => done += k,
                }
            }
            out.truncate(done);
            return Ok(out);
        }
        g.load(ino)?.read(offset, size).map_err(|e| io_errno(&e))
    }

    pub fn write(&self, fh: u64, offset: u64, data: &[u8]) -> FsResult<u32> {
        let mut g = self.lock();
        let h = g.handles.get(&fh).ok_or(libc::EBADF)?;
        if !h.write {
            return Err(libc::EBADF);
        }
        let ino = h.ino;
        let end = offset.checked_add(data.len() as u64).ok_or(libc::EFBIG)?;
        if end > max_file_size() {
            return Err(libc::EFBIG);
        }
        g.writable(ino)?.write_at(data, offset).map_err(|e| io_errno(&e))?;
        if let Some(n) = g.nodes.get_mut(&ino) {
            n.dirty = true;
        }
        if let Ok(p) = g.path(ino) {
            g.touch(&p);
        }
        u32::try_from(data.len()).map_err(|_| libc::EINVAL)
    }

    /// `close` (or `fsync`): what was written reaches the upper layer.
    pub fn flush(&self, fh: u64) -> FsResult<()> {
        let mut g = self.lock();
        let ino = g.handles.get(&fh).ok_or(libc::EBADF)?.ino;
        g.persist(ino)
    }

    pub fn release(&self, fh: u64) -> FsResult<()> {
        let mut g = self.lock();
        let Some(h) = g.handles.remove(&fh) else { return Err(libc::EBADF) };
        let r = g.persist(h.ino);
        let drop_node = match g.nodes.get_mut(&h.ino) {
            Some(n) => {
                n.open = n.open.saturating_sub(1);
                if n.open == 0 {
                    // What was written is in the upper file (synced above,
                    // or as far as the disk allowed).
                    n.file = None;
                    n.cache = None;
                    n.dirty = false;
                }
                n.open == 0 && (n.path.is_none() || n.lookups == 0)
            }
            None => false,
        };
        if drop_node {
            if let Some(Node { path: Some(p), .. }) = g.nodes.remove(&h.ino) {
                g.by_path.remove(&p);
            }
        }
        r
    }

    /// `truncate`, `chmod` and `utimes`. Only the executable bit of a mode
    /// is kept (as Veil records it); owners are ignored.
    pub fn setattr(&self, ino: u64, size: Option<u64>, mode: Option<u32>, mtime: Option<SystemTime>) -> FsResult<Attr> {
        let mut g = self.lock();
        let path = g.path(ino)?;
        let m = g.meta(&path)?.ok_or(libc::ENOENT)?;
        if let Some(size) = size {
            if m.kind == NodeKind::Dir {
                return Err(libc::EISDIR);
            }
            if m.kind == NodeKind::Symlink {
                return Err(libc::EINVAL);
            }
            if size > max_file_size() {
                return Err(libc::EFBIG);
            }
            let open = g.nodes.get(&ino).is_some_and(|n| n.open > 0);
            // Through a path (`truncate(1)`), or by a handle: either way
            // the upper layer has it now, durably.
            let r = g.resize(ino, size).and_then(|_| g.persist(ino));
            if !open {
                if let Some(n) = g.nodes.get_mut(&ino) {
                    n.file = None;
                    n.cache = None;
                    n.dirty = false;
                }
            }
            r?;
            g.touch(&path);
        }
        if let Some(mode) = mode {
            let exec = mode & 0o111 != 0;
            if m.kind == NodeKind::File && exec != m.executable {
                g.persist(ino)?;
                g.overlay.set_executable(&path, exec).map_err(|e| errno(&e))?;
                g.touch(&path);
            }
        }
        if let Some(t) = mtime {
            g.times.insert(path.clone(), t);
        }
        g.attr(ino, &path)
    }

    pub fn mkdir(&self, parent: u64, name: &std::ffi::OsStr) -> FsResult<Attr> {
        let mut g = self.lock();
        let path = g.child(parent, name)?;
        creatable(path.file_name())?;
        if g.meta(&path)?.is_some() {
            return Err(libc::EEXIST);
        }
        g.overlay.create_dir_all(&path).map_err(|e| errno(&e))?;
        g.touch(&path);
        let ino = g.ino_for(&path);
        if let Some(n) = g.nodes.get_mut(&ino) {
            n.lookups += 1;
        }
        g.attr(ino, &path)
    }

    /// The target of symlink `ino`, as it is (the kernel resolves it, in
    /// the caller's namespace; the mount itself never follows a link).
    pub fn readlink(&self, ino: u64) -> FsResult<Vec<u8>> {
        let g = self.lock();
        let path = g.path(ino)?;
        match g.meta(&path)? {
            Some(m) if m.kind == NodeKind::Symlink => g.overlay.read_link(&path).map_err(|e| errno(&e)),
            Some(_) => Err(libc::EINVAL),
            None => Err(libc::ENOENT),
        }
    }

    /// Create symlink `name` in `parent` pointing at `target` (written as
    /// it is, never resolved). Refused (`EPERM`) unless the repository
    /// records links (format 5).
    pub fn symlink(&self, parent: u64, name: &std::ffi::OsStr, target: &[u8]) -> FsResult<Attr> {
        let mut g = self.lock();
        if !g.links {
            return Err(libc::EPERM);
        }
        let path = g.child(parent, name)?;
        creatable(path.file_name())?;
        if target.len() > veil_core::vfs::MAX_LINK_TARGET {
            return Err(libc::ENAMETOOLONG);
        }
        if veil_core::vfs::check_link_target(target).is_err() {
            return Err(libc::EINVAL);
        }
        if g.meta(&path)?.is_some() {
            return Err(libc::EEXIST);
        }
        g.overlay.write_link(&path, target).map_err(|e| errno(&e))?;
        g.touch(&path);
        let ino = g.ino_for(&path);
        if let Some(n) = g.nodes.get_mut(&ino) {
            n.lookups += 1;
        }
        g.attr(ino, &path)
    }

    pub fn unlink(&self, parent: u64, name: &std::ffi::OsStr) -> FsResult<()> {
        let mut g = self.lock();
        let path = g.child(parent, name)?;
        match g.meta(&path)? {
            Some(m) if m.kind == NodeKind::Dir => return Err(libc::EISDIR),
            Some(_) => {}
            None => return Err(libc::ENOENT),
        }
        g.detach(&path)?;
        g.remove(&path, false)
    }

    pub fn rmdir(&self, parent: u64, name: &std::ffi::OsStr) -> FsResult<()> {
        let mut g = self.lock();
        let path = g.child(parent, name)?;
        match g.meta(&path)? {
            Some(m) if m.kind != NodeKind::Dir => return Err(libc::ENOTDIR),
            Some(_) => {}
            None => return Err(libc::ENOENT),
        }
        let entries = g.overlay.list_dir(&path).map_err(|e| errno(&e))?;
        if entries.iter().any(|e| !is_temp_name(&e.name)) {
            return Err(libc::ENOTEMPTY);
        }
        g.detach(&path)?;
        g.remove(&path, true)
    }

    /// Rename `name` in `parent` to `newname` in `newparent`. A directory
    /// is copied (into the upper layer) and then removed: renaming a large
    /// tree costs a copy of it. Nothing is removed before its copy exists.
    pub fn rename(
        &self,
        parent: u64,
        name: &std::ffi::OsStr,
        newparent: u64,
        newname: &std::ffi::OsStr,
        noreplace: bool,
    ) -> FsResult<()> {
        let mut g = self.lock();
        let from = g.child(parent, name)?;
        let to = g.child(newparent, newname)?;
        creatable(to.file_name())?;
        let src = g.meta(&from)?.ok_or(libc::ENOENT)?;
        if from == to {
            return Ok(());
        }
        if to.starts_with(&from) {
            return Err(libc::EINVAL);
        }
        if let Some(dst) = g.meta(&to)? {
            if noreplace {
                return Err(libc::EEXIST);
            }
            match (src.kind, dst.kind) {
                (NodeKind::File | NodeKind::Symlink, NodeKind::Dir) => return Err(libc::EISDIR),
                (NodeKind::Dir, NodeKind::File | NodeKind::Symlink) => return Err(libc::ENOTDIR),
                (NodeKind::Dir, NodeKind::Dir) => {
                    let entries = g.overlay.list_dir(&to).map_err(|e| errno(&e))?;
                    if !entries.is_empty() {
                        return Err(libc::ENOTEMPTY);
                    }
                }
                (NodeKind::File | NodeKind::Symlink, NodeKind::File | NodeKind::Symlink) => {}
            }
            g.detach(&to)?;
            g.remove(&to, dst.kind == NodeKind::Dir)?;
        }
        g.persist_under(&from)?;
        match src.kind {
            NodeKind::File => g.copy_file(&from, &to)?,
            NodeKind::Symlink => g.copy_link(&from, &to)?,
            NodeKind::Dir => {
                g.overlay.create_dir_all(&to).map_err(|e| errno(&e))?;
                let rel = |p: &VPath| VPath::new(&p.as_str()[from.as_str().len()..]).expect("below");
                for d in walk_dirs(&g.overlay, &from).map_err(|e| errno(&e))? {
                    let target = VPath::new(&format!("{}/{}", to.as_str(), rel(&d).as_str())).map_err(|e| errno(&e))?;
                    g.overlay.create_dir_all(&target).map_err(|e| errno(&e))?;
                }
                for (f, kind) in walk_leaves(&g.overlay, &from, &|_| false).map_err(|e| errno(&e))? {
                    let target = VPath::new(&format!("{}/{}", to.as_str(), rel(&f).as_str())).map_err(|e| errno(&e))?;
                    match kind {
                        NodeKind::Symlink => g.copy_link(&f, &target)?,
                        _ => g.copy_file(&f, &target)?,
                    }
                    let t = g.mtime(&f);
                    g.times.insert(target, t);
                }
            }
        }
        let t = g.mtime(&from);
        g.remove(&from, src.kind == NodeKind::Dir)?;
        g.times.insert(to.clone(), t);
        // Open files and known inodes follow the rename.
        let moved: Vec<(VPath, u64)> = g.by_path.iter().filter(|(p, _)| p.starts_with(&from)).map(|(p, i)| (p.clone(), *i)).collect();
        for (p, ino) in moved {
            let rest = &p.as_str()[from.as_str().len()..];
            let np = VPath::new(&format!("{}{rest}", to.as_str())).map_err(|e| errno(&e))?;
            g.by_path.remove(&p);
            g.by_path.insert(np.clone(), ino);
            if let Some(n) = g.nodes.get_mut(&ino) {
                if let Some(f) = n.file.as_mut() {
                    f.moved(&np);
                }
                n.path = Some(np);
            }
        }
        Ok(())
    }

    // ---- recording -----------------------------------------------------------

    /// A counter that moves whenever what the mount shows changes.
    pub fn generation(&self) -> u64 {
        self.lock().generation
    }

    /// Write every changed open file to the upper layer.
    pub fn persist_all(&self) -> FsResult<()> {
        self.lock().persist_under(&VPath::root())
    }

    /// Run `f` on the merged view (the builder records it), with every
    /// request waiting meanwhile.
    pub fn with_view<R>(&self, f: impl FnOnce(&OverlayBackend) -> R) -> R {
        let g = self.lock();
        f(&g.overlay)
    }

    /// Does the overlay hold nothing (no file or directory written, nothing
    /// deleted)?
    pub fn is_clean(&self) -> bool {
        let g = self.lock();
        g.overlay.whiteouts().is_empty() && g.overlay.upper().list_dir(&VPath::root()).is_ok_and(|l| l.is_empty())
    }

    /// The overlay's footprint: every path the upper layer holds (files and
    /// directories) and every whiteout.
    pub fn region(&self) -> (Vec<VPath>, Vec<VPath>) {
        let g = self.lock();
        let upper = g.overlay.upper().clone();
        let mut paths: Vec<VPath> = walk_leaves(&*upper, &VPath::root(), &|_| false).unwrap_or_default().into_iter().map(|(p, _)| p).collect();
        paths.extend(walk_dirs(&*upper, &VPath::root()).unwrap_or_default());
        paths.sort();
        (paths, g.overlay.whiteouts())
    }

    /// The files of the upper layer (what the mount holds that the lower
    /// layer does not).
    pub fn upper_files(&self) -> Vec<VPath> {
        let g = self.lock();
        walk_leaves(&**g.overlay.upper(), &VPath::root(), &|_| false).unwrap_or_default().into_iter().map(|(p, _)| p).collect()
    }

    /// The same tree as the lower layer, read with keys that may have
    /// changed since (a grant, an embargo release): what became readable
    /// shows from now on, except where a whiteout hides it (it stays
    /// [unseen](MountFs::unseen)). The overlay is unchanged.
    pub fn refresh_lower(&self, lower: Arc<dyn Lower>) {
        let mut g = self.lock();
        g.set_lower(lower);
        for n in g.nodes.values_mut() {
            if n.open == 0 {
                n.cache = None;
            }
        }
    }

    /// Files of the lower layer that whiteouts hide and that the mount never
    /// showed: a directory deleted in the mount held them, unreadable to
    /// this reader then. A recording carries them (it never records them
    /// as deleted), whatever this reader can read now.
    pub fn unseen(&self) -> Vec<VPath> {
        self.lock().unseen.iter().cloned().collect()
    }

    /// Put the overlay over `lower` (the workspace moved under the mount):
    /// `changed` are the paths that differ between the old and the new
    /// lower layer, `drop` the parts of the overlay to give up first (they
    /// conflict with the move; the caller saved them). Everything else the
    /// overlay holds stays as it is.
    pub fn switch_lower(&self, lower: Arc<dyn Lower>, changed: &[VPath], drop: &[VPath]) -> FsResult<()> {
        let mut g = self.lock();
        g.persist_under(&VPath::root())?;
        let upper = g.overlay.upper().clone();
        for p in drop {
            match upper_kind(&*upper, p) {
                Some(NodeKind::Dir) => upper.remove_dir_all(p).map_err(|e| errno(&e))?,
                Some(NodeKind::File | NodeKind::Symlink) => upper.remove_file(p).map_err(|e| errno(&e))?,
                None => {}
            }
            g.overlay.remove_whiteout(p);
            for w in g.overlay.whiteouts() {
                if w.starts_with(p) {
                    g.overlay.remove_whiteout(&w);
                }
            }
            // The paths stay (now from the new lower layer): the kernel
            // keeps its inodes, only cached content (and the dropped upper
            // file an open node had: what was written to it is in the
            // saved change) goes.
            for n in g.nodes.values_mut() {
                if n.path.as_ref().is_some_and(|q| q.starts_with(p)) {
                    n.cache = None;
                    n.file = None;
                    n.dirty = false;
                }
            }
        }
        g.set_lower(lower);
        g.rewrite_journal()?;
        let mut all: Vec<VPath> = changed.to_vec();
        all.extend(drop.iter().cloned());
        g.changed(&all);
        Ok(())
    }

    /// After the overlay was recorded as `lower`'s tree: put it over
    /// `lower`, keeping only what still differs from it (files the
    /// recording left out: isolated, ignored, quarantined or held-back
    /// ones; deletions it did not record). What the mount shows does not
    /// change.
    #[cfg(test)]
    pub fn reconcile(&self, lower: Arc<dyn Lower>) -> FsResult<()> {
        self.lock().reconcile(lower)
    }

    /// Record: run `f` on the merged view, and put the overlay over the
    /// lower layer it returns (reconciling it: only what still differs from the new tree stays), with every request
    /// waiting meanwhile: a file deleted (or written) between the two would
    /// otherwise come back (or be dropped) as if recorded.
    pub fn record_with<R>(
        &self,
        f: impl FnOnce(&OverlayBackend) -> anyhow::Result<(R, Option<Arc<dyn Lower>>)>,
    ) -> anyhow::Result<R> {
        let mut g = self.lock();
        let (r, lower) = f(&g.overlay)?;
        if let Some(lower) = lower {
            g.reconcile(lower).map_err(|e| anyhow::anyhow!(std::io::Error::from_raw_os_error(e)))?;
        }
        Ok(r)
    }
}

impl Inner {
    fn reconcile(&mut self, lower: Arc<dyn Lower>) -> FsResult<()> {
        let g = self;
        g.persist_under(&VPath::root())?;
        let upper = g.overlay.upper().clone();
        let e = |e: VeilError| errno(&e);
        // Whiteouts: needed only where the new lower layer would show
        // something the overlay does not.
        let mut kept: BTreeSet<VPath> = BTreeSet::new();
        for w in g.overlay.whiteouts() {
            let needed = match lower.metadata(&w).map_err(e)? {
                None => false,
                Some(m) if m.kind == NodeKind::File => upper_kind(&*upper, &w) != Some(NodeKind::File),
                Some(m) if m.kind == NodeKind::Symlink => {
                    upper_kind(&*upper, &w) != Some(NodeKind::Symlink) || upper.read_link(&w).ok() != lower.read_link(&w).ok()
                }
                Some(_) => {
                    upper_kind(&*upper, &w) != Some(NodeKind::Dir)
                        || walk_leaves(&*lower, &w, &|_| false)
                            .map_err(e)?
                            .iter()
                            .any(|(f, k)| upper_kind(&*upper, f) != Some(*k))
                        || walk_dirs(&*lower, &w)
                            .map_err(e)?
                            .iter()
                            .any(|d| upper_kind(&*upper, d) != Some(NodeKind::Dir))
                }
            };
            if needed {
                kept.insert(w);
            }
        }
        let hidden = |p: &VPath| kept.contains(p) || p.ancestors().iter().any(|a| kept.contains(a));
        // Upper files open in place stay while they are open: what is
        // written to them must keep reaching the upper layer.
        let open: BTreeSet<VPath> = g.nodes.values().filter(|n| n.file.is_some()).filter_map(|n| n.path.clone()).collect();
        // Upper files identical to the new lower layer go.
        for f in walk_files(&*upper, &VPath::root(), &|_| false).map_err(e)? {
            if hidden(&f) || open.contains(&f) {
                continue;
            }
            let (Some(um), Some(lm)) = (upper.metadata(&f).map_err(e)?, lower.metadata(&f).map_err(e)?) else {
                continue;
            };
            if lm.kind != NodeKind::File || um.executable != lm.executable || um.len != lm.len {
                continue;
            }
            if upper.read(&f).map_err(e)? == lower.read(&f).map_err(e)? {
                upper.remove_file(&f).map_err(e)?;
            }
        }
        // Upper links identical to the new lower layer's go as well.
        for (l, kind) in walk_leaves(&*upper, &VPath::root(), &|_| false).map_err(e)? {
            if kind != NodeKind::Symlink || hidden(&l) {
                continue;
            }
            if lower.metadata(&l).map_err(e)?.is_some_and(|m| m.kind == NodeKind::Symlink) && upper.read_link(&l).ok() == lower.read_link(&l).ok() {
                upper.remove_file(&l).map_err(e)?;
            }
        }
        // Empty upper directories the lower layer has anyway go too, so
        // the builder's reuse hints work for them again.
        let mut dirs = walk_dirs(&*upper, &VPath::root()).map_err(e)?;
        dirs.reverse();
        for d in dirs {
            if hidden(&d) || !upper.list_dir(&d).map_err(e)?.is_empty() {
                continue;
            }
            if lower.metadata(&d).map_err(e)?.is_some_and(|m| m.kind == NodeKind::Dir) {
                upper.remove_dir_all(&d).map_err(e)?;
            }
        }
        g.overlay = OverlayBackend::with_upper(lower.clone(), upper, kept);
        g.lower = lower;
        g.rewrite_journal()?;
        // Cached content of closed files may be stale.
        for n in g.nodes.values_mut() {
            if n.open == 0 {
                n.cache = None;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use veil_core::vfs::MemoryBackend;

    use super::*;

    fn p(s: &str) -> VPath {
        VPath::new(s).unwrap()
    }

    fn os(s: &str) -> &OsStr {
        OsStr::new(s)
    }

    struct Mem {
        fs: MountFs,
        lower: Arc<MemoryBackend>,
        upper: Arc<MemoryBackend>,
        journal: Arc<Mutex<Vec<String>>>,
    }

    struct VecJournal(Arc<Mutex<Vec<String>>>);
    impl Journal for VecJournal {
        fn whiteout(&mut self, path: &VPath) -> std::io::Result<()> {
            self.0.lock().unwrap().push(format!("+{path}"));
            Ok(())
        }
        fn rewrite(&mut self, all: &[VPath]) -> std::io::Result<()> {
            let mut j = self.0.lock().unwrap();
            j.clear();
            j.extend(all.iter().map(|p| format!("={p}")));
            Ok(())
        }
        fn unseen(&mut self, all: &[VPath]) -> std::io::Result<()> {
            let list: Vec<String> = all.iter().map(|p| p.to_string()).collect();
            self.0.lock().unwrap().push(format!("unseen {}", list.join(",")));
            Ok(())
        }
    }

    /// A lower layer that does not show `hidden` (files this reader cannot
    /// read), as a [`ReaderView`] does.
    #[derive(Debug)]
    struct Hiding {
        inner: MemoryBackend,
        hidden: Vec<VPath>,
    }

    impl Hiding {
        fn shows(&self, path: &VPath) -> bool {
            !self.hidden.iter().any(|h| path.starts_with(h))
                && (self.inner.metadata(path).ok().flatten().is_some_and(|m| m.kind == NodeKind::File)
                    || walk_files(&self.inner, path, &|_| false).is_ok_and(|f| f.iter().any(|f| self.shows(f))))
        }
    }

    impl StorageBackend for Hiding {
        fn kind(&self) -> &'static str {
            "hiding"
        }
        fn read(&self, path: &VPath) -> VResult<Vec<u8>> {
            if !self.shows(path) {
                return Err(VeilError::NotFound(path.to_string()));
            }
            self.inner.read(path)
        }
        fn write(&self, _: &VPath, _: &[u8]) -> VResult<()> {
            Err(VeilError::ReadOnly)
        }
        fn create_new(&self, _: &VPath, _: &[u8]) -> VResult<bool> {
            Err(VeilError::ReadOnly)
        }
        fn remove_file(&self, _: &VPath) -> VResult<()> {
            Err(VeilError::ReadOnly)
        }
        fn remove_dir_all(&self, _: &VPath) -> VResult<()> {
            Err(VeilError::ReadOnly)
        }
        fn create_dir_all(&self, _: &VPath) -> VResult<()> {
            Err(VeilError::ReadOnly)
        }
        fn set_executable(&self, _: &VPath, _: bool) -> VResult<()> {
            Err(VeilError::ReadOnly)
        }
        fn list_dir(&self, path: &VPath) -> VResult<Vec<DirEntry>> {
            Ok(self.inner.list_dir(path)?.into_iter().filter(|e| self.shows(&path.join(&e.name))).collect())
        }
        fn metadata(&self, path: &VPath) -> VResult<Option<Metadata>> {
            if !path.is_root() && !self.shows(path) {
                return Ok(None);
            }
            self.inner.metadata(path)
        }
    }

    impl Lower for Hiding {
        fn unseen_under(&self, path: &VPath) -> Vec<VPath> {
            self.hidden.iter().filter(|h| h.starts_with(path)).cloned().collect()
        }
    }

    fn mem(files: &[(&str, &[u8])]) -> Mem {
        let lower = Arc::new(MemoryBackend::from_files(files.iter().copied()).unwrap());
        let upper = Arc::new(MemoryBackend::new());
        let journal = Arc::new(Mutex::new(Vec::new()));
        let fs = MountFs::new(lower.clone(), upper.clone(), Vec::new(), Some(Box::new(VecJournal(journal.clone()))));
        Mem { fs, lower, upper, journal }
    }

    impl Mem {
        fn ino(&self, path: &str) -> FsResult<u64> {
            let mut ino = ROOT;
            for c in p(path).components() {
                ino = self.fs.lookup(ino, os(c))?.ino;
            }
            Ok(ino)
        }
        fn cat(&self, path: &str) -> FsResult<Vec<u8>> {
            let ino = self.ino(path)?;
            let fh = self.fs.open(ino, false, false)?;
            let mut out = Vec::new();
            loop {
                let chunk = self.fs.read(fh, out.len() as u64, 3)?;
                if chunk.is_empty() {
                    break;
                }
                out.extend(chunk);
            }
            self.fs.release(fh)?;
            Ok(out)
        }
        fn put(&self, path: &str, data: &[u8]) -> FsResult<()> {
            let vp = p(path);
            let parent = self.ino(vp.parent().unwrap().as_str())?;
            let (_, fh) = self.fs.create(parent, os(vp.file_name()), false, false)?;
            self.fs.write(fh, 0, data)?;
            self.fs.flush(fh)?;
            self.fs.release(fh)
        }
        fn names(&self, dir: &str) -> Vec<String> {
            self.fs.readdir(self.ino(dir).unwrap()).unwrap().into_iter().map(|e| e.1).collect()
        }
    }

    #[test]
    fn reads_come_from_the_lower_layer_in_chunks() {
        let m = mem(&[("a/x.txt", b"hello world"), ("b", b"2")]);
        assert_eq!(m.cat("a/x.txt").unwrap(), b"hello world");
        assert_eq!(m.names(""), ["a", "b"]);
        let a = m.fs.getattr(m.ino("a/x.txt").unwrap()).unwrap();
        assert_eq!((a.kind, a.size), (NodeKind::File, 11));
        assert_eq!(m.fs.lookup(ROOT, os("nope")), Err(libc::ENOENT));
        assert_eq!(m.fs.open(m.ino("a").unwrap(), false, false), Err(libc::EISDIR));
        assert!(m.upper.files().is_empty(), "reading copies nothing up");
    }

    /// BUG-1365: a large open file's content is in an anonymous file, not
    /// in memory; it reads in pieces, copies up on a write, keeps its
    /// content when unlinked while open, and the open files held in memory
    /// stay under [`HELD`].
    #[test]
    fn large_open_files_are_spilled_and_behave_as_held_ones() {
        let big: Vec<u8> = (0..(SPILL_AT as usize + 4097)).map(|i| (i % 251) as u8).collect();
        let small = vec![7u8; 600 << 10];
        let files: Vec<(String, Vec<u8>)> = [("big.bin".to_string(), big.clone()), ("big2.bin".to_string(), big.clone())]
            .into_iter()
            .chain((0..120).map(|i| (format!("s/{i}.bin"), small.clone())))
            .collect();
        let refs: Vec<(&str, &[u8])> = files.iter().map(|(a, b)| (a.as_str(), b.as_slice())).collect();
        let spill = tempfile::tempdir().unwrap();
        let mut m = mem(&refs);
        m.fs = std::mem::replace(&mut m.fs, MountFs::new(m.lower.clone(), m.upper.clone(), Vec::new(), None)).with_spill(spill.path().to_path_buf());
        let held = |m: &Mem| -> u64 { m.fs.lock().nodes.values().filter_map(|n| n.cache.as_ref()).map(Lowered::held).sum() };
        // Read in pieces, spilled.
        let ino = m.ino("big.bin").unwrap();
        let fh = m.fs.open(ino, false, false).unwrap();
        assert_eq!(m.fs.read(fh, 5, 10).unwrap(), &big[5..15]);
        assert!(matches!(m.fs.lock().nodes[&ino].cache, Some(Lowered::Spilled { .. })));
        assert_eq!(held(&m), 0);
        assert_eq!(m.fs.read(fh, big.len() as u64 - 3, 10).unwrap(), &big[big.len() - 3..]);
        assert!(std::fs::read_dir(spill.path()).unwrap().next().is_none(), "a spilled file has no name");
        // 120 open small files: memory stays under the bound.
        let fhs: Vec<u64> = (0..120)
            .map(|i| {
                let f = m.fs.open(m.ino(&format!("s/{i}.bin")).unwrap(), false, false).unwrap();
                assert_eq!(m.fs.read(f, 0, 4).unwrap(), [7, 7, 7, 7]);
                f
            })
            .collect();
        assert!(held(&m) <= HELD, "{} bytes held", held(&m));
        // Written through a handle open on the spilled content: copied up whole.
        let w = m.fs.open(ino, true, false).unwrap();
        m.fs.write(w, 0, b"XY").unwrap();
        m.fs.release(w).unwrap();
        let mut want = big.clone();
        want[..2].copy_from_slice(b"XY");
        assert_eq!(m.upper.read(&p("big.bin")).unwrap(), want);
        // Unlinked while open, held or spilled: the open handle still
        // reads it, and writes to it reach no path.
        m.fs.unlink(m.ino("s").unwrap(), os("0.bin")).unwrap();
        assert_eq!(m.fs.read(fhs[0], 0, 3).unwrap(), [7, 7, 7]);
        let b2 = m.fs.open(m.ino("big2.bin").unwrap(), true, false).unwrap();
        assert_eq!(m.fs.read(b2, 1, 2).unwrap(), &big[1..3]);
        m.fs.unlink(ROOT, os("big2.bin")).unwrap();
        assert_eq!(m.fs.read(b2, big.len() as u64 - 2, 9).unwrap(), &big[big.len() - 2..]);
        m.fs.write(b2, 0, b"Q").unwrap();
        assert_eq!(m.fs.read(b2, 0, 2).unwrap(), [b'Q', big[1]]);
        m.fs.release(b2).unwrap();
        assert!(m.upper.read(&p("big2.bin")).is_err() && m.lower.read(&p("big2.bin")).unwrap() == big);
        for f in fhs {
            m.fs.release(f).unwrap();
        }
        m.fs.release(fh).unwrap();
    }

    /// The spill files' fallback (a filesystem without `O_TMPFILE`): a file
    /// that reads and writes, and leaves no name behind.
    #[test]
    fn a_spill_file_without_o_tmpfile_leaves_no_name() {
        use std::os::unix::fs::FileExt;
        let dir = tempfile::tempdir().unwrap();
        for f in [unlinked_file(dir.path()).unwrap(), anonymous_file(dir.path()).unwrap()] {
            f.write_all_at(b"spilled", 0).unwrap();
            let mut b = [0u8; 7];
            f.read_exact_at(&mut b, 0).unwrap();
            assert_eq!(&b, b"spilled");
            assert!(std::fs::read_dir(dir.path()).unwrap().next().is_none(), "a spill file left a name");
        }
        assert!(anonymous_file(&dir.path().join("missing")).is_err());
    }

    #[test]
    fn writes_go_to_the_upper_layer_only() {
        let m = mem(&[("a/x.txt", b"hello world")]);
        let ino = m.ino("a/x.txt").unwrap();
        let fh = m.fs.open(ino, true, false).unwrap();
        m.fs.write(fh, 6, b"there").unwrap();
        // Copied up on the first write, then written in place (BUG-561).
        assert_eq!(m.fs.getattr(ino).unwrap().size, 11);
        assert_eq!(m.upper.read(&p("a/x.txt")).unwrap(), b"hello there");
        m.fs.write(fh, 11, b"!!").unwrap();
        m.fs.flush(fh).unwrap();
        m.fs.release(fh).unwrap();
        assert_eq!(m.upper.read(&p("a/x.txt")).unwrap(), b"hello there!!");
        assert_eq!(m.lower.read(&p("a/x.txt")).unwrap(), b"hello world", "lower untouched");
        assert_eq!(m.cat("a/x.txt").unwrap(), b"hello there!!");
        // O_TRUNC
        let fh = m.fs.open(ino, true, true).unwrap();
        m.fs.write(fh, 0, b"new").unwrap();
        m.fs.release(fh).unwrap();
        assert_eq!(m.cat("a/x.txt").unwrap(), b"new");
        // A handle opened for reading cannot write.
        let fh = m.fs.open(ino, false, false).unwrap();
        assert_eq!(m.fs.write(fh, 0, b"x"), Err(libc::EBADF));
        m.fs.release(fh).unwrap();
    }

    #[test]
    fn create_mkdir_and_reserved_names() {
        let m = mem(&[("a/x.txt", b"1")]);
        m.put("a/new.txt", b"fresh").unwrap();
        assert_eq!(m.cat("a/new.txt").unwrap(), b"fresh");
        assert_eq!(m.fs.create(m.ino("a").unwrap(), os("new.txt"), false, true).err(), Some(libc::EEXIST));
        let d = m.fs.mkdir(ROOT, os("src")).unwrap();
        assert_eq!(d.kind, NodeKind::Dir);
        assert_eq!(m.fs.mkdir(ROOT, os("src")).err(), Some(libc::EEXIST));
        m.put("src/lib.rs", b"fn f() {}").unwrap();
        assert_eq!(m.names(""), ["a", "src"]);
        assert_eq!(m.fs.mkdir(ROOT, os(".veil")).err(), Some(libc::EPERM));
        assert_eq!(m.fs.create(ROOT, os(".VEIL"), false, false).err(), Some(libc::EPERM));
        assert_eq!(m.fs.lookup(ROOT, os(".veil")).err(), Some(libc::ENOENT));
        // A file in the way of a directory.
        assert_eq!(m.fs.mkdir(m.ino("a/x.txt").unwrap(), os("sub")).err(), Some(libc::ENOTDIR));
    }

    #[test]
    fn delete_records_a_journalled_whiteout() {
        let m = mem(&[("a/x.txt", b"1"), ("a/y.txt", b"2"), ("keep", b"k")]);
        let a = m.ino("a").unwrap();
        m.fs.unlink(a, os("x.txt")).unwrap();
        assert_eq!(m.fs.lookup(a, os("x.txt")).err(), Some(libc::ENOENT));
        assert_eq!(m.journal.lock().unwrap().as_slice(), ["+a/x.txt"]);
        assert_eq!(m.fs.rmdir(ROOT, os("a")).err(), Some(libc::ENOTEMPTY));
        assert_eq!(m.fs.unlink(ROOT, os("a")).err(), Some(libc::EISDIR));
        m.fs.unlink(a, os("y.txt")).unwrap();
        m.fs.rmdir(ROOT, os("a")).unwrap();
        assert_eq!(m.names(""), ["keep"]);
        // A file only the upper layer had needs no whiteout.
        m.put("tmp", b"t").unwrap();
        let before = m.journal.lock().unwrap().len();
        m.fs.unlink(ROOT, os("tmp")).unwrap();
        assert_eq!(m.journal.lock().unwrap().len(), before);
        assert_eq!(m.names(""), ["keep"]);
    }

    #[test]
    fn unlinked_open_files_stay_readable() {
        let m = mem(&[("f", b"content")]);
        let ino = m.ino("f").unwrap();
        let fh = m.fs.open(ino, false, false).unwrap();
        m.fs.unlink(ROOT, os("f")).unwrap();
        assert_eq!(m.fs.read(fh, 0, 100).unwrap(), b"content");
        m.fs.release(fh).unwrap();
        assert_eq!(m.fs.getattr(ino).err(), Some(libc::ENOENT));
    }

    #[test]
    fn rename_files_and_directories() {
        let m = mem(&[("d/a", b"A"), ("d/sub/b", b"B"), ("t", b"T"), ("other", b"O")]);
        m.fs.setattr(m.ino("d/sub/b").unwrap(), None, Some(0o755), None).unwrap();
        // File over file.
        m.fs.rename(ROOT, os("t"), ROOT, os("other"), false).unwrap();
        assert_eq!(m.cat("other").unwrap(), b"T");
        assert_eq!(m.fs.lookup(ROOT, os("t")).err(), Some(libc::ENOENT));
        assert_eq!(m.fs.rename(ROOT, os("other"), ROOT, os("d"), false).err(), Some(libc::EISDIR));
        assert_eq!(m.fs.rename(ROOT, os("d"), ROOT, os("other"), false).err(), Some(libc::ENOTDIR));
        assert_eq!(m.fs.rename(ROOT, os("other"), ROOT, os("d"), true).err(), Some(libc::EEXIST));
        // A directory into itself.
        let d = m.ino("d").unwrap();
        assert_eq!(m.fs.rename(ROOT, os("d"), d, os("inner"), false).err(), Some(libc::EINVAL));
        // A directory: its files, subdirectories and executable bits move.
        let open_ino = m.ino("d/a").unwrap();
        let fh = m.fs.open(open_ino, true, false).unwrap();
        m.fs.write(fh, 1, b"!").unwrap();
        m.fs.rename(ROOT, os("d"), ROOT, os("e"), false).unwrap();
        assert_eq!(m.names(""), ["e", "other"]);
        assert_eq!(m.cat("e/a").unwrap(), b"A!", "the unflushed write moved along");
        assert_eq!(m.cat("e/sub/b").unwrap(), b"B");
        assert!(m.fs.getattr(m.ino("e/sub/b").unwrap()).unwrap().executable);
        // The open handle follows the file.
        m.fs.write(fh, 2, b"?").unwrap();
        m.fs.release(fh).unwrap();
        assert_eq!(m.cat("e/a").unwrap(), b"A!?");
        assert_eq!(m.fs.getattr(open_ino).unwrap().size, 3);
        assert_eq!(m.lower.read(&p("d/a")).unwrap(), b"A");
    }

    /// Symlinks design, threat 8: a link is a leaf inode. Lookup never
    /// goes through one (`ENOTDIR`), even one pointing at the repository's
    /// own `.veil`; `open` refuses it (the kernel follows links itself);
    /// `symlink()` is refused unless the repository records links, and then
    /// stores the target as it is.
    #[test]
    fn links_are_leaf_inodes_never_traversed() {
        let m = mem(&[("a.txt", b"A"), ("dir/f", b"F")]);
        m.lower.write_link(&p("vault"), b"../../.veil/local/vault.sealed").unwrap();
        m.lower.write_link(&p("up"), b"..").unwrap();
        m.lower.write_link(&p("dir/l"), b"f").unwrap();
        let a = m.fs.lookup(ROOT, os("vault")).unwrap();
        assert_eq!(a.kind, NodeKind::Symlink);
        assert_eq!(m.fs.readlink(a.ino).unwrap(), b"../../.veil/local/vault.sealed");
        for (parent, name) in [("vault", "x"), ("up", "a.txt"), ("dir/l", "x")] {
            let ino = m.ino(parent).unwrap();
            assert_eq!(m.fs.lookup(ino, os(name)).err(), Some(libc::ENOTDIR), "{parent}/{name}");
            assert_eq!(m.fs.create(ino, os(name), false, false).err(), Some(libc::ENOTDIR));
            assert_eq!(m.fs.mkdir(ino, os(name)).err(), Some(libc::ENOTDIR));
        }
        assert_eq!(m.fs.open(a.ino, false, false).err(), Some(libc::ELOOP));
        assert_eq!(m.fs.create(ROOT, os("vault"), false, false).err(), Some(libc::EEXIST));
        assert_eq!(m.fs.setattr(a.ino, Some(0), None, None).err(), Some(libc::EINVAL));
        assert!(m.names("").contains(&"vault".to_string()));
        assert_eq!(m.fs.readlink(m.ino("a.txt").unwrap()).err(), Some(libc::EINVAL));
        // Below format 5, `symlink()` is refused.
        assert_eq!(m.fs.symlink(ROOT, os("new"), b"a.txt").err(), Some(libc::EPERM));
        let m = Mem { fs: m.fs.with_links(true), ..m };
        let new = m.fs.symlink(ROOT, os("new"), b"/etc/passwd").unwrap();
        assert_eq!(new.kind, NodeKind::Symlink);
        assert_eq!(m.upper.read_link(&p("new")).unwrap(), b"/etc/passwd");
        assert!(m.upper.read(&p("new")).is_err());
        assert_eq!(m.fs.symlink(ROOT, os("new"), b"x").err(), Some(libc::EEXIST));
        assert_eq!(m.fs.symlink(ROOT, os("bad"), b"a\0b").err(), Some(libc::EINVAL));
        assert_eq!(m.fs.symlink(ROOT, os("long"), &[b'a'; 5000]).err(), Some(libc::ENAMETOOLONG));
        assert_eq!(m.fs.symlink(ROOT, os(".veil"), b"x").err(), Some(libc::EPERM));
        // Renamed (alone or in a directory), a link stays the same link.
        m.fs.rename(ROOT, os("new"), ROOT, os("moved"), false).unwrap();
        assert_eq!(m.fs.readlink(m.ino("moved").unwrap()).unwrap(), b"/etc/passwd");
        m.fs.rename(ROOT, os("dir"), ROOT, os("dir2"), false).unwrap();
        assert_eq!(m.fs.readlink(m.ino("dir2/l").unwrap()).unwrap(), b"f");
        assert_eq!(m.fs.rename(ROOT, os("moved"), ROOT, os("dir2"), false).err(), Some(libc::EISDIR));
        // Unlinking removes the link, never its target; rmdir refuses it.
        assert_eq!(m.fs.rmdir(ROOT, os("moved")).err(), Some(libc::ENOTDIR));
        m.fs.unlink(ROOT, os("moved")).unwrap();
        assert_eq!(m.fs.lookup(ROOT, os("moved")).err(), Some(libc::ENOENT));
        assert_eq!(m.cat("a.txt").unwrap(), b"A");
        // The recorded view (what the builder reads) has the links as links.
        m.fs.with_view(|v| {
            assert_eq!(v.read_link(&p("dir2/l")).unwrap(), b"f");
            assert_eq!(v.metadata(&p("vault")).unwrap().unwrap().kind, NodeKind::Symlink);
        });
    }

    #[test]
    fn exec_bit_and_truncate() {
        let m = mem(&[("run.sh", b"echo hi\n")]);
        let ino = m.ino("run.sh").unwrap();
        let a = m.fs.setattr(ino, None, Some(0o755), None).unwrap();
        assert!(a.executable);
        assert!(m.upper.metadata(&p("run.sh")).unwrap().unwrap().executable);
        assert_eq!(m.upper.read(&p("run.sh")).unwrap(), b"echo hi\n", "copied up with its content");
        let a = m.fs.setattr(ino, Some(4), None, None).unwrap();
        assert_eq!(a.size, 4);
        assert_eq!(m.cat("run.sh").unwrap(), b"echo");
        assert!(m.fs.getattr(ino).unwrap().executable, "truncate keeps the bit");
        let a = m.fs.setattr(ino, Some(6), Some(0o644), None).unwrap();
        assert!(!a.executable);
        assert_eq!(m.cat("run.sh").unwrap(), b"echo\0\0");
        // Created executable.
        let (a, fh) = m.fs.create(ROOT, os("tool"), true, false).unwrap();
        m.fs.release(fh).unwrap();
        assert!(a.executable);
    }

    #[test]
    fn reconcile_keeps_what_was_not_recorded() {
        let m = mem(&[("a", b"1"), ("gone", b"g"), ("dir/x", b"x")]);
        m.put("a", b"edited").unwrap();
        m.put(".env", b"SECRET=1").unwrap();
        m.fs.unlink(ROOT, os("gone")).unwrap();
        m.fs.unlink(m.ino("dir").unwrap(), os("x")).unwrap();
        m.fs.rmdir(ROOT, os("dir")).unwrap();
        // The "recorded" tree: the edit and the deletions, not `.env`.
        let recorded = Arc::new(MemoryBackend::from_files([("a", &b"edited"[..])]).unwrap());
        m.fs.reconcile(recorded.clone()).unwrap();
        assert_eq!(m.upper.files(), [p(".env")], "only the unrecorded file stays up");
        assert!(m.journal.lock().unwrap().is_empty(), "no whiteout is needed any more");
        assert_eq!(m.names(""), [".env", "a"]);
        assert_eq!(m.cat("a").unwrap(), b"edited");
        assert!(!m.fs.is_clean());
        // A deletion the recording kept (a carried file) keeps its whiteout.
        let m = mem(&[("kept", b"k")]);
        m.fs.unlink(ROOT, os("kept")).unwrap();
        m.fs.reconcile(Arc::new(MemoryBackend::from_files([("kept", &b"k"[..])]).unwrap())).unwrap();
        assert_eq!(m.journal.lock().unwrap().as_slice(), ["=kept"]);
        assert!(m.names("").is_empty());
    }

    #[test]
    fn reconcile_an_opaque_directory() {
        // `rm -r d; mkdir d; echo n > d/new`: the new `d` is recorded, and
        // nothing of the old one may come back.
        let m = mem(&[("d/old", b"o")]);
        m.fs.unlink(m.ino("d").unwrap(), os("old")).unwrap();
        m.fs.rmdir(ROOT, os("d")).unwrap();
        m.fs.mkdir(ROOT, os("d")).unwrap();
        m.put("d/new", b"n").unwrap();
        m.fs.reconcile(Arc::new(MemoryBackend::from_files([("d/new", &b"n"[..])]).unwrap())).unwrap();
        assert!(m.fs.is_clean(), "the recorded tree is exactly what the mount showed");
        assert_eq!(m.names("d"), ["new"]);
        // Recorded with the old file carried (unreadable, say): the whiteout stays.
        let m = mem(&[("d/old", b"o")]);
        m.fs.unlink(m.ino("d").unwrap(), os("old")).unwrap();
        m.fs.rmdir(ROOT, os("d")).unwrap();
        m.fs.mkdir(ROOT, os("d")).unwrap();
        m.put("d/new", b"n").unwrap();
        m.fs.reconcile(Arc::new(MemoryBackend::from_files([("d/new", &b"n"[..]), ("d/old", b"o")]).unwrap())).unwrap();
        assert_eq!(m.names("d"), ["new"]);
        assert_eq!(m.upper.files(), [p("d/new")]);
    }

    #[test]
    fn switch_lower_keeps_the_overlay_and_drops_conflicts() {
        let m = mem(&[("a", b"1"), ("b", b"2")]);
        m.put("a", b"mine").unwrap();
        let before = m.fs.getattr(m.ino("b").unwrap()).unwrap().mtime;
        let moved = Arc::new(MemoryBackend::from_files([("a", &b"1"[..]), ("b", b"theirs"), ("c", b"new")]).unwrap());
        std::thread::sleep(std::time::Duration::from_millis(5));
        m.fs.switch_lower(moved.clone(), &[p("b"), p("c")], &[]).unwrap();
        assert_eq!(m.cat("a").unwrap(), b"mine");
        assert_eq!(m.cat("b").unwrap(), b"theirs");
        assert_eq!(m.cat("c").unwrap(), b"new");
        assert!(m.fs.getattr(m.ino("b").unwrap()).unwrap().mtime > before, "a changed file gets a new mtime");
        // A conflicting edit is dropped (the caller saved it elsewhere).
        let moved2 = Arc::new(MemoryBackend::from_files([("a", &b"other"[..]), ("b", b"theirs")]).unwrap());
        m.fs.switch_lower(moved2, &[p("a"), p("c")], &[p("a")]).unwrap();
        assert_eq!(m.cat("a").unwrap(), b"other");
        assert!(m.fs.is_clean());
    }

    #[test]
    fn errors_map_to_errno() {
        assert_eq!(errno(&VeilError::NotFound("x".into())), libc::ENOENT);
        assert_eq!(errno(&VeilError::InvalidPath("a is a directory".into())), libc::EISDIR);
        assert_eq!(errno(&VeilError::InvalidPath("a is a file, not a directory".into())), libc::ENOTDIR);
        assert_eq!(errno(&VeilError::ReadOnly), libc::EROFS);
        assert_eq!(errno(&VeilError::Redacted { scope: "team".into() }), libc::EACCES);
        let m = mem(&[]);
        assert_eq!(m.fs.lookup(ROOT, os("a/b")).err(), Some(libc::EINVAL));
        assert_eq!(m.fs.lookup(ROOT, os("..")).err(), Some(libc::EINVAL));
        let long = "x".repeat(300);
        assert_eq!(m.fs.create(ROOT, os(&long), false, false).err(), Some(libc::ENAMETOOLONG));
    }

    /// BUG-537: entries deleted while a directory is read shift nothing.
    #[test]
    fn readdir_offsets_survive_deletions() {
        let files: Vec<(String, Vec<u8>)> = (0..50).map(|i| (format!("d/f{i:02}"), b"x".to_vec())).collect();
        let m = mem(&files.iter().map(|(n, d)| (n.as_str(), d.as_slice())).collect::<Vec<_>>());
        let d = m.ino("d").unwrap();
        let fh = m.fs.opendir(d).unwrap();
        let mut seen = Vec::new();
        let mut offset = 0;
        loop {
            // A small buffer: the kernel asks again from the last offset.
            let batch: Vec<_> = m.fs.readdir_at(fh, d, offset).unwrap().into_iter().take(7).collect();
            if batch.is_empty() {
                break;
            }
            for (_, next, name, _) in batch {
                offset = next;
                if name != "." && name != ".." {
                    m.fs.unlink(d, os(&name)).unwrap();
                    seen.push(name);
                }
            }
        }
        m.fs.releasedir(fh);
        assert_eq!(seen.len(), 50);
        assert!(m.names("d").is_empty());
        m.fs.rmdir(ROOT, os("d")).unwrap();
        // Offset 0 again (`rewinddir`) lists afresh.
        let fh = m.fs.opendir(ROOT).unwrap();
        m.put("new", b"n").unwrap();
        let names: Vec<String> = m.fs.readdir_at(fh, ROOT, 0).unwrap().into_iter().map(|e| e.2).collect();
        assert_eq!(names, [".", "..", "new"]);
    }

    /// BUG-536: a size or an offset past the largest file is `EFBIG`, and
    /// the mount goes on serving.
    #[test]
    fn huge_sizes_and_offsets_are_refused() {
        let m = mem(&[("a", b"keep")]);
        let ino = m.ino("a").unwrap();
        assert_eq!(m.fs.setattr(ino, Some(1 << 40), None, None).err(), Some(libc::EFBIG));
        assert_eq!(m.fs.setattr(ino, Some(u64::MAX), None, None).err(), Some(libc::EFBIG));
        let fh = m.fs.open(ino, true, false).unwrap();
        assert_eq!(m.fs.write(fh, 1 << 40, b"x").err(), Some(libc::EFBIG));
        assert_eq!(m.fs.write(fh, u64::MAX, b"x").err(), Some(libc::EFBIG));
        assert_eq!(m.fs.setattr(ino, Some(max_file_size() + 1), None, None).err(), Some(libc::EFBIG));
        m.fs.write(fh, 4, b"!").unwrap();
        m.fs.release(fh).unwrap();
        assert_eq!(m.cat("a").unwrap(), b"keep!");
    }

    /// BUG-561: open files are their upper file. A truncate past the end
    /// and a write far out reach the upper layer at once, an open file
    /// renamed (moved in the upper layer) or unlinked keeps working, and a
    /// recording's reconcile leaves an open upper file alone.
    #[test]
    fn open_files_are_their_upper_file() {
        let m = mem(&[("a", b"lower")]);
        let ino = m.ino("a").unwrap();
        let fh = m.fs.open(ino, true, false).unwrap();
        m.fs.setattr(ino, Some(10), None, None).unwrap();
        assert_eq!(m.upper.read(&p("a")).unwrap(), b"lower\0\0\0\0\0");
        m.fs.write(fh, 12, b"far").unwrap();
        assert_eq!(m.fs.getattr(ino).unwrap().size, 15);
        assert_eq!(m.fs.read(fh, 8, 10).unwrap(), b"\0\0\0\0far");
        // Renamed while open: the handle follows.
        m.fs.rename(ROOT, os("a"), ROOT, os("b"), false).unwrap();
        m.fs.write(fh, 0, b"L").unwrap();
        assert_eq!(m.upper.read(&p("b")).unwrap(), b"Lower\0\0\0\0\0\0\0far");
        assert!(m.upper.metadata(&p("a")).unwrap().is_none());
        // A recording that saw the file as it is keeps it while it is open.
        let recorded = Arc::new(MemoryBackend::from_files([("b", &b"Lower\0\0\0\0\0\0\0far"[..])]).unwrap());
        m.fs.reconcile(recorded).unwrap();
        m.fs.write(fh, 1, b"O").unwrap();
        m.fs.release(fh).unwrap();
        assert_eq!(m.cat("b").unwrap(), b"LOwer\0\0\0\0\0\0\0far");
        // Unlinked while open: still readable and writable, reaching no path.
        let ino = m.ino("b").unwrap();
        let fh = m.fs.open(ino, true, false).unwrap();
        m.fs.unlink(ROOT, os("b")).unwrap();
        m.fs.write(fh, 0, b"gone").unwrap();
        assert_eq!(m.fs.read(fh, 0, 4).unwrap(), b"gone");
        assert!(m.upper.metadata(&p("b")).unwrap().is_none());
        m.fs.release(fh).unwrap();
    }

    /// BUG-534: deleting a directory that held files this reader could not
    /// read remembers them (before the whiteout), and forgets them once no
    /// whiteout hides them.
    #[test]
    fn deleted_directories_remember_what_they_never_showed() {
        let inner = MemoryBackend::from_files([("dir/a", &b"a"[..]), ("dir/secret", b"s"), ("b", b"b")]).unwrap();
        let lower = Arc::new(Hiding { inner, hidden: vec![p("dir/secret")] });
        let journal = Arc::new(Mutex::new(Vec::new()));
        let fs = MountFs::new(lower, Arc::new(MemoryBackend::new()), Vec::new(), Some(Box::new(VecJournal(journal.clone()))));
        let m = Mem { fs, lower: Arc::new(MemoryBackend::new()), upper: Arc::new(MemoryBackend::new()), journal };
        assert_eq!(m.names("dir"), ["a"]);
        let dir = m.ino("dir").unwrap();
        m.fs.unlink(dir, os("a")).unwrap();
        assert!(m.fs.unseen().is_empty(), "a was shown");
        m.fs.rmdir(ROOT, os("dir")).unwrap();
        assert_eq!(m.fs.unseen(), [p("dir/secret")]);
        assert_eq!(*m.journal.lock().unwrap(), ["+dir/a", "unseen dir/secret", "+dir"], "remembered before the whiteout");
        // Still hidden under the whiteout after a refresh that can read it.
        let inner = MemoryBackend::from_files([("dir/a", &b"a"[..]), ("dir/secret", b"s"), ("b", b"b")]).unwrap();
        m.fs.refresh_lower(Arc::new(Hiding { inner, hidden: Vec::new() }));
        assert!(m.ino("dir").is_err());
        assert_eq!(m.fs.unseen(), [p("dir/secret")]);
        // Recorded: the new tree holds only the carried file, which this
        // reader still cannot read; no whiteout is needed, nothing to carry.
        let inner = MemoryBackend::from_files([("dir/secret", &b"s"[..]), ("b", b"b")]).unwrap();
        m.fs.reconcile(Arc::new(Hiding { inner, hidden: vec![p("dir/secret")] })).unwrap();
        assert!(m.fs.is_clean());
        assert!(m.fs.unseen().is_empty());
        assert_eq!(m.journal.lock().unwrap().last().unwrap(), "unseen ");
    }
}
