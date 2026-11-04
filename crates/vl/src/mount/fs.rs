//! The file system a `vl ws mount` serves, without the kernel.
//!
//! [`MountFs`] speaks in inode numbers, file handles and `errno` values,
//! as FUSE does, but knows nothing about FUSE: the adapter in
//! `mount/fuse.rs` only translates. So every operation is unit-tested here
//! over [`MemoryBackend`](veil_core::vfs::MemoryBackend)s.
//!
//! **Layers.** Reads come from an [`OverlayBackend`]: its lower layer is a
//! [`ReaderView`] of the workspace's tree (what *this* reader may see: a
//! cloaked file it cannot decrypt shows its public fallback, or is absent,
//! exactly as checkout writes it), its upper layer holds every write, and
//! whiteouts hide what was deleted. The lower layer is never written. The
//! upper layer of a real mount is a directory on disk
//! (`.veil/local/mounts/<ws>/upper`) and whiteouts are appended to a
//! journal, so a crash of the mount loses nothing that was closed.
//!
//! **Open files** keep their content in a buffer while open (a read never
//! decrypts a file twice; writes at any offset are cheap). A written
//! buffer goes to the upper layer on `flush` (every `close`), `fsync` and
//! `release`.
//!
//! **Moving the base.** After the overlay was recorded, or when the
//! workspace moved under the mount, [`MountFs::reconcile`] and
//! [`MountFs::switch_lower`] put the overlay over the new tree, keeping
//! what it shows.

use std::{
    collections::{BTreeSet, HashMap},
    sync::{Arc, Mutex, MutexGuard},
    time::SystemTime,
};

use veil_core::{
    error::Result as VResult,
    id::ObjectId,
    object::{is_reserved_name, EntryKind, TreeEntry},
    store::ObjectStore,
    tree::{lookup, TreeView},
    vfs::{is_temp_name, walk_files, DirEntry, Metadata, NodeKind, OverlayBackend, StorageBackend},
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
}

/// The lower layer of a mount: a snapshot tree as this reader may see it.
///
/// A [`TreeView`] lists only what this reader can materialise, but answers
/// `metadata` (and `read`, with an error) for every entry. Here an entry
/// this reader cannot read is absent everywhere, as in a checkout, and a
/// cloaked file shown as its public fallback has the fallback's size.
#[derive(Debug)]
pub struct ReaderView {
    store: Arc<ObjectStore>,
    view: TreeView,
}

impl ReaderView {
    pub fn new(store: Arc<ObjectStore>, tree: ObjectId) -> ReaderView {
        ReaderView {
            view: TreeView::new(store.clone(), tree),
            store,
        }
    }

    /// The entry at `path`, if this reader can materialise it. A directory
    /// on the way that cannot be opened hides everything below it, and a
    /// directory holding nothing this reader can read is absent (checkout
    /// would not create it).
    fn entry(&self, path: &VPath) -> VResult<Option<TreeEntry>> {
        match lookup(&self.store, &self.view.root(), path) {
            Ok(Some(e)) if path.is_root() => Ok(Some(e)),
            Ok(Some(e)) if e.kind == EntryKind::Dir => Ok(self.dir_visible(&e)?.then_some(e)),
            Ok(Some(e)) if self.store.entry_readable(&e) => Ok(Some(e)),
            Ok(_) => Ok(None),
            Err(e) if e.is_unreadable() => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Does directory entry `dir` hold a file this reader can read?
    /// Depth first, stopping at the first one (usually the first entry).
    fn dir_visible(&self, dir: &TreeEntry) -> VResult<bool> {
        let mut stack = vec![dir.id];
        while let Some(id) = stack.pop() {
            let tree = match self.store.tree(&id) {
                Ok(t) => t,
                Err(e) if e.is_unreadable() || e.is_not_found() => continue,
                Err(e) => return Err(e),
            };
            for c in tree.entries.iter().rev() {
                match c.kind {
                    EntryKind::Dir => stack.push(c.id),
                    _ if self.store.entry_readable(c) => return Ok(true),
                    _ => {}
                }
            }
        }
        Ok(false)
    }
}

impl StorageBackend for ReaderView {
    fn kind(&self) -> &'static str {
        "tree"
    }

    fn read(&self, path: &VPath) -> VResult<Vec<u8>> {
        match self.entry(path)? {
            Some(_) => self.view.read(path),
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

    fn list_dir(&self, path: &VPath) -> VResult<Vec<DirEntry>> {
        if self.entry(path)?.is_none() {
            return Err(VeilError::NotFound(path.to_string()));
        }
        let mut out = Vec::new();
        for e in self.view.list_dir(path)? {
            if e.kind == NodeKind::File || self.entry(&path.join(&e.name))?.is_some() {
                out.push(e);
            }
        }
        Ok(out)
    }

    fn metadata(&self, path: &VPath) -> VResult<Option<Metadata>> {
        let Some(e) = self.entry(path)? else { return Ok(None) };
        if e.kind == EntryKind::File {
            if let Some(fb) = e.fallback {
                let own = TreeEntry {
                    fallback: None,
                    ..e.clone()
                };
                if !self.store.entry_readable(&own) {
                    // Shown as its last public version: that is its size.
                    let len = self.store.read_blob(&fb)?.len() as u64;
                    return Ok(Some(Metadata::unstamped(NodeKind::File, len, e.executable)));
                }
            }
        }
        self.view.metadata(path)
    }

    fn known_id(&self, path: &VPath) -> Option<ObjectId> {
        self.entry(path).ok().flatten().map(|e| e.id)
    }
}

struct Buf {
    data: Vec<u8>,
    dirty: bool,
}

struct Node {
    /// `None` once unlinked (or replaced by a rename) while still open.
    path: Option<VPath>,
    lookups: u64,
    open: u32,
    /// The content while the file is open.
    buf: Option<Buf>,
}

struct Handle {
    ino: u64,
    write: bool,
}

struct Inner {
    overlay: OverlayBackend,
    journal: Option<Box<dyn Journal>>,
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
                buf: None,
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
        let size = match self.nodes.get(&ino).and_then(|n| n.buf.as_ref()) {
            Some(b) if m.kind == NodeKind::File => b.data.len() as u64,
            _ => m.len,
        };
        Ok(Attr {
            ino,
            kind: m.kind,
            size,
            executable: m.executable,
            mtime: self.mtime(path),
        })
    }

    /// The attributes of an open node, which may no longer have a path.
    fn attr_of(&self, ino: u64) -> FsResult<Attr> {
        match self.nodes.get(&ino) {
            Some(Node { path: None, buf: Some(b), .. }) => Ok(Attr {
                ino,
                kind: NodeKind::File,
                size: b.data.len() as u64,
                executable: false,
                mtime: SystemTime::now(),
            }),
            _ => {
                let p = self.path(ino)?;
                self.attr(ino, &p)
            }
        }
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

    /// Load the content of open node `ino` into its buffer.
    fn load(&mut self, ino: u64) -> FsResult<&mut Buf> {
        let need = self.nodes.get(&ino).ok_or(libc::EBADF)?.buf.is_none();
        if need {
            let path = self.path(ino)?;
            let data = self.overlay.read(&path).map_err(|e| errno(&e))?;
            self.nodes.get_mut(&ino).ok_or(libc::EBADF)?.buf = Some(Buf { data, dirty: false });
        }
        Ok(self.nodes.get_mut(&ino).and_then(|n| n.buf.as_mut()).expect("loaded"))
    }

    /// Write node `ino`'s buffer to the upper layer if it changed.
    fn persist(&mut self, ino: u64) -> FsResult<()> {
        let Some(node) = self.nodes.get(&ino) else { return Ok(()) };
        let (Some(path), Some(buf)) = (&node.path, &node.buf) else { return Ok(()) };
        if !buf.dirty {
            return Ok(());
        }
        let path = path.clone();
        self.overlay.write(&path, &buf.data).map_err(|e| errno(&e))?;
        if let Some(b) = self.nodes.get_mut(&ino).and_then(|n| n.buf.as_mut()) {
            b.dirty = false;
        }
        Ok(())
    }

    fn persist_under(&mut self, root: &VPath) -> FsResult<()> {
        let inos: Vec<u64> = self
            .nodes
            .iter()
            .filter(|(_, n)| n.buf.as_ref().is_some_and(|b| b.dirty) && n.path.as_ref().is_some_and(|p| p.starts_with(root)))
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
                // Keep reading what was there, wherever it came from.
                if self.nodes.get(&ino).is_some_and(|n| n.buf.is_none()) && self.load(ino).is_err() {
                    if let Some(n) = self.nodes.get_mut(&ino) {
                        n.buf = Some(Buf { data: Vec::new(), dirty: false });
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

    fn copy_file(&mut self, from: &VPath, to: &VPath) -> FsResult<()> {
        let m = self.meta(from)?.ok_or(libc::ENOENT)?;
        let data = match self.by_path.get(from).and_then(|i| self.nodes.get(i)).and_then(|n| n.buf.as_ref()) {
            Some(b) => b.data.clone(),
            None => self.overlay.read(from).map_err(|e| errno(&e))?,
        };
        self.overlay.write(to, &data).map_err(|e| errno(&e))?;
        // `write` keeps the bit of what it replaced: set it either way.
        self.overlay.set_executable(to, m.executable).map_err(|e| errno(&e))?;
        Ok(())
    }

    fn rewrite_journal(&mut self) -> FsResult<()> {
        let all = self.overlay.whiteouts();
        if let Some(j) = self.journal.as_mut() {
            j.rewrite(&all).map_err(|e| io_errno(&e))?;
        }
        Ok(())
    }

    /// Replace the lower layer, keeping the upper one and the whiteouts.
    fn set_lower(&mut self, lower: Arc<dyn StorageBackend>) {
        let upper = self.overlay.upper().clone();
        let whiteouts = self.overlay.whiteouts();
        self.overlay = OverlayBackend::with_upper(lower, upper, whiteouts);
    }

    /// Drop the cached content of closed-but-cached nodes at `paths`, and
    /// give the paths a new modification time.
    fn changed(&mut self, paths: &[VPath]) {
        for p in paths {
            self.touch(p);
            if let Some(ino) = self.by_path.get(p).copied() {
                if let Some(n) = self.nodes.get_mut(&ino) {
                    if n.buf.as_ref().is_some_and(|b| !b.dirty) {
                        n.buf = None;
                    }
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
        lower: Arc<dyn StorageBackend>,
        upper: Arc<dyn StorageBackend>,
        whiteouts: Vec<VPath>,
        journal: Option<Box<dyn Journal>>,
    ) -> MountFs {
        MountFs {
            inner: Mutex::new(Inner {
                overlay: OverlayBackend::with_upper(lower, upper, whiteouts),
                journal,
                nodes: HashMap::new(),
                by_path: HashMap::new(),
                next_ino: ROOT + 1,
                handles: HashMap::new(),
                next_fh: 1,
                times: HashMap::new(),
                epoch: SystemTime::now(),
                generation: 0,
            }),
        }
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
    pub fn readdir(&self, ino: u64) -> FsResult<Vec<(u64, String, NodeKind)>> {
        let mut g = self.lock();
        let dir = g.path(ino)?;
        let entries = g.overlay.list_dir(&dir).map_err(|e| errno(&e))?;
        Ok(entries
            .into_iter()
            .filter(|e| !is_temp_name(&e.name) && !is_reserved_name(&e.name))
            .map(|e| {
                let p = dir.join(&e.name);
                (g.ino_for(&p), e.name, e.kind)
            })
            .collect())
    }

    pub fn open(&self, ino: u64, write: bool, truncate: bool) -> FsResult<u64> {
        let mut g = self.lock();
        let path = g.path(ino)?;
        match g.meta(&path)? {
            Some(m) if m.kind == NodeKind::Dir => return Err(libc::EISDIR),
            Some(_) => {}
            None => return Err(libc::ENOENT),
        }
        if truncate && write {
            let n = g.nodes.get_mut(&ino).ok_or(libc::ENOENT)?;
            n.buf = Some(Buf { data: Vec::new(), dirty: true });
            g.persist(ino)?;
            g.touch(&path);
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
        if !exists {
            n.buf = Some(Buf { data: Vec::new(), dirty: false });
        }
        let fh = g.next_fh;
        g.next_fh += 1;
        g.handles.insert(fh, Handle { ino, write: true });
        Ok((g.attr(ino, &path)?, fh))
    }

    pub fn read(&self, fh: u64, offset: u64, size: u32) -> FsResult<Vec<u8>> {
        let mut g = self.lock();
        let ino = g.handles.get(&fh).ok_or(libc::EBADF)?.ino;
        let buf = g.load(ino)?;
        let start = usize::try_from(offset).unwrap_or(usize::MAX).min(buf.data.len());
        let end = start.saturating_add(size as usize).min(buf.data.len());
        Ok(buf.data[start..end].to_vec())
    }

    pub fn write(&self, fh: u64, offset: u64, data: &[u8]) -> FsResult<u32> {
        let mut g = self.lock();
        let h = g.handles.get(&fh).ok_or(libc::EBADF)?;
        if !h.write {
            return Err(libc::EBADF);
        }
        let ino = h.ino;
        let start = usize::try_from(offset).map_err(|_| libc::EFBIG)?;
        let end = start.checked_add(data.len()).ok_or(libc::EFBIG)?;
        let buf = g.load(ino)?;
        if buf.data.len() < end {
            buf.data.resize(end, 0);
        }
        buf.data[start..end].copy_from_slice(data);
        buf.dirty = true;
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
                if n.open == 0 && n.buf.as_ref().is_none_or(|b| !b.dirty) {
                    n.buf = None;
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
            let size = usize::try_from(size).map_err(|_| libc::EFBIG)?;
            let open = g.nodes.get(&ino).is_some_and(|n| n.open > 0);
            let buf = g.load(ino)?;
            if buf.data.len() != size {
                buf.data.resize(size, 0);
                buf.dirty = true;
            }
            // Through a path (`truncate(1)`), or by a handle: either way
            // the upper layer has it now.
            g.persist(ino)?;
            if !open {
                if let Some(n) = g.nodes.get_mut(&ino) {
                    n.buf = None;
                }
            }
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
            Some(m) if m.kind == NodeKind::File => return Err(libc::ENOTDIR),
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
                (NodeKind::File, NodeKind::Dir) => return Err(libc::EISDIR),
                (NodeKind::Dir, NodeKind::File) => return Err(libc::ENOTDIR),
                (NodeKind::Dir, NodeKind::Dir) => {
                    let entries = g.overlay.list_dir(&to).map_err(|e| errno(&e))?;
                    if !entries.is_empty() {
                        return Err(libc::ENOTEMPTY);
                    }
                }
                (NodeKind::File, NodeKind::File) => {}
            }
            g.detach(&to)?;
            g.remove(&to, dst.kind == NodeKind::Dir)?;
        }
        g.persist_under(&from)?;
        match src.kind {
            NodeKind::File => g.copy_file(&from, &to)?,
            NodeKind::Dir => {
                g.overlay.create_dir_all(&to).map_err(|e| errno(&e))?;
                let rel = |p: &VPath| VPath::new(&p.as_str()[from.as_str().len()..]).expect("below");
                for d in walk_dirs(&g.overlay, &from).map_err(|e| errno(&e))? {
                    let target = VPath::new(&format!("{}/{}", to.as_str(), rel(&d).as_str())).map_err(|e| errno(&e))?;
                    g.overlay.create_dir_all(&target).map_err(|e| errno(&e))?;
                }
                for f in walk_files(&g.overlay, &from, &|_| false).map_err(|e| errno(&e))? {
                    let target = VPath::new(&format!("{}/{}", to.as_str(), rel(&f).as_str())).map_err(|e| errno(&e))?;
                    g.copy_file(&f, &target)?;
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
        let mut paths = walk_files(&*upper, &VPath::root(), &|_| false).unwrap_or_default();
        paths.extend(walk_dirs(&*upper, &VPath::root()).unwrap_or_default());
        paths.sort();
        (paths, g.overlay.whiteouts())
    }

    /// The files of the upper layer (what the mount holds that the lower
    /// layer does not).
    pub fn upper_files(&self) -> Vec<VPath> {
        let g = self.lock();
        walk_files(&**g.overlay.upper(), &VPath::root(), &|_| false).unwrap_or_default()
    }

    /// Put the overlay over `lower` (the workspace moved under the mount):
    /// `changed` are the paths that differ between the old and the new
    /// lower layer, `drop` the parts of the overlay to give up first (they
    /// conflict with the move; the caller saved them). Everything else the
    /// overlay holds stays as it is.
    pub fn switch_lower(&self, lower: Arc<dyn StorageBackend>, changed: &[VPath], drop: &[VPath]) -> FsResult<()> {
        let mut g = self.lock();
        g.persist_under(&VPath::root())?;
        let upper = g.overlay.upper().clone();
        for p in drop {
            match upper_kind(&*upper, p) {
                Some(NodeKind::Dir) => upper.remove_dir_all(p).map_err(|e| errno(&e))?,
                Some(NodeKind::File) => upper.remove_file(p).map_err(|e| errno(&e))?,
                None => {}
            }
            g.overlay.remove_whiteout(p);
            for w in g.overlay.whiteouts() {
                if w.starts_with(p) {
                    g.overlay.remove_whiteout(&w);
                }
            }
            // The paths stay (now from the new lower layer): the kernel
            // keeps its inodes, only cached content goes.
            for n in g.nodes.values_mut() {
                if n.open == 0 && n.path.as_ref().is_some_and(|q| q.starts_with(p)) {
                    n.buf = None;
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
    pub fn reconcile(&self, lower: Arc<dyn StorageBackend>) -> FsResult<()> {
        let mut g = self.lock();
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
                Some(_) => {
                    upper_kind(&*upper, &w) != Some(NodeKind::Dir)
                        || walk_files(&*lower, &w, &|_| false)
                            .map_err(e)?
                            .iter()
                            .any(|f| upper_kind(&*upper, f) != Some(NodeKind::File))
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
        // Upper files identical to the new lower layer go.
        for f in walk_files(&*upper, &VPath::root(), &|_| false).map_err(e)? {
            if hidden(&f) {
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
        g.overlay = OverlayBackend::with_upper(lower, upper, kept);
        g.rewrite_journal()?;
        // Cached content of closed files may be stale.
        for n in g.nodes.values_mut() {
            if n.open == 0 {
                n.buf = None;
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

    #[test]
    fn writes_go_to_the_upper_layer_only() {
        let m = mem(&[("a/x.txt", b"hello world")]);
        let ino = m.ino("a/x.txt").unwrap();
        let fh = m.fs.open(ino, true, false).unwrap();
        m.fs.write(fh, 6, b"there").unwrap();
        // Not yet closed: the buffer serves reads, the upper layer is empty.
        assert_eq!(m.fs.getattr(ino).unwrap().size, 11);
        assert!(m.upper.files().is_empty());
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
}
