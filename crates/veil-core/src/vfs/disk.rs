use std::{
    collections::BTreeSet,
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use super::{DirEntry, DirListing, Metadata, NameFolding, NodeKind, StatClock, StorageBackend};
use crate::{
    error::{Result, VeilError},
    vpath::VPath,
};

/// Persistent storage rooted at a host directory. Writes are atomic and
/// durable: temp file, fsync, rename, fsync of the directory. When `write`
/// or `create_new` returns, the data survives a crash, so the order of
/// writes is the order in which they become durable (the engine relies on
/// this: objects, then the operation, then the operation head). Symlinks are
/// not followed and are invisible to the engine in this MVP: `metadata`
/// reports nothing at a symlink, `read` refuses one, and `list_dir_full`
/// reports them as `special` so callers never write through or over them;
/// writes themselves refuse a path below a symlinked directory (outside
/// `.veil/`).
///
/// [`StorageBackend::write_unsynced`] skips both fsyncs and remembers the
/// file; [`StorageBackend::sync_barrier`] then syncs every remembered file
/// (several at a time, so the filesystem can share journal commits) and
/// every touched directory once. Clones share that state.
///
/// On macOS, durability needs `F_FULLFSYNC` (a plain `fsync` leaves data in
/// the drive's volatile cache). Single writes use it directly. A barrier
/// `fsync`s every file and directory, then issues one `F_FULLFSYNC`, which
/// flushes the drive cache for all of them at once.
///
/// [`StorageBackend::name_folding`] is probed once (see [`probe_folding`]):
/// whether the filesystem holding the root treats `README` and `readme` as
/// one name, which macOS volumes and FAT/SMB mounts do.
#[derive(Debug, Clone)]
pub struct DiskBackend {
    root: PathBuf,
    unsynced: Arc<Mutex<Unsynced>>,
    /// Serialises barriers (see [`StorageBackend::sync_barrier`]).
    barrier: Arc<Mutex<()>>,
    /// Probed lazily; only a definite answer is cached.
    folding: Arc<Mutex<Option<NameFolding>>>,
}

/// Writes made durable by the next barrier.
#[derive(Debug, Default)]
struct Unsynced {
    files: Vec<PathBuf>,
    /// Directories whose entries changed: parents of the files, and parents
    /// of newly created directories.
    dirs: BTreeSet<PathBuf>,
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

/// "Nothing there": the path is missing, or an ancestor is a file (ENOTDIR).
/// Read, metadata and removal paths treat both alike, as every other
/// backend does.
fn is_missing(e: &io::Error) -> bool {
    matches!(e.kind(), io::ErrorKind::NotFound | io::ErrorKind::NotADirectory)
}

/// [`io_err`] for read paths: ENOTDIR is "not found" too.
fn read_err(path: &Path, e: io::Error) -> VeilError {
    if is_missing(&e) {
        VeilError::NotFound(path.display().to_string())
    } else {
        io_err(path, e)
    }
}

/// Display form of a file name that is not valid UTF-8: valid runs as-is
/// (control characters escaped), every invalid byte as `\xNN`.
fn escape_name(name: &std::ffi::OsStr) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let mut out = String::new();
        for chunk in name.as_bytes().utf8_chunks() {
            // Control characters too: the result is printed to terminals.
            for c in chunk.valid().chars() {
                match c.is_control() {
                    true => out.extend(c.escape_default()),
                    false => out.push(c),
                }
            }
            for b in chunk.invalid() {
                out.push_str(&format!("\\x{b:02x}"));
            }
        }
        out
    }
    #[cfg(not(unix))]
    {
        name.to_string_lossy().into_owned()
    }
}

impl DiskBackend {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        DiskBackend {
            root: root.into(),
            unsynced: Arc::default(),
            barrier: Arc::default(),
            folding: Arc::default(),
        }
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

    /// Refuse to write `path` if a directory above it, below the root, is
    /// a symlink: the write would land wherever the link points, outside
    /// what the engine manages (an untracked `vendor -> /shared/vendor`).
    /// Checkout and `vl restore` already skip such paths; this guards every
    /// other caller. The engine's own directory (`.veil/` at the root) is
    /// not checked: nothing from a tree is ever written there. One `lstat`
    /// per existing directory above the path.
    fn refuse_symlinked_parent(&self, path: &VPath) -> Result<()> {
        let parts: Vec<&str> = path.components().collect();
        if parts.first() == Some(&crate::repo::VEIL_DIR) {
            return Ok(());
        }
        let mut dir = self.root.clone();
        for part in &parts[..parts.len().saturating_sub(1)] {
            dir.push(part);
            match fs::symlink_metadata(&dir) {
                Ok(m) if m.file_type().is_symlink() => {
                    return Err(VeilError::InvalidPath(format!(
                        "refusing to write {path}: {} is a symbolic link",
                        dir.strip_prefix(&self.root).unwrap_or(&dir).display()
                    )));
                }
                Ok(m) if m.is_dir() => {}
                // Missing (created as a real directory below) or not a
                // directory (the write fails).
                _ => break,
            }
        }
        Ok(())
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
    full_sync(&f)
}

/// Flush `f` to stable storage. On macOS `File::sync_all` is
/// `fcntl(F_FULLFSYNC)`, the only call that empties the drive's write cache;
/// filesystems that do not implement it (some network and FUSE ones) get a
/// plain `fsync`, the best they offer.
fn full_sync(f: &fs::File) -> io::Result<()> {
    match f.sync_all() {
        #[cfg(target_os = "macos")]
        Err(e) if fullfsync_unsupported(&e) => plain_fsync(f),
        r => r,
    }
}

/// `fsync(2)` without `F_FULLFSYNC`: on macOS this hands the data to the
/// drive but does not flush its cache (see [`DiskBackend`]'s barrier).
#[cfg(target_os = "macos")]
fn plain_fsync(f: &fs::File) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    loop {
        // SAFETY: `fsync` on a file descriptor we own for the duration.
        if unsafe { libc::fsync(f.as_raw_fd()) } == 0 {
            return Ok(());
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

#[cfg(target_os = "macos")]
fn fullfsync_unsupported(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(libc::ENOTSUP | libc::EOPNOTSUPP | libc::ENOTTY | libc::EINVAL)
    )
}

fn create_exclusive(full: &Path, data: &[u8]) -> io::Result<bool> {
    let mut f = match fs::OpenOptions::new().write(true).create_new(true).open(full) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => return Ok(false),
        Err(e) => return Err(e),
    };
    if let Err(e) = f.write_all(data).and_then(|_| full_sync(&f)) {
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
    match fs::File::open(dir).and_then(|d| full_sync(&d)) {
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

/// `create_dir_all` that reports the directories it created (shallowest
/// first), without syncing anything.
fn create_dir_all_tracked(dir: &Path, created: &mut Vec<PathBuf>) -> io::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    let mut missing = Vec::new();
    let mut cur = Some(dir);
    while let Some(d) = cur {
        if d.is_dir() {
            break;
        }
        missing.push(d.to_path_buf());
        cur = d.parent();
    }
    fs::create_dir_all(dir)?;
    created.extend(missing.into_iter().rev());
    Ok(())
}

/// fsync an existing file.
fn sync_file(path: &Path) -> io::Result<()> {
    // Windows needs write access to flush; Unix flushes through any handle.
    full_sync(&fs::OpenOptions::new().read(true).write(cfg!(windows)).open(path)?)
}

/// What a barrier does per file: on macOS a plain `fsync` (the drive cache
/// is flushed once for the whole batch by [`flush_drive_cache`]), elsewhere
/// [`sync_file`].
fn barrier_sync_file(path: &Path) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        plain_fsync(&fs::File::open(path)?)
    }
    #[cfg(not(target_os = "macos"))]
    {
        sync_file(path)
    }
}

/// [`barrier_sync_file`] for directories.
fn barrier_sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        match fs::File::open(dir).and_then(|d| plain_fsync(&d)) {
            Err(e) if fullfsync_unsupported(&e) => Ok(()),
            r => r,
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        sync_dir(dir)
    }
}

/// End of a barrier: on macOS, one `F_FULLFSYNC` empties the drive's write
/// cache, making every `fsync` of the batch durable. A no-op elsewhere,
/// where `fsync` already reached stable storage.
#[allow(unused_variables)]
fn flush_drive_cache(files: &[PathBuf], dirs: &[PathBuf]) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    for p in files.iter().chain(dirs) {
        match fs::File::open(p) {
            Ok(f) => return full_sync(&f),
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Run `f` on every item, on up to `max_workers` threads. Concurrent
/// fsyncs let filesystems such as ext4 and XFS commit many files in one
/// journal transaction instead of one each.
fn for_each_parallel<T: Sync>(
    items: &[T],
    max_workers: usize,
    f: impl Fn(&T) -> io::Result<()> + Sync,
) -> io::Result<()> {
    const PER_WORKER: usize = 16;
    let workers = items.len().div_ceil(PER_WORKER).clamp(1, max_workers);
    if workers == 1 {
        return items.iter().try_for_each(f);
    }
    let next = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..workers)
            .map(|_| {
                scope.spawn(|| loop {
                    let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    match items.get(i) {
                        Some(item) => f(item)?,
                        None => return Ok(()),
                    }
                })
            })
            .collect();
        handles
            .into_iter()
            .try_for_each(|h| h.join().unwrap_or_else(|_| Err(io::Error::other("sync worker panicked"))))
    })
}

const SYNC_WORKERS: usize = 32;

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
        // Symlinks are invisible: `metadata` reports nothing there, so
        // reading must not follow one either.
        if fs::symlink_metadata(&full).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err(VeilError::NotFound(full.display().to_string()));
        }
        fs::read(&full).map_err(|e| read_err(&full, e))
    }

    fn read_through_link(&self, path: &VPath, limit: u64) -> Result<Option<(String, Vec<u8>)>> {
        use std::io::Read;
        let full = self.full_path(path);
        let refuse = |why: &str| VeilError::Io {
            path: full.display().to_string(),
            source: io::Error::other(why.to_string()),
        };
        match fs::symlink_metadata(&full) {
            Ok(m) if m.file_type().is_symlink() => {}
            Ok(m) if m.is_file() || m.is_dir() => return Ok(None),
            Ok(_) => return Err(refuse("not a regular file (a FIFO, socket or device)")),
            Err(_) => return Ok(None),
        }
        // Follows every link; a loop is ELOOP, a dangling link ENOENT. What
        // is checked and read is the resolved path.
        let resolved = fs::canonicalize(&full).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => refuse("a symlink to a file that does not exist"),
            _ => io_err(&full, e),
        })?;
        let target = fs::metadata(&resolved).map_err(|e| io_err(&resolved, e))?;
        if !target.is_file() {
            return Err(refuse("a symlink to something other than a regular file"));
        }
        if target.len() > limit {
            return Err(refuse(&format!("a symlink to a file larger than {limit} bytes")));
        }
        // Non-blocking, so a FIFO swapped in after the check cannot hang
        // the command; checked again on the open file.
        let mut opts = fs::OpenOptions::new();
        opts.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.custom_flags(libc::O_NONBLOCK);
        }
        let f = opts.open(&resolved).map_err(|e| read_err(&resolved, e))?;
        if !f.metadata().map_err(|e| io_err(&full, e))?.is_file() {
            return Err(refuse("a symlink to something other than a regular file"));
        }
        let mut data = Vec::new();
        f.take(limit + 1).read_to_end(&mut data).map_err(|e| io_err(&full, e))?;
        if data.len() as u64 > limit {
            return Err(refuse(&format!("a symlink to a file larger than {limit} bytes")));
        }
        Ok(Some((resolved.display().to_string(), data)))
    }

    fn read_range(&self, path: &VPath, offset: u64, len: usize) -> Result<Vec<u8>> {
        use std::io::{Read, Seek, SeekFrom};
        let full = self.full_path(path);
        let mut f = fs::File::open(&full).map_err(|e| read_err(&full, e))?;
        f.seek(SeekFrom::Start(offset)).map_err(|e| io_err(&full, e))?;
        let mut buf = vec![0; len];
        f.read_exact(&mut buf).map_err(|e| io_err(&full, e))?;
        Ok(buf)
    }

    fn write(&self, path: &VPath, data: &[u8]) -> Result<()> {
        if path.is_root() {
            return Err(VeilError::InvalidPath("cannot write to the root".into()));
        }
        self.refuse_symlinked_parent(path)?;
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

    fn write_unsynced(&self, path: &VPath, data: &[u8]) -> Result<()> {
        if path.is_root() {
            return Err(VeilError::InvalidPath("cannot write to the root".into()));
        }
        self.refuse_symlinked_parent(path)?;
        let full = self.full_path(path);
        let parent = full.parent().expect("non-root path has a parent");
        let mut created = Vec::new();
        create_dir_all_tracked(parent, &mut created).map_err(|e| io_err(parent, e))?;
        // Record the new directories before anything can fail, so the next
        // barrier syncs them even if this write does not complete.
        if !created.is_empty() {
            let mut u = self.unsynced.lock().unwrap_or_else(|e| e.into_inner());
            u.dirs.extend(created.iter().filter_map(|d| d.parent().map(Path::to_path_buf)));
        }
        let tmp = temp_path(parent, path);
        let res = (|| {
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)?
                .write_all(data)?;
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
        let parent = parent.to_path_buf();
        let mut u = self.unsynced.lock().unwrap_or_else(|e| e.into_inner());
        u.files.push(full);
        u.dirs.insert(parent);
        Ok(())
    }

    fn sync_barrier(&self) -> Result<()> {
        // Held until our batch is durable: a concurrent barrier waits for
        // it rather than returning early with nothing left to sync.
        let _serial = self.barrier.lock().unwrap_or_else(|e| e.into_inner());
        let batch = std::mem::take(&mut *self.unsynced.lock().unwrap_or_else(|e| e.into_inner()));
        if batch.files.is_empty() && batch.dirs.is_empty() {
            return Ok(());
        }
        let dirs: Vec<PathBuf> = batch.dirs.iter().cloned().collect();
        let res = for_each_parallel(&batch.files, SYNC_WORKERS, |f| match barrier_sync_file(f) {
            // Removed since (by gc, or by crash recovery as torn): the
            // directory sync below makes the removal durable instead.
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            r => r,
        })
        .and_then(|()| {
            for_each_parallel(&dirs, SYNC_WORKERS, |d| match barrier_sync_dir(d) {
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                r => r,
            })
        })
        .and_then(|()| flush_drive_cache(&batch.files, &dirs));
        if let Err(e) = res {
            // Keep the batch for the next barrier: its directories still need
            // syncing. A retried fsync of a file whose write-back failed
            // proves nothing (the pages were marked clean), so the caller
            // must rewrite or remove those files; the object store does
            // (`ObjectStore::sync_barrier`). Nothing that depends on them may
            // be written by the caller, which gets the error.
            let mut u = self.unsynced.lock().unwrap_or_else(|e| e.into_inner());
            u.files.extend(batch.files);
            u.dirs.extend(batch.dirs);
            return Err(io_err(&self.root, e));
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
        self.refuse_symlinked_parent(path)?;
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
            Err(e) if !is_missing(&e) => Err(io_err(&full, e)),
            _ => Ok(()),
        }
    }

    fn remove_dir_all(&self, path: &VPath) -> Result<()> {
        if path.is_root() {
            return Err(VeilError::InvalidPath("refusing to remove the backend root".into()));
        }
        let full = self.full_path(path);
        match fs::remove_dir_all(&full) {
            Err(e) if !is_missing(&e) => Err(io_err(&full, e)),
            _ => Ok(()),
        }
    }

    fn create_dir_all(&self, path: &VPath) -> Result<()> {
        let full = self.full_path(path);
        fs::create_dir_all(&full).map_err(|e| io_err(&full, e))
    }

    fn list_dir(&self, path: &VPath) -> Result<Vec<DirEntry>> {
        Ok(self.list_dir_full(path)?.entries)
    }

    fn list_dir_full(&self, path: &VPath) -> Result<DirListing> {
        let full = self.full_path(path);
        let mut out = DirListing::default();
        for entry in fs::read_dir(&full).map_err(|e| read_err(&full, e))? {
            let entry = entry.map_err(|e| io_err(&full, e))?;
            let name = match entry.file_name().into_string() {
                Ok(name) => name,
                // Not representable as a VPath: reported, never recorded.
                Err(raw) => {
                    out.unrepresentable.push(escape_name(&raw));
                    continue;
                }
            };
            let ft = entry.file_type().map_err(|e| io_err(&full, e))?;
            let kind = if ft.is_dir() {
                NodeKind::Dir
            } else if ft.is_file() {
                NodeKind::File
            } else {
                out.special.push(name); // symlinks, sockets, devices
                continue;
            };
            out.entries.push(DirEntry { name, kind });
        }
        out.entries.sort_by(|a, b| a.name.cmp(&b.name));
        out.special.sort();
        out.unrepresentable.sort();
        Ok(out)
    }

    fn special_at(&self, path: &VPath) -> Result<Option<&'static str>> {
        let full = self.full_path(path);
        match fs::symlink_metadata(&full) {
            Ok(m) if m.file_type().is_symlink() => Ok(Some("a symlink")),
            Ok(m) if m.is_file() || m.is_dir() => Ok(None),
            Ok(_) => Ok(Some("neither a file nor a directory")),
            Err(e) if is_missing(&e) => Ok(None),
            Err(e) => Err(io_err(&full, e)),
        }
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
            Err(e) if is_missing(&e) => Ok(None),
            Err(e) => Err(io_err(&full, e)),
        }
    }

    fn name_folding(&self) -> NameFolding {
        let mut cached = self.folding.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(f) = *cached {
            return f;
        }
        let (folding, definite) = probe_folding(&self.root);
        if definite {
            *cached = Some(folding);
        }
        folding
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

// ---- name folding -------------------------------------------------------------

/// Environment override for [`probe_folding`]: `exact`, `case`, `unicode`,
/// `macos` (both) or `auto`. Lets Linux users and CI check that a tree
/// checks out on a macOS volume, and works around a wrong probe.
pub const FOLDING_ENV: &str = "VEIL_FS_FOLDING";

/// Parse a [`FOLDING_ENV`] value; `None` for `auto` and unknown values.
pub fn parse_folding(v: &str) -> Option<NameFolding> {
    let (case_insensitive, unicode_insensitive) = match v.trim().to_ascii_lowercase().as_str() {
        "exact" | "none" | "sensitive" => (false, false),
        "case" => (true, false),
        "unicode" => (false, true),
        "macos" | "case,unicode" | "unicode,case" | "all" => (true, true),
        _ => return None,
    };
    Some(NameFolding {
        case_insensitive,
        unicode_insensitive,
    })
}

/// How the filesystem holding `root` compares names, and whether that
/// answer is definite (worth caching).
///
/// Case-insensitivity is measured: the first entry of `root` with an ASCII
/// letter is looked up again with its letters' case swapped, and the two
/// must be the very same file (device and inode). A repository root always
/// has `.veil`, so this works wherever it matters. Without a usable entry
/// the platform default is assumed (insensitive on macOS) and re-probed
/// next time.
///
/// Normalisation-insensitivity cannot be measured without creating files,
/// so it is the platform's: APFS (both variants) and HFS+ are
/// normalisation-insensitive, Linux filesystems are not (`vl doctor` probes
/// it for real).
pub fn probe_folding(root: &Path) -> (NameFolding, bool) {
    if let Some(f) = std::env::var(FOLDING_ENV).ok().as_deref().and_then(parse_folding) {
        return (f, true);
    }
    let (case_insensitive, definite) = match probe_case_insensitive(root) {
        Some(ci) => (ci, true),
        None => (cfg!(target_os = "macos"), false),
    };
    (
        NameFolding {
            case_insensitive,
            unicode_insensitive: cfg!(target_os = "macos"),
        },
        definite,
    )
}

fn probe_case_insensitive(root: &Path) -> Option<bool> {
    for entry in fs::read_dir(root).ok()?.flatten().take(256) {
        let Ok(name) = entry.file_name().into_string() else { continue };
        let swapped: String = name
            .chars()
            .map(|c| match c {
                'a'..='z' => c.to_ascii_uppercase(),
                'A'..='Z' => c.to_ascii_lowercase(),
                c => c,
            })
            .collect();
        if swapped == name {
            continue;
        }
        let Ok(original) = fs::symlink_metadata(root.join(&name)) else { continue };
        return Some(match fs::symlink_metadata(root.join(&swapped)) {
            Ok(alias) => same_file(&original, &alias),
            Err(_) => false,
        });
    }
    None
}

#[cfg(unix)]
fn same_file(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.dev() == b.dev() && a.ino() == b.ino()
}

#[cfg(not(unix))]
fn same_file(_a: &fs::Metadata, _b: &fs::Metadata) -> bool {
    true
}
