//! The backend of a `vl ws exec` sandbox ([`SandboxFs`]) and the host
//! primitives a persistent sandbox needs: copy-on-write file clones
//! ([`clone_file`]), an advisory lock ([`SandboxLock`]) and a removal that
//! copes with read-only directories ([`remove_tree`]).
//!
//! A sandbox is a [`DiskBackend`] with three differences:
//!
//! * **Writes are not fsynced.** A sandbox is a cache of a workspace, never
//!   the only copy of anything recorded. Whoever keeps one across runs
//!   records the boot it was written in and rebuilds it after a reboot
//!   (see [`crate::sandbox`]), so a power loss can never pass a torn file
//!   off as an edit.
//! * **Files can be cloned instead of written.** Given [`CloneSources`]
//!   (the project directory and its stat cache), checkout asks
//!   [`StorageBackend::clone_known`] before reading an object: a file of
//!   the project directory that the stat cache vouches holds exactly that
//!   content is cloned with a copy-on-write reflink (`FICLONE` on Linux
//!   btrfs and XFS, `fclonefileat` on macOS APFS). Nothing is read or
//!   written, and the two files share their blocks until either changes.
//!   Where the filesystem cannot clone (ext4, tmpfs, two filesystems) the
//!   first attempt says so and every file is written as usual.
//! * **It remembers what it wrote** ([`SandboxFs::take_written`]): the
//!   content id of each file and its stat right after the write, so the
//!   sandbox's stat cache can vouch for them without reading them back.

use std::{
    collections::HashMap,
    fs, io,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, AtomicU8, Ordering},
        Mutex,
    },
};

use super::{
    disk::{file_metadata, temp_name},
    DirEntry, DirListing, Metadata, NameFolding, StatClock, StorageBackend,
};
use crate::{error::Result, id::ObjectId, object::Object, statcache::StatCache, vpath::VPath};

/// Where clones may come from: the project directory and the stat cache
/// that says what its files hold.
#[derive(Debug, Clone)]
pub struct CloneSources {
    fs: DiskBackend,
    cache: StatCache,
    by_id: HashMap<ObjectId, Vec<VPath>>,
}

use super::DiskBackend;

impl CloneSources {
    /// Index `cache` (the stat cache of the working copy `fs`) by the
    /// content and sealed object ids it records.
    pub fn new(fs: DiskBackend, cache: StatCache) -> CloneSources {
        let mut by_id: HashMap<ObjectId, Vec<VPath>> = HashMap::new();
        for (path, rec) in cache.records() {
            by_id.entry(rec.content).or_default().push(path.clone());
            if let Some((_, sealed)) = &rec.sealed {
                by_id.entry(*sealed).or_default().push(path.clone());
            }
        }
        CloneSources { fs, cache, by_id }
    }

    /// Number of files that could serve as a source.
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }
}

/// What [`SandboxFs`] wrote at a path: the plaintext's blob id, the sealed
/// object it was cloned as (when cloned from a cloaked file), and its stat
/// after the last write or mode change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrittenFile {
    pub content: ObjectId,
    pub sealed: Option<(String, ObjectId)>,
    pub meta: Option<Metadata>,
}

const REFLINK_UNKNOWN: u8 = 0;
const REFLINK_WORKS: u8 = 1;
const REFLINK_UNSUPPORTED: u8 = 2;

/// A sandbox directory as a backend (see the module documentation).
#[derive(Debug)]
pub struct SandboxFs {
    disk: DiskBackend,
    sources: Option<CloneSources>,
    reflink: AtomicU8,
    log: Mutex<Option<HashMap<VPath, WrittenFile>>>,
    cloned: AtomicU64,
    cloned_bytes: AtomicU64,
    /// Named when an absolute symlink target lies inside one of them (see
    /// [`SandboxFs::with_forbidden_targets`]).
    forbidden: Vec<PathBuf>,
}

impl SandboxFs {
    /// Name `roots` (the project directory, `$VEIL_HOME`) in the message
    /// that refuses a link whose absolute target lies inside one of them.
    /// Every absolute target is refused whatever this says (BUG-709), as is
    /// every relative one that could resolve outside the sandbox
    /// ([`super::sandbox_link_check`]). Symlinks design, threat 7.
    pub fn with_forbidden_targets(mut self, roots: impl IntoIterator<Item = PathBuf>) -> SandboxFs {
        for r in roots {
            if let Ok(c) = fs::canonicalize(&r) {
                if c != r {
                    self.forbidden.push(c);
                }
            }
            self.forbidden.push(r);
        }
        self
    }

    /// May a tree's symlink `path -> target` be materialised here? Refused
    /// (`Policy`, which checkout reports as blocked) unless it provably
    /// resolves beneath the sandbox root, whatever other links the tree
    /// holds: see [`super::sandbox_link_check`]. That rules out absolute
    /// targets (BUG-709: `/proc/self/cwd/../../.env`) and chains of links
    /// that are each inside on their own (BUG-708).
    fn guard_link(&self, path: &VPath, target: &[u8]) -> Result<()> {
        let t = super::check_link_target(target)?;
        let refuse = |why: String| {
            crate::error::VeilError::Policy(format!("{path} -> {t}: {why}; the link is not materialised in this sandbox"))
        };
        match super::sandbox_link_check(path, t) {
            Ok(()) => Ok(()),
            Err(why) if t.starts_with('/') => {
                let abs = Path::new(t);
                match self.forbidden.iter().find(|r| abs.starts_with(r)) {
                    Some(root) => Err(refuse(format!("it points into {}, which the sandbox does not give its commands", root.display()))),
                    None => Err(refuse(why.to_string())),
                }
            }
            Err(why) => Err(refuse(why.to_string())),
        }
    }
    /// A sandbox rooted at `root`. With `sources`, checkout clones files
    /// from them where it can; with `log_writes`, every write is remembered
    /// for [`SandboxFs::take_written`].
    pub fn new(root: impl Into<PathBuf>, sources: Option<CloneSources>, log_writes: bool) -> SandboxFs {
        SandboxFs {
            disk: DiskBackend::new(root),
            sources,
            reflink: AtomicU8::new(REFLINK_UNKNOWN),
            log: Mutex::new(log_writes.then(HashMap::new)),
            cloned: AtomicU64::new(0),
            cloned_bytes: AtomicU64::new(0),
            forbidden: Vec::new(),
        }
    }

    pub fn root(&self) -> &Path {
        self.disk.root()
    }

    pub fn full_path(&self, p: &VPath) -> PathBuf {
        self.disk.full_path(p)
    }

    /// Files cloned instead of written so far, and their total size.
    pub fn cloned(&self) -> (u64, u64) {
        (self.cloned.load(Ordering::Relaxed), self.cloned_bytes.load(Ordering::Relaxed))
    }

    /// Did a clone work (`Some(true)`), fail because the filesystem cannot
    /// clone (`Some(false)`), or was none tried (`None`)?
    pub fn reflink_supported(&self) -> Option<bool> {
        match self.reflink.load(Ordering::Relaxed) {
            REFLINK_WORKS => Some(true),
            REFLINK_UNSUPPORTED => Some(false),
            _ => None,
        }
    }

    /// Everything written since the sandbox was created, and stop
    /// remembering further writes.
    pub fn take_written(&self) -> HashMap<VPath, WrittenFile> {
        self.log.lock().unwrap_or_else(|e| e.into_inner()).take().unwrap_or_default()
    }

    fn logged(&self, f: impl FnOnce(&mut HashMap<VPath, WrittenFile>)) {
        if let Some(log) = self.log.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
            f(log)
        }
    }

    fn try_clone(&self, path: &VPath, id: &ObjectId) -> Result<bool> {
        let Some(src) = &self.sources else { return Ok(false) };
        let Some(candidates) = src.by_id.get(id) else { return Ok(false) };
        if path.is_root() {
            return Ok(false);
        }
        #[cfg(not(unix))]
        {
            let _ = candidates;
            Ok(false)
        }
        #[cfg(unix)]
        self.try_clone_beneath(path, candidates, id)
    }

    /// [`SandboxFs::try_clone`]: the clone is made in the destination's
    /// directory, opened without following a symlink (see
    /// `vfs::beneath`), and renamed into place there.
    #[cfg(unix)]
    fn try_clone_beneath(&self, path: &VPath, candidates: &[VPath], id: &ObjectId) -> Result<bool> {
        let Some(src) = &self.sources else { return Ok(false) };
        let mut dir: Option<super::beneath::Dir> = None;
        for cand in candidates {
            let Some(meta) = src.fs.metadata(cand)? else { continue };
            let Some(rec) = src.cache.trusted(cand, &meta) else { continue };
            if rec.content != *id && rec.sealed.as_ref().map(|s| &s.1) != Some(id) {
                continue;
            }
            // The file on disk is a line-ending conversion of the recorded
            // version (`.veilattributes`), not its bytes.
            if rec.eol.as_ref().is_some_and(|f| f.recorded.is_some()) {
                continue;
            }
            let Ok(file) = open_no_follow(&src.fs.full_path(cand)) else { continue };
            if !unchanged(&file, &meta) {
                continue;
            }
            if dir.is_none() {
                match super::beneath::open_parent(self.disk.root(), path, true, false, &mut Vec::new()) {
                    Ok(d) => dir = Some(d),
                    Err(_) => return Ok(false),
                }
            }
            let d = dir.as_ref().expect("opened above");
            let tmp = temp_name(path);
            match clone_file_at(&file, d, &tmp) {
                Ok(true) => {}
                Ok(false) => {
                    self.reflink.store(REFLINK_UNSUPPORTED, Ordering::Relaxed);
                    return Ok(false);
                }
                Err(_) => return Ok(false),
            }
            // The source changed while it was cloned: the clone may hold
            // anything. Try the next copy, or write the object.
            if !unchanged(&file, &meta) || d.rename(&tmp, path.file_name()).is_err() {
                let _ = d.unlink(&tmp, false);
                continue;
            }
            self.reflink.store(REFLINK_WORKS, Ordering::Relaxed);
            self.cloned.fetch_add(1, Ordering::Relaxed);
            self.cloned_bytes.fetch_add(meta.len, Ordering::Relaxed);
            let after = self.disk.metadata(path)?;
            let written = WrittenFile {
                content: rec.content,
                sealed: rec.sealed.clone(),
                meta: after,
            };
            self.logged(|log| {
                log.insert(path.clone(), written);
            });
            return Ok(true);
        }
        Ok(false)
    }
}

impl StorageBackend for SandboxFs {
    fn kind(&self) -> &'static str {
        "disk"
    }

    fn read(&self, path: &VPath) -> Result<Vec<u8>> {
        self.disk.read(path)
    }

    fn read_through_link(&self, path: &VPath, limit: u64) -> Result<Option<(String, Vec<u8>)>> {
        self.disk.read_through_link(path, limit)
    }

    fn read_range(&self, path: &VPath, offset: u64, len: usize) -> Result<Vec<u8>> {
        self.disk.read_range(path, offset, len)
    }

    fn read_link(&self, path: &VPath) -> Result<Vec<u8>> {
        self.disk.read_link(path)
    }

    /// Never through a symlink, like every write (see `vfs::beneath`).
    fn write_link(&self, path: &VPath, target: &[u8]) -> Result<()> {
        self.guard_link(path, target)?;
        self.disk.write_link(path, target)?;
        self.logged(|log| {
            log.remove(path);
        });
        Ok(())
    }

    fn supports_links(&self) -> bool {
        self.disk.supports_links()
    }

    /// Atomic (temp file and rename) but not durable: see the module
    /// documentation.
    fn write(&self, path: &VPath, data: &[u8]) -> Result<()> {
        self.disk.write_unsynced(path, data)?;
        if self.log.lock().unwrap_or_else(|e| e.into_inner()).is_some() {
            let written = WrittenFile {
                content: Object::blob_id(data),
                sealed: None,
                meta: self.disk.metadata(path)?,
            };
            self.logged(|log| {
                log.insert(path.clone(), written);
            });
        }
        Ok(())
    }

    fn write_secret(&self, path: &VPath, data: &[u8], executable: bool) -> Result<()> {
        self.disk.write_secret_unsynced(path, data, executable)?;
        if self.log.lock().unwrap_or_else(|e| e.into_inner()).is_some() {
            let written = WrittenFile {
                content: Object::blob_id(data),
                sealed: None,
                meta: self.disk.metadata(path)?,
            };
            self.logged(|log| {
                log.insert(path.clone(), written);
            });
        }
        Ok(())
    }

    fn write_unsynced(&self, path: &VPath, data: &[u8]) -> Result<()> {
        self.write(path, data)
    }

    fn write_secret_unsynced(&self, path: &VPath, data: &[u8], executable: bool) -> Result<()> {
        self.write_secret(path, data, executable)
    }

    /// Nothing to do: sandbox writes are never made durable.
    fn sync_barrier(&self) -> Result<()> {
        Ok(())
    }

    fn create_new(&self, path: &VPath, data: &[u8]) -> Result<bool> {
        self.disk.create_new(path, data)
    }

    fn create_new_secret(&self, path: &VPath, data: &[u8]) -> Result<bool> {
        self.disk.create_new_secret(path, data)
    }

    fn remove_file(&self, path: &VPath) -> Result<()> {
        self.disk.remove_file(path)?;
        self.logged(|log| {
            log.remove(path);
        });
        Ok(())
    }

    fn remove_dir_all(&self, path: &VPath) -> Result<()> {
        self.disk.remove_dir_all(path)?;
        let prefix = path.child_prefix();
        self.logged(|log| log.retain(|p, _| p != path && !p.as_str().starts_with(&prefix)));
        Ok(())
    }

    fn create_dir_all(&self, path: &VPath) -> Result<()> {
        self.disk.create_dir_all(path)
    }

    fn list_dir(&self, path: &VPath) -> Result<Vec<DirEntry>> {
        self.disk.list_dir(path)
    }

    fn list_dir_full(&self, path: &VPath) -> Result<DirListing> {
        self.disk.list_dir_full(path)
    }

    fn metadata(&self, path: &VPath) -> Result<Option<Metadata>> {
        self.disk.metadata(path)
    }

    fn set_executable(&self, path: &VPath, executable: bool) -> Result<()> {
        self.disk.set_executable(path, executable)?;
        if self.log.lock().unwrap_or_else(|e| e.into_inner()).is_some() {
            let meta = self.disk.metadata(path)?;
            self.logged(|log| {
                if let Some(w) = log.get_mut(path) {
                    w.meta = meta;
                }
            });
        }
        Ok(())
    }

    fn clone_known(&self, path: &VPath, id: &ObjectId) -> Result<bool> {
        if self.reflink.load(Ordering::Relaxed) == REFLINK_UNSUPPORTED {
            return Ok(false);
        }
        self.try_clone(path, id)
    }

    fn clones(&self) -> bool {
        true
    }

    fn stat_clock(&self) -> Option<StatClock> {
        self.disk.stat_clock()
    }

    fn name_folding(&self) -> NameFolding {
        self.disk.name_folding()
    }

    fn special_at(&self, path: &VPath) -> Result<Option<&'static str>> {
        self.disk.special_at(path)
    }
}

/// Open a regular file for reading without following a symlink at `path`.
fn open_no_follow(path: &Path) -> io::Result<fs::File> {
    let mut opts = fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let f = opts.open(path)?;
    if !f.metadata()?.is_file() {
        return Err(io::Error::other("not a regular file"));
    }
    Ok(f)
}

/// Does the open file still stat as `meta` (size, mtime, ctime, inode)?
fn unchanged(f: &fs::File, meta: &Metadata) -> bool {
    match f.metadata() {
        Ok(m) => {
            let now = file_metadata(&m);
            now.len == meta.len && now.mtime == meta.mtime && now.ctime == meta.ctime && now.inode == meta.inode
        }
        Err(_) => false,
    }
}

/// Make `dst`, which must not exist, a copy-on-write clone of the open
/// regular file `src`: the two share their data blocks until either is
/// written. `Ok(false)` when the filesystem cannot clone (ext4, tmpfs,
/// `src` and `dst` on different filesystems); nothing is left at `dst`
/// then. The clone is created `0600`.
pub fn clone_file(src: &fs::File, dst: &Path) -> io::Result<bool> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::{fs::OpenOptionsExt, io::AsRawFd};
        let out = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(dst)?;
        // SAFETY: both descriptors stay open for the duration of the call;
        // FICLONE takes the source descriptor as its argument.
        let r = unsafe { libc::ioctl(out.as_raw_fd(), libc::FICLONE, src.as_raw_fd()) };
        if r == 0 {
            return Ok(true);
        }
        let e = io::Error::last_os_error();
        drop(out);
        let _ = fs::remove_file(dst);
        if cannot_clone(&e) {
            Ok(false)
        } else {
            Err(e)
        }
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::{ffi::OsStrExt, fs::PermissionsExt, io::AsRawFd};
        const CLONE_NOFOLLOW: u32 = 0x0001;
        const CLONE_NOOWNERCOPY: u32 = 0x0002;
        let c = std::ffi::CString::new(dst.as_os_str().as_bytes()).map_err(io::Error::other)?;
        // SAFETY: `src` is open and `c` is a NUL-terminated path for the
        // duration of the call.
        let r = unsafe { libc::fclonefileat(src.as_raw_fd(), libc::AT_FDCWD, c.as_ptr(), CLONE_NOFOLLOW | CLONE_NOOWNERCOPY) };
        if r == 0 {
            if let Err(e) = fs::set_permissions(dst, fs::Permissions::from_mode(0o600)) {
                let _ = fs::remove_file(dst);
                return Err(e);
            }
            return Ok(true);
        }
        let e = io::Error::last_os_error();
        if cannot_clone(&e) {
            Ok(false)
        } else {
            Err(e)
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (src, dst);
        Ok(false)
    }
}

/// [`clone_file`] to the new name `name` of directory `dir`, never through a
/// symlink.
#[cfg(unix)]
fn clone_file_at(src: &fs::File, dir: &super::beneath::Dir, name: &str) -> io::Result<bool> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let out = dir.open_file(name, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL, 0o600)?;
        // SAFETY: both descriptors stay open for the duration of the call.
        let r = unsafe { libc::ioctl(out.as_raw_fd(), libc::FICLONE, src.as_raw_fd()) };
        if r == 0 {
            return Ok(true);
        }
        let e = io::Error::last_os_error();
        drop(out);
        let _ = dir.unlink(name, false);
        if cannot_clone(&e) {
            Ok(false)
        } else {
            Err(e)
        }
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::{fs::PermissionsExt, io::AsRawFd};
        const CLONE_NOFOLLOW: u32 = 0x0001;
        const CLONE_NOOWNERCOPY: u32 = 0x0002;
        let c = std::ffi::CString::new(name).map_err(io::Error::other)?;
        // SAFETY: `src` and `dir` are open and `c` is a NUL-terminated name
        // for the duration of the call.
        let r = unsafe { libc::fclonefileat(src.as_raw_fd(), dir.raw(), c.as_ptr(), CLONE_NOFOLLOW | CLONE_NOOWNERCOPY) };
        if r == 0 {
            let res = dir
                .open_file(name, libc::O_RDONLY, 0)
                .and_then(|f| f.set_permissions(fs::Permissions::from_mode(0o600)));
            if let Err(e) = res {
                let _ = dir.unlink(name, false);
                return Err(e);
            }
            return Ok(true);
        }
        let e = io::Error::last_os_error();
        if cannot_clone(&e) {
            Ok(false)
        } else {
            Err(e)
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (src, dir, name);
        Ok(false)
    }
}

/// Errors that mean "this filesystem (or this pair of files) cannot be
/// cloned", as opposed to a failure worth reporting.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn cannot_clone(e: &io::Error) -> bool {
    // ENOTSUP and EOPNOTSUPP are one value on Linux, two on macOS.
    e.raw_os_error().is_some_and(|c| {
        [libc::EOPNOTSUPP, libc::ENOTSUP, libc::EXDEV, libc::EINVAL, libc::ENOTTY, libc::ENOSYS, libc::EPERM].contains(&c)
    })
}

/// Can files in directory `dir` be cloned (see [`clone_file`])? Creates and
/// removes two small files there.
pub fn reflink_supported(dir: &Path) -> io::Result<bool> {
    let tag = hex::encode(crate::crypto::random_bytes::<4>());
    let a = dir.join(format!(".veil-reflink-probe-{tag}-a"));
    let b = dir.join(format!(".veil-reflink-probe-{tag}-b"));
    fs::write(&a, b"probe")?;
    let res = fs::File::open(&a).and_then(|f| clone_file(&f, &b));
    let _ = fs::remove_file(&a);
    let _ = fs::remove_file(&b);
    res
}

/// An exclusive advisory lock (`flock`) on a lock file, released when
/// dropped or when the process dies, however it dies.
#[derive(Debug)]
pub struct SandboxLock {
    _file: fs::File,
}

impl SandboxLock {
    /// Take the lock at `path` if nobody holds it.
    pub fn try_acquire(path: &Path) -> io::Result<Option<SandboxLock>> {
        Self::take(path, false, || {})
    }

    /// Take the lock at `path`, waiting for its holder; `on_wait` is called
    /// once if the lock is busy.
    pub fn acquire(path: &Path, on_wait: impl FnOnce()) -> io::Result<SandboxLock> {
        Self::take(path, true, on_wait)?.ok_or_else(|| io::Error::other("lock not taken"))
    }

    fn take(path: &Path, wait: bool, on_wait: impl FnOnce()) -> io::Result<Option<SandboxLock>> {
        let mut on_wait = Some(on_wait);
        // The lock file can be removed by its holder (`vl ws rm`) while we
        // wait; a lock on the removed file locks nothing, so try again.
        for _ in 0..100 {
            let file = open_lock_file(path)?;
            if !flock(&file, false)? {
                if !wait {
                    return Ok(None);
                }
                if let Some(f) = on_wait.take() {
                    f();
                }
                flock(&file, true)?;
            }
            if same_file(&file, path) {
                return Ok(Some(SandboxLock { _file: file }));
            }
        }
        Err(io::Error::other(format!("{} keeps being replaced", path.display())))
    }
}

fn open_lock_file(path: &Path) -> io::Result<fs::File> {
    let mut opts = fs::OpenOptions::new();
    opts.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    opts.open(path)
}

/// `flock(LOCK_EX)`, blocking or not. `Ok(false)`: held by someone else.
fn flock(f: &fs::File, block: bool) -> io::Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let op = if block { libc::LOCK_EX } else { libc::LOCK_EX | libc::LOCK_NB };
        loop {
            // SAFETY: `f` is an open descriptor for the duration of the call.
            if unsafe { libc::flock(f.as_raw_fd(), op) } == 0 {
                return Ok(true);
            }
            let e = io::Error::last_os_error();
            match e.raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::EWOULDBLOCK) if !block => return Ok(false),
                _ => return Err(e),
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (f, block);
        Ok(true)
    }
}

/// Is the open file `f` still the one at `path`?
fn same_file(f: &fs::File, path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        match (f.metadata(), fs::symlink_metadata(path)) {
            (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
            _ => false,
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (f, path);
        true
    }
}

/// Remove `path` and everything below it, never following a symlink (a
/// symlink at `path` itself is unlinked). Directories the user cannot
/// write (a Go module cache makes its directories read-only) are made
/// writable first. Missing is not an error.
pub fn remove_tree(path: &Path) -> io::Result<()> {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    if !meta.is_dir() {
        return fs::remove_file(path);
    }
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            make_writable(path);
            fs::remove_dir_all(path).or_else(|e| if e.kind() == io::ErrorKind::NotFound { Ok(()) } else { Err(e) })
        }
        Err(e) => Err(e),
    }
}

#[cfg(unix)]
fn make_writable(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let Ok(m) = fs::symlink_metadata(dir) else { return };
    if !m.is_dir() {
        return;
    }
    let mode = m.permissions().mode();
    if mode & 0o700 != 0o700 {
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(mode | 0o700));
    }
    if let Ok(entries) = fs::read_dir(dir) {
        for e in entries.flatten() {
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                make_writable(&e.path());
            }
        }
    }
}

#[cfg(not(unix))]
fn make_writable(_dir: &Path) {}

/// Create `dir` (and missing parents) as directories only the user can
/// enter, and make sure `dir` is a real directory owned by the user with
/// mode `0700`: never a symlink to somewhere else.
pub fn private_dir(dir: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)?;
    let m = fs::symlink_metadata(dir)?;
    if !m.is_dir() {
        return Err(io::Error::other(format!("{} is not a directory", dir.display())));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // SAFETY: geteuid has no preconditions and cannot fail.
        if m.uid() != unsafe { libc::geteuid() } {
            return Err(io::Error::other(format!("{} belongs to another user", dir.display())));
        }
        if m.permissions().mode() & 0o777 != 0o700 {
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clones_share_content_or_report_unsupported() {
        // Under the target directory, i.e. the filesystem the repository
        // would be on (not a tmpfs /tmp).
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/tmp");
        fs::create_dir_all(&base).unwrap();
        let dir = tempfile::tempdir_in(&base).unwrap();
        if !reflink_supported(dir.path()).unwrap() {
            eprintln!("skipped: {} cannot clone files (no reflink support)", dir.path().display());
            return;
        }
        let a = dir.path().join("a");
        fs::write(&a, b"hello clone").unwrap();
        let b = dir.path().join("b");
        assert!(clone_file(&fs::File::open(&a).unwrap(), &b).unwrap());
        assert_eq!(fs::read(&b).unwrap(), b"hello clone");
        // Copy-on-write: changing one leaves the other alone.
        fs::write(&b, b"changed").unwrap();
        assert_eq!(fs::read(&a).unwrap(), b"hello clone");
        // The destination must not exist.
        assert!(clone_file(&fs::File::open(&a).unwrap(), &b).is_err());
    }

    #[test]
    fn unsupported_filesystems_leave_nothing_behind() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        fs::write(&a, b"x").unwrap();
        let b = dir.path().join("b");
        match clone_file(&fs::File::open(&a).unwrap(), &b).unwrap() {
            true => assert_eq!(fs::read(&b).unwrap(), b"x"),
            false => assert!(!b.exists(), "a failed clone left a file"),
        }
    }

    #[test]
    fn lock_is_exclusive_and_survives_removal_races() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("lock");
        let held = SandboxLock::try_acquire(&p).unwrap().expect("free");
        assert!(SandboxLock::try_acquire(&p).unwrap().is_none(), "second holder");
        drop(held);
        let again = SandboxLock::try_acquire(&p).unwrap();
        assert!(again.is_some());
        // The holder removes the lock file: a waiter must not believe it
        // holds a lock on the removed file.
        let (tx, rx) = std::sync::mpsc::channel();
        let p2 = p.clone();
        let t = std::thread::spawn(move || {
            let l = SandboxLock::acquire(&p2, || tx.send(()).unwrap()).unwrap();
            assert!(same_file(&l._file, &p2));
        });
        rx.recv().unwrap();
        fs::remove_file(&p).unwrap();
        drop(again);
        t.join().unwrap();
    }

    #[test]
    fn remove_tree_handles_read_only_dirs_and_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("keep"), b"k").unwrap();
        let t = dir.path().join("t");
        fs::create_dir_all(t.join("ro/sub")).unwrap();
        fs::write(t.join("ro/sub/f"), b"f").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::os::unix::fs::symlink(&outside, t.join("link")).unwrap();
            fs::set_permissions(t.join("ro/sub"), fs::Permissions::from_mode(0o555)).unwrap();
            fs::set_permissions(t.join("ro"), fs::Permissions::from_mode(0o555)).unwrap();
        }
        remove_tree(&t).unwrap();
        assert!(!t.exists());
        assert!(outside.join("keep").exists(), "followed a symlink");
        remove_tree(&t).unwrap();
    }
}
