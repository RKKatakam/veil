//! Path resolution that never follows a symlink: every component below a
//! trusted root directory is opened with `openat(…, O_NOFOLLOW |
//! O_DIRECTORY)` relative to the directory before it, so a directory that
//! is (or is swapped for) a symlink while a write is under way can never
//! redirect it. What a write creates, replaces or removes is always in the
//! very directory that was checked, never wherever a link points.
//!
//! This replaces the `lstat` loop that used to guard
//! [`DiskBackend`](super::DiskBackend) writes, which left a window between
//! the check and the write (symlinks design, threat 1). It is the same
//! walk on Linux and macOS (`openat2(RESOLVE_NO_SYMLINKS)` is Linux-only
//! and gives nothing the walk does not).
//!
//! Every function takes the root as a path (opened, and followed, as it
//! is: the root is the caller's) and a [`VPath`] below it, whose
//! components are plain names (never `.` or `..`).

use std::{
    ffi::{CString, OsStr},
    fs,
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::ffi::OsStrExt,
    },
    path::{Path, PathBuf},
};

use crate::vpath::VPath;

/// Why a walk stopped before the directory it wanted.
#[derive(Debug)]
pub(super) enum WalkError {
    /// A component (this prefix of the path) is a symlink.
    Link(String),
    /// A component is not a directory (a file, a socket…).
    NotDir(String),
    /// A component is missing (only when not creating).
    Missing,
    Io(io::Error),
}

impl From<io::Error> for WalkError {
    fn from(e: io::Error) -> Self {
        WalkError::Io(e)
    }
}

fn cstr(name: &str) -> io::Result<CString> {
    CString::new(name).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "a name holds a NUL byte"))
}

fn last_err() -> io::Error {
    io::Error::last_os_error()
}

/// Retry `f` while it fails with `EINTR`.
fn retry<T: PartialEq + Copy>(fail: T, mut f: impl FnMut() -> T) -> io::Result<T> {
    loop {
        let r = f();
        if r != fail {
            return Ok(r);
        }
        let e = last_err();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

/// An open directory.
#[derive(Debug)]
pub(super) struct Dir {
    fd: OwnedFd,
    /// Its path (for messages, durability bookkeeping and clones), as
    /// walked: the root joined with the components.
    pub path: PathBuf,
}

const DIR_FLAGS: libc::c_int = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;

impl Dir {
    /// Open the root (following it: it is the caller's).
    pub fn root(root: &Path) -> io::Result<Dir> {
        let c = CString::new(root.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "the root path holds a NUL byte"))?;
        // SAFETY: a valid C string; the fd is owned below.
        let fd = retry(-1, || unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) })?;
        Ok(Dir {
            // SAFETY: `open` returned a new descriptor we own.
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
            path: root.to_path_buf(),
        })
    }

    pub fn raw(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// `fstatat(name, AT_SYMLINK_NOFOLLOW)`: what `name` is, itself.
    pub fn stat(&self, name: &str) -> io::Result<libc::stat> {
        let c = cstr(name)?;
        // SAFETY: `st` is written by the kernel on success.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        retry(-1, || unsafe { libc::fstatat(self.raw(), c.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) })?;
        Ok(st)
    }

    /// Open subdirectory `name`, never through a symlink.
    pub fn open_dir(&self, name: &str) -> std::result::Result<Dir, WalkError> {
        let c = cstr(name)?;
        // SAFETY: a valid C string; the fd is owned below.
        match retry(-1, || unsafe { libc::openat(self.raw(), c.as_ptr(), DIR_FLAGS) }) {
            Ok(fd) => Ok(Dir {
                // SAFETY: `openat` returned a new descriptor we own.
                fd: unsafe { OwnedFd::from_raw_fd(fd) },
                path: self.path.join(name),
            }),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Err(WalkError::Missing),
            Err(e) => {
                // ELOOP (Linux, macOS), EMLINK (BSD) or ENOTDIR: say which.
                let prefix = self.path.join(name).display().to_string();
                match self.stat(name) {
                    Ok(st) if st.st_mode & libc::S_IFMT == libc::S_IFLNK => Err(WalkError::Link(prefix)),
                    Ok(st) if st.st_mode & libc::S_IFMT != libc::S_IFDIR => Err(WalkError::NotDir(prefix)),
                    _ => Err(WalkError::Io(e)),
                }
            }
        }
    }

    /// `mkdirat(name)`; an existing entry is not an error (the open after it
    /// says what it is).
    fn make_dir(&self, name: &str) -> io::Result<bool> {
        let c = cstr(name)?;
        // SAFETY: a valid C string.
        match retry(-1, || unsafe { libc::mkdirat(self.raw(), c.as_ptr(), 0o777) }) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// A `File` for this directory's descriptor (for `fsync`).
    pub fn sync(&self) -> io::Result<()> {
        let dup = self.fd.try_clone()?;
        match super::disk::full_sync(&fs::File::from(dup)) {
            // Some filesystems cannot fsync directories.
            Err(e) if matches!(e.kind(), io::ErrorKind::InvalidInput | io::ErrorKind::Unsupported) => Ok(()),
            r => r,
        }
    }

    /// Open regular file `name` with `flags` (`O_NOFOLLOW` added): a
    /// symlink there fails (`ELOOP`).
    pub fn open_file(&self, name: &str, flags: libc::c_int, mode: libc::mode_t) -> io::Result<fs::File> {
        let c = cstr(name)?;
        let flags = flags | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        // SAFETY: a valid C string; the fd is owned below.
        let fd = retry(-1, || unsafe { libc::openat(self.raw(), c.as_ptr(), flags, libc::c_uint::from(mode)) })?;
        // SAFETY: `openat` returned a new descriptor we own.
        Ok(fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) }))
    }

    pub fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        let (a, b) = (cstr(from)?, cstr(to)?);
        // SAFETY: valid C strings.
        retry(-1, || unsafe { libc::renameat(self.raw(), a.as_ptr(), self.raw(), b.as_ptr()) })?;
        Ok(())
    }

    /// `linkat(from, to)` within this directory, never following `from`.
    pub fn hard_link(&self, from: &str, to: &str) -> io::Result<()> {
        let (a, b) = (cstr(from)?, cstr(to)?);
        // SAFETY: valid C strings.
        retry(-1, || unsafe { libc::linkat(self.raw(), a.as_ptr(), self.raw(), b.as_ptr(), 0) })?;
        Ok(())
    }

    /// `unlinkat(name)` (a file or a symlink, never followed); `dir` for an
    /// empty directory.
    pub fn unlink(&self, name: &str, dir: bool) -> io::Result<()> {
        let c = cstr(name)?;
        let flags = if dir { libc::AT_REMOVEDIR } else { 0 };
        // SAFETY: a valid C string.
        retry(-1, || unsafe { libc::unlinkat(self.raw(), c.as_ptr(), flags) })?;
        Ok(())
    }

    pub fn symlink(&self, target: &[u8], name: &str) -> io::Result<()> {
        let t = CString::new(target).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "a symlink target holds a NUL byte"))?;
        let c = cstr(name)?;
        // SAFETY: valid C strings.
        retry(-1, || unsafe { libc::symlinkat(t.as_ptr(), self.raw(), c.as_ptr()) })?;
        Ok(())
    }

    /// The target of symlink `name` (`EINVAL` when it is not one).
    pub fn read_link(&self, name: &str) -> io::Result<Vec<u8>> {
        let c = cstr(name)?;
        let mut buf = vec![0u8; super::MAX_LINK_TARGET + 1];
        // SAFETY: `buf` is writable for its length.
        let n = retry(-1, || unsafe { libc::readlinkat(self.raw(), c.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) })?;
        let n = usize::try_from(n).map_err(|_| io::Error::other("readlinkat returned a negative length"))?;
        if n > super::MAX_LINK_TARGET {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "the symlink target is longer than PATH_MAX"));
        }
        buf.truncate(n);
        Ok(buf)
    }

    /// Names of this directory's entries (not `.` and `..`).
    pub fn names(&self) -> io::Result<Vec<Vec<u8>>> {
        // `fdopendir` takes ownership of the descriptor: give it a copy.
        let dup = self.fd.try_clone()?;
        let raw = std::os::fd::IntoRawFd::into_raw_fd(dup);
        // SAFETY: `raw` is a directory descriptor we own; `fdopendir` owns
        // it from here (closed by `closedir`).
        let d = unsafe { libc::fdopendir(raw) };
        if d.is_null() {
            let e = last_err();
            // SAFETY: still ours, `fdopendir` failed.
            unsafe { libc::close(raw) };
            return Err(e);
        }
        let mut out = Vec::new();
        let res = loop {
            // SAFETY: `d` is a valid stream; errno is reset to tell the end
            // from an error.
            unsafe { *errno() = 0 };
            let ent = unsafe { libc::readdir(d) };
            if ent.is_null() {
                let e = last_err();
                break if e.raw_os_error().unwrap_or(0) == 0 { Ok(()) } else { Err(e) };
            }
            // SAFETY: the kernel NUL-terminates `d_name`.
            let name = unsafe { std::ffi::CStr::from_ptr((*ent).d_name.as_ptr()) }.to_bytes();
            if name != b"." && name != b".." {
                out.push(name.to_vec());
            }
        };
        // SAFETY: `d` came from `fdopendir`.
        unsafe { libc::closedir(d) };
        res.map(|()| out)
    }
}

#[cfg(target_os = "linux")]
fn errno() -> *mut libc::c_int {
    // SAFETY: always valid for the calling thread.
    unsafe { libc::__errno_location() }
}

#[cfg(target_os = "macos")]
fn errno() -> *mut libc::c_int {
    // SAFETY: always valid for the calling thread.
    unsafe { libc::__error() }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn errno() -> *mut libc::c_int {
    // SAFETY: always valid for the calling thread.
    unsafe { libc::__errno_location() }
}

/// The directory holding `path` (its parent), opened component by
/// component from `root` without following a symlink. With `create`,
/// missing directories are made (their paths appended to `created`,
/// shallowest first, each made durable by the caller syncing its parent
/// when `durable`).
pub(super) fn open_parent(root: &Path, path: &VPath, create: bool, durable: bool, created: &mut Vec<PathBuf>) -> std::result::Result<Dir, WalkError> {
    let parts: Vec<&str> = path.components().collect();
    let dirs = &parts[..parts.len().saturating_sub(1)];
    open_dirs(root, dirs, create, durable, created)
}

/// The directory `path` itself (see [`open_parent`]).
pub(super) fn open_path(root: &Path, path: &VPath, create: bool, durable: bool, created: &mut Vec<PathBuf>) -> std::result::Result<Dir, WalkError> {
    let parts: Vec<&str> = path.components().collect();
    open_dirs(root, &parts, create, durable, created)
}

fn open_dirs(root: &Path, dirs: &[&str], create: bool, durable: bool, created: &mut Vec<PathBuf>) -> std::result::Result<Dir, WalkError> {
    let mut cur = match Dir::root(root) {
        Ok(d) => d,
        Err(e) if create && e.kind() == io::ErrorKind::NotFound => {
            // The root itself is the caller's: created as a plain path.
            super::disk::create_dir_all_durable(root)?;
            Dir::root(root)?
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(WalkError::Missing),
        Err(e) => return Err(WalkError::Io(e)),
    };
    for name in dirs {
        cur = match cur.open_dir(name) {
            Ok(d) => d,
            Err(WalkError::Missing) if create => {
                if cur.make_dir(name)? {
                    created.push(cur.path.join(name));
                    if durable {
                        cur.sync()?;
                    }
                }
                cur.open_dir(name)?
            }
            Err(e) => return Err(e),
        };
    }
    Ok(cur)
}

/// Remove `name` in `dir` and everything below it, never following a
/// symlink: a link is unlinked, a directory emptied through descriptors
/// opened `O_NOFOLLOW`. Missing is not an error.
pub(super) fn remove_tree_at(dir: &Dir, name: &str) -> io::Result<()> {
    match dir.unlink(name, false) {
        Ok(()) => return Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        // EISDIR (Linux) or EPERM (macOS): a directory.
        Err(_) => {}
    }
    let sub = match dir.open_dir(name) {
        Ok(d) => d,
        Err(WalkError::Missing) => return Ok(()),
        Err(WalkError::Link(_) | WalkError::NotDir(_)) => return dir.unlink(name, false),
        Err(WalkError::Io(e)) => return Err(e),
    };
    for child in sub.names()? {
        let child = OsStr::from_bytes(&child);
        let Some(child) = child.to_str() else {
            // A name that is not UTF-8: removed by bytes.
            remove_raw(&sub, child.as_bytes())?;
            continue;
        };
        remove_tree_at(&sub, child)?;
    }
    match dir.unlink(name, true) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        r => r,
    }
}

/// [`remove_tree_at`] for a name that is not UTF-8.
fn remove_raw(dir: &Dir, name: &[u8]) -> io::Result<()> {
    let c = CString::new(name).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "a name holds a NUL byte"))?;
    // SAFETY: a valid C string.
    if unsafe { libc::unlinkat(dir.raw(), c.as_ptr(), 0) } == 0 {
        return Ok(());
    }
    // SAFETY: a valid C string; the fd is owned below.
    let fd = unsafe { libc::openat(dir.raw(), c.as_ptr(), DIR_FLAGS) };
    if fd < 0 {
        return Err(last_err());
    }
    let sub = Dir {
        // SAFETY: `openat` returned a new descriptor we own.
        fd: unsafe { OwnedFd::from_raw_fd(fd) },
        path: dir.path.join(OsStr::from_bytes(name)),
    };
    for child in sub.names()? {
        remove_raw(&sub, &child)?;
    }
    // SAFETY: a valid C string.
    if unsafe { libc::unlinkat(dir.raw(), c.as_ptr(), libc::AT_REMOVEDIR) } == 0 {
        Ok(())
    } else {
        Err(last_err())
    }
}

/// Read regular file `name` of `dir` (never a symlink, never a FIFO's
/// blocking open).
pub(super) fn read_file(dir: &Dir, name: &str) -> io::Result<Vec<u8>> {
    let mut f = dir.open_file(name, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
    if !f.metadata()?.is_file() {
        return Err(io::Error::other("not a regular file"));
    }
    let mut data = Vec::new();
    f.read_to_end(&mut data)?;
    Ok(data)
}

/// Write `data` to a new temp file `tmp` of `dir`, flushed if `durable`.
/// When `secret` is `Some(executable)`, `tmp` is created owner-only (`0600`
/// or `0700`) in `openat` and never copies permissions from `name`;
/// otherwise `tmp` is created `0666` (`& ~umask`) with the permissions of
/// the regular file `name` it will replace (if any).
pub(super) fn write_temp(
    dir: &Dir,
    tmp: &str,
    name: &str,
    data: &[u8],
    secret: Option<bool>,
    durable: bool,
) -> io::Result<()> {
    let create_mode = match secret {
        Some(exec) => super::secret_file_mode(exec) as libc::mode_t,
        None => 0o666,
    };
    let mut f = dir.open_file(tmp, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL, create_mode)?;
    f.write_all(data)?;
    if secret.is_none() {
        if let Ok(st) = dir.stat(name) {
            if st.st_mode & libc::S_IFMT == libc::S_IFREG {
                use std::os::unix::fs::PermissionsExt;
                // `mode_t` is `u16` on macOS.
                #[allow(clippy::useless_conversion)]
                let mode = u32::from(st.st_mode) & 0o7777;
                f.set_permissions(fs::Permissions::from_mode(mode))?;
            }
        }
    }
    if durable {
        super::disk::full_sync(&f)?;
    }
    Ok(())
}
