//! The FUSE side of `vl ws mount` (the `fuse` feature on Linux, `macfuse`
//! on macOS): translates kernel requests for [`MountFs`], nothing more.
//!
//! The mount is private to its owner: no `allow_other` (the kernel lets no
//! other user, not even root, into it), `default_permissions` (the kernel
//! checks the modes below), and modes `0700`/`0600` (`0700` for
//! executables), so a copy out of the mount is private too.

use std::{
    ffi::OsStr,
    path::Path,
    sync::Arc,
    time::{Duration, SystemTime},
};

#[cfg(target_os = "macos")]
use fuser_macos as fuser;

use fuser::{
    Config, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation, INodeNo, LockOwner, MountOption, OpenAccMode,
    OpenFlags, RenameFlags, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs,
    ReplyWrite, Request, SessionACL, TimeOrNow, WriteFlags,
};
use veil_core::vfs::NodeKind;

use super::fs::{Attr, MountFs};

/// How long the kernel may cache names and attributes. Changes made by
/// other commands (the workspace moving) show within about this long.
const TTL: Duration = Duration::from_secs(1);

pub struct Adapter {
    fs: Arc<MountFs>,
    uid: u32,
    gid: u32,
    /// For `statfs`: a directory on the file system holding the overlay
    /// (never the mountpoint, which would ask this very server).
    upper: std::path::PathBuf,
}

fn err(e: i32) -> Errno {
    Errno::from_i32(e)
}

impl Adapter {
    fn attr(&self, a: &Attr) -> FileAttr {
        let (kind, perm, nlink) = match a.kind {
            NodeKind::Dir => (FileType::Directory, 0o700, 2),
            NodeKind::File if a.executable => (FileType::RegularFile, 0o700, 1),
            NodeKind::File => (FileType::RegularFile, 0o600, 1),
        };
        FileAttr {
            ino: INodeNo(a.ino),
            size: a.size,
            blocks: a.size.div_ceil(512),
            atime: a.mtime,
            mtime: a.mtime,
            ctime: a.mtime,
            crtime: a.mtime,
            kind,
            perm,
            nlink,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        }
    }
}

/// Mount `fs` at `dir` (the handshake with the kernel included). Run the
/// returned session until the file system is unmounted.
pub fn mount(fs: Arc<MountFs>, dir: &Path, ws: &str, upper: &Path) -> std::io::Result<fuser::Session<Adapter>> {
    let upper = upper.to_path_buf();
    let adapter = Adapter {
        fs,
        // SAFETY: neither call has preconditions or can fail.
        uid: unsafe { libc::geteuid() },
        gid: unsafe { libc::getegid() },
        upper,
    };
    let mut config = Config::default();
    config.mount_options = vec![
        // Mount options are comma-separated: keep the name to characters
        // that cannot start another option (workspace names are already).
        MountOption::FSName(format!(
            "veil:{}",
            ws.chars().map(|c| if c.is_ascii_alphanumeric() || "-_.".contains(c) { c } else { '_' }).collect::<String>()
        )),
        MountOption::Subtype("veil".into()),
        MountOption::DefaultPermissions,
        MountOption::NoSuid,
        MountOption::NoDev,
        MountOption::RW,
    ];
    config.acl = SessionACL::Owner;
    fuser::Session::new(adapter, dir, &config)
}

impl Filesystem for Adapter {
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        match self.fs.lookup(parent.0, name) {
            Ok(a) => reply.entry(&TTL, &self.attr(&a), Generation(0)),
            Err(e) => reply.error(err(e)),
        }
    }

    fn forget(&self, _req: &Request, ino: INodeNo, nlookup: u64) {
        self.fs.forget(ino.0, nlookup);
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        match self.fs.getattr(ino.0) {
            Ok(a) => reply.attr(&TTL, &self.attr(&a)),
            Err(e) => reply.error(err(e)),
        }
    }

    fn setattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<fuser::BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        let mtime = mtime.map(|t| match t {
            TimeOrNow::SpecificTime(t) => t,
            TimeOrNow::Now => SystemTime::now(),
        });
        match self.fs.setattr(ino.0, size, mode, mtime) {
            Ok(a) => reply.attr(&TTL, &self.attr(&a)),
            Err(e) => reply.error(err(e)),
        }
    }

    fn mknod(&self, _req: &Request, _parent: INodeNo, _name: &OsStr, mode: u32, _umask: u32, _rdev: u32, reply: ReplyEntry) {
        // Only regular files (`mknod` of one is how some tools create).
        let _ = mode;
        reply.error(err(libc::EPERM));
    }

    fn mkdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, _mode: u32, _umask: u32, reply: ReplyEntry) {
        match self.fs.mkdir(parent.0, name) {
            Ok(a) => reply.entry(&TTL, &self.attr(&a), Generation(0)),
            Err(e) => reply.error(err(e)),
        }
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        match self.fs.unlink(parent.0, name) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(err(e)),
        }
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        match self.fs.rmdir(parent.0, name) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(err(e)),
        }
    }

    fn symlink(&self, _req: &Request, _parent: INodeNo, _link_name: &OsStr, _target: &Path, reply: ReplyEntry) {
        // Veil records files and directories only.
        reply.error(err(libc::EPERM));
    }

    fn rename(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        flags: RenameFlags,
        reply: ReplyEmpty,
    ) {
        if flags.intersects(RenameFlags::RENAME_EXCHANGE | RenameFlags::RENAME_WHITEOUT) {
            return reply.error(err(libc::EINVAL));
        }
        match self.fs.rename(parent.0, name, newparent.0, newname, flags.contains(RenameFlags::RENAME_NOREPLACE)) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(err(e)),
        }
    }

    fn link(&self, _req: &Request, _ino: INodeNo, _newparent: INodeNo, _newname: &OsStr, reply: ReplyEntry) {
        reply.error(err(libc::EPERM));
    }

    fn open(&self, _req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        let write = !matches!(flags.acc_mode(), OpenAccMode::O_RDONLY);
        let truncate = flags.0 & libc::O_TRUNC != 0;
        match self.fs.open(ino.0, write, truncate) {
            Ok(fh) => reply.opened(FileHandle(fh), FopenFlags::empty()),
            Err(e) => reply.error(err(e)),
        }
    }

    fn read(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        match self.fs.read(fh.0, offset, size) {
            Ok(d) => reply.data(&d),
            Err(e) => reply.error(err(e)),
        }
    }

    fn write(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        match self.fs.write(fh.0, offset, data) {
            Ok(n) => reply.written(n),
            Err(e) => reply.error(err(e)),
        }
    }

    fn flush(&self, _req: &Request, _ino: INodeNo, fh: FileHandle, _lock_owner: LockOwner, reply: ReplyEmpty) {
        match self.fs.flush(fh.0) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(err(e)),
        }
    }

    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        match self.fs.release(fh.0) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(err(e)),
        }
    }

    fn fsync(&self, _req: &Request, _ino: INodeNo, fh: FileHandle, _datasync: bool, reply: ReplyEmpty) {
        match self.fs.flush(fh.0) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(err(e)),
        }
    }

    fn opendir(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        match self.fs.getattr(ino.0) {
            Ok(a) if a.kind == NodeKind::Dir => reply.opened(FileHandle(0), FopenFlags::empty()),
            Ok(_) => reply.error(err(libc::ENOTDIR)),
            Err(e) => reply.error(err(e)),
        }
    }

    fn readdir(&self, _req: &Request, ino: INodeNo, _fh: FileHandle, offset: u64, mut reply: ReplyDirectory) {
        let entries = match self.fs.readdir(ino.0) {
            Ok(e) => e,
            Err(e) => return reply.error(err(e)),
        };
        let all = [(ino.0, ".".to_string(), NodeKind::Dir), (ino.0, "..".to_string(), NodeKind::Dir)]
            .into_iter()
            .chain(entries);
        for (i, (child, name, kind)) in all.enumerate().skip(offset as usize) {
            let kind = match kind {
                NodeKind::Dir => FileType::Directory,
                NodeKind::File => FileType::RegularFile,
            };
            if reply.add(INodeNo(child), (i + 1) as u64, kind, name) {
                break;
            }
        }
        reply.ok();
    }

    fn fsyncdir(&self, _req: &Request, _ino: INodeNo, _fh: FileHandle, _datasync: bool, reply: ReplyEmpty) {
        reply.ok();
    }

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        // The space of the file system the overlay is written to.
        let c = std::ffi::CString::new(self.upper.as_os_str().as_encoded_bytes()).unwrap_or_default();
        let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
        // SAFETY: `c` is a valid C string and `s` a writable statvfs.
        if unsafe { libc::statvfs(c.as_ptr(), &mut s) } == 0 {
            reply.statfs(
                s.f_blocks as u64,
                s.f_bfree as u64,
                s.f_bavail as u64,
                s.f_files as u64,
                s.f_ffree as u64,
                s.f_bsize as u32,
                255,
                s.f_frsize as u32,
            );
        } else {
            reply.statfs(0, 0, 0, 0, 0, 4096, 255, 4096);
        }
    }

    fn create(&self, _req: &Request, parent: INodeNo, name: &OsStr, mode: u32, _umask: u32, flags: i32, reply: ReplyCreate) {
        let exclusive = flags & libc::O_EXCL != 0;
        match self.fs.create(parent.0, name, mode & 0o111 != 0, exclusive) {
            Ok((a, fh)) => {
                if flags & libc::O_TRUNC != 0 && a.size > 0 {
                    if let Err(e) = self.fs.setattr(a.ino, Some(0), None, None) {
                        return reply.error(err(e));
                    }
                }
                let a = self.fs.getattr(a.ino).unwrap_or(a);
                reply.created(&TTL, &self.attr(&a), Generation(0), FileHandle(fh), FopenFlags::empty())
            }
            Err(e) => reply.error(err(e)),
        }
    }
}
