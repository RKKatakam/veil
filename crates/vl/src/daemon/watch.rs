//! The daemon's working-copy file watcher (milestone S7, `docs/HUB.md` §13.33;
//! design: `docs/design/server/phase-2-thin-clients.md` §4.7).
//!
//! * **Advisory, never authoritative.** The watcher only narrows which
//!   directories [`veil_core::builder::build_tree_watched`] opens and lists.
//!   When the watcher cannot vouch (first command on a working copy, daemon
//!   restarted, token mismatch, kernel queue overflow, `.veilpolicy` or
//!   `.veilattributes` edited, or a directory/dirty-path bound exceeded), it
//!   answers `known: false` and `vl` falls back to a full scan.
//! * **Confined to the working copy.** Every directory is opened with
//!   `openat(..., O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)` starting
//!   from the working copy's root, checked with `fstat` to stay on the root's
//!   filesystem (`st_dev == root_dev`) and belong to the user, and watched
//!   through `/proc/self/fd/{fd}` with `IN_DONT_FOLLOW | IN_ONLYDIR`. The
//!   watcher never follows symlinks, never crosses a mount boundary, and
//!   never descends into `.veil` or nested Veil repositories.
//! * **Bounded.** A daemon watches at most [`MAX_WATCHED_WCS`] working copies;
//!   each working copy watches at most `max_dirs` directories (default
//!   [`DEFAULT_MAX_DIRS`]) and holds at most `max_dirty_paths` dirty paths
//!   (default [`DEFAULT_MAX_DIRTY_PATHS`]) and [`MAX_DIRTY_BYTES`] of path
//!   strings. Past a bound, the working copy is marked overflowed, its
//!   watches are dropped, and `vl` warns and falls back to scanning.

use std::{
    collections::HashMap,
    ffi::CString,
    io,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::ffi::OsStrExt,
    },
    path::{Path, PathBuf},
    sync::Mutex,
};

use serde::{Deserialize, Serialize};
use veil_core::{
    attributes::ATTRIBUTES_FILE,
    object::is_reserved_name,
    policy::POLICY_FILE,
    vfs::is_temp_name,
    VPath,
};

/// Most working copies one daemon watches at once.
pub const MAX_WATCHED_WCS: usize = 64;
/// Default bound on watched directories per working copy.
pub const DEFAULT_MAX_DIRS: usize = 65_536;
/// Default bound on dirty paths tracked per working copy between snapshots.
pub const DEFAULT_MAX_DIRTY_PATHS: usize = 16_384;
/// Bound on total bytes of dirty path strings per working copy (1 MiB).
pub const MAX_DIRTY_BYTES: usize = 1 << 20;

/// What the daemon answers to `Request::Watch`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WatchReply {
    /// `true` when `dirty_dirs` and `dirty_subtrees` name every directory
    /// where a change may have happened since the caller's token.
    pub known: bool,
    /// Fresh token representing the daemon's current event sequence for this
    /// working copy (`None` when the working copy could not be watched or hit
    /// a bound).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    /// Directories whose direct leaf entries may have changed since the
    /// caller's token.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dirty_dirs: Vec<VPath>,
    /// Directories that must be walked recursively with all their
    /// descendants (a subdirectory was created, renamed or removed).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dirty_subtrees: Vec<VPath>,
    /// When a bound was exceeded, a human-readable explanation so `vl` can
    /// warn once and fall back to scanning.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notice: Option<String>,
}

/// Summary of one watched working copy for `vl daemon status`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WatchedSummary {
    pub root: PathBuf,
    pub dirs: usize,
    pub dirty: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overflow: Option<String>,
}

/// Per-working-copy bounds (configurable via `.veil/local/config.toml` or
/// environment variables passed by `vl`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WatchLimits {
    pub max_dirs: usize,
    pub max_dirty_paths: usize,
}

impl Default for WatchLimits {
    fn default() -> Self {
        Self {
            max_dirs: DEFAULT_MAX_DIRS,
            max_dirty_paths: DEFAULT_MAX_DIRTY_PATHS,
        }
    }
}

struct WatchedWc {
    root: PathBuf,
    root_dev: u64,
    root_ino: u64,
    id: u64,
    seq: u64,
    /// Events at or before `min_valid_seq` have already been pruned; any
    /// token older than `min_valid_seq` cannot be answered incrementally.
    min_valid_seq: u64,
    /// Sequence at which `.veilpolicy` or `.veilattributes` changed; any
    /// token older than `rescan_seq` must do a full scan.
    rescan_seq: u64,
    /// `wd -> VPath` for this working copy.
    wds: HashMap<i32, VPath>,
    /// `VPath -> wd` for this working copy.
    paths: HashMap<VPath, i32>,
    /// Directories where a direct leaf entry changed (`VPath -> latest seq`).
    dirty_dirs: HashMap<VPath, u64>,
    /// Directories whose subtree must be walked recursively (`VPath -> latest seq`).
    dirty_subtrees: HashMap<VPath, u64>,
    /// Approximate bytes held in `dirty_dirs` and `dirty_subtrees`.
    dirty_bytes: usize,
    limits: WatchLimits,
    /// Set when a bound was exceeded (`max_dirs`, `max_dirty_paths`, or
    /// `MAX_DIRTY_BYTES`).
    overflow: Option<String>,
    /// Whether the caller has already been told about `overflow`.
    overflow_reported: bool,
    last_used: i64,
}

pub struct Watcher {
    inner: Mutex<WatcherInner>,
}

struct WatcherInner {
    #[cfg(target_os = "linux")]
    inotify: Option<OwnedFd>,
    next_id: u64,
    wcs: HashMap<PathBuf, WatchedWc>,
    wd_to_root: HashMap<i32, PathBuf>,
}

impl Default for Watcher {
    fn default() -> Self {
        Self::new()
    }
}

impl Watcher {
    pub fn new() -> Self {
        Watcher {
            inner: Mutex::new(WatcherInner {
                #[cfg(target_os = "linux")]
                inotify: None,
                next_id: {
                    let t = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(1, |d| d.as_nanos() as u64);
                    t ^ ((std::process::id() as u64) << 32)
                },
                wcs: HashMap::new(),
                wd_to_root: HashMap::new(),
            }),
        }
    }

    /// Answer a `Request::Watch` for `root` with optional `token` and bounds.
    pub fn query(
        &self,
        root: &Path,
        token: Option<&str>,
        max_dirs: Option<usize>,
        max_dirty_paths: Option<usize>,
    ) -> WatchReply {
        let limits = WatchLimits {
            max_dirs: max_dirs.unwrap_or(DEFAULT_MAX_DIRS).max(1),
            max_dirty_paths: max_dirty_paths.unwrap_or(DEFAULT_MAX_DIRTY_PATHS).max(1),
        };
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.query(root, token, limits)
    }

    /// Drain pending kernel events and drop watched working copies whose
    /// `.veil` directory is gone. Called periodically by the daemon's
    /// background loop.
    pub fn tick(&self) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.drain_events();
        g.reap_gone();
    }

    /// Summaries of watched working copies for `vl daemon status`.
    pub fn status(&self) -> Vec<WatchedSummary> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.drain_events();
        g.reap_gone();
        let mut out: Vec<WatchedSummary> = g
            .wcs
            .values()
            .map(|wc| WatchedSummary {
                root: wc.root.clone(),
                dirs: wc.paths.len(),
                dirty: wc.dirty_dirs.len() + wc.dirty_subtrees.len(),
                overflow: wc.overflow.clone(),
            })
            .collect();
        out.sort_by(|a, b| a.root.cmp(&b.root));
        out
    }
}

#[cfg(target_os = "linux")]
const WATCH_MASK: u32 = libc::IN_CREATE
    | libc::IN_DELETE
    | libc::IN_DELETE_SELF
    | libc::IN_MODIFY
    | libc::IN_CLOSE_WRITE
    | libc::IN_ATTRIB
    | libc::IN_MOVED_FROM
    | libc::IN_MOVED_TO
    | libc::IN_MOVE_SELF
    | libc::IN_ONLYDIR
    | libc::IN_DONT_FOLLOW;

impl WatcherInner {
    fn query(&mut self, root: &Path, token: Option<&str>, limits: WatchLimits) -> WatchReply {
        if !root.is_absolute() {
            return WatchReply::default();
        }
        let Ok((root_fd, root_st)) = open_verified_root(root) else {
            self.remove_wc(root);
            return WatchReply::default();
        };
        self.drain_events();

        // Check if an existing watch matches the same underlying root directory.
        let needs_reset = match self.wcs.get(root) {
            Some(wc) => {
                wc.root_dev != root_st.st_dev as u64
                    || wc.root_ino != root_st.st_ino
                    || wc.limits != limits
            }
            None => false,
        };
        if needs_reset {
            self.remove_wc(root);
        }

        if !self.wcs.contains_key(root) {
            if self.wcs.len() >= MAX_WATCHED_WCS {
                // Evict the least recently used working copy if at capacity.
                if let Some(oldest) = self
                    .wcs
                    .values()
                    .min_by_key(|w| w.last_used)
                    .map(|w| w.root.clone())
                {
                    self.remove_wc(&oldest);
                }
            }
            let Some(inotify_fd) = self.ensure_inotify() else {
                return WatchReply::default();
            };
            self.next_id = self.next_id.wrapping_add(1);
            let mut wc = WatchedWc {
                root: root.to_path_buf(),
                root_dev: root_st.st_dev as u64,
                root_ino: root_st.st_ino,
                id: self.next_id,
                seq: 1,
                min_valid_seq: 1,
                rescan_seq: 1,
                wds: HashMap::new(),
                paths: HashMap::new(),
                dirty_dirs: HashMap::new(),
                dirty_subtrees: HashMap::new(),
                dirty_bytes: 0,
                limits,
                overflow: None,
                overflow_reported: false,
                last_used: veil_core::now_millis(),
            };
            let mut new_wds = Vec::new();
            if let Err(notice) = watch_subtree(
                inotify_fd,
                root_fd,
                &VPath::root(),
                wc.root_dev,
                &mut wc,
                &mut new_wds,
                false,
            ) {
                for wd in new_wds {
                    rm_watch(inotify_fd, wd);
                }
                wc.wds.clear();
                wc.paths.clear();
                wc.overflow = Some(notice.clone());
                wc.overflow_reported = true;
                self.wcs.insert(root.to_path_buf(), wc);
                return WatchReply {
                    known: false,
                    token: None,
                    dirty_dirs: Vec::new(),
                    dirty_subtrees: Vec::new(),
                    notice: Some(notice),
                };
            }
            for wd in new_wds {
                self.wd_to_root.insert(wd, root.to_path_buf());
            }
            let tok = format!("{:x}:{}", wc.id, wc.seq);
            self.wcs.insert(root.to_path_buf(), wc);
            // Drain any events that arrived while the initial tree walk was
            // registering watches so they get sequence numbers > wc.seq.
            self.drain_events();
            return WatchReply {
                known: false,
                token: Some(tok),
                dirty_dirs: Vec::new(),
                dirty_subtrees: Vec::new(),
                notice: None,
            };
        }

        // Existing watched working copy: drain once more after any watch additions.
        let wc = self.wcs.get_mut(root).expect("checked");
        wc.last_used = veil_core::now_millis();
        if let Some(why) = wc.overflow.clone() {
            let notice = (!wc.overflow_reported).then(|| {
                wc.overflow_reported = true;
                why
            });
            return WatchReply {
                known: false,
                token: None,
                dirty_dirs: Vec::new(),
                dirty_subtrees: Vec::new(),
                notice,
            };
        }

        let new_tok = format!("{:x}:{}", wc.id, wc.seq);
        let Some((tok_id, tok_seq)) = token.and_then(parse_token) else {
            return WatchReply {
                known: false,
                token: Some(new_tok),
                dirty_dirs: Vec::new(),
                dirty_subtrees: Vec::new(),
                notice: None,
            };
        };

        if tok_id != wc.id || tok_seq < wc.min_valid_seq || tok_seq < wc.rescan_seq || tok_seq > wc.seq {
            return WatchReply {
                known: false,
                token: Some(new_tok),
                dirty_dirs: Vec::new(),
                dirty_subtrees: Vec::new(),
                notice: None,
            };
        }

        // Prune changes at or before `tok_seq`: the caller has now durability-recorded
        // `tok_seq` in `checkout.json`, so no future call needs changes <= `tok_seq`.
        wc.prune_up_to(tok_seq);

        let mut dirty_dirs: Vec<VPath> = wc
            .dirty_dirs
            .iter()
            .filter(|(_, &s)| s > tok_seq)
            .map(|(p, _)| p.clone())
            .collect();
        let mut dirty_subtrees: Vec<VPath> = wc
            .dirty_subtrees
            .iter()
            .filter(|(_, &s)| s > tok_seq)
            .map(|(p, _)| p.clone())
            .collect();
        dirty_dirs.sort();
        dirty_subtrees.sort();

        WatchReply {
            known: true,
            token: Some(new_tok),
            dirty_dirs,
            dirty_subtrees,
            notice: None,
        }
    }

    #[cfg(target_os = "linux")]
    fn ensure_inotify(&mut self) -> Option<RawFd> {
        if self.inotify.is_none() {
            // SAFETY: `inotify_init1` has no preconditions.
            let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
            if fd < 0 {
                return None;
            }
            // SAFETY: `inotify_init1` returned a new descriptor we own.
            self.inotify = Some(unsafe { OwnedFd::from_raw_fd(fd) });
        }
        self.inotify.as_ref().map(AsRawFd::as_raw_fd)
    }

    #[cfg(not(target_os = "linux"))]
    fn ensure_inotify(&mut self) -> Option<RawFd> {
        None
    }

    #[cfg(target_os = "linux")]
    fn drain_events(&mut self) {
        let Some(inotify_fd) = self.inotify.as_ref().map(AsRawFd::as_raw_fd) else {
            return;
        };
        let mut buf = [0u64; 1024]; // 8 KiB aligned to u64
        let byte_buf: &mut [u8] =
            // SAFETY: `[u64; 1024]` is valid as `[u8; 8192]`.
            unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr().cast::<u8>(), std::mem::size_of_val(&buf)) };
        let mut overflowed_all = false;
        let mut new_subdirs: Vec<(PathBuf, VPath)> = Vec::new();

        loop {
            // SAFETY: `inotify_fd` is valid and `byte_buf` is writable.
            let n = unsafe { libc::read(inotify_fd, byte_buf.as_mut_ptr().cast(), byte_buf.len()) };
            if n <= 0 {
                break;
            }
            let n = n as usize;
            let mut offset = 0usize;
            while offset + std::mem::size_of::<libc::inotify_event>() <= n {
                // SAFETY: `byte_buf` is aligned to `u64` and `inotify_event` has alignment 4;
                // `read_unaligned` avoids any alignment assumptions across packed records.
                let ev = unsafe {
                    std::ptr::read_unaligned(byte_buf[offset..].as_ptr().cast::<libc::inotify_event>())
                };
                let name_start = offset + std::mem::size_of::<libc::inotify_event>();
                let name_end = (name_start + ev.len as usize).min(n);
                let raw_name = &byte_buf[name_start..name_end];
                let name_bytes = raw_name.split(|&b| b == 0).next().unwrap_or(&[]);
                offset = name_end;

                if ev.mask & libc::IN_Q_OVERFLOW != 0 {
                    overflowed_all = true;
                    break;
                }
                if ev.mask & libc::IN_UNMOUNT != 0 {
                    if let Some(root) = self.wd_to_root.remove(&ev.wd) {
                        self.reset_wc(&root);
                    }
                    continue;
                }
                let Some(root) = self.wd_to_root.get(&ev.wd).cloned() else {
                    continue;
                };
                if ev.mask & libc::IN_IGNORED != 0 {
                    self.wd_to_root.remove(&ev.wd);
                    if let Some(wc) = self.wcs.get_mut(&root) {
                        if let Some(dir) = wc.wds.remove(&ev.wd) {
                            if wc.paths.get(&dir) == Some(&ev.wd) {
                                wc.paths.remove(&dir);
                            }
                            if dir.is_root() {
                                wc.rescan_seq = wc.bump_seq();
                            } else {
                                let seq = wc.bump_seq();
                                wc.mark_dirty_subtree(dir.parent().unwrap_or_else(VPath::root), seq);
                            }
                        }
                    }
                    continue;
                }

                // Ignore temporary atomic-write staging files if they are pure temp debris,
                // EXCEPT that `.checkout.json.vltmp*` is inside `.veil` (which isn't watched
                // anyway). Wait: if a user creates a file via atomic rename, the rename onto
                // the real name fires `IN_MOVED_TO` for the real name! Still, only skip
                // reserved `.veil` so we never miss anything in the working copy.
                if name_bytes == b".veil" {
                    continue;
                }
                let name_str = std::str::from_utf8(name_bytes).ok();
                if name_str.is_some_and(|s| is_reserved_name(s) || is_temp_name(s)) {
                    continue;
                }

                let Some(wc) = self.wcs.get_mut(&root) else {
                    continue;
                };
                if wc.overflow.is_some() {
                    continue;
                }
                let Some(dir) = wc.wds.get(&ev.wd).cloned() else {
                    continue;
                };
                let seq = wc.bump_seq();

                // Any change to `.veilpolicy` or `.veilattributes` (at any depth)
                // forces a full scan, since classification or line-ending rules
                // across the tree may have changed.
                if name_str.is_some_and(|s| s == POLICY_FILE || s == ATTRIBUTES_FILE) {
                    wc.rescan_seq = seq;
                    continue;
                }

                let is_dir = ev.mask & libc::IN_ISDIR != 0;
                let self_moved_or_deleted = ev.mask & (libc::IN_DELETE_SELF | libc::IN_MOVE_SELF) != 0;

                if self_moved_or_deleted {
                    if dir.is_root() {
                        wc.rescan_seq = seq;
                    } else {
                        wc.mark_dirty_subtree(dir.parent().unwrap_or_else(VPath::root), seq);
                    }
                    continue;
                }

                if is_dir {
                    wc.mark_dirty_subtree(dir.clone(), seq);
                    if ev.mask & (libc::IN_CREATE | libc::IN_MOVED_TO) != 0 {
                        if let Some(s) = name_str.filter(|s| valid_component(s)) {
                            let sub = dir.join(s);
                            wc.mark_dirty_subtree(sub.clone(), seq);
                            new_subdirs.push((root.clone(), sub));
                        }
                    }
                } else {
                    wc.mark_dirty_dir(dir, seq);
                }
            }
            if overflowed_all {
                break;
            }
        }

        if overflowed_all {
            let roots: Vec<PathBuf> = self.wcs.keys().cloned().collect();
            for r in roots {
                self.reset_wc(&r);
            }
            return;
        }

        // Register watches on newly created subdirectories and mark them as
        // dirty subtrees so any files created inside them before the watch
        // was attached are walked.
        for (root, sub) in new_subdirs {
            self.watch_new_subdir(&root, &sub);
        }

        // Drop watches for any working copy that overflowed its dirty-path bound.
        let overflowed: Vec<PathBuf> = self
            .wcs
            .iter()
            .filter(|(_, wc)| wc.overflow.is_some() && !wc.wds.is_empty())
            .map(|(r, _)| r.clone())
            .collect();
        for r in overflowed {
            self.drop_wc_watches(&r);
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn drain_events(&mut self) {}

    fn watch_new_subdir(&mut self, root: &Path, sub: &VPath) {
        let Some(inotify_fd) = self.ensure_inotify() else {
            return;
        };
        let Ok((root_fd, root_st)) = open_verified_root(root) else {
            self.remove_wc(root);
            return;
        };
        let Some(wc) = self.wcs.get_mut(root) else {
            return;
        };
        if wc.overflow.is_some() || wc.root_dev != root_st.st_dev as u64 || wc.root_ino != root_st.st_ino {
            return;
        }
        let Some(sub_fd) = open_subdir_nofollow(&root_fd, sub, wc.root_dev) else {
            return;
        };
        let mut new_wds = Vec::new();
        match watch_subtree(inotify_fd, sub_fd, sub, wc.root_dev, wc, &mut new_wds, true) {
            Ok(()) => {
                for wd in new_wds {
                    self.wd_to_root.insert(wd, root.to_path_buf());
                }
            }
            Err(notice) => {
                for wd in new_wds {
                    rm_watch(inotify_fd, wd);
                }
                wc.overflow = Some(notice);
                self.drop_wc_watches(root);
            }
        }
    }

    fn reset_wc(&mut self, root: &Path) {
        self.remove_wc(root);
    }

    fn drop_wc_watches(&mut self, root: &Path) {
        #[cfg(target_os = "linux")]
        let inotify_fd = self.inotify.as_ref().map(AsRawFd::as_raw_fd);
        if let Some(wc) = self.wcs.get_mut(root) {
            for (wd, _) in wc.wds.drain() {
                self.wd_to_root.remove(&wd);
                #[cfg(target_os = "linux")]
                if let Some(fd) = inotify_fd {
                    rm_watch(fd, wd);
                }
            }
            wc.paths.clear();
            wc.dirty_dirs.clear();
            wc.dirty_subtrees.clear();
            wc.dirty_bytes = 0;
        }
    }

    fn remove_wc(&mut self, root: &Path) {
        self.drop_wc_watches(root);
        self.wcs.remove(root);
        #[cfg(target_os = "linux")]
        if self.wcs.is_empty() {
            self.inotify = None;
        }
    }

    fn reap_gone(&mut self) {
        let gone: Vec<PathBuf> = self
            .wcs
            .keys()
            .filter(|r| !r.join(".veil").join("repo.json").is_file())
            .cloned()
            .collect();
        for r in gone {
            self.remove_wc(&r);
        }
    }
}

impl WatchedWc {
    fn bump_seq(&mut self) -> u64 {
        self.seq += 1;
        self.seq
    }

    fn mark_dirty_dir(&mut self, dir: VPath, seq: u64) {
        if self.overflow.is_some() {
            return;
        }
        // If `dir` is already inside a dirty subtree at a sequence >= the old
        // one, still update `dirty_dirs` or `dirty_subtrees`.
        if let Some(s) = self.dirty_dirs.get_mut(&dir) {
            *s = (*s).max(seq);
            return;
        }
        let added_bytes = dir.as_str().len() + 32;
        if self.dirty_dirs.len() + self.dirty_subtrees.len() >= self.limits.max_dirty_paths
            || self.dirty_bytes + added_bytes > MAX_DIRTY_BYTES
        {
            self.overflow = Some(format!(
                "the file watcher's dirty-path bound ({} paths / {} KiB) was reached in {}; falling back to a full scan",
                self.limits.max_dirty_paths,
                MAX_DIRTY_BYTES >> 10,
                self.root.display()
            ));
            return;
        }
        self.dirty_bytes += added_bytes;
        self.dirty_dirs.insert(dir, seq);
    }

    fn mark_dirty_subtree(&mut self, dir: VPath, seq: u64) {
        if self.overflow.is_some() {
            return;
        }
        if let Some(s) = self.dirty_subtrees.get_mut(&dir) {
            *s = (*s).max(seq);
            return;
        }
        let added_bytes = dir.as_str().len() + 32;
        if self.dirty_dirs.len() + self.dirty_subtrees.len() >= self.limits.max_dirty_paths
            || self.dirty_bytes + added_bytes > MAX_DIRTY_BYTES
        {
            self.overflow = Some(format!(
                "the file watcher's dirty-path bound ({} paths / {} KiB) was reached in {}; falling back to a full scan",
                self.limits.max_dirty_paths,
                MAX_DIRTY_BYTES >> 10,
                self.root.display()
            ));
            return;
        }
        self.dirty_bytes += added_bytes;
        self.dirty_subtrees.insert(dir, seq);
    }

    fn prune_up_to(&mut self, seq: u64) {
        self.min_valid_seq = self.min_valid_seq.max(seq);
        self.dirty_dirs.retain(|p, &mut s| {
            let keep = s > seq;
            if !keep {
                self.dirty_bytes = self.dirty_bytes.saturating_sub(p.as_str().len() + 32);
            }
            keep
        });
        self.dirty_subtrees.retain(|p, &mut s| {
            let keep = s > seq;
            if !keep {
                self.dirty_bytes = self.dirty_bytes.saturating_sub(p.as_str().len() + 32);
            }
            keep
        });
    }
}

fn parse_token(tok: &str) -> Option<(u64, u64)> {
    let (id, seq) = tok.split_once(':')?;
    Some((u64::from_str_radix(id, 16).ok()?, seq.parse().ok()?))
}

fn valid_component(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains(['/', '\0'])
}

/// Open `root` as a directory, verify it is owned by this user and holds
/// `.veil/repo.json` (never following a symlink at `.veil`).
fn open_verified_root(root: &Path) -> io::Result<(OwnedFd, libc::stat)> {
    let c = CString::new(root.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in root path"))?;
    // SAFETY: `c` is a valid C string.
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a new descriptor we own.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let st = fstat_fd(owned.as_raw_fd())?;
    if st.st_uid != super::my_uid() {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "working copy is not owned by this user"));
    }
    // Check that `.veil/repo.json` exists inside `root` without following
    // symlinks.
    let veil_c = CString::new(".veil").expect("valid");
    // SAFETY: valid C string.
    let vfd = unsafe {
        libc::openat(
            owned.as_raw_fd(),
            veil_c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if vfd < 0 {
        return Err(io::Error::new(io::ErrorKind::NotFound, "no .veil directory"));
    }
    // SAFETY: `vfd` is a new descriptor we own.
    let veil_owned = unsafe { OwnedFd::from_raw_fd(vfd) };
    let repo_c = CString::new("repo.json").expect("valid");
    // SAFETY: `st_repo` is writable.
    let mut st_repo: libc::stat = unsafe { std::mem::zeroed() };
    let r = unsafe {
        libc::fstatat(
            veil_owned.as_raw_fd(),
            repo_c.as_ptr(),
            &mut st_repo,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if r != 0 || (st_repo.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return Err(io::Error::new(io::ErrorKind::NotFound, "no .veil/repo.json"));
    }
    Ok((owned, st))
}

fn fstat_fd(fd: RawFd) -> io::Result<libc::stat> {
    // SAFETY: `st` is written by `fstat`.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(st)
}

/// Open `sub` relative to `root_fd`, stepping one component at a time with
/// `O_NOFOLLOW | O_DIRECTORY` and verifying `st_dev == root_dev` and nested
/// `.veil` absence at every step.
fn open_subdir_nofollow(root_fd: &OwnedFd, sub: &VPath, root_dev: u64) -> Option<OwnedFd> {
    let mut cur = root_fd.try_clone().ok()?;
    for comp in sub.components() {
        if is_reserved_name(comp) {
            return None;
        }
        let c = CString::new(comp).ok()?;
        // SAFETY: `c` is a valid C string.
        let next = unsafe {
            libc::openat(
                cur.as_raw_fd(),
                c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if next < 0 {
            return None;
        }
        // SAFETY: `next` is a new descriptor we own.
        let next_owned = unsafe { OwnedFd::from_raw_fd(next) };
        let st = fstat_fd(next_owned.as_raw_fd()).ok()?;
        if st.st_dev as u64 != root_dev || has_dot_veil(next_owned.as_raw_fd()) {
            return None;
        }
        cur = next_owned;
    }
    Some(cur)
}

/// Does directory `fd` contain a `.veil` entry (a nested repository)?
fn has_dot_veil(fd: RawFd) -> bool {
    let veil_c = CString::new(".veil").expect("valid");
    // SAFETY: `st` is writable.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    unsafe { libc::fstatat(fd, veil_c.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) == 0 }
}

/// Walk `start_dir` (opened as `start_fd`) and its subdirectories iteratively
/// without following symlinks or crossing mount points, adding an inotify
/// watch for each directory.
fn watch_subtree(
    inotify_fd: RawFd,
    start_fd: OwnedFd,
    start_dir: &VPath,
    root_dev: u64,
    wc: &mut WatchedWc,
    new_wds: &mut Vec<i32>,
    mark_dirty: bool,
) -> Result<(), String> {
    let mut stack: Vec<(OwnedFd, VPath)> = vec![(start_fd, start_dir.clone())];
    while let Some((dir_fd, dir_path)) = stack.pop() {
        if !wc.paths.contains_key(&dir_path) && wc.paths.len() >= wc.limits.max_dirs {
            return Err(format!(
                "the file watcher's directory bound ({} directories) was reached in {}; falling back to a full scan",
                wc.limits.max_dirs,
                wc.root.display()
            ));
        }
        let wd = add_watch_fd(inotify_fd, dir_fd.as_raw_fd()).map_err(|e| {
            format!(
                "the file watcher could not watch {} ({e}); falling back to a full scan",
                wc.root.display()
            )
        })?;
        if let Some(old_dir) = wc.wds.insert(wd, dir_path.clone()) {
            if old_dir != dir_path {
                wc.paths.remove(&old_dir);
            }
        }
        wc.paths.insert(dir_path.clone(), wd);
        new_wds.push(wd);
        if mark_dirty {
            let seq = wc.bump_seq();
            wc.mark_dirty_subtree(dir_path.clone(), seq);
            if let Some(why) = &wc.overflow {
                return Err(why.clone());
            }
        }

        if dir_path.components().count() >= veil_core::tree::MAX_TREE_DEPTH {
            continue;
        }

        let children = list_subdir_names(&dir_fd);
        for name in children {
            let c = match CString::new(name.as_str()) {
                Ok(c) => c,
                Err(_) => continue,
            };
            // SAFETY: `c` is a valid C string.
            let cfd = unsafe {
                libc::openat(
                    dir_fd.as_raw_fd(),
                    c.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if cfd < 0 {
                continue;
            }
            // SAFETY: `cfd` is a new descriptor we own.
            let child_owned = unsafe { OwnedFd::from_raw_fd(cfd) };
            let Ok(st) = fstat_fd(child_owned.as_raw_fd()) else {
                continue;
            };
            // Never cross a mount boundary, and never descend into a nested
            // Veil repository.
            if st.st_dev as u64 != root_dev || has_dot_veil(child_owned.as_raw_fd()) {
                continue;
            }
            stack.push((child_owned, dir_path.join(&name)));
        }
    }
    Ok(())
}

/// Add an inotify watch on the open directory descriptor `dir_fd` via
/// `/proc/self/fd/{dir_fd}`, so the watch is placed on the exact verified
/// directory inode with zero path-resolution races.
#[cfg(target_os = "linux")]
fn add_watch_fd(inotify_fd: RawFd, dir_fd: RawFd) -> io::Result<i32> {
    let proc_path = CString::new(format!("/proc/self/fd/{dir_fd}")).expect("valid");
    // SAFETY: `proc_path` is a valid C string. Note that `/proc/self/fd/N` is a
    // magic link to the open directory, so we do NOT pass `IN_DONT_FOLLOW` to
    // `inotify_add_watch` on `/proc/self/fd/N` (which would watch the procfs
    // link itself instead of the target directory!), whereas `dir_fd` was
    // already opened with `O_NOFOLLOW | O_DIRECTORY`.
    let mask = WATCH_MASK & !libc::IN_DONT_FOLLOW;
    let wd = unsafe { libc::inotify_add_watch(inotify_fd, proc_path.as_ptr(), mask) };
    if wd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(wd)
}

#[cfg(not(target_os = "linux"))]
fn add_watch_fd(_inotify_fd: RawFd, _dir_fd: RawFd) -> io::Result<i32> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "inotify is Linux-only"))
}

#[cfg(target_os = "linux")]
fn rm_watch(inotify_fd: RawFd, wd: i32) {
    // SAFETY: valid descriptors.
    unsafe {
        libc::inotify_rm_watch(inotify_fd, wd);
    }
}

#[cfg(not(target_os = "linux"))]
fn rm_watch(_inotify_fd: RawFd, _wd: i32) {}

/// Read candidate subdirectory names in `dir_fd` using `fdopendir`/`readdir`.
/// Entries whose `d_type` is known to be a regular file, symlink, FIFO,
/// socket or device are skipped without an `openat` syscall; `DT_DIR` and
/// `DT_UNKNOWN` are returned and verified by `openat(O_DIRECTORY | O_NOFOLLOW)`.
fn list_subdir_names(dir_fd: &OwnedFd) -> Vec<String> {
    let Ok(dup) = dir_fd.try_clone() else {
        return Vec::new();
    };
    let raw = std::os::fd::IntoRawFd::into_raw_fd(dup);
    // SAFETY: `raw` is a directory descriptor we own; `fdopendir` takes ownership.
    let d = unsafe { libc::fdopendir(raw) };
    if d.is_null() {
        // SAFETY: `fdopendir` failed, so `raw` is still ours.
        unsafe { libc::close(raw) };
        return Vec::new();
    }
    let mut out = Vec::new();
    loop {
        // SAFETY: `d` is a valid DIR stream.
        let ent = unsafe { libc::readdir(d) };
        if ent.is_null() {
            break;
        }
        let d_type = unsafe { (*ent).d_type };
        if d_type != libc::DT_DIR && d_type != libc::DT_UNKNOWN {
            continue;
        }
        // SAFETY: `d_name` is NUL-terminated.
        let name = unsafe { std::ffi::CStr::from_ptr((*ent).d_name.as_ptr()) }.to_bytes();
        if name == b"." || name == b".." || name == b".veil" {
            continue;
        }
        let Ok(s) = std::str::from_utf8(name) else {
            continue;
        };
        if !valid_component(s) || is_reserved_name(s) {
            continue;
        }
        out.push(s.to_string());
    }
    // SAFETY: `d` came from `fdopendir`.
    unsafe { libc::closedir(d) };
    out.sort();
    out
}
