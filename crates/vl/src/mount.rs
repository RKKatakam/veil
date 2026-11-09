//! `vl ws mount` and `vl ws unmount`: a workspace as a directory (FUSE).
//!
//! **What is served.** Reads come from the workspace's tree as this reader
//! may see it ([`fs::ReaderView`]: a secret file it cannot decrypt is
//! absent, as in a checkout). Every write, create,
//! delete, rename, `mkdir`, `chmod +x` and truncate goes to a copy-on-write
//! overlay whose upper layer and whiteouts live in
//! `.veil/local/mounts/<ws>/` (`0700`), so a crash of the mount loses no
//! closed file.
//!
//! **One process owns a mount**: `vl ws mount --foreground` itself, or the
//! background process `vl ws mount` starts (the same binary, setsid'd, its
//! output in `.veil/local/mounts/<ws>/log`). It holds the mount's `lock`
//! (`flock`) for its whole life, and `state.json` names it: pid, boot,
//! mountpoint, control socket, and `base`, the snapshot the overlay is
//! over. `vl ws unmount`, `vl ws rm`, `vl doctor` and every other command
//! find it there.
//!
//! **Recording** goes through [`veil_core::Repo::snapshot_workspace_with`],
//! as for `vl ws write` and `vl ws exec`: the policy, the secret scanner,
//! sealing, isolation and quarantine all apply, and isolated, ignored or
//! quarantined files stay in the overlay (local), never in a snapshot. It
//! happens:
//! * when `vl ws unmount` asks (before and after unmounting);
//! * before every other `vl` command that snapshots: `Ctx::open` asks each
//!   live mount to record first ([`record_live`]), so `vl diff -r agent@`,
//!   `vl commit`, `vl merge agent@` see what was written in the mount, just
//!   as they see the project directory's edits;
//! * every `--record-every` seconds (default 60) while there are changes;
//! * when the file system is unmounted from outside (`fusermount -u`).
//!
//! **The workspace moving under the mount** (another command commits,
//! rewrites or undoes it; `vl ws write`; `vl ws exec`) is followed within a
//! second: the overlay is put over the new tree and keeps its edits. If the
//! move changed a path the overlay also changed, the overlay's content is
//! first saved as a change of its own on top of the snapshot it was over
//! (as `ws exec` does when its workspace moves), then those paths show the
//! new tree. Nothing is lost; the warning names the change.

// Without FUSE only the recording half of the file system is used.
#[cfg_attr(not(vl_fuse), allow(dead_code))]
pub mod fs;
#[cfg(vl_fuse)]
mod fuse;

use std::{
    io::{BufRead, BufReader, Write},
    os::unix::net::{UnixListener, UnixStream},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU32, Ordering},
        mpsc, Arc,
    },
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use veil_core::{
    builder::BuildReport,
    checkout::Materialised,
    object::EntryKind,
    sandbox::{dir_name, workspace_of},
    tree::{diff_trees, lookup},
    vfs::{private_dir, remove_tree, walk_files, DiskBackend, NodeKind, SandboxLock, StorageBackend},
    workspace::{mount_record_op_description, SnapshotOptions},
    ObjectId, Repo, VPath,
};

use self::fs::{DiskFiles, Journal, Lower, MountFs, ReaderView};
use crate::{
    ctx::{load_identity, user_for, Ctx},
    render::{bold, one_line, safe, warn},
};

/// Where mounts keep their state, relative to the project directory.
pub const MOUNTS_DIR: &str = ".veil/local/mounts";
/// Version of [`State`].
const STATE_VERSION: u32 = 1;
/// How often the server looks whether the workspace moved.
const TICK: Duration = Duration::from_millis(250);
const FOLLOW_EVERY: Duration = Duration::from_secs(1);

/// `.veil/local/mounts` of project directory `root`.
pub fn mounts_dir(root: &Path) -> PathBuf {
    let mut p = veil_core::repo::state_dir(root);
    p.extend(MOUNTS_DIR.split('/').skip(1));
    p
}

/// The files of one workspace's mount.
#[derive(Clone, Debug)]
pub struct Paths {
    pub dir: PathBuf,
    pub upper: PathBuf,
    whiteouts: PathBuf,
    /// The files the whiteouts hide that the mount never showed
    /// ([`MountFs::unseen`]), one JSON string per line.
    unseen: PathBuf,
    lock: PathBuf,
    pub log: PathBuf,
}

const STATE_FILE: &str = "state.json";

impl Paths {
    pub fn new(root: &Path, ws: &str) -> Paths {
        Self::at(mounts_dir(root).join(dir_name(ws)))
    }

    fn at(dir: PathBuf) -> Paths {
        Paths {
            upper: dir.join("upper"),
            whiteouts: dir.join("whiteouts"),
            unseen: dir.join("unseen"),
            lock: dir.join("lock"),
            log: dir.join("log"),
            dir,
        }
    }

    fn backend(&self) -> DiskBackend {
        DiskBackend::new(&self.dir)
    }

    pub fn load_state(&self) -> Result<Option<State>> {
        let Some(data) = self.backend().read_opt(&VPath::new(STATE_FILE)?)? else {
            return Ok(None);
        };
        let st: State = serde_json::from_slice(&data).with_context(|| format!("reading {}", self.dir.join(STATE_FILE).display()))?;
        if st.version != STATE_VERSION {
            bail!(
                "{} was written by another version of vl (state version {}); unmount it with that version",
                self.dir.display(),
                st.version
            );
        }
        Ok(Some(st))
    }

    /// Durably (temp file, fsync, rename).
    fn save_state(&self, st: &State) -> Result<()> {
        self.backend().write(&VPath::new(STATE_FILE)?, &serde_json::to_vec_pretty(st)?)?;
        Ok(())
    }

    fn load_whiteouts(&self) -> Vec<VPath> {
        load_paths(&self.whiteouts)
    }

    fn load_unseen(&self) -> Vec<VPath> {
        load_paths(&self.unseen)
    }
}

/// A journal of paths (whiteouts, unseen files).
fn load_paths(file: &Path) -> Vec<VPath> {
    let Ok(data) = std::fs::read_to_string(file) else { return Vec::new() };
    // One JSON string per line; a torn last line (a crash while appending)
    // is skipped: the file it hid comes back, nothing is lost.
    data.lines()
        .filter_map(|l| serde_json::from_str::<String>(l).ok())
        .filter_map(|s| VPath::new(&s).ok().filter(|p| !p.is_root()))
        .collect()
}

impl Paths {
    /// Does the overlay hold anything (files kept from earlier mounts)?
    fn upper_files(&self) -> Vec<VPath> {
        if !self.upper.is_dir() {
            return Vec::new();
        }
        veil_core::vfs::walk_files(&DiskBackend::new(&self.upper), &VPath::root(), &|_| false).unwrap_or_default()
    }
}

/// `state.json`: which snapshot the overlay is over, and who serves it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub version: u32,
    pub workspace: String,
    /// The snapshot (hex id) the overlay is over: recorded into, or
    /// followed to.
    pub base: String,
    /// Where it is mounted, while it is (or was, if its process died).
    #[serde(default)]
    pub mountpoint: Option<PathBuf>,
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub boot: Option<String>,
    /// The control socket of the serving process.
    #[serde(default)]
    pub socket: Option<PathBuf>,
}

impl State {
    fn base(&self) -> Result<ObjectId> {
        Ok(ObjectId::from_hex(&self.base)?)
    }
}

/// The whiteout journal of a mount on disk.
struct DiskJournal {
    paths: Paths,
}

impl Journal for DiskJournal {
    fn whiteout(&mut self, path: &VPath) -> std::io::Result<()> {
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&self.paths.whiteouts)?;
        let mut line = serde_json::to_string(path.as_str()).map_err(std::io::Error::other)?;
        line.push('\n');
        f.write_all(line.as_bytes())
    }

    fn rewrite(&mut self, all: &[VPath]) -> std::io::Result<()> {
        self.write_all("whiteouts", all)
    }

    fn unseen(&mut self, all: &[VPath]) -> std::io::Result<()> {
        if all.is_empty() && !self.paths.unseen.exists() {
            return Ok(());
        }
        self.write_all("unseen", all)
    }
}

impl DiskJournal {
    /// Durably replace journal `name` with `all`.
    fn write_all(&self, name: &str, all: &[VPath]) -> std::io::Result<()> {
        let mut out = String::new();
        for p in all {
            out.push_str(&serde_json::to_string(p.as_str()).map_err(std::io::Error::other)?);
            out.push('\n');
        }
        self.paths
            .backend()
            .write(&VPath::new(name).map_err(|e| std::io::Error::other(e.to_string()))?, out.as_bytes())
            .map_err(|e| std::io::Error::other(e.to_string()))
    }
}

fn open_repo(root: &Path) -> Result<Repo> {
    let identity = load_identity()?;
    let user = user_for(&identity);
    let repo = Repo::open(Arc::new(DiskBackend::new(root)), Some(identity.clone()), &user)?;
    crate::thin::attach(&repo, &identity);
    Ok(repo)
}

/// Snapshot `snapshot` as `repo`'s reader sees it now (with the keys
/// `repo` was opened with).
fn lower_of(repo: &Repo, snapshot: &ObjectId) -> Result<Arc<dyn Lower>> {
    let tree = repo.snapshot(snapshot)?.tree;
    Ok(Arc::new(ReaderView::new(repo.store().clone(), tree)))
}

/// What the overlay over `snapshot` shows, for the builder: everything as
/// read now, except the files the mount never showed (`unseen`, see
/// [`MountFs::unseen`]), which are carried (BUG-534).
fn shown_record(repo: &Repo, snapshot: &ObjectId, unseen: &[VPath]) -> Result<Materialised> {
    if unseen.is_empty() {
        return Ok(Materialised::default());
    }
    let tree = repo.snapshot(snapshot)?.tree;
    let store = repo.store();
    let mut hidden = Vec::new();
    for u in unseen {
        match lookup(store, &tree, u) {
            Ok(Some(e)) if e.kind == EntryKind::Dir => {
                // Unreadable: carried by the builder anyway.
                if let Ok(files) = veil_core::tree::walk_files(store, &e.id) {
                    hidden.extend(files.into_iter().filter_map(|(p, _)| VPath::new(&format!("{u}/{p}")).ok()));
                }
            }
            Ok(Some(_)) => hidden.push(u.clone()),
            Ok(None) | Err(_) => {}
        }
    }
    Ok(Materialised::hiding(hidden))
}

/// Do `ov` and `tree` hold the same at `p`: nothing, the same file, or a
/// directory of the same files? (A recording that reached the workspace
/// but not `state.json`, BUG-539, leaves the overlay agreeing with it.)
fn agrees(ov: &dyn StorageBackend, tree: &dyn StorageBackend, p: &VPath) -> bool {
    match (ov.metadata(p), tree.metadata(p)) {
        (Ok(None), Ok(None)) => true,
        (Ok(Some(a)), Ok(Some(b))) if a.kind == NodeKind::File && b.kind == NodeKind::File => same_file(ov, tree, p),
        (Ok(Some(a)), Ok(Some(b))) if a.kind == NodeKind::Dir && b.kind == NodeKind::Dir => {
            match (walk_files(ov, p, &|_| false), walk_files(tree, p, &|_| false)) {
                (Ok(x), Ok(y)) => x == y && x.iter().all(|f| same_file(ov, tree, f)),
                _ => false,
            }
        }
        _ => false,
    }
}

/// Do `a` and `b` hold the same file (content and executable bit) at `p`?
fn same_file(a: &dyn StorageBackend, b: &dyn StorageBackend, p: &VPath) -> bool {
    match (a.metadata(p), b.metadata(p)) {
        (Ok(Some(ma)), Ok(Some(mb))) if ma.executable == mb.executable && ma.len == mb.len => {
            matches!((a.read(p), b.read(p)), (Ok(x), Ok(y)) if x == y)
        }
        _ => false,
    }
}

fn fs_err(errno: i32) -> anyhow::Error {
    anyhow!(std::io::Error::from_raw_os_error(errno))
}

// ---- recording ---------------------------------------------------------------

/// Records a mount's overlay into its workspace (the server, or the
/// recovery of a mount whose process died).
struct Recorder {
    root: PathBuf,
    ws: String,
    paths: Paths,
    state: State,
    fs: Arc<MountFs>,
    /// [`MountFs::generation`] at the last recording (`None`: never).
    recorded_gen: Option<u64>,
    /// The last notes about files left out, so they are said once.
    said: String,
    /// What the last recording left out.
    report: BuildReport,
    /// The workspace is gone: the overlay was saved, the mount should go.
    orphaned: bool,
}

impl Recorder {
    /// Open the persisted overlay of `ws` (creating the state if needed).
    fn open(root: &Path, ws: &str) -> Result<Recorder> {
        let paths = Paths::new(root, ws);
        private_dir(&paths.dir).with_context(|| format!("creating {}", paths.dir.display()))?;
        private_dir(&paths.upper)?;
        let repo = open_repo(root)?;
        let state = match paths.load_state()? {
            Some(st) => st,
            None => {
                let wc = repo.workspace_wc(ws)?;
                let st = State {
                    version: STATE_VERSION,
                    workspace: ws.to_string(),
                    base: wc.hex(),
                    mountpoint: None,
                    pid: None,
                    boot: None,
                    socket: None,
                };
                paths.save_state(&st)?;
                st
            }
        };
        if state.workspace != ws {
            bail!("{} belongs to workspace '{}'", paths.dir.display(), safe(&state.workspace));
        }
        let base = state.base()?;
        let lower: Arc<dyn Lower> = match lower_of(&repo, &base) {
            Ok(l) => l,
            // The snapshot is gone (gc after the workspace moved on): the
            // overlay goes over the workspace as it is now, keeping all of
            // its edits.
            Err(_) => lower_of(&repo, &repo.workspace_wc(ws)?)?,
        };
        let upper: Arc<dyn StorageBackend> = Arc::new(DiskBackend::new(&paths.upper));
        // Large open files' content: anonymous files here, never in memory
        // (BUG-1365).
        let spill = paths.dir.join("spill");
        private_dir(&spill)?;
        let whiteouts = paths.load_whiteouts();
        let fs = Arc::new(
            MountFs::new(lower, upper, whiteouts, Some(Box::new(DiskJournal { paths: paths.clone() })))
                .with_files(Arc::new(DiskFiles::new(&paths.upper)))
                .with_spill(spill)
                .with_unseen(paths.load_unseen())
                .with_links(repo.format() >= veil_core::object::GIT_PARITY_REPO_FORMAT),
        );
        Ok(Recorder {
            root: root.to_path_buf(),
            ws: ws.to_string(),
            paths,
            state,
            fs,
            recorded_gen: None,
            said: String::new(),
            report: BuildReport::default(),
            orphaned: false,
        })
    }

    fn base(&self) -> Result<ObjectId> {
        self.state.base()
    }

    fn set_base(&mut self, id: ObjectId) -> Result<()> {
        self.state.base = id.hex();
        self.paths.save_state(&self.state)
    }

    /// Read the overlay's base again with `repo`'s keys: a grant or an
    /// embargo release since shows in the mount, and the recording that
    /// follows judges what the mount shows with the keys the builder uses.
    fn refresh(&self, repo: &Repo) -> Result<()> {
        if let Ok(lower) = lower_of(repo, &self.base()?) {
            self.fs.refresh_lower(lower);
        }
        Ok(())
    }

    /// What the overlay over `snapshot` shows, for the builder.
    fn shown(&self, repo: &Repo, snapshot: &ObjectId) -> Result<Materialised> {
        shown_record(repo, snapshot, &self.fs.unseen())
    }

    /// The workspace moved from the overlay's base to `wc` (another command
    /// recorded or rewrote it): put the overlay over `wc`'s tree.
    fn follow(&mut self, repo: &mut Repo, wc: ObjectId, notes: &mut Vec<String>) -> Result<()> {
        let old = self.base()?;
        self.refresh(repo)?;
        let new_tree = repo.snapshot(&wc)?.tree;
        let old_tree = repo.snapshot(&old).ok().map(|s| s.tree);
        let changed: Vec<VPath> = match &old_tree {
            Some(t) => diff_trees(repo.store(), Some(t), Some(&new_tree))?.into_iter().map(|c| c.path).collect(),
            None => Vec::new(),
        };
        let mut drop = Vec::new();
        if old_tree.is_some() && !changed.is_empty() {
            let (_, whiteouts) = self.fs.region();
            let overlaps = |x: &VPath| changed.iter().any(|d| d.starts_with(x) || x.starts_with(d));
            // Where the overlay already shows what the move brought (the
            // mount's own recording, whose `base` a crash kept from
            // `state.json`; the same edit made twice) there is no conflict:
            // nothing to save (BUG-539).
            let target = lower_of(repo, &wc)?;
            drop = self
                .fs
                .upper_files()
                .into_iter()
                .chain(whiteouts)
                .filter(|x| overlaps(x) && !self.fs.with_view(|ov| agrees(ov, &*target, x)))
                .collect();
            drop.sort();
            drop.dedup();
            // Ancestors cover their descendants.
            let all = drop.clone();
            drop.retain(|p| !all.iter().any(|a| a != p && p.starts_with(a)));
        }
        if !drop.is_empty() {
            self.fs.persist_all().map_err(fs_err)?;
            let desc = format!("edits made in the mount of workspace {} (they conflicted with a change to the workspace)", self.ws);
            let shown = self.shown(repo, &old)?;
            let (id, _) = self.fs.with_view(|ov| repo.commit_fs_as_child_with(old, ov, &desc, None, Some(&shown), &[], true))?;
            let change = repo.snapshot(&id)?.change_id.short();
            // Give up only what the saved change holds: an upper file it
            // left out (quarantined, held back) stays, over the new tree.
            let saved = lower_of(repo, &id)?;
            let upper = self.fs.upper_files();
            let (gone, kept): (Vec<VPath>, Vec<VPath>) = drop.into_iter().partition(|p| {
                let files: Vec<&VPath> = upper.iter().filter(|f| f.starts_with(p)).collect();
                files.iter().all(|f| self.fs.with_view(|ov| same_file(ov, &*saved, f)))
            });
            drop = gone;
            let list = |v: &[VPath]| {
                let mut shown: Vec<String> = v.iter().take(5).map(|p| safe(p.as_str()).into_owned()).collect();
                if v.len() > 5 {
                    shown.push("…".into());
                }
                shown.join(", ")
            };
            if !drop.is_empty() {
                notes.push(format!(
                    "workspace '{}' changed under its mount where the mount had edits too ({}); the mount's version was saved as change \
                     {change} on top of the snapshot it was over, and the mount now shows the workspace's. Merge or abandon {change}",
                    safe(&self.ws),
                    list(&drop)
                ));
            }
            if !kept.is_empty() {
                notes.push(format!(
                    "workspace '{}' changed files under its mount that the mount holds unrecorded versions of ({}); the mount keeps \
                     showing its own (they are not recorded: quarantined or held back)",
                    safe(&self.ws),
                    list(&kept)
                ));
            }
        }
        self.fs.switch_lower(lower_of(repo, &wc)?, &changed, &drop).map_err(fs_err)?;
        self.set_base(wc)
    }

    /// Record the overlay into the workspace (following it first if it
    /// moved). Returns what to tell the user.
    fn record(&mut self) -> Result<Vec<String>> {
        let mut notes = Vec::new();
        let _wc = veil_core::lock::WcLock::acquire(&veil_core::repo::state_dir(&self.root), &self.ws)?;
        for _ in 0..8 {
            let generation = self.fs.generation();
            let mut repo = open_repo(&self.root)?;
            repo.set_command_workspace(Some(self.ws.clone()));
            let Some(wc) = repo.view().workspaces.get(&self.ws).map(|w| w.wc) else {
                self.orphan(&mut repo, &mut notes)?;
                return Ok(notes);
            };
            if wc != self.base()? {
                self.follow(&mut repo, wc, &mut notes)?;
                continue;
            }
            self.refresh(&repo)?;
            if self.recorded_gen == Some(generation) {
                return Ok(notes);
            }
            if self.fs.is_clean() {
                self.recorded_gen = Some(generation);
                return Ok(notes);
            }
            self.fs.persist_all().map_err(fs_err)?;
            let ws = self.ws.clone();
            let shown = self.shown(&repo, &wc)?;
            // Recorded and reconciled with requests waiting throughout.
            let out = self.fs.record_with(|ov| {
                let out = repo.snapshot_workspace_with(
                    &ws,
                    ov,
                    SnapshotOptions {
                        expected_wc: Some(wc),
                        // Never a command of the user's: `vl undo` skips it
                        // and keeps what it recorded (BUG-538).
                        description: Some(mount_record_op_description(&ws)),
                        materialised: Some(&shown),
                        // Whoever writes in the mount (an agent, a tool, the
                        // member) is not known to be the member (BUG-560).
                        policy_from_command: true,
                        ..Default::default()
                    },
                )?;
                let lower = if out.superseded { None } else { Some(lower_of(&repo, &out.snapshot)?) };
                Ok((out, lower))
            })?;
            if out.superseded {
                continue;
            }
            if out.changed {
                // A crash before this point leaves `base` behind the
                // workspace: recovery follows the mount's own recording,
                // finds the overlay agreeing with it and saves nothing
                // (BUG-539).
                self.set_base(out.snapshot)?;
                notes.push(format!("Recorded {}", one_line(&repo, &out.snapshot)));
            }
            self.left_out(&out.report, &mut notes);
            self.report = out.report;
            self.recorded_gen = Some(generation);
            return Ok(notes);
        }
        bail!("workspace '{}' kept moving while its mount was being recorded; try again", self.ws)
    }

    /// Say (once) what the recording left out.
    fn left_out(&mut self, r: &BuildReport, notes: &mut Vec<String>) {
        let mut lines = Vec::new();
        for (p, f) in &r.quarantined {
            let why = f.first().map(|f| f.rule.to_string()).unwrap_or_else(|| "secret".into());
            lines.push(format!("{} quarantined in the mount ({why}): it looks like a secret, so it is not recorded", safe(p.as_str())));
        }
        for p in &r.isolated {
            lines.push(format!("{} is isolated (local-only): it stays in the mount and is never recorded", safe(p.as_str())));
        }
        for (p, why) in &r.cloak_failures {
            lines.push(format!("{} held back: {}", safe(p.as_str()), safe(why)));
        }
        if let Some(msg) = crate::render::policy_edit_held_message(r, Some(("the mount", self.ws.as_str()))) {
            lines.push(msg);
        }
        let sig = lines.join("\n");
        if sig != self.said {
            notes.extend(lines);
            self.said = sig;
        }
    }

    /// The workspace no longer exists (`vl undo` of its `vl ws new`, `vl op
    /// restore`): keep the overlay's content as a change on top of its base.
    fn orphan(&mut self, repo: &mut Repo, notes: &mut Vec<String>) -> Result<()> {
        if !self.orphaned && !self.fs.is_clean() {
            let desc = format!("edits made in the mount of workspace {} (the workspace was removed)", self.ws);
            let saved = (|| -> Result<String> {
                self.fs.persist_all().map_err(fs_err)?;
                let base = self.base()?;
                self.refresh(repo)?;
                let shown = self.shown(repo, &base)?;
                let (id, _) = self.fs.with_view(|ov| repo.commit_fs_as_child_with(base, ov, &desc, None, Some(&shown), &[], true))?;
                Ok(repo.snapshot(&id)?.change_id.short())
            })();
            notes.push(match saved {
                Ok(change) => format!(
                    "workspace '{}' no longer exists; what its mount held was saved as change {change}",
                    safe(&self.ws)
                ),
                // The overlay stays on disk either way.
                Err(e) => format!(
                    "workspace '{}' no longer exists, and what its mount held could not be saved as a change ({e:#}); \
                     it stays in {}",
                    safe(&self.ws),
                    self.paths.upper.display()
                ),
            });
        }
        self.orphaned = true;
        Ok(())
    }

    /// After the last recording: forget the mount, or keep the files the
    /// workspace does not record (isolated, ignored, quarantined) for the
    /// next mount.
    fn finish(&mut self, notes: &mut Vec<String>) -> Result<()> {
        if self.fs.is_clean() || self.orphaned && self.fs.upper_files().is_empty() {
            remove_tree(&self.paths.dir).with_context(|| format!("removing {}", self.paths.dir.display()))?;
            return Ok(());
        }
        self.state.mountpoint = None;
        self.state.pid = None;
        self.state.socket = None;
        self.state.boot = None;
        self.paths.save_state(&self.state)?;
        let kept = self.fs.upper_files();
        if !kept.is_empty() {
            let shown: Vec<String> = kept.iter().take(5).map(|p| safe(p.as_str()).into_owned()).collect();
            notes.push(format!(
                "kept {} file(s) the workspace does not record ({}{}) in {} for its next mount; `vl ws rm --force {}` deletes them",
                kept.len(),
                shown.join(", "),
                if kept.len() > 5 { ", …" } else { "" },
                self.paths.upper.display(),
                safe(&self.ws)
            ));
        }
        Ok(())
    }
}

// ---- the control socket ----------------------------------------------------------

#[derive(Serialize, Deserialize, Debug)]
struct Reply {
    ok: bool,
    #[serde(default)]
    notes: Vec<String>,
    #[serde(default)]
    error: Option<String>,
}

/// Send `request` to the process serving `state`'s mount. `None` when
/// nothing answers (no process, or a dead one).
fn request(state: &State, request: &str, timeout: Duration) -> Option<Result<Reply>> {
    let socket = state.socket.as_ref()?;
    let mut stream = UnixStream::connect(socket).ok()?;
    Some((|| {
        stream.set_read_timeout(Some(timeout))?;
        stream.write_all(format!("{request}\n").as_bytes())?;
        let mut line = String::new();
        BufReader::new(&stream).read_line(&mut line)?;
        if line.is_empty() {
            bail!("the mount process closed the connection");
        }
        Ok(serde_json::from_str(&line)?)
    })())
}

/// A socket path short enough for `sun_path` (104 bytes on macOS): in the
/// mount's directory if it fits, else in a private directory under
/// `$XDG_RUNTIME_DIR` or the temp directory.
fn socket_path(paths: &Paths) -> Result<PathBuf> {
    let p = paths.dir.join("ctl");
    if p.as_os_str().len() < 100 {
        return Ok(p);
    }
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|d| d.is_dir())
        .unwrap_or_else(std::env::temp_dir);
    let dir = base.join(format!("veil-mount-{}-{}", std::process::id(), ObjectId::hash(format!("{:?}{}", std::time::SystemTime::now(), paths.dir.display()).as_bytes()).short()));
    private_dir(&dir)?;
    Ok(dir.join("ctl"))
}

enum Msg {
    Request(String, Answer),
    #[cfg_attr(not(vl_fuse), allow(dead_code))]
    Ended,
}

/// Where the answer to a request goes; [`Answer::send`] returns once it
/// was written to the socket (the last answer is sent just before the
/// server exits).
struct Answer {
    reply: mpsc::Sender<Reply>,
    written: mpsc::Receiver<()>,
}

impl Answer {
    fn send(self, r: Reply) {
        if self.reply.send(r).is_ok() {
            let _ = self.written.recv_timeout(Duration::from_secs(5));
        }
    }
}

fn serve_socket(listener: UnixListener, tx: mpsc::Sender<Msg>) {
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let tx = tx.clone();
        let _ = (|| -> Result<()> {
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            let mut line = String::new();
            BufReader::new(&stream).read_line(&mut line)?;
            let (rtx, rrx) = mpsc::channel();
            let (wtx, wrx) = mpsc::channel();
            tx.send(Msg::Request(line.trim().to_string(), Answer { reply: rtx, written: wrx }))
                .map_err(|_| anyhow!("server gone"))?;
            let reply = rrx.recv().map_err(|_| anyhow!("server gone"))?;
            let r = stream.write_all(format!("{}\n", serde_json::to_string(&reply)?).as_bytes());
            let _ = wtx.send(());
            Ok(r?)
        })();
    }
}

// ---- mounted or not -----------------------------------------------------------------

/// Is a file system mounted at `dir` (an absolute path)?
pub fn is_mounted(dir: &Path) -> bool {
    #[cfg(target_os = "linux")]
    {
        let Ok(info) = std::fs::read_to_string("/proc/self/mountinfo") else { return false };
        let want = dir.as_os_str().to_string_lossy();
        info.lines().any(|l| l.split(' ').nth(4).is_some_and(|m| unescape_mountinfo(m) == want))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let Ok(out) = std::process::Command::new("mount").output() else { return false };
        let want = format!(" on {} (", dir.display());
        String::from_utf8_lossy(&out.stdout).lines().any(|l| l.contains(&want))
    }
}

/// `/proc/self/mountinfo` escapes space, tab, newline and `\` as `\ooo`.
#[cfg(target_os = "linux")]
fn unescape_mountinfo(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len() + 1 && b.len() >= i + 4 && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c)) {
            out.push((b[i + 1] - b'0') * 64 + (b[i + 2] - b'0') * 8 + (b[i + 3] - b'0'));
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Unmount `dir`: `fusermount3 -u` (or `fusermount`), `-z` for a lazy
/// unmount that detaches it even while busy; `umount` on macOS.
pub fn fuse_unmount(dir: &Path, lazy: bool) -> std::result::Result<(), String> {
    #[cfg(target_os = "linux")]
    let tries: Vec<(&str, Vec<&str>)> = vec![
        ("fusermount3", if lazy { vec!["-u", "-z", "-q"] } else { vec!["-u", "-q"] }),
        ("fusermount", if lazy { vec!["-u", "-z", "-q"] } else { vec!["-u", "-q"] }),
    ];
    #[cfg(not(target_os = "linux"))]
    let tries: Vec<(&str, Vec<&str>)> = vec![("umount", if lazy { vec!["-f"] } else { vec![] })];
    let mut last = String::from("no unmount program found (fusermount3, fusermount)");
    for (bin, args) in tries {
        let out = match std::process::Command::new(bin).args(args).arg(dir).output() {
            Ok(o) => o,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.to_string()),
        };
        if out.status.success() {
            return Ok(());
        }
        last = String::from_utf8_lossy(&out.stderr).trim().to_string();
        if last.is_empty() {
            last = format!("{bin} failed ({})", out.status);
        }
        break;
    }
    Err(last)
}

/// Is a process serving `paths`' mount right now? (It holds the lock.)
fn served(paths: &Paths) -> bool {
    if !paths.lock.exists() {
        return false;
    }
    matches!(SandboxLock::try_acquire(&paths.lock), Ok(None))
}

// ---- hooks for other commands ------------------------------------------------------------

/// Every mount of project directory `root`: workspace, state directory.
fn mounts(root: &Path) -> Vec<(String, Paths)> {
    let Ok(rd) = std::fs::read_dir(mounts_dir(root)) else { return Vec::new() };
    let mut out: Vec<(String, Paths)> = rd
        .filter_map(|e| e.ok())
        .filter_map(|e| Some((workspace_of(e.file_name().to_str()?)?, Paths::at(e.path()))))
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// Before a command snapshots: have every live mount record what was
/// written in it, so the command sees it (see the module documentation).
pub fn record_live(root: &Path) {
    for (ws, paths) in mounts(root) {
        let Ok(Some(st)) = paths.load_state() else { continue };
        let Some(mp) = &st.mountpoint else { continue };
        match request(&st, "record", Duration::from_secs(60)) {
            None if !served(&paths) => warn(&format!(
                "the mount of workspace {} at {} lost its process; `vl ws unmount {}` records what was written there",
                safe(&ws),
                mp.display(),
                safe(&ws)
            )),
            None => {}
            Some(Ok(r)) => {
                for n in r.notes.iter().filter(|n| !n.starts_with("Recorded ")) {
                    warn(&format!("mount of workspace {}: {n}", safe(&ws)));
                }
                if let Some(e) = r.error {
                    warn(&format!("could not record the mount of workspace {}: {}", safe(&ws), safe(&e)));
                }
            }
            Some(Err(e)) => warn(&format!("the mount of workspace {} did not answer: {e}", safe(&ws))),
        }
    }
}

/// Refuse `what` (switching the project directory to it, say) while `ws`
/// is mounted.
pub fn refuse_if_mounted(root: &Path, ws: &str, what: &str) -> Result<()> {
    let paths = Paths::new(root, ws);
    if let Ok(Some(st)) = paths.load_state() {
        if let Some(mp) = st.mountpoint {
            bail!(
                "workspace '{}' is mounted at {}; cannot {what} it. `vl ws unmount {}` first",
                safe(ws),
                mp.display(),
                safe(ws)
            );
        }
    }
    Ok(())
}

/// `vl ws rm`: refused while mounted, and without `force` while the
/// overlay holds files no snapshot has. `Ok(true)`: there is mount state to
/// remove afterwards ([`remove_state`]).
pub fn check_removable(root: &Path, ws: &str, force: bool) -> Result<bool> {
    let paths = Paths::new(root, ws);
    if std::fs::symlink_metadata(&paths.dir).is_err() {
        return Ok(false);
    }
    refuse_if_mounted(root, ws, "remove")?;
    if served(&paths) {
        bail!("a process is serving a mount of workspace '{}'; `vl ws unmount {}` first", safe(ws), safe(ws));
    }
    let kept = paths.upper_files();
    if !force && !kept.is_empty() {
        let shown: Vec<String> = kept.iter().take(10).map(|p| safe(p.as_str()).into_owned()).collect();
        bail!(
            "the mount state of workspace '{n}' holds files no snapshot has (isolated, ignored or quarantined ones written in the mount): {}. \
             They are in {}; `vl ws rm --force {n}` removes the workspace and them",
            shown.join(", "),
            paths.upper.display(),
            n = safe(ws)
        );
    }
    Ok(true)
}

pub fn remove_state(root: &Path, ws: &str) {
    let paths = Paths::new(root, ws);
    if let Err(e) = remove_tree(&paths.dir) {
        warn(&format!("could not remove {}: {e}; delete it with `rm -rf`", paths.dir.display()));
    }
}

/// `vl doctor`: each mount, and whether it needs attention.
pub fn doctor_status(root: &Path, repo: Option<&Repo>) -> Vec<(bool, String)> {
    let mut out = Vec::new();
    for (ws, paths) in mounts(root) {
        let st = match paths.load_state() {
            Ok(Some(st)) => st,
            Ok(None) => continue,
            Err(e) => {
                out.push((true, format!("{}: unreadable mount state: {e:#}", paths.dir.display())));
                continue;
            }
        };
        let gone = repo.is_some_and(|r| !r.view().workspaces.contains_key(&ws));
        let kept = paths.upper_files().len();
        let line = match (&st.mountpoint, served(&paths)) {
            (Some(mp), true) => (false, format!("workspace {} is mounted at {} (process {})", safe(&ws), mp.display(), st.pid.unwrap_or(0))),
            (Some(mp), false) => (
                true,
                format!(
                    "the mount of workspace {} at {} lost its process; `vl ws unmount {}` records its edits and cleans up",
                    safe(&ws),
                    mp.display(),
                    safe(&ws)
                ),
            ),
            (None, _) if gone => (
                true,
                format!(
                    "{} holds {kept} file(s) of the mounts of removed workspace {}; look at them, then delete the directory",
                    paths.dir.display(),
                    safe(&ws)
                ),
            ),
            (None, _) => (false, format!("workspace {} keeps {kept} local file(s) from earlier mounts", safe(&ws))),
        };
        out.push(line);
    }
    out
}

// ---- vl ws mount / unmount ------------------------------------------------------------------

/// `vl ws mount`.
pub struct MountArgs<'a> {
    pub name: &'a str,
    pub dir: &'a Path,
    pub foreground: bool,
    pub record_every: u64,
}

/// Bypasses the usual command flow: the serving process must not hold a
/// `Ctx` (its view would go stale while it serves).
pub fn cmd_mount(repo_arg: Option<&Path>, snapshot: bool, a: &MountArgs<'_>) -> Result<std::process::ExitCode> {
    let mut ctx = Ctx::open(repo_arg, snapshot)?;
    if ctx.bare {
        bail!("{} is a bare repository: it has no workspaces to mount", ctx.root.display());
    }
    let ws = a.name;
    ctx.repo.workspace_wc(ws)?;
    if ws == ctx.ws {
        bail!(
            "workspace '{}' is attached to the project directory; its files are there already. Mount another workspace",
            safe(ws)
        );
    }
    let root = ctx.root.clone();
    ctx.finish()?;
    drop(ctx);
    if !cfg!(vl_fuse) {
        bail!(
            "this vl was built without FUSE support. On Linux build it with the default features; on macOS install macFUSE \
             (https://macfuse.github.io) and build with `--features macfuse`"
        );
    }
    let paths = Paths::new(&root, ws);
    if let Some(st) = paths.load_state()? {
        if served(&paths) {
            bail!(
                "workspace '{}' is already mounted at {}",
                safe(ws),
                st.mountpoint.map(|m| m.display().to_string()).unwrap_or_else(|| "?".into())
            );
        }
        if let Some(old) = &st.mountpoint {
            // Its process died: detach the dead mount; the overlay is
            // picked up as it is.
            if is_mounted(old) {
                let _ = fuse_unmount(old, true);
            }
        }
    }
    let dir = mountpoint(&root, a.dir)?;
    if a.foreground {
        return serve(&root, ws, &dir, a.record_every, true);
    }
    spawn(&root, ws, &dir, a.record_every)
}

/// The mountpoint `dir`: an empty directory (created if missing) outside
/// the project directory, as an absolute path.
fn mountpoint(root: &Path, dir: &Path) -> Result<PathBuf> {
    if let Err(e) = std::fs::metadata(dir) {
        if e.raw_os_error() == Some(libc::ENOTCONN) {
            bail!(
                "{} is a mount whose process died; `fusermount3 -u -z {}` detaches it (or `vl ws unmount` of its workspace)",
                dir.display(),
                dir.display()
            );
        }
    }
    if !dir.exists() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let abs = std::fs::canonicalize(dir).with_context(|| format!("{}", dir.display()))?;
    if !abs.is_dir() {
        bail!("{} is not a directory", abs.display());
    }
    let root = std::fs::canonicalize(root)?;
    if abs.starts_with(&root) || root.starts_with(&abs) {
        bail!(
            "{} is inside the project directory {}: every snapshot would walk into the mount. Mount it elsewhere (next to the project, say)",
            abs.display(),
            root.display()
        );
    }
    // Inside another Veil repository (or a nested one), that repository's
    // snapshots would record what the mount shows, cloaked files in
    // plaintext, as its own files (BUG-535). The rule of BUG-200: a
    // directory holding a `.veil` is a repository.
    if let Some(repo) = abs.ancestors().find(|a| holds_veil(a)) {
        bail!(
            "{} is inside the Veil repository {}: its snapshots would record what the mount shows (cloaked files in plaintext) \
             as its own files. Mount it outside every repository",
            abs.display(),
            repo.display()
        );
    }
    if std::fs::read_dir(&abs)?.next().is_some() {
        bail!("{} is not empty; mount on an empty directory", abs.display());
    }
    Ok(abs)
}

/// Does directory `dir` hold a `.veil` (a directory, or a symlink to one,
/// in any case of the name)?
fn holds_veil(dir: &Path) -> bool {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return std::fs::symlink_metadata(dir.join(veil_core::repo::VEIL_DIR)).is_ok();
    };
    rd.filter_map(|e| e.ok()).any(|e| {
        e.file_name().to_str().is_some_and(veil_core::object::is_reserved_name)
            && e.file_type().is_ok_and(|t| t.is_dir() || t.is_symlink())
    })
}

/// Start the serving process in the background and wait until it serves.
fn spawn(root: &Path, ws: &str, dir: &Path, record_every: u64) -> Result<std::process::ExitCode> {
    let pid = start(root, ws, dir, record_every)?;
    println!("Mounted workspace {} at {} (process {pid})", bold(ws), dir.display());
    println!("  `vl ws unmount {ws}` records it and unmounts; until then other vl commands record it before they run");
    Ok(std::process::ExitCode::SUCCESS)
}

/// [`spawn`], saying nothing: the serving process's pid.
fn start(root: &Path, ws: &str, dir: &Path, record_every: u64) -> Result<u32> {
    use std::os::unix::process::CommandExt;
    let paths = Paths::new(root, ws);
    private_dir(&paths.dir)?;
    // Appended to (a mount that is starting must not truncate a live
    // one's log); started afresh once it grows past 1 MiB.
    if std::fs::metadata(&paths.log).is_ok_and(|m| m.len() > 1 << 20) {
        let _ = std::fs::remove_file(&paths.log);
    }
    let log = std::fs::OpenOptions::new().create(true).append(true).open(&paths.log)?;
    let mut cmd = std::process::Command::new(std::env::current_exe()?);
    cmd.arg("-R")
        .arg(root)
        .arg("--no-snapshot")
        .args(["ws", "mount", "--foreground", "--record-every", &record_every.to_string(), "--"])
        .arg(ws)
        .arg(dir)
        // Never a directory the mount could keep busy.
        .current_dir(root)
        .stdin(std::process::Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log)
        .env("VEIL_MOUNT_DAEMON", "1");
    // SAFETY: setsid is async-signal-safe; the child calls nothing else
    // before exec. Its own session: a Ctrl-C or a closed terminal does not
    // reach it.
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    let mut child = cmd.spawn().context("starting the mount process")?;
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            let log = std::fs::read_to_string(&paths.log).unwrap_or_default();
            bail!("the mount process exited ({status}):\n{}", log.trim_end());
        }
        if let Ok(Some(st)) = paths.load_state() {
            if st.pid == Some(child.id()) {
                if let Some(Ok(r)) = request(&st, "status", Duration::from_secs(10)) {
                    if r.ok {
                        break;
                    }
                }
            }
        }
        if started.elapsed() > Duration::from_secs(30) {
            let _ = child.kill();
            bail!("the mount process did not start within 30 s; see {}", paths.log.display());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(child.id())
}

// ---- vl ws exec --mount ---------------------------------------------------------------------

/// The prefix of the private directories `vl ws exec --mount` mounts in.
const EXEC_PREFIX: &str = "veil-ws-mnt-";

/// Can this machine mount a workspace? `Err(why)` when it cannot.
pub fn fuse_available() -> std::result::Result<(), String> {
    if !cfg!(vl_fuse) {
        return Err("this vl was built without FUSE".into());
    }
    // Tests of the fallback run where FUSE works.
    #[cfg(debug_assertions)]
    if std::env::var_os("VEIL_TEST_NO_FUSE").is_some() {
        return Err("FUSE is turned off (VEIL_TEST_NO_FUSE)".into());
    }
    #[cfg(target_os = "linux")]
    {
        if std::fs::OpenOptions::new().read(true).write(true).open("/dev/fuse").is_err() {
            return Err("/dev/fuse cannot be opened".into());
        }
        let on_path = |name: &str| {
            std::env::var_os("PATH").is_some_and(|p| std::env::split_paths(&p).any(|d| d.is_absolute() && d.join(name).is_file()))
        };
        if !on_path("fusermount3") && !on_path("fusermount") {
            return Err("fusermount3 is not installed".into());
        }
    }
    Ok(())
}

/// The mount a `vl ws exec --mount` runs over.
pub struct ExecMount {
    root: PathBuf,
    ws: String,
    /// Where the workspace is mounted (outside the project).
    pub dir: PathBuf,
    /// The private directory holding `dir`, when this run mounted it (and
    /// so unmounts it).
    ours: Option<PathBuf>,
    /// The mount is an earlier `vl ws exec`'s, which did not finish (`vl`
    /// was killed): what it held was recorded before this run.
    pub recovered: bool,
}

/// Mount `ws` for a run in a private directory (`$XDG_RUNTIME_DIR`, or the
/// temp directory), or use the mount already serving it.
pub fn for_exec(root: &Path, ws: &str) -> Result<ExecMount> {
    let paths = Paths::new(root, ws);
    if let Some(st) = paths.load_state()? {
        match (served(&paths), st.mountpoint) {
            (true, Some(mp)) => {
                // An earlier run's own mount (that run was killed) is this
                // run's to unmount.
                let ours = mp.parent().filter(|p| p.file_name().is_some_and(|n| n.to_string_lossy().starts_with(EXEC_PREFIX))).map(Path::to_path_buf);
                let recovered = ours.is_some();
                return Ok(ExecMount { root: root.to_path_buf(), ws: ws.to_string(), dir: mp, ours, recovered });
            }
            (false, Some(old)) if is_mounted(&old) => {
                let _ = fuse_unmount(&old, true);
            }
            _ => {}
        }
    }
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|d| d.is_dir())
        .unwrap_or_else(std::env::temp_dir);
    let parent = base.join(format!("{EXEC_PREFIX}{}-{}", std::process::id(), hex::encode(veil_core::crypto::random_bytes::<6>())));
    private_dir(&parent).with_context(|| format!("creating {}", parent.display()))?;
    let made = mountpoint(root, &parent.join("files")).and_then(|dir| start(root, ws, &dir, 0).map(|_| dir));
    match made {
        Ok(dir) => Ok(ExecMount { root: root.to_path_buf(), ws: ws.to_string(), dir, ours: Some(parent), recovered: false }),
        Err(e) => {
            let _ = remove_tree(&parent);
            Err(e)
        }
    }
}

impl ExecMount {
    /// Have the mount record what it holds now.
    pub fn record(&self) -> Result<()> {
        let st = Paths::new(&self.root, &self.ws).load_state()?.ok_or_else(|| anyhow!("the mount of workspace '{}' has no state", safe(&self.ws)))?;
        let r = request(&st, "record", Duration::from_secs(600)).ok_or_else(|| anyhow!("the mount process does not answer"))??;
        match r.error {
            Some(e) => bail!(e),
            None => Ok(()),
        }
    }

    /// After the run: the mount records what it holds into the workspace
    /// (its notes); one this run mounted is then unmounted.
    pub fn finish(self) -> Result<Vec<String>> {
        let paths = Paths::new(&self.root, &self.ws);
        let st = paths.load_state()?.ok_or_else(|| anyhow!("the mount of workspace '{}' has no state", safe(&self.ws)))?;
        let lost = || anyhow!("the mount process does not answer; `vl ws unmount {}` records what the command wrote", safe(&self.ws));
        let r = request(&st, "record", Duration::from_secs(600)).ok_or_else(lost)??;
        if let Some(e) = r.error {
            bail!("the command's output was not recorded: {e}. It stays in the mount; `vl ws unmount {}` records it", safe(&self.ws));
        }
        let mut notes = r.notes;
        if let Some(parent) = &self.ours {
            match request(&st, "unmount", Duration::from_secs(600)) {
                Some(Ok(u)) => {
                    notes.extend(u.notes);
                    match u.error {
                        // Recorded already; something the command left
                        // running keeps it busy.
                        Some(e) => notes.push(format!("the mount stays: {e}")),
                        None => {
                            let _ = std::fs::remove_dir(&self.dir);
                            let _ = std::fs::remove_dir(parent);
                        }
                    }
                }
                Some(Err(e)) => notes.push(format!("the mount stays: {e}")),
                None => {}
            }
        }
        Ok(notes)
    }
}

/// Signals that ask the foreground server to unmount (Ctrl-C, SIGTERM).
static SIGNALS: AtomicU32 = AtomicU32::new(0);

extern "C" fn on_signal(_: libc::c_int) {
    SIGNALS.fetch_add(1, Ordering::SeqCst);
}

/// Serve `ws` at `dir` until it is unmounted.
fn serve(root: &Path, ws: &str, dir: &Path, record_every: u64, banner: bool) -> Result<std::process::ExitCode> {
    let paths = Paths::new(root, ws);
    private_dir(&paths.dir)?;
    // One server per mount. A command probing liveness holds the lock for
    // an instant: retry a little before calling it taken.
    let mut lock = None;
    for _ in 0..100 {
        if let Some(l) = SandboxLock::try_acquire(&paths.lock)? {
            lock = Some(l);
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let Some(_lock) = lock else {
        bail!("workspace '{}' is already mounted (another process holds {})", safe(ws), paths.lock.display());
    };
    let mut rec = Recorder::open(root, ws)?;
    let mut notes = Vec::new();
    // Recover first: a crash left edits, or the workspace moved since.
    let first = rec.record();
    match first {
        Ok(n) => notes.extend(n),
        Err(e) => warn(&format!("could not record the overlay kept from an earlier mount: {e:#}")),
    }
    let socket = socket_path(&paths)?;
    let _ = std::fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket).with_context(|| format!("binding {}", socket.display()))?;
    let (tx, rx) = mpsc::channel();
    {
        let tx = tx.clone();
        std::thread::spawn(move || serve_socket(listener, tx));
    }
    // Recorded before mounting: if this process dies half way, the next
    // `vl ws unmount` knows where to look.
    rec.state.mountpoint = Some(dir.to_path_buf());
    rec.state.pid = Some(std::process::id());
    rec.state.boot = Some(veil_core::lock::boot_identity());
    rec.state.socket = Some(socket.clone());
    rec.paths.save_state(&rec.state)?;
    let session = match mount_fs(rec.fs.clone(), dir, ws, &paths.dir, tx) {
        Ok(s) => s,
        Err(e) => {
            let _ = std::fs::remove_file(&socket);
            let mut notes = Vec::new();
            let _ = rec.finish(&mut notes);
            return Err(e);
        }
    };
    for n in notes.drain(..) {
        eprintln!("{n}");
    }
    // SAFETY: the handler only touches an atomic.
    unsafe {
        libc::signal(libc::SIGINT, on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t);
        libc::signal(libc::SIGTERM, on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t);
        libc::signal(libc::SIGHUP, on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t);
    }
    if banner && std::env::var_os("VEIL_MOUNT_DAEMON").is_none() {
        eprintln!(
            "Mounted workspace {} at {} (Ctrl-C or `vl ws unmount {ws}` records it and unmounts)",
            bold(ws),
            dir.display()
        );
    } else {
        eprintln!("serving workspace {ws} at {} (process {})", dir.display(), std::process::id());
    }

    let every = (record_every > 0).then(|| Duration::from_secs(record_every));
    let mut last_record = Instant::now();
    let mut last_follow = Instant::now();
    let mut signals_seen = 0;
    // Who asked to unmount, waiting for the reply.
    let mut unmounting: Option<Option<Answer>> = None;
    let mut pending_notes: Vec<String> = Vec::new();
    loop {
        let msg = rx.recv_timeout(TICK);
        match msg {
            Ok(Msg::Request(req, reply)) => match req.as_str() {
                "status" => {
                    reply.send(Reply { ok: true, notes: Vec::new(), error: None });
                }
                "record" => {
                    let r = match rec.record() {
                        Ok(n) => Reply { ok: true, notes: n, error: None },
                        Err(e) => Reply { ok: false, notes: Vec::new(), error: Some(format!("{e:#}")) },
                    };
                    last_record = Instant::now();
                    reply.send(r);
                }
                "unmount" if unmounting.is_none() => {
                    match rec.record() {
                        Ok(n) => pending_notes.extend(n),
                        Err(e) => {
                            reply.send(Reply {
                                ok: false,
                                notes: Vec::new(),
                                error: Some(format!("could not record the mount, so it stays mounted: {e:#}")),
                            });
                            continue;
                        }
                    }
                    match fuse_unmount(dir, false) {
                        Ok(()) => unmounting = Some(Some(reply)),
                        Err(e) => {
                            reply.send(Reply {
                                ok: false,
                                notes: std::mem::take(&mut pending_notes),
                                error: Some(format!(
                                    "{} is busy ({e}); its edits are recorded, but it stays mounted. Close the files open there \
                                     and `cd` out of it, then run `vl ws unmount {ws}` again",
                                    dir.display()
                                )),
                            });
                        }
                    }
                }
                _ => {
                    reply.send(Reply {
                        ok: false,
                        notes: Vec::new(),
                        error: Some(format!("the mount is {}", if unmounting.is_some() { "being unmounted" } else { "busy" })),
                    });
                }
            },
            Ok(Msg::Ended) => break,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
        let signals = SIGNALS.load(Ordering::SeqCst);
        if signals > signals_seen {
            signals_seen = signals;
            match rec.record() {
                Ok(n) => pending_notes.extend(n),
                Err(e) => eprintln!("could not record the mount: {e:#}"),
            }
            // A second signal detaches it even while busy.
            match fuse_unmount(dir, signals > 1) {
                Ok(()) => {
                    unmounting.get_or_insert(None);
                }
                Err(e) => eprintln!(
                    "{} is busy ({e}); it stays mounted. Close what is open there, or signal again to detach it lazily",
                    dir.display()
                ),
            }
        }
        if unmounting.is_some() {
            continue;
        }
        if rec.orphaned {
            let _ = fuse_unmount(dir, true);
            unmounting = Some(None);
            continue;
        }
        if last_follow.elapsed() >= FOLLOW_EVERY {
            last_follow = Instant::now();
            let due = every.is_some_and(|e| last_record.elapsed() >= e);
            let r = if due {
                last_record = Instant::now();
                rec.record()
            } else {
                follow_only(&mut rec)
            };
            match r {
                Ok(n) => {
                    for line in n {
                        eprintln!("{line}");
                    }
                }
                Err(e) => eprintln!("could not record the mount: {e:#}"),
            }
        }
    }
    // Unmounted (asked, signalled, or from outside): record what is left.
    drop(session);
    let mut out = pending_notes;
    let result = rec.record().and_then(|n| {
        out.extend(n);
        rec.finish(&mut out)
    });
    let _ = std::fs::remove_file(&socket);
    if let Some(parent) = socket.parent().filter(|p| p.file_name().is_some_and(|n| n.to_string_lossy().starts_with("veil-mount-"))) {
        let _ = std::fs::remove_dir(parent);
    }
    let reply = match &result {
        Ok(()) => Reply { ok: true, notes: out.clone(), error: None },
        Err(e) => Reply {
            ok: false,
            notes: out.clone(),
            error: Some(format!("unmounted, but the last recording failed: {e:#}; `vl ws unmount {ws}` retries it")),
        },
    };
    if let Some(Some(tx)) = unmounting {
        tx.send(reply);
    } else {
        for line in &out {
            eprintln!("{line}");
        }
        if let Err(e) = &result {
            eprintln!("could not record the mount: {e:#}");
        }
        eprintln!("Unmounted workspace {ws} from {}", dir.display());
    }
    result.map(|_| std::process::ExitCode::SUCCESS)
}

/// A tick without recording: only follow the workspace if it moved.
fn follow_only(rec: &mut Recorder) -> Result<Vec<String>> {
    let mut notes = Vec::new();
    let mut repo = open_repo(&rec.root)?;
    match repo.view().workspaces.get(&rec.ws).map(|w| w.wc) {
        None => rec.orphan(&mut repo, &mut notes)?,
        Some(wc) if wc != rec.base()? => rec.follow(&mut repo, wc, &mut notes)?,
        // A grant or a release shows within a tick.
        Some(_) => rec.refresh(&repo)?,
    }
    Ok(notes)
}

/// The kernel side of a mount; dropping it after the file system was
/// unmounted joins the session thread.
struct Session {
    #[cfg_attr(not(vl_fuse), allow(dead_code))]
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

#[cfg(vl_fuse)]
fn mount_fs(fs: Arc<MountFs>, dir: &Path, ws: &str, upper: &Path, tx: mpsc::Sender<Msg>) -> Result<Session> {
    let session = fuse::mount(fs, dir, ws, upper).with_context(|| {
        format!(
            "could not mount at {} (FUSE needs /dev/fuse and fusermount3, or macFUSE on macOS)",
            dir.display()
        )
    })?;
    /// Says the session ended, also when it panicked.
    struct Ended(mpsc::Sender<Msg>);
    impl Drop for Ended {
        fn drop(&mut self) {
            let _ = self.0.send(Msg::Ended);
        }
    }
    let thread = std::thread::spawn(move || {
        let _ended = Ended(tx);
        if let Err(e) = session.run() {
            eprintln!("the FUSE session ended with an error: {e}");
        }
    });
    Ok(Session { thread: Some(thread) })
}

#[cfg(not(vl_fuse))]
fn mount_fs(_: Arc<MountFs>, _: &Path, _: &str, _: &Path, _: mpsc::Sender<Msg>) -> Result<Session> {
    bail!("this vl was built without FUSE support")
}

/// `vl ws unmount NAME`.
pub fn cmd_unmount(ctx: &mut Ctx, ws: &str) -> Result<()> {
    let paths = Paths::new(&ctx.root, ws);
    let Some(st) = paths.load_state()? else {
        bail!("workspace '{}' is not mounted", safe(ws));
    };
    if let Some(r) = request(&st, "unmount", Duration::from_secs(600)) {
        let r = r?;
        for n in &r.notes {
            eprintln!("{n}");
        }
        if let Some(e) = r.error {
            bail!(e);
        }
        println!(
            "Unmounted workspace {} from {}",
            bold(ws),
            st.mountpoint.map(|m| m.display().to_string()).unwrap_or_default()
        );
        return Ok(());
    }
    // Nobody answers: the process died (or never finished starting).
    let Some(_lock) = SandboxLock::try_acquire(&paths.lock)? else {
        bail!(
            "the process serving the mount of workspace '{}' (pid {}) does not answer; stop it (`kill {}`), then run this again",
            safe(ws),
            st.pid.unwrap_or(0),
            st.pid.unwrap_or(0)
        );
    };
    let Some(mp) = st.mountpoint.clone() else {
        let kept = paths.upper_files().len();
        bail!(
            "workspace '{}' is not mounted{}",
            safe(ws),
            if kept > 0 { format!(" (it keeps {kept} local file(s) from earlier mounts in {})", paths.upper.display()) } else { String::new() }
        );
    };
    if is_mounted(&mp) {
        fuse_unmount(&mp, true).map_err(|e| anyhow!("could not detach the dead mount at {}: {e}", mp.display()))?;
        eprintln!("Detached the mount at {} (its process had died)", mp.display());
    }
    if let Some(sock) = &st.socket {
        let _ = std::fs::remove_file(sock);
    }
    let mut rec = Recorder::open(&ctx.root, ws)?;
    let mut notes = rec.record()?;
    rec.finish(&mut notes)?;
    for n in &notes {
        eprintln!("{n}");
    }
    println!("Recovered the mount of workspace {} from {} and recorded its edits", bold(ws), mp.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn mountinfo_escapes() {
        assert_eq!(unescape_mountinfo("/home/a\\040b"), "/home/a b");
        assert_eq!(unescape_mountinfo("/x\\134y"), "/x\\y");
        assert_eq!(unescape_mountinfo("/plain"), "/plain");
        assert_eq!(unescape_mountinfo("/end\\04"), "/end\\04");
    }

    #[test]
    fn state_round_trips_and_whiteouts_survive_a_torn_line() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::new(tmp.path(), "agent");
        private_dir(&paths.dir).unwrap();
        let st = State {
            version: STATE_VERSION,
            workspace: "agent".into(),
            base: ObjectId::hash(b"x").hex(),
            mountpoint: Some("/mnt/a".into()),
            pid: Some(7),
            boot: None,
            socket: None,
        };
        paths.save_state(&st).unwrap();
        let back = paths.load_state().unwrap().unwrap();
        assert_eq!((back.workspace.as_str(), back.pid), ("agent", Some(7)));
        let mut j = DiskJournal { paths: paths.clone() };
        j.whiteout(&VPath::new("a b/c").unwrap()).unwrap();
        j.whiteout(&VPath::new("new\nline").unwrap()).unwrap();
        std::fs::OpenOptions::new().append(true).open(&paths.whiteouts).unwrap().write_all(b"\"torn").unwrap();
        assert_eq!(paths.load_whiteouts(), [VPath::new("a b/c").unwrap(), VPath::new("new\nline").unwrap()]);
        j.rewrite(&[VPath::new("only").unwrap()]).unwrap();
        assert_eq!(paths.load_whiteouts(), [VPath::new("only").unwrap()]);
    }

    #[test]
    fn mountpoints_inside_the_project_are_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("proj");
        std::fs::create_dir_all(root.join("sub")).unwrap();
        assert!(mountpoint(&root, &root.join("sub")).is_err());
        assert!(mountpoint(&root, &root.join("new/dir")).is_err());
        assert!(mountpoint(&root, tmp.path()).is_err(), "the project inside the mountpoint");
        let ok = mountpoint(&root, &tmp.path().join("mnt")).unwrap();
        assert!(ok.is_absolute() && ok.is_dir());
        std::fs::write(ok.join("f"), "x").unwrap();
        assert!(mountpoint(&root, &ok).is_err(), "not empty");
        // BUG-535: inside another repository, or a nested one, at any depth.
        let other = tmp.path().join("other");
        std::fs::create_dir_all(other.join(".veil")).unwrap();
        assert!(mountpoint(&root, &other.join("a/b/mnt")).is_err());
        let nested = tmp.path().join("plain/vendor");
        std::fs::create_dir_all(nested.join(".VEIL")).unwrap();
        assert!(mountpoint(&root, &nested.join("mnt")).is_err());
        assert!(mountpoint(&root, &tmp.path().join("plain/mnt")).is_ok());
    }
}
