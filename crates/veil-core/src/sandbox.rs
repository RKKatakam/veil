//! Persistent `vl ws exec` sandboxes.
//!
//! Each virtual workspace has at most one sandbox: a directory holding its
//! files, kept between runs so that a run only rewrites what changed (as a
//! Git worktree is kept), and removed by `vl ws rm`. Everything lives in
//! `.veil/local/sandboxes/<workspace>/` (`0700`, device-local):
//!
//! | Entry | What it is |
//! |-------|------------|
//! | `lock` | `flock`ed by the run using the sandbox ([`SandboxLock`](crate::vfs::SandboxLock)) |
//! | `manifest.json` | [`Manifest`]: which tree the files are, the run in progress |
//! | `statcache` | the files' stamps and content ids ([`StatCache`]) |
//! | `files/` | the files; the command's working directory |
//!
//! **The manifest** says what the sandbox holds: the tree its files were
//! last synced to or recorded as ([`Manifest::tree`]) plus, per file, the
//! blob id and the stat stamp (size, mtime, ctime, inode, executable bit)
//! in the stat cache next to it, exactly as the project directory's
//! working copy keeps them. A run diffs [`Manifest::tree`] against the
//! workspace's tree and rewrites only what differs ([`sync`]), and after
//! the command the builder records the files through the stat cache:
//! stamps first, content hash when they are ambiguous (the racy-mtime rule
//! of [`crate::statcache`]). Files checkout just wrote are vouched for
//! without being read back ([`vouch_written`]).
//!
//! **Sparse sandboxes** (`vl ws exec --only`) hold a [`SparseSet`] of the
//! tree ([`Manifest::only`]) and `.veilpolicy`: [`sync_to`] checks out the
//! tree restricted to the set ([`restrict`]), from the previous tree
//! restricted to the previous set, so a different set only adds and
//! removes what differs. The result is recorded through a [`SparseView`](crate::vfs::SparseView)
//! (everything outside the set is the synced tree's, unchanged), and what
//! the command wrote outside the set ([`strays`]) is never recorded and is
//! removed from the sandbox ([`remove_strays`]).
//!
//! **Crash safety.** A run first writes, durably, that it is in progress
//! ([`Manifest::running`]) and the boot it runs in. The files themselves
//! are never fsynced. A run that finds a sandbox it cannot trust (a run
//! that never finished, a different boot, a corrupt or unknown manifest,
//! files missing or not a directory, a tree no longer in the store)
//! rebuilds it from scratch ([`rebuild_reason`], [`wipe`]): when in doubt,
//! rebuild.
//!
//! **Injected secrets** (`--with-isolated`) are written for one run only
//! ([`inject`]) and taken out again after it is recorded
//! ([`remove_injected`]), together with every file the builder quarantined
//! because it contains one of them: nothing that copies an injected secret
//! survives into a run that no longer guards against it.

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    io,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{
    builder::{BuildReport, InjectedSecrets, INJECTED_RULE},
    crypto::Envelope,
    error::VeilError,
    keychain::LOCAL_SCOPE,
    policy::{PolicyFile, POLICY_FILE},
    checkout::{behind_special, CheckoutReport, Materialised},
    error::Result,
    id::ObjectId,
    object::{EntryKind, TreeEntry},
    repo::Repo,
    statcache::{CacheKey, Record, Stamp, StatCache},
    store::ObjectStore,
    object::is_reserved_name,
    policy::{Policy, Tier},
    tree::lookup,
    vfs::{holds_repository, is_temp_name, remove_tree, restrict, DiskBackend, NodeKind, SandboxFs, SparseSet, StorageBackend},
    vpath::VPath,
    workspace::validate_workspace_name,
};

/// Where the sandboxes live, relative to the project directory.
pub const SANDBOXES_DIR: &str = ".veil/local/sandboxes";
/// Version of [`Manifest`]; any other is rebuilt.
pub const MANIFEST_VERSION: u32 = 1;
const MANIFEST_FILE: &str = "manifest.json";
const CACHE_FILE: &str = "statcache";
const LOCK_FILE: &str = "lock";
const FILES_DIR: &str = "files";
const TRASH_PREFIX: &str = "files.trash-";
/// The injected-secret guard of a sandbox: every isolated file ever
/// injected into it, sealed under the `local` scope ([`Guard`]).
pub const GUARD_FILE: &str = "guard.sealed";
/// Prefix of a directory a rebuild moved the previous files to, whole,
/// because they may hold unrecorded work ([`set_aside`]). Never removed
/// by Veil except by `vl ws rm --force`.
pub const KEPT_PREFIX: &str = "unrecorded-";
const REBUILD_PREFIX: &str = "files.rebuild-";

/// `.veil/local/sandboxes` of the project directory `root`.
pub fn sandboxes_dir(root: &Path) -> PathBuf {
    let mut p = root.to_path_buf();
    p.extend(SANDBOXES_DIR.split('/'));
    p
}

/// Is `dir` a `.veil/local/sandboxes` directory?
pub fn is_sandboxes_dir(dir: &Path) -> bool {
    let names: Vec<_> = dir.ancestors().take(3).map(|a| a.file_name()).collect();
    names.len() == 3
        && names[0].is_some_and(|n| n == "sandboxes")
        && names[1].is_some_and(|n| n == "local")
        && names[2].is_some_and(|n| n == crate::repo::VEIL_DIR)
}

/// Name of workspace `ws`'s directory in [`sandboxes_dir`]: the name
/// itself, except that `.` and `..` (valid workspace names) are spelt
/// `%2e` and `%2e%2e` (`%` cannot occur in a workspace name).
pub fn dir_name(ws: &str) -> String {
    match ws {
        "." => "%2e".into(),
        ".." => "%2e%2e".into(),
        w => w.into(),
    }
}

/// The workspace whose sandbox directory is called `name`, if any.
pub fn workspace_of(name: &str) -> Option<String> {
    match name {
        "%2e" => Some(".".into()),
        "%2e%2e" => Some("..".into()),
        "." | ".." => None,
        n => validate_workspace_name(n).is_ok().then(|| n.to_string()),
    }
}

/// The paths of one workspace's sandbox.
#[derive(Debug, Clone)]
pub struct SandboxPaths {
    /// `.veil/local/sandboxes/<ws>`.
    pub dir: PathBuf,
    /// The files: the command's working directory.
    pub files: PathBuf,
    /// The lock file.
    pub lock: PathBuf,
}

impl SandboxPaths {
    pub fn new(root: &Path, ws: &str) -> SandboxPaths {
        Self::at(sandboxes_dir(root).join(dir_name(ws)))
    }

    /// The paths of the sandbox in directory `dir`.
    pub fn at(dir: PathBuf) -> SandboxPaths {
        SandboxPaths {
            files: dir.join(FILES_DIR),
            lock: dir.join(LOCK_FILE),
            dir,
        }
    }

    fn meta(&self) -> DiskBackend {
        DiskBackend::new(&self.dir)
    }

    fn manifest_path() -> VPath {
        VPath::new(MANIFEST_FILE).expect("valid")
    }

    fn cache_path() -> VPath {
        VPath::new(CACHE_FILE).expect("valid")
    }

    /// The sandbox's stat cache (empty if missing or corrupt).
    pub fn load_cache(&self) -> StatCache {
        StatCache::load(&self.meta(), &Self::cache_path())
    }

    /// Persist the stat cache if it changed. It is only an accelerator.
    pub fn save_cache(&self, cache: &mut StatCache) -> Result<()> {
        cache.save(&self.meta(), &Self::cache_path())
    }

    /// The manifest, if there is one.
    pub fn load_manifest(&self) -> Loaded {
        match self.meta().read_opt(&Self::manifest_path()) {
            Ok(None) => Loaded::Missing,
            Ok(Some(raw)) => match serde_json::from_slice::<Manifest>(&raw) {
                Ok(m) => Loaded::Found(Box::new(m)),
                Err(e) => Loaded::Corrupt(e.to_string()),
            },
            Err(e) => Loaded::Corrupt(e.to_string()),
        }
    }

    /// Write the manifest, atomically and durably.
    pub fn save_manifest(&self, m: &Manifest) -> Result<()> {
        self.meta().write(&Self::manifest_path(), &serde_json::to_vec_pretty(m)?)
    }
}

/// What a sandbox holds (see the module documentation).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub version: u32,
    /// The workspace the sandbox belongs to.
    pub workspace: String,
    /// The tree the files are: what the last run synced them to, then
    /// recorded them as. `None`: no files yet.
    #[serde(default)]
    pub tree: Option<ObjectId>,
    /// The workspace snapshot of [`Manifest::tree`] (informational).
    #[serde(default)]
    pub snapshot: Option<ObjectId>,
    /// What the files hold where they differ from [`Manifest::tree`] as
    /// this reader reads it now (unreadable files).
    #[serde(default, skip_serializing_if = "Materialised::is_empty")]
    pub materialised: Materialised,
    /// The boot the files were written in ([`crate::lock::boot_identity`]).
    /// Unsynced files of another boot may be torn: rebuilt.
    #[serde(default)]
    pub boot: String,
    /// Set (durably) by a run before it touches anything, cleared when it
    /// has recorded the result and cleaned up. Found set, the run died.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub running: Option<String>,
    /// The paths materialised ([`SparseSet::to_strings`]), `None` for the
    /// whole tree. Files the sandbox holds outside them (besides
    /// `.veilpolicy`) are not the workspace's: ignored or isolated output,
    /// or [`Manifest::quarantined`] files. Readers before sparse sandboxes
    /// rebuild a sandbox with a set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub only: Option<Vec<String>>,
    /// Files the last run left in the sandbox that the builder quarantined
    /// (they hold what looks like a secret): local work that is in no
    /// snapshot. `vl ws rm` refuses to delete them without `--force`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub quarantined: Vec<String>,
    /// Set (durably) just before the command starts, cleared once its
    /// output is recorded and the sandbox cleaned up: the files hold a
    /// command's output that is in no snapshot yet. Never wiped; the next
    /// run (or `vl ws exec --record-only`) records it first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<Pending>,
    /// For a sandbox that ever held injected secrets ([`GUARD_FILE`]): when
    /// the last run that checked the sandbox for copies of them started
    /// (ns since the epoch, wall clock). The next check reads files
    /// changed since ([`scrub`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guard_checked: Option<i64>,
    /// The [`crate::oplog::WorkspaceState::id`] of the workspace the files
    /// belong to: a later workspace of the same name is another one, and
    /// never gets them (BUG-1033). Absent for a workspace without one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<String>,
}

/// The output of a command that is not recorded yet ([`Manifest::pending`]).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Pending {
    /// The run that started the command.
    pub run: String,
    /// The workspace snapshot the files were synced to before the command
    /// ([`Manifest::tree`] is its tree): recorded with it as the expected
    /// working copy.
    pub base: ObjectId,
    /// `-m`, if given.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub message: String,
    /// When the run started (ns since the epoch, wall clock), before the
    /// sync and any injection.
    pub started: i64,
    /// Files outside the sparse set before the command ran ([`strays`]):
    /// not its output.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kept: Vec<String>,
    /// Isolated files were injected for the command.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub injected: bool,
    /// Once recorded: the snapshot and tree it was recorded as (only the
    /// cleanup is left).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recorded: Option<(ObjectId, ObjectId)>,
}

impl Manifest {
    pub fn new(ws: &str) -> Manifest {
        Manifest {
            version: MANIFEST_VERSION,
            workspace: ws.to_string(),
            tree: None,
            snapshot: None,
            materialised: Materialised::default(),
            boot: String::new(),
            running: None,
            only: None,
            quarantined: Vec::new(),
            pending: None,
            guard_checked: None,
            workspace_id: None,
        }
    }

    /// A new manifest for workspace `ws` as `repo` has it now.
    pub fn for_workspace(repo: &Repo, ws: &str) -> Manifest {
        Manifest { workspace_id: workspace_id(repo, ws), ..Manifest::new(ws) }
    }

    /// [`Manifest::only`] as a set (`None`: the whole tree).
    pub fn only_set(&self) -> Result<Option<SparseSet>> {
        match &self.only {
            None => Ok(None),
            Some(paths) => SparseSet::from_strings(paths),
        }
    }
}

/// The result of [`SandboxPaths::load_manifest`].
#[derive(Debug, Clone)]
pub enum Loaded {
    Missing,
    Corrupt(String),
    Found(Box<Manifest>),
}

/// Why the sandbox described by `loaded` must be rebuilt before workspace
/// `ws` can use it, if it must: `Some("")` for a sandbox that does not
/// exist yet, `Some(why)` for one that cannot be trusted, `None` to reuse
/// it.
pub fn rebuild_reason(repo: &Repo, paths: &SandboxPaths, ws: &str, loaded: &Loaded) -> Option<String> {
    let m = match loaded {
        Loaded::Missing => return Some(String::new()),
        Loaded::Corrupt(why) => return Some(format!("its manifest is unreadable ({why})")),
        Loaded::Found(m) => m,
    };
    if m.version != MANIFEST_VERSION {
        return Some(format!("its manifest has format {} (this vl writes {MANIFEST_VERSION})", m.version));
    }
    if m.workspace != ws {
        return Some(format!("its manifest belongs to workspace '{}'", m.workspace));
    }
    if m.workspace_id != workspace_id(repo, ws) {
        return Some(format!("it belongs to an earlier workspace named '{ws}' (removed, then made again)"));
    }
    if m.running.is_some() {
        return Some("the previous run did not finish (vl was killed or crashed)".into());
    }
    let boot = crate::lock::boot_identity();
    if boot.is_empty() || m.boot != boot {
        return Some("the machine has restarted since the last run".into());
    }
    if let Err(e) = m.only_set() {
        return Some(format!("its manifest names an invalid path ({e})"));
    }
    match std::fs::symlink_metadata(&paths.files) {
        Ok(md) if md.is_dir() => {}
        Ok(_) => return Some("its files directory was replaced".into()),
        Err(_) if m.tree.is_none() => return Some(String::new()),
        Err(_) => return Some("its files are missing".into()),
    }
    match m.tree {
        Some(t) if !repo.store().has(&t) => Some("the snapshot it holds is no longer in the repository".into()),
        _ => None,
    }
}

/// The identity of workspace `ws` in `repo` ([`crate::oplog::WorkspaceState::id`]).
pub fn workspace_id(repo: &Repo, ws: &str) -> Option<String> {
    repo.view().workspaces.get(ws).and_then(|w| w.id.clone())
}

/// Remove the sandbox's files, manifest and stat cache (the lock stays):
/// the next run rebuilds it. The manifest goes first, so a crash half way
/// leaves a sandbox the next run sees as new. Leftovers of earlier,
/// interrupted wipes go too.
pub fn wipe(paths: &SandboxPaths) -> io::Result<()> {
    for f in [MANIFEST_FILE, CACHE_FILE] {
        match std::fs::remove_file(paths.dir.join(f)) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
    }
    // Out of the way first: a run that rebuilds right after never sees a
    // half-removed tree under `files/`.
    if std::fs::symlink_metadata(&paths.files).is_ok() {
        let trash = paths
            .dir
            .join(format!("{TRASH_PREFIX}{}", hex::encode(crate::crypto::random_bytes::<4>())));
        std::fs::rename(&paths.files, &trash)?;
    }
    if let Ok(entries) = std::fs::read_dir(&paths.dir) {
        for e in entries.flatten() {
            if e.file_name().to_str().is_some_and(|n| n.starts_with(TRASH_PREFIX)) {
                remove_tree(&e.path())?;
            }
        }
    }
    Ok(())
}

/// Remove the whole sandbox directory, lock file included (`vl ws rm`).
/// The caller holds the lock; a run waiting for it notices that the lock
/// file is gone.
pub fn remove(paths: &SandboxPaths) -> io::Result<()> {
    wipe(paths)?;
    remove_tree(&paths.dir)
}

/// Every sandbox directory under `root`'s [`sandboxes_dir`], with the
/// workspace it belongs to (`None` for a name no workspace can have).
pub fn list(root: &Path) -> Vec<(Option<String>, SandboxPaths)> {
    let base = sandboxes_dir(root);
    let Ok(entries) = std::fs::read_dir(&base) else {
        return Vec::new();
    };
    let mut out: Vec<(Option<String>, SandboxPaths)> = entries
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_str()?.to_string();
            let dir = base.join(&name);
            Some((workspace_of(&name), SandboxPaths::at(dir)))
        })
        .collect();
    out.sort_by(|a, b| a.1.dir.cmp(&b.1.dir));
    out
}

/// Bring the sandbox's files from [`Manifest::tree`] to `tree`, rewriting
/// only what differs, with every rule of a checkout (files that hold
/// something else are kept and reported, nothing is written through a
/// symlink, …). Afterwards the manifest says the files are `tree`.
pub fn sync(repo: &Repo, fs: &SandboxFs, m: &mut Manifest, tree: &ObjectId, cache: &mut StatCache) -> Result<CheckoutReport> {
    sync_to(repo, fs, m, tree, None, cache)
}

/// [`sync`] to `tree` restricted to `only` (`None`: all of it). The files
/// go from what the manifest says they are ([`Manifest::tree`] restricted
/// to [`Manifest::only`]) to the new set: paths that leave the set are
/// removed (as checkout removes files: only if they hold what was
/// checked out), paths that join it are written, the rest is synced as
/// usual. Afterwards the manifest says the files are `tree` and `only`.
pub fn sync_to(
    repo: &Repo,
    fs: &SandboxFs,
    m: &mut Manifest,
    tree: &ObjectId,
    only: Option<&SparseSet>,
    cache: &mut StatCache,
) -> Result<CheckoutReport> {
    let store = repo.store();
    let from = match (m.tree, m.only_set()?) {
        (Some(t), Some(old)) => Some(restrict(store, &t, &old)?),
        (t, _) => t,
    };
    let to = match only {
        Some(set) => restrict(store, tree, set)?,
        None => *tree,
    };
    let report = repo.checkout_tree_recorded(fs, from.as_ref(), &to, &mut m.materialised, Some(cache))?;
    m.tree = Some(*tree);
    m.only = only.map(SparseSet::to_strings);
    Ok(report)
}

/// The files of the sparse working copy `fs` outside `set` that a full
/// working copy would record: what a command wrote outside its `--only`
/// paths. Files any of `policies` ignores or isolates are left out (build
/// output, `.env`: no full snapshot records them either), and so are
/// nested repositories, symlinks and other special files, crash debris and
/// `.veil`. Sorted.
///
/// After a command, pass the policy it started with and the one it left:
/// a file only counts if neither ignores or isolates it, so a command that
/// edits `.veilpolicy` never makes ignored files it did not write (a build
/// cache, a local config) look like its output (BUG-549).
pub fn strays(fs: &dyn StorageBackend, set: &SparseSet, policies: &[&Policy]) -> Result<Vec<VPath>> {
    let mut out = Vec::new();
    // (directory, entirely outside the set?)
    let mut stack = vec![(VPath::root(), false)];
    while let Some((dir, outside)) = stack.pop() {
        let listing = match fs.list_dir_full(&dir) {
            Ok(l) => l,
            Err(e) if e.is_not_found() => continue,
            Err(e) => return Err(e),
        };
        if outside && holds_repository(&listing) {
            continue;
        }
        for e in listing.entries {
            // Symlinks are never strays: never followed, never removed.
            if is_reserved_name(&e.name) || (e.kind == NodeKind::File && is_temp_name(&e.name)) || e.kind == NodeKind::Symlink {
                continue;
            }
            let p = dir.join(&e.name);
            let is_dir = e.kind == NodeKind::Dir;
            if !outside && set.contains(&p) {
                continue;
            }
            if !outside && is_dir && set.is_spine(&p) {
                stack.push((p, false));
                continue;
            }
            // Outside the set (a file where a spine directory belongs too).
            if policies.iter().any(|policy| matches!(policy.classify(&p, is_dir).tier, Tier::Ignored | Tier::Isolated)) {
                continue;
            }
            match is_dir {
                true => stack.push((p, true)),
                false => out.push(p),
            }
        }
    }
    out.sort();
    Ok(out)
}

/// Remove `paths` (from [`strays`]) from the sandbox, and the directories
/// that leaves empty outside the set. Returns the paths that could not be
/// removed, with why.
pub fn remove_strays(fs: &SandboxFs, set: &SparseSet, paths: &[VPath], cache: &mut StatCache) -> Vec<(VPath, String)> {
    let mut failed = Vec::new();
    let mut dirs = BTreeSet::new();
    for p in paths {
        cache.invalidate(p);
        match behind_special(fs, p) {
            Ok(false) => {}
            Ok(true) => continue,
            Err(e) => {
                failed.push((p.clone(), e.to_string()));
                continue;
            }
        }
        if let Err(e) = fs.remove_file(p) {
            failed.push((p.clone(), e.to_string()));
            continue;
        }
        let mut d = p.parent();
        while let Some(dir) = d.filter(|d| !d.is_root() && set.is_outside(d)) {
            d = dir.parent();
            dirs.insert(dir);
        }
    }
    // Deepest first.
    for d in dirs.into_iter().rev() {
        if let Ok(l) = fs.list_dir_full(&d) {
            if l.entries.is_empty() && l.special.is_empty() && l.unrepresentable.is_empty() {
                let _ = fs.remove_dir_all(&d);
            }
        }
    }
    failed
}

/// When [`vouch_written`] may wait out the racy window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VouchWait {
    /// Only if waiting costs less than re-reading the files would.
    IfCheaper,
    /// Always (tests, and callers that know the files are big).
    Always,
}

/// Rough cost of hashing what checkout wrote, in nanoseconds: what waiting
/// out the racy window to vouch for it instead may cost at most.
fn rehash_cost_ns(files: usize, bytes: u64) -> i64 {
    // ~1 GB/s to read and hash, plus ~25 µs of open/stat/close per file.
    (bytes as i64).saturating_add(files as i64 * 25_000)
}

/// Vouch, in the sandbox's stat cache, for the public files [`sync`] just
/// wrote into `fs` (they are `tree`'s), so that recording the sandbox after
/// the command does not read them back. A record is only trusted once its
/// stamp is older than the racy window (see [`crate::statcache`]); if
/// `wait` allows (by default: if waiting for that costs less than
/// re-reading the files would), this waits, then
/// stats every file again and vouches for those whose stamp has not moved
/// since the write. Sealed secret files are left to the builder,
/// which verifies their sealing. Returns the number of files vouched for.
pub fn vouch_written(
    store: &ObjectStore,
    fs: &SandboxFs,
    tree: &ObjectId,
    report: &CheckoutReport,
    cache: &mut StatCache,
    wait: VouchWait,
) -> Result<usize> {
    let written = fs.take_written();
    let Some(clock) = fs.stat_clock() else { return Ok(0) };
    let fallback: HashSet<&VPath> = report.from_fallback.iter().map(|(p, _)| p).collect();
    let mut candidates = Vec::new();
    let mut deadline = i64::MIN;
    let mut bytes = 0u64;
    for (path, w) in written {
        let (Some(meta), false) = (w.meta, fallback.contains(&path)) else { continue };
        let Some(stamp) = Stamp::of(&meta) else { continue };
        let entry = match lookup(store, tree, &path) {
            Ok(Some(e)) => e,
            _ => continue,
        };
        if !vouchable(&entry, &w.content, meta.executable) {
            continue;
        }
        deadline = deadline.max(stamp.trusted_from(clock.exact));
        bytes += meta.len;
        candidates.push((path, stamp, w.content));
    }
    if candidates.is_empty() {
        return Ok(0);
    }
    let needed = deadline.saturating_sub(clock.now);
    if wait == VouchWait::IfCheaper && needed > rehash_cost_ns(candidates.len(), bytes) {
        return Ok(0);
    }
    if needed > 0 {
        std::thread::sleep(std::time::Duration::from_nanos(needed as u64));
    }
    // Read before the files are stat'ed again: what they hold now is what
    // was written, unless their stamp moved.
    let Some(now) = fs.stat_clock() else { return Ok(0) };
    let key = CacheKey::compute(fs, &store.keys, now)?;
    let mut records = Vec::new();
    for (path, stamp, content) in candidates {
        let Some(meta) = fs.metadata(&path)? else { continue };
        if Stamp::of(&meta).as_ref() != Some(&stamp) {
            continue;
        }
        records.push((
            path,
            Record {
                stamp,
                verified_at: now.now,
                content,
                scanned_clean: false,
                sealed: None,
                // Written as recorded (`vouchable`: the entry's id is the
                // written content) against the tree the sandbox is
                // recorded against, so no line-ending fact is needed.
                eol: None,
            },
        ));
    }
    let n = records.len();
    cache.vouch(key, records);
    Ok(n)
}

/// Can a record of a file written with `content` vouch for `entry`? Only
/// for public entries whose id is that very content (plaintext by
/// construction; nothing to verify).
fn vouchable(entry: &TreeEntry, content: &ObjectId, executable: bool) -> bool {
    entry.kind == EntryKind::File
        && entry.visibility.is_public()
        && entry.id == *content
        && entry.executable == executable
}

/// Isolated files injected into a sandbox for one run.
#[derive(Debug, Default)]
pub struct Injection {
    /// Paths written.
    pub paths: Vec<VPath>,
    /// Paths not written, with why (a symlink or a directory is in the
    /// way, the name is invalid here, the filesystem refused).
    pub skipped: Vec<(String, String)>,
    /// What was at each written path before (content, executable).
    stash: HashMap<VPath, (Vec<u8>, bool)>,
    /// The guard the snapshot after the run applies.
    pub secrets: InjectedSecrets,
}

/// Write the vault's local-only files (`files`: path and content) into the
/// sandbox, remembering what each one replaces. Never through or over a
/// symlink or a directory. The guard covers every file given, written or
/// not. [`plan_injection`] then [`write_injection`], with nothing in
/// between.
pub fn inject(fs: &SandboxFs, files: &[(String, Vec<u8>)]) -> Result<Injection> {
    let mut inj = plan_injection(fs, files)?;
    write_injection(fs, &mut inj, files);
    Ok(inj)
}

/// What [`inject`] would do: the paths it would write ([`Injection::paths`])
/// and what they hold now (the stash), without writing anything. A caller
/// that must survive its own death saves this ([`Injection::to_saved`])
/// before [`write_injection`].
pub fn plan_injection(fs: &SandboxFs, files: &[(String, Vec<u8>)]) -> Result<Injection> {
    let mut inj = Injection {
        secrets: InjectedSecrets::from_files(files.iter().map(|(p, d)| (p.as_str(), d.as_slice()))),
        ..Default::default()
    };
    for (p, _) in files {
        let vp = match VPath::new(p) {
            Ok(vp) if !vp.is_root() => vp,
            _ => {
                inj.skipped.push((p.clone(), "not a valid path".into()));
                continue;
            }
        };
        if behind_special(fs, &vp)? {
            inj.skipped.push((p.clone(), "a symlink or special file is in the way".into()));
            continue;
        }
        match fs.metadata(&vp)? {
            Some(m) if m.kind == NodeKind::Dir => {
                inj.skipped.push((p.clone(), "a directory is in the way".into()));
                continue;
            }
            Some(m) => match fs.read(&vp) {
                Ok(old) => {
                    inj.stash.insert(vp.clone(), (old, m.executable));
                }
                Err(e) => {
                    inj.skipped.push((p.clone(), format!("the file there cannot be read: {e}")));
                    continue;
                }
            },
            None => {}
        }
        inj.paths.push(vp);
    }
    Ok(inj)
}

/// Write the files [`plan_injection`] planned. A path that cannot be
/// written gets back what it held and moves to [`Injection::skipped`].
pub fn write_injection(fs: &SandboxFs, inj: &mut Injection, files: &[(String, Vec<u8>)]) {
    let planned = std::mem::take(&mut inj.paths);
    for vp in planned {
        let Some((p, data)) = files.iter().find(|(p, _)| VPath::new(p).is_ok_and(|q| q == vp)) else { continue };
        match fs.write(&vp, data) {
            Ok(()) => inj.paths.push(vp),
            Err(e) => {
                // Put back what was there, if the write got that far.
                if let Some((old, exec)) = inj.stash.remove(&vp) {
                    let _ = fs.write(&vp, &old).and_then(|_| fs.set_executable(&vp, exec));
                }
                inj.skipped.push((p.clone(), e.to_string()));
            }
        }
    }
}

/// An [`Injection`] as the guard file keeps it (see [`Guard`]), so that a
/// run that dies after injecting can still be cleaned up exactly.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct SavedInjection {
    /// The run ([`Pending::run`]).
    pub run: String,
    /// The paths written (or about to be).
    pub paths: Vec<String>,
    /// What each held before: path, hex content, executable.
    #[serde(default)]
    pub stash: Vec<(String, String, bool)>,
}

impl Injection {
    /// What the guard file keeps of this injection.
    pub fn to_saved(&self, run: &str) -> SavedInjection {
        let mut stash: Vec<(String, String, bool)> = self
            .stash
            .iter()
            .map(|(p, (d, x))| (p.as_str().to_string(), hex::encode(d), *x))
            .collect();
        stash.sort();
        SavedInjection {
            run: run.to_string(),
            paths: self.paths.iter().map(|p| p.as_str().to_string()).collect(),
            stash,
        }
    }

    /// The injection `saved` describes, guarded by `secrets`.
    pub fn from_saved(saved: &SavedInjection, secrets: InjectedSecrets) -> Injection {
        let mut inj = Injection {
            secrets,
            ..Default::default()
        };
        inj.paths = saved.paths.iter().filter_map(|p| VPath::new(p).ok()).collect();
        for (p, d, x) in &saved.stash {
            if let (Ok(vp), Ok(d)) = (VPath::new(p), hex::decode(d)) {
                inj.stash.insert(vp, (d, *x));
            }
        }
        inj
    }

    /// What path `p` held before the injection (content, executable).
    pub fn stashed(&self, p: &VPath) -> Option<(&[u8], bool)> {
        self.stash.get(p).map(|(d, x)| (d.as_slice(), *x))
    }
}

/// What [`remove_injected`] did.
#[derive(Debug, Default)]
pub struct Cleanup {
    /// Paths put back as they were before the run (or as `recorded`).
    pub restored: Vec<VPath>,
    /// Paths removed.
    pub removed: Vec<VPath>,
    /// Paths that could not be cleaned, with the error.
    pub failed: Vec<(VPath, String)>,
}

/// After a run with `inj` was recorded as tree `recorded` (from `synced`,
/// the tree the sandbox was synced to before the run, with `report`): take
/// the injected files out of the sandbox again, and every file the builder
/// quarantined because it holds an injected secret. Each such path ends up
/// as:
///
/// * what the snapshot recorded, if it recorded something new there (the
///   command rewrote the file without the secret: it is the workspace's
///   now, and stays);
/// * otherwise what was there before the injection, if anything was;
/// * otherwise `recorded`'s version of a tracked file;
/// * otherwise nothing (and directories it leaves empty go too).
pub fn remove_injected(
    store: &ObjectStore,
    fs: &SandboxFs,
    synced: &ObjectId,
    recorded: &ObjectId,
    inj: &Injection,
    report: &BuildReport,
    cache: &mut StatCache,
) -> Result<Cleanup> {
    let mut targets: BTreeSet<VPath> = inj.paths.iter().cloned().collect();
    for (p, findings) in &report.quarantined {
        if findings.iter().any(|f| f.rule == INJECTED_RULE) {
            targets.insert(p.clone());
        }
    }
    let mut out = Cleanup::default();
    for p in targets {
        cache.invalidate(&p);
        if let Err(e) = clean_one(store, fs, synced, recorded, inj, &p, &mut out) {
            out.failed.push((p, e.to_string()));
        }
    }
    Ok(out)
}

fn clean_one(
    store: &ObjectStore,
    fs: &SandboxFs,
    synced: &ObjectId,
    recorded: &ObjectId,
    inj: &Injection,
    p: &VPath,
    out: &mut Cleanup,
) -> Result<()> {
    if behind_special(fs, p)? {
        return Ok(());
    }
    let entry_at = |tree: &ObjectId| match lookup(store, tree, p) {
        Ok(e) => Ok(e),
        Err(e) if e.is_unreadable() => Ok(None),
        Err(e) => Err(e),
    };
    let now = entry_at(recorded)?;
    let current = fs.metadata(p)?;
    if now != entry_at(synced)? && current.as_ref().is_some_and(|m| m.kind == NodeKind::File) {
        // Recorded from this very file (the guard found no injected secret
        // in it): it is the workspace's content now.
        if let Some(e) = &now {
            if e.kind == EntryKind::File && store.read_entry(e).is_ok_and(|d| fs.read(p).is_ok_and(|have| have == d)) {
                return Ok(());
            }
        }
    }
    if current.as_ref().is_some_and(|m| m.kind == NodeKind::Dir) {
        // The command put a directory there; nothing of ours to clean.
        return Ok(());
    }
    if let Some((old, exec)) = inj.stash.get(p) {
        fs.write(p, old)?;
        fs.set_executable(p, *exec)?;
        out.restored.push(p.clone());
        return Ok(());
    }
    if let Some(e) = now.filter(|e| e.kind == EntryKind::File) {
        if let Ok(data) = store.read_entry(&e) {
            fs.write(p, &data)?;
            fs.set_executable(p, e.executable)?;
            out.restored.push(p.clone());
            return Ok(());
        }
    }
    if current.is_some() {
        fs.remove_file(p)?;
        out.removed.push(p.clone());
        let mut dir = p.parent();
        while let Some(d) = dir.filter(|d| !d.is_root()) {
            match fs.list_dir_full(&d) {
                Ok(l) if l.entries.is_empty() && l.special.is_empty() && l.unrepresentable.is_empty() => {
                    fs.remove_dir_all(&d)?;
                }
                _ => break,
            }
            dir = d.parent();
        }
    }
    Ok(())
}

// ---- the injected-secret guard -------------------------------------------------

/// The injected-secret guard of a sandbox ([`GUARD_FILE`], sealed under
/// the `local` scope like the vault it copies from).
///
/// The guard of a `--with-isolated` run is not dropped after the run:
/// anything holding an injected value that is in the sandbox later (a
/// background process the command started that writes the environment to
/// a log after `vl` returned, a copy a later command moves) must not be
/// recorded by a later run that was not given the secrets (BUG-547). So
/// every isolated file ever injected into the sandbox is kept here, and
/// every recording of the sandbox applies the guard, until `vl ws rm`.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct Guard {
    /// Every file injected so far: path, hex content (deduplicated).
    #[serde(default)]
    pub files: Vec<(String, String)>,
    /// The injection of a run whose cleanup has not finished.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub injection: Option<SavedInjection>,
}

impl Guard {
    /// Add `files` (path, content) to the guard.
    pub fn add(&mut self, files: &[(String, Vec<u8>)]) {
        for (p, d) in files {
            let e = (p.clone(), hex::encode(d));
            if !self.files.contains(&e) {
                self.files.push(e);
            }
        }
    }

    /// The guard as the builder applies it.
    pub fn secrets(&self) -> InjectedSecrets {
        let files: Vec<(&str, Vec<u8>)> = self
            .files
            .iter()
            .filter_map(|(p, d)| Some((p.as_str(), hex::decode(d).ok()?)))
            .collect();
        InjectedSecrets::from_files(files.iter().map(|(p, d)| (*p, d.as_slice())))
    }
}

impl SandboxPaths {
    fn guard_path() -> VPath {
        VPath::new(GUARD_FILE).expect("valid")
    }

    /// The sandbox's guard, if it ever held injected secrets. An error if
    /// there is one this identity cannot open: recording without it could
    /// record a secret.
    pub fn load_guard(&self, repo: &Repo) -> Result<Option<Guard>> {
        let Some(raw) = self.meta().read_opt(&Self::guard_path())? else { return Ok(None) };
        let key = repo.keys().require(LOCAL_SCOPE)?;
        let plain = Envelope::from_bytes(&raw).and_then(|e| e.open(&key)).map_err(|_| {
            VeilError::Crypto(format!(
                "the injected-secret guard of the sandbox ({}) cannot be opened with this identity's key \
                 (was the identity replaced?); nothing in the sandbox is recorded without it. \
                 `vl ws rm --force` removes the sandbox",
                self.dir.join(GUARD_FILE).display()
            ))
        })?;
        Ok(Some(serde_json::from_slice(&plain)?))
    }

    /// Write the guard, sealed, atomically and durably.
    pub fn save_guard(&self, repo: &Repo, g: &Guard) -> Result<()> {
        let key = repo.keys().require(LOCAL_SCOPE)?;
        let env = Envelope::seal(&key, LOCAL_SCOPE, &serde_json::to_vec(g)?, false)?;
        self.meta().write(&Self::guard_path(), &env.to_bytes())
    }
}

/// Now, in nanoseconds since the epoch (wall clock, as file times are).
pub fn now_ns() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos().min(i64::MAX as u128) as i64)
}

/// Slack for file times on coarse clocks (some filesystems keep whole
/// seconds, the kernel's file clock lags the wall clock by a tick).
const CTIME_SLACK_NS: i64 = 2_000_000_000;
/// Files larger than this are not read by [`scrub`] (reported instead).
pub const MAX_SCRUB: u64 = 1 << 30;

fn ctime_ns(md: &std::fs::Metadata) -> i64 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        md.ctime().saturating_mul(1_000_000_000).saturating_add(md.ctime_nsec())
    }
    #[cfg(not(unix))]
    {
        md.modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(i64::MAX, |d| d.as_nanos().min(i64::MAX as u128) as i64)
    }
}

/// What [`scrub`] found.
#[derive(Debug, Default)]
pub struct Scrub {
    /// Files holding an injected value (relative to the sandbox's root).
    pub found: Vec<PathBuf>,
    /// Files it could not check, with why.
    pub unchecked: Vec<(PathBuf, String)>,
}

/// Every regular file under `root` (the sandbox's files, symlinks never
/// followed) that holds one of `secrets`, wherever it is: ignored and
/// isolated paths (`target/`, `.env.bak`), outside a sparse set, in a
/// nested repository, under a name that is not UTF-8. The builder only
/// guards what it records; these are never recorded but stay readable by
/// every later command (BUG-546).
///
/// Only files changed since `since` (ns, wall clock; their ctime, which
/// no command can set back) are read: nothing older can hold a value
/// injected since. Files `cache` vouches for (recorded or checked out
/// content, unchanged since) and `skip` (the injected files themselves,
/// which [`remove_injected`] takes care of) are left out.
pub fn scrub(fs: &SandboxFs, since: i64, secrets: &InjectedSecrets, cache: &StatCache, skip: &[VPath]) -> Scrub {
    let mut out = Scrub::default();
    let since = since.saturating_sub(CTIME_SLACK_NS);
    let root = fs.root().to_path_buf();
    let mut stack = vec![PathBuf::new()];
    while let Some(rel) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(root.join(&rel)) else { continue };
        for e in rd.flatten() {
            let r = rel.join(e.file_name());
            let Ok(md) = std::fs::symlink_metadata(root.join(&r)) else { continue };
            if md.is_dir() {
                stack.push(r);
                continue;
            }
            if !md.is_file() || ctime_ns(&md) < since {
                continue;
            }
            let vp = r.to_str().and_then(|s| VPath::new(&s.replace(std::path::MAIN_SEPARATOR, "/")).ok());
            if let Some(vp) = &vp {
                if skip.contains(vp) {
                    continue;
                }
                if let Ok(Some(m)) = fs.metadata(vp) {
                    if cache.trusted(vp, &m).is_some() {
                        continue;
                    }
                }
            }
            if md.len() > MAX_SCRUB {
                out.unchecked.push((r, format!("larger than {} MiB", MAX_SCRUB >> 20)));
                continue;
            }
            match std::fs::read(root.join(&r)) {
                Ok(d) if secrets.find(&d).is_some() => out.found.push(r),
                Ok(_) => {}
                Err(e) => out.unchecked.push((r, e.to_string())),
            }
        }
    }
    out.found.sort();
    out
}

/// Take the files [`scrub`] found out of the sandbox: a file `recorded`
/// (the tree the sandbox was just recorded as) has gets its recorded
/// version back, any other is removed. A file whose recorded version is
/// this very content, or holds an injected value itself, is left (history
/// has it already).
pub fn clean_copies(
    store: &ObjectStore,
    fs: &SandboxFs,
    recorded: &ObjectId,
    secrets: &InjectedSecrets,
    found: &[PathBuf],
    cache: &mut StatCache,
) -> Cleanup {
    let mut out = Cleanup::default();
    for r in found {
        let full = fs.root().join(r);
        let vp = r.to_str().and_then(|s| VPath::new(&s.replace(std::path::MAIN_SEPARATOR, "/")).ok());
        let result = (|| -> Result<()> {
            if let Some(vp) = &vp {
                cache.invalidate(vp);
                if behind_special(fs, vp)? {
                    return Ok(());
                }
                let entry = match lookup(store, recorded, vp) {
                    Ok(e) => e,
                    Err(e) if e.is_unreadable() => None,
                    Err(e) => return Err(e),
                };
                if let Some(e) = entry.filter(|e| e.kind == EntryKind::File) {
                    if let Ok(data) = store.read_entry(&e) {
                        if fs.read(vp).is_ok_and(|have| have == data) || secrets.find(&data).is_some() {
                            return Ok(());
                        }
                        fs.write(vp, &data)?;
                        fs.set_executable(vp, e.executable)?;
                        out.restored.push(vp.clone());
                        return Ok(());
                    }
                }
                fs.remove_file(vp)?;
                out.removed.push(vp.clone());
                return Ok(());
            }
            // A name Veil cannot represent: never recorded, simply removed.
            std::fs::remove_file(&full).map_err(|e| VeilError::Io {
                path: full.display().to_string(),
                source: e,
            })
        })();
        if let Err(e) = result {
            out.failed.push((vp.unwrap_or_else(VPath::root), format!("{}: {e}", r.display())));
        }
    }
    out
}

/// One injected file as the reaper of a run knows it: where, what was
/// injected (blob id), and what it replaced (content, executable).
pub type ReaperEntry = (VPath, ObjectId, Option<(Vec<u8>, bool)>);

/// For a run that died after injecting (the reaper): take out each
/// injected file that still holds exactly what was injected, putting back
/// what it replaced. Nothing else is touched: whatever the command wrote
/// is its output, recorded (under the guard) by the next run.
pub fn take_out_unchanged(fs: &SandboxFs, entries: &[ReaperEntry]) {
    for (p, id, stash) in entries {
        if behind_special(fs, p).unwrap_or(true) {
            continue;
        }
        if !fs.read(p).is_ok_and(|d| crate::object::Object::blob_id(&d) == *id) {
            continue;
        }
        let _ = match stash {
            Some((d, x)) => fs.write(p, d).and_then(|_| fs.set_executable(p, *x)),
            None => fs.remove_file(p),
        };
    }
}

// ---- the policy of a sandbox ---------------------------------------------------

/// A sandbox `inner` whose `.veilpolicy` is not a regular, readable file
/// (deleted, unreadable, a symlink, a directory), seen with the
/// `.veilpolicy` of `tree`, the tree it was synced from, in its place.
///
/// In the project directory such a policy file is never the member's edit:
/// the accepted policy keeps guarding until `vl policy accept` (BUG-106,
/// BUG-107). A sandbox has no accepted policy of its own that could keep
/// guarding its next run, so it keeps the recorded one: the snapshot
/// applies it and records it unchanged. Deleting `.veilpolicy` in a
/// sandbox thus never exposes a sealed secret file (BUG-553), and an
/// unreadable one never fails the recording (BUG-554). Only a regular,
/// readable `.veilpolicy` is an edit of the policy, and one that weakens
/// the recorded policy is held back by the recording (BUG-560, see
/// `SnapshotOptions::policy_from_command`).
#[derive(Debug)]
pub struct PolicyPin<'a> {
    inner: &'a dyn StorageBackend,
    /// `Some` when the pin applies: the tree's policy (content, executable,
    /// entry id), `None` inside for a tree without one.
    pinned: Option<Option<(Vec<u8>, bool, ObjectId)>>,
    /// Why the pin applies (for the warning).
    pub why: Option<String>,
    /// The sandbox has no `.veilpolicy` at all (it was deleted).
    pub deleted: bool,
}

impl<'a> PolicyPin<'a> {
    pub fn new(inner: &'a dyn StorageBackend, store: &ObjectStore, tree: &ObjectId) -> Result<PolicyPin<'a>> {
        let why = match crate::policy::read_policy_file(inner)? {
            PolicyFile::File(_) => None,
            PolicyFile::Absent => Some("was deleted".to_string()),
            PolicyFile::Linked(_) => Some("is a symlink".to_string()),
            PolicyFile::Unavailable(why) => Some(format!("cannot be read ({why})")),
        };
        let Some(why) = why else {
            return Ok(PolicyPin { inner, pinned: None, why: None, deleted: false });
        };
        let entry = match lookup(store, tree, &VPath::new(POLICY_FILE)?) {
            Ok(e) => e,
            Err(e) if e.is_unreadable() => return Ok(PolicyPin { inner, pinned: None, why: None, deleted: false }),
            Err(e) => return Err(e),
        };
        let pinned = match entry {
            None => None,
            Some(e) if e.kind == EntryKind::File => match store.read_entry(&e) {
                Ok(d) => Some((d, e.executable, e.id)),
                // Nothing to keep that this reader can read: as before.
                Err(_) => return Ok(PolicyPin { inner, pinned: None, why: None, deleted: false }),
            },
            Some(_) => return Ok(PolicyPin { inner, pinned: None, why: None, deleted: false }),
        };
        let deleted = why == "was deleted";
        // A sandbox with no policy file, synced from a tree with none.
        if pinned.is_none() && deleted {
            return Ok(PolicyPin { inner, pinned: None, why: None, deleted: false });
        }
        Ok(PolicyPin {
            inner,
            pinned: Some(pinned),
            why: Some(why),
            deleted,
        })
    }

    /// The recorded policy's text, if the pin applies and there is one.
    pub fn pinned_text(&self) -> Option<&[u8]> {
        self.pinned.as_ref()?.as_ref().map(|(d, _, _)| d.as_slice())
    }

    fn pins(&self, p: &VPath) -> Option<&Option<(Vec<u8>, bool, ObjectId)>> {
        self.pinned.as_ref().filter(|_| p.as_str() == POLICY_FILE)
    }

    fn refuse(&self, p: &VPath) -> Result<()> {
        match self.pins(p) {
            Some(_) => Err(VeilError::ReadOnly),
            None => Ok(()),
        }
    }
}

impl StorageBackend for PolicyPin<'_> {
    fn kind(&self) -> &'static str {
        self.inner.kind()
    }

    fn read(&self, path: &VPath) -> Result<Vec<u8>> {
        match self.pins(path) {
            Some(Some((d, _, _))) => Ok(d.clone()),
            Some(None) => Err(VeilError::NotFound(path.to_string())),
            None => self.inner.read(path),
        }
    }

    fn read_through_link(&self, path: &VPath, limit: u64) -> Result<Option<(String, Vec<u8>)>> {
        match self.pins(path) {
            Some(_) => Ok(None),
            None => self.inner.read_through_link(path, limit),
        }
    }

    fn read_link(&self, path: &VPath) -> Result<Vec<u8>> {
        match self.pins(path) {
            Some(_) => Err(VeilError::InvalidPath(format!("{path} is not a symlink"))),
            None => self.inner.read_link(path),
        }
    }

    fn write_link(&self, path: &VPath, target: &[u8]) -> Result<()> {
        self.refuse(path)?;
        self.inner.write_link(path, target)
    }

    fn supports_links(&self) -> bool {
        self.inner.supports_links()
    }

    fn read_range(&self, path: &VPath, offset: u64, len: usize) -> Result<Vec<u8>> {
        match self.pins(path) {
            Some(_) => {
                let data = self.read(path)?;
                crate::vfs::slice_range(path, &data, offset, len).map(<[u8]>::to_vec)
            }
            None => self.inner.read_range(path, offset, len),
        }
    }

    fn write(&self, path: &VPath, data: &[u8]) -> Result<()> {
        self.refuse(path)?;
        self.inner.write(path, data)
    }

    fn write_unsynced(&self, path: &VPath, data: &[u8]) -> Result<()> {
        self.refuse(path)?;
        self.inner.write_unsynced(path, data)
    }

    fn sync_barrier(&self) -> Result<()> {
        self.inner.sync_barrier()
    }

    fn create_new(&self, path: &VPath, data: &[u8]) -> Result<bool> {
        self.refuse(path)?;
        self.inner.create_new(path, data)
    }

    fn remove_file(&self, path: &VPath) -> Result<()> {
        self.refuse(path)?;
        self.inner.remove_file(path)
    }

    fn remove_dir_all(&self, path: &VPath) -> Result<()> {
        self.refuse(path)?;
        self.inner.remove_dir_all(path)
    }

    fn create_dir_all(&self, path: &VPath) -> Result<()> {
        self.refuse(path)?;
        self.inner.create_dir_all(path)
    }

    fn list_dir(&self, path: &VPath) -> Result<Vec<crate::vfs::DirEntry>> {
        Ok(self.list_dir_full(path)?.entries)
    }

    fn list_dir_full(&self, path: &VPath) -> Result<crate::vfs::DirListing> {
        let mut l = self.inner.list_dir_full(path)?;
        if let (true, Some(pinned)) = (path.is_root(), &self.pinned) {
            l.entries.retain(|e| e.name != POLICY_FILE);
            l.special.retain(|n| n != POLICY_FILE);
            if pinned.is_some() {
                l.entries.push(crate::vfs::DirEntry {
                    name: POLICY_FILE.to_string(),
                    kind: NodeKind::File,
                });
                l.entries.sort_by(|a, b| a.name.cmp(&b.name));
            }
        }
        Ok(l)
    }

    fn metadata(&self, path: &VPath) -> Result<Option<crate::vfs::Metadata>> {
        match self.pins(path) {
            Some(Some((d, x, _))) => Ok(Some(crate::vfs::Metadata::unstamped(NodeKind::File, d.len() as u64, *x))),
            Some(None) => Ok(None),
            None => self.inner.metadata(path),
        }
    }

    fn set_executable(&self, path: &VPath, executable: bool) -> Result<()> {
        self.refuse(path)?;
        self.inner.set_executable(path, executable)
    }

    fn known_id(&self, path: &VPath) -> Option<ObjectId> {
        match self.pins(path) {
            Some(p) => p.as_ref().map(|(_, _, id)| *id),
            None => self.inner.known_id(path),
        }
    }

    fn clone_known(&self, path: &VPath, id: &ObjectId) -> Result<bool> {
        self.refuse(path)?;
        self.inner.clone_known(path, id)
    }

    fn clones(&self) -> bool {
        self.inner.clones()
    }

    fn stat_clock(&self) -> Option<crate::vfs::StatClock> {
        self.inner.stat_clock()
    }

    fn name_folding(&self) -> crate::vfs::NameFolding {
        self.inner.name_folding()
    }

    fn special_at(&self, path: &VPath) -> Result<Option<&'static str>> {
        match self.pins(path) {
            Some(_) => Ok(None),
            None => self.inner.special_at(path),
        }
    }
}

// ---- rebuilding without losing work --------------------------------------------

/// What [`set_aside`] did with the files of a sandbox about to be rebuilt.
#[derive(Debug)]
pub enum SetAside {
    /// There was nothing to keep.
    Nothing,
    /// The files that are unrecorded work (quarantined files, files outside
    /// a sparse set that the tree does not have as they are) are to be
    /// copied into the rebuilt sandbox ([`reimport`]) from `from`.
    Reimport {
        from: PathBuf,
        paths: Vec<VPath>,
        /// The quarantined files among them.
        quarantined: Vec<String>,
        /// Other files differed from both the tree the sandbox held and the
        /// one it is rebuilt to (hand edits, or files a crash tore): `from`
        /// is kept whole after the re-import instead of being removed.
        keep_whole: bool,
    },
    /// The previous files were moved, whole, to `dir`: they may hold work
    /// in no snapshot that Veil cannot tell from torn or unknown files (the
    /// output of a run that cannot be recorded, a sandbox whose manifest
    /// cannot be read).
    Kept { dir: PathBuf },
}

/// Get the files of the sandbox out of the way of a rebuild without
/// deleting anything that may be unrecorded work (BUG-548): a rebuild
/// never deletes quarantined files, hand edits a sparse set keeps outside
/// it, or a command's unrecorded output. Recorded content (the tree's
/// files), ignored and isolated output (build caches, `.env`) and
/// injected files go. The manifest and stat cache go too, after the files
/// (a crash half way leaves a sandbox the next run rebuilds again, and a
/// re-import that was interrupted is kept whole).
///
/// `target`: the tree the sandbox is rebuilt to. A file that is neither the
/// previous tree's nor `target`'s (a hand edit in the sandbox, or a file a
/// power loss tore, which Veil cannot tell apart) keeps the previous files
/// whole.
pub fn set_aside(repo: &Repo, paths: &SandboxPaths, ws: &str, loaded: &Loaded, target: Option<&ObjectId>) -> Result<SetAside> {
    let io = |e: io::Error| VeilError::Io {
        path: paths.files.display().to_string(),
        source: e,
    };
    // An earlier re-import that never finished: keep it whole.
    if let Ok(entries) = std::fs::read_dir(&paths.dir) {
        for e in entries.flatten() {
            if e.file_name().to_str().is_some_and(|n| n.starts_with(REBUILD_PREFIX)) {
                std::fs::rename(e.path(), kept_dir(paths)).map_err(io)?;
            }
        }
    }
    let result = match std::fs::symlink_metadata(&paths.files) {
        Err(_) => SetAside::Nothing,
        Ok(md) if !md.is_dir() => {
            // A symlink or file where the directory belongs: never followed.
            std::fs::remove_file(&paths.files).map_err(io)?;
            SetAside::Nothing
        }
        Ok(_) if std::fs::read_dir(&paths.files).map_err(io)?.next().is_none() => {
            std::fs::remove_dir(&paths.files).map_err(io)?;
            SetAside::Nothing
        }
        Ok(_) => match loaded {
            // Only this very workspace's work is re-imported: another one's
            // (an earlier workspace of the same name) is kept aside whole.
            Loaded::Found(m) if m.pending.is_none() && m.version == MANIFEST_VERSION && m.workspace == ws && m.workspace_id == workspace_id(repo, ws) => {
                let (keep, quarantined, differing) = unrecorded_work(repo, paths, m, target)?;
                if keep.is_empty() && differing {
                    let dir = kept_dir(paths);
                    std::fs::rename(&paths.files, &dir).map_err(io)?;
                    SetAside::Kept { dir }
                } else if keep.is_empty() {
                    trash(paths).map_err(io)?;
                    SetAside::Nothing
                } else {
                    let from = paths
                        .dir
                        .join(format!("{REBUILD_PREFIX}{}", hex::encode(crate::crypto::random_bytes::<4>())));
                    std::fs::rename(&paths.files, &from).map_err(io)?;
                    SetAside::Reimport {
                        from,
                        paths: keep,
                        quarantined,
                        keep_whole: differing,
                    }
                }
            }
            _ => {
                let dir = kept_dir(paths);
                std::fs::rename(&paths.files, &dir).map_err(io)?;
                SetAside::Kept { dir }
            }
        },
    };
    wipe(paths).map_err(io)?;
    Ok(result)
}

fn kept_dir(paths: &SandboxPaths) -> PathBuf {
    paths.dir.join(format!(
        "{KEPT_PREFIX}{}-{}",
        crate::now_millis(),
        hex::encode(crate::crypto::random_bytes::<2>())
    ))
}

/// Move `files/` to the trash (removed by [`wipe`]).
fn trash(paths: &SandboxPaths) -> io::Result<()> {
    let trash = paths
        .dir
        .join(format!("{TRASH_PREFIX}{}", hex::encode(crate::crypto::random_bytes::<4>())));
    std::fs::rename(&paths.files, trash)
}

/// The files of the sandbox `m` describes that are unrecorded work to
/// re-import, the quarantined ones among them, and whether other files
/// (in the set) differ from both `m`'s tree and `target`.
fn unrecorded_work(repo: &Repo, paths: &SandboxPaths, m: &Manifest, target: Option<&ObjectId>) -> Result<(Vec<VPath>, Vec<String>, bool)> {
    let fs = SandboxFs::new(&paths.files, None, false);
    let mut keep: BTreeSet<VPath> = BTreeSet::new();
    let mut quarantined = Vec::new();
    for q in &m.quarantined {
        if let Ok(p) = VPath::new(q) {
            if !behind_special(&fs, &p)? && fs.metadata(&p)?.is_some_and(|md| md.kind == NodeKind::File) {
                keep.insert(p);
                quarantined.push(q.clone());
            }
        }
    }
    if let Ok(Some(set)) = m.only_set() {
        let (policy, _) = Policy::load_or_accepted(&fs, None)?;
        keep.extend(strays(&fs, &set, &[&policy])?);
    }
    // What is the tree's own content is no work of anyone's.
    let store = repo.store();
    let tree = m.tree.filter(|t| store.has(t));
    let mut out = Vec::new();
    for p in keep {
        if let Some(t) = &tree {
            if let Ok(Some(e)) = lookup(store, t, &p) {
                let same = e.kind == EntryKind::File
                    && e.visibility.is_public()
                    && fs.metadata(&p)?.is_some_and(|md| md.executable == e.executable)
                    && fs.read(&p).is_ok_and(|d| crate::object::Object::blob_id(&d) == e.id);
                if same && !quarantined.iter().any(|q| q == p.as_str()) {
                    continue;
                }
            }
        }
        out.push(p);
    }
    let differing = differs_from_trees(store, &fs, paths, m, tree.as_ref(), target, &out)?;
    Ok((out, quarantined, differing))
}

/// Does a file of the sandbox `fs` (inside `m`'s set; recorded under its
/// policy) hold something that is neither `old`'s nor `target`'s version
/// of it? Files in `skip` (re-imported anyway) do not count. The old stat
/// cache spares reading files it vouches for.
fn differs_from_trees(
    store: &ObjectStore,
    fs: &SandboxFs,
    paths: &SandboxPaths,
    m: &Manifest,
    old: Option<&ObjectId>,
    target: Option<&ObjectId>,
    skip: &[VPath],
) -> Result<bool> {
    let set = m.only_set().ok().flatten();
    let (policy, _) = Policy::load_or_accepted(fs, None)?;
    let cache = paths.load_cache();
    let entry = |tree: Option<&ObjectId>, p: &VPath| -> Option<TreeEntry> {
        lookup(store, tree?, p).ok().flatten().filter(|e| e.kind == EntryKind::File)
    };
    let mut stack = vec![VPath::root()];
    while let Some(dir) = stack.pop() {
        let listing = match fs.list_dir_full(&dir) {
            Ok(l) => l,
            Err(e) if e.is_not_found() => continue,
            Err(e) => return Err(e),
        };
        if !dir.is_root() && holds_repository(&listing) {
            continue;
        }
        for e in listing.entries {
            if is_reserved_name(&e.name) || (e.kind == NodeKind::File && is_temp_name(&e.name)) {
                continue;
            }
            let p = dir.join(&e.name);
            let is_dir = e.kind == NodeKind::Dir;
            if set.as_ref().is_some_and(|s| s.is_outside(&p) || (!is_dir && !s.contains(&p))) {
                continue;
            }
            if matches!(policy.classify(&p, is_dir).tier, Tier::Ignored | Tier::Isolated) {
                continue;
            }
            if is_dir {
                stack.push(p);
                continue;
            }
            if skip.contains(&p) {
                continue;
            }
            if e.kind == NodeKind::Symlink {
                // A link (format 5) is work unless it is one of the trees'
                // links, target for target.
                let have = fs.read_link(&p).ok();
                let same_link = |tree: Option<&ObjectId>| -> bool {
                    let Some(tree) = tree else { return false };
                    let e = lookup(store, tree, &p).ok().flatten().filter(|e| e.kind == EntryKind::Symlink);
                    have.is_some() && e.and_then(|e| store.read_entry(&e).ok()) == have
                };
                if !same_link(old) && !same_link(target) {
                    return Ok(true);
                }
                continue;
            }
            let rec = fs.metadata(&p)?.and_then(|md| cache.trusted(&p, &md).cloned());
            let mut have = rec.as_ref().map(|r| r.content);
            let mut same = |e: Option<TreeEntry>| -> bool {
                let Some(e) = e else { return false };
                // The stat cache knows the sealed object: no need to decrypt.
                if rec.as_ref().is_some_and(|r| r.sealed.as_ref().is_some_and(|(_, id)| *id == e.id)) {
                    return true;
                }
                if have.is_none() {
                    have = fs.read(&p).ok().map(|d| crate::object::Object::blob_id(&d));
                }
                let Some(h) = have else { return true };
                match e.visibility.is_public() {
                    true => e.id == h,
                    false => store.read_entry(&e).is_ok_and(|d| crate::object::Object::blob_id(&d) == h),
                }
            };
            if !same(entry(old, &p)) && !same(entry(target, &p)) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Copy `paths` from `from` (set aside by [`set_aside`]) into the rebuilt
/// sandbox `fs`, over what the rebuild checked out (they are the newer
/// work), never through a symlink. Then `from` goes, unless `keep_whole`
/// or something could not be copied: it is then kept whole, and returned
/// with the failures.
pub fn reimport(
    fs: &SandboxFs,
    from: &Path,
    paths: &[VPath],
    keep_whole: bool,
    cache: &mut StatCache,
) -> (Vec<(VPath, String)>, Option<PathBuf>) {
    let old = SandboxFs::new(from, None, false);
    let mut failed = Vec::new();
    for p in paths {
        cache.invalidate(p);
        let r = (|| -> Result<()> {
            if behind_special(&old, p)? {
                return Err(VeilError::InvalidPath(format!("{p}: a symlink is in the way in the old sandbox")));
            }
            let exec = old.metadata(p)?.is_some_and(|m| m.executable);
            let data = old.read(p)?;
            if behind_special(fs, p)? {
                return Err(VeilError::InvalidPath(format!("{p}: a symlink is in the way")));
            }
            if fs.metadata(p)?.is_some_and(|m| m.kind == NodeKind::Dir) {
                return Err(VeilError::InvalidPath(format!("{p}: the rebuilt sandbox has a directory there")));
            }
            fs.write(p, &data)?;
            fs.set_executable(p, exec)
        })();
        if let Err(e) = r {
            failed.push((p.clone(), e.to_string()));
        }
    }
    if failed.is_empty() && !keep_whole && remove_tree(from).is_ok() {
        return (failed, None);
    }
    let dir = from.parent().map(|d| SandboxPaths::at(d.to_path_buf())).map(|p| kept_dir(&p));
    match dir {
        Some(dir) if std::fs::rename(from, &dir).is_ok() => (failed, Some(dir)),
        _ => (failed, Some(from.to_path_buf())),
    }
}

/// Directories of the sandbox in `paths` that a rebuild kept whole
/// ([`SetAside::Kept`]): work that may be in no snapshot.
pub fn kept_dirs(paths: &SandboxPaths) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(&paths.dir)
        .map(|rd| {
            rd.flatten()
                .filter(|e| e.file_name().to_str().is_some_and(|n| n.starts_with(KEPT_PREFIX) || n.starts_with(REBUILD_PREFIX)))
                .map(|e| e.path())
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dir_names_round_trip_and_never_escape() {
        for ws in ["agent", "a.b", ".", "..", "-x", "_.."] {
            let d = dir_name(ws);
            assert!(d != "." && d != ".." && !d.contains('/'), "{d}");
            assert_eq!(workspace_of(&d).as_deref(), Some(ws));
        }
        assert_eq!(workspace_of("."), None);
        assert_eq!(workspace_of("a%b"), None);
        assert_eq!(workspace_of("files.trash-0"), Some("files.trash-0".into()));
    }

    #[test]
    fn manifest_round_trips_and_old_readers_fields_default() {
        let m = Manifest::new("agent");
        let raw = serde_json::to_vec(&m).unwrap();
        let back: Manifest = serde_json::from_slice(&raw).unwrap();
        assert_eq!(back, m);
        let minimal: Manifest = serde_json::from_str(r#"{"version":1,"workspace":"w"}"#).unwrap();
        assert_eq!(minimal.tree, None);
        assert_eq!(minimal.only, None);
        assert!(minimal.running.is_none());
    }
}
