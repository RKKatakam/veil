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
    /// this reader reads it now (unreadable files, embargo fallbacks).
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
        }
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
/// paths. Files `policy` ignores or isolates are left out (build output,
/// `.env`: no full snapshot records them either), and so are nested
/// repositories, symlinks and other special files, crash debris and
/// `.veil`. Sorted.
pub fn strays(fs: &dyn StorageBackend, set: &SparseSet, policy: &Policy) -> Result<Vec<VPath>> {
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
            if is_reserved_name(&e.name) || (e.kind == NodeKind::File && is_temp_name(&e.name)) {
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
            if matches!(policy.classify(&p, is_dir).tier, Tier::Ignored | Tier::Isolated) {
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
/// since the write. Cloaked and embargoed files are left to the builder,
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
        && entry.fallback.is_none()
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
/// not.
pub fn inject(fs: &SandboxFs, files: &[(String, Vec<u8>)]) -> Result<Injection> {
    let mut inj = Injection {
        secrets: InjectedSecrets::from_files(files.iter().map(|(p, d)| (p.as_str(), d.as_slice()))),
        ..Default::default()
    };
    for (p, data) in files {
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
    Ok(inj)
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
