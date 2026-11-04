//! CLI session: locate the repository, load the identity, auto-snapshot the
//! working copy, and keep the project directory in sync with the view.
//!
//! The session owns the project directory's stat cache
//! (`.veil/local/statcache/<workspace>.cache`). It is loaded once, used by
//! every snapshot and checkout of the session, and saved only when it changed.
//!
//! It also keeps the record of what the directory was materialised from
//! (`checkout.json`, [`Materialised`]): files left out because they were
//! unreadable, files written from an embargo fallback. Every command fills
//! in whatever has become readable since, before it snapshots and again when
//! it finishes, so a grant or an embargo release is never recorded as a
//! deletion or a revert.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use veil_core::{
    builder::BuildReport,
    checkout::{CheckoutReport, Materialised},
    workspace::SnapshotOptions,
    policy::POLICY_FILE,
    repo::{DEFAULT_WORKSPACE, VEIL_DIR},
    revset,
    statcache::{cache_path, StatCache},
    tree::lookup,
    DiskBackend, Identity, ObjectId, Repo, StorageBackend, VPath,
};

use crate::render::{self, safe, warn, warn_untrusted};

pub fn veil_home() -> PathBuf {
    if let Some(h) = std::env::var_os("VEIL_HOME") {
        return PathBuf::from(h);
    }
    if let Some(x) = std::env::var_os("XDG_CONFIG_HOME") {
        return PathBuf::from(x).join("veil");
    }
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".config").join("veil")
}

pub fn identity_path() -> PathBuf {
    veil_home().join("identity.json")
}

pub fn default_user_name() -> String {
    std::env::var("VEIL_USER")
        .or_else(|_| std::env::var("USER"))
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "anonymous".into())
}

pub fn write_identity(id: &Identity) -> Result<()> {
    let path = identity_path();
    std::fs::create_dir_all(path.parent().unwrap())?;
    std::fs::write(&path, id.to_json())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Load the identity, creating one on first use.
pub fn load_identity() -> Result<Identity> {
    let path = identity_path();
    if path.exists() {
        let s = std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
        return Ok(Identity::from_json(&s)?);
    }
    let id = Identity::generate(&default_user_name());
    write_identity(&id)?;
    eprintln!(
        "{} new identity for '{}' at {}",
        render::green("Created"),
        id.name,
        path.display()
    );
    Ok(id)
}

pub fn user_for(id: &Identity) -> String {
    std::env::var("VEIL_USER").unwrap_or_else(|_| id.name.clone())
}

/// Which workspace the project directory is attached to, which snapshot
/// was last materialised there, and what was materialised from what (files
/// left out because they were unreadable, files written from an embargo
/// fallback; see [`Materialised`]). Device-local.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CheckoutState {
    pub workspace: String,
    pub snapshot: ObjectId,
    #[serde(default, skip_serializing_if = "Materialised::is_empty")]
    pub materialised: Materialised,
}

impl CheckoutState {
    pub fn new(workspace: &str, snapshot: ObjectId, materialised: Materialised) -> CheckoutState {
        CheckoutState {
            workspace: workspace.to_string(),
            snapshot,
            materialised,
        }
    }
}

pub fn checkout_path() -> VPath {
    VPath::new(".veil/local/checkout.json").unwrap()
}

pub struct Ctx {
    pub root: PathBuf,
    pub fs: Arc<DiskBackend>,
    pub repo: Repo,
    pub ws: String,
    checkout: CheckoutState,
    pub report: BuildReport,
    /// Stat cache of the project directory (it follows the directory when
    /// another workspace is attached).
    cache: StatCache,
}

pub fn find_root(start: &Path) -> Option<PathBuf> {
    let mut cur = Some(start);
    while let Some(d) = cur {
        if d.join(VEIL_DIR).join("repo.json").is_file() {
            return Some(d.to_path_buf());
        }
        cur = d.parent();
    }
    None
}

pub fn save_checkout(fs: &DiskBackend, st: &CheckoutState) -> Result<()> {
    fs.write(&checkout_path(), &serde_json::to_vec_pretty(st)?)?;
    Ok(())
}

impl Ctx {
    pub fn open(repo_arg: Option<&Path>, snapshot: bool) -> Result<Ctx> {
        let start = match repo_arg {
            Some(p) => p.to_path_buf(),
            None => std::env::current_dir()?,
        };
        let root = find_root(&start)
            .ok_or_else(|| anyhow!("no Veil repository found in {} or its parents (run `vl init`)", start.display()))?;
        let identity = load_identity()?;
        let user = user_for(&identity);
        let fs = Arc::new(DiskBackend::new(&root));
        let mut repo = Repo::open(fs.clone(), Some(identity), &user)?;
        for id in repo.auto_release_embargoes()? {
            eprintln!("{} embargo {id}: its release time has passed", render::green("Released"));
        }
        let checkout = match fs.read_opt(&checkout_path())? {
            Some(raw) => serde_json::from_slice(&raw)?,
            None => CheckoutState::new(DEFAULT_WORKSPACE, repo.workspace_wc(DEFAULT_WORKSPACE)?, Materialised::default()),
        };
        let cache = StatCache::load(&*fs, &cache_path(&checkout.workspace));
        let mut ws = checkout.workspace.clone();
        if !repo.view().workspaces.contains_key(&ws) {
            let fallback = repo
                .view()
                .workspaces
                .keys()
                .next()
                .cloned()
                .ok_or_else(|| anyhow!("repository has no workspaces"))?;
            warn_untrusted(&format!("workspace '{ws}' no longer exists; attaching to '{fallback}'"));
            ws = fallback;
        }
        let mut ctx = Ctx {
            root,
            fs,
            repo,
            ws,
            checkout,
            report: BuildReport::default(),
            cache,
        };
        if snapshot {
            ctx.snapshot()?;
        }
        Ok(ctx)
    }

    pub fn wc(&self) -> Result<ObjectId> {
        Ok(self.repo.workspace_wc(&self.ws)?)
    }

    pub fn rev(&self, spec: &str) -> Result<ObjectId> {
        Ok(revset::resolve(&self.repo, spec, &self.ws)?)
    }

    /// Record the project directory into the attached workspace.
    pub fn snapshot(&mut self) -> Result<()> {
        self.record(None, false)
    }

    /// Record the project directory as operation `description`: for commands
    /// that edit the working copy themselves (`vl expose`, `vl restore`, …),
    /// so that `vl undo` reverts them instead of skipping them as the
    /// user's uncommitted edits.
    pub fn snapshot_as(&mut self, description: String) -> Result<()> {
        self.record(Some(description), false)
    }

    /// [`Ctx::snapshot_as`] after the command wrote `.veilpolicy` from
    /// another revision (`vl restore --from`): it is guarded by the accepted
    /// policy like any incoming change, never taken as the member's edit.
    pub fn snapshot_as_incoming_policy(&mut self, description: String) -> Result<()> {
        self.record(Some(description), true)
    }

    fn record(&mut self, description: Option<String>, policy_incoming: bool) -> Result<()> {
        let view_wc = self.wc()?;
        let disk = self.fs.clone();
        let fs: &dyn StorageBackend = &*disk;
        // Whatever became readable since the directory was materialised
        // (a grant, an embargo release) is filled in first; otherwise the
        // snapshot would record it as deleted, or reverted to the fallback.
        self.fill_in()?;
        let stale = self.checkout.workspace != self.ws
            || (self.checkout.snapshot != view_wc && self.repo.store().has(&self.checkout.snapshot));
        if stale {
            // The directory reflects `checkout.snapshot`, but the repository
            // moved on (undo, another process, removed workspace). Preserve
            // any local edits as their own change, then catch up.
            let base = self.checkout.snapshot;
            let base_snap = self.repo.snapshot(&base)?;
            let target_tree = self.repo.snapshot(&view_wc)?.tree;
            let (tree, report) = self.repo.build_from_recorded(
                fs,
                Some(base_snap.tree),
                base_snap.cloak.as_deref(),
                Some(&mut self.cache),
                Some(&self.checkout.materialised),
            )?;
            let mut from = base_snap.tree;
            if tree == target_tree {
                // Directory already matches (e.g. interrupted after checkout).
                from = target_tree;
            } else if tree != base_snap.tree {
                let (saved, _) = self
                    .repo
                    .commit_fs_as_child(base, fs, "recovered working-copy edits")?;
                let s = self.repo.snapshot(&saved)?;
                from = s.tree;
                warn(&format!(
                    "the working copy was stale; your edits were saved as change {}",
                    s.change_id.short()
                ));
            }
            print_working_copy_warnings(&report);
            self.report = report;
            let to = self.repo.snapshot(&view_wc)?.tree;
            let mut record = std::mem::take(&mut self.checkout.materialised);
            let co = self
                .repo
                .checkout_tree_recorded(fs, Some(&from), &to, &mut record, Some(&mut self.cache))?;
            print_kept_local(&co.kept_local);
            print_blocked(&co.blocked);
            self.checkout = CheckoutState::new(&self.ws, view_wc, record);
            save_checkout(&self.fs, &self.checkout)?;
            self.save_cache();
            return Ok(());
        }
        let out = self.repo.snapshot_workspace_with(
            &self.ws,
            fs,
            SnapshotOptions {
                cache: Some(&mut self.cache),
                materialised: Some(&self.checkout.materialised),
                description,
                policy_incoming,
                ..Default::default()
            },
        )?;
        self.save_cache();
        self.repo.capture_local_files(fs, &out.report)?;
        render::print_build_warnings(&out.report);
        print_working_copy_warnings(&out.report);
        self.report = out.report;
        if self.checkout.snapshot != out.snapshot {
            self.checkout.snapshot = out.snapshot;
            save_checkout(&self.fs, &self.checkout)?;
        }
        Ok(())
    }

    /// Materialise what was unreadable when the directory was checked out
    /// and is readable now (see [`Materialised::fill_in`]). Local edits are
    /// never overwritten.
    fn fill_in(&mut self) -> Result<()> {
        if self.checkout.materialised.is_empty() || !self.repo.store().has(&self.checkout.snapshot) {
            return Ok(());
        }
        let tree = self.repo.snapshot(&self.checkout.snapshot)?.tree;
        let mut record = self.checkout.materialised.clone();
        let co = self
            .repo
            .fill_in_materialised(&*self.fs, &tree, &mut record, Some(&mut self.cache))?;
        if record != self.checkout.materialised {
            self.checkout.materialised = record;
            save_checkout(&self.fs, &self.checkout)?;
            self.save_cache();
        }
        print_filled_in(&co);
        Ok(())
    }

    /// Bring the project directory in line with the attached workspace.
    pub fn finish(&mut self) -> Result<()> {
        let target = self.wc()?;
        let moved = target != self.checkout.snapshot || self.checkout.workspace != self.ws;
        if !moved && self.checkout.materialised.is_empty() {
            return Ok(());
        }
        if !moved {
            // Same snapshot, but this command may have made more of it
            // readable (`vl pull` brought a grant, `vl embargo release`).
            return self.fill_in();
        }
        let from = self.repo.snapshot(&self.checkout.snapshot)?.tree;
        let to_snap = self.repo.snapshot(&target)?;
        let previous = self.checkout.snapshot;
        let mut record = std::mem::take(&mut self.checkout.materialised);
        let report = if from != to_snap.tree || !record.is_empty() {
            Some(self.repo.checkout_tree_recorded(
                &*self.fs,
                Some(&from),
                &to_snap.tree,
                &mut record,
                Some(&mut self.cache),
            )?)
        } else {
            None
        };
        // Persist the pointer before printing anything.
        self.checkout = CheckoutState::new(&self.ws, target, record);
        save_checkout(&self.fs, &self.checkout)?;
        self.save_cache();
        if let Some(r) = report {
            if r.written + r.removed > 0 {
                eprintln!("Updated {} files, removed {}", r.written, r.removed);
            }
            for p in &r.redacted {
                let why = lookup(self.repo.store(), &to_snap.tree, p)?.and_then(|e| render::hidden_reason(&self.repo, &e));
                eprintln!(
                    "  {} {} ({}; left out of the working copy)",
                    render::yellow("redacted"),
                    safe(p.as_str()),
                    why.unwrap_or_else(|| "no key".into())
                );
            }
            for p in &r.protected {
                eprintln!(
                    "  {} {} (local-only file kept as is)",
                    render::yellow("protected"),
                    safe(p.as_str())
                );
            }
            print_kept_local(&r.kept_local);
            print_blocked(&r.blocked);
        }
        // A `.veilpolicy` that arrived with this checkout: say now (not at
        // the next snapshot) which local files keep their protection.
        let policy_of = |t: &ObjectId| lookup(self.repo.store(), t, &VPath::new(POLICY_FILE).expect("valid"));
        if policy_of(&from)? != policy_of(&to_snap.tree)? {
            render::print_policy_held_back(&self.repo.policy_held_back(&*self.fs)?, false);
        }
        if previous != target {
            eprintln!("Working copy now at: {}", render::one_line(&self.repo, &target));
        }
        Ok(())
    }

    /// Persist the stat cache if it changed. It is only an accelerator, so
    /// failing to write it is a warning, not an error.
    fn save_cache(&mut self) {
        if let Err(e) = self.cache.save(&*self.fs, &cache_path(&self.ws)) {
            warn(&format!("could not save the stat cache: {e}"));
        }
    }

    pub fn attach(&mut self, ws: &str) -> Result<()> {
        if !self.repo.view().workspaces.contains_key(ws) {
            bail!("no workspace named '{ws}'");
        }
        self.ws = ws.to_string();
        Ok(())
    }

    /// Convert a user path (relative to cwd) to a repository path.
    pub fn repo_path(&self, user: &str) -> Result<VPath> {
        let cwd = std::env::current_dir()?;
        let abs = if Path::new(user).is_absolute() {
            PathBuf::from(user)
        } else {
            cwd.join(user)
        };
        let rel = normalize(&abs)
            .strip_prefix(normalize(&self.root))
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|_| PathBuf::from(user));
        Ok(VPath::new(&rel.to_string_lossy().replace('\\', "/"))?)
    }
}

/// Things in the working copy a snapshot could not record. Never fatal, never
/// silent. Paths and reasons come from the working copy (or a tree), so they
/// are escaped.
pub fn print_working_copy_warnings(r: &BuildReport) {
    for (p, why) in &r.unreadable {
        warn_untrusted(&format!(
            "skipped {p}: cannot read it ({why}); its last recorded version, if any, is kept. Fix its permissions or `vl ignore {p}`"
        ));
    }
    for name in &r.unrepresentable {
        warn_untrusted(&format!(
            "skipped {name}: the file name is not valid UTF-8, so Veil cannot record it. Rename it to keep it under version control"
        ));
    }
    // A symlinked `.veilpolicy` is followed: its policy warning says so.
    for p in r.shadowed.iter().filter(|p| p.as_str() != POLICY_FILE) {
        warn_untrusted(&format!(
            "{p} is tracked but is now a symlink or special file; Veil never follows it and keeps the recorded version"
        ));
    }
    for (a, b) in &r.name_collisions {
        warn_untrusted(&format!(
            "{a} and {b} differ only in case or Unicode normalisation; a checkout on a case-insensitive \
             filesystem (macOS by default) will refuse this snapshot. Rename one of them"
        ));
    }
}

/// Report files that became readable and were materialised.
fn print_filled_in(r: &CheckoutReport) {
    if r.written + r.removed > 0 {
        eprintln!(
            "{} {} file(s) that became readable (a key arrived or an embargo was released), removed {}",
            render::green("Filled in"),
            r.written,
            r.removed
        );
    }
    print_kept_local(&r.kept_local);
    print_blocked(&r.blocked);
}

fn print_blocked(paths: &[VPath]) {
    for p in paths {
        eprintln!(
            "  {} {} (a symlink or special file is in the way; Veil never writes through or over it)",
            render::yellow("skipped"),
            safe(p.as_str())
        );
    }
}

fn print_kept_local(paths: &[VPath]) {
    for p in paths {
        eprintln!(
            "  {} {} (local edit not in history, e.g. quarantined; left as is instead of being overwritten)",
            render::yellow("kept"),
            safe(p.as_str())
        );
    }
}

fn normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            c => out.push(c),
        }
    }
    out
}
