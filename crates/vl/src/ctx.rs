//! CLI session: locate the repository, load the identity, auto-snapshot the
//! working copy, and keep the project directory in sync with the view.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use veil_core::{
    builder::BuildReport,
    repo::{DEFAULT_WORKSPACE, VEIL_DIR},
    revset, DiskBackend, Identity, ObjectId, Repo, StorageBackend, VPath,
};

use crate::render::{self, warn};

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

/// Which workspace the project directory is attached to, and which snapshot
/// was last materialised there. Device-local.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CheckoutState {
    pub workspace: String,
    pub snapshot: ObjectId,
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
            None => CheckoutState {
                workspace: DEFAULT_WORKSPACE.into(),
                snapshot: repo.workspace_wc(DEFAULT_WORKSPACE)?,
            },
        };
        let mut ws = checkout.workspace.clone();
        if !repo.view().workspaces.contains_key(&ws) {
            let fallback = repo
                .view()
                .workspaces
                .keys()
                .next()
                .cloned()
                .ok_or_else(|| anyhow!("repository has no workspaces"))?;
            warn(&format!("workspace '{ws}' no longer exists; attaching to '{fallback}'"));
            ws = fallback;
        }
        let mut ctx = Ctx {
            root,
            fs,
            repo,
            ws,
            checkout,
            report: BuildReport::default(),
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
        let view_wc = self.wc()?;
        let fs: &dyn StorageBackend = &*self.fs;
        let stale = self.checkout.workspace != self.ws
            || (self.checkout.snapshot != view_wc && self.repo.store().has(&self.checkout.snapshot));
        if stale {
            // The directory reflects `checkout.snapshot`, but the repository
            // moved on (undo, another process, removed workspace). Preserve
            // any local edits as their own change, then catch up.
            let base = self.checkout.snapshot;
            let base_snap = self.repo.snapshot(&base)?;
            let target_tree = self.repo.snapshot(&view_wc)?.tree;
            let (tree, report) = self.repo.build_from(fs, Some(base_snap.tree), base_snap.cloak.as_deref())?;
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
            self.report = report;
            let to = self.repo.snapshot(&view_wc)?.tree;
            self.repo.checkout_tree(fs, Some(&from), &to)?;
            self.checkout = CheckoutState {
                workspace: self.ws.clone(),
                snapshot: view_wc,
            };
            save_checkout(&self.fs, &self.checkout)?;
            return Ok(());
        }
        let out = self.repo.snapshot_workspace(&self.ws, fs)?;
        self.repo.capture_local_files(fs, &out.report)?;
        render::print_build_warnings(&out.report);
        self.report = out.report;
        if self.checkout.snapshot != out.snapshot {
            self.checkout.snapshot = out.snapshot;
            save_checkout(&self.fs, &self.checkout)?;
        }
        Ok(())
    }

    /// Bring the project directory in line with the attached workspace.
    pub fn finish(&mut self) -> Result<()> {
        let target = self.wc()?;
        if target == self.checkout.snapshot && self.checkout.workspace == self.ws {
            return Ok(());
        }
        let from = self.repo.snapshot(&self.checkout.snapshot)?.tree;
        let to_snap = self.repo.snapshot(&target)?;
        let previous = self.checkout.snapshot;
        let report = if from != to_snap.tree {
            Some(self.repo.checkout_tree(&*self.fs, Some(&from), &to_snap.tree)?)
        } else {
            None
        };
        // Persist the pointer before printing anything.
        self.checkout = CheckoutState {
            workspace: self.ws.clone(),
            snapshot: target,
        };
        save_checkout(&self.fs, &self.checkout)?;
        if let Some(r) = report {
            if r.written + r.removed > 0 {
                eprintln!("Updated {} files, removed {}", r.written, r.removed);
            }
            for p in &r.redacted {
                eprintln!("  {} {p} (no key; left out of the working copy)", render::yellow("redacted"));
            }
            for p in &r.protected {
                eprintln!("  {} {p} (local-only file kept as is)", render::yellow("protected"));
            }
        }
        if previous != target {
            eprintln!("Working copy now at: {}", render::one_line(&self.repo, &target));
        }
        Ok(())
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
