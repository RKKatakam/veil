//! Working copies and virtual workspaces.
//!
//! A *workspace* is just a named pointer to a working-copy snapshot in the
//! view. It has no directory of its own: the project root can be attached to
//! any workspace, other workspaces live purely in the DAG and are edited
//! through overlays (in memory) or short-lived materialisations. Nothing is
//! ever "checked out hostage" the way a git worktree locks a branch.

use std::sync::Arc;

use crate::{
    builder::{build_tree, BuildOptions, BuildReport},
    checkout::{checkout, CheckoutReport},
    error::{Result, VeilError},
    id::{ChangeId, ObjectId},
    now_millis,
    object::Snapshot,
    oplog::WorkspaceState,
    policy::Policy,
    repo::Repo,
    tree::{lookup, TreeView},
    vfs::{OverlayBackend, StorageBackend},
    vpath::VPath,
};

#[derive(Debug, Clone)]
pub struct WcSnapshot {
    pub snapshot: ObjectId,
    pub changed: bool,
    pub report: BuildReport,
}

/// An in-memory copy-on-write workspace over a base snapshot. Creating one is
/// O(1); committing it is O(changed paths). It never touches disk.
#[derive(Debug, Clone)]
pub struct EphemeralWorkspace {
    base: ObjectId,
    fs: Arc<OverlayBackend>,
}

impl EphemeralWorkspace {
    pub fn base(&self) -> ObjectId {
        self.base
    }

    pub fn fs(&self) -> &Arc<OverlayBackend> {
        &self.fs
    }

    pub fn write(&self, path: &str, data: impl AsRef<[u8]>) -> Result<()> {
        self.fs.write(&VPath::new(path)?, data.as_ref())
    }

    pub fn read(&self, path: &str) -> Result<Vec<u8>> {
        self.fs.read(&VPath::new(path)?)
    }

    pub fn remove(&self, path: &str) -> Result<()> {
        let p = VPath::new(path)?;
        match self.fs.metadata(&p)? {
            Some(m) if m.kind == crate::vfs::NodeKind::Dir => self.fs.remove_dir_all(&p),
            _ => self.fs.remove_file(&p),
        }
    }
}

pub fn validate_workspace_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.');
    if ok {
        Ok(())
    } else {
        Err(VeilError::repo(format!("invalid workspace name '{name}'")))
    }
}

impl Repo {
    /// Record the current state of `fs` as the working-copy snapshot of
    /// workspace `ws` (amending it in place, Jujutsu-style). This is the
    /// "automatic micro-snapshot": there is no index and no `add`.
    pub fn snapshot_workspace(&mut self, ws: &str, fs: &dyn StorageBackend) -> Result<WcSnapshot> {
        let mut tx = self.transaction(format!("snapshot working copy of '{ws}'"))?;
        let wc_id = tx.view.workspace(ws)?.wc;
        let wc = tx.repo().snapshot(&wc_id)?;
        let policy = Policy::load(fs)?;
        let store = tx.repo().store.clone();
        let (tree, report) = build_tree(
            &store,
            fs,
            &BuildOptions {
                policy: &policy,
                parent_tree: Some(wc.tree),
                cloak: wc.cloak.as_deref(),
            },
        )?;
        if tree == wc.tree {
            return Ok(WcSnapshot {
                snapshot: wc_id,
                changed: false,
                report,
            });
        }
        let mut new = (*wc).clone();
        new.tree = tree;
        new.predecessors = vec![wc_id];
        new.timestamp = now_millis();
        // A conflict stays recorded until the conflicted file is edited.
        new.conflicts.retain(|p| {
            let Ok(p) = VPath::new(p) else { return false };
            let old = lookup(&store, &wc.tree, &p).ok().flatten();
            let cur = lookup(&store, &tree, &p).ok().flatten();
            old.is_some() && old == cur
        });
        let id = tx.rewrite(wc_id, new)?;
        tx.commit()?;
        Ok(WcSnapshot {
            snapshot: id,
            changed: true,
            report,
        })
    }

    /// Build a tree from `fs` relative to `parent_tree` without recording
    /// anything (dry run / change detection).
    pub fn build_from(&self, fs: &dyn StorageBackend, parent_tree: Option<ObjectId>, cloak: Option<&str>) -> Result<(ObjectId, BuildReport)> {
        let policy = Policy::load(fs)?;
        build_tree(&self.store, fs, &BuildOptions { policy: &policy, parent_tree, cloak })
    }

    /// Materialise the difference between two trees onto `fs`.
    pub fn checkout_tree(&self, fs: &dyn StorageBackend, from: Option<&ObjectId>, to: &ObjectId) -> Result<CheckoutReport> {
        checkout(&self.store, fs, from, to)
    }

    /// A read-only VFS view of a snapshot's tree.
    pub fn tree_view(&self, snapshot: &ObjectId) -> Result<TreeView> {
        Ok(TreeView::new(self.store.clone(), self.snapshot(snapshot)?.tree))
    }

    /// An in-memory overlay over `base` — the agent sandbox primitive.
    pub fn ephemeral_workspace(&self, base: ObjectId) -> Result<EphemeralWorkspace> {
        let lower: Arc<dyn StorageBackend> = Arc::new(self.tree_view(&base)?);
        Ok(EphemeralWorkspace {
            base,
            fs: Arc::new(OverlayBackend::new(lower)),
        })
    }

    /// Record the overlay as a new snapshot whose parent is the workspace's
    /// base. The workspace itself can then simply be dropped.
    pub fn commit_ephemeral(&mut self, ws: &EphemeralWorkspace, description: &str) -> Result<(ObjectId, BuildReport)> {
        self.commit_fs_as_child(ws.base, &*ws.fs, description)
    }

    /// Snapshot an arbitrary backend as a new child of `base`.
    pub fn commit_fs_as_child(&mut self, base: ObjectId, fs: &dyn StorageBackend, description: &str) -> Result<(ObjectId, BuildReport)> {
        let mut tx = self.transaction("record ephemeral workspace")?;
        let parent = tx.repo().snapshot(&base)?;
        let policy = Policy::load(fs)?;
        let store = tx.repo().store.clone();
        let (tree, report) = build_tree(
            &store,
            fs,
            &BuildOptions {
                policy: &policy,
                parent_tree: Some(parent.tree),
                cloak: parent.cloak.as_deref(),
            },
        )?;
        let snap = Snapshot {
            parents: vec![base],
            change_id: ChangeId::random(),
            tree,
            description: store.make_text(description, parent.cloak.as_deref())?,
            author: tx.repo().user.clone(),
            timestamp: now_millis(),
            predecessors: vec![],
            conflicts: vec![],
            cloak: parent.cloak.clone(),
            embargo: None,
            signature: None, // signed by the transaction
        };
        let id = tx.write_snapshot(&snap)?;
        tx.set_description(format!("record ephemeral workspace as {}", snap.change_id.short()));
        tx.commit()?;
        Ok((id, report))
    }

    /// Create a named virtual workspace with a fresh change on `base`.
    pub fn create_workspace(&mut self, name: &str, bases: Vec<ObjectId>, cloak: Option<String>) -> Result<ObjectId> {
        validate_workspace_name(name)?;
        if let Some(scope) = &cloak {
            if !self.keys().has(scope) {
                return Err(VeilError::Policy(format!("you hold no key for scope '{scope}'")));
            }
        }
        let mut tx = self.transaction(format!("create workspace '{name}'"))?;
        if tx.view.workspaces.contains_key(name) {
            return Err(VeilError::AlreadyExists(format!("workspace '{name}'")));
        }
        let wc = tx.new_change(bases, "", cloak.clone())?;
        tx.view.workspaces.insert(name.to_string(), WorkspaceState { wc, cloak });
        tx.commit()?;
        Ok(wc)
    }

    pub fn remove_workspace(&mut self, name: &str) -> Result<()> {
        let mut tx = self.transaction(format!("remove workspace '{name}'"))?;
        let st = tx
            .view
            .workspaces
            .remove(name)
            .ok_or_else(|| VeilError::NotFound(format!("workspace '{name}'")))?;
        tx.maybe_abandon_empty(st.wc)?;
        tx.commit()?;
        Ok(())
    }

    /// Overlay over a workspace's current working copy (for editing a
    /// virtual workspace without materialising it).
    pub fn workspace_overlay(&self, ws: &str) -> Result<OverlayBackend> {
        let wc = self.workspace_wc(ws)?;
        Ok(OverlayBackend::new(Arc::new(self.tree_view(&wc)?)))
    }
}
