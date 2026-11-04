//! The operation log.
//!
//! Every mutation of the repository (snapshot, describe, rebase, tag move,
//! visibility toggle, push/pull, embargo release, …) is a transaction that
//! appends one immutable [`Operation`] holding the complete resulting
//! [`View`]. Undo is therefore trivial and total: restore an older view.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use serde::{Deserialize, Serialize};

use crate::{
    error::{Result, VeilError},
    id::ObjectId,
    vfs::StorageBackend,
    vpath::VPath,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceState {
    /// The working-copy snapshot of this workspace.
    pub wc: ObjectId,
    /// Scope under which this workspace's line of work is cloaked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloak: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tag {
    pub target: ObjectId,
    /// Cloaked tags are never pushed to public remotes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloak: Option<String>,
}

/// The complete mutable state of a repository at one point in time.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct View {
    /// Visible tips of the DAG. Everything reachable from a head, tag or
    /// workspace is visible; rewritten snapshots simply stop being reachable.
    pub heads: BTreeSet<ObjectId>,
    pub workspaces: BTreeMap<String, WorkspaceState>,
    pub tags: BTreeMap<String, Tag>,
    /// `remote/tag` → target as last seen on the remote.
    #[serde(default)]
    pub remote_tags: BTreeMap<String, ObjectId>,
}

impl View {
    pub fn workspace(&self, name: &str) -> Result<&WorkspaceState> {
        self.workspaces
            .get(name)
            .ok_or_else(|| VeilError::NotFound(format!("workspace '{name}'")))
    }

    /// Every snapshot referenced directly by this view.
    pub fn refs(&self) -> Vec<ObjectId> {
        let mut v: Vec<ObjectId> = self.heads.iter().copied().collect();
        v.extend(self.workspaces.values().map(|w| w.wc));
        v.extend(self.tags.values().map(|t| t.target));
        v.extend(self.remote_tags.values().copied());
        v.sort();
        v.dedup();
        v
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Operation {
    pub parents: Vec<ObjectId>,
    pub timestamp: i64,
    pub user: String,
    pub description: String,
    pub view: View,
    /// Set on an operation whose effect lies outside the [`View`] (a key
    /// ring, the remotes in `repo.json`, the local vault, which workspace
    /// the project directory is attached to): restoring an older view does
    /// not revert it, so `vl undo` refuses to "undo" it and shows this
    /// instead, which says how to reverse it by hand (or that it cannot be
    /// reversed). Absent on every other operation, and on every operation
    /// written before it existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manual_undo: Option<String>,
}

#[derive(Debug)]
pub struct OpStore {
    backend: Arc<dyn StorageBackend>,
}

impl OpStore {
    pub fn new(backend: Arc<dyn StorageBackend>) -> Self {
        OpStore { backend }
    }

    fn op_path(id: &ObjectId) -> VPath {
        VPath::new(&format!(".veil/ops/{}", id.hex())).unwrap()
    }

    fn head_path() -> VPath {
        VPath::new(".veil/op_head").unwrap()
    }

    pub fn put(&self, op: &Operation) -> Result<ObjectId> {
        let raw = serde_json::to_vec(op)?;
        let id = ObjectId::hash(&raw);
        self.backend.write(&Self::op_path(&id), &raw)?;
        Ok(id)
    }

    pub fn get(&self, id: &ObjectId) -> Result<Operation> {
        // Only a missing file is "not found": an I/O error (a lost SFTP
        // connection, EIO, a permission problem) is reported as itself, so
        // that the user looks at the network or the disk rather than for a
        // damaged repository (BUG-293).
        self.try_get(id)?
            .ok_or_else(|| VeilError::NotFound(format!("operation {}", id.short())))
    }

    /// Like [`OpStore::get`], but `Ok(None)` if the operation does not exist
    /// (e.g. pruned by `vl gc --keep-ops-days`).
    pub fn try_get(&self, id: &ObjectId) -> Result<Option<Operation>> {
        match self.backend.read_opt(&Self::op_path(id))? {
            Some(raw) => Ok(Some(serde_json::from_slice(&raw)?)),
            None => Ok(None),
        }
    }

    pub fn head(&self) -> Result<ObjectId> {
        let raw = self.backend.read(&Self::head_path())?;
        ObjectId::from_hex(String::from_utf8_lossy(&raw).trim())
    }

    pub fn set_head(&self, id: &ObjectId) -> Result<()> {
        self.backend.write(&Self::head_path(), id.hex().as_bytes())
    }

    /// Resolve an operation id prefix by walking back from the head.
    pub fn resolve_prefix(&self, prefix: &str) -> Result<ObjectId> {
        let mut cur = Some(self.head()?);
        let mut found = Vec::new();
        let mut steps = 0;
        while let Some(id) = cur {
            if id.hex().starts_with(prefix) {
                found.push(id);
            }
            // Older operations may have been pruned by gc.
            let Some(op) = self.try_get(&id)? else { break };
            cur = op.parents.first().copied();
            steps += 1;
            if steps > 100_000 {
                break;
            }
        }
        match found.as_slice() {
            [one] => Ok(*one),
            [] => Err(VeilError::Revset(format!("no operation matches '{prefix}'"))),
            _ => Err(VeilError::Revset(format!("operation prefix '{prefix}' is ambiguous"))),
        }
    }
}

const PRUNED_OPS: &str = ".veil/ops_pruned";

/// Record operations deliberately removed by `gc --keep-ops-days`, so that
/// integrity checks can tell pruning apart from loss. Must be called (and is
/// durable) before the operation files are deleted.
pub fn record_pruned_ops(backend: &dyn StorageBackend, ids: &[ObjectId]) -> Result<()> {
    if ids.is_empty() {
        return Ok(());
    }
    let path = VPath::new(PRUNED_OPS)?;
    let mut text = backend
        .read_opt(&path)?
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default();
    for id in ids {
        text.push_str(&id.hex());
        text.push('\n');
    }
    backend.write(&path, text.as_bytes())
}

/// Operations recorded as pruned by `gc`.
pub fn pruned_ops(backend: &dyn StorageBackend) -> Result<std::collections::HashSet<ObjectId>> {
    let Some(raw) = backend.read_opt(&VPath::new(PRUNED_OPS)?)? else {
        return Ok(Default::default());
    };
    Ok(String::from_utf8_lossy(&raw)
        .lines()
        .filter_map(|l| ObjectId::from_hex(l.trim()).ok())
        .collect())
}
