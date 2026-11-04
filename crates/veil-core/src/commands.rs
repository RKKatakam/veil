//! High-level history operations. Each is one transaction → one op-log entry.

use crate::{
    embargo::{apply_embargo, normalize_tree},
    error::{Result, VeilError},
    id::{ChangeId, ObjectId},
    merge::merge_trees,
    now_millis,
    object::Snapshot,
    oplog::Tag,
    policy::Policy,
    repo::Repo,
    tree::TreeView,
};

#[derive(Debug, Clone)]
pub struct EmbargoSpec {
    /// Scope whose members can see the merged content before release.
    pub scope: String,
    /// Automatic release time (ms since epoch), `None` for manual release.
    pub until: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct MergeResult {
    pub snapshot: ObjectId,
    pub conflicts: Vec<String>,
    pub embargo: Option<String>,
}

pub fn validate_tag_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && !name.ends_with('-')
        && !name.ends_with('@')
        && !name.contains("..")
        && name != "root"
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'/'));
    if ok {
        Ok(())
    } else {
        Err(VeilError::repo(format!("invalid tag name '{name}'")))
    }
}

impl Repo {
    /// Start a new change on top of `parents` in workspace `ws`.
    pub fn new_change(&mut self, ws: &str, parents: Vec<ObjectId>, message: &str) -> Result<ObjectId> {
        let mut tx = self.transaction("new change")?;
        let cloak = tx.view.workspace(ws)?.cloak.clone();
        let id = tx.new_change(parents, message, cloak)?;
        tx.set_workspace_wc(ws, id)?;
        let change = tx.repo().snapshot(&id)?.change_id;
        tx.set_description(format!("new change {}", change.short()));
        tx.commit()?;
        Ok(id)
    }

    pub fn describe(&mut self, id: ObjectId, message: &str) -> Result<ObjectId> {
        let mut tx = self.transaction("describe")?;
        let s = tx.repo().snapshot(&id)?;
        let mut ns = (*s).clone();
        ns.description = tx.repo().store.make_text(message, s.cloak.as_deref())?;
        ns.predecessors = vec![id];
        let new = tx.rewrite(id, ns)?;
        tx.set_description(format!("describe change {}", s.change_id.short()));
        tx.commit()?;
        Ok(new)
    }

    /// Describe the working copy and start a fresh change on top of it.
    /// Tags pointing at the working copy's parent advance to the commit.
    /// Returns `(committed, new working copy)`.
    pub fn commit_working_copy(&mut self, ws: &str, message: &str) -> Result<(ObjectId, ObjectId)> {
        let mut tx = self.transaction("commit")?;
        let wc_id = tx.view.workspace(ws)?.wc;
        let cloak = tx.view.workspace(ws)?.cloak.clone();
        let s = tx.repo().snapshot(&wc_id)?;
        let mut ns = (*s).clone();
        ns.description = tx.repo().store.make_text(message, s.cloak.as_deref())?;
        ns.predecessors = vec![wc_id];
        ns.timestamp = now_millis();
        let committed = tx.rewrite(wc_id, ns)?;
        for tag in tx.view.tags.values_mut() {
            if s.parents.first() == Some(&tag.target) {
                tag.target = committed;
            }
        }
        let wc = tx.new_change(vec![committed], "", cloak)?;
        tx.set_workspace_wc(ws, wc)?;
        tx.set_description(format!("commit change {}", s.change_id.short()));
        tx.commit()?;
        Ok((committed, wc))
    }

    pub fn edit(&mut self, ws: &str, id: ObjectId) -> Result<()> {
        let mut tx = self.transaction("edit")?;
        tx.set_workspace_wc(ws, id)?;
        let change = tx.repo().snapshot(&id)?.change_id;
        tx.set_description(format!("edit change {}", change.short()));
        tx.commit()?;
        Ok(())
    }

    pub fn abandon(&mut self, id: ObjectId) -> Result<()> {
        let mut tx = self.transaction("abandon")?;
        let change = tx.repo().snapshot(&id)?.change_id;
        tx.abandon(id)?;
        tx.set_description(format!("abandon change {}", change.short()));
        tx.commit()?;
        Ok(())
    }

    /// Move `source` (and, automatically, its descendants) onto `dest`.
    pub fn rebase(&mut self, source: ObjectId, dest: Vec<ObjectId>) -> Result<ObjectId> {
        if dest.is_empty() {
            return Err(VeilError::repo("rebase needs at least one destination"));
        }
        for d in &dest {
            if self.is_ancestor(&source, d)? {
                return Err(VeilError::repo("cannot rebase a change onto itself or its descendant"));
            }
        }
        let mut tx = self.transaction("rebase")?;
        let s = tx.repo().snapshot(&source)?;
        let old_base = tx.repo().parents_tree(&s.parents)?.tree;
        let new_base = tx.repo().parents_tree(&dest)?.tree;
        let out = merge_trees(&tx.repo().store, Some(old_base), new_base, s.tree)?;
        let mut ns = (*s).clone();
        ns.parents = dest;
        ns.tree = out.tree;
        ns.predecessors = vec![source];
        ns.conflicts.extend(out.conflicts.iter().map(|p| p.to_string()));
        ns.conflicts.sort();
        ns.conflicts.dedup();
        let id = tx.rewrite(source, ns)?;
        tx.set_description(format!("rebase change {}", s.change_id.short()));
        tx.commit()?;
        Ok(id)
    }

    /// Fold a change into its (single) parent.
    pub fn squash(&mut self, id: ObjectId) -> Result<ObjectId> {
        let mut tx = self.transaction("squash")?;
        let s = tx.repo().snapshot(&id)?;
        let [parent] = s.parents.as_slice() else {
            return Err(VeilError::repo("can only squash a change with exactly one parent"));
        };
        if *parent == tx.repo().root_id {
            return Err(VeilError::repo("cannot squash into the root snapshot"));
        }
        let p = tx.repo().snapshot(parent)?;
        let mut np = (*p).clone();
        np.tree = s.tree;
        np.predecessors = vec![*parent, id];
        let pd = tx.repo().description(&p);
        let sd = tx.repo().description(&s);
        if !sd.trim().is_empty() {
            let joined = if pd.trim().is_empty() { sd } else { format!("{pd}\n\n{sd}") };
            np.description = tx.repo().store.make_text(&joined, p.cloak.as_deref())?;
        }
        let new_parent = tx.rewrite(*parent, np)?;
        tx.abandon(id)?;
        tx.set_description(format!("squash {} into {}", s.change_id.short(), p.change_id.short()));
        tx.commit()?;
        Ok(new_parent)
    }

    /// Merge `others` into `into`, producing a described merge snapshot; the
    /// workspace continues on a fresh change on top of it. Tags pointing at
    /// `into` advance to the merge.
    pub fn merge(
        &mut self,
        ws: &str,
        into: ObjectId,
        others: Vec<ObjectId>,
        message: &str,
        embargo: Option<EmbargoSpec>,
    ) -> Result<MergeResult> {
        if others.is_empty() {
            return Err(VeilError::repo("nothing to merge"));
        }
        let embargo_id = match &embargo {
            Some(spec) => Some(self.keys().create_embargo(&spec.scope, spec.until, message)?),
            None => None,
        };
        let mut tx = self.transaction("merge")?;
        let mut parents = vec![into];
        parents.extend(others);
        let into_snap = tx.repo().snapshot(&into)?;
        let store = tx.repo().store.clone();
        let merged = tx.repo().parents_tree(&parents)?;
        let policy = Policy::load(&TreeView::new(store.clone(), merged.tree))?;
        let mut tree = normalize_tree(&store, &merged.tree, &policy, into_snap.cloak.as_deref())?;
        if let Some(e) = &embargo_id {
            tree = apply_embargo(&store, &tree, &into_snap.tree, e)?;
        }
        let snap = Snapshot {
            parents,
            change_id: ChangeId::random(),
            tree,
            description: store.make_text(message, into_snap.cloak.as_deref())?,
            author: tx.repo().user.clone(),
            timestamp: now_millis(),
            predecessors: vec![],
            conflicts: merged.conflicts.iter().map(|p| p.to_string()).collect(),
            cloak: into_snap.cloak.clone(),
            embargo: embargo_id.clone(),
            signature: None, // signed by the transaction
        };
        let m = tx.write_snapshot(&snap)?;
        for tag in tx.view.tags.values_mut() {
            if tag.target == into {
                tag.target = m;
            }
        }
        let cloak = tx.view.workspace(ws)?.cloak.clone();
        let wc = tx.new_change(vec![m], "", cloak)?;
        tx.set_workspace_wc(ws, wc)?;
        tx.set_description(match &embargo_id {
            Some(e) => format!("merge {} (embargo {e})", snap.change_id.short()),
            None => format!("merge {}", snap.change_id.short()),
        });
        tx.commit()?;
        Ok(MergeResult {
            snapshot: m,
            conflicts: snap.conflicts,
            embargo: embargo_id,
        })
    }

    pub fn set_tag(&mut self, name: &str, target: ObjectId, cloak: Option<String>, allow_backwards: bool) -> Result<()> {
        validate_tag_name(name)?;
        // A tag on anything but a snapshot (a blob, a tree) would break
        // every graph query that walks the view.
        match self.snapshot(&target) {
            Ok(_) => {}
            Err(VeilError::Corrupt(..)) | Err(VeilError::Json(_)) => {
                return Err(VeilError::repo(format!("{} is not a snapshot", target.short())))
            }
            Err(e) => return Err(e),
        }
        if let Some(t) = self.view.tags.get(name) {
            if !allow_backwards && !self.is_ancestor(&t.target, &target)? {
                return Err(VeilError::repo(format!(
                    "moving tag '{name}' would go backwards or sideways (use --allow-backwards)"
                )));
            }
        }
        let mut tx = self.transaction(format!("set tag {name}"))?;
        let cloak = cloak.or_else(|| tx.view.tags.get(name).and_then(|t| t.cloak.clone()));
        tx.view.tags.insert(name.to_string(), Tag { target, cloak });
        tx.commit()?;
        Ok(())
    }

    pub fn delete_tag(&mut self, name: &str) -> Result<()> {
        let mut tx = self.transaction(format!("delete tag {name}"))?;
        tx.view
            .tags
            .remove(name)
            .ok_or_else(|| VeilError::NotFound(format!("tag '{name}'")))?;
        tx.commit()?;
        Ok(())
    }

    pub fn release_embargo(&mut self, id: &str) -> Result<()> {
        self.keys().release_embargo(id)?;
        let mut tx = self.transaction(format!("release embargo {id}"))?;
        tx.record_always();
        tx.commit()?;
        Ok(())
    }

    /// Release every embargo whose deadline passed and for which we hold the
    /// key. Called on every CLI invocation.
    pub fn auto_release_embargoes(&mut self) -> Result<Vec<String>> {
        let now = now_millis();
        let mut released = Vec::new();
        for rec in self.keys().embargoes()? {
            // Only a deadline signed by a scope member may trigger a release.
            if rec.is_released() || rec.until.map_or(true, |u| u > now) || !self.keys().embargo_trusted(&rec) {
                continue;
            }
            if self.keys().has(&format!("embargo/{}", rec.id)) {
                self.release_embargo(&rec.id)?;
                released.push(rec.id);
            }
        }
        Ok(released)
    }

    /// Undo the most recent operation by restoring the view before it.
    pub fn undo(&mut self) -> Result<ObjectId> {
        self.reload()?;
        let op = self.ops.get(&self.op_id)?;
        let parent = *op
            .parents
            .first()
            .ok_or_else(|| VeilError::repo("nothing to undo"))?;
        let undone = op.description.clone();
        let view = self.ops.get(&parent)?.view;
        let mut tx = self.transaction(format!("undo: {undone}"))?;
        tx.view = view;
        tx.record_always();
        Ok(tx.commit()?.expect("recorded"))
    }

    /// Restore the view as of an earlier operation.
    pub fn restore_operation(&mut self, op: ObjectId) -> Result<ObjectId> {
        let view = self.ops.get(&op)?.view;
        let mut tx = self.transaction(format!("restore to operation {}", op.short()))?;
        tx.view = view;
        tx.record_always();
        Ok(tx.commit()?.expect("recorded"))
    }
}
