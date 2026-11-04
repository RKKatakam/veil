//! High-level history operations. Each is one transaction → one op-log entry.

use std::collections::BTreeSet;

use crate::{
    embargo::{
        apply_embargo, normalize_tree, policy_rekeys, seal_introduced, unreleased_wrapper, wrap, NormalizeOptions,
        NormalizeReport,
    },
    error::{Result, VeilError},
    id::{ChangeId, ObjectId},
    merge::merge_trees,
    now_millis,
    object::{Snapshot, TreeEntry},
    oplog::Tag,
    policy::{Policy, POLICY_FILE},
    repo::Repo,
    store::ObjectStore,
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
    /// Files of a merged-in cloaked line of work that this merge made public
    /// (each was secret-scanned first).
    pub declassified: Vec<String>,
    /// Files that would have become public but hold a secret: left out of
    /// the merge (the destination keeps its own version, if any).
    pub quarantined: Vec<String>,
    /// Visibility changes the merge refused to make silently.
    pub warnings: Vec<String>,
}

/// `tree` with its root entry `name` replaced by `entry` (or removed).
fn with_root_entry(store: &ObjectStore, tree: &ObjectId, name: &str, entry: Option<TreeEntry>) -> Result<ObjectId> {
    let mut t = (*store.tree(tree)?).clone();
    match entry {
        Some(e) => t.insert(e),
        None => {
            t.remove(name);
        }
    }
    store.put_tree(&t)
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
        // Folding into a cloaked change: what the result introduces is part
        // of the cloaked line and must be sealed like the rest of it.
        if let Some(scope) = &p.cloak {
            let base = tx.repo().parents_tree(&p.parents)?.tree;
            np.tree = seal_introduced(&tx.repo().store, &np.tree, Some(base), scope)?;
        }
        np.predecessors = vec![*parent, id];
        let pd = tx.repo().description(&p);
        let sd = tx.repo().description(&s);
        if !sd.trim().is_empty() {
            let joined = if pd.trim().is_empty() { sd } else { format!("{pd}\n\n{sd}") };
            // A cloaked change's description stays sealed for its scope, even
            // when folded into a public parent (the joined text is sealed).
            let scope = match (&p.cloak, &s.cloak) {
                (Some(a), Some(b)) if a != b => {
                    return Err(VeilError::Policy(format!(
                        "cannot squash a change cloaked under '{b}' into one cloaked under '{a}'"
                    )))
                }
                (a, b) => a.as_deref().or(b.as_deref()),
            };
            np.description = tx.repo().store.make_text(&joined, scope)?;
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
        // Embargo records are synced to every remote, public ones included,
        // so the record carries no message; the merge's description is
        // sealed under the embargo key instead.
        let embargo_id = match &embargo {
            Some(spec) => Some(self.keys().create_embargo(&spec.scope, spec.until, "")?),
            None => None,
        };
        let mut tx = self.transaction("merge")?;
        let mut parents = vec![into];
        parents.extend(others.iter().copied());
        let into_snap = tx.repo().snapshot(&into)?;
        let store = tx.repo().store.clone();
        let cloak = into_snap.cloak.as_deref();
        let merged = tx.repo().parents_tree(&parents)?;
        let outer = unreleased_wrapper(&store, &merged.tree)?;
        let dest_policy = Policy::load(&TreeView::new(store.clone(), into_snap.tree))?;
        let mut policy = Policy::load(&TreeView::new(store.clone(), merged.tree))?;
        let mut warnings = Vec::new();
        let mut tree = merged.tree;

        // A merged `.veilpolicy` that would move existing cloaked content to
        // another audience (re-key it, or make it public) is not taken: the
        // destination's policy is kept and the member is told. Applying it
        // is a deliberate edit, not a side effect of merging someone's PR.
        let mut rekeys = policy_rekeys(&store, &into_snap.tree, &dest_policy, &policy, cloak)?;
        for r in policy_rekeys(&store, &tree, &dest_policy, &policy, cloak)? {
            if !rekeys.iter().any(|(p, _, _)| *p == r.0) {
                rekeys.push(r);
            }
        }
        if !rekeys.is_empty() {
            let dest_entry = store.tree(&into_snap.tree)?.get(POLICY_FILE).cloned();
            tree = with_root_entry(&store, &tree, POLICY_FILE, dest_entry)?;
            policy = dest_policy.clone();
            let list: Vec<String> = rekeys
                .iter()
                .map(|(p, from, to)| format!("{p}: {} → {}", from.label(), to.label()))
                .collect();
            warnings.push(format!(
                "kept the destination's {POLICY_FILE}: the merged one would change the audience of existing cloaked files ({}); review it and apply it deliberately",
                list.join(", ")
            ));
        }

        // Merging a cloaked line of work into this one is the explicit act
        // that may publish its files (secret-scanned).
        let mut declassify = BTreeSet::new();
        for o in &others {
            if let Some(c) = tx.repo().snapshot(o)?.cloak.clone() {
                if Some(c.as_str()) != cloak {
                    declassify.insert(c);
                }
            }
        }
        let mut report = NormalizeReport::default();
        tree = normalize_tree(
            &store,
            &tree,
            &NormalizeOptions {
                policy: &policy,
                dest_policy: &dest_policy,
                dest_tree: into_snap.tree,
                cloak,
                declassify: &declassify,
            },
            &mut report,
        )?;
        // The destination is under an unreleased embargo: stay under it.
        if let Some(w) = &outer {
            if tree != merged.tree {
                tree = wrap(&store, &w.embargo, &tree, &w.fallback)?;
            }
        }
        if let Some(e) = &embargo_id {
            tree = apply_embargo(&store, &tree, &into_snap.tree, e)?;
        }
        let description = match (&embargo_id, cloak) {
            (Some(e), None) => store.make_text(message, Some(&format!("embargo/{e}")))?,
            _ => store.make_text(message, cloak)?,
        };
        warnings.extend(report.kept_sealed.iter().map(|(p, why)| format!("{p} {why}")));
        let snap = Snapshot {
            parents,
            change_id: ChangeId::random(),
            tree,
            description,
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
            declassified: report.declassified.iter().map(|p| p.to_string()).collect(),
            quarantined: report
                .quarantined
                .iter()
                .map(|(p, f)| {
                    let rules: Vec<&str> = f.iter().map(|f| f.rule).collect();
                    format!("{p} ({})", rules.join(", "))
                })
                .collect(),
            warnings,
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
            if rec.is_released() || rec.until.is_none_or(|u| u > now) || !self.keys().embargo_trusted(&rec) {
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
