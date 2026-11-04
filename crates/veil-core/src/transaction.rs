//! Transactions: the only way to change a repository's view.
//!
//! A transaction holds the repository lock, mutates a private copy of the
//! view, and on commit (1) automatically rebases every visible descendant of
//! rewritten snapshots — Jujutsu-style, so there is never a "detached" or
//! orphaned descendant — and (2) appends one operation to the op log.

use std::collections::{BTreeSet, HashMap};

use crate::{
    error::{Result, VeilError},
    id::{ChangeId, ObjectId},
    lock::RepoLock,
    now_millis,
    object::Snapshot,
    oplog::{Operation, View},
    repo::Repo,
};

#[derive(Clone, Debug)]
enum Rewrite {
    Replaced(ObjectId),
    /// Abandoned; children move to these (the abandoned snapshot's parents).
    Abandoned(Vec<ObjectId>),
}

pub struct Transaction<'r> {
    pub(crate) repo: &'r mut Repo,
    pub view: View,
    start_view: View,
    rewritten: HashMap<ObjectId, Rewrite>,
    description: String,
    record_always: bool,
    manual_undo: Option<String>,
    undo_of: Option<ObjectId>,
    redo_of: Option<ObjectId>,
    _lock: RepoLock,
}

impl<'r> Transaction<'r> {
    pub(crate) fn new(repo: &'r mut Repo, description: String, lock: RepoLock) -> Self {
        // Objects are written unsynced and made durable by one barrier in
        // `commit` (or `drop`), before the operation that references them.
        repo.store.begin_unsynced();
        let view = repo.view.clone();
        Transaction {
            repo,
            start_view: view.clone(),
            view,
            rewritten: HashMap::new(),
            description,
            record_always: false,
            manual_undo: None,
            undo_of: None,
            redo_of: None,
            _lock: lock,
        }
    }

    pub fn repo(&self) -> &Repo {
        self.repo
    }

    pub fn set_description(&mut self, d: impl Into<String>) {
        self.description = d.into();
    }

    /// Record an operation even if the view did not change (e.g. embargo
    /// release, which changes shared metadata rather than the view).
    pub fn record_always(&mut self) {
        self.record_always = true;
    }

    /// Record this operation (even with an unchanged view) as one whose
    /// effect `vl undo` cannot reach: `how` says how to reverse it by hand
    /// (see [`crate::oplog::Operation::manual_undo`]).
    pub fn manual_undo(&mut self, how: impl Into<String>) {
        self.record_always = true;
        self.manual_undo = Some(how.into());
    }

    /// Record this operation as the undo of operation `op` (see
    /// [`crate::oplog::Operation::undo_of`]).
    pub fn undo_of(&mut self, op: ObjectId) {
        self.record_always = true;
        self.undo_of = Some(op);
    }

    /// Record this operation as the redo that reverts the undo `op` (see
    /// [`crate::oplog::Operation::redo_of`]).
    pub fn redo_of(&mut self, op: ObjectId) {
        self.record_always = true;
        self.redo_of = Some(op);
    }

    pub fn add_head(&mut self, id: ObjectId) -> Result<()> {
        let s = self.repo.snapshot(&id)?;
        for p in &s.parents {
            self.view.heads.remove(p);
        }
        self.view.heads.insert(id);
        Ok(())
    }

    /// Sign `snap` as produced by this repository's identity (or strip any
    /// stale signature when there is no identity). Every snapshot a
    /// transaction writes passes through here, so whoever *produced* a
    /// snapshot is its signer, including when the auto-rebase rewrites a
    /// snapshot somebody else authored.
    fn sign(&self, snap: &Snapshot) -> Snapshot {
        let mut s = snap.clone();
        match self.repo.identity() {
            Some(id) => s.sign(id),
            None => s.signature = None,
        }
        s
    }

    /// `snap` with its conflict index brought up to date (repository format
    /// 4, see [`crate::conflict::index_conflicts`]): every conflict entry of
    /// its tree, plus the older kinds of conflict the operation carried,
    /// less those resolved since the snapshot it was derived from (the one
    /// it rewrites, else its first parent). Under an unreleased embargo no
    /// conflict is recorded (snapshot metadata is public). Below format 4
    /// the list is the operation's, unchanged.
    pub(crate) fn indexed(&self, snap: Snapshot) -> Result<Snapshot> {
        let store = &self.repo.store;
        if store.format() < crate::object::CONFLICT_REPO_FORMAT {
            return Ok(snap);
        }
        let mut s = snap;
        // A tree this reader cannot walk (sealed, withheld, or hostile and
        // refused) keeps the list the operation computed.
        let tolerated = |e: &VeilError| {
            e.is_unreadable() || e.is_not_found() || matches!(e, VeilError::Corrupt(..) | VeilError::Json(_) | VeilError::Unsupported(_))
        };
        match crate::embargo::unreleased_wrapper(store, &s.tree) {
            Ok(Some(_)) => {
                s.conflicts.clear();
                return Ok(s);
            }
            Ok(None) => {}
            Err(e) if tolerated(&e) => return Ok(s),
            Err(e) => return Err(e),
        }
        let from = s.predecessors.first().or(s.parents.first()).copied();
        let base = match from {
            Some(id) => self.repo.snapshot_opt(&id).ok().flatten(),
            None => None,
        };
        let base = base.as_ref().map(|b| (&b.tree, b.conflicts.as_slice()));
        match crate::conflict::index_conflicts(store, &s.tree, &s.conflicts, base) {
            Ok(list) => s.conflicts = list,
            Err(e) if tolerated(&e) => {}
            Err(e) => return Err(e),
        }
        Ok(s)
    }

    pub fn write_snapshot(&mut self, snap: &Snapshot) -> Result<ObjectId> {
        let snap = self.indexed(snap.clone())?;
        let signed = self.sign(&snap);
        let id = self.repo.store.put_snapshot(&signed)?;
        self.add_head(id)?;
        Ok(id)
    }

    /// Write `snap` as it is, without a signature: for snapshots whose
    /// content is a function of something outside Veil (a Git commit), so
    /// that every replica writing it gets the same id.
    #[cfg(feature = "git")]
    pub(crate) fn write_unsigned_snapshot(&mut self, snap: &Snapshot) -> Result<ObjectId> {
        let mut s = self.indexed(snap.clone())?;
        s.signature = None;
        let id = self.repo.store.put_snapshot(&s)?;
        self.add_head(id)?;
        Ok(id)
    }

    /// Create a new change on top of `parents` (merging them if several).
    ///
    /// The change takes the workspace's `cloak`, not its parents'. Sealed
    /// entries it inherits from a cloaked parent stay sealed regardless: the
    /// builder never moves sealed content to a wider audience (see
    /// `builder.rs`), so `vl new <cloaked change>` cannot declassify it.
    ///
    /// A parent named more than once is recorded once (BUG-240).
    pub fn new_change(&mut self, parents: Vec<ObjectId>, description: &str, cloak: Option<String>) -> Result<ObjectId> {
        let parents = dedup_parents(parents);
        let merged = self.repo.parents_tree(&parents)?;
        let store = &self.repo.store;
        // On a line under an unreleased embargo, messages are sealed under
        // the embargo key and conflicts are not recorded (see `embargo`).
        let scope = crate::embargo::description_scope(store, &merged.tree, cloak.as_deref())?;
        let conflicts = merged.conflicts.iter().map(|p| p.to_string()).collect();
        let snap = Snapshot {
            parents,
            change_id: ChangeId::random(),
            tree: merged.tree,
            description: store.make_text(description, scope.as_deref())?,
            author: self.repo.user.clone(),
            timestamp: now_millis(),
            predecessors: vec![],
            conflicts: crate::embargo::recordable_conflicts(store, &merged.tree, conflicts)?,
            cloak,
            embargo: None,
            signature: None,
        };
        self.write_snapshot(&snap)
    }

    /// Replace `old` with `new` (same change, new content/metadata).
    pub fn rewrite(&mut self, old: ObjectId, new: Snapshot) -> Result<ObjectId> {
        if old == self.repo.root_id {
            return Err(VeilError::repo("the root snapshot cannot be rewritten"));
        }
        // Content identical to `old`: keep `old` and its original signer
        // instead of re-signing an unchanged snapshot. Signatures,
        // predecessors and the timestamp are bookkeeping of the rewrite
        // itself, not content: a rewrite that changes nothing else changes
        // nothing (BUG-246).
        let prev = self.repo.snapshot(&old)?;
        let new = self.indexed(new)?;
        let mut same = new.clone();
        same.predecessors = prev.predecessors.clone();
        same.timestamp = prev.timestamp;
        same.signature = None;
        if prev.unsigned_id() == same.unsigned_id() {
            return Ok(old);
        }
        let id = self.repo.store.put_snapshot(&self.sign(&new))?;
        self.rewritten.insert(old, Rewrite::Replaced(id));
        self.view.heads.remove(&old);
        self.add_head(id)?;
        Ok(id)
    }

    pub fn abandon(&mut self, id: ObjectId) -> Result<()> {
        if id == self.repo.root_id {
            return Err(VeilError::repo("the root snapshot cannot be abandoned"));
        }
        let s = self.repo.snapshot(&id)?;
        self.rewritten.insert(id, Rewrite::Abandoned(s.parents.clone()));
        self.view.heads.remove(&id);
        for p in &s.parents {
            self.view.heads.insert(*p);
        }
        Ok(())
    }

    /// Point a workspace at `id`. An empty, undescribed change left behind is
    /// abandoned automatically (no clutter from savepoints you never used).
    pub fn set_workspace_wc(&mut self, ws: &str, id: ObjectId) -> Result<()> {
        if id == self.repo.root_id {
            return Err(VeilError::repo("cannot edit the root snapshot; use `vl new root` instead"));
        }
        let st = self
            .view
            .workspaces
            .get_mut(ws)
            .ok_or_else(|| VeilError::NotFound(format!("workspace '{ws}'")))?;
        let old = std::mem::replace(&mut st.wc, id);
        if old != id {
            self.maybe_abandon_empty(old)?;
        }
        Ok(())
    }

    pub(crate) fn maybe_abandon_empty(&mut self, id: ObjectId) -> Result<()> {
        if id == self.repo.root_id || self.rewritten.contains_key(&id) || !self.view.heads.contains(&id) {
            return Ok(());
        }
        if self.view.workspaces.values().any(|w| w.wc == id) || self.view.tags.values().any(|t| t.target == id) {
            return Ok(());
        }
        let s = self.repo.snapshot(&id)?;
        let undescribed = self.repo.store.read_text(&s.description).is_some_and(|t| t.trim().is_empty());
        // A change holding a conflict of its own (a merge that conflicted)
        // is kept; one that only inherits its parent's conflicts (format 4:
        // they are in its tree too) is as empty as any.
        let mut own_conflict = false;
        for c in &s.conflicts {
            let mut inherited = false;
            for p in &s.parents {
                if self.repo.snapshot_opt(p)?.is_some_and(|ps| ps.conflicts.contains(c)) {
                    inherited = true;
                }
            }
            own_conflict |= !inherited;
        }
        if undescribed && !own_conflict && self.repo.is_empty_change(&id)? {
            self.abandon(id)?;
        }
        Ok(())
    }

    /// Where did `id` end up? Returns the replacement(s) and whether the
    /// chain passed through an abandon.
    fn resolve(&self, id: ObjectId) -> (Vec<ObjectId>, bool) {
        match self.rewritten.get(&id) {
            None => (vec![id], false),
            Some(Rewrite::Replaced(n)) => self.resolve(*n),
            Some(Rewrite::Abandoned(ps)) => {
                let mut out = Vec::new();
                for p in ps {
                    for x in self.resolve(*p).0 {
                        if !out.contains(&x) {
                            out.push(x);
                        }
                    }
                }
                (out, true)
            }
        }
    }

    /// Rebase the descendants of what was rewritten so far now, rather than
    /// at commit: for a rewrite that then edits one of them (`vl squash
    /// --into` a descendant, or from a descendant into an ancestor). Commit
    /// rebases again whatever is rewritten after this.
    pub(crate) fn rebase_now(&mut self) -> Result<()> {
        if self.rewritten.is_empty() {
            return Ok(());
        }
        self.rebase_descendants()
    }

    /// The snapshot `id` is now, if it was rewritten into exactly one (or
    /// left alone); `None` if it was abandoned.
    pub(crate) fn current(&self, id: ObjectId) -> Option<ObjectId> {
        match self.resolve(id) {
            (r, false) if r.len() == 1 => Some(r[0]),
            _ => None,
        }
    }

    fn rebase_descendants(&mut self) -> Result<()> {
        let mut roots = self.start_view.refs();
        roots.extend(self.view.refs());
        let order = self.repo.topo_children_first(roots)?;
        let store = self.repo.store.clone();
        for id in order.into_iter().rev() {
            if self.rewritten.contains_key(&id) {
                continue;
            }
            let s = self.repo.snapshot(&id)?;
            let mut new_parents = Vec::new();
            for p in &s.parents {
                for r in self.resolve(*p).0 {
                    if !new_parents.contains(&r) {
                        new_parents.push(r);
                    }
                }
            }
            if new_parents == s.parents {
                continue;
            }
            // The merge of the new parents, plus what this snapshot changed
            // relative to the merge of its old ones. A merge one of whose
            // parents moved is re-merged, never rebased by one parent's diff
            // (that dropped what the other parents hold, BUG-251).
            let out = self.repo.rebase_tree(&s.parents, &new_parents, s.tree, s.cloak.as_deref())?;
            let tree = out.tree;
            let mut conflicts: BTreeSet<String> = s.conflicts.iter().cloned().collect();
            conflicts.extend(out.conflicts.iter().map(|c| c.to_string()));
            let mut ns = (*s).clone();
            ns.parents = new_parents;
            ns.tree = tree;
            ns.predecessors = vec![id];
            ns.conflicts = crate::embargo::recordable_conflicts(&store, &tree, conflicts.into_iter().collect())?;
            // Rebasing someone else's change: `author` stays theirs, the
            // signature becomes ours, and `predecessors` keeps the original.
            let ns = self.indexed(ns)?;
            let nid = store.put_snapshot(&self.sign(&ns))?;
            self.rewritten.insert(id, Rewrite::Replaced(nid));
            self.view.heads.remove(&id);
            self.add_head(nid)?;
        }

        // Re-point every reference.
        let heads: Vec<ObjectId> = self.view.heads.iter().copied().collect();
        self.view.heads = heads.into_iter().flat_map(|h| self.resolve(h).0).collect();
        let root = self.repo.root_id;
        let tags: Vec<(String, ObjectId)> = self.view.tags.iter().map(|(n, t)| (n.clone(), t.target)).collect();
        for (name, target) in tags {
            if self.rewritten.contains_key(&target) {
                let r = self.resolve(target).0;
                self.view.tags.get_mut(&name).unwrap().target = r.first().copied().unwrap_or(root);
            }
        }
        let wss: Vec<(String, ObjectId, Option<String>)> = self
            .view
            .workspaces
            .iter()
            .map(|(n, w)| (n.clone(), w.wc, w.cloak.clone()))
            .collect();
        for (name, wc, cloak) in wss {
            if !self.rewritten.contains_key(&wc) {
                continue;
            }
            let (r, abandoned) = self.resolve(wc);
            let new_wc = if !abandoned && r.len() == 1 {
                r[0]
            } else {
                let parents = if r.is_empty() { vec![root] } else { r };
                self.new_change(parents, "", cloak)?
            };
            self.view.workspaces.get_mut(&name).unwrap().wc = new_wc;
        }
        Ok(())
    }

    /// Finish the transaction. Returns the new operation id, or `None` if
    /// nothing changed.
    pub fn commit(mut self) -> Result<Option<ObjectId>> {
        if !self.rewritten.is_empty() {
            self.rebase_descendants()?;
        }
        // Durability barrier: every object this transaction wrote is on
        // stable storage before the operation that references it is written.
        self.repo.store.sync_barrier()?;
        if self.view == self.start_view && !self.record_always {
            return Ok(None);
        }
        let op = Operation {
            parents: vec![self.repo.op_id],
            timestamp: now_millis(),
            user: self.repo.user.clone(),
            description: self.description.clone(),
            view: self.view.clone(),
            manual_undo: self.manual_undo.clone(),
            undo_of: self.undo_of,
            redo_of: self.redo_of,
        };
        let id = self.repo.ops.put(&op)?;
        // Fencing: never move the head unless we still hold the lock.
        self._lock.ensure_held()?;
        self.repo.ops.set_head(&id)?;
        self.repo.op_id = id;
        self.repo.view = std::mem::take(&mut self.view);
        Ok(Some(id))
    }
}

/// `parents` without repeats, first occurrence kept (BUG-240).
pub(crate) fn dedup_parents(parents: Vec<ObjectId>) -> Vec<ObjectId> {
    let mut out: Vec<ObjectId> = Vec::with_capacity(parents.len());
    for p in parents {
        if !out.contains(&p) {
            out.push(p);
        }
    }
    out
}

impl Drop for Transaction<'_> {
    /// Also on abort or error, so unsynced objects do not outlive the lock
    /// (released after this, when `_lock` drops): only a holder that dies
    /// leaves any, and the next holder recovers them.
    ///
    /// A failed barrier (here or in `commit`) voids the objects it covered:
    /// the store removes them, so neither this process nor the next lock
    /// holder reuses a copy that may never reach the disk. If they cannot
    /// be removed, the lock is left behind flagged for recovery instead of
    /// being released, and the next holder (in any process) rewrites or
    /// removes them before doing anything else.
    fn drop(&mut self) {
        self.repo.store.end_unsynced();
        let _ = self.repo.store.sync_barrier();
        if self.repo.store.take_needs_recovery() {
            self._lock.abandon();
        }
    }
}
