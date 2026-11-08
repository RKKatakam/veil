//! Transactions: the only way to change a repository's view.
//!
//! A transaction mutates a private copy of the view, and on commit (1)
//! automatically rebases every visible descendant of rewritten snapshots —
//! Jujutsu-style, so there is never a "detached" or orphaned descendant —
//! and (2) appends one operation to the op log.
//!
//! **Up to format 5, and on remotes,** a transaction holds the repository
//! lock from start to commit, and moves the single op head under it.
//! **From format 6, locally,** it takes no lock (`docs/design/scale/
//! 2-lock-free-oplog.md`): it records the heads it started from (its
//! *base*), stages its new objects in its own directory
//! (`ObjectStore::begin_tx_staging`), and at commit
//! publishes them, re-checks what it was promised (the working copies it
//! recorded still where they were; the repository not upgraded), and
//! publishes its operation with the base as parents. Concurrent operations
//! leave several heads, which [`Repo::settle`] merges at once: a
//! deterministic 3-way merge of the views ([`crate::oplog::merge_views`])
//! that applies each side's rewrites to the other's new snapshots
//! (`Transaction::for_merge`) and never lets that move a change out of an
//! unreleased embargo.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crate::{
    error::{Result, VeilError},
    id::{ChangeId, ObjectId},
    lock::RepoLock,
    now_millis,
    object::Snapshot,
    oplog::{Operation, RawHeads, View},
    repo::Repo,
    vpath::VPath,
};

/// How old a transaction may get before it freshens, at commit, every
/// pre-existing object it references (half of gc's default grace period:
/// gc deletes only what stayed unreachable for the whole grace period).
const FRESHEN_AFTER_MS: i64 = (crate::gc::DEFAULT_GRACE.as_secs() as i64) * 1000 / 2;

/// The marker a superseded compare-and-swap returns (see
/// [`Transaction::expect_wc`]).
pub(crate) const SUPERSEDED: &str = "the working copy moved while this command ran";

/// What a merge transaction ([`Transaction::for_merge`]) works from.
struct MergeCtx {
    /// The views of the merged heads and of the common operations the
    /// merge was computed against: a change any of them had inside an
    /// unreleased embargo must stay inside it.
    before: Vec<View>,
    /// The merged view and rewrites, before any was dropped.
    view: View,
    rewritten: HashMap<ObjectId, Rewrite>,
    /// Seed of change ids the merge creates, and their timestamp: two
    /// processes merging the same heads write the same objects.
    seed: ObjectId,
    timestamp: i64,
    warnings: Vec<String>,
    /// Snapshots the current round left on their old parents, because
    /// rebasing them was refused (with why).
    held: Vec<(ObjectId, String)>,
}

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
    /// The workspace this operation attaches the project directory to (a
    /// `ws switch`, its undo or redo): its working copy is fetched ahead.
    attaches: Option<String>,
    undo_of: Option<ObjectId>,
    redo_of: Option<ObjectId>,
    /// The repository lock (format ≤ 5, remotes); `None` when lock-free.
    lock: Option<RepoLock>,
    /// The heads this transaction started from: its operation's parents.
    base: Vec<ObjectId>,
    /// The head files read with them (stale ancestors, a stray `op_head`).
    stale: RawHeads,
    /// [`Operation::workspace`].
    workspace: Option<String>,
    /// Working copies this transaction recorded, with the snapshot each
    /// pointed at when it started: re-checked at commit.
    expected: Vec<(String, ObjectId)>,
    /// When it started, on the wall clock (threat 14).
    started: i64,
    /// New objects go to a staging directory (format 6, not over a network).
    staging: bool,
    /// Registered for gc's deletion fence (and naming the staging
    /// directory) until the transaction ends (BUG-811,
    /// [`crate::maintenance`]).
    reg: Option<crate::maintenance::Registration>,
    /// gc deleted objects since the command last read its view: check at
    /// commit that what this transaction brought in is still there.
    pub(crate) check_carried: bool,
    merge: Option<MergeCtx>,
    done: bool,
    /// The staging directory, kept after the objects' publication for the
    /// staged operation ([`STAGED_OP`]); removed when it is published, or
    /// when the transaction ends without publishing it.
    kept_dir: Option<VPath>,
}

/// Names of the operation's bytes and of its (empty) head file in a
/// transaction's staging directory (format 6).
const STAGED_OP: &str = "operation";
const STAGED_HEAD: &str = "head";

impl<'r> Transaction<'r> {
    pub(crate) fn new(repo: &'r mut Repo, description: String, lock: Option<RepoLock>) -> Result<Self> {
        Self::registered(repo, description, lock, None)
    }

    /// [`Transaction::new`], registered (if it stages objects) by `reg`,
    /// taken before the caller read the heads it starts from.
    pub(crate) fn registered(
        repo: &'r mut Repo,
        description: String,
        lock: Option<RepoLock>,
        reg: Option<crate::maintenance::Registration>,
    ) -> Result<Self> {
        let staging = repo.stages_objects();
        let reg = match staging {
            true => {
                let reg = match reg {
                    Some(r) => r,
                    None => crate::maintenance::Registration::enter(&repo.store)?,
                };
                // Packs gc removed before we registered may still be in
                // this process's list: a presence check must not trust it.
                repo.store.refresh_packs()?;
                repo.store.begin_tx_staging(reg.tag())?;
                Some(reg)
            }
            // Objects are written unsynced and made durable by one barrier
            // in `commit` (or `drop`), before the operation that references
            // them.
            false => {
                repo.store.begin_unsynced();
                None
            }
        };
        let view = repo.view.clone();
        let workspace = repo.command_ws.clone();
        Ok(Transaction {
            base: repo.base.clone(),
            stale: repo.raw.clone(),
            started: now_millis(),
            repo,
            start_view: view.clone(),
            view,
            rewritten: HashMap::new(),
            description,
            record_always: false,
            manual_undo: None,
            attaches: None,
            undo_of: None,
            redo_of: None,
            lock,
            workspace,
            expected: Vec::new(),
            staging,
            reg,
            check_carried: false,
            merge: None,
            done: false,
            kept_dir: None,
        })
    }

    /// The merge of the heads `parents` (sorted) into one operation: starts
    /// from their merged `view`, applies `rewritten` (the sides' rewrites)
    /// at commit, and keeps every change any of `before` had inside an
    /// unreleased embargo inside it. Takes no lock: the caller holds it if
    /// the repository needs one.
    pub(crate) fn for_merge(repo: &'r mut Repo, parents: Vec<ObjectId>, stale: RawHeads, plan: crate::repo::MergePlan) -> Result<Self> {
        let crate::repo::MergePlan {
            view,
            rewritten,
            before,
            timestamp,
            warnings,
        } = plan;
        let n = parents.len();
        let mut tx = Transaction::new(repo, format!("merge {n} concurrent operations"), None)?;
        tx.base = parents;
        tx.stale = stale;
        tx.workspace = None;
        tx.record_always = true;
        let mut seed = Vec::new();
        for p in &tx.base {
            seed.extend_from_slice(&p.0);
        }
        let mut rw = HashMap::new();
        for (old, new) in rewritten {
            let r = match new.as_slice() {
                [] => match tx.repo.exact().snapshot(&old)? {
                    Some(s) => Rewrite::Abandoned(s.parents.clone()),
                    None => continue,
                },
                [one] => Rewrite::Replaced(*one),
                _ => continue,
            };
            rw.insert(old, r);
        }
        tx.view = view.clone();
        tx.start_view = view.clone();
        tx.rewritten = rw.clone();
        tx.merge = Some(MergeCtx {
            before,
            view,
            rewritten: rw,
            seed: ObjectId::hash(&seed),
            timestamp,
            warnings,
            held: Vec::new(),
        });
        Ok(tx)
    }

    /// Record this operation as one of no particular workspace (tags,
    /// remotes, push, pull): `vl undo` in any workspace may undo it.
    pub fn repository_wide(&mut self) {
        self.workspace = None;
    }

    /// This operation attaches the project directory to workspace `ws`
    /// (thin clones fetch ahead what it will hold, BUG-1263).
    pub fn attaches(&mut self, ws: &str) {
        self.attaches = Some(ws.to_string());
    }

    /// Record this operation as run for workspace `ws`.
    pub fn for_workspace(&mut self, ws: &str) {
        self.workspace = Some(ws.to_string());
    }

    /// The working copy of `ws` is being recorded from a directory that
    /// was materialised from `wc`: commit fails with "superseded"
    /// ([`Transaction::is_superseded`]) if an operation that landed since
    /// this transaction started moved it.
    pub fn expect_wc(&mut self, ws: &str, wc: ObjectId) {
        self.expected.push((ws.to_string(), wc));
    }

    /// Is `e` the error of a superseded [`Transaction::expect_wc`]?
    pub fn is_superseded(e: &VeilError) -> bool {
        matches!(e, VeilError::Repo(m) if m.starts_with(SUPERSEDED))
    }

    #[doc(hidden)]
    /// Pretend this transaction started `ms` earlier (tests of threat 14).
    pub fn backdate(&mut self, ms: i64) {
        self.started -= ms;
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
    /// it rewrites, else its first parent). Below format 4 the list is the
    /// operation's, unchanged.
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
        let from = s.predecessors.first().or(s.parents.first()).copied();
        let base = match from {
            Some(id) => self.repo.exact().snapshot(&id).ok().flatten(),
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

    /// Create a new change on top of `parents` (merging them if several).
    /// Sealed secrets it inherits stay sealed: the builder never moves
    /// sealed content to a wider audience (see `builder.rs`).
    ///
    /// A parent named more than once is recorded once (BUG-240).
    pub fn new_change(&mut self, parents: Vec<ObjectId>, description: &str) -> Result<ObjectId> {
        let parents = dedup_parents(parents);
        let merged = self.repo.parents_tree(&parents)?;
        let conflicts = merged.conflicts.iter().map(|p| p.to_string()).collect();
        // A merge of concurrent operations derives what is random elsewhere,
        // so that every process merging the same heads writes the same.
        let (change_id, timestamp) = match &self.merge {
            Some(m) => {
                let mut seed = m.seed.0.to_vec();
                for p in &parents {
                    seed.extend_from_slice(&p.0);
                }
                seed.extend_from_slice(description.as_bytes());
                let h = ObjectId::hash(&seed);
                let mut id = [0u8; 16];
                id.copy_from_slice(&h.0[..16]);
                (ChangeId(id), m.timestamp)
            }
            None => (ChangeId::random(), now_millis()),
        };
        let snap = Snapshot {
            parents,
            change_id,
            tree: merged.tree,
            description: crate::object::Text::Plain(description.to_string()),
            author: self.repo.user.clone(),
            timestamp,
            predecessors: vec![],
            conflicts,
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

    /// Move this clone to its person's current view (BUG-1509), in this
    /// transaction: after an access change the server names every snapshot
    /// above a folder the person lost under another id (its projection in
    /// the view they have now), and serves the old ids no more. Each server
    /// snapshot the view refers to (a tag, a head, a workspace, the base of
    /// a change only this clone holds) is replaced by its current
    /// projection; each change only this clone holds is rebased onto its
    /// parents' projections (`Repo::rebase_tree`: what the new parent no
    /// longer names is gone, and the server grafts it back on push).
    /// Nothing below a folder the person lost is read or written: the
    /// paths lost are found where the old and new parents differ, and a
    /// change is only compared with its parent there. A change that edited
    /// inside one stays exactly where it is, never rewritten, with every
    /// change connected to it (they cannot move without it), and is named
    /// in [`ViewMove::kept`]. Tags, workspaces and heads follow at commit.
    pub fn move_to_view(&mut self) -> Result<ViewMove> {
        let store = self.repo.store.clone();
        let root = self.repo.root_id;
        let mut out = ViewMove::default();
        if !store.is_partial() {
            return Ok(out);
        }
        // What the view refers to, and the changes only this clone holds.
        let mut refs: Vec<ObjectId> = self.view.tags.values().filter(|t| t.annotation.is_none()).map(|t| t.target).collect();
        refs.extend(self.view.workspaces.values().map(|w| w.wc));
        refs.extend(self.view.heads.iter().copied());
        refs.sort();
        refs.dedup();
        let mut local: HashMap<ObjectId, std::sync::Arc<Snapshot>> = HashMap::new();
        let mut servers: BTreeSet<ObjectId> = BTreeSet::new();
        let mut order: Vec<ObjectId> = Vec::new();
        // Parents first (an explicit post-order: history depth is not
        // trusted).
        let mut stack: Vec<(ObjectId, bool)> = refs.iter().map(|r| (*r, false)).collect();
        let mut seen: HashSet<ObjectId> = HashSet::new();
        while let Some((id, done)) = stack.pop() {
            if done {
                order.push(id);
                continue;
            }
            if !seen.insert(id) {
                continue;
            }
            if id == root || store.is_servers(&id) {
                servers.insert(id);
                continue;
            }
            let snap = self.repo.snapshot(&id)?;
            stack.push((id, true));
            stack.extend(snap.parents.iter().map(|p| (*p, false)));
            local.insert(id, snap);
        }
        // Each server snapshot's current projection.
        let mut map: HashMap<ObjectId, ObjectId> = HashMap::new();
        for s in &servers {
            if *s == root {
                continue;
            }
            if let Some(n) = store.current_projection(s)? {
                if n != *s {
                    map.insert(*s, n);
                }
            }
        }
        if map.is_empty() {
            return Ok(out);
        }
        // The paths each base lost, then each change's (its parents').
        let mut lost: HashMap<ObjectId, Option<Vec<VPath>>> = HashMap::new();
        for (old, new) in &map {
            if local.values().any(|c| c.parents.contains(old)) {
                lost.insert(*old, lost_paths(&store, &self.repo.snapshot(old)?.tree, &self.repo.snapshot(new)?.tree)?);
            }
        }
        let mut refused: HashMap<ObjectId, VPath> = HashMap::new();
        for id in &order {
            let c = &local[id];
            let mut paths: Option<Vec<VPath>> = Some(Vec::new());
            for p in &c.parents {
                let from = match lost.get(p) {
                    Some(l) => l.clone(),
                    None => Some(Vec::new()),
                };
                match (paths.as_mut(), from) {
                    (Some(all), Some(more)) => all.extend(more),
                    _ => paths = None,
                }
            }
            // Its own entry at each lost path, against its parents'.
            let paths = match paths {
                Some(p) => p,
                None => {
                    refused.insert(*id, VPath::root());
                    lost.insert(*id, None);
                    continue;
                }
            };
            for r in &paths {
                let mine = crate::tree::lookup(&store, &c.tree, r).ok();
                let mut same = false;
                for p in &c.parents {
                    let theirs = crate::tree::lookup(&store, &self.repo.snapshot(p)?.tree, r).ok();
                    same |= mine.is_some() && mine == theirs;
                }
                if !same && !refused.contains_key(id) {
                    refused.insert(*id, r.clone());
                }
            }
            lost.insert(*id, Some(paths));
        }
        // What cannot move: every change connected to a refused one.
        let mut kept: HashSet<ObjectId> = HashSet::new();
        if !refused.is_empty() {
            let mut neighbours: HashMap<ObjectId, Vec<ObjectId>> = HashMap::new();
            for (id, c) in &local {
                for p in c.parents.iter().filter(|p| local.contains_key(p)) {
                    neighbours.entry(*id).or_default().push(*p);
                    neighbours.entry(*p).or_default().push(*id);
                }
            }
            let mut todo: Vec<ObjectId> = refused.keys().copied().collect();
            while let Some(x) = todo.pop() {
                if kept.insert(x) {
                    todo.extend(neighbours.get(&x).into_iter().flatten().copied());
                }
            }
            let mut names: Vec<(ObjectId, VPath)> = refused.into_iter().collect();
            names.sort();
            for (id, folder) in names {
                out.kept.push(KeptChange { id, folder });
            }
            out.kept_with = kept.len() - out.kept.len();
        }
        // Parents first, onto the projections of theirs.
        let mut moved: HashMap<ObjectId, ObjectId> = HashMap::new();
        for id in order.iter().filter(|id| !kept.contains(id)) {
            let s = &local[id];
            let parents: Vec<ObjectId> = s.parents.iter().map(|p| *map.get(p).or_else(|| moved.get(p)).unwrap_or(p)).collect();
            if parents == s.parents {
                continue;
            }
            let merged = self.repo.rebase_tree(&s.parents, &parents, s.tree)?;
            let mut conflicts: BTreeSet<String> = s.conflicts.iter().cloned().collect();
            conflicts.extend(merged.conflicts.iter().map(|c| c.to_string()));
            let mut ns = (**s).clone();
            ns.parents = parents;
            ns.tree = merged.tree;
            ns.predecessors = vec![*id];
            ns.conflicts = conflicts.into_iter().collect();
            let ns = self.indexed(ns)?;
            let nid = store.put_snapshot(&self.sign(&ns))?;
            self.rewritten.insert(*id, Rewrite::Replaced(nid));
            self.view.heads.remove(id);
            self.add_head(nid)?;
            moved.insert(*id, nid);
            if let Some(Some(paths)) = lost.get(id) {
                // With the version the working copy held there, for when
                // the folder comes back.
                let held: Vec<(VPath, Option<ObjectId>)> = paths
                    .iter()
                    .map(|r| (r.clone(), crate::tree::lookup(&store, &s.tree, r).ok().flatten().filter(|e| e.kind == crate::object::EntryKind::Dir).map(|e| e.id)))
                    .collect();
                for (ws, st) in &self.view.workspaces {
                    if st.wc == *id {
                        out.lost.insert(ws.clone(), held.clone());
                    }
                }
            }
        }
        out.moved = moved.len();
        // The server's snapshots the view names: their projections.
        for t in self.view.tags.values_mut().filter(|t| t.annotation.is_none()) {
            if let Some(n) = map.get(&t.target) {
                t.target = *n;
                out.mapped += 1;
            }
        }
        for w in self.view.workspaces.values_mut() {
            if let Some(n) = map.get(&w.wc) {
                w.wc = *n;
                out.mapped += 1;
            }
        }
        let heads: Vec<ObjectId> = self.view.heads.iter().copied().filter(|h| map.contains_key(h)).collect();
        for h in heads {
            self.view.heads.remove(&h);
            self.add_head(map[&h])?;
            out.mapped += 1;
        }
        Ok(out)
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
        let undescribed = s.description.as_str().trim().is_empty();
        // A change holding a conflict of its own (a merge that conflicted)
        // is kept; one that only inherits its parent's conflicts (format 4:
        // they are in its tree too) is as empty as any.
        let mut own_conflict = false;
        for c in &s.conflicts {
            let mut inherited = false;
            for p in &s.parents {
                if self.repo.exact().snapshot(p)?.is_some_and(|ps| ps.conflicts.contains(c)) {
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
        self.resolve_from(id, &mut Vec::new())
    }

    /// [`Transaction::resolve`], safe against cycles (merged rewrites from
    /// concurrent operations can form one, e.g. a rewrite and its
    /// reversal): a snapshot on a cycle resolves to itself.
    fn resolve_from(&self, id: ObjectId, path: &mut Vec<ObjectId>) -> (Vec<ObjectId>, bool) {
        if path.contains(&id) {
            return (vec![path[0]], false);
        }
        path.push(id);
        let out = match self.rewritten.get(&id) {
            None => (vec![id], false),
            Some(Rewrite::Replaced(n)) => self.resolve_from(*n, path),
            Some(Rewrite::Abandoned(ps)) => {
                let mut out = Vec::new();
                for p in ps {
                    for x in self.resolve_from(*p, path).0 {
                        if !out.contains(&x) {
                            out.push(x);
                        }
                    }
                }
                (out, true)
            }
        };
        path.pop();
        out
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
        // Only descendants of a rewritten snapshot can move, and each has a
        // larger generation than the oldest one: the walk stops there
        // instead of reading all history.
        let mut floor = crate::graph_index::Gen::MAX;
        for old in self.rewritten.keys() {
            // Exactly (a thin clone: the rewritten change may be one it
            // has just fetched, its descendants above it unheld: BUG-1290).
            if let Some(g) = self.repo.exact().generation(old)? {
                floor = floor.min(g);
            }
        }
        let mut order: Vec<(crate::graph_index::Gen, i64, ObjectId)> = match floor {
            crate::graph_index::Gen::MAX => Vec::new(),
            f => self
                .repo
                .exact()
                .down_to(roots, f + 1)?
                .into_iter()
                .map(|(id, (g, s))| (g, s.timestamp, id))
                .collect(),
        };
        // Parents first: a parent has a smaller generation than its child.
        order.sort();
        let store = self.repo.store.clone();
        for id in order.into_iter().map(|(_, _, id)| id) {
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
            let out = match self.repo.rebase_tree(&s.parents, &new_parents, s.tree) {
                // A merge of concurrent operations never fails for a policy
                // reason (threat 18; two embargoes combined, say): this
                // snapshot, and what is built on it, stay where their side
                // put them, and the warning names it.
                Err(VeilError::Policy(why)) if self.merge.is_some() => {
                    self.merge.as_mut().expect("a merge").held.push((id, why));
                    continue;
                }
                r => r?,
            };
            let tree = out.tree;
            let mut conflicts: BTreeSet<String> = s.conflicts.iter().cloned().collect();
            conflicts.extend(out.conflicts.iter().map(|c| c.to_string()));
            let mut ns = (*s).clone();
            ns.parents = new_parents;
            ns.tree = tree;
            ns.predecessors = vec![id];
            ns.conflicts = conflicts.into_iter().collect();
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
        // A release tag (annotated, format 5) is immutable: it stays on the
        // snapshot it was made for, which it keeps visible, and its signed
        // annotation keeps matching it.
        let tags: Vec<(String, ObjectId)> =
            self.view.tags.iter().filter(|(_, t)| t.annotation.is_none()).map(|(n, t)| (n.clone(), t.target)).collect();
        for (name, target) in tags {
            if self.rewritten.contains_key(&target) {
                let r = self.resolve(target).0;
                self.view.tags.get_mut(&name).unwrap().target = r.first().copied().unwrap_or(root);
            }
        }
        let wss: Vec<(String, ObjectId)> = self.view.workspaces.iter().map(|(n, w)| (n.clone(), w.wc)).collect();
        for (name, wc) in wss {
            if !self.rewritten.contains_key(&wc) {
                continue;
            }
            let (r, abandoned) = self.resolve(wc);
            let new_wc = if !abandoned && r.len() == 1 {
                r[0]
            } else {
                let parents = if r.is_empty() { vec![root] } else { r };
                self.new_change(parents, "")?
            };
            self.view.workspaces.get_mut(&name).unwrap().wc = new_wc;
        }
        Ok(())
    }

    /// BUG-942/943/990/1015/1016: what an unreleased embargo withholds
    /// stays withheld. The rule is by change (`remote::Withheld`): every
    /// version of a change of the fix line, and everything descending from
    /// one. After any transaction, no visible snapshot that the rule of the
    /// view it started from withheld may be left unwithheld, unless its
    /// embargo was released or withdrawn: a squash of the merge into its
    /// follow-up or into the fix, an abandon that rebases the follow-up
    /// onto the merge's parents, a rebase of the merge onto other parents
    /// (which keeps its `embargo` field but no longer covers the fix), ...
    ///
    /// And every withheld snapshot the transaction rewrote (not abandoned)
    /// must have visible successors that are still withheld, unless the
    /// embargo was released (BUG-1040: work withheld only by descent, which
    /// holds the fix after `vl squash -r fix --into` it, rebased off the
    /// merge when the merge goes).
    ///
    /// An embargo is withdrawn, as undoing the merge withdraws it, when no
    /// visible snapshot carries it any more and the transaction replaced
    /// nothing it withheld (only dropped it: the bare merge abandoned, or a
    /// view restored by `vl undo`). The rule depends only on the visible
    /// embargoed merges: a transaction without rewrites that leaves them as
    /// they were cannot break it, and is not checked further.
    fn check_withheld(&mut self) -> Result<()> {
        let before = vec![self.repo.view.clone()];
        match self.withheld_violations(&before)?.into_iter().next() {
            None => Ok(()),
            Some((x, e)) => Err(VeilError::Policy(format!(
                "cannot drop, replace or move the embargoed merge of unreleased embargo {e} this way: change {} (which the embargo withholds) would stay visible but no longer be withheld, so the next push would publish it before the release; release the embargo first (`vl embargo release {e}`), or abandon what is built on the merge too",
                self.repo.snapshot(&x)?.change_id.short()
            ))),
        }
    }

    /// The visible unreleased embargoed merges of view `v`, sorted.
    fn embargoed_merges_in(&mut self, v: &View) -> Result<Vec<ObjectId>> {
        let mut v = v.clone();
        std::mem::swap(&mut self.repo.view, &mut v);
        let res = self.repo.exact().visible_embargoed();
        std::mem::swap(&mut self.repo.view, &mut v);
        let mut out = Vec::new();
        for id in res? {
            if self.repo.snapshot(&id)?.embargo.as_deref().is_some_and(|e| !self.repo.keys().embargo_released(e)) {
                out.push(id);
            }
        }
        out.sort();
        Ok(out)
    }

    /// [`Transaction::check_withheld`]'s findings: `(a version of a
    /// withheld change, visible and no longer withheld, its embargo)`,
    /// sorted.
    fn withheld_violations(&mut self, before: &[View]) -> Result<Vec<(ObjectId, String)>> {
        // Nothing withheld before: nothing to lose (and the view it ends
        // with is not read: most transactions stop here).
        let mut before_merges = Vec::new();
        for v in before {
            before_merges.push(self.embargoed_merges_in(v)?);
        }
        if before_merges.iter().all(|m| m.is_empty()) {
            return Ok(Vec::new());
        }
        let after_view = self.view.clone();
        let after_merges = self.embargoed_merges_in(&after_view)?;
        if self.rewritten.is_empty() && before_merges.iter().all(|m| *m == after_merges) {
            return Ok(Vec::new());
        }
        let mut was = crate::remote::Withheld::default();
        // What each view the transaction started from withheld, and which
        // of its rewritten snapshots were withheld there: those replaced
        // (not abandoned), with their finals.
        let olds: Vec<ObjectId> = self.rewritten.keys().copied().collect();
        let mut replaced: Vec<(ObjectId, String)> = Vec::new();
        for v in before {
            let mut v = v.clone();
            std::mem::swap(&mut self.repo.view, &mut v);
            let res = (|repo: &Repo| -> Result<(crate::remote::Withheld, Vec<Option<String>>)> {
                let w = crate::remote::embargo_withheld(repo)?;
                let of = if w.is_empty() { vec![None; olds.len()] } else { w.blocking(repo, &olds)? };
                Ok((w, of))
            })(self.repo);
            std::mem::swap(&mut self.repo.view, &mut v);
            let (w, of) = res?;
            for (old, e) in olds.iter().zip(of) {
                if let Some(e) = e {
                    let (finals, abandoned) = self.resolve(*old);
                    if !abandoned {
                        replaced.extend(finals.into_iter().map(|f| (f, e.clone())));
                    }
                }
            }
            was.extend(w);
        }
        if was.is_empty() {
            return Ok(Vec::new());
        }
        replaced.sort();
        replaced.dedup();
        let replaced_embargoes: HashSet<String> = replaced.iter().map(|(_, e)| e.clone()).collect();
        // ...against what the view it ends with withholds: every version
        // of a withheld change visible now must still be withheld (all
        // that descends from one then is too), and so must every final of
        // a withheld snapshot the transaction replaced (BUG-1040: work that
        // was withheld only by descent, and now holds the fix).
        std::mem::swap(&mut self.repo.view, &mut self.view);
        type Lost = (Vec<(ObjectId, String)>, Vec<(ObjectId, String)>, HashSet<String>);
        let res = (|repo: &Repo| -> Result<Lost> {
            let now = crate::remote::embargo_withheld(repo)?;
            let refs = repo.view.refs();
            let mut lost = Vec::new();
            for e in was.embargoes() {
                let versions = was.versions_from(repo, &e, &refs)?;
                for (y, w) in versions.iter().zip(now.blocking(repo, &versions)?) {
                    if w.is_none() {
                        lost.push((*y, e.clone()));
                    }
                }
            }
            let finals: HashSet<ObjectId> = replaced.iter().map(|(f, _)| *f).collect();
            let visible = repo.exact().visible_among(&finals)?;
            let shown: Vec<(ObjectId, String)> = replaced.iter().filter(|(f, _)| visible.contains(f)).cloned().collect();
            let ids: Vec<ObjectId> = shown.iter().map(|(f, _)| *f).collect();
            let mut moved = Vec::new();
            for ((f, e), w) in shown.into_iter().zip(now.blocking(repo, &ids)?) {
                if w.is_none() {
                    moved.push((f, e));
                }
            }
            let mut carried = HashSet::new();
            for id in repo.exact().visible_embargoed()? {
                carried.extend(repo.snapshot(&id)?.embargo.clone());
            }
            Ok((lost, moved, carried))
        })(self.repo);
        std::mem::swap(&mut self.repo.view, &mut self.view);
        let (lost, moved, carried) = res?;
        let mut out = Vec::new();
        for (y, e) in lost {
            if self.repo.keys().embargo_released(&e) {
                continue;
            }
            // Withdrawn: nothing carries it, and nothing it withheld was
            // replaced (only dropped).
            if !carried.contains(&e) && !replaced_embargoes.contains(&e) {
                continue;
            }
            out.push((y, e));
        }
        // A replaced snapshot is never withdrawn: its finals stay withheld.
        out.extend(moved.into_iter().filter(|(_, e)| !self.repo.keys().embargo_released(e)));
        out.sort();
        out.dedup();
        Ok(out)
    }

    /// BUG-681: no rewrite moves a change confined to an unreleased embargo
    /// (its fix, work built on it, the embargoed line) out of it. A rebase,
    /// or an abandon whose descendants move, that puts such a change onto
    /// parents outside the embargo would publish the fix's file names (the
    /// moved change's edits of them, as conflicts) before the release.
    /// Only rewrites that change parents are judged: confinement follows
    /// the history.
    fn check_confinement(&mut self) -> Result<()> {
        let before = vec![self.repo.view.clone()];
        match self.confinement_violations(&before)?.into_iter().next() {
            None => Ok(()),
            Some((old, e)) => {
                let change = self.repo.snapshot(&old)?.change_id;
                Err(VeilError::Policy(format!(
                    "cannot move change {} off unreleased embargo {e}: it is part of the fix (or built on it, or on the embargoed line), and on parents outside the embargo it would publish the fix's file names before the release; keep it inside the embargo, or release the embargo first (`vl embargo release {e}`)",
                    change.short()
                )))
            }
        }
    }

    /// The rewritten snapshots, with their embargo, that some view of
    /// `before` had inside an unreleased embargo that is still active in
    /// this transaction's view, and that this transaction moves (onto
    /// other parents) out of it. Sorted.
    fn confinement_violations(&mut self, before: &[View]) -> Result<Vec<(ObjectId, String)>> {
        let mut moved: Vec<(ObjectId, Vec<ObjectId>)> = Vec::new();
        let mut olds: Vec<ObjectId> = self.rewritten.keys().copied().collect();
        olds.sort();
        for old in olds {
            if !matches!(self.rewritten.get(&old), Some(Rewrite::Replaced(_))) {
                continue;
            }
            let (finals, abandoned) = self.resolve(old);
            if abandoned {
                continue;
            }
            let Some(prev) = self.repo.exact().snapshot(&old)? else { continue };
            let mut changed = Vec::new();
            for f in finals {
                if f != old && self.repo.snapshot(&f)?.parents != prev.parents {
                    changed.push(f);
                }
            }
            if !changed.is_empty() {
                moved.push((old, changed));
            }
        }
        if moved.is_empty() {
            return Ok(Vec::new());
        }
        // Judged in each view the transaction started from...
        let mut was: Vec<(ObjectId, String, Vec<ObjectId>)> = Vec::new();
        for v in before {
            let mut v = v.clone();
            std::mem::swap(&mut self.repo.view, &mut v);
            let res = (|repo: &Repo| -> Result<Vec<(ObjectId, String, Vec<ObjectId>)>> {
                let mut confined = crate::confinement::Confinement::new(repo)?;
                let mut out = Vec::new();
                for (old, finals) in &moved {
                    if let Some(e) = confined.of(repo, old)? {
                        out.push((*old, e, finals.clone()));
                    }
                }
                Ok(out)
            })(self.repo);
            std::mem::swap(&mut self.repo.view, &mut v);
            for w in res? {
                if !was.iter().any(|(o, e, _)| *o == w.0 && *e == w.1) {
                    was.push(w);
                }
            }
        }
        if was.is_empty() {
            return Ok(Vec::new());
        }
        // ...and in the one it ends with.
        std::mem::swap(&mut self.repo.view, &mut self.view);
        let res = (|repo: &Repo| -> Result<Vec<(ObjectId, String)>> {
            let mut after = crate::confinement::Confinement::new(repo)?;
            // Abandoning the embargoed merge itself, with nothing built on
            // it (`check_withheld` refuses it otherwise), withdraws
            // the embargo, as undoing the merge does: nothing is moved out
            // of it.
            let active = crate::confinement::active_embargoes(repo)?;
            let mut out = Vec::new();
            for (old, e, finals) in &was {
                if !active.contains(e) {
                    continue;
                }
                for f in finals {
                    if after.of(repo, f)?.as_deref() != Some(e.as_str()) {
                        out.push((*old, e.clone()));
                        break;
                    }
                }
            }
            Ok(out)
        })(self.repo);
        std::mem::swap(&mut self.repo.view, &mut self.view);
        let mut out = res?;
        out.sort();
        out.dedup();
        Ok(out)
    }

    /// The merge's rebase, with every rewrite that would move a change out
    /// of an unreleased embargo dropped: the moved change goes back onto
    /// its old parents (the side's replacement is itself rewritten back),
    /// and a warning names it. Never fails for a policy reason (threat 18):
    /// each round drops at least one rewrite.
    fn merge_rebase(&mut self) -> Result<()> {
        let m = self.merge.as_ref().expect("a merge");
        let (before, base_view, mut union) = (m.before.clone(), m.view.clone(), m.rewritten.clone());
        let mut reversals: HashMap<ObjectId, Rewrite> = HashMap::new();
        let mut kept: BTreeSet<ObjectId> = BTreeSet::new();
        let mut dropped: Vec<(ObjectId, String)> = Vec::new();
        let rounds = union.len() * 2 + 4;
        let mut clean = false;
        for _ in 0..rounds {
            self.view = base_view.clone();
            self.rewritten = union.clone();
            self.merge.as_mut().expect("a merge").held.clear();
            for (k, v) in &reversals {
                self.rewritten.insert(*k, v.clone());
            }
            if !self.rewritten.is_empty() {
                self.rebase_descendants()?;
            }
            let mut bad = self.confinement_violations(&before)?;
            // A side's rewrite of an embargoed merge that stops withholding
            // what it withheld (BUG-942/943/990), such as a drop of the
            // merge another side built on: the rewrite goes, the merge stays.
            for (x, e) in self.withheld_violations(&before)? {
                let mut merges: Vec<ObjectId> = Vec::new();
                for old in union.keys() {
                    if self.repo.exact().snapshot(old)?.is_some_and(|s| s.embargo.as_deref() == Some(e.as_str())) {
                        merges.push(*old);
                    }
                }
                if merges.is_empty() {
                    // No rewrite of its merge to drop: the rewrite that
                    // made `x` (a final no longer withheld, BUG-1040), or
                    // that of what was withheld, or of what it followed.
                    let mut made: Vec<ObjectId> = Vec::new();
                    for (old, r) in &union {
                        if matches!(r, Rewrite::Replaced(_)) && self.resolve(*old).0.contains(&x) {
                            made.push(*old);
                        }
                    }
                    made.sort();
                    merges = if made.is_empty() { vec![x] } else { made };
                }
                for m in merges {
                    if !bad.iter().any(|(o, _)| *o == m) {
                        bad.push((m, e.clone()));
                    }
                }
            }
            if bad.is_empty() {
                clean = true;
                break;
            }
            let mut progress = false;
            for (old, e) in bad {
                if reversals.contains_key(&old) {
                    // Moving it back would move it out of an embargo too:
                    // leave the side's replacement where it is.
                    reversals.remove(&old);
                    kept.insert(old);
                    progress = true;
                    continue;
                }
                // The rewrite to drop: `old`'s own, or (a snapshot the
                // merge moved) that of the rewritten ancestor it followed.
                let culprits: Vec<ObjectId> = match union.contains_key(&old) {
                    true => vec![old],
                    false => self.rewritten_ancestors(&old, &union)?,
                };
                for c in culprits {
                    let Some(r) = union.remove(&c) else { continue };
                    progress = true;
                    dropped.push((c, e.clone()));
                    if let Rewrite::Replaced(n) = r {
                        // The side already shows the replacement (or what
                        // that was rewritten into in turn): rewrite each
                        // back, so their descendants return as well.
                        let mut chain = vec![n];
                        while let Some(Rewrite::Replaced(next)) = union.get(chain.last().expect("non-empty")) {
                            if chain.contains(next) || *next == c {
                                break;
                            }
                            chain.push(*next);
                        }
                        for x in chain {
                            if x != c && !kept.contains(&x) {
                                reversals.insert(x, Rewrite::Replaced(c));
                            }
                        }
                    }
                }
            }
            if !progress {
                break;
            }
        }
        if !clean {
            return Err(VeilError::repo(
                "cannot merge concurrent operations without moving a change out of an unreleased embargo (run `vl fsck`)",
            ));
        }
        dropped.sort();
        dropped.dedup();
        let mut warn = Vec::new();
        for (c, e) in dropped {
            let change = self.repo.snapshot(&c)?.change_id;
            warn.push(format!(
                "a concurrent rewrite of change {} was not applied: it would have moved it out of unreleased embargo {e}; the change stays inside the embargo",
                change.short()
            ));
        }
        let held = std::mem::take(&mut self.merge.as_mut().expect("a merge").held);
        for (id, why) in held {
            let change = self.repo.snapshot(&id)?.change_id;
            warn.push(format!(
                "change {} was left on its old parents: moving it onto a concurrent rewrite was refused ({why})",
                change.short()
            ));
        }
        self.merge.as_mut().expect("a merge").warnings.extend(warn);
        Ok(())
    }

    /// The rewritten snapshots (keys of `union`) among the ancestors of
    /// `id`, nearest first; the walk stops at each.
    fn rewritten_ancestors(&self, id: &ObjectId, union: &HashMap<ObjectId, Rewrite>) -> Result<Vec<ObjectId>> {
        // `id` is a snapshot the merge rebased: start from the original.
        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut stack = vec![*id];
        while let Some(x) = stack.pop() {
            if !seen.insert(x) || seen.len() > 100_000 {
                continue;
            }
            // A walk of the history: what is held only (BUG-1260).
            let Some(s) = self.repo.held().snapshot(&x)? else { continue };
            for p in &s.parents {
                if union.contains_key(p) {
                    if !out.contains(p) {
                        out.push(*p);
                    }
                } else {
                    stack.push(*p);
                }
            }
        }
        out.sort();
        Ok(out)
    }

    /// The warnings of a merge transaction (what its conflicts decided).
    pub(crate) fn take_merge_warnings(&mut self) -> Vec<String> {
        self.merge.as_mut().map(|m| std::mem::take(&mut m.warnings)).unwrap_or_default()
    }

    /// Every pre-existing object this transaction's new objects and view
    /// reference, freshened for gc (threat 14). An object that is gone
    /// fails the commit: the operation would reference nothing. With
    /// `all` false, only what the view gained and what the new objects
    /// name: everything else is the base view's, which gc's deletion
    /// fence keeps (BUG-811), but an id this command carried from an
    /// older view may be gone.
    fn freshen_references(&self, all: bool) -> Result<()> {
        let store = &self.repo.store;
        let staged: std::collections::HashSet<ObjectId> = store.tx_staged().into_iter().collect();
        let mut refs: Vec<ObjectId> = self.view.refs();
        refs.extend(self.view.annotations());
        if !all {
            let mut before: std::collections::HashSet<ObjectId> = self.start_view.refs().into_iter().collect();
            before.extend(self.start_view.annotations());
            refs.retain(|r| !before.contains(r));
        }
        for id in store.tx_staged_naming() {
            match store.get(&id)? {
                crate::object::Object::Snapshot(s) => {
                    refs.push(s.tree);
                    refs.extend(s.parents.iter().copied());
                }
                crate::object::Object::Tree(t) => {
                    for e in &t.entries {
                        refs.push(e.id);
                    }
                }
                crate::object::Object::Conflict(c) => refs.extend(c.referenced_ids()),
                crate::object::Object::Atag(a) => refs.push(a.target),
                _ => {}
            }
        }
        refs.sort();
        refs.dedup();
        for r in refs.into_iter().filter(|r| !staged.contains(r)) {
            if !store.has_fresh(&r) {
                return Err(VeilError::repo(format!(
                    "object {} this command uses was removed by `vl gc` while the command ran; run the command again",
                    r.short()
                )));
            }
        }
        Ok(())
    }

    /// The compare-and-swap of a lock-free commit: the repository was not
    /// upgraded, and no operation that landed since this transaction
    /// started moved a working copy it recorded.
    fn recheck(&self) -> Result<()> {
        let config = crate::repo::read_config(&*self.repo.backend)?;
        if config.format != self.repo.config.format {
            return Err(VeilError::repo(
                "the repository was upgraded while this command ran; run the command again",
            ));
        }
        // An operation whose parent is gone has no common operation with
        // the heads that landed meanwhile, and would be merged against an
        // empty view (deleted tags and workspaces coming back).
        for b in &self.base {
            if self.repo.ops.try_get(b)?.is_none() {
                return Err(VeilError::repo(format!(
                    "operation {} this command started from was pruned by `vl gc --keep-ops-days` while it ran; run the command again",
                    b.short()
                )));
            }
        }
        if self.expected.is_empty() {
            return Ok(());
        }
        let raw = self.repo.ops.raw_heads()?;
        if raw.all == self.stale.all {
            return Ok(());
        }
        // The view the current heads merge to (in memory): a head that did
        // not move the workspace itself (one built on an older base) does
        // not count as moving it.
        let heads = self.repo.ops.drop_ancestors(&raw.all)?;
        let view = match heads.as_slice() {
            [one] => self.repo.ops.get(one)?.view,
            _ => self.repo.merge_plan(&heads, false)?.view,
        };
        for (ws, wc) in &self.expected {
            if view.workspaces.get(ws).map(|w| w.wc) != Some(*wc) {
                return Err(VeilError::repo(format!("{SUPERSEDED} (workspace '{ws}')")));
            }
        }
        Ok(())
    }

    /// The operation this transaction records (its view and rewrites as
    /// they are now).
    fn operation(&self) -> Operation {
        let format6 = self.repo.format() >= crate::oplog::OP_HEADS_REPO_FORMAT;
        let mut parents = self.base.clone();
        parents.sort();
        let mut rewritten = BTreeMap::new();
        if format6 {
            for (old, r) in &self.rewritten {
                let new = match r {
                    Rewrite::Replaced(n) => vec![*n],
                    Rewrite::Abandoned(_) => Vec::new(),
                };
                rewritten.insert(*old, new);
            }
        }
        let (timestamp, user) = match &self.merge {
            Some(m) => (m.timestamp, "veil".to_string()),
            None => (now_millis(), self.repo.user.clone()),
        };
        Operation {
            parents,
            timestamp,
            user,
            description: self.description.clone(),
            view: self.view.clone(),
            manual_undo: self.manual_undo.clone(),
            undo_of: self.undo_of,
            redo_of: self.redo_of,
            workspace: self.workspace.clone().filter(|_| format6),
            rewritten,
        }
    }

    /// Finish the transaction. Returns the new operation id, or `None` if
    /// nothing changed.
    /// [`Transaction::commit`]'s fetch-ahead (one rule for moves): the
    /// tree the project directory will hold after this operation (its
    /// workspace's working copy, or that of the workspace it attaches the
    /// directory to), against what the directory holds now.
    fn fetch_ahead_move(&self) -> Result<()> {
        let Some(st) = crate::working_copy::CheckoutState::load(&*self.repo.backend)? else { return Ok(()) };
        let ws = self.attaches.as_deref().unwrap_or(st.attached());
        let Some(new) = self.view.workspaces.get(ws) else { return Ok(()) };
        if self.attaches.is_none() && self.repo.view.workspaces.get(ws).is_some_and(|w| w.wc == new.wc) {
            return Ok(());
        }
        let store = self.repo.store();
        let from = match store.snapshot(&st.snapshot) {
            Ok(s) => Some(s.tree),
            Err(VeilError::Missing(_)) => None,
            Err(e) => return Err(e),
        };
        let to = store.snapshot(&new.wc)?.tree;
        store.prefetch_diff(from.as_ref(), &to)
    }

    pub fn commit(mut self) -> Result<Option<ObjectId>> {
        if self.merge.is_some() {
            self.merge_rebase()?;
        } else {
            if !self.rewritten.is_empty() {
                self.rebase_descendants()?;
            }
            // The more specific refusal first (a change moved out of the
            // embargo), then the withholding rule, for any change of the
            // view, rewrites or not (`vl undo`, a tag moved).
            if !self.rewritten.is_empty() {
                self.check_confinement()?;
            }
            if self.view != self.repo.view {
                self.check_withheld()?;
            }
        }
        // A thin clone: an operation that moves the working copy of the
        // project directory fetches what the move reads before it is
        // published (BUG-1146). Keyed on what the operation does (any
        // command: new, merge, rebase, cherry-pick, undo, op restore), so a
        // full cache or a lost server fails it with nothing recorded,
        // instead of leaving a move every later command retries.
        if self.repo.store.is_partial() && (self.view != self.repo.view || self.attaches.is_some()) {
            self.fetch_ahead_move()?;
        }
        let record = self.view != self.start_view || self.record_always;
        // The operation (format 6), when one is recorded: its bytes and its
        // empty head file are staged with the objects, so that the objects'
        // barrier makes them durable too (`OpStore::publish_staged`).
        let mut staged = None;
        if self.staging {
            // A long transaction freshens everything it references (gc's
            // grace period); one that gc deleted objects under checks what
            // it brought in (an id from an older view).
            let long = now_millis() - self.started > FRESHEN_AFTER_MS;
            if long || self.check_carried {
                self.freshen_references(long)?;
            }
            if record {
                let op = self.operation();
                let (id, raw) = self.repo.ops.encode(&op)?;
                let op_file = self.repo.store.stage_tx_file(STAGED_OP, &raw)?;
                let head = self.repo.store.stage_tx_file(STAGED_HEAD, b"")?;
                staged = Some((id, op, op_file, head));
            }
            // Durability barrier, then publication: every object this
            // transaction wrote is on stable storage, under its final name,
            // before the operation that references it is named.
            self.done = true;
            self.kept_dir = match record {
                true => self.repo.store.publish_tx_staging_keeping_dir()?,
                false => {
                    self.repo.store.publish_tx_staging()?;
                    None
                }
            };
        } else {
            // Durability barrier: every object this transaction wrote is on
            // stable storage before the operation that references it.
            self.repo.store.sync_barrier()?;
        }
        if !record {
            return Ok(None);
        }
        let lock_free = self.lock.is_none() && self.merge.is_none();
        // A recording's compare-and-swap (`recheck`) and its publication are
        // one step for the threads of this process: otherwise two recorders
        // of one workspace both pass the check and both publish (BUG-806).
        // Other processes recording a workspace hold its `WcLock` for the
        // whole recording.
        static PUBLISH: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let publishing = (lock_free && !self.expected.is_empty()).then(|| PUBLISH.lock().unwrap_or_else(|e| e.into_inner()));
        if lock_free || self.repo.format() >= crate::oplog::OP_HEADS_REPO_FORMAT {
            self.recheck()?;
        } else {
            // A format-5 writer under the lock: an upgrade to format 6 since
            // it opened the repository makes `op_head` a stray head.
            let config = crate::repo::read_config(&*self.repo.backend)?;
            if config.format != self.repo.config.format {
                return Err(VeilError::repo(
                    "the repository was upgraded while this command ran; run the command again",
                ));
            }
        }
        if let Some(lock) = &self.lock {
            // Fencing: never move the head unless we still hold the lock.
            lock.ensure_held()?;
        }
        let id = match staged {
            Some((id, op, op_file, head)) => {
                self.repo.ops.publish_staged(&id, &op, &op_file, &head, &self.stale)?;
                id
            }
            None => {
                let op = self.operation();
                self.repo.ops.publish(&op, &self.stale)?
            }
        };
        if let Some(dir) = self.kept_dir.take() {
            self.repo.store.drop_tx_dir(&dir);
        }
        drop(publishing);
        self.repo.op_id = id;
        self.repo.base = vec![id];
        self.repo.raw = RawHeads {
            all: vec![id],
            legacy: None,
        };
        self.repo.view = std::mem::take(&mut self.view);
        self.repo.pin_working_copies();
        // Best effort: the index is a cache.
        self.repo.persist_index();
        let warnings = self.take_merge_warnings();
        self.repo.warnings.extend(warnings);
        // Concurrent operations are merged by the next open or
        // transaction, not here: every committer merging right after it
        // publishes races the others into a storm of merges (measured: 13×
        // slower with eight writers).
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
    /// Also on abort or error. Staged objects (format 6) are published
    /// anyway: something may already name them (a stat cache updated by a
    /// snapshot that was then superseded), as the unsynced objects of
    /// formats ≤ 5 stay. Only a failed barrier removes them.
    ///
    /// Formats ≤ 5: unsynced objects do not outlive the lock (released
    /// after this, when `lock` drops): only a holder that dies leaves any,
    /// and the next holder recovers them. A failed barrier (here or in
    /// `commit`) voids the objects it covered: the store removes them, so
    /// neither this process nor the next lock holder reuses a copy that
    /// may never reach the disk. If they cannot be removed, the lock is
    /// left behind flagged for recovery instead of being released, and the
    /// next holder (in any process) rewrites or removes them before doing
    /// anything else.
    fn drop(&mut self) {
        if self.staging {
            if !self.done {
                let _ = self.repo.store.publish_tx_staging();
            }
            // An operation staged but not published (superseded, or a
            // barrier failed): nothing names it.
            if let Some(dir) = self.kept_dir.take() {
                self.repo.store.drop_tx_dir(&dir);
            }
            self.reg.take();
            return;
        }
        self.repo.store.end_unsynced();
        let _ = self.repo.store.sync_barrier();
        if self.repo.store.take_needs_recovery() {
            if let Some(lock) = &mut self.lock {
                lock.abandon();
            }
        }
    }
}

/// What [`Transaction::move_to_view`] did (BUG-1509).
#[derive(Clone, Debug, Default)]
pub struct ViewMove {
    /// References to server snapshots (tags, workspaces, heads) re-pointed
    /// to their projections.
    pub mapped: usize,
    /// Changes only this clone holds, moved onto those.
    pub moved: usize,
    /// Changes that edited inside a folder the person can no longer see,
    /// each with the folder (`/`: the clone could not tell): kept where
    /// they are.
    pub kept: Vec<KeptChange>,
    /// Changes kept with them (connected to one: they cannot move alone).
    pub kept_with: usize,
    /// Per workspace whose working-copy change moved: the paths it lost,
    /// each with the folder's tree as the working copy's change had it.
    pub lost: BTreeMap<String, Vec<(VPath, Option<ObjectId>)>>,
}

#[derive(Clone, Debug)]
pub struct KeptChange {
    pub id: ObjectId,
    pub folder: VPath,
}

/// The paths tree `old` names and tree `new` (the same snapshot, projected
/// for a view that reads less) no longer does: the topmost of each, never
/// below (a folder the server refuses is not walked,
/// `tree::diff_trees_hiding`). `None` when `old`'s root is refused (the
/// clone cannot tell).
fn lost_paths(store: &crate::store::ObjectStore, old: &ObjectId, new: &ObjectId) -> Result<Option<Vec<VPath>>> {
    let (changes, hidden) = crate::tree::diff_trees_hiding(store, Some(old), Some(new))?;
    if hidden.iter().any(|h| h.path.is_root()) {
        return Ok(None);
    }
    let mut out: BTreeSet<VPath> = BTreeSet::new();
    let gone = changes.iter().filter(|c| c.new.is_none()).map(|c| &c.path).chain(hidden.iter().filter(|h| h.new.is_none()).map(|h| &h.path));
    for p in gone {
        // The topmost ancestor the new tree no longer names.
        let mut at = VPath::root();
        for c in p.components() {
            at = at.join(c);
            if crate::tree::lookup(store, new, &at)?.is_none() {
                break;
            }
        }
        out.insert(at);
    }
    Ok(Some(out.into_iter().collect()))
}
