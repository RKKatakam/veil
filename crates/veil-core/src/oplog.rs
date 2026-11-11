//! The operation log.
//!
//! Every mutation of the repository (snapshot, describe, rebase, tag move,
//! visibility toggle, push/pull, embargo release, …) is a transaction that
//! appends one immutable [`Operation`] holding the complete resulting
//! [`View`]. Undo is therefore trivial and total: restore an older view.
//!
//! **Heads.** Up to format 5 the log has one mutable pointer, `.veil/op_head`,
//! moved under the repository lock. From format 6
//! ([`OP_HEADS_REPO_FORMAT`]) it has a set of heads, `.veil/op_heads/<hex
//! id>` (empty files): a transaction publishes its operation with the heads
//! it started from as parents ([`OpStore::publish`]), without any lock, and
//! concurrent operations leave several heads, which the next writer merges
//! ([`merge_views`], `Repo::settle`). A stray `op_head` at format 6 (an older
//! writer racing the upgrade) is read as one more head. See
//! `docs/design/scale/2-lock-free-oplog.md`.

use std::{
    cmp::Reverse,
    collections::{BTreeMap, BTreeSet, BinaryHeap, HashMap},
    sync::{
        atomic::{AtomicU32, Ordering as AtomicOrdering},
        Arc,
    },
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
    /// Random, made when the workspace is created: another workspace made
    /// later under the same name (after `vl undo` of the first one's
    /// creation, or `vl op restore`) has another. Device-local state kept
    /// per workspace (its `ws exec` sandbox and layers) belongs to an id,
    /// not a name (BUG-1031, BUG-1033). Absent on workspaces made before it
    /// existed, and dropped by an older vl that rewrites the view (whose
    /// sandbox then starts afresh).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

impl WorkspaceState {
    /// A new workspace's state, with a fresh [`WorkspaceState::id`].
    pub fn new(wc: ObjectId) -> WorkspaceState {
        WorkspaceState { wc, id: Some(hex::encode(crate::crypto::random_bytes::<16>())) }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tag {
    pub target: ObjectId,
    /// The annotated tag object (`veil:atag`, repository format 5) that
    /// makes this a release tag. Its `name` and `target` must equal this
    /// entry's (`Atag::verify`). Absent on every other tag, and on every
    /// tag written before format 5.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotation: Option<ObjectId>,
}

impl Tag {
    /// A tag without annotation.
    pub fn new(target: ObjectId) -> Tag {
        Tag { target, annotation: None }
    }
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

    /// Every annotated tag object the view names (format 5): tag
    /// annotations. Not snapshots: gc keeps them and their targets, fsck
    /// checks them, sync sends them with their tag.
    pub fn annotations(&self) -> Vec<ObjectId> {
        let mut v: Vec<ObjectId> = self.tags.values().filter_map(|t| t.annotation).collect();
        v.sort();
        v.dedup();
        v
    }

    /// Does the view use a format-5 field (an annotation)? Only a format-5
    /// repository may record one.
    pub fn uses_format_5(&self) -> bool {
        self.tags.values().any(|t| t.annotation.is_some())
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
    /// Set on an operation recorded by `vl undo`: the operation it undid
    /// (its view is that operation's parent's). Repeated undos walk back
    /// past it instead of undoing it, and `vl redo` re-applies what it
    /// undid (see [`crate::Repo::undo_target`]). Absent elsewhere, and on
    /// undos written before it existed (those are plain operations).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub undo_of: Option<ObjectId>,
    /// Set on an operation recorded by `vl redo`: the undo operation it
    /// reverted (its view is that undo's `undo_of`'s).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redo_of: Option<ObjectId>,
    /// Format 6: the workspace the command was run for (the attached one
    /// for project-directory commands, `NAME` for `ws exec NAME`, `ws write
    /// NAME` and mounts). `None` for repository-wide commands (tags, push,
    /// pull, remotes) and for every operation written before format 6.
    /// `vl undo` in a workspace undoes only its own and repository-wide
    /// commands ([`crate::Repo::undo_target`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace: Option<String>,
    /// Format 6: the snapshots this operation rewrote, each with its
    /// replacement (empty: abandoned). A merge of concurrent operations
    /// applies one side's rewrites to the other side's new snapshots (a
    /// child committed on a snapshot that was amended meanwhile moves onto
    /// the amended one). Omitted when empty.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub rewritten: BTreeMap<ObjectId, Vec<ObjectId>>,
    /// Set on an operation recorded by `vl op restore`: the operation whose
    /// view it restored. It takes back every operation between that one
    /// and its parents, which a merge of concurrent operations reads from
    /// here, not from what the view shows (BUG-1434). Absent elsewhere, and
    /// on restores written before it existed (a merge then reads the
    /// restored operation's id from the description).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restore_of: Option<ObjectId>,
}

impl Operation {
    /// A merge of concurrent operations (written by `Repo::settle`).
    pub fn is_merge(&self) -> bool {
        self.parents.len() > 1
    }

    /// Does the operation use a format-6 field?
    pub fn uses_format_6(&self) -> bool {
        self.workspace.is_some() || !self.rewritten.is_empty()
    }
}

/// First repository format with the `op_heads/` layout and the format-6
/// operation fields ([`Operation::workspace`], [`Operation::rewritten`]).
pub const OP_HEADS_REPO_FORMAT: u32 = 6;

/// The directory of operation heads (format 6).
pub const OP_HEADS_DIR: &str = ".veil/op_heads";

/// The single head of formats 1 to 5.
pub const OP_HEAD_FILE: &str = ".veil/op_head";

/// How far below the oldest head an ancestry walk looks (clock steps
/// between operations of one device are tolerated up to this).
const ANCESTRY_SLACK_MS: i64 = 60 * 60 * 1000;

/// The heads of the log as stored: what [`OpStore::raw_heads`] lists.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RawHeads {
    /// Every head file (and a stray `op_head`), sorted.
    pub all: Vec<ObjectId>,
    /// What a stray `.veil/op_head` named at format 6, if anything.
    pub legacy: Option<ObjectId>,
}

#[derive(Debug)]
pub struct OpStore {
    backend: Arc<dyn StorageBackend>,
    /// Repository format: below format 5, an operation whose view uses a
    /// format-5 field ([`View::uses_format_5`]) is refused, so an older vl
    /// never reads a view it would rewrite without the field.
    format: AtomicU32,
}

impl OpStore {
    pub fn new(backend: Arc<dyn StorageBackend>) -> Self {
        OpStore {
            backend,
            format: AtomicU32::new(crate::repo::REPO_FORMAT),
        }
    }

    /// Set the repository format the store writes for (`Repo::open`).
    pub fn set_format(&self, format: u32) {
        self.format.store(format, AtomicOrdering::Relaxed);
    }

    fn op_path(id: &ObjectId) -> VPath {
        VPath::new(&format!(".veil/ops/{}", id.hex())).unwrap()
    }

    fn head_path() -> VPath {
        VPath::new(".veil/op_head").unwrap()
    }

    pub fn put(&self, op: &Operation) -> Result<ObjectId> {
        let (id, raw) = self.encode(op)?;
        self.backend.write(&Self::op_path(&id), &raw)?;
        Ok(id)
    }

    /// `op`'s id and stored bytes, if this repository's format can record
    /// it.
    pub(crate) fn encode(&self, op: &Operation) -> Result<(ObjectId, Vec<u8>)> {
        let format = self.format.load(AtomicOrdering::Relaxed);
        if format < crate::object::GIT_PARITY_REPO_FORMAT && op.view.uses_format_5() {
            return Err(VeilError::Unsupported(format!(
                "this repository is at format {format} and cannot record annotated or release tags; \
                 upgrade it with `vl upgrade` once everyone who uses it runs vl {} or later",
                crate::repo::min_vl_for_format(crate::object::GIT_PARITY_REPO_FORMAT)
            )));
        }
        if format < OP_HEADS_REPO_FORMAT && op.uses_format_6() {
            return Err(VeilError::Unsupported(format!(
                "this repository is at format {format} and cannot record an operation's workspace or rewrites; \
                 upgrade it with `vl upgrade` once everyone who uses it runs vl {} or later",
                crate::repo::min_vl_for_format(OP_HEADS_REPO_FORMAT)
            )));
        }
        let raw = serde_json::to_vec(op)?;
        Ok((ObjectId::hash(&raw), raw))
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
            Some(raw) => {
                if ObjectId::hash(&raw) != *id {
                    return Err(VeilError::Corrupt(
                        format!("operation {}", id.short()),
                        "content does not match its id".into(),
                    ));
                }
                Ok(Some(serde_json::from_slice(&raw)?))
            }
            None => Ok(None),
        }
    }

    pub(crate) fn uses_heads_dir(&self) -> bool {
        self.format.load(AtomicOrdering::Relaxed) >= OP_HEADS_REPO_FORMAT
    }

    fn head_file(id: &ObjectId) -> VPath {
        VPath::new(&format!("{OP_HEADS_DIR}/{}", id.hex())).unwrap()
    }

    /// The heads as stored, ancestors included. Format ≤ 5: `op_head`.
    /// Format 6: every regular file of `op_heads/` named by a 64-digit
    /// lowercase hex id (anything else there is ignored, and noted by
    /// `fsck`), plus a stray `op_head`.
    pub fn raw_heads(&self) -> Result<RawHeads> {
        let legacy = match self.backend.read_opt(&Self::head_path())? {
            Some(raw) => Some(ObjectId::from_hex(String::from_utf8_lossy(&raw).trim()).map_err(|_| {
                VeilError::Corrupt(OP_HEAD_FILE.into(), "does not contain an operation id (run `vl fsck`)".into())
            })?),
            None => None,
        };
        if !self.uses_heads_dir() {
            let head = legacy.ok_or_else(|| VeilError::NotFound(format!("{OP_HEAD_FILE} (run `vl fsck`)")))?;
            return Ok(RawHeads {
                all: vec![head],
                legacy: None,
            });
        }
        let mut all = Vec::new();
        match self.backend.list_dir(&VPath::new(OP_HEADS_DIR)?) {
            Ok(entries) => {
                for e in entries {
                    if e.kind != crate::vfs::NodeKind::File || e.name.len() != 64 {
                        continue;
                    }
                    if !e.name.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
                        continue;
                    }
                    all.push(ObjectId::from_hex(&e.name)?);
                }
            }
            Err(e) if e.is_not_found() => {}
            Err(e) => return Err(e),
        }
        all.extend(legacy);
        all.sort();
        all.dedup();
        if all.is_empty() {
            return Err(VeilError::Corrupt(
                OP_HEADS_DIR.into(),
                "the operation log has no head (run `vl fsck`)".into(),
            ));
        }
        Ok(RawHeads { all, legacy })
    }

    /// The current heads: [`OpStore::raw_heads`] less every head that is an
    /// ancestor of another (a crash between publishing an operation and
    /// removing its parents' head files leaves one). Sorted. A head whose
    /// operation is missing or unreadable is an error naming the file.
    pub fn heads(&self) -> Result<Vec<ObjectId>> {
        let raw = self.raw_heads()?;
        self.drop_ancestors(&raw.all)
    }

    /// `heads` less those that are an op-graph ancestor of another. The
    /// walk stops an hour below the oldest head and at pruned operations:
    /// an unknown ancestry counts as "not an ancestor" (a harmless merge).
    pub fn drop_ancestors(&self, heads: &[ObjectId]) -> Result<Vec<ObjectId>> {
        if heads.len() < 2 {
            // The caller reads it ([`OpStore::get_head`]).
            return Ok(heads.to_vec());
        }
        let mut ops = HashMap::new();
        for h in heads {
            ops.insert(*h, self.get_head(h)?);
        }
        let words = heads.len().div_ceil(64);
        let mut full = vec![u64::MAX; words];
        if !heads.len().is_multiple_of(64) {
            full[words - 1] = (1u64 << (heads.len() % 64)) - 1;
        }
        let bit = |i: usize| -> Vec<u64> {
            let mut v = vec![0u64; words];
            v[i / 64] |= 1 << (i % 64);
            v
        };
        let floor = heads.iter().map(|h| ops[h].timestamp).min().unwrap_or(0).saturating_sub(ANCESTRY_SLACK_MS);
        let mut marks: HashMap<ObjectId, Vec<u64>> = HashMap::new();
        let mut done: HashMap<ObjectId, Vec<u64>> = HashMap::new();
        let mut queue = BinaryHeap::new();
        for (i, h) in heads.iter().enumerate() {
            marks.insert(*h, bit(i));
            queue.push((ops[h].timestamp, *h));
        }
        // A head reached from another head's walk is an ancestor.
        let mut reached_from_other = vec![false; heads.len()];
        while let Some((ts, id)) = queue.pop() {
            let m = marks[&id].clone();
            if done.get(&id) == Some(&m) {
                continue;
            }
            done.insert(id, m.clone());
            if m == full || ts < floor {
                continue;
            }
            let Some(op) = self.cached(&mut ops, &id)? else { continue };
            for p in op.parents.clone() {
                let Some(pop) = self.cached(&mut ops, &p)? else { continue };
                let pm = marks.entry(p).or_insert_with(|| vec![0; words]);
                let before = pm.clone();
                for (w, x) in pm.iter_mut().zip(&m) {
                    *w |= x;
                }
                if *pm != before {
                    if let Some(i) = heads.iter().position(|h| *h == p) {
                        reached_from_other[i] = true;
                    }
                    queue.push((pop.timestamp, p));
                }
            }
        }
        Ok(heads.iter().zip(reached_from_other).filter(|(_, r)| !r).map(|(h, _)| *h).collect())
    }

    /// The operation of head `id`; missing, an error naming the head file.
    pub fn get_head(&self, id: &ObjectId) -> Result<Operation> {
        self.try_get(id)?.ok_or_else(|| {
            let file = match self.uses_heads_dir() {
                true => format!("{OP_HEADS_DIR}/{}", id.hex()),
                false => OP_HEAD_FILE.to_string(),
            };
            VeilError::NotFound(format!("operation {} named by {file} (run `vl fsck`)", id.short()))
        })
    }

    fn cached<'a>(&self, ops: &'a mut HashMap<ObjectId, Operation>, id: &ObjectId) -> Result<Option<&'a Operation>> {
        if !ops.contains_key(id) {
            match self.try_get(id)? {
                Some(op) => {
                    ops.insert(*id, op);
                }
                None => return Ok(None),
            }
        }
        Ok(ops.get(id))
    }

    /// The newest head (by timestamp, then id): the one `vl op log` starts
    /// from, and what watchers compare to notice a new operation.
    pub fn head(&self) -> Result<ObjectId> {
        let heads = self.heads()?;
        let mut best = None;
        for h in heads {
            let ts = self.get(&h)?.timestamp;
            if best.is_none_or(|(bt, bid)| (ts, h) > (bt, bid)) {
                best = Some((ts, h));
            }
        }
        best.map(|(_, h)| h).ok_or_else(|| VeilError::NotFound("operation head".into()))
    }

    /// Format ≤ 5: move the single head. Only under the repository lock.
    pub fn set_head(&self, id: &ObjectId) -> Result<()> {
        self.backend.write(&Self::head_path(), id.hex().as_bytes())
    }

    /// Write `op` and make it a head: durably write the operation, create
    /// its head file (`create_new`, durable), then remove the head files of
    /// its parents and of `stale` (heads read with the parents that were
    /// ancestors of them), and a stray `op_head` that named one of them. A
    /// crash between the steps leaves a head that is an ancestor of
    /// another, which readers drop. Format ≤ 5: `put` and `set_head`.
    pub fn publish(&self, op: &Operation, stale: &RawHeads) -> Result<ObjectId> {
        let id = self.put(op)?;
        if !self.uses_heads_dir() {
            self.set_head(&id)?;
            return Ok(id);
        }
        self.backend.create_new(&Self::head_file(&id), b"")?;
        self.retire(&id, op, stale)?;
        Ok(id)
    }

    /// [`OpStore::publish`] of operation `id` (`op`, format 6), whose bytes
    /// and empty head file a transaction staged (`staged_op`, `staged_head`)
    /// and made durable with its objects, all now durable under their own
    /// names. Two barriers, each after one name: the operation's, then the
    /// head's. A crash leaves no head, or a head whose operation and
    /// objects are all durable.
    pub(crate) fn publish_staged(&self, id: &ObjectId, op: &Operation, staged_op: &VPath, staged_head: &VPath, stale: &RawHeads) -> Result<()> {
        debug_assert!(self.uses_heads_dir());
        self.backend.publish_unsynced(staged_op, &Self::op_path(id))?;
        self.backend.sync_barrier()?;
        self.backend.publish_unsynced(staged_head, &Self::head_file(id))?;
        self.backend.sync_barrier()?;
        self.retire(id, op, stale)
    }

    /// Remove the head files `id` replaces: its parents and the stale heads
    /// read with them (a crash before leaves ancestors among the heads,
    /// which readers drop).
    fn retire(&self, id: &ObjectId, op: &Operation, stale: &RawHeads) -> Result<()> {
        let id = *id;
        let mut gone: Vec<ObjectId> = op.parents.clone();
        gone.extend(stale.all.iter().copied());
        gone.sort();
        gone.dedup();
        for p in &gone {
            if *p != id {
                self.backend.remove_file(&Self::head_file(p))?;
            }
        }
        if let Some(l) = stale.legacy.filter(|l| gone.contains(l)) {
            // Only if it still names what was merged: an older writer may
            // have moved it again since.
            if self.raw_legacy()? == Some(l) {
                self.backend.remove_file(&Self::head_path())?;
            }
        }
        Ok(())
    }

    fn raw_legacy(&self) -> Result<Option<ObjectId>> {
        Ok(match self.backend.read_opt(&Self::head_path())? {
            Some(raw) => ObjectId::from_hex(String::from_utf8_lossy(&raw).trim()).ok(),
            None => None,
        })
    }

    /// Operations from `starts` and their ancestors, newest first (by
    /// time, then id), each once, and on a log written since operation
    /// times were clamped (none older than its parent) never before a
    /// descendant: on equal times the op log's ancestry orders them,
    /// reading only the operations of that time below the candidates
    /// (BUG-1402, BUG-1433). On an older log, a parent newer than its
    /// child is listed after it, but an operation can still come before an
    /// older descendant that only a branch not walked yet reaches
    /// (BUG-1432). Pruned operations end their branch ([`OpWalk::pruned`]).
    pub fn walk(&self, starts: &[ObjectId]) -> OpWalk<'_> {
        let mut w = OpWalk {
            ops: self,
            queue: BinaryHeap::new(),
            key: HashMap::new(),
            loaded: HashMap::new(),
            done: Default::default(),
            ready: Default::default(),
            pruned: None,
            error: None,
        };
        for s in starts {
            w.push(*s, None);
        }
        w
    }

    /// Split the history of `a` and `b` (each a set of operations): the
    /// operations only `a` reaches, those only `b` reaches (newest first),
    /// and their nearest common operation (the newest one both reach;
    /// `None` if there is none, or it was pruned). The walk is exact (no
    /// time floor): a side whose history spans more than an hour still
    /// finds the operation it forked from, and lists every operation since
    /// (their rewrites are applied by the merge).
    pub fn split(&self, a: &[ObjectId], b: &[ObjectId]) -> Result<Split> {
        let mut ops: HashMap<ObjectId, Operation> = HashMap::new();
        let mut marks: HashMap<ObjectId, u8> = HashMap::new();
        let mut done: HashMap<ObjectId, (u8, bool)> = HashMap::new();
        let mut queue = BinaryHeap::new();
        for (set, m) in [(a, 1u8), (b, 2u8)] {
            for id in set {
                let Some(op) = self.cached(&mut ops, id)? else { continue };
                queue.push((op.timestamp, *id));
                *marks.entry(*id).or_default() |= m;
            }
        }
        // Ancestors of a common operation (never the nearest one).
        let mut stale: std::collections::HashSet<ObjectId> = Default::default();
        // The oldest timestamp of an operation walked while one side alone
        // reached it.
        let mut low: Option<i64> = None;
        // A parent newer than its child (written before operation times
        // were clamped, with the clock set back): times no longer bound
        // what is still a descendant, so the walk never ends early (BUG-1401).
        let mut inverted = false;
        while let Some((ts, id)) = queue.pop() {
            let (m, st) = (marks[&id], stale.contains(&id));
            if done.get(&id) == Some(&(m, st)) {
                continue;
            }
            done.insert(id, (m, st));
            if m != 3 {
                low = Some(low.map_or(ts, |l| l.min(ts)));
            }
            // Common operations are walked too (the classic merge-base walk): a
            // timestamp out of order (a merge has its newest parent's) may
            // have sent one side below them first. The walk ends once
            // everything still queued is common and older than every
            // operation walked as one side's: a common operation of the same
            // timestamp may still be its descendant (a merge and the parent
            // whose timestamp it has, the parent's id sorting first), which
            // makes it common too (BUG-1297).
            let parents = match self.cached(&mut ops, &id)? {
                Some(op) => op.parents.clone(),
                None => Vec::new(),
            };
            let mut known = Vec::new();
            for p in parents {
                let Some(pts) = self.cached(&mut ops, &p)?.map(|o| o.timestamp) else { continue };
                inverted |= pts > ts;
                known.push((p, pts));
            }
            let below = |t: i64| low.is_none_or(|l| t < l);
            if !inverted && m == 3 && below(ts) && queue.iter().all(|(t, q)| marks[q] == 3 && below(*t)) {
                break;
            }
            for (p, pts) in known {
                let newly_stale = m == 3 && stale.insert(p);
                let pm = marks.entry(p).or_default();
                if *pm | m != *pm || newly_stale {
                    *pm |= m;
                    queue.push((pts, p));
                }
            }
        }
        let mut out = Split::default();
        let mut base: Option<(i64, ObjectId)> = None;
        let mut order: Vec<(i64, ObjectId)> = marks.keys().filter_map(|id| ops.get(id).map(|o| (o.timestamp, *id))).collect();
        order.sort_by_key(|k| Reverse(*k));
        for (ts, id) in order {
            match marks[&id] {
                1 => out.only_a.push(id),
                2 => out.only_b.push(id),
                _ if stale.contains(&id) => {}
                _ => {
                    if base.is_none_or(|b| (ts, id) > b) {
                        base = Some((ts, id));
                    }
                }
            }
        }
        out.base = base.map(|(_, id)| id);
        out.ops = ops;
        Ok(out)
    }

    /// Resolve an operation id prefix among the operations the heads reach.
    pub fn resolve_prefix(&self, prefix: &str) -> Result<ObjectId> {
        self.resolve_prefix_from(&self.heads()?, prefix)
    }

    /// Resolve an operation id prefix among the operations `starts` reach.
    pub fn resolve_prefix_from(&self, starts: &[ObjectId], prefix: &str) -> Result<ObjectId> {
        let mut found = Vec::new();
        for (steps, id) in self.walk(starts).enumerate() {
            let id = id?.0;
            if id.hex().starts_with(prefix) {
                found.push(id);
            }
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

/// See [`OpStore::split`].
#[derive(Clone, Debug, Default)]
pub struct Split {
    pub only_a: Vec<ObjectId>,
    pub only_b: Vec<ObjectId>,
    pub base: Option<ObjectId>,
    /// The operations the walk read (every one of `only_a` and `only_b`,
    /// and their parents, but pruned ones).
    pub(crate) ops: HashMap<ObjectId, Operation>,
}

impl Split {
    /// For each operation of `within` (`only_a` or `only_b`), the operations
    /// of `within` it descends from.
    pub(crate) fn ancestors_within(&self, within: &[ObjectId]) -> HashMap<ObjectId, std::collections::HashSet<ObjectId>> {
        let set: std::collections::HashSet<&ObjectId> = within.iter().collect();
        let parents = |id: &ObjectId| -> Vec<ObjectId> { self.ops.get(id).map(|o| o.parents.iter().filter(|p| set.contains(p)).copied().collect()).unwrap_or_default() };
        let mut out: HashMap<ObjectId, std::collections::HashSet<ObjectId>> = HashMap::new();
        for start in within {
            // Depth first: an operation is done once its parents are (times
            // do not order them).
            let mut stack = vec![(*start, false)];
            while let Some((id, expanded)) = stack.pop() {
                if out.contains_key(&id) {
                    continue;
                }
                let ps = parents(&id);
                if !expanded {
                    stack.push((id, true));
                    stack.extend(ps.iter().filter(|p| !out.contains_key(*p)).map(|p| (*p, false)));
                    continue;
                }
                let mut mine = std::collections::HashSet::new();
                for p in ps {
                    mine.insert(p);
                    mine.extend(out.get(&p).into_iter().flatten().copied());
                }
                out.insert(id, mine);
            }
        }
        out
    }

    /// What the operations of `ids` (`only_a` or `only_b`) introduced:
    /// see [`Introduced`].
    pub(crate) fn introduced(&self, ids: &[ObjectId]) -> Introduced {
        let mut out = Introduced::default();
        for id in ids {
            if let Some(op) = self.ops.get(id) {
                let parents: Vec<&View> = op.parents.iter().filter_map(|p| self.ops.get(p)).map(|o| &o.view).collect();
                out.add(&op.view, &parents);
            }
        }
        out
    }
}

/// A tag's target and annotation, merged as one unit.
type TagUnit = (ObjectId, Option<ObjectId>);

/// The values some operations introduced: a key's value in an operation's
/// view that none of its parents' views has (a new snapshot of a
/// workspace, a tag set or removed, a head added or dropped). A merge of
/// concurrent operations introduces only what it rewrote, and what it
/// takes from one of its parents is that parent's.
#[derive(Clone, Debug, Default)]
pub struct Introduced {
    workspaces: std::collections::HashSet<(String, Option<ObjectId>)>,
    tags: std::collections::HashSet<(String, Option<TagUnit>)>,
    remote_tags: std::collections::HashSet<(String, Option<ObjectId>)>,
    heads: std::collections::HashSet<(ObjectId, bool)>,
}

impl Introduced {
    /// Record what `view` introduces over `parents` (an operation without
    /// known parents introduces all of it).
    pub fn add(&mut self, view: &View, parents: &[&View]) {
        let unit = |t: &Tag| (t.target, t.annotation);
        let names: BTreeSet<&String> = view.workspaces.keys().chain(parents.iter().flat_map(|p| p.workspaces.keys())).collect();
        for n in names {
            let v = view.workspaces.get(n).map(|w| w.wc);
            if parents.iter().all(|p| p.workspaces.get(n).map(|w| w.wc) != v) {
                self.workspaces.insert((n.clone(), v));
            }
        }
        let names: BTreeSet<&String> = view.tags.keys().chain(parents.iter().flat_map(|p| p.tags.keys())).collect();
        for n in names {
            let v = view.tags.get(n).map(unit);
            if parents.iter().all(|p| p.tags.get(n).map(unit) != v) {
                self.tags.insert((n.clone(), v));
            }
        }
        let names: BTreeSet<&String> = view.remote_tags.keys().chain(parents.iter().flat_map(|p| p.remote_tags.keys())).collect();
        for n in names {
            let v = view.remote_tags.get(n).copied();
            if parents.iter().all(|p| p.remote_tags.get(n).copied() != v) {
                self.remote_tags.insert((n.clone(), v));
            }
        }
        let heads: BTreeSet<&ObjectId> = view.heads.iter().chain(parents.iter().flat_map(|p| p.heads.iter())).collect();
        for h in heads {
            let v = view.heads.contains(h);
            if parents.iter().all(|p| p.heads.contains(h) != v) {
                self.heads.insert((*h, v));
            }
        }
    }
}

/// The base [`merge_views`] compares `a` and `b` with, for two sides whose
/// histories share more than their nearest common operation `base` holds
/// (a criss-cross: two settlers merged some of the same operations, each
/// with others, BUG-1294). Per key: when one side's value was introduced
/// by an operation only it reaches (`ia`, `ib`) and the other's was not,
/// the other's is the shared history's, so it is the base and the change
/// wins. When both sides introduced theirs, both changed the key: the
/// base is absent (equal to neither, nor to a value a side wrote back,
/// BUG-1296), so the conflict rules decide between two changes (a change
/// beats a removal; two moves keep the loser visible and warn). When
/// neither did and they still differ, the key is `base`'s. Without it, a
/// value `base` lacks but both sides' shared history holds looks changed
/// on both sides, and the conflict rule could keep the side with the
/// older value: a commit's working copy lost.
pub fn shared_base(base: &View, a: &View, ia: &Introduced, b: &View, ib: &Introduced) -> View {
    fn key<T: Clone + PartialEq + Eq + std::hash::Hash, V: Clone>(
        name: &str,
        va: Option<&V>,
        vb: Option<&V>,
        vbase: Option<&V>,
        unit: impl Fn(&V) -> T,
        ia: &std::collections::HashSet<(String, Option<T>)>,
        ib: &std::collections::HashSet<(String, Option<T>)>,
    ) -> Option<V> {
        let (ua, ub) = (va.map(&unit), vb.map(&unit));
        if ua == ub {
            return vbase.cloned();
        }
        match (ia.contains(&(name.to_string(), ua)), ib.contains(&(name.to_string(), ub))) {
            (false, true) => va.cloned(),
            (true, false) => vb.cloned(),
            (true, true) => None,
            (false, false) => vbase.cloned(),
        }
    }
    let mut out = View::default();
    let names: BTreeSet<&String> = base.workspaces.keys().chain(a.workspaces.keys()).chain(b.workspaces.keys()).collect();
    for n in names {
        let v = key(n, a.workspaces.get(n), b.workspaces.get(n), base.workspaces.get(n), |w| w.wc, &ia.workspaces, &ib.workspaces);
        if let Some(v) = v {
            out.workspaces.insert(n.clone(), v);
        }
    }
    let names: BTreeSet<&String> = base.tags.keys().chain(a.tags.keys()).chain(b.tags.keys()).collect();
    for n in names {
        let v = key(n, a.tags.get(n), b.tags.get(n), base.tags.get(n), |t| (t.target, t.annotation), &ia.tags, &ib.tags);
        if let Some(v) = v {
            out.tags.insert(n.clone(), v);
        }
    }
    let names: BTreeSet<&String> = base.remote_tags.keys().chain(a.remote_tags.keys()).chain(b.remote_tags.keys()).collect();
    for n in names {
        let v = key(n, a.remote_tags.get(n), b.remote_tags.get(n), base.remote_tags.get(n), |t| *t, &ia.remote_tags, &ib.remote_tags);
        if let Some(v) = v {
            out.remote_tags.insert(n.clone(), v);
        }
    }
    let heads: BTreeSet<&ObjectId> = base.heads.iter().chain(a.heads.iter()).chain(b.heads.iter()).collect();
    for h in heads {
        let (pa, pb) = (a.heads.contains(h), b.heads.contains(h));
        let keep = match (pa == pb, ia.heads.contains(&(*h, pa)), ib.heads.contains(&(*h, pb))) {
            (false, false, true) => pa,
            (false, true, false) => pb,
            // Added on one side, dropped on the other: the addition wins.
            (false, true, true) => false,
            _ => base.heads.contains(h),
        };
        if keep {
            out.heads.insert(*h);
        }
    }
    out
}

/// See [`OpStore::walk`].
pub struct OpWalk<'a> {
    ops: &'a OpStore,
    /// `(key, id)`: an operation's key is its time, or a child's key if
    /// that is lower (a parent newer than its child, written before times
    /// were clamped). Entries whose key was lowered since are stale.
    queue: BinaryHeap<(i64, ObjectId)>,
    key: HashMap<ObjectId, i64>,
    loaded: HashMap<ObjectId, Operation>,
    /// Emitted, or in `ready`.
    done: std::collections::HashSet<ObjectId>,
    /// The current group of one key, children first.
    ready: std::collections::VecDeque<(ObjectId, i64)>,
    pruned: Option<ObjectId>,
    error: Option<VeilError>,
}

impl OpWalk<'_> {
    /// The newest pruned operation the walk met (where a branch ended).
    pub fn pruned(&self) -> Option<ObjectId> {
        self.pruned
    }

    /// Load `id`; `false` if it is pruned (or failed to read).
    fn load(&mut self, id: ObjectId) -> bool {
        if self.loaded.contains_key(&id) {
            return true;
        }
        match self.ops.try_get(&id) {
            Ok(Some(op)) => {
                self.loaded.insert(id, op);
                true
            }
            Ok(None) => {
                self.pruned = Some(id);
                false
            }
            Err(e) => {
                self.error = self.error.take().or(Some(e));
                false
            }
        }
    }

    /// Queue `id`, a start (`below` none) or a parent of an operation of
    /// key `below`. A parent newer than the key is queued at once, with
    /// that key, and so on down: it must come after the operation, and so
    /// must its ancestors, though another path may reach them sooner.
    fn push(&mut self, id: ObjectId, below: Option<i64>) {
        let mut work = vec![(id, below)];
        while let Some((id, below)) = work.pop() {
            if self.done.contains(&id) || !self.load(id) {
                continue;
            }
            let ts = self.loaded[&id].timestamp;
            let k = below.map_or(ts, |b| b.min(ts));
            if self.key.get(&id).is_some_and(|old| *old <= k) {
                continue;
            }
            self.key.insert(id, k);
            self.queue.push((k, id));
            for p in self.loaded[&id].parents.clone() {
                if self.done.contains(&p) || !self.load(p) {
                    continue;
                }
                if self.loaded[&p].timestamp > k {
                    work.push((p, Some(k)));
                }
            }
        }
    }

    /// The next operation to list: of the newest key, one no other queued
    /// operation of that key descends from (BUG-1402: times tie; a merge
    /// has its newest parent's, and a clock set back gives every operation
    /// its parent's). With one such operation queued, as on a line of
    /// operations of one time, that is it, read nothing more (BUG-1433);
    /// with several, only the operations of that key below them are read.
    fn fill(&mut self) {
        let mut cands: Vec<ObjectId> = Vec::new();
        let mut t = None;
        while let Some(&(k, id)) = self.queue.peek() {
            if t.is_some_and(|t| k != t) {
                break;
            }
            self.queue.pop();
            if self.done.contains(&id) || self.key.get(&id) != Some(&k) || cands.contains(&id) {
                continue;
            }
            t = Some(k);
            cands.push(id);
        }
        let Some(t) = t else { return };
        let pick = match cands.as_slice() {
            [one] => *one,
            _ => {
                // Those another candidate reaches through operations of this
                // key (an operation below one, of its time or newer, is listed
                // with its key).
                let mut reached: std::collections::HashSet<ObjectId> = Default::default();
                for c in &cands {
                    let mut stack: Vec<ObjectId> = self.loaded.get(c).map(|o| o.parents.clone()).unwrap_or_default();
                    let mut seen: std::collections::HashSet<ObjectId> = Default::default();
                    while let Some(x) = stack.pop() {
                        if !seen.insert(x) || self.done.contains(&x) || !self.load(x) {
                            continue;
                        }
                        if self.loaded[&x].timestamp < t {
                            continue;
                        }
                        reached.insert(x);
                        stack.extend(self.loaded[&x].parents.iter().copied());
                    }
                }
                let free = cands.iter().filter(|c| !reached.contains(*c)).max().copied();
                // A cycle cannot happen in the op log; should the data say
                // otherwise, the highest id goes first rather than none.
                free.unwrap_or_else(|| *cands.iter().max().expect("a candidate"))
            }
        };
        for c in cands {
            if c != pick {
                self.queue.push((t, c));
            }
        }
        self.done.insert(pick);
        self.key.remove(&pick);
        self.ready.push_back((pick, t));
    }
}

impl Iterator for OpWalk<'_> {
    type Item = Result<(ObjectId, Operation)>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.ready.is_empty() {
            self.fill();
        }
        if let Some(e) = self.error.take() {
            return Some(Err(e));
        }
        let (id, t) = self.ready.pop_front()?;
        let op = self.loaded.remove(&id)?;
        for p in &op.parents {
            self.push(*p, Some(t));
        }
        Some(Ok((id, op)))
    }
}

// ---- merging concurrent views --------------------------------------------------

/// The result of [`merge_views`].
#[derive(Clone, Debug, Default)]
pub struct MergedView {
    pub view: View,
    /// What a conflict decided, for the user (names workspaces and public
    /// tags; a cloaked tag is "a cloaked tag").
    pub warnings: Vec<String>,
    /// The losing values of those conflicts (heads of `view`).
    pub losers: Vec<ObjectId>,
}

/// A deterministic 3-way merge of `sides` against `base`. A key changed on
/// one side only takes that side's value; changed on several sides to
/// different values, the **first** of them wins (the caller orders the
/// sides: by operation id for concurrent operations, the reverting side
/// first for an undo), and the losing side's snapshot stays visible as a
/// head, with a warning.
///
/// * `heads`: kept if every side kept it, or some side added it.
/// * A workspace's `wc` and `cloak` merge separately, as do a tag's
///   `(target, annotation)` and its `cloak`; a cloak conflict keeps a
///   cloaked side, so a concurrent move never widens an audience. A release
///   tag's target and annotation are one unit (never torn apart). For two
///   moves of an ordinary tag, a target that descends from the other wins
///   (`descends(a, b)`: is `a` a descendant of `b`).
/// * A key removed on one side and changed on another keeps the change.
/// * `remote_tags`: per key, as above.
pub fn merge_views(base: &View, sides: &[&View], descends: &mut dyn FnMut(&ObjectId, &ObjectId) -> bool) -> MergedView {
    merge_views_with(base, sides, false, descends)
}

/// [`merge_views`] where the first side wins every conflict, a removal
/// included: an undo (a 3-way revert, the reverting side first) of a
/// command that created a workspace or tag removes it again.
pub fn revert_views(base: &View, revert: &View, current: &View, descends: &mut dyn FnMut(&ObjectId, &ObjectId) -> bool) -> MergedView {
    merge_views_with(base, &[revert, current], true, descends)
}

fn merge_views_with(base: &View, sides: &[&View], first_wins: bool, descends: &mut dyn FnMut(&ObjectId, &ObjectId) -> bool) -> MergedView {
    let mut out = MergedView::default();
    let mut losers: Vec<ObjectId> = Vec::new();
    // Heads.
    let mut all: BTreeSet<ObjectId> = base.heads.clone();
    for s in sides {
        all.extend(s.heads.iter().copied());
    }
    for h in all {
        let keep = match base.heads.contains(&h) {
            true => sides.iter().all(|s| s.heads.contains(&h)),
            false => sides.iter().any(|s| s.heads.contains(&h)),
        };
        if keep {
            out.view.heads.insert(h);
        }
    }
    // Workspaces.
    let names: BTreeSet<&String> = base.workspaces.keys().chain(sides.iter().flat_map(|s| s.workspaces.keys())).collect();
    for name in names {
        let b = base.workspaces.get(name);
        let vals: Vec<Option<&WorkspaceState>> = sides.iter().map(|s| s.workspaces.get(name)).collect();
        let Some((wc, lost)) = pick(b.map(|w| w.wc), vals.iter().map(|v| v.map(|w| w.wc)).collect(), first_wins) else { continue };
        // The identity goes with the working copy that won.
        let id = vals.iter().flatten().chain(b.iter()).find(|w| w.wc == wc).and_then(|w| w.id.clone());
        if !lost.is_empty() {
            out.warnings.push(format!(
                "workspace '{name}' was moved by concurrent commands; kept {}, and the other working cop{} as visible change{}",
                wc.short(),
                if lost.len() == 1 { "y stays" } else { "ies stay" },
                if lost.len() == 1 { "" } else { "s" }
            ));
            losers.extend(lost);
        }
        out.view.workspaces.insert(name.clone(), WorkspaceState { wc, id });
    }
    // Tags.
    let names: BTreeSet<&String> = base.tags.keys().chain(sides.iter().flat_map(|s| s.tags.keys())).collect();
    for name in names {
        let b = base.tags.get(name);
        let vals: Vec<Option<&Tag>> = sides.iter().map(|s| s.tags.get(name)).collect();
        let unit = |t: &Tag| (t.target, t.annotation);
        let Some((mut winner, lost)) = pick(b.map(unit), vals.iter().map(|v| v.map(unit)).collect(), first_wins) else { continue };
        // A release tag (annotated) is immutable: it wins over an ordinary
        // tag made concurrently under its name, and the first of two wins.
        if winner.1.is_none() {
            if let Some(a) = lost.iter().find(|u| u.1.is_some()) {
                winner = *a;
            }
        }
        // Two moves of an ordinary tag: a target descending from the
        // other wins.
        if winner.1.is_none() {
            for u in &lost {
                if u.1.is_none() && descends(&u.0, &winner.0) {
                    winner = *u;
                }
            }
        }
        let mut lost: Vec<ObjectId> = lost.iter().map(|u| u.0).collect();
        if let Some(first) = vals.iter().flatten().map(|t| t.target).find(|t| *t != winner.0 && !lost.contains(t) && b.map(|b| b.target) != Some(*t)) {
            lost.push(first);
        }
        lost.retain(|t| *t != winner.0);
        if !lost.is_empty() {
            out.warnings.push(format!(
                "tag '{name}' was moved by concurrent commands; kept {}, and the other target stays a visible change",
                winner.0.short()
            ));
            losers.extend(lost);
        }
        out.view.tags.insert(
            name.clone(),
            Tag { target: winner.0, annotation: winner.1 },
        );
    }
    // Remote tags.
    let names: BTreeSet<&String> = base.remote_tags.keys().chain(sides.iter().flat_map(|s| s.remote_tags.keys())).collect();
    for name in names {
        let b = base.remote_tags.get(name).copied();
        if let Some((t, _)) = pick(b, sides.iter().map(|s| s.remote_tags.get(name).copied()).collect(), first_wins) {
            out.view.remote_tags.insert(name.clone(), t);
        }
    }
    for l in &losers {
        out.view.heads.insert(*l);
    }
    out.losers = losers;
    out
}

/// 3-way value of a key: the value of the first side that changed it (a
/// removal loses to a change), with the other sides' changed values; `None`
/// when the key is gone.
fn pick<T: Copy + PartialEq>(base: Option<T>, sides: Vec<Option<T>>, first_wins: bool) -> Option<(T, Vec<T>)> {
    let changed: Vec<Option<T>> = sides.iter().filter(|s| **s != base).copied().collect();
    if changed.is_empty() {
        return base.map(|b| (b, Vec::new()));
    }
    if first_wins && changed[0].is_none() {
        return None;
    }
    let values: Vec<T> = changed.iter().flatten().copied().collect();
    let first = values.first().copied()?;
    let mut lost = Vec::new();
    for v in &values[1..] {
        if *v != first && !lost.contains(v) {
            lost.push(*v);
        }
    }
    Some((first, lost))
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
