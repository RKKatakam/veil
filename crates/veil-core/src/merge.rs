//! Three-way tree merge. Works at the tree level (identical subtrees are
//! resolved by id without reading content) and falls back to line-based
//! diff3 for files changed on both sides.
//!
//! Visibility never widens: a file merged from a sealed side stays sealed
//! (ours' sealing if ours is sealed, else theirs'), whichever side "ours"
//! happens to be. This matters for auto-rebase, where "ours" is the new
//! (possibly public) parent and "theirs" the (possibly cloaked) child.
//!
//! Trees under an unreleased embargo (see [`crate::embargo`]) stay under it:
//! the result is re-wrapped under the same embargo, with the merge of the
//! inputs' public views as its fallback. Merging them needs the embargo key,
//! and trees under two different unreleased embargoes are never merged
//! (embargoes cannot overlap in Veil 1.0).

use std::{collections::BTreeSet, sync::Arc};

use crate::{
    embargo::{overlap_error, public_view, unreleased_wrapper, wrap},
    error::{Result, VeilError},
    id::ObjectId,
    object::{EntryKind, Tree, TreeEntry, Visibility},
    secrets::looks_binary,
    store::ObjectStore,
    tree::MAX_TREE_DEPTH,
    vpath::VPath,
};

#[derive(Debug, Clone)]
pub struct MergeOutcome {
    pub tree: ObjectId,
    pub conflicts: Vec<VPath>,
}

pub fn merge_trees(store: &ObjectStore, base: Option<ObjectId>, ours: ObjectId, theirs: ObjectId) -> Result<MergeOutcome> {
    if ours == theirs || Some(theirs) == base {
        return Ok(MergeOutcome { tree: ours, conflicts: vec![] });
    }
    if Some(ours) == base {
        return Ok(MergeOutcome { tree: theirs, conflicts: vec![] });
    }
    let mut wrapped: Option<crate::embargo::EmbargoWrapper> = None;
    for id in [Some(ours), Some(theirs), base].into_iter().flatten() {
        if let Some(w) = unreleased_wrapper(store, &id)? {
            if !store.keys.has(&w.key_label()) {
                return Err(VeilError::Policy(format!(
                    "cannot merge: part of this history is under unreleased embargo {} and you do not hold its key",
                    w.embargo
                )));
            }
            // Embargoes never overlap (Veil 1.0): combining two lines under
            // different unreleased embargoes would nest one inside the other.
            match &wrapped {
                Some(first) if first.embargo != w.embargo => return Err(overlap_error(&first.embargo, &w.embargo)),
                Some(_) => {}
                None => wrapped = Some(w),
            }
        }
    }
    let full = merge_resolved(store, base, ours, theirs)?;
    let Some(w) = wrapped else {
        return Ok(full);
    };
    // What readers without the key see: the same merge of what they see.
    let pv = |id: ObjectId| public_view(store, &id);
    let (pb, po, pt) = (base.map(pv).transpose()?, pv(ours)?, pv(theirs)?);
    let fallback = match merge_resolved(store, pb, po, pt) {
        Ok(m) => m.tree,
        Err(_) => po,
    };
    Ok(MergeOutcome {
        tree: wrap(store, &w.embargo, &full.tree, &fallback)?,
        conflicts: full.conflicts,
    })
}

fn merge_resolved(store: &ObjectStore, base: Option<ObjectId>, ours: ObjectId, theirs: ObjectId) -> Result<MergeOutcome> {
    if ours == theirs || Some(theirs) == base {
        return Ok(MergeOutcome { tree: ours, conflicts: vec![] });
    }
    if Some(ours) == base {
        return Ok(MergeOutcome { tree: theirs, conflicts: vec![] });
    }
    let b = base.map(|id| store.tree(&id)).transpose()?;
    let o = store.tree(&ours)?;
    let t = store.tree(&theirs)?;
    let mut conflicts = Vec::new();
    let tree = match merge_dir(store, b, Some((o, ours)), Some((t, theirs)), &mut conflicts)? {
        Some(id) => id,
        None => store.empty_tree()?,
    };
    Ok(MergeOutcome { tree, conflicts })
}

fn same(a: Option<&TreeEntry>, b: Option<&TreeEntry>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(x), Some(y)) => x.same_content(y),
        _ => false,
    }
}

fn subtree(store: &ObjectStore, e: Option<&TreeEntry>) -> Result<Option<(Arc<Tree>, ObjectId)>> {
    match e {
        Some(e) if e.kind == EntryKind::Dir => Ok(Some((store.tree(&e.id)?, e.id))),
        _ => Ok(None),
    }
}

fn read_for_merge(store: &ObjectStore, e: &TreeEntry, path: &VPath) -> Result<Vec<u8>> {
    // A cloaked entry's fallback is its last public version, not its
    // content: merging that would silently revert the sealed edit.
    let read = match e.visibility {
        Visibility::Cloaked { .. } => store.read_blob(&e.id),
        _ => store.read_entry(e),
    };
    read.map_err(|err| match err {
        VeilError::Redacted { scope } => VeilError::Policy(format!(
            "cannot merge {path}: it is cloaked under scope '{scope}' and you do not hold the key"
        )),
        other => other,
    })
}

/// One directory being merged.
struct MergeFrame {
    dir: VPath,
    b: Option<Arc<Tree>>,
    o: Option<(Arc<Tree>, ObjectId)>,
    t: Option<(Arc<Tree>, ObjectId)>,
    names: Vec<String>,
    next: usize,
    out: Tree,
    /// Name of the entry whose subdirectory is being merged on top of this
    /// frame.
    waiting: Option<String>,
}

impl MergeFrame {
    fn new(dir: VPath, b: Option<Arc<Tree>>, o: Option<(Arc<Tree>, ObjectId)>, t: Option<(Arc<Tree>, ObjectId)>) -> Self {
        let mut names = BTreeSet::new();
        for tree in [b.as_deref(), o.as_ref().map(|x| &*x.0), t.as_ref().map(|x| &*x.0)].into_iter().flatten() {
            names.extend(tree.entries.iter().map(|e| e.name.clone()));
        }
        MergeFrame {
            dir,
            b,
            o,
            t,
            names: names.into_iter().collect(),
            next: 0,
            out: Tree::default(),
            waiting: None,
        }
    }

    /// Store the merged directory. A result equal to one side reuses that
    /// side's id (no re-encoding, so a format-1 tree keeps its id).
    fn finish(self, store: &ObjectStore) -> Result<Option<ObjectId>> {
        if self.out.is_empty() {
            return Ok(None);
        }
        for (tree, id) in [&self.o, &self.t].into_iter().flatten() {
            if **tree == self.out {
                return Ok(Some(*id));
            }
        }
        Ok(Some(store.put_tree(&self.out)?))
    }
}

/// Three-way merge of directories. Iterative: tree depth comes from
/// `.veil/` and remotes and is not trusted.
fn merge_dir(
    store: &ObjectStore,
    b: Option<Arc<Tree>>,
    o: Option<(Arc<Tree>, ObjectId)>,
    t: Option<(Arc<Tree>, ObjectId)>,
    conflicts: &mut Vec<VPath>,
) -> Result<Option<ObjectId>> {
    let mut stack = vec![MergeFrame::new(VPath::root(), b, o, t)];
    let mut result: Option<Option<ObjectId>> = None;
    loop {
        let depth = stack.len();
        let f = stack.last_mut().expect("stack is never empty here");
        if let Some(name) = f.waiting.take() {
            if let Some(id) = result.take().expect("a finished subdirectory") {
                f.out.insert(TreeEntry::dir(&name, id));
            }
        }
        let Some(name) = f.names.get(f.next).cloned() else {
            let done = stack.pop().expect("checked");
            let id = done.finish(store)?;
            if stack.is_empty() {
                return Ok(id);
            }
            result = Some(id);
            continue;
        };
        f.next += 1;
        let be = f.b.as_ref().and_then(|x| x.get(&name));
        let oe = f.o.as_ref().and_then(|x| x.0.get(&name));
        let te = f.t.as_ref().and_then(|x| x.0.get(&name));
        let path = f.dir.join(&name);
        let pick = if same(oe, te) || same(be, te) {
            oe.cloned()
        } else if same(be, oe) {
            te.cloned()
        } else {
            let kinds: Vec<EntryKind> = [oe, te].into_iter().flatten().map(|e| e.kind).collect();
            let base_ok = be.is_none_or(|e| e.kind == kinds[0]);
            if kinds.iter().all(|k| *k == EntryKind::Dir) && be.is_none_or(|e| e.kind == EntryKind::Dir) {
                if depth >= MAX_TREE_DEPTH {
                    return Err(VeilError::Corrupt(
                        path.to_string(),
                        format!("directory nesting exceeds {MAX_TREE_DEPTH} levels"),
                    ));
                }
                let (bs, os, ts) = (subtree(store, be)?.map(|x| x.0), subtree(store, oe)?, subtree(store, te)?);
                f.waiting = Some(name);
                stack.push(MergeFrame::new(path, bs, os, ts));
                continue;
            } else if let (Some(oe), Some(te), true) = (oe, te, kinds.iter().all(|k| *k == EntryKind::File) && base_ok) {
                Some(merge_file(store, &path, be, oe, te, conflicts)?)
            } else {
                // modify/delete or file/directory conflict: keep the surviving
                // side (ours first) and flag it.
                conflicts.push(path.clone());
                oe.or(te).cloned()
            }
        };
        if let Some(e) = pick {
            f.out.insert(e);
        }
    }
}

fn merge_file(
    store: &ObjectStore,
    path: &VPath,
    be: Option<&TreeEntry>,
    oe: &TreeEntry,
    te: &TreeEntry,
    conflicts: &mut Vec<VPath>,
) -> Result<TreeEntry> {
    let base = match be.filter(|e| e.kind == EntryKind::File) {
        Some(e) => read_for_merge(store, e, path)?,
        None => Vec::new(),
    };
    let ours = read_for_merge(store, oe, path)?;
    let theirs = read_for_merge(store, te, path)?;
    let executable = if be.is_some_and(|b| b.executable == oe.executable) {
        te.executable
    } else {
        oe.executable
    };
    if ours == theirs {
        return Ok(TreeEntry { executable, ..oe.clone() });
    }
    let merged = if looks_binary(&ours) || looks_binary(&theirs) || looks_binary(&base) {
        conflicts.push(path.clone());
        ours
    } else {
        match diffy::merge_bytes(&base, &ours, &theirs) {
            Ok(m) => m,
            Err(m) => {
                conflicts.push(path.clone());
                m
            }
        }
    };
    let (visibility, fallback) = merged_visibility(oe, te);
    let id = store.store_file(&merged, &visibility)?;
    Ok(TreeEntry {
        name: oe.name.clone(),
        kind: EntryKind::File,
        id,
        size: merged.len() as u64,
        executable,
        visibility,
        fallback,
    })
}

/// The visibility of a file merged from `oe` and `te`: never wider than
/// either side. Ours' sealing wins if ours is sealed; otherwise theirs'.
/// An embargoed result taken from theirs shows ours (public) as fallback.
/// A cloaked result from a side that is a sealed edit of a public file
/// (it has a fallback) shows the other side's public version as its
/// fallback if there is one (the newest public version), else the
/// sealed side's own.
fn merged_visibility(oe: &TreeEntry, te: &TreeEntry) -> (Visibility, Option<ObjectId>) {
    let public_other = |sealed: &TreeEntry, other: &TreeEntry| match (sealed.fallback, other.visibility.is_public() && other.fallback.is_none()) {
        (Some(_), true) => Some(other.id),
        (fb, _) => fb,
    };
    if !oe.visibility.is_public() {
        return match oe.visibility {
            Visibility::Cloaked { .. } => (oe.visibility.clone(), public_other(oe, te)),
            _ => (oe.visibility.clone(), oe.fallback),
        };
    }
    match &te.visibility {
        Visibility::Public => (Visibility::Public, None),
        Visibility::Cloaked { .. } => (te.visibility.clone(), public_other(te, oe)),
        Visibility::Embargoed { .. } => (te.visibility.clone(), Some(oe.id)),
    }
}
