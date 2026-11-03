//! Three-way tree merge. Works at the tree level (identical subtrees are
//! resolved by id without reading content) and falls back to line-based
//! diff3 for files changed on both sides. Visibility is preserved: a cloaked
//! file stays cloaked in the merge result.

use std::collections::BTreeSet;

use crate::{
    error::{Result, VeilError},
    id::ObjectId,
    object::{EntryKind, Tree, TreeEntry},
    secrets::looks_binary,
    store::ObjectStore,
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
    let b = base.map(|id| store.tree(&id)).transpose()?;
    let o = store.tree(&ours)?;
    let t = store.tree(&theirs)?;
    let mut conflicts = Vec::new();
    let tree = match merge_dir(store, &VPath::root(), b.as_deref(), Some(&o), Some(&t), &mut conflicts)? {
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

fn subtree(store: &ObjectStore, e: Option<&TreeEntry>) -> Result<Option<std::sync::Arc<Tree>>> {
    match e {
        Some(e) if e.kind == EntryKind::Dir => Ok(Some(store.tree(&e.id)?)),
        _ => Ok(None),
    }
}

fn read_for_merge(store: &ObjectStore, e: &TreeEntry, path: &VPath) -> Result<Vec<u8>> {
    store.read_entry(e).map_err(|err| match err {
        VeilError::Redacted { scope } => VeilError::Policy(format!(
            "cannot merge {path}: it is cloaked under scope '{scope}' and you do not hold the key"
        )),
        other => other,
    })
}

fn merge_dir(
    store: &ObjectStore,
    dir: &VPath,
    b: Option<&Tree>,
    o: Option<&Tree>,
    t: Option<&Tree>,
    conflicts: &mut Vec<VPath>,
) -> Result<Option<ObjectId>> {
    let mut names = BTreeSet::new();
    for tree in [b, o, t].into_iter().flatten() {
        names.extend(tree.entries.iter().map(|e| e.name.clone()));
    }
    let mut out = Tree::default();
    for name in names {
        let be = b.and_then(|x| x.get(&name));
        let oe = o.and_then(|x| x.get(&name));
        let te = t.and_then(|x| x.get(&name));
        let path = dir.join(&name);
        let pick = if same(oe, te) || same(be, te) {
            oe.cloned()
        } else if same(be, oe) {
            te.cloned()
        } else {
            let kinds: Vec<EntryKind> = [oe, te].into_iter().flatten().map(|e| e.kind).collect();
            let base_ok = be.map_or(true, |e| e.kind == kinds[0]);
            if kinds.iter().all(|k| *k == EntryKind::Dir) && be.map_or(true, |e| e.kind == EntryKind::Dir) {
                let (bs, os, ts) = (subtree(store, be)?, subtree(store, oe)?, subtree(store, te)?);
                merge_dir(store, &path, bs.as_deref(), os.as_deref(), ts.as_deref(), conflicts)?
                    .map(|id| TreeEntry::dir(&name, id))
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
            out.insert(e);
        }
    }
    if out.is_empty() {
        Ok(None)
    } else {
        Ok(Some(store.put_tree(&out)?))
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
    let id = store.store_file(&merged, &oe.visibility)?;
    Ok(TreeEntry {
        name: oe.name.clone(),
        kind: EntryKind::File,
        id,
        size: merged.len() as u64,
        executable,
        visibility: oe.visibility.clone(),
        fallback: oe.fallback,
    })
}
