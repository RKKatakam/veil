//! Delayed-visibility (embargoed) merges and visibility normalisation.
//!
//! An embargoed merge seals every file that differs from the first parent
//! under a fresh embargo key, keeping the first parent's version as the
//! entry's `fallback`. Readers without the key — e.g. a public mirror — see
//! the main line exactly as it was before the merge; members of the
//! embargo's scope see the merged content. Releasing publishes the key and
//! everyone sees the merge, with no history rewrite.
//!
//! Time-based release is enforced by the engines of key holders: the first
//! `vl` invocation by a key holder after the deadline publishes the key.
//! (True time-lock cryptography is out of scope.)

use crate::{
    error::Result,
    id::ObjectId,
    object::{EntryKind, Tree, TreeEntry, Visibility},
    policy::{Policy, Tier},
    store::ObjectStore,
    vpath::VPath,
};

/// Seal every file of `tree` that differs from `base` under `embargo`.
pub fn apply_embargo(store: &ObjectStore, tree: &ObjectId, base: &ObjectId, embargo: &str) -> Result<ObjectId> {
    let t = store.tree(tree)?;
    let b = store.tree(base)?;
    let vis = Visibility::Embargoed {
        embargo: embargo.to_string(),
    };
    let mut out = Tree::default();
    for e in &t.entries {
        let be = b.get(&e.name);
        if be.is_some_and(|x| x.same_content(e)) {
            out.insert(e.clone());
            continue;
        }
        match e.kind {
            EntryKind::Dir => {
                let base_sub = match be.filter(|x| x.kind == EntryKind::Dir) {
                    Some(x) => x.id,
                    None => store.empty_tree()?,
                };
                out.insert(TreeEntry::dir(&e.name, apply_embargo(store, &e.id, &base_sub, embargo)?));
            }
            EntryKind::File => {
                let data = store.read_entry(e)?;
                out.insert(TreeEntry {
                    id: store.store_file(&data, &vis)?,
                    visibility: vis.clone(),
                    fallback: be.filter(|x| x.kind == EntryKind::File).map(|x| x.id),
                    ..e.clone()
                });
            }
        }
    }
    store.put_tree(&out)
}

/// Re-seal entries whose visibility no longer matches policy (e.g. after
/// merging a cloaked line of work into a public one). Embargoed entries and
/// entries this reader cannot decrypt are left as they are.
pub fn normalize_tree(store: &ObjectStore, tree: &ObjectId, policy: &Policy, cloak: Option<&str>) -> Result<ObjectId> {
    normalize_dir(store, tree, &VPath::root(), policy, cloak)
}

fn normalize_dir(store: &ObjectStore, tree: &ObjectId, dir: &VPath, policy: &Policy, cloak: Option<&str>) -> Result<ObjectId> {
    let t = store.tree(tree)?;
    let mut out = Tree::default();
    let mut changed = false;
    for e in &t.entries {
        let path = dir.join(&e.name);
        let mut ne = e.clone();
        match e.kind {
            EntryKind::Dir => {
                ne.id = normalize_dir(store, &e.id, &path, policy, cloak)?;
            }
            EntryKind::File => {
                let desired = match policy.classify(&path, false).tier {
                    Tier::Public => match cloak {
                        Some(s) => Visibility::Cloaked { scope: s.to_string() },
                        None => Visibility::Public,
                    },
                    Tier::Cloaked(s) => Visibility::Cloaked { scope: s },
                    Tier::Isolated | Tier::Ignored => e.visibility.clone(),
                };
                if !matches!(e.visibility, Visibility::Embargoed { .. }) && desired != e.visibility {
                    if let Ok(data) = store.read_entry(e) {
                        if let Ok(id) = store.store_file(&data, &desired) {
                            ne.id = id;
                            ne.visibility = desired;
                        }
                    }
                }
            }
        }
        changed |= ne != *e;
        out.insert(ne);
    }
    if !changed {
        return Ok(*tree);
    }
    store.put_tree(&out)
}
