//! Tree utilities and [`TreeView`], a read-only `StorageBackend` over a
//! snapshot tree. A `TreeView` is lazy: it only loads (and decrypts) the
//! trees and blobs that are actually read.

use std::{collections::BTreeSet, sync::Arc};

use crate::{
    error::{Result, VeilError},
    id::ObjectId,
    object::{EntryKind, Tree, TreeEntry},
    store::ObjectStore,
    vfs::{DirEntry, Metadata, NodeKind, StorageBackend},
    vpath::VPath,
};

pub fn lookup(store: &ObjectStore, root: &ObjectId, path: &VPath) -> Result<Option<TreeEntry>> {
    if path.is_root() {
        return Ok(Some(TreeEntry::dir("", *root)));
    }
    let comps: Vec<&str> = path.components().collect();
    let mut tree = store.tree(root)?;
    for (i, c) in comps.iter().enumerate() {
        let Some(e) = tree.get(c).cloned() else {
            return Ok(None);
        };
        if i == comps.len() - 1 {
            return Ok(Some(e));
        }
        if e.kind != EntryKind::Dir {
            return Ok(None);
        }
        tree = store.tree(&e.id)?;
    }
    unreachable!()
}

/// All file entries below `root`, sorted by path.
pub fn walk_files(store: &ObjectStore, root: &ObjectId) -> Result<Vec<(VPath, TreeEntry)>> {
    let mut out = Vec::new();
    walk_into(store, root, &VPath::root(), &mut out)?;
    Ok(out)
}

fn walk_into(store: &ObjectStore, id: &ObjectId, dir: &VPath, out: &mut Vec<(VPath, TreeEntry)>) -> Result<()> {
    let tree = store.tree(id)?;
    for e in &tree.entries {
        let p = dir.join(&e.name);
        match e.kind {
            EntryKind::Dir => walk_into(store, &e.id, &p, out)?,
            EntryKind::File => out.push((p, e.clone())),
        }
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeChange {
    pub path: VPath,
    pub old: Option<TreeEntry>,
    pub new: Option<TreeEntry>,
}

impl TreeChange {
    pub fn status(&self) -> char {
        match (&self.old, &self.new) {
            (None, Some(_)) => 'A',
            (Some(_), None) => 'D',
            _ => 'M',
        }
    }
}

/// File-level differences between two trees. Identical subtrees are skipped
/// by id without being loaded.
pub fn diff_trees(store: &ObjectStore, from: Option<&ObjectId>, to: Option<&ObjectId>) -> Result<Vec<TreeChange>> {
    let mut out = Vec::new();
    if from == to {
        return Ok(out);
    }
    let a = from.map(|id| store.tree(id)).transpose()?;
    let b = to.map(|id| store.tree(id)).transpose()?;
    diff_dir(store, &VPath::root(), a.as_deref(), b.as_deref(), &mut out)?;
    Ok(out)
}

fn load_dir(store: &ObjectStore, e: Option<&TreeEntry>) -> Result<Option<Arc<Tree>>> {
    match e {
        Some(e) if e.kind == EntryKind::Dir => Ok(Some(store.tree(&e.id)?)),
        _ => Ok(None),
    }
}

fn diff_dir(store: &ObjectStore, dir: &VPath, a: Option<&Tree>, b: Option<&Tree>, out: &mut Vec<TreeChange>) -> Result<()> {
    let mut names = BTreeSet::new();
    for t in [a, b].into_iter().flatten() {
        names.extend(t.entries.iter().map(|e| e.name.as_str()));
    }
    for name in names {
        let ea = a.and_then(|t| t.get(name));
        let eb = b.and_then(|t| t.get(name));
        if let (Some(x), Some(y)) = (ea, eb) {
            if x.same_content(y) {
                continue;
            }
        }
        let path = dir.join(name);
        let da = load_dir(store, ea)?;
        let db = load_dir(store, eb)?;
        if da.is_some() || db.is_some() {
            diff_dir(store, &path, da.as_deref(), db.as_deref(), out)?;
        }
        let fa = ea.filter(|e| e.kind == EntryKind::File).cloned();
        let fb = eb.filter(|e| e.kind == EntryKind::File).cloned();
        if fa.is_some() || fb.is_some() {
            out.push(TreeChange {
                path,
                old: fa,
                new: fb,
            });
        }
    }
    Ok(())
}

/// Read-only VFS view of a tree.
#[derive(Debug)]
pub struct TreeView {
    store: Arc<ObjectStore>,
    root: ObjectId,
}

impl TreeView {
    pub fn new(store: Arc<ObjectStore>, root: ObjectId) -> Self {
        TreeView { store, root }
    }

    pub fn root(&self) -> ObjectId {
        self.root
    }

    fn entry(&self, path: &VPath) -> Result<Option<TreeEntry>> {
        lookup(&self.store, &self.root, path)
    }
}

impl StorageBackend for TreeView {
    fn kind(&self) -> &'static str {
        "tree"
    }

    fn read(&self, path: &VPath) -> Result<Vec<u8>> {
        match self.entry(path)? {
            Some(e) if e.kind == EntryKind::File => self.store.read_entry(&e),
            Some(_) => Err(VeilError::InvalidPath(format!("{path} is a directory"))),
            None => Err(VeilError::NotFound(path.to_string())),
        }
    }

    fn write(&self, _: &VPath, _: &[u8]) -> Result<()> {
        Err(VeilError::ReadOnly)
    }
    fn create_new(&self, _: &VPath, _: &[u8]) -> Result<bool> {
        Err(VeilError::ReadOnly)
    }
    fn remove_file(&self, _: &VPath) -> Result<()> {
        Err(VeilError::ReadOnly)
    }
    fn remove_dir_all(&self, _: &VPath) -> Result<()> {
        Err(VeilError::ReadOnly)
    }
    fn create_dir_all(&self, _: &VPath) -> Result<()> {
        Err(VeilError::ReadOnly)
    }
    fn set_executable(&self, _: &VPath, _: bool) -> Result<()> {
        Err(VeilError::ReadOnly)
    }

    fn list_dir(&self, path: &VPath) -> Result<Vec<DirEntry>> {
        match self.entry(path)? {
            Some(e) if e.kind == EntryKind::Dir => Ok(self
                .store
                .tree(&e.id)?
                .entries
                .iter()
                // unreadable entries are invisible in a materialised view
                .filter(|c| self.store.entry_readable(c))
                .map(|c| DirEntry {
                    name: c.name.clone(),
                    kind: match c.kind {
                        EntryKind::Dir => NodeKind::Dir,
                        EntryKind::File => NodeKind::File,
                    },
                })
                .collect()),
            Some(_) => Err(VeilError::InvalidPath(format!("{path} is not a directory"))),
            None => Err(VeilError::NotFound(path.to_string())),
        }
    }

    fn metadata(&self, path: &VPath) -> Result<Option<Metadata>> {
        Ok(self.entry(path)?.map(|e| Metadata {
            kind: match e.kind {
                EntryKind::Dir => NodeKind::Dir,
                EntryKind::File => NodeKind::File,
            },
            len: e.size,
            executable: e.executable,
        }))
    }

    fn known_id(&self, path: &VPath) -> Option<ObjectId> {
        self.entry(path).ok().flatten().map(|e| e.id)
    }
}
