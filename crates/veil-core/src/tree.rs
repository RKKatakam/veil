//! Tree utilities and [`TreeView`], a read-only `StorageBackend` over a
//! snapshot tree. A `TreeView` is lazy: it only loads (and decrypts) the
//! trees and blobs that are actually read.

use std::sync::Arc;

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

/// Deepest directory nesting accepted from a remote (see
/// `remote::Transfer`). Every walk in this module is iterative and copes
/// with any depth; the bound protects the remaining recursive algorithms
/// (merge, embargo normalisation, the builder) and keeps paths well below
/// the host's `PATH_MAX`. Git's `core.maxTreeDepth` serves the same purpose.
pub const MAX_TREE_DEPTH: usize = 1024;

/// All leaf entries below `root` (files and conflicts, and in format 5
/// symlinks and gitlinks), in tree order (depth first, entries sorted by
/// name within a directory). Callers that read content check the kind:
/// a symlink's or gitlink's blob is not file content.
pub fn walk_files(store: &ObjectStore, root: &ObjectId) -> Result<Vec<(VPath, TreeEntry)>> {
    let mut out = Vec::new();
    // Explicit stack: tree depth is attacker-controlled.
    let mut stack: Vec<(VPath, Arc<Tree>, usize)> = vec![(VPath::root(), store.tree(root)?, 0)];
    while let Some((dir, tree, i)) = stack.last_mut() {
        let Some(e) = tree.entries.get(*i) else {
            stack.pop();
            continue;
        };
        *i += 1;
        let p = dir.join(&e.name);
        match e.kind {
            EntryKind::File | EntryKind::Conflict | EntryKind::Symlink | EntryKind::Gitlink => out.push((p, e.clone())),
            EntryKind::Dir => {
                let child = store.tree(&e.id)?;
                stack.push((p, child, 0));
            }
        }
    }
    Ok(out)
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

/// Leaf-level differences between two trees (files, conflicts, and in
/// format 5 symlinks and gitlinks). Identical subtrees are skipped
/// by id without being loaded.
pub fn diff_trees(store: &ObjectStore, from: Option<&ObjectId>, to: Option<&ObjectId>) -> Result<Vec<TreeChange>> {
    let mut out = Vec::new();
    if from == to {
        return Ok(out);
    }
    let a = from.map(|id| store.tree(id)).transpose()?;
    let b = to.map(|id| store.tree(id)).transpose()?;
    diff_dir(store, a, b, &mut out)?;
    Ok(out)
}

fn load_dir(store: &ObjectStore, e: Option<&TreeEntry>) -> Result<Option<Arc<Tree>>> {
    match e {
        Some(e) if e.kind == EntryKind::Dir => Ok(Some(store.tree(&e.id)?)),
        _ => Ok(None),
    }
}

/// One directory being compared: both sides, and a merge-join cursor into
/// each (entries are sorted, see [`Tree::validate`]).
struct DiffFrame {
    dir: VPath,
    a: Option<Arc<Tree>>,
    b: Option<Arc<Tree>>,
    ia: usize,
    ib: usize,
    /// File change for the entry whose directory side is being walked on
    /// top of this frame; emitted once that walk is done, so the output
    /// order matches a depth-first recursion.
    pending: Option<TreeChange>,
}

fn entry_at(t: &Option<Arc<Tree>>, i: usize) -> Option<&TreeEntry> {
    t.as_ref().and_then(|t| t.entries.get(i))
}

fn diff_dir(store: &ObjectStore, a: Option<Arc<Tree>>, b: Option<Arc<Tree>>, out: &mut Vec<TreeChange>) -> Result<()> {
    // Explicit stack: tree depth is attacker-controlled.
    let mut stack = vec![DiffFrame {
        dir: VPath::root(),
        a,
        b,
        ia: 0,
        ib: 0,
        pending: None,
    }];
    while let Some(f) = stack.last_mut() {
        if let Some(c) = f.pending.take() {
            out.push(c);
        }
        let (ea, eb) = match (entry_at(&f.a, f.ia), entry_at(&f.b, f.ib)) {
            (None, None) => {
                stack.pop();
                continue;
            }
            (Some(x), Some(y)) if x.name == y.name => (Some(x.clone()), Some(y.clone())),
            (Some(x), Some(y)) if x.name < y.name => (Some(x.clone()), None),
            (Some(_), Some(y)) => (None, Some(y.clone())),
            (x, y) => (x.cloned(), y.cloned()),
        };
        f.ia += usize::from(ea.is_some());
        f.ib += usize::from(eb.is_some());
        if let (Some(x), Some(y)) = (&ea, &eb) {
            if x.same_content(y) {
                continue;
            }
        }
        let name = ea.as_ref().or(eb.as_ref()).map(|e| e.name.as_str()).unwrap_or_default();
        let path = f.dir.join(name);
        let da = load_dir(store, ea.as_ref())?;
        let db = load_dir(store, eb.as_ref())?;
        // Every leaf: files, conflicts, and (format 5) symlinks and gitlinks.
        let fa = ea.filter(|e| e.kind != EntryKind::Dir);
        let fb = eb.filter(|e| e.kind != EntryKind::Dir);
        let file_change = (fa.is_some() || fb.is_some()).then(|| TreeChange {
            path: path.clone(),
            old: fa,
            new: fb,
        });
        if da.is_some() || db.is_some() {
            f.pending = file_change;
            stack.push(DiffFrame {
                dir: path,
                a: da,
                b: db,
                ia: 0,
                ib: 0,
                pending: None,
            });
        } else if let Some(c) = file_change {
            out.push(c);
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

    /// What entry `e` is materialised as: a conflict with a symlink or
    /// gitlink side (format 5) as its shown side, as it is
    /// ([`crate::conflict::shown_side`]); anything else as itself.
    pub(crate) fn shown(&self, e: TreeEntry) -> TreeEntry {
        if e.kind != EntryKind::Conflict {
            return e;
        }
        match self.store.conflict(&e.id) {
            Ok(c) if c.has_special_terms() => match crate::conflict::shown_side(&c) {
                Some((_, t)) => t.entry(&e.name),
                None => e,
            },
            _ => e,
        }
    }

    /// The node kind entry `e` is materialised as (see [`TreeView::shown`]):
    /// a gitlink is the (empty) directory of a submodule.
    pub(crate) fn node_kind(&self, e: &TreeEntry) -> NodeKind {
        match self.shown(e.clone()).kind {
            EntryKind::Dir | EntryKind::Gitlink => NodeKind::Dir,
            EntryKind::Symlink => NodeKind::Symlink,
            EntryKind::File | EntryKind::Conflict => NodeKind::File,
        }
    }
}

impl StorageBackend for TreeView {
    fn kind(&self) -> &'static str {
        "tree"
    }

    fn read(&self, path: &VPath) -> Result<Vec<u8>> {
        match self.entry(path)?.map(|e| self.shown(e)) {
            Some(e) if e.kind.is_file_like() => crate::conflict::read_file_like(&self.store, &e),
            // A link is never read through, as on disk.
            Some(e) if e.kind == EntryKind::Symlink => Err(VeilError::NotFound(path.to_string())),
            Some(_) => Err(VeilError::InvalidPath(format!("{path} is a directory"))),
            None => Err(VeilError::NotFound(path.to_string())),
        }
    }

    fn read_link(&self, path: &VPath) -> Result<Vec<u8>> {
        match self.entry(path)?.map(|e| self.shown(e)) {
            Some(e) if e.kind == EntryKind::Symlink => self.store.read_entry(&e),
            Some(_) => Err(VeilError::InvalidPath(format!("{path} is not a symlink"))),
            None => Err(VeilError::NotFound(path.to_string())),
        }
    }

    fn special_at(&self, path: &VPath) -> Result<Option<&'static str>> {
        Ok(self.entry(path)?.is_some_and(|e| self.node_kind(&e) == NodeKind::Symlink).then_some("a symlink"))
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
        match self.entry(path)?.map(|e| self.shown(e)) {
            Some(e) if e.kind == EntryKind::Dir => Ok(self
                .store
                .tree(&e.id)?
                .entries
                .iter()
                // unreadable entries are invisible in a materialised view
                .filter(|c| self.store.entry_readable(&self.shown((*c).clone())))
                .map(|c| DirEntry {
                    name: c.name.clone(),
                    kind: self.node_kind(c),
                })
                .collect()),
            // A submodule's directory, as checkout leaves it: empty.
            Some(e) if e.kind == EntryKind::Gitlink => Ok(Vec::new()),
            Some(_) => Err(VeilError::InvalidPath(format!("{path} is not a directory"))),
            None => Err(VeilError::NotFound(path.to_string())),
        }
    }

    fn metadata(&self, path: &VPath) -> Result<Option<Metadata>> {
        // Immutable content is identified by `known_id`, not by stamps.
        let Some(e) = self.entry(path)?.map(|e| self.shown(e)) else { return Ok(None) };
        Ok(Some(match e.kind {
            EntryKind::Dir | EntryKind::Gitlink => Metadata::unstamped(NodeKind::Dir, 0, false),
            EntryKind::File => Metadata::unstamped(NodeKind::File, e.size, e.executable),
            // What a reader of the view gets is the materialised conflict.
            EntryKind::Conflict => {
                let m = crate::conflict::materialize_entry(&self.store, &e, crate::conflict::Audience::Reader)?;
                Metadata::unstamped(NodeKind::File, m.content.len() as u64, m.executable)
            }
            EntryKind::Symlink => Metadata::unstamped(NodeKind::Symlink, e.size, false),
        }))
    }

    fn known_id(&self, path: &VPath) -> Option<ObjectId> {
        self.entry(path).ok().flatten().map(|e| e.id)
    }
}
