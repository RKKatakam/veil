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

/// Files a reader by path asks for together (each at its own path).
const PREFETCH_CHUNK: usize = 4096;

/// In a thin clone, have the content of `files` (paths below `root`) that
/// is not held, each asked for at its own path, a batch a request. A reader
/// that walks a tree and then reads its files by id calls this first: the
/// server decides by path, and the store keeps one place an object, so
/// content refused at the path met first is fetched where it is readable
/// (BUG-1506). What the server refuses stays unfetched, for the read to
/// meet as hidden. Nothing happens in a full clone or while fetching is off.
pub fn prefetch_files<'a>(store: &ObjectStore, root: &ObjectId, files: impl IntoIterator<Item = (&'a VPath, &'a TreeEntry)>) -> Result<()> {
    if !store.may_fetch() {
        return Ok(());
    }
    let mut want: Vec<(VPath, ObjectId, u64)> = Vec::new();
    for (p, e) in files {
        if e.kind != EntryKind::Dir && !store.has(&e.id) {
            want.push((p.clone(), e.id, e.size));
        }
        if want.len() == PREFETCH_CHUNK {
            store.prefetch_at(root, &std::mem::take(&mut want))?;
        }
    }
    match want.is_empty() {
        true => Ok(()),
        false => store.prefetch_at(root, &want),
    }
}

/// [`prefetch_files`] for both sides of `changes` (from [`diff_trees`]
/// between `from` and `to`): each old side at its path in `from`, each
/// new side at its path in `to`.
pub fn prefetch_changes<'a>(store: &ObjectStore, from: Option<&ObjectId>, to: Option<&ObjectId>, changes: impl IntoIterator<Item = &'a TreeChange> + Clone) -> Result<()> {
    if !store.may_fetch() {
        return Ok(());
    }
    if let Some(f) = from {
        prefetch_files(store, f, changes.clone().into_iter().filter_map(|c| c.old.as_ref().map(|e| (&c.path, e))))?;
    }
    if let Some(t) = to {
        prefetch_files(store, t, changes.into_iter().filter_map(|c| c.new.as_ref().map(|e| (&c.path, e))))?;
    }
    Ok(())
}

/// [`lookup`] for a reader about to read the entry's content: in a thin
/// clone, content not held is asked for at `path` first (BUG-1506).
pub fn lookup_to_read(store: &ObjectStore, root: &ObjectId, path: &VPath) -> Result<Option<TreeEntry>> {
    let e = lookup(store, root, path)?;
    if let Some(e) = &e {
        prefetch_files(store, root, [(path, e)])?;
    }
    Ok(e)
}

/// Deepest directory nesting accepted from a remote (see
/// `remote::Transfer`). Every walk in this module is iterative and copes
/// with any depth; the bound protects the remaining recursive algorithms
/// (merge, embargo normalisation, the builder) and keeps paths well below
/// the host's `PATH_MAX`. Git's `core.maxTreeDepth` serves the same purpose.
pub const MAX_TREE_DEPTH: usize = 1024;

/// All leaf entries below `root` (files and conflicts, and in format 5
/// symlinks), in tree order (depth first, entries sorted by name within a
/// directory). Callers that read content check the kind: a symlink's blob
/// is not file content.
pub fn walk_files(store: &ObjectStore, root: &ObjectId) -> Result<Vec<(VPath, TreeEntry)>> {
    walk_files_in(store, root, None)
}

/// The leaf entries a walk found, and the folders it could not walk.
pub type WalkHiding = (Vec<(VPath, TreeEntry)>, Vec<VPath>);

/// [`walk_files`] for a reader: a folder whose tree the server refuses (a
/// thin clone whose person lost access to it) is not walked, listed
/// instead (BUG-1508), the root included.
pub fn walk_files_hiding(store: &ObjectStore, root: &ObjectId) -> Result<WalkHiding> {
    let mut hidden = Vec::new();
    let files = walk_files_in(store, root, Some(&mut hidden))?;
    Ok((files, hidden))
}

fn walk_files_in(store: &ObjectStore, root: &ObjectId, mut hidden: Option<&mut Vec<VPath>>) -> Result<Vec<(VPath, TreeEntry)>> {
    let mut out = Vec::new();
    let mut open = |id: &ObjectId, path: &VPath| -> Result<Option<Arc<Tree>>> {
        match store.tree(id) {
            Ok(t) => Ok(Some(t)),
            Err(e) if refused_tree(store, &e) => match hidden.as_deref_mut() {
                Some(h) => {
                    h.push(path.clone());
                    Ok(None)
                }
                None => Err(no_access(path, "this command needs its content")),
            },
            Err(e) => Err(e),
        }
    };
    let Some(top) = open(root, &VPath::root())? else { return Ok(out) };
    // Explicit stack: tree depth is attacker-controlled.
    let mut stack: Vec<(VPath, Arc<Tree>, usize)> = vec![(VPath::root(), top, 0)];
    while let Some((dir, tree, i)) = stack.last_mut() {
        let Some(e) = tree.entries.get(*i) else {
            stack.pop();
            continue;
        };
        *i += 1;
        let p = dir.join(&e.name);
        match e.kind {
            EntryKind::File | EntryKind::Conflict | EntryKind::Symlink => out.push((p, e.clone())),
            EntryKind::Dir => {
                if let Some(child) = open(&e.id, &p)? {
                    stack.push((p, child, 0));
                }
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
/// format 5 symlinks). Identical subtrees are skipped
/// by id without being loaded. For a writer: a folder whose tree the
/// server refuses (a thin clone whose person lost access to it) is a clear
/// refusal naming it ([`no_access`]), never "not present"; readers use
/// [`diff_trees_hiding`].
pub fn diff_trees(store: &ObjectStore, from: Option<&ObjectId>, to: Option<&ObjectId>) -> Result<Vec<TreeChange>> {
    let mut out = Vec::new();
    match diff_trees_in(store, from, to, &mut out, None) {
        Err(Hit::Refused(path)) => Err(no_access(&path, "this command needs its content")),
        Err(Hit::Error(e)) => Err(e),
        Ok(()) => Ok(out),
    }
}

/// A folder [`diff_trees_hiding`] did not compare: the server refused the
/// tree of one side (`old` in `from`, `new` in `to`; the directory entries,
/// whose names the person could already see).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HiddenDir {
    pub path: VPath,
    pub old: Option<TreeEntry>,
    pub new: Option<TreeEntry>,
}

/// [`diff_trees`] for a reader: a folder whose tree the server refuses is
/// not compared, listed instead (BUG-1508); nothing inside it is read or
/// shown. The root itself can be refused (a thin clone made before its
/// person's access changed, whose root it never fetched): then it is the
/// one hidden folder.
pub fn diff_trees_hiding(store: &ObjectStore, from: Option<&ObjectId>, to: Option<&ObjectId>) -> Result<(Vec<TreeChange>, Vec<HiddenDir>)> {
    let (mut out, mut hidden) = (Vec::new(), Vec::new());
    match diff_trees_in(store, from, to, &mut out, Some(&mut hidden)) {
        Err(Hit::Refused(_)) => unreachable!("a hiding diff lists refusals"),
        Err(Hit::Error(e)) => Err(e),
        Ok(()) => Ok((out, hidden)),
    }
}

/// Did the server refuse this tree to this thin clone? `Missing` while
/// fetching is the server's own "nothing there for you" (its person lost
/// access to that folder since its name was met); with fetching off, or in
/// a full clone, `Missing` is a gap and stays an error.
pub fn refused_tree(store: &ObjectStore, err: &VeilError) -> bool {
    matches!(err, VeilError::Missing(_)) && store.may_fetch()
}

/// The refusal of a writer that needs the content of a folder whose tree
/// the server refuses (BUG-1508): it names the folder, says why, and that
/// nothing was changed.
pub fn no_access(path: &VPath, why: &str) -> VeilError {
    let shown = if path.is_root() { "/".to_string() } else { format!("{path}/") };
    VeilError::Policy(format!(
        "{shown} is a folder you no longer have access to (the server refuses its content) and {why}; nothing was changed. \
         `vl pull` brings what you may read now"
    ))
}

enum Hit {
    Refused(VPath),
    Error(VeilError),
}

impl From<VeilError> for Hit {
    fn from(e: VeilError) -> Hit {
        Hit::Error(e)
    }
}

fn diff_trees_in(
    store: &ObjectStore,
    from: Option<&ObjectId>,
    to: Option<&ObjectId>,
    out: &mut Vec<TreeChange>,
    hidden: Option<&mut Vec<HiddenDir>>,
) -> std::result::Result<(), Hit> {
    if from == to {
        return Ok(());
    }
    let root = |id: &ObjectId| TreeEntry::dir("", *id);
    let a = from.map(|id| store.tree(id)).transpose();
    let b = to.map(|id| store.tree(id)).transpose();
    match (a, b) {
        (Ok(a), Ok(b)) => diff_dir(store, a, b, out, hidden),
        (Err(e), _) | (_, Err(e)) if refused_tree(store, &e) => match hidden {
            Some(h) => {
                h.push(HiddenDir { path: VPath::root(), old: from.map(root), new: to.map(root) });
                Ok(())
            }
            None => Err(Hit::Refused(VPath::root())),
        },
        (Err(e), _) | (_, Err(e)) => Err(Hit::Error(e)),
    }
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

fn diff_dir(
    store: &ObjectStore,
    a: Option<Arc<Tree>>,
    b: Option<Arc<Tree>>,
    out: &mut Vec<TreeChange>,
    mut hidden: Option<&mut Vec<HiddenDir>>,
) -> std::result::Result<(), Hit> {
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
        let (da, db) = match (load_dir(store, ea.as_ref()), load_dir(store, eb.as_ref())) {
            (Ok(da), Ok(db)) => (da, db),
            // A folder the server refuses: neither side of it is walked.
            (Err(e), _) | (_, Err(e)) if refused_tree(store, &e) => {
                let Some(h) = hidden.as_deref_mut() else { return Err(Hit::Refused(path)) };
                let dir = |e: &Option<TreeEntry>| e.clone().filter(|e| e.kind == EntryKind::Dir);
                h.push(HiddenDir { path: path.clone(), old: dir(&ea), new: dir(&eb) });
                (None, None)
            }
            (Err(e), _) | (_, Err(e)) => return Err(Hit::Error(e)),
        };
        // Every leaf: files, conflicts, and (format 5) symlinks.
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

    /// What entry `e` is materialised as: a conflict with a symlink side
    /// (format 5) as its shown side, as it is
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

    /// The node kind entry `e` is materialised as (see [`TreeView::shown`]).
    pub(crate) fn node_kind(&self, e: &TreeEntry) -> NodeKind {
        match self.shown(e.clone()).kind {
            EntryKind::Dir => NodeKind::Dir,
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
            Some(_) => Err(VeilError::InvalidPath(format!("{path} is not a directory"))),
            None => Err(VeilError::NotFound(path.to_string())),
        }
    }

    fn metadata(&self, path: &VPath) -> Result<Option<Metadata>> {
        // Immutable content is identified by `known_id`, not by stamps.
        let Some(e) = self.entry(path)?.map(|e| self.shown(e)) else { return Ok(None) };
        Ok(Some(match e.kind {
            EntryKind::Dir => Metadata::unstamped(NodeKind::Dir, 0, false),
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
