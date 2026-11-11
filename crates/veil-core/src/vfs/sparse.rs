//! Sparse working copies: a subset of a tree ([`SparseSet`]), the tree
//! restricted to it ([`restrict`]) and the backend that records a sparse
//! working copy as the whole tree ([`SparseView`]).
//!
//! A sparse `vl ws exec` sandbox holds only the paths of its set (plus
//! `.veilpolicy`, which the snapshot needs to classify anything). Recording
//! it must not delete everything else, and must not record anything the
//! command wrote elsewhere. [`SparseView`] presents the sandbox to the
//! builder as the full working copy: inside the set it *is* the sandbox;
//! outside it is the tree the sandbox was synced from (a
//! [`TreeView`](crate::tree::TreeView)), whose entries it vouches for
//! through [`StorageBackend::known_id`], so the builder reuses every
//! directory outside the set by id without listing it. Files the command
//! wrote outside the set are invisible ([`strays`](crate::sandbox::strays)
//! lists them). Directories on the way to a path of the set ("spine"
//! directories) are merged: the sandbox's entries that lead into the set,
//! the tree's entries that do not.
//!
//! Everything the builder decides is thus decided exactly as for a full
//! working copy whose files outside the set are unchanged: the policy,
//! sealed secrets, conflicts. When the policy changed (or the
//! scanner's rules did), hints are off and the builder reads the files
//! outside the set from the tree to reclassify them, which is slow but
//! exactly right.

use std::sync::Arc;

use super::{DirEntry, DirListing, Metadata, NameFolding, NodeKind, StatClock, StorageBackend};
use crate::{
    error::{Result, VeilError},
    id::ObjectId,
    object::{EntryKind, Object, Tree, TreeEntry},
    policy::POLICY_FILE,
    store::ObjectStore,
    tree::TreeView,
    vpath::VPath,
};

/// A set of paths of a tree (files or directories), normalised: sorted,
/// none inside another, never the root (the whole tree is "no set").
/// `.veilpolicy` is always a member.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SparseSet {
    paths: Vec<VPath>,
}

impl SparseSet {
    /// The set of `paths`, or `None` if one of them is the root (the whole
    /// tree) or there are none.
    pub fn new(paths: impl IntoIterator<Item = VPath>) -> Option<SparseSet> {
        let mut paths: Vec<VPath> = paths.into_iter().collect();
        if paths.is_empty() || paths.iter().any(VPath::is_root) {
            return None;
        }
        paths.sort();
        paths.dedup();
        // Sorted: an ancestor comes before everything below it.
        let mut out: Vec<VPath> = Vec::new();
        for p in paths {
            if !out.iter().any(|q| p.starts_with(q)) {
                out.push(p);
            }
        }
        Some(SparseSet { paths: out })
    }

    /// Parse the set as a manifest stores it.
    pub fn from_strings(paths: &[String]) -> Result<Option<SparseSet>> {
        let mut out = Vec::new();
        for p in paths {
            let vp = VPath::new(p)?;
            if vp.as_str() != p {
                return Err(VeilError::InvalidPath(format!("'{p}' is not a normalised path")));
            }
            out.push(vp);
        }
        Ok(SparseSet::new(out))
    }

    /// The set as a manifest stores it.
    pub fn to_strings(&self) -> Vec<String> {
        self.paths.iter().map(|p| p.as_str().to_string()).collect()
    }

    /// The paths given (normalised), without the implicit `.veilpolicy`.
    pub fn paths(&self) -> &[VPath] {
        &self.paths
    }

    /// Is `p` in the set: one of its paths, below one, or `.veilpolicy`?
    pub fn contains(&self, p: &VPath) -> bool {
        p.as_str() == POLICY_FILE || self.paths.iter().any(|q| p.starts_with(q))
    }

    /// Is `p` a directory on the way to a path of the set (a strict
    /// ancestor of one)? The root always is.
    pub fn is_spine(&self, p: &VPath) -> bool {
        p.is_root() || self.paths.iter().any(|q| q.starts_with(p) && q != p)
    }

    /// Is `p` neither in the set nor on the way to it?
    pub fn is_outside(&self, p: &VPath) -> bool {
        !self.contains(p) && !self.is_spine(p)
    }
}

/// `tree` restricted to `set`: the entries in the set, and the directories
/// leading to them (with nothing else). Entries are copied as they are
/// (sealed secrets, conflicts). New tree objects are written to
/// the store, as any build does.
pub fn restrict(store: &ObjectStore, tree: &ObjectId, set: &SparseSet) -> Result<ObjectId> {
    match restrict_dir(store, &VPath::root(), tree, set)? {
        Some(id) => Ok(id),
        None => store.empty_tree(),
    }
}

fn restrict_dir(store: &ObjectStore, dir: &VPath, id: &ObjectId, set: &SparseSet) -> Result<Option<ObjectId>> {
    let t = store.tree(id)?;
    let mut out = Tree::default();
    for e in &t.entries {
        let p = dir.join(&e.name);
        if set.contains(&p) {
            out.insert(e.clone());
        } else if e.kind == EntryKind::Dir && set.is_spine(&p) {
            if let Some(sub) = restrict_dir(store, &p, &e.id, set)? {
                out.insert(TreeEntry::dir(&e.name, sub));
            }
        }
    }
    if out.is_empty() && !dir.is_root() {
        return Ok(None);
    }
    if *t == out {
        return Ok(Some(*id));
    }
    Ok(Some(store.put_tree(&out)?))
}

/// A sparse working copy `inner` (holding the paths of `set`) seen as the
/// whole of `tree`, the tree it was synced from: see the module
/// documentation. Read-only outside the set.
#[derive(Debug)]
pub struct SparseView<'a> {
    inner: &'a dyn StorageBackend,
    set: &'a SparseSet,
    store: Arc<ObjectStore>,
    tree: TreeView,
}

impl<'a> SparseView<'a> {
    pub fn new(inner: &'a dyn StorageBackend, store: Arc<ObjectStore>, tree: ObjectId, set: &'a SparseSet) -> SparseView<'a> {
        SparseView {
            inner,
            set,
            tree: TreeView::new(store.clone(), tree),
            store,
        }
    }

    /// The listing of a spine directory: what of the sandbox's leads into
    /// the set, what of the tree's does not. `None` if neither has it.
    fn spine_listing(&self, dir: &VPath) -> Result<Option<DirListing>> {
        let mut out = DirListing::default();
        let mut found = false;
        // A file where a spine directory was: the sandbox has nothing of
        // the set there (and the file itself is outside it).
        let is_dir = dir.is_root() || self.inner.metadata(dir)?.is_some_and(|m| m.kind == NodeKind::Dir);
        let listing = match is_dir {
            true => self.inner.list_dir_full(dir),
            false => Err(VeilError::NotFound(dir.to_string())),
        };
        match listing {
            Ok(l) => {
                found = true;
                let leads_in = |name: &str| {
                    let p = dir.join(name);
                    self.set.contains(&p) || self.set.is_spine(&p)
                };
                out.entries.extend(l.entries.into_iter().filter(|e| {
                    let p = dir.join(&e.name);
                    // A file where the set needs a directory leads nowhere.
                    self.set.contains(&p) || (e.kind == NodeKind::Dir && self.set.is_spine(&p))
                }));
                out.special.extend(l.special.into_iter().filter(|n| leads_in(n)));
            }
            Err(e) if e.is_not_found() => {}
            Err(e) => return Err(e),
        }
        if let Some(e) = crate::tree::lookup(&self.store, &self.tree.root(), dir)?.filter(|e| e.kind == EntryKind::Dir) {
            found = true;
            for c in &self.store.tree(&e.id)?.entries {
                let p = dir.join(&c.name);
                // A spine directory of the tree that the sandbox no longer
                // has (the command removed it, or put a file there): it
                // still holds files outside the set, which are the tree's.
                // Its own listing keeps those and drops the set's paths, so
                // deletions only count inside the set, file by file
                // (BUG-552).
                if c.kind == EntryKind::Dir
                    && self.set.is_spine(&p)
                    && !out.entries.iter().any(|x| x.name == c.name && x.kind == NodeKind::Dir)
                {
                    out.entries.retain(|x| x.name != c.name);
                    out.special.retain(|n| *n != c.name);
                    out.entries.push(DirEntry {
                        name: c.name.clone(),
                        kind: NodeKind::Dir,
                    });
                    continue;
                }
                if !self.set.is_outside(&p) || !self.store.entry_shown(&self.tree.shown(c.clone())) {
                    continue;
                }
                out.entries.push(DirEntry {
                    name: c.name.clone(),
                    kind: self.tree.node_kind(c),
                });
            }
        }
        if !found {
            return Ok(None);
        }
        out.entries.sort_by(|a, b| a.name.cmp(&b.name));
        out.special.sort();
        Ok(Some(out))
    }

    fn outside_write(&self, path: &VPath) -> VeilError {
        VeilError::InvalidPath(format!("{path} is outside the sparse working copy"))
    }

    fn writable(&self, path: &VPath) -> Result<()> {
        if self.set.contains(path) {
            Ok(())
        } else {
            Err(self.outside_write(path))
        }
    }
}

impl StorageBackend for SparseView<'_> {
    fn kind(&self) -> &'static str {
        self.inner.kind()
    }

    fn read(&self, path: &VPath) -> Result<Vec<u8>> {
        if self.set.contains(path) {
            self.inner.read(path)
        } else if self.set.is_spine(path) {
            Err(VeilError::InvalidPath(format!("{path} is a directory")))
        } else {
            self.tree.read(path)
        }
    }

    fn read_link(&self, path: &VPath) -> Result<Vec<u8>> {
        if self.set.contains(path) {
            self.inner.read_link(path)
        } else if self.set.is_spine(path) {
            Err(VeilError::InvalidPath(format!("{path} is a directory")))
        } else {
            self.tree.read_link(path)
        }
    }

    fn write_link(&self, path: &VPath, target: &[u8]) -> Result<()> {
        self.writable(path)?;
        self.inner.write_link(path, target)
    }

    fn supports_links(&self) -> bool {
        self.inner.supports_links()
    }

    fn read_through_link(&self, path: &VPath, limit: u64) -> Result<Option<(String, Vec<u8>)>> {
        if self.set.contains(path) {
            self.inner.read_through_link(path, limit)
        } else {
            Ok(None)
        }
    }

    fn read_range(&self, path: &VPath, offset: u64, len: usize) -> Result<Vec<u8>> {
        if self.set.contains(path) {
            self.inner.read_range(path, offset, len)
        } else {
            let data = self.read(path)?;
            super::slice_range(path, &data, offset, len).map(<[u8]>::to_vec)
        }
    }

    fn write(&self, path: &VPath, data: &[u8]) -> Result<()> {
        self.writable(path)?;
        self.inner.write(path, data)
    }

    fn write_secret(&self, path: &VPath, data: &[u8], executable: bool) -> Result<()> {
        self.writable(path)?;
        self.inner.write_secret(path, data, executable)
    }

    fn write_unsynced(&self, path: &VPath, data: &[u8]) -> Result<()> {
        self.writable(path)?;
        self.inner.write_unsynced(path, data)
    }

    fn write_secret_unsynced(&self, path: &VPath, data: &[u8], executable: bool) -> Result<()> {
        self.writable(path)?;
        self.inner.write_secret_unsynced(path, data, executable)
    }

    fn write_staged(&self, path: &VPath, data: &[u8]) -> Result<VPath> {
        self.writable(path)?;
        self.inner.write_staged(path, data)
    }

    fn write_secret_staged(&self, path: &VPath, data: &[u8], executable: bool) -> Result<VPath> {
        self.writable(path)?;
        self.inner.write_secret_staged(path, data, executable)
    }

    fn rename_unsynced(&self, from: &VPath, to: &VPath) -> Result<()> {
        self.writable(to)?;
        self.inner.rename_unsynced(from, to)
    }

    fn sync_barrier(&self) -> Result<()> {
        self.inner.sync_barrier()
    }

    fn create_new(&self, path: &VPath, data: &[u8]) -> Result<bool> {
        self.writable(path)?;
        self.inner.create_new(path, data)
    }

    fn create_new_secret(&self, path: &VPath, data: &[u8]) -> Result<bool> {
        self.writable(path)?;
        self.inner.create_new_secret(path, data)
    }

    fn remove_file(&self, path: &VPath) -> Result<()> {
        self.writable(path)?;
        self.inner.remove_file(path)
    }

    fn remove_dir_all(&self, path: &VPath) -> Result<()> {
        self.writable(path)?;
        self.inner.remove_dir_all(path)
    }

    fn create_dir_all(&self, path: &VPath) -> Result<()> {
        if self.set.is_spine(path) {
            return self.inner.create_dir_all(path);
        }
        self.writable(path)?;
        self.inner.create_dir_all(path)
    }

    fn list_dir(&self, path: &VPath) -> Result<Vec<DirEntry>> {
        Ok(self.list_dir_full(path)?.entries)
    }

    fn list_dir_full(&self, path: &VPath) -> Result<DirListing> {
        if self.set.contains(path) {
            self.inner.list_dir_full(path)
        } else if self.set.is_spine(path) {
            self.spine_listing(path)?.ok_or_else(|| VeilError::NotFound(path.to_string()))
        } else {
            self.tree.list_dir_full(path)
        }
    }

    fn metadata(&self, path: &VPath) -> Result<Option<Metadata>> {
        if self.set.contains(path) {
            self.inner.metadata(path)
        } else if self.set.is_spine(path) {
            Ok(self
                .spine_listing(path)?
                .map(|_| Metadata::unstamped(NodeKind::Dir, 0, false)))
        } else {
            self.tree.metadata(path)
        }
    }

    fn set_executable(&self, path: &VPath, executable: bool) -> Result<()> {
        self.writable(path)?;
        self.inner.set_executable(path, executable)
    }

    /// Outside the set: the tree's entry, so the builder reuses it as it
    /// is. `.veilpolicy`: its blob id, so that an unchanged public policy
    /// lets the builder use these hints at all. Nothing else in the set
    /// is vouched for (the command may have changed it).
    fn known_id(&self, path: &VPath) -> Option<ObjectId> {
        if path.as_str() == POLICY_FILE {
            return self.inner.read(path).ok().map(|d| Object::blob_id(&d));
        }
        if self.set.contains(path) || self.set.is_spine(path) {
            return None;
        }
        self.tree.known_id(path)
    }

    fn stat_clock(&self) -> Option<StatClock> {
        self.inner.stat_clock()
    }

    fn name_folding(&self) -> NameFolding {
        self.inner.name_folding()
    }

    fn special_at(&self, path: &VPath) -> Result<Option<&'static str>> {
        if self.set.contains(path) {
            self.inner.special_at(path)
        } else {
            Ok(None)
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> VPath {
        VPath::new(s).unwrap()
    }

    #[test]
    fn sets_are_normalised() {
        assert_eq!(SparseSet::new([p(""), p("a")]), None, "the root is the whole tree");
        assert_eq!(SparseSet::new(Vec::<VPath>::new()), None);
        let s = SparseSet::new([p("src/a.rs"), p("tests"), p("src"), p("tests/x"), p("src")]).unwrap();
        assert_eq!(s.to_strings(), ["src", "tests"]);
        assert!(s.contains(&p("src/a/b")) && s.contains(&p(".veilpolicy")) && !s.contains(&p("srcx")));
        assert!(s.is_spine(&p("")) && !s.is_spine(&p("src")) && s.is_outside(&p("docs")));
        let f = SparseSet::new([p("a/b/c.txt")]).unwrap();
        assert!(f.is_spine(&p("a")) && f.is_spine(&p("a/b")) && f.is_outside(&p("a/c")) && !f.is_spine(&p("a/b/c.txt")));
        assert_eq!(SparseSet::from_strings(&["src".into()]).unwrap(), Some(SparseSet::new([p("src")]).unwrap()));
        assert!(SparseSet::from_strings(&["../x".into()]).is_err());
        assert!(SparseSet::from_strings(&["a//b".into()]).is_err());
    }
}
