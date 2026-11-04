//! Materialise tree changes onto a working-copy backend.
//!
//! Checkout never destroys local work. A file in the diff is only
//! overwritten or removed if its current content is exactly what `from`
//! says is materialised there. Anything else (above all a *quarantined*
//! edit, which the builder held back from the tree because it contains a
//! secret) is left alone and reported in [`CheckoutReport::kept_local`]. The
//! next snapshot then quarantines it again on top of the new tree.
//!
//! Checkout also never writes *through* or *over* something the engine does
//! not manage: if a path, or any directory above it, is a symlink (or a
//! socket, device…) in the working copy, the path is left alone and
//! reported in [`CheckoutReport::blocked`]. An untracked `vendor ->
//! /shared/vendor` link therefore never receives files from a pulled tree.
//! (The builder keeps such tracked entries unchanged, so this is not
//! recorded as a deletion.)

use std::collections::{HashMap, HashSet};

use crate::{
    error::{Result, VeilError},
    id::ObjectId,
    object::{EntryKind, Object, TreeEntry},
    policy::{Policy, Tier},
    statcache::StatCache,
    store::ObjectStore,
    tree::{diff_trees, TreeView},
    vfs::{NodeKind, StorageBackend},
    vpath::VPath,
};

#[derive(Debug, Default, Clone)]
pub struct CheckoutReport {
    pub written: usize,
    pub removed: usize,
    /// Entries this reader cannot decrypt (left absent on disk).
    pub redacted: Vec<VPath>,
    /// Local-only files that were protected from being overwritten.
    pub protected: Vec<VPath>,
    /// Files whose local content is not what `from` recorded (e.g.
    /// quarantined edits): neither overwritten nor removed.
    pub kept_local: Vec<VPath>,
    /// Paths that are, or lie below, a symlink or other special file in the
    /// working copy: never written, removed or followed.
    pub blocked: Vec<VPath>,
}

/// Finds paths that are, or lie below, a special entry (symlink, socket,
/// device) of the working copy. Directory listings are memoised: checkout
/// never creates special entries, so they cannot appear during a run.
struct SpecialGuard<'a> {
    fs: &'a dyn StorageBackend,
    special: HashMap<VPath, HashSet<String>>,
    /// Directories already seen to be real directories (checkout itself only
    /// ever creates real ones).
    real_dirs: HashSet<VPath>,
}

/// Is `path`, or any directory above it, a symlink or other special entry
/// of `fs`? Anything that writes to a working copy outside [`checkout`]
/// (e.g. `vl restore`) must skip such paths.
pub fn behind_special(fs: &dyn StorageBackend, path: &VPath) -> Result<bool> {
    SpecialGuard::new(fs).blocks(path)
}

impl<'a> SpecialGuard<'a> {
    fn new(fs: &'a dyn StorageBackend) -> Self {
        SpecialGuard {
            fs,
            special: HashMap::new(),
            real_dirs: HashSet::new(),
        }
    }

    fn is_special(&mut self, path: &VPath) -> Result<bool> {
        let Some(dir) = path.parent() else { return Ok(false) };
        if !self.special.contains_key(&dir) {
            let names = match self.fs.list_dir_full(&dir) {
                Ok(l) => l.special.into_iter().collect(),
                Err(e) if e.is_not_found() || matches!(e, VeilError::InvalidPath(_)) => HashSet::new(),
                Err(e) => return Err(e),
            };
            self.special.insert(dir.clone(), names);
        }
        Ok(self.special[&dir].contains(path.file_name()))
    }

    /// Is `path` or any of its ancestors a special entry? Only the topmost
    /// component that is not a real directory needs checking: below a
    /// missing directory nothing can exist yet.
    fn blocks(&mut self, path: &VPath) -> Result<bool> {
        for p in path.ancestors().into_iter().chain(std::iter::once(path.clone())) {
            if self.real_dirs.contains(&p) {
                continue;
            }
            match self.fs.metadata(&p)? {
                Some(m) if m.kind == NodeKind::Dir => {
                    self.real_dirs.insert(p);
                }
                Some(_) => return Ok(false),
                None => return self.is_special(&p),
            }
        }
        Ok(false)
    }
}

/// Update `fs` from tree `from` (what is currently materialised, `None` for an
/// empty directory) to tree `to`. Files outside the diff — including isolated
/// and ignored files — are never touched.
pub fn checkout(
    store: &std::sync::Arc<ObjectStore>,
    fs: &dyn StorageBackend,
    from: Option<&ObjectId>,
    to: &ObjectId,
) -> Result<CheckoutReport> {
    checkout_cached(store, fs, from, to, None)
}

/// [`checkout`] that keeps `fs`'s stat cache consistent: every path that is
/// written or removed is invalidated, and trusted records are used to tell
/// whether a file still holds the content `from` recorded without reading it.
///
/// Written files are *not* added to the cache. The generic backend API
/// cannot stat the exact file it wrote, so a concurrent edit between the
/// write and a later stat would be recorded under our content. The next
/// snapshot re-reads them once instead.
pub fn checkout_cached(
    store: &std::sync::Arc<ObjectStore>,
    fs: &dyn StorageBackend,
    from: Option<&ObjectId>,
    to: &ObjectId,
    mut cache: Option<&mut StatCache>,
) -> Result<CheckoutReport> {
    let mut report = CheckoutReport::default();
    let changes = diff_trees(store, from, Some(to))?;
    let policy = Policy::load(&TreeView::new(store.clone(), *to))?;
    let mut guard = SpecialGuard::new(fs);

    // Removals first so file<->directory swaps work.
    for c in changes.iter().filter(|c| c.new.is_none()) {
        if is_local_only(&policy, &c.path) {
            continue;
        }
        if guard.blocks(&c.path)? {
            report.blocked.push(c.path.clone());
            continue;
        }
        if fs.metadata(&c.path)?.is_some_and(|m| m.kind == NodeKind::File) {
            if !holds(store, fs, &c.path, c.old.as_ref(), cache.as_deref())? {
                report.kept_local.push(c.path.clone());
                continue;
            }
            fs.remove_file(&c.path)?;
            forget(&mut cache, &c.path);
            report.removed += 1;
        }
        prune_empty_parents(fs, &c.path)?;
    }
    for c in &changes {
        let Some(new) = &c.new else { continue };
        if is_local_only(&policy, &c.path) && fs.exists(&c.path)? {
            report.protected.push(c.path.clone());
            continue;
        }
        if guard.blocks(&c.path)? {
            report.blocked.push(c.path.clone());
            continue;
        }
        let current = fs.metadata(&c.path)?;
        let local_edit = current.as_ref().is_some_and(|m| m.kind == NodeKind::File)
            && !holds(store, fs, &c.path, c.old.as_ref(), cache.as_deref())?;
        match store.read_entry(new) {
            Ok(data) => {
                if local_edit {
                    // Already what we want? Then there is nothing to protect.
                    if fs.read(&c.path).map_or(true, |d| d != data) {
                        report.kept_local.push(c.path.clone());
                        continue;
                    }
                }
                if current.is_some_and(|m| m.kind == NodeKind::Dir) {
                    fs.remove_dir_all(&c.path)?;
                }
                fs.write(&c.path, &data)?;
                fs.set_executable(&c.path, new.executable)?;
                forget(&mut cache, &c.path);
                report.written += 1;
            }
            Err(e) if e.is_unreadable() => {
                // Never leave a stale readable version where hidden content
                // now lives, or the next snapshot would "revert" it. A local
                // edit there is kept (the builder carries the hidden entry).
                if c.old.is_some() && current.is_some_and(|m| m.kind == NodeKind::File) {
                    if local_edit {
                        report.kept_local.push(c.path.clone());
                    } else {
                        fs.remove_file(&c.path)?;
                        forget(&mut cache, &c.path);
                        report.removed += 1;
                        prune_empty_parents(fs, &c.path)?;
                    }
                }
                report.redacted.push(c.path.clone());
            }
            Err(e) => return Err(e),
        }
    }
    Ok(report)
}

/// Does the file at `path` hold exactly the content of `entry`?
fn holds(
    store: &ObjectStore,
    fs: &dyn StorageBackend,
    path: &VPath,
    entry: Option<&TreeEntry>,
    cache: Option<&StatCache>,
) -> Result<bool> {
    let Some(entry) = entry.filter(|e| e.kind == EntryKind::File) else {
        return Ok(false);
    };
    if let (Some(cache), Some(meta)) = (cache, fs.metadata(path)?) {
        if let Some(rec) = cache.trusted(path, &meta) {
            if rec.content == entry.id || rec.sealed.as_ref().is_some_and(|(_, id)| *id == entry.id) {
                return Ok(true);
            }
        }
    }
    // A file we cannot read is not one we may overwrite.
    let data = match fs.read_opt(path) {
        Ok(Some(d)) => d,
        Ok(None) | Err(VeilError::Io { .. }) => return Ok(false),
        Err(e) => return Err(e),
    };
    if entry.visibility.is_public() && Object::blob_id(&data) == entry.id {
        return Ok(true);
    }
    match store.read_entry(entry) {
        Ok(expected) => Ok(expected == data),
        Err(e) if e.is_unreadable() => Ok(false),
        Err(e) => Err(e),
    }
}

fn forget(cache: &mut Option<&mut StatCache>, path: &VPath) {
    if let Some(c) = cache.as_deref_mut() {
        c.invalidate(path);
    }
}

fn is_local_only(policy: &Policy, path: &VPath) -> bool {
    matches!(policy.classify(path, false).tier, Tier::Isolated | Tier::Ignored)
}

fn prune_empty_parents(fs: &dyn StorageBackend, path: &VPath) -> Result<()> {
    let mut cur = path.parent();
    while let Some(dir) = cur {
        if dir.is_root() {
            break;
        }
        match fs.list_dir(&dir) {
            Ok(children) if children.is_empty() => fs.remove_dir_all(&dir)?,
            _ => break,
        }
        cur = dir.parent();
    }
    Ok(())
}
