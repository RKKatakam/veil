//! Materialise tree changes onto a working-copy backend.
//!
//! Checkout never destroys local work. A file in the diff is only
//! overwritten or removed if its current content is exactly what `from`
//! says is materialised there. Anything else (above all a *quarantined*
//! edit, which the builder held back from the tree because it contains a
//! secret) is left alone and reported in [`CheckoutReport::kept_local`]. The
//! next snapshot then quarantines it again on top of the new tree.

use crate::{
    error::{Result, VeilError},
    id::ObjectId,
    object::{is_reserved_name, EntryKind, Object, TreeEntry},
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
    // Defence in depth: trees naming `.veil` are refused when decoded, but
    // checkout must never write repository metadata whatever the tree says.
    if let Some(c) = changes.iter().find(|c| c.path.components().any(is_reserved_name)) {
        return Err(VeilError::InvalidPath(format!("{:?} is inside reserved .veil", c.path.as_str())));
    }
    let policy = Policy::load(&TreeView::new(store.clone(), *to))?;

    // Removals first so file<->directory swaps work.
    for c in changes.iter().filter(|c| c.new.is_none()) {
        if is_local_only(&policy, &c.path) {
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
        let current = fs.metadata(&c.path)?;
        let local_edit = current.as_ref().is_some_and(|m| m.kind == NodeKind::File)
            && !holds(store, fs, &c.path, c.old.as_ref(), cache.as_deref())?;
        match store.read_entry(new) {
            Ok(data) => {
                if local_edit {
                    // Already what we want? Then there is nothing to protect.
                    if fs.read(&c.path)? != data {
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
    let Some(data) = fs.read_opt(path)? else {
        return Ok(false);
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
