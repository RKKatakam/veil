//! Materialise tree changes onto a working-copy backend.

use crate::{
    error::Result,
    id::ObjectId,
    policy::{Policy, Tier},
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
    let mut report = CheckoutReport::default();
    let changes = diff_trees(store, from, Some(to))?;
    let policy = Policy::load(&TreeView::new(store.clone(), *to))?;

    // Removals first so file<->directory swaps work.
    for c in changes.iter().filter(|c| c.new.is_none()) {
        if is_local_only(&policy, &c.path) {
            continue;
        }
        if fs.metadata(&c.path)?.is_some_and(|m| m.kind == NodeKind::File) {
            fs.remove_file(&c.path)?;
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
        match store.read_entry(new) {
            Ok(data) => {
                if fs.metadata(&c.path)?.is_some_and(|m| m.kind == NodeKind::Dir) {
                    fs.remove_dir_all(&c.path)?;
                }
                fs.write(&c.path, &data)?;
                fs.set_executable(&c.path, new.executable)?;
                report.written += 1;
            }
            Err(e) if e.is_unreadable() => {
                // Never leave a stale readable version where hidden content
                // now lives, or the next snapshot would "revert" it.
                if c.old.is_some() && fs.metadata(&c.path)?.is_some_and(|m| m.kind == NodeKind::File) {
                    fs.remove_file(&c.path)?;
                    report.removed += 1;
                    prune_empty_parents(fs, &c.path)?;
                }
                report.redacted.push(c.path.clone());
            }
            Err(e) => return Err(e),
        }
    }
    Ok(report)
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
