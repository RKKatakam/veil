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
//!
//! Checkout never deletes what it did not write. A directory where the tree
//! now has a file is only removed once checkout has emptied it; a directory
//! that still holds something (isolated or ignored files, untracked files,
//! kept local edits) is left in place, and so is a file where the tree now
//! has a directory. Both are reported in [`CheckoutReport::obstructed`],
//! and the paths they stand in the way of are not written. The next snapshot
//! records the working copy as it is, so the user's layout wins, as with
//! [`CheckoutReport::kept_local`].
//!
//! Checkout never writes or removes anything inside a nested Veil
//! repository (a directory holding a `.veil` of its own): the enclosing
//! repository does not record it either (see
//! [`crate::vfs::holds_repository`]); such paths are reported in
//! [`CheckoutReport::nested`].
//!
//! On a backend that folds names (a macOS volume: `README` and `readme`, or
//! NFC and NFD spellings, are one entry) checkout refuses a tree with two
//! such names in one directory, before writing anything: materialising both
//! would make one silently overwrite the other and corrupt the working copy
//! (see [`name_collisions`]).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::{
    error::{Result, VeilError},
    id::ObjectId,
    object::{is_reserved_name, EntryKind, Object, TreeEntry, Visibility},
    policy::{Policy, Tier},
    statcache::StatCache,
    store::ObjectStore,
    tree::{diff_trees, lookup, TreeChange, TreeView, MAX_TREE_DEPTH},
    vfs::{NodeKind, StorageBackend},
    vpath::{NameFolding, VPath},
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
    /// Files written from their embargo fallback because this reader cannot
    /// read the entry itself, with the fallback's id.
    pub from_fallback: Vec<(VPath, ObjectId)>,
    /// Paths of the tree that were not written because something checkout
    /// did not write is in the way, with that obstacle: a directory that
    /// still holds files where the tree has a file (an isolated `private/`,
    /// an ignored `target/`, untracked work), or a file where the tree has a
    /// directory (a quarantined or untracked `cfg` where the tree has
    /// `cfg/settings.json`). The obstacle is left exactly as it is.
    pub obstructed: Vec<(VPath, VPath)>,
    /// Paths of the diff inside a nested Veil repository (a directory that
    /// holds a `.veil` of its own, see [`crate::vfs::holds_repository`]),
    /// with that repository's directory: never written or removed, as the
    /// enclosing repository never records them either.
    pub nested: Vec<(VPath, VPath)>,
    /// Paths the working copy's filesystem refused (a name it cannot hold,
    /// permission denied on a directory, …), with the error. The rest of
    /// the checkout went ahead; a file that could not be written is left
    /// out of the working copy and recorded as such ([`Materialised`]), so
    /// the next snapshot keeps it in history instead of recording it
    /// deleted, and the next command tries again.
    pub failed: Vec<(VPath, String)>,
    /// Problems that did not stop the checkout (the target tree's
    /// `.veilpolicy` could not be read, so the accepted policy applied).
    pub warnings: Vec<String>,
}

/// What a working copy holds where it differs from its tree as this reader
/// would read that tree *now*: the record of what was materialised from
/// what. Device-local state, kept by whoever owns the working copy (the CLI
/// stores it in `.veil/local/checkout.json`).
///
/// A file that was unreadable at checkout (no key for its scope yet, an
/// unreleased embargo) is absent on disk, or holds the embargo's fallback.
/// Once it becomes readable (a grant arrives by pull, the embargo is
/// released), that is not the user deleting or reverting it: the working
/// copy is merely stale. [`Materialised::fill_in`] materialises the real
/// content, never over local edits, and the builder consults the record
/// ([`crate::builder::BuildOptions::materialised`]) so a path that was never
/// materialised is not recorded as deleted.
///
/// Three facts, each relative to the tree the working copy was last checked
/// out from (or snapshotted as):
///
/// * [`view`](Materialised::view): the root was an embargo wrapper shown as
///   its fallback; this is the tree actually materialised.
/// * [`hidden`](Materialised::hidden): file entries left out (unreadable).
/// * [`from_fallback`](Materialised::from_fallback): files written from an
///   embargo fallback instead of the entry's own content.
///
/// An empty record means "the working copy is the tree as read now", which
/// is also what a record written by an older version reads as.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "MaterialisedRaw", into = "MaterialisedRaw")]
pub struct Materialised {
    view: Option<ObjectId>,
    hidden: BTreeSet<VPath>,
    fallback: BTreeMap<VPath, ObjectId>,
}

/// On-disk form of [`Materialised`]: paths are plain strings, validated when
/// read back (the file is outside any tree's validation).
#[derive(Serialize, Deserialize, Default)]
struct MaterialisedRaw {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    view: Option<ObjectId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    hidden: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    fallback: BTreeMap<String, ObjectId>,
}

impl TryFrom<MaterialisedRaw> for Materialised {
    type Error = String;
    fn try_from(r: MaterialisedRaw) -> std::result::Result<Self, String> {
        let path = |s: &str| match VPath::new(s) {
            Ok(p) if !p.is_root() && p.as_str() == s => Ok(p),
            _ => Err(format!("invalid path {s:?} in the materialisation record")),
        };
        Ok(Materialised {
            view: r.view,
            hidden: r.hidden.iter().map(|s| path(s)).collect::<std::result::Result<_, _>>()?,
            fallback: r
                .fallback
                .iter()
                .map(|(s, id)| Ok((path(s)?, *id)))
                .collect::<std::result::Result<_, String>>()?,
        })
    }
}

impl From<Materialised> for MaterialisedRaw {
    fn from(m: Materialised) -> Self {
        MaterialisedRaw {
            view: m.view,
            hidden: m.hidden.into_iter().map(|p| p.as_str().to_string()).collect(),
            fallback: m.fallback.into_iter().map(|(p, id)| (p.as_str().to_string(), id)).collect(),
        }
    }
}

impl Materialised {
    /// Nothing hidden, nothing from a fallback.
    pub fn is_empty(&self) -> bool {
        self.view.is_none() && self.hidden.is_empty() && self.fallback.is_empty()
    }

    /// The tree actually materialised when the working copy's tree is an
    /// embargo wrapper this reader saw as its fallback (`None` otherwise).
    pub fn view(&self) -> Option<ObjectId> {
        self.view
    }

    /// Was the file entry at `path` left out of the working copy because
    /// this reader could not read it?
    pub fn hidden(&self, path: &VPath) -> bool {
        self.hidden.contains(path)
    }

    /// Every hidden path, in order.
    pub fn hidden_paths(&self) -> impl Iterator<Item = &VPath> {
        self.hidden.iter()
    }

    /// The embargo fallback materialised at `path`, if the file there was
    /// written from one and checkout has not written that path since:
    ///
    /// * a file whose entry this reader could not read, written from the
    ///   entry's `fallback` (that id is returned);
    /// * any file below a [`view`](Materialised::view): the whole tree was
    ///   shown as the wrapper's fallback, and the id of `path` in that
    ///   fallback tree is returned.
    ///
    /// `None` means the file at `path` (if any) was materialised from the
    /// entry itself, or not by checkout at all. It says nothing about later
    /// local edits: compare the content with the returned id to tell "still
    /// the fallback I was shown" from an edit that happens to match.
    pub fn from_fallback(&self, store: &ObjectStore, path: &VPath) -> Result<Option<ObjectId>> {
        if let Some(fb) = self.fallback.get(path) {
            return Ok(Some(*fb));
        }
        let Some(shown) = self.view else { return Ok(None) };
        Ok(match lookup_opt(store, &shown, path)? {
            Lookup::Entry(e) if e.kind == EntryKind::File => Some(e.id),
            _ => None,
        })
    }

    /// Every file written from an entry's fallback, with the fallback's id
    /// (files below a [`view`](Materialised::view) are not listed).
    pub fn fallback_paths(&self) -> impl Iterator<Item = (&VPath, &ObjectId)> {
        self.fallback.iter()
    }

    /// Fold in a checkout that applied `changes` and produced `report`.
    fn absorb(&mut self, fs: &dyn StorageBackend, changes: &[TreeChange], report: &CheckoutReport) -> Result<()> {
        for c in changes {
            self.hidden.remove(&c.path);
            self.fallback.remove(&c.path);
        }
        for p in report.redacted.iter().chain(report.failed.iter().map(|(p, _)| p)) {
            // Left absent (a kept local edit is the user's file, not ours).
            if fs.metadata(p)?.is_none_or(|m| m.kind != NodeKind::File) {
                self.hidden.insert(p.clone());
            }
        }
        for (p, fb) in &report.from_fallback {
            self.fallback.insert(p.clone(), *fb);
        }
        Ok(())
    }

    /// Materialise everything the record says is missing or shown as a
    /// fallback but that this reader can now read in `tree` (the tree the
    /// working copy was checked out from): files that were hidden, files
    /// written from a fallback, and the embargoed side of a wrapper root.
    /// Local edits are never overwritten (they are reported as
    /// [`CheckoutReport::kept_local`] and dropped from the record: the file
    /// is the user's now). Cheap when nothing changed: one lookup per
    /// recorded path.
    pub fn fill_in(
        &mut self,
        store: &std::sync::Arc<ObjectStore>,
        fs: &dyn StorageBackend,
        tree: &ObjectId,
        mut cache: Option<&mut StatCache>,
    ) -> Result<CheckoutReport> {
        let mut total = CheckoutReport::default();
        if let Some(shown) = self.view {
            let (now, fell_back) = resolve_view(store, tree)?;
            if now != shown {
                let changes = diff_trees(store, Some(&shown), Some(tree))?;
                let report = apply_changes(store, fs, tree, &changes, cache.as_deref_mut())?;
                self.absorb(fs, &changes, &report)?;
                self.view = fell_back.then_some(now);
                total.merge(report);
            }
        }
        let mut changes = Vec::new();
        for p in self.hidden.clone() {
            match lookup_opt(store, tree, &p)? {
                Lookup::Unreadable => {}
                Lookup::Entry(e) if e.kind == EntryKind::File => {
                    if store.entry_readable(&e) {
                        changes.push(TreeChange {
                            path: p,
                            old: None,
                            new: Some(e),
                        });
                    }
                }
                _ => {
                    self.hidden.remove(&p);
                }
            }
        }
        for (p, fb) in self.fallback.clone() {
            match lookup_opt(store, tree, &p)? {
                Lookup::Unreadable => {}
                // A conflict written with versions this reader could not
                // read then: write it again if it reads differently now.
                Lookup::Entry(e) if e.kind == EntryKind::Conflict => {
                    let (data, _) = read_materialised(store, &e)?;
                    if Object::blob_id(&data) != fb {
                        let shown = TreeEntry {
                            kind: EntryKind::File,
                            id: fb,
                            ..e.clone()
                        };
                        changes.push(TreeChange {
                            path: p,
                            old: Some(shown),
                            new: Some(e),
                        });
                    }
                }
                Lookup::Entry(e) if e.kind == EntryKind::File && e.fallback == Some(fb) => {
                    if store.read_blob(&e.id).is_ok() {
                        let shown = TreeEntry {
                            id: fb,
                            fallback: None,
                            visibility: Visibility::Public,
                            ..e.clone()
                        };
                        changes.push(TreeChange {
                            path: p,
                            old: Some(shown),
                            new: Some(e),
                        });
                    }
                }
                _ => {
                    self.fallback.remove(&p);
                }
            }
        }
        if !changes.is_empty() {
            let report = apply_changes(store, fs, tree, &changes, cache)?;
            self.absorb(fs, &changes, &report)?;
            total.merge(report);
        }
        Ok(total)
    }
}

enum Lookup {
    Entry(TreeEntry),
    Missing,
    /// A directory on the way cannot be opened by this reader.
    Unreadable,
}

fn lookup_opt(store: &ObjectStore, tree: &ObjectId, path: &VPath) -> Result<Lookup> {
    match lookup(store, tree, path) {
        Ok(Some(e)) => Ok(Lookup::Entry(e)),
        Ok(None) => Ok(Lookup::Missing),
        Err(e) if e.is_unreadable() => Ok(Lookup::Unreadable),
        Err(e) => Err(e),
    }
}

/// The plain tree this reader sees for `id` (as [`ObjectStore::tree`]
/// resolves embargo wrappers), and whether a wrapper was shown as its
/// fallback on the way.
pub fn resolve_view(store: &ObjectStore, id: &ObjectId) -> Result<(ObjectId, bool)> {
    let mut id = *id;
    let mut fell_back = false;
    for _ in 0..MAX_TREE_DEPTH {
        let t = store.tree_object(&id)?;
        let Some(w) = crate::embargo::wrapper_parts(&t) else {
            return Ok((id, fell_back));
        };
        if store.keys.has(&w.key_label()) {
            match store.tree_object(&w.inner) {
                Ok(_) => {
                    id = w.inner;
                    continue;
                }
                Err(e) if e.is_unreadable() => {}
                Err(e) => return Err(e),
            }
        }
        id = w.fallback;
        fell_back = true;
    }
    Err(VeilError::Corrupt(id.hex(), "embargo wrappers nest too deeply".into()))
}

/// [`checkout_cached`] that keeps `record` (what `fs` was materialised from
/// relative to `from`, see [`Materialised`]) up to date: the diff starts
/// from what is really on disk (a wrapper's fallback when that is what was
/// shown), and afterwards the record describes `fs` relative to `to`. Then
/// anything recorded that has become readable is filled in.
pub fn checkout_recorded(
    store: &std::sync::Arc<ObjectStore>,
    fs: &dyn StorageBackend,
    from: Option<&ObjectId>,
    to: &ObjectId,
    record: &mut Materialised,
    mut cache: Option<&mut StatCache>,
) -> Result<CheckoutReport> {
    let shown = record.view.or(from.copied());
    let changes = diff_trees(store, shown.as_ref(), Some(to))?;
    let mut report = apply_changes(store, fs, to, &changes, cache.as_deref_mut())?;
    record.absorb(fs, &changes, &report)?;
    let (now, fell_back) = resolve_view(store, to)?;
    record.view = fell_back.then_some(now);
    report.merge(record.fill_in(store, fs, to, cache)?);
    Ok(report)
}

/// `vl restore`: bring the paths of `fs` that `wanted` selects from tree
/// `from` to tree `to`, with every rule of a checkout: removals before
/// writes, so a file and a directory can trade places in either direction;
/// nothing in the way that checkout did not write is deleted (it is
/// reported in [`CheckoutReport::obstructed`]); directories the restore
/// empties are removed; local-only, special and nested-repository paths
/// are left alone; a path the filesystem refuses is reported and the rest
/// goes ahead (BUG-201, BUG-209).
///
/// `from` must be what `fs` holds: the caller snapshots the working copy
/// first, so every edit it can record is in `from`, and is what the restore
/// discards (a file that holds anything else is kept and reported in
/// [`CheckoutReport::kept_local`]). `record` describes `fs` relative to
/// `from` on entry, and on return relative to the tree the restore leaves
/// (the caller's next snapshot).
pub fn restore_paths(
    store: &std::sync::Arc<ObjectStore>,
    fs: &dyn StorageBackend,
    from: &ObjectId,
    to: &ObjectId,
    wanted: &dyn Fn(&VPath) -> bool,
    record: &mut Materialised,
    cache: Option<&mut StatCache>,
) -> Result<CheckoutReport> {
    let changes: Vec<TreeChange> = diff_trees(store, Some(from), Some(to))?
        .into_iter()
        .filter(|c| wanted(&c.path))
        .collect();
    let report = apply_changes(store, fs, to, &changes, cache)?;
    record.absorb(fs, &changes, &report)?;
    Ok(report)
}

impl CheckoutReport {
    fn merge(&mut self, o: CheckoutReport) {
        self.written += o.written;
        self.removed += o.removed;
        self.redacted.extend(o.redacted);
        self.protected.extend(o.protected);
        self.kept_local.extend(o.kept_local);
        self.blocked.extend(o.blocked);
        self.from_fallback.extend(o.from_fallback);
        self.obstructed.extend(o.obstructed);
        self.nested.extend(o.nested);
        // `fill_in` right after a checkout retries what it could not write.
        for f in o.failed {
            if !self.failed.iter().any(|(p, _)| *p == f.0) {
                self.failed.push(f);
            }
        }
        for w in o.warnings {
            if !self.warnings.contains(&w) {
                self.warnings.push(w);
            }
        }
    }
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
    /// Directories already checked for a nested repository (checkout never
    /// creates a `.veil`, so the answer holds for the whole run).
    nested: HashMap<VPath, bool>,
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
            nested: HashMap::new(),
        }
    }

    /// The nested repository `path` lies in, if any: the outermost
    /// directory above it that holds a `.veil` of its own.
    fn nested_repository(&mut self, path: &VPath) -> Result<Option<VPath>> {
        for p in path.ancestors() {
            let n = match self.nested.get(&p) {
                Some(n) => *n,
                None => {
                    let n = crate::vfs::is_nested_repository(self.fs, &p)?;
                    self.nested.insert(p.clone(), n);
                    n
                }
            };
            if n {
                return Ok(Some(p));
            }
        }
        Ok(None)
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

    /// The nearest ancestor of `path` that is a file (or anything but a
    /// directory) in the working copy: writing `path` would need to replace
    /// it. Directories checkout creates are real ones, so the answer for a
    /// directory already seen stays valid for the whole run.
    fn file_in_the_way(&mut self, path: &VPath) -> Result<Option<VPath>> {
        for p in path.ancestors() {
            if self.real_dirs.contains(&p) {
                continue;
            }
            match self.fs.metadata(&p)? {
                Some(m) if m.kind == NodeKind::Dir => {
                    self.real_dirs.insert(p);
                }
                Some(_) => return Ok(Some(p)),
                None => return Ok(None),
            }
        }
        Ok(None)
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
    cache: Option<&mut StatCache>,
) -> Result<CheckoutReport> {
    let changes = diff_trees(store, from, Some(to))?;
    apply_changes(store, fs, to, &changes, cache)
}

/// Apply `changes` (towards tree `to`, whose policy decides what is
/// local-only) to `fs`. Shared by [`checkout_cached`] and
/// [`Materialised::fill_in`].
fn apply_changes(
    store: &std::sync::Arc<ObjectStore>,
    fs: &dyn StorageBackend,
    to: &ObjectId,
    changes: &[TreeChange],
    mut cache: Option<&mut StatCache>,
) -> Result<CheckoutReport> {
    let mut report = CheckoutReport::default();
    // Defence in depth: trees naming `.veil` are refused when decoded, but
    // checkout must never write repository metadata whatever the tree says.
    if let Some(c) = changes.iter().find(|c| c.path.components().any(is_reserved_name)) {
        return Err(VeilError::InvalidPath(format!("{:?} is inside reserved .veil", c.path.as_str())));
    }
    let folding = fs.name_folding();
    if folding.folds() {
        // Only directories on the way to something new can hold a new pair.
        let dirs: BTreeSet<VPath> = changes
            .iter()
            .filter(|c| c.new.is_some())
            .flat_map(|c| {
                let mut d = c.path.ancestors();
                d.insert(0, VPath::root());
                d
            })
            .collect();
        let found = name_collisions(store, to, folding, Some(&dirs))?;
        if !found.is_empty() {
            return Err(collision_error(&found, folding));
        }
    }
    // A hostile tree's unreadable `.veilpolicy` (BUG-121) never blocks a
    // checkout: the policy accepted in this working copy (it holds the
    // repository's `.veil/` when it is the member's own) decides what is
    // local-only instead.
    let accepted = crate::policy::load_accepted(fs).ok().flatten();
    let (policy, warning) = Policy::load_or_accepted(&TreeView::new(store.clone(), *to), accepted.as_deref())?;
    report.warnings.extend(warning);
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
        if let Some(repo) = guard.nested_repository(&c.path)? {
            report.nested.push((c.path.clone(), repo));
            continue;
        }
        if fs.metadata(&c.path)?.is_some_and(|m| m.kind == NodeKind::File) {
            if !holds(store, fs, &c.path, c.old.as_ref(), cache.as_deref())? {
                report.kept_local.push(c.path.clone());
                continue;
            }
            if let Err(e) = fs.remove_file(&c.path) {
                per_file(&mut report, &c.path, e)?;
                continue;
            }
            forget(&mut cache, &c.path);
            report.removed += 1;
        }
        prune_empty_parents(fs, &c.path)?;
    }
    for c in changes {
        let Some(new) = &c.new else { continue };
        // VCS metadata a snapshot made before it was ignored (`.git/`) is
        // never written into the working copy's own repository.
        if policy.classify(&c.path, false).builtin_vcs {
            continue;
        }
        if is_local_only(&policy, &c.path) && fs.exists(&c.path)? {
            report.protected.push(c.path.clone());
            continue;
        }
        if guard.blocks(&c.path)? {
            report.blocked.push(c.path.clone());
            continue;
        }
        if let Some(repo) = guard.nested_repository(&c.path)? {
            report.nested.push((c.path.clone(), repo));
            continue;
        }
        // A file where the tree has a directory (a quarantined or untracked
        // `cfg` where the tree has `cfg/settings.json`): checkout removed
        // every file `from` put there, so this one is the user's. Keep it.
        if let Some(obstacle) = guard.file_in_the_way(&c.path)? {
            report.obstructed.push((c.path.clone(), obstacle));
            continue;
        }
        let mut current = fs.metadata(&c.path)?;
        if current.as_ref().is_some_and(|m| m.kind == NodeKind::Dir) && new.kind.is_file_like() {
            // A directory where the tree has a file. Everything `from` put
            // in it was removed above (and the directory with it, if that
            // emptied it), so what is left is not ours: isolated or ignored
            // files, untracked work, kept edits. Never delete it.
            if !is_empty_dir(fs, &c.path)? {
                report.obstructed.push((c.path.clone(), c.path.clone()));
                continue;
            }
            fs.remove_dir_all(&c.path)?;
            current = None;
        }
        let local_edit = current.as_ref().is_some_and(|m| m.kind == NodeKind::File)
            && !holds(store, fs, &c.path, c.old.as_ref(), cache.as_deref())?;
        // A copy the backend can clone (a sandbox reflinking the project
        // directory's file): nothing to read or write.
        if !local_edit && new.fallback.is_none() && store.entry_readable(new) && fs.clone_known(&c.path, &new.id)? {
            forget(&mut cache, &c.path);
            if let Err(e) = fs.set_executable(&c.path, new.executable) {
                // Never leave the content with the wrong mode behind.
                let _ = fs.remove_file(&c.path);
                per_file(&mut report, &c.path, e)?;
                continue;
            }
            report.written += 1;
            continue;
        }
        match read_materialised(store, new) {
            Ok((data, via_fallback)) => {
                if local_edit {
                    // Already what we want? Then there is nothing to protect.
                    if fs.read(&c.path).map_or(true, |d| d != data) {
                        report.kept_local.push(c.path.clone());
                        continue;
                    }
                }
                let executable = match new.kind {
                    EntryKind::Conflict => crate::conflict::materialize_entry(store, new, crate::conflict::Audience::Reader)?.executable,
                    _ => new.executable,
                };
                if let Err(e) = fs.write(&c.path, &data).and_then(|_| fs.set_executable(&c.path, executable)) {
                    forget(&mut cache, &c.path);
                    // Never leave the previous version where the new one
                    // belongs, or the next snapshot would revert it.
                    if c.old.is_some() && !local_edit && fs.metadata(&c.path)?.is_some_and(|m| m.kind == NodeKind::File) {
                        let _ = fs.remove_file(&c.path);
                    }
                    per_file(&mut report, &c.path, e)?;
                    continue;
                }
                forget(&mut cache, &c.path);
                report.written += 1;
                if let Some(fb) = via_fallback {
                    report.from_fallback.push((c.path.clone(), fb));
                }
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

/// A write or removal of `path` failed. A filesystem that refuses this one
/// path (a name too long for it, a character it cannot hold, permission
/// denied on one directory) must not stop the checkout, or wedge every
/// later command retrying it (BUG-202): the path is reported in
/// [`CheckoutReport::failed`] and the checkout goes on. A full or
/// read-only filesystem fails every path alike: that stops it.
fn per_file(report: &mut CheckoutReport, path: &VPath, e: VeilError) -> Result<()> {
    match e {
        VeilError::Io { source, .. } if !whole_filesystem(&source) => {
            report.failed.push((path.clone(), source.to_string()));
            Ok(())
        }
        e => Err(e),
    }
}

fn whole_filesystem(e: &std::io::Error) -> bool {
    use std::io::ErrorKind as K;
    matches!(e.kind(), K::StorageFull | K::ReadOnlyFilesystem | K::QuotaExceeded)
}

/// The bytes checkout writes for file entry `e`, and the embargo fallback
/// they were read from when this reader cannot read the entry itself (as
/// [`ObjectStore::read_entry`], which falls back silently).
///
/// A conflict entry is materialised with markers for this reader
/// ([`crate::conflict::materialize`]): only here, when it is written to
/// disk. When a version could not be read, the returned id is the blob id
/// of what was written, recorded like a fallback ([`Materialised`]) so that
/// the copy is rewritten once the reader can read it, and is never taken
/// for an edit meanwhile.
fn read_materialised(store: &ObjectStore, e: &TreeEntry) -> Result<(Vec<u8>, Option<ObjectId>)> {
    if e.kind == EntryKind::Conflict {
        let m = crate::conflict::materialize_entry(store, e, crate::conflict::Audience::Reader)?;
        let shown = m.unreadable_side.then(|| Object::blob_id(&m.content));
        return Ok((m.content, shown));
    }
    match store.read_blob(&e.id) {
        Ok(d) => Ok((d, None)),
        Err(err) if err.is_unreadable() => match e.fallback {
            Some(fb) => Ok((store.read_blob(&fb)?, Some(fb))),
            None => Err(err),
        },
        Err(err) => Err(err),
    }
}

/// Does the file at `path` hold exactly the content of `entry`?
fn holds(
    store: &ObjectStore,
    fs: &dyn StorageBackend,
    path: &VPath,
    entry: Option<&TreeEntry>,
    cache: Option<&StatCache>,
) -> Result<bool> {
    let Some(entry) = entry.filter(|e| e.kind.is_file_like()) else {
        return Ok(false);
    };
    if entry.kind == EntryKind::Conflict {
        // What checkout wrote for it: its materialisation for this reader.
        let data = match fs.read_opt(path) {
            Ok(Some(d)) => d,
            Ok(None) | Err(VeilError::Io { .. }) => return Ok(false),
            Err(e) => return Err(e),
        };
        return Ok(read_materialised(store, entry)?.0 == data);
    }
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
        if dir.is_root() || !is_empty_dir(fs, &dir)? {
            break;
        }
        fs.remove_dir_all(&dir)?;
        cur = dir.parent();
    }
    Ok(())
}

/// Does the directory at `dir` hold nothing at all? Symlinks, sockets and
/// entries whose names are not UTF-8 count: `list_dir` leaves them out, and
/// removing the directory would delete them. Anything unexpected (not a
/// directory, unreadable) counts as not empty.
fn is_empty_dir(fs: &dyn StorageBackend, dir: &VPath) -> Result<bool> {
    match fs.list_dir_full(dir) {
        Ok(l) => Ok(l.entries.is_empty() && l.special.is_empty() && l.unrepresentable.is_empty()),
        Err(e) if e.is_not_found() || matches!(e, VeilError::Io { .. } | VeilError::InvalidPath(_)) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Pairs of entries of tree `root` that a backend with `folding` would
/// store as a single file or directory, looking only at the directories in
/// `dirs` (every directory of the tree when `None`). Directories this
/// reader cannot open (sealed without a key) are skipped: nothing in them
/// is materialised.
pub fn name_collisions(
    store: &ObjectStore,
    root: &ObjectId,
    folding: NameFolding,
    dirs: Option<&BTreeSet<VPath>>,
) -> Result<Vec<(VPath, VPath)>> {
    let mut out = Vec::new();
    if !folding.folds() {
        return Ok(out);
    }
    let open = |id: &ObjectId| match store.tree(id) {
        Ok(t) => Ok(Some(t)),
        Err(e) if e.is_unreadable() => Ok(None),
        Err(e) => Err(e),
    };
    let check = |dir: &VPath, tree: &crate::object::Tree, out: &mut Vec<(VPath, VPath)>| {
        let mut seen: HashMap<std::borrow::Cow<'_, str>, &str> = HashMap::new();
        for e in &tree.entries {
            if let Some(other) = seen.insert(folding.key(&e.name), &e.name) {
                out.push((dir.join(other), dir.join(&e.name)));
            }
        }
    };
    match dirs {
        Some(dirs) => {
            for dir in dirs {
                let entry = match lookup(store, root, dir) {
                    Ok(e) => e,
                    Err(e) if e.is_unreadable() => continue,
                    Err(e) => return Err(e),
                };
                if let Some(tree) = entry.filter(|e| e.kind == EntryKind::Dir).map(|e| open(&e.id)).transpose()?.flatten() {
                    check(dir, &tree, &mut out);
                }
            }
        }
        None => {
            // Explicit stack: tree depth is attacker-controlled.
            let mut stack = vec![(VPath::root(), *root)];
            while let Some((dir, id)) = stack.pop() {
                let Some(tree) = open(&id)? else { continue };
                check(&dir, &tree, &mut out);
                for e in tree.entries.iter().filter(|e| e.kind == EntryKind::Dir) {
                    stack.push((dir.join(&e.name), e.id));
                }
            }
        }
    }
    Ok(out)
}

/// The error checkout returns for [`name_collisions`].
pub fn collision_error(found: &[(VPath, VPath)], folding: NameFolding) -> VeilError {
    const SHOWN: usize = 10;
    let mut pairs: Vec<String> = found
        .iter()
        .take(SHOWN)
        .map(|(a, b)| format!("'{a}' and '{b}'"))
        .collect();
    if found.len() > SHOWN {
        pairs.push(format!("and {} more", found.len() - SHOWN));
    }
    VeilError::NameCollision(format!(
        "cannot check out this snapshot here: the working copy's filesystem is {}, so these tracked paths would be the same file: {}. \
         Nothing in the working copy was changed. Rename one of each pair (on a case-sensitive machine, e.g. Linux) and commit that",
        folding.describe(),
        pairs.join("; ")
    ))
}
