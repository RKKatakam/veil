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
//! not manage: if a directory above a path is a symlink (or a socket,
//! device…) in the working copy, the path is left alone and reported in
//! [`CheckoutReport::blocked`]. An untracked `vendor -> /shared/vendor` link
//! therefore never receives files from a pulled tree. Every write and
//! removal also resolves its path without following any symlink (see
//! `vfs::beneath`), so a directory swapped for a link while checkout runs
//! cannot redirect it either.
//!
//! In repository format 5 symlink entries are materialised as symlinks
//! ([`StorageBackend::write_link`]; the target is written as it is, never
//! resolved). A symlink at a path is replaced or removed only when it is the version
//! `from` materialised there (same target); a link checkout did not write
//! is never replaced or removed (`kept_local`, or `blocked` where a file of
//! the tree would replace it). A conflict with a symlink side is materialised
//! as its shown side, as it is ([`crate::conflict::shown_side`]): never a
//! file of markers, which would turn a link target into file content.
//!
//! Line endings follow `.veilattributes` (see [`crate::attributes`]): a
//! file whose attributes say `eol=crlf` is written with CRLF line endings
//! (the attributes of the tree checked out decide), and recorded in
//! [`Materialised`] as written so. A file is taken for the version
//! checkout wrote when it holds that version's bytes, the CRLF rendering
//! recorded for it, or bytes that the attributes of the tree it was
//! checked out from normalise to that version (so an attribute change never
//! wedges a file as a local edit, and never hides one).
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
    attributes::{lf_to_crlf, to_odb, to_worktree, Attrs, ToOdb},
    error::{Result, VeilError},
    id::ObjectId,
    object::{is_reserved_name, EntryKind, Object, TreeEntry},
    policy::{Policy, Tier},
    statcache::StatCache,
    store::ObjectStore,
    tree::{diff_trees, diff_trees_hiding, lookup, refused_tree, walk_files_hiding, TreeChange, TreeView},
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
    /// Conflicts written with a version this reader cannot read (a sealed
    /// secret), with the blob id of the rendering written.
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
    /// Files written with CRLF line endings (`eol=crlf`) for a version
    /// recorded with LF.
    pub crlf: Vec<VPath>,
}

/// What a working copy holds where it differs from its tree as this reader
/// would read that tree *now*: the record of what was materialised from
/// what. Device-local state, kept by whoever owns the working copy (the CLI
/// stores it in `.veil/local/checkout.json`).
///
/// A file that was unreadable at checkout (a secret this device holds no
/// key for yet) is absent on disk, and a conflict with such a version is
/// written with that version redacted. Once it becomes readable (a grant
/// arrives by pull), that is not the user deleting or reverting it: the
/// working copy is merely stale. [`Materialised::fill_in`] materialises the real
/// content, never over local edits, and the builder consults the record
/// ([`crate::builder::BuildOptions::materialised`]) so a path that was never
/// materialised is not recorded as deleted.
///
/// Three facts, each relative to the tree the working copy was last checked
/// out from (or snapshotted as):
///
/// * [`view`](Materialised::view): the tree actually materialised, when it
///   is another (a one-directory clone's).
/// * [`hidden`](Materialised::hidden): file entries left out (unreadable),
///   and folders left out because the server refuses them (BUG-1508), which
///   the builder carries by id.
/// * [`from_fallback`](Materialised::from_fallback): conflicts written with
///   a version this reader could not read, with the rendering written.
///
/// An empty record means "the working copy is the tree as read now", which
/// is also what a record written by an older version reads as.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "MaterialisedRaw", into = "MaterialisedRaw")]
pub struct Materialised {
    view: Option<ObjectId>,
    hidden: BTreeSet<VPath>,
    fallback: BTreeMap<VPath, ObjectId>,
    /// Files checkout wrote with CRLF line endings for their LF version
    /// (`eol=crlf`). Whatever the attributes say later, such a file still
    /// holding exactly that rendering is the version, not an edit.
    crlf: BTreeSet<VPath>,
    /// Folders left out because the server refuses them, with the tree of
    /// the version the checkout left them from (when it could read it):
    /// what it may still find of that version on disk once the folder is
    /// readable again is its own copy (BUG-1531).
    left: BTreeMap<VPath, ObjectId>,
    /// Hidden folders the checkout left out because the server refused
    /// them (BUG-1508): only these are written once readable again. Any
    /// other hidden folder (a one-directory clone's) is never fetched or
    /// written by checkout (BUG-1566).
    refused: BTreeSet<VPath>,
    /// Files below such a folder, written back once it was readable again,
    /// where the working copy held the person's own edit of the version
    /// left: kept, and a conflict for `vl status` until written over.
    kept_edits: BTreeSet<VPath>,
    /// For each kept edit, the version written back there (`None`: no
    /// file): the edit is a conflict only while `@` and its parents record
    /// exactly that (BUG-1558).
    kept_versions: BTreeMap<VPath, Option<ObjectId>>,
    /// Folders the working copy's change no longer names because its person
    /// lost access to them (the clone moved to their current view,
    /// BUG-1509): what the working copy holds there is theirs, never
    /// recorded, never touched.
    lost: BTreeSet<VPath>,
    /// Files a checkout removed a version of but had to leave on disk (a
    /// secret the policy keeps local) while they held exactly what it wrote:
    /// the plaintext id of that content, so a folder coming back writes over
    /// them without the old version's key, which its person may no longer
    /// hold, and keeps them if edited since (BUG-1509, BUG-1531).
    own: BTreeMap<VPath, ObjectId>,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    crlf: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    left: BTreeMap<String, ObjectId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    refused: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    kept_edits: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    kept_versions: BTreeMap<String, Option<ObjectId>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    lost: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    own: BTreeMap<String, ObjectId>,
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
            crlf: r.crlf.iter().map(|s| path(s)).collect::<std::result::Result<_, _>>()?,
            left: r.left.iter().map(|(s, id)| Ok((path(s)?, *id))).collect::<std::result::Result<_, String>>()?,
            refused: r.refused.iter().map(|s| path(s)).collect::<std::result::Result<_, _>>()?,
            kept_edits: r.kept_edits.iter().map(|s| path(s)).collect::<std::result::Result<_, _>>()?,
            kept_versions: r.kept_versions.iter().map(|(s, id)| Ok((path(s)?, *id))).collect::<std::result::Result<_, String>>()?,
            lost: r.lost.iter().map(|s| path(s)).collect::<std::result::Result<_, _>>()?,
            own: r.own.iter().map(|(s, id)| Ok((path(s)?, *id))).collect::<std::result::Result<_, String>>()?,
        })
    }
}

impl From<Materialised> for MaterialisedRaw {
    fn from(m: Materialised) -> Self {
        MaterialisedRaw {
            view: m.view,
            hidden: m.hidden.into_iter().map(|p| p.as_str().to_string()).collect(),
            fallback: m.fallback.into_iter().map(|(p, id)| (p.as_str().to_string(), id)).collect(),
            crlf: m.crlf.into_iter().map(|p| p.as_str().to_string()).collect(),
            left: m.left.into_iter().map(|(p, id)| (p.as_str().to_string(), id)).collect(),
            refused: m.refused.into_iter().map(|p| p.as_str().to_string()).collect(),
            kept_edits: m.kept_edits.into_iter().map(|p| p.as_str().to_string()).collect(),
            kept_versions: m.kept_versions.into_iter().map(|(p, id)| (p.as_str().to_string(), id)).collect(),
            lost: m.lost.into_iter().map(|p| p.as_str().to_string()).collect(),
            own: m.own.into_iter().map(|(p, id)| (p.as_str().to_string(), id)).collect(),
        }
    }
}

impl Materialised {
    /// A record of a working copy that shows its tree as this reader reads
    /// it, except that it never showed the files at `hidden` (a `vl ws
    /// mount` whose deleted directories held files it could not read then):
    /// those are carried by the builder, never recorded as deleted.
    pub fn hiding(hidden: impl IntoIterator<Item = VPath>) -> Materialised {
        Materialised {
            hidden: hidden.into_iter().filter(|p| !p.is_root()).collect(),
            ..Materialised::default()
        }
    }

    /// The record of a working copy that shows tree `view` (by id: its
    /// entries are never walked) and never showed the paths `hidden`: the
    /// start of a partial clone's journalled checkout
    /// ([`Repo::check_out_new`](crate::repo::Repo::check_out_new)).
    pub(crate) fn shown_as(view: ObjectId, hidden: impl IntoIterator<Item = VPath>) -> Materialised {
        Materialised {
            view: Some(view),
            ..Materialised::hiding(hidden)
        }
    }

    /// Nothing hidden, nothing from a fallback, nothing converted.
    pub fn is_empty(&self) -> bool {
        self.view.is_none() && self.hidden.is_empty() && self.fallback.is_empty() && self.crlf.is_empty() && self.left.is_empty() && self.refused.is_empty() && self.kept_edits.is_empty() && self.lost.is_empty() && self.own.is_empty()
    }

    /// Did checkout write the file at `path` with CRLF line endings for
    /// its LF version (and has not written that path since)?
    pub fn wrote_crlf(&self, path: &VPath) -> bool {
        self.crlf.contains(path)
    }

    /// The tree actually materialised, when it is not the working copy's
    /// tree (a one-directory clone's; `None` otherwise).
    pub fn view(&self) -> Option<ObjectId> {
        self.view
    }

    /// Was the file entry at `path` left out of the working copy because
    /// this reader could not read it?
    pub fn hidden(&self, path: &VPath) -> bool {
        self.hidden.contains(path)
    }

    /// Is `path`, or a folder above it, hidden by the checkout's choice (a
    /// one-directory clone's: hidden and not refused by the server)?
    pub fn left_out_by_choice(&self, path: &VPath) -> bool {
        let mut at = Some(path.clone());
        while let Some(p) = at.filter(|p| !p.is_root()) {
            if self.hidden.contains(&p) && !self.refused.contains(&p) {
                return true;
            }
            at = p.parent();
        }
        false
    }

    /// `to` with every path left out by choice
    /// ([`Materialised::left_out_by_choice`]) as in `shown` (absent where
    /// `shown` has none): only the folders on the way to them are read.
    fn with_left_out_as(&self, store: &ObjectStore, to: &ObjectId, shown: Option<&ObjectId>) -> Result<ObjectId> {
        let mut tree = *to;
        for p in self.hidden.iter().filter(|p| !self.refused.contains(*p) && !p.is_root()) {
            let was = match shown {
                Some(s) => lookup(store, s, p)?,
                None => None,
            };
            if lookup(store, &tree, p)? != was {
                tree = crate::conflict::set_entry(store, &tree, p, was)?;
            }
        }
        Ok(tree)
    }

    /// Every hidden path, in order.
    pub fn hidden_paths(&self) -> impl Iterator<Item = &VPath> {
        self.hidden.iter()
    }

    /// Is the file at `path` the checkout's own copy of version `old` (what
    /// it wrote, or what it recorded as its own when it had to leave it)?
    fn own_copy(&self, store: &ObjectStore, fs: &dyn StorageBackend, path: &VPath, old: Option<&TreeEntry>, cache: Option<&StatCache>) -> bool {
        old.is_some_and(|o| holds_version(store, fs, path, o, cache, &self.crlf))
            || self.own.get(path).is_some_and(|id| fs.read(path).is_ok_and(|d| Object::blob_id(&d) == *id))
    }

    /// Mark `paths` as folders the working copy's change no longer names
    /// because its person lost access to them (BUG-1509).
    pub fn mark_lost(&mut self, paths: impl IntoIterator<Item = (VPath, Option<ObjectId>)>) {
        for (p, was) in paths.into_iter().filter(|(p, _)| !p.is_root()) {
            if let Some(w) = was {
                self.left.entry(p.clone()).or_insert(w);
            }
            self.lost.insert(p);
        }
    }

    /// A checkout writing a folder lost before (access came back, and the
    /// clone moved to a view that names it again, BUG-1509): a file on
    /// disk there is the checkout's own copy of the version the folder was
    /// lost from where it holds exactly that (written over), and the
    /// person's edit where it does not (kept, and a conflict for `vl
    /// status`), as for a folder left out (BUG-1531).
    fn refill_lost(&mut self, store: &ObjectStore, fs: &dyn StorageBackend, changes: Vec<TreeChange>, cache: Option<&StatCache>) -> Result<Vec<TreeChange>> {
        let lost: Vec<VPath> = self.lost.iter().filter(|l| changes.iter().any(|c| c.new.is_some() && c.path.starts_with(l))).cloned().collect();
        if lost.is_empty() {
            return Ok(changes);
        }
        let mut versions: Vec<(VPath, BTreeMap<VPath, TreeEntry>)> = Vec::new();
        for l in &lost {
            let old = match self.left.remove(l) {
                Some(o) => match walk_files_hiding(store, &o) {
                    Ok((files, _)) => files.into_iter().collect(),
                    Err(err) if refused_tree(store, &err) => BTreeMap::new(),
                    Err(err) => return Err(err),
                },
                None => BTreeMap::new(),
            };
            versions.push((l.clone(), old));
        }
        let mut out = Vec::with_capacity(changes.len());
        for c in changes {
            let at = versions.iter().find(|(l, _)| c.path.starts_with(l));
            if let (Some((l, old)), Some(_), None) = (at, &c.new, &c.old) {
                if fs.metadata(&c.path)?.is_some() {
                    let rel = VPath::new(&c.path.as_str()[l.as_str().len() + 1..]).expect("a path below the folder");
                    if !self.own_copy(store, fs, &c.path, old.get(&rel), cache) {
                        self.kept_versions.insert(c.path.clone(), c.new.as_ref().map(|e| e.id));
                        self.kept_edits.insert(c.path.clone());
                        continue;
                    }
                    fs.remove_file(&c.path)?;
                }
            }
            out.push(c);
        }
        Ok(out)
    }

    /// Is `path` a folder its person lost access to (BUG-1509)?
    pub fn lost(&self, path: &VPath) -> bool {
        self.lost.contains(path)
    }

    /// Files written back below a folder readable again where the working
    /// copy kept the person's own edit of the version left (BUG-1531).
    pub fn kept_edits(&self) -> impl Iterator<Item = &VPath> {
        self.kept_edits.iter()
    }

    /// The version written back where `path`'s edit was kept: `Some(None)`
    /// for no file, `None` when not recorded (an older record).
    pub fn kept_version(&self, path: &VPath) -> Option<Option<ObjectId>> {
        self.kept_versions.get(path).copied()
    }

    /// What checkout wrote at `path` instead of the entry itself, if it did
    /// and has not written that path since:
    ///
    /// * a conflict written with a version this reader could not read: the
    ///   blob id of the rendering written;
    /// * any file below a [`view`](Materialised::view): the id of `path` in
    ///   the tree actually materialised.
    ///
    /// `None` means the file at `path` (if any) was materialised from the
    /// entry itself, or not by checkout at all. It says nothing about later
    /// local edits: compare the content with the returned id.
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

    /// Every conflict written with an unreadable version, with the id of the
    /// rendering written (files below a [`view`](Materialised::view) are not
    /// listed).
    pub fn fallback_paths(&self) -> impl Iterator<Item = (&VPath, &ObjectId)> {
        self.fallback.iter()
    }

    /// Fold in a checkout that applied `changes` and produced `report`.
    fn absorb(&mut self, fs: &dyn StorageBackend, changes: &[TreeChange], report: &CheckoutReport) -> Result<()> {
        for c in changes {
            self.hidden.remove(&c.path);
            self.kept_edits.remove(&c.path);
            self.kept_versions.remove(&c.path);
            if c.new.is_some() {
                self.own.remove(&c.path);
            }
            // A folder left out whose files are now written (BUG-1508); one
            // lost is named again only when something is written below it
            // (the move's own checkout removes what it wrote there).
            let mut up = c.path.parent();
            while let Some(d) = up.filter(|d| !d.is_root()) {
                self.hidden.remove(&d);
                self.left.remove(&d);
                self.refused.remove(&d);
                if c.new.is_some() {
                    self.lost.remove(&d);
                }
                up = d.parent();
            }
            if c.new.is_some() {
                self.lost.remove(&c.path);
            }
            self.fallback.remove(&c.path);
            self.crlf.remove(&c.path);
        }
        for p in &report.crlf {
            self.crlf.insert(p.clone());
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

    /// Materialise everything the record says is missing or redacted but
    /// that this reader can now read in `tree` (the tree the working copy
    /// was checked out from): files that were hidden, and conflicts written
    /// with a version that was unreadable.
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
            if *tree != shown {
                let changes = diff_trees(store, Some(&shown), Some(tree))?;
                let report = apply_changes(store, fs, Some(&shown), tree, &changes, cache.as_deref_mut(), Some(&self.crlf))?;
                self.absorb(fs, &changes, &report)?;
                self.view = None;
                total.merge(report);
            }
        }
        let mut changes = Vec::new();
        for p in self.hidden.clone() {
            match lookup_opt(store, tree, &p)? {
                Lookup::Unreadable => {}
                // A folder left out because the server refused it
                // (BUG-1508): written once it is readable again.
                Lookup::Entry(e) if e.kind == EntryKind::Dir && self.refused.contains(&p) => match store.tree(&e.id) {
                    Ok(_) => {
                        // What is on disk of the version the folder was left
                        // from is the checkout's own copy where it still
                        // holds that version (written over), and the
                        // person's edit where it does not (kept, and a
                        // conflict for `vl status`, BUG-1531).
                        let old: BTreeMap<VPath, TreeEntry> = match self.left.get(&p) {
                            Some(o) => walk_files_hiding(store, o)?.0.into_iter().collect(),
                            None => BTreeMap::new(),
                        };
                        let at = |rel: &VPath| VPath::new(&format!("{p}/{rel}")).expect("a path below a tree's path");
                        // The checkout's own copy: the bytes it wrote of the
                        // version left (whatever the policy keeps local, a
                        // copy of a version is not the person's file).
                        let mut kept: Vec<(VPath, Option<ObjectId>)> = Vec::new();
                        let ours = |path: &VPath, rel: &VPath| self.own_copy(store, fs, path, old.get(rel), cache.as_deref());
                        let mut seen = BTreeSet::new();
                        for (rel, f) in walk_files_hiding(store, &e.id)?.0 {
                            let path = at(&rel);
                            seen.insert(rel.clone());
                            if fs.metadata(&path)?.is_some() {
                                if !ours(&path, &rel) {
                                    kept.push((path, Some(f.id)));
                                    continue;
                                }
                                fs.remove_file(&path)?;
                            }
                            changes.push(TreeChange { path, old: None, new: Some(f) });
                        }
                        for (rel, _) in old.iter().filter(|(rel, _)| !seen.contains(*rel)) {
                            let path = at(rel);
                            if fs.metadata(&path)?.is_some() {
                                match ours(&path, rel) {
                                    true => fs.remove_file(&path)?,
                                    false => kept.push((path, None)),
                                }
                            }
                        }
                        for (k, v) in kept {
                            self.kept_versions.insert(k.clone(), v);
                            self.kept_edits.insert(k);
                        }
                        self.left.remove(&p);
                        self.refused.remove(&p);
                        self.hidden.remove(&p);
                    }
                    Err(err) if refused_tree(store, &err) => {}
                    Err(err) => return Err(err),
                },
                // Any other folder left out (a one-directory clone's) stays
                // left out, readable or not: never fetched, written or
                // recorded (BUG-1566). A thin clone can read every folder,
                // and dropping it here made the next snapshot take its files
                // for deletions (BUG-1945).
                Lookup::Entry(e) if e.kind == EntryKind::Dir => {}
                Lookup::Entry(e) if e.kind.holds_blob() || e.kind == EntryKind::Conflict => {
                    if store.entry_readable(&e) && (e.kind != EntryKind::Conflict || Form::of(store, &e).entry().is_some_and(|f| f.kind != EntryKind::File && store.entry_readable(f))) {
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
                _ => {
                    self.fallback.remove(&p);
                }
            }
        }
        if !changes.is_empty() {
            let report = apply_changes(store, fs, Some(tree), tree, &changes, cache, Some(&self.crlf))?;
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

/// [`checkout_cached`] that keeps `record` (what `fs` was materialised from
/// relative to `from`, see [`Materialised`]) up to date: the diff starts
/// from what is really on disk, and afterwards the record describes `fs`
/// relative to `to`. Then
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
    // Nothing at or below a path a one-directory clone left out is read or
    // written, readable or not (BUG-1566): the changes are those to `to`
    // with each such path as the working copy shows it (a thin clone can
    // read every folder, and has not fetched those, BUG-1945).
    let target = record.with_left_out_as(store, to, shown.as_ref())?;
    let (changes, left_out) = checkout_changes(store, shown.as_ref(), &target)?;
    let changes: Vec<TreeChange> = changes.into_iter().filter(|c| !record.left_out_by_choice(&c.path)).collect();
    let changes = record.refill_lost(store, fs, changes, cache.as_deref())?;
    let mut report = apply_changes(store, fs, shown.as_ref(), to, &changes, cache.as_deref_mut(), Some(&record.crlf))?;
    // A version's file the checkout had to leave on disk though it held
    // exactly what it wrote: remembered as its own (see `Materialised::own`).
    for c in changes.iter().filter(|c| c.new.is_none()) {
        if let Some(o) = &c.old {
            if fs.metadata(&c.path)?.is_some() && holds_version(store, fs, &c.path, o, cache.as_deref(), &record.crlf) {
                if let Ok(d) = fs.read(&c.path) {
                    record.own.insert(c.path.clone(), Object::blob_id(&d));
                }
            }
        }
    }
    report.redacted.extend(left_out.iter().map(|(p, _)| p.clone()));
    record.absorb(fs, &changes, &report)?;
    // The version each folder was left from, for when it is readable again
    // (BUG-1531); one left before keeps the version it was left from.
    for (p, old) in left_out {
        // Named by the tree again (an undo of a move, BUG-1509): not lost.
        record.lost.remove(&p);
        record.refused.insert(p.clone());
        if let Some(old) = old {
            record.left.entry(p).or_insert(old);
        }
    }
    record.view = None;
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
    // A folder the server refuses stays as it is: the caller refused a
    // restore that asks for it (BUG-1529).
    let mut changes: Vec<TreeChange> = diff_trees_hiding(store, Some(from), Some(to))?
        .0
        .into_iter()
        .filter(|c| wanted(&c.path))
        .collect();
    // A kept edit asked for (BUG-1558): its conflict's advice is that a
    // restore takes the recorded version, also while `@` still records
    // that version (the edit not yet recorded): written over the edit.
    let asked: Vec<VPath> = record.kept_edits.iter().filter(|k| wanted(k) && !changes.iter().any(|c| c.path == **k)).cloned().collect();
    for k in asked {
        if let Some(e) = lookup(store, to, &k)?.filter(|e| e.kind.is_file_like()) {
            if fs.metadata(&k)?.is_some() {
                fs.remove_file(&k)?;
            }
            changes.push(TreeChange { path: k, old: None, new: Some(e) });
        }
    }
    let report = apply_changes(store, fs, Some(from), to, &changes, cache, Some(&record.crlf))?;
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
        self.crlf.extend(o.crlf);
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
    Ok(SpecialGuard::new(fs).blocks(path)? || fs.metadata(path)?.is_some_and(|m| m.kind == NodeKind::Symlink))
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

    /// Is `path` a special entry (a socket, device…), or is any of its
    /// ancestors one, or a symlink? A symlink at `path` itself is the
    /// caller's to judge (it may be the version checkout wrote). Only the
    /// topmost component that is not a real directory needs checking:
    /// below a missing directory nothing can exist yet.
    fn blocks(&mut self, path: &VPath) -> Result<bool> {
        for p in path.ancestors().into_iter().chain(std::iter::once(path.clone())) {
            if self.real_dirs.contains(&p) {
                continue;
            }
            match self.fs.metadata(&p)? {
                Some(m) if m.kind == NodeKind::Dir => {
                    self.real_dirs.insert(p);
                }
                Some(m) if m.kind == NodeKind::Symlink => return Ok(&p != path),
                Some(_) => return Ok(false),
                None => return self.is_special(&p),
            }
        }
        Ok(false)
    }

    /// Checkout replaced the node at `path` (a directory by a link or the
    /// reverse): forget what was learnt about it and below it.
    fn forget(&mut self, path: &VPath) {
        let prefix = path.child_prefix();
        self.real_dirs.retain(|d| d != path && !d.as_str().starts_with(&prefix));
    }
}

/// What checkout materialises for an entry: a file (or a conflict's file
/// of markers), a symlink, or nothing (a hostile
/// conflict with no side).
#[derive(Clone, Debug)]
enum Form {
    /// A file entry, or a conflict rendered as a file.
    File(TreeEntry),
    Symlink(TreeEntry),
    Nothing,
}

impl Form {
    /// The form of `e`: a conflict with a symlink side is its
    /// shown side, as it is ([`crate::conflict::shown_side`]).
    fn of(store: &ObjectStore, e: &TreeEntry) -> Form {
        let e = match e.kind {
            EntryKind::Conflict => match store.conflict(&e.id) {
                Ok(c) if c.has_special_terms() => match crate::conflict::shown_side(&c) {
                    Some((_, t)) => t.entry(&e.name),
                    None => return Form::Nothing,
                },
                _ => return Form::File(e.clone()),
            },
            _ => e.clone(),
        };
        match e.kind {
            EntryKind::Symlink => Form::Symlink(e),
            _ => Form::File(e),
        }
    }

    fn entry(&self) -> Option<&TreeEntry> {
        match self {
            Form::File(e) | Form::Symlink(e) => Some(e),
            Form::Nothing => None,
        }
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
    let (changes, left_out) = checkout_changes(store, from, to)?;
    let mut report = apply_changes(store, fs, from, to, &changes, cache, None)?;
    report.redacted.extend(left_out.into_iter().map(|(p, _)| p));
    Ok(report)
}

/// The changes a checkout from `from` to `to` applies, and the folders it
/// leaves out: in a thin clone, a folder whose tree the server refuses
/// (its person lost access to it, BUG-1508) is never read. What checkout
/// wrote there from `from` is removed (never a readable old version where
/// hidden content now lives) and the folder is reported, and recorded, as
/// left out, so the builder carries it by id; a folder readable again is
/// written whole.
/// Does the file at `path` hold exactly what checkout wrote for version
/// `e` (its own copy, never the person's file)? As [`holds`] decides it:
/// a sealed version is recognised by what the stat cache recorded there,
/// without its key (which the person may no longer hold).
fn holds_version(store: &ObjectStore, fs: &dyn StorageBackend, path: &VPath, e: &TreeEntry, cache: Option<&StatCache>, crlf: &BTreeSet<VPath>) -> bool {
    holds(store, fs, path, Some(e), cache, &Eol { from: None, crlf: Some(crlf) }).unwrap_or(false)
}

/// The changes a checkout applies, and each folder it leaves out with the
/// tree of the version it was left from (when readable).
type CheckoutChanges = (Vec<TreeChange>, Vec<(VPath, Option<ObjectId>)>);

fn checkout_changes(store: &ObjectStore, from: Option<&ObjectId>, to: &ObjectId) -> Result<CheckoutChanges> {
    let (mut changes, hidden) = diff_trees_hiding(store, from, Some(to))?;
    let mut left_out = Vec::new();
    let readable = |e: &Option<TreeEntry>| -> Result<Option<ObjectId>> {
        match e {
            Some(e) => match store.tree(&e.id) {
                Ok(_) => Ok(Some(e.id)),
                Err(err) if refused_tree(store, &err) => Ok(None),
                Err(err) => Err(err),
            },
            None => Ok(None),
        }
    };
    let under = |dir: &VPath, rel: &VPath| if dir.is_root() { rel.clone() } else { VPath::new(&format!("{dir}/{rel}")).expect("a path below a tree's path") };
    for h in hidden {
        // The root of `to` refused: not a folder to leave out (BUG-1574:
        // the record cannot name the root, and a working copy of nothing
        // is no checkout of this tree). The whole tree is of a view its
        // person no longer has: the reader's own refusal, which the
        // clone's move to their current view answers (BUG-1573).
        if h.path.is_root() {
            if let Some(e) = &h.new {
                store.tree(&e.id)?;
            }
        }
        match (readable(&h.old)?, readable(&h.new)?) {
            (_, Some(new)) => {
                for (rel, e) in walk_files_hiding(store, &new)?.0 {
                    changes.push(TreeChange { path: under(&h.path, &rel), old: None, new: Some(e) });
                }
            }
            (old, None) => {
                if let Some(old) = old {
                    for (rel, e) in walk_files_hiding(store, &old)?.0 {
                        changes.push(TreeChange { path: under(&h.path, &rel), old: Some(e), new: None });
                    }
                }
                if h.new.is_some() {
                    left_out.push((h.path, old));
                }
            }
        }
    }
    Ok((changes, left_out))
}

/// What [`holds`] needs to recognise a file checkout wrote with converted
/// line endings: the attributes of the tree `fs` was checked out from, and
/// the files the materialisation record says were written with CRLF.
struct Eol<'s> {
    from: Option<Attrs<'s>>,
    crlf: Option<&'s BTreeSet<VPath>>,
}

impl Eol<'_> {
    /// Does working-copy content `data` at `path` stand for recorded
    /// content `want` (exactly, as the CRLF rendering checkout wrote, or as
    /// what the `from` attributes normalise it to)?
    fn stands_for(&self, path: &VPath, data: &[u8], want: &[u8]) -> bool {
        if data == want {
            return true;
        }
        if memchr::memchr(b'\r', data).is_none() {
            return false;
        }
        if self.crlf.is_some_and(|c| c.contains(path)) && lf_to_crlf(want) == data {
            return true;
        }
        match &self.from {
            Some(a) => matches!(
                to_odb(data, a.for_path(path).conversion, || memchr::memchr(b'\r', want).is_some()),
                ToOdb::Converted(v) if v == want
            ),
            None => false,
        }
    }
}

/// Apply `changes` (from tree `from` towards tree `to`, whose policy
/// decides what is local-only and whose attributes decide line endings) to
/// `fs`, given the files `crlf` the materialisation record says were
/// written with CRLF. Shared by [`checkout_cached`] and
/// [`Materialised::fill_in`].
fn apply_changes(
    store: &std::sync::Arc<ObjectStore>,
    fs: &dyn StorageBackend,
    from: Option<&ObjectId>,
    to: &ObjectId,
    changes: &[TreeChange],
    mut cache: Option<&mut StatCache>,
    crlf: Option<&BTreeSet<VPath>>,
) -> Result<CheckoutReport> {
    let mut report = CheckoutReport::default();
    let eol = Eol {
        from: from.map(|f| Attrs::for_tree(store, *f)),
        crlf,
    };
    let attrs = Attrs::for_tree(store, *to);
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
    // Files are staged (written beside their path, unsynced) and moved into
    // place only after one barrier; dropped on an early return, the guard
    // removes what was staged (BUG-818).
    let mut staging = Staging {
        fs,
        files: Vec::new(),
    };

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
        if let Some(NodeKind::File | NodeKind::Symlink) = fs.metadata(&c.path)?.map(|m| m.kind) {
            if !holds(store, fs, &c.path, c.old.as_ref(), cache.as_deref(), &eol)? {
                // A link checkout did not write is never removed.
                report.kept_local.push(c.path.clone());
                continue;
            }
            if let Err(e) = fs.remove_file(&c.path) {
                per_file(&mut report, &c.path, e)?;
                continue;
            }
            sync_parent_later(fs, &c.path)?;
            forget(&mut cache, &c.path);
            report.removed += 1;
        }
        prune_empty_parents(fs, &c.path)?;
    }
    let mut jobs: Vec<Job<'_>> = Vec::new();
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
        let form = Form::of(store, new);
        if matches!(form, Form::Nothing) {
            continue;
        }
        if let Form::Symlink(_) = &form {
            apply_special(store, fs, c, &form, &policy, &mut guard, &mut report, cache.as_deref_mut(), &eol)?;
            continue;
        }
        let new = form.entry().expect("a form with an entry");
        // A file where the tree has a directory (a quarantined or untracked
        // `cfg` where the tree has `cfg/settings.json`): checkout removed
        // every file `from` put there, so this one is the user's. Keep it.
        if let Some(obstacle) = guard.file_in_the_way(&c.path)? {
            report.obstructed.push((c.path.clone(), obstacle));
            continue;
        }
        let mut current = fs.metadata(&c.path)?;
        if current.as_ref().is_some_and(|m| m.kind == NodeKind::Symlink) {
            // A link where the tree has a file: replaced only when it is
            // the version checkout wrote (the write renames over the link
            // itself, never through it). A link of the user's stays.
            if !holds(store, fs, &c.path, c.old.as_ref(), cache.as_deref(), &eol)? {
                report.blocked.push(c.path.clone());
                continue;
            }
            if let Err(e) = fs.remove_file(&c.path) {
                per_file(&mut report, &c.path, e)?;
                continue;
            }
            current = None;
        }
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
            guard.forget(&c.path);
            current = None;
        }
        let local_edit = current.as_ref().is_some_and(|m| m.kind == NodeKind::File)
            && !holds(store, fs, &c.path, c.old.as_ref(), cache.as_deref(), &eol)?;
        let conversion = attrs.for_path(&c.path).conversion;
        // A copy the backend can clone (a sandbox reflinking the project
        // directory's file): nothing to read or write. Never for a file
        // whose line endings are converted on the way out.
        if !local_edit
            && !conversion.writes_crlf()
            && fs.clones()
            && store.entry_readable(new)
            && fs.clone_known(&c.path, &new.id)?
        {
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
        jobs.push(Job {
            change: c,
            entry: new.clone(),
            conversion,
            local_edit,
            had_file: current.is_some_and(|m| m.kind == NodeKind::File),
        });
    }
    // Read and stage the small files on several threads (BUG-818's
    // barrier then makes them durable at once), the large ones here, one
    // at a time as before: memory stays bounded (the 1 GB profile's
    // checkout reached 593 MiB with every file on 16 threads). Then take
    // the outcomes in order.
    let small = |j: &Job<'_>| j.entry.size <= PARALLEL_FILE_MAX;
    let small_jobs: Vec<&Job<'_>> = jobs.iter().filter(|j| small(j)).collect();
    let mut parallel = parallel_map(&small_jobs, |j| stage_one(store, fs, j)).into_iter();
    let outcomes: Vec<Staging1> = jobs
        .iter()
        .map(|j| match small(j) {
            true => parallel.next().expect("one outcome per small file"),
            false => stage_one(store, fs, j),
        })
        .collect();
    let mut fatal = None;
    for (j, outcome) in jobs.iter().zip(outcomes) {
        let path = &j.change.path;
        match outcome {
            Staging1::Staged(s) => {
                forget(&mut cache, path);
                staging.files.push(s);
            }
            Staging1::KeptLocal => report.kept_local.push(path.clone()),
            Staging1::Failed(e) => {
                forget(&mut cache, path);
                drop_previous_version(fs, path, j.change.old.is_some() && !j.local_edit)?;
                if let Err(e) = per_file(&mut report, path, e) {
                    fatal.get_or_insert(e);
                }
            }
            Staging1::Unreadable => {
                // Never leave a stale readable version where hidden content
                // now lives, or the next snapshot would "revert" it. A local
                // edit there is kept (the builder carries the hidden entry).
                if j.change.old.is_some() && j.had_file {
                    if j.local_edit {
                        report.kept_local.push(path.clone());
                    } else {
                        fs.remove_file(path)?;
                        sync_parent_later(fs, path)?;
                        forget(&mut cache, path);
                        report.removed += 1;
                        prune_empty_parents(fs, path)?;
                    }
                }
                report.redacted.push(path.clone());
            }
            Staging1::Fatal(e) => {
                fatal.get_or_insert(e);
            }
        }
    }
    // Dropped with `staging`, what was staged is removed.
    if let Some(e) = fatal {
        return Err(e);
    }
    if !changes.is_empty() {
        staging.publish(&mut report)?;

    }
    for w in attrs.warnings().into_iter().chain(eol.from.iter().flat_map(|a| a.warnings())) {
        if !report.warnings.contains(&w) {
            report.warnings.push(w);
        }
    }
    Ok(report)
}

/// A file [`apply_changes`] writes: what it decided before reading it.
struct Job<'c> {
    change: &'c TreeChange,
    entry: TreeEntry,
    conversion: crate::attributes::Conversion,
    /// The working copy holds an edit of the user's at the path.
    local_edit: bool,
    /// The path held a file before.
    had_file: bool,
}

/// What became of one [`Job`].
enum Staging1 {
    Staged(Staged),
    /// A local edit that differs from the new version: kept.
    KeptLocal,
    /// Writing it failed ([`per_file`] decides whether that is fatal).
    Failed(VeilError),
    /// This reader cannot read the new version.
    Unreadable,
    Fatal(VeilError),
}

/// Read job `j`'s content and stage it beside its path (on any thread).
fn stage_one(store: &ObjectStore, fs: &dyn StorageBackend, j: &Job<'_>) -> Staging1 {
    let c = j.change;
    let new = &j.entry;
    let (data, via_fallback) = match read_materialised(store, new) {
        Ok(r) => r,
        Err(e) if e.is_unreadable() => return Staging1::Unreadable,
        Err(e) => return Staging1::Fatal(e),
    };
    // Line endings for the working copy (`eol=crlf`), on the bytes as
    // read: a conflict's markers too.
    let (data, crlf) = match to_worktree(&data, j.conversion) {
        Some(d) => (d, true),
        None => (data, false),
    };
    // Already what we want? Then there is nothing to protect.
    if j.local_edit && fs.read(&c.path).map_or(true, |d| d != data) {
        return Staging1::KeptLocal;
    }
    let (executable, secret) = match new.kind {
        EntryKind::Conflict => match crate::conflict::inspect_entry(store, new, crate::conflict::Audience::Reader) {
            Ok(i) => (i.executable, !i.visibility.is_public()),
            Err(e) => return Staging1::Fatal(e),
        },
        _ => (new.executable, !new.visibility.is_public()),
    };
    // The mode is set on the staged copy, so the barrier makes it durable
    // with the content; decrypted secrets are created owner-only (0600/0700).
    let staged = match secret {
        true => fs.write_secret_staged(&c.path, &data, executable),
        false => fs.write_staged(&c.path, &data).and_then(|at| match fs.set_executable(&at, executable) {
            Ok(()) => Ok(at),
            Err(e) => {
                if at != c.path {
                    let _ = fs.remove_file(&at);
                }
                Err(e)
            }
        }),
    };
    match staged {
        Ok(at) => Staging1::Staged(Staged {
            at,
            path: c.path.clone(),
            replaces: c.old.is_some() && !j.local_edit,
            crlf,
            fallback: via_fallback,
        }),
        Err(e) => Staging1::Failed(e),
    }
}

/// Largest file [`apply_changes`] stages on another thread.
const PARALLEL_FILE_MAX: u64 = 256 << 10;

/// Threads [`parallel_map`] uses at most. Each one reading packed objects
/// raises peak memory (about 6 MiB each on the scale benchmark's small
/// profile, more on larger ones); 8 keep the 1 GB profile's checkout well
/// under its 512 MiB gate. A 10,000-file clone: 365 ms at 16 threads, 445
/// at 8, 525 at 4 (Git 575).
const PARALLEL_THREADS: usize = 8;

/// `f` over `items` on up to [`PARALLEL_THREADS`] threads (in order); on one thread for a
/// few items, and always without the `os` feature (WASM).
fn parallel_map<T: Sync, R: Send>(items: &[T], f: impl Fn(&T) -> R + Sync) -> Vec<R> {
    let threads = match cfg!(feature = "os") && items.len() >= 64 {
        true => std::thread::available_parallelism().map_or(1, |n| n.get()).min(PARALLEL_THREADS),
        false => 1,
    };
    if threads <= 1 {
        return items.iter().map(f).collect();
    }
    let next = std::sync::atomic::AtomicUsize::new(0);
    let mut out: Vec<(usize, R)> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..threads)
            .map(|_| {
                s.spawn(|| {
                    let mut mine = Vec::new();
                    loop {
                        // A few at a time: little contention on the counter.
                        let i = next.fetch_add(16, std::sync::atomic::Ordering::Relaxed);
                        if i >= items.len() {
                            return mine;
                        }
                        for (k, item) in items[i..(i + 16).min(items.len())].iter().enumerate() {
                            mine.push((i + k, f(item)));
                        }
                    }
                })
            })
            .collect();
        handles.into_iter().flat_map(|h| h.join().expect("a checkout thread panicked")).collect()
    });
    out.sort_unstable_by_key(|(i, _)| *i);
    out.into_iter().map(|(_, r)| r).collect()
}

/// A file checkout staged ([`StorageBackend::write_staged`]) and moves
/// into place at [`Staging::publish`].
struct Staged {
    /// Where its content is now: a temp file beside `path`, or `path`
    /// itself on a backend that writes in place.
    at: VPath,
    path: VPath,
    /// It replaces the version `from` put at `path` (not a local edit).
    replaces: bool,
    crlf: bool,
    fallback: Option<ObjectId>,
}

/// The files of one checkout waiting for the barrier (BUG-818). Writing a
/// file and making it durable one at a time took two `fsync`s per file;
/// instead every file is staged beside its path, one barrier makes them
/// all durable, they are renamed into place, and a second barrier makes
/// the names (and the checkout's removals) durable. Only then does
/// checkout return, so the caller records the new state (`checkout.json`)
/// after its files are on disk. Whenever power is lost, each path holds
/// its old version or its complete new one, never a torn file that the
/// next snapshot would record as an edit; what a crash leaves staged is
/// debris that snapshots ignore ([`crate::vfs::is_temp_name`]) and that
/// resuming the move removes ([`remove_staging_debris`]).
struct Staging<'a> {
    fs: &'a dyn StorageBackend,
    files: Vec<Staged>,
}

impl Staging<'_> {
    /// Make the staged files durable, move them into place and make that
    /// durable, reporting each in `report`. A failed barrier fails the
    /// checkout: what it covered may never reach the disk, and is never
    /// renamed into place (a temp file is removed; a file written in
    /// place is rewritten by the next checkout, which takes a file
    /// holding the target for one to replace).
    fn publish(&mut self, report: &mut CheckoutReport) -> Result<()> {
        let fs = self.fs;
        fs.sync_barrier()?;
        let renames = parallel_map(&self.files, |s| match s.at != s.path {
            true => Some(fs.rename_unsynced(&s.at, &s.path)),
            false => None,
        });
        let mut renamed = false;
        let mut fatal = None;
        for (s, r) in std::mem::take(&mut self.files).into_iter().zip(renames) {
            match r {
                Some(Err(e)) => {
                    let _ = fs.remove_file(&s.at);
                    drop_previous_version(fs, &s.path, s.replaces)?;
                    if let Err(e) = per_file(report, &s.path, e) {
                        fatal.get_or_insert(e);
                    }
                    continue;
                }
                Some(Ok(())) => renamed = true,
                None => {}
            }
            report.written += 1;
            if s.crlf {
                report.crlf.push(s.path.clone());
            }
            if let Some(fb) = s.fallback {
                report.from_fallback.push((s.path, fb));
            }
        }
        if let Some(e) = fatal {
            return Err(e);
        }
        if renamed {
            fs.sync_barrier()?;
        }
        Ok(())
    }
}

impl Drop for Staging<'_> {
    fn drop(&mut self) {
        for s in self.files.drain(..).filter(|s| s.at != s.path) {
            let _ = self.fs.remove_file(&s.at);
        }
    }
}

/// A new version of `path` could not be put in place. Never leave the
/// previous version there when it `replaces` it, or the next snapshot
/// would revert the file.
fn drop_previous_version(fs: &dyn StorageBackend, path: &VPath, replaces: bool) -> Result<()> {
    if replaces && fs.metadata(path)?.is_some_and(|m| m.kind == NodeKind::File) {
        let _ = fs.remove_file(path);
    }
    Ok(())
}

/// Make the removal of `path` durable at the checkout's barrier.
fn sync_parent_later(fs: &dyn StorageBackend, path: &VPath) -> Result<()> {
    fs.sync_dir_later(&path.parent().unwrap_or_else(VPath::root))
}

/// After a move of the working copy from tree `from` to tree `to` was
/// interrupted and has been finished: remove the temp files the
/// interrupted checkout staged ([`StorageBackend::write_staged`]) and never
/// renamed into place, in the directories of the paths it wrote. Snapshots
/// ignore them anyway; this only tidies the directory.
pub fn remove_staging_debris(store: &ObjectStore, fs: &dyn StorageBackend, from: &ObjectId, to: &ObjectId) -> Result<()> {
    let dirs: BTreeSet<VPath> = diff_trees_hiding(store, Some(from), Some(to))?
        .0
        .into_iter()
        .filter(|c| c.new.is_some())
        .map(|c| c.path.parent().unwrap_or_else(VPath::root))
        .collect();
    for dir in dirs {
        let entries = match fs.list_dir(&dir) {
            Ok(e) => e,
            Err(e) if e.is_not_found() || matches!(e, VeilError::Io { .. } | VeilError::InvalidPath(_)) => continue,
            Err(e) => return Err(e),
        };
        for e in entries.into_iter().filter(|e| e.kind == NodeKind::File && crate::vfs::is_temp_name(&e.name)) {
            fs.remove_file(&dir.join(&e.name))?;
        }
    }
    Ok(())
}

/// Materialise change `c` whose new version is a symlink (`form`,
/// format 5): see the module documentation. `None` when nothing
/// was done (reported).
#[allow(clippy::too_many_arguments)]
fn apply_special(
    store: &ObjectStore,
    fs: &dyn StorageBackend,
    c: &TreeChange,
    form: &Form,
    policy: &Policy,
    guard: &mut SpecialGuard<'_>,
    report: &mut CheckoutReport,
    mut cache: Option<&mut StatCache>,
    eol: &Eol<'_>,
) -> Result<Option<()>> {
    let path = &c.path;
    let current = fs.metadata(path)?;
    let ours = |fs: &dyn StorageBackend| holds(store, fs, path, c.old.as_ref(), None, eol);
    match form {
        Form::Symlink(e) => {
            // A link named like VCS metadata (`.git -> …`) is never written.
            if policy.classify_link(path).builtin_vcs {
                return Ok(None);
            }
            // Nor is a `.veilpolicy` link (only a hostile tree has one): the
            // policy would be read from wherever it points (threat 14).
            if path.as_str() == crate::policy::POLICY_FILE {
                report.failed.push((path.clone(), "a .veilpolicy symlink is never written; the policy must be a file".into()));
                return Ok(None);
            }
            if let Some(obstacle) = guard.file_in_the_way(path)? {
                report.obstructed.push((path.clone(), obstacle));
                return Ok(None);
            }
            let target = match read_materialised(store, e) {
                Ok((t, None)) => t,
                // Never a stand-in for a link: left out, as unreadable.
                Ok((_, Some(_))) => {
                    remove_ours(store, fs, c, current.as_ref(), report, &mut cache, eol)?;
                    report.redacted.push(path.clone());
                    return Ok(None);
                }
                Err(err) if err.is_unreadable() => {
                    // Never leave a readable old version where hidden
                    // content now lives.
                    remove_ours(store, fs, c, current.as_ref(), report, &mut cache, eol)?;
                    report.redacted.push(path.clone());
                    return Ok(None);
                }
                Err(err) => return Err(err),
            };
            // A hostile tree's target (a NUL, over PATH_MAX, not UTF-8) is
            // refused for this path only, never written.
            if let Err(err) = crate::vfs::check_link_target(&target) {
                remove_ours(store, fs, c, current.as_ref(), report, &mut cache, eol)?;
                report.failed.push((path.clone(), err.to_string()));
                return Ok(None);
            }
            if !fs.supports_links() {
                remove_ours(store, fs, c, current.as_ref(), report, &mut cache, eol)?;
                report.failed.push((
                    path.clone(),
                    format!("this working copy's storage ({}) cannot hold symlinks; the link stays recorded, untouched", fs.kind()),
                ));
                return Ok(None);
            }
            match current.as_ref().map(|m| m.kind) {
                None => {}
                Some(NodeKind::Symlink) => {
                    if fs.read_link(path).is_ok_and(|t| t == target) {
                        return Ok(Some(()));
                    }
                    if !ours(fs)? {
                        report.kept_local.push(path.clone());
                        return Ok(None);
                    }
                }
                Some(NodeKind::File) => {
                    if !ours(fs)? {
                        report.kept_local.push(path.clone());
                        return Ok(None);
                    }
                }
                Some(NodeKind::Dir) => {
                    // Everything `from` put in it was removed above.
                    if !is_empty_dir(fs, path)? {
                        report.obstructed.push((path.clone(), path.clone()));
                        return Ok(None);
                    }
                    fs.remove_dir_all(path)?;
                    guard.forget(path);
                }
            }
            if let Err(err) = fs.write_link(path, &target) {
                forget(&mut cache, path);
                // The backend will not hold this link (a sandbox refusing a
                // target that leads out of it): nothing is written, and the
                // path is recorded as never materialised (`failed`), so
                // recording the working copy carries the link instead of
                // deleting it.
                if let VeilError::Policy(why) = err {
                    if c.old.is_some() && current.as_ref().is_some_and(|m| m.kind != NodeKind::Dir) && ours(fs)? {
                        let _ = fs.remove_file(path);
                    }
                    report.failed.push((path.clone(), why));
                    return Ok(None);
                }
                if c.old.is_some() && current.as_ref().is_some_and(|m| m.kind != NodeKind::Dir) && ours(fs)? {
                    let _ = fs.remove_file(path);
                }
                per_file(report, path, err)?;
                return Ok(None);
            }
            forget(&mut cache, path);
            guard.forget(path);
            report.written += 1;
            Ok(Some(()))
        }
        Form::File(_) | Form::Nothing => Ok(None),
    }
}

/// The old version of `c`, if checkout wrote it and it is still there
/// unchanged, is removed (the new one cannot be written here): the next
/// snapshot must not take it for an edit reverting the new one.
fn remove_ours(
    store: &ObjectStore,
    fs: &dyn StorageBackend,
    c: &TreeChange,
    current: Option<&crate::vfs::Metadata>,
    report: &mut CheckoutReport,
    cache: &mut Option<&mut StatCache>,
    eol: &Eol<'_>,
) -> Result<()> {
    if c.old.is_none() || !current.is_some_and(|m| matches!(m.kind, NodeKind::File | NodeKind::Symlink)) {
        return Ok(());
    }
    if holds(store, fs, &c.path, c.old.as_ref(), cache.as_deref(), eol)? {
        fs.remove_file(&c.path)?;
        forget(cache, &c.path);
        report.removed += 1;
        prune_empty_parents(fs, &c.path)?;
    } else {
        report.kept_local.push(c.path.clone());
    }
    Ok(())
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
        // The write found a symlink on its way (a directory swapped for
        // one while checkout ran): nothing was written through it. Or the
        // path vanished under it (a concurrent removal).
        VeilError::InvalidPath(why) => {
            report.failed.push((path.clone(), why));
            Ok(())
        }
        e if e.is_not_found() => {
            report.failed.push((path.clone(), e.to_string()));
            Ok(())
        }
        e => Err(e),
    }
}

fn whole_filesystem(e: &std::io::Error) -> bool {
    use std::io::ErrorKind as K;
    matches!(e.kind(), K::StorageFull | K::ReadOnlyFilesystem | K::QuotaExceeded)
}

/// The bytes checkout writes for file entry `e`.
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
    Ok((store.read_blob(&e.id)?, None))
}

/// Does the node at `path` hold exactly what checkout materialises for
/// `entry`: a file's content, a conflict's rendering, a symlink's target
/// (`readlink`, never followed)? Line endings as `eol` allows.
fn holds(
    store: &ObjectStore,
    fs: &dyn StorageBackend,
    path: &VPath,
    entry: Option<&TreeEntry>,
    cache: Option<&StatCache>,
    eol: &Eol<'_>,
) -> Result<bool> {
    let form = entry.map(|e| Form::of(store, e));
    let entry = match &form {
        Some(Form::Symlink(e)) => {
            if !fs.metadata(path)?.is_some_and(|m| m.kind == NodeKind::Symlink) {
                return Ok(false);
            }
            let Ok(target) = fs.read_link(path) else { return Ok(false) };
            return match store.read_blob(&e.id) {
                Ok(want) => Ok(want == target),
                Err(err) if err.is_unreadable() || err.is_not_found() => Ok(false),
                Err(err) => Err(err),
            };
        }
        Some(Form::File(e)) => e,
        _ => return Ok(false),
    };
    let Some(entry) = Some(entry).filter(|e| e.kind.is_file_like()) else {
        return Ok(false);
    };
    if entry.kind == EntryKind::Conflict {
        // What checkout wrote for it: its materialisation for this reader.
        let data = match fs.read_opt(path) {
            Ok(Some(d)) => d,
            Ok(None) | Err(VeilError::Io { .. }) => return Ok(false),
            Err(e) => return Err(e),
        };
        return Ok(eol.stands_for(path, &data, &read_materialised(store, entry)?.0));
    }
    if let (Some(cache), Some(meta)) = (cache, fs.metadata(path)?) {
        if let Some(rec) = cache.trusted(path, &meta) {
            if rec.content == entry.id
                || rec.sealed.as_ref().is_some_and(|(_, id)| *id == entry.id)
                || rec.eol.as_ref().is_some_and(|f| f.recorded == Some(entry.id))
            {
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
        Ok(expected) => Ok(eol.stands_for(path, &data, &expected)),
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
        sync_parent_later(fs, &dir)?;
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
