//! What Git may see: the *public projection* of a Veil tree, and its
//! conversion to Git objects.
//!
//! The projection is exactly what a clone of a **public** Veil remote can
//! materialise (`remote::Transfer` with `public: true`, read through
//! `ObjectStore::tree`), decided by how each object is sealed, never by the
//! keys this replica happens to hold:
//!
//! * plaintext objects are visible;
//! * objects sealed under a scope (cloaked), or under `local`, are not: their
//!   entries are left out, and a directory left empty disappears;
//! * objects sealed under an embargo are visible only once it is released;
//! * an embargo wrapper resolves to its sealed side once released, else to
//!   its fallback (the pre-merge tree); a file whose content is hidden
//!   shows its fallback if it has one (an embargoed file its pre-merge
//!   version, a public file edited on a cloaked line its last public
//!   version), so "now sealed" never reads as "deleted".
//!
//! Isolated files never reach this point: they are not in the graph at all.

use std::collections::BTreeSet;

use super::{map::GitOid, GitBridge};
use crate::{
    embargo::wrapper_parts,
    error::{Result, VeilError},
    id::ObjectId,
    keychain::{Keychain, LOCAL_SCOPE},
    object::{EntryKind, Object, Text, Tree, TreeEntry, Visibility},
    store::ObjectStore,
    tree::MAX_TREE_DEPTH,
};

/// Embargoes to treat as unreleased on top of the keychain's own state:
/// what Git saw of a snapshot *before* a release (an exported commit
/// pinned while the embargo held, or a Git commit made on such a view).
/// The default veils nothing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Veil {
    /// Every embargo (used to find which ones a projection depends on).
    pub all: bool,
    pub set: BTreeSet<String>,
}

impl Veil {
    pub fn of(set: BTreeSet<String>) -> Veil {
        Veil { all: false, set }
    }

    pub fn all() -> Veil {
        Veil {
            all: true,
            set: BTreeSet::new(),
        }
    }

    pub fn is_none(&self) -> bool {
        !self.all && self.set.is_empty()
    }

    /// Is embargo `e` released, as seen through this veil?
    pub fn released(&self, keys: &Keychain, e: &str) -> bool {
        !self.all && !self.set.contains(e) && keys.embargo_released(e)
    }
}

/// The public-remote rule for a sealed object's envelope label (mirrors
/// `remote::Transfer::allowed` for `public: true`), through `veil`.
pub(crate) fn label_is_public(keys: &Keychain, veil: &Veil, label: &str) -> bool {
    if label == LOCAL_SCOPE {
        return false;
    }
    match label.strip_prefix("embargo/") {
        Some(id) => veil.released(keys, id),
        None => false,
    }
}

/// An object as a public reader gets it.
// Transient values, like `Object` itself (see there).
#[allow(clippy::large_enum_variant)]
pub(crate) enum Public {
    /// Readable; `sealed` if it had to be opened (released embargo).
    Visible { obj: Object, sealed: bool },
    /// Exists but is withheld; names the embargo if an unreleased one.
    Hidden(Option<String>),
    /// Not in this replica.
    Missing,
}

/// Open `id` the way a public reader can: sealed layers are peeled only if
/// every label is public. Keys this replica holds for cloak scopes are
/// never used.
pub(crate) fn public_open(store: &ObjectStore, veil: &Veil, id: &ObjectId) -> Result<Public> {
    let raw = match store.get_raw(id) {
        Ok(r) => r,
        Err(VeilError::Missing(_)) => return Ok(Public::Missing),
        Err(e) => return Err(e),
    };
    let mut obj = Object::decode(&raw)?;
    let mut sealed = false;
    loop {
        match obj {
            Object::Sealed(env) => {
                if !label_is_public(&store.keys, veil, &env.scope) {
                    return Ok(Public::Hidden(env.scope.strip_prefix("embargo/").map(str::to_string)));
                }
                let Some(key) = store.keys.key(&env.scope) else {
                    return Ok(Public::Hidden(None));
                };
                let Ok(plain) = env.open(&key) else {
                    return Ok(Public::Hidden(None));
                };
                obj = Object::decode(&plain)?;
                sealed = true;
            }
            obj => return Ok(Public::Visible { obj, sealed }),
        }
    }
}

/// A projection and what it depended on.
#[derive(Clone, Debug, Default)]
pub(crate) struct Projection {
    /// The public Veil tree, `None` if nothing in it is public.
    pub tree: Option<ObjectId>,
    /// Unreleased embargoes that hid something.
    pub pending: BTreeSet<String>,
    /// False if an object was missing from this replica (the result may
    /// change once it arrives, so it is not cached).
    pub complete: bool,
}

/// Placeholder message for a description Git may not see.
pub(crate) const CLOAKED_DESCRIPTION: &str = "(description withheld: cloaked)";
pub(crate) const EMBARGOED_DESCRIPTION: &str = "(description withheld: under embargo)";

/// The description a public reader sees, and the unreleased embargo that
/// hides it, if any. Only plaintext and released embargo keys are used:
/// a description sealed for a scope is never opened, even if we hold the key.
pub(crate) fn public_text(store: &ObjectStore, veil: &Veil, t: &Text) -> (String, Option<String>) {
    match t {
        Text::Plain(s) => (s.clone(), None),
        Text::Sealed(env) => {
            if label_is_public(&store.keys, veil, &env.scope) {
                if let Some(s) = store.keys.key(&env.scope).and_then(|k| env.open(&k).ok()) {
                    if let Ok(s) = String::from_utf8(s) {
                        return (s, None);
                    }
                }
            }
            match env.scope.strip_prefix("embargo/") {
                Some(e) if !veil.released(&store.keys, e) => (EMBARGOED_DESCRIPTION.into(), Some(e.to_string())),
                _ => (CLOAKED_DESCRIPTION.into(), None),
            }
        }
    }
}

/// A description as a public mirror reads it: `None` if it is sealed for a
/// cloak scope or an unreleased embargo (keys this replica holds for them
/// are never used). For `--public` views outside the bridge (`vl blame
/// --public`).
pub fn public_description(store: &ObjectStore, t: &Text) -> Option<String> {
    match t {
        Text::Plain(s) => Some(s.clone()),
        Text::Sealed(env) if label_is_public(&store.keys, &Veil::default(), &env.scope) => {
            let key = store.keys.key(&env.scope)?;
            String::from_utf8(env.open(&key).ok()?).ok()
        }
        Text::Sealed(_) => None,
    }
}

/// The commit a gitlink's content `"<40 hex>\n"` names (lowercase hex,
/// SHA-1 only: the bridge repository is SHA-1).
pub(crate) fn gitlink_commit(data: &[u8]) -> Option<GitOid> {
    let hex = data.strip_suffix(b"\n")?;
    if hex.len() != 40 || !hex.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    GitOid::from_hex(hex).ok()
}

/// The content of a gitlink entry naming `commit`.
pub(crate) fn gitlink_content(commit: &GitOid) -> Vec<u8> {
    format!("{commit}\n").into_bytes()
}

/// Is `name` a spelling of `.git`, which Git refuses as a tree entry (and
/// a colocated working copy would take as its repository)? Any ASCII case,
/// and with HFS+-ignorable code points anywhere (`.g\u{200C}it`), as Git's
/// `is_hfs_dotgit` does: on macOS those all name the same directory.
/// The same test as the engine's built-in VCS ignore
/// ([`crate::policy::vcs_metadata_name`]).
pub(crate) fn is_git_dir_name(name: &str) -> bool {
    crate::policy::vcs_metadata_name(name) == Some(".git")
}

impl GitBridge {
    /// Run `f` with projections computed through `veil` (see [`Veil`]).
    pub(crate) fn with_veil<T>(&mut self, veil: Veil, f: impl FnOnce(&mut GitBridge) -> Result<T>) -> Result<T> {
        if veil == self.veil {
            return f(self);
        }
        let saved = std::mem::replace(&mut self.veil, veil);
        let memo = std::mem::take(&mut self.run_projected);
        let out = f(self);
        self.veil = saved;
        self.run_projected = memo;
        out
    }

    /// The public projection of Veil tree `id` (see the module docs).
    pub(crate) fn project(&mut self, store: &ObjectStore, id: &ObjectId) -> Result<Projection> {
        self.project_at(store, id, 0)
    }

    fn project_at(&mut self, store: &ObjectStore, id: &ObjectId, depth: usize) -> Result<Projection> {
        if depth > MAX_TREE_DEPTH + 1 {
            return Err(VeilError::Corrupt(id.hex(), "tree nested too deeply".into()));
        }
        if self.veil.is_none() {
            if let Some(p) = self.cache.projected.get(id) {
                return Ok(Projection {
                    tree: *p,
                    pending: BTreeSet::new(),
                    complete: true,
                });
            }
        }
        if let Some(p) = self.run_projected.get(id) {
            return Ok(p.clone());
        }
        let mut out = Projection {
            complete: true,
            ..Default::default()
        };
        let mut cur = *id;
        // Resolve embargo wrappers the way a public reader's store does.
        let (tree, plain) = loop {
            match public_open(store, &self.veil, &cur)? {
                Public::Missing => {
                    out.complete = false;
                    return Ok(self.remember(id, out));
                }
                Public::Hidden(e) => {
                    out.pending.extend(e);
                    return Ok(self.remember(id, out));
                }
                Public::Visible {
                    obj: Object::Tree(t),
                    sealed,
                } => match wrapper_parts(&t) {
                    None => break (t, !sealed),
                    Some(w) => {
                        let released = self.veil.released(&store.keys, &w.embargo);
                        let inner_ok = released
                            && matches!(
                                public_open(store, &self.veil, &w.inner)?,
                                Public::Visible { obj: Object::Tree(_), .. }
                            );
                        if !released {
                            out.pending.insert(w.embargo.clone());
                        }
                        cur = if inner_ok { w.inner } else { w.fallback };
                    }
                },
                Public::Visible { obj, .. } => {
                    return Err(VeilError::Corrupt(
                        cur.hex(),
                        format!("expected tree, found {}", obj.kind_name()),
                    ))
                }
            }
        };
        let mut kept = Tree::default();
        for e in &tree.entries {
            if is_git_dir_name(&e.name) {
                self.warnings
                    .push(format!("'{}' cannot be represented in Git and is not exported", e.name));
                continue;
            }
            match e.kind {
                EntryKind::Dir => {
                    let sub = self.project_at(store, &e.id, depth + 1)?;
                    out.pending.extend(sub.pending);
                    out.complete &= sub.complete;
                    if let Some(t) = sub.tree {
                        kept.insert(TreeEntry::dir(&e.name, t));
                    }
                }
                EntryKind::File => {
                    if let Some(ne) = self.public_file(store, e, &mut out)? {
                        kept.insert(ne);
                    }
                }
                EntryKind::Conflict => {
                    if let Some(ne) = self.public_conflict(store, e, &mut out)? {
                        kept.insert(ne);
                    }
                }
                // Format 5: a public link is exported as mode 120000 or
                // 160000; a sealed one is omitted like a sealed file.
                EntryKind::Symlink | EntryKind::Gitlink => {
                    if let Some(ne) = self.public_file(store, e, &mut out)? {
                        if let Some(ne) = self.exportable_link(store, ne)? {
                            kept.insert(ne);
                        }
                    }
                }
            }
        }
        out.tree = if kept.is_empty() {
            None
        } else if plain && kept == tree {
            Some(cur)
        } else {
            Some(store.put_tree(&kept)?)
        };
        Ok(self.remember(id, out))
    }

    fn remember(&mut self, id: &ObjectId, p: Projection) -> Projection {
        // `run_projected` holds the results for the current veil only
        // (`with_veil` clears it); the cache, those for no veil.
        if self.veil.is_none() && p.complete && p.pending.is_empty() {
            self.cache.projected.insert(*id, p.tree);
            self.cache.mark_dirty();
        } else {
            self.run_projected.insert(*id, p.clone());
        }
        p
    }

    /// What Git sees of conflict entry `e`: the conflict materialised for a
    /// public reader, a marker file in which every version that is not
    /// plaintext is a "not shown" line (`conflict::materialize` with
    /// `Audience::Public`). Content under an embargo, even a released one,
    /// is never shown in it (so a pinned pre-release export cannot depend
    /// on a release). With no public side at all, the newest public version
    /// a side carries as its fallback, else nothing (like a sealed file).
    fn public_conflict(&mut self, store: &ObjectStore, e: &TreeEntry, out: &mut Projection) -> Result<Option<TreeEntry>> {
        let c = match public_open(store, &self.veil, &e.id)? {
            Public::Visible { obj: Object::Conflict(c), .. } => c,
            Public::Visible { obj, .. } => {
                return Err(VeilError::Corrupt(
                    e.id.hex(),
                    format!("expected conflict, found {}", obj.kind_name()),
                ))
            }
            Public::Hidden(emb) => {
                out.pending.extend(emb);
                return Ok(None);
            }
            Public::Missing => {
                out.complete = false;
                return Ok(None);
            }
        };
        if c.has_special_terms() {
            // Format 5: a conflict with a symlink or gitlink side is never
            // shown as a file of markers (that would turn a link target
            // into file content). Git gets our side as it is, if public,
            // else nothing, like a sealed file.
            return self.public_special_conflict(store, e, &c, out);
        }
        for t in c.interleaved().flatten() {
            if store.get_raw(&t.id).is_err() {
                // A side this replica lacks: the projection may change.
                if !matches!(t.visibility, Visibility::Cloaked { .. }) {
                    out.complete = false;
                }
            }
        }
        let any_public = c.adds.iter().flatten().any(|t| {
            store.get_raw(&t.id).is_ok_and(|raw| Object::is_blob_raw(&raw))
        });
        if !any_public {
            let fb = c.adds.iter().flatten().find_map(|t| t.fallback);
            let Some(fb) = fb else { return Ok(None) };
            return Ok(match public_open(store, &self.veil, &fb)? {
                Public::Visible { obj: Object::Blob(b), sealed: false } => Some(TreeEntry {
                    name: e.name.clone(),
                    kind: EntryKind::File,
                    id: fb,
                    size: b.len() as u64,
                    executable: false,
                    visibility: Visibility::Public,
                    fallback: None,
                }),
                _ => None,
            });
        }
        let m = crate::conflict::materialize(store, &c, crate::conflict::Audience::Public)?;
        let id = store.store_file(&m.content, &Visibility::Public)?;
        Ok(Some(TreeEntry {
            name: e.name.clone(),
            kind: EntryKind::File,
            id,
            size: m.content.len() as u64,
            executable: m.executable,
            visibility: Visibility::Public,
            fallback: None,
        }))
    }

    /// Git's view of a conflict that has a symlink or gitlink side: the
    /// first side (ours) as its own kind, when a public reader can read it.
    fn public_special_conflict(
        &mut self,
        store: &ObjectStore,
        e: &TreeEntry,
        c: &crate::object::Conflict,
        out: &mut Projection,
    ) -> Result<Option<TreeEntry>> {
        use crate::object::TermKind;
        let Some(Some(t)) = c.adds.first() else { return Ok(None) };
        let kind = match t.kind {
            TermKind::File => EntryKind::File,
            TermKind::Symlink => EntryKind::Symlink,
            TermKind::Gitlink => EntryKind::Gitlink,
        };
        let side = TreeEntry {
            name: e.name.clone(),
            kind,
            id: t.id,
            size: t.size,
            executable: t.executable && kind == EntryKind::File,
            visibility: t.visibility.clone(),
            fallback: t.fallback,
        };
        let Some(ne) = self.public_file(store, &side, out)? else { return Ok(None) };
        if kind == EntryKind::File {
            return Ok(Some(ne));
        }
        self.exportable_link(store, ne)
    }

    /// `e` (a public symlink or gitlink) if Git can carry it, else `None`
    /// with a warning: a symlink target must be non-empty and hold no NUL,
    /// a gitlink must name a SHA-1 commit (the bridge is a SHA-1
    /// repository), and `.gitmodules` is never a symlink (Git's fsck
    /// refuses one, CVE-2018-11235).
    fn exportable_link(&mut self, store: &ObjectStore, e: TreeEntry) -> Result<Option<TreeEntry>> {
        let data = match public_open(store, &Veil::default(), &e.id)? {
            Public::Visible { obj: Object::Blob(b), .. } => b,
            _ => return Ok(None),
        };
        let why = match e.kind {
            EntryKind::Symlink if e.name.eq_ignore_ascii_case(".gitmodules") => {
                Some("a symlink named .gitmodules is refused by Git")
            }
            EntryKind::Symlink if data.is_empty() || data.contains(&0) => Some("its target is empty or holds a NUL"),
            EntryKind::Gitlink if gitlink_commit(&data).is_none() => Some("it does not name a SHA-1 commit"),
            _ => None,
        };
        if let Some(why) = why {
            self.warnings
                .push(format!("{} '{}' is not exported to Git: {why}", e.kind.name(), e.name));
            return Ok(None);
        }
        Ok(Some(e))
    }

    /// The entry a public reader materialises for file entry `e`, if any.
    fn public_file(&mut self, store: &ObjectStore, e: &TreeEntry, out: &mut Projection) -> Result<Option<TreeEntry>> {
        match public_open(store, &self.veil, &e.id)? {
            Public::Visible { obj: Object::Blob(_), .. } => return Ok(Some(e.clone())),
            Public::Visible { obj, .. } => {
                return Err(VeilError::Corrupt(
                    e.id.hex(),
                    format!("expected blob, found {}", obj.kind_name()),
                ))
            }
            Public::Hidden(emb) => out.pending.extend(emb),
            Public::Missing => out.complete = false,
        }
        let Some(fb) = e.fallback else { return Ok(None) };
        match public_open(store, &self.veil, &fb)? {
            Public::Visible { obj: Object::Blob(b), sealed } => Ok(Some(TreeEntry {
                name: e.name.clone(),
                // A link's last public version is a link target.
                kind: if e.kind.is_special() { e.kind } else { EntryKind::File },
                id: fb,
                size: b.len() as u64,
                executable: e.executable && !e.kind.is_special(),
                visibility: match (sealed, &e.visibility) {
                    (true, v) => v.clone(),
                    (false, _) => Visibility::Public,
                },
                fallback: None,
            })),
            Public::Visible { .. } | Public::Hidden(_) => Ok(None),
            Public::Missing => {
                out.complete = false;
                Ok(None)
            }
        }
    }

    /// Convert a public projection (every entry publicly readable) to a Git
    /// tree, writing the Git objects.
    pub(crate) fn git_tree(&mut self, store: &ObjectStore, id: &ObjectId) -> Result<GitOid> {
        self.git_tree_at(store, id, 0)
    }

    fn git_tree_at(&mut self, store: &ObjectStore, id: &ObjectId, depth: usize) -> Result<GitOid> {
        if let Some(g) = self.cache.trees.get(id) {
            if self.has_object(g) {
                return Ok(*g);
            }
        }
        if depth > MAX_TREE_DEPTH + 1 {
            return Err(VeilError::Corrupt(id.hex(), "tree nested too deeply".into()));
        }
        // Whatever a projection holds is readable through any veil, so
        // through none.
        let tree = match public_open(store, &Veil::default(), id)? {
            Public::Visible { obj: Object::Tree(t), .. } => t,
            _ => return Err(VeilError::Corrupt(id.hex(), "public projection is not readable".into())),
        };
        let mut entries = Vec::with_capacity(tree.entries.len());
        for e in &tree.entries {
            let (mode, oid) = match e.kind {
                EntryKind::Dir => (gix::objs::tree::EntryKind::Tree, self.git_tree_at(store, &e.id, depth + 1)?),
                EntryKind::File => {
                    let mode = if e.executable {
                        gix::objs::tree::EntryKind::BlobExecutable
                    } else {
                        gix::objs::tree::EntryKind::Blob
                    };
                    (mode, self.git_blob(store, &e.id)?)
                }
                EntryKind::Conflict => {
                    return Err(VeilError::Corrupt(id.hex(), "a public projection never holds a conflict entry".into()))
                }
                EntryKind::Symlink => (gix::objs::tree::EntryKind::Link, self.git_blob(store, &e.id)?),
                EntryKind::Gitlink => {
                    let data = match public_open(store, &Veil::default(), &e.id)? {
                        Public::Visible { obj: Object::Blob(b), .. } => b,
                        _ => return Err(VeilError::Corrupt(e.id.hex(), "public gitlink is not readable".into())),
                    };
                    let commit = gitlink_commit(&data)
                        .ok_or_else(|| VeilError::Corrupt(e.id.hex(), "gitlink does not name a commit".into()))?;
                    (gix::objs::tree::EntryKind::Commit, commit)
                }
            };
            entries.push(gix::objs::tree::Entry {
                mode: mode.into(),
                filename: e.name.as_str().into(),
                oid,
            });
        }
        entries.sort();
        let oid = self.write_tree(gix::objs::Tree { entries })?;
        self.cache.trees.insert(*id, oid);
        self.cache.mark_dirty();
        Ok(oid)
    }

    fn git_blob(&mut self, store: &ObjectStore, id: &ObjectId) -> Result<GitOid> {
        if let Some(g) = self.cache.blobs.get(id) {
            if self.has_object(g) {
                return Ok(*g);
            }
        }
        let data = match public_open(store, &Veil::default(), id)? {
            Public::Visible { obj: Object::Blob(b), .. } => b,
            _ => return Err(VeilError::Corrupt(id.hex(), "public file is not readable".into())),
        };
        let oid = self.write_blob(&data)?;
        self.cache.blobs.insert(*id, oid);
        self.cache.contents.insert(oid, Object::blob_id(&data));
        self.cache.mark_dirty();
        Ok(oid)
    }
}
