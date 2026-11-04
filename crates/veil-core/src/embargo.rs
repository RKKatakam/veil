//! Delayed-visibility (embargoed) merges and visibility normalisation.
//!
//! # Embargo wrappers
//!
//! An embargoed tree is stored as a small plaintext **wrapper** tree:
//!
//! ```text
//! embargo        dir   [embargo:<id>]  → Sealed(tree)     fallback → pre-merge tree
//! <hex id>       file  [embargo:<id>]  → every object only reachable from the sealed side
//! …
//! ```
//!
//! * The marker entry `embargo` points at the merged tree, **sealed** under
//!   `embargo/<id>`, and names the pre-merge tree as its `fallback`.
//!   [`ObjectStore::tree`] resolves a wrapper transparently: key holders see
//!   the merged tree, everyone else sees the fallback. Non-holders therefore
//!   learn nothing about the fix: no new names, no new sizes, not even
//!   which files changed.
//! * Inside the sealed side, every directory that differs from the fallback
//!   is itself a sealed tree, and every public file that differs is sealed
//!   under the embargo key (with the pre-merge version as its `fallback`).
//! * The other entries list, by id, every object that is reachable *only*
//!   through the sealed side. Relays, `gc` and `fsck` cannot open sealed
//!   trees, so this list is how they find (and keep, and transfer) the
//!   sealed subtrees and blobs. All listed objects are sealed, or are the
//!   public pre-merge versions. A public remote withholds the sealed ones
//!   until release.
//!
//! Releasing publishes the key; the wrapper then resolves to the merged tree
//! for everyone, with no history rewrite (snapshot ids do not change).
//!
//! While an embargo is unreleased its wrapper is sticky: a key holder's
//! later snapshots, merges and rebases on top of it are re-wrapped under the
//! same embargo (non-holders keep seeing the pre-merge tree), and a
//! non-holder cannot record edits on top of it (the builder holds them back)
//! because they cannot see what they would be editing.
//!
//! Embargoes never overlap (Veil 1.0). A tree under one unreleased embargo
//! is never wrapped under another ([`wrap`] refuses, and so does
//! [`crate::merge::merge_trees`] for inputs under two of them); a new
//! embargoed merge of, or into, a line that carries an unreleased embargo is
//! refused before anything is recorded (`Repo::merge`). Nesting would wrap
//! the second fix under the first's key, so releasing either one would
//! publish, or reveal the shape of, the other.
//!
//! Snapshot metadata stays public, so on a line under an unreleased embargo
//! a key holder's descriptions are sealed under the embargo key
//! ([`description_scope`]) and no conflict list is recorded
//! ([`recordable_conflicts`]).
//!
//! Time-based release is enforced by the engines of key holders: the first
//! `vl` invocation by a key holder after the deadline publishes the key.
//! (True time-lock cryptography is out of scope.)
//!
//! # Normalisation
//!
//! [`normalize_tree`] re-derives visibility after a merge. It may *seal*
//! content (public → cloaked), but it never moves content that is already
//! sealed to a wider or different audience, with one exception: an explicit
//! merge of a cloaked line of work into a public line publishes that line's
//! files, after secret scanning them.

use std::{collections::BTreeSet, sync::Arc};

use crate::{
    builder::{relabel_note, trusted_cloak, verify_sealing, Sealing},
    error::{Result, VeilError},
    id::ObjectId,
    object::{EntryKind, Object, Tree, TreeEntry, Visibility},
    policy::{Policy, Tier, POLICY_FILE},
    secrets::{self, Finding},
    store::ObjectStore,
    tree::MAX_TREE_DEPTH,
    vpath::VPath,
};

/// Name of the marker entry of an embargo wrapper tree.
pub const WRAPPER_ENTRY: &str = "embargo";

/// The parts of an embargo wrapper tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmbargoWrapper {
    pub embargo: String,
    /// The merged tree, sealed under `embargo/<id>`.
    pub inner: ObjectId,
    /// What readers without the key see (the pre-merge tree, possibly
    /// itself a wrapper of an older embargo).
    pub fallback: ObjectId,
    /// Objects reachable only through `inner`.
    pub listed: Vec<ObjectId>,
}

impl EmbargoWrapper {
    pub fn key_label(&self) -> String {
        format!("embargo/{}", self.embargo)
    }
}

/// Recognise an embargo wrapper. Ordinary directory entries are always
/// public, so a directory entry marked embargoed with a fallback can only
/// come from [`wrap`].
pub fn wrapper_parts(t: &Tree) -> Option<EmbargoWrapper> {
    let marker = t.get(WRAPPER_ENTRY)?;
    let Visibility::Embargoed { embargo } = &marker.visibility else {
        return None;
    };
    if marker.kind != EntryKind::Dir {
        return None;
    }
    let fallback = marker.fallback?;
    let mut listed = Vec::new();
    for e in &t.entries {
        if e.name == WRAPPER_ENTRY {
            continue;
        }
        if e.kind != EntryKind::File || e.visibility != marker.visibility || e.fallback.is_some() {
            return None;
        }
        listed.push(e.id);
    }
    Some(EmbargoWrapper {
        embargo: embargo.clone(),
        inner: marker.id,
        fallback,
        listed,
    })
}

/// The wrapper parts of tree `id`, if it is one.
pub fn wrapper_of(store: &ObjectStore, id: &ObjectId) -> Result<Option<EmbargoWrapper>> {
    Ok(wrapper_parts(&*store.tree_object(id)?))
}

/// The wrapper parts of tree `id` if it is a wrapper of an embargo that has
/// not been released.
pub fn unreleased_wrapper(store: &ObjectStore, id: &ObjectId) -> Result<Option<EmbargoWrapper>> {
    Ok(wrapper_of(store, id)?.filter(|w| !store.keys.embargo_released(&w.embargo)))
}

/// The tree a reader holding no unreleased embargo key sees: every
/// unreleased wrapper is replaced by its fallback.
pub fn public_view(store: &ObjectStore, id: &ObjectId) -> Result<ObjectId> {
    let mut id = *id;
    while let Some(w) = unreleased_wrapper(store, &id)? {
        id = w.fallback;
    }
    Ok(id)
}

/// Embargoes never overlap (Veil 1.0): refusal for content of two
/// unreleased embargoes `a` and `b` meeting in one tree.
pub fn overlap_error(a: &str, b: &str) -> VeilError {
    VeilError::Policy(format!(
        "cannot combine history under two unreleased embargoes ({a} and {b}): embargoes cannot overlap; release one of them first (`vl embargo release <id>`), then merge or rebase"
    ))
}

/// The scope a description written on a snapshot with `tree` is sealed
/// under: the line's cloak if it is a cloaked line of work, else the
/// embargo key if `tree` is under an unreleased embargo whose key we hold
/// (a key holder's follow-up messages describe the hidden fix), else none.
/// `cloak` comes from a snapshot's `cloak` field, so only a
/// [`trusted_cloak`] counts: a forged `embargo/<released id>` would seal
/// the message under a public key.
pub fn description_scope(store: &ObjectStore, tree: &ObjectId, cloak: Option<&str>) -> Result<Option<String>> {
    if let Some(c) = trusted_cloak(cloak) {
        return Ok(Some(c.to_string()));
    }
    Ok(unreleased_wrapper(store, tree)?
        .map(|w| w.key_label())
        .filter(|l| store.keys.has(l)))
}

/// The conflict list a snapshot with `tree` may carry. Snapshot metadata is
/// public, so a tree under an unreleased embargo records none: the names
/// would tell outsiders which files the hidden change touches. (The markers
/// are in the files themselves, and the command that produced them reports
/// them.)
pub fn recordable_conflicts(store: &ObjectStore, tree: &ObjectId, conflicts: Vec<String>) -> Result<Vec<String>> {
    if !conflicts.is_empty() && unreleased_wrapper(store, tree)?.is_some() {
        return Ok(vec![]);
    }
    Ok(conflicts)
}

/// Seal `tree` under `embargo`, showing `fallback` to everyone without the
/// key. Public files that differ from the fallback are sealed under the
/// embargo key. Content that is already sealed under a scope stays sealed
/// as it is: releasing this embargo never declassifies it. Returns
/// `fallback` itself when `tree` holds nothing to hide.
///
/// Embargoes never nest: content (or a fallback) under *another*
/// unreleased embargo is refused ([`overlap_error`]). Nesting would wrap
/// one embargo's fix under the other's key, so releasing either would
/// publish (or reveal the shape of) the other.
pub fn wrap(store: &ObjectStore, embargo: &str, tree: &ObjectId, fallback: &ObjectId) -> Result<ObjectId> {
    if tree == fallback {
        return Ok(*fallback);
    }
    for id in [tree, fallback] {
        if let Some(w) = unreleased_wrapper(store, id)? {
            if w.embargo != embargo {
                return Err(overlap_error(&w.embargo, embargo));
            }
        }
    }
    let base = public_view(store, fallback)?;
    let vis = Visibility::Embargoed {
        embargo: embargo.to_string(),
    };
    let mut listed = BTreeSet::new();
    let inner = seal_dir(store, &vis, tree, Some(base), &mut listed)?;
    let mut w = Tree::default();
    w.insert(TreeEntry {
        name: WRAPPER_ENTRY.to_string(),
        kind: EntryKind::Dir,
        id: inner,
        size: 0,
        executable: false,
        visibility: vis.clone(),
        fallback: Some(*fallback),
    });
    for id in listed {
        w.insert(TreeEntry {
            name: id.hex(),
            kind: EntryKind::File,
            id,
            size: 0,
            executable: false,
            visibility: vis.clone(),
            fallback: None,
        });
    }
    store.put_tree(&w)
}

struct SealFrame {
    t: Arc<Tree>,
    b: Option<Arc<Tree>>,
    dir: VPath,
    next: usize,
    out: Tree,
}

fn seal_frame(store: &ObjectStore, tree: &ObjectId, base: Option<ObjectId>, dir: VPath) -> Result<SealFrame> {
    Ok(SealFrame {
        t: store.tree(tree)?,
        b: base.map(|b| store.tree(&b)).transpose()?,
        dir,
        next: 0,
        out: Tree::default(),
    })
}

/// Iterative (tree depth is not trusted).
fn seal_dir(
    store: &ObjectStore,
    vis: &Visibility,
    tree: &ObjectId,
    base: Option<ObjectId>,
    listed: &mut BTreeSet<ObjectId>,
) -> Result<ObjectId> {
    let scope = vis.key_scope().expect("embargo visibility has a key scope");
    let mut stack = vec![seal_frame(store, tree, base, VPath::root())?];
    let mut done: Option<ObjectId> = None;
    loop {
        let depth = stack.len();
        let f = stack.last_mut().expect("never empty here");
        if let Some(id) = done.take() {
            let name = f.t.entries[f.next - 1].name.clone();
            f.out.insert(TreeEntry::dir(&name, id));
        }
        let Some(e) = f.t.entries.get(f.next).cloned() else {
            let fin = stack.pop().expect("checked");
            let sealed = store.put(&store.seal(&Object::Tree(fin.out), &scope)?)?;
            listed.insert(sealed);
            if stack.is_empty() {
                return Ok(sealed);
            }
            done = Some(sealed);
            continue;
        };
        f.next += 1;
        let be = f.b.as_deref().and_then(|b| b.get(&e.name)).cloned();
        if be.as_ref().is_some_and(|x| x.same_content(&e)) {
            // Reachable through the fallback; nothing to hide.
            f.out.insert(e);
            continue;
        }
        match e.kind {
            EntryKind::Dir => {
                let path = f.dir.join(&e.name);
                if depth >= MAX_TREE_DEPTH {
                    return Err(too_deep(&path));
                }
                let sub_base = be.filter(|x| x.kind == EntryKind::Dir).map(|x| x.id);
                let child = seal_frame(store, &e.id, sub_base, path)?;
                stack.push(child);
            }
            EntryKind::File => {
                // A public label is a claim: content that is really sealed
                // (a forged label) keeps its sealing, under its real label.
                let e = match e.visibility.is_public() {
                    true => verified_entry(store, &e)?.unwrap_or(e),
                    false => e,
                };
                if let (Visibility::Embargoed { embargo: other }, Visibility::Embargoed { embargo: this }) = (&e.visibility, vis) {
                    if other != this && !store.keys.embargo_released(other) {
                        return Err(overlap_error(other, this));
                    }
                }
                let ne = if e.visibility.is_public() {
                    let data = store.read_entry(&e)?;
                    TreeEntry {
                        id: store.store_file(&data, vis)?,
                        visibility: vis.clone(),
                        fallback: be.filter(|x| x.kind == EntryKind::File).map(|x| x.id),
                        ..e.clone()
                    }
                } else {
                    e.clone()
                };
                listed.insert(ne.id);
                if let Some(fb) = ne.fallback {
                    listed.insert(fb);
                }
                f.out.insert(ne);
            }
        }
    }
}

/// Embargo the merged `tree`: readers without the key see `base` (the first
/// parent's tree) exactly, and learn nothing about what changed.
pub fn apply_embargo(store: &ObjectStore, tree: &ObjectId, base: &ObjectId, embargo: &str) -> Result<ObjectId> {
    wrap(store, embargo, tree, base)
}

// ---- normalisation after a merge -------------------------------------------

/// Inputs of [`normalize_tree`].
pub struct NormalizeOptions<'a> {
    /// Policy of the merge result.
    pub policy: &'a Policy,
    /// Policy of the destination before the merge (rules the member already
    /// lives under).
    pub dest_policy: &'a Policy,
    /// The destination's tree (a quarantined file keeps its version).
    pub dest_tree: ObjectId,
    /// Cloak of the destination line, if it is a cloaked line of work.
    pub cloak: Option<&'a str>,
    /// Scopes of the cloaked lines of work being merged in. Their files may
    /// become public: merging them is the explicit act of declassification.
    pub declassify: &'a BTreeSet<String>,
}

/// What [`normalize_tree`] did.
#[derive(Debug, Default, Clone)]
pub struct NormalizeReport {
    /// Files of a merged-in cloaked line that are now public (scanned clean).
    pub declassified: Vec<VPath>,
    /// Files that would have become public but contain secrets: left out of
    /// the merge (or kept at the destination's version).
    pub quarantined: Vec<(VPath, Vec<Finding>)>,
    /// Sealed files whose audience the merge did not change, with the reason.
    pub kept_sealed: Vec<(VPath, String)>,
}

/// Re-derive visibility after merging (e.g. a cloaked line of work into a
/// public one). See the module documentation for the rules.
pub fn normalize_tree(store: &ObjectStore, tree: &ObjectId, opts: &NormalizeOptions, report: &mut NormalizeReport) -> Result<ObjectId> {
    let dest = Some(opts.dest_tree);
    normalize_dir(store, tree, dest, &VPath::root(), opts, report)
}

fn desired_visibility(policy: &Policy, path: &VPath, cloak: Option<&str>) -> Option<Visibility> {
    match policy.classify(path, false).tier {
        Tier::Public => Some(match trusted_cloak(cloak) {
            Some(s) if path.as_str() != POLICY_FILE => Visibility::Cloaked { scope: s.to_string() },
            _ => Visibility::Public,
        }),
        Tier::Cloaked(s) => Some(Visibility::Cloaked { scope: s }),
        Tier::Isolated | Tier::Ignored => None,
    }
}

struct NormalizeFrame {
    id: ObjectId,
    t: Arc<Tree>,
    d: Option<Arc<Tree>>,
    dir: VPath,
    next: usize,
    out: Tree,
    changed: bool,
}

fn normalize_frame(store: &ObjectStore, tree: &ObjectId, dest: Option<ObjectId>, dir: VPath) -> Result<NormalizeFrame> {
    let t = store.tree(tree)?;
    let d = match dest {
        Some(id) => match store.tree(&id) {
            Ok(t) => Some(t),
            Err(e) if e.is_unreadable() => None,
            Err(e) => return Err(e),
        },
        None => None,
    };
    Ok(NormalizeFrame {
        id: *tree,
        t,
        d,
        dir,
        next: 0,
        out: Tree::default(),
        changed: false,
    })
}

/// Iterative (tree depth is not trusted): a frame per directory being
/// normalised, resumed when its subdirectory is done.
fn normalize_dir(
    store: &ObjectStore,
    tree: &ObjectId,
    dest: Option<ObjectId>,
    dir: &VPath,
    opts: &NormalizeOptions,
    report: &mut NormalizeReport,
) -> Result<ObjectId> {
    let mut stack = vec![normalize_frame(store, tree, dest, dir.clone())?];
    let mut done: Option<ObjectId> = None;
    loop {
        let depth = stack.len();
        let f = stack.last_mut().expect("never empty here");
        // Entry `next - 1` is a directory whose normalisation just finished.
        if let Some(id) = done.take() {
            let e = f.t.entries[f.next - 1].clone();
            // Everything in it was quarantined: no empty directory.
            let emptied = id != e.id && store.tree(&id)?.is_empty();
            let ne = if emptied { None } else { Some(TreeEntry { id, ..e.clone() }) };
            settle(f, &e, ne);
        }
        let Some(e) = f.t.entries.get(f.next).cloned() else {
            let fin = stack.pop().expect("checked");
            let id = if !fin.changed {
                fin.id
            } else if fin.out.is_empty() {
                store.empty_tree()?
            } else {
                store.put_tree(&fin.out)?
            };
            if stack.is_empty() {
                return Ok(id);
            }
            done = Some(id);
            continue;
        };
        f.next += 1;
        let path = f.dir.join(&e.name);
        let de = f.d.as_deref().and_then(|d| d.get(&e.name)).cloned();
        match e.kind {
            EntryKind::Dir => {
                if depth >= MAX_TREE_DEPTH {
                    return Err(too_deep(&path));
                }
                let sub_dest = de.filter(|x| x.kind == EntryKind::Dir).map(|x| x.id);
                let child = normalize_frame(store, &e.id, sub_dest, path)?;
                stack.push(child);
            }
            EntryKind::File => {
                let ne = normalize_file(store, &e, de.as_ref(), &path, opts, report)?;
                settle(f, &e, ne);
            }
        }
    }
}

fn settle(f: &mut NormalizeFrame, e: &TreeEntry, ne: Option<TreeEntry>) {
    match ne {
        Some(ne) => {
            f.changed |= ne != *e;
            f.out.insert(ne);
        }
        None => f.changed = true,
    }
}

fn too_deep(path: &VPath) -> VeilError {
    VeilError::Corrupt(path.to_string(), format!("directory nesting exceeds {MAX_TREE_DEPTH} levels"))
}

/// The normalised entry for file `e` (`None`: left out of the merge).
fn normalize_file(
    store: &ObjectStore,
    e: &TreeEntry,
    de: Option<&TreeEntry>,
    path: &VPath,
    opts: &NormalizeOptions,
    report: &mut NormalizeReport,
) -> Result<Option<TreeEntry>> {
    let path = path.clone();
    let unchanged_from_dest = de.is_some_and(|x| x.same_content(e));
    let desired = desired_visibility(opts.policy, &path, opts.cloak);
    let differs_from_dest_seal = |e: &TreeEntry, de: Option<&TreeEntry>| {
        de.is_some_and(|d| d.kind == EntryKind::File && matches!(d.visibility, Visibility::Cloaked { .. }) && d.visibility != e.visibility)
    };
    // Labels are claims (BUG-103). Whenever this entry may be resealed,
    // published, or resealed for the destination's audience, both labels
    // are checked against their objects first, and the decision is taken on
    // what the objects really are. A label that cannot be verified is left
    // exactly as it is: no new content is sealed or published on its word.
    let acts = desired.as_ref().is_some_and(|w| *w != e.visibility) || (!unchanged_from_dest && differs_from_dest_seal(e, de));
    if !acts {
        return Ok(Some(e.clone()));
    }
    let checked_e;
    let e = match verify_sealing(store, e)? {
        Sealing::Verified => e,
        Sealing::Relabelled(actual) => {
            report.kept_sealed.push((path.clone(), relabel_note(&e.visibility, &actual)));
            checked_e = TreeEntry {
                visibility: actual,
                ..e.clone()
            };
            &checked_e
        }
        Sealing::Unverifiable => return Ok(Some(e.clone())),
    };
    let checked_d;
    let de = match de {
        Some(d) if d.kind == EntryKind::File && !d.visibility.is_public() && !unchanged_from_dest => match verify_sealing(store, d)? {
            Sealing::Verified => Some(d),
            Sealing::Relabelled(actual) => {
                checked_d = TreeEntry {
                    visibility: actual,
                    ..d.clone()
                };
                Some(&checked_d)
            }
            // The destination's sealing cannot be checked: keep its entry.
            Sealing::Unverifiable => {
                report.kept_sealed.push((
                    path.clone(),
                    format!(
                        "keeps the destination's version: it is labelled {} and its content is not here to verify that",
                        d.visibility.label()
                    ),
                ));
                return Ok(Some(d.clone()));
            }
        },
        d => d,
    };
    let mut ne = Some(e.clone());
    let dest_sealed = de.filter(|d| d.kind == EntryKind::File && matches!(d.visibility, Visibility::Cloaked { .. }));
    match (&e.visibility, desired) {
        // The destination holds this file sealed and the merged
        // side would widen or move its audience (e.g. a PR whose
        // author exposed it): keep the destination's audience,
        // with the merged content if we can read it.
        (v, _) if !unchanged_from_dest && !matches!(v, Visibility::Embargoed { .. }) && dest_sealed.is_some_and(|d| d.visibility != *v) => {
            let d = dest_sealed.expect("checked");
            // The entry's own content, never its fallback: resealing the
            // last public version would revert the merged side's edit.
            let resealed = match store.read_blob(&e.id) {
                Ok(data) => Some(TreeEntry {
                    id: store.store_file(&data, &d.visibility)?,
                    size: data.len() as u64,
                    visibility: d.visibility.clone(),
                    fallback: public_fallback(Some(e), &d.visibility).or(d.fallback),
                    ..e.clone()
                }),
                Err(err) if err.is_unreadable() => None,
                Err(err) => return Err(err),
            };
            ne = Some(resealed.unwrap_or_else(|| d.clone()));
            report.kept_sealed.push((
                path.clone(),
                format!(
                    "stays {}: the merged side would make it {}; a merge never widens or moves the audience of content the destination keeps sealed",
                    d.visibility.label(),
                    v.label()
                ),
            ));
        }
        // Under an (unreleased) embargo but cloaked by policy: seal it under
        // the scope (narrower), so the release never publishes it. Without
        // the key the entry stays as it was.
        (Visibility::Embargoed { embargo }, Some(want @ Visibility::Cloaked { .. })) if !store.keys.embargo_released(embargo) => {
            if let Ok(data) = store.read_entry(e) {
                ne = Some(TreeEntry {
                    id: store.store_file(&data, &want)?,
                    visibility: want,
                    fallback: None,
                    ..e.clone()
                });
            }
        }
        (Visibility::Embargoed { .. }, _) | (_, None) => {}
        (v, Some(want)) if *v == want => {}
        (Visibility::Public, Some(want)) => {
            // Sealing is never a downgrade. Without the key the
            // entry stays as it was in its source. Sealed only by the
            // destination's cloak (the policy says public): the public
            // content stays what readers without the key see.
            let line_sealed = opts.policy.classify(&path, false).tier == Tier::Public;
            if let Ok(data) = store.read_entry(e) {
                if let Ok(id) = store.store_file(&data, &want) {
                    ne = Some(TreeEntry {
                        id,
                        visibility: want,
                        fallback: line_sealed.then_some(e.id),
                        ..e.clone()
                    });
                }
            }
        }
        (Visibility::Cloaked { scope: have }, Some(Visibility::Cloaked { scope: want })) => {
            if !unchanged_from_dest {
                report.kept_sealed.push((
                    path.clone(),
                    format!("stays cloaked under '{have}' (policy says '{want}'); a merge never re-keys cloaked content, re-cloak it deliberately"),
                ));
            }
        }
        (Visibility::Cloaked { scope: have }, Some(Visibility::Public)) => {
            let dest_public = opts.dest_policy.classify(&path, false).tier == Tier::Public;
            if !opts.declassify.contains(have) || !dest_public {
                if !unchanged_from_dest {
                    report.kept_sealed.push((
                        path.clone(),
                        format!("stays cloaked under '{have}'; a merge only publishes files of the cloaked line being merged (use `vl expose` to publish deliberately)"),
                    ));
                }
            } else {
                ne = declassify(store, e, de, &path, opts, report)?;
            }
        }
        (Visibility::Cloaked { .. }, Some(Visibility::Embargoed { .. })) => {}
    }
    Ok(ne)
}

/// Publish one file of a merged-in cloaked line, unless it holds a secret.
fn declassify(
    store: &ObjectStore,
    e: &TreeEntry,
    dest: Option<&TreeEntry>,
    path: &VPath,
    opts: &NormalizeOptions,
    report: &mut NormalizeReport,
) -> Result<Option<TreeEntry>> {
    // The entry's own content: publishing its fallback (the last public
    // version) would silently revert the cloaked line's edit.
    let data = match store.read_blob(&e.id) {
        Ok(d) => d,
        Err(err) if err.is_unreadable() => {
            return Err(VeilError::Policy(format!(
                "cannot merge {path}: it is sealed and you do not hold the key"
            )))
        }
        Err(err) => return Err(err),
    };
    let allow = opts.policy.classify(path, false).allow_secrets && opts.dest_policy.classify(path, false).allow_secrets;
    if !allow {
        let findings = secrets::scan(&data);
        if !findings.is_empty() {
            report.quarantined.push((path.clone(), findings));
            // Keep what the destination already had at this path.
            return Ok(dest.filter(|d| d.kind == EntryKind::File).cloned());
        }
    }
    report.declassified.push(path.clone());
    Ok(Some(TreeEntry {
        id: store.store_file(&data, &Visibility::Public)?,
        visibility: Visibility::Public,
        fallback: None,
        ..e.clone()
    }))
}

/// Sealed files of `tree` whose audience a change from `old` to `new`
/// policy would widen or move: `(path, current visibility, new visibility)`.
pub fn policy_rekeys(
    store: &ObjectStore,
    tree: &ObjectId,
    old: &Policy,
    new: &Policy,
    cloak: Option<&str>,
) -> Result<Vec<(VPath, Visibility, Visibility)>> {
    let mut out = Vec::new();
    for (path, e) in crate::tree::walk_files(store, tree)? {
        let Visibility::Cloaked { .. } = &e.visibility else { continue };
        if old.classify(&path, false) == new.classify(&path, false) {
            continue;
        }
        if let Some(want) = desired_visibility(new, &path, cloak) {
            if want != e.visibility {
                out.push((path, e.visibility.clone(), want));
            }
        }
    }
    Ok(out)
}

/// The last public version of a file about to be sealed under `vis` only
/// because of the line it is edited on (its policy says public), given its
/// previous entry `prev`: `prev` itself if public, or the fallback `prev`
/// already carries if it is such a sealed edit under the same scope.
/// Readers without the key see this version instead of losing the file
/// (BUG-074): public remotes, Git export and members of other scopes.
pub(crate) fn public_fallback(prev: Option<&TreeEntry>, vis: &Visibility) -> Option<ObjectId> {
    let prev = prev.filter(|p| p.kind == EntryKind::File)?;
    if prev.visibility.is_public() && prev.fallback.is_none() {
        Some(prev.id)
    } else if prev.visibility == *vis {
        prev.fallback
    } else {
        None
    }
}

/// Seal, under `scope`, every public file of `tree` that differs from
/// `base` (what a cloaked line of work introduces must be sealed). The
/// policy file stays public. Used when a change is folded into a cloaked one.
///
/// `scope` comes from the cloaked change's `cloak` field: unless it is a
/// [`trusted_cloak`], nothing is sealed (the claim is not a line's cloak).
pub fn seal_introduced(store: &ObjectStore, tree: &ObjectId, base: Option<ObjectId>, scope: &str) -> Result<ObjectId> {
    if trusted_cloak(Some(scope)).is_none() {
        return Ok(*tree);
    }
    seal_introduced_dir(store, tree, base, &VPath::root(), scope)
}

struct IntroFrame {
    id: ObjectId,
    t: Arc<Tree>,
    b: Option<Arc<Tree>>,
    dir: VPath,
    next: usize,
    out: Tree,
    changed: bool,
}

/// Iterative (tree depth is not trusted).
fn seal_introduced_dir(store: &ObjectStore, tree: &ObjectId, base: Option<ObjectId>, dir: &VPath, scope: &str) -> Result<ObjectId> {
    if Some(*tree) == base {
        return Ok(*tree);
    }
    let vis = Visibility::Cloaked { scope: scope.to_string() };
    let frame = |id: &ObjectId, base: Option<ObjectId>, dir: VPath| -> Result<IntroFrame> {
        Ok(IntroFrame {
            id: *id,
            t: store.tree(id)?,
            b: base.map(|b| store.tree(&b)).transpose()?,
            dir,
            next: 0,
            out: Tree::default(),
            changed: false,
        })
    };
    let mut stack = vec![frame(tree, base, dir.clone())?];
    let mut done: Option<ObjectId> = None;
    loop {
        let depth = stack.len();
        let f = stack.last_mut().expect("never empty here");
        if let Some(id) = done.take() {
            let e = &f.t.entries[f.next - 1];
            let ne = TreeEntry { id, ..e.clone() };
            f.changed |= ne != *e;
            f.out.insert(ne);
        }
        let Some(e) = f.t.entries.get(f.next).cloned() else {
            let fin = stack.pop().expect("checked");
            let id = if fin.changed { store.put_tree(&fin.out)? } else { fin.id };
            if stack.is_empty() {
                return Ok(id);
            }
            done = Some(id);
            continue;
        };
        f.next += 1;
        let be = f.b.as_deref().and_then(|b| b.get(&e.name)).cloned();
        let path = f.dir.join(&e.name);
        let mut ne = e.clone();
        if !be.as_ref().is_some_and(|x| x.same_content(&e)) {
            match e.kind {
                EntryKind::Dir => {
                    let sub = be.filter(|x| x.kind == EntryKind::Dir).map(|x| x.id);
                    if Some(e.id) != sub {
                        if depth >= MAX_TREE_DEPTH {
                            return Err(too_deep(&path));
                        }
                        let child = frame(&e.id, sub, path)?;
                        stack.push(child);
                        continue;
                    }
                }
                // A public label is a claim: content that is really sealed
                // keeps its own sealing (under its real label).
                EntryKind::File if e.visibility.is_public() && path.as_str() != POLICY_FILE => {
                    match verified_entry(store, &e)? {
                        Some(real) => ne = real,
                        None => {
                            let data = store.read_entry(&e)?;
                            ne.id = store.store_file(&data, &vis)?;
                            ne.visibility = vis.clone();
                            // Its last public version stays what readers
                            // without the key see (see `public_fallback`).
                            ne.fallback = public_fallback(be.as_ref(), &vis);
                        }
                    }
                }
                EntryKind::File => {}
            }
        }
        f.changed |= ne != e;
        f.out.insert(ne);
    }
}

/// `e` with the visibility of its object, if its label disagrees with it
/// (a forged or corrupt label). `None`: the label is right, or cannot be
/// checked.
fn verified_entry(store: &ObjectStore, e: &TreeEntry) -> Result<Option<TreeEntry>> {
    Ok(match verify_sealing(store, e)? {
        Sealing::Relabelled(actual) => Some(TreeEntry {
            visibility: actual,
            ..e.clone()
        }),
        _ => None,
    })
}
