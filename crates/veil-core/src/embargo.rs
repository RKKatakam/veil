//! Embargoes and visibility normalisation.
//!
//! # Embargoes are permissions, not encryption
//!
//! An embargoed merge (`vl merge --embargo`) is an ordinary merge whose
//! snapshot names an embargo ([`crate::object::Snapshot::embargo`]) with a
//! plain record: the groups that see it now and an optional deadline
//! ([`crate::keychain::Keychain::create_embargo`]). Nothing is encrypted:
//! only secret files ever are (`docs/VISIBILITY.md`). Until the embargo is
//! released (by `vl embargo release`, or at its deadline) the merge, the
//! history it brings in and anything built on it never leave this
//! repository for any receiver (`remote::embargo_withheld`), and the
//! Veil server refuses embargoed merges until it enforces them as
//! permissions (`docs/HUB.md` §13.8).
//!
//! Embargoes never overlap (Veil 1.0): a new embargoed merge of, or into, a
//! line that carries an unreleased embargo is refused before anything is
//! recorded (`Repo::merge`). Combining two embargoed lines otherwise (a
//! merge, a rebase) is allowed: the result builds on both, so it is
//! withheld until both are released.
//!
//! # Normalisation
//!
//! [`normalize_tree`] re-derives the sealing of secret files after a merge.
//! It may seal a file the merged policy makes a secret, but it never moves
//! a sealed secret to a wider or different audience: the destination's
//! sealing wins, and a secret is never published by a merge.

use std::sync::Arc;

use crate::{
    builder::{relabel_note, verify_sealing, Sealing},
    error::{Result, VeilError},
    id::ObjectId,
    object::{EntryKind, Tree, TreeEntry, Visibility},
    policy::{Policy, Tier},
    store::ObjectStore,
    tree::MAX_TREE_DEPTH,
    vpath::VPath,
};

// ---- normalisation after a merge -------------------------------------------

/// Inputs of [`normalize_tree`].
pub struct NormalizeOptions<'a> {
    /// Policy of the merge result.
    pub policy: &'a Policy,
    /// Policy of the destination before the merge (rules the member already
    /// lives under).
    pub dest_policy: &'a Policy,
    /// The destination's tree.
    pub dest_tree: ObjectId,
}

/// What [`normalize_tree`] did.
#[derive(Debug, Default, Clone)]
pub struct NormalizeReport {
    /// Sealed files whose audience the merge did not change, with the reason.
    pub kept_sealed: Vec<(VPath, String)>,
}

/// Re-derive the sealing of secret files after merging. See the module
/// documentation for the rules.
pub fn normalize_tree(store: &ObjectStore, tree: &ObjectId, opts: &NormalizeOptions, report: &mut NormalizeReport) -> Result<ObjectId> {
    let dest = Some(opts.dest_tree);
    normalize_dir(store, tree, dest, &VPath::root(), opts, report)
}

fn desired_visibility(policy: &Policy, path: &VPath) -> Option<Visibility> {
    match policy.classify(path, false).tier {
        Tier::Public => Some(Visibility::Public),
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
            EntryKind::File | EntryKind::Symlink => {
                let ne = normalize_file(store, &e, de.as_ref(), &path, opts, report)?;
                settle(f, &e, ne);
            }
            // A conflict is never resealed by a merge: each of its
            // versions keeps the sealing it has, and its resolution is
            // sealed by the builder's rules for edits.
            EntryKind::Conflict => settle(f, &e, Some(e.clone())),
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
    let desired = desired_visibility(opts.policy, &path);
    let differs_from_dest_seal = |e: &TreeEntry, de: Option<&TreeEntry>| {
        de.is_some_and(|d| d.kind.holds_blob() && matches!(d.visibility, Visibility::Cloaked { .. }) && d.visibility != e.visibility)
    };
    // Labels are claims (BUG-103). Whenever this entry may be resealed, or
    // resealed for the destination's audience, both labels are checked
    // against their objects first, and the decision is taken on what the
    // objects really are. A label that cannot be verified is left exactly
    // as it is: no new content is sealed on its word.
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
        Some(d) if d.kind.holds_blob() && !d.visibility.is_public() && !unchanged_from_dest => match verify_sealing(store, d)? {
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
    let dest_sealed = de.filter(|d| d.kind.holds_blob() && matches!(d.visibility, Visibility::Cloaked { .. }));
    match (&e.visibility, desired) {
        // The destination holds this secret sealed and the merged side
        // would widen or move its audience: keep the destination's
        // audience, with the merged content if we can read it.
        (v, _) if !unchanged_from_dest && dest_sealed.is_some_and(|d| d.visibility != *v) => {
            let d = dest_sealed.expect("checked");
            // Content sealed for another scope is never resealed for the
            // destination's (BUG-123): that would hand one scope's secret
            // to the other's members. The destination keeps its version.
            let resealed = match store.read_blob(&e.id) {
                Ok(_) if matches!(v, Visibility::Cloaked { .. }) => None,
                Ok(data) => Some(TreeEntry {
                    id: store.store_file(&data, &d.visibility)?,
                    size: data.len() as u64,
                    visibility: d.visibility.clone(),
                    ..e.clone()
                }),
                Err(err) if err.is_unreadable() => None,
                Err(err) => return Err(err),
            };
            let why = match (&resealed, v) {
                (None, Visibility::Cloaked { .. }) => format!(
                    "keeps the destination's version, {}: the merged side holds it sealed as {}, and a merge never moves a secret from one scope to another; reconcile them deliberately",
                    d.visibility.label(),
                    v.label()
                ),
                _ => format!(
                    "stays {}: the merged side would make it {}; a merge never widens or moves the audience of a secret the destination keeps sealed",
                    d.visibility.label(),
                    v.label()
                ),
            };
            ne = Some(resealed.unwrap_or_else(|| d.clone()));
            report.kept_sealed.push((path.clone(), why));
        }
        (_, None) => {}
        (v, Some(want)) if *v == want => {}
        (Visibility::Public, Some(want)) => {
            // Sealing is never a downgrade. Without the key the entry
            // stays as it was in its source.
            if let Ok(data) = store.read_entry(e) {
                if let Ok(id) = store.store_file(&data, &want) {
                    ne = Some(TreeEntry {
                        id,
                        visibility: want,
                        ..e.clone()
                    });
                }
            }
        }
        (Visibility::Cloaked { scope: have }, Some(Visibility::Cloaked { scope: want })) => {
            if !unchanged_from_dest {
                report.kept_sealed.push((
                    path.clone(),
                    format!("stays sealed under '{have}' (policy says '{want}'); a merge never re-keys a secret, re-key it deliberately"),
                ));
            }
        }
        (Visibility::Cloaked { scope: have }, Some(Visibility::Public)) => {
            if !unchanged_from_dest {
                report.kept_sealed.push((path.clone(), format!("stays sealed under '{have}'; a merge never publishes a secret")));
            }
        }
    }
    Ok(ne)
}

/// Sealed secrets of `tree` whose audience a change from `old` to `new`
/// policy would widen or move: `(path, current visibility, new visibility)`.
pub fn policy_rekeys(store: &ObjectStore, tree: &ObjectId, old: &Policy, new: &Policy) -> Result<Vec<(VPath, Visibility, Visibility)>> {
    let mut out = Vec::new();
    for (path, e) in crate::tree::walk_files(store, tree)? {
        let Visibility::Cloaked { .. } = &e.visibility else { continue };
        if old.classify(&path, false) == new.classify(&path, false) {
            continue;
        }
        if let Some(want) = desired_visibility(new, &path) {
            if want != e.visibility {
                out.push((path, e.visibility.clone(), want));
            }
        }
    }
    Ok(out)
}
