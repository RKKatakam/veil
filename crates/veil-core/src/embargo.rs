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
                match normalize_frame(store, &e.id, sub_dest, path) {
                    Ok(child) => stack.push(child),
                    // A folder the server refuses (BUG-1508) is kept by id,
                    // as it is: never emptied, its secrets never resealed.
                    Err(err) if crate::tree::refused_tree(store, &err) => settle(f, &e, Some(e.clone())),
                    Err(err) => return Err(err),
                }
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
    // A folder the server refuses (BUG-1508) is carried as it is: its
    // secrets keep their audience, never rekeyed by someone who cannot read
    // them.
    for (path, e) in crate::tree::walk_files_hiding(store, tree)?.0 {
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

// ---- hidden embargo lines & `vl embargo follow` (milestone S22) ------------

/// Prefix of hidden server branches that hold an unreleased embargo's line
/// (`docs/HUB.md` §13.31, phase-4 decision 8).
pub const EMBARGO_BRANCH_PREFIX: &str = "embargo/";

/// The hidden branch name for embargo `id`.
pub fn embargo_branch(id: &str) -> String {
    format!("{EMBARGO_BRANCH_PREFIX}{id}")
}

/// If `branch` is a hidden embargo branch (`embargo/<id>`), its embargo id.
pub fn embargo_id_of_branch(branch: &str) -> Option<&str> {
    branch.strip_prefix(EMBARGO_BRANCH_PREFIX).filter(|id| !id.is_empty() && !id.contains('/'))
}

/// What a push is told of a release the server holds for approval
/// (BUG-1861): the embargo stays unreleased until it is approved. `vl` reads
/// it back with [`held_release`] to record the hold (BUG-1894).
pub fn held_release_warning(id: &str, why: &str) -> String {
    format!("embargo {id} is not released: it waits for approval, and releases once it is approved ({why})")
}

/// The embargo and the reason of a [`held_release_warning`].
pub fn held_release(warning: &str) -> Option<(&str, &str)> {
    let (id, why) = warning.strip_prefix("embargo ")?.split_once(" is not released: it waits for approval, and releases once it is approved (")?;
    Some((id, why.strip_suffix(')')?))
}

/// What [`follow`] did for one embargo.
#[derive(Debug, Clone)]
pub struct FollowResult {
    pub id: String,
    pub scope: String,
    pub until: Option<i64>,
    pub tip: ObjectId,
    pub wc: ObjectId,
    pub rebased: bool,
    pub conflicts: Vec<String>,
}

/// Unreleased, non-withdrawn embargo ids that have a line in `repo`.
pub fn active_embargoes(repo: &crate::repo::Repo) -> Result<Vec<String>> {
    let withdrawn = crate::remote::withdrawn_embargoes(repo)?;
    let visible_merges = repo.exact().visible_embargoed()?;
    let mut ids = std::collections::BTreeSet::new();
    for r in repo.keys().embargoes()? {
        if !repo.keys().embargo_released(&r.id) && !withdrawn.contains(&r.id) {
            ids.insert(r.id);
        }
    }
    for name in repo.view().tags.keys() {
        if let Some(id) = embargo_id_of_branch(name) {
            if !repo.keys().embargo_released(id) && !withdrawn.iter().any(|w| w == id) {
                ids.insert(id.to_string());
            }
        }
    }
    for key in repo.view().remote_tags.keys() {
        if let Some((_, name)) = key.split_once('/') {
            if let Some(id) = embargo_id_of_branch(name) {
                if !repo.keys().embargo_released(id) && !withdrawn.iter().any(|w| w == id) {
                    ids.insert(id.to_string());
                }
            }
        }
    }
    let mut out = Vec::new();
    for id in ids {
        let branch = embargo_branch(&id);
        let has_tag = repo.view().tags.contains_key(&branch)
            || repo.view().remote_tags.keys().any(|k| k.ends_with(&format!("/{branch}")));
        let has_merge = visible_merges.iter().any(|m| {
            repo.snapshot(m).ok().and_then(|s| s.embargo.clone()).as_deref() == Some(id.as_str())
        });
        if has_tag || has_merge {
            out.push(id);
        }
    }
    Ok(out)
}

/// Follow embargo `id`: rebase its hidden line (`embargo/<id>`) onto the
/// newest tip of `target_branch` when `target_branch` moved ahead of the
/// embargoed merge's first parent, and (when `switch_wc` is true) attach
/// workspace `ws` to the embargo line.
pub fn follow(
    repo: &mut crate::repo::Repo,
    ws: &str,
    id: &str,
    target_branch: &str,
    switch_wc: bool,
) -> Result<FollowResult> {
    use crate::oplog::Tag;

    if repo.keys().embargo_released(id) {
        return Err(VeilError::Policy(format!("embargo {id} is already released")));
    }
    let branch = embargo_branch(id);
    let tip = if let Some(t) = repo.view().tags.get(&branch) {
        t.target
    } else if let Some(t) = repo
        .view()
        .remote_tags
        .iter()
        .find_map(|(k, v)| k.ends_with(&format!("/{branch}")).then_some(*v))
    {
        t
    } else {
        let mut found = None;
        for m in repo.exact().visible_embargoed()? {
            if repo.snapshot(&m)?.embargo.as_deref() == Some(id) {
                found = Some(m);
                break;
            }
        }
        let m = found.ok_or_else(|| VeilError::NotFound(format!("embargo '{id}'")))?;
        match repo.view().tags.get(target_branch) {
            Some(t) if t.target == m || repo.is_ancestor(&m, &t.target)? => t.target,
            _ => m,
        }
    };
    let mut cur = tip;
    let merge_id = loop {
        let s = repo.snapshot(&cur)?;
        if s.embargo.as_deref() == Some(id) {
            break cur;
        }
        match s.parents.first() {
            Some(p) if *p != repo.root_id() => cur = *p,
            _ => {
                let mut found = None;
                for cand in repo.exact().embargoed_among([tip])? {
                    if repo.snapshot(&cand)?.embargo.as_deref() == Some(id) {
                        found = Some(cand);
                        break;
                    }
                }
                break found.ok_or_else(|| VeilError::NotFound(format!("embargo '{id}'")))?;
            }
        }
    };
    let merge_snap = repo.snapshot(&merge_id)?;
    let old_base = *merge_snap
        .parents
        .first()
        .ok_or_else(|| VeilError::Corrupt(merge_id.hex(), "embargoed merge has no parents".into()))?;
    let remote_main = repo.view().remote_tags.get(&format!("origin/{target_branch}")).copied();
    let local_main = repo.view().tags.get(target_branch).map(|t| t.target);
    let mut main_tip = old_base;
    for cand in [remote_main, local_main].into_iter().flatten() {
        if repo.carried_embargo(&cand)?.is_none()
            && (cand == main_tip || repo.is_ancestor(&main_tip, &cand)?)
        {
            main_tip = cand;
        }
    }
    let rec = repo.keys().load_embargo(id)?.unwrap_or(crate::keychain::EmbargoRecord {
        format: crate::keychain::EMBARGO_FORMAT,
        id: id.to_string(),
        scope: "team".to_string(),
        until: None,
        released_at: None,
        created: merge_snap.timestamp,
        state: None,
        reason: None,
    });

    let mut tx = repo.transaction(format!("follow embargo {id}"))?;
    tx.view.tags.insert(branch.clone(), Tag { target: tip, annotation: None });
    if let Some(lm) = local_main {
        if tx.repo().carried_embargo(&lm)?.as_deref() == Some(id) && tx.repo().carried_embargo(&main_tip)?.is_none() {
            tx.view.tags.insert(target_branch.to_string(), Tag { target: main_tip, annotation: None });
        }
    }
    let mut rebased = false;
    let mut new_merge_id = merge_id;
    if main_tip != old_base && tx.repo().is_ancestor(&old_base, &main_tip)? {
        let mut new_parents = vec![main_tip];
        new_parents.extend_from_slice(&merge_snap.parents[1..]);
        let out = tx.repo().rebase_tree(&merge_snap.parents, &new_parents, merge_snap.tree)?;
        let mut ns = (*merge_snap).clone();
        ns.parents = new_parents;
        ns.tree = out.tree;
        ns.predecessors = vec![merge_id];
        ns.conflicts.extend(out.conflicts.iter().map(|p| p.to_string()));
        ns.conflicts.sort();
        ns.conflicts.dedup();
        new_merge_id = tx.rewrite(merge_id, ns)?;
        tx.rebase_now()?;
        rebased = new_merge_id != merge_id;
    }
    let new_tip = tx.view.tags.get(&branch).map(|t| t.target).unwrap_or(new_merge_id);
    let mut conflicts = tx.repo().snapshot(&new_merge_id)?.conflicts.clone();
    for c in &tx.repo().snapshot(&new_tip)?.conflicts {
        if !conflicts.contains(c) {
            conflicts.push(c.clone());
        }
    }
    let wc = if switch_wc {
        if !conflicts.is_empty() {
            tx.set_workspace_wc(ws, new_merge_id)?;
            new_merge_id
        } else {
            let cur_wc = tx.view.workspace(ws)?.wc;
            let cur_s = tx.repo().snapshot(&cur_wc)?;
            if cur_s.parents == [new_tip] && tx.repo().is_empty_change(&cur_wc)? {
                cur_wc
            } else {
                let wc = tx.new_change(vec![new_tip], "")?;
                tx.set_workspace_wc(ws, wc)?;
                wc
            }
        }
    } else {
        tx.view.workspace(ws)?.wc
    };
    tx.commit()?;
    Ok(FollowResult {
        id: id.to_string(),
        scope: rec.scope,
        until: rec.until,
        tip: new_tip,
        wc,
        rebased,
        conflicts,
    })
}
