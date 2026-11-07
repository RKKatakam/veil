//! `Repo::duplicate`: copy changes onto new parents as new changes (the
//! engine of `vl duplicate` and `vl cherry-pick`).
//!
//! A duplicate is a new change (a new change id, the source's author, the
//! time of the copy), signed by whoever made the copy. Its tree is the
//! auto-rebase merge of the source onto its new parents
//! ([`Repo::rebase_tree`]): what the source changed relative to the merge of
//! its own parents, applied to the merge of the new ones, so conflicts are
//! recorded as first-class conflict entries rather than refused, and renames
//! the new parents made are followed ([`crate::merge`]).
//!
//! Audiences (`docs/design/git-parity/1-blame-bisect-duplicate.md`, threat
//! review 11–16):
//! * a duplicate is a tree merge only: a sealed secret keeps the sealing it
//!   really has ([`crate::merge`] never reads a sealed file into a wider
//!   audience), so a duplicate publishes nothing;
//! * the description is kept as stored;
//! * a source an unreleased embargo withholds (the fix and how it was
//!   made, work built on it, and the embargoed line:
//!   [`crate::confinement`]) is refused unless every new parent is inside
//!   that same embargo: a copy elsewhere would publish the fix before the
//!   release (BUG-681: a change
//!   built on the fix that edits its files carried them out as conflicts).
//!   An embargoed merge itself is refused (release it first).
//!
//! One transaction per command: `vl undo` removes every duplicate (and, for
//! cherry-pick, puts `@` and the tags back) exactly.

use std::collections::{HashMap, HashSet};

use crate::{
    error::{Result, VeilError},
    id::{ChangeId, ObjectId},
    merge::FollowedRename,
    now_millis,
    object::{EntryKind, Snapshot, Text},
    repo::Repo,
    transaction::{dedup_parents, Transaction},
    tree::lookup,
    vpath::VPath,
};

/// How each duplicate is described.
#[derive(Clone, Debug, Default)]
pub struct DuplicateOptions {
    /// A new description for every duplicate; `None` keeps each source's
    /// as stored.
    pub message: Option<String>,
    /// Append `(duplicated from change ID)` to a plain description.
    pub record_origin: bool,
}

/// One change copied.
#[derive(Clone, Debug)]
pub struct Duplicated {
    pub source: ObjectId,
    pub duplicate: ObjectId,
    /// Paths that conflicted while applying the source's change.
    pub conflicts: Vec<VPath>,
    /// Renames the copy followed.
    pub renames: Vec<FollowedRename>,
}

/// What `vl cherry-pick` did.
#[derive(Clone, Debug)]
pub struct CherryPicked {
    pub duplicates: Vec<Duplicated>,
    /// The workspace's working copy, rebased onto the last duplicate.
    pub wc: ObjectId,
    /// Tags that pointed at the working copy's parent and moved to the last
    /// duplicate (as `vl commit` moves them).
    pub advanced: Vec<String>,
    /// Tags that pointed there but stayed, with the reason.
    pub kept: Vec<(String, crate::commands::TagKept)>,
}

/// Where the duplicates go.
enum Placement<'a> {
    /// Onto each source's own parents (those duplicated too are replaced
    /// by their duplicates).
    InPlace,
    /// Sources with no parent among the sources go onto these; the others
    /// onto their parents' duplicates.
    Onto(&'a [ObjectId]),
    /// One after the other: the first onto this, each next onto the
    /// previous duplicate (cherry-pick).
    Chain(ObjectId),
}

/// The `(duplicated from change ID)` line `-x` appends.
fn with_origin(text: &str, change: &ChangeId) -> String {
    let line = format!("(duplicated from change {})", change.short());
    match text.trim_end() {
        "" => line,
        t => format!("{t}\n\n{line}"),
    }
}

impl Repo {
    /// Copy `sources` as new changes onto `dest` (or, empty, onto each
    /// source's own parents), as `vl duplicate` does. A source whose
    /// parent is also a source goes onto that parent's duplicate, so a
    /// chain of changes is copied as a chain. One transaction.
    pub fn duplicate(&mut self, sources: &[ObjectId], dest: &[ObjectId], o: &DuplicateOptions) -> Result<Vec<Duplicated>> {
        let dest = dedup_parents(dest.to_vec());
        let placement = match dest.is_empty() {
            true => Placement::InPlace,
            false => Placement::Onto(&dest),
        };
        let mut tx = self.transaction("duplicate")?;
        let done = duplicate_in(&mut tx, sources, &placement, o)?;
        tx.set_description(describe_op("duplicate", &tx, &done)?);
        tx.commit()?;
        Ok(done)
    }

    /// `vl cherry-pick`: copy `sources`, one after the other, onto the
    /// working copy's parent (`@-`), then rebase the working copy onto the
    /// last copy. Tags at `@-` move to the last copy as `vl commit` moves
    /// them (never a release tag). One transaction.
    pub fn cherry_pick(&mut self, ws: &str, sources: &[ObjectId], o: &DuplicateOptions) -> Result<CherryPicked> {
        let mut tx = self.transaction("cherry-pick")?;
        let wc_id = tx.view.workspace(ws)?.wc;
        let wc = tx.repo().snapshot(&wc_id)?;
        let Some(&onto) = wc.parents.first() else {
            return Err(VeilError::repo("the working copy has no parent to cherry-pick onto"));
        };
        let done = duplicate_in(&mut tx, sources, &Placement::Chain(onto), o)?;
        let last = done.last().expect("at least one source").duplicate;
        // `@` moves on top, keeping what it changed (and its other parents).
        let mut parents = wc.parents.clone();
        parents[0] = last;
        let parents = dedup_parents(parents);
        let out = tx.repo().rebase_tree(&wc.parents, &parents, wc.tree)?;
        let mut ns = (*wc).clone();
        ns.parents = parents;
        ns.tree = out.tree;
        ns.predecessors = vec![wc_id];
        ns.conflicts.extend(out.conflicts.iter().map(|p| p.to_string()));
        ns.conflicts.sort();
        ns.conflicts.dedup();
        let new_wc = tx.rewrite(wc_id, ns)?;
        let (mut advanced, kept) = (Vec::new(), Vec::new());
        for (name, tag) in tx.view.tags.iter_mut() {
            if tag.target != onto || tag.annotation.is_some() {
                continue;
            }
            tag.target = last;
            advanced.push(name.clone());
        }
        tx.set_description(describe_op("cherry-pick", &tx, &done)?);
        tx.commit()?;
        Ok(CherryPicked { duplicates: done, wc: new_wc, advanced, kept })
    }
}

/// `"<verb> change X"` or `"<verb> N changes"`.
fn describe_op(verb: &str, tx: &Transaction, done: &[Duplicated]) -> Result<String> {
    Ok(match done {
        [one] => format!("{verb} change {}", tx.repo().snapshot(&one.source)?.change_id.short()),
        many => format!("{verb} {} changes", many.len()),
    })
}

/// `sources` in an order where a source comes after every source that is
/// its parent; otherwise as given (first occurrence). Iterative.
fn parents_first(tx: &Transaction, sources: &[ObjectId]) -> Result<Vec<ObjectId>> {
    let set: HashSet<ObjectId> = sources.iter().copied().collect();
    let mut placed: HashSet<ObjectId> = HashSet::new();
    let mut order = Vec::with_capacity(set.len());
    for s in sources {
        let mut stack = vec![(*s, false)];
        while let Some((id, expanded)) = stack.pop() {
            if placed.contains(&id) {
                continue;
            }
            if expanded {
                placed.insert(id);
                order.push(id);
                continue;
            }
            stack.push((id, true));
            for p in tx.repo().snapshot(&id)?.parents.iter().rev() {
                if set.contains(p) && !placed.contains(p) {
                    stack.push((*p, false));
                }
            }
        }
    }
    Ok(order)
}

fn duplicate_in(tx: &mut Transaction, sources: &[ObjectId], placement: &Placement, o: &DuplicateOptions) -> Result<Vec<Duplicated>> {
    if sources.is_empty() {
        return Err(VeilError::repo("nothing to duplicate"));
    }
    if let Some(m) = &o.message {
        if m.contains('\0') {
            return Err(VeilError::repo("a description cannot contain a NUL character"));
        }
    }
    let root = tx.repo().root_id();
    let order = parents_first(tx, sources)?;
    // Which unreleased embargo each source and parent belongs to: its
    // withheld history, and what builds on it (BUG-681).
    let mut confined = crate::confinement::Confinement::new(tx.repo())?;
    let store = tx.repo().store.clone();
    let mut copy_of: HashMap<ObjectId, ObjectId> = HashMap::new();
    // Duplicates made inside an embargo (their source was withheld by it).
    let mut inside: HashMap<ObjectId, String> = HashMap::new();
    let mut done = Vec::with_capacity(order.len());
    let mut prev: Option<ObjectId> = None;
    for src in order {
        if src == root {
            return Err(VeilError::repo("the root snapshot cannot be duplicated"));
        }
        let s = tx.repo().snapshot(&src)?;
        if let Some(e) = &s.embargo {
            if !tx.repo().keys().embargo_released(e) {
                return Err(VeilError::Policy(format!(
                    "cannot duplicate {}: it is the merge of unreleased embargo {e}; release the embargo first (`vl embargo release {e}`)",
                    src.short()
                )));
            }
        }
        let mapped: Vec<ObjectId> = s.parents.iter().filter_map(|p| copy_of.get(p).copied()).collect();
        let parents = match placement {
            Placement::InPlace => s.parents.iter().map(|p| copy_of.get(p).copied().unwrap_or(*p)).collect(),
            Placement::Onto(dest) if mapped.is_empty() => dest.to_vec(),
            Placement::Onto(_) => mapped,
            Placement::Chain(onto) => vec![prev.unwrap_or(*onto)],
        };
        let parents = dedup_parents(parents);
        // Threat review 11: never copy withheld fix history out of its
        // embargo.
        let mut within: Option<String> = None;
        if let Some(e) = confined.of(tx.repo(), &src)? {
            // Inside: on the fix line (withheld, or built on it).
            let mut all_inside = true;
            for p in &parents {
                all_inside &= inside.get(p) == Some(&e) || confined.of_history(tx.repo(), p)?.as_ref() == Some(&e);
            }
            if !all_inside {
                return Err(VeilError::Policy(format!(
                    "cannot duplicate {}: unreleased embargo {e} withholds it (it is part of the fix, built on it, or on the embargoed line), and a copy outside the embargo would publish its file names before the release; duplicate it onto a change inside the embargo, or merge the fix with `vl merge --embargo`",
                    src.short()
                )));
            }
            within = Some(e);
        }
        let out = tx.repo().rebase_tree(&s.parents, &parents, s.tree)?;
        let description = match &o.message {
            Some(m) => Text::Plain(m.clone()),
            None => match &s.description {
                Text::Plain(t) if o.record_origin => Text::Plain(with_origin(t, &s.change_id)),
                Text::Plain(t) => Text::Plain(t.clone()),
            },
        };
        // Conflicts: those of applying the change, plus older kinds the
        // source recorded (markers, files moved aside) that the copy holds
        // as the source does. Conflict entries are indexed from the tree.
        let mut conflicts: Vec<String> = out.conflicts.iter().map(|p| p.to_string()).collect();
        for c in &s.conflicts {
            let Ok(p) = VPath::new(c) else { continue };
            let Some(e) = lookup(&store, &s.tree, &p).ok().flatten() else { continue };
            if e.kind != EntryKind::Conflict && lookup(&store, &out.tree, &p).ok().flatten().as_ref() == Some(&e) {
                conflicts.push(c.clone());
            }
        }
        conflicts.sort();
        conflicts.dedup();
        let snap = Snapshot {
            parents,
            change_id: ChangeId::random(),
            tree: out.tree,
            description,
            author: s.author.clone(),
            timestamp: now_millis(),
            predecessors: vec![],
            conflicts,
            embargo: None,
            signature: None, // signed by the transaction
        };
        let id = tx.write_snapshot(&snap)?;
        copy_of.insert(src, id);
        if let Some(e) = within {
            inside.insert(id, e);
        }
        prev = Some(id);
        done.push(Duplicated {
            source: src,
            duplicate: id,
            conflicts: out.conflicts,
            renames: out.renames,
        });
    }
    Ok(done)
}
