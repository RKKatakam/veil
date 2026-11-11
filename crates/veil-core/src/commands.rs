//! High-level history operations. Each is one transaction → one op-log entry.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    embargo::{normalize_tree, policy_rekeys, NormalizeOptions, NormalizeReport},
    error::{Result, VeilError},
    id::{ChangeId, ObjectId},
    keychain::{ReleaseState, TakeBack},
    now_millis,
    object::{Snapshot, Text, TreeEntry},
    oplog::Tag,
    policy::{Policy, POLICY_FILE},
    repo::Repo,
    selection::{self, Selection, Unit},
    store::ObjectStore,
    tag_object::{Atag, AtagVerification},
    transaction::{dedup_parents, Transaction},
    tree::{lookup, TreeView},
    vpath::VPath,
};

/// How [`Repo::set_tag_with`] sets a tag (`vl tag set`).
#[derive(Debug, Clone, Default)]
pub struct TagSpec {
    /// Allow moving a plain tag to a snapshot that is not a descendant.
    pub allow_backwards: bool,
    /// Make an annotated release tag with this message (`-a`, `-m`).
    pub annotate: Option<String>,
    /// Replace an existing release tag, or turn a plain tag into one.
    pub force: bool,
}

/// What [`Repo::set_tag_with`] did.
#[derive(Debug, Clone, Default)]
pub struct SetTagOutcome {
    /// The tag's atag, for a release tag.
    pub annotation: Option<ObjectId>,
    /// The atag a `--force` replaced.
    pub replaced: Option<ObjectId>,
    /// The new atag is signed with this repository's identity.
    pub signed: bool,
    /// Nothing changed: the release tag already points there.
    pub unchanged: bool,
}

/// A release tag's annotation as [`Repo::tag_annotation`] reads it.
#[derive(Debug, Clone)]
pub struct TagCheck {
    pub id: ObjectId,
    pub atag: Atag,
    pub verification: AtagVerification,
    /// The ring's name for the signer, when the signing key is a known
    /// member's (or this identity's).
    pub signer: Option<String>,
    /// A valid Veil signature by a known key.
    pub verified: bool,
    /// The message, `None` if sealed for a scope you are not in.
    pub message: Option<String>,
}

/// Description prefix of the operation that releases an embargo.
pub const RELEASE_OP_PREFIX: &str = "release embargo ";

/// Where a staged release stands by the op log
/// ([`Repo::staged_release_standing`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Standing {
    /// Its operation is in the heads' history, not taken back: a push
    /// publishes it.
    InForce,
    /// An undo or op restore in force took it back: a push does not.
    TakenBack,
    /// The op log holds no operation of it: a push does not.
    Unconfirmed,
}

#[derive(Debug, Clone)]
pub struct EmbargoSpec {
    /// Scope whose members can see the merged content before release.
    pub scope: String,
    /// Automatic release time (ms since epoch), `None` for manual release.
    pub until: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct MergeResult {
    pub snapshot: ObjectId,
    pub conflicts: Vec<String>,
    pub embargo: Option<String>,
    /// Visibility changes the merge refused to make silently.
    pub warnings: Vec<String>,
    /// Renames the merge followed (this reader's report; never stored).
    pub renames: Vec<crate::merge::FollowedRename>,
}

/// [`Repo::commit`] inside transaction `tx`. With `recorded`, the working
/// copy's content is that (the automatic snapshot of `vl commit`, recorded
/// in the same transaction as the commit: one operation, so `vl undo`
/// takes back both); without, the working copy as it is.
pub(crate) fn commit_in(tx: &mut Transaction, ws: &str, message: &str, advance: bool, recorded: Option<Snapshot>) -> Result<CommitResult> {
    let wc_id = tx.view.workspace(ws)?.wc;
    let s = tx.repo().snapshot(&wc_id)?;
    let mut ns = recorded.unwrap_or_else(|| (*s).clone());
    ns.description = Text::Plain(message.to_string());
    ns.predecessors = vec![wc_id];
    ns.timestamp = now_millis();
    let committed = tx.rewrite(wc_id, ns)?;
    let (mut advanced, mut kept) = (Vec::new(), Vec::new());
    for (name, tag) in tx.view.tags.iter_mut() {
        if s.parents.first() != Some(&tag.target) {
            continue;
        }
        match tag_kept(tag, advance) {
            None => {
                tag.target = committed;
                advanced.push(name.clone());
            }
            Some(why) => kept.push((name.clone(), why)),
        }
    }
    let wc = tx.new_change(vec![committed], "")?;
    tx.set_workspace_wc(ws, wc)?;
    tx.set_description(format!("commit change {}", s.change_id.short()));
    Ok(CommitResult {
        committed,
        wc,
        advanced,
        kept,
    })
}

/// What [`Repo::commit`] did.
#[derive(Debug, Clone)]
pub struct CommitResult {
    /// The committed change.
    pub committed: ObjectId,
    /// The workspace's new (empty) working-copy change.
    pub wc: ObjectId,
    /// Tags that pointed at the committed change's parent and moved to it.
    pub advanced: Vec<String>,
    /// Tags that pointed at the parent but stayed, with the reason.
    pub kept: Vec<(String, TagKept)>,
}

/// Why a tag at the parent of a commit did not move with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TagKept {
    /// The caller asked for no tag to move (`vl commit --no-advance`).
    NoAdvance,
    /// An annotated release tag: immutable (`vl tag set --force` moves it).
    Release,
}

/// Which tags a commit moves (see [`Repo::commit`]): `None` if `tag` may
/// advance, else why it stays.
fn tag_kept(tag: &Tag, advance: bool) -> Option<TagKept> {
    if tag.annotation.is_some() {
        // A release tag is immutable: commits never move it.
        return Some(TagKept::Release);
    }
    (!advance).then_some(TagKept::NoAdvance)
}

/// `tree` with its root entry `name` replaced by `entry` (or removed).
fn with_root_entry(store: &ObjectStore, tree: &ObjectId, name: &str, entry: Option<TreeEntry>) -> Result<ObjectId> {
    let mut t = (*store.tree(tree)?).clone();
    match entry {
        Some(e) => t.insert(e),
        None => {
            t.remove(name);
        }
    }
    store.put_tree(&t)
}

/// A change taken apart for [`Repo::split`] and [`Repo::squash_into`]
/// ([`Repo::change_parts`]).
#[derive(Clone, Debug)]
pub struct ChangeParts {
    pub id: ObjectId,
    /// The merge of its parents' trees.
    pub base: ObjectId,
    pub tree: ObjectId,
    pub units: Vec<Unit>,
    /// Folders whose tree the server refuses: kept where they are, never
    /// units (BUG-1529).
    pub hidden: Vec<VPath>,
}

/// What [`Repo::split`] made.
/// What [`Repo::drop_attempt`] wrote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DroppedAttempt {
    /// The abandoned snapshot that records the attempt.
    pub attempt: ObjectId,
    /// The change's new version, started again from its parents.
    pub change: ObjectId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SplitResult {
    /// The new change with the chosen part, on the original's parents.
    pub first: ObjectId,
    /// The original change (same change id) with the rest, on `first`.
    pub second: ObjectId,
}

/// What [`Repo::squash_into`] did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SquashResult {
    /// The destination, with the moved part.
    pub destination: ObjectId,
    /// The source with what stayed; `None` when everything moved (it was
    /// abandoned).
    pub source: Option<ObjectId>,
    /// Everything moved.
    pub emptied: bool,
}

/// Refuse to rewrite from a stale reading: every one of `ids` must still be
/// in the history, and `parts` must still describe `s` (an interactive
/// choice can take minutes, and `vl watch` or another command may have
/// rewritten the change meanwhile).
fn check_current(repo: &Repo, ids: &[ObjectId], parts: &ChangeParts, s: &Snapshot) -> Result<()> {
    // Exactly: in a thin clone the change may be one beyond what it holds
    // until this command (BUG-1290).
    let visible = repo.exact().visible_among(&ids.iter().copied().collect())?;
    for i in ids {
        if !visible.contains(i) {
            return Err(VeilError::repo(format!(
                "snapshot {} is no longer in the history (it was rewritten meanwhile): run the command again",
                i.short()
            )));
        }
    }
    if s.tree != parts.tree || repo.parents_tree(&s.parents)?.tree != parts.base {
        return Err(VeilError::repo("the change moved while its parts were being chosen: run the command again"));
    }
    Ok(())
}

/// The conflicts `s` records whose entry `tree` holds exactly as `s` does
/// (moved there whole, or untouched).
fn moved_conflicts(store: &ObjectStore, s: &Snapshot, tree: &ObjectId) -> Vec<String> {
    s.conflicts
        .iter()
        .filter(|c| {
            let Ok(path) = VPath::new(c) else { return false };
            let there = lookup(store, &s.tree, &path).ok().flatten();
            there.is_some() && there == lookup(store, tree, &path).ok().flatten()
        })
        .cloned()
        .collect()
}

pub fn validate_tag_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && !name.ends_with('-')
        && !name.ends_with('@')
        && !name.contains("..")
        && name != "root"
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'/'));
    if ok {
        Ok(())
    } else {
        Err(VeilError::repo(format!("invalid tag name '{name}'")))
    }
}

impl Repo {
    /// The unreleased embargo that snapshot `id` carries, if any: one of its
    /// ancestors (itself included) is an embargoed merge whose embargo has
    /// not been released. An embargo this
    /// repository has no record of counts as unreleased.
    pub fn carried_embargo(&self, id: &ObjectId) -> Result<Option<String>> {
        // Embargoed snapshots come from the history index: with none in
        // the history, nothing is walked.
        let mut carried: Vec<ObjectId> = self.exact().embargoed_among([*id])?.into_iter().collect();
        carried.sort();
        for a in carried {
            let Some(s) = self.exact().snapshot(&a)? else { continue };
            if let Some(e) = &s.embargo {
                if !self.keys().embargo_released(e) {
                    return Ok(Some(e.clone()));
                }
            }
        }
        Ok(None)
    }

    /// Start a new change on top of `parents` in workspace `ws`.
    pub fn new_change(&mut self, ws: &str, parents: Vec<ObjectId>, message: &str) -> Result<ObjectId> {
        let mut tx = self.transaction("new change")?;
        let id = tx.new_change(parents, message)?;
        tx.set_workspace_wc(ws, id)?;
        let change = tx.repo().snapshot(&id)?.change_id;
        tx.set_description(format!("new change {}", change.short()));
        tx.commit()?;
        Ok(id)
    }

    pub fn describe(&mut self, id: ObjectId, message: &str) -> Result<ObjectId> {
        let mut tx = self.transaction("describe")?;
        let s = tx.repo().snapshot(&id)?;
        let mut ns = (*s).clone();
        // The same message: nothing to do (BUG-246).
        if s.description.as_str() == message {
            return Ok(id);
        }
        ns.description = Text::Plain(message.to_string());
        ns.predecessors = vec![id];
        let new = tx.rewrite(id, ns)?;
        tx.set_description(format!("describe change {}", s.change_id.short()));
        tx.commit()?;
        Ok(new)
    }

    /// Record change `id`'s content as an abandoned attempt with `reason`,
    /// and start the change again from its parents (`vl attempt drop`,
    /// `docs/design/server/phase-2-thin-clients.md` §5.6).
    ///
    /// The attempt is a copy of the version `id` with `abandoned` set
    /// (signed by this identity, its attribution kept); the change's new
    /// version has its parents' content, names the attempt as its
    /// predecessor and lists it, after the attempts it had, in `attempts`.
    /// Descendants are rebased onto the new version. At most
    /// [`crate::object::MAX_ATTEMPTS`] attempts per change.
    pub fn drop_attempt(&mut self, id: ObjectId, reason: &str) -> Result<DroppedAttempt> {
        if id == self.root_id {
            return Err(VeilError::repo("the root snapshot has no attempts"));
        }
        crate::object::validate_reason(reason).map_err(VeilError::repo)?;
        let mut tx = self.transaction("attempt drop")?;
        let s = tx.repo().snapshot(&id)?;
        if s.attempts.len() >= crate::object::MAX_ATTEMPTS {
            return Err(VeilError::repo(format!(
                "change {} already keeps {} attempts, the most a change keeps; start a new change (`vl new`) \
                 or abandon this one (`vl abandon`)",
                s.change_id.short(),
                crate::object::MAX_ATTEMPTS
            )));
        }
        let base = tx.repo().parents_tree(&s.parents)?;
        if base.tree == s.tree {
            return Err(VeilError::repo(format!(
                "change {} is empty: there is no attempt to drop",
                s.change_id.short()
            )));
        }
        let mut attempt = (*s).clone();
        attempt.abandoned = Some(reason.to_string());
        attempt.attempts = vec![];
        let attempt_id = tx.repo.store.put_snapshot(&tx.signed(&attempt))?;
        let mut ns = (*s).clone();
        ns.tree = base.tree;
        ns.conflicts = base.conflicts.iter().map(|p| p.to_string()).collect();
        ns.predecessors = vec![attempt_id];
        ns.attempts.push(attempt_id);
        ns.timestamp = now_millis();
        let new = tx.rewrite(id, ns)?;
        tx.set_description(format!("drop an attempt of change {}", s.change_id.short()));
        tx.commit()?;
        Ok(DroppedAttempt { attempt: attempt_id, change: new })
    }

    /// Describe the working copy and start a fresh change on top of it,
    /// moving tags as [`Repo::commit`] does with `advance`. Returns
    /// `(committed, new working copy)`.
    pub fn commit_working_copy(&mut self, ws: &str, message: &str) -> Result<(ObjectId, ObjectId)> {
        let r = self.commit(ws, message, true)?;
        Ok((r.committed, r.wc))
    }

    /// Describe the working copy of `ws` and start a fresh change on top of
    /// it.
    ///
    /// **Tags.** A tag pointing at the working copy's (first) parent moves
    /// to the commit, so committing on `main` moves `main`, except:
    ///
    /// * a release tag (annotated) never moves;
    /// * with `advance == false` (`vl commit --no-advance`), no tag moves.
    ///
    /// Tags that stayed are reported in [`CommitResult::kept`].
    pub fn commit(&mut self, ws: &str, message: &str, advance: bool) -> Result<CommitResult> {
        let mut tx = self.transaction("commit")?;
        let r = commit_in(&mut tx, ws, message, advance, None)?;
        tx.commit()?;
        Ok(r)
    }

    pub fn edit(&mut self, ws: &str, id: ObjectId) -> Result<()> {
        let mut tx = self.transaction("edit")?;
        tx.set_workspace_wc(ws, id)?;
        let change = tx.repo().snapshot(&id)?.change_id;
        tx.set_description(format!("edit change {}", change.short()));
        tx.commit()?;
        Ok(())
    }

    pub fn abandon(&mut self, id: ObjectId) -> Result<()> {
        let mut tx = self.transaction("abandon")?;
        let change = tx.repo().snapshot(&id)?.change_id;
        tx.abandon(id)?;
        tx.set_description(format!("abandon change {}", change.short()));
        tx.commit()?;
        Ok(())
    }

    /// Move `source` (and, automatically, its descendants) onto `dest`.
    ///
    /// Rebasing onto the parents `source` already has changes nothing
    /// (BUG-246).
    pub fn rebase(&mut self, source: ObjectId, dest: Vec<ObjectId>) -> Result<ObjectId> {
        Ok(self.rebase_reporting(source, dest)?.0)
    }

    /// [`Repo::rebase`], also returning the renames moving `source` followed
    /// (a file the destination renamed gets the change's edit at its new
    /// name).
    pub fn rebase_reporting(&mut self, source: ObjectId, dest: Vec<ObjectId>) -> Result<(ObjectId, Vec<crate::merge::FollowedRename>)> {
        let dest = dedup_parents(dest);
        if dest.is_empty() {
            return Err(VeilError::repo("rebase needs at least one destination"));
        }
        if self.snapshot(&source)?.parents == dest {
            return Ok((source, vec![]));
        }
        for d in &dest {
            if self.is_ancestor(&source, d)? {
                return Err(VeilError::repo("cannot rebase a change onto itself or its descendant"));
            }
        }
        let mut tx = self.transaction("rebase")?;
        tx.keep_attribution();
        let s = tx.repo().snapshot(&source)?;
        let out = tx.repo().rebase_tree(&s.parents, &dest, s.tree)?;
        let mut ns = (*s).clone();
        ns.parents = dest;
        ns.tree = out.tree;
        ns.predecessors = vec![source];
        ns.conflicts.extend(out.conflicts.iter().map(|p| p.to_string()));
        ns.conflicts.sort();
        ns.conflicts.dedup();
        let id = tx.rewrite(source, ns)?;
        tx.set_description(format!("rebase change {}", s.change_id.short()));
        tx.commit()?;
        Ok((id, out.renames))
    }

    /// Fold a change into its (single) parent.
    pub fn squash(&mut self, id: ObjectId) -> Result<ObjectId> {
        Ok(self.squash_into(id, None, None)?.destination)
    }

    /// A change taken apart for [`Repo::split`] and [`Repo::squash_into`]:
    /// its base (the merge of its parents), its tree and its
    /// [`selection::Unit`]s. With `by_hunk`, every unit is classified
    /// (`selection::classify`, which reads the files), so its hunks can be
    /// chosen; without, units are taken whole and no content is read.
    pub fn change_parts(&self, id: &ObjectId, by_hunk: bool) -> Result<ChangeParts> {
        if *id == self.root_id {
            return Err(VeilError::repo("the root snapshot has no changes"));
        }
        let s = self.snapshot(id)?;
        let base = self.parents_tree(&s.parents)?.tree;
        let (mut units, hidden) = selection::units(&self.store, &base, &s.tree)?;
        if by_hunk {
            // In a thin clone, each side asked for at its own path
            // (BUG-1506).
            crate::tree::prefetch_changes(&self.store, Some(&base), Some(&s.tree), units.iter().flat_map(|u| &u.changes))?;
            for u in &mut units {
                selection::classify(&self.store, u, &s.conflicts)?;
            }
        }
        Ok(ChangeParts { id: *id, base, tree: s.tree, units, hidden })
    }

    /// `vl split`: split change `parts.id` in two. The **first** change, on
    /// the original's parents, holds what `sel` chooses and gets a new
    /// change id and `message` (empty by default). The **second**, its
    /// child, holds the rest and stays the original change: the same
    /// change id, description, cloak, and the same tree, so its descendants,
    /// tags and working copies follow it with nothing to rebase. Nothing's
    /// audience changes (see [`selection`]).
    ///
    /// Refused when either change would be empty (nothing chosen, or
    /// everything), for an embargoed merge, and when the change moved since
    /// `parts` was read.
    pub fn split(&mut self, parts: &ChangeParts, sel: &Selection, message: Option<&str>) -> Result<SplitResult> {
        let id = parts.id;
        let mut tx = self.transaction("split")?;
        tx.keep_sealing();
        let s = tx.repo().snapshot(&id)?;
        check_current(tx.repo(), &[id], parts, &s)?;
        if s.embargo.is_some() {
            return Err(VeilError::Policy("an embargoed merge cannot be split".into()));
        }
        let store = tx.repo().store.clone();
        let h = selection::halves_hiding(&store, &parts.base, &parts.tree, &parts.units, &parts.hidden, sel)?;
        if !h.any {
            return Err(VeilError::repo(
                "nothing chosen: the first change would be empty (choose at least one file or hunk; `vl new -B` is not needed to start an empty change before it, `vl new REV-` does that)",
            ));
        }
        if h.all {
            return Err(VeilError::repo(
                "everything chosen: the second change would be empty (to change only the description, use `vl describe`)",
            ));
        }
        let first = Snapshot {
            parents: s.parents.clone(),
            change_id: ChangeId::random(),
            tree: h.chosen,
            description: Text::Plain(message.unwrap_or("").to_string()),
            author: s.author.clone(),
            timestamp: s.timestamp,
            predecessors: vec![id],
            conflicts: moved_conflicts(&store, &s, &h.chosen),
            embargo: None,
            agent: s.agent.clone(),
            abandoned: None,
            attempts: vec![],
            signature: None,
        };
        let first_id = tx.write_snapshot(&first)?;
        let mut second = (*s).clone();
        second.parents = vec![first_id];
        second.predecessors = vec![id];
        let second_id = tx.rewrite(id, second)?;
        tx.set_description(format!("split change {}", s.change_id.short()));
        tx.commit()?;
        Ok(SplitResult { first: first_id, second: second_id })
    }

    /// `vl squash`: move what `part` chooses of change `id` (all of it for
    /// `None`) into `into`, by default its single parent. The source keeps
    /// its change id, description and recorded attempts and holds the rest;
    /// when nothing is left it is abandoned and its description and attempts
    /// are joined to the destination's.
    ///
    /// * into its **parent**: the parent gets the chosen part; the source's
    ///   own tree is unchanged (it already held everything);
    /// * into an **ancestor**: the chosen part is merged into it, the
    ///   changes in between are rebased onto it, and the source keeps its
    ///   tree;
    /// * into a **descendant**: the source keeps the rest, the changes in
    ///   between are rebased without the chosen part, and the destination
    ///   keeps its tree;
    /// * into an **unrelated** change: the source keeps the rest and the
    ///   chosen part is merged into the destination.
    ///
    /// Descendants are rebased. One transaction: `vl undo` restores
    /// everything.
    pub fn squash_into(&mut self, id: ObjectId, into: Option<ObjectId>, part: Option<(&ChangeParts, &Selection)>) -> Result<SquashResult> {
        let mut tx = self.transaction("squash")?;
        let s = tx.repo().snapshot(&id)?;
        if id == tx.repo().root_id {
            return Err(VeilError::repo("the root snapshot cannot be squashed"));
        }
        let dest = match into {
            Some(d) => d,
            None => match s.parents.as_slice() {
                [p] => *p,
                _ => return Err(VeilError::repo("can only squash a change with exactly one parent (name a destination with --into)")),
            },
        };
        if dest == tx.repo().root_id {
            return Err(VeilError::repo("cannot squash into the root snapshot"));
        }
        if dest == id {
            return Err(VeilError::repo("cannot squash a change into itself"));
        }
        // Never fold an embargoed fix (or work built on it) into a change
        // outside its embargo (BUG-681).
        crate::confinement::Confinement::new(tx.repo())?.check_copy(tx.repo(), "cannot squash", &[id], &[dest])?;
        let store = tx.repo().store.clone();
        let into_parent = s.parents == [dest];
        let (base, chosen, rest, all) = match part {
            Some((parts, sel)) => {
                if parts.id != id {
                    return Err(VeilError::repo("internal: the selection is of another change"));
                }
                check_current(tx.repo(), &[id, dest], parts, &s)?;
                let h = selection::halves_hiding(&store, &parts.base, &parts.tree, &parts.units, &parts.hidden, sel)?;
                if !h.any {
                    return Err(VeilError::repo("nothing chosen: nothing to squash"));
                }
                (parts.base, h.chosen, h.rest, h.all)
            }
            None if into_parent => (tx.repo().snapshot(&dest)?.tree, s.tree, s.tree, true),
            None => {
                let base = tx.repo().parents_tree(&s.parents)?.tree;
                check_current(tx.repo(), &[id, dest], &ChangeParts { id, base, tree: s.tree, units: vec![], hidden: vec![] }, &s)?;
                (base, s.tree, base, true)
            }
        };
        let d = tx.repo().snapshot(&dest)?;
        if all && !s.attempts.is_empty() {
            let total = d.attempts.len() + s.attempts.iter().filter(|a| !d.attempts.contains(a)).count();
            if total > crate::object::MAX_ATTEMPTS {
                return Err(VeilError::repo(format!(
                    "cannot squash {} into {}: the destination would keep {total} attempts ({} + {}), more than the {} a change keeps",
                    s.change_id.short(),
                    d.change_id.short(),
                    d.attempts.len(),
                    s.attempts.len(),
                    crate::object::MAX_ATTEMPTS,
                )));
            }
        }
        // The destination as it ends up: `tree`, conflicts, and (if the
        // source is emptied) the joined description and attempts.
        let finish_dest = |tx: &Transaction, cur: ObjectId, tree: ObjectId, extra: Vec<String>| -> Result<Snapshot> {
            let now = tx.repo().snapshot(&cur)?;
            let mut nd = (*now).clone();
            nd.tree = tree;
            nd.predecessors = vec![cur, id];
            // A path stays conflicted only if the result still has the
            // conflict: the destination's conflicted files the squash left
            // untouched, and the source's own that moved.
            let mut conflicts = BTreeSet::new();
            for c in &now.conflicts {
                let Ok(path) = VPath::new(c) else { continue };
                let before = lookup(&store, &now.tree, &path).ok().flatten();
                if before.is_some() && before == lookup(&store, &nd.tree, &path).ok().flatten() {
                    conflicts.insert(c.clone());
                }
            }
            conflicts.extend(moved_conflicts(&store, &s, &nd.tree));
            conflicts.extend(extra);
            nd.conflicts = conflicts.into_iter().collect();
            if all {
                let pd = tx.repo().description(&now);
                let sd = tx.repo().description(&s);
                if !sd.trim().is_empty() {
                    let joined = if pd.trim().is_empty() { sd } else { format!("{pd}\n\n{sd}") };
                    nd.description = Text::Plain(joined);
                }
                for a in &s.attempts {
                    if !nd.attempts.contains(a) {
                        nd.attempts.push(*a);
                    }
                }
                if nd.attempts.len() > crate::object::MAX_ATTEMPTS {
                    return Err(VeilError::repo(format!(
                        "cannot squash {} into {}: the destination would keep {} attempts, more than the {} a change keeps",
                        s.change_id.short(),
                        d.change_id.short(),
                        nd.attempts.len(),
                        crate::object::MAX_ATTEMPTS,
                    )));
                }
            }
            Ok(nd)
        };
        // The source as it ends up, with `tree`; abandoned if emptied.
        let finish_source = |tx: &mut Transaction, cur: ObjectId, parents: Option<Vec<ObjectId>>, tree: ObjectId| -> Result<Option<ObjectId>> {
            if all {
                tx.abandon(cur)?;
                return Ok(None);
            }
            let mut ns = (*tx.repo().snapshot(&cur)?).clone();
            if let Some(p) = parents {
                ns.parents = p;
            }
            ns.tree = tree;
            ns.predecessors = vec![cur];
            ns.conflicts = s.conflicts.clone();
            Ok(Some(tx.rewrite(cur, ns)?))
        };
        let merge_into = |tree: ObjectId| -> Result<(ObjectId, Vec<String>)> {
            let out = crate::merge::merge_trees(&store, Some(base), tree, chosen)?;
            Ok((out.tree, out.conflicts.iter().map(|p| p.to_string()).collect()))
        };
        let (destination, source) = if into_parent {
            let nd = finish_dest(&tx, dest, chosen, vec![])?;
            let src_tree = s.tree;
            let new_dest = tx.rewrite(dest, nd)?;
            let source = finish_source(&mut tx, id, Some(vec![new_dest]), src_tree)?;
            (new_dest, source)
        } else if tx.repo().is_ancestor(&dest, &id)? {
            let (tree, extra) = merge_into(d.tree)?;
            let nd = finish_dest(&tx, dest, tree, extra)?;
            let src_tree = s.tree;
            let new_dest = tx.rewrite(dest, nd)?;
            tx.rebase_now()?;
            let cur = tx.current(id).ok_or_else(|| VeilError::repo("the change to squash disappeared while rebasing"))?;
            let source = finish_source(&mut tx, cur, None, src_tree)?;
            (new_dest, source)
        } else if tx.repo().is_ancestor(&id, &dest)? {
            let source = finish_source(&mut tx, id, None, rest)?;
            tx.rebase_now()?;
            let cur = tx.current(dest).ok_or_else(|| VeilError::repo("the destination disappeared while rebasing"))?;
            let nd = finish_dest(&tx, cur, d.tree, vec![])?;
            let new_dest = tx.rewrite(cur, nd)?;
            (new_dest, source)
        } else {
            let source = finish_source(&mut tx, id, None, rest)?;
            let (tree, extra) = merge_into(d.tree)?;
            let nd = finish_dest(&tx, dest, tree, extra)?;
            (tx.rewrite(dest, nd)?, source)
        };
        tx.set_description(format!("squash {} into {}", s.change_id.short(), d.change_id.short()));
        tx.commit()?;
        Ok(SquashResult { destination, source, emptied: all })
    }

    /// Merge `others` into `into`, producing a described merge snapshot; the
    /// workspace continues on a fresh change on top of it. Tags pointing at
    /// `into` advance to the merge.
    pub fn merge(
        &mut self,
        ws: &str,
        into: ObjectId,
        others: Vec<ObjectId>,
        message: &str,
        embargo: Option<EmbargoSpec>,
    ) -> Result<MergeResult> {
        // Each parent once (BUG-240): merging the destination into itself
        // merges nothing.
        let others: Vec<ObjectId> = dedup_parents(others).into_iter().filter(|o| *o != into).collect();
        if others.is_empty() {
            return Err(VeilError::repo(format!(
                "nothing to merge: {} is the change being merged into",
                into.short()
            )));
        }
        // Embargoes never overlap (Veil 1.0): a new embargoed merge is
        // refused if the line it merges into, or any line it merges in,
        // still carries an unreleased embargo.
        if embargo.is_some() {
            for (what, id) in std::iter::once(("the line it merges into", into)).chain(others.iter().map(|o| ("a line it merges in", *o))) {
                if let Some(e) = self.carried_embargo(&id)? {
                    return Err(VeilError::Policy(format!(
                        "cannot merge under a new embargo: {what} ({}) already carries unreleased embargo {e}, and embargoes cannot overlap; release the earlier embargo first (`vl embargo release {e}`), then merge",
                        id.short()
                    )));
                }
            }
        }
        let mut tx = self.transaction("merge")?;
        let mut parents = vec![into];
        parents.extend(others.iter().copied());
        let into_snap = tx.repo().snapshot(&into)?;
        let store = tx.repo().store.clone();
        let merged = tx.repo().parents_tree(&parents)?;
        // An unreadable `.veilpolicy` on either side (a hostile tree's
        // directory, BUG-121) never blocks the merge: the accepted policy
        // applies there, with a warning.
        let accepted = crate::policy::load_accepted(&*tx.repo().backend).ok().flatten();
        let (dest_policy, w1) = Policy::load_or_accepted(&TreeView::new(store.clone(), into_snap.tree), accepted.as_deref())?;
        let (mut policy, w2) = Policy::load_or_accepted(&TreeView::new(store.clone(), merged.tree), accepted.as_deref())?;
        let mut warnings: Vec<String> = w1.into_iter().chain(w2).collect();
        warnings.dedup();
        let mut tree = merged.tree;

        // A merged `.veilpolicy` that would move an existing secret to
        // another audience (re-key it, or make it public) is not taken: the
        // destination's policy is kept and the member is told. Applying it
        // is a deliberate edit, not a side effect of merging someone's PR.
        let mut rekeys = policy_rekeys(&store, &into_snap.tree, &dest_policy, &policy)?;
        for r in policy_rekeys(&store, &tree, &dest_policy, &policy)? {
            if !rekeys.iter().any(|(p, _, _)| *p == r.0) {
                rekeys.push(r);
            }
        }
        if !rekeys.is_empty() {
            let dest_entry = store.tree(&into_snap.tree)?.get(POLICY_FILE).cloned();
            tree = with_root_entry(&store, &tree, POLICY_FILE, dest_entry)?;
            policy = dest_policy.clone();
            let list: Vec<String> = rekeys
                .iter()
                .map(|(p, from, to)| format!("{p}: {} → {}", from.label(), to.label()))
                .collect();
            warnings.push(format!(
                "kept the destination's {POLICY_FILE}: the merged one would change the audience of existing secrets ({}); review it and apply it deliberately",
                list.join(", ")
            ));
        }
        let mut report = NormalizeReport::default();
        tree = normalize_tree(
            &store,
            &tree,
            &NormalizeOptions {
                policy: &policy,
                dest_policy: &dest_policy,
                dest_tree: into_snap.tree,
            },
            &mut report,
        )?;
        let conflicts: Vec<String> = merged.conflicts.iter().map(|p| p.to_string()).collect();
        // The record is only created once the merge is known to be
        // possible. It is plain: embargoes are permissions, not encryption.
        let embargo_id = match &embargo {
            Some(spec) => Some(tx.repo().keys().create_embargo(&spec.scope, spec.until)?),
            None => None,
        };
        let description = Text::Plain(message.to_string());
        warnings.extend(report.kept_sealed.iter().map(|(p, why)| format!("{p} {why}")));
        let snap = Snapshot {
            parents,
            change_id: ChangeId::random(),
            tree,
            description,
            author: tx.repo().user.clone(),
            timestamp: now_millis(),
            predecessors: vec![],
            conflicts: conflicts.clone(),
            embargo: embargo_id.clone(),
            agent: None,
            abandoned: None,
            attempts: vec![],
            signature: None, // signed by the transaction
        };
        let m = tx.write_snapshot(&snap)?;
        for tag in tx.view.tags.values_mut() {
            // Release tags are immutable: a merge never moves one.
            if tag.target == into && tag.annotation.is_none() {
                tag.target = m;
            }
        }
        let wc = tx.new_change(vec![m], "")?;
        tx.set_workspace_wc(ws, wc)?;
        tx.set_description(match &embargo_id {
            Some(e) => format!("merge {} (embargo {e})", snap.change_id.short()),
            None => format!("merge {}", snap.change_id.short()),
        });
        tx.commit()?;
        Ok(MergeResult {
            snapshot: m,
            conflicts,
            embargo: embargo_id,
            warnings,
            renames: merged.renames,
        })
    }

    /// Create or move a plain (branch-like) tag. See [`Repo::set_tag_with`].
    pub fn set_tag(&mut self, name: &str, target: ObjectId, allow_backwards: bool) -> Result<()> {
        self.set_tag_with(
            name,
            target,
            &TagSpec {
                allow_backwards,
                ..TagSpec::default()
            },
        )
        .map(|_| ())
    }

    /// Create or move tag `name` (`vl tag set`).
    ///
    /// An annotated tag (`spec.annotate`, repository format 5) is a
    /// **release tag**: it names a `veil:atag` object holding the message,
    /// the tagger, the time and (when this repository has an identity) an
    /// Ed25519 signature over all of it, name and target included. A
    /// release tag is immutable: setting it again is refused unless
    /// `spec.force`, which writes a new atag (moving it anywhere, like `git
    /// tag -f`). The annotation is never dropped silently: forcing without
    /// a message keeps the old one, and turning a release tag back into a
    /// plain tag takes `vl tag delete` first. Commits and merges never
    /// advance a release tag.
    pub fn set_tag_with(&mut self, name: &str, target: ObjectId, spec: &TagSpec) -> Result<SetTagOutcome> {
        validate_tag_name(name)?;
        // A tag on anything but a snapshot (a blob, a tree) would break
        // every graph query that walks the view.
        match self.snapshot(&target) {
            Ok(_) => {}
            Err(VeilError::Corrupt(..)) | Err(VeilError::Json(_)) => {
                return Err(VeilError::repo(format!("{} is not a snapshot", target.short())))
            }
            Err(e) => return Err(e),
        }
        let existing = self.view.tags.get(name).cloned();
        if spec.annotate.is_some() && self.format() < crate::object::GIT_PARITY_REPO_FORMAT {
            return Err(VeilError::Unsupported(format!(
                "annotated tags need repository format {}; this one is at format {}: upgrade it with `vl upgrade`",
                crate::object::GIT_PARITY_REPO_FORMAT,
                self.format()
            )));
        }
        let mut old_annotation = None;
        if let Some(t) = &existing {
            match t.annotation {
                Some(a) => {
                    let unchanged = t.target == target && spec.annotate.is_none();
                    if unchanged && !spec.force {
                        return Ok(SetTagOutcome {
                            annotation: Some(a),
                            unchanged: true,
                            ..SetTagOutcome::default()
                        });
                    }
                    if !spec.force {
                        return Err(VeilError::repo(format!(
                            "tag '{name}' is an annotated release tag, and release tags are immutable; replace it with                              `vl tag set {name} --force`, or delete it first with `vl tag delete {name}`"
                        )));
                    }
                    old_annotation = Some(a);
                }
                None if spec.annotate.is_some() && !spec.force => {
                    return Err(VeilError::repo(format!(
                        "tag '{name}' already exists as a plain tag; make it an annotated release tag                          with --force, or pick another name"
                    )));
                }
                None => {}
            }
            if !spec.allow_backwards && !spec.force && !self.is_ancestor(&t.target, &target)? {
                return Err(VeilError::repo(format!(
                    "moving tag '{name}' would go backwards or sideways (use --allow-backwards)"
                )));
            }
        }
        // The annotation: a new message, or (forcing a release tag without
        // one) the old message, never dropped.
        let message = match (&spec.annotate, old_annotation) {
            (Some(m), _) => Some(m.clone()),
            (None, Some(a)) => Some(self.store().atag(&a)?.message.as_str().to_string()),
            (None, None) => None,
        };
        let mut signed = false;
        let annotation = match message {
            None => None,
            Some(m) => {
                let text = Text::Plain(m);
                let tagger: String = self.user.chars().filter(|c| !c.is_control()).take(crate::tag_object::MAX_TAGGER).collect();
                let mut a = Atag::annotated(name, target, text, &tagger, now_millis());
                if let Some(id) = self.identity() {
                    a.sign(id);
                    signed = true;
                }
                Some(self.store().put_atag(&a)?)
            }
        };
        let mut tx = self.transaction(format!("set tag {name}"))?;
        tx.repository_wide();
        tx.view.tags.insert(
            name.to_string(),
            Tag { target, annotation },
        );
        tx.commit()?;
        Ok(SetTagOutcome {
            annotation,
            replaced: old_annotation,
            signed,
            unchanged: false,
        })
    }

    /// The annotation of tag `name` and what its signature proves, or
    /// `None` for a plain tag (`vl tag verify`, `vl tag list`). `verified`
    /// is true only for a valid Veil signature by a key some ring of this
    /// repository registers for the member it names.
    pub fn tag_annotation(&self, name: &str) -> Result<Option<TagCheck>> {
        let t = self
            .view
            .tags
            .get(name)
            .ok_or_else(|| VeilError::NotFound(format!("tag '{name}'")))?;
        let Some(a) = t.annotation else { return Ok(None) };
        Ok(Some(self.check_atag(name, &t.target, &a)?))
    }

    /// [`Repo::tag_annotation`] for atag `id` shown as `name → target`.
    pub fn check_atag(&self, name: &str, target: &ObjectId, id: &ObjectId) -> Result<TagCheck> {
        let atag = self.store().atag(id)?;
        let verification = atag.verify(name, target);
        let signer = match &verification {
            AtagVerification::Signed { signer, key } => {
                let known = self.keys().known_signers();
                match known.get(key) {
                    Some((member, who)) if member == signer => Some(who.clone()),
                    _ => match self.identity() {
                        Some(me) if me.verifying_hex() == *key && me.public_hex() == *signer => Some(self.user.clone()),
                        _ => None,
                    },
                }
            }
            _ => None,
        };
        let message = Some(atag.message.as_str().to_string());
        Ok(TagCheck {
            id: *id,
            verified: signer.is_some(),
            signer,
            verification,
            message,
            atag,
        })
    }

    pub fn delete_tag(&mut self, name: &str) -> Result<()> {
        let mut tx = self.transaction(format!("delete tag {name}"))?;
        tx.repository_wide();
        let old = tx
            .view
            .tags
            .remove(name)
            .ok_or_else(|| VeilError::NotFound(format!("tag '{name}'")))?;
        // So that the next pull does not bring it back (BUG-280).
        crate::remote::record_tag_deletion(&**tx.repo().backend(), name, old.target)?;
        tx.commit()?;
        Ok(())
    }

    /// Release embargo `id`, recorded as the operation `release embargo
    /// <id>`. The release is **staged** ([`Keychain::stage_release`]): this
    /// repository treats the embargo as released at once, and the release
    /// reaches the synced record with the next push. Until
    /// then `vl undo` takes the release back completely; afterwards it
    /// cannot be undone (BUG-109).
    ///
    /// [`Keychain::stage_release`]: crate::keychain::Keychain::stage_release
    pub fn release_embargo(&mut self, id: &str) -> Result<()> {
        if self.keys().load_embargo(id)?.is_none() {
            return Err(VeilError::NotFound(format!("embargo '{id}'")));
        }
        if self.keys().release_state(id) != ReleaseState::Unreleased {
            return Ok(());
        }
        // The operation first, then the staged release: stopped in between,
        // the embargo stays unreleased, and a staged release always has its
        // operation in the op log, which a push checks (BUG-1487).
        let mut tx = self.transaction(format!("{RELEASE_OP_PREFIX}{id}"))?;
        tx.repository_wide();
        tx.record_always();
        tx.commit()?;
        self.keys().stage_release(id)?;
        Ok(())
    }

    /// Where each staged release stands by the op log, and the operations
    /// read to tell: from the heads, newest first, down to the oldest
    /// staged release's operation (an operation that takes a release back
    /// descends from it, so it is read before it). In force: its latest
    /// `release embargo <id>` operation is in the heads' history and no
    /// undo or op restore in that history took it back (a take-back is
    /// permanent, even if the undo or restore was itself taken back since).
    pub fn staged_release_standing(&self) -> Result<(BTreeMap<String, Standing>, Vec<ObjectId>)> {
        let staged: Vec<String> = self.keys().staged_releases()?.into_iter().map(|(id, _)| id).collect();
        let mut out = BTreeMap::new();
        let mut read = Vec::new();
        if staged.is_empty() {
            return Ok((out, read));
        }
        let mut want: BTreeSet<String> = staged.iter().cloned().collect();
        let mut release_op: BTreeMap<String, ObjectId> = BTreeMap::new();
        let mut retractors = BTreeMap::new();
        for r in self.ops.walk(&self.ops.heads()?) {
            let (id, op) = r?;
            read.push(id);
            if let Some(x) = self.retractor(&op)? {
                retractors.insert(id, x);
            }
            if let Some(e) = op.description.strip_prefix(RELEASE_OP_PREFIX) {
                if want.remove(e) {
                    release_op.insert(e.to_string(), id);
                }
            }
            if want.is_empty() {
                break;
            }
        }
        // A release taken back stays taken back (undo and op restore never
        // release): an undo or restore that names the release's operation
        // takes it back for good, even if that undo or restore was itself
        // taken back since (BUG-1535). A redo only retracts an undo.
        let mut taken: std::collections::HashSet<ObjectId> = crate::repo::retracted_commands(&retractors);
        for r in retractors.values() {
            match r {
                crate::repo::Retractor::Undo(u) => {
                    taken.insert(*u);
                }
                crate::repo::Retractor::Restore(ops) => taken.extend(ops.iter().copied()),
                crate::repo::Retractor::Redo(_) => {}
            }
        }
        for e in staged {
            let standing = match release_op.get(&e) {
                Some(o) if taken.contains(o) => Standing::TakenBack,
                Some(_) => Standing::InForce,
                None => Standing::Unconfirmed,
            };
            out.insert(e, standing);
        }
        Ok((out, read))
    }

    /// Before a push publishes the staged releases: take back each one the
    /// op log does not hold in force (BUG-1487: an undo or op restore that
    /// stopped before taking it back), and say so. One whose operation the
    /// op log does not hold (an older `vl` staged it without one) is not
    /// published either; release it again. Never silent, never early.
    /// Returns a warning per release taken back.
    pub fn take_back_releases_out_of_force(&self) -> Result<Vec<String>> {
        let (standing, _) = self.staged_release_standing()?;
        let mut warnings = Vec::new();
        for (e, s) in standing {
            let why = match s {
                Standing::InForce => continue,
                Standing::TakenBack => "an undo or op restore took its release back",
                Standing::Unconfirmed => "its release is not in the op log",
            };
            if self.keys().take_back_release(&e)? == TakeBack::TakenBack {
                warnings.push(format!("embargo {e} was not published: {why}; to publish it, release it again (`vl embargo release {e}`)"));
            }
        }
        Ok(warnings)
    }

    /// Undoing the operation `description`, as far as embargo releases go.
    /// A release lives in the embargo record (or, until pushed, in
    /// device-local state), not in the view an undo restores. So undoing
    /// `release embargo <id>` takes back a release that is only staged
    /// (returns its id, for [`Repo::finish_undo_release`] once the view is
    /// restored), and is **refused**, before anything changes, when the
    /// release has been published: nothing can unpublish it. Undoing the undo of a
    /// release is refused too: undo never releases an embargo.
    pub fn check_undo_release(&self, description: &str) -> Result<Option<String>> {
        if let Some(id) = description.strip_prefix("undo: ").and_then(|d| d.strip_prefix(RELEASE_OP_PREFIX)) {
            return Err(VeilError::Policy(format!(
                "the last command took back the release of embargo {id}, and `vl undo` never releases an embargo; run `vl embargo release {id}` to release it again (nothing was changed)"
            )));
        }
        let Some(id) = description.strip_prefix(RELEASE_OP_PREFIX) else {
            return Ok(None);
        };
        match self.keys().release_state(id) {
            ReleaseState::Released => Err(VeilError::Policy(format!(
                "cannot undo `{description}`: the release has been published (pushed, received from a remote, or past its deadline), and a published release cannot be taken back. Nothing was changed. Treat the fix as public"
            ))),
            ReleaseState::Staged => Ok(Some(id.to_string())),
            ReleaseState::Unreleased => Ok(None),
        }
    }

    /// Take back the staged release [`Repo::check_undo_release`] returned.
    pub fn finish_undo_release(&self, id: Option<String>) -> Result<()> {
        if let Some(id) = id {
            if self.keys().take_back_release(&id)? == TakeBack::Published {
                return Err(VeilError::Policy(format!(
                    "embargo {id} was published while undoing its release; it stays released"
                )));
            }
        }
        Ok(())
    }

    /// The releases that the op restore `restore` took the view back past,
    /// which restoring cannot reach through the view: `(staged, published)`
    /// embargo ids. Staged ones can be taken back
    /// ([`Keychain::take_back_release`]); published ones stay released.
    ///
    /// They are read from the op log, from the restore operation's own
    /// parents: the `release embargo <id>` operations those reach and the
    /// restored operation does not. Not from times (a clock set back gets
    /// them wrong, BUG-1400), and not from the heads read before the
    /// restore's transaction (a release another process staged in between
    /// is behind the restore, BUG-1404).
    ///
    /// [`Keychain::take_back_release`]: crate::keychain::Keychain::take_back_release
    pub fn releases_restored(&self, restore: &ObjectId) -> Result<(Vec<String>, Vec<String>)> {
        let r = self.ops.get(restore)?;
        let Some(op) = r.restore_of else {
            return Err(VeilError::repo(format!("operation {} is not an op restore", restore.short())));
        };
        let split = self.ops.split(&r.parents, &[op])?;
        let mut ids = std::collections::BTreeSet::new();
        for id in &split.only_a {
            if let Some(e) = split.ops.get(id).and_then(|o| o.description.strip_prefix(RELEASE_OP_PREFIX)) {
                ids.insert(e.to_string());
            }
        }
        let (mut staged, mut published) = (Vec::new(), Vec::new());
        for e in ids {
            match self.keys().release_state(&e) {
                ReleaseState::Staged => staged.push(e),
                ReleaseState::Released => published.push(e),
                ReleaseState::Unreleased => {}
            }
        }
        Ok((staged, published))
    }

    /// Undo the most recent operation by restoring the view before it.
    pub fn undo(&mut self) -> Result<ObjectId> {
        self.reload()?;
        let op = self.ops.get(&self.op_id)?;
        let undone = op.description.clone();
        let release = self.check_undo_release(&undone)?;
        let mut tx = self.transaction(format!("undo: {undone}"))?;
        // From the transaction's base: what it reads is what it replaces.
        let op = tx.repo().ops.get(&tx.repo().op_id)?;
        if op.description != undone {
            return Err(VeilError::repo("another command ran meanwhile; run `vl undo` again"));
        }
        let parent = *op
            .parents
            .first()
            .ok_or_else(|| VeilError::repo("nothing to undo"))?;
        tx.view = tx.repo().ops.get(&parent)?.view;
        let undone = tx.repo().op_id;
        tx.undo_of(undone);
        let id = tx.commit()?.expect("recorded");
        self.finish_undo_release(release)?;
        Ok(id)
    }

    /// Restore the view as of an earlier operation. Releases staged after
    /// it are taken back; published ones stay ([`Repo::releases_restored`]).
    pub fn restore_operation(&mut self, op: ObjectId) -> Result<ObjectId> {
        let view = self.ops.get(&op)?.view;
        let mut tx = self.transaction(format!("restore to operation {}", op.short()))?;
        tx.view = view;
        tx.restore_of(op);
        let id = tx.commit()?.expect("recorded");
        let (staged, _) = self.releases_restored(&id)?;
        for e in staged {
            self.keys().take_back_release(&e)?;
        }
        Ok(id)
    }
}
