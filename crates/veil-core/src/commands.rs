//! High-level history operations. Each is one transaction → one op-log entry.

use std::collections::BTreeSet;

use crate::{
    builder::trusted_cloak,
    embargo::{
        apply_embargo, description_scope, normalize_tree, policy_rekeys, recordable_conflicts, seal_declassified, seal_introduced,
        unreleased_wrapper, wrap, NormalizeOptions, NormalizeReport,
    },
    error::{Result, VeilError},
    id::{ChangeId, ObjectId},
    keychain::{ReleaseState, StageOutcome, TakeBack},
    now_millis,
    object::{Snapshot, Text, TreeEntry, Visibility},
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
    /// Cloak the tag under this scope (kept from the existing tag if unset).
    pub cloak: Option<String>,
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
    /// Files of a merged-in cloaked line of work that this merge made public
    /// (each was secret-scanned first).
    pub declassified: Vec<String>,
    /// Files that would have become public but hold a secret: left out of
    /// the merge (the destination keeps its own version, if any).
    pub quarantined: Vec<String>,
    /// Visibility changes the merge refused to make silently.
    pub warnings: Vec<String>,
    /// Renames the merge followed (this reader's report; never stored).
    pub renames: Vec<crate::merge::FollowedRename>,
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
    /// The commit is on a cloaked line (this scope) and the tag is not
    /// cloaked under that scope: cloaked work never moves it.
    CloakedLine(String),
    /// The caller asked for no tag to move (`vl commit --no-advance`).
    NoAdvance,
    /// An annotated release tag: immutable (`vl tag set --force` moves it).
    Release,
}

/// Which tags a commit moves (see [`Repo::commit`]): `None` if `tag` may
/// advance, else why it stays.
fn tag_kept(tag: &Tag, line_cloak: Option<&str>, advance: bool) -> Option<TagKept> {
    if tag.annotation.is_some() {
        // A release tag is immutable: commits never move it.
        return Some(TagKept::Release);
    }
    if !advance {
        return Some(TagKept::NoAdvance);
    }
    match line_cloak {
        Some(scope) if tag.cloak.as_deref() != Some(scope) => Some(TagKept::CloakedLine(scope.to_string())),
        _ => None,
    }
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

/// Files that `tree` adds or changes relative to `dest` and that are sealed
/// under a scope other than `scope`. An embargo wrapper keeps such content
/// sealed as it is (releasing the embargo must not declassify it), so every
/// member of that other scope could read the change before the release.
fn sealed_for_other_scopes(store: &ObjectStore, dest: &ObjectId, tree: &ObjectId, scope: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for c in crate::tree::diff_trees(store, Some(dest), Some(tree))? {
        let Some(e) = &c.new else { continue };
        if let (true, Visibility::Cloaked { scope: s }) = (e.kind.holds_blob(), &e.visibility) {
            if s != scope {
                out.push(format!("{} (cloaked under '{s}')", c.path));
            }
        }
    }
    Ok(out)
}

/// Is `text` the description `message`, sealed for `scope` (plain when
/// `None`)?
fn same_description(store: &ObjectStore, text: &Text, message: &str, scope: Option<&str>) -> bool {
    match (text, scope) {
        (Text::Plain(t), None) => t == message,
        (Text::Sealed(env), Some(scope)) => {
            store.keys.sealing_key(scope).is_ok_and(|(label, _)| label == env.scope)
                && store.read_text(text).as_deref() == Some(message)
        }
        _ => false,
    }
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
}

/// What [`Repo::split`] made.
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
    let visible = repo.visible_among(&ids.iter().copied().collect())?;
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
    /// The unreleased embargo that snapshot `id` carries, if any: its tree
    /// is under one, or one of its ancestors (itself included) is an
    /// embargoed merge whose embargo has not been released. An embargo this
    /// repository has no record of counts as unreleased.
    pub fn carried_embargo(&self, id: &ObjectId) -> Result<Option<String>> {
        let s = self.snapshot(id)?;
        if let Some(w) = unreleased_wrapper(&self.store, &s.tree)? {
            return Ok(Some(w.embargo));
        }
        // Embargoed snapshots come from the history index: with none in
        // the history, nothing is walked.
        let mut carried: Vec<ObjectId> = self.graph().embargoed_among(self, [*id])?.into_iter().collect();
        carried.sort();
        for a in carried {
            let Some(s) = self.snapshot_opt(&a)? else { continue };
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
        let cloak = tx.view.workspace(ws)?.cloak.clone();
        let id = tx.new_change(parents, message, cloak)?;
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
        let store = &tx.repo().store;
        let scope = description_scope(store, &s.tree, s.cloak.as_deref())?;
        // The same message, sealed for the same audience: nothing to do
        // (a sealed description never encrypts the same way twice, so the
        // rewrite's own no-op check cannot see this, BUG-246).
        if same_description(store, &s.description, message, scope.as_deref()) {
            return Ok(id);
        }
        ns.description = store.make_text(message, scope.as_deref())?;
        ns.predecessors = vec![id];
        let new = tx.rewrite(id, ns)?;
        tx.set_description(format!("describe change {}", s.change_id.short()));
        tx.commit()?;
        Ok(new)
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
    /// * on a **cloaked line** (the workspace, or the change itself, is
    ///   cloaked under scope `S`), only tags cloaked under `S` move. An
    ///   uncloaked tag such as `main` stays: it is what public remotes
    ///   receive, and cloaked work reaches it only through an explicit
    ///   `vl merge` (which publishes it after a secret scan, or embargoes
    ///   it) or `vl tag set`;
    /// * with `advance == false` (`vl commit --no-advance`), no tag moves.
    ///
    /// Tags that stayed are reported in [`CommitResult::kept`].
    pub fn commit(&mut self, ws: &str, message: &str, advance: bool) -> Result<CommitResult> {
        let mut tx = self.transaction("commit")?;
        let wc_id = tx.view.workspace(ws)?.wc;
        let cloak = tx.view.workspace(ws)?.cloak.clone();
        let s = tx.repo().snapshot(&wc_id)?;
        let mut ns = (*s).clone();
        // On a line under an unreleased embargo a key holder's message
        // describes the hidden fix: it is sealed under the embargo key.
        let store = &tx.repo().store;
        ns.description = store.make_text(message, description_scope(store, &s.tree, s.cloak.as_deref())?.as_deref())?;
        ns.predecessors = vec![wc_id];
        ns.timestamp = now_millis();
        let committed = tx.rewrite(wc_id, ns)?;
        let line_cloak = cloak.clone().or_else(|| s.cloak.clone());
        let (mut advanced, mut kept) = (Vec::new(), Vec::new());
        for (name, tag) in tx.view.tags.iter_mut() {
            if s.parents.first() != Some(&tag.target) {
                continue;
            }
            match tag_kept(tag, line_cloak.as_deref(), advance) {
                None => {
                    tag.target = committed;
                    advanced.push(name.clone());
                }
                Some(why) => kept.push((name.clone(), why)),
            }
        }
        let wc = tx.new_change(vec![committed], "", cloak)?;
        tx.set_workspace_wc(ws, wc)?;
        tx.set_description(format!("commit change {}", s.change_id.short()));
        tx.commit()?;
        Ok(CommitResult {
            committed,
            wc,
            advanced,
            kept,
        })
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
        let s = tx.repo().snapshot(&source)?;
        let out = tx.repo().rebase_tree(&s.parents, &dest, s.tree, s.cloak.as_deref())?;
        let mut ns = (*s).clone();
        ns.parents = dest;
        ns.tree = out.tree;
        ns.predecessors = vec![source];
        ns.conflicts.extend(out.conflicts.iter().map(|p| p.to_string()));
        ns.conflicts.sort();
        ns.conflicts.dedup();
        ns.conflicts = recordable_conflicts(&tx.repo().store, &ns.tree, ns.conflicts)?;
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
        let mut units = selection::units(&self.store, &base, &s.tree)?;
        if by_hunk {
            for u in &mut units {
                selection::classify(&self.store, u, &s.conflicts)?;
            }
        }
        Ok(ChangeParts { id: *id, base, tree: s.tree, units })
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
        let s = tx.repo().snapshot(&id)?;
        check_current(tx.repo(), &[id], parts, &s)?;
        if s.embargo.is_some() {
            return Err(VeilError::Policy("an embargoed merge cannot be split".into()));
        }
        let store = tx.repo().store.clone();
        let h = selection::halves(&store, &parts.base, &parts.tree, &parts.units, sel)?;
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
        let scope = description_scope(&store, &h.chosen, s.cloak.as_deref())?;
        let first = Snapshot {
            parents: s.parents.clone(),
            change_id: ChangeId::random(),
            tree: h.chosen,
            description: store.make_text(message.unwrap_or(""), scope.as_deref())?,
            author: s.author.clone(),
            timestamp: s.timestamp,
            predecessors: vec![id],
            conflicts: recordable_conflicts(&store, &h.chosen, moved_conflicts(&store, &s, &h.chosen))?,
            cloak: s.cloak.clone(),
            embargo: None,
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
    /// its change id and description and holds the rest; when nothing is
    /// left it is abandoned and its description is joined to the
    /// destination's, as a whole squash always did.
    ///
    /// * into its **parent**: the parent gets the chosen part; the source's
    ///   own tree is unchanged (it already held everything), except that
    ///   what a cloaked destination sealed is sealed in it too
    ///   ([`crate::embargo::seal_moved`]);
    /// * into an **ancestor**: the chosen part is merged into it, the
    ///   changes in between are rebased onto it, and the source keeps its
    ///   tree (sealed the same way);
    /// * into a **descendant**: the source keeps the rest, the changes in
    ///   between are rebased without the chosen part, and the destination
    ///   keeps its tree;
    /// * into an **unrelated** change: the source keeps the rest and the
    ///   chosen part is merged into the destination.
    ///
    /// Descendants are rebased, and a cloaked destination seals what it is
    /// given (as [`crate::embargo::seal_introduced`] does for a whole
    /// squash). One transaction: `vl undo` restores everything.
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
                let h = selection::halves(&store, &parts.base, &parts.tree, &parts.units, sel)?;
                if !h.any {
                    return Err(VeilError::repo("nothing chosen: nothing to squash"));
                }
                (parts.base, h.chosen, h.rest, h.all)
            }
            None if into_parent => (tx.repo().snapshot(&dest)?.tree, s.tree, s.tree, true),
            None => {
                let base = tx.repo().parents_tree(&s.parents)?.tree;
                check_current(tx.repo(), &[id, dest], &ChangeParts { id, base, tree: s.tree, units: vec![] }, &s)?;
                (base, s.tree, base, true)
            }
        };
        let general = !into_parent || part.is_some();
        if general {
            let d = tx.repo().snapshot(&dest)?;
            for t in [&s.tree, &base, &d.tree] {
                if crate::embargo::wrapper_of(&store, t)?.is_some() {
                    return Err(VeilError::Policy(
                        "a change under an embargo can only be squashed whole into its parent (`vl squash` with no paths)".into(),
                    ));
                }
            }
        }
        let d = tx.repo().snapshot(&dest)?;
        // The destination as it ends up: `tree`, conflicts, and (if the
        // source is emptied) the joined description.
        let finish_dest = |tx: &Transaction, cur: ObjectId, tree: ObjectId, extra: Vec<String>| -> Result<Snapshot> {
            let now = tx.repo().snapshot(&cur)?;
            let mut nd = (*now).clone();
            nd.tree = match &now.cloak {
                // Folding into a cloaked change: what it introduces is part
                // of the cloaked line and is sealed like the rest of it.
                Some(scope) => {
                    let pbase = tx.repo().parents_tree(&now.parents)?.tree;
                    seal_introduced(&store, &tree, Some(pbase), scope)?
                }
                None => tree,
            };
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
            nd.conflicts = recordable_conflicts(&store, &nd.tree, conflicts.into_iter().collect())?;
            if all {
                let pd = tx.repo().description(&now);
                let sd = tx.repo().description(&s);
                if !sd.trim().is_empty() {
                    let joined = if pd.trim().is_empty() { sd } else { format!("{pd}\n\n{sd}") };
                    // A cloaked change's description stays sealed for its
                    // scope, even when folded into a public one (the
                    // joined text is sealed).
                    let scope = match (&now.cloak, &s.cloak) {
                        (Some(a), Some(b)) if a != b => {
                            return Err(VeilError::Policy(format!(
                                "cannot squash a change cloaked under '{b}' into one cloaked under '{a}'"
                            )))
                        }
                        (a, b) => a.as_deref().or(b.as_deref()),
                    };
                    // Folded into (or from) a line under an unreleased
                    // embargo: the joined text stays sealed under its key.
                    let scope = description_scope(&store, &nd.tree, scope)?;
                    nd.description = store.make_text(&joined, scope.as_deref())?;
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
            ns.conflicts = recordable_conflicts(&store, &tree, ns.conflicts)?;
            Ok(Some(tx.rewrite(cur, ns)?))
        };
        let merge_into = |tree: ObjectId| -> Result<(ObjectId, Vec<String>)> {
            let out = crate::merge::merge_trees(&store, Some(base), tree, chosen)?;
            Ok((out.tree, out.conflicts.iter().map(|p| p.to_string()).collect()))
        };
        // A source that keeps its tree (into its parent or an ancestor)
        // still holds what it gave: where a cloaked destination sealed it,
        // the source holds it sealed too, so that the moved part leaves
        // the source's own change and nothing sealed in the destination
        // stays public on top of it (BUG-483).
        let kept_source = |nd: &Snapshot, given: ObjectId| -> Result<ObjectId> {
            match &nd.cloak {
                Some(scope) => crate::embargo::seal_moved(&store, s.tree, given, nd.tree, scope),
                None => Ok(s.tree),
            }
        };
        let (destination, source) = if into_parent {
            let nd = finish_dest(&tx, dest, chosen, vec![])?;
            let src_tree = kept_source(&nd, chosen)?;
            let new_dest = tx.rewrite(dest, nd)?;
            let source = finish_source(&mut tx, id, Some(vec![new_dest]), src_tree)?;
            (new_dest, source)
        } else if tx.repo().is_ancestor(&dest, &id)? {
            let (tree, extra) = merge_into(d.tree)?;
            let nd = finish_dest(&tx, dest, tree, extra)?;
            let src_tree = kept_source(&nd, tree)?;
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
        let cloak = into_snap.cloak.as_deref();
        // A merge put under an embargo records its conflicts as markers:
        // the embargo's sealed tree never holds conflict entries.
        let merged = tx.repo().parents_tree_with(&parents, embargo.is_some())?;
        let outer = unreleased_wrapper(&store, &merged.tree)?;
        // An unreadable `.veilpolicy` on either side (a hostile tree's
        // directory, BUG-121) never blocks the merge: the accepted policy
        // applies there, with a warning.
        let accepted = crate::policy::load_accepted(&*tx.repo().backend).ok().flatten();
        let (dest_policy, w1) = Policy::load_or_accepted(&TreeView::new(store.clone(), into_snap.tree), accepted.as_deref())?;
        let (mut policy, w2) = Policy::load_or_accepted(&TreeView::new(store.clone(), merged.tree), accepted.as_deref())?;
        let mut warnings: Vec<String> = w1.into_iter().chain(w2).collect();
        warnings.dedup();
        let mut tree = merged.tree;

        // A merged `.veilpolicy` that would move existing cloaked content to
        // another audience (re-key it, or make it public) is not taken: the
        // destination's policy is kept and the member is told. Applying it
        // is a deliberate edit, not a side effect of merging someone's PR.
        let mut rekeys = policy_rekeys(&store, &into_snap.tree, &dest_policy, &policy, cloak)?;
        for r in policy_rekeys(&store, &tree, &dest_policy, &policy, cloak)? {
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
                "kept the destination's {POLICY_FILE}: the merged one would change the audience of existing cloaked files ({}); review it and apply it deliberately",
                list.join(", ")
            ));
        }

        // Merging a cloaked line of work into this one is the explicit act
        // that may publish its files (secret-scanned). A `cloak` field is a
        // claim anyone can write over anyone's sealed objects, so a line
        // counts only if every snapshot the merge brings in is signed by a
        // current member of its scope (BUG-122).
        let mut declassify = BTreeSet::new();
        for o in &others {
            let Some(c) = trusted_cloak(tx.repo().snapshot(o)?.cloak.as_deref()).map(str::to_string) else {
                continue;
            };
            if Some(c.as_str()) == cloak || declassify.contains(&c) {
                continue;
            }
            if tx.repo().merged_in_signed_by(&into, &others, &c)? {
                declassify.insert(c);
            } else {
                warnings.push(format!(
                    "not publishing the files of the line cloaked under '{c}' ({}): not every snapshot this merge brings in is signed by a current member of '{c}', and only members may publish its content; they stay cloaked (`vl expose` publishes deliberately)",
                    o.short()
                ));
            }
        }
        let mut report = NormalizeReport::default();
        tree = normalize_tree(
            &store,
            &tree,
            &NormalizeOptions {
                policy: &policy,
                dest_policy: &dest_policy,
                dest_tree: into_snap.tree,
                cloak,
                declassify: &declassify,
                // Declassified content of an embargoed result is sealed
                // under the embargo key directly, never stored as
                // plaintext first (BUG-249).
                defer_declassify: embargo.is_some() || outer.is_some(),
            },
            &mut report,
        )?;
        // A file whose edit followed a rename stays sealed at its new path,
        // whatever the policy says there: the rename moved it, not the line
        // being merged, and only `vl expose` publishes it.
        tree = crate::merge::keep_followed_sealed(&store, tree, merged.tree, &merged.renames, &mut report.declassified, &mut report.quarantined, &mut warnings)?;
        // The destination is under an unreleased embargo: stay under it.
        if let Some(w) = &outer {
            tree = seal_declassified(&store, &tree, &report.declassified, &w.embargo, &into_snap.tree)?;
            if tree != merged.tree {
                tree = wrap(&store, &w.embargo, &tree, &w.fallback)?;
            }
        }
        let mut conflicts: Vec<String> = merged.conflicts.iter().map(|p| p.to_string()).collect();
        let reported_conflicts = conflicts.clone();
        // Embargo records are synced to every remote, public ones included,
        // so the record carries no message; the merge's description is
        // sealed under the embargo key instead. The record is only created
        // once the merge is known to be possible.
        let embargo_id = match &embargo {
            Some(spec) => {
                let mut other_scopes = sealed_for_other_scopes(&store, &into_snap.tree, &tree, &spec.scope)?;
                // Declassified files are still sealed under their line's
                // scope here; they go under the embargo key below.
                other_scopes.retain(|o| !report.declassified.iter().any(|p| o.starts_with(&format!("{p} ("))));
                if !other_scopes.is_empty() {
                    return Err(VeilError::Policy(format!(
                        "cannot merge under an embargo for scope '{}': the merge changes files cloaked under another scope, whose members could read them before the release ({}); embargo under that scope, or make those changes after the release",
                        spec.scope,
                        other_scopes.join(", ")
                    )));
                }
                let e = tx.repo().keys().create_embargo(&spec.scope, spec.until)?;
                tree = seal_declassified(&store, &tree, &report.declassified, &e, &into_snap.tree)?;
                tree = apply_embargo(&store, &tree, &into_snap.tree, &e)?;
                Some(e)
            }
            None => None,
        };
        let recorded = recordable_conflicts(&store, &tree, std::mem::take(&mut conflicts))?;
        if recorded.len() < reported_conflicts.len() {
            warnings.push(format!(
                "{} conflicted file(s) are not recorded on the merge: snapshot metadata is public, and their names would reveal what the embargo hides; resolve the conflict markers before committing",
                reported_conflicts.len()
            ));
        }
        let scope = match (&embargo_id, cloak) {
            (Some(e), None) => Some(format!("embargo/{e}")),
            // Also a plain merge into a line under an unreleased embargo.
            _ => description_scope(&store, &tree, cloak)?,
        };
        let description = store.make_text(message, scope.as_deref())?;
        warnings.extend(report.kept_sealed.iter().map(|(p, why)| format!("{p} {why}")));
        let snap = Snapshot {
            parents,
            change_id: ChangeId::random(),
            tree,
            description,
            author: tx.repo().user.clone(),
            timestamp: now_millis(),
            predecessors: vec![],
            conflicts: recorded,
            cloak: into_snap.cloak.clone(),
            embargo: embargo_id.clone(),
            signature: None, // signed by the transaction
        };
        let m = tx.write_snapshot(&snap)?;
        for tag in tx.view.tags.values_mut() {
            // Release tags are immutable: a merge never moves one.
            if tag.target == into && tag.annotation.is_none() {
                tag.target = m;
            }
        }
        let cloak = tx.view.workspace(ws)?.cloak.clone();
        let wc = tx.new_change(vec![m], "", cloak)?;
        tx.set_workspace_wc(ws, wc)?;
        tx.set_description(match &embargo_id {
            Some(e) => format!("merge {} (embargo {e})", snap.change_id.short()),
            None => format!("merge {}", snap.change_id.short()),
        });
        tx.commit()?;
        Ok(MergeResult {
            snapshot: m,
            conflicts: reported_conflicts,
            embargo: embargo_id,
            declassified: report.declassified.iter().map(|p| p.to_string()).collect(),
            quarantined: report
                .quarantined
                .iter()
                .map(|(p, f)| {
                    let rules: Vec<&str> = f.iter().map(|f| f.rule).collect();
                    format!("{p} ({})", rules.join(", "))
                })
                .collect(),
            warnings,
            renames: merged.renames,
        })
    }

    /// Is every snapshot that merging `others` into `into` brings in (an
    /// ancestor of one of `others`, not of `into`) present and signed by a
    /// current member of `scope` ([`crate::keychain::Keychain::signed_by_member`])?
    fn merged_in_signed_by(&self, into: &ObjectId, others: &[ObjectId], scope: &str) -> Result<bool> {
        // What the merge brings in, without reading `into`'s history below
        // the merge base (the history index).
        let brought = self.graph().range(self, others, &[*into])?;
        for x in others.iter().chain(&brought) {
            if brought.contains(x) || !self.is_ancestor(x, into)? {
                let Some(s) = self.snapshot_opt(x)? else { return Ok(false) };
                if !self.keys().signed_by_member(scope, &s) {
                    return Ok(false);
                }
                // A parent this replica lacks counts as unsigned unless
                // `into` already has it.
                for p in &s.parents {
                    if !brought.contains(p) && self.snapshot_opt(p)?.is_none() && !self.is_ancestor(p, into)? {
                        return Ok(false);
                    }
                }
            }
        }
        Ok(true)
    }

    /// Create or move a plain (branch-like) tag. See [`Repo::set_tag_with`].
    pub fn set_tag(&mut self, name: &str, target: ObjectId, cloak: Option<String>, allow_backwards: bool) -> Result<()> {
        self.set_tag_with(
            name,
            target,
            &TagSpec {
                cloak,
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
    /// advance a release tag. A cloaked tag's message is sealed under its
    /// scope.
    pub fn set_tag_with(&mut self, name: &str, target: ObjectId, spec: &TagSpec) -> Result<SetTagOutcome> {
        validate_tag_name(name)?;
        let cloak = spec.cloak.clone();
        // A cloaked tag names a scope you can use, as `vl ws new --cloak`
        // and `vl cloak --scope` require: a typo or a reserved name would
        // leave a tag no cloaked line ever advances (BUG-210).
        if let Some(scope) = &cloak {
            crate::keychain::validate_scope_name(scope)?;
            if !self.keys().is_member(scope) {
                return Err(VeilError::Policy(format!("you hold no key for scope '{scope}'")));
            }
        }
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
                    let unchanged = t.target == target
                        && spec.annotate.is_none()
                        && spec.cloak.as_ref().is_none_or(|c| t.cloak.as_ref() == Some(c));
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
        let cloak = cloak.or_else(|| existing.as_ref().and_then(|t| t.cloak.clone()));
        // The annotation: a new message, or (forcing a release tag without
        // one) the old message, never dropped.
        let message = match (&spec.annotate, old_annotation) {
            (Some(m), _) => Some(m.clone()),
            (None, Some(a)) => {
                let old = self.store().atag(&a)?;
                Some(self.store().read_text(&old.message).ok_or_else(|| {
                    VeilError::repo(format!(
                        "the message of release tag '{name}' is sealed and you cannot read it; give a new one with -m"
                    ))
                })?)
            }
            (None, None) => None,
        };
        let mut signed = false;
        let annotation = match message {
            None => None,
            Some(m) => {
                let text = self.store().make_text(&m, cloak.as_deref())?;
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
            Tag {
                target,
                cloak,
                annotation,
            },
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
        let message = self.store().read_text(&atag.message);
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
    /// repository treats the embargo as released at once, and the key
    /// reaches the synced record with the next push. Until
    /// then `vl undo` takes the release back completely; afterwards it
    /// cannot be undone (BUG-109).
    ///
    /// [`Keychain::stage_release`]: crate::keychain::Keychain::stage_release
    pub fn release_embargo(&mut self, id: &str) -> Result<()> {
        if self.keys().stage_release(id)? != StageOutcome::Staged {
            return Ok(());
        }
        let mut tx = self.transaction(format!("{RELEASE_OP_PREFIX}{id}"))?;
        tx.repository_wide();
        tx.record_always();
        tx.commit()?;
        Ok(())
    }

    /// Undoing the operation `description`, as far as embargo releases go.
    /// A release lives in the embargo record (or, until pushed, in
    /// device-local state), not in the view an undo restores. So undoing
    /// `release embargo <id>` takes back a release that is only staged
    /// (returns its id, for [`Repo::finish_undo_release`] once the view is
    /// restored), and is **refused**, before anything changes, when the key
    /// has been published: nothing can unpublish it. Undoing the undo of a
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
                "cannot undo `{description}`: the embargo key has been published (pushed, or received from a remote), and a published key cannot be taken back. Nothing was changed. Treat the fix as public"
            ))),
            ReleaseState::Staged => Ok(Some(id.to_string())),
            ReleaseState::Unreleased | ReleaseState::Rejected(_) => Ok(None),
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

    /// Releases made after operation `op` was recorded, which restoring it
    /// cannot reach through the view: `(staged, published)` embargo ids.
    /// Staged ones can be taken back ([`Keychain::take_back_release`]);
    /// published ones stay released.
    ///
    /// [`Keychain::take_back_release`]: crate::keychain::Keychain::take_back_release
    pub fn releases_after(&self, op: &ObjectId) -> Result<(Vec<String>, Vec<String>)> {
        let at = self.ops.get(op)?.timestamp;
        let staged: Vec<String> = self.keys().staged_releases()?.into_iter().filter(|(_, t)| *t > at).map(|(id, _)| id).collect();
        let mut published = Vec::new();
        for rec in self.keys().embargoes()? {
            if self.keys().release_state(&rec.id) == ReleaseState::Released && rec.released_at.is_some_and(|t| t > at) {
                published.push(rec.id);
            }
        }
        Ok((staged, published))
    }

    /// Release every embargo whose deadline passed and for which we hold the
    /// key. Called on every CLI invocation.
    pub fn auto_release_embargoes(&mut self) -> Result<Vec<String>> {
        let now = now_millis();
        let mut released = Vec::new();
        for rec in self.keys().embargoes()? {
            // Only a deadline signed by a scope member may trigger a release.
            if self.keys().embargo_released(&rec.id) || rec.until.is_none_or(|u| u > now) || !self.keys().embargo_trusted(&rec) {
                continue;
            }
            if self.keys().has(&format!("embargo/{}", rec.id)) {
                self.release_embargo(&rec.id)?;
                released.push(rec.id);
            }
        }
        Ok(released)
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
        tx.record_always();
        let id = tx.commit()?.expect("recorded");
        self.finish_undo_release(release)?;
        Ok(id)
    }

    /// Restore the view as of an earlier operation. Releases staged after
    /// it are taken back; published ones stay ([`Repo::releases_after`]).
    pub fn restore_operation(&mut self, op: ObjectId) -> Result<ObjectId> {
        let (staged, _) = self.releases_after(&op)?;
        let view = self.ops.get(&op)?.view;
        let mut tx = self.transaction(format!("restore to operation {}", op.short()))?;
        tx.view = view;
        tx.record_always();
        let id = tx.commit()?.expect("recorded");
        for e in staged {
            self.keys().take_back_release(&e)?;
        }
        Ok(id)
    }
}
