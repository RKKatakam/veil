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
    merge::merge_trees,
    now_millis,
    object::{EntryKind, Snapshot, TreeEntry, Visibility},
    oplog::Tag,
    policy::{Policy, POLICY_FILE},
    repo::Repo,
    store::ObjectStore,
    tree::{lookup, TreeView},
    vpath::VPath,
};

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
}

/// Which tags a commit moves (see [`Repo::commit`]): `None` if `tag` may
/// advance, else why it stays.
fn tag_kept(tag: &Tag, line_cloak: Option<&str>, advance: bool) -> Option<TagKept> {
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
        if let (EntryKind::File, Visibility::Cloaked { scope: s }) = (e.kind, &e.visibility) {
            if s != scope {
                out.push(format!("{} (cloaked under '{s}')", c.path));
            }
        }
    }
    Ok(out)
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
        for a in self.ancestors(id)? {
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
        ns.description = store.make_text(message, description_scope(store, &s.tree, s.cloak.as_deref())?.as_deref())?;
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
    ///   uncloaked tag such as `main` stays: it is what public remotes and
    ///   Git receive, and cloaked work reaches it only through an explicit
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
    pub fn rebase(&mut self, source: ObjectId, dest: Vec<ObjectId>) -> Result<ObjectId> {
        if dest.is_empty() {
            return Err(VeilError::repo("rebase needs at least one destination"));
        }
        for d in &dest {
            if self.is_ancestor(&source, d)? {
                return Err(VeilError::repo("cannot rebase a change onto itself or its descendant"));
            }
        }
        let mut tx = self.transaction("rebase")?;
        let s = tx.repo().snapshot(&source)?;
        let old_base = tx.repo().parents_tree(&s.parents)?.tree;
        let new_base = tx.repo().parents_tree(&dest)?.tree;
        let out = merge_trees(&tx.repo().store, Some(old_base), new_base, s.tree)?;
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
        Ok(id)
    }

    /// Fold a change into its (single) parent.
    pub fn squash(&mut self, id: ObjectId) -> Result<ObjectId> {
        let mut tx = self.transaction("squash")?;
        let s = tx.repo().snapshot(&id)?;
        let [parent] = s.parents.as_slice() else {
            return Err(VeilError::repo("can only squash a change with exactly one parent"));
        };
        if *parent == tx.repo().root_id {
            return Err(VeilError::repo("cannot squash into the root snapshot"));
        }
        let p = tx.repo().snapshot(parent)?;
        let mut np = (*p).clone();
        np.tree = s.tree;
        // Folding into a cloaked change: what the result introduces is part
        // of the cloaked line and must be sealed like the rest of it.
        if let Some(scope) = &p.cloak {
            let base = tx.repo().parents_tree(&p.parents)?.tree;
            np.tree = seal_introduced(&tx.repo().store, &np.tree, Some(base), scope)?;
        }
        np.predecessors = vec![*parent, id];
        // A path stays conflicted only if the result still has the
        // conflict: the parent's conflicted files the squashed change left
        // untouched, and the squashed change's own.
        let store = tx.repo().store.clone();
        let mut conflicts = BTreeSet::new();
        for c in &p.conflicts {
            let Ok(path) = VPath::new(c) else { continue };
            let before = lookup(&store, &p.tree, &path).ok().flatten();
            if before.is_some() && before == lookup(&store, &s.tree, &path).ok().flatten() {
                conflicts.insert(c.clone());
            }
        }
        conflicts.extend(s.conflicts.iter().cloned());
        np.conflicts = recordable_conflicts(&store, &np.tree, conflicts.into_iter().collect())?;
        let pd = tx.repo().description(&p);
        let sd = tx.repo().description(&s);
        if !sd.trim().is_empty() {
            let joined = if pd.trim().is_empty() { sd } else { format!("{pd}\n\n{sd}") };
            // A cloaked change's description stays sealed for its scope, even
            // when folded into a public parent (the joined text is sealed).
            let scope = match (&p.cloak, &s.cloak) {
                (Some(a), Some(b)) if a != b => {
                    return Err(VeilError::Policy(format!(
                        "cannot squash a change cloaked under '{b}' into one cloaked under '{a}'"
                    )))
                }
                (a, b) => a.as_deref().or(b.as_deref()),
            };
            // Folded into (or from) a line under an unreleased embargo: the
            // joined text stays sealed under the embargo key.
            let store = &tx.repo().store;
            let scope = description_scope(store, &np.tree, scope)?;
            np.description = store.make_text(&joined, scope.as_deref())?;
        }
        let new_parent = tx.rewrite(*parent, np)?;
        tx.abandon(id)?;
        tx.set_description(format!("squash {} into {}", s.change_id.short(), p.change_id.short()));
        tx.commit()?;
        Ok(new_parent)
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
        if others.is_empty() {
            return Err(VeilError::repo("nothing to merge"));
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
        let merged = tx.repo().parents_tree(&parents)?;
        let outer = unreleased_wrapper(&store, &merged.tree)?;
        let dest_policy = Policy::load(&TreeView::new(store.clone(), into_snap.tree))?;
        let mut policy = Policy::load(&TreeView::new(store.clone(), merged.tree))?;
        let mut warnings = Vec::new();
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
            if tag.target == into {
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
        })
    }

    /// Is every snapshot that merging `others` into `into` brings in (an
    /// ancestor of one of `others`, not of `into`) present and signed by a
    /// current member of `scope` ([`crate::keychain::Keychain::signed_by_member`])?
    fn merged_in_signed_by(&self, into: &ObjectId, others: &[ObjectId], scope: &str) -> Result<bool> {
        let known = self.ancestors(into)?;
        let mut seen = std::collections::HashSet::new();
        let mut stack = others.to_vec();
        while let Some(x) = stack.pop() {
            if known.contains(&x) || !seen.insert(x) {
                continue;
            }
            let Some(s) = self.snapshot_opt(&x)? else { return Ok(false) };
            if !self.keys().signed_by_member(scope, &s) {
                return Ok(false);
            }
            stack.extend(s.parents.iter().copied());
        }
        Ok(true)
    }

    pub fn set_tag(&mut self, name: &str, target: ObjectId, cloak: Option<String>, allow_backwards: bool) -> Result<()> {
        validate_tag_name(name)?;
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
        if let Some(t) = self.view.tags.get(name) {
            if !allow_backwards && !self.is_ancestor(&t.target, &target)? {
                return Err(VeilError::repo(format!(
                    "moving tag '{name}' would go backwards or sideways (use --allow-backwards)"
                )));
            }
        }
        let mut tx = self.transaction(format!("set tag {name}"))?;
        let cloak = cloak.or_else(|| tx.view.tags.get(name).and_then(|t| t.cloak.clone()));
        tx.view.tags.insert(name.to_string(), Tag { target, cloak });
        tx.commit()?;
        Ok(())
    }

    pub fn delete_tag(&mut self, name: &str) -> Result<()> {
        let mut tx = self.transaction(format!("delete tag {name}"))?;
        tx.view
            .tags
            .remove(name)
            .ok_or_else(|| VeilError::NotFound(format!("tag '{name}'")))?;
        tx.commit()?;
        Ok(())
    }

    /// Release embargo `id`, recorded as the operation `release embargo
    /// <id>`. The release is **staged** ([`Keychain::stage_release`]): this
    /// repository treats the embargo as released at once, and the key
    /// reaches the synced record with the next push or Git export. Until
    /// then `vl undo` takes the release back completely; afterwards it
    /// cannot be undone (BUG-109).
    ///
    /// [`Keychain::stage_release`]: crate::keychain::Keychain::stage_release
    pub fn release_embargo(&mut self, id: &str) -> Result<()> {
        if self.keys().stage_release(id)? != StageOutcome::Staged {
            return Ok(());
        }
        let mut tx = self.transaction(format!("{RELEASE_OP_PREFIX}{id}"))?;
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
                "cannot undo `{description}`: the embargo key has been published (pushed, exported to Git, or received from a remote), and a published key cannot be taken back. Nothing was changed. Treat the fix as public"
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
        let parent = *op
            .parents
            .first()
            .ok_or_else(|| VeilError::repo("nothing to undo"))?;
        let undone = op.description.clone();
        let release = self.check_undo_release(&undone)?;
        let view = self.ops.get(&parent)?.view;
        let mut tx = self.transaction(format!("undo: {undone}"))?;
        tx.view = view;
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
