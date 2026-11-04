//! The accepted policy of the repository's own working copy.
//!
//! A `.veilpolicy` that arrives from someone else (merge, pull, checkout of
//! another change, rebase, Git import, undo) must never weaken, silently,
//! the protection of files that exist only in this working copy: isolated
//! files (`.env`, keys) never enter history, so nothing but the policy
//! protects them. Every route ends in a snapshot of the working copy, so
//! that is where the guard sits: snapshots of the repository's own directory
//! apply [`policy::working_copy_policy`], i.e. the working copy's
//! `.veilpolicy` except where it weakens the policy this device last
//! accepted. Those paths keep their accepted classification, are reported
//! as held back ([`BuildReport::policy_held_back`]), and move only after
//! `vl policy accept` ([`Repo::accept_policy`]).
//!
//! Other backends (sandboxes of `vl ws exec`, overlays, ephemeral
//! workspaces, trees being imported) hold no local-only files of this
//! member and are snapshotted under their own `.veilpolicy`, as before; they
//! never move the accepted policy either, so an agent editing `.veilpolicy`
//! in a sandbox cannot accept it on the member's behalf.
//!
//! [`BuildReport::policy_held_back`]: crate::builder::BuildReport::policy_held_back

use std::sync::Arc;

use crate::{
    error::{Result, VeilError},
    id::ObjectId,
    object::is_reserved_name,
    policy::{self, HeldBack, Policy, PolicyFile, Tier, WorkingCopyPolicy, POLICY_FILE},
    repo::Repo,
    vfs::{is_temp_name, NodeKind, StorageBackend},
    vpath::VPath,
};

impl Repo {
    /// Is `fs` the repository's own directory (the backend it was opened
    /// on), whose local-only files the accepted policy protects?
    pub fn is_own_working_copy(&self, fs: &dyn StorageBackend) -> bool {
        std::ptr::addr_eq(Arc::as_ptr(&self.backend), fs as *const dyn StorageBackend)
    }

    /// The policy a snapshot of `fs` applies. `checked_out_from`: the tree
    /// `fs` was checked out from, when `fs` can only differ from it by the
    /// member's own edits (then an edit of `.veilpolicy` is theirs, and is
    /// accepted). `None` when anything else may have written `.veilpolicy`
    /// since: a difference is then guarded like any incoming change.
    pub(crate) fn snapshot_policy(&self, fs: &dyn StorageBackend, checked_out_from: Option<&ObjectId>) -> Result<WorkingCopyPolicy> {
        if !self.is_own_working_copy(fs) {
            return Ok(WorkingCopyPolicy {
                policy: Policy::load(fs)?,
                accept: None,
            });
        }
        let parent = match checked_out_from {
            Some(tree) => self.policy_text_in(tree)?,
            None => None,
        };
        policy::working_copy_policy(&*self.backend, fs, parent.as_ref().map(|t| t.as_deref()))
    }

    /// Record what [`Repo::snapshot_policy`] decided to accept.
    pub(crate) fn record_accepted(&self, wp: &WorkingCopyPolicy) -> Result<()> {
        match &wp.accept {
            Some(text) => policy::save_accepted(&*self.backend, text),
            None => Ok(()),
        }
    }

    /// `.veilpolicy` of `tree`: `Some(None)` if it has none, `None` if it
    /// cannot be read.
    fn policy_text_in(&self, tree: &ObjectId) -> Result<Option<Option<Vec<u8>>>> {
        let Some(e) = self.store.tree(tree)?.get(POLICY_FILE).cloned() else {
            return Ok(Some(None));
        };
        // A directory (only a hostile tree records one, BUG-121): no text.
        if e.kind != crate::object::EntryKind::File {
            return Ok(None);
        }
        match self.store.read_entry(&e) {
            Ok(b) => Ok(Some(Some(b))),
            Err(err) if err.is_unreadable() => Ok(None),
            Err(err) => Err(err),
        }
    }

    /// The policy snapshots of `fs` apply now (`vl policy check`, `vl scan`).
    pub fn effective_policy(&self, fs: &dyn StorageBackend) -> Result<Policy> {
        Ok(self.snapshot_policy(fs, None)?.policy)
    }

    /// Files of working copy `fs` kept under the accepted policy because its
    /// `.veilpolicy` would weaken their protection, and directories the
    /// accepted policy ignores that it would not (as a whole, as snapshots
    /// report them).
    pub fn policy_held_back(&self, fs: &dyn StorageBackend) -> Result<Vec<HeldBack>> {
        let policy = self.effective_policy(fs)?;
        if policy.accepted().is_none() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        let mut stack = vec![VPath::root()];
        while let Some(dir) = stack.pop() {
            for child in fs.list_dir(&dir)? {
                if is_reserved_name(&child.name) || is_temp_name(&child.name) {
                    continue;
                }
                let path = dir.join(&child.name);
                let is_dir = child.kind == NodeKind::Dir;
                let c = policy.classify(&path, is_dir);
                if is_dir && c.tier != Tier::Ignored {
                    // Never recorded here, so nothing to hold back (BUG-200).
                    if !crate::vfs::is_nested_repository(fs, &path)? {
                        stack.push(path);
                    }
                } else if let Some((tier, force)) = &c.held_back {
                    out.push(HeldBack {
                        path,
                        accepted: c.keyword(),
                        wanted: policy::tier_keyword(tier, *force),
                        dir: is_dir,
                    });
                }
            }
        }
        out.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(out)
    }

    /// Accept the `.veilpolicy` of working copy `fs` (`vl policy accept`):
    /// from the next snapshot on it applies in full. Returns the files whose
    /// protection this weakens (until now held back).
    pub fn accept_policy(&self, fs: &dyn StorageBackend) -> Result<Vec<HeldBack>> {
        let text = match policy::read_policy_file(fs)? {
            PolicyFile::File(t) | PolicyFile::Linked(t) => t,
            PolicyFile::Absent => Vec::new(),
            // Accepting "no policy" for a file that is there but cannot be
            // read would lift every rule.
            PolicyFile::Unavailable(why) => {
                return Err(VeilError::Policy(format!("cannot accept {POLICY_FILE}: cannot read it ({why}); fix it first")))
            }
        };
        let held = self.policy_held_back(fs)?;
        policy::save_accepted(&*self.backend, &text)?;
        Ok(held)
    }
}
