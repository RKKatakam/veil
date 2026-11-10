//! The accepted policy of the repository's own working copy.
//!
//! A `.veilpolicy` that arrives from someone else (merge, pull, checkout of
//! another change, rebase, undo) must never weaken, silently,
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
//! member and are snapshotted under their own `.veilpolicy`; they never
//! move the accepted policy either, so an agent editing `.veilpolicy` in a
//! sandbox cannot accept it on the member's behalf.
//!
//! Where the files were written by a command rather than the member (a
//! `vl ws exec` sandbox, a mount: `SnapshotOptions::policy_from_command`),
//! the recorded `.veilpolicy` (of the tree the files were synced from) is
//! the pin (`Repo::command_policy`, BUG-560): an edit that only protects
//! more is recorded and applies; one that weakens it, or could, is held
//! back. The paths it would weaken keep their recorded classification
//! (reported in [`BuildReport::policy_held_back`]), its stronger rules
//! apply, and the tree keeps the recorded `.veilpolicy`, so the next run,
//! which starts from that tree, is pinned the same way. The edit stays
//! where the command made it until the member records it with
//! [`Repo::accept_workspace_policy`] (`vl policy accept --workspace`).
//!
//! [`BuildReport::policy_held_back`]: crate::builder::BuildReport::policy_held_back

use std::sync::Arc;

use crate::{
    error::{Result, VeilError},
    id::ObjectId,
    object::is_reserved_name,
    policy::{self, CommandEdit, HeldBack, Policy, PolicyFile, Tier, WorkingCopyPolicy, POLICY_FILE},
    repo::Repo,
    vfs::{is_temp_name, NodeKind, StorageBackend},
    vpath::VPath,
    workspace::{SnapshotOptions, WcSnapshot},
};

/// The policy a recording of files a command wrote applies (see
/// [`Repo::command_policy`]).
#[derive(Debug)]
pub(crate) struct CommandPolicy {
    pub policy: Policy,
    /// `.veilpolicy` was edited in a way that may weaken the recorded one:
    /// how, and why (for
    /// [`BuildReport::policy_edit_held`](crate::builder::BuildReport::policy_edit_held)). Held back
    /// (`hold_command_edit`) unless it is [`CommandEdit::Adds`] and no
    /// path of the snapshot is held back.
    pub edit: Option<(CommandEdit, String)>,
}

/// Every path of `fs` that `policy` keeps under its accepted classification,
/// and directories the accepted policy ignores that it would not (as a
/// whole, as snapshots report them).
fn held_back_in(fs: &dyn StorageBackend, policy: &Policy) -> Result<Vec<HeldBack>> {
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
        // A conflict: the text checkout wrote for it (with its markers).
        if !e.kind.is_file_like() {
            return Ok(None);
        }
        match crate::conflict::read_file_like(&self.store, &e) {
            Ok(b) => Ok(Some(Some(b))),
            Err(err) if err.is_unreadable() => Ok(None),
            Err(err) => Err(err),
        }
    }

    /// The policy snapshots of `fs` apply now (`vl policy check`, `vl scan`).
    pub fn effective_policy(&self, fs: &dyn StorageBackend) -> Result<Policy> {
        Ok(self.snapshot_policy(fs, None)?.policy)
    }

    /// [`Repo::effective_policy`] when `fs` was checked out from
    /// `checked_out_from` (so an edit made on disk since `checked_out_from` is
    /// folded as the member's own edit, while any unaccepted incoming change in
    /// `checked_out_from` stays held back).
    pub fn effective_policy_from(&self, fs: &dyn StorageBackend, checked_out_from: Option<&ObjectId>) -> Result<Policy> {
        Ok(self.snapshot_policy(fs, checked_out_from)?.policy)
    }

    /// Files of working copy `fs` kept under the accepted policy because its
    /// `.veilpolicy` would weaken their protection, and directories the
    /// accepted policy ignores that it would not (as a whole, as snapshots
    /// report them).
    pub fn policy_held_back(&self, fs: &dyn StorageBackend) -> Result<Vec<HeldBack>> {
        held_back_in(fs, &self.effective_policy(fs)?)
    }

    /// The policy a recording applies to files a command wrote (a `vl ws
    /// exec` sandbox, a mount), not the member: `parent_tree` is the tree
    /// they were synced from, whose `.veilpolicy` is the pin (BUG-560).
    ///
    /// * The same rules, or an edit that only protects more
    ///   ([`CommandEdit::Strengthens`]): the edit applies and is recorded.
    /// * Any other regular `.veilpolicy`: it applies where it is stronger,
    ///   the recorded policy where it would be weaker; whether the edit is
    ///   held back is decided once the snapshot's paths are known
    ///   (`hold_command_edit`).
    /// * Deleted, a symlink, unreadable: the recorded policy applies, and
    ///   the tree keeps it (a deleted policy file never lifts protection,
    ///   BUG-553; an unreadable one never fails the recording, BUG-554).
    pub(crate) fn command_policy(&self, fs: &dyn StorageBackend, parent_tree: &ObjectId) -> Result<CommandPolicy> {
        let Some(recorded) = self.policy_text_in(parent_tree)? else {
            // The recorded policy cannot be read (only a hostile tree):
            // nothing to pin, as before.
            return Ok(CommandPolicy {
                policy: Policy::load_or_accepted(fs, None)?.0,
                edit: None,
            });
        };
        let pinned = Policy::parse(&String::from_utf8_lossy(recorded.as_deref().unwrap_or_default()));
        let held = |why: String| {
            Ok(CommandPolicy {
                policy: pinned.clone(),
                edit: Some((CommandEdit::Weakens, why)),
            })
        };
        match policy::read_policy_file(fs)? {
            PolicyFile::File(text) => {
                let edited = Policy::parse(&String::from_utf8_lossy(&text));
                if recorded.as_deref() == Some(text.as_slice()) {
                    return Ok(CommandPolicy { policy: edited, edit: None });
                }
                match policy::command_edit(&pinned, &edited) {
                    CommandEdit::Strengthens => Ok(CommandPolicy { policy: edited, edit: None }),
                    kind => Ok(CommandPolicy {
                        policy: edited.guarded_by(pinned),
                        edit: Some((kind, "could classify some paths more weakly than the recorded policy".to_string())),
                    }),
                }
            }
            PolicyFile::Absent if recorded.is_none() => Ok(CommandPolicy {
                policy: Policy::builtin(),
                edit: None,
            }),
            PolicyFile::Absent => held("was deleted".to_string()),
            PolicyFile::Linked(_) => held("is a symlink".to_string()),
            PolicyFile::Unavailable(why) => held(format!("cannot be read ({why})")),
        }
    }

    /// Record `text` as the `.veilpolicy` of virtual workspace `ws`, as the
    /// member's decision (`vl policy accept --workspace`): an edit a
    /// command made in the workspace's sandbox or mount that was held back
    /// because it weakens the recorded policy (see
    /// `Repo::command_policy`). Returns the recording and the paths of
    /// the workspace whose protection this weakens.
    pub fn accept_workspace_policy(&mut self, ws: &str, text: &[u8]) -> Result<(WcSnapshot, Vec<HeldBack>)> {
        let wc = self.workspace_wc(ws)?;
        let tree = self.snapshot(&wc)?.tree;
        let overlay = self.workspace_overlay(ws)?;
        overlay.write(&VPath::new(POLICY_FILE)?, text)?;
        let held = held_back_in(&overlay, &self.command_policy(&overlay, &tree)?.policy)?;
        let out = self.snapshot_workspace_with(
            ws,
            &overlay,
            SnapshotOptions {
                description: Some(format!("accept {POLICY_FILE} in workspace '{ws}'")),
                expected_wc: Some(wc),
                ..Default::default()
            },
        )?;
        if out.superseded {
            return Err(VeilError::repo(format!("workspace '{ws}' moved meanwhile; try again")));
        }
        Ok((out, held))
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
