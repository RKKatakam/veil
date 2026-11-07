//! The project directory as a working copy: which workspace it is attached
//! to, which snapshot it was last materialised from, and the journal that
//! makes moving it to another snapshot or workspace crash-safe.
//!
//! The record lives in `.veil/local/checkout.json` ([`CheckoutState`]),
//! device-local like the rest of `.veil/local/`. Moving the directory
//! ([`Repo::move_working_copy`]) is journalled:
//!
//! 1. the target (workspace and snapshot) is written to the record as
//!    [`CheckoutState::pending`], durably, before any file is touched;
//! 2. the files are checked out;
//! 3. the record is rewritten to say the directory now holds the target.
//!
//! A process that dies between 1 and 3 (`kill -9`, a full disk, a checkout
//! error) leaves the record saying "somewhere between `snapshot` and
//! `pending`". The next command finishes the move
//! ([`Repo::resume_working_copy`]) before it records anything: checkout only
//! writes files that still hold what `snapshot` put there or already hold
//! the target, and keeps everything else, so running it again from
//! `snapshot` is deterministic. Without the journal the half-moved
//! directory would be recorded as an edit of the workspace it was leaving
//! (BUG-113).
//!
//! Checkout makes its files durable with one barrier, before step 3
//! (BUG-818): until then a file is staged beside its path and renamed into
//! place only once its content is durable, so whenever the power fails each
//! path holds its old version or its new one, never a torn file the next
//! snapshot could record as an edit. Finishing the move rewrites every
//! file of the diff that holds the target already (an earlier write may
//! never have reached the disk if its barrier failed), and removes the
//! staged copies the interrupted checkout left.

use serde::{Deserialize, Serialize};

use crate::{
    checkout::{CheckoutReport, Materialised},
    error::{Result, VeilError},
    id::ObjectId,
    repo::Repo,
    statcache::StatCache,
    vfs::StorageBackend,
    vpath::VPath,
};

/// Where the CLI keeps the record of the project directory.
pub const CHECKOUT_STATE_PATH: &str = ".veil/local/checkout.json";

/// Which workspace the project directory is attached to, which snapshot was
/// last materialised there, and what was materialised from what (files left
/// out because they were unreadable; see [`Materialised`]). Device-local.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CheckoutState {
    pub workspace: String,
    pub snapshot: ObjectId,
    #[serde(default, skip_serializing_if = "Materialised::is_empty")]
    pub materialised: Materialised,
    /// The journal: a move of the directory to this target was started and
    /// has not finished. Until it has, the directory holds a mix of
    /// `snapshot` and the target, and belongs to the target's workspace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<PendingCheckout>,
}

/// The target of an unfinished move of the project directory.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PendingCheckout {
    pub workspace: String,
    pub snapshot: ObjectId,
}

impl CheckoutState {
    pub fn new(workspace: &str, snapshot: ObjectId, materialised: Materialised) -> CheckoutState {
        CheckoutState {
            workspace: workspace.to_string(),
            snapshot,
            materialised,
            pending: None,
        }
    }

    pub fn path() -> VPath {
        VPath::new(CHECKOUT_STATE_PATH).expect("valid")
    }

    /// The record in `fs`, if there is one.
    pub fn load(fs: &dyn StorageBackend) -> Result<Option<CheckoutState>> {
        match fs.read_opt(&Self::path())? {
            Some(raw) => serde_json::from_slice(&raw)
                .map(Some)
                .map_err(|e| VeilError::Corrupt(CHECKOUT_STATE_PATH.into(), e.to_string())),
            None => Ok(None),
        }
    }

    /// Write the record (atomically and durably, as every backend write).
    pub fn save(&self, fs: &dyn StorageBackend) -> Result<()> {
        fs.write(&Self::path(), &serde_json::to_vec_pretty(self)?)
    }

    /// The workspace the directory belongs to: the target of an unfinished
    /// move, else the one it was last materialised from.
    pub fn attached(&self) -> &str {
        self.pending.as_ref().map_or(&self.workspace, |p| &p.workspace)
    }
}

impl Repo {
    /// Check snapshot `target` of workspace `ws` out into `fs`, a new,
    /// empty working copy (a clone), journalled like every move: the
    /// record says "moving from the root snapshot to `target`" before the
    /// first file is written, so a clone killed during its checkout is
    /// finished by the next command instead of having the files it had
    /// not written recorded as deleted (BUG-830). Returns the saved record.
    ///
    /// `partial`: a clone that writes only part of `target` (`vl clone
    /// --only`) gives the tree that stands for what it never writes
    /// (`target`'s tree without the directory it writes, its entries kept
    /// by id and never walked) and the paths it never shows. Checkout then
    /// writes only what differs from that tree, now and when resumed.
    pub fn check_out_new(
        &self,
        fs: &dyn StorageBackend,
        ws: &str,
        target: ObjectId,
        partial: Option<(ObjectId, Vec<VPath>)>,
    ) -> Result<(CheckoutState, CheckoutReport)> {
        let record = match partial {
            Some((shown, hidden)) => Materialised::shown_as(shown, hidden),
            None => Materialised::default(),
        };
        let mut state = CheckoutState::new(ws, self.root_id(), record);
        let report = self.move_working_copy(fs, &mut state, ws, target, None)?;
        Ok((state, report))
    }

    /// Move the working copy `fs`, described by `state`, to snapshot
    /// `target` of workspace `ws`, journalled (see the module
    /// documentation). On return `state` describes `fs` as holding `target`
    /// and is saved. Files that are not what `state` says were materialised
    /// (local edits, quarantined files, anything in the way) are kept and
    /// reported, never overwritten or deleted.
    pub fn move_working_copy(
        &self,
        fs: &dyn StorageBackend,
        state: &mut CheckoutState,
        ws: &str,
        target: ObjectId,
        cache: Option<&mut StatCache>,
    ) -> Result<CheckoutReport> {
        let from = self.snapshot(&state.snapshot)?.tree;
        let to = self.snapshot(&target)?.tree;
        let mut record = state.materialised.clone();
        let report = if from != to || !record.is_empty() {
            // Intent first: from here on, a crash leaves the move to finish.
            state.pending = Some(PendingCheckout {
                workspace: ws.to_string(),
                snapshot: target,
            });
            state.save(fs)?;
            match self.checkout_tree_recorded(fs, Some(&from), &to, &mut record, cache) {
                Ok(report) => report,
                // Refused before any file was touched (the target's paths
                // collide on this filesystem): there is no move to finish,
                // and leaving it pending would make every later command,
                // `vl --no-snapshot undo` included, retry it and fail.
                Err(e @ VeilError::NameCollision(_)) => {
                    state.pending = None;
                    state.save(fs)?;
                    return Err(e);
                }
                Err(e) => return Err(e),
            }
        } else {
            CheckoutReport::default()
        };
        *state = CheckoutState::new(ws, target, record);
        state.save(fs)?;
        Ok(report)
    }

    /// Finish a move of the working copy `fs` that was interrupted (see
    /// [`CheckoutState::pending`]). `None` if there was nothing to finish.
    ///
    /// If the target snapshot is gone (it never should be: gc keeps it),
    /// the directory is handed to the target workspace as it is, still
    /// described as `state.snapshot`: the next snapshot then finds it stale
    /// and saves what differs from `state.snapshot` as a change of its own,
    /// so nothing is recorded into the workspace it was leaving.
    pub fn resume_working_copy(
        &self,
        fs: &dyn StorageBackend,
        state: &mut CheckoutState,
        cache: Option<&mut StatCache>,
    ) -> Result<Option<CheckoutReport>> {
        let Some(p) = state.pending.clone() else {
            return Ok(None);
        };
        if self.store().has(&p.snapshot) && self.store().has(&state.snapshot) {
            let from = state.materialised.view().map_or_else(|| self.snapshot(&state.snapshot).map(|s| s.tree), Ok)?;
            let to = self.snapshot(&p.snapshot)?.tree;
            let report = self.move_working_copy(fs, state, &p.workspace, p.snapshot, cache)?;
            crate::checkout::remove_staging_debris(self.store(), fs, &from, &to)?;
            return Ok(Some(report));
        }
        state.workspace = p.workspace;
        state.pending = None;
        state.save(fs)?;
        Ok(None)
    }

    /// If `op` (what `vl undo` in `ws` undoes, see [`Repo::undo_target`])
    /// attached the project directory to `ws`, the workspace it came from:
    /// `vl undo` then goes back to that workspace instead of restoring a
    /// view (the attachment is not in the view). The edits of either
    /// workspace are kept: each was recorded into its own workspace.
    pub fn undo_switch(&self, ws: &str, op: &ObjectId) -> Result<Option<String>> {
        let op = self.ops().get(op)?;
        if op.manual_undo.is_none() {
            return Ok(None);
        }
        Ok(parse_switch_description(&op.description)
            .filter(|(from, to)| to == ws && self.view().workspaces.contains_key(from))
            .map(|(from, _)| from))
    }

    /// If `op` (what `vl redo` in `ws` re-applies, see
    /// [`Repo::redo_target`]) attached the project directory from `ws` to
    /// another workspace, that workspace: `vl redo` switches to it again.
    pub fn redo_switch(&self, ws: &str, op: &ObjectId) -> Result<Option<String>> {
        let op = self.ops().get(op)?;
        if op.manual_undo.is_none() {
            return Ok(None);
        }
        Ok(parse_switch_description(&op.description)
            .filter(|(from, to)| from == ws && self.view().workspaces.contains_key(to))
            .map(|(_, to)| to))
    }

    /// Record, as an operation of its own, that the project directory moves
    /// from workspace `from` to workspace `to`. The view does not change
    /// (the attachment is device-local state), so the operation says how to
    /// go back instead (see [`crate::oplog::Operation::manual_undo`]): `vl
    /// undo` right after a switch must not undo the automatic snapshot of
    /// the workspace just left, which would drop the edits recorded there
    /// (BUG-100).
    pub fn record_workspace_switch(&mut self, from: &str, to: &str) -> Result<Option<ObjectId>> {
        self.record_switch(from, to, |_| {})
    }

    /// [`Repo::record_workspace_switch`] for `vl undo` of the switch `undone`
    /// (see [`Repo::undo_switch`]).
    pub fn record_workspace_switch_undo(&mut self, from: &str, to: &str, undone: ObjectId) -> Result<Option<ObjectId>> {
        self.record_switch(from, to, |tx| tx.undo_of(undone))
    }

    /// [`Repo::record_workspace_switch`] for `vl redo` taking back the undo
    /// `undo` (see [`Repo::redo_switch`]).
    pub fn record_workspace_switch_redo(&mut self, from: &str, to: &str, undo: ObjectId) -> Result<Option<ObjectId>> {
        self.record_switch(from, to, |tx| tx.redo_of(undo))
    }

    fn record_switch(&mut self, from: &str, to: &str, link: impl FnOnce(&mut crate::transaction::Transaction<'_>)) -> Result<Option<ObjectId>> {
        let mut tx = self.transaction(switch_description(from, to))?;
        // `vl undo` in the workspace the directory is now attached to
        // undoes the switch.
        tx.for_workspace(to);
        link(&mut tx);
        tx.view.workspace(to)?;
        tx.manual_undo(format!(
            "it attached the project directory to another workspace, which is not part of the operation log; \
             run `vl ws switch {from}` to go back"
        ));
        tx.commit()
    }

    /// Record, as an operation, a command whose effect lies outside the
    /// view (a key ring, `repo.json`'s remotes, the local vault, the
    /// accepted policy): the view does not change, and `how` says how to
    /// reverse it by hand. `vl undo` then refuses with that explanation
    /// instead of undoing an unrelated, earlier operation (BUG-116).
    pub fn record_outside_view(&mut self, description: impl Into<String>, how: impl Into<String>) -> Result<Option<ObjectId>> {
        let mut tx = self.transaction(description)?;
        tx.repository_wide();
        tx.manual_undo(how);
        tx.commit()
    }
}

fn switch_description(from: &str, to: &str) -> String {
    format!("switch the project directory from workspace '{from}' to '{to}'")
}

/// `(from, to)` of a [`switch_description`]. Workspace names cannot hold
/// quotes ([`crate::workspace::validate_workspace_name`]), so this is exact.
fn parse_switch_description(d: &str) -> Option<(String, String)> {
    let rest = d.strip_prefix("switch the project directory from workspace '")?;
    let (from, rest) = rest.split_once("' to '")?;
    let to = rest.strip_suffix('\'')?;
    (!from.contains('\'') && !to.contains('\'')).then(|| (from.to_string(), to.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn switch_descriptions_round_trip() {
        let d = switch_description("default", "agent-1.x");
        assert_eq!(parse_switch_description(&d), Some(("default".into(), "agent-1.x".into())));
        assert_eq!(parse_switch_description("undo: switch"), None);
    }
}
