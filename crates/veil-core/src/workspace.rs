//! Working copies and virtual workspaces.
//!
//! A *workspace* is just a named pointer to a working-copy snapshot in the
//! view. It has no directory of its own: the project root can be attached to
//! any workspace, other workspaces live purely in the DAG and are edited
//! through overlays (in memory) or short-lived materialisations. Nothing is
//! ever "checked out hostage" the way a git worktree locks a branch.

use std::sync::Arc;

use crate::{
    builder::{build_tree_cached, BuildOptions, BuildReport, InjectedSecrets},
    checkout::{checkout_cached, checkout_recorded, CheckoutReport, Materialised},
    error::{Result, VeilError},
    id::{ChangeId, ObjectId},
    merge::merge_trees,
    now_millis,
    object::Snapshot,
    oplog::{View, WorkspaceState},
    repo::Repo,
    statcache::StatCache,
    store::ObjectStore,
    tree::{lookup, TreeView},
    vfs::{OverlayBackend, StorageBackend},
    vpath::VPath,
};

/// Options of [`Repo::snapshot_workspace_with`].
#[derive(Default)]
pub struct SnapshotOptions<'a> {
    /// Stat cache of `fs` (consulted and updated).
    pub cache: Option<&'a mut StatCache>,
    /// Secrets handed to whoever wrote `fs` (see
    /// [`Repo::snapshot_workspace_injected`]).
    pub injected: Option<&'a InjectedSecrets>,
    /// What `fs` was materialised from (see [`BuildOptions::materialised`]).
    pub materialised: Option<&'a Materialised>,
    /// Description of the operation. The default is the automatic snapshot
    /// ([`snapshot_op_description`]), which `undo` skips as "the user's
    /// uncommitted edits". A command that edits the working copy itself
    /// (`vl expose`, `vl restore`, …) names its operation instead, so `vl
    /// undo` reverts that command.
    pub description: Option<String>,
    /// A command wrote `.veilpolicy` into `fs` from another revision without
    /// moving the working copy (`vl restore --from`): a difference from the
    /// working copy's tree is then not the member's own edit, and is
    /// guarded by the accepted policy like any incoming change (see
    /// [`crate::policy::working_copy_policy`]).
    pub policy_incoming: bool,
    /// The working-copy snapshot `fs` was materialised from. If the
    /// workspace has moved on since (another process committed, undid or
    /// checked out, and has not updated `fs` yet), nothing is recorded and
    /// [`WcSnapshot::superseded`] is set: recording `fs` now would put the
    /// old snapshot's files into the new one. Checked under the repository
    /// lock, so no other command can slip in between.
    pub expected_wc: Option<ObjectId>,
    /// Entries a command put back from another revision (`vl restore`):
    /// it wrote what each materialises to into `fs`. The files at these
    /// paths are judged against these entries instead of the working
    /// copy's, so a version put back as it was keeps its audience (a
    /// sealed version stays sealed, a conflict stays the same conflict,
    /// BUG-481); an edit made on top of it is sealed as an edit of it.
    pub carried: &'a [(VPath, crate::object::TreeEntry)],
}

#[derive(Debug, Clone)]
pub struct WcSnapshot {
    pub snapshot: ObjectId,
    pub changed: bool,
    pub report: BuildReport,
    /// Nothing was recorded: the workspace no longer points at
    /// [`SnapshotOptions::expected_wc`] (`snapshot` is where it points now).
    pub superseded: bool,
}

/// An in-memory copy-on-write workspace over a base snapshot. Creating one is
/// O(1); committing it is O(changed paths). It never touches disk.
#[derive(Debug, Clone)]
pub struct EphemeralWorkspace {
    base: ObjectId,
    fs: Arc<OverlayBackend>,
}

impl EphemeralWorkspace {
    pub fn base(&self) -> ObjectId {
        self.base
    }

    pub fn fs(&self) -> &Arc<OverlayBackend> {
        &self.fs
    }

    pub fn write(&self, path: &str, data: impl AsRef<[u8]>) -> Result<()> {
        self.fs.write(&VPath::new(path)?, data.as_ref())
    }

    pub fn read(&self, path: &str) -> Result<Vec<u8>> {
        self.fs.read(&VPath::new(path)?)
    }

    pub fn remove(&self, path: &str) -> Result<()> {
        let p = VPath::new(path)?;
        match self.fs.metadata(&p)? {
            Some(m) if m.kind == crate::vfs::NodeKind::Dir => self.fs.remove_dir_all(&p),
            _ => self.fs.remove_file(&p),
        }
    }
}

/// Description of the operation that records workspace `ws`'s working copy
/// (the automatic snapshot every CLI command takes first).
pub fn snapshot_op_description(ws: &str) -> String {
    format!("snapshot working copy of '{ws}'")
}

/// Description of the operation a `vl ws mount` of workspace `ws` records
/// its overlay with (before another command runs, every `--record-every`
/// seconds, on unmount). Like the automatic snapshot of the attached
/// workspace it is never a command of the user's: `vl undo`, `vl redo` and
/// `vl op restore` skip it, whichever workspace is attached, and carry what
/// it recorded over (BUG-538).
pub fn mount_record_op_description(ws: &str) -> String {
    format!("{MOUNT_RECORD_OP_PREFIX}{ws}'")
}

const MOUNT_RECORD_OP_PREFIX: &str = "record the mount of workspace '";

/// Is `description` that of an automatic recording undo skips in workspace
/// `ws`: `ws`'s automatic snapshot, or any mount's recording?
fn is_automatic_recording(description: &str, ws: &str) -> bool {
    description == snapshot_op_description(ws)
        || description
            .strip_prefix(MOUNT_RECORD_OP_PREFIX)
            .and_then(|rest| rest.strip_suffix('\''))
            .is_some_and(|name| validate_workspace_name(name).is_ok())
}

/// `tree` with the `carried` entries put in (see
/// [`SnapshotOptions::carried`]).
fn with_carried(store: &ObjectStore, tree: ObjectId, carried: &[(VPath, crate::object::TreeEntry)]) -> Result<ObjectId> {
    let mut out = tree;
    for (p, e) in carried {
        out = crate::conflict::set_entry(store, &out, p, Some(e.clone()))?;
    }
    Ok(out)
}

pub fn validate_workspace_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.');
    if ok {
        Ok(())
    } else {
        Err(VeilError::repo(format!("invalid workspace name '{name}'")))
    }
}

impl Repo {
    /// Record the current state of `fs` as the working-copy snapshot of
    /// workspace `ws` (amending it in place, Jujutsu-style). This is the
    /// "automatic micro-snapshot": there is no index and no `add`.
    pub fn snapshot_workspace(&mut self, ws: &str, fs: &dyn StorageBackend) -> Result<WcSnapshot> {
        self.snapshot_workspace_cached(ws, fs, None)
    }

    /// [`Repo::snapshot_workspace`] using (and updating) `cache`, the stat
    /// cache of the working copy `fs`. Unchanged files are not re-read.
    pub fn snapshot_workspace_cached(
        &mut self,
        ws: &str,
        fs: &dyn StorageBackend,
        cache: Option<&mut StatCache>,
    ) -> Result<WcSnapshot> {
        self.snapshot_workspace_injected(ws, fs, cache, None)
    }

    /// [`Repo::snapshot_workspace_cached`] for a backend that was handed
    /// `injected` secrets (a `ws exec --with-isolated` sandbox): content
    /// containing them is quarantined instead of recorded.
    pub fn snapshot_workspace_injected(
        &mut self,
        ws: &str,
        fs: &dyn StorageBackend,
        cache: Option<&mut StatCache>,
        injected: Option<&InjectedSecrets>,
    ) -> Result<WcSnapshot> {
        self.snapshot_workspace_with(
            ws,
            fs,
            SnapshotOptions {
                cache,
                injected,
                ..Default::default()
            },
        )
    }

    /// Record `fs` as the working copy of `ws`, with every option.
    pub fn snapshot_workspace_with(&mut self, ws: &str, fs: &dyn StorageBackend, opts: SnapshotOptions<'_>) -> Result<WcSnapshot> {
        let SnapshotOptions {
            cache,
            injected,
            materialised,
            description,
            policy_incoming,
            expected_wc,
            carried,
        } = opts;
        let mut tx = self.transaction(description.unwrap_or_else(|| snapshot_op_description(ws)))?;
        let wc_id = tx.view.workspace(ws)?.wc;
        if expected_wc.is_some_and(|e| e != wc_id) {
            return Ok(WcSnapshot {
                snapshot: wc_id,
                changed: false,
                report: BuildReport::default(),
                superseded: true,
            });
        }
        let wc = tx.repo().snapshot(&wc_id)?;
        // `fs` was checked out from `wc.tree`: a `.veilpolicy` edit is the
        // member's, unless a command wrote it from elsewhere.
        let wp = tx.repo().snapshot_policy(fs, (!policy_incoming).then_some(&wc.tree))?;
        let store = tx.repo().store.clone();
        let rescan = scanner_outdated(&*tx.repo().backend, ws)?;
        // What `fs` was materialised from: the working copy, with the
        // entries a command put back in place of its own.
        let parent_tree = with_carried(&store, wc.tree, carried)?;
        let repo = tx.repo();
        let line_base = || Ok(repo.parents_tree(&wc.parents)?.tree);
        let (tree, report) = build_tree_cached(
            &store,
            fs,
            &BuildOptions {
                policy: &wp.policy,
                parent_tree: Some(parent_tree),
                cloak: wc.cloak.as_deref(),
                injected,
                rescan,
                materialised,
                line_base: Some(&line_base),
            },
            cache,
        )?;
        tx.repo().record_accepted(&wp)?;
        if tree == wc.tree {
            // Nothing to record; the re-scan (if any) found nothing new.
            if rescan {
                mark_scanned(&*tx.repo().backend, ws)?;
            }
            return Ok(WcSnapshot {
                snapshot: wc_id,
                changed: false,
                report,
                superseded: false,
            });
        }
        let mut new = (*wc).clone();
        new.tree = tree;
        new.predecessors = vec![wc_id];
        new.timestamp = now_millis();
        // A conflict stays recorded until the conflicted file is edited.
        new.conflicts.retain(|p| {
            let Ok(p) = VPath::new(p) else { return false };
            let old = lookup(&store, &wc.tree, &p).ok().flatten();
            let cur = lookup(&store, &tree, &p).ok().flatten();
            old.is_some() && old == cur
        });
        // A conflict put back as it was is a conflict of this change again.
        for (p, e) in carried {
            if e.kind == crate::object::EntryKind::Conflict
                && lookup(&store, &tree, p).ok().flatten().as_ref() == Some(e)
                && !new.conflicts.iter().any(|c| c == p.as_str())
            {
                new.conflicts.push(p.to_string());
            }
        }
        let id = tx.rewrite(wc_id, new)?;
        let backend = tx.repo().backend.clone();
        tx.commit()?;
        // Only after the re-scanned tree is durable: a crash before this
        // point simply re-scans again next time.
        if rescan {
            mark_scanned(&*backend, ws)?;
        }
        Ok(WcSnapshot {
            snapshot: id,
            changed: true,
            report,
            superseded: false,
        })
    }

    /// Build a tree from `fs` as an amendment of `snapshot` (what recording
    /// `fs` as that snapshot's new content would give), without recording
    /// anything: [`Repo::build_from_recorded`] relative to its tree, on its
    /// line of work, with its parents as the line's base.
    pub fn build_amending(
        &self,
        fs: &dyn StorageBackend,
        snapshot: &ObjectId,
        cache: Option<&mut StatCache>,
        materialised: Option<&Materialised>,
    ) -> Result<(ObjectId, BuildReport)> {
        self.build_amending_carried(fs, snapshot, cache, materialised, &[])
    }

    /// [`Repo::build_amending`] for a working copy into which a command put
    /// back `carried` entries from another revision (`vl restore`, see
    /// [`SnapshotOptions::carried`]): the files at those paths are judged
    /// against those entries, so a sealed version put back stays sealed.
    pub fn build_amending_carried(
        &self,
        fs: &dyn StorageBackend,
        snapshot: &ObjectId,
        cache: Option<&mut StatCache>,
        materialised: Option<&Materialised>,
        carried: &[(VPath, crate::object::TreeEntry)],
    ) -> Result<(ObjectId, BuildReport)> {
        let snap = self.snapshot(snapshot)?;
        let policy = self.snapshot_policy(fs, None)?.policy;
        let line_base = || Ok(self.parents_tree(&snap.parents)?.tree);
        let parent_tree = with_carried(&self.store, snap.tree, carried)?;
        build_tree_cached(
            &self.store,
            fs,
            &BuildOptions {
                policy: &policy,
                parent_tree: Some(parent_tree),
                cloak: snap.cloak.as_deref(),
                injected: None,
                rescan: false,
                materialised,
                line_base: Some(&line_base),
            },
            cache,
        )
    }

    /// Build a tree from `fs` relative to `parent_tree` without recording
    /// anything (dry run / change detection). With a `cloak`, the line's
    /// base is unknown (see [`BuildOptions::line_base`]); to rebuild a
    /// snapshot of a cloaked line use [`Repo::build_amending`].
    pub fn build_from(&self, fs: &dyn StorageBackend, parent_tree: Option<ObjectId>, cloak: Option<&str>) -> Result<(ObjectId, BuildReport)> {
        self.build_from_cached(fs, parent_tree, cloak, None)
    }

    /// [`Repo::build_from`] using (and updating) the stat cache of `fs`.
    pub fn build_from_cached(
        &self,
        fs: &dyn StorageBackend,
        parent_tree: Option<ObjectId>,
        cloak: Option<&str>,
        cache: Option<&mut StatCache>,
    ) -> Result<(ObjectId, BuildReport)> {
        self.build_from_recorded(fs, parent_tree, cloak, cache, None)
    }

    /// [`Repo::build_from_cached`] for a working copy materialised as
    /// `materialised` says (see [`BuildOptions::materialised`]).
    pub fn build_from_recorded(
        &self,
        fs: &dyn StorageBackend,
        parent_tree: Option<ObjectId>,
        cloak: Option<&str>,
        cache: Option<&mut StatCache>,
        materialised: Option<&Materialised>,
    ) -> Result<(ObjectId, BuildReport)> {
        let policy = self.snapshot_policy(fs, None)?.policy;
        build_tree_cached(
            &self.store,
            fs,
            &BuildOptions {
                policy: &policy,
                parent_tree,
                cloak,
                injected: None,
                rescan: false,
                materialised,
                line_base: None,
            },
            cache,
        )
    }

    /// Materialise the difference between two trees onto `fs`.
    pub fn checkout_tree(&self, fs: &dyn StorageBackend, from: Option<&ObjectId>, to: &ObjectId) -> Result<CheckoutReport> {
        self.checkout_tree_cached(fs, from, to, None)
    }

    /// [`Repo::checkout_tree`] that keeps the stat cache of `fs` consistent
    /// (every written or removed path is invalidated).
    pub fn checkout_tree_cached(
        &self,
        fs: &dyn StorageBackend,
        from: Option<&ObjectId>,
        to: &ObjectId,
        cache: Option<&mut StatCache>,
    ) -> Result<CheckoutReport> {
        checkout_cached(&self.store, fs, from, to, cache)
    }

    /// [`Repo::checkout_tree_cached`] that keeps `record`, the record of
    /// what `fs` was materialised from (see [`Materialised`]), up to date:
    /// on entry it describes `fs` relative to `from`, on return relative to
    /// `to`. Anything recorded that has become readable is filled in.
    pub fn checkout_tree_recorded(
        &self,
        fs: &dyn StorageBackend,
        from: Option<&ObjectId>,
        to: &ObjectId,
        record: &mut Materialised,
        cache: Option<&mut StatCache>,
    ) -> Result<CheckoutReport> {
        checkout_recorded(&self.store, fs, from, to, record, cache)
    }

    /// Materialise what `record` says is missing from `fs` (or shown as an
    /// embargo fallback) relative to `tree`, where this reader can now read
    /// it: a scope key arrived, an embargo was released. Local edits are
    /// never overwritten. See [`Materialised::fill_in`].
    pub fn fill_in_materialised(
        &self,
        fs: &dyn StorageBackend,
        tree: &ObjectId,
        record: &mut Materialised,
        cache: Option<&mut StatCache>,
    ) -> Result<CheckoutReport> {
        record.fill_in(&self.store, fs, tree, cache)
    }

    /// A read-only VFS view of a snapshot's tree.
    pub fn tree_view(&self, snapshot: &ObjectId) -> Result<TreeView> {
        Ok(TreeView::new(self.store.clone(), self.snapshot(snapshot)?.tree))
    }

    /// An in-memory overlay over `base` — the agent sandbox primitive.
    pub fn ephemeral_workspace(&self, base: ObjectId) -> Result<EphemeralWorkspace> {
        let lower: Arc<dyn StorageBackend> = Arc::new(self.tree_view(&base)?);
        Ok(EphemeralWorkspace {
            base,
            fs: Arc::new(OverlayBackend::new(lower)),
        })
    }

    /// Record the overlay as a new snapshot whose parent is the workspace's
    /// base. The workspace itself can then simply be dropped.
    pub fn commit_ephemeral(&mut self, ws: &EphemeralWorkspace, description: &str) -> Result<(ObjectId, BuildReport)> {
        self.commit_fs_as_child(ws.base, &*ws.fs, description)
    }

    /// Snapshot an arbitrary backend as a new child of `base`.
    pub fn commit_fs_as_child(&mut self, base: ObjectId, fs: &dyn StorageBackend, description: &str) -> Result<(ObjectId, BuildReport)> {
        self.commit_fs_as_child_injected(base, fs, description, None)
    }

    /// [`Repo::commit_fs_as_child`] for a backend that was handed `injected`
    /// secrets (see [`Repo::snapshot_workspace_injected`]).
    pub fn commit_fs_as_child_injected(
        &mut self,
        base: ObjectId,
        fs: &dyn StorageBackend,
        description: &str,
        injected: Option<&InjectedSecrets>,
    ) -> Result<(ObjectId, BuildReport)> {
        self.commit_fs_as_child_with(base, fs, description, injected, None, &[])
    }

    /// [`Repo::commit_fs_as_child_injected`] for a backend materialised as
    /// `materialised` records (a path it never showed is carried, not
    /// deleted; see [`BuildOptions::materialised`]) into which a command
    /// put back `carried` entries (see [`SnapshotOptions::carried`]).
    pub fn commit_fs_as_child_with(
        &mut self,
        base: ObjectId,
        fs: &dyn StorageBackend,
        description: &str,
        injected: Option<&InjectedSecrets>,
        materialised: Option<&Materialised>,
        carried: &[(VPath, crate::object::TreeEntry)],
    ) -> Result<(ObjectId, BuildReport)> {
        let mut tx = self.transaction("record ephemeral workspace")?;
        let parent = tx.repo().snapshot(&base)?;
        let wp = tx.repo().snapshot_policy(fs, None)?;
        let store = tx.repo().store.clone();
        // The new change's base is `base` itself.
        let line_base = || Ok(parent.tree);
        let parent_tree = with_carried(&store, parent.tree, carried)?;
        let (tree, report) = build_tree_cached(
            &store,
            fs,
            &BuildOptions {
                policy: &wp.policy,
                parent_tree: Some(parent_tree),
                cloak: parent.cloak.as_deref(),
                injected,
                rescan: false,
                materialised,
                line_base: Some(&line_base),
            },
            None,
        )?;
        tx.repo().record_accepted(&wp)?;
        let snap = Snapshot {
            parents: vec![base],
            change_id: ChangeId::random(),
            tree,
            description: store.make_text(
                description,
                crate::embargo::description_scope(&store, &tree, parent.cloak.as_deref())?.as_deref(),
            )?,
            author: tx.repo().user.clone(),
            timestamp: now_millis(),
            predecessors: vec![],
            conflicts: vec![],
            cloak: parent.cloak.clone(),
            embargo: None,
            signature: None, // signed by the transaction
        };
        let id = tx.write_snapshot(&snap)?;
        tx.set_description(format!("record ephemeral workspace as {}", snap.change_id.short()));
        tx.commit()?;
        Ok((id, report))
    }

    /// Create a named virtual workspace with a fresh change on `base`.
    pub fn create_workspace(&mut self, name: &str, bases: Vec<ObjectId>, cloak: Option<String>) -> Result<ObjectId> {
        validate_workspace_name(name)?;
        if let Some(scope) = &cloak {
            // A line is cloaked under a scope: never an embargo (whose key
            // `is_member` also finds), `local` or a key generation (BUG-124).
            crate::keychain::validate_scope_name(scope)?;
            if !self.keys().is_member(scope) {
                return Err(VeilError::Policy(format!("you hold no key for scope '{scope}'")));
            }
        }
        let mut tx = self.transaction(format!("create workspace '{name}'"))?;
        if tx.view.workspaces.contains_key(name) {
            return Err(VeilError::AlreadyExists(format!("workspace '{name}'")));
        }
        let wc = tx.new_change(bases, "", cloak.clone())?;
        tx.view.workspaces.insert(name.to_string(), WorkspaceState { wc, cloak });
        tx.commit()?;
        Ok(wc)
    }

    pub fn remove_workspace(&mut self, name: &str) -> Result<()> {
        let mut tx = self.transaction(format!("remove workspace '{name}'"))?;
        let st = tx
            .view
            .workspaces
            .remove(name)
            .ok_or_else(|| VeilError::NotFound(format!("workspace '{name}'")))?;
        tx.maybe_abandon_empty(st.wc)?;
        tx.commit()?;
        Ok(())
    }

    /// Undo the most recent *command* not undone yet, without discarding
    /// working-copy edits.
    ///
    /// Every CLI command first snapshots the working copy, so the newest
    /// operations are usually automatic snapshots of `ws`, i.e. the user's
    /// uncommitted edits. Those are not commands: they are skipped, the
    /// operation before them is undone, and the edits they recorded are
    /// re-applied on top of the restored working copy (a 3-way merge, so
    /// what the undone command changed is reverted and the edits stay).
    /// Undos are skipped too: run again, undo goes further back (as in jj;
    /// see [`Repo::undo_target`]), and [`Repo::redo_keeping_edits`] takes
    /// undos back. Returns the new operation and the description of the
    /// undone one.
    ///
    /// A command whose effect lies outside the view (a grant, `vl remote
    /// add`, `vl ws switch`; see [`crate::oplog::Operation::manual_undo`])
    /// is not undone, and neither is anything before it: the error says
    /// how to reverse it by hand. Restoring an older view would leave its
    /// effect in place and silently undo an unrelated, earlier command
    /// instead (BUG-116).
    pub fn undo_keeping_edits(&mut self, ws: &str) -> Result<(ObjectId, String)> {
        self.reload()?;
        let command = self.undo_target(ws)?;
        let op = self.ops.get(&command)?;
        if let Some(how) = &op.manual_undo {
            return Err(VeilError::repo(format!(
                "cannot undo '{}': {how}. \
                 To go back to an earlier state of the repository anyway, pick an operation from `vl op log` \
                 and run `vl op restore <id>` (your unrecorded edits are kept)",
                op.description
            )));
        }
        let parent = *op
            .parents
            .first()
            .ok_or_else(|| VeilError::repo("nothing to undo"))?;
        // An embargo release is not in the view (see `check_undo_release`).
        let release = self.check_undo_release(&op.description)?;
        let view = self.ops.get(&parent)?.view;
        let link = OpLink::UndoOf(command);
        let id = self.restore_view_keeping_edits(ws, view, &op.view, format!("undo: {}", op.description), link)?;
        self.finish_undo_release(release)?;
        Ok((id, op.description))
    }

    /// Re-apply the command the newest undo not yet redone took back,
    /// keeping working-copy edits like [`Repo::undo_keeping_edits`].
    /// Successive redos take back successive undos, newest first; any
    /// command recorded after an undo (other than an undo or redo, and
    /// automatic snapshots of `ws`) leaves nothing to redo. Returns the
    /// new operation and the description of the redone command.
    pub fn redo_keeping_edits(&mut self, ws: &str) -> Result<(ObjectId, String)> {
        self.reload()?;
        let (undo, command) = self.redo_target(ws)?;
        let op = self.ops.get(&command)?;
        if let Some(how) = &op.manual_undo {
            return Err(VeilError::repo(format!("cannot redo '{}': {how}", op.description)));
        }
        if let Some(id) = op.description.strip_prefix(crate::commands::RELEASE_OP_PREFIX) {
            return Err(VeilError::Policy(format!(
                "the last undo took back the release of embargo {id}, and `vl redo` never releases an embargo; \
                 run `vl embargo release {id}` to release it again (nothing was changed)"
            )));
        }
        let parent = *op
            .parents
            .first()
            .ok_or_else(|| VeilError::repo("nothing to redo"))?;
        let before_edits = self.ops.get(&parent)?.view;
        let id = self.restore_view_keeping_edits(ws, op.view, &before_edits, format!("redo: {}", op.description), OpLink::RedoOf(undo))?;
        Ok((id, op.description))
    }

    /// The operation `vl undo` in workspace `ws` undoes: the newest command
    /// that is neither an automatic snapshot of `ws` nor already undone.
    /// An undo is skipped together with what it undid (and everything
    /// between them, which that undo already reverted); a redo stands for
    /// the command it re-applied. So `undo, undo` walks back over two
    /// commands, and `undo, redo, undo` undoes the same one twice.
    pub fn undo_target(&self, ws: &str) -> Result<ObjectId> {
        let mut cur = self.command_at(self.op_id, ws)?;
        loop {
            let op = self.op_or_pruned(&cur, "undo")?;
            if let Some(undone) = op.undo_of {
                let parent = self.op_or_pruned(&undone, "undo")?.parents.first().copied();
                cur = self.command_at(parent.ok_or_else(|| VeilError::repo("nothing to undo"))?, ws)?;
            } else if let Some(undo) = op.redo_of {
                cur = self
                    .op_or_pruned(&undo, "undo")?
                    .undo_of
                    .ok_or_else(|| VeilError::Corrupt(format!("operation {}", cur.short()), format!("it redoes {}, which is not an undo", undo.short())))?;
            } else if op.parents.is_empty() {
                return Err(VeilError::repo("nothing to undo"));
            } else {
                return Ok(cur);
            }
        }
    }

    /// What `vl redo` in workspace `ws` re-applies: `(undo, command)`, the
    /// newest undo not taken back by a redo yet and the command it undid.
    /// Redos are skipped together with the undo they took back; any other
    /// command (automatic snapshots of `ws` aside) ends the search: a new
    /// command clears what could be redone, as in jj.
    pub fn redo_target(&self, ws: &str) -> Result<(ObjectId, ObjectId)> {
        let mut cur = self.command_at(self.op_id, ws)?;
        loop {
            let op = self.op_or_pruned(&cur, "redo")?;
            if let Some(undone) = op.undo_of {
                return Ok((cur, undone));
            }
            let Some(undo) = op.redo_of else {
                return Err(VeilError::repo("nothing to redo: the last command was not an undo"));
            };
            let parent = self.op_or_pruned(&undo, "redo")?.parents.first().copied();
            cur = self.command_at(parent.ok_or_else(|| VeilError::repo("nothing to redo"))?, ws)?;
        }
    }

    /// Operation `id`, or a clear error if `vl gc --keep-ops-days` pruned it.
    fn op_or_pruned(&self, id: &ObjectId, what: &str) -> Result<crate::oplog::Operation> {
        self.ops.try_get(id)?.ok_or_else(|| {
            VeilError::repo(format!(
                "nothing further to {what}: operation {} was pruned by `vl gc --keep-ops-days`",
                id.short()
            ))
        })
    }

    /// [`Repo::restore_operation`] that keeps the uncommitted edits of `ws`
    /// (see [`Repo::undo_keeping_edits`]).
    pub fn restore_operation_keeping_edits(&mut self, ws: &str, op: ObjectId) -> Result<ObjectId> {
        self.reload()?;
        let command = self.last_command_op(ws)?;
        let before_edits = self.ops.get(&command)?.view;
        let view = self.ops.get(&op)?.view;
        self.restore_view_keeping_edits(ws, view, &before_edits, format!("restore to operation {}", op.short()), OpLink::None)
    }

    /// The operations after `op`, newest first, whose effect lies outside
    /// the view (see [`crate::oplog::Operation::manual_undo`]): restoring
    /// the view of `op` leaves what they did in place.
    pub fn manual_undo_since(&self, op: ObjectId) -> Result<Vec<crate::oplog::Operation>> {
        let mut out = Vec::new();
        let mut cur = self.op_id;
        while cur != op {
            let Some(o) = self.ops.try_get(&cur)? else { break };
            let next = o.parents.first().copied();
            if o.manual_undo.is_some() {
                out.push(o);
            }
            match next {
                Some(p) => cur = p,
                None => break,
            }
        }
        Ok(out)
    }

    /// The newest operation that is not an automatic snapshot of `ws`.
    pub(crate) fn last_command_op(&self, ws: &str) -> Result<ObjectId> {
        self.command_at(self.op_id, ws)
    }

    /// `start`, or the newest operation before it that is not an automatic
    /// recording: a snapshot of `ws`, or a mount's recording of any
    /// workspace (see [`mount_record_op_description`]).
    fn command_at(&self, start: ObjectId, ws: &str) -> Result<ObjectId> {
        let mut cur = start;
        loop {
            let op = self.op_or_pruned(&cur, "undo")?;
            match op.parents.first() {
                Some(p) if is_automatic_recording(&op.description, ws) => cur = *p,
                _ => return Ok(cur),
            }
        }
    }

    /// Install `view`, then carry the edits of each workspace recorded
    /// since `before_edits` (its working copy there vs. now) over to the
    /// working copy `view` restores for it. `ws`, the attached workspace,
    /// comes first; the others matter once undo walks back past a switch,
    /// whose new workspace may have recorded edits in the range it skips.
    ///
    /// An undo or redo that would remove a workspace holding such edits is
    /// refused (nothing changes): they could not be carried anywhere.
    /// `vl op restore` goes to the exact state the user picked.
    fn restore_view_keeping_edits(&mut self, ws: &str, view: View, before_edits: &View, description: String, link: OpLink) -> Result<ObjectId> {
        let wc_of = |v: &View, name: &str| v.workspaces.get(name).map(|w| w.wc);
        let mut names: Vec<&String> = self.view.workspaces.keys().collect();
        names.sort_by_key(|n| n.as_str() != ws);
        let mut edits = Vec::new();
        for name in names {
            let (Some(base), Some(now)) = (wc_of(before_edits, name), wc_of(&self.view, name)) else {
                continue;
            };
            if base == now || self.snapshot(&base)?.tree == self.snapshot(&now)?.tree {
                continue;
            }
            match wc_of(&view, name) {
                Some(restored) => {
                    if !edits.iter().any(|(_, _, r)| *r == restored) {
                        edits.push((base, now, restored));
                    }
                }
                None if !matches!(link, OpLink::None) => {
                    let (verb, what) = description.split_once(": ").unwrap_or(("restore", &description));
                    return Err(VeilError::repo(format!(
                        "cannot {verb} '{what}': it would remove workspace '{name}', which holds edits recorded since. \
                         Nothing was changed. To go back anyway, pick an operation from `vl op log` and run \
                         `vl op restore <id>` (the op log keeps those edits)"
                    )));
                }
                None => {}
            }
        }
        let mut tx = self.transaction(description)?;
        tx.view = view;
        tx.record_always();
        match link {
            OpLink::None => {}
            OpLink::UndoOf(op) => tx.undo_of(op),
            OpLink::RedoOf(op) => tx.redo_of(op),
        }
        for (base, now, restored) in edits {
            let base_tree = tx.repo().snapshot(&base)?.tree;
            let now_tree = tx.repo().snapshot(&now)?.tree;
            let target = tx.repo().snapshot(&restored)?;
            let store = tx.repo().store.clone();
            let merged = merge_trees(&store, Some(base_tree), target.tree, now_tree)?;
            if merged.tree != target.tree {
                let mut new = (*target).clone();
                new.tree = merged.tree;
                new.predecessors = vec![restored];
                new.timestamp = now_millis();
                for c in merged.conflicts {
                    let c = c.to_string();
                    if !new.conflicts.contains(&c) {
                        new.conflicts.push(c);
                    }
                }
                tx.rewrite(restored, new)?;
            }
        }
        Ok(tx.commit()?.expect("recorded"))
    }

    /// Overlay over a workspace's current working copy (for editing a
    /// virtual workspace without materialising it).
    pub fn workspace_overlay(&self, ws: &str) -> Result<OverlayBackend> {
        let wc = self.workspace_wc(ws)?;
        Ok(OverlayBackend::new(Arc::new(self.tree_view(&wc)?)))
    }
}

/// How an operation recorded by [`Repo::restore_view_keeping_edits`]
/// relates to earlier ones.
enum OpLink {
    None,
    UndoOf(ObjectId),
    RedoOf(ObjectId),
}

fn scanned_marker(ws: &str) -> Result<VPath> {
    Ok(VPath::new(".veil/local/scanned")?.join(&format!("{ws}.version")))
}

/// Has the working copy of `ws` on this device been fully scanned by the
/// current secret-scanner rules? (Device-local: each machine re-scans once
/// after an upgrade that changes the rules.)
fn scanner_outdated(backend: &dyn StorageBackend, ws: &str) -> Result<bool> {
    let current = crate::secrets::RULES_VERSION.to_string();
    Ok(backend
        .read_opt(&scanned_marker(ws)?)?
        .is_none_or(|v| String::from_utf8_lossy(&v).trim() != current))
}

fn mark_scanned(backend: &dyn StorageBackend, ws: &str) -> Result<()> {
    backend.write(&scanned_marker(ws)?, crate::secrets::RULES_VERSION.to_string().as_bytes())
}
