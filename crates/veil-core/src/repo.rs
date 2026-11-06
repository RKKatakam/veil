//! The repository: CAS + keychain + operation log, all on one backend.
//!
//! On-backend layout:
//!
//! ```text
//! .veil/repo.json               format version, repository id, remotes
//! .veil/objects/ab/cdef…        content-addressed objects (shared)
//! .veil/objects/pack/           packfiles written by `vl gc`
//! .veil/objects/gc/             gc pending list and keep markers
//! .veil/ops/<id>                operation log (local)
//! .veil/op_heads/<id>           its heads (format 6; `op_head` before)
//! .veil/meta/keyrings/*.json    wrapped scope keys (shared, safe to publish)
//! .veil/meta/embargoes/*.json   embargo records (shared)
//! .veil/meta/vault/<scope>/     team-vault records (shared with team remotes)
//! .veil/local/                  device-only state: checkout pointer, vault
//! ```

use std::{
    collections::{BTreeMap, BinaryHeap, HashMap, HashSet, VecDeque},
    path::Path,
    sync::Arc,
};

use serde::{Deserialize, Serialize};

use crate::{
    crypto::random_bytes,
    error::{Result, VeilError},
    id::{ChangeId, ObjectId},
    identity::Identity,
    keychain::Keychain,
    lock::RepoLock,
    merge::{merge_trees, virtual_merge_base, MergeOutcome},
    now_millis,
    object::{Snapshot, Text},
    oplog::{OpStore, Operation, RawHeads, View, WorkspaceState},
    policy::DEFAULT_SCOPE,
    graph_index::GraphIndex,
    store::ObjectStore,
    transaction::Transaction,
    vfs::StorageBackend,
    vpath::VPath,
};

pub const VEIL_DIR: &str = ".veil";

/// The directory holding the Veil repository of the project at `root`:
/// `<root>/.veil`.
pub fn state_dir(root: &Path) -> std::path::PathBuf {
    root.join(VEIL_DIR)
}

/// Repository format written by `vl init` and by [`crate::upgrade`].
///
/// | format | introduced | adds |
/// |---|---|---|
/// | 1 | vl 0.1.0 | JSON trees |
/// | 2 | vl 1.0.0 | binary trees (`TreeEncoding::Binary`) |
/// | 3 | vl 1.0.0 | standard crypto: AES-SIV sealed objects (`veil:sea2`), HPKE-wrapped ring keys (ring format 3) |
/// | 4 | vl 1.0.0 | first-class conflicts: conflict objects (`veil:conf`) and conflict tree entries |
/// | 5 | vl 1.0.0 | symlink tree entries and conflict terms, annotated tags (`veil:atag`, `Tag::annotation`, `View::remote_release_tags`) |
/// | 6 | vl 1.1.0 | the lock-free op log: `op_heads/`, `Operation::{workspace, rewritten}` |
/// | 7 | vl 1.1.0 | key rings of ring format 4: invites, shares by members, a member's removal of their own device (`docs/HUB.md` §13.12) |
///
/// Every format up to this one is read; see `docs/FORMAT.md` and
/// `docs/CRYPTO.md`.
pub const REPO_FORMAT: u32 = 7;

/// Oldest repository format this build reads (and keeps writing, unchanged,
/// until `vl upgrade`).
pub const MIN_REPO_FORMAT: u32 = 1;

/// The first vl release that reads repository format `format`.
pub fn min_vl_for_format(format: u32) -> &'static str {
    match format {
        0 | 1 => "0.1.0",
        2..=5 => "1.0.0",
        6 | 7 => "1.1.0",
        _ => "a newer release",
    }
}

/// `Ok` if this build can read and write a repository of `format`.
pub fn check_format_supported(format: u32) -> Result<()> {
    if format > REPO_FORMAT {
        return Err(VeilError::Unsupported(format!(
            "this repository uses format {format}, which needs a newer vl (this is vl {}, which reads formats {MIN_REPO_FORMAT} to {REPO_FORMAT})",
            env!("CARGO_PKG_VERSION")
        )));
    }
    if format < MIN_REPO_FORMAT {
        return Err(VeilError::Corrupt("repo.json".into(), format!("invalid repository format {format}")));
    }
    Ok(())
}
pub const DEFAULT_WORKSPACE: &str = "default";
/// The `format` written to `.veil/repo.json` by this version (alias of
/// [`REPO_FORMAT`], kept for the CLI's `--version` and `vl doctor`).
pub const REPO_FORMAT_VERSION: u32 = REPO_FORMAT;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RemoteConfig {
    pub url: String,
    /// Public remotes never receive sealed secrets or unreleased embargoed
    /// history.
    #[serde(default)]
    pub public: bool,
    /// A Veil server remote cloned with `vl clone --only DIR`: only DIR's
    /// files are fetched (device-local; absent otherwise, so earlier
    /// `repo.json` files keep their bytes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub only: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RepoConfig {
    /// Repository format ([`REPO_FORMAT`]). A reader refuses a format newer
    /// than it knows before reading anything else, so newer data is never
    /// half-understood or rewritten by an older vl.
    pub format: u32,
    pub repo_id: String,
    #[serde(default)]
    pub remotes: BTreeMap<String, RemoteConfig>,
    /// The first vl release that reads this format, for the error message
    /// of releases that do not know the format yet ("needs vl ≥ X").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_vl: Option<String>,
}

impl RepoConfig {
    /// Error if this build cannot use the repository, naming the vl release
    /// it needs when the configuration says so.
    pub fn check_supported(&self) -> Result<()> {
        check_format_supported(self.format).map_err(|e| match (&e, &self.min_vl) {
            (VeilError::Unsupported(_), Some(v)) => VeilError::Unsupported(format!(
                "this repository uses format {} and needs vl {v} or later (this is vl {})",
                self.format,
                env!("CARGO_PKG_VERSION")
            )),
            _ => e,
        })?;
        Ok(())
    }
}

/// Read and parse `.veil/repo.json` on `backend`.
pub fn read_config(backend: &dyn StorageBackend) -> Result<RepoConfig> {
    let raw = backend
        .read(&config_path())
        .map_err(|_| VeilError::NotFound("Veil repository (run `vl init`)".into()))?;
    Ok(serde_json::from_slice(&raw)?)
}

/// Write `.veil/repo.json` (atomically and durably on disk).
pub(crate) fn write_config(backend: &dyn StorageBackend, config: &RepoConfig) -> Result<()> {
    backend.write(&config_path(), &serde_json::to_vec_pretty(config)?)
}

pub struct Repo {
    pub(crate) backend: Arc<dyn StorageBackend>,
    pub(crate) store: Arc<ObjectStore>,
    pub(crate) ops: OpStore,
    pub(crate) config: RepoConfig,
    pub(crate) op_id: ObjectId,
    pub(crate) view: View,
    pub(crate) user: String,
    pub(crate) root_id: ObjectId,
    /// The history index (`graph_index`): generations, to stop walks early.
    pub(crate) graph: GraphIndex,
    /// The heads the view was read from (ancestors dropped, sorted): the
    /// parents of the next operation.
    pub(crate) base: Vec<ObjectId>,
    /// The head files as read.
    pub(crate) raw: RawHeads,
    /// Opened as a remote ([`Repo::open_remote`]): transactions take the
    /// repository lock, and several heads are merged in memory only.
    pub(crate) remote: bool,
    /// [`Repo::set_command_workspace`].
    pub(crate) command_ws: Option<String>,
    /// What merges of concurrent operations decided ([`Repo::take_warnings`]).
    pub(crate) warnings: Vec<String>,
    /// gc's prune epoch when the view was last read (lock-free
    /// repositories, [`crate::maintenance::prune_epoch`]): a transaction
    /// that finds it changed checks the ids it carried in (BUG-811).
    pub(crate) prune_epoch: Option<Vec<u8>>,
}

impl std::fmt::Debug for Repo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Repo({} on {})", self.config.repo_id, self.backend.kind())
    }
}

pub(crate) fn config_path() -> VPath {
    VPath::new(".veil/repo.json").unwrap()
}

/// Whether a repository keeps its history index on disk: a local one with
/// a working copy. Remotes (bare, or over the network) compute it in memory.
fn persists_index(backend: &dyn StorageBackend, view: &View) -> bool {
    !backend.is_network() && !view.workspaces.is_empty()
}

/// See `Repo::merge_plan`.
pub(crate) struct MergePlan {
    pub(crate) view: View,
    pub(crate) rewritten: BTreeMap<ObjectId, Vec<ObjectId>>,
    pub(crate) before: Vec<View>,
    pub(crate) timestamp: i64,
    pub(crate) warnings: Vec<String>,
}

pub fn is_repo(backend: &dyn StorageBackend) -> bool {
    backend.exists(&config_path()).unwrap_or(false)
}

impl Repo {
    /// Create a repository with a `default` workspace. If an identity is
    /// given, a `team` scope is created with that identity as its first member.
    pub fn init(backend: Arc<dyn StorageBackend>, identity: Option<Identity>, user: &str) -> Result<Repo> {
        Self::init_with(backend, identity, user, false, true, REPO_FORMAT)
    }

    /// Like [`Repo::init`] but without creating the default `team` scope —
    /// used when cloning, where scopes arrive with the remote's key rings.
    pub fn init_for_clone(backend: Arc<dyn StorageBackend>, identity: Option<Identity>, user: &str) -> Result<Repo> {
        Self::init_with(backend, identity, user, false, false, REPO_FORMAT)
    }

    /// [`Repo::init_for_clone`] at a given repository format. A clone takes
    /// its source's format, so that what it writes can be pushed back and
    /// read by everyone who reads the source.
    pub fn init_for_clone_at(
        backend: Arc<dyn StorageBackend>,
        identity: Option<Identity>,
        user: &str,
        format: u32,
    ) -> Result<Repo> {
        check_format_supported(format)?;
        Self::init_with(backend, identity, user, false, false, format)
    }

    /// Create a repository without workspaces (used for remotes).
    pub fn init_bare(backend: Arc<dyn StorageBackend>) -> Result<Repo> {
        Self::init_with(backend, None, "remote", true, false, REPO_FORMAT)
    }

    /// [`Repo::init_bare`] at a given repository format.
    pub fn init_bare_at(backend: Arc<dyn StorageBackend>, format: u32) -> Result<Repo> {
        check_format_supported(format)?;
        Self::init_with(backend, None, "remote", true, false, format)
    }

    fn init_with(
        backend: Arc<dyn StorageBackend>,
        identity: Option<Identity>,
        user: &str,
        bare: bool,
        default_scope: bool,
        format: u32,
    ) -> Result<Repo> {
        if is_repo(&*backend) {
            return Err(VeilError::AlreadyExists("a Veil repository".into()));
        }
        // An `init` that never wrote `repo.json` wrote its objects
        // unsynced ([`InitWrites`]): a power loss may have torn them.
        crate::fsck::recover_interrupted_writes(&*backend, crate::fsck::RecoveryWindow::All)?;
        let config = RepoConfig {
            format,
            repo_id: hex::encode(random_bytes::<16>()),
            remotes: BTreeMap::new(),
            min_vl: (format > 1).then(|| min_vl_for_format(format).to_string()),
        };
        let has_identity = identity.is_some();
        let keys = Arc::new(Keychain::new(backend.clone(), identity, config.repo_id.clone()));
        // The first objects are written unsynced and made durable by one
        // barrier ([`InitWrites`]).
        let deferred: Arc<dyn StorageBackend> = Arc::new(InitWrites(backend.clone()));
        let init_store = ObjectStore::new(deferred.clone(), VPath::new(".veil/objects")?, keys.clone());
        init_store.set_format(format);
        let empty = init_store.empty_tree()?;
        let root_id = init_store.put_snapshot(&Snapshot::root(empty))?;
        // A crashed earlier `init` may have left the ring behind.
        if has_identity && default_scope && keys.load_ring(DEFAULT_SCOPE)?.is_none() {
            keys.create_scope(DEFAULT_SCOPE)?;
        }
        let mut view = View::default();
        if bare {
            view.heads.insert(root_id);
        } else {
            let wc = Snapshot {
                parents: vec![root_id],
                change_id: ChangeId::random(),
                tree: empty,
                description: Text::default(),
                author: user.to_string(),
                timestamp: now_millis(),
                ..Snapshot::root(empty)
            };
            let wc_id = init_store.put_snapshot(&wc)?;
            view.heads.insert(wc_id);
            view.workspaces.insert(
                DEFAULT_WORKSPACE.to_string(),
                WorkspaceState { wc: wc_id },
            );
        }
        drop(init_store);
        drop(deferred);
        // The objects are durable before the operation that names them.
        backend.sync_barrier()?;
        let ops = OpStore::new(backend.clone());
        ops.set_format(format);
        let op = Operation {
            parents: vec![],
            timestamp: now_millis(),
            user: user.to_string(),
            description: "initialize repository".into(),
            view: view.clone(),
            manual_undo: None,
            undo_of: None,
            redo_of: None,
            workspace: None,
            rewritten: Default::default(),
        };
        let op_id = ops.publish(&op, &RawHeads::default())?;
        // `repo.json` is what makes this a repository, so it is written last:
        // a crash before this point leaves no half-initialised repository.
        write_config(&*backend, &config)?;
        let store = Arc::new(ObjectStore::new(backend.clone(), VPath::new(".veil/objects")?, keys.clone()));
        store.set_format(format);
        let graph = GraphIndex::new(backend.clone(), persists_index(&*backend, &view));
        Ok(Repo {
            graph,
            backend,
            store,
            ops,
            config,
            op_id,
            view,
            user: user.to_string(),
            root_id,
            base: vec![op_id],
            raw: RawHeads {
                all: vec![op_id],
                legacy: None,
            },
            remote: bare,
            command_ws: None,
            warnings: Vec::new(),
            prune_epoch: None,
        })
    }

    /// Open the repository on `backend` as a project (or a bare repository
    /// worked on directly). From format 6 its transactions take no lock;
    /// staging left by dead processes is removed, and several heads (from
    /// concurrent operations) are merged now, on disk, so that every command
    /// sees one settled view.
    pub fn open(backend: Arc<dyn StorageBackend>, identity: Option<Identity>, user: &str) -> Result<Repo> {
        Self::open_as(backend, identity, user, false)
    }

    /// Open the repository on `backend` as a remote: its transactions take
    /// the repository lock (push, remote gc), as at every format, and its
    /// single head is never merged on disk by a reader (several heads, which
    /// only a lock-free writer working in the bare repository itself
    /// leaves, are merged in memory, and by the next push under the lock).
    pub fn open_remote(backend: Arc<dyn StorageBackend>) -> Result<Repo> {
        Self::open_as(backend, None, "remote", true)
    }

    fn open_as(backend: Arc<dyn StorageBackend>, identity: Option<Identity>, user: &str, remote: bool) -> Result<Repo> {
        let config = read_config(&*backend)?;
        // Before reading anything else: a newer format is never
        // half-understood, and never rewritten by this build.
        config.check_supported()?;
        let keys = Arc::new(Keychain::new(backend.clone(), identity, config.repo_id.clone()));
        let store = Arc::new(ObjectStore::new(backend.clone(), VPath::new(".veil/objects")?, keys));
        store.set_format(config.format);
        let root_id = store.put_snapshot(&Snapshot::root(store.empty_tree()?))?;
        let ops = OpStore::new(backend.clone());
        ops.set_format(config.format);
        let graph = GraphIndex::new(backend.clone(), false);
        let mut repo = Repo {
            graph,
            backend,
            store,
            ops,
            config,
            op_id: root_id,
            view: View::default(),
            user: user.to_string(),
            root_id,
            base: Vec::new(),
            raw: RawHeads::default(),
            remote,
            command_ws: None,
            warnings: Vec::new(),
            prune_epoch: None,
        };
        // Reading the heads walks the op log (and may merge): registered for
        // gc's deletion fence meanwhile, so no operation it reads is pruned
        // under it (BUG-811's class).
        let reg = match repo.lock_free() {
            true => Some(crate::maintenance::Registration::enter(&repo.store)?),
            false => None,
        };
        repo.read_heads()?;
        repo.graph = GraphIndex::new(repo.backend.clone(), persists_index(&*repo.backend, &repo.view));
        if reg.is_some() {
            // Best effort: what dead transactions staged is garbage.
            let ctx = crate::lock::LockContext::default();
            let _ = repo.store.sweep_staging(&ctx);
            let _ = crate::maintenance::sweep_registrations(&repo.store, &ctx);
            repo.settle()?;
        }
        drop(reg);
        Ok(repo)
    }

    /// Transactions take no lock: format ≥ 6, opened as a project, not over
    /// a network.
    pub fn lock_free(&self) -> bool {
        self.config.format >= crate::oplog::OP_HEADS_REPO_FORMAT && !self.remote && !self.backend.is_network()
    }

    /// New objects are staged per transaction (format ≥ 6, not over a
    /// network, where the unsynced-object protocol and lock recovery stay).
    pub(crate) fn stages_objects(&self) -> bool {
        self.config.format >= crate::oplog::OP_HEADS_REPO_FORMAT && !self.backend.is_network()
    }

    /// Read the heads; with several, merge their views in memory (without
    /// applying rewrites: [`Repo::settle`] does that on disk).
    fn read_heads(&mut self) -> Result<bool> {
        if self.lock_free() {
            self.prune_epoch = crate::maintenance::prune_epoch(&self.store)?;
        }
        let raw = self.ops.raw_heads()?;
        if raw == self.raw && !self.base.is_empty() {
            return Ok(false);
        }
        let heads = self.ops.drop_ancestors(&raw.all)?;
        let (op_id, view) = match heads.as_slice() {
            [one] => (*one, self.ops.get_head(one)?.view),
            _ => {
                let plan = self.merge_plan(&heads, false)?;
                (self.ops.head()?, plan.view)
            }
        };
        self.raw = raw;
        self.base = heads;
        self.op_id = op_id;
        self.view = view;
        Ok(true)
    }

    /// Re-read the operation heads (another process or task may have
    /// published since); from format 6, merge several.
    pub fn reload(&mut self) -> Result<()> {
        // As in `open`: registered while the op log is read.
        let _reg = match self.lock_free() {
            true => Some(crate::maintenance::Registration::enter(&self.store)?),
            false => None,
        };
        if self.read_heads()? {
            // Another process may have pulled a parent the index took as
            // missing.
            self.graph.revalidate(self);
        }
        if self.base.len() > 1 && self.lock_free() {
            self.settle()?;
        }
        Ok(())
    }

    pub fn transaction(&mut self, description: impl Into<String>) -> Result<Transaction<'_>> {
        if self.lock_free() {
            // Registered for gc's deletion fence before the heads are read:
            // nothing the base view names is deleted while this runs (BUG-811).
            let reg = crate::maintenance::Registration::enter(&self.store)?;
            // gc deleted objects since this process last read its view: an
            // id it carried from there may be gone (checked at commit).
            let before = self.prune_epoch.clone();
            self.reload()?;
            let carried_check = before != self.prune_epoch;
            // A transaction starts from one merged head: from several, its
            // view would lack the merge's rewrites and confinement check.
            if self.base.len() > 1 {
                return Err(VeilError::repo(
                    "other commands keep recording operations faster than they can be merged; try again",
                ));
            }
            let mut tx = Transaction::registered(self, description.into(), None, Some(reg))?;
            tx.check_carried = carried_check;
            return Ok(tx);
        }
        let lock = RepoLock::acquire(self.backend.clone())?;
        self.transaction_with_lock(description, lock)
    }

    /// A transaction under `lock`, the repository lock taken by the caller
    /// (a push's phase B waits for it longer than other commands).
    pub(crate) fn transaction_with_lock(&mut self, description: impl Into<String>, lock: RepoLock) -> Result<Transaction<'_>> {
        self.reload()?;
        if self.base.len() > 1 {
            self.settle()?;
        }
        Transaction::new(self, description.into(), Some(lock))
    }

    /// Merge the heads of the op log into one operation, as long as there
    /// are several: a deterministic 3-way merge of their views against
    /// their nearest common operation, applying each side's rewrites to
    /// the other side's new snapshots, and never moving a change out of an
    /// unreleased embargo (`Transaction::for_merge`). Two processes merging
    /// the same heads write the same operation. Lock-free repositories do
    /// this at open and before every transaction; what the merges decided
    /// is in [`Repo::take_warnings`].
    pub fn settle(&mut self) -> Result<()> {
        for _ in 0..16 {
            self.read_heads()?;
            if self.base.len() < 2 {
                return Ok(());
            }
            let heads = self.base.clone();
            let stale = self.raw.clone();
            let plan = self.merge_plan(&heads, true)?;
            let tx = Transaction::for_merge(self, heads, stale, plan)?;
            tx.commit()?;
            self.graph.revalidate(self);
        }
        Ok(())
    }

    /// What merging `heads` (sorted) gives: folded in order, each against
    /// the nearest common operation of those merged so far and the next.
    /// With `rewrites`, also the sides' rewrites to apply, and the views a
    /// change's embargo is judged in.
    pub(crate) fn merge_plan(&self, heads: &[ObjectId], rewrites: bool) -> Result<MergePlan> {
        let mut acc_heads = vec![heads[0]];
        let first = self.ops.get(&heads[0])?;
        let mut timestamp = first.timestamp;
        let mut acc = first.view;
        let mut before = vec![acc.clone()];
        let mut warnings = Vec::new();
        let mut rewritten: BTreeMap<ObjectId, Vec<ObjectId>> = BTreeMap::new();
        let mut divergent: std::collections::BTreeSet<ObjectId> = Default::default();
        for h in &heads[1..] {
            let op = self.ops.get(h)?;
            timestamp = timestamp.max(op.timestamp);
            let split = self.ops.split(&acc_heads, &[*h])?;
            let base = match split.base {
                Some(b) => self.ops.try_get(&b)?.map(|o| o.view).unwrap_or_default(),
                None => View::default(),
            };
            if rewrites {
                for (ids, side) in [(&split.only_a, &acc), (&split.only_b, &op.view)] {
                    let refs: std::collections::HashSet<ObjectId> = side.refs().into_iter().collect();
                    // Oldest first: a later rewrite of a snapshot wins.
                    let mut side_map: BTreeMap<ObjectId, Vec<ObjectId>> = BTreeMap::new();
                    for id in ids.iter().rev() {
                        if let Some(o) = self.ops.try_get(id)? {
                            for (old, new) in o.rewritten {
                                side_map.insert(old, new);
                            }
                        }
                    }
                    // Undone on that side since: it shows `old` again, as
                    // a ref or as an ancestor of one (an undone abandon or
                    // amend of a parent of `@`). One walk from the refs, down
                    // to the oldest rewritten snapshot.
                    let mut floor = crate::graph_index::Gen::MAX;
                    for old in side_map.keys() {
                        if let Some(g) = self.graph.generation(self, old)? {
                            floor = floor.min(g);
                        }
                    }
                    let visible: std::collections::HashSet<ObjectId> = match floor {
                        crate::graph_index::Gen::MAX => Default::default(),
                        f => self.graph.down_to(self, refs.iter().copied(), f)?.into_keys().collect(),
                    };
                    for (old, new) in side_map {
                        if refs.contains(&old) || visible.contains(&old) {
                            continue;
                        }
                        match rewritten.get(&old) {
                            Some(prev) if *prev != new => {
                                divergent.insert(old);
                            }
                            _ => {
                                rewritten.insert(old, new);
                            }
                        }
                    }
                }
                before.push(base.clone());
                before.push(op.view.clone());
            }
            let mut descends = |a: &ObjectId, b: &ObjectId| self.is_ancestor(b, a).unwrap_or(false);
            let merged = crate::oplog::merge_views(&base, &[&acc, &op.view], &mut descends);
            warnings.extend(merged.warnings);
            acc = merged.view;
            acc_heads.push(*h);
        }
        // Both sides rewrote it differently: a divergent change, both
        // replacements stay visible and nothing follows either.
        for d in divergent {
            rewritten.remove(&d);
        }
        Ok(MergePlan {
            view: acc,
            rewritten,
            before,
            timestamp,
            warnings,
        })
    }

    /// Set the workspace the operations of this command are for
    /// ([`crate::oplog::Operation::workspace`]): the attached one, or the
    /// workspace a `ws exec`, `ws write` or mount works on. `None`: the
    /// command is repository-wide.
    pub fn set_command_workspace(&mut self, ws: Option<String>) {
        self.command_ws = ws;
    }

    /// The workspace set by [`Repo::set_command_workspace`].
    pub fn command_workspace(&self) -> Option<&str> {
        self.command_ws.as_deref()
    }

    /// What merges of concurrent operations written by this handle decided
    /// (a workspace or tag moved on two sides, a rewrite not applied), for
    /// the user. Each merge's warnings are returned once.
    pub fn take_warnings(&mut self) -> Vec<String> {
        std::mem::take(&mut self.warnings)
    }

    /// The current heads of the op log (one, unless concurrent operations
    /// landed since this handle last settled).
    pub fn heads(&self) -> &[ObjectId] {
        &self.base
    }

    // ---- accessors -------------------------------------------------------

    pub fn backend(&self) -> &Arc<dyn StorageBackend> {
        &self.backend
    }
    pub fn store(&self) -> &Arc<ObjectStore> {
        &self.store
    }
    pub fn keys(&self) -> &Keychain {
        &self.store.keys
    }
    pub fn identity(&self) -> Option<&Identity> {
        self.store.keys.identity()
    }
    pub fn view(&self) -> &View {
        &self.view
    }
    pub fn op_id(&self) -> ObjectId {
        self.op_id
    }
    pub fn ops(&self) -> &OpStore {
        &self.ops
    }
    pub fn root_id(&self) -> ObjectId {
        self.root_id
    }
    /// The history index.
    pub fn graph(&self) -> &GraphIndex {
        &self.graph
    }
    pub fn user(&self) -> &str {
        &self.user
    }
    pub fn config(&self) -> &RepoConfig {
        &self.config
    }
    pub fn repo_id(&self) -> &str {
        &self.config.repo_id
    }

    pub fn save_config(&mut self, config: RepoConfig) -> Result<()> {
        config.check_supported()?;
        write_config(&*self.backend, &config)?;
        self.store.set_format(config.format);
        self.ops.set_format(config.format);
        self.config = config;
        Ok(())
    }

    /// Read-modify-write `.veil/repo.json` under the repository lock, so
    /// concurrent edits (two `vl remote add`) cannot lose one another: `f`
    /// sees the configuration as currently on disk, not this handle's copy.
    /// Nothing is written if `f` fails.
    pub fn update_config<T>(&mut self, f: impl FnOnce(&mut RepoConfig) -> Result<T>) -> Result<T> {
        let _lock = RepoLock::acquire(self.backend.clone())?;
        let mut config = read_config(&*self.backend)?;
        let out = f(&mut config)?;
        self.save_config(config)?;
        Ok(out)
    }

    /// Repository format (see [`REPO_FORMAT`]).
    pub fn format(&self) -> u32 {
        self.config.format
    }

    pub fn snapshot(&self, id: &ObjectId) -> Result<Arc<Snapshot>> {
        self.store.snapshot(id)
    }

    /// Like [`Repo::snapshot`], but `None` for a snapshot this replica does
    /// not hold. Graph walks use it: a public remote withholds the merged-in
    /// history of an unreleased embargoed merge, so such parents are absent.
    pub fn snapshot_opt(&self, id: &ObjectId) -> Result<Option<Arc<Snapshot>>> {
        match self.store.snapshot(id) {
            Ok(s) => Ok(Some(s)),
            Err(VeilError::Missing(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn workspace_wc(&self, ws: &str) -> Result<ObjectId> {
        Ok(self.view.workspace(ws)?.wc)
    }

    /// The description (plain text).
    pub fn description(&self, s: &Snapshot) -> String {
        s.description.as_str().to_string()
    }

    // ---- graph queries ---------------------------------------------------

    /// Snapshots reachable from `roots`, children before parents, newest
    /// first among unrelated snapshots.
    pub fn topo_children_first(&self, roots: impl IntoIterator<Item = ObjectId>) -> Result<Vec<ObjectId>> {
        let mut nodes: HashMap<ObjectId, Arc<Snapshot>> = HashMap::new();
        let mut stack: Vec<ObjectId> = roots.into_iter().collect();
        while let Some(id) = stack.pop() {
            if nodes.contains_key(&id) {
                continue;
            }
            // A redacted parent (withheld by an unreleased embargo) is simply
            // not part of this replica's graph.
            let Some(s) = self.snapshot_opt(&id)? else { continue };
            stack.extend(s.parents.iter().copied());
            nodes.insert(id, s);
        }
        let mut child_count: HashMap<ObjectId, usize> = HashMap::new();
        for s in nodes.values() {
            for p in s.parents.iter().filter(|p| nodes.contains_key(*p)) {
                *child_count.entry(*p).or_default() += 1;
            }
        }
        let mut heap: BinaryHeap<(i64, ObjectId)> = nodes
            .iter()
            .filter(|(id, _)| !child_count.contains_key(*id))
            .map(|(id, s)| (s.timestamp, *id))
            .collect();
        let mut out = Vec::with_capacity(nodes.len());
        while let Some((_, id)) = heap.pop() {
            out.push(id);
            for p in nodes[&id].parents.iter().filter(|p| nodes.contains_key(*p)) {
                let c = child_count.get_mut(p).unwrap();
                *c -= 1;
                if *c == 0 {
                    heap.push((nodes[p].timestamp, *p));
                }
            }
        }
        Ok(out)
    }

    pub fn visible_snapshots(&self) -> Result<Vec<ObjectId>> {
        self.topo_children_first(self.view.refs())
    }

    /// [`Repo::topo_children_first`] of `roots`, lazily: callers that need
    /// only the first few snapshots read only the history above them.
    pub fn topo_iter(&self, roots: impl IntoIterator<Item = ObjectId>) -> crate::graph_index::TopoIter<'_> {
        self.graph.topo_iter(self, roots)
    }

    /// The visible snapshots ([`Repo::visible_snapshots`]), lazily.
    pub fn visible_iter(&self) -> crate::graph_index::TopoIter<'_> {
        self.topo_iter(self.view.refs())
    }

    /// The visible snapshots whose `embargo` is set, newest first
    /// (generation, then timestamp, then id). Found through the history
    /// index, which walks only lines that build on one: with no embargo in
    /// the history, nothing is walked.
    pub fn visible_embargoed(&self) -> Result<Vec<ObjectId>> {
        let found = self.graph.embargoed_among(self, self.view.refs())?;
        let mut out = Vec::with_capacity(found.len());
        for id in found {
            let g = self.graph.generation(self, &id)?.unwrap_or(0);
            out.push((std::cmp::Reverse(g), std::cmp::Reverse(self.snapshot(&id)?.timestamp), id));
        }
        out.sort();
        Ok(out.into_iter().map(|(_, _, id)| id).collect())
    }

    /// Which of `candidates` are visible (reachable from the view)? Reads
    /// only the history above the oldest candidate.
    pub fn visible_among(&self, candidates: &HashSet<ObjectId>) -> Result<HashSet<ObjectId>> {
        self.graph.reachable_among(self, self.view.refs(), candidates)
    }

    pub fn ancestors(&self, id: &ObjectId) -> Result<HashSet<ObjectId>> {
        let mut seen = HashSet::new();
        let mut stack = vec![*id];
        while let Some(x) = stack.pop() {
            if seen.insert(x) {
                if let Some(s) = self.snapshot_opt(&x)? {
                    stack.extend(s.parents.iter().copied());
                }
            }
        }
        Ok(seen)
    }

    /// Is `a` an ancestor of (or equal to) `b`? Reads only the history
    /// between them (the history index stops the walk below `a`).
    pub fn is_ancestor(&self, a: &ObjectId, b: &ObjectId) -> Result<bool> {
        // A snapshot this replica lacks (a redacted parent) has no
        // generation; it is an ancestor if some ancestor names it.
        if a != b && self.snapshot_opt(a)?.is_none() {
            return Ok(self.ancestors(b)?.contains(a));
        }
        self.graph.is_ancestor(self, a, b)
    }

    pub fn common_ancestor(&self, a: &ObjectId, b: &ObjectId) -> Result<ObjectId> {
        let anc = self.ancestors(a)?;
        let mut queue = VecDeque::from([*b]);
        let mut seen = HashSet::new();
        while let Some(x) = queue.pop_front() {
            if anc.contains(&x) {
                return Ok(x);
            }
            if seen.insert(x) {
                if let Some(s) = self.snapshot_opt(&x)? {
                    queue.extend(s.parents.iter().copied());
                }
            }
        }
        Ok(self.root_id)
    }

    /// The tree a new child of `parents` starts from (merging if several).
    ///
    /// Each further parent is merged into the accumulated result against
    /// the merge base of the parents merged so far and that parent
    /// ([`Repo::merge_base_tree`]: a virtual base when there are several).
    pub fn parents_tree(&self, parents: &[ObjectId]) -> Result<MergeOutcome> {
        match parents {
            [] => Ok(MergeOutcome::clean(self.store.empty_tree()?)),
            [p] => Ok(MergeOutcome::clean(self.snapshot(p)?.tree)),
            [first, rest @ ..] => {
                let mut acc = self.snapshot(first)?.tree;
                let mut merged = vec![*first];
                let mut conflicts = Vec::new();
                let mut renames = Vec::new();
                for p in rest {
                    // A redacted extra parent (the withheld source of an
                    // unreleased embargo) contributes nothing we can see.
                    let Some(ps) = self.snapshot_opt(p)? else { continue };
                    let base = self.merge_base_tree(&merged, &[*p])?;
                    let out = merge_trees(&self.store, Some(base), acc, ps.tree)?;
                    acc = out.tree;
                    conflicts.extend(out.conflicts);
                    renames.extend(out.renames);
                    merged.push(*p);
                }
                Ok(MergeOutcome { tree: acc, conflicts, renames })
            }
        }
    }

    /// Every snapshot reachable from `ids` (themselves included). Redacted
    /// snapshots are included but not walked through.
    fn ancestors_of(&self, ids: &[ObjectId]) -> Result<HashSet<ObjectId>> {
        let mut seen = HashSet::new();
        let mut stack = ids.to_vec();
        while let Some(x) = stack.pop() {
            if seen.insert(x) {
                if let Some(s) = self.snapshot_opt(&x)? {
                    stack.extend(s.parents.iter().copied());
                }
            }
        }
        Ok(seen)
    }

    /// The merge bases of `a` and `b` (each a set of snapshots): their
    /// common ancestors that are not an ancestor of another common
    /// ancestor. There are several after a criss-cross merge. Oldest first
    /// (by timestamp, then id), so the order does not depend on the order
    /// of `a` and `b`. Redacted snapshots are left out.
    pub fn merge_bases(&self, a: &[ObjectId], b: &[ObjectId]) -> Result<Vec<ObjectId>> {
        let mut best = Vec::new();
        for c in self.graph.merge_bases(self, a, b)? {
            if let Some(s) = self.snapshot_opt(&c)? {
                best.push((s.timestamp, c));
            }
        }
        best.sort();
        Ok(best.into_iter().map(|(_, id)| id).collect())
    }

    /// [`Repo::merge_bases`] by full ancestor sets, without the history
    /// index: the reference the index is tested against.
    #[doc(hidden)]
    pub fn merge_bases_naive(&self, a: &[ObjectId], b: &[ObjectId]) -> Result<Vec<ObjectId>> {
        let from_a = self.ancestors_of(a)?;
        let common: HashSet<ObjectId> = self.ancestors_of(b)?.into_iter().filter(|x| from_a.contains(x)).collect();
        // Everything below a common ancestor is a common ancestor too, and
        // not a best one.
        let mut below = HashSet::new();
        let mut stack = Vec::new();
        for c in &common {
            if let Some(s) = self.snapshot_opt(c)? {
                stack.extend(s.parents.iter().copied());
            }
        }
        while let Some(x) = stack.pop() {
            if below.insert(x) {
                if let Some(s) = self.snapshot_opt(&x)? {
                    stack.extend(s.parents.iter().copied());
                }
            }
        }
        let mut best = Vec::new();
        for c in common {
            if below.contains(&c) {
                continue;
            }
            if let Some(s) = self.snapshot_opt(&c)? {
                best.push((s.timestamp, c));
            }
        }
        best.sort();
        Ok(best.into_iter().map(|(_, id)| id).collect())
    }

    /// The tree to merge `a` and `b` against: the tree of their merge base
    /// or, when there are several (a criss-cross merge), a **virtual merge
    /// base**, as Git's recursive/ort strategies build it. The bases are
    /// merged with each other, recursively against their own merge bases,
    /// and conflicts in that merge stay in it as markers. So two earlier
    /// resolutions that disagree conflict again instead of one of them
    /// being taken silently (BUG-244).
    pub fn merge_base_tree(&self, a: &[ObjectId], b: &[ObjectId]) -> Result<ObjectId> {
        self.merge_base_tree_at(a, b, 0)
    }

    fn merge_base_tree_at(&self, a: &[ObjectId], b: &[ObjectId], depth: usize) -> Result<ObjectId> {
        /// Nested criss-crosses deeper than this merge against the empty
        /// tree: every disagreement is then a conflict, never a silent pick.
        const MAX_VIRTUAL_BASE_DEPTH: usize = 8;
        let bases = self.merge_bases(a, b)?;
        match bases.as_slice() {
            [] => self.store.empty_tree(),
            [one] => Ok(self.snapshot(one)?.tree),
            _ if depth >= MAX_VIRTUAL_BASE_DEPTH => self.store.empty_tree(),
            [first, rest @ ..] => {
                let mut acc = self.snapshot(first)?.tree;
                let mut merged = vec![*first];
                for x in rest {
                    let base = self.merge_base_tree_at(&merged, &[*x], depth + 1)?;
                    acc = virtual_merge_base(&self.store, Some(base), acc, self.snapshot(x)?.tree)?;
                    merged.push(*x);
                }
                Ok(acc)
            }
        }
    }

    /// `tree`, a child of `old_parents`, moved onto `new_parents`: what the
    /// child changed relative to the merge of its old parents, applied to
    /// the merge of its new parents. A merge moved because one parent moved
    /// is re-merged this way, as Jujutsu does, never rebased by one
    /// parent's diff alone (BUG-251).
    ///
    /// Conflicts are those of applying the change, plus those of the new
    /// parents' own merge whose markers reach the result unchanged. Renames
    /// are followed ([`crate::merge`]): a file the new parents renamed gets
    /// the change's edit at its new name; `renames` reports those of
    /// applying the change.
    pub fn rebase_tree(&self, old_parents: &[ObjectId], new_parents: &[ObjectId], tree: ObjectId) -> Result<MergeOutcome> {
        let base = self.parents_tree(old_parents)?.tree;
        let onto = self.parents_tree(new_parents)?;
        let out = merge_trees(&self.store, Some(base), onto.tree, tree)?;
        let mut conflicts = out.conflicts;
        for c in onto.conflicts {
            if conflicts.contains(&c) {
                continue;
            }
            let now = crate::tree::lookup(&self.store, &out.tree, &c).ok().flatten();
            if now.is_some() && now == crate::tree::lookup(&self.store, &onto.tree, &c).ok().flatten() {
                conflicts.push(c);
            }
        }
        Ok(MergeOutcome { tree: out.tree, conflicts, renames: out.renames })
    }

    /// No content change relative to its parents.
    pub fn is_empty_change(&self, id: &ObjectId) -> Result<bool> {
        let s = self.snapshot(id)?;
        if s.parents.is_empty() {
            return Ok(true);
        }
        Ok(self.parents_tree(&s.parents)?.tree == s.tree)
    }

    /// The newest `limit` operations the heads reach, newest first (by
    /// timestamp, then id). A merge of concurrent operations is followed
    /// by both sides; pruned operations end their branch.
    pub fn op_log(&self, limit: usize) -> Result<Vec<(ObjectId, Operation)>> {
        // The current operations must exist.
        for h in &self.base {
            self.ops.get(h)?;
        }
        self.ops.walk(&self.base).take(limit).collect()
    }
}

/// The first objects [`Repo::init_with`] writes (the empty tree, the root
/// snapshot, the first working copy): unsynced, all made durable by one
/// barrier before the operation that names them, instead of three fsyncs
/// each in turn. An `init` that crashed before `repo.json` may leave them
/// torn; the next `init` removes those first.
#[derive(Debug)]
struct InitWrites(Arc<dyn StorageBackend>);

impl StorageBackend for InitWrites {
    fn kind(&self) -> &'static str {
        self.0.kind()
    }
    fn is_network(&self) -> bool {
        self.0.is_network()
    }
    fn read(&self, path: &VPath) -> Result<Vec<u8>> {
        self.0.read(path)
    }
    fn write(&self, path: &VPath, data: &[u8]) -> Result<()> {
        self.0.write_unsynced(path, data)
    }
    fn write_unsynced(&self, path: &VPath, data: &[u8]) -> Result<()> {
        self.0.write_unsynced(path, data)
    }
    fn sync_barrier(&self) -> Result<()> {
        self.0.sync_barrier()
    }
    fn create_new(&self, path: &VPath, data: &[u8]) -> Result<bool> {
        // Whatever is there was left by an `init` that never finished
        // (nothing is a repository before `repo.json`), maybe torn by a
        // power loss: written again.
        self.0.write_unsynced(path, data)?;
        Ok(true)
    }
    fn remove_file(&self, path: &VPath) -> Result<()> {
        self.0.remove_file(path)
    }
    fn remove_dir_all(&self, path: &VPath) -> Result<()> {
        self.0.remove_dir_all(path)
    }
    fn create_dir_all(&self, path: &VPath) -> Result<()> {
        self.0.create_dir_all(path)
    }
    fn list_dir(&self, path: &VPath) -> Result<Vec<crate::vfs::DirEntry>> {
        self.0.list_dir(path)
    }
    fn metadata(&self, path: &VPath) -> Result<Option<crate::vfs::Metadata>> {
        self.0.metadata(path)
    }
    fn set_executable(&self, path: &VPath, executable: bool) -> Result<()> {
        self.0.set_executable(path, executable)
    }
}
