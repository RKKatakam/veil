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
    object::{Object, Snapshot, Text},
    oplog::{OpStore, Operation, RawHeads, View, WorkspaceState},
    policy::DEFAULT_SCOPE,
    graph_index::GraphIndex,
    store::ObjectStore,
    transaction::Transaction,
    vfs::StorageBackend,
    vpath::VPath,
};

pub const VEIL_DIR: &str = ".veil";

thread_local! {
    /// Depth of [`Repo::exact`] on this thread: nested queries run once,
    /// inside the outer one's rounds.
    static EXACT: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// Is this thread inside [`Exact::run`]?
pub(crate) fn in_exact() -> bool {
    EXACT.with(|d| d.get() > 0)
}

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
/// | 8 | vl 1.1.0 | only secret files are encrypted: no encrypted descriptions, tag messages, tag names, embargoes, folders or lines of work; plain embargo records (embargo record format 2) |
/// | 9 | vl 1.1.0 | a thin clone of a server project ([`PARTIAL_FORMAT`]): the `partial` marker, objects fetched on demand into `.veil/cache/` |
///
/// This build reads format 8 only. `vl upgrade` brings formats 6 and 7 to
/// it, after checking that they hold nothing the removed encryption of
/// non-secret content wrote; formats 1 to 5 are no longer supported. See
/// `docs/FORMAT.md` and `docs/CRYPTO.md`.
pub const REPO_FORMAT: u32 = 8;

/// Oldest repository format this build opens.
pub const MIN_REPO_FORMAT: u32 = REPO_FORMAT;

/// The format of a thin clone (`docs/HUB.md` §13.21): format 8 plus the
/// `partial` marker in `repo.json`. Only `vl clone` writes it, for a thin
/// clone; every other repository stays at [`REPO_FORMAT`], readable by the
/// vl releases that read format 8. A vl that does not know format 9 refuses
/// a thin clone instead of reading its unfetched objects as hidden.
pub const PARTIAL_FORMAT: u32 = 9;

/// Newest repository format this build opens.
pub const MAX_REPO_FORMAT: u32 = PARTIAL_FORMAT;

/// Default bound of a thin clone's object cache (`vl clone --cache-size`).
pub const DEFAULT_CACHE_LIMIT: u64 = 4 << 30;

/// Oldest repository format `vl upgrade` brings to [`REPO_FORMAT`].
pub const MIN_UPGRADE_FORMAT: u32 = 6;

/// The first vl release that reads repository format `format`.
pub fn min_vl_for_format(format: u32) -> &'static str {
    match format {
        0 | 1 => "0.1.0",
        2..=5 => "1.0.0",
        6..=9 => "1.1.0",
        _ => "a newer release",
    }
}

/// `Ok` if this build can read and write a repository of `format`.
pub fn check_format_supported(format: u32) -> Result<()> {
    check_format_upgradable(format)?;
    if format < MIN_REPO_FORMAT {
        return Err(VeilError::Unsupported(format!(
            "this repository uses format {format}, which may hold encrypted descriptions, tags, embargoes or folders; \
             this vl encrypts secret files only and reads format {REPO_FORMAT}. Run `vl upgrade`: it checks the \
             repository and moves it to format {REPO_FORMAT}"
        )));
    }
    Ok(())
}

/// `Ok` if `vl upgrade` (and `vl fsck`) can read a repository of `format`:
/// [`MIN_UPGRADE_FORMAT`] to [`MAX_REPO_FORMAT`].
pub fn check_format_upgradable(format: u32) -> Result<()> {
    if format > MAX_REPO_FORMAT {
        return Err(VeilError::Unsupported(format!(
            "this repository uses format {format}, which needs a newer vl (this is vl {}, which reads formats {REPO_FORMAT} and {MAX_REPO_FORMAT})",
            env!("CARGO_PKG_VERSION")
        )));
    }
    if format == 0 {
        return Err(VeilError::Corrupt("repo.json".into(), "invalid repository format 0".into()));
    }
    if format < MIN_UPGRADE_FORMAT {
        return Err(VeilError::Unsupported(format!(
            "this repository uses format {format}, which this vl no longer reads (formats 1 to {} were dropped). \
             Nothing was changed. Upgrade it to format 7 first with a vl from before format 8 (`vl upgrade` there), \
             then run `vl upgrade` here",
            MIN_UPGRADE_FORMAT - 1
        )));
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

/// The `partial` marker of a thin clone (format [`PARTIAL_FORMAT`],
/// device-local): objects not in the main store are fetched from the
/// server of remote `remote` when read, into the cache area, which is kept
/// under `cache_limit` bytes (`docs/HUB.md` §13.21).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PartialConfig {
    pub remote: String,
    pub cache_limit: u64,
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
    /// A thin clone (format [`PARTIAL_FORMAT`] only; absent otherwise, so
    /// other `repo.json` files keep their bytes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partial: Option<PartialConfig>,
}

impl RepoConfig {
    /// Error if this build cannot use the repository, naming the vl release
    /// it needs when the configuration says so.
    pub fn check_supported(&self) -> Result<()> {
        check_format_supported(self.format).map_err(|e| match (&e, &self.min_vl) {
            (VeilError::Unsupported(_), Some(v)) if self.format > MAX_REPO_FORMAT => VeilError::Unsupported(format!(
                "this repository uses format {} and needs vl {v} or later (this is vl {})",
                self.format,
                env!("CARGO_PKG_VERSION")
            )),
            _ => e,
        })?;
        self.check_partial()
    }

    /// The `partial` marker and format 9 go together: a marker in another
    /// format, or format 9 without one, is a damaged `repo.json` (threat 14
    /// of `docs/design/scale/6-partial-clone.md`).
    pub fn check_partial(&self) -> Result<()> {
        match (&self.partial, self.format == PARTIAL_FORMAT) {
            (Some(_), false) => Err(VeilError::Corrupt(
                "repo.json".into(),
                format!("a `partial` marker in a repository of format {} (only format {PARTIAL_FORMAT} has one)", self.format),
            )),
            (None, true) => Err(VeilError::Corrupt("repo.json".into(), format!("format {PARTIAL_FORMAT} without its `partial` marker"))),
            (Some(p), true) if p.remote.is_empty() => Err(VeilError::Corrupt("repo.json".into(), "a `partial` marker naming no remote".into())),
            _ => Ok(()),
        }
    }

    /// Is this a thin clone?
    pub fn is_partial(&self) -> bool {
        self.partial.is_some()
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
    graph: GraphIndex,
    /// The heads the view was read from (ancestors dropped, sorted): the
    /// parents of the next operation.
    pub(crate) base: Vec<ObjectId>,
    /// The newest timestamp of `base`: the next operation is never older
    /// than its parents, even with the clock set back (the op log's walks
    /// visit descendants first, BUG-1297).
    pub(crate) base_time: i64,
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

/// A rewrite: the old snapshot and its replacements (none: abandoned).
type Rewritten = (ObjectId, Vec<ObjectId>);

/// The operations a merge saw record one rewrite, and those of them that
/// are commands (not merges recording a rewrite they applied).
#[derive(Default)]
struct Recorded {
    ops: Vec<ObjectId>,
    commands: Vec<ObjectId>,
}

/// A ref of a view the merge's rebase re-points: a workspace, a tag, a head.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum RefKey {
    Ws(String),
    Tag(String),
    Head(ObjectId),
}

/// Each ref of `view` with its value (the snapshot it names).
fn ref_values(view: &View) -> Vec<(RefKey, ObjectId)> {
    let mut out: Vec<(RefKey, ObjectId)> = view.workspaces.iter().map(|(n, w)| (RefKey::Ws(n.clone()), w.wc)).collect();
    out.extend(view.tags.iter().map(|(n, t)| (RefKey::Tag(n.clone()), t.target)));
    out.extend(view.heads.iter().map(|h| (RefKey::Head(*h), *h)));
    out
}

/// What an operation takes back (see `Repo::retractor`).
pub(crate) enum Retractor {
    Undo(ObjectId),
    Redo(ObjectId),
    Restore(std::collections::HashSet<ObjectId>),
}

/// The operations the retractors take back, those taken back themselves
/// (an undo of a restore, a redo of an undo) taking back nothing.
pub(crate) fn retracted_commands(retractors: &BTreeMap<ObjectId, Retractor>) -> std::collections::HashSet<ObjectId> {
    let mut out: std::collections::HashSet<ObjectId> = Default::default();
    // A fixed point: each round recomputes from the retractors still in
    // force; an operation only takes back older ones, so it settles.
    for _ in 0..=retractors.len() {
        let mut next: std::collections::HashSet<ObjectId> = Default::default();
        for (id, r) in retractors {
            if out.contains(id) {
                continue;
            }
            match r {
                Retractor::Undo(u) => {
                    next.insert(*u);
                }
                Retractor::Redo(u) => {
                    next.insert(*u);
                }
                Retractor::Restore(ops) => next.extend(ops.iter().copied()),
            }
        }
        if next == out {
            break;
        }
        out = next;
    }
    out
}

/// See `Repo::merge_plan`.
pub(crate) struct MergePlan {
    pub(crate) view: View,
    pub(crate) rewritten: BTreeMap<ObjectId, Vec<ObjectId>>,
    /// Refs the rebase leaves where they are: set on an old snapshot by an
    /// operation that saw its rewrite (BUG-1434).
    pub(crate) pinned: std::collections::BTreeSet<RefKey>,
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
            partial: None,
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
                WorkspaceState::new(wc_id),
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
            restore_of: None,
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
            base_time: op.timestamp,
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
        if let Some(p) = &config.partial {
            store.set_partial(VPath::new(crate::promisor::CACHE_DIR)?, p.cache_limit);
        }
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
            base_time: 0,
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
        // A release a restore or undo took back, stopped before the
        // take-back itself, is taken back here (BUG-1487).
        if !repo.remote {
            repo.take_back_releases_out_of_force()?;
        }
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
        let (op_id, view, time) = match heads.as_slice() {
            [one] => {
                let op = self.ops.get_head(one)?;
                (*one, op.view, op.timestamp)
            }
            _ => {
                let plan = self.merge_plan(&heads, false)?;
                (self.ops.head()?, plan.view, plan.timestamp)
            }
        };
        self.raw = raw;
        self.base = heads;
        self.base_time = time;
        self.op_id = op_id;
        self.view = view;
        self.pin_working_copies();
        Ok(true)
    }

    /// A thin clone pins what its workspaces hold (never evicted from the
    /// cache): called whenever the view changes.
    pub(crate) fn pin_working_copies(&self) {
        if self.store.is_partial() {
            self.store.set_anchor_snapshots(self.view.workspaces.values().map(|w| w.wc).collect());
            let mut heads: Vec<ObjectId> = self.view.heads.iter().copied().collect();
            heads.extend(self.view.tags.values().map(|t| t.target));
            heads.extend(self.view.workspaces.values().map(|w| w.wc));
            let remote = self.config.partial.as_ref().map_or("", |p| p.remote.as_str());
            self.store.set_local_heads(heads, crate::promisor::own_tips(&self.view.remote_tags, remote).collect());
        }
    }

    /// Is this a thin clone (`docs/HUB.md` §13.21)?
    pub fn is_partial(&self) -> bool {
        self.config.partial.is_some()
    }

    /// Run graph query `f` exactly in a thin clone: when its walk reached
    /// snapshots this clone does not hold (its boundary), fetch the next
    /// page of history from the server and run it again, until the walk
    /// stays inside what is held or the server has no more. In any other
    /// repository, `f` once. A thin clone that cannot reach the server
    /// fails with [`VeilError::Unavailable`]; it never answers from the
    /// part of the graph it holds alone.
    fn run_exact<R>(&self, mut f: impl FnMut(&Repo) -> Result<R>) -> Result<R> {
        if !self.store.is_partial() || EXACT.with(|d| d.get() > 0) {
            return f(self);
        }
        EXACT.with(|d| d.set(d.get() + 1));
        struct Undo;
        impl Drop for Undo {
            fn drop(&mut self) {
                EXACT.with(|d| d.set(d.get() - 1));
            }
        }
        let _undo = Undo;
        loop {
            let _ = self.store.take_boundary_hits();
            // An error too (a revision not found) is answered again once
            // the history it may be in is here.
            let out = f(self);
            let hits = self.store.take_boundary_hits();
            if hits.is_empty() || self.deepen(&hits, crate::promisor::HISTORY_PAGE)? == 0 {
                return out;
            }
        }
    }

    /// A thin clone: the generation of snapshot `id` (held, at the boundary)
    /// as the server's viewer graph has it, the history index's exact value
    /// without the ancestry below (BUG-1291). `None`: not a thin clone, a
    /// server older than protocol revision 6, or a snapshot its history
    /// lacks (one of this clone's own). An error when it cannot be reached.
    pub(crate) fn boundary_generation(&self, id: &ObjectId) -> Result<Option<u64>> {
        if !self.store.is_partial() || !self.store.may_fetch() {
            return Ok(None);
        }
        let Some(promisor) = self.store.promisor() else {
            return Err(VeilError::Unavailable("this thin clone has no connection to its server".into()));
        };
        Ok(promisor.generations(&[*id])?.and_then(|g| g.first().copied().flatten()))
    }

    /// Fetch one page of history below `tips` (snapshots this thin clone
    /// lacks) into the main store; returns how many snapshots were new.
    /// Only tips a full clone made now would hold are asked for (below a
    /// held snapshot, or a name what the server's branches or this clone's
    /// own refs reach, BUG-1319); the others are not found, as there.
    pub fn deepen(&self, tips: &[ObjectId], limit: usize) -> Result<usize> {
        let Some(promisor) = self.store.promisor() else {
            return Err(VeilError::Unavailable(
                "this command needs history this thin clone does not hold, and has no connection to its server".into(),
            ));
        };
        let mut wanted = Vec::with_capacity(tips.len());
        for t in tips {
            if self.may_page(t)? {
                wanted.push(*t);
            }
        }
        if wanted.is_empty() {
            return Ok(0);
        }
        let page = promisor.history(&wanted, limit)?;
        let mut incoming = crate::remote::Incoming::new(&self.store);
        let mut new = 0;
        for (id, raw) in page {
            if ObjectId::hash(&raw) != id {
                return Err(VeilError::Corrupt(id.hex(), "the server sent history that does not match its ids".into()));
            }
            if !matches!(Object::decode(&raw)?, Object::Snapshot(_)) {
                return Err(VeilError::Corrupt(id.hex(), "the server sent a non-snapshot in history".into()));
            }
            if !self.store.has(&id) && incoming.put(id, raw, "")? {
                new += 1;
            }
        }
        incoming.finish()?;
        if new > 0 {
            self.store.forget_server_walk();
            self.graph.revalidate(self);
        }
        Ok(new)
    }

    /// A thin clone, about to page in snapshot `id`, which it does not
    /// hold: would a full clone made now hold it? Two questions, two rules
    /// (BUG-1319, BUG-1268):
    ///
    /// * **History below what the clone holds** (a parent of a held
    ///   snapshot): always. The person was sent the child; what is below
    ///   is theirs, also when a rewrite elsewhere left it off the branches.
    /// * **A name** (any other snapshot: a predecessor `vl evolog` follows,
    ///   an id typed): only if the server's branches reach it (`q/resolve`,
    ///   which answers from what they reach), or what this clone holds
    ///   reaches it (its view and its operation log, as a full clone's gc
    ///   keeps them: a walk down to the server's generation of `id`, which
    ///   pages in only that range). An old version a rewrite left behind
    ///   that nothing here reaches is not found, as in a full clone.
    ///
    /// A server older than protocol revision 6 cannot tell: the page is
    /// asked for, as before.
    fn may_page(&self, id: &ObjectId) -> Result<bool> {
        if !self.store.is_partial() || self.store.is_below_held(id) {
            return Ok(true);
        }
        let Some(promisor) = self.store.promisor() else { return Ok(true) };
        let Some((from, whole)) = self.server_roots(true)? else { return Ok(true) };
        match promisor.resolve(&id.hex(), &from)? {
            None => return Ok(true),
            Some(r) if r.snapshots.contains(id) => return Ok(true),
            // Every root counted: nothing here reaches it.
            Some(_) if whole => return Ok(false),
            Some(_) => {}
        }
        // More roots than one request names: a walk from all of them,
        // down to the server's generation of `id` (only that range is
        // paged in).
        let floor = match promisor.generations(&[*id])? {
            None => return Ok(true),
            Some(g) => match g.first().copied().flatten() {
                Some(g) => g,
                // Not in this person's history at all.
                None => return Ok(false),
            },
        };
        let mut roots: Vec<ObjectId> = self.view.refs();
        roots.extend(self.store.op_log_heads());
        roots.sort();
        roots.dedup();
        // A walk of its own (inside an `Exact` query, whose hits are put
        // back): pages in only what is below what it holds.
        let outer = self.store.take_boundary_hits();
        let reached = (|| loop {
            if self.graph.down_to(self, roots.iter().copied(), floor)?.contains_key(id) {
                return Ok(true);
            }
            let below: Vec<ObjectId> = self.store.take_boundary_hits().into_iter().filter(|h| self.store.is_below_held(h)).collect();
            if below.is_empty() || self.deepen(&below, crate::promisor::HISTORY_PAGE)? == 0 {
                return Ok(false);
            }
        })();
        let _ = self.store.take_boundary_hits();
        self.store.restore_boundary_hits(outer);
        reached
    }

    /// A thin clone's own refs as its server knows them, for `q/resolve`'s
    /// `from` (BUG-1319): the view's refs (with `op_log`, every
    /// operation's too, as a full clone's gc keeps them), each the server
    /// has no snapshot of (this clone's own work) replaced by its held
    /// parents. With whether they all fit in one request
    /// ([`crate::hub::wire::MAX_RESOLVE_FROM`]). `None`: a server older
    /// than protocol revision 6 (it cannot tell).
    pub(crate) fn server_roots(&self, op_log: bool) -> Result<Option<(Vec<ObjectId>, bool)>> {
        use crate::hub::wire::{MAX_GENERATIONS, MAX_RESOLVE_FROM};
        let Some(promisor) = self.store.promisor() else { return Ok(Some((Vec::new(), true))) };
        let mut todo: Vec<ObjectId> = self.view.refs();
        if op_log {
            todo.extend(self.store.op_log_heads());
        }
        let (mut out, mut seen, mut whole) = (Vec::new(), HashSet::new(), true);
        // Local work is a few commits deep: a few rounds.
        for _ in 0..16 {
            todo.retain(|x| seen.insert(*x));
            if todo.is_empty() {
                break;
            }
            let batch: Vec<ObjectId> = todo.drain(..todo.len().min(MAX_GENERATIONS)).collect();
            let Some(gens) = promisor.generations(&batch)? else { return Ok(None) };
            for (x, g) in batch.iter().zip(gens) {
                match g {
                    Some(_) => out.push(*x),
                    None => {
                        if let Some(s) = self.snapshot_held(x)? {
                            todo.extend(s.parents.iter().copied());
                        }
                    }
                }
            }
        }
        whole &= todo.is_empty() && out.len() <= MAX_RESOLVE_FROM;
        out.truncate(MAX_RESOLVE_FROM);
        Ok(Some((out, whole)))
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
        // The views of the heads merged so far.
        let mut head_views = vec![acc.clone()];
        let mut warnings = Vec::new();
        // Every rewrite seen (old snapshot, its replacements), with the
        // operations that recorded it, keyed by the rewrite (BUG-1299). A
        // command's rewrites are taken back only by what the op log says
        // takes the command back: an undo of it, an op restore past it
        // (BUG-1434: showing an old snapshot again is never an undo). A
        // rewrite only merges recorded is judged by the views (`undone`).
        let mut seen: BTreeMap<Rewritten, Recorded> = BTreeMap::new();
        let mut undone: std::collections::HashSet<Rewritten> = Default::default();
        let mut retractors: BTreeMap<ObjectId, Retractor> = BTreeMap::new();
        // Which command set each ref value (an operation of a side's own
        // history, not a merge): a ref on an old snapshot set by a command
        // that saw its rewrite is deliberate, and stays (a tag on the old
        // version, a workspace on it, an undo's revert).
        let mut introducers: HashMap<(RefKey, ObjectId), Vec<ObjectId>> = HashMap::new();
        let mut scanned: std::collections::HashSet<ObjectId> = Default::default();
        // Every step's conflict losers: a later step's removal of the head
        // (a side that dropped it, unaware of the losing write) never hides
        // one (BUG-1298).
        let mut losers: Vec<ObjectId> = Vec::new();
        for h in &heads[1..] {
            let op = self.ops.get(h)?;
            timestamp = timestamp.max(op.timestamp);
            let split = self.ops.split(&acc_heads, &[*h])?;
            let base = match split.base {
                Some(b) => self.ops.try_get(&b)?.map(|o| o.view).unwrap_or_default(),
                None => View::default(),
            };
            // What the two sides' shared history holds beyond `base`
            // (BUG-1294).
            let shared = crate::oplog::shared_base(&base, &acc, &split.introduced(&split.only_a), &op.view, &split.introduced(&split.only_b));
            if rewrites {
                for (ids, sides) in [(&split.only_a, &head_views[..]), (&split.only_b, std::slice::from_ref(&op.view))] {
                    // Each rewrite with the operations that recorded it (and
                    // those that are commands, not merges recording what
                    // they applied). A rewrite of a snapshot by an operation
                    // that descends from another's rewrite of it replaces
                    // that one; concurrent ones (merged on that side as a
                    // divergent change) all stay. One an earlier step
                    // collected is decided already.
                    let mut by_old: BTreeMap<ObjectId, Vec<(Vec<ObjectId>, ObjectId, bool)>> = BTreeMap::new();
                    for id in ids.iter() {
                        if let Some(o) = split.ops.get(id) {
                            for (old, new) in &o.rewritten {
                                by_old.entry(*old).or_default().push((new.clone(), *id, !o.is_merge()));
                            }
                        }
                    }
                    let mut side_map: BTreeMap<Rewritten, Recorded> = BTreeMap::new();
                    let mut below: Option<HashMap<ObjectId, std::collections::HashSet<ObjectId>>> = None;
                    for (old, entries) in by_old {
                        let differ = entries.iter().any(|(n, _, _)| *n != entries[0].0);
                        for (new, id, command) in &entries {
                            let replaced = differ && {
                                let below = below.get_or_insert_with(|| split.ancestors_within(ids));
                                entries.iter().any(|(n2, id2, _)| n2 != new && below.get(id2).is_some_and(|b| b.contains(id)))
                            };
                            if replaced {
                                continue;
                            }
                            let r = side_map.entry((old, new.clone())).or_default();
                            r.ops.push(*id);
                            if *command {
                                r.commands.push(*id);
                            }
                        }
                    }
                    side_map.retain(|k, r| !seen.get(k).is_some_and(|s| r.ops.iter().all(|o| s.ops.contains(o))));
                    // Undone on that side since: one of its heads shows
                    // `old` again, as a ref or as an ancestor of one (an
                    // undone abandon or amend of a parent of `@`, BUG-802).
                    // Every head of the side saw the rewrite (it first
                    // appears here); each is asked, not their merged view,
                    // where a conflict may have hidden what one shows.
                    let mut olds: Vec<ObjectId> = side_map.keys().map(|k| k.0).collect();
                    olds.dedup();
                    let mut shown = std::collections::HashSet::new();
                    if !olds.is_empty() {
                        for v in sides {
                            shown.extend(self.shown(v, &olds)?);
                        }
                    }
                    for (k, rec) in side_map {
                        let r = seen.entry(k.clone()).or_default();
                        r.ops.extend(rec.ops);
                        r.commands.extend(rec.commands);
                        if r.commands.is_empty() && shown.contains(&k.0) {
                            undone.insert(k);
                        }
                    }
                    for id in ids.iter() {
                        let Some(o) = split.ops.get(id) else { continue };
                        if !scanned.insert(*id) {
                            continue;
                        }
                        if let Some(r) = self.retractor(o)? {
                            retractors.insert(*id, r);
                        }
                        // A merge sets nothing deliberately (what it adds are
                        // rebases and a conflict's losers).
                        if o.is_merge() {
                            continue;
                        }
                        let parents: Vec<std::collections::HashSet<(RefKey, ObjectId)>> =
                            o.parents.iter().filter_map(|p| split.ops.get(p)).map(|p| ref_values(&p.view).into_iter().collect()).collect();
                        for kv in ref_values(&o.view) {
                            if !parents.iter().any(|p| p.contains(&kv)) {
                                introducers.entry(kv).or_default().push(*id);
                            }
                        }
                    }
                }
                // A rewrite only merges recorded (the op log does not say
                // which command it is, so not what took it back), undone by
                // a head merged after the step that collected it (BUG-1295):
                // this head saw it and shows `old`; or a side shows `old`
                // where the shared history does not (a rewrite from the
                // shared history, recorded again by a settler's merge on the
                // other side: the side showing `old` brought it back).
                let live: Vec<Rewritten> = seen.iter().filter(|(k, r)| r.commands.is_empty() && !undone.contains(*k)).map(|(k, _)| k.clone()).collect();
                if !live.is_empty() {
                    let mut olds: Vec<ObjectId> = live.iter().map(|k| k.0).collect();
                    olds.dedup();
                    let in_shared = self.shown(&shared, &olds)?;
                    let only_a: std::collections::HashSet<&ObjectId> = split.only_a.iter().collect();
                    for (side, head) in [(&acc, false), (&op.view, true)] {
                        let shown = self.shown(side, &olds)?;
                        for k in live.iter().filter(|k| shown.contains(&k.0)) {
                            let r = &seen[k];
                            let saw = head && r.ops.iter().any(|o| !only_a.contains(o));
                            if saw || !in_shared.contains(&k.0) {
                                undone.insert(k.clone());
                            }
                        }
                    }
                }
                before.push(base.clone());
                before.push(op.view.clone());
            }
            let mut descends = |a: &ObjectId, b: &ObjectId| self.is_ancestor(b, a).unwrap_or(false);
            let merged = crate::oplog::merge_views(&shared, &[&acc, &op.view], &mut descends);
            warnings.extend(merged.warnings);
            losers.extend(merged.losers);
            acc = merged.view;
            acc_heads.push(*h);
            if rewrites {
                head_views.push(op.view.clone());
            }
        }
        acc.heads.extend(losers);
        // The commands the op log says were taken back: by an undo or op
        // restore that is not itself taken back (an undo of the restore, a
        // redo of the undo).
        let retracted = retracted_commands(&retractors);
        // A command's rewrite by the op log alone (even if a merge recorded
        // it first, and the view rule judged it there); one only merges
        // recorded by the views.
        let stands = |k: &Rewritten, r: &Recorded| match r.commands.is_empty() {
            true => !undone.contains(k),
            false => r.commands.iter().any(|o| !retracted.contains(o)),
        };
        // The rewrites nobody undid. Two different ones of a snapshot: a
        // divergent change, both replacements stay visible and nothing
        // follows either.
        let mut rewritten: BTreeMap<ObjectId, Vec<ObjectId>> = BTreeMap::new();
        let mut divergent: std::collections::BTreeSet<ObjectId> = Default::default();
        let mut commands_of: BTreeMap<ObjectId, Vec<ObjectId>> = BTreeMap::new();
        let applied: Vec<(Rewritten, Recorded)> = seen.into_iter().filter(|(k, r)| stands(k, r)).collect();
        for ((old, new), r) in applied {
            commands_of.entry(old).or_default().extend(r.commands.iter().filter(|o| !retracted.contains(o)).copied());
            match rewritten.get(&old) {
                Some(prev) if *prev != new => {
                    divergent.insert(old);
                }
                _ => {
                    rewritten.insert(old, new);
                }
            }
        }
        for d in &divergent {
            rewritten.remove(d);
        }
        // Refs on an old snapshot that a command which saw each rewrite of
        // what they show set stay where they are (BUG-1434: a tag on the old
        // version, a workspace on it, an undo's revert); a ref some rewrite
        // it shows is new to follows the rewrites.
        let mut pinned: std::collections::BTreeSet<RefKey> = Default::default();
        if rewrites && !rewritten.is_empty() {
            for (key, v) in ref_values(&acc) {
                let mut shows = 0;
                let mut deliberate = true;
                for old in rewritten.keys() {
                    if !(v == *old || self.is_ancestor(old, &v)?) {
                        continue;
                    }
                    shows += 1;
                    let commands = commands_of.get(old).map(Vec::as_slice).unwrap_or_default();
                    if commands.is_empty() || !self.set_after(introducers.get(&(key.clone(), v)), commands)? {
                        deliberate = false;
                        break;
                    }
                }
                if shows > 0 && deliberate {
                    pinned.insert(key);
                }
            }
        }
        Ok(MergePlan {
            view: acc,
            rewritten,
            pinned,
            before,
            timestamp,
            warnings,
        })
    }

    /// Did one of `introducers` (the operations that set a ref value)
    /// descend from one of `commands`?
    fn set_after(&self, introducers: Option<&Vec<ObjectId>>, commands: &[ObjectId]) -> Result<bool> {
        for x in introducers.into_iter().flatten() {
            for c in commands {
                if x == c || self.ops.split(&[*x], &[*c])?.only_b.is_empty() {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// What operation `o` takes back, by the op log: an undo the operation
    /// it undid, a redo the undo it reverts, an op restore every operation
    /// between the restored one and its parents (a restore written before
    /// `restore_of` names the restored operation in its description).
    pub(crate) fn retractor(&self, o: &crate::oplog::Operation) -> Result<Option<Retractor>> {
        if let Some(u) = o.undo_of {
            return Ok(Some(Retractor::Undo(u)));
        }
        if let Some(u) = o.redo_of {
            return Ok(Some(Retractor::Redo(u)));
        }
        let target = match o.restore_of {
            Some(t) => Some(t),
            None => match o.description.strip_prefix("restore to operation ") {
                Some(prefix) if !o.parents.is_empty() && !o.is_merge() => self.ops.resolve_prefix_from(&o.parents, prefix).ok(),
                _ => None,
            },
        };
        match target {
            Some(t) => Ok(Some(Retractor::Restore(self.ops.split(&o.parents, &[t])?.only_a.into_iter().collect()))),
            None => Ok(None),
        }
    }

    /// The snapshots of `olds` that `view` shows: as a ref, or as an
    /// ancestor of one. One walk from the refs, down to the oldest of them.
    fn shown(&self, view: &View, olds: &[ObjectId]) -> Result<std::collections::HashSet<ObjectId>> {
        let mut floor = crate::graph_index::Gen::MAX;
        for old in olds {
            if let Some(g) = self.graph.generation(self, old)? {
                floor = floor.min(g);
            }
        }
        let refs: std::collections::HashSet<ObjectId> = view.refs().into_iter().collect();
        let visible: std::collections::HashSet<ObjectId> = match floor {
            crate::graph_index::Gen::MAX => Default::default(),
            f => self.graph.down_to(self, refs.iter().copied(), f)?.into_keys().collect(),
        };
        Ok(olds.iter().filter(|o| refs.contains(o) || visible.contains(o)).copied().collect())
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
        if let Some(p) = &config.partial {
            match self.store.is_partial() {
                false => self.store.set_partial(VPath::new(crate::promisor::CACHE_DIR)?, p.cache_limit),
                true => self.store.set_cache_limit(p.cache_limit),
            }
        }
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
        self.snapshot_opt(id)?.ok_or(VeilError::Missing(*id))
    }

    /// Like [`Repo::snapshot`], but `None` for a snapshot this replica does
    /// not hold. Graph walks use it: a public remote withholds the merged-in
    /// history of an unreleased embargoed merge, so such parents are absent.
    ///
    /// **A thin clone** fetches a page of history from the server when the
    /// snapshot is beyond what it holds (BUG-1141): every command that reads
    /// a snapshot reads it as a full clone would, and `None` is the
    /// server's own answer (this person's history has no such snapshot).
    /// Without the server: `Unavailable`. The one walk that must not fetch
    /// (the history index computes a generation from every ancestor) reads
    /// with [`Repo::snapshot_held`].
    fn snapshot_opt(&self, id: &ObjectId) -> Result<Option<Arc<Snapshot>>> {
        if let Some(s) = self.snapshot_held(id)? {
            return Ok(Some(s));
        }
        if !self.store.may_fetch() || self.store.history_refused(id, false) {
            return Ok(None);
        }
        let _ = self.store.take_boundary_hits_of_one(id);
        if self.deepen(&[*id], crate::promisor::HISTORY_PAGE)? == 0 && !self.store.has_main(id) {
            self.store.history_refused(id, true);
            return Ok(None);
        }
        self.snapshot_held(id)
    }

    /// [`Repo::snapshot_opt`] of what this replica holds, never fetching:
    /// `None` beyond a thin clone's boundary (recorded for [`Repo::exact`]).
    fn snapshot_held(&self, id: &ObjectId) -> Result<Option<Arc<Snapshot>>> {
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
    fn topo_children_first(&self, roots: impl IntoIterator<Item = ObjectId>) -> Result<Vec<ObjectId>> {
        let mut nodes: HashMap<ObjectId, Arc<Snapshot>> = HashMap::new();
        let mut stack: Vec<ObjectId> = roots.into_iter().collect();
        while let Some(id) = stack.pop() {
            if nodes.contains_key(&id) {
                continue;
            }
            // A redacted parent (withheld by an unreleased embargo) is simply
            // not part of this replica's graph.
            let Some(s) = self.snapshot_held(&id)? else { continue };
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

    fn visible_snapshots(&self) -> Result<Vec<ObjectId>> {
        self.topo_children_first(self.view.refs())
    }

    /// [`Repo::topo_children_first`] of `roots`, lazily: callers that need
    /// only the first few snapshots read only the history above them.
    fn topo_iter(&self, roots: impl IntoIterator<Item = ObjectId>) -> crate::graph_index::TopoIter<'_> {
        self.graph.topo_iter(self, roots)
    }

    /// The visible snapshots ([`Repo::visible_snapshots`]), lazily.
    fn visible_iter(&self) -> crate::graph_index::TopoIter<'_> {
        self.topo_iter(self.view.refs())
    }

    /// The visible snapshots whose `embargo` is set, newest first
    /// (generation, then timestamp, then id). Found through the history
    /// index, which walks only lines that build on one: with no embargo in
    /// the history, nothing is walked.
    fn visible_embargoed(&self) -> Result<Vec<ObjectId>> {
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
    fn visible_among(&self, candidates: &HashSet<ObjectId>) -> Result<HashSet<ObjectId>> {
        self.graph.reachable_among(self, self.view.refs(), candidates)
    }

    fn ancestors(&self, id: &ObjectId) -> Result<HashSet<ObjectId>> {
        let mut seen = HashSet::new();
        let mut stack = vec![*id];
        while let Some(x) = stack.pop() {
            if seen.insert(x) {
                if let Some(s) = self.snapshot_held(&x)? {
                    stack.extend(s.parents.iter().copied());
                }
            }
        }
        Ok(seen)
    }

    /// Is `a` an ancestor of (or equal to) `b`? Reads only the history
    /// between them (the history index stops the walk below `a`).
    pub fn is_ancestor(&self, a: &ObjectId, b: &ObjectId) -> Result<bool> {
        // A thin clone answers from the server's history where the walk
        // reaches what it does not hold.
        self.run_exact(|r| {
            // A snapshot this replica lacks (a redacted parent) has no
            // generation; it is an ancestor if some ancestor names it.
            if a != b && r.snapshot_opt(a)?.is_none() {
                // A thin clone asked its server: `a` is in no history of
                // this person's, so it is no ancestor (never a walk of all
                // of `b`'s ancestry, BUG-1291).
                if r.store.is_partial() {
                    return Ok(false);
                }
                return Ok(r.ancestors(b)?.contains(a));
            }
            r.graph.is_ancestor(r, a, b)
        })
    }

    pub fn common_ancestor(&self, a: &ObjectId, b: &ObjectId) -> Result<ObjectId> {
        // A thin clone: the newest merge base, a walk bounded by the history
        // index (the walk of every ancestor of `a` is not, BUG-1291).
        if self.store.is_partial() {
            return Ok(self.merge_bases(&[*a], &[*b])?.last().copied().unwrap_or(self.root_id));
        }
        self.run_exact(|r| r.common_ancestor_here(a, b))
    }

    fn common_ancestor_here(&self, a: &ObjectId, b: &ObjectId) -> Result<ObjectId> {
        let anc = self.ancestors(a)?;
        let mut queue = VecDeque::from([*b]);
        let mut seen = HashSet::new();
        while let Some(x) = queue.pop_front() {
            if anc.contains(&x) {
                return Ok(x);
            }
            if seen.insert(x) {
                if let Some(s) = self.snapshot_held(&x)? {
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
                if let Some(s) = self.snapshot_held(&x)? {
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
        self.run_exact(|r| {
            let mut best = Vec::new();
            for c in r.graph.merge_bases(r, a, b)? {
                if let Some(s) = r.snapshot_opt(&c)? {
                    best.push((s.timestamp, c));
                }
            }
            best.sort();
            Ok(best.into_iter().map(|(_, id)| id).collect())
        })
    }

    /// [`Repo::merge_bases`] by full ancestor sets, without the history
    /// index: the reference the index is tested against.
    fn merge_bases_naive(&self, a: &[ObjectId], b: &[ObjectId]) -> Result<Vec<ObjectId>> {
        let from_a = self.ancestors_of(a)?;
        let common: HashSet<ObjectId> = self.ancestors_of(b)?.into_iter().filter(|x| from_a.contains(x)).collect();
        // Everything below a common ancestor is a common ancestor too, and
        // not a best one.
        let mut below = HashSet::new();
        let mut stack = Vec::new();
        for c in &common {
            if let Some(s) = self.snapshot_held(c)? {
                stack.extend(s.parents.iter().copied());
            }
        }
        while let Some(x) = stack.pop() {
            if below.insert(x) {
                if let Some(s) = self.snapshot_held(&x)? {
                    stack.extend(s.parents.iter().copied());
                }
            }
        }
        let mut best = Vec::new();
        for c in common {
            if below.contains(&c) {
                continue;
            }
            if let Some(s) = self.snapshot_held(&c)? {
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


/// Reads of the history this repository **holds** (`Repo::held`): they
/// never fetch. In a thin clone a walk stops at the snapshots it does not
/// hold (its boundary), and records where, for [`Exact`]. For bookkeeping
/// whose answer is about what is here: the history index, gc and
/// maintenance, the pins of eviction, the pull's check of tag names (with
/// the server's lookup), this clone's own history (`docs/HUB.md` §13.21,
/// "Revised: names and fetching").
#[derive(Clone, Copy)]
pub struct Held<'r>(&'r Repo);

/// Reads whose answer is a **full clone's** ([`Repo::exact`]): in a thin
/// clone, a single read fetches a page of history at the boundary, and a
/// walk is the held walk run again after each page of history the boundary
/// it reached needs, so it pages in what its own range reaches and no more.
/// For anything shown to the person or deciding a result: revisions,
/// bisect, evolog, merges, rebases. In any other repository the same as
/// [`Held`].
#[derive(Clone, Copy)]
pub struct Exact<'r>(&'r Repo);

impl Repo {
    /// Reads of the history held here ([`Held`]).
    pub fn held(&self) -> Held<'_> {
        Held(self)
    }

    /// Reads that answer as a full clone does ([`Exact`]).
    pub fn exact(&self) -> Exact<'_> {
        Exact(self)
    }
}

impl<'r> Held<'r> {
    /// Snapshot `id` if held (`None` beyond a thin clone's boundary, or
    /// withheld).
    pub fn snapshot(&self, id: &ObjectId) -> Result<Option<Arc<Snapshot>>> {
        self.0.snapshot_held(id)
    }

    /// Every held ancestor of `id` (itself included).
    pub fn ancestors(&self, id: &ObjectId) -> Result<HashSet<ObjectId>> {
        self.0.ancestors(id)
    }

    /// The held snapshots reachable from `roots`, children first.
    pub fn topo_children_first(&self, roots: impl IntoIterator<Item = ObjectId>) -> Result<Vec<ObjectId>> {
        self.0.topo_children_first(roots)
    }

    /// The held snapshots reachable from the view, children first.
    pub fn visible(&self) -> Result<Vec<ObjectId>> {
        self.0.visible_snapshots()
    }

    /// [`Held::topo_children_first`], lazily (the history index).
    pub fn topo_iter(&self, roots: impl IntoIterator<Item = ObjectId>) -> crate::graph_index::TopoIter<'r> {
        self.0.topo_iter(roots)
    }

    /// [`Held::visible`], lazily.
    pub fn visible_iter(&self) -> crate::graph_index::TopoIter<'r> {
        self.0.visible_iter()
    }

    /// Merge bases by full ancestor sets, without the history index: the
    /// reference the index is tested against.
    #[doc(hidden)]
    pub fn merge_bases_naive(&self, a: &[ObjectId], b: &[ObjectId]) -> Result<Vec<ObjectId>> {
        self.0.merge_bases_naive(a, b)
    }

    /// The history index itself: held data (its own tests read it).
    pub fn index(&self) -> &'r crate::graph_index::GraphIndex {
        &self.0.graph
    }

    /// Which of `candidates` the view reaches, in held history.
    pub fn visible_among(&self, candidates: &HashSet<ObjectId>) -> Result<HashSet<ObjectId>> {
        self.0.visible_among(candidates)
    }

    /// The held embargoed merges the view reaches (the history index walks
    /// only lines that build on one).
    pub fn visible_embargoed(&self) -> Result<Vec<ObjectId>> {
        self.0.visible_embargoed()
    }

    /// The held snapshots reachable from `include` and not from `exclude`.
    pub fn range(&self, include: &[ObjectId], exclude: &[ObjectId]) -> Result<HashSet<ObjectId>> {
        self.0.graph.range(self.0, include, exclude)
    }

    /// Which of `wanted` held history reaches from `roots`.
    pub fn reachable_among(&self, roots: impl IntoIterator<Item = ObjectId>, wanted: &HashSet<ObjectId>) -> Result<HashSet<ObjectId>> {
        self.0.graph.reachable_among(self.0, roots, wanted)
    }

    /// Held snapshots reachable from `roots` whose index entry `keep`s,
    /// after indexing them (candidates for a change-id prefix or a flag;
    /// the caller confirms what it uses against the store).
    pub fn entries_matching(
        &self,
        roots: impl IntoIterator<Item = ObjectId>,
        keep: impl FnMut(&ObjectId, &crate::graph_index::Entry) -> bool,
    ) -> Result<Vec<ObjectId>> {
        self.0.graph.entries_matching(self.0, roots, keep)
    }

    /// The held embargoed merges reachable from `roots`.
    pub fn embargoed_among(&self, roots: impl IntoIterator<Item = ObjectId>) -> Result<HashSet<ObjectId>> {
        self.0.graph.embargoed_among(self.0, roots)
    }

    /// The generation of `id` in the history index (`None` if not held).
    pub fn generation(&self, id: &ObjectId) -> Result<Option<crate::graph_index::Gen>> {
        self.0.graph.generation(self.0, id)
    }
}

impl Exact<'_> {
    /// Snapshot `id` as a full clone holds it: in a thin clone, a page of
    /// history is fetched where it is beyond the boundary. `None`: this
    /// person's history has no such snapshot. Without the server:
    /// `Unavailable`.
    pub fn snapshot(&self, id: &ObjectId) -> Result<Option<Arc<Snapshot>>> {
        self.0.snapshot_opt(id)
    }

    /// Run `f`, a query over held history, until the boundary it reaches no
    /// longer changes its answer (each round fetches the next page of
    /// history there). A thin clone that cannot reach the server fails
    /// with `Unavailable`, never answers from what it holds alone.
    pub fn run<R>(&self, f: impl FnMut(&Repo) -> Result<R>) -> Result<R> {
        self.0.run_exact(f)
    }

    /// Every ancestor of `id` (itself included).
    pub fn ancestors(&self, id: &ObjectId) -> Result<HashSet<ObjectId>> {
        self.run(|r| r.ancestors(id))
    }

    /// The snapshots reachable from `roots`, children first.
    pub fn topo_children_first(&self, roots: impl IntoIterator<Item = ObjectId>) -> Result<Vec<ObjectId>> {
        let roots: Vec<ObjectId> = roots.into_iter().collect();
        self.run(|r| r.topo_children_first(roots.iter().copied()))
    }

    /// The snapshots reachable from the view, children first.
    pub fn visible(&self) -> Result<Vec<ObjectId>> {
        self.run(|r| r.visible_snapshots())
    }

    /// The snapshots reachable from `include` and not from `exclude`: the
    /// history index's walk, which stops once everything left is below
    /// `exclude`, so only that range is paged in.
    pub fn range(&self, include: &[ObjectId], exclude: &[ObjectId]) -> Result<HashSet<ObjectId>> {
        self.run(|r| r.graph.range(r, include, exclude))
    }

    /// Which of `candidates` the view reaches (the history above the
    /// oldest of them only).
    pub fn visible_among(&self, candidates: &HashSet<ObjectId>) -> Result<HashSet<ObjectId>> {
        self.run(|r| r.visible_among(candidates))
    }

    /// The embargoed merges the view reaches.
    pub fn visible_embargoed(&self) -> Result<Vec<ObjectId>> {
        self.run(|r| r.visible_embargoed())
    }

    /// The embargoed merges reachable from `roots`.
    pub fn embargoed_among(&self, roots: impl IntoIterator<Item = ObjectId>) -> Result<HashSet<ObjectId>> {
        let roots: Vec<ObjectId> = roots.into_iter().collect();
        self.run(|r| r.graph.embargoed_among(r, roots.iter().copied()))
    }

    /// The generation of `id` (fetched as `Exact::snapshot` fetches it).
    pub fn generation(&self, id: &ObjectId) -> Result<Option<crate::graph_index::Gen>> {
        if self.snapshot(id)?.is_none() {
            return Ok(None);
        }
        self.run(|r| r.graph.generation(r, id))
    }

    /// Every snapshot reachable from `roots` of generation `floor` or more,
    /// with its generation and snapshot (the walk stops below `floor`, so a
    /// thin clone pages in only that part).
    pub fn down_to(
        &self,
        roots: impl IntoIterator<Item = ObjectId>,
        floor: crate::graph_index::Gen,
    ) -> Result<HashMap<ObjectId, (crate::graph_index::Gen, Arc<Snapshot>)>> {
        let roots: Vec<ObjectId> = roots.into_iter().collect();
        self.run(|r| r.graph.down_to(r, roots.iter().copied(), floor))
    }
}

impl Repo {
    /// Persist the history index's new entries (best effort).
    pub(crate) fn persist_index(&self) {
        self.graph.persist(self);
    }
}
