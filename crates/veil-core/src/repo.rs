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
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
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
/// | 10 | vl 1.2.0 | agent attribution and attempts on snapshots (`Snapshot::{agent, abandoned, attempts}`); 1.2.0, because builds that already call themselves 1.1.0 read only up to format 9 (BUG-1379) |
///
/// This build writes format 10 and opens formats 8 to 10: a format-8 or 9
/// repository is read and written as it is, and refuses to store a
/// format-10 snapshot ("run `vl upgrade`"). `vl upgrade` brings formats 6
/// to 9 to it, after checking that 6 and 7 hold nothing the removed
/// encryption of non-secret content wrote; formats 1 to 5 are no longer
/// supported. See `docs/FORMAT.md` and `docs/CRYPTO.md`.
pub const REPO_FORMAT: u32 = 10;

/// The format from which only secret files are encrypted: older ones must
/// be checked and upgraded before this build opens them.
pub const ONLY_SECRETS_REPO_FORMAT: u32 = 8;

/// Oldest repository format this build opens.
pub const MIN_REPO_FORMAT: u32 = ONLY_SECRETS_REPO_FORMAT;

/// The first format that may hold the `partial` marker of a thin clone
/// (`docs/HUB.md` §13.21): format 9 is format 8 plus the marker (S3's
/// release wrote thin clones at it, and a format-9 repository always has
/// one); format 10 has everything 9 has, so this release writes a thin
/// clone at [`REPO_FORMAT`] with the marker. A vl that does not know format
/// 9 refuses a thin clone by its number instead of reading its unfetched
/// objects as hidden.
pub const PARTIAL_FORMAT: u32 = 9;

/// Newest repository format this build opens.
pub const MAX_REPO_FORMAT: u32 = REPO_FORMAT;

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
        10 => "1.2.0",
        _ => "a newer release",
    }
}

/// `Ok` if this build can read and write a repository of `format`.
pub fn check_format_supported(format: u32) -> Result<()> {
    check_format_upgradable(format)?;
    if format < MIN_REPO_FORMAT {
        return Err(VeilError::Unsupported(format!(
            "this repository uses format {format}, which may hold encrypted descriptions, tags, embargoes or folders; \
             this vl encrypts secret files only and reads formats {MIN_REPO_FORMAT} to {REPO_FORMAT}. Run `vl upgrade`: \
             it checks the repository and moves it to format {REPO_FORMAT}"
        )));
    }
    Ok(())
}

/// `Ok` if `vl upgrade` (and `vl fsck`) can read a repository of `format`:
/// [`MIN_UPGRADE_FORMAT`] to [`MAX_REPO_FORMAT`].
pub fn check_format_upgradable(format: u32) -> Result<()> {
    if format > MAX_REPO_FORMAT {
        return Err(VeilError::Unsupported(format!(
            "this repository uses format {format}, which needs a newer vl (this is vl {}, which reads formats {MIN_REPO_FORMAT} to {MAX_REPO_FORMAT})",
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
    /// Fields this build does not know, kept as they are ([`RepoConfig::unknown`]).
    #[serde(flatten)]
    pub unknown: BTreeMap<String, serde_json::Value>,
}

/// The `partial` marker of a thin clone (format [`PARTIAL_FORMAT`] or later,
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
    /// A thin clone (format [`PARTIAL_FORMAT`] or later; absent otherwise,
    /// so other `repo.json` files keep their bytes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partial: Option<PartialConfig>,
    /// Fields of `repo.json` this build does not know (a later release's),
    /// kept as they are by every rewrite of the file. A repository that has
    /// any is never opened or upgraded by this build
    /// ([`RepoConfig::check_known`]): it would be half-understood (BUG-1390).
    #[serde(flatten)]
    pub unknown: BTreeMap<String, serde_json::Value>,
}

impl RepoConfig {
    /// Error unless this build knows every field of `repo.json`, its
    /// remotes' included: a field it does not know may change what the
    /// repository means (format 9's `partial`: objects not fetched yet),
    /// so it neither opens nor upgrades such a repository, and changes
    /// nothing.
    pub fn check_known(&self) -> Result<()> {
        let mut names: Vec<String> = self.unknown.keys().map(|k| format!("{k:?}")).collect();
        for (r, c) in &self.remotes {
            names.extend(c.unknown.keys().map(|k| format!("{k:?} of remote {r:?}")));
        }
        if names.is_empty() {
            return Ok(());
        }
        names.truncate(8);
        Err(VeilError::Unsupported(format!(
            "this repository's .veil/repo.json holds {} which this vl (format {REPO_FORMAT}) does not know; it needs a \
             newer vl. Nothing was changed",
            names.join(", ")
        )))
    }

    /// Error if this build cannot use the repository, naming the vl release
    /// it needs when the configuration says so.
    pub fn check_supported(&self) -> Result<()> {
        self.check_known()?;
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
        match (&self.partial, self.format) {
            (Some(_), f) if f < PARTIAL_FORMAT => Err(VeilError::Corrupt(
                "repo.json".into(),
                format!("a `partial` marker in a repository of format {f} (it needs format {PARTIAL_FORMAT} or later)"),
            )),
            (None, PARTIAL_FORMAT) => Err(VeilError::Corrupt("repo.json".into(), format!("format {PARTIAL_FORMAT} without its `partial` marker"))),
            (Some(p), _) if p.remote.is_empty() => Err(VeilError::Corrupt("repo.json".into(), "a `partial` marker naming no remote".into())),
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
    /// [`Repo::set_attribution`].
    pub(crate) attribution: Option<crate::object::Attribution>,
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
    retracted_commands_with(retractors, None)
}

/// [`retracted_commands`], plus an uncommitted operation's own `extra`
/// retractor (nothing older can take it back).
pub(crate) fn retracted_commands_with(
    retractors: &BTreeMap<ObjectId, Retractor>,
    extra: Option<&Retractor>,
) -> std::collections::HashSet<ObjectId> {
    let add = |next: &mut std::collections::HashSet<ObjectId>, r: &Retractor| match r {
        Retractor::Undo(u) | Retractor::Redo(u) => {
            next.insert(*u);
        }
        Retractor::Restore(ops) => next.extend(ops.iter().copied()),
    };
    let mut out: std::collections::HashSet<ObjectId> = Default::default();
    // A fixed point: each round recomputes from the retractors still in
    // force; an operation only takes back older ones, so it settles.
    for _ in 0..=retractors.len() + usize::from(extra.is_some()) {
        let mut next: std::collections::HashSet<ObjectId> = Default::default();
        if let Some(r) = extra {
            add(&mut next, r);
        }
        for (id, r) in retractors {
            if !out.contains(id) {
                add(&mut next, r);
            }
        }
        if next == out {
            break;
        }
        out = next;
    }
    out
}

/// Does `o` take earlier operations back (`undo_of`, `redo_of`, `restore_of`,
/// or a pre-`restore_of` restore description)?
fn is_retractor_op(o: &crate::oplog::Operation) -> bool {
    o.undo_of.is_some()
        || o.redo_of.is_some()
        || o.restore_of.is_some()
        || (!o.is_merge() && !o.parents.is_empty() && o.description.starts_with("restore to operation "))
}

/// The operations directly named by `r`.
fn retractor_targets(r: &Retractor) -> Vec<ObjectId> {
    match r {
        Retractor::Undo(u) | Retractor::Redo(u) => vec![*u],
        Retractor::Restore(ops) => ops.iter().copied().collect(),
    }
}

/// Does `start` equal or descend from any operation in `targets` within `ops`?
fn op_reaches_any(start: ObjectId, targets: &[ObjectId], ops: &HashMap<ObjectId, crate::oplog::Operation>) -> bool {
    if targets.is_empty() {
        return false;
    }
    let mut stack = vec![start];
    let mut visited: std::collections::HashSet<ObjectId> = Default::default();
    while let Some(cur) = stack.pop() {
        if targets.contains(&cur) {
            return true;
        }
        if !visited.insert(cur) {
            continue;
        }
        if let Some(op) = ops.get(&cur) {
            stack.extend(op.parents.iter().copied());
        }
    }
    false
}

/// Record the ref values non-merge operation `id` (`o`) introduced over its
/// parents in `ops` (and under `Head(v)` as well, should a conflict turn a
/// workspace or tag write into a losing head).
fn add_introducers(
    id: ObjectId,
    o: &crate::oplog::Operation,
    ops: &HashMap<ObjectId, crate::oplog::Operation>,
    introducers: &mut HashMap<(RefKey, ObjectId), Vec<ObjectId>>,
) {
    let parents: Vec<std::collections::HashSet<(RefKey, ObjectId)>> =
        o.parents.iter().filter_map(|p| ops.get(p)).map(|p| ref_values(&p.view).into_iter().collect()).collect();
    for kv in ref_values(&o.view) {
        if !parents.iter().any(|p| p.contains(&kv)) {
            let head_kv = (RefKey::Head(kv.1), kv.1);
            let is_head = matches!(kv.0, RefKey::Head(_));
            introducers.entry(kv).or_default().push(id);
            if !is_head {
                introducers.entry(head_kv).or_default().push(id);
            }
        }
    }
}

/// For each rewrite of `keys`, what it made and what the rewrites of
/// `seen` made of that in turn (at most 64 snapshots).
fn made_of(seen: &BTreeMap<Rewritten, Recorded>, keys: &[Rewritten]) -> Vec<Vec<ObjectId>> {
    let mut next: HashMap<ObjectId, Vec<ObjectId>> = HashMap::new();
    for (o, ns) in seen.keys() {
        next.entry(*o).or_default().extend(ns.iter().copied());
    }
    keys.iter()
        .map(|k| {
            let mut chain = k.1.clone();
            let mut i = 0;
            while i < chain.len() && chain.len() < 64 {
                for n in next.get(&chain[i]).into_iter().flatten() {
                    if !chain.contains(n) {
                        chain.push(*n);
                    }
                }
                i += 1;
            }
            chain
        })
        .collect()
}

/// See `Repo::merge_plan`.
pub(crate) struct MergePlan {
    pub(crate) view: View,
    pub(crate) rewritten: BTreeMap<ObjectId, Vec<ObjectId>>,
    /// Keys of `rewritten` that came from shared-history commands an undo,
    /// redo or op restore put back in force: applied to what the view shows,
    /// not recorded again as this operation's own (BUG-2640).
    pub(crate) transient: std::collections::BTreeSet<ObjectId>,
    /// Snapshots with two versions that stand and differ (a divergent
    /// change): the rebase leaves them where they are (BUG-1488).
    pub(crate) divergent: std::collections::BTreeSet<ObjectId>,
    /// Refs the rebase leaves where they are: set on an old snapshot by an
    /// operation that saw its rewrite (BUG-1434).
    pub(crate) pinned: std::collections::BTreeSet<RefKey>,
    pub(crate) before: Vec<View>,
    pub(crate) timestamp: i64,
    pub(crate) warnings: Vec<String>,
}

/// Rewrites an undo, redo or op restore puts back in force by taking an
/// earlier undo or restore back (BUG-2640).
#[derive(Default)]
pub(crate) struct ReinstatedPlan {
    pub(crate) rewritten: BTreeMap<ObjectId, Vec<ObjectId>>,
    pub(crate) divergent: std::collections::BTreeSet<ObjectId>,
    pub(crate) pinned: std::collections::BTreeSet<RefKey>,
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
            unknown: BTreeMap::new(),
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
            attribution: None,
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
            attribution: None,
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
        if !self.store.may_fetch() || EXACT.with(|d| d.get() > 0) {
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
        if !self.store.may_fetch() {
            return Ok(0);
        }
        if self.store.promisor().is_none() {
            return Err(VeilError::Unavailable(
                "this command needs history this thin clone does not hold, and has no connection to its server".into(),
            ));
        }
        let mut wanted = Vec::with_capacity(tips.len());
        for t in tips {
            if self.may_page(t)? {
                wanted.push(*t);
            }
        }
        self.page_in(&wanted, limit)
    }

    /// [`Repo::deepen`] for tips that need no question: the server's own
    /// branch tips, which a full clone made now would hold. One request for
    /// all of them, however many branches name them (BUG-1625).
    pub fn page_in(&self, wanted: &[ObjectId], limit: usize) -> Result<usize> {
        if wanted.is_empty() || !self.store.may_fetch() {
            return Ok(0);
        }
        let Some(promisor) = self.store.promisor() else {
            return Err(VeilError::Unavailable(
                "this command needs history this thin clone does not hold, and has no connection to its server".into(),
            ));
        };
        let page = promisor.history(wanted, limit)?;
        // One snapshot asked for: the page starts with it as the person's
        // current view has it; another id is a view change (BUG-1509).
        if let ([asked], Some((first, _))) = (wanted, page.first()) {
            self.store.note_projection(*asked, *first);
        }
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
        let mut acc = first.view.clone();
        let mut before = vec![acc.clone()];
        // The views of the heads merged so far.
        let mut head_views = vec![acc.clone()];
        let mut all_ops: HashMap<ObjectId, crate::oplog::Operation> = HashMap::from([(heads[0], first)]);
        let mut non_common: std::collections::HashSet<ObjectId> = Default::default();
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
        // The rewrites that are merges' rebases (BUG-2464, BUG-2466): see
        // below, where a step collects them.
        let mut rebases: std::collections::HashSet<Rewritten> = Default::default();
        for h in &heads[1..] {
            let op = self.ops.get(h)?;
            timestamp = timestamp.max(op.timestamp);
            let split = self.ops.split(&acc_heads, &[*h])?;
            non_common.extend(split.only_a.iter().copied());
            non_common.extend(split.only_b.iter().copied());
            for (id, o) in &split.ops {
                all_ops.entry(*id).or_insert_with(|| o.clone());
            }
            all_ops.entry(*h).or_insert_with(|| op.clone());
            let base = match split.base {
                Some(b) => self.ops.try_get(&b)?.map(|o| o.view).unwrap_or_default(),
                None => View::default(),
            };
            // What the two sides' shared history holds beyond `base`
            // (BUG-1294).
            let (ia, ib) = (split.introduced(&split.only_a), split.introduced(&split.only_b));
            let shared = crate::oplog::shared_base_with(&base, &acc, &ia, &op.view, &ib, false);
            if rewrites {
                let known: std::collections::HashSet<Rewritten> = seen.keys().cloned().collect();
                for (ids, sides, side_heads) in [
                    (&split.only_a, &head_views[..], &acc_heads[..]),
                    (&split.only_b, std::slice::from_ref(&op.view), std::slice::from_ref(h)),
                ] {
                    // Each rewrite with the operations that recorded it (and
                    // those that are commands, not merges recording what
                    // they applied). Two rewrites of one snapshot that
                    // differ both stay, a divergent change, whether their
                    // operations were concurrent or one saw the other (a
                    // second version of an old version, BUG-1488): one
                    // that was taken back is dropped by what the op log
                    // says took it back, below. One an earlier step
                    // collected is decided already.
                    let mut side_map: BTreeMap<Rewritten, Recorded> = BTreeMap::new();
                    for id in ids.iter() {
                        if let Some(o) = split.ops.get(id) {
                            for (old, new) in &o.rewritten {
                                let r = side_map.entry((*old, new.clone())).or_default();
                                r.ops.push(*id);
                                if !o.is_merge() {
                                    r.commands.push(*id);
                                }
                            }
                        }
                    }
                    side_map.retain(|k, r| !seen.get(k).is_some_and(|s| r.ops.iter().all(|o| s.ops.contains(o))));
                    // Undone on that side since: one of its heads that saw
                    // the rewrite shows `old` again, as a ref or as an
                    // ancestor of one (an undone abandon or amend of a
                    // parent of `@`, BUG-802). Each head that reached it is
                    // asked, not their merged view, where a conflict may
                    // have hidden what one shows.
                    let mut olds: Vec<ObjectId> = side_map.keys().map(|k| k.0).collect();
                    olds.dedup();
                    let mut shown_per: Vec<std::collections::HashSet<ObjectId>> = Vec::new();
                    if !olds.is_empty() {
                        for v in sides {
                            shown_per.push(self.shown(v, &olds)?);
                        }
                    }
                    for (k, rec) in side_map {
                        let was_undone = !shown_per.is_empty()
                            && match side_heads.len() {
                                1 => shown_per[0].contains(&k.0),
                                _ => side_heads
                                    .iter()
                                    .enumerate()
                                    .any(|(i, sh)| shown_per[i].contains(&k.0) && op_reaches_any(*sh, &rec.ops, &all_ops)),
                            };
                        let r = seen.entry(k.clone()).or_default();
                        r.ops.extend(rec.ops);
                        r.commands.extend(rec.commands);
                        if r.commands.is_empty() && was_undone {
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
                        add_introducers(*id, o, &split.ops, &mut introducers);
                    }
                }
                // A merge's rebase: a rewrite this step collected that only
                // merges recorded and that the shared history does not show
                // (what it made, or what the rewrites seen made of that):
                // made since the sides split, by a merge's rebase of a
                // descendant of what the commands it merged rewrote. Not a
                // version of a change, but derived from those commands. A
                // command's rewrite from the shared history, recorded again
                // by merges, is shown by the shared history.
                let fresh: Vec<Rewritten> = seen.iter().filter(|(k, r)| !known.contains(*k) && r.commands.is_empty() && !k.1.is_empty()).map(|(k, _)| k.clone()).collect();
                if !fresh.is_empty() {
                    let made = made_of(&seen, &fresh);
                    let all: Vec<ObjectId> = made.iter().flatten().copied().collect();
                    let in_shared = self.shown(&shared, &all)?;
                    for (k, chain) in fresh.into_iter().zip(&made) {
                        if !chain.iter().any(|n| in_shared.contains(n)) {
                            rebases.insert(k);
                        }
                    }
                }
                // A rewrite only merges recorded (the op log does not say
                // which command it is, so not what took it back), undone by
                // a head merged after the step that collected it (BUG-1295):
                // a head saw it and shows `old`; or a head shows `old` where
                // its shared history with the step's head does not (a
                // rewrite from their shared history, recorded again by a
                // settler's merge: the head showing `old` brought it back).
                // Each folded head is asked against its own shared history
                // with `h`, never `acc` (not rebased yet, so `acc` can hold
                // `old` from one head while `shared` holds `new` from
                // another: BUG-2641). And only for a rewrite from that
                // shared history (BUG-1503).
                let live: Vec<Rewritten> = seen.iter().filter(|(k, r)| r.commands.is_empty() && !undone.contains(*k)).map(|(k, _)| k.clone()).collect();
                if !live.is_empty() {
                    let mut olds: Vec<ObjectId> = live.iter().map(|k| k.0).collect();
                    olds.dedup();
                    let mut shown_a = Vec::with_capacity(head_views.len());
                    for v in &head_views {
                        shown_a.push(self.shown(v, &olds)?);
                    }
                    let shown_b = self.shown(&op.view, &olds)?;
                    for k in &live {
                        let r = &seen[k];
                        let saw_b = shown_b.contains(&k.0) && op_reaches_any(*h, &r.ops, &all_ops);
                        let saw_a = acc_heads
                            .iter()
                            .enumerate()
                            .any(|(i, ah)| shown_a[i].contains(&k.0) && op_reaches_any(*ah, &r.ops, &all_ops));
                        if saw_b || saw_a {
                            undone.insert(k.clone());
                        }
                    }
                    let made = made_of(&seen, &live);
                    let all: Vec<ObjectId> = made.iter().flatten().copied().collect();
                    for (i, ah) in acc_heads.iter().enumerate() {
                        let any_shown = live
                            .iter()
                            .any(|k| !undone.contains(k) && (shown_a[i].contains(&k.0) || shown_b.contains(&k.0)));
                        if !any_shown {
                            continue;
                        }
                        let pair_shared = if acc_heads.len() == 1 {
                            shared.clone()
                        } else {
                            let ps = self.ops.split(&[*ah], &[*h])?;
                            let pb = match ps.base {
                                Some(b) => match all_ops.get(&b) {
                                    Some(o) => o.view.clone(),
                                    None => self.ops.try_get(&b)?.map(|o| o.view).unwrap_or_default(),
                                },
                                None => View::default(),
                            };
                            let (pia, pib) = (ps.introduced(&ps.only_a), ps.introduced(&ps.only_b));
                            crate::oplog::shared_base_with(&pb, &head_views[i], &pia, &op.view, &pib, false)
                        };
                        let in_sh = self.shown(&pair_shared, &olds)?;
                        let made_in_sh = self.shown(&pair_shared, &all)?;
                        for (k, chain) in live.iter().zip(&made) {
                            if undone.contains(k) || !(shown_a[i].contains(&k.0) || shown_b.contains(&k.0)) {
                                continue;
                            }
                            let from_sh = k.1.is_empty() || chain.iter().any(|n| made_in_sh.contains(n));
                            if !in_sh.contains(&k.0) && from_sh {
                                undone.insert(k.clone());
                            }
                        }
                    }
                }
                before.push(base.clone());
                before.push(op.view.clone());
            }
            let mut descends = |a: &ObjectId, b: &ObjectId| self.is_ancestor(b, a).unwrap_or(false);
            // The base of the merge of the values: a merge's rebase is no
            // change of its side's (BUG-2464).
            let merge_base = crate::oplog::shared_base(&base, &acc, &ia, &op.view, &ib);
            let merged = crate::oplog::merge_views(&merge_base, &[&acc, &op.view], &mut descends);
            warnings.extend(merged.warnings);
            losers.extend(merged.losers);
            acc = merged.view;
            acc_heads.push(*h);
            head_views.push(op.view);
        }
        acc.heads.extend(losers);
        let shared_merge_olds = match rewrites {
            true => self.extend_with_reinstated(
                heads,
                &non_common,
                None,
                &head_views,
                &mut all_ops,
                &mut seen,
                &mut rebases,
                &mut retractors,
                &mut introducers,
            )?,
            false => Default::default(),
        };
        if non_common.iter().any(|id| all_ops.get(id).is_some_and(|o| o.is_merge())) {
            self.recover_hidden_losers(
                heads,
                &head_views,
                &non_common,
                &all_ops,
                rewrites,
                &mut retractors,
                &mut introducers,
                &mut acc,
            )?;
        }
        let retracted = retracted_commands(&retractors);
        let (rewritten, versioned, pinned, transient) = self.resolve_standing_rewrites(
            seen,
            &undone,
            &rebases,
            &retracted,
            &introducers,
            &non_common,
            &shared_merge_olds,
            &mut all_ops,
            &acc,
            rewrites,
        )?;
        Ok(MergePlan {
            view: acc,
            rewritten,
            transient,
            divergent: versioned,
            pinned,
            before,
            timestamp,
            warnings,
        })
    }

    /// BUG-2642: a conflict's losing workspace or tag write settled in an
    /// earlier merge of `non_common` can have had its head dropped there
    /// because another head `W` covered it (`drop_ancestor_heads`), and a
    /// concurrent undo or restore merged now can remove `W` while neither
    /// head of this merge still holds the losing value on the ref. Keep any
    /// un-retracted, causally unsuperseded write in `non_common` whose own
    /// heads in `heads` still show it.
    #[allow(clippy::too_many_arguments)]
    fn recover_hidden_losers(
        &self,
        heads: &[ObjectId],
        head_views: &[View],
        non_common: &std::collections::HashSet<ObjectId>,
        all_ops: &HashMap<ObjectId, crate::oplog::Operation>,
        rewrites: bool,
        retractors: &mut BTreeMap<ObjectId, Retractor>,
        introducers: &mut HashMap<(RefKey, ObjectId), Vec<ObjectId>>,
        acc: &mut View,
    ) -> Result<()> {
        let mut non_merges: Vec<ObjectId> = non_common
            .iter()
            .copied()
            .filter(|id| all_ops.get(id).is_some_and(|o| !o.is_merge()))
            .collect();
        non_merges.sort();
        let mut ws_changers: HashMap<&str, Vec<ObjectId>> = HashMap::new();
        let mut tag_changers: HashMap<&str, Vec<ObjectId>> = HashMap::new();
        for &id in &non_merges {
            let o = &all_ops[&id];
            let mut ws_names: std::collections::BTreeSet<&str> = o.view.workspaces.keys().map(String::as_str).collect();
            let mut tag_names: std::collections::BTreeSet<&str> = o.view.tags.keys().map(String::as_str).collect();
            for p in o.parents.iter().filter_map(|p| all_ops.get(p)) {
                ws_names.extend(p.view.workspaces.keys().map(String::as_str));
                tag_names.extend(p.view.tags.keys().map(String::as_str));
            }
            for name in ws_names {
                let v = o.view.workspaces.get(name).map(|w| w.wc);
                if o.parents.iter().filter_map(|p| all_ops.get(p)).all(|p| p.view.workspaces.get(name).map(|w| w.wc) != v) {
                    ws_changers.entry(name).or_default().push(id);
                }
            }
            for name in tag_names {
                let v = o.view.tags.get(name).map(|t| (t.target, t.annotation));
                if o.parents
                    .iter()
                    .filter_map(|p| all_ops.get(p))
                    .all(|p| p.view.tags.get(name).map(|t| (t.target, t.annotation)) != v)
                {
                    tag_changers.entry(name).or_default().push(id);
                }
            }
        }
        let ancestors_of = |changers: &[ObjectId]| -> std::collections::HashSet<ObjectId> {
            let mut anc: std::collections::HashSet<ObjectId> = Default::default();
            let mut stack: Vec<ObjectId> = changers
                .iter()
                .filter_map(|id| all_ops.get(id))
                .flat_map(|o| o.parents.iter().copied())
                .collect();
            while let Some(cur) = stack.pop() {
                if !anc.insert(cur) {
                    continue;
                }
                if let Some(o) = all_ops.get(&cur) {
                    stack.extend(o.parents.iter().copied());
                }
            }
            anc
        };
        let mut candidates: Vec<(ObjectId, RefKey, ObjectId)> = Vec::new();
        for (name, changers) in &ws_changers {
            let raw: Vec<(ObjectId, ObjectId)> = changers
                .iter()
                .filter_map(|&c_id| {
                    let wc = all_ops[&c_id].view.workspaces.get(*name)?.wc;
                    if acc.workspaces.get(*name).map(|aw| aw.wc) == Some(wc) || acc.heads.contains(&wc) {
                        return None;
                    }
                    Some((c_id, wc))
                })
                .collect();
            if raw.is_empty() {
                continue;
            }
            let anc = if changers.len() > 1 { ancestors_of(changers) } else { Default::default() };
            for (c_id, wc) in raw {
                if !anc.contains(&c_id) {
                    candidates.push((c_id, RefKey::Ws((*name).to_string()), wc));
                }
            }
        }
        for (name, changers) in &tag_changers {
            let raw: Vec<(ObjectId, ObjectId)> = changers
                .iter()
                .filter_map(|&c_id| {
                    let target = all_ops[&c_id].view.tags.get(*name)?.target;
                    if acc.tags.get(*name).map(|at| at.target) == Some(target) || acc.heads.contains(&target) {
                        return None;
                    }
                    Some((c_id, target))
                })
                .collect();
            if raw.is_empty() {
                continue;
            }
            let anc = if changers.len() > 1 { ancestors_of(changers) } else { Default::default() };
            for (c_id, target) in raw {
                if !anc.contains(&c_id) {
                    candidates.push((c_id, RefKey::Tag((*name).to_string()), target));
                }
            }
        }
        candidates.sort();
        if candidates.is_empty() {
            return Ok(());
        }
        if !rewrites {
            for &id in non_common {
                if let std::collections::btree_map::Entry::Vacant(e) = retractors.entry(id) {
                    if let Some(o) = all_ops.get(&id) {
                        if let Some(r) = self.retractor(o)? {
                            e.insert(r);
                        }
                    }
                }
            }
        }
        let retracted = retracted_commands(retractors);
        let mut fwd: HashMap<ObjectId, Vec<ObjectId>> = HashMap::new();
        for o in all_ops.values() {
            for (old, ns) in &o.rewritten {
                fwd.entry(*old).or_default().extend(ns.iter().copied());
            }
        }
        for (c_id, key, v) in candidates {
            if retracted.contains(&c_id) || acc.heads.contains(&v) {
                continue;
            }
            let mut chain = vec![v];
            let mut idx = 0;
            while idx < chain.len() && chain.len() < 64 {
                for n in fwd.get(&chain[idx]).into_iter().flatten() {
                    if !chain.contains(n) {
                        chain.push(*n);
                    }
                }
                idx += 1;
            }
            let winner = match &key {
                RefKey::Ws(n) => acc.workspaces.get(n).map(|w| w.wc),
                RefKey::Tag(n) => acc.tags.get(n).map(|t| t.target),
                RefKey::Head(_) => None,
            };
            if winner.is_some_and(|w| chain.contains(&w)) {
                continue;
            }
            let own: Vec<usize> = (0..heads.len()).filter(|&i| op_reaches_any(heads[i], &[c_id], all_ops)).collect();
            if own.is_empty() {
                continue;
            }
            let mut all_show_v = true;
            for &i in &own {
                if !self.shown(&head_views[i], &[v])?.contains(&v) {
                    all_show_v = false;
                    break;
                }
            }
            if all_show_v {
                acc.heads.insert(v);
                introducers.entry((RefKey::Head(v), v)).or_default().push(c_id);
                continue;
            }
            if chain.len() > 1 {
                let mut shown_per = Vec::with_capacity(own.len());
                let mut all_have = true;
                for &i in &own {
                    let s = self.shown(&head_views[i], &chain)?;
                    if s.is_empty() {
                        all_have = false;
                        break;
                    }
                    shown_per.push(s);
                }
                if all_have {
                    if let Some(&common) = chain.iter().find(|x| shown_per.iter().all(|s| s.contains(x))) {
                        acc.heads.insert(common);
                        introducers.entry((RefKey::Head(common), common)).or_default().push(c_id);
                    } else {
                        for s in &shown_per {
                            if let Some(&first) = chain.iter().find(|x| s.contains(x)) {
                                acc.heads.insert(first);
                                introducers.entry((RefKey::Head(first), first)).or_default().push(c_id);
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// BUG-2640: when an operation (`extra` for a command, or `retractors`
    /// in a merge) takes back an earlier undo, redo or op restore, commands
    /// older than that retractor (in the shared history outside
    /// `non_common`) can come back into force. Collect the bounded op-log
    /// region down to their parents, extending `retractors`, `introducers`
    /// and `seen` with the reinstated rewrites and what the shared history
    /// made of their replacements. Returns `old`s added only from shared
    /// merges' rebases (also transient).
    #[allow(clippy::too_many_arguments)]
    fn extend_with_reinstated(
        &self,
        heads: &[ObjectId],
        non_common: &std::collections::HashSet<ObjectId>,
        extra: Option<&Retractor>,
        views_to_check: &[View],
        all_ops: &mut HashMap<ObjectId, crate::oplog::Operation>,
        seen: &mut BTreeMap<Rewritten, Recorded>,
        rebases: &mut std::collections::HashSet<Rewritten>,
        retractors: &mut BTreeMap<ObjectId, Retractor>,
        introducers: &mut HashMap<(RefKey, ObjectId), Vec<ObjectId>>,
    ) -> Result<std::collections::HashSet<ObjectId>> {
        let mut shared_merge_olds: std::collections::HashSet<ObjectId> = Default::default();
        let get_op = |id: &ObjectId, cache: &HashMap<ObjectId, crate::oplog::Operation>| -> Result<Option<crate::oplog::Operation>> {
            match cache.get(id) {
                Some(o) => Ok(Some(o.clone())),
                None => self.ops.try_get(id),
            }
        };
        let mut todo_ret: Vec<ObjectId> = Vec::new();
        let mut check_targets = Vec::new();
        if let Some(r) = extra {
            check_targets.extend(retractor_targets(r));
        }
        for r in retractors.values() {
            check_targets.extend(retractor_targets(r));
        }
        for t in check_targets {
            if let Some(o) = get_op(&t, all_ops)? {
                if is_retractor_op(&o) {
                    todo_ret.push(t);
                }
                all_ops.entry(t).or_insert(o);
            }
        }
        if todo_ret.is_empty() {
            return Ok(shared_merge_olds);
        }
        let mut visited_ret: std::collections::HashSet<ObjectId> = Default::default();
        let mut candidates: std::collections::BTreeSet<ObjectId> = Default::default();
        while let Some(r_id) = todo_ret.pop() {
            if !visited_ret.insert(r_id) {
                continue;
            }
            let Some(r_op) = get_op(&r_id, all_ops)? else { continue };
            let Some(ret) = self.retractor(&r_op)? else { continue };
            all_ops.entry(r_id).or_insert(r_op);
            for x in retractor_targets(&ret) {
                let Some(x_op) = get_op(&x, all_ops)? else { continue };
                if is_retractor_op(&x_op) {
                    todo_ret.push(x);
                }
                if !x_op.is_merge() && !x_op.rewritten.is_empty() {
                    candidates.insert(x);
                }
                all_ops.entry(x).or_insert(x_op);
            }
        }
        if candidates.is_empty() {
            return Ok(shared_merge_olds);
        }
        // BUG-1488: if a candidate rewrote `old` after an earlier command
        // had already made another version of `old` (kept visible by a
        // pinned ref in the candidate's parent view), include that earlier
        // command in the region so both versions are seen together.
        let mut anchors: std::collections::BTreeSet<ObjectId> = candidates.clone();
        for &c_id in &candidates {
            let c_op = all_ops[&c_id].clone();
            for old in c_op.rewritten.keys() {
                if *old == self.root_id {
                    continue;
                }
                let Some(old_snap) = self.held().snapshot(old)? else { continue };
                for p_id in &c_op.parents {
                    let Some(p_op) = get_op(p_id, all_ops)? else { continue };
                    let sibs = self
                        .held()
                        .entries_matching(p_op.view.refs(), |id, e| *id != *old && e.change_id == old_snap.change_id)?;
                    all_ops.entry(*p_id).or_insert(p_op);
                    if sibs.is_empty() {
                        continue;
                    }
                    for (steps, item) in self.ops.walk(std::slice::from_ref(p_id)).enumerate() {
                        if steps > 10_000 {
                            break;
                        }
                        let (w_id, w_op) = item?;
                        if !w_op.is_merge() && w_op.rewritten.contains_key(old) {
                            anchors.insert(w_id);
                        }
                        let still_has = self.shown(&w_op.view, &[*old])?.contains(old);
                        all_ops.entry(w_id).or_insert(w_op);
                        if !still_has {
                            break;
                        }
                    }
                }
            }
        }
        let mut parent_sets: Vec<Vec<ObjectId>> = Vec::new();
        for a_id in &anchors {
            if let Some(a_op) = all_ops.get(a_id) {
                let mut ps = a_op.parents.clone();
                ps.sort();
                if !parent_sets.contains(&ps) {
                    parent_sets.push(ps);
                }
            }
        }
        let mut region_ids: std::collections::BTreeSet<ObjectId> = Default::default();
        for ps in &parent_sets {
            let s = self.ops.split(heads, ps)?;
            region_ids.extend(s.only_a.iter().copied());
            for (id, o) in s.ops {
                all_ops.entry(id).or_insert(o);
            }
        }
        for &id in &region_ids {
            if non_common.contains(&id) {
                continue;
            }
            let Some(o) = all_ops.get(&id).cloned() else { continue };
            if let std::collections::btree_map::Entry::Vacant(e) = retractors.entry(id) {
                if let Some(r) = self.retractor(&o)? {
                    e.insert(r);
                }
            }
            if !o.is_merge() {
                add_introducers(id, &o, all_ops, introducers);
            }
        }
        let retracted = retracted_commands_with(retractors, extra);
        let mut cmd_by_old: HashMap<ObjectId, Vec<(Vec<ObjectId>, ObjectId)>> = HashMap::new();
        let mut merge_by_old: HashMap<ObjectId, Vec<(Vec<ObjectId>, ObjectId)>> = HashMap::new();
        for &id in &region_ids {
            if retracted.contains(&id) {
                continue;
            }
            let Some(o) = all_ops.get(&id) else { continue };
            if !o.is_merge() {
                for (old, new) in &o.rewritten {
                    cmd_by_old.entry(*old).or_default().push((new.clone(), id));
                }
            } else if !non_common.contains(&id) {
                for (old, new) in &o.rewritten {
                    merge_by_old.entry(*old).or_default().push((new.clone(), id));
                }
            }
        }
        let mut seed_olds: std::collections::HashSet<ObjectId> = Default::default();
        let mut todo_olds: Vec<ObjectId> = Vec::new();
        for &c_id in &candidates {
            if retracted.contains(&c_id) {
                continue;
            }
            if let Some(c_op) = all_ops.get(&c_id) {
                for &old in c_op.rewritten.keys() {
                    if seed_olds.insert(old) {
                        todo_olds.push(old);
                    }
                }
            }
        }
        let mut active_olds: std::collections::HashSet<ObjectId> = Default::default();
        while let Some(old) = todo_olds.pop() {
            if !active_olds.insert(old) || active_olds.len() > 256 {
                continue;
            }
            if let Some(entries) = cmd_by_old.get(&old) {
                let mut distinct: Vec<&Vec<ObjectId>> = Vec::new();
                for (new, cmd_id) in entries {
                    if !distinct.contains(&new) {
                        distinct.push(new);
                    }
                    if !non_common.contains(cmd_id) {
                        let r = seen.entry((old, new.clone())).or_default();
                        if !r.ops.contains(cmd_id) {
                            r.ops.push(*cmd_id);
                        }
                        if !r.commands.contains(cmd_id) {
                            r.commands.push(*cmd_id);
                        }
                    }
                }
                if let [one] = distinct.as_slice() {
                    if let [rep] = one.as_slice() {
                        todo_olds.push(*rep);
                    }
                }
            } else if !seed_olds.contains(&old) {
                if let Some(entries) = merge_by_old.get(&old) {
                    let mut old_shown = false;
                    for v in views_to_check {
                        if self.shown(v, &[old])?.contains(&old) {
                            old_shown = true;
                            break;
                        }
                    }
                    if !old_shown {
                        for (new, m_id) in entries {
                            let key = (old, new.clone());
                            let r = seen.entry(key.clone()).or_default();
                            if !r.ops.contains(m_id) {
                                r.ops.push(*m_id);
                            }
                            rebases.insert(key);
                            shared_merge_olds.insert(old);
                            if let [rep] = new.as_slice() {
                                todo_olds.push(*rep);
                            }
                        }
                    }
                }
            }
        }
        Ok(shared_merge_olds)
    }

    /// Decide which rewrites of `seen` stand, resolve merges' rebases vs.
    /// commands' versions, and compute `versioned`, `pinned` and `transient`
    /// (shared by [`Repo::merge_plan`] and [`Repo::reinstated_for_command`]).
    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    fn resolve_standing_rewrites(
        &self,
        seen: BTreeMap<Rewritten, Recorded>,
        undone: &std::collections::HashSet<Rewritten>,
        rebases: &std::collections::HashSet<Rewritten>,
        retracted: &std::collections::HashSet<ObjectId>,
        introducers: &HashMap<(RefKey, ObjectId), Vec<ObjectId>>,
        non_common: &std::collections::HashSet<ObjectId>,
        shared_merge_olds: &std::collections::HashSet<ObjectId>,
        all_ops: &mut HashMap<ObjectId, crate::oplog::Operation>,
        view: &View,
        rewrites: bool,
    ) -> Result<(
        BTreeMap<ObjectId, Vec<ObjectId>>,
        std::collections::BTreeSet<ObjectId>,
        std::collections::BTreeSet<RefKey>,
        std::collections::BTreeSet<ObjectId>,
    )> {
        // A command's rewrite by the op log alone (even if a merge recorded
        // it first, and the view rule judged it there); one only merges
        // recorded by the views, unless op restores still in force took
        // every merge that recorded it back (BUG-2641).
        let stands = |k: &Rewritten, r: &Recorded| match r.commands.is_empty() {
            true => !undone.contains(k) && r.ops.iter().any(|o| !retracted.contains(o)),
            false => r.commands.iter().any(|o| !retracted.contains(o)),
        };
        let mut rewritten: BTreeMap<ObjectId, Vec<ObjectId>> = BTreeMap::new();
        let mut divergent: std::collections::BTreeSet<ObjectId> = Default::default();
        let mut commands_of: BTreeMap<ObjectId, Vec<ObjectId>> = BTreeMap::new();
        let applied: Vec<(Rewritten, Recorded)> = seen.into_iter().filter(|(k, r)| stands(k, r)).collect();
        for ((old, new), r) in &applied {
            commands_of
                .entry(*old)
                .or_default()
                .extend(r.commands.iter().filter(|o| !retracted.contains(o)).copied());
            match rewritten.get(old) {
                Some(prev) if prev != new => {
                    divergent.insert(*old);
                }
                _ => {
                    rewritten.insert(*old, new.clone());
                }
            }
        }
        for d in &divergent {
            rewritten.remove(d);
        }
        let mut versioned: std::collections::BTreeSet<ObjectId> = Default::default();
        let mut order: Vec<(crate::graph_index::Gen, ObjectId)> = Vec::new();
        for d in &divergent {
            order.push((self.graph.generation(self, d)?.unwrap_or(crate::graph_index::Gen::MAX), *d));
        }
        order.sort();
        let mut nc_cache: HashMap<ObjectId, Option<Vec<ObjectId>>> = HashMap::new();
        for (_, d) in order {
            let from = applied.partition_point(|(k, _)| k.0 < d);
            let to = from + applied[from..].partition_point(|(k, _)| k.0 == d);
            let mut rebased: Vec<&(Rewritten, Recorded)> = Vec::new();
            let mut versions_rec: Vec<&(Rewritten, Recorded)> = Vec::new();
            for item in &applied[from..to] {
                let (k, r) = item;
                let is_reb = r.commands.is_empty()
                    && (rebases.contains(k)
                        || match k.1.as_slice() {
                            [new] => self.is_merge_rebase(&k.0, new, &r.ops, retracted, all_ops, &mut nc_cache)?,
                            _ => false,
                        });
                if is_reb {
                    rebased.push(item);
                } else {
                    versions_rec.push(item);
                }
            }
            let mut versions: Vec<&Vec<ObjectId>> = versions_rec.iter().map(|(k, _)| &k.1).collect();
            versions.sort();
            versions.dedup();
            let mut made: Vec<&Vec<ObjectId>> = applied[from..to]
                .iter()
                .filter(|(_, r)| r.commands.iter().any(|o| !retracted.contains(o)))
                .map(|(k, _)| &k.1)
                .collect();
            made.sort();
            made.dedup();
            if made.len() > 1 {
                versioned.insert(d);
            }
            let new = match versions[..] {
                [one] => one.clone(),
                [] => match self.one_rebase(&rebased, &rewritten)? {
                    Some(new) => {
                        for ((_, n), _) in &rebased {
                            if let [copy] = n[..] {
                                if copy != new && !divergent.contains(&copy) {
                                    rewritten.entry(copy).or_insert(vec![new]);
                                }
                            }
                        }
                        vec![new]
                    }
                    None => continue,
                },
                _ => continue,
            };
            divergent.remove(&d);
            rewritten.insert(d, new);
        }
        let mut transient: std::collections::BTreeSet<ObjectId> = Default::default();
        for old in rewritten.keys() {
            let standing_cmds = commands_of.get(old).map(Vec::as_slice).unwrap_or_default();
            if (!standing_cmds.is_empty() && standing_cmds.iter().all(|c| !non_common.contains(c))) || shared_merge_olds.contains(old) {
                transient.insert(*old);
            }
        }
        let mut pinned: std::collections::BTreeSet<RefKey> = Default::default();
        if rewrites && !rewritten.is_empty() {
            for (key, v) in ref_values(view) {
                let mut shows = 0;
                let mut deliberate = true;
                for old in rewritten.keys() {
                    if !(v == *old || self.is_ancestor(old, &v)?) {
                        continue;
                    }
                    shows += 1;
                    let commands = commands_of.get(old).map(Vec::as_slice).unwrap_or_default();
                    let active_intro: Vec<ObjectId> = introducers
                        .get(&(key.clone(), v))
                        .into_iter()
                        .flatten()
                        .copied()
                        .filter(|id| !retracted.contains(id))
                        .collect();
                    if commands.is_empty() || !self.set_after(Some(&active_intro), commands)? {
                        deliberate = false;
                        break;
                    }
                }
                if shows > 0 && deliberate {
                    pinned.insert(key);
                }
            }
        }
        Ok((rewritten, versioned, pinned, transient))
    }

    /// True if `old -> [new]`, recorded only by merges `ops`, originated as a
    /// merge's own rebase rather than a shared-history command copied onto a
    /// merge (BUG-2641). When two settlers independently make the same merge
    /// rebase and one of them is in `shared`, the `in_shared` heuristic misses
    /// it; walking back each merge's own non-common region distinguishes a
    /// command's rewrite from a merge's rebase exactly.
    fn is_merge_rebase(
        &self,
        old: &ObjectId,
        new: &ObjectId,
        ops: &[ObjectId],
        retracted: &std::collections::HashSet<ObjectId>,
        all_ops: &mut HashMap<ObjectId, crate::oplog::Operation>,
        nc_cache: &mut HashMap<ObjectId, Option<Vec<ObjectId>>>,
    ) -> Result<bool> {
        let (Some(os), Some(ns)) = (self.exact().snapshot(old)?, self.exact().snapshot(new)?) else {
            return Ok(false);
        };
        if os.parents == ns.parents || os.change_id != ns.change_id || os.description != ns.description {
            return Ok(false);
        }
        let mut todo: Vec<ObjectId> = ops.iter().copied().filter(|id| !retracted.contains(id)).collect();
        let mut visited: std::collections::HashSet<ObjectId> = Default::default();
        let mut checked_any = false;
        while let Some(m_id) = todo.pop() {
            if !visited.insert(m_id) {
                continue;
            }
            if let std::collections::hash_map::Entry::Vacant(e) = all_ops.entry(m_id) {
                let Some(o) = self.ops.try_get(&m_id)? else {
                    return Ok(false);
                };
                e.insert(o);
            }
            let (is_merge, parents) = {
                let m = &all_ops[&m_id];
                (m.is_merge(), m.parents.clone())
            };
            if !is_merge {
                return Ok(false);
            }
            if let std::collections::hash_map::Entry::Vacant(e) = nc_cache.entry(m_id) {
                let computed = self.non_common_of_parents(&parents, all_ops)?;
                e.insert(computed);
            }
            let Some(nc) = nc_cache[&m_id].as_deref() else {
                return Ok(false);
            };
            for x_id in nc {
                let Some(x) = all_ops.get(x_id) else { continue };
                if x.rewritten.get(old).map(Vec::as_slice) == Some(&[*new]) {
                    if !x.is_merge() {
                        return Ok(false);
                    }
                    todo.push(*x_id);
                }
            }
            checked_any = true;
        }
        Ok(checked_any)
    }

    /// Operations reached by some of `parents` and not by all of them
    /// (a merge's own non-common region). Returns `None` if a pruned
    /// operation prevents an exact answer.
    fn non_common_of_parents(
        &self,
        parents: &[ObjectId],
        all_ops: &mut HashMap<ObjectId, crate::oplog::Operation>,
    ) -> Result<Option<Vec<ObjectId>>> {
        let n = parents.len();
        if n < 2 {
            return Ok(Some(Vec::new()));
        }
        if n > 128 {
            let mut nc: std::collections::HashSet<ObjectId> = Default::default();
            for i in 1..n {
                let s = self.ops.split(&parents[..i], &[parents[i]])?;
                nc.extend(s.only_a.iter().copied());
                nc.extend(s.only_b.iter().copied());
                for (id, o) in s.ops {
                    all_ops.entry(id).or_insert(o);
                }
            }
            return Ok(Some(nc.into_iter().collect()));
        }
        let all_mask: u128 = if n == 128 { u128::MAX } else { (1u128 << n) - 1 };
        let mut marks: HashMap<ObjectId, u128> = HashMap::new();
        let mut done: HashMap<ObjectId, u128> = HashMap::new();
        let mut queue: std::collections::BinaryHeap<(i64, ObjectId)> = std::collections::BinaryHeap::new();
        for (i, p) in parents.iter().enumerate() {
            if let std::collections::hash_map::Entry::Vacant(e) = all_ops.entry(*p) {
                let Some(o) = self.ops.try_get(p)? else {
                    return Ok(None);
                };
                e.insert(o);
            }
            let ts = all_ops[p].timestamp;
            *marks.entry(*p).or_default() |= 1u128 << i;
            queue.push((ts, *p));
        }
        let mut low: Option<i64> = None;
        let mut inverted = false;
        while let Some((ts, id)) = queue.pop() {
            let m = marks[&id];
            if done.get(&id) == Some(&m) {
                continue;
            }
            done.insert(id, m);
            if m != all_mask {
                low = Some(low.map_or(ts, |l| l.min(ts)));
            }
            let ps = all_ops[&id].parents.clone();
            let mut known: Vec<(ObjectId, i64)> = Vec::with_capacity(ps.len());
            for p in ps {
                if let std::collections::hash_map::Entry::Vacant(e) = all_ops.entry(p) {
                    let Some(o) = self.ops.try_get(&p)? else {
                        return Ok(None);
                    };
                    e.insert(o);
                }
                let pts = all_ops[&p].timestamp;
                inverted |= pts > ts;
                known.push((p, pts));
            }
            let below = |t: i64| low.is_none_or(|l| t < l);
            if !inverted && m == all_mask && below(ts) && queue.iter().all(|(t, q)| marks[q] == all_mask && below(*t)) {
                break;
            }
            for (p, pts) in known {
                let pm = marks.entry(p).or_default();
                if *pm | m != *pm {
                    *pm |= m;
                    queue.push((pts, p));
                }
            }
        }
        Ok(Some(marks.into_iter().filter(|(_, m)| *m != all_mask).map(|(id, _)| id).collect()))
    }

    /// Rewrites an undo, redo or op restore (`self_ret` on `base`, resulting
    /// in `view`) puts back in force by taking an earlier undo or restore
    /// back (BUG-2640).
    pub(crate) fn reinstated_for_command(
        &self,
        base: &[ObjectId],
        self_ret: &Retractor,
        view: &View,
    ) -> Result<ReinstatedPlan> {
        let non_common: std::collections::HashSet<ObjectId> = Default::default();
        let mut all_ops: HashMap<ObjectId, crate::oplog::Operation> = HashMap::new();
        let mut seen: BTreeMap<Rewritten, Recorded> = BTreeMap::new();
        let mut rebases: std::collections::HashSet<Rewritten> = Default::default();
        let mut retractors: BTreeMap<ObjectId, Retractor> = BTreeMap::new();
        let mut introducers: HashMap<(RefKey, ObjectId), Vec<ObjectId>> = HashMap::new();
        let shared_merge_olds = self.extend_with_reinstated(
            base,
            &non_common,
            Some(self_ret),
            std::slice::from_ref(view),
            &mut all_ops,
            &mut seen,
            &mut rebases,
            &mut retractors,
            &mut introducers,
        )?;
        if seen.is_empty() {
            return Ok(ReinstatedPlan::default());
        }
        let undone: std::collections::HashSet<Rewritten> = Default::default();
        let retracted = retracted_commands_with(&retractors, Some(self_ret));
        let (rewritten, divergent, pinned, _) = self.resolve_standing_rewrites(
            seen,
            &undone,
            &rebases,
            &retracted,
            &introducers,
            &non_common,
            &shared_merge_olds,
            &mut all_ops,
            view,
            true,
        )?;
        Ok(ReinstatedPlan {
            rewritten,
            divergent,
            pinned,
        })
    }

    /// Of merges' rebases of one snapshot, the one rebase they all are:
    /// each one's parents are, through `rewritten`, where one of them is
    /// (equal inputs make equal rebases; one made from older parents is
    /// superseded by one made from what they became). That one, already on
    /// those parents; `None` when they differ (merges of concurrent
    /// rewrites of the parents), or none is there yet.
    fn one_rebase(&self, rebases: &[&(Rewritten, Recorded)], rewritten: &BTreeMap<ObjectId, Vec<ObjectId>>) -> Result<Option<ObjectId>> {
        let resolve = |mut x: ObjectId| {
            for _ in 0..64 {
                match rewritten.get(&x).map(Vec::as_slice) {
                    Some([n]) if *n != x => x = *n,
                    _ => break,
                }
            }
            x
        };
        let mut now: Option<Vec<ObjectId>> = None;
        let mut there = None;
        for ((_, n), _) in rebases {
            let [copy] = n[..] else { return Ok(None) };
            let Some(snap) = self.exact().snapshot(&copy)? else { return Ok(None) };
            let at: Vec<ObjectId> = snap.parents.iter().map(|p| resolve(*p)).collect();
            match &now {
                Some(a) if *a != at => return Ok(None),
                _ => now = Some(at.clone()),
            }
            if there.is_none() && at == snap.parents {
                there = Some(copy);
            }
        }
        Ok(there)
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

    /// The agent attribution every snapshot this process creates carries
    /// (`Snapshot::agent`): set once by the CLI from `vl`'s own arguments and
    /// environment, never from anything in the repository or a sandbox.
    /// Rebases and duplicates keep each change's own.
    pub fn set_attribution(&mut self, a: Option<crate::object::Attribution>) {
        self.attribution = a;
    }

    /// [`Repo::set_attribution`].
    pub fn attribution(&self) -> Option<&crate::object::Attribution> {
        self.attribution.as_ref()
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

    /// Snapshots reachable from `roots`, newest first by generation (the
    /// corrected commit date: strictly greater than every parent's, so
    /// children always come before their parents), ties by id.
    fn topo_children_first(&self, roots: impl IntoIterator<Item = ObjectId>) -> Result<Vec<ObjectId>> {
        self.graph.topo_iter(self, roots).collect()
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
        self.parents_tree_within(parents, None)
    }

    /// [`Repo::parents_tree`], optionally restricted to `within` before any
    /// parent trees are merged so paths outside `within` are never read or
    /// fetched.
    pub fn parents_tree_within(&self, parents: &[ObjectId], within: Option<&crate::vfs::SparseSet>) -> Result<MergeOutcome> {
        let restrict = |tree: ObjectId| -> Result<ObjectId> {
            match within {
                Some(set) => crate::vfs::restrict(&self.store, &tree, set),
                None => Ok(tree),
            }
        };
        match parents {
            [] => Ok(MergeOutcome::clean(self.store.empty_tree()?)),
            [p] => Ok(MergeOutcome::clean(restrict(self.snapshot(p)?.tree)?)),
            [first, rest @ ..] => {
                let mut acc = restrict(self.snapshot(first)?.tree)?;
                let mut merged = vec![*first];
                let mut conflicts = Vec::new();
                let mut renames = Vec::new();
                for p in rest {
                    // A redacted extra parent (the withheld source of an
                    // unreleased embargo) contributes nothing we can see.
                    let Some(ps) = self.snapshot_opt(p)? else { continue };
                    let base = self.merge_base_tree_at(&merged, &[*p], 0, within)?;
                    let out = merge_trees(&self.store, Some(base), acc, restrict(ps.tree)?)?;
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
        self.merge_base_tree_at(a, b, 0, None)
    }

    fn merge_base_tree_at(&self, a: &[ObjectId], b: &[ObjectId], depth: usize, within: Option<&crate::vfs::SparseSet>) -> Result<ObjectId> {
        /// Nested criss-crosses deeper than this merge against the empty
        /// tree: every disagreement is then a conflict, never a silent pick.
        const MAX_VIRTUAL_BASE_DEPTH: usize = 8;
        let restrict = |tree: ObjectId| -> Result<ObjectId> {
            match within {
                Some(set) => crate::vfs::restrict(&self.store, &tree, set),
                None => Ok(tree),
            }
        };
        let bases = self.merge_bases(a, b)?;
        match bases.as_slice() {
            [] => self.store.empty_tree(),
            [one] => restrict(self.snapshot(one)?.tree),
            _ if depth >= MAX_VIRTUAL_BASE_DEPTH => self.store.empty_tree(),
            [first, rest @ ..] => {
                let mut acc = restrict(self.snapshot(first)?.tree)?;
                let mut merged = vec![*first];
                for x in rest {
                    let base = self.merge_base_tree_at(&merged, &[*x], depth + 1, within)?;
                    acc = virtual_merge_base(&self.store, Some(base), acc, restrict(self.snapshot(x)?.tree)?)?;
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
        if !out.conflicts.is_empty() {
            self.refuse_lost_edit(old_parents, &out.conflicts)?;
        }
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

    /// A change moved off parents that stand in a view its person no longer
    /// has (the move to their current view kept it there: it edits a folder
    /// they lost, BUG-1509) conflicts at that folder, which its new parents
    /// no longer name: a change of the current view naming a folder its
    /// person cannot see, which no push accepts. Refused instead, by the
    /// folder's name, as the move refuses it (BUG-1563). Asked only of a
    /// move that conflicts, in a thin clone: the server says which of the
    /// old parents' snapshots it names otherwise now, and nothing below a
    /// folder it refuses is read. At most [`Self::LOST_EDIT_QUESTIONS`]
    /// snapshots are asked about, the old parents first: a conflicting
    /// rebase on a long local stack costs no request a commit.
    fn refuse_lost_edit(&self, old_parents: &[ObjectId], conflicts: &[VPath]) -> Result<()> {
        let store = &self.store;
        if !store.is_partial() || !store.may_fetch() {
            return Ok(());
        }
        let mut queue: VecDeque<ObjectId> = old_parents.iter().copied().collect();
        let mut seen = HashSet::new();
        while let Some(p) = queue.pop_front() {
            if p == self.root_id || !seen.insert(p) {
                continue;
            }
            if seen.len() > Self::LOST_EDIT_QUESTIONS {
                break;
            }
            // Down through the changes only this clone holds, to the
            // server's snapshots they stand on.
            if !store.is_servers(&p)? {
                queue.extend(self.snapshot(&p)?.parents.iter().copied());
                continue;
            }
            let Some(now) = store.current_projection(&p)?.filter(|n| *n != p) else { continue };
            let Some(lost) = crate::transaction::lost_paths(store, &self.snapshot(&p)?.tree, &self.snapshot(&now)?.tree)? else { continue };
            if let Some(folder) = lost.iter().find(|l| conflicts.iter().any(|c| c.starts_with(l))) {
                return Err(crate::tree::no_access(folder, "the change edits it, so it stays in the view it was made in"));
            }
        }
        Ok(())
    }

    const LOST_EDIT_QUESTIONS: usize = 4;

    /// `e`, a refusal to move `s` ([`Repo::refuse_lost_edit`]), naming it.
    pub(crate) fn naming_change(e: VeilError, s: &Snapshot) -> VeilError {
        match e {
            VeilError::Policy(m) if crate::tree::is_view_error(&VeilError::Policy(m.clone())) => VeilError::Policy(format!(
                "change {} ({}) cannot be moved: {m}",
                s.change_id.short(),
                s.description.as_str().lines().next().unwrap_or_default()
            )),
            e => e,
        }
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

    /// [`Held::reachable_among`], told `tips` (snapshots none of which
    /// descends from another) and their parents (`under`): the same
    /// answer, without reading what lies below them
    /// (`GraphIndex::reachable_among_tips`).
    pub fn reachable_among_tips(
        &self,
        roots: impl IntoIterator<Item = ObjectId>,
        wanted: &HashSet<ObjectId>,
        tips: &HashSet<ObjectId>,
        under: &HashSet<ObjectId>,
    ) -> Result<HashSet<ObjectId>> {
        self.0.graph.reachable_among_tips(self.0, roots, wanted, tips, under)
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

    /// Does the history index persist (not over a network)?
    pub(crate) fn graph_persists(&self) -> bool {
        self.graph.persists()
    }

    /// [`GraphIndex::voids`].
    pub(crate) fn graph_voids(&self) -> u64 {
        self.graph.voids()
    }

    /// [`GraphIndex::missing_below`].
    pub(crate) fn graph_missing_below(&self, heads: &[ObjectId], voids: u64) -> Result<Option<Vec<ObjectId>>> {
        self.graph.missing_below(self, heads, voids)
    }

    /// Drop the history index, to be computed again: after a thin clone is
    /// made full, whose entries at its boundary list no missing parents
    /// (BUG-1960).
    pub fn discard_history_index(&self) {
        self.graph.discard();
    }
}
