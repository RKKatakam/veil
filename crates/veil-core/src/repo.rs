//! The repository: CAS + keychain + operation log, all on one backend.
//!
//! On-backend layout:
//!
//! ```text
//! .veil/repo.json               format version, repository id, remotes
//! .veil/objects/ab/cdef…        content-addressed objects (shared)
//! .veil/objects/pack/           packfiles written by `vl gc`
//! .veil/objects/gc/             gc pending list and keep markers
//! .veil/ops/<id>, op_head       operation log (local)
//! .veil/meta/keyrings/*.json    wrapped scope keys (shared, safe to publish)
//! .veil/meta/embargoes/*.json   embargo records (shared)
//! .veil/local/                  device-only state: checkout pointer, vault
//! ```

use std::{
    collections::{BTreeMap, BinaryHeap, HashMap, HashSet, VecDeque},
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
    merge::{merge_trees, MergeOutcome},
    now_millis,
    object::{Snapshot, Text},
    oplog::{OpStore, Operation, View, WorkspaceState},
    policy::DEFAULT_SCOPE,
    store::ObjectStore,
    transaction::Transaction,
    vfs::StorageBackend,
    vpath::VPath,
};

pub const VEIL_DIR: &str = ".veil";

/// Repository format written by `vl init` and by [`crate::upgrade`].
///
/// | format | introduced | adds |
/// |---|---|---|
/// | 1 | vl 0.1.0 | JSON trees |
/// | 2 | vl 1.0.0 | binary trees (`TreeEncoding::Binary`) |
///
/// Every format up to this one is read; see `docs/FORMAT.md`.
pub const REPO_FORMAT: u32 = 2;

/// Oldest repository format this build reads (and keeps writing, unchanged,
/// until `vl upgrade`).
pub const MIN_REPO_FORMAT: u32 = 1;

/// The first vl release that reads repository format `format`.
pub fn min_vl_for_format(format: u32) -> &'static str {
    match format {
        0 | 1 => "0.1.0",
        2 => "1.0.0",
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RemoteConfig {
    pub url: String,
    /// Public remotes never receive cloaked content, cloaked tags or
    /// unreleased embargoed content.
    #[serde(default)]
    pub public: bool,
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
        })
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
}

impl std::fmt::Debug for Repo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Repo({} on {})", self.config.repo_id, self.backend.kind())
    }
}

fn config_path() -> VPath {
    VPath::new(".veil/repo.json").unwrap()
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
        let config = RepoConfig {
            format,
            repo_id: hex::encode(random_bytes::<16>()),
            remotes: BTreeMap::new(),
            min_vl: (format > 1).then(|| min_vl_for_format(format).to_string()),
        };
        let has_identity = identity.is_some();
        let keys = Arc::new(Keychain::new(backend.clone(), identity, config.repo_id.clone()));
        let store = Arc::new(ObjectStore::new(backend.clone(), VPath::new(".veil/objects")?, keys.clone()));
        store.set_format(format);
        let empty = store.empty_tree()?;
        let root_id = store.put_snapshot(&Snapshot::root(empty))?;
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
            let wc_id = store.put_snapshot(&wc)?;
            view.heads.insert(wc_id);
            view.workspaces.insert(
                DEFAULT_WORKSPACE.to_string(),
                WorkspaceState { wc: wc_id, cloak: None },
            );
        }
        let ops = OpStore::new(backend.clone());
        let op_id = ops.put(&Operation {
            parents: vec![],
            timestamp: now_millis(),
            user: user.to_string(),
            description: "initialize repository".into(),
            view: view.clone(),
        })?;
        ops.set_head(&op_id)?;
        // `repo.json` is what makes this a repository, so it is written last:
        // a crash before this point leaves no half-initialised repository.
        write_config(&*backend, &config)?;
        Ok(Repo {
            backend,
            store,
            ops,
            config,
            op_id,
            view,
            user: user.to_string(),
            root_id,
        })
    }

    pub fn open(backend: Arc<dyn StorageBackend>, identity: Option<Identity>, user: &str) -> Result<Repo> {
        let config = read_config(&*backend)?;
        // Before reading anything else: a newer format is never
        // half-understood, and never rewritten by this build.
        config.check_supported()?;
        let keys = Arc::new(Keychain::new(backend.clone(), identity, config.repo_id.clone()));
        let store = Arc::new(ObjectStore::new(backend.clone(), VPath::new(".veil/objects")?, keys));
        store.set_format(config.format);
        let root_id = store.put_snapshot(&Snapshot::root(store.empty_tree()?))?;
        let ops = OpStore::new(backend.clone());
        let op_id = ops.head()?;
        let view = ops.get(&op_id)?.view;
        Ok(Repo {
            backend,
            store,
            ops,
            config,
            op_id,
            view,
            user: user.to_string(),
            root_id,
        })
    }

    /// Re-read the operation head (another process or task may have moved it).
    pub fn reload(&mut self) -> Result<()> {
        let head = self.ops.head()?;
        if head != self.op_id {
            self.view = self.ops.get(&head)?.view;
            self.op_id = head;
        }
        Ok(())
    }

    pub fn transaction(&mut self, description: impl Into<String>) -> Result<Transaction<'_>> {
        let lock = RepoLock::acquire(self.backend.clone())?;
        self.reload()?;
        Ok(Transaction::new(self, description.into(), lock))
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
        self.store.set_format(config.format);
        self.config = config;
        Ok(())
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

    /// Plaintext description, or a `[cloaked:scope]` marker.
    pub fn description(&self, s: &Snapshot) -> String {
        match self.store.read_text(&s.description) {
            Some(t) => t,
            None => match &s.description {
                Text::Sealed(e) => format!("[cloaked:{}]", crate::keychain::split_label(&e.scope).0),
                Text::Plain(t) => t.clone(),
            },
        }
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

    /// Is `a` an ancestor of (or equal to) `b`?
    pub fn is_ancestor(&self, a: &ObjectId, b: &ObjectId) -> Result<bool> {
        Ok(a == b || self.ancestors(b)?.contains(a))
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
    pub fn parents_tree(&self, parents: &[ObjectId]) -> Result<MergeOutcome> {
        match parents {
            [] => Ok(MergeOutcome {
                tree: self.store.empty_tree()?,
                conflicts: vec![],
            }),
            [p] => Ok(MergeOutcome {
                tree: self.snapshot(p)?.tree,
                conflicts: vec![],
            }),
            [first, rest @ ..] => {
                let mut acc = self.snapshot(first)?.tree;
                let mut conflicts = Vec::new();
                for p in rest {
                    // A redacted extra parent (the withheld source of an
                    // unreleased embargo) contributes nothing we can see.
                    if self.snapshot_opt(p)?.is_none() {
                        continue;
                    }
                    let base = self.common_ancestor(first, p)?;
                    let out = merge_trees(
                        &self.store,
                        Some(self.snapshot(&base)?.tree),
                        acc,
                        self.snapshot(p)?.tree,
                    )?;
                    acc = out.tree;
                    conflicts.extend(out.conflicts);
                }
                Ok(MergeOutcome { tree: acc, conflicts })
            }
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

    pub fn op_log(&self, limit: usize) -> Result<Vec<(ObjectId, Operation)>> {
        let mut out = Vec::new();
        let mut cur = Some(self.op_id);
        while let Some(id) = cur {
            if out.len() >= limit {
                break;
            }
            // The current operation must exist; older ones may have been
            // pruned by gc, which simply ends the log.
            let op = match self.ops.try_get(&id)? {
                Some(op) => op,
                None if !out.is_empty() => break,
                None => return Err(VeilError::NotFound(format!("operation {}", id.short()))),
            };
            cur = op.parents.first().copied();
            out.push((id, op));
        }
        Ok(out)
    }
}
