//! Sync through the server (`docs/HUB.md` §4): per-viewer projections of
//! history, fetch on demand by object id, and push validation with an
//! atomic branch move.
//!
//! **Projected history** (`docs/HUB.md` §5.4, decided for S1). For a viewer
//! `v` the server maps each real snapshot `S` to `P(S)`:
//!
//! * `P(S).tree` is `S.tree` projected for `v` ([`Projector`]); the paths
//!   in `conflicts` that `v` cannot read are dropped;
//! * `P(S).parents` are the projections of `S.parents` (duplicates
//!   removed);
//! * a change that only touched what `v` cannot see (one parent, the same
//!   projected tree as that parent, a real tree that did change) is not in
//!   `v`'s history at all: `P(S) = P(parent)`. Its description never
//!   reaches `v`;
//! * if that is `S` itself (field for field, ignoring the signature), `v`
//!   gets `S` with its author's signature. Otherwise, if `S` was completed
//!   by the server from a pusher's own snapshot `N` and `P(S)` equals `N`,
//!   `v` gets `N`, again with its author's signature. Otherwise `P(S)` is a
//!   new snapshot **signed by the server's key** (`Session::hub_key`).
//!
//! So every snapshot a viewer holds has a signature that verifies: its
//! author's where the viewer sees all of it, the server's where the server
//! left something out. The server is trusted with code (HUB.md §3.1), so
//! its signature on a projection is within the trust boundary.
//! Projections are deterministic (Ed25519 signatures are), and memoised in
//! `projections` under the viewer's view key.

use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};

use bytes::Bytes;
use tokio::runtime::Handle;
use veil_core::{
    hub::{
        access::{AccessPolicy, View},
        project::{Change, Graft, Node, Projector, TreeSource, UploadedSet},
        encoding,
        wire::{put_frame, BranchResult, PushRequest, PushResult, Want, MAX_FRAME_OBJECT},
    },
    object::{EntryKind, Object, Snapshot, Tree, Visibility},
    policy::{Policy, Tier, POLICY_FILE},
    ObjectId, VPath, VeilError,
};

use crate::{
    error::{Error, Result},
    pack::{Slot, StagedSlots},
    perm::{Project, Viewer},
    Hub,
};

/// Most new snapshots one push may carry.
pub const MAX_PUSH_SNAPSHOTS: usize = 100_000;
/// Most parents of one snapshot (BUG-1078): a walk of history reads every
/// parent of each snapshot it passes, in one step.
pub const MAX_PARENTS: usize = 64;
/// Most branch updates one push may carry (BUG-913).
pub const MAX_PUSH_UPDATES: usize = 1_000;
/// Most branches one project may have (BUG-913): work lives as changes and
/// PRs, not as thousands of long-lived branches (`docs/OVERVIEW.md`).
pub const MAX_BRANCHES: usize = 10_000;
/// Most snapshots one history answer holds.
pub const MAX_HISTORY: usize = 200_000;

fn builtins() -> &'static ((ObjectId, Bytes), (ObjectId, Bytes)) {
    static B: std::sync::OnceLock<((ObjectId, Bytes), (ObjectId, Bytes))> = std::sync::OnceLock::new();
    B.get_or_init(|| {
        let empty = Bytes::from(Object::Tree(Tree::default()).encode());
        let empty_id = ObjectId::hash(&empty);
        let root = Bytes::from(Object::Snapshot(Snapshot::root(empty_id)).encode());
        let root_id = ObjectId::hash(&root);
        ((empty_id, empty), (root_id, root))
    })
}

/// The id of the universal root snapshot (every history starts there).
pub fn root_snapshot_id() -> ObjectId {
    builtins().1 .0
}

/// Every history starts at the universal root and its empty tree, which no
/// project stores.
pub(crate) fn builtin(id: &ObjectId) -> Option<Bytes> {
    let ((empty_id, empty), (root_id, root)) = builtins();
    if *id == *empty_id {
        return Some(empty.clone());
    }
    if *id == *root_id {
        return Some(root.clone());
    }
    None
}

/// Objects of one project, read synchronously (for the projection code,
/// which runs on a blocking thread).
pub struct Source {
    pub hub: Arc<Hub>,
    pub project: i64,
    pub rt: Handle,
    /// Objects read before the store: what an API commit made and has not
    /// stored yet (stored only once every check passed, so a refused
    /// plain-text secret is never stored; `changes`).
    pub pending: HashMap<ObjectId, Bytes>,
    /// A push's uploads and what it made (S28), read before the store.
    pub staged: Option<Arc<Staged>>,
}

/// A staged pack a push's receipts name: its name, and what the push
/// keeps of its index (BUG-1496): how many objects it holds, its length
/// and the slots of the objects the receipts name.
type StagedPack = (Arc<str>, StagedSlots);
type HeldPack = (Arc<str>, Arc<crate::pack::Held>);

/// What a push's receipts or named staged packs hold, and the objects the
/// server made for it (S28). None of it is the project's until the push's
/// transaction commits: staged objects are read only through this (under
/// cache keys of their own), so a refused upload is never answered as the
/// project's, and it is discarded with its pack (BUG-930).
pub struct Staged {
    /// Each receipted object in a staged pack: the pack and its slot.
    /// Empty for `PushRequest::packs` pushes, which look up directly in
    /// `held` (`BUG-2852`).
    at: Arc<HashMap<ObjectId, (Arc<str>, Slot)>>,
    /// Receipted staged packs: what the push keeps of each index.
    packs: Arc<Vec<StagedPack>>,
    /// Staged pack indexes held under `Packs::bound` (`pack::INDEXES_HELD`)
    /// for `PushRequest::packs` pushes (`BUG-1150`, `BUG-2852`): kept alive
    /// for the duration of the push and binary-searched in place without
    /// duplicating index entries.
    held: Arc<Vec<HeldPack>>,
    /// Objects the server made for the push (canonical encodings).
    made: Arc<Mutex<HashMap<ObjectId, Bytes>>>,
    /// Receipted objects whose container was consumed or swept (`BUG-2661`),
    /// answering `409 Conflict` if read.
    vanished: Arc<HashSet<ObjectId>>,
    /// The staged objects read through this one: what the checks read.
    touched: Mutex<HashSet<ObjectId>>,
}

impl UploadedSet for Staged {
    fn contains_uploaded(&self, id: &ObjectId) -> bool {
        self.has_staged(id) || self.vanished.contains(id)
    }
}

impl Staged {

    /// Nothing uploaded: what a check makes is held here and never stored.
    /// For the landing's re-check of a change it built (BUG-2220): the trees
    /// a re-check that passes makes are the batch's own, which the batch
    /// stores, and one that fails makes nothing anything names.
    pub(crate) fn held() -> Arc<Staged> {
        Arc::new(Staged {
            at: Arc::new(HashMap::new()),
            packs: Arc::new(Vec::new()),
            held: Arc::new(Vec::new()),
            made: Arc::new(Mutex::new(HashMap::new())),
            vanished: Arc::new(HashSet::new()),
            touched: Mutex::new(HashSet::new()),
        })
    }

    /// [`Staged::held`], holding `objects` (canonical encodings) from the
    /// start: what an API commit made, read by its checks before it is
    /// stored (BUG-1948).
    pub(crate) fn holding(objects: impl IntoIterator<Item = (ObjectId, Bytes)>) -> Arc<Staged> {
        let st = Staged::held();
        st.made.lock().unwrap().extend(objects);
        st
    }

    /// What the checks made and hold (never stored by them).
    pub(crate) fn made(&self) -> Vec<(ObjectId, Bytes)> {
        let mut v: Vec<(ObjectId, Bytes)> = self.made.lock().unwrap().iter().map(|(k, v)| (*k, v.clone())).collect();
        v.sort_by_key(|a| a.0);
        v
    }

    /// The same uploads and made objects, with reads counted apart (one
    /// snapshot's completion).
    fn child(&self) -> Arc<Staged> {
        Arc::new(Staged {
            at: self.at.clone(),
            packs: self.packs.clone(),
            held: self.held.clone(),
            made: self.made.clone(),
            vanished: self.vanished.clone(),
            touched: Mutex::new(HashSet::new()),
        })
    }

    fn touched(&self) -> HashSet<ObjectId> {
        std::mem::take(&mut *self.touched.lock().unwrap())
    }

    /// The staged pack and slot holding `id`, if uploaded in this push.
    fn slot_of(&self, id: &ObjectId) -> Option<(&Arc<str>, Slot)> {
        if let Some((n, s)) = self.at.get(id) {
            return Some((n, *s));
        }
        for (n, h) in self.held.iter() {
            if let Some(s) = h.index.get(id) {
                return Some((n, s));
            }
        }
        None
    }

    fn has_staged(&self, id: &ObjectId) -> bool {
        self.slot_of(id).is_some()
    }

    /// The staged packs' names.
    fn names(&self) -> Vec<Arc<str>> {
        self.packs
            .iter()
            .map(|p| p.0.clone())
            .chain(self.held.iter().map(|(n, _)| n.clone()))
            .collect()
    }

    /// A staged or made object's key in [`Hub::trees`]: never the
    /// project's.
    fn tree_key(&self, project: i64, id: &ObjectId) -> Option<ObjectId> {
        if self.made.lock().unwrap().contains_key(id) {
            return Some(crate::store::Objects::staged_key(project, "made", id, true));
        }
        if self.vanished.contains(id) {
            return Some(crate::store::Objects::staged_key(project, "vanished", id, true));
        }
        self.slot_of(id).map(|(n, _)| crate::store::Objects::staged_key(project, n, id, true))
    }
}

#[derive(Debug)]
struct StoredMissing(ObjectId);

impl std::fmt::Display for StoredMissing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "stored object {} is missing", self.0)
    }
}

impl std::error::Error for StoredMissing {}

impl Source {
    /// Is `id` an object uploaded in this request (`pending` or a staged pack)?
    /// Server-side reads of objects already in `hub.objects` return `store_err`
    /// (`VeilError::Io` -> logged `500 internal`) when missing or corrupt,
    /// whereas client uploads keep `VeilError::Missing` / `VeilError::Corrupt`
    /// for `Error::client_object` (`400 bad_request`: BUG-2681).
    pub(crate) fn is_client_upload(&self, id: &ObjectId) -> bool {
        self.pending.contains_key(id) || self.staged.as_ref().is_some_and(|st| st.contains_uploaded(id))
    }

    fn stored_missing(id: &ObjectId) -> VeilError {
        store_err(anyhow::Error::new(StoredMissing(*id)))
    }

    fn stored_corrupt(id: &ObjectId, m: impl std::fmt::Display) -> VeilError {
        store_err(anyhow::anyhow!("stored object {id} is corrupt: {m}"))
    }

    /// Object `id` when absence in the store is a valid `None` (`ChainSource`,
    /// `narrowing_gate`, `own_projection`, `resolve_for_mode`).
    pub(crate) fn present_raw(&self, id: &ObjectId) -> veil_core::Result<Option<Bytes>> {
        if let Some(raw) = self.pending.get(id) {
            return Ok(Some(raw.clone()));
        }
        if let Some(b) = builtin(id) {
            return Ok(Some(b));
        }
        if let Some(st) = &self.staged {
            if let Some(raw) = st.made.lock().unwrap().get(id) {
                return Ok(Some(raw.clone()));
            }
            if st.vanished.contains(id) {
                return Err(staged_gone());
            }
            if let Some((name, slot)) = st.slot_of(id) {
                // From its staged pack only, never from the project's store
                // (BUG-1155: that would answer for what the pusher did not
                // upload).
                let got = self.rt.block_on(self.hub.objects.get_staged(self.project, name, slot, id));
                let Some((_, raw)) = got.map_err(store_err)? else {
                    return Err(staged_gone());
                };
                st.touched.lock().unwrap().insert(*id);
                return Ok(Some(raw));
            }
        }
        self.hub.objects.get_blocking(&self.rt, self.project, id).map_err(store_err)
    }

    pub fn raw(&self, id: &ObjectId) -> veil_core::Result<Bytes> {
        match self.present_raw(id)? {
            Some(raw) => Ok(raw),
            None if self.is_client_upload(id) => Err(VeilError::Missing(*id)),
            None => Err(Self::stored_missing(id)),
        }
    }

    pub fn raw_ephemeral(&self, id: &ObjectId) -> veil_core::Result<Bytes> {
        if let Some(raw) = self.pending.get(id) {
            return Ok(raw.clone());
        }
        if let Some(b) = builtin(id) {
            return Ok(b);
        }
        // A staged or made object from where `raw` reads it; anything else
        // from the store, uncached, as without them.
        if self.staged.as_ref().is_some_and(|st| {
            st.contains_uploaded(id) || st.made.lock().unwrap().contains_key(id)
        }) {
            return self.raw(id);
        }
        self.hub
            .objects
            .get_ephemeral_blocking(&self.rt, self.project, id)
            .map_err(store_err)?
            .ok_or_else(|| Self::stored_missing(id))
    }

    /// Object `id` as stored ([`crate::store::Objects::get_encoded`]).
    pub fn encoded(&self, id: &ObjectId) -> veil_core::Result<Bytes> {
        if let Some(b) = builtin(id) {
            return Ok(b);
        }
        self.rt
            .block_on(self.hub.objects.get_encoded(self.project, id))
            .map_err(store_err)?
            .ok_or_else(|| Self::stored_missing(id))
    }

    pub(crate) fn decode_bytes(&self, id: &ObjectId, raw: &[u8]) -> veil_core::Result<Object> {
        let client = self.is_client_upload(id);
        Object::decode(raw).map_err(|e| match e {
            VeilError::Corrupt(_, m) if client => VeilError::Corrupt(id.hex(), m),
            other if client => other,
            other => Self::stored_corrupt(id, other),
        })
    }

    pub(crate) fn decode(&self, id: &ObjectId) -> veil_core::Result<Object> {
        let raw = self.raw(id)?;
        self.decode_bytes(id, &raw)
    }

    fn decode_snapshot_bytes(&self, id: &ObjectId, raw: &[u8]) -> veil_core::Result<Arc<Snapshot>> {
        if self.pending.contains_key(id) {
            return match self.decode_bytes(id, raw)? {
                Object::Snapshot(s) => Ok(Arc::new(s)),
                o => Err(VeilError::Corrupt(id.hex(), format!("expected a snapshot, found a {}", o.kind_name()))),
            };
        }
        let client = self.is_client_upload(id);
        Object::decode_snapshot_trusted(raw).map(Arc::new).map_err(|e| match e {
            VeilError::Corrupt(_, m) if client => VeilError::Corrupt(id.hex(), m),
            other if client => other,
            other => Self::stored_corrupt(id, other),
        })
    }

    pub fn snapshot(&self, id: &ObjectId) -> veil_core::Result<Arc<Snapshot>> {
        let raw = self.raw(id)?;
        self.decode_snapshot_bytes(id, &raw)
    }

    /// Stored or staged snapshot `id` when absence in the store is a valid
    /// `None` (`own_projection`, `resolve_for_mode`).
    pub(crate) fn present_snapshot(&self, id: &ObjectId) -> veil_core::Result<Option<Arc<Snapshot>>> {
        let Some(raw) = self.present_raw(id)? else {
            return Ok(None);
        };
        self.decode_snapshot_bytes(id, &raw).map(Some)
    }

    fn cached_node(&self, id: &ObjectId) -> (ObjectId, Option<Node>) {
        // A push's uploads and made trees are cached under keys of their
        // own, never as the project's.
        let staged = self.staged.as_ref().and_then(|st| st.tree_key(self.project, id).map(|k| (st, k)));
        let ck = match &staged {
            Some((_, k)) => *k,
            None => self.hub.objects.tree_key(self.project, id),
        };
        if let Some(t) = self.hub.trees.get(&ck) {
            if let Some((st, _)) = &staged {
                if st.has_staged(id) {
                    st.touched.lock().unwrap().insert(*id);
                }
            }
            return (ck, Some(Node::Tree(t.0, t.1)));
        }
        (ck, None)
    }

    fn decode_node(&self, id: &ObjectId, ck: ObjectId, raw: &[u8]) -> veil_core::Result<Node> {
        let Some(enc) = Object::tree_encoding(raw) else {
            return Ok(Node::Leaf);
        };
        match self.decode_bytes(id, raw)? {
            Object::Tree(t) => {
                let t = Arc::new(t);
                self.hub.trees.insert(ck, (t.clone(), enc), tree_weight(&t));
                Ok(Node::Tree(t, enc))
            }
            _ => Ok(Node::Leaf),
        }
    }

    /// Tree `id` when absence in the store is a valid `None` (`ChainSource`,
    /// `narrowing_gate`).
    pub(crate) fn present_tree(&self, id: &ObjectId) -> veil_core::Result<Option<Arc<Tree>>> {
        let (ck, cached) = self.cached_node(id);
        if let Some(Node::Tree(t, _)) = cached {
            return Ok(Some(t));
        }
        let Some(raw) = self.present_raw(id)? else {
            return Ok(None);
        };
        Ok(match self.decode_node(id, ck, &raw)? {
            Node::Tree(t, _) => Some(t),
            Node::Leaf => None,
        })
    }
}

pub(crate) const DISCARDED_UPLOAD: &str = "an upload this push names was discarded; push again";

#[derive(Debug)]
pub(crate) struct StagedUploadDiscarded;

impl std::fmt::Display for StagedUploadDiscarded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(DISCARDED_UPLOAD)
    }
}

impl std::error::Error for StagedUploadDiscarded {}

pub(crate) fn staged_gone() -> VeilError {
    VeilError::Io {
        path: "staged upload".into(),
        source: std::io::Error::other(StagedUploadDiscarded),
    }
}

pub(crate) fn staged_upload_discarded(e: &std::io::Error) -> bool {
    e.get_ref().is_some_and(|inner| {
        let mut cur: &(dyn std::error::Error + 'static) = inner;
        loop {
            if cur.is::<StagedUploadDiscarded>() {
                return true;
            }
            if let Some(a) = cur.downcast_ref::<crate::error::AnyhowCause>() {
                if crate::error::caused_by::<StagedUploadDiscarded>(&a.0) {
                    return true;
                }
            }
            match cur.source() {
                Some(s) => cur = s,
                None => return false,
            }
        }
    })
}

fn is_check_refusal(status: axum::http::StatusCode) -> bool {
    status.is_client_error()
        && status != axum::http::StatusCode::CONFLICT
        && status != axum::http::StatusCode::TOO_MANY_REQUESTS
}

/// Keep a store error's cause (`pack::IndexesFull` included: BUG-1622)
/// through [`VeilError`].
fn store_err(e: anyhow::Error) -> VeilError {
    VeilError::Io {
        path: "object store".into(),
        source: match e.downcast::<crate::pack::IndexesFull>() {
            Ok(full) => std::io::Error::other(full),
            Err(e) => match e.downcast::<std::io::Error>() {
                Ok(io) => io,
                Err(e) => std::io::Error::other(crate::error::AnyhowCause(e)),
            },
        },
    }
}

impl TreeSource for Source {
    fn node(&self, id: &ObjectId) -> veil_core::Result<Node> {
        let (ck, cached) = self.cached_node(id);
        if let Some(node) = cached {
            return Ok(node);
        }
        let raw = self.raw(id)?;
        self.decode_node(id, ck, &raw)
    }
}

/// About the memory decoded tree `t` holds in [`Hub::trees`], its slot
/// included (BUG-860: twice its encoding was well below it).
fn tree_weight(t: &Tree) -> usize {
    let heap: usize = t
        .entries
        .iter()
        .map(|e| e.name.capacity() + if e.visibility.is_public() { 0 } else { 64 })
        .sum();
    128 + std::mem::size_of::<Tree>() + t.entries.capacity() * std::mem::size_of::<veil_core::TreeEntry>() + heap
}

/// Run `f` with a [`Source`] on a blocking thread.
pub async fn blocking<T: Send + 'static>(hub: &Arc<Hub>, project: i64, f: impl FnOnce(&Source) -> Result<T> + Send + 'static) -> Result<T> {
    blocking_with(hub, project, HashMap::new(), f).await
}

/// [`blocking`], with objects `pending` read before the store.
pub async fn blocking_with<T: Send + 'static>(
    hub: &Arc<Hub>,
    project: i64,
    pending: HashMap<ObjectId, Bytes>,
    f: impl FnOnce(&Source) -> Result<T> + Send + 'static,
) -> Result<T> {
    blocking_in(hub, project, pending, None, f).await
}

/// [`blocking`], reading a push's `staged` objects before the store.
pub(crate) async fn blocking_staged<T: Send + 'static>(
    hub: &Arc<Hub>,
    project: i64,
    staged: Option<Arc<Staged>>,
    f: impl FnOnce(&Source) -> Result<T> + Send + 'static,
) -> Result<T> {
    blocking_in(hub, project, HashMap::new(), staged, f).await
}

pub(crate) async fn blocking_in<T: Send + 'static>(
    hub: &Arc<Hub>,
    project: i64,
    pending: HashMap<ObjectId, Bytes>,
    staged: Option<Arc<Staged>>,
    f: impl FnOnce(&Source) -> Result<T> + Send + 'static,
) -> Result<T> {
    let src = Source {
        hub: hub.clone(),
        project,
        rt: Handle::current(),
        pending,
        staged,
    };
    tokio::task::spawn_blocking(move || f(&src)).await.map_err(|e| Error::Other(e.into()))?
}

fn without_signature(s: &Snapshot) -> Snapshot {
    let mut s = s.clone();
    s.signature = None;
    s
}

/// The projection of real snapshot `real` for `viewer` (the module docs).
/// Its predecessors are projected too (BUG-826).
pub async fn projected(hub: &Arc<Hub>, project: &Project, viewer: &Viewer, real: ObjectId) -> Result<ObjectId> {
    // Run again on a retryable database error, as a request would
    // (BUG-1006): callers outside a request (background work, tests) get
    // neither the transaction retry nor the request middleware's. Safe to
    // repeat: its only writes are memo rows, `ON CONFLICT DO NOTHING`.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);
    loop {
        match crate::store::not_own(Box::pin(projected_inner(hub, project, viewer, real, None))).await {
            Err(e) if e.is_retryable() && std::time::Instant::now() < deadline => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
            r => return r,
        }
    }
}

/// What a push made and has not committed yet: the pusher's projections of
/// its new snapshots are worked out before its transaction and written in it
/// (one commit per push, `storage-and-cost.md` §3).
#[derive(Default)]
pub(crate) struct Deferred {
    /// The push's new real snapshots, each with the pusher's own snapshot
    /// the server completed it from.
    pub(crate) fresh: HashMap<ObjectId, Option<ObjectId>>,
    /// Memo rows `(view key, real, projected)` for the push's transaction.
    pub(crate) rows: Vec<(String, ObjectId, ObjectId)>,
    /// `rows` by view key and real snapshot.
    index: HashMap<(String, ObjectId), ObjectId>,
    /// Those of them whose real snapshot collapsed into its parent's
    /// projection (a change hidden from that view).
    pub(crate) collapsed: HashSet<ObjectId>,
    /// The push's uploads and made objects (its new snapshots are there).
    staged: Option<Arc<Staged>>,
    /// The projections it signed, among the made objects, for its pack.
    made: Vec<ObjectId>,
}

/// Is `id` committed history of `project` (`snapshots`, keyed by GC epoch)?
async fn committed(hub: &Hub, project: i64, id: &ObjectId) -> Result<bool> {
    if hub.caches.committed(project, id) {
        return Ok(true);
    }
    let gce = hub.caches.gc_epoch(project);
    let stored: Option<String> = sqlx::query_scalar("SELECT id FROM snapshots WHERE project_id = $1 AND id = $2")
        .bind(project)
        .bind(id.hex())
        .fetch_optional(&hub.db)
        .await?;
    if stored.is_some() {
        hub.caches.put_committed_at(project, gce, id);
    }
    Ok(stored.is_some())
}

/// The predecessors of `s` as `viewer` is shown them (BUG-826): a stored
/// predecessor becomes its projection, kept only if that is still a version
/// of the same change (not one that touched only what the viewer cannot
/// see); one the server never stored names nothing on it and is kept.
/// Terminates: ids are hashes of what they name, so no snapshot is its own
/// predecessor or ancestor.
async fn projected_predecessors(
    hub: &Arc<Hub>,
    project: &Project,
    viewer: &Viewer,
    s: &Snapshot,
    mut deferred: Option<&mut Deferred>,
) -> Result<Vec<ObjectId>> {
    let mut out = Vec::new();
    for p in &s.predecessors {
        // A push's own new snapshots count as stored: they are, once it commits.
        let fresh = deferred.as_ref().is_some_and(|d| d.fresh.contains_key(p));
        if !fresh && !committed(hub, project.id, p).await? {
            out.push(*p);
            continue;
        }
        let pp = Box::pin(projected_inner(hub, project, viewer, *p, deferred.as_deref_mut())).await?;
        let (p, pp2) = (*p, pp);
        let staged = deferred.as_ref().and_then(|d| d.staged.clone());
        let same = blocking_staged(hub, project.id, staged, move |src| Ok(src.snapshot(&pp2)?.change_id == src.snapshot(&p)?.change_id)).await?;
        if same && !out.contains(&pp) {
            out.push(pp);
        }
    }
    Ok(out)
}

pub(crate) async fn projected_inner(
    hub: &Arc<Hub>,
    project: &Project,
    viewer: &Viewer,
    real: ObjectId,
    mut deferred: Option<&mut Deferred>,
) -> Result<ObjectId> {
    if viewer.admin {
        return Ok(real);
    }
    let view_key = project.view(viewer).key();
    let root = root_snapshot_id();
    let staged = deferred.as_ref().and_then(|d| d.staged.clone());
    let mut done: HashMap<ObjectId, ObjectId> = HashMap::new();
    let mut stack = vec![(real, false)];
    let mut snaps: HashMap<ObjectId, Arc<Snapshot>> = HashMap::new();
    while let Some((x, expanded)) = stack.pop() {
        if done.contains_key(&x) {
            continue;
        }
        if x == root {
            done.insert(x, x);
            continue;
        }
        if !expanded {
            let fresh = deferred.as_ref().is_some_and(|d| d.fresh.contains_key(&x));
            // A push's new snapshot has no memo yet, except one this push
            // just worked out.
            let mine = deferred.as_ref().and_then(|d| d.index.get(&(view_key.clone(), x)).copied());
            let memo = match mine {
                Some(p) => Some(p),
                None if fresh => None,
                None => match hub.caches.memo(project.id, &view_key, &x) {
                    Some(p) => Some(p),
                    None => {
                        let gce = hub.caches.gc_epoch(project.id);
                        let m: Option<(String, bool)> =
                            sqlx::query_as("SELECT projected_id, collapsed FROM projections WHERE project_id = $1 AND view_key = $2 AND real_id = $3")
                                .bind(project.id)
                                .bind(&view_key)
                                .bind(x.hex())
                                .fetch_optional(&hub.db)
                                .await?;
                        let m = m
                            .map(|(p, c)| ObjectId::from_hex(&p).map(|p| (p, c)).map_err(|e| Error::Other(e.into())))
                            .transpose()?;
                        if let Some((p, c)) = &m {
                            hub.caches.put_memo_row_at(project.id, gce, &view_key, &x, p, *c);
                        }
                        m.map(|(p, _)| p)
                    }
                },
            };
            if let Some(p) = memo {
                done.insert(x, p);
                continue;
            }
            let s = blocking_staged(hub, project.id, staged.clone(), move |src| Ok(src.snapshot(&x)?)).await?;
            stack.push((x, true));
            // Attempts (format 10) are projected like any version, first.
            for p in s.parents.iter().chain(&s.attempts).rev() {
                if !done.contains_key(p) {
                    stack.push((*p, false));
                }
            }
            snaps.insert(x, s);
            continue;
        }
        let s = snaps[&x].clone();
        let pparents: Vec<ObjectId> = {
            let mut v = Vec::new();
            for p in &s.parents {
                let pp = done[p];
                if !v.contains(&pp) {
                    v.push(pp);
                }
            }
            v
        };
        let origin = match deferred.as_ref().and_then(|d| d.fresh.get(&x)) {
            Some(o) => *o,
            None => {
                let origin: Option<String> = sqlx::query_scalar("SELECT origin_id FROM origins WHERE project_id = $1 AND real_id = $2")
                    .bind(project.id)
                    .bind(x.hex())
                    .fetch_optional(&hub.db)
                    .await?;
                origin.and_then(|o| ObjectId::from_hex(&o).ok())
            }
        };
        let ppreds = projected_predecessors(hub, project, viewer, &s, deferred.as_deref_mut()).await?;
        let pattempts: Vec<ObjectId> = s.attempts.iter().map(|a| done[a]).collect();
        let (proj_text, bindings, viewer2) = (project.policy_text.clone(), project.bindings.clone(), viewer.clone());
        let hub2 = hub.clone();
        let first_pp = (pparents.len() == 1).then(|| pparents[0]);
        let (result, new_obj) = blocking_staged(hub, project.id, staged.clone(), move |src| {
            let policy = AccessPolicy::parse(&proj_text);
            let p = Project {
                id: src.project,
                name: String::new(),
                default_branch: String::new(),
                policy_text: String::new(),
                policy,
                bindings,
            };
            project_one(src, &p.view(&viewer2), x, &s, pparents, ppreds, pattempts, origin, &hub2.identity)
        })
        .await?;
        // A change hidden from this view: it collapsed into its parent's
        // projection (`projections.collapsed`, BUG-1468).
        let collapsed = first_pp == Some(result);
        let result = match deferred.as_deref_mut() {
            Some(d) => {
                // Stored with the push's pack (S28).
                if let Some(raw) = new_obj {
                    match &d.staged {
                        Some(st) => {
                            st.made.lock().unwrap().insert(result, raw);
                            d.made.push(result);
                        }
                        None => hub.objects.put(project.id, &result, raw).await?,
                    }
                }
                d.rows.push((view_key.clone(), x, result));
                d.index.insert((view_key.clone(), x), result);
                if collapsed {
                    d.collapsed.insert(x);
                }
                // A fill's progress, as it is worked out (BUG-2627: a fill
                // that stores its memos together stepped only once they
                // were all committed).
                crate::query::graph::projected_one();
                result
            }
            None => {
                if let Some(raw) = new_obj {
                    hub.objects.put(project.id, &result, raw).await?;
                }
                let inserted = sqlx::query(
                    "INSERT INTO projections (project_id, view_key, real_id, projected_id, created_at, collapsed) VALUES ($1, $2, $3, $4, $5, $6) \
                     ON CONFLICT DO NOTHING",
                )
                .bind(project.id)
                .bind(&view_key)
                .bind(x.hex())
                .bind(result.hex())
                .bind(veil_core::now_millis())
                .bind(collapsed)
                .execute(&hub.db)
                .await?
                .rows_affected();
                if inserted == 1 {
                    hub.commits.count(match crate::query::graph::filling() {
                        true => crate::db::Commit::Fill,
                        false => crate::db::Commit::Memo,
                    });
                }
                // Another request stored it first: every server answers what
                // is stored.
                let (stored, stored_collapsed) = if inserted == 1 {
                    (result, collapsed)
                } else {
                    let (p, c): (String, bool) =
                        sqlx::query_as("SELECT projected_id, collapsed FROM projections WHERE project_id = $1 AND view_key = $2 AND real_id = $3")
                            .bind(project.id)
                            .bind(&view_key)
                            .bind(x.hex())
                            .fetch_one(&hub.db)
                            .await?;
                    (ObjectId::from_hex(&p).map_err(|e| Error::Other(e.into()))?, c)
                };
                hub.caches.put_memo_row(project.id, &view_key, &x, &stored, stored_collapsed);
                // A fill's progress, when a fill asked (BUG-1943).
                crate::query::graph::projected_one();
                stored
            }
        };
        done.insert(x, result);
    }
    Ok(done[&real])
}

/// The projection of real snapshot `s` (id `x`) for a viewer of `view`,
/// given the projections of its parents (`pparents`), predecessors
/// (`ppreds`) and attempts (`pattempts`, one per attempt: an attempt, its
/// reason and attribution are seen by exactly the people who see the
/// change) and the pusher's own snapshot it was completed from
/// (`origin`): its id, and the object to store when the server signed a
/// new one (the module docs). Pure: [`projected`] memoises the answer, and
/// a commit through the API (`changes`) records it in its own transaction.
#[allow(clippy::too_many_arguments)]
pub(crate) fn project_one(
    src: &Source,
    view: &View,
    x: ObjectId,
    s: &Snapshot,
    pparents: Vec<ObjectId>,
    ppreds: Vec<ObjectId>,
    pattempts: Vec<ObjectId>,
    origin: Option<ObjectId>,
    identity: &veil_core::Identity,
) -> Result<(ObjectId, Option<Bytes>)> {
    let mut pr = Projector::new(src, view);
    let ptree = pr.root(s.tree)?;
    // A change of what the viewer cannot see only: not in their history.
    // An attempt stays one, whatever it changed: it is never history.
    if pparents.len() == 1 && !s.parents.is_empty() && s.abandoned.is_none() {
        let pp = src.snapshot(&pparents[0])?;
        let real_changed = s.parents.len() > 1 || src.snapshot(&s.parents[0])?.tree != s.tree;
        if pp.tree == ptree && real_changed {
            return Ok((pparents[0], None));
        }
    }
    let view_read = |p: &str| view.read(p);
    let mut u = without_signature(s);
    u.tree = ptree;
    u.parents = pparents;
    u.predecessors = ppreds;
    u.attempts = pattempts;
    u.conflicts.retain(|c| view_read(c));
    if u == without_signature(s) {
        return Ok((x, None));
    }
    if let Some(o) = origin {
        let n = src.snapshot(&o)?;
        if without_signature(&n) == u {
            return Ok((o, None));
        }
    }
    u.sign(identity);
    let raw = Object::Snapshot(u).encode();
    Ok((ObjectId::hash(&raw), Some(Bytes::from(raw))))
}

/// The real snapshots a snapshot id the client names may stand for: itself
/// if it is committed history, else the snapshots it is a projection of
/// (newest first). From the server's memory where it knows the answer for
/// the asker's view (`view_key`): that a snapshot is committed never
/// changes, and a real snapshot whose projection for that view is `id` is
/// one (BUG-915: never another view's). Otherwise the database's list.
/// Callers project what they get for the asker's current view, so the
/// answer grants nothing.
pub async fn resolve(hub: &Hub, project: i64, view_key: &str, id: &ObjectId) -> Result<Vec<ObjectId>> {
    resolve_at_most_excluding(hub, project, view_key, id, None, &[]).await
}

/// [`resolve`], excluding any real snapshot belonging to an embargo in
/// `exclude_embargoes` before picking candidates (BUG-2850).
pub async fn resolve_excluding(
    hub: &Hub,
    project: i64,
    view_key: &str,
    id: &ObjectId,
    exclude_embargoes: &[String],
) -> Result<Vec<ObjectId>> {
    resolve_at_most_excluding(hub, project, view_key, id, None, exclude_embargoes).await
}

/// The first of [`resolve`]'s answer, reading no more of the database's
/// list than it (BUG-2510: a run hidden from a view is one projected id
/// for every real snapshot of it).
pub async fn resolve_first(hub: &Hub, project: i64, view_key: &str, id: &ObjectId) -> Result<Option<ObjectId>> {
    resolve_first_excluding(hub, project, view_key, id, &[]).await
}

/// The first of [`resolve_excluding`]'s answer, excluding any real snapshot
/// belonging to an embargo in `exclude_embargoes` before applying `LIMIT` or
/// reading the reverse cache (BUG-2850).
pub async fn resolve_first_excluding(
    hub: &Hub,
    project: i64,
    view_key: &str,
    id: &ObjectId,
    exclude_embargoes: &[String],
) -> Result<Option<ObjectId>> {
    Ok(resolve_at_most_excluding(hub, project, view_key, id, Some(1), exclude_embargoes)
        .await?
        .into_iter()
        .next())
}

/// [`resolve`]'s answer, its first `limit` only when given, excluding any
/// snapshot in `exclude_embargoes`.
async fn resolve_at_most_excluding(
    hub: &Hub,
    project: i64,
    view_key: &str,
    id: &ObjectId,
    limit: Option<i64>,
    exclude_embargoes: &[String],
) -> Result<Vec<ObjectId>> {
    if *id == root_snapshot_id() || hub.caches.committed(project, id) {
        return Ok(vec![*id]);
    }
    if let Some(real) = hub.caches.resolved(project, view_key, id) {
        if exclude_embargoes.is_empty() {
            return Ok(vec![real]);
        }
        let excluded: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM embargo_snapshots WHERE project_id = $1 AND snapshot = $2 AND embargo_id = ANY($3))",
        )
        .bind(project)
        .bind(real.hex())
        .bind(exclude_embargoes)
        .fetch_one(&hub.db)
        .await?;
        if !excluded {
            return Ok(vec![real]);
        }
    }
    resolve_stored_excluding(hub, project, view_key, id, limit, exclude_embargoes).await
}

/// [`resolve`] as the database answers it now, in one statement: the first
/// `limit` of it when given (all when `None`), excluding snapshots in
/// `exclude_embargoes` (BUG-915, BUG-2634, BUG-2850, BUG-2880).
///
/// Priority:
/// 0. `id` itself if it is a committed snapshot.
/// 1. Uncollapsed projections under `view_key` (`projections_own`), newest first.
/// 2. Collapsed projections under `view_key` (`projections_by_view`), only if
///    (0) and (1) found nothing.
/// 3. Projections under any other `view_key` (`projections_by_projected_at`),
///    newest first, only if (0), (1), and (2) found nothing — so an id from a
///    caller's prior view after an access change (e.g. `vl pull` / `history`)
///    or from another view (e.g. `subtree`) still resolves to a real snapshot
///    that the caller's route then projects through their current view, while
///    never shadowing `view_key`'s own projection or returning an embargoed
///    snapshot in `exclude_embargoes`.
async fn resolve_stored_excluding(
    hub: &Hub,
    project: i64,
    view_key: &str,
    id: &ObjectId,
    limit: Option<i64>,
    exclude_embargoes: &[String],
) -> Result<Vec<ObjectId>> {
    if *id == root_snapshot_id() || hub.caches.committed(project, id) {
        return Ok(vec![*id]);
    }
    let gce = hub.caches.gc_epoch(project);
    // Read no more than the answer (BUG-2510): a run hidden from a view is
    // projected to one id, so reading every row with that id to sort them
    // read the whole run. The projections are read only for an id that is
    // no committed snapshot (the `NOT EXISTS`, uncorrelated: decided once,
    // before any of them is read; a committed id stands for itself alone):
    // first for `view_key`, preferring the snapshot `id` stands for
    // (`projections_own`, `NOT collapsed`) over any hidden changes collapsed
    // into it (`projections_by_view`, read only when there is no uncollapsed
    // row, stopped after `limit`); only when `view_key` has no non-excluded
    // row at all, falling back across other views (`projections_by_projected_at`,
    // newest first, stopped after `limit`: BUG-2880). Every branch excludes
    // snapshots in `exclude_embargoes` so withheld embargoes never mask a
    // public commit or leak via another view's projection.
    let rows: Vec<(String, i32, i64)> = if exclude_embargoes.is_empty() {
        sqlx::query_as(
            "SELECT id, 0, 0::BIGINT FROM snapshots WHERE project_id = $1 AND id = $2 \
             UNION ALL (SELECT real_id, 1, created_at FROM projections \
             WHERE project_id = $1 AND view_key = $3 AND projected_id = $2 AND NOT collapsed \
               AND NOT EXISTS (SELECT 1 FROM snapshots WHERE project_id = $1 AND id = $2) \
             ORDER BY created_at DESC LIMIT $4) \
             UNION ALL (SELECT real_id, 2, 0::BIGINT FROM projections \
             WHERE project_id = $1 AND view_key = $3 AND projected_id = $2 \
               AND NOT EXISTS (SELECT 1 FROM snapshots WHERE project_id = $1 AND id = $2) \
               AND NOT EXISTS (SELECT 1 FROM projections WHERE project_id = $1 AND view_key = $3 AND projected_id = $2 AND NOT collapsed) \
             LIMIT $4) \
             UNION ALL (SELECT real_id, 3, created_at FROM projections \
             WHERE project_id = $1 AND projected_id = $2 \
               AND NOT EXISTS (SELECT 1 FROM snapshots WHERE project_id = $1 AND id = $2) \
               AND NOT EXISTS (SELECT 1 FROM projections WHERE project_id = $1 AND view_key = $3 AND projected_id = $2) \
             ORDER BY created_at DESC LIMIT $4) \
             ORDER BY 2, 3 DESC",
        )
        // Planned for its own id (`resolve_for_mode`, BUG-2467).
        .persistent(false)
        .bind(project)
        .bind(id.hex())
        .bind(view_key)
        .bind(limit)
        .fetch_all(&hub.db)
        .await?
    } else {
        sqlx::query_as(
            "SELECT id, 0, 0::BIGINT FROM snapshots WHERE project_id = $1 AND id = $2 \
             UNION ALL (SELECT p.real_id, 1, p.created_at FROM projections p \
             WHERE p.project_id = $1 AND p.view_key = $3 AND p.projected_id = $2 AND NOT p.collapsed \
               AND NOT EXISTS (SELECT 1 FROM snapshots WHERE project_id = $1 AND id = $2) \
               AND NOT EXISTS (SELECT 1 FROM embargo_snapshots es WHERE es.project_id = $1 AND es.snapshot = p.real_id AND es.embargo_id = ANY($5)) \
             ORDER BY p.created_at DESC LIMIT $4) \
             UNION ALL (SELECT p.real_id, 2, 0::BIGINT FROM projections p \
             WHERE p.project_id = $1 AND p.view_key = $3 AND p.projected_id = $2 \
               AND NOT EXISTS (SELECT 1 FROM snapshots WHERE project_id = $1 AND id = $2) \
               AND NOT EXISTS (SELECT 1 FROM embargo_snapshots es WHERE es.project_id = $1 AND es.snapshot = p.real_id AND es.embargo_id = ANY($5)) \
               AND NOT EXISTS (SELECT 1 FROM projections p2 WHERE p2.project_id = $1 AND p2.view_key = $3 AND p2.projected_id = $2 AND NOT p2.collapsed \
                 AND NOT EXISTS (SELECT 1 FROM embargo_snapshots es2 WHERE es2.project_id = $1 AND es2.snapshot = p2.real_id AND es2.embargo_id = ANY($5))) \
             LIMIT $4) \
             UNION ALL (SELECT p.real_id, 3, p.created_at FROM projections p \
             WHERE p.project_id = $1 AND p.projected_id = $2 \
               AND NOT EXISTS (SELECT 1 FROM snapshots WHERE project_id = $1 AND id = $2) \
               AND NOT EXISTS (SELECT 1 FROM embargo_snapshots es WHERE es.project_id = $1 AND es.snapshot = p.real_id AND es.embargo_id = ANY($5)) \
               AND NOT EXISTS (SELECT 1 FROM projections p3 WHERE p3.project_id = $1 AND p3.view_key = $3 AND p3.projected_id = $2 \
                 AND NOT EXISTS (SELECT 1 FROM embargo_snapshots es3 WHERE es3.project_id = $1 AND es3.snapshot = p3.real_id AND es3.embargo_id = ANY($5))) \
             ORDER BY p.created_at DESC LIMIT $4) \
             ORDER BY 2, 3 DESC",
        )
        // Planned for its own id (`resolve_for_mode`, BUG-2467).
        .persistent(false)
        .bind(project)
        .bind(id.hex())
        .bind(view_key)
        .bind(limit)
        .bind(exclude_embargoes)
        .fetch_all(&hub.db)
        .await?
    };
    if rows.first().is_some_and(|r| r.1 == 0) {
        hub.caches.put_committed_at(project, gce, id);
        return Ok(vec![*id]);
    }
    Ok(rows.iter().filter_map(|r| ObjectId::from_hex(&r.0).ok()).collect())
}

/// The real snapshot `viewer` means by `id` (a snapshot id they were
/// given), for a change that will go to `branches` (a push's: the branches
/// it moves; an API commit's: its `onto`; the default branch is always
/// last): **one resolution for every route** (BUG-1467, BUG-1520), each
/// answer checked to project to `id` for them now.
///
/// 1. The tip of one of `branches`, in that order, then of the default
///    branch, that they see as `id`: the change goes there, so it is made
///    on what is there (even when `id` is itself committed history they see
///    whole, below a change hidden from them at the tip: BUG-1525).
/// 2. Committed history named by its own id: itself, if they see it so.
/// 3. Of their own view's real snapshots with that projection (changes
///    hidden from them share one; never another view's, never by when a
///    memo was stored): when they are one line (one of them is no other's
///    first parent), its newest; when lines diverge (two branches' hidden
///    work on one change they see), or there are more than
///    [`NEWEST_BOUND`], the change they all stand on, the one that did not
///    collapse into its parent's projection (`projections_own`): it carries
///    no line's hidden work, and the answer never depends on how much
///    hidden history there is (BUG-1521).
///    When no one change stands under diverging lines (two changes alike
///    for them, on two branches): for a landing (`landing`: its edits land
///    on the tip, and any of them gives the same edits) the lowest id of
///    their ends; for anything that moves a branch to it, refused (it
///    would carry one line's hidden work).
/// 4. A name from before their access changed: their own change's latest
///    revision (`change_refs`), if it projects to `id`.
///
/// `None`: nothing they can see is `id`.
pub(crate) async fn resolve_for(
    hub: &Arc<Hub>,
    project: &Project,
    viewer: &Viewer,
    id: &ObjectId,
    branches: &[&str],
    landing: bool,
) -> Result<Option<ObjectId>> {
    resolve_for_mode(hub, project, viewer, id, branches, landing, false, None).await
}

/// [`resolve_for`] with the branch rows of `branches` and the default
/// branch already read from the database by the caller in this request
/// (`tips`, as `branches` stores them; rows of other branches are ignored):
/// a push reads them once for all its resolutions. `no_embargo`: the same
/// statement found no unreleased embargo line, so no tip it read is
/// withheld from anyone (as of that statement, which read the tip).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn resolve_for_in(
    hub: &Arc<Hub>,
    project: &Project,
    viewer: &Viewer,
    id: &ObjectId,
    branches: &[&str],
    landing: bool,
    tips: &[(String, String)],
    no_embargo: bool,
) -> Result<Option<ObjectId>> {
    resolve_for_mode(hub, project, viewer, id, branches, landing, false, Some((tips, no_embargo))).await
}

/// As [`resolve_for`], preferring the uncollapsed commit `id` stands for over a
/// hidden commit collapsed above it (once past the default branch's tip), so CI
/// checks and bisect probes attach to the visible commit itself while keeping
/// S22 embargo withholding in the single resolver (BUG-1783).
pub(crate) async fn resolve_exact_for(
    hub: &Arc<Hub>,
    project: &Project,
    viewer: &Viewer,
    id: &ObjectId,
) -> Result<Option<ObjectId>> {
    resolve_for_mode(hub, project, viewer, id, &[], true, true, None).await
}

/// The one real snapshot of `project` whose projection for `viewer` (view key
/// `key`) is `projected_id` and that did not collapse into its parent's
/// projection (`projections_own`, BUG-1468), or `None` when there is none or
/// more than one.
///
/// Before BUG-2671, `projected_inner` recorded `collapsed = false` for every
/// multi-parent merge even when `project_one` collapsed it into its single
/// projected parent (`pparents == [projected_id]`). A multi-parent candidate
/// from `projections_own` is checked against its first parent's projection; one
/// that collapsed is repaired in place (`SET collapsed = TRUE`, bounded per
/// call) so `projections_own` drops it from then on. A candidate whose snapshot
/// or first parent was swept by a concurrent GC pass is dropped (neither kept
/// nor marked `collapsed`).
pub(crate) async fn own_projection(
    hub: &Arc<Hub>,
    project: &Project,
    viewer: &Viewer,
    key: &str,
    projected_id: &ObjectId,
) -> Result<Option<ObjectId>> {
    let withheld_eids = crate::embargo::withheld_embargo_ids(hub, project, viewer).await?;
    own_projection_excluding(hub, project, viewer, key, projected_id, &withheld_eids).await
}

async fn own_projection_excluding(
    hub: &Arc<Hub>,
    project: &Project,
    viewer: &Viewer,
    key: &str,
    projected_id: &ObjectId,
    withheld_eids: &[String],
) -> Result<Option<ObjectId>> {
    const REPAIR_BATCH: usize = 256;
    const MAX_REPAIR_BATCHES: usize = 16;

    let classify_and_repair = |batch: Vec<(String, Option<String>)>, mut keep: Vec<ObjectId>| async move {
        let mut derived_merges: Vec<(ObjectId, String, ObjectId)> = Vec::new();
        let mut unread: Vec<(ObjectId, String)> = Vec::new();
        for (r_hex, g_parents) in batch {
            let Ok(r) = ObjectId::from_hex(&r_hex) else { continue };
            match g_parents {
                Some(ps) if !ps.contains(',') => keep.push(r),
                Some(ps) => match serde_json::from_str::<Vec<ObjectId>>(&ps) {
                    Ok(v) if v.len() > 1 => derived_merges.push((r, r_hex, v[0])),
                    Ok(_) => keep.push(r),
                    Err(_) => unread.push((r, r_hex)),
                },
                None => unread.push((r, r_hex)),
            }
        }
        if unread.is_empty() && derived_merges.is_empty() {
            return Ok::<Vec<ObjectId>, Error>(keep);
        }

        // `projections` was read on `&hub.db` with autocommit, so a concurrent
        // GC pass may have swept an expired candidate's snapshot or first
        // parent since then. GC retains every parent of any live snapshot, so
        // a candidate whose snapshot or first parent is absent from the store
        // cannot be live: drop it into neither `keep` nor `stale`.
        let (single, merges) = blocking(hub, project.id, move |src| {
            let mut single = Vec::new();
            let mut merges = Vec::with_capacity(derived_merges.len() + unread.len());
            for (r, r_hex) in unread {
                let Some(s) = src.present_snapshot(&r)? else { continue };
                if let Some(p0) = s.parents.first() {
                    if src.present_raw(p0)?.is_none() {
                        continue;
                    }
                }
                if s.parents.len() > 1 {
                    merges.push((r, r_hex, s.parents[0]));
                } else {
                    single.push(r);
                }
            }
            for (r, r_hex, p0) in derived_merges {
                if src.present_raw(&r)?.is_some() && src.present_raw(&p0)?.is_some() {
                    merges.push((r, r_hex, p0));
                }
            }
            Ok((single, merges))
        })
        .await?;
        keep.extend(single);
        if merges.is_empty() {
            return Ok(keep);
        }

        let root = root_snapshot_id();
        let mut p0_proj: HashMap<ObjectId, ObjectId> = HashMap::new();
        let mut need_db: Vec<ObjectId> = Vec::new();
        for &(_, _, p0) in &merges {
            if p0 == root {
                p0_proj.insert(p0, root);
            } else if let Some(pp) = hub.caches.memo(project.id, key, &p0) {
                p0_proj.insert(p0, pp);
            } else if !need_db.contains(&p0) {
                need_db.push(p0);
            }
        }
        if !need_db.is_empty() {
            let gce = hub.caches.gc_epoch(project.id);
            let need_hex: Vec<String> = need_db.iter().map(ObjectId::hex).collect();
            let stored: Vec<(String, String, bool)> = sqlx::query_as(
                "SELECT real_id, projected_id, collapsed FROM projections WHERE project_id = $1 AND view_key = $2 AND real_id = ANY($3)",
            )
            .bind(project.id)
            .bind(key)
            .bind(&need_hex)
            .fetch_all(&hub.db)
            .await?;
            for (r_hex, pp_hex, collapsed) in stored {
                if let (Ok(p0), Ok(pp)) = (ObjectId::from_hex(&r_hex), ObjectId::from_hex(&pp_hex)) {
                    hub.caches.put_memo_row_at(project.id, gce, key, &p0, &pp, collapsed);
                    p0_proj.insert(p0, pp);
                }
            }
            if viewer.admin {
                for p0 in need_db {
                    p0_proj.entry(p0).or_insert(p0);
                }
            } else {
                for p0 in need_db {
                    if let std::collections::hash_map::Entry::Vacant(entry) = p0_proj.entry(p0) {
                        match projected(hub, project, viewer, p0).await {
                            Ok(pp) => {
                                entry.insert(pp);
                            }
                            Err(Error::Other(e)) if crate::error::caused_by::<StoredMissing>(&e) => {}
                            Err(e) => return Err(e),
                        }
                    }
                }
            }
        }

        let mut stale: Vec<String> = Vec::new();
        for (r, r_hex, p0) in merges {
            match p0_proj.get(&p0) {
                Some(pp) if pp == projected_id => stale.push(r_hex),
                Some(_) => keep.push(r),
                None => {}
            }
        }
        // On every GC path (`mark_and_sweep_loose` before `delete_loose_chunk`
        // in both `packs` and `objects` layouts, and `compact_batch`'s switch
        // before `forget_packs` / `sweep_discarded`), `purge_expired_db_records`
        // commits its `DELETE FROM projections` before any expired object is
        // deleted: if `r` and `p0` were still stored while `parents[1..]` was
        // swept (BUG-2721), `UPDATE ... AND NOT collapsed` matches 0 rows (and
        // before the purge, or under BUG-2623, only marks a collapsed row true).
        if !stale.is_empty() {
            stale.sort();
            let updated = sqlx::query(
                "UPDATE projections SET collapsed = TRUE \
                 WHERE project_id = $1 AND view_key = $2 AND real_id = ANY($3) AND NOT collapsed",
            )
            .bind(project.id)
            .bind(key)
            .bind(&stale)
            .execute(&hub.db)
            .await?
            .rows_affected();
            if updated > 0 {
                hub.commits.count(crate::db::Commit::Memo);
            }
        }
        Ok(keep)
    };

    let initial: Vec<(String, Option<String>)> = if withheld_eids.is_empty() {
        sqlx::query_as(
            "SELECT p.real_id, g.parents \
             FROM (SELECT real_id FROM projections \
                   WHERE project_id = $1 AND view_key = $2 AND projected_id = $3 AND NOT collapsed \
                   ORDER BY real_id LIMIT 2) p \
             LEFT JOIN graph g ON g.project_id = $1 AND g.snapshot = p.real_id \
             ORDER BY p.real_id",
        )
        .persistent(false)
        .bind(project.id)
        .bind(key)
        .bind(projected_id.hex())
        .fetch_all(&hub.db)
        .await?
    } else {
        sqlx::query_as(
            "SELECT p.real_id, g.parents \
             FROM (SELECT pr.real_id FROM projections pr \
                   WHERE pr.project_id = $1 AND pr.view_key = $2 AND pr.projected_id = $3 AND NOT pr.collapsed \
                     AND NOT EXISTS (SELECT 1 FROM embargo_snapshots es WHERE es.project_id = $1 AND es.snapshot = pr.real_id AND es.embargo_id = ANY($4)) \
                   ORDER BY pr.real_id LIMIT 2) p \
             LEFT JOIN graph g ON g.project_id = $1 AND g.snapshot = p.real_id \
             ORDER BY p.real_id",
        )
        .persistent(false)
        .bind(project.id)
        .bind(key)
        .bind(projected_id.hex())
        .bind(withheld_eids)
        .fetch_all(&hub.db)
        .await?
    };
    if initial.is_empty() {
        return Ok(None);
    }
    let initial_len = initial.len();
    let mut after = initial.last().unwrap().0.clone();
    let mut keep = classify_and_repair(initial, Vec::new()).await?;
    if keep.len() >= 2 || initial_len < 2 {
        return Ok(match keep.as_slice() {
            [o] => Some(*o),
            _ => None,
        });
    }
    for _ in 0..MAX_REPAIR_BATCHES {
        let batch: Vec<(String, Option<String>)> = if withheld_eids.is_empty() {
            sqlx::query_as(
                "SELECT p.real_id, g.parents \
                 FROM (SELECT real_id FROM projections \
                       WHERE project_id = $1 AND view_key = $2 AND projected_id = $3 AND NOT collapsed AND real_id > $4 \
                       ORDER BY real_id LIMIT $5) p \
                 LEFT JOIN graph g ON g.project_id = $1 AND g.snapshot = p.real_id \
                 ORDER BY p.real_id",
            )
            .persistent(false)
            .bind(project.id)
            .bind(key)
            .bind(projected_id.hex())
            .bind(&after)
            .bind(REPAIR_BATCH as i64)
            .fetch_all(&hub.db)
            .await?
        } else {
            sqlx::query_as(
                "SELECT p.real_id, g.parents \
                 FROM (SELECT pr.real_id FROM projections pr \
                       WHERE pr.project_id = $1 AND pr.view_key = $2 AND pr.projected_id = $3 AND NOT pr.collapsed AND pr.real_id > $4 \
                         AND NOT EXISTS (SELECT 1 FROM embargo_snapshots es WHERE es.project_id = $1 AND es.snapshot = pr.real_id AND es.embargo_id = ANY($6)) \
                       ORDER BY pr.real_id LIMIT $5) p \
                 LEFT JOIN graph g ON g.project_id = $1 AND g.snapshot = p.real_id \
                 ORDER BY p.real_id",
            )
            .persistent(false)
            .bind(project.id)
            .bind(key)
            .bind(projected_id.hex())
            .bind(&after)
            .bind(REPAIR_BATCH as i64)
            .bind(withheld_eids)
            .fetch_all(&hub.db)
            .await?
        };
        if batch.is_empty() {
            return Ok(match keep.as_slice() {
                [o] => Some(*o),
                _ => None,
            });
        }
        let batch_len = batch.len();
        after = batch.last().unwrap().0.clone();
        keep = classify_and_repair(batch, keep).await?;
        if keep.len() >= 2 {
            return Ok(None);
        }
        if batch_len < REPAIR_BATCH {
            return Ok(match keep.as_slice() {
                [o] => Some(*o),
                _ => None,
            });
        }
    }
    Ok(None)
}

#[allow(clippy::too_many_arguments)]
async fn resolve_for_mode(
    hub: &Arc<Hub>,
    project: &Project,
    viewer: &Viewer,
    id: &ObjectId,
    branches: &[&str],
    landing: bool,
    prefer_own: bool,
    read: Option<(&[(String, String)], bool)>,
) -> Result<Option<ObjectId>> {
    if *id == root_snapshot_id() {
        return Ok(Some(*id));
    }
    let withheld = |r: ObjectId| async move {
        if crate::embargo::is_withheld_from_viewer(hub, project, viewer, id).await? {
            return Ok::<bool, Error>(true);
        }
        if r != *id && crate::embargo::is_withheld_from_viewer(hub, project, viewer, &r).await? {
            return Ok(true);
        }
        Ok(false)
    };
    let seen = |r: ObjectId| async move {
        if projected(hub, project, viewer, r).await? != *id {
            return Ok::<bool, Error>(false);
        }
        Ok(!withheld(r).await?)
    };
    let mut names: Vec<&str> = branches.to_vec();
    names.push(&project.default_branch);
    let tips: Vec<(String, String)> = match read {
        Some((rows, _)) => rows.iter().filter(|(n, _)| names.contains(&n.as_str())).cloned().collect(),
        None => sqlx::query_as("SELECT name, target FROM branches WHERE project_id = $1 AND name = ANY($2)")
            .bind(project.id)
            .bind(names.iter().map(|n| n.to_string()).collect::<Vec<_>>())
            .fetch_all(&hub.db)
            .await?,
    };
    let tips = crate::embargo::filter_branches(hub, project, viewer, &tips).await?;
    // No embargo line was unreleased when the tips were read (in that one
    // statement): no tip is withheld.
    let tips_free = read.is_some_and(|(_, free)| free);
    for name in &names {
        if let Some(t) = tips.iter().find(|(n, _)| n == name).and_then(|(_, t)| ObjectId::from_hex(t).ok()) {
            let ok = match tips_free {
                true => projected(hub, project, viewer, t).await? == *id,
                false => seen(t).await?,
            };
            if ok {
                return Ok(Some(t));
            }
        }
    }
    // Committed history named by its own id (after the tips: a snapshot
    // they see whole under a change hidden from them at the tip, BUG-1525).
    // Asked with whether any view's projection is `id`, in one statement:
    // a new snapshot (a push's) is neither, and nothing they can see is it.
    let projected_somewhere = if hub.caches.committed(project.id, id) {
        return Ok(seen(*id).await?.then_some(*id));
    } else {
        let gce = hub.caches.gc_epoch(project.id);
        let (stored, projected): (bool, bool) = sqlx::query_as(
            "SELECT EXISTS (SELECT 1 FROM snapshots WHERE project_id = $1 AND id = $2), \
             EXISTS (SELECT 1 FROM projections WHERE project_id = $1 AND projected_id = $2)",
        )
        // Planned for its own id, never by a cached generic plan (an unnamed
        // statement, BUG-2467): a run hidden from a view is one projected id
        // for millions of rows, so a generic plan, built for any id, reckons
        // that every id matches millions and scans the table, which for a
        // new snapshot's id (a push's, a landing's) reads every row of it.
        // So for each lookup of `projections` by `projected_id` (those by
        // `projections_own`, `NOT collapsed`, excepted: few rows for any id).
        .persistent(false)
        .bind(project.id)
        .bind(id.hex())
        .fetch_one(&hub.db)
        .await?;
        if stored {
            hub.caches.put_committed_at(project.id, gce, id);
            return Ok(seen(*id).await?.then_some(*id));
        }
        projected
    };
    if !projected_somewhere {
        return Ok(None);
    }
    let key = project.view(viewer).key();
    let withheld_eids = crate::embargo::withheld_embargo_ids(hub, project, viewer).await?;
    let rows: Vec<(String, Option<String>)> = if withheld_eids.is_empty() {
        sqlx::query_as(
            "SELECT p.real_id, g.parents FROM projections p LEFT JOIN graph g ON g.project_id = p.project_id AND g.snapshot = p.real_id \
             WHERE p.project_id = $1 AND p.view_key = $2 AND p.projected_id = $3 LIMIT $4",
        )
        // Planned for its own id (above, BUG-2467).
        .persistent(false)
        .bind(project.id)
        .bind(&key)
        .bind(id.hex())
        .bind(NEWEST_BOUND as i64 + 1)
        .fetch_all(&hub.db)
        .await?
    } else {
        // Exclude snapshots belonging to unreleased embargoes withheld from
        // `viewer` before applying `LIMIT` or computing `firsts`/`leaves`
        // (BUG-2850): a collapsed embargoed commit under the same `view_key`
        // must never mask its public parent or split a visible line.
        sqlx::query_as(
            "SELECT p.real_id, g.parents FROM projections p LEFT JOIN graph g ON g.project_id = p.project_id AND g.snapshot = p.real_id \
             WHERE p.project_id = $1 AND p.view_key = $2 AND p.projected_id = $3 \
               AND NOT EXISTS (SELECT 1 FROM embargo_snapshots es WHERE es.project_id = $1 AND es.snapshot = p.real_id AND es.embargo_id = ANY($5)) \
             LIMIT $4",
        )
        // Planned for its own id (above, BUG-2467).
        .persistent(false)
        .bind(project.id)
        .bind(&key)
        .bind(id.hex())
        .bind(NEWEST_BOUND as i64 + 1)
        .bind(&withheld_eids)
        .fetch_all(&hub.db)
        .await?
    };
    let own = || own_projection_excluding(hub, project, viewer, &key, id, &withheld_eids);
    let pick = if rows.is_empty() {
        None
    } else if rows.len() > NEWEST_BOUND {
        own().await?
    } else if let Some(o) = if prefer_own { own().await? } else { None } {
        Some(o)
    } else {
        // Their first parents: the derived graph's, else the objects'.
        let mut cands: Vec<(ObjectId, Option<ObjectId>)> = Vec::new();
        let mut unread = Vec::new();
        for (r, parents) in &rows {
            let Ok(r) = ObjectId::from_hex(r) else { continue };
            match parents.as_deref().and_then(|p| serde_json::from_str::<Vec<ObjectId>>(p).ok()) {
                Some(ps) => cands.push((r, ps.first().copied())),
                None => unread.push(r),
            }
        }
        if !unread.is_empty() {
            let read = blocking(hub, project.id, move |src| {
                let mut out = Vec::with_capacity(unread.len());
                for r in &unread {
                    let Some(s) = src.present_snapshot(r)? else { continue };
                    if let Some(p0) = s.parents.first() {
                        if src.present_raw(p0)?.is_none() {
                            continue;
                        }
                    }
                    out.push((*r, s.parents.first().copied()));
                }
                Ok(out)
            })
            .await?;
            cands.extend(read);
        }
        let firsts: HashSet<ObjectId> = cands.iter().filter_map(|c| c.1).collect();
        let mut leaves: Vec<ObjectId> = cands.iter().map(|c| c.0).filter(|c| !firsts.contains(c)).collect();
        leaves.sort();
        match leaves.as_slice() {
            [one] => Some(*one),
            _ => match own().await? {
                Some(o) => Some(o),
                None => {
                    if !leaves.is_empty() {
                        let first_of: HashMap<ObjectId, Option<ObjectId>> = cands.into_iter().collect();
                        let candidates = leaves;
                        let present = blocking(hub, project.id, move |src| {
                            let mut out = Vec::with_capacity(candidates.len());
                            for r in candidates {
                                if src.present_raw(&r)?.is_none() {
                                    continue;
                                }
                                if let Some(Some(p0)) = first_of.get(&r) {
                                    if src.present_raw(p0)?.is_none() {
                                        continue;
                                    }
                                }
                                out.push((r, first_of.get(&r).copied().flatten()));
                            }
                            Ok(out)
                        })
                        .await?;
                        let root = root_snapshot_id();
                        leaves = Vec::with_capacity(present.len());
                        for (r, p0) in present {
                            if !viewer.admin {
                                if let Some(p0) = p0.filter(|p| *p != root && hub.caches.memo(project.id, &key, p).is_none()) {
                                    match projected(hub, project, viewer, p0).await {
                                        Ok(_) => {}
                                        Err(Error::Other(e)) if crate::error::caused_by::<StoredMissing>(&e) => continue,
                                        Err(e) => return Err(e),
                                    }
                                }
                            }
                            leaves.push(r);
                        }
                    }
                    match leaves.as_slice() {
                        [] => None,
                        [one] => Some(*one),
                        _ if landing => leaves.first().copied(),
                        _ => {
                            return Err(Error::conflict(format!(
                                "snapshot {} stands for changes on different lines as you see them: make the change on a branch's tip, or land it",
                                id.short()
                            )))
                        }
                    }
                }
            },
        }
    };
    if let Some(r) = pick {
        if withheld(r).await? {
            return Ok(None);
        }
        // A memo of their view that no longer projects to it: their view
        // is changing under them.
        return match projected(hub, project, viewer, r).await? == *id {
            true => Ok(Some(r)),
            false => Err(crate::query::graph::warming()),
        };
    }
    // Some view's projection is `id` (asked above).
    let named = *id;
    let cid = blocking(hub, project.id, move |src| Ok(src.present_snapshot(&named)?.map(|s| s.change_id.to_string()))).await?;
    let Some(cid) = cid else { return Ok(None) };
    let latest: Option<String> = sqlx::query_scalar("SELECT snapshot FROM change_refs WHERE project_id = $1 AND change_id = $2 AND created_by = $3")
        .bind(project.id)
        .bind(&cid)
        .bind(viewer.person.unwrap_or(0))
        .fetch_optional(&hub.db)
        .await?;
    match latest.and_then(|l| ObjectId::from_hex(&l).ok()) {
        Some(r) if seen(r).await? => Ok(Some(r)),
        _ => Ok(None),
    }
}

/// Most real snapshots of one view's projected id `resolve_for` orders
/// as a line; past it, the change they stand on.
pub const NEWEST_BOUND: usize = 4_096;

/// Branch tips as `viewer` sees them: every branch, or (`only`) those of
/// them named (`tips?branches=`, `docs/HUB.md` §13.41), each projected as
/// in the full answer. The branch rows come from this server's memory for
/// at most `caches::TIPS_TTL`, dropped at every push's notice; each
/// viewer's projection is of their current view.
pub async fn tips(hub: &Arc<Hub>, project: &Project, viewer: &Viewer, only: Option<&std::collections::BTreeSet<String>>) -> Result<Vec<(String, ObjectId)>> {
    use crate::caches::TipsLookup;
    let asked = std::time::Instant::now();
    let rows = loop {
        match hub.caches.tips(project.id) {
            TipsLookup::Hit(rows) => break rows,
            TipsLookup::Wait(done) => {
                let woken = done.woken().notified();
                tokio::pin!(woken);
                woken.as_mut().enable();
                if hub.caches.tips_reading(project.id, &done) {
                    // A read whose request was dropped never wakes anyone:
                    // after TIPS_TTL the next asker reads.
                    let _ = tokio::time::timeout(crate::caches::TIPS_TTL, woken).await;
                }
                // A read that started after this request answers it, kept
                // or not (BUG-2460).
                if let Some(rows) = done.rows_for(asked) {
                    break rows;
                }
            }
            TipsLookup::Read(read) => {
                let at = std::time::Instant::now();
                let r: std::result::Result<Vec<(String, String)>, sqlx::Error> =
                    sqlx::query_as("SELECT name, target FROM branches WHERE project_id = $1 ORDER BY name")
                        .bind(project.id)
                        .fetch_all(&hub.db)
                        .await;
                match r {
                    Ok(rows) => break hub.caches.put_tips(project.id, read, at, rows),
                    Err(e) => {
                        hub.caches.tips_failed(project.id, read);
                        return Err(e.into());
                    }
                }
            }
        }
    };
    let named: Vec<(String, String)>;
    let rows: &[(String, String)] = match only {
        Some(only) => {
            named = rows.iter().filter(|(name, _)| only.contains(name)).cloned().collect();
            &named
        }
        None => rows.as_slice(),
    };
    let rows = crate::embargo::filter_branches(hub, project, viewer, rows).await?;
    let mut out = Vec::new();
    for (name, target) in rows.iter() {
        let real = ObjectId::from_hex(target).map_err(|e| Error::Other(e.into()))?;
        out.push((name.clone(), projected(hub, project, viewer, real).await?));
    }
    Ok(out)
}

/// The snapshots reachable from `tips` in `viewer`'s projected history,
/// down to (not including) `stop`, as object frames: as stored, compressed
/// or not, when the caller reads `encoded` frames.
#[allow(clippy::too_many_arguments)]
pub async fn history(
    hub: &Arc<Hub>,
    project: &Project,
    viewer: &Viewer,
    epochs: &crate::caches::Epochs,
    tips: &[ObjectId],
    stop: &[ObjectId],
    limit: Option<usize>,
    encoded: bool,
    reads: u32,
) -> Result<Vec<u8>> {
    let mut starts = Vec::new();
    let mut reals = Vec::new();
    let mut resolved = Vec::with_capacity(tips.len());
    let vk = project.view(viewer).key();
    let withheld_eids = if epochs.embargo_free(project.id) {
        Vec::new()
    } else {
        crate::embargo::withheld_embargo_ids(hub, project, viewer).await?
    };
    for t in tips {
        if crate::embargo::is_withheld_in(hub, project, viewer, epochs, t).await? {
            return Err(Error::not_found(format!("no snapshot {} that you can see", t.short())));
        }
        let Some(real) = resolve_first_excluding(hub, project.id, &vk, t, &withheld_eids).await? else {
            return Err(Error::not_found(format!("no snapshot {} that you can see", t.short())));
        };
        if crate::embargo::is_withheld_in(hub, project, viewer, epochs, &real).await? {
            return Err(Error::not_found(format!("no snapshot {} that you can see", t.short())));
        }
        resolved.push((*t, real));
    }
    // An embargo made while this request resolved its tips (BUG-1947's
    // review): asked before any of them is projected.
    if let Some(t) = crate::embargo::withheld_since(hub, project, viewer, epochs, &resolved).await? {
        return Err(Error::not_found(format!("no snapshot {} that you can see", t.short())));
    }
    for (_, real) in resolved {
        starts.push(projected(hub, project, viewer, real).await?);
        reals.push(real);
    }
    let stop: HashSet<ObjectId> = stop.iter().copied().collect();
    if let Some(limit) = limit {
        // A page (a thin clone's): from any snapshot of the viewer's graph
        // that is not withheld, whether the branches still reach it or not
        // (an old version a rewrite elsewhere left under the clone's own
        // work is the person's to read below, BUG-1319). Names keep to what
        // the branches reach (`q/resolve`, BUG-1268).
        // (Branch tips, as a clone and a pull ask for, are in it: no
        // viewer graph is needed for them.)
        let branch_tips: HashSet<ObjectId> = self::tips(hub, project, viewer, None).await?.into_iter().map(|(_, t)| t).collect();
        let starts = match starts.iter().all(|s| branch_tips.contains(s)) {
            true => starts,
            false => {
                let readable = crate::query::page_starts(hub, project, viewer, reals).await?;
                starts.into_iter().zip(readable).filter(|(_, r)| *r).map(|(s, _)| s).collect()
            }
        };
        return blocking(hub, project.id, move |src| history_page(src, starts, &stop, limit.clamp(1, MAX_HISTORY), encoded, reads)).await;
    }
    blocking(hub, project.id, move |src| {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        let mut stack = starts;
        while let Some(id) = stack.pop() {
            if stop.contains(&id) || !seen.insert(id) {
                continue;
            }
            if seen.len() > MAX_HISTORY {
                return Err(Error::bad_request("history too long for one request"));
            }
            let raw = src.raw(&id)?;
            let Object::Snapshot(s) = Object::decode(&raw)? else {
                return Err(Error::Other(anyhow::anyhow!("projected history holds a non-snapshot")));
            };
            readable_by(&s, reads)?;
            match encoded {
                true => put_frame(&mut out, &id, &src.encoded(&id)?),
                false => put_frame(&mut out, &id, &raw),
            }
            // A version's attempts travel with it (format 10).
            stack.extend(s.parents.iter().chain(&s.attempts).copied());
        }
        Ok(out)
    })
    .await
}

/// One page of [`history`] (S3's thin clones): the tips, then their
/// ancestors, those of the newest children first, at most `limit`
/// snapshots in all (and every tip). Any page is a region the client can
/// hold: what it leaves out is reached by the next page.
/// Refuse to send snapshot `s` to a client that reads repository formats up
/// to `reads` only (BUG-1379): it is told to update `vl`, never sent what
/// it would report as a corrupt object. Every route that sends snapshots
/// calls it.
fn readable_by(s: &Snapshot, reads: u32) -> Result<()> {
    if s.has_format_10_fields() && reads < veil_core::object::ATTRIBUTION_REPO_FORMAT {
        return Err(Error::new(
            axum::http::StatusCode::UPGRADE_REQUIRED,
            "update_vl",
            format!(
                "this project holds changes of repository format {} (agent attribution, recorded attempts), which \
                 this vl does not read: update vl to {} or later",
                veil_core::object::ATTRIBUTION_REPO_FORMAT,
                veil_core::repo::min_vl_for_format(veil_core::object::ATTRIBUTION_REPO_FORMAT)
            ),
        ));
    }
    Ok(())
}

fn history_page(src: &Source, starts: Vec<ObjectId>, stop: &HashSet<ObjectId>, limit: usize, encoded: bool, reads: u32) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut heap: std::collections::BinaryHeap<(bool, i64, ObjectId)> = std::collections::BinaryHeap::new();
    for t in starts {
        heap.push((true, i64::MAX, t));
    }
    let mut taken = 0;
    while let Some((tip, _, id)) = heap.pop() {
        if stop.contains(&id) || !seen.insert(id) {
            continue;
        }
        if !tip && taken >= limit {
            break;
        }
        let raw = src.raw(&id)?;
        let Object::Snapshot(s) = Object::decode(&raw)? else {
            return Err(Error::Other(anyhow::anyhow!("projected history holds a non-snapshot")));
        };
        readable_by(&s, reads)?;
        match encoded {
            true => put_frame(&mut out, &id, &src.encoded(&id)?),
            false => put_frame(&mut out, &id, &raw),
        }
        taken += 1;
        // A version's attempts travel with it, in the same page (format 10:
        // at most 32; a client walks parents, so it never asks for them).
        for a in &s.attempts {
            if stop.contains(a) || !seen.insert(*a) {
                continue;
            }
            let raw = src.raw(a)?;
            let Object::Snapshot(at) = Object::decode(&raw)? else {
                return Err(Error::Other(anyhow::anyhow!("an attempt is not a snapshot")));
            };
            readable_by(&at, reads)?;
            match encoded {
                true => put_frame(&mut out, a, &src.encoded(a)?),
                false => put_frame(&mut out, a, &raw),
            }
        }
        for p in &s.parents {
            if !seen.contains(p) {
                // A parent's timestamp is read when it is taken; until then
                // its child's stands for it (parents are older).
                heap.push((false, s.timestamp, *p));
            }
        }
    }
    Ok(out)
}

/// Objects `wants` under snapshot `snapshot`, each checked against what
/// `viewer` may read at its path, as a stream of object frames (`encoded`:
/// each object as stored, compressed or not, for a caller that reads
/// encoded frames; the projected trees made for this viewer as they
/// are). Anything
/// not found at its path in the viewer's projection is refused as not
/// found, without saying whether it exists.
///
/// Memory is bounded (BUG-860): every want is checked first, a snapshot at
/// a time (its projected trees dropped before the next), then the answer
/// is read and sent a few objects ahead of the caller (`FETCH_WINDOW`);
/// a failure while sending ends the stream with an error, so it is never
/// taken as whole.
pub async fn fetch(
    hub: &Arc<Hub>,
    project: &Project,
    viewer: &Viewer,
    epochs: &crate::caches::Epochs,
    snapshot: ObjectId,
    wants: Vec<Want>,
    encoded: bool,
) -> Result<FrameStream> {
    // Each want is checked in its own snapshot (revision 1), as the viewer
    // sees it.
    let mut reals: HashMap<ObjectId, ObjectId> = HashMap::new();
    let vk = project.view(viewer).key();
    let withheld_eids = if epochs.embargo_free(project.id) {
        Vec::new()
    } else {
        crate::embargo::withheld_embargo_ids(hub, project, viewer).await?
    };
    for snap in std::iter::once(snapshot).chain(wants.iter().filter_map(|w| w.snapshot)) {
        if reals.contains_key(&snap) {
            continue;
        }
        if crate::embargo::is_withheld_in(hub, project, viewer, epochs, &snap).await? {
            return Err(Error::not_found(format!("no snapshot {} that you can see", snap.short())));
        }
        let Some(real) = resolve_first_excluding(hub, project.id, &vk, &snap, &withheld_eids).await? else {
            return Err(Error::not_found(format!("no snapshot {} that you can see", snap.short())));
        };
        if crate::embargo::is_withheld_in(hub, project, viewer, epochs, &real).await? {
            return Err(Error::not_found(format!("no snapshot {} that you can see", snap.short())));
        }
        reals.insert(snap, real);
    }
    // An embargo made while this request resolved its snapshots (BUG-1947's
    // review).
    let resolved: Vec<(ObjectId, ObjectId)> = reals.iter().map(|(named, real)| (*named, *real)).collect();
    if let Some(snap) = crate::embargo::withheld_since(hub, project, viewer, epochs, &resolved).await? {
        return Err(Error::not_found(format!("no snapshot {} that you can see", snap.short())));
    }
    let (policy_text, bindings, viewer) = (project.policy_text.clone(), project.bindings.clone(), viewer.clone());
    let wants = Arc::new(wants);
    let w2 = wants.clone();
    let (sizes, created) = blocking(hub, project.id, move |src| {
        let p = Project {
            id: src.project,
            name: String::new(),
            default_branch: String::new(),
            policy: AccessPolicy::parse(&policy_text),
            policy_text: String::new(),
            bindings,
        };
        let view = p.view(&viewer);
        check_wants(src, &view, snapshot, &reals, &w2)
    })
    .await?;
    // Packed objects the answer needs, neighbours read together (BUG-1152).
    {
        let ids: Vec<ObjectId> = wants.iter().map(|w| w.id).filter(|id| !created.contains_key(id) && builtin(id).is_none()).collect();
        hub.objects.prefetch(project.id, &ids).await;
    }
    // The answer: objects read concurrently (a remote store's latency would
    // otherwise add up one object at a time), at most `FETCH_WINDOW` of
    // them and about `FETCH_WINDOW_BYTES` ahead of the one sent next, each
    // counted by what reading it may hold (`Objects::read_cost`: the size
    // its entry records, checked at push, or what its encoding declares)
    // and taken from the server-wide `store::DECODED_IN_FLIGHT` (BUG-1087);
    // an id asked for more than once is read once. Framed in order and
    // sent about a MiB at a time as the caller takes it.
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    let (hub, pid) = (hub.clone(), project.id);
    tokio::spawn(async move {
        use crate::store::ReadAhead;
        let stop = |e: Error| {
            // Details go to the server's log; the caller's answer ends in an
            // error, never taken as whole.
            eprintln!("veil-server: a fetch answer stopped: {e:?}");
            std::io::Error::other("the answer stopped")
        };
        // What reading each id may hold, looked up once per id, 64 at a
        // time.
        let builtin_or_made = |id: &ObjectId| created.get(id).cloned().or_else(|| builtin(id));
        let mut cost_of: HashMap<ObjectId, u64> = HashMap::new();
        let mut lookups = tokio::task::JoinSet::new();
        for (i, w) in wants.iter().enumerate() {
            if cost_of.contains_key(&w.id) || builtin_or_made(&w.id).is_some() {
                continue;
            }
            cost_of.insert(w.id, 0);
            if lookups.len() >= FETCH_WINDOW {
                match lookups.join_next().await {
                    Some(Ok((id, Ok(c)))) => {
                        cost_of.insert(id, c);
                    }
                    Some(Ok((_, Err(e)))) => return drop(tx.send(Err(stop(Error::Other(e)))).await),
                    Some(Err(e)) => return drop(tx.send(Err(stop(Error::Other(e.into())))).await),
                    None => {}
                }
            }
            let (hub, id, recorded) = (hub.clone(), w.id, sizes[i]);
            lookups.spawn(async move { (id, hub.objects.read_cost(pid, &id, recorded).await) });
        }
        while let Some(r) = lookups.join_next().await {
            match r {
                Ok((id, Ok(c))) => {
                    cost_of.insert(id, c);
                }
                Ok((_, Err(e))) => return drop(tx.send(Err(stop(Error::Other(e)))).await),
                Err(e) => return drop(tx.send(Err(stop(Error::Other(e.into())))).await),
            }
        }
        let mut set = tokio::task::JoinSet::new();
        let mut ready: HashMap<usize, (Bytes, Option<ReadAhead>)> = HashMap::new();
        // Each id read and not yet sent: its want's index. A later want of
        // the same id inside the window is an alias: it is not read again,
        // and the bytes (and their share of the budget) are kept in `kept`
        // from the read's frame to the last alias's.
        let mut reading: HashMap<ObjectId, usize> = HashMap::new();
        let mut aliases: HashMap<ObjectId, usize> = HashMap::new();
        let mut is_alias = vec![false; wants.len()];
        let mut kept: HashMap<ObjectId, (Bytes, Option<ReadAhead>)> = HashMap::new();
        let mut cost = vec![0u64; wants.len()];
        let (mut next, mut sent, mut ahead) = (0usize, 0usize, 0u64);
        let mut out = Vec::new();
        while sent < wants.len() {
            while next < wants.len() && next - sent < FETCH_WINDOW {
                let id = wants[next].id;
                if let Some(raw) = builtin_or_made(&id) {
                    ready.insert(next, (raw, None));
                } else if reading.contains_key(&id) || kept.contains_key(&id) {
                    is_alias[next] = true;
                    *aliases.entry(id).or_default() += 1;
                } else {
                    cost[next] = cost_of[&id];
                    if next != sent && ahead + cost[next] > FETCH_WINDOW_BYTES {
                        break;
                    }
                    // Wait for the budget only while holding none of it (an
                    // empty window holds nothing, `kept` included).
                    let taken = if next == sent {
                        ReadAhead::wait(cost[next]).await
                    } else {
                        match ReadAhead::try_take(cost[next]) {
                            Some(t) => t,
                            None => break,
                        }
                    };
                    reading.insert(id, next);
                    let (hub, i) = (hub.clone(), next);
                    set.spawn(async move {
                        let got = match encoded {
                            true => hub.objects.get_encoded(pid, &id).await,
                            false => hub.objects.get(pid, &id).await,
                        };
                        (i, got, taken)
                    });
                }
                ahead += cost[next];
                next += 1;
            }
            let id = wants[sent].id;
            let raw = if is_alias[sent] {
                let raw = kept.get(&id).expect("an alias's bytes are kept until it is sent").0.clone();
                let n = aliases.get_mut(&id).expect("counted");
                *n -= 1;
                if *n == 0 {
                    aliases.remove(&id);
                    kept.remove(&id);
                }
                raw
            } else {
                while !ready.contains_key(&sent) {
                    let got = match set.join_next().await {
                        Some(Ok((i, Ok(Some(raw)), taken))) => Ok((i, raw, taken)),
                        Some(Ok((i, Ok(None), _))) => Err(Error::Other(anyhow::anyhow!("object {} is not stored", wants[i].id.short()))),
                        Some(Ok((_, Err(e), _))) => Err(Error::Other(e)),
                        Some(Err(e)) => Err(Error::Other(e.into())),
                        None => Err(Error::Other(anyhow::anyhow!("a fetch read went missing"))),
                    };
                    match got {
                        Ok((i, raw, taken)) => {
                            ready.insert(i, (raw, Some(taken)));
                        }
                        Err(e) => {
                            let _ = tx.send(Err(stop(e))).await;
                            return;
                        }
                    }
                }
                let (raw, taken) = ready.remove(&sent).expect("ready");
                if reading.get(&id) == Some(&sent) {
                    reading.remove(&id);
                    if aliases.contains_key(&id) {
                        kept.insert(id, (raw.clone(), taken));
                    }
                }
                raw
            };
            put_frame(&mut out, &id, &raw);
            ahead -= cost[sent];
            sent += 1;
            if out.len() >= 1 << 20 && tx.send(Ok(Bytes::from(std::mem::take(&mut out)))).await.is_err() {
                return;
            }
        }
        if !out.is_empty() {
            let _ = tx.send(Ok(Bytes::from(out))).await;
        }
    });
    Ok(FrameStream(rx))
}

/// Most objects, and about the most bytes (by the sizes tree entries
/// carry), [`fetch`] reads ahead of what it has sent.
const FETCH_WINDOW: usize = 64;
const FETCH_WINDOW_BYTES: u64 = 8 << 20;

/// An answer of object frames, sent as [`fetch`] reads them.
pub struct FrameStream(pub(crate) tokio::sync::mpsc::Receiver<std::result::Result<Bytes, std::io::Error>>);

impl hyper::body::Body for FrameStream {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<std::result::Result<hyper::body::Frame<Bytes>, std::io::Error>>> {
        self.0.poll_recv(cx).map(|o| o.map(|r| r.map(hyper::body::Frame::data)))
    }
}

/// Check every want of a fetch (see [`fetch`]), a snapshot at a time.
/// Returns each want's size where its tree entry says (0 otherwise), and
/// the projected trees the server made that the wants name.
fn check_wants(
    src: &Source,
    view: &View,
    snapshot: ObjectId,
    reals: &HashMap<ObjectId, ObjectId>,
    wants: &[Want],
) -> Result<(Vec<u64>, HashMap<ObjectId, Bytes>)> {
    let gone = || Error::not_found("no such object at that path that you can see");
    let mut sizes = vec![0u64; wants.len()];
    let mut created = HashMap::new();
    let mut order: Vec<usize> = (0..wants.len()).collect();
    order.sort_by_key(|&i| wants[i].snapshot.unwrap_or(snapshot));
    for group in order.chunk_by(|&a, &b| wants[a].snapshot.unwrap_or(snapshot) == wants[b].snapshot.unwrap_or(snapshot)) {
        let snap = wants[group[0]].snapshot.unwrap_or(snapshot);
        // This snapshot's projected root and directory trees by path,
        // filled as its wants need them, and dropped after them.
        let mut pr = Projector::new(src, view);
        let root = pr.root(src.snapshot(&reals[&snap])?.tree)?;
        let mut dirs: Dirs = HashMap::new();
        dirs.insert(String::new(), pr.tree(&root)?);
        for &i in group {
            let w = &wants[i];
            // A narrowed agent session (`docs/HUB.md` §13.27): files inside
            // its narrowing, and the trees of the folders on the way there.
            let narrowed_dir = !view.within_narrowing(&w.path);
            if narrowed_dir && !view.toward_narrowing(&w.path) {
                return Err(gone());
            }
            let ok = if w.path.is_empty() {
                w.id == root
            } else {
                let (dir, name) = w.path.rsplit_once('/').unwrap_or(("", w.path.as_str()));
                let tree = dir_tree(&mut pr, &mut dirs, dir)?.ok_or_else(gone)?;
                let e = tree.get(name).ok_or_else(gone)?;
                if narrowed_dir && e.kind != EntryKind::Dir {
                    return Err(gone());
                }
                if e.id == w.id && e.kind != EntryKind::Dir {
                    sizes[i] = e.size;
                }
                e.id == w.id
                    || (e.kind == EntryKind::Conflict
                        && matches!(Object::decode(&src.raw(&e.id)?)?, Object::Conflict(c) if c.referenced_ids().contains(&w.id)))
            };
            if !ok {
                return Err(gone());
            }
            if let Some(raw) = pr.created_raw(&w.id) {
                created.insert(w.id, Bytes::copy_from_slice(raw));
            }
        }
    }
    Ok((sizes, created))
}

/// Projected directory trees of one snapshot, by path.
type Dirs = HashMap<String, Option<Arc<Tree>>>;

/// The projected tree of directory `dir`, walking down from the root.
fn dir_tree(pr: &mut Projector, dirs: &mut Dirs, dir: &str) -> Result<Option<Arc<Tree>>> {
    if let Some(t) = dirs.get(dir) {
        return Ok(t.clone());
    }
    let (parent, name) = dir.rsplit_once('/').unwrap_or(("", dir));
    let t = match dir_tree(pr, dirs, parent)? {
        Some(pt) => match pt.get(name) {
            Some(e) if e.kind == EntryKind::Dir => pr.tree(&e.id)?,
            _ => None,
        },
        None => None,
    };
    dirs.insert(dir.to_string(), t.clone());
    Ok(t)
}

// ---- push -------------------------------------------------------------------------

/// What a narrowed agent session is told when a branch move would change
/// something outside its paths: it names nothing there.
pub(crate) const NARROWED_MOVE: &str = NARROWED_WRITE;

/// The refusal of what an agent session may never do (`docs/HUB.md` §13.27).
pub(crate) fn agent_refusal(m: &str) -> Error {
    Error::new(axum::http::StatusCode::FORBIDDEN, crate::auth::AGENT_SESSION, m.to_string())
}

/// What [`differs_where`] does at an entry that differs between the trees.
enum Visit {
    /// Nothing to look at here.
    Skip,
    /// Look below (the folders, on either side; a file side counts as none).
    Descend,
    /// This difference is what was looked for.
    Found,
}

/// What [`differs_where`] asks at each entry that differs: its path and
/// the entry on each side.
type Visitor<'a> = &'a dyn Fn(&str, Option<&veil_core::TreeEntry>, Option<&veil_core::TreeEntry>) -> Visit;

/// How [`differs_where`] reads a tree: `None` for no tree there.
type Trees<'a> = &'a dyn Fn(&ObjectId) -> veil_core::Result<Option<Arc<Tree>>>;

/// Real trees from the store.
fn stored_tree(src: &Source, id: &ObjectId) -> veil_core::Result<Option<Arc<Tree>>> {
    Ok(match src.node(id)? {
        Node::Tree(t, _) => Some(t),
        Node::Leaf => None,
    })
}

/// Do trees `a` and `b` (read by `get`) differ anywhere `visit` says
/// [`Visit::Found`]? Both are walked down at once, only where they differ,
/// and only into what `visit` descends into: the work is that of the
/// difference.
fn differs_where(
    get: Trees,
    a: Option<ObjectId>,
    b: ObjectId,
    visit: Visitor,
) -> Result<bool> {
    use std::collections::{BTreeMap, BTreeSet};
    fn entries(get: Trees, id: Option<ObjectId>) -> Result<BTreeMap<String, veil_core::TreeEntry>> {
        let Some(id) = id else { return Ok(BTreeMap::new()) };
        Ok(match get(&id).map_err(Error::client_object)? {
            Some(t) => t.entries.iter().map(|e| (e.name.clone(), e.clone())).collect(),
            None => BTreeMap::new(),
        })
    }
    fn walk(src: Trees, visit: Visitor, dir: &str, a: Option<ObjectId>, b: Option<ObjectId>, depth: usize) -> Result<bool> {
        if a == b {
            return Ok(false);
        }
        if depth > veil_core::tree::MAX_TREE_DEPTH {
            return Ok(true);
        }
        let (ea, eb) = (entries(src, a)?, entries(src, b)?);
        for name in ea.keys().chain(eb.keys()).collect::<BTreeSet<_>>() {
            let (x, y) = (ea.get(name), eb.get(name));
            if x == y {
                continue;
            }
            let path = if dir.is_empty() { name.clone() } else { format!("{dir}/{name}") };
            let dir_of = |e: Option<&veil_core::TreeEntry>| e.filter(|e| e.kind == EntryKind::Dir).map(|e| e.id);
            match visit(&path, x, y) {
                Visit::Skip => {}
                Visit::Found => return Ok(true),
                Visit::Descend => {
                    if walk(src, visit, &path, dir_of(x), dir_of(y), depth + 1)? {
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    }
    walk(get, visit, "", a, Some(b), 0)
}

/// Does going from tree `from` to tree `to` (read by `get`) change
/// anything outside `view`'s narrowing (BUG-1378)? Inside it anything may
/// differ; on the way to it, only folders that are folders on both sides
/// are looked into; anywhere else nothing may.
fn differs_outside_narrowing(get: Trees, view: &View, from: ObjectId, to: ObjectId) -> Result<bool> {
    differs_where(get, Some(from), to, &|path, x, y| {
        let dir = |e: Option<&veil_core::TreeEntry>| e.is_none_or(|e| e.kind == EntryKind::Dir);
        if view.within_narrowing(path) {
            Visit::Skip
        } else if dir(x) && dir(y) && view.toward_narrowing(path) {
            Visit::Descend
        } else {
            Visit::Found
        }
    })
}

/// Does going from real tree `from` to real tree `to` change a file that
/// decides access or review (`hub::agent::decides_access`), in any folder,
/// whoever made the change (BUG-1391)?
fn differs_in_access_files(src: &Source, from: ObjectId, to: ObjectId) -> Result<bool> {
    differs_where(&|id| stored_tree(src, id), Some(from), to, &|path, x, y| {
        let file = |e: Option<&veil_core::TreeEntry>| e.is_some_and(|e| e.kind != EntryKind::Dir);
        if veil_core::hub::agent::decides_access(path) && (file(x) || file(y)) {
            Visit::Found
        } else if x.is_some_and(|e| e.kind == EntryKind::Dir) || y.is_some_and(|e| e.kind == EntryKind::Dir) {
            Visit::Descend
        } else {
            Visit::Skip
        }
    })
}

/// The landed work a branch's new tip `new` holds (BUG-1920): the default
/// branch's snapshots at the merge bases of `new` and the default branch's
/// tip, the newest landed ones `new` contains. They are found when first
/// asked for (a move whose every path its mover may write never asks).
pub(crate) struct Landed {
    tip: Option<ObjectId>,
    new: ObjectId,
    trees: Option<Vec<ObjectId>>,
}

impl Landed {
    /// `tip`: the default branch's tip, or `None` where nothing counts as
    /// landed work (a move of the default branch itself, a forced move).
    pub(crate) fn new(tip: Option<ObjectId>, new: ObjectId) -> Landed {
        Landed { tip, new, trees: None }
    }

    /// Does the default branch hold `entry` at `path` where `new` joins it?
    pub(crate) fn holds(&mut self, src: &Source, rows: &mut PushRows, path: &str, entry: Option<&veil_core::TreeEntry>) -> Result<bool> {
        let Some(tip) = self.tip else { return Ok(false) };
        if self.trees.is_none() {
            let mut trees = Vec::new();
            for b in merge_bases(src, rows, self.new, tip)? {
                trees.push(src.snapshot(&b)?.tree);
            }
            self.trees = Some(trees);
        }
        for t in self.trees.iter().flatten() {
            if entry_at(src, t, path)?.as_ref() == entry {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

/// **The one write rule of a branch's move** (`docs/HUB.md` §4.5, check 2;
/// BUG-1858, BUG-1920): every path whose entry differs between the branch's
/// old tip `cur` and its new tip `new` needs the mover's write access,
/// whatever the shape of the snapshots that bring the difference (a
/// fast-forward to a snapshot the server holds, a merge with a held or an
/// uploaded parent in any place, a stack on someone's work, a forced move).
/// What an uploaded snapshot's own check allows as "taken from another
/// parent's side" (`check_changes`) is decided here for the branch.
///
/// `landed` is the default branch's tip, given for a move that only adds to
/// a branch other than the default one: there, a path where `new` holds
/// what the default branch held at a merge base of the two (the newest
/// landed snapshots `new` contains) is landed work the move takes, and no
/// write (merging the default branch into one's own). The default branch
/// itself, and a forced move, have no such paths. `cur` is `None` for a
/// branch that holds nothing yet (everything in `new` is brought).
///
/// Never names a path `viewer` cannot read. `rows` are the push's graph
/// rows (the merge bases are found only when a path would be refused).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn branch_move_write_refusal(
    hub: &Arc<Hub>,
    project: &Project,
    viewer: &Viewer,
    cur: Option<ObjectId>,
    new: ObjectId,
    landed: Option<ObjectId>,
    rows: &mut PushRows,
    staged: Option<Arc<Staged>>,
) -> Result<Option<String>> {
    if (viewer.admin && viewer.only.is_none() && !viewer.agent) || cur == Some(new) {
        return Ok(None);
    }
    let (v, text, bindings) = (viewer.clone(), project.policy_text.clone(), project.bindings.clone());
    let mut taken = std::mem::take(rows);
    let (refusal, back) = blocking_in(hub, project.id, HashMap::new(), staged, move |src| {
        let p = Project {
            id: src.project,
            name: String::new(),
            default_branch: String::new(),
            policy: AccessPolicy::parse(&text),
            policy_text: String::new(),
            bindings,
        };
        let view = p.view(&v);
        let from = match cur {
            Some(c) => Some(src.snapshot(&c)?.tree),
            None => None,
        };
        let to = src.snapshot(&new)?.tree;
        if from == Some(to) {
            return Ok((None, taken));
        }
        // An error in finding the landed work ends the walk.
        let failed: std::cell::RefCell<Option<Error>> = std::cell::RefCell::new(None);
        let landed = std::cell::RefCell::new((Landed::new(landed, new), &mut taken));
        let is_landed = |path: &str, y: Option<&veil_core::TreeEntry>| -> Result<bool> {
            let (landed, rows) = &mut *landed.borrow_mut();
            landed.holds(src, rows, path, y)
        };
        let refusal = std::cell::RefCell::new(None);
        differs_where(&|id| stored_tree(src, id), from, to, &|path, x, y| {
            let is_dir = |e: Option<&veil_core::TreeEntry>| e.is_some_and(|e| e.kind == EntryKind::Dir);
            let is_file = |e: Option<&veil_core::TreeEntry>| e.is_some_and(|e| e.kind != EntryKind::Dir);
            if is_file(x) || is_file(y) {
                let why = if !view.within_narrowing(path) {
                    Some(NARROWED_MOVE.to_string())
                } else if !view.read(path) {
                    Some("you may not move this branch across changes outside your view".to_string())
                } else if !view.write(path) {
                    Some(format!("you may not write '{path}'"))
                } else {
                    None
                };
                if let Some(why) = why {
                    match is_landed(path, y) {
                        Ok(true) => {}
                        Ok(false) => {
                            *refusal.borrow_mut() = Some(why);
                            return Visit::Found;
                        }
                        Err(e) => {
                            *failed.borrow_mut() = Some(e);
                            return Visit::Found;
                        }
                    }
                }
            }
            if is_dir(x) || is_dir(y) {
                Visit::Descend
            } else {
                Visit::Skip
            }
        })?;
        if let Some(e) = failed.into_inner() {
            return Err(e);
        }
        Ok((refusal.into_inner(), taken))
    })
    .await?;
    *rows = back;
    Ok(refusal)
}

/// Why an agent session may not set a branch's tip ([`agent_tip`]).
pub(crate) enum AgentTip {
    /// The tip would change files outside a narrowed session's paths
    /// ([`NARROWED_MOVE`]: naming nothing there).
    Narrowed,
    /// The tip would change a file that decides access or review
    /// ([`AGENT_ACCESS_MOVE`]).
    Access,
    /// The tip would create (or recreate) the default branch
    /// ([`AGENT_DEFAULT_BRANCH`]).
    DefaultBranch,
}

/// What an agent session is told when it would create or recreate the
/// default branch (BUG-1538).
pub(crate) const AGENT_DEFAULT_BRANCH: &str = "an agent session never creates the default branch; its person does";

/// **The one rule of every branch tip an agent session sets** (`docs/HUB.md`
/// §13.27): a move, a forced move, a creation, a recreation after a
/// deletion, by push, by API commit with `onto`, and by any landing to come
/// (S17 calls it too). The tip is compared with the old tip's tree. An
/// agent session never creates or recreates the default branch (BUG-1538:
/// there is nothing to compare with); other new branches decide nothing
/// and are allowed (`None` with `default` false).
///
/// For a narrowed session the first question is whether anything outside
/// its paths changes: it is answered before any other comparison, so the
/// answer never tells what changed there (BUG-1481). Then the files that
/// decide access or review (BUG-1391). `None`: allowed.
pub(crate) fn agent_tip(src: &Source, view: &View, default: bool, cur: Option<ObjectId>, to: ObjectId) -> Result<Option<AgentTip>> {
    if !view.is_agent() {
        return Ok(None);
    }
    let from = match cur {
        Some(c) => src.snapshot(&c)?.tree,
        None if default => return Ok(Some(AgentTip::DefaultBranch)),
        None => return Ok(None),
    };
    let to = src.snapshot(&to)?.tree;
    if view.is_narrowed() && differs_outside_narrowing(&|id| stored_tree(src, id), view, from, to)? {
        return Ok(Some(AgentTip::Narrowed));
    }
    if differs_in_access_files(src, from, to)? {
        return Ok(Some(AgentTip::Access));
    }
    Ok(None)
}

/// [`agent_tip`] for a push or an API commit: off the async runtime.
pub(crate) async fn agent_tip_of(
    hub: &Arc<Hub>,
    project: &Project,
    viewer: &Viewer,
    branch: &str,
    cur: Option<ObjectId>,
    to: ObjectId,
    pending: HashMap<ObjectId, Bytes>,
) -> Result<Option<AgentTip>> {
    agent_tip_of_in(hub, project, viewer, branch, cur, to, pending, None).await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn agent_tip_of_in(
    hub: &Arc<Hub>,
    project: &Project,
    viewer: &Viewer,
    branch: &str,
    cur: Option<ObjectId>,
    to: ObjectId,
    pending: HashMap<ObjectId, Bytes>,
    staged: Option<Arc<Staged>>,
) -> Result<Option<AgentTip>> {
    if !viewer.agent {
        return Ok(None);
    }
    let (v, text, bindings) = (viewer.clone(), project.policy_text.clone(), project.bindings.clone());
    let default = branch == project.default_branch;
    blocking_in(hub, project.id, pending, staged, move |src| {
        let p = Project {
            id: src.project,
            name: String::new(),
            default_branch: String::new(),
            policy: AccessPolicy::parse(&text),
            policy_text: String::new(),
            bindings,
        };
        agent_tip(src, &p.view(&v), default, cur, to)
    })
    .await
}

/// **The first check of every write a narrowed session makes** (a pushed
/// snapshot, an API commit's snapshot, a merge, a landing), before the
/// graft or any other step: outside its paths, the tree it sends (`pushed`,
/// in its person's view) must equal **every** parent's content as its
/// person sees it (`parents`: their real trees, projected here), so it
/// neither writes there nor decides how changes there merge (BUG-1539,
/// BUG-1540). One answer, naming nothing ([`NARROWED_WRITE`]). A tree it
/// did not send reads as none. Anyone else passes.
pub(crate) fn narrowing_gate(src: &Source, view: &View, pushed: ObjectId, parents: &[ObjectId]) -> Result<()> {
    if !view.is_narrowed() {
        return Ok(());
    }
    for t in parents {
        let mut pr = Projector::new(src, view);
        let seen = pr.root(*t)?;
        let made = pr.created;
        let get = |id: &ObjectId| -> veil_core::Result<Option<Arc<Tree>>> {
            if let Some((t, _)) = made.get(id) {
                return Ok(Some(t.clone()));
            }
            src.present_tree(id)
        };
        if differs_outside_narrowing(&get, view, seen, pushed)? {
            return Err(agent_refusal(NARROWED_WRITE));
        }
    }
    Ok(())
}

/// What a narrowed session is told when it would write outside its paths:
/// it names nothing there (BUG-1392).
pub(crate) const NARROWED_WRITE: &str = "this agent session is narrowed: this would change files outside its paths";

/// What an agent session is told when a branch move would land a change of
/// a file that decides access or review (BUG-1391).
pub(crate) const AGENT_ACCESS_MOVE: &str =
    "an agent session never moves a branch onto a change of a file that decides access or review (.veilpolicy, .veilrules)";

/// Names of personal private keys: never accepted, sealed or not
/// (`docs/VISIBILITY.md`, "Personal private keys never leave your machine").
fn personal_key(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    matches!(name.as_str(), "id_rsa" | "id_dsa" | "id_ecdsa" | "id_ed25519")
}

/// The text of the `.veilpolicy` at the root of real tree `tree`.
pub(crate) fn policy_text(src: &Source, tree: &ObjectId) -> Result<String> {
    let Node::Tree(t, _) = src.node(tree).map_err(Error::client_object)? else {
        return Ok(String::new());
    };
    let Some(e) = t.get(POLICY_FILE) else {
        return Ok(String::new());
    };
    match src.decode(&e.id).map_err(Error::client_object)? {
        Object::Blob(b) if e.kind == EntryKind::File => Ok(String::from_utf8_lossy(&b).into_owned()),
        _ => Err(Error::forbidden(".veilpolicy must be a plain-text file")),
    }
}

/// The entry at `path` in real tree `tree`.
pub(crate) fn entry_at(src: &Source, tree: &ObjectId, path: &str) -> Result<Option<veil_core::TreeEntry>> {
    let mut cur = *tree;
    let parts: Vec<&str> = path.split('/').collect();
    for (i, part) in parts.iter().enumerate() {
        let Node::Tree(t, _) = src.node(&cur).map_err(Error::client_object)? else {
            return Ok(None);
        };
        let Some(e) = t.get(part) else {
            return Ok(None);
        };
        if i + 1 == parts.len() {
            return Ok(Some(e.clone()));
        }
        cur = e.id;
    }
    Ok(None)
}

/// Every object entry `e` names: its object and, for a conflict, its
/// terms' objects (what `fetch` serves at its path).
pub(crate) fn named_ids(src: &Source, e: &veil_core::TreeEntry) -> Result<Vec<ObjectId>> {
    let mut out = vec![e.id];
    if e.kind == EntryKind::Conflict {
        if let Object::Conflict(c) = src.decode(&e.id).map_err(Error::client_object)? {
            out.extend(c.referenced_ids());
        }
    }
    Ok(out)
}

/// The most snapshots not derived yet that one push's merge checks read
/// (the push's own, or the derive workers' lag) before they answer busy
/// (BUG-1425: the snapshots read are counted, not the rows made, over
/// the whole push).
const UNDERIVED_ROWS: usize = 100_000;

/// The graph rows one push's checks compute (BUG-1425): one set for the
/// whole push. `complete` adds each accepted snapshot's row, and
/// `merge_bases` keeps the rows its walk makes, so a later merge's walk
/// stops at the push's earlier snapshots and at anything an earlier walk
/// gave a row, instead of reading every snapshot below it again. `read`
/// counts the snapshots not derived yet that the push has read.
#[derive(Clone, Default)]
pub struct PushRows {
    rows: HashMap<ObjectId, Arc<crate::derive::graph::GraphRow>>,
    /// The push's rows frozen at the start of a parallel guess window, so each
    /// concurrent check reads earlier windows' rows without cloning the map.
    frozen: Option<Arc<HashMap<ObjectId, Arc<crate::derive::graph::GraphRow>>>>,
    read: usize,
    /// No row is kept for an accepted snapshot ([`PushRows::unkept`]).
    unkept: bool,
}

impl PushRows {
    /// Rows for checks whose accepted snapshot is not kept (the landing's
    /// re-check, BUG-2220): `complete` makes no row for it, so it never asks
    /// the database for the row of a parent the batch made a moment ago.
    pub(crate) fn unkept() -> PushRows {
        PushRows { unkept: true, ..PushRows::default() }
    }

    /// A cheap snapshot of the rows so far for a parallel guess window.
    fn freeze(&self) -> PushRows {
        PushRows {
            rows: HashMap::new(),
            frozen: Some(Arc::new(self.rows.clone())),
            read: self.read,
            unkept: self.unkept,
        }
    }

    /// The row of `id`, from this push or the derived graph.
    fn row(&self, src: &Source, id: &ObjectId) -> Result<Option<Arc<crate::derive::graph::GraphRow>>> {
        if let Some(r) = self.rows.get(id) {
            return Ok(Some(r.clone()));
        }
        if let Some(r) = self.frozen.as_ref().and_then(|f| f.get(id)) {
            return Ok(Some(r.clone()));
        }
        if *id == root_snapshot_id() {
            return Ok(Some(Arc::new(crate::derive::graph::GraphRow::root())));
        }
        graph_cx(src).stored_row(id)
    }

    /// Add the row of accepted snapshot `s`, stored as `id`, on real
    /// `parents`, when every parent has a row (otherwise a walk that needs
    /// it makes it).
    fn add(&mut self, src: &Source, id: ObjectId, s: &Snapshot, parents: &[ObjectId]) -> Result<()> {
        if self.unkept {
            return Ok(());
        }
        let mut rows = Vec::with_capacity(parents.len());
        for p in parents {
            match self.row(src, p)? {
                Some(r) => rows.push((*p, r)),
                None => return Ok(()),
            }
        }
        self.rows.insert(id, Arc::new(crate::derive::graph::GraphRow::compute(s, &rows)));
        Ok(())
    }

    /// Add the row of accepted snapshot `s`, stored as `id`, on real
    /// `parents`, when every parent already has a row in `self.rows` (or is the
    /// root), without touching the database (safe on an async thread).
    fn add_in_memory(&mut self, id: ObjectId, s: &Snapshot, parents: &[ObjectId]) {
        if self.rows.contains_key(&id) {
            return;
        }
        let mut rows = Vec::with_capacity(parents.len());
        for p in parents {
            let r = if let Some(r) = self.rows.get(p) {
                r.clone()
            } else if *p == root_snapshot_id() {
                Arc::new(crate::derive::graph::GraphRow::root())
            } else {
                return;
            };
            rows.push((*p, r));
        }
        self.rows.insert(id, Arc::new(crate::derive::graph::GraphRow::compute(s, &rows)));
    }
}

/// A derive context on `src`'s project for graph rows (no pending
/// objects: rows come from the database, the snapshots from `src`).
fn graph_cx(src: &Source) -> crate::derive::Cx {
    crate::derive::Cx {
        src: Source { hub: src.hub.clone(), project: src.project, rt: src.rt.clone(), pending: HashMap::new(), staged: None },
    }
}

/// The merge bases of real snapshots `a` and `b`: their best common
/// ancestors, none an ancestor of another (BUG-1327; several after a
/// criss-cross merge), by the derived commit graph (`derive::graph`, paint
/// down by generation). Snapshots not derived yet (this push's own, or the
/// derive workers' lag) get their rows computed here first, kept in `rows`
/// for the rest of the push (BUG-1425); past [`UNDERIVED_ROWS`] snapshots
/// read, the push is answered busy rather than left to run on.
fn merge_bases(src: &Source, rows: &mut PushRows, a: ObjectId, b: ObjectId) -> Result<Vec<ObjectId>> {
    use crate::derive::graph::{Graph, GraphRow};
    let cx = graph_cx(src);
    let mut g = Graph::new(&cx);
    if let Some(f) = &rows.frozen {
        g.pending.extend(f.iter().map(|(k, v)| (*k, v.clone())));
    }
    g.pending.extend(std::mem::take(&mut rows.rows));
    let walked = (|| -> Result<Vec<ObjectId>> {
        for tip in [a, b] {
            // Depth first, parents before their child; a snapshot is read
            // once (it travels with its stack entry) and gets its row when
            // it is reached again with its parents' rows made.
            let mut stack: Vec<(ObjectId, Option<Arc<Snapshot>>)> = vec![(tip, None)];
            while let Some((x, read)) = stack.pop() {
                match read {
                    None => {
                        if g.row(&x)?.is_some() {
                            continue;
                        }
                        rows.read += 1;
                        if rows.read > UNDERIVED_ROWS {
                            return Err(Error::busy());
                        }
                        let s = src.snapshot(&x)?;
                        stack.push((x, Some(s.clone())));
                        stack.extend(s.parents.iter().map(|p| (*p, None)));
                    }
                    Some(s) => {
                        if g.pending.contains_key(&x) {
                            continue;
                        }
                        let parents: Vec<(ObjectId, Arc<GraphRow>)> = s.parents.iter().map(|p| Ok((*p, g.get(p)?))).collect::<Result<_>>()?;
                        g.pending.insert(x, Arc::new(GraphRow::compute(&s, &parents)));
                    }
                }
            }
        }
        g.merge_bases(a, b)
    })();
    rows.rows = std::mem::take(&mut g.pending);
    walked
}

/// Did parent `i`'s side make version `new` of `path`, against parent `j`:
/// does `i` have it and no merge base of `i` and `j` (each pair's bases
/// found once per merge, BUG-1329) have it?
struct Sides<'a> {
    src: &'a Source,
    rows: &'a mut PushRows,
    parents: &'a [ObjectId],
    trees: Vec<ObjectId>,
    bases: HashMap<(usize, usize), Vec<ObjectId>>,
}

impl<'a> Sides<'a> {
    fn new(src: &'a Source, rows: &'a mut PushRows, parents: &'a [ObjectId]) -> Result<Sides<'a>> {
        let trees = parents.iter().map(|p| Ok(src.snapshot(p)?.tree)).collect::<Result<_>>()?;
        Ok(Sides { src, rows, parents, trees, bases: HashMap::new() })
    }

    fn made(&mut self, i: usize, j: usize, path: &str, new: &Option<veil_core::TreeEntry>) -> Result<bool> {
        if entry_at(self.src, &self.trees[i], path)? != *new {
            return Ok(false);
        }
        let k = (i.min(j), i.max(j));
        if !self.bases.contains_key(&k) {
            let mut trees = Vec::new();
            for b in merge_bases(self.src, self.rows, self.parents[k.0], self.parents[k.1])? {
                trees.push(self.src.snapshot(&b)?.tree);
            }
            self.bases.insert(k, trees);
        }
        for t in &self.bases[&k] {
            if entry_at(self.src, t, path)? == *new {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// Check the paths one snapshot changes: write access, personal keys,
/// secrets sealed, nothing local-only, no secret in a plain-text file
/// (`docs/HUB.md` §4.5, checks 2, 8 and 9). `parents` are the snapshot's
/// real parents; `accepted` is the project's accepted `.veilpolicy`;
/// `rows` are the push's graph rows (BUG-1425).
#[allow(clippy::too_many_arguments)]
fn check_changes(
    src: &Source,
    rows: &mut PushRows,
    view: &View,
    changes: &[Change],
    real_tree: &ObjectId,
    parents: &[ObjectId],
    accepted: &Policy,
    admin: bool,
) -> Result<()> {
    let text = policy_text(src, real_tree)?;
    let policy = Policy::parse(&text);
    // A merge's other parents: their trees, and the tree of a common
    // ancestor with the first parent (found when first needed).
    let mut sides = Sides::new(src, rows, parents)?;
    // A merge checked against every parent, not only the first (BUG-1321,
    // BUG-820's class): a path where it differs from another parent `j`,
    // and not from the first (those are `changes`, below), keeps the first
    // parent's version over `j`'s. That is a write, unless some other
    // parent `i`'s side made that version since their merge bases (taking a
    // change someone who could write it made).
    for j in 1..parents.len() {
        let (differ, _) = crate::derive::changes::diff(src, sides.trees[j], *real_tree)?;
        for c in differ {
            if view.write(&c.path) || changes.iter().any(|x| x.path == c.path) {
                continue;
            }
            let mut taken = false;
            for i in 0..parents.len() {
                if i != j && sides.made(i, j, &c.path, &c.new)? {
                    taken = true;
                    break;
                }
            }
            if !taken {
                return Err(Error::forbidden(format!("you may not write '{}'", c.path)));
            }
        }
    }
    for c in changes {
        // (A narrowed session's changes outside its paths never get here:
        // `narrowing_gate` refused them first, naming nothing; every refusal
        // below names its path.)
        // Taken from another parent of a merge, where that parent's side
        // changed it since their merge bases: the merge takes a change
        // someone who could write it made. Taking the version the first
        // parent replaced is a revert, a write like any other.
        let mut from_other = false;
        if !view.write(&c.path) {
            for i in 1..parents.len() {
                if sides.made(i, 0, &c.path, &c.new)? {
                    from_other = true;
                    break;
                }
            }
        }
        // Not even by taking someone else's change in a merge (BUG-1377).
        if view.is_agent() && veil_core::hub::agent::decides_access(&c.path) {
            return Err(agent_refusal(&format!("an agent session never changes '{}', which decides access or review", c.path)));
        }
        if !view.write(&c.path) && !from_other {
            return Err(Error::forbidden(format!("you may not write '{}'", c.path)));
        }
        let Some(e) = &c.new else { continue };
        if personal_key(&c.path) {
            return Err(Error::forbidden(format!(
                "'{}' is a personal private key: it never leaves your device",
                c.path
            )));
        }
        // The content to check: a file's or link's blob, or each term of a
        // conflict, with its label (BUG-931).
        let contents: Vec<(ObjectId, Visibility, u64)> = match e.kind {
            k if k.holds_blob() => vec![(e.id, e.visibility.clone(), e.size)],
            EntryKind::Conflict => match src.decode(&e.id).map_err(Error::client_object)? {
                Object::Conflict(cf) => cf.adds.iter().chain(&cf.removes).flatten().map(|t| (t.id, t.visibility.clone(), t.size)).collect(),
                _ => return Err(Error::bad_request(format!("'{}': a conflict entry names something else", c.path))),
            },
            // A directory entry that is itself a change (its object could
            // not be walked as a directory) names a tree (BUG-2622).
            EntryKind::Dir => {
                if !matches!(src.decode(&e.id).map_err(Error::client_object)?, Object::Tree(_)) {
                    return Err(Error::bad_request(format!("'{}': a directory entry names something that is not a directory", c.path)));
                }
                continue;
            }
            _ => continue,
        };
        let vp = VPath::new(&c.path).map_err(|_| Error::bad_request(format!("invalid path '{}'", c.path)))?;
        let class = policy.classify(&vp, false);
        // Check 9 (below) is off only where `public!` says so in the
        // accepted policy (an admin's), or in an admin's own change: anyone
        // may turn `public` into `public!`, which is the same access.
        let unscanned = class.allow_secrets && (admin || accepted.classify(&vp, false).allow_secrets);
        for (id, visibility, size) in contents {
            let raw = src.raw(&id).map_err(Error::client_object)?;
            // What a file or symlink entry, or a conflict's term, names is
            // a file's content: a blob, or a secret's sealed envelope
            // (BUG-2622). Pack GC keeps it as a leaf without reading it, so
            // a directory's tree named there was never walked where a
            // directory entry named it too, and the directory's files were
            // deleted as unreferenced. (The object is one the pusher
            // uploaded, or the entry's at this path in a parent: the
            // answer tells them nothing they do not hold.)
            if !(Object::is_blob_raw(&raw) || Object::sealed_scope(&raw).is_some()) {
                return Err(Error::bad_request(format!("'{}': a file entry names something that is not a file's content", c.path)));
            }
            // The size an entry records bounds what reading its object
            // holds (`store::Objects::read_cost`, BUG-1087).
            if raw.len() as u64 > size.saturating_add(crate::store::SIZE_SLACK) {
                return Err(Error::bad_request(format!(
                    "'{}': its entry records {size} bytes, less than its content holds",
                    c.path
                )));
            }
            let sealed = Object::sealed_scope(&raw).is_some();
            match class.tier {
                Tier::Isolated | Tier::Ignored => {
                    return Err(Error::forbidden(format!(
                        "'{}' stays on the device by the project's policy (a secret or ignored file)",
                        c.path
                    )))
                }
                Tier::Cloaked(_) if !sealed || !matches!(visibility, Visibility::Cloaked { .. }) => {
                    return Err(Error::forbidden(format!("'{}' is a secret and must arrive encrypted", c.path)))
                }
                // Format 8: only secret files are encrypted, by the rule `vl`
                // seals by and `vl upgrade` checks (BUG-1055): a secret's
                // path, or content that descends from a secret (a parent's
                // secret at this path, or one of the same scope this
                // snapshot moved away). A secret a policy makes public may
                // also arrive sealed: the member's `vl` keeps the protection
                // they accepted.
                Tier::Public if sealed && !sealed_secret_here(src, c, changes, parents, &visibility)? => {
                    return Err(Error::forbidden(format!("'{}' is not a secret file: only secret files are encrypted", c.path)))
                }
                _ => {}
            }
            // A sealed object under a plain label (or the reverse) is malformed.
            if sealed != matches!(visibility, Visibility::Cloaked { .. }) {
                return Err(Error::bad_request(format!("'{}': the entry's label does not match its object", c.path)));
            }
            // Check 9: the secret scan of every new plain-text file, as `vl`
            // scans before it records one. Findings name the rule and the
            // line, never the text.
            if !sealed && !unscanned {
                if let Object::Blob(data) = src.decode_bytes(&id, &raw).map_err(Error::client_object)? {
                    if let Some(f) = veil_core::secrets::scan(&data).first() {
                        return Err(Error::forbidden(format!(
                            "'{}' looks like it holds a secret ({}, line {}): put secrets in a secret file such as .env, \
                             which Veil encrypts",
                            c.path, f.rule, f.line
                        )));
                    }
                }
            }
        }
    }
    Ok(())
}

/// [`veil_core::policy::sealed_secret`] for sealed content labelled
/// `visibility` at changed path `c`, among `changes` (relative to the first
/// of real `parents`).
///
/// "A parent holds a sealed file at the path" is read as `vl` reads it
/// (`Transaction::reconcile_sealing`, `Builder::protect_moves`,
/// `upgrade::sealed_entries`): a parent's conflict there with a sealed
/// version counts. A conflict entry's own label is always public; its
/// versions carry theirs, each checked by this rule when the conflict was
/// accepted. Otherwise the resolution of a conflict in a renamed secret,
/// recorded as a change of its own, is refused for good (BUG-1930).
fn sealed_secret_here(src: &Source, c: &Change, changes: &[Change], parents: &[ObjectId], visibility: &Visibility) -> Result<bool> {
    let Visibility::Cloaked { scope } = visibility else { return Ok(false) };
    veil_core::policy::sealed_secret(
        &c.path,
        scope,
        false,
        |path| {
            for p in parents {
                let Some(e) = entry_at(src, &src.snapshot(p)?.tree, path)? else { continue };
                let sealed = match e.kind {
                    EntryKind::Conflict => match src.decode(&e.id)? {
                        Object::Conflict(cf) => cf.adds.iter().chain(&cf.removes).flatten().any(|t| !t.visibility.is_public()),
                        _ => false,
                    },
                    _ => !e.visibility.is_public(),
                };
                if sealed {
                    return Ok(true);
                }
            }
            Ok(false)
        },
        |scope| {
            Ok(changes.iter().any(|o| {
                o.new.is_none() && o.old.as_ref().is_some_and(|e| matches!(&e.visibility, Visibility::Cloaked { scope: s } if s == scope))
            }))
        },
    )
}

/// Complete and check new snapshot `n` on its real parents `rp`, for
/// `viewer` (`docs/HUB.md` §4.5): the graft of its tree onto the full
/// tree, a merge that changes nothing the viewer cannot see, closure
/// (every object a changed path names was `uploaded` or is the entry at
/// that path in a parent), checks 2, 8 and 9 ([`check_changes`]) and access
/// lines changed only by admins. Pushes and commits through the API
/// (`changes`) both run it. `p` carries the accepted policy. `ra` are the
/// real ids of `n`'s attempts (format 10), each an abandoned version of the
/// same change; no parent may be one; `rows` are the push's graph rows,
/// which the accepted snapshot joins (BUG-1425).
#[allow(clippy::too_many_arguments)]
pub(crate) fn complete(
    src: &Source,
    p: &Project,
    viewer: &Viewer,
    uploaded: &dyn UploadedSet,
    n: &Snapshot,
    rp: &[ObjectId],
    ra: &[ObjectId],
    identity: &veil_core::Identity,
    rows: &mut PushRows,
) -> Result<Completed> {
    if rp.len() > MAX_PARENTS {
        return Err(Error::bad_request(format!("a snapshot may have at most {MAX_PARENTS} parents")));
    }
    // Attempts never enter ancestry (`Snapshot::abandoned`).
    for p in rp {
        if src.snapshot(p)?.abandoned.is_some() {
            return Err(Error::bad_request("a parent is an abandoned attempt: nothing is built on one"));
        }
    }
    for a in ra {
        let at = src.snapshot(a)?;
        if at.abandoned.is_none() || at.change_id != n.change_id {
            return Err(Error::bad_request("an attempt must be an abandoned version of the same change"));
        }
    }
    let admin = viewer.admin;
    let view = p.view(viewer);
    let ptrees: Vec<ObjectId> = rp.iter().map(|p| Ok(src.snapshot(p)?.tree)).collect::<Result<_>>()?;
    // A narrowed session: anything outside its paths, decided first, on the
    // tree it sent against every parent, before the graft, any comparison,
    // object check or lookup, and answered one way, naming nothing
    // (BUG-1392, BUG-1481, BUG-1539, BUG-1540).
    narrowing_gate(src, &view, n.tree, &ptrees)?;
    let mut g = Graft::new(src, &view).proving(uploaded, ptrees.clone());
    let real_tree = g.root(n.tree, Some(ptrees[0])).map_err(Error::client_object)?;
    // A merge must not change what the pusher cannot see.
    for other in &ptrees[1..] {
        let mut g2 = Graft::new(src, &view).proving(uploaded, ptrees.clone());
        if g2.root(n.tree, Some(*other)).map_err(Error::client_object)? != real_tree && !admin {
            // Compare the hidden parts: the same full tree from either side.
            return Err(Error::forbidden(
                "this merge combines changes in folders you cannot see; ask someone with access to merge it",
            ));
        }
    }
    let mut trees: Vec<(ObjectId, Vec<u8>)> = g.created.drain().collect();
    trees.sort();
    // The trees the graft built, readable before checking (the check reads
    // them): a push's go into its pack once every check passed (S28);
    // anyone else's are stored now.
    let made: Vec<ObjectId> = trees.iter().map(|(id, _)| *id).collect();
    for (id, raw) in trees {
        match &src.staged {
            Some(st) => {
                st.made.lock().unwrap().insert(id, Bytes::from(raw));
            }
            None => src.rt.block_on(src.hub.objects.put(src.project, &id, Bytes::from(raw)))?,
        }
    }
    // Every object a changed path names (its object and conflict
    // terms) was uploaded by the pusher, or is named by the
    // entry at that path in a parent: anything else gets the answer
    // a missing object gets, stored or not (BUG-824, BUG-834).
    for c in &g.changes {
        let Some(e) = &c.new else { continue };
        let mut before = HashSet::new();
        for t in &ptrees {
            if let Some(pe) = entry_at(src, t, &c.path)? {
                before.extend(named_ids(src, &pe)?);
            }
        }
        let known = |id: &ObjectId| uploaded.contains_uploaded(id) || before.contains(id);
        if !known(&e.id) {
            return Err(Error::client_object(VeilError::Missing(e.id)));
        }
        if let Some(id) = named_ids(src, e)?.into_iter().find(|id| !known(id)) {
            return Err(Error::client_object(VeilError::Missing(id)));
        }
    }
    check_changes(src, rows, &view, &g.changes, &real_tree, rp, &Policy::parse(&p.policy_text), admin)?;
    // Access lines: only admins change them.
    let mine = AccessPolicy::parse(&policy_text(src, &real_tree)?);
    let mut unchanged = false;
    for t in &ptrees {
        if AccessPolicy::parse(&policy_text(src, t)?).same_rules(&mine) {
            unchanged = true;
        }
    }
    if !unchanged && !admin {
        return Err(Error::forbidden("only admins may change access lines in .veilpolicy"));
    }
    // Branch rules (`.veilrules`, S17): only admins change them, on any
    // branch, so the default branch's are always an admin's; theirs must
    // parse.
    let rules_at = |t: &ObjectId| entry_at(src, t, crate::landing::rules::RULES_FILE);
    let rules = rules_at(&real_tree)?;
    let mut same_rules = false;
    for t in &ptrees {
        if rules_at(t)?.is_some_and(|e| rules.as_ref().is_some_and(|r| r.same_content(&e))) || (rules.is_none() && rules_at(t)?.is_none()) {
            same_rules = true;
        }
    }
    if !same_rules {
        if !admin {
            return Err(Error::forbidden("only admins may change the branch rules (.veilrules)"));
        }
        if let Some(e) = &rules {
            let text = match src.decode(&e.id).map_err(Error::client_object)? {
                Object::Blob(b) if e.kind == EntryKind::File => String::from_utf8_lossy(&b).into_owned(),
                _ => return Err(Error::bad_request(".veilrules must be a plain-text file")),
            };
            if text.parse::<toml_edit::DocumentMut>().is_ok() || text.contains("branches") {
                crate::landing::rules::Rules::parse(&text).map_err(Error::bad_request)?;
            }
        }
    }
    let mut real = n.clone();
    real.tree = real_tree;
    real.parents = rp.to_vec();
    real.attempts = ra.to_vec();
    if real == *n {
        let id = ObjectId::hash(&Object::Snapshot(real.clone()).encode());
        rows.add(src, id, &real, rp)?;
        return Ok(Completed {
            real: id,
            raw: None,
            origin: None,
            made,
        });
    }
    real.sign(identity);
    let raw = Object::Snapshot(real.clone()).encode();
    let id = ObjectId::hash(&raw);
    rows.add(src, id, &real, rp)?;
    Ok(Completed {
        real: id,
        raw: Some(Bytes::from(raw)),
        origin: None,
        made,
    })
}

/// One new snapshot, completed.
pub(crate) struct Completed {
    pub real: ObjectId,
    pub raw: Option<Bytes>,
    /// The pusher's own snapshot, when the server completed it.
    pub origin: Option<ObjectId>,
    /// The trees the graft built (stored already, unless the source was a
    /// push's: then in its made objects).
    pub made: Vec<ObjectId>,
}

/// Handle a push (`docs/HUB.md` §4.5): complete and check every new
/// snapshot, then move every branch in one transaction of
/// compare-and-swaps, which also lists the packs holding what the push
/// stored and writes the snapshot, origin, projection memo and audit rows:
/// **one database commit per push** (`storage-and-cost.md` §3). Other
/// viewers' projections are worked out when they first ask, as before.
///
/// **What it stores** (S28): the uploads its receipts name are staged packs
/// ([`upload`]). A staged pack every object of which the checks read is
/// listed as it is; the objects the checks read from any other, and the
/// objects the server made (the graft's trees, completed snapshots, the
/// pusher's signed projections), go into one pack of the push's own. So a
/// push costs at most one storage write of its own, and none for a `vl`
/// push's uploads. Staged packs it does not list are discarded once it is
/// answered, landed or refused (BUG-930), except after an error the request
/// may be run again for (a database or store error).
pub async fn push(hub: &Arc<Hub>, project: &Project, viewer: &Viewer, who: &crate::landing::Submitter, req: PushRequest) -> Result<PushResult> {
    Ok(push_with(hub, project, viewer, who, req, false, true).await?.0)
}

/// [`push`]. An update of a protected branch (every update, with
/// `land_all`: `POST …/land` of an uploaded snapshot) is not moved here: the
/// new snapshots it brings join the landing queue, in the push's one
/// commit, as one stack (`landing`), and with `wait` the push answers once
/// they landed. Their outcomes come back too.
pub(crate) async fn push_with(
    hub: &Arc<Hub>,
    project: &Project,
    viewer: &Viewer,
    who: &crate::landing::Submitter,
    req: PushRequest,
    land_all: bool,
    wait: bool,
) -> Result<(PushResult, Vec<veil_core::hub::land::LandResult>)> {
    // In a task of its own: a client that goes away stops the request, not
    // the push, so its clean-up always runs (BUG-1399); and in the push's
    // own scope, so the storage writes it makes are counted as its own
    // (BUG-1398; what it spawns, the deriver and the indexer, are not).
    let (hub2, project, viewer, who) = (hub.clone(), project.clone(), viewer.clone(), who.clone());
    let fut = crate::limits::in_request(hub, crate::store::own(async move {
        push_to_its_end(&hub2, &project, &viewer, &who, req, land_all, wait).await
    }));
    tokio::spawn(fut)
        .await
        .map_err(|e| Error::Other(e.into()))?
}

/// [`push`], to its end.
async fn push_to_its_end(
    hub: &Arc<Hub>,
    project: &Project,
    viewer: &Viewer,
    who: &crate::landing::Submitter,
    mut req: PushRequest,
    land_all: bool,
    wait: bool,
) -> Result<(PushResult, Vec<veil_core::hub::land::LandResult>)> {
    if !project.participant(viewer) {
        return Err(Error::forbidden("you are not in this project"));
    }
    let person = who.person.id;
    let req_packs = std::mem::take(&mut req.packs);
    // The receipts (a long history's are tens of megabytes) are not held
    // through the checks once read.
    let receipts = std::mem::take(&mut req.receipts);
    if !req_packs.is_empty() && !receipts.is_empty() {
        return Err(Error::bad_request("a push names either `packs` or `receipts`, not both"));
    }
    let (st, owned_names) = if !req_packs.is_empty() {
        drop(receipts);
        let (st, owned) = staging_packs(hub, project.id, person, req_packs).await?;
        (Arc::new(st), owned)
    } else {
        let staged = receipted(hub, project.id, person, &receipts);
        drop(receipts);
        let mut receipt_names: Vec<Arc<str>> = staged.values().cloned().collect();
        receipt_names.sort();
        receipt_names.dedup();
        let st = match staging(hub, project.id, person, &staged).await {
            Ok(st) => Arc::new(st),
            Err(e) => {
                hub.objects.release_recent(project.id, person, &receipt_names);
                return Err(e);
            }
        };
        drop(staged);
        (st, receipt_names)
    };
    let progress = Mutex::new(Progress::default());
    let r = push_staged(hub, project, viewer, who, req, land_all, wait, st, &progress).await;
    let p = progress.into_inner().unwrap();
    match &r {
        Ok((_, _, Some(kept))) => {
            let unkept: Vec<Arc<str>> = owned_names.into_iter().filter(|n| !kept.contains(n)).collect();
            if let Err(e) = hub.objects.discard_consumed(project.id, &unkept).await {
                eprintln!("veil-server: discarding what a push did not list: {e:#}");
            }
        }
        Ok((_, _, None)) => {
            hub.objects.release_recent(project.id, person, &owned_names);
        }
        Err(Error::Api { status, .. }) if !p.transaction && is_check_refusal(*status) => {
            if let Err(e) = hub.objects.discard_refused(project.id, &owned_names).await {
                eprintln!("veil-server: discarding what a refused push uploaded: {e:#}");
            }
        }
        Err(_) => {
            hub.objects.release_recent(project.id, person, &owned_names);
        }
    }
    r.map(|(res, landings, _)| (res, landings))
}

/// Whether a push's transaction began.
#[derive(Default)]
pub(crate) struct Progress {
    pub(crate) transaction: bool,
}

/// One new snapshot completed, what its checks read of the uploads, and its
/// graph rows.
type Checked = (Completed, HashSet<ObjectId>, PushRows);

/// How many new snapshots a push checks at once (BUG-865).
const CHECKS_AT_ONCE: usize = 8;
/// How many it checks ahead on a guess, a window at a time.
const GUESS_WINDOW: usize = 64;

/// [`push`] with its uploads read: the result and the packs it listed
/// (`None` if nothing landed). `progress`: what it wrote, how far it got.
#[allow(clippy::too_many_arguments)]
async fn push_staged(
    hub: &Arc<Hub>,
    project: &Project,
    viewer: &Viewer,
    who: &crate::landing::Submitter,
    mut req: PushRequest,
    land_all: bool,
    wait: bool,
    st: Arc<Staged>,
    progress: &Mutex<Progress>,
) -> Result<(PushResult, Vec<veil_core::hub::land::LandResult>, Option<HashSet<Arc<str>>>)> {
    let person = who.person.id;
    if !project.participant(viewer) {
        return Err(Error::forbidden("you are not in this project"));
    }
    if req.force && !viewer.admin {
        return Err(Error::forbidden("only admins may force a branch move"));
    }
    if req.force && viewer.agent {
        return Err(agent_refusal("an agent session never forces a branch move"));
    }
    let gc_epoch = crate::pack_gc::push_gc_epoch(hub, project.id, who.epochs.gc).await?;
    if req.updates.len() > MAX_PUSH_UPDATES {
        return Err(Error::bad_request(format!("at most {MAX_PUSH_UPDATES} branch updates per push")));
    }
    let root = root_snapshot_id();
    // Current tips (always from the database: a push never trusts a cache),
    // to pick which real snapshot a projected parent stands for (the
    // branch's tip when it projects to it): of the branches it moves and the
    // default branch only, read once for the push and its resolutions
    // (`resolve_for_in`), never every branch of the project.
    let mut tip_names: Vec<String> = req.updates.iter().map(|u| u.branch.clone()).collect();
    tip_names.push(project.default_branch.clone());
    tip_names.sort();
    tip_names.dedup();
    let (current_rows, tips_embargo_free) = branch_rows_unembargoed(hub, project.id, &tip_names).await?;
    let mut current: HashMap<String, ObjectId> =
        current_rows.iter().filter_map(|(n, t)| ObjectId::from_hex(t).ok().map(|t| (n.clone(), t))).collect();
    // An agent session never creates or recreates the default branch
    // (BUG-1538): decided before anything else of the push, so the answer is
    // one, whatever the snapshots hold. (`agent_tip` says the same for any
    // later route.)
    if viewer.agent && req.updates.iter().any(|u| u.branch == project.default_branch && u.new.is_some() && !current.contains_key(&u.branch)) {
        return Err(agent_refusal(AGENT_DEFAULT_BRANCH));
    }
    // Branches only the landing service moves (S17).
    let protected = {
        let default_tip = current.get(&project.default_branch).copied();
        blocking(hub, project.id, move |src| crate::landing::protected(src, default_tip)).await?
    };
    // The branches this push moves come first, then the default branch
    // (`resolve_for`: one resolution for a push and an API commit).
    let moved_names: Vec<String> = req.updates.iter().map(|u| u.branch.clone()).collect();
    let moved_refs: Vec<&str> = moved_names.iter().map(|s| s.as_str()).collect();
    // Every update lands through the landing service (its edits on the tip),
    // none moves a branch here.
    let lands_only = !req.force && req.updates.iter().all(|u| land_all || protected.contains(&u.branch));
    // What this pusher uploaded (BUG-824): only that may be new here; any
    // other name is "not uploaded", whether or not the server holds a
    // snapshot by it they cannot see (BUG-1523).
    // 1. The new snapshots: everything the new tips reach that the server
    //    does not hold as history or as a projection.
    let mut known: HashMap<ObjectId, Vec<ObjectId>> = HashMap::new();
    let mut new: Vec<ObjectId> = Vec::new();
    let mut parents_of: HashMap<ObjectId, Arc<Snapshot>> = HashMap::new();
    let mut stack: Vec<ObjectId> = req.updates.iter().filter_map(|u| u.new).collect();
    while let Some(id) = stack.pop() {
        if known.contains_key(&id) || parents_of.contains_key(&id) {
            continue;
        }
        // Grafted only on what its pusher saw (BUG-1467, BUG-1520).
        if id == root {
            known.insert(id, vec![root]);
            continue;
        }
        if let Some(r) = resolve_for_in(hub, project, viewer, &id, &moved_refs, lands_only, &current_rows, tips_embargo_free).await? {
            known.insert(id, vec![r]);
            continue;
        }
        if !st.contains_uploaded(&id) {
            return Err(Error::bad_request(format!("snapshot {} was not uploaded", id.short())));
        }
        let s = blocking_staged(hub, project.id, Some(st.clone()), move |src| match src.snapshot(&id) {
            Err(VeilError::Missing(_)) => Err(Error::bad_request(format!("snapshot {} was not uploaded", id.short()))),
            Err(e) => Err(Error::client_object(e)),
            Ok(s) => Ok(s),
        })
        .await?;
        // Its attempts (format 10) are pushed with it, before it.
        stack.extend(s.parents.iter().chain(&s.attempts).copied());
        parents_of.insert(id, s);
        new.push(id);
        if new.len() > MAX_PUSH_SNAPSHOTS {
            return Err(Error::bad_request("too many new snapshots in one push"));
        }
    }
    // Parents first.
    let mut order = Vec::new();
    {
        let mut placed = HashSet::new();
        let mut todo: Vec<(ObjectId, bool)> = new.iter().map(|id| (*id, false)).collect();
        while let Some((id, expanded)) = todo.pop() {
            if placed.contains(&id) || !parents_of.contains_key(&id) {
                continue;
            }
            if expanded {
                placed.insert(id);
                order.push(id);
            } else {
                todo.push((id, true));
                for p in parents_of[&id].parents.iter().chain(&parents_of[&id].attempts) {
                    todo.push((*p, false));
                }
            }
        }
    }
    // The keys that signed the new snapshots, and which of them are
    // registered, confirmed devices (now, from the database).
    let keys: Vec<String> = {
        let mut k: Vec<String> = parents_of.values().filter_map(|n| n.signature.as_ref().map(|s| s.key.clone())).collect();
        k.sort();
        k.dedup();
        k
    };
    // Read with them: whether the project has any unreleased embargo line.
    // After every resolution above, so each snapshot the push names was
    // committed when this was read; with none, every embargo check below
    // (`active_embargoes_of`, which reads the unreleased lines first and
    // answers nothing without one) answers nothing as of this one read.
    let (signers, embargoes): (HashMap<String, i64>, bool) = {
        let rows: Vec<(Option<String>, Option<i64>, bool)> = sqlx::query_as(
            "SELECT d.signing_key, d.person_id, e.active \
             FROM (SELECT EXISTS (SELECT 1 FROM embargo_lines WHERE project_id = $2 AND released_at IS NULL) AS active) e \
             LEFT JOIN devices d ON d.signing_key = ANY($1) AND d.removed_at IS NULL AND NOT d.pending",
        )
        .bind(&keys)
        .bind(project.id)
        .fetch_all(&hub.db)
        .await?;
        let embargoes = rows.iter().any(|r| r.2);
        (rows.into_iter().filter_map(|(k, p, _)| Some((k?, p?))).collect(), embargoes)
    };
    let mut real_of: HashMap<ObjectId, ObjectId> = HashMap::new();
    real_of.insert(root, root);
    for (id, reals) in &known {
        let r = reals[0];
        real_of.insert(*id, r);
    }
    // Validate embargoes (`req.embargoes` and `n.embargo`) and divert embargoed
    // branch updates to their hidden `embargo/<id>` line (S22).
    let (embargo_upserts, embargo_releases, embargo_diverted) =
        crate::embargo::prepare_push(hub, project, viewer, &who.person.device_key, &mut req, &parents_of, &order, &real_of, Some(st.clone()), !land_all, embargoes)
            .await?;
    // An update diverted to its embargo's hidden line (`embargo/<id>`) moves
    // a branch not read above.
    let diverted: Vec<String> = req.updates.iter().filter(|u| !tip_names.contains(&u.branch)).map(|u| u.branch.clone()).collect();
    if !diverted.is_empty() {
        for (n, t) in branch_rows(hub, project.id, &diverted).await? {
            if let Ok(t) = ObjectId::from_hex(&t) {
                current.insert(n, t);
            }
        }
    }
    let current = current;
    // How many branches the project has, asked only when the push creates one.
    let mut branch_count: Option<usize> = None;
    // What the walk read of the uploads (the new snapshots).
    let mut touched = st.touched();
    // 2. Complete and check each new snapshot, parents first. BUG-865:
    //    several at once, on the guess that each new parent is completed to
    //    itself (its real id is its own): a right guess gives exactly the
    //    answer of checking one at a time (the same inputs), and a wrong one
    //    is checked again, in order. Results and the first error are taken
    //    in order, as one at a time.
    let mut completed: Vec<Completed> = Vec::new();
    // Each new real snapshot's real parents and signer (`people.id`).
    let mut real_parents_of: HashMap<ObjectId, (Vec<ObjectId>, i64)> = HashMap::new();
    let mut real_attempts_of: HashMap<ObjectId, Vec<ObjectId>> = HashMap::new();
    let mut made: Vec<ObjectId> = Vec::new();
    // The graph rows of this push's snapshots, carried from one check to
    // the next (BUG-1425). Each parallel window reads a frozen view of the
    // rows from earlier windows (`rows.freeze()`), and any guessed check
    // whose `merge_bases` walk had to read un-derived ancestors (such as an
    // in-window parent not yet in `rows`) is treated as a wrong guess and
    // recomputed sequentially with the up-to-date `rows`.
    let mut rows = PushRows::default();
    type Guess = (Vec<ObjectId>, Vec<ObjectId>, Result<Checked>);
    let mut guessing = true;
    for window in order.chunks(GUESS_WINDOW) {
        let mut guesses: HashMap<ObjectId, Guess> = HashMap::new();
        if guessing && window.len() > 1 {
            let frozen_rows = rows.freeze();
            let mut set = tokio::task::JoinSet::new();
            let mut it = window.iter();
            loop {
                while set.len() < CHECKS_AT_ONCE {
                    let Some(id) = it.next() else { break };
                    let n = parents_of[id].clone();
                    if precheck(id, &n, &signers).is_err() {
                        continue;
                    }
                    let rp: Vec<ObjectId> = n.parents.iter().map(|p| real_of.get(p).copied().unwrap_or(*p)).collect();
                    let ra: Vec<ObjectId> = n.attempts.iter().map(|a| real_of.get(a).copied().unwrap_or(*a)).collect();
                    let job = complete_one(
                        hub.clone(),
                        project.clone(),
                        viewer.clone(),
                        st.child(),
                        n,
                        rp.clone(),
                        ra.clone(),
                        frozen_rows.clone(),
                    );
                    let id = *id;
                    set.spawn(async move { (id, rp, ra, job.await) });
                }
                match set.join_next().await {
                    Some(Ok((id, rp, ra, r))) => {
                        guesses.insert(id, (rp, ra, r));
                    }
                    Some(Err(e)) => return Err(Error::Other(e.into())),
                    None => break,
                }
            }
        }
        let mut wrong = 0;
        for id in window {
            let n = parents_of[id].clone();
            let author = precheck(id, &n, &signers)?;
            let real_parents: Vec<ObjectId> = n.parents.iter().map(|p| real_of[p]).collect();
            let real_attempts: Vec<ObjectId> = n
                .attempts
                .iter()
                .map(|a| real_of.get(a).copied().ok_or_else(|| Error::bad_request("an attempt is not a snapshot of this project")))
                .collect::<Result<_>>()?;
            let (c, read) = match guesses.remove(id) {
                Some((rp, ra, Ok((c, read, back))))
                    if rp == real_parents && ra == real_attempts && back.read == rows.read =>
                {
                    rows.rows.extend(back.rows);
                    rows.add_in_memory(c.real, &n, &real_parents);
                    (c, read)
                }
                Some((rp, ra, Err(e)))
                    if rp == real_parents && ra == real_attempts && n.parents.len() <= 1 =>
                {
                    return Err(e);
                }
                g => {
                    wrong += usize::from(g.is_some());
                    let (c, read, back) = complete_one(
                        hub.clone(),
                        project.clone(),
                        viewer.clone(),
                        st.child(),
                        n,
                        real_parents.clone(),
                        real_attempts.clone(),
                        rows,
                    )
                    .await?;
                    rows = back;
                    (c, read)
                }
            };
            let c = Completed {
                origin: c.raw.as_ref().map(|_| *id),
                ..c
            };
            touched.extend(read);
            made.extend(c.made.iter().copied());
            if let Some(raw) = &c.raw {
                st.made.lock().unwrap().insert(c.real, raw.clone());
                made.push(c.real);
            }
            real_of.insert(*id, c.real);
            // What its landing records: its parents and author (S17, BUG-1581);
            // its attempts (S11) are recorded with it, but are no branch's
            // history: kept apart, so that no attempt counts as landed.
            real_parents_of.insert(c.real, (real_parents, author));
            real_attempts_of.insert(c.real, real_attempts);
            completed.push(c);
        }
        // Mostly wrong (a pusher who cannot see everything: the server
        // completes each snapshot): one at a time from here.
        if wrong * 2 > window.len() {
            guessing = false;
        }
    }
    // 3. Move the branches: one serialisable transaction of compare-and-swaps.
    let mut plans = Vec::new();
    let mut queued: Vec<crate::landing::Queued> = Vec::new();
    let mut results = Vec::new();
    // The review rules a landing on the default branch brings (S21,
    // `prs::state`): recorded in this push's transaction.
    let mut rules_landing: Option<crate::prs::state::Landing> = None;
    // The default branch, for the deletions of merged branches (BUG-1885):
    // read once a push, its lineage checked again where the branch goes.
    let mut default_anc: Option<(ObjectId, i64, crate::landing::Ancestry)> = None;
    // New branches, against the branches when the push began (concurrent
    // pushes may each add up to the bound; deletions in the push free slots at once).
    let created: HashSet<&str> = req.updates.iter().filter(|u| u.new.is_some() && !current.contains_key(&u.branch)).map(|u| u.branch.as_str()).collect();
    let deleting: HashSet<&str> = req.updates.iter().filter(|u| u.new.is_none() && current.contains_key(&u.branch)).map(|u| u.branch.as_str()).collect();
    if !created.is_empty() && count_branches(hub, project.id, &mut branch_count).await?.saturating_sub(deleting.len()) + created.len() > MAX_BRANCHES {
        return Err(Error::bad_request(format!("a project has at most {MAX_BRANCHES} branches")));
    }
    for u in &req.updates {
        if veil_core::commands::validate_tag_name(&u.branch).is_err() {
            return Err(Error::bad_request(format!("invalid branch name {:?}", u.branch)));
        }
        let cur = current.get(&u.branch).copied();
        let new_real = match u.new {
            Some(n) => Some(*real_of.get(&n).ok_or_else(|| Error::bad_request("unknown new tip"))?),
            None => None,
        };
        if let Some(n) = new_real {
            // An attempt never lands (`Snapshot::abandoned`).
            if blocking_staged(hub, project.id, Some(st.clone()), move |src| Ok(src.snapshot(&n)?.abandoned.is_some())).await? {
                return Err(Error::bad_request(format!("branch '{}': an abandoned attempt is never a branch's tip", u.branch)));
            }
        }
        let is_embargo_branch = veil_core::embargo::embargo_id_of_branch(&u.branch).is_some();
        let rev_twice_branch = !is_embargo_branch
            && !req.force
            && !land_all
            && !protected.contains(&u.branch)
            && cur.is_some()
            && crate::bisect::branch_has_reverted_twice(hub, project.id, &u.branch).await?;
        // Landed by the landing service instead of moved here: the new
        // changes on top of whatever base they have (they need not be on
        // the tip), as one stack. Hidden embargo lines (`embargo/<id>`) move
        // directly by CAS and land on their target branch at release.
        if !is_embargo_branch && !req.force && (land_all || protected.contains(&u.branch) || rev_twice_branch) && (cur.is_some() || land_all) {
            let Some(new_real) = new_real else {
                return Err(Error::forbidden(format!("'{}' is protected: only an admin's forced push deletes it", u.branch)));
            };
            let refuse = |m: &str| BranchResult {
                branch: u.branch.clone(),
                ok: false,
                message: Some(m.to_string()),
                tip: None,
                ticket: None,
            };
            if cur.is_none() {
                results.push(refuse(&format!("there is no branch '{}' to land on", u.branch)));
                continue;
            }
            if Some(new_real) == cur {
                results.push(BranchResult { tip: Some(projected(hub, project, viewer, new_real).await?), ok: true, message: None, ..refuse("") });
                continue;
            }
            // Every change between the branch's tip and the pushed one: what
            // this push brought, and what the server already held (BUG-1103).
            let judged = match crate::landing::stack(hub, project, viewer, &u.branch, new_real, &real_parents_of, Some(st.clone())).await? {
                Ok(s) if !s.branch => {
                    results.push(refuse(&format!("there is no branch '{}' to land on", u.branch)));
                    continue;
                }
                Ok(s) => s,
                Err(why) => {
                    results.push(refuse(&why));
                    continue;
                }
            };
            // S11's agent rule (`agent_tip`) on the stack's edits before the
            // landing is queued (BUG-1636).
            if let Some(msg) = crate::landing::agent_stack(hub, project, viewer, &u.branch, &judged, new_real, !land_all, Some(st.clone())).await? {
                let cur_seen = match cur {
                    Some(c) => Some(projected(hub, project, viewer, c).await?),
                    None => None,
                };
                results.push(BranchResult {
                    branch: u.branch.clone(),
                    ok: false,
                    message: Some(msg.into()),
                    tip: cur_seen,
                    ticket: None,
                });
                continue;
            }
            if judged.stack.is_empty() {
                let mut msg = crate::landing::NOTHING_TO_LAND.to_string();
                let skipped = crate::landing::skipped_warnings(hub, project.id, &u.branch, &judged.skipped, None).await?;
                if !skipped.is_empty() {
                    msg = format!("{msg}; {}", skipped.join("; "));
                }
                results.push(refuse(&msg));
                continue;
            }
            if judged.stack.iter().any(|e| parents_of.iter().any(|(pid, n)| real_of.get(pid) == Some(&e.id) && !n.conflicts.is_empty())) {
                results.push(refuse("a change with unresolved conflicts never lands: resolve them first"));
                continue;
            }
            let mut stack = judged.stack;
            match crate::prs::check_landing_review(
                hub,
                project,
                viewer,
                &u.branch,
                &stack,
                Some(st.clone()),
                protected.contains(&u.branch),
            )
            .await
            {
                Ok(claim) => {
                    if let (Some(first), Some(c)) = (stack.first_mut(), claim) {
                        first.review = Some(c);
                    }
                }
                Err(e) if land_all => return Err(e),
                Err(Error::Api { message, .. }) => {
                    results.push(refuse(&message));
                    continue;
                }
                Err(e) => return Err(e),
            }
            queued.push(crate::landing::Queued {
                ticket: crate::landing::ticket(),
                branch: u.branch.clone(),
                stack,
                lineage: judged.lineage,
                skipped: Arc::new(std::sync::Mutex::new(judged.skipped)),
            });
            continue;
        }
        let cur_seen = match cur {
            Some(c) => Some(projected(hub, project, viewer, c).await?),
            None => None,
        };
        if !is_embargo_branch && cur_seen != u.expected && !req.force {
            results.push(BranchResult {
                branch: u.branch.clone(),
                ok: false,
                message: Some("the branch has moved since you last pulled; pull, then push again".into()),
                tip: cur_seen,
                ticket: None,
            });
            continue;
        }
        if new_real.is_none() {
            // A branch whose tip is contained in the default branch holds
            // nothing of its own: whoever may write here deletes it
            // (BUG-1885). Any other deletion stays an admin's, and is never
            // an agent session's. Never this way: a forced push, the default
            // branch, a protected one, an embargo's line.
            let mut merged = false;
            if let Some(c) = cur {
                if !req.force
                    && !(viewer.admin && !viewer.agent)
                    && !is_embargo_branch
                    && !crate::branches::kept(&u.branch, &project.default_branch, &protected)
                    && project.view(viewer).writes_anything()
                {
                    if default_anc.is_none() {
                        if let Some((tip, lineage)) = crate::branches::tip_of(hub, project.id, &project.default_branch).await? {
                            let anc = crate::landing::Ancestry::new_staged(hub.clone(), project.id, &project.default_branch, tip, lineage, Some(st.clone()));
                            default_anc = Some((tip, lineage, anc));
                        }
                    }
                    if let Some((tip, _, anc)) = default_anc.as_mut() {
                        merged = crate::branches::contained(hub, project.id, anc, *tip, c).await?;
                    }
                }
            }
            if !merged {
                if !viewer.admin {
                    return Err(Error::forbidden(if is_embargo_branch || crate::branches::kept(&u.branch, &project.default_branch, &protected) {
                        "only admins may delete a branch".to_string()
                    } else {
                        format!(
                            "only admins may delete a branch, unless its work is all on '{}' and you may write here: '{}' was not deleted",
                            project.default_branch, u.branch
                        )
                    }));
                }
                if viewer.agent {
                    return Err(agent_refusal("an agent session never deletes a branch"));
                }
            } else if let Some(c) = cur {
                // S11: an agent session deletes only a branch it may move.
                match crate::branches::agent_may_delete(hub, project, viewer, c, Some(st.clone())).await? {
                    Some(AgentTip::Narrowed) => {
                        results.push(BranchResult {
                            branch: u.branch.clone(),
                            ok: false,
                            message: Some(NARROWED_MOVE.into()),
                            tip: cur_seen,
                            ticket: None,
                        });
                        continue;
                    }
                    Some(AgentTip::Access) => return Err(agent_refusal(AGENT_ACCESS_MOVE)),
                    Some(AgentTip::DefaultBranch) | None => {}
                }
            }
        }
        // The one rule of every tip an agent session sets (`agent_tip`):
        // first, for a narrowed one, anything outside its paths; then the
        // files that decide access or review, a new default branch included.
        if let Some(n) = new_real {
            match agent_tip_of_in(hub, project, viewer, &u.branch, cur, n, HashMap::new(), Some(st.clone())).await? {
                Some(AgentTip::Narrowed) => {
                    results.push(BranchResult {
                        branch: u.branch.clone(),
                        ok: false,
                        message: Some(NARROWED_MOVE.into()),
                        tip: cur_seen,
                        ticket: None,
                    });
                    continue;
                }
                Some(AgentTip::Access) => return Err(agent_refusal(AGENT_ACCESS_MOVE)),
                Some(AgentTip::DefaultBranch) => return Err(agent_refusal(AGENT_DEFAULT_BRANCH)),
                None => {}
            }
        }
        if !is_embargo_branch {
            if let (Some(c), Some(n)) = (cur, new_real) {
                if !req.force && !is_ancestor_in(hub, project.id, Some(st.clone()), c, n).await? {
                    results.push(BranchResult {
                        branch: u.branch.clone(),
                        ok: false,
                        message: Some("not a fast-forward; pull and merge, then push again".into()),
                        tip: cur_seen,
                        ticket: None,
                    });
                    continue;
                }
            }
            // The one write rule of a branch's move (BUG-1858, BUG-1920),
            // for a push of any shape. A new branch other than the default
            // one or a protected one holds nothing landed, and anyone may
            // name what they can read; a new protected branch is judged
            // against the default branch, a new default branch against
            // nothing.
            if let Some(n) = new_real {
                let default = u.branch == project.default_branch;
                if cur.is_some() || default || protected.contains(&u.branch) {
                    let default_tip = if default { None } else { current.get(&project.default_branch).copied() };
                    let (from, landed) = match cur {
                        Some(c) if req.force && !is_ancestor_in(hub, project.id, Some(st.clone()), c, n).await? => (Some(c), None),
                        Some(c) => (Some(c), default_tip),
                        None => (default_tip, default_tip),
                    };
                    if let Some(msg) = branch_move_write_refusal(hub, project, viewer, from, n, landed, &mut rows, Some(st.clone())).await? {
                        return Err(Error::forbidden(msg));
                    }
                }
            }
        }
        // The default branch carries the accepted policy.
        let (mut accept, mut policy_text_update) = (None, None);
        if u.branch == project.default_branch {
            if let Some(n) = new_real {
                let file = blocking_staged(hub, project.id, Some(st.clone()), move |src| crate::prs::state::file_at(src, src.snapshot(&n)?.tree)).await?;
                let fast_forward = match cur {
                    Some(c) => !req.force || is_ancestor_in(hub, project.id, Some(st.clone()), c, n).await?,
                    None => false,
                };
                rules_landing = Some(crate::prs::state::Landing { old: cur, new: n, file, fast_forward });
                let text = blocking_staged(hub, project.id, Some(st.clone()), move |src| policy_text(src, &src.snapshot(&n)?.tree)).await?;
                let incoming = AccessPolicy::parse(&text);
                if !incoming.same_rules(&project.policy) {
                    if !viewer.admin {
                        return Err(Error::forbidden("only admins may change who has access (the default branch's .veilpolicy)"));
                    }
                    if viewer.agent {
                        return Err(agent_refusal("an agent session never changes who has access (the default branch's .veilpolicy)"));
                    }
                    accept = Some(text);
                } else if text != project.policy_text {
                    policy_text_update = Some(text);
                }
                // The branch rules likewise: against the tip, never a
                // parent's (BUG-1102).
                let changed = blocking_staged(hub, project.id, Some(st.clone()), move |src| {
                    let t = match cur {
                        Some(c) => Some(src.snapshot(&c)?.tree),
                        None => None,
                    };
                    crate::landing::rules_changed(src, &src.snapshot(&n)?.tree, t.as_ref())
                })
                .await?;
                if changed && !viewer.admin {
                    return Err(Error::forbidden("only admins may change the branch rules (.veilrules)"));
                }
            }
        }
        if !is_embargo_branch && embargoes {
            if let Some(n) = new_real {
                let eids = crate::embargo::active_embargoes_of(hub, project.id, &[n], &real_parents_of, Some(st.clone())).await?;
                if let Some(eid) = eids.into_iter().next() {
                    results.push(BranchResult {
                        branch: u.branch.clone(),
                        ok: false,
                        message: Some(format!("cannot move '{}' to work built on unreleased embargo {eid}", u.branch)),
                        tip: cur_seen,
                        ticket: None,
                    });
                    continue;
                }
            }
        }
        plans.push((u.branch.clone(), cur, new_real, accept, policy_text_update));
    }
    let planned_creates: HashSet<&str> = plans.iter().filter(|(_, cur, new, ..)| cur.is_none() && new.is_some()).map(|(b, ..)| b.as_str()).collect();
    let planned_deletes: HashSet<&str> = plans.iter().filter(|(_, cur, new, ..)| cur.is_some() && new.is_none()).map(|(b, ..)| b.as_str()).collect();
    if !planned_creates.is_empty() && count_branches(hub, project.id, &mut branch_count).await?.saturating_sub(planned_deletes.len()) + planned_creates.len() > MAX_BRANCHES {
        return Err(Error::bad_request(format!("a project has at most {MAX_BRANCHES} branches")));
    }
    // The pusher's projections of what this push moves branches to, worked
    // out now and written in its transaction (an admin's are the snapshots).
    let mut deferred = Deferred {
        fresh: completed.iter().map(|c| (c.real, c.origin)).collect(),
        rows: Vec::new(),
        index: HashMap::new(),
        collapsed: HashSet::new(),
        staged: Some(st.clone()),
        made: Vec::new(),
    };
    for (_, _, new, _, _) in &plans {
        if let Some(n) = new {
            Box::pin(projected_inner(hub, project, viewer, *n, Some(&mut deferred))).await?;
        }
    }
    for q in &queued {
        Box::pin(projected_inner(hub, project, viewer, q.stack.last().expect("a stack is never empty").id, Some(&mut deferred))).await?;
    }
    touched.extend(st.touched());
    made.extend(deferred.made.iter().copied());
    // Only the snapshots this push made (known ones are recorded already:
    // rewriting their rows made every racing pusher write the same row),
    // and of those only what the updates that land reach: a refused
    // update's snapshots are no branch's history (BUG-914).
    let landing: HashSet<ObjectId> = {
        let mut seen = HashSet::new();
        let mut stack: Vec<ObjectId> = plans.iter().filter_map(|p| p.2).chain(queued.iter().filter_map(|q| q.stack.last().map(|e| e.id))).collect();
        while let Some(x) = stack.pop() {
            if let Some((ps, _)) = real_parents_of.get(&x) {
                if seen.insert(x) {
                    stack.extend(ps.iter().chain(real_attempts_of.get(&x).into_iter().flatten()).copied());
                }
            }
        }
        seen
    };
    completed.retain(|c| landing.contains(&c.real));
    // What it stores when something lands: each uploaded object the checks read
    // (`touched`) and each object the server made (`made`), written under its
    // own object key.
    let commits = !plans.is_empty() || !queued.is_empty() || !embargo_upserts.is_empty();
    if commits {
        keep_uploads(hub, project.id, &st, &touched, &made).await?;
    }
    let new_reals: Vec<(String, i64)> = completed
        .iter()
        .map(|c| (c.real.hex(), real_parents_of.get(&c.real).map_or(0, |(_, a)| *a)))
        .collect();
    let pushed_snapshots: Vec<ObjectId> = completed.iter().map(|c| c.real).collect();
    let origins: Vec<(String, String)> = completed.iter().filter_map(|c| c.origin.map(|o| (c.real.hex(), o.hex()))).collect();
    let memos: Vec<(String, String, String, bool)> =
        deferred.rows.iter().map(|(k, r, p)| (k.clone(), r.hex(), p.hex(), deferred.collapsed.contains(r))).collect();
    // Snapshots introduced on hidden embargo lines in this push (real, origin, and projected).
    let embargo_snaps: Vec<(String, String)> = {
        let mut out = Vec::new();
        for (branch, _, new, ..) in &plans {
            let Some(eid) = veil_core::embargo::embargo_id_of_branch(branch) else { continue };
            let Some(n) = new else { continue };
            out.push((n.hex(), eid.to_string()));
            for (_, r, p) in &deferred.rows {
                if *r == *n && !deferred.collapsed.contains(r) {
                    out.push((p.hex(), eid.to_string()));
                }
            }
            let mut seen = HashSet::new();
            let mut stack = vec![*n];
            while let Some(x) = stack.pop() {
                if let (Some((ps, _)), true) = (real_parents_of.get(&x), seen.insert(x)) {
                    out.push((x.hex(), eid.to_string()));
                    for c in &completed {
                        if c.real == x {
                            if let Some(orig) = c.origin {
                                out.push((orig.hex(), eid.to_string()));
                            }
                        }
                    }
                    for (_, r, p) in &deferred.rows {
                        if *r == x && !deferred.collapsed.contains(r) {
                            out.push((p.hex(), eid.to_string()));
                        }
                    }
                    stack.extend(ps.iter().chain(real_attempts_of.get(&x).into_iter().flatten()).copied());
                }
            }
        }
        out
    };
    // The changes each moved branch now holds that this push brought, by
    // change id and author (`landed_changes`, BUG-1522, BUG-1527).
    let change_of: HashMap<ObjectId, String> =
        real_of.iter().filter_map(|(pushed, real)| parents_of.get(pushed).map(|s| (*real, s.change_id.to_string()))).collect();
    let mut plan_changes: HashMap<_, _> = plans
        .iter()
        .filter_map(|(branch, _, new, _, _)| new.map(|n| (branch.clone(), n)))
        .map(|(branch, n)| {
            let (mut cs, mut aus, mut ls) = (Vec::new(), Vec::new(), Vec::new());
            let mut seen = HashSet::new();
            let mut stack = vec![n];
            while let Some(x) = stack.pop() {
                if let (Some((ps, author)), true) = (real_parents_of.get(&x), seen.insert(x)) {
                    if let Some(cid) = change_of.get(&x) {
                        cs.push(cid.clone());
                        aus.push(*author);
                        ls.push(x.hex());
                    }
                    stack.extend(ps.iter().copied());
                }
            }
            (branch, (cs, aus, ls))
        })
        .collect();
    // What each moved branch now holds that this push did not bring
    // (BUG-1524): snapshots the server already held (another branch's, a
    // merged line's), below the new tip and not below the tip it moves
    // from. A fast-forward's are read here and recorded with the push's own
    // (`landing::reached`, bounded); a move that reaches more, a new branch
    // on held history and a forced move (a new lineage, with no rows) leave
    // the branch's `changes_recorded` false, and "already landed" then asks
    // the derived graph. Per branch: whether its changes are all recorded
    // after the move, and the lineage that was read under.
    let mut plan_recorded: HashMap<String, (bool, Option<i64>)> = HashMap::new();
    for (branch, cur, new, _, _) in &plans {
        let Some(n) = *new else { continue };
        let mut held = Vec::new();
        let mut seen = HashSet::new();
        let mut stack = vec![n];
        while let Some(x) = stack.pop() {
            if seen.insert(x) {
                match real_parents_of.get(&x) {
                    Some((ps, _)) => stack.extend(ps.iter().copied()),
                    None => held.push(x),
                }
            }
        }
        held.retain(|x| *x != root_snapshot_id() && (req.force || Some(*x) != *cur));
        let recorded = if veil_core::embargo::embargo_id_of_branch(branch).is_some() {
            // An embargo line's changes are never recorded (below).
            (false, None)
        } else if held.is_empty() {
            (true, None)
        } else if req.force || cur.is_none() {
            (false, None)
        } else {
            match crate::landing::reached(hub, project.id, branch, held, *cur).await? {
                Some((lineage, (cs, aus, ls))) => {
                    let rows = plan_changes.entry(branch.clone()).or_default();
                    rows.0.extend(cs);
                    rows.1.extend(aus);
                    rows.2.extend(ls);
                    (true, Some(lineage))
                }
                None => (false, None),
            }
        };
        plan_recorded.insert(branch.clone(), recorded);
    }
    let pid = project.id;
    let plans2 = plans.clone();
    let force = req.force;
    let (queued2, who2) = (queued.clone(), who.clone());
    let embargo_upserts2 = embargo_upserts.clone();
    let embargo_snaps2 = embargo_snaps.clone();
    // Whoever lands here hears at once (registered before the commit).
    let waiters: Vec<crate::landing::Waiter> = queued.iter().map(|q| hub.landing.register(&q.ticket)).collect();
    let mut tx_packs: Vec<String> = st.names().into_iter().map(|n| n.to_string()).collect();
    tx_packs.sort();
    tx_packs.dedup();
    let default_branch = project.default_branch.clone();
    // A merged branch goes only while the default branch it was judged
    // against is in the same lineage (not rewound since: BUG-1885).
    let admin_delete = viewer.admin && !viewer.agent;
    let merged_lineage = default_anc.as_ref().map_or(-1, |(_, lineage, _)| *lineage);
    // Nothing to move (every update refused: the pusher pulls and tries
    // again): no commit, and nothing recorded as history no branch reaches.
    progress.lock().unwrap().transaction = commits;
    let (moved, memo_stored, discarded_containers) = if !commits {
        (Vec::new(), Vec::new(), Vec::new())
    } else {
        let r = crate::db::transaction(&hub.db, crate::db::Isolation::ReadCommitted, move |c| {
        let plans = plans2.clone();
        let plan_changes = plan_changes.clone();
        let plan_recorded = plan_recorded.clone();
        let (rules_landing, default_branch) = (rules_landing.clone(), default_branch.clone());
        let new_reals = new_reals.clone();
        let origins = origins.clone();
        let memos = memos.clone();
        let (queued, who) = (queued2.clone(), who2.clone());
        let embargo_upserts = embargo_upserts2.clone();
        let embargo_snaps = embargo_snaps2.clone();
        let tx_packs = tx_packs.clone();
        Box::pin(async move {
            crate::pack_gc::guard_root_write(&mut *c, pid, gc_epoch).await?;
            for q in &queued {
                crate::landing::insert(&mut *c, pid, &who, q).await?;
            }
            let mut moved = Vec::new();
            let mut lineages: Vec<(String, i64)> = Vec::new();
            let mut rules_changed = false;
            let mut policy = None;
            for (branch, cur, new, accept, policy_text_update) in plans {
                let (recorded, read_under) = plan_recorded.get(&branch).copied().unwrap_or((false, None));
                let rows = match (cur, new) {
                    // A forced update starts a new lineage (BUG-1300): what the
                    // landing service recorded of the branch no longer counts.
                    // The branch's changes stay all recorded (BUG-1524) only
                    // when this move's are (in a new lineage: the whole
                    // history), in the lineage the held ones were read under.
                    (Some(c0), Some(n)) => {
                        // The changes it brings (`landed_changes`, below for
                        // the rest) recorded in the same statement, in the
                        // lineage it returns, for a branch other than the
                        // default one (whose review rules are recorded
                        // first) and its embargo lines (never recorded).
                        let with_changes = branch != default_branch && veil_core::embargo::embargo_id_of_branch(&branch).is_none();
                        let none = (Vec::new(), Vec::new(), Vec::new());
                        let (cs, aus, ls) = match with_changes {
                            true => plan_changes.get(&branch).unwrap_or(&none),
                            false => &none,
                        };
                        sqlx::query_scalar::<_, i64>(
                            "WITH u AS (UPDATE branches SET target = $1, lineage = CASE WHEN $5 THEN nextval('branch_lineages') ELSE lineage END, \
                             changes_recorded = $6 AND ($5 OR (changes_recorded AND ($7::BIGINT IS NULL OR lineage = $7))) \
                             WHERE project_id = $2 AND name = $3 AND target = $4 RETURNING lineage), \
                             rec AS (INSERT INTO landed_changes (project_id, branch, lineage, change_id, author, landed) \
                             SELECT DISTINCT ON (ch, au) $2, $3, u.lineage, ch, au, ld \
                             FROM u, unnest($8::TEXT[], $9::BIGINT[], $10::TEXT[]) WITH ORDINALITY AS v(ch, au, ld, ord) \
                             ORDER BY ch, au, ord \
                             ON CONFLICT (project_id, branch, lineage, change_id, author) DO UPDATE SET landed = EXCLUDED.landed \
                             WHERE EXISTS (SELECT 1 FROM bisect_reverts br WHERE br.project_id = landed_changes.project_id AND br.branch = landed_changes.branch \
                             AND br.lineage = landed_changes.lineage AND br.culprit = landed_changes.landed AND br.state = 'reverted')) \
                             SELECT lineage FROM u",
                        )
                        .bind(n.hex())
                        .bind(pid)
                        .bind(&branch)
                        .bind(c0.hex())
                        .bind(force)
                        .bind(recorded)
                        .bind(read_under)
                        .bind(cs)
                        .bind(aus)
                        .bind(ls)
                        .fetch_optional(&mut *c)
                        .await?
                        .map_or(0, |lineage| {
                            if !with_changes {
                                lineages.push((branch.clone(), lineage));
                            }
                            1
                        })
                    }
                    (None, Some(n)) => sqlx::query_scalar::<_, i64>(
                        "INSERT INTO branches (project_id, name, target, changes_recorded) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING RETURNING lineage",
                    )
                        .bind(pid)
                        .bind(&branch)
                        .bind(n.hex())
                        .bind(recorded)
                        .fetch_optional(&mut *c)
                        .await?
                        .map_or(0, |lineage| {
                            lineages.push((branch.clone(), lineage));
                            1
                        }),
                    // A deletion of a merged branch locks the default
                    // branch's row at the lineage it was judged in first:
                    // a forced move of it in flight is not raced (BUG-2450).
                    (Some(_), None) if !admin_delete
                        && sqlx::query_scalar::<_, i32>("SELECT 1 FROM branches WHERE project_id = $1 AND name = $2 AND lineage = $3 FOR SHARE")
                            .bind(pid)
                            .bind(&default_branch)
                            .bind(merged_lineage)
                            .fetch_optional(&mut *c)
                            .await?
                            .is_none() => 0,
                    (Some(c0), None) => sqlx::query(
                        "DELETE FROM branches WHERE project_id = $1 AND name = $2 AND target = $3 \
                         AND ($4 OR EXISTS (SELECT 1 FROM branches WHERE project_id = $1 AND name = $5 AND lineage = $6))",
                    )
                        .bind(pid)
                        .bind(&branch)
                        .bind(c0.hex())
                        .bind(admin_delete)
                        .bind(&default_branch)
                        .bind(merged_lineage)
                        .execute(&mut *c)
                        .await?
                        .rows_affected(),
                    (None, None) => 1,
                };
                if rows != 1 {
                    // Someone else moved it first: nothing of this push lands.
                    return Err(Error::conflict(format!("branch '{branch}' moved during the push; pull, then push again")));
                }
                if accept.is_some() || policy_text_update.is_some() {
                    // Written after the review gate (below): the project's
                    // row comes after it (lock order, BUG-2130).
                    policy = Some((accept, policy_text_update));
                    rules_changed = true;
                }
                if let (true, Some(l)) = (branch == default_branch, &rules_landing) {
                    rules_changed |= crate::prs::state::record_landing(&mut *c, pid, l).await?;
                }
                moved.push(branch);
            }
            for (branch, lineage) in &lineages {
                // Only record `landed_changes` on non-embargo branches so that
                // landing at release onto `main` does not skip them!
                if veil_core::embargo::embargo_id_of_branch(branch).is_none() {
                    if let Some((cs, aus, ls)) = plan_changes.get(branch) {
                        if !cs.is_empty() {
                            crate::landing::record_changes(&mut *c, pid, branch, *lineage, cs, aus, ls).await?;
                        }
                    }
                }
            }
            crate::embargo::record_in_tx(&mut *c, pid, &embargo_upserts, &embargo_snaps).await?;
            // The upload containers that hold what this push stored (S28):
            // `STAGED` containers turned `DISCARDED` (keeping any already
            // `LISTED` pack from an earlier `packs` server). A row missing or
            // not `STAGED`/`LISTED` is excluded by `state IN ($15, $16)`
            // (`BUG-2860`), returning fewer rows and aborting with 409 Conflict.
            let mut authors: Vec<(String, i64)> = Vec::with_capacity(new_reals.len());
            let mut author_at: HashMap<&str, usize> = HashMap::with_capacity(new_reals.len());
            for (r, author) in &new_reals {
                match author_at.get(r.as_str()) {
                    Some(&i) if authors[i].1 == 0 => authors[i].1 = *author,
                    Some(_) => {}
                    None => {
                        author_at.insert(r.as_str(), authors.len());
                        authors.push((r.clone(), *author));
                    }
                }
            }
            let (snap_ids, snap_authors): (Vec<String>, Vec<i64>) = authors.into_iter().unzip();
            let (origin_reals, origin_ids): (Vec<String>, Vec<String>) = origins.iter().cloned().unzip();
            let memo_keys: Vec<String> = memos.iter().map(|m| m.0.clone()).collect();
            let memo_reals: Vec<String> = memos.iter().map(|m| m.1.clone()).collect();
            let memo_projected: Vec<String> = memos.iter().map(|m| m.2.clone()).collect();
            let memo_collapsed: Vec<bool> = memos.iter().map(|m| m.3).collect();
            let (stored_keys, stored_reals, updated_packs, discarded_names): (Vec<String>, Vec<String>, i64, Vec<String>) = sqlx::query_as(
                "WITH k AS (UPDATE packs \
                   SET state = CASE WHEN state = $15 THEN $13 ELSE state END, \
                       discarded_at = CASE WHEN state = $15 THEN $6 ELSE discarded_at END, \
                       objects = CASE WHEN state = $15 THEN -1 ELSE objects END \
                   WHERE project_id = $1 AND name = ANY($14) AND state IN ($15, $16) \
                   RETURNING CASE WHEN state = $13 THEN name ELSE '' END AS discarded_name), \
                 s AS (INSERT INTO snapshots (project_id, id, author) SELECT $1, i, a FROM UNNEST($2::text[], $3::bigint[]) AS t(i, a) \
                   ON CONFLICT (project_id, id) DO UPDATE SET author = EXCLUDED.author WHERE snapshots.author = 0), \
                 o AS (INSERT INTO origins (project_id, real_id, origin_id) SELECT $1, r, g FROM UNNEST($4::text[], $5::text[]) AS t(r, g) \
                   ON CONFLICT DO NOTHING), \
                 m AS (INSERT INTO projections (project_id, view_key, real_id, projected_id, created_at, collapsed) \
                   SELECT $1, k, r, p, $6, c FROM UNNEST($7::text[], $8::text[], $9::text[], $10::bool[]) AS t(k, r, p, c) \
                   ON CONFLICT DO NOTHING RETURNING view_key, real_id), \
                 l AS (INSERT INTO audit_log (project_id, at, actor, action, details) VALUES ($1, $6, $11, 'push', $12)) \
                 SELECT x.k, x.r, (SELECT count(*) FROM k)::bigint, \
                   COALESCE((SELECT array_agg(discarded_name) FROM k WHERE discarded_name <> ''), '{}') \
                 FROM (SELECT COALESCE(array_agg(view_key), '{}') AS k, COALESCE(array_agg(real_id), '{}') AS r FROM m) x",
            )
            .bind(pid)
            .bind(&snap_ids)
            .bind(&snap_authors)
            .bind(&origin_reals)
            .bind(&origin_ids)
            .bind(veil_core::now_millis())
            .bind(&memo_keys)
            .bind(&memo_reals)
            .bind(&memo_projected)
            .bind(&memo_collapsed)
            .bind(person)
            .bind(format!("moved {moved:?}"))
            .bind(crate::pack::DISCARDED)
            .bind(&tx_packs)
            .bind(crate::pack::STAGED)
            .bind(crate::pack::LISTED)
            .fetch_one(&mut *c)
            .await?;
            if updated_packs != tx_packs.len() as i64 {
                return Err(Error::conflict(DISCARDED_UPLOAD));
            }
            let stored: HashSet<(&str, &str)> = stored_keys.iter().map(|k| k.as_str()).zip(stored_reals.iter().map(|r| r.as_str())).collect();
            let memo_stored: Vec<bool> = memos.iter().map(|m| stored.contains(&(m.0.as_str(), m.1.as_str()))).collect();
            if rules_changed {
                crate::prs::close_review_gate(&mut *c, pid).await?;
            }
            match policy {
                Some((Some(text), _)) => crate::perm::accept_policy(&mut *c, pid, &text).await?,
                Some((None, Some(text))) => {
                    sqlx::query("UPDATE projects SET policy_text = $1 WHERE id = $2")
                        .bind(&text)
                        .bind(pid)
                        .execute(&mut *c)
                        .await?;
                }
                _ => {}
            }
            Ok((moved, memo_stored, discarded_names))
        })
    })
    .await;
        match r {
            Ok(r) => {
                hub.commits.count(if queued.is_empty() { crate::db::Commit::Push } else { crate::db::Commit::LandSubmit });
                r
            }
            Err(e) => {
                for w in waiters {
                    crate::landing::abandon(hub, w);
                }
                return Err(e);
            }
        }
    };
    let kept = if commits {
        if let Err(e) = hub.objects.purge_discarded(project.id, &discarded_containers).await {
            eprintln!("veil-server: deleting what a push discarded: {e:#}");
        }
        let settled: HashSet<Arc<str>> = st.names().into_iter().collect();
        // Every server's copy too, by a notice sent after the commit
        // (never in the push's transaction: BUG-2459).
        if !moved.is_empty() || !embargo_upserts.is_empty() {
            hub.caches.tips_moved(project.id);
        }
        for c in &completed {
            hub.caches.put_committed(project.id, &c.real);
        }
        Some(settled)
    } else {
        None
    };
    drop(st);
    if !embargo_upserts.is_empty() {
        hub.embargo.wake();
    }
    for ((view_key, real, projected), stored) in deferred.rows.iter().zip(memo_stored) {
        if stored {
            hub.caches.put_memo_row(project.id, view_key, real, projected, deferred.collapsed.contains(real));
        }
    }
    // The landings: their services wake, and with `wait` the push answers
    // once they are decided.
    let deadline = tokio::time::Instant::now() + crate::landing::WAIT;
    let mut landings = Vec::new();
    for (q, w) in queued.iter().zip(waiters) {
        crate::landing::ensure(hub, project.id, &q.branch);
        let mut r = match wait {
            true => {
                let r = crate::landing::wait(hub, project.id, person, &q.branch, w, deadline).await?;
                crate::landing::seen(hub, project, viewer, r).await?
            }
            false => {
                crate::landing::abandon(hub, w);
                crate::landing::queued(&q.ticket)
            }
        };
        let skipped = q.skipped.lock().unwrap().clone();
        r.warnings.extend(crate::landing::skipped_warnings(hub, project.id, &q.branch, &skipped, None).await?);
        landings.push(r);
    }
    // Derived history data for the public branches moved, in the background:
    // hidden embargo branches are derived only once released onto `main`.
    let public_moved: Vec<String> = moved
        .into_iter()
        .filter(|b| veil_core::embargo::embargo_id_of_branch(b).is_none())
        .collect();
    if !public_moved.is_empty() {
        // A push of many snapshots: every view key's rows are filled from
        // now on (the new snapshots read ahead first), beside the derived
        // data and not after it (BUG-1943: the diffs of 10,000 snapshots
        // take minutes, and a clone a second after the push asks for the
        // tip's row). A small push's rows are written with its derived
        // data (`derive::finish_landing_run`), or by the first query that
        // names its tip.
        if pushed_snapshots.len() > 16 {
            let (hub, id, moved) = (hub.clone(), project.id, public_moved.clone());
            tokio::spawn(async move {
                crate::query::graph::read_ahead(&hub, id, pushed_snapshots).await;
                if let Err(e) = crate::derive::rows_of_tips(&hub, id, &moved).await {
                    eprintln!("veil-server: filling the graphs of project {id} after a push: {e:?}");
                }
            });
        }
        crate::derive::landed(hub, project.id, public_moved);
    }
    // Early embargo releases pushed via `vl embargo release <id>` + `vl push`.
    // One that waits for an approval is held, not an error of the push
    // (which is committed): the pusher is told (BUG-1861).
    let mut held_releases = Vec::new();
    for (eid, rec) in embargo_releases {
        match crate::embargo::release_one(hub, project.id, &eid, Some(rec), Some((viewer, who))).await {
            Ok(_) => {}
            Err(Error::Api { code: "not_ready", message, .. }) => held_releases.push(message),
            Err(e) => return Err(e),
        }
    }
    // The tips as the pusher sees them now (their own snapshots, where the
    // server's projection gives them back).
    let accepted = plans.iter().any(|p| p.3.is_some());
    let reloaded;
    let project = if accepted {
        reloaded = crate::perm::load_project(&mut *hub.db.acquire().await?, &project.name)
            .await?
            .ok_or_else(|| Error::not_found("project"))?;
        &reloaded
    } else {
        project
    };
    let mut warnings = match accepted {
        true => crate::perm::accepted_listing(project),
        false => Vec::new(),
    };
    warnings.extend(held_releases);
    for (branch, _, new, _, _) in plans {
        let tip = match new {
            Some(n) => Some(projected(hub, project, viewer, n).await?),
            None => None,
        };
        let client_branch = embargo_diverted.get(&branch).cloned().unwrap_or(branch);
        results.push(BranchResult { branch: client_branch, ok: true, message: None, tip, ticket: None });
    }
    for (q, l) in queued.iter().zip(&landings) {
        use veil_core::hub::land::LandState;
        warnings.extend(l.warnings.iter().cloned());
        results.push(BranchResult {
            branch: q.branch.clone(),
            ok: l.state == LandState::Landed,
            message: match l.state {
                LandState::Landed => None,
                LandState::Queued => Some(format!("queued to land as {} (`vl land --status {}`)", l.ticket, l.ticket)),
                LandState::Conflict => Some(format!(
                    "conflict: {} changed on '{}' since your change's base; pull, redo it there, and push again",
                    l.paths.join(", "),
                    q.branch
                )),
                LandState::Rejected => Some(l.message.clone().unwrap_or_default()),
            },
            tip: l.landed.last().copied(),
            ticket: Some(q.ticket.clone()),
        });
    }
    Ok((PushResult { results, warnings }, landings, kept))
}

/// The rows `(name, target)` of `project`'s branches named `names`, as
/// stored now.
async fn branch_rows(hub: &Hub, project: i64, names: &[String]) -> Result<Vec<(String, String)>> {
    Ok(sqlx::query_as("SELECT name, target FROM branches WHERE project_id = $1 AND name = ANY($2)")
        .bind(project)
        .bind(names)
        .fetch_all(&hub.db)
        .await?)
}

/// [`branch_rows`], and whether no embargo line of `project` is unreleased,
/// in one statement (so as of the moment the rows were read).
async fn branch_rows_unembargoed(hub: &Hub, project: i64, names: &[String]) -> Result<(Vec<(String, String)>, bool)> {
    let rows: Vec<(Option<String>, Option<String>, bool)> = sqlx::query_as(
        "SELECT b.name, b.target, e.active \
         FROM (SELECT EXISTS (SELECT 1 FROM embargo_lines WHERE project_id = $1 AND released_at IS NULL) AS active) e \
         LEFT JOIN branches b ON b.project_id = $1 AND b.name = ANY($2)",
    )
    .bind(project)
    .bind(names)
    .fetch_all(&hub.db)
    .await?;
    let free = !rows.iter().any(|r| r.2);
    Ok((rows.into_iter().filter_map(|(n, t, _)| Some((n?, t?))).collect(), free))
}

/// How many branches `project` has, read once (`count`) for a push.
async fn count_branches(hub: &Hub, project: i64, count: &mut Option<usize>) -> Result<usize> {
    if let Some(n) = *count {
        return Ok(n);
    }
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM branches WHERE project_id = $1").bind(project).fetch_one(&hub.db).await?;
    *count = Some(n as usize);
    Ok(n as usize)
}

/// The checks of new snapshot `id` (`n`) that need nothing but itself:
/// signed by a registered device (`signers`), parents.
/// Returns the signer's `people.id`.
fn precheck(id: &ObjectId, n: &Snapshot, signers: &HashMap<String, i64>) -> Result<i64> {
    let author = match &n.signature {
        Some(sig) if n.signature_valid() == Some(true) => match signers.get(&sig.key) {
            Some(&p) => p,
            None => {
                return Err(Error::forbidden(format!(
                    "snapshot {} is signed by a key no device here is registered with",
                    id.short()
                )))
            }
        },
        _ => return Err(Error::forbidden(format!("snapshot {} is unsigned or its signature is invalid", id.short()))),
    };
    if n.parents.is_empty() {
        return Err(Error::bad_request("a snapshot without parents (only the root has none)"));
    }
    Ok(author)
}

/// [`complete`] new snapshot `n` on real parents `rp` and real attempts `ra`,
/// reading the push's uploads through `staged` (one completion's own): the
/// result, what it read of the uploads, and the updated [`PushRows`].
#[allow(clippy::too_many_arguments)]
async fn complete_one(
    hub: Arc<Hub>,
    project: Project,
    viewer: Viewer,
    staged: Arc<Staged>,
    n: Arc<Snapshot>,
    rp: Vec<ObjectId>,
    ra: Vec<ObjectId>,
    mut rows: PushRows,
) -> Result<Checked> {
    let st = staged.clone();
    let st_check = staged.clone();
    let hub2 = hub.clone();
    let (c, rows) = blocking_staged(&hub, project.id, Some(staged), move |src| {
        let c = complete(src, &project, &viewer, &*st_check, &n, &rp, &ra, &hub2.identity, &mut rows)?;
        Ok((c, rows))
    })
    .await?;
    Ok((c, st.touched(), rows))
}

/// Keep what a landing push retains ([`crate::store::Objects::keep`]): each
/// uploaded object its checks read (`touched`) and each object the server made
/// (`made`), written under its own object key. Nothing a check did not read is
/// kept.
async fn keep_uploads(
    hub: &Arc<Hub>,
    project: i64,
    st: &Staged,
    touched: &HashSet<ObjectId>,
    made: &[ObjectId],
) -> Result<()> {
    let made_objects: Vec<(ObjectId, Bytes)> = {
        let m = st.made.lock().unwrap();
        made.iter().filter_map(|id| Some((*id, m.get(id)?.clone()))).collect()
    };
    let held_containers: Vec<StagedPack>;
    let containers: &[StagedPack] = if st.held.is_empty() {
        &st.packs
    } else {
        debug_assert!(st.packs.is_empty(), "a push uses either `packs` or `receipts`, never both");
        let mut out = Vec::with_capacity(st.held.len());
        for (name, held) in st.held.iter() {
            let mut slots = Vec::new();
            for id in touched {
                if let Some(slot) = held.index.get(id) {
                    slots.push((*id, slot));
                }
            }
            if !slots.is_empty() {
                out.push((
                    name.clone(),
                    StagedSlots {
                        objects: held.index.len(),
                        size: held.size,
                        slots,
                    },
                ));
            }
        }
        held_containers = out;
        &held_containers
    };
    let opts = crate::store::KeepOpts { encode_threads: 1, already_held: false };
    hub.objects
        .keep(project, containers, touched, made_objects, opts)
        .await
        .map_err(|e| match e {
            crate::store::KeepError::Discarded => {
                Error::conflict("an upload this push names was discarded; push again")
            }
            crate::store::KeepError::Store(e) => Error::Other(e),
        })
}

/// Is `a` an ancestor of (or equal to) `b` in the real history (a push's
/// `staged` snapshots read first)?
async fn is_ancestor_in(hub: &Arc<Hub>, project: i64, staged: Option<Arc<Staged>>, a: ObjectId, b: ObjectId) -> Result<bool> {
    blocking_staged(hub, project, staged, move |src| {
        let mut seen = HashSet::new();
        let mut stack = vec![b];
        while let Some(x) = stack.pop() {
            if x == a {
                return Ok(true);
            }
            if !seen.insert(x) || x == root_snapshot_id() {
                continue;
            }
            stack.extend(src.snapshot(&x)?.parents.iter().copied());
        }
        Ok(false)
    })
    .await
}

/// The receipt for `person` uploading object `id` to `project` in staged
/// pack `pack` (S28): a MAC only the server can make, then the pack's name.
/// A push shows it for each object it introduces; the server reads the
/// object from that pack, and only for that person.
pub fn receipt(hub: &Hub, project: i64, person: i64, id: &ObjectId, pack: &str) -> String {
    format!("{}.{pack}", mac(hub, project, person, id, pack))
}

fn mac(hub: &Hub, project: i64, person: i64, id: &ObjectId, pack: &str) -> String {
    let mut h = blake3::Hasher::new_keyed(&hub.receipt_key);
    h.update(&project.to_le_bytes());
    h.update(&person.to_le_bytes());
    h.update(&id.0);
    h.update(b"staged in");
    h.update(pack.as_bytes());
    hex::encode(&h.finalize().as_bytes()[..16])
}

/// Compared in constant time.
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The staged pack of each object whose receipt in `receipts` is
/// `person`'s. A receipt is only a claim: what was uploaded is what
/// [`staging`] finds in those packs. (Receipts without a pack, from servers
/// before S28, are not accepted: the upgrade to S28 is not rolling,
/// BUG-1158.)
pub(crate) fn receipted(hub: &Hub, project: i64, person: i64, receipts: &std::collections::BTreeMap<ObjectId, String>) -> HashMap<ObjectId, Arc<str>> {
    let mut staged = HashMap::new();
    let mut names: HashMap<&str, Arc<str>> = HashMap::new();
    for (id, r) in receipts {
        let Some((m, p)) = r.split_once('.') else { continue };
        if !crate::pack::valid_name(p) || !same(m, &mac(hub, project, person, id, p)) {
            continue;
        }
        staged.insert(*id, names.entry(p).or_insert_with(|| Arc::from(p)).clone());
    }
    staged
}

/// The staged packs `staged` names (from [`receipted`]) that `person`
/// uploaded and nobody discarded (the database's rows: BUG-1155), what
/// the push keeps of each one's index (its object count, its length and
/// the slots of the objects the receipts name in it: the index itself is
/// held, under its share of the server's bound on indexes, only while it
/// is read, BUG-1496), and where each object is. **An object counts as
/// uploaded only if its receipt's pack holds it** ([`Staged::uploaded`]):
/// a receipt of a discarded upload, or of another pack, is worth nothing,
/// and the object is never looked for in the project's store instead.
async fn staging(hub: &Arc<Hub>, project: i64, person: i64, staged: &HashMap<ObjectId, Arc<str>>) -> Result<Staged> {
    let mut by_pack: HashMap<Arc<str>, Vec<ObjectId>> = HashMap::new();
    for (id, n) in staged {
        by_pack.entry(n.clone()).or_default().push(*id);
    }
    let mut names: Vec<Arc<str>> = by_pack.keys().cloned().collect();
    names.sort();
    let mut vanished_ids: HashSet<ObjectId> = HashSet::new();
    hub.objects.claim_recent(project, person, &names);
    let rp = hub.objects.usable_for_receipts(project, person, &names).await.map_err(Error::Other)?;
    for v in &rp.vanished {
        if let Some(ids) = by_pack.remove(v) {
            vanished_ids.extend(ids);
        }
    }
    let usable = rp.usable;
    let mut packs: Vec<StagedPack> = Vec::new();
    let mut set = tokio::task::JoinSet::new();
    let mut it = names.into_iter().filter(|n| usable.contains(n));
    loop {
        while set.len() < 16 {
            let Some(n) = it.next() else { break };
            let h = hub.clone();
            let ids = by_pack.remove(&n).unwrap_or_default();
            set.spawn(async move {
                let r = h.objects.staged_slots(project, &n, &ids).await;
                (n, ids, r)
            });
        }
        match set.join_next().await {
            Some(Ok((n, _, Ok(Some(slots))))) => packs.push((n, slots)),
            Some(Ok((n, ids, Ok(None)))) => {
                let rp = hub
                    .objects
                    .usable_for_receipts(project, person, std::slice::from_ref(&n))
                    .await
                    .map_err(Error::Other)?;
                if rp.usable.contains(&n) || rp.vanished.contains(&n) {
                    vanished_ids.extend(ids);
                }
            }
            Some(Ok((_, _, Err(e)))) => return Err(Error::Other(e)),
            Some(Err(e)) => return Err(Error::Other(e.into())),
            None => break,
        }
    }
    let at = packs
        .iter()
        .flat_map(|(n, sp)| sp.slots.iter().map(move |(id, s)| (*id, (n.clone(), *s))))
        .collect();
    Ok(Staged {
        at: Arc::new(at),
        packs: Arc::new(packs),
        held: Arc::new(Vec::new()),
        made: Default::default(),
        vanished: Arc::new(vanished_ids),
        touched: Mutex::new(HashSet::new()),
    })
}

/// Uniform `400 bad_request` message for every invalid pack name in
/// `PushRequest::packs` (another person's pack, another project's pack, a
/// forged/malformed name, or a pack discarded by an earlier refused push) so
/// none of those cases can be told apart (BUG-1150, BUG-1155).
const BAD_PACK_UPLOAD: &str = "an upload this push names is missing or was discarded";

/// Validate and load the staged packs named in `PushRequest::packs`
/// (`BUG-1150`, `BUG-2851`, `BUG-2852`). Every name must be syntactically
/// valid, unique in the request, owned by `person` in `project`, and still
/// `STAGED` or `LISTED` in `packs`. Only caller-owned packs from `usable` are
/// ever passed to discard or `release_recent`, so naming someone else's pack
/// can never read or discard it. Each pack's [`crate::pack::Held`] index
/// stays alive inside [`Staged::held`] under `Packs::bound`
/// (`pack::INDEXES_HELD`) for the duration of the push and is binary-searched
/// directly without duplicating entries (`BUG-2852`).
async fn staging_packs(
    hub: &Arc<Hub>,
    project: i64,
    person: i64,
    req_packs: Vec<String>,
) -> Result<(Staged, Vec<Arc<str>>)> {
    let mut seen: HashSet<&str> = HashSet::with_capacity(req_packs.len());
    let mut names: Vec<Arc<str>> = Vec::with_capacity(req_packs.len());
    for p in &req_packs {
        if !crate::pack::valid_name(p) {
            return Err(Error::bad_request(BAD_PACK_UPLOAD));
        }
        if !seen.insert(p.as_str()) {
            return Err(Error::bad_request("a push must not name the same staged pack twice"));
        }
        names.push(Arc::from(p.as_str()));
    }
    hub.objects.claim_recent(project, person, &names);
    let check = hub.objects.usable_for_packs(project, person, &names).await.map_err(Error::Other)?;
    let mut owned: Vec<Arc<str>> = check.usable.into_iter().collect();
    owned.sort();
    if !check.invalid.is_empty() {
        if let Err(e) = hub.objects.discard_refused(project, &owned).await {
            eprintln!("veil-server: discarding what a refused push uploaded: {e:#}");
        }
        return Err(Error::bad_request(BAD_PACK_UPLOAD));
    }
    if !check.consumed.is_empty() {
        hub.objects.release_recent(project, person, &owned);
        return Err(Error::conflict(DISCARDED_UPLOAD));
    }
    let mut held_packs: Vec<HeldPack> = Vec::with_capacity(owned.len());
    let mut set = tokio::task::JoinSet::new();
    let mut it = owned.iter().cloned();
    let mut missing_pack: Option<Arc<str>> = None;
    let mut load_err: Option<Error> = None;
    loop {
        while set.len() < 16 {
            let Some(n) = it.next() else { break };
            let h = hub.clone();
            set.spawn(async move {
                let r = h.objects.staged_index(project, &n).await;
                (n, r)
            });
        }
        match set.join_next().await {
            Some(Ok((n, Ok(Some(held))))) => held_packs.push((n, held)),
            Some(Ok((n, Ok(None)))) => {
                missing_pack = Some(n);
                break;
            }
            Some(Ok((_, Err(e)))) => {
                load_err = Some(Error::Other(e));
                break;
            }
            Some(Err(e)) => {
                load_err = Some(Error::Other(e.into()));
                break;
            }
            None => break,
        }
    }
    if let Some(e) = load_err {
        set.abort_all();
        hub.objects.release_recent(project, person, &owned);
        return Err(e);
    }
    if let Some(n) = missing_pack {
        set.abort_all();
        // `n` was already verified owned by `person` in `project` above:
        // only a check-refusal discard (`state = DISCARDED, objects >= 0`)
        // answers `400`; consumption/purge or sweep answers `409` and keeps
        // live sibling uploads (`BUG-2851`).
        let rp = hub
            .objects
            .usable_for_receipts(project, person, std::slice::from_ref(&n))
            .await
            .map_err(Error::Other)?;
        if rp.vanished.contains(&n) || rp.usable.contains(&n) {
            hub.objects.release_recent(project, person, &owned);
            return Err(Error::conflict(DISCARDED_UPLOAD));
        }
        if let Err(e) = hub.objects.discard_refused(project, &owned).await {
            eprintln!("veil-server: discarding what a refused push uploaded: {e:#}");
        }
        return Err(Error::bad_request(BAD_PACK_UPLOAD));
    }
    Ok((
        Staged {
            at: Arc::new(HashMap::new()),
            packs: Arc::new(Vec::new()),
            held: Arc::new(held_packs),
            made: Default::default(),
            vanished: Arc::new(HashSet::new()),
            touched: Mutex::new(HashSet::new()),
        },
        owned,
    ))
}

/// Most bytes of uploaded objects one API commit may name. They are held
/// decoded for its checks under [`DECODING_IN_FLIGHT`] for every request
/// together (BUG-1156): a commit naming more than that takes all of it, so
/// one at a time.
pub const MAX_API_UPLOADS: u64 = MAX_FRAME_OBJECT as u64;

/// The objects an API commit's `receipts` name in its staged packs (S28),
/// read into memory for its checks (`changes`: what the commit keeps is
/// stored only once every check passed), at most [`MAX_API_UPLOADS`] bytes of
/// them decoded, held under the server-wide bound on decoded bytes (the
/// share returned: keep it while the objects are held, BUG-1156); and the
/// objects uploaded. [`settle_uploads`] discards the packs when the commit
/// is answered.
pub(crate) async fn take_uploads(
    hub: &Arc<Hub>,
    project: i64,
    person: i64,
    receipts: &std::collections::BTreeMap<ObjectId, String>,
) -> Result<(HashSet<ObjectId>, HashMap<ObjectId, Bytes>, Option<crate::store::ReadAhead>)> {
    let staged = receipted(hub, project, person, receipts);
    let st = staging(hub, project, person, &staged).await?;
    if !st.vanished.is_empty() {
        return Err(Error::conflict(DISCARDED_UPLOAD));
    }
    // What they decode to, from their first bytes, before anything is read
    // whole: the share is taken first (BUG-1397).
    let mut total = 0u64;
    let mut wanted = Vec::new();
    for (id, (name, slot)) in st.at.iter() {
        let Some(declared) = hub.objects.staged_declared(project, name, *slot, id).await.map_err(Error::Other)? else {
            return Err(Error::conflict(DISCARDED_UPLOAD));
        };
        total = total.saturating_add(declared);
        if total > MAX_API_UPLOADS {
            return Err(Error::bad_request(format!(
                "a commit through the API names at most {} MiB of uploaded objects: push larger changes with `vl push`",
                MAX_API_UPLOADS >> 20
            )));
        }
        wanted.push((*id, name.clone(), *slot));
    }
    let held = match total {
        0 => None,
        n => Some(crate::store::ReadAhead::wait(n).await),
    };
    // Then one at a time: read, decode (within what it declared), keep.
    let mut out = HashMap::new();
    for (id, name, slot) in wanted {
        let Some(enc) = hub.objects.staged_encoding(project, &name, slot, &id).await.map_err(Error::Other)? else {
            return Err(Error::conflict(DISCARDED_UPLOAD));
        };
        let raw = tokio::task::spawn_blocking(move || -> veil_core::Result<Bytes> {
            Ok(match encoding::decode(&id, &enc, MAX_API_UPLOADS)? {
                Cow::Owned(v) => Bytes::from(v),
                Cow::Borrowed(_) => enc.clone(),
            })
        })
        .await
        .map_err(|e| Error::Other(e.into()))?
        .map_err(Error::client_object)?;
        out.insert(id, raw);
    }
    Ok((out.keys().copied().collect(), out, held))
}

/// After an API commit with `receipts` was answered with `outcome`: its
/// staged packs are discarded when it landed (what it kept was stored) or
/// its checks refused it (BUG-930); not after a lost race (409: every check
/// passed, and the caller may try again with the same receipts) or a
/// database error the request is run again for (`db::retry_requests`
/// reads them again).
pub(crate) async fn settle_uploads<T>(
    hub: &Arc<Hub>,
    project: i64,
    person: i64,
    receipts: &std::collections::BTreeMap<ObjectId, String>,
    outcome: &Result<T>,
) {
    let mut names: Vec<Arc<str>> = receipted(hub, project, person, receipts).into_values().collect();
    names.sort();
    names.dedup();
    match outcome {
        Ok(_) => {
            if let Err(e) = hub.objects.discard_consumed(project, &names).await {
                eprintln!("veil-server: discarding staged uploads: {e:#}");
            }
        }
        Err(Error::Api { status, .. }) if is_check_refusal(*status) => {
            if let Err(e) = hub.objects.discard_refused(project, &names).await {
                eprintln!("veil-server: discarding staged uploads: {e:#}");
            }
        }
        Err(_) => {
            hub.objects.release_recent(project, person, &names);
        }
    }
}

/// Check uploaded objects (`docs/HUB.md` §4.5) and stage them (S28). Each
/// frame, plain or compressed (`docs/HUB.md` §13.15), is decoded (bounded:
/// at most the object size limit each, at most `limit` bytes for the whole
/// request, a compressed one only if it expands at most
/// [`encoding::MAX_RATIO`] times its size, and at most
/// [`DECODING_IN_FLIGHT`] bytes across the server at once: BUG-1009),
/// re-hashed against its id, and must decode canonically (safe names,
/// sorted trees) at a repository format the server serves. It is kept as
/// the server's own encoding of it, never as the client sent it, so no
/// client chooses the stored bytes of an object others share (BUG-1008).
/// The request's objects are written as **one staged pack** (one storage
/// write), which nobody reads but a push or API commit of the same person
/// that names it or shows its receipts; a push that lands lists it, a refused
/// one deletes it (BUG-930). Returns `Uploaded` with one receipt per object
/// in order (made whether or not the project held it already, so the answer is
/// the same either way) and the unique staged pack names written (BUG-1150).
pub async fn upload(hub: &Arc<Hub>, project: i64, person: i64, body: Bytes, limit: u64) -> Result<veil_core::hub::wire::Uploaded> {
    // The checks, decoding and compressing on a blocking thread.
    let rt = Handle::current();
    let mut frames: Vec<(ObjectId, Bytes)> = tokio::task::spawn_blocking(move || -> Result<Vec<(ObjectId, Bytes)>> {
        let mut left = limit;
        let mut out = Vec::new();
        for (id, enc) in encoding::split_frames(&body).map_err(Error::client_object)? {
            if !encoding::within_ratio(enc) {
                return Err(Error::bad_request(format!(
                    "object {} expands more than {} times its compressed size: send it uncompressed",
                    id.short(),
                    encoding::MAX_RATIO
                )));
            }
            // Bytes decoded from a compressed frame count against the
            // server-wide bound while they are held.
            let _decoding = match encoding::is_compressed(enc) {
                true => {
                    let n = encoding::decoded_len(enc).unwrap_or(0).min(DECODING_IN_FLIGHT as u64) as u32;
                    Some(rt.block_on(DECODING.acquire_many(n)).map_err(|e| Error::Other(e.into()))?)
                }
                false => None,
            };
            let raw = encoding::decode(&id, enc, left.min(MAX_FRAME_OBJECT as u64)).map_err(Error::client_object)?;
            left -= raw.len() as u64;
            if Object::min_repo_format(&raw) > veil_core::repo::REPO_FORMAT {
                return Err(Error::bad_request("an object of a newer format than this server serves"));
            }
            // Any bytes are a blob: decoding one would only copy it.
            if !raw.starts_with(b"veil:blob\n") {
                Object::decode(&raw).map_err(Error::client_object)?;
            }
            // The server's own encoding of what it decoded (BUG-1008). Each
            // is its own allocation: a slice would keep the whole body
            // alive in the object cache (BUG-860).
            let compressed = match encoding::encode(&raw) {
                Cow::Owned(z) => Some(z),
                Cow::Borrowed(_) => None,
            };
            let stored = match (compressed, raw) {
                (Some(z), _) => Bytes::from(z),
                (None, Cow::Owned(r)) => Bytes::from(r),
                (None, Cow::Borrowed(r)) => Bytes::copy_from_slice(r),
            };
            out.push((id, stored));
        }
        Ok(out)
    })
    .await
    .map_err(|e| Error::Other(e.into()))??;
    if frames.is_empty() {
        return Ok(veil_core::hub::wire::Uploaded::default());
    }
    let mut receipts = Vec::with_capacity(frames.len());
    let mut packs = Vec::new();
    let mut seen_packs: HashSet<Arc<str>> = HashSet::new();
    while !frames.is_empty() {
        let rest = if frames.len() > crate::pack::MAX_OBJECTS {
            frames.split_off(crate::pack::MAX_OBJECTS)
        } else {
            Vec::new()
        };
        let ids: Vec<ObjectId> = frames.iter().map(|(id, _)| *id).collect();
        // Encodings, checked above: staged as they are, never encoded again.
        let pack = crate::store::own(hub.objects.stage(project, person, frames)).await.map_err(Error::Other)?;
        if seen_packs.insert(pack.clone()) {
            packs.push(pack.to_string());
        }
        receipts.extend(ids.iter().map(|id| receipt(hub, project, person, id, &pack)));
        frames = rest;
    }
    Ok(veil_core::hub::wire::Uploaded {
        stored: receipts.len(),
        receipts,
        packs,
    })
}

/// Store `objects` (canonical encodings; compressed by the store) in
/// `project`, at most [`PUTS_AT_ONCE`] at a time (an object store answers a
/// flood with "slow down": BUG-1053).
pub async fn put_all(hub: &Arc<Hub>, project: i64, objects: impl IntoIterator<Item = (ObjectId, Bytes)>) -> Result<()> {
    let mut set = tokio::task::JoinSet::new();
    let mut it = objects.into_iter();
    let at_once = hub.objects.blob_store().writes_at_once().max(1);
    loop {
        while set.len() < at_once {
            let Some((id, b)) = it.next() else { break };
            let h = hub.clone();
            set.spawn(async move { h.objects.put(project, &id, b).await });
        }
        match set.join_next().await {
            Some(r) => r.map_err(|e| Error::Other(e.into()))??,
            None => break,
        }
    }
    Ok(())
}

/// Bytes decoded from compressed uploads the server holds at once, across
/// every request (BUG-1009); an object larger than this takes all of it.
pub use crate::store::DECODED_IN_FLIGHT as DECODING_IN_FLIGHT;
use crate::store::DECODED as DECODING;

/// Most object writes one request has in flight ([`put_all`]), unless the
/// store says otherwise (`BlobStore::writes_at_once`: a local directory).
pub const PUTS_AT_ONCE: usize = 64;
