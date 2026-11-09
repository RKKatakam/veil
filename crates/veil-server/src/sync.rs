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
    sync::Arc,
};

use bytes::Bytes;
use tokio::runtime::Handle;
use veil_core::{
    hub::{
        access::{AccessPolicy, View},
        project::{Change, Graft, Node, Projector, TreeSource},
        encoding,
        wire::{put_frame, BranchResult, PushRequest, PushResult, Want, MAX_FRAME_OBJECT},
    },
    object::{EntryKind, Object, Snapshot, Tree, Visibility},
    policy::{Policy, Tier, POLICY_FILE},
    ObjectId, VPath, VeilError,
};

use crate::{
    error::{Error, Result},
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

/// The id of the universal root snapshot (every history starts there).
pub fn root_snapshot_id() -> ObjectId {
    let empty = ObjectId::hash(&Object::Tree(Tree::default()).encode());
    ObjectId::hash(&Object::Snapshot(Snapshot::root(empty)).encode())
}

/// Every history starts at the universal root and its empty tree, which no
/// project stores.
pub(crate) fn builtin(id: &ObjectId) -> Option<Bytes> {
    let empty = Object::Tree(Tree::default()).encode();
    if *id == ObjectId::hash(&empty) {
        return Some(Bytes::from(empty));
    }
    let root = Object::Snapshot(Snapshot::root(ObjectId::hash(&empty))).encode();
    (*id == ObjectId::hash(&root)).then(|| Bytes::from(root))
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
}

impl Source {
    pub fn raw(&self, id: &ObjectId) -> veil_core::Result<Bytes> {
        if let Some(raw) = self.pending.get(id) {
            return Ok(raw.clone());
        }
        if let Some(b) = builtin(id) {
            return Ok(b);
        }
        self.hub
            .objects
            .get_blocking(&self.rt, self.project, id)
            .map_err(|e| VeilError::Repo(format!("object store: {e}")))?
            .ok_or(VeilError::Missing(*id))
    }

    /// Object `id` as stored ([`crate::store::Objects::get_encoded`]).
    pub fn encoded(&self, id: &ObjectId) -> veil_core::Result<Bytes> {
        if let Some(b) = builtin(id) {
            return Ok(b);
        }
        self.rt
            .block_on(self.hub.objects.get_encoded(self.project, id))
            .map_err(|e| VeilError::Repo(format!("object store: {e}")))?
            .ok_or(VeilError::Missing(*id))
    }

    pub fn snapshot(&self, id: &ObjectId) -> veil_core::Result<Arc<Snapshot>> {
        match Object::decode(&self.raw(id)?)? {
            Object::Snapshot(s) => Ok(Arc::new(s)),
            o => Err(VeilError::Corrupt(id.hex(), format!("expected a snapshot, found a {}", o.kind_name()))),
        }
    }
}

impl TreeSource for Source {
    fn node(&self, id: &ObjectId) -> veil_core::Result<Node> {
        let ck = crate::store::Objects::tree_key(self.project, id);
        if let Some(t) = self.hub.trees.get(&ck) {
            return Ok(Node::Tree(t.0, t.1));
        }
        let raw = self.raw(id)?;
        let Some(enc) = Object::tree_encoding(&raw) else {
            return Ok(Node::Leaf);
        };
        match Object::decode(&raw)? {
            Object::Tree(t) => {
                let t = Arc::new(t);
                self.hub.trees.insert(ck, (t.clone(), enc), tree_weight(&t));
                Ok(Node::Tree(t, enc))
            }
            _ => Ok(Node::Leaf),
        }
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
    let src = Source {
        hub: hub.clone(),
        project,
        rt: Handle::current(),
        pending,
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
        match Box::pin(projected_inner(hub, project, viewer, real, None)).await {
            Err(e) if e.is_retryable() && std::time::Instant::now() < deadline => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
            r => return r,
        }
    }
}

/// What a push made and has not committed yet: the pusher's projections of
/// its new snapshots are worked out before its transaction and written in it
/// (one commit per push, `storage-and-cost.md` §3).
#[derive(Default)]
struct Deferred {
    /// The push's new real snapshots, each with the pusher's own snapshot
    /// the server completed it from.
    fresh: HashMap<ObjectId, Option<ObjectId>>,
    /// Memo rows `(view key, real, projected)` for the push's transaction.
    rows: Vec<(String, ObjectId, ObjectId)>,
    /// Those of them whose real snapshot collapsed into its first parent's
    /// projection (a change hidden from that view).
    collapsed: HashSet<ObjectId>,
}

/// Is `id` committed history of `project` (a `snapshots` row; never deleted,
/// so a yes is cached)?
async fn committed(hub: &Hub, project: i64, id: &ObjectId) -> Result<bool> {
    if hub.caches.committed(project, id) {
        return Ok(true);
    }
    let stored: Option<String> = sqlx::query_scalar("SELECT id FROM snapshots WHERE project_id = $1 AND id = $2")
        .bind(project)
        .bind(id.hex())
        .fetch_optional(&hub.db)
        .await?;
    if stored.is_some() {
        hub.caches.put_committed(project, id);
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
        let same = blocking(hub, project.id, move |src| Ok(src.snapshot(&pp2)?.change_id == src.snapshot(&p)?.change_id)).await?;
        if same && !out.contains(&pp) {
            out.push(pp);
        }
    }
    Ok(out)
}

async fn projected_inner(
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
            let mine = deferred.as_ref().and_then(|d| d.rows.iter().find(|(k, r, _)| *k == view_key && *r == x).map(|(_, _, p)| *p));
            let memo = match mine {
                Some(p) => Some(p),
                None if fresh => None,
                None => match hub.caches.memo(project.id, &view_key, &x) {
                    Some(p) => Some(p),
                    None => {
                        let m: Option<String> =
                            sqlx::query_scalar("SELECT projected_id FROM projections WHERE project_id = $1 AND view_key = $2 AND real_id = $3")
                                .bind(project.id)
                                .bind(&view_key)
                                .bind(x.hex())
                                .fetch_optional(&hub.db)
                                .await?;
                        let m = m.map(|p| ObjectId::from_hex(&p).map_err(|e| Error::Other(e.into()))).transpose()?;
                        if let Some(p) = &m {
                            hub.caches.put_memo(project.id, &view_key, &x, p);
                        }
                        m
                    }
                },
            };
            if let Some(p) = memo {
                done.insert(x, p);
                continue;
            }
            let s = blocking(hub, project.id, move |src| Ok(src.snapshot(&x)?)).await?;
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
        let first_pp = (s.parents.len() == 1).then(|| pparents.first().copied()).flatten();
        let (result, new_obj) = blocking(hub, project.id, move |src| {
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
        if let Some(raw) = new_obj {
            hub.objects.put(project.id, &result, raw).await?;
        }
        // A change hidden from this view: it collapsed into its parent's
        // projection (`projections.collapsed`, BUG-1468).
        let collapsed = first_pp == Some(result);
        let result = match deferred.as_deref_mut() {
            Some(d) => {
                d.rows.push((view_key.clone(), x, result));
                if collapsed {
                    d.collapsed.insert(x);
                }
                result
            }
            None => {
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
                // Another request stored it first: every server answers what
                // is stored.
                let stored = if inserted == 1 {
                    result
                } else {
                    let p: String =
                        sqlx::query_scalar("SELECT projected_id FROM projections WHERE project_id = $1 AND view_key = $2 AND real_id = $3")
                            .bind(project.id)
                            .bind(&view_key)
                            .bind(x.hex())
                            .fetch_one(&hub.db)
                            .await?;
                    ObjectId::from_hex(&p).map_err(|e| Error::Other(e.into()))?
                };
                hub.caches.put_memo(project.id, &view_key, &x, &stored);
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
    if *id == root_snapshot_id() || hub.caches.committed(project, id) {
        return Ok(vec![*id]);
    }
    if let Some(real) = hub.caches.resolved(project, view_key, id) {
        return Ok(vec![real]);
    }
    resolve_stored(hub, project, id).await
}

/// [`resolve`] as the database answers it now, newest first (a push picks
/// the real parent it grafts on from it), in one statement.
async fn resolve_stored(hub: &Hub, project: i64, id: &ObjectId) -> Result<Vec<ObjectId>> {
    if *id == root_snapshot_id() || hub.caches.committed(project, id) {
        return Ok(vec![*id]);
    }
    let rows: Vec<(String, i32, i64)> = sqlx::query_as(
        "SELECT id, 0, 0::BIGINT FROM snapshots WHERE project_id = $1 AND id = $2 \
         UNION ALL SELECT real_id, 1, created_at FROM projections WHERE project_id = $1 AND projected_id = $2 \
         ORDER BY 2, 3 DESC",
    )
    .bind(project)
    .bind(id.hex())
    .fetch_all(&hub.db)
    .await?;
    if rows.first().is_some_and(|r| r.1 == 0) {
        hub.caches.put_committed(project, id);
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
    if *id == root_snapshot_id() {
        return Ok(Some(*id));
    }
    let seen = |r: ObjectId| async move { Ok::<bool, Error>(projected(hub, project, viewer, r).await? == *id) };
    let mut names: Vec<&str> = branches.to_vec();
    names.push(&project.default_branch);
    let tips: Vec<(String, String)> = sqlx::query_as("SELECT name, target FROM branches WHERE project_id = $1 AND name = ANY($2)")
        .bind(project.id)
        .bind(names.iter().map(|n| n.to_string()).collect::<Vec<_>>())
        .fetch_all(&hub.db)
        .await?;
    for name in &names {
        if let Some(t) = tips.iter().find(|(n, _)| n == name).and_then(|(_, t)| ObjectId::from_hex(t).ok()) {
            if seen(t).await? {
                return Ok(Some(t));
            }
        }
    }
    // Committed history named by its own id (after the tips: a snapshot
    // they see whole under a change hidden from them at the tip, BUG-1525).
    if committed(hub, project.id, id).await? {
        return Ok(seen(*id).await?.then_some(*id));
    }
    let key = project.view(viewer).key();
    let rows: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT p.real_id, g.parents FROM projections p LEFT JOIN graph g ON g.project_id = p.project_id AND g.snapshot = p.real_id \
         WHERE p.project_id = $1 AND p.view_key = $2 AND p.projected_id = $3 LIMIT $4",
    )
    .bind(project.id)
    .bind(&key)
    .bind(id.hex())
    .bind(NEWEST_BOUND as i64 + 1)
    .fetch_all(&hub.db)
    .await?;
    let own = || async {
        let own: Vec<String> = sqlx::query_scalar(
            "SELECT real_id FROM projections WHERE project_id = $1 AND view_key = $2 AND projected_id = $3 AND NOT collapsed ORDER BY real_id LIMIT 2",
        )
        .bind(project.id)
        .bind(&key)
        .bind(id.hex())
        .fetch_all(&hub.db)
        .await?;
        Ok::<Option<ObjectId>, Error>(match own.as_slice() {
            [o] => ObjectId::from_hex(o).ok(),
            _ => None,
        })
    };
    let pick = if rows.is_empty() {
        None
    } else if rows.len() > NEWEST_BOUND {
        own().await?
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
        let read = blocking(hub, project.id, move |src| {
            unread.iter().map(|r| Ok((*r, src.snapshot(r)?.parents.first().copied()))).collect::<Result<Vec<_>>>()
        })
        .await?;
        cands.extend(read);
        let firsts: HashSet<ObjectId> = cands.iter().filter_map(|c| c.1).collect();
        let mut leaves: Vec<ObjectId> = cands.iter().map(|c| c.0).filter(|c| !firsts.contains(c)).collect();
        leaves.sort();
        match leaves.as_slice() {
            [one] => Some(*one),
            _ => match own().await? {
                Some(o) => Some(o),
                None if landing => leaves.first().copied(),
                None => {
                    return Err(Error::conflict(format!(
                        "snapshot {} stands for changes on different lines as you see them: make the change on a branch's tip, or land it",
                        id.short()
                    )))
                }
            },
        }
    };
    if let Some(r) = pick {
        // A memo of their view that no longer projects to it: their view
        // is changing under them.
        return match seen(r).await? {
            true => Ok(Some(r)),
            false => Err(crate::query::graph::warming()),
        };
    }
    let named = *id;
    let cid = blocking(hub, project.id, move |src| match src.snapshot(&named) {
        Ok(s) => Ok(Some(s.change_id.to_string())),
        Err(VeilError::Missing(_)) => Ok(None),
        Err(e) => Err(e.into()),
    })
    .await?;
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

/// Branch tips as `viewer` sees them. The branch rows come from this
/// server's memory for at most `caches::TIPS_TTL`, dropped at every push's
/// notice; each viewer's projection is of their current view.
pub async fn tips(hub: &Arc<Hub>, project: &Project, viewer: &Viewer) -> Result<Vec<(String, ObjectId)>> {
    use crate::caches::TipsLookup;
    let rows = loop {
        match hub.caches.tips(project.id) {
            TipsLookup::Hit(rows) => break rows,
            TipsLookup::Wait(done) => {
                let woken = done.notified();
                tokio::pin!(woken);
                woken.as_mut().enable();
                if hub.caches.tips_reading(project.id, &done) {
                    // A read whose request was dropped never wakes anyone:
                    // after TIPS_TTL the next asker reads.
                    let _ = tokio::time::timeout(crate::caches::TIPS_TTL, woken).await;
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
                    Ok(rows) => {
                        hub.caches.put_tips(project.id, read, at, rows.clone());
                        break Arc::new(rows);
                    }
                    Err(e) => {
                        hub.caches.tips_failed(project.id, read);
                        return Err(e.into());
                    }
                }
            }
        }
    };
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
    tips: &[ObjectId],
    stop: &[ObjectId],
    limit: Option<usize>,
    encoded: bool,
    reads: u32,
) -> Result<Vec<u8>> {
    let mut starts = Vec::new();
    let mut reals = Vec::new();
    for t in tips {
        let Some(real) = resolve(hub, project.id, &project.view(viewer).key(), t).await?.into_iter().next() else {
            return Err(Error::not_found(format!("no snapshot {} that you can see", t.short())));
        };
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
        let branch_tips: HashSet<ObjectId> = self::tips(hub, project, viewer).await?.into_iter().map(|(_, t)| t).collect();
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
pub async fn fetch(hub: &Arc<Hub>, project: &Project, viewer: &Viewer, snapshot: ObjectId, wants: Vec<Want>, encoded: bool) -> Result<FrameStream> {
    // Each want is checked in its own snapshot (revision 1), as the viewer
    // sees it.
    let mut reals: HashMap<ObjectId, ObjectId> = HashMap::new();
    for snap in std::iter::once(snapshot).chain(wants.iter().filter_map(|w| w.snapshot)) {
        if reals.contains_key(&snap) {
            continue;
        }
        let Some(real) = resolve(hub, project.id, &project.view(viewer).key(), &snap).await?.into_iter().next() else {
            return Err(Error::not_found(format!("no snapshot {} that you can see", snap.short())));
        };
        reals.insert(snap, real);
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
        Ok(match get(&id)? {
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
    if !viewer.agent {
        return Ok(None);
    }
    let (v, text, bindings) = (viewer.clone(), project.policy_text.clone(), project.bindings.clone());
    let default = branch == project.default_branch;
    blocking_with(hub, project.id, pending, move |src| {
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
            match stored_tree(src, id) {
                Err(VeilError::Missing(_)) => Ok(None),
                r => r,
            }
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
    let Node::Tree(t, _) = src.node(tree)? else {
        return Ok(String::new());
    };
    let Some(e) = t.get(POLICY_FILE) else {
        return Ok(String::new());
    };
    match Object::decode(&src.raw(&e.id)?)? {
        Object::Blob(b) if e.kind == EntryKind::File => Ok(String::from_utf8_lossy(&b).into_owned()),
        _ => Err(Error::forbidden(".veilpolicy must be a plain-text file")),
    }
}

/// The entry at `path` in real tree `tree`.
pub(crate) fn entry_at(src: &Source, tree: &ObjectId, path: &str) -> Result<Option<veil_core::TreeEntry>> {
    let mut cur = *tree;
    let parts: Vec<&str> = path.split('/').collect();
    for (i, part) in parts.iter().enumerate() {
        let Node::Tree(t, _) = src.node(&cur)? else {
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
        if let Object::Conflict(c) = Object::decode(&src.raw(&e.id)?)? {
            out.extend(c.referenced_ids());
        }
    }
    Ok(out)
}

/// A common ancestor of real snapshots `a` and `b` (the universal root at
/// worst): both histories are walked a generation at a time until one
/// reaches a snapshot the other has seen.
fn common_ancestor(src: &Source, a: ObjectId, b: ObjectId) -> Result<ObjectId> {
    let root = root_snapshot_id();
    let mut seen = [HashSet::new(), HashSet::new()];
    let mut queue = [std::collections::VecDeque::from([a]), std::collections::VecDeque::from([b])];
    loop {
        let mut walked = false;
        for side in 0..2 {
            let Some(x) = queue[side].pop_front() else { continue };
            walked = true;
            if seen[1 - side].contains(&x) {
                return Ok(x);
            }
            if seen[side].insert(x) && x != root {
                queue[side].extend(src.snapshot(&x)?.parents.iter().copied());
            }
        }
        if !walked {
            return Ok(root);
        }
    }
}

/// Check the paths one snapshot changes: write access, personal keys,
/// secrets sealed, nothing local-only, no secret in a plain-text file
/// (`docs/HUB.md` §4.5, checks 2, 8 and 9). `parents` are the snapshot's
/// real parents; `accepted` is the project's accepted `.veilpolicy`.
fn check_changes(
    src: &Source,
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
    let mut others: Vec<(ObjectId, Option<ObjectId>)> = Vec::new();
    for p in parents.iter().skip(1) {
        others.push((src.snapshot(p)?.tree, None));
    }
    for c in changes {
        // (A narrowed session's changes outside its paths never get here:
        // `narrowing_gate` refused them first, naming nothing; every refusal
        // below names its path.)
        // Taken from another parent of a merge, where that parent's side
        // changed it since the common ancestor: the merge takes a change
        // someone who could write it made. Taking the version the first
        // parent replaced is a revert, a write like any other.
        let mut from_other = false;
        if !view.write(&c.path) {
            for (i, (tree, base)) in others.iter_mut().enumerate() {
                if entry_at(src, tree, &c.path)? != c.new {
                    continue;
                }
                let base = match base {
                    Some(b) => *b,
                    None => *base.insert(src.snapshot(&common_ancestor(src, parents[0], parents[i + 1])?)?.tree),
                };
                if entry_at(src, &base, &c.path)? != c.new {
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
            EntryKind::Conflict => match Object::decode(&src.raw(&e.id)?)? {
                Object::Conflict(cf) => cf.adds.iter().chain(&cf.removes).flatten().map(|t| (t.id, t.visibility.clone(), t.size)).collect(),
                _ => return Err(Error::bad_request(format!("'{}': a conflict entry names something else", c.path))),
            },
            _ => continue,
        };
        let vp = VPath::new(&c.path).map_err(|_| Error::bad_request(format!("invalid path '{}'", c.path)))?;
        let class = policy.classify(&vp, false);
        // Check 9 (below) is off only where `public!` says so in the
        // accepted policy (an admin's), or in an admin's own change: anyone
        // may turn `public` into `public!`, which is the same access.
        let unscanned = class.allow_secrets && (admin || accepted.classify(&vp, false).allow_secrets);
        for (id, visibility, size) in contents {
            let raw = src.raw(&id)?;
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
                if let Object::Blob(data) = Object::decode(&raw)? {
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
fn sealed_secret_here(src: &Source, c: &Change, changes: &[Change], parents: &[ObjectId], visibility: &Visibility) -> Result<bool> {
    let Visibility::Cloaked { scope } = visibility else { return Ok(false) };
    veil_core::policy::sealed_secret(
        &c.path,
        scope,
        false,
        |path| {
            for p in parents {
                if entry_at(src, &src.snapshot(p)?.tree, path)?.is_some_and(|e| !e.visibility.is_public()) {
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
/// same change; no parent may be one.
#[allow(clippy::too_many_arguments)]
pub(crate) fn complete(
    src: &Source,
    p: &Project,
    viewer: &Viewer,
    uploaded: &HashSet<ObjectId>,
    n: &Snapshot,
    rp: &[ObjectId],
    ra: &[ObjectId],
    identity: &veil_core::Identity,
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
    let real_tree = g.root(n.tree, Some(ptrees[0]))?;
    // A merge must not change what the pusher cannot see.
    for other in &ptrees[1..] {
        let mut g2 = Graft::new(src, &view).proving(uploaded, ptrees.clone());
        if g2.root(n.tree, Some(*other))? != real_tree && !admin {
            // Compare the hidden parts: the same full tree from either side.
            return Err(Error::forbidden(
                "this merge combines changes in folders you cannot see; ask someone with access to merge it",
            ));
        }
    }
    let mut trees: Vec<(ObjectId, Vec<u8>)> = g.created.drain().collect();
    trees.sort();
    // Store the trees the graft built before checking (the check reads them).
    for (id, raw) in &trees {
        src.rt.block_on(src.hub.objects.put(src.project, id, Bytes::from(raw.clone())))?;
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
        let known = |id: &ObjectId| uploaded.contains(id) || before.contains(id);
        if !known(&e.id) {
            return Err(VeilError::Missing(e.id).into());
        }
        if let Some(id) = named_ids(src, e)?.into_iter().find(|id| !known(id)) {
            return Err(VeilError::Missing(id).into());
        }
    }
    check_changes(src, &view, &g.changes, &real_tree, rp, &Policy::parse(&p.policy_text), admin)?;
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
            let text = match Object::decode(&src.raw(&e.id)?)? {
                Object::Blob(b) if e.kind == EntryKind::File => String::from_utf8_lossy(&b).into_owned(),
                _ => return Err(Error::bad_request(".veilrules must be a plain-text file")),
            };
            crate::landing::rules::Rules::parse(&text).map_err(Error::bad_request)?;
        }
    }
    let mut real = n.clone();
    real.tree = real_tree;
    real.parents = rp.to_vec();
    real.attempts = ra.to_vec();
    if real == *n {
        return Ok(Completed {
            real: ObjectId::hash(&Object::Snapshot(real).encode()),
            raw: None,
            origin: None,
        });
    }
    real.sign(identity);
    let raw = Object::Snapshot(real).encode();
    Ok(Completed {
        real: ObjectId::hash(&raw),
        raw: Some(Bytes::from(raw)),
        origin: None,
    })
}

/// One new snapshot, completed.
pub(crate) struct Completed {
    pub real: ObjectId,
    pub raw: Option<Bytes>,
    /// The pusher's own snapshot, when the server completed it.
    pub origin: Option<ObjectId>,
}

/// Handle a push (`docs/HUB.md` §4.5): complete and check every new
/// snapshot, store what the server built, then move every branch in one
/// transaction of compare-and-swaps, which also writes the snapshot,
/// origin, projection memo and audit rows: **one database commit per push**
/// (`storage-and-cost.md` §3). Other viewers' projections are worked out when
/// they first ask, as before.
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
    if req.updates.len() > MAX_PUSH_UPDATES {
        return Err(Error::bad_request(format!("at most {MAX_PUSH_UPDATES} branch updates per push")));
    }
    let root = root_snapshot_id();
    // Current tips (always from the database: a push never trusts a cache),
    // to pick which real snapshot a projected parent stands for (the
    // branch's tip when it projects to it).
    let current: HashMap<String, ObjectId> = {
        let rows: Vec<(String, String)> = sqlx::query_as("SELECT name, target FROM branches WHERE project_id = $1")
            .bind(project.id)
            .fetch_all(&hub.db)
            .await?;
        rows.into_iter().filter_map(|(n, t)| ObjectId::from_hex(&t).ok().map(|t| (n, t))).collect()
    };
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
    let moved_names: Vec<&str> = req.updates.iter().map(|u| u.branch.as_str()).collect();
    // Every update lands through the landing service (its edits on the tip),
    // none moves a branch here.
    let lands_only = !req.force && req.updates.iter().all(|u| land_all || protected.contains(&u.branch));
    // What this pusher uploaded (BUG-824): only that may be new here; any
    // other name is "not uploaded", whether or not the server holds a
    // snapshot by it they cannot see (BUG-1523).
    let uploaded = Arc::new(receipted(hub, project.id, person, &req.receipts));
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
        if let Some(r) = resolve_for(hub, project, viewer, &id, &moved_names, lands_only).await? {
            known.insert(id, vec![r]);
            continue;
        }
        if !uploaded.contains(&id) {
            return Err(Error::bad_request(format!("snapshot {} was not uploaded", id.short())));
        }
        let s = blocking(hub, project.id, move |src| match src.snapshot(&id) {
            Err(VeilError::Missing(_)) => Err(Error::bad_request(format!("snapshot {} was not uploaded", id.short()))),
            r => Ok(r?),
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
        let mut st: Vec<(ObjectId, bool)> = new.iter().map(|id| (*id, false)).collect();
        while let Some((id, expanded)) = st.pop() {
            if placed.contains(&id) || !parents_of.contains_key(&id) {
                continue;
            }
            if expanded {
                placed.insert(id);
                order.push(id);
            } else {
                st.push((id, true));
                for p in parents_of[&id].parents.iter().chain(&parents_of[&id].attempts) {
                    st.push((*p, false));
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
    let signers: HashMap<String, i64> =
        sqlx::query_as::<_, (String, i64)>("SELECT signing_key, person_id FROM devices WHERE signing_key = ANY($1) AND removed_at IS NULL AND NOT pending")
            .bind(&keys)
            .fetch_all(&hub.db)
            .await?
            .into_iter()
            .collect();
    let mut real_of: HashMap<ObjectId, ObjectId> = HashMap::new();
    real_of.insert(root, root);
    for (id, reals) in &known {
        let r = reals[0];
        real_of.insert(*id, r);
    }
    // 2. Complete and check each new snapshot (`uploaded`: a push names
    // nothing else that is not already where it was in a parent, BUG-824).
    let mut completed: Vec<Completed> = Vec::new();
    // Each new real snapshot's real parents and signer (`people.id`).
    let mut real_parents_of: HashMap<ObjectId, (Vec<ObjectId>, i64)> = HashMap::new();
    let mut real_attempts_of: HashMap<ObjectId, Vec<ObjectId>> = HashMap::new();
    for id in &order {
        let n = parents_of[id].clone();
        if n.embargo.is_some() {
            return Err(Error::forbidden(
                "embargoed merges cannot be pushed to the server yet (docs/HUB.md §11)",
            ));
        }
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
        let real_parents: Vec<ObjectId> = n.parents.iter().map(|p| real_of[p]).collect();
        let real_attempts: Vec<ObjectId> =
            n.attempts.iter().map(|a| real_of.get(a).copied().ok_or_else(|| Error::bad_request("an attempt is not a snapshot of this project"))).collect::<Result<_>>()?;
        let (policy_text_acc, bindings, viewer2, n2) = (project.policy_text.clone(), project.bindings.clone(), viewer.clone(), n.clone());
        let hub2 = hub.clone();
        let rp = real_parents.clone();
        let ra = real_attempts.clone();
        let uploaded = uploaded.clone();
        let c = blocking(hub, project.id, move |src| {
            let p = Project {
                id: src.project,
                name: String::new(),
                default_branch: String::new(),
                policy: AccessPolicy::parse(&policy_text_acc),
                policy_text: policy_text_acc,
                bindings,
            };
            complete(src, &p, &viewer2, &uploaded, &n2, &rp, &ra, &hub2.identity)
        })
        .await?;
        let c = Completed {
            origin: c.raw.as_ref().map(|_| *id),
            ..c
        };
        if let Some(raw) = &c.raw {
            hub.objects.put(project.id, &c.real, raw.clone()).await?;
        }
        real_of.insert(*id, c.real);
        // What its landing records: its parents and author (S17, BUG-1581);
        // its attempts (S11) are recorded with it, but are no branch's
        // history: kept apart, so that no attempt counts as landed.
        real_parents_of.insert(c.real, (real_parents, author));
        real_attempts_of.insert(c.real, real_attempts);
        completed.push(c);
    }
    // 3. Move the branches: one serialisable transaction of compare-and-swaps.
    let mut plans = Vec::new();
    let mut queued: Vec<crate::landing::Queued> = Vec::new();
    let mut results = Vec::new();
    // New branches, against the branches when the push began (concurrent
    // pushes may each add up to the bound).
    let created: HashSet<&str> = req.updates.iter().filter(|u| u.new.is_some() && !current.contains_key(&u.branch)).map(|u| u.branch.as_str()).collect();
    if !created.is_empty() && current.len() + created.len() > MAX_BRANCHES {
        return Err(Error::bad_request(format!("a project has at most {MAX_BRANCHES} branches")));
    }
    for u in &req.updates {
        if veil_core::commands::validate_tag_name(&u.branch).is_err() {
            return Err(Error::bad_request(format!("invalid branch name {:?}", u.branch)));
        }
        let cur = current.get(&u.branch).copied();
        // Landed by the landing service instead of moved here: the new
        // changes on top of whatever base they have (they need not be on
        // the tip), as one stack.
        if !req.force && (land_all || protected.contains(&u.branch)) && (cur.is_some() || land_all) {
            let Some(n) = u.new else {
                return Err(Error::forbidden(format!("'{}' is protected: only an admin's forced push deletes it", u.branch)));
            };
            let new_real = *real_of.get(&n).ok_or_else(|| Error::bad_request("unknown new tip"))?;
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
            let judged = match crate::landing::stack(hub, project, viewer, &u.branch, new_real, &real_parents_of).await? {
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
            if judged.stack.is_empty() {
                let mut msg = crate::landing::NOTHING_TO_LAND.to_string();
                let skipped = crate::landing::skipped_warnings(hub, project.id, &u.branch, &judged.skipped).await?;
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
            queued.push(crate::landing::Queued {
                ticket: crate::landing::ticket(),
                branch: u.branch.clone(),
                stack: judged.stack,
                lineage: judged.lineage,
                skipped: Arc::new(std::sync::Mutex::new(judged.skipped)),
            });
            continue;
        }
        let cur_seen = match cur {
            Some(c) => Some(projected(hub, project, viewer, c).await?),
            None => None,
        };
        if cur_seen != u.expected && !req.force {
            results.push(BranchResult {
                branch: u.branch.clone(),
                ok: false,
                message: Some("the branch has moved since you last pulled; pull, then push again".into()),
                tip: cur_seen,
                ticket: None,
            });
            continue;
        }
        let new_real = match u.new {
            Some(n) => Some(*real_of.get(&n).ok_or_else(|| Error::bad_request("unknown new tip"))?),
            None => None,
        };
        if let Some(n) = new_real {
            // An attempt never lands (`Snapshot::abandoned`).
            if blocking(hub, project.id, move |src| Ok(src.snapshot(&n)?.abandoned.is_some())).await? {
                return Err(Error::bad_request(format!("branch '{}': an abandoned attempt is never a branch's tip", u.branch)));
            }
        }
        if new_real.is_none() && !viewer.admin {
            return Err(Error::forbidden("only admins may delete a branch"));
        }
        if new_real.is_none() && viewer.agent {
            return Err(agent_refusal("an agent session never deletes a branch"));
        }
        // The one rule of every tip an agent session sets (`agent_tip`):
        // first, for a narrowed one, anything outside its paths; then the
        // files that decide access or review, a new default branch included.
        if let Some(n) = new_real {
            match agent_tip_of(hub, project, viewer, &u.branch, cur, n, HashMap::new()).await? {
                Some(AgentTip::Narrowed) => {
                    results.push(BranchResult {
                        branch: u.branch.clone(),
                        ok: false,
                        message: Some(NARROWED_MOVE.into()),
                        tip: cur_seen,
                    });
                    continue;
                }
                Some(AgentTip::Access) => return Err(agent_refusal(AGENT_ACCESS_MOVE)),
                Some(AgentTip::DefaultBranch) => return Err(agent_refusal(AGENT_DEFAULT_BRANCH)),
                None => {}
            }
        }
        if let (Some(c), Some(n)) = (cur, new_real) {
            if !req.force && !is_ancestor(hub, project.id, c, n).await? {
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
        // The default branch carries the accepted policy.
        let (mut accept, mut policy_text_update) = (None, None);
        if u.branch == project.default_branch {
            if let Some(n) = new_real {
                let text = blocking(hub, project.id, move |src| policy_text(src, &src.snapshot(&n)?.tree)).await?;
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
                let changed = blocking(hub, project.id, move |src| {
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
        plans.push((u.branch.clone(), cur, new_real, accept, policy_text_update));
    }
    // The pusher's projections of what this push moves branches to, worked
    // out now and written in its transaction (an admin's are the snapshots).
    let mut deferred = Deferred {
        fresh: completed.iter().map(|c| (c.real, c.origin)).collect(),
        rows: Vec::new(),
        collapsed: HashSet::new(),
    };
    for (_, _, new, _, _) in &plans {
        if let Some(n) = new {
            Box::pin(projected_inner(hub, project, viewer, *n, Some(&mut deferred))).await?;
        }
    }
    for q in &queued {
        Box::pin(projected_inner(hub, project, viewer, q.stack.last().expect("a stack is never empty").id, Some(&mut deferred))).await?;
    }
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
    let new_reals: Vec<(String, i64)> = completed
        .iter()
        .map(|c| (c.real.hex(), real_parents_of.get(&c.real).map_or(0, |(_, a)| *a)))
        .collect();
    let origins: Vec<(String, String)> = completed.iter().filter_map(|c| c.origin.map(|o| (c.real.hex(), o.hex()))).collect();
    let memos: Vec<(String, String, String, bool)> =
        deferred.rows.iter().map(|(k, r, p)| (k.clone(), r.hex(), p.hex(), deferred.collapsed.contains(r))).collect();
    // The changes each moved branch now holds that this push brought, by
    // change id and author (`landed_changes`, BUG-1522, BUG-1527).
    let change_of: HashMap<ObjectId, String> =
        real_of.iter().filter_map(|(pushed, real)| parents_of.get(pushed).map(|s| (*real, s.change_id.to_string()))).collect();
    let plan_changes: HashMap<_, _> = plans
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
    let notify = hub.caches.notices.load(std::sync::atomic::Ordering::SeqCst);
    let pid = project.id;
    let plans2 = plans.clone();
    let force = req.force;
    let (queued2, who2) = (queued.clone(), who.clone());
    // Whoever lands here hears at once (registered before the commit).
    let waiters: Vec<crate::landing::Waiter> = queued.iter().map(|q| hub.landing.register(&q.ticket)).collect();
    // Nothing to move (every update refused: the pusher pulls and tries
    // again): no commit, and nothing recorded as history no branch reaches.
    let (moved, memo_stored) = if plans.is_empty() && queued.is_empty() {
        (Vec::new(), Vec::new())
    } else {
        let r = crate::db::transaction(&hub.db, crate::db::Isolation::ReadCommitted, move |c| {
        let plans = plans2.clone();
        let plan_changes = plan_changes.clone();
        let new_reals = new_reals.clone();
        let origins = origins.clone();
        let memos = memos.clone();
        let (queued, who) = (queued2.clone(), who2.clone());
        Box::pin(async move {
            for q in &queued {
                crate::landing::insert(&mut *c, pid, &who, q).await?;
            }
            let mut moved = Vec::new();
            let mut lineages: Vec<(String, i64)> = Vec::new();
            for (branch, cur, new, accept, policy_text_update) in plans {
                let rows = match (cur, new) {
                    // A forced update starts a new lineage (BUG-1300): what the
                    // landing service recorded of the branch no longer counts.
                    (Some(c0), Some(n)) => sqlx::query_scalar::<_, i64>(
                        "UPDATE branches SET target = $1, lineage = CASE WHEN $5 THEN nextval('branch_lineages') ELSE lineage END \
                         WHERE project_id = $2 AND name = $3 AND target = $4 RETURNING lineage",
                    )
                        .bind(n.hex())
                        .bind(pid)
                        .bind(&branch)
                        .bind(c0.hex())
                        .bind(force)
                        .fetch_optional(&mut *c)
                        .await?
                        .map_or(0, |lineage| {
                            lineages.push((branch.clone(), lineage));
                            1
                        }),
                    (None, Some(n)) => sqlx::query_scalar::<_, i64>(
                        "INSERT INTO branches (project_id, name, target) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING RETURNING lineage",
                    )
                        .bind(pid)
                        .bind(&branch)
                        .bind(n.hex())
                        .fetch_optional(&mut *c)
                        .await?
                        .map_or(0, |lineage| {
                            lineages.push((branch.clone(), lineage));
                            1
                        }),
                    (Some(c0), None) => sqlx::query("DELETE FROM branches WHERE project_id = $1 AND name = $2 AND target = $3")
                        .bind(pid)
                        .bind(&branch)
                        .bind(c0.hex())
                        .execute(&mut *c)
                        .await?
                        .rows_affected(),
                    (None, None) => 1,
                };
                if rows != 1 {
                    // Someone else moved it first: nothing of this push lands.
                    return Err(Error::conflict(format!("branch '{branch}' moved during the push; pull, then push again")));
                }
                if let Some(text) = accept {
                    // Bumps the project's access epoch (a trigger): every
                    // server's cached permissions for it are void.
                    crate::perm::accept_policy(&mut *c, pid, &text).await?;
                } else if let Some(text) = policy_text_update {
                    sqlx::query("UPDATE projects SET policy_text = $1 WHERE id = $2")
                        .bind(&text)
                        .bind(pid)
                        .execute(&mut *c)
                        .await?;
                }
                moved.push(branch);
            }
            for (branch, lineage) in &lineages {
                if let Some((cs, aus, ls)) = plan_changes.get(branch) {
                    if !cs.is_empty() {
                        crate::landing::record_changes(&mut *c, pid, branch, *lineage, cs, aus, ls).await?;
                    }
                }
            }
            for (r, author) in &new_reals {
                sqlx::query("INSERT INTO snapshots (project_id, id, author) VALUES ($1, $2, $3) ON CONFLICT (project_id, id) DO UPDATE SET author = EXCLUDED.author WHERE snapshots.author = 0")
                    .bind(pid)
                    .bind(r)
                    .bind(*author)
                    .execute(&mut *c)
                    .await?;
            }
            for (real, origin) in &origins {
                sqlx::query("INSERT INTO origins (project_id, real_id, origin_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING")
                    .bind(pid)
                    .bind(real)
                    .bind(origin)
                    .execute(&mut *c)
                    .await?;
            }
            // A row stored first by another request wins (and is not cached
            // here from this push's answer).
            let mut memo_stored = Vec::new();
            for (view_key, real, projected, collapsed) in &memos {
                let n = sqlx::query(
                    "INSERT INTO projections (project_id, view_key, real_id, projected_id, created_at, collapsed) VALUES ($1, $2, $3, $4, $5, $6) \
                     ON CONFLICT DO NOTHING",
                )
                .bind(pid)
                .bind(view_key)
                .bind(real)
                .bind(projected)
                .bind(veil_core::now_millis())
                .bind(collapsed)
                .execute(&mut *c)
                .await?
                .rows_affected();
                memo_stored.push(n == 1);
            }
            sqlx::query("INSERT INTO audit_log (project_id, at, actor, action, details) VALUES ($1, $2, $3, 'push', $4)")
                .bind(pid)
                .bind(veil_core::now_millis())
                .bind(person)
                .bind(format!("moved {moved:?}"))
                .execute(&mut *c)
                .await?;
            // Delivered at commit, to every server: drop your tips.
            if notify && !moved.is_empty() {
                sqlx::query("SELECT pg_notify($1, $2)")
                    .bind(crate::caches::TIPS_CHANNEL)
                    .bind(pid.to_string())
                    .execute(&mut *c)
                    .await?;
            }
            Ok((moved, memo_stored))
        })
    })
    .await;
        match r {
            Ok(r) => r,
            Err(e) => {
                for w in waiters {
                    crate::landing::abandon(hub, w);
                }
                return Err(e);
            }
        }
    };
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
        r.warnings.extend(crate::landing::skipped_warnings(hub, project.id, &q.branch, &skipped).await?);
        landings.push(r);
    }
    if !moved.is_empty() {
        hub.caches.tips_changed(project.id);
        for c in &completed {
            hub.caches.put_committed(project.id, &c.real);
        }
    }
    for ((view_key, real, projected), stored) in deferred.rows.iter().zip(memo_stored) {
        if stored {
            hub.caches.put_memo(project.id, view_key, real, projected);
        }
    }
    // Derived history data for the branches moved, in the background: the
    // push never waits.
    crate::derive::landed(hub, project.id, moved);
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
    let warnings = match accepted {
        true => crate::perm::accepted_listing(project),
        false => Vec::new(),
    };
    for (branch, _, new, _, _) in plans {
        let tip = match new {
            Some(n) => Some(projected(hub, project, viewer, n).await?),
            None => None,
        };
        results.push(BranchResult { branch, ok: true, message: None, tip, ticket: None });
    }
    let mut warnings = warnings;
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
    Ok((PushResult { results, warnings }, landings))
}

/// Is `a` an ancestor of (or equal to) `b` in the real history?
pub(crate) async fn is_ancestor(hub: &Arc<Hub>, project: i64, a: ObjectId, b: ObjectId) -> Result<bool> {
    blocking(hub, project, move |src| {
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

/// The receipt for `person` uploading object `id` to `project`: a MAC only
/// the server can make. A push shows it for each object it introduces.
pub fn receipt(hub: &Hub, project: i64, person: i64, id: &ObjectId) -> String {
    let mut h = blake3::Hasher::new_keyed(&hub.receipt_key);
    h.update(&project.to_le_bytes());
    h.update(&person.to_le_bytes());
    h.update(&id.0);
    hex::encode(&h.finalize().as_bytes()[..16])
}

/// The objects whose receipts in `receipts` are `person`'s (compared in
/// constant time).
pub(crate) fn receipted(hub: &Hub, project: i64, person: i64, receipts: &std::collections::BTreeMap<ObjectId, String>) -> HashSet<ObjectId> {
    receipts
        .iter()
        .filter(|(id, r)| {
            let want = receipt(hub, project, person, id);
            r.len() == want.len() && r.bytes().zip(want.bytes()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
        })
        .map(|(id, _)| *id)
        .collect()
}

/// Store uploaded objects (`docs/HUB.md` §4.5). Each frame, plain or
/// compressed (`docs/HUB.md` §13.15), is decoded (bounded: at most the
/// object size limit each, at most `limit` bytes for the whole request, a
/// compressed one only if it expands at most [`encoding::MAX_RATIO`] times
/// its size, and at most [`DECODING_IN_FLIGHT`] bytes across the server at
/// once: BUG-1009), re-hashed against its id, and must decode canonically
/// (safe names, sorted trees) at a repository format the server serves.
/// It is stored as the server's own encoding of it, never as the client
/// sent it, so no client chooses the stored bytes of an object others
/// share (BUG-1008). Nothing uploaded is visible until a push makes a
/// branch reach it. Returns a receipt per object, in order (stored whether
/// or not the project held it already, so the answer is the same either
/// way).
pub async fn upload(hub: &Arc<Hub>, project: i64, person: i64, body: Bytes, limit: u64) -> Result<Vec<String>> {
    // The checks, decoding and compressing on a blocking thread.
    let rt = Handle::current();
    let frames: Vec<(ObjectId, Bytes)> = tokio::task::spawn_blocking(move || -> Result<Vec<(ObjectId, Bytes)>> {
        let mut left = limit;
        let mut out = Vec::new();
        for (id, enc) in encoding::split_frames(&body)? {
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
            let raw = encoding::decode(&id, enc, left.min(MAX_FRAME_OBJECT as u64))?;
            left -= raw.len() as u64;
            if Object::min_repo_format(&raw) > veil_core::repo::REPO_FORMAT {
                return Err(Error::bad_request("an object of a newer format than this server serves"));
            }
            // Any bytes are a blob: decoding one would only copy it.
            if !raw.starts_with(b"veil:blob\n") {
                Object::decode(&raw)?;
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
    let receipts = frames.iter().map(|(id, _)| receipt(hub, project, person, id)).collect();
    // Encodings, checked above: stored as they are, never encoded again.
    put_many(hub, project, frames, true).await?;
    Ok(receipts)
}

/// Store `objects` (canonical encodings; compressed by the store) in
/// `project`, at most [`PUTS_AT_ONCE`] at a time (an object store answers a
/// flood with "slow down": BUG-1053).
pub async fn put_all(hub: &Arc<Hub>, project: i64, objects: impl IntoIterator<Item = (ObjectId, Bytes)>) -> Result<()> {
    put_many(hub, project, objects, false).await
}

/// [`put_all`] of canonical encodings, or (`encoded`) of checked encodings
/// stored as they are ([`crate::store::Objects::put_encoded`]).
async fn put_many(hub: &Arc<Hub>, project: i64, objects: impl IntoIterator<Item = (ObjectId, Bytes)>, encoded: bool) -> Result<()> {
    let mut set = tokio::task::JoinSet::new();
    let mut it = objects.into_iter();
    loop {
        while set.len() < PUTS_AT_ONCE {
            let Some((id, b)) = it.next() else { break };
            let h = hub.clone();
            set.spawn(async move {
                match encoded {
                    true => h.objects.put_encoded(project, &id, b).await,
                    false => h.objects.put(project, &id, b).await,
                }
            });
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

/// Most object writes one request has in flight ([`put_all`]).
pub const PUTS_AT_ONCE: usize = 64;
