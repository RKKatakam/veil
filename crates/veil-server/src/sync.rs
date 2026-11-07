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
    collections::{HashMap, HashSet},
    sync::Arc,
};

use bytes::Bytes;
use tokio::runtime::Handle;
use veil_core::{
    hub::{
        access::{AccessPolicy, View},
        project::{Change, Graft, Node, Projector, TreeSource},
        wire::{put_frame, BranchResult, PushRequest, PushResult, Want},
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
}

impl Source {
    pub fn raw(&self, id: &ObjectId) -> veil_core::Result<Bytes> {
        if let Some(b) = builtin(id) {
            return Ok(b);
        }
        self.hub
            .objects
            .get_blocking(&self.rt, self.project, id)
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
    let src = Source {
        hub: hub.clone(),
        project,
        rt: Handle::current(),
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
    Box::pin(projected_inner(hub, project, viewer, real)).await
}

/// The predecessors of `s` as `viewer` is shown them (BUG-826): a stored
/// predecessor becomes its projection, kept only if that is still a version
/// of the same change (not one that touched only what the viewer cannot
/// see); one the server never stored names nothing on it and is kept.
/// Terminates: ids are hashes of what they name, so no snapshot is its own
/// predecessor or ancestor.
async fn projected_predecessors(hub: &Arc<Hub>, project: &Project, viewer: &Viewer, s: &Snapshot) -> Result<Vec<ObjectId>> {
    let mut out = Vec::new();
    for p in &s.predecessors {
        let stored: Option<String> = sqlx::query_scalar("SELECT id FROM snapshots WHERE project_id = $1 AND id = $2")
            .bind(project.id)
            .bind(p.hex())
            .fetch_optional(&hub.db)
            .await?;
        if stored.is_none() {
            out.push(*p);
            continue;
        }
        let pp = projected(hub, project, viewer, *p).await?;
        let (p, pp2) = (*p, pp);
        let same = blocking(hub, project.id, move |src| Ok(src.snapshot(&pp2)?.change_id == src.snapshot(&p)?.change_id)).await?;
        if same && !out.contains(&pp) {
            out.push(pp);
        }
    }
    Ok(out)
}

async fn projected_inner(hub: &Arc<Hub>, project: &Project, viewer: &Viewer, real: ObjectId) -> Result<ObjectId> {
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
            let memo: Option<String> =
                sqlx::query_scalar("SELECT projected_id FROM projections WHERE project_id = $1 AND view_key = $2 AND real_id = $3")
                    .bind(project.id)
                    .bind(&view_key)
                    .bind(x.hex())
                    .fetch_optional(&hub.db)
                    .await?;
            if let Some(p) = memo {
                done.insert(x, ObjectId::from_hex(&p).map_err(|e| Error::Other(e.into()))?);
                continue;
            }
            let s = blocking(hub, project.id, move |src| Ok(src.snapshot(&x)?)).await?;
            stack.push((x, true));
            for p in s.parents.iter().rev() {
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
        let origin: Option<String> = sqlx::query_scalar("SELECT origin_id FROM origins WHERE project_id = $1 AND real_id = $2")
            .bind(project.id)
            .bind(x.hex())
            .fetch_optional(&hub.db)
            .await?;
        let origin = origin.and_then(|o| ObjectId::from_hex(&o).ok());
        let ppreds = projected_predecessors(hub, project, viewer, &s).await?;
        let (proj_text, bindings, viewer2) = (project.policy_text.clone(), project.bindings.clone(), viewer.clone());
        let hub2 = hub.clone();
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
            let view = p.view(&viewer2);
            let mut pr = Projector::new(src, &view);
            let ptree = pr.root(s.tree)?;
            // A change of what the viewer cannot see only: not in their history.
            if pparents.len() == 1 && !s.parents.is_empty() {
                let pp = src.snapshot(&pparents[0])?;
                let real_changed = s.parents.len() > 1 || src.snapshot(&s.parents[0])?.tree != s.tree;
                if pp.tree == ptree && real_changed {
                    return Ok((pparents[0], None));
                }
            }
            let view_read = |p: &str| view.read(p);
            let mut u = without_signature(&s);
            u.tree = ptree;
            u.parents = pparents;
            u.predecessors = ppreds;
            u.conflicts.retain(|c| view_read(c));
            if u == without_signature(&s) {
                return Ok((x, None));
            }
            if let Some(o) = origin {
                let n = src.snapshot(&o)?;
                if without_signature(&n) == u {
                    return Ok((o, None));
                }
            }
            u.sign(&hub2.identity);
            let raw = Object::Snapshot(u).encode();
            Ok((ObjectId::hash(&raw), Some(Bytes::from(raw))))
        })
        .await?;
        if let Some(raw) = new_obj {
            hub.objects.put(project.id, &result, raw).await?;
        }
        sqlx::query(
            "INSERT INTO projections (project_id, view_key, real_id, projected_id, created_at) VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT DO NOTHING",
        )
        .bind(project.id)
        .bind(&view_key)
        .bind(x.hex())
        .bind(result.hex())
        .bind(veil_core::now_millis())
        .execute(&hub.db)
        .await?;
        done.insert(x, result);
    }
    Ok(done[&real])
}

/// The real snapshots a snapshot id the client names may stand for: itself
/// if it is committed history, else the snapshots it is a projection of
/// (newest first).
pub async fn resolve(hub: &Hub, project: i64, id: &ObjectId) -> Result<Vec<ObjectId>> {
    if *id == root_snapshot_id() {
        return Ok(vec![*id]);
    }
    let real: Option<String> = sqlx::query_scalar("SELECT id FROM snapshots WHERE project_id = $1 AND id = $2")
        .bind(project)
        .bind(id.hex())
        .fetch_optional(&hub.db)
        .await?;
    if real.is_some() {
        return Ok(vec![*id]);
    }
    let rows: Vec<String> =
        sqlx::query_scalar("SELECT real_id FROM projections WHERE project_id = $1 AND projected_id = $2 ORDER BY created_at DESC")
            .bind(project)
            .bind(id.hex())
            .fetch_all(&hub.db)
            .await?;
    Ok(rows.iter().filter_map(|r| ObjectId::from_hex(r).ok()).collect())
}

/// Branch tips as `viewer` sees them.
pub async fn tips(hub: &Arc<Hub>, project: &Project, viewer: &Viewer) -> Result<Vec<(String, ObjectId)>> {
    let rows: Vec<(String, String)> = sqlx::query_as("SELECT name, target FROM branches WHERE project_id = $1 ORDER BY name")
        .bind(project.id)
        .fetch_all(&hub.db)
        .await?;
    let mut out = Vec::new();
    for (name, target) in rows {
        let real = ObjectId::from_hex(&target).map_err(|e| Error::Other(e.into()))?;
        out.push((name, projected(hub, project, viewer, real).await?));
    }
    Ok(out)
}

/// The snapshots reachable from `tips` in `viewer`'s projected history,
/// down to (not including) `stop`, as object frames.
pub async fn history(hub: &Arc<Hub>, project: &Project, viewer: &Viewer, tips: &[ObjectId], stop: &[ObjectId]) -> Result<Vec<u8>> {
    let mut starts = Vec::new();
    for t in tips {
        let Some(real) = resolve(hub, project.id, t).await?.into_iter().next() else {
            return Err(Error::not_found(format!("no snapshot {} that you can see", t.short())));
        };
        starts.push(projected(hub, project, viewer, real).await?);
    }
    let stop: HashSet<ObjectId> = stop.iter().copied().collect();
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
            put_frame(&mut out, &id, &raw);
            stack.extend(s.parents.iter().copied());
        }
        Ok(out)
    })
    .await
}

/// Objects `wants` under snapshot `snapshot`, each checked against what
/// `viewer` may read at its path, as a stream of object frames. Anything
/// not found at its path in the viewer's projection is refused as not
/// found, without saying whether it exists.
///
/// Memory is bounded (BUG-860): every want is checked first, a snapshot at
/// a time (its projected trees dropped before the next), then the answer
/// is read and sent a few objects ahead of the caller (`FETCH_WINDOW`);
/// a failure while sending ends the stream with an error, so it is never
/// taken as whole.
pub async fn fetch(hub: &Arc<Hub>, project: &Project, viewer: &Viewer, snapshot: ObjectId, wants: Vec<Want>) -> Result<FrameStream> {
    // Each want is checked in its own snapshot (revision 1), as the viewer
    // sees it.
    let mut reals: HashMap<ObjectId, ObjectId> = HashMap::new();
    for snap in std::iter::once(snapshot).chain(wants.iter().filter_map(|w| w.snapshot)) {
        if reals.contains_key(&snap) {
            continue;
        }
        let Some(real) = resolve(hub, project.id, &snap).await?.into_iter().next() else {
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
    // them and about `FETCH_WINDOW_BYTES` (by the sizes tree entries
    // carry) ahead of the one sent next, framed in order and sent about a
    // MiB at a time as the caller takes it.
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    let (hub, pid) = (hub.clone(), project.id);
    tokio::spawn(async move {
        let stop = |e: Error| {
            // Details go to the server's log; the caller's answer ends in an
            // error, never taken as whole.
            eprintln!("veil-server: a fetch answer stopped: {e:?}");
            std::io::Error::other("the answer stopped")
        };
        let mut set = tokio::task::JoinSet::new();
        let mut ready: HashMap<usize, Bytes> = HashMap::new();
        let (mut next, mut sent, mut ahead) = (0usize, 0usize, 0u64);
        let mut out = Vec::new();
        while sent < wants.len() {
            while next < wants.len() && next - sent < FETCH_WINDOW && (next == sent || ahead + sizes[next] <= FETCH_WINDOW_BYTES) {
                let id = wants[next].id;
                match created.get(&id).cloned().or_else(|| builtin(&id)) {
                    Some(raw) => {
                        ready.insert(next, raw);
                    }
                    None => {
                        let (hub, i) = (hub.clone(), next);
                        set.spawn(async move { (i, hub.objects.get(pid, &id).await) });
                    }
                }
                ahead += sizes[next];
                next += 1;
            }
            while !ready.contains_key(&sent) {
                let got = match set.join_next().await {
                    Some(Ok((i, Ok(Some(raw))))) => Ok((i, raw)),
                    Some(Ok((i, Ok(None)))) => Err(Error::Other(anyhow::anyhow!("object {} is not stored", wants[i].id.short()))),
                    Some(Ok((_, Err(e)))) => Err(Error::Other(e)),
                    Some(Err(e)) => Err(Error::Other(e.into())),
                    None => Err(Error::Other(anyhow::anyhow!("a fetch read went missing"))),
                };
                match got {
                    Ok((i, raw)) => {
                        ready.insert(i, raw);
                    }
                    Err(e) => {
                        let _ = tx.send(Err(stop(e))).await;
                        return;
                    }
                }
            }
            let raw = ready.remove(&sent).expect("ready");
            put_frame(&mut out, &wants[sent].id, &raw);
            ahead -= sizes[sent];
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
            let ok = if w.path.is_empty() {
                w.id == root
            } else {
                let (dir, name) = w.path.rsplit_once('/').unwrap_or(("", w.path.as_str()));
                let tree = dir_tree(&mut pr, &mut dirs, dir)?.ok_or_else(gone)?;
                let e = tree.get(name).ok_or_else(gone)?;
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

/// Names of personal private keys: never accepted, sealed or not
/// (`docs/VISIBILITY.md`, "Personal private keys never leave your machine").
fn personal_key(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    matches!(name.as_str(), "id_rsa" | "id_dsa" | "id_ecdsa" | "id_ed25519")
}

/// The text of the `.veilpolicy` at the root of real tree `tree`.
fn policy_text(src: &Source, tree: &ObjectId) -> Result<String> {
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
fn entry_at(src: &Source, tree: &ObjectId, path: &str) -> Result<Option<veil_core::TreeEntry>> {
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
fn named_ids(src: &Source, e: &veil_core::TreeEntry) -> Result<Vec<ObjectId>> {
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
/// secrets sealed, nothing local-only (`docs/HUB.md` §4.5, checks 2 and 8).
/// `parents` are the snapshot's real parents.
fn check_changes(src: &Source, view: &View, changes: &[Change], real_tree: &ObjectId, parents: &[ObjectId]) -> Result<()> {
    let text = policy_text(src, real_tree)?;
    let policy = Policy::parse(&text);
    // A merge's other parents: their trees, and the tree of a common
    // ancestor with the first parent (found when first needed).
    let mut others: Vec<(ObjectId, Option<ObjectId>)> = Vec::new();
    for p in parents.iter().skip(1) {
        others.push((src.snapshot(p)?.tree, None));
    }
    for c in changes {
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
        if !e.kind.holds_blob() {
            continue;
        }
        let vp = VPath::new(&c.path).map_err(|_| Error::bad_request(format!("invalid path '{}'", c.path)))?;
        let sealed = Object::sealed_scope(&src.raw(&e.id)?).is_some();
        match policy.classify(&vp, false).tier {
            Tier::Isolated | Tier::Ignored => {
                return Err(Error::forbidden(format!(
                    "'{}' stays on the device by the project's policy (a secret or ignored file)",
                    c.path
                )))
            }
            Tier::Cloaked(_) if !sealed || !matches!(e.visibility, Visibility::Cloaked { .. }) => {
                return Err(Error::forbidden(format!("'{}' is a secret and must arrive encrypted", c.path)))
            }
            _ => {}
        }
        // A sealed object under a plain label (or the reverse) is malformed.
        if sealed != matches!(e.visibility, Visibility::Cloaked { .. }) {
            return Err(Error::bad_request(format!("'{}': the entry's label does not match its object", c.path)));
        }
    }
    Ok(())
}

/// One new snapshot, completed.
struct Completed {
    real: ObjectId,
    raw: Option<Bytes>,
    /// The pusher's own snapshot, when the server completed it.
    origin: Option<ObjectId>,
}

/// Handle a push (`docs/HUB.md` §4.5): complete and check every new
/// snapshot, store what the server built, then move every branch in one
/// serialisable transaction of compare-and-swaps.
pub async fn push(hub: &Arc<Hub>, project: &Project, viewer: &Viewer, person: i64, req: PushRequest) -> Result<PushResult> {
    if !project.participant(viewer) {
        return Err(Error::forbidden("you are not in this project"));
    }
    if req.force && !viewer.admin {
        return Err(Error::forbidden("only admins may force a branch move"));
    }
    let root = root_snapshot_id();
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
        let r = resolve(hub, project.id, &id).await?;
        if !r.is_empty() {
            known.insert(id, r);
            continue;
        }
        let s = blocking(hub, project.id, move |src| match src.snapshot(&id) {
            Err(VeilError::Missing(_)) => Err(Error::bad_request(format!("snapshot {} was not uploaded", id.short()))),
            r => Ok(r?),
        })
        .await?;
        stack.extend(s.parents.iter().copied());
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
                for p in &parents_of[&id].parents {
                    st.push((*p, false));
                }
            }
        }
    }
    // Current tips, to pick which real snapshot a projected parent stands
    // for (the branch's tip when it projects to it).
    let current: HashMap<String, ObjectId> = {
        let rows: Vec<(String, String)> = sqlx::query_as("SELECT name, target FROM branches WHERE project_id = $1")
            .bind(project.id)
            .fetch_all(&hub.db)
            .await?;
        rows.into_iter().filter_map(|(n, t)| ObjectId::from_hex(&t).ok().map(|t| (n, t))).collect()
    };
    // Only the branches this push moves, and the default branch, are
    // candidates; a branch this push moves wins over the default branch
    // (both may look the same to the pusher).
    let mut tip_projection: HashMap<ObjectId, ObjectId> = HashMap::new();
    let candidates = std::iter::once(&project.default_branch).chain(req.updates.iter().map(|u| &u.branch));
    for name in candidates {
        if let Some(t) = current.get(name) {
            tip_projection.insert(projected(hub, project, viewer, *t).await?, *t);
        }
    }
    let signers: HashSet<String> = sqlx::query_scalar::<_, String>("SELECT signing_key FROM devices WHERE removed_at IS NULL AND NOT pending")
        .fetch_all(&hub.db)
        .await?
        .into_iter()
        .collect();
    let mut real_of: HashMap<ObjectId, ObjectId> = HashMap::new();
    real_of.insert(root, root);
    for (id, reals) in &known {
        let r = tip_projection.get(id).copied().unwrap_or(reals[0]);
        real_of.insert(*id, r);
    }
    // What this pusher uploaded (BUG-824): a push names nothing else that
    // is not already where it was in a parent.
    let uploaded = Arc::new(receipted(hub, project.id, person, &req.receipts));
    // 2. Complete and check each new snapshot.
    let mut completed: Vec<Completed> = Vec::new();
    for id in &order {
        let n = parents_of[id].clone();
        if n.embargo.is_some() {
            return Err(Error::forbidden(
                "embargoed merges cannot be pushed to the server yet (docs/HUB.md §11)",
            ));
        }
        match &n.signature {
            Some(sig) if n.signature_valid() == Some(true) && signers.contains(&sig.key) => {}
            Some(_) if n.signature_valid() == Some(true) => {
                return Err(Error::forbidden(format!(
                    "snapshot {} is signed by a key no device here is registered with",
                    id.short()
                )))
            }
            _ => return Err(Error::forbidden(format!("snapshot {} is unsigned or its signature is invalid", id.short()))),
        }
        if n.parents.is_empty() {
            return Err(Error::bad_request("a snapshot without parents (only the root has none)"));
        }
        let real_parents: Vec<ObjectId> = n.parents.iter().map(|p| real_of[p]).collect();
        let (policy_text_acc, bindings, viewer2, n2, admin) =
            (project.policy_text.clone(), project.bindings.clone(), viewer.clone(), n.clone(), viewer.admin);
        let hub2 = hub.clone();
        let rp = real_parents.clone();
        let uploaded = uploaded.clone();
        let c = blocking(hub, project.id, move |src| {
            let p = Project {
                id: src.project,
                name: String::new(),
                default_branch: String::new(),
                policy: AccessPolicy::parse(&policy_text_acc),
                policy_text: String::new(),
                bindings,
            };
            let view = p.view(&viewer2);
            let ptrees: Vec<ObjectId> = rp.iter().map(|p| Ok(src.snapshot(p)?.tree)).collect::<Result<_>>()?;
            let mut g = Graft::new(src, &view).proving(&uploaded, ptrees.clone());
            let real_tree = g.root(n2.tree, Some(ptrees[0]))?;
            // A merge must not change what the pusher cannot see.
            for other in &ptrees[1..] {
                let mut g2 = Graft::new(src, &view).proving(&uploaded, ptrees.clone());
                if g2.root(n2.tree, Some(*other))? != real_tree && !admin {
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
            check_changes(src, &view, &g.changes, &real_tree, &rp)?;
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
            let mut real = (*n2).clone();
            real.tree = real_tree;
            real.parents = rp.clone();
            if real == *n2 {
                return Ok(Completed {
                    real: ObjectId::hash(&Object::Snapshot(real).encode()),
                    raw: None,
                    origin: None,
                });
            }
            real.sign(&hub2.identity);
            let raw = Object::Snapshot(real).encode();
            Ok(Completed {
                real: ObjectId::hash(&raw),
                raw: Some(Bytes::from(raw)),
                origin: None,
            })
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
        completed.push(c);
    }
    // 3. Move the branches: one serialisable transaction of compare-and-swaps.
    let mut plans = Vec::new();
    let mut results = Vec::new();
    for u in &req.updates {
        if veil_core::commands::validate_tag_name(&u.branch).is_err() {
            return Err(Error::bad_request(format!("invalid branch name {:?}", u.branch)));
        }
        let cur = current.get(&u.branch).copied();
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
            });
            continue;
        }
        let new_real = match u.new {
            Some(n) => Some(*real_of.get(&n).ok_or_else(|| Error::bad_request("unknown new tip"))?),
            None => None,
        };
        if new_real.is_none() && !viewer.admin {
            return Err(Error::forbidden("only admins may delete a branch"));
        }
        if let (Some(c), Some(n)) = (cur, new_real) {
            if !req.force && !is_ancestor(hub, project.id, c, n).await? {
                results.push(BranchResult {
                    branch: u.branch.clone(),
                    ok: false,
                    message: Some("not a fast-forward; pull and merge, then push again".into()),
                    tip: cur_seen,
                });
                continue;
            }
        }
        // The default branch carries the accepted policy.
        let mut accept = None;
        if u.branch == project.default_branch {
            if let Some(n) = new_real {
                let text = blocking(hub, project.id, move |src| policy_text(src, &src.snapshot(&n)?.tree)).await?;
                let incoming = AccessPolicy::parse(&text);
                if !incoming.same_rules(&project.policy) {
                    if !viewer.admin {
                        return Err(Error::forbidden("only admins may change who has access (the default branch's .veilpolicy)"));
                    }
                    accept = Some(text);
                }
            }
        }
        plans.push((u.branch.clone(), cur, new_real, accept));
    }
    // Only the snapshots this push made: known ones are recorded already
    // (rewriting their rows made every racing pusher write the same row).
    let new_reals: Vec<String> = completed.iter().map(|c| c.real.hex()).collect();
    let origins: Vec<(String, String)> = completed.iter().filter_map(|c| c.origin.map(|o| (c.real.hex(), o.hex()))).collect();
    let pid = project.id;
    let plans2 = plans.clone();
    let moved = crate::db::transaction(&hub.db, crate::db::Isolation::ReadCommitted, move |c| {
        let plans = plans2.clone();
        let new_reals = new_reals.clone();
        let origins = origins.clone();
        Box::pin(async move {
            let mut moved = Vec::new();
            for (branch, cur, new, accept) in plans {
                let rows = match (cur, new) {
                    (Some(c0), Some(n)) => sqlx::query("UPDATE branches SET target = $1 WHERE project_id = $2 AND name = $3 AND target = $4")
                        .bind(n.hex())
                        .bind(pid)
                        .bind(&branch)
                        .bind(c0.hex())
                        .execute(&mut *c)
                        .await?
                        .rows_affected(),
                    (None, Some(n)) => sqlx::query("INSERT INTO branches (project_id, name, target) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING")
                        .bind(pid)
                        .bind(&branch)
                        .bind(n.hex())
                        .execute(&mut *c)
                        .await?
                        .rows_affected(),
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
                    let policy = AccessPolicy::parse(&text);
                    let bindings = crate::perm::bind_names(&mut *c, pid, &policy).await?;
                    sqlx::query("UPDATE projects SET policy_text = $1, policy_bindings = $2, policy_version = policy_version + 1 WHERE id = $3")
                        .bind(&text)
                        .bind(serde_json::to_string(&bindings).map_err(|e| Error::Other(e.into()))?)
                        .bind(pid)
                        .execute(&mut *c)
                        .await?;
                }
                moved.push(branch);
            }
            for r in &new_reals {
                sqlx::query("INSERT INTO snapshots (project_id, id) VALUES ($1, $2) ON CONFLICT DO NOTHING")
                    .bind(pid)
                    .bind(r)
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
            Ok(moved)
        })
    })
    .await?;
    crate::audit(&hub.db, Some(project.id), Some(person), "push", &format!("moved {moved:?}")).await;
    // Derived history data for the branches moved, in the background: the
    // push never waits.
    crate::derive::landed(hub, project.id, moved);
    // The tips as the pusher sees them now (their own snapshots, where the
    // server's projection gives them back).
    let accepted = plans.iter().any(|p| p.3.is_some());
    let project = crate::perm::load_project(&mut *hub.db.acquire().await?, &project.name)
        .await?
        .ok_or_else(|| Error::not_found("project"))?;
    let mut warnings = Vec::new();
    if accepted {
        // Never silently: say who can now see what.
        for r in &project.policy.rules {
            let mut who: Vec<String> = Vec::new();
            if r.public {
                who.push("everyone on Earth (public, read)".into());
            }
            for n in &r.names {
                who.push(match project.bindings.get(n) {
                    Some(crate::perm::Binding::Group(_)) => format!("group {n}"),
                    _ => format!("person {n}"),
                });
            }
            warnings.push(format!("access accepted: {}/ → {}", r.path, who.join(", ")));
        }
        for w in &project.policy.warnings {
            warnings.push(w.clone());
        }
    }
    for (branch, _, new, _) in plans {
        let tip = match new {
            Some(n) => Some(projected(hub, &project, viewer, n).await?),
            None => None,
        };
        results.push(BranchResult { branch, ok: true, message: None, tip });
    }
    Ok(PushResult { results, warnings })
}

/// Is `a` an ancestor of (or equal to) `b` in the real history?
async fn is_ancestor(hub: &Arc<Hub>, project: i64, a: ObjectId, b: ObjectId) -> Result<bool> {
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
fn receipted(hub: &Hub, project: i64, person: i64, receipts: &std::collections::BTreeMap<ObjectId, String>) -> HashSet<ObjectId> {
    receipts
        .iter()
        .filter(|(id, r)| {
            let want = receipt(hub, project, person, id);
            r.len() == want.len() && r.bytes().zip(want.bytes()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
        })
        .map(|(id, _)| *id)
        .collect()
}

/// Store uploaded objects (`docs/HUB.md` §4.5): each is re-hashed against
/// its id and must decode canonically (safe names, sorted trees) at a
/// repository format the server serves. Nothing uploaded is visible until a
/// push makes a branch reach it. Returns a receipt per object, in order
/// (stored whether or not the project held it already, so the answer is
/// the same either way).
pub async fn upload(hub: &Arc<Hub>, project: i64, person: i64, body: Bytes) -> Result<Vec<String>> {
    // Each object copied out of the request: a slice would keep the whole
    // body alive in the object cache for as long as any one of its objects
    // stays there (BUG-860).
    let frames: Vec<(ObjectId, Bytes)> = veil_core::hub::wire::read_frames(&body)?
        .into_iter()
        .map(|(id, raw)| (id, Bytes::copy_from_slice(raw)))
        .collect();
    drop(body);
    for (_, raw) in &frames {
        if Object::min_repo_format(raw) > veil_core::repo::REPO_FORMAT {
            return Err(Error::bad_request("an object of a newer format than this server serves"));
        }
        Object::decode(raw)?;
    }
    let receipts = frames.iter().map(|(id, _)| receipt(hub, project, person, id)).collect();
    let mut set = tokio::task::JoinSet::new();
    let hub2 = hub.clone();
    let mut it = frames.into_iter();
    loop {
        while set.len() < 64 {
            let Some((id, raw)) = it.next() else { break };
            let h = hub2.clone();
            set.spawn(async move { h.objects.put(project, &id, raw).await });
        }
        match set.join_next().await {
            Some(r) => r.map_err(|e| Error::Other(e.into()))??,
            None => break,
        }
    }
    Ok(receipts)
}
