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

/// Objects of one project, read synchronously (for the projection code,
/// which runs on a blocking thread).
pub struct Source {
    pub hub: Arc<Hub>,
    pub project: i64,
    pub rt: Handle,
}

impl Source {
    pub fn raw(&self, id: &ObjectId) -> veil_core::Result<Bytes> {
        // Every history starts at the universal root and its empty tree.
        let empty = Object::Tree(Tree::default()).encode();
        if *id == ObjectId::hash(&empty) {
            return Ok(Bytes::from(empty));
        }
        let root = Object::Snapshot(Snapshot::root(ObjectId::hash(&empty))).encode();
        if *id == ObjectId::hash(&root) {
            return Ok(Bytes::from(root));
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
                self.hub.trees.insert(ck, (t.clone(), enc), raw.len() * 2);
                Ok(Node::Tree(t, enc))
            }
            _ => Ok(Node::Leaf),
        }
    }
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
pub async fn projected(hub: &Arc<Hub>, project: &Project, viewer: &Viewer, real: ObjectId) -> Result<ObjectId> {
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
/// `viewer` may read at its path, as object frames. Anything not found at
/// its path in the viewer's projection is refused as not found, without
/// saying whether it exists.
pub async fn fetch(hub: &Arc<Hub>, project: &Project, viewer: &Viewer, snapshot: ObjectId, wants: Vec<Want>) -> Result<Vec<u8>> {
    let Some(real) = resolve(hub, project.id, &snapshot).await?.into_iter().next() else {
        return Err(Error::not_found(format!("no snapshot {} that you can see", snapshot.short())));
    };
    hub.objects.prefetch(project.id, wants.iter().map(|w| w.id).collect()).await;
    let (policy_text, bindings, viewer) = (project.policy_text.clone(), project.bindings.clone(), viewer.clone());
    blocking(hub, project.id, move |src| {
        let p = Project {
            id: src.project,
            name: String::new(),
            default_branch: String::new(),
            policy: AccessPolicy::parse(&policy_text),
            policy_text: String::new(),
            bindings,
        };
        let view = p.view(&viewer);
        let mut pr = Projector::new(src, &view);
        let s = src.snapshot(&real)?;
        let root = pr.root(s.tree)?;
        // Projected directory trees by path, filled as the wants need them.
        let mut dirs: HashMap<String, Option<Arc<Tree>>> = HashMap::new();
        dirs.insert(String::new(), pr.tree(&root)?);
        let mut out = Vec::new();
        let gone = || Error::not_found("no such object at that path that you can see");
        for w in wants {
            let ok = if w.path.is_empty() {
                w.id == root
            } else {
                let (dir, name) = w.path.rsplit_once('/').unwrap_or(("", w.path.as_str()));
                let tree = dir_tree(&mut pr, &mut dirs, dir)?.ok_or_else(gone)?;
                let e = tree.get(name).ok_or_else(gone)?;
                e.id == w.id
                    || e.fallback == Some(w.id)
                    || (e.kind == EntryKind::Conflict
                        && matches!(Object::decode(&src.raw(&e.id)?)?, Object::Conflict(c) if c.referenced_ids().contains(&w.id)))
            };
            if !ok {
                return Err(gone());
            }
            match pr.created_raw(&w.id) {
                Some(raw) => put_frame(&mut out, &w.id, raw),
                None => put_frame(&mut out, &w.id, &src.raw(&w.id)?),
            }
        }
        Ok(out)
    })
    .await
}

/// The projected tree of directory `dir`, walking down from the root.
fn dir_tree(pr: &mut Projector, dirs: &mut HashMap<String, Option<Arc<Tree>>>, dir: &str) -> Result<Option<Arc<Tree>>> {
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

/// Check the paths one snapshot changes: write access, personal keys,
/// secrets sealed, nothing local-only (`docs/HUB.md` §4.5, checks 2 and 8).
fn check_changes(src: &Source, view: &View, changes: &[Change], real_tree: &ObjectId, other_parents: &[ObjectId]) -> Result<()> {
    let text = policy_text(src, real_tree)?;
    let policy = Policy::parse(&text);
    for c in changes {
        // Taken unchanged from another parent (a merge): written by someone
        // who could, already.
        let from_other = || -> Result<bool> {
            for t in other_parents {
                if entry_at(src, t, &c.path)? == c.new {
                    return Ok(true);
                }
            }
            Ok(false)
        };
        if !view.write(&c.path) && !from_other()? {
            return Err(Error::forbidden(format!("you may not write '{}'", c.path)));
        }
        let Some(e) = &c.new else { continue };
        if personal_key(&c.path) {
            return Err(Error::forbidden(format!(
                "'{}' is a personal private key: it never leaves your device",
                c.path
            )));
        }
        if matches!(e.visibility, Visibility::Embargoed { .. }) || e.fallback.is_some() && !matches!(e.visibility, Visibility::Cloaked { .. }) {
            return Err(Error::forbidden(format!("'{}': embargoed content cannot be pushed to the server yet", c.path)));
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
    // candidates.
    let mut tip_projection: HashMap<ObjectId, ObjectId> = HashMap::new();
    for (name, t) in &current {
        if *name == project.default_branch || req.updates.iter().any(|u| u.branch == *name) {
            tip_projection.insert(projected(hub, project, viewer, *t).await?, *t);
        }
    }
    let signers: HashSet<String> = sqlx::query_scalar::<_, String>("SELECT signing_key FROM devices WHERE removed_at IS NULL")
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
    // 2. Complete and check each new snapshot.
    let mut completed: Vec<Completed> = Vec::new();
    for id in &order {
        let n = parents_of[id].clone();
        if n.cloak.is_some() || n.embargo.is_some() {
            return Err(Error::forbidden(
                "cloaked lines of work and embargoed merges cannot be pushed to the server yet (docs/HUB.md §11)",
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
            let mut g = Graft::new(src, &view);
            let real_tree = g.root(n2.tree, Some(ptrees[0]))?;
            // A merge must not change what the pusher cannot see.
            for other in &ptrees[1..] {
                let mut g2 = Graft::new(src, &view);
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
            check_changes(src, &view, &g.changes, &real_tree, &ptrees[1..])?;
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

/// Store uploaded objects (`docs/HUB.md` §4.5): each is re-hashed against
/// its id and must decode canonically (safe names, sorted trees) at a
/// repository format the server serves. Nothing uploaded is visible until a
/// push makes a branch reach it.
pub async fn upload(hub: &Arc<Hub>, project: i64, body: Bytes) -> Result<usize> {
    let frames: Vec<(ObjectId, Bytes)> = veil_core::hub::wire::read_frames(&body)?
        .into_iter()
        .map(|(id, raw)| (id, body.slice_ref(raw)))
        .collect();
    for (_, raw) in &frames {
        if Object::min_repo_format(raw) > veil_core::repo::REPO_FORMAT {
            return Err(Error::bad_request("an object of a newer format than this server serves"));
        }
        Object::decode(raw)?;
    }
    let n = frames.len();
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
    Ok(n)
}
