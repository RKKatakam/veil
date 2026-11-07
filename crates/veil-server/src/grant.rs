//! Read grants, the object routes and the access-epoch feed (`docs/HUB.md`
//! §13.15; [`veil_core::hub::grant`] has the grant and the chain check).
//!
//! * **Grants with the tips.** `GET …/tips` returns, per branch, a grant for
//!   the caller's projected root tree of its tip, signed by the server's
//!   grant key (`<data>/hub-grant-key`), bound to the caller's device, for
//!   [`GRANT_TTL_MS`]. The projected trees a grant's root reaches are
//!   stored, so every layer can check chains against them.
//! * **The object routes** (`GET /v1/objects/{p}/{id}`, `POST
//!   /v1/objects/{p}:batch`) check the grant (signature, project, expiry,
//!   epoch), the device's signature of the request, then each object's
//!   chain from the grant's root, and only then read the object. "Not
//!   reachable" and "not there" get the same answer. Every object is read
//!   through [`crate::store::Objects`] only (`read`, and `Range` reads),
//!   and served on its own, after its own check: wherever the store keeps it
//!   (a pack, later: S28), nothing else is ever handed out with it. A batch
//!   is streamed with bounded memory, as `sync::fetch` is.
//! * **Access epochs** are S4's (`migrations/0006_access_epochs.sql`,
//!   `caches`): every access change gives its project or person a new
//!   random epoch in its own transaction. A grant carries the two epochs
//!   its view was built under (`perm::open_at`); they show no count, time
//!   or server-wide clock (BUG-1081). The server refuses a grant whose
//!   epochs are not the current ones on the next request; `GET /v1/epochs`
//!   gives a signed-in caller the current epochs of their person and of the
//!   projects they can see, for caches.

use std::{collections::BTreeMap, sync::Arc};

use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use veil_core::{
    cache::LruCache,
    hub::{
        grant::{request_signed, BatchRequest, ChainSource, Chains, Epochs, Grant, GrantBody, GRANT_TTL_MS},
        project::{Node, Projector, TreeSource},
        wire::{put_frame, MAX_WANTS},
    },
    identity::SeedSigner,
    object::{Object, Tree},
    ObjectId, VeilError,
};

use crate::{
    auth::Caller,
    error::{Error, Result},
    perm::{Project, Viewer},
    sync::{self, Source},
    Hub, HubState,
};

/// Most projects one epoch-feed request names.
pub const FEED_PROJECTS: usize = 1000;

/// The server's grant key, and the projected roots whose trees it stored.
pub struct Grants {
    key: SeedSigner,
    key_hex: String,
    stored: LruCache<()>,
}

impl Grants {
    /// Load or create the grant key in `data_dir` (`hub-grant-key`, an
    /// Ed25519 seed in hex, 0600). Servers sharing the data directory make
    /// and accept the same grants.
    pub fn load(data_dir: &std::path::Path) -> anyhow::Result<Grants> {
        let path = data_dir.join("hub-grant-key");
        if !path.exists() {
            let _ = crate::tls::write_private(&path, hex::encode(veil_core::crypto::random_bytes::<32>()).as_bytes());
        }
        let seed: [u8; 32] = hex::decode(std::fs::read_to_string(&path)?.trim())
            .ok()
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| anyhow::anyhow!("hub-grant-key must hold 32 bytes in hex"))?;
        let key = SeedSigner::from_seed(&seed);
        Ok(Grants {
            key_hex: key.verifying_hex(),
            key,
            stored: LruCache::new(8 << 20),
        })
    }

    /// The grant key's public half (hex).
    pub fn key_hex(&self) -> &str {
        &self.key_hex
    }

    /// Sign a grant (tests make expired or stale ones with it).
    pub fn issue(&self, body: &GrantBody) -> String {
        Grant::issue(&self.key, body)
    }

    /// The current access epochs of `project` and of `person` (anyone on
    /// Earth: 0), from S4's table (one indexed query).
    pub async fn current(&self, db: &sqlx::PgPool, project: i64, person: Option<i64>) -> Result<(i64, i64)> {
        let e = crate::caches::read_epochs(db, person.unwrap_or(0), Some(project)).await?;
        Ok((e.project.map_or(0, |(_, e)| e), person.map_or(0, |_| e.person)))
    }
}

/// Grants for `tips` (branch → projected snapshot), made with the epochs
/// `viewer` was built under (`perm::open_at`). A branch whose projected root cannot be
/// stored (the store failing, BUG-1083) gets none: the server logs it, and
/// the tips, S1's fetch and every pull still work.
pub async fn for_tips(
    hub: &Arc<Hub>,
    project: &Project,
    viewer: &Viewer,
    caller: &Caller,
    epochs: crate::caches::Epochs,
    tips: &BTreeMap<String, ObjectId>,
) -> Result<BTreeMap<String, String>> {
    let person = caller.person.as_ref().map(|p| p.id);
    let (epoch, person_epoch) = (epochs.project.map_or(0, |(_, e)| e), person.map_or(0, |_| epochs.person));
    let expires = veil_core::now_millis() + GRANT_TTL_MS;
    let mut out = BTreeMap::new();
    for (branch, snap) in tips {
        let root = match grant_root(hub, project, viewer, *snap).await {
            Ok(Some(root)) => root,
            Ok(None) => continue,
            Err(e) => {
                eprintln!("veil-server: no grant for a branch of project {}: {e:?}", project.id);
                continue;
            }
        };
        let body = GrantBody {
            project: project.name.clone(),
            project_id: project.id,
            person: caller.person.as_ref().map(|p| p.id),
            device: caller.person.as_ref().map(|p| p.device_key.clone()),
            root,
            epoch,
            person_epoch,
            expires,
        };
        out.insert(branch.clone(), hub.grants.issue(&body));
    }
    Ok(out)
}

/// The projected root tree of projected snapshot `snap`, with every tree
/// the projection rewrote stored (they exist nowhere else), so a chain
/// through them can be checked by the store's contents alone.
async fn grant_root(hub: &Arc<Hub>, project: &Project, viewer: &Viewer, snap: ObjectId) -> Result<Option<ObjectId>> {
    let root = sync::blocking(hub, project.id, move |src| Ok(src.snapshot(&snap)?.tree)).await?;
    if viewer.admin {
        return Ok(Some(root));
    }
    let memo = {
        let mut m = project.id.to_le_bytes().to_vec();
        m.extend_from_slice(&root.0);
        ObjectId::hash(&m)
    };
    if hub.grants.stored.get(&memo).is_some() {
        return Ok(Some(root));
    }
    let reals = sync::resolve(hub, project.id, &project.view(viewer).key(), &snap).await?;
    let (p, v) = (project.clone(), viewer.clone());
    let created = sync::blocking(hub, project.id, move |src| {
        let view = p.view(&v);
        for real in reals {
            let mut pr = Projector::new(src, &view);
            if pr.root(src.snapshot(&real)?.tree)? == root {
                return Ok(Some(pr.created.into_iter().map(|(id, (_, raw))| (id, raw)).collect::<Vec<_>>()));
            }
        }
        Ok(None)
    })
    .await?;
    let Some(created) = created else {
        eprintln!("veil-server: projected root {} of project {} not reproduced; no grant", root.short(), project.id);
        return Ok(None);
    };
    for (id, raw) in created {
        if !hub.objects.exists(project.id, &id).await? {
            hub.objects.put(project.id, &id, Bytes::from(raw)).await?;
        }
    }
    hub.grants.stored.insert(memo, (), 64);
    Ok(Some(root))
}

impl ChainSource for Source {
    fn tree(&self, id: &ObjectId) -> veil_core::Result<Option<Arc<Tree>>> {
        match self.node(id) {
            Ok(Node::Tree(t, _)) => Ok(Some(t)),
            Ok(Node::Leaf) | Err(VeilError::Missing(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn conflict_terms(&self, id: &ObjectId) -> veil_core::Result<Option<Vec<(ObjectId, u64)>>> {
        match self.raw(id) {
            Ok(raw) => Ok(match Object::decode(&raw)? {
                Object::Conflict(c) => Some(c.interleaved().flatten().map(|t| (t.id, t.size)).collect()),
                _ => None,
            }),
            Err(VeilError::Missing(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// What a request under a grant that does not hold gets. It says nothing
/// of any object.
fn grant_invalid() -> Error {
    Error::new(
        StatusCode::UNAUTHORIZED,
        "grant_invalid",
        "the read grant is not valid here (expired, voided by an access change, or not this device's): ask for the tips again",
    )
}

/// What an object the grant does not reach, and an object that is not
/// there, both get.
fn not_reached() -> Error {
    Error::not_found("no such object that your grant reaches")
}

/// The grant in `token`, if it may be used now for `project` by the
/// request for `ids` at `ts` signed `signature`. Checked before any object
/// is looked at.
async fn check(hub: &Hub, project: &str, token: &str, ts: i64, signature: Option<&str>, ids: &[ObjectId]) -> Result<Grant> {
    let g = Grant::verify(token, hub.grants.key_hex()).ok_or_else(grant_invalid)?;
    let now = veil_core::now_millis();
    if !g.usable(project, now, g.body.epoch, g.body.person_epoch) || !request_signed(&g, ts, ids, signature, now) {
        return Err(grant_invalid());
    }
    let (epoch, person_epoch) = hub.grants.current(&hub.db, g.body.project_id, g.body.person).await?;
    if !g.usable(project, now, epoch, person_epoch) {
        return Err(grant_invalid());
    }
    Ok(g)
}

/// Which of `wants` `grant`'s root reaches, in order, with the size each
/// one's entry records. Reads only trees the chains reach.
async fn reached(hub: &Arc<Hub>, grant: &Grant, wants: Vec<(Vec<ObjectId>, ObjectId)>) -> Result<Vec<(ObjectId, u64)>> {
    let root = grant.body.root;
    sync::blocking(hub, grant.body.project_id, move |src| {
        let mut chains = Chains::new(src, root);
        let mut out = Vec::new();
        for (chain, id) in &wants {
            if let Some(size) = chains.check(chain, id)? {
                out.push((*id, size));
            }
        }
        Ok(out)
    })
    .await
}

/// A checked object, from the store (`None`: not there). The one place the
/// object routes read an object: whatever holds it, only it is returned.
async fn read(hub: &Hub, project: i64, id: &ObjectId) -> Result<Option<Bytes>> {
    if let Some(b) = sync::builtin(id) {
        return Ok(Some(b));
    }
    Ok(hub.objects.get(project, id).await?)
}

/// Most objects, and about the most bytes, read ahead of the one a batch
/// sends next: its memory is bounded, as `sync::fetch`'s is (BUG-860). An
/// object counts the size its entry or conflict term records; one that
/// records none (a tree, an empty file) counts [`UNSIZED`] until it is read,
/// and then what it is.
const WINDOW: usize = 64;
const WINDOW_BYTES: u64 = 8 << 20;
const UNSIZED: u64 = 1 << 20;

/// Checked objects `items`, read a window ahead and sent as frames in
/// order; one that is not there is left out. A failure ends the stream
/// with an error, so it is never taken as whole.
fn stream(hub: Arc<Hub>, project: i64, items: Vec<(ObjectId, u64)>) -> sync::FrameStream {
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    tokio::spawn(async move {
        let mut set = tokio::task::JoinSet::new();
        let mut ready: std::collections::HashMap<usize, Option<Bytes>> = std::collections::HashMap::new();
        let (mut next, mut sent, mut ahead) = (0usize, 0usize, 0u64);
        // What each object read counts against the window: its recorded
        // size, or UNSIZED, then its real size once read.
        let mut cost: Vec<u64> = items.iter().map(|(_, size)| if *size == 0 { UNSIZED } else { *size }).collect();
        let mut out = Vec::new();
        while sent < items.len() {
            while next < items.len() && next - sent < WINDOW && (next == sent || ahead + cost[next] <= WINDOW_BYTES) {
                let (hub, id, i) = (hub.clone(), items[next].0, next);
                set.spawn(async move { (i, read(&hub, project, &id).await) });
                ahead += cost[next];
                next += 1;
            }
            while !ready.contains_key(&sent) {
                match set.join_next().await {
                    Some(Ok((i, Ok(raw)))) => {
                        let real = raw.as_ref().map_or(0, |r| r.len() as u64);
                        ahead = ahead - cost[i] + real;
                        cost[i] = real;
                        ready.insert(i, raw);
                    }
                    other => {
                        eprintln!("veil-server: an object batch stopped: {other:?}");
                        let _ = tx.send(Err(std::io::Error::other("the answer stopped"))).await;
                        return;
                    }
                }
            }
            if let Some(raw) = ready.remove(&sent).flatten() {
                put_frame(&mut out, &items[sent].0, &raw);
            }
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
    sync::FrameStream(rx)
}

fn header<'a>(h: &'a HeaderMap, name: &str) -> Option<&'a str> {
    h.get(name).and_then(|v| v.to_str().ok())
}

/// `Veil-Chain: id,id,…` (absent or empty: the root itself).
fn parse_chain(h: &HeaderMap) -> Result<Vec<ObjectId>> {
    match header(h, "veil-chain").map(str::trim) {
        None | Some("") => Ok(Vec::new()),
        Some(s) => s
            .split(',')
            .take(veil_core::hub::grant::MAX_CHAIN + 1)
            .map(|x| ObjectId::from_hex(x.trim()).map_err(|_| Error::bad_request("Veil-Chain: object ids in hex, separated by commas")))
            .collect(),
    }
}

/// `Veil-Signature: <unix ms>.<signature>`, absent for anyone on Earth.
fn parse_signature(h: &HeaderMap) -> Result<(i64, Option<String>)> {
    match header(h, "veil-signature") {
        None => Ok((0, None)),
        Some(s) => {
            let (ts, sig) = s.split_once('.').ok_or_else(|| Error::bad_request("Veil-Signature: <unix ms>.<signature>"))?;
            Ok((ts.parse().map_err(|_| Error::bad_request("Veil-Signature: <unix ms>.<signature>"))?, Some(sig.to_string())))
        }
    }
}

/// A single `bytes=START-[END]` range (`END` absent: to the end); `None`
/// for no range, or one this server does not take (it then sends the whole
/// object, as HTTP allows).
fn parse_range(h: &HeaderMap) -> Option<(u64, u64)> {
    let r = header(h, "range")?.strip_prefix("bytes=")?;
    let (a, b) = r.split_once('-')?;
    let start: u64 = a.trim().parse().ok()?;
    let end: u64 = if b.trim().is_empty() { u64::MAX } else { b.trim().parse().ok()? };
    (end >= start).then_some((start, end))
}

/// `GET /v1/objects/{p}/{id}`: one object, under the grant of `Veil-Grant`
/// at the end of `Veil-Chain`, the request signed in `Veil-Signature`;
/// `Range` supported (a dropped download resumes), reading only the bytes
/// asked for.
pub async fn get_object(State(hub): State<HubState>, Path((p, id)): Path<(String, String)>, headers: HeaderMap) -> Result<Response> {
    let token = header(&headers, "veil-grant").ok_or_else(grant_invalid)?;
    let id = ObjectId::from_hex(&id).map_err(|_| Error::bad_request("an object id is 64 hex digits"))?;
    let chain = parse_chain(&headers)?;
    let (ts, sig) = parse_signature(&headers)?;
    let grant = check(&hub, &p, token, ts, sig.as_deref(), &[id]).await?;
    if reached(&hub, &grant, vec![(chain, id)]).await?.is_empty() {
        return Err(not_reached());
    }
    let project = grant.body.project_id;
    let octets = (header::CONTENT_TYPE, "application/octet-stream".to_string());
    let Some((start, end)) = parse_range(&headers) else {
        let raw = read(&hub, project, &id).await?.ok_or_else(not_reached)?;
        return Ok(([octets], raw).into_response());
    };
    let (part, len) = match sync::builtin(&id) {
        Some(b) => (crate::store::slice(&b, start, end), b.len() as u64),
        None => hub.objects.get_range(project, &id, start, end).await?.ok_or_else(not_reached)?,
    };
    if start >= len {
        return Ok((StatusCode::RANGE_NOT_SATISFIABLE, [(header::CONTENT_RANGE, format!("bytes */{len}"))]).into_response());
    }
    let last = start + part.len() as u64 - 1;
    Ok((StatusCode::PARTIAL_CONTENT, [octets, (header::CONTENT_RANGE, format!("bytes {start}-{last}/{len}"))], part).into_response())
}

/// `POST /v1/objects/{p}:batch`: the objects of the request its grant
/// reaches, as object frames; the others are left out, alike whether they
/// exist or not.
pub async fn batch(State(hub): State<HubState>, Path(target): Path<String>, body: Bytes) -> Result<Response> {
    let Some(p) = target.strip_suffix(":batch") else {
        return Err(Error::not_found("no such route"));
    };
    let req: BatchRequest = serde_json::from_slice(&body).map_err(|e| Error::bad_request(format!("invalid batch request: {e}")))?;
    if req.wants.len() > MAX_WANTS {
        return Err(Error::bad_request(format!("at most {MAX_WANTS} objects per request")));
    }
    let ids: Vec<ObjectId> = req.wants.iter().map(|w| w.id).collect();
    let grant = check(&hub, p, &req.grant, req.ts, req.signature.as_deref(), &ids).await?;
    let items = reached(&hub, &grant, req.wants.into_iter().map(|w| (w.chain, w.id)).collect()).await?;
    let body = axum::body::Body::new(stream(hub.clone(), grant.body.project_id, items));
    Ok(([(header::CONTENT_TYPE, "application/octet-stream")], body).into_response())
}

#[derive(Deserialize)]
pub struct EpochsQuery {
    /// Project names, separated by commas.
    #[serde(default)]
    projects: String,
}

/// `GET /v1/epochs?projects=a,b` (signed in, BUG-1081): the caller's own
/// person epoch, and the current epoch of each named project the caller
/// can see; a project they cannot see, or that does not exist, is left out
/// alike. What the Veil daemon polls (S6); regional caches (S9) will
/// authenticate as the server's own. Every key asked for is answered with
/// its current epoch: nothing is paged, so no change is passed over
/// (BUG-1082).
pub async fn epochs(State(hub): State<HubState>, caller: Caller, Query(q): Query<EpochsQuery>) -> Result<Json<Epochs>> {
    caller.signed_in()?;
    let names: Vec<&str> = q.projects.split(',').map(str::trim).filter(|n| !n.is_empty()).collect();
    if names.len() > FEED_PROJECTS {
        return Err(Error::bad_request(format!("at most {FEED_PROJECTS} projects per request")));
    }
    let mut out = Epochs { person: caller.epochs.person, ..Default::default() };
    for name in names {
        let Ok((project, _, e)) = crate::perm::open_at(&hub, name, &caller).await else { continue };
        out.projects.insert(project.name, e.project.map_or(0, |(_, e)| e));
    }
    Ok(Json(out))
}
