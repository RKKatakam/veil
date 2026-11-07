//! Read grants, the object routes and the access-epoch feed (`docs/HUB.md`
//! §13.13; [`veil_core::hub::grant`] has the grant and the chain check).
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
//!   through one function (`read`, over [`crate::store::Objects::get`]) and
//!   served on its own, after its own check: wherever the store keeps it (a
//!   pack, later: S28), nothing else is ever handed out with it. A batch is
//!   streamed with bounded memory, as `sync::fetch` is.
//! * **Access epochs.** Every change that can take access away bumps an
//!   epoch in its own transaction (database triggers,
//!   `migrations/0007_access_epochs.sql`). The server refuses a grant older
//!   than its project's or person's newest epoch on the next request;
//!   `GET /v1/epochs?since=N` lists the changes for caches.
//!
//! **Order matters when a grant is made:** the clock is read *before* the
//! caller's view is loaded. An access change committed after that read has
//! a higher epoch and voids the grant; one committed before it is in the
//! view.

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
        grant::{request_signed, BatchRequest, ChainSource, Chains, EpochChange, Epochs, Grant, GrantBody, GRANT_TTL_MS},
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

/// Most changes one epoch-feed answer lists.
pub const FEED_LIMIT: i64 = 10_000;

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
}

/// The access-epoch clock: every epoch committed so far is at most this.
pub async fn clock(db: &sqlx::PgPool) -> Result<i64> {
    Ok(sqlx::query_scalar("SELECT n FROM access_epoch_clock WHERE id = 1").fetch_optional(db).await?.unwrap_or(0))
}

/// The newest epoch of `project` and of `person`.
pub async fn newest_epoch(db: &sqlx::PgPool, project: i64, person: Option<i64>) -> Result<i64> {
    Ok(sqlx::query_scalar(
        "SELECT COALESCE(MAX(epoch), 0) FROM access_epochs WHERE (project_id = $1 AND person_id = 0) OR (project_id = 0 AND person_id = $2)",
    )
    .bind(project)
    .bind(person.unwrap_or(-1))
    .fetch_one(db)
    .await?)
}

/// Grants for `tips` (branch → projected snapshot), made with the epoch
/// `epoch` read before `viewer` was loaded. A branch whose projected root
/// cannot be stored gets none (the server logs it; S1's fetch still works).
pub async fn for_tips(
    hub: &Arc<Hub>,
    project: &Project,
    viewer: &Viewer,
    caller: &Caller,
    epoch: i64,
    tips: &BTreeMap<String, ObjectId>,
) -> Result<BTreeMap<String, String>> {
    let view = project.view(viewer).key();
    let expires = veil_core::now_millis() + GRANT_TTL_MS;
    let mut out = BTreeMap::new();
    for (branch, snap) in tips {
        let Some(root) = grant_root(hub, project, viewer, *snap).await? else { continue };
        let body = GrantBody {
            project: project.name.clone(),
            project_id: project.id,
            person: caller.person.as_ref().map(|p| p.id),
            device: caller.person.as_ref().map(|p| p.device_key.clone()),
            view: view.clone(),
            root,
            epoch,
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
    let reals = sync::resolve(hub, project.id, &snap).await?;
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

    fn conflict_terms(&self, id: &ObjectId) -> veil_core::Result<Option<Vec<ObjectId>>> {
        match self.raw(id) {
            Ok(raw) => Ok(match Object::decode(&raw)? {
                Object::Conflict(c) => Some(c.referenced_ids()),
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
    if !g.usable(project, now, 0) || !request_signed(&g, ts, ids, signature, now) {
        return Err(grant_invalid());
    }
    let newest = newest_epoch(&hub.db, g.body.project_id, g.body.person).await?;
    if !g.usable(project, now, newest) {
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

/// Most objects, and about the most bytes (by the sizes their entries
/// record), read ahead of the one a batch sends next: its memory is
/// bounded, as `sync::fetch`'s is (BUG-860).
const WINDOW: usize = 64;
const WINDOW_BYTES: u64 = 8 << 20;

/// Checked objects `items`, read a window ahead and sent as frames in
/// order; one that is not there is left out. A failure ends the stream
/// with an error, so it is never taken as whole.
fn stream(hub: Arc<Hub>, project: i64, items: Vec<(ObjectId, u64)>) -> sync::FrameStream {
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    tokio::spawn(async move {
        let mut set = tokio::task::JoinSet::new();
        let mut ready: std::collections::HashMap<usize, Option<Bytes>> = std::collections::HashMap::new();
        let (mut next, mut sent, mut ahead) = (0usize, 0usize, 0u64);
        let mut out = Vec::new();
        while sent < items.len() {
            while next < items.len() && next - sent < WINDOW && (next == sent || ahead + items[next].1 <= WINDOW_BYTES) {
                let (hub, id, i) = (hub.clone(), items[next].0, next);
                set.spawn(async move { (i, read(&hub, project, &id).await) });
                ahead += items[next].1;
                next += 1;
            }
            while !ready.contains_key(&sent) {
                match set.join_next().await {
                    Some(Ok((i, Ok(raw)))) => {
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
            ahead -= items[sent].1;
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

/// A single `bytes=START-[END]` range within `len` bytes.
fn parse_range(h: &HeaderMap, len: usize) -> Option<std::result::Result<(usize, usize), ()>> {
    let r = header(h, "range")?.strip_prefix("bytes=")?;
    let (a, b) = r.split_once('-')?;
    let start: usize = a.trim().parse().ok()?;
    let end: usize = if b.trim().is_empty() { len.saturating_sub(1) } else { b.trim().parse::<usize>().ok()?.min(len.saturating_sub(1)) };
    Some(if start >= len || end < start { Err(()) } else { Ok((start, end)) })
}

/// `GET /v1/objects/{p}/{id}`: one object, under the grant of `Veil-Grant`
/// at the end of `Veil-Chain`, the request signed in `Veil-Signature`;
/// `Range` supported (a dropped download resumes).
pub async fn get_object(State(hub): State<HubState>, Path((p, id)): Path<(String, String)>, headers: HeaderMap) -> Result<Response> {
    let token = header(&headers, "veil-grant").ok_or_else(grant_invalid)?;
    let id = ObjectId::from_hex(&id).map_err(|_| Error::bad_request("an object id is 64 hex digits"))?;
    let chain = parse_chain(&headers)?;
    let (ts, sig) = parse_signature(&headers)?;
    let grant = check(&hub, &p, token, ts, sig.as_deref(), &[id]).await?;
    if reached(&hub, &grant, vec![(chain, id)]).await?.is_empty() {
        return Err(not_reached());
    }
    let raw = read(&hub, grant.body.project_id, &id).await?.ok_or_else(not_reached)?;
    let octets = [(header::CONTENT_TYPE, "application/octet-stream".to_string())];
    match parse_range(&headers, raw.len()) {
        None => Ok((octets, raw).into_response()),
        Some(Ok((a, b))) => Ok((
            StatusCode::PARTIAL_CONTENT,
            [octets[0].clone(), (header::CONTENT_RANGE, format!("bytes {a}-{b}/{}", raw.len()))],
            raw.slice(a..=b),
        )
            .into_response()),
        Some(Err(())) => Ok((StatusCode::RANGE_NOT_SATISFIABLE, [(header::CONTENT_RANGE, format!("bytes */{}", raw.len()))]).into_response()),
    }
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
pub struct Since {
    #[serde(default)]
    since: i64,
}

/// `GET /v1/epochs?since=N`: access changes with an epoch above `N`, oldest
/// first, and `now`, the epoch to ask from next. Numeric ids only: no name,
/// path or content. Every epoch up to `now` is listed (they commit in
/// order); a key changed again since shows only its newest epoch.
pub async fn epochs(State(hub): State<HubState>, Query(q): Query<Since>) -> Result<Json<Epochs>> {
    let now = clock(&hub.db).await?;
    let rows: Vec<(i64, i64, i64)> = sqlx::query_as(
        "SELECT project_id, person_id, epoch FROM access_epochs WHERE epoch > $1 AND epoch <= $2 ORDER BY epoch LIMIT $3",
    )
    .bind(q.since)
    .bind(now)
    .bind(FEED_LIMIT)
    .fetch_all(&hub.db)
    .await?;
    let now = if rows.len() as i64 == FEED_LIMIT { rows.last().map_or(now, |r| r.2) } else { now };
    Ok(Json(Epochs {
        now,
        changes: rows
            .into_iter()
            .map(|(project, person, epoch)| EpochChange {
                project: (project != 0).then_some(project),
                person: (person != 0).then_some(person),
                epoch,
            })
            .collect(),
    }))
}
