//! The regional cache (milestone S9, `docs/HUB.md` §13.18; design:
//! `docs/design/server/phase-2-thin-clients.md` §4.1–§4.4):
//! `veil-server cache --upstream URL`.
//!
//! It answers S5's object routes (`GET /v1/objects/{p}/{id}`, `POST
//! /v1/objects/{p}:batch`) near the clients, from a bounded store of the
//! objects that passed through it, and passes everything else to the Veil
//! server with the client's own signed request. It holds **no permission
//! authority, no database and no key**: it serves an object only under a
//! read grant the server signed, for the device that signed the request,
//! at the end of a chain from the grant's root that it checks in its own
//! hash-checked store (`veil_core::hub::grant`, the checks the server and
//! the Veil daemon run), and only while the server has confirmed the
//! grant's access epochs at most [`epochs::STALE`] ago (`epochs`). Whatever
//! it cannot decide that way (a tree it does not hold, epochs not confirmed,
//! the grant key not known yet) goes to the server, which decides.
//!
//! * **Never wider than the server.** Every object reachable from a grant's
//!   projected root is one its holder may read, and nothing else is; the
//!   check reads only trees already reached from the root, and an object is
//!   looked up only after its chain allows it. A refused chain gets what
//!   the server gives: `404` alike for "not reachable" and "not there"; in
//!   a batch it is left out.
//! * **Removal within 5 seconds** (the owner's bound): epochs polled every
//!   second; a cache that cannot read the feed stops serving from its store
//!   (fail closed) and passes every request up.
//! * **Secrets stay ciphertext:** objects are kept as the server sends
//!   them; nothing is decrypted, and nothing new is encrypted.
//! * **Bounded:** the store by `--size` bytes; memory by `--memory` (the
//!   decoded trees, the store's index, and objects being read for answers).

pub mod disk;
pub mod epochs;
pub mod feed;
mod relay;

use std::{
    cell::Cell,
    collections::HashSet,
    net::SocketAddr,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering::Relaxed},
        Arc,
    },
    time::{Duration, Instant},
};

use anyhow::Context;
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use veil_core::{
    cache::LruCache,
    hub::{
        grant::{request_signed, BatchRequest, ChainSource, Chains, Grant},
        wire::{put_frame, MAX_WANTS},
    },
    object::{Object, Tree},
    ObjectId,
};

use crate::{
    error::Error,
    grant::{grant_invalid, header, not_reached, parse_chain, parse_range, parse_signature},
    tls::TlsSource,
};

/// Largest object the store keeps; larger ones pass through.
pub const MAX_OBJECT: u64 = 16 << 20;
/// Bytes of an answer gathered before they are sent.
const CHUNK: usize = 256 << 10;
/// How long a poll of the feed may take.
const POLL_TIMEOUT: Duration = Duration::from_secs(3);
/// Most objects being fetched from the server at once that later requests
/// can wait on, and how long they wait.
const MAX_FLIGHTS: usize = 1 << 16;
const FLIGHT_WAIT: Duration = Duration::from_secs(2);

pub struct Config {
    pub listen: SocketAddr,
    /// The Veil server: `https://host:port`.
    pub upstream: String,
    /// Its certificate (PEM), for a self-signed one.
    pub upstream_ca: Option<String>,
    /// The caches' token (the server's `<data>/hub-cache-token`).
    pub token: String,
    /// The cache's directory: its store, and its self-signed certificate.
    pub dir: PathBuf,
    pub tls: TlsSource,
    /// Most bytes of objects on disk.
    pub size: u64,
    /// About the most memory it holds beyond its fixed costs.
    pub memory: u64,
}

/// What the cache did, for its operator and the benchmarks.
#[derive(Default)]
pub struct Stats {
    pub requests: AtomicU64,
    /// Objects served from the store.
    pub local: AtomicU64,
    /// Objects the server sent through the cache.
    pub upstream: AtomicU64,
    /// Requests answered without the server: refused (an invalid grant or
    /// signature, a chain the root does not reach).
    pub refused: AtomicU64,
    /// Requests passed to the server.
    pub forwarded: AtomicU64,
    /// … of which because the grant's epochs were not confirmed current.
    pub unconfirmed: AtomicU64,
    /// Requests that waited for objects another request was fetching.
    pub joined: AtomicU64,
    /// Requests the server could not be reached for.
    pub unavailable: AtomicU64,
    pub polls: AtomicU64,
    pub poll_errors: AtomicU64,
}

pub struct Cache {
    up: reqwest::Client,
    base: String,
    token: String,
    pub store: disk::Store,
    /// Decoded trees, by the store's key.
    trees: LruCache<Arc<Tree>>,
    pub epochs: epochs::Tracker,
    /// KiB of objects being read for answers, across every request.
    budget: tokio::sync::Semaphore,
    budget_kib: u32,
    /// Objects a request is fetching from the server, by the store's key:
    /// a later request for one waits for it (closed when it is done)
    /// instead of asking again.
    flights: std::sync::Mutex<std::collections::HashMap<[u8; 32], Arc<tokio::sync::Semaphore>>>,
    pub stats: Stats,
}

/// The objects one request is fetching for others to wait on: done when
/// dropped (its answer finished, kept or not).
struct Flight {
    cache: Arc<Cache>,
    keys: Vec<[u8; 32]>,
}

impl Drop for Flight {
    fn drop(&mut self) {
        let mut f = self.cache.flights.lock().unwrap();
        for k in &self.keys {
            if let Some(s) = f.remove(k) {
                s.close();
            }
        }
    }
}

pub struct Running {
    pub addr: SocketAddr,
    /// The cache's certificate (PEM).
    pub cert_pem: String,
    pub cache: Arc<Cache>,
    shutdown: tokio::sync::watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl Running {
    pub async fn stop(self) {
        let _ = self.shutdown.send(true);
        let _ = self.task.await;
    }
}

/// Start the cache: open its store, start polling the server's feed, and
/// serve.
pub async fn start(c: Config) -> anyhow::Result<Running> {
    std::fs::create_dir_all(&c.dir)?;
    let (tls, cert_pem, _) = crate::tls::server_config(&c.tls, &c.dir)?;
    let mut b = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .read_timeout(Duration::from_secs(60))
        .pool_max_idle_per_host(256);
    if let Some(pem) = &c.upstream_ca {
        b = b.add_root_certificate(reqwest::Certificate::from_pem(pem.as_bytes()).context("the upstream certificate")?);
    }
    // A quarter of the memory for decoded trees, a quarter for the store's
    // index, half for objects being read.
    let quarter = (c.memory / 4).max(1 << 20);
    let store = disk::Store::open(&c.dir.join("store"), c.size, (quarter / disk::ENTRY_BYTES) as usize, MAX_OBJECT.min(quarter))
        .context("opening the cache's store")?;
    let budget_kib = ((c.memory / 2) >> 10).clamp(MAX_OBJECT >> 10, u32::MAX as u64 >> 4) as u32;
    let cache = Arc::new(Cache {
        up: b.build()?,
        base: c.upstream.trim_end_matches('/').to_string(),
        token: c.token.trim().to_string(),
        store,
        trees: LruCache::new(quarter as usize),
        epochs: epochs::Tracker::default(),
        budget: tokio::sync::Semaphore::new(budget_kib as usize),
        budget_kib,
        flights: Default::default(),
        stats: Stats::default(),
    });
    let listener = tokio::net::TcpListener::bind(c.listen).await?;
    let addr = listener.local_addr()?;
    let (tx, rx) = tokio::sync::watch::channel(false);
    let app = Router::new()
        .route("/v1/objects/{p}/{id}", get(get_object))
        .route("/v1/objects/{target}", post(batch))
        .layer(DefaultBodyLimit::max(crate::db::body_limit("")))
        .with_state(cache.clone());
    tokio::spawn(poll(cache.clone(), rx.clone()));
    let task = tokio::spawn(crate::serve_tls(listener, tls, app, rx));
    Ok(Running {
        addr,
        cert_pem,
        cache,
        shutdown: tx,
        task,
    })
}

// ---- the epoch feed --------------------------------------------------------------------------

/// Poll the server's feed every [`epochs::POLL`], and soon after a grant
/// names a new key, until stopped.
async fn poll(cache: Arc<Cache>, mut stop: tokio::sync::watch::Receiver<bool>) {
    let mut logged: Option<Instant> = None;
    loop {
        let started = Instant::now();
        let asked = cache.epochs.to_ask(started);
        match tokio::time::timeout(POLL_TIMEOUT, cache.feed(&asked)).await {
            Ok(Ok(answer)) => cache.epochs.apply(&asked, &answer),
            failed => {
                cache.stats.poll_errors.fetch_add(1, Relaxed);
                if logged.is_none_or(|t| t.elapsed() > Duration::from_secs(10)) {
                    let why = match failed {
                        Ok(Err(e)) => format!("{e:#}"),
                        _ => "timed out".into(),
                    };
                    eprintln!("veil-server cache: the server's epoch feed: {why}; serving from the store stops 5 s after its last answer");
                    logged = Some(Instant::now());
                }
            }
        }
        cache.stats.polls.fetch_add(1, Relaxed);
        tokio::select! {
            _ = tokio::time::sleep_until((started + epochs::POLL).into()) => {}
            _ = cache.epochs.wake.notified() => tokio::time::sleep_until((started + Duration::from_millis(50)).into()).await,
            _ = stop.changed() => return,
        }
    }
}

impl Cache {
    /// The server's answer for every key of `asked`, in requests of at most
    /// [`feed::FEED_KEYS`] keys.
    async fn feed(&self, asked: &epochs::Asked) -> anyhow::Result<feed::FeedAnswer> {
        let mut all = feed::FeedAnswer::default();
        let keys: Vec<(bool, &String)> = asked.projects.iter().map(|p| (true, p)).chain(asked.devices.iter().map(|d| (false, d))).collect();
        let mut chunks: Vec<&[(bool, &String)]> = keys.chunks(feed::FEED_KEYS).collect();
        if chunks.is_empty() {
            // Nothing to ask yet: the grant key still.
            chunks.push(&[]);
        }
        for chunk in chunks {
            let req = feed::FeedRequest {
                projects: chunk.iter().filter(|k| k.0).map(|k| k.1.clone()).collect(),
                devices: chunk.iter().filter(|k| !k.0).map(|k| k.1.clone()).collect(),
            };
            let r = self
                .up
                .post(format!("{}/v1/cache/epochs", self.base))
                .header(feed::TOKEN_HEADER, &self.token)
                .header(header::CONTENT_TYPE, "application/json")
                .body(serde_json::to_vec(&req)?)
                .send()
                .await?;
            anyhow::ensure!(r.status().is_success(), "HTTP {}", r.status());
            let a: feed::FeedAnswer = serde_json::from_slice(&r.bytes().await?)?;
            all.grant_key = a.grant_key;
            all.projects.extend(a.projects);
            all.devices.extend(a.devices);
        }
        Ok(all)
    }
}

// ---- deciding locally --------------------------------------------------------------------------

/// What the cache can say of a request by itself.
enum Decision {
    /// The grant, or the request's signature, does not hold: `grant_invalid`.
    Invalid,
    /// Only the server can say (the grant key or the epochs not confirmed).
    Forward,
    /// The answer's plan, in the request's order: each object the store
    /// serves (with its size), once, and each want only the server can
    /// decide (`None`: a tree of its chain, or the object, not held).
    /// A want in neither is refused.
    Checked(Vec<(ObjectId, Option<u64>)>),
}

/// The store, as a chain check reads it: trees decoded once (in
/// [`Cache::trees`]), every object hash-checked; `missed` once anything
/// asked for is not held, so a refusal after it is not final.
struct Local<'a> {
    cache: &'a Cache,
    project: &'a str,
    missed: Cell<bool>,
}

impl Local<'_> {
    fn raw(&self, id: &ObjectId) -> Option<Vec<u8>> {
        let raw = read_local(self.cache, self.project, id);
        if raw.is_none() {
            self.missed.set(true);
        }
        raw
    }
}

impl ChainSource for Local<'_> {
    fn tree(&self, id: &ObjectId) -> veil_core::Result<Option<Arc<Tree>>> {
        let k = ObjectId(disk::key(self.project, id));
        if let Some(t) = self.cache.trees.get(&k) {
            return Ok(Some(t));
        }
        let Some(raw) = self.raw(id) else { return Ok(None) };
        Ok(match Object::decode(&raw) {
            Ok(Object::Tree(t)) => {
                let t = Arc::new(t);
                self.cache.trees.insert(k, t.clone(), raw.len() * 2);
                Some(t)
            }
            _ => None,
        })
    }

    fn conflict_terms(&self, id: &ObjectId) -> veil_core::Result<Option<Vec<(ObjectId, u64)>>> {
        let Some(raw) = self.raw(id) else { return Ok(None) };
        Ok(match Object::decode(&raw) {
            Ok(Object::Conflict(c)) => Some(c.interleaved().flatten().map(|t| (t.id, t.size)).collect()),
            _ => None,
        })
    }
}

/// Object `id` of `project` from the store, checked; the empty tree and
/// the universal root, which no project stores, are anyone's.
fn read_local(cache: &Cache, project: &str, id: &ObjectId) -> Option<Vec<u8>> {
    if let Some(b) = crate::sync::builtin(id) {
        return Some(b.to_vec());
    }
    cache.store.get(project, id)
}

/// Decide what the cache can of a request under grant `token` for
/// `project`, signed `signature` at `ts`, for `wants` (chain, id); ids in
/// `skip` are not served. The grant and the request's signature first, then
/// the epochs, then each want's chain: no object is looked up before its
/// chain allows it.
async fn decide(
    cache: &Arc<Cache>,
    project: &str,
    token: &str,
    ts: i64,
    signature: Option<&str>,
    wants: Vec<(Vec<ObjectId>, ObjectId)>,
    skip: &HashSet<ObjectId>,
) -> Decision {
    let Some(key) = cache.epochs.grant_key() else { return Decision::Forward };
    let Some(g) = Grant::verify(token, &key) else { return Decision::Invalid };
    let now = veil_core::now_millis();
    let ids: Vec<ObjectId> = wants.iter().map(|w| w.1).collect();
    if !g.usable(project, now, g.body.epoch, g.body.person_epoch) || !request_signed(&g, ts, &ids, signature, now) {
        return Decision::Invalid;
    }
    if !cache.epochs.current(&g.body, Instant::now()) {
        cache.stats.unconfirmed.fetch_add(1, Relaxed);
        return Decision::Forward;
    }
    let (cache, project, root, skip) = (cache.clone(), project.to_string(), g.body.root, skip.clone());
    let checked = tokio::task::spawn_blocking(move || {
        let src = Local {
            cache: &cache,
            project: &project,
            missed: Cell::new(false),
        };
        let mut chains = Chains::new(&src, root);
        let (mut plan, mut local, mut up) = (Vec::new(), HashSet::new(), HashSet::new());
        for (chain, id) in &wants {
            if skip.contains(id) || local.contains(id) {
                continue;
            }
            let held = match chains.check(chain, id) {
                Ok(Some(_)) => crate::sync::builtin(id).map(|b| b.len() as u64).or_else(|| cache.store.has(&project, id)),
                // Refused: final only if everything it read was held.
                Ok(None) if !src.missed.get() => continue,
                Ok(None) | Err(_) => None,
            };
            match held {
                Some(size) => {
                    local.insert(*id);
                    plan.push((*id, Some(size)));
                }
                None if up.insert(*id) => plan.push((*id, None)),
                None => {}
            }
        }
        Decision::Checked(plan)
    })
    .await;
    checked.unwrap_or(Decision::Forward)
}

/// [`decide`], then, for the objects only the server can give: the request
/// fetches those nobody else is fetching (the [`Flight`] it holds until its
/// answer is done), and first waits, at most [`FLIGHT_WAIT`], for those
/// another request is fetching, then decides again. So many readers of a
/// new object (a tree after each landing) cost the server one request, not
/// one each.
async fn decide_joined(
    cache: &Arc<Cache>,
    project: &str,
    token: &str,
    ts: i64,
    signature: Option<&str>,
    wants: Vec<(Vec<ObjectId>, ObjectId)>,
    skip: &HashSet<ObjectId>,
) -> (Decision, Option<Flight>) {
    let d = decide(cache, project, token, ts, signature, wants.clone(), skip).await;
    let Decision::Checked(plan) = &d else { return (d, None) };
    let (mut mine, mut others) = (Vec::new(), Vec::new());
    {
        let mut f = cache.flights.lock().unwrap();
        for (id, _) in plan.iter().filter(|p| p.1.is_none()) {
            let k = disk::key(project, id);
            match f.get(&k) {
                Some(s) => others.push(s.clone()),
                None if f.len() < MAX_FLIGHTS => {
                    f.insert(k, Arc::new(tokio::sync::Semaphore::new(0)));
                    mine.push(k);
                }
                None => {}
            }
        }
    }
    let flight = (!mine.is_empty()).then(|| Flight { cache: cache.clone(), keys: mine });
    if others.is_empty() {
        return (d, flight);
    }
    cache.stats.joined.fetch_add(1, Relaxed);
    let _ = tokio::time::timeout(FLIGHT_WAIT, async {
        for s in others {
            // Closed when its fetch is done: an error is the wake-up.
            let _ = s.acquire().await;
        }
    })
    .await;
    (decide(cache, project, token, ts, signature, wants, skip).await, flight)
}

// ---- answers -----------------------------------------------------------------------------------

/// A body sent as it is produced; an error ends it unfinished, so it is
/// never taken as whole.
struct Chunks(tokio::sync::mpsc::Receiver<std::io::Result<Bytes>>);

impl hyper::body::Body for Chunks {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<std::io::Result<hyper::body::Frame<Bytes>>>> {
        self.0.poll_recv(cx).map(|o| o.map(|r| r.map(hyper::body::Frame::data)))
    }
}

type Tx = tokio::sync::mpsc::Sender<std::io::Result<Bytes>>;

fn unavailable() -> Error {
    Error::new(StatusCode::SERVICE_UNAVAILABLE, "unavailable", "the cache cannot reach the Veil server; try again")
}

fn broken(what: &str) -> std::io::Error {
    eprintln!("veil-server cache: an answer stopped: {what}");
    std::io::Error::other("the answer stopped")
}

impl Cache {
    fn kib(&self, size: u64) -> u32 {
        (size.div_ceil(1024).max(1)).min(self.budget_kib as u64) as u32
    }

    /// Keep the objects a relay collected (each checked against its id).
    async fn keep(self: &Arc<Self>, project: &str, kept: Vec<(ObjectId, Vec<u8>)>) {
        if kept.is_empty() {
            return;
        }
        let (c, p) = (self.clone(), project.to_string());
        let _ = tokio::task::spawn_blocking(move || {
            for (id, raw) in kept {
                c.store.put(&p, &id, &raw);
            }
        })
        .await;
    }

    /// Send the store's objects of `plan` (those with a size) to `out`
    /// and on to `tx`; one gone or damaged since the check is left out (the
    /// client asks again). `false` if the client went away.
    async fn locals(self: &Arc<Self>, project: &str, plan: &[(ObjectId, Option<u64>)], out: &mut Vec<u8>, tx: &Tx) -> bool {
        for (id, size) in plan {
            let Some(size) = size else { continue };
            let Ok(permit) = self.budget.acquire_many(self.kib(*size)).await else { return false };
            let (c, q, i) = (self.clone(), project.to_string(), *id);
            if let Ok(Some(raw)) = tokio::task::spawn_blocking(move || read_local(&c, &q, &i)).await {
                put_frame(out, id, &raw);
                self.stats.local.fetch_add(1, Relaxed);
            }
            drop(permit);
            if out.len() >= CHUNK && tx.send(Ok(Bytes::from(std::mem::take(out)))).await.is_err() {
                return false;
            }
        }
        true
    }

    /// Send the answer to a batch on to `tx`, in the request's order: the
    /// store's objects of `plan` read here, the others as the server's
    /// answer `resp` (a `200` of frames) brings them, dropping those in the
    /// relay's `sent` and keeping what the store takes. Before each frame
    /// of the server's, the store's objects planned before it go out.
    async fn answer(self: &Arc<Self>, project: &str, plan: Vec<(ObjectId, Option<u64>)>, resp: Option<reqwest::Response>, mut r: relay::Relay, tx: Tx) {
        let mut out = Vec::new();
        let at: std::collections::HashMap<ObjectId, usize> =
            plan.iter().enumerate().filter(|(_, p)| p.1.is_none()).map(|(i, p)| (p.0, i)).collect();
        let mut next = 0;
        if let Some(mut resp) = resp {
            loop {
                let chunk = match resp.chunk().await {
                    Ok(Some(c)) => c,
                    Ok(None) => break,
                    Err(e) => return drop(tx.send(Err(broken(&format!("{e}")))).await),
                };
                let mut rest = &chunk[..];
                let mut kept = Vec::new();
                loop {
                    match r.feed(&mut rest, &mut out, &mut kept) {
                        Ok(Some(id)) => {
                            self.stats.upstream.fetch_add(1, Relaxed);
                            if let Some(&i) = at.get(&id).filter(|i| **i >= next) {
                                if !self.locals(project, &plan[next..i], &mut out, &tx).await {
                                    return;
                                }
                                next = i + 1;
                            }
                        }
                        Ok(None) => break,
                        Err(e) => return drop(tx.send(Err(broken(e))).await),
                    }
                }
                self.keep(project, kept).await;
                if out.len() >= CHUNK && tx.send(Ok(Bytes::from(std::mem::take(&mut out)))).await.is_err() {
                    return;
                }
            }
            if !r.whole() {
                return drop(tx.send(Err(broken("the server's answer ended inside a frame"))).await);
            }
        }
        if self.locals(project, &plan[next..], &mut out, &tx).await && !out.is_empty() {
            let _ = tx.send(Ok(Bytes::from(out))).await;
        }
    }

    async fn post_batch(&self, project: &str, req: &BatchRequest) -> Result<reqwest::Response, Error> {
        self.stats.forwarded.fetch_add(1, Relaxed);
        let body = serde_json::to_vec(req).map_err(|e| Error::Other(e.into()))?;
        self.up
            .post(format!("{}/v1/objects/{}:batch", self.base, project))
            .header(header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(|_| {
                self.stats.unavailable.fetch_add(1, Relaxed);
                unavailable()
            })
    }
}

/// A server's answer that is not one to keep (an error, a range), passed
/// on as it is: its status, type, range and body.
fn pass_on(resp: reqwest::Response) -> Response {
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut headers = HeaderMap::new();
    for h in [header::CONTENT_TYPE, header::CONTENT_RANGE] {
        if let Some(v) = resp.headers().get(h.as_str()).and_then(|v| v.to_str().ok()).and_then(|v| v.parse().ok()) {
            headers.insert(h, v);
        }
    }
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    tokio::spawn(async move {
        let mut resp = resp;
        loop {
            match resp.chunk().await {
                Ok(Some(c)) => {
                    if tx.send(Ok(c)).await.is_err() {
                        return;
                    }
                }
                Ok(None) => return,
                Err(e) => return drop(tx.send(Err(broken(&format!("{e}")))).await),
            }
        }
    });
    (status, headers, axum::body::Body::new(Chunks(rx))).into_response()
}

fn frames_response(rx: tokio::sync::mpsc::Receiver<std::io::Result<Bytes>>) -> Response {
    ([(header::CONTENT_TYPE, "application/octet-stream")], axum::body::Body::new(Chunks(rx))).into_response()
}

/// `POST /v1/objects/{p}:batch`, as the server answers it: the objects of
/// the request that its grant reaches, as frames, in the request's order.
/// The store's are read here; the server sends the rest, asked with the
/// client's own signed request and told to skip what the cache sends.
async fn batch(State(cache): State<Arc<Cache>>, Path(target): Path<String>, body: Bytes) -> Response {
    cache.stats.requests.fetch_add(1, Relaxed);
    let Some(p) = target.strip_suffix(":batch") else {
        return Error::not_found("no such route").into_response();
    };
    let p = p.to_string();
    let mut req: BatchRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return Error::bad_request(format!("invalid batch request: {e}")).into_response(),
    };
    if req.wants.len() > MAX_WANTS || req.skip.len() > MAX_WANTS {
        return Error::bad_request(format!("at most {MAX_WANTS} objects per request")).into_response();
    }
    let mut skip: HashSet<ObjectId> = req.skip.iter().copied().collect();
    let wants = req.wants.iter().map(|w| (w.chain.clone(), w.id)).collect();
    let (decision, flight) = decide_joined(&cache, &p, &req.grant, req.ts, req.signature.as_deref(), wants, &skip).await;
    let (plan, upstream) = match decision {
        Decision::Invalid => {
            cache.stats.refused.fetch_add(1, Relaxed);
            return grant_invalid().into_response();
        }
        Decision::Forward => (Vec::new(), true),
        Decision::Checked(plan) => {
            let upstream = plan.iter().any(|p| p.1.is_none());
            (plan, upstream)
        }
    };
    if plan.is_empty() && !upstream {
        // Every want refused, by the server's own rule.
        cache.stats.refused.fetch_add(1, Relaxed);
    }
    let resp = if upstream {
        skip.extend(plan.iter().filter(|p| p.1.is_some()).map(|p| p.0));
        req.skip = skip.iter().copied().collect();
        match cache.post_batch(&p, &req).await {
            Ok(r) if r.status() == reqwest::StatusCode::OK => Some(r),
            // Nothing is sent yet: the server's refusal, as it is.
            Ok(r) => return pass_on(r),
            Err(e) => return e.into_response(),
        }
    } else {
        None
    };
    let r = relay::Relay::new(skip, req.wants.iter().map(|w| w.id).collect(), cache.store.max_object as usize);
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    tokio::spawn(async move {
        cache.answer(&p, plan, resp, r, tx).await;
        // What it fetched is kept: requests waiting on it look again.
        drop(flight);
    });
    frames_response(rx)
}

/// `GET /v1/objects/{p}/{id}`, as the server answers it: from the store
/// when the grant reaches the object there (`Range` as the server takes
/// it), else from the server with the client's own headers, keeping a
/// whole object that arrives.
async fn get_object(State(cache): State<Arc<Cache>>, Path((p, id)): Path<(String, String)>, headers: HeaderMap) -> Response {
    cache.stats.requests.fetch_add(1, Relaxed);
    let Some(token) = header(&headers, "veil-grant") else {
        cache.stats.refused.fetch_add(1, Relaxed);
        return grant_invalid().into_response();
    };
    let Ok(id) = ObjectId::from_hex(&id) else {
        return Error::bad_request("an object id is 64 hex digits").into_response();
    };
    let chain = match parse_chain(&headers) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    let (ts, sig) = match parse_signature(&headers) {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    let range = parse_range(&headers);
    let (decision, flight) = decide_joined(&cache, &p, token, ts, sig.as_deref(), vec![(chain, id)], &HashSet::new()).await;
    match decision {
        Decision::Invalid => {
            cache.stats.refused.fetch_add(1, Relaxed);
            grant_invalid().into_response()
        }
        Decision::Checked(plan) if plan.first().is_some_and(|p| p.1.is_some()) => {
            let permit = cache.budget.acquire_many(cache.kib(plan[0].1.unwrap_or(0))).await;
            let c = cache.clone();
            let q = p.clone();
            let raw = tokio::task::spawn_blocking(move || read_local(&c, &q, &id)).await;
            drop(permit);
            match raw {
                Ok(Some(raw)) => {
                    cache.stats.local.fetch_add(1, Relaxed);
                    local_answer(raw, range)
                }
                // Gone or damaged since the check: the server sends it.
                _ => forward_get(cache, p, id, headers, range.is_some(), flight).await,
            }
        }
        Decision::Checked(plan) if plan.is_empty() => {
            cache.stats.refused.fetch_add(1, Relaxed);
            not_reached().into_response()
        }
        _ => forward_get(cache, p, id, headers, range.is_some(), flight).await,
    }
}

/// An object from the store, whole or the `Range` asked for, as the server
/// answers it.
fn local_answer(raw: Vec<u8>, range: Option<(u64, u64)>) -> Response {
    let octets = (header::CONTENT_TYPE, "application/octet-stream".to_string());
    let Some((start, end)) = range else {
        return ([octets], raw).into_response();
    };
    let len = raw.len() as u64;
    if start >= len {
        return (StatusCode::RANGE_NOT_SATISFIABLE, [(header::CONTENT_RANGE, format!("bytes */{len}"))]).into_response();
    }
    let last = end.min(len - 1);
    let part = raw[start as usize..=last as usize].to_vec();
    (StatusCode::PARTIAL_CONTENT, [octets, (header::CONTENT_RANGE, format!("bytes {start}-{last}/{len}"))], part).into_response()
}

/// Ask the server for one object with the client's headers; pass its
/// answer on, keeping a whole object (no range) that matches its id.
async fn forward_get(cache: Arc<Cache>, p: String, id: ObjectId, headers: HeaderMap, ranged: bool, flight: Option<Flight>) -> Response {
    cache.stats.forwarded.fetch_add(1, Relaxed);
    let mut r = cache.up.get(format!("{}/v1/objects/{}/{}", cache.base, p, id.hex()));
    for h in ["veil-grant", "veil-chain", "veil-signature", "range"] {
        if let Some(v) = header(&headers, h) {
            r = r.header(h, v);
        }
    }
    let resp = match r.send().await {
        Ok(r) => r,
        Err(_) => {
            cache.stats.unavailable.fetch_add(1, Relaxed);
            return unavailable().into_response();
        }
    };
    if resp.status() != reqwest::StatusCode::OK || ranged {
        return pass_on(resp);
    }
    cache.stats.upstream.fetch_add(1, Relaxed);
    let (tx, rx) = tokio::sync::mpsc::channel(1);
    tokio::spawn(async move {
        let (mut resp, max) = (resp, cache.store.max_object as usize);
        let mut whole = Some(Vec::new());
        loop {
            match resp.chunk().await {
                Ok(Some(c)) => {
                    if let Some(w) = &mut whole {
                        if w.len() + c.len() <= max {
                            w.extend_from_slice(&c);
                        } else {
                            whole = None;
                        }
                    }
                    if tx.send(Ok(c)).await.is_err() {
                        return;
                    }
                }
                Ok(None) => break,
                Err(e) => return drop(tx.send(Err(broken(&format!("{e}")))).await),
            }
        }
        if let Some(w) = whole {
            cache.keep(&p, vec![(id, w)]).await;
        }
        drop(flight);
    });
    ([(header::CONTENT_TYPE, "application/octet-stream")], axum::body::Body::new(Chunks(rx))).into_response()
}

/// The cache's counters, as `veil-server cache` writes them on `SIGUSR1`.
pub fn stats_json(cache: &Cache) -> serde_json::Value {
    let s = &cache.stats;
    let (objects, bytes) = cache.store.usage();
    let (projects, devices) = cache.epochs.len();
    serde_json::json!({
        "requests": s.requests.load(Relaxed),
        "local": s.local.load(Relaxed),
        "upstream": s.upstream.load(Relaxed),
        "refused": s.refused.load(Relaxed),
        "forwarded": s.forwarded.load(Relaxed),
        "unconfirmed": s.unconfirmed.load(Relaxed),
        "joined": s.joined.load(Relaxed),
        "unavailable": s.unavailable.load(Relaxed),
        "polls": s.polls.load(Relaxed),
        "poll_errors": s.poll_errors.load(Relaxed),
        "stored_objects": objects,
        "stored_bytes": bytes,
        "polled_projects": projects,
        "polled_devices": devices,
    })
}
