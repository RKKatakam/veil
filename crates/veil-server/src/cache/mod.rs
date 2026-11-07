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

pub(crate) mod deadline;
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
/// The slices an answer is handed to the connection in, and the size of
/// each connection's write buffer: a connection holds about two of them
/// outside `--memory` (BUG-1181).
const SLICE: usize = 64 << 10;
/// How long a poll of the feed may take.
const POLL_TIMEOUT: Duration = Duration::from_secs(3);
/// Most objects being fetched from the server at once that later requests
/// can wait on, and how long they wait.
const MAX_FLIGHTS: usize = 1 << 16;
const FLIGHT_WAIT: Duration = Duration::from_secs(2);
/// Most objects one request marks in flight.
const MAX_MARKS: usize = 256;
/// How long a write to a client may stay pending before its connection is
/// closed (BUG-1181).
const WRITE_DEADLINE: Duration = Duration::from_secs(30);

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
    /// Most connections open at once; the next waits until one closes.
    /// Each may hold the HTTP layer's write buffer and one slice of an
    /// answer (64 KiB each) outside `memory`.
    pub max_connections: usize,
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
    /// KiB of answers being read or sent, across every request: held by
    /// each chunk until its connection takes it (BUG-1181).
    budget: Arc<tokio::sync::Semaphore>,
    budget_kib: u32,
    /// Objects a request is fetching from the server, by the store's key:
    /// a later request for one waits for it (closed when it is done)
    /// instead of asking again.
    flights: std::sync::Mutex<std::collections::HashMap<[u8; 32], Arc<tokio::sync::Semaphore>>>,
    pub stats: Stats,
}

/// The objects one request is fetching for others to wait on. A mark is
/// let go when its object is kept ([`Flight::done`]), and every mark when
/// the flight is dropped: once the server's answer has passed, or before
/// the request waits for its client or the budget (BUG-1180).
struct Flight {
    cache: Arc<Cache>,
    keys: Vec<[u8; 32]>,
}

impl Flight {
    fn done(&mut self, key: &[u8; 32]) {
        if let Some(i) = self.keys.iter().position(|k| k == key) {
            self.keys.swap_remove(i);
            if let Some(s) = self.cache.flights.lock().unwrap().remove(key) {
                s.close();
            }
        }
    }
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
    // The caches' token and the grant key never cross the network in clear.
    anyhow::ensure!(c.upstream.starts_with("https://"), "the upstream server must be an https:// URL (given: {})", c.upstream);
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
        budget: Arc::new(tokio::sync::Semaphore::new(budget_kib as usize)),
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
    let limits = crate::ConnectionLimits { write_deadline: WRITE_DEADLINE, max_connections: c.max_connections, buffer: SLICE };
    let task = tokio::spawn(crate::serve_tls(listener, tls, app, rx, Some(limits)));
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
    /// The answer's plan, in the request's order, each id once. A want in
    /// it is refused.
    Checked(Vec<(ObjectId, Plan)>),
}

/// What the cache plans for one object of a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Plan {
    /// Its chain checked and the store holds it (its size).
    Local(u64),
    /// Its chain checked, the store does not hold it: the server sends it
    /// (the size its entry records).
    Fetch(u64),
    /// Only the server can say: a tree of its chain is not held.
    Unknown,
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
            // Wanted again after a want only the server decides: where the
            // server sends it depends on which of its wants the server
            // allows, so the server answers it all (BUG-1182).
            if up.contains(id) {
                return Decision::Forward;
            }
            let p = match chains.check(chain, id) {
                Ok(Some(size)) => match crate::sync::builtin(id).map(|b| b.len() as u64).or_else(|| cache.store.has(&project, id)) {
                    Some(held) => Plan::Local(held),
                    None => Plan::Fetch(size),
                },
                // Refused: final only if everything it read was held.
                Ok(None) if !src.missed.get() => continue,
                Ok(None) | Err(_) => Plan::Unknown,
            };
            match p {
                Plan::Local(_) => local.insert(*id),
                _ => up.insert(*id),
            };
            plan.push((*id, p));
        }
        Decision::Checked(plan)
    })
    .await;
    checked.unwrap_or(Decision::Forward)
}

/// [`decide`], then, for the objects the server must send whose chains
/// checked: the request marks those nobody else is fetching (the
/// [`Flight`] it holds while it reads them from the server, at most
/// [`MAX_MARKS`]), and first waits, at most [`FLIGHT_WAIT`], for those
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
        // Only objects whose chain checked and that the store will keep
        // (BUG-1180): a fetch of anything else helps no one.
        let fetch = plan.iter().filter(|p| matches!(p.1, Plan::Fetch(size) if size <= cache.store.max_object));
        for (id, _) in fetch {
            let k = disk::key(project, id);
            match f.get(&k) {
                Some(s) => others.push(s.clone()),
                None if f.len() < MAX_FLIGHTS && mine.len() < MAX_MARKS => {
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

/// A chunk of an answer.
type Item = std::io::Result<Bytes>;

/// A body sent as it is produced; an error ends it unfinished, so it is
/// never taken as whole.
struct Chunks(tokio::sync::mpsc::Receiver<Item>);

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

fn body(rx: tokio::sync::mpsc::Receiver<Item>) -> axum::body::Body {
    axum::body::Body::new(Chunks(rx))
}

/// A chunk's bytes with their share of the budget, given back only when
/// the connection lets go of the bytes, that is, once they are written
/// (BUG-1181).
struct Held {
    bytes: Vec<u8>,
    _share: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl AsRef<[u8]> for Held {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

fn unavailable() -> Error {
    Error::new(StatusCode::SERVICE_UNAVAILABLE, "unavailable", "the cache cannot reach the Veil server; try again")
}

fn broken(what: &str) -> std::io::Error {
    eprintln!("veil-server cache: an answer stopped: {what}");
    std::io::Error::other("the answer stopped")
}

/// An answer being sent: bytes gathered with their share of the budget,
/// and sent with it. **It never waits holding marks:** before it waits for
/// its client or for the budget, it lets go of its [`Flight`], so a client
/// that does not read never holds up other readers (BUG-1180). And it waits
/// for the budget only after sending what it holds, so answers never wait
/// on each other in a cycle.
struct Out {
    cache: Arc<Cache>,
    tx: tokio::sync::mpsc::Sender<Item>,
    buf: Vec<u8>,
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl Out {
    fn new(cache: Arc<Cache>) -> (Out, tokio::sync::mpsc::Receiver<Item>) {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        (Out { cache, tx, buf: Vec::new(), permit: None }, rx)
    }

    fn take(&mut self, p: tokio::sync::OwnedSemaphorePermit) {
        match &mut self.permit {
            Some(q) => q.merge(p),
            None => self.permit = Some(p),
        }
    }

    /// The budget's share for `size` more bytes, if it is free now.
    fn try_reserve(&mut self, size: u64) -> bool {
        match self.cache.budget.clone().try_acquire_many_owned(self.cache.kib(size)) {
            Ok(p) => {
                self.take(p);
                true
            }
            Err(_) => false,
        }
    }

    /// The budget's share for `size` more bytes; `false` if the client went
    /// away.
    async fn reserve(&mut self, size: u64, flight: &mut Option<Flight>) -> bool {
        let n = self.cache.kib(size);
        match self.cache.budget.clone().try_acquire_many_owned(n) {
            Ok(p) => {
                self.take(p);
                return true;
            }
            Err(tokio::sync::TryAcquireError::Closed) => return false,
            Err(tokio::sync::TryAcquireError::NoPermits) => {}
        }
        *flight = None;
        if !self.flush(flight).await {
            return false;
        }
        match self.cache.budget.clone().acquire_many_owned(n).await {
            Ok(p) => {
                self.take(p);
                true
            }
            Err(_) => false,
        }
    }

    /// Send what it gathered, in slices of at most [`SLICE`] that share
    /// one owner holding the whole share of the budget: the connection's
    /// layer copies a slice at a time, so the share is given back only once
    /// it took the last one (BUG-1181). `false` if the client went away.
    async fn flush(&mut self, flight: &mut Option<Flight>) -> bool {
        if self.buf.is_empty() {
            self.permit = None;
            return true;
        }
        let all = Bytes::from_owner(Held { bytes: std::mem::take(&mut self.buf), _share: self.permit.take() });
        let mut at = 0;
        while at < all.len() {
            let piece = all.slice(at..(at + SLICE).min(all.len()));
            at += piece.len();
            match self.tx.try_send(Ok(piece)) {
                Ok(()) => {}
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => return false,
                Err(tokio::sync::mpsc::error::TrySendError::Full(item)) => {
                    *flight = None;
                    if self.tx.send(item).await.is_err() {
                        return false;
                    }
                }
            }
        }
        true
    }

    async fn flush_if_full(&mut self, flight: &mut Option<Flight>) -> bool {
        self.buf.len() < CHUNK || self.flush(flight).await
    }

    /// End the answer unfinished.
    async fn fail(mut self, e: std::io::Error) {
        self.permit = None;
        let _ = self.tx.send(Err(e)).await;
    }
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

    /// Send the store's objects of `plan` to `out`; one gone or damaged
    /// since the check is left out (the client asks again). `false` if the
    /// client went away.
    async fn locals(self: &Arc<Self>, project: &str, plan: &[(ObjectId, Plan)], out: &mut Out, flight: &mut Option<Flight>) -> bool {
        let wanted: Vec<(ObjectId, u64)> = plan.iter().filter_map(|(id, p)| match p {
            Plan::Local(size) => Some((*id, *size)),
            _ => None,
        }).collect();
        // Read in groups of up to 64 objects and about 1 MiB, each on one
        // blocking thread under one share of the budget, held until sent.
        let mut rest = &wanted[..];
        while !rest.is_empty() {
            let (mut n, mut bytes) = (0, 0u64);
            while n < rest.len() && n < 64 && (n == 0 || bytes + rest[n].1 <= 1 << 20) {
                bytes += rest[n].1;
                n += 1;
            }
            let (group, next) = rest.split_at(n);
            rest = next;
            if !out.reserve(bytes, flight).await {
                return false;
            }
            let (c, q, ids) = (self.clone(), project.to_string(), group.iter().map(|g| g.0).collect::<Vec<_>>());
            let read = tokio::task::spawn_blocking(move || ids.iter().map(|id| (*id, read_local(&c, &q, id))).collect::<Vec<_>>()).await;
            for (id, raw) in read.unwrap_or_default() {
                if let Some(raw) = raw {
                    put_frame(&mut out.buf, &id, &raw);
                    self.stats.local.fetch_add(1, Relaxed);
                }
            }
            if !out.flush_if_full(flight).await {
                return false;
            }
        }
        true
    }

    /// Send the answer to a batch, in the request's order: the store's
    /// objects of `plan` read here, the others as the server's answer `resp`
    /// (a `200` of frames) brings them, dropping those in the relay's `sent`
    /// and keeping what the store takes. Before each frame of the server's,
    /// the store's objects planned before it go out. Each mark of `flight`
    /// is let go once its object is kept, and all of them once the server's
    /// answer has passed.
    async fn answer(self: &Arc<Self>, project: &str, plan: Vec<(ObjectId, Plan)>, resp: Option<reqwest::Response>, mut r: relay::Relay, mut out: Out, mut flight: Option<Flight>) {
        let at: std::collections::HashMap<ObjectId, usize> =
            plan.iter().enumerate().filter(|(_, p)| !matches!(p.1, Plan::Local(_))).map(|(i, p)| (p.0, i)).collect();
        let mut next = 0;
        if let Some(mut resp) = resp {
            // The share of the budget of the frame being kept, and of those
            // kept but not stored yet.
            let mut keeping = None;
            let mut kept_shares = Vec::new();
            loop {
                let chunk = match resp.chunk().await {
                    Ok(Some(c)) => c,
                    Ok(None) => break,
                    Err(e) => return out.fail(broken(&format!("{e}"))).await,
                };
                if !out.reserve(chunk.len() as u64, &mut flight).await {
                    return;
                }
                let mut rest = &chunk[..];
                let mut kept = Vec::new();
                loop {
                    match r.feed(&mut rest, &mut out.buf, &mut kept) {
                        Ok(Some(f)) => {
                            self.stats.upstream.fetch_add(1, Relaxed);
                            kept_shares.extend(keeping.take());
                            if f.keeping {
                                match self.budget.clone().try_acquire_many_owned(self.kib(f.len as u64)) {
                                    Ok(p) => keeping = Some(p),
                                    Err(_) => r.stop_keeping(),
                                }
                            }
                            if let Some(&i) = at.get(&f.id).filter(|i| **i >= next) {
                                if !self.locals(project, &plan[next..i], &mut out, &mut flight).await {
                                    return;
                                }
                                next = i + 1;
                            }
                        }
                        Ok(None) => break,
                        Err(e) => return out.fail(broken(e)).await,
                    }
                }
                if !r.keeping() {
                    kept_shares.extend(keeping.take());
                }
                let ids: Vec<ObjectId> = kept.iter().map(|k| k.0).collect();
                self.keep(project, kept).await;
                kept_shares.clear();
                if let Some(f) = &mut flight {
                    ids.iter().for_each(|id| f.done(&disk::key(project, id)));
                }
                if !out.flush_if_full(&mut flight).await {
                    return;
                }
            }
            // The server's part has passed: nobody waits on this answer now.
            flight = None;
            if !r.whole() {
                return out.fail(broken("the server's answer ended inside a frame")).await;
            }
        }
        drop(flight);
        if self.locals(project, &plan[next..], &mut out, &mut None).await {
            out.flush(&mut None).await;
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

/// The status and the headers of a server's answer the cache passes on.
fn head_of(resp: &reqwest::Response) -> (StatusCode, HeaderMap) {
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut headers = HeaderMap::new();
    for h in [header::CONTENT_TYPE, header::CONTENT_RANGE] {
        if let Some(v) = resp.headers().get(h.as_str()).and_then(|v| v.to_str().ok()).and_then(|v| v.parse().ok()) {
            headers.insert(h, v);
        }
    }
    (status, headers)
}

/// A server's answer that is not one to keep (an error, a range), passed
/// on as it is: its status, type, range and body, each chunk under its
/// share of the budget.
fn pass_on(cache: &Arc<Cache>, resp: reqwest::Response) -> Response {
    let (status, headers) = head_of(&resp);
    let (mut out, rx) = Out::new(cache.clone());
    tokio::spawn(async move {
        let mut resp = resp;
        loop {
            match resp.chunk().await {
                Ok(Some(c)) => {
                    if !out.reserve(c.len() as u64, &mut None).await {
                        return;
                    }
                    out.buf.extend_from_slice(&c);
                    if !out.flush(&mut None).await {
                        return;
                    }
                }
                Ok(None) => return,
                Err(e) => return out.fail(broken(&format!("{e}"))).await,
            }
        }
    });
    (status, headers, body(rx)).into_response()
}

fn frames_response(rx: tokio::sync::mpsc::Receiver<Item>) -> Response {
    ([(header::CONTENT_TYPE, "application/octet-stream")], body(rx)).into_response()
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
            let upstream = plan.iter().any(|p| !matches!(p.1, Plan::Local(_)));
            (plan, upstream)
        }
    };
    if plan.is_empty() && !upstream {
        // Every want refused, by the server's own rule.
        cache.stats.refused.fetch_add(1, Relaxed);
    }
    let resp = if upstream {
        skip.extend(plan.iter().filter(|p| matches!(p.1, Plan::Local(_))).map(|p| p.0));
        req.skip = skip.iter().copied().collect();
        match cache.post_batch(&p, &req).await {
            Ok(r) if r.status() == reqwest::StatusCode::OK => Some(r),
            // Nothing is sent yet: the server's refusal, as it is.
            Ok(r) => return pass_on(&cache, r),
            Err(e) => return e.into_response(),
        }
    } else {
        None
    };
    let r = relay::Relay::new(skip, req.wants.iter().map(|w| w.id).collect(), cache.store.max_object as usize);
    let (out, rx) = Out::new(cache.clone());
    tokio::spawn(async move { cache.answer(&p, plan, resp, r, out, flight).await });
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
        Decision::Checked(plan) if matches!(plan.first(), Some((_, Plan::Local(_)))) => {
            let Some(&(_, Plan::Local(size))) = plan.first() else { unreachable!() };
            let (status, head, part) = local_head(size, range);
            if status == StatusCode::RANGE_NOT_SATISFIABLE {
                return (status, head).into_response();
            }
            let (mut out, rx) = Out::new(cache.clone());
            let slice = move |raw: Vec<u8>| match part {
                Some((start, last)) => raw[start as usize..=last as usize].to_vec(),
                None => raw,
            };
            if out.try_reserve(size) {
                let Ok(Some(raw)) = read_sized(&cache, &p, id, size).await else {
                    // Gone or damaged since the check: the server sends it.
                    return forward_get(cache, p, id, headers, range.is_some(), flight).await;
                };
                cache.stats.local.fetch_add(1, Relaxed);
                out.buf = slice(raw);
                tokio::spawn(async move { out.flush(&mut None).await });
                return (status, head, body(rx)).into_response();
            }
            // The budget is taken: the answer's head now, its bytes once its
            // share is free (one lost since the check ends it unfinished, and
            // the client asks again).
            tokio::spawn(async move {
                if !out.reserve(size, &mut None).await {
                    return;
                }
                match read_sized(&cache, &p, id, size).await {
                    Ok(Some(raw)) => {
                        cache.stats.local.fetch_add(1, Relaxed);
                        out.buf = slice(raw);
                        out.flush(&mut None).await;
                    }
                    _ => out.fail(broken("an object left the store since its check")).await,
                }
            });
            (status, head, body(rx)).into_response()
        }
        Decision::Checked(plan) if plan.is_empty() => {
            cache.stats.refused.fetch_add(1, Relaxed);
            not_reached().into_response()
        }
        _ => forward_get(cache, p, id, headers, range.is_some(), flight).await,
    }
}

/// Object `id` of `project` from the store, if it is still the `size` bytes
/// its check found.
fn read_sized(cache: &Arc<Cache>, project: &str, id: ObjectId, size: u64) -> tokio::task::JoinHandle<Option<Vec<u8>>> {
    let (c, q) = (cache.clone(), project.to_string());
    tokio::task::spawn_blocking(move || read_local(&c, &q, &id).filter(|raw| raw.len() as u64 == size))
}

/// The head of an answer of an object of `len` bytes from the store, whole
/// or the `Range` asked for, as the server answers it: the status, the
/// headers, and the bytes to send (`None`: all of them).
fn local_head(len: u64, range: Option<(u64, u64)>) -> (StatusCode, HeaderMap, Option<(u64, u64)>) {
    let mut h = HeaderMap::new();
    let Some((start, end)) = range else {
        h.insert(header::CONTENT_TYPE, "application/octet-stream".parse().expect("a header"));
        return (StatusCode::OK, h, None);
    };
    if start >= len {
        h.insert(header::CONTENT_RANGE, format!("bytes */{len}").parse().expect("a header"));
        return (StatusCode::RANGE_NOT_SATISFIABLE, h, None);
    }
    let last = end.min(len - 1);
    h.insert(header::CONTENT_TYPE, "application/octet-stream".parse().expect("a header"));
    h.insert(header::CONTENT_RANGE, format!("bytes {start}-{last}/{len}").parse().expect("a header"));
    (StatusCode::PARTIAL_CONTENT, h, Some((start, last)))
}

/// Ask the server for one object with the client's headers; pass its
/// answer on, each chunk under its share of the budget, keeping a whole
/// object (no range) that matches its id if the budget allows; `flight`'s
/// mark is let go once it is kept, or the server's answer has passed.
async fn forward_get(cache: Arc<Cache>, p: String, id: ObjectId, headers: HeaderMap, ranged: bool, mut flight: Option<Flight>) -> Response {
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
        return pass_on(&cache, resp);
    }
    cache.stats.upstream.fetch_add(1, Relaxed);
    let (mut out, rx) = Out::new(cache.clone());
    tokio::spawn(async move {
        let (mut resp, max) = (resp, cache.store.max_object as usize);
        // The object as it arrives, and its share of the budget.
        let mut whole: Option<(Vec<u8>, Option<tokio::sync::OwnedSemaphorePermit>)> = Some((Vec::new(), None));
        loop {
            match resp.chunk().await {
                Ok(Some(c)) => {
                    if let Some((w, share)) = &mut whole {
                        match cache.budget.clone().try_acquire_many_owned(cache.kib(c.len() as u64)) {
                            Ok(more) if w.len() + c.len() <= max => {
                                w.extend_from_slice(&c);
                                match share {
                                    Some(s) => s.merge(more),
                                    None => *share = Some(more),
                                }
                            }
                            _ => whole = None,
                        }
                    }
                    if !out.reserve(c.len() as u64, &mut flight).await {
                        return;
                    }
                    out.buf.extend_from_slice(&c);
                    if !out.flush(&mut flight).await {
                        return;
                    }
                }
                Ok(None) => break,
                Err(e) => return out.fail(broken(&format!("{e}"))).await,
            }
        }
        if let Some((w, _share)) = whole {
            cache.keep(&p, vec![(id, w)]).await;
        }
        drop(flight);
    });
    ([(header::CONTENT_TYPE, "application/octet-stream")], body(rx)).into_response()
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The caches' token and the grant key never cross the network in
    /// clear: an upstream that is not `https://` is refused at start.
    #[test]
    fn an_upstream_that_is_not_https_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        for upstream in ["http://127.0.0.1:8443", "127.0.0.1:8443", "HTTP://hub", "ftp://hub"] {
            let e = rt
                .block_on(start(Config {
                    listen: "127.0.0.1:0".parse().unwrap(),
                    upstream: upstream.into(),
                    upstream_ca: None,
                    token: "t".repeat(64),
                    dir: dir.path().to_path_buf(),
                    tls: TlsSource::SelfSigned,
                    size: 1 << 20,
                    memory: 64 << 20,
                    max_connections: 16,
                }))
                .err()
                .unwrap_or_else(|| panic!("{upstream} accepted"));
            assert!(e.to_string().contains("https://"), "{e}");
        }
        assert!(std::fs::read_dir(dir.path()).unwrap().next().is_none(), "nothing written before the refusal");
    }
}
