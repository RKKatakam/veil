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
//!   decoded trees, the store's index, batch requests, and answers being
//!   sent) plus each connection's buffers; every connection's time by a
//!   minimum rate (`deadline`).

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
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use veil_core::{
    cache::LruCache,
    hub::{
        grant::{request_signed, BatchRequest, ChainSource, ChainWant, Chains, Grant},
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
/// How long a request keeps its marks while its client has not taken the
/// last chunk: a client that reads takes it within moments (BUG-1180).
const MARK_GRACE: Duration = Duration::from_millis(100);
/// How long a write to a client may stay pending before its connection is
/// closed (BUG-1181), and how long writes may wait in all before the
/// minimum rate counts (BUG-1183).
const WRITE_DEADLINE: Duration = Duration::from_secs(30);
/// The slowest client served, in bytes a second: past a grace, a request's
/// body must arrive, and its answer be read, at least this fast on average,
/// or its connection is closed, so every connection slot is given back in
/// bounded time (BUG-1183). 128 kbit/s: a slow mobile link.
const MIN_RATE: u64 = 16 << 10;
/// How long a request's body may take before [`MIN_RATE`] counts.
const BODY_GRACE: Duration = Duration::from_secs(20);
/// The largest batch body the cache decides itself; a larger one goes to
/// the server as it arrives, so the cache never holds it (BUG-1184). About
/// 20,000 wants two folders deep.
const LOCAL_BODY: usize = 4 << 20;
/// A batch decided here holds about this many times its body's bytes (the
/// parsed request, the copy sent to the server, the answer's plan), under
/// a share of the requests' pool (BUG-1184).
const REQUEST_FACTOR: u64 = 3;

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
    /// Each may hold its TLS and HTTP buffers outside `memory` (about
    /// 352 KiB, `docs/HUB.md` §13.18).
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
    /// each chunk until its connection takes it (BUG-1181). **No answer
    /// waits for it while holding any of it** (BUG-1185): see [`Out::reserve`].
    budget: Arc<tokio::sync::Semaphore>,
    budget_kib: u32,
    /// KiB of batch requests being read and answered (their bodies, parsed
    /// requests and plans), taken in one step before a body is read, and
    /// held until its answer ends (BUG-1184). Always taken before any of
    /// [`Cache::budget`], never while holding it, so waits for the two
    /// never form a cycle.
    requests: Arc<tokio::sync::Semaphore>,
    requests_kib: u32,
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
    // index, an eighth for batch requests, three eighths for answers.
    let quarter = (c.memory / 4).max(1 << 20);
    let store = disk::Store::open(&c.dir.join("store"), c.size, (quarter / disk::ENTRY_BYTES) as usize, MAX_OBJECT.min(quarter))
        .context("opening the cache's store")?;
    let requests = (c.memory / 8).max(REQUEST_FACTOR * LOCAL_BODY as u64);
    let requests_kib = (requests >> 10).min(u32::MAX as u64 >> 4) as u32;
    let budget_kib = ((c.memory / 2).saturating_sub(requests) >> 10).clamp(MAX_OBJECT >> 10, u32::MAX as u64 >> 4) as u32;
    let cache = Arc::new(Cache {
        up: b.build()?,
        base: c.upstream.trim_end_matches('/').to_string(),
        token: c.token.trim().to_string(),
        store,
        trees: LruCache::new(quarter as usize),
        epochs: epochs::Tracker::default(),
        budget: Arc::new(tokio::sync::Semaphore::new(budget_kib as usize)),
        budget_kib,
        requests: Arc::new(tokio::sync::Semaphore::new(requests_kib as usize)),
        requests_kib,
        flights: Default::default(),
        stats: Stats::default(),
    });
    let listener = tokio::net::TcpListener::bind(c.listen).await?;
    let addr = listener.local_addr()?;
    let (tx, rx) = tokio::sync::watch::channel(false);
    let app = Router::new()
        .route("/v1/objects/{p}/{id}", get(get_object))
        .route("/v1/objects/{target}", post(batch))
        .with_state(cache.clone());
    tokio::spawn(poll(cache.clone(), rx.clone()));
    let pace = deadline::Pace { stall: WRITE_DEADLINE, grace: WRITE_DEADLINE, min_rate: MIN_RATE };
    let limits = crate::ConnectionLimits { pace, max_connections: c.max_connections, buffer: SLICE };
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
/// `project`, signed `signature` at `ts`, for `wants`; ids in
/// `skip` are not served. The grant and the request's signature first, then
/// the epochs, then each want's chain: no object is looked up before its
/// chain allows it.
async fn decide(
    cache: &Arc<Cache>,
    project: &str,
    token: &str,
    ts: i64,
    signature: Option<&str>,
    wants: Arc<Vec<ChainWant>>,
    skip: &HashSet<ObjectId>,
) -> Decision {
    let Some(key) = cache.epochs.grant_key() else { return Decision::Forward };
    let Some(g) = Grant::verify(token, &key) else { return Decision::Invalid };
    let now = veil_core::now_millis();
    let ids: Vec<ObjectId> = wants.iter().map(|w| w.id).collect();
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
        for ChainWant { chain, id } in wants.iter() {
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
    wants: Arc<Vec<ChainWant>>,
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

/// A slice's bytes with its share of the budget, given back only when the
/// connection lets go of the bytes, that is, once they are written
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

/// How sending an object from the store in slices ended.
enum Streamed {
    Sent,
    /// Gone before any of it went out (evicted, or not its checked size).
    Gone,
    /// Damaged (then removed) after some of it may have gone out: the
    /// answer must end unfinished.
    Damaged,
    /// The client went away.
    Stopped,
}

/// What an answer holds beyond the bytes it sends: its marks (others wait
/// on them) and the object it is collecting to keep (its bytes and their
/// share of the budget). **Both are let go before the answer waits for the
/// budget, or for its client past [`MARK_GRACE`]**, so no answer waits for
/// the budget holding any of it (BUG-1185), and a slow client holds neither
/// marks (BUG-1180) nor an object's share (BUG-1186): the object is then
/// not kept, and nobody waits for it.
#[derive(Default)]
struct Hold {
    flight: Option<Flight>,
    keeping: Option<relay::Keeping>,
}

impl Hold {
    fn with(flight: Option<Flight>) -> Hold {
        Hold { flight, keeping: None }
    }

    fn let_go(&mut self) {
        self.flight = None;
        self.keeping = None;
    }

    /// Object `id` of `project` will not be kept: nobody waits for it.
    fn done(&mut self, project: &str, id: &ObjectId) {
        if let Some(f) = &mut self.flight {
            f.done(&disk::key(project, id));
        }
    }
}

/// An answer being sent: bytes gathered with their share of the budget,
/// and sent with it, **each slice of at most [`SLICE`] with its own share**,
/// given back once that slice is written, so what an answer holds while
/// its client reads is a slice or two whatever the object's size
/// (BUG-1186). It never waits long holding its [`Hold`] (above), and it
/// never waits for the budget holding any of it (BUG-1185): it sends what
/// it gathered first, so every share is free or on its way to a client, and
/// answers never wait on each other.
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
    /// away. If it is not free now, it lets go of `hold`, sends what it
    /// gathered (each slice's share with it), then waits, holding nothing.
    async fn reserve(&mut self, size: u64, hold: &mut Hold) -> bool {
        let n = self.cache.kib(size);
        match self.cache.budget.clone().try_acquire_many_owned(n) {
            Ok(p) => {
                self.take(p);
                return true;
            }
            Err(tokio::sync::TryAcquireError::Closed) => return false,
            Err(tokio::sync::TryAcquireError::NoPermits) => {}
        }
        hold.let_go();
        if !self.flush(hold).await {
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

    /// Send what it gathered, in slices of at most [`SLICE`], each its own
    /// bytes with its own part of the share, given back once the connection
    /// has written it (BUG-1181, BUG-1186). `false` if the client went away.
    async fn flush(&mut self, hold: &mut Hold) -> bool {
        let mut rest = std::mem::take(&mut self.buf);
        let mut share = self.permit.take();
        while !rest.is_empty() {
            let tail = if rest.len() > SLICE { rest.split_off(SLICE) } else { Vec::new() };
            let mine = match (&mut share, tail.is_empty()) {
                (Some(s), false) => s.split((self.cache.kib(rest.len() as u64) as usize).min(s.num_permits())),
                _ => share.take(),
            };
            let piece = Bytes::from_owner(Held { bytes: std::mem::replace(&mut rest, tail), _share: mine });
            match self.tx.try_send(Ok(piece)) {
                Ok(()) => {}
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => return false,
                // A client that reads takes it within moments; one that does
                // not is let go of what it would hold up.
                Err(tokio::sync::mpsc::error::TrySendError::Full(item)) => match self.tx.send_timeout(item, MARK_GRACE).await {
                    Ok(()) => {}
                    Err(tokio::sync::mpsc::error::SendTimeoutError::Closed(_)) => return false,
                    Err(tokio::sync::mpsc::error::SendTimeoutError::Timeout(item)) => {
                        hold.let_go();
                        if self.tx.send(item).await.is_err() {
                            return false;
                        }
                    }
                },
            }
        }
        true
    }

    async fn flush_if_full(&mut self, hold: &mut Hold) -> bool {
        self.buf.len() < SLICE || self.flush(hold).await
    }

    /// End the answer unfinished.
    async fn fail(mut self, e: std::io::Error) {
        self.end_unfinished(e).await;
    }

    async fn end_unfinished(&mut self, e: std::io::Error) {
        self.buf.clear();
        self.permit = None;
        let _ = self.tx.send(Err(e)).await;
    }
}

impl Cache {
    fn kib(&self, size: u64) -> u32 {
        (size.div_ceil(1024).max(1)).min(self.budget_kib as u64) as u32
    }

    /// The requests' pool's share for a batch body of `len` bytes.
    fn request_kib(&self, len: u64) -> u32 {
        ((REQUEST_FACTOR * len).div_ceil(1024).max(1)).min(self.requests_kib as u64) as u32
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

    /// Store the whole objects a relay collected, then let their shares and
    /// marks go.
    async fn keep_whole(self: &Arc<Self>, project: &str, kept: &mut Vec<relay::Keeping>, hold: &mut Hold) {
        if kept.is_empty() {
            return;
        }
        let all = std::mem::take(kept);
        let ids: Vec<ObjectId> = all.iter().map(|k| k.id).collect();
        self.keep(project, all.into_iter().map(|k| (k.id, k.bytes)).collect()).await;
        ids.iter().for_each(|id| hold.done(project, id));
    }

    /// Send object `id` of `project` from the store, `size` bytes as
    /// checked, to `out` in slices, each read under its own share, its hash
    /// checked as they go (BUG-1186): the bytes from `start` to `last` of it
    /// for `Some((start, last))`, or all of it as a frame for `None`.
    async fn stream_local(self: &Arc<Self>, project: &str, id: ObjectId, size: u64, part: Option<(u64, u64)>, out: &mut Out, hold: &mut Hold) -> Streamed {
        let (c, q) = (self.clone(), project.to_string());
        let Ok(Some(mut reading)) = tokio::task::spawn_blocking(move || c.store.open_object(&q, &id)).await else { return Streamed::Gone };
        if reading.size != size {
            return Streamed::Gone;
        }
        if part.is_none() {
            out.buf.extend_from_slice(&id.0);
            out.buf.extend_from_slice(&(size as u32).to_be_bytes());
        }
        let (start, last) = part.unwrap_or((0, size - 1));
        let mut at = 0u64;
        while at < size {
            let n = (SLICE as u64).min(size - at);
            if !out.reserve(n, hold).await {
                return Streamed::Stopped;
            }
            let c = self.clone();
            let Ok((r, Ok(piece))) = tokio::task::spawn_blocking(move || {
                let piece = c.store.read_some(&mut reading, n as usize);
                (reading, piece)
            })
            .await
            else {
                return Streamed::Damaged;
            };
            reading = r;
            let (from, to) = (start.max(at), (last + 1).min(at + n));
            if from < to {
                out.buf.extend_from_slice(&piece[(from - at) as usize..(to - at) as usize]);
            }
            at += n;
            if !out.flush_if_full(hold).await {
                return Streamed::Stopped;
            }
        }
        Streamed::Sent
    }

    /// Send the store's objects of `plan` to `out`; one gone or damaged
    /// before any of it went out is left out (the client asks again), one
    /// damaged after ends the answer unfinished. `false` if the answer
    /// stopped.
    async fn locals(self: &Arc<Self>, project: &str, plan: &[(ObjectId, Plan)], out: &mut Out, hold: &mut Hold) -> bool {
        let wanted: Vec<(ObjectId, u64)> = plan.iter().filter_map(|(id, p)| match p {
            Plan::Local(size) => Some((*id, *size)),
            _ => None,
        }).collect();
        // Objects of up to a slice are read whole in groups of about a
        // slice, each on one blocking thread under one share of the budget;
        // larger ones a slice at a time (BUG-1186).
        let mut rest = &wanted[..];
        while let Some(&(id, size)) = rest.first() {
            if size > SLICE as u64 {
                rest = &rest[1..];
                match self.stream_local(project, id, size, None, out, hold).await {
                    Streamed::Sent => {
                        self.stats.local.fetch_add(1, Relaxed);
                    }
                    Streamed::Gone => {}
                    Streamed::Stopped => return false,
                    Streamed::Damaged => {
                        out.end_unfinished(broken("an object in the store turned out damaged")).await;
                        return false;
                    }
                }
                continue;
            }
            let (mut n, mut bytes) = (0, 0u64);
            while n < rest.len() && rest[n].1 <= SLICE as u64 && (n == 0 || bytes + rest[n].1 <= SLICE as u64) {
                bytes += rest[n].1;
                n += 1;
            }
            let (group, next) = rest.split_at(n);
            rest = next;
            if !out.reserve(bytes, hold).await {
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
            if !out.flush_if_full(hold).await {
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
    async fn answer(self: &Arc<Self>, project: &str, plan: Vec<(ObjectId, Plan)>, resp: Option<reqwest::Response>, mut r: relay::Relay, mut out: Out, flight: Option<Flight>) {
        let at: std::collections::HashMap<ObjectId, usize> =
            plan.iter().enumerate().filter(|(_, p)| !matches!(p.1, Plan::Local(_))).map(|(i, p)| (p.0, i)).collect();
        let mut next = 0;
        let mut hold = Hold::with(flight);
        if let Some(mut resp) = resp {
            let mut kept = Vec::new();
            loop {
                let chunk = match resp.chunk().await {
                    Ok(Some(c)) => c,
                    Ok(None) => break,
                    Err(e) => return out.fail(broken(&format!("{e}"))).await,
                };
                if !out.reserve(chunk.len() as u64, &mut hold).await {
                    return;
                }
                let mut rest = &chunk[..];
                loop {
                    match r.feed(&mut rest, &mut out.buf, &mut hold.keeping, &mut kept) {
                        Ok(Some(f)) => {
                            self.stats.upstream.fetch_add(1, Relaxed);
                            // The frame before it is whole: keep it, and let
                            // its share go, before the store's objects may wait.
                            self.keep_whole(project, &mut kept, &mut hold).await;
                            hold.keeping = None;
                            if let Some(&i) = at.get(&f.id).filter(|i| **i >= next) {
                                if !self.locals(project, &plan[next..i], &mut out, &mut hold).await {
                                    return;
                                }
                                next = i + 1;
                            }
                            if f.keeping {
                                match self.budget.clone().try_acquire_many_owned(self.kib(f.len as u64)) {
                                    Ok(p) => hold.keeping = Some(relay::Keeping { id: f.id, bytes: Vec::with_capacity(f.len), share: Some(p) }),
                                    Err(_) => hold.done(project, &f.id),
                                }
                            }
                        }
                        Ok(None) => break,
                        Err(e) => return out.fail(broken(e)).await,
                    }
                }
                self.keep_whole(project, &mut kept, &mut hold).await;
                if !out.flush_if_full(&mut hold).await {
                    return;
                }
            }
            // The server's part has passed: nobody waits on this answer now.
            hold.let_go();
            if !r.whole() {
                return out.fail(broken("the server's answer ended inside a frame")).await;
            }
        }
        hold.let_go();
        if self.locals(project, &plan[next..], &mut out, &mut hold).await {
            out.flush(&mut hold).await;
        }
    }

    async fn post_batch(&self, project: &str, req: &Forwarded<'_>) -> Result<reqwest::Response, Error> {
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
                    if !out.reserve(c.len() as u64, &mut Hold::default()).await {
                        return;
                    }
                    out.buf.extend_from_slice(&c);
                    if !out.flush(&mut Hold::default()).await {
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

/// A batch request as the cache sends it to the server: the client's, with
/// `skip` naming what the cache sends itself ([`BatchRequest`]'s form).
#[derive(serde::Serialize)]
struct Forwarded<'a> {
    grant: &'a str,
    ts: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<&'a str>,
    wants: &'a [ChainWant],
    #[serde(skip_serializing_if = "Vec::is_empty")]
    skip: Vec<ObjectId>,
}

/// The next bytes of a request's body; `None` at its end.
async fn next_chunk(body: &mut axum::body::Body) -> Option<Result<Bytes, axum::Error>> {
    use hyper::body::Body as _;
    loop {
        match std::future::poll_fn(|cx| std::pin::Pin::new(&mut *body).poll_frame(cx)).await? {
            Ok(f) => match f.into_data() {
                Ok(d) if !d.is_empty() => return Some(Ok(d)),
                _ => continue,
            },
            Err(e) => return Some(Err(e)),
        }
    }
}

/// A request's body arriving: since when, and how many bytes so far. Its
/// next bytes are due by [`BODY_GRACE`] plus a second per [`MIN_RATE`]
/// bytes received, so a body takes at most that (BUG-1183).
struct Arrival {
    start: Instant,
    got: u64,
}

impl Arrival {
    /// The next bytes, or `None` at the end; `Err` if they are late, or the
    /// body broke.
    async fn next(&mut self, body: &mut axum::body::Body) -> Result<Option<Bytes>, Error> {
        let due = self.start + BODY_GRACE + Duration::from_secs_f64(self.got as f64 / MIN_RATE as f64);
        match tokio::time::timeout_at(due.into(), next_chunk(body)).await {
            Err(_) => Err(Error::new(StatusCode::REQUEST_TIMEOUT, "timeout", "the request's body did not arrive in time")),
            Ok(Some(Err(_))) => Err(Error::bad_request("the request's body could not be read")),
            Ok(Some(Ok(c))) => {
                self.got += c.len() as u64;
                Ok(Some(c))
            }
            Ok(None) => Ok(None),
        }
    }
}

/// `POST /v1/objects/{p}:batch`, as the server answers it: the objects of
/// the request that its grant reaches, as frames, in the request's order.
/// The store's are read here; the server sends the rest, asked with the
/// client's own signed request and told to skip what the cache sends.
///
/// **Its body is held only under a share of the requests' pool**, taken in
/// one step before it is read (BUG-1184): at most [`LOCAL_BODY`] bytes; a
/// larger body goes to the server as it arrives, whose answer is passed on
/// as it is (the server's own limit and checks then apply).
async fn batch(State(cache): State<Arc<Cache>>, Path(target): Path<String>, headers: HeaderMap, mut body: axum::body::Body) -> Response {
    cache.stats.requests.fetch_add(1, Relaxed);
    let Some(p) = target.strip_suffix(":batch") else {
        return Error::not_found("no such route").into_response();
    };
    let p = p.to_string();
    let declared = header(&headers, header::CONTENT_LENGTH.as_str()).and_then(|v| v.parse::<u64>().ok());
    if declared.is_some_and(|n| n > LOCAL_BODY as u64) {
        return forward_streamed(&cache, &p, None, body, Arrival { start: Instant::now(), got: 0 }).await;
    }
    // Its share for the bytes it declared (or a slice's, for a body of
    // unknown length), in one step, holding nothing else.
    let mut share = match cache.requests.clone().acquire_many_owned(cache.request_kib(declared.unwrap_or(SLICE as u64))).await {
        Ok(s) => s,
        Err(_) => return unavailable().into_response(),
    };
    let mut arrival = Arrival { start: Instant::now(), got: 0 };
    let mut raw = Vec::with_capacity(declared.unwrap_or(0) as usize);
    loop {
        match arrival.next(&mut body).await {
            Ok(Some(c)) => {
                raw.extend_from_slice(&c);
                // More than it declared cannot arrive; more than a body of
                // unknown length had only if it is free now (never waiting
                // while holding a share); larger than the cache decides
                // itself, or no share for it: the server's.
                let more = (cache.request_kib(raw.len() as u64) as usize).saturating_sub(share.num_permits());
                let grown = more == 0 || cache.requests.clone().try_acquire_many_owned(more as u32).map(|m| share.merge(m)).is_ok();
                if raw.len() > LOCAL_BODY || !grown {
                    let first = Bytes::from_owner(Held { bytes: raw, _share: Some(share) });
                    return forward_streamed(&cache, &p, Some(first), body, arrival).await;
                }
            }
            Ok(None) => break,
            Err(e) => return e.into_response(),
        }
    }
    drop(body);
    let req: BatchRequest = match serde_json::from_slice(&raw) {
        Ok(r) => r,
        Err(e) => return Error::bad_request(format!("invalid batch request: {e}")).into_response(),
    };
    drop(raw);
    if req.wants.len() > MAX_WANTS || req.skip.len() > MAX_WANTS {
        return Error::bad_request(format!("at most {MAX_WANTS} objects per request")).into_response();
    }
    let BatchRequest { grant, ts, signature, wants, skip } = req;
    let wants = Arc::new(wants);
    let mut skip: HashSet<ObjectId> = skip.into_iter().collect();
    let (decision, flight) = decide_joined(&cache, &p, &grant, ts, signature.as_deref(), wants.clone(), &skip).await;
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
        let fwd = Forwarded { grant: &grant, ts, signature: signature.as_deref(), wants: &wants, skip: skip.iter().copied().collect() };
        match cache.post_batch(&p, &fwd).await {
            Ok(r) if r.status() == reqwest::StatusCode::OK => Some(r),
            // Nothing is sent yet: the server's refusal, as it is.
            Ok(r) => return pass_on(&cache, r),
            Err(e) => return e.into_response(),
        }
    } else {
        None
    };
    let r = relay::Relay::new(skip, wants.iter().map(|w| w.id).collect(), cache.store.max_object as usize);
    drop(wants);
    let (out, rx) = Out::new(cache.clone());
    tokio::spawn(async move {
        // The request's share, until its answer ends.
        let _share = share;
        cache.answer(&p, plan, resp, r, out, flight).await
    });
    frames_response(rx)
}

/// A batch whose body is larger than the cache decides itself
/// ([`LOCAL_BODY`]): `first` and the rest of `body` go to the server as they
/// arrive, still due at the client's minimum rate, and the server's answer
/// is passed on as it is. The cache holds a chunk of it at a time. Past the
/// server's own limit it stops reading, and the server refuses what it got.
async fn forward_streamed(cache: &Arc<Cache>, p: &str, first: Option<Bytes>, mut body: axum::body::Body, mut arrival: Arrival) -> Response {
    cache.stats.forwarded.fetch_add(1, Relaxed);
    let (tx, rx) = tokio::sync::mpsc::channel::<Item>(1);
    let (late_tx, mut late) = tokio::sync::oneshot::channel::<Error>();
    tokio::spawn(async move {
        if let Some(b) = first {
            if tx.send(Ok(b)).await.is_err() {
                return;
            }
        }
        while arrival.got <= crate::db::body_limit("") as u64 {
            match arrival.next(&mut body).await {
                Ok(Some(c)) => {
                    if tx.send(Ok(c)).await.is_err() {
                        return;
                    }
                }
                Ok(None) => return,
                Err(e) => {
                    let _ = late_tx.send(e);
                    let _ = tx.send(Err(std::io::Error::other("the client's body stopped"))).await;
                    return;
                }
            }
        }
    });
    let sent = cache
        .up
        .post(format!("{}/v1/objects/{}:batch", cache.base, p))
        .header(header::CONTENT_TYPE, "application/json")
        .body(reqwest::Body::wrap(Chunks(rx)))
        .send()
        .await;
    match sent {
        Ok(r) => pass_on(cache, r),
        Err(_) => match late.try_recv() {
            Ok(e) => e.into_response(),
            Err(_) => {
                cache.stats.unavailable.fetch_add(1, Relaxed);
                unavailable().into_response()
            }
        },
    }
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
    let (decision, flight) = decide_joined(&cache, &p, token, ts, sig.as_deref(), Arc::new(vec![ChainWant { chain, id }]), &HashSet::new()).await;
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
            if size > SLICE as u64 {
                // A slice at a time, each under its own share, its hash
                // checked as it goes (BUG-1186): its head now; one gone or
                // damaged since the check ends it unfinished (the client asks
                // again, and the cache, which removed it, asks the server).
                tokio::spawn(async move {
                    let part = Some(part.unwrap_or((0, size - 1)));
                    match cache.stream_local(&p, id, size, part, &mut out, &mut Hold::default()).await {
                        Streamed::Sent => {
                            cache.stats.local.fetch_add(1, Relaxed);
                            out.flush(&mut Hold::default()).await;
                        }
                        Streamed::Stopped => {}
                        Streamed::Gone | Streamed::Damaged => out.fail(broken("an object left the store, or turned out damaged, since its check")).await,
                    }
                });
                return (status, head, body(rx)).into_response();
            }
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
                tokio::spawn(async move { out.flush(&mut Hold::default()).await });
                return (status, head, body(rx)).into_response();
            }
            // The budget is taken: the answer's head now, its bytes once its
            // share is free (one lost since the check ends it unfinished, and
            // the client asks again).
            tokio::spawn(async move {
                if !out.reserve(size, &mut Hold::default()).await {
                    return;
                }
                match read_sized(&cache, &p, id, size).await {
                    Ok(Some(raw)) => {
                        cache.stats.local.fetch_add(1, Relaxed);
                        out.buf = slice(raw);
                        out.flush(&mut Hold::default()).await;
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
        return pass_on(&cache, resp);
    }
    cache.stats.upstream.fetch_add(1, Relaxed);
    let (mut out, rx) = Out::new(cache.clone());
    tokio::spawn(async move {
        let (mut resp, max) = (resp, cache.store.max_object as usize);
        // The object as it arrives, and its share of the budget: let go of
        // before the answer waits for the budget or a slow client (`Hold`).
        let mut hold = Hold { flight, keeping: Some(relay::Keeping { id, bytes: Vec::new(), share: None }) };
        loop {
            match resp.chunk().await {
                Ok(Some(c)) => {
                    if !out.reserve(c.len() as u64, &mut hold).await {
                        return;
                    }
                    if let Some(k) = &mut hold.keeping {
                        match cache.budget.clone().try_acquire_many_owned(cache.kib(c.len() as u64)) {
                            Ok(more) if k.bytes.len() + c.len() <= max => {
                                k.bytes.extend_from_slice(&c);
                                match &mut k.share {
                                    Some(s) => s.merge(more),
                                    None => k.share = Some(more),
                                }
                            }
                            _ => hold.let_go(),
                        }
                    }
                    out.buf.extend_from_slice(&c);
                    if !out.flush(&mut hold).await {
                        return;
                    }
                }
                Ok(None) => break,
                Err(e) => return out.fail(broken(&format!("{e}"))).await,
            }
        }
        if let Some(k) = hold.keeping.take() {
            cache.keep(&p, vec![(id, k.bytes)]).await;
        }
        drop(hold);
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
