//! The daemon's process (`vl daemon run`, `docs/HUB.md` §13.29).
//!
//! **When it serves an object from its store** (in this order, nothing
//! looked up before its turn), as the regional cache does (§13.18):
//! 1. the grant verifies under the server's grant key, which the daemon
//!    fetched itself (`GET /v1/grant-key`), never one a client sent;
//! 2. the grant is for this project and not expired, and the request is
//!    signed by the grant's device (`veil_core::hub::grant`);
//! 3. the server confirmed the grant's access epochs (of its project and of
//!    its device's person) at most [`STALE_MS`] ago, and has not refused
//!    them since: a confirmation is the time a request the server answered
//!    `200` under those epochs was *sent*, so an access change committed
//!    at time R voids it by R + 5 s at the latest;
//! 4. the want's chain starts at the grant's root and each step is an entry
//!    of a tree in the store (`Chains`, the server's own check), and only
//!    then is the object looked up.
//!
//! **Everything else goes to the server, as the client signed it:** the
//! grant key not known, an invalid grant or signature (the server answers),
//! epochs not confirmed, a chain through a tree the store lacks, an object
//! not in the store. The forwarded request names in `skip` what the daemon
//! sent itself. What the server sends is checked against its id, kept and
//! passed on. A refusal is passed on as the end of the answer.
//!
//! **Confirmations without a session.** The daemon holds no device key and
//! no session. It confirms epochs by the server's own answers: every request
//! it passes on that the server answers `200` confirms, and once a second it
//! sends again, for each grant used in the last 15 minutes, the latest small
//! request signed under it (within the signature's 5 minutes), every object
//! skipped: the server checks the grant, its epochs and the device, and
//! sends nothing. `401` voids the epochs; no answer leaves them to go stale,
//! so without the server nothing is served from the store after 5 s (fail
//! closed), public objects included.
//!
//! **Memory** ([`MEMORY`] in all, besides the store's index and each
//! connection's buffers): requests are read under a share of their pool
//! (three times their length, taken before reading); trees read for chain
//! checks under a share of theirs (three times their length, never waited
//! for: past it the rest of the request goes to the server); every object
//! held (from the store or the server) under a share of the answers' budget,
//! taken before it is read and given back once it is written. A request
//! waits for a pool only while holding nothing of it, and the pools are
//! always taken in the order requests, trees, answers, so waits never form
//! a cycle.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    io::{BufWriter, Read, Write},
    os::unix::net::{UnixListener, UnixStream},
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc, Condvar, Mutex,
    },
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result};
use serde_json::json;
use veil_core::{
    hub::grant::{request_signed, BatchRequest, ChainSource, Chains, Grant, GrantKey},
    hub::wire::MAX_WANTS,
    object::{Object, Tree},
    ObjectId, VeilError,
};

use super::{
    proto::{self, Head, Request, MAX_OBJECT, MAX_REQUEST},
    store::{self, Store},
    Paths,
};

/// How long a confirmation of a grant's epochs holds (the owner's bound,
/// product decision 1 of the phase-2 design).
pub const STALE_MS: i64 = 5_000;
/// How often confirmations are renewed.
const POLL: Duration = Duration::from_secs(1);
/// Grants confirmed again for this long after their last use.
const KEEP_MS: i64 = 15 * 60 * 1000;
/// A request kept for renewing confirmations names at most this many
/// objects; it is sent again only while its signature's time is this far
/// inside the server's skew.
const REPLAY_WANTS: usize = 256;
const REPLAY_MARGIN_MS: i64 = 30_000;
/// Most grants' epochs tracked.
const MAX_CONFIRMS: usize = 1024;
/// Most projects followed (warm trees), and how long one is kept unused.
const MAX_FOLLOWS: usize = 64;
const FOLLOW_KEEP_MS: i64 = 7 * 24 * 3600 * 1000;
/// The daemon exits after this long with no read or pin through it.
const IDLE_MS: i64 = 3600 * 1000;
/// Most connections served at once; the next ones wait in the listener's
/// queue.
pub const MAX_CONNECTIONS: usize = 64;
/// Memory budgets: requests, trees read for chain checks, answers.
const REQUESTS: u64 = 16 << 20;
const TREES: u64 = 16 << 20;
const ANSWERS: u64 = 32 << 20;
pub const MEMORY: u64 = REQUESTS + TREES + ANSWERS;
/// A connection's time limits: its request within 20 s, each write within
/// 30 s.
const READ_TIMEOUT: Duration = Duration::from_secs(20);
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// Slices an oversized object from the server is skipped in.
const SLICE: usize = 64 << 10;

/// A byte budget: shares are taken before bytes are held and given back
/// when dropped.
pub struct Budget {
    left: Mutex<u64>,
    cv: Condvar,
    total: u64,
}

pub struct Share<'a> {
    b: &'a Budget,
    n: u64,
}

impl Drop for Share<'_> {
    fn drop(&mut self) {
        *self.b.left.lock().unwrap_or_else(|e| e.into_inner()) += self.n;
        self.b.cv.notify_all();
    }
}

impl Budget {
    pub fn new(total: u64) -> Budget {
        Budget { left: Mutex::new(total), cv: Condvar::new(), total }
    }

    /// Wait for `n` bytes (at most the whole budget). The caller holds no
    /// share of this budget.
    pub fn take(&self, n: u64) -> Share<'_> {
        let n = n.min(self.total);
        let mut left = self.left.lock().unwrap_or_else(|e| e.into_inner());
        while *left < n {
            left = self.cv.wait(left).unwrap_or_else(|e| e.into_inner());
        }
        *left -= n;
        Share { b: self, n }
    }

    pub fn try_take(&self, n: u64) -> Option<Share<'_>> {
        let mut left = self.left.lock().unwrap_or_else(|e| e.into_inner());
        if n > *left {
            return None;
        }
        *left -= n;
        Some(Share { b: self, n })
    }

    pub fn left(&self) -> u64 {
        *self.left.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// The server a request names.
struct Upstream {
    authority: String,
    agent: ureq::Agent,
    /// The grant key and when it was fetched (or last failed to be).
    key: Mutex<(Option<String>, Option<Instant>)>,
}

impl Upstream {
    fn url(&self, path: &str) -> String {
        format!("https://{}{path}", self.authority)
    }

    /// The server's grant key, fetched by the daemon itself (at most every
    /// 10 minutes; after a failure, not again for 5 s).
    fn grant_key(&self) -> Option<String> {
        let mut k = self.key.lock().unwrap_or_else(|e| e.into_inner());
        let fresh = |at: Option<Instant>, d: u64| at.is_some_and(|t| t.elapsed() < Duration::from_secs(d));
        if k.0.is_some() && fresh(k.1, 600) || k.0.is_none() && fresh(k.1, 5) {
            return k.0.clone();
        }
        let got = self
            .agent
            .get(&self.url("/v1/grant-key"))
            .call()
            .ok()
            .filter(|r| r.status() == 200)
            .and_then(|r| r.into_body().with_config().limit(4096).read_to_vec().ok())
            .and_then(|b| serde_json::from_slice::<GrantKey>(&b).ok())
            .map(|g| g.grant_key);
        // A key that stops being fetchable is kept until it is replaced.
        if got.is_some() || k.0.is_none() {
            k.0 = got;
        }
        k.1 = Some(Instant::now());
        k.0.clone()
    }
}

/// What a confirmation is of: the grants of one device (or anyone on
/// Earth's) for one project of one server, under one pair of epochs.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct EpochKey {
    authority: String,
    project: String,
    device: String,
    epoch: i64,
    person_epoch: i64,
}

#[derive(Default)]
struct Confirm {
    /// The send time (unix ms) of the latest request the server answered
    /// `200` under these epochs.
    confirmed: i64,
    /// The send time of the latest answer of either kind, and whether it
    /// was a refusal.
    verdict_at: i64,
    void: bool,
    /// The latest small request signed under these epochs, sent again to
    /// renew the confirmation.
    replay: Option<BatchRequest>,
    replay_expires: i64,
    used: i64,
}

#[derive(Default)]
pub struct Stats {
    pub requests: AtomicU64,
    pub from_store: AtomicU64,
    pub from_upstream: AtomicU64,
    pub forwarded: AtomicU64,
    pub refused_upstream: AtomicU64,
    pub unavailable: AtomicU64,
    pub polls: AtomicU64,
    pub poll_errors: AtomicU64,
    pub voided: AtomicU64,
    pub peer_refused: AtomicU64,
}

pub struct Daemon {
    paths: Paths,
    store: Arc<Store>,
    upstreams: Mutex<HashMap<String, Arc<Upstream>>>,
    confirms: Mutex<HashMap<EpochKey, Confirm>>,
    follows: Mutex<BTreeMap<(String, String), i64>>,
    requests: Budget,
    trees: Budget,
    answers: Budget,
    pub stats: Stats,
    stop: AtomicBool,
    active: (Mutex<usize>, Condvar),
    peak_connections: AtomicUsize,
    socket_ino: AtomicU64,
    /// When someone last read or pinned through it (unix ms).
    last_used: std::sync::atomic::AtomicI64,
    /// Whether its Veil home's identity existed at start.
    had_identity: bool,
}

fn now() -> i64 {
    veil_core::now_millis()
}

/// The time limits of the daemon's own requests to the server.
fn upstream_agent(authority: &str) -> Result<ureq::Agent> {
    Ok(crate::hub::upstream_agent_config(authority)?
        .timeout_connect(Some(Duration::from_secs(5)))
        .timeout_recv_response(Some(Duration::from_secs(30)))
        .timeout_per_read(Some(Duration::from_secs(30)))
        .timeout_send_body(Some(Duration::from_secs(30)))
        .build()
        .new_agent())
}

/// A valid `host[:port]` of a Veil server.
fn valid_authority(a: &str) -> bool {
    !a.is_empty() && a.len() <= 255 && a.bytes().all(|b| b.is_ascii_alphanumeric() || b"-.:[]".contains(&b))
}

/// A valid project name, as the server takes them.
fn valid_project(p: &str) -> bool {
    (1..=64).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-_.".contains(&b))
}

/// Reads trees for chain checks from the store, each checked against its
/// id, under the trees' budget (never waited for: past it, an error, and
/// the rest of the request goes to the server).
struct StoreSource<'a> {
    d: &'a Daemon,
    authority: &'a str,
    project: &'a str,
    shares: std::cell::RefCell<Vec<Share<'a>>>,
}

impl StoreSource<'_> {
    fn raw(&self, id: &ObjectId) -> veil_core::Result<Option<Vec<u8>>> {
        let k = store::key(self.authority, self.project, id);
        let Some(size) = self.d.store.size(&k) else { return Ok(None) };
        let share = self.d.trees.try_take(size * 3).ok_or_else(|| VeilError::Unavailable("the daemon's tree budget is in use".into()))?;
        let raw = self.d.store.read(&k, id);
        self.shares.borrow_mut().push(share);
        Ok(raw)
    }
}

impl ChainSource for StoreSource<'_> {
    fn tree(&self, id: &ObjectId) -> veil_core::Result<Option<Arc<Tree>>> {
        Ok(match self.raw(id)?.map(|r| Object::decode(&r)) {
            Some(Ok(Object::Tree(t))) => Some(Arc::new(t)),
            _ => None,
        })
    }

    fn conflict_terms(&self, id: &ObjectId) -> veil_core::Result<Option<Vec<(ObjectId, u64)>>> {
        Ok(match self.raw(id)?.map(|r| Object::decode(&r)) {
            Some(Ok(Object::Conflict(c))) => Some(c.interleaved().flatten().map(|t| (t.id, t.size)).collect()),
            _ => None,
        })
    }
}

impl Daemon {
    pub fn new(paths: Paths, store: Arc<Store>) -> Daemon {
        let follows = std::fs::read(paths.state.join("follow.json"))
            .ok()
            .and_then(|b| serde_json::from_slice::<Vec<(String, String, i64)>>(&b).ok())
            .unwrap_or_default()
            .into_iter()
            .map(|(a, p, t)| ((a, p), t))
            .collect();
        Daemon {
            paths,
            store,
            upstreams: Mutex::new(HashMap::new()),
            confirms: Mutex::new(HashMap::new()),
            follows: Mutex::new(follows),
            requests: Budget::new(REQUESTS),
            trees: Budget::new(TREES),
            answers: Budget::new(ANSWERS),
            stats: Stats::default(),
            stop: AtomicBool::new(false),
            active: (Mutex::new(0), Condvar::new()),
            peak_connections: AtomicUsize::new(0),
            socket_ino: AtomicU64::new(0),
            last_used: std::sync::atomic::AtomicI64::new(now()),
            had_identity: crate::ctx::identity_path().exists(),
        }
    }

    fn upstream(&self, authority: &str) -> Result<Arc<Upstream>> {
        let mut u = self.upstreams.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(x) = u.get(authority) {
            return Ok(x.clone());
        }
        if u.len() >= 64 {
            bail!("too many servers");
        }
        let x = Arc::new(Upstream { authority: authority.to_string(), agent: upstream_agent(authority)?, key: Mutex::new((None, None)) });
        u.insert(authority.to_string(), x.clone());
        Ok(x)
    }

    fn confirms(&self) -> std::sync::MutexGuard<'_, HashMap<EpochKey, Confirm>> {
        self.confirms.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// May the store serve under these epochs now?
    fn confirmed(&self, k: &EpochKey) -> bool {
        self.confirms().get(k).is_some_and(|c| !c.void && c.confirmed > 0 && now() - c.confirmed <= STALE_MS)
    }

    /// The server answered (`ok`: `200`, else a refusal of the grant) a
    /// request under `k` sent at `sent_at`. A later-sent answer wins.
    fn verdict(&self, k: &EpochKey, sent_at: i64, ok: bool) {
        let mut cs = self.confirms();
        let c = cs.entry(k.clone()).or_default();
        if sent_at < c.verdict_at {
            return;
        }
        c.verdict_at = sent_at;
        if ok {
            c.confirmed = c.confirmed.max(sent_at);
            c.void = false;
        } else if !c.void {
            c.void = true;
            self.stats.voided.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// A request under `k` was checked (grant and signature valid): keep it
    /// for renewing confirmations if it is small.
    fn used(&self, k: &EpochKey, req: &BatchRequest, expires: i64) {
        let mut cs = self.confirms();
        if !cs.contains_key(k) && cs.len() >= MAX_CONFIRMS {
            let oldest = cs.iter().min_by_key(|(_, c)| c.used).map(|(k, _)| k.clone());
            if let Some(o) = oldest {
                cs.remove(&o);
            }
        }
        let c = cs.entry(k.clone()).or_default();
        c.used = now();
        if req.wants.len() <= REPLAY_WANTS && c.replay.as_ref().is_none_or(|r| r.ts <= req.ts) {
            c.replay = Some(BatchRequest {
                grant: req.grant.clone(),
                ts: req.ts,
                signature: req.signature.clone(),
                wants: req.wants.clone(),
                skip: req.wants.iter().map(|w| w.id).collect(),
            });
            c.replay_expires = expires;
        }
    }

    fn follow(&self, authority: &str, project: &str) {
        let mut f = self.follows.lock().unwrap_or_else(|e| e.into_inner());
        let k = (authority.to_string(), project.to_string());
        let fresh = !f.contains_key(&k);
        if fresh && f.len() >= MAX_FOLLOWS {
            return;
        }
        let t = now();
        let stale = f.get(&k).is_none_or(|old| t - old > 3_600_000);
        f.insert(k, t);
        if fresh || stale {
            let list: Vec<(&String, &String, &i64)> = f.iter().map(|((a, p), t)| (a, p, t)).collect();
            if let Ok(b) = serde_json::to_vec(&list) {
                let tmp = self.paths.state.join(format!("follow.json.tmp{}", std::process::id()));
                if std::fs::write(&tmp, b).is_ok() {
                    let _ = std::fs::rename(&tmp, self.paths.state.join("follow.json"));
                }
            }
        }
    }

    // ---- the socket -------------------------------------------------------------------

    /// Serve on `listener` until stopped.
    pub fn serve(self: &Arc<Self>, listener: UnixListener) -> Result<()> {
        use std::os::unix::fs::MetadataExt;
        self.socket_ino.store(std::fs::metadata(&self.paths.socket)?.ino(), Ordering::SeqCst);
        let bg = self.clone();
        std::thread::spawn(move || bg.background());
        for conn in listener.incoming() {
            if self.stop.load(Ordering::SeqCst) {
                break;
            }
            let Ok(conn) = conn else { continue };
            // At most MAX_CONNECTIONS at once: the next wait here, then in
            // the listener's queue.
            {
                let (m, cv) = &self.active;
                let mut n = m.lock().unwrap_or_else(|e| e.into_inner());
                while *n >= MAX_CONNECTIONS {
                    n = cv.wait(n).unwrap_or_else(|e| e.into_inner());
                }
                *n += 1;
                self.peak_connections.fetch_max(*n, Ordering::Relaxed);
            }
            let d = self.clone();
            std::thread::Builder::new().stack_size(512 << 10).spawn(move || {
                let _ = d.connection(conn);
                let (m, cv) = &d.active;
                *m.lock().unwrap_or_else(|e| e.into_inner()) -= 1;
                cv.notify_one();
            })?;
        }
        self.shutdown();
        Ok(())
    }

    fn shutdown(&self) {
        use std::os::unix::fs::MetadataExt;
        // Remove the socket only if it is still ours.
        if std::fs::metadata(&self.paths.socket).is_ok_and(|m| m.ino() == self.socket_ino.load(Ordering::SeqCst)) {
            let _ = std::fs::remove_file(&self.paths.socket);
        }
    }

    fn connection(&self, mut s: UnixStream) -> Result<()> {
        // Only this user's processes (the directory is 0700 too).
        if super::peer_uid(&s) != Some(super::my_uid()) {
            self.stats.peer_refused.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        s.set_read_timeout(Some(READ_TIMEOUT))?;
        s.set_write_timeout(Some(WRITE_TIMEOUT))?;
        let (kind, len) = proto::read_head(&mut s, MAX_REQUEST)?;
        if kind != proto::Q {
            bail!("not a request");
        }
        let _share = self.requests.take(len as u64 * 3);
        let req: Request = serde_json::from_slice(&proto::read_payload(&mut s, len)?)?;
        let mut w = BufWriter::with_capacity(SLICE, s);
        match req {
            Request::Batch { upstream, project, batch } => {
                self.stats.requests.fetch_add(1, Ordering::Relaxed);
                self.last_used.store(now(), Ordering::Relaxed);
                let head = self.batch(&mut w, &upstream, &project, batch)?;
                end(&mut w, &head)?;
            }
            Request::Pin { upstream, project, key, roots } => {
                self.last_used.store(now(), Ordering::Relaxed);
                let ok = valid_authority(&upstream) && valid_project(&project) && key.len() <= 128 && roots.len() <= 64;
                let status = match ok && self.store.set_pin(&key, &upstream, &project, roots).is_ok() {
                    true => None,
                    false => Some(400),
                };
                end(&mut w, &Head { status, body: None })?;
            }
            Request::Follows => {
                let f: Vec<(String, String)> = self.follows.lock().unwrap_or_else(|e| e.into_inner()).keys().cloned().collect();
                end(&mut w, &Head { status: None, body: Some(json!(f)) })?;
            }
            Request::Status => end(&mut w, &Head { status: None, body: Some(self.status()) })?,
            Request::Stop => {
                self.stop.store(true, Ordering::SeqCst);
                end(&mut w, &Head::default())?;
                // Wake the accept loop.
                let _ = UnixStream::connect(&self.paths.socket);
            }
        }
        Ok(())
    }

    pub fn status(&self) -> serde_json::Value {
        let u = self.store.usage();
        let s = &self.stats;
        let ld = |a: &AtomicU64| a.load(Ordering::Relaxed);
        let t = now();
        let confirmed = self.confirms().values().filter(|c| !c.void && c.confirmed > 0 && t - c.confirmed <= STALE_MS).count();
        json!({
            "pid": std::process::id(),
            "socket": self.paths.socket,
            "store": {
                "bytes": u.bytes, "objects": u.objects, "limit": u.limit, "pins": u.pins, "ready": u.ready,
                "evicted": ld(&self.store.counters.evicted), "damaged": ld(&self.store.counters.damaged),
                "not_kept": ld(&self.store.counters.not_kept), "pinned_bytes": ld(&self.store.counters.pinned_bytes),
            },
            "requests": ld(&s.requests), "from_store": ld(&s.from_store), "from_upstream": ld(&s.from_upstream),
            "forwarded": ld(&s.forwarded), "refused_upstream": ld(&s.refused_upstream), "unavailable": ld(&s.unavailable),
            "polls": ld(&s.polls), "poll_errors": ld(&s.poll_errors), "voided": ld(&s.voided), "peer_refused": ld(&s.peer_refused),
            "confirmed": confirmed,
            "upstreams": self.upstreams.lock().unwrap_or_else(|e| e.into_inner()).keys().cloned().collect::<Vec<_>>(),
            "follows": self.follows.lock().unwrap_or_else(|e| e.into_inner()).len(),
            "memory": { "budget": MEMORY, "free": self.requests.left() + self.trees.left() + self.answers.left() },
            "peak_connections": self.peak_connections.load(Ordering::Relaxed),
        })
    }

    // ---- objects ----------------------------------------------------------------------

    /// Answer a batch: what the store may serve, then what the server
    /// sends for the rest. Returns the answer's end.
    fn batch(&self, w: &mut impl Write, authority: &str, project: &str, req: BatchRequest) -> Result<Head> {
        if !valid_authority(authority) || !valid_project(project) || req.wants.len() > MAX_WANTS || req.skip.len() > MAX_WANTS {
            return Ok(Head { status: Some(400), body: None });
        }
        let up = self.upstream(authority)?;
        self.follow(authority, project);
        let ids: Vec<ObjectId> = req.wants.iter().map(|w| w.id).collect();
        let (checked, from_store) = self.decide(&up, project, &req, &ids);
        // From the store, each under its share of the answers' budget.
        let mut sent: HashSet<ObjectId> = HashSet::new();
        for (id, size) in from_store {
            let k = store::key(authority, project, &id);
            let _share = self.answers.take(size);
            if let Some(raw) = self.store.read(&k, &id) {
                proto::write_object(w, &id, &raw)?;
                sent.insert(id);
                self.stats.from_store.fetch_add(1, Ordering::Relaxed);
            }
        }
        let skipped: HashSet<ObjectId> = req.skip.iter().copied().collect();
        if ids.iter().all(|i| sent.contains(i) || skipped.contains(i)) {
            return Ok(Head::default());
        }
        self.forward(w, &up, project, req, checked.as_ref(), &sent)
    }

    /// Steps 1–4: the epochs the request's grant is under (when its grant
    /// and signature check), and the wants the store may serve, each once,
    /// with its size.
    fn decide(&self, up: &Upstream, project: &str, req: &BatchRequest, ids: &[ObjectId]) -> (Option<EpochKey>, Vec<(ObjectId, u64)>) {
        let Some(key) = up.grant_key() else { return (None, Vec::new()) };
        let Some(g) = Grant::verify(&req.grant, &key) else { return (None, Vec::new()) };
        let t = now();
        if !g.usable(project, t, g.body.epoch, g.body.person_epoch) || !request_signed(&g, req.ts, ids, req.signature.as_deref(), t) {
            return (None, Vec::new());
        }
        let k = EpochKey {
            authority: up.authority.clone(),
            project: project.to_string(),
            device: g.body.device.clone().unwrap_or_default(),
            epoch: g.body.epoch,
            person_epoch: g.body.person_epoch,
        };
        self.used(&k, req, g.body.expires);
        if !self.confirmed(&k) || !self.store.ready() {
            return (Some(k), Vec::new());
        }
        let src = StoreSource { d: self, authority: &up.authority, project, shares: Default::default() };
        let mut chains = Chains::new(&src, g.body.root);
        let skip: HashSet<ObjectId> = req.skip.iter().copied().collect();
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for want in &req.wants {
            if skip.contains(&want.id) || !seen.insert(want.id) {
                continue;
            }
            match chains.check(&want.chain, &want.id) {
                Ok(Some(recorded)) if recorded <= MAX_OBJECT as u64 => {
                    if let Some(size) = self.store.size(&store::key(&up.authority, project, &want.id)) {
                        out.push((want.id, size));
                    }
                }
                Ok(_) => {}
                // The trees' budget is in use: the rest goes to the server.
                Err(_) => break,
            }
        }
        (Some(k), out)
    }

    /// Pass the request on to the server, as the client signed it, leaving
    /// out what was sent; check, keep and pass on what it sends.
    fn forward(&self, w: &mut impl Write, up: &Upstream, project: &str, req: BatchRequest, checked: Option<&EpochKey>, sent: &HashSet<ObjectId>) -> Result<Head> {
        self.stats.forwarded.fetch_add(1, Ordering::Relaxed);
        let wanted: HashSet<ObjectId> = req.wants.iter().map(|w| w.id).collect();
        let mut skip = req.skip.clone();
        skip.extend(sent.iter().copied());
        let body = serde_json::to_vec(&BatchRequest { skip, ..req })?;
        let sent_at = now();
        let resp = match up.agent.post(&up.url(&format!("/v1/objects/{project}:batch"))).header("content-type", "application/json").send(&body[..]) {
            Ok(r) => r,
            Err(_) => {
                self.stats.unavailable.fetch_add(1, Ordering::Relaxed);
                return Ok(Head { status: Some(503), body: None });
            }
        };
        drop(body);
        let status = resp.status().as_u16();
        if let Some(k) = checked {
            match status {
                200 => self.verdict(k, sent_at, true),
                // The grant and signature checked here: the server's
                // refusal is of its epochs or its device.
                401 => self.verdict(k, sent_at, false),
                _ => {}
            }
        }
        if status != 200 {
            self.stats.refused_upstream.fetch_add(1, Ordering::Relaxed);
            return Ok(Head { status: Some(status), body: None });
        }
        let mut r = resp.into_body().into_reader();
        loop {
            let mut head = [0u8; 36];
            match read_full(&mut r, &mut head)? {
                0 => break,
                36 => {}
                _ => bail!("the server's answer ended inside a frame"),
            }
            let id = ObjectId(head[..32].try_into().expect("32 bytes"));
            let len = u32::from_be_bytes(head[32..].try_into().expect("4 bytes")) as usize;
            if !wanted.contains(&id) {
                bail!("the server sent an object not asked for");
            }
            if len > MAX_OBJECT {
                // Too large to hold: left out, and its reader asks the
                // server itself.
                let mut buf = vec![0u8; SLICE];
                let mut left = len;
                while left > 0 {
                    let n = left.min(SLICE);
                    r.read_exact(&mut buf[..n])?;
                    left -= n;
                }
                continue;
            }
            let _share = self.answers.take(len as u64);
            let mut raw = vec![0u8; len];
            r.read_exact(&mut raw)?;
            if ObjectId::hash(&raw) != id {
                bail!("the server sent an object that does not match its id");
            }
            self.store.put(&store::key(&up.authority, project, &id), &id, &raw);
            proto::write_object(w, &id, &raw)?;
            self.stats.from_upstream.fetch_add(1, Ordering::Relaxed);
        }
        Ok(Head::default())
    }

    // ---- once a second ----------------------------------------------------------------

    fn background(self: Arc<Self>) {
        let mut follower: Option<std::process::Child> = None;
        let mut spawned: Option<Instant> = None;
        loop {
            let tick = Instant::now();
            if self.gone() {
                self.stop.store(true, Ordering::SeqCst);
                let _ = UnixStream::connect(&self.paths.socket);
                if let Some(mut c) = follower.take() {
                    let _ = c.kill();
                    let _ = c.wait();
                }
                // The socket may be gone: end the accept loop directly.
                self.shutdown();
                std::process::exit(0);
            }
            if let Some(limit) = super::configured_limit(&self.paths) {
                self.store.set_limit(limit);
            }
            self.renew();
            self.tend_follows(&mut follower, &mut spawned);
            std::thread::sleep(POLL.saturating_sub(tick.elapsed()));
        }
    }

    /// Stopped, turned off, its socket or directory gone (another daemon
    /// in its place), its Veil home's identity gone (a removed home), or
    /// idle for [`IDLE_MS`] (no read or pin through it; the next `vl` that
    /// needs it starts it again, with its store as it was).
    fn gone(&self) -> bool {
        use std::os::unix::fs::MetadataExt;
        self.stop.load(Ordering::SeqCst)
            || self.paths.off.exists()
            || (self.had_identity && !crate::ctx::identity_path().exists())
            || now() - self.last_used.load(Ordering::Relaxed) > IDLE_MS
            || !std::fs::metadata(&self.paths.socket).is_ok_and(|m| m.ino() == self.socket_ino.load(Ordering::SeqCst))
    }

    /// Renew the confirmation of every grant's epochs used recently.
    fn renew(&self) {
        let t = now();
        let mut due: Vec<(EpochKey, BatchRequest)> = Vec::new();
        {
            let mut cs = self.confirms();
            cs.retain(|_, c| t - c.used <= KEEP_MS);
            for (k, c) in cs.iter() {
                let Some(r) = &c.replay else { continue };
                if r.ts.abs_diff(t) as i64 > veil_core::hub::grant::REQUEST_SKEW_MS - REPLAY_MARGIN_MS || c.replay_expires <= t + 1000 {
                    continue;
                }
                due.push((k.clone(), r.clone()));
            }
        }
        for (k, r) in due {
            let Ok(up) = self.upstream(&k.authority) else { continue };
            let Ok(body) = serde_json::to_vec(&r) else { continue };
            let sent_at = now();
            self.stats.polls.fetch_add(1, Ordering::Relaxed);
            match up.agent.post(&up.url(&format!("/v1/objects/{}:batch", k.project))).header("content-type", "application/json").send(&body[..]) {
                Ok(resp) if resp.status() == 200 => self.verdict(&k, sent_at, true),
                Ok(resp) if resp.status() == 401 => self.verdict(&k, sent_at, false),
                _ => {
                    self.stats.poll_errors.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    /// Keep `vl daemon follow` running while projects are followed (it
    /// holds the device key; this process never does).
    fn tend_follows(&self, child: &mut Option<std::process::Child>, spawned: &mut Option<Instant>) {
        {
            let mut f = self.follows.lock().unwrap_or_else(|e| e.into_inner());
            let t = now();
            f.retain(|_, used| t - *used <= FOLLOW_KEEP_MS);
            if f.is_empty() {
                return;
            }
        }
        if let Some(c) = child {
            if matches!(c.try_wait(), Ok(None)) {
                return;
            }
        }
        if spawned.is_some_and(|s| s.elapsed() < Duration::from_secs(30)) {
            return;
        }
        *spawned = Some(Instant::now());
        *child = super::spawn_self(&["daemon", "follow"], &self.paths).ok();
    }
}

/// Read until `buf` is full or the stream ends; how many bytes were read.
fn read_full(r: &mut impl Read, buf: &mut [u8]) -> Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]).context("reading the server's answer")? {
            0 => break,
            k => n += k,
        }
    }
    Ok(n)
}

fn end(w: &mut BufWriter<UnixStream>, head: &Head) -> Result<()> {
    proto::write_msg(w, proto::E, &serde_json::to_vec(head)?)?;
    w.flush()?;
    Ok(())
}
