//! Rate limits, request bodies and answers under a budget, per-project
//! bulkheads, load shedding and health metrics (milestone S24, part A;
//! `docs/HUB.md` §13.25; design `docs/design/server/phase-4-agent-scale.md`
//! §4.11). All in each server's memory: no database work per request but
//! the session lookup a route would make anyway.
//!
//! [`admit`] runs before every route, in this order:
//!
//! 1. **Who** the request counts against ([`bucket::Key`]): the device of a
//!    session this server knows, or finds (looked up once, as the route
//!    would, the lookup itself under the address's own rate of lookups); of
//!    a read grant whose signature verifies (the object routes); anyone
//!    else by address. A request a regional cache forwards (with the
//!    caches' token) counts against the device of the grant it carries, or
//!    the address of the cache's client, never the cache's.
//! 2. **Rate** ([`bucket`]): a token from the device's or the address's
//!    buckets, else `429 rate_limited` with `retry_after_ms`, naming
//!    nothing.
//! 3. **The body** ([`body`]): read under a share of the memory budget that
//!    grows as it arrives, at a minimum rate.
//! 4. **Bulkheads** ([`gate`]): a place in the project's gate, for callers
//!    this server already knows can see the project, then in the server's,
//!    landings first and search last, else `503 busy` with
//!    `retry_after_ms`.
//! 5. The route, its counts added to its project's [`health`], and its
//!    answer under the answers' budget ([`answers`]).
//!
//! The connection cap, the per-address share of it ([`Connections`]), the
//! idle limit and the answer's time limit are the listener's
//! (`crate::serve`). Landing limits (outstanding landings per agent
//! session, the fair share of a batch) come with the landing service
//! (S17), and per agent session buckets with S11: each agent session at
//! [`Settings::device`]'s rate, under a per-person bucket of ten times it.

pub mod answers;
pub mod body;
pub mod bucket;
pub mod gate;
pub mod health;

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    body::Body,
    extract::{Request, State},
    http::{header, HeaderValue, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::HubState;
use bucket::{Buckets, Key, Rate};
use gate::Class;

/// The limits a server is started with (`veil-server` flags).
#[derive(Clone, Copy, Debug)]
pub struct Settings {
    /// Per signed-in device (and, with S11, per agent session).
    pub device: Rate,
    /// Per address, for requests without a session: anonymous reads of
    /// `public` folders, sign-in.
    pub anonymous: Rate,
    /// Most connections open at once; an address (an IPv4 address, an IPv6
    /// /64) has at most an eighth of them.
    pub max_connections: usize,
    /// Most bytes of request bodies held at once, and as many of answers
    /// being written.
    pub request_memory: u64,
}

impl Default for Settings {
    /// The owner's defaults (S24 cycle 1, BUG-1339): a device runs one
    /// person's agents (about 18 requests a commit, push and pull).
    fn default() -> Settings {
        Settings {
            device: Rate { per_second: 200, per_hour: 50_000 },
            anonymous: Rate { per_second: 20, per_hour: 1000 },
            max_connections: 1024,
            request_memory: 512 << 20,
        }
    }
}

/// The client's address, set on each request by the listener.
#[derive(Clone, Copy, Debug)]
pub struct Peer(pub IpAddr);

/// The header a regional cache's listener sets to its client's address (it
/// replaces any the client sent); the server believes it only beside the
/// caches' token (BUG-1332).
pub const CLIENT_ADDRESS: &str = "veil-client-address";

/// How long an address that sent the caches' token counts as a regional
/// cache's for the per-address connection share.
const TRUSTED_FOR: Duration = Duration::from_secs(300);

/// Connections open per address ([`Key::ip`]: an IPv4 address, an IPv6
/// /64, BUG-1336), for the listener: at most an eighth of the cap from one,
/// except a regional cache's (an address that sent the caches' token in the
/// last 5 minutes), which serves many clients.
pub struct Connections {
    most: usize,
    open: Mutex<HashMap<Key, usize>>,
    trusted: Mutex<HashMap<Key, Instant>>,
}

/// One connection's place in [`Connections`].
pub struct Slot(Arc<Connections>, Key);

impl Connections {
    pub fn new(max_connections: usize) -> Arc<Connections> {
        Arc::new(Connections { most: (max_connections / 8).max(1), open: Default::default(), trusted: Default::default() })
    }

    pub fn open(self: &Arc<Self>, ip: IpAddr) -> Option<Slot> {
        let key = Key::ip(ip);
        let trusted = self.trusted.lock().unwrap().get(&key).is_some_and(|t| t.elapsed() < TRUSTED_FOR);
        let mut m = self.open.lock().unwrap();
        let n = m.entry(key).or_default();
        if *n >= self.most && !trusted {
            return None;
        }
        *n += 1;
        Some(Slot(self.clone(), key))
    }

    fn trust(&self, ip: IpAddr) {
        let mut t = self.trusted.lock().unwrap();
        t.retain(|_, at| at.elapsed() < TRUSTED_FOR);
        t.insert(Key::ip(ip), Instant::now());
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut m = self.0.open.lock().unwrap();
        if let Some(n) = m.get_mut(&self.1) {
            *n -= 1;
            if *n == 0 {
                m.remove(&self.1);
            }
        }
    }
}

/// The limits' state in one server.
pub struct Limits {
    pub settings: Settings,
    devices: Buckets,
    addresses: Buckets,
    /// Session lookups per address (tokens this server does not know yet),
    /// at the device rate: a restarted server's people behind one address
    /// are looked up, made-up tokens are not looked up past it (BUG-1338).
    lookups: Buckets,
    pub bodies: body::Pools,
    pub answers: Arc<answers::Answers>,
    /// Each project's gate, and the server's.
    projects: Arc<gate::Map>,
    server: Arc<gate::Gate>,
    pub connections: Arc<Connections>,
    pub health: health::Health,
}

impl Limits {
    /// With `db_connections` for requests: a project runs at most three
    /// quarters of them at once (one flooded project leaves the others a
    /// quarter), the server at most twice as many requests as it has
    /// connections.
    pub fn new(settings: Settings, db_connections: u32) -> Limits {
        let n = db_connections.max(2) as usize;
        Limits {
            settings,
            devices: Buckets::new(settings.device),
            addresses: Buckets::new(settings.anonymous),
            lookups: Buckets::new(settings.device),
            bodies: body::Pools::new(settings.request_memory),
            answers: answers::Answers::new(settings.request_memory),
            projects: gate::Map::new(n - n / 4),
            server: gate::Gate::new(2 * n),
            connections: Connections::new(settings.max_connections),
            health: health::Health::default(),
        }
    }

    /// Whether the server sheds: requests are waiting for a place in it.
    pub fn overloaded(&self) -> bool {
        self.server.load().1 > 0
    }

    /// What derive work waits for (the second to be shed, design §4.11):
    /// while the server is overloaded, at most [`DERIVE_PAUSE`] a run, so
    /// derivation always progresses and only lags.
    pub async fn derive_turn(&self) {
        let until = tokio::time::Instant::now() + DERIVE_PAUSE;
        while self.overloaded() && tokio::time::Instant::now() < until {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Requests running and waiting in the server's gate, and in a
    /// project's (for tests).
    pub fn load(&self, project: Option<&str>) -> (usize, usize) {
        match project {
            Some(p) => self.projects.load(&gate::Key::Project(p.to_string())),
            None => self.server.load(),
        }
    }
}

/// The longest one derive run waits for the server to stop shedding.
pub const DERIVE_PAUSE: Duration = Duration::from_secs(10);

tokio::task_local! {
    /// The bulkhead places held by the request being served: dropped when
    /// the route answers, or sooner ([`leave_gates`]) before a wait for
    /// something other than the request's own work (BUG-1635).
    static PLACES: std::cell::RefCell<Option<(Option<gate::Place>, gate::Place)>>;
}

/// Give back the bulkhead places of the request being served before it
/// waits for something other than its own work (a landing's outcome, a
/// ticket, BUG-1635; nothing outside a request).
pub fn leave_gates() {
    let _ = PLACES.try_with(|p| {
        p.borrow_mut().take();
    });
}

/// `s` percent-decoded, as the routes' `Path` decodes it; `None` if it does
/// not decode to UTF-8.
fn decoded(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let h = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(h, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// The project a route names, as the route decodes it (BUG-1335; `None`
/// for a name that is not one), and what the route does.
fn route(method: &Method, path: &str) -> (Option<String>, Class) {
    let mut seg = path.split('/').skip(1);
    let (v1, kind, name) = (seg.next(), seg.next(), seg.next().and_then(decoded));
    let batch = kind == Some("objects") && name.as_deref().is_some_and(|n| n.ends_with(":batch"));
    let project = match (v1, kind, name) {
        (Some("v1"), Some("projects"), Some(p)) => Some(p),
        (Some("v1"), Some("objects"), Some(p)) => Some(p.strip_suffix(":batch").map(str::to_string).unwrap_or(p)),
        _ => None,
    }
    .filter(|p| crate::perm::valid_project_name(p));
    let rest = seg.collect::<Vec<_>>();
    let class = match (method, project.is_some(), rest.as_slice()) {
        (_, true, ["q", "search" | "grep"]) => Class::Search,
        (&Method::GET, _, _) => Class::Read,
        (_, true, ["history" | "fetch"] | ["q", ..]) => Class::Read,
        (_, true, []) if batch => Class::Read,
        _ => Class::Write,
    };
    (project, class)
}

/// An answer refusing a request: `status`, `code`, a message naming nothing
/// but the caller's own wait, and when to come back. The connection is
/// closed when the body was not read.
pub(crate) fn refuse(status: StatusCode, code: &str, message: &str, retry: Option<Duration>, close: bool) -> Response {
    let mut v = serde_json::json!({ "code": code, "message": message });
    if let Some(r) = retry {
        v["retry_after_ms"] = (r.as_millis().max(1) as u64).into();
    }
    let mut resp = (status, axum::Json(v)).into_response();
    if let Some(r) = retry {
        let secs = r.as_secs() + u64::from(r.subsec_nanos() > 0);
        resp.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from(secs.max(1)));
    }
    if close {
        resp.headers_mut().insert(header::CONNECTION, HeaderValue::from_static("close"));
    }
    resp
}

fn rate_limited(wait: Duration) -> Response {
    refuse(StatusCode::TOO_MANY_REQUESTS, "rate_limited", "too many requests from this device or address; try again later", Some(wait), false)
}

/// A wait of about a second, jittered, for a request shed under load.
pub(crate) fn shed_wait() -> Duration {
    let j = u64::from(u16::from_le_bytes(veil_core::crypto::random_bytes::<2>())) % 1000;
    Duration::from_millis(500 + j)
}

fn busy(close: bool) -> Response {
    refuse(StatusCode::SERVICE_UNAVAILABLE, "busy", "the server is busy; try again", Some(shed_wait()), close)
}

/// Who a request counts against.
#[derive(Default)]
struct Who {
    /// The device, if any (else the address counts).
    device: Option<Key>,
    /// The person and the person's access epoch, for a session.
    person: Option<(crate::auth::Person, i64)>,
    /// The project a verified read grant is for.
    grant: Option<String>,
}

/// The device a read grant was issued to (if any) and its project, if its
/// signature verifies and it has not expired (the route checks the rest).
fn grant(hub: &HubState, token: &str) -> Option<(Option<Key>, String)> {
    let g = veil_core::hub::grant::Grant::verify(token, hub.grants.key_hex())?;
    if g.body.expires <= veil_core::now_millis() {
        return None;
    }
    Some((g.body.device.as_deref().and_then(Key::device), g.body.project))
}

/// Who `parts` counts against, its rate taken (`address`: the client's).
/// A batch's grant is in its body: [`Who::default`] then, its rate taken
/// once the body is read.
async fn who(hub: &HubState, parts: &mut axum::http::request::Parts, address: Key, deferred: bool, free: bool) -> Result<Who, Duration> {
    let limits = &hub.limits;
    let charge = |device: Option<Key>| -> Result<(), Duration> {
        match (free, device) {
            (true, _) => Ok(()),
            (false, Some(d)) => limits.devices.take(d),
            (false, None) => limits.addresses.take(address),
        }
    };
    if let Some(token) = parts.headers.get(header::AUTHORIZATION).and_then(|a| a.to_str().ok()).and_then(|a| a.strip_prefix("Bearer ")) {
        let now = veil_core::now_millis();
        if let Some(e) = hub.caches.session(&crate::auth::token_hash(token)).filter(|e| e.expires_at > now) {
            if let Some(d) = Key::device(&e.person.device_key) {
                charge(Some(d))?;
                return Ok(Who { device: Some(d), person: Some((e.person.clone(), e.epoch)), grant: None });
            }
        }
        // Not known here yet (another server's, a restart, an evicted entry,
        // or not a session): looked up as the route would (which caches it),
        // under the address's rate of lookups; a session found pays its
        // device, anything else the address (BUG-1338).
        limits.lookups.take(address)?;
        let found = <crate::auth::Caller as axum::extract::FromRequestParts<HubState>>::from_request_parts(parts, hub).await.ok();
        let person = found.and_then(|c| c.person.map(|p| (p, c.epochs.person)));
        let device = person.as_ref().and_then(|(p, _)| Key::device(&p.device_key));
        charge(device)?;
        return Ok(Who { device, person: person.filter(|_| device.is_some()), grant: None });
    }
    if let Some(g) = parts.headers.get("veil-grant").and_then(|g| g.to_str().ok()) {
        if let Some((device, project)) = grant(hub, g) {
            charge(device)?;
            return Ok(Who { device, person: None, grant: Some(project) });
        }
    }
    if deferred {
        return Ok(Who::default());
    }
    charge(None)?;
    Ok(Who::default())
}

/// Whether this server already knows, from memory alone, that the caller
/// may see project `name`: a session whose permissions for it are cached
/// and current, a grant for it, or anyone on Earth for a project with
/// `public` folders. Only those wait in the project's gate (BUG-1334):
/// anyone else's request goes through the server's gate alone, so its wait
/// says nothing about the project.
fn sees(hub: &HubState, name: &str, who: &Who) -> bool {
    if who.grant.as_deref() == Some(name) {
        return true;
    }
    let Some(entry) = hub.caches.project(name) else { return false };
    let project = &entry.project;
    match &who.person {
        Some((person, epoch)) => hub.caches.viewer(project.id, person).is_some_and(|v| {
            !v.barred
                && v.project_epoch == entry.epoch
                && v.person_epoch == *epoch
                && (project.view(&v.viewer).sees_anything() || project.participant(&v.viewer))
        }),
        None => who.device.is_none() && project.view(&crate::perm::Viewer::default()).sees_anything(),
    }
}

/// The middleware (see the module's documentation).
pub async fn admit(State(hub): State<HubState>, req: Request, next: Next) -> Response {
    let limits = &hub.limits;
    let peer = req.extensions().get::<Peer>().map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |p| p.0);
    let (mut parts, body) = req.into_parts();
    let (name, class) = route(&parts.method, parts.uri.path());
    let project = |hub: &HubState| name.as_deref().and_then(|n| hub.caches.project(n)).map(|e| e.project.id);
    let record = |hub: &HubState, c: health::Counts| {
        if let Some(p) = project(hub) {
            hub.limits.health.record(p, &c);
        }
    };
    let counted = |status: StatusCode| health::Counts {
        requests: 1,
        rate_limited: u64::from(status == StatusCode::TOO_MANY_REQUESTS),
        busy: u64::from(status == StatusCode::SERVICE_UNAVAILABLE),
        timeouts: u64::from(status == StatusCode::REQUEST_TIMEOUT),
        ..Default::default()
    };
    let finish = |hub: &HubState, resp: Response| {
        record(hub, counted(resp.status()));
        resp
    };

    // 1–2: who, and their rate. A request with the caches' token is a
    // regional cache's: its client's address counts, not the cache's, and
    // the cache's own feed counts against nobody.
    let from_cache = parts.headers.get(crate::cache::feed::TOKEN_HEADER).and_then(|v| v.to_str().ok()).map(|t| blake3::hash(t.trim().as_bytes()))
        == Some(hub.cache_token);
    let client = match from_cache {
        true => {
            limits.connections.trust(peer);
            parts.headers.get(CLIENT_ADDRESS).and_then(|v| v.to_str().ok()).and_then(|v| v.parse().ok()).unwrap_or(peer)
        }
        false => peer,
    };
    let address = Key::ip(client);
    let feed = from_cache && parts.uri.path() == "/v1/cache/epochs";
    let batch = parts.method == Method::POST && parts.uri.path().starts_with("/v1/objects/") && parts.uri.path().ends_with(":batch");
    let mut who = match who(&hub, &mut parts, address, batch, feed).await {
        Ok(w) => w,
        Err(wait) => return finish(&hub, rate_limited(wait)),
    };
    let deferred = batch && who.device.is_none() && who.person.is_none() && who.grant.is_none();

    // 3: the body, under the budget.
    let declared = hyper::body::Body::size_hint(&body).exact();
    let limit = crate::db::body_limit(parts.uri.path()) as u64;
    let body_key = who.device.unwrap_or(address);
    let mut body = body;
    let (bytes, _share) = match limits.bodies.read(body_key, who.device.is_some(), &mut body, declared, limit).await {
        Ok(b) => b,
        Err(r) => {
            // What is left of a body refused for its size or a share is read
            // and dropped (nothing held, at the minimum rate), so the client
            // reads the refusal; a late or broken body is not.
            if matches!(r, body::Refused::TooLarge | body::Refused::Busy) {
                body::drain(&mut body, limit).await;
            }
            let resp = match r {
                body::Refused::TooLarge => refuse(StatusCode::PAYLOAD_TOO_LARGE, "too_large", "request body too large", None, true),
                body::Refused::Late => refuse(StatusCode::REQUEST_TIMEOUT, "timeout", "the request's body did not arrive in time", None, true),
                body::Refused::Unreadable => refuse(StatusCode::BAD_REQUEST, "bad_request", "the request's body could not be read", None, true),
                body::Refused::Busy => busy(true),
            };
            return finish(&hub, resp);
        }
    };
    if deferred && !feed {
        #[derive(serde::Deserialize)]
        struct Batch {
            grant: String,
        }
        let found = serde_json::from_slice::<Batch>(&bytes).ok().and_then(|b| grant(&hub, &b.grant));
        let taken = match &found {
            Some((Some(d), _)) => limits.devices.take(*d),
            _ => limits.addresses.take(address),
        };
        if let Err(wait) = taken {
            return finish(&hub, rate_limited(wait));
        }
        if let Some((device, project)) = found {
            who.device = device;
            who.grant = Some(project);
        }
    }

    // 4: the bulkheads: the project's for those known to see it, then the
    // server's.
    let deadline = tokio::time::Instant::now() + class.wait();
    let gate_key = match &name {
        Some(n) if sees(&hub, n, &who) => Some(gate::Key::Project(n.clone())),
        Some(_) => None,
        None => Some(gate::Key::Server),
    };
    let project_place = match gate_key {
        Some(k) => match limits.projects.place(k, class, deadline).await {
            Some(p) => Some(p),
            None => return finish(&hub, busy(false)),
        },
        None => None,
    };
    let Some(server_place) = limits.server.place(class, deadline).await else {
        return finish(&hub, busy(false));
    };

    // 5: the route, its cache hits counted for its project, its answer
    // under the answers' budget.
    let mut req = Request::from_parts(parts, Body::from(bytes));
    req.extensions_mut().insert(answers::For(body_key));
    let (resp, layers) = PLACES
        .scope(
            std::cell::RefCell::new(Some((project_place, server_place))),
            health::LAYERS.scope(std::cell::Cell::new(health::Counts::default()), async {
                let r = next.run(req).await;
                (r, health::LAYERS.with(|c| c.get()))
            }),
        )
        .await;
    let resp = match limits.answers.budget(body_key, resp, class != Class::Write).await {
        Some(r) => r,
        None => busy(false),
    };
    let mut c = counted(resp.status());
    c.tips_hits = layers.tips_hits;
    c.tips_misses = layers.tips_misses;
    c.permission_hits = layers.permission_hits;
    c.permission_misses = layers.permission_misses;
    record(&hub, c);
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_are_classed_for_shedding() {
        let g = Method::GET;
        let p = Method::POST;
        let r = |m: &Method, path: &str| {
            let (n, c) = route(m, path);
            (n.as_deref().map(str::to_string), c)
        };
        let a = Some("a".to_string());
        assert_eq!(r(&g, "/v1/projects/a/q/search"), (a.clone(), Class::Search));
        assert_eq!(r(&g, "/v1/projects/a/q/grep"), (a.clone(), Class::Search));
        assert_eq!(r(&g, "/v1/projects/a/q/log"), (a.clone(), Class::Read));
        assert_eq!(r(&p, "/v1/projects/a/q/ancestry"), (a.clone(), Class::Read));
        assert_eq!(r(&g, "/v1/projects/a/tips"), (a.clone(), Class::Read));
        assert_eq!(r(&p, "/v1/projects/a/history"), (a.clone(), Class::Read));
        assert_eq!(r(&p, "/v1/projects/a/fetch"), (a.clone(), Class::Read));
        assert_eq!(r(&p, "/v1/objects/a:batch"), (a.clone(), Class::Read));
        assert_eq!(r(&g, "/v1/objects/a/00ff"), (a.clone(), Class::Read));
        assert_eq!(r(&p, "/v1/projects/a/push"), (a.clone(), Class::Write));
        assert_eq!(r(&p, "/v1/projects/a/changes"), (a.clone(), Class::Write));
        assert_eq!(r(&p, "/v1/projects/a/objects"), (a.clone(), Class::Write));
        assert_eq!(r(&p, "/v1/projects/a"), (a.clone(), Class::Write));
        assert_eq!(r(&p, "/v1/auth/login"), (None, Class::Write));
        assert_eq!(r(&g, "/v1/epochs"), (None, Class::Read));
    }

    /// BUG-1335: a project's name is keyed as the route decodes it, in any
    /// spelling; one that does not decode, or is not a name, has no gate.
    #[test]
    fn project_names_are_keyed_as_the_route_decodes_them() {
        let g = Method::GET;
        for path in ["/v1/projects/lim1/groups", "/v1/projects/%6Cim1/groups", "/v1/projects/%6c%69%6D1/groups"] {
            assert_eq!(route(&g, path).0.as_deref(), Some("lim1"), "{path}");
        }
        assert_eq!(route(&Method::POST, "/v1/objects/%6Cim1%3Abatch").0.as_deref(), Some("lim1"));
        assert_eq!(route(&Method::POST, "/v1/objects/%6Cim1%3Abatch").1, Class::Read);
        for bad in ["/v1/projects/%zz/tips", "/v1/projects/%ff/tips", "/v1/projects/A%20B/tips", "/v1/projects/%/tips"] {
            assert_eq!(route(&g, bad).0, None, "{bad}");
        }
    }

    /// BUG-1336: an IPv6 /64 is one address for the connection share, as
    /// for the rates; a regional cache's address has no share.
    #[test]
    fn the_connection_share_groups_addresses_as_the_rates_do() {
        let c = Connections::new(16);
        let a: IpAddr = "2001:db8::1".parse().unwrap();
        let b: IpAddr = "2001:db8::2".parse().unwrap();
        let other: IpAddr = "2001:db8:0:1::1".parse().unwrap();
        let held = [c.open(a).unwrap(), c.open(a).unwrap()];
        assert!(c.open(b).is_none(), "the same /64");
        assert!(c.open(other).is_some());
        c.trust(b);
        assert!(c.open(a).is_some(), "a cache's /64 has no share");
        drop(held);
    }

    /// A refusal names nothing but the wait, in the body and the header.
    #[tokio::test]
    async fn refusals_say_when_to_come_back_and_nothing_else() {
        let r = rate_limited(Duration::from_millis(1500));
        assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(r.headers()[header::RETRY_AFTER], "2");
        let b = axum::body::to_bytes(r.into_body(), 1 << 16).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(v["code"], "rate_limited");
        assert_eq!(v["retry_after_ms"], 1500);
        assert_eq!(v.as_object().unwrap().len(), 3, "{v}");
    }

    /// Derive work is shed second: it waits while requests wait for a place
    /// in the server, but at most [`DERIVE_PAUSE`] a run, so it only lags.
    #[tokio::test(start_paused = true)]
    async fn derive_work_waits_while_the_server_sheds_but_not_for_ever() {
        let l = Arc::new(Limits::new(Settings::default(), 2));
        let t = tokio::time::Instant::now();
        l.derive_turn().await;
        assert!(t.elapsed() < Duration::from_millis(1), "nothing to wait for");
        let far = tokio::time::Instant::now() + Duration::from_secs(600);
        let mut places = Vec::new();
        for _ in 0..4 {
            places.push(l.server.place(Class::Read, far).await.unwrap());
        }
        let l2 = l.clone();
        let waiting = tokio::spawn(async move { l2.server.place(Class::Write, far).await.is_some() });
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(l.overloaded());
        let t = tokio::time::Instant::now();
        l.derive_turn().await;
        let waited = t.elapsed();
        assert!(waited >= DERIVE_PAUSE && waited < DERIVE_PAUSE + Duration::from_millis(100), "{waited:?}");
        drop(places);
        assert!(waiting.await.unwrap());
        assert!(!l.overloaded());
    }
}
