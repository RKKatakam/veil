//! Rate limits, request bodies under a budget, per-project bulkheads, load
//! shedding and health metrics (milestone S24, part A; `docs/HUB.md`
//! §13.25; design `docs/design/server/phase-4-agent-scale.md` §4.11). All in
//! each server's memory: no database work per request.
//!
//! [`admit`] runs before every route, in this order:
//!
//! 1. **Who** the request counts against ([`bucket::Key`]): the device of a
//!    session this server knows, or of a read grant whose signature
//!    verifies (the object routes); anyone else by address. A session not
//!    known here yet is looked up once, as the route itself would.
//! 2. **Rate** ([`bucket`]): a token from the device's or the address's
//!    buckets, else `429 rate_limited` with `retry_after_ms`, naming
//!    nothing.
//! 3. **The body** ([`body`]): read under a share of the memory budget, at
//!    a minimum rate.
//! 4. **Bulkheads** ([`gate`]): a place in the project's gate, then in the
//!    server's, landings first and search last, else `503 busy` with
//!    `retry_after_ms`.
//! 5. The route, its counts added to its project's [`health`].
//!
//! The connection cap and the answer's time limit are the listener's
//! (`crate::serve`). Landing limits (outstanding landings per agent
//! session, the fair share of a batch) come with the landing service
//! (S17): it gets its own [`gate::Class`] and buckets keyed by session.

pub mod body;
pub mod bucket;
pub mod gate;
pub mod health;

use std::{
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
    time::Duration,
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
    /// Per signed-in device (and later agent session).
    pub device: Rate,
    /// Per address, for requests without a session this server knows:
    /// anonymous reads of `public` folders, sign-in.
    pub anonymous: Rate,
    /// Most connections open at once; an address has at most an eighth of
    /// them. The next waits in the listener's queue.
    pub max_connections: usize,
    /// Most bytes of request bodies held at once (an eighth of it for
    /// requests without a session).
    pub request_memory: u64,
}

impl Default for Settings {
    /// The design's defaults (`docs/HUB.md` §4.7).
    fn default() -> Settings {
        Settings {
            device: Rate { per_second: 60, per_hour: 5000 },
            anonymous: Rate { per_second: 20, per_hour: 1000 },
            max_connections: 1024,
            request_memory: 512 << 20,
        }
    }
}

/// The client's address, set on each request by the listener.
#[derive(Clone, Copy, Debug)]
pub struct Peer(pub IpAddr);

/// The limits' state in one server.
pub struct Limits {
    pub settings: Settings,
    devices: Buckets,
    addresses: Buckets,
    pub bodies: body::Pools,
    /// Each project's gate, and the server's.
    projects: Arc<gate::Map>,
    server: Arc<gate::Gate>,
    pub health: health::Health,
}

impl Limits {
    /// With `db_connections` for requests: a project runs at most half of
    /// them at once (so another always finds a connection), the server at
    /// most twice as many requests as it has connections.
    pub fn new(settings: Settings, db_connections: u32) -> Limits {
        let n = db_connections.max(2) as usize;
        Limits {
            settings,
            devices: Buckets::new(settings.device),
            addresses: Buckets::new(settings.anonymous),
            bodies: body::Pools::new(settings.request_memory),
            projects: gate::Map::new(n / 2),
            server: gate::Gate::new(2 * n),
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
    pub fn load(&self, project: Option<i64>) -> (usize, usize) {
        match project {
            Some(p) => self.projects.load(&gate::Key::Project(p)),
            None => self.server.load(),
        }
    }
}

/// The longest one derive run waits for the server to stop shedding.
pub const DERIVE_PAUSE: Duration = Duration::from_secs(10);

/// The project a route names, and what it does.
fn route<'a>(method: &Method, path: &'a str) -> (Option<&'a str>, Class) {
    let mut seg = path.split('/').skip(1);
    let (v1, kind, name) = (seg.next(), seg.next(), seg.next());
    let project = match (v1, kind, name) {
        (Some("v1"), Some("projects"), Some(p)) => Some(p),
        (Some("v1"), Some("objects"), Some(p)) => Some(p.strip_suffix(":batch").unwrap_or(p)),
        _ => None,
    };
    let rest = seg.collect::<Vec<_>>();
    let class = match (method, project, rest.as_slice()) {
        (_, Some(_), ["q", "search" | "grep"]) => Class::Search,
        (&Method::GET, _, _) => Class::Read,
        (_, Some(_), ["history" | "fetch"] | ["q", ..]) => Class::Read,
        (_, Some(p), []) if kind == Some("objects") && name.is_some_and(|n| n.ends_with(":batch")) && !p.is_empty() => Class::Read,
        _ => Class::Write,
    };
    (project, class)
}

/// An answer refusing a request: `status`, `code`, a message naming nothing
/// but the caller's own wait, and when to come back. The connection is
/// closed when the body was not read.
fn refuse(status: StatusCode, code: &str, message: &str, retry: Option<Duration>, close: bool) -> Response {
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
fn shed_wait() -> Duration {
    let j = u64::from(u16::from_le_bytes(veil_core::crypto::random_bytes::<2>())) % 1000;
    Duration::from_millis(500 + j)
}

fn busy(close: bool) -> Response {
    refuse(StatusCode::SERVICE_UNAVAILABLE, "busy", "the server is busy; try again", Some(shed_wait()), close)
}

/// Who a request counts against, and whether its token is taken already.
enum Who {
    /// A device: its session is known here, or its grant verifies.
    Device(Key),
    /// An address.
    Address(Key),
    /// An address whose token was taken before a session not known here
    /// yet was looked up: a made-up token costs its address, never a
    /// database read past the address's rate.
    Charged(bool),
}

async fn who(hub: &HubState, parts: &mut axum::http::request::Parts, ip: IpAddr) -> Result<Who, Duration> {
    let address = Key::ip(ip);
    if let Some(token) = parts.headers.get(header::AUTHORIZATION).and_then(|a| a.to_str().ok()).and_then(|a| a.strip_prefix("Bearer ")) {
        let now = veil_core::now_millis();
        let known = hub.caches.session(&crate::auth::token_hash(token)).filter(|e| e.expires_at > now).map(|e| e.person.device_key.clone());
        if let Some(k) = known.as_deref().and_then(Key::device) {
            return Ok(Who::Device(k));
        }
        // Not known here yet (a restart, an evicted entry, or not a session):
        // the address pays, then the lookup the route would make, which
        // caches it for both.
        hub.limits.addresses.take(address)?;
        let found = match <crate::auth::Caller as axum::extract::FromRequestParts<HubState>>::from_request_parts(parts, hub).await {
            Ok(c) => c.person.and_then(|p| Key::device(&p.device_key)),
            Err(_) => None,
        };
        return Ok(Who::Charged(found.is_some()));
    }
    if let Some(g) = parts.headers.get("veil-grant").and_then(|g| g.to_str().ok()) {
        if let Some(k) = grant_device(hub, g) {
            return Ok(Who::Device(k));
        }
    }
    Ok(Who::Address(address))
}

/// The device a read grant was issued to, if its signature verifies and
/// it has not expired (the route checks the rest).
fn grant_device(hub: &HubState, token: &str) -> Option<Key> {
    let g = veil_core::hub::grant::Grant::verify(token, hub.grants.key_hex())?;
    if g.body.expires <= veil_core::now_millis() {
        return None;
    }
    Key::device(g.body.device.as_deref()?)
}

/// The middleware (see the module's documentation).
pub async fn admit(State(hub): State<HubState>, req: Request, next: Next) -> Response {
    let limits = &hub.limits;
    let ip = req.extensions().get::<Peer>().map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |p| p.0);
    let (mut parts, body) = req.into_parts();
    let (name, class) = route(&parts.method, parts.uri.path());
    let name = name.map(str::to_string);
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

    // 1–2: who, and their rate. The regional caches' feed (one request a
    // second per cache, by the caches' token) counts against nobody.
    let cache_feed = parts.headers.get(crate::cache::feed::TOKEN_HEADER).and_then(|v| v.to_str().ok()).map(|t| blake3::hash(t.trim().as_bytes()))
        == Some(hub.cache_token);
    let batch = parts.method == Method::POST && parts.uri.path().starts_with("/v1/objects/") && parts.uri.path().ends_with(":batch");
    let who = match who(&hub, &mut parts, ip).await {
        Ok(w) => w,
        Err(wait) => return finish(&hub, rate_limited(wait)),
    };
    let signed = matches!(who, Who::Device(_) | Who::Charged(true));
    // A batch's grant is in its body: its rate is checked once it is read.
    let deferred = batch && matches!(who, Who::Address(_));
    let taken = match (&who, cache_feed || deferred) {
        (_, true) | (Who::Charged(_), _) => Ok(()),
        (Who::Device(k), _) => limits.devices.take(*k),
        (Who::Address(k), _) => limits.addresses.take(*k),
    };
    if let Err(wait) = taken {
        return finish(&hub, rate_limited(wait));
    }

    // 3: the body, under the budget.
    // The body's length as its head declared it (0 for none).
    let declared = hyper::body::Body::size_hint(&body).exact();
    let limit = crate::db::body_limit(parts.uri.path()) as u64;
    let body_key = match &who {
        Who::Device(k) => *k,
        _ => Key::ip(ip),
    };
    let (bytes, _share) = match limits.bodies.read(body_key, signed, body, declared, limit).await {
        Ok(b) => b,
        Err(r) => {
            let resp = match r {
                body::Refused::TooLarge => refuse(StatusCode::PAYLOAD_TOO_LARGE, "too_large", "request body too large", None, true),
                body::Refused::Late => refuse(StatusCode::REQUEST_TIMEOUT, "timeout", "the request's body did not arrive in time", None, true),
                body::Refused::Unreadable => refuse(StatusCode::BAD_REQUEST, "bad_request", "the request's body could not be read", None, true),
                body::Refused::Busy => busy(true),
            };
            return finish(&hub, resp);
        }
    };
    if deferred && !cache_feed {
        #[derive(serde::Deserialize)]
        struct Grant {
            grant: String,
        }
        let taken = match serde_json::from_slice::<Grant>(&bytes).ok().and_then(|g| grant_device(&hub, &g.grant)) {
            Some(k) => limits.devices.take(k),
            None => limits.addresses.take(Key::ip(ip)),
        };
        if let Err(wait) = taken {
            return finish(&hub, rate_limited(wait));
        }
    }

    // 4: the bulkheads.
    let gate_key = match (&name, project(&hub)) {
        (_, Some(id)) => gate::Key::Project(id),
        (Some(_), None) => gate::Key::Unresolved,
        (None, None) => gate::Key::Server,
    };
    let deadline = tokio::time::Instant::now() + class.wait();
    let Some(_project_place) = limits.projects.place(gate_key, class, deadline).await else {
        return finish(&hub, busy(false));
    };
    let Some(_server_place) = limits.server.place(class, deadline).await else {
        return finish(&hub, busy(false));
    };

    // 5: the route, its cache hits counted for its project.
    let req = Request::from_parts(parts, Body::from(bytes));
    let (resp, layers) = health::LAYERS
        .scope(std::cell::Cell::new(health::Counts::default()), async {
            let r = next.run(req).await;
            (r, health::LAYERS.with(|c| c.get()))
        })
        .await;
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
        assert_eq!(route(&g, "/v1/projects/a/q/search"), (Some("a"), Class::Search));
        assert_eq!(route(&g, "/v1/projects/a/q/grep"), (Some("a"), Class::Search));
        assert_eq!(route(&g, "/v1/projects/a/q/log"), (Some("a"), Class::Read));
        assert_eq!(route(&p, "/v1/projects/a/q/ancestry"), (Some("a"), Class::Read));
        assert_eq!(route(&g, "/v1/projects/a/tips"), (Some("a"), Class::Read));
        assert_eq!(route(&p, "/v1/projects/a/history"), (Some("a"), Class::Read));
        assert_eq!(route(&p, "/v1/projects/a/fetch"), (Some("a"), Class::Read));
        assert_eq!(route(&p, "/v1/objects/a:batch"), (Some("a"), Class::Read));
        assert_eq!(route(&g, "/v1/objects/a/00ff"), (Some("a"), Class::Read));
        assert_eq!(route(&p, "/v1/projects/a/push"), (Some("a"), Class::Write));
        assert_eq!(route(&p, "/v1/projects/a/changes"), (Some("a"), Class::Write));
        assert_eq!(route(&p, "/v1/projects/a/objects"), (Some("a"), Class::Write));
        assert_eq!(route(&p, "/v1/projects/a"), (Some("a"), Class::Write));
        assert_eq!(route(&p, "/v1/auth/login"), (None, Class::Write));
        assert_eq!(route(&g, "/v1/epochs"), (None, Class::Read));
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
