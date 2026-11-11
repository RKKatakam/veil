//! Signing in (`docs/HUB.md` §4.3): challenge-response with the device's
//! Ed25519 identity key, then a session token.
//!
//! * A challenge is 32 random bytes, valid for [`CHALLENGE_TTL_MS`], and
//!   **single use**: login deletes it in the same statement that checks it,
//!   so a replayed login finds nothing.
//! * The device signs `hub ‖ 0 ‖ challenge` under the `hub-login` context.
//!   `hub` is the server's name as the client dialled it. It must be a name
//!   this server's TLS certificate is valid for (the client checked that
//!   before signing), and equal the request's `Host`: a signature made for
//!   another server (one relaying our challenges) is refused. The `Host`
//!   header alone proves nothing, as the relaying server writes it.
//! * The token is 32 random bytes; the database keeps only its BLAKE3
//!   hash, with an expiry and the device. A removed device's sessions stop
//!   at once.
//! * An unknown key may register as a new person, under a name nobody has.
//!   Under a name somebody has, it becomes one of their **pending**
//!   devices: no session until one of their devices vouches for it
//!   (`docs/HUB.md` §13.11). A pending device lasts [`PENDING_TTL_MS`]
//!   (signing in again renews it) and is looked up by its fingerprint, so
//!   pending devices someone else makes under the name never hide it
//!   (§13.12). A person has at most [`PENDING_PER_PERSON`] pending devices:
//!   a new one pushes out the oldest, except one whose fingerprint the
//!   person's `vl identity confirm` looked for (`device_expected`, for
//!   [`EXPECTED_TTL_MS`]), which nobody else can push out.

use axum::{
    extract::{FromRequestParts, State},
    http::{request::Parts, HeaderMap},
    Json,
};
use veil_core::{
    crypto::domains::SIG_CONTEXT_HUB_LOGIN,
    hub::wire::{login_message, Challenge, ChallengeRequest, LoginRequest, Session},
    identity::verify_signature,
};

use std::sync::{atomic::Ordering, Arc};

use veil_core::{
    hub::agent::{normalize_only, AgentSession, AgentSessionRequest, MAX_AGENT_SESSION_MS},
    object::Attribution,
};

use crate::{
    caches::Epochs,
    error::{Error, Result},
    HubState,
};

pub const CHALLENGE_TTL_MS: i64 = 60_000;
/// How long a pending device waits to be confirmed.
pub const PENDING_TTL_MS: i64 = 24 * 3600 * 1000;
/// The most pending devices a person has: anyone can make them under the
/// name, so the table stays bounded.
pub const PENDING_PER_PERSON: i64 = 32;
/// How long a fingerprint the person looked for is kept for them: its
/// device, signing in again, is never pushed out by the bound.
pub const EXPECTED_TTL_MS: i64 = 3600 * 1000;
/// The most fingerprints a person waits for at once.
pub const EXPECTED_PER_PERSON: i64 = 8;
/// Pending devices listed in `Devices::pending` (the newest; for display).
/// Confirming one looks it up by fingerprint instead.
pub const LISTED_PENDING: i64 = 8;

/// The code of the answer to a pending device's login.
pub const DEVICE_PENDING: &str = "device_pending";

fn pending(name: &str) -> Error {
    Error::new(
        axum::http::StatusCode::CONFLICT,
        DEVICE_PENDING,
        format!(
            "the name '{name}' is taken. If it is yours, this device waits for one of your devices to confirm it \
             (`vl identity confirm`); otherwise choose another name"
        ),
    )
}

/// The signed-in person, if any.
#[derive(Clone, Debug)]
pub struct Caller {
    pub person: Option<Person>,
    /// The access epochs this request read: cached permissions are used
    /// only if they were built under exactly these (`caches`).
    pub epochs: Epochs,
}

#[derive(Clone, Debug)]
pub struct Person {
    pub id: i64,
    pub name: String,
    /// The signed-in device's Ed25519 key (hex).
    pub device_key: String,
    /// Set when the session is an agent session (`docs/HUB.md` §13.27):
    /// every request is checked as the person's, then narrowed.
    pub agent: Option<Arc<AgentGrant>>,
}

/// What an agent session is: made from its person's own session, for one
/// project, maybe narrowed, with the attribution its commits through the
/// API carry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentGrant {
    pub session_hash: String,
    pub project: i64,
    /// The session's stored hash (`session_hash`), for its rate-limit bucket
    /// and its landing queue share and bound (S24 part B).
    pub session: String,
    /// `--only`: the paths its files are narrowed to (`None`: all its
    /// person sees).
    pub only: Option<Arc<Vec<String>>>,
    pub attribution: Attribution,
    /// A CI runner session: reads what its grant allows and writes only
    /// check results.
    pub runner: bool,
}

/// The code of the refusal of what an agent session may not do.
pub const AGENT_SESSION: &str = "agent_session";
/// The code of the refusal of what a browser/web session may not do.
pub const WEB_SESSION: &str = "web_session";
/// The code of a failed CSRF or same-origin check on a browser request.
pub const CSRF_FAILED: &str = "csrf_failed";
/// The `__Host-` session cookie set by the web client (`HttpOnly; Secure; SameSite=Strict; Path=/`).
pub const SESSION_COOKIE: &str = "__Host-veil_session";

fn valid_key(key: &str) -> bool {
    key.len() == 64 && key.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn token_hash(token: &str) -> String {
    blake3::hash(token.as_bytes()).to_hex().to_string()
}

/// What an agent session's token starts with.
pub const AGENT_TOKEN_PREFIX: &str = "agent-";

/// The hash a session is kept under: a person's under [`token_hash`], an
/// agent session's (its token starts with [`AGENT_TOKEN_PREFIX`]) under a
/// derived key of its own, and a web session's (`web-`) under
/// `HUB_WEB_SESSION`, which a server that predates that milestone never
/// computes, so it never finds one (BUG-1376).
pub fn session_hash(token: &str) -> String {
    if token.starts_with(AGENT_TOKEN_PREFIX) {
        blake3::Hasher::new_derive_key(veil_core::crypto::domains::HUB_AGENT_SESSION)
            .update(token.as_bytes())
            .finalize()
            .to_hex()
            .to_string()
    } else if token.starts_with(veil_core::hub::web::WEB_TOKEN_PREFIX) {
        veil_core::hub::web::web_token_hash(token)
    } else {
        token_hash(token)
    }
}

/// Extract `__Host-veil_session` from `Cookie` request headers, if present and non-empty.
pub fn cookie_token(headers: &HeaderMap) -> Option<&str> {
    let prefix = format!("{SESSION_COOKIE}=");
    for val in headers.get_all(axum::http::header::COOKIE) {
        let Ok(s) = val.to_str() else { continue };
        for part in s.split(';') {
            if let Some(tok) = part.trim().strip_prefix(&prefix) {
                if !tok.is_empty() {
                    return Some(tok);
                }
            }
        }
    }
    None
}

/// True when `headers` carry browser fetch metadata, `Origin`, `Cookie`, or `X-Veil-Web`.
pub fn has_browser_headers(headers: &HeaderMap) -> bool {
    headers.contains_key("sec-fetch-dest")
        || headers.contains_key("sec-fetch-mode")
        || headers.contains_key("sec-fetch-site")
        || headers.contains_key(axum::http::header::ORIGIN)
        || headers.contains_key(axum::http::header::COOKIE)
        || headers.contains_key("x-veil-web")
}

/// True when `headers` carry browser headers or a `Bearer web-...` session token.
pub fn has_browser_or_web_headers(headers: &HeaderMap) -> bool {
    has_browser_headers(headers)
        || headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|a| a.strip_prefix("Bearer "))
            .is_some_and(|t| t.starts_with(veil_core::hub::web::WEB_TOKEN_PREFIX))
}

pub async fn challenge(State(hub): State<HubState>, Json(req): Json<ChallengeRequest>) -> Result<Json<Challenge>> {
    if !valid_key(&req.key) {
        return Err(Error::bad_request("key must be an Ed25519 public key in lowercase hex"));
    }
    let now = veil_core::now_millis();
    let challenge = hex::encode(veil_core::crypto::random_bytes::<32>());
    sqlx::query("DELETE FROM challenges WHERE expires_at < $1").bind(now).execute(&hub.db).await?;
    sqlx::query("INSERT INTO challenges (challenge, signing_key, expires_at) VALUES ($1, $2, $3)")
        .bind(&challenge)
        .bind(&req.key)
        .bind(now + CHALLENGE_TTL_MS)
        .execute(&hub.db)
        .await?;
    Ok(Json(Challenge {
        challenge,
        expires_at: now + CHALLENGE_TTL_MS,
    }))
}

/// `host[:port]` without the default port, for comparing names.
fn normal_host(h: &str) -> String {
    h.trim().trim_end_matches(":443").to_ascii_lowercase()
}

pub async fn login(State(hub): State<HubState>, headers: HeaderMap, Json(req): Json<LoginRequest>) -> Result<Json<Session>> {
    let token = hex::encode(veil_core::crypto::random_bytes::<32>());
    let session = token_hash(&token);
    let (person_name, expires_at) = finish_login(&hub, &headers, req, session, hub.session_ttl_ms, "login").await?;
    Ok(Json(Session {
        token,
        person: person_name,
        expires_at,
        hub_key: hub.identity.verifying_hex(),
    }))
}

async fn finish_login(
    hub: &HubState,
    headers: &HeaderMap,
    req: LoginRequest,
    session: String,
    ttl_ms: i64,
    audit_action: &str,
) -> Result<(String, i64)> {
    if !valid_key(&req.key) {
        return Err(Error::bad_request("key must be an Ed25519 public key in lowercase hex"));
    }
    let host = headers.get("host").and_then(|h| h.to_str().ok()).unwrap_or_default();
    if normal_host(host) != normal_host(&req.hub) || !crate::tls::names(&hub.certificate, &req.hub) {
        return Err(Error::unauthorized("the signature names another server"));
    }
    let now = veil_core::now_millis();
    // Single use: the challenge is gone whatever happens next.
    let found: Option<String> =
        sqlx::query_scalar("DELETE FROM challenges WHERE challenge = $1 AND signing_key = $2 AND expires_at > $3 RETURNING challenge")
            .bind(&req.challenge)
            .bind(&req.key)
            .bind(now)
            .fetch_optional(&hub.db)
            .await?;
    if found.is_none() {
        return Err(Error::unauthorized("unknown, used or expired challenge"));
    }
    if !verify_signature(&req.key, SIG_CONTEXT_HUB_LOGIN, &login_message(&req.hub, &req.challenge), &req.signature) {
        return Err(Error::unauthorized("bad signature"));
    }
    // The full identity must be this key's, with a valid binding.
    let ident = veil_core::identity::parse_public_identity(&req.identity).map_err(|_| Error::bad_request("invalid public identity"))?;
    if ident.signing_hex().as_deref() != Some(req.key.as_str()) || ident.is_unbound() {
        return Err(Error::bad_request("the public identity does not belong to this key, or has no binding"));
    }
    let public_identity = req.identity.clone();
    let fingerprint = veil_core::hub::wire::device_fingerprint(&ident).unwrap_or_default();
    let key = req.key.clone();
    let name = req.name.clone();
    let expires_at = now + ttl_ms;
    // The session is written in the same transaction as the device: a
    // request that committed is never run again (`db::retry_requests`),
    // and its challenge is spent.
    //
    // READ COMMITTED, not SERIALIZABLE (BUG-847): a new sign-up looks up a
    // device by `signing_key` and a person by `name` and finds neither, and
    // on YugabyteDB a SERIALIZABLE read that finds no row through a unique
    // secondary index locks its whole table; every concurrent sign-up then
    // inserted into a table another one held, and they deadlocked. The only
    // races sign-in has are decided by those unique keys anyway: two
    // sign-ups of one name, or one key signing in twice. The loser's insert
    // fails on the key (`23505`), and the transaction runs again: it then
    // finds the person (a pending device) or the device.
    let mut attempt = 0;
    let outcome = loop {
        attempt += 1;
        let (key, name, public_identity, fingerprint, session) =
            (key.clone(), name.clone(), public_identity.clone(), fingerprint.clone(), session.clone());
        let r = crate::db::transaction(&hub.db, crate::db::Isolation::ReadCommitted, move |c| {
            let key = key.clone();
            let name = name.clone();
            let public_identity = public_identity.clone();
            let fingerprint = fingerprint.clone();
            let session = session.clone();
            Box::pin(async move {
                let found = signed_in(&mut *c, &key, name, &public_identity, &fingerprint).await?;
                if let Ok((device, person, _)) = &found {
                    sqlx::query("INSERT INTO sessions (token_hash, device_id, person_id, expires_at) VALUES ($1, $2, $3, $4)")
                        .bind(&session)
                        .bind(device)
                        .bind(person)
                        .bind(expires_at)
                        .execute(&mut *c)
                        .await?;
                }
                Ok(found)
            })
        })
        .await;
        match r {
            Err(Error::Db(sqlx::Error::Database(d))) if d.code().as_deref() == Some("23505") && attempt < 5 => continue,
            r => break r?,
        }
    };
    if let Err(name) = &outcome {
        prune_pending(&hub.db, name).await;
    }
    let (device, person, person_name) = outcome.map_err(|name| pending(&name))?;
    crate::audit(&hub.db, None, Some(person), audit_action, &format!("device {device}")).await;
    Ok((person_name, expires_at))
}

/// The device signing in with `key` (registering `name` for a new person,
/// or a pending device of an existing one): `Ok((device, person, name))`,
/// or `Err(name)` for a device still waiting to be confirmed.
async fn signed_in(
    c: &mut sqlx::PgConnection,
    key: &str,
    name: Option<String>,
    public_identity: &str,
    fingerprint: &str,
) -> Result<Result<(i64, i64, String), String>> {
    let row: Option<(i64, i64, String, bool, bool)> = sqlx::query_as(
        "SELECT d.id, p.id, p.name, d.pending, d.browser FROM devices d JOIN people p ON p.id = d.person_id \
         WHERE d.signing_key = $1 AND d.removed_at IS NULL",
    )
    .bind(key)
    .fetch_optional(&mut *c)
    .await?;
    if let Some((device, person, name, pending, browser)) = row {
        if browser {
            return Err(Error::unauthorized("browser devices sign in with a passkey in the web client"));
        }
        if pending {
            // Signing in again renews the wait.
            sqlx::query("UPDATE devices SET created_at = $1 WHERE id = $2").bind(veil_core::now_millis()).bind(device).execute(&mut *c).await?;
            return Ok(Err(name));
        }
        return Ok(Ok((device, person, name)));
    }
    let Some(name) = name else {
        return Err(Error::unauthorized("this device is not registered; sign up with a name (`vl login URL --name NAME`)"));
    };
    if !veil_core::policy::valid_principal_name(&name) {
        return Err(Error::bad_request(
            "a name is 1 to 64 lowercase letters, digits, '-', '_' or '.', and not a tier word",
        ));
    }
    let now = veil_core::now_millis();
    let taken: Option<i64> = sqlx::query_scalar("SELECT id FROM people WHERE name = $1").bind(&name).fetch_optional(&mut *c).await?;
    if let Some(person) = taken {
        // One of their devices may vouch for it; until then it is nothing
        // (no session, its signatures not accepted). The bound on pending
        // devices is kept after the transaction ([`prune_pending`]).
        sqlx::query(
            "INSERT INTO devices (person_id, signing_key, public_identity, created_at, pending, fingerprint) \
             VALUES ($1, $2, $3, $4, TRUE, $5)",
        )
        .bind(person)
        .bind(key)
        .bind(public_identity)
        .bind(now)
        .bind(fingerprint)
        .execute(&mut *c)
        .await?;
        return Ok(Err(name));
    }
    let person: i64 = sqlx::query_scalar("INSERT INTO people (name, created_at) VALUES ($1, $2) RETURNING id")
        .bind(&name)
        .bind(now)
        .fetch_one(&mut *c)
        .await?;
    let device: i64 = sqlx::query_scalar(
        "INSERT INTO devices (person_id, signing_key, public_identity, created_at) VALUES ($1, $2, $3, $4) RETURNING id",
    )
    .bind(person)
    .bind(key)
    .bind(public_identity)
    .bind(now)
    .fetch_one(&mut *c)
    .await?;
    Ok(Ok((device, person, name)))
}

/// Keep `name`'s pending devices bounded (§13.12): the expired ones go, then
/// all but the newest [`PENDING_PER_PERSON`], never one the person is
/// waiting for (`device_expected`). Best effort and idempotent, outside the
/// sign-in's transaction: its scans of other tables would make every
/// concurrent sign-in conflict with it on YugabyteDB.
async fn prune_pending(db: &sqlx::PgPool, name: &str) {
    let now = veil_core::now_millis();
    let unreferenced = "NOT EXISTS (SELECT 1 FROM sessions s WHERE s.device_id = d.id) \
         AND NOT EXISTS (SELECT 1 FROM device_vouches v WHERE v.device_id = d.id) \
         AND NOT EXISTS (SELECT 1 FROM invites i WHERE i.device_id = d.id) \
         AND NOT EXISTS (SELECT 1 FROM webauthn_credentials w WHERE w.device_id = d.id)";
    let expired = sqlx::query(&format!(
        "DELETE FROM devices d WHERE d.person_id = (SELECT id FROM people WHERE name = $1) AND d.pending \
         AND d.created_at < $2 AND {unreferenced}"
    ))
    .bind(name)
    .bind(now - PENDING_TTL_MS)
    .execute(db)
    .await;
    let over = sqlx::query(&format!(
        "DELETE FROM devices WHERE id IN (SELECT d.id FROM devices d WHERE d.person_id = (SELECT id FROM people WHERE name = $1) \
         AND d.pending AND NOT EXISTS (SELECT 1 FROM device_expected e WHERE e.person_id = d.person_id \
         AND e.fingerprint = d.fingerprint AND e.expires_at > $2) AND {unreferenced} \
         ORDER BY d.created_at DESC, d.id DESC OFFSET $3)"
    ))
    .bind(name)
    .bind(now)
    .bind(PENDING_PER_PERSON)
    .execute(db)
    .await;
    for r in [expired, over] {
        if let Err(e) = r {
            eprintln!("veil-server: pruning pending devices: {e}");
        }
    }
}

impl FromRequestParts<HubState> for Caller {
    type Rejection = Error;

    /// The session, checked on every request against the person's access
    /// epoch, which is read in the same statement as the project's (when the
    /// path names a project this server knows): a session ended or a device
    /// removed on any server is refused here (`caches`).
    async fn from_request_parts(parts: &mut Parts, hub: &HubState) -> Result<Caller> {
        authenticate_parts(parts, hub, true).await
    }
}

pub(crate) async fn authenticate_parts(parts: &mut Parts, hub: &HubState, enforce_api_csrf: bool) -> Result<Caller> {
    let project = match axum::extract::RawPathParams::from_request_parts(parts, hub).await {
        Ok(params) => params.iter().find(|(k, _)| *k == "p").and_then(|(_, v)| hub.caches.project(v)).map(|e| e.project.id),
        Err(_) => None,
    };
    let (token, from_cookie) = if let Some(auth) = parts.headers.get("authorization") {
        let tok = auth
            .to_str()
            .ok()
            .and_then(|a| a.strip_prefix("Bearer "))
            .ok_or_else(|| Error::unauthorized("expected a bearer token"))?;
        (tok, false)
    } else if let Some(tok) = cookie_token(&parts.headers) {
        (tok, true)
    } else {
        let epochs = match project {
            Some(p) => {
                let e = crate::caches::read_epochs(&hub.db, 0, Some(p)).await?;
                if let Some((pid, ge)) = e.gc {
                    hub.observe_gc_epoch(pid, ge);
                }
                e
            }
            None => Epochs::default(),
        };
        return Ok(Caller { person: None, epochs });
    };
    let hash = session_hash(token);
    let agent_token = token.starts_with(AGENT_TOKEN_PREFIX);
    let web_token = token.starts_with(veil_core::hub::web::WEB_TOKEN_PREFIX);
    let now = veil_core::now_millis();
    let stats = &hub.caches.stats;

    let caller = 'lookup: {
        if let Some(e) = hub.caches.session(&hash).filter(|e| e.expires_at > now) {
            let epochs = crate::caches::read_epochs(&hub.db, e.person.id, project).await?;
            if let Some((pid, ge)) = epochs.gc {
                hub.observe_gc_epoch(pid, ge);
            }
            if epochs.person == e.epoch {
                stats.session_hits.fetch_add(1, Ordering::Relaxed);
                break 'lookup Caller {
                    person: Some(e.person.clone()),
                    epochs,
                };
            }
        }
        stats.session_misses.fetch_add(1, Ordering::Relaxed);
        // The session and the person's epoch in one statement: the entry is
        // never tagged with an epoch newer than what it was read with.
        type Row = (i64, String, String, i64, i64, i64, i64, Option<String>, Option<i64>, Option<String>, bool);
        let row: Option<Row> = sqlx::query_as(
            "SELECT p.id, p.name, d.signing_key, s.expires_at, \
             COALESCE((SELECT epoch FROM access_epochs WHERE project_id = 0 AND person_id = p.id), 0), \
             COALESCE((SELECT epoch FROM access_epochs WHERE project_id = $3 AND person_id = 0), 0), \
             COALESCE((SELECT epoch FROM access_epochs WHERE project_id = $3 AND person_id = -1), 0), \
             s.agent, s.agent_project, s.agent_only, s.agent_runner \
             FROM sessions s JOIN devices d ON d.id = s.device_id JOIN people p ON p.id = s.person_id \
             LEFT JOIN sessions par ON par.token_hash = s.parent_hash \
             WHERE s.token_hash = $1 AND s.expires_at > $2 AND d.removed_at IS NULL \
             AND (NOT d.pending OR ($5 AND d.browser)) \
             AND (s.agent IS NOT NULL) = $4 AND (s.parent_hash IS NULL OR par.expires_at > $2)",
        )
        .bind(&hash)
        .bind(now)
        .bind(project.unwrap_or(-1))
        .bind(agent_token)
        .bind(web_token)
        .fetch_optional(&hub.db)
        .await?;
        match row {
            Some((id, name, device_key, expires_at, person_epoch, project_epoch, gc_epoch, agent, agent_project, agent_only, agent_runner)) => {
                if let Some(pid) = project {
                    hub.observe_gc_epoch(pid, gc_epoch);
                }
                let agent = agent_grant(hash.clone(), agent, agent_project, agent_only, agent_runner)?;
                let person = Person { id, name, device_key, agent };
                hub.caches.put_session(
                    &hash,
                    crate::caches::SessionEntry {
                        person: person.clone(),
                        expires_at,
                        epoch: person_epoch,
                    },
                );
                Caller {
                    person: Some(person),
                    epochs: Epochs {
                        person: person_epoch,
                        project: project.map(|p| (p, project_epoch)),
                        gc: project.map(|p| (p, gc_epoch)),
                    },
                }
            }
            // Never downgraded to anonymous: the client signs in again.
            None => return Err(Error::unauthorized("session expired or unknown; sign in again")),
        }
    };

    crate::web::record_session(hash.clone(), from_cookie, web_token);
    if enforce_api_csrf
        && from_cookie
        && !matches!(parts.method, axum::http::Method::GET | axum::http::Method::HEAD)
        && parts.uri.path().starts_with("/v1/")
    {
        crate::web::require_csrf(&parts.headers, Some(&hash), None)?;
    }
    Ok(caller)
}

/// An agent session's record, as stored; a malformed one fails closed.
pub(crate) fn agent_grant(session_hash: String, agent: Option<String>, project: Option<i64>, only: Option<String>, runner: bool) -> Result<Option<Arc<AgentGrant>>> {
    let Some(agent) = agent else { return Ok(None) };
    let damaged = || Error::unauthorized("this agent session's record is damaged; make a new one");
    let attribution: Attribution = serde_json::from_str(&agent).map_err(|_| damaged())?;
    let only = match only {
        Some(o) => Some(Arc::new(serde_json::from_str::<Vec<String>>(&o).map_err(|_| damaged())?)),
        None => None,
    };
    let session = session_hash.clone();
    Ok(Some(Arc::new(AgentGrant {
        session_hash,
        project: project.ok_or_else(damaged)?,
        session,
        only,
        attribution,
        runner,
    })))
}

/// An agent session's record: its attribution, project, narrowing and
/// whether it is a CI runner.
type AgentRow = (Option<String>, Option<i64>, Option<String>, bool);

/// Load an active agent session (`session_hash`) for `person_id` in
/// `project_id`, verifying that neither it, its parent session, nor its device
/// has expired or been revoked.
pub async fn load_agent_session<'c>(
    c: impl sqlx::PgExecutor<'c>,
    session_hash: &str,
    person_id: i64,
    project_id: i64,
) -> Result<Option<Arc<AgentGrant>>> {
    let now = veil_core::now_millis();
    let row: Option<AgentRow> = sqlx::query_as(
        "SELECT s.agent, s.agent_project, s.agent_only, s.agent_runner \
         FROM sessions s \
         JOIN devices d ON d.id = s.device_id \
         LEFT JOIN sessions par ON par.token_hash = s.parent_hash \
         WHERE s.token_hash = $1 AND s.person_id = $2 AND s.agent IS NOT NULL \
         AND s.agent_project = $3 AND s.expires_at > $4 \
         AND d.removed_at IS NULL AND NOT d.pending \
         AND (s.parent_hash IS NULL OR par.expires_at > $4)",
    )
    .bind(session_hash)
    .bind(person_id)
    .bind(project_id)
    .bind(now)
    .fetch_optional(c)
    .await?;
    match row {
        Some((agent, project, only, runner)) => Ok(agent_grant(session_hash.to_string(), agent, project, only, runner).ok().flatten()),
        None => Ok(None),
    }
}

impl Caller {
    pub fn signed_in(&self) -> Result<&Person> {
        self.person.as_ref().ok_or_else(|| Error::unauthorized("sign in first (`vl login`)"))
    }

    /// True when the request is a browser/web request (web UI route, cookie
    /// auth, browser fetch/origin headers, or a `web-` session token).
    pub fn is_web(&self) -> bool {
        crate::web::current_is_web()
    }

    /// Refuse an action that S25's no-secrets web client may never perform
    /// (secret key rings, secret shares, raw object streams, device/invite
    /// management, or minting child sessions).
    pub fn not_web(&self) -> Result<()> {
        if self.is_web() {
            return Err(Error::new(
                axum::http::StatusCode::FORBIDDEN,
                WEB_SESSION,
                "this route is not available to a browser or web session; use vl",
            ));
        }
        Ok(())
    }

    /// [`Caller::signed_in`], refusing a CI runner session: a runner reads
    /// what it tests and writes only check results, never objects, branches,
    /// changes or landings.
    pub fn not_runner(&self) -> Result<&Person> {
        let p = self.signed_in()?;
        if p.agent.as_ref().is_some_and(|a| a.runner) {
            return Err(Error::new(
                axum::http::StatusCode::FORBIDDEN,
                AGENT_SESSION,
                "a CI runner session writes only check results: it cannot upload objects, push, commit or land changes",
            ));
        }
        Ok(p)
    }

    /// [`Caller::signed_in`], refusing an agent session: changes of who
    /// has access, of devices, invites, key rings, shares, new projects and
    /// new sessions are the person's own, never an agent's (an agent session
    /// could otherwise make something that outlives it).
    pub fn person_only(&self) -> Result<&Person> {
        let p = self.signed_in()?;
        if p.agent.is_some() {
            return Err(Error::new(
                axum::http::StatusCode::FORBIDDEN,
                AGENT_SESSION,
                "an agent session cannot do this; only its person can, with their own session",
            ));
        }
        Ok(p)
    }

    /// The agent session's record, if this is one.
    pub fn agent(&self) -> Option<&AgentGrant> {
        self.person.as_ref().and_then(|p| p.agent.as_deref())
    }
}

/// `POST /v1/sessions/agent`: an agent session from the caller's own
/// session (`docs/HUB.md` §13.27). It lasts at most 12 hours and never past
/// the session it is made from, works in one project the person can see,
/// and is never wider than its person: narrowing only takes away. Nothing
/// is shown to anyone but the caller, and only the token's hash is kept.
pub async fn agent_session(
    State(hub): State<HubState>,
    headers: HeaderMap,
    caller: Caller,
    Json(req): Json<AgentSessionRequest>,
) -> Result<Json<AgentSession>> {
    caller.not_web()?;
    let me = caller.person_only()?.clone();
    req.attribution.validate().map_err(Error::bad_request)?;
    let only = normalize_only(&req.only).map_err(Error::bad_request)?;
    let (project, viewer) = crate::perm::open(&hub, &req.project, &caller).await?;
    let mut narrowed_viewer = viewer.clone();
    if !only.is_empty() {
        narrowed_viewer.only = Some(Arc::new(only.clone()));
    }
    narrowed_viewer.agent = true;
    if !project.view(&narrowed_viewer).sees_anything() && !project.participant(&narrowed_viewer) {
        return Err(Error::forbidden("this narrowing can see nothing in this project"));
    }
    if req.runner {
        let view = project.view(&viewer);
        for p in &only {
            if !view.sees_under(p) {
                return Err(Error::forbidden("a CI runner cannot be granted a path you cannot read"));
            }
        }
    }
    let parent = headers
        .get("authorization")
        .and_then(|a| a.to_str().ok())
        .and_then(|a| a.strip_prefix("Bearer "))
        .map(token_hash)
        .ok_or_else(|| Error::unauthorized("expected a bearer token"))?;
    let now = veil_core::now_millis();
    let want = match req.seconds {
        None => MAX_AGENT_SESSION_MS,
        Some(s) if s > 0 => s.saturating_mul(1000).min(MAX_AGENT_SESSION_MS),
        Some(_) => return Err(Error::bad_request("seconds must be positive")),
    };
    let token = format!("{AGENT_TOKEN_PREFIX}{}", hex::encode(veil_core::crypto::random_bytes::<32>()));
    let attribution = serde_json::to_string(&req.attribution).map_err(|e| Error::Other(e.into()))?;
    let only_json = (!only.is_empty()).then(|| serde_json::to_string(&only)).transpose().map_err(|e| Error::Other(e.into()))?;
    // The parent's device and expiry are read in the insert itself: a
    // parent that ended (its device removed) makes nothing.
    let expires_at: Option<i64> = sqlx::query_scalar(
        "INSERT INTO sessions (token_hash, device_id, person_id, expires_at, agent, agent_project, agent_only, agent_runner, parent_hash) \
         SELECT $1, s.device_id, s.person_id, LEAST(s.expires_at, $2), $3, $4, $5, $6, s.token_hash \
         FROM sessions s JOIN devices d ON d.id = s.device_id \
         WHERE s.token_hash = $7 AND s.person_id = $8 AND s.agent IS NULL AND s.expires_at > $9 \
         AND d.removed_at IS NULL AND NOT d.pending \
         RETURNING expires_at",
    )
    .bind(session_hash(&token))
    .bind(now + want)
    .bind(&attribution)
    .bind(project.id)
    .bind(&only_json)
    .bind(req.runner)
    .bind(&parent)
    .bind(me.id)
    .bind(now)
    .fetch_optional(&hub.db)
    .await?;
    let expires_at = expires_at.ok_or_else(|| Error::unauthorized("session expired or unknown; sign in again"))?;
    let tested = crate::ci::tested_for(&hub, &project, &viewer, &project.default_branch).await?;
    crate::audit(&hub.db, Some(project.id), Some(me.id), "agent session", &format!("for {}", req.attribution.agent.escape_debug())).await;
    Ok(Json(AgentSession {
        token,
        project: project.name,
        person: me.name,
        expires_at,
        only,
        attribution: req.attribution,
        runner: req.runner,
        tested,
    }))
}

/// `POST /v1/sessions/web`: mint a short-lived `web-` session derived from a
/// person's device session (`docs/HUB.md` §13.39). Lasts at most 4 hours and
/// never past its parent session; ending the parent session or removing the
/// device ends it immediately across all servers.
pub async fn web_session(
    State(hub): State<HubState>,
    headers: HeaderMap,
    caller: Caller,
    body: axum::body::Bytes,
) -> Result<Json<veil_core::hub::web::WebSession>> {
    caller.not_web()?;
    let me = caller.person_only()?.clone();
    let req: veil_core::hub::web::WebSessionRequest = if body.is_empty() {
        veil_core::hub::web::WebSessionRequest::default()
    } else {
        serde_json::from_slice(&body).map_err(|e| Error::bad_request(format!("invalid web session request: {e}")))?
    };
    let parent = headers
        .get("authorization")
        .and_then(|a| a.to_str().ok())
        .and_then(|a| a.strip_prefix("Bearer "))
        .map(token_hash)
        .ok_or_else(|| Error::unauthorized("expected a bearer token"))?;
    let now = veil_core::now_millis();
    let want = match req.seconds {
        None => veil_core::hub::web::DEFAULT_WEB_SESSION_MS,
        Some(s) if s > 0 => s.saturating_mul(1000).min(veil_core::hub::web::MAX_WEB_SESSION_MS),
        Some(_) => return Err(Error::bad_request("seconds must be positive")),
    };
    let token = format!(
        "{}{}",
        veil_core::hub::web::WEB_TOKEN_PREFIX,
        hex::encode(veil_core::crypto::random_bytes::<32>())
    );
    let hash = veil_core::hub::web::web_token_hash(&token);
    let csrf = veil_core::hub::web::csrf_for_session(&hash);
    let expires_at: Option<i64> = sqlx::query_scalar(
        "INSERT INTO sessions (token_hash, device_id, person_id, expires_at, parent_hash) \
         SELECT $1, s.device_id, s.person_id, LEAST(s.expires_at, $2), s.token_hash \
         FROM sessions s JOIN devices d ON d.id = s.device_id \
         WHERE s.token_hash = $3 AND s.person_id = $4 AND s.agent IS NULL AND s.parent_hash IS NULL \
         AND s.expires_at > $5 AND d.removed_at IS NULL AND NOT d.pending \
         RETURNING expires_at",
    )
    .bind(&hash)
    .bind(now + want)
    .bind(&parent)
    .bind(me.id)
    .bind(now)
    .fetch_optional(&hub.db)
    .await?;
    let expires_at = expires_at.ok_or_else(|| Error::unauthorized("session expired or unknown; sign in again"))?;
    crate::audit(&hub.db, None, Some(me.id), "web session", "derived").await;
    Ok(Json(veil_core::hub::web::WebSession {
        token,
        person: me.name,
        csrf,
        expires_at,
    }))
}

/// `POST /v1/sessions/web-enroll`: mint a short-lived single-use browser
/// enrollment code from a person's confirmed `vl` device (`docs/HUB.md` §13.40).
pub async fn web_enroll_session(
    State(hub): State<HubState>,
    headers: HeaderMap,
    caller: Caller,
    body: axum::body::Bytes,
) -> Result<Json<veil_core::hub::web::WebEnrollResponse>> {
    caller.not_web()?;
    let me = caller.person_only()?.clone();
    let req: veil_core::hub::web::WebEnrollRequest = if body.is_empty() {
        veil_core::hub::web::WebEnrollRequest::default()
    } else {
        serde_json::from_slice(&body).map_err(|e| Error::bad_request(format!("invalid web enroll request: {e}")))?
    };
    if let Some(lbl) = &req.label {
        if lbl.chars().count() > 64 {
            return Err(Error::bad_request("label is at most 64 characters"));
        }
    }
    let parent = headers
        .get("authorization")
        .and_then(|a| a.to_str().ok())
        .and_then(|a| a.strip_prefix("Bearer "))
        .map(token_hash)
        .ok_or_else(|| Error::unauthorized("expected a bearer token"))?;
    let now = veil_core::now_millis();
    let want = match req.seconds {
        None => veil_core::hub::web::DEFAULT_WEB_ENROLL_MS,
        Some(s) if s > 0 => s.saturating_mul(1000).min(veil_core::hub::web::MAX_WEB_ENROLL_MS),
        Some(_) => return Err(Error::bad_request("seconds must be positive")),
    };
    let code = format!(
        "{}{}",
        veil_core::hub::web::WEB_ENROLL_PREFIX,
        hex::encode(veil_core::crypto::random_bytes::<24>())
    );
    let hash = veil_core::hub::web::web_enroll_hash(&code);
    let expires_at: Option<i64> = sqlx::query_scalar(
        "INSERT INTO web_enrollments (code_hash, person_id, label, created_at, expires_at) \
         SELECT $1, s.person_id, $2, $3, LEAST(s.expires_at, $4) \
         FROM sessions s JOIN devices d ON d.id = s.device_id \
         WHERE s.token_hash = $5 AND s.person_id = $6 AND s.agent IS NULL AND s.parent_hash IS NULL \
         AND s.expires_at > $3 AND d.removed_at IS NULL AND NOT d.pending AND NOT d.browser \
         RETURNING expires_at",
    )
    .bind(&hash)
    .bind(&req.label)
    .bind(now)
    .bind(now + want)
    .bind(&parent)
    .bind(me.id)
    .fetch_optional(&hub.db)
    .await?;
    let expires_at = expires_at.ok_or_else(|| Error::unauthorized("session expired or unknown; sign in again"))?;
    let _ = sqlx::query("DELETE FROM web_enrollments WHERE person_id = $1 AND expires_at < $2")
        .bind(me.id)
        .bind(now)
        .execute(&hub.db)
        .await;
    crate::audit(&hub.db, None, Some(me.id), "web enroll", "passkey enrollment code").await;
    Ok(Json(veil_core::hub::web::WebEnrollResponse {
        code,
        person: me.name,
        expires_at,
    }))
}
