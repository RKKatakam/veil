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
//!   (`docs/HUB.md` §13.11). At most [`MAX_PENDING`] per person.

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

use crate::{
    error::{Error, Result},
    HubState,
};

pub const CHALLENGE_TTL_MS: i64 = 60_000;
/// Pending devices kept per person (the newest).
pub const MAX_PENDING: i64 = 8;

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
}

#[derive(Clone, Debug)]
pub struct Person {
    pub id: i64,
    pub name: String,
    /// The signed-in device's Ed25519 key (hex).
    pub device_key: String,
}

fn valid_key(key: &str) -> bool {
    key.len() == 64 && key.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn token_hash(token: &str) -> String {
    blake3::hash(token.as_bytes()).to_hex().to_string()
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
    let key = req.key.clone();
    let name = req.name.clone();
    let outcome = crate::db::serializable(&hub.db, move |c| {
        let key = key.clone();
        let name = name.clone();
        let public_identity = public_identity.clone();
        Box::pin(async move {
            let row: Option<(i64, i64, String, bool)> = sqlx::query_as(
                "SELECT d.id, p.id, p.name, d.pending FROM devices d JOIN people p ON p.id = d.person_id \
                 WHERE d.signing_key = $1 AND d.removed_at IS NULL",
            )
            .bind(&key)
            .fetch_optional(&mut *c)
            .await?;
            if let Some((device, person, name, pending)) = row {
                return Ok(if pending { Err(name) } else { Ok((device, person, name)) });
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
                // One of their devices may vouch for it; until then it is
                // nothing (no session, its signatures not accepted).
                sqlx::query(
                    "INSERT INTO devices (person_id, signing_key, public_identity, created_at, pending) VALUES ($1, $2, $3, $4, TRUE)",
                )
                .bind(person)
                .bind(&key)
                .bind(&public_identity)
                .bind(now)
                .execute(&mut *c)
                .await?;
                sqlx::query(
                    "DELETE FROM devices WHERE person_id = $1 AND pending AND id NOT IN \
                     (SELECT id FROM devices WHERE person_id = $1 AND pending ORDER BY id DESC LIMIT $2)",
                )
                .bind(person)
                .bind(MAX_PENDING)
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
                    .bind(&key)
                    .bind(&public_identity)
                    .bind(now)
                    .fetch_one(&mut *c)
                    .await?;
            Ok(Ok((device, person, name)))
        })
    })
    .await?;
    let (device, person, person_name) = outcome.map_err(|name| pending(&name))?;
    let token = hex::encode(veil_core::crypto::random_bytes::<32>());
    let expires_at = now + hub.session_ttl_ms;
    sqlx::query("INSERT INTO sessions (token_hash, device_id, person_id, expires_at) VALUES ($1, $2, $3, $4)")
        .bind(token_hash(&token))
        .bind(device)
        .bind(person)
        .bind(expires_at)
        .execute(&hub.db)
        .await?;
    crate::audit(&hub.db, None, Some(person), "login", &format!("device {device}")).await;
    Ok(Json(Session {
        token,
        person: person_name,
        expires_at,
        hub_key: hub.identity.verifying_hex(),
    }))
}

impl FromRequestParts<HubState> for Caller {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, hub: &HubState) -> Result<Caller> {
        let Some(auth) = parts.headers.get("authorization") else {
            return Ok(Caller { person: None });
        };
        let token = auth
            .to_str()
            .ok()
            .and_then(|a| a.strip_prefix("Bearer "))
            .ok_or_else(|| Error::unauthorized("expected a bearer token"))?;
        let row: Option<(i64, String, String)> = sqlx::query_as(
            "SELECT p.id, p.name, d.signing_key FROM sessions s JOIN devices d ON d.id = s.device_id JOIN people p ON p.id = s.person_id \
             WHERE s.token_hash = $1 AND s.expires_at > $2 AND d.removed_at IS NULL AND NOT d.pending",
        )
        .bind(token_hash(token))
        .bind(veil_core::now_millis())
        .fetch_optional(&hub.db)
        .await?;
        match row {
            Some((id, name, device_key)) => Ok(Caller {
                person: Some(Person { id, name, device_key }),
            }),
            // Never downgraded to anonymous: the client signs in again.
            None => Err(Error::unauthorized("session expired or unknown; sign in again")),
        }
    }
}

impl Caller {
    pub fn signed_in(&self) -> Result<&Person> {
        self.person.as_ref().ok_or_else(|| Error::unauthorized("sign in first (`vl login`)"))
    }
}
