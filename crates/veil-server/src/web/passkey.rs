//! Passkey (WebAuthn + PRF) enrollment and sign-in (`docs/HUB.md` §13.40;
//! `docs/design/server/phase-4-agent-scale.md` §4.12).
//!
//! * A browser device never receives or imports a `vl` private key.
//! * Enrollment requires a short-lived single-use `web-enroll-` code minted by
//!   an already signed-in `vl` device (`POST /v1/sessions/web-enroll` / `vl web`).
//! * When the browser supports WebAuthn PRF, its WASM Worker generates a fresh
//!   browser `Identity`, encrypts the private keys under the passkey's PRF
//!   output in IndexedDB, and sends **only** `public_identity` here. The new
//!   browser device starts `pending = TRUE` until confirmed (`vl identity confirm`).
//! * When the browser lacks WebAuthn PRF, passkey sign-in still works for plain
//!   files, diffs, search, and PR reviews, with a clear message that this
//!   browser cannot open secrets.

use axum::{
    extract::State,
    http::{header, HeaderMap, HeaderValue},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use veil_core::{
    hub::{
        web::{
            b64url_decode, b64url_encode, csrf_for_session, sha256, web_enroll_hash, web_token_hash,
            DEFAULT_WEB_SESSION_MS, WEB_ENROLL_PREFIX, WEB_TOKEN_PREFIX,
        },
        wire::device_fingerprint,
    },
    identity::parse_public_identity,
};

use crate::{
    error::{Error, Result},
    web::{
        html::{attach_security_headers, session_cookie_value},
        session::check_same_origin,
    },
    HubState,
};

const WEBAUTHN_CHALLENGE_TTL_MS: i64 = 120_000;
const COSE_ALG_ES256: i32 = -7;
const COSE_ALG_EDDSA: i32 = -8;

pub const NON_PRF_MESSAGE: &str = "Signed in with passkey, but this browser can't open secrets (WebAuthn PRF extension is unavailable). Everything else in the web client works.";

fn request_origin_and_rp_id(headers: &HeaderMap) -> Result<(String, String)> {
    let host_raw = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::bad_request("missing Host header"))?;
    let rp_id = host_raw
        .split(':')
        .next()
        .unwrap_or(host_raw)
        .to_ascii_lowercase();
    if rp_id.is_empty() {
        return Err(Error::bad_request("invalid Host header"));
    }
    let origin = match headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        Some(o) if !o.trim().is_empty() => o.trim().to_string(),
        _ => format!("https://{host_raw}"),
    };
    Ok((origin, rp_id))
}

#[derive(Deserialize)]
pub struct RegisterBeginReq {
    pub code: String,
}

#[derive(Deserialize)]
pub struct RegisterFinishReq {
    pub code: String,
    pub credential_id: String,
    pub client_data_json: String,
    pub attestation_object: String,
    pub prf_supported: bool,
    pub prf_salt: String,
    #[serde(default)]
    pub public_identity: Option<String>,
}

#[derive(Default, Deserialize)]
pub struct LoginBeginReq {
    #[serde(default)]
    pub person: Option<String>,
}

#[derive(Deserialize)]
pub struct LoginFinishReq {
    pub credential_id: String,
    pub client_data_json: String,
    pub authenticator_data: String,
    pub signature: String,
}

#[derive(Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    kind: String,
    challenge: String,
    origin: String,
}

/// `POST /web/passkey/register/begin`: validate an unconsumed `vl web` code and
/// issue a single-use WebAuthn creation challenge + PRF salt.
pub async fn register_begin_route(
    State(hub): State<HubState>,
    headers: HeaderMap,
    Json(req): Json<RegisterBeginReq>,
) -> Result<Json<Value>> {
    check_same_origin(&headers)?;
    let (origin, rp_id) = request_origin_and_rp_id(&headers)?;
    let code = req.code.trim();
    if !code.starts_with(WEB_ENROLL_PREFIX) {
        return Err(Error::bad_request("invalid enrollment code"));
    }
    let code_hash = web_enroll_hash(code);
    let now = veil_core::now_millis();
    let row: Option<(i64, String)> = sqlx::query_as(
        "SELECT p.id, p.name FROM web_enrollments e JOIN people p ON p.id = e.person_id \
         WHERE e.code_hash = $1 AND e.used_at IS NULL AND e.expires_at > $2",
    )
    .bind(&code_hash)
    .bind(now)
    .fetch_optional(&hub.db)
    .await?;
    let Some((person_id, person_name)) = row else {
        return Err(Error::unauthorized("enrollment code expired, unknown, or already used"));
    };

    let challenge = b64url_encode(&veil_core::crypto::random_bytes::<32>());
    let prf_salt = b64url_encode(&veil_core::crypto::random_bytes::<32>());
    sqlx::query(
        "INSERT INTO webauthn_challenges (challenge, kind, person_id, code_hash, prf_salt, origin, rp_id, expires_at) \
         VALUES ($1, 'register', $2, $3, $4, $5, $6, $7)",
    )
    .bind(&challenge)
    .bind(person_id)
    .bind(&code_hash)
    .bind(&prf_salt)
    .bind(&origin)
    .bind(&rp_id)
    .bind(now + WEBAUTHN_CHALLENGE_TTL_MS)
    .execute(&hub.db)
    .await?;

    let _ = sqlx::query("DELETE FROM webauthn_challenges WHERE expires_at < $1")
        .bind(now)
        .execute(&hub.db)
        .await;

    Ok(Json(json!({
        "challenge": challenge,
        "rp_id": rp_id,
        "person": person_name,
        "user_id": b64url_encode(&person_id.to_be_bytes()),
        "prf_salt": prf_salt,
    })))
}

/// `POST /web/passkey/register/finish`: verify WebAuthn attestation, consume
/// the single-use `vl web` enrollment code, register the browser device
/// (`pending = prf_supported`), and issue `__Host-veil_session`.
pub async fn register_finish_route(
    State(hub): State<HubState>,
    headers: HeaderMap,
    Json(req): Json<RegisterFinishReq>,
) -> Result<Response> {
    check_same_origin(&headers)?;
    if req.credential_id.len() > 512 || req.prf_salt.len() > 256 {
        return Err(Error::bad_request("invalid credential metadata"));
    }
    let _cred_raw = b64url_decode(&req.credential_id)
        .map_err(|_| Error::bad_request("invalid base64url credential_id"))?;
    let client_bytes = b64url_decode(&req.client_data_json)
        .map_err(|_| Error::bad_request("invalid base64url client_data_json"))?;
    let client: ClientData = serde_json::from_slice(&client_bytes)
        .map_err(|_| Error::bad_request("invalid clientDataJSON"))?;
    if client.kind != "webauthn.create" {
        return Err(Error::bad_request("expected webauthn.create ceremony"));
    }

    let now = veil_core::now_millis();
    type ChalRow = (Option<i64>, Option<String>, Option<String>, String, String);
    let chal: Option<ChalRow> = sqlx::query_as(
        "DELETE FROM webauthn_challenges \
         WHERE challenge = $1 AND kind = 'register' AND expires_at > $2 \
         RETURNING person_id, code_hash, prf_salt, origin, rp_id",
    )
    .bind(&client.challenge)
    .bind(now)
    .fetch_optional(&hub.db)
    .await?;
    let Some((Some(person_id), Some(expected_code_hash), Some(expected_prf_salt), expected_origin, expected_rp_id)) = chal else {
        return Err(Error::unauthorized("registration challenge expired or unknown"));
    };

    if web_enroll_hash(req.code.trim()) != expected_code_hash {
        return Err(Error::unauthorized("enrollment code mismatch"));
    }
    if client.origin != expected_origin {
        return Err(Error::unauthorized("WebAuthn origin mismatch"));
    }
    if req.prf_salt != expected_prf_salt {
        return Err(Error::bad_request("PRF salt mismatch"));
    }

    let att_bytes = b64url_decode(&req.attestation_object)
        .map_err(|_| Error::bad_request("invalid base64url attestation_object"))?;
    let parsed_att = parse_attestation_object(&att_bytes)?;
    if parsed_att.rp_id_hash != sha256(expected_rp_id.as_bytes()) {
        return Err(Error::unauthorized("WebAuthn rpIdHash mismatch"));
    }
    if parsed_att.flags & 0x01 == 0 {
        return Err(Error::unauthorized("WebAuthn user-present flag not set"));
    }
    if b64url_encode(&parsed_att.credential_id) != req.credential_id {
        return Err(Error::bad_request("attestation credential_id mismatch"));
    }

    // Defense-in-depth: refuse any payload that looks like private key material.
    if let Some(raw_pub) = &req.public_identity {
        if raw_pub.contains('{') || raw_pub.contains("signing_seed") || raw_pub.contains("secret") {
            return Err(Error::bad_request("private device key material is never accepted by the server"));
        }
    }

    let (signing_key, public_identity, fingerprint, pending) = if req.prf_supported {
        let raw_pub = req
            .public_identity
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| Error::bad_request("public_identity is required when prf_supported is true"))?;
        let parsed = parse_public_identity(raw_pub)
            .ok()
            .filter(|p| p.binding.is_some())
            .ok_or_else(|| Error::bad_request("browser public_identity must carry a valid key binding"))?;
        let sk = parsed
            .signing_hex()
            .ok_or_else(|| Error::bad_request("browser public_identity missing Ed25519 key"))?;
        let fp = device_fingerprint(&parsed)
            .ok_or_else(|| Error::bad_request("browser public_identity missing fingerprint"))?;
        (sk, raw_pub.to_string(), Some(fp), true)
    } else {
        if req.public_identity.as_deref().is_some_and(|s| !s.trim().is_empty()) {
            return Err(Error::bad_request("non-PRF browser registration cannot carry a secret-capable public_identity"));
        }
        let sk = format!("web-noprf:{}", hex::encode(sha256(req.credential_id.as_bytes())));
        (sk, String::new(), None, false)
    };

    let token = format!("{WEB_TOKEN_PREFIX}{}", hex::encode(veil_core::crypto::random_bytes::<32>()));
    let session_hash = web_token_hash(&token);
    let csrf = csrf_for_session(&session_hash);
    let expires_at = now + DEFAULT_WEB_SESSION_MS;

    let cred_id = req.credential_id.clone();
    let prf_salt = req.prf_salt.clone();
    let prf_supported = req.prf_supported;
    let sign_count = parsed_att.sign_count as i64;
    let alg = parsed_att.alg;
    let pub_key_bytes = parsed_att.public_key;
    let sk_clone = signing_key.clone();
    let pub_id_clone = public_identity.clone();
    let fp_clone = fingerprint.clone();
    let sh_clone = session_hash.clone();

    let person_name: String = crate::db::serializable(&hub.db, move |c| {
        let code_hash = expected_code_hash.clone();
        let cred_id = cred_id.clone();
        let prf_salt = prf_salt.clone();
        let sk = sk_clone.clone();
        let pub_id = pub_id_clone.clone();
        let fp = fp_clone.clone();
        let pub_key = pub_key_bytes.clone();
        let sh = sh_clone.clone();
        Box::pin(async move {
            let consumed = sqlx::query(
                "UPDATE web_enrollments SET used_at = $1 \
                 WHERE code_hash = $2 AND person_id = $3 AND used_at IS NULL AND expires_at > $1",
            )
            .bind(now)
            .bind(&code_hash)
            .bind(person_id)
            .execute(&mut *c)
            .await?
            .rows_affected();
            if consumed != 1 {
                return Err(Error::unauthorized("enrollment code expired or already used"));
            }

            // Refuse reusing any existing device's signing key or public identity (never copy a `vl` device key).
            let dup: Option<i64> = sqlx::query_scalar(
                "SELECT id FROM devices WHERE signing_key = $1 OR ($2 <> '' AND public_identity = $2) LIMIT 1",
            )
            .bind(&sk)
            .bind(&pub_id)
            .fetch_optional(&mut *c)
            .await?;
            if dup.is_some() {
                return Err(Error::conflict("device key is already registered; browser devices must generate fresh keys"));
            }

            let dup_cred: Option<i32> = sqlx::query_scalar("SELECT 1 FROM webauthn_credentials WHERE credential_id = $1")
                .bind(&cred_id)
                .fetch_optional(&mut *c)
                .await?;
            if dup_cred.is_some() {
                return Err(Error::conflict("passkey credential is already registered"));
            }

            let device_id: i64 = sqlx::query_scalar(
                "INSERT INTO devices (person_id, signing_key, public_identity, fingerprint, created_at, pending, browser, prf_supported) \
                 VALUES ($1, $2, $3, $4, $5, $6, TRUE, $7) RETURNING id",
            )
            .bind(person_id)
            .bind(&sk)
            .bind(&pub_id)
            .bind(&fp)
            .bind(now)
            .bind(pending)
            .bind(prf_supported)
            .fetch_one(&mut *c)
            .await?;

            sqlx::query(
                "INSERT INTO webauthn_credentials (credential_id, person_id, device_id, alg, public_key, sign_count, prf_salt, created_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            )
            .bind(&cred_id)
            .bind(person_id)
            .bind(device_id)
            .bind(alg)
            .bind(&pub_key)
            .bind(sign_count)
            .bind(&prf_salt)
            .bind(now)
            .execute(&mut *c)
            .await?;

            sqlx::query(
                "INSERT INTO sessions (token_hash, device_id, person_id, expires_at) VALUES ($1, $2, $3, $4)",
            )
            .bind(&sh)
            .bind(device_id)
            .bind(person_id)
            .bind(expires_at)
            .execute(&mut *c)
            .await?;

            let pname: String = sqlx::query_scalar("SELECT name FROM people WHERE id = $1")
                .bind(person_id)
                .fetch_one(&mut *c)
                .await?;
            Ok(pname)
        })
    })
    .await?;

    crate::audit(
        &hub.db,
        None,
        Some(person_id),
        "passkey enroll",
        if req.prf_supported { "prf browser device (pending confirmation)" } else { "non-prf browser passkey" },
    )
    .await;

    let message = match (&fingerprint, req.prf_supported) {
        (Some(fp), true) => format!(
            "Passkey enrolled. Confirm browser device {fp} from vl (`vl identity confirm {fp}`) before opening secrets."
        ),
        _ => NON_PRF_MESSAGE.to_string(),
    };

    let max_age = ((expires_at - now) / 1000).max(1);
    let cookie = session_cookie_value(&token, max_age);
    let mut resp = Json(json!({
        "person": person_name,
        "csrf": csrf,
        "expires_at": expires_at,
        "prf_supported": req.prf_supported,
        "prf_salt": req.prf_salt,
        "confirmed": false,
        "fingerprint": fingerprint,
        "message": message,
    }))
    .into_response();
    resp.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).map_err(|e| Error::Other(e.into()))?,
    );
    attach_security_headers(&mut resp, true);
    Ok(resp)
}

/// `POST /web/passkey/login/begin`: issue a single-use WebAuthn assertion challenge.
pub async fn login_begin_route(
    State(hub): State<HubState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Value>> {
    check_same_origin(&headers)?;
    let req: LoginBeginReq = if body.is_empty() {
        LoginBeginReq::default()
    } else {
        serde_json::from_slice(&body).map_err(|_| Error::bad_request("invalid JSON body"))?
    };
    let (origin, rp_id) = request_origin_and_rp_id(&headers)?;
    let now = veil_core::now_millis();
    let challenge = b64url_encode(&veil_core::crypto::random_bytes::<32>());

    let mut allow_credentials: Vec<Value> = Vec::new();
    let mut person_id: Option<i64> = None;
    if let Some(name) = req.person.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        person_id = sqlx::query_scalar("SELECT id FROM people WHERE name = $1")
            .bind(name)
            .fetch_optional(&hub.db)
            .await?;
        if let Some(pid) = person_id {
            let creds: Vec<(String, String)> = sqlx::query_as(
                "SELECT w.credential_id, w.prf_salt FROM webauthn_credentials w \
                 JOIN devices d ON d.id = w.device_id \
                 WHERE w.person_id = $1 AND d.removed_at IS NULL ORDER BY w.created_at DESC LIMIT 32",
            )
            .bind(pid)
            .fetch_all(&hub.db)
            .await?;
            for (cid, salt) in creds {
                allow_credentials.push(json!({ "id": cid, "prf_salt": salt }));
            }
        }
    }

    sqlx::query(
        "INSERT INTO webauthn_challenges (challenge, kind, person_id, origin, rp_id, expires_at) \
         VALUES ($1, 'login', $2, $3, $4, $5)",
    )
    .bind(&challenge)
    .bind(person_id)
    .bind(&origin)
    .bind(&rp_id)
    .bind(now + WEBAUTHN_CHALLENGE_TTL_MS)
    .execute(&hub.db)
    .await?;

    Ok(Json(json!({
        "challenge": challenge,
        "rp_id": rp_id,
        "allow_credentials": allow_credentials,
    })))
}

/// `POST /web/passkey/login/finish`: verify a WebAuthn assertion (challenge,
/// origin, `rpIdHash`, UP flag, monotonic `signCount`, and ES256/EdDSA
/// signature) and issue `__Host-veil_session`.
pub async fn login_finish_route(
    State(hub): State<HubState>,
    headers: HeaderMap,
    Json(req): Json<LoginFinishReq>,
) -> Result<Response> {
    check_same_origin(&headers)?;
    let client_bytes = b64url_decode(&req.client_data_json)
        .map_err(|_| Error::bad_request("invalid base64url client_data_json"))?;
    let client: ClientData = serde_json::from_slice(&client_bytes)
        .map_err(|_| Error::bad_request("invalid clientDataJSON"))?;
    if client.kind != "webauthn.get" {
        return Err(Error::bad_request("expected webauthn.get ceremony"));
    }
    let auth_data = b64url_decode(&req.authenticator_data)
        .map_err(|_| Error::bad_request("invalid base64url authenticator_data"))?;
    if auth_data.len() < 37 {
        return Err(Error::bad_request("authenticatorData too short"));
    }
    let sig_bytes = b64url_decode(&req.signature)
        .map_err(|_| Error::bad_request("invalid base64url signature"))?;

    let now = veil_core::now_millis();
    let chal: Option<(Option<i64>, String, String)> = sqlx::query_as(
        "DELETE FROM webauthn_challenges \
         WHERE challenge = $1 AND kind = 'login' AND expires_at > $2 \
         RETURNING person_id, origin, rp_id",
    )
    .bind(&client.challenge)
    .bind(now)
    .fetch_optional(&hub.db)
    .await?;
    let Some((expected_person, expected_origin, expected_rp_id)) = chal else {
        return Err(Error::unauthorized("login challenge expired or unknown"));
    };

    if client.origin != expected_origin {
        return Err(Error::unauthorized("WebAuthn origin mismatch"));
    }
    if auth_data[..32] != sha256(expected_rp_id.as_bytes()) {
        return Err(Error::unauthorized("WebAuthn rpIdHash mismatch"));
    }
    if auth_data[32] & 0x01 == 0 {
        return Err(Error::unauthorized("WebAuthn user-present flag not set"));
    }
    let new_sign_count = u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]) as i64;

    type CredRow = (i64, String, i64, i32, Vec<u8>, i64, String, bool, bool, Option<String>);
    let row: Option<CredRow> = sqlx::query_as(
        "SELECT p.id, p.name, d.id, w.alg, w.public_key, w.sign_count, w.prf_salt, d.pending, d.prf_supported, d.fingerprint \
         FROM webauthn_credentials w \
         JOIN devices d ON d.id = w.device_id \
         JOIN people p ON p.id = w.person_id \
         WHERE w.credential_id = $1 AND d.removed_at IS NULL",
    )
    .bind(&req.credential_id)
    .fetch_optional(&hub.db)
    .await?;
    let Some((person_id, person_name, device_id, alg, public_key, stored_sign_count, prf_salt, pending, prf_supported, fingerprint)) = row else {
        return Err(Error::unauthorized("unknown or revoked passkey"));
    };
    if let Some(pid) = expected_person {
        if pid != person_id {
            return Err(Error::unauthorized("passkey belongs to a different person"));
        }
    }
    if (stored_sign_count > 0 || new_sign_count > 0) && new_sign_count <= stored_sign_count {
        return Err(Error::unauthorized("WebAuthn signCount did not advance"));
    }

    let mut signed_payload = Vec::with_capacity(auth_data.len() + 32);
    signed_payload.extend_from_slice(&auth_data);
    signed_payload.extend_from_slice(&sha256(&client_bytes));
    verify_webauthn_sig(alg, &public_key, &signed_payload, &sig_bytes)?;

    let updated = sqlx::query(
        "UPDATE webauthn_credentials SET sign_count = $1 WHERE credential_id = $2 AND sign_count = $3",
    )
    .bind(new_sign_count)
    .bind(&req.credential_id)
    .bind(stored_sign_count)
    .execute(&hub.db)
    .await?
    .rows_affected();
    if updated != 1 {
        return Err(Error::unauthorized("concurrent passkey assertion replay refused"));
    }

    let token = format!("{WEB_TOKEN_PREFIX}{}", hex::encode(veil_core::crypto::random_bytes::<32>()));
    let session_hash = web_token_hash(&token);
    let csrf = csrf_for_session(&session_hash);
    let expires_at = now + DEFAULT_WEB_SESSION_MS;

    sqlx::query("INSERT INTO sessions (token_hash, device_id, person_id, expires_at) VALUES ($1, $2, $3, $4)")
        .bind(&session_hash)
        .bind(device_id)
        .bind(person_id)
        .bind(expires_at)
        .execute(&hub.db)
        .await?;

    crate::audit(&hub.db, None, Some(person_id), "passkey login", "web session").await;

    let confirmed = prf_supported && !pending;
    let message = if !prf_supported {
        NON_PRF_MESSAGE.to_string()
    } else if !confirmed {
        match &fingerprint {
            Some(fp) => format!(
                "Signed in. Confirm browser device {fp} from vl (`vl identity confirm {fp}`) before opening secrets."
            ),
            None => "Signed in. Confirm this browser device from vl before opening secrets.".to_string(),
        }
    } else {
        "Signed in with passkey.".to_string()
    };

    let max_age = ((expires_at - now) / 1000).max(1);
    let cookie = session_cookie_value(&token, max_age);
    let mut resp = Json(json!({
        "person": person_name,
        "csrf": csrf,
        "expires_at": expires_at,
        "prf_supported": prf_supported,
        "prf_salt": prf_salt,
        "confirmed": confirmed,
        "fingerprint": fingerprint,
        "message": message,
    }))
    .into_response();
    resp.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).map_err(|e| Error::Other(e.into()))?,
    );
    attach_security_headers(&mut resp, true);
    Ok(resp)
}

fn verify_webauthn_sig(alg: i32, public_key: &[u8], msg: &[u8], sig: &[u8]) -> Result<()> {
    let ok = match alg {
        COSE_ALG_ES256 => webpki::ring::ECDSA_P256_SHA256.verify_signature(public_key, msg, sig).is_ok(),
        COSE_ALG_EDDSA => webpki::ring::ED25519.verify_signature(public_key, msg, sig).is_ok(),
        _ => false,
    };
    if !ok {
        return Err(Error::unauthorized("invalid WebAuthn assertion signature"));
    }
    Ok(())
}

// ---- Minimal RFC 8949 CBOR reader for WebAuthn attestationObject & COSE_Key ----

struct ParsedAttestation {
    rp_id_hash: [u8; 32],
    flags: u8,
    sign_count: u32,
    credential_id: Vec<u8>,
    alg: i32,
    public_key: Vec<u8>,
}

#[derive(Clone, Debug)]
enum CborVal {
    Int(i64),
    Bytes(Vec<u8>),
    Text(String),
    #[allow(dead_code)]
    Array(Vec<CborVal>),
    Map(Vec<(CborVal, CborVal)>),
    Other,
}

fn read_cbor_head(buf: &[u8], pos: &mut usize) -> Result<(u8, u64)> {
    let b = *buf.get(*pos).ok_or_else(|| Error::bad_request("truncated CBOR"))?;
    *pos += 1;
    let major = b >> 5;
    let info = b & 0x1f;
    let val = match info {
        0..=23 => info as u64,
        24 => {
            let v = *buf.get(*pos).ok_or_else(|| Error::bad_request("truncated CBOR u8"))?;
            *pos += 1;
            v as u64
        }
        25 => {
            let s = buf.get(*pos..*pos + 2).ok_or_else(|| Error::bad_request("truncated CBOR u16"))?;
            *pos += 2;
            u16::from_be_bytes([s[0], s[1]]) as u64
        }
        26 => {
            let s = buf.get(*pos..*pos + 4).ok_or_else(|| Error::bad_request("truncated CBOR u32"))?;
            *pos += 4;
            u32::from_be_bytes([s[0], s[1], s[2], s[3]]) as u64
        }
        27 => {
            let s = buf.get(*pos..*pos + 8).ok_or_else(|| Error::bad_request("truncated CBOR u64"))?;
            *pos += 8;
            u64::from_be_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]])
        }
        _ => return Err(Error::bad_request("unsupported indefinite CBOR encoding")),
    };
    Ok((major, val))
}

fn read_cbor_val(buf: &[u8], pos: &mut usize, depth: usize) -> Result<CborVal> {
    if depth > 8 {
        return Err(Error::bad_request("CBOR nesting too deep"));
    }
    let (major, len) = read_cbor_head(buf, pos)?;
    match major {
        0 => Ok(CborVal::Int(i64::try_from(len).map_err(|_| Error::bad_request("CBOR uint overflow"))?)),
        1 => {
            let n = i64::try_from(len).map_err(|_| Error::bad_request("CBOR nint overflow"))?;
            Ok(CborVal::Int(-1 - n))
        }
        2 => {
            let n = usize::try_from(len).ok().filter(|&n| n <= 65_536).ok_or_else(|| Error::bad_request("CBOR bytes too large"))?;
            let s = buf.get(*pos..*pos + n).ok_or_else(|| Error::bad_request("truncated CBOR bytes"))?;
            *pos += n;
            Ok(CborVal::Bytes(s.to_vec()))
        }
        3 => {
            let n = usize::try_from(len).ok().filter(|&n| n <= 65_536).ok_or_else(|| Error::bad_request("CBOR text too large"))?;
            let s = buf.get(*pos..*pos + n).ok_or_else(|| Error::bad_request("truncated CBOR text"))?;
            *pos += n;
            let txt = std::str::from_utf8(s).map_err(|_| Error::bad_request("invalid UTF-8 in CBOR"))?;
            Ok(CborVal::Text(txt.to_string()))
        }
        4 => {
            let n = usize::try_from(len).ok().filter(|&n| n <= 256).ok_or_else(|| Error::bad_request("CBOR array too large"))?;
            let mut items = Vec::with_capacity(n);
            for _ in 0..n {
                items.push(read_cbor_val(buf, pos, depth + 1)?);
            }
            Ok(CborVal::Array(items))
        }
        5 => {
            let n = usize::try_from(len).ok().filter(|&n| n <= 256).ok_or_else(|| Error::bad_request("CBOR map too large"))?;
            let mut pairs = Vec::with_capacity(n);
            for _ in 0..n {
                let k = read_cbor_val(buf, pos, depth + 1)?;
                let v = read_cbor_val(buf, pos, depth + 1)?;
                pairs.push((k, v));
            }
            Ok(CborVal::Map(pairs))
        }
        6 => read_cbor_val(buf, pos, depth + 1),
        7 => Ok(CborVal::Other),
        _ => Err(Error::bad_request("invalid CBOR major type")),
    }
}

fn map_int(pairs: &[(CborVal, CborVal)], key: i64) -> Option<&CborVal> {
    pairs.iter().find_map(|(k, v)| match k {
        CborVal::Int(i) if *i == key => Some(v),
        _ => None,
    })
}

fn parse_attestation_object(bytes: &[u8]) -> Result<ParsedAttestation> {
    let mut pos = 0;
    let top = read_cbor_val(bytes, &mut pos, 0)?;
    let CborVal::Map(pairs) = top else {
        return Err(Error::bad_request("attestationObject must be a CBOR map"));
    };
    let auth_data = pairs
        .iter()
        .find_map(|(k, v)| match (k, v) {
            (CborVal::Text(s), CborVal::Bytes(b)) if s == "authData" => Some(b.as_slice()),
            _ => None,
        })
        .ok_or_else(|| Error::bad_request("attestationObject missing authData"))?;
    if auth_data.len() < 55 {
        return Err(Error::bad_request("attestation authData too short"));
    }
    let mut rp_id_hash = [0u8; 32];
    rp_id_hash.copy_from_slice(&auth_data[..32]);
    let flags = auth_data[32];
    if flags & 0x40 == 0 {
        return Err(Error::bad_request("attestation authData missing attestedCredentialData"));
    }
    let sign_count = u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]);
    let cred_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
    if cred_len == 0 || cred_len > 512 || auth_data.len() <= 55 + cred_len {
        return Err(Error::bad_request("invalid attested credentialId length"));
    }
    let credential_id = auth_data[55..55 + cred_len].to_vec();
    let mut cose_pos = 55 + cred_len;
    let cose = read_cbor_val(auth_data, &mut cose_pos, 0)?;
    let CborVal::Map(cose_map) = cose else {
        return Err(Error::bad_request("credentialPublicKey must be a COSE_Key map"));
    };
    let Some(CborVal::Int(alg_i64)) = map_int(&cose_map, 3) else {
        return Err(Error::bad_request("COSE_Key missing alg"));
    };
    let (alg, public_key) = match *alg_i64 {
        -7 => {
            // ES256: kty = 2 (EC2), crv = 1 (P-256), -2 = x (32B), -3 = y (32B).
            if !matches!(map_int(&cose_map, 1), Some(CborVal::Int(2)))
                || !matches!(map_int(&cose_map, -1), Some(CborVal::Int(1)))
            {
                return Err(Error::bad_request("ES256 COSE_Key must be P-256 EC2"));
            }
            let Some(CborVal::Bytes(x)) = map_int(&cose_map, -2) else {
                return Err(Error::bad_request("ES256 COSE_Key missing x coordinate"));
            };
            let Some(CborVal::Bytes(y)) = map_int(&cose_map, -3) else {
                return Err(Error::bad_request("ES256 COSE_Key missing y coordinate"));
            };
            if x.len() != 32 || y.len() != 32 {
                return Err(Error::bad_request("ES256 P-256 coordinates must be 32 bytes"));
            }
            let mut uncompressed = Vec::with_capacity(65);
            uncompressed.push(0x04);
            uncompressed.extend_from_slice(x);
            uncompressed.extend_from_slice(y);
            (COSE_ALG_ES256, uncompressed)
        }
        -8 => {
            // EdDSA: kty = 1 (OKP), crv = 6 (Ed25519), -2 = x (32B).
            if !matches!(map_int(&cose_map, 1), Some(CborVal::Int(1)))
                || !matches!(map_int(&cose_map, -1), Some(CborVal::Int(6)))
            {
                return Err(Error::bad_request("EdDSA COSE_Key must be Ed25519 OKP"));
            }
            let Some(CborVal::Bytes(x)) = map_int(&cose_map, -2) else {
                return Err(Error::bad_request("EdDSA COSE_Key missing public key bytes"));
            };
            if x.len() != 32 {
                return Err(Error::bad_request("Ed25519 public key must be 32 bytes"));
            }
            (COSE_ALG_EDDSA, x.clone())
        }
        _ => return Err(Error::bad_request("unsupported COSE algorithm (expected ES256 or EdDSA)")),
    };

    Ok(ParsedAttestation {
        rp_id_hash,
        flags,
        sign_count,
        credential_id,
        alg,
        public_key,
    })
}
