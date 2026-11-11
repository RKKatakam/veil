//! Browser secret opening, project opt-in (`projects.web_secrets`), key-ring
//! filtering, and isolated Worker assets (`docs/HUB.md` §13.40;
//! `docs/design/server/phase-4-agent-scale.md` §4.12, §11 item 6, threat 18).
//!
//! * Off by default (`projects.web_secrets = FALSE`). With the setting off:
//!   - `device_list(?project=...)` omits browser devices from active `identities`
//!     and lists confirmed browser devices in `removed` so `vl` never wraps keys
//!     to them (and rotates away if turned off);
//!   - `post_ring` refuses any ring granting a browser device (`403 web_secrets_disabled`);
//!   - no HTML page renders a decrypt path, and `/v1/projects/{p}/web/*` plus
//!     `/p/{p}/web/*` all return `403 web_secrets_disabled`.
//! * Unconfirmed browser devices (`pending = TRUE` or lacking a `device_vouches`
//!   row) never receive a wrapped key (`403 unconfirmed_browser_device`).
//! * Confirmed PRF browser devices receive only verified `KeyRing`s of scopes
//!   their person may read right now, and decryption runs exclusively inside a
//!   dedicated Web Worker (`web_secret_worker.wasm`).

use std::collections::{BTreeMap, HashSet};

use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use veil_core::{
    keychain::{project_fingerprint, KeyRing, RingOp},
    object::Object,
    policy::{rule_scope_of, Policy, Tier, DEFAULT_SCOPE, RULE_SCOPE},
    ObjectId,
};

use crate::{
    auth::Caller,
    error::{Error, Result},
    perm::{self, Project, Viewer},
    query::{self, Ask, FileParams},
    web::{
        html::{attach_security_headers, redirect_see_other, url_part},
        session::{parse_form, require_current_csrf},
    },
    HubState,
};

pub const WEB_SECRETS_DISABLED_CODE: &str = "web_secrets_disabled";
pub const UNCONFIRMED_BROWSER_DEVICE_CODE: &str = "unconfirmed_browser_device";
pub const NON_PRF_BROWSER_CODE: &str = "prf_unavailable";

pub const HONEST_LIMIT_NOTICE: &str = "Honest limit: unlike vl on your machine, a server that was broken into could serve web code that reads secrets opened in a browser.";

const WORKER_CSP_HEADER: &str = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'self'; base-uri 'none'; form-action 'none'";

pub fn web_secrets_disabled_err() -> Error {
    Error::new(
        StatusCode::FORBIDDEN,
        WEB_SECRETS_DISABLED_CODE,
        "browser secret decryption is turned off for this project; open secrets with vl",
    )
}

pub fn unconfirmed_browser_device_err() -> Error {
    Error::new(
        StatusCode::FORBIDDEN,
        UNCONFIRMED_BROWSER_DEVICE_CODE,
        "browser device is not confirmed yet; run `vl identity confirm <FINGERPRINT>` on an existing device",
    )
}

pub async fn is_project_web_secrets_enabled(db: &sqlx::PgPool, project_id: i64) -> Result<bool> {
    let enabled: Option<bool> = sqlx::query_scalar("SELECT web_secrets FROM projects WHERE id = $1")
        .bind(project_id)
        .fetch_optional(db)
        .await?;
    Ok(enabled.unwrap_or(false))
}

/// Exact set of secret key-ring scopes `viewer` is entitled to open in `project`
/// right now under the server's accepted `.veilpolicy` and live group memberships.
pub fn readable_scopes(project: &Project, viewer: &Viewer) -> HashSet<String> {
    let mut out = HashSet::new();
    if !project.participant(viewer) {
        return out;
    }
    let view = project.view(viewer);
    let policy = Policy::parse(&project.policy_text);
    let per_rule = policy
        .rules()
        .iter()
        .any(|r| r.tier == Tier::Cloaked(RULE_SCOPE.into()));

    if viewer.admin {
        out.insert(DEFAULT_SCOPE.to_string());
        if per_rule {
            for (i, r) in project.policy.rules.iter().enumerate() {
                if r.names.is_empty() || project.policy.rules[i + 1..].iter().any(|l| l.path == r.path) {
                    continue;
                }
                out.insert(rule_scope_of(&r.path));
            }
        }
        for r in policy.rules() {
            if let Tier::Cloaked(s) = &r.tier {
                if s != RULE_SCOPE {
                    out.insert(s.clone());
                }
            }
        }
    } else {
        if per_rule {
            for (i, r) in project.policy.rules.iter().enumerate() {
                if r.names.is_empty() || project.policy.rules[i + 1..].iter().any(|l| l.path == r.path) {
                    continue;
                }
                // `view.write(&r.path)` holds iff `viewer` matches a group or person
                // named on `r` (never merely `public` read access).
                if view.write(&r.path) {
                    out.insert(rule_scope_of(&r.path));
                }
            }
        }
        for r in policy.rules() {
            if let Tier::Cloaked(s) = &r.tier {
                if s != RULE_SCOPE && !(per_rule && s == DEFAULT_SCOPE) && view.sees_anything() {
                    out.insert(s.clone());
                }
            }
        }
    }

    if let Some(narrowed) = viewer.narrowed_scopes(project) {
        out.retain(|s| narrowed.contains(s));
    }
    out
}

/// Enforce S26's two server-side ring-upload invariants on `POST /v1/projects/{p}/rings/{scope}`:
/// 1. No ring ever wraps a key to an unconfirmed (`pending`) device or unvouched browser device.
/// 2. When `projects.web_secrets` is `false`, no ring wraps a key to a browser device.
pub async fn validate_ring_browser_members(
    db: &sqlx::PgPool,
    project_id: i64,
    ring: &KeyRing,
) -> Result<bool> {
    let web_secrets = is_project_web_secrets_enabled(db, project_id).await?;
    let mut member_ids: HashSet<String> = HashSet::new();
    if let Ok(st) = ring.verify() {
        member_ids.extend(st.members.keys().cloned());
    } else {
        for entry in &ring.log {
            match &entry.op {
                RingOp::Genesis { members, .. } => {
                    for m in members {
                        member_ids.insert(m.id.clone());
                    }
                }
                RingOp::Grant { member } | RingOp::Share { member, .. } => {
                    member_ids.insert(member.id.clone());
                }
                _ => {}
            }
        }
    }
    member_ids.extend(ring.members.keys().cloned());
    if member_ids.is_empty() {
        return Ok(web_secrets);
    }

    let ids: Vec<String> = member_ids.into_iter().collect();
    type DevRow = (bool, bool, bool);
    let rows: Vec<DevRow> = sqlx::query_as(
        "SELECT d.browser, d.pending, EXISTS (SELECT 1 FROM device_vouches v WHERE v.device_id = d.id) \
         FROM devices d \
         WHERE d.removed_at IS NULL AND d.public_identity <> '' AND LEFT(d.public_identity, 69) = ANY($1)",
    )
    .bind(&ids)
    .fetch_all(db)
    .await?;

    for (browser, pending, has_vouch) in &rows {
        if *pending || (*browser && !*has_vouch) {
            return Err(unconfirmed_browser_device_err());
        }
    }
    if !web_secrets && rows.iter().any(|(browser, _, _)| *browser) {
        return Err(web_secrets_disabled_err());
    }
    Ok(web_secrets)
}

/// Synchronize `browser_device_rings` for one `(project_id, scope)` after `merge_ring`.
pub async fn sync_browser_rings_for_scope(
    db: &sqlx::PgPool,
    project_id: i64,
    scope: &str,
    body: &str,
) -> Result<()> {
    let Ok(ring) = serde_json::from_str::<KeyRing>(body) else {
        return Ok(());
    };
    let Ok(state) = ring.verify() else {
        return Ok(());
    };
    let active_members: Vec<String> = state.members.keys().cloned().collect();
    sqlx::query("DELETE FROM browser_device_rings WHERE project_id = $1 AND scope = $2")
        .bind(project_id)
        .bind(scope)
        .execute(db)
        .await?;
    if active_members.is_empty() {
        return Ok(());
    }
    let dev_ids: Vec<i64> = sqlx::query_scalar(
        "SELECT d.id FROM devices d \
         WHERE d.browser AND d.prf_supported AND NOT d.pending AND d.removed_at IS NULL \
         AND d.public_identity <> '' AND LEFT(d.public_identity, 69) = ANY($1) \
         AND EXISTS (SELECT 1 FROM device_vouches v WHERE v.device_id = d.id) \
         AND NOT EXISTS (SELECT 1 FROM device_bars b WHERE b.project_id = $2 AND b.device_id = d.id)",
    )
    .bind(&active_members)
    .bind(project_id)
    .fetch_all(db)
    .await?;

    for dev_id in dev_ids {
        sqlx::query(
            "INSERT INTO browser_device_rings (device_id, project_id, scope, body) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (device_id, project_id, scope) DO UPDATE SET body = EXCLUDED.body",
        )
        .bind(dev_id)
        .bind(project_id)
        .bind(scope)
        .bind(body)
        .execute(db)
        .await?;
    }
    Ok(())
}

async fn queue_project_key_requests(db: &sqlx::PgPool, project_id: i64) -> Result<()> {
    let now = veil_core::now_millis();
    sqlx::query(
        "INSERT INTO key_requests (project_id, person_id, created_at) \
         SELECT $1, person_id, $2 FROM ( \
             SELECT person_id FROM project_admins WHERE project_id = $1 \
             UNION \
             SELECT m.person_id FROM groups g JOIN group_members m ON m.group_id = g.id WHERE g.project_id = $1 \
         ) u \
         ON CONFLICT (project_id, person_id) DO UPDATE SET created_at = EXCLUDED.created_at",
    )
    .bind(project_id)
    .bind(now)
    .execute(db)
    .await?;
    Ok(())
}

async fn set_project_web_secrets(hub: &HubState, project: &Project, actor_id: i64, enabled: bool) -> Result<()> {
    sqlx::query("UPDATE projects SET web_secrets = $1 WHERE id = $2")
        .bind(enabled)
        .bind(project.id)
        .execute(&hub.db)
        .await?;
    if enabled {
        let rows: Vec<(String, String)> = sqlx::query_as("SELECT scope, body FROM rings WHERE project_id = $1")
            .bind(project.id)
            .fetch_all(&hub.db)
            .await?;
        for (scope, body) in rows {
            sync_browser_rings_for_scope(&hub.db, project.id, &scope, &body).await?;
        }
    } else {
        sqlx::query("DELETE FROM browser_device_rings WHERE project_id = $1")
            .bind(project.id)
            .execute(&hub.db)
            .await?;
    }
    queue_project_key_requests(&hub.db, project.id).await?;
    crate::audit(
        &hub.db,
        Some(project.id),
        Some(actor_id),
        "web secrets",
        if enabled { "enabled" } else { "disabled" },
    )
    .await;
    Ok(())
}

#[derive(Deserialize)]
pub struct WebSecretsToggleReq {
    pub enabled: bool,
}

/// `POST /v1/projects/{p}/web-secrets`: admin-only JSON toggle for browser secrets.
pub async fn set_web_secrets_api_route(
    State(hub): State<HubState>,
    caller: Caller,
    Path(p): Path<String>,
    Json(req): Json<WebSecretsToggleReq>,
) -> Result<Json<Value>> {
    let me = caller.person_only()?;
    let (project, viewer) = perm::open(&hub, &p, &caller).await?;
    if !viewer.admin {
        return Err(Error::forbidden("only an admin of this project may change browser secret settings"));
    }
    set_project_web_secrets(&hub, &project, me.id, req.enabled).await?;
    Ok(Json(json!({
        "project": project.name,
        "enabled": req.enabled,
    })))
}

/// `POST /p/{p}/admin/web-secrets`: admin-only HTML form toggle for browser secrets.
pub async fn admin_web_secrets_form_route(
    State(hub): State<HubState>,
    caller: Caller,
    headers: HeaderMap,
    Path(p): Path<String>,
    body: Bytes,
) -> Result<Response> {
    let me = caller.person_only()?;
    let form = parse_form(&body);
    require_current_csrf(&headers, form.get("_csrf").map(String::as_str))?;
    let (project, viewer) = perm::open(&hub, &p, &caller).await?;
    if !viewer.admin {
        return Err(Error::forbidden("only an admin of this project may change browser secret settings"));
    }
    let enabled = matches!(
        form.get("enabled").map(String::as_str),
        Some("true" | "1" | "on")
    );
    if enabled {
        let ack = matches!(
            form.get("acknowledge_limit").map(String::as_str),
            Some("true" | "1" | "on")
        );
        if !ack {
            return Err(Error::bad_request(
                "acknowledge the browser secret security limit before enabling browser secrets",
            ));
        }
    }
    set_project_web_secrets(&hub, &project, me.id, enabled).await?;
    Ok(redirect_see_other(&format!("/p/{}/admin", url_part(&project.name))))
}

#[derive(Clone, Debug)]
pub struct BrowserDeviceStatus {
    pub browser: bool,
    pub prf_supported: bool,
    pub confirmed: bool,
    pub fingerprint: Option<String>,
}

pub async fn caller_browser_device_status(db: &sqlx::PgPool, caller: &Caller) -> Result<Option<BrowserDeviceStatus>> {
    let Some(me) = &caller.person else {
        return Ok(None);
    };
    type Row = (bool, bool, bool, Option<String>, bool);
    let row: Option<Row> = sqlx::query_as(
        "SELECT d.browser, d.prf_supported, d.pending, d.fingerprint, \
         EXISTS (SELECT 1 FROM device_vouches v WHERE v.device_id = d.id) \
         FROM devices d WHERE d.signing_key = $1 AND d.removed_at IS NULL",
    )
    .bind(&me.device_key)
    .fetch_optional(db)
    .await?;
    Ok(row.map(|(browser, prf_supported, pending, fingerprint, has_vouch)| BrowserDeviceStatus {
        browser,
        prf_supported,
        confirmed: browser && prf_supported && !pending && has_vouch,
        fingerprint,
    }))
}

async fn require_confirmed_browser_device(
    db: &sqlx::PgPool,
    project_id: i64,
    caller: &Caller,
) -> Result<(i64, String)> {
    let me = caller.person_only()?;
    type Row = (i64, bool, bool, bool, String, bool, bool);
    let row: Option<Row> = sqlx::query_as(
        "SELECT d.id, d.browser, d.prf_supported, d.pending, d.public_identity, \
         EXISTS (SELECT 1 FROM device_vouches v WHERE v.device_id = d.id), \
         EXISTS (SELECT 1 FROM device_bars b WHERE b.project_id = $2 AND b.device_id = d.id) \
         FROM devices d WHERE d.signing_key = $1 AND d.removed_at IS NULL",
    )
    .bind(&me.device_key)
    .bind(project_id)
    .fetch_optional(db)
    .await?;
    let Some((dev_id, browser, prf_supported, pending, pub_id, has_vouch, barred)) = row else {
        return Err(Error::unauthorized("session expired or device removed"));
    };
    if barred {
        return Err(Error::forbidden("this browser device is barred from this project"));
    }
    if !browser {
        return Err(unconfirmed_browser_device_err());
    }
    if !prf_supported || pub_id.len() < 69 {
        return Err(Error::new(
            StatusCode::FORBIDDEN,
            NON_PRF_BROWSER_CODE,
            "this browser can't open secrets (WebAuthn PRF extension is unavailable)",
        ));
    }
    if pending || !has_vouch {
        return Err(unconfirmed_browser_device_err());
    }
    Ok((dev_id, pub_id[..69].to_string()))
}

/// `GET /v1/projects/{p}/web/rings`: return only the verified `KeyRing`s of
/// folders the signed-in person may read right now, wrapped to their confirmed
/// browser device.
pub async fn web_rings_route(
    State(hub): State<HubState>,
    caller: Caller,
    Path(p): Path<String>,
) -> Result<Json<Value>> {
    let (project, viewer) = perm::open(&hub, &p, &caller).await?;
    if !is_project_web_secrets_enabled(&hub.db, project.id).await? {
        return Err(web_secrets_disabled_err());
    }
    let (device_id, member_id) = require_confirmed_browser_device(&hub.db, project.id, &caller).await?;
    let allowed = readable_scopes(&project, &viewer);

    let team_body: Option<String> = sqlx::query_scalar("SELECT body FROM rings WHERE project_id = $1 AND scope = $2")
        .bind(project.id)
        .bind(DEFAULT_SCOPE)
        .fetch_optional(&hub.db)
        .await?;
    let proj_fp = team_body
        .as_deref()
        .and_then(|b| serde_json::from_str::<KeyRing>(b).ok())
        .and_then(|r| r.verify().ok())
        .and_then(|st| st.project)
        .map(|pid| project_fingerprint(&pid));

    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT b.scope, r.body \
         FROM browser_device_rings b \
         JOIN rings r ON r.project_id = b.project_id AND r.scope = b.scope \
         WHERE b.device_id = $1 AND b.project_id = $2 \
         ORDER BY b.scope",
    )
    .bind(device_id)
    .bind(project.id)
    .fetch_all(&hub.db)
    .await?;

    let mut out_rings = BTreeMap::new();
    for (scope, body) in rows {
        if !allowed.contains(&scope) {
            continue;
        }
        let Ok(ring) = serde_json::from_str::<KeyRing>(&body) else {
            continue;
        };
        let Ok(st) = ring.verify() else {
            continue;
        };
        if !st.members.contains_key(&member_id) {
            continue;
        }
        if let Ok(val) = serde_json::from_str::<Value>(&body) {
            out_rings.insert(scope, val);
        }
    }

    Ok(Json(json!({
        "project": project.name,
        "project_fingerprint": proj_fp,
        "rings": out_rings,
    })))
}

/// `GET /v1/projects/{p}/web/ciphertext`: serve the encrypted `Object::Sealed`
/// bytes of one readable secret file to a confirmed PRF browser device so its
/// isolated Worker can decrypt it locally. Plain `Object::Blob` files are refused.
pub async fn web_ciphertext_route(
    State(hub): State<HubState>,
    caller: Caller,
    Path(p): Path<String>,
    Query(q): Query<FileParams>,
) -> Result<Response> {
    let ask = Ask::open(&hub, &p, &caller).await?;
    if !is_project_web_secrets_enabled(&hub.db, ask.project.id).await? {
        return Err(web_secrets_disabled_err());
    }
    let (_device_id, _member_id) = require_confirmed_browser_device(&hub.db, ask.project.id, &caller).await?;
    let allowed_scopes = readable_scopes(&ask.project, &ask.viewer);

    let (meta, bytes) = query::file(&hub, &ask, q, query::Limits::default()).await?;
    if meta["sealed"].as_bool() != Some(true) || meta["encoding"].as_str() == Some("content") {
        drop(bytes);
        return Err(Error::bad_request("plain files are not sealed secrets"));
    }
    let oid = meta["id"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| ObjectId::hash(&bytes).hex());
    match Object::decode(&bytes) {
        Ok(Object::Sealed(env)) => {
            let base_scope = env.scope.split('#').next().unwrap_or(env.scope.as_str());
            if !allowed_scopes.contains(base_scope) {
                return Err(Error::not_found("no such path in this revision"));
            }
        }
        _ => {
            drop(bytes);
            return Err(Error::bad_request("object is not a sealed secret envelope"));
        }
    }

    let mut resp = (
        [(header::CONTENT_TYPE, "application/octet-stream")],
        bytes,
    )
        .into_response();
    resp.headers_mut().insert(
        header::HeaderName::from_static("x-veil-object-id"),
        HeaderValue::from_str(&oid).map_err(|e| Error::Other(e.into()))?,
    );
    attach_security_headers(&mut resp, true);
    Ok(resp)
}

async fn guard_project_worker_asset(hub: &HubState, caller: &Caller, p: &str) -> Result<String> {
    let (project, _viewer) = perm::open(hub, p, caller).await?;
    if !is_project_web_secrets_enabled(&hub.db, project.id).await? {
        return Err(web_secrets_disabled_err());
    }
    Ok(project.name)
}

/// `GET /p/{p}/web/secrets.js`: project-gated main-thread controller for "Show secret".
/// Served ONLY when `projects.web_secrets = TRUE`.
pub async fn project_secrets_js_route(
    State(hub): State<HubState>,
    caller: Caller,
    Path(p): Path<String>,
) -> Result<Response> {
    let _ = guard_project_worker_asset(&hub, &caller, &p).await?;
    let mut resp = (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        SECRETS_PAGE_JS,
    )
        .into_response();
    attach_security_headers(&mut resp, true);
    Ok(resp)
}

/// `GET /p/{p}/web/secret-worker.js`: project-gated dedicated Web Worker script.
/// Served ONLY when `projects.web_secrets = TRUE`, with its own strict Worker CSP
/// and locked-down `fetch` allowing ONLY `rings`, `ciphertext`, and `secret-worker.wasm`.
pub async fn project_secret_worker_js_route(
    State(hub): State<HubState>,
    caller: Caller,
    Path(p): Path<String>,
) -> Result<Response> {
    let _ = guard_project_worker_asset(&hub, &caller, &p).await?;
    let mut resp = (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        SECRET_WORKER_JS,
    )
        .into_response();
    attach_security_headers(&mut resp, true);
    resp.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(WORKER_CSP_HEADER),
    );
    Ok(resp)
}

/// `GET /p/{p}/web/secret-worker.wasm`: project-gated `web_secret_worker.wasm` binary.
/// Served ONLY when `projects.web_secrets = TRUE`.
pub async fn project_secret_worker_wasm_route(
    State(hub): State<HubState>,
    caller: Caller,
    Path(p): Path<String>,
) -> Result<Response> {
    let _ = guard_project_worker_asset(&hub, &caller, &p).await?;
    let candidates = [
        std::env::var_os("VEIL_WEB_SECRET_WORKER_WASM_PATH").map(std::path::PathBuf::from),
        Some(std::path::PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../target/wasm-smoke/wasm32-unknown-unknown/release/examples/web_secret_worker.wasm"
        ))),
        Some(std::path::PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../target/wasm32-unknown-unknown/release/examples/web_secret_worker.wasm"
        ))),
    ];
    for cand in candidates.into_iter().flatten() {
        if let Ok(bytes) = tokio::fs::read(&cand).await {
            let mut resp = ([(header::CONTENT_TYPE, "application/wasm")], bytes).into_response();
            attach_security_headers(&mut resp, true);
            return Ok(resp);
        }
    }
    Err(Error::not_found("secret worker WASM binary not found"))
}

const SECRETS_PAGE_JS: &str = r#"'use strict';
(function () {
  var btn = document.getElementById('veil-show-secret');
  if (!btn) return;
  var proj = btn.getAttribute('data-project') || '';
  var path = btn.getAttribute('data-path') || '';
  var rev = btn.getAttribute('data-rev') || '';
  var statusEl = document.getElementById('veil-secret-status');
  var boxEl = document.getElementById('veil-secret-plaintext');
  var hideBtn = document.getElementById('veil-hide-secret');
  var activeWorker = null;

  function b64urlDecode(s) {
    var pad = s.replace(/-/g, '+').replace(/_/g, '/');
    while (pad.length % 4) pad += '=';
    var bin = atob(pad);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function b64urlEncode(bytes) {
    var bin = '';
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function loadStoredDevice() {
    return new Promise(function (resolve, reject) {
      if (!window.indexedDB) return reject(new Error('IndexedDB unavailable'));
      var req = indexedDB.open('veil_web_devices', 1);
      req.onupgradeneeded = function () {
        var db = req.result;
        if (!db.objectStoreNames.contains('devices')) {
          db.createObjectStore('devices', { keyPath: 'credential_id' });
        }
      };
      req.onerror = function () { reject(new Error('Cannot open browser device store')); };
      req.onsuccess = function () {
        var db = req.result;
        var tx = db.transaction('devices', 'readonly');
        var all = tx.objectStore('devices').getAll();
        all.onerror = function () { reject(new Error('Cannot read browser device store')); };
        all.onsuccess = function () {
          var list = all.result || [];
          if (!list.length) return reject(new Error('No enrolled passkey device in this browser'));
          resolve(list[list.length - 1]);
        };
      };
    });
  }

  function workerUrl(u) {
    if (window.__veilTrustedScriptURL) return window.__veilTrustedScriptURL(u);
    return u;
  }

  function clearSecret() {
    if (activeWorker) {
      activeWorker.terminate();
      activeWorker = null;
    }
    if (boxEl) {
      boxEl.textContent = '';
      boxEl.hidden = true;
    }
    if (hideBtn) hideBtn.hidden = true;
    btn.hidden = false;
    if (statusEl) statusEl.textContent = '';
  }

  if (hideBtn) {
    hideBtn.addEventListener('click', clearSecret);
  }
  window.addEventListener('pagehide', clearSecret);

  btn.addEventListener('click', function () {
    if (!window.PublicKeyCredential || !navigator.credentials) {
      if (statusEl) statusEl.textContent = "This browser can't open secrets (WebAuthn PRF unavailable).";
      return;
    }
    if (statusEl) statusEl.textContent = 'Touch your passkey to unlock your browser device key…';
    loadStoredDevice().then(function (rec) {
      var saltBytes = b64urlDecode(rec.prf_salt);
      var credBytes = b64urlDecode(rec.credential_id);
      var chal = new Uint8Array(32);
      crypto.getRandomValues(chal);
      return navigator.credentials.get({
        publicKey: {
          challenge: chal,
          rpId: window.location.hostname,
          allowCredentials: [{ type: 'public-key', id: credBytes }],
          userVerification: 'required',
          extensions: { prf: { eval: { first: saltBytes } } }
        }
      }).then(function (assertion) {
        var ext = assertion.getClientExtensionResults ? assertion.getClientExtensionResults() : {};
        var first = ext && ext.prf && ext.prf.results && ext.prf.results.first;
        if (!first) {
          throw new Error("This browser can't open secrets (passkey PRF extension produced no key).");
        }
        var prfCopy = new Uint8Array(first).slice();
        return new Promise(function (resolve, reject) {
          var wUrl = '/p/' + encodeURIComponent(proj) + '/web/secret-worker.js';
          var worker = new Worker(workerUrl(wUrl));
          activeWorker = worker;
          worker.onmessage = function (ev) {
            worker.terminate();
            activeWorker = null;
            if (ev.data && ev.data.ok) resolve(ev.data);
            else reject(new Error((ev.data && ev.data.error) || 'Worker decryption failed'));
          };
          worker.onerror = function () {
            worker.terminate();
            activeWorker = null;
            reject(new Error('Secret Worker execution failed'));
          };
          worker.postMessage({
            project: proj,
            path: path,
            rev: rev,
            credential_id: b64urlEncode(new Uint8Array(assertion.rawId)),
            prf_output: prfCopy.buffer,
            sealed_identity_hex: rec.sealed_identity_hex,
            project_fingerprint: rec.project_fingerprint || ''
          }, [prfCopy.buffer]);
        });
      });
    }).then(function (opened) {
      if (boxEl) {
        boxEl.textContent = opened.text !== null && opened.text !== undefined
          ? opened.text
          : ('[binary secret: ' + opened.size + ' bytes — open with vl]');
        boxEl.hidden = false;
      }
      btn.hidden = true;
      if (hideBtn) hideBtn.hidden = false;
      if (statusEl) statusEl.textContent = 'Decrypted locally in an isolated Worker (never cached).';
    }).catch(function (err) {
      if (statusEl) statusEl.textContent = String(err.message || err);
    });
  });
})();
"#;

const SECRET_WORKER_JS: &str = r#"'use strict';
(function () {
  var rawFetch = self.fetch.bind(self);
  try { delete self.XMLHttpRequest; } catch (_) {}
  try { delete self.WebSocket; } catch (_) {}
  try { delete self.EventSource; } catch (_) {}
  try { delete self.BroadcastChannel; } catch (_) {}
  try { self.importScripts = function () { throw new Error('importScripts disabled'); }; } catch (_) {}

  function allowedWorkerPath(u) {
    return /^\/p\/[a-z0-9._-]+\/web\/secret-worker\.wasm$/.test(u)
      || /^\/v1\/projects\/[a-z0-9._-]+\/web\/rings$/.test(u)
      || /^\/v1\/projects\/[a-z0-9._-]+\/web\/ciphertext\?/.test(u);
  }

  self.fetch = function (url, opts) {
    if (typeof url !== 'string' || !allowedWorkerPath(url)) {
      return Promise.reject(new Error('Worker network access locked to rings and ciphertext'));
    }
    var method = (opts && opts.method) ? String(opts.method).toUpperCase() : 'GET';
    if (method !== 'GET' || (opts && opts.body)) {
      return Promise.reject(new Error('Worker never sends outbound request bodies'));
    }
    return rawFetch(url, { method: 'GET', credentials: 'same-origin', cache: 'no-store' });
  };

  function putBytes(ex, mem, bytes) {
    if (!bytes.length) return [0, 0];
    var ptr = ex.veil_worker_alloc(bytes.length);
    new Uint8Array(mem.buffer, ptr, bytes.length).set(bytes);
    return [ptr, bytes.length];
  }

  function putStr(ex, mem, s) {
    return putBytes(ex, mem, new TextEncoder().encode(s || ''));
  }

  function zeroAndFree(ex, mem, pair) {
    if (pair[1] > 0) {
      new Uint8Array(mem.buffer, pair[0], pair[1]).fill(0);
      ex.veil_worker_free(pair[0], pair[1]);
    }
  }

  self.onmessage = function (ev) {
    var msg = ev.data || {};
    var proj = encodeURIComponent(msg.project || '');
    var prfBytes = new Uint8Array(msg.prf_output || new ArrayBuffer(0));
    var memory = null;
    var imports = {
      env: {
        veil_now_ms: function () { return Date.now(); },
        veil_random_fill: function (ptr, len) {
          for (var off = 0; off < len; off += 65536) {
            var n = Math.min(65536, len - off);
            crypto.getRandomValues(new Uint8Array(memory.buffer, ptr + off, n));
          }
          return 0;
        }
      }
    };

    var qs = '?path=' + encodeURIComponent(msg.path || '')
      + (msg.rev ? ('&rev=' + encodeURIComponent(msg.rev)) : '');

    Promise.all([
      self.fetch('/p/' + proj + '/web/secret-worker.wasm').then(function (r) {
        if (!r.ok) throw new Error('Secret Worker WASM unavailable');
        return r.arrayBuffer();
      }),
      self.fetch('/v1/projects/' + proj + '/web/rings').then(function (r) {
        return r.json().then(function (j) {
          if (!r.ok) throw new Error(j.message || 'Cannot load key rings');
          return j;
        });
      }),
      self.fetch('/v1/projects/' + proj + '/web/ciphertext' + qs).then(function (r) {
        if (!r.ok) {
          return r.json().catch(function () { return {}; }).then(function (j) {
            throw new Error(j.message || 'Cannot load sealed ciphertext');
          });
        }
        var oid = r.headers.get('x-veil-object-id') || '';
        return r.arrayBuffer().then(function (b) { return { oid: oid, bytes: new Uint8Array(b) }; });
      })
    ]).then(function (parts) {
      return WebAssembly.instantiate(parts[0], imports).then(function (inst) {
        memory = inst.instance.exports.memory;
        var ex = inst.instance.exports;
        var ringsData = parts[1];
        var ctData = parts[2];
        var fp = msg.project_fingerprint || ringsData.project_fingerprint || '';
        var aCred = putStr(ex, memory, msg.credential_id || '');
        var aPrf = putBytes(ex, memory, prfBytes);
        prfBytes.fill(0);
        var aSeal = putStr(ex, memory, msg.sealed_identity_hex || '');
        var aRings = putStr(ex, memory, JSON.stringify(ringsData.rings || {}));
        var aFp = putStr(ex, memory, fp);
        var aOid = putStr(ex, memory, ctData.oid);
        var aCt = putBytes(ex, memory, ctData.bytes);
        var rc = ex.veil_worker_open_secret(
          aCred[0], aCred[1],
          aPrf[0], aPrf[1],
          aSeal[0], aSeal[1],
          aRings[0], aRings[1],
          aFp[0], aFp[1],
          aOid[0], aOid[1],
          aCt[0], aCt[1]
        );
        var outPtr = ex.veil_worker_out_ptr();
        var outLen = ex.veil_worker_out_len();
        var outTxt = new TextDecoder().decode(new Uint8Array(memory.buffer, outPtr, outLen));
        ex.veil_worker_clear_out();
        zeroAndFree(ex, memory, aCred);
        zeroAndFree(ex, memory, aPrf);
        zeroAndFree(ex, memory, aSeal);
        zeroAndFree(ex, memory, aRings);
        zeroAndFree(ex, memory, aFp);
        zeroAndFree(ex, memory, aOid);
        zeroAndFree(ex, memory, aCt);
        if (rc !== 0) throw new Error(outTxt);
        var parsed = JSON.parse(outTxt);
        self.postMessage({ ok: true, text: parsed.text, size: parsed.size });
      });
    }).catch(function (err) {
      prfBytes.fill(0);
      self.postMessage({ ok: false, error: String(err.message || err) });
    });
  };
})();
"#;
