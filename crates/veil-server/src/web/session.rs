//! Browser session lifecycle (`__Host-veil_session`), per-session CSRF
//! verification, same-origin enforcement, and request context (`docs/HUB.md` §13.39).

use std::cell::RefCell;

use axum::{
    body::Bytes,
    extract::{Request, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;
use veil_core::hub::{
    web::{csrf_for_session, csrf_matches, web_token_hash, MAX_WEB_SESSION_MS, WEB_TOKEN_PREFIX},
    wire::LoginRequest,
};

use crate::{
    auth::{self, CSRF_FAILED},
    error::{Error, Result},
    web::html::{self, attach_security_headers, clear_session_cookie_value, esc, page_shell, redirect_see_other, session_cookie_value, PageCtx},
    HubState,
};

#[derive(Clone, Debug, Default)]
pub struct WebCtx {
    pub is_web: bool,
    pub from_cookie: bool,
    pub session_hash: Option<String>,
}

tokio::task_local! {
    static WEB_CTX: RefCell<WebCtx>;
}

pub fn current_is_web() -> bool {
    WEB_CTX.try_with(|c| c.borrow().is_web).unwrap_or(false)
}

pub fn current_csrf() -> Option<String> {
    WEB_CTX
        .try_with(|c| c.borrow().session_hash.as_deref().map(csrf_for_session))
        .ok()
        .flatten()
}

pub fn record_session(hash: String, from_cookie: bool, web_token: bool) {
    let _ = WEB_CTX.try_with(|c| {
        let mut ctx = c.borrow_mut();
        if from_cookie || web_token {
            ctx.is_web = true;
        }
        ctx.from_cookie = from_cookie;
        ctx.session_hash = Some(hash);
    });
}

fn normal_host(h: &str) -> String {
    h.trim().trim_end_matches(":443").to_ascii_lowercase()
}

fn csrf_err(msg: &'static str) -> Error {
    Error::new(StatusCode::FORBIDDEN, CSRF_FAILED, msg)
}

/// Verify that a state-changing browser request comes from the same origin.
pub fn check_same_origin(headers: &HeaderMap) -> Result<()> {
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(normal_host)
        .unwrap_or_default();

    let mut verified = false;
    if let Some(sfs) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        if !sfs.eq_ignore_ascii_case("same-origin") {
            return Err(csrf_err("cross-site request refused"));
        }
        verified = true;
    }

    if let Some(orig) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        let orig_host = orig
            .strip_prefix("https://")
            .or_else(|| orig.strip_prefix("http://"))
            .unwrap_or("");
        if orig_host.is_empty() || orig_host.contains('/') || host.is_empty() || normal_host(orig_host) != host {
            return Err(csrf_err("request Origin does not match Host"));
        }
        verified = true;
    }

    if !verified {
        return Err(csrf_err("missing Origin or Sec-Fetch-Site header on state-changing request"));
    }
    Ok(())
}

/// Verify both same-origin headers and the session-bound CSRF token.
pub fn require_csrf(headers: &HeaderMap, session_hash: Option<&str>, form_csrf: Option<&str>) -> Result<()> {
    check_same_origin(headers)?;
    let Some(hash) = session_hash else {
        return Err(csrf_err("missing session for CSRF verification"));
    };
    let provided = headers
        .get("x-veil-csrf")
        .and_then(|v| v.to_str().ok())
        .or(form_csrf)
        .unwrap_or("");
    if provided.is_empty() || !csrf_matches(hash, provided) {
        return Err(csrf_err("missing or invalid CSRF token"));
    }
    Ok(())
}

pub fn require_current_csrf(headers: &HeaderMap, form_csrf: Option<&str>) -> Result<()> {
    let hash = WEB_CTX.try_with(|c| c.borrow().session_hash.clone()).ok().flatten();
    require_csrf(headers, hash.as_deref(), form_csrf)
}

/// Router middleware: tracks browser/web context per request, attaches CSP &
/// security headers, and renders static non-leaking HTML error pages on web UI routes.
pub async fn layer(req: Request, next: Next) -> Response {
    let path = req.uri().path().to_string();
    let is_api = path.starts_with("/v1/");
    let wants_json = is_api
        || (path.starts_with("/web/")
            && req
                .headers()
                .get(header::ACCEPT)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|a| a.contains("application/json")));
    let had_cookie = auth::cookie_token(req.headers()).is_some();
    let init = WebCtx {
        is_web: !is_api || auth::has_browser_or_web_headers(req.headers()),
        from_cookie: false,
        session_hash: None,
    };

    let mut resp = WEB_CTX.scope(RefCell::new(init), next.run(req)).await;

    if !wants_json && (resp.status().is_client_error() || resp.status().is_server_error()) {
        let already_html = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|ct| ct.starts_with("text/html"));
        if !already_html {
            let status = resp.status();
            let body_bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap_or_default();
            let code = serde_json::from_slice::<serde_json::Value>(&body_bytes)
                .ok()
                .and_then(|v| v["code"].as_str().map(str::to_string))
                .unwrap_or_default();
            return html::error_page(status, &code, status == StatusCode::UNAUTHORIZED && had_cookie);
        }
    }

    if !is_api {
        let is_static = path.starts_with("/static/");
        attach_security_headers(&mut resp, !is_static);
    } else {
        resp.headers_mut()
            .insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    }
    resp
}

fn decode_form_component(raw: &[u8]) -> String {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        match raw[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < raw.len() => {
                if let (Ok(s), Some(b)) = (
                    std::str::from_utf8(&raw[i + 1..i + 3]),
                    std::str::from_utf8(&raw[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok()),
                ) {
                    let _ = s;
                    out.push(b);
                    i += 3;
                } else {
                    out.push(raw[i]);
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn parse_form(bytes: &[u8]) -> std::collections::BTreeMap<String, String> {
    let mut map = std::collections::BTreeMap::new();
    for pair in bytes.split(|&b| b == b'&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.iter().position(|&b| b == b'=') {
            Some(pos) => (&pair[..pos], &pair[pos + 1..]),
            None => (pair, &[][..]),
        };
        map.insert(decode_form_component(k), decode_form_component(v));
    }
    map
}

pub async fn login_page_route() -> Response {
    let body = r#"<div class="card">
  <div class="card-header">Sign in to Veil</div>
  <div class="card-body">
    <p>Sign in with a short-lived web session derived from your <code>vl</code> device session, or sign a single-use challenge in browser memory with your device identity.</p>
    <p class="muted">Secret files (<code>.env</code>, keys) are never decrypted or served in the browser — open them locally with <code>vl</code>.</p>
    <h3>Option 1: Short-lived web token</h3>
    <form method="post" action="/web/session">
      <div class="form-row">
        <input type="text" name="token" placeholder="web-…" autocomplete="off" required>
        <button type="submit">Activate web session</button>
      </div>
    </form>
    <h3>Option 2: Device-signed challenge (in-memory WASM)</h3>
    <form id="veil-device-login-form">
      <textarea id="veil-identity-json" placeholder="Paste device identity JSON (kept in WASM memory only, never sent over the network)"></textarea>
      <div class="form-row">
        <button type="submit">Sign challenge &amp; sign in</button>
        <span id="veil-login-status" class="muted"></span>
      </div>
    </form>
  </div>
</div>"#;
    page_shell(
        PageCtx {
            title: "Sign in — Veil",
            project: None,
            active_tab: "",
            you: None,
            csrf: None,
            admin_link: false,
        },
        body,
    )
}

#[derive(Deserialize)]
struct AdoptInput {
    token: String,
}

/// `POST /web/session`: validate a short-lived `web-` token and set
/// `__Host-veil_session` (`HttpOnly; Secure; SameSite=Strict`).
pub async fn adopt_session_route(State(hub): State<HubState>, headers: HeaderMap, body: Bytes) -> Result<Response> {
    check_same_origin(&headers)?;
    let ct = headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");
    let token = if ct.contains("application/json") {
        serde_json::from_slice::<AdoptInput>(&body)
            .map_err(|_| Error::bad_request("invalid JSON body"))?
            .token
    } else {
        parse_form(&body)
            .remove("token")
            .ok_or_else(|| Error::bad_request("missing token"))?
    };
    let token = token.trim();
    if !token.starts_with(WEB_TOKEN_PREFIX) {
        return Err(Error::bad_request("only short-lived web- tokens can be used in the browser"));
    }
    let hash = web_token_hash(token);
    let now = veil_core::now_millis();
    let row: Option<(String, i64)> = sqlx::query_as(
        "SELECT p.name, s.expires_at FROM sessions s \
         JOIN devices d ON d.id = s.device_id \
         JOIN people p ON p.id = s.person_id \
         LEFT JOIN sessions par ON par.token_hash = s.parent_hash \
         WHERE s.token_hash = $1 AND s.expires_at > $2 AND s.agent IS NULL \
         AND d.removed_at IS NULL AND NOT d.pending \
         AND (s.parent_hash IS NULL OR par.expires_at > $2)",
    )
    .bind(&hash)
    .bind(now)
    .fetch_optional(&hub.db)
    .await?;

    let Some((person, expires_at)) = row else {
        return Err(Error::unauthorized("web session expired or unknown"));
    };
    let max_age = ((expires_at - now) / 1000).max(1);
    let cookie = session_cookie_value(token, max_age);
    let csrf = csrf_for_session(&hash);
    let wants_json = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|a| a.contains("application/json"));

    let mut resp = if wants_json {
        Json(json!({ "person": person, "expires_at": expires_at, "csrf": csrf })).into_response()
    } else {
        redirect_see_other("/")
    };
    resp.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).map_err(|e| Error::Other(e.into()))?,
    );
    attach_security_headers(&mut resp, true);
    Ok(resp)
}

/// `POST /web/login`: verify a single-use `hub-login` signature and issue a
/// short-lived `web-` session directly into `__Host-veil_session`.
pub async fn device_login_route(State(hub): State<HubState>, headers: HeaderMap, Json(req): Json<LoginRequest>) -> Result<Response> {
    check_same_origin(&headers)?;
    let (token, person, expires_at, csrf) = auth::login_web_direct(&hub, &headers, req, MAX_WEB_SESSION_MS).await?;
    let now = veil_core::now_millis();
    let max_age = ((expires_at - now) / 1000).max(1);
    let cookie = session_cookie_value(&token, max_age);
    let mut resp = Json(json!({
        "person": person,
        "expires_at": expires_at,
        "csrf": csrf,
    }))
    .into_response();
    resp.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).map_err(|e| Error::Other(e.into()))?,
    );
    attach_security_headers(&mut resp, true);
    Ok(resp)
}

/// `POST /web/logout`: verify same-origin + CSRF, delete the session row in
/// PostgreSQL (bumping `access_epochs` across all servers immediately), and
/// clear `__Host-veil_session`.
pub async fn logout_route(State(hub): State<HubState>, headers: HeaderMap, body: Bytes) -> Result<Response> {
    let tok = auth::cookie_token(&headers).ok_or_else(|| Error::unauthorized("not signed in"))?;
    let hash = auth::session_hash(tok);
    let form = parse_form(&body);
    require_csrf(&headers, Some(&hash), form.get("_csrf").map(String::as_str))?;

    sqlx::query("DELETE FROM sessions WHERE token_hash = $1")
        .bind(&hash)
        .execute(&hub.db)
        .await?;

    let mut resp = redirect_see_other("/");
    resp.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&clear_session_cookie_value()).map_err(|e| Error::Other(e.into()))?,
    );
    let _ = esc;
    Ok(resp)
}
