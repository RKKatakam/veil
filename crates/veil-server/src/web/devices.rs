//! "Your devices" (`GET /devices`) and removing a browser
//! (`POST /web/devices/remove`), `docs/HUB.md` §13.40.
//!
//! Every passkey signs in to the web client as its person, so every one is
//! listed here with the person's `vl` devices, and removed here or with `vl
//! identity remove` (BUG-1901). "Sign out" ends a session and nothing else;
//! removing a browser is this separate action, named "Remove this browser"
//! for the browser the session is in (BUG-1905). It does what removing any
//! device does (`api::remove_own_device`): the device and its passkey no
//! longer sign in, its sessions end, the server deletes the wrapped keys it
//! kept for it, and the person's projects rotate their keys away from it.
//!
//! The web client removes browsers only: a `vl` device is removed with `vl
//! identity remove`, where its key rings are (S25: no device management for
//! a web session but this removal of its person's own passkeys).

use std::fmt::Write as _;

use axum::{
    body::Bytes,
    extract::State,
    http::{header, HeaderMap, HeaderValue},
    response::Response,
};

use crate::{
    auth::Caller,
    error::{Error, Result},
    web::{
        html::{clear_session_cookie_value, esc, page_shell, redirect_see_other, PageCtx},
        session::{current_csrf, parse_form, require_current_csrf},
    },
    HubState,
};

/// The most devices of one kind the page lists (a person's own browsers; a
/// stranger makes none: an enrollment needs the person's `vl web` code).
const LISTED: i64 = 200;

/// `GET /devices`: the signed-in person's devices and passkeys.
pub async fn devices_page_route(State(hub): State<HubState>, caller: Caller) -> Result<Response> {
    let me = caller.person_only()?.clone();
    let csrf = current_csrf();
    type Row = (String, Option<String>, bool, bool, bool, Option<String>, Option<String>, Option<i64>, String);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT d.signing_key, d.fingerprint, d.browser, d.prf_supported, d.pending, w.credential_id, w.label, w.created_at, d.public_identity \
         FROM devices d LEFT JOIN webauthn_credentials w ON w.device_id = d.id \
         WHERE d.person_id = $1 AND d.removed_at IS NULL AND (d.browser OR NOT d.pending) ORDER BY d.browser DESC, d.id LIMIT $2",
    )
    .bind(me.id)
    .bind(2 * LISTED)
    .fetch_all(&hub.db)
    .await?;
    // Anyone can sign in under a taken name (a pending device): the newest few.
    let waiting: Vec<Option<String>> = sqlx::query_scalar(
        "SELECT fingerprint FROM devices WHERE person_id = $1 AND removed_at IS NULL AND pending AND NOT browser ORDER BY id DESC LIMIT $2",
    )
    .bind(me.id)
    .bind(crate::auth::LISTED_PENDING)
    .fetch_all(&hub.db)
    .await?;

    let mut body = String::new();
    body.push_str("<div class=\"card\"><div class=\"card-header\">Your devices</div><div class=\"card-body\">");
    body.push_str("<p class=\"muted\">Everything that signs in as you. <strong>Sign out</strong> ends this session only: this browser and its passkey stay enrolled, and the next visit signs in with the passkey. <strong>Remove</strong> a browser you no longer use or have lost: its passkey no longer signs in, the server deletes the wrapped secret keys it kept for it, and your projects rotate their secret keys away from it.</p>");

    body.push_str("<h3>Browsers (passkeys)</h3>");
    let browsers: Vec<&Row> = rows.iter().filter(|r| r.2).collect();
    if browsers.is_empty() {
        body.push_str("<p class=\"muted\">No browser is enrolled. Run <code>vl web</code> on a computer where you are signed in.</p>");
    } else {
        body.push_str("<table class=\"listing\"><tbody>");
        for (key, fingerprint, _, prf, pending, credential, label, enrolled, _) in browsers {
            let fp = fingerprint.as_deref().unwrap_or_default();
            let this = *key == me.device_key;
            let state = match (prf, pending) {
                (false, _) => "signs in; cannot open secrets".to_string(),
                (true, true) => format!("signs in; waits for <code>vl identity confirm {}</code> to open secrets", esc(fp)),
                (true, false) => "signs in; confirmed to open secrets".to_string(),
            };
            let _ = write!(
                body,
                "<tr><td><code>{}</code>{}</td><td>{}</td><td class=\"muted\">enrolled {}</td><td class=\"muted\">{state}</td><td>",
                esc(fp),
                if this { " <strong>(this browser)</strong>" } else { "" },
                esc(label.as_deref().unwrap_or("")),
                day(enrolled.unwrap_or_default()),
            );
            if let Some(csrf) = &csrf {
                let _ = write!(
                    body,
                    "<form method=\"post\" action=\"/web/devices/remove\" class=\"form-row veil-remove-browser\" data-credential=\"{}\"><input type=\"hidden\" name=\"_csrf\" value=\"{}\"><input type=\"hidden\" name=\"fingerprint\" value=\"{}\"><button type=\"submit\">{}</button></form>",
                    esc(credential.as_deref().unwrap_or_default()),
                    esc(csrf),
                    esc(fp),
                    if this { "Remove this browser" } else { "Remove" },
                );
            }
            body.push_str("</td></tr>");
        }
        body.push_str("</tbody></table>");
    }

    body.push_str("<h3><code>vl</code> devices</h3><table class=\"listing\"><tbody>");
    for (key, .., identity) in rows.iter().filter(|r| !r.2) {
        // (The stored fingerprint is only of devices that waited to be confirmed.)
        let fingerprint = veil_core::identity::parse_public_identity(identity).ok().and_then(|i| veil_core::hub::wire::device_fingerprint(&i));
        let _ = write!(
            body,
            "<tr><td><code>{}</code>{}</td><td class=\"muted\">signed in with <code>vl login</code></td></tr>",
            esc(fingerprint.as_deref().unwrap_or("(no fingerprint)")),
            if *key == me.device_key { " <strong>(the device this session came from)</strong>" } else { "" },
        );
    }
    for fingerprint in waiting.iter().flatten() {
        let _ = write!(
            body,
            "<tr><td><code>{}</code></td><td class=\"muted\">signed in under your name; waits for <code>vl identity confirm</code> (confirm only a device of yours)</td></tr>",
            esc(fingerprint),
        );
    }
    body.push_str("</tbody></table>");
    body.push_str("<p class=\"muted\">Remove a <code>vl</code> device (a lost laptop) with <code>vl identity remove FINGERPRINT</code> on another of your devices; <code>vl identity list</code> shows this list too.</p>");
    body.push_str("</div></div>");

    Ok(page_shell(
        PageCtx {
            title: "Your devices — Veil",
            project: None,
            active_tab: "",
            you: Some(&me.name),
            csrf: csrf.as_deref(),
            admin_link: false,
        },
        &body,
    ))
}

/// `2026-11-11` of Unix milliseconds (UTC).
fn day(ms: i64) -> String {
    // Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
    let z = ms.div_euclid(86_400_000) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let (d, m) = (doy - (153 * mp + 2) / 5 + 1, if mp < 10 { mp + 3 } else { mp - 9 });
    format!("{:04}-{m:02}-{d:02}", yoe + era * 400 + i64::from(m <= 2))
}

/// `POST /web/devices/remove` (same origin, CSRF): remove one of the
/// signed-in person's own browsers, by its fingerprint. Removing the browser
/// the session is in ("Remove this browser") also clears its cookie.
pub async fn remove_browser_route(State(hub): State<HubState>, caller: Caller, headers: HeaderMap, body: Bytes) -> Result<Response> {
    let me = caller.person_only()?.clone();
    let form = parse_form(&body);
    require_current_csrf(&headers, form.get("_csrf").map(String::as_str))?;
    let fingerprint = form
        .get("fingerprint")
        .and_then(|f| veil_core::hub::wire::normalize_fingerprint(f))
        .ok_or_else(|| Error::bad_request("not a device fingerprint"))?;
    let (person, fp) = (me.id, fingerprint.clone());
    let key: String = crate::db::serializable(&hub.db, move |c| {
        let fp = fp.clone();
        Box::pin(async move {
            let found: Option<(i64, String)> = sqlx::query_as(
                "SELECT id, signing_key FROM devices WHERE person_id = $1 AND browser AND fingerprint = $2 AND removed_at IS NULL ORDER BY id LIMIT 1",
            )
            .bind(person)
            .bind(&fp)
            .fetch_optional(&mut *c)
            .await?;
            let Some((id, key)) = found else {
                return Err(Error::not_found("no such browser of yours"));
            };
            crate::api::remove_own_device(c, id).await?;
            Ok(key)
        })
    })
    .await?;
    crate::api::queue_key_requests_for_person(&hub.db, me.id).await?;
    crate::audit(&hub.db, None, Some(me.id), "remove browser device", &format!("{} ({}): {fingerprint}", me.name, me.id)).await;

    if key != me.device_key {
        return Ok(redirect_see_other("/devices"));
    }
    let mut resp = redirect_see_other("/login");
    resp.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&clear_session_cookie_value()).map_err(|e| Error::Other(e.into()))?,
    );
    Ok(resp)
}

#[cfg(test)]
mod tests {
    #[test]
    fn day_is_the_utc_date() {
        assert_eq!(super::day(0), "1970-01-01");
        assert_eq!(super::day(951_782_400_000), "2000-02-29");
        assert_eq!(super::day(1_794_355_200_000), "2026-11-11");
        assert_eq!(super::day(1_794_441_599_999), "2026-11-11");
    }
}
