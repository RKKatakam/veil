//! Safe HTML shell, strict Content-Security-Policy, URL encoding, and
//! non-leaking error pages (`docs/HUB.md` §13.39).

use std::fmt::Write as _;

use axum::{
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::Value;
use veil_core::hub::web::html_escape;

use crate::auth::SESSION_COOKIE;

pub const CSP_HEADER: &str = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'; require-trusted-types-for 'script'; trusted-types veil";

pub fn esc(s: &str) -> String {
    html_escape(s)
}

/// Percent-encode a single URL component (query value or path segment).
pub fn url_part(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => {
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

/// Percent-encode each `/`-separated segment of a repository path while preserving `/`.
pub fn url_repo_path(path: &str) -> String {
    path.split('/')
        .filter(|seg| !seg.is_empty())
        .map(url_part)
        .collect::<Vec<_>>()
        .join("/")
}

pub fn attach_security_headers(resp: &mut Response, no_store: bool) {
    let h = resp.headers_mut();
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(CSP_HEADER));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert(
        header::HeaderName::from_static("cross-origin-opener-policy"),
        HeaderValue::from_static("same-origin"),
    );
    h.insert(
        header::HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("same-origin"),
    );
    if no_store && !h.contains_key(header::CACHE_CONTROL) {
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
}

pub fn clear_session_cookie_value() -> String {
    format!("{SESSION_COOKIE}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Strict")
}

pub fn session_cookie_value(token: &str, max_age_secs: i64) -> String {
    let secs = max_age_secs.max(1);
    format!("{SESSION_COOKIE}={token}; Max-Age={secs}; Path=/; HttpOnly; Secure; SameSite=Strict")
}

pub struct PageCtx<'a> {
    pub title: &'a str,
    pub project: Option<&'a str>,
    pub active_tab: &'a str,
    pub you: Option<&'a str>,
    pub csrf: Option<&'a str>,
    pub admin_link: bool,
}

pub fn page_shell(ctx: PageCtx<'_>, body_html: &str) -> Response {
    let mut doc = String::with_capacity(body_html.len() + 1536);
    doc.push_str("<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
    doc.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    if let Some(csrf) = ctx.csrf {
        let _ = writeln!(doc, "<meta name=\"veil-csrf\" content=\"{}\">", esc(csrf));
    }
    let _ = writeln!(doc, "<title>{}</title>", esc(ctx.title));
    doc.push_str("<link rel=\"stylesheet\" href=\"/static/app.css\">\n</head>\n<body>\n");
    doc.push_str("<header class=\"topbar\">\n<div class=\"nav-tabs\">\n");
    doc.push_str("<a class=\"brand\" href=\"/\">Veil</a>\n");
    if let Some(proj) = ctx.project {
        let up = url_part(proj);
        let ep = esc(proj);
        let tabs = [
            ("overview", format!("/p/{up}"), ep),
            ("files", format!("/p/{up}/tree"), "Files".into()),
            ("commits", format!("/p/{up}/log"), "Commits".into()),
            ("search", format!("/p/{up}/search"), "Search".into()),
            ("prs", format!("/p/{up}/prs"), "Pull requests".into()),
        ];
        for (id, href, label) in tabs {
            let cls = if ctx.active_tab == id { " class=\"active\"" } else { "" };
            let _ = writeln!(doc, "<a href=\"{href}\"{cls}>{label}</a>");
        }
        if ctx.admin_link {
            let cls = if ctx.active_tab == "admin" { " class=\"active\"" } else { "" };
            let _ = writeln!(doc, "<a href=\"/p/{up}/admin\"{cls}>Groups &amp; access</a>");
        }
    }
    doc.push_str("<a href=\"/about\">About</a>\n</div>\n<div class=\"nav-tabs\">\n");
    match ctx.you {
        Some(me) => {
            let _ = writeln!(doc, "<span class=\"muted\">Signed in as <strong>{}</strong></span>", esc(me));
            if let Some(csrf) = ctx.csrf {
                let _ = writeln!(
                    doc,
                    "<form method=\"post\" action=\"/web/logout\" class=\"form-row\"><input type=\"hidden\" name=\"_csrf\" value=\"{}\"><button type=\"submit\">Sign out</button></form>",
                    esc(csrf)
                );
            }
        }
        None => {
            doc.push_str("<a class=\"btn\" href=\"/login\">Sign in</a>\n");
        }
    }
    doc.push_str("</div>\n</header>\n<main class=\"container\">\n");
    doc.push_str(body_html);
    doc.push_str("\n</main>\n<script src=\"/static/app.js\" defer></script>\n</body>\n</html>\n");

    let mut resp = (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        doc,
    )
        .into_response();
    attach_security_headers(&mut resp, true);
    resp
}

/// Render a completely static, non-leaking HTML error page: never reflects
/// unverified project names, hidden paths, PR ids, or query parameters.
pub fn error_page(status: StatusCode, code: &str, clear_cookie: bool) -> Response {
    let (title, heading, detail) = match (status, code) {
        (StatusCode::NOT_FOUND, _) => (
            "Not found — Veil",
            "Not found",
            "Nothing here that you can see.",
        ),
        (StatusCode::UNAUTHORIZED, _) => (
            "Sign in required — Veil",
            "Sign in required",
            "Please sign in to continue, or renew your expired web session.",
        ),
        (StatusCode::FORBIDDEN, "csrf_failed") => (
            "Forbidden — Veil",
            "Request refused (CSRF)",
            "Missing or invalid CSRF token, or cross-site request origin.",
        ),
        (StatusCode::FORBIDDEN, "agent_session") => (
            "Forbidden — Veil",
            "Restricted session",
            "This agent or CI runner session is not permitted to perform that action.",
        ),
        (StatusCode::FORBIDDEN, "web_session" | "sealed_file") => (
            "Forbidden — Veil",
            "Requires vl on a trusted device",
            "Secret files and device key operations are never exposed to the browser; open with vl.",
        ),
        (StatusCode::FORBIDDEN, _) => (
            "Forbidden — Veil",
            "Forbidden",
            "You do not have permission to perform that action.",
        ),
        (StatusCode::BAD_REQUEST, _) => (
            "Bad request — Veil",
            "Bad request",
            "The request parameters could not be processed.",
        ),
        (StatusCode::CONFLICT, _) => (
            "Conflict — Veil",
            "Conflict",
            "The target state changed or is not ready for this operation.",
        ),
        (StatusCode::TOO_MANY_REQUESTS, _) => (
            "Rate limited — Veil",
            "Too many requests",
            "Please wait a moment and try again.",
        ),
        (StatusCode::SERVICE_UNAVAILABLE, _) => (
            "Busy — Veil",
            "Server busy",
            "The server is temporarily busy; please try again in a few seconds.",
        ),
        _ => (
            "Error — Veil",
            "Error",
            "An internal error occurred.",
        ),
    };

    let body = format!(
        "<div class=\"card\"><div class=\"card-header\">{} <span class=\"badge\">{}</span></div><div class=\"card-body\"><p>{}</p><p><a href=\"/\">Return home</a> · <a href=\"/login\">Sign in</a></p></div></div>",
        esc(heading),
        status.as_u16(),
        esc(detail)
    );
    let mut resp = page_shell(
        PageCtx {
            title,
            project: None,
            active_tab: "",
            you: None,
            csrf: None,
            admin_link: false,
        },
        &body,
    );
    *resp.status_mut() = status;
    if clear_cookie {
        if let Ok(v) = HeaderValue::from_str(&clear_session_cookie_value()) {
            resp.headers_mut().append(header::SET_COOKIE, v);
        }
    }
    resp
}

pub fn redirect_see_other(location: &str) -> Response {
    let mut resp = StatusCode::SEE_OTHER.into_response();
    if let Ok(v) = HeaderValue::from_str(location) {
        resp.headers_mut().insert(header::LOCATION, v);
    }
    attach_security_headers(&mut resp, true);
    resp
}

/// Render projected diff JSON (`veil.diff/2`) into safe HTML cards, capping
/// total rendered lines per page so huge diffs stay bounded.
pub fn render_diff_files(diff: &Value, project: &str, rev: Option<&str>, max_total_lines: usize) -> String {
    let Some(files) = diff["files"].as_array() else {
        return "<p class=\"muted\">No file changes.</p>".to_string();
    };
    if files.is_empty() {
        return "<p class=\"muted\">No visible file changes.</p>".to_string();
    }
    let up = url_part(project);
    let rev_q = rev.map(|r| format!("?rev={}", url_part(r))).unwrap_or_default();
    let mut out = String::new();
    let mut rendered_lines = 0usize;

    for f in files {
        let path = f["path"].as_str().unwrap_or("");
        let status = f["status"].as_str().unwrap_or("modified");
        let old_sealed = f["old"]["sealed"].as_bool() == Some(true);
        let new_sealed = f["new"]["sealed"].as_bool() == Some(true);
        let hidden_sealed = f["content"]["hidden"].as_str() == Some("sealed");
        let is_sealed = old_sealed || new_sealed || hidden_sealed;

        out.push_str("<div class=\"card\"><div class=\"card-header\"><span class=\"mono\">");
        if status != "deleted" {
            let _ = write!(
                out,
                "<a href=\"/p/{up}/file/{}{rev_q}\">{}</a>",
                url_repo_path(path),
                esc(path)
            );
        } else {
            out.push_str(&esc(path));
        }
        out.push_str("</span><span>");
        let _ = write!(out, "<span class=\"badge\">{}</span> ", esc(status));
        if is_sealed {
            out.push_str("<span class=\"badge badge-sealed\">sealed</span>");
        }
        out.push_str("</span></div><div class=\"card-body\">");

        if is_sealed {
            out.push_str("<p class=\"muted\">Sealed secret file — open with <code>vl</code>. Secret bytes never reach the browser.</p>");
        } else if f["content"]["binary"].as_bool() == Some(true) {
            out.push_str("<p class=\"muted\">Binary or non-plain-text object — open file to inspect metadata.</p>");
        } else if f["content"]["too_large"].as_bool() == Some(true) || f["content"]["omitted"].as_bool() == Some(true) {
            out.push_str("<p class=\"muted\">Diff omitted due to size bound — view the file directly.</p>");
        } else if let Some(hunks) = f["content"]["hunks"].as_array() {
            if rendered_lines >= max_total_lines {
                out.push_str("<p class=\"muted\">Remaining diff hunks omitted for page size bound.</p>");
            } else if hunks.is_empty() {
                out.push_str("<p class=\"muted\">Empty or mode-only change.</p>");
            } else {
                out.push_str("<table class=\"code-table mono\"><tbody>");
                for h in hunks {
                    let os = h["old_start"].as_u64().unwrap_or(0);
                    let ol = h["old_lines"].as_u64().unwrap_or(0);
                    let ns = h["new_start"].as_u64().unwrap_or(0);
                    let nl = h["new_lines"].as_u64().unwrap_or(0);
                    let _ = writeln!(
                        out,
                        "<tr><td class=\"ln\">@@</td><td class=\"muted\">-{os},{ol} +{ns},{nl} @@</td></tr>"
                    );
                    if let Some(lines) = h["lines"].as_array() {
                        for l in lines {
                            if rendered_lines >= max_total_lines {
                                out.push_str("<tr><td class=\"ln\">…</td><td class=\"muted\">Diff truncated at page bound.</td></tr>");
                                break;
                            }
                            let text = l.as_str().unwrap_or("");
                            let row_cls = if text.starts_with('+') {
                                " class=\"diff-add\""
                            } else if text.starts_with('-') {
                                " class=\"diff-del\""
                            } else {
                                ""
                            };
                            let _ = writeln!(out, "<tr{row_cls}><td class=\"ln\"></td><td>{}</td></tr>", esc(text));
                            rendered_lines += 1;
                        }
                    }
                    if rendered_lines >= max_total_lines {
                        break;
                    }
                }
                out.push_str("</tbody></table>");
            }
        }
        out.push_str("</div></div>");
    }

    if diff["truncated"].as_bool() == Some(true) || diff["content_truncated"].as_bool() == Some(true) {
        out.push_str("<p class=\"muted\">Diff list truncated to stay within page bounds.</p>");
    }
    out
}
