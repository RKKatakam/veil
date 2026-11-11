//! S25: The Veil web client, first version, with no secrets (`docs/HUB.md` §13.39).
//!
//! Serves a lightweight server-rendered + progressive-enhancement browser UI at
//! `/` over the existing S13–S15 query, S21 PR, and S1 group handlers under the
//! caller's session. Secret files show as sealed (`open with vl`) and their
//! bytes never reach the browser by any route.

pub mod assets;
pub mod html;
pub mod session;

use std::fmt::Write as _;

use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::Value;
use veil_core::hub::wire::GroupChange;

pub use assets::static_route;
pub use session::{
    adopt_session_route, check_same_origin, current_csrf, current_is_web, device_login_route, layer, login_page_route, logout_route,
    record_session, require_csrf,
};

use crate::{
    auth::Caller,
    error::{Error, Result},
    perm,
    prs::{self, CreatePr, DismissRequest, ListParams, NewThread, PrDiffParams, ThreadUpdate},
    query::{self, Ask, BlameParams, FileParams, HistoryParams, LogParams, ShowParams, TreeParams},
    search::{self, GrepParams, SearchParams},
    sync,
    web::{
        html::{esc, page_shell, redirect_see_other, render_diff_files, url_part, url_repo_path, PageCtx},
        session::{parse_form, require_current_csrf},
    },
    HubState,
};

pub const WEB_FILE_LINES_PER_PAGE: usize = 200;
pub const WEB_FILE_BYTES_PER_PAGE: usize = 60 * 1024;
pub const WEB_TREE_PAGE: usize = 100;
pub const WEB_LOG_PAGE: usize = 50;
pub const WEB_BLAME_PAGE: usize = 200;
pub const WEB_SEARCH_PAGE: usize = 25;
pub const WEB_PRS_PAGE: i64 = 25;
pub const WEB_DIFF_MAX_LINES: usize = 500;

pub const SEALED_FILE_CODE: &str = "sealed_file";

fn you_name(caller: &Caller) -> Option<&str> {
    caller.person.as_ref().map(|p| p.name.as_str())
}

fn can_admin_tab(caller: &Caller, ask: &Ask) -> bool {
    caller.person.as_ref().is_some_and(|p| p.agent.is_none()) && ask.project.participant(&ask.viewer)
}

fn format_breadcrumbs(project: &str, path: &str, rev: Option<&str>, leaf_is_file: bool) -> String {
    let up = url_part(project);
    let rq = rev.map(|r| format!("?rev={}", url_part(r))).unwrap_or_default();
    let mut out = format!("<a href=\"/p/{up}/tree{rq}\">{}</a>", esc(project));
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let mut acc = String::new();
    for (i, seg) in segs.iter().enumerate() {
        if !acc.is_empty() {
            acc.push('/');
        }
        acc.push_str(seg);
        out.push_str(" / ");
        if i + 1 == segs.len() && leaf_is_file {
            let _ = write!(out, "<strong>{}</strong>", esc(seg));
        } else {
            let _ = write!(out, "<a href=\"/p/{up}/tree/{}{rq}\">{}</a>", url_repo_path(&acc), esc(seg));
        }
    }
    out
}

/// Guarded `/v1/projects/{p}/q/file`: refuses sealed or non-plain-blob objects
/// to every web/browser caller (`403 sealed_file`), while leaving `vl` CLI
/// device calls unchanged.
pub async fn guarded_file_route(
    State(hub): State<HubState>,
    caller: Caller,
    Path(p): Path<String>,
    Query(q): Query<FileParams>,
) -> Result<Response> {
    if caller.is_web() {
        let ask = Ask::open(&hub, &p, &caller).await?;
        let (meta, bytes) = query::file(&hub, &ask, q, query::Limits::default()).await?;
        if meta["sealed"].as_bool() == Some(true) || meta["encoding"].as_str() != Some("content") {
            drop(bytes);
            return Err(Error::new(
                StatusCode::FORBIDDEN,
                SEALED_FILE_CODE,
                "sealed secret files are never served to the web client; open with vl",
            ));
        }
        return Ok((
            [(header::CONTENT_TYPE, "application/octet-stream".to_string())],
            bytes,
        )
            .into_response());
    }
    query::file_route(State(hub), caller, Path(p), Query(q)).await
}

/// `GET /`: home page. Never enumerates projects across the database (matching
/// the API, which has no global project list).
pub async fn home_route(caller: Caller) -> Result<Response> {
    let csrf = current_csrf();
    let mut body = String::new();
    body.push_str("<div class=\"card\"><div class=\"card-header\">Veil Hub</div><div class=\"card-body\">");
    body.push_str("<p>Server-centric version control with path-scoped visibility and end-to-end sealed secrets.</p>");
    body.push_str("<form id=\"veil-goto-project\" method=\"get\" action=\"/\"><div class=\"form-row\">");
    body.push_str("<label for=\"veil-project-input\">Open project:</label>");
    body.push_str("<input id=\"veil-project-input\" type=\"text\" placeholder=\"project-name\" autocomplete=\"off\">");
    body.push_str("<button type=\"submit\">Go</button></div></form>");
    body.push_str("<p class=\"muted\">Enter the exact name of a project you participate in or that publishes public folders. Secret files remain sealed on your devices — open them with <code>vl</code>.</p>");
    body.push_str("</div></div>");

    Ok(page_shell(
        PageCtx {
            title: "Veil",
            project: None,
            active_tab: "",
            you: you_name(&caller),
            csrf: csrf.as_deref(),
            admin_link: false,
        },
        &body,
    ))
}

/// `GET /about`: About Veil (includes credit to okpom from README).
pub async fn about_route(caller: Caller) -> Result<Response> {
    let csrf = current_csrf();
    let body = r#"<div class="card">
  <div class="card-header">About Veil</div>
  <div class="card-body">
    <p>Veil is a server-centric version control system where visibility is private by default, folder access is enforced by the Hub, and secret files (<code>.env</code>, keys) are encrypted end-to-end on trusted devices.</p>
    <p>In this web client, you see exactly what your account (or anonymous public access) is permitted to see. Sealed secret files are shown as sealed and their bytes never reach the browser; use <code>vl</code> locally to read or edit secrets.</p>
    <p>Thanks to okpom, who helped with the idea for Veil.</p>
  </div>
</div>"#;
    Ok(page_shell(
        PageCtx {
            title: "About — Veil",
            project: None,
            active_tab: "",
            you: you_name(&caller),
            csrf: csrf.as_deref(),
            admin_link: false,
        },
        body,
    ))
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct RevQuery {
    pub rev: Option<String>,
    pub after: Option<String>,
    pub page: Option<usize>,
    pub path: Option<String>,
}

/// `GET /p/{p}`: Project overview (branches, root tree or narrowed paths,
/// recent commits, open PRs).
pub async fn project_overview_route(
    State(hub): State<HubState>,
    caller: Caller,
    Path(p): Path<String>,
    Query(q): Query<RevQuery>,
) -> Result<Response> {
    let ask = Ask::open(&hub, &p, &caller).await?;
    let csrf = current_csrf();
    let pname = &ask.project.name;
    let up = url_part(pname);
    let rev = q.rev.as_deref().unwrap_or(&ask.project.default_branch);

    let branches = sync::tips(&hub, &ask.project, &ask.viewer).await?;
    let tested = crate::ci::all_tested_for(&hub, &ask.project, &ask.viewer).await?;
    let embargoes = crate::embargo::embargoes_for(&hub, &ask.project, &ask.viewer).await?;

    let mut body = String::new();

    // Branches card
    body.push_str("<div class=\"card\"><div class=\"card-header\"><span>Branches</span>");
    let _ = write!(body, "<span class=\"muted\">default: <code>{}</code></span></div><div class=\"card-body\">", esc(&ask.project.default_branch));
    if branches.is_empty() {
        body.push_str("<p class=\"muted\">No visible branches yet.</p>");
    } else {
        body.push_str("<div class=\"form-row\">");
        for (br, oid) in &branches {
            let short = &oid.hex()[..8];
            let ci_mark = if tested.get(br) == Some(oid) { " ✓" } else { "" };
            let _ = write!(
                body,
                "<a class=\"badge\" href=\"/p/{up}?rev={}\">{}{} ({})</a> ",
                url_part(br),
                esc(br),
                ci_mark,
                esc(short)
            );
        }
        body.push_str("</div>");
    }
    if !embargoes.is_empty() {
        body.push_str("<p class=\"muted\">Active embargoes visible to you: ");
        for (i, e) in embargoes.iter().enumerate() {
            if i > 0 {
                body.push_str(", ");
            }
            let _ = write!(body, "<code>{}</code> (scope <code>{}</code>)", esc(&e.id), esc(&e.scope));
        }
        body.push_str("</p>");
    }
    body.push_str("</div></div>");

    // Tree or narrowed paths card
    if let Some(only) = &ask.viewer.only {
        body.push_str("<div class=\"card\"><div class=\"card-header\">Narrowed session paths</div><div class=\"card-body\"><ul>");
        for prefix in only.iter() {
            let _ = writeln!(
                body,
                "<li><a class=\"mono\" href=\"/p/{up}/tree/{}?rev={}\">{}</a></li>",
                url_repo_path(prefix),
                url_part(rev),
                esc(prefix)
            );
        }
        body.push_str("</ul></div></div>");
    } else if !branches.is_empty() {
        let lim = query::Limits { list: 25, ..Default::default() };
        if let Ok(tr) = query::tree(
            &hub,
            &ask,
            TreeParams {
                rev: Some(rev.to_string()),
                path: None,
                after: None,
            },
            lim,
        )
        .await
        {
            body.push_str("<div class=\"card\"><div class=\"card-header\"><span>Files</span>");
            let _ = write!(body, "<a href=\"/p/{up}/tree?rev={}\">Full tree →</a></div>", url_part(rev));
            body.push_str(&render_tree_table(&tr, pname, "", Some(rev)));
            body.push_str("</div>");
        }
    }

    // Recent commits
    if !branches.is_empty() {
        let log_path = ask.viewer.only.as_ref().and_then(|o| (o.len() == 1).then(|| o[0].clone()));
        if let Ok(lg) = query::log(
            &hub,
            &ask,
            LogParams {
                rev: Some(rev.to_string()),
                n: Some(10),
                path: log_path,
                after: None,
            },
            query::Limits::default(),
        )
        .await
        {
            body.push_str("<div class=\"card\"><div class=\"card-header\"><span>Recent commits</span>");
            let _ = write!(body, "<a href=\"/p/{up}/log?rev={}\">All commits →</a></div>", url_part(rev));
            body.push_str(&render_log_table(&lg, pname));
            body.push_str("</div>");
        }
    }

    // Open PRs summary
    if let Ok(prs_val) = prs::list(
        &hub,
        &ask,
        ListParams {
            state: Some("open".into()),
            q: None,
            n: Some(5),
            after: None,
        },
    )
    .await
    {
        if let Some(arr) = prs_val["prs"].as_array() {
            if !arr.is_empty() {
                body.push_str("<div class=\"card\"><div class=\"card-header\"><span>Open pull requests</span>");
                let _ = write!(body, "<a href=\"/p/{up}/prs\">All PRs →</a></div>");
                body.push_str("<table class=\"listing\"><tbody>");
                for item in arr {
                    let id = item["id"].as_str().unwrap_or("");
                    let title = item["title"].as_str().unwrap_or("");
                    let author = item["author"].as_str().unwrap_or("");
                    let risk = item["risk"].as_str().unwrap_or("low");
                    let _ = writeln!(
                        body,
                        "<tr><td><a href=\"/p/{up}/prs/{}\">{}</a> <span class=\"muted\">({})</span></td><td><span class=\"badge\">{}</span></td><td class=\"muted\">{}</td></tr>",
                        url_part(id),
                        esc(title),
                        esc(id),
                        esc(risk),
                        esc(author)
                    );
                }
                body.push_str("</tbody></table></div>");
            }
        }
    }

    let title = format!("{pname} — Veil");
    Ok(page_shell(
        PageCtx {
            title: &title,
            project: Some(pname),
            active_tab: "overview",
            you: you_name(&caller),
            csrf: csrf.as_deref(),
            admin_link: can_admin_tab(&caller, &ask),
        },
        &body,
    ))
}

fn render_tree_table(tr: &Value, project: &str, dir_path: &str, rev: Option<&str>) -> String {
    let Some(entries) = tr["entries"].as_array() else {
        return "<div class=\"card-body\"><p class=\"muted\">Empty directory.</p></div>".into();
    };
    if entries.is_empty() {
        return "<div class=\"card-body\"><p class=\"muted\">Empty directory.</p></div>".into();
    }
    let up = url_part(project);
    let rq = rev.map(|r| format!("?rev={}", url_part(r))).unwrap_or_default();
    let mut out = String::from("<table class=\"listing\"><thead><tr><th>Name</th><th>Kind</th><th>Size / Status</th></tr></thead><tbody>");
    for e in entries {
        let name = e["name"].as_str().unwrap_or("");
        let kind = e["kind"].as_str().unwrap_or("file");
        let sealed = e["sealed"].as_bool() == Some(true);
        let full = if dir_path.is_empty() {
            name.to_string()
        } else {
            format!("{dir_path}/{name}")
        };
        let href = if kind == "dir" {
            format!("/p/{up}/tree/{}{rq}", url_repo_path(&full))
        } else {
            format!("/p/{up}/file/{}{rq}", url_repo_path(&full))
        };
        let suffix = if kind == "dir" { "/" } else { "" };
        let status_html = if sealed {
            "<span class=\"badge badge-sealed\">sealed</span> <span class=\"muted\">open with vl</span>".to_string()
        } else if kind == "dir" {
            "—".to_string()
        } else {
            format!("{} B", e["size"].as_u64().unwrap_or(0))
        };
        let _ = writeln!(
            out,
            "<tr><td class=\"mono\"><a href=\"{href}\">{}{}</a></td><td class=\"muted\">{}</td><td>{}</td></tr>",
            esc(name),
            suffix,
            esc(kind),
            status_html
        );
    }
    out.push_str("</tbody></table>");
    out
}

/// `GET /p/{p}/tree`: Root directory listing (bounded at 100 entries/page).
pub async fn tree_root_route(
    State(hub): State<HubState>,
    caller: Caller,
    Path(p): Path<String>,
    Query(q): Query<RevQuery>,
) -> Result<Response> {
    tree_common(hub, caller, p, String::new(), q).await
}

/// `GET /p/{p}/tree/{*path}`: Subdirectory listing (bounded at 100 entries/page).
pub async fn tree_path_route(
    State(hub): State<HubState>,
    caller: Caller,
    Path((p, path)): Path<(String, String)>,
    Query(q): Query<RevQuery>,
) -> Result<Response> {
    tree_common(hub, caller, p, path, q).await
}

async fn tree_common(hub: HubState, caller: Caller, p: String, raw_path: String, q: RevQuery) -> Result<Response> {
    let ask = Ask::open(&hub, &p, &caller).await?;
    let csrf = current_csrf();
    let lim = query::Limits { list: WEB_TREE_PAGE, ..Default::default() };
    let tr = query::tree(
        &hub,
        &ask,
        TreeParams {
            rev: q.rev.clone(),
            path: (!raw_path.is_empty()).then_some(raw_path.clone()),
            after: q.after.clone(),
        },
        lim,
    )
    .await?;

    let clean = tr["path"].as_str().unwrap_or("").to_string();
    let pname = &ask.project.name;
    let up = url_part(pname);
    let mut body = String::new();
    let _ = writeln!(
        body,
        "<div class=\"card\"><div class=\"card-header\"><span>{}</span></div>",
        format_breadcrumbs(pname, &clean, q.rev.as_deref(), false)
    );
    body.push_str(&render_tree_table(&tr, pname, &clean, q.rev.as_deref()));
    body.push_str("</div>");

    if let Some(next) = tr["next"].as_str() {
        let base = if clean.is_empty() {
            format!("/p/{up}/tree")
        } else {
            format!("/p/{up}/tree/{}", url_repo_path(&clean))
        };
        let mut qs = format!("after={}", url_part(next));
        if let Some(r) = &q.rev {
            let _ = write!(qs, "&amp;rev={}", url_part(r));
        }
        let _ = writeln!(body, "<div class=\"pager\"><a class=\"btn\" href=\"{base}?{qs}\">Next page →</a></div>");
    }

    let title = if clean.is_empty() {
        format!("Files · {pname} — Veil")
    } else {
        format!("{clean} · {pname} — Veil")
    };
    Ok(page_shell(
        PageCtx {
            title: &title,
            project: Some(pname),
            active_tab: "files",
            you: you_name(&caller),
            csrf: csrf.as_deref(),
            admin_link: can_admin_tab(&caller, &ask),
        },
        &body,
    ))
}

/// `GET /p/{p}/file/{*path}`: View a file. Sealed files (by visibility label OR
/// object authority `encoding != "content"`) never expose bytes; plain files
/// are HTML-escaped and paged at 200 lines / 60 KiB per page.
pub async fn file_route(
    State(hub): State<HubState>,
    caller: Caller,
    Path((p, raw_path)): Path<(String, String)>,
    Query(q): Query<RevQuery>,
) -> Result<Response> {
    let ask = Ask::open(&hub, &p, &caller).await?;
    let csrf = current_csrf();
    let (meta, bytes) = query::file(
        &hub,
        &ask,
        FileParams {
            rev: q.rev.clone(),
            path: raw_path,
        },
        query::Limits::default(),
    )
    .await?;

    let clean = meta["path"].as_str().unwrap_or("").to_string();
    let pname = &ask.project.name;
    let up = url_part(pname);
    let rq = q.rev.as_deref().map(|r| format!("?rev={}", url_part(r))).unwrap_or_default();
    let is_sealed = meta["sealed"].as_bool() == Some(true) || meta["encoding"].as_str() != Some("content");

    let mut body = String::new();
    body.push_str("<div class=\"card\"><div class=\"card-header\"><span>");
    body.push_str(&format_breadcrumbs(pname, &clean, q.rev.as_deref(), true));
    body.push_str("</span><span>");
    if !is_sealed {
        let _ = write!(
            body,
            "<a class=\"btn\" href=\"/p/{up}/blame/{}{rq}\">Blame</a> ",
            url_repo_path(&clean)
        );
    }
    let _ = write!(
        body,
        "<a class=\"btn\" href=\"/p/{up}/history/{}{rq}\">History</a>",
        url_repo_path(&clean)
    );
    body.push_str("</span></div><div class=\"card-body\">");

    if is_sealed {
        // Drop raw object bytes immediately; never inspect or render them.
        drop(bytes);
        body.push_str("<p><span class=\"badge badge-sealed\">sealed</span> <strong>Sealed secret file — open with vl.</strong></p>");
        body.push_str("<p class=\"muted\">In S25, secret files are decrypted only on trusted devices via <code>vl cat</code> or a local workspace. Their bytes never reach the browser.</p>");
    } else if bytes.contains(&0) {
        let len = bytes.len();
        drop(bytes);
        let _ = writeln!(body, "<p class=\"muted\">Binary file ({len} bytes).</p>");
    } else {
        match std::str::from_utf8(&bytes) {
            Err(_) => {
                let len = bytes.len();
                drop(bytes);
                let _ = writeln!(body, "<p class=\"muted\">Non-UTF-8 binary file ({len} bytes).</p>");
            }
            Ok(text) => {
                let all_lines: Vec<&str> = text.lines().collect();
                let total = all_lines.len();
                let page = q.page.unwrap_or(1).max(1);
                let start = (page - 1).saturating_mul(WEB_FILE_LINES_PER_PAGE);
                let mut end = start;
                let mut used_bytes = 0usize;
                while end < total && (end - start) < WEB_FILE_LINES_PER_PAGE {
                    let line_len = all_lines[end].len();
                    if end > start && used_bytes + line_len > WEB_FILE_BYTES_PER_PAGE {
                        break;
                    }
                    used_bytes += line_len;
                    end += 1;
                }

                let _ = writeln!(
                    body,
                    "<p class=\"muted\">Showing lines {}–{} of {} ({} bytes total)</p>",
                    if total == 0 { 0 } else { start + 1 },
                    end,
                    total,
                    bytes.len()
                );
                body.push_str("<table class=\"code-table mono\"><tbody>");
                if start < total {
                    for (idx, line) in all_lines[start..end].iter().enumerate() {
                        let ln = start + idx + 1;
                        let _ = writeln!(
                            body,
                            "<tr id=\"L{ln}\"><td class=\"ln\">{ln}</td><td>{}</td></tr>",
                            esc(line)
                        );
                    }
                }
                body.push_str("</tbody></table>");

                if page > 1 || end < total {
                    body.push_str("<div class=\"pager\">");
                    let rev_amp = q.rev.as_deref().map(|r| format!("&amp;rev={}", url_part(r))).unwrap_or_default();
                    if page > 1 {
                        let prev = page - 1;
                        let _ = write!(
                            body,
                            "<a class=\"btn\" href=\"/p/{up}/file/{}?page={prev}{rev_amp}\">← Previous</a>",
                            url_repo_path(&clean)
                        );
                    }
                    let _ = write!(body, "<span class=\"muted\">Page {page}</span>");
                    if end < total {
                        let next = page + 1;
                        let _ = write!(
                            body,
                            "<a class=\"btn\" href=\"/p/{up}/file/{}?page={next}{rev_amp}\">Next →</a>",
                            url_repo_path(&clean)
                        );
                    }
                    body.push_str("</div>");
                }
            }
        }
    }

    body.push_str("</div></div>");
    let title = format!("{clean} · {pname} — Veil");
    Ok(page_shell(
        PageCtx {
            title: &title,
            project: Some(pname),
            active_tab: "files",
            you: you_name(&caller),
            csrf: csrf.as_deref(),
            admin_link: can_admin_tab(&caller, &ask),
        },
        &body,
    ))
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct BlameQuery {
    pub rev: Option<String>,
    pub after: Option<usize>,
    pub follow: Option<bool>,
}

/// `GET /p/{p}/blame/{*path}`: Bounded line-by-line blame on viewer's projected history.
pub async fn blame_route(
    State(hub): State<HubState>,
    caller: Caller,
    Path((p, raw_path)): Path<(String, String)>,
    Query(q): Query<BlameQuery>,
) -> Result<Response> {
    let ask = Ask::open(&hub, &p, &caller).await?;
    let csrf = current_csrf();
    let bl = query::blame(
        &hub,
        &ask,
        BlameParams {
            rev: q.rev.clone(),
            path: raw_path,
            follow: q.follow,
            after: q.after,
            n: Some(WEB_BLAME_PAGE),
        },
        query::Limits::default(),
    )
    .await?;

    let clean = bl["path"].as_str().unwrap_or("").to_string();
    let pname = &ask.project.name;
    let up = url_part(pname);
    let mut authors = std::collections::HashMap::new();
    if let Some(changes) = bl["changes"].as_array() {
        for c in changes {
            if let (Some(sid), Some(au)) = (c["snapshot_id"].as_str(), c["author"].as_str()) {
                authors.insert(sid.to_string(), au.to_string());
            }
        }
    }

    let mut body = String::new();
    let _ = writeln!(
        body,
        "<div class=\"card\"><div class=\"card-header\"><span>Blame · {}</span><span class=\"muted\">{} lines</span></div>",
        format_breadcrumbs(pname, &clean, q.rev.as_deref(), true),
        bl["line_count"].as_u64().unwrap_or(0)
    );
    body.push_str("<table class=\"code-table mono\"><tbody>");
    if let Some(lines) = bl["lines"].as_array() {
        for l in lines {
            let ln = l["line"].as_u64().unwrap_or(0);
            let snap = l["snapshot"].as_str().unwrap_or("");
            let short = snap.get(..8).unwrap_or(snap);
            let who = authors.get(snap).map(String::as_str).unwrap_or("");
            let text = l["text"].as_str().unwrap_or("");
            let _ = writeln!(
                body,
                "<tr><td class=\"ln\"><a href=\"/p/{up}/commit/{}\">{}</a> {}</td><td class=\"ln\">{ln}</td><td>{}</td></tr>",
                url_part(snap),
                esc(short),
                esc(who),
                esc(text)
            );
        }
    }
    body.push_str("</tbody></table></div>");

    if let Some(next) = bl["next"].as_u64() {
        let rev_amp = q.rev.as_deref().map(|r| format!("&amp;rev={}", url_part(r))).unwrap_or_default();
        let _ = writeln!(
            body,
            "<div class=\"pager\"><a class=\"btn\" href=\"/p/{up}/blame/{}?after={next}{rev_amp}\">Next lines →</a></div>",
            url_repo_path(&clean)
        );
    }

    let title = format!("Blame {clean} · {pname} — Veil");
    Ok(page_shell(
        PageCtx {
            title: &title,
            project: Some(pname),
            active_tab: "files",
            you: you_name(&caller),
            csrf: csrf.as_deref(),
            admin_link: can_admin_tab(&caller, &ask),
        },
        &body,
    ))
}

fn render_log_table(lg: &Value, project: &str) -> String {
    let Some(entries) = lg["entries"].as_array() else {
        return "<div class=\"card-body\"><p class=\"muted\">No commits.</p></div>".into();
    };
    if entries.is_empty() {
        return "<div class=\"card-body\"><p class=\"muted\">No commits.</p></div>".into();
    }
    let up = url_part(project);
    let mut out = String::from("<table class=\"listing\"><thead><tr><th>Snapshot</th><th>Summary</th><th>Author</th></tr></thead><tbody>");
    for e in entries {
        let sid = e["snapshot_id"].as_str().unwrap_or("");
        let short = e["snapshot_short"].as_str().unwrap_or_else(|| sid.get(..8).unwrap_or(sid));
        let desc = e["description"].as_str().unwrap_or("");
        let first_line = desc.lines().next().unwrap_or("(root)");
        let author = e["author"].as_str().unwrap_or("—");
        let _ = writeln!(
            out,
            "<tr><td class=\"mono\"><a href=\"/p/{up}/commit/{}\">{}</a></td><td>{}</td><td class=\"muted\">{}</td></tr>",
            url_part(sid),
            esc(short),
            esc(first_line),
            esc(author)
        );
    }
    out.push_str("</tbody></table>");
    out
}

/// `GET /p/{p}/history/{*path}`: Bounded per-file history (`n = 50`, cursor-paged).
pub async fn file_history_route(
    State(hub): State<HubState>,
    caller: Caller,
    Path((p, raw_path)): Path<(String, String)>,
    Query(q): Query<RevQuery>,
) -> Result<Response> {
    let ask = Ask::open(&hub, &p, &caller).await?;
    let clean = ask.file_path(Some(&raw_path))?;
    let csrf = current_csrf();
    let hist = query::history(
        &hub,
        &ask,
        HistoryParams {
            rev: q.rev.clone(),
            path: Some(clean.clone()),
            follow: Some(ask.viewer.only.is_none()),
            n: Some(WEB_LOG_PAGE),
            after: q.after.clone(),
        },
        query::Limits::default(),
    )
    .await?;

    let pname = &ask.project.name;
    let up = url_part(pname);
    let mut body = String::new();
    let _ = writeln!(
        body,
        "<div class=\"card\"><div class=\"card-header\"><span>History · {}</span></div>",
        format_breadcrumbs(pname, &clean, q.rev.as_deref(), true)
    );
    body.push_str(&render_log_table(&hist, pname));
    body.push_str("</div>");

    if let Some(next) = hist["next"].as_str() {
        let rev_amp = q.rev.as_deref().map(|r| format!("&amp;rev={}", url_part(r))).unwrap_or_default();
        let _ = writeln!(
            body,
            "<div class=\"pager\"><a class=\"btn\" href=\"/p/{up}/history/{}?after={}{rev_amp}\">Older versions →</a></div>",
            url_repo_path(&clean),
            url_part(next)
        );
    }

    let title = format!("History {clean} · {pname} — Veil");
    Ok(page_shell(
        PageCtx {
            title: &title,
            project: Some(pname),
            active_tab: "commits",
            you: you_name(&caller),
            csrf: csrf.as_deref(),
            admin_link: can_admin_tab(&caller, &ask),
        },
        &body,
    ))
}

/// `GET /p/{p}/log`: Project commit log (`n = 50`, cursor-paged).
pub async fn log_route(
    State(hub): State<HubState>,
    caller: Caller,
    Path(p): Path<String>,
    Query(q): Query<RevQuery>,
) -> Result<Response> {
    let ask = Ask::open(&hub, &p, &caller).await?;
    let csrf = current_csrf();
    let lg = query::log(
        &hub,
        &ask,
        LogParams {
            rev: q.rev.clone(),
            n: Some(WEB_LOG_PAGE),
            path: q.path.clone(),
            after: q.after.clone(),
        },
        query::Limits::default(),
    )
    .await?;

    let pname = &ask.project.name;
    let up = url_part(pname);
    let mut body = String::from("<div class=\"card\"><div class=\"card-header\"><span>Commit history</span></div>");
    body.push_str(&render_log_table(&lg, pname));
    body.push_str("</div>");

    if let Some(next) = lg["next"].as_str() {
        let mut qs = format!("after={}", url_part(next));
        if let Some(r) = &q.rev {
            let _ = write!(qs, "&amp;rev={}", url_part(r));
        }
        if let Some(pth) = &q.path {
            let _ = write!(qs, "&amp;path={}", url_part(pth));
        }
        let _ = writeln!(body, "<div class=\"pager\"><a class=\"btn\" href=\"/p/{up}/log?{qs}\">Older commits →</a></div>");
    }

    let title = format!("Commits · {pname} — Veil");
    Ok(page_shell(
        PageCtx {
            title: &title,
            project: Some(pname),
            active_tab: "commits",
            you: you_name(&caller),
            csrf: csrf.as_deref(),
            admin_link: can_admin_tab(&caller, &ask),
        },
        &body,
    ))
}

/// `GET /p/{p}/commit/{rev}`: Single commit metadata + projected diff.
pub async fn commit_route(
    State(hub): State<HubState>,
    caller: Caller,
    Path((p, rev)): Path<(String, String)>,
    Query(q): Query<RevQuery>,
) -> Result<Response> {
    let ask = Ask::open(&hub, &p, &caller).await?;
    let csrf = current_csrf();
    let shown = query::show(
        &hub,
        &ask,
        ShowParams {
            rev: Some(rev.clone()),
            path: q.path.clone(),
            stat: Some(false),
        },
        query::Limits::default(),
    )
    .await?;

    let pname = &ask.project.name;
    let sid = shown["snapshot_id"].as_str().unwrap_or(&rev);
    let short = shown["snapshot_short"].as_str().unwrap_or_else(|| sid.get(..8).unwrap_or(sid));
    let author = shown["author"].as_str().unwrap_or("—");
    let desc = shown["description"].as_str().unwrap_or("");

    let mut body = String::new();
    let _ = writeln!(
        body,
        "<div class=\"card\"><div class=\"card-header\"><span class=\"mono\">Commit {}</span><span class=\"muted\">Author: {}</span></div><div class=\"card-body\"><pre>{}</pre></div></div>",
        esc(sid),
        esc(author),
        esc(desc)
    );
    body.push_str(&render_diff_files(&shown["diff"], pname, Some(sid), WEB_DIFF_MAX_LINES));

    let title = format!("{short} · {pname} — Veil");
    Ok(page_shell(
        PageCtx {
            title: &title,
            project: Some(pname),
            active_tab: "commits",
            you: you_name(&caller),
            csrf: csrf.as_deref(),
            admin_link: can_admin_tab(&caller, &ask),
        },
        &body,
    ))
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct WebSearchQuery {
    pub q: Option<String>,
    pub mode: Option<String>,
    pub rev: Option<String>,
    pub path: Option<String>,
    pub after: Option<String>,
}

/// `GET /p/{p}/search`: Bounded code/path search (`search`) and regex/literal `grep`.
pub async fn search_route(
    State(hub): State<HubState>,
    caller: Caller,
    Path(p): Path<String>,
    Query(q): Query<WebSearchQuery>,
) -> Result<Response> {
    let ask = Ask::open(&hub, &p, &caller).await?;
    // Enforce narrowing on `path` upfront even if `q` is empty.
    let clean_filter = ask.log_path(q.path.as_deref())?;
    let csrf = current_csrf();
    let pname = &ask.project.name;
    let up = url_part(pname);
    let mode = match q.mode.as_deref() {
        Some("grep") => "grep",
        Some("path") => "path",
        _ => "search",
    };
    let query_text = q.q.clone().unwrap_or_default();

    let mut body = String::new();
    body.push_str("<div class=\"card\"><div class=\"card-header\">Search code &amp; paths</div><div class=\"card-body\">");
    let _ = writeln!(
        body,
        "<form method=\"get\" action=\"/p/{up}/search\"><div class=\"form-row\"><input type=\"search\" name=\"q\" value=\"{}\" placeholder=\"Search terms or pattern…\"><select name=\"mode\"><option value=\"search\"{}>Ranked search</option><option value=\"grep\"{}>Exact / regex grep</option><option value=\"path\"{}>File names</option></select><input type=\"text\" name=\"path\" value=\"{}\" placeholder=\"Optional folder filter\"><button type=\"submit\">Search</button></div></form>",
        esc(&query_text),
        if mode == "search" { " selected" } else { "" },
        if mode == "grep" { " selected" } else { "" },
        if mode == "path" { " selected" } else { "" },
        esc(&clean_filter)
    );
    body.push_str("<p class=\"muted\">Sealed secret files are never indexed or searched.</p></div></div>");

    if !query_text.trim().is_empty() {
        let val = if mode == "grep" {
            search::grep(
                &hub,
                &ask,
                GrepParams {
                    pattern: query_text.clone(),
                    rev: q.rev.clone(),
                    i: Some(false),
                    path: (!clean_filter.is_empty()).then_some(clean_filter.clone()),
                    n: Some(WEB_SEARCH_PAGE),
                    after: q.after.clone(),
                },
                search::Limits::default(),
            )
            .await?
        } else {
            search::search(
                &hub,
                &ask,
                SearchParams {
                    q: Some(query_text.clone()),
                    rev: q.rev.clone(),
                    kind: (mode == "path").then(|| "path".into()),
                    path: (!clean_filter.is_empty()).then_some(clean_filter.clone()),
                    lang: None,
                    n: Some(WEB_SEARCH_PAGE),
                    after: q.after.clone(),
                },
                search::Limits::default(),
            )
            .await?
        };

        let items = val["results"].as_array().or_else(|| val["files"].as_array());
        if let Some(arr) = items {
            if arr.is_empty() {
                body.push_str("<div class=\"card\"><div class=\"card-body\"><p class=\"muted\">No matching files in your visible tree.</p></div></div>");
            } else {
                for item in arr {
                    let fpath = item["path"].as_str().unwrap_or("");
                    let _ = writeln!(
                        body,
                        "<div class=\"card\"><div class=\"card-header\"><a class=\"mono\" href=\"/p/{up}/file/{}\">{}</a></div>",
                        url_repo_path(fpath),
                        esc(fpath)
                    );
                    if let Some(lines) = item["lines"].as_array() {
                        if !lines.is_empty() {
                            body.push_str("<table class=\"code-table mono\"><tbody>");
                            for l in lines {
                                let ln = l["line"].as_u64().unwrap_or(0);
                                let txt = l["text"].as_str().unwrap_or("");
                                let _ = writeln!(body, "<tr><td class=\"ln\">{ln}</td><td>{}</td></tr>", esc(txt));
                            }
                            body.push_str("</tbody></table>");
                        }
                    }
                    body.push_str("</div>");
                }
            }
        }

        if let Some(next) = val["next"].as_str() {
            let mut qs = format!("mode={}&amp;q={}&amp;after={}", url_part(mode), url_part(&query_text), url_part(next));
            if !clean_filter.is_empty() {
                let _ = write!(qs, "&amp;path={}", url_part(&clean_filter));
            }
            if let Some(r) = &q.rev {
                let _ = write!(qs, "&amp;rev={}", url_part(r));
            }
            let _ = writeln!(body, "<div class=\"pager\"><a class=\"btn\" href=\"/p/{up}/search?{qs}\">More results →</a></div>");
        }
    }

    let title = format!("Search · {pname} — Veil");
    Ok(page_shell(
        PageCtx {
            title: &title,
            project: Some(pname),
            active_tab: "search",
            you: you_name(&caller),
            csrf: csrf.as_deref(),
            admin_link: can_admin_tab(&caller, &ask),
        },
        &body,
    ))
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct WebPrsQuery {
    pub state: Option<String>,
    pub q: Option<String>,
    pub after: Option<String>,
}

/// `GET /p/{p}/prs`: Bounded pull-request list (`n = 25`, cursor-paged).
pub async fn prs_list_route(
    State(hub): State<HubState>,
    caller: Caller,
    Path(p): Path<String>,
    Query(q): Query<WebPrsQuery>,
) -> Result<Response> {
    let ask = Ask::open(&hub, &p, &caller).await?;
    let csrf = current_csrf();
    let state = q.state.clone().unwrap_or_else(|| "open".into());
    let listing = prs::list(
        &hub,
        &ask,
        ListParams {
            state: Some(state.clone()),
            q: q.q.clone(),
            n: Some(WEB_PRS_PAGE),
            after: q.after.clone(),
        },
    )
    .await?;

    let pname = &ask.project.name;
    let up = url_part(pname);
    let mut body = String::new();
    body.push_str("<div class=\"card\"><div class=\"card-header\"><span>Pull requests</span><span class=\"nav-tabs\">");
    for st in ["open", "landed", "closed", "all"] {
        let cls = if state == st { " class=\"active\"" } else { "" };
        let _ = write!(body, "<a href=\"/p/{up}/prs?state={st}\"{cls}>{st}</a> ");
    }
    body.push_str("</span></div>");

    if let Some(arr) = listing["prs"].as_array() {
        if arr.is_empty() {
            body.push_str("<div class=\"card-body\"><p class=\"muted\">No pull requests match.</p></div>");
        } else {
            body.push_str("<table class=\"listing\"><thead><tr><th>Title</th><th>ID</th><th>Target</th><th>Risk</th><th>Author</th></tr></thead><tbody>");
            for item in arr {
                let id = item["id"].as_str().unwrap_or("");
                let title = item["title"].as_str().unwrap_or("");
                let target = item["target"].as_str().unwrap_or("");
                let risk = item["risk"].as_str().unwrap_or("");
                let author = item["author"].as_str().unwrap_or("");
                let _ = writeln!(
                    body,
                    "<tr><td><a href=\"/p/{up}/prs/{}\">{}</a></td><td class=\"mono\">{}</td><td class=\"mono\">{}</td><td><span class=\"badge\">{}</span></td><td class=\"muted\">{}</td></tr>",
                    url_part(id),
                    esc(title),
                    esc(id),
                    esc(target),
                    esc(risk),
                    esc(author)
                );
            }
            body.push_str("</tbody></table>");
        }
    }
    body.push_str("</div>");

    if let Some(next) = listing["next"].as_str() {
        let mut qs = format!("state={}&amp;after={}", url_part(&state), url_part(next));
        if let Some(qq) = &q.q {
            let _ = write!(qs, "&amp;q={}", url_part(qq));
        }
        let _ = writeln!(body, "<div class=\"pager\"><a class=\"btn\" href=\"/p/{up}/prs?{qs}\">Older PRs →</a></div>");
    }

    // Create PR form for non-runner participants
    let is_runner = caller.person.as_ref().and_then(|u| u.agent.as_ref()).is_some_and(|a| a.runner);
    if caller.person.is_some() && !is_runner && ask.project.participant(&ask.viewer) {
        if let Some(tok) = &csrf {
            let _ = writeln!(
                body,
                "<div class=\"card\"><div class=\"card-header\">Open a pull request</div><div class=\"card-body\"><form method=\"post\" action=\"/p/{up}/prs\"><input type=\"hidden\" name=\"_csrf\" value=\"{}\"><div class=\"form-row\"><input type=\"text\" name=\"head\" placeholder=\"head branch\" required><input type=\"text\" name=\"onto\" value=\"{}\" placeholder=\"target branch\"><input type=\"text\" name=\"title\" placeholder=\"PR title\" required></div><textarea name=\"body\" placeholder=\"Description (optional)\"></textarea><div class=\"form-row\"><button type=\"submit\">Create PR</button></div></form></div></div>",
                esc(tok),
                esc(&ask.project.default_branch)
            );
        }
    }

    let title = format!("Pull requests · {pname} — Veil");
    Ok(page_shell(
        PageCtx {
            title: &title,
            project: Some(pname),
            active_tab: "prs",
            you: you_name(&caller),
            csrf: csrf.as_deref(),
            admin_link: can_admin_tab(&caller, &ask),
        },
        &body,
    ))
}

/// `POST /p/{p}/prs`: Create a PR (CSRF-protected; refuses CI runners & non-participants).
pub async fn prs_create_route(
    State(hub): State<HubState>,
    caller: Caller,
    headers: HeaderMap,
    Path(p): Path<String>,
    body: Bytes,
) -> Result<Response> {
    let mut form = parse_form(&body);
    require_current_csrf(&headers, form.get("_csrf").map(String::as_str))?;
    let ask = Ask::open(&hub, &p, &caller).await?;
    let created = prs::create(
        &hub,
        &ask,
        &caller,
        CreatePr {
            head: form.remove("head").unwrap_or_default(),
            onto: form.remove("onto").filter(|s| !s.trim().is_empty()),
            title: form.remove("title").unwrap_or_default(),
            body: form.remove("body"),
        },
    )
    .await?;
    let id = created["id"].as_str().unwrap_or("");
    Ok(redirect_see_other(&format!("/p/{}/prs/{}", url_part(&ask.project.name), url_part(id))))
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct PrShowQuery {
    pub after: Option<String>,
    pub revision: Option<i32>,
}

/// `GET /p/{p}/prs/{id}`: PR detail, review gate, bounded diff, threads, and actions.
pub async fn pr_show_route(
    State(hub): State<HubState>,
    caller: Caller,
    Path((p, id)): Path<(String, String)>,
    Query(q): Query<PrShowQuery>,
) -> Result<Response> {
    let ask = Ask::open(&hub, &p, &caller).await?;
    let csrf = current_csrf();
    let pr = prs::show(&hub, &ask, &id).await?;
    let diff = prs::diff(
        &hub,
        &ask,
        &id,
        PrDiffParams {
            revision: q.revision,
            change: None,
            stat: Some(false),
        },
    )
    .await?;
    let threads = prs::threads_json(&hub, &ask, &id, q.after.as_deref()).await?;

    let pname = &ask.project.name;
    let up = url_part(pname);
    let pr_id = pr["id"].as_str().unwrap_or(&id);
    let pr_title = pr["title"].as_str().unwrap_or("");
    let pr_body = pr["body"].as_str().unwrap_or("");
    let pr_state = pr["state"].as_str().unwrap_or("open");
    let pr_author = pr["author"].as_str().unwrap_or("");
    let pr_target = pr["target"].as_str().unwrap_or("");
    let pr_risk = pr["risk"].as_str().unwrap_or("");
    let pr_patch = pr["patch"].as_str().unwrap_or("");
    let ready = pr["review"]["ready"].as_bool() == Some(true);

    let mut body = String::new();
    let _ = writeln!(
        body,
        "<div class=\"card\"><div class=\"card-header\"><span>{} <span class=\"mono muted\">({})</span></span><span><span class=\"badge\">{}</span> <span class=\"badge\">risk: {}</span></span></div><div class=\"card-body\">",
        esc(pr_title),
        esc(pr_id),
        esc(pr_state),
        esc(pr_risk)
    );
    let _ = writeln!(
        body,
        "<p class=\"muted\">By <strong>{}</strong> onto <code>{}</code> · Gate: <strong>{}</strong></p>",
        esc(pr_author),
        esc(pr_target),
        if ready { "ready to land" } else { "needs review / checks" }
    );
    if !pr_body.is_empty() {
        let _ = writeln!(body, "<pre>{}</pre>", esc(pr_body));
    }

    // Reviews list
    if let Some(verdicts) = pr["review"]["verdicts"].as_array() {
        if !verdicts.is_empty() {
            body.push_str("<p><strong>Reviews:</strong> ");
            for (i, v) in verdicts.iter().enumerate() {
                if i > 0 {
                    body.push_str(", ");
                }
                let who = v["person"].as_str().unwrap_or("");
                let verd = v["verdict"].as_str().unwrap_or("");
                let _ = write!(body, "{} (<code>{}</code>)", esc(who), esc(verd));
            }
            body.push_str("</p>");
        }
    }

    // State-changing buttons for signed-in non-runner participants
    let is_runner = caller.person.as_ref().and_then(|u| u.agent.as_ref()).is_some_and(|a| a.runner);
    if pr_state == "open" && caller.person.is_some() && !is_runner && ask.project.participant(&ask.viewer) {
        if let Some(tok) = &csrf {
            body.push_str("<div class=\"form-row\">");
            if ready {
                let _ = writeln!(
                    body,
                    "<form method=\"post\" action=\"/p/{up}/prs/{}/land\"><input type=\"hidden\" name=\"_csrf\" value=\"{}\"><button type=\"submit\">Land PR</button></form>",
                    url_part(pr_id),
                    esc(tok)
                );
            }
            let _ = writeln!(
                body,
                "<form method=\"post\" action=\"/p/{up}/prs/{}/close\"><input type=\"hidden\" name=\"_csrf\" value=\"{}\"><button type=\"submit\">Close PR</button></form>",
                url_part(pr_id),
                esc(tok)
            );
            body.push_str("</div>");
        }
    }
    body.push_str("</div></div>");

    // Diff files
    body.push_str(&render_diff_files(&diff, pname, None, WEB_DIFF_MAX_LINES));

    // Comment threads
    body.push_str("<div class=\"card\"><div class=\"card-header\">Discussion threads</div><div class=\"card-body\">");
    if let Some(tarr) = threads["threads"].as_array() {
        if tarr.is_empty() {
            body.push_str("<p class=\"muted\">No comments yet.</p>");
        } else {
            for t in tarr {
                let tid = t["id"].as_str().unwrap_or("");
                let tstate = t["state"].as_str().unwrap_or("open");
                let _ = writeln!(
                    body,
                    "<div class=\"card\"><div class=\"card-header\"><span class=\"mono\">Thread {}</span><span class=\"badge\">{}</span></div><div class=\"card-body\">",
                    esc(tid),
                    esc(tstate)
                );
                if let Some(carr) = t["comments"].as_array() {
                    for c in carr {
                        let cauthor = c["author"].as_str().unwrap_or("");
                        let cbody = c["body"].as_str().unwrap_or("");
                        let _ = writeln!(body, "<p><strong>{}:</strong></p><pre>{}</pre>", esc(cauthor), esc(cbody));
                    }
                }
                if caller.person.is_some() && !is_runner && ask.project.participant(&ask.viewer) {
                    if let Some(tok) = &csrf {
                        let toggle = if tstate == "open" { "resolved" } else { "open" };
                        let _ = writeln!(
                            body,
                            "<form method=\"post\" action=\"/p/{up}/prs/{}/threads/{}\"><input type=\"hidden\" name=\"_csrf\" value=\"{}\"><input type=\"hidden\" name=\"state\" value=\"{toggle}\"><div class=\"form-row\"><input type=\"text\" name=\"body\" placeholder=\"Reply (optional)\"><button type=\"submit\">Reply / mark {toggle}</button></div></form>",
                            url_part(pr_id),
                            url_part(tid),
                            esc(tok)
                        );
                    }
                }
                body.push_str("</div></div>");
            }
        }
    }
    if let Some(next_t) = threads["next"].as_str() {
        let _ = writeln!(
            body,
            "<div class=\"pager\"><a class=\"btn\" href=\"/p/{up}/prs/{}?after={}\">More threads →</a></div>",
            url_part(pr_id),
            url_part(next_t)
        );
    }

    if caller.person.is_some() && !is_runner && ask.project.participant(&ask.viewer) {
        if let Some(tok) = &csrf {
            let _ = writeln!(
                body,
                "<form method=\"post\" action=\"/p/{up}/prs/{}/threads\"><input type=\"hidden\" name=\"_csrf\" value=\"{}\"><textarea name=\"body\" placeholder=\"Start a new comment thread…\" required></textarea><div class=\"form-row\"><button type=\"submit\">Comment</button></div></form>",
                url_part(pr_id),
                esc(tok)
            );
        }
        if caller.person.as_ref().is_some_and(|u| u.agent.is_none()) && pr_state == "open" {
            let _ = writeln!(
                body,
                "<hr><h4>Device-signed review (WASM in-memory)</h4><form id=\"veil-wasm-review-form\" data-project=\"{}\" data-pr=\"{}\" data-patch=\"{}\"><div class=\"form-row\"><select id=\"veil-review-verdict\"><option value=\"approve\">Approve</option><option value=\"request-changes\">Request changes</option></select><input id=\"veil-review-body\" type=\"text\" placeholder=\"Review note (optional)\"></div><textarea id=\"veil-review-identity\" placeholder=\"Paste device identity JSON to sign review in WASM memory (never sent to server)\"></textarea><div class=\"form-row\"><button type=\"submit\">Sign &amp; submit review</button><span id=\"veil-review-status\" class=\"muted\"></span></div></form>",
                esc(pname),
                esc(pr_id),
                esc(pr_patch)
            );
        }
    }
    body.push_str("</div></div>");

    let title = format!("{} ({pr_id}) · {pname} — Veil", pr_title);
    Ok(page_shell(
        PageCtx {
            title: &title,
            project: Some(pname),
            active_tab: "prs",
            you: you_name(&caller),
            csrf: csrf.as_deref(),
            admin_link: can_admin_tab(&caller, &ask),
        },
        &body,
    ))
}

/// `POST /p/{p}/prs/{id}/threads`: Start a new PR comment thread.
pub async fn pr_new_thread_route(
    State(hub): State<HubState>,
    caller: Caller,
    headers: HeaderMap,
    Path((p, id)): Path<(String, String)>,
    body: Bytes,
) -> Result<Response> {
    let mut form = parse_form(&body);
    require_current_csrf(&headers, form.get("_csrf").map(String::as_str))?;
    let ask = Ask::open(&hub, &p, &caller).await?;
    prs::new_thread(
        &hub,
        &ask,
        &caller,
        &id,
        NewThread {
            body: form.remove("body").unwrap_or_default(),
            anchor: None,
        },
    )
    .await?;
    Ok(redirect_see_other(&format!("/p/{}/prs/{}", url_part(&ask.project.name), url_part(&id))))
}

/// `POST /p/{p}/prs/{id}/threads/{t}`: Reply to or resolve/reopen a PR thread.
pub async fn pr_thread_update_route(
    State(hub): State<HubState>,
    caller: Caller,
    headers: HeaderMap,
    Path((p, id, t)): Path<(String, String, String)>,
    body: Bytes,
) -> Result<Response> {
    let mut form = parse_form(&body);
    require_current_csrf(&headers, form.get("_csrf").map(String::as_str))?;
    let ask = Ask::open(&hub, &p, &caller).await?;
    prs::update_thread(
        &hub,
        &ask,
        &caller,
        &id,
        &t,
        ThreadUpdate {
            body: form.remove("body").filter(|s| !s.trim().is_empty()),
            state: form.remove("state").filter(|s| !s.trim().is_empty()),
        },
    )
    .await?;
    Ok(redirect_see_other(&format!("/p/{}/prs/{}", url_part(&ask.project.name), url_part(&id))))
}

/// `POST /p/{p}/prs/{id}/close`: Close an open PR.
pub async fn pr_close_route(
    State(hub): State<HubState>,
    caller: Caller,
    headers: HeaderMap,
    Path((p, id)): Path<(String, String)>,
    body: Bytes,
) -> Result<Response> {
    let form = parse_form(&body);
    require_current_csrf(&headers, form.get("_csrf").map(String::as_str))?;
    let ask = Ask::open(&hub, &p, &caller).await?;
    prs::close(&hub, &ask, &caller, &id).await?;
    Ok(redirect_see_other(&format!("/p/{}/prs/{}", url_part(&ask.project.name), url_part(&id))))
}

/// `POST /p/{p}/prs/{id}/land`: Land a ready PR (`landing::wait` calls `leave_gates()`).
pub async fn pr_land_route(
    State(hub): State<HubState>,
    caller: Caller,
    headers: HeaderMap,
    Path((p, id)): Path<(String, String)>,
    body: Bytes,
) -> Result<Response> {
    let form = parse_form(&body);
    require_current_csrf(&headers, form.get("_csrf").map(String::as_str))?;
    let ask = Ask::open(&hub, &p, &caller).await?;
    prs::land(&hub, &ask, &caller, &id).await?;
    Ok(redirect_see_other(&format!("/p/{}/prs/{}", url_part(&ask.project.name), url_part(&id))))
}

/// `POST /p/{p}/prs/{id}/dismiss`: Admin dismisses a reviewer's change request (`person_only`).
pub async fn pr_dismiss_route(
    State(hub): State<HubState>,
    caller: Caller,
    headers: HeaderMap,
    Path((p, id)): Path<(String, String)>,
    body: Bytes,
) -> Result<Response> {
    caller.person_only()?;
    let mut form = parse_form(&body);
    require_current_csrf(&headers, form.get("_csrf").map(String::as_str))?;
    let ask = Ask::open(&hub, &p, &caller).await?;
    prs::dismiss(
        &hub,
        &ask,
        &caller,
        &id,
        DismissRequest {
            person: form.remove("person").unwrap_or_default(),
        },
    )
    .await?;
    Ok(redirect_see_other(&format!("/p/{}/prs/{}", url_part(&ask.project.name), url_part(&id))))
}

/// `GET /p/{p}/admin`: Groups & access administration (`person_only`).
/// Shows only the groups the signed-in person is allowed to see (`api::list_groups`).
pub async fn admin_route(State(hub): State<HubState>, caller: Caller, Path(p): Path<String>) -> Result<Response> {
    caller.person_only()?;
    let (project, viewer) = perm::open(&hub, &p, &caller).await?;
    if !project.participant(&viewer) {
        return Err(Error::not_found("no such project that you can see"));
    }
    let csrf = current_csrf();
    let groups = crate::api::list_groups(State(hub.clone()), caller.clone(), Path(p)).await?.0;
    let pname = &project.name;
    let up = url_part(pname);

    let mut body = String::new();
    body.push_str("<div class=\"card\"><div class=\"card-header\">Groups</div><div class=\"card-body\">");
    if groups.is_empty() {
        body.push_str("<p class=\"muted\">No groups visible to you.</p>");
    } else {
        for g in &groups {
            let can_manage = viewer.admin || caller.person.as_ref().is_some_and(|me| g.managers.contains(&me.name));
            let _ = writeln!(
                body,
                "<div class=\"card\"><div class=\"card-header\"><span><code>{}</code></span><span class=\"muted\">members: {} · managers: {}</span></div><div class=\"card-body\">",
                esc(&g.name),
                esc(&g.members.join(", ")),
                esc(&g.managers.join(", "))
            );
            if can_manage {
                if let Some(tok) = &csrf {
                    let _ = writeln!(
                        body,
                        "<form method=\"post\" action=\"/p/{up}/admin/groups/{}/members\"><input type=\"hidden\" name=\"_csrf\" value=\"{}\"><div class=\"form-row\"><select name=\"op\"><option value=\"add\">Add member</option><option value=\"remove\">Remove member</option>{}</select><input type=\"text\" name=\"person\" placeholder=\"username\" required><button type=\"submit\">Update</button></div></form>",
                        url_part(&g.name),
                        esc(tok),
                        if viewer.admin { "<option value=\"manager\">Add manager</option>" } else { "" }
                    );
                }
            }
            if viewer.admin {
                if let Some(tok) = &csrf {
                    let _ = writeln!(
                        body,
                        "<form method=\"post\" action=\"/p/{up}/admin/groups/{}/delete\"><input type=\"hidden\" name=\"_csrf\" value=\"{}\"><button type=\"submit\">Delete group</button></form>",
                        url_part(&g.name),
                        esc(tok)
                    );
                }
            }
            body.push_str("</div></div>");
        }
    }

    if viewer.admin {
        if let Some(tok) = &csrf {
            let _ = writeln!(
                body,
                "<h4>Create group</h4><form method=\"post\" action=\"/p/{up}/admin/groups\"><input type=\"hidden\" name=\"_csrf\" value=\"{}\"><div class=\"form-row\"><input type=\"text\" name=\"name\" placeholder=\"group-name\" required><button type=\"submit\">Create group</button></div></form>",
                esc(tok)
            );
        }
    }
    body.push_str("</div></div>");

    let title = format!("Groups & access · {pname} — Veil");
    Ok(page_shell(
        PageCtx {
            title: &title,
            project: Some(pname),
            active_tab: "admin",
            you: you_name(&caller),
            csrf: csrf.as_deref(),
            admin_link: true,
        },
        &body,
    ))
}

/// `POST /p/{p}/admin/groups`: Create a group (`person_only`, admin-only, CSRF-protected).
pub async fn admin_create_group_route(
    State(hub): State<HubState>,
    caller: Caller,
    headers: HeaderMap,
    Path(p): Path<String>,
    body: Bytes,
) -> Result<Response> {
    caller.person_only()?;
    let mut form = parse_form(&body);
    require_current_csrf(&headers, form.get("_csrf").map(String::as_str))?;
    let g = form.remove("name").unwrap_or_default();
    let _ = crate::api::create_group(State(hub), caller, Path((p.clone(), g))).await?;
    Ok(redirect_see_other(&format!("/p/{}/admin", url_part(&p))))
}

/// `POST /p/{p}/admin/groups/{g}/delete`: Delete a group (`person_only`, admin-only, CSRF-protected).
pub async fn admin_delete_group_route(
    State(hub): State<HubState>,
    caller: Caller,
    headers: HeaderMap,
    Path((p, g)): Path<(String, String)>,
    body: Bytes,
) -> Result<Response> {
    caller.person_only()?;
    let form = parse_form(&body);
    require_current_csrf(&headers, form.get("_csrf").map(String::as_str))?;
    let _ = crate::api::delete_group(State(hub), caller, Path((p.clone(), g))).await?;
    Ok(redirect_see_other(&format!("/p/{}/admin", url_part(&p))))
}

/// `POST /p/{p}/admin/groups/{g}/members`: Add/remove member or add manager (`person_only`, CSRF-protected).
pub async fn admin_members_route(
    State(hub): State<HubState>,
    caller: Caller,
    headers: HeaderMap,
    Path((p, g)): Path<(String, String)>,
    body: Bytes,
) -> Result<Response> {
    caller.person_only()?;
    let mut form = parse_form(&body);
    require_current_csrf(&headers, form.get("_csrf").map(String::as_str))?;
    let op = form.remove("op").unwrap_or_default();
    let person = form.remove("person").unwrap_or_default();
    let req = GroupChange {
        people: vec![person],
    };
    match op.as_str() {
        "add" => {
            let _ = crate::api::add_members(State(hub), caller, Path((p.clone(), g)), axum::Json(req)).await?;
        }
        "remove" => {
            let _ = crate::api::remove_members(State(hub), caller, Path((p.clone(), g)), axum::Json(req)).await?;
        }
        "manager" => {
            let _ = crate::api::add_managers(State(hub), caller, Path((p.clone(), g)), axum::Json(req)).await?;
        }
        _ => return Err(Error::bad_request("unknown group operation")),
    }
    Ok(redirect_see_other(&format!("/p/{}/admin", url_part(&p))))
}
