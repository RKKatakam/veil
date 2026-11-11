//! Milestone S25: the web client, first version, with no secrets
//! (`docs/HUB.md` §13.39; `docs/design/server/phase-4-agent-scale.md` §4.11,
//! decision 13, and §6 row 11).
//!
//! Guarantees tested here:
//! 1. Exact API parity: the web client shows a person at most what the API
//!    shows them; hidden paths, embargoed content, and other projects never
//!    appear in HTML, JSON, error pages, or `<title>`.
//! 2. Secrets never reach the browser: sealed files show as sealed, and their
//!    bytes (neither plaintext nor ciphertext) are never served to the web
//!    client by any route (including forged public-visibility tree entries
//!    pointing to a `Sealed` object).
//! 3. Session safety: sign-in uses device-signed `hub-login` or a short-lived
//!    derived `web-` session, `__Host-veil_session` (`HttpOnly; Secure;
//!    SameSite=Strict`), CSRF protection on every state-changing request,
//!    strict `Content-Security-Policy` + security headers, and unconditional
//!    HTML escaping of all repository and user content.
//! 4. Narrowed agent sessions (S11) and CI runner sessions (S19) cannot use
//!    the web client to read or act beyond their limits.
//! 5. Bounded: page sizes and API work per page are bounded; large files and
//!    long histories, trees, searches, and PR lists are paged.

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use serde_json::{json, Value};
use veil_core::{
    crypto::Envelope,
    hub::web::WEB_TOKEN_PREFIX,
    object::{EntryKind, Object, Snapshot, Tree, TreeEntry, Visibility},
    ObjectId,
};

use crate::support::*;

struct WebReply {
    status: u16,
    headers: BTreeMap<String, Vec<String>>,
    body: Vec<u8>,
}

impl WebReply {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .and_then(|v| v.first())
            .map(String::as_str)
    }

    fn set_cookies(&self) -> &[String] {
        self.headers.get("set-cookie").map(Vec::as_slice).unwrap_or(&[])
    }

    fn title(&self) -> String {
        let t = self.text();
        let Some((_, rest)) = t.split_once("<title>") else {
            return String::new();
        };
        rest.split_once("</title>").map(|(s, _)| s.to_string()).unwrap_or_default()
    }
}

/// Minimal browser-like HTTPS client (`max_redirects(0)`) with explicit cookie
/// jar, `Origin`, `Sec-Fetch-*`, and CSRF support.
struct WebClient {
    agent: ureq::Agent,
    base: String,
    origin: String,
    #[allow(dead_code)]
    authority: String,
    cookie: Option<String>,
    csrf: Option<String>,
}

impl WebClient {
    fn new(hub: &TestHub) -> Self {
        Self::at(&hub.authority(), &hub.cert_pem)
    }

    fn at(authority: &str, cert_pem: &str) -> Self {
        let certs: Vec<ureq::tls::Certificate<'static>> = ureq::tls::parse_pem(cert_pem.as_bytes())
            .filter_map(|i| match i {
                Ok(ureq::tls::PemItem::Certificate(c)) => Some(c),
                _ => None,
            })
            .collect();
        let tls = ureq::tls::TlsConfig::builder()
            .provider(ureq::tls::TlsProvider::Rustls)
            .root_certs(ureq::tls::RootCerts::Specific(Arc::new(certs)))
            .build();
        let agent = ureq::Agent::config_builder()
            .tls_config(tls)
            .http_status_as_error(false)
            .max_redirects(0)
            .timeout_global(Some(Duration::from_secs(60)))
            .build()
            .new_agent();
        let origin = format!("https://{authority}");
        Self {
            agent,
            base: origin.clone(),
            origin,
            authority: authority.to_string(),
            cookie: None,
            csrf: None,
        }
    }

    fn finish(r: Result<ureq::http::Response<ureq::Body>, ureq::Error>) -> WebReply {
        let r = r.expect("HTTP response");
        let status = r.status().as_u16();
        let mut headers: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (k, v) in r.headers() {
            if let Ok(s) = v.to_str() {
                headers.entry(k.as_str().to_ascii_lowercase()).or_default().push(s.to_string());
            }
        }
        let body = r.into_body().with_config().limit(16 << 20).read_to_vec().unwrap();
        WebReply { status, headers, body }
    }

    fn capture_cookie(&mut self, r: &WebReply) {
        for sc in r.set_cookies() {
            if let Some(rest) = sc.strip_prefix("__Host-veil_session=") {
                let val = rest.split(';').next().unwrap_or("");
                if val.is_empty() || sc.contains("Max-Age=0") {
                    self.cookie = None;
                } else {
                    self.cookie = Some(val.to_string());
                }
            }
        }
    }

    fn get(&self, path: &str) -> WebReply {
        let mut req = self
            .agent
            .get(format!("{}{path}", self.base))
            .header("sec-fetch-dest", "document")
            .header("sec-fetch-mode", "navigate")
            .header("sec-fetch-site", "same-origin");
        if let Some(c) = &self.cookie {
            req = req.header("cookie", &format!("__Host-veil_session={c}"));
        }
        Self::finish(req.call())
    }

    fn get_with(&self, path: &str, extra: &[(&str, &str)]) -> WebReply {
        let mut req = self.agent.get(format!("{}{path}", self.base));
        if let Some(c) = &self.cookie {
            req = req.header("cookie", &format!("__Host-veil_session={c}"));
        }
        for (k, v) in extra {
            req = req.header(*k, *v);
        }
        Self::finish(req.call())
    }

    fn post_form(&self, path: &str, fields: &[(&str, &str)], include_csrf: bool, origin: Option<&str>, fetch_site: Option<&str>) -> WebReply {
        let mut req = self
            .agent
            .post(format!("{}{path}", self.base))
            .header("content-type", "application/x-www-form-urlencoded");
        if let Some(o) = origin {
            req = req.header("origin", o);
        }
        if let Some(fs) = fetch_site {
            req = req.header("sec-fetch-site", fs);
        }
        if let Some(c) = &self.cookie {
            req = req.header("cookie", &format!("__Host-veil_session={c}"));
        }
        let mut pairs: Vec<String> = fields.iter().map(|(k, v)| format!("{}={}", url_enc(k), url_enc(v))).collect();
        if include_csrf {
            if let Some(csrf) = &self.csrf {
                pairs.push(format!("_csrf={}", url_enc(csrf)));
            }
        }
        Self::finish(req.send(pairs.join("&").as_bytes()))
    }

    fn post_json_web(&self, path: &str, body: &Value, csrf: Option<&str>, origin: Option<&str>, fetch_site: Option<&str>) -> WebReply {
        let mut req = self
            .agent
            .post(format!("{}{path}", self.base))
            .header("content-type", "application/json")
            .header("accept", "application/json");
        if let Some(o) = origin {
            req = req.header("origin", o);
        }
        if let Some(fs) = fetch_site {
            req = req.header("sec-fetch-site", fs);
        }
        if let Some(c) = &self.cookie {
            req = req.header("cookie", &format!("__Host-veil_session={c}"));
        }
        if let Some(tok) = csrf {
            req = req.header("x-veil-csrf", tok);
        }
        let bytes = serde_json::to_vec(body).unwrap();
        Self::finish(req.send(&bytes))
    }

    fn delete_web(&self, path: &str, csrf: Option<&str>, origin: Option<&str>) -> WebReply {
        let mut req = self.agent.delete(format!("{}{path}", self.base));
        if let Some(o) = origin {
            req = req.header("origin", o);
        }
        if let Some(c) = &self.cookie {
            req = req.header("cookie", &format!("__Host-veil_session={c}"));
        }
        if let Some(tok) = csrf {
            req = req.header("x-veil-csrf", tok);
        }
        Self::finish(req.call())
    }

    /// Sign in via short-lived derived `web-` session (`POST /v1/sessions/web` -> `POST /web/session`).
    fn sign_in_derived(&mut self, hub: &TestHub, person: &Person) -> Value {
        let api = hub.api();
        let r = api.post_json(Some(&person.token()), "/v1/sessions/web", &json!({ "seconds": 3600 }));
        assert_eq!(r.status, 200, "mint web session failed: {}", String::from_utf8_lossy(&r.body));
        let ws = r.json();
        let web_tok = ws["token"].as_str().expect("web token");
        assert!(web_tok.starts_with(WEB_TOKEN_PREFIX));
        let csrf = ws["csrf"].as_str().expect("csrf").to_string();

        let adopt = self.post_json_web(
            "/web/session",
            &json!({ "token": web_tok }),
            None,
            Some(&self.origin.clone()),
            Some("same-origin"),
        );
        assert_eq!(adopt.status, 200, "adopt web session failed: {}", adopt.text());
        assert_strict_session_cookie(&adopt);
        self.capture_cookie(&adopt);
        self.csrf = Some(csrf);
        ws
    }
}

fn url_enc(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn assert_strict_session_cookie(r: &WebReply) {
    let cookies = r.set_cookies();
    let sc = cookies
        .iter()
        .find(|c| c.starts_with("__Host-veil_session="))
        .unwrap_or_else(|| panic!("missing __Host-veil_session Set-Cookie: {cookies:?}"));
    let low = sc.to_ascii_lowercase();
    assert!(low.contains("httponly"), "cookie missing HttpOnly: {sc}");
    assert!(low.contains("secure"), "cookie missing Secure: {sc}");
    assert!(low.contains("samesite=strict"), "cookie missing SameSite=Strict: {sc}");
    assert!(low.contains("path=/"), "cookie missing Path=/: {sc}");
}

fn assert_strict_csp_and_headers(r: &WebReply, ctx: &str) {
    let csp = r.header("content-security-policy").unwrap_or_else(|| panic!("missing CSP on {ctx}"));
    assert!(csp.contains("default-src 'none'"), "CSP missing default-src 'none' on {ctx}: {csp}");
    assert!(csp.contains("frame-ancestors 'none'"), "CSP missing frame-ancestors 'none' on {ctx}: {csp}");
    assert!(csp.contains("base-uri 'none'"), "CSP missing base-uri 'none' on {ctx}: {csp}");
    assert!(csp.contains("form-action 'self'"), "CSP missing form-action 'self' on {ctx}: {csp}");
    assert!(csp.contains("require-trusted-types-for 'script'"), "CSP missing Trusted Types on {ctx}: {csp}");
    assert!(!csp.contains("'unsafe-inline'"), "CSP allows unsafe-inline on {ctx}: {csp}");
    assert!(!csp.contains("'unsafe-eval'"), "CSP allows unsafe-eval on {ctx}: {csp}");
    assert_eq!(r.header("x-content-type-options"), Some("nosniff"), "missing nosniff on {ctx}");
    assert_eq!(r.header("x-frame-options"), Some("DENY"), "missing X-Frame-Options on {ctx}");
    assert_eq!(r.header("referrer-policy"), Some("no-referrer"), "missing Referrer-Policy on {ctx}");
}

fn assert_absent(haystack: &str, forbidden: &[&str], where_: &str) {
    for m in forbidden {
        assert!(!haystack.contains(m), "forbidden marker {m:?} appeared in {where_}:\n{haystack}");
    }
}

fn iso_utc(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let hour = rem / 3600;
    let min = (rem % 3600) / 60;
    let sec = rem % 60;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{hour:02}:{min:02}:{sec:02}Z")
}

fn catch_up(hub: &TestHub, project: &str) {
    let h = hub.hub();
    let pid: i64 = hub
        .rt
        .block_on(sqlx::query_scalar("SELECT id FROM projects WHERE name = $1").bind(project).fetch_one(&h.db))
        .unwrap();
    hub.rt.block_on(veil_server::derive::catch_up_project(&h, pid)).unwrap();
    hub.rt.block_on(veil_server::search::index::catch_up_project(&h, pid)).unwrap();
}

/// Guarantee 1: The web client shows a person at most what the API shows them.
/// Hidden paths, embargoed content, and other projects never appear in HTML,
/// JSON, error pages, or page `<title>`, and multi-server access revocation
/// takes effect on the very next web request.
#[test]
fn guarantee_1_web_shows_exact_api_view_and_hides_private_embargoed_and_other_projects() {
    const PUB_MARK: &str = "PUBLIC_README_MARKER_1001";
    const FIN_MARK: &str = "BILLING_FINANCE_MARKER_2002";
    const OPS_MARK: &str = "OPS_ADMIN_ONLY_MARKER_3003";
    const EMB_MARK: &str = "EMBARGO_VULN_PATCH_MARKER_4004";
    const EMB_MSG: &str = "EMBARGO_COMMIT_TITLE_5005";
    const OTHER_MARK: &str = "OTHER_PROJECT_TOP_SECRET_6006";

    let hub = TestHub::start();
    let alice = hub.person("alice");
    let bob = hub.person("bob");
    let sec = hub.person("sec");
    let mallory = hub.person("mallory");

    // Mallory creates a completely separate private project.
    let other_proj = unique("secretproj");
    let mdir = mallory.dir("m");
    std::fs::create_dir_all(&mdir).unwrap();
    mallory.ok(&mdir, &["init"]);
    write_files(&mdir, &[("vault.txt", OTHER_MARK)]);
    mallory.ok(&mdir, &["remote", "add", "origin", &hub.url(&other_proj)]);
    mallory.commit_main(&mdir, "mallory vault");
    mallory.ok(&mdir, &["push"]);

    // Alice creates `proj` with `public/`, `billing/` (finance), `ops/` (admin-only), and `security` group.
    let proj = unique("acmeweb");
    let adir = alice.dir("a");
    std::fs::create_dir_all(&adir).unwrap();
    alice.ok(&adir, &["init"]);
    alice.ok(&adir, &["remote", "add", "origin", &hub.url(&proj)]);
    write_files(&adir, &[("public/readme.md", &format!("# Hello\n{PUB_MARK}\n"))]);
    alice.commit_main(&adir, "initial public");
    alice.ok(&adir, &["push"]);

    alice.ok(&adir, &["group", "create", "finance"]);
    alice.ok(&adir, &["group", "add", "finance", &bob.name, "--confirm", &bob.fingerprint()]);
    alice.ok(&adir, &["group", "create", "security"]);
    alice.ok(&adir, &["group", "add", "security", &sec.name, "--confirm", &sec.fingerprint()]);
    alice.ok(&adir, &["group", "create", "ops_grp"]);

    alice.ok(&adir, &["access", "public/", "public", "security"]);
    alice.ok(&adir, &["access", "billing/", "finance"]);
    write_files(
        &adir,
        &[
            ("billing/invoice.txt", &format!("invoice: {FIN_MARK}\n")),
            ("ops/runbook.txt", &format!("runbook: {OPS_MARK}\n")),
        ],
    );
    alice.commit_main(&adir, "add policy, billing, and ops");
    alice.ok(&adir, &["push"]);

    let fp = alice.project_fingerprint(&adir);
    bob.trust_project(&hub, &proj, &fp);
    sec.trust_project(&hub, &proj, &fp);

    // Create two changes + PRs: one public PR, one finance-only PR.
    let api = hub.api();
    let main_tip = api.tips(Some(&alice.token()), &proj).unwrap().branches["main"];
    let pub_chg = api.post_json(
        Some(&alice.token()),
        &format!("/v1/projects/{proj}/changes"),
        &json!({
            "base": main_tip,
            "description": "public improvement",
            "edits": [{ "path": "public/feature.txt", "put": { "text": "PUB_PR_CONTENT\n" } }]
        }),
    );
    assert_eq!(pub_chg.status, 200, "{}", String::from_utf8_lossy(&pub_chg.body));
    let pub_snap = pub_chg.json()["snapshot"].as_str().unwrap().to_string();
    let pub_pr_res = api.post_json(
        Some(&alice.token()),
        &format!("/v1/projects/{proj}/prs"),
        &json!({ "head": pub_snap, "onto": "main", "title": "Public feature PR", "body": "Visible to public" }),
    );
    assert_eq!(pub_pr_res.status, 200, "{}", String::from_utf8_lossy(&pub_pr_res.body));
    let pub_pr_id = pub_pr_res.json()["id"].as_str().unwrap().to_string();

    let fin_chg = api.post_json(
        Some(&alice.token()),
        &format!("/v1/projects/{proj}/changes"),
        &json!({
            "base": main_tip,
            "description": "billing adjustment",
            "edits": [{ "path": "billing/q4.txt", "put": { "text": "FIN_PR_ONLY_777\n" } }]
        }),
    );
    assert_eq!(fin_chg.status, 200, "{}", String::from_utf8_lossy(&fin_chg.body));
    let fin_snap = fin_chg.json()["snapshot"].as_str().unwrap().to_string();
    let fin_pr_res = api.post_json(
        Some(&alice.token()),
        &format!("/v1/projects/{proj}/prs"),
        &json!({ "head": fin_snap, "onto": "main", "title": "Confidential Q4 Billing PR", "body": "Finance eyes only" }),
    );
    assert_eq!(fin_pr_res.status, 200, "{}", String::from_utf8_lossy(&fin_pr_res.body));
    let fin_pr_id = fin_pr_res.json()["id"].as_str().unwrap().to_string();

    // `sec` pushes an embargoed fix for `security`.
    let sdir = sec.dir("s");
    sec.clone_trusting(&hub.url(&proj), &sdir, &fp);
    write_files(&sdir, &[("public/embargo_patch.rs", &format!("pub const E: &str = \"{EMB_MARK}\";\n"))]);
    sec.ok(&sdir, &["commit", "--no-advance", "-m", EMB_MSG]);
    let until = iso_utc(veil_core::now_millis() + 3_600_000);
    sec.ok(&sdir, &["merge", "@-", "--into", "main", "--embargo-for", "security", "--until", &until, "-m", EMB_MSG]);
    sec.ok(&sdir, &["push"]);

    catch_up(&hub, &proj);

    // ---- 1A. Anonymous browser view ----
    let anon = WebClient::new(&hub);
    let home = anon.get("/");
    assert_eq!(home.status, 200, "{}", home.text());
    assert_strict_csp_and_headers(&home, "GET /");
    assert_absent(&home.text(), &[&proj, &other_proj, OTHER_MARK, FIN_MARK, OPS_MARK, EMB_MARK], "GET /");

    let about = anon.get("/about");
    assert_eq!(about.status, 200, "{}", about.text());
    assert!(
        about.text().contains("Thanks to okpom, who helped with the idea for Veil."),
        "About page missing okpom credit: {}",
        about.text()
    );

    let anon_overview = anon.get(&format!("/p/{proj}"));
    assert_eq!(anon_overview.status, 200, "{}", anon_overview.text());
    assert!(anon_overview.text().contains("public"));
    assert_absent(
        &anon_overview.text(),
        &["billing", "ops", FIN_MARK, OPS_MARK, EMB_MARK, EMB_MSG, "Confidential Q4 Billing PR", &other_proj],
        "anon overview",
    );

    let anon_file = anon.get(&format!("/p/{proj}/file/public/readme.md"));
    assert_eq!(anon_file.status, 200);
    assert!(anon_file.text().contains(PUB_MARK));

    let anon_blame = anon.get(&format!("/p/{proj}/blame/public/readme.md"));
    assert_eq!(anon_blame.status, 200, "{}", anon_blame.text());
    assert!(anon_blame.text().contains(&alice.name));

    let anon_hist = anon.get(&format!("/p/{proj}/history/public/readme.md"));
    assert_eq!(anon_hist.status, 200);
    assert!(anon_hist.text().contains("initial public"));

    let anon_search = anon.get(&format!("/p/{proj}/search?q={PUB_MARK}"));
    assert_eq!(anon_search.status, 200);
    assert!(anon_search.text().contains("public/readme.md"));
    let anon_secret_search = anon.get(&format!("/p/{proj}/search?q=FINANCE_MARKER"));
    assert_eq!(anon_secret_search.status, 200);
    assert_absent(&anon_secret_search.text(), &["billing", FIN_MARK], "anon search hidden");

    let anon_prs = anon.get(&format!("/p/{proj}/prs"));
    assert_eq!(anon_prs.status, 200);
    assert!(anon_prs.text().contains("Public feature PR"));
    assert_absent(&anon_prs.text(), &["Confidential Q4 Billing PR", &fin_pr_id, "FIN_PR_ONLY_777"], "anon PR list");

    // Hidden paths, hidden PRs, embargoed files, and other projects all 404 with static titles and no leaks.
    for (bad_url, leak_tokens) in [
        (format!("/p/{proj}/file/billing/invoice.txt"), vec!["billing", "invoice.txt", FIN_MARK]),
        (format!("/p/{proj}/tree/billing"), vec!["billing", "invoice.txt", FIN_MARK]),
        (format!("/p/{proj}/blame/billing/invoice.txt"), vec!["billing", "invoice.txt", FIN_MARK]),
        (format!("/p/{proj}/history/billing/invoice.txt"), vec!["billing", "invoice.txt", FIN_MARK]),
        (format!("/p/{proj}/file/public/embargo_patch.rs"), vec!["embargo_patch", EMB_MARK, EMB_MSG]),
        (format!("/p/{proj}/prs/{fin_pr_id}"), vec![fin_pr_id.as_str(), "Confidential Q4 Billing PR", "FIN_PR_ONLY_777"]),
        (format!("/p/{other_proj}"), vec![other_proj.as_str(), OTHER_MARK]),
        (format!("/p/{other_proj}/file/vault.txt"), vec![other_proj.as_str(), "vault.txt", OTHER_MARK]),
    ] {
        let r = anon.get(&bad_url);
        assert_eq!(r.status, 404, "expected 404 for {bad_url}, got {}: {}", r.status, r.text());
        assert_eq!(r.title(), "Not found — Veil", "error title leaked on {bad_url}");
        assert_strict_csp_and_headers(&r, &bad_url);
        assert_absent(&r.text(), &leak_tokens, &bad_url);
    }

    // ---- 1B. Group member `bob` (`finance`) view ----
    let mut bob_web = WebClient::new(&hub);
    bob_web.sign_in_derived(&hub, &bob);

    let bob_fin = bob_web.get(&format!("/p/{proj}/file/billing/invoice.txt"));
    assert_eq!(bob_fin.status, 200, "{}", bob_fin.text());
    assert!(bob_fin.text().contains(FIN_MARK));

    let bob_prs = bob_web.get(&format!("/p/{proj}/prs"));
    assert_eq!(bob_prs.status, 200);
    assert!(bob_prs.text().contains("Public feature PR"));
    assert!(bob_prs.text().contains("Confidential Q4 Billing PR"));

    let bob_fin_pr = bob_web.get(&format!("/p/{proj}/prs/{fin_pr_id}"));
    assert_eq!(bob_fin_pr.status, 200);
    assert!(bob_fin_pr.text().contains("FIN_PR_ONLY_777"));

    let bob_admin_page = bob_web.get(&format!("/p/{proj}/admin"));
    assert_eq!(bob_admin_page.status, 200);
    assert!(bob_admin_page.text().contains("finance"));
    assert_absent(&bob_admin_page.text(), &["ops_grp", "security"], "bob groups page");

    // Bob still never sees admin-only `ops/`, `security`'s embargo, or `mallory`'s project.
    for (bad_url, leaks) in [
        (format!("/p/{proj}/file/ops/runbook.txt"), vec!["ops/runbook.txt", OPS_MARK]),
        (format!("/p/{proj}/file/public/embargo_patch.rs"), vec!["embargo_patch", EMB_MARK, EMB_MSG]),
        (format!("/p/{other_proj}"), vec![other_proj.as_str(), OTHER_MARK]),
    ] {
        let r = bob_web.get(&bad_url);
        assert_eq!(r.status, 404, "bob should get 404 on {bad_url}");
        assert_absent(&r.text(), &leaks, &bad_url);
    }

    // ---- 1C. Admin `alice` view & multi-server revocation (`TestHub::beside`) ----
    let hub_b = TestHub::beside(&hub);
    let mut bob_on_b = WebClient::new(&hub_b);
    bob_on_b.cookie = bob_web.cookie.clone();
    bob_on_b.csrf = bob_web.csrf.clone();

    // Warm bob's view cache on server B.
    let warm = bob_on_b.get(&format!("/p/{proj}/file/billing/invoice.txt"));
    assert_eq!(warm.status, 200);
    assert!(warm.text().contains(FIN_MARK));

    let mut alice_web = WebClient::new(&hub);
    alice_web.sign_in_derived(&hub, &alice);
    let alice_ops = alice_web.get(&format!("/p/{proj}/file/ops/runbook.txt"));
    assert_eq!(alice_ops.status, 200);
    assert!(alice_ops.text().contains(OPS_MARK));
    // Even admin of `proj` gets 404 on `mallory`'s `other_proj`.
    let alice_other = alice_web.get(&format!("/p/{other_proj}"));
    assert_eq!(alice_other.status, 404);
    assert_absent(&alice_other.text(), &[&other_proj, OTHER_MARK], "alice on mallory project");

    // Alice removes `bob` from `finance` via the web admin form on server A.
    let origin_a = alice_web.origin.clone();
    let rev = alice_web.post_form(
        &format!("/p/{proj}/admin/groups/finance/members"),
        &[("op", "remove"), ("person", &bob.name)],
        true,
        Some(&origin_a),
        Some("same-origin"),
    );
    assert_eq!(rev.status, 303, "remove member via web failed: {}", rev.text());

    // Very next request on server B refuses `bob` immediately.
    let after_rev = bob_on_b.get(&format!("/p/{proj}/file/billing/invoice.txt"));
    assert_eq!(after_rev.status, 404, "revoked member still read billing on server B: {}", after_rev.text());
    assert_absent(&after_rev.text(), &[FIN_MARK, "invoice.txt"], "bob after revocation on server B");
    let _ = pub_pr_id;
}

/// Guarantee 2: Secrets never reach the browser. A sealed file shows as
/// sealed, and neither its plaintext nor its sealed envelope bytes are ever
/// served to the web client by any route — including when a tree entry has a
/// forged `Public` visibility label pointing to a `Sealed` object.
#[test]
fn guarantee_2_secrets_never_reach_browser_on_any_route() {
    const SEC_ALPHA: &str = "SECRET_CANARY_ALPHA_991122";
    const SEC_BETA: &str = "SECRET_CANARY_BETA_334455";
    const FORGED_SEC: &str = "FORGED_PUBLIC_SEALED_CANARY_778899";

    let hub = TestHub::start();
    let alice = hub.person("alice");
    let proj = unique("nosecrets");
    let dir = alice.dir("s");
    std::fs::create_dir_all(&dir).unwrap();
    alice.ok(&dir, &["init"]);
    alice.ok(&dir, &["remote", "add", "origin", &hub.url(&proj)]);
    write_files(&dir, &[("public/open.txt", "PLAIN_PUBLIC_OK\n")]);
    alice.commit_main(&dir, "initial open");
    alice.ok(&dir, &["push"]);

    alice.ok(&dir, &["access", "public/", "public"]);
    write_files(
        &dir,
        &[
            ("public/secrets/.env", &format!("API_KEY={SEC_BETA}\n")),
            ("private_sec/.env", &format!("DB_PASS={SEC_ALPHA}\n")),
        ],
    );
    alice.commit_main(&dir, "commit sealed secrets");
    alice.ok(&dir, &["push"]);

    // Create a branch `sec-branch` with an updated sealed `.env` file and open a PR for it.
    write_files(&dir, &[("public/secrets/.env", &format!("API_KEY={SEC_BETA}_V2\n"))]);
    alice.ok(&dir, &["commit", "--no-advance", "-m", "rotate sealed secret"]);
    alice.ok(&dir, &["tag", "set", "sec-branch", "-r", "@-"]);
    alice.ok(&dir, &["push"]);

    let api = hub.api();
    let main_tip = api.tips(Some(&alice.token()), &proj).unwrap().branches["main"];

    let pr_res = api.post_json(
        Some(&alice.token()),
        &format!("/v1/projects/{proj}/prs"),
        &json!({ "head": "sec-branch", "onto": "main", "title": "PR with sealed object", "body": "check diff" }),
    );
    assert_eq!(pr_res.status, 200, "{}", String::from_utf8_lossy(&pr_res.body));
    let pr_id = pr_res.json()["id"].as_str().unwrap().to_string();

    // Also test defense-in-depth when storage itself holds a snapshot with a forged
    // `Visibility::Public` tree entry pointing to an `Object::Sealed` envelope.
    let env = Envelope::seal_deterministic(&[42u8; 32], "forged#0102030405060708", FORGED_SEC.as_bytes()).unwrap();
    let raw_sealed = Object::Sealed(env).encode();
    let sealed_id = ObjectId::hash(&raw_sealed);
    let cipher_marker = hex::encode(&raw_sealed[raw_sealed.len().saturating_sub(16)..]);

    let local_repo = veil_core::Repo::open(std::sync::Arc::new(veil_core::DiskBackend::new(&dir)), None, "test").unwrap();
    let local_main = local_repo.view().tags["main"].target;
    let tip_snap = local_repo.snapshot(&local_main).unwrap();
    let root_tree = local_repo.store().tree(&tip_snap.tree).unwrap();
    let pub_entry = root_tree.entries.iter().find(|e| e.name == "public").unwrap().clone();
    let mut pub_tree = (*local_repo.store().tree(&pub_entry.id).unwrap()).clone();
    pub_tree.entries.push(TreeEntry {
        name: "forged.txt".into(),
        kind: EntryKind::File,
        id: sealed_id,
        size: FORGED_SEC.len() as u64,
        executable: false,
        visibility: Visibility::Public,
    });
    pub_tree.entries.sort_by(|a, b| a.name.cmp(&b.name));
    let raw_pub_tree = Object::Tree(pub_tree).encode();
    let new_pub_id = ObjectId::hash(&raw_pub_tree);

    let mut new_root_entries = root_tree.entries.clone();
    for e in &mut new_root_entries {
        if e.name == "public" {
            e.id = new_pub_id;
        }
    }
    let raw_root_tree = Object::Tree(Tree { entries: new_root_entries }).encode();
    let new_root_id = ObjectId::hash(&raw_root_tree);

    let mut forged_snap = Snapshot::root(new_root_id);
    forged_snap.parents = vec![main_tip];
    forged_snap.author = alice.name.clone();
    forged_snap.description = veil_core::object::Text::Plain("forged public entry to sealed blob".into());
    forged_snap.timestamp = veil_core::now_millis();
    forged_snap.sign(&hub.hub().identity);
    let raw_forged_snap = Object::Snapshot(forged_snap).encode();
    let forged_snap_id = ObjectId::hash(&raw_forged_snap);

    let h = hub.hub();
    hub.rt.block_on(async {
        let pid: i64 = sqlx::query_scalar("SELECT id FROM projects WHERE name = $1")
            .bind(&proj)
            .fetch_one(&h.db)
            .await
            .unwrap();
        let aid: i64 = sqlx::query_scalar("SELECT id FROM people WHERE name = $1")
            .bind(&alice.name)
            .fetch_one(&h.db)
            .await
            .unwrap();
        for (oid, raw) in [
            (sealed_id, raw_sealed.clone()),
            (new_pub_id, raw_pub_tree),
            (new_root_id, raw_root_tree),
            (forged_snap_id, raw_forged_snap),
        ] {
            h.objects.put(pid, &oid, bytes::Bytes::from(raw)).await.unwrap();
        }
        sqlx::query("INSERT INTO snapshots (project_id, id, author) VALUES ($1, $2, $3)")
            .bind(pid)
            .bind(forged_snap_id.hex())
            .bind(aid)
            .execute(&h.db)
            .await
            .unwrap();
        sqlx::query("INSERT INTO branches (project_id, name, target) VALUES ($1, 'forged-branch', $2)")
            .bind(pid)
            .bind(forged_snap_id.hex())
            .execute(&h.db)
            .await
            .unwrap();
    });

    catch_up(&hub, &proj);

    // Native `vl` still reads secrets via device token (no regression for CLI).
    let cli_q = api.get(Some(&alice.token()), &format!("/v1/projects/{proj}/q/file?path=private_sec/.env"));
    assert_eq!(cli_q.status, 200);

    // Sign in as admin `alice` in the web client.
    let mut web = WebClient::new(&hub);
    let ws = web.sign_in_derived(&hub, &alice);
    let web_tok = ws["token"].as_str().unwrap().to_string();

    let forbidden = [SEC_ALPHA, SEC_BETA, FORGED_SEC, "veil:seal", "veil:siv2", &cipher_marker];
    let check_no_bytes = |r: &WebReply, label: &str| {
        assert_absent(&r.text(), &forbidden, label);
        for vals in r.headers.values() {
            for v in vals {
                assert_absent(v, &forbidden, &format!("{label} header"));
            }
        }
        assert!(
            !r.body.windows(10).any(|w| w == b"veil:seal\n" || w == b"veil:siv2\n"),
            "raw sealed header leaked on {label}"
        );
    };

    // 1. Tree pages mark `.env` as sealed, with zero secret bytes.
    for tree_path in [format!("/p/{proj}/tree/private_sec"), format!("/p/{proj}/tree/public/secrets")] {
        let r = web.get(&tree_path);
        assert_eq!(r.status, 200, "{}", r.text());
        assert!(r.text().contains(".env"));
        assert!(r.text().to_ascii_lowercase().contains("sealed"), "missing sealed badge on {tree_path}: {}", r.text());
        check_no_bytes(&r, &tree_path);
    }

    // 2. Web file pages show sealed placeholder (including on forged-public entry!) and zero bytes.
    for file_url in [
        format!("/p/{proj}/file/private_sec/.env"),
        format!("/p/{proj}/file/public/secrets/.env"),
        format!("/p/{proj}/file/public/forged.txt?rev=forged-branch"),
    ] {
        let r = web.get(&file_url);
        assert_eq!(r.status, 200, "{}", r.text());
        assert!(r.text().contains("open with vl"), "missing 'open with vl' on {file_url}: {}", r.text());
        check_no_bytes(&r, &file_url);
    }

    // 3. `/v1/projects/{p}/q/file` refuses sealed & forged-sealed files for:
    //    (a) cookie web session, (b) Bearer `web-` token, and (c) device token + browser header!
    for q_path in [
        format!("/v1/projects/{proj}/q/file?path=private_sec/.env"),
        format!("/v1/projects/{proj}/q/file?path=public/secrets/.env"),
        format!("/v1/projects/{proj}/q/file?path=public/forged.txt&rev=forged-branch"),
    ] {
        let r_cookie = web.get(&q_path);
        assert_eq!(r_cookie.status, 403, "cookie q/file must refuse {q_path}: {}", r_cookie.text());
        assert_eq!(r_cookie.json()["code"], "sealed_file");
        check_no_bytes(&r_cookie, &q_path);

        let r_bearer = api.get(Some(&web_tok), &q_path);
        assert_eq!(r_bearer.status, 403);
        assert_eq!(r_bearer.json()["code"], "sealed_file");

        let dev_auth = format!("Bearer {}", alice.token());
        let r_browser_hdr = api.get_with(&q_path, &[("authorization", &dev_auth), ("sec-fetch-dest", "empty")]);
        assert_eq!(r_browser_hdr.status, 403);
        assert_eq!(r_browser_hdr.json()["code"], "sealed_file");
    }

    // Plain non-secret files still work on `/v1/projects/{p}/q/file` for web sessions!
    let plain_q = web.get(&format!("/v1/projects/{proj}/q/file?path=public/open.txt"));
    assert_eq!(plain_q.status, 200);
    assert_eq!(plain_q.text(), "PLAIN_PUBLIC_OK\n");

    // 4. Commit, PR, blame, and search views never expose secret bytes.
    let commit_page = web.get(&format!("/p/{proj}/commit/forged-branch"));
    assert_eq!(commit_page.status, 200);
    check_no_bytes(&commit_page, "commit page");

    let pr_page = web.get(&format!("/p/{proj}/prs/{pr_id}"));
    assert_eq!(pr_page.status, 200);
    check_no_bytes(&pr_page, "PR page");

    let blame_sec = web.get(&format!("/p/{proj}/blame/private_sec/.env"));
    assert_eq!(blame_sec.status, 400);
    check_no_bytes(&blame_sec, "blame sealed");

    for mode in ["search", "grep"] {
        let s = web.get(&format!("/p/{proj}/search?mode={mode}&q=SECRET_CANARY"));
        assert_eq!(s.status, 200);
        check_no_bytes(&s, &format!("search {mode}"));
    }

    // 5. Tips omits grants for web callers; raw object, ring, pending-key, and share routes refuse web callers.
    let web_tips = web.get(&format!("/v1/projects/{proj}/tips"));
    assert_eq!(web_tips.status, 200);
    assert!(
        web_tips.json()["grants"].as_object().is_none_or(|m| m.is_empty()),
        "web tips must omit read grants: {}",
        web_tips.text()
    );

    for get_secret_route in [
        format!("/v1/projects/{proj}/rings"),
        format!("/v1/projects/{proj}/rings/priv_sec"),
        format!("/v1/projects/{proj}/keys/pending"),
        format!("/v1/projects/{proj}/shares"),
    ] {
        let r1 = web.get(&get_secret_route);
        assert_eq!(r1.status, 403, "{get_secret_route} must refuse cookie web session");
        assert_eq!(r1.json()["code"], "web_session");

        let r2 = api.get(Some(&web_tok), &get_secret_route);
        assert_eq!(r2.status, 403, "{get_secret_route} must refuse Bearer web- token");
        assert_eq!(r2.json()["code"], "web_session");
    }

    let csrf = web.csrf.clone().unwrap();
    let orig = web.origin.clone();
    for (post_secret_route, payload) in [
        (format!("/v1/projects/{proj}/fetch"), json!({ "snapshot": main_tip.hex(), "objects": [] })),
        (format!("/v1/projects/{proj}/history"), json!({ "tips": [main_tip.hex()], "stop": [] })),
    ] {
        let r1 = web.post_json_web(&post_secret_route, &payload, Some(&csrf), Some(&orig), Some("same-origin"));
        assert_eq!(r1.status, 403, "{post_secret_route} must refuse web session");
        assert_eq!(r1.json()["code"], "web_session");

        let r2 = api.post_json(Some(&web_tok), &post_secret_route, &payload);
        assert_eq!(r2.status, 403, "{post_secret_route} must refuse Bearer web- token");
        assert_eq!(r2.json()["code"], "web_session");
    }

    // Even if someone steals a `Veil-Grant` from CLI `tips`, browser requests to `/v1/objects/...` are refused!
    let cli_tips = api.get(Some(&alice.token()), &format!("/v1/projects/{proj}/tips")).json();
    let stolen_grant = cli_tips["grants"]["forged-branch"].as_str().unwrap_or("");
    let obj_get = web.get_with(
        &format!("/v1/objects/{proj}/{}", sealed_id.hex()),
        &[("veil-grant", stolen_grant), ("sec-fetch-mode", "cors")],
    );
    assert_eq!(obj_get.status, 403, "browser request to /v1/objects must be refused: {}", obj_get.text());
    assert_eq!(obj_get.json()["code"], "web_session");

    let obj_batch = web.post_json_web(
        &format!("/v1/objects/{proj}:batch"),
        &json!({ "grant": stolen_grant, "wants": [], "skip": [] }),
        None,
        Some(&orig),
        Some("same-origin"),
    );
    assert_eq!(obj_batch.status, 403);
    assert_eq!(obj_batch.json()["code"], "web_session");
}

/// Guarantee 3: Session safety — device-signed login & derived `web-` session,
/// `__Host-veil_session` cookie attributes, CSRF protection on every
/// state-changing request (including login CSRF and cross-user CSRF), strict
/// CSP, unconditional XSS escaping, and immediate multi-server logout &
/// device-removal invalidation.
#[test]
fn guarantee_3_session_safety_csrf_cookies_csp_and_xss_escaping() {
    const XSS_SCRIPT: &str = "<script>window.__veil_xss=1</script>";
    const XSS_IMG: &str = "\"><img src=x onerror=alert(1)>";
    const XSS_SVG: &str = "<svg onload=alert('svg')></svg>";
    const XSS_TEXTAREA: &str = "</textarea><script>alert('ta')</script>";

    let hub = TestHub::start();
    let hub_b = TestHub::beside(&hub);
    let alice = hub.person("alice");
    let bob = hub.person("bob");
    let proj = unique("safeweb");

    let dir = alice.dir("w");
    std::fs::create_dir_all(&dir).unwrap();
    alice.ok(&dir, &["init"]);
    alice.ok(&dir, &["remote", "add", "origin", &hub.url(&proj)]);
    write_files(
        &dir,
        &[
            ("public/evil.html", &format!("<!doctype html>{XSS_SCRIPT}{XSS_IMG}\n")),
            ("public/icon.svg", &format!("{XSS_SVG}\n")),
            ("public/notes.md", &format!("# Notes\n{XSS_TEXTAREA}\n")),
        ],
    );
    alice.commit_main(&dir, &format!("commit {XSS_SCRIPT} & {XSS_IMG}"));
    alice.ok(&dir, &["push"]);
    alice.ok(&dir, &["group", "create", "devs"]);
    alice.ok(&dir, &["group", "add", "devs", &bob.name, "--confirm", &bob.fingerprint()]);
    alice.ok(&dir, &["access", "public/", "public", "devs"]);
    alice.commit_main(&dir, "grant devs access to public");
    alice.ok(&dir, &["push"]);

    catch_up(&hub, &proj);

    // 1. Raw 30-day device token is refused on `POST /web/session` (must be a short-lived `web-` token).
    let mut alice_web = WebClient::new(&hub);
    let orig = alice_web.origin.clone();
    let raw_attempt = alice_web.post_json_web(
        "/web/session",
        &json!({ "token": alice.token() }),
        None,
        Some(&orig),
        Some("same-origin"),
    );
    assert_eq!(raw_attempt.status, 400, "raw device token must not be accepted as browser cookie");

    // 2. Login CSRF on `/web/login` and `/web/session` from cross-site origin is refused (`403 csrf_failed`).
    let ws = hub
        .api()
        .post_json(Some(&alice.token()), "/v1/sessions/web", &json!({ "seconds": 1800 }))
        .json();
    let cross_adopt = alice_web.post_json_web(
        "/web/session",
        &json!({ "token": ws["token"] }),
        None,
        Some("https://evil.example"),
        Some("cross-site"),
    );
    assert_eq!(cross_adopt.status, 403);
    assert_eq!(cross_adopt.json()["code"], "csrf_failed");

    // 3. Derived web session sign-in (`POST /v1/sessions/web` -> `POST /web/session`; passkey sign-in is tested in `web_secrets`).
    let login_ws = alice_web.sign_in_derived(&hub, &alice);
    assert_eq!(login_ws["person"], alice.name);

    let mut bob_web = WebClient::new(&hub);
    bob_web.sign_in_derived(&hub, &bob);
    let bob_csrf = bob_web.csrf.clone().unwrap();

    // Create a change so we can test PR creation, commenting, review, and landing with CSRF.
    let api = hub.api();
    let main_tip = api.tips(Some(&alice.token()), &proj).unwrap().branches["main"];
    let chg = api.post_json(
        Some(&alice.token()),
        &format!("/v1/projects/{proj}/changes"),
        &json!({
            "base": main_tip,
            "description": format!("branch {XSS_SVG}"),
            "edits": [{ "path": "public/pr.txt", "put": { "text": format!("line {XSS_SCRIPT}\n") } }]
        }),
    );
    assert_eq!(chg.status, 200, "{}", String::from_utf8_lossy(&chg.body));
    let xss_head = chg.json()["snapshot"].as_str().unwrap().to_string();

    // 4. State-changing requests without CSRF, with another user's CSRF, or with cross-site Origin MUST fail (`403 csrf_failed`).
    let title_str = format!("Title {XSS_SVG} {XSS_IMG}");
    let body_str = format!("Body {XSS_TEXTAREA} {XSS_SCRIPT}");
    let pr_fields = [
        ("head", xss_head.as_str()),
        ("onto", "main"),
        ("title", title_str.as_str()),
        ("body", body_str.as_str()),
    ];
    let no_csrf = alice_web.post_form(&format!("/p/{proj}/prs"), &pr_fields, false, Some(&orig), Some("same-origin"));
    assert_eq!(no_csrf.status, 403);
    assert!(no_csrf.text().contains("csrf") || no_csrf.status == 403);

    let wrong_csrf = alice_web.post_json_web(
        &format!("/v1/projects/{proj}/prs"),
        &json!({ "head": xss_head, "onto": "main", "title": "bad csrf" }),
        Some(&bob_csrf),
        Some(&orig),
        Some("same-origin"),
    );
    assert_eq!(wrong_csrf.status, 403);
    assert_eq!(wrong_csrf.json()["code"], "csrf_failed");

    let cross_site = alice_web.post_form(
        &format!("/p/{proj}/prs"),
        &pr_fields,
        true,
        Some("https://attacker.example"),
        Some("cross-site"),
    );
    assert_eq!(cross_site.status, 403);

    // Cookie-authenticated `/v1/...` DELETE without CSRF also fails (`403 csrf_failed`).
    let del_no_csrf = alice_web.delete_web(&format!("/v1/projects/{proj}/groups/devs"), None, Some(&orig));
    assert_eq!(del_no_csrf.status, 403);
    assert_eq!(del_no_csrf.json()["code"], "csrf_failed");

    // 5. Same-origin + valid CSRF succeeds! Create PR and post hostile XSS comment via web UI.
    let ok_pr = alice_web.post_form(&format!("/p/{proj}/prs"), &pr_fields, true, Some(&orig), Some("same-origin"));
    assert_eq!(ok_pr.status, 303, "expected 303 redirect creating PR: {}", ok_pr.text());
    let pr_loc = ok_pr.header("location").expect("Location header").to_string();
    let pr_id = pr_loc.rsplit('/').next().unwrap().to_string();

    let ok_comment = alice_web.post_form(
        &format!("/p/{proj}/prs/{pr_id}/threads"),
        &[("body", &format!("Comment {XSS_SCRIPT} {XSS_TEXTAREA} {XSS_IMG}"))],
        true,
        Some(&orig),
        Some("same-origin"),
    );
    assert_eq!(ok_comment.status, 303, "expected 303 posting thread: {}", ok_comment.text());

    // Server-recorded PR review submitted from browser (`/v1/projects/{p}/prs/{id}/reviews` with cookie + CSRF, no `identity.json`!).
    let pr_json = alice_web.get_with(&format!("/v1/projects/{proj}/prs/{pr_id}"), &[("accept", "application/json")]).json();
    let patch_hash = pr_json["patch"].as_str().unwrap().to_string();
    let bob_orig = bob_web.origin.clone();
    let rev_submit = bob_web.post_json_web(
        &format!("/v1/projects/{proj}/prs/{pr_id}/reviews"),
        &json!({ "patch": patch_hash, "verdict": "approve", "body": format!("LGTM {XSS_SCRIPT}") }),
        Some(&bob_csrf),
        Some(&bob_orig),
        Some("same-origin"),
    );
    assert_eq!(rev_submit.status, 200, "server-recorded web review via cookie+CSRF failed: {}", rev_submit.text());

    // 6. Inspect every HTML page where hostile payloads were placed: strict CSP, `text/html`, and ZERO unescaped payloads!
    for page_url in [
        format!("/p/{proj}"),
        format!("/p/{proj}/file/public/evil.html"),
        format!("/p/{proj}/file/public/icon.svg"),
        format!("/p/{proj}/file/public/notes.md"),
        format!("/p/{proj}/blame/public/evil.html"),
        format!("/p/{proj}/log"),
        format!("/p/{proj}/commit/main"),
        format!("/p/{proj}/search?mode=grep&q=veil_xss"),
        format!("/p/{proj}/prs"),
        format!("/p/{proj}/prs/{pr_id}"),
    ] {
        let r = alice_web.get(&page_url);
        assert_eq!(r.status, 200, "failed GET {page_url}: {}", r.text());
        assert_strict_csp_and_headers(&r, &page_url);
        let ct = r.header("content-type").unwrap_or("");
        assert!(ct.starts_with("text/html"), "expected text/html on {page_url}, got {ct}");
        let html = r.text();
        assert_absent(
            &html,
            &[XSS_SCRIPT, "<img src=x", "<svg onload=", "</textarea><script>"],
            &page_url,
        );
    }

    // 7. Web session cannot mint child sessions (`403 web_session`).
    let alice_csrf = alice_web.csrf.clone().unwrap();
    for mint_route in ["/v1/sessions/web", "/v1/sessions/agent", "/v1/sessions/ci"] {
        let r = alice_web.post_json_web(
            mint_route,
            &json!({ "project": proj, "attribution": { "agent": "x" }, "only": [] }),
            Some(&alice_csrf),
            Some(&orig),
            Some("same-origin"),
        );
        assert_eq!(r.status, 403, "{mint_route} must refuse web session: {}", r.text());
        assert_eq!(r.json()["code"], "web_session");
    }

    // 8. Logout invalidates the session across BOTH servers (`hub` and `hub_b`) immediately!
    let saved_cookie = alice_web.cookie.clone().unwrap();
    let mut alice_on_b = WebClient::new(&hub_b);
    alice_on_b.cookie = Some(saved_cookie.clone());
    assert_eq!(alice_on_b.get(&format!("/v1/projects/{proj}/tips")).status, 200);

    let logout = alice_web.post_form("/web/logout", &[], true, Some(&orig), Some("same-origin"));
    assert_eq!(logout.status, 303, "logout failed: {}", logout.text());
    alice_web.capture_cookie(&logout);
    assert!(alice_web.cookie.is_none(), "logout must clear cookie");

    // Replaying the old cookie on server A OR server B is refused (`401`), never downgraded to anonymous!
    alice_on_b.cookie = Some(saved_cookie);
    assert_eq!(alice_on_b.get(&format!("/v1/projects/{proj}/tips")).status, 401);
    assert_eq!(alice_on_b.get(&format!("/p/{proj}")).status, 401);

    // 9. Removing a parent device invalidates derived web sessions immediately across servers.
    let dev2 = hub.new_device_of(&alice);
    alice.ok(alice.home.path(), &["identity", "confirm", &dev2.fingerprint()]);
    dev2.ok(
        dev2.home.path(),
        &["login", &format!("veil://{}", hub.authority()), "--ca", hub.ca.to_str().unwrap()],
    );
    let mut dev2_web = WebClient::new(&hub_b);
    dev2_web.sign_in_derived(&hub, &dev2);
    assert_eq!(dev2_web.get(&format!("/p/{proj}")).status, 200);
    let rm = api.post_json(
        Some(&alice.token()),
        "/v1/devices/remove",
        &json!({ "device": dev2.identity().public_id() }),
    );
    assert_eq!(rm.status, 200, "{}", String::from_utf8_lossy(&rm.body));
    assert_eq!(dev2_web.get(&format!("/p/{proj}")).status, 401);
}

/// Guarantee 4: Narrowed agent sessions (S11) and CI runner sessions (S19)
/// cannot use the web client to read outside their narrowed paths or act
/// beyond their session limits.
#[test]
fn guarantee_4_narrowed_agent_and_ci_runner_sessions_respect_limits_on_web() {
    const ALLOWED_MARK: &str = "API_HANDLER_ALLOWED_111";
    const OUTSIDE_MARK: &str = "OUTSIDE_CORE_SECRET_222";

    let hub = TestHub::start();
    let alice = hub.person("alice");
    let proj = unique("agentweb");
    let dir = alice.dir("ag");
    std::fs::create_dir_all(&dir).unwrap();
    alice.ok(&dir, &["init"]);
    alice.ok(&dir, &["remote", "add", "origin", &hub.url(&proj)]);
    write_files(
        &dir,
        &[
            ("src/api/handler.rs", &format!("pub fn handle() {{ /* {ALLOWED_MARK} */ }}\n")),
            ("src/other/engine.rs", &format!("pub fn secret_algo() {{ /* {OUTSIDE_MARK} */ }}\n")),
        ],
    );
    alice.commit_main(&dir, "setup workspace");
    alice.ok(&dir, &["push"]);

    let api = hub.api();
    let main_tip = api.tips(Some(&alice.token()), &proj).unwrap().branches["main"];

    // Create one PR inside `src/api/` and one PR outside (`src/other/`).
    let in_chg = api.post_json(
        Some(&alice.token()),
        &format!("/v1/projects/{proj}/changes"),
        &json!({
            "base": main_tip,
            "description": "api tweak",
            "edits": [{ "path": "src/api/v2.rs", "put": { "text": "pub fn v2() {}\n" } }]
        }),
    );
    assert_eq!(in_chg.status, 200, "{}", String::from_utf8_lossy(&in_chg.body));
    let in_snap = in_chg.json()["snapshot"].as_str().unwrap().to_string();
    let in_pr = api
        .post_json(
            Some(&alice.token()),
            &format!("/v1/projects/{proj}/prs"),
            &json!({ "head": in_snap, "onto": "main", "title": "In-scope API PR" }),
        )
        .json()["id"]
        .as_str()
        .unwrap()
        .to_string();

    let out_chg = api.post_json(
        Some(&alice.token()),
        &format!("/v1/projects/{proj}/changes"),
        &json!({
            "base": main_tip,
            "description": "engine tweak",
            "edits": [{ "path": "src/other/v2.rs", "put": { "text": "OUTSIDE_PR_DIFF_333\n" } }]
        }),
    );
    assert_eq!(out_chg.status, 200, "{}", String::from_utf8_lossy(&out_chg.body));
    let out_snap = out_chg.json()["snapshot"].as_str().unwrap().to_string();
    let out_pr = api
        .post_json(
            Some(&alice.token()),
            &format!("/v1/projects/{proj}/prs"),
            &json!({ "head": out_snap, "onto": "main", "title": "Out-of-scope Engine PR" }),
        )
        .json()["id"]
        .as_str()
        .unwrap()
        .to_string();

    catch_up(&hub, &proj);

    // ---- 4A. Narrowed agent session (`only = ["src/api"]`) ----
    let ag_res = api.post_json(
        Some(&alice.token()),
        "/v1/sessions/agent",
        &json!({
            "project": proj,
            "attribution": { "agent": "codex-test" },
            "only": ["src/api"]
        }),
    );
    assert_eq!(ag_res.status, 200);
    let ag_tok = ag_res.json()["token"].as_str().unwrap().to_string();

    // Agent session cannot mint a `web-` session to widen itself!
    let widen = api.post_json(Some(&ag_tok), "/v1/sessions/web", &json!({}));
    assert_eq!(widen.status, 403);
    assert_eq!(widen.json()["code"], "agent_session");

    // Agent calling web routes via Bearer token (and via stuffed cookie!):
    let ag_hash = veil_server::auth::session_hash(&ag_tok);
    let ag_csrf = veil_core::hub::web::csrf_for_session(&ag_hash);
    let mut ag_web = WebClient::new(&hub);
    ag_web.cookie = Some(ag_tok.clone());
    ag_web.csrf = Some(ag_csrf);
    let orig = ag_web.origin.clone();

    // Allowed inside `src/api`:
    let ok_ov = ag_web.get(&format!("/p/{proj}"));
    assert_eq!(ok_ov.status, 200, "{}", ok_ov.text());
    assert!(ok_ov.text().contains("src/api"));
    assert_absent(&ok_ov.text(), &["src/other", OUTSIDE_MARK, "Out-of-scope Engine PR"], "agent overview");

    assert_eq!(ag_web.get(&format!("/p/{proj}/tree/src/api")).status, 200);
    let ok_file = ag_web.get(&format!("/p/{proj}/file/src/api/handler.rs"));
    assert_eq!(ok_file.status, 200);
    assert!(ok_file.text().contains(ALLOWED_MARK));
    assert_eq!(ag_web.get(&format!("/p/{proj}/blame/src/api/handler.rs")).status, 200);
    assert_eq!(ag_web.get(&format!("/p/{proj}/history/src/api/handler.rs")).status, 200);
    assert_eq!(ag_web.get(&format!("/p/{proj}/search?q={ALLOWED_MARK}&path=src/api")).status, 200);
    assert_eq!(ag_web.get(&format!("/p/{proj}/prs/{in_pr}")).status, 200);

    // Refused outside `src/api` with exact API parity (`403` from `Viewer::narrowed_to`
    // regardless of whether the path exists, `404` from `prs::show`, zero content leak):
    for (outside_url, expected_status) in [
        (format!("/p/{proj}/tree"), 403),
        (format!("/p/{proj}/tree/src/other"), 403),
        (format!("/p/{proj}/file/src/other/engine.rs"), 403),
        (format!("/p/{proj}/file/src/nonexistent/ghost.rs"), 403),
        (format!("/p/{proj}/blame/src/other/engine.rs"), 403),
        (format!("/p/{proj}/history/src/other/engine.rs"), 403),
        (format!("/p/{proj}/search?q=OUTSIDE_ENGINE&path=src/other"), 403),
        (format!("/p/{proj}/prs/{out_pr}"), 404),
    ] {
        let r = ag_web.get(&outside_url);
        assert_eq!(r.status, expected_status, "narrowed agent expected {expected_status} on {outside_url}, got {}: {}", r.status, r.text());
        assert_absent(&r.text(), &[OUTSIDE_MARK, "OUTSIDE_PR_DIFF_333", "Out-of-scope Engine PR"], &outside_url);
    }
    assert_eq!(
        ag_web.get(&format!("/p/{proj}/file/src/other/engine.rs")).text(),
        ag_web.get(&format!("/p/{proj}/file/src/nonexistent/ghost.rs")).text(),
        "narrowed agent refusal must be identical for existing and non-existing paths"
    );

    // Refused person-only web routes (`403 agent_session`):
    let adm_get = ag_web.get(&format!("/p/{proj}/admin"));
    assert_eq!(adm_get.status, 403);
    let adm_post = ag_web.post_form(
        &format!("/p/{proj}/admin/groups"),
        &[("name", "rogue")],
        true,
        Some(&orig),
        Some("same-origin"),
    );
    assert_eq!(adm_post.status, 403);
    let dis_post = ag_web.post_form(
        &format!("/p/{proj}/prs/{in_pr}/dismiss"),
        &[("person", &alice.name)],
        true,
        Some(&orig),
        Some("same-origin"),
    );
    assert_eq!(dis_post.status, 403);

    // ---- 4B. CI runner session (`POST /v1/sessions/ci`) ----
    let ci_res = api.post_json(
        Some(&alice.token()),
        "/v1/sessions/ci",
        &json!({ "project": proj, "check": "unit", "only": ["src/api"] }),
    );
    assert_eq!(ci_res.status, 200);
    let ci_tok = ci_res.json()["token"].as_str().unwrap().to_string();
    let ci_hash = veil_server::auth::session_hash(&ci_tok);
    let mut ci_web = WebClient::new(&hub);
    ci_web.cookie = Some(ci_tok);
    ci_web.csrf = Some(veil_core::hub::web::csrf_for_session(&ci_hash));

    // CI runner reads within `src/api`, refused (`403`) outside:
    assert_eq!(ci_web.get(&format!("/p/{proj}/file/src/api/handler.rs")).status, 200);
    assert_eq!(ci_web.get(&format!("/p/{proj}/file/src/other/engine.rs")).status, 403);

    // CI runner is refused (`403`) on EVERY write action in the web client:
    for (write_url, fields) in [
        (format!("/p/{proj}/prs"), vec![("head", in_snap.as_str()), ("onto", "main"), ("title", "ci pr")]),
        (format!("/p/{proj}/prs/{in_pr}/threads"), vec![("body", "ci comment")]),
        (format!("/p/{proj}/prs/{in_pr}/close"), vec![]),
        (format!("/p/{proj}/prs/{in_pr}/land"), vec![]),
        (format!("/p/{proj}/admin/groups"), vec![("name", "cigrp")]),
    ] {
        let r = ci_web.post_form(&write_url, &fields, true, Some(&orig), Some("same-origin"));
        assert_eq!(r.status, 403, "CI runner must be refused on {write_url}: {}", r.text());
    }
}

/// Guarantee 5: Bounded — page sizes and API work per page are bounded;
/// large files, large directories, long commit/file histories, searches, and
/// PR lists are paged with working cursors.
#[test]
fn guarantee_5_web_pages_large_files_and_long_histories_are_bounded_and_paged() {
    let hub = TestHub::start();
    let alice = hub.person("alice");
    let proj = unique("boundedweb");
    let dir = alice.dir("b");
    std::fs::create_dir_all(&dir).unwrap();
    alice.ok(&dir, &["init"]);
    alice.ok(&dir, &["remote", "add", "origin", &hub.url(&proj)]);

    // 1. A 650-line file + 135 files in `public/many/`.
    let mut big = String::new();
    for i in 1..=650 {
        big.push_str(&format!("LINE_MARKER_{i:04}: the quick brown fox jumps over the lazy dog\n"));
    }
    write_files(&dir, &[(".veilpolicy", "public/ public\n"), ("public/big.txt", &big)]);
    let mut many_files = Vec::new();
    for i in 1..=135 {
        many_files.push((format!("public/many/f_{i:03}.txt"), format!("MANY_GREP_ITEM_{i:03}\n")));
    }
    for (p, c) in &many_files {
        let full = dir.join(p);
        std::fs::create_dir_all(full.parent().unwrap()).unwrap();
        std::fs::write(full, c).unwrap();
    }
    alice.commit_main(&dir, "COMMIT_SEQ_001");
    alice.ok(&dir, &["push"]);

    // 2. 64 more commits via `/changes` onto `main` so commit log & file history have 65 entries.
    let api = hub.api();
    let mut tip = api.tips(Some(&alice.token()), &proj).unwrap().branches["main"];
    for seq in 2..=65 {
        let chg = api.post_json(
            Some(&alice.token()),
            &format!("/v1/projects/{proj}/changes"),
            &json!({
                "base": tip,
                "description": format!("COMMIT_SEQ_{seq:03}"),
                "edits": [{ "path": "public/tracked.txt", "put": { "text": format!("v{seq}\n") } }],
                "onto": { "branch": "main", "expected": tip }
            }),
        );
        assert_eq!(chg.status, 200, "change {seq} failed: {}", String::from_utf8_lossy(&chg.body));
        tip = ObjectId::from_hex(chg.json()["snapshot"].as_str().unwrap()).unwrap();
    }

    // 3. 30 open PRs.
    for pseq in 1..=30 {
        let chg = api.post_json(
            Some(&alice.token()),
            &format!("/v1/projects/{proj}/changes"),
            &json!({
                "base": tip,
                "description": format!("pr commit {pseq}"),
                "edits": [{ "path": format!("public/pr_{pseq:02}.txt"), "put": { "text": "x\n" } }]
            }),
        );
        assert_eq!(chg.status, 200, "{}", String::from_utf8_lossy(&chg.body));
        let pr_snap = chg.json()["snapshot"].as_str().unwrap().to_string();
        let pr = api.post_json(
            Some(&alice.token()),
            &format!("/v1/projects/{proj}/prs"),
            &json!({ "head": pr_snap, "onto": "main", "title": format!("PR_SEQ_{pseq:02}") }),
        );
        assert_eq!(pr.status, 200, "{}", String::from_utf8_lossy(&pr.body));
    }

    catch_up(&hub, &proj);

    let mut web = WebClient::new(&hub);
    web.sign_in_derived(&hub, &alice);

    // A. Large file is paged (200 lines / <= 96 KiB HTML per page).
    let f_p1 = web.get(&format!("/p/{proj}/file/public/big.txt"));
    assert_eq!(f_p1.status, 200);
    assert!(f_p1.body.len() < 96 * 1024, "file page 1 too large: {} bytes", f_p1.body.len());
    let t1 = f_p1.text();
    assert!(t1.contains("LINE_MARKER_0001") && t1.contains("LINE_MARKER_0200"));
    assert!(!t1.contains("LINE_MARKER_0201") && !t1.contains("LINE_MARKER_0650"));
    assert!(t1.contains("page=2"), "missing next page link on file page 1");

    let f_p2 = web.get(&format!("/p/{proj}/file/public/big.txt?page=2"));
    assert_eq!(f_p2.status, 200);
    assert!(f_p2.text().contains("LINE_MARKER_0201") && f_p2.text().contains("LINE_MARKER_0400"));
    assert!(!f_p2.text().contains("LINE_MARKER_0001") && !f_p2.text().contains("LINE_MARKER_0401"));

    let f_p4 = web.get(&format!("/p/{proj}/file/public/big.txt?page=4"));
    assert_eq!(f_p4.status, 200);
    assert!(f_p4.text().contains("LINE_MARKER_0601") && f_p4.text().contains("LINE_MARKER_0650"));

    // B. Large directory tree is paged (100 entries per page).
    let tr_p1 = web.get(&format!("/p/{proj}/tree/public/many"));
    assert_eq!(tr_p1.status, 200);
    assert!(tr_p1.text().contains("f_001.txt") && tr_p1.text().contains("f_100.txt"));
    assert!(!tr_p1.text().contains("f_135.txt"));
    let tr_next = extract_next_href(&tr_p1.text(), &format!("/p/{proj}/tree/public/many?"));
    let tr_p2 = web.get(&tr_next);
    assert_eq!(tr_p2.status, 200);
    assert!(tr_p2.text().contains("f_101.txt") && tr_p2.text().contains("f_135.txt"));

    // C. Long commit log is paged (50 commits per page).
    let log_p1 = web.get(&format!("/p/{proj}/log"));
    assert_eq!(log_p1.status, 200);
    assert!(log_p1.text().contains("COMMIT_SEQ_065") && log_p1.text().contains("COMMIT_SEQ_016"));
    assert!(!log_p1.text().contains("COMMIT_SEQ_001"));
    let log_next = extract_next_href(&log_p1.text(), &format!("/p/{proj}/log?"));
    let log_p2 = web.get(&log_next);
    assert_eq!(log_p2.status, 200);
    assert!(log_p2.text().contains("COMMIT_SEQ_015") && log_p2.text().contains("COMMIT_SEQ_001"));

    // D. Long file history is paged (50 versions per page).
    let fh_p1 = web.get(&format!("/p/{proj}/history/public/tracked.txt"));
    assert_eq!(fh_p1.status, 200);
    assert!(fh_p1.text().contains("COMMIT_SEQ_065"));
    assert!(!fh_p1.text().contains("COMMIT_SEQ_002"));
    let fh_next = extract_next_href(&fh_p1.text(), &format!("/p/{proj}/history/public/tracked.txt?"));
    let fh_p2 = web.get(&fh_next);
    assert_eq!(fh_p2.status, 200);
    assert!(fh_p2.text().contains("COMMIT_SEQ_002"));

    // E. Grep / search results are paged (<= 25 files per page).
    let gr_p1 = web.get(&format!("/p/{proj}/search?mode=grep&q=MANY_GREP_ITEM"));
    assert_eq!(gr_p1.status, 200);
    assert!(gr_p1.text().contains("f_001.txt"));
    assert!(!gr_p1.text().contains("f_135.txt"));
    let gr_next = extract_next_href(&gr_p1.text(), &format!("/p/{proj}/search?"));
    let gr_p2 = web.get(&gr_next);
    assert_eq!(gr_p2.status, 200);
    assert!(gr_p2.text().contains("f_026.txt"));

    // F. PR list is paged (25 PRs per page).
    let prs_p1 = web.get(&format!("/p/{proj}/prs"));
    assert_eq!(prs_p1.status, 200);
    assert!(prs_p1.text().contains("PR_SEQ_30"));
    assert!(!prs_p1.text().contains("PR_SEQ_01"));
    let prs_next = extract_next_href(&prs_p1.text(), &format!("/p/{proj}/prs?"));
    let prs_p2 = web.get(&prs_next);
    assert_eq!(prs_p2.status, 200);
    assert!(prs_p2.text().contains("PR_SEQ_01"));
}

fn extract_next_href(html: &str, prefix: &str) -> String {
    for part in html.split("href=\"").skip(1) {
        if let Some((raw, _)) = part.split_once('"') {
            let decoded = raw.replace("&amp;", "&");
            if decoded.starts_with(prefix) && decoded.contains("after=") {
                return decoded;
            }
        }
    }
    panic!("no next-page href starting with {prefix:?} in HTML:\n{html}");
}

// ---- review rv-new (BUG-1871 to BUG-1873) ---------------------------------------

/// BUG-1871: the web client asks for the device's `identity.json` (sign-in
/// "option 2" and every review). That file holds the device's signing seed
/// **and** its X25519 secret, the key that opens the secret key rings: a
/// personal private key in the browser, which the server's code runs in
/// (`docs/design/server/phase-4-agent-scale.md` §6 row 18, decision 13).
#[test]
fn bug_1871_the_web_client_never_asks_for_a_device_identity_file() {
    let hub = TestHub::start();
    let web = WebClient::new(&hub);
    let login = web.get("/login");
    assert_eq!(login.status, 200, "{}", login.text());
    let js = web.get("/static/app.js");
    assert_eq!(js.status, 200, "{}", js.text());
    let asks = [
        "veil-identity-json",
        "veil-review-identity",
        "identity JSON",
        "veil_web_sign_login",
        "veil_web_sign_review",
        "veil_web_generate_identity",
    ];
    assert_absent(&login.text(), &asks, "GET /login");
    assert_absent(&js.text(), &asks, "GET /static/app.js");
}

/// BUG-1872: a file page is bounded in lines only. A line is rendered whole
/// whatever its length, so a minified bundle (one line) comes back as one
/// page of the file's whole size (`docs/HUB.md` §13.39: 200 lines /
/// `<= 64 KiB` per page).
#[test]
#[ignore = "BUG-1872: a file page renders a long line whole: its size is not bounded"]
fn bug_1872_a_file_page_is_bounded_whatever_the_length_of_a_line() {
    let hub = TestHub::start();
    let alice = hub.person("alice");
    let proj = unique("longline");
    let dir = alice.dir("l");
    std::fs::create_dir_all(&dir).unwrap();
    alice.ok(&dir, &["init"]);
    alice.ok(&dir, &["remote", "add", "origin", &hub.url(&proj)]);
    let bundle = format!("{}\n", "var a=1;".repeat(600 * 1024 / 8));
    write_files(&dir, &[(".veilpolicy", "public/ public\n"), ("public/bundle.min.js", &bundle)]);
    alice.commit_main(&dir, "a minified bundle");
    alice.ok(&dir, &["push"]);
    catch_up(&hub, &proj);

    let mut web = WebClient::new(&hub);
    web.sign_in_derived(&hub, &alice);
    let page = web.get(&format!("/p/{proj}/file/public/bundle.min.js"));
    assert_eq!(page.status, 200, "{}", page.text().chars().take(400).collect::<String>());
    // The same bound as `guarantee_5` holds a 650-line file's page to.
    assert!(page.body.len() < 96 * 1024, "a file page of {} bytes", page.body.len());
}

/// BUG-1873: `docs/HUB.md` §13.39 says a web session lasts 8 hours by
/// default (12 at most; the cookie's `Max-Age=28800`); the server gives 1
/// hour (4 at most).
#[test]
#[ignore = "BUG-1873: a web session lasts 1 hour by default, not the 8 hours docs/HUB.md §13.39 says"]
fn bug_1873_a_web_session_lasts_as_long_as_the_design_says() {
    let hub = TestHub::start();
    let alice = hub.person("alice");
    let before = veil_core::now_millis();
    let r = hub.api().post_json(Some(&alice.token()), "/v1/sessions/web", &json!({}));
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let lasts = r.json()["expires_at"].as_i64().expect("expires_at") - before;
    let hour = 3600 * 1000;
    assert!((8 * hour - 60_000..=8 * hour + 60_000).contains(&lasts), "a default web session lasts {} minutes", lasts / 60_000);
}
