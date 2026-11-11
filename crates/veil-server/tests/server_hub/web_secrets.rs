//! Milestone S26 (`docs/HUB.md` §13.40; `docs/design/server/phase-4-agent-scale.md`
//! §4.12, §6 row 18, §11 item 6): secrets in the browser, passkey sign-in, and
//! server-recorded web reviews.
//!
//! Guarantees tested here:
//! 1. No route ever returns a plain secret (`guarantee_1_no_route_ever_returns_a_plain_secret`).
//! 2. An unconfirmed browser device gets no wrapped key (`guarantee_2_unconfirmed_browser_device_gets_no_wrapped_key`).
//! 3. With the project setting off, no browser gets a wrapped key and no page has
//!    a decrypt path (`guarantee_3_project_setting_off_gives_no_wrapped_key_and_no_decrypt_path`).
//! 4. A browser device sees only the rings of folders its person may read;
//!    removal deletes its rings (`guarantee_4_browser_device_sees_only_readable_folder_rings_and_removal_deletes_them`).
//! 5. The browser's private keys are never in a request body (`guarantee_5_browser_private_keys_are_never_in_a_request_body`).
//! 6. Web approvals count only under S21's rules (`guarantee_6_web_approvals_count_only_under_s21_rules`).
//! 7. Passkey enrollment via `vl web` replaces identity-file sign-in (`guarantee_7_passkey_enrollment_via_vl_web_replaces_identity_file_sign_in`,
//!    together with `web::bug_1871_the_web_client_never_asks_for_a_device_identity_file`).

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use rcgen::{KeyPair, SigningKey as _};
use serde_json::{json, Value};
use veil_core::{
    hub::{
        access::AccessPolicy,
        web::{b64url_encode, seal_new_browser_device, sha256, BrowserDeviceBundle, WEB_ENROLL_PREFIX},
        web_secrets::open_secret_in_worker,
    },
    keychain::{KeyRing, Keychain},
    policy::rule_scope,
    vfs::MemoryBackend,
    StorageBackend,
};

use crate::support::*;

#[derive(Clone)]
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
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|e| panic!("status {}: bad JSON ({e}): {}", self.status, self.text()))
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(&name.to_ascii_lowercase())?.first().map(String::as_str)
    }

    fn set_cookies(&self) -> Vec<&str> {
        self.headers
            .get("set-cookie")
            .map(|v| v.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }
}

type SentLog = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

struct BrowserClient {
    agent: ureq::Agent,
    base: String,
    origin: String,
    rp_id: String,
    cookie: Option<String>,
    csrf: Option<String>,
    sent_bodies: SentLog,
}

impl BrowserClient {
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
        let rp_id = authority.split(':').next().unwrap_or(authority).to_string();
        Self {
            agent,
            base: origin.clone(),
            origin,
            rp_id,
            cookie: None,
            csrf: None,
            sent_bodies: Arc::new(Mutex::new(Vec::new())),
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

    fn get_api(&self, path: &str) -> WebReply {
        let mut req = self
            .agent
            .get(format!("{}{path}", self.base))
            .header("accept", "application/json")
            .header("sec-fetch-site", "same-origin");
        if let Some(c) = &self.cookie {
            req = req.header("cookie", &format!("__Host-veil_session={c}"));
        }
        Self::finish(req.call())
    }

    fn post_json(&self, path: &str, body: &Value, include_csrf: bool) -> WebReply {
        self.post_json_origin(path, body, include_csrf, &self.origin)
    }

    fn post_json_origin(&self, path: &str, body: &Value, include_csrf: bool, origin: &str) -> WebReply {
        let bytes = serde_json::to_vec(body).unwrap();
        self.sent_bodies.lock().unwrap().push((path.to_string(), bytes.clone()));
        let mut req = self
            .agent
            .post(format!("{}{path}", self.base))
            .header("content-type", "application/json")
            .header("accept", "application/json")
            .header("origin", origin)
            .header("sec-fetch-site", "same-origin");
        if let Some(c) = &self.cookie {
            req = req.header("cookie", &format!("__Host-veil_session={c}"));
        }
        if include_csrf {
            if let Some(csrf) = &self.csrf {
                req = req.header("x-veil-csrf", csrf);
            }
        }
        Self::finish(req.send(&bytes))
    }

    fn post_form(&self, path: &str, fields: &[(&str, &str)], include_csrf: bool) -> WebReply {
        let mut pairs: Vec<String> = fields
            .iter()
            .map(|(k, v)| format!("{}={}", url_enc(k), url_enc(v)))
            .collect();
        if include_csrf {
            if let Some(csrf) = &self.csrf {
                pairs.push(format!("_csrf={}", url_enc(csrf)));
            }
        }
        let encoded = pairs.join("&").into_bytes();
        self.sent_bodies.lock().unwrap().push((path.to_string(), encoded.clone()));
        let mut req = self
            .agent
            .post(format!("{}{path}", self.base))
            .header("content-type", "application/x-www-form-urlencoded")
            .header("origin", &self.origin)
            .header("sec-fetch-site", "same-origin");
        if let Some(c) = &self.cookie {
            req = req.header("cookie", &format!("__Host-veil_session={c}"));
        }
        Self::finish(req.send(&encoded))
    }
}

fn url_enc(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Real ES256 (P-256 ECDSA SHA-256) virtual WebAuthn passkey authenticator with
/// optional WebAuthn PRF support.
struct VirtualPasskey {
    cred_id: Vec<u8>,
    cred_id_b64: String,
    key_pair: KeyPair,
    sign_count: u32,
    prf_secret: Option<[u8; 32]>,
    bundle: Option<BrowserDeviceBundle>,
}

impl VirtualPasskey {
    fn new_with_prf(tag: u8) -> Self {
        let mut cred_id = vec![0x42, tag];
        cred_id.extend_from_slice(&veil_core::crypto::random_bytes::<16>());
        let cred_id_b64 = b64url_encode(&cred_id);
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("P-256 keypair");
        Self {
            cred_id,
            cred_id_b64,
            key_pair,
            sign_count: 1,
            prf_secret: Some([tag.wrapping_add(0x31); 32]),
            bundle: None,
        }
    }

    fn new_without_prf(tag: u8) -> Self {
        let mut p = Self::new_with_prf(tag);
        p.prf_secret = None;
        p
    }

    fn prf_eval(&self, prf_salt_b64: &str) -> Option<[u8; 32]> {
        let secret = self.prf_secret?;
        let mut h = blake3::Hasher::new_keyed(&secret);
        h.update(b"webauthn-prf-eval:");
        h.update(prf_salt_b64.as_bytes());
        Some(*h.finalize().as_bytes())
    }

    /// Encode COSE_Key map for ES256 (`{1: 2, 3: -7, -1: 1, -2: x, -3: y}`).
    fn cose_es256_public_key(&self) -> Vec<u8> {
        let raw = self.key_pair.public_key_raw();
        assert_eq!(raw.len(), 65, "uncompressed P-256 point must be 65 bytes");
        assert_eq!(raw[0], 0x04);
        let x = &raw[1..33];
        let y = &raw[33..65];
        let mut cbor = Vec::with_capacity(77);
        cbor.push(0xa5); // map(5)
        // 1: 2 (kty = EC2)
        cbor.push(0x01);
        cbor.push(0x02);
        // 3: -7 (alg = ES256; negative int -1 - n -> 0x20 | 6 = 0x26)
        cbor.push(0x03);
        cbor.push(0x26);
        // -1: 1 (crv = P-256; -1 -> 0x20)
        cbor.push(0x20);
        cbor.push(0x01);
        // -2: h'x' (-2 -> 0x21, 32-byte bstr -> 0x58, 0x20)
        cbor.push(0x21);
        cbor.push(0x58);
        cbor.push(0x20);
        cbor.extend_from_slice(x);
        // -3: h'y' (-3 -> 0x22, 32-byte bstr -> 0x58, 0x20)
        cbor.push(0x22);
        cbor.push(0x58);
        cbor.push(0x20);
        cbor.extend_from_slice(y);
        cbor
    }

    /// Build `attestationObject` CBOR (`{"fmt": "none", "attStmt": {}, "authData": h'...'}`).
    fn make_attestation_object(&self, rp_id: &str, sign_count: u32) -> Vec<u8> {
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&sha256(rp_id.as_bytes()));
        auth_data.push(0x45); // flags: UP (0x01) | UV (0x04) | AT (0x40)
        auth_data.extend_from_slice(&sign_count.to_be_bytes());
        auth_data.extend_from_slice(&[0u8; 16]); // AAGUID
        auth_data.extend_from_slice(&(self.cred_id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(&self.cred_id);
        auth_data.extend_from_slice(&self.cose_es256_public_key());

        let mut att = Vec::new();
        att.push(0xa3); // map(3)
        // "fmt": "none"
        att.push(0x63);
        att.extend_from_slice(b"fmt");
        att.push(0x64);
        att.extend_from_slice(b"none");
        // "attStmt": {}
        att.push(0x67);
        att.extend_from_slice(b"attStmt");
        att.push(0xa0);
        // "authData": bstr
        att.push(0x68);
        att.extend_from_slice(b"authData");
        if auth_data.len() < 256 {
            att.push(0x58);
            att.push(auth_data.len() as u8);
        } else {
            att.push(0x59);
            att.extend_from_slice(&(auth_data.len() as u16).to_be_bytes());
        }
        att.extend_from_slice(&auth_data);
        att
    }

    fn enroll(&mut self, web: &mut BrowserClient, person_name: &str, code: &str) -> Value {
        let begin = web.post_json("/web/passkey/register/begin", &json!({ "code": code }), false);
        assert_eq!(begin.status, 200, "register/begin failed: {}", begin.text());
        let bj = begin.json();
        assert_eq!(bj["person"], person_name);
        let challenge = bj["challenge"].as_str().expect("challenge");
        let prf_salt = bj["prf_salt"].as_str().expect("prf_salt");

        let client_data = serde_json::to_vec(&json!({
            "type": "webauthn.create",
            "challenge": challenge,
            "origin": web.origin,
            "crossOrigin": false,
        }))
        .unwrap();
        let att_obj = self.make_attestation_object(&web.rp_id, self.sign_count);

        let (prf_supported, public_identity) = match self.prf_eval(prf_salt) {
            Some(prf_out) => {
                // Generated inside WASM Worker in browser; plain private keys stay encrypted under `prf_out`.
                let b = seal_new_browser_device(person_name, &self.cred_id_b64, &prf_out).unwrap();
                let pub_id = b.public_identity.clone();
                self.bundle = Some(b);
                (true, Some(pub_id))
            }
            None => (false, None),
        };

        let finish = web.post_json(
            "/web/passkey/register/finish",
            &json!({
                "code": code,
                "credential_id": self.cred_id_b64,
                "client_data_json": b64url_encode(&client_data),
                "attestation_object": b64url_encode(&att_obj),
                "prf_supported": prf_supported,
                "prf_salt": prf_salt,
                "public_identity": public_identity,
            }),
            false,
        );
        assert_eq!(finish.status, 200, "register/finish failed: {}", finish.text());
        web.capture_cookie(&finish);
        assert!(web.cookie.is_some(), "passkey registration must set __Host-veil_session");
        let fj = finish.json();
        web.csrf = fj["csrf"].as_str().map(str::to_string);
        assert!(web.csrf.is_some(), "passkey registration must return CSRF token");
        fj
    }

    fn sign_in(&mut self, web: &mut BrowserClient, person_hint: Option<&str>) -> Value {
        let begin = web.post_json(
            "/web/passkey/login/begin",
            &match person_hint {
                Some(p) => json!({ "person": p }),
                None => json!({}),
            },
            false,
        );
        assert_eq!(begin.status, 200, "login/begin failed: {}", begin.text());
        let bj = begin.json();
        let challenge = bj["challenge"].as_str().expect("challenge");

        self.sign_count += 1;
        let finish = self.assert_with(web, challenge, &web.origin, &web.rp_id, self.sign_count);
        assert_eq!(finish.status, 200, "login/finish failed: {}", finish.text());
        web.capture_cookie(&finish);
        let fj = finish.json();
        web.csrf = fj["csrf"].as_str().map(str::to_string);
        fj
    }

    fn assert_with(&self, web: &BrowserClient, challenge: &str, origin: &str, rp_id: &str, sign_count: u32) -> WebReply {
        let client_data = serde_json::to_vec(&json!({
            "type": "webauthn.get",
            "challenge": challenge,
            "origin": origin,
            "crossOrigin": false,
        }))
        .unwrap();
        let mut auth_data = Vec::with_capacity(37);
        auth_data.extend_from_slice(&sha256(rp_id.as_bytes()));
        auth_data.push(0x05); // flags: UP (0x01) | UV (0x04)
        auth_data.extend_from_slice(&sign_count.to_be_bytes());

        let mut signed_payload = auth_data.clone();
        signed_payload.extend_from_slice(&sha256(&client_data));
        let sig = self.key_pair.sign(&signed_payload).expect("ES256 sign");

        web.post_json(
            "/web/passkey/login/finish",
            &json!({
                "credential_id": self.cred_id_b64,
                "client_data_json": b64url_encode(&client_data),
                "authenticator_data": b64url_encode(&auth_data),
                "signature": b64url_encode(&sig),
            }),
            false,
        )
    }
}

fn mint_enroll_code(hub: &TestHub, person: &Person) -> String {
    let r = hub
        .api()
        .post_json(Some(&person.token()), "/v1/sessions/web-enroll", &json!({}));
    assert_eq!(r.status, 200, "mint web-enroll failed: {}", String::from_utf8_lossy(&r.body));
    let code = r.json()["code"].as_str().expect("code").to_string();
    assert!(code.starts_with(WEB_ENROLL_PREFIX));
    code
}

fn catch_up(hub: &TestHub, project: &str) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        let r = hub.api().get(None, &format!("/v1/projects/{project}/q/log?limit=1"));
        if r.status != 202 {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn assert_no_canary_bytes(haystack: &[u8], canaries: &[&str], ctx: &str) {
    let text = String::from_utf8_lossy(haystack);
    for c in canaries {
        assert!(
            !haystack.windows(c.len()).any(|w| w == c.as_bytes()) && !text.contains(c),
            "plain secret canary '{c}' leaked on {ctx}"
        );
    }
}

// ---------------------------------------------------------------------------
// Guarantee 1: No route ever returns a plain secret.
// ---------------------------------------------------------------------------
#[test]
fn guarantee_1_no_route_ever_returns_a_plain_secret() {
    const CANARY_TEAM: &str = "CANARY_S26_TEAM_PLAIN_NEVER_991122";
    const CANARY_BILLING: &str = "CANARY_S26_BILLING_PLAIN_NEVER_334455";
    const CANARY_INFRA: &str = "CANARY_S26_INFRA_PLAIN_NEVER_667788";
    let all_canaries = [CANARY_TEAM, CANARY_BILLING, CANARY_INFRA];

    let hub = TestHub::start();
    let alice = hub.person("alice");
    let proj = unique("g1plain");
    let dir = alice.dir("g1");
    std::fs::create_dir_all(&dir).unwrap();
    alice.ok(&dir, &["init"]);
    alice.ok(&dir, &["remote", "add", "origin", &hub.url(&proj)]);
    write_files(
        &dir,
        &[
            ("public/readme.md", "# Public docs\n"),
            (".env", &format!("TEAM_KEY={CANARY_TEAM}\n")),
        ],
    );
    alice.commit_main(&dir, "initial secret");
    alice.ok(&dir, &["push"]);
    alice.ok(&dir, &["group", "create", "finance"]);
    alice.ok(&dir, &["group", "create", "ops"]);
    alice.ok(&dir, &["access", "public/", "public"]);
    alice.ok(&dir, &["access", "billing/", "finance"]);
    alice.ok(&dir, &["access", "infra/", "ops"]);
    write_files(
        &dir,
        &[
            ("billing/.env.stripe", &format!("STRIPE={CANARY_BILLING}\n")),
            ("infra/.env.prod", &format!("PROD={CANARY_INFRA}\n")),
        ],
    );
    alice.commit_main(&dir, "scoped secrets");
    alice.ok(&dir, &["push"]);
    catch_up(&hub, &proj);

    // Enroll and confirm Alice's PRF browser device, then enable `web_secrets` on the project.
    let code = mint_enroll_code(&hub, &alice);
    let mut web = BrowserClient::new(&hub);
    let mut pk = VirtualPasskey::new_with_prf(1);
    let enrolled = pk.enroll(&mut web, &alice.name, &code);
    let fp = enrolled["fingerprint"].as_str().expect("fingerprint").to_string();
    alice.ok(&dir, &["identity", "confirm", &fp]);

    let toggle = web.post_json(&format!("/v1/projects/{proj}/web-secrets"), &json!({ "enabled": true }), true);
    assert_eq!(toggle.status, 200, "enable web-secrets failed: {}", toggle.text());
    alice.ok(&dir, &["share-keys"]);

    // Open a PR touching a secret file so PR & diff endpoints also exercise sealed files.
    write_files(&dir, &[(".env", &format!("TEAM_KEY={CANARY_TEAM}_V2\n"))]);
    alice.ok(&dir, &["commit", "--no-advance", "-m", "update secret"]);
    alice.ok(&dir, &["tag", "set", "rot", "-r", "@-"]);
    alice.ok(&dir, &["push"]);
    catch_up(&hub, &proj);
    let rot_tip = hub.api().tips(Some(&alice.token()), &proj).unwrap().branches["rot"];
    let pr_res = web.post_json(
        &format!("/v1/projects/{proj}/prs"),
        &json!({ "head": rot_tip, "onto": "main", "title": "Rotate env" }),
        true,
    );
    assert_eq!(pr_res.status, 200, "{}", pr_res.text());
    let pr_id = pr_res.json()["id"].as_str().unwrap().to_string();

    // Every HTML route, static/worker asset, and JSON/binary API route MUST NEVER return plain secret bytes.
    let html_routes = [
        "/".to_string(),
        "/about".to_string(),
        "/login".to_string(),
        format!("/p/{proj}"),
        format!("/p/{proj}/tree"),
        format!("/p/{proj}/tree/billing"),
        format!("/p/{proj}/file/.env"),
        format!("/p/{proj}/file/billing/.env.stripe"),
        format!("/p/{proj}/file/infra/.env.prod"),
        format!("/p/{proj}/blame/.env"),
        format!("/p/{proj}/history/.env"),
        format!("/p/{proj}/log"),
        format!("/p/{proj}/commit/main"),
        format!("/p/{proj}/search?mode=grep&q=CANARY_S26"),
        format!("/p/{proj}/prs"),
        format!("/p/{proj}/prs/{pr_id}"),
        format!("/p/{proj}/admin"),
        format!("/p/{proj}/web/secrets.js"),
        format!("/p/{proj}/web/secret-worker.js"),
    ];
    for route in &html_routes {
        let r = web.get(route);
        assert!(r.status == 200 || r.status == 400 || r.status == 403, "unexpected status {} on {route}", r.status);
        assert_no_canary_bytes(&r.body, &all_canaries, route);
    }

    // `/q/file` still refuses sealed files even when `web_secrets` is ON.
    for sp in [".env", "billing/.env.stripe", "infra/.env.prod"] {
        let qf = web.get_api(&format!("/v1/projects/{proj}/q/file?rev=main&path={sp}"));
        assert_eq!(qf.status, 403, "/q/file must refuse {sp}: {}", qf.text());
        assert_eq!(qf.json()["code"], "sealed_file");
        assert_no_canary_bytes(&qf.body, &all_canaries, sp);
    }

    for api_route in [
        format!("/v1/projects/{proj}/q/tree?rev=main"),
        format!("/v1/projects/{proj}/q/log?rev=main"),
        format!("/v1/projects/{proj}/q/show?rev=main"),
        format!("/v1/projects/{proj}/q/history?rev=main&path=.env"),
        format!("/v1/projects/{proj}/q/diff?to=rot&from=main"),
        format!("/v1/projects/{proj}/q/search?mode=grep&q=CANARY_S26"),
        format!("/v1/projects/{proj}/q/grep?rev=main&pattern=CANARY_S26"),
        format!("/v1/projects/{proj}/prs/{pr_id}"),
        format!("/v1/projects/{proj}/prs/{pr_id}/diff"),
        format!("/v1/projects/{proj}/web/rings"),
    ] {
        let r = web.get_api(&api_route);
        assert_eq!(r.status, 200, "{api_route}: {}", r.text());
        assert_no_canary_bytes(&r.body, &all_canaries, &api_route);
    }
    let q_blame = web.get_api(&format!("/v1/projects/{proj}/q/blame?rev=main&path=.env"));
    assert!(q_blame.status == 400 || q_blame.status == 403, "blame on sealed file must fail: {}", q_blame.status);
    assert_no_canary_bytes(&q_blame.body, &all_canaries, "/q/blame .env");

    // `/web/ciphertext` returns ONLY encrypted `Object::Sealed` bytes (never plain secrets, and refuses plain files!).
    let plain_try = web.get_api(&format!("/v1/projects/{proj}/web/ciphertext?rev=main&path=public/readme.md"));
    assert_eq!(plain_try.status, 400, "ciphertext endpoint must refuse plain files");

    let ct_res = web.get_api(&format!("/v1/projects/{proj}/web/ciphertext?rev=main&path=.env"));
    assert_eq!(ct_res.status, 200, "ciphertext fetch failed: {}", ct_res.text());
    assert_no_canary_bytes(&ct_res.body, &all_canaries, "/web/ciphertext .env");

    // Decryption happens strictly in Worker WASM memory (`open_secret_in_worker`).
    let rings_res = web.get_api(&format!("/v1/projects/{proj}/web/rings")).json();
    let proj_fp = rings_res["project_fingerprint"].as_str().expect("project_fingerprint");
    let rings_str = serde_json::to_string(&rings_res["rings"]).unwrap();
    let oid = ct_res.header("x-veil-object-id").expect("x-veil-object-id header");
    let login_info = pk.sign_in(&mut web, Some(&alice.name));
    let prf_out = pk.prf_eval(login_info["prf_salt"].as_str().unwrap()).unwrap();
    let bundle = pk.bundle.as_ref().unwrap();
    let opened = open_secret_in_worker(
        &pk.cred_id_b64,
        &prf_out,
        &bundle.sealed_identity_hex,
        &rings_str,
        Some(proj_fp),
        Some(oid),
        &ct_res.body,
    )
    .expect("Worker must decrypt authorized secret");
    assert_eq!(opened.text.as_deref(), Some(format!("TEAM_KEY={CANARY_TEAM}\n").as_str()));
}

// ---------------------------------------------------------------------------
// Guarantee 2: An unconfirmed browser device gets no wrapped key (plus non-PRF fallback).
// ---------------------------------------------------------------------------
#[test]
fn guarantee_2_unconfirmed_browser_device_gets_no_wrapped_key() {
    let hub = TestHub::start();
    let alice = hub.person("alice");
    let proj = unique("g2unconf");
    let dir = alice.dir("g2");
    std::fs::create_dir_all(&dir).unwrap();
    alice.ok(&dir, &["init"]);
    alice.ok(&dir, &["remote", "add", "origin", &hub.url(&proj)]);
    write_files(
        &dir,
        &[
            ("public/hello.txt", "hello\n"),
            (".env", "UNCONFIRMED_MUST_NOT_GET=1\n"),
        ],
    );
    alice.commit_main(&dir, "init");
    alice.ok(&dir, &["push"]);
    catch_up(&hub, &proj);

    // Enable `web_secrets` first so ONLY confirmation stands between the browser and wrapped keys.
    let enable = hub.api().post_json(
        Some(&alice.token()),
        &format!("/v1/projects/{proj}/web-secrets"),
        &json!({ "enabled": true }),
    );
    assert_eq!(enable.status, 200, "{}", String::from_utf8_lossy(&enable.body));

    // 1. Enroll an UNCONFIRMED PRF browser device.
    let code = mint_enroll_code(&hub, &alice);
    let mut unconf_web = BrowserClient::new(&hub);
    let mut unconf_pk = VirtualPasskey::new_with_prf(2);
    let reg = unconf_pk.enroll(&mut unconf_web, &alice.name, &code);
    assert_eq!(reg["confirmed"], false);
    assert_eq!(reg["prf_supported"], true);
    let unconf_bundle = unconf_pk.bundle.as_ref().unwrap().clone();

    // Unconfirmed browser device CAN browse permitted plain files with its passkey session...
    let plain_page = unconf_web.get(&format!("/p/{proj}/file/public/hello.txt"));
    assert_eq!(plain_page.status, 200);
    assert!(plain_page.text().contains("hello"));

    // ...but `device_list` omits it from active `identities`, and `vl keys` wraps ZERO keys to it!
    let devs = hub
        .api()
        .get(Some(&alice.token()), &format!("/v1/people/{}/devices?project={proj}", alice.name))
        .json();
    let active_ids: Vec<&str> = devs["identities"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(
        !active_ids.contains(&unconf_bundle.public_identity.as_str()),
        "unconfirmed browser device must never appear in active identities"
    );

    alice.ok(&dir, &["share-keys"]);
    let server_rings = hub
        .api()
        .get(Some(&alice.token()), &format!("/v1/projects/{proj}/rings"))
        .json();
    for r in server_rings.as_array().unwrap() {
        let kr: KeyRing = serde_json::from_value(r.clone()).unwrap();
        let st = kr.verify().unwrap();
        assert!(
            !st.members.contains_key(&unconf_bundle.member_id),
            "unconfirmed browser device received a wrapped key in scope '{}'",
            kr.scope
        );
    }

    // Even a direct forged `POST /v1/projects/{p}/rings/team` granting the unconfirmed browser device is REFUSED!
    let team_val = &server_rings.as_array().unwrap()[0];
    let mem = Arc::new(MemoryBackend::new());
    mem.write(
        &veil_core::VPath::new(".veil/meta/keyrings/team.json").unwrap(),
        &serde_json::to_vec(team_val).unwrap(),
    )
    .unwrap();
    let kc = Keychain::new(mem, Some(alice.identity()), "forged".into());
    kc.set_format(veil_core::repo::REPO_FORMAT);
    // Seed local scope key by unwrapping from `team_val`
    kc.grant("team", &unconf_bundle.public_identity, &alice.name).unwrap();
    let forged_ring = kc.load_ring("team").unwrap().unwrap();
    let post_forged = hub.api().post_json(
        Some(&alice.token()),
        &format!("/v1/projects/{proj}/rings/team"),
        &serde_json::to_value(&forged_ring).unwrap(),
    );
    assert_eq!(post_forged.status, 403, "server must refuse ring wrapping to unconfirmed browser device");
    assert_eq!(post_forged.json()["code"], "unconfirmed_browser_device");

    // And the unconfirmed browser device gets `403 unconfirmed_browser_device` on `/web/rings` & `/web/ciphertext`.
    let r_rings = unconf_web.get_api(&format!("/v1/projects/{proj}/web/rings"));
    assert_eq!(r_rings.status, 403);
    assert_eq!(r_rings.json()["code"], "unconfirmed_browser_device");
    let r_ct = unconf_web.get_api(&format!("/v1/projects/{proj}/web/ciphertext?rev=main&path=.env"));
    assert_eq!(r_ct.status, 403);
    assert_eq!(r_ct.json()["code"], "unconfirmed_browser_device");

    // 2. Enroll a browser WITHOUT WebAuthn PRF: clear message, browsing works, never gets wrapped keys.
    let code_noprf = mint_enroll_code(&hub, &alice);
    let mut noprf_web = BrowserClient::new(&hub);
    let mut noprf_pk = VirtualPasskey::new_without_prf(3);
    let reg_noprf = noprf_pk.enroll(&mut noprf_web, &alice.name, &code_noprf);
    assert_eq!(reg_noprf["prf_supported"], false);
    assert!(
        reg_noprf["message"]
            .as_str()
            .unwrap_or("")
            .to_ascii_lowercase()
            .contains("can't open secrets"),
        "expected clear non-PRF message, got: {reg_noprf}"
    );
    assert_eq!(noprf_web.get(&format!("/p/{proj}/file/public/hello.txt")).status, 200);
    let sealed_html = noprf_web.get(&format!("/p/{proj}/file/.env"));
    assert_eq!(sealed_html.status, 200);
    assert!(
        sealed_html.text().to_ascii_lowercase().contains("can't open secrets")
            || sealed_html.text().contains("can&#x27;t open secrets"),
        "sealed file page must explain non-PRF browser limit: {}",
        sealed_html.text()
    );
    assert_eq!(noprf_web.get_api(&format!("/v1/projects/{proj}/web/rings")).status, 403);
}

// ---------------------------------------------------------------------------
// Guarantee 3: With the project setting off, no browser gets a wrapped key and no page has a decrypt path.
// ---------------------------------------------------------------------------
#[test]
fn guarantee_3_project_setting_off_gives_no_wrapped_key_and_no_decrypt_path() {
    let hub = TestHub::start();
    let hub_b = TestHub::beside(&hub);
    let alice = hub.person("alice");
    let bob = hub.person("bob");
    let proj = unique("g3off");
    let dir = alice.dir("g3");
    std::fs::create_dir_all(&dir).unwrap();
    alice.ok(&dir, &["init"]);
    alice.ok(&dir, &["remote", "add", "origin", &hub.url(&proj)]);
    write_files(
        &dir,
        &[
            ("public/app.rs", "pub fn main() {}\n"),
            (".env", "OFF_BY_DEFAULT_SECRET=topsecret\n"),
        ],
    );
    alice.commit_main(&dir, "init");
    alice.ok(&dir, &["push"]);
    alice.ok(&dir, &["group", "create", "devs"]);
    alice.ok(&dir, &["group", "add", "devs", &bob.name, "--confirm", &bob.fingerprint()]);
    alice.ok(&dir, &["access", "public/", "public", "devs"]);
    alice.commit_main(&dir, "devs access");
    alice.ok(&dir, &["push"]);
    catch_up(&hub, &proj);

    // Enroll AND confirm Alice's PRF browser device while `web_secrets` is OFF (default).
    let code = mint_enroll_code(&hub, &alice);
    let mut web = BrowserClient::new(&hub);
    let mut pk = VirtualPasskey::new_with_prf(4);
    let reg = pk.enroll(&mut web, &alice.name, &code);
    let fp = reg["fingerprint"].as_str().unwrap().to_string();
    alice.ok(&dir, &["identity", "confirm", &fp]);
    let bundle = pk.bundle.as_ref().unwrap().clone();

    // Non-admin (`bob`) CANNOT turn `web_secrets` on.
    let bob_try = hub.api().post_json(
        Some(&bob.token()),
        &format!("/v1/projects/{proj}/web-secrets"),
        &json!({ "enabled": true }),
    );
    assert_eq!(bob_try.status, 403);

    // With setting OFF:
    // (a) `GET /v1/people/alice/devices?project={proj}` omits the confirmed browser device from `identities`!
    let proj_devs = hub
        .api()
        .get(Some(&alice.token()), &format!("/v1/people/{}/devices?project={proj}", alice.name))
        .json();
    let proj_ids: Vec<&str> = proj_devs["identities"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(
        !proj_ids.contains(&bundle.public_identity.as_str()),
        "confirmed browser device must not be listed as active for a project with web_secrets=false"
    );

    // (b) `vl keys` wraps ZERO keys to the browser device, and a direct ring POST wrapping to it is refused (`403`).
    alice.ok(&dir, &["share-keys"]);
    let rings_arr = hub
        .api()
        .get(Some(&alice.token()), &format!("/v1/projects/{proj}/rings"))
        .json();
    let team_val = rings_arr
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["scope"] == "team")
        .unwrap();
    let team_kr: KeyRing = serde_json::from_value(team_val.clone()).unwrap();
    assert!(!team_kr.verify().unwrap().members.contains_key(&bundle.member_id));

    let mem = Arc::new(MemoryBackend::new());
    mem.write(
        &veil_core::VPath::new(".veil/meta/keyrings/team.json").unwrap(),
        &serde_json::to_vec(team_val).unwrap(),
    )
    .unwrap();
    let kc = Keychain::new(mem, Some(alice.identity()), "forged-off".into());
    kc.set_format(veil_core::repo::REPO_FORMAT);
    kc.grant("team", &bundle.public_identity, &alice.name).unwrap();
    let forged_off = kc.load_ring("team").unwrap().unwrap();
    let r_forged_off = hub.api().post_json(
        Some(&alice.token()),
        &format!("/v1/projects/{proj}/rings/team"),
        &serde_json::to_value(&forged_off).unwrap(),
    );
    assert_eq!(r_forged_off.status, 403);
    assert_eq!(r_forged_off.json()["code"], "web_secrets_disabled");

    // (c) No page has a decrypt path, and every Worker/secret asset & API route returns 403 `web_secrets_disabled`.
    let file_html = web.get(&format!("/p/{proj}/file/.env"));
    assert_eq!(file_html.status, 200);
    let txt = file_html.text();
    for forbidden in ["secret-worker", "secrets.js", "veil-show-secret", "veil_worker_open_secret"] {
        assert!(!txt.contains(forbidden), "file page had decrypt path '{forbidden}' while web_secrets=false");
    }
    let app_js = web.get("/static/app.js").text();
    for forbidden in ["secret-worker", "veil_worker_open_secret", "unwrap_key"] {
        assert!(!app_js.contains(forbidden), "app.js contained '{forbidden}'");
    }
    for disabled_route in [
        format!("/v1/projects/{proj}/web/rings"),
        format!("/v1/projects/{proj}/web/ciphertext?rev=main&path=.env"),
        format!("/p/{proj}/web/secrets.js"),
        format!("/p/{proj}/web/secret-worker.js"),
        format!("/p/{proj}/web/secret-worker.wasm"),
    ] {
        let r = web.get_api(&disabled_route);
        assert_eq!(r.status, 403, "{disabled_route} must be 403 when setting is off");
        assert_eq!(r.json()["code"], "web_secrets_disabled");
    }

    // (d) Admin page states the honest limit; turning `web_secrets` ON enables decryption, and turning it BACK OFF
    //     wipes `browser_device_rings` immediately across both servers (`hub` and `hub_b`).
    let admin_html = web.get(&format!("/p/{proj}/admin")).text();
    assert!(
        admin_html.contains("broken into") && admin_html.contains("web code"),
        "admin settings page must state the honest limit: {admin_html}"
    );
    let no_ack = web.post_form(&format!("/p/{proj}/admin/web-secrets"), &[("enabled", "true")], true);
    assert_eq!(no_ack.status, 400, "enabling without acknowledging limit must fail: {}", no_ack.text());
    let turn_on = web.post_form(
        &format!("/p/{proj}/admin/web-secrets"),
        &[("enabled", "true"), ("acknowledge_limit", "1")],
        true,
    );
    assert_eq!(turn_on.status, 303, "admin form toggle failed: {}", turn_on.text());
    alice.ok(&dir, &["share-keys"]);

    let file_on_html = web.get(&format!("/p/{proj}/file/.env")).text();
    assert!(
        file_on_html.contains("broken into") && file_on_html.contains("veil-show-secret"),
        "enabled sealed file page must show button and honest-limit notice: {file_on_html}"
    );
    let secrets_js = web.get(&format!("/p/{proj}/web/secrets.js")).text();
    assert!(
        secrets_js.contains("broken into") && secrets_js.contains("web code") && secrets_js.contains("window.confirm"),
        "secrets.js must confirm the honest limit on the first Show secret: {secrets_js}"
    );
    assert_eq!(web.get_api(&format!("/v1/projects/{proj}/web/rings")).status, 200);

    let mut web_b = BrowserClient::new(&hub_b);
    web_b.cookie = web.cookie.clone();
    web_b.csrf = web.csrf.clone();
    assert_eq!(web_b.get_api(&format!("/v1/projects/{proj}/web/rings")).status, 200);

    // Turn back OFF -> immediate 403 across both `hub` and `hub_b`!
    let turn_off = web.post_json(&format!("/v1/projects/{proj}/web-secrets"), &json!({ "enabled": false }), true);
    assert_eq!(turn_off.status, 200);
    assert_eq!(web.get_api(&format!("/v1/projects/{proj}/web/rings")).status, 403);
    assert_eq!(web_b.get_api(&format!("/v1/projects/{proj}/web/rings")).status, 403);
    assert_eq!(web_b.get_api(&format!("/p/{proj}/web/secret-worker.wasm")).status, 403);
}

// ---------------------------------------------------------------------------
// Guarantee 4: A browser device sees only the rings of folders its person may read;
//              removal (or browser sign-out) deletes its rings and rotates keys.
// ---------------------------------------------------------------------------
#[test]
fn guarantee_4_browser_device_sees_only_readable_folder_rings_and_removal_deletes_them() {
    let hub = TestHub::start();
    let hub_b = TestHub::beside(&hub);
    let alice = hub.person("alice");
    let bob = hub.person("bob");
    let proj = unique("g4rings");

    let dir = alice.dir("g4a");
    std::fs::create_dir_all(&dir).unwrap();
    alice.ok(&dir, &["init"]);
    alice.ok(&dir, &["remote", "add", "origin", &hub.url(&proj)]);
    write_files(&dir, &[(".env", "ROOT_TEAM=secret\n"), ("public/info.txt", "public\n")]);
    alice.commit_main(&dir, "root");
    alice.ok(&dir, &["push"]);

    alice.ok(&dir, &["group", "create", "finance"]);
    alice.ok(&dir, &["group", "create", "ops"]);
    alice.ok(&dir, &["group", "add", "finance", &bob.name, "--confirm", &bob.fingerprint()]);
    alice.ok(&dir, &["access", "public/", "public"]);
    alice.ok(&dir, &["access", "billing/", "finance"]);
    alice.ok(&dir, &["access", "infra/", "ops"]);
    write_files(
        &dir,
        &[
            ("billing/.env.stripe", "BILLING_G0=stripe_123\n"),
            ("infra/.env.ops", "OPS_ONLY=hidden_456\n"),
        ],
    );
    alice.commit_main(&dir, "scoped secrets");
    alice.ok(&dir, &["push"]);
    catch_up(&hub, &proj);

    let proj_fp = alice.project_fingerprint(&dir);
    let bob_dir = bob.dir("g4b");
    bob.clone_trusting(&hub.url(&proj), &bob_dir, &proj_fp);

    let enable = hub.api().post_json(
        Some(&alice.token()),
        &format!("/v1/projects/{proj}/web-secrets"),
        &json!({ "enabled": true }),
    );
    assert_eq!(enable.status, 200);

    // 1. Bob enrolls browser #1 and confirms it from `bob_dir`; Alice shares keys.
    let code1 = mint_enroll_code(&hub, &bob);
    let mut bob_web1 = BrowserClient::new(&hub);
    let mut bob_pk1 = VirtualPasskey::new_with_prf(5);
    let reg1 = bob_pk1.enroll(&mut bob_web1, &bob.name, &code1);
    let fp1 = reg1["fingerprint"].as_str().unwrap().to_string();
    bob.ok(&bob_dir, &["identity", "confirm", &fp1]);
    alice.ok(&dir, &["share-keys"]);

    let access = AccessPolicy::parse("public/ public\nbilling/ finance\ninfra/ ops\n");
    let billing_scope = rule_scope(&access, "billing");
    let infra_scope = rule_scope(&access, "infra");

    // Bob's browser sees ONLY `billing_scope` — NEVER `team` and NEVER `infra_scope`!
    let rings_resp = bob_web1.get_api(&format!("/v1/projects/{proj}/web/rings"));
    assert_eq!(rings_resp.status, 200, "{}", rings_resp.text());
    let rings_obj = rings_resp.json()["rings"].as_object().unwrap().clone();
    let scopes: Vec<String> = rings_obj.keys().cloned().collect();
    assert_eq!(scopes, vec![billing_scope.clone()], "Bob must see ONLY billing ring, got {scopes:?}");
    assert!(!rings_obj.contains_key("team"));
    assert!(!rings_obj.contains_key(&infra_scope));

    // Bob cannot fetch ciphertext for `.env` or `infra/.env.ops` (`404`), only `billing/.env.stripe`.
    assert_eq!(bob_web1.get_api(&format!("/v1/projects/{proj}/web/ciphertext?rev=main&path=.env")).status, 404);
    assert_eq!(
        bob_web1
            .get_api(&format!("/v1/projects/{proj}/web/ciphertext?rev=main&path=infra/.env.ops"))
            .status,
        404
    );
    let ct_bill = bob_web1.get_api(&format!("/v1/projects/{proj}/web/ciphertext?rev=main&path=billing/.env.stripe"));
    assert_eq!(ct_bill.status, 200, "{}", ct_bill.text());
    let oid_bill = ct_bill.header("x-veil-object-id").unwrap();
    let login1 = bob_pk1.sign_in(&mut bob_web1, Some(&bob.name));
    let prf1 = bob_pk1.prf_eval(login1["prf_salt"].as_str().unwrap()).unwrap();
    let bundle1 = bob_pk1.bundle.as_ref().unwrap().clone();
    let opened = open_secret_in_worker(
        &bob_pk1.cred_id_b64,
        &prf1,
        &bundle1.sealed_identity_hex,
        &serde_json::to_string(&rings_obj).unwrap(),
        Some(&proj_fp),
        Some(oid_bill),
        &ct_bill.body,
    )
    .unwrap();
    assert_eq!(opened.text.as_deref(), Some("BILLING_G0=stripe_123\n"));

    // 2. Removing Bob from `finance` IMMEDIATELY hides `billing_scope` on both `hub` and `hub_b`!
    alice.ok(&dir, &["group", "remove", "finance", &bob.name]);
    let mut bob_web1_b = BrowserClient::new(&hub_b);
    bob_web1_b.cookie = bob_web1.cookie.clone();
    assert!(
        bob_web1
            .get_api(&format!("/v1/projects/{proj}/web/rings"))
            .json()["rings"]
            .as_object()
            .unwrap()
            .is_empty()
    );
    assert!(
        bob_web1_b
            .get_api(&format!("/v1/projects/{proj}/web/rings"))
            .json()["rings"]
            .as_object()
            .unwrap()
            .is_empty()
    );

    // Re-add Bob to `finance` (confirming both his `vl` device and his previously-revoked browser device `fp1` per S2) and share keys again.
    alice.ok(&dir, &["group", "add", "finance", &bob.name, "--confirm", &bob.fingerprint(), "--confirm", &fp1]);
    alice.ok(&dir, &["share-keys"]);
    assert_eq!(
        bob_web1
            .get_api(&format!("/v1/projects/{proj}/web/rings"))
            .json()["rings"]
            .as_object()
            .unwrap()
            .len(),
        1
    );

    // 3. Removing Bob's browser device #1 (`vl identity remove`) deletes its rings immediately, kills its
    //    session across both servers, and rotates `billing_scope` so new secrets cannot be opened by it!
    let saved_cookie1 = bob_web1.cookie.clone().unwrap();
    bob.ok(&bob_dir, &["identity", "remove", &fp1]);

    bob_web1.cookie = Some(saved_cookie1.clone());
    bob_web1_b.cookie = Some(saved_cookie1);
    assert_eq!(bob_web1.get_api(&format!("/v1/projects/{proj}/web/rings")).status, 401);
    assert_eq!(bob_web1_b.get_api(&format!("/v1/projects/{proj}/web/rings")).status, 401);

    // Alice runs `vl keys` + seals a new secret -> key rotated to new generation, revoked browser #1 cannot open it!
    alice.ok(&dir, &["pull"]);
    alice.ok(&dir, &["share-keys"]);
    write_files(&dir, &[("billing/.env.stripe", "BILLING_POST_REMOVE=rotated_789\n")]);
    alice.commit_main(&dir, "post-remove secret");
    alice.ok(&dir, &["push"]);
    catch_up(&hub, &proj);

    // Enroll & confirm browser #2 so we can fetch the post-removal ring & ciphertext, then verify browser #1 CANNOT open it,
    // AND verify `POST /web/logout` on browser #2 ALSO revokes browser #2 and rotates keys!
    let code2 = mint_enroll_code(&hub, &bob);
    let mut bob_web2 = BrowserClient::new(&hub);
    let mut bob_pk2 = VirtualPasskey::new_with_prf(6);
    let reg2 = bob_pk2.enroll(&mut bob_web2, &bob.name, &code2);
    let fp2 = reg2["fingerprint"].as_str().unwrap().to_string();
    bob.ok(&bob_dir, &["pull"]);
    bob.ok(&bob_dir, &["identity", "confirm", &fp2]);
    alice.ok(&dir, &["share-keys"]);

    let rings2 = bob_web2.get_api(&format!("/v1/projects/{proj}/web/rings")).json()["rings"].clone();
    let ct_rot = bob_web2.get_api(&format!("/v1/projects/{proj}/web/ciphertext?rev=main&path=billing/.env.stripe"));
    assert_eq!(ct_rot.status, 200);
    let oid_rot = ct_rot.header("x-veil-object-id").unwrap();

    // Browser #1 (removed) CANNOT open `ct_rot` even if handed `rings2`!
    assert!(
        open_secret_in_worker(
            &bob_pk1.cred_id_b64,
            &prf1,
            &bundle1.sealed_identity_hex,
            &serde_json::to_string(&rings2).unwrap(),
            Some(&proj_fp),
            Some(oid_rot),
            &ct_rot.body,
        )
        .is_err(),
        "removed browser device #1 must not open secrets sealed after key rotation"
    );

    // Signing out browser #2 (`POST /web/logout`) revokes browser #2 like device removal:
    // its passkey credential & rings are deleted, and `vl` rotates keys for new secrets!
    let logout2 = bob_web2.post_form("/web/logout", &[], true);
    assert_eq!(logout2.status, 303, "logout failed: {}", logout2.text());
    let relogin2 = bob_pk2.assert_with(&bob_web2, "deadbeef", &bob_web2.origin, &bob_web2.rp_id, 99);
    assert!(relogin2.status == 400 || relogin2.status == 401, "revoked passkey must never sign in again");

    let devs_after_logout = hub
        .api()
        .get(Some(&alice.token()), &format!("/v1/people/{}/devices?project={proj}", bob.name))
        .json();
    let removed_list: Vec<&str> = devs_after_logout["removed"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let bundle2 = bob_pk2.bundle.as_ref().unwrap();
    assert!(
        removed_list.contains(&bundle2.public_identity.as_str()),
        "signed-out browser device must be marked removed so vl rotates keys"
    );

    // 4. Project-admin bar (`POST /v1/devices/remove` with `project`) deletes that project's
    //    `browser_device_rings`, hides `veil-show-secret`, and refuses `/web/rings` (`403`).
    let code3 = mint_enroll_code(&hub, &bob);
    let mut bob_web3 = BrowserClient::new(&hub);
    let mut bob_pk3 = VirtualPasskey::new_with_prf(26);
    let reg3 = bob_pk3.enroll(&mut bob_web3, &bob.name, &code3);
    let fp3 = reg3["fingerprint"].as_str().unwrap().to_string();
    bob.ok(&bob_dir, &["pull"]);
    bob.ok(&bob_dir, &["identity", "confirm", &fp3]);
    alice.ok(&dir, &["share-keys"]);
    assert_eq!(bob_web3.get_api(&format!("/v1/projects/{proj}/web/rings")).status, 200);

    let bundle3 = bob_pk3.bundle.as_ref().unwrap().clone();
    let bar_res = hub.api().post_json(
        Some(&alice.token()),
        "/v1/devices/remove",
        &json!({ "device": bundle3.public_identity, "project": proj }),
    );
    assert_eq!(bar_res.status, 200, "{}", String::from_utf8_lossy(&bar_res.body));
    assert_eq!(bob_web3.get_api(&format!("/v1/projects/{proj}/web/rings")).status, 403);
    assert_eq!(
        bob_web3
            .get_api(&format!("/v1/projects/{proj}/web/ciphertext?rev=main&path=billing/.env.stripe"))
            .status,
        403
    );
    let barred_page = bob_web3.get(&format!("/p/{proj}/file/billing/.env.stripe")).text();
    assert!(!barred_page.contains("veil-show-secret"), "barred browser device must not render Show secret: {barred_page}");
}

// ---------------------------------------------------------------------------
// Guarantee 5: The browser's private keys are never in a request body.
// ---------------------------------------------------------------------------
#[test]
fn guarantee_5_browser_private_keys_are_never_in_a_request_body() {
    let hub = TestHub::start();
    let alice = hub.person("alice");
    let proj = unique("g5priv");
    let dir = alice.dir("g5");
    std::fs::create_dir_all(&dir).unwrap();
    alice.ok(&dir, &["init"]);
    alice.ok(&dir, &["remote", "add", "origin", &hub.url(&proj)]);
    write_files(&dir, &[(".env", "G5_SECRET=abc\n"), ("README.md", "hi\n")]);
    alice.commit_main(&dir, "init");
    alice.ok(&dir, &["push"]);
    catch_up(&hub, &proj);

    let code = mint_enroll_code(&hub, &alice);
    let mut web = BrowserClient::new(&hub);
    let mut pk = VirtualPasskey::new_with_prf(7);
    let reg = pk.enroll(&mut web, &alice.name, &code);
    let fp = reg["fingerprint"].as_str().unwrap().to_string();
    alice.ok(&dir, &["identity", "confirm", &fp]);
    let _ = web.post_json(&format!("/v1/projects/{proj}/web-secrets"), &json!({ "enabled": true }), true);
    alice.ok(&dir, &["share-keys"]);
    let _ = pk.sign_in(&mut web, Some(&alice.name));
    let _ = web.get_api(&format!("/v1/projects/{proj}/web/rings"));
    let _ = web.get_api(&format!("/v1/projects/{proj}/web/ciphertext?rev=main&path=.env"));

    // 1. Inspect every request body sent during enrollment, sign-in, settings, ring fetch, and ciphertext fetch:
    //    none ever contains `signing_seed`, `sealed_identity_hex`, PRF bytes, or Alice's `vl` private keys!
    let alice_id_json: Value = serde_json::from_str(&alice.identity().to_json()).unwrap();
    let alice_seed = alice_id_json["signing_seed"].as_str().unwrap_or("NONE");
    let alice_x25519_sec = alice_id_json["secret"].as_str().unwrap_or("NONE");
    let bundle = pk.bundle.as_ref().unwrap();

    for (path, body) in web.sent_bodies.lock().unwrap().iter() {
        let s = String::from_utf8_lossy(body);
        assert!(!s.contains("signing_seed"), "private signing_seed sent in {path}");
        assert!(!s.contains(&bundle.sealed_identity_hex), "IndexedDB sealed identity sent in {path}");
        assert!(!s.contains(alice_seed), "vl signing_seed sent in {path}");
        assert!(!s.contains(alice_x25519_sec), "vl x25519 secret sent in {path}");
    }

    // 2. Server-side defense in depth: if a buggy client ever tries to include `signing_seed` or a private
    //    `Identity` JSON in registration, the server rejects it with `400`.
    let code_bad = mint_enroll_code(&hub, &alice);
    let begin_bad = web.post_json("/web/passkey/register/begin", &json!({ "code": code_bad }), false).json();
    let cd_bad = serde_json::to_vec(&json!({
        "type": "webauthn.create",
        "challenge": begin_bad["challenge"],
        "origin": web.origin,
    }))
    .unwrap();
    let pk_bad = VirtualPasskey::new_with_prf(8);
    let att_bad = pk_bad.make_attestation_object(&web.rp_id, 1);
    let bad_finish = web.post_json(
        "/web/passkey/register/finish",
        &json!({
            "code": code_bad,
            "credential_id": pk_bad.cred_id_b64,
            "client_data_json": b64url_encode(&cd_bad),
            "attestation_object": b64url_encode(&att_bad),
            "prf_supported": true,
            "prf_salt": begin_bad["prf_salt"],
            "public_identity": alice.identity().to_json(),
        }),
        false,
    );
    assert_eq!(bad_finish.status, 400, "server must reject private Identity JSON in public_identity");

    // 3. Also refuse reusing an existing `vl` device's public_identity as a browser device!
    let code_copy = mint_enroll_code(&hub, &alice);
    let begin_copy = web.post_json("/web/passkey/register/begin", &json!({ "code": code_copy }), false).json();
    let cd_copy = serde_json::to_vec(&json!({
        "type": "webauthn.create",
        "challenge": begin_copy["challenge"],
        "origin": web.origin,
    }))
    .unwrap();
    let pk_copy = VirtualPasskey::new_with_prf(9);
    let att_copy = pk_copy.make_attestation_object(&web.rp_id, 1);
    let copy_finish = web.post_json(
        "/web/passkey/register/finish",
        &json!({
            "code": code_copy,
            "credential_id": pk_copy.cred_id_b64,
            "client_data_json": b64url_encode(&cd_copy),
            "attestation_object": b64url_encode(&att_copy),
            "prf_supported": true,
            "prf_salt": begin_copy["prf_salt"],
            "public_identity": alice.identity().public_id(),
        }),
        false,
    );
    assert!(
        copy_finish.status == 400 || copy_finish.status == 409,
        "server must refuse registering a copy of a vl device key as a browser device: {}",
        copy_finish.text()
    );
}

// ---------------------------------------------------------------------------
// Guarantee 6: Web approvals count only under S21's rules.
// ---------------------------------------------------------------------------
#[test]
fn guarantee_6_web_approvals_count_only_under_s21_rules() {
    let hub = TestHub::start();
    let alice = hub.person("alice");
    let bob = hub.person("bob");
    let carol = hub.person("carol");
    let proj = unique("g6s21");

    let dir = alice.dir("g6");
    std::fs::create_dir_all(&dir).unwrap();
    alice.ok(&dir, &["init"]);
    alice.ok(&dir, &["remote", "add", "origin", &hub.url(&proj)]);
    write_files(
        &dir,
        &[
            ("infra/deploy.sh", "#!/bin/sh\necho v1\n"),
            ("docs/runbook.md", "runbook v1\n"),
            ("public/readme.md", "hi\n"),
        ],
    );
    alice.commit_main(&dir, "initial files");
    alice.ok(&dir, &["push"]);

    alice.ok(&dir, &["group", "create", "devs"]);
    alice.ok(&dir, &["group", "create", "ops"]);
    alice.ok(&dir, &["group", "add", "devs", &bob.name, "--confirm", &bob.fingerprint()]);
    alice.ok(&dir, &["group", "add", "ops", &carol.name, "--confirm", &carol.fingerprint()]);
    alice.ok(&dir, &["access", "public/", "public", "devs", "ops"]);
    alice.ok(&dir, &["access", "docs/", "public", "ops"]);
    alice.ok(&dir, &["access", "infra/", "ops"]);
    write_files(
        &dir,
        &[(
            ".veilrules",
            "[branches.main]\nprotected = true\n\n[review]\nnormal = { approvals = 1, people_only = true }\nhigh = { approvals = 1, people_only = true }\nhigh_risk_paths = [\"infra/\"]\n",
        )],
    );
    alice.commit_main(&dir, "groups, access, and protected main rules");
    alice.ok(&dir, &["push"]);
    catch_up(&hub, &proj);

    // Enroll passkey browser sessions for Alice (author), Bob (`devs` only, cannot write `docs/` or see `infra/`), and Carol (`ops`, can write all).
    let mut alice_web = BrowserClient::new(&hub);
    let mut alice_pk = VirtualPasskey::new_with_prf(10);
    alice_pk.enroll(&mut alice_web, &alice.name, &mint_enroll_code(&hub, &alice));

    let mut bob_web = BrowserClient::new(&hub);
    let mut bob_pk = VirtualPasskey::new_with_prf(11);
    bob_pk.enroll(&mut bob_web, &bob.name, &mint_enroll_code(&hub, &bob));

    let mut carol_web = BrowserClient::new(&hub);
    let mut carol_pk = VirtualPasskey::new_with_prf(12);
    carol_pk.enroll(&mut carol_web, &carol.name, &mint_enroll_code(&hub, &carol));

    // Rule 2a (visible PR with partial write): PR touching `public/readme.md` (Bob can write) + `docs/runbook.md` (Bob can read via `public`, cannot write).
    let api = hub.api();
    let base = api.tips(Some(&alice.token()), &proj).unwrap().branches["main"];
    let chg_docs = api
        .post_json(
            Some(&alice.token()),
            &format!("/v1/projects/{proj}/changes"),
            &json!({
                "base": base,
                "description": "update docs and readme",
                "edits": [
                    { "path": "public/readme.md", "put": { "text": "hi docs\n" } },
                    { "path": "docs/runbook.md", "put": { "text": "runbook v2\n" } }
                ]
            }),
        )
        .json();
    let head_docs = chg_docs["snapshot"].as_str().unwrap().to_string();
    let pr_docs = alice_web
        .post_json(
            &format!("/v1/projects/{proj}/prs"),
            &json!({ "head": head_docs, "onto": "main", "title": "Docs v2" }),
            true,
        )
        .json();
    let pr_docs_id = pr_docs["id"].as_str().unwrap().to_string();
    let patch_docs = pr_docs["patch"].as_str().unwrap().to_string();
    assert_eq!(bob_web.get(&format!("/p/{proj}/prs/{pr_docs_id}")).status, 200, "Bob can read docs PR");
    let bob_partial = bob_web.post_json(
        &format!("/v1/projects/{proj}/prs/{pr_docs_id}/reviews"),
        &json!({ "patch": patch_docs, "verdict": "approve", "body": "bob partial write" }),
        true,
    );
    assert_eq!(bob_partial.status, 403, "Bob lacks write on docs/runbook.md so approval must fail with 403");

    // Alice opens a high-risk PR touching hidden `infra/deploy.sh`.
    let chg1 = api
        .post_json(
            Some(&alice.token()),
            &format!("/v1/projects/{proj}/changes"),
            &json!({
                "base": base,
                "description": "update deploy",
                "edits": [{ "path": "infra/deploy.sh", "put": { "text": "#!/bin/sh\necho v2\n" } }]
            }),
        )
        .json();
    let head1 = chg1["snapshot"].as_str().unwrap().to_string();
    let pr_created = alice_web
        .post_json(
            &format!("/v1/projects/{proj}/prs"),
            &json!({ "head": head1, "onto": "main", "title": "Deploy v2" }),
            true,
        )
        .json();
    let pr_id = pr_created["id"].as_str().unwrap().to_string();
    let patch1 = pr_created["patch"].as_str().unwrap().to_string();

    // Rule 1: Author (`alice`) self-approval in the browser is REFUSED (`403`).
    let self_rev = alice_web.post_form(
        &format!("/p/{proj}/prs/{pr_id}/reviews"),
        &[("patch", &patch1), ("verdict", "approve"), ("body", "self lgtm")],
        true,
    );
    assert_eq!(self_rev.status, 403, "author self-approval must fail");

    // Rule 2b: Reviewer who cannot read/write hidden `infra/deploy.sh` (`bob`) gets `404` (invisible PR), even when mixed with `public/readme.md`!
    let bob_rev = bob_web.post_json(
        &format!("/v1/projects/{proj}/prs/{pr_id}/reviews"),
        &json!({ "patch": patch1, "verdict": "approve", "body": "bob tries" }),
        true,
    );
    assert_eq!(bob_rev.status, 404, "Hidden infra PR must return 404 to Bob: {}", bob_rev.text());

    let chg_mixed = api
        .post_json(
            Some(&alice.token()),
            &format!("/v1/projects/{proj}/changes"),
            &json!({
                "base": head1,
                "description": "also readme",
                "edits": [{ "path": "public/readme.md", "put": { "text": "hi v2\n" } }]
            }),
        )
        .json();
    let head_mixed = chg_mixed["snapshot"].as_str().unwrap().to_string();
    let upd_mixed = api.post_json(
        Some(&alice.token()),
        &format!("/v1/projects/{proj}/prs/{pr_id}/revisions"),
        &json!({ "head": head_mixed }),
    );
    assert_eq!(upd_mixed.status, 200, "{}", String::from_utf8_lossy(&upd_mixed.body));
    let patch_mixed = upd_mixed.json()["patch"].as_str().unwrap().to_string();

    let bob_mixed_rev = bob_web.post_json(
        &format!("/v1/projects/{proj}/prs/{pr_id}/reviews"),
        &json!({ "patch": patch_mixed, "verdict": "approve", "body": "bob hidden mixed" }),
        true,
    );
    assert_eq!(bob_mixed_rev.status, 404, "Mixed PR touching hidden infra/deploy.sh must stay 404 to Bob");

    // Rule 3: Agent session and CI runner session CANNOT submit web reviews (`403` / `401`).
    let agt = api
        .post_json(
            Some(&carol.token()),
            "/v1/sessions/agent",
            &json!({ "project": proj, "attribution": { "agent": "bot" }, "only": [] }),
        )
        .json();
    let agt_tok = agt["token"].as_str().unwrap();
    let agt_try = api.post_json(
        Some(agt_tok),
        &format!("/v1/projects/{proj}/prs/{pr_id}/reviews"),
        &json!({ "patch": patch_mixed, "verdict": "approve" }),
    );
    assert!(agt_try.status == 401 || agt_try.status == 403, "agent must not submit web review without device sig");
    let ci = api
        .post_json(
            Some(&carol.token()),
            "/v1/sessions/ci",
            &json!({ "project": proj }),
        )
        .json();
    let ci_tok = ci["token"].as_str().unwrap();
    let ci_try = api.post_json(
        Some(ci_tok),
        &format!("/v1/projects/{proj}/prs/{pr_id}/reviews"),
        &json!({ "patch": patch_mixed, "verdict": "approve" }),
    );
    assert!(ci_try.status == 401 || ci_try.status == 403, "CI runner session must never approve PRs");

    // Rule 4: Stale patch hash is refused (`409`).
    let stale = carol_web.post_json(
        &format!("/v1/projects/{proj}/prs/{pr_id}/reviews"),
        &json!({ "patch": patch1, "verdict": "approve" }),
        true,
    );
    assert_eq!(stale.status, 409);

    // Rule 5: Carol (`ops` + `public` write access) approves in the browser (HTML form, no `identity.json`!) -> gate passes!
    let carol_ok = carol_web.post_form(
        &format!("/p/{proj}/prs/{pr_id}/reviews"),
        &[("patch", &patch_mixed), ("verdict", "approve"), ("body", "Approved in browser")],
        true,
    );
    assert_eq!(carol_ok.status, 303, "Carol HTML review form failed: {}", carol_ok.text());
    let pr_after_carol = alice_web.get_api(&format!("/v1/projects/{proj}/prs/{pr_id}")).json();
    assert_eq!(pr_after_carol["review"]["ready"], true, "Carol's web approval must satisfy S21 gate: {pr_after_carol}");

    // Rule 6: Carol submits `request-changes` -> holds the PR (`ready == false`)!
    let carol_hold = carol_web.post_form(
        &format!("/p/{proj}/prs/{pr_id}/reviews"),
        &[("patch", &patch_mixed), ("verdict", "request-changes"), ("body", "Wait")],
        true,
    );
    assert_eq!(carol_hold.status, 303);
    assert_eq!(
        alice_web.get_api(&format!("/v1/projects/{proj}/prs/{pr_id}")).json()["review"]["ready"],
        false
    );

    // Carol re-approves -> `ready == true`.
    let carol_re = carol_web.post_form(
        &format!("/p/{proj}/prs/{pr_id}/reviews"),
        &[("patch", &patch_mixed), ("verdict", "approve"), ("body", "Fixed")],
        true,
    );
    assert_eq!(carol_re.status, 303);
    assert_eq!(
        alice_web.get_api(&format!("/v1/projects/{proj}/prs/{pr_id}")).json()["review"]["ready"],
        true
    );

    // Rule 7: Removing Carol from `ops` immediately invalidates Carol's approval at gate evaluation time!
    alice.ok(&dir, &["group", "remove", "ops", &carol.name]);
    assert_eq!(
        alice_web.get_api(&format!("/v1/projects/{proj}/prs/{pr_id}")).json()["review"]["ready"],
        false,
        "approval from reviewer who lost write access must no longer count"
    );
    alice.ok(&dir, &["group", "add", "ops", &carol.name, "--confirm", &carol.fingerprint()]);
    assert_eq!(
        alice_web.get_api(&format!("/v1/projects/{proj}/prs/{pr_id}")).json()["review"]["ready"],
        true
    );

    // Rule 8: Changing PR files dismisses the approval (`ready == false`) until re-approved, then landing succeeds!
    let chg3 = api
        .post_json(
            Some(&alice.token()),
            &format!("/v1/projects/{proj}/changes"),
            &json!({
                "base": head_mixed,
                "description": "v3",
                "edits": [{ "path": "infra/deploy.sh", "put": { "text": "#!/bin/sh\necho v3\n" } }]
            }),
        )
        .json();
    let head3 = chg3["snapshot"].as_str().unwrap();
    let upd3 = api
        .post_json(
            Some(&alice.token()),
            &format!("/v1/projects/{proj}/prs/{pr_id}/revisions"),
            &json!({ "head": head3 }),
        )
        .json();
    let patch3 = upd3["patch"].as_str().unwrap().to_string();
    assert_eq!(upd3["review"]["ready"], false, "file change must dismiss web approval");

    let land_blocked = alice_web.post_form(&format!("/p/{proj}/prs/{pr_id}/land"), &[], true);
    assert!(land_blocked.status == 403 || land_blocked.status == 409 || land_blocked.status == 422);

    let carol_v3 = carol_web.post_form(
        &format!("/p/{proj}/prs/{pr_id}/reviews"),
        &[("patch", &patch3), ("verdict", "approve"), ("body", "v3 good")],
        true,
    );
    assert_eq!(carol_v3.status, 303);
    let landed = alice_web.post_form(&format!("/p/{proj}/prs/{pr_id}/land"), &[], true);
    assert_eq!(landed.status, 303, "approved PR must land cleanly: {}", landed.text());
}

// ---------------------------------------------------------------------------
// Guarantee 7 (and BUG-1871 end-to-end): `vl web` passkey enrollment, single-use
// codes, WebAuthn origin/rpId/signCount checks, and removal of `/web/login`.
// ---------------------------------------------------------------------------
#[test]
fn guarantee_7_passkey_enrollment_via_vl_web_replaces_identity_file_sign_in() {
    let hub = TestHub::start();
    let alice = hub.person("alice");
    let proj = unique("g7vlweb");
    let dir = alice.dir("g7");
    std::fs::create_dir_all(&dir).unwrap();
    alice.ok(&dir, &["init"]);
    alice.ok(&dir, &["remote", "add", "origin", &hub.url(&proj)]);
    write_files(&dir, &[(".env", "VL_WEB_E2E=works\n"), ("README.md", "# E2E\n")]);
    alice.commit_main(&dir, "init");
    alice.ok(&dir, &["push"]);
    catch_up(&hub, &proj);

    // 1. Old `/web/login` (`identity.json` challenge endpoint) is gone (`404` / `405`).
    let mut web = BrowserClient::new(&hub);
    let old_login = web.post_json("/web/login", &json!({}), false);
    assert!(old_login.status == 404 || old_login.status == 405, "old /web/login must be removed");

    // 2. Run actual `vl web --json` CLI command!
    let out = alice.ok(&dir, &["web", "--json"]);
    let enroll_json: Value = serde_json::from_str(&out).expect("vl web --json output");
    let code = enroll_json["code"].as_str().expect("code").to_string();
    assert!(code.starts_with(WEB_ENROLL_PREFIX));
    assert!(enroll_json["url"].as_str().unwrap().contains(&code));

    // 3. Enroll passkey with `code`; replaying the single-use `code` MUST fail (`401` / `400`).
    let mut pk = VirtualPasskey::new_with_prf(20);
    let reg = pk.enroll(&mut web, &alice.name, &code);
    let fp = reg["fingerprint"].as_str().unwrap().to_string();

    let replay_begin = web.post_json("/web/passkey/register/begin", &json!({ "code": code }), false);
    assert!(replay_begin.status == 400 || replay_begin.status == 401, "single-use enrollment code must not replay");

    // 4. WebAuthn phishing & replay defenses: wrong `origin`, wrong `rpIdHash`, and cloned/replayed `signCount` all fail!
    let b1 = web.post_json("/web/passkey/login/begin", &json!({ "person": alice.name }), false).json();
    let bad_origin = pk.assert_with(&web, b1["challenge"].as_str().unwrap(), "https://phishing.example", &web.rp_id, 10);
    assert!(bad_origin.status == 400 || bad_origin.status == 401 || bad_origin.status == 403);

    let b2 = web.post_json("/web/passkey/login/begin", &json!({ "person": alice.name }), false).json();
    let bad_rp = pk.assert_with(&web, b2["challenge"].as_str().unwrap(), &web.origin, "phishing.example", 10);
    assert!(bad_rp.status == 400 || bad_rp.status == 401);

    // Valid sign-in advances `sign_count` to 5; replaying `sign_count = 5` on next challenge fails!
    let b3 = web.post_json("/web/passkey/login/begin", &json!({ "person": alice.name }), false).json();
    let ok_login = pk.assert_with(&web, b3["challenge"].as_str().unwrap(), &web.origin, &web.rp_id, 5);
    assert_eq!(ok_login.status, 200);
    web.capture_cookie(&ok_login);
    web.csrf = ok_login.json()["csrf"].as_str().map(str::to_string);

    let b4 = web.post_json("/web/passkey/login/begin", &json!({ "person": alice.name }), false).json();
    let stale_cnt = pk.assert_with(&web, b4["challenge"].as_str().unwrap(), &web.origin, &web.rp_id, 5);
    assert_eq!(stale_cnt.status, 401, "non-increasing WebAuthn signCount must be rejected");

    // 5. Confirm browser device via `vl identity confirm <fp>` after enabling `web_secrets` -> immediate key sharing!
    let _ = web.post_json(&format!("/v1/projects/{proj}/web-secrets"), &json!({ "enabled": true }), true);
    alice.ok(&dir, &["identity", "confirm", &fp]);

    let rings = web.get_api(&format!("/v1/projects/{proj}/web/rings")).json();
    let proj_fp = rings["project_fingerprint"].as_str().unwrap();
    let ct = web.get_api(&format!("/v1/projects/{proj}/web/ciphertext?rev=main&path=.env"));
    assert_eq!(ct.status, 200, "{}", ct.text());
    let prf = pk.prf_eval(ok_login.json()["prf_salt"].as_str().unwrap()).unwrap();
    let opened = open_secret_in_worker(
        &pk.cred_id_b64,
        &prf,
        &pk.bundle.as_ref().unwrap().sealed_identity_hex,
        &serde_json::to_string(&rings["rings"]).unwrap(),
        Some(proj_fp),
        ct.header("x-veil-object-id"),
        &ct.body,
    )
    .unwrap();
    assert_eq!(opened.text.as_deref(), Some("VL_WEB_E2E=works\n"));
}
