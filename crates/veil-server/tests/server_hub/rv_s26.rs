//! Review `rv-s26` of milestone S26, secrets in the browser (`docs/HUB.md`
//! §13.40): reproductions of BUG-1900 to BUG-1906 (`docs/BUGS.md`), and the
//! guarantees `web_secrets::guarantee_1…7` leave unproven:
//!
//! * a browser session, confirmed or not, setting on or off, gets no wrapped
//!   key from the routes older than S26
//!   (`a_browser_session_gets_no_wrapped_key_from_the_routes_older_than_s26`);
//! * passkey challenges are single use, expire, and are bound to their
//!   ceremony and person; an enrollment code expires; the session keeps S25's
//!   cookie and same-origin rules
//!   (`passkey_challenges_and_enrollment_codes_are_single_use_expire_and_bind_their_person`);
//! * only an admin changes the project setting, never across sites, and the
//!   change is recorded (`only_an_admin_changes_the_setting_and_it_is_recorded`);
//! * turning the setting off rotates the keys away from the browser device
//!   (`turning_the_setting_off_rotates_keys_away_from_the_browser_device`);
//! * right after an access change, or after someone leaves a group, their
//!   browser device gets neither the folder's ring nor its secret's bytes
//!   (`an_access_change_hides_a_folders_ring_and_secret_at_once`,
//!   `leaving_a_group_hides_the_folders_ring_and_secret_bytes_at_once`);
//! * agent sessions and CI runners use no route of S26, also with a
//!   browser's headers (`agent_and_runner_sessions_use_no_route_of_s26`).
//!
//! The key wrapping in WASM is `veil-core`'s portable test
//! `web_browser_device_sealing_is_authenticated_randomised_and_domain_separated`.

use rcgen::SigningKey as _;
use serde_json::{json, Value};
use veil_core::{
    crypto::domains::{SIG_CONTEXT_HUB_LOGIN, SIG_CONTEXT_MEMBER_BINDING},
    hub::{
        web::{b64url_encode, sha256},
        wire::login_message,
    },
    identity::parse_public_identity,
    keychain::KeyRing,
    Identity,
};

use crate::{
    support::*,
    web_secrets::{catch_up, mint_enroll_code, BrowserClient, VirtualPasskey, WebReply},
};

/// A project of `admin`'s with one public file and one secret (`.env`).
fn project_with_secret(hub: &TestHub, admin: &Person, tag: &str) -> (String, std::path::PathBuf) {
    let proj = unique(tag);
    let dir = admin.dir(tag);
    std::fs::create_dir_all(&dir).unwrap();
    admin.ok(&dir, &["init"]);
    admin.ok(&dir, &["remote", "add", "origin", &hub.url(&proj)]);
    write_files(&dir, &[("public/readme.md", "# docs\n"), (".env", "RV_S26_SECRET=first\n")]);
    admin.commit_main(&dir, "init");
    admin.ok(&dir, &["push"]);
    admin.ok(&dir, &["access", "public/", "public"]);
    catch_up(hub, &proj);
    (proj, dir)
}

/// The project's `team` key ring, as the server stores it.
fn team_ring(hub: &TestHub, token: &str, proj: &str) -> Value {
    let r = hub.api().get(Some(token), &format!("/v1/projects/{proj}/rings"));
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    r.json().as_array().unwrap().iter().find(|r| r["scope"] == "team").expect("the team ring").clone()
}

/// `vl`'s request after any change of a key ring: the ring, sent to the server.
fn send_ring(hub: &TestHub, token: &str, proj: &str, ring: &Value) -> Reply {
    hub.api().post_json(Some(token), &format!("/v1/projects/{proj}/rings/team"), ring)
}

/// A public identity with `signer`'s signing key and binding, and the
/// encryption key of `victim`: whoever holds a signing key can make one, the
/// binding only says that the signing key chose the encryption key.
fn identity_with_the_encryption_key_of(victim: &Identity, signer: &Identity) -> String {
    let x25519 = parse_public_identity(&victim.public_id()).unwrap().x25519;
    let forged = format!("{}{}{}", victim.public_hex(), signer.verifying_hex(), signer.sign(SIG_CONTEXT_MEMBER_BINDING, &x25519));
    let parsed = parse_public_identity(&forged).expect("the identity parses and its binding verifies");
    assert_eq!(parsed.signing_hex().as_deref(), Some(signer.verifying_hex().as_str()));
    forged
}

/// Enroll `pk` with `code`, sending `public_identity` as the browser's device
/// identity (`None`: a browser without PRF). The answer of `register/finish`.
fn enroll_with(pk: &VirtualPasskey, web: &mut BrowserClient, code: &str, public_identity: Option<&str>) -> WebReply {
    let begin = web.post_json("/web/passkey/register/begin", &json!({ "code": code }), false);
    assert_eq!(begin.status, 200, "register/begin: {}", begin.text());
    let bj = begin.json();
    let client_data = serde_json::to_vec(&json!({
        "type": "webauthn.create",
        "challenge": bj["challenge"],
        "origin": web.origin,
        "crossOrigin": false,
    }))
    .unwrap();
    let att = pk.make_attestation_object(&web.rp_id, 1);
    let finish = web.post_json(
        "/web/passkey/register/finish",
        &json!({
            "code": code,
            "credential_id": pk.cred_id_b64,
            "client_data_json": b64url_encode(&client_data),
            "attestation_object": b64url_encode(&att),
            "prf_supported": public_identity.is_some(),
            "prf_salt": bj["prf_salt"],
            "public_identity": public_identity,
        }),
        false,
    );
    if finish.status == 200 {
        web.capture_cookie(&finish);
        web.csrf = finish.json()["csrf"].as_str().map(str::to_string);
    }
    finish
}

/// A new login challenge.
fn login_challenge(web: &BrowserClient, person: Option<&str>) -> String {
    let body = match person {
        Some(p) => json!({ "person": p }),
        None => json!({}),
    };
    let r = web.post_json("/web/passkey/login/begin", &body, false);
    assert_eq!(r.status, 200, "login/begin: {}", r.text());
    r.json()["challenge"].as_str().expect("a challenge").to_string()
}

/// `pk`'s assertion over `challenge` with the authenticator `flags` given
/// (`0x01` user present, `0x04` user verified).
fn assert_with_flags(pk: &VirtualPasskey, web: &BrowserClient, challenge: &str, flags: u8, sign_count: u32) -> WebReply {
    let client_data = serde_json::to_vec(&json!({
        "type": "webauthn.get",
        "challenge": challenge,
        "origin": web.origin,
        "crossOrigin": false,
    }))
    .unwrap();
    let mut auth_data = Vec::with_capacity(37);
    auth_data.extend_from_slice(&sha256(web.rp_id.as_bytes()));
    auth_data.push(flags);
    auth_data.extend_from_slice(&sign_count.to_be_bytes());
    let mut signed = auth_data.clone();
    signed.extend_from_slice(&sha256(&client_data));
    let sig = pk.key_pair.sign(&signed).expect("ES256 signature");
    web.post_json(
        "/web/passkey/login/finish",
        &json!({
            "credential_id": pk.cred_id_b64,
            "client_data_json": b64url_encode(&client_data),
            "authenticator_data": b64url_encode(&auth_data),
            "signature": b64url_encode(&sig),
        }),
        false,
    )
}

fn count(hub: &TestHub, sql: &str, bind: &str) -> i64 {
    let db = hub.hub().db.clone();
    hub.rt.block_on(sqlx::query_scalar::<_, i64>(sql).bind(bind).fetch_one(&db)).expect("count")
}

fn exec(hub: &TestHub, sql: &str, bind: &str) -> u64 {
    let db = hub.hub().db.clone();
    hub.rt.block_on(sqlx::query(sql).bind(bind).execute(&db)).expect("statement").rows_affected()
}

// ---------------------------------------------------------------------------
// BUG-1900: the server matches a key ring's members to devices by encryption
// key alone, over every person's devices.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "BUG-1900: a stranger's pending device that names an admin's encryption key makes the server refuse every key ring that holds the admin"]
fn bug_1900_a_strangers_pending_device_never_blocks_a_key_ring_update() {
    let hub = TestHub::start();
    let alice = hub.person("alice");
    let (proj, _dir) = project_with_secret(&hub, &alice, "rv1900a");
    let token = alice.token();
    let ring = team_ring(&hub, &token, &proj);
    let before = send_ring(&hub, &token, &proj, &ring);
    assert_eq!(before.status, 200, "the admin's own ring is accepted: {}", String::from_utf8_lossy(&before.body));

    // Mallory never signed in and has no account. She signs in under the
    // admin's name with her own signing key and the admin's encryption key:
    // a pending device, as any sign-in under a taken name is (§13.11).
    let mallory = Identity::generate("mallory");
    let forged = identity_with_the_encryption_key_of(&alice.identity(), &mallory);
    let api = hub.api();
    let ch = api.post_json(None, "/v1/auth/challenge", &json!({ "key": mallory.verifying_hex() }));
    assert_eq!(ch.status, 200);
    let challenge = ch.json()["challenge"].as_str().unwrap().to_string();
    let login = api.post_json(
        None,
        "/v1/auth/login",
        &json!({
            "key": mallory.verifying_hex(),
            "challenge": challenge,
            "hub": hub.authority(),
            "signature": mallory.sign(SIG_CONTEXT_HUB_LOGIN, &login_message(&hub.authority(), &challenge)),
            "identity": forged,
            "name": alice.name,
        }),
    );
    assert_eq!(login.status, 409, "a pending device, no session: {}", String::from_utf8_lossy(&login.body));

    // The admin's key rings are still hers to change.
    let after = send_ring(&hub, &token, &proj, &ring);
    assert_eq!(
        after.status,
        200,
        "a stranger's pending device blocked the admin's key ring: {}",
        String::from_utf8_lossy(&after.body)
    );
}

#[test]
#[ignore = "BUG-1900: another person's browser device that names an admin's encryption key makes the server refuse every key ring that holds the admin, in every project with browser secrets off"]
fn bug_1900_another_persons_browser_device_never_blocks_a_key_ring_update() {
    let hub = TestHub::start();
    let alice = hub.person("alice");
    let mallory = hub.person("mallory");
    let (proj, _dir) = project_with_secret(&hub, &alice, "rv1900b");
    let token = alice.token();
    let ring = team_ring(&hub, &token, &proj);
    let before = send_ring(&hub, &token, &proj, &ring);
    assert_eq!(before.status, 200, "the admin's own ring is accepted: {}", String::from_utf8_lossy(&before.body));

    // Mallory is in no project of Alice's. She enrolls a browser device of
    // her own whose identity names Alice's encryption key, and confirms it.
    let code = mint_enroll_code(&hub, &mallory);
    let mut web = BrowserClient::new(&hub);
    let pk = VirtualPasskey::new_with_prf(31);
    let forged = identity_with_the_encryption_key_of(&alice.identity(), &Identity::generate(&mallory.name));
    let reg = enroll_with(&pk, &mut web, &code, Some(&forged));
    assert_eq!(reg.status, 200, "{}", reg.text());
    let fp = reg.json()["fingerprint"].as_str().expect("a fingerprint").to_string();
    mallory.ok(mallory.home.path(), &["identity", "confirm", &fp]);

    // Browser secrets are off in Alice's project (the default).
    let after = send_ring(&hub, &token, &proj, &ring);
    assert_eq!(
        after.status,
        200,
        "another person's browser device blocked the admin's key ring: {}",
        String::from_utf8_lossy(&after.body)
    );
}

// ---------------------------------------------------------------------------
// BUG-1901: a passkey of a browser without PRF is a device nobody can see or
// remove.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "BUG-1901: a passkey enrolled without PRF is in no device list and no route removes it: it signs in for ever"]
fn bug_1901_a_person_can_remove_a_passkey_enrolled_without_prf() {
    let hub = TestHub::start();
    let bob = hub.person("bob");
    let code = mint_enroll_code(&hub, &bob);
    let mut web = BrowserClient::new(&hub);
    let mut pk = VirtualPasskey::new_without_prf(41);
    let reg = pk.enroll(&mut web, &bob.name, &code);
    assert_eq!(reg["prf_supported"], false);
    // It signs in: a session as Bob, for everything but secrets.
    let first = assert_with_flags(&pk, &web, &login_challenge(&web, None), 0x05, 2);
    assert_eq!(first.status, 200, "{}", first.text());
    assert_eq!(first.json()["person"], bob.name.as_str());

    // The phone that holds it is lost. From `vl`, Bob removes every device
    // of his but the one he is using: everything the server lists.
    let token = bob.token();
    let mine = bob.identity().public_id();
    let listed = hub.api().get(Some(&token), &format!("/v1/people/{}/devices", bob.name));
    assert_eq!(listed.status, 200);
    let listed = listed.json();
    let others: Vec<String> = ["identities", "pending"]
        .iter()
        .flat_map(|k| listed[*k].as_array().cloned().unwrap_or_default())
        .filter_map(|v| v.as_str().map(str::to_string))
        .filter(|id| *id != mine)
        .collect();
    for id in &others {
        let r = hub.api().post_json(Some(&token), "/v1/devices/remove", &json!({ "device": id }));
        assert_eq!(r.status, 200, "removing {id}: {}", String::from_utf8_lossy(&r.body));
    }

    // The lost passkey no longer signs in.
    let again = assert_with_flags(&pk, &web, &login_challenge(&web, None), 0x05, 3);
    assert_eq!(
        again.status,
        401,
        "the passkey still signs in as {} after he removed every other device the server lists ({} listed): {}",
        bob.name,
        others.len(),
        again.text()
    );
}

// ---------------------------------------------------------------------------
// BUG-1902: login challenges are never deleted.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "BUG-1902: /web/passkey/login/begin stores a row for anyone and never deletes expired ones"]
fn bug_1902_expired_login_challenges_are_deleted() {
    let hub = TestHub::start();
    let web = BrowserClient::new(&hub);
    // Anyone, never signed in, starts three sign-ins and finishes none.
    for _ in 0..3 {
        login_challenge(&web, None);
    }
    let mine = "SELECT count(*) FROM webauthn_challenges WHERE origin = $1 AND kind = 'login'";
    assert_eq!(count(&hub, mine, &web.origin), 3);
    // They expire (two minutes; here, at once).
    assert_eq!(exec(&hub, "UPDATE webauthn_challenges SET expires_at = 1 WHERE origin = $1", &web.origin), 3);
    // The next sign-in that starts clears them, as `/v1/auth/challenge` does.
    login_challenge(&web, None);
    assert_eq!(
        count(&hub, "SELECT count(*) FROM webauthn_challenges WHERE origin = $1 AND expires_at < 2", &web.origin),
        0,
        "expired login challenges stay in the database"
    );
}

// ---------------------------------------------------------------------------
// BUG-1903: the client asks for user verification; the server never checks it.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "BUG-1903: a passkey assertion without user verification signs in (the pages ask for userVerification: 'required')"]
fn bug_1903_a_passkey_assertion_without_user_verification_is_refused() {
    let hub = TestHub::start();
    let alice = hub.person("alice");
    let code = mint_enroll_code(&hub, &alice);
    let mut web = BrowserClient::new(&hub);
    let mut pk = VirtualPasskey::new_with_prf(51);
    pk.enroll(&mut web, &alice.name, &code);
    // Verified (PIN or biometric: UP | UV): signs in.
    let verified = assert_with_flags(&pk, &web, &login_challenge(&web, None), 0x05, 2);
    assert_eq!(verified.status, 200, "{}", verified.text());
    // Present only (a touch of a security key someone else holds: UP).
    let touched = assert_with_flags(&pk, &web, &login_challenge(&web, None), 0x01, 3);
    assert_eq!(touched.status, 401, "signed in without user verification: {}", touched.text());
}

// ---------------------------------------------------------------------------
// BUG-1904: a browser device that waited a day can never be confirmed.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "BUG-1904: a browser device enrolled more than a day ago is never found by `vl identity confirm`, and signing in with the passkey does not renew it"]
fn bug_1904_a_browser_device_is_confirmed_a_day_after_it_enrolled() {
    let hub = TestHub::start();
    let alice = hub.person("alice");
    let code = mint_enroll_code(&hub, &alice);
    let mut web = BrowserClient::new(&hub);
    let mut pk = VirtualPasskey::new_with_prf(61);
    let reg = pk.enroll(&mut web, &alice.name, &code);
    let fp = reg["fingerprint"].as_str().expect("a fingerprint").to_string();
    // A day and an hour pass.
    assert_eq!(exec(&hub, "UPDATE devices SET created_at = created_at - 90000000 WHERE fingerprint = $1", &fp), 1);
    // The browser signs in again with its passkey, as the pending-device
    // rule asks ("signing in again renews it"), and is told to confirm.
    let again = pk.sign_in(&mut web, Some(&alice.name));
    assert_eq!(again["confirmed"], false);
    assert!(again["message"].as_str().unwrap_or_default().contains(&format!("vl identity confirm {fp}")), "{again}");
    // The person does what the page says.
    let out = alice.run(alice.home.path(), &["identity", "confirm", &fp]);
    assert!(
        out.status.success(),
        "`vl identity confirm {fp}` failed for a browser device that is signed in: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// ---------------------------------------------------------------------------
// Guarantees the milestone's own tests leave unproven.
// ---------------------------------------------------------------------------

/// The routes that carried a wrapped key, a share or a sealed object before
/// S26 answer no browser session, whatever the device's state and the
/// project's setting: a browser device's only way to a key ring is
/// `/v1/projects/{p}/web/rings`.
#[test]
fn a_browser_session_gets_no_wrapped_key_from_the_routes_older_than_s26() {
    let hub = TestHub::start();
    let alice = hub.person("alice");
    let (proj, dir) = project_with_secret(&hub, &alice, "rvold");
    let token = alice.token();
    let older = [
        format!("/v1/projects/{proj}/rings"),
        format!("/v1/projects/{proj}/rings/team"),
        format!("/v1/projects/{proj}/shares"),
        format!("/v1/projects/{proj}/keys/pending"),
        format!("/v1/projects/{proj}/q/file?path=.env"),
    ];
    // The action: `vl`'s session reads each of them.
    for route in &older {
        let r = hub.api().get(Some(&token), route);
        assert_eq!(r.status, 200, "{route} for vl: {}", String::from_utf8_lossy(&r.body));
    }
    let ring = team_ring(&hub, &token, &proj);
    let wrapped = serde_json::to_string(&ring).unwrap();
    let marker = &wrapped[wrapped.len() / 2..wrapped.len() / 2 + 40];

    let enable = |on: bool| {
        let r = hub.api().post_json(Some(&token), &format!("/v1/projects/{proj}/web-secrets"), &json!({ "enabled": on }));
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    };
    let code = mint_enroll_code(&hub, &alice);
    let mut web = BrowserClient::new(&hub);
    let mut pk = VirtualPasskey::new_with_prf(71);
    let reg = pk.enroll(&mut web, &alice.name, &code);
    let fp = reg["fingerprint"].as_str().unwrap().to_string();
    let refused = |web: &BrowserClient, state: &str| {
        let cookie = web.cookie.clone().expect("a session");
        for route in &older {
            // As the browser sends it (a cookie), and as a bearer token.
            let by_cookie = web.get_api(route);
            let by_bearer = hub.api().get(Some(&cookie), route);
            for (how, status, body) in [("cookie", by_cookie.status, &by_cookie.body), ("bearer", by_bearer.status, &by_bearer.body)] {
                assert_eq!(status, 403, "{state}: {route} by {how}: {}", String::from_utf8_lossy(body));
                assert!(!String::from_utf8_lossy(body).contains(marker), "{state}: {route} by {how} carried the key ring");
            }
        }
    };

    // 1. Unconfirmed, setting on.
    enable(true);
    refused(&web, "unconfirmed, setting on");
    assert_eq!(web.get_api(&format!("/v1/projects/{proj}/web/rings")).status, 403);
    // 2. Confirmed, setting off.
    enable(false);
    alice.ok(&dir, &["identity", "confirm", &fp]);
    alice.ok(&dir, &["share-keys"]);
    refused(&web, "confirmed, setting off");
    assert_eq!(web.get_api(&format!("/v1/projects/{proj}/web/rings")).status, 403);
    // 3. Confirmed, setting on: the new route answers, the older ones still don't.
    enable(true);
    alice.ok(&dir, &["share-keys"]);
    let rings = web.get_api(&format!("/v1/projects/{proj}/web/rings"));
    assert_eq!(rings.status, 200, "{}", rings.text());
    assert!(rings.json()["rings"].as_object().unwrap().contains_key("team"), "{}", rings.text());
    refused(&web, "confirmed, setting on");
}

/// The passkey protocol: a challenge is used once, expires, and belongs to
/// one ceremony and (when it names one) one person; an enrollment code
/// expires and is not minted from the web; the session cookie and the
/// same-origin rule are S25's.
#[test]
fn passkey_challenges_and_enrollment_codes_are_single_use_expire_and_bind_their_person() {
    let hub = TestHub::start();
    let alice = hub.person("alice");
    let bob = hub.person("bob");
    let mut web = BrowserClient::new(&hub);
    let mut alice_pk = VirtualPasskey::new_with_prf(81);
    alice_pk.enroll(&mut web, &alice.name, &mint_enroll_code(&hub, &alice));
    let mut bob_web = BrowserClient::new(&hub);
    let mut bob_pk = VirtualPasskey::new_without_prf(82);
    bob_pk.enroll(&mut bob_web, &bob.name, &mint_enroll_code(&hub, &bob));

    // The action: a sign-in, with S25's cookie.
    let challenge = login_challenge(&web, None);
    let ok = assert_with_flags(&alice_pk, &web, &challenge, 0x05, 2);
    assert_eq!(ok.status, 200, "{}", ok.text());
    assert_eq!(ok.json()["person"], alice.name.as_str(), "a passkey signs in as the person who enrolled it");
    let cookie = ok.set_cookies().into_iter().find(|c| c.starts_with("__Host-veil_session=")).expect("the session cookie").to_string();
    for attr in ["HttpOnly", "Secure", "SameSite=Strict", "Path=/"] {
        assert!(cookie.contains(attr), "the session cookie lacks {attr}: {cookie}");
    }
    assert!(!cookie.contains("Domain="), "{cookie}");

    // A challenge is used once: the same one again, with a new signature.
    let replay = assert_with_flags(&alice_pk, &web, &challenge, 0x05, 3);
    assert_eq!(replay.status, 401, "{}", replay.text());
    // A challenge expires.
    let late = login_challenge(&web, None);
    assert_eq!(exec(&hub, "UPDATE webauthn_challenges SET expires_at = 1 WHERE challenge = $1", &late), 1);
    assert_eq!(assert_with_flags(&alice_pk, &web, &late, 0x05, 4).status, 401);
    // A challenge that named a person takes only that person's passkey.
    let for_bob = login_challenge(&web, Some(&bob.name));
    assert_eq!(assert_with_flags(&alice_pk, &web, &for_bob, 0x05, 5).status, 401);
    let for_alice = login_challenge(&web, Some(&alice.name));
    assert_eq!(assert_with_flags(&bob_pk, &web, &for_alice, 0x05, 2).status, 401);
    // A registration challenge is not a login challenge.
    let begin = web.post_json("/web/passkey/register/begin", &json!({ "code": mint_enroll_code(&hub, &alice) }), false);
    assert_eq!(begin.status, 200, "{}", begin.text());
    let registration = begin.json()["challenge"].as_str().unwrap().to_string();
    assert_eq!(assert_with_flags(&alice_pk, &web, &registration, 0x05, 6).status, 401);
    // After all those refusals, the passkey still signs in (nothing above
    // was refused for a broken passkey).
    assert_eq!(assert_with_flags(&alice_pk, &web, &login_challenge(&web, None), 0x05, 7).status, 200);

    // An enrollment code expires.
    let code = mint_enroll_code(&hub, &alice);
    assert_eq!(web.post_json("/web/passkey/register/begin", &json!({ "code": code }), false).status, 200);
    assert!(exec(&hub, "UPDATE web_enrollments SET expires_at = 1 WHERE person_id = (SELECT id FROM people WHERE name = $1)", &alice.name) >= 1);
    let expired = web.post_json("/web/passkey/register/begin", &json!({ "code": code }), false);
    assert_eq!(expired.status, 401, "{}", expired.text());
    let unknown = enroll_with(&VirtualPasskey::new_with_prf(83), &mut BrowserClient::new(&hub), &mint_enroll_code(&hub, &alice), None);
    assert_eq!(unknown.status, 200, "a new code still enrolls: {}", unknown.text());
    // A code comes from `vl`, never from a web session (which would enroll
    // more browsers from one browser).
    web.capture_cookie(&ok);
    web.csrf = ok.json()["csrf"].as_str().map(str::to_string);
    let from_web = web.post_json("/v1/sessions/web-enroll", &json!({}), true);
    assert_eq!(from_web.status, 403, "{}", from_web.text());

    // The same-origin rule: another site starts or finishes no ceremony.
    let shaped = json!({
        "code": "web-enroll-none", "person": alice.name, "credential_id": "AA", "client_data_json": "AA", "attestation_object": "AA",
        "authenticator_data": "AA", "signature": "AA", "prf_supported": false, "prf_salt": "AA",
    });
    for path in ["/web/passkey/login/begin", "/web/passkey/login/finish", "/web/passkey/register/begin", "/web/passkey/register/finish"] {
        let r = BrowserClient::new(&hub).post_json_origin(path, &shaped, false, "https://evil.example");
        assert_eq!(r.status, 403, "{path} from another origin: {}", r.text());
        assert_eq!(r.json()["code"], "csrf_failed", "{path}: {}", r.text());
    }
    // The enrollment link's code is shown back escaped.
    let page = BrowserClient::new(&hub).get("/login?enroll=%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E");
    assert_eq!(page.status, 200);
    assert!(!page.text().contains("<script>alert(1)"), "the login page reflects its enroll parameter");
}

/// Only an admin turns browser secrets on, with their own session and from
/// the same site, and the change is in the audit log.
#[test]
fn only_an_admin_changes_the_setting_and_it_is_recorded() {
    let hub = TestHub::start();
    let alice = hub.person("alice");
    let bob = hub.person("bob");
    let (proj, dir) = project_with_secret(&hub, &alice, "rvset");
    alice.ok(&dir, &["group", "create", "devs"]);
    alice.ok(&dir, &["group", "add", "devs", &bob.name, "--confirm", &bob.fingerprint()]);
    alice.ok(&dir, &["access", "public/", "public", "devs"]);
    let api_route = format!("/v1/projects/{proj}/web-secrets");
    let form_route = format!("/p/{proj}/admin/web-secrets");
    let on = "SELECT count(*) FROM projects WHERE name = $1 AND web_secrets";
    let recorded = "SELECT count(*) FROM audit_log a JOIN projects p ON p.id = a.project_id WHERE p.name = $1 AND a.action = 'web secrets'";

    // A member who is not an admin: by the API, and by the form in a browser.
    let r = hub.api().post_json(Some(&bob.token()), &api_route, &json!({ "enabled": true }));
    assert_eq!(r.status, 403, "{}", String::from_utf8_lossy(&r.body));
    let mut bob_web = BrowserClient::new(&hub);
    VirtualPasskey::new_without_prf(91).enroll(&mut bob_web, &bob.name, &mint_enroll_code(&hub, &bob));
    assert_eq!(bob_web.get(&format!("/p/{proj}")).status, 200, "the member sees the project");
    let r = bob_web.post_form(&form_route, &[("enabled", "true"), ("acknowledge_limit", "1")], true);
    assert_eq!(r.status, 403, "{}", r.text());
    // Nobody signed in.
    assert_eq!(hub.api().post_json(None, &api_route, &json!({ "enabled": true })).status, 401);
    // The admin's browser, without the CSRF token, and from another site.
    let mut web = BrowserClient::new(&hub);
    VirtualPasskey::new_without_prf(92).enroll(&mut web, &alice.name, &mint_enroll_code(&hub, &alice));
    assert_eq!(web.post_json(&api_route, &json!({ "enabled": true }), false).status, 403);
    assert_eq!(web.post_form(&form_route, &[("enabled", "true"), ("acknowledge_limit", "1")], false).status, 403);
    assert_eq!(web.post_json_origin(&api_route, &json!({ "enabled": true }), true, "https://evil.example").status, 403);
    assert_eq!(count(&hub, on, &proj), 0, "a refused request turned browser secrets on");
    assert_eq!(count(&hub, recorded, &proj), 0);

    // The admin, from their own browser session.
    let r = web.post_form(&form_route, &[("enabled", "true"), ("acknowledge_limit", "1")], true);
    assert_eq!(r.status, 303, "{}", r.text());
    assert_eq!(count(&hub, on, &proj), 1);
    assert_eq!(count(&hub, recorded, &proj), 1, "turning browser secrets on is in the audit log");
    let r = hub.api().post_json(Some(&alice.token()), &api_route, &json!({ "enabled": false }));
    assert_eq!(r.status, 200);
    assert_eq!(count(&hub, on, &proj), 0);
    assert_eq!(count(&hub, recorded, &proj), 2, "turning browser secrets off is in the audit log");
}

/// Turning the setting off takes the browser device out of the key rings
/// the next time keys are shared, and new secrets no longer open with what
/// it held.
#[test]
fn turning_the_setting_off_rotates_keys_away_from_the_browser_device() {
    let hub = TestHub::start();
    let alice = hub.person("alice");
    let (proj, dir) = project_with_secret(&hub, &alice, "rvoff");
    let token = alice.token();
    let enable = |on: bool| {
        let r = hub.api().post_json(Some(&token), &format!("/v1/projects/{proj}/web-secrets"), &json!({ "enabled": on }));
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    };
    enable(true);
    let mut web = BrowserClient::new(&hub);
    let mut pk = VirtualPasskey::new_with_prf(95);
    let reg = pk.enroll(&mut web, &alice.name, &mint_enroll_code(&hub, &alice));
    let fp = reg["fingerprint"].as_str().unwrap().to_string();
    alice.ok(&dir, &["identity", "confirm", &fp]);
    alice.ok(&dir, &["share-keys"]);
    let member = pk.bundle.as_ref().unwrap().member_id.clone();
    let state = |hub: &TestHub| serde_json::from_value::<KeyRing>(team_ring(hub, &token, &proj)).unwrap().verify().unwrap();
    // The action: the browser device holds the key.
    let held = state(&hub);
    assert!(held.members.contains_key(&member), "the confirmed browser device is in the team ring");

    enable(false);
    alice.ok(&dir, &["share-keys"]);
    let after = state(&hub);
    assert!(!after.members.contains_key(&member), "the browser device is still in the team ring after the setting was turned off");
    assert_ne!(after.key_id(), held.key_id(), "the key was not rotated away from the browser device");
    // Work goes on: a new secret is pushed.
    write_files(&dir, &[(".env", "RV_S26_SECRET=second\n")]);
    alice.commit_main(&dir, "rotate");
    alice.ok(&dir, &["push"]);
}

// ---------------------------------------------------------------------------
// BUG-1905: signing out deletes the passkey.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "BUG-1905: signing out of the web client deletes the browser's passkey and device: the next visit cannot sign in (the guide: \"later visits sign in with that passkey\")"]
fn bug_1905_a_passkey_signs_in_again_after_signing_out() {
    let hub = TestHub::start();
    let alice = hub.person("alice");
    let mut web = BrowserClient::new(&hub);
    let mut pk = VirtualPasskey::new_without_prf(96);
    pk.enroll(&mut web, &alice.name, &mint_enroll_code(&hub, &alice));
    assert_eq!(web.get("/").status, 200);
    let out = web.post_form("/web/logout", &[], true);
    assert!(out.status == 303 || out.status == 200, "signing out: {} {}", out.status, out.text());
    // The session is over.
    let cookie = web.cookie.clone().expect("the old session's cookie");
    assert_eq!(hub.api().get(Some(&cookie), "/v1/epochs").status, 401, "the signed-out session still works");
    // The next visit: the passkey the browser still holds.
    let again = assert_with_flags(&pk, &web, &login_challenge(&web, None), 0x05, 2);
    assert_eq!(again.status, 200, "the passkey no longer signs in after a sign-out: {}", again.text());
}

/// Right after an admin gives a folder to another group, the browser device
/// of someone who lost it gets neither the folder's key ring nor its
/// secret's bytes nor its pages. (A change of a group's members, which needs
/// no push, is `web_secrets::guarantee_4…`.)
#[test]
fn an_access_change_hides_a_folders_ring_and_secret_at_once() {
    let hub = TestHub::start();
    let alice = hub.person("alice");
    let bob = hub.person("bob");
    let (proj, dir) = project_with_secret(&hub, &alice, "rvacc");
    alice.ok(&dir, &["group", "create", "finance"]);
    alice.ok(&dir, &["group", "create", "ops"]);
    alice.ok(&dir, &["group", "add", "finance", &bob.name, "--confirm", &bob.fingerprint()]);
    alice.ok(&dir, &["access", "billing/", "finance"]);
    write_files(&dir, &[("billing/.env", "RV_S26_BILLING=1\n"), ("billing/notes.txt", "plain\n")]);
    alice.commit_main(&dir, "billing");
    alice.ok(&dir, &["push"]);
    catch_up(&hub, &proj);
    let r = hub.api().post_json(Some(&alice.token()), &format!("/v1/projects/{proj}/web-secrets"), &json!({ "enabled": true }));
    assert_eq!(r.status, 200);
    let mut web = BrowserClient::new(&hub);
    let mut pk = VirtualPasskey::new_with_prf(97);
    let reg = pk.enroll(&mut web, &bob.name, &mint_enroll_code(&hub, &bob));
    let fp = reg["fingerprint"].as_str().unwrap().to_string();
    bob.ok(bob.home.path(), &["identity", "confirm", &fp]);
    alice.ok(&dir, &["share-keys"]);
    let rings_route = format!("/v1/projects/{proj}/web/rings");
    let secret_route = format!("/v1/projects/{proj}/web/ciphertext?rev=main&path=billing/.env");
    // The action: Bob's browser device holds the folder's ring and reads its secret's bytes.
    let rings = web.get_api(&rings_route);
    assert_eq!(rings.status, 200, "{}", rings.text());
    assert_eq!(rings.json()["rings"].as_object().unwrap().len(), 1, "{}", rings.text());
    assert_eq!(web.get_api(&secret_route).status, 200);

    // The folder goes to another group (an access line is part of
    // `.veilpolicy`: it takes effect when pushed).
    alice.ok(&dir, &["access", "billing/", "ops"]);
    alice.commit_main(&dir, "billing to ops");
    alice.ok(&dir, &["push"]);
    catch_up(&hub, &proj);
    let rings = web.get_api(&rings_route);
    assert_eq!(rings.status, 200, "{}", rings.text());
    assert!(rings.json()["rings"].as_object().unwrap().is_empty(), "the ring of a folder Bob lost: {}", rings.text());
    assert_eq!(web.get_api(&secret_route).status, 404);
    assert_eq!(web.get(&format!("/p/{proj}/file/billing/notes.txt")).status, 404);
    assert_eq!(web.get(&format!("/p/{proj}/file/billing/.env")).status, 404);
}

/// Right after someone leaves a group (no push, no rotation yet: the ring
/// still holds their browser device), the server gives that device neither
/// the folder's ring nor its secret's bytes, on every server.
#[test]
fn leaving_a_group_hides_the_folders_ring_and_secret_bytes_at_once() {
    let hub = TestHub::start();
    let hub_b = TestHub::beside(&hub);
    let alice = hub.person("alice");
    let bob = hub.person("bob");
    let (proj, dir) = project_with_secret(&hub, &alice, "rvgrp");
    alice.ok(&dir, &["group", "create", "finance"]);
    alice.ok(&dir, &["group", "add", "finance", &bob.name, "--confirm", &bob.fingerprint()]);
    alice.ok(&dir, &["access", "billing/", "finance"]);
    write_files(&dir, &[("billing/.env", "RV_S26_BILLING=1\n")]);
    alice.commit_main(&dir, "billing");
    alice.ok(&dir, &["push"]);
    catch_up(&hub, &proj);
    let token = alice.token();
    let r = hub.api().post_json(Some(&token), &format!("/v1/projects/{proj}/web-secrets"), &json!({ "enabled": true }));
    assert_eq!(r.status, 200);
    let mut web = BrowserClient::new(&hub);
    let mut pk = VirtualPasskey::new_with_prf(101);
    let reg = pk.enroll(&mut web, &bob.name, &mint_enroll_code(&hub, &bob));
    bob.ok(bob.home.path(), &["identity", "confirm", reg["fingerprint"].as_str().unwrap()]);
    alice.ok(&dir, &["share-keys"]);
    let mut web_b = BrowserClient::new(&hub_b);
    web_b.cookie = web.cookie.clone();
    let rings_route = format!("/v1/projects/{proj}/web/rings");
    let secret_route = format!("/v1/projects/{proj}/web/ciphertext?rev=main&path=billing/.env");
    // The action: both servers give Bob's browser device the ring and the bytes.
    for w in [&web, &web_b] {
        let rings = w.get_api(&rings_route);
        assert_eq!(rings.status, 200, "{}", rings.text());
        assert_eq!(rings.json()["rings"].as_object().unwrap().len(), 1, "{}", rings.text());
        assert_eq!(w.get_api(&secret_route).status, 200);
    }

    // The group change is the server's: no key was rotated.
    let r = hub.api().post_json(Some(&token), &format!("/v1/projects/{proj}/groups/finance/members/remove"), &json!({ "people": [bob.name] }));
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let member = pk.bundle.as_ref().unwrap().member_id.clone();
    let still: Vec<KeyRing> = serde_json::from_value(hub.api().get(Some(&token), &format!("/v1/projects/{proj}/rings")).json()).unwrap();
    assert!(
        still.iter().any(|r| r.scope != "team" && r.verify().unwrap().members.contains_key(&member)),
        "the folder's ring still holds the browser device (nothing rotated): the server's filter is what is tested"
    );
    for (w, which) in [(&web, "the first server"), (&web_b, "the second server")] {
        let rings = w.get_api(&rings_route);
        assert!(rings.status == 200 || rings.status == 403 || rings.status == 404, "{which}: {}", rings.text());
        assert!(!rings.text().contains(&member["veil1".len()..]), "{which} still gave the ring: {}", rings.text());
        let bytes = w.get_api(&secret_route);
        assert!(bytes.status == 403 || bytes.status == 404, "{which} still gave the secret's bytes: {}", bytes.status);
    }
}

/// Agent sessions and CI runners use no route of S26, also when they send
/// what a browser sends (S26 takes an unsigned review from "the web": an
/// `Origin` header must not make an agent's request one).
#[test]
fn agent_and_runner_sessions_use_no_route_of_s26() {
    let hub = TestHub::start();
    let alice = hub.person("alice");
    let bob = hub.person("bob");
    let (proj, dir) = project_with_secret(&hub, &alice, "rvagent");
    alice.ok(&dir, &["group", "create", "devs"]);
    alice.ok(&dir, &["group", "add", "devs", &bob.name, "--confirm", &bob.fingerprint()]);
    alice.ok(&dir, &["access", "public/", "public", "devs"]);
    alice.commit_main(&dir, "devs write public/");
    alice.ok(&dir, &["push"]);
    // A PR of Alice's that Bob may review.
    write_files(&dir, &[("public/readme.md", "# docs, changed\n")]);
    alice.ok(&dir, &["commit", "--no-advance", "-m", "change the docs"]);
    alice.ok(&dir, &["tag", "set", "docs", "-r", "@-"]);
    alice.ok(&dir, &["push"]);
    catch_up(&hub, &proj);
    let api = hub.api();
    let head = api.tips(Some(&alice.token()), &proj).unwrap().branches["docs"];
    let pr = api.post_json(Some(&alice.token()), &format!("/v1/projects/{proj}/prs"), &json!({ "head": head, "onto": "main", "title": "Docs" }));
    assert_eq!(pr.status, 200, "{}", String::from_utf8_lossy(&pr.body));
    let (pr_id, patch) = (pr.json()["id"].as_str().unwrap().to_string(), pr.json()["patch"].as_str().unwrap().to_string());

    let sessions = |person: &Person| -> [String; 2] {
        let agent = api.post_json(Some(&person.token()), "/v1/sessions/agent", &json!({ "project": proj, "attribution": { "agent": "bot" }, "only": [] }));
        assert_eq!(agent.status, 200, "{}", String::from_utf8_lossy(&agent.body));
        let runner = api.post_json(Some(&person.token()), "/v1/sessions/ci", &json!({ "project": proj }));
        assert_eq!(runner.status, 200, "{}", String::from_utf8_lossy(&runner.body));
        [agent.json()["token"].as_str().unwrap().to_string(), runner.json()["token"].as_str().unwrap().to_string()]
    };
    let origin = format!("https://{}", hub.authority());
    // A request as a browser's script sends it, with a bearer token.
    let as_browser = |token: &str, post: Option<&Value>, path: &str| -> Reply {
        let bearer = format!("Bearer {token}");
        let headers = [("authorization", bearer.as_str()), ("origin", origin.as_str()), ("sec-fetch-site", "same-origin"), ("accept", "application/json")];
        match post {
            Some(body) => api.post_with(path, &serde_json::to_vec(body).unwrap(), &headers),
            None => api.get_with(path, &headers),
        }
    };
    let refused = |r: Reply, what: &str| {
        assert_eq!(r.status, 403, "{what}: {}", String::from_utf8_lossy(&r.body));
        assert_eq!(r.json()["code"], "agent_session", "{what}: {}", String::from_utf8_lossy(&r.body));
    };

    // An unsigned review "from the web": never an agent's or a runner's.
    let review = json!({ "patch": patch, "verdict": "request-changes", "body": "no" });
    let review_route = format!("/v1/projects/{proj}/prs/{pr_id}/reviews");
    for (token, who) in sessions(&bob).iter().zip(["Bob's agent", "Bob's runner"]) {
        refused(as_browser(token, Some(&review), &review_route), &format!("{who}, an unsigned review"));
        let form = api.post_with(
            &format!("/p/{proj}/prs/{pr_id}/reviews"),
            format!("patch={patch}&verdict=request-changes").as_bytes(),
            &[("authorization", &format!("Bearer {token}")), ("origin", &origin), ("sec-fetch-site", "same-origin"), ("content-type", "application/x-www-form-urlencoded")],
        );
        assert_eq!(form.status, 403, "{who}, the review form: {}", String::from_utf8_lossy(&form.body));
    }
    // The action: the same request with Bob's own session is a review.
    let own = as_browser(&bob.token(), Some(&review), &review_route);
    assert_eq!(own.status, 200, "{}", String::from_utf8_lossy(&own.body));

    // The setting, the enrollment code, the rings, the bytes, the Worker.
    for (token, who) in sessions(&alice).iter().zip(["the admin's agent", "the admin's runner"]) {
        refused(as_browser(token, Some(&json!({ "enabled": true })), &format!("/v1/projects/{proj}/web-secrets")), &format!("{who}, the setting"));
        // (An enrollment code is `vl`'s to ask for: no browser headers.)
        refused(api.post_json(Some(token), "/v1/sessions/web-enroll", &json!({})), &format!("{who}, an enrollment code"));
        for path in [
            format!("/v1/projects/{proj}/web/rings"),
            format!("/v1/projects/{proj}/web/ciphertext?rev=main&path=.env"),
            format!("/p/{proj}/web/secrets.js"),
            format!("/p/{proj}/web/secret-worker.js"),
            format!("/p/{proj}/web/secret-worker.wasm"),
        ] {
            refused(as_browser(token, None, &path), &format!("{who}, {path}"));
        }
    }
    assert_eq!(count(&hub, "SELECT count(*) FROM projects WHERE name = $1 AND web_secrets", &proj), 0);
    // The action: the admin's own session turns the setting on.
    let on = api.post_json(Some(&alice.token()), &format!("/v1/projects/{proj}/web-secrets"), &json!({ "enabled": true }));
    assert_eq!(on.status, 200);
}

// ---------------------------------------------------------------------------
// BUG-1906: over HTTP/2 a request has no `Host` header.
// ---------------------------------------------------------------------------

/// One request over HTTP/2, which is what every browser speaks to this
/// server (its TLS offers `h2` first): the status and the body of the
/// answer. As a browser sends it: `:authority`, and no `host` header.
fn over_http2(hub: &TestHub, method: &str, path: &str, headers: &[(&str, &str)], body: &[u8]) -> (u16, String) {
    use crate::limits::raw;
    use std::io::{Read, Write};
    fn int(out: &mut Vec<u8>, n: usize) {
        // A string's length (HPACK, 7-bit prefix, no Huffman).
        if n < 127 {
            out.push(n as u8);
        } else {
            out.push(127);
            let mut rest = n - 127;
            while rest >= 128 {
                out.push((rest % 128) as u8 | 0x80);
                rest /= 128;
            }
            out.push(rest as u8);
        }
    }
    fn digits(value: &[u8], huffman: bool) -> u16 {
        if !huffman {
            return std::str::from_utf8(value).ok().and_then(|s| s.parse().ok()).unwrap_or(0);
        }
        // HPACK's Huffman codes of the digits: '0'..'2' are 5 bits (00000..00010), '3'..'9' are 6 (011001..011111).
        let bits: Vec<u8> = value.iter().flat_map(|b| (0..8).rev().map(move |i| (b >> i) & 1)).collect();
        let (mut at, mut n, mut read) = (0, 0u16, 0);
        while read < 3 && at + 5 <= bits.len() {
            let five = bits[at..at + 5].iter().fold(0u8, |a, b| (a << 1) | b);
            if five <= 2 {
                n = n * 10 + five as u16;
                at += 5;
            } else if at + 6 <= bits.len() {
                let six = bits[at..at + 6].iter().fold(0u8, |a, b| (a << 1) | b);
                if !(0b011001..=0b011111).contains(&six) {
                    return 0;
                }
                n = n * 10 + (six - 0b011001 + 3) as u16;
                at += 6;
            } else {
                return 0;
            }
            read += 1;
        }
        n
    }
    let authority = hub.authority();
    let mut block = Vec::new();
    let pseudo = [(":method", method), (":scheme", "https"), (":authority", authority.as_str()), (":path", path)];
    for (name, value) in pseudo.iter().chain(headers) {
        block.push(0x00); // a literal field, not indexed, a new name
        int(&mut block, name.len());
        block.extend(name.as_bytes());
        int(&mut block, value.len());
        block.extend(value.as_bytes());
    }
    let mut s = raw::tls(raw::tcp("127.0.0.1".parse().unwrap(), authority.parse().unwrap()));
    s.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").unwrap();
    s.write_all(&raw::frame(4, 0, 0, &[])).unwrap();
    s.write_all(&raw::frame(1, if body.is_empty() { 0x5 } else { 0x4 }, 1, &block)).unwrap();
    if !body.is_empty() {
        s.write_all(&raw::frame(0, 0x1, 1, body)).unwrap();
    }
    s.flush().unwrap();
    s.sock.set_read_timeout(Some(std::time::Duration::from_secs(20))).unwrap();
    let (mut buf, mut status, mut answer, mut done) = (Vec::new(), 0u16, Vec::new(), false);
    while !done {
        while buf.len() >= 9 && !done {
            let len = u32::from_be_bytes([0, buf[0], buf[1], buf[2]]) as usize;
            if buf.len() < 9 + len {
                break;
            }
            let (kind, flags, stream, payload) = (buf[3], buf[4], u32::from_be_bytes([buf[5] & 0x7f, buf[6], buf[7], buf[8]]), buf[9..9 + len].to_vec());
            buf.drain(..9 + len);
            match (kind, stream) {
                (4, 0) if flags & 1 == 0 => {
                    s.write_all(&raw::frame(4, 1, 0, &[])).unwrap();
                    s.flush().unwrap();
                }
                (1, 1) => {
                    // `:status` is the answer's first field.
                    status = match payload.first().copied() {
                        Some(b) if b & 0x80 != 0 => [200, 204, 206, 304, 400, 404, 500].get((b & 0x7f).wrapping_sub(8) as usize).copied().unwrap_or(0),
                        Some(b) if matches!(b, 0x48 | 0x08 | 0x18) && payload.len() > 1 => {
                            let n = (payload[1] & 0x7f) as usize;
                            payload.get(2..2 + n).map_or(0, |v| digits(v, payload[1] & 0x80 != 0))
                        }
                        _ => 0,
                    };
                    done = flags & 1 != 0;
                }
                (0, 1) => {
                    answer.extend(&payload);
                    done = flags & 1 != 0;
                }
                (3, 1) | (7, _) => done = true,
                _ => {}
            }
        }
        if done {
            break;
        }
        let mut chunk = [0u8; 4096];
        match s.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend(&chunk[..n]),
        }
    }
    (status, String::from_utf8_lossy(&answer).into_owned())
}

#[test]
fn bug_1906_a_browser_enrolls_signs_in_and_signs_out_over_http2() {
    let hub = TestHub::start();
    let alice = hub.person("alice");
    let origin = format!("https://{}", hub.authority());
    let browser = [("origin", origin.as_str()), ("sec-fetch-site", "same-origin"), ("content-type", "application/json"), ("accept", "application/json")];
    // The helper speaks HTTP/2 to this server: a page.
    let (status, page) = over_http2(&hub, "GET", "/login", &[("accept", "text/html")], b"");
    assert_eq!(status, 200, "{page}");
    assert!(page.contains("veil-passkey-login-form"), "{page}");

    // A sign-in starts, over HTTP/1.1 and over HTTP/2.
    login_challenge(&BrowserClient::http1(&hub), None);
    login_challenge(&BrowserClient::new(&hub), None);
    let (status, answer) = over_http2(&hub, "POST", "/web/passkey/login/begin", &browser, b"{}");
    assert_eq!(status, 200, "a passkey sign-in over HTTP/2: {answer}");
    assert!(answer.contains("\"challenge\""), "{answer}");
    // An enrollment starts.
    let body = serde_json::to_vec(&json!({ "code": mint_enroll_code(&hub, &alice) })).unwrap();
    let (status, answer) = over_http2(&hub, "POST", "/web/passkey/register/begin", &browser, &body);
    assert_eq!(status, 200, "a passkey enrollment over HTTP/2: {answer}");

    // S25's forms: a session made by `vl`, adopted and then signed out.
    let web = hub.api().post_json(Some(&alice.token()), "/v1/sessions/web", &json!({}));
    assert_eq!(web.status, 200, "{}", String::from_utf8_lossy(&web.body));
    let (token, csrf) = (web.json()["token"].as_str().unwrap().to_string(), web.json()["csrf"].as_str().unwrap().to_string());
    let cookie = format!("__Host-veil_session={token}");
    let form = [("origin", origin.as_str()), ("sec-fetch-site", "same-origin"), ("content-type", "application/x-www-form-urlencoded"), ("accept", "application/json"), ("cookie", cookie.as_str())];
    let (status, answer) = over_http2(&hub, "POST", "/web/logout", &form, format!("_csrf={csrf}").as_bytes());
    assert!(status == 303 || status == 200, "signing out over HTTP/2: {status} {answer}");
}
