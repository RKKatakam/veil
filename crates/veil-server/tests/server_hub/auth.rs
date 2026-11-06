//! Sign-in and sessions (`docs/HUB.md` §4.3): replays, forged signatures,
//! signatures for another server, expired and unknown tokens.

use std::time::Duration;

use serde_json::json;
use veil_core::{crypto::domains::SIG_CONTEXT_HUB_LOGIN, hub::wire::login_message, Identity};

use crate::support::*;

fn challenge(api: &Api, id: &Identity) -> String {
    let r = api.post_json(None, "/v1/auth/challenge", &json!({"key": id.verifying_hex()}));
    assert_eq!(r.status, 200);
    r.json()["challenge"].as_str().unwrap().to_string()
}

fn login_body(api: &Api, id: &Identity, signer: &Identity, challenge: &str, hub: &str, name: Option<&str>) -> serde_json::Value {
    let _ = api;
    json!({
        "key": id.verifying_hex(),
        "challenge": challenge,
        "hub": hub,
        "signature": signer.sign(SIG_CONTEXT_HUB_LOGIN, &login_message(hub, challenge)),
        "identity": id.public_id(),
        "name": name,
    })
}

#[test]
fn a_login_cannot_be_replayed_forged_or_relayed() {
    let hub = TestHub::start();
    let api = hub.api();
    let alice = Identity::generate("alice");
    let name = unique("alice");
    let ch = challenge(&api, &alice);
    let body = login_body(&api, &alice, &alice, &ch, &api.authority, Some(&name));
    assert_eq!(api.post_json(None, "/v1/auth/login", &body).status, 200);
    // Replay: the challenge is gone.
    let r = api.post_json(None, "/v1/auth/login", &body);
    assert_eq!(r.status, 401, "{}", String::from_utf8_lossy(&r.body));
    // Forged: signed by another key, claiming alice's.
    let mallory = Identity::generate("mallory");
    let ch = challenge(&api, &alice);
    let r = api.post_json(None, "/v1/auth/login", &login_body(&api, &alice, &mallory, &ch, &api.authority, None));
    assert_eq!(r.status, 401);
    // Relayed: alice signed a challenge for another server's name.
    let ch = challenge(&api, &alice);
    let r = api.post_json(None, "/v1/auth/login", &login_body(&api, &alice, &alice, &ch, "evil.example:443", None));
    assert_eq!(r.status, 401);
    // A challenge issued for one key is useless for another.
    let ch = challenge(&api, &alice);
    let r = api.post_json(None, "/v1/auth/login", &login_body(&api, &mallory, &mallory, &ch, &api.authority, Some("m")));
    assert_eq!(r.status, 401);
    // Mallory's own identity, claiming alice's public identity, is refused.
    let ch = challenge(&api, &mallory);
    let mut b = login_body(&api, &mallory, &mallory, &ch, &api.authority, Some(&unique("m")));
    b["identity"] = json!(alice.public_id());
    assert_eq!(api.post_json(None, "/v1/auth/login", &b).status, 400);
    // A taken name cannot be registered again by another key.
    let ch = challenge(&api, &mallory);
    let r = api.post_json(None, "/v1/auth/login", &login_body(&api, &mallory, &mallory, &ch, &api.authority, Some(&name)));
    assert_eq!(r.status, 409);
    // An unknown device without a name is not signed in.
    let ch = challenge(&api, &mallory);
    let r = api.post_json(None, "/v1/auth/login", &login_body(&api, &mallory, &mallory, &ch, &api.authority, None));
    assert_eq!(r.status, 401);
}

#[test]
fn expired_and_unknown_tokens_are_refused_never_downgraded() {
    let hub = TestHub::start_with_ttl(Duration::from_secs(2));
    let p = hub.person("ttl");
    let d = p.dir("proj");
    std::fs::create_dir_all(&d).unwrap();
    p.ok(&d, &["init"]);
    write_files(&d, &[("a.txt", "a")]);
    let name = unique("ttl");
    p.ok(&d, &["remote", "add", "origin", &hub.url(&name)]);
    p.commit_main(&d, "a");
    p.ok(&d, &["push"]);
    let api = hub.api();
    let token = p.token();
    assert!(api.tips(Some(&token), &name).is_some());
    std::thread::sleep(Duration::from_secs(3));
    let r = api.get(Some(&token), &format!("/v1/projects/{name}/tips"));
    assert_eq!(r.status, 401, "an expired token is refused");
    let r = api.get(Some("not-a-token"), &format!("/v1/projects/{name}/tips"));
    assert_eq!(r.status, 401, "an unknown token is refused, not served as anyone");
    // vl signs in again with the device key, without asking.
    write_files(&d, &[("b.txt", "b")]);
    p.commit_main(&d, "b");
    p.ok(&d, &["push"]);
    assert_ne!(p.token(), token);
}
