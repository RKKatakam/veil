//! Review `rv-new` of milestone S16 (BUG-1870).

use veil_core::{
    hub::access::{AccessPolicy, View},
    ObjectId,
};

use crate::support::*;

/// What `query::graph::cache_key` does with a view key since S16: folded
/// into bytes 8..32 of the snapshot's id with XOR.
fn fold_view_key(id: &mut [u8; 32], view_key: &str) {
    for (i, b) in view_key.bytes().enumerate() {
        id[8 + (i % 24)] ^= b.wrapping_add(i as u8);
    }
}

/// BUG-1870: the key of the viewer graph's rows kept in memory
/// (`hub.query.rows`) was a BLAKE3 hash of (project, view key, snapshot id);
/// S16 made it the id XOR the project XOR the view key folded. Whoever asks
/// chooses the id, so an id made from a row of **another view** (here the
/// admin's, whose view key is the word `admin`) names that row under the
/// asker's own key: `resolve` answers an id nobody made, a real snapshot the
/// asker was never given, and the query routes walk it (projected for the
/// asker, so only paths they read: but of a snapshot that is not theirs to
/// name, and past the embargo check, which looks at the id sent).
#[test]
fn bug_1870_an_id_made_from_another_views_row_resolves_for_nobody_else() {
    const POLICY: &str = "public/ public\n";
    let hub = TestHub::start();
    let alice = hub.person("alice");
    let proj = unique("rvkey");
    let dir = alice.dir("k");
    std::fs::create_dir_all(&dir).unwrap();
    alice.ok(&dir, &["init"]);
    alice.ok(&dir, &["remote", "add", "origin", &hub.url(&proj)]);
    write_files(&dir, &[(".veilpolicy", POLICY), ("public/readme.txt", "hello\n"), ("private/plan.txt", "a plan\n")]);
    alice.commit_main(&dir, "first");
    alice.ok(&dir, &["push"]);

    let api = hub.api();
    let tree = |token: Option<&str>, rev: &ObjectId| api.get(token, &format!("/v1/projects/{proj}/q/tree?rev={}", rev.hex()));
    // The admin reads the tree by the real id: the row of the admin's view
    // is in the server's memory.
    let real = api.tips(Some(&alice.token()), &proj).unwrap().branches["main"];
    let admin = tree(Some(&alice.token()), &real);
    assert_eq!(admin.status, 200, "{}", String::from_utf8_lossy(&admin.body));

    // Anyone on Earth reads their own projection, and nothing by the real
    // id (it is not theirs: the tree hides `private/`).
    let theirs = api.tips(None, &proj).unwrap().branches["main"];
    assert_ne!(theirs, real);
    let own = tree(None, &theirs);
    assert_eq!(own.status, 200, "{}", String::from_utf8_lossy(&own.body));
    let plain = tree(None, &real);
    assert_eq!(plain.status, 404, "{}", String::from_utf8_lossy(&plain.body));

    // The real id with the admin's view key folded out and their own folded
    // in: an id nobody made, which no view was ever given.
    let policy = AccessPolicy::parse(POLICY);
    let mut made = real.0;
    fold_view_key(&mut made, "admin");
    fold_view_key(&mut made, &View::anonymous(&policy).key());
    let made = ObjectId(made);
    assert_ne!(made, real);
    let got = tree(None, &made);
    assert_eq!(got.status, 404, "an id nobody made answered: {}", String::from_utf8_lossy(&got.body));
}

/// BUG-1874: S16 made `vl` take its session token from the environment
/// (`VEIL_TOKEN`, `crates/vl/src/hub.rs` `Client::new`), whatever server it
/// talks to: a token one server issued is presented to every other server
/// `vl` reaches (another remote, a clone of someone else's project). A
/// stored session is kept per server and goes only to that one.
#[test]
fn bug_1874_vl_presents_no_token_to_a_server_that_did_not_issue_it() {
    let hub = TestHub::start();
    let alice = hub.person("alice");
    let proj = unique("rvtoken");
    let dir = alice.dir("t");
    std::fs::create_dir_all(&dir).unwrap();
    alice.ok(&dir, &["init"]);
    alice.ok(&dir, &["remote", "add", "origin", &hub.url(&proj)]);
    write_files(&dir, &[(".veilpolicy", "public/ public\n"), ("public/readme.txt", "hello\n")]);
    alice.commit_main(&dir, "first");
    alice.ok(&dir, &["push"]);

    // Anyone on Earth, signed in nowhere, clones the public folder.
    let anyone = hub.anyone();
    let base = anyone.dir("base");
    std::fs::create_dir_all(&base).unwrap();
    let plain = anyone.run(&base, &["clone", "--full", &hub.url(&proj), anyone.dir("c0").to_str().unwrap()]);
    assert!(plain.status.success(), "{}{}", String::from_utf8_lossy(&plain.stdout), String::from_utf8_lossy(&plain.stderr));

    // The same clone while the environment holds a session of another
    // server (one this server never issued): this server must not see it.
    let mut c = anyone.command(&base, &["clone", "--full", &hub.url(&proj), anyone.dir("c1").to_str().unwrap()]);
    c.env("VEIL_TOKEN", "ab".repeat(32));
    let o = c.output().unwrap();
    assert!(
        o.status.success(),
        "vl sent another server's token to this one: {}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );

    // And a session stored in hub.json for another authority is never sent here either.
    let veil_home = anyone.home.path().join("veil");
    std::fs::create_dir_all(&veil_home).unwrap();
    std::fs::write(
        veil_home.join("hub.json"),
        serde_json::to_vec(&serde_json::json!({
            "servers": {
                "other.example:4443": {
                    "token": "cd".repeat(32),
                    "expires_at": veil_core::now_millis() + 3_600_000,
                    "person": "someone"
                }
            }
        }))
        .unwrap(),
    )
    .unwrap();
    let o2 = anyone.run(&base, &["clone", "--full", &hub.url(&proj), anyone.dir("c2").to_str().unwrap()]);
    assert!(
        o2.status.success(),
        "vl sent another authority's stored token to this server: {}{}",
        String::from_utf8_lossy(&o2.stdout),
        String::from_utf8_lossy(&o2.stderr)
    );
}
