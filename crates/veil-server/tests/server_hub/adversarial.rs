//! The independent adversarial pass on milestone S1 (docs/BUGS.md,
//! "Server S1: adversarial pass"): each test is one finding's
//! reproduction. Attackers are outside the trust boundary
//! (docs/ARCHITECTURE.md, "Threat model") unless a test says otherwise.

use std::{
    io::Read,
    time::{Duration, Instant},
};

use serde_json::json;
use veil_core::{
    crypto::domains::SIG_CONTEXT_HUB_LOGIN,
    hub::wire::login_message,
    object::Object,
    Identity, ObjectId,
};

use crate::support::*;

/// Everything `token` (or anyone on Earth) receives by walking branch
/// `branch` as the server shows it: the snapshot and every tree and file
/// of its projection, fetched at their paths.
fn walk(api: &Api, token: Option<&str>, project: &str, branch: &str) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let Some(tips) = api.tips(token, project) else { return out };
    let Some(tip) = tips.branches.get(branch).copied() else { return out };
    let h = api.post_json(token, &format!("/v1/projects/{project}/history"), &json!({"tips": [tip.hex()]}));
    let frames = h.frames();
    let (_, raw) = frames.iter().find(|(id, _)| *id == tip).unwrap();
    out.push(("snapshot".into(), raw.clone()));
    let Object::Snapshot(s) = Object::decode(raw).unwrap() else { panic!() };
    let mut stack = vec![(String::new(), s.tree)];
    while let Some((path, id)) = stack.pop() {
        let r = api.post_json(
            token,
            &format!("/v1/projects/{project}/fetch"),
            &json!({"snapshot": tip.hex(), "objects": [{"path": path, "id": id.hex()}]}),
        );
        let (_, raw) = r.frames().into_iter().next().unwrap();
        if let Ok(Object::Tree(t)) = Object::decode(&raw) {
            for e in &t.entries {
                let child = if path.is_empty() { e.name.clone() } else { format!("{path}/{}", e.name) };
                out.push((format!("name {child}"), child.clone().into_bytes()));
                stack.push((child, e.id));
            }
        }
        out.push((format!("object at '{path}'"), raw));
    }
    out
}

/// The entry at `path` of snapshot `snap`, as `token` is shown it.
fn entry_of(api: &Api, token: &str, project: &str, snap: ObjectId, path: &str) -> veil_core::TreeEntry {
    let h = api.post_json(Some(token), &format!("/v1/projects/{project}/history"), &json!({"tips": [snap.hex()]}));
    let (_, raw) = h.frames().into_iter().find(|(id, _)| *id == snap).unwrap();
    let Object::Snapshot(s) = Object::decode(&raw).unwrap() else { panic!() };
    let mut tree = s.tree;
    let mut dir = String::new();
    let parts: Vec<&str> = path.split('/').collect();
    for (i, part) in parts.iter().enumerate() {
        let r = api.post_json(
            Some(token),
            &format!("/v1/projects/{project}/fetch"),
            &json!({"snapshot": snap.hex(), "objects": [{"path": dir, "id": tree.hex()}]}),
        );
        let Object::Tree(t) = Object::decode(&r.frames()[0].1).unwrap() else { panic!() };
        let e = t.get(part).unwrap().clone();
        if i + 1 == parts.len() {
            return e;
        }
        tree = e.id;
        dir = if dir.is_empty() { part.to_string() } else { format!("{dir}/{part}") };
    }
    unreachable!()
}

fn parents_of(api: &Api, token: &str, project: &str, snap: ObjectId) -> Vec<ObjectId> {
    let h = api.post_json(Some(token), &format!("/v1/projects/{project}/history"), &json!({"tips": [snap.hex()]}));
    let (_, raw) = h.frames().into_iter().find(|(id, _)| *id == snap).unwrap();
    let Object::Snapshot(s) = Object::decode(&raw).unwrap() else { panic!() };
    s.parents
}

/// A person's private project holding `marker`.
fn private_project(hub: &TestHub, who: &Person, marker: &str) -> String {
    let name = unique("priv");
    let d = who.dir(&name);
    std::fs::create_dir_all(&d).unwrap();
    who.ok(&d, &["init"]);
    write_files(&d, &[("plan.txt", marker)]);
    who.ok(&d, &["remote", "add", "origin", &hub.url(&name)]);
    who.commit_main(&d, "private");
    who.ok(&d, &["push"]);
    name
}

/// BUG-819. Attacker: the operator of another Veil server the victim
/// signs in to (any `vl login` to it, or a silent re-login after a 401).
/// They relay this server's challenge for the victim's key; the victim's
/// `vl` signs it for the attacker's server name, and the attacker sends
/// that name as the `Host` header too. Harm: a session as the victim here.
#[test]
fn bug_819_a_login_relayed_by_another_server_is_refused() {
    let hub = TestHub::start();
    let victim = hub.person("victim");
    let marker = "MARKER-RELAY-PRIVATE-5c1d93a0";
    let project = private_project(&hub, &victim, marker);
    let api = hub.api();
    let id = victim.identity();
    let ch = api.post_json(None, "/v1/auth/challenge", &json!({"key": id.verifying_hex()}));
    let challenge = ch.json()["challenge"].as_str().unwrap().to_string();
    // What the victim's `vl` sends to evil.example when it signs in there.
    let evil = "evil.example:443";
    let body = json!({
        "key": id.verifying_hex(),
        "challenge": challenge,
        "hub": evil,
        "signature": id.sign(SIG_CONTEXT_HUB_LOGIN, &login_message(evil, &challenge)),
        "identity": id.public_id(),
        "name": null,
    });
    let r = api.post_json_host("/v1/auth/login", &body, evil);
    if r.status == 200 {
        let token = r.json()["token"].as_str().unwrap().to_string();
        let got = walk(&api, Some(&token), &project, "main");
        panic!(
            "a login signed for {evil} was accepted (the victim's private project {}readable)",
            if has_marker(&got, marker) { "is " } else { "is not " }
        );
    }
    assert_eq!(r.status, 401, "{}", String::from_utf8_lossy(&r.body));
    // The genuine login still works.
    api.login(&id, None).unwrap();
}

/// BUG-820. Attacker: a participant who may read a public folder but not
/// write it (carol: named on her own folder's rule). They push a merge of
/// the tip and an older snapshot that takes the older version of a file
/// in `src/` (writable only by `devs`): "taken unchanged from another
/// parent" lets it through. Harm: anyone in the project rolls back any
/// file they can read, e.g. a security fix.
#[test]
fn bug_820_a_merge_cannot_revert_a_file_the_pusher_may_not_write() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    // A dev fixes src/lib.rs.
    let d = p.dev.dir("c");
    p.dev.ok(p.dev.home.path(), &["clone", &hub.url(&p.name), d.to_str().unwrap()]);
    write_files(&d, &[("src/lib.rs", "fixed: MARKER-THE-FIX-1b2c")]);
    p.dev.commit_main(&d, "security fix");
    p.dev.ok(&d, &["push"]);
    let api = hub.api();
    let token = p.carol.token();
    let fixed = api.tips(Some(&token), &p.name).unwrap().branches["main"];
    let before = parents_of(&api, &token, &p.name, fixed)[0];
    let old = entry_of(&api, &token, &p.name, before, "src/lib.rs");
    // Carol may not write src/ directly...
    let mut c = Craft::new(&api, &p.carol, &p.name, "main");
    c.copy("src/lib.rs", before, "src/lib.rs", old.id, old.size);
    let r = c.push("main", "revert");
    assert_eq!(r.status, 403, "{}", String::from_utf8_lossy(&r.body));
    // ...nor through a merge with the snapshot before the fix.
    let mut c = Craft::new(&api, &p.carol, &p.name, "main");
    c.refer("src/lib.rs", old.id, old.size);
    let r = c.push_merge("main", &[before]);
    assert_eq!(r.status, 403, "the revert landed: {}", String::from_utf8_lossy(&r.body));
    assert_eq!(api.tips(Some(&token), &p.name).unwrap().branches["main"], fixed);
    // Merging a dev's branch still takes the dev's change of src/.
    let mut f = Craft::new(&api, &p.dev, &p.name, "main");
    f.file("src/lib.rs", "the dev's next change");
    let r = f.push_to("feat", None);
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let feat = api.tips(Some(&token), &p.name).unwrap().branches["feat"];
    let theirs = entry_of(&api, &token, &p.name, feat, "src/lib.rs");
    let mut c = Craft::new(&api, &p.carol, &p.name, "main");
    c.refer("src/lib.rs", theirs.id, theirs.size);
    let r = c.push_merge("main", &[feat]);
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert!(r.json()["results"][0]["ok"].as_bool().unwrap(), "{}", String::from_utf8_lossy(&r.body));
}

/// BUG-821. Attacker: anyone on Earth who signs up under a likely group
/// name (`ops-…`) before the project has that group. The admin writes
/// the access line, then creates the group and adds its people, as
/// teams do. The name stays bound to the squatter. Harm: the squatter
/// reads the folder; the group's members never get it.
#[test]
fn bug_821_a_group_created_after_its_access_line_takes_the_name() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let gname = unique("ops");
    let squatter = api.login(&Identity::generate("squat"), Some(&gname)).unwrap();
    let marker = "MARKER-OPS-PLAN-0e7d55aa";
    p.admin.ok(&p.dir, &["new", "main"]);
    write_files(&p.dir, &[("ops-area/plan.txt", marker)]);
    p.admin.ok(&p.dir, &["access", "ops-area/", &gname]);
    p.admin.commit_main(&p.dir, "ops folder");
    p.admin.ok(&p.dir, &["push"]);
    p.admin.ok(&p.dir, &["group", "create", &gname]);
    p.admin.ok(&p.dir, &["group", "add", &gname, &p.fin.name]);
    // A group always wins: the person who signed up under its name loses
    // the folder...
    let got = walk(&api, Some(&squatter), &p.name, "main");
    assert_no_marker(&got, &[marker], "the squatter");
    // ...and the group's member reads it.
    let fin = walk(&api, Some(&p.fin.token()), &p.name, "main");
    assert!(has_marker(&fin, marker), "the group's member does not see the folder");
}

/// BUG-822. Attacker: a participant (a dev). They post the first key ring
/// of a secret scope the project does not have yet (as with `vl upgrade
/// --sync-secrets`, or a new scope): they are its only ring admin. Harm:
/// the admins' own ring for that scope is refused from then on, and new
/// members' devices adopt the dev's ring and seal under the dev's key.
#[test]
fn bug_822_only_an_admin_starts_a_key_ring() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let d = p.dev.dir("c");
    p.dev.ok(p.dev.home.path(), &["clone", &hub.url(&p.name), d.to_str().unwrap()]);
    p.dev.ok(&d, &["scope", "create", "ops"]);
    let ring: serde_json::Value = serde_json::from_slice(&std::fs::read(d.join(".veil/meta/keyrings/ops.json")).unwrap()).unwrap();
    let api = hub.api();
    let r = api.post_json(Some(&p.dev.token()), &format!("/v1/projects/{}/rings/ops", p.name), &ring);
    assert_eq!(r.status, 403, "a dev started the project's 'ops' key ring: {}", String::from_utf8_lossy(&r.body));
    // An admin may.
    p.admin.ok(&p.dir, &["scope", "create", "ops"]);
    let ring: serde_json::Value = serde_json::from_slice(&std::fs::read(p.dir.join(".veil/meta/keyrings/ops.json")).unwrap()).unwrap();
    let r = api.post_json(Some(&p.admin.token()), &format!("/v1/projects/{}/rings/ops", p.name), &ring);
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
}

/// BUG-823. Attacker: none (a confusing failure). A branch whose only
/// change since `main` is in a folder the dev cannot see looks to them
/// like `main`. Their push to that branch is grafted onto `main`'s tip or
/// the branch's, at random, and in the first case refused as "not a
/// fast-forward" however often they pull.
#[test]
fn bug_823_a_push_builds_on_the_tip_of_the_branch_it_moves() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    for i in 0..8 {
        let branch = format!("feat-{i}");
        let mut f = Craft::new(&api, &p.fin, &p.name, "main");
        f.file(&format!("{BILL_DIR}/feat-{i}.txt"), "billing only");
        let r = f.push_to(&branch, None);
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        let mut c = Craft::new(&api, &p.dev, &p.name, &branch);
        let seen = c.tip;
        c.file(&format!("src/dev-{i}.rs"), "fn x() {}");
        let r = c.push_to(&branch, Some(seen));
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        let ok = r.json()["results"][0]["ok"].as_bool().unwrap();
        assert!(ok, "attempt {i}: {}", String::from_utf8_lossy(&r.body));
    }
}

/// BUG-824. Attacker: a participant with write access somewhere (a dev).
/// A push could name, without uploading it, any object the project stores:
/// it landed if the object existed and failed if not. Harm: confirms
/// guesses of whole files in folders they cannot see (a short password
/// file, a salary). Fixed: a push names only objects its pusher uploaded
/// (upload receipts) or that are already at that path in a parent.
#[test]
fn bug_824_a_push_does_not_confirm_guesses_of_hidden_content() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let path = format!("{BILL_DIR}/acme/invoice.txt");
    let real = real_paths(&p.dir).into_iter().find(|(q, _)| *q == path).unwrap().1;
    // The guess is the file's exact content; its id follows from it.
    let mut right = Craft::new(&api, &p.dev, &p.name, "main");
    right.refer("src/guess.txt", real, 10);
    let r_right = right.push("main", "guess");
    let wrong_id = ObjectId::hash(&Object::Blob(b"a wrong guess".to_vec()).encode());
    let mut wrong = Craft::new(&api, &p.dev, &p.name, "main");
    wrong.refer("src/guess2.txt", wrong_id, 10);
    let r_wrong = wrong.push("main", "guess");
    assert_eq!(
        r_right.status,
        r_wrong.status,
        "a right guess and a wrong one get different answers: {} / {}",
        String::from_utf8_lossy(&r_right.body),
        String::from_utf8_lossy(&r_wrong.body)
    );
    let msg = |r: &Reply, ids: [ObjectId; 2]| {
        let mut m = String::from_utf8_lossy(&r.body).to_string();
        for id in ids {
            m = m.replace(&id.short(), "ID");
        }
        m
    };
    assert_eq!(msg(&r_right, [real, wrong_id]), msg(&r_wrong, [real, wrong_id]));
    // A whole hidden folder guessed as a tree: the same answer too.
    let bill = real_paths(&p.dir).into_iter().find(|(q, _)| *q == BILL_DIR).unwrap().1;
    let mut right = Craft::new(&api, &p.dev, &p.name, "main");
    right.refer_dir("src/guess", bill);
    let r_right = right.push("main", "guess");
    let mut wrong = Craft::new(&api, &p.dev, &p.name, "main");
    wrong.refer_dir("src/guess", wrong_id);
    let r_wrong = wrong.push("main", "guess");
    assert_eq!(
        msg(&r_right, [bill, wrong_id]),
        msg(&r_wrong, [bill, wrong_id]),
        "a guessed hidden folder gets another answer than a wrong guess"
    );
    // Uploading the guess itself lands the push whether or not the
    // project held it: the push says nothing about other folders.
    let mut c = Craft::new(&api, &p.dev, &p.name, "main");
    c.file("src/guess.txt", BILL_MARK);
    let r = c.push("main", "uploaded guess");
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
}

/// BUG-825. Attacker: anyone on Earth. TCP connections that never start
/// TLS (or never send a request) are held open forever, one task each.
/// Harm: a few thousand idle sockets exhaust the server's file
/// descriptors; then `accept` fails and the accept loop spins.
#[test]
fn bug_825_a_silent_connection_is_closed() {
    let hub = TestHub::start();
    let mut s = std::net::TcpStream::connect(("127.0.0.1", hub.port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(45))).unwrap();
    let start = Instant::now();
    let mut buf = [0u8; 16];
    let r = s.read(&mut buf);
    let open = matches!(&r, Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut));
    assert!(!open, "a silent connection was still open after {:?}", start.elapsed());
}

/// BUG-826. Attacker: none (low). A projected snapshot kept the real
/// ids in `predecessors`: a viewer learned the id of an earlier version
/// of a change that touched a folder they cannot see. Fixed: they are
/// projected too.
#[test]
fn bug_826_a_projection_names_no_hidden_predecessor() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    // The admin pushes a change of billing and src to `a`...
    let mut c = Craft::new(&api, &p.admin, &p.name, "main");
    c.file(&format!("{BILL_DIR}/a.txt"), "a");
    c.file("src/a.rs", "a");
    let (first, r) = c.push_edited("a", None, |_| {});
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    // ...then a new version of it to `b`.
    let mut c = Craft::new(&api, &p.admin, &p.name, "main");
    c.file(&format!("{BILL_DIR}/a.txt"), "a2");
    c.file("src/a.rs", "a2");
    let (_, r) = c.push_edited("b", None, |s| s.predecessors = vec![first]);
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let token = p.dev.token();
    let tip = api.tips(Some(&token), &p.name).unwrap().branches["b"];
    let h = api.post_json(Some(&token), &format!("/v1/projects/{}/history", p.name), &json!({"tips": [tip.hex()]}));
    let (_, raw) = h.frames().into_iter().find(|(id, _)| *id == tip).unwrap();
    let Object::Snapshot(s) = Object::decode(&raw).unwrap() else { panic!() };
    assert!(!s.predecessors.contains(&first), "the dev was given the real id of a change of billing");
    // ...but the dev's own version of it: their history stays connected.
    let seen_first = api.tips(Some(&token), &p.name).unwrap().branches["a"];
    assert_eq!(s.predecessors, vec![seen_first]);
    // A later version that touches only what the dev sees is no longer
    // served as is when its predecessor touched more.
    let mut c = Craft::new(&api, &p.admin, &p.name, "main");
    c.file("src/a.rs", "a3");
    let (_, r) = c.push_edited("c", None, |s| s.predecessors = vec![first]);
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let tip_c = api.tips(Some(&token), &p.name).unwrap().branches["c"];
    let h = api.post_json(Some(&token), &format!("/v1/projects/{}/history", p.name), &json!({"tips": [tip_c.hex()]}));
    let (_, raw) = h.frames().into_iter().find(|(id, _)| *id == tip_c).unwrap();
    let Object::Snapshot(sc) = Object::decode(&raw).unwrap() else { panic!() };
    assert_eq!(sc.predecessors, vec![seen_first]);
    assert_eq!(sc.signature_valid(), Some(true));
    // The admin sees the real one.
    let tip = api.tips(Some(&p.admin.token()), &p.name).unwrap().branches["b"];
    let h = api.post_json(Some(&p.admin.token()), &format!("/v1/projects/{}/history", p.name), &json!({"tips": [tip.hex()]}));
    let (_, raw) = h.frames().into_iter().find(|(id, _)| *id == tip).unwrap();
    let Object::Snapshot(s) = Object::decode(&raw).unwrap() else { panic!() };
    assert_eq!(s.predecessors, vec![first]);
}

/// BUG-827. Attacker: a compromised server (outside the boundary for
/// secrets: HUB.md §13.6). It lists its own device under a person an
/// admin adds to a group; the admin's `vl group add` wrapped the secret
/// key for every listed device. Harm: the server (or whoever broke in)
/// holds the project's secret key and opens every `.env`. Fixed: a key is
/// wrapped only for devices vouched for outside the server (§13.11).
#[test]
fn bug_827_a_server_cannot_slip_its_own_device_into_a_key_grant() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let newbie = hub.person("newbie");
    let mal = Identity::generate("mal");
    let db = hub.hub().db.clone();
    hub.rt
        .block_on(
            sqlx::query(
                "INSERT INTO devices (person_id, signing_key, public_identity, created_at) SELECT id, $1, $2, 0 FROM people WHERE name = $3",
            )
            .bind(mal.verifying_hex())
            .bind(mal.public_id())
            .bind(&newbie.name)
            .execute(&db),
        )
        .unwrap();
    let api = hub.api();
    let member = veil_core::identity::parse_public_identity(&mal.public_id()).unwrap().member_id();
    let mine = newbie.identity().public_hex();
    let rings = |who: &str| String::from_utf8_lossy(&api.get(Some(&p.admin.token()), &format!("/v1/projects/{}/rings", p.name)).body).contains(who);
    // Unconfirmed: both devices are shown to be confirmed, neither gets the key.
    let out = p.admin.ok(&p.dir, &["group", "add", "finance", &newbie.name]);
    assert!(out.contains(&format!("confirm {}'s device", newbie.name)), "{out}");
    assert!(!rings(&member), "the server's device was granted the secret key");
    assert!(!rings(&mine), "an unconfirmed device was granted the secret key");
    // The server forges vouches for its device: signed by its own key, and
    // newbie's genuine signature over another device moved onto it.
    let other = Identity::generate("newbie");
    let pid = |i: &Identity| veil_core::identity::parse_public_identity(&i.public_id()).unwrap();
    let genuine = newbie.identity().sign(
        veil_core::crypto::domains::SIG_CONTEXT_HUB_DEVICE,
        &veil_core::hub::wire::vouch_message(&pid(&other)).unwrap(),
    );
    let self_signed = mal.sign(veil_core::crypto::domains::SIG_CONTEXT_HUB_DEVICE, &veil_core::hub::wire::vouch_message(&pid(&mal)).unwrap());
    for (by, sig) in [(newbie.identity().verifying_hex(), genuine), (mal.verifying_hex(), self_signed)] {
        hub.rt
            .block_on(
                sqlx::query(
                    "INSERT INTO device_vouches (device_id, voucher_key, signature, created_at) SELECT id, $1, $2, 0 FROM devices WHERE signing_key = $3",
                )
                .bind(by)
                .bind(sig)
                .bind(mal.verifying_hex())
                .execute(&db),
            )
            .unwrap();
    }
    // The admin checks newbie's fingerprint with newbie: newbie's device
    // gets the key, the server's still does not.
    let out = p.admin.ok(&p.dir, &["group", "add", "finance", &newbie.name, "--confirm", &newbie.fingerprint()]);
    assert!(out.contains("granted to"), "{out}");
    assert!(rings(&mine), "the confirmed device has no key: {out}");
    assert!(!rings(&member), "the server's device was granted the secret key: {out}");
    // A fingerprint that matches nothing the server lists stops the grant.
    let other_fp = veil_core::hub::wire::device_fingerprint(&pid(&other)).unwrap();
    let out = p.admin.fails(&p.dir, &["group", "add", "finance", &newbie.name, "--confirm", &other_fp]);
    assert!(out.contains("different device"), "{out}");
    assert!(!rings(&member));
}

/// A person's later device is confirmed by the person (cross-signing),
/// and then receives the key from an admin without asking the admin to
/// check a fingerprint again (HUB.md §13.11). Until confirmed, it is
/// nothing: no session, no folder, no key.
#[test]
fn a_later_device_is_confirmed_by_its_person() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let laptop = hub.new_device_of(&p.fin);
    let api = hub.api();
    // Pending: anyone on Earth until confirmed.
    let d = laptop.dir("early");
    let _ = laptop.run(laptop.home.path(), &["clone", &hub.url(&p.name), d.to_str().unwrap()]);
    assert_no_marker(&everything_in(&d), &[BILL_MARK, ENV_MARK], "a pending device");
    // fin confirms it from the device they already use.
    let fp = laptop.fingerprint();
    p.fin.ok(p.fin.home.path(), &["identity", "confirm", &fp]);
    laptop.ok(laptop.home.path(), &["login", &format!("veil://{}", hub.authority()), "--ca", hub.ca.to_str().unwrap()]);
    let c = laptop.dir("c");
    laptop.ok(laptop.home.path(), &["clone", &hub.url(&p.name), c.to_str().unwrap()]);
    assert!(c.join(BILL_DIR).join("acme/invoice.txt").exists(), "folder access follows the person");
    assert!(!c.join(BILL_DIR).join(".env").exists(), "no key before an admin wraps it");
    // The admin's next `vl group add` wraps the key for it: no fingerprint
    // to check, fin's first device vouched for it.
    let out = p.admin.ok(&p.dir, &["group", "add", "finance", &p.fin.name]);
    assert!(!out.contains("confirm "), "{out}");
    assert!(out.contains("granted to"), "{out}");
    let c2 = laptop.dir("c2");
    laptop.ok(laptop.home.path(), &["clone", &hub.url(&p.name), c2.to_str().unwrap()]);
    assert!(std::fs::read_to_string(c2.join(BILL_DIR).join(".env")).unwrap().contains(ENV_MARK));
    // Another person cannot confirm a device under fin's name...
    let thief = hub.new_device_of(&p.fin);
    let out = p.dev.fails(p.dev.home.path(), &["identity", "confirm", &thief.fingerprint()]);
    assert!(out.contains("none of"), "{out}");
    // ...nor through the API, with a valid signature of their own.
    let pid = veil_core::identity::parse_public_identity(&thief.identity().public_id()).unwrap();
    let sig = p.dev.identity().sign(veil_core::crypto::domains::SIG_CONTEXT_HUB_DEVICE, &veil_core::hub::wire::vouch_message(&pid).unwrap());
    let r = api.post_json(Some(&p.dev.token()), "/v1/devices/vouch", &json!({"device": thief.identity().public_id(), "signature": sig}));
    assert_eq!(r.status, 404, "{}", String::from_utf8_lossy(&r.body));
    thief.fails(thief.home.path(), &["login", &format!("veil://{}", hub.authority()), "--ca", hub.ca.to_str().unwrap()]);
    // Removing fin from their last group rotates the key away from both
    // devices, even one a compromised server leaves out of the list.
    hub.rt
        .block_on(
            sqlx::query("UPDATE devices SET removed_at = 1 WHERE signing_key = $1")
                .bind(laptop.identity().verifying_hex())
                .execute(&hub.hub().db),
        )
        .unwrap();
    let out = p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    assert!(out.contains("rotated away"), "{out}");
    let repo = veil_core::Repo::open(std::sync::Arc::new(veil_core::DiskBackend::new(&p.dir)), None, "test").unwrap();
    let st = repo.keys().ring_state("team").unwrap().unwrap().unwrap();
    for who in [&p.fin, &laptop] {
        assert!(!st.members.contains_key(&who.identity().public_hex()), "{} kept the key", who.home.path().display());
    }
}

/// BUG-828. Attacker: none (a silent gap). A group's manager removes
/// someone from their last group: the folder closes, but the manager's
/// device is no ring admin, so the secret key is not rotated, and
/// nothing says so (an admin's removal rotates it).
#[test]
fn bug_828_a_managers_removal_says_the_key_was_not_rotated() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    p.admin.ok(&p.dir, &["group", "manager", "finance", &p.carol.name]);
    let c = p.carol.dir("c");
    p.carol.ok(p.carol.home.path(), &["clone", &hub.url(&p.name), c.to_str().unwrap()]);
    let out = p.carol.ok(&c, &["group", "remove", "finance", &p.fin.name]);
    assert!(out.contains("not rotated"), "{out}");
}

/// Held up (no finding). Attacker: whoever controls what a member pulls
/// (a compromised server signs projections, so it can serve any
/// `.veilpolicy`). A pulled policy that exposes `.env` (`.en[v] public!`:
/// a device rule, not an access line)
/// would make the server accept the member's next `.env` in plain text:
/// the member's device holds the weakening back, and keeps sealing.
#[test]
fn a_pulled_policy_never_unseals_a_members_secret() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    p.admin.ok(&p.dir, &["new", "main"]);
    p.admin.ok(&p.dir, &["access", ".veilpolicy", "finance"]);
    p.admin.commit_main(&p.dir, "finance reads the policy");
    p.admin.ok(&p.dir, &["push"]);
    let f = p.fin.dir("c");
    p.fin.ok(p.fin.home.path(), &["clone", &hub.url(&p.name), f.to_str().unwrap()]);
    p.admin.ok(&p.dir, &["new", "main"]);
    let policy = std::fs::read_to_string(p.dir.join(".veilpolicy")).unwrap();
    std::fs::write(p.dir.join(".veilpolicy"), format!("{policy}{BILL_DIR}/.en[v]  public!\n")).unwrap();
    p.admin.commit_main(&p.dir, "expose");
    p.admin.ok(&p.dir, &["push"]);
    p.fin.ok(&f, &["pull"]);
    p.fin.ok(&f, &["new", "main"]);
    let marker = "MARKER-FIN-NEW-SECRET-3c9e04d1";
    write_files(&f, &[(&format!("{BILL_DIR}/.env"), &format!("KEY={marker}\n"))]);
    p.fin.ok(&f, &["commit", "-m", "rotate the key"]);
    p.fin.ok(&f, &["tag", "set", "main", "-r", "@-", "--force"]);
    let out = p.fin.ok(&f, &["push"]);
    let _ = out;
    let api = hub.api();
    let got = walk(&api, Some(&p.admin.token()), &p.name, "main");
    assert_no_marker(&got, &[marker], "the server");
    // The member's new secret did land, sealed.
    p.admin.ok(&p.dir, &["pull"]);
    p.admin.ok(&p.dir, &["new", "main"]);
    let env = std::fs::read_to_string(p.dir.join(format!("{BILL_DIR}/.env"))).unwrap();
    assert!(env.contains(marker), "the member's push did not land: {env}");
}

/// BUG-834. Attacker: a participant who may write somewhere (dev writes
/// `src/`). Controls: a pushed conflict object whose terms name an object
/// id the push never uploaded. Upload receipts cover entries, not the ids
/// a conflict names, and the fetch route serves an id a conflict at a
/// readable path names. Harm: a right guess of a hidden file is served
/// back (a wrong one is not found): BUG-824's oracle, through fetch.
#[test]
fn bug_834_a_conflict_names_no_hidden_object() {
    use veil_core::object::{Conflict, ConflictTerm, EntryKind, TermKind, TreeEntry, Visibility};
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let path = format!("{BILL_DIR}/acme/invoice.txt");
    let real = real_paths(&p.dir).into_iter().find(|(q, _)| *q == path).unwrap().1;
    let term = |id: ObjectId| {
        Some(ConflictTerm {
            kind: TermKind::File,
            id,
            size: 1,
            executable: false,
            visibility: Visibility::Public,
            fallback: None,
        })
    };
    let mut c = Craft::new(&api, &p.dev, &p.name, "main");
    let mine = c.put_object(Object::Blob(b"mine".to_vec()));
    let conflict = c.put_object(Object::Conflict(Conflict {
        adds: vec![term(mine), term(real)],
        removes: vec![term(mine)],
    }));
    c.set_entry(
        "src/c.txt",
        TreeEntry {
            name: String::new(),
            kind: EntryKind::Conflict,
            id: conflict,
            size: 0,
            executable: false,
            visibility: Visibility::Public,
            fallback: None,
        },
    );
    let r = c.push("main", "a conflict");
    if r.status == 200 {
        let tip = api.tips(Some(&p.dev.token()), &p.name).unwrap().branches["main"];
        let f = api.post_json(
            Some(&p.dev.token()),
            &format!("/v1/projects/{}/fetch", p.name),
            &json!({"snapshot": tip.hex(), "objects": [{"path": "src/c.txt", "id": real.hex()}]}),
        );
        assert!(
            !String::from_utf8_lossy(&f.body).contains(BILL_MARK),
            "a hidden file was served through a conflict that names it"
        );
    }
}

/// BUG-834, the other route: a sealed secret's `fallback` names an object
/// the push never uploaded, and the fetch route serves an entry's fallback.
#[test]
fn bug_834_a_fallback_names_no_hidden_object() {
    use veil_core::{
        crypto::{Envelope, Suite},
        object::{EntryKind, TreeEntry, Visibility},
    };
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let path = format!("{BILL_DIR}/acme/invoice.txt");
    let real = real_paths(&p.dir).into_iter().find(|(q, _)| *q == path).unwrap().1;
    let mut c = Craft::new(&api, &p.dev, &p.name, "main");
    let sealed = c.put_object(Object::Sealed(Envelope {
        scope: "team".into(),
        suite: Suite::AesSiv,
        ciphertext: vec![7u8; 48],
    }));
    c.set_entry(
        "src/.env",
        TreeEntry {
            name: String::new(),
            kind: EntryKind::File,
            id: sealed,
            size: 1,
            executable: false,
            visibility: Visibility::Cloaked { scope: "team".into() },
            fallback: Some(real),
        },
    );
    let r = c.push("main", "a secret with a fallback");
    if r.status == 200 {
        let tip = api.tips(Some(&p.dev.token()), &p.name).unwrap().branches["main"];
        let f = api.post_json(
            Some(&p.dev.token()),
            &format!("/v1/projects/{}/fetch", p.name),
            &json!({"snapshot": tip.hex(), "objects": [{"path": "src/.env", "id": real.hex()}]}),
        );
        assert!(
            !String::from_utf8_lossy(&f.body).contains(BILL_MARK),
            "a hidden file was served as a secret's fallback"
        );
    } else {
        println!("refused: {}", String::from_utf8_lossy(&r.body));
    }
}

/// BUG-835. Attacker: a compromised server, with a person it will help
/// keep the key after their removal. Controls: the device lists. When an
/// admin adds two people at once and confirms one's device (`vl group add
/// finance one two --confirm <two's fingerprint>`), the server lists
/// two's device under one: the fingerprint matched there, so the key ring
/// recorded two's device under the name `one`. Removing two later revokes
/// only what the server lists for two and the ring members named `two`:
/// two's device keeps the secret key. Fixed: a `--confirm` names one
/// person's device, so it takes one person.
#[test]
fn bug_835_a_confirmed_device_is_recorded_under_its_persons_name() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let one = hub.person("one");
    let two = hub.person("two");
    // two keeps a (pending) device of their own, so the server still
    // lists a person named two.
    let _spare = hub.new_device_of(&two);
    let db = hub.hub().db.clone();
    let move_device = |to: &str| {
        hub.rt
            .block_on(
                sqlx::query("UPDATE devices SET person_id = (SELECT id FROM people WHERE name = $1) WHERE signing_key = $2")
                    .bind(to)
                    .bind(two.identity().verifying_hex())
                    .execute(&db),
            )
            .unwrap();
    };
    // The admin compared two's fingerprint with two; the server lists
    // two's device under one.
    move_device(&one.name);
    let fp = two.fingerprint();
    let out = p.admin.run(&p.dir, &["group", "add", "finance", &one.name, &two.name, "--confirm", &fp]);
    let out = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    move_device(&two.name);
    let ring = || {
        let repo = veil_core::Repo::open(std::sync::Arc::new(veil_core::DiskBackend::new(&p.dir)), None, "test").unwrap();
        repo.keys().ring_state("team").unwrap().unwrap().unwrap()
    };
    let member = two.identity().public_hex();
    assert!(out.contains("one at a time"), "{out}");
    if let Some(m) = ring().members.get(&member) {
        assert_eq!(m.name, two.name, "two's device was recorded under another name: {out}");
    }
    // Removing two (the server hides two's device) leaves two no key.
    move_device(&one.name);
    p.admin.ok(&p.dir, &["group", "remove", "finance", &two.name]);
    assert!(!ring().members.contains_key(&member), "two kept the secret key after their removal");
}

/// BUG-836. Attacker: a compromised server keeping a removed person the
/// key. Controls: the group list an admin's `vl group remove` reads to
/// decide whether the person still has the folder. It says fin is still
/// in another group the folder's line names: the key was not rotated, and
/// nothing said so. Fixed: the removal says who keeps the key, and why.
#[test]
fn bug_836_a_removal_that_does_not_rotate_says_so() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    // billing/ is finance's and security's.
    p.admin.ok(&p.dir, &["access", &format!("{BILL_DIR}/"), "finance", "security"]);
    // The server's records gain fin in `security` (no admin did that).
    hub.rt
        .block_on(
            sqlx::query(
                "INSERT INTO group_members (group_id, person_id) SELECT g.id, pe.id FROM groups g JOIN projects pr ON pr.id = g.project_id, \
                 people pe WHERE pr.name = $1 AND g.name = 'security' AND pe.name = $2",
            )
            .bind(&p.name)
            .bind(&p.fin.name)
            .execute(&hub.hub().db),
        )
        .unwrap();
    let out = p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    assert!(out.contains("not rotated") && out.contains("security"), "{out}");
}

/// BUG-832's fix, held against its own risk. Attacker: a teammate who may
/// write `billing/` and holds the `team` key. Controls: a sealed
/// `billing/.netrc` they commit (the project's policy seals it). fin,
/// who cannot read the policy, keeps a `.netrc` of their own there, which
/// the built-in rules keep local. fin's snapshots must never seal fin's
/// file under `team` (the teammate would open it): the recorded entry is
/// kept, fin's file stays on fin's device.
#[test]
fn a_view_without_the_policy_never_seals_a_local_only_file() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let d = p.fin.dir("c");
    p.fin.ok(p.fin.home.path(), &["clone", &hub.url(&p.name), d.to_str().unwrap()]);
    // fin's own credential, local-only on fin's device.
    let mine = "machine example.com login fin password MARKER-FINS-OWN-NETRC-5b1e";
    write_files(&d, &[(&format!("{BILL_DIR}/.netrc") as &str, mine)]);
    p.fin.ok(&d, &["status"]);
    // The teammate (here the admin) seals and pushes a `.netrc` of theirs.
    let policy = std::fs::read_to_string(p.dir.join(".veilpolicy")).unwrap();
    std::fs::write(p.dir.join(".veilpolicy"), format!("{policy}{BILL_DIR}/.netrc  cloak team\n")).unwrap();
    write_files(&p.dir, &[(&format!("{BILL_DIR}/.netrc") as &str, "machine example.com login team password theirs")]);
    p.admin.commit_main(&p.dir, "a shared netrc");
    p.admin.ok(&p.dir, &["push"]);
    // fin pulls, commits other work, and pushes.
    p.fin.ok(&d, &["pull"]);
    let _ = p.fin.run(&d, &["new", "main"]);
    write_files(&d, &[(&format!("{BILL_DIR}/q.txt") as &str, "q")]);
    if std::fs::read_to_string(d.join(BILL_DIR).join(".netrc")).unwrap_or_default() != mine {
        write_files(&d, &[(&format!("{BILL_DIR}/.netrc") as &str, mine)]);
    }
    p.fin.commit_main(&d, "fin's work");
    p.fin.ok(&d, &["push"]);
    p.admin.ok(&p.dir, &["pull"]);
    p.admin.ok(&p.dir, &["new", "main"]);
    let got = std::fs::read_to_string(p.dir.join(BILL_DIR).join(".netrc")).unwrap_or_default();
    assert!(!got.contains("MARKER-FINS-OWN-NETRC-5b1e"), "fin's local-only credential was sealed and pushed: {got:?}");
    assert!(got.contains("theirs"), "{got:?}");
}
