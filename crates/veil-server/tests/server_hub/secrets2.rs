//! S2 secrets (`docs/HUB.md` §13.12): invites, keys per access rule,
//! sharing by members' devices, device removal, pending devices. Most
//! tests play a **compromised server**: it writes its own rows into the
//! database (devices, joins, vouches, memberships, invites) and must still
//! never get a key wrapped for a device of its choosing.

use std::{path::Path, sync::Arc, time::Duration};

use serde_json::json;
use veil_core::{
    crypto::domains::{SIG_CONTEXT_HUB_DEVICE, SIG_CONTEXT_HUB_INVITE, SIG_CONTEXT_RING_CHANGE},
    hub::wire::{device_fingerprint, join_message, vouch_message, InviteKey},
    identity::{parse_public_identity, PublicIdentity},
    keychain::{KeyRing, MemberGrant, RingChange, RingOp, RingState, Role, ShareProof},
    policy::{rule_scope_of, DEFAULT_SCOPE},
    Identity, ObjectId, VPath,
};

use crate::support::*;

pub(crate) fn pid(i: &Identity) -> PublicIdentity {
    parse_public_identity(&i.public_id()).unwrap()
}

/// Run `q` with text and integer binds on the server's database, again
/// while it loses a race (YugabyteDB reports deadlocks and conflicts under
/// load, as the server's own transactions retry them).
pub(crate) fn sql(hub: &TestHub, q: &str, binds: &[&dyn Bind]) {
    let db = hub.hub().db.clone();
    for attempt in 0.. {
        let mut query = sqlx::query(q);
        for b in binds {
            query = b.bind(query);
        }
        match hub.rt.block_on(query.execute(&db)) {
            Ok(_) => return,
            Err(e) if attempt < 100 && lost_race(&e) => std::thread::sleep(Duration::from_millis(20 + attempt * 10)),
            Err(e) => panic!("{q}: {e:?}"),
        }
    }
}

/// A serialisation failure or deadlock: run the statement again.
pub(crate) fn lost_race(e: &sqlx::Error) -> bool {
    matches!(e.as_database_error().and_then(|d| d.code()).as_deref(), Some("40001" | "40P01"))
}

pub(crate) trait Bind {
    fn bind<'q>(&'q self, q: sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments>)
        -> sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments>;
}
impl Bind for &str {
    fn bind<'q>(&'q self, q: sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments>) -> sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments> {
        q.bind(*self)
    }
}
impl Bind for String {
    fn bind<'q>(&'q self, q: sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments>) -> sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments> {
        q.bind(self.as_str())
    }
}
impl Bind for i64 {
    fn bind<'q>(&'q self, q: sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments>) -> sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments> {
        q.bind(*self)
    }
}

pub(crate) fn bill_scope() -> String {
    rule_scope_of(BILL_DIR)
}

/// The server's ring of `scope`, verified.
pub(crate) fn ring(hub: &TestHub, p: &Project, scope: &str) -> (KeyRing, RingState) {
    let r = hub.api().get(Some(&p.admin.token()), &format!("/v1/projects/{}/rings/{scope}", p.name));
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let ring: KeyRing = serde_json::from_slice(&r.body).unwrap();
    let st = ring.verify().unwrap();
    (ring, st)
}

pub(crate) fn named(st: &RingState, name: &str) -> usize {
    st.members.values().filter(|m| m.name == name).count()
}

pub(crate) fn member_of(st: &RingState, who: &Identity) -> bool {
    st.members.contains_key(&who.public_hex())
}

/// The invite link in `vl invite`'s output.
pub(crate) fn link_in(out: &str) -> String {
    out.lines().map(str::trim).find(|l| l.starts_with("veil://") && l.contains("#invite=")).unwrap_or_else(|| panic!("no link in:\n{out}")).to_string()
}

/// A person's clone of the project, trusting its keys (they confirmed the
/// project's fingerprint with the admin, or joined with an invite).
pub(crate) fn clone(hub: &TestHub, p: &Project, who: &Person, name: &str) -> std::path::PathBuf {
    let d = who.dir(name);
    who.clone_trusting(&hub.url(&p.name), &d, &p.fp);
    d
}

/// The raw sealed object at `path` on the admin's `main`.
pub(crate) fn sealed_raw(p: &Project, path: &str) -> (ObjectId, Vec<u8>) {
    let repo = veil_core::Repo::open(Arc::new(veil_core::DiskBackend::new(&p.dir)), None, "test").unwrap();
    let tip = repo.view().tags["main"].target;
    let tree = repo.store().snapshot(&tip).unwrap().tree;
    let e = veil_core::tree::lookup(repo.store(), &tree, &VPath::new(path).unwrap()).unwrap().unwrap();
    (e.id, repo.store().get_raw(&e.id).unwrap())
}

/// Can `who`, in their clone `dir`, open this sealed object if a
/// (compromised) server hands it to them?
pub(crate) fn opens(who: &Person, dir: &Path, (id, raw): &(ObjectId, Vec<u8>)) -> bool {
    let repo = veil_core::Repo::open(Arc::new(veil_core::DiskBackend::new(dir)), Some(who.identity()), "test").unwrap();
    repo.store().put_raw(id, raw).unwrap();
    repo.store().read_blob(id).is_ok()
}

/// A ring change signed by `signer` (a member's device), appended by hand:
/// what a hostile writer could send, bypassing `vl`'s own checks.
pub(crate) fn forged(ring: &KeyRing, signer: &Identity, op: RingOp) -> KeyRing {
    let mut r = ring.clone();
    let mut c = RingChange {
        seq: r.log.len() as u64,
        prev: r.log.last().map(|c| c.hash(&r.scope)).unwrap_or_default(),
        timestamp: veil_core::now_millis(),
        signer: signer.public_hex(),
        signing_key: signer.verifying_hex(),
        op,
        signature: String::new(),
    };
    c.signature = signer.sign(SIG_CONTEXT_RING_CHANGE, &c.signing_body(&r.scope));
    r.log.push(c);
    r.format = 4;
    r
}

pub(crate) fn grant_for(who: &Identity, name: &str, st: &RingState) -> MemberGrant {
    let p = pid(who);
    MemberGrant {
        id: p.member_id(),
        name: name.to_string(),
        signing_key: p.signing_hex(),
        binding: p.binding_hex(),
        role: Role::Member,
        generation: st.generation,
        // Any wrap: the replay cannot check it, and must refuse first.
        wrapped: veil_core::identity::wrap_key(&p.x25519, &[7u8; 32], "x").unwrap(),
    }
}

/// Post a ring as `who`; the status.
pub(crate) fn post_ring(hub: &TestHub, p: &Project, who: &Person, ring: &KeyRing) -> u16 {
    hub.api().post_json(Some(&who.token()), &format!("/v1/projects/{}/rings/{}", p.name, ring.scope), &serde_json::to_value(ring).unwrap()).status
}

/// Invite a new person to finance and have them join; the person.
pub(crate) fn invited(hub: &TestHub, p: &Project, prefix: &str) -> (Person, String) {
    let who = hub.newcomer(prefix);
    let out = p.admin.ok(&p.dir, &["invite", &who.name, "--to", "finance"]);
    let link = link_in(&out);
    let out = who.ok(who.home.path(), &["join", &link]);
    assert!(out.contains("Joined"), "{out}");
    (who, link)
}

/// An invite's secret, from its link.
pub(crate) fn invite_key(link: &str) -> InviteKey {
    InviteKey::from_hex(link.split("#invite=").nth(1).unwrap().split(':').nth(1).unwrap()).unwrap()
}

/// An invite made by the admin's device and recorded on the server, as
/// `vl invite` makes one, but expiring at `expires_at`.
fn raw_invite(hub: &TestHub, p: &Project, person: &str, expires_at: i64) -> InviteKey {
    let key = InviteKey::generate();
    let r = hub.api().post_json(
        Some(&p.admin.token()),
        &format!("/v1/projects/{}/invites", p.name),
        &json!({"key": key.public_hex(), "person": person, "group": "finance", "expires_at": expires_at}),
    );
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let repo = veil_core::Repo::open(Arc::new(veil_core::DiskBackend::new(&p.dir)), Some(p.admin.identity()), "test").unwrap();
    repo.keys().merge_ring(&ring(hub, p, &bill_scope()).0).unwrap();
    repo.keys().invite(&bill_scope(), person, &key.public_hex(), expires_at).unwrap();
    let ring = repo.keys().load_ring(&bill_scope()).unwrap().unwrap();
    assert_eq!(post_ring(hub, p, &p.admin, &ring), 200);
    key
}

/// Run `f` until it holds, poking with `poke`, for at most a minute.
pub(crate) fn eventually(mut poke: impl FnMut(), f: impl Fn() -> bool) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(60) {
        poke();
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    false
}

// ---- invites ----------------------------------------------------------------------------

/// The owner's flow for remote teams: `vl invite`, `vl join`, and a
/// member's device (not an admin's) wraps the key. Nothing of the invite's
/// secret ever reaches the server: not its tables, not its files.
#[test]
fn an_invite_confirms_a_device_and_a_member_shares_the_key() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let f = clone(&hub, &p, &p.fin, "f");
    let (newbie, link) = invited(&hub, &p, "newbie");
    let secret = link.rsplit(':').next().unwrap().to_string();
    // Folder access at once, the key not yet.
    let d = clone(&hub, &p, &newbie, "early");
    assert!(d.join(BILL_DIR).join("acme/invoice.txt").exists());
    assert!(!d.join(BILL_DIR).join(".env").exists());
    // fin's device (a member, not an admin) shares the key.
    let out = p.fin.ok(&f, &["share-keys"]);
    assert!(out.contains("shared with a confirmed device of"), "{out}");
    let (_, st) = ring(&hub, &p, &bill_scope());
    assert!(member_of(&st, &newbie.identity()), "the invited device has no key");
    assert!(st.invites.values().all(|i| i.used), "the invite is used up");
    let (_, team) = ring(&hub, &p, DEFAULT_SCOPE);
    assert!(!member_of(&team, &newbie.identity()), "a finance member was given the admins' key");
    let d = clone(&hub, &p, &newbie, "c");
    assert!(std::fs::read_to_string(d.join(BILL_DIR).join(".env")).unwrap().contains(ENV_MARK));
    // The secret is only in the link.
    let tables = ["invites", "devices", "device_vouches", "rings", "audit_log", "key_requests", "people", "sessions"];
    for t in tables {
        let rows: Vec<String> = hub.rt.block_on(sqlx::query_scalar(&format!("SELECT CAST(t AS TEXT) FROM {t} t")).fetch_all(&hub.hub().db)).unwrap();
        assert!(!rows.iter().any(|r| r.contains(&secret)), "the invite's secret is in the server's table {t}");
    }
    let mut stack = vec![hub._dir.path().to_path_buf()];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir).unwrap().flatten() {
            let path = e.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                let b = stored_bytes(&path);
                assert!(!String::from_utf8_lossy(&b).contains(&secret), "the invite's secret is in {}", path.display());
            }
        }
    }
}

/// The real background: after an ordinary command on a member's device, a
/// detached `vl` shares the key within seconds, with no admin online.
#[test]
fn a_members_device_shares_in_the_background() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let f = clone(&hub, &p, &p.fin, "f");
    let (newbie, _) = invited(&hub, &p, "newbie");
    let start = std::time::Instant::now();
    let got = eventually(
        || {
            p.fin.ok(&f, &["status"]);
        },
        || member_of(&ring(&hub, &p, &bill_scope()).1, &newbie.identity()),
    );
    assert!(got, "no member's device shared the key in the background");
    println!("shared after {:?}", start.elapsed());
}

/// One-time use and expiry, on the server and in the key ring itself.
#[test]
fn an_invite_is_used_once_and_expires() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let f = clone(&hub, &p, &p.fin, "f");
    let (newbie, link) = invited(&hub, &p, "newbie");
    // newbie's second device, confirmed by newbie: the link is used up.
    let laptop = hub.new_device_of(&newbie);
    newbie.ok(newbie.home.path(), &["identity", "confirm", &laptop.fingerprint()]);
    let out = laptop.fails(laptop.home.path(), &["join", &link]);
    assert!(out.contains("already used"), "{out}");
    p.fin.ok(&f, &["share-keys"]);
    // In the ring: whoever holds the link (and a member's signature)
    // cannot use it for a second device either.
    let mal = Identity::generate("mal");
    let key = invite_key(&link);
    let (r, st) = ring(&hub, &p, &bill_scope());
    let proof = ShareProof::Invite {
        key: key.public_hex(),
        signature: key.sign_join(&newbie.name, &pid(&mal)).unwrap(),
    };
    let bad = forged(&r, &p.fin.identity(), RingOp::Share { member: grant_for(&mal, &newbie.name, &st), proof });
    assert!(bad.verify().unwrap_err().contains("already used"));
    assert_eq!(post_ring(&hub, &p, &p.fin, &bad), 409, "the server stored a second use of an invite");
    // Expired: the server refuses the join, and the ring a share.
    let late = hub.newcomer("late");
    let key = raw_invite(&hub, &p, &late.name, veil_core::now_millis() + 1500);
    std::thread::sleep(Duration::from_millis(2500));
    let link = format!("veil://{}/{}#invite={}:{}:{}", hub.authority(), p.name, late.name, key.secret_hex(), p.fp.replace('-', ""));
    let out = late.fails(late.home.path(), &["join", &link]);
    assert!(out.contains("expired"), "{out}");
    let (r, st) = ring(&hub, &p, &bill_scope());
    let proof = ShareProof::Invite {
        key: key.public_hex(),
        signature: key.sign_join(&late.name, &pid(&late.identity())).unwrap(),
    };
    let bad = forged(&r, &p.fin.identity(), RingOp::Share { member: grant_for(&late.identity(), &late.name, &st), proof });
    assert!(bad.verify().unwrap_err().contains("expired"));
    assert_eq!(post_ring(&hub, &p, &p.fin, &bad), 409);
}

/// Hostile input at the join and invite routes: bad keys and signatures,
/// another person's invite, another device's join, a non-admin's invite.
#[test]
fn the_invite_routes_refuse_hostile_input() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let inv = |who: &Person, v: serde_json::Value| api.post_json(Some(&who.token()), &format!("/v1/projects/{}/invites", p.name), &v).status;
    let far = veil_core::now_millis() + 3_600_000;
    let k = InviteKey::generate().public_hex();
    assert_eq!(inv(&p.fin, json!({"key": k, "person": "x", "group": "finance", "expires_at": far})), 403, "a member made an invite");
    assert_eq!(inv(&p.admin, json!({"key": "zz", "person": "x", "group": "finance", "expires_at": far})), 400);
    assert_eq!(inv(&p.admin, json!({"key": k, "person": "Bad Name", "group": "finance", "expires_at": far})), 400);
    assert_eq!(inv(&p.admin, json!({"key": k, "person": "x", "group": "finance", "expires_at": far * 10})), 400);
    assert_eq!(inv(&p.admin, json!({"key": k, "person": "x", "group": "no-such", "expires_at": far})), 404);
    let key = raw_invite(&hub, &p, &p.dev.name, far);
    let join = |who: &Person, device: &str, sig: &str| {
        api.post_json(
            Some(&who.token()),
            &format!("/v1/projects/{}/invites/join", p.name),
            &json!({"key": key.public_hex(), "device": device, "signature": sig}),
        )
        .status
    };
    let dev = p.dev.identity();
    let good = key.sign_join(&p.dev.name, &pid(&dev)).unwrap();
    // Another person's invite; a join for a device that is not the caller's;
    // a signature by the wrong key or over another name.
    assert_eq!(join(&p.sec, &p.sec.identity().public_id(), &key.sign_join(&p.sec.name, &pid(&p.sec.identity())).unwrap()), 403);
    let other = Identity::generate("dev");
    assert_eq!(join(&p.dev, &other.public_id(), &key.sign_join(&p.dev.name, &pid(&other)).unwrap()), 400);
    assert_eq!(join(&p.dev, &dev.public_id(), &dev.sign(SIG_CONTEXT_HUB_INVITE, &join_message(&p.dev.name, &pid(&dev)).unwrap())), 400);
    assert_eq!(join(&p.dev, &dev.public_id(), &key.sign_join("someone", &pid(&dev)).unwrap()), 400);
    assert_eq!(join(&p.dev, &dev.public_id(), "00"), 400);
    assert_eq!(join(&p.dev, &dev.public_id(), &good), 200);
    assert_eq!(join(&p.dev, &dev.public_id(), &good), 409, "a join was accepted twice");
    // Links that are not invites.
    for bad in ["veil://h/p", "veil://h/p#invite=", "veil://h/p#invite=x:zz", "veil://h#invite=x:00", "#invite=x:00"] {
        let out = p.dev.fails(p.dev.home.path(), &["join", bad]);
        assert!(out.contains("expected the link"), "{bad}: {out}");
    }
}

// ---- a compromised server ---------------------------------------------------------------

/// A compromised server makes up joins: for its own device under an
/// invite (signed by a key that is not the invite's), under an invite key
/// of its own choosing, and with a genuine join moved onto its device.
/// Members' devices share with none of them.
#[test]
fn a_server_cannot_forge_choose_or_move_a_join() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let f = clone(&hub, &p, &p.fin, "f");
    let (newbie, link) = invited(&hub, &p, "newbie");
    let mal = Identity::generate(&newbie.name);
    let fp = device_fingerprint(&pid(&mal)).unwrap();
    // Its device, listed under newbie.
    sql(
        &hub,
        "INSERT INTO devices (person_id, signing_key, public_identity, created_at, fingerprint) SELECT id, $1, $2, 0, $3 FROM people WHERE name = $4",
        &[&mal.verifying_hex(), &mal.public_id(), &fp, &newbie.name],
    );
    let key = invite_key(&link);
    // 1. A join under the real invite, signed by its own key.
    let own = mal.sign(SIG_CONTEXT_HUB_INVITE, &join_message(&newbie.name, &pid(&mal)).unwrap());
    // 2. An invite key of its own choosing, with a valid join under it.
    let chosen = InviteKey::generate();
    let chosen_join = chosen.sign_join(&newbie.name, &pid(&mal)).unwrap();
    // 3. newbie's genuine join signature, moved onto its device.
    let genuine = key.sign_join(&newbie.name, &pid(&newbie.identity())).unwrap();
    // Each in a project of its own making (its own rows: the list it
    // serves is whatever it wants).
    for (i, (k, sig)) in [(key.public_hex(), own), (chosen.public_hex(), chosen_join), (key.public_hex(), genuine)].into_iter().enumerate() {
        let fake = format!("{}-fake{i}", p.name);
        sql(
            &hub,
            "INSERT INTO projects (name, created_by, created_at, default_branch, policy_text, policy_bindings, policy_version) \
             SELECT $1, created_by, 0, 'main', '', '{}', 0 FROM projects WHERE name = $2",
            &[&fake, &p.name],
        );
        sql(
            &hub,
            "INSERT INTO invites (project_id, invite_key, person, group_id, expires_at, created_by, created_at, used_at, device_id, signature) \
             SELECT f.id, $1, $2, g.id, 9999999999999, f.created_by, 0, 1, d.id, $3 \
             FROM projects f, projects pr JOIN groups g ON g.project_id = pr.id AND g.name = 'finance', devices d \
             WHERE f.name = $4 AND pr.name = $5 AND d.signing_key = $6",
            &[&k, &newbie.name, &sig, &fake, &p.name, &mal.verifying_hex()],
        );
    }
    sql(
        &hub,
        "INSERT INTO key_requests (project_id, person_id, created_at) SELECT pr.id, pe.id, $1 FROM projects pr, people pe \
         WHERE pr.name = $2 AND pe.name = $3 ON CONFLICT (project_id, person_id) DO UPDATE SET created_at = EXCLUDED.created_at",
        &[&veil_core::now_millis(), &p.name, &newbie.name],
    );
    for (who, dir) in [(&p.fin, &f), (&p.admin, &p.dir)] {
        who.ok(dir, &["share-keys"]);
    }
    let (_, st) = ring(&hub, &p, &bill_scope());
    assert!(!member_of(&st, &mal), "the server's device was given the key");
    assert!(member_of(&st, &newbie.identity()), "the genuine device was not");
    // And an admin's `vl group add` does not take its device either.
    let out = p.admin.ok(&p.dir, &["group", "add", "finance", &newbie.name]);
    assert!(out.contains(&fp), "its device is shown to be confirmed: {out}");
    assert!(!member_of(&ring(&hub, &p, &bill_scope()).1, &mal));
}

/// A compromised server hides a device at a removal, re-lists a removed
/// device with its genuine old vouch, and replays the removed person's
/// membership with a new device vouched by a revoked one. Nothing gets a
/// key.
#[test]
fn a_server_cannot_keep_hide_or_bring_back_a_device() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let f = clone(&hub, &p, &p.fin, "f");
    let (newbie, _) = invited(&hub, &p, "newbie");
    p.fin.ok(&f, &["share-keys"]);
    // newbie's laptop, confirmed by newbie from a clone: shared at once.
    let nd = clone(&hub, &p, &newbie, "c");
    let laptop = hub.new_device_of(&newbie);
    let out = newbie.ok(&nd, &["identity", "confirm", &laptop.fingerprint()]);
    assert!(out.contains("shared with a confirmed device"), "{out}");
    assert!(member_of(&ring(&hub, &p, &bill_scope()).1, &laptop.identity()));
    // The server hides the laptop when the admin removes newbie.
    sql(&hub, "UPDATE devices SET removed_at = 1 WHERE signing_key = $1", &[&laptop.identity().verifying_hex()]);
    let out = p.admin.ok(&p.dir, &["group", "remove", "finance", &newbie.name]);
    assert!(out.contains("rotated away"), "{out}");
    let (_, st) = ring(&hub, &p, &bill_scope());
    assert_eq!(named(&st, &newbie.name), 0, "a device of the removed person kept the key");
    assert!(st.invites.values().all(|i| i.used), "an invite of the removed person is still usable");
    // It brings the laptop back, puts newbie back in finance, and adds a
    // third device vouched for by newbie's (revoked) first one.
    sql(&hub, "UPDATE devices SET removed_at = NULL WHERE signing_key = $1", &[&laptop.identity().verifying_hex()]);
    sql(
        &hub,
        "INSERT INTO group_members (group_id, person_id) SELECT g.id, pe.id FROM groups g JOIN projects pr ON pr.id = g.project_id, people pe \
         WHERE pr.name = $1 AND g.name = 'finance' AND pe.name = $2 ON CONFLICT DO NOTHING",
        &[&p.name, &newbie.name],
    );
    let third = hub.new_device_of(&newbie);
    newbie.ok(newbie.home.path(), &["identity", "confirm", &third.fingerprint()]);
    for (who, dir) in [(&p.fin, &f), (&p.admin, &p.dir)] {
        who.ok(dir, &["share-keys"]);
    }
    let (_, st) = ring(&hub, &p, &bill_scope());
    assert_eq!(named(&st, &newbie.name), 0, "the server got a removed person a key back");
}

/// A pending device cannot be hidden by others' pending devices under the
/// same name, before or after it signs in (HUB.md §13.8's limit), and their
/// number is bounded: a flood pushes out the oldest, but never a device the
/// person looked for (`vl identity confirm` keeps its fingerprint for an
/// hour), even while strangers flood in parallel.
#[test]
fn pending_devices_made_by_others_never_hide_the_real_one() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let flood = |n: usize| {
        for _ in 0..n {
            let id = Identity::generate(&p.fin.name);
            let r = api.login(&id, Some(&p.fin.name));
            assert!(r.is_err(), "a stranger signed in under fin's name");
        }
    };
    let pending_rows = || -> i64 {
        let db = hub.hub().db.clone();
        hub.rt
            .block_on(
                sqlx::query_scalar("SELECT COUNT(*) FROM devices d JOIN people p ON p.id = d.person_id WHERE p.name = $1 AND d.pending")
                    .bind(&p.fin.name)
                    .fetch_one(&db),
            )
            .unwrap()
    };
    flood(30);
    let laptop = hub.new_device_of(&p.fin);
    // Pushed out by a flood bigger than the bound...
    flood(40);
    assert!(pending_rows() <= veil_server::auth::PENDING_PER_PERSON, "{} pending devices", pending_rows());
    let devices = api.get(Some(&p.fin.token()), &format!("/v1/people/{}/devices", p.fin.name)).json();
    assert!(devices["pending"].as_array().unwrap().len() <= 8, "{devices}");
    let out = p.fin.fails(p.fin.home.path(), &["identity", "confirm", &laptop.fingerprint()]);
    assert!(out.contains("sign in there again"), "{out}");
    // ...but once fin looked for it, strangers flooding in parallel never
    // push it out again.
    std::thread::scope(|s| {
        let floods: Vec<_> = (0..4).map(|_| s.spawn(|| flood(25))).collect();
        let out = laptop.fails(laptop.home.path(), &["login", &format!("veil://{}", hub.authority()), "--name", &p.fin.name, "--ca", hub.ca.to_str().unwrap()]);
        assert!(out.contains("vl identity confirm"), "{out}");
        for f in floods {
            f.join().unwrap();
        }
    });
    flood(40);
    assert!(pending_rows() <= veil_server::auth::PENDING_PER_PERSON + 1, "{} pending devices", pending_rows());
    p.fin.ok(p.fin.home.path(), &["identity", "confirm", &laptop.fingerprint()]);
    laptop.ok(laptop.home.path(), &["login", &format!("veil://{}", hub.authority()), "--ca", hub.ca.to_str().unwrap()]);
    // Someone else cannot look fin's pending devices up, nor keep one.
    let other = hub.new_device_of(&p.fin);
    let r = api.get(Some(&p.dev.token()), &format!("/v1/people/{}/pending/{}", p.fin.name, other.fingerprint()));
    assert_eq!(r.status, 404);
    flood(40);
    let r = api.get(Some(&p.fin.token()), &format!("/v1/people/{}/pending/{}", p.fin.name, other.fingerprint()));
    assert_eq!(r.status, 404, "a stranger's lookup kept the device");
}

// ---- keys per access rule ---------------------------------------------------------------

/// Each access line's secrets have their own key: someone with `billing/`
/// cannot open `src/<nested>/.env` even if a compromised server hands them
/// its ciphertext, and removing them rotates only the keys they lose.
#[test]
fn removal_rotates_only_the_affected_keys() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let nested_env = format!("src/{NESTED_DIR}/.env");
    let mark = "MARKER-NESTED-SECRET-ENV-7c1d29aa";
    write_files(&p.dir, &[(&nested_env, &format!("K={mark}\n"))]);
    p.admin.commit_main(&p.dir, "a security secret");
    p.admin.ok(&p.dir, &["push"]);
    let nested = rule_scope_of(&format!("src/{NESTED_DIR}"));
    let f = clone(&hub, &p, &p.fin, "f");
    let s = clone(&hub, &p, &p.sec, "s");
    let bill = sealed_raw(&p, &format!("{BILL_DIR}/.env"));
    let sec_env = sealed_raw(&p, &nested_env);
    assert!(opens(&p.fin, &f, &bill) && !opens(&p.fin, &f, &sec_env), "fin opens billing's secret only");
    assert!(opens(&p.sec, &s, &sec_env) && !opens(&p.sec, &s, &bill), "sec opens the nested secret only");
    let generation = |scope: &str| ring(&hub, &p, scope).1.generation;
    let before = (generation(&bill_scope()), generation(&nested), generation(DEFAULT_SCOPE));
    let out = p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    assert!(out.contains("rotated away from"), "{out}");
    let after = (generation(&bill_scope()), generation(&nested), generation(DEFAULT_SCOPE));
    assert_eq!(after, (before.0 + 1, before.1, before.2), "rotated another rule's key, or not this one");
    // A new billing secret: fin's device cannot open it.
    let fresh = "MARKER-BILLING-NEW-SECRET-3a9e5c01";
    p.admin.ok(&p.dir, &["new", "main"]);
    write_files(&p.dir, &[(&format!("{BILL_DIR}/.env") as &str, &format!("K={fresh}\n"))]);
    p.admin.commit_main(&p.dir, "a new billing secret");
    p.admin.ok(&p.dir, &["push"]);
    let new_bill = sealed_raw(&p, &format!("{BILL_DIR}/.env"));
    p.fin.ok(&f, &["pull"]);
    assert!(!opens(&p.fin, &f, &new_bill), "a removed person opens a secret sealed after their removal");
    assert!(opens(&p.fin, &f, &bill), "they keep what they had (as designed)");
}

/// `vl identity remove`: a lost laptop stops signing in and loses the
/// keys of every rule it held (its person removes it, from another device),
/// and an admin can remove anyone's device in their project.
#[test]
fn a_removed_device_stops_receiving_secrets() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let f = clone(&hub, &p, &p.fin, "f");
    let laptop = hub.new_device_of(&p.fin);
    let out = p.fin.ok(&f, &["identity", "confirm", &laptop.fingerprint()]);
    assert!(out.contains("shared with a confirmed device"), "{out}");
    laptop.ok(laptop.home.path(), &["login", &format!("veil://{}", hub.authority()), "--ca", hub.ca.to_str().unwrap()]);
    let l = clone(&hub, &p, &laptop, "l");
    assert!(std::fs::read_to_string(l.join(BILL_DIR).join(".env")).unwrap().contains(ENV_MARK));
    let g = ring(&hub, &p, &bill_scope()).1.generation;
    let out = p.fin.ok(&f, &["identity", "remove", &laptop.fingerprint()]);
    assert!(out.contains("rotated away"), "{out}");
    let st = ring(&hub, &p, &bill_scope()).1;
    assert!(!member_of(&st, &laptop.identity()) && st.generation == g + 1, "the lost laptop kept the key");
    assert!(member_of(&st, &p.fin.identity()), "fin lost their own key");
    laptop.fails(laptop.home.path(), &["login", &format!("veil://{}", hub.authority()), "--ca", hub.ca.to_str().unwrap()]);
    // A compromised server lists the laptop again, with fin's genuine vouch
    // (fin's device is still a member): no pass shares to it again.
    sql(&hub, "UPDATE devices SET removed_at = NULL WHERE signing_key = $1", &[&laptop.identity().verifying_hex()]);
    sql(
        &hub,
        "INSERT INTO key_requests (project_id, person_id, created_at) SELECT pr.id, pe.id, $1 FROM projects pr, people pe \
         WHERE pr.name = $2 AND pe.name = $3 ON CONFLICT (project_id, person_id) DO UPDATE SET created_at = EXCLUDED.created_at",
        &[&veil_core::now_millis(), &p.name, &p.fin.name],
    );
    for (who, dir) in [(&p.fin, &f), (&p.admin, &p.dir)] {
        who.ok(dir, &["share-keys"]);
    }
    assert!(!member_of(&ring(&hub, &p, &bill_scope()).1, &laptop.identity()), "a removed device was shared to again");
    // Signed by fin's device itself, with fin's genuine vouch: every
    // replay (the server's too) refuses it.
    let (r, st) = ring(&hub, &p, &bill_scope());
    let proof = ShareProof::Vouch {
        by: p.fin.identity().verifying_hex(),
        signature: p.fin.identity().sign(SIG_CONTEXT_HUB_DEVICE, &vouch_message(&pid(&laptop.identity())).unwrap()),
    };
    let bad = forged(&r, &p.fin.identity(), RingOp::Share { member: grant_for(&laptop.identity(), &p.fin.name, &st), proof });
    assert!(bad.verify().unwrap_err().contains("never shared to again"));
    assert_eq!(post_ring(&hub, &p, &p.fin, &bad), 409);
    // Nor does an admin's `vl group add` give it back on the old vouch.
    let out = p.admin.ok(&p.dir, &["group", "add", "finance", &p.fin.name]);
    assert!(out.contains("held the secret key") && out.contains(&laptop.fingerprint()), "{out}");
    assert!(!member_of(&ring(&hub, &p, &bill_scope()).1, &laptop.identity()), "an admin's device gave a removed device its key back");
    sql(&hub, "UPDATE devices SET removed_at = 1 WHERE signing_key = $1", &[&laptop.identity().verifying_hex()]);
    // Not from the device itself.
    let out = p.fin.fails(&f, &["identity", "remove", &p.fin.fingerprint()]);
    assert!(out.contains("this device"), "{out}");
    // An admin removes another person's device, found in the rings.
    let laptop2 = hub.new_device_of(&p.fin);
    p.fin.ok(&f, &["identity", "confirm", &laptop2.fingerprint()]);
    let out = p.admin.ok(&p.dir, &["identity", "remove", &laptop2.fingerprint()]);
    assert!(out.contains("Removed") && out.contains("rotated away"), "{out}");
    assert!(!member_of(&ring(&hub, &p, &bill_scope()).1, &laptop2.identity()));
    // A member cannot remove someone else's device, from the server or a ring.
    let out = p.dev.fails(p.dev.home.path(), &["identity", "remove", &p.fin.fingerprint()]);
    assert!(out.contains("no device"), "{out}");
    let (r, st) = ring(&hub, &p, &bill_scope());
    let fin_member = p.fin.identity().public_hex();
    let rotation = veil_core::keychain::Rotation {
        generation: st.generation + 1,
        key_id: "0".repeat(16),
        previous: vec![],
        wrapped: Default::default(),
    };
    // An admin's own-device removal of fin's device: refused by name.
    let bad = forged(&r, &p.admin.identity(), RingOp::RevokeOwn { member: fin_member, rotation });
    assert!(bad.verify().unwrap_err().contains("only their own devices"));
}

// ---- migration --------------------------------------------------------------------------

/// A project from milestone S1 (`.env  cloak team`, one key for everyone
/// added to a group) moves to keys per rule only through `vl upgrade
/// --rule-keys`, which lists every secret and who will hold its key first,
/// and makes `team` the admins' only.
#[test]
fn the_s1_key_moves_to_keys_per_rule_explicitly() {
    let hub = TestHub::start();
    let admin = hub.person("admin");
    let fin = hub.person("fin");
    let dev = hub.person("dev");
    let name = unique("old");
    let dir = admin.dir("proj");
    std::fs::create_dir_all(&dir).unwrap();
    admin.ok(&dir, &["init"]);
    // What milestone S1's `vl init` wrote.
    let policy = std::fs::read_to_string(dir.join(".veilpolicy")).unwrap().replace("cloak rule", "cloak team");
    std::fs::write(dir.join(".veilpolicy"), policy).unwrap();
    write_files(&dir, &[(&format!("{BILL_DIR}/.env") as &str, &format!("K={ENV_MARK}\n")), ("src/lib.rs", "fn main() {}")]);
    admin.ok(&dir, &["remote", "add", "origin", &hub.url(&name)]);
    admin.commit_main(&dir, "s1");
    admin.ok(&dir, &["push"]);
    for g in ["finance", "devs"] {
        admin.ok(&dir, &["group", "create", g]);
    }
    admin.ok(&dir, &["group", "add", "finance", &fin.name, "--confirm", &fin.fingerprint()]);
    admin.ok(&dir, &["group", "add", "devs", &dev.name, "--confirm", &dev.fingerprint()]);
    admin.ok(&dir, &["access", &format!("{BILL_DIR}/"), "finance"]);
    admin.ok(&dir, &["access", "src/", "devs"]);
    admin.commit_main(&dir, "access");
    admin.ok(&dir, &["push"]);
    let repo = || veil_core::Repo::open(Arc::new(veil_core::DiskBackend::new(&dir)), None, "test").unwrap();
    let team = || repo().keys().ring_state(DEFAULT_SCOPE).unwrap().unwrap().unwrap();
    assert!(member_of(&team(), &dev.identity()), "S1 gave everyone the one key");
    let before = std::fs::read_to_string(dir.join(".veilpolicy")).unwrap();
    let out = admin.ok(&dir, &["upgrade", "--rule-keys", "--dry-run"]);
    assert!(out.contains(&format!("{BILL_DIR}/.env")) && out.contains(&format!("key of {BILL_DIR}/")) && out.contains(&fin.name), "{out}");
    assert!(out.contains("rotated away from") && out.contains(&dev.name), "{out}");
    assert_eq!(std::fs::read_to_string(dir.join(".veilpolicy")).unwrap(), before, "a dry run changed the policy");
    assert!(member_of(&team(), &dev.identity()), "a dry run changed a key");
    let out = admin.ok(&dir, &["upgrade", "--rule-keys"]);
    assert!(out.contains("Commit and push"), "{out}");
    admin.commit_main(&dir, "keys per rule");
    admin.ok(&dir, &["push"]);
    let st = team();
    assert!(!member_of(&st, &dev.identity()) && !member_of(&st, &fin.identity()), "team is still everyone's");
    let raw = {
        let r = repo();
        let tip = r.view().tags["main"].target;
        let e = veil_core::tree::lookup(r.store(), &r.store().snapshot(&tip).unwrap().tree, &VPath::new(&format!("{BILL_DIR}/.env")).unwrap()).unwrap().unwrap();
        assert!(matches!(&e.visibility, veil_core::Visibility::Cloaked { scope } if *scope == bill_scope()), "{:?}", e.visibility);
        (e.id, r.store().get_raw(&e.id).unwrap())
    };
    let f = fin.dir("f");
    fin.clone_trusting(&hub.url(&name), &f, &admin.project_fingerprint(&dir));
    assert!(std::fs::read_to_string(f.join(BILL_DIR).join(".env")).unwrap().contains(ENV_MARK));
    let d = dev.dir("d");
    dev.ok(dev.home.path(), &["clone", &hub.url(&name), d.to_str().unwrap()]);
    assert!(!opens(&dev, &d, &raw), "a dev opens billing's secret after the move");
    let out = admin.ok(&dir, &["upgrade", "--rule-keys"]);
    assert!(out.contains("already"), "{out}");
}

// ---- vouches in the ring ----------------------------------------------------------------

/// The ring's replay, through the server: a member's share needs a vouch
/// by a current device of the same person.
#[test]
fn a_share_needs_a_vouch_by_the_same_person() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let (r, st) = ring(&hub, &p, &bill_scope());
    let mal = Identity::generate("x");
    // dev vouches for a device as fin's; fin vouches for a device as dev's.
    let sig = |by: &Identity| by.sign(SIG_CONTEXT_HUB_DEVICE, &vouch_message(&pid(&mal)).unwrap());
    for (as_name, by) in [(&p.fin.name, p.dev.identity()), (&p.dev.name, p.fin.identity())] {
        let proof = ShareProof::Vouch {
            by: by.verifying_hex(),
            signature: sig(&by),
        };
        let bad = forged(&r, &p.fin.identity(), RingOp::Share { member: grant_for(&mal, as_name, &st), proof });
        assert!(bad.verify().is_err());
        assert_eq!(post_ring(&hub, &p, &p.fin, &bad), 409);
    }
    // A share signed by someone who is not a member at all.
    let proof = ShareProof::Vouch {
        by: p.fin.identity().verifying_hex(),
        signature: sig(&p.fin.identity()),
    };
    let bad = forged(&r, &p.dev.identity(), RingOp::Share { member: grant_for(&mal, &p.fin.name, &st), proof });
    assert!(bad.verify().unwrap_err().contains("not a member"));
    assert_eq!(post_ring(&hub, &p, &p.dev, &bad), 409);
}
