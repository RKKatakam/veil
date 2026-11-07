//! Person-to-person secret shares (`docs/HUB.md` §13.13): `vl secret share
//! PATH --with PERSON`, `unshare`, `shares`, and their background delivery.
//! Most tests play a **compromised server**: it writes its own rows (devices,
//! vouches, share records) and must never read a share nor get one sealed
//! for a device of its choosing.

use std::path::{Path, PathBuf};

use serde_json::json;
use veil_core::{
    crypto::domains::SIG_CONTEXT_HUB_DEVICE,
    hub::wire::{device_fingerprint, vouch_message},
    secret_share::{ShareInfo, SharePut, ShareRecord, ShareTarget, MAX_SHARES_PER_SHARER},
    Identity,
};

use crate::{secrets2::*, support::*};

fn env_path() -> String {
    format!("{BILL_DIR}/.env")
}

/// The shares `who` gets from the server (raw API).
fn shares_of(hub: &TestHub, p: &Project, who: &Person) -> (u16, Vec<ShareInfo>) {
    let r = hub.api().get(Some(&who.token()), &format!("/v1/projects/{}/shares", p.name));
    let list = if r.status == 200 { serde_json::from_slice(&r.body).unwrap() } else { vec![] };
    (r.status, list)
}

type Stored = (i64, Option<i64>, Option<String>);

/// The stored share of `path` from `sharer` to `recipient`: (version,
/// unshared, body).
fn row_of(hub: &TestHub, p: &Project, path: &str, sharer: &str, recipient: &str) -> Option<Stored> {
    hub.rt
        .block_on(
            sqlx::query_as(
                "SELECT s.version, s.unshared_at, s.body FROM secret_shares s JOIN projects pr ON pr.id = s.project_id \
                 JOIN people a ON a.id = s.sharer_id JOIN people b ON b.id = s.recipient_id \
                 WHERE pr.name = $1 AND s.path = $2 AND a.name = $3 AND b.name = $4",
            )
            .bind(&p.name)
            .bind(path)
            .bind(sharer)
            .bind(recipient)
            .fetch_optional(&hub.hub().db),
        )
        .unwrap()
}

/// fin's share of `path` with `recipient`.
fn row(hub: &TestHub, p: &Project, path: &str, recipient: &str) -> Option<Stored> {
    row_of(hub, p, path, &p.fin.name, recipient)
}

fn record(hub: &TestHub, p: &Project, path: &str, recipient: &str) -> ShareRecord {
    serde_json::from_str(&row(hub, p, path, recipient).unwrap().2.expect("an active share has a record")).unwrap()
}

/// Replace the stored record (what a compromised server can do).
fn store(hub: &TestHub, p: &Project, path: &str, r: &ShareRecord) {
    sql(
        hub,
        "UPDATE secret_shares SET body = $1, version = $2 WHERE path = $3 AND project_id = (SELECT id FROM projects WHERE name = $4)",
        &[&serde_json::to_string(r).unwrap(), &(r.version as i64), &path, &p.name],
    );
}

/// Run fin's pass until fin's share of `path` with `to` satisfies `f`: a
/// background pass a command of fin's started may race the explicit one
/// (one of them then loses the compare-and-swap, and the next pass decides
/// again).
fn seal_until(hub: &TestHub, p: &Project, f: &Path, path: &str, to: &str, ok: impl Fn(&ShareRecord) -> bool) -> ShareRecord {
    for _ in 0..5 {
        p.fin.ok(f, &["share-keys"]);
        let r = record(hub, p, path, to);
        if ok(&r) {
            return r;
        }
    }
    panic!("fin's share of {path} with {to} never got there: {:?}", record(hub, p, path, to).devices());
}

fn read(dir: &Path, path: &str) -> Option<String> {
    std::fs::read_to_string(dir.join(path)).ok()
}

fn project_id(dir: &Path) -> String {
    let repo = veil_core::Repo::open(std::sync::Arc::new(veil_core::DiskBackend::new(dir)), None, "test").unwrap();
    repo.keys().project_id().unwrap()
}

/// A device the server makes up under `person`'s name, with a vouch
/// signed by its own key.
fn server_device(hub: &TestHub, person: &str) -> Identity {
    let eve = Identity::generate(person);
    let fp = device_fingerprint(&pid(&eve)).unwrap();
    sql(
        hub,
        "INSERT INTO devices (person_id, signing_key, public_identity, created_at, fingerprint) SELECT id, $1, $2, 0, $3 FROM people WHERE name = $4",
        &[&eve.verifying_hex(), &eve.public_id(), &fp, &person],
    );
    sql(
        hub,
        "INSERT INTO device_vouches (device_id, voucher_key, signature, created_at) SELECT id, $1, $2, 0 FROM devices WHERE signing_key = $1",
        &[&eve.verifying_hex(), &eve.sign(SIG_CONTEXT_HUB_DEVICE, &vouch_message(&pid(&eve)).unwrap())],
    );
    eve
}

/// fin's clone and dev's, with fin's `.env` shared with dev and received.
fn shared(hub: &TestHub, p: &Project) -> (PathBuf, PathBuf) {
    let f = clone(hub, p, &p.fin, "f");
    let out = p.fin.ok(&f, &["secret", "share", &env_path(), "--with", &p.dev.name]);
    assert!(out.contains("Shared") && out.contains("1 device"), "{out}");
    // Delivered by dev's `vl pull` (or by the background pass a command in
    // dev's clone starts, whichever comes first).
    let d = clone(hub, p, &p.dev, "d");
    p.dev.ok(&d, &["pull"]);
    assert!(read(&d, &env_path()).unwrap().contains(ENV_MARK));
    (f, d)
}

// ---- what a share is ---------------------------------------------------------------------

/// A member shares their `.env` with someone outside its folder: only that
/// person's devices receive it, it stays on their device (never recorded),
/// it reaches their agent, it opens nothing else of the folder, admins see
/// that it exists and never its content, and the server holds ciphertext.
#[test]
fn a_share_reaches_its_recipient_only() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let (f, d) = shared(&hub, &p);
    let env = env_path();
    // Nothing else of the folder arrived with it.
    assert!(!d.join(BILL_DIR).join("acme").exists());
    // It stays on dev's device: a commit records nothing of it, and a push
    // sends nothing of it (dev may not write the folder anyway).
    p.dev.ok(&d, &["commit", "-m", "after receiving"]);
    let repo = veil_core::Repo::open(std::sync::Arc::new(veil_core::DiskBackend::new(&d)), Some(p.dev.identity()), "test").unwrap();
    let head = repo.view().workspaces["default"].wc;
    let tree = repo.store().snapshot(&head).unwrap().tree;
    assert!(veil_core::tree::lookup(repo.store(), &tree, &veil_core::VPath::new(&env).unwrap()).unwrap().is_none());
    // dev's agent gets it, like any of dev's local-only secrets.
    p.dev.ok(&d, &["ws", "new", "agent"]);
    let out = p.dev.ok(&d, &["ws", "exec", "agent", "--with-isolated", "--", "cat", &env]);
    assert!(out.contains(ENV_MARK), "{out}");
    // Another secret of the folder stays closed to dev.
    write_files(&p.dir, &[(&format!("{BILL_DIR}/.env.prod"), "PROD=MARKER-PROD-SECRET-77e1aa02\n")]);
    p.admin.commit_main(&p.dir, "a second billing secret");
    p.admin.ok(&p.dir, &["push"]);
    assert!(!opens(&p.dev, &d, &sealed_raw(&p, &format!("{BILL_DIR}/.env.prod"))));
    // A one-directory clone of dev's writes nothing outside its directory.
    let o = p.dev.dir("only");
    p.dev.ok(p.dev.home.path(), &["clone", &hub.url(&p.name), o.to_str().unwrap(), "--only", "src"]);
    p.dev.ok(&o, &["identity", "confirm", &p.fp]);
    let out = p.dev.ok(&o, &["pull"]);
    assert!(out.contains("outside this clone's directory") && read(&o, &env).is_none(), "{out}");
    // A device that holds the folder's key (an admin's) would record a copy
    // of a file the folder does not have for everyone in it: not written.
    let own = format!("{BILL_DIR}/.env.fin-own");
    write_files(&f, &[(&own, "FIN=MARKER-FIN-OWN-SECRET-3c0d11e9\n")]);
    p.fin.ok(&f, &["secret", "share", &own, "--with", &p.admin.name]);
    let out = p.admin.ok(&p.dir, &["pull"]);
    assert!(out.contains("holds the key of its folder's secrets"), "{out}");
    assert!(read(&p.dir, &own).is_none());
    // Nobody else receives it.
    let c = clone(&hub, &p, &p.carol, "c");
    p.carol.ok(&c, &["pull"]);
    assert!(read(&c, &env).is_none());
    assert!(shares_of(&hub, &p, &p.carol).1.is_empty());
    // Admins see who shares what with whom, never its content or record.
    let out = p.admin.ok(&p.dir, &["secret", "shares"]);
    assert!(out.contains(&env) && out.contains(&p.fin.name) && out.contains(&p.dev.name) && out.contains("active"), "{out}");
    assert!(!out.contains(ENV_MARK));
    let (_, list) = shares_of(&hub, &p, &p.admin);
    let to_dev: Vec<&ShareInfo> = list.iter().filter(|s| s.recipient == p.dev.name).collect();
    assert!(list.len() == 2 && to_dev.len() == 1 && to_dev[0].record.is_none(), "{list:?}");
    let out = p.admin.ok(&p.dir, &["--no-snapshot", "secret", "shares", "--json"]);
    assert!(!out.contains(ENV_MARK), "{out}");
    // The documented shapes (docs/reference/json.md).
    let doc: serde_json::Value = serde_json::from_str(out.lines().find(|l| l.starts_with('{')).unwrap()).unwrap();
    assert_eq!(doc["schema"], "veil.secret.shares/1");
    let keys: Vec<&str> = doc["shares"][0].as_object().unwrap().keys().map(String::as_str).collect();
    let mut want = vec!["active", "created_at", "path", "paused", "recipient", "sharer", "unshared_at", "updated_at", "version"];
    want.sort();
    assert_eq!(keys, want);
    let out = p.fin.ok(&f, &["secret", "share", &env, "--with", &p.dev.name, "--json"]);
    let doc: serde_json::Value = serde_json::from_str(out.lines().find(|l| l.starts_with('{')).unwrap()).unwrap();
    assert!(doc["schema"] == "veil.secret.share/1" && doc["action"] == "shared" && doc["devices"].as_array().unwrap().len() == 1, "{doc}");
    let keys: Vec<&str> = doc.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(keys, vec!["action", "devices", "path", "recipient", "schema", "unconfirmed", "version"]);
    // The server's row holds ciphertext only.
    let body = row(&hub, &p, &env, &p.dev.name).unwrap().2.unwrap();
    assert!(!body.contains(ENV_MARK) && !body.contains(&hex::encode(ENV_MARK)), "{body}");
    // Sealed for dev's one confirmed device and fin's sharing device only.
    let mut want = vec![p.dev.identity().public_hex(), p.fin.identity().public_hex()];
    want.sort();
    let mut got = record(&hub, &p, &env, &p.dev.name).devices();
    got.sort();
    assert_eq!(got, want);
    // dev sees the share they receive; fin the ones they made.
    assert_eq!(shares_of(&hub, &p, &p.dev).1.len(), 1);
    assert_eq!(shares_of(&hub, &p, &p.fin).1.len(), 2);
    let out = p.fin.ok(&f, &["secret", "shares"]);
    assert!(out.contains(&env), "{out}");
}

/// Updates reach the recipient in the background; their own edit is never
/// written over; unsharing stops every later version (what they received
/// stays theirs); sharing again starts it again.
#[test]
fn updates_and_unsharing() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let (f, d) = shared(&hub, &p);
    let env = env_path();
    write_files(&f, &[(&env, "KEY=second-v2\n")]);
    let dev_id = p.dev.identity();
    seal_until(&hub, &p, &f, &env, &p.dev.name, |r| r.open(&dev_id).is_ok_and(|c| c == b"KEY=second-v2\n"));
    p.dev.ok(&d, &["pull"]);
    assert_eq!(read(&d, &env).unwrap(), "KEY=second-v2\n");
    // dev's own edit stays.
    write_files(&d, &[(&env, "KEY=dev-own\n")]);
    write_files(&f, &[(&env, "KEY=third-v3\n")]);
    seal_until(&hub, &p, &f, &env, &p.dev.name, |r| r.open(&dev_id).is_ok_and(|c| c == b"KEY=third-v3\n"));
    let out = p.dev.ok(&d, &["pull"]);
    assert!(out.contains("not written over your own"), "{out}");
    assert_eq!(read(&d, &env).unwrap(), "KEY=dev-own\n");
    std::fs::remove_file(d.join(&env)).unwrap();
    p.dev.ok(&d, &["pull"]);
    assert_eq!(read(&d, &env).unwrap(), "KEY=third-v3\n");
    // Unshared: nothing later reaches dev.
    let out = p.fin.ok(&f, &["secret", "unshare", &env, "--from", &p.dev.name]);
    assert!(out.contains("keeps what they already received"), "{out}");
    write_files(&f, &[(&env, "KEY=fourth-after-unshare\n")]);
    let out = p.fin.ok(&f, &["share-keys"]);
    assert!(!out.contains("version"), "{out}");
    let (v, ended, body) = row(&hub, &p, &env, &p.dev.name).unwrap();
    assert!(ended.is_some() && body.is_none(), "{v}");
    p.dev.ok(&d, &["pull"]);
    assert_eq!(read(&d, &env).unwrap(), "KEY=third-v3\n");
    let (_, list) = shares_of(&hub, &p, &p.dev);
    assert!(list.len() == 1 && !list[0].active && list[0].record.is_none(), "{list:?}");
    let out = p.dev.ok(&d, &["secret", "shares"]);
    assert!(out.contains("ended"), "{out}");
    // Unsharing again changes nothing (a retried request is the same).
    p.fin.ok(&f, &["secret", "unshare", &env, "--from", &p.dev.name]);
    assert_eq!(row(&hub, &p, &env, &p.dev.name).unwrap().0, v);
    p.fin.fails(&f, &["secret", "unshare", &env, "--from", &p.carol.name]);
    // Shared again: a later version than any before.
    p.fin.ok(&f, &["secret", "share", &env, "--with", &p.dev.name]);
    assert!(record(&hub, &p, &env, &p.dev.name).version > v as u64);
    p.dev.ok(&d, &["pull"]);
    assert_eq!(read(&d, &env).unwrap(), "KEY=fourth-after-unshare\n");
    let out = p.fin.ok(&f, &["secret", "shares", "--json"]);
    assert!(out.contains("\"active\":true"), "{out}");
}

// ---- a compromised server ----------------------------------------------------------------

/// The server lists devices of its own under the recipient's name, with a
/// vouch it signed, or moves another person's device under that name: none
/// of them is sealed for. A `--confirm` that matches none of the listed
/// devices fails before anything is shared.
#[test]
fn a_server_cannot_redirect_a_share_to_its_device() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let f = clone(&hub, &p, &p.fin, "f");
    let eve = server_device(&hub, &p.dev.name);
    // carol's real device, listed as dev's.
    sql(
        &hub,
        "UPDATE devices SET person_id = (SELECT id FROM people WHERE name = $1) WHERE signing_key = $2",
        &[&p.dev.name, &p.carol.identity().verifying_hex()],
    );
    let out = p.fin.ok(&f, &["secret", "share", &env_path(), "--with", &p.dev.name]);
    assert!(out.contains("1 device") && out.contains(&format!("confirm {}'s device", p.dev.name)), "{out}");
    assert!(out.contains(&device_fingerprint(&pid(&eve)).unwrap()), "{out}");
    let got = record(&hub, &p, &env_path(), &p.dev.name).devices();
    assert!(!got.contains(&eve.public_hex()) && !got.contains(&p.carol.identity().public_hex()), "{got:?}");
    // The fingerprint dev reads from their screen is not the server's
    // device: a `--confirm` of another one fails and shares nothing new.
    let v = record(&hub, &p, &env_path(), &p.dev.name).version;
    let out = p.fin.fails(&f, &["secret", "share", &env_path(), "--with", &p.dev.name, "--confirm", &p.sec.fingerprint()]);
    assert!(out.contains("no device of"), "{out}");
    assert_eq!(record(&hub, &p, &env_path(), &p.dev.name).version, v);
    // The background pass never adds them either.
    p.fin.ok(&f, &["share-keys"]);
    let got = record(&hub, &p, &env_path(), &p.dev.name).devices();
    assert!(!got.contains(&eve.public_hex()) && !got.contains(&p.carol.identity().public_hex()), "{got:?}");
    // Someone the rings record no device of gets nothing without --confirm.
    let newbie = hub.person("newbie");
    p.admin.ok(&p.dir, &["group", "add", "devs", &newbie.name]);
    let out = p.fin.fails(&f, &["secret", "share", &env_path(), "--with", &newbie.name]);
    assert!(out.contains("no device of") && out.contains("--confirm"), "{out}");
    assert!(row(&hub, &p, &env_path(), &newbie.name).is_none());
    // With the fingerprint fin compared with them: it is.
    p.fin.ok(&f, &["secret", "share", &env_path(), "--with", &newbie.name, "--confirm", &newbie.fingerprint()]);
    assert!(record(&hub, &p, &env_path(), &newbie.name).devices().contains(&newbie.identity().public_hex()));
}

/// Records the server makes or changes are refused by the recipient: one
/// signed by its own device in the sharer's name, a changed one, an older
/// version, one moved to another path, another recipient or another
/// project. Nothing is written.
#[test]
fn a_server_cannot_forge_change_replay_or_move_a_share() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let (f, d) = shared(&hub, &p);
    let env = env_path();
    let v1 = record(&hub, &p, &env, &p.dev.name);
    write_files(&f, &[(&env, "KEY=genuine-v2\n")]);
    let dev_id = p.dev.identity();
    seal_until(&hub, &p, &f, &env, &p.dev.name, |r| r.open(&dev_id).is_ok_and(|c| c == b"KEY=genuine-v2\n"));
    p.dev.ok(&d, &["pull"]);
    let v2 = record(&hub, &p, &env, &p.dev.name);
    assert_eq!(read(&d, &env).unwrap(), "KEY=genuine-v2\n");
    let project = project_id(&d);
    let dev_dev = p.dev.identity().public_hex();
    let check_refused = |what: &str, r: &ShareRecord, says: &str| {
        store(&hub, &p, &env, r);
        let out = p.dev.ok(&d, &["pull"]);
        assert!(out.contains(says), "{what}: {out}");
        assert_eq!(read(&d, &env).unwrap(), "KEY=genuine-v2\n", "{what}");
    };
    // Signed by the server's own device, in fin's name.
    let eve = Identity::generate(&p.fin.name);
    let target = ShareTarget {
        project: &project,
        path: &env,
        sharer: &p.fin.name,
        recipient: &p.dev.name,
        version: 3,
    };
    let forged = ShareRecord::seal(&eve, &target, 9, b"KEY=evil\n", std::slice::from_ref(&dev_dev)).unwrap();
    check_refused("forged", &forged, "not signed by a device");
    // fin's genuine record with its sealed file swapped.
    let mut changed = v2.clone();
    changed.sealed = forged.sealed.clone();
    check_refused("changed", &changed, "not a valid share");
    // An older genuine version.
    check_refused("replayed", &v1, "older than the one received");
    // fin's device's own signature, for another project (fin shares the
    // same path there): bound to its project.
    let other = ShareRecord::seal(&p.fin.identity(), &ShareTarget { project: &"f".repeat(32), version: 3, ..target }, 9, b"KEY=other\n", std::slice::from_ref(&dev_dev)).unwrap();
    check_refused("another project", &other, "not a valid share");
    // Moved to another path (the row's, not the record's).
    store(&hub, &p, &env, &v2);
    let in_p = "AND project_id = (SELECT id FROM projects WHERE name = $3)";
    sql(&hub, &format!("UPDATE secret_shares SET path = $1 WHERE path = $2 {in_p}"), &[&format!("{BILL_DIR}/.env.moved"), &env, &p.name]);
    let out = p.dev.ok(&d, &["pull"]);
    assert!(out.contains("not a valid share"), "{out}");
    assert!(read(&d, &format!("{BILL_DIR}/.env.moved")).is_none());
    sql(&hub, &format!("UPDATE secret_shares SET path = $1 WHERE path = $2 {in_p}"), &[&env, &format!("{BILL_DIR}/.env.moved"), &p.name]);
    // Given to someone else: carol cannot open it, and refuses it.
    sql(
        &hub,
        &format!("UPDATE secret_shares SET recipient_id = (SELECT id FROM people WHERE name = $1) WHERE path = $2 {in_p}"),
        &[&p.carol.name, &env, &p.name],
    );
    let c = clone(&hub, &p, &p.carol, "c");
    let out = p.carol.ok(&c, &["pull"]);
    assert!(out.contains("not a valid share"), "{out}");
    assert!(read(&c, &env).is_none());
    assert!(v2.open(&p.carol.identity()).is_err());
    // Nor does fin's device, updating its share, seal for the person the
    // server's listing now names: the signed record says who it is for.
    write_files(&f, &[(&env, "KEY=fin-v3-after-the-move\n")]);
    p.fin.ok(&f, &["share-keys"]);
    let (v, _, body) = row(&hub, &p, &env, &p.carol.name).unwrap();
    assert_eq!(v as u64, v2.version, "fin's device sealed a version for the listing's recipient");
    assert!(!body.unwrap().contains(&p.carol.identity().public_hex()));
    // And no record opens for anyone but dev and fin's device.
    for who in [&p.admin, &p.carol, &p.sec] {
        assert!(v2.open(&who.identity()).is_err());
    }
}

/// What the routes refuse, whoever sends it.
#[test]
fn the_share_routes_refuse_what_may_not_be_shared() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let f = clone(&hub, &p, &p.fin, "f");
    let api = hub.api();
    let project = project_id(&f);
    let route = format!("/v1/projects/{}/shares", p.name);
    let env = env_path();
    let put = |who: &Person, signer: &Identity, path: &str, to: &str, expect: u64, version: u64, reshare: bool| {
        let t = ShareTarget {
            project: &project,
            path,
            sharer: &who.name,
            recipient: to,
            version,
        };
        let r = ShareRecord::seal(signer, &t, 1, b"K=1\n", &[signer.public_hex()]).unwrap();
        let body = serde_json::to_value(SharePut { expect, reshare, record: r }).unwrap();
        api.post_json(Some(&who.token()), &route, &body).status
    };
    let fin = p.fin.identity();
    // Not signed in.
    assert_eq!(api.get(None, &route).status, 401);
    let t = ShareTarget {
        project: &project,
        path: &env,
        sharer: &p.fin.name,
        recipient: &p.dev.name,
        version: 1,
    };
    let anon = SharePut { expect: 0, reshare: true, record: ShareRecord::seal(&fin, &t, 1, b"K", &[fin.public_hex()]).unwrap() };
    assert_eq!(api.post_json(None, &route, &serde_json::to_value(anon).unwrap()).status, 401);
    // Malformed.
    assert_eq!(api.post_json(Some(&p.fin.token()), &route, &json!({"expect": 0, "reshare": true})).status, 422);
    // Someone without access to the folder.
    assert_eq!(put(&p.carol, &p.carol.identity(), &env, &p.dev.name, 0, 1, true), 404);
    // Code, a personal key, a path that is no path.
    assert_eq!(put(&p.dev, &p.dev.identity(), "src/lib.rs", &p.fin.name, 0, 1, true), 403);
    assert_eq!(put(&p.fin, &fin, &format!("{BILL_DIR}/id_ed25519"), &p.dev.name, 0, 1, true), 403);
    assert_eq!(put(&p.fin, &fin, "../x/.env", &p.dev.name, 0, 1, true), 400);
    // To themselves, to nobody, to someone outside the project.
    assert_eq!(put(&p.fin, &fin, &env, &p.fin.name, 0, 1, true), 400);
    assert_eq!(put(&p.fin, &fin, &env, "nobody-at-all", 0, 1, true), 404);
    let outsider = hub.person("outsider");
    assert_eq!(put(&p.fin, &fin, &env, &outsider.name, 0, 1, true), 404);
    // Signed by another device than the one sending it.
    assert_eq!(put(&p.fin, &Identity::generate("x"), &env, &p.dev.name, 0, 1, true), 400);
    // A version that does not follow.
    assert_eq!(put(&p.fin, &fin, &env, &p.dev.name, 0, 2, true), 400);
    assert_eq!(put(&p.fin, &fin, &env, &p.dev.name, 0, 1, true), 200);
    // Another one built on nothing, or on a version that is not the
    // server's: refused.
    assert_eq!(put(&p.fin, &fin, &env, &p.dev.name, 0, 1, true), 409);
    assert_eq!(put(&p.fin, &fin, &env, &p.dev.name, 5, 6, false), 409);
    assert_eq!(put(&p.fin, &fin, &env, &p.dev.name, 1, 2, false), 200);
    // Only its sharer ends it.
    let remove = |who: &Person| {
        api.post_json(Some(&who.token()), &format!("{route}/remove"), &json!({"path": env, "recipient": p.dev.name})).status
    };
    assert_eq!(remove(&p.dev), 404);
    assert_eq!(remove(&p.admin), 404);
    assert_eq!(remove(&p.fin), 200);
    // An update built before the end never brings it back; sharing again does.
    assert_eq!(put(&p.fin, &fin, &env, &p.dev.name, 3, 4, false), 409);
    assert_eq!(put(&p.fin, &fin, &env, &p.dev.name, 2, 3, false), 409);
    assert_eq!(put(&p.fin, &fin, &env, &p.dev.name, 3, 4, true), 200);
    // Who sees what: the record only for its sharer and recipient.
    let (s, l) = shares_of(&hub, &p, &p.dev);
    assert!(s == 200 && l.len() == 1 && l[0].record.is_some());
    assert!(shares_of(&hub, &p, &p.fin).1[0].record.is_some());
    let (_, l) = shares_of(&hub, &p, &p.admin);
    assert!(l.len() == 1 && l[0].record.is_none());
    assert!(shares_of(&hub, &p, &p.sec).1.is_empty());
    assert_eq!(shares_of(&hub, &p, &outsider).0, 403);
    // Hostile sizes: a huge sealed file, too many devices, a huge body.
    let t = ShareTarget {
        project: &project,
        path: &env,
        sharer: &p.fin.name,
        recipient: &p.sec.name,
        version: 1,
    };
    let mut big = ShareRecord::seal(&fin, &t, 1, b"x", &[fin.public_hex()]).unwrap();
    // 60 MiB, under the request limit: parsed, then refused, never stored.
    big.sealed = "00".repeat(30 << 20);
    big.signature = fin.sign(veil_core::crypto::domains::SIG_CONTEXT_HUB_SHARE, &big.signing_body());
    let body = serde_json::to_value(SharePut { expect: 0, reshare: true, record: big }).unwrap();
    assert_eq!(api.post_json(Some(&p.fin.token()), &route, &body).status, 400);
    let many: Vec<String> = (0..65).map(|i| Identity::generate(&format!("d{i}")).public_hex()).collect();
    assert!(ShareRecord::seal(&fin, &t, 1, b"x", &many).is_err());
    assert!(row_of(&hub, &p, &env, &p.fin.name, &p.sec.name).is_none());
    // At most so many shares per person and project.
    sql(
        &hub,
        "INSERT INTO secret_shares (project_id, path, sharer_id, recipient_id, version, created_at, updated_at, unshared_at) \
         SELECT pr.id, 'x/' || g || '/.env', a.id, b.id, 1, 0, 0, 0 FROM projects pr, people a, people b, generate_series(1, $1) g \
         WHERE pr.name = $2 AND a.name = $3 AND b.name = $4",
        &[&MAX_SHARES_PER_SHARER, &p.name, &p.fin.name, &p.carol.name],
    );
    assert_eq!(put(&p.fin, &fin, &env, &p.sec.name, 0, 1, true), 403);
}

// ---- removals ----------------------------------------------------------------------------

/// A device the recipient removes is left out of every later version, also
/// when a compromised server lists it again with its old vouch; a recipient
/// who leaves the project is no longer served; a sharer who loses the
/// folder can no longer update or serve it.
#[test]
fn removed_devices_people_and_access() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let (f, d) = shared(&hub, &p);
    let env = env_path();
    // dev's second device, confirmed by dev: it is sealed for in the
    // background.
    let laptop = hub.new_device_of(&p.dev);
    p.dev.ok(&d, &["identity", "confirm", &laptop.fingerprint()]);
    laptop.ok(laptop.home.path(), &["login", &format!("veil://{}", hub.authority()), "--ca", hub.ca.to_str().unwrap()]);
    let lap = laptop.identity().public_hex();
    seal_until(&hub, &p, &f, &env, &p.dev.name, |r| r.devices().contains(&lap));
    let l = clone(&hub, &p, &laptop, "l");
    laptop.ok(&l, &["pull"]);
    assert!(read(&l, &env).unwrap().contains(ENV_MARK));
    // dev removes it: fin's next pass seals without it.
    p.dev.ok(&d, &["identity", "remove", &laptop.fingerprint()]);
    p.fin.ok(&f, &["pull"]);
    write_files(&f, &[(&env, "KEY=after-the-laptop-was-lost\n")]);
    let dev_id = p.dev.identity();
    let r = seal_until(&hub, &p, &f, &env, &p.dev.name, |r| r.open(&dev_id).is_ok_and(|c| c == b"KEY=after-the-laptop-was-lost\n"));
    assert!(!r.devices().contains(&laptop.identity().public_hex()), "{:?}", r.devices());
    assert!(r.open(&laptop.identity()).is_err());
    // Listed again, with dev's genuine old vouch: still left out.
    sql(&hub, "UPDATE devices SET removed_at = NULL WHERE signing_key = $1", &[&laptop.identity().verifying_hex()]);
    write_files(&f, &[(&env, "KEY=later\n")]);
    let r = seal_until(&hub, &p, &f, &env, &p.dev.name, |r| r.open(&dev_id).is_ok_and(|c| c == b"KEY=later\n"));
    assert!(r.version >= 4 && !r.devices().contains(&laptop.identity().public_hex()), "{:?}", r.devices());
    sql(&hub, "UPDATE devices SET removed_at = 1 WHERE signing_key = $1", &[&laptop.identity().verifying_hex()]);
    p.dev.ok(&d, &["pull"]);
    assert_eq!(read(&d, &env).unwrap(), "KEY=later\n");
    // The sharer loses the folder: the share pauses, nothing is served, and
    // fin's device can no longer update it.
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    let (_, l) = shares_of(&hub, &p, &p.dev);
    assert!(l.len() == 1 && !l[0].active && l[0].record.is_none() && l[0].paused.as_deref().unwrap_or("").contains("may no longer read"), "{l:?}");
    let out = p.admin.ok(&p.dir, &["secret", "shares"]);
    assert!(out.contains("paused") && out.contains("may no longer read"), "{out}");
    let v = row(&hub, &p, &env, &p.dev.name).unwrap().0;
    write_files(&f, &[(&env, "KEY=after-losing-access\n")]);
    p.fin.run(&f, &["share-keys"]);
    assert_eq!(row(&hub, &p, &env, &p.dev.name).unwrap().0, v);
    p.dev.ok(&d, &["pull"]);
    assert_eq!(read(&d, &env).unwrap(), "KEY=later\n");
    p.admin.ok(&p.dir, &["group", "add", "finance", &p.fin.name]);
    // The recipient leaves the project: not served, and no update reaches
    // them.
    p.admin.ok(&p.dir, &["group", "remove", "devs", &p.dev.name]);
    assert_eq!(shares_of(&hub, &p, &p.dev).0, 403);
    let (_, l) = shares_of(&hub, &p, &p.admin);
    assert!(l[0].paused.as_deref().unwrap_or("").contains("no longer takes part"), "{l:?}");
    let v = row(&hub, &p, &env, &p.dev.name).unwrap().0;
    p.fin.ok(&f, &["share-keys"]);
    assert_eq!(row(&hub, &p, &env, &p.dev.name).unwrap().0, v);
}

// ---- under load --------------------------------------------------------------------------

/// Two sharers update shares with several recipients from many threads at
/// once (each a compare-and-swap on the version), while some shares are
/// ended: every accepted version is unique and consecutive, and no update
/// brings an ended share back.
#[test]
fn concurrency_share_updates_and_unshares_under_load() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let project = project_id(&p.dir);
    let env = env_path();
    let route = format!("/v1/projects/{}/shares", p.name);
    let pairs: Vec<(&Person, &Person)> = vec![
        (&p.fin, &p.dev),
        (&p.fin, &p.carol),
        (&p.fin, &p.sec),
        (&p.admin, &p.dev),
        (&p.admin, &p.carol),
        (&p.admin, &p.sec),
    ];
    let tokens: Vec<(String, Identity)> = pairs.iter().map(|(s, _)| (s.token(), s.identity())).collect();
    let accepted = std::sync::Mutex::new(Vec::<(usize, u64)>::new());
    std::thread::scope(|scope| {
        for (i, (sharer, to)) in pairs.iter().enumerate() {
            for _thread in 0..3 {
                let (token, me) = (&tokens[i].0, &tokens[i].1);
                let (accepted, route, project, env) = (&accepted, &route, &project, &env);
                let api = hub.api();
                scope.spawn(move || {
                    for n in 0..12 {
                        let list: Vec<ShareInfo> = serde_json::from_slice(&api.get(Some(token), route).body).unwrap_or_default();
                        let cur = list.iter().find(|s| s.sharer == sharer.name && s.recipient == to.name);
                        if cur.is_some_and(|s| s.unshared_at.is_some()) {
                            return;
                        }
                        let expect = cur.map_or(0, |s| s.version);
                        let t = ShareTarget {
                            project,
                            path: env,
                            sharer: &sharer.name,
                            recipient: &to.name,
                            version: expect + 1,
                        };
                        let r = ShareRecord::seal(me, &t, n, format!("K={n}\n").as_bytes(), &[me.public_hex()]).unwrap();
                        let body = serde_json::to_value(SharePut { expect, reshare: false, record: r }).unwrap();
                        match api.post_json(Some(token), route, &body).status {
                            200 => accepted.lock().unwrap().push((i, expect + 1)),
                            409 => {}
                            s => panic!("unexpected {s}"),
                        }
                    }
                });
            }
        }
        // Meanwhile two shares end.
        let api = hub.api();
        for i in [1usize, 4] {
            let (sharer, to) = pairs[i];
            for _ in 0..200 {
                let r = api.post_json(Some(&tokens[i].0), &format!("{route}/remove"), &json!({"path": env, "recipient": to.name}));
                if r.status == 200 {
                    break;
                }
                assert_eq!(r.status, 404, "{}", String::from_utf8_lossy(&r.body));
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            let _ = sharer;
        }
    });
    let accepted = accepted.into_inner().unwrap();
    for (i, (sharer, to)) in pairs.iter().enumerate() {
        let mut v: Vec<u64> = accepted.iter().filter(|(j, _)| *j == i).map(|(_, v)| *v).collect();
        v.sort();
        let n = v.len() as u64;
        assert!(n > 0, "pair {i}: nothing accepted");
        assert_eq!(v, (1..=n).collect::<Vec<_>>(), "pair {i}: versions not unique and consecutive");
        let (version, ended, body) = row_of(&hub, &p, &env, &sharer.name, &to.name).unwrap();
        if i == 1 || i == 4 {
            assert!(ended.is_some() && body.is_none() && version as u64 == n + 1, "pair {i}: an ended share came back (v{version}, {n} accepted)");
        } else {
            assert!(ended.is_none() && version as u64 == n, "pair {i}: v{version}, {n} accepted");
            let r: ShareRecord = serde_json::from_str(&body.unwrap()).unwrap();
            assert_eq!(r.version, n);
        }
    }
    eprintln!("{} share versions accepted under load", accepted.len());
}
