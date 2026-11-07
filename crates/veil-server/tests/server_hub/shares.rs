//! Person-to-person secret shares (`docs/HUB.md` §13.15): `vl secret share
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

/// fin sends what fin's clone `f` holds now (`vl secret share` again: the
/// only way a new content goes out), and the record it stored.
fn send(hub: &TestHub, p: &Project, f: &Path, path: &str, to: &str, content: &[u8]) -> ShareRecord {
    p.fin.ok(f, &["secret", "share", path, "--with", to]);
    let r = record(hub, p, path, to);
    assert_eq!(r.open(&p.dev.identity()).unwrap(), content);
    r
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

/// A new version reaches the recipient when fin shares the file again (an
/// edit alone sends nothing); their own edit is never written over; unsharing stops every later version (what they received
/// stays theirs); sharing again starts it again.
#[test]
fn updates_and_unsharing() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let (f, d) = shared(&hub, &p);
    let env = env_path();
    write_files(&f, &[(&env, "KEY=second-v2\n")]);
    // An edit alone sends nothing.
    p.fin.ok(&f, &["share-keys"]);
    assert_eq!(record(&hub, &p, &env, &p.dev.name).version, 1);
    send(&hub, &p, &f, &env, &p.dev.name, b"KEY=second-v2\n");
    p.dev.ok(&d, &["pull"]);
    assert_eq!(read(&d, &env).unwrap(), "KEY=second-v2\n");
    // dev's own edit stays.
    write_files(&d, &[(&env, "KEY=dev-own\n")]);
    write_files(&f, &[(&env, "KEY=third-v3\n")]);
    send(&hub, &p, &f, &env, &p.dev.name, b"KEY=third-v3\n");
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
    send(&hub, &p, &f, &env, &p.dev.name, b"KEY=genuine-v2\n");
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
    let r = seal_until(&hub, &p, &f, &env, &p.dev.name, |r| !r.devices().contains(&lap));
    assert!(r.open(&laptop.identity()).is_err());
    // The same content, sealed again: never what fin's copy holds now.
    write_files(&f, &[(&env, "KEY=fin-edit-never-sent-by-the-pass\n")]);
    assert_eq!(r.open(&p.dev.identity()).unwrap(), read(&l, &env).unwrap().as_bytes());
    // Listed again, with dev's genuine old vouch: still left out, also from
    // the next version fin sends.
    sql(&hub, "UPDATE devices SET removed_at = NULL WHERE signing_key = $1", &[&laptop.identity().verifying_hex()]);
    write_files(&f, &[(&env, "KEY=later\n")]);
    p.fin.ok(&f, &["share-keys"]);
    let r = send(&hub, &p, &f, &env, &p.dev.name, b"KEY=later\n");
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

// ---- adversarial pass: secret shares (docs/BUGS.md) --------------------------------------

/// BUG-1060: the sharing device does not remember its own unshare. A
/// compromised server puts back the last record and lists the share as
/// active again; fin's background pass then seals fin's **rotated** secret
/// (the rotation `vl secret unshare` advises) for dev, whom fin cut off.
#[test]
fn bug_1060_an_unshare_the_server_forgets_never_seals_a_later_version() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let (f, _d) = shared(&hub, &p);
    let env = env_path();
    let last = record(&hub, &p, &env, &p.dev.name);
    p.fin.ok(&f, &["secret", "unshare", &env, "--from", &p.dev.name]);
    // The compromised server forgets the unshare: the last record is back,
    // at its version, and the share is listed as active.
    store(&hub, &p, &env, &last);
    sql(
        &hub,
        "UPDATE secret_shares SET unshared_at = NULL WHERE path = $1 AND project_id = (SELECT id FROM projects WHERE name = $2)",
        &[&env, &p.name],
    );
    // fin rotates the secret, as the unshare told them to.
    let rotated = "KEY=MARKER-ROTATED-AFTER-UNSHARE-5b0e77c1\n";
    write_files(&f, &[(&env, rotated)]);
    for _ in 0..3 {
        p.fin.ok(&f, &["share-keys"]);
    }
    let r = record(&hub, &p, &env, &p.dev.name);
    let dev_id = p.dev.identity();
    assert!(
        !r.open(&dev_id).is_ok_and(|c| c == rotated.as_bytes()),
        "fin's device sealed the rotated secret for dev after fin unshared it (version {} > {})",
        r.version,
        last.version
    );
}

/// BUG-1061: the limit of 256 shares per person and project is a count,
/// then an insert, in separate statements: requests that arrive together
/// all see room and all insert.
#[test]
fn bug_1061_concurrent_new_shares_never_pass_the_limit() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let project = project_id(&p.dir);
    // One short of the limit (ended shares count too).
    sql(
        &hub,
        "INSERT INTO secret_shares (project_id, path, sharer_id, recipient_id, version, created_at, updated_at, unshared_at) \
         SELECT pr.id, 'x/' || g || '/.env', a.id, b.id, 1, 0, 0, 0 FROM projects pr, people a, people b, generate_series(1, $1) g \
         WHERE pr.name = $2 AND a.name = $3 AND b.name = $4",
        &[&(MAX_SHARES_PER_SHARER - 1), &p.name, &p.fin.name, &p.carol.name],
    );
    let route = format!("/v1/projects/{}/shares", p.name);
    let (token, fin) = (p.fin.token(), p.fin.identity());
    let n = 24;
    let start = std::sync::Barrier::new(n);
    let accepted = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for i in 0..n {
            let (route, token, fin, project, start, accepted, dev, me) = (&route, &token, &fin, &project, &start, &accepted, &p.dev.name, &p.fin.name);
            let api = hub.api();
            scope.spawn(move || {
                let path = format!("{BILL_DIR}/race-{i}/.env");
                let t = ShareTarget {
                    project,
                    path: &path,
                    sharer: me,
                    recipient: dev,
                    version: 1,
                };
                let r = ShareRecord::seal(fin, &t, 1, b"K=1\n", &[fin.public_hex()]).unwrap();
                let body = serde_json::to_value(SharePut { expect: 0, reshare: true, record: r }).unwrap();
                start.wait();
                let s = api.post_json(Some(token), route, &body).status;
                assert!(s == 200 || s == 403, "unexpected {s}");
                if s == 200 {
                    accepted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            });
        }
    });
    let count: i64 = hub
        .rt
        .block_on(
            sqlx::query_scalar(
                "SELECT count(*) FROM secret_shares s JOIN projects pr ON pr.id = s.project_id JOIN people a ON a.id = s.sharer_id \
                 WHERE pr.name = $1 AND a.name = $2",
            )
            .bind(&p.name)
            .bind(&p.fin.name)
            .fetch_one(&hub.hub().db),
        )
        .unwrap();
    assert!(
        count <= MAX_SHARES_PER_SHARER,
        "{count} shares stored for one person (at most {MAX_SHARES_PER_SHARER}); {} of {n} concurrent new shares accepted",
        accepted.into_inner()
    );
}

/// BUG-1062: a symlink at the share's path in the recipient's working copy
/// (dev keeps `.env -> ../dev-own.env`) reads as "absent", so a new version
/// replaces dev's link with the sharer's copy: written over dev's own setup,
/// which "never written over the person's own edit" promises not to do.
#[test]
fn bug_1062_a_share_never_replaces_the_recipients_symlink() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let (f, d) = shared(&hub, &p);
    let env = env_path();
    // dev points the path at a file of their own.
    write_files(&d, &[("dev-own-a3c1.env", "DEV=MARKER-DEV-OWN-LINKED-6e2f\n")]);
    std::fs::remove_file(d.join(&env)).unwrap();
    std::os::unix::fs::symlink("../dev-own-a3c1.env", d.join(&env)).unwrap();
    write_files(&f, &[(&env, "KEY=sharer-v2-after-the-link\n")]);
    send(&hub, &p, &f, &env, &p.dev.name, b"KEY=sharer-v2-after-the-link\n");
    p.dev.ok(&d, &["pull"]);
    let meta = std::fs::symlink_metadata(d.join(&env)).unwrap();
    assert!(meta.file_type().is_symlink(), "dev's symlink was replaced by the shared copy: {:?}", read(&d, &env));
    // The same for a FIFO (reading it would block), and nothing hangs.
    std::fs::remove_file(d.join(&env)).unwrap();
    assert!(std::process::Command::new("mkfifo").arg(d.join(&env)).status().unwrap().success());
    write_files(&f, &[(&env, "KEY=sharer-v3-after-the-fifo\n")]);
    send(&hub, &p, &f, &env, &p.dev.name, b"KEY=sharer-v3-after-the-fifo\n");
    let out = p.dev.ok(&d, &["pull"]);
    assert!(out.contains("not a regular file"), "{out}");
    use std::os::unix::fs::FileTypeExt;
    assert!(std::fs::symlink_metadata(d.join(&env)).unwrap().file_type().is_fifo());
}

/// BUG-1063: every clone on the sharing device updates the share, each
/// from its own copy. fin keeps a second clone (an older checkout, an
/// agent's): its background pass seals that clone's older secret as a new
/// version, and dev is rolled back to it; the two clones then take turns.
#[test]
fn bug_1063_another_clone_on_the_sharing_device_never_rolls_the_share_back() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let (f, _d) = shared(&hub, &p);
    let env = env_path();
    let f2 = clone(&hub, &p, &p.fin, "f2");
    assert!(read(&f2, &env).unwrap().contains(ENV_MARK));
    let newer = "KEY=MARKER-NEWER-FROM-F-2d7a90be\n";
    write_files(&f, &[(&env, newer)]);
    let dev_id = p.dev.identity();
    send(&hub, &p, &f, &env, &p.dev.name, newer.as_bytes());
    // A command in fin's other clone runs its background pass.
    p.fin.ok(&f2, &["share-keys"]);
    let r = record(&hub, &p, &env, &p.dev.name);
    let got = r.open(&dev_id).unwrap();
    assert_eq!(String::from_utf8_lossy(&got), newer, "fin's other clone sealed its older copy (version {})", r.version);
}

// ---- content updates are explicit (owner's delegate, 2026-11-07, cycle 3) ---------------

/// A new content goes out only with `vl secret share`: the background pass,
/// whatever the working copy holds (an edit, a value the share held
/// before), seals nothing new; run again, the command sends what the clone
/// holds now, whatever it is.
#[test]
fn content_updates_are_explicit() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let (f, d) = shared(&hub, &p);
    let env = env_path();
    let first = read(&f, &env).unwrap();
    for v in ["KEY=an-edit-0a91\n", "KEY=another-edit-77c2\n"] {
        write_files(&f, &[(&env, v)]);
        let out = p.fin.ok(&f, &["share-keys"]);
        assert!(!out.contains("version"), "{out}");
        assert_eq!(record(&hub, &p, &env, &p.dev.name).version, 1);
    }
    send(&hub, &p, &f, &env, &p.dev.name, b"KEY=another-edit-77c2\n");
    // On purpose, even a value it held before.
    write_files(&f, &[(&env, &first)]);
    send(&hub, &p, &f, &env, &p.dev.name, first.as_bytes());
    p.dev.ok(&d, &["pull"]);
    assert_eq!(read(&d, &env).unwrap(), first);
}

/// A genuine version the recipient saw but did not write (their own edit
/// was there) is remembered: after they remove their copy, a compromised
/// server cannot serve an older one instead.
#[test]
fn a_version_seen_but_not_written_still_refuses_older_ones() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let (f, d) = shared(&hub, &p);
    let env = env_path();
    let v1 = record(&hub, &p, &env, &p.dev.name);
    write_files(&d, &[(&env, "KEY=dev-own-edit\n")]);
    // Two versions dev sees but does not write (their own edit is there).
    let mut seen = Vec::new();
    for v in ["KEY=newer-v2\n", "KEY=newer-v3\n"] {
        write_files(&f, &[(&env, v)]);
        seen.push(send(&hub, &p, &f, &env, &p.dev.name, v.as_bytes()));
        let out = p.dev.ok(&d, &["pull"]);
        assert!(out.contains("not written over your own"), "{out}");
    }
    std::fs::remove_file(d.join(&env)).unwrap();
    // The version dev wrote, and one older than the newest dev saw: neither
    // is written now.
    store(&hub, &p, &env, &v1);
    p.dev.ok(&d, &["pull"]);
    assert!(read(&d, &env).is_none());
    store(&hub, &p, &env, &seen[0]);
    let out = p.dev.ok(&d, &["pull"]);
    assert!(out.contains("older than the one received") && read(&d, &env).is_none(), "{out}");
    store(&hub, &p, &env, &seen[1]);
    p.dev.ok(&d, &["pull"]);
    assert_eq!(read(&d, &env).unwrap(), "KEY=newer-v3\n");
}

/// A received copy is never recorded once the device holds the key of its
/// folder: dev, with a `.veilpolicy` of their own that seals the folder's
/// secrets, receives a file of `billing/` while holding no key there; then
/// dev joins finance, and the next snapshot moves the copy out of the
/// working copy instead of sealing it for everyone in finance.
#[test]
fn a_received_copy_is_never_recorded_after_the_device_gains_the_key() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let f = clone(&hub, &p, &p.fin, "f");
    let d = clone(&hub, &p, &p.dev, "d");
    write_files(&d, &[(".veilpolicy", &format!("{}{BILL_DIR}/  finance\n", veil_core::policy::SYNCED_SECRETS_POLICY))]);
    let own = format!("{BILL_DIR}/.env.fin-own");
    let mark = "FIN=MARKER-FIN-OWN-SHARED-1f7c3a90\n";
    write_files(&f, &[(&own, mark)]);
    p.fin.ok(&f, &["secret", "share", &own, "--with", &p.dev.name]);
    p.dev.ok(&d, &["pull"]);
    assert_eq!(read(&d, &own).unwrap(), mark);
    // dev joins finance: their device receives the folder's key.
    p.admin.ok(&p.dir, &["group", "add", "finance", &p.dev.name]);
    p.dev.ok(&d, &["pull"]);
    let out = p.dev.ok(&d, &["commit", "-m", "after joining finance"]);
    assert!(read(&d, &own).is_none(), "the copy stayed in the working copy:\n{out}");
    let held = std::fs::read_dir(d.join(".veil/local/secret-shares-held")).unwrap().count();
    assert_eq!(held, 1);
    let repo = veil_core::Repo::open(std::sync::Arc::new(veil_core::DiskBackend::new(&d)), Some(p.dev.identity()), "test").unwrap();
    for snap in repo.ancestors(&repo.view().workspaces["default"].wc).unwrap() {
        let tree = repo.store().snapshot(&snap).unwrap().tree;
        assert!(veil_core::tree::lookup(repo.store(), &tree, &veil_core::VPath::new(&own).unwrap()).unwrap().is_none(), "recorded in {snap}");
    }
}

// ---- secret shares, review cycle 2 (docs/BUGS.md "Secret shares cycle 2") ----------------

/// The snapshot the working copy of `dir`'s default workspace is on (its
/// first parent), as hex.
fn wc_parent(dir: &Path) -> String {
    let repo = veil_core::Repo::open(std::sync::Arc::new(veil_core::DiskBackend::new(dir)), None, "test").unwrap();
    let wc = repo.view().workspaces["default"].wc;
    repo.store().snapshot(&wc).unwrap().parents[0].to_string()
}

/// The share of `path` from `sharer` to `recipient`, as stored.
fn record_from(hub: &TestHub, p: &Project, path: &str, sharer: &str, recipient: &str) -> ShareRecord {
    serde_json::from_str(&row_of(hub, p, path, sharer, recipient).unwrap().2.expect("an active share has a record")).unwrap()
}

/// BUG-1064: the forward rule reads the revisions of the workspace the
/// share was made in, but the file from the project directory, whichever
/// workspace it is attached to. The admin (whose commits record `.env`)
/// rotates it, commits, shares the rotated value with dev, then switches
/// the directory to a workspace on the revision before the rotation: the
/// old value is back in the directory, the default workspace has not
/// moved, and the pass seals the old value, rolling dev back to the secret
/// the admin rotated away from.
#[test]
fn bug_1064_switching_the_directory_to_an_older_workspace_never_rolls_the_share_back() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let (a, env, dev_id) = (&p.dir, env_path(), p.dev.identity());
    let old = read(a, &env).unwrap();
    assert!(old.contains(ENV_MARK));
    let rotated = "KEY=MARKER-ROTATED-BEFORE-SHARING-3c9d1e07\n";
    write_files(a, &[(&env, rotated)]);
    p.admin.ok(a, &["commit", "-m", "rotate the key"]);
    p.admin.ok(a, &["secret", "share", &env, "--with", &p.dev.name]);
    assert_eq!(record_from(&hub, &p, &env, &p.admin.name, &p.dev.name).open(&dev_id).unwrap(), rotated.as_bytes());
    // A workspace on the revision before the rotation, and the directory on it.
    p.admin.ok(a, &["ws", "new", "before", "-r", "@--"]);
    p.admin.ok(a, &["ws", "switch", "before"]);
    assert_eq!(read(a, &env).unwrap(), old, "the older workspace holds the value before the rotation");
    let out = (0..3).map(|_| p.admin.ok(a, &["share-keys"])).collect::<Vec<_>>().join("");
    let r = record_from(&hub, &p, &env, &p.admin.name, &p.dev.name);
    // No content goes out without `vl secret share`: dev keeps the rotated value.
    assert!(r.version == 1 && r.open(&dev_id).unwrap() == rotated.as_bytes(), "the admin's pass sealed a new content (version {}):\n{out}", r.version);
}

/// BUG-1065: "forward" accepts any snapshot of the change the last value
/// was sealed on, an earlier version of it too (step 5.6 of the review
/// skill: the change id alone does not say which version is newer). The
/// admin commits a value (never shared), squashes a newer one into the
/// same change, shares that, then starts a change on the earlier version
/// of the change (where `vl undo` of the squash, or `vl evolog`, lead):
/// the earlier value is back, and the pass seals it.
#[test]
fn bug_1065_an_earlier_version_of_the_same_change_is_an_older_revision() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let (a, env, dev_id) = (&p.dir, env_path(), p.dev.identity());
    let earlier = "KEY=MARKER-EARLIER-VERSION-NEVER-SHARED-77d0a4b2\n";
    write_files(a, &[(&env, earlier)]);
    p.admin.ok(a, &["commit", "-m", "the key"]);
    let first_version = wc_parent(a);
    let current = "KEY=MARKER-CURRENT-VERSION-SHARED-0e5f2c19\n";
    write_files(a, &[(&env, current)]);
    p.admin.ok(a, &["squash"]);
    assert_ne!(wc_parent(a), first_version, "the squash rewrote the change");
    p.admin.ok(a, &["secret", "share", &env, "--with", &p.dev.name]);
    assert_eq!(record_from(&hub, &p, &env, &p.admin.name, &p.dev.name).open(&dev_id).unwrap(), current.as_bytes());
    // On the earlier version of the same change.
    p.admin.ok(a, &["new", &first_version]);
    assert_eq!(read(a, &env).unwrap(), earlier);
    let out = (0..3).map(|_| p.admin.ok(a, &["share-keys"])).collect::<Vec<_>>().join("");
    let r = record_from(&hub, &p, &env, &p.admin.name, &p.dev.name);
    // No content goes out without `vl secret share`: dev keeps the current value.
    assert!(r.version == 1 && r.open(&dev_id).unwrap() == current.as_bytes(), "the admin's pass sealed a new content (version {}):\n{out}", r.version);
}

/// `vl args` as `who` in `dir`, starting no background pass.
fn quiet(who: &Person, dir: &Path, args: &[&str]) -> std::process::Output {
    let o = who.command(dir, args).env("VEIL_KEY_SHARE", "0").output().unwrap();
    assert!(o.status.success(), "vl {args:?}: {}", String::from_utf8_lossy(&o.stderr));
    o
}

/// Wait until no background pass runs in `dir`.
fn no_pass_running(dir: &Path) {
    let dir = dir.canonicalize().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    loop {
        let busy = std::fs::read_dir("/proc").unwrap().flatten().any(|e| {
            let cmd = std::fs::read(e.path().join("cmdline")).unwrap_or_default();
            cmd.windows(10).any(|w| w == b"share-keys") && std::fs::read_link(e.path().join("cwd")).is_ok_and(|c| c == dir)
        });
        if !busy {
            return;
        }
        assert!(std::time::Instant::now() < deadline, "a background pass never ended");
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// BUG-1066: `secret-shares.json` is read, changed and written back with
/// no lock, by `vl secret share|unshare`, the background pass and `vl
/// pull` in different processes. A pass in flight when fin unshares writes
/// back the record it read before: the unshared share is recorded again,
/// and the server that forgets the unshare (BUG-1060's attack) gets fin's
/// rotated secret sealed for dev after all. The server decides how long
/// the pass is in flight (it answers the recipient's device list when it
/// likes); here a gate in the database holds that answer until fin's
/// unshare is done. (PostgreSQL: advisory locks.)
#[test]
fn bug_1066_a_pass_in_flight_never_brings_back_an_unshare() {
    // The gate replaces the `devices` table with a view and adds a function:
    // in a database of this test's own, so no other test sees them.
    let admin_url = std::env::var("VEIL_TEST_DATABASE_URL").expect("VEIL_TEST_DATABASE_URL (run scripts/verify-server.sh)");
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let name = format!("{}{}", std::env::var("VEIL_TEST_DB_PREFIX").unwrap_or_default(), unique("veil_fresh_"));
    let yugabyte = rt.block_on(async {
        let db = veil_server::db::connect(&admin_url, 1).await.unwrap();
        let v: String = sqlx::query_scalar("SELECT version()").fetch_one(&db).await.unwrap();
        if !v.contains("-YB-") {
            sqlx::raw_sql(&format!("CREATE DATABASE {name}")).execute(&db).await.unwrap();
        }
        db.close().await;
        v.contains("-YB-")
    });
    if yugabyte {
        eprintln!("bug_1066: the gate uses PostgreSQL's advisory locks; it runs on PostgreSQL only");
        return;
    }
    let (base, _) = admin_url.rsplit_once('/').unwrap();
    let hub = TestHub::start_on(&format!("{base}/{name}"), std::time::Duration::from_secs(3600));
    let p = setup_project(&hub);
    let (f, _d) = shared(&hub, &p);
    let env = env_path();
    // A second share of fin's, ended from another device of fin's: the
    // pass forgets it, so it writes its record back.
    let other = format!("{BILL_DIR}/.env.other");
    write_files(&f, &[(&other, "OTHER=MARKER-OTHER-SHARE-6d13a0b4\n")]);
    quiet(&p.fin, &f, &["secret", "share", &other, "--with", &p.dev.name]);
    no_pass_running(&f);
    sql(
        &hub,
        "UPDATE secret_shares SET unshared_at = 1, version = version + 1, body = NULL \
         WHERE path = $1 AND project_id = (SELECT id FROM projects WHERE name = $2)",
        &[&other, &p.name],
    );
    let last = record(&hub, &p, &env, &p.dev.name);
    // The gate: the server answers dev's device list (`GET
    // /v1/people/dev/devices`, the route's own query) only when the test
    // says, from its second call on (the first is the key pass's, before
    // the share pass reads `secret-shares.json`).
    let db = hub.hub().db.clone();
    let dev_person: i64 = hub.rt.block_on(sqlx::query_scalar("SELECT id FROM people WHERE name = $1").bind(&p.dev.name).fetch_one(&db)).unwrap();
    let _rt = hub.rt.enter();
    let mut gate = hub.rt.block_on(db.acquire()).unwrap();
    hub.rt.block_on(sqlx::query("SELECT pg_advisory_lock(4242)").execute(&mut *gate)).unwrap();
    sql(
        &hub,
        &format!(
            "CREATE FUNCTION veil_test_gate(p BIGINT) RETURNS BOOLEAN LANGUAGE plpgsql VOLATILE AS $g$ BEGIN \
             IF p = {dev_person} AND current_query() LIKE '%d.person_id = $1 AND d.removed_at IS NULL AND NOT d.pending AND NOT EXISTS%' THEN INSERT INTO gate_log VALUES (current_query()); \
             IF (SELECT count(*) FROM gate_log) > 1 THEN PERFORM pg_advisory_lock_shared(4242); PERFORM pg_advisory_unlock_shared(4242); END IF; END IF; \
             RETURN TRUE; END $g$"
        ),
        &[],
    );
    sql(&hub, "CREATE TABLE gate_log (q TEXT)", &[]);
    sql(&hub, "ALTER TABLE devices RENAME TO devices_gated", &[]);
    sql(&hub, "CREATE VIEW devices AS SELECT * FROM devices_gated d WHERE veil_test_gate(d.person_id)", &[]);
    let waiting = || -> i64 {
        hub.rt
            .block_on(sqlx::query_scalar("SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND objid = 4242 AND NOT granted \
                 AND database = (SELECT oid FROM pg_database WHERE datname = current_database())").fetch_one(&db))
            .unwrap()
    };
    std::thread::scope(|scope| {
        let pass = scope.spawn(|| quiet(&p.fin, &f, &["share-keys"]));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        while waiting() == 0 {
            assert!(std::time::Instant::now() < deadline, "the pass never asked for dev's devices");
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        // While the pass waits for the server: fin unshares.
        quiet(&p.fin, &f, &["secret", "unshare", &env, "--from", &p.dev.name]);
        hub.rt.block_on(sqlx::query("SELECT pg_advisory_unlock(4242)").execute(&mut *gate)).unwrap();
        let o = pass.join().unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    });
    let gated: i64 = hub.rt.block_on(sqlx::query_scalar("SELECT count(*) FROM gate_log").fetch_one(&db)).unwrap();
    assert!(gated >= 2, "the share pass never asked for dev's devices");
    sql(&hub, "DROP VIEW devices", &[]);
    sql(&hub, "ALTER TABLE devices_gated RENAME TO devices", &[]);
    let local = std::fs::read_to_string(f.join(".veil/local/secret-shares.json")).unwrap_or_default();
    // BUG-1060's attack: the server forgets the unshare; fin rotates.
    store(&hub, &p, &env, &last);
    sql(
        &hub,
        "UPDATE secret_shares SET unshared_at = NULL WHERE path = $1 AND project_id = (SELECT id FROM projects WHERE name = $2)",
        &[&env, &p.name],
    );
    let rotated = "KEY=MARKER-ROTATED-AFTER-UNSHARE-9e4c27f5\n";
    write_files(&f, &[(&env, rotated)]);
    for _ in 0..3 {
        p.fin.ok(&f, &["share-keys"]);
    }
    let r = record(&hub, &p, &env, &p.dev.name);
    assert!(
        !r.open(&p.dev.identity()).is_ok_and(|c| c == rotated.as_bytes()),
        "fin's device sealed the rotated secret for dev after fin unshared it (version {} > {}); the clone's record \
         after the race: {local}",
        r.version,
        last.version
    );
}

/// BUG-1067: the hold-back before a snapshot moves whatever regular file is
/// at a received share's path, every time, to one fixed name: the second
/// move writes over the first. dev edits the copy they received, gains the
/// folder's key (the edit is moved out), then writes a file of their own
/// at that path: it is moved too, over dev's edit, which is lost.
#[test]
fn bug_1067_holding_back_a_received_copy_never_loses_what_it_held() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let f = clone(&hub, &p, &p.fin, "f");
    let d = clone(&hub, &p, &p.dev, "d");
    write_files(&d, &[(".veilpolicy", &format!("{}{BILL_DIR}/  finance\n", veil_core::policy::SYNCED_SECRETS_POLICY))]);
    let own = format!("{BILL_DIR}/.env.fin-own");
    let mark = "FIN=MARKER-FIN-OWN-SHARED-1f7c3a90\n";
    write_files(&f, &[(&own, mark)]);
    p.fin.ok(&f, &["secret", "share", &own, "--with", &p.dev.name]);
    p.dev.ok(&d, &["pull"]);
    assert_eq!(read(&d, &own).unwrap(), mark);
    // dev's own edit of the copy (never written over by a later version).
    let edited = format!("{mark}DEV=MARKER-DEV-OWN-EDIT-OF-THE-COPY-8b2e40d1\n");
    write_files(&d, &[(&own, &edited)]);
    p.admin.ok(&p.dir, &["group", "add", "finance", &p.dev.name]);
    p.dev.ok(&d, &["pull"]);
    p.dev.ok(&d, &["commit", "-m", "after joining finance"]);
    assert!(read(&d, &own).is_none());
    // A file of dev's own at that path, later.
    write_files(&d, &[(&own, "FIN=MARKER-DEV-OWN-NEW-FILE-c41a9e3f\n")]);
    let out = p.dev.ok(&d, &["commit", "-m", "a file of my own"]);
    let held: Vec<String> = std::fs::read_dir(d.join(".veil/local/secret-shares-held"))
        .unwrap()
        .map(|e| std::fs::read_to_string(e.unwrap().path()).unwrap())
        .collect();
    assert!(held.contains(&edited), "dev's own edit of the copy is gone; held now: {held:?}\n{out}");
}

/// BUG-1066's class, as a property of concurrent commands: random `vl
/// secret share` and `unshare` commands (a pinned seed) in fin's clone,
/// while background passes run there and `vl pull` and passes run in dev's
/// clone, all at once. After each round: fin's record holds exactly the
/// shares whose last command was a share, each at the server's version;
/// dev's record never holds a version newer than the server's, never one
/// older than it saw, and a final pull brings every active share's latest.
#[test]
fn concurrency_the_share_record_under_concurrent_commands() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let f = clone(&hub, &p, &p.fin, "f");
    let d = clone(&hub, &p, &p.dev, "d");
    let paths: Vec<String> = (0..4).map(|i| format!("{BILL_DIR}/.env.c{i}")).collect();
    for (i, path) in paths.iter().enumerate() {
        write_files(&f, &[(path, &format!("C{i}=MARKER-CONCURRENT-{i}-5e81c0d2\n"))]);
    }
    let state = |dir: &Path| -> serde_json::Value {
        serde_json::from_str(&std::fs::read_to_string(dir.join(".veil/local/secret-shares.json")).unwrap_or_else(|_| "{}".into())).unwrap()
    };
    // xorshift64*, seeded: the same commands every run.
    let mut seed: u64 = std::env::var("PROPTEST_RNG_SEED").ok().and_then(|s| s.parse().ok()).unwrap_or(0x5eed_1066);
    let mut next = move || {
        seed ^= seed >> 12;
        seed ^= seed << 25;
        seed ^= seed >> 27;
        seed.wrapping_mul(0x2545_f491_4f6c_dd1d)
    };
    let mut shared_now = std::collections::BTreeSet::new();
    for round in 0..3 {
        let ops: Vec<(usize, bool)> = (0..6).map(|_| ((next() % 4) as usize, next() % 3 != 0)).collect();
        let done = std::sync::atomic::AtomicBool::new(false);
        std::thread::scope(|scope| {
            for (who, dir) in [(&p.fin, &f), (&p.fin, &f), (&p.dev, &d)] {
                let done = &done;
                scope.spawn(move || {
                    while !done.load(std::sync::atomic::Ordering::SeqCst) {
                        let _ = who.command(dir, &["share-keys"]).env("VEIL_KEY_SHARE", "0").output();
                    }
                });
            }
            let done2 = &done;
            scope.spawn(|| {
                while !done2.load(std::sync::atomic::Ordering::SeqCst) {
                    let _ = p.dev.command(&d, &["pull"]).env("VEIL_KEY_SHARE", "0").output();
                }
            });
            for (i, share) in &ops {
                let path = &paths[*i];
                if *share {
                    quiet(&p.fin, &f, &["secret", "share", path, "--with", &p.dev.name]);
                    shared_now.insert(path.clone());
                } else if shared_now.remove(path) {
                    quiet(&p.fin, &f, &["secret", "unshare", path, "--from", &p.dev.name]);
                }
            }
            done.store(true, std::sync::atomic::Ordering::SeqCst);
        });
        // fin's record: exactly the shares last shared, at the server's version.
        let st = state(&f);
        let made: std::collections::BTreeMap<String, u64> = st["made"]
            .as_object()
            .map(|m| m.iter().map(|(k, v)| (k.split('\u{0}').next().unwrap().to_string(), v["version"].as_u64().unwrap())).collect())
            .unwrap_or_default();
        let want: std::collections::BTreeSet<&String> = shared_now.iter().collect();
        assert_eq!(made.keys().collect::<std::collections::BTreeSet<_>>(), want, "round {round}: fin's record {st}");
        for (path, v) in &made {
            let (server, ended, _) = row(&hub, &p, path, &p.dev.name).unwrap();
            assert!(ended.is_none() && server as u64 == *v, "round {round}: {path} recorded at {v}, the server has {server}");
        }
        // dev's record: never ahead of the server, never behind what it saw.
        p.dev.ok(&d, &["pull"]);
        let st = state(&d);
        for path in &paths {
            let k = format!("{}\u{0}{path}", p.fin.name);
            let got = st["received"][&k]["version"].as_u64();
            let seen = st["seen"][&k].as_u64().unwrap_or(0);
            let Some((server, ended, _)) = row(&hub, &p, path, &p.dev.name) else { continue };
            if let Some(g) = got {
                assert!(g <= server as u64 && seen >= g, "round {round}: {path}: received {g}, seen {seen}, server {server}");
            }
            if ended.is_none() {
                assert_eq!(got, Some(server as u64), "round {round}: {path} not delivered at its latest version: {st}");
            }
        }
    }
}
