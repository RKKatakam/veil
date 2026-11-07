//! Packs (S28, `docs/HUB.md` §13.18): a push's objects in one storage
//! write, read by range; uploads staged until a push lists them, refused
//! ones deleted (BUG-930); receipts bound to their person and pack; the
//! push's checks of a long history several at once (BUG-865), with the
//! answers of one at a time.

use std::sync::atomic::Ordering::Relaxed;

use serde_json::json;
use veil_core::{hub::wire::put_frame, object::Object as O, ObjectId};

use crate::{secrets2::clone, support::*};

fn project_id(hub: &TestHub, name: &str) -> i64 {
    hub.rt
        .block_on(sqlx::query_scalar::<_, i64>("SELECT id FROM projects WHERE name = $1").bind(name).fetch_one(&hub.hub().db))
        .unwrap()
}

/// `(listed, discarded)` pack rows of the project.
fn pack_rows(hub: &TestHub, project: i64) -> (i64, i64) {
    hub.rt
        .block_on(
            sqlx::query_as::<_, (i64, i64)>(
                "SELECT count(*) FILTER (WHERE listed), count(*) FILTER (WHERE NOT listed) FROM packs WHERE project_id = $1",
            )
            .bind(project)
            .fetch_one(&hub.hub().db),
        )
        .unwrap()
}

/// Storage writes of requests: the deriver's in the background aside.
fn writes(hub: &TestHub) -> u64 {
    let o = &hub.hub().objects;
    o.writes.load(Relaxed) - o.background_writes.load(Relaxed)
}

fn blob(text: &str) -> (ObjectId, Vec<u8>) {
    let raw = O::Blob(text.as_bytes().to_vec()).encode();
    (ObjectId::hash(&raw), raw)
}

/// A `vl push` of a change costs one storage write: its upload's staged
/// pack, listed as it is. A push the server completes (a member who cannot
/// see every folder: the graft's trees, the real snapshot, the member's
/// projection) costs one more, its own pack. Everyone reads what they read
/// before, through a second server too (which learns of the packs from the
/// database).
#[test]
fn a_push_is_one_storage_write_and_reads_come_from_its_pack() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let (listed0, _) = pack_rows(&hub, pid);
    assert!(listed0 >= 1, "the initial import is in packs");
    // The admin: the upload's pack, listed as it is.
    write_files(&p.dir, &[("src/one.rs", "MARKER-PACK-ADMIN-0d9e")]);
    p.admin.commit_main(&p.dir, "one file");
    let w = writes(&hub);
    p.admin.ok(&p.dir, &["push"]);
    assert_eq!(writes(&hub) - w, 1, "an admin's push: one storage write");
    assert_eq!(pack_rows(&hub, pid), (listed0 + 1, 0));
    // A developer, who cannot see billing: the server completes the
    // snapshot, and stores what it made in one pack of the push's own.
    let d = clone(&hub, &p, &p.dev, "dev");
    write_files(&d, &[("src/two.rs", "MARKER-PACK-DEV-77ab")]);
    p.dev.commit_main(&d, "dev's file");
    let w = writes(&hub);
    p.dev.ok(&d, &["push"]);
    let n = writes(&hub) - w;
    assert!(n <= 2, "a completed push: {n} storage writes");
    // Every viewer reads it, from a fresh server on the same database and
    // store (nothing cached: the packs read from the listing).
    let other = TestHub::beside(&hub);
    let api = other.api();
    for (who, sees_billing) in [(&p.admin, true), (&p.fin, true), (&p.dev, false)] {
        let token = who.token();
        assert_eq!(read_file(&api, &token, &p.name, "src/one.rs").as_deref(), Some(&b"MARKER-PACK-ADMIN-0d9e"[..]));
        assert_eq!(read_file(&api, &token, &p.name, "src/two.rs").as_deref(), Some(&b"MARKER-PACK-DEV-77ab"[..]));
        let bill = read_file(&api, &token, &p.name, &format!("{BILL_DIR}/acme/invoice.txt"));
        assert_eq!(bill.is_some(), sees_billing, "{}", who.name);
    }
}

/// The content of the file at `path` on `main` as `token`'s person sees it,
/// read through `api`'s server: its tips, history and fetch routes.
fn read_file(api: &Api, token: &str, project: &str, path: &str) -> Option<Vec<u8>> {
    let tip = api.tips(Some(token), project).unwrap().branches["main"];
    let h = api.post_json(Some(token), &format!("/v1/projects/{project}/history"), &json!({"tips": [tip.hex()]}));
    let (_, raw) = h.frames().into_iter().find(|(id, _)| *id == tip).unwrap();
    let O::Snapshot(s) = O::decode(&raw).unwrap() else { panic!() };
    let mut id = s.tree;
    let mut at = String::new();
    for part in path.split('/') {
        let r = api.post_json(Some(token), &format!("/v1/projects/{project}/fetch"), &json!({"snapshot": tip.hex(), "objects": [{"path": at, "id": id.hex()}]}));
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        let O::Tree(t) = O::decode(&r.frames()[0].1).unwrap() else { panic!("not a tree") };
        id = t.get(part)?.id;
        at = if at.is_empty() { part.to_string() } else { format!("{at}/{part}") };
    }
    let r = api.post_json(Some(token), &format!("/v1/projects/{project}/fetch"), &json!({"snapshot": tip.hex(), "objects": [{"path": at, "id": id.hex()}]}));
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    match O::decode(&r.frames()[0].1).unwrap() {
        O::Blob(b) => Some(b),
        _ => panic!("not a file"),
    }
}

/// BUG-930 with S28: an upload is staged; a push that refuses it deletes its
/// pack, so the refused plain-text secret is in no object of the store,
/// and the upload's receipt is of no use after.
#[test]
fn a_refused_push_deletes_its_staged_upload() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let secret = "aws_access_key_id = AKIAR4T6EXAMPLEW8Y2Q\n";
    let mut c = Craft::new(&api, &p.dev, &p.name, "main");
    c.file("src/creds.txt", secret);
    let tip = c.tip;
    // As `Craft::push`, with the receipts kept.
    let mut s = veil_core::object::Snapshot {
        parents: vec![tip],
        change_id: veil_core::ChangeId::random(),
        tree: c.root,
        description: veil_core::object::Text::Plain("a secret".into()),
        author: "crafter".into(),
        timestamp: veil_core::now_millis(),
        predecessors: vec![],
        conflicts: vec![],
        embargo: None,
        signature: None,
    };
    s.sign(&c.identity);
    let snap = c.put(O::Snapshot(s));
    let up = api.upload(&c.token, &p.name, &c.objects);
    assert_eq!(up.status, 200);
    let receipts: Vec<String> = serde_json::from_value(up.json()["receipts"].clone()).unwrap();
    let pack = receipts[0].split_once('.').unwrap().1.to_string();
    assert!(receipts.iter().all(|r| r.ends_with(&pack)), "one upload, one pack");
    let h = hub.hub();
    assert!(hub.rt.block_on(h.objects.staged_index(pid, &pack)).unwrap().is_some(), "staged");
    let map: serde_json::Map<String, serde_json::Value> = c.objects.iter().zip(&receipts).map(|((id, _), r)| (id.hex(), json!(r))).collect();
    let body = json!({"updates": [{"branch": "main", "expected": tip.hex(), "new": snap.hex()}], "receipts": map});
    let r = api.post_json(Some(&c.token), &format!("/v1/projects/{}/push", p.name), &body);
    assert_eq!(r.status, 403, "{}", String::from_utf8_lossy(&r.body));
    // Gone from the store (a fresh server reads only the store), never the
    // project's, and refused as never uploaded when shown again.
    let other = TestHub::beside(&hub);
    assert!(other.rt.block_on(other.hub().objects.staged_index(pid, &pack)).unwrap().is_none(), "the refused upload is deleted");
    assert!(hub.rt.block_on(h.objects.get(pid, &blob(secret).0)).unwrap().is_none());
    assert_eq!(pack_rows(&hub, pid).1, 1, "the discarded pack's row");
    let again = api.post_json(Some(&c.token), &format!("/v1/projects/{}/push", p.name), &body);
    assert!(again.status == 400 || again.status == 404, "{}: {}", again.status, String::from_utf8_lossy(&again.body));
    assert_eq!(hub.api().tips(Some(&p.dev.token()), &p.name).unwrap().branches["main"], tip);
}

/// A receipt holds for the person it was given to and the pack it names
/// only: another member showing it, or a receipt moved to another pack (of
/// theirs or anyone's), is an object never uploaded; malformed ones too.
#[test]
fn receipts_hold_only_for_their_person_and_pack() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let mark = "MARKER-RECEIPT-PERSON-5a1c";
    let mut c = Craft::new(&api, &p.dev, &p.name, "main");
    c.file("src/receipt.rs", mark);
    let tip = c.tip;
    let mut s = veil_core::object::Snapshot {
        parents: vec![tip],
        change_id: veil_core::ChangeId::random(),
        tree: c.root,
        description: veil_core::object::Text::Plain("receipts".into()),
        author: "crafter".into(),
        timestamp: veil_core::now_millis(),
        predecessors: vec![],
        conflicts: vec![],
        embargo: None,
        signature: None,
    };
    s.sign(&c.identity);
    let snap = c.put(O::Snapshot(s));
    let up = api.upload(&c.token, &p.name, &c.objects);
    let receipts: Vec<String> = serde_json::from_value(up.json()["receipts"].clone()).unwrap();
    // Carol (who may write src/) uploads something of her own: another pack.
    let (oid, oraw) = blob("carol's");
    let mut body = Vec::new();
    put_frame(&mut body, &oid, &oraw);
    let theirs: Vec<String> = serde_json::from_value(api.upload_body(&p.carol.token(), &p.name, &body).json()["receipts"].clone()).unwrap();
    let carol_pack = theirs[0].split_once('.').unwrap().1.to_string();
    let push = |token: &str, f: &dyn Fn(&str) -> String| {
        let map: serde_json::Map<String, serde_json::Value> = c.objects.iter().zip(&receipts).map(|((id, _), r)| (id.hex(), json!(f(r)))).collect();
        let body = json!({"updates": [{"branch": "main", "expected": tip.hex(), "new": snap.hex()}], "receipts": map});
        api.post_json(Some(token), &format!("/v1/projects/{}/push", p.name), &body)
    };
    let refused = |r: Reply, what: &str| {
        assert!(r.status == 400 || r.status == 404, "{what}: {} {}", r.status, String::from_utf8_lossy(&r.body));
    };
    let mac = |r: &str| r.split_once('.').unwrap().0.to_string();
    refused(push(&p.carol.token(), &|r| r.to_string()), "dev's receipts shown by carol");
    refused(push(&c.token, &|r| format!("{}.{carol_pack}", mac(r))), "moved to carol's pack");
    refused(push(&c.token, &|r| format!("{}.{}", mac(r), "0".repeat(32))), "moved to a pack nobody has");
    refused(push(&c.token, &|r| mac(r)), "without its pack");
    for bad in ["", ".", "x.y", &format!("{}.{}", "f".repeat(32), "A".repeat(32)), &format!("{}.../../x", "f".repeat(32))] {
        refused(push(&c.token, &|_| bad.to_string()), bad);
    }
    // The receipts as given, by the dev: landed.
    let r = push(&c.token, &|r| r.to_string());
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let d = clone(&hub, &p, &p.sec, "sec");
    assert_eq!(std::fs::read_to_string(d.join("src/receipt.rs")).unwrap(), mark);
}

/// BUG-865: a long history in one push, checked several snapshots at once.
/// The admin's (every guess right) and a developer's, who cannot see
/// billing (the server completes every snapshot: every guess wrong, so one
/// at a time), both land with the answers of one at a time: the same tips,
/// each snapshot's files, and billing intact for those who see it.
#[test]
fn bug_865_a_long_history_is_checked_several_at_once_with_the_same_answers() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    for i in 0..70 {
        write_files(&p.dir, &[(&format!("src/a/f{i}.rs"), &format!("admin {i}"))]);
        p.admin.commit_main(&p.dir, &format!("admin {i}"));
    }
    p.admin.ok(&p.dir, &["push"]);
    let d = clone(&hub, &p, &p.dev, "dev");
    for i in 0..70 {
        write_files(&d, &[(&format!("src/d/f{i}.rs"), &format!("dev {i}"))]);
        p.dev.commit_main(&d, &format!("dev {i}"));
    }
    p.dev.ok(&d, &["push"]);
    let f = clone(&hub, &p, &p.fin, "fin");
    for i in 0..70 {
        assert_eq!(std::fs::read_to_string(f.join(format!("src/a/f{i}.rs"))).unwrap(), format!("admin {i}"));
        assert_eq!(std::fs::read_to_string(f.join(format!("src/d/f{i}.rs"))).unwrap(), format!("dev {i}"));
    }
    assert!(std::fs::read_to_string(f.join(BILL_DIR).join("acme/invoice.txt")).unwrap().contains(BILL_MARK));
    // The developer's own history: every one of their 70 snapshots, under
    // the ids they made.
    let log = p.dev.ok(&d, &["log", "-n", "200"]);
    for i in 0..70 {
        assert!(log.contains(&format!("dev {i}")), "dev {i} missing from\n{log}");
    }
}
