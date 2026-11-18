//! The `objects` server object layout (`docs/design/server/object-layout.md`
//! §8.1, guarantees 1–11): each kept object stored under its own key
//! `p/<project>/<2 hex>/<62 hex>`, uploads staged in containers that are
//! marked discarded in the push's statement and deleted from storage and
//! `packs` after commit, always-write rule on kept objects, mixed-layout
//! deployments, GC races, object routes, landing batches, crash recovery and
//! one-shot leftover pack merging.

use std::{
    collections::HashSet,
    sync::{
        atomic::{AtomicUsize, Ordering::Relaxed},
        Arc,
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use serde_json::{json, Value};
use veil_core::{
    hub::{
        grant::{sign_request, BatchRequest, ChainWant, Grant},
        wire::put_frame,
    },
    object::{Object as O, Snapshot, Text, Visibility},
    ChangeId, Identity, ObjectId,
};
use veil_server::{
    pack_gc::{self, Fault, FaultPoint, Options},
    ObjectLayout,
};

use crate::{
    landing_hold::{packs_in, whole_tree_beside},
    limits::{hold_branch, land_edit, release_branch},
    pack_gc::gc_pass,
    support::*,
};

fn project_id(hub: &TestHub, name: &str) -> i64 {
    hub.rt
        .block_on(sqlx::query_scalar::<_, i64>("SELECT id FROM projects WHERE name = $1").bind(name).fetch_one(&hub.hub().db))
        .unwrap()
}

/// `(staged, listed, discarded)` pack rows of `project`.
fn pack_counts(hub: &TestHub, project: i64) -> (i64, i64, i64) {
    hub.rt
        .block_on(
            sqlx::query_as::<_, (i64, i64, i64)>(
                "SELECT count(*) FILTER (WHERE state = 0), \
                        count(*) FILTER (WHERE state = 1), \
                        count(*) FILTER (WHERE state = 2) \
                 FROM packs WHERE project_id = $1",
            )
            .bind(project)
            .fetch_one(&hub.hub().db),
        )
        .unwrap()
}

fn packs_in_store(hub: &TestHub, project: i64) -> Vec<String> {
    let prefix = format!("p/{project}/pack/");
    let keys = hub.rt.block_on(hub.blob_store().list(&prefix)).unwrap();
    keys.iter()
        .filter_map(|k| k.strip_prefix(&prefix))
        .filter(|n| veil_server::pack::valid_name(n))
        .map(str::to_string)
        .collect()
}

fn loose_keys_in_store(hub: &TestHub, project: i64) -> HashSet<String> {
    let prefix = format!("p/{project}/");
    let pack_prefix = format!("p/{project}/pack/");
    hub.rt
        .block_on(hub.blob_store().list(&prefix))
        .unwrap()
        .into_iter()
        .filter(|k| !k.starts_with(&pack_prefix))
        .collect()
}

fn blob(text: &str) -> (ObjectId, Vec<u8>) {
    let raw = O::Blob(text.as_bytes().to_vec()).encode();
    (ObjectId::hash(&raw), raw)
}

/// An incompressible blob (> 64 bytes) so `Objects::get_range` serves a true
/// byte-range read without whole-object decompression fallback.
fn plain_blob(seed: u64, tag: &str) -> (ObjectId, Vec<u8>) {
    let mut payload = Vec::with_capacity(256);
    payload.extend_from_slice(tag.as_bytes());
    let mut x = seed;
    while payload.len() < 256 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        payload.extend_from_slice(&x.to_le_bytes());
    }
    let raw = O::Blob(payload).encode();
    assert!(!veil_core::hub::encoding::is_compressed(&veil_core::hub::encoding::encode(&raw)));
    (ObjectId::hash(&raw), raw)
}

fn snap(c: &mut Craft, parents: Vec<ObjectId>, msg: &str, by: Option<&Identity>) -> ObjectId {
    let mut s = Snapshot {
        parents,
        change_id: ChangeId::random(),
        tree: c.root,
        description: Text::Plain(msg.into()),
        author: "crafter".into(),
        timestamp: veil_core::now_millis(),
        predecessors: vec![],
        conflicts: vec![],
        embargo: None,
        signature: None,
        agent: None,
        attempts: vec![],
        abandoned: None,
    };
    s.sign(by.unwrap_or(&c.identity));
    c.put(O::Snapshot(s))
}

fn upload_all(api: &Api, c: &Craft) -> (serde_json::Map<String, Value>, String) {
    let up = api.upload(&c.token, &c.project, &c.objects);
    assert_eq!(up.status, 200, "{}", String::from_utf8_lossy(&up.body));
    let receipts: Vec<String> = serde_json::from_value(up.json()["receipts"].clone()).unwrap();
    let pack = receipts[0].split_once('.').unwrap().1.to_string();
    (
        c.objects.iter().zip(&receipts).map(|((id, _), r)| (id.hex(), json!(r))).collect(),
        pack,
    )
}

fn push_body(
    api: &Api,
    token: &str,
    project: &str,
    branch: &str,
    expected: Option<ObjectId>,
    new: ObjectId,
    receipts: &serde_json::Map<String, Value>,
) -> Reply {
    let exp = expected.map(|e| json!(e.hex())).unwrap_or(Value::Null);
    let body = json!({"updates": [{"branch": branch, "expected": exp, "new": new.hex()}], "receipts": receipts});
    api.post_json(Some(token), &format!("/v1/projects/{project}/push"), &body)
}

fn settle(hub: &TestHub) {
    let mut last = (u64::MAX, Instant::now());
    let start = Instant::now();
    loop {
        let w = hub.hub().objects.writes.load(Relaxed);
        if w != last.0 {
            last = (w, Instant::now());
        } else if last.1.elapsed() > Duration::from_millis(800) {
            return;
        }
        assert!(start.elapsed() < Duration::from_secs(60), "background writes never settled");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn read_file(api: &Api, token: &str, project: &str, path: &str) -> Option<Vec<u8>> {
    let tip = api.tips(Some(token), project).unwrap().branches["main"];
    let h = api.history(token, project, &[tip]);
    let (_, raw) = h.frames().into_iter().find(|(id, _)| *id == tip).unwrap();
    let O::Snapshot(s) = O::decode(&raw).unwrap() else { panic!() };
    let mut id = s.tree;
    let mut at = String::new();
    for part in path.split('/') {
        let r = api.post_json(
            Some(token),
            &format!("/v1/projects/{project}/fetch"),
            &json!({"snapshot": tip.hex(), "objects": [{"path": at, "id": id.hex()}]}),
        );
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        let O::Tree(t) = O::decode(&r.frames()[0].1).unwrap() else { panic!("not a tree") };
        id = t.get(part)?.id;
        at = if at.is_empty() { part.to_string() } else { format!("{at}/{part}") };
    }
    let r = api.post_json(
        Some(token),
        &format!("/v1/projects/{project}/fetch"),
        &json!({"snapshot": tip.hex(), "objects": [{"path": at, "id": id.hex()}]}),
    );
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    match O::decode(&r.frames()[0].1).unwrap() {
        O::Blob(b) => Some(b),
        _ => panic!("not a file"),
    }
}

fn wait_landed(api: &Api, token: &str, project: &str, ticket: &str) {
    for _ in 0..600 {
        let r = api.get(Some(token), &format!("/v1/projects/{project}/land/{ticket}"));
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        let v = r.json();
        if v["state"] != "queued" && v["state"] != "merging" {
            assert_eq!(v["state"], "landed", "{v}");
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("ticket {ticket} still queued");
}

async fn is_yugabyte(db: &sqlx::PgPool) -> bool {
    let v: String = sqlx::query_scalar("SELECT version()").fetch_one(db).await.unwrap_or_default();
    v.contains("-YB-")
}

async fn wait_for_sql_lock(db: &sqlx::PgPool, query_like: &str, msg: &str) {
    if is_yugabyte(db).await {
        let end = Instant::now() + Duration::from_secs(5);
        while Instant::now() < end {
            let active: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND state = 'active' AND query LIKE $1",
            )
            .bind(query_like)
            .fetch_one(db)
            .await
            .unwrap_or(0);
            if active > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        tokio::time::sleep(Duration::from_millis(800)).await;
        return;
    }
    let until = Instant::now() + Duration::from_secs(30);
    loop {
        let waiting: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock' AND query LIKE $1",
        )
        .bind(query_like)
        .fetch_one(db)
        .await
        .unwrap_or(0);
        if waiting > 0 {
            return;
        }
        assert!(Instant::now() < until, "{msg}");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// Guarantee 1 (`object-layout.md` §8.1): a push keeps each object under its
/// key, lists no pack, and its container is gone (row and storage). Its
/// storage writes are exactly 1 + the objects kept, the same whether or not
/// the project already held them.
#[test]
fn guarantee_1_push_keeps_loose_lists_no_pack_purges_container_and_always_writes() {
    let hub = TestHub::start_objects();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let h = hub.hub();
    let store = hub.blob_store();
    settle(&hub);

    assert_eq!(pack_counts(&hub, pid), (0, 0, 0), "setup_project in objects mode leaves no pack rows");
    assert!(packs_in_store(&hub, pid).is_empty(), "setup_project in objects mode leaves no packs in storage");

    // `Craft::file` records intermediate trees when called multiple times; retain only the 5 objects
    // `s1` actually reaches (2 blobs, `src/` tree, root tree, `s1`), matching a real `vl push`.
    let keep_reachable = |c: &mut Craft<'_>, snap_id: ObjectId| {
        let map: std::collections::HashMap<ObjectId, Vec<u8>> = c.objects.iter().cloned().collect();
        let mut reach = HashSet::new();
        let mut stack = vec![snap_id];
        while let Some(id) = stack.pop() {
            if !reach.insert(id) {
                continue;
            }
            if let Some(raw) = map.get(&id) {
                match O::decode(raw).unwrap() {
                    O::Snapshot(s) => stack.push(s.tree),
                    O::Tree(t) => stack.extend(t.entries.iter().map(|e| e.id)),
                    _ => {}
                }
            }
        }
        c.objects.retain(|(id, _)| reach.contains(id));
    };

    // 1. Admin push of two new files: 0 server-made objects, every uploaded object is kept.
    let mut c1 = Craft::new(&api, &p.admin, &p.name, "main");
    c1.file("src/g1_a.rs", "MARKER-G1-FILE-A-9011\n");
    c1.file("src/g1_b.rs", "MARKER-G1-FILE-B-9012\n");
    let s1 = {
        let t = c1.tip;
        snap(&mut c1, vec![t], "g1 first push", None)
    };
    keep_reachable(&mut c1, s1);
    let unique_ids_1: HashSet<ObjectId> = c1.objects.iter().map(|(id, _)| *id).collect();
    assert_eq!(unique_ids_1.len(), 5);

    let own_0 = h.objects.own_writes.load(Relaxed);
    let kept_0 = h.objects.objects_kept.load(Relaxed);
    let uploads_0 = h.objects.uploads.load(Relaxed);
    let deletes_0 = h.objects.deletes.load(Relaxed);

    let (map1, container1) = upload_all(&api, &c1);
    let r1 = push_body(&api, &c1.token, &p.name, "main", Some(c1.tip), s1, &map1);
    assert_eq!(r1.status, 200, "{}", String::from_utf8_lossy(&r1.body));
    assert_eq!(r1.json()["results"][0]["ok"], json!(true), "{}", String::from_utf8_lossy(&r1.body));

    let k1 = unique_ids_1.len() as u64;
    assert_eq!(h.objects.uploads.load(Relaxed) - uploads_0, 1, "1 upload container");
    assert_eq!(h.objects.objects_kept.load(Relaxed) - kept_0, k1, "objects_kept equals unique kept objects");
    assert_eq!(
        h.objects.own_writes.load(Relaxed) - own_0,
        1 + k1,
        "push storage writes are exactly 1 (upload container) + kept objects"
    );
    assert_eq!(h.objects.deletes.load(Relaxed) - deletes_0, 1, "staged container deleted after commit");
    assert_eq!(pack_counts(&hub, pid), (0, 0, 0), "no staged, listed or discarded pack rows remain");
    assert!(!hub.rt.block_on(store.exists(&veil_server::pack::key(pid, &container1))).unwrap(), "container deleted from store");
    for id in &unique_ids_1 {
        assert!(
            hub.rt.block_on(store.exists(&veil_server::store::object_key(pid, id))).unwrap(),
            "kept object {id} stored under its own key"
        );
    }

    // 2. Second push whose blobs are ALREADY stored in the project (`g1_a.rs` and `g1_b.rs` copied to
    //    new paths and re-uploaded in the container): storage writes are STILL 1 + objects kept.
    settle(&hub);
    let mut c2 = Craft::new(&api, &p.admin, &p.name, "main");
    c2.file("src/g1_copy_a.rs", "MARKER-G1-FILE-A-9011\n");
    c2.file("src/g1_copy_b.rs", "MARKER-G1-FILE-B-9012\n");
    let s2 = {
        let t = c2.tip;
        snap(&mut c2, vec![t], "g1 duplicate blobs push", None)
    };
    keep_reachable(&mut c2, s2);
    let blob_a_id = blob("MARKER-G1-FILE-A-9011\n").0;
    let blob_b_id = blob("MARKER-G1-FILE-B-9012\n").0;
    assert!(hub.rt.block_on(store.exists(&veil_server::store::object_key(pid, &blob_a_id))).unwrap(), "already stored before push 2");
    assert!(hub.rt.block_on(store.exists(&veil_server::store::object_key(pid, &blob_b_id))).unwrap(), "already stored before push 2");
    let unique_ids_2: HashSet<ObjectId> = c2.objects.iter().map(|(id, _)| *id).collect();
    assert_eq!(unique_ids_2.len(), 5);

    let own_1 = h.objects.own_writes.load(Relaxed);
    let kept_1 = h.objects.objects_kept.load(Relaxed);
    let (map2, container2) = upload_all(&api, &c2);
    let r2 = push_body(&api, &c2.token, &p.name, "main", Some(c2.tip), s2, &map2);
    assert_eq!(r2.status, 200, "{}", String::from_utf8_lossy(&r2.body));
    assert_eq!(r2.json()["results"][0]["ok"], json!(true), "{}", String::from_utf8_lossy(&r2.body));

    let k2 = unique_ids_2.len() as u64;
    assert_eq!(h.objects.objects_kept.load(Relaxed) - kept_1, k2, "already-stored blobs still counted in objects_kept");
    assert_eq!(
        h.objects.own_writes.load(Relaxed) - own_1,
        1 + k2,
        "push writes are 1 + objects_kept even when objects are already stored"
    );
    assert_eq!(pack_counts(&hub, pid), (0, 0, 0));
    assert!(!hub.rt.block_on(store.exists(&veil_server::pack::key(pid, &container2))).unwrap());

    // 3. Restricted member push (`p.dev` cannot see billing -> server completes trees + snapshots):
    //    writes are still 1 + objects_kept, 0 packs listed, and a fresh server reads everything.
    settle(&hub);
    let mut c3 = Craft::new(&api, &p.dev, &p.name, "main");
    c3.file("src/g1_dev.rs", "MARKER-G1-DEV-9013\n");
    let s3 = {
        let t = c3.tip;
        snap(&mut c3, vec![t], "g1 dev push", None)
    };
    let own_2 = h.objects.own_writes.load(Relaxed);
    let kept_2 = h.objects.objects_kept.load(Relaxed);
    let (map3, container3) = upload_all(&api, &c3);
    let r3 = push_body(&api, &c3.token, &p.name, "main", Some(c3.tip), s3, &map3);
    assert_eq!(r3.status, 200, "{}", String::from_utf8_lossy(&r3.body));
    assert_eq!(r3.json()["results"][0]["ok"], json!(true), "{}", String::from_utf8_lossy(&r3.body));

    let k3 = h.objects.objects_kept.load(Relaxed) - kept_2;
    assert!(k3 > c3.objects.len() as u64, "completed push kept uploaded + server-made objects ({k3})");
    assert_eq!(h.objects.own_writes.load(Relaxed) - own_2, 1 + k3);
    assert_eq!(pack_counts(&hub, pid), (0, 0, 0));
    assert!(!hub.rt.block_on(store.exists(&veil_server::pack::key(pid, &container3))).unwrap());

    let other = TestHub::beside(&hub);
    let other_api = other.api();
    for (who, sees_billing) in [(&p.admin, true), (&p.fin, true), (&p.dev, false)] {
        let tok = who.token();
        assert_eq!(read_file(&other_api, &tok, &p.name, "src/g1_a.rs").as_deref(), Some(&b"MARKER-G1-FILE-A-9011\n"[..]));
        assert_eq!(read_file(&other_api, &tok, &p.name, "src/g1_copy_b.rs").as_deref(), Some(&b"MARKER-G1-FILE-B-9012\n"[..]));
        assert_eq!(read_file(&other_api, &tok, &p.name, "src/g1_dev.rs").as_deref(), Some(&b"MARKER-G1-DEV-9013\n"[..]));
        assert_eq!(read_file(&other_api, &tok, &p.name, &format!("{BILL_DIR}/acme/invoice.txt")).is_some(), sees_billing);
    }
}

/// Guarantee 2 (`object-layout.md` §8.1): a push refused for a plain-text
/// secret, or a path the pusher may not write, leaves nothing under any
/// project key, and its container is deleted (BUG-930's twin).
#[test]
fn guarantee_2_refused_push_leaves_no_project_key_and_deletes_container() {
    let hub = TestHub::start_objects();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let store = hub.blob_store();
    settle(&hub);

    let keys_before = loose_keys_in_store(&hub, pid);
    let tip_before = api.tips(Some(&p.dev.token()), &p.name).unwrap().branches["main"];

    // 1. Refused for a plain-text secret (.env / AWS key).
    let secret = "aws_access_key_id = AKIAR4T6EXAMPLEW8Y2Q\n";
    let mut c_sec = Craft::new(&api, &p.dev, &p.name, "main");
    c_sec.file("src/creds.txt", secret);
    let s_sec = {
        let t = c_sec.tip;
        snap(&mut c_sec, vec![t], "plain secret", None)
    };
    let (map_sec, pack_sec) = upload_all(&api, &c_sec);
    assert!(hub.rt.block_on(store.exists(&veil_server::pack::key(pid, &pack_sec))).unwrap(), "staged before push");
    let r_sec = push_body(&api, &c_sec.token, &p.name, "main", Some(c_sec.tip), s_sec, &map_sec);
    assert_eq!(r_sec.status, 403, "plain-text secret push must be refused 403: {}", String::from_utf8_lossy(&r_sec.body));
    assert!(!hub.rt.block_on(store.exists(&veil_server::pack::key(pid, &pack_sec))).unwrap(), "refused secret container deleted");
    assert!(hub.rt.block_on(hub.hub().objects.staged_index(pid, &pack_sec)).unwrap().is_none());
    for (id, _) in &c_sec.objects {
        assert!(!hub.rt.block_on(store.exists(&veil_server::store::object_key(pid, id))).unwrap(), "refused object {id} never written under project key");
    }
    assert_eq!(loose_keys_in_store(&hub, pid), keys_before, "no new loose key written on secret refusal");

    // 2. Refused for a path the pusher may not write (`PERSON_DIR` is readable/writable only as configured:
    //    `p.dev` may read `src/` and public files, not write `PERSON_DIR` or `BILL_DIR`).
    let mut c_forbid = Craft::new(&api, &p.dev, &p.name, "main");
    c_forbid.file(&format!("{PERSON_DIR}/forbid.txt"), "MARKER-FORBIDDEN-WRITE-9022\n");
    let s_forbid = {
        let t = c_forbid.tip;
        snap(&mut c_forbid, vec![t], "forbidden path", None)
    };
    let (map_forbid, pack_forbid) = upload_all(&api, &c_forbid);
    let r_forbid = push_body(&api, &c_forbid.token, &p.name, "main", Some(c_forbid.tip), s_forbid, &map_forbid);
    assert_eq!(r_forbid.status, 403, "unauthorized path push must be refused 403: {}", String::from_utf8_lossy(&r_forbid.body));
    assert!(!hub.rt.block_on(store.exists(&veil_server::pack::key(pid, &pack_forbid))).unwrap(), "refused path container deleted");
    for (id, _) in &c_forbid.objects {
        assert!(!hub.rt.block_on(store.exists(&veil_server::store::object_key(pid, id))).unwrap(), "refused object {id} never written under project key");
    }
    assert_eq!(loose_keys_in_store(&hub, pid), keys_before, "no new loose key written on unauthorized path refusal");
    assert_eq!(api.tips(Some(&p.dev.token()), &p.name).unwrap().branches["main"], tip_before);
}

/// Guarantee 3 (`object-layout.md` §8.1): an upload a landing push names and
/// never reads is not kept (threat 7 of §13.20).
#[test]
fn guarantee_3_unread_uploaded_object_beside_landing_push_is_not_kept() {
    let hub = TestHub::start_objects();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let store = hub.blob_store();

    let mut c = Craft::new(&api, &p.dev, &p.name, "main");
    c.file("src/g3_landed.rs", "MARKER-G3-LANDED-2b7e\n");
    let s = {
        let t = c.tip;
        snap(&mut c, vec![t], "landed beside unread secret", None)
    };
    let (unread_id, unread_raw) = blob("AWS_SECRET_ACCESS_KEY=MARKER-G3-UNREAD-PLAIN-SECRET-c4d9e1\n");
    c.objects.push((unread_id, unread_raw));
    let (map, container) = upload_all(&api, &c);
    assert!(map.contains_key(&unread_id.hex()), "push names the unread upload's receipt");

    let r = push_body(&api, &c.token, &p.name, "main", Some(c.tip), s, &map);
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["results"][0]["ok"], json!(true), "{}", String::from_utf8_lossy(&r.body));

    assert!(!hub.rt.block_on(store.exists(&veil_server::store::object_key(pid, &unread_id))).unwrap(), "unread upload is not written under any project key");
    assert!(!hub.rt.block_on(store.exists(&veil_server::pack::key(pid, &container))).unwrap(), "upload container is deleted");
    assert_eq!(pack_counts(&hub, pid), (0, 0, 0), "upload container row is deleted");

    let fresh = TestHub::beside(&hub);
    assert!(fresh.rt.block_on(fresh.hub().objects.get(pid, &unread_id)).unwrap().is_none());
    assert_eq!(
        read_file(&fresh.api(), &c.token, &p.name, "src/g3_landed.rs").as_deref(),
        Some(&b"MARKER-G3-LANDED-2b7e\n"[..])
    );
}

/// Guarantee 4 (`object-layout.md` §8.1): receipts hold only for their person
/// and their container; a discarded container's receipt is worth nothing
/// (BUG-1155's twin, a push and an API commit).
#[test]
fn guarantee_4_receipts_bound_to_person_and_container_and_discarded_worth_nothing() {
    let hub = TestHub::start_objects();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let dev_tok = p.dev.token();

    // 1. Receipt binding to person and container.
    let mut c = Craft::new(&api, &p.dev, &p.name, "main");
    c.file("src/g4_receipt.rs", "MARKER-G4-RECEIPT-5a1c\n");
    let s = {
        let t = c.tip;
        snap(&mut c, vec![t], "g4 receipts", None)
    };
    let (dev_map, _dev_container) = upload_all(&api, &c);
    let (carol_id, carol_raw) = blob("carol's own upload");
    let mut carol_body = Vec::new();
    put_frame(&mut carol_body, &carol_id, &carol_raw);
    let carol_up = api.upload_body(&p.carol.token(), &p.name, &carol_body);
    assert_eq!(carol_up.status, 200);
    let carol_receipts: Vec<String> = serde_json::from_value(carol_up.json()["receipts"].clone()).unwrap();
    let carol_container = carol_receipts[0].split_once('.').unwrap().1.to_string();

    let try_push = |tok: &str, f: &dyn Fn(&str) -> String| {
        let map: serde_json::Map<String, Value> = dev_map
            .iter()
            .map(|(k, v)| (k.clone(), json!(f(v.as_str().unwrap()))))
            .collect();
        push_body(&api, tok, &p.name, "main", Some(c.tip), s, &map)
    };
    let mac = |r: &str| r.split_once('.').unwrap().0.to_string();
    for (label, r) in [
        ("dev receipts shown by carol", try_push(&p.carol.token(), &|r| r.to_string())),
        ("moved to carol's container", try_push(&dev_tok, &|r| format!("{}.{carol_container}", mac(r)))),
        ("moved to nonexistent container", try_push(&dev_tok, &|r| format!("{}.{}", mac(r), "0".repeat(32)))),
        ("without container suffix", try_push(&dev_tok, &|r| mac(r))),
    ] {
        assert!(r.status == 400 || r.status == 404, "{label}: {} {}", r.status, String::from_utf8_lossy(&r.body));
    }

    // 2. BUG-1155's twin for push: guessing hidden billing content with a discarded container's receipt.
    let hidden_path = format!("{BILL_DIR}/acme/invoice.txt");
    let real_hidden_id = real_paths(&p.dir).into_iter().find(|(path, _)| *path == hidden_path).unwrap().1;
    let right_bytes = format!("{BILL_MARK}\nsecond").into_bytes();
    let wrong_bytes = b"MARKER-G4-WRONG-GUESS-PUSH-71c0".to_vec();
    let (rid, rraw) = (ObjectId::hash(&O::Blob(right_bytes.clone()).encode()), O::Blob(right_bytes.clone()).encode());
    let (wid, wraw) = (ObjectId::hash(&O::Blob(wrong_bytes.clone()).encode()), O::Blob(wrong_bytes.clone()).encode());
    assert_eq!(rid, real_hidden_id, "right guess matches hidden billing blob");

    let up_guess = api.upload(&dev_tok, &p.name, &[(rid, rraw.clone()), (wid, wraw.clone())]);
    assert_eq!(up_guess.status, 200);
    let g_receipts: Vec<String> = serde_json::from_value(up_guess.json()["receipts"].clone()).unwrap();
    let g_pack = g_receipts[0].split_once('.').unwrap().1.to_string();
    let tip = api.tips(Some(&dev_tok), &p.name).unwrap().branches["main"];
    let shown: serde_json::Map<String, Value> = [(rid.hex(), json!(g_receipts[0])), (wid.hex(), json!(g_receipts[1]))].into_iter().collect();
    let refused = push_body(&api, &dev_tok, &p.name, "main", Some(tip), ObjectId::hash(b"missing-snap"), &shown);
    assert_eq!(refused.status, 400, "{}", String::from_utf8_lossy(&refused.body));
    assert!(hub.rt.block_on(hub.hub().objects.staged_index(pid, &g_pack)).unwrap().is_none());

    let mut push_answers = Vec::new();
    for (id, content, receipt) in [(wid, &wrong_bytes, &g_receipts[1]), (rid, &right_bytes, &g_receipts[0])] {
        let mut cg = Craft::new(&api, &p.dev, &p.name, "main");
        cg.set("src/guess.txt", O::Blob(content.clone()), Visibility::Public);
        cg.objects.retain(|(o, _)| *o != id);
        let sg = {
            let t = cg.tip;
            snap(&mut cg, vec![t], "guess push", None)
        };
        let (mut map, _) = upload_all(&api, &cg);
        map.insert(id.hex(), json!(receipt));
        let r = push_body(&api, &cg.token, &p.name, "main", Some(cg.tip), sg, &map);
        let mut body_norm = String::from_utf8_lossy(&r.body).into_owned();
        for oid in cg.objects.iter().map(|(o, _)| *o).chain([id, sg]) {
            body_norm = body_norm.replace(&oid.hex(), "ID").replace(&oid.short(), "ID");
        }
        push_answers.push((r.status, body_norm));
    }
    assert!(push_answers[0].0 == 400 || push_answers[0].0 == 404, "wrong guess refused: {:?}", push_answers[0]);
    assert_eq!(push_answers[1], push_answers[0], "discarded receipt in push must not distinguish right vs wrong hidden guess");

    // 3. BUG-1155's twin for API commit (`POST /v1/projects/{p}/changes`).
    let up_api = api.upload(&dev_tok, &p.name, &[(rid, rraw), (wid, wraw)]);
    assert_eq!(up_api.status, 200);
    let api_receipts: Vec<String> = serde_json::from_value(up_api.json()["receipts"].clone()).unwrap();
    let base = api.tips(Some(&dev_tok), &p.name).unwrap().branches["main"];
    let both: serde_json::Map<String, Value> = [(rid.hex(), json!(api_receipts[0])), (wid.hex(), json!(api_receipts[1]))].into_iter().collect();
    let refused_api = api.post_json(
        Some(&dev_tok),
        &format!("/v1/projects/{}/changes", p.name),
        &json!({"base": base.hex(), "edits": [{"path": format!("{BILL_DIR}/x.txt"), "put": {"object": rid.hex()}}], "receipts": both}),
    );
    assert!(refused_api.status == 403 || refused_api.status == 400, "{}: {}", refused_api.status, String::from_utf8_lossy(&refused_api.body));

    let mut api_answers = Vec::new();
    for (id, receipt) in [(wid, &api_receipts[1]), (rid, &api_receipts[0])] {
        let r = api.post_json(
            Some(&dev_tok),
            &format!("/v1/projects/{}/changes", p.name),
            &json!({"base": base.hex(), "edits": [{"path": "src/guess.txt", "put": {"object": id.hex()}}], "receipts": {id.hex(): receipt}}),
        );
        let norm = String::from_utf8_lossy(&r.body).replace(&id.hex(), "ID").replace(&id.short(), "ID");
        api_answers.push((r.status, norm));
    }
    assert!(api_answers[0].0 == 400 || api_answers[0].0 == 404, "wrong guess refused in API commit: {:?}", api_answers[0]);
    assert_eq!(api_answers[1], api_answers[0], "discarded receipt in API commit must not distinguish right vs wrong hidden guess");
}

/// Guarantee 5 (`object-layout.md` §8.1): a push that lost a race pushes again
/// with the same receipts and no new upload (BUG-1157's twin).
#[test]
fn guarantee_5_race_loser_retries_with_same_receipts_and_no_new_upload() {
    let hub = TestHub::start_objects();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let h = hub.hub();
    settle(&hub);

    let mut c = Craft::new(&api, &p.dev, &p.name, "main");
    let blob_text = "MARKER-G5-RACED-UPLOAD-61aa\n";
    c.file("src/g5_raced.rs", blob_text);
    let s1 = {
        let t = c.tip;
        snap(&mut c, vec![t], "g5 raced", None)
    };
    let (map, container) = upload_all(&api, &c);

    // Admin advances `main` first, so `c`'s push on `c.tip` loses its race.
    write_files(&p.dir, &[("src/g5_first.rs", "admin first\n")]);
    p.admin.commit_main(&p.dir, "admin first");
    p.admin.ok(&p.dir, &["push"]);
    settle(&hub);

    let uploads_before = h.objects.uploads.load(Relaxed);
    let writes_before = h.objects.own_writes.load(Relaxed);

    // Losing push: leaves the container STAGED and writes nothing.
    let r_lost = push_body(&api, &c.token, &p.name, "main", Some(c.tip), s1, &map);
    assert_eq!(r_lost.status, 200, "{}", String::from_utf8_lossy(&r_lost.body));
    assert_eq!(r_lost.json()["results"][0]["ok"], json!(false), "{}", String::from_utf8_lossy(&r_lost.body));
    assert_eq!(h.objects.own_writes.load(Relaxed) - writes_before, 0, "lost race writes nothing");
    assert_eq!(pack_counts(&hub, pid), (1, 0, 0), "upload container remains staged after lost race");

    // Re-uploading the identical objects (`vl`'s retry) hits `staged_holding` with 0 new uploads or writes.
    let (map_again, container_again) = upload_all(&api, &c);
    assert_eq!(container_again, container, "re-upload reuses staged container");
    assert_eq!(map_again, map);
    assert_eq!(h.objects.uploads.load(Relaxed) - uploads_before, 0, "no new upload container created");
    assert_eq!(h.objects.own_writes.load(Relaxed) - writes_before, 0, "no storage write for deduplicated re-upload");

    // Pushing again with the exact same `map` and literally ZERO upload requests (creating `dev/g5`
    // at `s1`) lands cleanly, keeps the loose objects, and purges the staged container.
    let r_land = push_body(&api, &c.token, &p.name, "dev/g5", None, s1, &map);
    assert_eq!(r_land.status, 200, "{}", String::from_utf8_lossy(&r_land.body));
    assert_eq!(r_land.json()["results"][0]["ok"], json!(true), "{}", String::from_utf8_lossy(&r_land.body));
    assert_eq!(h.objects.uploads.load(Relaxed) - uploads_before, 0, "landed with zero new upload requests");
    assert_eq!(pack_counts(&hub, pid), (0, 0, 0), "staged container purged once retry lands");
    assert!(!hub.rt.block_on(hub.blob_store().exists(&veil_server::pack::key(pid, &container))).unwrap());

    let f = api.get(Some(&c.token), &format!("/v1/projects/{}/q/file?rev=dev/g5&path=src/g5_raced.rs", p.name));
    assert_eq!((f.status, String::from_utf8_lossy(&f.body).to_string()), (200, blob_text.to_string()));
}

/// Guarantee 6 (`object-layout.md` §8.1): two servers on one database and
/// store, one `packs`, one `objects`: each reads what the other pushed, on
/// every read (`get`, `get_many`, `get_range`, `fetch`), and after each
/// restarts with the other setting.
#[test]
fn guarantee_6_mixed_packs_and_objects_servers_read_every_way_and_after_swapping_layouts() {
    let hub_packs = TestHub::start_with_layout(ObjectLayout::Packs);
    let hub_objs = TestHub::beside_with_layout(&hub_packs, ObjectLayout::Objects);
    let p = setup_project(&hub_packs);
    let pid = project_id(&hub_packs, &p.name);

    // Push A through the `packs` server (stored in a listed pack, not loose).
    let (id_a1, raw_a1) = plain_blob(0x1234_5678_9abc_def0, "PACKS-SERVER-A1:");
    let (id_a2, raw_a2) = plain_blob(0x0fed_cba9_8765_4321, "PACKS-SERVER-A2:");
    {
        let api_p = hub_packs.api();
        let mut ca = Craft::new(&api_p, &p.admin, &p.name, "main");
        let O::Blob(b1) = O::decode(&raw_a1).unwrap() else { unreachable!() };
        let O::Blob(b2) = O::decode(&raw_a2).unwrap() else { unreachable!() };
        ca.set("src/from_packs_1.bin", O::Blob(b1), Visibility::Public);
        ca.set("src/from_packs_2.bin", O::Blob(b2), Visibility::Public);
        let ra = ca.push("main", "pushed on packs server");
        assert_eq!(ra.status, 200, "{}", String::from_utf8_lossy(&ra.body));
        assert_eq!(ra.json()["results"][0]["ok"], json!(true));
    }
    assert!(!hub_packs.rt.block_on(hub_packs.blob_store().exists(&veil_server::store::object_key(pid, &id_a1))).unwrap(), "id_a1 is in a pack, not loose");

    // Push B through the `objects` server (stored loose, lists no new pack, leaves `packs` server's listed packs untouched).
    let listed_after_a = pack_counts(&hub_packs, pid).1;
    let (id_b1, raw_b1) = plain_blob(0xaaaa_bbbb_cccc_dddd, "OBJECTS-SERVER-B1:");
    let (id_b2, raw_b2) = plain_blob(0x1122_3344_5566_7788, "OBJECTS-SERVER-B2:");
    {
        let api_o = hub_objs.api();
        let mut cb = Craft::new(&api_o, &p.admin, &p.name, "main");
        let O::Blob(b1) = O::decode(&raw_b1).unwrap() else { unreachable!() };
        let O::Blob(b2) = O::decode(&raw_b2).unwrap() else { unreachable!() };
        cb.set("src/from_objs_1.bin", O::Blob(b1), Visibility::Public);
        cb.set("src/from_objs_2.bin", O::Blob(b2), Visibility::Public);
        let rb = cb.push("main", "pushed on objects server");
        assert_eq!(rb.status, 200, "{}", String::from_utf8_lossy(&rb.body));
        assert_eq!(rb.json()["results"][0]["ok"], json!(true));
    }
    assert_eq!(pack_counts(&hub_objs, pid).1, listed_after_a, "objects server kept existing listed packs and listed no new pack");
    assert!(hub_objs.rt.block_on(hub_objs.blob_store().exists(&veil_server::store::object_key(pid, &id_b1))).unwrap(), "id_b1 is stored loose");

    let items = [
        ("src/from_packs_1.bin", id_a1, &raw_a1),
        ("src/from_packs_2.bin", id_a2, &raw_a2),
        ("src/from_objs_1.bin", id_b1, &raw_b1),
        ("src/from_objs_2.bin", id_b2, &raw_b2),
    ];

    let check_all_reads = |srv: &TestHub, token: &str, label: &str| {
        let h = srv.hub();
        let api = srv.api();
        let tip = api.tips(Some(token), &p.name).unwrap().branches["main"];

        // Also check through a cold `Objects` on the same DB + store so in-memory caches never mask a broken lookup.
        let cold = veil_server::store::Objects::with_layout(
            srv.blob_store(),
            1 << 20,
            Some(h.db.clone()),
            h.objects.layout(),
        );
        for obj_store in [&*h.objects, &cold] {
            // 1. `get`
            for (path, id, raw) in &items {
                let got = srv.rt.block_on(obj_store.get(pid, id)).unwrap().unwrap_or_else(|| panic!("{label}: get missing {path}"));
                assert_eq!(&got[..], &raw[..], "{label}: get mismatch for {path}");
            }
            // 2. `get_many`
            let ids: Vec<ObjectId> = items.iter().map(|(_, id, _)| *id).collect();
            let many = srv.rt.block_on(obj_store.get_many(pid, &ids)).unwrap();
            for ((path, _, raw), got) in items.iter().zip(many) {
                assert_eq!(got.unwrap().as_ref(), raw.as_slice(), "{label}: get_many mismatch for {path}");
            }
            // 3. `get_range`
            for (path, id, raw) in &items {
                let (slice, total) = srv
                    .rt
                    .block_on(obj_store.get_range(pid, id, 12, 60))
                    .unwrap()
                    .unwrap_or_else(|| panic!("{label}: get_range missing {path}"));
                assert_eq!(total, raw.len() as u64, "{label}: get_range total len for {path}");
                assert_eq!(&slice[..], &raw[12..=60], "{label}: get_range bytes for {path}");
            }
        }
        // 4. `fetch`
        let fetch_objs: Vec<Value> = items.iter().map(|(path, id, _)| json!({"path": path, "id": id.hex()})).collect();
        let rf = api.post_json(
            Some(token),
            &format!("/v1/projects/{}/fetch", p.name),
            &json!({"snapshot": tip.hex(), "objects": fetch_objs}),
        );
        assert_eq!(rf.status, 200, "{label}: fetch failed: {}", String::from_utf8_lossy(&rf.body));
        let frames = rf.frames();
        assert_eq!(frames.len(), items.len(), "{label}: fetch frame count");
        for ((path, id, raw), (fid, fraw)) in items.iter().zip(frames) {
            assert_eq!(&fid, id, "{label}: fetch id for {path}");
            assert_eq!(&fraw, *raw, "{label}: fetch bytes for {path}");
        }
    };

    let tok = p.dev.token();
    check_all_reads(&hub_packs, &tok, "before swap: packs server");
    check_all_reads(&hub_objs, &tok, "before swap: objects server");

    // Restart each server with the OTHER layout setting.
    let hub_now_objs = hub_packs.restart_with_layout(ObjectLayout::Objects, |_| {});
    let hub_now_packs = hub_objs.restart_with_layout(ObjectLayout::Packs, |_| {});
    assert_eq!(veil_server::stats_json(&hub_now_objs.hub(), 0)["object_layout"], json!("objects"));
    assert_eq!(veil_server::stats_json(&hub_now_packs.hub(), 0)["object_layout"], json!("packs"));

    check_all_reads(&hub_now_objs, &tok, "after swap: server switched packs -> objects");
    check_all_reads(&hub_now_packs, &tok, "after swap: server switched objects -> packs");
}

/// Guarantee 7 (`object-layout.md` §8.1): a push whose object GC deletes
/// between its write and its commit runs again and stores it again; the landed
/// tip reads whole (the push's twin of BUG-2621's test).
#[test]
fn guarantee_7_push_whose_object_gc_deletes_between_write_and_commit_retries_and_stores_again() {
    const CONTENT: &str = "MARKER-G7-PUSH-DURING-GC-DELETE-0e7a\n";
    let th = TestHub::start_objects();
    let p = setup_project(&th);
    let pid = project_id(&th, &p.name);
    let api = th.api();
    let admin_tok = p.admin.token();
    let h = th.hub();
    settle(&th);

    let (victim_id, victim_raw) = blob(CONTENT);
    th.rt.block_on(h.objects.put(pid, &victim_id, Bytes::from(victim_raw))).unwrap();
    let marked = gc_pass(
        &th,
        pid,
        &Options {
            min_packs_to_merge: 99,
            run_gc: true,
            retention_window_ms: 60_000,
            ..Options::default()
        },
    );
    assert!(!marked.skipped, "marking pass ran");

    let answer: Arc<std::sync::Mutex<Option<std::sync::mpsc::Receiver<Reply>>>> = Arc::default();
    let kept_before_push = Arc::new(AtomicUsize::new(0));
    let push_obj_count = Arc::new(AtomicUsize::new(0));

    let fault = {
        let (db, h2, answer) = (h.db.clone(), h.clone(), answer.clone());
        let (kept_before_push, push_obj_count) = (kept_before_push.clone(), push_obj_count.clone());
        let (authority, cert, tok, name, identity) = (
            th.authority(),
            th.cert_pem.clone(),
            admin_tok.clone(),
            p.name.clone(),
            p.admin.identity(),
        );
        Fault(Arc::new(move |at, id| {
            let (db, h2, answer) = (db.clone(), h2.clone(), answer.clone());
            let (kept_before_push, push_obj_count) = (kept_before_push.clone(), push_obj_count.clone());
            let (authority, cert, tok, name, identity) = (
                authority.clone(),
                cert.clone(),
                tok.clone(),
                name.clone(),
                identity.clone(),
            );
            Box::pin(async move {
                if at == FaultPoint::LooseDelete && id == victim_id {
                    let api_in = Api::at(&authority, &cert);
                    let mut c = Craft::with(&api_in, tok.clone(), identity, &name, "main");
                    c.file("src/g7_reborn.txt", CONTENT);
                    let s = {
                        let t = c.tip;
                        snap(&mut c, vec![t], "g7 push racing loose delete", None)
                    };
                    let n_objs = c.objects.len();
                    push_obj_count.store(n_objs, Relaxed);
                    let (map, _) = upload_all(&api_in, &c);
                    let tip = c.tip;
                    let kb = h2.objects.objects_kept.load(Relaxed) as usize;
                    kept_before_push.store(kb, Relaxed);

                    let (tx, rx) = std::sync::mpsc::channel::<Reply>();
                    std::thread::spawn(move || {
                        let r = push_body(&api_in, &tok, &name, "main", Some(tip), s, &map);
                        let _ = tx.send(r);
                    });
                    *answer.lock().unwrap() = Some(rx);

                    // Wait until the push has completed `Objects::keep` (written `victim_id`!) and
                    // is blocked at `guard_root_write` behind GC's exclusive gate.
                    let deadline = Instant::now() + Duration::from_secs(30);
                    while (h2.objects.objects_kept.load(Relaxed) as usize) < kb + n_objs {
                        assert!(Instant::now() < deadline, "push never finished first Objects::keep");
                        tokio::time::sleep(Duration::from_millis(15)).await;
                    }
                    wait_for_sql_lock(
                        &db,
                        "SELECT e.epoch FROM (SELECT pg_advisory_xact_lock_shared%",
                        "push never reached guard_root_write",
                    )
                    .await;
                }
                Ok(())
            })
        }))
    };

    let rep = th
        .rt
        .block_on(pack_gc::run_project(
            &h,
            pid,
            &Options {
                min_packs_to_merge: 99,
                run_gc: true,
                retention_window_ms: 60_000,
                pack_grace_ms: 0,
                now_offset_ms: 120_000,
                fault: Some(fault),
                ..Options::default()
            },
        ))
        .expect("GC pass with racing push succeeded");
    assert!(!rep.skipped, "GC pass ran: {rep:?}");
    assert!(rep.loose_objects_deleted >= 1, "GC deleted victim_id between push's first write and commit: {rep:?}");

    let rx = answer.lock().unwrap().take().expect("push started during LooseDelete");
    let r = rx.recv_timeout(Duration::from_secs(60)).expect("push answered after retry");
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["results"][0]["ok"], json!(true), "{}", String::from_utf8_lossy(&r.body));

    let kb = kept_before_push.load(Relaxed) as u64;
    let n_objs = push_obj_count.load(Relaxed) as u64;
    assert!(
        h.objects.objects_kept.load(Relaxed) >= kb + 2 * n_objs,
        "push ran Objects::keep a second time on GcMoved retry and stored every object again"
    );
    assert_eq!(pack_counts(&th, pid), (0, 0, 0), "staged container kept across retry, then purged after commit");

    // Verify in the raw blob store and from a second server with empty caches.
    assert!(
        th.rt.block_on(th.blob_store().exists(&veil_server::store::object_key(pid, &victim_id))).unwrap(),
        "victim_id was written again by the push retry"
    );
    let tip = api.tips(Some(&admin_tok), &p.name).unwrap().branches["main"];
    assert!(whole_tree_beside(&th, pid, tip) >= 2, "landed tip reads whole from a fresh server");
    let f = api.get(Some(&admin_tok), &format!("/v1/projects/{}/q/file?rev={}&path=src/g7_reborn.txt", p.name, tip.hex()));
    assert_eq!((f.status, String::from_utf8_lossy(&f.body).to_string()), (200, CONTENT.to_string()));
}

/// Guarantee 8 (`object-layout.md` §8.1): object routes over loose objects
/// serve only what a grant reaches; a stored, unreferenced object, a hidden
/// reachable one and a random id get byte-identical answers.
#[test]
fn guarantee_8_object_routes_over_loose_objects_enforce_grants_and_indistinguishable_refusals() {
    let hub = TestHub::start_objects();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let store = hub.blob_store();

    // Push a >64-byte plain blob visible to `p.dev` so we also test ranged GET on loose objects.
    let (vis_id, vis_raw) = plain_blob(0x7788_99aa_bbcc_ddee, "VISIBLE-LOOSE-G8:");
    {
        let mut c = Craft::new(&api, &p.admin, &p.name, "main");
        let O::Blob(b) = O::decode(&vis_raw).unwrap() else { unreachable!() };
        c.set("src/g8_visible.bin", O::Blob(b), Visibility::Public);
        let r = c.push("main", "g8 visible");
        assert_eq!(r.status, 200);
        assert_eq!(r.json()["results"][0]["ok"], json!(true));
    }
    assert_eq!(pack_counts(&hub, pid), (0, 0, 0), "all project objects are loose");

    // 1. A stored, unreferenced loose object.
    let (unref_id, unref_raw) = plain_blob(0xdead_beef_cafe_f00d, "UNREFERENCED-LOOSE-G8:");
    hub.rt.block_on(hub.hub().objects.put(pid, &unref_id, Bytes::from(unref_raw))).unwrap();
    assert!(hub.rt.block_on(store.exists(&veil_server::store::object_key(pid, &unref_id))).unwrap());

    // 2. A hidden reachable loose object (`billing/acme/invoice.txt`) and the admin's real root tree.
    let hidden_path = format!("{BILL_DIR}/acme/invoice.txt");
    let hidden_id = real_paths(&p.dir).into_iter().find(|(path, _)| *path == hidden_path).unwrap().1;
    assert!(hub.rt.block_on(store.exists(&veil_server::store::object_key(pid, &hidden_id))).unwrap());
    let admin_tips = api.tips(Some(&p.admin.token()), &p.name).unwrap();
    let admin_root = Grant::read_unverified(admin_tips.grants.get("main").unwrap()).unwrap().root;

    // 3. A random id not in storage.
    let rand_id = ObjectId(veil_core::crypto::random_bytes());
    assert!(!hub.rt.block_on(store.exists(&veil_server::store::object_key(pid, &rand_id))).unwrap());

    // Build `p.dev`'s grant reader.
    let dev_tok = p.dev.token();
    let dev_id = p.dev.identity();
    let dev_tips = api.tips(Some(&dev_tok), &p.name).unwrap();
    let grant_str = dev_tips.grants.get("main").unwrap().clone();
    let grant_key = dev_tips.grant_key.unwrap();
    let verified = Grant::verify(&grant_str, &grant_key).unwrap();
    let dev_root = verified.body.root;

    let get_obj = |chain: &[ObjectId], id: &ObjectId, extra: &[(&str, &str)]| -> Reply {
        let ts = veil_core::now_millis();
        let sig = format!("{ts}.{}", sign_request(&dev_id, &verified, ts, &[*id]));
        let chain_hdr = chain.iter().map(ObjectId::hex).collect::<Vec<_>>().join(",");
        let mut h = vec![
            ("veil-grant", grant_str.as_str()),
            ("veil-chain", chain_hdr.as_str()),
            ("veil-signature", sig.as_str()),
        ];
        h.extend_from_slice(extra);
        api.get_with(&format!("/v1/objects/{}/{}", p.name, id.hex()), &h)
    };
    let post_batch = |wants: &[(Vec<ObjectId>, ObjectId)]| -> Reply {
        let ids: Vec<ObjectId> = wants.iter().map(|(_, id)| *id).collect();
        let ts = veil_core::now_millis();
        let req = BatchRequest {
            grant: grant_str.clone(),
            ts,
            signature: Some(sign_request(&dev_id, &verified, ts, &ids)),
            wants: wants.iter().map(|(c, id)| ChainWant { chain: c.clone(), id: *id }).collect(),
            skip: Vec::new(),
        };
        api.post(None, &format!("/v1/objects/{}:batch", p.name), &serde_json::to_vec(&req).unwrap(), true)
    };

    // Walk `dev_root` to find `src` tree and serve `vis_id` over both `:batch`, `GET` and ranged `GET`.
    let root_reply = get_obj(&[], &dev_root, &[]);
    assert_eq!(root_reply.status, 200);
    let O::Tree(root_tree) = O::decode(&root_reply.body).unwrap() else { panic!("root is tree") };
    let src_id = root_tree.get("src").unwrap().id;
    let vis_chain = vec![dev_root, src_id];

    let vis_get = get_obj(&vis_chain, &vis_id, &[]);
    assert_eq!((vis_get.status, &vis_get.body), (200, &vis_raw));
    let vis_range = get_obj(&vis_chain, &vis_id, &[("range", "bytes=10-49")]);
    assert_eq!(vis_range.status, 206);
    assert_eq!(&vis_range.body[..], &vis_raw[10..=49]);
    let vis_batch = post_batch(&[(vis_chain.clone(), vis_id)]);
    assert_eq!(vis_batch.frames(), vec![(vis_id, vis_raw.clone())]);

    // Indistinguishability: `unref_id` (stored, unreferenced), `hidden_id` (stored, reachable for admin,
    // hidden from dev), `admin_root`, and `rand_id` (absent) must produce byte-identical answers on
    // whole GET, ranged GET, and `:batch` across every candidate chain!
    for chain in [Vec::new(), vec![dev_root], vis_chain] {
        let ref_whole = get_obj(&chain, &rand_id, &[]);
        assert_eq!(ref_whole.status, 404);
        let ref_range = get_obj(&chain, &rand_id, &[("range", "bytes=0-15")]);
        assert_eq!(ref_range.status, 404);
        let ref_batch = post_batch(&[(chain.clone(), rand_id)]);
        assert_eq!(ref_batch.status, 200);
        assert!(ref_batch.frames().is_empty());

        for probe in [unref_id, hidden_id, admin_root] {
            let gw = get_obj(&chain, &probe, &[]);
            assert_eq!((gw.status, &gw.body), (ref_whole.status, &ref_whole.body), "GET {probe} differed from random id");
            let gr = get_obj(&chain, &probe, &[("range", "bytes=0-15")]);
            assert_eq!((gr.status, &gr.body), (ref_range.status, &ref_range.body), "ranged GET {probe} differed from random id");
            let gb = post_batch(&[(chain.clone(), probe)]);
            assert_eq!((gb.status, &gb.body), (ref_batch.status, &ref_batch.body), "batch {probe} differed from random id");
        }
    }
}

/// Guarantee 9 (`object-layout.md` §8.1): a landing batch keeps its objects
/// under their keys; a batch that does not commit leaves only unreferenced
/// objects, which a pass collects after the retention window.
#[test]
fn guarantee_9_landing_batch_keeps_loose_and_failed_batch_leaves_only_collectible_unreferenced() {
    let hub = TestHub::start_objects();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let dev = p.dev.token();
    let h = hub.hub();
    let store = hub.blob_store();
    settle(&hub);

    // 1. A landing batch that commits keeps every object under its own key and lists no pack.
    let base1 = api.tips(Some(&dev), &p.name).unwrap().branches["main"];
    hold_branch(&hub, pid, "main");
    let mut tickets1 = Vec::new();
    for i in 0..4 {
        let r = land_edit(&api, &dev, &p.name, base1, &format!("src/g9_ok{i}/f.rs"), &format!("g9 ok {i}\n"), false);
        assert_eq!(r.status, 200, "submit {i}: {}", String::from_utf8_lossy(&r.body));
        tickets1.push(r.json()["ticket"].as_str().unwrap().to_string());
    }
    release_branch(&hub, pid, "main");
    for t in &tickets1 {
        wait_landed(&api, &dev, &p.name, t);
    }
    let tip1 = api.tips(Some(&dev), &p.name).unwrap().branches["main"];
    assert_ne!(tip1, base1);
    assert_eq!(pack_counts(&hub, pid), (0, 0, 0), "landing batch in objects mode creates no pack rows");
    assert!(packs_in(&hub, pid, 1).is_empty());
    assert!(hub.rt.block_on(store.exists(&veil_server::store::object_key(pid, &tip1))).unwrap(), "landed tip stored loose under its key");
    assert!(whole_tree_beside(&hub, pid, tip1) >= 6);

    // 2. A landing batch that does not commit: hold the GC epoch row while the batch writes its
    //    objects, cancel `tickets2[0]` and bump the epoch so attempt 1 rolls back and attempt 2
    //    lands only `tickets2[1..3]`. Attempt 1's `[0+1, 0+1+2]` trees/snapshots/projections are
    //    left unreferenced in storage, kept inside the retention window, and collected after it.
    settle(&hub);
    let base2 = api.tips(Some(&dev), &p.name).unwrap().branches["main"];
    hold_branch(&hub, pid, "main");
    let mut tickets2 = Vec::new();
    for i in 0..3 {
        let r = land_edit(&api, &dev, &p.name, base2, &format!("src/g9_lost{i}/f.rs"), &format!("g9 lost {i}\n"), false);
        assert_eq!(r.status, 200, "submit {i}: {}", String::from_utf8_lossy(&r.body));
        tickets2.push(r.json()["ticket"].as_str().unwrap().to_string());
    }
    let keys_before = loose_keys_in_store(&hub, pid);
    let kept_before = h.objects.objects_kept.load(Relaxed);

    let mut switch = hub.rt.block_on(h.db.begin()).unwrap();
    let epoch: i64 = hub
        .rt
        .block_on(
            sqlx::query_scalar("SELECT epoch FROM access_epochs WHERE project_id = $1 AND person_id = -1 FOR UPDATE")
                .bind(pid)
                .fetch_one(&mut *switch),
        )
        .unwrap();
    release_branch(&hub, pid, "main");

    // Wait until the batch has written its loose objects (`Objects::keep` finished) while its tx waits on `switch`.
    let deadline = Instant::now() + Duration::from_secs(30);
    while h.objects.objects_kept.load(Relaxed) == kept_before {
        assert!(Instant::now() < deadline, "landing batch never wrote its loose objects");
        std::thread::sleep(Duration::from_millis(25));
    }
    wait_for_sql_keys_settled(&hub, pid);
    let keys_after_failed_attempt = loose_keys_in_store(&hub, pid);
    let attempt1_written: HashSet<String> = keys_after_failed_attempt.difference(&keys_before).cloned().collect();
    assert!(!attempt1_written.is_empty(), "failed batch attempt wrote loose objects before committing");
    assert_eq!(api.tips(Some(&dev), &p.name).unwrap().branches["main"], base2, "nothing landed while tx waited");

    // Cancel `tickets2[0]` and bump GC epoch so attempt 1 aborts and attempt 2 builds a batch without `tickets2[0]`.
    hub.rt
        .block_on(async {
            sqlx::query("UPDATE landing_queue SET state = 'cancelled', done_at = $3 WHERE project_id = $1 AND ticket = $2")
                .bind(pid)
                .bind(&tickets2[0])
                .bind(veil_core::now_millis())
                .execute(&mut *switch)
                .await?;
            sqlx::query("UPDATE access_epochs SET epoch = $2 WHERE project_id = $1 AND person_id = -1")
                .bind(pid)
                .bind(epoch + 1)
                .execute(&mut *switch)
                .await?;
            switch.commit().await
        })
        .unwrap();

    for t in &tickets2[1..] {
        wait_landed(&api, &dev, &p.name, t);
    }
    settle(&hub);
    let tip2 = api.tips(Some(&dev), &p.name).unwrap().branches["main"];
    assert_ne!(tip2, base2);

    // Run GC pass 1 inside retention window (`now_offset_ms = 0`): nothing collected yet, marks unreferenced objects.
    let rep_in_win = gc_pass(
        &hub,
        pid,
        &Options {
            min_packs_to_merge: 99,
            run_gc: true,
            retention_window_ms: 60_000,
            now_offset_ms: 0,
            ..Options::default()
        },
    );
    assert_eq!(rep_in_win.loose_objects_deleted, 0, "nothing deleted inside retention window");
    for k in &attempt1_written {
        assert!(hub.rt.block_on(store.exists(k)).unwrap(), "unreferenced batch object {k} retained inside window");
    }

    // Run GC pass 2 past retention window (`now_offset_ms = 120_000`): failed batch's unreferenced objects are collected!
    let rep_past = gc_pass(
        &hub,
        pid,
        &Options {
            min_packs_to_merge: 99,
            run_gc: true,
            retention_window_ms: 60_000,
            pack_grace_ms: 0,
            now_offset_ms: 120_000,
            ..Options::default()
        },
    );
    assert!(rep_past.loose_objects_deleted >= 1, "failed batch's unreferenced objects collected: {rep_past:?}");
    let keys_after_gc = loose_keys_in_store(&hub, pid);
    let collected: Vec<_> = attempt1_written.difference(&keys_after_gc).collect();
    assert!(!collected.is_empty(), "attempt 1's orphaned trees/snapshots were deleted by GC");

    // Landed `[1, 2]` still read whole!
    assert!(whole_tree_beside(&hub, pid, tip2) >= 5);
    for i in 1..3 {
        let f = api.get(Some(&dev), &format!("/v1/projects/{}/q/file?rev={}&path=src/g9_lost{i}/f.rs", p.name, tip2.hex()));
        assert_eq!((f.status, String::from_utf8_lossy(&f.body).to_string()), (200, format!("g9 lost {i}\n")));
    }
}

fn wait_for_sql_keys_settled(hub: &TestHub, pid: i64) {
    let mut last = loose_keys_in_store(hub, pid).len();
    for _ in 0..20 {
        std::thread::sleep(Duration::from_millis(25));
        let now = loose_keys_in_store(hub, pid).len();
        if now == last {
            return;
        }
        last = now;
    }
}

/// Guarantee 10 (`object-layout.md` §8.1): a server stopped between a push's
/// writes and its commit: after a restart nothing reachable is missing, the
/// container is still staged for the retry, and a pass collects the rest
/// after the window. An embargo's hidden line is never collected.
#[test]
fn guarantee_10_stop_between_push_writes_and_commit_keeps_staged_collects_orphans_and_preserves_embargo() {
    let hub = TestHub::start_own_objects();
    let p = setup_project(&hub);
    p.admin.ok(&p.dir, &["group", "add", "devs", &p.sec.name]);
    let pid = project_id(&hub, &p.name);

    // 1. Push an embargoed fix on a hidden `embargo/<id>` line (`p.sec`).
    let eid = "e10a20b30c";
    let emb_content = "MARKER-G10-EMBARGO-PATCH-9100\n";
    let emb_blob_id = blob(emb_content).0;
    {
        let api = hub.api();
        let mut ce = Craft::new(&api, &p.sec, &p.name, "main");
        let base = ce.tip;
        ce.file("src/g10_vuln.rs", emb_content);
        let fix_id = snap(&mut ce, vec![base], "g10 embargo fix", None);
        let mut mrg = Snapshot {
            parents: vec![base, fix_id],
            change_id: ChangeId::random(),
            tree: ce.root,
            description: Text::Plain("g10 embargo merge".into()),
            author: p.sec.name.clone(),
            timestamp: veil_core::now_millis(),
            predecessors: vec![],
            conflicts: vec![],
            embargo: Some(eid.to_string()),
            signature: None,
            agent: None,
            attempts: vec![],
            abandoned: None,
        };
        mrg.sign(&ce.identity);
        let mrg_id = ce.put(O::Snapshot(mrg));
        let (emap, _) = upload_all(&api, &ce);
        let rec = veil_core::keychain::EmbargoRecord {
            format: veil_core::keychain::EMBARGO_FORMAT,
            id: eid.to_string(),
            scope: "security".to_string(),
            until: Some(veil_core::now_millis() + 3_600_000),
            created: veil_core::now_millis(),
            released_at: None,
            state: None,
            reason: None,
        };
        let r = api.post_json(
            Some(&ce.token),
            &format!("/v1/projects/{}/push", p.name),
            &json!({
                "updates": [{"branch": "main", "expected": base.hex(), "new": mrg_id.hex()}],
                "receipts": emap,
                "embargoes": [rec],
            }),
        );
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        assert_eq!(r.json()["results"][0]["ok"], json!(true));
    }
    settle(&hub);

    // 2. Upload `p.dev`'s change, hold its `packs` row in an external DB connection so the push
    //    blocks inside its transaction AFTER `Objects::keep` writes all loose objects (including
    //    server-completed `made` trees/snapshots), and crash + restart the server!
    let stopped_content = "MARKER-G10-STOPPED-PUSH-9101\n";
    let (stopped_blob_id, _) = blob(stopped_content);
    let (dev_tok, dev_ident, proj_name) = (p.dev.token(), p.dev.identity(), p.name.clone());
    let (map1, container, tip_before, s1, keys_before) = {
        let api = hub.api();
        let mut c = Craft::new(&api, &p.dev, &p.name, "main");
        c.file("src/g10_stopped.rs", stopped_content);
        let s1 = {
            let t = c.tip;
            snap(&mut c, vec![t], "stopped before commit", None)
        };
        let (map, container) = upload_all(&api, &c);
        let keys_before = loose_keys_in_store(&hub, pid);
        (map, container, c.tip, s1, keys_before)
    };

    let db_url = hub
        .rt
        .block_on(async {
            // Open a separate 1-connection pool on the same DB so `hub.crash_and_restart` never touches it.
            sqlx::query_scalar::<_, String>("SELECT current_database()").fetch_one(&hub.hub().db).await.unwrap()
        });
    let admin_base = std::env::var("VEIL_TEST_DATABASE_URL").unwrap();
    let ext_url = format!("{}/{db_url}", admin_base.rsplit_once('/').unwrap().0);
    let ext_rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let ext_pool = ext_rt.block_on(veil_server::db::connect(&ext_url, 1)).unwrap();
    let mut lock_tx = ext_rt.block_on(ext_pool.begin()).unwrap();
    ext_rt
        .block_on(
            sqlx::query("SELECT 1 FROM packs WHERE project_id = $1 AND name = $2 FOR UPDATE")
                .bind(pid)
                .bind(&container)
                .execute(&mut *lock_tx),
        )
        .unwrap();

    let kept_before = hub.hub().objects.objects_kept.load(Relaxed);
    let (authority, cert) = (hub.authority(), hub.cert_pem.clone());
    let map_spawn = map1.clone();
    let name_spawn = proj_name.clone();
    let tok_spawn = dev_tok.clone();
    let push_thread = std::thread::spawn(move || {
        let api = Api::at(&authority, &cert);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            push_body(&api, &tok_spawn, &name_spawn, "main", Some(tip_before), s1, &map_spawn)
        }));
    });

    let deadline = Instant::now() + Duration::from_secs(30);
    while hub.hub().objects.objects_kept.load(Relaxed) == kept_before
        || !hub
            .rt
            .block_on(hub.blob_store().exists(&veil_server::store::object_key(pid, &stopped_blob_id)))
            .unwrap()
    {
        assert!(Instant::now() < deadline, "push never finished Objects::keep before stop");
        std::thread::sleep(Duration::from_millis(20));
    }
    let keys_at_stop = loose_keys_in_store(&hub, pid);
    let written_before_stop: HashSet<String> = keys_at_stop.difference(&keys_before).cloned().collect();
    assert!(!written_before_stop.is_empty(), "interrupted push wrote loose objects before crash");

    // Crash and restart the server while the push has not committed!
    let hub = hub.crash_and_restart(|_| {});
    ext_rt.block_on(lock_tx.rollback()).unwrap();
    ext_rt.block_on(ext_pool.close());
    let _ = push_thread.join();

    // 3. After restart: nothing reachable is missing, and the upload container is STILL staged!
    let api = hub.api();
    let admin_tok = p.admin.token();
    let sec_tok = p.sec.token();
    assert_eq!(api.tips(Some(&dev_tok), &p.name).unwrap().branches["main"], tip_before, "stopped push did not commit");
    assert_eq!(packs_in(&hub, pid, 0), vec![container.clone()], "container is still staged for retry");
    assert!(hub.rt.block_on(hub.blob_store().exists(&veil_server::pack::key(pid, &container))).unwrap(), "staged container still in store");
    let admin_main = api.tips(Some(&admin_tok), &p.name).unwrap().branches["main"];
    assert!(whole_tree_beside(&hub, pid, admin_main) >= 2, "reachable main tree intact after restart");

    // Advance `main` with an admin commit so `p.dev`'s retry builds a new snapshot `s2` on the new tip,
    // reusing `stopped_blob_id`'s receipt from the STILL-STAGED `container` (without re-uploading `stopped_blob_id`!),
    // leaving Attempt 1's `s1` and server-completed `made` objects unreferenced ("the rest")!
    {
        let mut ca = Craft::with(&api, admin_tok.clone(), p.admin.identity(), &p.name, "main");
        ca.file("src/g10_admin_step.rs", "admin moved main\n");
        let ra = ca.push("main", "admin step");
        assert_eq!(ra.status, 200);
        assert_eq!(ra.json()["results"][0]["ok"], json!(true));
    }
    {
        let blob_receipt = map1.get(&stopped_blob_id.hex()).unwrap().clone();
        let mut c2 = Craft::with(&api, dev_tok.clone(), dev_ident, &p.name, "main");
        c2.refer("src/g10_stopped.rs", stopped_blob_id, stopped_content.len() as u64);
        let s2 = {
            let t = c2.tip;
            snap(&mut c2, vec![t], "retry after restart", None)
        };
        assert!(!c2.objects.iter().any(|(id, _)| *id == stopped_blob_id), "blob itself is not re-uploaded");
        let (mut map2, _) = upload_all(&api, &c2);
        map2.insert(stopped_blob_id.hex(), blob_receipt);
        let r_retry = push_body(&api, &dev_tok, &p.name, "main", Some(c2.tip), s2, &map2);
        assert_eq!(r_retry.status, 200, "{}", String::from_utf8_lossy(&r_retry.body));
        assert_eq!(r_retry.json()["results"][0]["ok"], json!(true), "retry using staged container landed");
    }
    assert_eq!(pack_counts(&hub, pid), (0, 0, 0), "staged containers purged once retry landed");
    settle(&hub);

    // 4. GC inside window keeps everything; GC past window collects the unreferenced objects from the
    //    stopped push ("the rest") while NEVER collecting the hidden embargo line!
    let s1_key = veil_server::store::object_key(pid, &s1);
    assert!(hub.rt.block_on(hub.blob_store().exists(&s1_key)).unwrap(), "orphaned s1 from stopped push is in store before GC");

    let r_gc1 = gc_pass(
        &hub,
        pid,
        &Options {
            min_packs_to_merge: 99,
            run_gc: true,
            retention_window_ms: 60_000,
            now_offset_ms: 0,
            ..Options::default()
        },
    );
    assert_eq!(r_gc1.loose_objects_deleted, 0);
    assert!(hub.rt.block_on(hub.blob_store().exists(&s1_key)).unwrap(), "orphaned s1 kept inside retention window");

    let r_gc2 = gc_pass(
        &hub,
        pid,
        &Options {
            min_packs_to_merge: 99,
            run_gc: true,
            retention_window_ms: 60_000,
            pack_grace_ms: 0,
            now_offset_ms: 180_000,
            ..Options::default()
        },
    );
    assert!(r_gc2.loose_objects_deleted >= 1, "orphaned loose objects from stopped push collected: {r_gc2:?}");
    assert!(!hub.rt.block_on(hub.blob_store().exists(&s1_key)).unwrap(), "orphaned s1 collected after retention window");

    // Embargo hidden line was NEVER collected, and releases cleanly onto `main`!
    assert!(
        hub.rt.block_on(hub.blob_store().exists(&veil_server::store::object_key(pid, &emb_blob_id))).unwrap(),
        "embargoed blob never collected by GC"
    );
    let rel = api.post_json(
        Some(&sec_tok),
        &format!("/v1/projects/{}/embargoes/{eid}/release", p.name),
        &json!({}),
    );
    assert_eq!(rel.status, 200, "{}", String::from_utf8_lossy(&rel.body));
    assert_eq!(rel.json()["released"], json!(true));
    assert_eq!(read_file(&api, &dev_tok, &p.name, "src/g10_vuln.rs").as_deref(), Some(emb_content.as_bytes()));
    assert_eq!(read_file(&api, &dev_tok, &p.name, "src/g10_stopped.rs").as_deref(), Some(stopped_content.as_bytes()));
}

/// Guarantee 11 (`object-layout.md` §8.1): pushes schedule no merge and list no
/// pack; a project with leftover small packs is merged down once and every
/// object still reads on two servers. `stats.json` names the layout.
#[test]
fn guarantee_11_pushes_schedule_no_merge_leftover_small_packs_merge_once_and_stats_names_layout() {
    let hub = TestHub::start_objects();
    let other = TestHub::beside(&hub);
    assert_eq!(veil_server::stats_json(&hub.hub(), 0)["object_layout"], json!("objects"));
    assert_eq!(veil_server::stats_json(&other.hub(), 0)["object_layout"], json!("objects"));

    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();

    // 1. Pushes in `objects` mode (>= MERGE_MIN_PACKS + 8 pushes) list no pack and schedule no merge.
    let pushes = pack_gc::MERGE_MIN_PACKS + 8;
    for i in 0..pushes {
        let mut c = Craft::new(&api, &p.admin, &p.name, "main");
        c.file(&format!("src/g11_push/p{i}.txt"), &format!("g11 push {i}\n"));
        let r = c.push_to(&format!("b11-{i}"), None);
        assert_eq!(r.status, 200, "push {i}: {}", String::from_utf8_lossy(&r.body));
        assert_eq!(r.json()["results"][0]["ok"], json!(true));
    }
    assert_eq!(pack_counts(&hub, pid), (0, 0, 0), "{pushes} pushes listed no pack and left no row");
    assert!(packs_in_store(&hub, pid).is_empty(), "{pushes} pushes wrote no pack in storage");

    // 2. A project with leftover small listed packs (as from before switching `--object-layout` to
    //    `objects`) is merged down once when its listing is loaded, and every object still reads on
    //    both `objects` servers (`hub` and `other`)!
    let leftover_blobs = pack_gc::MERGE_MIN_PACKS + 6;
    let mut sample_blobs: Vec<(ObjectId, Bytes)> = Vec::with_capacity(leftover_blobs);
    let (p_left, pid_left, total_before_merge) = {
        let init_srv = TestHub::beside(&hub);
        let p_left = setup_project(&init_srv);
        let pid_left = project_id(&init_srv, &p_left.name);
        drop(init_srv);

        let hub_packs = TestHub::beside_with_layout(&hub, ObjectLayout::Packs);
        let api_packs = hub_packs.api();

        // Push one commit adding `leftover_blobs` files through the real push path on `hub_packs`
        // so `branches`, `snapshots` and `projections` are committed normally.
        let mut c_left = Craft::new(&api_packs, &p_left.admin, &p_left.name, "main");
        for i in 0..leftover_blobs {
            let text = format!("MARKER-G11-LEFTOVER-PACK-BLOB-{i:03}\n");
            let (bid, braw_vec) = blob(&text);
            sample_blobs.push((bid, Bytes::from(braw_vec)));
            c_left.file(&format!("src/leftover/f{i:03}.txt"), &text);
        }
        let s_left = {
            let t = c_left.tip;
            snap(&mut c_left, vec![t], "leftover pack files", None)
        };
        let (map_left, combined_pack) = upload_all(&api_packs, &c_left);
        let r_left = push_body(&api_packs, &c_left.token, &p_left.name, "main", Some(c_left.tip), s_left, &map_left);
        assert_eq!(r_left.status, 200, "{}", String::from_utf8_lossy(&r_left.body));
        assert_eq!(r_left.json()["results"][0]["ok"], json!(true));
        settle(&hub_packs);

        // Split `combined_pack` into one small `LISTED` pack per blob plus one small `LISTED` pack
        // for the trees and snapshot, removing `combined_pack` so every blob lives exclusively in
        // its own small `LISTED` pack before `hub` or `other` ever loads `pid_left`.
        let hp = hub_packs.hub();
        let blob_id_set: HashSet<ObjectId> = sample_blobs.iter().map(|(id, _)| *id).collect();
        let mut non_blobs = Vec::new();
        let mut seen = HashSet::new();
        for (id, raw) in &c_left.objects {
            if !blob_id_set.contains(id) && seen.insert(*id) {
                non_blobs.push((*id, veil_server::store::encode(Bytes::from(raw.clone()))));
            }
        }
        hub_packs.rt.block_on(async {
            for (bid, braw) in &sample_blobs {
                let enc = veil_server::store::encode(braw.clone());
                let (pname, _) = hp.objects.put_job_pack(pid_left, vec![(*bid, enc)]).await.unwrap();
                sqlx::query("UPDATE packs SET state = 1 WHERE project_id = $1 AND name = $2")
                    .bind(pid_left)
                    .bind(&*pname)
                    .execute(&hp.db)
                    .await
                    .unwrap();
            }
            let (tname, _) = hp.objects.put_job_pack(pid_left, non_blobs).await.unwrap();
            sqlx::query("UPDATE packs SET state = 1 WHERE project_id = $1 AND name = $2")
                .bind(pid_left)
                .bind(&*tname)
                .execute(&hp.db)
                .await
                .unwrap();
            sqlx::query("DELETE FROM packs WHERE project_id = $1 AND name = $2")
                .bind(pid_left)
                .bind(&combined_pack)
                .execute(&hp.db)
                .await
                .unwrap();
            hub_packs.blob_store().delete(&veil_server::pack::key(pid_left, &combined_pack)).await.unwrap();
        });
        let total = pack_counts(&hub_packs, pid_left).1 as usize;
        assert!(total > leftover_blobs, "expected > {leftover_blobs} listed small packs, got {total}");
        (p_left, pid_left, total)
    };

    let h = hub.hub();
    // Reading from `other` (cold listing for `pid_left`, running `ObjectLayout::Objects`) loads the
    // listing and schedules the one-shot leftover merge!
    let got0 = other.rt.block_on(other.hub().objects.get(pid_left, &sample_blobs[0].0)).unwrap().expect("reads from leftover pack");
    assert_eq!(got0, sample_blobs[0].1);

    let until = Instant::now() + Duration::from_secs(30);
    while pack_counts(&hub, pid_left).1 >= pack_gc::MERGE_MIN_PACKS as i64 && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(100));
    }
    let (_, listed_after, discarded_after) = pack_counts(&hub, pid_left);
    assert_eq!(listed_after, 1, "leftover small packs merged down to 1 pack (listed={listed_after}, discarded={discarded_after})");
    assert_eq!(discarded_after, total_before_merge as i64, "all {total_before_merge} small packs marked discarded");

    // Sweep discarded packs (grace = 0) once `other`'s background merge pass
    // releases the project's advisory lock, so old packs are physically deleted
    // from storage, and verify every single object reads back byte-identically
    // on BOTH servers (`hub` and `other`)!
    let sweep_opts = Options {
        min_packs_to_merge: 99,
        run_gc: false,
        pack_grace_ms: 0,
        ..Options::default()
    };
    let sweep = {
        let mut tries = 0;
        loop {
            tries += 1;
            match hub.rt.block_on(pack_gc::run_project(&h, pid_left, &sweep_opts)) {
                Ok(r) if r.skipped && tries < 40 => std::thread::sleep(Duration::from_millis(25)),
                Ok(r) => break r,
                Err(e) if e.is_retryable() && tries < 40 => std::thread::sleep(Duration::from_millis(25)),
                Err(e) => panic!("sweep pass: {e:?}"),
            }
        }
    };
    assert!(!sweep.skipped);
    assert_eq!(sweep.discarded_packs_swept, total_before_merge);
    assert_eq!(pack_counts(&hub, pid_left), (0, 1, 0));

    let other_api = other.api();
    let tok_left = p_left.dev.token();
    for (i, (bid, expected)) in sample_blobs.iter().enumerate() {
        let g1 = hub.rt.block_on(h.objects.get(pid_left, bid)).unwrap().expect("hub reads merged pack");
        let g2 = other.rt.block_on(other.hub().objects.get(pid_left, bid)).unwrap().expect("other reads merged pack");
        assert_eq!(&g1, expected, "hub blob {i}");
        assert_eq!(&g2, expected, "other blob {i}");
        if i % 17 == 0 {
            assert_eq!(
                read_file(&other_api, &tok_left, &p_left.name, &format!("src/leftover/f{i:03}.txt")).as_deref(),
                Some(&expected[10..])
            );
        }
    }

    // Further pushes on `hub` (`ObjectLayout::Objects`) list no new pack, leaving only the 1 merged pack.
    for i in 0..4 {
        let mut c_more = Craft::new(&api, &p_left.admin, &p_left.name, "main");
        c_more.file(&format!("src/after_merge/m{i}.txt"), &format!("after merge {i}\n"));
        let r = c_more.push("main", &format!("after merge {i}"));
        assert_eq!(r.status, 200);
        assert_eq!(r.json()["results"][0]["ok"], json!(true));
    }
    assert_eq!(pack_counts(&hub, pid_left), (0, 1, 0), "later pushes in objects layout list no pack");
}

/// BUG-2661 (part 1): in `objects` mode, a staged container `C1` that an
/// in-flight request is using is never handed out by `staged_holding` to a
/// concurrent upload by the same person — tested across push+push,
/// push+API commit and push+land (both snapshot-based `vl land` and
/// edits-based `POST …/land`), where the first push commits and purges `C1`.
#[test]
fn bug_2661_concurrent_uploads_by_one_person_do_not_share_in_flight_containers() {
    let hub = TestHub::start_objects();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let dev_tok = p.dev.token();

    // Helper: start a push by `p.dev` uploading `c1`, hold `c1`'s `packs` row `FOR UPDATE` so the
    // push enters its commit transaction and blocks right on `UPDATE packs`, run `concurrent` while
    // that first push is in-flight, then release the row lock so the first push commits and purges
    // `c1`, and return `(c1_pack, concurrent_out)`.
    let while_push_in_flight = |branch1: &str, shared_path: &str, shared_body: &str, concurrent: &dyn Fn(&str, ObjectId, &[u8])| {
        let mut c1 = Craft::new(&api, &p.dev, &p.name, "main");
        let (shared_id, shared_raw) = blob(shared_body);
        c1.file(shared_path, shared_body);
        let s1 = {
            let t = c1.tip;
            snap(&mut c1, vec![t], &format!("first push {branch1}"), None)
        };
        let (map1, pack1) = upload_all(&api, &c1);

        let mut lock = hub.rt.block_on(hub.hub().db.begin()).unwrap();
        hub.rt
            .block_on(
                sqlx::query("SELECT 1 FROM packs WHERE project_id = $1 AND name = $2 FOR UPDATE")
                    .bind(pid)
                    .bind(&pack1)
                    .execute(&mut *lock),
            )
            .unwrap();

        let writes_before = hub.hub().objects.writes.load(Relaxed);
        std::thread::scope(|sc| {
            let api1 = hub.api();
            let pname = p.name.clone();
            let tok1 = dev_tok.clone();
            let b1 = branch1.to_string();
            let map1_c = map1.clone();
            let h1 = sc.spawn(move || push_body(&api1, &tok1, &pname, &b1, None, s1, &map1_c));

            // Wait until the first push has kept its loose objects and is blocked on `UPDATE packs`.
            let deadline = Instant::now() + Duration::from_secs(15);
            while hub.hub().objects.writes.load(Relaxed) <= writes_before {
                assert!(Instant::now() < deadline, "first push never reached its commit transaction");
                std::thread::sleep(Duration::from_millis(10));
            }
            std::thread::sleep(Duration::from_millis(30));

            // While the first push is in-flight, run the same person's second upload, then let the
            // first push commit and purge `pack1`, then finish the second request inside `concurrent`.
            let up2 = api.upload(&dev_tok, &p.name, &[(shared_id, shared_raw.clone())]);
            assert_eq!(up2.status, 200, "{}", String::from_utf8_lossy(&up2.body));
            let recs2: Vec<String> = serde_json::from_value(up2.json()["receipts"].clone()).unwrap();
            let pack2 = recs2[0].split_once('.').unwrap().1.to_string();

            hub.rt.block_on(lock.rollback()).unwrap();
            let r1 = h1.join().unwrap();
            assert_eq!(r1.status, 200, "{}", String::from_utf8_lossy(&r1.body));
            assert_eq!(r1.json()["results"][0]["ok"], json!(true), "{}", String::from_utf8_lossy(&r1.body));
            assert!(
                !hub.rt.block_on(hub.blob_store().exists(&veil_server::pack::key(pid, &pack1))).unwrap(),
                "committing first push purged {pack1}"
            );

            concurrent(&recs2[0], shared_id, &shared_raw);
            assert_ne!(
                pack2, pack1,
                "concurrent upload by the same person must not be handed in-flight container {pack1}"
            );
        });
    };

    // 1. push + push
    while_push_in_flight(
        "dev/b2661-p1",
        "src/b2661_shared_1.txt",
        "MARKER-B2661-SHARED-PUSH-PUSH-01\n",
        &|shared_receipt, shared_id, _| {
            let mut c2 = Craft::new(&api, &p.dev, &p.name, "main");
            c2.file("src/b2661_push2.txt", "MARKER-B2661-SHARED-PUSH-PUSH-01\n");
            c2.file("src/b2661_push2_own.txt", "own sibling file\n");
            c2.objects.retain(|(id, _)| *id != shared_id);
            let s2 = {
                let t = c2.tip;
                snap(&mut c2, vec![t], "second push", None)
            };
            let (mut map2, _) = upload_all(&api, &c2);
            map2.insert(shared_id.hex(), json!(shared_receipt));
            let r2 = push_body(&api, &dev_tok, &p.name, "dev/b2661-p2", None, s2, &map2);
            assert_eq!(r2.status, 200, "push+push failed: {}", String::from_utf8_lossy(&r2.body));
            assert_eq!(r2.json()["results"][0]["ok"], json!(true), "{}", String::from_utf8_lossy(&r2.body));
            let got = api.get(
                Some(&dev_tok),
                &format!("/v1/projects/{}/q/file?rev=dev/b2661-p2&path=src/b2661_push2.txt", p.name),
            );
            assert_eq!((got.status, got.body.as_slice()), (200, &b"MARKER-B2661-SHARED-PUSH-PUSH-01\n"[..]));
        },
    );

    // 2. push + API commit (`POST /v1/projects/{p}/changes`)
    while_push_in_flight(
        "dev/b2661-api-p1",
        "src/b2661_shared_2.txt",
        "MARKER-B2661-SHARED-PUSH-API-02\n",
        &|shared_receipt, shared_id, _| {
            let base = api.tips(Some(&dev_tok), &p.name).unwrap().branches["main"];
            let r_api = api.post_json(
                Some(&dev_tok),
                &format!("/v1/projects/{}/changes", p.name),
                &json!({
                    "base": base.hex(),
                    "description": "concurrent api commit",
                    "edits": [{"path": "src/b2661_api.txt", "put": {"object": shared_id.hex()}}],
                    "receipts": {shared_id.hex(): shared_receipt},
                }),
            );
            assert_eq!(r_api.status, 200, "push+API commit failed: {}", String::from_utf8_lossy(&r_api.body));
            let snap_hex = r_api.json()["snapshot"].as_str().unwrap().to_string();
            let got = api.get(Some(&dev_tok), &format!("/v1/projects/{}/q/file?rev={snap_hex}&path=src/b2661_api.txt", p.name));
            assert_eq!((got.status, got.body.as_slice()), (200, &b"MARKER-B2661-SHARED-PUSH-API-02\n"[..]));
        },
    );

    // 3a. push + snapshot-based land (`vl land` -> `POST /v1/projects/{p}/land` with `snapshot`)
    while_push_in_flight(
        "dev/b2661-land-p1",
        "src/b2661_shared_3.txt",
        "MARKER-B2661-SHARED-PUSH-LAND-SNAP-03\n",
        &|shared_receipt, shared_id, _| {
            let mut cl = Craft::new(&api, &p.dev, &p.name, "main");
            cl.file("src/b2661_land_snap.txt", "MARKER-B2661-SHARED-PUSH-LAND-SNAP-03\n");
            cl.objects.retain(|(id, _)| *id != shared_id);
            let sl = {
                let t = cl.tip;
                snap(&mut cl, vec![t], "concurrent snapshot land", None)
            };
            let (mut map_l, _) = upload_all(&api, &cl);
            map_l.insert(shared_id.hex(), json!(shared_receipt));
            let r_land = api.post_json(
                Some(&dev_tok),
                &format!("/v1/projects/{}/land", p.name),
                &json!({
                    "onto": "main",
                    "snapshot": sl.hex(),
                    "receipts": map_l,
                    "wait": true,
                }),
            );
            assert_eq!(r_land.status, 200, "push+snapshot land failed: {}", String::from_utf8_lossy(&r_land.body));
            assert_eq!(r_land.json()["state"], json!("landed"), "{}", String::from_utf8_lossy(&r_land.body));
            assert_eq!(
                read_file(&api, &dev_tok, &p.name, "src/b2661_land_snap.txt").as_deref(),
                Some(&b"MARKER-B2661-SHARED-PUSH-LAND-SNAP-03\n"[..])
            );
        },
    );

    // 3b. push + edits-based land (`POST /v1/projects/{p}/land` with `base` + `edits`)
    while_push_in_flight(
        "dev/b2661-land-ed-p1",
        "src/b2661_shared_4.txt",
        "MARKER-B2661-SHARED-PUSH-LAND-EDITS-04\n",
        &|shared_receipt, shared_id, _| {
            let base = api.tips(Some(&dev_tok), &p.name).unwrap().branches["main"];
            let r_land = api.post_json(
                Some(&dev_tok),
                &format!("/v1/projects/{}/land", p.name),
                &json!({
                    "onto": "main",
                    "base": base.hex(),
                    "description": "concurrent edits land",
                    "edits": [{"path": "src/b2661_land_edits.txt", "put": {"object": shared_id.hex()}}],
                    "receipts": {shared_id.hex(): shared_receipt},
                    "wait": true,
                }),
            );
            assert_eq!(r_land.status, 200, "push+edits land failed: {}", String::from_utf8_lossy(&r_land.body));
            assert_eq!(r_land.json()["state"], json!("landed"), "{}", String::from_utf8_lossy(&r_land.body));
            assert_eq!(
                read_file(&api, &dev_tok, &p.name, "src/b2661_land_edits.txt").as_deref(),
                Some(&b"MARKER-B2661-SHARED-PUSH-LAND-EDITS-04\n"[..])
            );
        },
    );

    assert_eq!(pack_counts(&hub, pid), (0, 0, 0), "all staged containers purged cleanly");
}

/// BUG-2661 (part 2): whenever a request's receipted container has vanished
/// (consumed & purged by an earlier committing push, missing at `staged_slots`,
/// or gone after `staging()` at `Source::raw` / `take_uploads`), push, API
/// commit and `POST …/land` all answer `409 Conflict` (`"an upload this push
/// names was discarded; push again"`) instead of `400`, and **never** discard
/// sibling staged containers (`C2`), so retrying after re-uploading only the
/// vanished container succeeds without re-uploading `C2`.
struct VanishOnEntryStore {
    inner: Arc<dyn veil_server::store::BlobStore>,
    /// Map of `key -> remaining entry reads (start > 0)` before deleting `key`.
    vanish_at: std::sync::Mutex<std::collections::HashMap<String, usize>>,
}

impl VanishOnEntryStore {
    fn wrap(inner: Arc<dyn veil_server::store::BlobStore>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            vanish_at: Default::default(),
        })
    }

    fn schedule(&self, key: String, entry_read: usize) {
        self.vanish_at.lock().unwrap().insert(key, entry_read);
    }
}

#[async_trait::async_trait]
impl veil_server::store::BlobStore for VanishOnEntryStore {
    async fn get(&self, key: &str) -> anyhow::Result<Option<Bytes>> {
        self.inner.get(key).await
    }
    async fn put(&self, key: &str, data: Bytes) -> anyhow::Result<()> {
        self.inner.put(key, data).await
    }
    async fn exists(&self, key: &str) -> anyhow::Result<bool> {
        self.inner.exists(key).await
    }
    async fn len(&self, key: &str) -> anyhow::Result<Option<u64>> {
        self.inner.len(key).await
    }
    async fn get_range(&self, key: &str, start: u64, end: u64) -> anyhow::Result<Option<(Bytes, u64)>> {
        // Pack index reads in `staging()` start at byte 0; entry reads in
        // `get_staged`, `staged_declared` and `staged_encoding` always have `start > 0`.
        if start > 0 {
            let delete_now = {
                let mut g = self.vanish_at.lock().unwrap();
                match g.get_mut(key) {
                    Some(n) if *n <= 1 => {
                        g.remove(key);
                        true
                    }
                    Some(n) => {
                        *n -= 1;
                        false
                    }
                    None => false,
                }
            };
            if delete_now {
                self.inner.delete(key).await?;
            }
        }
        self.inner.get_range(key, start, end).await
    }
    async fn delete(&self, key: &str) -> anyhow::Result<()> {
        self.inner.delete(key).await
    }
    async fn list(&self, prefix: &str) -> anyhow::Result<Vec<String>> {
        self.inner.list(prefix).await
    }
}

#[test]
fn bug_2661_vanished_receipted_container_answers_409_and_keeps_sibling_uploads() {
    let hub = TestHub::start_objects();
    let store = hub.blob_store();
    let vanish = VanishOnEntryStore::wrap(store.clone());
    let cold = TestHub::beside_with_store(&hub, ObjectLayout::Objects, vanish.clone());
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let cold_api = cold.api();
    let dev_tok = p.dev.token();

    let assert_sibling_intact = |sibling_pack: &str| {
        let state: Option<i16> = hub
            .rt
            .block_on(
                sqlx::query_scalar("SELECT state FROM packs WHERE project_id = $1 AND name = $2")
                    .bind(pid)
                    .bind(sibling_pack)
                    .fetch_optional(&hub.hub().db),
            )
            .unwrap();
        assert_eq!(state, Some(0), "sibling container {sibling_pack} must remain STAGED (0), got {state:?}");
        assert!(
            hub.rt.block_on(store.exists(&veil_server::pack::key(pid, sibling_pack))).unwrap(),
            "sibling container {sibling_pack} must remain stored"
        );
    };

    // Helper: create `C1` (holding `shared_body`) and consume+purge `C1` via a committing push by `p.dev`,
    // returning `(shared_id, shared_raw, vanished_receipt)`.
    let make_purged_receipt = |tag: &str| -> (ObjectId, Vec<u8>, String) {
        let (sid, sraw) = blob(tag);
        let mut c1 = Craft::new(&api, &p.dev, &p.name, "main");
        c1.file("src/b2661_consume.txt", tag);
        c1.objects.retain(|(id, _)| *id != sid);
        let snap1 = {
            let t = c1.tip;
            snap(&mut c1, vec![t], "consume c1", None)
        };
        let up_c1 = api.upload(&dev_tok, &p.name, &[(sid, sraw.clone())]);
        assert_eq!(up_c1.status, 200);
        let c1_rec: Vec<String> = serde_json::from_value(up_c1.json()["receipts"].clone()).unwrap();
        let c1_pack = c1_rec[0].split_once('.').unwrap().1.to_string();
        let (mut m1, _) = upload_all(&api, &c1);
        m1.insert(sid.hex(), json!(c1_rec[0]));
        let bname = format!("dev/consume-{}", &c1_pack[..10]);
        let r1 = push_body(&api, &dev_tok, &p.name, &bname, None, snap1, &m1);
        assert_eq!(r1.status, 200, "{}", String::from_utf8_lossy(&r1.body));
        assert_eq!(r1.json()["results"][0]["ok"], json!(true));
        assert!(!hub.rt.block_on(store.exists(&veil_server::pack::key(pid, &c1_pack))).unwrap());
        (sid, sraw, c1_rec[0].clone())
    };

    // 1a. Push with purged `C1` + live sibling `C2` -> 409 Conflict, `C2` preserved, retry lands!
    {
        let (sid, sraw, c1_rec) = make_purged_receipt("MARKER-B2661-VANISHED-PUSH-1A\n");
        let mut c2 = Craft::new(&api, &p.dev, &p.name, "main");
        c2.file("src/b2661_v_push.txt", "MARKER-B2661-VANISHED-PUSH-1A\n");
        c2.file("src/b2661_v_push_sib.txt", "sibling push content\n");
        c2.objects.retain(|(id, _)| *id != sid);
        let s2 = {
            let t = c2.tip;
            snap(&mut c2, vec![t], "push with vanished c1", None)
        };
        let (mut map2, sib_pack) = upload_all(&api, &c2);
        map2.insert(sid.hex(), json!(c1_rec));

        let r_vanished = push_body(&api, &dev_tok, &p.name, "dev/b2661-v-push", None, s2, &map2);
        let body = String::from_utf8_lossy(&r_vanished.body);
        assert_eq!(r_vanished.status, 409, "expected 409 for vanished container in push, got {}: {body}", r_vanished.status);
        assert!(body.contains("an upload this push names was discarded; push again"), "unexpected body: {body}");
        assert_sibling_intact(&sib_pack);

        // Re-upload ONLY `sid`, keeping `sib_pack`'s receipts untouched, and retry!
        let up_re = api.upload(&dev_tok, &p.name, &[(sid, sraw)]);
        assert_eq!(up_re.status, 200);
        let re_rec: Vec<String> = serde_json::from_value(up_re.json()["receipts"].clone()).unwrap();
        map2.insert(sid.hex(), json!(re_rec[0]));
        let r_retry = push_body(&api, &dev_tok, &p.name, "dev/b2661-v-push", None, s2, &map2);
        assert_eq!(r_retry.status, 200, "{}", String::from_utf8_lossy(&r_retry.body));
        assert_eq!(r_retry.json()["results"][0]["ok"], json!(true));
    }

    // 1b. API commit (`POST /changes`) with purged `C1` + live sibling `C2` -> 409 Conflict, `C2` preserved!
    {
        let (sid, sraw, c1_rec) = make_purged_receipt("MARKER-B2661-VANISHED-API-1B\n");
        let (sib_id, sib_raw) = blob("MARKER-B2661-API-SIBLING-1B\n");
        let up_sib = api.upload(&dev_tok, &p.name, &[(sib_id, sib_raw)]);
        assert_eq!(up_sib.status, 200);
        let sib_rec: Vec<String> = serde_json::from_value(up_sib.json()["receipts"].clone()).unwrap();
        let sib_pack = sib_rec[0].split_once('.').unwrap().1.to_string();
        let base = api.tips(Some(&dev_tok), &p.name).unwrap().branches["main"];

        let r_vanished = api.post_json(
            Some(&dev_tok),
            &format!("/v1/projects/{}/changes", p.name),
            &json!({
                "base": base.hex(),
                "description": "api commit vanished c1",
                "edits": [
                    {"path": "src/b2661_v_api1.txt", "put": {"object": sid.hex()}},
                    {"path": "src/b2661_v_api2.txt", "put": {"object": sib_id.hex()}},
                ],
                "receipts": {sid.hex(): c1_rec, sib_id.hex(): sib_rec[0]},
            }),
        );
        let body = String::from_utf8_lossy(&r_vanished.body);
        assert_eq!(r_vanished.status, 409, "expected 409 for vanished container in API commit, got {}: {body}", r_vanished.status);
        assert!(body.contains("an upload this push names was discarded; push again"), "unexpected body: {body}");
        assert_sibling_intact(&sib_pack);

        let up_re = api.upload(&dev_tok, &p.name, &[(sid, sraw)]);
        let re_rec: Vec<String> = serde_json::from_value(up_re.json()["receipts"].clone()).unwrap();
        let r_retry = api.post_json(
            Some(&dev_tok),
            &format!("/v1/projects/{}/changes", p.name),
            &json!({
                "base": base.hex(),
                "description": "api commit retry",
                "edits": [
                    {"path": "src/b2661_v_api1.txt", "put": {"object": sid.hex()}},
                    {"path": "src/b2661_v_api2.txt", "put": {"object": sib_id.hex()}},
                ],
                "receipts": {sid.hex(): re_rec[0], sib_id.hex(): sib_rec[0]},
            }),
        );
        assert_eq!(r_retry.status, 200, "{}", String::from_utf8_lossy(&r_retry.body));
    }

    // 1c. `POST /land` (edits-based) with purged `C1` + live sibling `C2` -> 409 Conflict, `C2` preserved!
    {
        let (sid, sraw, c1_rec) = make_purged_receipt("MARKER-B2661-VANISHED-LAND-1C\n");
        let (sib_id, sib_raw) = blob("MARKER-B2661-LAND-SIBLING-1C\n");
        let up_sib = api.upload(&dev_tok, &p.name, &[(sib_id, sib_raw)]);
        let sib_rec: Vec<String> = serde_json::from_value(up_sib.json()["receipts"].clone()).unwrap();
        let sib_pack = sib_rec[0].split_once('.').unwrap().1.to_string();
        let base = api.tips(Some(&dev_tok), &p.name).unwrap().branches["main"];

        let r_vanished = api.post_json(
            Some(&dev_tok),
            &format!("/v1/projects/{}/land", p.name),
            &json!({
                "onto": "main",
                "base": base.hex(),
                "description": "land vanished c1",
                "edits": [
                    {"path": "src/b2661_v_land1.txt", "put": {"object": sid.hex()}},
                    {"path": "src/b2661_v_land2.txt", "put": {"object": sib_id.hex()}},
                ],
                "receipts": {sid.hex(): c1_rec, sib_id.hex(): sib_rec[0]},
                "wait": true,
            }),
        );
        let body = String::from_utf8_lossy(&r_vanished.body);
        assert_eq!(r_vanished.status, 409, "expected 409 for vanished container in land, got {}: {body}", r_vanished.status);
        assert!(body.contains("an upload this push names was discarded; push again"), "unexpected body: {body}");
        assert_sibling_intact(&sib_pack);

        let up_re = api.upload(&dev_tok, &p.name, &[(sid, sraw)]);
        let re_rec: Vec<String> = serde_json::from_value(up_re.json()["receipts"].clone()).unwrap();
        let r_retry = api.post_json(
            Some(&dev_tok),
            &format!("/v1/projects/{}/land", p.name),
            &json!({
                "onto": "main",
                "base": base.hex(),
                "description": "land retry",
                "edits": [
                    {"path": "src/b2661_v_land1.txt", "put": {"object": sid.hex()}},
                    {"path": "src/b2661_v_land2.txt", "put": {"object": sib_id.hex()}},
                ],
                "receipts": {sid.hex(): re_rec[0], sib_id.hex(): sib_rec[0]},
                "wait": true,
            }),
        );
        assert_eq!(r_retry.status, 200, "{}", String::from_utf8_lossy(&r_retry.body));
        assert_eq!(r_retry.json()["state"], json!("landed"));
    }

    // 2a. Vanished right between `usable` and `staged_slots` (`staged_slots -> Ok(None)` on cold server):
    //     row is still STAGED in DB, storage object gone -> 409 Conflict, sibling preserved!
    {
        let (sid, sraw) = blob("MARKER-B2661-STAGED-SLOTS-NONE-2A\n");
        let up_c1 = api.upload(&dev_tok, &p.name, &[(sid, sraw)]);
        let c1_rec: Vec<String> = serde_json::from_value(up_c1.json()["receipts"].clone()).unwrap();
        let c1_pack = c1_rec[0].split_once('.').unwrap().1.to_string();
        hub.rt.block_on(store.delete(&veil_server::pack::key(pid, &c1_pack))).unwrap();

        let mut c2 = Craft::new(&cold_api, &p.dev, &p.name, "main");
        c2.file("src/b2661_slots_none.txt", "MARKER-B2661-STAGED-SLOTS-NONE-2A\n");
        c2.objects.retain(|(id, _)| *id != sid);
        let s2 = {
            let t = c2.tip;
            snap(&mut c2, vec![t], "slots none push", None)
        };
        let (mut map2, sib_pack) = upload_all(&cold_api, &c2);
        map2.insert(sid.hex(), json!(c1_rec[0]));

        let r = push_body(&cold_api, &dev_tok, &p.name, "dev/b2661-slots-none", None, s2, &map2);
        assert_eq!(r.status, 409, "staged_slots -> None must answer 409, got {}: {}", r.status, String::from_utf8_lossy(&r.body));
        assert_sibling_intact(&sib_pack);
        hub.rt.block_on(hub.hub().objects.discard(pid, &[Arc::<str>::from(c1_pack.as_str()), Arc::<str>::from(sib_pack.as_str())])).unwrap();
    }

    // 2b. Vanished AFTER `staging()` succeeded (`Source::raw` `get_staged -> None` in push, and
    //     `take_uploads` `staged_declared -> None` and `staged_encoding -> None` in API commit),
    //     triggered deterministically on the Nth entry read (`start > 0`) after `staging()`'s
    //     index read (`start == 0`) -> 409 Conflict, sibling preserved!
    {
        // Push path (`Source::raw` `get_staged -> None`, 1st entry read):
        let (sid, sraw) = blob("MARKER-B2661-AFTER-STAGING-PUSH-2B\n");
        let up_c1 = api.upload(&dev_tok, &p.name, &[(sid, sraw)]);
        let c1_rec: Vec<String> = serde_json::from_value(up_c1.json()["receipts"].clone()).unwrap();
        let c1_pack = c1_rec[0].split_once('.').unwrap().1.to_string();

        let mut c2 = Craft::new(&api, &p.dev, &p.name, "main");
        c2.file("src/b2661_after_staging.txt", "MARKER-B2661-AFTER-STAGING-PUSH-2B\n");
        c2.objects.retain(|(id, _)| *id != sid);
        let s2 = {
            let t = c2.tip;
            snap(&mut c2, vec![t], "after staging push", None)
        };
        let (mut map2, sib_pack) = upload_all(&api, &c2);
        map2.insert(sid.hex(), json!(c1_rec[0]));

        vanish.schedule(veil_server::pack::key(pid, &c1_pack), 1);
        let r_push = push_body(&cold_api, &dev_tok, &p.name, "dev/b2661-after-staging", None, s2, &map2);
        assert_eq!(
            r_push.status,
            409,
            "Source::raw get_staged -> None must answer 409, got {}: {}",
            r_push.status,
            String::from_utf8_lossy(&r_push.body)
        );
        assert_sibling_intact(&sib_pack);
        hub.rt.block_on(hub.hub().objects.discard(pid, &[Arc::<str>::from(c1_pack.as_str()), Arc::<str>::from(sib_pack.as_str())])).unwrap();

        // API commit path (`take_uploads` `staged_declared -> None` on 1st entry read, and
        // `staged_encoding -> None` on 2nd entry read):
        for (entry_read, tag) in [(1usize, "DECLARED"), (2usize, "ENCODING")] {
            let (sid_a, sraw_a) = blob(&format!("MARKER-B2661-AFTER-STAGING-API-{tag}\n"));
            let up_a1 = api.upload(&dev_tok, &p.name, &[(sid_a, sraw_a)]);
            let a1_rec: Vec<String> = serde_json::from_value(up_a1.json()["receipts"].clone()).unwrap();
            let a1_pack = a1_rec[0].split_once('.').unwrap().1.to_string();
            let (sib_a, sib_a_raw) = blob(&format!("MARKER-B2661-AFTER-STAGING-API-SIB-{tag}\n"));
            let up_asib = api.upload(&dev_tok, &p.name, &[(sib_a, sib_a_raw)]);
            let asib_rec: Vec<String> = serde_json::from_value(up_asib.json()["receipts"].clone()).unwrap();
            let asib_pack = asib_rec[0].split_once('.').unwrap().1.to_string();
            let base = api.tips(Some(&dev_tok), &p.name).unwrap().branches["main"];

            vanish.schedule(veil_server::pack::key(pid, &a1_pack), entry_read);
            let r_api = cold_api.post_json(
                Some(&dev_tok),
                &format!("/v1/projects/{}/changes", p.name),
                &json!({
                    "base": base.hex(),
                    "description": format!("after staging api {tag}"),
                    "edits": [
                        {"path": "src/b2661_as_a1.txt", "put": {"object": sid_a.hex()}},
                        {"path": "src/b2661_as_a2.txt", "put": {"object": sib_a.hex()}},
                    ],
                    "receipts": {sid_a.hex(): a1_rec[0], sib_a.hex(): asib_rec[0]},
                }),
            );
            assert_eq!(
                r_api.status,
                409,
                "take_uploads ({tag}) -> None must answer 409, got {}: {}",
                r_api.status,
                String::from_utf8_lossy(&r_api.body)
            );
            assert_sibling_intact(&asib_pack);
            hub.rt.block_on(hub.hub().objects.discard(pid, &[Arc::<str>::from(a1_pack.as_str()), Arc::<str>::from(asib_pack.as_str())])).unwrap();
        }
    }
}


