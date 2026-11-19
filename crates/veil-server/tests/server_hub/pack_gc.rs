//! Tests for object-kind validation (`BUG-2622`), staged-pack discard cache
//! hygiene (`BUG-2770`), and clean server shutdown (`BUG-2635`).
//!
//! Unreachable-object collection and online pack merging were removed for v1
//! (append-only storage, `objects` layout default; owner decision 2026-11-18).

use std::time::Duration;

use bytes::Bytes;
use serde_json::json;
use veil_core::{
    object::{EntryKind, Object, Tree, Visibility},
    ObjectId,
};

use crate::support::*;

fn project_id(hub: &TestHub, name: &str) -> i64 {
    hub.rt
        .block_on(sqlx::query_scalar::<_, i64>("SELECT id FROM projects WHERE name = $1").bind(name).fetch_one(&hub.hub().db))
        .unwrap()
}

fn make_blob(text: &str) -> (ObjectId, Bytes) {
    let raw = Bytes::from(Object::Blob(text.as_bytes().to_vec()).encode());
    (ObjectId::hash(&raw), raw)
}

/// On `main`, a directory two levels under `src/` with a file: the commit,
/// the directory's tree as stored, and the file's blob.
fn victim_directory(hub: &TestHub, p: &Project, pid: i64, content: &str) -> (ObjectId, Tree, ObjectId) {
    let api = hub.api();
    let h = hub.hub();
    let mut c = Craft::new(&api, &p.admin, &p.name, "main");
    c.file("src/victim/deep/file.txt", content);
    let before = c.tip;
    let (main1, r) = c.push_edited("main", Some(before), |_| {});
    assert_eq!(r.status, 200, "push main: {}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["results"][0]["ok"], json!(true), "push main ok: {}", String::from_utf8_lossy(&r.body));
    let get = |id: &ObjectId| Object::decode(&hub.rt.block_on(h.objects.get(pid, id)).unwrap().expect("stored")).unwrap();
    let Object::Snapshot(s) = get(&main1) else { panic!("a snapshot") };
    let mut at = s.tree;
    for part in ["src", "victim", "deep"] {
        let Object::Tree(t) = get(&at) else { panic!("a tree") };
        at = t.get(part).unwrap_or_else(|| panic!("no {part}")).id;
    }
    let Object::Tree(deep) = get(&at) else { panic!("a tree") };
    (main1, deep, make_blob(content).0)
}

/// BUG-2622, the push's end: an entry's object is of the entry's kind. A
/// file or symlink entry names a file's content (a blob, or a secret's
/// sealed envelope), a directory entry a tree, a conflict entry a conflict:
/// a push of anything else is refused, as is an API commit that puts a
/// tree at a file's path.
#[test]
fn bug_2622_a_push_or_an_api_commit_of_an_entry_whose_object_is_not_of_its_kind_is_refused() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let dev_tok = p.dev.token();
    let (_main1, deep, _blob) = victim_directory(&hub, &p, pid, "VICTIM-2622-KINDS\n");
    let branches = || api.tips(Some(&dev_tok), &p.name).unwrap().branches;

    // The member's ordinary push is accepted: what is refused below is the entry.
    let mut ok = Craft::new(&api, &p.dev, &p.name, "main");
    ok.file("src/ordinary-2622.txt", "ORDINARY-2622\n");
    let (_, r) = ok.push_edited("ordinary-2622", None, |_| {});
    assert_eq!(r.status, 200, "an ordinary push: {}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["results"][0]["ok"], json!(true), "an ordinary push is accepted: {}", String::from_utf8_lossy(&r.body));

    let refused = |what: &str, branch: &str, r: Reply, message: &str| {
        let body = String::from_utf8_lossy(&r.body).to_string();
        assert_eq!(r.status, 400, "{what}: refused: {body}");
        assert!(body.contains(message), "{what}: the refusal says why ({message}): {body}");
        assert!(!branches().contains_key(branch), "{what}: nothing was pushed");
    };
    // A file entry, and a symlink entry, naming a directory's tree.
    for (what, kind, branch) in [("a file entry naming a tree", EntryKind::File, "forge-file-2622"), ("a symlink entry naming a tree", EntryKind::Symlink, "forge-link-2622")] {
        let mut forge = Craft::new(&api, &p.dev, &p.name, "main");
        forge.set_kind("src/aaa-forged", Object::Tree(deep.clone()), kind, Visibility::Public);
        let (_, r) = forge.push_edited(branch, None, |_| {});
        refused(what, branch, r, "'src/aaa-forged': a file entry names something that is not a file's content");
    }
    // A directory entry naming a file's blob.
    {
        let mut forge = Craft::new(&api, &p.dev, &p.name, "main");
        let id = forge.put(Object::Blob(b"NOT-A-DIRECTORY-2622\n".to_vec()));
        forge.refer_dir("src/aaa-notadir", id);
        let (_, r) = forge.push_edited("forge-dir-2622", None, |_| {});
        refused("a directory entry naming a blob", "forge-dir-2622", r, "'src/aaa-notadir': a directory entry names something that is not a directory");
    }
    // A conflict entry naming a blob.
    {
        let mut forge = Craft::new(&api, &p.dev, &p.name, "main");
        forge.set_kind("src/aaa-conflict", Object::Blob(b"NOT-A-CONFLICT-2622\n".to_vec()), EntryKind::Conflict, Visibility::Public);
        let (_, r) = forge.push_edited("forge-conflict-2622", None, |_| {});
        refused("a conflict entry naming a blob", "forge-conflict-2622", r, "'src/aaa-conflict': a conflict entry names something else");
    }
    // An API commit that puts the tree, uploaded first, at a file's path.
    {
        let raw = Object::Tree(deep.clone()).encode_with(veil_core::object::TreeEncoding::Binary);
        let id = ObjectId::hash(&raw);
        let up = api.upload(&dev_tok, &p.name, &[(id, raw)]);
        assert_eq!(up.status, 200, "the upload: {}", String::from_utf8_lossy(&up.body));
        let base = branches()["main"];
        let receipt = up.json()["receipts"][0].as_str().expect("the upload's receipt").to_string();
        let r = api.post_json(
            Some(&dev_tok),
            &format!("/v1/projects/{}/changes", p.name),
            &json!({"base": base.hex(), "edits": [{"path": "src/aaa-forged", "put": {"object": id.hex()}}], "receipts": {id.hex(): receipt}}),
        );
        let body = String::from_utf8_lossy(&r.body).to_string();
        assert_eq!(r.status, 400, "an API commit putting a tree at a file's path: refused: {body}");
        assert!(body.contains("'src/aaa-forged': the object is not a file's content"), "the refusal says why: {body}");
    }
}

/// BUG-2770: calling `Packs::discard` with a pack that was already promoted
/// from `STAGED` to `LISTED` leaves the DB row and stored blob intact, and
/// must NOT poison the in-memory `staged` LRU cache with a `None` tombstone
/// for that pack (only packs actually transitioned to `DISCARDED` by the DB
/// `UPDATE ... RETURNING name` may be tombstoned).
#[test]
fn bug_2770_discard_on_listed_pack_does_not_tombstone_staged_cache() {
    let hub = TestHub::start_own();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let h = hub.hub();

    // Find admin's person_id to stage two packs under it.
    let person_id: i64 = hub
        .rt
        .block_on(sqlx::query_scalar("SELECT id FROM people LIMIT 1").fetch_one(&h.db))
        .unwrap();

    let raw1 = bytes::Bytes::from(veil_core::object::Object::Blob(b"BUG-2770-LISTED-BLOB\n".to_vec()).encode());
    let id1 = ObjectId::hash(&raw1);
    let raw2 = bytes::Bytes::from(veil_core::object::Object::Blob(b"BUG-2770-DISCARDED-BLOB\n".to_vec()).encode());
    let id2 = ObjectId::hash(&raw2);

    let listed_pack = hub.rt.block_on(h.objects.stage(pid, person_id, vec![(id1, raw1)])).unwrap();
    let abandoned_pack = hub.rt.block_on(h.objects.stage(pid, person_id, vec![(id2, raw2)])).unwrap();

    // Simulate a pre-existing `LISTED` pack alongside a `STAGED` upload pack.
    hub.rt
        .block_on(
            sqlx::query("UPDATE packs SET state = 1 WHERE project_id = $1 AND name = $2")
                .bind(pid)
                .bind(&*listed_pack)
                .execute(&h.db),
        )
        .unwrap();

    // Discard both names together: DB only transitions `abandoned_pack` to DISCARDED.
    hub.rt
        .block_on(h.objects.discard(pid, &[listed_pack.clone(), abandoned_pack.clone()]))
        .unwrap();

    // `abandoned_pack` was genuinely discarded: tombstoned in cache and gone from DB/store.
    assert!(
        hub.rt.block_on(h.objects.staged_slots(pid, &abandoned_pack, &[id2])).unwrap().is_none(),
        "genuinely discarded pack must return None"
    );

    // `listed_pack` stayed LISTED: its staged-cache entry must NOT be poisoned with None.
    assert!(
        h.objects.packs().staged_cached(pid, &listed_pack).is_some(),
        "already-listed pack must not be tombstoned to None in staged cache"
    );
    assert!(
        hub.rt.block_on(h.objects.staged_slots(pid, &listed_pack, &[id1])).unwrap().is_some(),
        "already-listed pack must still resolve via staged_slots"
    );
}

/// BUG-2635: a clean server stop (`Running::stop`) must stop and wait for
/// background `derive` (`landed` and `resume`) and `query::graph` fills (both
/// row fills and leased file-history fills) before returning, so no background
/// writer keeps running or writing to the database after `Running::stop` returns.
#[test]
fn bug_2635_clean_stop_stops_and_waits_for_deriver_and_viewer_graph_fills() {
    let mut hub = TestHub::start_own();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let h = hub.hub();
    let api = hub.api();

    // Hold the project's derive advisory lock on a separate connection before
    // pushing a new branch so `snap_b` stays underived until we unblock it.
    const DERIVE_LOCK_BASE: i64 = 0x7665_696c_6472_0000;
    let lock_key = DERIVE_LOCK_BASE ^ pid;
    let mut derive_lock = hub.rt.block_on(h.db.acquire()).unwrap();
    let got_lock: bool = hub
        .rt
        .block_on(sqlx::query_scalar("SELECT pg_try_advisory_lock($1)").bind(lock_key).fetch_one(&mut *derive_lock))
        .unwrap();
    assert!(got_lock, "test acquired project derive advisory lock");

    let mut c = Craft::new(&api, &p.admin, &p.name, "main");
    c.file("src/stop-2635.txt", "hello-2635\n");
    let (snap_b, r) = c.push_edited("b_stop", None, |_| {});
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["results"][0]["ok"], serde_json::json!(true));

    // Confirm `snap_b` is not derived yet.
    let pre_graph: i64 = hub
        .rt
        .block_on(
            sqlx::query_scalar("SELECT COUNT(*) FROM graph WHERE project_id = $1 AND snapshot = $2")
                .bind(pid)
                .bind(snap_b.hex())
                .fetch_one(&h.db),
        )
        .unwrap();
    assert_eq!(pre_graph, 0, "snap_b must start underived while derive lock is held");

    // Start both `derive::landed` and `derive::resume` in the background while
    // the derive lock is held.
    veil_server::derive::landed(&h, pid, vec!["b_stop".to_string()]);
    let resume_handle = hub.rt.spawn(veil_server::derive::resume(h.clone(), Some(pid)));

    // Load project and a fresh uncached viewer (`Viewer::default()`), block
    // row fills via `hold_row_fills()` and file-history fills via an external
    // `view_fills` lease, then start both background fills.
    let project = hub.rt.block_on(async {
        let mut c = h.db.acquire().await.unwrap();
        veil_server::perm::load_project(&mut c, &p.name).await.unwrap().unwrap()
    });
    let anyone = veil_server::perm::Viewer::default();
    let vk = project.view(&anyone).key();
    let row_hold = hub.rt.block_on(h.query.hold_row_fills());
    hub.rt
        .block_on(
            sqlx::query(
                "INSERT INTO view_fills (project_id, view_key, holder, expires_at) VALUES ($1, $2, 'external-blocker', $3) \
                 ON CONFLICT (project_id, view_key) DO UPDATE SET holder = EXCLUDED.holder, expires_at = EXCLUDED.expires_at",
            )
            .bind(pid)
            .bind(&vk)
            .bind(veil_core::now_millis() + 60_000)
            .execute(&h.db),
        )
        .unwrap();

    let pre_vg: i64 = hub
        .rt
        .block_on(
            sqlx::query_scalar("SELECT COUNT(*) FROM view_graph WHERE project_id = $1 AND view_key = $2")
                .bind(pid)
                .bind(&vk)
                .fetch_one(&h.db),
        )
        .unwrap();
    let pre_vg_snap_b: i64 = hub
        .rt
        .block_on(
            sqlx::query_scalar("SELECT COUNT(*) FROM view_graph WHERE project_id = $1 AND view_key = $2 AND real_id = $3")
                .bind(pid)
                .bind(&vk)
                .bind(snap_b.hex())
                .fetch_one(&h.db),
        )
        .unwrap();
    assert_eq!(pre_vg_snap_b, 0, "snap_b must not be in view_graph before fills start");

    hub.rt
        .block_on(veil_server::query::graph::prefill_rows(&h, &project, &anyone, &[snap_b]))
        .unwrap();
    hub.rt
        .block_on(veil_server::query::graph::prefill(&h, &project, &anyone, &[snap_b]))
        .unwrap();

    let wait_until = std::time::Instant::now() + Duration::from_secs(5);
    while h.query.fills_started(pid) == 0 || h.query.file_fills_started(pid) == 0 {
        assert!(std::time::Instant::now() < wait_until, "both row and file fills must start");
        std::thread::sleep(Duration::from_millis(10));
    }
    // Give `derive::landed` / `derive::resume` time to enter `locked_landing`.
    std::thread::sleep(Duration::from_millis(150));

    // Clean stop: must stop and wait for all derive and viewer-graph fill tasks
    // promptly (well under 5 s).
    let stop_started = std::time::Instant::now();
    hub.stop_serving();
    let stop_took = stop_started.elapsed();
    assert!(stop_took < Duration::from_secs(5), "clean stop took too long: {stop_took:?}");

    // `derive::resume` must already have exited by the time `Running::stop` returned.
    assert!(
        resume_handle.is_finished(),
        "derive::resume was still running after Running::stop returned"
    );

    // Release every external blocker after `Running::stop` returned. If any
    // zombie derive or viewer-graph fill task survived `Running::stop`, it will
    // wake up and write rows now.
    hub.rt.block_on(async {
        let unlocked: bool = sqlx::query_scalar("SELECT pg_advisory_unlock($1)")
            .bind(lock_key)
            .fetch_one(&mut *derive_lock)
            .await
            .unwrap();
        assert!(unlocked);
        drop(derive_lock);
    });
    drop(row_hold);
    let check_db = hub.rt.block_on(veil_server::db::connect(hub.database_url(), 2)).unwrap();
    hub.rt
        .block_on(
            sqlx::query("DELETE FROM view_fills WHERE project_id = $1 AND view_key = $2 AND holder = 'external-blocker'")
                .bind(pid)
                .bind(&vk)
                .execute(&check_db),
        )
        .unwrap();

    // Wait past locked_landing's 100 ms sleep and leased_fill's 250 ms sleep.
    std::thread::sleep(Duration::from_millis(450));

    let post_graph: i64 = hub
        .rt
        .block_on(
            sqlx::query_scalar("SELECT COUNT(*) FROM graph WHERE project_id = $1 AND snapshot = $2")
                .bind(pid)
                .bind(snap_b.hex())
                .fetch_one(&check_db),
        )
        .unwrap();
    let post_vg: i64 = hub
        .rt
        .block_on(
            sqlx::query_scalar("SELECT COUNT(*) FROM view_graph WHERE project_id = $1 AND view_key = $2")
                .bind(pid)
                .bind(&vk)
                .fetch_one(&check_db),
        )
        .unwrap();
    let post_vg_snap_b: i64 = hub
        .rt
        .block_on(
            sqlx::query_scalar("SELECT COUNT(*) FROM view_graph WHERE project_id = $1 AND view_key = $2 AND real_id = $3")
                .bind(pid)
                .bind(&vk)
                .bind(snap_b.hex())
                .fetch_one(&check_db),
        )
        .unwrap();
    let post_vf: i64 = hub
        .rt
        .block_on(
            sqlx::query_scalar("SELECT COUNT(*) FROM view_fills WHERE project_id = $1 AND view_key = $2")
                .bind(pid)
                .bind(&vk)
                .fetch_one(&check_db),
        )
        .unwrap();
    hub.rt.block_on(check_db.close());

    assert_eq!(post_graph, 0, "zombie deriver wrote graph rows after Running::stop returned");
    assert_eq!(post_vg_snap_b, 0, "zombie viewer-graph fill wrote snap_b view_graph row after Running::stop returned");
    assert_eq!(post_vg, pre_vg, "zombie viewer-graph fill wrote view_graph rows after Running::stop returned");
    assert_eq!(post_vf, 0, "zombie file-history fill took view_fills lease after Running::stop returned");
}
