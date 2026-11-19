//! Staged/discarded upload container sweeping (`pack_gc::sweep_project`,
//! `pack_gc::schedule_sweep`, `pack_gc::projects_to_sweep`): abandoned staged
//! uploads are swept without a push while pre-existing `LISTED` packs stay
//! readable and untouched, and a push never commits an upload swept while it
//! ran (`BUG-2310`).

use std::{
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

use bytes::Bytes;
use veil_core::{object::Object, ObjectId};
use veil_server::{
    pack::LISTED,
    pack_gc::{self, SweepOptions},
};

use crate::{limits::project_id_of, support::*};

fn tip_of(api: &Api, token: &str, project: &str, branch: &str) -> Option<ObjectId> {
    api.tips(Some(token), project).unwrap().branches.get(branch).copied()
}

/// Push one new file to `branch`: the new snapshot.
fn push_file(api: &Api, p: &Project, branch: &str, path: &str) -> ObjectId {
    let tok = p.admin.token();
    let had = tip_of(api, &tok, &p.name, branch);
    let mut c = Craft::new(api, &p.admin, &p.name, if had.is_some() { branch } else { "main" });
    c.file(path, &format!("{path}\n"));
    let (id, r) = c.push_edited(branch, had, |_| {});
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["results"][0]["ok"], true, "{}", String::from_utf8_lossy(&r.body));
    id
}

/// Every one of `ids` read through `hub`'s object store: none may be missing.
fn read_all(hub: &TestHub, project: i64, ids: &[ObjectId], when: &str) {
    let h = hub.hub();
    let got = hub.rt.block_on(h.objects.get_many(project, ids)).expect("the objects are read");
    for (id, g) in ids.iter().zip(&got) {
        assert!(g.is_some(), "{when}: object {} missing", id.hex());
    }
}

/// The names of `project`'s packs in `state`.
fn pack_names(hub: &TestHub, project: i64, state: i16) -> Vec<String> {
    hub.rt
        .block_on(
            sqlx::query_scalar("SELECT name FROM packs WHERE project_id = $1 AND state = $2 ORDER BY name")
                .bind(project)
                .bind(state)
                .fetch_all(&hub.hub().db),
        )
        .unwrap()
}

/// Whether pack `name` of `project` is still in storage.
fn stored(hub: &TestHub, project: i64, name: &str) -> bool {
    let h = hub.hub();
    hub.rt.block_on(h.objects.blob_store().exists(&veil_server::pack::key(project, name))).expect("storage answers")
}

/// BUG-2280 (staged upload sweep): an abandoned staged upload past
/// `DEFAULT_STAGED_GRACE_MS` is found by another server's start-up scan
/// (`pack_gc::projects_to_sweep`, then `schedule_sweep`, as `sweep_scan` does)
/// and swept with no push since: the staged container is discarded (its
/// storage object deleted at once), its row deleted once `DEFAULT_PACK_GRACE_MS`
/// has passed, and pre-existing `LISTED` packs are untouched and readable on
/// both servers.
#[test]
fn abandoned_staged_upload_is_swept_without_a_push() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id_of(&hub, &p.name);
    let h = hub.hub();
    let mut ids = Vec::new();
    for i in 0..4 {
        let raw = Bytes::from(Object::Blob(format!("legacy listed pack object {i}").into_bytes()).encode());
        let id = ObjectId::hash(&raw);
        ids.push(id);
        let enc = veil_server::store::encode(raw);
        hub.rt.block_on(async {
            let (name, held) = h.objects.put_pack(pid, 1, vec![(id, enc)]).await.expect("the pack is stored");
            let r = sqlx::query("UPDATE packs SET state = $3 WHERE project_id = $1 AND name = $2")
                .bind(pid)
                .bind(&*name)
                .bind(LISTED)
                .execute(&h.db)
                .await
                .expect("the pack is listed");
            assert_eq!(r.rows_affected(), 1);
            h.objects.listed_here(pid, vec![(name, held.index.clone())]);
        });
    }
    let listed_before = pack_names(&hub, pid, LISTED);
    assert_eq!(listed_before.len(), 4, "{listed_before:?}");

    // Stage an abandoned upload container and age it past `DEFAULT_STAGED_GRACE_MS`.
    let api = hub.api();
    let abandoned_raw = Object::Blob(b"abandoned upload secret payload\n".to_vec()).encode();
    let abandoned_id = ObjectId::hash(&abandoned_raw);
    let up = api.upload(&p.dev.token(), &p.name, &[(abandoned_id, abandoned_raw)]);
    assert_eq!(up.status, 200, "{}", String::from_utf8_lossy(&up.body));
    let receipts: Vec<String> = serde_json::from_value(up.json()["receipts"].clone()).unwrap();
    let staged_name = receipts[0].split_once('.').unwrap().1.to_string();
    assert_eq!(pack_names(&hub, pid, 0), vec![staged_name.clone()]);
    assert!(stored(&hub, pid, &staged_name), "the staged upload container was written");
    hub.rt
        .block_on(
            sqlx::query("UPDATE packs SET created_at = created_at - $2 WHERE project_id = $1 AND name = $3")
                .bind(pid)
                .bind(2 * pack_gc::DEFAULT_STAGED_GRACE_MS)
                .bind(&staged_name)
                .execute(&h.db),
        )
        .expect("the staged upload is aged");

    // Another server starts and discovers the project via `projects_to_sweep`.
    let fresh = TestHub::beside(&hub);
    let f = fresh.hub();
    let due = fresh.rt.block_on(pack_gc::projects_to_sweep(&f)).expect("the look runs");
    assert!(due.contains(&pid), "the start-up look finds the project");
    fresh.rt.block_on(async { pack_gc::schedule_sweep(&f, pid) });
    let until = Instant::now() + pack_gc::SWEEP_RECHECK + Duration::from_secs(20);
    while (!pack_names(&hub, pid, 0).is_empty() || stored(&hub, pid, &staged_name)) && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(pack_names(&hub, pid, 0).is_empty(), "the staged upload is no longer staged");
    assert!(!stored(&hub, pid, &staged_name), "the staged upload's storage object is deleted");
    assert_eq!(pack_names(&hub, pid, 2), vec![staged_name], "its row is discarded, kept for the grace period");

    // The grace period passes: the discarded row goes.
    let aged = hub
        .rt
        .block_on(
            sqlx::query("UPDATE packs SET discarded_at = discarded_at - $2 WHERE project_id = $1 AND state = 2")
                .bind(pid)
                .bind(2 * pack_gc::DEFAULT_PACK_GRACE_MS)
                .execute(&h.db),
        )
        .expect("the discarded row is aged");
    assert_eq!(aged.rows_affected(), 1);
    let until = Instant::now() + pack_gc::SWEEP_RECHECK + Duration::from_secs(20);
    while !pack_names(&hub, pid, 2).is_empty() && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(pack_names(&hub, pid, 2).is_empty(), "the discarded row is deleted after its grace period");
    assert!(f.pack_gc.sweeps.load(Ordering::Relaxed) >= 2, "the other server's sweeper swept twice");
    assert_eq!(pack_names(&hub, pid, LISTED), listed_before, "the pre-existing listed packs are untouched");
    read_all(&hub, pid, &ids, "after the sweep");
    read_all(&fresh, pid, &ids, "after the sweep, another server");

    // Nothing is left to sweep: the sweeper stopped and the look finds nothing.
    let due = fresh.rt.block_on(pack_gc::projects_to_sweep(&f)).expect("the look runs");
    assert!(!due.contains(&pid), "nothing of the project is left to sweep");
}

/// BUG-2310: an upload a sweep discarded past its staged grace period
/// (`DEFAULT_STAGED_GRACE_MS`), and whose row it then deleted past the
/// pack grace period, is never committed by a push that named it before
/// the sweep: the push is held at its commit transaction (the branch row
/// locked) while the sweeps run, as a sweeper does on
/// a server other than the one with the upload's index in hand. It is
/// refused with "push again", the branch does not move and no row remains
/// for the deleted upload.
#[test]
fn bug_2310_a_push_never_lists_an_upload_swept_while_it_ran() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id_of(&hub, &p.name);
    let api = hub.api();
    push_file(&api, &p, "slow", "src/first.txt");
    let h = hub.hub();
    hub.rt.block_on(pack_gc::flush_purged(&h)).unwrap();
    let uploads = |hub: &TestHub| -> Vec<(String, i16)> {
        hub.rt
            .block_on(
                sqlx::query_as("SELECT name, state FROM packs WHERE project_id = $1 AND person_id IS NOT NULL AND state <> 1")
                    .bind(pid)
                    .fetch_all(&hub.hub().db),
            )
            .unwrap()
    };
    assert!(uploads(&hub).is_empty(), "no upload is left staged");
    let tip = tip_of(&api, &p.admin.token(), &p.name, "slow");
    // The branch row held: the push waits at its commit transaction's
    // branch UPDATE.
    let mut held = hub.rt.block_on(h.db.begin()).expect("a transaction");
    let locked: String = hub
        .rt
        .block_on(
            sqlx::query_scalar("SELECT target FROM branches WHERE project_id = $1 AND name = 'slow' FOR UPDATE")
                .bind(pid)
                .fetch_one(&mut *held),
        )
        .expect("the branch row is locked");
    assert_eq!(locked, tip.expect("tip").hex());
    std::thread::scope(|s| {
        let pushing = s.spawn(|| {
            let mut c = Craft::new(&api, &p.admin, &p.name, "slow");
            c.file("src/second.txt", "second\n");
            c.push_edited("slow", tip, |_| {}).1
        });
        let until = Instant::now() + Duration::from_secs(30);
        while uploads(&hub).is_empty() && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(50));
        }
        let up = uploads(&hub);
        assert_eq!(up.len(), 1, "the push uploaded one pack: {up:?}");
        assert_eq!(up[0].1, 0, "staged");
        // The push reaches its commit transaction.
        std::thread::sleep(Duration::from_secs(3));
        assert!(!pushing.is_finished(), "the push waits at its commit transaction");
        // An hour passes: another server's sweep discards the upload and,
        // once the grace period has passed, deletes its row.
        let other = TestHub::beside(&hub);
        let o = other.hub();
        other.rt.block_on(async {
            sqlx::query("UPDATE packs SET created_at = created_at - $2 WHERE project_id = $1 AND name = $3")
                .bind(pid)
                .bind(2 * pack_gc::DEFAULT_STAGED_GRACE_MS)
                .bind(&up[0].0)
                .execute(&o.db)
                .await
                .expect("the upload is aged");
            let r = pack_gc::sweep_project(&o, pid, SweepOptions::default()).await.expect("the sweep runs");
            assert_eq!(r.staged_packs_swept, 1, "the upload is discarded: {r:?}");
            sqlx::query("UPDATE packs SET discarded_at = discarded_at - $2 WHERE project_id = $1 AND name = $3")
                .bind(pid)
                .bind(2 * pack_gc::DEFAULT_PACK_GRACE_MS)
                .bind(&up[0].0)
                .execute(&o.db)
                .await
                .expect("the discarded row is aged");
            let r = pack_gc::sweep_project(&o, pid, SweepOptions::default()).await.expect("the sweep runs");
            assert_eq!(r.discarded_packs_swept, 1, "the upload's row is deleted: {r:?}");
        });
        assert!(!stored(&hub, pid, &up[0].0), "the upload's storage object is deleted");
        hub.rt.block_on(held.rollback()).expect("the epoch row is released");
        let r = pushing.join().unwrap();
        assert_eq!(r.status, 409, "{}", String::from_utf8_lossy(&r.body));
        assert!(String::from_utf8_lossy(&r.body).contains("push again"), "{}", String::from_utf8_lossy(&r.body));
        let rows: i64 = hub
            .rt
            .block_on(sqlx::query_scalar("SELECT count(*) FROM packs WHERE project_id = $1 AND name = $2").bind(pid).bind(&up[0].0).fetch_one(&h.db))
            .unwrap();
        assert_eq!(rows, 0, "no row lists the deleted upload");
        assert_eq!(tip_of(&api, &p.admin.token(), &p.name, "slow"), tip, "the branch did not move");
    });
}
