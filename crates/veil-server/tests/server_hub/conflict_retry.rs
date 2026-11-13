//! BUG-2340: a database conflict met by a statement of the object store
//! (`pack::Packs`, `store::Objects`: errors through `anyhow`) is retried as
//! any other, never answered "internal error". On YugabyteDB a push's and a
//! landing's `INSERT INTO packs` (its foreign key locks the pusher's
//! `people` row) failed so beside another test's long SERIALIZABLE
//! transaction (BUG-2341).

use std::{
    sync::mpsc,
    time::{Duration, Instant},
};

use veil_core::object::Object as O;

use crate::{limits::project_id_of, support::*};

/// A push's upload whose pack row waits on a lock past the database's
/// `lock_timeout` (the pusher's `people` row held `FOR UPDATE`, as a
/// conflicting transaction holds it) is run again and stored once the lock
/// is free: 200, never 500.
#[test]
fn bug_2340_an_upload_whose_pack_row_waits_out_a_lock_is_retried_not_an_internal_error() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let token = p.dev.token();
    let h = hub.hub();
    let person: i64 = hub
        .rt
        .block_on(sqlx::query_scalar("SELECT id FROM people WHERE name = $1").bind(&p.dev.name).fetch_one(&h.db))
        .unwrap();

    // Past the lock timeout (10 s): the first attempt's insert gives up.
    let hold = veil_server::db::LOCK_TIMEOUT + Duration::from_secs(2);
    let (locked, wait_locked) = mpsc::channel();
    let db = h.db.clone();
    let holder = hub.rt.spawn(async move {
        let mut tx = db.begin().await.unwrap();
        let got: i64 = sqlx::query_scalar("SELECT id FROM people WHERE id = $1 FOR UPDATE").bind(person).fetch_one(&mut *tx).await.unwrap();
        assert_eq!(got, person);
        locked.send(()).unwrap();
        tokio::time::sleep(hold).await;
        tx.commit().await.unwrap();
    });
    wait_locked.recv_timeout(Duration::from_secs(30)).expect("the people row locked");

    let started = Instant::now();
    let raw = O::Blob(b"bug 2340: stored once the lock is free\n".to_vec()).encode();
    let id = veil_core::ObjectId::hash(&raw);
    let up = api.upload(&token, &p.name, &[(id, raw)]);
    let took = started.elapsed();
    assert_eq!(up.status, 200, "the upload failed: {}", String::from_utf8_lossy(&up.body));
    assert_eq!(up.json()["receipts"].as_array().map(Vec::len), Some(1), "{}", String::from_utf8_lossy(&up.body));
    hub.rt.block_on(holder).unwrap();
    // It was held up by the lock (its pack row could not be written
    // before), so the conflict was met and retried, not missed.
    assert!(took >= hold - Duration::from_secs(1), "the upload did not wait for the lock ({took:?}): the test met no conflict");
    // Its pack is recorded, staged by the person.
    let rows: i64 = hub
        .rt
        .block_on(sqlx::query_scalar("SELECT count(*) FROM packs WHERE project_id = $1 AND person_id = $2").bind(project_id_of(&hub, &p.name)).bind(person).fetch_one(&h.db))
        .unwrap();
    assert!(rows >= 1, "no pack row of the upload");
}

