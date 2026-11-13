//! The landing lease after its holder is gone (BUG-1970, cause 2;
//! `docs/HUB.md` §13.32 item 13): a holder holds a session advisory lock of
//! its lease's epoch, and once the database frees it (the holder's process
//! died, or its lock session ended) another server takes the lease over at
//! the next epoch at once, not when the lease expires; every change lands
//! exactly once, and the holder that lost the lease lands nothing more.

use std::time::{Duration, Instant};

use crate::{
    limits::{hold_branch, land_edit, project_id_of, release_branch, wait_ticket},
    support::*,
};

const LEASE: Duration = Duration::from_millis(veil_server::landing::LEASE_MS as u64);

/// `main`'s lease: holder, epoch, expiry, the epoch whose lock was taken,
/// and the database's clock now (milliseconds).
fn lease(hub: &TestHub, pid: i64) -> (String, i64, i64, Option<i64>, i64) {
    hub.rt
        .block_on(
            sqlx::query_as(
                "SELECT holder, epoch, expires_at, lock_epoch, (extract(epoch FROM clock_timestamp()) * 1000)::BIGINT \
                 FROM landing_leases WHERE project_id = $1 AND branch = 'main'",
            )
            .bind(pid)
            .fetch_one(&hub.hub().db),
        )
        .unwrap()
}

/// The descriptions of `main`'s first-parent line from its tip down to
/// `base` (not included), sorted: each change that landed, as many times as
/// it is on the line.
fn line_since(api: &Api, token: &str, project: &str, base: veil_core::ObjectId) -> Vec<String> {
    use veil_core::object::Object;
    let mut s = api.tips(Some(token), project).unwrap().branches["main"];
    let mut out = Vec::new();
    while s != base {
        assert!(out.len() < 50, "`main` does not come down to its base");
        let h = api.post_json(Some(token), &format!("/v1/projects/{project}/history"), &serde_json::json!({"tips": [s.hex()]}));
        assert_eq!(h.status, 200, "{}", String::from_utf8_lossy(&h.body));
        let (_, raw) = h.frames().into_iter().find(|(id, _)| *id == s).expect("the snapshot is in its history");
        let Object::Snapshot(snap) = Object::decode(&raw).unwrap() else { panic!("not a snapshot") };
        out.push(snap.description.as_str().to_string());
        s = snap.parents[0];
    }
    out.sort();
    out
}

/// Poll `main`'s lease from `hub` until its holder is not `holder`: the
/// new lease, and how long since `since` that took (bounded by the test:
/// each asserts its own bound on it).
fn wait_for_new_holder(hub: &TestHub, pid: i64, holder: &str, since: Instant) -> ((String, i64, i64, Option<i64>, i64), Duration) {
    loop {
        let l = lease(hub, pid);
        if l.0 != holder {
            return (l, since.elapsed());
        }
        assert!(since.elapsed() < Duration::from_secs(30), "the lease was never taken over: {l:?}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Wait until a server's batch of `main` of project `pid` waits at the
/// queue row the test's transaction (backend `held_pid`) locks: on
/// PostgreSQL the backend it blocks; YugabyteDB names no blocker, so there
/// a server holds the lease (not the test's hold) and some batch's update
/// of the queue is running.
pub(crate) fn wait_for_batch_at_row(hub: &TestHub, pid: i64, held_pid: i32) {
    let db = hub.hub().db.clone();
    let yugabyte = hub.rt.block_on(sqlx::query_scalar::<_, String>("SELECT version()").fetch_one(&db)).unwrap().contains("-YB-");
    let until = Instant::now() + Duration::from_secs(30);
    loop {
        let at_row: bool = hub
            .rt
            .block_on(
                sqlx::query_scalar(if yugabyte {
                    "SELECT EXISTS (SELECT 1 FROM landing_leases WHERE project_id = $1 AND branch = 'main' AND holder <> 'test' AND expires_at > 0) \
                     AND EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname = current_database() AND state = 'active' AND query LIKE 'UPDATE landing_queue AS q%' AND $2 >= 0)"
                } else {
                    "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname = current_database() AND $2 = ANY(pg_blocking_pids(pid)) AND query LIKE 'UPDATE landing_queue AS q%' AND $1 >= 0)"
                })
                .bind(pid)
                .bind(held_pid)
                .fetch_one(&db),
            )
            .unwrap();
        if at_row {
            return;
        }
        assert!(Instant::now() < until, "the batch never reached its entry's row");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn file_at_tip(hub: &TestHub, api: &Api, token: &str, project: &str, path: &str) -> String {
    let _ = hub;
    let tip = api.tips(Some(token), project).unwrap().branches["main"];
    let r = api.get(Some(token), &format!("/v1/projects/{project}/q/file?rev={}&path={path}", tip.hex()));
    assert_eq!(r.status, 200, "{path}: {}", String::from_utf8_lossy(&r.body));
    String::from_utf8_lossy(&r.body).into_owned()
}

/// BUG-1970, cause 2: the holder killed while it commits a batch. Its
/// connections close, the database rolls its batch back and frees its
/// lock, and the other server takes the lease over well before the lease
/// would have expired (it was 2 s and more); the batch the killed server
/// was committing lands once, by the other server, and so does the next.
#[test]
fn bug_1970_a_killed_holder_is_taken_over_before_its_lease_expires_and_its_batch_lands_once() {
    let a = TestHub::start();
    let p = setup_project(&a);
    let b = TestHub::beside(&a);
    let pid = project_id_of(&b, &p.name);
    let (api_a, api_b) = (a.api(), b.api());
    let dev = p.dev.token();
    let base = api_b.tips(Some(&dev), &p.name).unwrap().branches["main"];

    // `a`'s batch is held at its entry's row, which it writes in its commit.
    hold_branch(&b, pid, "main");
    let r = land_edit(&api_a, &dev, &p.name, base, "src/crash/one.txt", "one\n", false);
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["state"], "queued", "{}", r.json());
    let ticket = r.json()["ticket"].as_str().unwrap().to_string();
    let db = b.hub().db.clone();
    let mut held = b.rt.block_on(db.begin()).unwrap();
    b.rt.block_on(sqlx::query("SELECT 1 FROM landing_queue WHERE project_id = $1 AND ticket = $2 FOR UPDATE").bind(pid).bind(&ticket).fetch_one(&mut *held)).unwrap();
    let held_pid: i32 = b.rt.block_on(sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *held)).unwrap();
    release_branch(&b, pid, "main");
    wait_for_batch_at_row(&b, pid, held_pid);
    let (holder_a, epoch_a, _, lock_epoch, _) = lease(&b, pid);
    assert_ne!(holder_a, "test", "`a` holds the lease");
    assert_eq!(lock_epoch, Some(epoch_a), "`a` took its lease's lock first");

    drop(api_a);
    a.crash();
    let crashed = Instant::now();
    // The killed server's statement waiting at the row ends as a wait does
    // (a backend notices its client is gone only once it answers): its
    // transaction ends with it, never committed.
    b.rt.block_on(held.rollback()).unwrap();
    // The balancer sends the next landing to `b`.
    let r = land_edit(&api_b, &dev, &p.name, base, "src/crash/two.txt", "two\n", false);
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["state"], "queued", "{}", r.json());
    let ticket_two = r.json()["ticket"].as_str().unwrap().to_string();
    let ((holder_b, epoch_b, expires_b, lock_b, _), took) = wait_for_new_holder(&b, pid, &holder_a, crashed);
    eprintln!("bug_1970: the killed holder's lease was taken over {took:?} after the kill");
    assert_eq!(epoch_b, epoch_a + 1, "taken over at the next epoch: the killed holder is fenced");
    assert_eq!(lock_b, Some(epoch_b), "`b` took its own lock first");
    assert!(took < LEASE / 2, "taken over {took:?} after the kill: not well inside the lease ({LEASE:?})");
    let _ = (holder_b, expires_b);

    for t in [&ticket, &ticket_two] {
        let v = wait_ticket(&api_b, &dev, &p.name, t);
        assert_eq!(v["state"], "landed", "{t}: {v}");
    }
    assert_eq!(line_since(&api_b, &dev, &p.name, base), ["land src/crash/one.txt", "land src/crash/two.txt"], "each change landed exactly once");
    assert_eq!(file_at_tip(&b, &api_b, &dev, &p.name, "src/crash/one.txt"), "one\n");
    assert_eq!(file_at_tip(&b, &api_b, &dev, &p.name, "src/crash/two.txt"), "two\n");
    assert_eq!(lease(&b, pid).1, epoch_b, "no other takeover");
}

/// BUG-1970, cause 2: a live holder that keeps its lock is never taken
/// over; one whose lock session the database ended (its connection
/// dropped, a partition) is taken over at once, as a dead one is, and is
/// fenced: it lands nothing more, and what is sent to it lands once, by
/// the new holder.
#[test]
fn bug_1970_a_holder_whose_lock_session_ends_is_taken_over_at_once_and_fenced() {
    let a = TestHub::start();
    let p = setup_project(&a);
    let b = TestHub::beside(&a);
    let pid = project_id_of(&b, &p.name);
    let (api_a, api_b) = (a.api(), b.api());
    let dev = p.dev.token();
    let base = api_a.tips(Some(&dev), &p.name).unwrap().branches["main"];
    let tip = base;
    let r = land_edit(&api_a, &dev, &p.name, tip, "src/fence/one.txt", "one\n", true);
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["state"], "landed", "{}", r.json());
    let (holder_a, epoch_a, _, lock_epoch, _) = lease(&b, pid);
    assert_eq!(lock_epoch, Some(epoch_a), "`a` took its lease's lock first");

    // While `a` lives and keeps its lock, `b`'s landing is `a`'s to land.
    let tip = api_b.tips(Some(&dev), &p.name).unwrap().branches["main"];
    let r = land_edit(&api_b, &dev, &p.name, tip, "src/fence/two.txt", "two\n", true);
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["state"], "landed", "{}", r.json());
    std::thread::sleep(Duration::from_millis(700));
    let (h, e, ..) = lease(&b, pid);
    assert_eq!((h.as_str(), e), (holder_a.as_str(), epoch_a), "a live holder with its lock is not taken over");

    // The database ends `a`'s lock session; `a` itself goes on, renewing.
    let ended: Vec<bool> = b
        .rt
        .block_on(
            sqlx::query_scalar("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = current_database() AND application_name = $1")
                .bind(format!("{} {holder_a}", veil_server::landing::lease_lock::APPLICATION_NAME))
                .fetch_all(&b.hub().db),
        )
        .unwrap();
    assert_eq!(ended, vec![true], "`a`'s one lock session ended");
    // Ended once its backend is gone (terminating it only asks).
    let asked = Instant::now();
    loop {
        let left: i64 = b
            .rt
            .block_on(
                sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND application_name = $1")
                    .bind(format!("{} {holder_a}", veil_server::landing::lease_lock::APPLICATION_NAME))
                    .fetch_one(&b.hub().db),
            )
            .unwrap();
        if left == 0 {
            break;
        }
        assert!(asked.elapsed() < Duration::from_secs(10), "`a`'s lock session never ended");
        std::thread::sleep(Duration::from_millis(5));
    }
    let ended_at = Instant::now();
    let tip = api_b.tips(Some(&dev), &p.name).unwrap().branches["main"];
    let r = land_edit(&api_b, &dev, &p.name, tip, "src/fence/three.txt", "three\n", true);
    let landed_in = ended_at.elapsed();
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["state"], "landed", "{}", r.json());
    // `a`, alive, may land it before `b` asks for the lease (it lands what
    // it finds); `b`, asking, takes the lease over at once either way.
    let ((holder_b, epoch_b, _, lock_b, _), took) = wait_for_new_holder(&b, pid, &holder_a, ended_at);
    eprintln!("bug_1970: landed {landed_in:?}, and the lease taken over {took:?}, after the old holder's lock session ended");
    assert_eq!(epoch_b, epoch_a + 1, "at the next epoch: `a` is fenced");
    assert_eq!(lock_b, Some(epoch_b));
    assert!(landed_in < LEASE, "landed {landed_in:?} after: as late as the lease ({LEASE:?})");
    assert!(took < LEASE, "taken over {took:?} after: as late as the lease ({LEASE:?})");

    // `a` is fenced: a landing sent to it lands once, by `b`, at `b`'s epoch.
    let tip = api_a.tips(Some(&dev), &p.name).unwrap().branches["main"];
    let r = land_edit(&api_a, &dev, &p.name, tip, "src/fence/four.txt", "four\n", true);
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["state"], "landed", "{}", r.json());
    let (h, e, ..) = lease(&b, pid);
    assert_eq!((h.as_str(), e), (holder_b.as_str(), epoch_b), "`b` keeps the lease; `a` took nothing back");
    let landed: Vec<String> = ["four", "one", "three", "two"].iter().map(|f| format!("land src/fence/{f}.txt")).collect();
    assert_eq!(line_since(&api_b, &dev, &p.name, base), landed, "each change landed exactly once");
    for (path, text) in [("one", "one\n"), ("two", "two\n"), ("three", "three\n"), ("four", "four\n")] {
        assert_eq!(file_at_tip(&b, &api_b, &dev, &p.name, &format!("src/fence/{path}.txt")), text);
    }
}
