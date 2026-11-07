//! Request-path caches (milestone S4, `docs/HUB.md` §13.13): a cache never
//! serves a decision that a permission change has made stale, on any server.
//! Two servers on one database (the normal deployment): whatever changes
//! someone's access, through either server or straight in the database, their
//! very next request to either server is decided by the new access.

use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use serde_json::json;

use crate::support::*;

/// Can the holder of `token` read the billing folder, through `api`? Two
/// probes, through the session, permission, tips, resolution and memo
/// caches: who-has-access (answered only to readers) and their projected
/// history (the billing-only change's description is in it only for
/// readers). Both must agree.
fn reads_billing(api: &Api, token: &str, project: &str) -> bool {
    let access = api.get(Some(token), &format!("/v1/projects/{project}/access?path={BILL_DIR}"));
    let tips = api.get(Some(token), &format!("/v1/projects/{project}/tips"));
    let history = (tips.status == 200).then(|| {
        let tip = tips.json()["branches"]["main"].as_str().unwrap().to_string();
        api.post_json(Some(token), &format!("/v1/projects/{project}/history"), &json!({"tips": [tip]}))
    });
    let sees = history.as_ref().is_some_and(|h| h.status == 200 && has_marker(&[("history".into(), h.body.clone())], DESC_MARK));
    assert!(
        matches!(access.status, 200 | 404 | 401 | 403),
        "unexpected answer {}: {}",
        access.status,
        String::from_utf8_lossy(&access.body)
    );
    assert_eq!(access.status == 200, sees, "the access route and projected history disagree");
    sees
}

/// The billing check on both servers, several times (so every cache is warm
/// before a change, and every later request is checked after it).
fn both(apis: &[&Api; 2], token: &str, project: &str) -> [bool; 2] {
    let mut out = [false; 2];
    for (i, api) in apis.iter().enumerate() {
        let first = reads_billing(api, token, project);
        for _ in 0..3 {
            assert_eq!(reads_billing(api, token, project), first, "answers changed with nothing changing");
        }
        out[i] = first;
    }
    out
}

fn sql(hub: &TestHub, q: &str) -> u64 {
    let h = hub.hub();
    hub.rt.block_on(sqlx::query(q).execute(&h.db)).unwrap().rows_affected()
}

fn member(api: &Api, admin: &str, project: &str, group: &str, who: &str, add: bool) {
    let path = format!("/v1/projects/{project}/groups/{group}/members{}", if add { "" } else { "/remove" });
    let r = api.post_json(Some(admin), &path, &json!({"people": [who]}));
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
}

#[test]
fn every_access_change_reaches_every_server_at_the_next_request() {
    let a = TestHub::start();
    let b = TestHub::beside(&a);
    let p = setup_project(&a);
    let (api_a, api_b) = (a.api(), b.api());
    let apis = [&api_a, &api_b];
    let admin = p.admin.token();
    let fin_id = p.fin.identity();
    let mut fin = p.fin.token();
    let fin_person: i64 = a.rt.block_on(sqlx::query_scalar("SELECT id FROM people WHERE name = $1").bind(&p.fin.name).fetch_one(&a.hub().db)).unwrap();
    let pid: i64 = a.rt.block_on(sqlx::query_scalar("SELECT id FROM projects WHERE name = $1").bind(&p.name).fetch_one(&a.hub().db)).unwrap();
    assert_eq!(both(&apis, &fin, &p.name), [true, true], "finance reads billing on both servers");
    assert_eq!(both(&apis, &p.dev.token(), &p.name), [false, false], "devs never do");

    // 1. Removed from the group through one server: refused on both.
    member(&api_a, &admin, &p.name, "finance", &p.fin.name, false);
    assert_eq!(both(&apis, &fin, &p.name), [false, false], "removal from finance");
    member(&api_b, &admin, &p.name, "finance", &p.fin.name, true);
    assert_eq!(both(&apis, &fin, &p.name), [true, true], "added back through the other server");

    // 2. The admin's push takes billing from finance (a policy change).
    p.admin.ok(&p.dir, &["access", &format!("{BILL_DIR}/"), &p.carol.name]);
    p.admin.commit_main(&p.dir, "billing to carol only");
    p.admin.ok(&p.dir, &["push"]);
    assert_eq!(both(&apis, &fin, &p.name), [false, false], "policy change");
    p.admin.ok(&p.dir, &["access", &format!("{BILL_DIR}/"), "finance"]);
    p.admin.commit_main(&p.dir, "billing back to finance");
    p.admin.ok(&p.dir, &["push"]);
    assert_eq!(both(&apis, &fin, &p.name), [true, true], "policy restored");

    // 3. The group deleted; then made again (it rebinds the line) and refilled.
    let r = api_a.agent_delete(&admin, &format!("/v1/projects/{}/groups/finance", p.name));
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(both(&apis, &fin, &p.name), [false, false], "group deleted");
    assert_eq!(api_b.post_json(Some(&admin), &format!("/v1/projects/{}/groups/finance", p.name), &json!({})).status, 200);
    assert_eq!(both(&apis, &fin, &p.name), [false, false], "a new, empty group gives nobody anything");
    member(&api_b, &admin, &p.name, "finance", &p.fin.name, true);
    assert_eq!(both(&apis, &fin, &p.name), [true, true], "group made again");

    // 4. An admin bars the device from the project (BUG-843).
    let r = api_a.post_json(Some(&admin), "/v1/devices/remove", &json!({"device": fin_id.public_id(), "project": p.name}));
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    for api in apis {
        let r = api.get(Some(&fin), &format!("/v1/projects/{}/tips", p.name));
        assert_eq!(r.status, 403, "a barred device: {}", String::from_utf8_lossy(&r.body));
    }
    assert_eq!(sql(&a, &format!("DELETE FROM device_bars WHERE project_id = {pid}")), 1);
    assert_eq!(both(&apis, &fin, &p.name), [true, true], "the bar lifted (straight in the database)");

    // 5. Written straight in the database, as a route written later or an
    //    operator would: the triggers bump the epochs all the same.
    sql(&a, &format!("DELETE FROM group_members WHERE person_id = {fin_person}"));
    assert_eq!(both(&apis, &fin, &p.name), [false, false], "membership deleted in the database");
    member(&api_a, &admin, &p.name, "finance", &p.fin.name, true);
    sql(&a, &format!("UPDATE projects SET policy_bindings = '{{}}' WHERE id = {pid}"));
    assert_eq!(both(&apis, &fin, &p.name), [false, false], "bindings changed in the database");

    // 6. Admin rights taken away (no route does it yet).
    let admin_person: i64 = a.rt.block_on(sqlx::query_scalar("SELECT person_id FROM project_admins WHERE project_id = $1").bind(pid).fetch_one(&a.hub().db)).unwrap();
    for api in apis {
        assert!(api.tips(Some(&admin), &p.name).unwrap().admin);
    }
    sql(&a, &format!("DELETE FROM project_admins WHERE project_id = {pid}"));
    for api in apis {
        assert!(api.tips(Some(&admin), &p.name).is_none_or(|t| !t.admin), "no longer an admin");
        let r = api.post_json(Some(&admin), &format!("/v1/projects/{}/groups/ops", p.name), &json!({}));
        assert_eq!(r.status, 403, "creating a group needs an admin");
    }
    sql(&a, &format!("INSERT INTO project_admins (project_id, person_id) VALUES ({pid}, {admin_person})"));

    // 7. Signing out (the session row deleted) and removing a device: 401
    //    on both servers, never anyone on Earth's answer.
    for api in apis {
        assert_eq!(api.get(Some(&fin), &format!("/v1/projects/{}/tips", p.name)).status, 200);
    }
    sql(&a, &format!("DELETE FROM sessions WHERE person_id = {fin_person}"));
    for api in apis {
        assert_eq!(api.get(Some(&fin), &format!("/v1/projects/{}/tips", p.name)).status, 401, "signed out");
    }
    fin = api_b.login(&fin_id, None).expect("signs in again");
    for api in apis {
        assert_eq!(api.get(Some(&fin), &format!("/v1/projects/{}/tips", p.name)).status, 200);
    }
    sql(&a, &format!("UPDATE devices SET removed_at = 1 WHERE person_id = {fin_person}"));
    for api in apis {
        assert_eq!(api.get(Some(&fin), &format!("/v1/projects/{}/tips", p.name)).status, 401, "device removed");
        assert_eq!(api.get(Some(&fin), &format!("/v1/people/{}/devices", p.fin.name)).status, 401, "on every route");
    }
}

/// Under load: readers hammer both servers while an admin removes them
/// through one; every request that starts after the removal returned is
/// refused, on both servers.
#[test]
fn revocation_under_load_refuses_every_later_request() {
    let a = TestHub::start();
    let b = TestHub::beside(&a);
    let p = setup_project(&a);
    let admin = p.admin.token();
    let fin = p.fin.token();
    let stop = Arc::new(AtomicBool::new(false));
    // (server, started, may read billing)
    let seen: Arc<Mutex<Vec<(usize, Instant, bool)>>> = Arc::default();
    let mut threads = Vec::new();
    for (i, hub) in [&a, &b].into_iter().enumerate() {
        for _ in 0..4 {
            let (api, stop, seen, fin, name) = (hub.api(), stop.clone(), seen.clone(), fin.clone(), p.name.clone());
            threads.push(std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    let at = Instant::now();
                    let r = api.get(Some(&fin), &format!("/v1/projects/{name}/access?path={BILL_DIR}"));
                    seen.lock().unwrap().push((i, at, r.status == 200));
                }
            }));
        }
    }
    std::thread::sleep(Duration::from_millis(1500));
    member(&a.api(), &admin, &p.name, "finance", &p.fin.name, false);
    let revoked = Instant::now();
    std::thread::sleep(Duration::from_millis(1500));
    stop.store(true, Ordering::SeqCst);
    for t in threads {
        t.join().unwrap();
    }
    let seen = seen.lock().unwrap();
    // Safety first: nothing after the removal returned was answered.
    let late: Vec<_> = seen.iter().filter(|(_, at, ok)| *at > revoked && *ok).collect();
    assert!(late.is_empty(), "{} requests started after the removal were answered: {:?}", late.len(), &late[..late.len().min(5)]);
    // Then liveness: both servers answered before, and were asked after.
    for server in 0..2 {
        assert!(seen.iter().any(|(s, at, ok)| *s == server && *at < revoked && *ok), "server {server} answered before the removal");
        let after = seen.iter().filter(|(s, at, _)| *s == server && *at > revoked).count();
        assert!(after > 10, "server {server} was asked {after} times after the removal");
    }
    eprintln!("revocation under load: {} requests, {} after the removal, all refused", seen.len(), seen.iter().filter(|s| s.1 > revoked).count());
}

/// A push through one server: the other server's tips follow within the
/// tips' expiry (at once where the database delivers notices); a push is
/// never decided by a cached tip.
#[test]
fn tips_follow_pushes_on_every_server() {
    let a = TestHub::start();
    let b = TestHub::beside(&a);
    let p = setup_project(&a);
    let admin = p.admin.token();
    let notices = a.hub().caches.notices.load(Ordering::SeqCst);
    eprintln!("the database delivers notices: {notices}");
    for round in 0..5 {
        let before = b.api().tips(Some(&admin), &p.name).unwrap().branches["main"];
        write_files(&p.dir, &[("src/round.txt", &format!("round {round}"))]);
        p.admin.commit_main(&p.dir, &format!("round {round}"));
        p.admin.ok(&p.dir, &["push"]);
        let now = a.api().tips(Some(&admin), &p.name).unwrap().branches["main"];
        assert_ne!(now, before, "the pushing server answers the new tip at once");
        let t = Instant::now();
        while b.api().tips(Some(&admin), &p.name).unwrap().branches["main"] != now {
            assert!(t.elapsed() < Duration::from_secs(5), "the other server never saw the push");
            std::thread::sleep(Duration::from_millis(5));
        }
        eprintln!("round {round}: the other server saw the push after {:?}", t.elapsed());
    }
    // Pushing on a stale tip (B's cache may hold it) is a database decision.
    let api_b = b.api();
    let tip = api_b.tips(Some(&admin), &p.name).unwrap().branches["main"];
    let mut c = Craft::new(&api_b, &p.dev, &p.name, "main");
    c.file("src/x.txt", "x");
    assert_eq!(c.push("main", "x").status, 200);
    let mut c = Craft::with(&api_b, p.dev.token(), p.dev.identity(), &p.name, "main");
    c.file("src/y.txt", "y");
    let h = a.hub();
    let count = || -> i64 {
        a.rt.block_on(sqlx::query_scalar("SELECT count(*) FROM snapshots s JOIN projects p ON p.id = s.project_id WHERE p.name = $1").bind(&p.name).fetch_one(&h.db))
            .unwrap()
    };
    let before = count();
    let (_, r) = c.push_edited("main", Some(tip), |_| {});
    let refused = r.status == 409 || r.json()["results"][0]["ok"] == json!(false);
    assert!(refused, "a push expecting the old tip is refused: {}", String::from_utf8_lossy(&r.body));
    // BUG-910: a refused push records nothing as history (and commits nothing).
    assert_eq!(count(), before, "a refused push recorded its snapshot as committed history");
}

/// A non-admin's landing through the graft (snapshot, origin, memo and
/// audit rows, and the branch move) is one database commit
/// (`storage-and-cost.md` §3): every row it wrote carries the same
/// transaction id (`xmin`, PostgreSQL), whatever else runs at the time.
#[test]
fn a_push_is_one_database_commit() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let h = hub.hub();
    // YugabyteDB has no `xmin` ("not supported yet"): nothing to count there.
    if hub.rt.block_on(sqlx::query("SELECT xmin FROM projects LIMIT 1").execute(&h.db)).is_err() {
        eprintln!("this database has no xmin: transactions not counted");
        return;
    }
    let q = |sql: &str, pid: i64, id: &str| -> Vec<String> {
        hub.rt.block_on(sqlx::query_scalar::<_, String>(sql).bind(pid).bind(id).fetch_all(&h.db)).unwrap()
    };
    let pid: i64 = hub.rt.block_on(sqlx::query_scalar("SELECT id FROM projects WHERE name = $1").bind(&p.name).fetch_one(&h.db)).unwrap();
    let api = hub.api();
    for i in 0..3 {
        let mut c = Craft::new(&api, &p.dev, &p.name, "main");
        c.file(&format!("src/one-{i}.txt"), "one commit");
        let since = veil_core::now_millis().to_string();
        let r = c.push("main", "one commit");
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        let real: String = hub.rt.block_on(sqlx::query_scalar("SELECT target FROM branches WHERE project_id = $1 AND name = 'main'").bind(pid).fetch_one(&h.db)).unwrap();
        let mut xids = Vec::new();
        for (what, sql, arg) in [
            ("branch", "SELECT xmin::text FROM branches WHERE project_id = $1 AND target = $2", &real),
            ("snapshot", "SELECT xmin::text FROM snapshots WHERE project_id = $1 AND id = $2", &real),
            ("origin", "SELECT xmin::text FROM origins WHERE project_id = $1 AND real_id = $2", &real),
            ("memo", "SELECT xmin::text FROM projections WHERE project_id = $1 AND created_at >= $2::bigint", &since),
            ("audit", "SELECT xmin::text FROM audit_log WHERE project_id = $1 AND action = 'push' AND at >= $2::bigint", &since),
        ] {
            let got = q(sql, pid, arg);
            assert!(!got.is_empty(), "push {i}: no {what} row");
            xids.extend(got.into_iter().map(|x| (what, x)));
        }
        let distinct: std::collections::BTreeSet<&String> = xids.iter().map(|(_, x)| x).collect();
        assert_eq!(distinct.len(), 1, "push {i}: rows written by more than one transaction: {xids:?}");
    }
}
