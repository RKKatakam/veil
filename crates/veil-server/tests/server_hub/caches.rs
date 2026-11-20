//! Request-path caches (milestone S4, `docs/HUB.md` §13.14): a cache never
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

/// Run `q` straight in the database, as an operator would. Its trigger
/// bumps an epoch row that concurrent changes may bump too: YugabyteDB may
/// refuse it as a conflict (`40001`), and it runs again.
fn sql(hub: &TestHub, q: &str) -> u64 {
    let h = hub.hub();
    for _ in 0..50 {
        match hub.rt.block_on(sqlx::query(q).execute(&h.db)) {
            Ok(r) => return r.rows_affected(),
            Err(sqlx::Error::Database(e)) if e.code().as_deref() == Some("40001") => std::thread::sleep(Duration::from_millis(50)),
            Err(e) => panic!("{q}: {e}"),
        }
    }
    panic!("{q}: kept conflicting")
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

/// BUG-2459: the tips notice is sent after the push's commit, not in it, so
/// nothing in the push's own answer shows it went out: a listener on the
/// channel hears the project's id. (The other tests of tips on two servers
/// pass on the 100 ms expiry alone.) PostgreSQL only: YugabyteDB 2025.2
/// does not deliver notices by default, and the server then sends none.
#[test]
fn bug_2459_a_push_notifies_every_server_after_its_commit() {
    let a = TestHub::start();
    let h = a.hub();
    let version: String = a.rt.block_on(sqlx::query_scalar("SELECT version()").fetch_one(&h.db)).unwrap();
    if version.contains("-YB-") {
        eprintln!("YugabyteDB: notices are not delivered by default; nothing to hear");
        return;
    }
    // The server checks at start, by a notice to itself, that they arrive.
    let t = Instant::now();
    // Under a whole suite's load that check can miss its 5 s and runs again
    // (BUG-2463).
    while !h.caches.notices.load(Ordering::SeqCst) && t.elapsed() < Duration::from_secs(60) {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(h.caches.notices.load(Ordering::SeqCst), "PostgreSQL delivers notices, and the server found it does");
    let p = setup_project(&a);
    let pid: i64 = a.rt.block_on(sqlx::query_scalar("SELECT id FROM projects WHERE name = $1").bind(&p.name).fetch_one(&h.db)).unwrap();
    let mut listener = a
        .rt
        .block_on(async {
            let mut l = sqlx::postgres::PgListener::connect_with(&h.db).await?;
            l.listen(veil_server::caches::TIPS_CHANNEL).await?;
            Ok::<_, sqlx::Error>(l)
        })
        .unwrap();
    write_files(&p.dir, &[("src/notice.txt", "heard")]);
    p.admin.commit_main(&p.dir, "a push to hear");
    p.admin.ok(&p.dir, &["push"]);
    // Moved in: the listener is dropped inside the runtime.
    let heard = a.rt.block_on(async move {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            match tokio::time::timeout_at(deadline, listener.recv()).await {
                Ok(Ok(n)) if n.payload() == pid.to_string() => return true,
                Ok(Ok(_)) => continue,
                _ => return false,
            }
        }
    });
    assert!(heard, "no notice for project {pid} after its push");
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
/// Other viewers' projections, which the deriver works out after the
/// landing (S12), are their own commits.
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
        // The pusher's projection of what landed, as the push answered it.
        let seen = r.json()["results"][0]["tip"].as_str().unwrap().to_string();
        let real: String = hub.rt.block_on(sqlx::query_scalar("SELECT target FROM branches WHERE project_id = $1 AND name = 'main'").bind(pid).fetch_one(&h.db)).unwrap();
        let mut xids = Vec::new();
        for (what, sql, arg) in [
            ("branch", "SELECT xmin::text FROM branches WHERE project_id = $1 AND target = $2", &real),
            ("snapshot", "SELECT xmin::text FROM snapshots WHERE project_id = $1 AND id = $2", &real),
            ("origin", "SELECT xmin::text FROM origins WHERE project_id = $1 AND real_id = $2", &real),
            ("memo", "SELECT xmin::text FROM projections WHERE project_id = $1 AND projected_id = $2", &seen),
            ("audit", "SELECT xmin::text FROM audit_log WHERE project_id = $1 AND action = 'push' AND at >= $2::bigint", &since),
        ] {
            let got = q(sql, pid, arg);
            assert!(!got.is_empty(), "push {i}: no {what} row");
            xids.extend(got.into_iter().map(|x| (what, x)));
        }
        // The pusher's memo row is one of those naming its projection.
        let push_xid = xids.iter().find(|(w, _)| *w == "branch").unwrap().1.clone();
        let mut written: Vec<_> = xids.iter().filter(|(w, x)| *w != "memo" || *x == push_xid).collect();
        written.dedup_by_key(|(w, _)| *w);
        assert!(written.iter().any(|(w, _)| *w == "memo"), "push {i}: the pusher's memo row was written by another transaction: {xids:?}");
        let distinct: std::collections::BTreeSet<&String> = written.iter().map(|(_, x)| x).collect();
        assert_eq!(distinct.len(), 1, "push {i}: rows written by more than one transaction: {xids:?}");
    }
}

/// What a read grant needs from the permission cache (S5): a view comes
/// with the epochs read before its rows were loaded (`perm::open_at`), so a
/// grant made from it carries those, never a later read. After a removal
/// committed on one server, the other server's very next view is the new
/// one, and comes with the removal's epoch; before it, with an older one.
#[test]
fn a_view_carries_the_epochs_it_was_built_under() {
    let a = TestHub::start();
    let b = TestHub::beside(&a);
    let p = setup_project(&a);
    let admin = p.admin.token();
    let hb = b.hub();
    let person: i64 = b.rt.block_on(sqlx::query_scalar("SELECT id FROM people WHERE name = $1").bind(&p.fin.name).fetch_one(&hb.db)).unwrap();
    let device_key = p.fin.identity().verifying_hex();
    // The caller as server B's session check makes it: its epochs read now.
    let caller = |project: i64| {
        let epochs = b.rt.block_on(veil_server::caches::read_epochs(&hb.db, person, Some(project))).unwrap();
        veil_server::auth::Caller {
            person: Some(veil_server::auth::Person {
                id: person,
                name: p.fin.name.clone(),
                device_key: device_key.clone(),
                agent: None,
            }),
            epochs,
        }
    };
    let pid: i64 = b.rt.block_on(sqlx::query_scalar("SELECT id FROM projects WHERE name = $1").bind(&p.name).fetch_one(&hb.db)).unwrap();
    let open = || b.rt.block_on(veil_server::perm::open_at(&hb, &p.name, &caller(pid))).unwrap();
    let finance: i64 = b.rt.block_on(sqlx::query_scalar("SELECT id FROM groups WHERE project_id = $1 AND name = 'finance'").bind(pid).fetch_one(&hb.db)).unwrap();
    let (_, v, before) = open();
    let (_, v2, again) = open();
    assert!(v.groups.contains(&finance) && v2.groups.contains(&finance));
    assert_eq!(before, again, "a cached view carries the epochs it was built under");
    member(&a.api(), &admin, &p.name, "finance", &p.fin.name, false);
    let bump: i64 = b
        .rt
        .block_on(sqlx::query_scalar("SELECT epoch FROM access_epochs WHERE project_id = 0 AND person_id = $1").bind(person).fetch_one(&hb.db))
        .unwrap();
    let (_, v, after) = open();
    assert!(!v.groups.contains(&finance), "the very next view on the other server is the new one");
    assert_eq!(after.person, bump, "it carries the removal's epoch");
    assert_ne!(bump, before.person, "the removal set a new epoch ({before:?} → {bump})");
    // A random value, not a count (BUG-1081): nothing small or in sequence.
    assert!(bump.unsigned_abs() > 1 << 20 && bump != before.person + 1, "epoch {bump} looks like a count");
}

/// A commit through the API (S10) that moves `main` is one database commit
/// too (branch, snapshot, memo, change ref, audit), and every server's tips
/// follow it: its notice follows that commit (BUG-2459).
#[test]
fn an_api_commit_is_one_commit_and_moves_every_servers_tips() {
    let a = TestHub::start();
    let b = TestHub::beside(&a);
    let p = setup_project(&a);
    let h = a.hub();
    let dev = p.dev.token();
    let pid: i64 = a.rt.block_on(sqlx::query_scalar("SELECT id FROM projects WHERE name = $1").bind(&p.name).fetch_one(&h.db)).unwrap();
    let xmin = a.rt.block_on(sqlx::query("SELECT xmin FROM projects LIMIT 1").execute(&h.db)).is_ok();
    for i in 0..3 {
        let base = a.api().tips(Some(&dev), &p.name).unwrap().branches["main"];
        // B has seen the old tip (and may hold it).
        assert_eq!(b.api().tips(Some(&dev), &p.name).unwrap().branches["main"], base);
        let since = veil_core::now_millis().to_string();
        let r = a.api().post_json(
            Some(&dev),
            &format!("/v1/projects/{}/changes", p.name),
            &json!({"base": base.hex(), "edits": [{"path": format!("src/api-{i}.txt"), "put": {"text": "through the API"}}],
                    "onto": {"branch": "main", "expected": base.hex()}}),
        );
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        let v = r.json();
        assert_eq!(v["branch"]["status"], "ok", "{v}");
        let seen = v["branch"]["tip"].as_str().unwrap().to_string();
        let t = Instant::now();
        while b.api().tips(Some(&dev), &p.name).unwrap().branches["main"].hex() != seen {
            assert!(t.elapsed() < Duration::from_secs(5), "the other server never saw the API commit");
            std::thread::sleep(Duration::from_millis(5));
        }
        if !xmin {
            continue;
        }
        let real: String =
            a.rt.block_on(sqlx::query_scalar("SELECT target FROM branches WHERE project_id = $1 AND name = 'main'").bind(pid).fetch_one(&h.db)).unwrap();
        let q = |sql: &str, arg: &str| -> Vec<String> { a.rt.block_on(sqlx::query_scalar::<_, String>(sql).bind(pid).bind(arg).fetch_all(&h.db)).unwrap() };
        let branch = q("SELECT xmin::text FROM branches WHERE project_id = $1 AND target = $2", &real);
        let mut rows = vec![("branch", branch[0].clone())];
        for (what, sql, arg) in [
            ("snapshot", "SELECT xmin::text FROM snapshots WHERE project_id = $1 AND id = $2", &real),
            ("change ref", "SELECT xmin::text FROM change_refs WHERE project_id = $1 AND snapshot = $2", &real),
            ("audit", "SELECT xmin::text FROM audit_log WHERE project_id = $1 AND action = 'change' AND at >= $2::bigint", &since),
        ] {
            let got = q(sql, arg);
            assert!(!got.is_empty(), "commit {i}: no {what} row");
            rows.extend(got.into_iter().map(|x| (what, x)));
        }
        // The caller's memo row is one of those naming its projection.
        let memos = q("SELECT xmin::text FROM projections WHERE project_id = $1 AND projected_id = $2", &seen);
        assert!(memos.contains(&rows[0].1), "commit {i}: the caller's memo row is another transaction's: {memos:?} {rows:?}");
        let distinct: std::collections::BTreeSet<&String> = rows.iter().map(|(_, x)| x).collect();
        assert_eq!(distinct.len(), 1, "commit {i}: rows written by more than one transaction: {rows:?}");
    }
}

/// P6 / BUG-2930: `access_epochs` is composite hash-sharded on
/// `(project_id, person_id)` on hash-sharded YugabyteDB (migration 0046) with
/// no dual-written `person_epochs` table; `caches::read_epochs` batches both
/// point lookups into one statement; `GET /tips` caches `tested` alongside
/// `branches` and invalidates it when `tested` moves; and `embargo_lines` is
/// NEVER cached (a newly committed embargo row is observed immediately on the
/// very next `GET /tips`, even within `TIPS_TTL`).
#[test]
fn p6_person_epochs_sharded_tested_cached_embargo_live() {
    let a = TestHub::start();
    let b = TestHub::beside(&a);
    let p = setup_project(&a);
    let ha = a.hub();
    let hb = b.hub();
    let admin = p.admin.token();
    let dev = p.dev.token();
    let pid: i64 = a.rt.block_on(sqlx::query_scalar("SELECT id FROM projects WHERE name = $1").bind(&p.name).fetch_one(&ha.db)).unwrap();
    let fin_id: i64 = a.rt.block_on(sqlx::query_scalar("SELECT id FROM people WHERE name = $1").bind(&p.fin.name).fetch_one(&ha.db)).unwrap();

    // 1. Person epoch bumps write `access_epochs(0, person_id)` directly (no `person_epochs` table),
    //    and on hash-sharded YugabyteDB `access_epochs` uses composite hash PK `(project_id, person_id) HASH`.
    member(&a.api(), &admin, &p.name, "finance", &p.fin.name, false);
    let has_pe: Option<String> = a.rt.block_on(sqlx::query_scalar("SELECT to_regclass('person_epochs')::text").fetch_one(&ha.db)).unwrap();
    assert!(has_pe.is_none(), "person_epochs table was withdrawn (BUG-2930)");
    let ae_row: i64 = a
        .rt
        .block_on(sqlx::query_scalar("SELECT epoch FROM access_epochs WHERE project_id = 0 AND person_id = $1").bind(fin_id).fetch_one(&ha.db))
        .unwrap();
    let read = a.rt.block_on(veil_server::caches::read_epochs(&ha.db, fin_id, Some(pid))).unwrap();
    assert_eq!(read.person, ae_row, "read_epochs reads access_epochs (0, person_id)");
    assert!(read.embargo_free(pid) && read.no_embargoes(pid), "embargo-free project reports no_embargoes=true");
    let version: String = a.rt.block_on(sqlx::query_scalar("SELECT version()").fetch_one(&ha.db)).unwrap();
    if veil_server::db::is_yugabyte(&version) {
        let colocated: bool = a.rt.block_on(sqlx::query_scalar("SELECT yb_is_database_colocated()").fetch_one(&ha.db)).unwrap();
        if !colocated {
            let pk_def: String = a
                .rt
                .block_on(sqlx::query_scalar(
                    "SELECT pg_get_indexdef(i.indexrelid) FROM pg_index i \
                     WHERE i.indrelid = to_regclass('access_epochs') AND i.indisprimary",
                ).fetch_one(&ha.db))
                .unwrap();
            assert!(pk_def.contains("(project_id, person_id) HASH"), "access_epochs PK must be composite hash on YB: {pk_def}");
        }
    }

    // 2. Warm GET /tips caches branches + tested together (tips_hits increments on repeat).
    // Prime hub B's connection/auth caches first, then issue back-to-back calls so a single
    // >100 ms cold-pool hiccup on YugabyteDB does not outlive `TIPS_TTL` (100 ms).
    let t1 = b.api().tips(Some(&dev), &p.name).unwrap();
    let hits_before = hb.caches.stats.tips_hits.load(std::sync::atomic::Ordering::Relaxed);
    let mut hits_after = hits_before;
    for _ in 0..5 {
        let t2 = b.api().tips(Some(&dev), &p.name).unwrap();
        assert_eq!(t1.branches, t2.branches);
        assert_eq!(t1.tested, t2.tested);
        assert!(t2.embargoes.is_empty());
        hits_after = hb.caches.stats.tips_hits.load(std::sync::atomic::Ordering::Relaxed);
        if hits_after > hits_before {
            break;
        }
    }
    assert!(hits_after > hits_before, "warm GET /tips hits caches.tips");

    // 3. Embargoes are NEVER cached: inserting an embargo_lines row is visible
    //    on the VERY NEXT GET /tips on hub B (even while caches.tips is hot within TIPS_TTL).
    let now = veil_core::now_millis();
    let rec = veil_core::keychain::EmbargoRecord {
        format: veil_core::keychain::EMBARGO_FORMAT,
        id: "emb-p6-live".into(),
        scope: "eng".into(),
        until: None,
        released_at: None,
        created: now,
        state: None,
        reason: None,
    };
    let rec_json = serde_json::to_string(&rec).unwrap();
    a.rt.block_on(
        sqlx::query(
            "INSERT INTO embargo_lines (project_id, embargo_id, group_names, target_branch, embargo_branch, until_ms, released_at, record_json, created_by, created_at) \
             VALUES ($1, 'emb-p6-live', ARRAY['eng'], 'main', 'embargo/emb-p6-live', NULL, NULL, $2, $3, $4)",
        )
        .bind(pid)
        .bind(&rec_json)
        .bind(&p.admin.name)
        .bind(now)
        .execute(&ha.db),
    )
    .unwrap();
    // Immediately ask hub B (no tips_moved notice sent, caches.tips still warm!):
    let t3 = b.api().tips(Some(&admin), &p.name).unwrap();
    assert_eq!(t3.embargoes.len(), 1, "new embargo must be visible immediately without waiting for TIPS_TTL");
    assert_eq!(t3.embargoes[0].id, "emb-p6-live");
    // And an outsider (fin, removed from finance and not in eng, still reads public src/) sees no embargoes:
    let t3_out = b.api().tips(Some(&p.fin.token()), &p.name).expect("fin still reads public src/");
    assert!(t3_out.embargoes.is_empty(), "outsider must not see eng embargo: {:?}", t3_out.embargoes);
    // Releasing the embargo sets released_at (embargo_free becomes true, no_embargoes stays false so released record is still returned for pull keychain sync):
    a.rt.block_on(
        sqlx::query("UPDATE embargo_lines SET released_at = $2 WHERE project_id = $1 AND embargo_id = 'emb-p6-live'")
            .bind(pid)
            .bind(veil_core::now_millis())
            .execute(&ha.db),
    )
    .unwrap();
    let read_rel = a.rt.block_on(veil_server::caches::read_epochs(&ha.db, fin_id, Some(pid))).unwrap();
    assert!(read_rel.embargo_free(pid), "released embargo is embargo_free for snapshot withholding");
    assert!(!read_rel.no_embargoes(pid), "released embargo still triggers live embargoes_for so clients sync release");
    let t4 = b.api().tips(Some(&admin), &p.name).unwrap();
    assert_eq!(t4.embargoes.len(), 1, "released embargo record still returned on GET /tips");
    assert!(t4.embargoes[0].id == "emb-p6-live");
}
