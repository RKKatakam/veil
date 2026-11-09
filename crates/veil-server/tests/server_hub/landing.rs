//! The landing service (S17, `docs/HUB.md` §13.19; phase 4 §4.1–4.6 and
//! its threat review, §6 rows 1–4): batched landings with one move of the
//! branch, the fast path, conflicts never landed over, access checked at
//! submit and again when an entry lands, fencing between servers, protected
//! branches, `vl land` and `vl push` to a protected branch.

use std::{collections::HashSet, sync::Arc, time::Duration};

use serde_json::{json, Value};
use veil_core::ObjectId;

use crate::support::*;

fn tip_for(hub: &TestHub, token: &str, project: &str) -> ObjectId {
    hub.api().tips(Some(token), project).unwrap().branches["main"]
}

fn put(path: &str, text: &str) -> Value {
    json!({"path": path, "put": {"text": text}})
}

/// Submit edits on `base` to land on main.
fn land(api: &Api, token: &str, project: &str, base: ObjectId, edits: Value, wait: bool) -> Reply {
    api.post_json(
        Some(token),
        &format!("/v1/projects/{project}/land"),
        &json!({"onto": "main", "base": base.hex(), "edits": edits, "description": "a landing", "wait": wait}),
    )
}

/// A ticket's outcome, waiting for it.
fn outcome(api: &Api, token: &str, project: &str, ticket: &str) -> Value {
    for _ in 0..8 {
        let r = api.get(Some(token), &format!("/v1/projects/{project}/land/{ticket}"));
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        let v = r.json();
        if v["state"] != "queued" {
            return v;
        }
    }
    panic!("ticket {ticket} still queued");
}

fn project_id(hub: &TestHub, name: &str) -> i64 {
    let h = hub.hub();
    hub.rt
        .block_on(sqlx::query_scalar::<_, i64>("SELECT id FROM projects WHERE name = $1").bind(name).fetch_one(&h.db))
        .unwrap()
}

fn sql_i64(hub: &TestHub, q: &str, project: i64) -> i64 {
    let h = hub.hub();
    hub.rt.block_on(sqlx::query_scalar::<_, i64>(q).bind(project).fetch_one(&h.db)).unwrap()
}

/// Hold main's landing lease as nobody: entries queue, and none lands
/// until [`release`].
fn hold(hub: &TestHub, project: i64) {
    let h = hub.hub();
    hub.rt
        .block_on(
            sqlx::query(
                "INSERT INTO landing_leases (project_id, branch, holder, epoch, expires_at) VALUES ($1, 'main', 'test', 1, $2) \
                 ON CONFLICT (project_id, branch) DO UPDATE SET holder = 'test', epoch = landing_leases.epoch + 1, expires_at = $2",
            )
            .bind(project)
            .bind(veil_core::now_millis() + 600_000)
            .execute(&h.db),
        )
        .unwrap();
}

fn release(hub: &TestHub, project: i64) {
    let h = hub.hub();
    hub.rt
        .block_on(sqlx::query("UPDATE landing_leases SET expires_at = 0 WHERE project_id = $1 AND holder = 'test'").bind(project).execute(&h.db))
        .unwrap();
}

/// The real tip of main.
fn real_tip(hub: &TestHub, project: i64) -> ObjectId {
    let t = sql_text(hub, "SELECT target FROM branches WHERE project_id = $1 AND name = 'main'", project);
    ObjectId::from_hex(&t).unwrap()
}

fn sql_text(hub: &TestHub, q: &str, project: i64) -> String {
    let h = hub.hub();
    hub.rt.block_on(sqlx::query_scalar::<_, String>(q).bind(project).fetch_one(&h.db)).unwrap()
}

/// The server's objects of `project`, read as the landing service reads
/// them.
fn source(hub: &TestHub, project: i64) -> veil_server::sync::Source {
    veil_server::sync::Source {
        hub: hub.hub(),
        project,
        rt: hub.rt.handle().clone(),
        pending: Default::default(),
    }
}

/// Main's first-parent chain, newest first, down to (not including) `stop`.
fn chain(hub: &TestHub, project: i64, stop: ObjectId) -> Vec<(ObjectId, Arc<veil_core::object::Snapshot>)> {
    let src = source(hub, project);
    let mut out = Vec::new();
    let mut x = real_tip(hub, project);
    while x != stop {
        let s = src.snapshot(&x).unwrap();
        let next = s.parents[0];
        out.push((x, s));
        x = next;
        assert!(out.len() < 10_000, "{stop} is not below main");
    }
    out
}

#[test]
fn non_overlapping_changes_land_in_batches_each_once_with_exactly_its_edits() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let token = p.dev.token();
    // Every change is made on the same, soon old, tip: nobody catches up.
    let base = tip_for(&hub, &token, &p.name);
    let start = real_tip(&hub, pid);
    hold(&hub, pid);
    let n = 40;
    let tickets: Vec<String> = (0..n)
        .map(|i| {
            let r = land(&api, &token, &p.name, base, json!([put(&format!("src/agents/a{i:02}/f.rs"), &format!("agent {i}\n"))]), false);
            assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
            let v = r.json();
            assert_eq!(v["state"], "queued", "{v}");
            v["ticket"].as_str().unwrap().to_string()
        })
        .collect();
    assert_eq!(real_tip(&hub, pid), start, "nothing lands while the lease is held elsewhere");
    release(&hub, pid);
    let mut seen_landed = Vec::new();
    for t in &tickets {
        let v = outcome(&api, &token, &p.name, t);
        assert_eq!(v["state"], "landed", "{v}");
        seen_landed.push(serde_json::from_value::<ObjectId>(v["landed"][0].clone()).unwrap());
    }
    // The dev sees main at the last one (tips may be up to 100 ms old, as
    // on YugabyteDB, which delivers no notices), and each one is a
    // distinct snapshot.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while tip_for(&hub, &token, &p.name) != *seen_landed.last().unwrap() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(tip_for(&hub, &token, &p.name), *seen_landed.last().unwrap());
    assert_eq!(seen_landed.iter().collect::<HashSet<_>>().len(), n);
    // Each change landed exactly once, as its own snapshot, in order, with
    // exactly its own edit; and main moved far fewer times than n.
    let src = source(&hub, pid);
    let landed = chain(&hub, pid, start);
    assert_eq!(landed.len(), n);
    for (i, (id, s)) in landed.iter().rev().enumerate() {
        let parent = src.snapshot(&s.parents[0]).unwrap();
        let set = veil_server::landing::edits::edit_set(&src, s.tree, parent.tree).unwrap();
        assert_eq!(set.len(), 1, "{id}");
        assert_eq!(set[0].path, format!("src/agents/a{i:02}/f.rs"));
        assert!(set[0].old.is_none());
        // Each is made again on the tip, naming what was submitted (the
        // first too, though it was on the tip: a change always lands as
        // its edits, S17 cycle 3).
        assert_eq!(s.predecessors.len(), 1, "{i}");
        assert!(s.signature_valid() == Some(true));
    }
    let moves = sql_i64(&hub, "SELECT count(*) FROM audit_log WHERE project_id = $1 AND action = 'land'", pid);
    assert!(moves <= 4, "{moves} batches for {n} queued changes");
    // A stream of landings from 8 agents at once, each on its own last one:
    // batches are built while the one before commits (pipelined), on trees
    // not stored yet. Every one lands, none is refused.
    std::thread::scope(|s| {
        for t in 0..8 {
            let (hub, token, name) = (&hub, &token, &p.name);
            s.spawn(move || {
                let api = hub.api();
                let mut base = tip_for(hub, token, name);
                for i in 0..15 {
                    let r = land(&api, token, name, base, json!([put(&format!("src/stream/t{t}/{i:02}.rs"), "s\n")]), true);
                    let v = r.json();
                    assert_eq!(v["state"], "landed", "{v}");
                    base = serde_json::from_value(v["landed"][0].clone()).unwrap();
                }
            });
        }
    });
    assert_eq!(hub.hub().landing.stats.rejected.load(std::sync::atomic::Ordering::Relaxed), 0);
    // Nobody's access changed: no entry's checks ran again.
    let rechecked = hub.hub().landing.stats.rechecked.load(std::sync::atomic::Ordering::Relaxed);
    eprintln!("rechecked {rechecked}");
    assert_eq!(rechecked, 0, "entries were checked again with no access change");
    // A landed change is a base like any snapshot: the next one builds on
    // the dev's own last landing, which main has moved past.
    let r = land(&api, &token, &p.name, seen_landed[0], json!([put("src/agents/later.rs", "later\n")]), true);
    assert_eq!(r.json()["state"], "landed", "{}", String::from_utf8_lossy(&r.body));
    // Everyone receives only what they may see, and every snapshot verifies.
    p.admin.ok(&p.dir, &["pull"]);
    for who in [&p.dev, &p.fin, &p.carol, &p.sec] {
        let d = who.dir(&unique("after"));
        let out = who.ok(who.home.path(), &["clone", &hub.url(&p.name), d.to_str().unwrap()]);
        assert!(!out.contains("no valid signature"), "{out}");
        assert_eq!(std::fs::read_to_string(d.join("src/agents/a07/f.rs")).unwrap(), "agent 7\n");
        let hidden: Vec<&str> = match &who.name {
            n if *n == p.fin.name => vec![ROOT_MARK, NESTED_MARK, PERSON_MARK],
            n if *n == p.sec.name => vec![ROOT_MARK, BILL_MARK, PERSON_MARK, ENV_MARK],
            n if *n == p.carol.name => vec![ROOT_MARK, BILL_MARK, NESTED_MARK, ENV_MARK],
            _ => restricted_markers(),
        };
        assert_no_marker(&everything_in(&d), &hidden, &who.name);
    }
}

#[test]
fn an_overlapping_change_is_answered_conflict_and_never_landed_over() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let token = p.dev.token();
    let base = tip_for(&hub, &token, &p.name);
    let a = land(&api, &token, &p.name, base, json!([put("src/lib.rs", "first\n"), put("src/a.rs", "a\n")]), true);
    assert_eq!(a.json()["state"], "landed", "{}", String::from_utf8_lossy(&a.body));
    // The same file from the same base: a conflict naming it, nothing landed.
    let b = land(&api, &token, &p.name, base, json!([put("src/b.rs", "b\n"), put("src/lib.rs", "second\n")]), true);
    let v = b.json();
    assert_eq!(v["state"], "conflict", "{v}");
    assert_eq!(v["paths"], json!(["src/lib.rs"]));
    // Adding a file someone else added meanwhile, and deleting one they
    // changed, overlap too.
    let c = land(&api, &token, &p.name, base, json!([put("src/a.rs", "mine\n")]), true);
    assert_eq!(c.json()["state"], "conflict");
    let d = land(&api, &token, &p.name, base, json!([{"path": "src/lib.rs", "delete": true}]), true);
    assert_eq!(d.json()["state"], "conflict");
    let dir = p.dev.dir("check");
    p.dev.ok(p.dev.home.path(), &["clone", &hub.url(&p.name), dir.to_str().unwrap()]);
    assert_eq!(std::fs::read_to_string(dir.join("src/lib.rs")).unwrap(), "first\n");
    assert!(!dir.join("src/b.rs").exists());
    // Redone on the new tip, it lands.
    let tip = tip_for(&hub, &token, &p.name);
    let e = land(&api, &token, &p.name, tip, json!([put("src/b.rs", "b\n"), put("src/lib.rs", "second\n")]), true);
    assert_eq!(e.json()["state"], "landed");
}

#[test]
fn access_is_checked_at_submit_and_again_when_an_entry_lands() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let token = p.dev.token();
    let base = tip_for(&hub, &token, &p.name);
    let queued = |pid: i64| sql_i64(&hub, "SELECT count(*) FROM landing_queue WHERE project_id = $1", pid);
    // At submit: the push's checks, before anything is queued.
    let secret = "aws_access_key_id = AKIAQ7W3EXAMPLEZ4K2M\n";
    for (edits, expect) in [
        (json!([put(&format!("{BILL_DIR}/x.txt"), "x")]), "access"),
        (json!([put("NEW-AT-ROOT.txt", "x")]), "access"),
        (json!([put("src/config.rs", secret)]), "secret"),
        (json!([put(".veilrules", "[branches.main]\nprotected = false\n")]), ".veilrules"),
        (json!([put(".veilpolicy", "src/  public devs\n")]), "access"),
    ] {
        let r = land(&api, &token, &p.name, base, edits, true);
        let body = String::from_utf8_lossy(&r.body).to_string();
        assert!(matches!(r.status, 400 | 403), "{body}");
        assert!(body.to_lowercase().contains(expect), "{body}");
        assert!(!body.contains("AKIAQ7W3EXAMPLEZ4K2M"));
    }
    assert_eq!(queued(pid), 0, "nothing refused at submit is queued");
    // Threat 2: a revoking policy change queued between two writes of the
    // revoked path. Each is accepted at submit (the policy has not changed
    // yet); the second is refused when it lands, after the policy.
    hold(&hub, pid);
    let first = land(&api, &token, &p.name, base, json!([put("src/one.rs", "1\n")]), false).json();
    let atok = p.admin.token();
    let abase = tip_for(&hub, &atok, &p.name);
    let policy = std::fs::read_to_string(p.dir.join(".veilpolicy")).unwrap();
    let revoked: String = policy
        .lines()
        .map(|l| match l.starts_with("src/ ") && l.ends_with(" public devs") {
            true => format!("{}\n", l.trim_end_matches(" devs")),
            false => format!("{l}\n"),
        })
        .collect();
    assert_ne!(policy, revoked);
    let change = land(&api, &atok, &p.name, abase, json!([put(".veilpolicy", &revoked)]), false).json();
    let second = land(&api, &token, &p.name, base, json!([put("src/two.rs", "2\n")]), false).json();
    release(&hub, pid);
    let one = outcome(&api, &token, &p.name, first["ticket"].as_str().unwrap());
    assert_eq!(one["state"], "landed", "{one}");
    let pol = outcome(&api, &atok, &p.name, change["ticket"].as_str().unwrap());
    assert_eq!(pol["state"], "landed", "{pol}");
    assert!(pol["warnings"].as_array().is_some_and(|w| !w.is_empty()), "the admin is told who can now see what: {pol}");
    let two = outcome(&api, &token, &p.name, second["ticket"].as_str().unwrap());
    assert_eq!(two["state"], "rejected", "{two}");
    assert!(two["message"].as_str().unwrap().contains("may not write 'src/two.rs'"), "{two}");
    // The policy change landed alone, between the two.
    let landed: Vec<String> = {
        let h = hub.hub();
        hub.rt
            .block_on(sqlx::query_scalar::<_, String>("SELECT details FROM audit_log WHERE project_id = $1 AND action = 'land' ORDER BY id").bind(pid).fetch_all(&h.db))
            .unwrap()
    };
    assert!(landed.iter().any(|d| d.starts_with("1 of 1 landed")), "{landed:?}");
    // Threat 1, later: someone removed from their group between submit and
    // landing is refused when it lands.
    hold(&hub, pid);
    let token = p.sec.token();
    let base = tip_for(&hub, &token, &p.name);
    let mine = land(&api, &token, &p.name, base, json!([put(&format!("src/{NESTED_DIR}/three.rs"), "3\n")]), false).json();
    assert_eq!(mine["state"], "queued", "{mine}");
    p.admin.ok(&p.dir, &["group", "remove", "security", &p.sec.name]);
    release(&hub, pid);
    // They still read the public src/ (and so their ticket); the entry was
    // refused when it came to land.
    let r = outcome(&api, &token, &p.name, mine["ticket"].as_str().unwrap());
    assert_eq!(r["state"], "rejected", "{r}");
    assert!(r["message"].as_str().unwrap().contains("no longer in this project"), "{r}");
    let check = p.admin.dir("check");
    p.admin.ok(p.admin.home.path(), &["clone", &hub.url(&p.name), check.to_str().unwrap()]);
    assert!(!check.join(format!("src/{NESTED_DIR}/three.rs")).exists());
    assert!(check.join("src/one.rs").exists() && !check.join("src/two.rs").exists());
}

#[test]
fn only_the_lease_holder_lands_and_every_ticket_lands_once_across_servers() {
    let a = TestHub::start();
    let p = setup_project(&a);
    let b = TestHub::beside(&a);
    let pid = project_id(&a, &p.name);
    let token = p.dev.token();
    let base = tip_for(&a, &token, &p.name);
    let start = real_tip(&a, pid);
    let stop = std::sync::atomic::AtomicBool::new(false);
    let n = 48;
    let tickets: Vec<(usize, String)> = std::thread::scope(|s| {
        // The lease is taken from its holder again and again (a takeover):
        // the holder's next batch must not move main.
        s.spawn(|| {
            let h = a.hub();
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                let _ = a.rt.block_on(
                    sqlx::query("UPDATE landing_leases SET holder = 'thief', epoch = epoch + 1, expires_at = 0 WHERE project_id = $1")
                        .bind(pid)
                        .execute(&h.db),
                );
                std::thread::sleep(Duration::from_millis(30));
            }
        });
        let handles: Vec<_> = (0..n)
            .map(|i| {
                let (hub, token, name) = (if i % 2 == 0 { &a } else { &b }, &token, &p.name);
                s.spawn(move || {
                    let api = hub.api();
                    let r = land(&api, token, name, base, json!([put(&format!("src/f/{i:02}.rs"), &format!("{i}\n"))]), true);
                    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
                    (i, r.json()["ticket"].as_str().unwrap().to_string())
                })
            })
            .collect();
        let out = handles.into_iter().map(|h| h.join().unwrap()).collect();
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        out
    });
    let api = a.api();
    let mut landed = 0;
    for (_, t) in &tickets {
        let v = outcome(&api, &token, &p.name, t);
        assert!(v["state"] == "landed" || v["state"] == "rejected", "{v}");
        landed += usize::from(v["state"] == "landed");
    }
    assert_eq!(landed, n, "no change was refused");
    // Each landed exactly once: one snapshot per change on main, n in all.
    let chain = chain(&a, pid, start);
    assert_eq!(chain.len(), n);
    let ids: HashSet<_> = chain.iter().map(|(_, s)| s.change_id).collect();
    assert_eq!(ids.len(), n, "a change landed twice");
    let fenced: u64 = [&a, &b].iter().map(|h| h.hub().landing.stats.lease_lost.load(std::sync::atomic::Ordering::Relaxed)).sum();
    eprintln!("batches refused for a lost lease: {fenced}");
}

#[test]
fn protected_branches_move_only_by_landing_and_push_lands_instead() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    // The admin protects main.
    write_files(&p.dir, &[(".veilrules", "[branches.main]\nprotected = true\n")]);
    p.admin.commit_main(&p.dir, "protect main");
    p.admin.ok(&p.dir, &["push"]);
    // Two clones of the dev's, made now.
    let d1 = p.dev.dir("one");
    let d2 = p.dev.dir("two");
    for d in [&d1, &d2] {
        p.dev.ok(p.dev.home.path(), &["clone", &hub.url(&p.name), d.to_str().unwrap()]);
    }
    // A push of main lands instead, and the local main follows.
    write_files(&d1, &[("src/one.rs", "one\n")]);
    p.dev.commit_main(&d1, "one");
    let out = p.dev.ok(&d1, &["push"]);
    assert!(out.contains("landed"), "{out}");
    // The other clone is behind now, and lands without pulling first.
    write_files(&d2, &[("src/two.rs", "two\n")]);
    p.dev.commit_main(&d2, "two");
    let out = p.dev.ok(&d2, &["push"]);
    assert!(out.contains("landed"), "{out}");
    let log = p.dev.ok(&d2, &["log", "-r", "main", "-n", "1"]);
    assert!(log.contains("two") && log.contains("main origin/main"), "the local main followed the landed change: {log}");
    assert!(d2.join("src/two.rs").exists());
    // `vl land`, from a clone two changes behind.
    write_files(&d1, &[("src/three.rs", "three\n")]);
    p.dev.ok(&d1, &["commit", "-m", "three"]);
    let out = p.dev.ok(&d1, &["land"]);
    assert!(out.contains("landed main"), "{out}");
    // An overlapping push is a conflict, and main is untouched.
    write_files(&d1, &[("src/two.rs", "not two\n")]);
    p.dev.commit_main(&d1, "overlap");
    let out = p.dev.fails(&d1, &["push"]);
    assert!(out.contains("conflict") && out.contains("src/two.rs"), "{out}");
    let check = p.dev.dir("check");
    p.dev.ok(p.dev.home.path(), &["clone", &hub.url(&p.name), check.to_str().unwrap()]);
    for (f, c) in [("one", "one\n"), ("two", "two\n"), ("three", "three\n")] {
        assert_eq!(std::fs::read_to_string(check.join(format!("src/{f}.rs"))).unwrap(), c);
    }
    // An API commit may not move it; the change is kept.
    let tok = p.dev.token();
    let tip = tip_for(&hub, &tok, &p.name);
    let r = api.post_json(
        Some(&tok),
        &format!("/v1/projects/{}/changes", p.name),
        &json!({"base": tip.hex(), "edits": [put("src/api.rs", "x")], "onto": {"branch": "main", "expected": "rebase"}}),
    );
    let v = r.json();
    assert_eq!(v["branch"]["status"], "rejected", "{v}");
    assert!(v["branch"]["message"].as_str().unwrap().contains("protected"), "{v}");
    assert_eq!(tip_for(&hub, &tok, &p.name), tip);
    // Nobody but an admin changes the rules, on any branch, even someone
    // given the file itself (an admin's access change: it lands alone).
    p.admin.ok(&p.dir, &["pull"]);
    p.admin.ok(&p.dir, &["access", ".veilrules", "devs"]);
    p.admin.commit_main(&p.dir, "devs may edit the rules file");
    let out = p.admin.ok(&p.dir, &["push"]);
    assert!(out.contains("landed main"), "{out}");
    let tip = tip_for(&hub, &tok, &p.name);
    let r = api.post_json(Some(&tok), &format!("/v1/projects/{}/changes", p.name), &json!({"base": tip.hex(), "edits": [put(".veilrules", "")]}));
    assert!(String::from_utf8_lossy(&r.body).contains("only admins may change the branch rules"), "{}", String::from_utf8_lossy(&r.body));
    // A malformed rules file is refused even from an admin.
    let atok = p.admin.token();
    let atip = tip_for(&hub, &atok, &p.name);
    let r = land(&api, &atok, &p.name, atip, json!([put(".veilrules", "[branches.main]\nprotcted = true\n")]), true);
    assert_eq!(r.status, 400, "{}", String::from_utf8_lossy(&r.body));
    // An admin's forced push still moves it.
    p.admin.ok(&p.dir, &["pull"]);
    write_files(&p.dir, &[("src/forced.rs", "forced\n")]);
    p.admin.commit_main(&p.dir, "forced");
    let out = p.admin.ok(&p.dir, &["push", "--force"]);
    assert!(out.contains("pushed main"), "{out}");
}

#[test]
fn hostile_landing_requests_are_refused() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let token = p.dev.token();
    let base = tip_for(&hub, &token, &p.name);
    let path = format!("/v1/projects/{}/land", p.name);
    let edits = json!([put("src/h.rs", "h")]);
    for body in [
        json!({"onto": "../main", "base": base.hex(), "edits": edits}),
        json!({"onto": "main", "base": base.hex(), "edits": edits, "snapshot": base.hex()}),
        json!({"onto": "main"}),
        json!({"onto": "main", "base": base.hex(), "edits": edits, "force": true}),
        json!({"onto": "main", "base": ObjectId::hash(b"none").hex(), "edits": edits}),
        json!({"onto": "main", "snapshot": ObjectId::hash(b"none").hex()}),
    ] {
        let r = api.post_json(Some(&token), &path, &body);
        assert!(matches!(r.status, 400 | 404 | 422), "{body}: {} {}", r.status, String::from_utf8_lossy(&r.body));
    }
    // Signed out: refused.
    assert_eq!(api.post_json(None, &path, &json!({"onto": "main", "base": base.hex(), "edits": edits})).status, 401);
    // A branch that does not exist: the landing is refused, nothing moves.
    let r = api.post_json(Some(&token), &path, &json!({"onto": "nowhere", "base": base.hex(), "edits": edits}));
    assert_eq!(r.json()["state"], "rejected", "{}", String::from_utf8_lossy(&r.body));
    // A ticket is its submitter's only.
    let r = land(&api, &token, &p.name, base, edits.clone(), false);
    let t = r.json()["ticket"].as_str().unwrap().to_string();
    let other = api.get(Some(&p.fin.token()), &format!("/v1/projects/{}/land/{t}", p.name));
    assert_eq!(other.status, 404);
    let guess = api.get(Some(&token), &format!("/v1/projects/{}/land/land-{}", p.name, "0".repeat(32)));
    assert_eq!(guess.status, 404);
    assert_eq!(outcome(&api, &token, &p.name, &t)["state"], "landed");
}

#[test]
fn bug_1100_a_new_view_key_after_an_access_change_never_stalls_the_landing_service() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let token = p.dev.token();
    // A history of 120 landings.
    let base = tip_for(&hub, &token, &p.name);
    let tickets: Vec<String> = (0..120)
        .map(|i| land(&api, &token, &p.name, base, json!([put(&format!("src/h/{i:03}.rs"), "x\n")]), false).json()["ticket"].as_str().unwrap().to_string())
        .collect();
    for t in &tickets {
        assert_eq!(outcome(&api, &token, &p.name, t)["state"], "landed");
    }
    // An access change: the dev's view key is new (docs/ is public now).
    let atok = p.admin.token();
    let policy = std::fs::read_to_string(p.dir.join(".veilpolicy")).unwrap();
    let r = land(&api, &atok, &p.name, tip_for(&hub, &atok, &p.name), json!([put(".veilpolicy", &format!("{policy}docs/  public\n"))]), true);
    assert_eq!(r.json()["state"], "landed");
    // The dev lands with that new key, and the admin lands right after.
    // Nobody holds the dev's new view: its history is projected once, by
    // the background fill or the dev's own request, never in the landing
    // service's loop, which the admin's landing (and every other) goes
    // through meanwhile.
    let h = hub.hub();
    let projected = || h.landing.stats.projected.load(std::sync::atomic::Ordering::Relaxed);
    let busy = || {
        let st = &h.landing.stats;
        st.prepare_us.load(std::sync::atomic::Ordering::Relaxed) + st.build_us.load(std::sync::atomic::Ordering::Relaxed)
    };
    let before = projected();
    let busy0 = busy();
    let (dev, admin) = std::thread::scope(|s| {
        let dev = s.spawn(|| land(&hub.api(), &token, &p.name, tip_for(&hub, &token, &p.name), json!([put("src/after.rs", "after\n")]), true).json());
        std::thread::sleep(Duration::from_millis(50));
        let t = std::time::Instant::now();
        let r = land(&api, &atok, &p.name, tip_for(&hub, &atok, &p.name), json!([put("src/admin.rs", "admin\n")]), true).json();
        assert_eq!(r["state"], "landed", "{r}");
        (dev.join().unwrap(), t.elapsed())
    });
    assert_eq!(dev["state"], "landed", "{dev}");
    let inline = projected() - before;
    // At most one attach budget (a key the background fill memoised part of
    // the way is projected the rest of it, bounded) and a projection per key
    // and landing.
    let bound = veil_server::landing::ATTACH_BUDGET as u64 + 20;
    assert!(inline <= bound, "the landing service made {inline} projections for two landings");
    // The service's own time for these batches (reading and building them):
    // no history walk in it. (The admin's request time also counts the
    // database connections the background fills hold, on a busy machine.)
    let loop_time = Duration::from_micros(busy() - busy0);
    eprintln!("the admin landed in {admin:?}; the service spent {loop_time:?} and made {inline} projections");
    assert!(loop_time < Duration::from_secs(2), "the landing service spent {loop_time:?} on two landings behind a new view key");
    // And the dev's answer is theirs: their own view of where it landed.
    let mine: ObjectId = serde_json::from_value(dev["landed"][0].clone()).unwrap();
    let r = land(&api, &token, &p.name, mine, json!([put("src/after2.rs", "after\n")]), true);
    assert_eq!(r.json()["state"], "landed", "the dev's landed snapshot is a base like any: {}", String::from_utf8_lossy(&r.body));
    let _ = pid;
}

// S17 review, cycle 1 (docs/BUGS.md, "S17 cycle 1").

use veil_core::object::{Object as O, Snapshot, Text};

/// `c`'s root without the entry `name` (fetched as the crafter sees it).
fn without(c: &mut Craft<'_>, name: &str) {
    let r = c.api.post_json(
        Some(&c.token),
        &format!("/v1/projects/{}/fetch", c.project),
        &json!({"snapshot": c.tip.hex(), "objects": [{"path": "", "id": c.root.hex()}]}),
    );
    let O::Tree(mut t) = O::decode(&r.frames()[0].1).unwrap() else { panic!("not a tree") };
    assert!(t.get(name).is_some(), "{name} is not in the crafter's root");
    t.remove(name);
    c.root = c.put(O::Tree(t));
}

/// Sign a snapshot of `c`'s root on `parents`, upload it with what `c`
/// made, and submit it to land on main (`POST …/land` of a snapshot).
fn land_crafted(mut c: Craft<'_>, parents: Vec<ObjectId>, wait: bool) -> Reply {
    let mut s = Snapshot {
        parents,
        change_id: veil_core::ChangeId::random(),
        tree: c.root,
        description: Text::Plain("crafted".into()),
        author: "crafter".into(),
        timestamp: veil_core::now_millis(),
        predecessors: vec![],
        conflicts: vec![],
        embargo: None,
        signature: None,
    };
    s.sign(&c.identity);
    let id = c.put(O::Snapshot(s));
    let up = c.api.upload(&c.token, &c.project, &c.objects);
    assert_eq!(up.status, 200, "{}", String::from_utf8_lossy(&up.body));
    let receipts = up.json()["receipts"].as_array().unwrap().clone();
    let map: serde_json::Map<String, Value> = c.objects.iter().zip(receipts).map(|((id, _), r)| (id.hex(), r)).collect();
    c.api.post_json(
        Some(&c.token),
        &format!("/v1/projects/{}/land", c.project),
        &json!({"onto": "main", "snapshot": id.hex(), "receipts": map, "wait": wait}),
    )
}

#[test]
fn bug_1102_a_merge_never_lets_a_non_admin_change_the_branch_rules() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    // The admin gives the devs the rules file (as
    // `protected_branches_move_only_by_landing_and_push_lands_instead`
    // does), then protects main.
    p.admin.ok(&p.dir, &["access", ".veilrules", "devs"]);
    p.admin.commit_main(&p.dir, "devs may edit the rules file");
    p.admin.ok(&p.dir, &["push"]);
    let token = p.dev.token();
    // A change of the dev's own from before the rules, kept on no branch
    // (an API commit without `onto`).
    let base = tip_for(&hub, &token, &p.name);
    let r = api.post_json(Some(&token), &format!("/v1/projects/{}/changes", p.name), &json!({"base": base.hex(), "edits": [put("src/side.rs", "side\n")]}));
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let unprotected: ObjectId = serde_json::from_value(r.json()["snapshot"].clone()).unwrap();
    write_files(&p.dir, &[(".veilrules", "[branches.main]\nprotected = true\n")]);
    p.admin.commit_main(&p.dir, "protect main");
    p.admin.ok(&p.dir, &["push"]);
    // A plain edit of the rules by the dev is refused (the builder's test).
    let r = land(&api, &token, &p.name, tip_for(&hub, &token, &p.name), json!([put(".veilrules", "")]), true);
    assert!(String::from_utf8_lossy(&r.body).contains("only admins may change the branch rules"));
    // The dev merges main with their change from before the rules, keeping
    // that side's (absent) .veilrules: every parent's rules count as "the
    // same rules" in `sync::complete`.
    let mut c = Craft::new(&api, &p.dev, &p.name, "main");
    without(&mut c, ".veilrules");
    let tip = c.tip;
    let r = land_crafted(c, vec![tip, unprotected], true);
    let body = String::from_utf8_lossy(&r.body).to_string();
    // Expected: refused, as any non-admin change of the rules is.
    let landed = r.status == 200 && r.json()["state"] == "landed";
    // Main is still protected: a plain push of it lands (it has a ticket).
    let mut c = Craft::new(&api, &p.dev, &p.name, "main");
    c.file("src/direct.rs", "direct\n");
    let v = c.push("main", "a direct push").json();
    assert!(v["results"][0]["ticket"].is_string(), "main is no longer protected after a non-admin's merge ({body}): {v}");
    assert!(!landed, "a non-admin's merge changed the branch rules: {body}");
}

#[test]
fn bug_1103_a_landed_stack_brings_every_change_the_branch_lacks() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    write_files(&p.dir, &[(".veilrules", "[branches.main]\nprotected = true\n")]);
    p.admin.commit_main(&p.dir, "protect main");
    p.admin.ok(&p.dir, &["push"]);
    let token = p.dev.token();
    let base = tip_for(&hub, &token, &p.name);
    // A change the server keeps on no branch (an API commit without
    // `onto`; a `vl push` of another branch, or a landing answered
    // `conflict`, leaves the same).
    let r = api.post_json(Some(&token), &format!("/v1/projects/{}/changes", p.name), &json!({"base": base.hex(), "edits": [put("src/first.rs", "first\n")]}));
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let first: ObjectId = serde_json::from_value(r.json()["snapshot"].clone()).unwrap();
    // A second change on top of it, pushed to main: it lands instead.
    let mut c = Craft::new(&api, &p.dev, &p.name, "main");
    c.file("src/first.rs", "first\n");
    c.file("src/second.rs", "second\n");
    c.tip = first;
    let v = c.push("main", "second").json();
    assert_eq!(v["results"][0]["ok"], true, "the push of a change on a held one lands: {v}");
    let check = p.dev.dir("check");
    p.dev.ok(p.dev.home.path(), &["clone", &hub.url(&p.name), check.to_str().unwrap()]);
    assert!(check.join("src/second.rs").exists(), "{v}");
    // Main was asked to hold both changes; it says "landed".
    assert!(check.join("src/first.rs").exists(), "main got the second change without the first, and the push said it landed: {v}");
}

#[test]
fn bug_1104_a_submitter_who_lost_access_is_told_nothing_of_what_changed_since() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    // fin is also a dev, so stays in the project without finance.
    p.admin.ok(&p.dir, &["group", "add", "devs", &p.fin.name]);
    let token = p.fin.token();
    let base = tip_for(&hub, &token, &p.name);
    let invoice = format!("{BILL_DIR}/acme/invoice.txt");
    let other = format!("{BILL_DIR}/acme/other.txt");
    hold(&hub, pid);
    let changed = land(&api, &token, &p.name, base, json!([put(&invoice, "fin's edit\n")]), false).json();
    let unchanged = land(&api, &token, &p.name, base, json!([put(&other, "fin's file\n")]), false).json();
    assert_eq!(changed["state"], "queued", "{changed}");
    // fin loses billing; then the admin edits the invoice (main is not
    // protected: a plain push, while fin's entries wait).
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.fin.name]);
    write_files(&p.dir, &[(&invoice, "the admin's edit, after fin lost billing\n")]);
    p.admin.commit_main(&p.dir, "after fin lost billing");
    p.admin.ok(&p.dir, &["push"]);
    release(&hub, pid);
    let u = outcome(&api, &token, &p.name, unchanged["ticket"].as_str().unwrap());
    assert_eq!(u["state"], "rejected", "{u}");
    let c = outcome(&api, &token, &p.name, changed["ticket"].as_str().unwrap());
    // Both answers must be the same kind: a `conflict` tells fin the
    // invoice changed after it was hidden from them.
    assert_eq!(c["state"], "rejected", "the answer tells someone without access that a hidden file changed: {c}");
}

#[test]
fn bug_1105_a_merge_checked_again_at_landing_keeps_its_other_parents() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    // The dev adds a file to src/ on a branch of their own.
    let mut c = Craft::new(&api, &p.dev, &p.name, "main");
    c.file("src/feature.rs", "feature\n");
    let r = c.push_to("feature", None);
    assert_eq!(r.json()["results"][0]["ok"], true, "{}", String::from_utf8_lossy(&r.body));
    // fin reads src/ (it is public) but may not write it; a merge taking
    // the dev's change from the other parent is allowed (`check_changes`).
    let ftok = p.fin.token();
    let feature = api.tips(Some(&ftok), &p.name).unwrap().branches["feature"];
    let mut m = Craft::new(&api, &p.fin, &p.name, "main");
    m.root = m.tree_of(feature);
    let tip = m.tip;
    hold(&hub, pid);
    let r = land_crafted(m, vec![tip, feature], false);
    let v = r.json();
    assert_eq!(v["state"], "queued", "accepted at submit: {v}");
    // fin's access epoch changes (a new group: nothing they may read or
    // write changes), so the checks run again when the merge lands.
    p.admin.ok(&p.dir, &["group", "create", "observers"]);
    p.admin.ok(&p.dir, &["group", "add", "observers", &p.fin.name]);
    release(&hub, pid);
    let r = outcome(&api, &ftok, &p.name, v["ticket"].as_str().unwrap());
    assert_eq!(r["state"], "landed", "{r}");
}

#[test]
fn bug_1106_a_landing_after_the_service_restarts_projects_one_batch_not_the_gap() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let token = p.dev.token();
    let r = land(&api, &token, &p.name, tip_for(&hub, &token, &p.name), json!([put("src/first.rs", "x\n")]), true);
    assert_eq!(r.json()["state"], "landed");
    // Nothing to land for longer than a service waits idle (5 s): it
    // stops, and the next one keeps no view key.
    std::thread::sleep(Duration::from_secs(7));
    // Then 150 landings by the admin (who sees real snapshots: no view
    // key), as any busy branch has from others.
    let atok = p.admin.token();
    let abase = tip_for(&hub, &atok, &p.name);
    let tickets: Vec<String> = (0..150)
        .map(|i| land(&api, &atok, &p.name, abase, json!([put(&format!("src/g/{i:03}.rs"), "x\n")]), false).json()["ticket"].as_str().unwrap().to_string())
        .collect();
    for t in &tickets {
        assert_eq!(outcome(&api, &atok, &p.name, t)["state"], "landed");
    }
    // No access changed. The dev lands once more.
    let before = veil_core::now_millis();
    let t = std::time::Instant::now();
    let r = land(&api, &token, &p.name, tip_for(&hub, &token, &p.name), json!([put("src/after.rs", "after\n")]), true);
    assert_eq!(r.json()["state"], "landed");
    let took = t.elapsed();
    let h = hub.hub();
    let rows: i64 = hub
        .rt
        .block_on(sqlx::query_scalar("SELECT count(*) FROM projections WHERE project_id = $1 AND created_at >= $2").bind(pid).bind(before).fetch_one(&h.db))
        .unwrap();
    assert!(rows <= 10, "{rows} projections made in the landing service's loop for one landing ({took:?}), with no access change");
}

/// This process's resident memory and its peak since the last reset, in
/// bytes (Linux).
fn rss() -> (u64, u64) {
    let s = std::fs::read_to_string("/proc/self/status").unwrap();
    let kb = |k: &str| s.lines().find(|l| l.starts_with(k)).unwrap().split_whitespace().nth(1).unwrap().parse::<u64>().unwrap() * 1024;
    (kb("VmRSS:"), kb("VmHWM:"))
}

/// BUG-1107, in a process of its own (it measures this process's memory,
/// which other tests running beside it would add to).
#[test]
fn bug_1107_a_batch_of_one_line_changes_in_a_big_folder_stays_within_memory() {
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["landing::big_folder_batch_in_a_child", "--exact", "--include-ignored", "--nocapture", "--test-threads", "1"])
        .env("VEIL_S17_CHILD", "1")
        // As the server's allocator (jemalloc, two arenas: BUG-864); this
        // test binary has glibc's, with an arena per thread.
        .env("MALLOC_ARENA_MAX", "2")
        .output()
        .unwrap();
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success() && text.contains("1 passed"), "{}", &text[text.len().saturating_sub(1500)..]);
}

#[test]
#[ignore = "helper of bug_1107 (run in a child process)"]
fn big_folder_batch_in_a_child() {
    if std::env::var_os("VEIL_S17_CHILD").is_none() {
        return;
    }
    use veil_core::object::{EntryKind, Tree, TreeEntry, Visibility};
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    // A folder of 30,000 files (generated code, fixtures, translations):
    // its listing is about 1.6 MB.
    let mut c = Craft::new(&api, &p.admin, &p.name, "main");
    let blob = c.put(O::Blob(b"x\n".to_vec()));
    let mut t = Tree::default();
    for i in 0..30_000 {
        t.insert(TreeEntry {
            name: format!("generated-file-{i:05}.rs"),
            kind: EntryKind::File,
            id: blob,
            size: 2,
            executable: false,
            visibility: Visibility::Public,
        });
    }
    let big = c.put(O::Tree(t));
    c.refer_dir("src/big", big);
    let r = c.push("main", "a big folder");
    assert_eq!(r.json()["results"][0]["ok"], true, "{}", String::from_utf8_lossy(&r.body));
    // 400 agents each change one file in it, from the same base.
    let token = p.dev.token();
    let base = tip_for(&hub, &token, &p.name);
    hold(&hub, pid);
    let tickets: Vec<String> = (0..400)
        .map(|i| {
            let r = land(&api, &token, &p.name, base, json!([put(&format!("src/big/generated-file-{i:05}.rs"), &format!("{i}\n"))]), false);
            assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
            r.json()["ticket"].as_str().unwrap().to_string()
        })
        .collect();
    // The peak from here: the landing service's batch.
    std::fs::write("/proc/self/clear_refs", "5").unwrap();
    let (start, _) = rss();
    let trees0 = hub.hub().trees.stats().weight;
    release(&hub, pid);
    for t in &tickets {
        assert_eq!(outcome(&api, &token, &p.name, t)["state"], "landed");
    }
    let (_, peak) = rss();
    // The decoded-tree cache filling (shared, bounded by its own budget,
    // 256 MiB) is not the batch's.
    let trees = hub.hub().trees.stats().weight.saturating_sub(trees0) as u64;
    eprintln!("decoded-tree cache grew by {} MiB", trees >> 20);
    let grew = peak.saturating_sub(start).saturating_sub(trees) >> 20;
    let batches = sql_i64(&hub, "SELECT count(*) FROM audit_log WHERE project_id = $1 AND action = 'land'", pid);
    eprintln!("the landing service's peak grew by {grew} MiB for 400 one-line changes ({batches} batches)");
    assert!(grew <= 256, "the landing service's peak grew by {grew} MiB for 400 one-line changes ({batches} batches)");
}

// S17 review, cycle 2 (docs/BUGS.md, "S17 cycle 2").

/// The content of `path` on main's real tip, if it is a file there.
fn real_file(hub: &TestHub, project: i64, path: &str) -> Option<Vec<u8>> {
    let src = source(hub, project);
    let mut id = src.snapshot(&real_tip(hub, project)).unwrap().tree;
    let parts: Vec<&str> = path.split('/').collect();
    for (i, part) in parts.iter().enumerate() {
        let O::Tree(t) = O::decode(&src.raw(&id).unwrap()).unwrap() else { return None };
        let e = t.get(part)?.clone();
        if i + 1 == parts.len() {
            return match O::decode(&src.raw(&e.id).unwrap()).unwrap() {
                O::Blob(b) => Some(b),
                _ => None,
            };
        }
        id = e.id;
    }
    None
}

/// Land a snapshot the server already holds (named as `token`'s owner sees
/// it), uploading nothing.
fn land_held(api: &Api, token: &str, project: &str, snapshot: ObjectId, wait: bool) -> Reply {
    api.post_json(
        Some(token),
        &format!("/v1/projects/{project}/land"),
        &json!({"onto": "main", "snapshot": snapshot.hex(), "receipts": {}, "wait": wait}),
    )
}

/// An API commit of `edits` on `base`, kept on no branch: the snapshot as
/// its maker sees it.
fn kept_change(api: &Api, token: &str, project: &str, base: ObjectId, edits: Value) -> ObjectId {
    let r = api.post_json(Some(token), &format!("/v1/projects/{project}/changes"), &json!({"base": base.hex(), "edits": edits}));
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    serde_json::from_value(r.json()["snapshot"].clone()).unwrap()
}

#[test]
fn bug_1110_a_stack_of_two_new_changes_lands() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    // Two new commits of the dev's, one on the other, landed at once (as
    // `vl push` of two commits to a protected branch submits them). Others
    // read src/ (it is public): their view keys see both changes.
    let mut c = Craft::new(&api, &p.dev, &p.name, "main");
    c.file("src/first.rs", "first\n");
    let mut s = Snapshot {
        parents: vec![c.tip],
        change_id: veil_core::ChangeId::random(),
        tree: c.root,
        description: Text::Plain("first".into()),
        author: "dev".into(),
        timestamp: veil_core::now_millis(),
        predecessors: vec![],
        conflicts: vec![],
        embargo: None,
        signature: None,
    };
    s.sign(&c.identity);
    let first = c.put(O::Snapshot(s));
    c.tip = first;
    c.file("src/second.rs", "second\n");
    let r = land_crafted(c, vec![first], true);
    let v = r.json();
    assert_eq!(v["state"], "landed", "a stack of two new changes: {v}");
    assert_eq!(v["landed"].as_array().map(Vec::len), Some(2), "{v}");
    assert!(real_file(&hub, pid, "src/first.rs").is_some() && real_file(&hub, pid, "src/second.rs").is_some());
}

#[test]
fn bug_1111_a_landing_answer_names_no_path_its_submitter_cannot_read() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    // fin (finance and devs) pushes a change of billing and src/ to a branch
    // of their own.
    p.admin.ok(&p.dir, &["group", "add", "devs", &p.fin.name]);
    let invoice = format!("{BILL_DIR}/acme/invoice.txt");
    let mut c = Craft::new(&api, &p.fin, &p.name, "main");
    c.file(&invoice, "fin's edit\n");
    c.file("src/fin.rs", "fin\n");
    let r = c.push_to("fin-wip", None);
    assert_eq!(r.json()["results"][0]["ok"], true, "{}", String::from_utf8_lossy(&r.body));
    // The admin edits the invoice on main meanwhile.
    write_files(&p.dir, &[(&invoice, "the admin's edit\n")]);
    p.admin.commit_main(&p.dir, "the admin's invoice edit");
    p.admin.ok(&p.dir, &["push"]);
    // The dev, who may not read billing, sees fin's change only as its
    // projection (src/fin.rs), and asks for it to land.
    let token = p.dev.token();
    let theirs = api.tips(Some(&token), &p.name).unwrap().branches["fin-wip"];
    let r = land_held(&api, &token, &p.name, theirs, true);
    let body = String::from_utf8_lossy(&r.body).to_string();
    assert!(!body.contains(BILL_DIR), "the dev's landing answer names a path under billing, which they cannot read: {body}");
    // fin's change is one the dev sees only in part: left for whoever sees
    // it whole, never landed in part (the S17 simplified rule).
    assert_eq!(r.status, 400, "{body}");
    assert!(body.contains("nothing to land"), "{body}");
    let pid = project_id(&hub, &p.name);
    assert!(real_file(&hub, pid, "src/fin.rs").is_none(), "a change the dev sees only in part landed in part");
    assert_eq!(real_file(&hub, pid, &invoice).as_deref(), Some(&b"the admin's edit\n"[..]));
    // fin, who sees all of it, lands it: the invoice moved on main since
    // fin's base, so that is a conflict (on fin's own path), never landed
    // over.
    let ftok = p.fin.token();
    let mine = api.tips(Some(&ftok), &p.name).unwrap().branches["fin-wip"];
    let v = land_held(&api, &ftok, &p.name, mine, true).json();
    assert_eq!(v["state"], "conflict", "{v}");
    assert_eq!(v["paths"], json!([invoice]), "{v}");
    assert_eq!(real_file(&hub, pid, &invoice).as_deref(), Some(&b"the admin's edit\n"[..]));
}

#[test]
fn bug_1112_edits_landed_on_an_unlanded_base_bring_the_base_or_are_refused() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let token = p.dev.token();
    // The dev's first change, kept on no branch (an API commit; a landing
    // answered `conflict` leaves the same).
    let first = kept_change(&api, &token, &p.name, tip_for(&hub, &token, &p.name), json!([put("src/first.rs", "first\n")]));
    // A second change made of edits on it, landed.
    let r = land(&api, &token, &p.name, first, json!([put("src/second.rs", "second\n")]), true).json();
    assert_eq!(r["state"], "landed", "{r}");
    assert_eq!(r["landed"].as_array().map(Vec::len), Some(2), "the base change lands with it: {r}");
    assert!(real_file(&hub, pid, "src/second.rs").is_some(), "{r}");
    assert!(real_file(&hub, pid, "src/first.rs").is_some(), "main got the second change without the first it was made on, and the answer says landed: {r}");
}

#[test]
fn bug_1270_stacks_that_share_a_change_both_land_and_it_lands_once() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let token = p.dev.token();
    // A change two agents build on (kept on no branch).
    let shared = kept_change(&api, &token, &p.name, tip_for(&hub, &token, &p.name), json!([put("src/shared.rs", "shared\n")]));
    // Two stacks on it, each one more change of a file of its own, both
    // queued before either lands.
    hold(&hub, pid);
    let mut tickets = Vec::new();
    for name in ["src/one.rs", "src/two.rs"] {
        let mut c = Craft::new(&api, &p.dev, &p.name, "main");
        c.root = c.tree_of(shared);
        c.tip = shared;
        c.file(name, "mine\n");
        let r = land_crafted(c, vec![shared], false).json();
        assert_eq!(r["state"], "queued", "{r}");
        tickets.push(r["ticket"].as_str().unwrap().to_string());
    }
    release(&hub, pid);
    let outcomes: Vec<Value> = tickets.iter().map(|t| outcome(&api, &token, &p.name, t)).collect();
    eprintln!("{outcomes:?}");
    for o in &outcomes {
        assert_eq!(o["state"], "landed", "a stack whose shared change landed with the other one is refused: {o}");
    }
    assert!(real_file(&hub, pid, "src/one.rs").is_some() && real_file(&hub, pid, "src/two.rs").is_some());
}

#[test]
fn bug_1271_a_conflicted_change_with_a_fix_on_top_lands() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let token = p.dev.token();
    // The dev changes src/lib.rs; the admin changes it on main first.
    let base = tip_for(&hub, &token, &p.name);
    let mine = kept_change(&api, &token, &p.name, base, json!([put("src/lib.rs", "the dev's\n")]));
    write_files(&p.dir, &[("src/lib.rs", "the admin's\n")]);
    p.admin.commit_main(&p.dir, "the admin's lib.rs");
    p.admin.ok(&p.dir, &["push"]);
    let r = land_held(&api, &token, &p.name, mine, true).json();
    assert_eq!(r["state"], "conflict", "{r}");
    // The fix on top (HUB.md §13.19 lists "a landing answered `conflict`
    // with a fix on top" among the stacks that land): the dev merges main
    // into their change and resolves the file.
    let main_now = tip_for(&hub, &token, &p.name);
    let mut c = Craft::new(&api, &p.dev, &p.name, "main");
    c.root = c.tree_of(mine);
    c.tip = mine;
    c.file("src/lib.rs", "the admin's and the dev's\n");
    let r = land_crafted(c, vec![mine, main_now], true);
    let v = r.json();
    eprintln!("{v}");
    assert_eq!(v["state"], "landed", "the fix on top of a conflicted change never lands: {v}");
    assert_eq!(real_file(&hub, pid, "src/lib.rs").as_deref(), Some(&b"the admin's and the dev's\n"[..]));
}

/// Guarantee 4 of the cycle-2 review: a merge checked again after an
/// access change is judged against all its parents, both ways: what it takes
/// from another parent stays allowed (bug_1105), and its own edit of a path
/// its submitter may no longer write is refused.
#[test]
fn a_merge_checked_again_refuses_its_own_edit_its_submitter_may_no_longer_write() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    p.admin.ok(&p.dir, &["group", "add", "devs", &p.fin.name]);
    let mut c = Craft::new(&api, &p.dev, &p.name, "main");
    c.file("src/feature.rs", "feature\n");
    let r = c.push_to("feature", None);
    assert_eq!(r.json()["results"][0]["ok"], true, "{}", String::from_utf8_lossy(&r.body));
    // fin (a dev for now) merges it, and edits src/own.rs in the merge.
    let ftok = p.fin.token();
    let feature = api.tips(Some(&ftok), &p.name).unwrap().branches["feature"];
    let mut m = Craft::new(&api, &p.fin, &p.name, "main");
    let tip = m.tip;
    m.root = m.tree_of(feature);
    m.tip = feature;
    m.file("src/own.rs", "fin's own\n");
    hold(&hub, pid);
    let v = land_crafted(m, vec![tip, feature], false).json();
    assert_eq!(v["state"], "queued", "accepted at submit: {v}");
    // fin is no longer a dev: src/ stays readable (public), not writable.
    p.admin.ok(&p.dir, &["group", "remove", "devs", &p.fin.name]);
    release(&hub, pid);
    let r = outcome(&api, &ftok, &p.name, v["ticket"].as_str().unwrap());
    assert_eq!(r["state"], "rejected", "{r}");
    assert!(real_file(&hub, pid, "src/own.rs").is_none());
}

/// Guarantee 1 of the cycle-2 review, on the routes bug_1102 does not take:
/// with main unprotected, a non-admin who may write `.veilrules` changes the
/// default branch's rules neither by an API commit with `onto` nor by a
/// plain push of a merge that keeps an older parent's (absent) rules.
#[test]
fn the_default_branch_rules_change_by_no_route_but_an_admin_s() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    p.admin.ok(&p.dir, &["access", ".veilrules", "devs"]);
    p.admin.commit_main(&p.dir, "devs may edit the rules file");
    p.admin.ok(&p.dir, &["push"]);
    let token = p.dev.token();
    let before = kept_change(&api, &token, &p.name, tip_for(&hub, &token, &p.name), json!([put("src/side.rs", "side\n")]));
    write_files(&p.dir, &[(".veilrules", "[branches.release]\nprotected = true\n")]);
    p.admin.commit_main(&p.dir, "protect release");
    p.admin.ok(&p.dir, &["push"]);
    let rules_tip = tip_for(&hub, &token, &p.name);
    // An API commit moving main.
    let r = api.post_json(
        Some(&token),
        &format!("/v1/projects/{}/changes", p.name),
        &json!({"base": rules_tip.hex(), "edits": [put(".veilrules", "")], "onto": {"branch": "main", "expected": rules_tip.hex()}}),
    );
    let body = String::from_utf8_lossy(&r.body).to_string();
    assert!(body.contains("only admins may change the branch rules"), "{} {body}", r.status);
    assert_eq!(tip_for(&hub, &token, &p.name), rules_tip, "{body}");
    // A plain push of a merge keeping the older parent's (absent) rules.
    let mut c = Craft::new(&api, &p.dev, &p.name, "main");
    without(&mut c, ".veilrules");
    let r = c.push_merge("main", &[before]);
    let body = String::from_utf8_lossy(&r.body).to_string();
    assert!(body.contains("only admins may change the branch rules"), "{} {body}", r.status);
    assert_eq!(tip_for(&hub, &token, &p.name), rules_tip, "{body}");
}

/// BUG-1272, in a process of its own (it measures this process's memory).
#[test]
fn bug_1272_a_stack_of_changes_in_a_big_folder_stays_within_the_batch_bound() {
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["landing::big_folder_stacks_in_a_child", "--exact", "--include-ignored", "--nocapture", "--test-threads", "1"])
        .env("VEIL_S17_CHILD", "1")
        // What the child's own crafting freed goes back to the system
        // before it measures (S17 cycle 3 review: glibc kept it, the
        // service's growth fitted in it unseen, and the child said 0 MiB).
        .env("VEIL_S17_TRIM", "1")
        .env("MALLOC_ARENA_MAX", "2")
        .output()
        .unwrap();
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success() && text.contains("1 passed"), "{}", &text[text.len().saturating_sub(1500)..]);
}

#[test]
#[ignore = "helper of bug_1272 (run in a child process)"]
fn big_folder_stacks_in_a_child() {
    if std::env::var_os("VEIL_S17_CHILD").is_none() {
        return;
    }
    use veil_core::object::{EntryKind, Tree, TreeEntry, Visibility};
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    // A folder of 60,000 files (twice bug_1107's), a listing of about 3.2 MB, in
    // a folder only admins read (so no view key's projection changes:
    // BUG-1110 does not hide this one).
    let mut c = Craft::new(&api, &p.admin, &p.name, "main");
    let blob = c.put(O::Blob(b"x\n".to_vec()));
    let mut t = Tree::default();
    for i in 0..60_000 {
        t.insert(TreeEntry {
            name: format!("generated-file-{i:05}.rs"),
            kind: EntryKind::File,
            id: blob,
            size: 2,
            executable: false,
            visibility: Visibility::Public,
        });
    }
    let big = c.put(O::Tree(t.clone()));
    c.refer_dir("gen/big", big);
    let r = c.push("main", "a big folder");
    assert_eq!(r.json()["results"][0]["ok"], true, "{}", String::from_utf8_lossy(&r.body));
    // Two agents (admins') each make a stack of 64 one-line changes in it
    // (as many as one landing takes), on the same base.
    let token = p.admin.token();
    let base = tip_for(&hub, &token, &p.name);
    hold(&hub, pid);
    let mut tickets = Vec::new();
    for agent in 0..2 {
        let mut c = Craft::new(&api, &p.admin, &p.name, "main");
        let mut parent = base;
        let mut t = t.clone();
        for k in 0..veil_core::hub::land::MAX_LAND_STACK {
            let i = agent * 1000 + k;
            let b = c.put(O::Blob(format!("{i}\n").into_bytes()));
            let mut e = t.get(&format!("generated-file-{i:05}.rs")).unwrap().clone();
            e.id = b;
            e.size = format!("{i}\n").len() as u64;
            t.remove(&e.name.clone());
            t.insert(e);
            let id = c.put(O::Tree(t.clone()));
            c.refer_dir("gen/big", id);
            let mut s = Snapshot {
                parents: vec![parent],
                change_id: veil_core::ChangeId::random(),
                tree: c.root,
                description: Text::Plain(format!("change {i}")),
                author: "agent".into(),
                timestamp: veil_core::now_millis(),
                predecessors: vec![],
                conflicts: vec![],
                embargo: None,
                signature: None,
            };
            s.sign(&c.identity);
            parent = c.put(O::Snapshot(s));
        }
        let up = c.api.upload(&c.token, &c.project, &c.objects);
        assert_eq!(up.status, 200, "{}", String::from_utf8_lossy(&up.body));
        let receipts = up.json()["receipts"].as_array().unwrap().clone();
        let map: serde_json::Map<String, Value> = c.objects.iter().zip(receipts).map(|((id, _), r)| (id.hex(), r)).collect();
        let r = c.api.post_json(Some(&c.token), &format!("/v1/projects/{}/land", c.project), &json!({"onto": "main", "snapshot": parent.hex(), "receipts": map, "wait": false}));
        assert_eq!(r.json()["state"], "queued", "{}", String::from_utf8_lossy(&r.body));
        tickets.push(r.json()["ticket"].as_str().unwrap().to_string());
    }
    // Main moves first, so both stacks are made again on it.
    let atok = p.admin.token();
    let a = land(&api, &atok, &p.name, tip_for(&hub, &atok, &p.name), json!([put("src/admin.rs", "admin\n")]), false).json();
    if std::env::var_os("VEIL_S17_TRIM").is_some() {
        // What the test's own crafting freed goes back to the system, so
        // the service's growth is not hidden in it (S17 cycle 3 review).
        extern "C" {
            fn malloc_trim(pad: usize) -> i32;
        }
        unsafe { malloc_trim(0) };
    }
    // The project's deriver is held meanwhile (as another server's would
    // be): what the deriver and the search index (which follows it) do
    // with these landings is not the landing service's (BUG-1305).
    let deriver = hub.rt.block_on(async {
        use sqlx::Connection;
        let url = std::env::var("VEIL_TEST_DATABASE_URL").unwrap();
        let mut c = sqlx::PgConnection::connect(&url).await.unwrap();
        let key: i64 = 0x7665_696c_6472_0000_i64 ^ pid;
        sqlx::query("SELECT pg_advisory_lock($1)").bind(key).execute(&mut c).await.unwrap();
        c
    });
    std::fs::write("/proc/self/clear_refs", "5").unwrap();
    let (start, _) = rss();
    let trees0 = hub.hub().trees.stats().weight;
    release(&hub, pid);
    assert_eq!(outcome(&api, &atok, &p.name, a["ticket"].as_str().unwrap())["state"], "landed");
    for t in &tickets {
        assert_eq!(outcome(&api, &token, &p.name, t)["state"], "landed");
    }
    let (_, peak) = rss();
    drop(deriver);
    let trees = hub.hub().trees.stats().weight.saturating_sub(trees0) as u64;
    let grew = peak.saturating_sub(start).saturating_sub(trees) >> 20;
    let batches = sql_i64(&hub, "SELECT count(*) FROM audit_log WHERE project_id = $1 AND action = 'land'", pid);
    eprintln!("decoded-tree cache grew by {} MiB; the landing service's peak grew by {grew} MiB for two stacks of 64 ({batches} batches)", trees >> 20);
    // bug_1107's bound for 400 such changes in batches of 8 MiB.
    assert!(grew <= 256, "the landing service's peak grew by {grew} MiB for two stacks of 64 one-line changes ({batches} batches)");
}

/// BUG-1112's class, the other two routes: `vl land` of a change on one the
/// server holds on another branch, and an API commit with `onto` on one kept
/// on no branch, each bring the change under it to main (a push and a
/// landing of edits: `bug_1103_…`, `bug_1112_…`).
#[test]
fn every_route_lands_the_changes_under_a_change() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    // `vl land`: A pushed to a branch of its own, B on it, landed.
    let d = p.dev.dir("land");
    p.dev.ok(p.dev.home.path(), &["clone", &hub.url(&p.name), d.to_str().unwrap()]);
    write_files(&d, &[("src/route-a.rs", "a\n")]);
    p.dev.ok(&d, &["commit", "-m", "a"]);
    p.dev.ok(&d, &["tag", "set", "side", "-r", "@-"]);
    p.dev.ok(&d, &["push", "-t", "side"]);
    write_files(&d, &[("src/route-b.rs", "b\n")]);
    p.dev.ok(&d, &["commit", "-m", "b"]);
    let out = p.dev.ok(&d, &["land"]);
    assert!(out.contains("landed main") && out.contains("2 change(s)"), "{out}");
    assert!(real_file(&hub, pid, "src/route-a.rs").is_some() && real_file(&hub, pid, "src/route-b.rs").is_some());
    // An API commit with `onto` (an expected tip) on a change kept on no
    // branch: the kept change is made again under it.
    let token = p.dev.token();
    let tip = tip_for(&hub, &token, &p.name);
    let kept = kept_change(&api, &token, &p.name, tip, json!([put("src/route-c.rs", "c\n")]));
    let r = api.post_json(
        Some(&token),
        &format!("/v1/projects/{}/changes", p.name),
        &json!({"base": kept.hex(), "edits": [put("src/route-d.rs", "d\n")], "onto": {"branch": "main", "expected": tip.hex()}}),
    );
    assert_eq!(r.json()["branch"]["status"], "ok", "{}", String::from_utf8_lossy(&r.body));
    assert!(real_file(&hub, pid, "src/route-c.rs").is_some() && real_file(&hub, pid, "src/route-d.rs").is_some());
}

/// The costs the cycle-2 review asked to measure, bounded: (1) the service
/// reads the project's view keys again at an access change, with 5,000
/// members; (2) waiters on a server that does not hold the lease cost that
/// server one statement per poll, however many wait.
#[test]
fn the_service_s_reads_at_an_access_change_and_remote_waiters_stay_bounded() {
    let a = TestHub::start();
    let p = setup_project(&a);
    let pid = project_id(&a, &p.name);
    let api = a.api();
    let token = p.dev.token();
    // 5,000 people in the devs group (straight into the database).
    let h = a.hub();
    a.rt.block_on(async {
        let gid: i64 = sqlx::query_scalar("SELECT id FROM groups WHERE project_id = $1 AND name = 'devs'").bind(pid).fetch_one(&h.db).await.unwrap();
        sqlx::query(
            "WITH p AS (INSERT INTO people (name, created_at) SELECT 'member-' || $2 || '-' || g, 0 FROM generate_series(1, 5000) g RETURNING id) \
             INSERT INTO group_members (group_id, person_id) SELECT $1, id FROM p",
        )
        .bind(gid)
        .bind(unique("m"))
        .execute(&h.db)
        .await
        .unwrap();
    });
    // An access change of the project (a new group), then a landing: the
    // service reads the view keys again before it.
    p.admin.ok(&p.dir, &["group", "create", "observers"]);
    let st = &h.landing.stats;
    let prep0 = st.prepare_us.load(std::sync::atomic::Ordering::Relaxed);
    let r = land(&api, &token, &p.name, tip_for(&a, &token, &p.name), json!([put("src/after.rs", "after\n")]), true);
    assert_eq!(r.json()["state"], "landed", "{}", String::from_utf8_lossy(&r.body));
    let prep = Duration::from_micros(st.prepare_us.load(std::sync::atomic::Ordering::Relaxed) - prep0);
    eprintln!("prepare with 5,000 members, after an access change: {prep:?}");
    assert!(prep < Duration::from_secs(2), "{prep:?}");
    // Waiters on a second server while the first holds the lease: hold it
    // as nobody, queue 100 landings through b, and count b's polls.
    let b = TestHub::beside(&a);
    hold(&a, pid);
    let bapi = b.api();
    let base = tip_for(&b, &token, &p.name);
    let polls = || b.hub().landing.stats.polls.load(std::sync::atomic::Ordering::Relaxed);
    let polls0 = polls();
    let t = std::time::Instant::now();
    std::thread::scope(|s| {
        for i in 0..100 {
            let (bapi, token, name) = (&bapi, &token, &p.name);
            s.spawn(move || {
                let r = land(bapi, token, name, base, json!([put(&format!("src/remote/{i:03}.rs"), "r\n")]), true);
                assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
                assert_eq!(r.json()["state"], "landed", "a remote waiter: {}", String::from_utf8_lossy(&r.body));
            });
        }
        // Released after 3 s: a's service lands them, b's poller answers.
        std::thread::sleep(Duration::from_secs(3));
        release(&a, pid);
        let _rt = a.rt.enter();
        veil_server::landing::ensure(&a.hub(), pid, "main");
    });
    let n = polls() - polls0;
    let secs = t.elapsed().as_secs_f64();
    eprintln!("100 remote waiters for {secs:.1} s: {n} statements from their server's poller");
    assert!((n as f64) < secs * 4.0 + 8.0, "{n} polls in {secs:.1} s for 100 waiters");
}


/// BUG-1275: a submit decides which changes it brings from the tip and the
/// service's own record of what it landed (`landings`), and the tips it
/// moved from: it never asks the derived graph, nor walks the branch, for
/// a change on the tip an agent read, nor on its own last landing, however
/// far the branch moved since (10,000 agents on one tip, the deriver behind).
#[test]
fn bug_1275_a_submit_on_a_tip_read_or_its_own_last_landing_never_walks_the_branch() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let token = p.dev.token();
    let walks = || hub.hub().landing.stats.walks.load(std::sync::atomic::Ordering::Relaxed);
    let first = tip_for(&hub, &token, &p.name);
    let walks0 = walks();
    // Agent A lands on the tip it read, then on its own last landing,
    // again and again; agent B stays on the first tip; agent C reads the tip
    // each time.
    let mut a_last = first;
    for i in 0..6 {
        let r = land(&api, &token, &p.name, a_last, json!([put(&format!("src/a/{i}.rs"), "a\n")]), true);
        let v = r.json();
        assert_eq!(v["state"], "landed", "{v}");
        a_last = serde_json::from_value(v["landed"].as_array().unwrap().last().unwrap().clone()).unwrap();
        let r = land(&api, &token, &p.name, first, json!([put(&format!("src/b/{i}.rs"), "b\n")]), true);
        assert_eq!(r.json()["state"], "landed", "{}", String::from_utf8_lossy(&r.body));
        let read = tip_for(&hub, &token, &p.name);
        let r = land(&api, &token, &p.name, read, json!([put(&format!("src/c/{i}.rs"), "c\n")]), true);
        assert_eq!(r.json()["state"], "landed", "{}", String::from_utf8_lossy(&r.body));
    }
    assert_eq!(walks() - walks0, 0, "a submit on a tip read, or on a landing, asked the graph or walked");
}

// ---------------------------------------------------------------------
// S17 cycle 3 review (docs/BUGS.md, "S17 cycle 3"): guarantees 1–5 of the
// cycle-2 fixes.

/// A branch update as `token`'s owner (an admin here) sends it, naming
/// snapshots the server holds (no upload): create (`expected` None), move,
/// force, or delete (`new` None).
fn move_branch(api: &Api, token: &str, project: &str, branch: &str, expected: Option<ObjectId>, new: Option<ObjectId>, force: bool) -> Value {
    let r = api.post_json(
        Some(token),
        &format!("/v1/projects/{project}/push"),
        &json!({"updates": [{"branch": branch, "expected": expected.map(|e| e.hex()), "new": new.map(|n| n.hex())}], "force": force, "receipts": {}}),
    );
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let v = r.json();
    assert_eq!(v["results"][0]["ok"], true, "the move of {branch}: {v}");
    v
}

/// Submit edits on `base` to land on `branch`, waiting.
fn land_on(api: &Api, token: &str, project: &str, branch: &str, base: ObjectId, edits: Value) -> Value {
    let r = api.post_json(
        Some(token),
        &format!("/v1/projects/{project}/land"),
        &json!({"onto": branch, "base": base.hex(), "edits": edits, "description": "a landing", "wait": true}),
    );
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    r.json()
}

/// The last snapshot an answer says landed (as its submitter sees it).
fn last_landed(v: &Value) -> ObjectId {
    serde_json::from_value(v["landed"].as_array().unwrap().last().unwrap().clone()).unwrap()
}

/// Is `path` in the real tree of `branch`'s tip?
fn on_branch_file(hub: &TestHub, project: i64, branch: &str, path: &str) -> bool {
    let h = hub.hub();
    let t: String = hub
        .rt
        .block_on(sqlx::query_scalar("SELECT target FROM branches WHERE project_id = $1 AND name = $2").bind(project).bind(branch).fetch_one(&h.db))
        .unwrap();
    let src = source(hub, project);
    let mut id = src.snapshot(&ObjectId::from_hex(&t).unwrap()).unwrap().tree;
    let parts: Vec<&str> = path.split('/').collect();
    for part in parts {
        let O::Tree(t) = O::decode(&src.raw(&id).unwrap()).unwrap() else { return false };
        let Some(e) = t.get(part) else { return false };
        id = e.id;
    }
    true
}

/// Guarantee 5: a branch deleted and made again starts a new history. The
/// service's record of what it landed on the old one (`landings`, keyed by
/// the branch's name) must not make a submit take a change of the old
/// history for one the new branch holds: the dev's change A, landed on the
/// old `feat` only, must land with B (made on A), or B must be refused;
/// never "landed" without A.
#[test]
fn bug_1300_a_branch_made_again_never_takes_the_old_branch_s_landings_for_its_history() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let atok = p.admin.token();
    let t0 = tip_for(&hub, &atok, &p.name);
    move_branch(&api, &atok, &p.name, "feat", None, Some(t0), false);
    let token = p.dev.token();
    let feat0 = api.tips(Some(&token), &p.name).unwrap().branches["feat"];
    let a = land_on(&api, &token, &p.name, "feat", feat0, json!([put("src/feat-a.rs", "a\n")]));
    assert_eq!(a["state"], "landed", "{a}");
    let a_id = last_landed(&a);
    assert!(on_branch_file(&hub, pid, "feat", "src/feat-a.rs"));
    // The dev keeps A on a branch of their own (as `vl push` of their work
    // does), so they can still name it.
    move_branch(&api, &token, &p.name, "dev-keep", None, Some(a_id), false);
    // The admin deletes feat, and makes it again on main's tip.
    let feat = api.tips(Some(&atok), &p.name).unwrap().branches["feat"];
    move_branch(&api, &atok, &p.name, "feat", Some(feat), None, false);
    move_branch(&api, &atok, &p.name, "feat", None, Some(t0), false);
    assert!(!on_branch_file(&hub, pid, "feat", "src/feat-a.rs"));
    // The dev's next change, B on A, lands on the new feat.
    let b = land_on(&api, &token, &p.name, "feat", a_id, json!([put("src/feat-b.rs", "b\n")]));
    assert_eq!(b["state"], "landed", "{b}");
    assert!(on_branch_file(&hub, pid, "feat", "src/feat-b.rs"), "{b}");
    assert!(
        on_branch_file(&hub, pid, "feat", "src/feat-a.rs"),
        "the new feat got B without A (A was landed only on the old feat), and the answer says landed: {b}"
    );
}

/// Guarantee 1 (an admin's forced push removes a landed change): what a
/// stack on the removed change lands must not depend on whether the
/// service's record of it is younger than a day. The same sequence twice:
/// with the record (the change under B is taken as on the branch and left
/// out), and with the record gone, as it is a day later (`clean`): the
/// change under B lands again with it.
#[test]
fn bug_1300_after_a_forced_move_a_stack_lands_the_same_however_old_the_service_s_record() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let atok = p.admin.token();
    let token = p.dev.token();
    let mut kept = Vec::new();
    for (round, forget) in [(1, false), (2, true)] {
        let t = tip_for(&hub, &atok, &p.name);
        let a = land(&api, &token, &p.name, tip_for(&hub, &token, &p.name), json!([put(&format!("src/forced-a{round}.rs"), "a\n")]), true).json();
        assert_eq!(a["state"], "landed", "{a}");
        let a_id = last_landed(&a);
        // The admin's forced push takes A away.
        move_branch(&api, &atok, &p.name, "main", Some(tip_for(&hub, &atok, &p.name)), Some(t), true);
        assert!(!on_branch_file(&hub, pid, "main", &format!("src/forced-a{round}.rs")));
        // Someone else's landing after it (so the service reads the moved
        // tip; BUG-1304).
        let o = land(&api, &atok, &p.name, tip_for(&hub, &atok, &p.name), json!([put(&format!("src/other{round}.rs"), "o\n")]), true).json();
        assert_eq!(o["state"], "landed", "{o}");
        if forget {
            // A day later: `clean` removed the service's record.
            let h = hub.hub();
            hub.rt.block_on(sqlx::query("DELETE FROM landings WHERE project_id = $1").bind(pid).execute(&h.db)).unwrap();
        }
        let b = land(&api, &token, &p.name, a_id, json!([put(&format!("src/forced-b{round}.rs"), "b\n")]), true).json();
        assert_eq!(b["state"], "landed", "{b}");
        assert!(on_branch_file(&hub, pid, "main", &format!("src/forced-b{round}.rs")), "{b}");
        kept.push(on_branch_file(&hub, pid, "main", &format!("src/forced-a{round}.rs")));
    }
    assert_eq!(
        kept[0], kept[1],
        "the removed change under B: landed again with B {} the record a day old, {} it is fresh",
        if kept[1] { "once" } else { "not even once" },
        if kept[0] { "and also while" } else { "but not while" }
    );
}

/// Guarantee 2 (the BUG-1111 refusal itself): a change that touched only
/// folders the dev cannot see is not in their history at all
/// (docs/VISIBILITY.md). The answer to landing a branch must be the same
/// whether or not such a change is below what they can see of it.
#[test]
fn bug_1301_a_landing_answer_never_tells_whether_a_hidden_change_is_below() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let invoice = format!("{BILL_DIR}/acme/invoice.txt");
    // The admin's branch with a billing-only change, then one in src/.
    let mut c = Craft::new(&api, &p.admin, &p.name, "main");
    c.file(&invoice, "the admin's hidden edit\n");
    let r = c.push_to("with-hidden", None);
    assert_eq!(r.json()["results"][0]["ok"], true, "{}", String::from_utf8_lossy(&r.body));
    let mut c = Craft::new(&api, &p.admin, &p.name, "with-hidden");
    c.file("src/visible-1.rs", "1\n");
    let r = c.push("with-hidden", "visible 1");
    assert_eq!(r.json()["results"][0]["ok"], true, "{}", String::from_utf8_lossy(&r.body));
    // And one with the src/ change only.
    let mut c = Craft::new(&api, &p.admin, &p.name, "main");
    c.file("src/visible-2.rs", "2\n");
    let r = c.push_to("without", None);
    assert_eq!(r.json()["results"][0]["ok"], true, "{}", String::from_utf8_lossy(&r.body));
    // The dev sees each branch as one change of src/ on main.
    let token = p.dev.token();
    let tips = api.tips(Some(&token), &p.name).unwrap().branches;
    let without = land_held(&api, &token, &p.name, tips["without"], true);
    assert_eq!(without.status, 200, "{}", String::from_utf8_lossy(&without.body));
    let without = without.json();
    assert_eq!(without["state"], "landed", "{without}");
    let with = land_held(&api, &token, &p.name, tips["with-hidden"], true);
    let body = String::from_utf8_lossy(&with.body).to_string();
    assert!(!body.contains(BILL_DIR), "{body}");
    assert_eq!(with.status, 200, "the answer differs because of a change the dev cannot see: {} {body}", with.status);
    assert_eq!(with.json()["state"], without["state"], "the answer differs because of a change the dev cannot see: {body}");
}

/// Guarantee 1: a fix on top of a conflicted change that is not a merge
/// of the branch stays `conflict` (the conflicted change is still in its
/// stack); the merge-in fix lands (bug_1271).
#[test]
fn a_fix_on_top_of_a_conflicted_change_that_is_not_a_merge_stays_conflict() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let token = p.dev.token();
    let base = tip_for(&hub, &token, &p.name);
    let mine = kept_change(&api, &token, &p.name, base, json!([put("src/lib.rs", "the dev's\n")]));
    write_files(&p.dir, &[("src/lib.rs", "the admin's\n")]);
    p.admin.commit_main(&p.dir, "the admin's lib.rs");
    p.admin.ok(&p.dir, &["push"]);
    let r = land_held(&api, &token, &p.name, mine, true).json();
    assert_eq!(r["state"], "conflict", "{r}");
    // A fix on top that edits the file again, without merging main.
    let mut c = Craft::new(&api, &p.dev, &p.name, "main");
    c.root = c.tree_of(mine);
    c.tip = mine;
    c.file("src/lib.rs", "the dev's, fixed\n");
    c.file("src/fix.rs", "fix\n");
    let v = land_crafted(c, vec![mine], true).json();
    assert_eq!(v["state"], "conflict", "{v}");
    assert_eq!(real_file(&hub, pid, "src/lib.rs").as_deref(), Some(&b"the admin's\n"[..]));
    assert!(real_file(&hub, pid, "src/fix.rs").is_none());
}

/// Guarantee 3 on the merge-in route (BUG-1271): a non-admin who may edit
/// `.veilrules` cannot change the default branch's rules by merging main
/// into a change of theirs from before the rules (its first parent; it has
/// no `.veilrules`, so every parent's rules count as "the same" at the
/// push's check, as in bug_1102): the merge lands as its edits against
/// main, which remove the rules, and is refused.
#[test]
fn a_merge_in_fix_never_lets_a_non_admin_change_the_default_branch_rules() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    p.admin.ok(&p.dir, &["access", ".veilrules", "devs"]);
    p.admin.commit_main(&p.dir, "devs may edit the rules file");
    p.admin.ok(&p.dir, &["push"]);
    let token = p.dev.token();
    let base = tip_for(&hub, &token, &p.name);
    // The dev's change of src/lib.rs from before the rules, kept.
    let mine = kept_change(&api, &token, &p.name, base, json!([put("src/lib.rs", "the dev's\n")]));
    write_files(&p.dir, &[(".veilrules", "[branches.release]\nprotected = true\n"), ("src/lib.rs", "the admin's\n")]);
    p.admin.commit_main(&p.dir, "the rules, and the admin's lib.rs");
    p.admin.ok(&p.dir, &["push"]);
    let main_now = tip_for(&hub, &token, &p.name);
    // The merge-in fix: main merged into the dev's change, keeping that
    // side's (absent) rules.
    let mut c = Craft::new(&api, &p.dev, &p.name, "main");
    c.root = c.tree_of(mine);
    c.tip = mine;
    c.file("src/lib.rs", "both\n");
    let r = land_crafted(c, vec![mine, main_now], true);
    let body = String::from_utf8_lossy(&r.body).to_string();
    assert_eq!(r.status, 200, "{body}");
    assert_eq!(r.json()["state"], "rejected", "{body}");
    assert!(body.contains("only admins may change the branch rules"), "{body}");
    assert_eq!(tip_for(&hub, &token, &p.name), main_now, "{body}");
}

/// Guarantee 2 on the merge-in route: a merge of main into someone else's
/// change with a billing edit (the dev reads src/, not billing) is refused
/// at the push's check, naming nothing under billing.
#[test]
fn a_merge_in_of_a_change_with_hidden_edits_names_no_hidden_path() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    p.admin.ok(&p.dir, &["group", "add", "devs", &p.fin.name]);
    let invoice = format!("{BILL_DIR}/acme/invoice.txt");
    let mut c = Craft::new(&api, &p.fin, &p.name, "main");
    c.file(&invoice, "fin's edit\n");
    c.file("src/lib.rs", "fin's lib\n");
    let r = c.push_to("fin-wip", None);
    assert_eq!(r.json()["results"][0]["ok"], true, "{}", String::from_utf8_lossy(&r.body));
    write_files(&p.dir, &[("src/lib.rs", "the admin's lib\n")]);
    p.admin.commit_main(&p.dir, "the admin's lib.rs");
    p.admin.ok(&p.dir, &["push"]);
    let token = p.dev.token();
    let theirs = api.tips(Some(&token), &p.name).unwrap().branches["fin-wip"];
    let main_now = tip_for(&hub, &token, &p.name);
    let mut c = Craft::new(&api, &p.dev, &p.name, "main");
    c.root = c.tree_of(theirs);
    c.tip = theirs;
    c.file("src/lib.rs", "both libs\n");
    let r = land_crafted(c, vec![theirs, main_now], true);
    let body = String::from_utf8_lossy(&r.body).to_string();
    assert_eq!(r.status, 403, "{body}");
    assert!(body.contains("combines changes in folders you cannot see"), "{body}");
    assert!(!body.contains(BILL_DIR), "{body}");
    assert_eq!(tip_for(&hub, &token, &p.name), main_now, "{body}");
}

/// Pre-existing (S17 cycle 1): a batch that lands nothing commits its
/// answers without checking that the branch is still at the tip it judged
/// them on (only a batch that moves the branch compares). After a move the
/// service did not make (a plain push to an unprotected branch, an admin's
/// forced push), a change made on the new tip is answered `conflict`
/// against the old one, though it lands on the branch as it is.
#[test]
fn bug_1304_a_change_made_on_a_tip_the_service_did_not_make_is_judged_on_that_tip() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let token = p.dev.token();
    // A landing starts main's service (it keeps main's tip in memory).
    let a = land(&api, &token, &p.name, tip_for(&hub, &token, &p.name), json!([put("src/started.rs", "s\n")]), true).json();
    assert_eq!(a["state"], "landed", "{a}");
    // The admin pushes main (unprotected) directly: an edit of src/lib.rs.
    let mut c = Craft::new(&api, &p.admin, &p.name, "main");
    c.file("src/lib.rs", "the admin's\n");
    let r = c.push("main", "a direct push");
    assert_eq!(r.json()["results"][0]["ok"], true, "{}", String::from_utf8_lossy(&r.body));
    // The dev edits src/lib.rs on that tip, at once (the service is still
    // running, `IDLE`).
    let v = land(&api, &token, &p.name, tip_for(&hub, &token, &p.name), json!([put("src/lib.rs", "the dev's, on the admin's\n")]), true).json();
    assert_eq!(v["state"], "landed", "a change made on the branch's tip, answered against a tip the branch left: {v}");
    assert_eq!(real_file(&hub, pid, "src/lib.rs").as_deref(), Some(&b"the dev's, on the admin's\n"[..]));
}

/// A chain of `n` new snapshots on `branch`'s tip as `person` sees it,
/// pushed in one push: each adds `{dir}/{i}.rs` when `dir` is given, else
/// keeps the tree. The new tip as they see it.
fn push_chain(api: &Api, person: &Person, project: &str, branch: &str, onto: &str, n: usize, dir: Option<&str>) -> ObjectId {
    let mut c = Craft::new(api, person, project, onto);
    let expected = api.tips(Some(&c.token), project).unwrap().branches.get(branch).copied();
    let mut parent = c.tip;
    for i in 0..n {
        if let Some(d) = dir {
            c.file(&format!("{d}/{i}.rs"), &format!("{i}\n"));
        }
        let mut s = Snapshot {
            parents: vec![parent],
            change_id: veil_core::ChangeId::random(),
            tree: c.root,
            description: Text::Plain(format!("chain {i}")),
            author: "chain".into(),
            timestamp: veil_core::now_millis(),
            predecessors: vec![],
            conflicts: vec![],
            embargo: None,
            signature: None,
        };
        s.sign(&c.identity);
        parent = c.put(O::Snapshot(s));
    }
    let up = c.api.upload(&c.token, &c.project, &c.objects);
    assert_eq!(up.status, 200, "{}", String::from_utf8_lossy(&up.body));
    let receipts = up.json()["receipts"].as_array().unwrap().clone();
    let map: serde_json::Map<String, Value> = c.objects.iter().zip(receipts).map(|((id, _), r)| (id.hex(), r)).collect();
    let r = c.api.post_json(
        Some(&c.token),
        &format!("/v1/projects/{project}/push"),
        &json!({"updates": [{"branch": branch, "expected": expected.map(|e| e.hex()), "new": parent.hex()}], "receipts": map}),
    );
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["results"][0]["ok"], true, "{}", String::from_utf8_lossy(&r.body));
    parent
}

/// Guarantee 4, the fallback walk: when a submit's base, or a change it
/// brings, is not in `landings` (older than a day, from before the service
/// ran, or not on the branch at all) and the derived graph does not hold
/// the tip (the deriver is behind, or another server's holds the project),
/// `landing::stack` walks the branch (`sync::is_ancestor`: every snapshot
/// down to the root when the change is not on it), once per change of the
/// stack, on the request. Here: main with 5,000 snapshots of history, the
/// deriver held, and a dev landing their 64-change branch.
#[test]
fn bug_1302_a_submit_s_stack_never_walks_the_branch_s_history_per_change() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    // The deriver of the project is held (as by another server's, or
    // behind): the graph never holds main's tip below.
    let h = hub.hub();
    let lock = hub.rt.block_on(async {
        use sqlx::Connection;
        let url = std::env::var("VEIL_TEST_DATABASE_URL").unwrap();
        let mut c = sqlx::PgConnection::connect(&url).await.unwrap();
        let key: i64 = 0x7665_696c_6472_0000_i64 ^ pid;
        sqlx::query("SELECT pg_advisory_lock($1)").bind(key).execute(&mut c).await.unwrap();
        c
    });
    let t = std::time::Instant::now();
    push_chain(&api, &p.admin, &p.name, "main", "main", 5_000, None);
    eprintln!("5,000 snapshots of history pushed in {:?}", t.elapsed());
    // The dev's 64 changes on a branch of their own, then landed on main.
    let token = p.dev.token();
    let side = push_chain(&api, &p.dev, &p.name, "side", "main", veil_core::hub::land::MAX_LAND_STACK, Some("src/side"));
    let walks = || h.landing.stats.walks.load(std::sync::atomic::Ordering::Relaxed);
    let w0 = walks();
    let t = std::time::Instant::now();
    let r = land_held(&api, &token, &p.name, side, false);
    let took = t.elapsed();
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["state"], "queued", "{}", String::from_utf8_lossy(&r.body));
    eprintln!("the submit of a 64-change stack took {took:?} ({} walks)", walks() - w0);
    drop(lock);
    // A submit's own work is bounded by its stack, not by the branch's
    // history (bug_1275 measured 954 landings/s at 1,000 agents).
    assert!(took < Duration::from_secs(2), "the submit of a 64-change stack took {took:?} on a branch of 5,000 snapshots ({} walks)", walks() - w0);
}

/// Guarantee 4, retention: finished queue rows and `landings` rows older
/// than a day go (`Service::clean`), also while the branch is busy. Here a
/// backlog of 600 landings, and a row a day old of each table: they must
/// go before the backlog is landed (clean runs only once the queue is
/// empty, so at the 1,000- and 10,000-agent loads, never).
#[test]
fn bug_1303_rows_a_day_old_go_while_the_branch_is_busy() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let token = p.dev.token();
    let first = land(&api, &token, &p.name, tip_for(&hub, &token, &p.name), json!([put("src/first.rs", "f\n")]), true).json();
    assert_eq!(first["state"], "landed", "{first}");
    let h = hub.hub();
    // The service stops (idle; its first clean ran), and the lease is held
    // as nobody's while the old rows and the backlog are made.
    std::thread::sleep(Duration::from_secs(7));
    hold(&hub, pid);
    // A finished row and a `landings` row, each a day and a minute old.
    let old = veil_core::now_millis() - 24 * 3600 * 1000 - 60_000;
    hub.rt.block_on(async {
        sqlx::query("UPDATE landing_queue SET done_at = $2 WHERE project_id = $1 AND ticket = $3").bind(pid).bind(old).bind(first["ticket"].as_str().unwrap()).execute(&h.db).await.unwrap();
        sqlx::query("INSERT INTO landings (project_id, branch, lineage, submitted, landed, at) VALUES ($1, 'main', 0, $2, $2, $3)").bind(pid).bind(ObjectId::hash(b"old").hex()).bind(old).execute(&h.db).await.unwrap();
    });
    let base = tip_for(&hub, &token, &p.name);
    std::thread::scope(|s| {
        for t in 0..8 {
            let (api, token, name) = (&api, &token, &p.name);
            s.spawn(move || {
                for i in 0..75 {
                    let r = land(api, token, name, base, json!([put(&format!("src/backlog/{t}-{i:03}.rs"), "b\n")]), false);
                    assert_eq!(r.json()["state"], "queued", "{}", String::from_utf8_lossy(&r.body));
                }
            });
        }
    });
    let count = |q: &str| hub.rt.block_on(sqlx::query_scalar::<_, i64>(q).bind(pid).fetch_one(&h.db)).unwrap();
    let stale = || {
        count(&format!("SELECT count(*) FROM landing_queue WHERE project_id = $1 AND done_at < {}", old + 1))
            + count(&format!("SELECT count(*) FROM landings WHERE project_id = $1 AND at < {}", old + 1))
    };
    assert_eq!(stale(), 2);
    release(&hub, pid);
    let t = std::time::Instant::now();
    // Read the old rows first, then the queue: nothing is submitted any
    // more, so the queue only shrinks, and "the old rows are gone while
    // entries are still queued" means the clean ran while it was busy.
    let mut cleaned_while_busy = None;
    let mut drained = false;
    while t.elapsed() < Duration::from_secs(120) && !drained {
        // (No waiter here starts the service: the test does, as a submit
        // or a waiter's poller would.)
        {
            let _rt = hub.rt.enter();
            veil_server::landing::ensure(&h, pid, "main");
        }
        let gone = stale() == 0;
        let queued = count("SELECT count(*) FROM landing_queue WHERE project_id = $1 AND state = 'queued'");
        if gone && cleaned_while_busy.is_none() {
            cleaned_while_busy = Some(queued > 0);
        }
        drained = queued == 0;
        std::thread::sleep(Duration::from_millis(20));
    }
    eprintln!("the backlog landed after {:?}; the old rows went while entries were queued: {cleaned_while_busy:?}", t.elapsed());
    assert!(drained, "the backlog landed within 2 minutes");
    let landed = count("SELECT count(*) FROM landing_queue WHERE project_id = $1 AND state = 'landed'");
    assert!(landed >= 600, "{landed} landed");
    assert_eq!(cleaned_while_busy, Some(true), "the day-old rows stayed while the branch was busy (until its queue was empty)");
}

// ---------------------------------------------------------------------
// S17 cycle 3, the revised design (docs/HUB.md §13.19): the stack is the
// submitter's own history; "on the branch" within the branch's lineage;
// a bounded base lookup.

/// A branch `branch` of crafted snapshots on `onto`'s tip as `person` sees
/// it, one per step (its files, and a seed for its change id), with fixed
/// metadata (times from `t0`), so the same steps make the same snapshots:
/// their ids.
fn crafted_branch(api: &Api, person: &Person, project: &str, onto: &str, branch: &str, steps: &[(&[(&str, &str)], u8)], t0: i64) -> Vec<ObjectId> {
    let mut c = Craft::new(api, person, project, onto);
    let mut parent = c.tip;
    let mut ids = Vec::new();
    for (files, seed) in steps {
        for (path, text) in files.iter() {
            c.file(path, text);
        }
        let mut s = Snapshot {
            parents: vec![parent],
            change_id: veil_core::ChangeId([*seed; 16]),
            tree: c.root,
            description: Text::Plain(format!("step {seed}")),
            author: "crafter".into(),
            timestamp: t0 + i64::from(*seed),
            predecessors: vec![],
            conflicts: vec![],
            embargo: None,
            signature: None,
        };
        s.sign(&c.identity);
        parent = c.put(O::Snapshot(s));
        ids.push(parent);
    }
    let up = c.api.upload(&c.token, &c.project, &c.objects);
    assert_eq!(up.status, 200, "{}", String::from_utf8_lossy(&up.body));
    let receipts = up.json()["receipts"].as_array().unwrap().clone();
    let map: serde_json::Map<String, Value> = c.objects.iter().zip(receipts).map(|((id, _), r)| (id.hex(), r)).collect();
    let r = c.api.post_json(
        Some(&c.token),
        &format!("/v1/projects/{project}/push"),
        &json!({"updates": [{"branch": branch, "expected": null, "new": parent.hex()}], "receipts": map}),
    );
    assert_eq!(r.json()["results"][0]["ok"], true, "{}", String::from_utf8_lossy(&r.body));
    ids
}

/// The first parent of snapshot `id` as `token`'s owner is shown it.
fn seen_parent(api: &Api, token: &str, project: &str, id: ObjectId) -> ObjectId {
    let h = api.post_json(Some(token), &format!("/v1/projects/{project}/history"), &json!({"tips": [id.hex()]}));
    let (_, raw) = h.frames().into_iter().find(|(i, _)| *i == id).unwrap();
    let O::Snapshot(s) = O::decode(&raw).unwrap() else { panic!("not a snapshot") };
    s.parents[0]
}

/// An answer without its ticket (each submit's own).
fn without_ticket(mut v: Value) -> Value {
    v.as_object_mut().unwrap().remove("ticket");
    v
}

/// Guarantee: answers are identical whether or not changes the submitter
/// cannot see sit between the changes they land (docs/VISIBILITY.md: such
/// a change is not in their history). The admin's branch A interleaves
/// billing-only changes with two src/ changes; branch B holds the same two
/// src/ changes alone. The dev sees both branches as the same snapshots,
/// lands A's two points one after the other, then (main reset to where it
/// was) B's: every answer, and main as the dev sees it, is the same.
#[test]
fn answers_are_the_same_whether_or_not_hidden_changes_sit_between_the_changes_landed() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let atok = p.admin.token();
    let token = p.dev.token();
    let main0 = tip_for(&hub, &atok, &p.name);
    let t0 = veil_core::now_millis();
    let h1 = format!("{BILL_DIR}/hidden-1.txt");
    let h2 = format!("{BILL_DIR}/hidden-2.txt");
    let v1: &[(&str, &str)] = &[("src/g/one.rs", "one\n")];
    let v2: &[(&str, &str)] = &[("src/g/two.rs", "two\n")];
    crafted_branch(&api, &p.admin, &p.name, "main", "g-a", &[(v1, 1), (&[(&h1, "h1\n")], 2), (v2, 3), (&[(&h2, "h2\n")], 4)], t0);
    let two = api.tips(Some(&token), &p.name).unwrap().branches["g-a"];
    let one = seen_parent(&api, &token, &p.name, two);
    let land_point = |id: ObjectId| {
        let r = land_held(&api, &token, &p.name, id, true);
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        without_ticket(r.json())
    };
    let a1 = land_point(one);
    let a2 = land_point(two);
    assert_eq!(a1["state"], "landed", "{a1}");
    assert_eq!(a2["state"], "landed", "{a2}");
    let main_a = tip_for(&hub, &token, &p.name);
    assert!(real_file(&hub, pid, &h1).is_none() && real_file(&hub, pid, &h2).is_none(), "a change the dev cannot see landed");
    // main back where it was; the same two changes, with nothing between.
    move_branch(&api, &atok, &p.name, "main", Some(tip_for(&hub, &atok, &p.name)), Some(main0), true);
    crafted_branch(&api, &p.admin, &p.name, "main", "g-b", &[(v1, 1), (v2, 3)], t0);
    assert_eq!(api.tips(Some(&token), &p.name).unwrap().branches["g-b"], two, "the dev sees the two branches as the same snapshots");
    let b1 = land_point(one);
    let b2 = land_point(two);
    assert_eq!(a1, b1, "landing the first point");
    assert_eq!(a2, b2, "landing the second point");
    assert_eq!(tip_for(&hub, &token, &p.name), main_a, "main as the dev sees it");
}

/// Guarantee: a submitter lands only changes they see whole (the S17
/// simplified rule). fin's change edits the invoice (billing) and src/; the
/// dev, who reads src/ only, sees it only in part: their landing of it lands
/// nothing (naming nothing of billing), and it stays for fin, whose landing
/// lands all of it, once; the dev landing it again then lands nothing.
#[test]
fn a_change_its_submitter_sees_only_in_part_is_left_for_whoever_sees_it_whole() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    p.admin.ok(&p.dir, &["group", "add", "devs", &p.fin.name]);
    let invoice = format!("{BILL_DIR}/acme/invoice.txt");
    let mut c = Craft::new(&api, &p.fin, &p.name, "main");
    c.file(&invoice, "fin's edit\n");
    c.file("src/fin.rs", "fin\n");
    let r = c.push_to("fin-wip", None);
    assert_eq!(r.json()["results"][0]["ok"], true, "{}", String::from_utf8_lossy(&r.body));
    let tip0 = real_tip(&hub, pid);
    let token = p.dev.token();
    let theirs = api.tips(Some(&token), &p.name).unwrap().branches["fin-wip"];
    let r = land_held(&api, &token, &p.name, theirs, true);
    let body = String::from_utf8_lossy(&r.body).to_string();
    assert_eq!(r.status, 400, "{body}");
    assert!(body.contains("nothing to land") && !body.contains(BILL_DIR), "{body}");
    assert_eq!(real_tip(&hub, pid), tip0, "a change the dev sees only in part landed");
    let ftok = p.fin.token();
    let mine = api.tips(Some(&ftok), &p.name).unwrap().branches["fin-wip"];
    let v = land_held(&api, &ftok, &p.name, mine, true).json();
    assert_eq!(v["state"], "landed", "{v}");
    assert_eq!(real_file(&hub, pid, &invoice).as_deref(), Some(&b"fin's edit\n"[..]));
    assert_eq!(real_file(&hub, pid, "src/fin.rs").as_deref(), Some(&b"fin\n"[..]));
    // One snapshot, with exactly the change's two edits.
    let tip = real_tip(&hub, pid);
    let src = source(&hub, pid);
    let s = src.snapshot(&tip).unwrap();
    assert_eq!(s.parents, vec![tip0]);
    let set = veil_server::landing::edits::edit_set(&src, s.tree, src.snapshot(&s.parents[0]).unwrap().tree).unwrap();
    assert_eq!(set.iter().map(|c| c.path.clone()).collect::<Vec<_>>(), vec![invoice.clone(), "src/fin.rs".to_string()]);
    let r = land_held(&api, &token, &p.name, theirs, true);
    assert_eq!(r.status, 400, "{}", String::from_utf8_lossy(&r.body));
    assert!(String::from_utf8_lossy(&r.body).contains("nothing to land"), "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(real_tip(&hub, pid), tip);
}

/// Guarantee: exactly once across a reset. An entry queued before an
/// admin's forced push moves its branch was judged against a history the
/// branch no longer has: it is answered so, never landed on what it took
/// for its base, and lands once when submitted again.
#[test]
fn an_entry_queued_before_its_branch_is_reset_lands_only_when_submitted_again() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let atok = p.admin.token();
    let token = p.dev.token();
    let t0 = tip_for(&hub, &atok, &p.name);
    let a = land(&api, &token, &p.name, tip_for(&hub, &token, &p.name), json!([put("src/reset-a.rs", "a\n")]), true).json();
    assert_eq!(a["state"], "landed", "{a}");
    hold(&hub, pid);
    let q = land(&api, &token, &p.name, last_landed(&a), json!([put("src/reset-b.rs", "b\n")]), false).json();
    assert_eq!(q["state"], "queued", "{q}");
    // The admin resets main to before A.
    move_branch(&api, &atok, &p.name, "main", Some(tip_for(&hub, &atok, &p.name)), Some(t0), true);
    release(&hub, pid);
    {
        let _rt = hub.rt.enter();
        veil_server::landing::ensure(&hub.hub(), pid, "main");
    }
    let v = outcome(&api, &token, &p.name, q["ticket"].as_str().unwrap());
    assert_eq!(v["state"], "rejected", "{v}");
    assert!(v["message"].as_str().unwrap().contains("reset"), "{v}");
    assert!(real_file(&hub, pid, "src/reset-b.rs").is_none());
    // Submitted again on main as it is: A is no longer on it, so B brings A.
    let again = land(&api, &token, &p.name, last_landed(&a), json!([put("src/reset-b.rs", "b\n")]), true).json();
    assert_eq!(again["state"], "landed", "{again}");
    assert!(real_file(&hub, pid, "src/reset-a.rs").is_some() && real_file(&hub, pid, "src/reset-b.rs").is_some());
    let src = source(&hub, pid);
    let mut x = real_tip(&hub, pid);
    let mut adds = 0;
    while x != t0 {
        let s = src.snapshot(&x).unwrap();
        let set = veil_server::landing::edits::edit_set(&src, s.tree, src.snapshot(&s.parents[0]).unwrap().tree).unwrap();
        adds += set.iter().filter(|c| c.path == "src/reset-b.rs").count();
        x = s.parents[0];
    }
    assert_eq!(adds, 1, "B landed more than once");
}

/// Guarantee: a submit's cost is bounded. With the derived graph behind the
/// tip (another server's deriver holds the project) and a base 5,000
/// snapshots down main that `landings` does not know, the submit reads at
/// most `WALK_BUDGET` snapshots and is answered `warming` (try again),
/// never walking the history.
#[test]
fn a_submit_whose_base_is_past_its_walk_budget_is_answered_warming() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let atok = p.admin.token();
    let t0 = tip_for(&hub, &atok, &p.name);
    let lock = hub.rt.block_on(async {
        use sqlx::Connection;
        let url = std::env::var("VEIL_TEST_DATABASE_URL").unwrap();
        let mut c = sqlx::PgConnection::connect(&url).await.unwrap();
        let key: i64 = 0x7665_696c_6472_0000_i64 ^ pid;
        sqlx::query("SELECT pg_advisory_lock($1)").bind(key).execute(&mut c).await.unwrap();
        c
    });
    push_chain(&api, &p.admin, &p.name, "main", "main", 5_000, None);
    move_branch(&api, &atok, &p.name, "old", None, Some(t0), false);
    let token = p.dev.token();
    let mine = push_chain(&api, &p.dev, &p.name, "old-work", "old", 1, Some("src/old"));
    let t = std::time::Instant::now();
    let r = land_held(&api, &token, &p.name, mine, false);
    let took = t.elapsed();
    drop(lock);
    assert_eq!(r.status, 503, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["code"], "warming", "{}", String::from_utf8_lossy(&r.body));
    assert!(took < Duration::from_secs(2), "the submit took {took:?}");
}

/// BUG-1310: a change landed, its branch reset by an admin, then landed
/// again, is made again exactly as before (the same snapshot), whose
/// projections were stored the first time. Meanwhile someone else's view
/// stored a projection of the submitted change itself, so the batch's own
/// projection of the snapshot (which now names that one as its
/// predecessor) differs from the stored one: a stored memo wins, the batch
/// rolled back, was built again the same way, and lost again, for as long
/// as anyone waited. It must land, with what is stored.
#[test]
fn bug_1310_a_change_landed_again_after_a_reset_lands_with_its_stored_projections() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let atok = p.admin.token();
    let token = p.dev.token();
    let t0 = tip_for(&hub, &atok, &p.name);
    // No one else's view projects the dev's change while it first lands
    // (the deriver, which keeps every view's tips, is held).
    let deriver = hub.rt.block_on(async {
        use sqlx::Connection;
        let url = std::env::var("VEIL_TEST_DATABASE_URL").unwrap();
        let mut c = sqlx::PgConnection::connect(&url).await.unwrap();
        let key: i64 = 0x7665_696c_6472_0000_i64 ^ pid;
        sqlx::query("SELECT pg_advisory_lock($1)").bind(key).execute(&mut c).await.unwrap();
        c
    });
    let mine = push_chain(&api, &p.dev, &p.name, "dev-work", "main", 1, Some("src/again"));
    let v = land_held(&api, &token, &p.name, mine, true).json();
    assert_eq!(v["state"], "landed", "{v}");
    drop(deriver);
    // fin's view projects the change itself (fin reads the dev's branch).
    let ftok = p.fin.token();
    let _ = api.tips(Some(&ftok), &p.name).unwrap().branches["dev-work"];
    // The admin resets main; the dev lands the same change again.
    move_branch(&api, &atok, &p.name, "main", Some(tip_for(&hub, &atok, &p.name)), Some(t0), true);
    let t = std::time::Instant::now();
    let again = land_held(&api, &token, &p.name, mine, true);
    assert_eq!(again.status, 200, "{}", String::from_utf8_lossy(&again.body));
    let again = again.json();
    assert_eq!(again["state"], "landed", "after {:?}: {again}", t.elapsed());
    assert_eq!(again["landed"], v["landed"], "made again exactly as before");
    assert!(real_file(&hub, pid, "src/again/0.rs").is_some());
}

// ---- S17 redesign review (cycle 1 of the revised design) ----------------

/// BUG-1311: "the stack is the submitter's own history" also for the next
/// submitter. The admin's branch holds A (src/), H (billing only) and B
/// (src/); the dev, who cannot see H, lands B: A and B land, H stays
/// unlanded (it is not in the dev's history). B is then recorded as landed
/// "whole" (all of B's own edits landed), and every later stack takes B for
/// on main, though B's history (its tree) holds H and main does not. The
/// admin, who sees all three, landing B must land H, or be told it is not
/// on main; never "nothing to land" with H missing.
#[test]
fn bug_1311_a_change_landed_for_a_view_that_left_out_a_change_below_still_brings_it_for_whoever_sees_it() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let atok = p.admin.token();
    let token = p.dev.token();
    let t0 = veil_core::now_millis();
    let hidden = format!("{BILL_DIR}/between.txt");
    let ids = crafted_branch(
        &api,
        &p.admin,
        &p.name,
        "main",
        "hc",
        &[(&[("src/hc/a.rs", "a\n")], 1), (&[(&hidden, "h\n")], 2), (&[("src/hc/b.rs", "b\n")], 3)],
        t0,
    );
    // The dev lands what they see of the branch: A and B.
    let seen = api.tips(Some(&token), &p.name).unwrap().branches["hc"];
    let r = land_held(&api, &token, &p.name, seen, true);
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let v = r.json();
    assert_eq!(v["state"], "landed", "{v}");
    assert!(real_file(&hub, pid, "src/hc/a.rs").is_some() && real_file(&hub, pid, "src/hc/b.rs").is_some(), "{v}");
    assert!(real_file(&hub, pid, &hidden).is_none(), "a change the dev cannot see landed");
    // The admin lands B, whose history holds H.
    let r = land_held(&api, &atok, &p.name, ids[2], true);
    let body = String::from_utf8_lossy(&r.body).to_string();
    assert_eq!(r.status, 200, "the admin's B, whose history holds H (not on main), was refused: {body}");
    assert_eq!(r.json()["state"], "landed", "{body}");
    assert_eq!(real_file(&hub, pid, &hidden).as_deref(), Some(&b"h\n"[..]), "H is in the admin's history below B and not on main: {body}");
}

/// fin's change P edits the invoice (billing) and src/fin.rs, on fin-wip;
/// the dev, who reads src/ only, asks for it to land and lands nothing (they
/// see P only in part: it is left for fin); fin lands it, whole. The tip of
/// fin-wip as fin sees it.
fn part_seen_then_landed_whole(hub: &TestHub, p: &Project) -> ObjectId {
    let pid = project_id(hub, &p.name);
    let api = hub.api();
    p.admin.ok(&p.dir, &["group", "add", "devs", &p.fin.name]);
    let invoice = format!("{BILL_DIR}/acme/invoice.txt");
    let mut c = Craft::new(&api, &p.fin, &p.name, "main");
    c.file(&invoice, "fin's edit\n");
    c.file("src/fin.rs", "fin\n");
    let r = c.push_to("fin-wip", None);
    assert_eq!(r.json()["results"][0]["ok"], true, "{}", String::from_utf8_lossy(&r.body));
    let token = p.dev.token();
    let theirs = api.tips(Some(&token), &p.name).unwrap().branches["fin-wip"];
    let r = land_held(&api, &token, &p.name, theirs, true);
    assert_eq!(r.status, 400, "{}", String::from_utf8_lossy(&r.body));
    assert!(real_file(hub, pid, "src/fin.rs").is_none(), "landed in part");
    let mine = api.tips(Some(&p.fin.token()), &p.name).unwrap().branches["fin-wip"];
    let v = land_held(&api, &p.fin.token(), &p.name, mine, true).json();
    assert_eq!(v["state"], "landed", "{v}");
    assert_eq!(real_file(hub, pid, &invoice).as_deref(), Some(&b"fin's edit\n"[..]));
    assert_eq!(real_file(hub, pid, "src/fin.rs").as_deref(), Some(&b"fin\n"[..]));
    mine
}

/// BUG-1312: no change lands in part, so nothing of one is judged by the
/// tip's content later. fin's change, seen only in part by the dev, lands
/// whole when fin lands it, after src/fin.rs... (`part_seen_then_landed_whole`);
/// then src/fin.rs moves on (the dev edits it again): landing fin's change
/// again, by fin or by the dev, lands nothing, and the later edit stays.
#[test]
fn bug_1312_a_change_its_submitter_sees_in_part_lands_whole_once_and_never_again_after_its_paths_moved_on() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let mine = part_seen_then_landed_whole(&hub, &p);
    let token = p.dev.token();
    let v = land(&api, &token, &p.name, tip_for(&hub, &token, &p.name), json!([put("src/fin.rs", "the dev's, later\n")]), true).json();
    assert_eq!(v["state"], "landed", "{v}");
    for t in [p.fin.token(), p.dev.token()] {
        let id = api.tips(Some(&t), &p.name).unwrap().branches["fin-wip"];
        let r = land_held(&api, &t, &p.name, id, true);
        assert_eq!(r.status, 400, "{}", String::from_utf8_lossy(&r.body));
        assert!(String::from_utf8_lossy(&r.body).contains("nothing to land"), "{}", String::from_utf8_lossy(&r.body));
    }
    let _ = mine;
    assert_eq!(real_file(&hub, pid, "src/fin.rs").as_deref(), Some(&b"the dev's, later\n"[..]));
    assert_eq!(real_file(&hub, pid, &format!("{BILL_DIR}/acme/invoice.txt")).as_deref(), Some(&b"fin's edit\n"[..]));
}

/// BUG-1312, the same class: exactly once. fin's change lands whole; then
/// src/fin.rs is deleted on main; landing fin's change again lands nothing
/// (its edits are on the branch: `landings`), never re-creating the file.
#[test]
fn bug_1312_a_change_landed_once_never_lands_an_edit_again_after_it_was_undone() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let mine = part_seen_then_landed_whole(&hub, &p);
    let token = p.dev.token();
    let v = land(&api, &token, &p.name, tip_for(&hub, &token, &p.name), json!([{"path": "src/fin.rs", "delete": true}]), true).json();
    assert_eq!(v["state"], "landed", "{v}");
    assert!(real_file(&hub, pid, "src/fin.rs").is_none());
    let r = land_held(&api, &p.fin.token(), &p.name, mine, true);
    assert_eq!(r.status, 400, "{}", String::from_utf8_lossy(&r.body));
    assert!(String::from_utf8_lossy(&r.body).contains("nothing to land"), "{}", String::from_utf8_lossy(&r.body));
    assert!(real_file(&hub, pid, "src/fin.rs").is_none(), "src/fin.rs, landed once and deleted since, landed a second time");
}

/// BUG-1313: answers are the same whether or not hidden changes sit below
/// the submitter's change. `landing::stack` reads the submitted line at
/// most `LINE_LIMIT` (1,024) snapshots deep, hidden ones included: the dev's
/// one change on a branch of 1,030 billing-only changes (none of them in
/// the dev's history: they see the branch as main) is refused with "more
/// than 64 changes between the branch's tip and this one", while the same
/// change with nothing hidden below lands.
#[test]
fn bug_1313_a_change_on_many_hidden_changes_lands_as_it_would_with_none_below() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let token = p.dev.token();
    // 1,030 billing-only changes on `billing-run` (one file, edited each time).
    let mut c = Craft::new(&api, &p.admin, &p.name, "main");
    let mut parent = c.tip;
    for i in 0..1_030 {
        c.file(&format!("{BILL_DIR}/run.txt"), &format!("{i}\n"));
        let mut s = Snapshot {
            parents: vec![parent],
            change_id: veil_core::ChangeId::random(),
            tree: c.root,
            description: Text::Plain(format!("billing {i}")),
            author: "fin".into(),
            timestamp: veil_core::now_millis(),
            predecessors: vec![],
            conflicts: vec![],
            embargo: None,
            signature: None,
        };
        s.sign(&c.identity);
        parent = c.put(O::Snapshot(s));
    }
    let up = c.api.upload(&c.token, &c.project, &c.objects);
    assert_eq!(up.status, 200, "{}", String::from_utf8_lossy(&up.body));
    let receipts = up.json()["receipts"].as_array().unwrap().clone();
    let map: serde_json::Map<String, Value> = c.objects.iter().zip(receipts).map(|((id, _), r)| (id.hex(), r)).collect();
    let r = c.api.post_json(
        Some(&c.token),
        &format!("/v1/projects/{}/push", p.name),
        &json!({"updates": [{"branch": "billing-run", "expected": null, "new": parent.hex()}], "receipts": map}),
    );
    assert_eq!(r.json()["results"][0]["ok"], true, "{}", String::from_utf8_lossy(&r.body));
    let seen = api.tips(Some(&token), &p.name).unwrap().branches["billing-run"];
    assert_eq!(seen, tip_for(&hub, &token, &p.name), "the dev sees billing-run as main");
    // The dev's one change, pushed on billing-run, then landed on main.
    let mut c = Craft::new(&api, &p.dev, &p.name, "billing-run");
    c.file("src/run.rs", "the dev's\n");
    let r = c.push_to("billing-run", Some(seen));
    assert_eq!(r.json()["results"][0]["ok"], true, "{}", String::from_utf8_lossy(&r.body));
    let mine = api.tips(Some(&token), &p.name).unwrap().branches["billing-run"];
    let r = land_held(&api, &token, &p.name, mine, true);
    let body = String::from_utf8_lossy(&r.body).to_string();
    assert_eq!(r.status, 200, "one change of the dev's, on changes they cannot see: {body}");
    assert_eq!(r.json()["state"], "landed", "{body}");
    assert_eq!(real_file(&hub, pid, "src/run.rs").as_deref(), Some(&b"the dev's\n"[..]));
}

/// BUG-1314 (pre-existing; the builder's unconfirmed YugabyteDB 403 in
/// `a_merge_in_fix_never_lets_a_non_admin_change_the_default_branch_rules`):
/// a projection several hidden-only changes share stands for each of them,
/// and `changes::resolve_base` takes "the newest real snapshot that is
/// `base`" from `sync::resolve`, which orders the candidates by their
/// memo's `created_at` (milliseconds, across every view key): neither the
/// snapshots' order nor unique. For the dev, main's initial import, the
/// access lines, the billing-only change and the admin's "devs may edit
/// the rules file" (a `.veilpolicy` change) all project to one snapshot;
/// with their memos stored in one millisecond (here: made equal), a server
/// that has not cached the answer (another server, after a restart) grafts
/// the dev's change on an older one. Its hidden `.veilpolicy` then differs
/// from main's, and the merge-in fix is refused at the push's check (403,
/// "combines changes in folders you cannot see") instead of being judged.
#[test]
fn bug_1314_a_base_shared_by_hidden_only_changes_resolves_to_the_newest_of_them() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    p.admin.ok(&p.dir, &["access", ".veilrules", "devs"]);
    p.admin.commit_main(&p.dir, "devs may edit the rules file");
    p.admin.ok(&p.dir, &["push"]);
    let token = p.dev.token();
    let base = tip_for(&hub, &token, &p.name);
    let tip = real_tip(&hub, pid);
    // Every memo of that projection stored in one millisecond.
    let h = hub.hub();
    let n = hub
        .rt
        .block_on(sqlx::query("UPDATE projections SET created_at = 1 WHERE project_id = $1 AND projected_id = $2").bind(pid).bind(base.hex()).execute(&h.db))
        .unwrap()
        .rows_affected();
    assert!(n >= 2, "the dev's main stands for {n} real snapshot(s)");
    // Another server (nothing cached) makes the dev's change on it.
    let other = TestHub::beside(&hub);
    let oapi = other.api();
    let mine = kept_change(&oapi, &token, &p.name, base, json!([put("src/lib.rs", "the dev's\n")]));
    let real: String = hub
        .rt
        .block_on(sqlx::query_scalar("SELECT real_id FROM projections WHERE project_id = $1 AND projected_id = $2 LIMIT 1").bind(pid).bind(mine.hex()).fetch_one(&h.db))
        .unwrap();
    let parent = source(&hub, pid).snapshot(&ObjectId::from_hex(&real).unwrap()).unwrap().parents[0];
    // The merge-in fix of a_merge_in_fix_… on it.
    write_files(&p.dir, &[(".veilrules", "[branches.release]\nprotected = true\n"), ("src/lib.rs", "the admin's\n")]);
    p.admin.commit_main(&p.dir, "the rules, and the admin's lib.rs");
    p.admin.ok(&p.dir, &["push"]);
    let main_now = tip_for(&other, &token, &p.name);
    let mut c = Craft::new(&oapi, &p.dev, &p.name, "main");
    c.root = c.tree_of(mine);
    c.tip = mine;
    c.file("src/lib.rs", "both\n");
    let r = land_crafted(c, vec![mine, main_now], true);
    let body = String::from_utf8_lossy(&r.body).to_string();
    assert_eq!(r.status, 200, "the dev's change was made on {} (main was {}): {body}", parent.short(), tip.short());
    assert_eq!(r.json()["state"], "rejected", "{body}");
    assert!(body.contains("only admins may change the branch rules"), "{body}");
    assert_eq!(parent, tip, "the dev's change, made on main as they see it, is on an older snapshot");
}

/// BUG-1315: one change is one revision on the branch for whoever sees it.
/// fin's change (the invoice and src/fin.rs) is never landed in parts (the
/// dev, who sees it only in part, lands nothing of it); fin lands it whole:
/// for fin, `vl log -r <its change id>` names one revision, never a
/// divergent change.
#[test]
fn bug_1315_a_change_one_submitter_sees_in_part_is_one_change_on_the_branch_for_whoever_sees_it() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    part_seen_then_landed_whole(&hub, &p);
    let cid = source(&hub, pid).snapshot(&real_tip(&hub, pid)).unwrap().change_id;
    let d = p.fin.dir(&unique("parts"));
    p.fin.ok(p.fin.home.path(), &["clone", &hub.url(&p.name), d.to_str().unwrap()]);
    let out = p.fin.run(&d, &["log", "-r", &cid.to_string()]);
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success(), "fin's own change, landed on main: {text}");
    assert!(!text.contains("divergent"), "{text}");
}


/// Guarantee (property 4 of the redesign's review): only admins change the
/// branch rules and access lines, whatever lies below a change. The admin's
/// held change on `rules-wip` edits `.veilrules`, `.veilpolicy` and src/; a
/// billing-only change of theirs sits below it. The dev, who may read and
/// edit `.veilrules` but not read `.veilpolicy`, sees the admin's change only
/// in part (the S17 simplified rule: it is left for the admin), and lands
/// their own change on top: theirs lands, and the rules and access lines
/// never move. On `rules-wip-2` the admin's change edits `.veilrules` and
/// src/ only (the dev sees it whole): landing it with theirs is refused for
/// the rules, and nothing of it lands.
#[test]
fn a_change_landed_as_projected_edits_never_lets_a_non_admin_change_the_rules_or_access_lines() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    p.admin.ok(&p.dir, &["access", ".veilrules", "devs"]);
    p.admin.commit_main(&p.dir, "devs may edit the rules file");
    p.admin.ok(&p.dir, &["push"]);
    let tip0 = real_tip(&hub, pid);
    let policy0 = real_file(&hub, pid, ".veilpolicy");
    let mut policy = String::from_utf8(policy0.clone().unwrap()).unwrap();
    policy.push_str("src/open/ devs\n");
    let t0 = veil_core::now_millis();
    let hidden = format!("{BILL_DIR}/below.txt");
    crafted_branch(
        &api,
        &p.admin,
        &p.name,
        "main",
        "rules-wip",
        &[(&[(&hidden, "h\n")], 1), (&[(".veilrules", "[branches.release]\nprotected = true\n"), (".veilpolicy", &policy), ("src/rules.rs", "r\n")], 2)],
        t0,
    );
    let token = p.dev.token();
    let mut c = Craft::new(&api, &p.dev, &p.name, "rules-wip");
    c.file("src/mine.rs", "the dev's\n");
    let seen = c.tip;
    let r = c.push_to("rules-wip", Some(seen));
    assert_eq!(r.json()["results"][0]["ok"], true, "{}", String::from_utf8_lossy(&r.body));
    let mine = api.tips(Some(&token), &p.name).unwrap().branches["rules-wip"];
    let r = land_held(&api, &token, &p.name, mine, true);
    let body = String::from_utf8_lossy(&r.body).to_string();
    assert_eq!(r.status, 200, "{body}");
    assert_eq!(r.json()["state"], "landed", "{body}");
    assert_eq!(real_file(&hub, pid, "src/mine.rs").as_deref(), Some(&b"the dev's\n"[..]));
    assert_eq!(real_file(&hub, pid, ".veilpolicy"), policy0, "the access lines moved");
    assert!(real_file(&hub, pid, ".veilrules").is_none() && real_file(&hub, pid, "src/rules.rs").is_none(), "{body}");
    assert!(real_file(&hub, pid, &hidden).is_none());
    // The rules change the dev sees whole: refused, nothing of it lands.
    let tip1 = real_tip(&hub, pid);
    crafted_branch(
        &api,
        &p.admin,
        &p.name,
        "main",
        "rules-wip-2",
        &[(&[(&hidden, "h2\n")], 3), (&[(".veilrules", "[branches.release]\nprotected = true\n"), ("src/rules2.rs", "r\n")], 4)],
        t0,
    );
    let mut c = Craft::new(&api, &p.dev, &p.name, "rules-wip-2");
    c.file("src/mine2.rs", "the dev's\n");
    let seen = c.tip;
    let r = c.push_to("rules-wip-2", Some(seen));
    assert_eq!(r.json()["results"][0]["ok"], true, "{}", String::from_utf8_lossy(&r.body));
    let mine = api.tips(Some(&token), &p.name).unwrap().branches["rules-wip-2"];
    let r = land_held(&api, &token, &p.name, mine, true);
    let body = String::from_utf8_lossy(&r.body).to_string();
    assert_eq!(r.status, 200, "{body}");
    assert_eq!(r.json()["state"], "rejected", "{body}");
    assert!(body.contains("only admins may change the branch rules"), "{body}");
    assert_eq!(real_tip(&hub, pid), tip1, "{body}");
    assert!(real_file(&hub, pid, ".veilrules").is_none() && real_file(&hub, pid, "src/mine2.rs").is_none());
    let _ = tip0;
}

// ---- S17 redesign review (cycle 2 of the revised design) ----------------

/// BUG-1405: "only a snapshot that is on the branch itself (the tip, one the
/// service landed or moved the branch from, or the branch's ancestry) ends
/// the line". `landing::stack` reads the submitted line down to the tip, the
/// root or a `landings` row only; the branch's ancestry (`Ancestry::has`)
/// is asked only after the line was read, and the line's reading stops at
/// `WALK_BUDGET` with `warming`. A change made on a snapshot of main that
/// `landings` does not know (main moved by plain pushes, or the row is past
/// its hour of retention) reads main's whole history below its base: with
/// 4,200 snapshots there, the dev's landing on main's tip's parent (one
/// step below the tip) is answered `warming`, every time, though the graph
/// (or a walk of two snapshots from the tip) answers at once.
#[test]
fn bug_1405_a_change_on_a_snapshot_of_the_branch_that_landings_does_not_know_lands() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let token = p.dev.token();
    // main: 4,200 snapshots by plain pushes (no `landings` rows), then one more.
    push_chain(&api, &p.admin, &p.name, "main", "main", 4_200, None);
    push_chain(&api, &p.admin, &p.name, "main", "main", 1, Some("src/after"));
    let tip = real_tip(&hub, pid);
    let base = seen_parent(&api, &token, &p.name, tip_for(&hub, &token, &p.name));
    // As many tries as an agent backing off for a minute would make.
    let mut last = None;
    for _ in 0..5 {
        let r = land(&api, &token, &p.name, base, json!([put("src/on-old.rs", "the dev's\n")]), true);
        if r.status != 503 {
            last = Some(r);
            break;
        }
        last = Some(r);
        std::thread::sleep(Duration::from_secs(2));
    }
    let r = last.unwrap();
    let body = String::from_utf8_lossy(&r.body).to_string();
    assert_eq!(r.status, 200, "a change one snapshot below main's tip: {body}");
    assert_eq!(r.json()["state"], "landed", "{body}");
    assert_eq!(real_file(&hub, pid, "src/on-old.rs").as_deref(), Some(&b"the dev's\n"[..]));
    assert_eq!(source(&hub, pid).snapshot(&real_tip(&hub, pid)).unwrap().parents, vec![tip]);
}

/// The dev's view of world `hidden` (a fresh project): the admin's branch
/// `g` holds one change P of `src/g/p.rs`, and (with `hidden`) of a billing
/// file too, which the dev cannot read; the dev lands their own change on
/// top of P (as they see it). The answer (its ticket and the dev's own
/// change id left out), the snapshots it lists, and whether main then
/// shows the dev `src/g/p.rs`.
fn land_on_a_change_seen(hub: &TestHub, hidden: bool) -> (Value, usize, bool) {
    let p = setup_project(hub);
    let pid = project_id(hub, &p.name);
    let api = hub.api();
    let token = p.dev.token();
    let t0 = 1_700_000_000_000;
    let bill = format!("{BILL_DIR}/g.txt");
    let mut files: Vec<(&str, &str)> = vec![("src/g/p.rs", "p\n")];
    if hidden {
        files.push((&bill, "the hidden edit\n"));
    }
    crafted_branch(&api, &p.admin, &p.name, "main", "g", &[(&files, 1)], t0);
    let seen = api.tips(Some(&token), &p.name).unwrap().branches["g"];
    let r = land(&api, &token, &p.name, seen, json!([put("src/g/mine.rs", "the dev's\n")]), true);
    let body = String::from_utf8_lossy(&r.body).to_string();
    assert_eq!(r.status, 200, "{body}");
    for secret in [BILL_DIR, "the hidden edit", "g.txt"] {
        assert!(!body.contains(secret), "the answer names what the dev cannot see ({secret}): {body}");
    }
    let mut v = r.json();
    assert_eq!(v["state"], "landed", "{v}");
    assert_eq!(real_file(hub, pid, "src/g/mine.rs").as_deref(), Some(&b"the dev's\n"[..]));
    assert!(real_file(hub, pid, &bill).is_none(), "a change the dev sees only in part landed");
    let n = v["landed"].as_array().unwrap().len();
    let o = v.as_object_mut().unwrap();
    for k in ["ticket", "change_id", "landed"] {
        o.remove(k);
    }
    (v, n, real_file(hub, pid, "src/g/p.rs").is_some())
}

/// BUG-1406 (decided, `docs/VISIBILITY.md`: that a change you see also
/// touched folders you cannot see is not secret; what and where is): two
/// worlds, the same for the dev, where P edits `src/g/p.rs` and in one of
/// them a billing file too. The dev lands their change on P: with nothing
/// hidden in P, P lands with theirs; with the hidden edit, P is left for
/// someone who sees it whole and only theirs lands. That bit is all the
/// answer tells: the same state and message, no hidden path, name, count or
/// content in either, one snapshot fewer listed.
#[test]
fn bug_1406_an_answer_tells_whether_a_change_below_has_hidden_edits_and_nothing_more() {
    let hub = TestHub::start();
    let (plain, plain_n, plain_p) = land_on_a_change_seen(&hub, false);
    let (part, part_n, part_p) = land_on_a_change_seen(&hub, true);
    assert_eq!(plain, part, "beyond which snapshots landed, the answers differ");
    assert_eq!((plain_n, plain_p), (2, true), "P and the dev's change land");
    assert_eq!((part_n, part_p), (1, false), "P, seen in part, is left for whoever sees it whole");
}

/// BUG-1407: `sync::resolve_newest` keeps the 64 smallest ids of the real
/// snapshots a projected id stands for (`ids.sort_unstable(); …
/// ids.truncate(NEWEST_CANDIDATES)`) before it looks for a branch tip or
/// the newest among them, so once more than 64 hidden-only changes share a
/// projection, main's tip, and the newest of them, are dropped by the
/// order of their hashes. 200 billing-only changes on main (all one
/// snapshot for the dev), the last with a large id: the dev's API commit on
/// main as they see it is grafted on an older one (BUG-1314's harm: its
/// hidden files are an older main's).
#[test]
fn bug_1407_a_base_shared_by_many_hidden_only_changes_resolves_to_the_tip() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let token = p.dev.token();
    let mut c = Craft::new(&api, &p.admin, &p.name, "main");
    let mut parent = c.tip;
    for i in 0..200 {
        c.file(&format!("{BILL_DIR}/many.txt"), &format!("{i}\n"));
        let mut n = 0u32;
        loop {
            let mut s = Snapshot {
                parents: vec![parent],
                change_id: veil_core::ChangeId::random(),
                tree: c.root,
                description: Text::Plain(format!("billing {i} {n}")),
                author: "fin".into(),
                timestamp: veil_core::now_millis(),
                predecessors: vec![],
                conflicts: vec![],
                embargo: None,
                signature: None,
            };
            s.sign(&c.identity);
            let id = ObjectId::hash(&O::Snapshot(s.clone()).encode());
            // The last one (main's tip): an id past every other's, likely.
            if i < 199 || id.hex().starts_with('f') {
                parent = c.put(O::Snapshot(s));
                break;
            }
            n += 1;
        }
    }
    let up = c.api.upload(&c.token, &c.project, &c.objects);
    assert_eq!(up.status, 200, "{}", String::from_utf8_lossy(&up.body));
    let receipts = up.json()["receipts"].as_array().unwrap().clone();
    let map: serde_json::Map<String, Value> = c.objects.iter().zip(receipts).map(|((id, _), r)| (id.hex(), r)).collect();
    let main0 = api.tips(Some(&c.token), &p.name).unwrap().branches["main"];
    let r = c.api.post_json(
        Some(&c.token),
        &format!("/v1/projects/{}/push", p.name),
        &json!({"updates": [{"branch": "main", "expected": main0.hex(), "new": parent.hex()}], "receipts": map}),
    );
    assert_eq!(r.json()["results"][0]["ok"], true, "{}", String::from_utf8_lossy(&r.body));
    let tip = real_tip(&hub, pid);
    assert_eq!(tip, parent);
    let base = tip_for(&hub, &token, &p.name);
    let shared = sql_i64_text(&hub, "SELECT count(DISTINCT real_id) FROM projections WHERE project_id = $1 AND projected_id = $2", pid, &base.hex());
    assert!(shared > 64, "main as the dev sees it stands for {shared} real snapshots");
    let mine = kept_change(&api, &token, &p.name, base, json!([put("src/lib.rs", "the dev's\n")]));
    let h = hub.hub();
    let real: String = hub
        .rt
        .block_on(sqlx::query_scalar("SELECT real_id FROM projections WHERE project_id = $1 AND projected_id = $2 LIMIT 1").bind(pid).bind(mine.hex()).fetch_one(&h.db))
        .unwrap();
    let got = source(&hub, pid).snapshot(&ObjectId::from_hex(&real).unwrap()).unwrap().parents[0];
    assert_eq!(got, tip, "the dev's change, made on main as they see it, is on an older snapshot ({} of {shared})", got.short());
}

fn sql_i64_text(hub: &TestHub, q: &str, project: i64, text: &str) -> i64 {
    let h = hub.hub();
    hub.rt.block_on(sqlx::query_scalar::<_, i64>(q).bind(project).bind(text).fetch_one(&h.db)).unwrap()
}

/// BUG-1408 (pre-existing: S17 cycle 3's one-hour retention, BUG-1303):
/// "every accepted change lands exactly once" holds only while its
/// `landings` row is kept. The dev lands P from their branch and keeps
/// working on it (`vl land` leaves the local history as it was); an hour
/// later (the rows are gone, as `Service::clean` deletes them) they land Q
/// on top of P: the stack holds P again, which lands again as its edits on
/// its first parent, and is answered `conflict` on P's own path (main holds
/// P's file since P landed), so Q never lands; had P's path been undone
/// meanwhile, P would land a second time.
#[test]
fn bug_1408_a_change_landed_an_hour_ago_is_not_landed_again_under_a_later_one() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let token = p.dev.token();
    let first = push_chain(&api, &p.dev, &p.name, "dev-work", "main", 1, Some("src/once"));
    let v = land_held(&api, &token, &p.name, first, true).json();
    assert_eq!(v["state"], "landed", "{v}");
    let second = push_chain(&api, &p.dev, &p.name, "dev-work", "dev-work", 1, Some("src/twice"));
    // An hour later: retention has deleted the rows (`Service::clean`).
    let h = hub.hub();
    hub.rt.block_on(sqlx::query("DELETE FROM landings WHERE project_id = $1").bind(pid).execute(&h.db)).unwrap();
    let r = land_held(&api, &token, &p.name, second, true);
    let body = String::from_utf8_lossy(&r.body).to_string();
    assert_eq!(r.status, 200, "{body}");
    assert_eq!(r.json()["state"], "landed", "the dev's change on their own change landed an hour ago: {body}");
    assert_eq!(r.json()["landed"].as_array().unwrap().len(), 1, "{body}");
    assert_eq!(real_file(&hub, pid, "src/twice/0.rs").as_deref(), Some(&b"0\n"[..]));
}

/// Guarantee (properties 1 and 3 of the cycle-2 review): a change the dev
/// sees only in part lands by no route of theirs (`vl land` of it, edits on
/// it, a push to protected main on it, an API commit `onto` main on it),
/// and never blocks their own changes on top from landing as their own
/// edits; fin, who sees it whole, lands it afterwards on top of what landed
/// meanwhile, once.
#[test]
fn a_change_seen_in_part_lands_by_no_route_of_its_viewer_and_its_author_lands_it_later() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let token = p.dev.token();
    write_files(&p.dir, &[(".veilrules", "[branches.main]\nprotected = true\n")]);
    p.admin.commit_main(&p.dir, "protect main");
    p.admin.ok(&p.dir, &["push"]);
    p.admin.ok(&p.dir, &["group", "add", "devs", &p.fin.name]);
    let invoice = format!("{BILL_DIR}/acme/invoice.txt");
    let mut c = Craft::new(&api, &p.fin, &p.name, "main");
    c.file(&invoice, "fin's edit\n");
    c.file("src/fin.rs", "fin\n");
    let r = c.push_to("fin-wip", None);
    assert_eq!(r.json()["results"][0]["ok"], true, "{}", String::from_utf8_lossy(&r.body));
    let theirs = api.tips(Some(&token), &p.name).unwrap().branches["fin-wip"];
    let untouched = |what: &str| {
        assert!(real_file(&hub, pid, "src/fin.rs").is_none(), "{what}: fin's change landed in part or whole");
        assert_eq!(real_file(&hub, pid, &invoice).as_deref(), Some(&format!("{BILL_MARK}\nsecond").into_bytes()[..]), "{what}");
    };
    // 1. `vl land` of it.
    let r = land_held(&api, &token, &p.name, theirs, true);
    assert_eq!(r.status, 400, "{}", String::from_utf8_lossy(&r.body));
    assert!(!String::from_utf8_lossy(&r.body).contains(BILL_DIR));
    untouched("vl land");
    // 2. Edits on it: the dev's own edit lands, alone.
    let v = land(&api, &token, &p.name, theirs, json!([put("src/one.rs", "1\n")]), true).json();
    assert_eq!(v["state"], "landed", "{v}");
    assert_eq!(v["landed"].as_array().unwrap().len(), 1, "{v}");
    assert_eq!(real_file(&hub, pid, "src/one.rs").as_deref(), Some(&b"1\n"[..]));
    untouched("edits on it");
    // 3. A push to protected main of a change on it.
    let mut c = Craft::new(&api, &p.dev, &p.name, "fin-wip");
    c.file("src/two.rs", "2\n");
    let r = c.push_to("main", Some(theirs));
    let body = String::from_utf8_lossy(&r.body).to_string();
    assert_eq!(r.status, 200, "{body}");
    assert_eq!(r.json()["results"][0]["ok"], true, "{body}");
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while real_file(&hub, pid, "src/two.rs").is_none() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(real_file(&hub, pid, "src/two.rs").as_deref(), Some(&b"2\n"[..]), "{body}");
    untouched("a push on it");
    // 4. An API commit onto main on it: refused (only the landing service
    // moves protected main), and nothing of it lands.
    let tip_seen = tip_for(&hub, &token, &p.name);
    let r = api.post_json(
        Some(&token),
        &format!("/v1/projects/{}/changes", p.name),
        &json!({"base": theirs.hex(), "edits": [put("src/three.rs", "3\n")], "onto": {"branch": "main", "expected": tip_seen.hex()}}),
    );
    let body = String::from_utf8_lossy(&r.body).to_string();
    assert_eq!(r.status, 200, "{body}");
    assert_eq!(r.json()["branch"]["status"], "rejected", "{body}");
    assert!(real_file(&hub, pid, "src/three.rs").is_none(), "{body}");
    untouched("an API commit onto main");
    // fin lands it, whole, on top of what landed meanwhile.
    let tip_before = real_tip(&hub, pid);
    let mine = api.tips(Some(&p.fin.token()), &p.name).unwrap().branches["fin-wip"];
    let v = land_held(&api, &p.fin.token(), &p.name, mine, true).json();
    assert_eq!(v["state"], "landed", "{v}");
    assert_eq!(v["landed"].as_array().unwrap().len(), 1, "{v}");
    assert_eq!(real_file(&hub, pid, &invoice).as_deref(), Some(&b"fin's edit\n"[..]));
    assert_eq!(real_file(&hub, pid, "src/fin.rs").as_deref(), Some(&b"fin\n"[..]));
    assert_eq!(real_file(&hub, pid, "src/one.rs").as_deref(), Some(&b"1\n"[..]));
    assert_eq!(real_file(&hub, pid, "src/two.rs").as_deref(), Some(&b"2\n"[..]));
    let src = source(&hub, pid);
    let s = src.snapshot(&real_tip(&hub, pid)).unwrap();
    assert_eq!(s.parents, vec![tip_before]);
    let set = veil_server::landing::edits::edit_set(&src, s.tree, src.snapshot(&tip_before).unwrap().tree).unwrap();
    assert_eq!(set.iter().map(|c| c.path.clone()).collect::<Vec<_>>(), vec![invoice.clone(), "src/fin.rs".to_string()]);
    // Once: landing it again lands nothing.
    let r = land_held(&api, &p.fin.token(), &p.name, mine, true);
    assert_eq!(r.status, 400, "{}", String::from_utf8_lossy(&r.body));
}

/// BUG-1409 (BUG-1313's class, moved): the line's reading budget counts
/// changes the submitter cannot see. The dev's one change on a branch of
/// 4,100 billing-only changes (none in their history: they see the branch
/// as main) is answered `warming` ("try again in a few seconds") on every
/// try, while the same change with nothing hidden below lands at once, and
/// with 1,030 below it lands (`bug_1313_…`): the answer tells the dev that
/// more than 4,096 changes they cannot see are there, and they can never
/// land on that history.
#[test]
fn bug_1409_a_change_on_more_hidden_changes_than_the_walk_budget_lands_as_it_would_with_none_below() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let token = p.dev.token();
    // 4,100 billing-only changes on `billing-run` (one file, edited each time).
    let mut c = Craft::new(&api, &p.admin, &p.name, "main");
    let mut parent = c.tip;
    for i in 0..4_100 {
        c.file(&format!("{BILL_DIR}/run.txt"), &format!("{i}\n"));
        let mut s = Snapshot {
            parents: vec![parent],
            change_id: veil_core::ChangeId::random(),
            tree: c.root,
            description: Text::Plain(format!("billing {i}")),
            author: "fin".into(),
            timestamp: veil_core::now_millis(),
            predecessors: vec![],
            conflicts: vec![],
            embargo: None,
            signature: None,
        };
        s.sign(&c.identity);
        parent = c.put(O::Snapshot(s));
    }
    let up = c.api.upload(&c.token, &c.project, &c.objects);
    assert_eq!(up.status, 200, "{}", String::from_utf8_lossy(&up.body));
    let receipts = up.json()["receipts"].as_array().unwrap().clone();
    let map: serde_json::Map<String, Value> = c.objects.iter().zip(receipts).map(|((id, _), r)| (id.hex(), r)).collect();
    let r = c.api.post_json(
        Some(&c.token),
        &format!("/v1/projects/{}/push", p.name),
        &json!({"updates": [{"branch": "billing-run", "expected": null, "new": parent.hex()}], "receipts": map}),
    );
    assert_eq!(r.json()["results"][0]["ok"], true, "{}", String::from_utf8_lossy(&r.body));
    let seen = api.tips(Some(&token), &p.name).unwrap().branches["billing-run"];
    assert_eq!(seen, tip_for(&hub, &token, &p.name), "the dev sees billing-run as main");
    let mut c = Craft::new(&api, &p.dev, &p.name, "billing-run");
    c.file("src/run.rs", "the dev's\n");
    let r = c.push_to("billing-run", Some(seen));
    assert_eq!(r.json()["results"][0]["ok"], true, "{}", String::from_utf8_lossy(&r.body));
    let mine = api.tips(Some(&token), &p.name).unwrap().branches["billing-run"];
    let mut r = land_held(&api, &token, &p.name, mine, true);
    for _ in 0..4 {
        if r.status != 503 {
            break;
        }
        std::thread::sleep(Duration::from_secs(2));
        r = land_held(&api, &token, &p.name, mine, true);
    }
    let body = String::from_utf8_lossy(&r.body).to_string();
    assert_eq!(r.status, 200, "one change of the dev's, on 4,100 changes they cannot see: {body}");
    assert_eq!(r.json()["state"], "landed", "{body}");
    assert_eq!(real_file(&hub, pid, "src/run.rs").as_deref(), Some(&b"the dev's\n"[..]));
}

// ---- S17 redesign review, cycle 3 (BUG-1465..1468) ----------------------------

/// Hold the deriver of project `pid` (as another server's, or one behind a
/// burst of landings, does): the derived graph learns nothing new until
/// the connection returned is dropped.
fn hold_deriver(hub: &TestHub, pid: i64) -> sqlx::PgConnection {
    hub.rt.block_on(async {
        use sqlx::Connection;
        let url = std::env::var("VEIL_TEST_DATABASE_URL").unwrap();
        let mut c = sqlx::PgConnection::connect(&url).await.unwrap();
        let key: i64 = 0x7665_696c_6472_0000_i64 ^ pid;
        sqlx::query("SELECT pg_advisory_lock($1)").bind(key).execute(&mut c).await.unwrap();
        c
    })
}

/// Wait until the derived graph holds real snapshot `id`.
fn wait_derived(hub: &TestHub, pid: i64, id: ObjectId) {
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    while sql_i64_text(hub, "SELECT count(*) FROM graph WHERE project_id = $1 AND snapshot = $2", pid, &id.hex()) == 0 {
        assert!(std::time::Instant::now() < deadline, "the deriver never reached {}", id.short());
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// One snapshot crafted on `parent` with `c`'s tree as it stands and change
/// id `cid`, signed by `c`'s device; its description varied until its id
/// starts with `prefix`.
fn crafted_on(c: &mut Craft<'_>, parent: ObjectId, cid: veil_core::ChangeId, what: &str, prefix: &str) -> ObjectId {
    for n in 0u64.. {
        let mut s = Snapshot {
            parents: vec![parent],
            change_id: cid,
            tree: c.root,
            description: Text::Plain(format!("{what} {n}")),
            author: "crafter".into(),
            timestamp: veil_core::now_millis(),
            predecessors: vec![],
            conflicts: vec![],
            embargo: None,
            signature: None,
        };
        s.sign(&c.identity);
        if ObjectId::hash(&O::Snapshot(s.clone()).encode()).hex().starts_with(prefix) {
            return c.put(O::Snapshot(s));
        }
    }
    unreachable!()
}

/// Upload what `c` made, and push `updates` (new branches: name, snapshot).
fn push_new_branches(c: &Craft<'_>, updates: &[(String, ObjectId)]) {
    let up = c.api.upload(&c.token, &c.project, &c.objects);
    assert_eq!(up.status, 200, "{}", String::from_utf8_lossy(&up.body));
    let receipts = up.json()["receipts"].as_array().unwrap().clone();
    let map: serde_json::Map<String, Value> = c.objects.iter().zip(receipts).map(|((id, _), r)| (id.hex(), r)).collect();
    let updates: Vec<Value> = updates.iter().map(|(b, id)| json!({"branch": b, "expected": null, "new": id.hex()})).collect();
    let r = c.api.post_json(Some(&c.token), &format!("/v1/projects/{}/push", c.project), &json!({"updates": updates, "receipts": map}));
    let body = String::from_utf8_lossy(&r.body).to_string();
    assert_eq!(r.status, 200, "{body}");
    for res in r.json()["results"].as_array().unwrap() {
        assert_eq!(res["ok"], true, "{body}");
    }
}

/// BUG-1465: `Ancestry::landed` takes "not decided" for "not landed". A
/// revision of the change on the branch counts only when `near` answers
/// `Some(true)`; while the derived graph does not hold the tip (the deriver
/// a moment behind a busy branch, or another server's) `near` walks at most
/// 256 snapshots and answers `None` for one further down, so a change
/// landed long ago (its `landings` row gone, its landing more than 256
/// snapshots below the tip) is in the stack again: it lands as its edits a
/// second time, or (here: main holds its file) is answered `conflict`, and
/// the dev's change on top never lands.
#[test]
fn bug_1465_a_change_landed_long_ago_is_not_landed_again_while_the_deriver_is_behind() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let token = p.dev.token();
    let first = push_chain(&api, &p.dev, &p.name, "dev-work", "main", 1, Some("src/once"));
    let v = land_held(&api, &token, &p.name, first, true).json();
    assert_eq!(v["state"], "landed", "{v}");
    // Its landing, derived long since (an hour later).
    wait_derived(&hub, pid, real_tip(&hub, pid));
    // The deriver a moment behind the tip, after an hour of other work on
    // main (300 snapshots), and the `landings` rows gone.
    let lock = hold_deriver(&hub, pid);
    push_chain(&api, &p.admin, &p.name, "main", "main", 300, None);
    let second = push_chain(&api, &p.dev, &p.name, "dev-work", "dev-work", 1, Some("src/twice"));
    let h = hub.hub();
    hub.rt.block_on(sqlx::query("DELETE FROM landings WHERE project_id = $1").bind(pid).execute(&h.db)).unwrap();
    let r = land_held(&api, &token, &p.name, second, true);
    drop(lock);
    let body = String::from_utf8_lossy(&r.body).to_string();
    assert_eq!(r.status, 200, "{body}");
    assert_eq!(r.json()["state"], "landed", "the dev's change on their own change landed an hour ago: {body}");
    assert_eq!(r.json()["landed"].as_array().unwrap().len(), 1, "{body}");
    assert_eq!(real_file(&hub, pid, "src/twice/0.rs").as_deref(), Some(&b"0\n"[..]));
}

/// BUG-1466: `Ancestry::landed` reads at most 16 revisions of a change, the
/// smallest snapshot ids first (`ORDER BY snapshot LIMIT 16`), and only
/// then asks which one was made from it: a change with more than 16 other
/// revisions on the server (an agent amending and pushing its work) whose
/// landing's id is not among the 16 smallest is taken for not landed once
/// its `landings` row is gone, and is in the stack again. Here 16 earlier
/// revisions (each on a branch, ids starting `000`), the one landed, and,
/// after the rows' hour, a change on top of it.
#[test]
fn bug_1466_a_change_with_many_revisions_landed_long_ago_is_not_landed_again() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let token = p.admin.token();
    let mut c = Craft::new(&api, &p.admin, &p.name, "main");
    let base = c.tip;
    let cid = veil_core::ChangeId::random();
    c.file("src/once/0.rs", "0\n");
    let mut updates: Vec<(String, ObjectId)> = (0..16).map(|i| (format!("rev-{i}"), crafted_on(&mut c, base, cid, &format!("revision {i}"), "000"))).collect();
    let landed_one = crafted_on(&mut c, base, cid, "the revision landed", "");
    updates.push(("work".to_string(), landed_one));
    push_new_branches(&c, &updates);
    let v = land_held(&api, &token, &p.name, landed_one, true).json();
    assert_eq!(v["state"], "landed", "{v}");
    let landing = real_tip(&hub, pid);
    assert!(!landing.hex().starts_with("000"), "the landing's id is among the revisions' (one chance in 4,096): run again");
    wait_derived(&hub, pid, landing);
    for (_, id) in &updates {
        wait_derived(&hub, pid, *id);
    }
    // An hour later: the rows are gone; a change on top of the one landed.
    let h = hub.hub();
    hub.rt.block_on(sqlx::query("DELETE FROM landings WHERE project_id = $1").bind(pid).execute(&h.db)).unwrap();
    let second = push_chain(&api, &p.admin, &p.name, "work", "work", 1, Some("src/twice"));
    let r = land_held(&api, &token, &p.name, second, true);
    let body = String::from_utf8_lossy(&r.body).to_string();
    assert_eq!(r.status, 200, "{body}");
    assert_eq!(r.json()["state"], "landed", "a change on one landed an hour ago, with 16 other revisions: {body}");
    assert_eq!(r.json()["landed"].as_array().unwrap().len(), 1, "{body}");
    assert_eq!(real_file(&hub, pid, "src/twice/0.rs").as_deref(), Some(&b"0\n"[..]));
}

/// BUG-1467: `sync::resolve_newest` still truncates by id before it orders,
/// for the real snapshots the derived graph does not hold yet (`ORDER BY
/// p.real_id LIMIT 64`): with the deriver behind a run of more than 64
/// billing-only changes (all one snapshot for the dev, none a branch tip),
/// the dev's API commit on that snapshot is grafted on whichever of the 64
/// smallest ids descends from the others, not on the newest of the run
/// (BUG-1314's harm: its hidden files are an older state's). The answer
/// depends on how far the deriver is, so two servers, or one a second
/// later, answer differently.
#[test]
fn bug_1467_a_base_shared_by_many_underived_hidden_only_changes_resolves_to_the_newest() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let token = p.dev.token();
    let lock = hold_deriver(&hub, pid);
    let mut c = Craft::new(&api, &p.admin, &p.name, "main");
    c.file("src/v.rs", "v\n");
    let main_tip = c.tip;
    let mut parent = crafted_on(&mut c, main_tip, veil_core::ChangeId::random(), "v", "");
    let mut run = Vec::new();
    for i in 0..200 {
        c.file(&format!("{BILL_DIR}/run.txt"), &format!("{i}\n"));
        // The newest of the run: an id past every other's, likely.
        parent = crafted_on(&mut c, parent, veil_core::ChangeId::random(), &format!("billing {i}"), if i == 199 { "f" } else { "" });
        run.push(parent);
    }
    c.file("src/v2.rs", "v2\n");
    let v2 = crafted_on(&mut c, parent, veil_core::ChangeId::random(), "v2", "");
    push_new_branches(&c, &[("w".to_string(), v2)]);
    let newest = *run.last().unwrap();
    let seen = api.tips(Some(&token), &p.name).unwrap().branches["w"];
    let base = seen_parent(&api, &token, &p.name, seen);
    let shared = sql_i64_text(&hub, "SELECT count(DISTINCT real_id) FROM projections WHERE project_id = $1 AND projected_id = $2", pid, &base.hex());
    assert!(shared > 64, "the dev's snapshot below w's tip stands for {shared} real snapshots");
    let mine = kept_change(&api, &token, &p.name, base, json!([put("src/lib.rs", "the dev's\n")]));
    drop(lock);
    let h = hub.hub();
    let real: String = hub
        .rt
        .block_on(sqlx::query_scalar("SELECT real_id FROM projections WHERE project_id = $1 AND projected_id = $2 LIMIT 1").bind(pid).bind(mine.hex()).fetch_one(&h.db))
        .unwrap();
    let got = source(&hub, pid).snapshot(&ObjectId::from_hex(&real).unwrap()).unwrap().parents[0];
    let at = run.iter().position(|r| *r == got).map_or("none of the run".to_string(), |i| format!("billing {i}"));
    assert_eq!(got, newest, "the dev's change, made on what they see below w's tip, is on {at} of 200");
}

/// BUG-1468: the "one indexed statement" that steps over a hidden run
/// (`Ancestry::below_hidden`: the lowest real snapshot with the run's
/// projection by the derived graph) reads every real snapshot with that
/// projection, and looks each up in `graph`, to find the lowest: its cost
/// grows with the run (and `sync::resolve_newest`'s three statements read
/// the same range, of every view). A viewer who sees only a quiet folder
/// sees a day of other folders' landings as one snapshot: here a run of
/// 1,500,000 (their `projections` and `graph` rows, written directly), and
/// the dev's one change on it, which lands in milliseconds with a run of
/// 50 (`bug_1409_…`'s shape).
#[test]
fn bug_1468_stepping_over_a_hidden_run_costs_the_same_however_long_the_run() {
    // A database of its own: the rows read are counted per database, and
    // other tests' statements (whose plans change on a table this size)
    // are none of this submit's.
    let admin_url = std::env::var("VEIL_TEST_DATABASE_URL").unwrap();
    let db_name = format!("{}{}", std::env::var("VEIL_TEST_DB_PREFIX").unwrap_or_default(), unique("veil_run_"));
    let sql = |url: &str, q: String| {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let db = veil_server::db::connect(url, 1).await.unwrap();
            sqlx::raw_sql(&q).execute(&db).await.unwrap();
            db.close().await;
        });
    };
    sql(&admin_url, format!("CREATE DATABASE {db_name}"));
    let url = format!("{}/{db_name}", admin_url.rsplit_once('/').unwrap().0);
    let hub = TestHub::start_on(&url, Duration::from_secs(3600));
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let token = p.dev.token();
    let mut c = Craft::new(&api, &p.admin, &p.name, "main");
    let mut parent = c.tip;
    for i in 0..50 {
        c.file(&format!("{BILL_DIR}/run.txt"), &format!("{i}\n"));
        parent = crafted_on(&mut c, parent, veil_core::ChangeId::random(), &format!("billing {i}"), "");
    }
    push_new_branches(&c, &[("billing-run".to_string(), parent)]);
    let seen = api.tips(Some(&token), &p.name).unwrap().branches["billing-run"];
    assert_eq!(seen, tip_for(&hub, &token, &p.name), "the dev sees billing-run as main");
    wait_derived(&hub, pid, parent);
    // The rest of the run, as the services and the deriver store it.
    let key = sql_text(&hub, &format!("SELECT view_key FROM projections WHERE project_id = $1 AND real_id = '{}'", parent.hex()), pid);
    let h = hub.hub();
    hub.rt.block_on(async {
        let mut tx = h.db.begin().await.unwrap();
        sqlx::query("SET LOCAL statement_timeout = 0").execute(&mut *tx).await.unwrap();
        sqlx::query(
            "INSERT INTO projections (project_id, view_key, real_id, projected_id, created_at) \
             SELECT $1, $2, md5('r' || i) || md5('s' || i), $3, 0 FROM generate_series(1, 1500000) i",
        )
        .bind(pid)
        .bind(&key)
        .bind(seen.hex())
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO graph (project_id, snapshot, generation, depth, parents, change_id, flags, skip, changed) \
             SELECT $1, md5('r' || i) || md5('s' || i), 9000000000000000 + i, 100000 + i, '[]', md5('c' || i), 0, '[]', 'none' \
             FROM generate_series(1, 1500000) i",
        )
        .bind(pid)
        .execute(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
        sqlx::query("ANALYZE projections").execute(&h.db).await.unwrap();
        sqlx::query("ANALYZE graph").execute(&h.db).await.unwrap();
    });
    let mut c = Craft::new(&api, &p.dev, &p.name, "billing-run");
    c.file("src/run.rs", "the dev's\n");
    let r = c.push_to("billing-run", Some(seen));
    assert_eq!(r.json()["results"][0]["ok"], true, "{}", String::from_utf8_lossy(&r.body));
    let mine = api.tips(Some(&token), &p.name).unwrap().branches["billing-run"];
    // Rows read from `graph` and `projections` (the database's statistics,
    // flushed within about 10 s of a connection's last statement).
    let read = || -> i64 {
        std::thread::sleep(Duration::from_secs(12));
        hub.rt
            .block_on(
                sqlx::query_scalar::<_, i64>(
                    "SELECT (sum(coalesce(seq_tup_read, 0)) + sum(coalesce(idx_tup_fetch, 0)))::BIGINT FROM pg_stat_user_tables \
                     WHERE relname IN ('graph', 'projections')",
                )
                .fetch_one(&h.db),
            )
            .unwrap()
    };
    let before = read();
    let r = land_held(&api, &token, &p.name, mine, false);
    let body = String::from_utf8_lossy(&r.body).to_string();
    assert_eq!(r.status, 200, "{body}");
    assert_eq!(r.json()["state"], "queued", "{body}");
    let rows = read() - before;
    // (The rows go with the database.)
    drop(hub);
    sql(&admin_url, format!("DROP DATABASE IF EXISTS {db_name} WITH (FORCE)"));
    assert!(rows < 100_000, "the submit of one change on a hidden run of 1,500,050 read {rows} rows of graph and projections");
}

/// BUG-1467, another view's candidates first (why `changes::resolve_base`
/// needed its fallback): `sync::resolve_newest` reads the candidates of
/// every view and puts a branch tip first even when its row is another
/// view's, and a push grafts on the first it is given (`real_of`, no check
/// that it projects to the parent the pusher named). Here a folder only
/// the devs see (`zz-docs/`): anyone on Earth sees w2's tip D (an edit of
/// it on H) as the same snapshot as H, the dev does not. The dev's push of
/// a change on H as they see it is grafted on D, a snapshot they never saw,
/// and their change deletes D's `zz-docs/d.txt`.
#[test]
fn bug_1467_a_push_on_a_shared_projection_is_grafted_on_what_its_pusher_saw() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    p.admin.ok(&p.dir, &["access", "zz-docs/", "devs"]);
    p.admin.commit_main(&p.dir, "the devs see zz-docs");
    p.admin.ok(&p.dir, &["push"]);
    let token = p.dev.token();
    let mut c = Craft::new(&api, &p.admin, &p.name, "main");
    let main_tip = c.tip;
    c.file("src/h.rs", "h\n");
    let h = crafted_on(&mut c, main_tip, veil_core::ChangeId::random(), "h", "");
    let h_tree = c.root;
    c.file("src/t.rs", "t\n");
    let t = crafted_on(&mut c, h, veil_core::ChangeId::random(), "t", "");
    let mut c2 = Craft::new(&api, &p.admin, &p.name, "main");
    c2.objects = c.objects.clone();
    c2.root = h_tree;
    c2.file("zz-docs/d.txt", "d\n");
    let d = crafted_on(&mut c2, h, veil_core::ChangeId::random(), "d", "");
    push_new_branches(&c2, &[("w".to_string(), t), ("w2".to_string(), d)]);
    // Anyone on Earth, then the dev, read the branches.
    api.tips(None, &p.name).unwrap();
    let seen = api.tips(Some(&token), &p.name).unwrap().branches["w"];
    let base = seen_parent(&api, &token, &p.name, seen);
    let views = sql_i64_text(&hub, "SELECT count(DISTINCT view_key) FROM projections WHERE project_id = $1 AND projected_id = $2", pid, &base.hex());
    assert!(views >= 2, "H looks the same to anyone on Earth and to the dev ({views} view)");
    let mut m = Craft::new(&api, &p.dev, &p.name, "main");
    m.tip = base;
    m.root = m.tree_of(base);
    m.file("src/mine.rs", "the dev's\n");
    let mine = crafted_on(&mut m, base, veil_core::ChangeId::random(), "mine", "");
    push_new_branches(&m, &[("mine".to_string(), mine)]);
    let real = ObjectId::from_hex(&sql_text(&hub, "SELECT target FROM branches WHERE project_id = $1 AND name = 'mine'", pid)).unwrap();
    let got = source(&hub, pid).snapshot(&real).unwrap().parents[0];
    let named = if got == d { "w2's tip D".to_string() } else { got.short() };
    let src = source(&hub, pid);
    let docs = |id: ObjectId| {
        let O::Tree(root) = O::decode(&src.raw(&src.snapshot(&id).unwrap().tree).unwrap()).unwrap() else { panic!("not a tree") };
        root.get("zz-docs").is_some()
    };
    assert_eq!(got, h, "the dev's change on H as they see it is grafted on {named} (zz-docs/d.txt there: {}; in the dev's change: {})", docs(got), docs(real));
}

// ---- S17 redesign, cycle 3: guarantees ---------------------------------------------------

/// Guarantee: a change landed by any route, at any depth below the tip, is
/// never landed again, whatever the deriver and whatever rows expired. The
/// dev's change P lands by the landing service, by a plain push of it, and
/// by an API commit `onto` main; then, with the deriver held, 300 more
/// snapshots go on main and the `landings` rows go; a change of theirs on P
/// lands alone (one snapshot), P's file once.
#[test]
fn a_change_landed_by_any_route_at_any_depth_is_never_landed_again() {
    for route in ["landing", "push", "api"] {
        let hub = TestHub::start();
        let p = setup_project(&hub);
        let pid = project_id(&hub, &p.name);
        let api = hub.api();
        let token = p.dev.token();
        let first = match route {
            "landing" => {
                let first = push_chain(&api, &p.dev, &p.name, "dev-work", "main", 1, Some("src/once"));
                let v = land_held(&api, &token, &p.name, first, true).json();
                assert_eq!(v["state"], "landed", "{route}: {v}");
                first
            }
            "push" => {
                let first = push_chain(&api, &p.dev, &p.name, "main", "main", 1, Some("src/once"));
                move_branch(&api, &token, &p.name, "dev-work", None, Some(first), false);
                first
            }
            _ => {
                let base = tip_for(&hub, &token, &p.name);
                let r = api.post_json(
                    Some(&token),
                    &format!("/v1/projects/{}/changes", p.name),
                    &json!({"base": base.hex(), "edits": [put("src/once/0.rs", "0\n")], "description": "once", "onto": {"branch": "main", "expected": base.hex()}}),
                );
                assert_eq!(r.status, 200, "{route}: {}", String::from_utf8_lossy(&r.body));
                assert_eq!(r.json()["branch"]["status"], "ok", "{route}: {}", String::from_utf8_lossy(&r.body));
                let first: ObjectId = serde_json::from_value(r.json()["snapshot"].clone()).unwrap();
                move_branch(&api, &token, &p.name, "dev-work", None, Some(first), false);
                first
            }
        };
        let _ = first;
        wait_derived(&hub, pid, real_tip(&hub, pid));
        let lock = hold_deriver(&hub, pid);
        push_chain(&api, &p.admin, &p.name, "main", "main", 300, None);
        let second = push_chain(&api, &p.dev, &p.name, "dev-work", "dev-work", 1, Some("src/twice"));
        let h = hub.hub();
        hub.rt.block_on(sqlx::query("DELETE FROM landings WHERE project_id = $1").bind(pid).execute(&h.db)).unwrap();
        let r = land_held(&api, &token, &p.name, second, true);
        drop(lock);
        let body = String::from_utf8_lossy(&r.body).to_string();
        assert_eq!(r.status, 200, "{route}: {body}");
        assert_eq!(r.json()["state"], "landed", "{route}: {body}");
        assert_eq!(r.json()["landed"].as_array().unwrap().len(), 1, "{route}: P landed again: {body}");
        assert_eq!(real_file(&hub, pid, "src/twice/0.rs").as_deref(), Some(&b"0\n"[..]), "{route}");
        assert_eq!(real_file(&hub, pid, "src/once/0.rs").as_deref(), Some(&b"0\n"[..]), "{route}");
    }
}

/// Guarantee: an API commit is grafted only on what its author saw (the
/// push: `bug_1467_a_push_on_a_shared_projection_is_grafted_on_what_its_pusher_saw`).
/// Anyone on Earth sees w2's tip D (an edit of `zz-docs/`, which only the
/// devs see) as the same snapshot as H; the dev's API commit on H as they
/// see it is made on H, never on D.
#[test]
fn an_api_commit_on_a_shared_projection_is_made_on_what_its_author_saw() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    p.admin.ok(&p.dir, &["access", "zz-docs/", "devs"]);
    p.admin.commit_main(&p.dir, "the devs see zz-docs");
    p.admin.ok(&p.dir, &["push"]);
    let token = p.dev.token();
    let mut c = Craft::new(&api, &p.admin, &p.name, "main");
    let main_tip = c.tip;
    c.file("src/h.rs", "h\n");
    let h = crafted_on(&mut c, main_tip, veil_core::ChangeId::random(), "h", "");
    let h_tree = c.root;
    c.file("src/t.rs", "t\n");
    let t = crafted_on(&mut c, h, veil_core::ChangeId::random(), "t", "");
    let mut c2 = Craft::new(&api, &p.admin, &p.name, "main");
    c2.objects = c.objects.clone();
    c2.root = h_tree;
    c2.file("zz-docs/d.txt", "d\n");
    let d = crafted_on(&mut c2, h, veil_core::ChangeId::random(), "d", "");
    push_new_branches(&c2, &[("w".to_string(), t), ("w2".to_string(), d)]);
    api.tips(None, &p.name).unwrap();
    let seen = api.tips(Some(&token), &p.name).unwrap().branches["w"];
    let base = seen_parent(&api, &token, &p.name, seen);
    let mine = kept_change(&api, &token, &p.name, base, json!([put("src/mine.rs", "the dev's\n")]));
    let h2 = hub.hub();
    let real: String = hub
        .rt
        .block_on(sqlx::query_scalar("SELECT real_id FROM projections WHERE project_id = $1 AND projected_id = $2 LIMIT 1").bind(pid).bind(mine.hex()).fetch_one(&h2.db))
        .unwrap();
    let got = source(&hub, pid).snapshot(&ObjectId::from_hex(&real).unwrap()).unwrap().parents[0];
    assert_eq!(got, h, "the dev's API commit on H as they see it is made on {}", if got == d { "w2's tip D".to_string() } else { got.short() });
}

// ---- S17 redesign review, cycle 4 (BUG-1520..) --------------------------------

/// Upload what `c` made and push `updates` (new branches); the push's reply,
/// unchecked.
fn push_new(c: &Craft<'_>, updates: &[(&str, ObjectId)]) -> Reply {
    let up = c.api.upload(&c.token, &c.project, &c.objects);
    assert_eq!(up.status, 200, "{}", String::from_utf8_lossy(&up.body));
    let receipts = up.json()["receipts"].as_array().unwrap().clone();
    let map: serde_json::Map<String, Value> = c.objects.iter().zip(receipts).map(|((id, _), r)| (id.hex(), r)).collect();
    let updates: Vec<Value> = updates.iter().map(|(b, id)| json!({"branch": b, "expected": null, "new": id.hex()})).collect();
    c.api.post_json(Some(&c.token), &format!("/v1/projects/{}/push", c.project), &json!({"updates": updates, "receipts": map}))
}

/// The real snapshot `token`'s owner sees as `seen` (their only one).
fn real_of_seen(hub: &TestHub, pid: i64, seen: ObjectId) -> ObjectId {
    let h = hub.hub();
    let real: String = hub
        .rt
        .block_on(sqlx::query_scalar("SELECT real_id FROM projections WHERE project_id = $1 AND projected_id = $2 LIMIT 1").bind(pid).bind(seen.hex()).fetch_one(&h.db))
        .unwrap();
    ObjectId::from_hex(&real).unwrap()
}

/// BUG-1520: `sync::resolve_newest` orders several branch tips that share
/// the caller's projection by generation, not by the branch they work on.
/// fin's billing-only change D sits unlanded on `w2`, on main's tip H: the
/// dev sees both branches as the same snapshot. The dev's API commit on
/// main's tip as they see it (no `onto`, as an agent makes a change before
/// moving a branch) is made on D, the newer; their push of it to main is
/// then a fast-forward over D, and fin's unlanded billing work is on main,
/// moved there by someone who cannot see it. A push of the same change
/// (`push_with`'s tip candidates: the default branch first) is made on H.
#[test]
fn bug_1520_an_api_commit_on_main_as_seen_is_made_on_main_even_when_another_branch_s_tip_looks_the_same() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let token = p.dev.token();
    let mut c = Craft::new(&api, &p.admin, &p.name, "main");
    let main_tip = c.tip;
    c.file("src/h.rs", "h\n");
    let h = crafted_on(&mut c, main_tip, veil_core::ChangeId::random(), "h", "");
    let bill = format!("{BILL_DIR}/unlanded.txt");
    c.file(&bill, "fin's unlanded work\n");
    let d = crafted_on(&mut c, h, veil_core::ChangeId::random(), "d", "");
    let r = push_new(&c, &[("w2", d)]);
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["results"][0]["ok"], true, "{}", String::from_utf8_lossy(&r.body));
    move_branch(&api, &p.admin.token(), &p.name, "main", Some(main_tip), Some(h), false);
    let tips = api.tips(Some(&token), &p.name).unwrap().branches;
    assert_eq!(tips["main"], tips["w2"], "the dev sees w2 as main");
    wait_derived(&hub, pid, d);
    let seen = tips["main"];
    let mine = kept_change(&api, &token, &p.name, seen, json!([put("src/mine.rs", "the dev's\n")]));
    // The dev moves main to their change (a fast-forward, as they see it).
    move_branch(&api, &token, &p.name, "main", Some(seen), Some(mine), false);
    let got = source(&hub, pid).snapshot(&real_of_seen(&hub, pid, mine)).unwrap().parents[0];
    assert!(!on_branch_file(&hub, pid, "main", &bill), "fin's unlanded change on w2 is on main, moved there by the dev, who cannot see it");
    assert_eq!(got, h, "the dev's change on main as they see it is made on {}", if got == d { "w2's tip D".to_string() } else { got.short() });
}

/// BUG-1521: `sync::resolve_newest` answers `warming` for ever once more
/// than 4,096 real snapshots share the caller's projection (`NEWEST_BOUND`):
/// a run of changes hidden from them above a snapshot they see. The dev's
/// API commit, and their push, on a snapshot of main they read before a
/// burst of billing-only landings (4,100 here, then one change they see)
/// are answered 503 "try again" on every try, and succeed with 10 such
/// changes: the answer depends on how much hidden history there is (the
/// class of BUG-1409), and nothing the dev made on that snapshot is ever
/// accepted until someone changes a folder they see on top of it.
#[test]
fn bug_1521_a_change_on_a_snapshot_many_hidden_changes_share_is_accepted_as_with_few() {
    for n in [10usize, 4_100] {
        let hub = TestHub::start();
        let p = setup_project(&hub);
        let api = hub.api();
        let token = p.dev.token();
        let mut c = Craft::new(&api, &p.admin, &p.name, "main");
        let mut parent = c.tip;
        for i in 0..n {
            c.file(&format!("{BILL_DIR}/run.txt"), &format!("{i}\n"));
            parent = crafted_on(&mut c, parent, veil_core::ChangeId::random(), &format!("billing {i}"), "");
        }
        c.file("src/v.rs", "v\n");
        let v = crafted_on(&mut c, parent, veil_core::ChangeId::random(), "v", "");
        let r = push_new(&c, &[("billing-run", v)]);
        assert_eq!(r.json()["results"][0]["ok"], true, "{}", String::from_utf8_lossy(&r.body));
        // main moves on (so the snapshot below is no branch's tip).
        push_chain(&api, &p.admin, &p.name, "main", "main", 1, Some("src/later"));
        let seen_v = api.tips(Some(&token), &p.name).unwrap().branches["billing-run"];
        let base = seen_parent(&api, &token, &p.name, seen_v);
        let r = api.post_json(Some(&token), &format!("/v1/projects/{}/changes", p.name), &json!({"base": base.hex(), "edits": [put("src/old.rs", "the dev's\n")]}));
        assert_eq!(r.status, 200, "{n} hidden changes: the dev's API commit on a snapshot they read: {}", String::from_utf8_lossy(&r.body));
        let mut m = Craft::new(&api, &p.dev, &p.name, "main");
        m.tip = base;
        m.root = m.tree_of(base);
        m.file("src/old2.rs", "the dev's\n");
        let mine = crafted_on(&mut m, base, veil_core::ChangeId::random(), "mine", "");
        let r = push_new(&m, &[("dev-old", mine)]);
        assert_eq!(r.status, 200, "{n} hidden changes: the dev's push on a snapshot they read: {}", String::from_utf8_lossy(&r.body));
        assert_eq!(r.json()["results"][0]["ok"], true, "{n}: {}", String::from_utf8_lossy(&r.body));
    }
}

/// BUG-1522: "already landed" is keyed on the submitted snapshot's id
/// (`landed_from.source`), which a rebase changes. The dev lands P; after
/// pulling, they rebase P (and Q on it) onto main's tip, which holds P's
/// edits already: P2 is a revision of P (same change id, predecessor P)
/// with no edits of its own. Landing Q2 lands P2 as well: a second snapshot
/// of P's change on main (two snapshots with one change id on one branch,
/// a divergent change for every client); had P's file been undone on main
/// meanwhile, P2's edits (P's) would land again (BUG-1312's harm).
#[test]
fn bug_1522_a_rebased_revision_of_a_landed_change_is_not_landed_again() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let token = p.dev.token();
    let first = push_chain(&api, &p.dev, &p.name, "dev-work", "main", 1, Some("src/once"));
    let v = land_held(&api, &token, &p.name, first, true).json();
    assert_eq!(v["state"], "landed", "{v}");
    let start = real_tip(&hub, pid);
    let cid = source(&hub, pid).snapshot(&start).unwrap().change_id;
    // The dev's rebase of P and Q onto main as they now see it.
    let mut c = Craft::new(&api, &p.dev, &p.name, "main");
    let tip = c.tip;
    let mut s = Snapshot {
        parents: vec![tip],
        change_id: cid,
        tree: c.root,
        description: Text::Plain("chain 0".into()),
        author: "chain".into(),
        timestamp: veil_core::now_millis(),
        predecessors: vec![first],
        conflicts: vec![],
        embargo: None,
        signature: None,
    };
    s.sign(&c.identity);
    let p2 = c.put(O::Snapshot(s));
    c.file("src/twice/0.rs", "0\n");
    let q2 = crafted_on(&mut c, p2, veil_core::ChangeId::random(), "q", "");
    let r = push_new(&c, &[("rebased", q2)]);
    assert_eq!(r.json()["results"][0]["ok"], true, "{}", String::from_utf8_lossy(&r.body));
    let r = land_held(&api, &token, &p.name, q2, true);
    let body = String::from_utf8_lossy(&r.body).to_string();
    assert_eq!(r.status, 200, "{body}");
    assert_eq!(r.json()["state"], "landed", "{body}");
    assert_eq!(real_file(&hub, pid, "src/twice/0.rs").as_deref(), Some(&b"0\n"[..]));
    let ids: Vec<_> = chain(&hub, pid, veil_server::sync::root_snapshot_id()).into_iter().map(|(_, s)| s.change_id).collect();
    let twice = ids.iter().filter(|i| **i == cid).count();
    assert_eq!(twice, 1, "P's change is on main {twice} times");
    assert_eq!(r.json()["landed"].as_array().unwrap().len(), 1, "{body}");
}

/// BUG-1523 (and the guarantee it breaks): naming a real snapshot the
/// caller cannot see (a change hidden from them, or one they see only in
/// part) is answered exactly as naming a snapshot that does not exist, by
/// every route that takes a name: an API commit's `base`, a landing's
/// `base`, a push's parent and a landing of an uploaded snapshot on it
/// (status and message, ids aside). The first two hold. A push's parent
/// that `sync::resolve_named` does not resolve (`None`: "not theirs") is
/// taken for one the pusher uploads (`push_with`, step 1): the server reads
/// the hidden snapshot, and every one below it down to one the pusher sees
/// whole (here to the project's first), as theirs, and answers "missing
/// object 7717d0c0" (the real root tree of the first snapshot, an object
/// the dev may not read) where a snapshot that does not exist is "snapshot
/// … was not uploaded".
#[test]
fn bug_1523_a_snapshot_the_caller_cannot_see_is_named_as_one_that_does_not_exist() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let token = p.dev.token();
    let mut c = Craft::new(&api, &p.admin, &p.name, "main");
    let main_tip = c.tip;
    c.file(&format!("{BILL_DIR}/hidden.txt"), "fin's\n");
    let hidden = crafted_on(&mut c, main_tip, veil_core::ChangeId::random(), "hidden", "");
    c.file("src/part.rs", "part\n");
    let part = crafted_on(&mut c, hidden, veil_core::ChangeId::random(), "part", "");
    let r = push_new(&c, &[("w", part)]);
    assert_eq!(r.json()["results"][0]["ok"], true, "{}", String::from_utf8_lossy(&r.body));
    let seen = api.tips(Some(&token), &p.name).unwrap().branches["w"];
    assert_ne!(seen, part, "the dev sees w's tip only in part");
    let nothing = ObjectId::hash(b"no snapshot at all 5d1c");
    let answers = |x: ObjectId| -> Vec<(u16, String)> {
        let norm = |r: Reply, ids: &[ObjectId]| {
            let mut m = String::from_utf8_lossy(&r.body).to_string();
            for id in ids {
                m = m.replace(&id.hex(), "<id>").replace(&id.short(), "<id>");
            }
            (r.status, m)
        };
        let mut out = Vec::new();
        let r = api.post_json(Some(&token), &format!("/v1/projects/{}/changes", p.name), &json!({"base": x.hex(), "edits": [put("src/n.rs", "n\n")]}));
        out.push(norm(r, &[x]));
        out.push(norm(land(&api, &token, &p.name, x, json!([put("src/n.rs", "n\n")]), true), &[x]));
        let mut m = Craft::new(&api, &p.dev, &p.name, "main");
        m.file("src/n.rs", "n\n");
        let s = crafted_on(&mut m, x, veil_core::ChangeId::random(), "on a name", "");
        out.push(norm(push_new(&m, &[("named", s)]), &[x, s]));
        let up = api.upload(&token, &p.name, &m.objects);
        assert_eq!(up.status, 200, "{}", String::from_utf8_lossy(&up.body));
        let receipts = up.json()["receipts"].as_array().unwrap().clone();
        let map: serde_json::Map<String, Value> = m.objects.iter().zip(receipts).map(|((id, _), r)| (id.hex(), r)).collect();
        let r = api.post_json(Some(&token), &format!("/v1/projects/{}/land", p.name), &json!({"onto": "main", "snapshot": s.hex(), "receipts": map, "wait": true}));
        out.push(norm(r, &[x, s]));
        out
    };
    let none = answers(nothing);
    for (what, x) in [("a change hidden from the dev", hidden), ("a change the dev sees in part", part)] {
        let got = answers(x);
        for (i, route) in ["API commit", "landing of edits", "push", "landing of a snapshot"].iter().enumerate() {
            assert!(none[i].0 >= 400, "{route}: a snapshot that does not exist is refused: {:?}", none[i]);
            assert_eq!(got[i], none[i], "{route}: {what} is answered unlike a snapshot that does not exist");
        }
    }
}

/// BUG-1521, another bound of the class: "already landed" reads at most 64
/// `landed_from` rows of a change (`LANDED_FROM_LIMIT`) and answers
/// `warming` past it, and the rows are never deleted: a change landed on
/// more than 64 branches (a fix landed on every release branch) makes
/// every later landing of a change on it `warming`, for ever. Here the 64
/// other landings are rows written directly.
#[test]
fn bug_1521_a_change_on_one_landed_on_many_branches_lands() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let token = p.dev.token();
    let first = push_chain(&api, &p.dev, &p.name, "dev-work", "main", 1, Some("src/once"));
    let v = land_held(&api, &token, &p.name, first, true).json();
    assert_eq!(v["state"], "landed", "{v}");
    let source_id: String = sql_text(&hub, "SELECT source FROM landed_from WHERE project_id = $1 LIMIT 1", pid);
    let h = hub.hub();
    hub.rt
        .block_on(
            sqlx::query("INSERT INTO landed_from (project_id, source, landed) SELECT $1, $2, md5('l' || i) || md5('m' || i) FROM generate_series(1, 64) i")
                .bind(pid)
                .bind(&source_id)
                .execute(&h.db),
        )
        .unwrap();
    // An hour later: the `landings` rows are gone.
    hub.rt.block_on(sqlx::query("DELETE FROM landings WHERE project_id = $1").bind(pid).execute(&h.db)).unwrap();
    let second = push_chain(&api, &p.dev, &p.name, "dev-work", "dev-work", 1, Some("src/twice"));
    let r = land_held(&api, &token, &p.name, second, true);
    let body = String::from_utf8_lossy(&r.body).to_string();
    assert_eq!(r.status, 200, "a change on one landed on 65 branches: {body}");
    assert_eq!(r.json()["state"], "landed", "{body}");
    assert_eq!(r.json()["landed"].as_array().unwrap().len(), 1, "{body}");
}

/// Guarantee: a change landed long ago is not landed again under a later
/// one when its submitter's access changed in between (their view key is
/// another), with the `landings` rows gone and the deriver behind.
#[test]
fn a_change_landed_before_its_submitter_s_access_changed_is_not_landed_again() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let token = p.dev.token();
    let first = push_chain(&api, &p.dev, &p.name, "dev-work", "main", 1, Some("src/once"));
    let v = land_held(&api, &token, &p.name, first, true).json();
    assert_eq!(v["state"], "landed", "{v}");
    wait_derived(&hub, pid, real_tip(&hub, pid));
    p.admin.ok(&p.dir, &["group", "add", "security", &p.dev.name, "--confirm", &p.dev.fingerprint()]);
    let lock = hold_deriver(&hub, pid);
    push_chain(&api, &p.admin, &p.name, "main", "main", 300, None);
    let second = push_chain(&api, &p.dev, &p.name, "dev-work", "dev-work", 1, Some("src/twice"));
    let h = hub.hub();
    hub.rt.block_on(sqlx::query("DELETE FROM landings WHERE project_id = $1").bind(pid).execute(&h.db)).unwrap();
    let r = land_held(&api, &token, &p.name, second, true);
    drop(lock);
    let body = String::from_utf8_lossy(&r.body).to_string();
    assert_eq!(r.status, 200, "{body}");
    assert_eq!(r.json()["state"], "landed", "{body}");
    assert_eq!(r.json()["landed"].as_array().unwrap().len(), 1, "P landed again: {body}");
    assert_eq!(real_file(&hub, pid, "src/once/0.rs").as_deref(), Some(&b"0\n"[..]));
    assert_eq!(real_file(&hub, pid, "src/twice/0.rs").as_deref(), Some(&b"0\n"[..]));
}

/// Guarantee: entries queued before the server restarts land after it,
/// each exactly once (`landing::resume`), and their tickets answer.
#[test]
fn entries_queued_before_a_restart_land_once_after_it() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let token = p.dev.token();
    let start = real_tip(&hub, pid);
    hold(&hub, pid);
    let tickets: Vec<String> = {
        let api = hub.api();
        let base = tip_for(&hub, &token, &p.name);
        (0..3)
            .map(|i| {
                let r = land(&api, &token, &p.name, base, json!([put(&format!("src/restart/{i}.rs"), "r\n")]), false);
                assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
                assert_eq!(r.json()["state"], "queued", "{}", String::from_utf8_lossy(&r.body));
                r.json()["ticket"].as_str().unwrap().to_string()
            })
            .collect()
    };
    let hub = hub.restart(|_| {});
    release(&hub, pid);
    let api = hub.api();
    for t in &tickets {
        let mut v = outcome(&api, &token, &p.name, t);
        for _ in 0..20 {
            if v["state"] != "queued" {
                break;
            }
            v = outcome(&api, &token, &p.name, t);
        }
        assert_eq!(v["state"], "landed", "{v}");
    }
    let chain = chain(&hub, pid, start);
    assert_eq!(chain.len(), 3, "each queued change landed once");
    let ids: HashSet<_> = chain.iter().map(|(_, s)| s.change_id).collect();
    assert_eq!(ids.len(), 3, "a change landed twice");
}

/// Guarantee: a change named as its author saw it before their access
/// changed is landed as exactly their change, or refused; never grafted
/// on, or landed as, another snapshot.
#[test]
fn a_change_named_from_before_an_access_change_lands_as_itself_or_is_refused() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let token = p.dev.token();
    let start = real_tip(&hub, pid);
    let base = tip_for(&hub, &token, &p.name);
    let mine = kept_change(&api, &token, &p.name, base, json!([put("src/before.rs", "before\n")]));
    p.admin.ok(&p.dir, &["group", "add", "security", &p.dev.name, "--confirm", &p.dev.fingerprint()]);
    let r = land_held(&api, &token, &p.name, mine, true);
    let body = String::from_utf8_lossy(&r.body).to_string();
    match r.status {
        200 => {
            assert_eq!(r.json()["state"], "landed", "{body}");
            let chain = chain(&hub, pid, start);
            assert_eq!(chain.len(), 1, "{body}");
            assert_eq!(real_file(&hub, pid, "src/before.rs").as_deref(), Some(&b"before\n"[..]));
        }
        s => {
            // (403 today: "signed by a key no device here is registered
            // with", the old name read as an upload: BUG-1523.)
            assert!((400..500).contains(&s) || s == 503, "{s}: {body}");
            assert_eq!(real_tip(&hub, pid), start, "nothing landed: {body}");
        }
    }
    eprintln!("a change named from before an access change: {} {body}", r.status);
}

/// Guarantee, the merge route: the dev lands P, then merges main (with P's
/// landing) into their branch and puts Q on the merge; with the `landings`
/// rows gone, landing Q never lands P again (main's first-parent line holds
/// P's change once, and P's file as it was).
#[test]
fn a_change_landed_then_merged_back_is_not_landed_again() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let token = p.dev.token();
    let first = push_chain(&api, &p.dev, &p.name, "dev-work", "main", 1, Some("src/once"));
    let v = land_held(&api, &token, &p.name, first, true).json();
    assert_eq!(v["state"], "landed", "{v}");
    let landed_p = real_tip(&hub, pid);
    let cid = source(&hub, pid).snapshot(&landed_p).unwrap().change_id;
    let main_seen = tip_for(&hub, &token, &p.name);
    let mut c = Craft::new(&api, &p.dev, &p.name, "dev-work");
    c.root = c.tree_of(main_seen);
    let r = c.push_merge("dev-work", &[main_seen]);
    assert_eq!(r.json()["results"][0]["ok"], true, "{}", String::from_utf8_lossy(&r.body));
    let second = push_chain(&api, &p.dev, &p.name, "dev-work", "dev-work", 1, Some("src/twice"));
    let h = hub.hub();
    hub.rt.block_on(sqlx::query("DELETE FROM landings WHERE project_id = $1").bind(pid).execute(&h.db)).unwrap();
    let r = land_held(&api, &token, &p.name, second, true);
    let body = String::from_utf8_lossy(&r.body).to_string();
    assert_eq!(r.status, 200, "{body}");
    assert_eq!(r.json()["state"], "landed", "{body}");
    assert_eq!(real_file(&hub, pid, "src/twice/0.rs").as_deref(), Some(&b"0\n"[..]));
    assert_eq!(real_file(&hub, pid, "src/once/0.rs").as_deref(), Some(&b"0\n"[..]));
    let line = chain(&hub, pid, veil_server::sync::root_snapshot_id());
    assert_eq!(line.iter().filter(|(_, s)| s.change_id == cid).count(), 1, "P's change is on main's line more than once: {body}");
}

// ---- S17 redesign, cycle 4: guarantees -------------------------------------------------------

/// BUG-1522's rule, the refusal (decided): a revision of a change landed
/// already that brings further edits never lands them as that change: the
/// dev lands P, then a revision of P with one more file; landing it is
/// refused, naming the change's rule, and nothing of it lands.
#[test]
fn a_revision_of_a_landed_change_with_further_edits_is_refused() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let token = p.dev.token();
    let first = push_chain(&api, &p.dev, &p.name, "dev-work", "main", 1, Some("src/once"));
    let v = land_held(&api, &token, &p.name, first, true).json();
    assert_eq!(v["state"], "landed", "{v}");
    let tip = real_tip(&hub, pid);
    let cid = source(&hub, pid).snapshot(&tip).unwrap().change_id;
    // A revision of P on main as the dev sees it, with a further file.
    let mut c = Craft::new(&api, &p.dev, &p.name, "main");
    c.file("src/once/more.rs", "more\n");
    let mut s = Snapshot {
        parents: vec![c.tip],
        change_id: cid,
        tree: c.root,
        description: Text::Plain("P, amended".into()),
        author: "chain".into(),
        timestamp: veil_core::now_millis(),
        predecessors: vec![first],
        conflicts: vec![],
        embargo: None,
        signature: None,
    };
    s.sign(&c.identity);
    let p3 = c.put(O::Snapshot(s));
    let r = push_new(&c, &[("amended", p3)]);
    assert_eq!(r.json()["results"][0]["ok"], true, "{}", String::from_utf8_lossy(&r.body));
    let r = land_held(&api, &token, &p.name, p3, true);
    let body = String::from_utf8_lossy(&r.body).to_string();
    assert_eq!(r.status, 400, "{body}");
    assert!(body.contains("already landed") && body.contains("make a new change for the further edits"), "{body}");
    assert_eq!(real_tip(&hub, pid), tip, "{body}");
    assert!(real_file(&hub, pid, "src/once/more.rs").is_none());
}

/// BUG-1520's other route: a push of a change on main as its pusher sees it
/// is made on main's tip, as the API commit is (one resolution for both),
/// never on another branch's tip that looks the same to them.
#[test]
fn a_push_on_main_as_seen_is_made_on_main_even_when_another_branch_s_tip_looks_the_same() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let token = p.dev.token();
    let mut c = Craft::new(&api, &p.admin, &p.name, "main");
    let main_tip = c.tip;
    c.file("src/h.rs", "h\n");
    let h = crafted_on(&mut c, main_tip, veil_core::ChangeId::random(), "h", "");
    c.file(&format!("{BILL_DIR}/unlanded.txt"), "fin's unlanded work\n");
    let d = crafted_on(&mut c, h, veil_core::ChangeId::random(), "d", "");
    let r = push_new(&c, &[("w2", d)]);
    assert_eq!(r.json()["results"][0]["ok"], true, "{}", String::from_utf8_lossy(&r.body));
    move_branch(&api, &p.admin.token(), &p.name, "main", Some(main_tip), Some(h), false);
    let tips = api.tips(Some(&token), &p.name).unwrap().branches;
    assert_eq!(tips["main"], tips["w2"], "the dev sees w2 as main");
    wait_derived(&hub, pid, d);
    let mut m = Craft::new(&api, &p.dev, &p.name, "main");
    m.file("src/mine.rs", "the dev's\n");
    let mine = crafted_on(&mut m, tips["main"], veil_core::ChangeId::random(), "mine", "");
    let r = push_new(&m, &[("mine", mine)]);
    assert_eq!(r.json()["results"][0]["ok"], true, "{}", String::from_utf8_lossy(&r.body));
    let real = ObjectId::from_hex(&sql_text(&hub, "SELECT target FROM branches WHERE project_id = $1 AND name = 'mine'", pid)).unwrap();
    let got = source(&hub, pid).snapshot(&real).unwrap().parents[0];
    assert_eq!(got, h, "the dev's push on main as they see it is made on {}", if got == d { "w2's tip D".to_string() } else { got.short() });
}

/// BUG-1524: `landed_changes` is written for what a move brings; a
/// fast-forward to snapshots the server held already (here main moved to
/// the tip of another branch) records nothing for them, so a rebased
/// revision of one of their changes (emptied: main holds its edits) lands
/// again as an empty change with that change id.
#[test]
#[ignore = "BUG-1524: a rebased revision of a change that reached the branch by a fast-forward to held snapshots lands again"]
fn bug_1524_a_rebased_revision_of_a_change_fast_forwarded_onto_main_is_not_landed_again() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let token = p.dev.token();
    let main0 = tip_for(&hub, &token, &p.name);
    let first = push_chain(&api, &p.dev, &p.name, "side", "main", 1, Some("src/once"));
    // main fast-forwards to the side branch's tip (snapshots the server holds).
    move_branch(&api, &token, &p.name, "main", Some(main0), Some(first), false);
    let cid = source(&hub, pid).snapshot(&real_tip(&hub, pid)).unwrap().change_id;
    let mut c = Craft::new(&api, &p.dev, &p.name, "main");
    let mut s = Snapshot {
        parents: vec![c.tip],
        change_id: cid,
        tree: c.root,
        description: Text::Plain("rebased".into()),
        author: "chain".into(),
        timestamp: veil_core::now_millis(),
        predecessors: vec![first],
        conflicts: vec![],
        embargo: None,
        signature: None,
    };
    s.sign(&c.identity);
    let p2 = c.put(O::Snapshot(s));
    c.file("src/twice/0.rs", "0\n");
    let q2 = crafted_on(&mut c, p2, veil_core::ChangeId::random(), "q", "");
    let r = push_new(&c, &[("rebased", q2)]);
    assert_eq!(r.json()["results"][0]["ok"], true, "{}", String::from_utf8_lossy(&r.body));
    let v = land_held(&api, &token, &p.name, q2, true).json();
    assert_eq!(v["state"], "landed", "{v}");
    let ids: Vec<_> = chain(&hub, pid, veil_server::sync::root_snapshot_id()).into_iter().map(|(_, s)| s.change_id).collect();
    assert_eq!(ids.iter().filter(|i| **i == cid).count(), 1, "the change is on main twice");
}

// ---- S17 re-check (s17r5): guarantees and findings -------------------------------------------

/// A snapshot of `c`'s tree on `parent`, every field given (so two of them
/// differ only in what their trees hold).
fn snap_at(c: &mut Craft<'_>, parent: ObjectId, cid: veil_core::ChangeId, what: &str, t: i64, predecessors: Vec<ObjectId>) -> ObjectId {
    let mut s = Snapshot {
        parents: vec![parent],
        change_id: cid,
        tree: c.root,
        description: Text::Plain(what.into()),
        author: "crafter".into(),
        timestamp: t,
        predecessors,
        conflicts: vec![],
        embargo: None,
        signature: None,
    };
    s.sign(&c.identity);
    c.put(O::Snapshot(s))
}

/// Guarantee (`resolve_for`, the "two identical-looking changes on two
/// lines" rule): the admin's change A (`src/x.rs` and a billing file) is on
/// `w1`, and A2, the same change with other billing content, on `w2`; the
/// dev sees both tips as one snapshot N, and no one change stands under
/// them. A landing of edits on N takes the lowest real id of the two; its
/// answer and what lands are the same as with only A, or only A2, there
/// (any of them gives the same edits, and the choice tells nothing). An API
/// commit on N that is no landing is refused, the same with either lower.
#[test]
fn a_landing_on_a_name_two_lines_share_lands_the_same_whichever_is_lower() {
    let mut answers = Vec::new();
    for (has1, has2) in [(true, false), (false, true), (true, true), (true, true)] {
        let hub = TestHub::start();
        let p = setup_project(&hub);
        let pid = project_id(&hub, &p.name);
        let api = hub.api();
        let token = p.dev.token();
        let main0 = real_tip(&hub, pid);
        let mut c = Craft::new(&api, &p.admin, &p.name, "main");
        let (cid, t) = (veil_core::ChangeId::random(), veil_core::now_millis());
        c.file("src/x.rs", "x\n");
        c.file(&format!("{BILL_DIR}/acme/a.txt"), "one\n");
        let a1 = snap_at(&mut c, main0, cid, "A", t, vec![]);
        // In the last run A2 is made until the order of the two is the
        // other way round from the run before.
        let mut a2;
        let mut n = 0;
        loop {
            c.file(&format!("{BILL_DIR}/acme/a.txt"), &format!("two {n}\n"));
            a2 = snap_at(&mut c, main0, cid, "A", t, vec![]);
            if answers.len() < 3 || (a2 < a1) != matches!(answers.last(), Some((_, true))) {
                break;
            }
            n += 1;
        }
        let mut ups = Vec::new();
        if has1 {
            ups.push(("w1", a1));
        }
        if has2 {
            ups.push(("w2", a2));
        }
        let r = push_new(&c, &ups);
        assert!(r.json()["results"].as_array().unwrap().iter().all(|x| x["ok"] == true), "{}", String::from_utf8_lossy(&r.body));
        let tips = api.tips(Some(&token), &p.name).unwrap().branches;
        let seen = tips[if has1 { "w1" } else { "w2" }];
        if has1 && has2 {
            assert_eq!(tips["w1"], tips["w2"], "the dev sees the two lines' tips as one snapshot");
            // Anything that would move a branch to it is refused.
            let r = api.post_json(Some(&token), &format!("/v1/projects/{}/changes", p.name), &json!({"base": seen.hex(), "edits": [put("src/mine.rs", "m\n")]}));
            let body = String::from_utf8_lossy(&r.body).to_string();
            assert_eq!(r.status, 409, "{body}");
            assert!(body.contains("stands for changes on different lines"), "{body}");
        }
        let v = land(&api, &token, &p.name, seen, json!([put("src/mine.rs", "m\n")]), true).json();
        assert_eq!(v["state"], "landed", "{v}");
        let mut shown = without_ticket(v);
        shown.as_object_mut().unwrap().remove("landed");
        shown.as_object_mut().unwrap().remove("change_id");
        // What lands: the dev's edit on main's tip, nothing of either line.
        assert_eq!(real_file(&hub, pid, "src/mine.rs").as_deref(), Some(&b"m\n"[..]));
        assert!(real_file(&hub, pid, "src/x.rs").is_none());
        assert!(real_file(&hub, pid, &format!("{BILL_DIR}/acme/a.txt")).is_none());
        let line = chain(&hub, pid, main0);
        assert_eq!(line.len(), 1, "one change landed on main0");
        answers.push((shown, a2 < a1));
    }
    assert!(answers[2].1 != answers[3].1, "the two runs with both lines put the lower id on each line once");
    for a in &answers[1..] {
        assert_eq!(a.0, answers[0].0, "the answer is the same whatever is on the lines");
    }
}

/// BUG-1525: `resolve_for` answers a snapshot the pusher sees whole by its
/// own id before it looks at the branch tips: a push to main, on main's
/// tip as the dev sees it, is made on that snapshot, not on the hidden-only
/// change at main's tip, and is refused as "not a fast-forward" for ever.
/// The project's billing folder (finance only) is made after its access
/// line, so the dev sees main's first snapshot whole.
#[test]
fn bug_1525_a_push_on_main_as_seen_whole_is_made_on_main_s_tip_over_a_hidden_only_change() {
    let hub = TestHub::start();
    let admin = hub.person("admin");
    let dev = hub.person("dev");
    let fin = hub.person("fin");
    let name = unique("acme");
    let dir = admin.dir("proj");
    std::fs::create_dir_all(&dir).unwrap();
    admin.ok(&dir, &["init"]);
    // The access lines are in the first snapshot, so the dev sees it whole.
    let policy = format!(".veilpolicy {0}\nsrc/ {0}\nbilling/ {1}\n", dev.name, fin.name);
    write_files(&dir, &[("src/lib.rs", "pub fn a() {}\n"), (".veilpolicy", &policy)]);
    admin.ok(&dir, &["remote", "add", "origin", &hub.url(&name)]);
    admin.commit_main(&dir, "initial import");
    let out = admin.ok(&dir, &["push"]);
    assert!(out.contains("Created project"), "{out}");
    let api = hub.api();
    let pid = project_id(&hub, &name);
    let h = real_tip(&hub, pid);
    assert_eq!(tip_for(&hub, &dev.token(), &name), h, "the dev sees main's tip whole");
    // A billing-only change at main's tip: hidden from the dev.
    let mut c = Craft::new(&api, &admin, &name, "main");
    c.file("billing/x.txt", "fin's\n");
    let r = c.push("main", "billing only");
    assert_eq!(r.json()["results"][0]["ok"], true, "{}", String::from_utf8_lossy(&r.body));
    let x = real_tip(&hub, pid);
    assert_ne!(x, h);
    assert_eq!(tip_for(&hub, &dev.token(), &name), h, "the dev sees main as before");
    let mut m = Craft::new(&api, &dev, &name, "main");
    m.file("src/mine.rs", "the dev's\n");
    let r = m.push("main", "mine");
    assert_eq!(r.json()["results"][0]["ok"], true, "{}", String::from_utf8_lossy(&r.body));
    let tip = real_tip(&hub, pid);
    assert_eq!(source(&hub, pid).snapshot(&tip).unwrap().parents, vec![x], "made on main's tip");
    assert_eq!(real_file(&hub, pid, "billing/x.txt").as_deref(), Some(&b"fin's\n"[..]));
}

/// BUG-1526: "already landed" (`Ancestry::landed`) compares a held change's
/// whole edits, hidden paths included, for every change on the
/// submitter's line, also one they see only in part: the admin's change F
/// (`src/f.rs` and a billing file) landed; F2, a revision of F on main0
/// with one more billing file, is on `f2`. The dev, who sees F2 exactly as
/// F (its `src/f.rs`), lands their change made on `f2`: refused ("already
/// landed … with other edits"), where with F2 holding no further billing
/// file it lands. The answer tells the dev whether hidden content of a
/// revision changed, and blocks their landing on edits they cannot see.
#[test]
fn bug_1526_already_landed_never_judges_a_change_by_edits_its_submitter_cannot_see() {
    let mut answers = Vec::new();
    for extra in [false, true] {
        let hub = TestHub::start();
        let p = setup_project(&hub);
        let pid = project_id(&hub, &p.name);
        let api = hub.api();
        let mut c = Craft::new(&api, &p.admin, &p.name, "main");
        let main0 = c.tip;
        let cid = veil_core::ChangeId::random();
        c.file("src/f.rs", "f\n");
        c.file(&format!("{BILL_DIR}/acme/f.txt"), "f\n");
        let f = snap_at(&mut c, main0, cid, "F", veil_core::now_millis(), vec![]);
        let r = push_new(&c, &[("f1", f)]);
        assert_eq!(r.json()["results"][0]["ok"], true, "{}", String::from_utf8_lossy(&r.body));
        let v = land_held(&api, &p.admin.token(), &p.name, f, true).json();
        assert_eq!(v["state"], "landed", "{v}");
        if extra {
            c.file(&format!("{BILL_DIR}/acme/g.txt"), "g\n");
        }
        let f2 = snap_at(&mut c, main0, cid, "F, amended", veil_core::now_millis(), vec![f]);
        let r = push_new(&c, &[("f2", f2)]);
        assert_eq!(r.json()["results"][0]["ok"], true, "{}", String::from_utf8_lossy(&r.body));
        let mut m = Craft::new(&api, &p.dev, &p.name, "f2");
        m.file("src/mine.rs", "the dev's\n");
        let on = m.tip;
        let mine = crafted_on(&mut m, on, veil_core::ChangeId::random(), "mine", "");
        let r = push_new(&m, &[("mine", mine)]);
        assert_eq!(r.json()["results"][0]["ok"], true, "{}", String::from_utf8_lossy(&r.body));
        let r = land_held(&api, &p.dev.token(), &p.name, mine, true);
        let body = String::from_utf8_lossy(&r.body).to_string();
        assert_eq!(r.status, 200, "extra billing file: {extra}: {body}");
        let v = r.json();
        assert_eq!(v["state"], "landed", "extra billing file: {extra}: {v}");
        assert_eq!(real_file(&hub, pid, "src/mine.rs").as_deref(), Some(&b"the dev's\n"[..]));
        let mut shown = without_ticket(v);
        shown.as_object_mut().unwrap().remove("landed");
        shown.as_object_mut().unwrap().remove("change_id");
        answers.push(shown);
    }
    assert_eq!(answers[0], answers[1], "the answer is the same whatever F2 holds in billing");
}

/// BUG-1527: "already landed" trusts a change id, which every client
/// chooses: fin, who reads `src/` but may write only billing, sees the
/// dev's unlanded change V on `v` and lands a change of their own (a
/// billing file) under V's change id. The dev's landing of V is then
/// refused ("already landed … with other edits"), though nothing of V is
/// on main: fin blocks a change they may not write.
#[test]
fn bug_1527_a_change_landed_under_someone_else_s_change_id_never_blocks_theirs() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let mut d = Craft::new(&api, &p.dev, &p.name, "main");
    let on = d.tip;
    d.file("src/v.rs", "the dev's\n");
    let cid = veil_core::ChangeId::random();
    let v = crafted_on(&mut d, on, cid, "V", "");
    let r = push_new(&d, &[("v", v)]);
    assert_eq!(r.json()["results"][0]["ok"], true, "{}", String::from_utf8_lossy(&r.body));
    // fin sees V on `v`, its change id included.
    let fin_v = Craft::new(&api, &p.fin, &p.name, "v").tip;
    let h = api.post_json(Some(&p.fin.token()), &format!("/v1/projects/{}/history", p.name), &json!({"tips": [fin_v.hex()]}));
    let (_, raw) = h.frames().into_iter().find(|(id, _)| *id == fin_v).unwrap();
    let O::Snapshot(seen) = O::decode(&raw).unwrap() else { panic!() };
    assert_eq!(seen.change_id, cid);
    let mut f2 = Craft::new(&api, &p.fin, &p.name, "main");
    let on = f2.tip;
    f2.file(&format!("{BILL_DIR}/acme/s.txt"), "fin's\n");
    let s = crafted_on(&mut f2, on, seen.change_id, "not V", "");
    let r = push_new(&f2, &[("s", s)]);
    assert_eq!(r.json()["results"][0]["ok"], true, "{}", String::from_utf8_lossy(&r.body));
    let w = land_held(&api, &p.fin.token(), &p.name, s, true).json();
    assert_eq!(w["state"], "landed", "{w}");
    let r = land_held(&api, &p.dev.token(), &p.name, v, true);
    let body = String::from_utf8_lossy(&r.body).to_string();
    assert_eq!(r.status, 200, "{body}");
    assert_eq!(r.json()["state"], "landed", "{body}");
    assert_eq!(real_file(&hub, pid, "src/v.rs").as_deref(), Some(&b"the dev's\n"[..]));
}

/// Guarantee (BUG-1523's rule, the receipts): a push treats as new only a
/// snapshot its pusher holds a receipt of their own for. fin uploads a
/// billing change F (never pushed); the dev pushes a change on F with fin's
/// receipt for it, and another on an id nothing has: both are answered
/// "snapshot … was not uploaded", the same answer, and nothing moves.
#[test]
fn a_push_on_a_snapshot_uploaded_by_someone_else_is_answered_as_one_that_does_not_exist() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let mut f = Craft::new(&api, &p.fin, &p.name, "main");
    let on = f.tip;
    f.file(&format!("{BILL_DIR}/acme/up.txt"), "fin's upload\n");
    let fs = crafted_on(&mut f, on, veil_core::ChangeId::random(), "F", "");
    let up = api.upload(&f.token, &p.name, &f.objects);
    assert_eq!(up.status, 200, "{}", String::from_utf8_lossy(&up.body));
    let fin_receipts: Vec<Value> = up.json()["receipts"].as_array().unwrap().clone();
    let fin_receipt = fin_receipts[f.objects.iter().position(|(id, _)| *id == fs).unwrap()].clone();
    let mut answers = Vec::new();
    let nothing = ObjectId::hash(b"no such snapshot, s17r5");
    for (parent, lend) in [(fs, true), (nothing, false)] {
        let mut d = Craft::new(&api, &p.dev, &p.name, "main");
        d.file("src/on.rs", "on\n");
        let c = crafted_on(&mut d, parent, veil_core::ChangeId::random(), "C", "");
        let up = api.upload(&d.token, &p.name, &d.objects);
        assert_eq!(up.status, 200, "{}", String::from_utf8_lossy(&up.body));
        let receipts = up.json()["receipts"].as_array().unwrap().clone();
        let mut map: serde_json::Map<String, Value> = d.objects.iter().zip(receipts).map(|((id, _), r)| (id.hex(), r)).collect();
        if lend {
            map.insert(fs.hex(), fin_receipt.clone());
        }
        let r = api.post_json(
            Some(&d.token),
            &format!("/v1/projects/{}/push", p.name),
            &json!({"updates": [{"branch": "on-f", "expected": null, "new": c.hex()}], "receipts": map}),
        );
        let body = String::from_utf8_lossy(&r.body).to_string();
        assert_eq!(r.status, 400, "{body}");
        assert_eq!(r.json()["message"], format!("snapshot {} was not uploaded", parent.short()), "{body}");
        answers.push(r.json()["code"].clone());
        assert!(!api.tips(Some(&d.token), &p.name).unwrap().branches.contains_key("on-f"));
    }
    assert_eq!(answers[0], answers[1]);
}

/// Never silent: a change left out of a stack as landed already (its edits
/// the landed revision's: here P rebased on main, which holds P) is named in
/// the answer, by its change id.
#[test]
fn a_change_left_out_as_landed_already_is_named_in_the_answer() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let api = hub.api();
    let token = p.dev.token();
    let first = push_chain(&api, &p.dev, &p.name, "dev-work", "main", 1, Some("src/once"));
    let v = land_held(&api, &token, &p.name, first, true).json();
    assert_eq!(v["state"], "landed", "{v}");
    let cid = source(&hub, pid).snapshot(&real_tip(&hub, pid)).unwrap().change_id;
    let mut c = Craft::new(&api, &p.dev, &p.name, "main");
    let tip = c.tip;
    let p2 = snap_at(&mut c, tip, cid, "P, rebased", veil_core::now_millis(), vec![first]);
    c.file("src/twice/0.rs", "0\n");
    let q2 = crafted_on(&mut c, p2, veil_core::ChangeId::random(), "q", "");
    let r = push_new(&c, &[("rebased", q2)]);
    assert_eq!(r.json()["results"][0]["ok"], true, "{}", String::from_utf8_lossy(&r.body));
    let v = land_held(&api, &token, &p.name, q2, true).json();
    assert_eq!(v["state"], "landed", "{v}");
    assert_eq!(v["landed"].as_array().unwrap().len(), 1, "{v}");
    let warnings = v["warnings"].as_array().cloned().unwrap_or_default();
    assert!(
        warnings.iter().any(|w| w.as_str().is_some_and(|w| w.contains(&cid.to_string()) && w.contains("already landed"))),
        "the change left out is not named: {v}"
    );
}
