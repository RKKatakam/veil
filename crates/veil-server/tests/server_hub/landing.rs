//! The landing service (S17, `docs/HUB.md` §13.15; phase 4 §4.1–4.6 and
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
        // The first was on the tip already, and lands as it was submitted;
        // the others are made again on it, naming what was submitted.
        assert_eq!(s.predecessors.len(), usize::from(i > 0), "{i}");
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
#[ignore = "BUG-1100: after an access change, the landing service's first batch projects all history for each new view key"]
fn bug_1100_the_first_landing_after_an_access_change_projects_one_batch_not_all_history() {
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
    let before = veil_core::now_millis();
    let r = land(&api, &token, &p.name, tip_for(&hub, &token, &p.name), json!([put("src/after.rs", "after\n")]), true);
    assert_eq!(r.json()["state"], "landed");
    // One landing: a batch's worth of projections, not one per snapshot of
    // the history.
    let h = hub.hub();
    let rows: i64 = hub
        .rt
        .block_on(sqlx::query_scalar("SELECT count(*) FROM projections WHERE project_id = $1 AND created_at >= $2").bind(pid).bind(before).fetch_one(&h.db))
        .unwrap();
    assert!(rows <= 10, "{rows} projections made for one landing");
}
