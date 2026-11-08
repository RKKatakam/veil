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
    eprintln!("{} {body}", r.status);
    assert!(!body.contains(BILL_DIR), "the dev's landing answer names a path under billing, which they cannot read: {body}");
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
    std::fs::write("/proc/self/clear_refs", "5").unwrap();
    let (start, _) = rss();
    let trees0 = hub.hub().trees.stats().weight;
    release(&hub, pid);
    assert_eq!(outcome(&api, &atok, &p.name, a["ticket"].as_str().unwrap())["state"], "landed");
    for t in &tickets {
        assert_eq!(outcome(&api, &token, &p.name, t)["state"], "landed");
    }
    let (_, peak) = rss();
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
