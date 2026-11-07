//! Commits through the API (`docs/HUB.md` §13.13): `POST …/changes` and
//! `vl change new`. Every check a push gets, an API commit gets too; the
//! server-side secret scan; hostile edit lists; `onto` with `expected` and
//! `rebase` under races; snapshots and projections that verify like
//! pushed ones (phase 2 §6, threats 11–13).

use serde_json::{json, Value};
use veil_core::{object::Object as O, ObjectId};

use crate::support::*;

fn tip_for(hub: &TestHub, token: &str, project: &str) -> ObjectId {
    hub.api().tips(Some(token), project).unwrap().branches["main"]
}

fn change(hub: &TestHub, token: &str, project: &str, body: &Value) -> Reply {
    hub.api().post_json(Some(token), &format!("/v1/projects/{project}/changes"), body)
}

fn put(path: &str, text: &str) -> Value {
    json!({"path": path, "put": {"text": text}})
}

/// The project's id on the server.
fn project_id(hub: &TestHub, name: &str) -> i64 {
    let h = hub.hub();
    hub.rt
        .block_on(sqlx::query_scalar::<_, i64>("SELECT id FROM projects WHERE name = $1").bind(name).fetch_one(&h.db))
        .unwrap()
}

/// Is object `id` in the project's object store?
fn stored(hub: &TestHub, project: i64, id: &ObjectId) -> bool {
    let h = hub.hub();
    hub.rt.block_on(h.objects.get(project, id)).unwrap().is_some()
}

fn change_refs(hub: &TestHub, project: i64) -> i64 {
    let h = hub.hub();
    hub.rt
        .block_on(sqlx::query_scalar::<_, i64>("SELECT count(*) FROM change_refs WHERE project_id = $1").bind(project).fetch_one(&h.db))
        .unwrap()
}

/// Files under `dir`, recursively.
fn walk_count(dir: &std::path::Path) -> usize {
    let Ok(rd) = std::fs::read_dir(dir) else { return 0 };
    rd.flatten()
        .map(|e| if e.file_type().unwrap().is_dir() { walk_count(&e.path()) } else { 1 })
        .sum()
}

fn blob_id(text: &str) -> ObjectId {
    ObjectId::hash(&O::Blob(text.as_bytes().to_vec()).encode())
}

#[test]
fn an_api_commit_lands_and_verifies_like_a_push_for_every_viewer() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let token = p.dev.token();
    let base = tip_for(&hub, &token, &p.name);
    let mark = "MARKER-API-COMMIT-5d7e21b0";
    // Objects stored, when they go to a directory (not MinIO).
    let objects = hub._dir.path().join("objects");
    let count = || walk_count(&objects);
    let before = count();
    let t0 = std::time::Instant::now();
    let r = change(
        &hub,
        &token,
        &p.name,
        &json!({"base": base.hex(), "description": "through the API", "edits": [put("src/api/new.rs", mark)],
                "onto": {"branch": "main", "expected": base.hex()}}),
    );
    let took = t0.elapsed();
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let v = r.json();
    assert_eq!(v["branch"]["status"], "ok", "{v}");
    let mine: ObjectId = serde_json::from_value(v["snapshot"].clone()).unwrap();
    assert_eq!(tip_for(&hub, &token, &p.name), mine, "the caller sees the change they made as main");
    eprintln!("api commit of one file: {took:?} (request, as the client sees it)");
    if std::env::var_os("VEIL_TEST_S3_ENDPOINT").is_none() {
        // The blob, the full trees on its path (root, src/, src/api/), the
        // server's snapshot and the dev's projection of it.
        let new = count() - before;
        eprintln!("api commit of one file by a non-admin: {new} new objects stored");
        assert!(new <= 6, "{new} objects stored for one file");
    }
    // Everyone pulls it through `vl`, which verifies every signature; each
    // receives only what they may see, and the hidden folders are intact.
    p.admin.ok(&p.dir, &["pull"]);
    let real = real_paths(&p.dir);
    for want in ["src/api/new.rs", ROOT_FILE, &format!("{BILL_DIR}/acme/invoice.txt") as &str, &format!("src/{NESTED_DIR}/key.txt"), &format!("{BILL_DIR}/.env")] {
        assert!(real.iter().any(|(path, _)| path == want), "{want} missing after the API commit");
    }
    let log = p.admin.ok(&p.dir, &["log", "-r", "main", "-n", "1"]);
    assert!(log.contains("through the API") && log.contains(&p.dev.name), "{log}");
    for who in [&p.dev, &p.fin, &p.sec, &p.carol] {
        let d = who.dir(&unique("after"));
        who.ok(who.home.path(), &["clone", &hub.url(&p.name), d.to_str().unwrap()]);
        assert_eq!(std::fs::read_to_string(d.join("src/api/new.rs")).unwrap(), mark, "{}", who.name);
        let mut seen = everything_in(&d);
        let h = hub.api().post_json(Some(&who.token()), &format!("/v1/projects/{}/history", p.name), &json!({"tips": [tip_for(&hub, &who.token(), &p.name).hex()]}));
        seen.push(("history".into(), h.body));
        let hidden: Vec<&str> = match who.name == p.fin.name {
            true => vec![ROOT_MARK, NESTED_MARK, PERSON_MARK],
            false if who.name == p.sec.name => vec![ROOT_MARK, BILL_MARK, PERSON_MARK, ENV_MARK],
            false if who.name == p.carol.name => vec![ROOT_MARK, BILL_MARK, NESTED_MARK, ENV_MARK],
            false => restricted_markers(),
        };
        assert_no_marker(&seen, &hidden, &who.name);
    }
    // The dev builds on it with a push, as on any snapshot.
    let d = p.dev.dir("c");
    p.dev.ok(p.dev.home.path(), &["clone", &hub.url(&p.name), d.to_str().unwrap()]);
    write_files(&d, &[("src/api/more.rs", "fn more() {}")]);
    p.dev.commit_main(&d, "on top");
    p.dev.ok(&d, &["push"]);
}

#[test]
fn an_api_commit_is_refused_whatever_a_push_refuses_and_stores_nothing() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id(&hub, &p.name);
    let token = p.dev.token();
    let base = tip_for(&hub, &token, &p.name);
    let policy = std::fs::read_to_string(p.dir.join(".veilpolicy")).unwrap();
    // A blob that is only in a folder the dev cannot see.
    let hidden = real_paths(&p.dir).into_iter().find(|(path, _)| path.ends_with("acme/invoice.txt")).unwrap().1;
    let token_secret = "AKIAQ7W3EXAMPLEZ4K2M";
    let secret_line = format!("aws_access_key_id = {token_secret}\n");
    let cases: Vec<(&str, Value, &str)> = vec![
        ("a folder they cannot see", put(&format!("{BILL_DIR}/x.txt"), "x"), "access"),
        ("the private root", put("NEW-AT-ROOT.txt", "x"), "access"),
        ("a nested folder they cannot see", put(&format!("src/{NESTED_DIR}/x.txt"), "x"), "access"),
        ("an access line", put(".veilpolicy", &format!("{policy}{BILL_DIR}/ devs\n")), "access"),
        ("a personal key", put("src/id_ed25519", "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n"), "personal"),
        ("a plain-text shared secret", put("src/.env", "KEY=value\n"), "secret"),
        ("a secret in an ordinary file", put("src/config.rs", &secret_line), "secret"),
        ("a hidden object", json!({"path": "src/copy.txt", "put": {"object": hidden.hex()}}), "missing object"),
        ("an object never uploaded", json!({"path": "src/copy.txt", "put": {"object": ObjectId::hash(b"nothing").hex()}}), "missing object"),
        ("a hidden file deleted", json!({"path": format!("{BILL_DIR}/acme/invoice.txt"), "delete": true}), "nothing at"),
    ];
    for (what, edit, expect) in &cases {
        for onto in [json!(null), json!({"branch": "main", "expected": "rebase"})] {
            let r = change(&hub, &token, &p.name, &json!({"base": base.hex(), "edits": [edit], "onto": onto}));
            let body = String::from_utf8_lossy(&r.body).to_string();
            assert!(matches!(r.status, 400 | 403), "{what}: {} {body}", r.status);
            assert!(body.to_lowercase().contains(expect), "{what}: {body}");
            assert!(!body.contains(token_secret) && !body.contains("KEY=value"), "{what}: the answer echoes the secret: {body}");
        }
    }
    // The hidden object and a random one are refused alike: nothing tells
    // the dev which exists.
    let a = change(&hub, &token, &p.name, &json!({"base": base.hex(), "edits": [cases[7].1]}));
    let b = change(&hub, &token, &p.name, &json!({"base": base.hex(), "edits": [cases[8].1]}));
    assert_eq!(
        a.json()["message"].as_str().unwrap().replace(&hidden.short(), "X"),
        b.json()["message"].as_str().unwrap().replace(&ObjectId::hash(b"nothing").short(), "X")
    );
    // Read-only: finance reads the public src/ but may not write it.
    let r = change(&hub, &p.fin.token(), &p.name, &json!({"base": tip_for(&hub, &p.fin.token(), &p.name).hex(), "edits": [put("src/lib.rs", "x")]}));
    assert_eq!(r.status, 403);
    assert!(String::from_utf8_lossy(&r.body).contains("may not write 'src/lib.rs'"));
    // Anyone on Earth, and a base the caller cannot see (the admin's real tip).
    assert_eq!(hub.api().post_json(None, &format!("/v1/projects/{}/changes", p.name), &json!({"base": base.hex(), "edits": [put("src/a", "a")]})).status, 401);
    let real_tip = tip_for(&hub, &p.admin.token(), &p.name);
    assert_ne!(real_tip, base);
    let r = change(&hub, &token, &p.name, &json!({"base": real_tip.hex(), "edits": [put("src/a", "a")]}));
    assert_eq!(r.status, 404, "{}", String::from_utf8_lossy(&r.body));
    // Nothing landed, nothing is on a change ref, and neither secret was
    // ever stored, even unreferenced.
    assert_eq!(tip_for(&hub, &token, &p.name), base);
    assert_eq!(change_refs(&hub, pid), 0);
    assert!(!stored(&hub, pid, &blob_id(&secret_line)), "a refused secret reached the object store");
    assert!(!stored(&hub, pid, &blob_id("KEY=value\n")), "a refused secret reached the object store");
    // What the dev may do lands; a sealed secret from `vl` does too (below).
    let r = change(&hub, &token, &p.name, &json!({"base": base.hex(), "edits": [put("src/ok.rs", "fn ok() {}")], "onto": {"branch": "main", "expected": "rebase"}}));
    assert_eq!(r.json()["branch"]["status"], "ok", "{}", String::from_utf8_lossy(&r.body));
    // Admins change access lines through the API too, and are told who
    // can now see what.
    let atok = p.admin.token();
    let abase = tip_for(&hub, &atok, &p.name);
    let r = change(&hub, &atok, &p.name, &json!({"base": abase.hex(), "edits": [put(".veilpolicy", &format!("{policy}docs/ public\n"))],
        "onto": {"branch": "main", "expected": abase.hex()}}));
    let v = r.json();
    assert_eq!(v["branch"]["status"], "ok", "{v}");
    assert!(v["warnings"].as_array().unwrap().iter().any(|w| w.as_str().unwrap().contains("docs/ → everyone on Earth")), "{v}");
}

#[test]
fn the_secret_scan_is_off_only_where_the_accepted_policy_says_public_bang() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let fixture = "aws_access_key_id = AKIAZ3K7EXAMPLEQ9W2N\n";
    let atok = p.admin.token();
    let commit = |token: &str, edits: Value| {
        let base = tip_for(&hub, token, &p.name);
        change(&hub, token, &p.name, &json!({"base": base.hex(), "edits": edits, "onto": {"branch": "main", "expected": "rebase"}}))
    };
    // Before any `public!`, the admin's fixture is refused like anyone's.
    let r = commit(&atok, json!([put("src/fixtures/aws.txt", fixture)]));
    assert_eq!(r.status, 403, "{}", String::from_utf8_lossy(&r.body));
    let r = commit(&p.dev.token(), json!([put("src/aws.txt", fixture)]));
    assert_eq!(r.status, 403, "{}", String::from_utf8_lossy(&r.body));
    assert!(!String::from_utf8_lossy(&r.body).contains("AKIAZ3K7EXAMPLEQ9W2N"));
    // The admin marks src/fixtures/ `public!` (test data: scanning off),
    // and the fixture lands there, in the same change or a later one.
    let policy = std::fs::read_to_string(p.dir.join(".veilpolicy")).unwrap();
    let r = commit(&atok, json!([put(".veilpolicy", &format!("{policy}src/fixtures/ public!\n")), put("src/fixtures/aws.txt", fixture)]));
    assert_eq!(r.json()["branch"]["status"], "ok", "{}", String::from_utf8_lossy(&r.body));
    let r = commit(&atok, json!([put("src/fixtures/aws2.txt", fixture)]));
    assert_eq!(r.json()["branch"]["status"], "ok", "{}", String::from_utf8_lossy(&r.body));
    // Anywhere else it is still refused.
    let r = commit(&atok, json!([put("src/aws.txt", fixture)]));
    assert_eq!(r.status, 403, "{}", String::from_utf8_lossy(&r.body));
}

#[test]
fn hostile_edit_lists_are_refused() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let token = p.dev.token();
    let base = tip_for(&hub, &token, &p.name);
    let deep = vec!["d"; 1100].join("/");
    let many: Vec<Value> = (0..10_001).map(|i| put(&format!("src/m/{i}"), "x")).collect();
    let decomposed = "src/cafe\u{301}.txt";
    let bodies: Vec<(&str, Value)> = vec![
        ("dot-dot", json!({"base": base.hex(), "edits": [put("src/../x", "x")]})),
        ("leading slash", json!({"base": base.hex(), "edits": [put("/src/x", "x")]})),
        ("trailing slash", json!({"base": base.hex(), "edits": [put("src/x/", "x")]})),
        ("empty component", json!({"base": base.hex(), "edits": [put("src//x", "x")]})),
        ("dot", json!({"base": base.hex(), "edits": [put("src/./x", "x")]})),
        (".veil", json!({"base": base.hex(), "edits": [put("src/.veil/x", "x")]})),
        (".VEIL", json!({"base": base.hex(), "edits": [put("src/.VEIL", "x")]})),
        (".v\u{200C}eil", json!({"base": base.hex(), "edits": [put("src/.v\u{200C}eil/x", "x")]})),
        ("NUL", json!({"base": base.hex(), "edits": [put("src/a\u{0}b", "x")]})),
        ("not NFC", json!({"base": base.hex(), "edits": [put(decomposed, "x")]})),
        ("too deep", json!({"base": base.hex(), "edits": [put(&format!("src/{deep}"), "x")]})),
        ("too many", json!({"base": base.hex(), "edits": many})),
        ("none", json!({"base": base.hex(), "edits": []})),
        ("twice", json!({"base": base.hex(), "edits": [put("src/a", "1"), put("src/a", "2")]})),
        ("a file and below it", json!({"base": base.hex(), "edits": [put("src/a", "1"), put("src/a/b", "2")]})),
        ("put and delete", json!({"base": base.hex(), "edits": [{"path": "src/a", "put": {"text": "x"}, "delete": true}]})),
        ("neither", json!({"base": base.hex(), "edits": [{"path": "src/a"}]})),
        ("object and text", json!({"base": base.hex(), "edits": [{"path": "src/a", "put": {"text": "x", "object": base.hex()}}]})),
        ("unknown field", json!({"base": base.hex(), "edits": [{"path": "src/a", "put": {"text": "x", "mode": 777}}]})),
        ("a file as a folder", json!({"base": base.hex(), "edits": [put("src/lib.rs/x", "x")]})),
        ("a folder as a file", json!({"base": base.hex(), "edits": [put("src", "x")]})),
        ("a snapshot as a file", json!({"base": base.hex(), "edits": [{"path": "src/s", "put": {"object": base.hex()}}]})),
        ("bad branch", json!({"base": base.hex(), "edits": [put("src/a", "x")], "onto": {"branch": "../main", "expected": "rebase"}})),
        ("no such branch", json!({"base": base.hex(), "edits": [put("src/a", "x")], "onto": {"branch": "nope", "expected": "rebase"}})),
        ("bad expected", json!({"base": base.hex(), "edits": [put("src/a", "x")], "onto": {"branch": "main", "expected": "soon"}})),
        ("someone else's change id", json!({"base": base.hex(), "change_id": veil_core::ChangeId::random().to_string(), "edits": [put("src/a", "x")]})),
    ];
    for (what, body) in &bodies {
        let r = change(&hub, &token, &p.name, body);
        assert!((400..500).contains(&r.status), "{what}: {} {}", r.status, String::from_utf8_lossy(&r.body));
    }
    // More than 64 MiB of inline text.
    let big = "x".repeat((64 << 20) + 1);
    let r = change(&hub, &token, &p.name, &json!({"base": base.hex(), "edits": [put("src/big", &big)]}));
    assert!(matches!(r.status, 400 | 413), "{}", r.status);
    assert_eq!(tip_for(&hub, &token, &p.name), base, "nothing landed");
    assert_eq!(change_refs(&hub, project_id(&hub, &p.name)), 0);
}

#[test]
fn rebase_lands_every_racing_change_once_with_exactly_its_edits() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let token = p.dev.token();
    let start = tip_for(&hub, &token, &p.name);
    const AGENTS: usize = 50;
    let landed: Vec<(String, u64)> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..AGENTS)
            .map(|i| {
                let (hub, token, name) = (&hub, &token, &p.name);
                s.spawn(move || {
                    let path = format!("src/agents/a{i:02}.txt");
                    // Every agent starts from the same base; a rejected one
                    // (moved more than 5 times) starts again from the tip.
                    let mut base = start;
                    for attempt in 0..40 {
                        let r = change(hub, token, name, &json!({"base": base.hex(), "description": format!("agent {i}"),
                            "edits": [put(&path, &format!("agent {i}\n"))], "onto": {"branch": "main", "expected": "rebase"}}));
                        assert_eq!(r.status, 200, "agent {i}: {}", String::from_utf8_lossy(&r.body));
                        let v = r.json();
                        if v["branch"]["status"] == "ok" {
                            return (path, attempt);
                        }
                        base = tip_for(hub, token, name);
                    }
                    panic!("agent {i} never landed");
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let retries: u64 = landed.iter().map(|(_, a)| a).sum();
    eprintln!("{AGENTS} agents landed through the API, {retries} client retries after 5 server rebases");
    // The admin's history: exactly one new snapshot per agent, each adding
    // exactly its own file to its parent.
    p.admin.ok(&p.dir, &["pull"]);
    let repo = veil_core::Repo::open(std::sync::Arc::new(veil_core::DiskBackend::new(&p.dir)), None, "test").unwrap();
    let store = repo.store();
    let mut cur = repo.view().tags["main"].target;
    let mut added = Vec::new();
    let admin_start = {
        // The admin's real snapshot behind the dev's start.
        let mut seen = 0;
        loop {
            let s = store.snapshot(&cur).unwrap();
            let parent = s.parents[0];
            let diff = veil_core::tree::diff_trees(store, Some(&store.snapshot(&parent).unwrap().tree), Some(&s.tree)).unwrap();
            if !s.author.contains(&p.dev.name) {
                break cur;
            }
            assert_eq!(diff.len(), 1, "a landed change's diff is exactly its edit: {diff:?}");
            added.push(diff[0].path.as_str().to_string());
            cur = parent;
            seen += 1;
            assert!(seen <= AGENTS, "more landings than agents");
        }
    };
    let _ = admin_start;
    added.sort();
    let mut want: Vec<String> = landed.iter().map(|(p, _)| p.clone()).collect();
    want.sort();
    assert_eq!(added, want, "every change landed exactly once");
    // Two changes of the same file from the same base: the second is not
    // applied over the first.
    let base = tip_for(&hub, &token, &p.name);
    let one = change(&hub, &token, &p.name, &json!({"base": base.hex(), "edits": [put("src/same.txt", "one")], "onto": {"branch": "main", "expected": "rebase"}}));
    assert_eq!(one.json()["branch"]["status"], "ok");
    let two = change(&hub, &token, &p.name, &json!({"base": base.hex(), "edits": [put("src/same.txt", "two")], "onto": {"branch": "main", "expected": "rebase"}}));
    let v = two.json();
    assert_eq!(v["branch"]["status"], "rejected", "{v}");
    assert!(v["branch"]["message"].as_str().unwrap().contains("changed there"), "{v}");
    // The rejected change is kept: its snapshot is a base like any other.
    let kept: ObjectId = serde_json::from_value(v["snapshot"].clone()).unwrap();
    let r = change(&hub, &token, &p.name, &json!({"base": kept.hex(), "edits": [put("src/kept.txt", "k")]}));
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
}

#[test]
fn expected_tips_and_revisions_of_a_change() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let token = p.dev.token();
    let base = tip_for(&hub, &token, &p.name);
    // Someone lands first: the dev's expected tip is stale.
    let r = change(&hub, &p.admin.token(), &p.name, &json!({"base": tip_for(&hub, &p.admin.token(), &p.name).hex(), "edits": [put("src/first.txt", "1")],
        "onto": {"branch": "main", "expected": "rebase"}}));
    assert_eq!(r.json()["branch"]["status"], "ok");
    let r = change(&hub, &token, &p.name, &json!({"base": base.hex(), "description": "v1", "edits": [put("src/mine.txt", "v1")],
        "onto": {"branch": "main", "expected": base.hex()}}));
    let v = r.json();
    assert_eq!(v["branch"]["status"], "rejected", "{v}");
    let cid = v["change_id"].as_str().unwrap().to_string();
    let v1: ObjectId = serde_json::from_value(v["snapshot"].clone()).unwrap();
    // A new revision of it, on the new tip, lands; it names v1 as its
    // predecessor.
    let now = tip_for(&hub, &token, &p.name);
    let r = change(&hub, &token, &p.name, &json!({"base": now.hex(), "change_id": cid, "description": "v2", "edits": [put("src/mine.txt", "v2")],
        "onto": {"branch": "main", "expected": now.hex()}}));
    let v = r.json();
    assert_eq!(v["branch"]["status"], "ok", "{v}");
    assert_eq!(v["change_id"].as_str().unwrap(), cid);
    let h = hub.api().post_json(Some(&token), &format!("/v1/projects/{}/history", p.name), &json!({"tips": [tip_for(&hub, &token, &p.name).hex()]}));
    let tip = tip_for(&hub, &token, &p.name);
    let (_, raw) = h.frames().into_iter().find(|(id, _)| *id == tip).unwrap();
    let O::Snapshot(s) = O::decode(&raw).unwrap() else { panic!() };
    assert_eq!(s.predecessors, vec![v1]);
    assert_eq!(s.change_id.to_string(), cid);
    // Nobody else revises the dev's change.
    let r = change(&hub, &p.admin.token(), &p.name, &json!({"base": tip_for(&hub, &p.admin.token(), &p.name).hex(), "change_id": cid, "edits": [put("src/mine.txt", "x")]}));
    assert_eq!(r.status, 404, "{}", String::from_utf8_lossy(&r.body));
}

#[test]
fn vl_change_new_seals_secrets_and_lands_without_a_checkout() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let scratch = p.admin.dir("edits");
    std::fs::create_dir_all(&scratch).unwrap();
    // From the admin's clone: the .env is sealed with the clone's key.
    let env = format!("{BILL_DIR}/.env");
    let mark = "MARKER-API-SECRET-c41e9a7d";
    let edits = scratch.join("e.json");
    std::fs::write(&edits, serde_json::to_vec(&json!([put(&env, &format!("KEY={mark}\n")), put("src/cli.rs", "fn cli() {}")])).unwrap()).unwrap();
    let out = p.admin.ok(&p.dir, &["change", "new", "--edits", edits.to_str().unwrap(), "-m", "rotate", "--onto", "main"]);
    assert!(out.contains("Moved main"), "{out}");
    // Finance opens it; the server never held it in the clear.
    let f = p.fin.dir(&unique("f"));
    p.fin.clone_trusting(&hub.url(&p.name), &f, &p.fp);
    assert_eq!(std::fs::read_to_string(f.join(&env)).unwrap(), format!("KEY={mark}\n"));
    let pid = project_id(&hub, &p.name);
    assert!(!stored(&hub, pid, &blob_id(&format!("KEY={mark}\n"))));
    // Without a clone: secrets cannot be sealed, so they are not sent;
    // a secret in an ordinary file is refused before it leaves the device.
    let elsewhere = p.dev.dir("nowhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    let e2 = elsewhere.join("e.json");
    std::fs::write(&e2, serde_json::to_vec(&json!([put("src/.env", "KEY=x\n")])).unwrap()).unwrap();
    let out = p.dev.fails(&elsewhere, &["change", "new", &hub.url(&p.name), "--edits", e2.to_str().unwrap()]);
    assert!(out.contains("stays on this device"), "{out}");
    std::fs::write(&e2, serde_json::to_vec(&json!([put("src/k.rs", "aws_access_key_id = AKIAQ7W3EXAMPLEZ4K2M\n")])).unwrap()).unwrap();
    let out = p.dev.fails(&elsewhere, &["change", "new", &hub.url(&p.name), "--edits", e2.to_str().unwrap()]);
    assert!(out.contains("looks like it holds a secret") && !out.contains("AKIAQ7W3EXAMPLEZ4K2M"), "{out}");
    // An ordinary change lands from anywhere, onto the current tip.
    std::fs::write(&e2, serde_json::to_vec(&json!([put("src/from-ci.rs", "fn ci() {}"), {"path": "src/cli.rs", "delete": true}])).unwrap()).unwrap();
    let out = p.dev.ok(&elsewhere, &["change", "new", &hub.url(&p.name), "--edits", e2.to_str().unwrap(), "-m", "ci", "--onto", "main"]);
    assert!(out.contains("Moved main"), "{out}");
    p.admin.ok(&p.dir, &["pull"]);
    p.admin.ok(&p.dir, &["new", "main"]);
    assert!(p.dir.join("src/from-ci.rs").exists() && !p.dir.join("src/cli.rs").exists());
    assert_eq!(std::fs::read_to_string(p.dir.join(&env)).unwrap(), format!("KEY={mark}\n"));
}

#[test]
#[ignore = "BUG-930: an uploaded object is stored before any check, so a refused plain-text secret stays in the object store"]
fn bug_930_a_refused_upload_leaves_no_plain_text_secret_stored() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let secret = "aws_access_key_id = AKIAR4T6EXAMPLEW8Y2Q\n";
    let mut c = Craft::new(&api, &p.dev, &p.name, "main");
    c.file("src/creds.txt", secret);
    let r = c.push("main", "a secret");
    assert_eq!(r.status, 403, "{}", String::from_utf8_lossy(&r.body));
    assert!(!stored(&hub, project_id(&hub, &p.name), &blob_id(secret)), "the refused secret is in the object store");
}

#[test]
fn bug_931_a_conflicts_terms_get_the_secret_checks() {
    use veil_core::object::{Conflict, ConflictTerm, EntryKind, Visibility};
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let before = tip_for(&hub, &p.dev.token(), &p.name);
    for (path, text) in [("src/.env", "KEY=plain\n"), ("src/creds.txt", "aws_access_key_id = AKIAR4T6EXAMPLEW8Y2Q\n")] {
        let mut c = Craft::new(&api, &p.dev, &p.name, "main");
        let term = |c: &mut Craft, t: &str| {
            let id = c.put(O::Blob(t.as_bytes().to_vec()));
            Some(ConflictTerm { kind: Default::default(), id, size: t.len() as u64, executable: false, visibility: Visibility::Public })
        };
        let (a, b, base) = (term(&mut c, text), term(&mut c, "other\n"), term(&mut c, "base\n"));
        c.set_kind(path, O::Conflict(Conflict { adds: vec![a, b], removes: vec![base] }), EntryKind::Conflict, Visibility::Public);
        let r = c.push("main", "a conflict");
        assert_eq!(r.status, 403, "{path}: {}", String::from_utf8_lossy(&r.body));
    }
    assert_eq!(tip_for(&hub, &p.dev.token(), &p.name), before);
}

/// A stack of the caller's own unlanded changes lands with `expected` after
/// a change they cannot see landed on main: their changes are made again on
/// the real tip, the hidden change is kept, and the caller sees their
/// changes with the ids they were given (BUG-1054).
#[test]
fn a_stack_lands_over_a_hidden_change_which_it_keeps_and_never_shows() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let token = p.dev.token();
    let main = tip_for(&hub, &token, &p.name);
    let r = change(&hub, &token, &p.name, &json!({"base": main.hex(), "description": "first", "edits": [put("src/first.txt", "1")]}));
    let x: ObjectId = serde_json::from_value(r.json()["snapshot"].clone()).unwrap();
    let hidden = "MARKER-HIDDEN-UNDER-STACK-71c2e9";
    write_files(&p.dir, &[(&format!("{BILL_DIR}/acme/invoice.txt"), hidden)]);
    p.admin.commit_main(&p.dir, "billing only");
    p.admin.ok(&p.dir, &["push"]);
    assert_eq!(tip_for(&hub, &token, &p.name), main);
    let r = change(&hub, &token, &p.name, &json!({"base": x.hex(), "description": "second", "edits": [put("src/second.txt", "2")],
        "onto": {"branch": "main", "expected": main.hex()}}));
    let v = r.json();
    assert_eq!(v["branch"]["status"], "ok", "{v}");
    // The dev's history: second, then first with the id they were given.
    let now = tip_for(&hub, &token, &p.name);
    let h = hub.api().post_json(Some(&token), &format!("/v1/projects/{}/history", p.name), &json!({"tips": [now.hex()], "stop": [main.hex()]}));
    let snaps: Vec<_> = h.frames();
    assert_eq!(snaps.len(), 2, "two changes above main");
    let (_, raw) = snaps.iter().find(|(id, _)| *id == now).unwrap();
    let O::Snapshot(top) = O::decode(raw).unwrap() else { panic!() };
    assert_eq!(top.parents, vec![x], "the first change keeps its id for the dev");
    assert_no_marker(&[("history".into(), h.body.clone())], &[hidden, "billing only"], &p.dev.name);
    // The full main keeps the hidden change and has both files.
    p.admin.ok(&p.dir, &["pull"]);
    p.admin.ok(&p.dir, &["new", "main"]);
    assert_eq!(std::fs::read_to_string(p.dir.join(format!("{BILL_DIR}/acme/invoice.txt"))).unwrap(), hidden);
    assert!(p.dir.join("src/first.txt").exists() && p.dir.join("src/second.txt").exists());
    // The real history: second, first (made again), then the hidden change.
    let repo = veil_core::Repo::open(std::sync::Arc::new(veil_core::DiskBackend::new(&p.dir)), None, "test").unwrap();
    let mut cur = repo.view().tags["main"].target;
    let mut seen = Vec::new();
    for _ in 0..3 {
        let s = repo.store().snapshot(&cur).unwrap();
        let veil_core::object::Text::Plain(d) = &s.description;
        seen.push(d.clone());
        cur = s.parents[0];
    }
    assert_eq!(seen, ["second", "first", "billing only"]);
}

/// A stack is made again on the tip only if the caller may still write
/// everything it changes (otherwise their view would drop an edit): a dev
/// whose write access to a folder was taken away cannot land an older
/// change of theirs there by stacking on it.
#[test]
fn a_stack_writing_where_its_author_lost_access_is_rejected() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let token = p.dev.token();
    let main = tip_for(&hub, &token, &p.name);
    let r = change(&hub, &token, &p.name, &json!({"base": main.hex(), "edits": [put("src/x.txt", "x")]}));
    let x: ObjectId = serde_json::from_value(r.json()["snapshot"].clone()).unwrap();
    // The admin keeps src/ public but lets devs write only src/y/.
    let policy = std::fs::read_to_string(p.dir.join(".veilpolicy")).unwrap();
    let edited: String = policy
        .lines()
        .map(|l| match l.split_whitespace().collect::<Vec<_>>()[..] {
            ["src/", "public", "devs"] => "src/ public\nsrc/y/ devs".to_string(),
            _ => l.to_string(),
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert_ne!(edited, policy.trim_end());
    let atok = p.admin.token();
    let abase = tip_for(&hub, &atok, &p.name);
    let r = change(&hub, &atok, &p.name, &json!({"base": abase.hex(), "edits": [put(".veilpolicy", &format!("{edited}\n"))], "onto": {"branch": "main", "expected": abase.hex()}}));
    assert_eq!(r.json()["branch"]["status"], "ok", "{}", String::from_utf8_lossy(&r.body));
    let now = tip_for(&hub, &token, &p.name);
    let r = change(&hub, &token, &p.name, &json!({"base": x.hex(), "edits": [put("src/y/new.txt", "y")], "onto": {"branch": "main", "expected": now.hex()}}));
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let v = r.json();
    assert_eq!(v["branch"]["status"], "rejected", "{v}");
    assert!(v["branch"]["message"].as_str().unwrap().contains("writes 'src/x.txt', which you may no longer write"), "{v}");
    assert_eq!(tip_for(&hub, &token, &p.name), now);
}

/// Format 8: only secret files are encrypted. A sealed object at a path
/// that is not a secret is refused, through the API and in a push.
#[test]
fn a_sealed_object_at_a_path_that_is_not_a_secret_is_refused() {
    use veil_core::{crypto::Envelope, object::Visibility};
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let token = p.dev.token();
    let base = tip_for(&hub, &token, &p.name);
    let env = Envelope::seal_random(&[7u8; 32], "team#k1", b"fn hidden() {}").unwrap();
    let raw = O::Sealed(env.clone()).encode();
    let id = ObjectId::hash(&raw);
    let up = api.upload(&token, &p.name, &[(id, raw)]);
    assert_eq!(up.status, 200, "{}", String::from_utf8_lossy(&up.body));
    let receipt = up.json()["receipts"][0].as_str().unwrap().to_string();
    let r = change(&hub, &token, &p.name, &json!({"base": base.hex(), "edits": [{"path": "src/code.rs", "put": {"object": id.hex()}}],
        "receipts": {id.hex(): receipt}}));
    assert_eq!(r.status, 403, "{}", String::from_utf8_lossy(&r.body));
    assert!(String::from_utf8_lossy(&r.body).contains("only secret files are encrypted"));
    let mut c = Craft::new(&api, &p.dev, &p.name, "main");
    c.set("src/code.rs", O::Sealed(env), Visibility::Cloaked { scope: "team".into() });
    let r = c.push("main", "sealed code");
    assert_eq!(r.status, 403, "{}", String::from_utf8_lossy(&r.body));
    assert!(String::from_utf8_lossy(&r.body).contains("only secret files are encrypted"));
    assert_eq!(tip_for(&hub, &token, &p.name), base);
}
