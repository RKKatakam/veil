//! Many pushers at once on one project (brief S1 §4): every branch move is
//! one compare-and-swap row, so no update is lost and exactly one of
//! several racing creations wins. Run under load by
//! `scripts/verify-server.sh` (several copies of this binary at once).

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use serde_json::json;
use veil_core::{object::Object, Identity, ObjectId};

use crate::support::*;

const WORKERS: usize = 12;
const PUSHES: usize = 6;

struct Worker {
    name: String,
    identity: Identity,
    token: String,
}

/// A project where each worker may write `w/` (group `w`).
fn workers_project(hub: &TestHub) -> (Project, Vec<Worker>) {
    let p = setup_project(hub);
    let api = hub.api();
    let mut ws = Vec::new();
    for i in 0..WORKERS {
        let identity = Identity::generate(&format!("w{i}"));
        let name = unique("worker");
        let token = api.login(&identity, Some(&name)).unwrap();
        ws.push(Worker { name, identity, token });
    }
    p.admin.ok(&p.dir, &["group", "create", "w"]);
    let mut args = vec!["group", "add", "w"];
    args.extend(ws.iter().map(|w| w.name.as_str()));
    p.admin.ok(&p.dir, &args);
    p.admin.ok(&p.dir, &["new", "main"]);
    p.admin.ok(&p.dir, &["access", "w/", "w"]);
    write_files(&p.dir, &[("w/README", "workers")]);
    p.admin.commit_main(&p.dir, "workers' folder");
    p.admin.ok(&p.dir, &["push"]);
    (p, ws)
}

#[test]
fn concurrent_pushers_lose_no_update() {
    let hub = TestHub::start();
    let (p, ws) = workers_project(&hub);
    let api = Arc::new(hub.api());
    let rejected = Arc::new(AtomicUsize::new(0));
    std::thread::scope(|s| {
        for (i, w) in ws.iter().enumerate() {
            let api = api.clone();
            let rejected = rejected.clone();
            let project = p.name.clone();
            s.spawn(move || {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(240);
                for k in 0..PUSHES {
                    loop {
                        assert!(std::time::Instant::now() < deadline, "worker {i} made no progress for 4 minutes (push {k})");
                        let mut c = Craft::with(&api, w.token.clone(), w.identity.clone(), &project, "main");
                        c.file(&format!("w/{i}/{k}"), &format!("worker {i} push {k}"));
                        let r = c.push("main", &format!("w{i}-{k}"));
                        let ok = r.status == 200 && r.json()["results"][0]["ok"] == json!(true);
                        if ok {
                            break;
                        }
                        // 409: the branch moved; 503: the database was busy. Both: again.
                        assert!(matches!(r.status, 200 | 409 | 503), "{}: {}", r.status, String::from_utf8_lossy(&r.body));
                        rejected.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });
        }
    });
    // Every push landed, in one linear history, and every file is there.
    p.admin.ok(&p.dir, &["pull"]);
    let repo = veil_core::Repo::open(Arc::new(veil_core::DiskBackend::new(&p.dir)), None, "test").unwrap();
    let mut id = repo.view().tags["main"].target;
    let mut descs = Vec::new();
    loop {
        let s = repo.snapshot(&id).unwrap();
        let t = s.description.as_str();
        if t.starts_with('w') && t.contains('-') {
            descs.push(t.to_string());
        }
        assert!(s.parents.len() <= 1, "a fast-forward-only branch has no merges");
        match s.parents.first() {
            Some(p) => id = *p,
            None => break,
        }
    }
    descs.sort();
    descs.dedup();
    assert_eq!(descs.len(), WORKERS * PUSHES, "lost updates: {descs:?}");
    let real = real_paths(&p.dir);
    for i in 0..WORKERS {
        for k in 0..PUSHES {
            assert!(real.iter().any(|(path, _)| *path == format!("w/{i}/{k}")), "w/{i}/{k} lost");
        }
    }
    // What the workers could not see survived every one of their pushes.
    for want in [ROOT_FILE, &format!("{BILL_DIR}/acme/invoice.txt") as &str, &format!("src/{NESTED_DIR}/key.txt")] {
        assert!(real.iter().any(|(path, _)| path == want), "{want} lost");
    }
    eprintln!("{} pushes landed; {} compare-and-swap rejections retried", WORKERS * PUSHES, rejected.load(Ordering::Relaxed));
}

#[test]
fn racing_branch_creations_and_separate_branches() {
    let hub = TestHub::start();
    let (p, ws) = workers_project(&hub);
    let api = Arc::new(hub.api());
    let race = unique("race");
    let winners = Arc::new(AtomicUsize::new(0));
    std::thread::scope(|s| {
        for (i, w) in ws.iter().enumerate() {
            let (api, winners, race, project) = (api.clone(), winners.clone(), race.clone(), p.name.clone());
            s.spawn(move || {
                // Everyone creates the same branch at once: one wins.
                let mut c = Craft::with(&api, w.token.clone(), w.identity.clone(), &project, "main");
                c.file(&format!("w/{i}/race"), "x");
                let tip_before = c.tip;
                let r = c.push_to(&race, None);
                if r.status == 200 && r.json()["results"][0]["ok"] == json!(true) {
                    winners.fetch_add(1, Ordering::Relaxed);
                }
                // Each on their own branch: no one waits for anyone.
                let mine = format!("{race}-{i}");
                let mut expected: Option<ObjectId> = None;
                for k in 0..PUSHES {
                    let mut c = Craft::with(&api, w.token.clone(), w.identity.clone(), &project, "main");
                    if let Some(e) = expected {
                        c.tip = e;
                        c.root = c.tree_of(e);
                    } else {
                        assert_eq!(c.tip, tip_before);
                    }
                    c.file(&format!("w/{i}/own{k}"), "y");
                    let r = c.push_to(&mine, expected);
                    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
                    let res = &r.json()["results"][0];
                    assert_eq!(res["ok"], json!(true), "{res}");
                    expected = Some(ObjectId::from_hex(res["tip"].as_str().unwrap()).unwrap());
                }
            });
        }
    });
    assert_eq!(winners.load(Ordering::Relaxed), 1, "exactly one creation wins");
    let tips = api.tips(Some(&p.admin.token()), &p.name).unwrap();
    for i in 0..WORKERS {
        assert!(tips.branches.contains_key(&format!("{race}-{i}")));
    }
    let _ = Object::Blob(vec![]);
}

/// Members' devices share keys while an admin removes the person they share
/// with (HUB.md §13.12, threat 13): every ring change is decided on the
/// server's latest ring, so once the removal lands no device of the person
/// is in the ring, and no later pass brings one back. The person keeps
/// confirming new devices during the removal, so shares race it.
#[test]
fn shares_racing_a_removal_never_keep_a_removed_device() {
    use crate::secrets2::{bill_scope, clone, invited, member_of, named, ring};
    use std::sync::atomic::AtomicBool;
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let f = clone(&hub, &p, &p.fin, "f");
    // More finance members whose devices hold the key.
    let mut sharers = vec![(&p.fin, f.clone())];
    let extra: Vec<Person> = (0..2).map(|i| invited(&hub, &p, &format!("m{i}-")).0).collect();
    p.fin.ok(&f, &["share-keys"]);
    for (i, m) in extra.iter().enumerate() {
        assert!(member_of(&ring(&hub, &p, &bill_scope()).1, &m.identity()));
        sharers.push((m, clone(&hub, &p, m, &format!("c{i}"))));
    }
    let mut raced = 0;
    for round in 0..3 {
        let (newbie, _) = invited(&hub, &p, &format!("newbie{round}-"));
        p.fin.ok(&f, &["share-keys"]);
        assert!(member_of(&ring(&hub, &p, &bill_scope()).1, &newbie.identity()));
        let before = ring(&hub, &p, &bill_scope()).0.log.len();
        let done = AtomicBool::new(false);
        let removing = AtomicBool::new(false);
        let confirm_one = || {
            let d = hub.new_device_of(&newbie);
            newbie.ok(newbie.home.path(), &["identity", "confirm", &d.fingerprint()]);
            d
        };
        std::thread::scope(|s| {
            for (who, dir) in &sharers {
                let (dir, done) = (dir.clone(), &done);
                s.spawn(move || {
                    while !done.load(Ordering::SeqCst) {
                        // A pass may lose every race and give up: that is
                        // allowed; leaving a removed device in is not.
                        let o = who.run(&dir, &["share-keys"]);
                        if !o.status.success() {
                            println!("a pass gave up: {}", String::from_utf8_lossy(&o.stderr).trim());
                        }
                    }
                });
            }
            let first = confirm_one();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
            while !member_of(&ring(&hub, &p, &bill_scope()).1, &first.identity()) {
                assert!(std::time::Instant::now() < deadline, "round {round}: no pass shared the first device");
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            let removal = s.spawn(|| {
                removing.store(true, Ordering::SeqCst);
                p.admin.ok(&p.dir, &["group", "remove", "finance", &newbie.name]);
            });
            // More devices while the removal runs.
            while !removing.load(Ordering::SeqCst) {
                std::thread::yield_now();
            }
            for _ in 0..2 {
                confirm_one();
            }
            removal.join().unwrap();
            // Sharers keep passing a little after the removal.
            std::thread::sleep(std::time::Duration::from_secs(2));
            done.store(true, Ordering::SeqCst);
        });
        let (r, st) = ring(&hub, &p, &bill_scope());
        let shares = r.log[before..]
            .iter()
            .filter(|c| matches!(&c.op, veil_core::keychain::RingOp::Share { member, .. } if member.name == newbie.name))
            .count();
        raced += shares;
        println!("round {round}: {shares} share(s) to newbie's devices around the removal; ring of {} changes, generation {}", st.len, st.generation);
        assert_eq!(named(&st, &newbie.name), 0, "round {round}: a removed person's device kept the key");
        for (who, dir) in &sharers {
            who.ok(dir, &["share-keys"]);
        }
        let st = ring(&hub, &p, &bill_scope()).1;
        assert_eq!(named(&st, &newbie.name), 0, "round {round}: a pass gave a removed person a key back");
    }
    assert!(raced > 0, "no share raced the removal: the test proved nothing");
}

/// BUG-847. New people signing up at once: on YugabyteDB, sign-in's
/// SERIALIZABLE transaction found no device by its key and no person by the
/// name, and each such read locked its whole table (`devices`, `people`), so
/// concurrent sign-ups deadlocked and, under load, some ran past the 45 s
/// deadline ("the database is busy"). Every sign-up must succeed, whatever
/// else signs up meanwhile, and a name raced for goes to one person: the
/// other sign-ups under it wait as pending devices.
#[test]
fn bug_847_concurrent_sign_ups_all_succeed() {
    let hub = TestHub::start();
    let failed = AtomicUsize::new(0);
    std::thread::scope(|s| {
        for _ in 0..48 {
            s.spawn(|| {
                let api = hub.api();
                for _ in 0..4 {
                    if api.login(&Identity::generate("x"), Some(&unique("signup"))).is_err() {
                        failed.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });
        }
    });
    assert_eq!(failed.load(Ordering::Relaxed), 0, "sign-ups failed");
    // One name raced for by several new devices: one signs up, the others
    // are its pending devices.
    let name = unique("raced");
    let (signed, pending) = (AtomicUsize::new(0), AtomicUsize::new(0));
    std::thread::scope(|s| {
        for _ in 0..8 {
            s.spawn(|| match hub.api().login(&Identity::generate("x"), Some(&name)) {
                Ok(_) => signed.fetch_add(1, Ordering::Relaxed),
                Err(r) => {
                    assert!(String::from_utf8_lossy(&r.body).contains("device_pending"), "{r:?}");
                    pending.fetch_add(1, Ordering::Relaxed)
                }
            });
        }
    });
    assert_eq!((signed.load(Ordering::Relaxed), pending.load(Ordering::Relaxed)), (1, 7));
}

/// BUG-1593: the cost gate "1 database commit per landing"
/// (`docs/design/server/storage-and-cost.md` §9, S4) is missed on
/// `integration` `ae3d57ed`: `scripts/bench-server.sh load` measures 9 to
/// 13 commits per landing at 1 agent (about 1.5 at 100), on every landing
/// route (`land`, `branches`, `api`). Found by the deployment kit's
/// rehearsal, 2026-11-09, then confirmed by the canonical benchmark. This
/// counts the transactions that committed while one person lands 40
/// changes in turn, and allows one more per landing for the deriver's
/// background write (the benchmark subtracts those exactly, through
/// `pg_stat_statements`, which the shared test database lacks). Run alone:
/// transaction ids are counted for the whole database server.
#[test]
fn bug_1593_a_landing_is_one_database_commit() {
    const LANDINGS: usize = 40;
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let h = hub.hub();
    p.admin.ok(&p.dir, &["new", "main"]);
    write_files(&p.dir, &[("doc/0.txt", "0")]);
    p.admin.commit_main(&p.dir, "first");
    p.admin.ok(&p.dir, &["push"]);
    if hub.rt.block_on(sqlx::query("SELECT xmin FROM projects LIMIT 1").execute(&h.db)).is_err() {
        for i in 1..=LANDINGS {
            write_files(&p.dir, &[("doc/0.txt", &i.to_string())]);
            p.admin.commit_main(&p.dir, &format!("landing {i}"));
            p.admin.ok(&p.dir, &["push"]);
        }
        return;
    }
    let pid: i64 = hub
        .rt
        .block_on(sqlx::query_scalar("SELECT id FROM projects WHERE name = $1").bind(&p.name).fetch_one(&h.db))
        .unwrap();
    let xmax = || {
        hub.rt
            .block_on(sqlx::query_scalar::<_, i64>("SELECT pg_snapshot_xmax(pg_current_snapshot())::text::bigint").fetch_one(&h.db))
            .unwrap()
    };
    let sample = |xids: &mut std::collections::BTreeSet<i64>, from: i64| {
        let rows: Vec<i64> = hub
            .rt
            .block_on(
                sqlx::query_scalar(
                    "SELECT DISTINCT x FROM ( \
                        SELECT xmin::text::bigint AS x FROM branches WHERE project_id = $1 \
                        UNION ALL SELECT xmin::text::bigint FROM snapshots WHERE project_id = $1 \
                        UNION ALL SELECT xmin::text::bigint FROM origins WHERE project_id = $1 \
                        UNION ALL SELECT xmin::text::bigint FROM audit_log WHERE project_id = $1 \
                        UNION ALL SELECT xmin::text::bigint FROM change_refs WHERE project_id = $1 \
                        UNION ALL SELECT xmin::text::bigint FROM projections WHERE project_id = $1 \
                        UNION ALL SELECT xmin::text::bigint FROM graph WHERE project_id = $1 \
                        UNION ALL SELECT xmin::text::bigint FROM file_history WHERE project_id = $1 \
                        UNION ALL SELECT xmin::text::bigint FROM rule_history WHERE project_id = $1 \
                        UNION ALL SELECT xmin::text::bigint FROM rule_lines WHERE project_id = $1 \
                        UNION ALL SELECT xmin::text::bigint FROM derive_progress WHERE project_id = $1 \
                        UNION ALL SELECT xmin::text::bigint FROM view_file_history WHERE project_id = $1 \
                        UNION ALL SELECT xmin::text::bigint FROM view_graph WHERE project_id = $1 \
                        UNION ALL SELECT xmin::text::bigint FROM view_fills WHERE project_id = $1 \
                        UNION ALL SELECT xmin::text::bigint FROM view_changes WHERE project_id = $1 \
                        UNION ALL SELECT xmin::text::bigint FROM view_access WHERE project_id = $1 \
                        UNION ALL SELECT xmin::text::bigint FROM search_heads WHERE project_id = $1 \
                        UNION ALL SELECT xmin::text::bigint FROM search_shards WHERE project_id = $1 \
                        UNION ALL SELECT xmin::text::bigint FROM landing_queue WHERE project_id = $1 \
                        UNION ALL SELECT xmin::text::bigint FROM landing_leases WHERE project_id = $1 \
                        UNION ALL SELECT xmin::text::bigint FROM landings WHERE project_id = $1 \
                        UNION ALL SELECT xmin::text::bigint FROM landed_from WHERE project_id = $1 \
                        UNION ALL SELECT xmin::text::bigint FROM landed_changes WHERE project_id = $1 \
                        UNION ALL SELECT xmin::text::bigint FROM access_epochs WHERE project_id = $1 \
                    ) t WHERE x >= $2",
                )
                .bind(pid)
                .bind(from)
                .fetch_all(&h.db),
            )
            .unwrap();
        xids.extend(rows);
    };
    std::thread::sleep(std::time::Duration::from_secs(2)); // the first landing's background work
    let from = xmax();
    let mut xids = std::collections::BTreeSet::new();
    for i in 1..=LANDINGS {
        write_files(&p.dir, &[("doc/0.txt", &i.to_string())]);
        p.admin.commit_main(&p.dir, &format!("landing {i}"));
        p.admin.ok(&p.dir, &["push"]);
        sample(&mut xids, from);
    }
    std::thread::sleep(std::time::Duration::from_secs(2)); // let the deriver finish
    sample(&mut xids, from);
    let committed = xids.len() as i64;
    let per_landing = committed as f64 / LANDINGS as f64;
    // 1 for the landing, at most 1 for the deriver, and a few for the
    // database's own maintenance.
    assert!(committed <= (2 * LANDINGS + 20) as i64, "{committed} transactions committed for {LANDINGS} landings ({per_landing:.2} per landing; the gate is 1, the deriver's aside)");
}

/// The person id of `name`.
fn person_id(hub: &TestHub, name: &str) -> i64 {
    hub.rt
        .block_on(sqlx::query_scalar("SELECT id FROM people WHERE name = $1").bind(name).fetch_one(&hub.hub().db))
        .unwrap()
}

/// The push's rows are written in one statement of its transaction (its
/// snapshot, origin, the pusher's memo and its audit row; the tips notice
/// follows the commit, BUG-2459)
/// and its packs listed in one (`packs::` races those with discards):
/// under pushes racing on one branch and on branches of their own, every
/// push that landed wrote exactly its rows, and one that lost wrote none.
#[test]
fn racing_pushes_write_exactly_the_rows_of_those_that_landed() {
    let hub = TestHub::start();
    let (p, ws) = workers_project(&hub);
    let api = Arc::new(hub.api());
    // (worker, the tip shown back) of every push that landed.
    let landed = Arc::new(std::sync::Mutex::new(Vec::<(usize, ObjectId)>::new()));
    std::thread::scope(|s| {
        for (i, w) in ws.iter().enumerate() {
            let (api, landed, project) = (api.clone(), landed.clone(), p.name.clone());
            s.spawn(move || {
                let mine = format!("own-{i}");
                let mut expected: Option<ObjectId> = None;
                for k in 0..PUSHES {
                    // Its own branch: never raced, always lands.
                    let mut c = Craft::with(&api, w.token.clone(), w.identity.clone(), &project, "main");
                    if let Some(e) = expected {
                        c.tip = e;
                        c.root = c.tree_of(e);
                    }
                    c.file(&format!("w/{i}/own{k}"), "mine");
                    let r = c.push_to(&mine, expected);
                    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
                    let res = &r.json()["results"][0];
                    assert_eq!(res["ok"], json!(true), "{res}");
                    let tip = ObjectId::from_hex(res["tip"].as_str().unwrap()).unwrap();
                    landed.lock().unwrap().push((i, tip));
                    expected = Some(tip);
                    // `main`, raced by everyone: once each, lands or loses.
                    let mut c = Craft::with(&api, w.token.clone(), w.identity.clone(), &project, "main");
                    c.file(&format!("w/{i}/main{k}"), "shared");
                    let r = c.push("main", &format!("w{i}-{k}"));
                    assert!(matches!(r.status, 200 | 409 | 503), "{}: {}", r.status, String::from_utf8_lossy(&r.body));
                    if r.status == 200 && r.json()["results"][0]["ok"] == json!(true) {
                        let tip = ObjectId::from_hex(r.json()["results"][0]["tip"].as_str().unwrap()).unwrap();
                        landed.lock().unwrap().push((i, tip));
                    }
                }
            });
        }
    });
    let landed = landed.lock().unwrap().clone();
    assert!(landed.len() > WORKERS * PUSHES, "every own-branch push and at least one push to main landed: {}", landed.len());
    let h = hub.hub();
    let pid: i64 = hub.rt.block_on(sqlx::query_scalar("SELECT id FROM projects WHERE name = $1").bind(&p.name).fetch_one(&h.db)).unwrap();
    let mut audit_want: std::collections::HashMap<i64, i64> = std::collections::HashMap::new();
    for (i, shown) in &landed {
        let person = person_id(&hub, &ws[*i].name);
        *audit_want.entry(person).or_default() += 1;
        // The worker cannot see everything: the server completed their
        // snapshot (a real one, its origin theirs) and showed them their own.
        let reals: Vec<String> = hub
            .rt
            .block_on(sqlx::query_scalar("SELECT real_id FROM origins WHERE project_id = $1 AND origin_id = $2").bind(pid).bind(shown.hex()).fetch_all(&h.db))
            .unwrap();
        assert_eq!(reals.len(), 1, "one completed snapshot of {}", shown.short());
        let author: i64 = hub
            .rt
            .block_on(sqlx::query_scalar("SELECT author FROM snapshots WHERE project_id = $1 AND id = $2").bind(pid).bind(&reals[0]).fetch_one(&h.db))
            .unwrap();
        assert_eq!(author, person, "the snapshot's author is its pusher");
        let memos: Vec<String> = hub
            .rt
            .block_on(
                sqlx::query_scalar("SELECT projected_id FROM projections WHERE project_id = $1 AND real_id = $2 AND view_key <> 'admin'")
                    .bind(pid)
                    .bind(&reals[0])
                    .fetch_all(&h.db),
            )
            .unwrap();
        assert!(memos.contains(&shown.hex()), "the pusher's memo of {} is their own snapshot: {memos:?}", shown.short());
    }
    for (person, want) in audit_want {
        let n: i64 = hub
            .rt
            .block_on(
                sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE project_id = $1 AND actor = $2 AND action = 'push'")
                    .bind(pid)
                    .bind(person)
                    .fetch_one(&h.db),
            )
            .unwrap();
        assert_eq!(n, want, "one audit row for each push of person {person} that landed, none for one that lost");
    }
}

/// A push and an admin's deletion of the same branch, both on its tip, at
/// once, round after round: exactly one of them wins each time, and the
/// branch is then where the winner left it.
#[test]
fn a_push_racing_a_branch_deletion_one_wins() {
    const ROUNDS: usize = 8;
    let hub = TestHub::start();
    let (p, ws) = workers_project(&hub);
    let api = hub.api();
    let w = &ws[0];
    let branch = unique("doomed");
    let admin_token = p.admin.token();
    let push_path = format!("/v1/projects/{}/push", p.name);
    for round in 0..ROUNDS {
        // The branch, (re)made by the worker on main.
        let mut c = Craft::with(&api, w.token.clone(), w.identity.clone(), &p.name, "main");
        c.file(&format!("w/0/r{round}"), "x");
        let r = c.push_to(&branch, None);
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        assert_eq!(r.json()["results"][0]["ok"], json!(true), "{}", r.json());
        let shown = ObjectId::from_hex(r.json()["results"][0]["tip"].as_str().unwrap()).unwrap();
        let real = api.tips(Some(&admin_token), &p.name).unwrap().branches[&branch];
        // The worker's next push on it, crafted before the race.
        let mut next = Craft::with(&api, w.token.clone(), w.identity.clone(), &p.name, "main");
        next.tip = shown;
        next.root = next.tree_of(shown);
        next.file(&format!("w/0/r{round}b"), "y");
        let barrier = std::sync::Barrier::new(2);
        let (pushed, deleted) = std::thread::scope(|s| {
            let pushed = s.spawn(|| {
                barrier.wait();
                next.push_to(&branch, Some(shown))
            });
            let deleted = s.spawn(|| {
                barrier.wait();
                api.post_json(Some(&admin_token), &push_path, &json!({"updates": [{"branch": branch, "expected": real.hex(), "new": null}], "receipts": {}}))
            });
            (pushed.join().unwrap(), deleted.join().unwrap())
        });
        let won = |r: &Reply| r.status == 200 && r.json()["results"][0]["ok"] == json!(true);
        for r in [&pushed, &deleted] {
            assert!(matches!(r.status, 200 | 409 | 503), "{}: {}", r.status, String::from_utf8_lossy(&r.body));
        }
        let tips = api.tips(Some(&admin_token), &p.name).unwrap();
        match (won(&pushed), won(&deleted)) {
            (true, false) => {
                let tip = tips.branches.get(&branch).copied();
                assert!(tip.is_some() && tip != Some(real), "round {round}: the push won and the branch moved");
                // Gone for the next round.
                let r = api.post_json(Some(&admin_token), &push_path, &json!({"updates": [{"branch": branch, "expected": tip.unwrap().hex(), "new": null}], "receipts": {}}));
                assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
                assert_eq!(r.json()["results"][0]["ok"], json!(true), "{}", r.json());
            }
            (false, true) => assert!(!tips.branches.contains_key(&branch), "round {round}: the deletion won and the branch is gone"),
            other => panic!("round {round}: exactly one wins, not {other:?}: push {} {}, delete {} {}", pushed.status, String::from_utf8_lossy(&pushed.body), deleted.status, String::from_utf8_lossy(&deleted.body)),
        }
    }
}

/// Pushes racing an admin's removal of the pushers from the group that
/// may write `w/`: each push is either landed or refused, a push that began
/// after the removal was in never lands, and one does get refused.
#[test]
fn pushes_racing_an_access_change_land_only_before_it() {
    const PUSHERS: usize = 4;
    let hub = TestHub::start();
    let (p, ws) = workers_project(&hub);
    let api = hub.api();
    // Each pusher's first push, crafted while they may read (each next one
    // carries the trees its last one made, so it reads nothing).
    let crafts: Vec<Craft> = ws
        .iter()
        .take(PUSHERS)
        .enumerate()
        .map(|(i, w)| {
            let mut c = Craft::with(&api, w.token.clone(), w.identity.clone(), &p.name, "main");
            c.file(&format!("w/{i}/acc0"), "z");
            c
        })
        .collect();
    let landed_once = AtomicUsize::new(0);
    let removed_at = std::sync::Mutex::new(None::<std::time::Instant>);
    let results = std::sync::Mutex::new(Vec::<(std::time::Instant, bool)>::new());
    std::thread::scope(|s| {
        for (i, (w, mut c)) in ws.iter().zip(crafts).enumerate() {
            let (api, results, removed_at, landed_once) = (&api, &results, &removed_at, &landed_once);
            let project = p.name.clone();
            s.spawn(move || {
                let mine = format!("acc-{i}");
                let mut expected: Option<ObjectId> = None;
                for k in 1.. {
                    let (root, objects) = (c.root, c.objects.clone());
                    let started = std::time::Instant::now();
                    // Landed, or refused at the upload or at the push, either
                    // way by the participant check: out of every group, they
                    // still see the public `src/`, so the project is found and
                    // they are told they are not in it.
                    let (r, _at_upload) = c.try_push_to(&mine, expected);
                    let ok = r.status == 200 && r.json()["results"][0]["ok"] == json!(true);
                    if !ok {
                        assert_eq!(r.status, 403, "pusher {i}: landed or refused, not: {}", String::from_utf8_lossy(&r.body));
                        assert_eq!(
                            r.json(),
                            json!({"code": "forbidden", "message": "you are not in this project"}),
                            "pusher {i}: refused by the participant check (at the upload: {_at_upload})"
                        );
                    }
                    results.lock().unwrap().push((started, ok));
                    if !ok {
                        break;
                    }
                    if k == 1 {
                        landed_once.fetch_add(1, Ordering::SeqCst);
                    }
                    let tip = ObjectId::from_hex(r.json()["results"][0]["tip"].as_str().unwrap()).unwrap();
                    expected = Some(tip);
                    c = Craft { api, token: w.token.clone(), identity: w.identity.clone(), project: project.clone(), tip, root, objects };
                    c.file(&format!("w/{i}/acc{k}"), "z");
                    let late = removed_at.lock().unwrap().is_some_and(|t: std::time::Instant| t.elapsed() > std::time::Duration::from_secs(10));
                    assert!(!late, "pusher {i} still landing 10 s after the removal");
                }
            });
        }
        // Every pusher landed once; then the removal, while they push.
        let until = std::time::Instant::now() + std::time::Duration::from_secs(120);
        while landed_once.load(Ordering::SeqCst) < PUSHERS {
            assert!(std::time::Instant::now() < until, "every pusher lands a first push");
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let mut args = vec!["group", "remove", "w"];
        args.extend(ws.iter().take(PUSHERS).map(|w| w.name.as_str()));
        p.admin.ok(&p.dir, &args);
        *removed_at.lock().unwrap() = Some(std::time::Instant::now());
    });
    let removed_at = removed_at.lock().unwrap().unwrap();
    let results = results.lock().unwrap();
    assert!(results.iter().filter(|(started, ok)| *ok && *started < removed_at).count() >= PUSHERS, "every pusher landed before the removal");
    assert_eq!(results.iter().filter(|(_, ok)| !*ok).count(), PUSHERS, "the removal refused each pusher");
    for (started, ok) in results.iter() {
        assert!(!(*ok && *started > removed_at), "a push that began after the removal was in landed");
    }
}
