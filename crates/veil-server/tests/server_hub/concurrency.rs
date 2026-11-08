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
