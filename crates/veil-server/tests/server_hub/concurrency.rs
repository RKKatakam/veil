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
                for k in 0..PUSHES {
                    let mut tries = 0;
                    loop {
                        tries += 1;
                        assert!(tries < 400, "worker {i} starved");
                        let mut c = Craft::with(&api, w.token.clone(), w.identity.clone(), &project, "main");
                        c.file(&format!("w/{i}/{k}"), &format!("worker {i} push {k}"));
                        let r = c.push("main", &format!("w{i}-{k}"));
                        let ok = r.status == 200 && r.json()["results"][0]["ok"] == json!(true);
                        if ok {
                            break;
                        }
                        assert!(r.status == 200 || r.status == 409, "{}: {}", r.status, String::from_utf8_lossy(&r.body));
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
        let s = repo.store().snapshot(&id).unwrap();
        if let veil_core::object::Text::Plain(t) = &s.description {
            if t.starts_with('w') && t.contains('-') {
                descs.push(t.clone());
            }
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
