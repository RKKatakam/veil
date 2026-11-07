//! Adversarial pass on S4, request-path caches and one commit per push
//! (`docs/HUB.md` §13.14). The attackers: anyone who signs up (and so may
//! create projects, groups and branches of their own), and a member whose
//! access was narrowed. Findings are in `docs/BUGS.md`, "Adversarial pass:
//! S4".

use std::time::Instant;

use serde_json::json;
use veil_core::{
    hub::access::AccessPolicy,
    object::{Object as O, Snapshot, Text},
    ObjectId,
};
use veil_server::{
    auth::Person as Who,
    caches::{project_bytes, Caches, ProjectEntry, TipsLookup, ViewerEntry, TIPS_TTL},
    perm::{Project as Proj, Viewer},
};

use crate::support::*;

/// This process's resident memory, in bytes.
fn rss() -> usize {
    let statm = std::fs::read_to_string("/proc/self/statm").unwrap();
    let pages: usize = statm.split_whitespace().nth(1).unwrap().parse().unwrap();
    pages * 4096
}

const MIB: usize = 1 << 20;

/// BUG-913: every cache is bounded by its entries' count, and only the
/// projects cache by bytes (and that one counts a parsed policy at a fraction
/// of what it takes). What someone puts in an entry is theirs to size:
/// anyone who signs up can create projects, push any number of branches in
/// one push (64 MiB of JSON) and create any number of groups and join them.
/// So a server's memory grows with what they wrote, and is kept: tip rows
/// stay after they expire, until the same project is read again.
///
/// Fixed: every entry is weighed by what it holds, each cache has a byte
/// budget, and expired tip rows are freed. It measures memory, so it runs
/// in a process of its own (other tests beside it count for nothing).
#[test]
fn bug_913_caches_are_bounded_by_bytes_not_by_what_an_attacker_writes() {
    const CHILD: &str = "VEIL_BUG913_CHILD";
    if std::env::var(CHILD).is_err() {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "adversarial_s4::bug_913_caches_are_bounded_by_bytes_not_by_what_an_attacker_writes", "--nocapture", "--test-threads=1"])
            .env(CHILD, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success() && stdout.contains("1 passed"), "{stdout}{}", String::from_utf8_lossy(&out.stderr));
        return;
    }
    let c = Caches::default();
    let mut failures = Vec::new();

    // 1. Tips: 100 projects of 10,000 branches each with 100-byte names (a
    //    push of about 1.6 MB of JSON per project), read once each.
    let before = rss();
    for p in 1..=100i64 {
        let TipsLookup::Read(read) = c.tips(p) else { panic!("a first read") };
        let rows: Vec<(String, String)> = (0..10_000u32).map(|i| (format!("{i:0>100}"), ObjectId::hash(&i.to_le_bytes()).hex())).collect();
        c.put_tips(p, read, Instant::now(), rows);
    }
    std::thread::sleep(TIPS_TTL * 3);
    let tips = rss().saturating_sub(before);
    // Expired, but still held: nothing frees them until the project is read again.
    if tips > 64 * MIB {
        failures.push(format!("expired branch tips of 100 projects keep {} MiB", tips / MIB));
    }

    // 2. Permissions: 50 entries (50 of the attacker's projects, or devices)
    //    of a person in 250,000 groups each, each counted as 1 of 100,000.
    let before = rss();
    for p in 1..=50i64 {
        let who = Who {
            id: 7,
            name: "attacker".into(),
            device_key: format!("{p:064x}"),
        };
        let viewer = Viewer {
            person: Some(7),
            admin: false,
            groups: (0..250_000).collect(),
        };
        c.put_viewer(
            p,
            &who,
            ViewerEntry {
                viewer,
                barred: false,
                project_epoch: 1,
                person_epoch: 1,
            },
        );
    }
    let viewers = rss().saturating_sub(before);
    if viewers > 64 * MIB {
        failures.push(format!("50 permission entries (of 100,000 allowed) keep {} MiB", viewers / MIB));
    }

    // 3. Projects: one accepted policy of 1 MiB of five-byte lines (about
    //    200,000 rules). Its entry must weigh at least half of what it holds
    //    (`caches::project_bytes`, against the cache's byte budget).
    let text: String = "a/ x\n".repeat(MIB / 5);
    let before = rss();
    let policy = AccessPolicy::parse(&text);
    let project = Proj {
        id: 1,
        name: "p".into(),
        default_branch: "main".into(),
        policy,
        policy_text: text,
        bindings: Default::default(),
    };
    let weight = project_bytes(&project);
    c.put_project(ProjectEntry { project, epoch: 1 });
    let project = rss().saturating_sub(before);
    if project > 2 * weight {
        failures.push(format!(
            "a project entry weighed {} MiB keeps {} MiB (the 64 MiB budget holds about {}x that in memory)",
            weight / MIB,
            project / MIB,
            project / weight
        ));
    }
    println!(
        "BUG-913: expired tips of 100 projects {} MiB, 50 permission entries {} MiB, a project weighed {} MiB holds {} MiB",
        tips / MIB,
        viewers / MIB,
        weight / MIB,
        project / MIB
    );
    assert!(failures.is_empty(), "{failures:#?}");
}

/// BUG-914: BUG-910 fixed only the push whose every update is refused. A
/// push that moves one branch and is refused another (that branch moved
/// since the pusher pulled) still records the refused update's snapshots
/// as committed history, which no branch reaches (BUG-910's harm: their
/// projections can then be fetched by id, and the database grows on every
/// lost race).
#[test]
fn bug_914_a_partly_refused_push_records_the_refused_updates_snapshots() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let h = hub.hub();
    // The dev builds two snapshots on the tip they pulled...
    let mut c = Craft::new(&api, &p.dev, &p.name, "main");
    let stale = c.tip;
    let snap = |c: &mut Craft, msg: &str| {
        let mut s = Snapshot {
            parents: vec![c.tip],
            change_id: veil_core::ChangeId::random(),
            tree: c.root,
            description: Text::Plain(msg.into()),
            author: "crafter".into(),
            timestamp: veil_core::now_millis(),
            predecessors: vec![],
            conflicts: vec![],
            embargo: None,
            signature: None,
        };
        s.sign(&c.identity);
        c.put(O::Snapshot(s))
    };
    c.file("src/to-main-ab12.txt", "for main");
    let for_main = snap(&mut c, "for main");
    c.file("src/to-side-ab12.txt", "for a new branch");
    let for_side = snap(&mut c, "for a new branch");
    // ...then main moves (someone else lands first).
    let mut other = Craft::new(&api, &p.dev, &p.name, "main");
    other.file("src/first-ab12.txt", "first");
    assert_eq!(other.push("main", "first").status, 200);
    let count = || -> i64 {
        hub.rt
            .block_on(sqlx::query_scalar("SELECT count(*) FROM snapshots s JOIN projects p ON p.id = s.project_id WHERE p.name = $1").bind(&p.name).fetch_one(&h.db))
            .unwrap()
    };
    let before = count();
    // One push: main (refused: it moved) and a new branch (accepted).
    let up = api.upload(&c.token, &p.name, &c.objects);
    assert_eq!(up.status, 200, "{}", String::from_utf8_lossy(&up.body));
    let receipts: serde_json::Map<String, serde_json::Value> =
        c.objects.iter().zip(up.json()["receipts"].as_array().unwrap().clone()).map(|((id, _), r)| (id.hex(), r)).collect();
    let r = api.post_json(
        Some(&c.token),
        &format!("/v1/projects/{}/push", p.name),
        &json!({"updates": [
            {"branch": "main", "expected": stale.hex(), "new": for_main.hex()},
            {"branch": "side-ab12", "expected": null, "new": for_side.hex()},
        ], "receipts": receipts}),
    );
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let v = r.json();
    assert_eq!(v["results"][0]["ok"], json!(false), "main had moved: {v}");
    assert_eq!(v["results"][1]["ok"], json!(true), "the new branch is made: {v}");
    // Only the new branch's snapshot is history now.
    assert_eq!(count(), before + 1, "the refused update's snapshot was recorded as committed history: {v}");
}

/// BUG-915: the snapshot-resolution cache remembers one real snapshot per
/// projected id, whichever view key's memo came last. A projected id two
/// views share (a snapshot that differs only where neither looks: finance
/// and devs both see `src/` before billing exists) stands for different
/// real snapshots for each: once devs' projection of a later billing-only
/// change (the same id for them) is cached, finance's commit through the
/// API on the base they were shown is refused as "no snapshot that you can
/// see". A server with a cold cache accepts it (the database lists every
/// real snapshot the id stands for, `changes::resolve_base` tries 16).
#[test]
fn bug_915_a_base_two_views_share_is_refused_once_the_other_views_memo_is_cached() {
    let a = TestHub::start();
    let b = TestHub::beside(&a);
    let admin = a.person("admin");
    let dev = a.person("dev");
    let fin = a.person("fin");
    let name = unique("share");
    let dir = admin.dir("proj");
    std::fs::create_dir_all(&dir).unwrap();
    admin.ok(&dir, &["init"]);
    write_files(&dir, &[("src/lib.rs", "pub fn shared() {}")]);
    admin.ok(&dir, &["remote", "add", "origin", &a.url(&name)]);
    admin.commit_main(&dir, "initial import");
    admin.ok(&dir, &["push"]);
    for g in ["devs", "finance"] {
        admin.ok(&dir, &["group", "create", g]);
    }
    admin.ok(&dir, &["group", "add", "devs", &dev.name, "--confirm", &dev.fingerprint()]);
    admin.ok(&dir, &["group", "add", "finance", &fin.name, "--confirm", &fin.fingerprint()]);
    admin.ok(&dir, &["access", "src/", "public", "devs"]);
    admin.ok(&dir, &["access", "billing-c4d2/", "finance"]);
    admin.commit_main(&dir, "access rules");
    admin.ok(&dir, &["push"]);
    let (dt, ft) = (dev.token(), fin.token());
    let api = a.api();
    // Both see the same snapshot: src/ only (billing does not exist yet).
    let shared = api.tips(Some(&ft), &name).unwrap().branches["main"];
    assert_eq!(api.tips(Some(&dt), &name).unwrap().branches["main"], shared, "precondition: one projection for both views");
    // A billing-only change: devs still see `shared`; finance sees a new tip.
    write_files(&dir, &[("billing-c4d2/q3.txt", "invoice")]);
    admin.commit_main(&dir, "billing only");
    admin.ok(&dir, &["push"]);
    assert_eq!(api.tips(Some(&dt), &name).unwrap().branches["main"], shared, "precondition: the change is hidden-only for devs");
    assert_ne!(api.tips(Some(&ft), &name).unwrap().branches["main"], shared);
    // Finance commits on the base they were shown, through each server.
    let commit = |api: &Api, file: &str| {
        let r = api.post_json(
            Some(&ft),
            &format!("/v1/projects/{name}/changes"),
            &json!({"base": shared.hex(), "edits": [{"path": format!("billing-c4d2/{file}"), "put": {"text": "q4"}}]}),
        );
        (r.status, String::from_utf8_lossy(&r.body).to_string())
    };
    let cold = commit(&b.api(), "cold.txt");
    assert_eq!(cold.0, 200, "control: a server with a cold cache accepts the base: {}", cold.1);
    let warm = commit(&api, "warm.txt");
    assert_eq!(warm.0, 200, "the server that cached devs' memo refuses finance's base: {}", warm.1);
}
