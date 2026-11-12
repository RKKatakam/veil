//! The landing service under sustained load (BUG-1955): a submitter past
//! what the service lands in time is told to come back, at once and before
//! any work is done for the submit; and a batch built on several cores is
//! the batch built on one.

use std::time::Duration;

use crate::{
    limits::{hold_branch, land_edit, project_id_of, release_branch, wait_ticket},
    support::*,
};

/// Rows of `table` of project `pid`.
fn rows(hub: &TestHub, table: &str, pid: i64) -> i64 {
    hub.rt.block_on(sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table} WHERE project_id = $1")).bind(pid).fetch_one(&hub.hub().db)).unwrap()
}

/// BUG-1955: past the branch's bound a submit is refused at once with
/// `503 queue_full` and when to come back, and nothing was done for it (no
/// queue row, no snapshot, no change ref). The bound is each person's fair
/// share: behind one person's full queue, another person's landing is
/// queued. Once the queue has landed, the refused submit goes in.
#[test]
fn bug_1955_a_full_queue_tells_the_submitter_to_come_back_and_holds_nobody_else_up() {
    let mut settings = TestHub::limits();
    settings.max_branch_waiting = 6;
    let hub = TestHub::start_with_limits(settings);
    let p = setup_project(&hub);
    let pid = project_id_of(&hub, &p.name);
    let api = hub.api();
    let (dev, admin) = (p.dev.token(), p.admin.token());
    let base = api.tips(Some(&dev), &p.name).unwrap().branches["main"];
    let admin_base = api.tips(Some(&admin), &p.name).unwrap().branches["main"];
    let served = |hub: &TestHub| -> i64 {
        hub.rt
            .block_on(sqlx::query_scalar("SELECT served FROM landing_leases WHERE project_id = $1 AND branch = 'main'").bind(pid).fetch_one(&hub.hub().db))
            .unwrap()
    };

    hold_branch(&hub, pid, "main");
    let mut tickets = Vec::new();
    for i in 0..6 {
        let r = land_edit(&api, &dev, &p.name, base, &format!("src/hold/f{i}.rs"), "x\n", false);
        assert_eq!(r.status, 200, "submit {i}: {}", String::from_utf8_lossy(&r.body));
        tickets.push(r.json()["ticket"].as_str().unwrap().to_string());
    }
    // The seventh: told to come back, at once, and nothing was done for it.
    let before = (rows(&hub, "landing_queue", pid), rows(&hub, "snapshots", pid), rows(&hub, "change_refs", pid));
    let asked = std::time::Instant::now();
    let refused = land_edit(&api, &dev, &p.name, base, "src/hold/late.rs", "x\n", true);
    assert_eq!(refused.status, 503, "{}", String::from_utf8_lossy(&refused.body));
    assert!(asked.elapsed() < Duration::from_secs(5), "the refusal took {:?}: it does not wait for the queue", asked.elapsed());
    let v = refused.json();
    assert_eq!(v["code"], "queue_full", "{v}");
    let wait = v["retry_after_ms"].as_u64().expect("the answer says how long to wait");
    assert!((1_000..=5_000).contains(&wait), "{v}");
    assert!(v["message"].as_str().unwrap().contains("'main'"), "{v}");
    assert_eq!((rows(&hub, "landing_queue", pid), rows(&hub, "snapshots", pid), rows(&hub, "change_refs", pid)), before, "a refused submit left something");
    // Another person, behind the six: queued (one of the flood's lands before it).
    let other = land_edit(&api, &admin, &p.name, admin_base, "src/hold/other.rs", "y\n", false);
    assert_eq!(other.status, 200, "{}", String::from_utf8_lossy(&other.body));
    let other = other.json()["ticket"].as_str().unwrap().to_string();
    // And the first person is still refused, however often they ask.
    for _ in 0..3 {
        let r = land_edit(&api, &dev, &p.name, base, "src/hold/late.rs", "x\n", false);
        assert_eq!(r.status, 503, "{}", String::from_utf8_lossy(&r.body));
    }

    // The queue lands; the service counts what it served in its lease row.
    release_branch(&hub, pid, "main");
    let v = wait_ticket(&api, &admin, &p.name, &other);
    assert_eq!(v["state"], "landed", "{v}");
    for t in &tickets {
        let v = wait_ticket(&api, &dev, &p.name, t);
        assert_eq!(v["state"], "landed", "{v}");
    }
    assert_eq!(served(&hub), 7);
    // Now the refused submit goes in (what was read of the queue is used
    // for a tenth of a second).
    std::thread::sleep(Duration::from_millis(150));
    let again = land_edit(&api, &dev, &p.name, base, "src/hold/late.rs", "x\n", true);
    assert_eq!(again.status, 200, "{}", String::from_utf8_lossy(&again.body));
    assert_eq!(again.json()["state"], "landed", "{}", again.json());
    assert_eq!(served(&hub), 8);
}

/// BUG-1955: `vl land` told to come back waits as the answer asks, says
/// what it waits for, and lands once the queue has room.
#[test]
fn bug_1955_vl_land_waits_for_a_full_queue_and_says_so() {
    let mut settings = TestHub::limits();
    settings.max_branch_waiting = 2;
    let hub = TestHub::start_with_limits(settings);
    let p = setup_project(&hub);
    let pid = project_id_of(&hub, &p.name);
    let api = hub.api();
    let admin = p.admin.token();
    let base = api.tips(Some(&admin), &p.name).unwrap().branches["main"];
    write_files(&p.dir, &[("src/held.txt", "held\n")]);
    p.admin.ok(&p.dir, &["commit", "-m", "lands once the queue has room"]);

    hold_branch(&hub, pid, "main");
    let mut tickets = Vec::new();
    for i in 0..2 {
        let r = land_edit(&api, &admin, &p.name, base, &format!("src/full/f{i}.rs"), "x\n", false);
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        tickets.push(r.json()["ticket"].as_str().unwrap().to_string());
    }
    let out = std::thread::scope(|s| {
        s.spawn(|| {
            std::thread::sleep(Duration::from_millis(2_500));
            release_branch(&hub, pid, "main");
        });
        p.admin.ok(&p.dir, &["land"])
    });
    assert!(out.contains("landed main"), "{out}");
    assert!(out.contains("waiting for the server: the landing queue of 'main' is full"), "{out}");
    for t in &tickets {
        let v = wait_ticket(&api, &admin, &p.name, t);
        assert_eq!(v["state"], "landed", "{v}");
    }
}
