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

/// BUG-1955: a batch whose entries are read on several threads is the batch
/// built on one, byte for byte: the same objects, the same snapshots,
/// projections and landing records in the same order, the same tip, and
/// the same answer for every entry. Seeded batches of two people's changes:
/// new files, edits of one shared file (the second of two overlaps: handed
/// to a merge), and two changes adding one path (the second conflicts).
/// And what the service then lands is what the build on one thread said.
#[test]
fn bug_1955_a_batch_read_on_several_threads_is_the_batch_built_on_one() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id_of(&hub, &p.name);
    let api = hub.api();
    let (dev, admin) = (p.dev.token(), p.admin.token());
    let shared: String = (0..40).map(|i| format!("line {i}\n")).collect();
    let made = land_edit(&api, &admin, &p.name, api.tips(Some(&admin), &p.name).unwrap().branches["main"], "src/par/shared.txt", &shared, true);
    assert_eq!(made.status, 200, "{}", String::from_utf8_lossy(&made.body));
    assert_eq!(made.json()["state"], "landed", "{}", made.json());

    for seed in 1..=3u64 {
        let mut state = seed.wrapping_mul(0x9e3779b97f4a7c15);
        let mut next = |n: u64| {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (state >> 33) % n
        };
        hold_branch(&hub, pid, "main");
        let bases = [api.tips(Some(&dev), &p.name).unwrap().branches["main"], api.tips(Some(&admin), &p.name).unwrap().branches["main"]];
        // 90 submits: more than one batch, so the batch is the service's fair choice.
        let mut tickets: Vec<(usize, String)> = Vec::new();
        for i in 0..90 {
            let who = next(2) as usize;
            let (path, text) = match next(100) {
                0..=14 => {
                    let at = next(40);
                    ("src/par/shared.txt".to_string(), shared.replace(&format!("line {at}\n"), &format!("line {at} of {seed}/{i}\n")))
                }
                15..=29 => (format!("src/par/s{seed}/same-{}.txt", next(3)), format!("{seed}/{i}\n")),
                _ => (format!("src/par/s{seed}/f{i:02}.rs"), format!("{seed}/{i}\n")),
            };
            let r = land_edit(&api, [&dev, &admin][who], &p.name, bases[who], &path, &text, false);
            assert_eq!(r.status, 200, "seed {seed}, submit {i}: {}", String::from_utf8_lossy(&r.body));
            tickets.push((who, r.json()["ticket"].as_str().unwrap().to_string()));
        }
        let [one, several] = hub.rt.block_on(veil_server::landing::build_both_ways(&hub.hub(), pid, "main", 8)).expect("the batch builds both ways");
        let count = |what: &str| one.iter().filter(|l| l.contains(what)).count();
        assert!(count("object ") > 100 && count(" landed as ") >= 20, "seed {seed}: {} objects, {} landed", count("object "), count(" landed as "));
        assert!(count(" merging on ") >= 1 && count(" conflict ") >= 1, "seed {seed}: {} merging, {} conflicts", count(" merging on "), count(" conflict "));
        assert!(count("memo ") >= 20, "seed {seed}: {} projections", count("memo "));
        for (a, b) in one.iter().zip(&several) {
            assert_eq!(a, b, "seed {seed}");
        }
        assert_eq!(one.len(), several.len(), "seed {seed}");

        // The service lands them (on this machine's threads): every ticket
        // ends, and an admin's landing the one-thread build said lands is
        // answered with the snapshots it said.
        release_branch(&hub, pid, "main");
        for (who, t) in &tickets {
            let token = [&dev, &admin][*who];
            let mut v = wait_ticket(&api, token, &p.name, t);
            // (A merged change that was queued again is waited for again.)
            for _ in 0..200 {
                if v["state"] != "queued" && v["state"] != "merging" {
                    break;
                }
                v = wait_ticket(&api, token, &p.name, t);
            }
            assert!(v["state"] == "landed" || v["state"] == "conflict", "seed {seed}: {v}");
            if let (1, Some(line)) = (*who, one.iter().find(|l| l.starts_with(&format!("{t} landed as ")))) {
                assert_eq!(v["state"], "landed", "seed {seed}: {v}");
                let landed: Vec<String> = v["landed"].as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect();
                assert_eq!(*line, format!("{t} landed as {landed:?}"), "seed {seed}");
            }
        }
    }
}
