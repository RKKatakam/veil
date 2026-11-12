//! The landing service's speed bugs of 2026-11-12 (BUG-1940 to BUG-1942):
//! one person's submits waited for one another, each batch read the whole
//! queue, and a protected branch asked the review rules three times for
//! each change. Each test here is one guarantee of their fixes.

use std::{
    collections::HashSet,
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

use serde_json::json;
use veil_core::{crypto::domains::SIG_CONTEXT_HUB_PR_REVIEW, hub::pr::review_message, ObjectId};
use veil_server::{
    auth::Person,
    caches::Epochs,
    landing::{Queued, Submitter},
    limits::landing::{admit_queue, fair_batch, pick_batch, QueuedEntry, PICK_CHUNK},
};

use crate::{
    limits::{agent_session_token, hold_branch, land_edit, project_id_of, release_branch, wait_ticket},
    support::*,
};

fn run_id() -> String {
    hex::encode(veil_core::crypto::random_bytes::<6>())
}

/// BUG-1940: one person's submits do not wait for one another. A submit
/// whose transaction is still open (its queue row written, not committed)
/// holds nothing another submit of the same person needs: the next ones are
/// queued at once. (Before, the first held the person's row to its commit.)
#[test]
fn bug_1940_one_persons_submits_do_not_wait_for_one_another() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id_of(&hub, &p.name);
    let db = hub.hub().db.clone();
    let run = run_id();
    hub.rt.block_on(async {
        let person: i64 = sqlx::query_scalar("SELECT id FROM people WHERE name = $1").bind(&p.dev.name).fetch_one(&db).await.unwrap();
        let who = Submitter {
            person: Person { id: person, name: p.dev.name.clone(), device_key: format!("key-{run}"), agent: None },
            epochs: Epochs { person: 0, project: Some((pid, 0)), gc: None },
        };
        let queued = |n: usize| Queued {
            ticket: format!("land-{run}-{n}"),
            branch: format!("speed-{run}"),
            stack: Vec::new(),
            lineage: 0,
            skipped: Default::default(),
        };
        let mut first = db.begin().await.unwrap();
        admit_queue(&mut first, pid, &who, &queued(0)).await.expect("the first submit is queued");
        // Three more of the same person while the first is open. (One that
        // chose the first's slot, one chance in 1,000, waits for it.)
        let mut went_through = 0;
        for n in 1..=3 {
            let mut next = db.begin().await.unwrap();
            let waited = tokio::time::timeout(Duration::from_secs(3), admit_queue(&mut next, pid, &who, &queued(n))).await;
            if let Ok(r) = waited {
                r.expect("a submit that did not wait is queued");
                went_through += 1;
            }
            drop(next);
        }
        assert!(went_through >= 2, "{went_through} of 3 submits went through while another submit of the same person was open");
        first.rollback().await.unwrap();
    });
}

/// BUG-1940: the bounds on waiting landings stay exact when one person's
/// submits race (no lock orders them any more: the slots' unique indexes
/// decide), on a person's own session and on an agent session, and a
/// landing that has landed gives its slot back.
#[test]
fn bug_1940_the_bounds_are_exact_when_one_persons_submits_race_and_slots_come_back() {
    let mut settings = TestHub::limits();
    settings.max_session_outstanding = 4;
    settings.max_person_outstanding = 9;
    let hub = TestHub::start_with_limits(settings);
    let p = setup_project(&hub);
    let pid = project_id_of(&hub, &p.name);
    let api = hub.api();
    let dev = p.dev.token();
    let race = |token: &str, base: ObjectId, dir: &str, n: usize| -> Vec<Reply> {
        std::thread::scope(|scope| {
            let handles: Vec<_> = (0..n)
                .map(|i| {
                    let (api, name) = (&api, &p.name);
                    scope.spawn(move || land_edit(api, token, name, base, &format!("src/{dir}/f{i:02}.rs"), "x\n", false))
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        })
    };
    let count = |replies: &[Reply]| (replies.iter().filter(|r| r.status == 200).count(), replies.iter().filter(|r| r.status == 429).count());
    let land_all = |token: &str, replies: &[Reply]| {
        for r in replies.iter().filter(|r| r.status == 200) {
            let v = wait_ticket(&api, token, &p.name, r.json()["ticket"].as_str().unwrap());
            assert_eq!(v["state"], "landed", "{v}");
        }
    };

    // 24 at once on the person's own session: exactly the person's 9.
    hold_branch(&hub, pid, "main");
    let base = api.tips(Some(&dev), &p.name).unwrap().branches["main"];
    let own = race(&dev, base, "own", 24);
    assert_eq!(count(&own), (9, 15), "{:?}", own.iter().map(|r| r.status).collect::<Vec<_>>());
    let refused = own.iter().find(|r| r.status == 429).unwrap();
    assert!(String::from_utf8_lossy(&refused.body).contains("you already have 9 landings waiting"), "{}", String::from_utf8_lossy(&refused.body));
    release_branch(&hub, pid, "main");
    land_all(&dev, &own);

    // The 9 landed: their slots are free again. 12 at once from an agent
    // session: exactly the session's 4; then 12 on the person's own
    // session: exactly the 5 the person has left.
    hold_branch(&hub, pid, "main");
    let base = api.tips(Some(&dev), &p.name).unwrap().branches["main"];
    let agent = agent_session_token(&api, &dev, &p.name, "speed");
    let from_agent = race(&agent, base, "agent", 12);
    assert_eq!(count(&from_agent), (4, 8), "{:?}", from_agent.iter().map(|r| r.status).collect::<Vec<_>>());
    let refused = from_agent.iter().find(|r| r.status == 429).unwrap();
    assert!(String::from_utf8_lossy(&refused.body).contains("this agent session already has 4 landings waiting"), "{}", String::from_utf8_lossy(&refused.body));
    let again = race(&dev, base, "again", 12);
    assert_eq!(count(&again), (5, 7), "{:?}", again.iter().map(|r| r.status).collect::<Vec<_>>());
    // Each waiting landing holds a slot of its own, below the bound.
    let (waiting, slots, highest): (i64, i64, i32) = hub
        .rt
        .block_on(
            sqlx::query_as("SELECT COUNT(*), COUNT(DISTINCT person_slot), MAX(person_slot) FROM landing_queue WHERE project_id = $1 AND state = 'queued'")
                .bind(pid)
                .fetch_one(&hub.hub().db),
        )
        .unwrap();
    assert_eq!((waiting, slots), (9, 9));
    assert!(highest < 9, "{highest}");
    release_branch(&hub, pid, "main");
    land_all(&agent, &from_agent);
    land_all(&dev, &again);
}

/// A queued row as the test reads the whole queue.
struct Whole {
    seq: i64,
    person: i64,
    key: String,
    revert: bool,
}

impl QueuedEntry for Whole {
    fn seq(&self) -> i64 {
        self.seq
    }
    fn person_id(&self) -> i64 {
        self.person
    }
    fn session_key(&self) -> &str {
        &self.key
    }
}

/// The batch the whole queue gives, as the service chose it before
/// BUG-1941: every queued row read, the reverts first, then fair shares.
async fn whole_queue_batch(c: &mut sqlx::PgConnection, project: i64, branch: &str, exclude: &HashSet<i64>, limit: usize) -> veil_server::error::Result<Vec<i64>> {
    let rows: Vec<(i64, i64, String, String, bool)> = sqlx::query_as(
        "SELECT seq, person_id, session, device_key, priority > 0 FROM landing_queue WHERE project_id = $1 AND branch = $2 AND state = 'queued' \
         ORDER BY priority DESC, created_at, seq",
    )
    .bind(project)
    .bind(branch)
    .fetch_all(&mut *c)
    .await?;
    let (reverts, rest): (Vec<Whole>, Vec<Whole>) = rows
        .into_iter()
        .map(|(seq, person, session, device, revert)| Whole { seq, person, key: if session.is_empty() { device } else { session }, revert })
        .partition(|r| r.revert);
    let mut batch: Vec<i64> = reverts.iter().map(|r| r.seq).filter(|s| !exclude.contains(s)).take(limit).collect();
    let rest_limit = limit - batch.len();
    batch.extend(fair_batch(rest, exclude, rest_limit).iter().map(|r| r.seq));
    Ok(batch)
}

/// Rows of `landing_queue` the transaction has read so far (PostgreSQL's
/// count of rows fetched through indexes and by scans; 0 where the database
/// keeps none).
async fn rows_fetched(c: &mut sqlx::PgConnection) -> i64 {
    sqlx::query_scalar("SELECT COALESCE(SUM(COALESCE(idx_tup_fetch, 0) + COALESCE(seq_tup_read, 0)), 0)::BIGINT FROM pg_stat_xact_user_tables WHERE relname = 'landing_queue'")
        .fetch_one(&mut *c)
        .await
        .unwrap()
}

/// BUG-1941: choosing a batch reads a bounded part of the queue, and the
/// batch is the one the whole queue gives. A queue of 20,000 landings of
/// 300 people is read in one statement of `PICK_CHUNK` rows; behind one
/// person's flood of 1,000 it is that person's rows at most; and twice the
/// queue reads no more.
#[test]
fn bug_1941_choosing_a_batch_reads_a_bounded_part_of_a_long_queue() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id_of(&hub, &p.name);
    let db = hub.hub().db.clone();
    let run = run_id();
    let branch = format!("speed-{run}");
    // YugabyteDB may ask a transaction that read after other transactions'
    // writes to start again ("Restart read required"); the server's own
    // picks are single statements, which the database then runs again by
    // itself. Here the whole transaction is run again.
    hub.rt.block_on(async {
      let mut attempts = 0;
      loop {
        attempts += 1;
        let done: veil_server::error::Result<()> = async {
        // Everything in one transaction that is rolled back: no landing
        // service sees these rows.
        let mut tx = db.begin().await.unwrap();
        let people: Vec<i64> = sqlx::query_scalar("INSERT INTO people (name, created_at) SELECT $1 || g, 0 FROM generate_series(1, 301) g RETURNING id")
            .bind(format!("speed-{run}-"))
            .fetch_all(&mut *tx)
            .await
            .unwrap();
        assert_eq!(people.len(), 301);
        let (flooder, people) = (people[300], &people[..300]);
        // (person, session, created_at, priority)
        async fn insert(tx: &mut sqlx::PgConnection, project: i64, branch: &str, run: &str, rows: &[(i64, String, i64, i32)]) -> Vec<i64> {
            let seqs: Vec<i64> = sqlx::query_scalar(
                "INSERT INTO landing_queue (project_id, branch, ticket, person_id, person_name, device_key, session, stack, lineage, person_epoch, project_epoch, \
                 state, created_at, priority) \
                 SELECT $1, $2, 'land-' || $3 || '-' || at::TEXT, person, 'p', 'device-' || person::TEXT, session, '[]', 0, 0, 0, 'queued', at, priority \
                 FROM UNNEST($4::BIGINT[], $5::TEXT[], $6::BIGINT[], $7::INT[]) AS r(person, session, at, priority) RETURNING seq",
            )
            .bind(project)
            .bind(branch)
            .bind(run)
            .bind(rows.iter().map(|r| r.0).collect::<Vec<_>>())
            .bind(rows.iter().map(|r| r.1.clone()).collect::<Vec<_>>())
            .bind(rows.iter().map(|r| r.2).collect::<Vec<_>>())
            .bind(rows.iter().map(|r| r.3).collect::<Vec<_>>())
            .fetch_all(&mut *tx)
            .await
            .unwrap();
            assert_eq!(seqs.len(), rows.len());
            seqs
        }
        // 20,000 landings of 300 people in turn; every other person's are
        // from three agent sessions, the others' from their own.
        let many = |from: i64, n: i64| -> Vec<(i64, String, i64, i32)> {
            (from..from + n)
                .map(|i| {
                    let who = (i % 300) as usize;
                    let session = if who % 2 == 0 { format!("s{}-{}", who, (i / 300) % 3) } else { String::new() };
                    (people[who], session, 1_000_000 + i, 0)
                })
                .collect()
        };
        insert(&mut tx, pid, &branch, &run, &many(0, 20_000)).await;
        let none = HashSet::new();
        let before = rows_fetched(&mut tx).await;
        let picked = pick_batch(&mut tx, pid, &branch, &none, 64).await?;
        let fetched = rows_fetched(&mut tx).await - before;
        let whole = whole_queue_batch(&mut tx, pid, &branch, &none, 64).await?;
        assert_eq!(picked.rows.iter().map(|r| r.seq).collect::<Vec<_>>(), whole);
        assert_eq!(whole.len(), 64);
        assert_eq!((picked.statements, picked.read), (1, PICK_CHUNK), "20,000 queued landings of 300 people");
        assert!(fetched <= 2 * PICK_CHUNK as i64, "the database fetched {fetched} rows of the queue to choose 64 of 20,000");

        // Ahead of them: one person's 1,000 (10 agent sessions of 100, one
        // after another) and three of the server's reverts. Some of the
        // first rows are being committed (left out).
        let flood: Vec<(i64, String, i64, i32)> = (0..1_000).map(|i| (flooder, format!("flood-{}", i / 100), i, 0)).collect();
        let flood_seqs = insert(&mut tx, pid, &branch, &run, &flood).await;
        let reverts: Vec<(i64, String, i64, i32)> = (0..3).map(|i| (people[7], String::new(), 5_000_000 + i, 1)).collect();
        let revert_seqs = insert(&mut tx, pid, &branch, &run, &reverts).await;
        let mut flood_order = flood_seqs.clone();
        flood_order.sort();
        let exclude: HashSet<i64> = flood_order[..5].iter().copied().chain([*revert_seqs.iter().min().unwrap()]).collect();
        let before = rows_fetched(&mut tx).await;
        let behind_flood = pick_batch(&mut tx, pid, &branch, &exclude, 64).await?;
        let fetched = rows_fetched(&mut tx).await - before;
        let whole = whole_queue_batch(&mut tx, pid, &branch, &exclude, 64).await?;
        let picked_seqs: Vec<i64> = behind_flood.rows.iter().map(|r| r.seq).collect();
        assert_eq!(picked_seqs, whole);
        assert_eq!(whole.len(), 64);
        // The two reverts not being committed first, one landing of the
        // flood's person, and 61 other people's.
        assert!(behind_flood.rows[..2].iter().all(|r| r.revert) && behind_flood.rows[2..].iter().all(|r| !r.revert));
        assert_eq!(behind_flood.rows.iter().filter(|r| r.person_id == flooder).count(), 1);
        assert_eq!(behind_flood.rows[2..].iter().map(|r| r.person_id).collect::<HashSet<_>>().len(), 62);
        assert!(picked_seqs.iter().all(|s| !exclude.contains(s)));
        assert!(
            behind_flood.statements <= 5 && behind_flood.read <= 1_000 + 2 * PICK_CHUNK,
            "behind a flood of 1,000: {} statements read {} rows",
            behind_flood.statements,
            behind_flood.read
        );
        assert!(fetched <= 3_000, "the database fetched {fetched} rows of the queue to choose 64 of 21,000 behind a flood");

        // Twice the queue: the same batch from the same reading.
        insert(&mut tx, pid, &branch, &run, &many(20_000, 20_000)).await;
        let before = rows_fetched(&mut tx).await;
        let twice = pick_batch(&mut tx, pid, &branch, &exclude, 64).await?;
        let fetched_twice = rows_fetched(&mut tx).await - before;
        assert_eq!(twice.rows.iter().map(|r| r.seq).collect::<Vec<_>>(), picked_seqs);
        assert_eq!((twice.statements, twice.read), (behind_flood.statements, behind_flood.read));
        assert!(fetched_twice <= 3_000, "the database fetched {fetched_twice} rows of the queue to choose 64 of 41,000");
        tx.rollback().await.unwrap();
        Ok(())
        }
        .await;
        match done {
            Ok(()) => break,
            Err(e) if e.is_retryable() && attempts < 8 => continue,
            Err(e) => panic!("choosing a batch failed (attempt {attempts}): {e:?}"),
        }
      }
    });
}

/// BUG-1942: a batch onto a protected branch asks the review rules a
/// bounded number of times, not three for each change, and still refuses
/// the one change a reviewer's hold was placed on while it was queued
/// (BUG-1880), in the same batch as the forty that land.
#[test]
fn bug_1942_a_protected_branchs_batch_asks_the_review_rules_a_bounded_number_of_times() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id_of(&hub, &p.name);
    let api = hub.api();
    let (dev, admin) = (p.dev.token(), p.admin.token());
    // `main` is protected, and no change needs an approval (what
    // `veil-bench load --protected` sets).
    write_files(
        &p.dir,
        &[(".veilrules", "[branches.main]\nprotected = true\n\n[review]\nlow = { approvals = 0 }\nnormal = { approvals = 0 }\nhigh = { approvals = 0 }\n")],
    );
    p.admin.commit_main(&p.dir, "protect main, no approvals needed");
    p.admin.ok(&p.dir, &["push"]);
    let base = api.tips(Some(&dev), &p.name).unwrap().branches["main"];

    // Another PR of dev's edits `src/held.rs`: the admin's request for
    // changes on it (below) holds that path.
    let other: ObjectId = serde_json::from_value(
        api.post_json(
            Some(&dev),
            &format!("/v1/projects/{}/changes", p.name),
            &json!({"base": base.hex(), "edits": [{"path": "src/held.rs", "put": {"text": "the other PR\n"}}]}),
        )
        .json()["snapshot"]
            .clone(),
    )
    .unwrap();
    let r = api.post_json(
        Some(&dev),
        &format!("/v1/projects/{}/push", p.name),
        &json!({"updates": [{"branch": "other-held", "expected": null, "new": other.hex()}], "force": false}),
    );
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let r = api.post_json(Some(&dev), &format!("/v1/projects/{}/prs", p.name), &json!({"head": "other-held", "title": "other"}));
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let pr = r.json();
    let (pr_id, pr_patch) = (pr["id"].as_str().unwrap().to_string(), pr["patch"].as_str().unwrap().to_string());

    // 41 landings queued while another server holds the branch: 40 of
    // files of their own, one of `src/held.rs`.
    hold_branch(&hub, pid, "main");
    let mut tickets = Vec::new();
    for i in 0..40 {
        let r = land_edit(&api, &dev, &p.name, base, &format!("src/speed/f{i:02}.rs"), "x\n", false);
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        tickets.push(r.json()["ticket"].as_str().unwrap().to_string());
    }
    let r = land_edit(&api, &dev, &p.name, base, "src/held.rs", "queued\n", false);
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let held = r.json()["ticket"].as_str().unwrap().to_string();
    let sig = p.admin.identity().sign(SIG_CONTEXT_HUB_PR_REVIEW, &review_message(&p.name, &pr_id, &pr_patch, "request-changes"));
    let r = api.post_json(
        Some(&admin),
        &format!("/v1/projects/{}/prs/{pr_id}/reviews", p.name),
        &json!({"patch": pr_patch, "verdict": "request-changes", "signature": sig}),
    );
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));

    let stats = &hub.hub().landing.stats;
    let (asks, batches) = (stats.review_asks.load(Ordering::Relaxed), stats.batches.load(Ordering::Relaxed));
    release_branch(&hub, pid, "main");
    let until = Instant::now() + Duration::from_secs(60);
    let outcome = |ticket: &str| loop {
        let r = api.get(Some(&dev), &format!("/v1/projects/{}/land/{ticket}", p.name));
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        let v = r.json();
        if (v["state"] != "queued" && v["state"] != "merging") || Instant::now() > until {
            return v;
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    for t in &tickets {
        let v = outcome(t);
        assert_eq!(v["state"], "landed", "{v}");
    }
    let v = outcome(&held);
    assert_eq!(v["state"], "rejected", "{v}");
    assert!(v["message"].as_str().unwrap_or_default().contains("asked for changes"), "{v}");

    // Each batch asks at most twice for all its entries when it is read
    // (the PRs that could carry an approval, the holds) and twice in its
    // transaction; the held entry is asked alone, once. Three statements
    // for each of 41 changes, twice, were 246.
    let (asks, batches) = (stats.review_asks.load(Ordering::Relaxed) - asks, stats.batches.load(Ordering::Relaxed) - batches);
    assert!(batches >= 1, "{batches}");
    assert!(asks >= 2 && asks <= 4 * batches + 2, "{asks} asks of the review rules in {batches} batches");
}
