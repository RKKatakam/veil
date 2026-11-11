//! Whole-codebase review, 2026-11-11, `rv-core2`: the landing service's
//! batches and merges, approval when an entry lands, derived data, GC races
//! and request budgets (BUG-1880 to BUG-1889). Each test here is the
//! reproduction of one `docs/BUGS.md` row, ignored until its fix.

use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use serde_json::{json, Value};
use veil_core::{crypto::domains::SIG_CONTEXT_HUB_PR_REVIEW, hub::pr::review_message, ObjectId};
use veil_server::pack_gc::{self, Options, SwitchHook};

use crate::support::*;

fn project_id(hub: &TestHub, name: &str) -> i64 {
    hub.rt
        .block_on(sqlx::query_scalar::<_, i64>("SELECT id FROM projects WHERE name = $1").bind(name).fetch_one(&hub.hub().db))
        .unwrap()
}

fn put(path: &str, text: &str) -> Value {
    json!({"path": path, "put": {"text": text}})
}

/// Another server holds `branch`'s landing lease (for ten minutes): nothing
/// queued for it lands until [`release_lease`].
fn hold_lease(hub: &TestHub, project: i64, branch: &str) {
    hub.rt
        .block_on(
            sqlx::query(
                "INSERT INTO landing_leases (project_id, branch, holder, epoch, expires_at) \
                 VALUES ($1, $2, 'rv-core2-another-server', 1, (extract(epoch FROM clock_timestamp()) * 1000)::BIGINT + 600000) \
                 ON CONFLICT (project_id, branch) DO UPDATE SET holder = EXCLUDED.holder, epoch = landing_leases.epoch + 1, expires_at = EXCLUDED.expires_at",
            )
            .bind(project)
            .bind(branch)
            .execute(&hub.hub().db),
        )
        .unwrap();
}

/// The other server's lease ends.
fn release_lease(hub: &TestHub, project: i64, branch: &str) {
    hub.rt
        .block_on(
            sqlx::query("DELETE FROM landing_leases WHERE project_id = $1 AND branch = $2 AND holder = 'rv-core2-another-server'")
                .bind(project)
                .bind(branch)
                .execute(&hub.hub().db),
        )
        .unwrap();
}

/// The ticket's outcome, once it is no longer queued (within a minute).
fn outcome(api: &Api, token: &str, project: &str, ticket: &str) -> Value {
    let until = Instant::now() + Duration::from_secs(60);
    loop {
        let r = api.get(Some(token), &format!("/v1/projects/{project}/land/{ticket}"));
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        let v = r.json();
        if v["state"] != "queued" || Instant::now() > until {
            return v;
        }
    }
}

/// `docs/HUB.md` §13.24: every landing onto a protected branch meets the
/// review rules. The rules are asked when the entry is queued and never
/// again: a reviewer who takes the approval back (a request for changes,
/// answered `ready: false`) while the entry waits in the queue (here behind
/// another server's lease; in use, behind a long queue, a slow batch or a
/// merge worker) still sees it land.
#[test]
#[ignore = "BUG-1880: a queued entry lands on a protected branch after its approval was withdrawn"]
fn bug_1880_an_approval_withdrawn_while_the_entry_is_queued_still_lands() {
    let th = TestHub::start();
    let p = setup_project(&th);
    let api = th.api();
    let pid = project_id(&th, &p.name);
    let (dev_tok, admin_tok) = (p.dev.token(), p.admin.token());

    write_files(&p.dir, &[(".veilrules", "[branches.main]\nprotected = true\n")]);
    p.admin.commit_main(&p.dir, "protect main with review rules");
    p.admin.ok(&p.dir, &["push"]);

    let base = api.tips(Some(&dev_tok), &p.name).unwrap().branches["main"];
    let r = api.post_json(
        Some(&dev_tok),
        &format!("/v1/projects/{}/changes", p.name),
        &json!({"base": base.hex(), "edits": [put("src/feature-1880.rs", "pub fn feat() {}\n")]}),
    );
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let feat: ObjectId = serde_json::from_value(r.json()["snapshot"].clone()).unwrap();
    let r = api.post_json(
        Some(&dev_tok),
        &format!("/v1/projects/{}/push", p.name),
        &json!({"updates": [{"branch": "feat", "expected": null, "new": feat.hex()}], "force": false}),
    );
    assert_eq!(r.json()["results"][0]["ok"], true);
    let pr = api.post_json(Some(&dev_tok), &format!("/v1/projects/{}/prs", p.name), &json!({"head": "feat", "title": "add feat"})).json();
    let (pr_id, patch) = (pr["id"].as_str().unwrap().to_string(), pr["patch"].as_str().unwrap().to_string());
    let review = |verdict: &str| {
        let sig = p.admin.identity().sign(SIG_CONTEXT_HUB_PR_REVIEW, &review_message(&p.name, &pr_id, &patch, verdict));
        api.post_json(
            Some(&admin_tok),
            &format!("/v1/projects/{}/prs/{pr_id}/reviews", p.name),
            &json!({"patch": patch, "verdict": verdict, "signature": sig}),
        )
    };
    let r = review("approve");
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["review"]["ready"], true);

    // The approved change is queued, and waits.
    hold_lease(&th, pid, "main");
    let r = api.post_json(
        Some(&dev_tok),
        &format!("/v1/projects/{}/land", p.name),
        &json!({"onto": "main", "snapshot": feat.hex(), "wait": false}),
    );
    assert_eq!(r.status, 200, "the approved change is queued: {}", String::from_utf8_lossy(&r.body));
    let queued = r.json();
    assert_eq!(queued["state"], "queued", "{queued}");
    let ticket = queued["ticket"].as_str().unwrap().to_string();

    // Its reviewer takes the approval back, and is told the PR is not ready.
    let r = review("request-changes");
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["review"]["ready"], false, "the PR is no longer ready to land");

    release_lease(&th, pid, "main");
    let done = outcome(&api, &dev_tok, &p.name, &ticket);
    assert_ne!(done["state"], "queued", "the entry was answered: {done}");
    assert_eq!(
        api.tips(Some(&dev_tok), &p.name).unwrap().branches["main"],
        base,
        "a change whose only approval was withdrawn landed on protected main: {done}"
    );
    assert_eq!(done["state"], "rejected", "{done}");
}

/// GC never deletes an object a concurrent push is about to reference. The
/// only guard is the reference stamp, read in GC's own transaction: a push
/// whose transaction is open then (it found the snapshot stored, and waits
/// for its branch's row, as behind another push to the branch) commits
/// after it, onto objects GC deletes.
#[test]
fn bug_1881_a_push_committing_during_the_gc_switch_points_its_branch_at_deleted_objects() {
    let th = TestHub::start();
    let p = setup_project(&th);
    let api = th.api();
    let pid = project_id(&th, &p.name);
    let admin_tok = p.admin.token();
    let h = th.hub();
    let main0 = api.tips(Some(&admin_tok), &p.name).unwrap().branches["main"];
    let push = |api: &Api, tok: &str, branch: &str, expected: Option<ObjectId>, new: Option<ObjectId>, force: bool| {
        api.post_json(
            Some(tok),
            &format!("/v1/projects/{}/push", p.name),
            &json!({"updates": [{"branch": branch, "expected": expected.map(|e| e.hex()), "new": new.map(|e| e.hex())}], "force": force}),
        )
    };

    // A branch `hold` at main, and a change on a branch that is then deleted.
    let r = push(&api, &admin_tok, "hold", None, Some(main0), false);
    assert_eq!(r.json()["results"][0]["ok"], true, "{}", String::from_utf8_lossy(&r.body));
    const CONTENT: &str = "RV-CORE2-BUG-1881-CONTENT-5d0c1f7e\n";
    let mut c = Craft::new(&api, &p.admin, &p.name, "main");
    c.file("src/gc-race-1881.txt", CONTENT);
    let (snap, r) = c.push_edited("tmp-1881", None, |_| {});
    assert_eq!(r.json()["results"][0]["ok"], true, "{}", String::from_utf8_lossy(&r.body));
    let r = push(&api, &admin_tok, "tmp-1881", Some(snap), None, true);
    assert_eq!(r.json()["results"][0]["ok"], true, "{}", String::from_utf8_lossy(&r.body));

    // GC sees the change unreferenced; two minutes later it is past retention.
    let gc = |offset: i64, hook: Option<SwitchHook>| {
        th.rt.block_on(pack_gc::run_project(
            &h,
            pid,
            &Options {
                min_packs_to_merge: 1,
                run_gc: true,
                retention_window_ms: 60_000,
                pack_grace_ms: 0,
                now_offset_ms: offset,
                before_switch: hook,
                ..Options::default()
            },
        ))
    };
    gc(0, None).unwrap();

    // Right before GC checks its stamp: the branch's row is locked (as by
    // another push to it), and a push of `hold` to the change begins. It
    // finds the snapshot stored and waits for the row in its transaction.
    let (tx_done, rx_done) = std::sync::mpsc::channel::<Reply>();
    let release = Arc::new(tokio::sync::Notify::new());
    let once = Arc::new(AtomicBool::new(false));
    let hook = {
        let (db, release, once) = (h.db.clone(), release.clone(), once.clone());
        let (authority, cert, tok, name) = (th.authority(), th.cert_pem.clone(), admin_tok.clone(), p.name.clone());
        SwitchHook(Arc::new(move || {
            let (db, release, once, tx_done) = (db.clone(), release.clone(), once.clone(), tx_done.clone());
            let (authority, cert, tok, name) = (authority.clone(), cert.clone(), tok.clone(), name.clone());
            Box::pin(async move {
                if once.swap(true, Ordering::SeqCst) {
                    return;
                }
                let mut lock = db.begin().await.unwrap();
                sqlx::query("SELECT 1 FROM branches WHERE project_id = $1 AND name = 'hold' FOR UPDATE").bind(pid).execute(&mut *lock).await.unwrap();
                std::thread::spawn(move || {
                    let api = Api::at(&authority, &cert);
                    let r = api.post_json(
                        Some(&tok),
                        &format!("/v1/projects/{name}/push"),
                        &json!({"updates": [{"branch": "hold", "expected": main0.hex(), "new": snap.hex()}], "force": false}),
                    );
                    let _ = tx_done.send(r);
                });
                let until = Instant::now() + Duration::from_secs(30);
                loop {
                    let waiting: i64 = sqlx::query_scalar(
                        "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock' AND query LIKE 'UPDATE branches SET target%'",
                    )
                    .fetch_one(&db)
                    .await
                    .unwrap();
                    if waiting > 0 {
                        break;
                    }
                    assert!(Instant::now() < until, "the push never reached its branch update");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                // The row is released when GC is done (or after 8 s, were GC to wait for the push).
                tokio::spawn(async move {
                    let _ = tokio::time::timeout(Duration::from_secs(8), release.notified()).await;
                    lock.rollback().await.unwrap();
                });
            })
        }))
    };
    gc(120_000, Some(hook)).unwrap();
    assert!(once.load(Ordering::SeqCst), "GC reached its switch");
    release.notify_one();

    let r = rx_done.recv_timeout(Duration::from_secs(60)).expect("the push answers");
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["results"][0]["ok"], true, "the push moved `hold`: {}", String::from_utf8_lossy(&r.body));
    assert_eq!(api.tips(Some(&admin_tok), &p.name).unwrap().branches["hold"], snap);

    // What the branch holds can be read.
    let r = api.get(Some(&admin_tok), &format!("/v1/projects/{}/q/file?rev=hold&path=src/gc-race-1881.txt", p.name));
    assert_eq!(r.status, 200, "`hold` points at objects GC deleted: {}", String::from_utf8_lossy(&r.body).chars().take(300).collect::<String>());
    assert!(String::from_utf8_lossy(&r.body).contains(CONTENT.trim_end()), "the file's content is served");
}

#[test]
fn bug_1881_pr_writer_and_reverse_switch_order_serialize_with_gc() {
    let th = TestHub::start();
    let p = setup_project(&th);
    let api = th.api();
    let pid = project_id(&th, &p.name);
    let admin_tok = p.admin.token();
    let h = th.hub();
    let main0 = api.tips(Some(&admin_tok), &p.name).unwrap().branches["main"];
    let push = |api: &Api, tok: &str, branch: &str, expected: Option<ObjectId>, new: Option<ObjectId>, force: bool| {
        api.post_json(
            Some(tok),
            &format!("/v1/projects/{}/push", p.name),
            &json!({"updates": [{"branch": branch, "expected": expected.map(|e| e.hex()), "new": new.map(|e| e.hex())}], "force": force}),
        )
    };

    // Open a PR on an initial branch `feat1`.
    let mut c1 = Craft::new(&api, &p.admin, &p.name, "main");
    c1.file("src/pr-1881.txt", "v1\n");
    let (_, r) = c1.push_edited("feat1", None, |_| {});
    assert_eq!(r.json()["results"][0]["ok"], true);
    let pr = api
        .post_json(Some(&admin_tok), &format!("/v1/projects/{}/prs", p.name), &json!({"head": "feat1", "title": "gc race pr"}))
        .json();
    let pr_id = pr["id"].as_str().unwrap().to_string();

    // Create an unreferenced snapshot `snap2` past retention.
    const PR_CONTENT: &str = "RV-CORE2-BUG-1881-PR-REV-99a1b2c3\n";
    let mut c2 = Craft::new(&api, &p.admin, &p.name, "main");
    c2.file("src/pr-1881.txt", PR_CONTENT);
    let (snap2, r) = c2.push_edited("tmp-pr-1881", None, |_| {});
    assert_eq!(r.json()["results"][0]["ok"], true);
    let r = push(&api, &admin_tok, "tmp-pr-1881", Some(snap2), None, true);
    assert_eq!(r.json()["results"][0]["ok"], true);

    let gc = |offset: i64, hook: Option<SwitchHook>| {
        th.rt.block_on(pack_gc::run_project(
            &h,
            pid,
            &Options {
                min_packs_to_merge: 1,
                run_gc: true,
                retention_window_ms: 60_000,
                pack_grace_ms: 0,
                now_offset_ms: offset,
                before_switch: hook,
                ..Options::default()
            },
        ))
    };
    gc(0, None).unwrap();

    // Order A (non-push root writer commits during GC switch): `add_revision`
    // enters its transaction (`FOR SHARE` on the GC epoch) and waits on the PR
    // row while GC reaches its switch; GC waits for it and keeps `snap2`.
    let (tx_pr, rx_pr) = std::sync::mpsc::channel::<Reply>();
    let release_pr = Arc::new(tokio::sync::Notify::new());
    let once_pr = Arc::new(AtomicBool::new(false));
    let hook = {
        let (db, release, once) = (h.db.clone(), release_pr.clone(), once_pr.clone());
        let (authority, cert, tok, name, pr_id) = (th.authority(), th.cert_pem.clone(), admin_tok.clone(), p.name.clone(), pr_id.clone());
        SwitchHook(Arc::new(move || {
            let (db, release, once, tx_pr) = (db.clone(), release.clone(), once.clone(), tx_pr.clone());
            let (authority, cert, tok, name, pr_id) = (authority.clone(), cert.clone(), tok.clone(), name.clone(), pr_id.clone());
            Box::pin(async move {
                if once.swap(true, Ordering::SeqCst) {
                    return;
                }
                let mut lock = db.begin().await.unwrap();
                sqlx::query("SELECT 1 FROM prs WHERE project_id = $1 AND id = $2 FOR UPDATE")
                    .bind(pid)
                    .bind(&pr_id)
                    .execute(&mut *lock)
                    .await
                    .unwrap();
                std::thread::spawn(move || {
                    let api = Api::at(&authority, &cert);
                    let r = api.post_json(
                        Some(&tok),
                        &format!("/v1/projects/{name}/prs/{pr_id}/revisions"),
                        &json!({"head": snap2.hex()}),
                    );
                    let _ = tx_pr.send(r);
                });
                let until = Instant::now() + Duration::from_secs(30);
                loop {
                    let waiting: i64 = sqlx::query_scalar(
                        "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock' AND query LIKE 'UPDATE prs SET revision%'",
                    )
                    .fetch_one(&db)
                    .await
                    .unwrap();
                    if waiting > 0 {
                        break;
                    }
                    assert!(Instant::now() < until, "add_revision never reached its prs update");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                tokio::spawn(async move {
                    let _ = tokio::time::timeout(Duration::from_secs(6), release.notified()).await;
                    lock.rollback().await.unwrap();
                });
            })
        }))
    };
    gc(120_000, Some(hook)).unwrap();
    release_pr.notify_one();
    let r = rx_pr.recv_timeout(Duration::from_secs(60)).expect("PR revision answers");
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let diff_r = api.get(Some(&admin_tok), &format!("/v1/projects/{}/prs/{pr_id}/diff", p.name));
    assert_eq!(diff_r.status, 200, "PR diff points at objects GC deleted: {}", String::from_utf8_lossy(&diff_r.body));
    assert!(String::from_utf8_lossy(&diff_r.body).contains(PR_CONTENT.trim_end()));

    // Order B (GC switch commits after push checked objects, before push commits):
    // GC holds `access_epochs FOR UPDATE` while blocked on `packs FOR UPDATE`;
    // a push of `hold2` to an expired unreferenced `snap3` passes its pre-tx
    // checks and blocks on `access_epochs FOR SHARE`. Once GC finishes its
    // switch and sweeps `snap3`, the push sees `GcEpochChanged`, reruns from
    // scratch, and refuses cleanly instead of moving `hold2` to deleted objects.
    let r = push(&api, &admin_tok, "hold2", None, Some(main0), false);
    assert_eq!(r.json()["results"][0]["ok"], true);
    let mut c3 = Craft::new(&api, &p.admin, &p.name, "main");
    c3.file("src/reverse-1881.txt", "RV-CORE2-BUG-1881-REV-ORDER\n");
    let (snap3, r) = c3.push_edited("tmp-rev-1881", None, |_| {});
    assert_eq!(r.json()["results"][0]["ok"], true);
    let r = push(&api, &admin_tok, "tmp-rev-1881", Some(snap3), None, true);
    assert_eq!(r.json()["results"][0]["ok"], true);
    gc(240_000, None).unwrap();

    let snap_lock = th.rt.block_on(async {
        let mut tx = h.db.begin().await.unwrap();
        sqlx::query("SELECT 1 FROM snapshots WHERE project_id = $1 AND id = $2 FOR SHARE")
            .bind(pid)
            .bind(snap3.hex())
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        tx
    });
    let h_gc = h.clone();
    let gc_handle = th.rt.spawn(async move {
        pack_gc::run_project(
            &h_gc,
            pid,
            &Options {
                min_packs_to_merge: 1,
                run_gc: true,
                retention_window_ms: 60_000,
                pack_grace_ms: 0,
                now_offset_ms: 360_000,
                ..Options::default()
            },
        )
        .await
    });
    th.rt.block_on(async {
        let until = Instant::now() + Duration::from_secs(30);
        loop {
            let waiting: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock' AND query LIKE 'DELETE FROM snapshots%'",
            )
            .fetch_one(&h.db)
            .await
            .unwrap();
            if waiting > 0 {
                break;
            }
            assert!(Instant::now() < until, "GC never reached DELETE FROM snapshots");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    });

    let (tx_push, rx_push) = std::sync::mpsc::channel::<Reply>();
    {
        let (authority, cert, tok, name) = (th.authority(), th.cert_pem.clone(), admin_tok.clone(), p.name.clone());
        std::thread::spawn(move || {
            let api = Api::at(&authority, &cert);
            let r = api.post_json(
                Some(&tok),
                &format!("/v1/projects/{name}/push"),
                &json!({"updates": [{"branch": "hold2", "expected": main0.hex(), "new": snap3.hex()}], "force": false}),
            );
            let _ = tx_push.send(r);
        });
    }
    th.rt.block_on(async {
        let until = Instant::now() + Duration::from_secs(30);
        loop {
            let waiting: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock' AND query LIKE 'SELECT epoch FROM access_epochs%FOR SHARE%'",
            )
            .fetch_one(&h.db)
            .await
            .unwrap();
            if waiting > 0 {
                break;
            }
            assert!(Instant::now() < until, "push never reached guard_root_write FOR SHARE");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        snap_lock.rollback().await.unwrap();
    });
    let rep = th.rt.block_on(gc_handle).unwrap().unwrap();
    assert!(rep.packed_objects_deleted + rep.loose_objects_deleted > 0, "GC swept snap3: {rep:?}");

    let r = rx_push.recv_timeout(Duration::from_secs(60)).expect("push answers after retry");
    assert_ne!(r.status, 500, "push never 500s: {}", String::from_utf8_lossy(&r.body));
    assert_ne!(r.json()["results"][0]["ok"], json!(true), "push without objects does not point hold2 at swept snap3: {}", String::from_utf8_lossy(&r.body));
    assert_eq!(api.tips(Some(&admin_tok), &p.name).unwrap().branches["hold2"], main0);
}

/// A request body that sends `left` bytes, then stops until its gate
/// closes (a client that went quiet).
struct Stalls {
    left: usize,
    gate: std::sync::mpsc::Receiver<()>,
    sent: Arc<std::sync::atomic::AtomicUsize>,
}

impl std::io::Read for Stalls {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.left == 0 {
            let _ = self.gate.recv();
            return Err(std::io::Error::other("the client went away"));
        }
        let n = buf.len().min(self.left).min(64 << 10);
        buf[..n].fill(b' ');
        self.left -= n;
        self.sent.fetch_add(n, Ordering::Relaxed);
        Ok(n)
    }
}

/// `docs/HUB.md` §13.25, `limits::body`: one client holds at most a quarter
/// of each pool of request bodies, "so one cannot refuse the others". The
/// client is the device, or the agent session: a person's agent sessions
/// (anyone signed in mints as many as they like) each have a quarter of
/// their own, with nothing over them all (rates have the person's bucket).
/// Five sessions of one person, each sending 4 MiB of an upload slowly,
/// hold the whole signed-in pool, and everyone else's upload is `503 busy`.
#[test]
#[ignore = "BUG-1882: one person's agent sessions hold the whole signed-in pool of request bodies"]
fn bug_1882_one_persons_agent_sessions_take_the_whole_signed_in_body_pool() {
    use veil_server::limits::Settings;
    let hub = TestHub::start_with_limits(Settings { request_memory: 64 << 20, ..TestHub::limits() });
    let api = hub.api();
    let sign_up = |prefix: &str| api.login(&veil_core::Identity::generate("rv-core2"), Some(&unique(prefix))).expect("signs up");
    let project = |token: &str| {
        let name = unique("rvlim");
        let r = api.post(Some(token), &format!("/v1/projects/{name}"), b"", false);
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        name
    };
    let (mallory, victim) = (sign_up("rvmal"), sign_up("rvvic"));
    let (pm, pv) = (project(&mallory), project(&victim));
    let sessions: Vec<String> = (0..5)
        .map(|i| {
            let r = api.post_json(
                Some(&mallory),
                "/v1/sessions/agent",
                &json!({"project": pm, "attribution": {"agent": "rv-core2/1", "task": format!("BUG-1882-{i}")}}),
            );
            assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
            r.json()["token"].as_str().unwrap().to_string()
        })
        .collect();
    // A 2 MiB blob that does not compress: an upload past the small bodies' reserve.
    let blob = |seed: u64| {
        let mut x = seed | 1;
        let bytes: Vec<u8> = (0..2usize << 20)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect();
        let raw = veil_core::object::Object::Blob(bytes).encode();
        (ObjectId::hash(&raw), raw)
    };
    let h = hub.hub();
    let signed_in_kib = || h.limits.bodies.held_kib().0;
    // Each token in turn sends 4 MiB of an upload of unknown length (8 MiB held), and stops.
    let stall = |tokens: &[String]| {
        let mut gates = Vec::new();
        let mut threads = Vec::new();
        for t in tokens {
            let sent = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let (tx, gate) = std::sync::mpsc::channel::<()>();
            let (api, sent2, token, path) = (hub.api(), sent.clone(), t.clone(), format!("/v1/projects/{pm}/objects"));
            threads.push(std::thread::spawn(move || drop(api.post_reader_as(Some(&token), &path, Stalls { left: 4 << 20, gate, sent: sent2 }))));
            gates.push(tx);
            // Until the server took it all in, or refused it (nothing more is sent for a second).
            let t = Instant::now();
            let mut last = (0, Instant::now());
            while t.elapsed() < Duration::from_secs(60) && last.1.elapsed() < Duration::from_secs(1) {
                std::thread::sleep(Duration::from_millis(50));
                let s = sent.load(Ordering::Relaxed);
                if s != last.0 {
                    last = (s, Instant::now());
                }
            }
        }
        (gates, threads)
    };

    // One device: five such bodies, one after another, hold at most its quarter
    // (10 MiB of 40: the first is held, the others refused), and others upload.
    let (gates, threads) = stall(&vec![mallory.clone(); 5]);
    let held = signed_in_kib();
    assert!(held > 0 && held <= 10 << 10, "one device holds at most a quarter of the signed-in pool: {held} KiB");
    let r = api.upload(&victim, &pv, &[blob(1)]);
    assert_eq!(r.status, 200, "beside one device's stalled uploads: {}", String::from_utf8_lossy(&r.body));
    drop(gates);
    for t in threads {
        t.join().unwrap();
    }
    let t = Instant::now();
    while signed_in_kib() > 0 && t.elapsed() < Duration::from_secs(60) {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(signed_in_kib(), 0, "the stalled bodies were let go");

    // The same person's five agent sessions: the same five bodies.
    let (gates, threads) = stall(&sessions);
    let held = signed_in_kib();
    let r = api.upload(&victim, &pv, &[blob(2)]);
    let status = r.status;
    drop(gates);
    for t in threads {
        t.join().unwrap();
    }
    assert_eq!(
        status,
        200,
        "one person's agent sessions hold {held} KiB of the 40960 KiB signed-in pool, and another person's 2 MiB upload is refused: {}",
        String::from_utf8_lossy(&r.body)
    );
    assert!(held <= 10 << 10, "one person holds at most a quarter of the signed-in pool: {held} KiB");
}

/// Every queued entry lands once or is refused, whatever servers stop. A
/// `merging` row has no owner: only a server's start gives it back to the
/// queue (`landing::resume`, which resets every server's). When the server
/// whose worker held it goes away while the others keep running, nothing
/// ever answers it: the ticket stays `queued`, and counts against its
/// person's outstanding landings.
#[test]
#[ignore = "BUG-1883: a merging entry of a server that went away is never answered"]
fn bug_1883_a_merging_entry_of_a_server_that_went_away_is_never_answered() {
    let a = TestHub::start();
    let p = setup_project(&a);
    let b = TestHub::beside(&a);
    let (api_a, api_b) = (a.api(), b.api());
    let pid = project_id(&a, &p.name);
    let (dev_tok, admin_tok) = (p.dev.token(), p.admin.token());
    let db = b.hub().db.clone();
    const FILE: &str = "src/merge-1883.txt";
    let text = |second: &str, last: &str| {
        let mut lines: Vec<String> = (0..30).map(|i| format!("line {i} of bug 1883")).collect();
        lines[2] = second.to_string();
        lines[28] = last.to_string();
        lines.join("\n") + "\n"
    };
    let land_as_admin = |content: String| {
        let base = api_a.tips(Some(&admin_tok), &p.name).unwrap().branches["main"];
        let r = api_a.post_json(
            Some(&admin_tok),
            &format!("/v1/projects/{}/land", p.name),
            &json!({"onto": "main", "base": base.hex(), "edits": [put(FILE, &content)], "wait": true}),
        );
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        assert_eq!(r.json()["state"], "landed", "{}", r.json());
    };
    land_as_admin(text("two", "twenty-eight"));
    // dev changes line 2 on that tip; the admin lands a change of line 28 first.
    let base = api_a.tips(Some(&dev_tok), &p.name).unwrap().branches["main"];
    let r = api_a.post_json(
        Some(&dev_tok),
        &format!("/v1/projects/{}/changes", p.name),
        &json!({"base": base.hex(), "edits": [put(FILE, &text("TWO BY DEV", "twenty-eight"))]}),
    );
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let change: ObjectId = serde_json::from_value(r.json()["snapshot"].clone()).unwrap();
    land_as_admin(text("two", "TWENTY-EIGHT BY ADMIN"));

    // The merge worker's commit waits (its insert into `origins`), so that the
    // server stops while the entry is `merging`.
    let mut lock = b.rt.block_on(db.begin()).unwrap();
    b.rt.block_on(sqlx::query("LOCK TABLE origins IN EXCLUSIVE MODE").execute(&mut *lock)).unwrap();
    let r = api_a.post_json(
        Some(&dev_tok),
        &format!("/v1/projects/{}/land", p.name),
        &json!({"onto": "main", "snapshot": change.hex(), "wait": false}),
    );
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["state"], "queued", "{}", r.json());
    let ticket = r.json()["ticket"].as_str().unwrap().to_string();
    let state = || -> String {
        b.rt.block_on(sqlx::query_scalar("SELECT state FROM landing_queue WHERE project_id = $1 AND ticket = $2").bind(pid).bind(&ticket).fetch_one(&db)).unwrap()
    };
    let until = Instant::now() + Duration::from_secs(30);
    loop {
        let waiting: i64 = b
            .rt
            .block_on(
                sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock' AND query LIKE 'INSERT INTO origins%'")
                    .fetch_one(&db),
            )
            .unwrap();
        if state() == "merging" && waiting > 0 {
            break;
        }
        assert!(Instant::now() < until, "the entry was handed to a merge worker: {}", state());
        std::thread::sleep(Duration::from_millis(50));
    }
    // The server with the worker goes away; the other keeps running.
    drop(api_a);
    drop(a);
    b.rt.block_on(lock.rollback()).unwrap();
    assert_eq!(state(), "merging", "the worker's commit went with its server");

    // The entry's submitter asks the server that is left.
    let until = Instant::now() + Duration::from_secs(45);
    let done = loop {
        let r = api_b.get(Some(&dev_tok), &format!("/v1/projects/{}/land/{ticket}", p.name));
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        let v = r.json();
        if v["state"] != "queued" || Instant::now() > until {
            break v;
        }
    };
    assert_eq!(done["state"], "landed", "45 s after its server went away the entry is still `{}` in the queue: {done}", state());
}
