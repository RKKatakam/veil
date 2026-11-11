//! Whole-codebase review, 2026-11-10: what changes server state (the landing
//! service, review rules, automatic bisect and revert). Each test here shows
//! one guarantee of `CLAUDE.md` / `docs/VISIBILITY.md` failing; it stays
//! ignored, with its `docs/BUGS.md` row, until the bug is fixed.

use std::time::Duration;

use serde_json::{json, Value};
use veil_core::ObjectId;

use crate::support::*;

fn body(r: &Reply) -> String {
    String::from_utf8_lossy(&r.body).into_owned()
}

fn post_check(hub: &TestHub, token: &str, project: &str, snapshot: ObjectId, name: &str, state: &str) -> Reply {
    hub.api().post_json(
        Some(token),
        &format!("/v1/projects/{project}/checks"),
        &json!({"snapshot": snapshot.hex(), "name": name, "state": state}),
    )
}

fn bisect_status(hub: &TestHub, token: &str, project: &str) -> Reply {
    hub.api().get(Some(token), &format!("/v1/projects/{project}/bisect/main"))
}

fn tip(hub: &TestHub, token: &str, project: &str) -> ObjectId {
    hub.api().tips(Some(token), project).unwrap().branches["main"]
}

fn file_on_main(hub: &TestHub, token: &str, project: &str, path: &str) -> Reply {
    hub.api().get(Some(token), &format!("/v1/projects/{project}/q/file?path={path}"))
}

/// A change of `path` on the tip of `main`, as `token` sees it: the reply of
/// `POST …/changes`.
fn change(hub: &TestHub, token: &str, project: &str, path: &str, text: &str, desc: &str) -> Reply {
    let base = tip(hub, token, project);
    hub.api().post_json(
        Some(token),
        &format!("/v1/projects/{project}/changes"),
        &json!({"base": base.hex(), "description": desc, "edits": [{"path": path, "put": {"text": text}}]}),
    )
}

fn land(hub: &TestHub, token: &str, project: &str, snapshot: &str) -> Reply {
    hub.api().post_json(Some(token), &format!("/v1/projects/{project}/land"), &json!({"onto": "main", "snapshot": snapshot, "wait": true}))
}

/// `path` changed and landed on `main` by `token`: the real tip it left.
fn land_edit(hub: &TestHub, p: &Project, token: &str, path: &str, text: &str, desc: &str) -> ObjectId {
    let c = change(hub, token, &p.name, path, text, desc);
    assert_eq!(c.status, 200, "{}", body(&c));
    let l = land(hub, token, &p.name, c.json()["snapshot"].as_str().unwrap());
    assert_eq!(l.status, 200, "{}", body(&l));
    assert_eq!(l.json()["state"], "landed", "{}", body(&l));
    tip(hub, &p.admin.token(), &p.name)
}

fn project_id(hub: &TestHub, name: &str) -> i64 {
    let h = hub.hub();
    hub.rt.block_on(sqlx::query_scalar::<_, i64>("SELECT id FROM projects WHERE name = $1").bind(name).fetch_one(&h.db)).unwrap()
}

/// `main` protected, `ci/src` required on it (its paths: `src/`), automatic
/// revert as the default leaves it (on). The fixtures land without a PR, so
/// the review rules ask for no approval here; a revert is never reviewed
/// whatever they say (`bisect::revert_confirmed_culprit` queues it itself).
const RULES_CI: &str = "[branches.main]\nprotected = true\nrequired_checks = [\"ci/src\"]\n\n[checks.\"ci/src\"]\npaths = [\"src/\"]\n\n\
                        [review]\nlow = { approvals = 0 }\nnormal = { approvals = 0 }\nhigh = { approvals = 0 }\n";

/// The guarantee: nobody changes a folder they cannot write, and what landed
/// on a protected branch stays landed unless someone who may change it says
/// otherwise. `fin` (in `finance`) reads `src/` because it is public, and
/// may not write it. Three check results posted by `fin` make the server
/// revert a developer's landing in `src/`.
#[test]
fn bug_1860_someone_who_cannot_write_a_folder_never_reverts_a_landing_there() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let (admin, dev, fin) = (p.admin.token(), p.dev.token(), p.fin.token());

    let s0 = land_edit(&hub, &p, &admin, ".veilrules", RULES_CI, "protect main, require ci/src");
    let r = post_check(&hub, &admin, &p.name, s0, "ci/src", "pass");
    assert_eq!(r.status, 200, "{}", body(&r));

    // A developer's change in src/ lands.
    const WORK: &str = "pub fn shipped() -> u32 { 1860 }\n";
    let c1 = land_edit(&hub, &p, &dev, "src/shipped_1860.rs", WORK, "ship a feature");
    let f = file_on_main(&hub, &admin, &p.name, "src/shipped_1860.rs");
    assert_eq!((f.status, body(&f).as_str()), (200, WORK));

    // fin may not write src/: their own change of that file is refused.
    let refused = change(&hub, &fin, &p.name, "src/shipped_1860.rs", "gone\n", "not mine to change");
    assert_eq!(refused.status, 403, "{}", body(&refused));

    // fin says the required check failed on the landing, twice (its parent
    // passed above). Whether the server takes or refuses these results, the
    // landing stays.
    let c1_fin = tip(&hub, &fin, &p.name);
    for _ in 0..2 {
        let r = post_check(&hub, &fin, &p.name, c1_fin, "ci/src", "fail");
        assert!(r.status == 200 || r.status == 403, "{} {}", r.status, body(&r));
    }
    // (A revert lands within the second request, or a moment after.)
    let mut now = tip(&hub, &admin, &p.name);
    for _ in 0..40 {
        if now != c1 {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
        now = tip(&hub, &admin, &p.name);
    }
    let st = bisect_status(&hub, &admin, &p.name);
    let f = file_on_main(&hub, &admin, &p.name, "src/shipped_1860.rs");
    assert_eq!(
        (now, f.status),
        (c1, 200),
        "someone with no write access to src/ had the landing there reverted: main moved from {} to {}, bisect: {}",
        c1.short(),
        now.short(),
        body(&st)
    );
}

#[test]
fn bug_1852_1860_ci_runner_sessions_follow_their_minters_write_authority() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let (admin, dev, fin) = (p.admin.token(), p.dev.token(), p.fin.token());

    let _s0 = land_edit(&hub, &p, &admin, ".veilrules", RULES_CI, "protect main, require ci/src");
    let fin_sess = hub
        .api()
        .post_json(Some(&fin), "/v1/sessions/ci", &json!({"project": p.name, "check": "ci/src"}));
    assert_eq!(fin_sess.status, 200, "{}", body(&fin_sess));
    let fin_runner = fin_sess.json()["token"].as_str().unwrap().to_string();

    let dev_sess = hub
        .api()
        .post_json(Some(&dev), "/v1/sessions/ci", &json!({"project": p.name, "check": "ci/src"}));
    assert_eq!(dev_sess.status, 200, "{}", body(&dev_sess));
    let dev_runner = dev_sess.json()["token"].as_str().unwrap().to_string();

    // `fin`'s runner cannot advance `main@tested` for `ci/src`.
    let s0_fin = tip(&hub, &fin_runner, &p.name);
    let r_fin_pass = post_check(&hub, &fin_runner, &p.name, s0_fin, "ci/src", "pass");
    assert_eq!(r_fin_pass.status, 403, "{}", body(&r_fin_pass));
    assert_eq!(hub.api().get(Some(&admin), &format!("/v1/projects/{}/tested/main", p.name)).status, 404);

    // `dev`'s runner (minted by someone who writes `src/`, though the runner itself
    // is refused code writes by `not_runner()`) advances `main@tested` and drives bisect.
    let s0_dev = tip(&hub, &dev_runner, &p.name);
    let r_dev_pass = post_check(&hub, &dev_runner, &p.name, s0_dev, "ci/src", "pass");
    assert_eq!(r_dev_pass.status, 200, "{}", body(&r_dev_pass));
    assert_eq!(hub.api().get(Some(&admin), &format!("/v1/projects/{}/tested/main", p.name)).status, 200);

    let c1 = land_edit(&hub, &p, &dev, "src/runner_check.rs", "pub fn broken() {}\n", "land src change");
    let c1_fin = tip(&hub, &fin_runner, &p.name);
    for _ in 0..2 {
        let r = post_check(&hub, &fin_runner, &p.name, c1_fin, "ci/src", "fail");
        assert_eq!(r.status, 403, "{}", body(&r));
    }
    assert_eq!(tip(&hub, &admin, &p.name), c1, "fin's runner never reverts src/");

    let c1_dev = tip(&hub, &dev_runner, &p.name);
    for _ in 0..2 {
        let r = post_check(&hub, &dev_runner, &p.name, c1_dev, "ci/src", "fail");
        assert_eq!(r.status, 200, "{}", body(&r));
    }
    let mut now = tip(&hub, &admin, &p.name);
    for _ in 0..40 {
        if now != c1 {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
        now = tip(&hub, &admin, &p.name);
    }
    assert_ne!(now, c1, "dev's runner still drives bisect and reverts the failing src/ landing");
}

/// The guarantee: a landing onto a protected branch meets the review rules
/// by every route (`docs/HUB.md` §13.24). With the default rules a change of
/// source code needs one approval; `dev` has none. Landing it directly is
/// refused; the same change put on an embargo line of `dev`'s own group and
/// released by `dev` lands on `main` with no approval at all.
#[test]
#[ignore = "BUG-1861: an embargo's release lands on a protected branch with no approval: any group member lands unreviewed changes by embargoing and releasing them"]
fn bug_1861_an_embargo_release_never_lands_an_unapproved_change_on_a_protected_branch() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let (admin, dev) = (p.admin.token(), p.dev.token());

    // main is protected, with the default review rules.
    land_edit(&hub, &p, &admin, ".veilrules", "[branches.main]\nprotected = true\n", "protect main");
    let before = tip(&hub, &admin, &p.name);

    // Landing a change of source code without an approval is refused.
    let c = change(&hub, &dev, &p.name, "src/direct_1861.rs", "pub fn direct() {}\n", "no review");
    assert_eq!(c.status, 200, "{}", body(&c));
    let l = land(&hub, &dev, &p.name, c.json()["snapshot"].as_str().unwrap());
    assert_eq!(l.status, 409, "{}", body(&l));
    assert!(body(&l).contains("not ready to land") && body(&l).contains("approval"), "{}", body(&l));
    assert_eq!(tip(&hub, &admin, &p.name), before);

    // The same kind of change as an embargo of dev's own group: pushing the
    // embargo line is fine (it is hidden, and not main).
    const UNREVIEWED: &str = "pub fn unreviewed() -> u32 { 1861 }\n";
    let dir = p.dev.dir("embargo-1861");
    p.dev.ok(p.dev.home.path(), &["clone", &hub.url(&p.name), dir.to_str().unwrap()]);
    write_files(&dir, &[("src/unreviewed_1861.rs", UNREVIEWED)]);
    p.dev.ok(&dir, &["commit", "--no-advance", "-m", "nobody reviewed this"]);
    let out = p.dev.ok(&dir, &["merge", "@-", "--into", "main", "--embargo-for", "devs", "-m", "embargoed, unreviewed"]);
    let eid = out
        .split_whitespace()
        .map(|w| w.trim_end_matches(':'))
        .find(|w| w.len() == 10 && w.bytes().all(|b| b.is_ascii_hexdigit()))
        .unwrap_or_else(|| panic!("no embargo id in {out}"))
        .to_string();
    p.dev.ok(&dir, &["push"]);
    assert_eq!(tip(&hub, &admin, &p.name), before, "an embargo line is not main");

    // dev releases it. Whether the release is refused or waits for an
    // approval, main never gets the unapproved change.
    let _ = p.dev.run(&dir, &["embargo", "release", &eid, "--yes"]);
    let _ = p.dev.run(&dir, &["push"]);
    let mut f = file_on_main(&hub, &admin, &p.name, "src/unreviewed_1861.rs");
    for _ in 0..40 {
        if f.status == 200 {
            break;
        }
        let _ = hub.rt.block_on(veil_server::embargo::release_due(&hub.hub()));
        std::thread::sleep(Duration::from_millis(150));
        f = file_on_main(&hub, &admin, &p.name, "src/unreviewed_1861.rs");
    }
    let now = tip(&hub, &admin, &p.name);
    assert_eq!(
        (f.status, now),
        (404, before),
        "a change no one approved landed on protected main through an embargo's release: {}",
        body(&f)
    );
}

/// The guarantee: a confirmed culprit is reverted (`docs/HUB.md` §13.36,
/// guarantees 2 and 5, "safe across two servers"). The server asks for a
/// second failing run of the culprit; the runner delivers it while another
/// request (or another server) is in its own step of this branch's bisect,
/// holding `bisect_leases`. The result is stored (`200`) and never counted:
/// the bisect waits for ever for a result it already has, and while it
/// waits no other bisect starts on the branch.
#[test]
fn bug_1862_a_check_result_that_arrives_during_another_bisect_step_still_counts() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let (admin, dev) = (p.admin.token(), p.dev.token());
    let pid = project_id(&hub, &p.name);
    let h = hub.hub();

    let s0 = land_edit(&hub, &p, &admin, ".veilrules", RULES_CI, "protect main, require ci/src");
    let r = post_check(&hub, &admin, &p.name, s0, "ci/src", "pass");
    assert_eq!(r.status, 200, "{}", body(&r));
    let c1 = land_edit(&hub, &p, &dev, "src/broken_1862.rs", "pub fn broken() {}\n", "break the build");

    // The first failure: the culprit is found, and the server asks for its
    // confirmation run.
    let r = post_check(&hub, &admin, &p.name, c1, "ci/src", "fail");
    assert_eq!(r.status, 200, "{}", body(&r));
    let st: Value = bisect_status(&hub, &admin, &p.name).json();
    assert_eq!((st["phase"].as_str(), &st["culprit"], &st["probes"]), (Some("confirming"), &json!(c1.hex()), &json!([c1.hex()])), "{st}");

    // Another step of this branch's bisect is running (as `acquire_lease`
    // takes the lease for every report of a required check)...
    hub.rt
        .block_on(
            sqlx::query(
                "INSERT INTO bisect_leases (project_id, branch, holder, epoch, expires_at) \
                 VALUES ($1, 'main', 'another-request', 1, (extract(epoch FROM clock_timestamp()) * 1000)::BIGINT + 4000) \
                 ON CONFLICT (project_id, branch) DO UPDATE SET holder = EXCLUDED.holder, epoch = bisect_leases.epoch + 1, expires_at = EXCLUDED.expires_at",
            )
            .bind(pid)
            .execute(&h.db),
        )
        .unwrap();
    // ...when the confirmation run's failure arrives: accepted.
    let r = post_check(&hub, &admin, &p.name, c1, "ci/src", "fail");
    assert_eq!(r.status, 200, "{}", body(&r));
    // The other step ends, as `release_lease` ends it.
    hub.rt
        .block_on(sqlx::query("UPDATE bisect_leases SET expires_at = 0 WHERE project_id = $1 AND branch = 'main' AND holder = 'another-request'").bind(pid).execute(&h.db))
        .unwrap();

    // Both runs the server asked for were delivered: the culprit is reverted.
    let mut st: Value = bisect_status(&hub, &admin, &p.name).json();
    for _ in 0..50 {
        if st["phase"] == "reverted" {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
        st = bisect_status(&hub, &admin, &p.name).json();
    }
    assert_eq!(st["phase"], "reverted", "the culprit failed twice and its parent passed, and every result was accepted: {st}");
    assert_ne!(tip(&hub, &admin, &p.name), c1, "the revert landed");
}

#[test]
fn bug_1862_a_first_failure_during_another_bisect_step_still_starts_bisect() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let (admin, dev) = (p.admin.token(), p.dev.token());
    let pid = project_id(&hub, &p.name);
    let h = hub.hub();

    let s0 = land_edit(&hub, &p, &admin, ".veilrules", RULES_CI, "protect main, require ci/src");
    assert_eq!(post_check(&hub, &admin, &p.name, s0, "ci/src", "pass").status, 200);
    let c1 = land_edit(&hub, &p, &dev, "src/first_fail_1862.rs", "pub fn broken() {}\n", "break");

    // Hold `bisect_leases` when the very first failure (after `pending`) arrives.
    hub.rt
        .block_on(
            sqlx::query(
                "INSERT INTO bisect_leases (project_id, branch, holder, epoch, expires_at) \
                 VALUES ($1, 'main', 'another-request', 1, (extract(epoch FROM clock_timestamp()) * 1000)::BIGINT + 4000) \
                 ON CONFLICT (project_id, branch) DO UPDATE SET holder = EXCLUDED.holder, epoch = bisect_leases.epoch + 1, expires_at = EXCLUDED.expires_at",
            )
            .bind(pid)
            .execute(&h.db),
        )
        .unwrap();
    assert_eq!(post_check(&hub, &admin, &p.name, c1, "ci/src", "pending").status, 200);
    assert_eq!(post_check(&hub, &admin, &p.name, c1, "ci/src", "fail").status, 200);
    hub.rt
        .block_on(sqlx::query("UPDATE bisect_leases SET expires_at = 0 WHERE project_id = $1 AND branch = 'main' AND holder = 'another-request'").bind(pid).execute(&h.db))
        .unwrap();

    let mut st = bisect_status(&hub, &admin, &p.name);
    for _ in 0..50 {
        if st.status == 200 {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
        st = bisect_status(&hub, &admin, &p.name);
    }
    assert_eq!(st.status, 200, "{}", body(&st));
    let stj: Value = st.json();
    assert_eq!(stj["phase"], "confirming", "{stj}");
    assert_eq!(stj["culprit"], c1.hex(), "{stj}");

    // Runner posts `pending` before the confirming `fail`: must still count as run 2 and revert!
    assert_eq!(post_check(&hub, &admin, &p.name, c1, "ci/src", "pending").status, 200);
    assert_eq!(post_check(&hub, &admin, &p.name, c1, "ci/src", "fail").status, 200);
    let mut stj: Value = bisect_status(&hub, &admin, &p.name).json();
    for _ in 0..50 {
        if stj["phase"] == "reverted" {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
        stj = bisect_status(&hub, &admin, &p.name).json();
    }
    assert_eq!(stj["phase"], "reverted", "{stj}");
    assert_ne!(tip(&hub, &admin, &p.name), c1);
}

/// The guarantee: a request runs again only while nothing it did was
/// committed (`db::retry_requests`), so no push, and no landing it queues,
/// happens twice. `sync::push_with` runs the push in a task of its own
/// (BUG-1399), wrapped in `limits::in_request` (BUG-1668), which carries the
/// request's landing bounds and bulkhead places into that task and not
/// `db::COMMITTED`: the push's commit is never noted, and a retryable
/// database error after it (YugabyteDB's "Restart read required" on the
/// read of the ticket in `landing::wait`, a cancelled statement) runs the
/// whole push again. This test runs the real middleware over a route that
/// does its work as `push_with` does (a transaction, then a statement that
/// fails once with a retryable error), in the request's task and then in a
/// task spawned through `limits::in_request`.
#[test]
fn bug_1863_what_a_push_committed_in_its_own_task_is_never_run_again() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use axum::{body::Body, extract::State, http::Request, routing::post, Router};
    use tower::ServiceExt;
    use veil_server::{db, error::Error, limits, Hub};

    type Shared = (Arc<Hub>, Arc<AtomicUsize>, String, bool);

    /// One run of the request's work: a committed row, then (the first
    /// time) a statement that fails with a retryable error.
    async fn work(hub: &Hub, runs: &AtomicUsize, key: &str) -> Result<(), Error> {
        let n = runs.fetch_add(1, Ordering::SeqCst);
        let key = key.to_string();
        db::transaction(&hub.db, db::Isolation::ReadCommitted, move |c| {
            let key = key.clone();
            Box::pin(async move {
                // (Not expired: every sign-in deletes the expired ones.)
                sqlx::query("INSERT INTO challenges (challenge, signing_key, expires_at) VALUES ($1, $2, $3)")
                    .bind(format!("{key}-{n}"))
                    .bind(&key)
                    .bind(veil_core::now_millis() + 3_600_000)
                    .execute(&mut *c)
                    .await?;
                Ok(())
            })
        })
        .await?;
        if n == 0 {
            sqlx::query("DO $$ BEGIN RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'a read to restart'; END $$").execute(&hub.db).await?;
        }
        Ok(())
    }

    async fn route(State((hub, runs, key, own_task)): State<Shared>) -> Result<&'static str, Error> {
        if own_task {
            let h = hub.clone();
            // As `sync::push_with` does.
            tokio::spawn(limits::in_request(&hub, async move { work(&h, &runs, &key).await })).await.map_err(|e| Error::Other(e.into()))??;
        } else {
            work(&hub, &runs, &key).await?;
        }
        Ok("done")
    }

    let hub = TestHub::start();
    let h = hub.hub();
    let outcome = |own_task: bool| -> (usize, i64) {
        let runs = Arc::new(AtomicUsize::new(0));
        let key = unique("rv1863");
        let app = Router::new()
            .route("/work", post(route))
            .with_state((h.clone(), runs.clone(), key.clone(), own_task))
            .layer(axum::middleware::from_fn(db::retry_requests));
        let _ = hub.rt.block_on(app.oneshot(Request::post("/work").body(Body::empty()).unwrap())).unwrap();
        let rows: i64 = hub.rt.block_on(sqlx::query_scalar("SELECT COUNT(*) FROM challenges WHERE signing_key = $1").bind(&key).fetch_one(&h.db)).unwrap();
        (runs.load(Ordering::SeqCst), rows)
    };
    // In the request's own task the commit is noted: one run, one row.
    assert_eq!(outcome(false), (1, 1), "(runs, rows committed) in the request's task");
    // In the task a push runs in: the same.
    assert_eq!(outcome(true), (1, 1), "(runs, rows committed) in a task spawned through limits::in_request: the request ran again after its commit");

    // Before any commit in the spawned task, a retryable error still retries.
    async fn uncommitted_first(State((hub, runs, _key, _own)): State<Shared>) -> Result<&'static str, Error> {
        let h = hub.clone();
        tokio::spawn(limits::in_request(&hub, async move {
            if runs.fetch_add(1, Ordering::SeqCst) == 0 {
                sqlx::query("DO $$ BEGIN RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'restart before commit'; END $$")
                    .execute(&h.db)
                    .await?;
            }
            Ok::<_, Error>("ok")
        }))
        .await
        .map_err(|e| Error::Other(e.into()))?
    }
    let runs = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route("/uncommitted", post(uncommitted_first))
        .with_state((h.clone(), runs.clone(), String::new(), true))
        .layer(axum::middleware::from_fn(db::retry_requests));
    let resp = hub.rt.block_on(app.oneshot(Request::post("/uncommitted").body(Body::empty()).unwrap())).unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(runs.load(Ordering::SeqCst), 2, "uncommitted retryable failure in spawned task must still retry");
}

fn collect_sse_events(resp: ureq::http::Response<ureq::Body>, want: usize, timeout: Duration) -> Vec<(String, Value)> {
    use std::io::{BufRead, BufReader};
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(resp.into_body().into_reader());
        let mut cur_event = String::new();
        let mut cur_data = String::new();
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    let trimmed = line.trim_end_matches(&['\r', '\n'][..]);
                    if trimmed.is_empty() {
                        if !cur_event.is_empty() || !cur_data.is_empty() {
                            let val = serde_json::from_str(&cur_data).unwrap_or(Value::String(cur_data.clone()));
                            if tx.send((cur_event.clone(), val)).is_err() {
                                break;
                            }
                            cur_event.clear();
                            cur_data.clear();
                        }
                    } else if let Some(ev) = trimmed.strip_prefix("event:") {
                        cur_event = ev.trim().to_string();
                    } else if let Some(d) = trimmed.strip_prefix("data:") {
                        if !cur_data.is_empty() {
                            cur_data.push('\n');
                        }
                        cur_data.push_str(d.trim());
                    }
                }
            }
        }
    });
    let deadline = std::time::Instant::now() + timeout;
    let mut out = Vec::new();
    while out.len() < want {
        let rem = deadline.saturating_duration_since(std::time::Instant::now());
        if rem.is_zero() {
            break;
        }
        match rx.recv_timeout(rem) {
            Ok(item) => out.push(item),
            Err(_) => break,
        }
    }
    out
}

/// BUG-1884 guarantee 1: the server never reverts a revert it made itself.
/// When a later landing builds on a change that bisect reverts, and a second
/// bisect names the server's own revert as the culprit, bisect stops as
/// `needs a person` without reverting, and the authors of both the culprit and
/// the original change are notified through the project's event stream.
#[test]
fn bug_1884_server_never_reverts_a_revert_it_made_itself() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let admin = p.admin.token();
    let dev1 = p.dev.token();

    // Add `p.sec` to `devs` so the original change and the dependent change
    // have distinct authors, and verify both receive `bisect.needs_person`.
    p.admin.ok(&p.dir, &["group", "add", "devs", &p.sec.name]);
    let dev2 = p.sec.token();

    let rules = "[branches.main]\nprotected = true\nrequired_checks = [\"ci/lint\", \"ci/build\"]\n\n\
                 [checks.\"ci/lint\"]\npaths = [\"src/\"]\n\n\
                 [checks.\"ci/build\"]\npaths = [\"src/\"]\n\n\
                 [review]\nnormal = { approvals = 0 }\nhigh = { approvals = 0 }\n";
    let s0 = land_edit(&hub, &p, &admin, ".veilrules", rules, "rules");
    assert_eq!(post_check(&hub, &admin, &p.name, s0, "ci/lint", "pass").status, 200);
    assert_eq!(post_check(&hub, &admin, &p.name, s0, "ci/build", "pass").status, 200);

    // `p.dev` lands `c1` adding `src/helper.rs`, and `bob` lands `c2` calling it.
    let c1_reply = change(&hub, &dev1, &p.name, "src/helper.rs", "pub fn helper() -> i32 { 7 }\n", "add helper");
    assert_eq!(c1_reply.status, 200, "{}", body(&c1_reply));
    let c1_sub = c1_reply.json()["snapshot"].as_str().unwrap().to_string();
    let c1_cid = c1_reply.json()["change_id"].as_str().unwrap().to_string();
    let l1 = land(&hub, &dev1, &p.name, &c1_sub);
    assert_eq!(l1.status, 200, "{}", body(&l1));
    assert_eq!(l1.json()["state"], "landed");
    let c1 = tip(&hub, &admin, &p.name);

    let c2 = land_edit(&hub, &p, &dev2, "src/caller.rs", "pub fn run() -> i32 { crate::helper::helper() }\n", "use helper");

    // `ci/lint` fails on `c2` and `c1` (twice on `c1`), so S20 reverts `c1` as `r1`.
    assert_eq!(post_check(&hub, &admin, &p.name, c2, "ci/lint", "fail").status, 200);
    assert_eq!(post_check(&hub, &admin, &p.name, c1, "ci/lint", "fail").status, 200);
    assert_eq!(post_check(&hub, &admin, &p.name, c1, "ci/lint", "fail").status, 200);

    let mut st1 = bisect_status(&hub, &admin, &p.name).json();
    for _ in 0..50 {
        if st1["phase"] == "reverted" {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
        st1 = bisect_status(&hub, &admin, &p.name).json();
    }
    assert_eq!(st1["phase"], "reverted", "{st1}");
    let r1 = ObjectId::from_hex(st1["revert"].as_str().unwrap()).unwrap();
    assert_eq!(tip(&hub, &admin, &p.name), r1);

    // Subscribe both authors (`p.dev` and `bob`) and `p.admin` to `/events`.
    let dev1_sse = hub.api().get_unread(&format!("/v1/projects/{}/events", p.name), &[("authorization", &format!("Bearer {dev1}"))]);
    let dev2_sse = hub.api().get_unread(&format!("/v1/projects/{}/events", p.name), &[("authorization", &format!("Bearer {dev2}"))]);
    assert_eq!(dev1_sse.status().as_u16(), 200);
    assert_eq!(dev2_sse.status().as_u16(), 200);

    // `ci/build` passes on `c1` and `c2`, but fails on `r1` (because `c2` needs `c1`!).
    // A second `fail` on `r1` confirms `r1` (the server's own revert!) as the culprit.
    assert_eq!(post_check(&hub, &admin, &p.name, c1, "ci/build", "pass").status, 200);
    assert_eq!(post_check(&hub, &admin, &p.name, c2, "ci/build", "pass").status, 200);
    assert_eq!(post_check(&hub, &admin, &p.name, r1, "ci/build", "fail").status, 200);
    assert_eq!(post_check(&hub, &admin, &p.name, r1, "ci/build", "fail").status, 200);

    let st2 = bisect_status(&hub, &admin, &p.name).json();
    assert_eq!(st2["phase"], "needs a person", "server-made revert named as culprit must stop as 'needs a person': {st2}");
    assert_eq!(st2["culprit"], r1.hex(), "{st2}");
    assert_eq!(st2["original"], c1.hex(), "{st2}");
    assert_eq!(st2["original_change_id"], c1_cid, "{st2}");
    assert!(st2["revert"].is_null(), "must not revert a server-made revert: {st2}");
    assert_eq!(tip(&hub, &admin, &p.name), r1, "branch tip must remain at r1 without a revert-of-revert");

    let ev1 = collect_sse_events(dev1_sse, 1, Duration::from_secs(2));
    let ev2 = collect_sse_events(dev2_sse, 1, Duration::from_secs(2));
    assert!(
        ev1.iter().any(|(ev, d)| ev == "bisect.needs_person" && d["state"] == "needs a person" && d["original_change_id"] == c1_cid),
        "author of original change must receive bisect.needs_person event: {ev1:?}"
    );
    assert!(
        ev2.iter().any(|(ev, d)| ev == "bisect.needs_person" && d["state"] == "needs a person" && d["original_change_id"] == c1_cid),
        "author of subsequent change must receive bisect.needs_person event: {ev2:?}"
    );
}

/// BUG-1884 guarantee 2: after a `change_id` has been reverted twice by the
/// server, landing that `change_id` again (even rewritten/rebased and under
/// permissive branch rules) requires one person's approval via S21 as if high
/// risk; an agent's approval never counts, the refusal names
/// `reverted twice: needs a person's approval`, and the count is never reset.
#[test]
fn bug_1884_change_reverted_twice_needs_a_persons_approval() {
    use veil_core::{crypto::domains::SIG_CONTEXT_HUB_PR_REVIEW, hub::pr::review_message};

    let hub = TestHub::start();
    let p = setup_project(&hub);
    let admin = p.admin.token();
    let dev = p.dev.token();

    // Even when `.veilrules` marks `src/**` as `checks_only` and sets 0 approvals
    // for both normal and high risk (with `people_only = false` on normal),
    // a twice-reverted `change_id` must still require 1 person's approval!
    let rules = "[branches.main]\nprotected = true\nrequired_checks = [\"ci/src\"]\n\n\
                 [checks.\"ci/src\"]\npaths = [\"src/\"]\n\n\
                 [review]\nchecks_only = [\"src/**\"]\n\
                 normal = { approvals = 0, people_only = false }\n\
                 high = { approvals = 0 }\n";
    let s0 = land_edit(&hub, &p, &admin, ".veilrules", rules, "permissive rules");
    assert_eq!(post_check(&hub, &admin, &p.name, s0, "ci/src", "pass").status, 200);

    // Mint agent sessions for `p.dev` and `p.admin`.
    let dev_sess = hub
        .api()
        .post_json(
            Some(&dev),
            "/v1/sessions/agent",
            &json!({"project": p.name, "attribution": {"agent": "test/coder"}}),
        )
        .json();
    let dev_agent = dev_sess["token"].as_str().unwrap().to_string();
    let admin_sess = hub
        .api()
        .post_json(
            Some(&admin),
            "/v1/sessions/agent",
            &json!({"project": p.name, "attribution": {"agent": "test/reviewer"}}),
        )
        .json();
    let admin_agent = admin_sess["token"].as_str().unwrap().to_string();

    // 1st landing of `cid` by `dev_agent`, followed by 1st automatic revert.
    let c1_res = change(&hub, &dev_agent, &p.name, "src/flaky.rs", "pub const V: i32 = 1;\n", "feature v1");
    assert_eq!(c1_res.status, 200, "{}", body(&c1_res));
    let cid = c1_res.json()["change_id"].as_str().unwrap().to_string();
    let sub1 = c1_res.json()["snapshot"].as_str().unwrap().to_string();
    let l1 = land(&hub, &dev_agent, &p.name, &sub1);
    assert_eq!(l1.status, 200, "{}", body(&l1));
    assert_eq!(l1.json()["state"], "landed");
    let s1 = tip(&hub, &admin, &p.name);

    assert_eq!(post_check(&hub, &admin, &p.name, s1, "ci/src", "fail").status, 200);
    assert_eq!(post_check(&hub, &admin, &p.name, s1, "ci/src", "fail").status, 200);
    let mut st = bisect_status(&hub, &admin, &p.name).json();
    for _ in 0..50 {
        if st["phase"] == "reverted" {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
        st = bisect_status(&hub, &admin, &p.name).json();
    }
    assert_eq!(st["phase"], "reverted", "{st}");
    let r1 = tip(&hub, &admin, &p.name);
    assert_eq!(post_check(&hub, &admin, &p.name, r1, "ci/src", "pass").status, 200);

    // After 1 revert, rewriting `cid` still lands directly without person approval.
    let base2 = tip(&hub, &dev_agent, &p.name);
    let c2_res = hub.api().post_json(
        Some(&dev_agent),
        &format!("/v1/projects/{}/changes", p.name),
        &json!({
            "base": base2.hex(),
            "change_id": cid,
            "description": "feature v2",
            "edits": [{"path": "src/flaky.rs", "put": {"text": "pub const V: i32 = 2;\n"}}]
        }),
    );
    assert_eq!(c2_res.status, 200, "{}", body(&c2_res));
    let sub2 = c2_res.json()["snapshot"].as_str().unwrap().to_string();
    let l2 = land(&hub, &dev_agent, &p.name, &sub2);
    assert_eq!(l2.status, 200, "after 1 revert, re-landing cid must still be allowed: {}", body(&l2));
    assert_eq!(l2.json()["state"], "landed");
    let s2 = tip(&hub, &admin, &p.name);

    // 2nd automatic revert of `cid`.
    assert_eq!(post_check(&hub, &admin, &p.name, s2, "ci/src", "fail").status, 200);
    assert_eq!(post_check(&hub, &admin, &p.name, s2, "ci/src", "fail").status, 200);
    st = bisect_status(&hub, &admin, &p.name).json();
    for _ in 0..50 {
        if st["phase"] == "reverted" && st["culprit"] == s2.hex() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
        st = bisect_status(&hub, &admin, &p.name).json();
    }
    assert_eq!(st["phase"], "reverted", "{st}");
    let r2 = tip(&hub, &admin, &p.name);

    // 3rd attempt: direct re-land of `sub2` AND rebased/rewritten `cid` (`sub3`) must both be refused!
    let l2_again = land(&hub, &dev_agent, &p.name, &sub2);
    assert_eq!(l2_again.status, 409, "{}", body(&l2_again));
    assert!(
        body(&l2_again).contains("reverted twice: needs a person's approval"),
        "expected reverted-twice refusal reason, got: {}",
        body(&l2_again)
    );

    let base3 = tip(&hub, &dev_agent, &p.name);
    let c3_topic = hub.api().post_json(
        Some(&dev_agent),
        &format!("/v1/projects/{}/changes", p.name),
        &json!({
            "base": base3.hex(),
            "change_id": cid,
            "description": "feature v3 rebased and rewritten",
            "edits": [{"path": "src/flaky.rs", "put": {"text": "pub const V: i32 = 3;\n"}}]
        }),
    );
    assert_eq!(c3_topic.status, 200, "{}", body(&c3_topic));
    let sub3 = c3_topic.json()["snapshot"].as_str().unwrap().to_string();

    let c3_land = land(&hub, &dev_agent, &p.name, &sub3);
    assert_eq!(c3_land.status, 409, "{}", body(&c3_land));
    assert!(
        body(&c3_land).contains("reverted twice: needs a person's approval"),
        "rewritten change_id must still require person approval: {}",
        body(&c3_land)
    );

    // Push `sub3` onto a topic branch `wip/fix` and open a PR onto `main`.
    let push_wip = hub.api().post_json(
        Some(&dev_agent),
        &format!("/v1/projects/{}/push", p.name),
        &json!({"updates": [{"branch": "wip/fix", "expected": null, "new": sub3}]}),
    );
    assert_eq!(push_wip.status, 200, "{}", body(&push_wip));
    assert_eq!(push_wip.json()["results"][0]["ok"], json!(true), "{}", body(&push_wip));
    let wip_admin = hub.api().tips(Some(&admin), &p.name).unwrap().branches["wip/fix"];
    assert_eq!(post_check(&hub, &admin, &p.name, wip_admin, "ci/src", "pass").status, 200);

    let pr_resp = hub.api().post_json(
        Some(&dev_agent),
        &format!("/v1/projects/{}/prs", p.name),
        &json!({"head": sub3, "onto": "main", "title": "Fix feature v3"}),
    );
    assert_eq!(pr_resp.status, 200, "{}", body(&pr_resp));
    let pr_json = pr_resp.json();
    let pr_id = pr_json["id"].as_str().unwrap().to_string();
    let patch3 = pr_json["patch"].as_str().unwrap().to_string();
    assert_eq!(pr_json["review"]["risk"], "high", "{pr_json}");
    assert_eq!(pr_json["review"]["ready"], false, "{pr_json}");
    assert!(
        pr_json["review"]["reasons"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r.as_str() == Some("reverted twice: needs a person's approval")),
        "PR review gate must name reverted-twice reason: {pr_json}"
    );

    // Agent approval is refused over HTTP, and even a stored `agent = true`
    // verdict never counts toward landing a twice-reverted change_id.
    let admin_sig = p
        .admin
        .identity()
        .sign(SIG_CONTEXT_HUB_PR_REVIEW, &review_message(&p.name, &pr_id, &patch3, "approve"));
    let agent_rev = hub.api().post_json(
        Some(&admin_agent),
        &format!("/v1/projects/{}/prs/{pr_id}/reviews", p.name),
        &json!({"patch": patch3, "verdict": "approve", "signature": admin_sig}),
    );
    assert_eq!(agent_rev.status, 403, "agent session must not approve PR: {}", body(&agent_rev));

    let pid: i64 = hub
        .rt
        .block_on(sqlx::query_scalar("SELECT id FROM projects WHERE name = $1").bind(&p.name).fetch_one(&hub.hub().db))
        .unwrap();
    let admin_person_id: i64 = hub
        .rt
        .block_on(sqlx::query_scalar("SELECT id FROM people WHERE name = $1").bind(&p.admin.name).fetch_one(&hub.hub().db))
        .unwrap();
    let stored = hub
        .rt
        .block_on(veil_server::prs::review::put_verdict(
            &hub.hub(),
            pid,
            &pr_id,
            1,
            admin_person_id,
            "approve",
            &patch3,
            true,
            "agent-dev",
            &admin_sig,
            "lgtm from agent",
            true,
        ))
        .unwrap();
    assert!(stored);
    let pr_land_agent = hub
        .api()
        .post_json(Some(&dev_agent), &format!("/v1/projects/{}/prs/{pr_id}/land", p.name), &json!({}));
    assert_eq!(pr_land_agent.status, 409, "agent verdict must never count: {}", body(&pr_land_agent));
    assert!(body(&pr_land_agent).contains("reverted twice: needs a person's approval"));

    // Now a human person (`p.admin`) approves the exact patch -> landing succeeds!
    let person_rev = hub.api().post_json(
        Some(&admin),
        &format!("/v1/projects/{}/prs/{pr_id}/reviews", p.name),
        &json!({"patch": patch3, "verdict": "approve", "signature": admin_sig}),
    );
    assert_eq!(person_rev.status, 200, "{}", body(&person_rev));
    assert_eq!(person_rev.json()["review"]["ready"], true, "{}", body(&person_rev));

    // Approval of `patch3` only lets that exact patch land: another rewrite of
    // `cid` (`V = 99`) is still refused without its own person approval.
    let c3_other = hub.api().post_json(
        Some(&dev_agent),
        &format!("/v1/projects/{}/changes", p.name),
        &json!({
            "base": base3.hex(),
            "change_id": cid,
            "description": "feature v3 different patch",
            "edits": [{"path": "src/flaky.rs", "put": {"text": "pub const V: i32 = 99;\n"}}]
        }),
    );
    assert_eq!(c3_other.status, 200, "{}", body(&c3_other));
    let sub3_other = c3_other.json()["snapshot"].as_str().unwrap().to_string();
    let other_land = land(&hub, &dev_agent, &p.name, &sub3_other);
    assert_eq!(other_land.status, 409, "person approval applies only to exact patch: {}", body(&other_land));
    assert!(body(&other_land).contains("reverted twice: needs a person's approval"));

    let pr_land_ok = hub
        .api()
        .post_json(Some(&dev_agent), &format!("/v1/projects/{}/prs/{pr_id}/land", p.name), &json!({}));
    assert_eq!(pr_land_ok.status, 200, "person approval of exact patch must let cid land: {}", body(&pr_land_ok));
    assert_eq!(file_on_main(&hub, &admin, &p.name, "src/flaky.rs").body, b"pub const V: i32 = 3;\n");

    // The revert count was not reset to 0 by `pr_land_ok`: after just ONE more
    // revert of `cid`, re-landing `cid` still needs a person's approval (if the
    // count had been reset to 0, one revert would leave count == 1 and allow it).
    assert_eq!(post_check(&hub, &admin, &p.name, r2, "ci/src", "pass").status, 200);
    let s3 = tip(&hub, &admin, &p.name);
    assert_eq!(post_check(&hub, &admin, &p.name, s3, "ci/src", "fail").status, 200);
    assert_eq!(post_check(&hub, &admin, &p.name, s3, "ci/src", "fail").status, 200);
    st = bisect_status(&hub, &admin, &p.name).json();
    for _ in 0..50 {
        if st["phase"] == "reverted" && st["culprit"] == s3.hex() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
        st = bisect_status(&hub, &admin, &p.name).json();
    }
    assert_eq!(st["phase"], "reverted", "{st}");
    assert_eq!(st["culprit"], s3.hex(), "{st}");

    let base4 = tip(&hub, &dev_agent, &p.name);
    let c4_res = hub.api().post_json(
        Some(&dev_agent),
        &format!("/v1/projects/{}/changes", p.name),
        &json!({
            "base": base4.hex(),
            "change_id": cid,
            "description": "feature v4 unapproved rewrite",
            "edits": [{"path": "src/flaky.rs", "put": {"text": "pub const V: i32 = 4;\n"}}]
        }),
    );
    assert_eq!(c4_res.status, 200, "{}", body(&c4_res));
    let sub4 = c4_res.json()["snapshot"].as_str().unwrap().to_string();
    let c4_land = land(&hub, &dev_agent, &p.name, &sub4);
    assert_eq!(c4_land.status, 409, "revert count must not reset after landing: {}", body(&c4_land));
    assert!(body(&c4_land).contains("reverted twice: needs a person's approval"));
}

/// BUG-1884 guarantee 3: bisect still reverts a first-time confirmed culprit
/// at once, as before, so normal operation is unchanged.
#[test]
fn bug_1884_first_time_culprit_still_reverts_at_once() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let admin = p.admin.token();
    let dev = p.dev.token();

    let rules = "[branches.main]\nprotected = true\nrequired_checks = [\"ci/src\"]\n\n\
                 [checks.\"ci/src\"]\npaths = [\"src/\"]\n\n\
                 [review]\nnormal = { approvals = 0 }\nhigh = { approvals = 0 }\n";
    let s0 = land_edit(&hub, &p, &admin, ".veilrules", rules, "rules");
    assert_eq!(post_check(&hub, &admin, &p.name, s0, "ci/src", "pass").status, 200);

    let c1 = land_edit(&hub, &p, &dev, "src/good.rs", "pub const OK: bool = true;\n", "good");
    let c2 = land_edit(&hub, &p, &dev, "src/bad.rs", "compile_error!(\"oops\");\n", "first-time culprit");

    assert_eq!(post_check(&hub, &admin, &p.name, c1, "ci/src", "pass").status, 200);
    assert_eq!(post_check(&hub, &admin, &p.name, c2, "ci/src", "fail").status, 200);
    assert_eq!(post_check(&hub, &admin, &p.name, c2, "ci/src", "fail").status, 200);

    let mut st = bisect_status(&hub, &admin, &p.name).json();
    for _ in 0..50 {
        if st["phase"] == "reverted" {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
        st = bisect_status(&hub, &admin, &p.name).json();
    }
    assert_eq!(st["phase"], "reverted", "{st}");
    assert_eq!(st["culprit"], c2.hex(), "{st}");
    assert_eq!(file_on_main(&hub, &admin, &p.name, "src/good.rs").status, 200);
    assert_eq!(file_on_main(&hub, &admin, &p.name, "src/bad.rs").status, 404);
}

