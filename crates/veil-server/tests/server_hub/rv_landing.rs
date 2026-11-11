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
#[ignore = "BUG-1860: anyone in the project, with no write access to a folder, makes the server revert a landing there by posting check results"]
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

/// The guarantee: a landing onto a protected branch meets the review rules
/// by every route (`docs/HUB.md` §13.24). With the default rules a change of
/// source code needs one approval; `dev` has none. Landing it directly is
/// refused; the same change put on an embargo line of `dev`'s own group and
/// released by `dev` lands on `main` with no approval at all.
#[test]
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
#[ignore = "BUG-1862: a check result that arrives while the branch's bisect lease is held is recorded and never counted: the bisect stalls in `confirming` and nothing is reverted"]
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
#[ignore = "BUG-1863: work committed in the task a push runs in is not noted as committed (task-local db::COMMITTED is not carried by limits::in_request): a retryable error after the commit runs the push again"]
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
}
