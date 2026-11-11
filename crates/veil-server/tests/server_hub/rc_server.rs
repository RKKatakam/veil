//! The re-check of the server's review fixes (`rc-server`, 2026-11-11):
//! the fixes of BUG-1850 to BUG-1907 as merged on `integration`, each asked
//! whether it closes its row's whole class on every route.

use serde_json::{json, Value};
use veil_core::ObjectId;

use crate::support::*;

fn body(r: &Reply) -> String {
    String::from_utf8_lossy(&r.body).into_owned()
}

fn main_tip(hub: &TestHub, token: Option<&str>, project: &str) -> ObjectId {
    hub.api().tips(token, project).expect("the project's tips").branches["main"]
}

fn change(hub: &TestHub, token: &str, project: &str, req: &Value) -> Reply {
    hub.api().post_json(Some(token), &format!("/v1/projects/{project}/changes"), req)
}

fn push(hub: &TestHub, token: &str, project: &str, branch: &str, expected: Option<ObjectId>, new: ObjectId) -> Reply {
    hub.api().post_json(
        Some(token),
        &format!("/v1/projects/{project}/push"),
        &json!({"updates": [{"branch": branch, "expected": expected.map(|e| e.hex()), "new": new.hex()}]}),
    )
}

/// BUG-1858's class by its third route (`docs/HUB.md` §4.5, check 2: "every
/// file the push adds, changes or removes is in a folder the pusher has
/// access to"; `docs/VISIBILITY.md`: "Writing a public folder needs a named
/// group or person").
///
/// BUG-1858's fix refuses `fin` (she reads `src/` because it is public and
/// may not write it) when she moves `main` to a developer's unfinished
/// branch `wip`, and when she stacks a change of her own on `wip` and moves
/// `main` to that. It does not refuse her the same move as a **merge**: one
/// uploaded snapshot with the parents [`main`, `wip`] and `wip`'s tree. The
/// branch move's write check (`sync.rs`, `branch_move_write_refusal`) is
/// skipped because the uploaded snapshot stands directly on `main`'s tip,
/// and `check_changes` counts `src/unfinished.rs` as "taken from another
/// parent's side" (BUG-820's rule), whatever branch that side is on.
#[test]
#[ignore = "BUG-1920: a merge of someone's unlanded branch moves a branch across changes its pusher may not write"]
fn bug_1920_a_merge_of_an_unlanded_branch_needs_write_access_to_what_it_brings() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let (admin_tok, dev_tok, fin_tok) = (p.admin.token(), p.dev.token(), p.fin.token());
    // A developer's work in progress, on a branch of its own.
    let dev_main = main_tip(&hub, Some(&dev_tok), &p.name);
    let made = push(&hub, &dev_tok, &p.name, "wip", None, dev_main);
    assert_eq!(made.status, 200, "{}", body(&made));
    assert_eq!(made.json()["results"][0]["ok"], json!(true), "{}", body(&made));
    let c = change(
        &hub,
        &dev_tok,
        &p.name,
        &json!({"base": dev_main.hex(), "description": "work in progress", "onto": {"branch": "wip", "expected": dev_main.hex()},
                "edits": [{"path": "src/unfinished.rs", "put": {"text": "pub fn unfinished() { todo!() }\n"}}]}),
    );
    assert_eq!(c.status, 200, "{}", body(&c));
    assert_eq!(c.json()["branch"]["status"], "ok", "{}", body(&c));
    let main_before = main_tip(&hub, Some(&admin_tok), &p.name);

    // Control: `fin` may not write `src/`, and BUG-1858's route is closed.
    let tips = hub.api().tips(Some(&fin_tok), &p.name).unwrap();
    let (fin_main, fin_wip) = (tips.branches["main"], tips.branches["wip"]);
    let write = change(
        &hub,
        &fin_tok,
        &p.name,
        &json!({"base": fin_main.hex(), "description": "fin writes src/", "onto": {"branch": "main", "expected": fin_main.hex()},
                "edits": [{"path": "src/unfinished.rs", "put": {"text": "fin's\n"}}]}),
    );
    assert_eq!(write.status, 403, "control: fin may not write src/: {}", body(&write));
    let moved = push(&hub, &fin_tok, &p.name, "main", Some(fin_main), fin_wip);
    assert_eq!(moved.status, 403, "control: BUG-1858's own route is refused: {}", body(&moved));

    // The same move as a merge of [main, wip] with wip's tree.
    let api = hub.api();
    let mut merge = Craft::new(&api, &p.fin, &p.name, "wip");
    merge.tip = fin_main;
    let merged = merge.push_merge("main", &[fin_wip]);
    let answered = format!("the push answered {} {}", merged.status, body(&merged));
    let file = hub.api().get(Some(&admin_tok), &format!("/v1/projects/{}/q/file?path=src/unfinished.rs", p.name));
    assert_eq!(file.status, 404, "the unfinished file is on main ({answered}): {}", body(&file));
    assert_eq!(main_tip(&hub, Some(&admin_tok), &p.name), main_before, "main moved on the push of someone who may not write src/ ({answered})");
    assert_eq!(merged.status, 403, "{answered}");
}

fn post_check(hub: &TestHub, token: &str, project: &str, snapshot: ObjectId, name: &str, state: &str) -> Reply {
    hub.api().post_json(
        Some(token),
        &format!("/v1/projects/{project}/checks"),
        &json!({"snapshot": snapshot.hex(), "name": name, "state": state}),
    )
}

fn land(hub: &TestHub, token: &str, project: &str, snapshot: &str) -> Reply {
    hub.api().post_json(Some(token), &format!("/v1/projects/{project}/land"), &json!({"onto": "main", "snapshot": snapshot, "wait": true}))
}

/// One edit of `path` on `main`'s tip, landed by `token` with no change id
/// named (the server gives it a new one): the change id and the real tip.
fn land_new_change(hub: &TestHub, token: &str, project: &str, path: &str, text: &str) -> (Reply, String) {
    let base = main_tip(hub, Some(token), project);
    let c = change(hub, token, project, &json!({"base": base.hex(), "description": "feature", "edits": [{"path": path, "put": {"text": text}}]}));
    assert_eq!(c.status, 200, "{}", body(&c));
    let cid = c.json()["change_id"].as_str().unwrap().to_string();
    (land(hub, token, project, c.json()["snapshot"].as_str().unwrap()), cid)
}

/// The tip's required check fails twice: wait until the server reverted it.
fn fail_until_reverted(hub: &TestHub, admin: &str, project: &str, culprit: ObjectId) {
    assert_eq!(post_check(hub, admin, project, culprit, "ci/src", "fail").status, 200);
    assert_eq!(post_check(hub, admin, project, culprit, "ci/src", "fail").status, 200);
    let status = || hub.api().get(Some(admin), &format!("/v1/projects/{project}/bisect/main")).json();
    let mut st = status();
    for _ in 0..100 {
        if st["phase"] == "reverted" && st["culprit"] == culprit.hex() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
        st = status();
    }
    assert_eq!(st["phase"], "reverted", "{st}");
    assert_eq!(st["culprit"], culprit.hex(), "{st}");
    let reverted = main_tip(hub, Some(admin), project);
    assert_ne!(reverted, culprit, "the revert moved main");
    assert_eq!(post_check(hub, admin, project, reverted, "ci/src", "pass").status, 200);
}

/// BUG-1884's class ("Automatic reverts can loop. A landed change reverted
/// by S20 bisect can be re-landed by its agent, reverted again, and repeated
/// without end"), by the route an agent that commits through the API takes.
///
/// The fix counts reverts by **change id** (`bisect::any_reverted_twice`),
/// and a change id is the submitter's to choose: `POST …/changes` without
/// `change_id` gives every attempt a new one. Here an agent session lands
/// the same edit of the same file three times, each as a new change. The
/// first two are reverted; the third lands with nobody's approval (and can
/// be reverted and landed again, for ever), where the same edit under its
/// first change id is refused: "reverted twice: needs a person's approval"
/// (`rv_landing::bug_1884_change_reverted_twice_needs_a_persons_approval`).
#[test]
#[ignore = "BUG-1921: a change the server reverted twice lands again unapproved under a new change id"]
fn bug_1921_an_edit_reverted_twice_needs_a_person_whatever_change_id_it_is_given() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let (admin, dev) = (p.admin.token(), p.dev.token());
    let rules = "[branches.main]\nprotected = true\nrequired_checks = [\"ci/src\"]\n\n\
                 [checks.\"ci/src\"]\npaths = [\"src/\"]\n\n\
                 [review]\nchecks_only = [\"src/**\"]\n\
                 normal = { approvals = 0, people_only = false }\n\
                 high = { approvals = 0 }\n";
    let (l0, _) = land_new_change(&hub, &admin, &p.name, ".veilrules", rules);
    assert_eq!(l0.status, 200, "{}", body(&l0));
    assert_eq!(l0.json()["state"], "landed", "{}", body(&l0));
    let s0 = main_tip(&hub, Some(&admin), &p.name);
    assert_eq!(post_check(&hub, &admin, &p.name, s0, "ci/src", "pass").status, 200);
    let sess = hub.api().post_json(Some(&dev), "/v1/sessions/agent", &json!({"project": p.name, "attribution": {"agent": "test/coder"}}));
    assert_eq!(sess.status, 200, "{}", body(&sess));
    let agent = sess.json()["token"].as_str().unwrap().to_string();

    const EDIT: &str = "pub const V: i32 = 1;\n";
    let mut cids = Vec::new();
    for round in 1..=2 {
        let (l, cid) = land_new_change(&hub, &agent, &p.name, "src/flaky.rs", EDIT);
        assert_eq!(l.status, 200, "landing {round}: {}", body(&l));
        assert_eq!(l.json()["state"], "landed", "landing {round}: {}", body(&l));
        cids.push(cid);
        fail_until_reverted(&hub, &admin, &p.name, main_tip(&hub, Some(&admin), &p.name));
    }
    assert_ne!(cids[0], cids[1], "each attempt was given a change id of its own");
    let before = main_tip(&hub, Some(&admin), &p.name);

    // The third attempt of the same edit: twice reverted, it needs a person.
    let (l3, _) = land_new_change(&hub, &agent, &p.name, "src/flaky.rs", EDIT);
    let answered = format!("the third landing answered {} {}", l3.status, body(&l3));
    assert_eq!(main_tip(&hub, Some(&admin), &p.name), before, "an edit the server reverted twice landed again with nobody's approval ({answered})");
    assert_eq!(l3.status, 409, "{answered}");
    assert!(body(&l3).contains("reverted twice: needs a person's approval"), "{answered}");
}

/// BUG-1524's class ("every route by which snapshots the server already
/// held come onto a branch wrote no row" in `landed_changes`), by the API
/// commit that moves a branch onto a **stack** of its caller's own changes.
///
/// `POST …/changes` with `onto` and a `base` that is not the branch's tip
/// but the caller's own unlanded changes on it (`changes.rs`, `stack_on`:
/// "the changes it is on were made on the tip itself") moves the branch to
/// the new change and so brings the changes below it, which the server held
/// already. The move records the new change only (`on_branch`: "the
/// caller's restacked changes and this one"), reads nothing with
/// `landing::reached`, and leaves `branches.changes_recorded` true. A later
/// revision of the lower change is then not known as landed: with further
/// edits it lands again, and the change is on `main` twice.
///
/// The control is the same revision of a change that reached `main` as the
/// move's own change: refused, "already landed on 'main' with other edits".
#[test]
#[ignore = "BUG-1922: a change brought onto a branch below an API commit's own is landed again"]
fn bug_1922_a_change_below_an_api_commit_that_moved_the_branch_is_not_landed_again() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let dev = p.dev.token();
    let project = p.name.as_str();
    let made = |req: Value| {
        let c = change(&hub, &dev, project, &req);
        assert_eq!(c.status, 200, "{}", body(&c));
        c.json()
    };
    // A further revision of change `cid` (another text of `path`) on main's tip, sent to land.
    let land_revision = |cid: &str, path: &str| {
        let tip = main_tip(&hub, Some(&dev), project);
        let r = made(json!({"base": tip.hex(), "change_id": cid, "description": "revised", "edits": [{"path": path, "put": {"text": "revised\n"}}]}));
        land(&hub, &dev, project, r["snapshot"].as_str().unwrap())
    };
    const REFUSAL: &str = "already landed on 'main' with other edits";

    // Control: a change that moved main itself is known as landed.
    let main0 = main_tip(&hub, Some(&dev), project);
    let alone = made(json!({"base": main0.hex(), "description": "alone", "onto": {"branch": "main", "expected": main0.hex()},
                            "edits": [{"path": "src/alone.rs", "put": {"text": "alone\n"}}]}));
    assert_eq!(alone["branch"]["status"], "ok", "{alone}");
    let l = land_revision(alone["change_id"].as_str().unwrap(), "src/alone.rs");
    assert_eq!(l.status, 400, "control: {}", body(&l));
    assert!(body(&l).contains(REFUSAL), "control: {}", body(&l));

    // A stack of two: the lower change made alone, the upper moves main.
    let main1 = main_tip(&hub, Some(&dev), project);
    let lower = made(json!({"base": main1.hex(), "description": "lower", "edits": [{"path": "src/lower.rs", "put": {"text": "lower\n"}}]}));
    let upper = made(json!({"base": lower["snapshot"], "description": "upper", "onto": {"branch": "main", "expected": main1.hex()},
                            "edits": [{"path": "src/upper.rs", "put": {"text": "upper\n"}}]}));
    assert_eq!(upper["branch"]["status"], "ok", "{upper}");
    let on_main = hub.api().get(Some(&dev), &format!("/v1/projects/{project}/q/file?path=src/lower.rs"));
    assert_eq!(on_main.status, 200, "the lower change is on main: {}", body(&on_main));
    let before = main_tip(&hub, Some(&dev), project);

    let l = land_revision(lower["change_id"].as_str().unwrap(), "src/lower.rs");
    let answered = format!("the landing answered {} {}", l.status, body(&l));
    assert_eq!(main_tip(&hub, Some(&dev), project), before, "a change that is on main landed again ({answered})");
    assert_eq!(l.status, 400, "{answered}");
    assert!(body(&l).contains(REFUSAL), "{answered}");
}

/// One round of GC's switch against a root writer (BUG-1881's order): a
/// change on a branch that is then deleted is unreferenced; GC marks it;
/// two minutes later (past retention) GC runs again, and right before its
/// switch a writer commits a row naming the change's snapshot as a root
/// (`row`: SQL with `$1` the project, `$2` a key, `$3` the snapshot's hex),
/// as every root writer does: its transaction first locks the project's GC
/// epoch row `FOR SHARE` and finds the epoch it read before. Answers whether
/// the snapshot is still stored after GC.
fn snapshot_survives_a_root_written_before_the_switch(th: &TestHub, p: &Project, round: i64, row: &'static str) -> bool {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    use veil_server::pack_gc::{self, Options, SwitchHook};
    let api = th.api();
    let h = th.hub();
    let pid: i64 = th.rt.block_on(sqlx::query_scalar("SELECT id FROM projects WHERE name = $1").bind(&p.name).fetch_one(&h.db)).unwrap();
    let admin = p.admin.token();
    let branch = format!("tmp-rc-{round}");
    let mut c = Craft::new(&api, &p.admin, &p.name, "main");
    c.file(&format!("src/rc-gc-{round}.txt"), &format!("RC-SERVER-GC-ROOT-{round}-7c41d09e\n"));
    let (snap, r) = c.push_edited(&branch, None, |_| {});
    assert_eq!(r.json()["results"][0]["ok"], true, "{}", body(&r));
    let r = api.post_json(
        Some(&admin),
        &format!("/v1/projects/{}/push", p.name),
        &json!({"updates": [{"branch": branch, "expected": snap.hex(), "new": null}], "force": true}),
    );
    assert_eq!(r.json()["results"][0]["ok"], true, "{}", body(&r));
    assert!(th.rt.block_on(h.objects.exists(pid, &snap)).unwrap(), "the change is stored");

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
    // Each round is two minutes after the one before: GC sees the change
    // unreferenced, and two minutes later it is past retention.
    gc(round * 240_000, None).unwrap();
    let wrote = Arc::new(AtomicBool::new(false));
    let hook = {
        let (db, wrote, hex) = (h.db.clone(), wrote.clone(), snap.hex());
        SwitchHook(Arc::new(move || {
            let (db, wrote, hex) = (db.clone(), wrote.clone(), hex.clone());
            Box::pin(async move {
                if wrote.swap(true, Ordering::SeqCst) {
                    return;
                }
                let epoch = "SELECT epoch FROM access_epochs WHERE project_id = $1 AND person_id = -1";
                let before: i64 = sqlx::query_scalar(epoch).bind(pid).fetch_one(&db).await.unwrap();
                let mut tx = db.begin().await.unwrap();
                let now: i64 = sqlx::query_scalar(&format!("{epoch} FOR SHARE")).bind(pid).fetch_one(&mut *tx).await.unwrap();
                assert_eq!(now, before, "the writer's guard: the GC epoch it read before its checks");
                let n = sqlx::query(row).bind(pid).bind(format!("rc-{round}")).bind(&hex).execute(&mut *tx).await.unwrap().rows_affected();
                assert_eq!(n, 1, "the writer's row");
                tx.commit().await.unwrap();
            })
        }))
    };
    gc(round * 240_000 + 120_000, Some(hook)).unwrap();
    assert!(wrote.load(Ordering::SeqCst), "GC reached its switch, and the writer committed before it");
    th.rt.block_on(h.objects.exists(pid, &snap)).unwrap()
}

/// BUG-1881's guarantee ("every writer that adds a root takes the GC guard
/// first", so that GC never deletes what a writer's commit names), for the
/// search index's writer (`search::index::apply_write`, in the fix's list).
///
/// The guard orders a writer and GC's switch; what makes the switch give
/// way to a writer that committed **before** it (after GC computed what is
/// reachable) is the reference stamp, read again in the switch
/// (`pack_gc.rs`, `read_ref_stamp`). The stamp fingerprints `STAMP_TABLES`,
/// which leave out two tables whose columns GC roots: `search_shards`
/// (`segments`: registered `GcConditionalLeafRoot`, "fingerprinted in
/// `read_ref_stamp`" by its own comment) and `pr_review_rules`. A shard row
/// committed in that window, naming an object unreferenced past retention
/// (a segment whose content the index wrote before: segments are
/// content-addressed), is not noticed: GC switches and deletes the object.
///
/// The control is the same writer with a row in a stamped table.
#[test]
#[ignore = "BUG-1923: GC's reference stamp leaves out search_shards: a segment named right before the switch is deleted"]
fn bug_1923_gc_gives_way_to_a_search_shard_written_right_before_its_switch() {
    let th = TestHub::start();
    let p = setup_project(&th);
    let kept = snapshot_survives_a_root_written_before_the_switch(
        &th,
        &p,
        0,
        "INSERT INTO change_refs (project_id, change_id, snapshot, created_by, created_at) \
         SELECT $1, $2, $3, created_by, 0 FROM projects WHERE id = $1",
    );
    assert!(kept, "control: GC gives way to a change ref written right before its switch");
    let kept = snapshot_survives_a_root_written_before_the_switch(
        &th,
        &p,
        1,
        "INSERT INTO search_shards (project_id, kind, branch, line_key, segments, docs, text_docs, text_bytes, dead) \
         VALUES ($1, 'names', '', $2, '[\"' || $3 || '\"]', 0, 0, 0, 0)",
    );
    assert!(kept, "GC deleted an object that a search shard, committed before its switch under the writer's guard, names");
}

/// BUG-1885's second part ("landing a PR left its source branch": the
/// branch is deleted "when `prs::land` marks the PR landed"), and the PR's
/// own state, when the landing outlasts its request.
///
/// `prs::land` marks the PR `landed` and deletes its source branch only in
/// the request that asked, after `landing::wait`. A landing that is still
/// queued when the wait ends (30 s: behind another server's lease here; in
/// use behind a long queue, a slow batch or merges) is answered `queued`,
/// lands afterwards, and nothing then marks the PR or cleans its branch:
/// the PR stays `open` with its change on `main`, and its branch stays,
/// until someone asks to land it again.
#[test]
#[ignore = "BUG-1924: a PR whose landing outlasts its request stays open, and its source branch is left"]
fn bug_1924_a_pr_that_lands_after_its_request_was_answered_queued_is_landed() {
    use std::time::{Duration, Instant};
    let th = TestHub::start();
    let p = setup_project(&th);
    let api = th.api();
    let db = th.hub().db.clone();
    let pid: i64 = th.rt.block_on(sqlx::query_scalar("SELECT id FROM projects WHERE name = $1").bind(&p.name).fetch_one(&db)).unwrap();
    let dev = p.dev.token();
    // `main` is protected; `src/docs/**` needs checks only (no approval).
    write_files(&p.dir, &[(".veilrules", "[branches.main]\nprotected = true\n\n[review]\nchecks_only = [\"src/docs/**\"]\n")]);
    p.admin.commit_main(&p.dir, "protect main, docs need no approval");
    p.admin.ok(&p.dir, &["push"]);

    let base = main_tip(&th, Some(&dev), &p.name);
    let c = change(&th, &dev, &p.name, &json!({"base": base.hex(), "description": "a doc", "edits": [{"path": "src/docs/late.md", "put": {"text": "late\n"}}]}));
    assert_eq!(c.status, 200, "{}", body(&c));
    let snap = c.json()["snapshot"].as_str().unwrap().to_string();
    let made = api.post_json(Some(&dev), &format!("/v1/projects/{}/push", p.name), &json!({"updates": [{"branch": "topic-late", "expected": null, "new": snap}]}));
    assert_eq!(made.json()["results"][0]["ok"], true, "{}", body(&made));
    let pr = api.post_json(Some(&dev), &format!("/v1/projects/{}/prs", p.name), &json!({"head": "topic-late", "title": "a doc"}));
    assert_eq!(pr.status, 200, "{}", body(&pr));
    let id = pr.json()["id"].as_str().unwrap().to_string();

    // Another server holds main's landing lease: the PR's landing waits.
    th.rt
        .block_on(
            sqlx::query(
                "INSERT INTO landing_leases (project_id, branch, holder, epoch, expires_at) \
                 VALUES ($1, 'main', 'rc-server-another-server', 1, (extract(epoch FROM clock_timestamp()) * 1000)::BIGINT + 600000) \
                 ON CONFLICT (project_id, branch) DO UPDATE SET holder = EXCLUDED.holder, epoch = landing_leases.epoch + 1, expires_at = EXCLUDED.expires_at",
            )
            .bind(pid)
            .execute(&db),
        )
        .unwrap();
    let asked = api.post_json(Some(&dev), &format!("/v1/projects/{}/prs/{id}/land", p.name), &json!({}));
    assert_eq!(asked.status, 200, "{}", body(&asked));
    assert_eq!(asked.json()["landing"]["state"], "queued", "the request's wait ended with the landing queued: {}", body(&asked));
    let ticket = asked.json()["landing"]["ticket"].as_str().unwrap().to_string();

    // The lease ends, and the landing lands.
    th.rt
        .block_on(sqlx::query("DELETE FROM landing_leases WHERE project_id = $1 AND branch = 'main' AND holder = 'rc-server-another-server'").bind(pid).execute(&db))
        .unwrap();
    let until = Instant::now() + Duration::from_secs(60);
    let landed = loop {
        let r = api.get(Some(&dev), &format!("/v1/projects/{}/land/{ticket}", p.name));
        assert_eq!(r.status, 200, "{}", body(&r));
        if r.json()["state"] != "queued" || Instant::now() > until {
            break r.json();
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    assert_eq!(landed["state"], "landed", "{landed}");
    let file = api.get(Some(&dev), &format!("/v1/projects/{}/q/file?path=src/docs/late.md", p.name));
    assert_eq!(file.status, 200, "the PR's change is on main: {}", body(&file));

    // The PR is landed, and its source branch is cleaned up, as when the
    // landing ends within the request (`rv_core2::bug_1885_pr_landing_…`).
    std::thread::sleep(Duration::from_secs(2));
    let shown = api.get(Some(&dev), &format!("/v1/projects/{}/prs/{id}", p.name));
    assert_eq!(shown.status, 200, "{}", body(&shown));
    assert_eq!(shown.json()["state"], "landed", "the PR's change is on main and the PR is still {}", shown.json()["state"]);
    let tips = api.tips(Some(&dev), &p.name).unwrap();
    assert!(!tips.branches.contains_key("topic-late"), "the landed PR's source branch is left");
}

/// BUG-1852's rule ("a result counts only when its poster may write every
/// path the check covers … other results are stored and shown, and decide
/// nothing"), against the bound on a snapshot's checks.
///
/// A snapshot keeps at most 64 distinct checks, 32 of one person, and the
/// bound is asked before a new name is stored whoever posts it. Two people
/// who take part in the project and may write nothing the check covers
/// (`fin` and `carol`: neither may write `src/`) post 32 names each on
/// `main`'s tip. The required check's own result, from the admin, is then
/// refused (`400 a snapshot keeps at most 64 distinct checks`): the results
/// that "decide nothing" decide that `main@tested` never reaches this tip
/// and that no bisect of it starts.
#[test]
#[ignore = "BUG-1925: results that count for nothing fill a snapshot's 64 checks, and the required check's result is refused"]
fn bug_1925_results_that_do_not_count_never_keep_out_the_required_checks_result() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let (admin, fin, carol) = (p.admin.token(), p.fin.token(), p.carol.token());
    let rules = "[branches.main]\nprotected = true\nrequired_checks = [\"ci/src\"]\n\n[checks.\"ci/src\"]\npaths = [\"src/\"]\n";
    let (l0, _) = land_new_change(&hub, &admin, &p.name, ".veilrules", rules);
    assert_eq!(l0.status, 200, "{}", body(&l0));
    assert_eq!(l0.json()["state"], "landed", "{}", body(&l0));
    let tip = main_tip(&hub, Some(&admin), &p.name);

    // Neither of them may report the required check itself.
    for (who, token) in [("fin", &fin), ("carol", &carol)] {
        let seen = main_tip(&hub, Some(token), &p.name);
        let r = post_check(&hub, token, &p.name, seen, "ci/src", "fail");
        assert_eq!(r.status, 403, "control: {who} may not report ci/src: {}", body(&r));
        for i in 0..32 {
            let r = post_check(&hub, token, &p.name, seen, &format!("other/{who}-{i}"), "pass");
            assert_eq!(r.status, 200, "{who}'s result {i}: {}", body(&r));
        }
    }

    let r = post_check(&hub, &admin, &p.name, tip, "ci/src", "pass");
    assert_eq!(r.status, 200, "the required check's result, from someone who may write what it covers: {}", body(&r));
    let tested = hub.api().get(Some(&admin), &format!("/v1/projects/{}/tested/main", p.name));
    assert_eq!(tested.status, 200, "{}", body(&tested));
    assert!(body(&tested).contains(&tip.hex()), "main@tested is the tip whose required check passed: {}", body(&tested));
}
