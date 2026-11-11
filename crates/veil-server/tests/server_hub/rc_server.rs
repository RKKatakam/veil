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
