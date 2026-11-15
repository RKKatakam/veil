//! What a push costs, whatever the number of branches (`docs/HUB.md`
//! §13.41). BUG-2445: every push, landing and pull asked for the tips, and
//! the answer projected, signed a grant for and sent every branch. BUG-2446:
//! an agent could not delete its subagent's branch once merged into its
//! own, so branches piled up.
//!
//! Guarantees, each a test here:
//! * `tips?branches=` answers the same, whatever the number of branches;
//! * for every viewer it is the full answer cut to the names (and the
//!   default branch): no branch, tip, grant or `@tested` the full answer
//!   does not hold, an embargo's hidden line left out as a name that is not
//!   there;
//! * a landing deletes the branch it was asked to when, and only when, its
//!   work is all on the branch landed on: never the default branch, an
//!   embargo's line or a branch that moved on; for an agent session, only a
//!   branch it may move; refusals say one sentence; recorded in the audit log;
//! * `vl land BRANCH --onto B --delete` deletes the branch and its tag.

use serde_json::{json, Value};
use veil_core::{
    hub::{grant::Grant, wire::Tips},
    ObjectId,
};

use crate::{limits::project_id_of, support::*};

fn body(r: &Reply) -> String {
    String::from_utf8_lossy(&r.body).into_owned()
}

fn named(api: &Api, token: Option<&str>, project: &str, names: &[&str]) -> Reply {
    api.get(token, &format!("/v1/projects/{project}/tips?branches={}", names.join(",")))
}

fn named_tips(api: &Api, token: Option<&str>, project: &str, names: &[&str]) -> Tips {
    let r = named(api, token, project, names);
    assert_eq!(r.status, 200, "{}", body(&r));
    serde_json::from_slice(&r.body).unwrap()
}

/// A change of one file on `base` through the API: its snapshot.
fn change_on(api: &Api, token: &str, project: &str, base: ObjectId, path: &str) -> ObjectId {
    let r = api.post_json(
        Some(token),
        &format!("/v1/projects/{project}/changes"),
        &json!({"base": base.hex(), "description": format!("put {path}"), "edits": [{"path": path, "put": {"text": format!("{path}\n")}}]}),
    );
    assert_eq!(r.status, 200, "{}", body(&r));
    serde_json::from_value(r.json()["snapshot"].clone()).unwrap()
}

/// Move (or make, `expected: None`) `branch` to `new`; it must be accepted.
fn set_branch(api: &Api, token: &str, project: &str, branch: &str, expected: Option<ObjectId>, new: ObjectId) {
    let r = api.post_json(
        Some(token),
        &format!("/v1/projects/{project}/push"),
        &json!({"updates": [{"branch": branch, "expected": expected.map(|e| e.hex()), "new": new.hex()}]}),
    );
    assert_eq!(r.status, 200, "{}", body(&r));
    assert_eq!(r.json()["results"][0]["ok"], true, "{}", body(&r));
}

fn land(api: &Api, token: &str, project: &str, req: &Value) -> Value {
    let r = api.post_json(Some(token), &format!("/v1/projects/{project}/land"), req);
    assert_eq!(r.status, 200, "{}", body(&r));
    let v = r.json();
    assert_eq!(v["state"], "landed", "{v}");
    v
}

fn agent_token(hub: &TestHub, token: &str, project: &str, only: &[&str]) -> String {
    let r = hub.api().post_json(Some(token), "/v1/sessions/agent", &json!({"project": project, "attribution": {"agent": "claude-code/2.3"}, "only": only}));
    assert_eq!(r.status, 200, "{}", body(&r));
    r.json()["token"].as_str().unwrap().to_string()
}

/// What a landing's `delete_branch` that was not deleted is told
/// (`branches::not_deleted`), pinned.
fn not_deleted(branch: &str, onto: &str) -> String {
    format!("'{branch}' was not deleted: only a branch whose work is all on '{onto}' is, and never the default branch, a protected branch or an embargo's line")
}

/// An embargo's line, as `rv_core2`'s BUG-1885 test makes one: at `main`.
const LINE: &str = "embargo/e1a2b3c4d5e6f708";

fn add_embargo_line(hub: &TestHub, project: &str) {
    let pid = project_id_of(hub, project);
    let h = hub.hub();
    hub.rt
        .block_on(
            sqlx::query("INSERT INTO branches (project_id, name, target) SELECT project_id, $2, target FROM branches WHERE project_id = $1 AND name = 'main'")
                .bind(pid)
                .bind(LINE)
                .execute(&h.db),
        )
        .unwrap();
    h.caches.tips_changed(pid);
}

/// BUG-2445: the answer to `tips?branches=` is the same size, and holds
/// the same branches and grants, with 1 other branch or 40.
#[test]
fn bug_2445_tips_for_named_branches_cost_the_same_whatever_the_number_of_branches() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let dev = p.dev.token();
    let main = api.tips(Some(&dev), &p.name).unwrap().branches["main"];
    let mine = change_on(&api, &dev, &p.name, main, "src/mine.rs");
    set_branch(&api, &dev, &p.name, "a/0", None, mine);
    let few = named(&api, Some(&dev), &p.name, &["a/0"]);
    assert_eq!(few.status, 200, "{}", body(&few));
    let full_few = api.get(Some(&dev), &format!("/v1/projects/{}/tips", p.name)).body.len();
    for i in 1..=40 {
        let s = change_on(&api, &dev, &p.name, main, &format!("src/b{i}.rs"));
        set_branch(&api, &dev, &p.name, &format!("b/{i}"), None, s);
    }
    let many = named(&api, Some(&dev), &p.name, &["a/0"]);
    assert_eq!(many.status, 200, "{}", body(&many));
    let full_many = api.get(Some(&dev), &format!("/v1/projects/{}/tips", p.name)).body.len();
    // The full answer grows with the branches; the named one does not.
    assert!(full_many > full_few + 40 * 64, "the full answer: {full_few} then {full_many} bytes");
    assert_eq!(many.body.len(), few.body.len(), "the named answer: {} then {} bytes", few.body.len(), many.body.len());
    let t: Tips = serde_json::from_slice(&many.body).unwrap();
    assert_eq!(t.branches.keys().collect::<Vec<_>>(), ["a/0", "main"]);
    assert_eq!(t.grants.keys().collect::<Vec<_>>(), ["a/0", "main"]);
    assert_eq!(t.branches["a/0"], mine);
    assert_eq!(t.revision, veil_core::hub::wire::REVISION);
    // Empty: the default branch alone (what a push needs: the revision).
    let none = named_tips(&api, Some(&dev), &p.name, &[]);
    assert_eq!(none.branches.keys().collect::<Vec<_>>(), ["main"]);
    // Past the bound, refused in clear words, for anyone.
    let names: Vec<String> = (0..65).map(|i| format!("b/{i}")).collect();
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    for who in [Some(dev.as_str()), None] {
        let r = named(&api, who, &p.name, &refs);
        assert_eq!((r.status, r.json()["message"].clone()), (400, json!("at most 64 branches in `branches`")), "{}", body(&r));
    }
}

/// The grant's body without its expiry (made at each answer).
fn bound(t: &Tips) -> Vec<(String, String, Option<String>, ObjectId, i64, i64)> {
    t.grants
        .iter()
        .map(|(b, g)| {
            let g = Grant::verify(g, t.grant_key.as_deref().unwrap()).expect("a grant that verifies");
            (b.clone(), g.body.project, g.body.device, g.body.root, g.body.epoch, g.body.person_epoch)
        })
        .collect()
}

/// BUG-2445: for every viewer (anyone on Earth, a member who sees `src/`
/// only, finance, an admin, a narrowed agent session), `tips?branches=` is
/// the full answer cut to the names and the default branch; an embargo's
/// line and a name that is not there are left out alike.
#[test]
fn bug_2445_a_named_tips_answer_is_the_full_answer_cut_to_the_names_for_every_viewer() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let (admin, dev, fin) = (p.admin.token(), p.dev.token(), p.fin.token());
    let main = api.tips(Some(&admin), &p.name).unwrap().branches["main"];
    // A branch of `src/` work, one of billing work, and an embargo's line.
    let d = change_on(&api, &dev, &p.name, api.tips(Some(&dev), &p.name).unwrap().branches["main"], "src/dev-work.rs");
    set_branch(&api, &dev, &p.name, "t/dev", None, d);
    let b = change_on(&api, &admin, &p.name, main, &format!("{BILL_DIR}/acme/more.txt"));
    set_branch(&api, &admin, &p.name, "t/bill", None, b);
    add_embargo_line(&hub, &p.name);
    // And one that is not named: left out of every named answer.
    set_branch(&api, &dev, &p.name, "t/other", None, d);
    let agent = agent_token(&hub, &dev, &p.name, &["src/"]);
    let names = ["t/dev", "t/bill", LINE, "no-such-branch-x"];
    for (who, token) in [("anyone", None), ("dev", Some(dev.as_str())), ("fin", Some(fin.as_str())), ("admin", Some(admin.as_str())), ("agent", Some(agent.as_str()))] {
        let full = api.tips(token, &p.name).unwrap_or_else(|| panic!("{who}: no tips"));
        let cut = named_tips(&api, token, &p.name, &names);
        let keep = |k: &String| names.contains(&k.as_str()) || *k == full.default_branch;
        let want: Vec<_> = full.branches.iter().filter(|(k, _)| keep(k)).collect();
        assert_eq!(cut.branches.iter().collect::<Vec<_>>(), want, "{who}: branches");
        assert_eq!(cut.tested.iter().collect::<Vec<_>>(), full.tested.iter().filter(|(k, _)| keep(k)).collect::<Vec<_>>(), "{who}: tested");
        let mut want_grants = bound(&full);
        want_grants.retain(|g| keep(&g.0));
        assert_eq!(bound(&cut), want_grants, "{who}: grants");
        assert_eq!(
            (&cut.default_branch, &cut.you, cut.admin, cut.revision, &cut.grant_key),
            (&full.default_branch, &full.you, full.admin, full.revision, &full.grant_key),
            "{who}"
        );
        assert_eq!(serde_json::to_value(&cut.embargoes).unwrap(), serde_json::to_value(&full.embargoes).unwrap(), "{who}: embargoes");
        assert!(!cut.branches.contains_key("no-such-branch-x") && !cut.branches.contains_key("t/other"), "{who}");
        assert!(who == "anyone" || full.branches.contains_key("t/other"), "{who}: the full answer has it");
        // Only an admin sees the embargo's line, in either answer.
        assert_eq!(cut.branches.contains_key(LINE), who == "admin", "{who}: {:?}", cut.branches);
    }
    // The narrowed session gets no grant either way; the member sees the
    // billing branch as their projection, never its real tip.
    assert!(named_tips(&api, Some(&agent), &p.name, &names).grants.is_empty());
    assert_ne!(named_tips(&api, Some(&dev), &p.name, &names).branches.get("t/bill"), Some(&b));
}

/// BUG-2446: an agent session merges its subagent's branch into its own
/// through the landing service, and the subagent's branch is deleted with
/// it; a push's deletion of it stays refused, as before.
#[test]
fn bug_2446_an_agent_deletes_its_subagents_branch_once_merged_into_its_own() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let dev = p.dev.token();
    let agent = agent_token(&hub, &dev, &p.name, &[]);
    let main = api.tips(Some(&agent), &p.name).unwrap().branches["main"];
    let mine = change_on(&api, &agent, &p.name, main, "src/agent-1.rs");
    set_branch(&api, &agent, &p.name, "a/1", None, mine);
    let sub = change_on(&api, &agent, &p.name, mine, "src/agent-1-s1.rs");
    set_branch(&api, &agent, &p.name, "a/1-s1", None, sub);
    // A push's deletion: its work is not on `main`, so refused as before.
    let r = api.post_json(
        Some(&agent),
        &format!("/v1/projects/{}/push", p.name),
        &json!({"updates": [{"branch": "a/1-s1", "expected": sub.hex(), "new": null}]}),
    );
    assert_eq!(r.status, 403, "{}", body(&r));
    let v = land(&api, &agent, &p.name, &json!({"onto": "a/1", "snapshot": sub.hex(), "delete_branch": "a/1-s1"}));
    assert_eq!(v["deleted_branch"], "a/1-s1", "{v}");
    assert!(v.get("warnings").is_none(), "{v}");
    let tips = api.tips(Some(&p.admin.token()), &p.name).unwrap();
    assert!(!tips.branches.contains_key("a/1-s1"), "{:?}", tips.branches);
    // Its work is on the agent's branch (as its person sees it).
    let onto = api.tips(Some(&dev), &p.name).unwrap().branches["a/1"];
    let f = api.get(Some(&dev), &format!("/v1/projects/{}/q/file?rev={}&path=src/agent-1-s1.rs", p.name, onto.hex()));
    assert_eq!((f.status, body(&f)), (200, "src/agent-1-s1.rs\n".to_string()));
    // Recorded.
    let h = hub.hub();
    let audit: Vec<String> = hub
        .rt
        .block_on(sqlx::query_scalar("SELECT details FROM audit_log WHERE project_id = $1 AND action = 'push'").bind(project_id_of(&hub, &p.name)).fetch_all(&h.db))
        .unwrap();
    assert!(audit.iter().any(|d| d == r#"deleted the branch "a/1-s1": it landed on "a/1""#), "{audit:?}");
}

/// BUG-2446: a landing deletes only a branch whose work is all on the
/// branch it landed on; never the default branch or an embargo's line; for
/// a narrowed agent session, never a branch it could not move. Each
/// refusal is one sentence, the same for a name that is not there.
#[test]
fn bug_2446_a_landing_deletes_only_a_branch_whose_work_is_all_on_the_branch_landed_on() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let (admin, dev) = (p.admin.token(), p.dev.token());
    add_embargo_line(&hub, &p.name);
    let main = api.tips(Some(&dev), &p.name).unwrap().branches["main"];
    let top = change_on(&api, &dev, &p.name, main, "src/top.rs");
    set_branch(&api, &dev, &p.name, "u/top", None, top);
    // A branch that moved on past what lands: kept.
    let s1 = change_on(&api, &dev, &p.name, top, "src/s1.rs");
    let s2 = change_on(&api, &dev, &p.name, s1, "src/s2.rs");
    set_branch(&api, &dev, &p.name, "u/sub", None, s2);
    let v = land(&api, &dev, &p.name, &json!({"onto": "u/top", "snapshot": s1.hex(), "delete_branch": "u/sub"}));
    assert_eq!((v.get("deleted_branch"), v["warnings"].clone()), (None, json!([not_deleted("u/sub", "u/top")])), "{v}");
    assert_eq!(api.tips(Some(&dev), &p.name).unwrap().branches.get("u/sub"), Some(&s2));
    // The default branch, an embargo's line, a name that is not there:
    // landed, never deleted, one sentence each.
    let mut base = api.tips(Some(&dev), &p.name).unwrap().branches["u/top"];
    for (i, name) in ["main", LINE, "no-such-branch-x"].into_iter().enumerate() {
        let s = change_on(&api, &dev, &p.name, base, &format!("src/k{i}.rs"));
        set_branch(&api, &dev, &p.name, &format!("u/k{i}"), None, s);
        let v = land(&api, &dev, &p.name, &json!({"onto": "u/top", "snapshot": s.hex(), "delete_branch": name}));
        assert_eq!((v.get("deleted_branch"), v["warnings"].clone()), (None, json!([not_deleted(name, "u/top")])), "{name}: {v}");
        base = api.tips(Some(&dev), &p.name).unwrap().branches["u/top"];
    }
    let all = api.tips(Some(&admin), &p.name).unwrap().branches;
    assert!(all.contains_key("main") && all.contains_key(LINE), "{all:?}");
    // A narrowed agent session (src/api/) lands its own work and names the
    // person's branch (work outside its paths, all on `u/top` already): not
    // the branch it landed from, so kept (BUG-2448).
    let outside = change_on(&api, &dev, &p.name, base, "src/outside.rs");
    set_branch(&api, &dev, &p.name, "u/person", None, outside);
    land(&api, &dev, &p.name, &json!({"onto": "u/top", "snapshot": outside.hex()}));
    let narrowed = agent_token(&hub, &dev, &p.name, &["src/api/"]);
    let base = api.tips(Some(&narrowed), &p.name).unwrap().branches["u/top"];
    let inside = change_on(&api, &narrowed, &p.name, base, "src/api/inside.rs");
    set_branch(&api, &narrowed, &p.name, "u/agent", None, inside);
    let v = land(&api, &narrowed, &p.name, &json!({"onto": "u/top", "snapshot": inside.hex(), "delete_branch": "u/person"}));
    assert_eq!((v.get("deleted_branch"), v["warnings"].clone()), (None, json!([not_deleted("u/person", "u/top")])), "{v}");
    assert!(api.tips(Some(&dev), &p.name).unwrap().branches.contains_key("u/person"));
    // Malformed requests: refused before anything lands.
    for (req, message) in [
        (json!({"onto": "u/top", "snapshot": inside.hex(), "delete_branch": "u/top"}), "`delete_branch` names the branch landed from, not the one landed on"),
        (
            json!({"onto": "u/top", "base": base.hex(), "edits": [{"path": "src/api/e.rs", "put": {"text": "e"}}], "delete_branch": "u/agent"}),
            "`delete_branch` goes with an uploaded `snapshot`: the branch it was pushed to",
        ),
    ] {
        let r = api.post_json(Some(&dev), &format!("/v1/projects/{}/land", p.name), &req);
        assert_eq!((r.status, r.json()["message"].clone()), (400, json!(message)), "{}", body(&r));
    }
}

/// BUG-2446 through `vl`: `vl land BRANCH --onto B --delete` lands the
/// branch, deletes it on the server and its tag here, in one operation;
/// the next push does not make it again.
#[test]
fn bug_2446_vl_land_delete_deletes_the_merged_branch_and_its_tag() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let dir = p.dev.dir("clone");
    p.dev.clone_trusting(&hub.url(&p.name), &dir, &p.fp);
    write_files(&dir, &[("src/top.rs", "top\n")]);
    p.dev.ok(&dir, &["commit", "--no-advance", "-m", "top"]);
    p.dev.ok(&dir, &["tag", "set", "w-top", "-r", "@-"]);
    write_files(&dir, &[("src/sub.rs", "sub\n")]);
    p.dev.ok(&dir, &["commit", "--no-advance", "-m", "sub"]);
    p.dev.ok(&dir, &["tag", "set", "w-sub", "-r", "@-"]);
    p.dev.ok(&dir, &["push", "-t", "w-top", "-t", "w-sub"]);
    let out = p.dev.ok(&dir, &["land", "w-sub", "--onto", "w-top", "--delete"]);
    assert!(out.contains("Deleted the branch 'w-sub'"), "{out}");
    let tags = p.dev.ok(&dir, &["tag", "list"]);
    assert!(!tags.contains("w-sub"), "{tags}");
    p.dev.ok(&dir, &["push"]);
    let branches = hub.api().tips(Some(&p.dev.token()), &p.name).unwrap().branches;
    assert!(!branches.contains_key("w-sub") && branches.contains_key("w-top"), "{branches:?}");
}

/// Run `statements` (one or several) on the test server's database.
fn sql(hub: &TestHub, statements: &str) {
    let h = hub.hub();
    hub.rt.block_on(sqlx::raw_sql(statements).execute(&h.db)).unwrap();
}

/// A server on a database of its own: the triggers a test adds to hold a
/// transaction open, or to make a statement fail, are nobody else's.
fn own_hub() -> TestHub {
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().worker_threads(2).build().unwrap();
    TestHub::start_on(&crate::grants::fresh_database(&rt), std::time::Duration::from_secs(3600))
}

/// The land request's answer, whatever its status.
fn land_reply(api: &Api, token: &str, project: &str, req: &Value) -> Reply {
    api.post_json(Some(token), &format!("/v1/projects/{project}/land"), req)
}

/// BUG-2447: two landings, each of the same snapshot onto one of two
/// branches and each asking to delete the other, never both delete, and the
/// work is on a branch left; four pairs at once, six times, every deletion's
/// transaction held open 0.5 s by a trigger. (Since BUG-2448 a deletion
/// needs the deleted branch's tip to be the snapshot landed, which the other
/// landing moves away from: neither passes. The lock itself is shown by
/// `bug_2447_two_crossed_deletions_never_both_commit`.)
#[test]
fn bug_2447_two_crossed_landings_never_delete_both_branches() {
    let hub = own_hub();
    let p = setup_project(&hub);
    let api = hub.api();
    let dev = p.dev.token();
    sql(
        &hub,
        "CREATE FUNCTION t2447_slow() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.5); RETURN NULL; END $$; \
         CREATE TRIGGER t2447_slow AFTER DELETE ON branches FOR EACH ROW WHEN (OLD.name LIKE 'x/%') EXECUTE PROCEDURE t2447_slow();",
    );
    let (mut rounds, mut one_deleted) = (0, 0);
    for round in 0..6 {
        let main = api.tips(Some(&dev), &p.name).unwrap().branches["main"];
        // Per pair: A and B at S (S on no other branch), T a change on S.
        let pairs: Vec<(String, String, ObjectId)> = (0..4)
            .map(|k| {
                let (a, b) = (format!("x/a{round}-{k}"), format!("x/b{round}-{k}"));
                let s = change_on(&api, &dev, &p.name, main, &format!("src/x{round}-{k}-s.rs"));
                set_branch(&api, &dev, &p.name, &a, None, s);
                set_branch(&api, &dev, &p.name, &b, None, s);
                (a, b, change_on(&api, &dev, &p.name, s, &format!("src/x{round}-{k}-t.rs")))
            })
            .collect();
        let start = std::sync::Barrier::new(8);
        let answers: Vec<Vec<Reply>> = std::thread::scope(|sc| {
            let handles: Vec<_> = pairs
                .iter()
                .map(|(a, b, t)| {
                    let one = |onto: &str, del: &str| {
                        let (api, dev, name, start) = (hub.api(), dev.clone(), p.name.clone(), &start);
                        let req = json!({"onto": onto, "snapshot": t.hex(), "delete_branch": del});
                        sc.spawn(move || {
                            start.wait();
                            land_reply(&api, &dev, &name, &req)
                        })
                    };
                    (one(a, b), one(b, a))
                })
                .collect();
            handles.into_iter().map(|(x, y)| vec![x.join().unwrap(), y.join().unwrap()]).collect()
        });
        let tips = api.tips(Some(&dev), &p.name).unwrap().branches;
        for ((a, b, t), replies) in pairs.iter().zip(answers) {
            let mut deleted = 0;
            for r in &replies {
                assert_eq!(r.status, 200, "{}", body(r));
                assert_eq!(r.json()["state"], "landed", "{}", body(r));
                deleted += r.json().get("deleted_branch").is_some() as usize;
            }
            let left: Vec<&String> = [a, b].into_iter().filter(|n| tips.contains_key(*n)).collect();
            assert!(!left.is_empty(), "round {round}: both {a} and {b} were deleted: {:?}", replies.iter().map(body).collect::<Vec<_>>());
            assert_eq!(deleted + left.len(), 2, "round {round}: the answers say what happened");
            for (n, r) in [a, b].into_iter().zip(&replies) {
                if let Some(tip) = tips.get(n) {
                    let landed: ObjectId = serde_json::from_value(r.json()["landed"].as_array().unwrap().last().unwrap().clone()).unwrap();
                    assert_eq!(*tip, landed, "round {round}: the work ({}) is on {n}", t.short());
                }
            }
            rounds += 1;
            one_deleted += deleted;
        }
    }
    assert_eq!(rounds, 24);
    eprintln!("bug_2447: {one_deleted} of {rounds} pairs deleted one branch");
}

/// BUG-2450, the push's deletion (BUG-1885): a member's deletion of a branch
/// whose work is on `main` only, while an admin's forced rewind of `main`
/// is in flight, is refused once the rewind commits; the branch, and its
/// work, stay. A trigger holds the rewind's transaction open for 1 s.
#[test]
fn bug_2450_a_merged_branchs_deletion_never_races_a_forced_rewind_of_main() {
    let hub = own_hub();
    let p = setup_project(&hub);
    let api = hub.api();
    let (admin, dev) = (p.admin.token(), p.dev.token());
    let before = api.tips(Some(&admin), &p.name).unwrap().branches["main"];
    // The dev's change lands on `main`, and a branch of theirs is at it.
    let base = api.tips(Some(&dev), &p.name).unwrap().branches["main"];
    let s = change_on(&api, &dev, &p.name, base, "src/rewound.rs");
    set_branch(&api, &dev, &p.name, "main", Some(base), s);
    set_branch(&api, &dev, &p.name, "y/merged", None, s);
    let now = api.tips(Some(&admin), &p.name).unwrap().branches["main"];
    sql(
        &hub,
        "CREATE FUNCTION t2450_rewind() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(1); RETURN NULL; END $$; \
         CREATE TRIGGER t2450_rewind AFTER UPDATE ON branches FOR EACH ROW WHEN (NEW.name = 'main' AND NEW.lineage <> OLD.lineage) \
         EXECUTE PROCEDURE t2450_rewind();",
    );
    let (rewind, delete) = std::thread::scope(|sc| {
        let (a, name) = (hub.api(), p.name.clone());
        let admin = admin.clone();
        let rewind = sc.spawn(move || {
            a.post_json(
                Some(&admin),
                &format!("/v1/projects/{name}/push"),
                &json!({"updates": [{"branch": "main", "expected": now.hex(), "new": before.hex()}], "force": true}),
            )
        });
        std::thread::sleep(std::time::Duration::from_millis(300));
        let delete = api.post_json(
            Some(&dev),
            &format!("/v1/projects/{}/push", p.name),
            &json!({"updates": [{"branch": "y/merged", "expected": s.hex(), "new": null}]}),
        );
        (rewind.join().unwrap(), delete)
    });
    assert_eq!(rewind.status, 200, "{}", body(&rewind));
    assert_eq!(rewind.json()["results"][0]["ok"], true, "{}", body(&rewind));
    assert_eq!(api.tips(Some(&admin), &p.name).unwrap().branches["main"], before, "rewound");
    assert_eq!(
        (delete.status, delete.json()["message"].clone()),
        (409, json!("branch 'y/merged' moved during the push; pull, then push again")),
        "{}",
        body(&delete)
    );
    assert_eq!(api.tips(Some(&dev), &p.name).unwrap().branches.get("y/merged"), Some(&s), "the branch and its work stay");
}

/// BUG-2448: a landing deletes only the branch it came from (whose tip is
/// the snapshot landed): naming another branch whose work is on `onto` too
/// (made there by the caller) is refused in the one sentence.
#[test]
fn bug_2448_a_landing_deletes_only_the_branch_it_landed_from() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let (admin, dev) = (p.admin.token(), p.dev.token());
    let main_real = api.tips(Some(&admin), &p.name).unwrap().branches["main"];
    let alice = change_on(&api, &admin, &p.name, main_real, "src/alice.rs");
    set_branch(&api, &admin, &p.name, "alice/work", None, alice);
    // The dev makes `m` at the admin's branch, lands a change onto it, and
    // names the admin's branch.
    let at = api.tips(Some(&dev), &p.name).unwrap().branches["alice/work"];
    set_branch(&api, &dev, &p.name, "m/mine", None, at);
    let t = change_on(&api, &dev, &p.name, at, "src/trivial.rs");
    set_branch(&api, &dev, &p.name, "m/child", None, t);
    let v = land(&api, &dev, &p.name, &json!({"onto": "m/mine", "snapshot": t.hex(), "delete_branch": "alice/work"}));
    assert_eq!((v.get("deleted_branch"), v["warnings"].clone()), (None, json!([not_deleted("alice/work", "m/mine")])), "{v}");
    assert_eq!(api.tips(Some(&admin), &p.name).unwrap().branches.get("alice/work"), Some(&alice), "kept");
    // The branch it came from is deleted as before.
    let t2 = change_on(&api, &dev, &p.name, t, "src/trivial2.rs");
    set_branch(&api, &dev, &p.name, "m/child", Some(t), t2);
    let v = land(&api, &dev, &p.name, &json!({"onto": "m/mine", "snapshot": t2.hex(), "delete_branch": "m/child"}));
    assert_eq!(v["deleted_branch"], "m/child", "{v}");
}

/// BUG-2449: a deletion that fails after its landing committed (here a
/// trigger makes the delete fail) leaves the answer `landed`, with the one
/// sentence; the branch stays.
#[test]
fn bug_2449_a_failed_deletion_after_the_landing_still_answers_landed() {
    let hub = own_hub();
    let p = setup_project(&hub);
    let api = hub.api();
    let dev = p.dev.token();
    sql(
        &hub,
        "CREATE FUNCTION t2449_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'a forced failure'; END $$; \
         CREATE TRIGGER t2449_fail BEFORE DELETE ON branches FOR EACH ROW WHEN (OLD.name = 'u/boom') EXECUTE PROCEDURE t2449_fail();",
    );
    let main = api.tips(Some(&dev), &p.name).unwrap().branches["main"];
    let top = change_on(&api, &dev, &p.name, main, "src/top.rs");
    set_branch(&api, &dev, &p.name, "u/top", None, top);
    let t = change_on(&api, &dev, &p.name, top, "src/boom.rs");
    set_branch(&api, &dev, &p.name, "u/boom", None, t);
    let v = land(&api, &dev, &p.name, &json!({"onto": "u/top", "snapshot": t.hex(), "delete_branch": "u/boom"}));
    assert_eq!(v["landed"].as_array().map(Vec::len), Some(1), "{v}");
    assert_eq!((v.get("deleted_branch"), v["warnings"].clone()), (None, json!([not_deleted("u/boom", "u/top")])), "{v}");
    let landed: ObjectId = serde_json::from_value(v["landed"][0].clone()).unwrap();
    let tips = api.tips(Some(&dev), &p.name).unwrap().branches;
    assert_eq!((tips.get("u/top"), tips.get("u/boom")), (Some(&landed), Some(&t)), "landed, and the branch stays");
}

/// BUG-2447, the lock itself: two deletions, each of a branch whose work is
/// on the other (`branches::delete_held`, as two crossed landings would
/// call it), run at once with every deletion's transaction held open 0.5 s
/// after its delete: exactly one commits, ten times. Without the lock on
/// `onto` both did, and the work was on no branch.
#[test]
fn bug_2447_two_crossed_deletions_never_both_commit() {
    let hub = own_hub();
    let p = setup_project(&hub);
    let api = hub.api();
    let admin = p.admin.token();
    let pid = project_id_of(&hub, &p.name);
    sql(
        &hub,
        "CREATE FUNCTION t2447_hold() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.5); RETURN NULL; END $$; \
         CREATE TRIGGER t2447_hold AFTER DELETE ON branches FOR EACH ROW WHEN (OLD.name LIKE 'z/%') EXECUTE PROCEDURE t2447_hold();",
    );
    let main = api.tips(Some(&admin), &p.name).unwrap().branches["main"];
    let h = hub.hub();
    for round in 0..10 {
        let (a, b) = (format!("z/a{round}"), format!("z/b{round}"));
        let t = change_on(&api, &admin, &p.name, main, &format!("src/z{round}.rs"));
        set_branch(&api, &admin, &p.name, &a, None, t);
        set_branch(&api, &admin, &p.name, &b, None, t);
        let lineage = |n: &str| -> i64 {
            hub.rt
                .block_on(sqlx::query_scalar("SELECT lineage FROM branches WHERE project_id = $1 AND name = $2").bind(pid).bind(n).fetch_one(&h.db))
                .unwrap()
        };
        let (la, lb) = (lineage(&a), lineage(&b));
        let (x, y) = hub.rt.block_on(async {
            let one = veil_server::branches::delete_held(&h, pid, &b, t, &a, la, 0, format!("test: {b} into {a}"));
            let two = veil_server::branches::delete_held(&h, pid, &a, t, &b, lb, 0, format!("test: {a} into {b}"));
            tokio::join!(one, two)
        });
        let (x, y) = (x.expect("the first deletion answers"), y.expect("the second deletion answers"));
        let tips = api.tips(Some(&admin), &p.name).unwrap().branches;
        let left: Vec<&String> = [&a, &b].into_iter().filter(|n| tips.contains_key(*n)).collect();
        assert_eq!((x as usize + y as usize, left.len()), (1, 1), "round {round}: exactly one deleted ({x}, {y}); left {left:?}");
        assert_eq!(tips[left[0]], t, "round {round}: the work is on the branch left");
    }
}
