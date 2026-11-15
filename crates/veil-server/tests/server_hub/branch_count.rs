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
    // A narrowed agent session (src/api/) lands its own work; the branch it
    // names holds the person's work outside its paths, all on `u/top`
    // already: not one it may move, so kept, in the session's own words.
    let outside = change_on(&api, &dev, &p.name, base, "src/outside.rs");
    set_branch(&api, &dev, &p.name, "u/person", None, outside);
    land(&api, &dev, &p.name, &json!({"onto": "u/top", "snapshot": outside.hex()}));
    let narrowed = agent_token(&hub, &dev, &p.name, &["src/api/"]);
    let base = api.tips(Some(&narrowed), &p.name).unwrap().branches["u/top"];
    let inside = change_on(&api, &narrowed, &p.name, base, "src/api/inside.rs");
    set_branch(&api, &narrowed, &p.name, "u/agent", None, inside);
    let v = land(&api, &narrowed, &p.name, &json!({"onto": "u/top", "snapshot": inside.hex(), "delete_branch": "u/person"}));
    assert_eq!(
        (v.get("deleted_branch"), v["warnings"].clone()),
        (None, json!(["this agent session is narrowed: this would change files outside its paths"])),
        "{v}"
    );
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
