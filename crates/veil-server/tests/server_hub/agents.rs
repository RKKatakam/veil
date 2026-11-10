//! Milestone S11 on the server (`docs/HUB.md` §13.27; phase 2 §5.6):
//! agent sessions, narrowing, attribution stamped by the server on API
//! commits, and attempts.
//!
//! Guarantees, each a test here:
//! * an agent session is made only from a person's own session, for one
//!   project, never outlives it nor lasts over 12 hours, and cannot change
//!   access, devices, invites, rings or shares, nor make sessions;
//! * it never sees or writes more than its person, nor (narrowed) any file
//!   outside its paths, by any file route; its history is the person's;
//! * the server stamps its API commits with its attribution; a caller can
//!   never set or forge one;
//! * `task`, `prompt` and attempts' reasons reach exactly the people who
//!   see the change;
//! * attempts never land and never enter ancestry; a valid one is kept,
//!   projected and shown.

use serde_json::{json, Value};
use veil_core::{
    object::{Attribution, Object as O, Snapshot, Text},
    ObjectId,
};

use crate::support::*;

/// The exact answers of the agent-session refusals (`sync.rs`), pinned.
const NARROWED: &str = "this agent session is narrowed: this would change files outside its paths";
const ACCESS_MOVE: &str = "an agent session never moves a branch onto a change of a file that decides access or review (.veilpolicy, .veilrules)";
const DEFAULT_BRANCH_REFUSAL: &str = "an agent session never creates the default branch; its person does";
const NARROWED_READ: &str = "this agent session is narrowed to other paths: ask for a path inside them";
const PERSON_ONLY: &str = "an agent session cannot do this; only its person can, with their own session";
const NO_FORCE: &str = "an agent session never forces a branch move";
const NO_DELETE: &str = "an agent session never deletes a branch";
/// The refusal of an agent session's change of a file that decides access.
fn access_file(path: &str) -> String {
    format!("an agent session never changes '{path}', which decides access or review")
}

/// A 200 push answer whose one branch result is refused with exactly `message`.
fn assert_move_refused(r: &Reply, message: &str, what: &str) {
    assert_eq!(r.status, 200, "{what}: {}", body(r));
    assert_eq!((r.json()["results"][0]["ok"].clone(), r.json()["results"][0]["message"].clone()), (json!(false), json!(message)), "{what}: {}", body(r));
}

/// A 403 `agent_session` with exactly `message`.
fn assert_agent_refusal(r: &Reply, message: &str, what: &str) {
    assert_eq!((r.status, r.json()["code"].clone(), r.json()["message"].clone()), (403, json!("agent_session"), json!(message)), "{what}: {}", body(r));
}

fn session(hub: &TestHub, token: Option<&str>, body: &Value) -> Reply {
    hub.api().post_json(token, "/v1/sessions/agent", body)
}

/// An agent session of `token`'s person in `project`: its token.
fn agent_token(hub: &TestHub, token: &str, project: &str, only: &[&str]) -> String {
    let r = session(hub, Some(token), &json!({"project": project, "attribution": {"agent": "claude-code/2.3", "task": "TASK-S11-1", "run": "run-9"}, "only": only}));
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    r.json()["token"].as_str().unwrap().to_string()
}

fn q(hub: &TestHub, token: Option<&str>, project: &str, route: &str, params: &str) -> Reply {
    hub.api().get(token, &format!("/v1/projects/{project}/q/{route}?{params}"))
}

fn change(hub: &TestHub, token: &str, project: &str, body: &Value) -> Reply {
    hub.api().post_json(Some(token), &format!("/v1/projects/{project}/changes"), body)
}

fn tip(hub: &TestHub, token: &str, project: &str) -> ObjectId {
    hub.api().tips(Some(token), project).unwrap().branches["main"]
}

fn body(r: &Reply) -> String {
    String::from_utf8_lossy(&r.body).into_owned()
}

/// The dev puts `src/api/h.rs` and `src/other.rs` on `main` with their own
/// session: something for a narrowed session to read.
fn with_api_folder(hub: &TestHub, p: &Project) {
    let token = p.dev.token();
    let base = tip(hub, &token, &p.name);
    let r = change(
        hub,
        &token,
        &p.name,
        &json!({"base": base.hex(), "description": "api folder", "onto": {"branch": "main", "expected": base.hex()},
                "edits": [{"path": "src/api/h.rs", "put": {"text": "fn h() {} // MARKER-INSIDE-1c"}},
                          {"path": "src/other.rs", "put": {"text": "fn o() {} // MARKER-OUTSIDE-2d"}}]}),
    );
    assert_eq!(r.status, 200, "{}", body(&r));
    assert_eq!(r.json()["branch"]["status"], "ok", "{}", body(&r));
}

#[test]
fn an_agent_session_comes_from_a_persons_own_session_and_never_outlives_or_widens_it() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let token = p.dev.token();
    let now = veil_core::now_millis();
    let r = session(&hub, Some(&token), &json!({"project": p.name, "attribution": {"agent": "claude"}, "only": ["src/api/", "src/api/x"]}));
    assert_eq!(r.status, 200, "{}", body(&r));
    let s = r.json();
    assert_eq!(s["person"], p.dev.name.as_str());
    assert_eq!(s["only"], json!(["src/api"]), "the narrowing is normalised");
    // The test server's sessions last an hour: never past the parent's.
    let expires = s["expires_at"].as_i64().unwrap();
    assert!(expires <= now + 3600 * 1000 + 60_000 && expires > now, "{s}");
    let short = session(&hub, Some(&token), &json!({"project": p.name, "attribution": {"agent": "claude"}, "seconds": 10}));
    assert_eq!(short.status, 200, "{}", body(&short));
    assert!(short.json()["expires_at"].as_i64().unwrap() <= veil_core::now_millis() + 11_000);
    // An agent session makes no session.
    let agent = s["token"].as_str().unwrap();
    let r = session(&hub, Some(agent), &json!({"project": p.name, "attribution": {"agent": "nested"}}));
    assert_agent_refusal(&r, PERSON_ONLY, "a session from an agent session");
    // Signed out, a project nobody can see, hostile input: refused, never echoed.
    assert_eq!(session(&hub, None, &json!({"project": p.name, "attribution": {"agent": "a"}})).status, 401);
    assert_eq!(session(&hub, Some(&token), &json!({"project": "no-such-project-77", "attribution": {"agent": "a"}})).status, 404);
    for bad in [
        json!({"project": p.name, "attribution": {"agent": "evil\u{1b}[2J"}}),
        json!({"project": p.name, "attribution": {"agent": "a", "run": "has space"}}),
        json!({"project": p.name, "attribution": {"agent": "a"}, "only": ["src/../billing"]}),
        json!({"project": p.name, "attribution": {"agent": "a"}, "only": ["src/*"]}),
        json!({"project": p.name, "attribution": {"agent": "a"}, "only": ["\u{1b}]8;;x"]}),
        json!({"project": p.name, "attribution": {"agent": "a"}, "only": vec!["a"; 65]}),
        json!({"project": p.name, "attribution": {"agent": "a"}, "seconds": 0}),
        json!({"project": p.name, "attribution": {"agent": "a"}, "wider": true}),
    ] {
        let r = session(&hub, Some(&token), &bad);
        // An unknown field is the JSON parser's 422; every other input is
        // the route's own refusal.
        match bad.get("wider") {
            Some(_) => assert_eq!(r.status, 422, "{bad}: {}", body(&r)),
            None => assert_eq!((r.status, r.json()["code"].clone()), (400, json!("bad_request")), "{bad}: {}", body(&r)),
        }
        assert!(!body(&r).contains('\u{1b}'), "{bad}: echoed");
    }
    // A session for one project works in it only, even where its person
    // sees more (another project's public folder).
    let other = setup_project(&hub);
    let mine = q(&hub, Some(&token), &other.name, "log", "");
    assert_eq!(mine.status, 200, "control: the dev sees the other project's public folder: {}", body(&mine));
    for route in ["log", "show"] {
        assert_eq!(q(&hub, Some(agent), &other.name, route, "").status, 404, "{route}");
    }
    assert!(hub.api().tips(Some(agent), &other.name).is_none(), "tips of another project");
    assert_eq!(q(&hub, Some(agent), &p.name, "log", "").status, 200, "control: its own project");
}

#[test]
fn an_agent_session_cannot_change_access_devices_invites_rings_shares_or_projects() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let agent = agent_token(&hub, &p.admin.token(), &p.name, &[]);
    let api = hub.api();
    let pr = &p.name;
    let refused: Vec<(String, Value)> = vec![
        (format!("/v1/projects/{pr}/groups/agents"), json!({})),
        (format!("/v1/projects/{pr}/groups/devs/members"), json!({"people": [p.fin.name]})),
        (format!("/v1/projects/{pr}/groups/devs/members/remove"), json!({"people": [p.dev.name]})),
        (format!("/v1/projects/{pr}/groups/devs/managers"), json!({"people": [p.dev.name]})),
        (format!("/v1/projects/{pr}/invites"), json!({"person": "newbie", "group": "devs", "key": "00", "expires_at": 0, "secret_hash": "00"})),
        ("/v1/devices/vouch".to_string(), json!({"device": "veil1x", "signature": "00"})),
        ("/v1/devices/remove".to_string(), json!({"device": "veil1x"})),
        (format!("/v1/projects/{}", unique("agentmade")), json!({})),
        // Bodies that parse, so the answer is the route's, not the parser's
        // (each refused as an agent's before anything in it is read).
        (format!("/v1/projects/{pr}/rings/team"), json!({"scope": "team"})),
        (
            format!("/v1/projects/{pr}/shares"),
            json!({"expect": 0, "reshare": false, "record": {"format": 1, "project": "00", "path": "billing/.env", "sharer": p.dev.name,
                   "recipient": p.fin.name, "version": 1, "at": 0, "signer": "00", "sealed": "00", "wraps": [], "signature": "00"}}),
        ),
        (format!("/v1/projects/{pr}/shares/remove"), json!({"path": "billing/.env", "recipient": p.fin.name})),
    ];
    for (path, v) in refused {
        let r = api.post_json(Some(&agent), &path, &v);
        assert_agent_refusal(&r, PERSON_ONLY, &path);
    }
    // The ones that parse are refused as an agent's, not for their input.
    let r = api.post_json(Some(&agent), &format!("/v1/projects/{pr}/groups/agents"), &json!({}));
    assert_agent_refusal(&r, PERSON_ONLY, "a group");
    let r = api.post(Some(&agent), &format!("/v1/projects/{}", unique("agentmade")), b"", false);
    assert_agent_refusal(&r, PERSON_ONLY, "a project");
    // Control: the admin's own session creates the group.
    let r = api.post(Some(&p.admin.token()), &format!("/v1/projects/{pr}/groups/agents"), b"", false);
    assert_eq!(r.status, 200, "{}", body(&r));
}

#[test]
fn a_narrowed_session_reads_and_writes_only_inside_its_paths_and_its_history_is_its_persons() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    with_api_folder(&hub, &p);
    let token = p.dev.token();
    let agent = agent_token(&hub, &token, &p.name, &["src/api"]);
    // Files inside: read.
    let r = q(&hub, Some(&agent), &p.name, "file", "path=src/api/h.rs");
    assert_eq!(r.status, 200, "{}", body(&r));
    assert!(body(&r).contains("MARKER-INSIDE-1c"));
    assert_eq!(q(&hub, Some(&agent), &p.name, "tree", "path=src/api").status, 200);
    assert_eq!(q(&hub, Some(&agent), &p.name, "show", "path=src/api").status, 200);
    // Outside, by every file route: refused, and nothing of it in the answer.
    for (route, params) in [
        ("file", "path=src/other.rs"),
        ("file", "path=src/lib.rs"),
        ("tree", "path=src"),
        ("tree", ""),
        ("show", ""),
        ("show", "path=src"),
        ("diff", "from=main&base=from"),
        ("diff", "from=main&base=from&path=src/other.rs"),
        ("search", "q=MARKER"),
        ("search", "q=MARKER&path=src"),
        ("grep", "pattern=MARKER"),
        ("grep", "pattern=MARKER&path=src"),
    ] {
        let r = q(&hub, Some(&agent), &p.name, route, params);
        assert_agent_refusal(&r, NARROWED_READ, &format!("{route}?{params}"));
        assert!(!body(&r).contains("MARKER-OUTSIDE-2d") && !body(&r).contains(PUBLIC_MARK), "{route}?{params}");
        // Control: the person reads it.
        if route != "search" && route != "grep" {
            assert_eq!(q(&hub, Some(&token), &p.name, route, params).status, 200, "control {route}?{params}");
        }
    }
    // Grants reach everything below their root: a narrowed session has none.
    let t = hub.api().tips(Some(&agent), &p.name).unwrap();
    assert!(t.grants.is_empty(), "{:?}", t.grants);
    assert!(!hub.api().tips(Some(&token), &p.name).unwrap().grants.is_empty(), "control: the person's tips carry grants");
    // Fetch: the folders on the way (their trees), files inside; nothing else.
    let tree_of = |path: &str| -> Value { q(&hub, Some(&token), &p.name, "tree", &format!("path={path}")).json() };
    let root = tree_of("");
    let src = tree_of("src");
    let api = tree_of("src/api");
    let id_in = |t: &Value, name: &str| t["entries"].as_array().unwrap().iter().find(|e| e["name"] == name).unwrap()["id"].as_str().unwrap().to_string();
    let snap = tip(&hub, &agent, &p.name);
    let fetch = |path: &str, id: &str| hub.api().post_json(Some(&agent), &format!("/v1/projects/{}/fetch", p.name), &json!({"snapshot": snap.hex(), "objects": [{"path": path, "id": id}]}));
    for (path, id) in [("", root["id"].as_str().unwrap().to_string()), ("src", id_in(&root, "src")), ("src/api", id_in(&src, "api")), ("src/api/h.rs", id_in(&api, "h.rs"))] {
        let r = fetch(path, &id);
        assert_eq!(r.status, 200, "{path}: {}", body(&r));
    }
    for (path, id) in [("src/other.rs", id_in(&src, "other.rs")), ("src/lib.rs", id_in(&src, "lib.rs"))] {
        let r = fetch(path, &id);
        assert_eq!(r.status, 404, "{path}: {} {}", r.status, body(&r));
        assert!(!body(&r).contains("MARKER"), "{path}");
    }
    // Writes: inside only (the dev may write all of src/).
    let base = tip(&hub, &agent, &p.name);
    let inside = change(&hub, &agent, &p.name, &json!({"base": base.hex(), "description": "inside", "edits": [{"path": "src/api/new.rs", "put": {"text": "x"}}]}));
    assert_eq!(inside.status, 200, "{}", body(&inside));
    for path in ["src/other.rs", "src/apix.rs", ".veilpolicy", "src/api"] {
        let r = change(&hub, &agent, &p.name, &json!({"base": base.hex(), "description": "outside", "edits": [{"path": path, "put": {"text": "x"}}]}));
        match path {
            // Inside the narrowing: a file where a folder is, the route's own refusal.
            "src/api" => assert_eq!((r.status, r.json()["code"].clone()), (400, json!("bad_request")), "{path}: {}", body(&r)),
            _ => assert_agent_refusal(&r, NARROWED, path),
        }
    }
    let r = change(&hub, &token, &p.name, &json!({"base": base.hex(), "description": "control", "edits": [{"path": "src/other.rs", "put": {"text": "y"}}]}));
    assert_eq!(r.status, 200, "control: the person writes src/other.rs: {}", body(&r));
    // History is the person's projection: the same log, the same ids.
    let ids = |t: &str| -> Vec<String> {
        let r = q(&hub, Some(t), &p.name, "log", "");
        assert_eq!(r.status, 200, "{}", body(&r));
        r.json()["entries"].as_array().unwrap().iter().map(|e| e["snapshot_id"].as_str().unwrap().to_string()).collect()
    };
    assert_eq!(ids(&agent), ids(&token));
}

#[test]
fn api_commits_carry_the_sessions_attribution_and_never_the_callers() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let token = p.dev.token();
    let agent = agent_token(&hub, &token, &p.name, &[]);
    let base = tip(&hub, &agent, &p.name);
    let r = change(
        &hub,
        &agent,
        &p.name,
        &json!({"base": base.hex(), "description": "by the agent", "edits": [{"path": "src/a.rs", "put": {"text": "a"}}],
                "onto": {"branch": "main", "expected": base.hex()}}),
    );
    assert_eq!(r.status, 200, "{}", body(&r));
    assert_eq!(r.json()["branch"]["status"], "ok", "{}", body(&r));
    // Every viewer of the change sees the server's stamp (on `main` now).
    for who in [&token, &p.admin.token(), &agent, &p.fin.token()] {
        let show = q(&hub, Some(who), &p.name, "show", "path=src");
        assert_eq!(show.status, 200, "{}", body(&show));
        let v = show.json();
        assert_eq!(v["agent"]["agent"], "claude-code/2.3", "{v}");
        assert_eq!(v["agent"]["task"], "TASK-S11-1", "{v}");
    }
    // The request has no field for one: a caller's is refused, nothing stored.
    let forged = change(
        &hub,
        &token,
        &p.name,
        &json!({"base": base.hex(), "description": "forged", "agent": {"agent": "someone-else"}, "edits": [{"path": "src/f.rs", "put": {"text": "f"}}]}),
    );
    // No field for it: the JSON parser's refusal of an unknown field.
    assert_eq!(forged.status, 422, "{}", body(&forged));
    // The person's own commit carries none.
    let mine = change(&hub, &token, &p.name, &json!({"base": base.hex(), "description": "by the person", "edits": [{"path": "src/m.rs", "put": {"text": "m"}}]}));
    assert_eq!(mine.status, 200, "{}", body(&mine));
    let id = mine.json()["snapshot"].as_str().unwrap().to_string();
    let v = q(&hub, Some(&token), &p.name, "show", &format!("rev={id}&path=src")).json();
    assert!(v["agent"].is_null(), "{v}");
}

/// A signed snapshot on `tip` with `edit` applied, uploaded by `c`.
fn crafted(c: &mut Craft, edit: impl FnOnce(&mut Snapshot)) -> (ObjectId, Snapshot) {
    let mut s = Snapshot {
        parents: vec![c.tip],
        change_id: veil_core::ChangeId::random(),
        tree: c.root,
        description: Text::Plain("crafted".into()),
        author: "crafter".into(),
        timestamp: veil_core::now_millis(),
        predecessors: vec![],
        conflicts: vec![],
        embargo: None,
        agent: None,
        abandoned: None,
        attempts: vec![],
        signature: None,
    };
    edit(&mut s);
    s.sign(&c.identity);
    (c.put_object(O::Snapshot(s.clone())), s)
}

fn attribution(task: &str) -> Attribution {
    Attribution { agent: "claude-code".into(), task: Some(task.into()), prompt: Some("PROMPT-S11-REF-61".into()), run: None }
}

#[test]
fn attempts_never_land_and_a_valid_one_is_kept_projected_and_shown() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    // A branch's tip at an abandoned snapshot: refused.
    let mut c = Craft::new(&api, &p.dev, &p.name, "main");
    let tip0 = c.tip;
    c.file("src/tried.rs", "tried");
    let (_, r) = c.push_edited("main", Some(tip0), |s| s.abandoned = Some("dead end".into()));
    assert_eq!(r.status, 400, "{}", body(&r));
    assert!(body(&r).contains("abandoned attempt"), "{}", body(&r));
    // A snapshot built on one: refused.
    let mut c = Craft::new(&api, &p.dev, &p.name, "main");
    c.file("src/tried.rs", "tried");
    let (a, _) = crafted(&mut c, |s| s.abandoned = Some("dead end".into()));
    let (_, r) = c.push_edited("main", Some(tip0), |s| s.parents = vec![a]);
    assert_eq!(r.status, 400, "{}", body(&r));
    // An "attempt" that is not an abandoned version of the same change: refused.
    let mut c = Craft::new(&api, &p.dev, &p.name, "main");
    c.file("src/tried.rs", "tried");
    let (plain, _) = crafted(&mut c, |_| {});
    let (_, r) = c.push_edited("main", Some(tip0), |s| s.attempts = vec![plain]);
    assert_eq!(r.status, 400, "{}", body(&r));
    // A valid attempt on a change of src/ and billing: kept.
    let mut c = Craft::new(&api, &p.admin, &p.name, "main");
    let tip0 = c.tip;
    c.file("src/tried.rs", "tried src");
    c.file(&format!("{BILL_DIR}/tried.txt"), "tried billing");
    let cid = veil_core::ChangeId::random();
    let (a, _) = crafted(&mut c, |s| {
        s.change_id = cid;
        s.abandoned = Some("REASON-S11-SEEN-BY-DEVS-4a: deadlocks".into());
        s.agent = Some(attribution("TASK-S11-SEEN-BY-DEVS-5b"));
    });
    let mut c2 = Craft::new(&api, &p.admin, &p.name, "main");
    c2.objects = c.objects.clone();
    c2.file("src/done.rs", "done");
    let (_, r) = c2.push_edited("main", Some(tip0), |s| {
        s.change_id = cid;
        s.attempts = vec![a];
        s.agent = Some(attribution("TASK-S11-SEEN-BY-DEVS-5b"));
    });
    assert_eq!(r.status, 200, "{}", body(&r));
    assert!(r.json()["results"][0]["ok"].as_bool().unwrap(), "{}", body(&r));
    // The dev sees the change, so its task, prompt and the attempt's reason;
    // not the attempt's billing file.
    let dev = p.dev.token();
    let show = q(&hub, Some(&dev), &p.name, "show", "");
    assert_eq!(show.status, 200, "{}", body(&show));
    let v = show.json();
    assert_eq!(v["agent"]["task"], "TASK-S11-SEEN-BY-DEVS-5b", "{v}");
    let attempts = v["attempts"].as_array().unwrap_or_else(|| panic!("no attempts: {v}"));
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0]["reason"], "REASON-S11-SEEN-BY-DEVS-4a: deadlocks");
    assert_eq!(attempts[0]["files"], json!(["src/tried.rs"]), "{v}");
    assert!(!show.body.windows(BILL_DIR.len()).any(|w| w == BILL_DIR.as_bytes()), "the dev saw a hidden name");
    // The attempt travels with the change in the dev's history, projected.
    let t = tip(&hub, &dev, &p.name);
    let h = api.history(&dev, &p.name, &[t]);
    assert_eq!(h.status, 200);
    let frames = h.frames();
    let snaps: Vec<Snapshot> = frames.iter().filter_map(|(_, raw)| match O::decode(raw) { Ok(O::Snapshot(s)) => Some(s), _ => None }).collect();
    let mine = snaps.iter().find(|s| s.change_id == cid && s.abandoned.is_none()).expect("the change");
    assert_eq!(mine.attempts.len(), 1);
    let pa = snaps.iter().find(|s| frames.iter().any(|(id, _)| *id == mine.attempts[0]) && s.abandoned.is_some()).expect("the projected attempt");
    assert_eq!(pa.abandoned.as_deref(), Some("REASON-S11-SEEN-BY-DEVS-4a: deadlocks"));
    // Never a tip, never in the log.
    let log = body(&q(&hub, Some(&dev), &p.name, "log", ""));
    assert!(!log.contains(&mine.attempts[0].hex()), "the attempt is in the log");
}

/// Threats 1 and 2 of `7-agent-attribution.md` on the server: a change of
/// billing only, made by an agent with an attempt, is not in the dev's
/// history; its task, prompt and reason reach finance and admins, and
/// nobody else by any route (log, show, history, fetch, a clone).
#[test]
fn task_prompt_and_reasons_reach_exactly_who_sees_the_change() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let mut c = Craft::new(&api, &p.fin, &p.name, "main");
    let tip0 = c.tip;
    c.file(&format!("{BILL_DIR}/try.txt"), "a try");
    let cid = veil_core::ChangeId::random();
    let (a, _) = crafted(&mut c, |s| {
        s.change_id = cid;
        s.abandoned = Some("REASON-BILLING-ONLY-7e1d".into());
        s.agent = Some(attribution("TASK-BILLING-ONLY-91aa"));
    });
    let mut c2 = Craft::new(&api, &p.fin, &p.name, "main");
    c2.objects = c.objects.clone();
    c2.file(&format!("{BILL_DIR}/done.txt"), "done");
    let (_, r) = c2.push_edited("main", Some(tip0), |s| {
        s.change_id = cid;
        s.attempts = vec![a];
        s.agent = Some(attribution("TASK-BILLING-ONLY-91aa"));
    });
    assert_eq!(r.status, 200, "{}", body(&r));
    assert!(r.json()["results"][0]["ok"].as_bool().unwrap(), "{}", body(&r));
    let markers = ["TASK-BILLING-ONLY-91aa", "REASON-BILLING-ONLY-7e1d", "PROMPT-S11-REF-61"];
    // Who sees the change sees them.
    for who in [&p.fin, &p.admin] {
        let v = body(&q(&hub, Some(&who.token()), &p.name, "show", ""));
        for m in markers {
            assert!(v.contains(m), "{} lacks {m}: {v}", who.name);
        }
    }
    // Nobody else, by any route.
    for (who, token) in [("dev", Some(p.dev.token())), ("carol", Some(p.carol.token())), ("anyone", None)] {
        let t = token.as_deref();
        let mut seen = Vec::new();
        for (route, params) in [("log", ""), ("show", ""), ("show", "path=src")] {
            seen.push((format!("{route}?{params}"), q(&hub, t, &p.name, route, params).body));
        }
        if let Some(tips) = api.tips(t, &p.name) {
            let tip = tips.branches["main"];
            // As this release's vl asks (it reads format 10).
            let h = match t {
                Some(t) => api.history(t, &p.name, &[tip]),
                None => api.post_with(
                    &format!("/v1/projects/{}/history", p.name),
                    &serde_json::to_vec(&json!({"tips": [tip.hex()]})).unwrap(),
                    &[(veil_core::hub::wire::FORMAT_HEADER, "10")],
                ),
            };
            assert_eq!(h.status, 200, "{who}: {}", body(&h));
            seen.push(("history".into(), h.body));
        }
        let items: Vec<(String, Vec<u8>)> = seen;
        assert_no_marker(&items, &markers, who);
    }
    // A clone by the dev holds none of them.
    let d = p.dev.dir("clone-s11");
    p.dev.clone_trusting(&hub.url(&p.name), &d, &p.fp);
    assert_no_marker(&everything_in(&d), &markers, "dev's clone");
}

/// End to end through `vl`: a member's agent drops an attempt and commits
/// in a clone, pushes; the server keeps both, and another member's clone
/// pulls them and shows them.
#[test]
fn a_vl_push_and_pull_carry_attribution_and_attempts() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let d = p.dev.dir("agent-clone");
    p.dev.clone_trusting(&hub.url(&p.name), &d, &p.fp);
    let as_agent = |args: &[&str]| {
        let mut c = p.dev.command(&d, args);
        c.env("VEIL_AGENT", "claude-code").env("VEIL_AGENT_TASK", "TASK-E2E-31");
        let o = c.output().unwrap();
        assert!(o.status.success(), "{args:?}: {}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    };
    write_files(&d, &[("src/lease.rs", "fn hold() {}\n")]);
    as_agent(&["attempt", "drop", "--reason", "REASON-E2E-77: deadlocks"]);
    write_files(&d, &[("src/lease.rs", "fn take() {}\n")]);
    as_agent(&["commit", "-m", "lease, second try"]);
    p.dev.ok(&d, &["tag", "set", "main", "-r", "@-", "--force"]);
    p.dev.ok(&d, &["push"]);
    // The server shows them to whoever sees the change.
    let v = q(&hub, Some(&p.admin.token()), &p.name, "show", "").json();
    assert_eq!(v["agent"]["task"], "TASK-E2E-31", "{v}");
    assert_eq!(v["attempts"][0]["reason"], "REASON-E2E-77: deadlocks", "{v}");
    assert_eq!(v["attempts"][0]["files"], json!(["src/lease.rs"]), "{v}");
    // Another member's clone pulls the attempt with its change.
    let f = p.fin.dir("fin-clone");
    p.fin.clone_trusting(&hub.url(&p.name), &f, &p.fp);
    let show = p.fin.ok(&f, &["show", "main"]);
    assert!(show.contains("Agent     : claude-code") && show.contains("Discarded attempts (1):") && show.contains("REASON-E2E-77"), "{show}");
    assert!(show.contains("changed: src/lease.rs"), "{show}");
    p.fin.ok(&f, &["fsck"]);
}

// ---- S11 review, cycle 1 ---------------------------------------------------------

/// A server of the release before migration 20 finds a session by its
/// token's hash alone (`auth.rs` of `integration` @ 6fa552c4): in a rolling
/// upgrade it runs beside servers that make agent sessions, on the same
/// database. It must never find an agent session's token, or it would take
/// it as its person's own session: unnarrowed, in every project, able to
/// make sessions and change access.
#[test]
fn an_agent_sessions_token_is_never_a_full_session_to_a_server_that_predates_it() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let token = p.dev.token();
    let agent = agent_token(&hub, &token, &p.name, &["src/api"]);
    // The previous release's lookup, verbatim but for the epochs.
    let old_lookup = |t: &str| -> Option<i64> {
        hub.rt
            .block_on(
                sqlx::query_scalar::<_, i64>(
                    "SELECT p.id FROM sessions s JOIN devices d ON d.id = s.device_id JOIN people p ON p.id = s.person_id \
                     WHERE s.token_hash = $1 AND s.expires_at > $2 AND d.removed_at IS NULL AND NOT d.pending",
                )
                .bind(veil_server::auth::token_hash(t))
                .bind(veil_core::now_millis())
                .fetch_optional(&hub.hub().db),
            )
            .unwrap()
    };
    assert!(old_lookup(&token).is_some(), "control: the older server finds the person's own session");
    assert_eq!(old_lookup(&agent), None, "an older server takes the agent session for its person's own");
}

/// An agent session cannot change who has access (`docs/HUB.md` §13.27):
/// not through the access routes, and not through `.veilpolicy`, the
/// access lines an admin's commit on the default branch makes the project's
/// policy. An admin's agent session making a private folder public through
/// an API commit is refused; the admin's own session may.
#[test]
fn an_admins_agent_session_cannot_change_access_through_the_policy_file() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let atok = p.admin.token();
    let agent = agent_token(&hub, &atok, &p.name, &[]);
    let policy = std::fs::read_to_string(p.dir.join(".veilpolicy")).unwrap();
    let edit = |tok: &str| {
        let base = tip(&hub, tok, &p.name);
        change(
            &hub,
            tok,
            &p.name,
            &json!({"base": base.hex(), "description": "open carol's folder",
                    "edits": [{"path": ".veilpolicy", "put": {"text": format!("{policy}{PERSON_DIR}/ public\n")}}],
                    "onto": {"branch": "main", "expected": base.hex()}}),
        )
    };
    let anyone_reads = || q(&hub, None, &p.name, "file", &format!("path={PERSON_DIR}/notes.txt")).status == 200;
    assert!(!anyone_reads(), "control: carol's folder is private");
    let r = edit(&agent);
    assert_agent_refusal(&r, &access_file(".veilpolicy"), "the admin's agent session's commit of .veilpolicy");
    assert!(!anyone_reads(), "carol's folder became public through an agent session");
    // Control: the admin's own session may.
    let r = edit(&atok);
    assert_eq!(r.status, 200, "{}", body(&r));
    assert_eq!(r.json()["branch"]["status"], "ok", "{}", body(&r));
    assert!(anyone_reads(), "control: the admin's own change opened it");
}

/// A narrowed session writes only inside its paths (`View::write`). Moving
/// a branch back (a forced push) or deleting it takes away what others
/// wrote everywhere else: an admin's session narrowed to `src/api` may do
/// neither. Neither needs a new snapshot, so neither needs a device key:
/// the token is enough.
#[test]
fn an_admins_narrowed_agent_session_neither_forces_nor_deletes_a_branch() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let atok = p.admin.token();
    let before = tip(&hub, &atok, &p.name);
    with_api_folder(&hub, &p);
    let main = tip(&hub, &atok, &p.name);
    assert_ne!(main, before);
    // A branch of the admin's own, for the deletion.
    let api = hub.api();
    let r = Craft::new(&api, &p.admin, &p.name, "main").push_to("release-77ab", None);
    assert_eq!(r.status, 200, "{}", body(&r));
    let release = api.tips(Some(&atok), &p.name).unwrap().branches["release-77ab"];
    let agent = agent_token(&hub, &atok, &p.name, &["src/api"]);
    let push = |updates: Value, force: bool| api.post_json(Some(&agent), &format!("/v1/projects/{}/push", p.name), &json!({"updates": updates, "force": force}));
    // Forced back to before `src/other.rs` existed.
    let forced = push(json!([{"branch": "main", "expected": main.hex(), "new": before.hex()}]), true);
    // Deleted.
    let deleted = push(json!([{"branch": "release-77ab", "expected": release.hex(), "new": null}]), false);
    let tips = api.tips(Some(&atok), &p.name).unwrap().branches;
    assert_agent_refusal(&forced, NO_FORCE, "forced");
    assert_agent_refusal(&deleted, NO_DELETE, "deleted");
    assert_eq!(tips["main"], main, "main moved back");
    assert_eq!(q(&hub, Some(&atok), &p.name, "file", "path=src/other.rs").status, 200, "src/other.rs left main");
    assert_eq!(tips.get("release-77ab"), Some(&release), "the branch is gone");
}

/// A `vl` of the release before format 10 decodes every snapshot strictly
/// (`Object::decode`: "snapshot is not in canonical encoding"), and its
/// pull stops at the first one it cannot read. Once any change of a project
/// is attributed, such a client is told its pull found a corrupt object.
/// A client that does not say it reads format 10 (the previous release
/// sends nothing) must be told to update `vl` instead, before anything is
/// sent.
#[test]
fn a_client_that_predates_format_10_is_told_to_update_not_sent_what_it_calls_corrupt() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let token = p.dev.token();
    let agent = agent_token(&hub, &token, &p.name, &[]);
    let base = tip(&hub, &agent, &p.name);
    let r = change(&hub, &agent, &p.name, &json!({"base": base.hex(), "description": "by an agent", "edits": [{"path": "src/a.rs", "put": {"text": "a"}}],
                                                  "onto": {"branch": "main", "expected": base.hex()}}));
    assert_eq!(r.status, 200, "{}", body(&r));
    assert_eq!(r.json()["branch"]["status"], "ok", "{}", body(&r));
    // What the previous release's pull asks for: history from the new tip.
    let fin = p.fin.token();
    let t = tip(&hub, &fin, &p.name);
    let h = hub.api().post_json(Some(&fin), &format!("/v1/projects/{}/history", p.name), &json!({"tips": [t.hex()]}));
    let newer: Vec<String> = match h.status {
        200 => h.frames().iter().filter(|(_, raw)| O::min_repo_format(raw) >= veil_core::object::ATTRIBUTION_REPO_FORMAT).map(|(id, _)| id.short()).collect(),
        _ => vec![],
    };
    assert_ne!(h.status, 200, "an older vl was sent format-10 snapshots {newer:?}, which it reports as corrupt");
    assert_eq!((h.status, h.json()["code"].clone()), (426, json!("update_vl")), "{}", body(&h));
    assert!(body(&h).contains("vl"), "the refusal names the release to update to: {}", body(&h));
}

/// Guarantee 1, revocation: an agent session is checked as its person,
/// request by request. A person removed from the group that lets them write
/// `src/` writes nothing there through their agent session; a device an
/// admin bars from the project takes its agent sessions with it.
#[test]
fn an_agent_session_loses_what_its_person_loses_at_once() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let token = p.dev.token();
    let agent = agent_token(&hub, &token, &p.name, &[]);
    let write = |tok: &str, path: &str| {
        let base = tip(&hub, tok, &p.name);
        change(&hub, tok, &p.name, &json!({"base": base.hex(), "description": "w", "edits": [{"path": path, "put": {"text": "w"}}]}))
    };
    let r = write(&agent, "src/before.rs");
    assert_eq!(r.status, 200, "control: the agent writes src/: {}", body(&r));
    let atok = p.admin.token();
    let r = hub.api().post_json(Some(&atok), &format!("/v1/projects/{}/groups/devs/members/remove", p.name), &json!({"people": [p.dev.name]}));
    assert_eq!(r.status, 200, "{}", body(&r));
    let r = write(&agent, "src/after.rs");
    assert_eq!(r.status, 403, "the agent of a person no longer in devs wrote src/: {}", body(&r));
    assert_eq!(r.json()["code"], "forbidden", "{}", body(&r));
    // Barred: a device's agent sessions are refused everywhere in the project.
    let fin_agent = agent_token(&hub, &p.fin.token(), &p.name, &[]);
    assert_eq!(hub.api().get(Some(&fin_agent), &format!("/v1/projects/{}/tips", p.name)).status, 200, "control");
    let r = hub.api().post_json(Some(&atok), "/v1/devices/remove", &json!({"device": p.fin.identity().public_id(), "project": p.name}));
    assert_eq!(r.status, 200, "{}", body(&r));
    let r = hub.api().get(Some(&fin_agent), &format!("/v1/projects/{}/tips", p.name));
    assert_eq!(r.status, 403, "a barred device's agent session: {}", body(&r));
    assert_eq!(r.json()["code"], "forbidden", "{}", body(&r));
    assert_eq!(q(&hub, Some(&fin_agent), &p.name, "file", &format!("path={BILL_DIR}/acme/invoice.txt")).status, 403, "a file through a barred device's agent session");
}

/// Guarantee 3, the builder's residual: a narrowed session is served the
/// folders on the way to its paths, so it learns the names in them. They
/// are exactly its person's (the person's projection, the same bytes): no
/// name the person cannot see, and no file of them.
#[test]
fn the_folders_on_the_way_are_exactly_what_the_person_sees() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    with_api_folder(&hub, &p);
    let token = p.dev.token();
    let agent = agent_token(&hub, &token, &p.name, &["src/api"]);
    let snap = tip(&hub, &agent, &p.name);
    assert_eq!(snap, tip(&hub, &token, &p.name), "the agent's history is the person's");
    let root = q(&hub, Some(&token), &p.name, "tree", "").json();
    let src_id = root["entries"].as_array().unwrap().iter().find(|e| e["name"] == "src").unwrap()["id"].as_str().unwrap().to_string();
    let fetch = |tok: &str, path: &str, id: &str| hub.api().post_json(Some(tok), &format!("/v1/projects/{}/fetch", p.name), &json!({"snapshot": snap.hex(), "objects": [{"path": path, "id": id}]}));
    for (path, id) in [("", root["id"].as_str().unwrap().to_string()), ("src", src_id)] {
        let a = fetch(&agent, path, &id);
        assert_eq!(a.status, 200, "{path}: {}", body(&a));
        let mine = fetch(&token, path, &id);
        assert_eq!(mine.status, 200, "{path}: {}", body(&mine));
        assert_eq!(a.frames(), mine.frames(), "{path:?}: the agent's folder differs from its person's");
        let items = vec![(path.to_string(), a.body.clone())];
        assert_no_marker(&items, &[BILL_DIR, PERSON_DIR, NESTED_DIR, ROOT_FILE], "a narrowed agent session");
    }
}

// ---- S11 cycle 2: the classes of BUG-1377 and BUG-1378 -----------------------------

/// BUG-1377's class: an agent session never changes a file that decides
/// access or review, by any route: its own push, its own API commit (at the
/// root or in a folder; `.veilrules` as `.veilpolicy`), a merge that takes
/// someone else's change of one, or a branch move that lands someone else's.
#[test]
fn an_agent_session_never_changes_a_file_that_decides_access_by_any_route() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let atok = p.admin.token();
    let agent = agent_token(&hub, &atok, &p.name, &[]);
    let opened = format!("{}{PERSON_DIR}/ public\n", std::fs::read_to_string(p.dir.join(".veilpolicy")).unwrap());
    // Its own push, signed by its person's device (the workspace vl holds it).
    let mut c = Craft::with(&api, agent.clone(), p.admin.identity(), &p.name, "main");
    let tip0 = c.tip;
    c.file(".veilpolicy", &opened);
    let r = c.push_to("main", Some(tip0));
    assert_agent_refusal(&r, &access_file(".veilpolicy"), "its own push");
    // Its own API commits: `.veilrules`, and a policy file in a folder.
    for path in [".veilrules", "src/.veilpolicy", ".veilpolicy"] {
        let r = change(&hub, &agent, &p.name, &json!({"base": tip0.hex(), "description": "x", "edits": [{"path": path, "put": {"text": "src/ public\n"}}]}));
        assert_agent_refusal(&r, &access_file(path), path);
    }
    // Someone else's change of it: the admin's own, on a side branch.
    let mut own = Craft::new(&api, &p.admin, &p.name, "main");
    own.file(".veilpolicy", &opened);
    let r = own.push_to("policy-side-2b", None);
    assert_eq!(r.status, 200, "{}", body(&r));
    assert!(r.json()["results"][0]["ok"].as_bool().unwrap(), "{}", body(&r));
    let side = api.tips(Some(&atok), &p.name).unwrap().branches["policy-side-2b"];
    // A merge that takes it, onto a branch of the agent's.
    let mut m = Craft::with(&api, agent.clone(), p.admin.identity(), &p.name, "main");
    m.file(".veilpolicy", &opened);
    let (_, r) = m.push_edited("agent-side-1a", None, |s| s.parents.push(side));
    assert_agent_refusal(&r, &access_file(".veilpolicy"), "a merge taking someone else's change of .veilpolicy");
    // A move of the default branch that lands it.
    let r = api.post_json(Some(&agent), &format!("/v1/projects/{}/push", p.name), &json!({"updates": [{"branch": "main", "expected": tip0.hex(), "new": side.hex()}]}));
    assert_agent_refusal(&r, ACCESS_MOVE, "a fast-forward landing someone else's .veilpolicy");
    assert_eq!(q(&hub, None, &p.name, "file", &format!("path={PERSON_DIR}/notes.txt")).status, 404, "carol's folder became public");
    // Control: the admin's own session lands it.
    let r = api.post_json(Some(&atok), &format!("/v1/projects/{}/push", p.name), &json!({"updates": [{"branch": "main", "expected": tip0.hex(), "new": side.hex()}]}));
    assert_eq!(r.status, 200, "{}", body(&r));
    assert!(r.json()["results"][0]["ok"].as_bool().unwrap(), "{}", body(&r));
}

/// BUG-1378's class: no agent session forces or deletes a branch (narrowed
/// or not), and a narrowed one moves a branch only when the move changes
/// nothing outside its paths: not a fast-forward onto someone else's work
/// elsewhere (refused, naming nothing there), while its own change inside
/// lands.
#[test]
fn agent_sessions_never_force_or_delete_and_a_narrowed_one_moves_a_branch_only_within_its_paths() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let atok = p.admin.token();
    let push = |tok: &str, updates: Value, force: bool| api.post_json(Some(tok), &format!("/v1/projects/{}/push", p.name), &json!({"updates": updates, "force": force}));
    let before = tip(&hub, &atok, &p.name);
    with_api_folder(&hub, &p);
    let main = tip(&hub, &atok, &p.name);
    let r = Craft::new(&api, &p.admin, &p.name, "main").push_to("release-9c1d", None);
    assert_eq!(r.status, 200, "{}", body(&r));
    let release = api.tips(Some(&atok), &p.name).unwrap().branches["release-9c1d"];
    // Unnarrowed: never forced, never deleted.
    let wide = agent_token(&hub, &atok, &p.name, &[]);
    let r = push(&wide, json!([{"branch": "main", "expected": main.hex(), "new": before.hex()}]), true);
    assert_agent_refusal(&r, NO_FORCE, "forced");
    let r = push(&wide, json!([{"branch": "release-9c1d", "expected": release.hex(), "new": null}]), false);
    assert_agent_refusal(&r, NO_DELETE, "deleted");
    // Narrowed: someone else's change of src/other.rs, kept on its change
    // ref, is not the narrowed session's to land.
    let dev = p.dev.token();
    let base = tip(&hub, &dev, &p.name);
    let theirs = change(&hub, &dev, &p.name, &json!({"base": base.hex(), "description": "elsewhere", "edits": [{"path": "src/other.rs", "put": {"text": "MARKER-ELSEWHERE-5e"}}]}));
    assert_eq!(theirs.status, 200, "{}", body(&theirs));
    let theirs = theirs.json()["snapshot"].as_str().unwrap().to_string();
    let narrow = agent_token(&hub, &dev, &p.name, &["src/api"]);
    // The same work on a branch of the dev's own: a fast-forward of main.
    let mut c = Craft::new(&api, &p.dev, &p.name, "main");
    c.file("src/other.rs", "MARKER-ELSEWHERE-5e");
    let r = c.push_to("elsewhere-7f", None);
    assert_eq!(r.status, 200, "{}", body(&r));
    assert!(r.json()["results"][0]["ok"].as_bool().unwrap(), "{}", body(&r));
    let elsewhere = api.tips(Some(&dev), &p.name).unwrap().branches["elsewhere-7f"];
    let r = push(&narrow, json!([{"branch": "main", "expected": base.hex(), "new": elsewhere.hex()}]), false);
    assert_eq!(r.status, 200, "{}", body(&r));
    assert_eq!(r.json()["results"][0]["ok"], false, "a narrowed session landed a change outside its paths: {}", body(&r));
    assert!(!body(&r).contains("other.rs") && !body(&r).contains("src/"), "the refusal names a path: {}", body(&r));
    assert_eq!(tip(&hub, &dev, &p.name), base, "main moved");
    // Through the API, `onto` a stack holding the same change: rejected too.
    let r = change(&hub, &narrow, &p.name, &json!({"base": theirs, "description": "on theirs", "edits": [{"path": "src/api/n.rs", "put": {"text": "n"}}],
                                                   "onto": {"branch": "main", "expected": base.hex()}}));
    assert_eq!(r.status, 200, "{}", body(&r));
    assert_eq!(r.json()["branch"]["status"], "rejected", "{}", body(&r));
    assert_eq!(r.json()["branch"]["message"], "this agent session is narrowed: this would change files outside its paths", "{}", body(&r));
    // Its own change inside lands.
    let r = change(&hub, &narrow, &p.name, &json!({"base": base.hex(), "description": "inside", "edits": [{"path": "src/api/m.rs", "put": {"text": "m"}}],
                                                   "onto": {"branch": "main", "expected": base.hex()}}));
    assert_eq!(r.status, 200, "{}", body(&r));
    assert_eq!(r.json()["branch"]["status"], "ok", "{}", body(&r));
}

// ---- S11 review, cycle 2 ---------------------------------------------------------

/// Property 1, by a branch move: an agent session never lands someone
/// else's change of a file that decides access or review
/// (`hub::agent::ACCESS_FILES`: "… or a branch move that lands one"). The
/// admin parks a change of `.veilpolicy` (a tier line: no access line
/// changes) and of `.veilrules` on a side branch; the admin's agent session
/// moves `main` onto it, by a fast-forward push and by an API commit on it.
#[test]
fn an_agent_session_never_lands_someone_elses_change_of_an_access_file_by_moving_a_branch() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let atok = p.admin.token();
    let tip0 = tip(&hub, &atok, &p.name);
    let policy = std::fs::read_to_string(p.dir.join(".veilpolicy")).unwrap();
    let mut own = Craft::new(&api, &p.admin, &p.name, "main");
    own.file(".veilpolicy", &format!("{policy}src/api/generated/  ignore\n"));
    own.file(".veilrules", "[review]\nmain = 2\n");
    let r = own.push_to("policy-draft-3e", None);
    assert_eq!(r.status, 200, "{}", body(&r));
    assert!(r.json()["results"][0]["ok"].as_bool().unwrap(), "{}", body(&r));
    let side = api.tips(Some(&atok), &p.name).unwrap().branches["policy-draft-3e"];
    let agent = agent_token(&hub, &atok, &p.name, &[]);
    // A fast-forward push of main onto it.
    let r = api.post_json(Some(&agent), &format!("/v1/projects/{}/push", p.name), &json!({"updates": [{"branch": "main", "expected": tip0.hex(), "new": side.hex()}]}));
    assert_agent_refusal(&r, ACCESS_MOVE, "a fast-forward onto the admin's draft");
    assert_eq!(tip(&hub, &atok, &p.name), tip0, "main moved onto the draft");
    // An API commit of its own on the draft, onto main.
    let r = change(&hub, &agent, &p.name, &json!({"base": side.hex(), "description": "on the draft", "edits": [{"path": "src/api/x.rs", "put": {"text": "x"}}],
                                                  "onto": {"branch": "main", "expected": tip0.hex()}}));
    assert_eq!(r.status, 200, "{}", body(&r));
    assert_eq!((r.json()["branch"]["status"].clone(), r.json()["branch"]["message"].clone()), (json!("rejected"), json!("not a fast-forward: the change is not on the branch's tip, or on your own unlanded changes on it")), "an API commit on the draft (not its own change: refused before the access files are looked at): {}", body(&r));
    assert_eq!(tip(&hub, &atok, &p.name), tip0, "main moved onto the draft");
}

/// Property 2, refusals: a narrowed session is told nothing of what lies
/// outside its paths. It sees the folders on the way to `src/api` (so the
/// entry `src/util`) but never what `src/util` holds; a push that replaces
/// `src/util` by an empty folder is refused, and the refusal must not name
/// the files there.
#[test]
fn a_narrowed_agent_sessions_refused_push_names_nothing_outside_its_paths() {
    const NAME: &str = "MARKER-UNLISTED-NAME-6b";
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let dev = p.dev.token();
    let base = tip(&hub, &dev, &p.name);
    let r = change(&hub, &dev, &p.name, &json!({"base": base.hex(), "description": "util", "onto": {"branch": "main", "expected": base.hex()},
                                                "edits": [{"path": format!("src/util/{NAME}.rs"), "put": {"text": "u"}}]}));
    assert_eq!(r.status, 200, "{}", body(&r));
    assert_eq!(r.json()["branch"]["status"], "ok", "{}", body(&r));
    let narrow = agent_token(&hub, &dev, &p.name, &["src/api"]);
    // Control: the narrowed session cannot list src/util.
    let listed = q(&hub, Some(&narrow), &p.name, "tree", "path=src/util");
    assert!(!body(&listed).contains(NAME), "control: the narrowed session lists src/util: {}", body(&listed));
    let mut c = Craft::with(&api, narrow.clone(), p.dev.identity(), &p.name, "main");
    let t = c.tip;
    let empty = c.put_object(O::Tree(veil_core::object::Tree::default()));
    c.refer_dir("src/util", empty);
    let r = c.push_to("main", Some(t));
    assert_agent_refusal(&r, NARROWED, "the push");
    assert!(!body(&r).contains(NAME), "the refusal names a file outside the session's paths: {}", body(&r));
}

/// Property 3, the other way round: a new server never takes a person's
/// token as an agent session's, nor an agent session's as a person's,
/// whatever is done to its form; and no stored hash of an agent session is
/// the previous release's hash of its token (or of its token without the
/// prefix).
#[test]
fn a_token_is_only_ever_the_kind_of_session_it_was_made_as() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let token = p.dev.token();
    let agent = agent_token(&hub, &token, &p.name, &["src/api"]);
    let tips = |t: &str| api.get(Some(t), &format!("/v1/projects/{}/tips", p.name)).status;
    assert_eq!(tips(&token), 200, "control: the person's session");
    assert_eq!(tips(&agent), 200, "control: the agent session");
    let bare = agent.strip_prefix(veil_server::auth::AGENT_TOKEN_PREFIX).expect("an agent token starts with agent-");
    assert_eq!(tips(bare), 401, "an agent token without its prefix");
    assert_eq!(tips(&format!("{}{token}", veil_server::auth::AGENT_TOKEN_PREFIX)), 401, "a person's token with the agent prefix");
    // A person's session cannot make an agent session from an agent token.
    let r = session(&hub, Some(&agent), &json!({"project": p.name, "attribution": {"agent": "x"}}));
    assert_agent_refusal(&r, PERSON_ONLY, "an agent session made another");
    // Every stored hash: none is the plain BLAKE3 of the token or of its bare part.
    let rows: Vec<(String, Option<String>)> = hub
        .rt
        .block_on(sqlx::query_as("SELECT token_hash, parent_hash FROM sessions WHERE agent IS NOT NULL").fetch_all(&hub.hub().db))
        .unwrap();
    assert!(!rows.is_empty(), "the agent session is stored");
    for (h, _) in &rows {
        for t in [agent.as_str(), bare] {
            assert_ne!(*h, veil_server::auth::token_hash(t), "an agent session kept under the previous release's hash");
        }
    }
}

/// Property 5, the other routes: an older `vl` (no `veil-format`) is never
/// sent a format-10 snapshot by `fetch` (it serves trees and files of a
/// snapshot, never a snapshot) nor by the object routes, and its history
/// request is refused before any frame.
#[test]
fn an_older_vl_gets_no_format_10_snapshot_by_any_route() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let token = p.dev.token();
    let agent = agent_token(&hub, &token, &p.name, &[]);
    let base = tip(&hub, &agent, &p.name);
    let r = change(&hub, &agent, &p.name, &json!({"base": base.hex(), "description": "by an agent", "edits": [{"path": "src/a.rs", "put": {"text": "a"}}],
                                                  "onto": {"branch": "main", "expected": base.hex()}}));
    assert_eq!(r.status, 200, "{}", body(&r));
    assert_eq!(r.json()["branch"]["status"], "ok", "{}", body(&r));
    let t = tip(&hub, &token, &p.name);
    let api = hub.api();
    // History: refused, with no frame.
    let h = api.post_json(Some(&token), &format!("/v1/projects/{}/history", p.name), &json!({"tips": [t.hex()]}));
    assert_eq!(h.status, 426, "{}", body(&h));
    assert!(body(&h).contains("update_vl"), "{}", body(&h));
    // Fetch, asking for the snapshot itself at the root: not served.
    let f = api.post_json(Some(&token), &format!("/v1/projects/{}/fetch", p.name), &json!({"snapshot": t.hex(), "objects": [{"path": "", "id": t.hex()}]}));
    assert_ne!(f.status, 200, "fetch served the snapshot: {}", f.status);
    // Control: what fetch serves at the root is a tree.
    let O::Snapshot(s) = O::decode(&api.history(&token, &p.name, &[t]).frames().into_iter().find(|(id, _)| *id == t).unwrap().1).unwrap() else { panic!() };
    assert!(s.agent.is_some(), "control: the tip is attributed");
    let f = api.post_json(Some(&token), &format!("/v1/projects/{}/fetch", p.name), &json!({"snapshot": t.hex(), "objects": [{"path": "", "id": s.tree.hex()}]}));
    assert_eq!(f.status, 200, "{}", body(&f));
    for (_, raw) in f.frames() {
        assert!(matches!(O::decode(&raw), Ok(O::Tree(_))), "fetch sent something other than the tree");
    }
}

/// BUG-1392's class through the API: a narrowed session's edits outside its
/// paths get one refusal, naming nothing, whether the path holds a file or
/// nothing at all, and whatever the edit is.
#[test]
fn a_narrowed_sessions_api_edits_outside_its_paths_get_one_answer_naming_nothing() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    with_api_folder(&hub, &p);
    let narrow = agent_token(&hub, &p.dev.token(), &p.name, &["src/api"]);
    let base = tip(&hub, &narrow, &p.name);
    let mut answers = Vec::new();
    for edit in [
        json!({"path": "src/other.rs", "delete": true}),
        json!({"path": "src/no-such-file-4d.rs", "delete": true}),
        json!({"path": "src/other.rs", "put": {"text": "x"}}),
        json!({"path": "src/no-such-dir-4d/x.rs", "put": {"text": "x"}}),
    ] {
        let r = change(&hub, &narrow, &p.name, &json!({"base": base.hex(), "description": "x", "edits": [edit.clone()]}));
        assert_agent_refusal(&r, NARROWED, &edit.to_string());
        assert!(!body(&r).contains("src/"), "{edit}: the refusal names a path: {}", body(&r));
        answers.push(body(&r));
    }
    assert!(answers.windows(2).all(|w| w[0] == w[1]), "the answers differ: {answers:?}");
}

/// BUG-1480: the log's `path` is a file route too. A narrowed session
/// cannot list `src/other.rs`'s folder contents beyond the way, nor read
/// it; a path-limited log must not tell it which changes touched a path
/// outside its paths, nor whether such a path ever existed.
#[test]
fn a_narrowed_sessions_path_limited_log_tells_nothing_of_paths_outside() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    with_api_folder(&hub, &p);
    let token = p.dev.token();
    let narrow = agent_token(&hub, &token, &p.name, &["src/api"]);
    // Control: inside its paths the log works, and the person's log of the
    // outside path holds the change that made it.
    let inside = q(&hub, Some(&narrow), &p.name, "log", "path=src/api");
    assert_eq!(inside.status, 200, "{}", body(&inside));
    assert!(!inside.json()["entries"].as_array().unwrap().is_empty(), "{}", body(&inside));
    let person = q(&hub, Some(&token), &p.name, "log", "path=src/other.rs");
    assert_eq!(person.status, 200, "{}", body(&person));
    assert!(body(&person).contains("api folder"), "control: {}", body(&person));
    // Outside: refused like every other file route, the same for a path
    // that exists and one that never did.
    let mut answers = Vec::new();
    for path in ["src/other.rs", "src/no-such-file-5e.rs"] {
        let r = q(&hub, Some(&narrow), &p.name, "log", &format!("path={path}"));
        assert_agent_refusal(&r, NARROWED_READ, path);
        assert!(!body(&r).contains("api folder"), "{path}: {}", body(&r));
        answers.push(body(&r));
    }
    assert_eq!(answers[0], answers[1]);
}

/// BUG-1481 (a): a narrowed session's refused branch move says nothing of
/// what changed outside its paths. Two drafts of the admin's change only
/// `ops/` (a folder not on the way to `src/api`): one a script, one
/// `ops/.veilrules`. Moving `main` onto either changes files outside the
/// session's paths; the answers must be the same.
#[test]
fn a_narrowed_sessions_refused_move_says_nothing_of_which_files_outside_changed() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let atok = p.admin.token();
    let tip0 = tip(&hub, &atok, &p.name);
    let mut a = Craft::new(&api, &p.admin, &p.name, "main");
    a.file("ops/run.sh", "echo run");
    let r = a.push_to("ops-draft-a7", None);
    assert_eq!(r.status, 200, "{}", body(&r));
    assert!(r.json()["results"][0]["ok"].as_bool().unwrap(), "{}", body(&r));
    let mut b = Craft::new(&api, &p.admin, &p.name, "main");
    b.file("ops/.veilrules", "main  2 approvals\n");
    let r = b.push_to("ops-draft-b7", None);
    assert_eq!(r.status, 200, "{}", body(&r));
    assert!(r.json()["results"][0]["ok"].as_bool().unwrap(), "{}", body(&r));
    let tips = api.tips(Some(&atok), &p.name).unwrap().branches;
    let narrow = agent_token(&hub, &atok, &p.name, &["src/api"]);
    let answer = |r: &Reply| -> (u16, String) {
        match r.status {
            200 => (200, r.json()["results"][0]["message"].as_str().unwrap_or("").to_string()),
            s => (s, r.json()["message"].as_str().unwrap_or("").to_string()),
        }
    };
    let mut answers = Vec::new();
    for draft in ["ops-draft-a7", "ops-draft-b7"] {
        let r = api.post_json(Some(&narrow), &format!("/v1/projects/{}/push", p.name), &json!({"updates": [{"branch": "main", "expected": tip0.hex(), "new": tips[draft].hex()}]}));
        assert_move_refused(&r, NARROWED, draft);
        answers.push(answer(&r));
    }
    assert_eq!(tip(&hub, &atok, &p.name), tip0, "main moved");
    assert_eq!(answers[0], answers[1], "the refusals tell an access file's change outside the paths from another change there");
}

/// BUG-1481 (b): the object-closure check of a push answers before the
/// narrowing refusal. A narrowed session pushes a merge of `main` with an
/// older snapshot, naming at a path outside its paths a blob it did not
/// upload: the id of a guess of what that path held in the older parent.
/// A right guess and a wrong one must get the same answer.
#[test]
fn a_narrowed_sessions_push_cannot_confirm_what_a_file_outside_its_paths_held() {
    const PATH: &str = "src/util/MARKER-GUESS-PATH-8c.rs";
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let dev = p.dev.token();
    // `old` holds the path at "guessable-v1"; `main` then moves it to v2.
    let mut tips = Vec::new();
    for text in ["guessable-v1", "guessable-v2"] {
        let base = tip(&hub, &dev, &p.name);
        let r = change(&hub, &dev, &p.name, &json!({"base": base.hex(), "description": format!("util {text}"), "onto": {"branch": "main", "expected": base.hex()},
                                                    "edits": [{"path": PATH, "put": {"text": text}}]}));
        assert_eq!(r.status, 200, "{}", body(&r));
        assert_eq!(r.json()["branch"]["status"], "ok", "{}", body(&r));
        tips.push(tip(&hub, &dev, &p.name));
    }
    let (old, base) = (tips[0], tips[1]);
    let narrow = agent_token(&hub, &dev, &p.name, &["src/api"]);
    // Control: the narrowed session cannot read the path, nor list its folder.
    assert_eq!(q(&hub, Some(&narrow), &p.name, "file", &format!("path={PATH}")).status, 403);
    assert_eq!(q(&hub, Some(&narrow), &p.name, "tree", "path=src/util").status, 403);
    let blob = |t: &str| ObjectId::hash(&O::Blob(t.as_bytes().to_vec()).encode());
    let (old_seen, tip_seen) = (old, tip(&hub, &narrow, &p.name));
    assert_ne!(old_seen, tip_seen);
    let mut answers = Vec::new();
    for guess in ["guessable-v1", "a-wrong-guess"] {
        let mut c = Craft::with(&api, narrow.clone(), p.dev.identity(), &p.name, "main");
        // `src/util` holds only that file: its tree is built here (the
        // session may not fetch it), naming the guess without uploading it.
        let (dir, name) = PATH.rsplit_once('/').unwrap();
        let mut t = veil_core::object::Tree::default();
        t.insert(veil_core::object::TreeEntry {
            name: name.into(),
            kind: veil_core::object::EntryKind::File,
            id: blob(guess),
            size: guess.len() as u64,
            executable: false,
            visibility: veil_core::object::Visibility::Public,
        });
        let t = c.put_object(O::Tree(t));
        c.refer_dir(dir, t);
        let r = c.push_merge("main", &[old_seen]);
        assert_agent_refusal(&r, NARROWED, guess);
        answers.push((r.status, body(&r)));
    }
    assert_eq!(tip(&hub, &dev, &p.name), base, "main moved");
    assert_eq!(answers[0], answers[1], "a right guess and a wrong one get different answers");
}

/// BUG-1482: "a new branch removes nothing" does not hold for the default
/// branch, whose `.veilpolicy` decides what every member's `vl` seals,
/// ignores and scans, and whose `.veilrules` the review rules. With no
/// `main` (an admin deleted it), the admin's agent session creates `main`
/// at the admin's draft of both files: it must be refused, as the same move
/// from an existing tip is (BUG-1391).
#[test]
fn an_agent_session_never_creates_the_default_branch_at_a_change_of_an_access_file() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let atok = p.admin.token();
    let tip0 = tip(&hub, &atok, &p.name);
    let policy = std::fs::read_to_string(p.dir.join(".veilpolicy")).unwrap();
    let mut own = Craft::new(&api, &p.admin, &p.name, "main");
    own.file(".veilpolicy", &format!("{policy}src/api/generated/  ignore\n"));
    own.file(".veilrules", "[review]\nmain = 2\n");
    let r = own.push_to("policy-draft-9f", None);
    assert_eq!(r.status, 200, "{}", body(&r));
    assert!(r.json()["results"][0]["ok"].as_bool().unwrap(), "{}", body(&r));
    let draft = api.tips(Some(&atok), &p.name).unwrap().branches["policy-draft-9f"];
    // The admin deletes main (their own session).
    let r = api.post_json(Some(&atok), &format!("/v1/projects/{}/push", p.name), &json!({"updates": [{"branch": "main", "expected": tip0.hex(), "new": null}]}));
    assert_eq!(r.status, 200, "{}", body(&r));
    assert!(r.json()["results"][0]["ok"].as_bool().unwrap(), "the admin deletes main: {}", body(&r));
    assert!(!api.tips(Some(&atok), &p.name).unwrap().branches.contains_key("main"), "main is gone");
    // Control: the agent may create another branch there (a new branch
    // that is not the default one decides nothing).
    let agent = agent_token(&hub, &atok, &p.name, &[]);
    let r = api.post_json(Some(&agent), &format!("/v1/projects/{}/push", p.name), &json!({"updates": [{"branch": "agent-copy-9f", "expected": null, "new": draft.hex()}]}));
    assert_eq!(r.status, 200, "{}", body(&r));
    assert!(r.json()["results"][0]["ok"].as_bool().unwrap(), "control: {}", body(&r));
    // The default branch: refused.
    let r = api.post_json(Some(&agent), &format!("/v1/projects/{}/push", p.name), &json!({"updates": [{"branch": "main", "expected": null, "new": draft.hex()}]}));
    assert_agent_refusal(&r, DEFAULT_BRANCH_REFUSAL, "the agent created main at the admin's draft");
    assert!(!api.tips(Some(&atok), &p.name).unwrap().branches.contains_key("main"), "main was created");
}

/// Property 3 on the server's rebuilds: an agent session's API commit
/// rebased by the server onto a moved `main` lands with the session's
/// attribution, inside the server's signature.
#[test]
fn an_agent_sessions_rebased_landing_keeps_its_attribution() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let token = p.dev.token();
    let agent = agent_token(&hub, &token, &p.name, &[]);
    let base = tip(&hub, &agent, &p.name);
    // main moves under the agent.
    let r = change(&hub, &token, &p.name, &json!({"base": base.hex(), "description": "the person's", "edits": [{"path": "src/p.rs", "put": {"text": "p"}}],
                                                  "onto": {"branch": "main", "expected": base.hex()}}));
    assert_eq!(r.status, 200, "{}", body(&r));
    assert_eq!(r.json()["branch"]["status"], "ok", "{}", body(&r));
    let r = change(&hub, &agent, &p.name, &json!({"base": base.hex(), "description": "the agent's", "edits": [{"path": "src/a.rs", "put": {"text": "a"}}],
                                                  "onto": {"branch": "main", "expected": "rebase"}}));
    assert_eq!(r.status, 200, "{}", body(&r));
    assert_eq!(r.json()["branch"]["status"], "ok", "{}", body(&r));
    assert_eq!(r.json()["branch"]["rebased"], 1, "{}", body(&r));
    let t = tip(&hub, &token, &p.name);
    let frames = hub.api().history(&token, &p.name, &[t]).frames();
    let O::Snapshot(s) = O::decode(&frames.into_iter().find(|(id, _)| *id == t).unwrap().1).unwrap() else { panic!() };
    assert_eq!(s.agent.as_ref().map(|a| a.agent.as_str()), Some("claude-code/2.3"), "{s:?}");
    assert_eq!(s.agent.as_ref().and_then(|a| a.task.as_deref()), Some("TASK-S11-1"));
    assert_eq!(s.signature_valid(), Some(true));
}

// ---- S11 cycle 4: one rule per class ----------------------------------------------

/// BUG-1480's class: every query route that takes a path takes it through
/// `Ask::file_path`, so for a narrowed session a path outside its paths gets
/// one answer, the same whether it exists or not, on every route.
#[test]
fn every_query_route_that_takes_a_path_refuses_one_outside_the_narrowing_the_same_way() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    with_api_folder(&hub, &p);
    let narrow = agent_token(&hub, &p.dev.token(), &p.name, &["src/api"]);
    let routes: [(&str, &str); 8] = [
        ("log", "path={}"),
        ("show", "path={}"),
        ("tree", "path={}"),
        ("file", "path={}"),
        ("diff", "from=main&base=from&path={}"),
        ("search", "q=fn&path={}"),
        ("search", "q=fn&kind=path&path={}"),
        ("grep", "pattern=fn&path={}"),
    ];
    for (route, params) in routes {
        let mut answers = Vec::new();
        for path in ["src/other.rs", "src/no-such-path-6f.rs", "src"] {
            let r = q(&hub, Some(&narrow), &p.name, route, &params.replace("{}", path));
            assert_agent_refusal(&r, NARROWED_READ, &format!("{route}?{params} {path}"));
            assert!(!body(&r).contains("src/") && !body(&r).contains("api folder"), "{route} {path}: {}", body(&r));
            answers.push(body(&r));
        }
        assert!(answers.windows(2).all(|w| w[0] == w[1]), "{route}: the answers differ: {answers:?}");
    }
    // Control: inside its paths, and the whole history (no path) for the log.
    for (route, params) in [("log", "path=src/api"), ("log", ""), ("file", "path=src/api/h.rs"), ("tree", "path=src/api")] {
        let r = q(&hub, Some(&narrow), &p.name, route, params);
        assert_eq!(r.status, 200, "{route}?{params}: {}", body(&r));
    }
}

/// BUG-1481's class: every write route of a narrowed session decides
/// "anything outside its paths?" first, and answers one way naming
/// nothing, whatever the outside change is: an ordinary file, a file that
/// decides access, an object it never uploaded, a deletion.
#[test]
fn every_write_route_of_a_narrowed_session_answers_one_way_for_any_change_outside() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    with_api_folder(&hub, &p);
    let api = hub.api();
    let (dev, atok) = (p.dev.token(), p.admin.token());
    let narrow = agent_token(&hub, &atok, &p.name, &["src/api"]);
    let never_uploaded = ObjectId::hash(&O::Blob(b"MARKER-NEVER-UPLOADED-7a".to_vec()).encode());
    // 1. A pushed snapshot.
    let mut pushes = Vec::new();
    for kind in ["file", "access", "missing", "delete"] {
        let mut c = Craft::with(&api, narrow.clone(), p.admin.identity(), &p.name, "main");
        let t = c.tip;
        match kind {
            "file" => c.file("src/other.rs", "changed"),
            "access" => c.file("ops/.veilrules", "main  2 approvals\n"),
            "missing" => c.refer("src/never.rs", never_uploaded, 24),
            _ => {
                let empty = c.put_object(O::Tree(veil_core::object::Tree::default()));
                c.refer_dir("src/util-gone", empty);
                c.file("src/other.rs", "");
            }
        }
        let r = c.push_to("main", Some(t));
        assert_agent_refusal(&r, NARROWED, kind);
        pushes.push(body(&r));
    }
    assert!(pushes.windows(2).all(|w| w[0] == w[1]), "pushes: {pushes:?}");
    assert!(!pushes[0].contains("src/") && !pushes[0].contains(".veilrules"), "{}", pushes[0]);
    // 2. A branch move onto an existing snapshot (the admin's drafts).
    let tip0 = tip(&hub, &atok, &p.name);
    let mut moves = Vec::new();
    for (i, kind) in ["file", "access"].iter().enumerate() {
        let mut d = Craft::new(&api, &p.admin, &p.name, "main");
        match *kind {
            "file" => d.file("src/other.rs", "the admin's"),
            _ => d.file("ops/.veilrules", "main  2 approvals\n"),
        }
        let branch = format!("draft-{i}-c4");
        let r = d.push_to(&branch, None);
        assert_eq!(r.status, 200, "{}", body(&r));
        let to = api.tips(Some(&atok), &p.name).unwrap().branches[&branch];
        let r = api.post_json(Some(&narrow), &format!("/v1/projects/{}/push", p.name), &json!({"updates": [{"branch": "main", "expected": tip0.hex(), "new": to.hex()}]}));
        assert_eq!(r.status, 200, "move {kind}: {}", body(&r));
        assert_eq!(r.json()["results"][0]["ok"], false, "move {kind}: {}", body(&r));
        moves.push(r.json()["results"][0]["message"].clone());
    }
    assert_eq!(moves[0], moves[1], "moves: {moves:?}");
    // 3. API commits.
    let base = tip(&hub, &narrow, &p.name);
    let mut commits = Vec::new();
    for edit in [
        json!({"path": "src/other.rs", "put": {"text": "x"}}),
        json!({"path": "ops/.veilrules", "put": {"text": "main  2 approvals\n"}}),
        json!({"path": "src/never.rs", "put": {"object": never_uploaded.hex()}}),
        json!({"path": "src/other.rs", "delete": true}),
    ] {
        let r = change(&hub, &narrow, &p.name, &json!({"base": base.hex(), "description": "x", "edits": [edit.clone()]}));
        assert_agent_refusal(&r, NARROWED, &edit.to_string());
        commits.push(body(&r));
    }
    assert!(commits.windows(2).all(|w| w[0] == w[1]), "commits: {commits:?}");
    // 4. `onto` a stack of its person's own changes holding an outside change.
    let mut stacks = Vec::new();
    for edit in [json!({"path": "src/other.rs", "put": {"text": "s"}}), json!({"path": "ops/.veilrules", "put": {"text": "main  1 approval\n"}})] {
        let own = change(&hub, &atok, &p.name, &json!({"base": base.hex(), "description": "own", "edits": [edit]}));
        assert_eq!(own.status, 200, "{}", body(&own));
        let on = own.json()["snapshot"].as_str().unwrap().to_string();
        let r = change(&hub, &narrow, &p.name, &json!({"base": on, "description": "on it", "edits": [{"path": "src/api/s.rs", "put": {"text": "s"}}],
                                                       "onto": {"branch": "main", "expected": base.hex()}}));
        assert_eq!(r.status, 200, "{}", body(&r));
        assert_eq!(r.json()["branch"]["status"], "rejected", "{}", body(&r));
        stacks.push(r.json()["branch"]["message"].clone());
    }
    assert_eq!(stacks[0], stacks[1], "stacks: {stacks:?}");
    assert_eq!(moves[0], stacks[0], "a move and a stack are told differently");
    let _ = dev;
}

/// BUG-1538, decided, on a project made through the API with no `main`
/// yet: an agent session never creates the default branch, whatever it
/// holds; its person does (the control, last).
#[test]
fn an_agent_session_never_creates_a_new_projects_default_branch() {
    let hub = TestHub::start();
    let admin = hub.person("admin");
    let name = unique("fresh");
    let api = hub.api();
    let atok = admin.token();
    let r = api.post(Some(&atok), &format!("/v1/projects/{name}"), b"", false);
    assert_eq!(r.status, 200, "{}", body(&r));
    assert!(!api.tips(Some(&atok), &name).unwrap().branches.contains_key("main"), "control: no main yet");
    let agent = agent_token(&hub, &atok, &name, &[]);
    let identity = admin.identity();
    // A first snapshot holding `files`, on the universal root.
    let first = |files: &[(&str, &str)]| -> (ObjectId, Vec<(ObjectId, Vec<u8>)>) {
        let mut objects = Vec::new();
        let mut t = veil_core::object::Tree::default();
        for (name, text) in files {
            let raw = O::Blob(text.as_bytes().to_vec()).encode();
            let id = ObjectId::hash(&raw);
            objects.push((id, raw));
            t.insert(veil_core::object::TreeEntry {
                name: name.to_string(),
                kind: veil_core::object::EntryKind::File,
                id,
                size: text.len() as u64,
                executable: false,
                visibility: veil_core::object::Visibility::Public,
            });
        }
        let raw = O::Tree(t).encode_with(veil_core::object::TreeEncoding::Binary);
        let tree = ObjectId::hash(&raw);
        objects.push((tree, raw));
        let mut s = Snapshot {
            parents: vec![veil_server::sync::root_snapshot_id()],
            change_id: veil_core::ChangeId::random(),
            tree,
            description: Text::Plain("first".into()),
            author: "admin".into(),
            timestamp: veil_core::now_millis(),
            predecessors: vec![],
            conflicts: vec![],
            embargo: None,
            agent: None,
            abandoned: None,
            attempts: vec![],
            signature: None,
        };
        s.sign(&identity);
        let raw = O::Snapshot(s).encode();
        let id = ObjectId::hash(&raw);
        objects.push((id, raw));
        (id, objects)
    };
    let push_main = |token: &str, files: &[(&str, &str)]| -> Reply {
        let (id, objects) = first(files);
        let up = api.upload(token, &name, &objects);
        assert_eq!(up.status, 200, "{}", body(&up));
        let receipts = up.json()["receipts"].as_array().unwrap().clone();
        let map: serde_json::Map<String, Value> = objects.iter().zip(receipts).map(|((id, _), r)| (id.hex(), r)).collect();
        api.post_json(Some(token), &format!("/v1/projects/{name}/push"), &json!({"updates": [{"branch": "main", "expected": null, "new": id.hex()}], "receipts": map}))
    };
    for files in [vec![(".veilrules", "main  2 approvals\n"), ("README", "r")], vec![(".veilpolicy", "src/  public\n"), ("README", "r")], vec![("README", "r")]] {
        let r = push_main(&agent, &files);
        assert_eq!((r.status, r.json()["code"].clone(), r.json()["message"].clone()), (403, json!("agent_session"), json!(DEFAULT_BRANCH_REFUSAL)), "{files:?}: {}", body(&r));
        assert!(!api.tips(Some(&atok), &name).unwrap().branches.contains_key("main"), "{files:?}: main was created");
    }
    let r = push_main(&atok, &[("README", "r")]);
    assert_eq!(r.status, 200, "{}", body(&r));
    assert!(r.json()["results"][0]["ok"].as_bool().unwrap(), "control: the person creates main: {}", body(&r));
}

// ---- S11 review, cycle 1 of the redesign (BUG-1536..1539) ----------------------------

/// Rule 1 for search: a narrowed session's ranked results inside its paths
/// are a function of what lies inside them alone. A file added outside its
/// paths (one its person may read) leaves them as they were.
#[test]
fn a_narrowed_sessions_search_results_do_not_depend_on_files_outside_its_paths() {
    use std::time::{Duration, Instant};
    let hub = TestHub::start();
    let p = setup_project(&hub);
    with_api_folder(&hub, &p);
    let token = p.dev.token();
    let narrow = agent_token(&hub, &token, &p.name, &["src/api"]);
    // The narrowed search, once the index covers the tip it is asked at.
    let settled = |old_tip: Option<&str>| -> Value {
        let end = Instant::now() + Duration::from_secs(120);
        loop {
            let r = q(&hub, Some(&narrow), &p.name, "search", "q=marker-inside-1c&path=src/api");
            if r.status == 200 && r.json()["behind"] == false && old_tip.is_none_or(|t| r.json()["tip_id"] != t) && r.json()["files"] == 1 {
                return r.json();
            }
            assert!(Instant::now() < end, "never indexed: {} {}", r.status, body(&r));
            std::thread::sleep(Duration::from_millis(200));
        }
    };
    let before = settled(None);
    assert_eq!(before["results"][0]["path"], "src/api/h.rs", "{before}");
    // The person adds files outside the session's paths.
    let base = tip(&hub, &token, &p.name);
    let r = change(
        &hub,
        &token,
        &p.name,
        &json!({"base": base.hex(), "description": "outside", "onto": {"branch": "main", "expected": base.hex()},
                "edits": [{"path": "src/other-a.rs", "put": {"text": "marker-inside-1c marker-inside-1c\n".repeat(50)}},
                          {"path": "src/other-b.rs", "put": {"text": "marker-inside-1c\n"}}]}),
    );
    assert_eq!(r.status, 200, "{}", body(&r));
    assert_eq!(r.json()["branch"]["status"], "ok", "{}", body(&r));
    let after = settled(before["tip_id"].as_str());
    assert_eq!(before["results"], after["results"], "the results inside the narrowing changed with files outside it");
}

/// Rule 1 for every route that takes a path, not only `q/`: the access
/// route's `path` outside a narrowed session's paths gets the one refusal
/// the query routes give, whether the person may read it, and whether it
/// exists.
#[test]
fn a_narrowed_sessions_access_route_answers_one_way_outside_its_paths() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    with_api_folder(&hub, &p);
    let narrow = agent_token(&hub, &p.dev.token(), &p.name, &["src/api"]);
    let api = hub.api();
    // Control: inside its paths, the person's answer.
    let r = api.get(Some(&narrow), &format!("/v1/projects/{}/access?path=src/api/h.rs", p.name));
    assert_eq!(r.status, 200, "{}", body(&r));
    // The query routes' refusal of a path outside.
    let refusal = q(&hub, Some(&narrow), &p.name, "file", "path=src/other.rs");
    assert_agent_refusal(&refusal, NARROWED_READ, "q/file");
    for path in ["src/other.rs", "src/no-such-path-6f.rs", BILL_DIR, &format!("src/{NESTED_DIR}")] {
        let r = api.get(Some(&narrow), &format!("/v1/projects/{}/access?path={path}", p.name));
        assert_eq!((r.status, body(&r)), (refusal.status, body(&refusal)), "access?path={path}");
    }
}

/// BUG-1690: blame and file history (S14) took their path without the
/// narrowing, and followed renames out of it. A narrowed session gets the
/// query routes' one refusal for a path outside its paths, and a file
/// renamed into its paths never names the path it came from, though its
/// person's own session does.
#[test]
fn a_narrowed_sessions_blame_and_history_stay_inside_its_paths() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    with_api_folder(&hub, &p);
    let token = p.dev.token();
    let base = tip(&hub, &token, &p.name);
    let r = change(
        &hub,
        &token,
        &p.name,
        &json!({"base": base.hex(), "description": "move it in", "onto": {"branch": "main", "expected": base.hex()},
                "edits": [{"path": "src/other.rs", "delete": true},
                          {"path": "src/api/moved.rs", "put": {"text": "fn o() {} // MARKER-OUTSIDE-2d"}}]}),
    );
    assert_eq!(r.status, 200, "{}", body(&r));
    assert_eq!(r.json()["branch"]["status"], "ok", "{}", body(&r));
    let narrow = agent_token(&hub, &token, &p.name, &["src/api"]);
    // Outside its paths: the one refusal, for blame and history alike.
    let refusal = q(&hub, Some(&narrow), &p.name, "file", "path=src/other.rs");
    assert_agent_refusal(&refusal, NARROWED_READ, "q/file");
    for route in ["blame", "history"] {
        for path in ["src/other.rs", "src/no-such-path-6f.rs", BILL_DIR] {
            let r = q(&hub, Some(&narrow), &p.name, route, &format!("path={path}"));
            assert_eq!((r.status, body(&r)), (refusal.status, body(&refusal)), "{route}?path={path}");
        }
    }
    // Control: the person's own session follows the rename out of src/api.
    let full = q(&hub, Some(&token), &p.name, "history", "path=src/api/moved.rs&follow=true");
    assert_eq!(full.status, 200, "{}", body(&full));
    assert!(body(&full).contains("src/other.rs"), "the control follows the rename: {}", body(&full));
    // The narrowed session's answers never name it.
    for route in ["history", "blame"] {
        let r = q(&hub, Some(&narrow), &p.name, route, "path=src/api/moved.rs&follow=true");
        assert_eq!(r.status, 200, "{route}: {}", body(&r));
        assert!(!body(&r).contains("src/other.rs"), "{route} named the path outside: {}", body(&r));
    }
}

/// Rule 3, the accepted text: an agent session recreating a deleted default
/// branch never sets a `.veilpolicy` other than the one the branch last
/// carried. The accepted text is updated only when access lines change, so
/// it may be an older text than the branch's (a tier line added since).
#[test]
fn an_agent_session_never_recreates_the_default_branch_with_an_older_policy_text() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let atok = p.admin.token();
    let older = tip(&hub, &atok, &p.name);
    // The admin adds a tier line (no access line changes: not re-accepted).
    let policy = std::fs::read_to_string(p.dir.join(".veilpolicy")).unwrap();
    let mut own = Craft::new(&api, &p.admin, &p.name, "main");
    own.file(".veilpolicy", &format!("{policy}src/api/generated/  ignore\n"));
    let r = own.push_to("main", Some(older));
    assert_eq!(r.status, 200, "{}", body(&r));
    assert!(r.json()["results"][0]["ok"].as_bool().unwrap(), "{}", body(&r));
    let newer = tip(&hub, &atok, &p.name);
    // The admin deletes main.
    let r = api.post_json(Some(&atok), &format!("/v1/projects/{}/push", p.name), &json!({"updates": [{"branch": "main", "expected": newer.hex(), "new": null}]}));
    assert_eq!(r.status, 200, "{}", body(&r));
    assert!(r.json()["results"][0]["ok"].as_bool().unwrap(), "the admin deletes main: {}", body(&r));
    // The admin's agent session creates main at the snapshot before the
    // tier line: its `.veilpolicy` is not the one main last carried.
    let agent = agent_token(&hub, &atok, &p.name, &[]);
    let r = api.post_json(Some(&agent), &format!("/v1/projects/{}/push", p.name), &json!({"updates": [{"branch": "main", "expected": null, "new": older.hex()}]}));
    assert_agent_refusal(&r, DEFAULT_BRANCH_REFUSAL, "the agent recreated main");
    assert!(!api.tips(Some(&atok), &p.name).unwrap().branches.contains_key("main"), "main was created");
}

/// Rule 2, before the graft's own answers: a narrowed session's pushed
/// snapshot that writes outside its paths gets one answer, whether its
/// person may read the outside path or not.
#[test]
fn a_narrowed_sessions_push_outside_gets_one_answer_whatever_its_person_may_read_there() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    with_api_folder(&hub, &p);
    let api = hub.api();
    let narrow = agent_token(&hub, &p.dev.token(), &p.name, &["src/api"]);
    let mut answers = Vec::new();
    for path in ["src/other.rs".to_string(), format!("{BILL_DIR}/x.txt"), format!("src/{NESTED_DIR}/x.txt"), format!("{PERSON_DIR}/x.txt")] {
        let mut c = Craft::with(&api, narrow.clone(), p.dev.identity(), &p.name, "main");
        let t = c.tip;
        c.file(&path, "x");
        let r = c.push_to("main", Some(t));
        assert_agent_refusal(&r, NARROWED, &path);
        answers.push((path, body(&r)));
    }
    for (path, a) in &answers {
        assert_eq!(a, &answers[0].1, "{path}");
    }
}

/// Rule 3, decided (BUG-1538): an agent session never recreates the
/// default branch, whatever its `.veilpolicy` holds: a trailing byte, a
/// byte-order mark, another `.veilpolicy` in a folder, the text as a
/// symbolic link, and no change at all each get the one refusal. The
/// admin's own session recreates it (the control, last).
#[test]
fn an_agent_session_never_recreates_the_default_branch_whatever_its_policy_text() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let atok = p.admin.token();
    let tip0 = tip(&hub, &atok, &p.name);
    let policy = std::fs::read_to_string(p.dir.join(".veilpolicy")).unwrap();
    let agent = agent_token(&hub, &atok, &p.name, &[]);
    let craft = || Craft::with(&api, agent.clone(), p.admin.identity(), &p.name, "main");
    let mut variants = Vec::new();
    let mut c = craft();
    c.file(".veilpolicy", &format!("{policy}\n"));
    variants.push(("a trailing byte", c));
    let mut c = craft();
    c.file(".veilpolicy", &format!("\u{feff}{policy}"));
    variants.push(("a byte-order mark", c));
    let mut c = craft();
    c.file("src/.veilpolicy", &policy);
    variants.push(("a .veilpolicy in a folder", c));
    let mut c = craft();
    c.set_kind(".veilpolicy", O::Blob(policy.as_bytes().to_vec()), veil_core::object::EntryKind::Symlink, veil_core::object::Visibility::Public);
    variants.push(("the text as a symbolic link", c));
    let mut c = craft();
    c.file("src/recreated.rs", "fn r() {}");
    variants.push(("no change of an access file", c));
    let mut control = Craft::new(&api, &p.admin, &p.name, "main");
    control.file("src/recreated.rs", "fn r() {}");
    // The admin deletes main.
    let r = api.post_json(Some(&atok), &format!("/v1/projects/{}/push", p.name), &json!({"updates": [{"branch": "main", "expected": tip0.hex(), "new": null}]}));
    assert_eq!(r.status, 200, "{}", body(&r));
    assert!(r.json()["results"][0]["ok"].as_bool().unwrap(), "the admin deletes main: {}", body(&r));
    for (what, c) in variants {
        let r = c.push_to("main", None);
        assert_eq!((r.status, r.json()["code"].clone(), r.json()["message"].clone()), (403, json!("agent_session"), json!(DEFAULT_BRANCH_REFUSAL)), "{what}: {}", body(&r));
        assert!(!api.tips(Some(&atok), &p.name).unwrap().branches.contains_key("main"), "{what}: main was created");
    }
    let r = control.push_to("main", None);
    assert_eq!(r.status, 200, "{}", body(&r));
    assert!(r.json()["results"][0]["ok"].as_bool().unwrap(), "control: the admin's own session: {}", body(&r));
}

/// Rule 1, mechanically: every route the server answers is classified here
/// by what it does with a path or a revision, and a route added without a
/// class fails this test. Each query route that takes a path must take it
/// through `Ask::file_path` (the log through `Ask::log_path`); the routes
/// that read the tree by path (`fetch`) or write (`push`, `changes`) must
/// decide the narrowing. Routes that take a path and are not narrowed yet
/// are listed as open, with their bug (BUG-1537), so that fixing them moves
/// them to a narrowed class.
#[test]
fn every_route_that_takes_a_path_or_a_revision_is_classified_and_narrowed() {
    const API: &str = include_str!("../../src/api.rs");
    const QUERY: &str = include_str!("../../src/query/mod.rs");
    const SEARCH: &str = include_str!("../../src/search/mod.rs");
    const SYNC: &str = include_str!("../../src/sync.rs");
    const CHANGES: &str = include_str!("../../src/changes.rs");
    // (route, class): "path" a query route taking a path (its function must
    // call `file_path` or `log_path`); "rev" revisions of the person's
    // history only; "tree" serves the tree by path (narrowed in `fetch`);
    // "write" (narrowed in push and changes); "person" refused to agent
    // sessions (`person_only`); "none" takes neither; "open:BUG-NNN" takes a
    // path, not narrowed yet.
    let classes: &[(&str, &str)] = &[
        ("/v1/auth/challenge", "none"),
        ("/v1/auth/login", "none"),
        ("/v1/sessions/agent", "person"),
        ("/v1/people/{name}/devices", "none"),
        ("/v1/people/{name}/pending/{fingerprint}", "none"),
        ("/v1/devices/vouch", "person"),
        ("/v1/devices/remove", "person"),
        ("/v1/projects/{p}/invites", "person"),
        ("/v1/projects/{p}/invites/join", "person"),
        ("/v1/projects/{p}/keys/pending", "person"),
        ("/v1/projects/{p}", "person"),
        ("/v1/projects/{p}/tips", "rev"),
        ("/v1/projects/{p}/history", "rev"),
        ("/v1/projects/{p}/fetch", "tree"),
        ("/v1/projects/{p}/objects", "none"),
        ("/v1/projects/{p}/push", "write"),
        ("/v1/projects/{p}/changes", "write"),
        ("/v1/projects/{p}/land", "write"),
        ("/v1/projects/{p}/land/{ticket}", "rev"),
        ("/v1/projects/{p}/access", "narrowed"),
        ("/v1/projects/{p}/groups", "none"),
        ("/v1/projects/{p}/groups/{g}", "person"),
        ("/v1/projects/{p}/groups/{g}/members", "person"),
        ("/v1/projects/{p}/groups/{g}/members/remove", "person"),
        ("/v1/projects/{p}/groups/{g}/managers", "person"),
        ("/v1/projects/{p}/rings", "narrowed"),
        ("/v1/projects/{p}/rings/{scope}", "narrowed"),
        ("/v1/projects/{p}/shares", "narrowed"),
        ("/v1/projects/{p}/shares/remove", "person"),
        ("/v1/objects/{p}/{id}", "none"),
        ("/v1/objects/{target}", "none"),
        ("/v1/epochs", "none"),
        ("/v1/cache/epochs", "none"),
        ("/v1/projects/{p}/q/log", "path"),
        ("/v1/projects/{p}/q/show", "path"),
        ("/v1/projects/{p}/q/tree", "path"),
        ("/v1/projects/{p}/q/file", "path"),
        ("/v1/projects/{p}/q/diff", "path"),
        ("/v1/projects/{p}/q/ancestry", "rev"),
        ("/v1/projects/{p}/q/resolve", "rev"),
        ("/v1/projects/{p}/q/generations", "rev"),
        ("/v1/projects/{p}/q/blame", "path"),
        ("/v1/projects/{p}/q/history", "path"),
        ("/v1/projects/{p}/q/search", "path"),
        ("/v1/projects/{p}/q/grep", "path"),
        // S14: blame and file history take a path (BUG-1690).
        ("/v1/projects/{p}/q/blame", "path"),
        ("/v1/projects/{p}/q/history", "path"),
        // S24: counts for the project's admins, no path or revision (merge s11r6).
        ("/v1/projects/{p}/health", "none"),
        // S6: the server's public key that grants verify under, for the Veil
        // daemon; no path or revision (merge of S6).
        ("/v1/grant-key", "none"),
        // S19: CI runner sessions, check results, and `<branch>@tested`.
        ("/v1/sessions/ci", "person"),
        ("/v1/projects/{p}/checks", "rev"),
        ("/v1/projects/{p}/tested/{branch}", "rev"),
    ];
    let routes: Vec<&str> = API.split(".route(\"").skip(1).map(|s| s.split('"').next().unwrap()).collect();
    assert!(routes.len() >= 40, "the router was not read: {routes:?}");
    for r in &routes {
        assert!(classes.iter().any(|(c, _)| c == r), "route {r} is not classified: decide how it treats a narrowed session");
    }
    for (c, _) in classes {
        assert!(routes.contains(c), "{c} is classified but not routed");
    }
    // The body of `fn name` in `src`, up to the next item.
    let body_of = |src: &'static str, name: &str| -> &'static str {
        let start = src.find(&format!("pub async fn {name}(")).unwrap_or_else(|| panic!("no fn {name}"));
        let rest = &src[start + 1..];
        let end = ["\npub async fn ", "\nasync fn ", "\npub fn ", "\nfn ", "\n#[derive"].iter().filter_map(|m| rest.find(m)).min().unwrap_or(rest.len());
        &rest[..end]
    };
    for (f, src) in [("log", QUERY), ("show", QUERY), ("tree", QUERY), ("file", QUERY), ("diff", QUERY), ("blame", QUERY), ("history", QUERY), ("search", SEARCH), ("grep", SEARCH)] {
        let b = body_of(src, f);
        assert!(b.contains("ask.file_path(") || b.contains("ask.log_path("), "query route {f} takes its path without Ask::file_path");
    }
    assert!(SYNC.contains("let narrowed_dir = !view.within_narrowing(&w.path);"), "fetch serves the tree without the narrowing");
    // Every route that takes or returns a path outside `q/` is narrowed in
    // its handler (BUG-1537), and no route is left open.
    assert!(!classes.iter().any(|(_, c)| c.starts_with("open:")), "a route is still open: {classes:?}");
    let handler = |src: &'static str, name: &str| -> &'static str {
        let start = src.find(&format!("async fn {name}(")).unwrap_or_else(|| panic!("no fn {name}"));
        let rest = &src[start + 1..];
        let end = ["\npub async fn ", "\nasync fn ", "\npub fn ", "\nfn ", "\n#[derive"].iter().filter_map(|m| rest.find(m)).min().unwrap_or(rest.len());
        &rest[..end]
    };
    const SHARES: &str = include_str!("../../src/shares.rs");
    for (src, f, call) in [
        (API, "access", "viewer.narrowed_to(&path)?"),
        (API, "get_rings", "viewer.narrowed_scopes(&project)"),
        (API, "get_ring", "viewer.narrowed_scopes(&project)"),
        (SHARES, "list", "viewer.within_narrowing(&path)"),
    ] {
        assert!(handler(src, f).contains(call), "route handler {f} is not narrowed ({call})");
    }
    assert!(SYNC.contains("narrowing_gate(src, &view, n.tree, &ptrees)?;\n    let mut g = Graft::new"), "complete does not run the narrowing gate on the pushed tree before the graft");
    assert!(body_of(CHANGES, "create").contains("within_narrowing"), "an API commit's edits are not narrowed");
}

/// Rule 2, the kinds the cycle-4 test leaves out: a rename into or out of
/// the narrowing, a mode change outside, and a merge whose tree takes
/// another parent's change outside each get the one refusal a plain file
/// outside gets; a write inside only still lands (the control, last).
#[test]
fn a_narrowed_sessions_renames_mode_changes_and_merges_outside_get_the_one_refusal() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    with_api_folder(&hub, &p);
    let api = hub.api();
    // The admin's draft of a file outside the narrowing.
    let mut d = Craft::new(&api, &p.admin, &p.name, "main");
    d.file("src/other.rs", "fn o() {} // the admin's draft");
    let r = d.push_to("draft-r4", None);
    assert_eq!(r.status, 200, "{}", body(&r));
    assert!(r.json()["results"][0]["ok"].as_bool().unwrap(), "{}", body(&r));
    let narrow = agent_token(&hub, &p.dev.token(), &p.name, &["src/api"]);
    let draft = api.tips(Some(&narrow), &p.name).unwrap().branches["draft-r4"];
    let craft = || Craft::with(&api, narrow.clone(), p.dev.identity(), &p.name, "main");
    let theirs = Craft::with(&api, narrow.clone(), p.dev.identity(), &p.name, "draft-r4").entry("src/other.rs").expect("the draft's entry");
    let mut answers = Vec::new();
    // A plain file outside: the answer every other kind must equal.
    let mut c = craft();
    let t = c.tip;
    c.file("src/other.rs", "changed");
    answers.push(("a file", c.push_to("main", Some(t))));
    // A rename out of the narrowing.
    let mut c = craft();
    let t = c.tip;
    let h = c.entry("src/api/h.rs").unwrap();
    c.remove("src/api/h.rs");
    c.set_entry("src/moved-h.rs", h);
    answers.push(("a rename out", c.push_to("main", Some(t))));
    // A rename into it.
    let mut c = craft();
    let t = c.tip;
    let o = c.entry("src/other.rs").unwrap();
    c.remove("src/other.rs");
    c.set_entry("src/api/other.rs", o);
    answers.push(("a rename in", c.push_to("main", Some(t))));
    // A mode change outside.
    let mut c = craft();
    let t = c.tip;
    let mut o = c.entry("src/other.rs").unwrap();
    o.executable = true;
    c.set_entry("src/other.rs", o);
    answers.push(("a mode change", c.push_to("main", Some(t))));
    // A merge whose tree takes the draft's change outside.
    let mut c = craft();
    c.set_entry("src/other.rs", theirs);
    c.file("src/api/m.rs", "m");
    answers.push(("a merge taking theirs", c.push_merge("main", &[draft])));
    let first = body(&answers[0].1);
    assert_agent_refusal(&answers[0].1, NARROWED, "a file");
    for (what, r) in &answers {
        assert_eq!((r.status, body(r)), (403, first.clone()), "{what}");
    }
    // Control: a write inside its paths lands.
    let mut c = craft();
    let t = c.tip;
    c.file("src/api/inside.rs", "fn i() {}");
    let r = c.push_to("main", Some(t));
    assert_eq!(r.status, 200, "{}", body(&r));
    assert!(r.json()["results"][0]["ok"].as_bool().unwrap(), "control: {}", body(&r));
}

/// Rule 2, a merge parent whose changes lie outside the narrowing: a
/// narrowed session's merge that keeps its own side outside still records
/// the other parent as merged, so the person's later merge of that parent
/// finds nothing to do and its change outside never lands. A narrowed
/// session never decides how changes outside its paths merge.
#[test]
fn a_narrowed_session_never_merges_a_parent_whose_changes_lie_outside_its_paths() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    with_api_folder(&hub, &p);
    let api = hub.api();
    let atok = p.admin.token();
    let mut d = Craft::new(&api, &p.admin, &p.name, "main");
    d.file("src/other.rs", "fn o() {} // MARKER-DRAFT-FIX-4e");
    let r = d.push_to("draft-r4b", None);
    assert_eq!(r.status, 200, "{}", body(&r));
    assert!(r.json()["results"][0]["ok"].as_bool().unwrap(), "{}", body(&r));
    let draft = api.tips(Some(&atok), &p.name).unwrap().branches["draft-r4b"];
    let narrow = agent_token(&hub, &p.dev.token(), &p.name, &["src/api"]);
    let draft_seen = api.tips(Some(&narrow), &p.name).unwrap().branches["draft-r4b"];
    let mut c = Craft::with(&api, narrow.clone(), p.dev.identity(), &p.name, "main");
    c.file("src/api/m.rs", "m");
    let r = c.push_merge("main", &[draft_seen]);
    assert_agent_refusal(&r, NARROWED, "the narrowed session's merge of the draft");
    let main = tip(&hub, &atok, &p.name);
    let r = hub.api().post_json(Some(&atok), &format!("/v1/projects/{}/q/ancestry", p.name), &json!({"pairs": [[draft.hex(), main.hex()]]}));
    assert_eq!(r.status, 200, "{}", body(&r));
    assert_eq!(r.json()["results"][0]["is_ancestor"], false, "the draft is now merged into main without its change");
}

// ---- S11 redesign review, cycle 2 (s11r5): guarantees of the five fixes -----------------

/// Rule 1 for `rings`, `rings/{scope}` and `shares`, with one scope whose
/// secrets lie both inside and outside a narrowing (`src/`'s rule decides
/// `src/api/.env` and `src/tools/.env`): the narrowed session gets that
/// scope's ring exactly as its person does (its secrets inside need it),
/// no other scope (billing's is answered as a ring that does not exist),
/// and only the shares of files inside its paths. Its person gets them all
/// (the control).
#[test]
fn a_narrowed_sessions_rings_and_shares_are_its_persons_limited_to_its_paths() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let (a, api) = (&p.dir, hub.api());
    write_files(a, &[("src/api/.env", "API=MARKER-API-ENV-5b1e"), ("src/tools/.env", "TOOLS=MARKER-TOOLS-ENV-7c2f")]);
    p.admin.commit_main(a, "two secrets under src/");
    p.admin.ok(a, &["push"]);
    let bill_env = format!("{BILL_DIR}/.env");
    for path in ["src/api/.env", "src/tools/.env", bill_env.as_str()] {
        p.admin.ok(a, &["secret", "share", path, "--with", &p.dev.name]);
    }
    let policy = veil_core::hub::access::AccessPolicy::parse(&std::fs::read_to_string(a.join(".veilpolicy")).unwrap());
    let (src_scope, bill_scope) = (veil_core::policy::rule_scope(&policy, "src/api/.env"), veil_core::policy::rule_scope(&policy, &bill_env));
    assert_eq!(src_scope, veil_core::policy::rule_scope(&policy, "src/tools/.env"), "one scope inside and outside the narrowing");
    assert_ne!(src_scope, bill_scope);
    let (dev, narrow) = (p.dev.token(), agent_token(&hub, &p.dev.token(), &p.name, &["src/api"]));
    let rings = |t: &str| -> Vec<Value> {
        let r = api.get(Some(t), &format!("/v1/projects/{}/rings", p.name));
        assert_eq!(r.status, 200, "{}", body(&r));
        r.json().as_array().unwrap().clone()
    };
    let scopes = |v: &[Value]| v.iter().map(|r| r["scope"].as_str().unwrap().to_string()).collect::<Vec<_>>();
    let (mine, its) = (rings(&dev), rings(&narrow));
    assert!(scopes(&mine).contains(&src_scope) && scopes(&mine).contains(&bill_scope), "control: the person's rings: {:?}", scopes(&mine));
    assert_eq!(scopes(&its), vec![src_scope.clone()], "the narrowed session's rings");
    assert_eq!(its[0], mine.iter().find(|r| r["scope"] == src_scope.as_str()).unwrap().clone(), "the ring differs from its person's");
    // `rings/{scope}`: inside, the person's ring; outside, as one that does not exist.
    let ring = |t: &str, s: &str| api.get(Some(t), &format!("/v1/projects/{}/rings/{s}", p.name));
    let r = ring(&narrow, &src_scope);
    assert_eq!(r.status, 200, "{}", body(&r));
    assert_eq!(r.json(), its[0]);
    let r = ring(&dev, &bill_scope);
    assert_eq!(r.status, 200, "control: the person reads billing's ring: {}", body(&r));
    let none = "rule-00000000000000000000";
    let (outside, missing) = (ring(&narrow, &bill_scope), ring(&narrow, none));
    assert_eq!(missing.status, 404, "{}", body(&missing));
    assert_eq!((outside.status, body(&outside).replace(&bill_scope, "S")), (missing.status, body(&missing).replace(none, "S")), "billing's ring is told from one that does not exist");
    // `shares`: only those of files inside.
    let shares = |t: &str| -> Vec<String> {
        let r = api.get(Some(t), &format!("/v1/projects/{}/shares", p.name));
        assert_eq!(r.status, 200, "{}", body(&r));
        let mut v: Vec<String> = r.json().as_array().unwrap().iter().map(|s| s["path"].as_str().unwrap().to_string()).collect();
        v.sort();
        v
    };
    let mut all = vec![bill_env.clone(), "src/api/.env".to_string(), "src/tools/.env".to_string()];
    all.sort();
    assert_eq!(shares(&dev), all, "control: the person's shares");
    assert_eq!(shares(&narrow), vec!["src/api/.env".to_string()], "the narrowed session's shares");
}

/// Rule 1 for search, grep and the name search, whole answers: what a
/// narrowed session is told about its paths (results, scores, counts, the
/// complete and truncated flags, the cursor, the work done) is the same
/// before and after its person adds files outside them that match the same
/// words and names.
#[test]
fn a_narrowed_sessions_search_grep_and_name_answers_are_unchanged_by_files_outside() {
    use std::time::{Duration, Instant};
    let hub = TestHub::start();
    let p = setup_project(&hub);
    with_api_folder(&hub, &p);
    let token = p.dev.token();
    // Two more files inside, so that n=1 pages are truncated.
    let base = tip(&hub, &token, &p.name);
    let r = change(&hub, &token, &p.name, &json!({"base": base.hex(), "description": "inside", "onto": {"branch": "main", "expected": base.hex()},
        "edits": [{"path": "src/api/h2.rs", "put": {"text": "marker-inside-1c hh\n".repeat(3)}}, {"path": "src/api/hh3.rs", "put": {"text": "x marker-inside-1c\n"}}]}));
    assert_eq!(r.status, 200, "{}", body(&r));
    assert_eq!(r.json()["branch"]["status"], "ok", "{}", body(&r));
    let narrow = agent_token(&hub, &token, &p.name, &["src/api"]);
    let asks = [
        ("search", "q=marker-inside-1c&path=src/api"),
        ("search", "q=marker-inside-1c&path=src/api&n=1"),
        ("search", "q=hh&kind=path&path=src/api"),
        ("search", "q=hh&kind=path&path=src/api&n=1"),
        ("grep", "pattern=marker-inside-1c&path=src/api"),
        ("grep", "pattern=marker-inside-1c&path=src/api&n=1"),
    ];
    // Every answer, once the index covers the tip (`old`: not this one).
    let settled = |old: Option<&str>| -> Vec<Value> {
        let end = Instant::now() + Duration::from_secs(120);
        loop {
            let all: Vec<Reply> = asks.iter().map(|(r, a)| q(&hub, Some(&narrow), &p.name, r, a)).collect();
            let ready = all.iter().all(|r| r.status == 200 && r.json()["behind"] == false && old.is_none_or(|t| r.json()["tip_id"] != t));
            if ready {
                return all
                    .iter()
                    .map(|r| {
                        let mut v = r.json();
                        let o = v.as_object_mut().unwrap();
                        o.remove("tip_id");
                        o.remove("snapshot_id");
                        v
                    })
                    .collect();
            }
            assert!(Instant::now() < end, "never indexed: {:?}", all.iter().map(body).collect::<Vec<_>>());
            std::thread::sleep(Duration::from_millis(200));
        }
    };
    let before = settled(Some(&base.hex()));
    for (i, v) in before.iter().enumerate() {
        let n = v["results"].as_array().or(v["files"].as_array()).map_or(0, |a| a.len());
        assert!(n >= 1, "{:?}: nothing found: {v}", asks[i]);
    }
    assert_eq!(before[1]["truncated"], true, "{}", before[1]);
    assert_eq!(before[5]["truncated"], true, "{}", before[5]);
    let old = tip(&hub, &token, &p.name);
    let r = change(&hub, &token, &p.name, &json!({"base": old.hex(), "description": "outside", "onto": {"branch": "main", "expected": old.hex()},
        "edits": [{"path": "src/hh-outside.rs", "put": {"text": "marker-inside-1c marker-inside-1c\n".repeat(40)}},
                  {"path": "src/apiary/hh.rs", "put": {"text": "marker-inside-1c\n"}},
                  {"path": "src/api-hh.rs", "put": {"text": "marker-inside-1c hh\n"}}]}));
    assert_eq!(r.status, 200, "{}", body(&r));
    assert_eq!(r.json()["branch"]["status"], "ok", "{}", body(&r));
    let after = settled(Some(&old.hex()));
    for (i, (b, a)) in before.iter().zip(&after).enumerate() {
        assert_eq!(b, a, "{:?}: the answer changed with files outside the narrowing", asks[i]);
    }
}

/// Rule 2, a merge parent that differs outside the narrowing in each way
/// (a file added, deleted, renamed, its mode changed, the same content at
/// another path): the narrowed session's merge gets the one refusal a
/// plain write outside gets, whether its tree keeps its own side outside or
/// takes the other parent's. A merge of a parent that differs only inside,
/// and a stack of two snapshots inside, land (the controls, last).
#[test]
fn a_narrowed_sessions_merge_of_a_parent_differing_outside_in_any_way_gets_the_one_refusal() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    with_api_folder(&hub, &p);
    let api = hub.api();
    let dev = p.dev.token();
    let narrow = agent_token(&hub, &dev, &p.name, &["src/api"]);
    let main0 = tip(&hub, &dev, &p.name);
    // `src/other.rs`'s content (`with_api_folder`).
    const OTHER: &str = "fn o() {} // MARKER-OUTSIDE-2d";
    // The admin's drafts, one per kind of difference outside.
    let draft = |name: &str, edit: &dyn Fn(&mut Craft)| -> ObjectId {
        let mut d = Craft::new(&api, &p.admin, &p.name, "main");
        edit(&mut d);
        let r = d.push_to(name, None);
        assert_eq!(r.status, 200, "{}", body(&r));
        assert!(r.json()["results"][0]["ok"].as_bool().unwrap(), "{name}: {}", body(&r));
        api.tips(Some(&dev), &p.name).unwrap().branches[name]
    };
    let kinds: Vec<(&str, ObjectId)> = vec![
        ("added", draft("d-added-r5", &|d| d.file("src/added-r5.rs", "fn a() {}"))),
        ("deleted", draft("d-deleted-r5", &|d| d.remove("src/other.rs"))),
        ("renamed", draft("d-renamed-r5", &|d| {
            d.remove("src/other.rs");
            d.file("src/renamed-r5.rs", OTHER);
        })),
        ("mode", draft("d-mode-r5", &|d| {
            d.file("src/other.rs", OTHER);
            let mut e = d.entry("src/other.rs").unwrap();
            e.executable = true;
            d.set_entry("src/other.rs", e);
        })),
        ("same content elsewhere", draft("d-copy-r5", &|d| d.file("src/copy-r5.rs", OTHER))),
    ];
    // The reference: a plain write outside.
    let mut c = Craft::with(&api, narrow.clone(), p.dev.identity(), &p.name, "main");
    c.file("src/other.rs", "changed");
    let reference = c.push_to("main", Some(main0));
    assert_agent_refusal(&reference, NARROWED, "a plain write outside");
    for (kind, d) in &kinds {
        // Its own side outside, and a file inside.
        let mut ours = Craft::with(&api, dev.clone(), p.dev.identity(), &p.name, "main");
        ours.file("src/api/m.rs", "m");
        ours.token = narrow.clone();
        // The other parent's side outside (its person's view of it), and a file inside.
        let mut theirs = Craft::with(&api, dev.clone(), p.dev.identity(), &p.name, &format!("d-{}-r5", match *kind { "same content elsewhere" => "copy", k => k }));
        theirs.file("src/api/m.rs", "m");
        theirs.tip = main0;
        theirs.token = narrow.clone();
        for (side, r) in [("ours", ours.push_merge("main", &[*d])), ("theirs", theirs.push_merge("main", &[*d]))] {
            assert_eq!((r.status, body(&r)), (reference.status, body(&reference)), "{kind}, {side}");
        }
        assert_eq!(tip(&hub, &dev, &p.name), main0, "{kind}: main moved");
    }
    // Control 1: a parent that differs only inside merges.
    let inside = draft("d-inside-r5", &|d| d.file("src/api/d.rs", "fn d() {}"));
    let mut m = Craft::with(&api, dev.clone(), p.dev.identity(), &p.name, "d-inside-r5");
    m.file("src/api/m.rs", "m");
    m.tip = main0;
    m.token = narrow.clone();
    let r = m.push_merge("main", &[inside]);
    assert_eq!(r.status, 200, "{}", body(&r));
    assert!(r.json()["results"][0]["ok"].as_bool().unwrap(), "control: an inside-only merge: {}", body(&r));
    let main1 = tip(&hub, &dev, &p.name);
    let inside_seen = api.tips(Some(&dev), &p.name).unwrap().branches["d-inside-r5"];
    let r = api.post_json(Some(&dev), &format!("/v1/projects/{}/q/ancestry", p.name), &json!({"pairs": [[inside_seen.hex(), main1.hex()]]}));
    assert_eq!(r.status, 200, "{}", body(&r));
    assert_eq!(r.json()["results"][0]["is_ancestor"], true, "the inside-only parent is merged");
    // Control 2: a stack of two snapshots inside, pushed at once.
    let mut s = Craft::with(&api, narrow.clone(), p.dev.identity(), &p.name, "main");
    s.file("src/api/s1.rs", "fn s1() {}");
    let mut first = Snapshot {
        parents: vec![main1],
        change_id: veil_core::ChangeId::random(),
        tree: s.root,
        description: Text::Plain("s1".into()),
        author: "dev".into(),
        timestamp: veil_core::now_millis(),
        predecessors: vec![],
        conflicts: vec![],
        embargo: None,
        agent: None,
        abandoned: None,
        attempts: vec![],
        signature: None,
    };
    first.sign(&p.dev.identity());
    let s1 = s.put_object(O::Snapshot(first));
    s.file("src/api/s2.rs", "fn s2() {}");
    let (s2, r) = s.push_edited("main", Some(main1), |snap| snap.parents = vec![s1]);
    assert_eq!(r.status, 200, "{}", body(&r));
    assert!(r.json()["results"][0]["ok"].as_bool().unwrap(), "control: a stack of two inside: {}", body(&r));
    assert_eq!(tip(&hub, &narrow, &p.name), s2);
}

/// Rule 3 by every route that sets a tip: an agent session never creates
/// the default branch, narrowed or not, alone or beside another branch in
/// one push (nothing of that push lands), and an API commit's `onto` never
/// creates a branch for anyone. Another new branch is allowed (the control).
#[test]
fn an_agent_session_never_creates_the_default_branch_by_any_route() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    with_api_folder(&hub, &p);
    let api = hub.api();
    let atok = p.admin.token();
    let tip0 = tip(&hub, &atok, &p.name);
    let agent = agent_token(&hub, &atok, &p.name, &[]);
    let narrow = agent_token(&hub, &atok, &p.name, &["src/api"]);
    // Built while main exists; pushed once it is gone.
    let mut both = Craft::with(&api, agent.clone(), p.admin.identity(), &p.name, "main");
    both.file("src/api/b.rs", "fn b() {}");
    let mut narrowed = Craft::with(&api, narrow.clone(), p.admin.identity(), &p.name, "main");
    narrowed.file("src/other.rs", "outside");
    let mut feature = Craft::with(&api, agent.clone(), p.admin.identity(), &p.name, "main");
    feature.file("src/api/f.rs", "fn f() {}");
    let r = api.post_json(Some(&atok), &format!("/v1/projects/{}/push", p.name), &json!({"updates": [{"branch": "main", "expected": tip0.hex(), "new": null}]}));
    assert_eq!(r.status, 200, "{}", body(&r));
    assert!(r.json()["results"][0]["ok"].as_bool().unwrap(), "the admin deletes main: {}", body(&r));
    let branches = || api.tips(Some(&atok), &p.name).unwrap().branches;
    // Beside another new branch, in one push.
    let (_, r) = both.push_edited("feature-a-r5", None, |_| {});
    assert_eq!(r.status, 200, "{}", body(&r));
    assert!(r.json()["results"][0]["ok"].as_bool().unwrap(), "{}", body(&r));
    let fa = branches()["feature-a-r5"];
    let r = api.post_json(Some(&agent), &format!("/v1/projects/{}/push", p.name),
        &json!({"updates": [{"branch": "feature-b-r5", "expected": null, "new": fa.hex()}, {"branch": "main", "expected": null, "new": fa.hex()}]}));
    assert_agent_refusal(&r, DEFAULT_BRANCH_REFUSAL, "main beside another branch");
    assert!(!branches().contains_key("main") && !branches().contains_key("feature-b-r5"), "part of the push landed: {:?}", branches().keys());
    // A narrowed session, with a write outside: the default branch's answer first.
    let r = narrowed.push_to("main", None);
    assert_agent_refusal(&r, DEFAULT_BRANCH_REFUSAL, "a narrowed session's main");
    assert!(!branches().contains_key("main"));
    // An API commit `onto` the absent default branch: refused, for the person as for the agent.
    let mut answers = Vec::new();
    for t in [&agent, &atok] {
        let r = change(&hub, t, &p.name, &json!({"base": fa.hex(), "description": "x", "edits": [{"path": "src/api/c.rs", "put": {"text": "c"}}],
                                                 "onto": {"branch": "main", "expected": fa.hex()}}));
        assert_eq!(r.status, 400, "{}", body(&r));
        answers.push(body(&r));
        assert!(!branches().contains_key("main"), "an API commit created main");
    }
    assert_eq!(answers[0], answers[1]);
    // Control: another new branch.
    let r = feature.push_to("feature-c-r5", None);
    assert_eq!(r.status, 200, "{}", body(&r));
    assert!(r.json()["results"][0]["ok"].as_bool().unwrap(), "control: another new branch: {}", body(&r));
}

/// Rule 2 for an API commit `onto` a stack of its person's own changes
/// that holds a change outside the narrowing: one answer, whether or not a
/// change its person cannot see landed on the branch since (then the stack
/// is made again on the tip, BUG-1054). Neither the outside change nor the
/// landing it cannot see may show in the answer.
#[test]
fn a_narrowed_sessions_commit_onto_its_persons_stack_answers_one_way_whatever_landed_unseen() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    with_api_folder(&hub, &p);
    let api = hub.api();
    let (dev, atok) = (p.dev.token(), p.admin.token());
    let narrow = agent_token(&hub, &dev, &p.name, &["src/api"]);
    let mut answers = Vec::new();
    for unseen in [false, true] {
        let base = tip(&hub, &dev, &p.name);
        // The person's own change outside the narrowing, not landed.
        let own = change(&hub, &dev, &p.name, &json!({"base": base.hex(), "description": "own", "edits": [{"path": "src/other.rs", "put": {"text": format!("own {unseen}")}}]}));
        assert_eq!(own.status, 200, "{}", body(&own));
        let on = own.json()["snapshot"].as_str().unwrap().to_string();
        if unseen {
            // The admin lands a change of billing, which dev cannot see.
            let mut d = Craft::new(&api, &p.admin, &p.name, "main");
            let t = d.tip;
            d.file(&format!("{BILL_DIR}/unseen-r5.txt"), "unseen");
            let r = d.push_to("main", Some(t));
            assert_eq!(r.status, 200, "{}", body(&r));
            assert!(r.json()["results"][0]["ok"].as_bool().unwrap(), "{}", body(&r));
            assert_eq!(tip(&hub, &dev, &p.name), base, "dev sees the tip as before");
        }
        let r = change(&hub, &narrow, &p.name, &json!({"base": on, "description": "on it", "edits": [{"path": "src/api/s.rs", "put": {"text": format!("s {unseen}")}}],
                                                       "onto": {"branch": "main", "expected": base.hex()}}));
        let v = r.json();
        answers.push((r.status, v["code"].clone(), v["message"].clone(), v["branch"]["status"].clone(), v["branch"]["message"].clone()));
        let _ = &atok;
    }
    assert_eq!(answers[0].0, 200, "{:?}", answers[0]);
    assert_eq!(answers[0].3, "rejected", "{:?}", answers[0]);
    assert_eq!(answers[0], answers[1], "the answer tells whether a change dev cannot see landed");
}

/// BUG-1567: a secret inside a narrowing sealed under a scope a `cloak`
/// line names (a plain `cloak` line names `team`; `cloak ops` names `ops`)
/// is a secret inside its paths, so the narrowed session gets that scope's
/// ring as its person does. `Viewer::narrowed_scopes` takes scopes from the
/// access rules alone and leaves it out.
#[test]
fn a_narrowed_session_gets_the_ring_of_a_secret_inside_its_paths_sealed_under_a_named_scope() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let a = &p.dir;
    let policy = std::fs::read_to_string(a.join(".veilpolicy")).unwrap();
    // `team` seals a secret inside (`src/api/.env.ops  cloak`); `ops` seals
    // secrets both inside and outside; `out` seals a secret only outside.
    std::fs::write(
        a.join(".veilpolicy"),
        format!(
            "{policy}\
             src/api/.env.ops  cloak\n\
             src/api/.env.shared  cloak ops\n\
             src/tools/.env.shared  cloak ops\n\
             src/tools/.env.out  cloak out\n"
        ),
    )
    .unwrap();
    write_files(
        a,
        &[
            ("src/api/.env.ops", "OPS=MARKER-OPS-ENV-3d9a"),
            ("src/api/.env.shared", "SHARED_IN=MARKER-SHARED-IN-8b1e"),
            ("src/tools/.env.shared", "SHARED_OUT=MARKER-SHARED-OUT-4c2f"),
            ("src/tools/.env.out", "OUT_ONLY=MARKER-OUT-ONLY-9f7d"),
        ],
    );
    for s in ["ops", "out"] {
        p.admin.ok(a, &["scope", "create", s]);
    }
    p.admin.commit_main(a, "secrets under named scopes inside and outside");
    p.admin.ok(a, &["push"]);
    let api = hub.api();
    for s in ["ops", "out"] {
        let ring: Value = serde_json::from_slice(&std::fs::read(a.join(format!(".veil/meta/keyrings/{s}.json"))).unwrap()).unwrap();
        let r = api.post_json(Some(&p.admin.token()), &format!("/v1/projects/{}/rings/{s}", p.name), &ring);
        assert_eq!(r.status, 200, "{s}: {}", body(&r));
    }
    let (dev, narrow) = (p.dev.token(), agent_token(&hub, &p.dev.token(), &p.name, &["src/api"]));
    let scopes = |t: &str| -> Vec<String> {
        let r = api.get(Some(t), &format!("/v1/projects/{}/rings", p.name));
        assert_eq!(r.status, 200, "{}", body(&r));
        r.json().as_array().unwrap().iter().map(|r| r["scope"].as_str().unwrap().to_string()).collect()
    };
    for s in ["team", "ops", "out"] {
        assert!(scopes(&dev).contains(&s.to_string()), "control: the person's rings lack {s}: {:?}", scopes(&dev));
    }
    // The secret is inside the narrowing, sealed under `team`.
    let r = q(&hub, Some(&narrow), &p.name, "tree", "path=src/api");
    assert_eq!(r.status, 200, "{}", body(&r));
    assert!(body(&r).contains(".env.ops"), "{}", body(&r));
    // It is sealed under `team` (the admin's own tree says so).
    let repo = veil_core::Repo::open(std::sync::Arc::new(veil_core::DiskBackend::new(a)), None, "test").unwrap();
    let main = repo.snapshot(&repo.view().tags["main"].target).unwrap().tree;
    let (mut id, mut entry) = (main, None);
    for part in ["src", "api", ".env.ops"] {
        let e = repo.store().tree(&id).unwrap().entries.iter().find(|e| e.name == part).unwrap().clone();
        id = e.id;
        entry = Some(e);
    }
    assert_eq!(entry.unwrap().visibility, veil_core::object::Visibility::Cloaked { scope: "team".into() }, "the secret's scope");
    let ns = scopes(&narrow);
    assert!(ns.contains(&"team".to_string()), "the narrowed session lacks the ring of its own secret: {ns:?}");
    assert!(ns.contains(&"ops".to_string()), "a scope sealing secrets both inside and outside gives the ring: {ns:?}");
    assert!(!ns.contains(&"out".to_string()), "a scope sealing secrets only outside is left out: {ns:?}");
    for s in ["team", "ops"] {
        let r = api.get(Some(&narrow), &format!("/v1/projects/{}/rings/{s}", p.name));
        assert_eq!(r.status, 200, "{s}: {}", body(&r));
    }
    let r_out = api.get(Some(&narrow), &format!("/v1/projects/{}/rings/out", p.name));
    let r_none = api.get(Some(&narrow), &format!("/v1/projects/{}/rings/no-such-scope", p.name));
    assert_eq!(r_out.status, 404, "{}", body(&r_out));
    assert_eq!(
        (r_out.status, body(&r_out).replace("out", "S")),
        (r_none.status, body(&r_none).replace("no-such-scope", "S"))
    );
}

/// BUG-1567's fix writes `projects.policy_text` itself when the default
/// branch moves to a `.veilpolicy` whose access lines are unchanged (review
/// s11r6). Another server beside the first, whose cache already holds the
/// project, gives a narrowed session the ring of a secret a new tier line
/// seals inside its paths at once (the access epoch, a trigger on
/// `policy_text`, voids every server's cached project). Neither an agent
/// session nor a member who is not an admin moves the default branch to new
/// tier lines.
#[test]
fn a_tier_line_on_the_default_branch_reaches_every_servers_narrowed_rings_and_only_an_admin_writes_it() {
    let hub = TestHub::start();
    let beside = TestHub::beside(&hub);
    let p = setup_project(&hub);
    let a = &p.dir;
    p.admin.ok(a, &["scope", "create", "ops"]);
    p.admin.commit_main(a, "scope ops");
    p.admin.ok(a, &["push"]);
    let ring: Value = serde_json::from_slice(&std::fs::read(a.join(".veil/meta/keyrings/ops.json")).unwrap()).unwrap();
    let r = hub.api().post_json(Some(&p.admin.token()), &format!("/v1/projects/{}/rings/ops", p.name), &ring);
    assert_eq!(r.status, 200, "{}", body(&r));
    let narrow = agent_token(&hub, &p.dev.token(), &p.name, &["src/api"]);
    let ops = |h: &TestHub| h.api().get(Some(&narrow), &format!("/v1/projects/{}/rings/ops", p.name));
    // Before: `ops` seals nothing inside, on either server (both cache the project).
    for h in [&hub, &beside] {
        let r = ops(h);
        assert_eq!(r.status, 404, "{}", body(&r));
    }
    let policy = std::fs::read_to_string(a.join(".veilpolicy")).unwrap();
    std::fs::write(a.join(".veilpolicy"), format!("{policy}src/api/.env.ops  cloak ops\n")).unwrap();
    write_files(a, &[("src/api/.env.ops", "OPS=MARKER-OPS-TIER-LINE-5e1c")]);
    p.admin.commit_main(a, "a tier line sealing a secret inside src/api under ops");
    p.admin.ok(a, &["push"]);
    for h in [&beside, &hub] {
        let r = ops(h);
        assert_eq!(r.status, 200, "{}", body(&r));
    }
    // Who else could move the default branch to new tier lines: an admin's
    // agent session, and a member who is not an admin. Both are refused,
    // and the branch stays where it was.
    let before = tip(&hub, &p.admin.token(), &p.name);
    let weaker = format!("{policy}src/api/.env.ops  cloak ops\nsrc/api/.env.ops  public!\n");
    for (who, token) in [("admin's agent", agent_token(&hub, &p.admin.token(), &p.name, &[])), ("member", p.dev.token())] {
        let base = tip(&hub, &token, &p.name);
        let r = change(
            &hub,
            &token,
            &p.name,
            &json!({"base": base.hex(), "edits": [{"path": ".veilpolicy", "put": {"text": weaker}}], "onto": {"branch": "main", "expected": "rebase"}}),
        );
        assert_eq!(r.status, 403, "{who}: {}", body(&r));
    }
    assert_eq!(tip(&hub, &p.admin.token(), &p.name), before);
    let r = ops(&beside);
    assert_eq!(r.status, 200, "{}", body(&r));
}
