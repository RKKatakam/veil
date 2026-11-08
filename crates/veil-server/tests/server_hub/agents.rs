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
    assert_eq!(r.status, 403, "{}", body(&r));
    assert!(body(&r).contains("agent_session"), "{}", body(&r));
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
        assert!(r.status == 400 || r.status == 422, "{bad}: {} {}", r.status, body(&r));
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
        (format!("/v1/projects/{pr}/rings/team"), json!({})),
        (format!("/v1/projects/{pr}/shares"), json!({})),
        (format!("/v1/projects/{pr}/shares/remove"), json!({})),
    ];
    for (path, v) in refused {
        let r = api.post_json(Some(&agent), &path, &v);
        assert!(r.status == 403 || r.status == 422 || r.status == 400, "{path}: {} {}", r.status, body(&r));
        if r.status == 403 {
            assert!(body(&r).contains("agent_session"), "{path}: {}", body(&r));
        }
    }
    // The ones that parse are refused as an agent's, not for their input.
    let r = api.post_json(Some(&agent), &format!("/v1/projects/{pr}/groups/agents"), &json!({}));
    assert_eq!(r.status, 403, "{}", body(&r));
    let r = api.post(Some(&agent), &format!("/v1/projects/{}", unique("agentmade")), b"", false);
    assert_eq!(r.status, 403, "{}", body(&r));
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
        assert_eq!(r.status, 403, "{route}?{params}: {} {}", r.status, body(&r));
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
        assert!(r.status == 403 || r.status == 400, "{path}: {} {}", r.status, body(&r));
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
    assert!(forged.status == 400 || forged.status == 422, "{} {}", forged.status, body(&forged));
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
    let refused = (r.status == 403 && body(&r).contains("agent_session")) || (r.status == 200 && r.json()["branch"]["status"] == "rejected");
    assert!(refused, "the admin's agent session changed access: {} {}", r.status, body(&r));
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
    let refused = |r: &Reply| r.status == 403 || (r.status == 200 && r.json()["results"].as_array().unwrap().iter().all(|x| x["ok"] == false));
    // Forced back to before `src/other.rs` existed.
    let forced = push(json!([{"branch": "main", "expected": main.hex(), "new": before.hex()}]), true);
    // Deleted.
    let deleted = push(json!([{"branch": "release-77ab", "expected": release.hex(), "new": null}]), false);
    let tips = api.tips(Some(&atok), &p.name).unwrap().branches;
    assert!(
        refused(&forced) && refused(&deleted),
        "forced: {} {}; deleted: {} {}",
        forced.status,
        body(&forced),
        deleted.status,
        body(&deleted)
    );
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
    assert!(h.status == 400 || h.status == 409 || h.status == 426, "{} {}", h.status, body(&h));
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
    // Barred: a device's agent sessions are refused everywhere in the project.
    let fin_agent = agent_token(&hub, &p.fin.token(), &p.name, &[]);
    assert_eq!(hub.api().get(Some(&fin_agent), &format!("/v1/projects/{}/tips", p.name)).status, 200, "control");
    let r = hub.api().post_json(Some(&atok), "/v1/devices/remove", &json!({"device": p.fin.identity().public_id(), "project": p.name}));
    assert_eq!(r.status, 200, "{}", body(&r));
    let r = hub.api().get(Some(&fin_agent), &format!("/v1/projects/{}/tips", p.name));
    assert_eq!(r.status, 403, "a barred device's agent session: {}", body(&r));
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
    let is_agent_refusal = |r: &Reply| r.status == 403 && body(r).contains("agent_session");
    // Its own push, signed by its person's device (the workspace vl holds it).
    let mut c = Craft::with(&api, agent.clone(), p.admin.identity(), &p.name, "main");
    let tip0 = c.tip;
    c.file(".veilpolicy", &opened);
    let r = c.push_to("main", Some(tip0));
    assert!(is_agent_refusal(&r), "its own push: {} {}", r.status, body(&r));
    // Its own API commits: `.veilrules`, and a policy file in a folder.
    for path in [".veilrules", "src/.veilpolicy", ".veilpolicy"] {
        let r = change(&hub, &agent, &p.name, &json!({"base": tip0.hex(), "description": "x", "edits": [{"path": path, "put": {"text": "src/ public\n"}}]}));
        assert!(r.status == 403, "{path}: {} {}", r.status, body(&r));
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
    assert!(is_agent_refusal(&r), "a merge taking someone else's change of .veilpolicy: {} {}", r.status, body(&r));
    // A move of the default branch that lands it.
    let r = api.post_json(Some(&agent), &format!("/v1/projects/{}/push", p.name), &json!({"updates": [{"branch": "main", "expected": tip0.hex(), "new": side.hex()}]}));
    assert!(is_agent_refusal(&r), "a fast-forward landing someone else's .veilpolicy: {} {}", r.status, body(&r));
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
    assert!(r.status == 403 && body(&r).contains("agent_session"), "{} {}", r.status, body(&r));
    let r = push(&wide, json!([{"branch": "release-9c1d", "expected": release.hex(), "new": null}]), false);
    assert!(r.status == 403 && body(&r).contains("agent_session"), "{} {}", r.status, body(&r));
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
    assert_eq!(r.json()["branch"]["message"], "this agent session is narrowed: the move would change files outside its paths", "{}", body(&r));
    // Its own change inside lands.
    let r = change(&hub, &narrow, &p.name, &json!({"base": base.hex(), "description": "inside", "edits": [{"path": "src/api/m.rs", "put": {"text": "m"}}],
                                                   "onto": {"branch": "main", "expected": base.hex()}}));
    assert_eq!(r.status, 200, "{}", body(&r));
    assert_eq!(r.json()["branch"]["status"], "ok", "{}", body(&r));
}
