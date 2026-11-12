//! The access hunt of 2026-11-12 (after phase 4 and the speed work): every
//! route added or changed since S1's crawl (`leaks.rs`), crawled as anyone
//! on Earth, as a member who sees only the public folder and as an admin's
//! agent session narrowed to `src/`, with every real path and snapshot id
//! an admin sees. Every byte received is searched for every whole marker
//! the viewer may not see (`docs/VISIBILITY.md`; `docs/HUB.md` §13.27).

use serde_json::json;
use veil_core::ObjectId;

use crate::support::*;

const PR_MARK: &str = "MARKER-PR-OF-BILLING-ONLY-73c9e1d4";
const CHECK_MARK: &str = "MARKER-CHECK-OF-FINANCE-SESSION-0e5a9b27";

fn body(r: &Reply) -> String {
    String::from_utf8_lossy(&r.body).into_owned()
}

fn agent_token(hub: &TestHub, token: &str, project: &str, only: &[&str]) -> String {
    let r = hub.api().post_json(
        Some(token),
        "/v1/sessions/agent",
        &json!({"project": project, "attribution": {"agent": "hunt/1", "task": "TASK-HUNT-1"}, "only": only}),
    );
    assert_eq!(r.status, 200, "{}", body(&r));
    r.json()["token"].as_str().unwrap().to_string()
}

/// Every answer `token` (or anyone on Earth) gets from the query API, PRs,
/// checks, bisect and the web client for `project`, given the admin's real
/// paths and snapshot ids.
fn crawl(api: &Api, token: Option<&str>, project: &str, real: &[(String, ObjectId)], snaps: &[ObjectId], prs: &[String]) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut get = |what: String, path: String| {
        let r = api.get(token, &path);
        out.push((format!("{what} ({})", r.status), r.body));
    };
    let q = |route: &str, params: String| format!("/v1/projects/{project}/q/{route}?{params}");
    let mut revs: Vec<String> = snaps.iter().map(ObjectId::hex).collect();
    revs.push("main".into());
    get("log".into(), q("log", "n=100".into()));
    for (path, _) in real.iter().filter(|(p, _)| !p.is_empty()) {
        get(format!("log {path}"), q("log", format!("path={path}")));
        get(format!("blame {path}"), q("blame", format!("path={path}")));
        get(format!("blame follow {path}"), q("blame", format!("path={path}&follow=true")));
        get(format!("history {path}"), q("history", format!("path={path}")));
        get(format!("history follow {path}"), q("history", format!("path={path}&follow=true")));
        get(format!("search under {path}"), q("search", format!("q=MARKER&path={path}")));
        get(format!("grep under {path}"), q("grep", format!("pattern=MARKER&path={path}")));
        get(format!("web file {path}"), format!("/p/{project}/file/{path}"));
        get(format!("web tree {path}"), format!("/p/{project}/tree/{path}"));
        get(format!("web blame {path}"), format!("/p/{project}/blame/{path}"));
        get(format!("web history {path}"), format!("/p/{project}/history/{path}"));
    }
    for rev in &revs {
        get(format!("show {rev}"), q("show", format!("rev={rev}")));
        get(format!("tree {rev}"), q("tree", format!("rev={rev}")));
        get(format!("diff {rev}"), q("diff", format!("from={rev}")));
        get(format!("resolve {rev}"), q("resolve", format!("prefix={}", &rev[..rev.len().min(12)])));
        get(format!("checks {rev}"), format!("/v1/projects/{project}/checks?rev={rev}"));
        get(format!("web commit {rev}"), format!("/p/{project}/commit/{rev}"));
        for (path, _) in real.iter().filter(|(p, _)| !p.is_empty()) {
            get(format!("show {rev} {path}"), q("show", format!("rev={rev}&path={path}")));
            get(format!("file {rev} {path}"), q("file", format!("rev={rev}&path={path}")));
            get(format!("tree {rev} {path}"), q("tree", format!("rev={rev}&path={path}")));
            get(format!("diff {rev} {path}"), q("diff", format!("from={rev}&path={path}")));
        }
    }
    for kind in ["code", "path"] {
        get(format!("search {kind}"), q("search", format!("q=MARKER&kind={kind}")));
        get(format!("search {kind} bill"), q("search", format!("q=bill&kind={kind}")));
    }
    get("grep".into(), q("grep", "pattern=MARKER".into()));
    get("tested".into(), format!("/v1/projects/{project}/tested/main"));
    get("bisect".into(), format!("/v1/projects/{project}/bisect/main"));
    get("prs".into(), format!("/v1/projects/{project}/prs"));
    get("prs all".into(), format!("/v1/projects/{project}/prs?state=all"));
    get("prs search".into(), format!("/v1/projects/{project}/prs?q=MARKER"));
    for id in prs {
        for tail in ["", "/diff", "/threads"] {
            get(format!("pr {id}{tail}"), format!("/v1/projects/{project}/prs/{id}{tail}"));
        }
        get(format!("web pr {id}"), format!("/p/{project}/prs/{id}"));
    }
    for page in ["", "/tree", "/log", "/prs", "/search?q=MARKER", "/search?q=bill&mode=path", "/admin"] {
        get(format!("web {page}"), format!("/p/{project}{page}"));
    }
    get("access".into(), format!("/v1/projects/{project}/access"));
    get("shares".into(), format!("/v1/projects/{project}/shares"));
    get("health".into(), format!("/v1/projects/{project}/health"));
    let pairs: Vec<(String, String)> = snaps.iter().flat_map(|a| snaps.iter().map(move |b| (a.hex(), b.hex()))).collect();
    for (what, route, v) in [
        ("ancestry", "q/ancestry", json!({"pairs": pairs})),
        ("generations", "q/generations", json!({"snapshots": snaps.iter().map(ObjectId::hex).collect::<Vec<_>>()})),
    ] {
        let r = api.post_json(token, &format!("/v1/projects/{project}/{route}"), &v);
        out.push((format!("{what} ({})", r.status), r.body));
    }
    out
}

/// The standard project, plus: a PR of a billing-only change (its title a
/// marker), and a check that finance's session posts on the tip (its
/// summary a marker).
fn hunt_project(hub: &TestHub) -> (Project, Vec<String>) {
    let p = setup_project(hub);
    let api = hub.api();
    let admin = p.admin.token();
    let base = api.tips(Some(&admin), &p.name).unwrap().branches["main"];
    let r = api.post_json(
        Some(&admin),
        &format!("/v1/projects/{}/changes", p.name),
        &json!({"base": base.hex(), "description": "billing follow-up",
                "edits": [{"path": format!("{BILL_DIR}/acme/next.txt"), "put": {"text": BILL_MARK}}]}),
    );
    assert_eq!(r.status, 200, "the admin commits a billing change: {}", body(&r));
    let snap: ObjectId = serde_json::from_value(r.json()["snapshot"].clone()).unwrap();
    let r = api.post_json(
        Some(&admin),
        &format!("/v1/projects/{}/push", p.name),
        &json!({"updates": [{"branch": "hunt-bill", "expected": null, "new": snap.hex()}], "force": false}),
    );
    assert_eq!((r.status, r.json()["results"][0]["ok"].clone()), (200, json!(true)), "the admin makes a branch of it: {}", body(&r));
    let r = api.post_json(Some(&admin), &format!("/v1/projects/{}/prs", p.name), &json!({"head": "hunt-bill", "title": PR_MARK, "body": PR_MARK}));
    assert_eq!(r.status, 200, "the admin opens a PR of it: {}", body(&r));
    let pr = r.json()["id"].as_str().unwrap().to_string();
    let r = api.post_json(
        Some(&p.fin.token()),
        &format!("/v1/projects/{}/checks", p.name),
        &json!({"snapshot": base.hex(), "name": "ci/fin", "state": "fail", "summary": CHECK_MARK, "log": CHECK_MARK}),
    );
    assert_eq!(r.status, 200, "finance posts a check on the tip: {}", body(&r));
    // Controls: the admin sees both.
    let prs = api.get(Some(&admin), &format!("/v1/projects/{}/prs", p.name));
    assert!(body(&prs).contains(PR_MARK), "the admin lists the PR: {}", body(&prs));
    let checks = api.get(Some(&p.fin.token()), &format!("/v1/projects/{}/checks", p.name));
    assert!(body(&checks).contains(CHECK_MARK), "finance sees its check: {}", body(&checks));
    (p, vec![pr])
}

#[test]
fn no_route_of_this_week_gives_anyone_a_folder_they_cannot_see() {
    let hub = TestHub::start();
    let (p, prs) = hunt_project(&hub);
    let api = hub.api();
    let real = real_paths(&p.dir);
    let snaps = real_snapshots(&p.dir);
    let mut hidden = restricted_markers();
    hidden.extend([PR_MARK, CHECK_MARK]);

    let anyone = crawl(&api, None, &p.name, &real, &snaps, &prs);
    assert_no_marker(&anyone, &hidden, "anyone on Earth");
    let dev = crawl(&api, Some(&p.dev.token()), &p.name, &real, &snaps, &prs);
    assert_no_marker(&dev, &hidden, "a member of devs");
    // Liveness: both read the public folder through these routes.
    assert!(has_marker(&anyone, PUBLIC_MARK), "anyone on Earth reads src/");
    assert!(has_marker(&dev, PUBLIC_MARK), "the dev reads src/");
}

#[test]
fn an_admins_session_narrowed_to_src_gets_nothing_outside_it_on_this_weeks_routes() {
    let hub = TestHub::start();
    let (p, prs) = hunt_project(&hub);
    let api = hub.api();
    let real = real_paths(&p.dir);
    let snaps = real_snapshots(&p.dir);
    let agent = agent_token(&hub, &p.admin.token(), &p.name, &["src"]);
    // History is the person's (`docs/HUB.md` §13.27): descriptions may
    // show; no path, content, PR or check of outside its paths.
    let outside = [ROOT_FILE, ROOT_MARK, BILL_DIR, BILL_MARK, PERSON_DIR, PERSON_MARK, ENV_MARK, PR_MARK, CHECK_MARK];
    let got = crawl(&api, Some(&agent), &p.name, &real, &snaps, &prs);
    assert_no_marker(&got, &outside, "the admin's agent narrowed to src/");
    assert!(has_marker(&got, PUBLIC_MARK), "the narrowed session reads src/");
    assert!(has_marker(&got, NESTED_MARK), "the admin's narrowed session reads src/'s restricted folder");
}

/// `docs/HUB.md` §13.27 (a narrowed session sees only its paths on every
/// route; BUG-1536: its statistics are taken over its paths alone) and
/// §13.25 (health is for the project's admins: "the counts include work by
/// people and on folders others may not see"). An admin's agent session
/// narrowed to `src/` is refused health, as `ci::can_see_check` refuses it
/// admin-only results; the admin's own session reads it.
#[test]
#[ignore = "BUG-1995: a narrowed agent session of an admin reads the whole project's health counts"]
fn bug_1995_a_narrowed_session_of_an_admin_is_refused_the_projects_health() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let admin = p.admin.token();
    let r = api.get(Some(&admin), &format!("/v1/projects/{}/health", p.name));
    assert_eq!(r.status, 200, "the admin reads the project's health: {}", body(&r));
    let agent = agent_token(&hub, &admin, &p.name, &["src"]);
    let r = api.get(Some(&agent), &format!("/v1/projects/{}/health", p.name));
    assert_eq!((r.status, r.json()["code"].clone()), (403, json!("forbidden")), "{}", body(&r));
}
