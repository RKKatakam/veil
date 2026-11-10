//! Milestone S19 on the server (`docs/HUB.md` §13.35;
//! `docs/design/server/phase-4-agent-scale.md` §4.6, §4.7, §5.2):
//! CI through the API; land first, test after; `main@tested`; agents start
//! from `main@tested` by default.
//!
//! Guarantees, each a test here:
//! 1. A CI runner sees only what its grant allows. A result names nothing its
//!    readers can't see. A runner can't move any branch or land anything.
//! 2. `main@tested` only ever moves to a tip whose required checks all passed,
//!    never backwards, and correctly across two servers and restarts.
//! 3. A failing or absent runner never blocks landings; `main@tested` just
//!    stays put.
//! 4. Agents start from `main@tested` by default, and a person can still
//!    choose another base.
//! 5. Results and their logs are bounded per tip and per runner.

use serde_json::{json, Value};
use veil_core::{
    hub::ci::{
        MAX_CHECKS_PER_SNAPSHOT, MAX_CHECK_NAME, MAX_LOG_BYTES, MAX_RUNNER_CHECKS, MAX_RUNNER_LOG_BYTES, MAX_SUMMARY_BYTES,
        MAX_TIP_LOG_BYTES, MAX_URL_BYTES,
    },
    ObjectId,
};

use crate::support::*;

const RUNNER_REFUSAL: &str = "a CI runner session may only read what its grant allows and report check results";

fn body(r: &Reply) -> String {
    String::from_utf8_lossy(&r.body).into_owned()
}

fn ci_session(hub: &TestHub, token: Option<&str>, req: &Value) -> Reply {
    hub.api().post_json(token, "/v1/sessions/ci", req)
}

fn post_check(hub: &TestHub, token: Option<&str>, project: &str, req: &Value) -> Reply {
    hub.api().post_json(token, &format!("/v1/projects/{project}/checks"), req)
}

fn get_checks(hub: &TestHub, token: Option<&str>, project: &str, rev: Option<&str>) -> Reply {
    let path = match rev {
        Some(r) => format!("/v1/projects/{project}/checks?rev={r}"),
        None => format!("/v1/projects/{project}/checks"),
    };
    hub.api().get(token, &path)
}

fn get_tested(hub: &TestHub, token: Option<&str>, project: &str, branch: &str) -> Reply {
    hub.api().get(token, &format!("/v1/projects/{project}/tested/{branch}"))
}

fn change(hub: &TestHub, token: &str, project: &str, req: &Value) -> Reply {
    hub.api().post_json(Some(token), &format!("/v1/projects/{project}/changes"), req)
}

fn land(hub: &TestHub, token: &str, project: &str, req: &Value) -> Reply {
    hub.api().post_json(Some(token), &format!("/v1/projects/{project}/land"), req)
}

fn tip(hub: &TestHub, token: &str, project: &str) -> ObjectId {
    hub.api().tips(Some(token), project).unwrap().branches["main"]
}

/// Set `.veilrules` on `main` via an admin change.
fn set_rules(hub: &TestHub, p: &Project, rules_toml: &str) -> ObjectId {
    let admin = p.admin.token();
    let base = tip(hub, &admin, &p.name);
    let r = change(
        hub,
        &admin,
        &p.name,
        &json!({
            "base": base.hex(),
            "description": "configure .veilrules",
            "onto": {"branch": "main", "expected": base.hex()},
            "edits": [{"path": ".veilrules", "put": {"text": rules_toml}}]
        }),
    );
    assert_eq!(r.status, 200, "{}", body(&r));
    assert_eq!(r.json()["branch"]["status"], "ok", "{}", body(&r));
    ObjectId::from_hex(r.json()["snapshot"].as_str().unwrap()).unwrap()
}

/// Guarantee 1: A CI runner sees only what its grant allows. A result names
/// nothing its readers can't see. A runner can't move any branch or land
/// anything.
#[test]
fn runner_sees_only_its_grant_and_results_respect_visibility_and_runner_cannot_write_code() {
    let hub = TestHub::start();
    let p = setup_project(&hub);

    // Configure `.veilrules` with check-specific paths and required checks.
    let bill_rule = format!("{BILL_DIR}/");
    let rules_toml = format!(
        "[branches.main]\nrequired_checks = [\"ci/src\", \"ci/billing\"]\n\n[checks.\"ci/src\"]\npaths = [\"src/\"]\n\n[checks.\"ci/billing\"]\npaths = [\"{bill_rule}\"]\n"
    );
    let tip1 = set_rules(&hub, &p, &rules_toml);

    let admin_tok = p.admin.token();
    let dev_tok = p.dev.token();
    let fin_tok = p.fin.token();

    // 1a. A non-admin (`dev`, who cannot read `BILL_DIR/`) cannot mint a runner
    // session narrowed to `BILL_DIR/`.
    let bad_grant = ci_session(&hub, Some(&dev_tok), &json!({"project": p.name, "check": "ci/billing"}));
    assert_eq!(bad_grant.status, 403, "{}", body(&bad_grant));

    // 1b. Mint `ci/src` runner from `dev` (auto-narrowed from `.veilrules` to `["src"]`)
    // and `ci/billing` runner from `fin` (auto-narrowed to `[BILL_DIR]`).
    let src_sess = ci_session(&hub, Some(&dev_tok), &json!({"project": p.name, "check": "ci/src"}));
    assert_eq!(src_sess.status, 200, "{}", body(&src_sess));
    assert_eq!(src_sess.json()["only"], json!(["src"]));
    assert_eq!(src_sess.json()["runner"], json!(true));
    let src_runner = src_sess.json()["token"].as_str().unwrap().to_string();

    let bill_sess = ci_session(&hub, Some(&fin_tok), &json!({"project": p.name, "check": "ci/billing"}));
    assert_eq!(bill_sess.status, 200, "{}", body(&bill_sess));
    assert_eq!(bill_sess.json()["only"], json!([BILL_DIR]));
    assert_eq!(bill_sess.json()["runner"], json!(true));
    let bill_runner = bill_sess.json()["token"].as_str().unwrap().to_string();

    // Also mint a runner from `admin` narrowed to `BILL_DIR/` — even though
    // `admin` can read everything, the runner session can only read `BILL_DIR/`.
    let admin_bill_sess = ci_session(
        &hub,
        Some(&admin_tok),
        &json!({"project": p.name, "only": [bill_rule]}),
    );
    assert_eq!(admin_bill_sess.status, 200, "{}", body(&admin_bill_sess));
    let admin_bill_runner = admin_bill_sess.json()["token"].as_str().unwrap().to_string();

    // 1c. The runner narrowed to `src` can read `src/lib.rs`, but is refused on
    // `{BILL_DIR}/acme/invoice.txt` and `ROOT_FILE`.
    let ok_file = hub
        .api()
        .get(Some(&src_runner), &format!("/v1/projects/{}/q/file?path=src/lib.rs", p.name));
    assert_eq!(ok_file.status, 200, "{}", body(&ok_file));
    let bill_file = format!("{BILL_DIR}/acme/invoice.txt");
    for forbidden_path in [bill_file.as_str(), ROOT_FILE] {
        let r = hub
            .api()
            .get(Some(&src_runner), &format!("/v1/projects/{}/q/file?path={forbidden_path}", p.name));
        assert_eq!(r.status, 403, "{forbidden_path}: {}", body(&r));
    }
    // And the admin-minted runner narrowed to `BILL_DIR` cannot read `src/lib.rs`
    // or `ROOT_FILE`!
    for forbidden_path in ["src/lib.rs", ROOT_FILE] {
        let r = hub.api().get(
            Some(&admin_bill_runner),
            &format!("/v1/projects/{}/q/file?path={forbidden_path}", p.name),
        );
        assert_eq!(r.status, 403, "admin_bill_runner on {forbidden_path}: {}", body(&r));
    }

    // 1d. A runner cannot upload objects, push, create changes, move any branch,
    // or land anything.
    let tip_before = tip(&hub, &admin_tok, &p.name);
    assert_eq!(tip_before, tip1);

    let r_change = change(
        &hub,
        &src_runner,
        &p.name,
        &json!({
            "base": tip1.hex(),
            "description": "runner tries to commit",
            "onto": {"branch": "main", "expected": tip1.hex()},
            "edits": [{"path": "src/lib.rs", "put": {"text": "hacked"}}]
        }),
    );
    assert_eq!(
        (r_change.status, r_change.json()["code"].clone(), r_change.json()["message"].clone()),
        (403, json!("agent_session"), json!(RUNNER_REFUSAL)),
        "{}",
        body(&r_change)
    );

    let r_land = land(
        &hub,
        &src_runner,
        &p.name,
        &json!({"branch": "main", "changes": []}),
    );
    assert_eq!(
        (r_land.status, r_land.json()["code"].clone(), r_land.json()["message"].clone()),
        (403, json!("agent_session"), json!(RUNNER_REFUSAL)),
        "{}",
        body(&r_land)
    );

    let r_push = hub.api().post_json(
        Some(&src_runner),
        &format!("/v1/projects/{}/push", p.name),
        &json!({"snapshots": [], "branches": [{"name": "main", "old": tip1.hex(), "new": tip1.hex()}]}),
    );
    assert_eq!(
        (r_push.status, r_push.json()["code"].clone(), r_push.json()["message"].clone()),
        (403, json!("agent_session"), json!(RUNNER_REFUSAL)),
        "{}",
        body(&r_push)
    );

    let r_obj = hub.api().upload_body(&src_runner, &p.name, &[0u8; 8]);
    assert_eq!(
        (r_obj.status, r_obj.json()["code"].clone(), r_obj.json()["message"].clone()),
        (403, json!("agent_session"), json!(RUNNER_REFUSAL)),
        "{}",
        body(&r_obj)
    );

    assert_eq!(tip(&hub, &admin_tok, &p.name), tip1, "branch did not move");

    // 1e. Both runners report check results on their view of `main`:
    // `src_runner` reports `ci/src` (public path `src`), and `bill_runner`
    // reports `ci/billing` (private path `BILL_DIR`, quoting a billing detail in
    // its summary and log).
    let dev_tip = tip(&hub, &dev_tok, &p.name);
    let fin_tip = tip(&hub, &fin_tok, &p.name);

    let r1 = post_check(
        &hub,
        Some(&src_runner),
        &p.name,
        &json!({
            "snapshot": dev_tip.hex(),
            "name": "ci/src",
            "state": "pass",
            "summary": "src tests ok",
            "log": "running 12 src tests... ok"
        }),
    );
    assert_eq!(r1.status, 200, "{}", body(&r1));

    let r2 = post_check(
        &hub,
        Some(&bill_runner),
        &p.name,
        &json!({
            "snapshot": fin_tip.hex(),
            "name": "ci/billing",
            "state": "pass",
            "summary": "SECRET-BILLING-SUMMARY-991",
            "url": "https://ci.internal/SECRET-BILLING-URL-992",
            "log": "SECRET-BILLING-LOG-993"
        }),
    );
    assert_eq!(r2.status, 200, "{}", body(&r2));

    // Also an un-narrowed admin posts an internal check `ci/internal`:
    let r3 = post_check(
        &hub,
        Some(&admin_tok),
        &p.name,
        &json!({
            "snapshot": tip1.hex(),
            "name": "ci/internal",
            "state": "pass",
            "summary": "SECRET-INTERNAL-ADMIN-994",
            "log": "SECRET-INTERNAL-LOG-995"
        }),
    );
    assert_eq!(r3.status, 200, "{}", body(&r3));

    // Check what each reader sees:
    // - `dev` (and anonymous) sees ONLY `ci/src` (never `ci/billing` or `ci/internal`),
    //   and the snapshot id in `ci/src` is `dev_tip` (never `tip1` or `fin_tip`).
    for (label, tok) in [("dev", Some(dev_tok.as_str())), ("anon", None)] {
        let res = get_checks(&hub, tok, &p.name, None);
        assert_eq!(res.status, 200, "{label}: {}", body(&res));
        let text = body(&res);
        assert!(!text.contains("SECRET-BILLING"), "{label} leaked billing check: {text}");
        assert!(!text.contains("SECRET-INTERNAL"), "{label} leaked internal check: {text}");
        assert!(!text.contains(&tip1.hex()), "{label} leaked real snapshot id: {text}");
        assert!(!text.contains(&fin_tip.hex()), "{label} leaked fin snapshot id: {text}");
        let checks = res.json()["checks"].as_array().unwrap().clone();
        assert_eq!(checks.len(), 1, "{label}: {checks:?}");
        assert_eq!(checks[0]["name"], "ci/src");
        assert_eq!(checks[0]["snapshot"], dev_tip.hex());
    }

    // - `fin` sees `ci/src` (public) and `ci/billing` (finance), with `fin_tip`
    //   as the snapshot id, and never `ci/internal` or `tip1`.
    let fin_res = get_checks(&hub, Some(&fin_tok), &p.name, None);
    assert_eq!(fin_res.status, 200, "{}", body(&fin_res));
    let fin_text = body(&fin_res);
    assert!(!fin_text.contains("SECRET-INTERNAL"), "fin leaked internal check: {fin_text}");
    assert!(!fin_text.contains(&tip1.hex()), "fin leaked real snapshot id: {fin_text}");
    let fin_names: Vec<String> = fin_res.json()["checks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(fin_names, vec!["ci/billing", "ci/src"]);

    // - `admin` sees all three (`ci/billing`, `ci/internal`, `ci/src`).
    let adm_res = get_checks(&hub, Some(&admin_tok), &p.name, None);
    assert_eq!(adm_res.status, 200, "{}", body(&adm_res));
    let adm_names: Vec<String> = adm_res.json()["checks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(adm_names, vec!["ci/billing", "ci/internal", "ci/src"]);
}

/// Guarantee 2: `main@tested` only ever moves to a tip whose required checks
/// all passed, never backwards, and correctly across two servers and restarts.
#[test]
fn main_at_tested_moves_only_forward_when_required_checks_pass_across_servers_and_restarts() {
    let hub1 = TestHub::start();
    let hub2 = TestHub::beside(&hub1);
    let p = setup_project(&hub1);
    let admin = p.admin.token();

    // Configure `.veilrules` requiring BOTH `ci/build` and `ci/test` on `main`.
    let s1 = set_rules(
        &hub1,
        &p,
        "[branches.main]\nrequired_checks = [\"ci/build\", \"ci/test\"]\n\n[checks.\"ci/build\"]\npaths = [\"src/\"]\n\n[checks.\"ci/test\"]\npaths = [\"src/\"]\n",
    );

    // Before required checks pass, `main@tested` is 404 on both servers.
    assert_eq!(get_tested(&hub1, Some(&admin), &p.name, "main").status, 404);
    assert_eq!(get_tested(&hub2, Some(&admin), &p.name, "main").status, 404);

    // Land S2 and S3 on `main` before CI finishes testing S1.
    let r2 = change(
        &hub1,
        &admin,
        &p.name,
        &json!({
            "base": s1.hex(),
            "description": "commit s2",
            "onto": {"branch": "main", "expected": s1.hex()},
            "edits": [{"path": "src/lib.rs", "put": {"text": "pub fn v() -> u32 { 2 }\n"}}]
        }),
    );
    assert_eq!(r2.status, 200, "{}", body(&r2));
    let s2 = ObjectId::from_hex(r2.json()["snapshot"].as_str().unwrap()).unwrap();

    let r3 = change(
        &hub1,
        &admin,
        &p.name,
        &json!({
            "base": s2.hex(),
            "description": "commit s3",
            "onto": {"branch": "main", "expected": s2.hex()},
            "edits": [{"path": "src/lib.rs", "put": {"text": "pub fn v() -> u32 { 3 }\n"}}]
        }),
    );
    assert_eq!(r3.status, 200, "{}", body(&r3));
    let s3 = ObjectId::from_hex(r3.json()["snapshot"].as_str().unwrap()).unwrap();

    // Passing only `ci/build` on S1 does NOT advance `main@tested`.
    let r = post_check(
        &hub1,
        Some(&admin),
        &p.name,
        &json!({"snapshot": s1.hex(), "name": "ci/build", "state": "pass"}),
    );
    assert_eq!(r.status, 200, "{}", body(&r));
    assert_eq!(get_tested(&hub1, Some(&admin), &p.name, "main").status, 404);

    // Failing `ci/test` on S1 does NOT advance `main@tested`.
    let r = post_check(
        &hub1,
        Some(&admin),
        &p.name,
        &json!({"snapshot": s1.hex(), "name": "ci/test", "state": "fail"}),
    );
    assert_eq!(r.status, 200, "{}", body(&r));
    assert_eq!(get_tested(&hub1, Some(&admin), &p.name, "main").status, 404);

    // Now `ci/build` passes on S2 (on hub1) and `ci/test` passes on S2 (on hub2!):
    // `main@tested` advances to S2 on both servers.
    let r = post_check(
        &hub1,
        Some(&admin),
        &p.name,
        &json!({"snapshot": s2.hex(), "name": "ci/build", "state": "pass"}),
    );
    assert_eq!(r.status, 200, "{}", body(&r));
    let r = post_check(
        &hub2,
        Some(&admin),
        &p.name,
        &json!({"snapshot": s2.hex(), "name": "ci/test", "state": "pass"}),
    );
    assert_eq!(r.status, 200, "{}", body(&r));

    for h in [&hub1, &hub2] {
        let t = get_tested(h, Some(&admin), &p.name, "main");
        assert_eq!(t.status, 200, "{}", body(&t));
        assert_eq!(t.json()["snapshot"], s2.hex());
    }

    // Now a late runner reports `ci/test = pass` on S1 (an older ancestor of S2),
    // and `ci/build = pass`, `ci/test = fail` on S3 (newer, but incomplete):
    // `main@tested` MUST NEVER move backwards to S1 or forwards to S3; it stays at S2!
    let r = post_check(
        &hub1,
        Some(&admin),
        &p.name,
        &json!({"snapshot": s1.hex(), "name": "ci/test", "state": "pass"}),
    );
    assert_eq!(r.status, 200, "{}", body(&r));
    let r = post_check(
        &hub1,
        Some(&admin),
        &p.name,
        &json!({"snapshot": s3.hex(), "name": "ci/build", "state": "pass"}),
    );
    assert_eq!(r.status, 200, "{}", body(&r));
    let r = post_check(
        &hub1,
        Some(&admin),
        &p.name,
        &json!({"snapshot": s3.hex(), "name": "ci/test", "state": "fail"}),
    );
    assert_eq!(r.status, 200, "{}", body(&r));

    for h in [&hub1, &hub2] {
        let t = get_tested(h, Some(&admin), &p.name, "main");
        assert_eq!(t.status, 200, "{}", body(&t));
        assert_eq!(t.json()["snapshot"], s2.hex(), "must stay at S2, never move back to S1 or forward to failing S3");
    }

    // Restart hub2 (`restart` on the same DB/object store): `main@tested`
    // is persisted in Postgres and still S2; when `ci/test` finally passes on S3
    // against the restarted server, `main@tested` advances to S3 everywhere.
    let hub2 = hub2.restart(|_| {});
    let t = get_tested(&hub2, Some(&admin), &p.name, "main");
    assert_eq!(t.status, 200, "{}", body(&t));
    assert_eq!(t.json()["snapshot"], s2.hex());

    let r = post_check(
        &hub2,
        Some(&admin),
        &p.name,
        &json!({"snapshot": s3.hex(), "name": "ci/test", "state": "pass"}),
    );
    assert_eq!(r.status, 200, "{}", body(&r));

    for h in [&hub1, &hub2] {
        let t = get_tested(h, Some(&admin), &p.name, "main");
        assert_eq!(t.status, 200, "{}", body(&t));
        assert_eq!(t.json()["snapshot"], s3.hex());
        // Query API resolves `main@tested` too.
        let qr = h
            .api()
            .get(Some(&admin), &format!("/v1/projects/{}/q/resolve?rev=main@tested", p.name));
        assert_eq!(qr.status, 200, "{}", body(&qr));
        assert_eq!(qr.json()["id"], s3.hex());
    }
}

/// Guarantee 3: A failing or absent runner never blocks landings;
/// `main@tested` just stays put.
#[test]
fn failing_or_absent_runner_never_blocks_landings_and_tested_stays_put() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let admin = p.admin.token();
    let dev = p.dev.token();

    // Protect `main` and require `ci/test`.
    let s1 = set_rules(
        &hub,
        &p,
        "[branches.main]\nprotected = true\nrequired_checks = [\"ci/test\"]\n\n[checks.\"ci/test\"]\npaths = [\"src/\"]\n",
    );

    // Mark S1 as passing `ci/test` so `main@tested` starts at S1.
    let r = post_check(
        &hub,
        Some(&admin),
        &p.name,
        &json!({"snapshot": s1.hex(), "name": "ci/test", "state": "pass"}),
    );
    assert_eq!(r.status, 200, "{}", body(&r));
    let dev_s1 = tip(&hub, &dev, &p.name);
    assert_eq!(get_tested(&hub, Some(&dev), &p.name, "main").json()["snapshot"], dev_s1.hex());

    // Land change 1 via `/changes` onto protected `main`, and report `ci/test = fail` on it.
    let c1 = change(
        &hub,
        &dev,
        &p.name,
        &json!({
            "base": dev_s1.hex(),
            "description": "landing 1 (breaks ci)",
            "onto": {"branch": "main", "expected": "rebase"},
            "edits": [{"path": "src/a.rs", "put": {"text": "pub fn a() {}\n"}}]
        }),
    );
    assert_eq!(c1.status, 200, "{}", body(&c1));
    assert_eq!(c1.json()["branch"]["status"], "ok", "{}", body(&c1));
    let dev_s2 = ObjectId::from_hex(c1.json()["snapshot"].as_str().unwrap()).unwrap();

    let rf = post_check(
        &hub,
        Some(&dev),
        &p.name,
        &json!({"snapshot": dev_s2.hex(), "name": "ci/test", "state": "fail", "summary": "broken test"}),
    );
    assert_eq!(rf.status, 200, "{}", body(&rf));

    // Even with `ci/test` failing on `main`'s tip and no runner reporting on
    // subsequent commits, landings continue to succeed without waiting for CI!
    let c2 = change(
        &hub,
        &dev,
        &p.name,
        &json!({
            "base": dev_s2.hex(),
            "description": "landing 2 (runner absent)",
            "onto": {"branch": "main", "expected": "rebase"},
            "edits": [{"path": "src/b.rs", "put": {"text": "pub fn b() {}\n"}}]
        }),
    );
    assert_eq!(c2.status, 200, "{}", body(&c2));
    assert_eq!(c2.json()["branch"]["status"], "ok", "{}", body(&c2));
    let dev_s3 = ObjectId::from_hex(c2.json()["snapshot"].as_str().unwrap()).unwrap();

    // `main` moved forward to `dev_s3`, while `main@tested` stayed put at `dev_s1`.
    assert_eq!(tip(&hub, &dev, &p.name), dev_s3);
    let tested = get_tested(&hub, Some(&dev), &p.name, "main");
    assert_eq!(tested.status, 200, "{}", body(&tested));
    assert_eq!(tested.json()["snapshot"], dev_s1.hex());
}

/// Guarantee 4: Agents start from `main@tested` by default, and a person can
/// still choose another base.
#[test]
fn agents_and_workspaces_start_from_main_at_tested_by_default_and_person_can_choose_base() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let dev = p.dev.token();

    // Configure `.veilrules` requiring `ci/test` on `main`.
    let _s1 = set_rules(
        &hub,
        &p,
        "[branches.main]\nrequired_checks = [\"ci/test\"]\n\n[checks.\"ci/test\"]\npaths = [\"src/\"]\n",
    );

    // Commit S2 (good, passes CI) and S3 (untested, modifies `src/untested.rs`).
    let dev_s1 = tip(&hub, &dev, &p.name);
    let c2 = change(
        &hub,
        &dev,
        &p.name,
        &json!({
            "base": dev_s1.hex(),
            "description": "s2 tested commit",
            "onto": {"branch": "main", "expected": "rebase"},
            "edits": [{"path": "src/tested.rs", "put": {"text": "pub const TESTED: bool = true;\n"}}]
        }),
    );
    assert_eq!(c2.status, 200, "{}", body(&c2));
    let dev_s2 = ObjectId::from_hex(c2.json()["snapshot"].as_str().unwrap()).unwrap();

    let pass = post_check(
        &hub,
        Some(&dev),
        &p.name,
        &json!({"snapshot": dev_s2.hex(), "name": "ci/test", "state": "pass"}),
    );
    assert_eq!(pass.status, 200, "{}", body(&pass));

    let c3 = change(
        &hub,
        &dev,
        &p.name,
        &json!({
            "base": dev_s2.hex(),
            "description": "s3 untested commit",
            "onto": {"branch": "main", "expected": "rebase"},
            "edits": [{"path": "src/untested.rs", "put": {"text": "pub const UNTESTED: bool = true;\n"}}]
        }),
    );
    assert_eq!(c3.status, 200, "{}", body(&c3));
    let dev_s3 = ObjectId::from_hex(c3.json()["snapshot"].as_str().unwrap()).unwrap();
    assert_ne!(dev_s2, dev_s3);

    // 4a. `POST /v1/sessions/agent` returns `tested: Some(dev_s2)`.
    let sess = hub.api().post_json(
        Some(&dev),
        "/v1/sessions/agent",
        &json!({"project": p.name, "attribution": {"agent": "claude-code"}}),
    );
    assert_eq!(sess.status, 200, "{}", body(&sess));
    assert_eq!(sess.json()["tested"], json!(dev_s2.hex()));
    let agent_tok = sess.json()["token"].as_str().unwrap().to_string();

    // 4b. An API change created without `base` defaults to `main@tested` (`dev_s2`)!
    let agent_change = change(
        &hub,
        &agent_tok,
        &p.name,
        &json!({
            "description": "agent change from default base",
            "edits": [{"path": "src/agent_work.rs", "put": {"text": "pub fn work() {}\n"}}]
        }),
    );
    assert_eq!(agent_change.status, 200, "{}", body(&agent_change));
    let agent_snap = agent_change.json()["snapshot"].as_str().unwrap().to_string();
    let show = hub
        .api()
        .get(Some(&dev), &format!("/v1/projects/{}/q/show?rev={agent_snap}", p.name));
    assert_eq!(show.status, 200, "{}", body(&show));
    assert_eq!(show.json()["parents"], json!([dev_s2.hex()]), "agent change parent is main@tested");

    // 4c. In a local clone (`dev_dir`), `vl clone` / `vl pull` fetches `main` (`dev_s3`)
    // and records `origin/main@tested` (`dev_s2`).
    let dev_dir = p.dev.dir("dev-clone");
    p.dev.clone_trusting(&hub.url(&p.name), &dev_dir, &p.fp);

    // `vl ws new agent-ws` (no `-r`) starts from `main@tested` (`dev_s2`),
    // whereas `vl ws new person-ws -r main` starts from `main` (`dev_s3`)!
    p.dev.ok(&dev_dir, &["ws", "new", "agent-ws"]);
    p.dev.ok(&dev_dir, &["ws", "cat", "agent-ws", "src/tested.rs"]);
    p.dev.fails(&dev_dir, &["ws", "cat", "agent-ws", "src/untested.rs"]);

    p.dev.ok(&dev_dir, &["ws", "new", "person-ws", "-r", "main"]);
    p.dev.ok(&dev_dir, &["ws", "cat", "person-ws", "src/untested.rs"]);
}

/// Guarantee 5: Results and their logs are bounded per tip and per runner.
#[test]
fn check_results_and_logs_are_bounded_per_tip_and_per_runner() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let admin = p.admin.token();
    let s0 = tip(&hub, &admin, &p.name);

    // 5a. Per-result bounds: oversized check name, summary, URL, or log (> 64 KiB)
    // and control characters are rejected with 400 `bad_request`.
    for bad in [
        json!({"snapshot": s0.hex(), "name": "", "state": "pass"}),
        json!({"snapshot": s0.hex(), "name": "a".repeat(MAX_CHECK_NAME + 1), "state": "pass"}),
        json!({"snapshot": s0.hex(), "name": "../evil", "state": "pass"}),
        json!({"snapshot": s0.hex(), "name": "ci/ok", "state": "pass", "summary": "s".repeat(MAX_SUMMARY_BYTES + 1)}),
        json!({"snapshot": s0.hex(), "name": "ci/ok", "state": "pass", "summary": "bad\u{1b}[2J"}),
        json!({"snapshot": s0.hex(), "name": "ci/ok", "state": "pass", "url": "https://example.com/".to_string() + &"u".repeat(MAX_URL_BYTES)}),
        json!({"snapshot": s0.hex(), "name": "ci/ok", "state": "pass", "url": "javascript:alert(1)"}),
        json!({"snapshot": s0.hex(), "name": "ci/ok", "state": "pass", "log": "l".repeat(MAX_LOG_BYTES + 1)}),
        json!({"snapshot": s0.hex(), "name": "ci/ok", "state": "pass", "log": "null\0byte"}),
    ] {
        let r = post_check(&hub, Some(&admin), &p.name, &bad);
        assert_eq!(
            (r.status, r.json()["code"].clone()),
            (400, json!("bad_request")),
            "{}: {}",
            bad["name"],
            body(&r)
        );
    }

    // 5b. Per-tip log bound (`MAX_TIP_LOG_BYTES = 256 KiB`) and per-runner-per-tip
    // check count bound (`MAX_RUNNER_CHECKS_PER_SNAPSHOT = 32`), and per-tip
    // total check count bound (`MAX_CHECKS_PER_SNAPSHOT = 64`).
    // Post 5 checks on `s0` each with a 64 KiB log (5 * 64 KiB = 320 KiB > 256 KiB):
    // the oldest check's log is trimmed to `None` so total logs on `s0` stay <= 256 KiB.
    let big_log = "x".repeat(MAX_LOG_BYTES);
    for i in 0..5 {
        let r = post_check(
            &hub,
            Some(&admin),
            &p.name,
            &json!({
                "snapshot": s0.hex(),
                "name": format!("ci/log-{i:02}"),
                "state": "pass",
                "log": big_log
            }),
        );
        assert_eq!(r.status, 200, "{}", body(&r));
    }
    let checks_on_s0 = get_checks(&hub, Some(&admin), &p.name, Some(&s0.hex()));
    assert_eq!(checks_on_s0.status, 200, "{}", body(&checks_on_s0));
    let list = checks_on_s0.json()["checks"].as_array().unwrap().clone();
    let total_tip_log_bytes: usize = list
        .iter()
        .filter_map(|c| c.get("log").and_then(Value::as_str).map(str::len))
        .sum();
    assert!(
        total_tip_log_bytes <= MAX_TIP_LOG_BYTES,
        "tip log bytes {total_tip_log_bytes} exceeded MAX_TIP_LOG_BYTES ({MAX_TIP_LOG_BYTES})"
    );
    assert_eq!(total_tip_log_bytes, 4 * MAX_LOG_BYTES);

    // Fill up to 32 checks from `admin` on `s0`: the 33rd check from `admin` on
    // `s0` is rejected, while updating an existing check on `s0` still succeeds!
    for i in 5..32 {
        let r = post_check(
            &hub,
            Some(&admin),
            &p.name,
            &json!({"snapshot": s0.hex(), "name": format!("ci/adm-{i:02}"), "state": "pass"}),
        );
        assert_eq!(r.status, 200, "i={i}: {}", body(&r));
    }
    let over_runner_tip = post_check(
        &hub,
        Some(&admin),
        &p.name,
        &json!({"snapshot": s0.hex(), "name": "ci/adm-overflow", "state": "pass"}),
    );
    assert_eq!(over_runner_tip.status, 400, "{}", body(&over_runner_tip));

    // Updating an existing check on `s0` succeeds.
    let update_existing = post_check(
        &hub,
        Some(&admin),
        &p.name,
        &json!({"snapshot": s0.hex(), "name": "ci/adm-05", "state": "fail", "summary": "updated"}),
    );
    assert_eq!(update_existing.status, 200, "{}", body(&update_existing));

    // `dev` can post another 32 checks on `s0` (reaching `MAX_CHECKS_PER_SNAPSHOT = 64`),
    // after which a third runner (`fin`) cannot add a 65th distinct check on `s0`.
    let dev = p.dev.token();
    let dev_s0 = tip(&hub, &dev, &p.name);
    for i in 0..32 {
        let r = post_check(
            &hub,
            Some(&dev),
            &p.name,
            &json!({"snapshot": dev_s0.hex(), "name": format!("ci/dev-{i:02}"), "state": "pass"}),
        );
        assert_eq!(r.status, 200, "dev i={i}: {}", body(&r));
    }
    let fin = p.fin.token();
    let fin_s0 = tip(&hub, &fin, &p.name);
    let over_tip = post_check(
        &hub,
        Some(&fin),
        &p.name,
        &json!({"snapshot": fin_s0.hex(), "name": "ci/fin-65th", "state": "pass"}),
    );
    assert_eq!(over_tip.status, 400, "{}", body(&over_tip));
    assert!(
        body(&over_tip).contains(&MAX_CHECKS_PER_SNAPSHOT.to_string()),
        "{}",
        body(&over_tip)
    );

    // 5c. Per-runner total log bound (`MAX_RUNNER_LOG_BYTES = 1 MiB`) and
    // per-runner total check count bound (`MAX_RUNNER_CHECKS = 256`) across
    // snapshots: create 9 snapshots, post 30 checks per snapshot from `admin`
    // (270 total > 256, with 20 * 64 KiB > 1 MiB of logs), and verify the
    // database retains at most `MAX_RUNNER_CHECKS` rows and at most
    // `MAX_RUNNER_LOG_BYTES` of logs for that runner.
    let mut cur = s0;
    for s_idx in 0..9 {
        let c = change(
            &hub,
            &admin,
            &p.name,
            &json!({
                "base": cur.hex(),
                "description": format!("snap {s_idx}"),
                "onto": {"branch": "main", "expected": cur.hex()},
                "edits": [{"path": "src/lib.rs", "put": {"text": format!("pub const S: usize = {s_idx};\n")}}]
            }),
        );
        assert_eq!(c.status, 200, "{}", body(&c));
        cur = ObjectId::from_hex(c.json()["snapshot"].as_str().unwrap()).unwrap();
        for c_idx in 0..30 {
            let with_log = s_idx < 5 && c_idx < 4;
            let r = post_check(
                &hub,
                Some(&admin),
                &p.name,
                &json!({
                    "snapshot": cur.hex(),
                    "name": format!("ci/r-{c_idx:02}"),
                    "state": "pass",
                    "log": if with_log { Some(big_log.as_str()) } else { None }
                }),
            );
            assert_eq!(r.status, 200, "s={s_idx} c={c_idx}: {}", body(&r));
        }
    }

    let db = hub.hub().db.clone();
    let (runner_rows, runner_log_bytes): (i64, i64) = hub.rt.block_on(async {
        sqlx::query_as(
            "SELECT COUNT(*), COALESCE(SUM(LENGTH(log)), 0)::BIGINT FROM checks WHERE runner_name = $1",
        )
        .bind(&p.admin.name)
        .fetch_one(&db)
        .await
        .unwrap()
    });
    assert!(
        runner_rows <= MAX_RUNNER_CHECKS as i64,
        "runner rows {runner_rows} exceeded MAX_RUNNER_CHECKS ({MAX_RUNNER_CHECKS})"
    );
    assert_eq!(runner_rows, MAX_RUNNER_CHECKS as i64);
    assert!(
        runner_log_bytes <= MAX_RUNNER_LOG_BYTES as i64,
        "runner log bytes {runner_log_bytes} exceeded MAX_RUNNER_LOG_BYTES ({MAX_RUNNER_LOG_BYTES})"
    );
    assert_eq!(runner_log_bytes, MAX_RUNNER_LOG_BYTES as i64);
}
