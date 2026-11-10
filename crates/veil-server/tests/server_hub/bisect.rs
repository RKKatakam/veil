//! Milestone S20 on the server (`docs/HUB.md` §13.36;
//! `docs/design/server/phase-4-agent-scale.md` §4.8, §4.9):
//! automatic bisect and revert when `<branch>@tested` stops advancing.
//!
//! Guarantees, each a test here:
//! 1. Bisect finds the first landing whose tests fail, using the same CI
//!    runners and check results as S19. Its work is bounded (log₂ of the
//!    landings), and it never needs a check result a runner can't produce.
//! 2. A revert is itself a landing through S17 (`landing::agent_stack` doesn't
//!    apply: the server acts, not an agent). It's attributed to the server with
//!    the culprit named. It reverts exactly the culprit's edits, never another
//!    change's, and only on a protected branch whose rules allow automatic
//!    revert.
//! 3. Only a confirmed culprit is reverted: its failure reproduces on a re-run,
//!    and its parent passes. A flaky check never reverts anything.
//! 4. Nothing hidden leaks: a revert, its message and its events name only what
//!    each viewer can see (`docs/VISIBILITY.md`), and an embargoed change is
//!    never reverted into the public before its release.
//! 5. Bounded and safe across two servers and restarts: one bisect per branch
//!    at a time, and a revert lands at most once.

use std::time::Duration;

use serde_json::{json, Value};
use veil_core::ObjectId;

use crate::support::*;

fn body(r: &Reply) -> String {
    String::from_utf8_lossy(&r.body).into_owned()
}

fn ci_session(hub: &TestHub, token: Option<&str>, req: &Value) -> Reply {
    hub.api().post_json(token, "/v1/sessions/ci", req)
}

fn post_check(hub: &TestHub, token: Option<&str>, project: &str, req: &Value) -> Reply {
    hub.api().post_json(token, &format!("/v1/projects/{project}/checks"), req)
}

fn get_bisect(hub: &TestHub, token: Option<&str>, project: &str, branch: &str) -> Reply {
    hub.api().get(token, &format!("/v1/projects/{project}/bisect/{branch}"))
}

fn change(hub: &TestHub, token: &str, project: &str, req: &Value) -> Reply {
    hub.api().post_json(Some(token), &format!("/v1/projects/{project}/changes"), req)
}

fn land_req(hub: &TestHub, token: &str, project: &str, req: &Value) -> Reply {
    hub.api().post_json(Some(token), &format!("/v1/projects/{project}/land"), req)
}

fn tip(hub: &TestHub, token: &str, project: &str) -> ObjectId {
    hub.api().tips(Some(token), project).unwrap().branches["main"]
}

fn set_rules(hub: &TestHub, p: &Project, rules_toml: &str) -> ObjectId {
    let admin = p.admin.token();
    land_edit(hub, p, &admin, ".veilrules", rules_toml, "configure .veilrules").0
}

fn land_edit(hub: &TestHub, p: &Project, token: &str, path: &str, text: &str, desc: &str) -> (ObjectId, String) {
    let base = tip(hub, token, &p.name);
    let c = change(
        hub,
        token,
        &p.name,
        &json!({
            "base": base.hex(),
            "description": desc,
            "edits": [{"path": path, "put": {"text": text}}]
        }),
    );
    assert_eq!(c.status, 200, "{}", body(&c));
    let sub = c.json()["snapshot"].as_str().unwrap().to_string();
    let cid = c.json()["change_id"].as_str().unwrap().to_string();
    let l = land_req(
        hub,
        token,
        &p.name,
        &json!({
            "onto": "main",
            "snapshot": sub,
            "wait": true
        }),
    );
    assert_eq!(l.status, 200, "{}", body(&l));
    assert_eq!(l.json()["state"], "landed", "{}", body(&l));
    let real_landed = tip(hub, &p.admin.token(), &p.name);
    (real_landed, cid)
}

fn walk_first_parent(hub: &TestHub, token: &str, project: &str, from: ObjectId, stop_at: ObjectId) -> Vec<Value> {
    let mut out = Vec::new();
    let mut cur = from;
    for _ in 0..32 {
        if cur == stop_at {
            break;
        }
        let r = hub.api().get(Some(token), &format!("/v1/projects/{project}/q/show?rev={}", cur.hex()));
        assert_eq!(r.status, 200, "{}", body(&r));
        let j = r.json();
        let next = j["parents"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|v| v.as_str())
            .and_then(|s| ObjectId::from_hex(s).ok());
        out.push(j);
        match next {
            Some(p) => cur = p,
            None => break,
        }
    }
    out
}

fn project_id(hub: &TestHub, name: &str) -> i64 {
    let h = hub.hub();
    hub.rt
        .block_on(sqlx::query_scalar::<_, i64>("SELECT id FROM projects WHERE name = $1").bind(name).fetch_one(&h.db))
        .unwrap()
}

/// Read SSE `(event, data_json)` frames from an open response until `want` events
/// arrive or `timeout` elapses.
fn collect_sse(resp: ureq::http::Response<ureq::Body>, want: usize, timeout: Duration) -> Vec<(String, Value)> {
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

/// Guarantee 1: Bisect finds the first landing whose tests fail, using the same
/// CI runners and check results as S19. Its work is bounded (log₂ of the
/// landings), and it never needs a check result a runner can't produce.
#[test]
fn bisect_finds_first_failing_landing_in_bounded_steps_and_respects_runner_footprint() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let admin_tok = p.admin.token();
    let dev_tok = p.dev.token();
    let fin_tok = p.fin.token();

    let bill_rule = format!("{BILL_DIR}/");
    let rules_toml = format!(
        "[branches.main]\nprotected = true\nrequired_checks = [\"ci/src\"]\n\n\
         [checks.\"ci/src\"]\npaths = [\"src/\"]\n\n\
         [checks.\"ci/billing\"]\npaths = [\"{bill_rule}\"]\n"
    );
    let s0 = set_rules(&hub, &p, &rules_toml);

    // Mint a `ci/src` runner from `dev` (narrowed to `["src"]`).
    let sess = ci_session(&hub, Some(&dev_tok), &json!({"project": p.name, "check": "ci/src"}));
    assert_eq!(sess.status, 200, "{}", body(&sess));
    assert_eq!(sess.json()["only"], json!(["src"]));
    let runner_tok = sess.json()["token"].as_str().unwrap().to_string();

    // Advance `main@tested` to `s0`.
    let runner_s0 = tip(&hub, &runner_tok, &p.name);
    let _ = s0;
    let r0 = post_check(
        &hub,
        Some(&runner_tok),
        &p.name,
        &json!({"snapshot": runner_s0.hex(), "name": "ci/src", "state": "pass"}),
    );
    assert_eq!(r0.status, 200, "{}", body(&r0));

    // Land 8 changes in `src/` (`src_snaps[0..8]`), interleaved with 4 changes
    // in `BILL_DIR/` that the `ci/src` runner cannot read or produce check results for!
    // Suppose `src_snaps[4]` (the 5th `src/` change) introduces the test failure.
    let mut src_snaps = Vec::new();
    let mut runner_src_snaps = Vec::new();
    let mut bill_snaps = Vec::new();
    for i in 0..8 {
        if i % 2 == 0 {
            let bill_file = format!("{BILL_DIR}/acme/note-{i}.txt");
            let (bs, _) = land_edit(&hub, &p, &fin_tok, &bill_file, &format!("bill {i}\n"), &format!("bill {i}"));
            bill_snaps.push(bs);
        }
        let code = if i < 4 {
            format!("pub fn step() -> usize {{ {i} }}\n")
        } else {
            format!("pub fn step() -> usize {{ panic!(\"broken at {i}\") }}\n")
        };
        let (ss, _) = land_edit(&hub, &p, &dev_tok, &format!("src/mod_{i}.rs"), &code, &format!("src {i}"));
        src_snaps.push(ss);
        runner_src_snaps.push(tip(&hub, &runner_tok, &p.name));
    }
    assert_eq!(runner_src_snaps.len(), 8);

    // Open an SSE stream as the runner to observe `check.requested` events.
    let sse_resp = hub.api().get_unread(
        &format!("/v1/projects/{}/events", p.name),
        &[("authorization", &format!("Bearer {runner_tok}"))],
    );
    assert_eq!(sse_resp.status().as_u16(), 200);

    // Runner reports `fail` on the tip (`runner_src_snaps[7]`).
    let fail_tip = post_check(
        &hub,
        Some(&runner_tok),
        &p.name,
        &json!({"snapshot": runner_src_snaps[7].hex(), "name": "ci/src", "state": "fail"}),
    );
    assert_eq!(fail_tip.status, 200, "{}", body(&fail_tip));

    // Check bisect status:
    // 1. Only the 8 `src/` snapshots are candidates — none of `bill_snaps`!
    // 2. It immediately probes a single midpoint (`probes.len() == 1`).
    let st0 = get_bisect(&hub, Some(&runner_tok), &p.name, "main");
    assert_eq!(st0.status, 200, "{}", body(&st0));
    let j0 = st0.json();
    assert_eq!(j0["phase"], "searching", "{j0}");
    assert_eq!(j0["check"], "ci/src", "{j0}");
    let cands: Vec<ObjectId> = j0["candidates"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| ObjectId::from_hex(x.as_str().unwrap()).unwrap())
        .collect();
    assert_eq!(cands, runner_src_snaps, "candidates must be narrowed to `src/` commits only");
    for b in &bill_snaps {
        assert!(!cands.contains(b), "billing commit must never be a candidate for ci/src");
    }

    // Verify the runner received a `check.requested` SSE event for the first midpoint probe.
    let sse_events = collect_sse(sse_resp, 1, Duration::from_secs(3));
    assert_eq!(sse_events.len(), 1, "expected check.requested SSE event: {sse_events:?}");
    assert_eq!(sse_events[0].0, "check.requested");
    assert_eq!(sse_events[0].1["name"], "ci/src");
    assert_eq!(sse_events[0].1["reason"], "bisect");

    // Drive the bisect search phase: count how many probe rounds it takes to reach `confirming`.
    let mut rounds = 0usize;
    loop {
        let st = get_bisect(&hub, Some(&runner_tok), &p.name, "main").json();
        if st["phase"] != "searching" {
            assert_eq!(st["phase"], "confirming", "expected confirming phase: {st}");
            break;
        }
        let probes = st["probes"].as_array().unwrap();
        assert_eq!(probes.len(), 1, "binary bisect probes 1 midpoint at a time: {st}");
        let probe_id = ObjectId::from_hex(probes[0].as_str().unwrap()).unwrap();
        let idx = runner_src_snaps
            .iter()
            .position(|x| *x == probe_id)
            .expect("every probe must be one of the runner's readable `src/` commits");
        let state = if idx < 4 { "pass" } else { "fail" };
        rounds += 1;
        assert!(rounds <= 3, "bisect over 8 candidates must take at most log2(8) = 3 probes (took {rounds})");
        let pr = post_check(
            &hub,
            Some(&runner_tok),
            &p.name,
            &json!({"snapshot": probe_id.hex(), "name": "ci/src", "state": state}),
        );
        assert_eq!(pr.status, 200, "{}", body(&pr));
    }
    assert!(rounds <= 3, "bounded bisect work: took {rounds} rounds for 8 candidates");

    // Verify bisect identified `runner_src_snaps[4]` (the first failing landing) as the culprit!
    let st_conf = get_bisect(&hub, Some(&runner_tok), &p.name, "main").json();
    assert_eq!(st_conf["phase"], "confirming", "{st_conf}");
    assert_eq!(st_conf["culprit"], runner_src_snaps[4].hex(), "{st_conf}");

    // Also verify k-way parallel probing (`parallel = 3`):
    // Enable `parallel = 3` on `ci/src` and advance `main@tested` to that new rules commit.
    let rules_k = "[branches.main]\nprotected = true\nrequired_checks = [\"ci/src\"]\n\n\
                   [checks.\"ci/src\"]\npaths = [\"src/\"]\nparallel = 3\n";
    let sk0 = set_rules(&hub, &p, rules_k);
    let r_sk0 = post_check(
        &hub,
        Some(&admin_tok),
        &p.name,
        &json!({"snapshot": sk0.hex(), "name": "ci/src", "state": "pass"}),
    );
    assert_eq!(r_sk0.status, 200, "{}", body(&r_sk0));

    let mut k_snaps = Vec::new();
    for i in 0..15 {
        let (ks, _) = land_edit(
            &hub,
            &p,
            &dev_tok,
            &format!("src/k_{i}.rs"),
            &format!("pub const K: usize = {i};\n"),
            &format!("k {i}"),
        );
        k_snaps.push(ks);
    }
    // Report fail on tip `k_snaps[14]`: with `parallel = 3`, the first round probes 3 midpoints!
    let fk = post_check(
        &hub,
        Some(&admin_tok),
        &p.name,
        &json!({"snapshot": k_snaps[14].hex(), "name": "ci/src", "state": "fail"}),
    );
    assert_eq!(fk.status, 200, "{}", body(&fk));
    let stk = get_bisect(&hub, Some(&admin_tok), &p.name, "main").json();
    assert_eq!(stk["phase"], "searching", "{stk}");
    assert_eq!(
        stk["probes"].as_array().unwrap().len(),
        3,
        "parallel = 3 must probe 3 evenly-spaced midpoints simultaneously: {stk}"
    );
}

/// Guarantee 2: A revert is itself a landing through S17 (`landing::agent_stack`
/// doesn't apply: the server acts, not an agent). It's attributed to the server
/// with the culprit named. It reverts exactly the culprit's edits, never
/// another change's, and only on a protected branch whose rules allow automatic
/// revert.
#[test]
fn confirmed_culprit_is_reverted_through_s17_priority_lane_server_attributed_and_surgical() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let admin_tok = p.admin.token();
    let dev_tok = p.dev.token();

    // Seed `src/shared.rs` with 5 lines so we can test surgical 3-way content merge revert
    // when a later commit edits a different part of `src/shared.rs`!
    let initial_shared = "line 1: alpha\nline 2: beta\nline 3: gamma\nline 4: delta\nline 5: epsilon\n";
    let _ = land_edit(&hub, &p, &admin_tok, "src/shared.rs", initial_shared, "seed shared.rs");

    // 2a. First verify that when `auto_revert = false` (or branch is unprotected),
    // even a confirmed culprit is NOT reverted.
    let rules_no_revert = "[branches.main]\nprotected = true\nauto_revert = false\nrequired_checks = [\"ci/src\"]\n\n\
                           [checks.\"ci/src\"]\npaths = [\"src/\"]\n";
    let s_norev = set_rules(&hub, &p, rules_no_revert);
    post_check(&hub, Some(&admin_tok), &p.name, &json!({"snapshot": s_norev.hex(), "name": "ci/src", "state": "pass"}));
    let (c_norev, _) = land_edit(&hub, &p, &dev_tok, "src/norev.rs", "broken\n", "broken norev");
    post_check(&hub, Some(&admin_tok), &p.name, &json!({"snapshot": c_norev.hex(), "name": "ci/src", "state": "fail"}));
    post_check(&hub, Some(&admin_tok), &p.name, &json!({"snapshot": c_norev.hex(), "name": "ci/src", "state": "fail"}));
    assert_eq!(
        get_bisect(&hub, Some(&admin_tok), &p.name, "main").status,
        404,
        "branch with auto_revert = false must not start auto-revert bisect"
    );
    assert_eq!(tip(&hub, &admin_tok, &p.name), c_norev, "tip must remain untouched when auto_revert = false");

    // 2b. Now enable protected branch with default `auto_revert = true` and `required_checks = ["ci/src"]`.
    let rules_auto = "[branches.main]\nprotected = true\nrequired_checks = [\"ci/src\"]\n\n\
                      [checks.\"ci/src\"]\npaths = [\"src/\"]\n";
    let _s0 = set_rules(&hub, &p, rules_auto);
    let src_runner = ci_session(&hub, Some(&dev_tok), &json!({"project": p.name, "check": "ci/src"}))
        .json()["token"]
        .as_str()
        .unwrap()
        .to_string();
    let s0_runner = tip(&hub, &src_runner, &p.name);
    let r0 = post_check(
        &hub,
        Some(&src_runner),
        &p.name,
        &json!({"snapshot": s0_runner.hex(), "name": "ci/src", "state": "pass"}),
    );
    assert_eq!(r0.status, 200, "{}", body(&r0));

    // Land `c1` (good: adds `src/good_before.rs`).
    let (c1, _) = land_edit(&hub, &p, &dev_tok, "src/good_before.rs", "pub const GOOD: i32 = 1;\n", "good before");
    let c1_runner = tip(&hub, &src_runner, &p.name);

    // Land `c2` (the culprit! Modifies line 1 of `src/shared.rs` and adds `src/culprit_only.rs`).
    let base_c2 = tip(&hub, &dev_tok, &p.name);
    let culprit_shared = "line 1: CULPRIT BUG\nline 2: beta\nline 3: gamma\nline 4: delta\nline 5: epsilon\n";
    let ch_c2 = change(
        &hub,
        &dev_tok,
        &p.name,
        &json!({
            "base": base_c2.hex(),
            "description": "introduce bug in shared.rs and culprit_only.rs",
            "edits": [
                {"path": "src/shared.rs", "put": {"text": culprit_shared}},
                {"path": "src/culprit_only.rs", "put": {"text": "bad file\n"}}
            ]
        }),
    )
    .json();
    let c2_sub = ch_c2["snapshot"].as_str().unwrap();
    let c2_cid = ch_c2["change_id"].as_str().unwrap().to_string();
    let l_c2 = land_req(&hub, &dev_tok, &p.name, &json!({"onto": "main", "snapshot": c2_sub, "wait": true})).json();
    assert_eq!(l_c2["state"], "landed", "{l_c2}");
    let c2_dev = ObjectId::from_hex(l_c2["landed"][0].as_str().unwrap()).unwrap();
    let c2_runner = tip(&hub, &src_runner, &p.name);
    let c2 = tip(&hub, &admin_tok, &p.name);

    // Land `c3` after `c2`: modifies line 5 of `src/shared.rs` (non-overlapping with line 1!)
    // and adds `src/good_after.rs`.
    let base_c3 = tip(&hub, &dev_tok, &p.name);
    let after_shared = "line 1: CULPRIT BUG\nline 2: beta\nline 3: gamma\nline 4: delta\nline 5: KEPT AFTER\n";
    let ch_c3 = change(
        &hub,
        &dev_tok,
        &p.name,
        &json!({
            "base": base_c3.hex(),
            "description": "good change after culprit",
            "edits": [
                {"path": "src/shared.rs", "put": {"text": after_shared}},
                {"path": "src/good_after.rs", "put": {"text": "pub const AFTER: i32 = 2;\n"}}
            ]
        }),
    )
    .json();
    let c3_sub = ch_c3["snapshot"].as_str().unwrap();
    let l_c3 = land_req(&hub, &dev_tok, &p.name, &json!({"onto": "main", "snapshot": c3_sub, "wait": true})).json();
    assert_eq!(l_c3["state"], "landed", "{l_c3}");
    let c3_runner = tip(&hub, &src_runner, &p.name);

    // Subscribe to SSE events to observe the `reverted` event.
    let sse_resp = hub.api().get_unread(
        &format!("/v1/projects/{}/events", p.name),
        &[("authorization", &format!("Bearer {dev_tok}"))],
    );
    assert_eq!(sse_resp.status().as_u16(), 200);

    // 1. Report `fail` on tip `c3` -> bisect probes `c2`.
    let r = post_check(&hub, Some(&src_runner), &p.name, &json!({"snapshot": c3_runner.hex(), "name": "ci/src", "state": "fail"}));
    assert_eq!(r.status, 200, "{}", body(&r));
    let st1 = get_bisect(&hub, Some(&admin_tok), &p.name, "main").json();
    assert_eq!(st1["phase"], "searching", "{st1}");
    assert_eq!(st1["probes"], json!([c2.hex()]), "{st1}");

    // 2. Report `fail` on `c2` (1st failure on `c2`) -> bisect probes `c1`.
    let r = post_check(&hub, Some(&src_runner), &p.name, &json!({"snapshot": c2_runner.hex(), "name": "ci/src", "state": "fail"}));
    assert_eq!(r.status, 200, "{}", body(&r));
    let st2 = get_bisect(&hub, Some(&admin_tok), &p.name, "main").json();
    assert_eq!(st2["phase"], "searching", "{st2}");
    assert_eq!(st2["probes"], json!([c1.hex()]), "{st2}");

    // 3. Report `pass` on `c1` -> narrows to `c2` (`lo == hi == 1`), enters `confirming`
    // (since `c1` already passed, only `c2`'s confirmation re-run is still needed!).
    let r = post_check(&hub, Some(&src_runner), &p.name, &json!({"snapshot": c1_runner.hex(), "name": "ci/src", "state": "pass"}));
    assert_eq!(r.status, 200, "{}", body(&r));
    let st3 = get_bisect(&hub, Some(&admin_tok), &p.name, "main").json();
    assert_eq!(st3["phase"], "confirming", "{st3}");
    assert_eq!(st3["culprit"], c2.hex(), "{st3}");
    assert_eq!(st3["probes"], json!([c2.hex()]), "{st3}");

    // 4. Report 2nd `fail` on `c2` -> confirms `c2` and lands the surgical revert via S17/S18!
    let r = post_check(&hub, Some(&src_runner), &p.name, &json!({"snapshot": c2_runner.hex(), "name": "ci/src", "state": "fail"}));
    assert_eq!(r.status, 200, "{}", body(&r));

    // Wait briefly if S18 content merge is completing in background.
    let mut st4 = get_bisect(&hub, Some(&admin_tok), &p.name, "main").json();
    for _ in 0..20 {
        if st4["phase"] == "reverted" {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
        st4 = get_bisect(&hub, Some(&admin_tok), &p.name, "main").json();
    }
    assert_eq!(st4["phase"], "reverted", "{st4}");
    assert_eq!(st4["culprit"], c2.hex(), "{st4}");
    assert_eq!(st4["culprit_change_id"], c2_cid, "{st4}");
    let rev_id = ObjectId::from_hex(st4["revert"].as_str().unwrap()).unwrap();
    assert_eq!(tip(&hub, &admin_tok, &p.name), rev_id, "main tip must be the landed revert snapshot");

    // Inspect the revert commit via `q/show`:
    let show = hub
        .api()
        .get(Some(&admin_tok), &format!("/v1/projects/{}/q/show?rev={}", p.name, rev_id.hex()))
        .json();
    assert_eq!(show["author"], "server", "{show}");
    assert_eq!(show["description"], format!("revert {c2_cid}"), "{show}");
    assert_eq!(show["agent"]["agent"], "server/bisect", "{show}");
    assert_eq!(show["agent"]["task"], format!("revert:{c2_cid}"), "{show}");

    // Verify surgical revert:
    // - `src/good_before.rs` (`c1`) is still there.
    // - `src/good_after.rs` (`c3`) is still there.
    // - `src/culprit_only.rs` (`c2`) is deleted.
    // - `src/shared.rs` has line 1 restored to `"line 1: alpha"` AND line 5 kept as `"line 5: KEPT AFTER"`!
    let f_before = hub.api().get(Some(&admin_tok), &format!("/v1/projects/{}/q/file?path=src/good_before.rs", p.name));
    assert_eq!(f_before.status, 200);
    let f_after = hub.api().get(Some(&admin_tok), &format!("/v1/projects/{}/q/file?path=src/good_after.rs", p.name));
    assert_eq!(f_after.status, 200);
    let f_culprit = hub.api().get(Some(&admin_tok), &format!("/v1/projects/{}/q/file?path=src/culprit_only.rs", p.name));
    assert_eq!(f_culprit.status, 404, "culprit_only.rs must be removed by the revert");
    let f_shared = hub.api().get(Some(&admin_tok), &format!("/v1/projects/{}/q/file?path=src/shared.rs", p.name));
    assert_eq!(f_shared.status, 200);
    assert_eq!(
        body(&f_shared),
        "line 1: alpha\nline 2: beta\nline 3: gamma\nline 4: delta\nline 5: KEPT AFTER\n",
        "revert must undo only c2's edit (line 1) while preserving c3's edit (line 5)"
    );

    // Verify the `reverted` SSE event arrived for `dev` and named `dev`'s projected culprit and revert snapshot.
    let dev_rev_id = tip(&hub, &dev_tok, &p.name);
    let events = collect_sse(sse_resp, 10, Duration::from_secs(3));
    let rev_ev = events
        .iter()
        .find(|(ev, _)| ev == "reverted")
        .expect("expected `reverted` SSE event");
    assert_eq!(rev_ev.1["branch"], "main");
    assert_eq!(rev_ev.1["culprit"], c2_dev.hex());
    assert_eq!(rev_ev.1["culprit_change_id"], c2_cid);
    assert_eq!(rev_ev.1["revert"], dev_rev_id.hex());
    assert_eq!(rev_ev.1["check"], "ci/src");
}

/// Guarantee 3: Only a confirmed culprit is reverted: its failure reproduces on
/// a re-run, and its parent passes. A flaky check never reverts anything.
#[test]
fn only_confirmed_culprit_is_reverted_and_flaky_check_never_reverts() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let admin_tok = p.admin.token();
    let dev_tok = p.dev.token();

    let rules_toml = "[branches.main]\nprotected = true\nrequired_checks = [\"ci/src\"]\n\n\
                      [checks.\"ci/src\"]\npaths = [\"src/\"]\n";
    let s0 = set_rules(&hub, &p, rules_toml);
    let r = post_check(&hub, Some(&admin_tok), &p.name, &json!({"snapshot": s0.hex(), "name": "ci/src", "state": "pass"}));
    assert_eq!(r.status, 200, "{}", body(&r));

    // Case A: A single landing `c_flake` fails once, entering `confirming`, and then
    // PASSES on the confirmation re-run -> marked `flaky`, never reverted!
    let (c_flake, _) = land_edit(&hub, &p, &dev_tok, "src/flake1.rs", "pub const F1: i32 = 1;\n", "flake 1");

    let r = post_check(&hub, Some(&admin_tok), &p.name, &json!({"snapshot": c_flake.hex(), "name": "ci/src", "state": "fail"}));
    assert_eq!(r.status, 200, "{}", body(&r));
    let st1 = get_bisect(&hub, Some(&admin_tok), &p.name, "main").json();
    assert_eq!(st1["phase"], "confirming", "1 failure must enter confirming, not revert immediately: {st1}");
    assert_eq!(st1["culprit"], c_flake.hex(), "{st1}");
    assert_eq!(tip(&hub, &admin_tok, &p.name), c_flake, "unconfirmed culprit must not be reverted");

    // Re-run on `c_flake` passes!
    let r = post_check(&hub, Some(&admin_tok), &p.name, &json!({"snapshot": c_flake.hex(), "name": "ci/src", "state": "pass"}));
    assert_eq!(r.status, 200, "{}", body(&r));
    let st2 = get_bisect(&hub, Some(&admin_tok), &p.name, "main").json();
    assert_eq!(st2["phase"], "flaky", "passing confirmation re-run must mark bisect flaky: {st2}");
    assert!(st2["revert"].is_null(), "flaky check must not revert: {st2}");
    assert_eq!(tip(&hub, &admin_tok, &p.name), c_flake, "main tip must still be c_flake");

    // Case B: Two landings `c_p` and `c_c` after `c_flake`: advance `main@tested` to `c_c`,
    // land `c_only` on top of `c_c`, clear `c_c`'s check row so `c_only`'s parent (`c_c`)
    // is untested when `c_only` enters `confirming`, and verify that if `c_c` fails,
    // `c_only` is NOT reverted!
    let (c_p, _) = land_edit(&hub, &p, &dev_tok, "src/parent.rs", "pub const P: i32 = 1;\n", "parent");
    let (c_c, _) = land_edit(&hub, &p, &dev_tok, "src/child.rs", "pub const C: i32 = 2;\n", "child");
    post_check(&hub, Some(&admin_tok), &p.name, &json!({"snapshot": c_p.hex(), "name": "ci/src", "state": "pass"}));
    post_check(&hub, Some(&admin_tok), &p.name, &json!({"snapshot": c_c.hex(), "name": "ci/src", "state": "pass"}));

    let (c_only, _) = land_edit(&hub, &p, &dev_tok, "src/only.rs", "pub const O: i32 = 3;\n", "only");
    // Delete `c_c`'s check result from `checks` so `c_only`'s parent (`c_c`) has to be
    // verified during `confirming`.
    let pid = project_id(&hub, &p.name);
    let h = hub.hub();
    hub.rt.block_on(async {
        sqlx::query("DELETE FROM checks WHERE project_id = $1 AND snapshot = $2")
            .bind(pid)
            .bind(c_c.hex())
            .execute(&h.db)
            .await
            .unwrap();
    });

    // 1st fail on `c_only`: enters `confirming`, probing both `c_only` (needs 2nd fail)
    // and its parent `c_c` (needs a pass).
    let r = post_check(&hub, Some(&admin_tok), &p.name, &json!({"snapshot": c_only.hex(), "name": "ci/src", "state": "fail"}));
    assert_eq!(r.status, 200, "{}", body(&r));
    let st3 = get_bisect(&hub, Some(&admin_tok), &p.name, "main").json();
    assert_eq!(st3["phase"], "confirming", "{st3}");
    assert_eq!(st3["culprit"], c_only.hex(), "{st3}");
    assert_eq!(
        st3["probes"],
        json!([c_c.hex(), c_only.hex()]),
        "confirming must request both culprit re-run and parent pass when parent is untested: {st3}"
    );

    // Even after 2nd fail on `c_only`, it STILL waits for parent `c_c` to pass!
    let r = post_check(&hub, Some(&admin_tok), &p.name, &json!({"snapshot": c_only.hex(), "name": "ci/src", "state": "fail"}));
    assert_eq!(r.status, 200, "{}", body(&r));
    let st4 = get_bisect(&hub, Some(&admin_tok), &p.name, "main").json();
    assert_eq!(st4["phase"], "confirming", "must not revert before parent passes: {st4}");
    assert_eq!(tip(&hub, &admin_tok, &p.name), c_only);

    // Parent `c_c` reports `fail` -> bisect marks `flaky` and does NOT revert `c_only`!
    let r = post_check(&hub, Some(&admin_tok), &p.name, &json!({"snapshot": c_c.hex(), "name": "ci/src", "state": "fail"}));
    assert_eq!(r.status, 200, "{}", body(&r));
    let st5 = get_bisect(&hub, Some(&admin_tok), &p.name, "main").json();
    assert_eq!(st5["phase"], "flaky", "failing parent during confirmation must mark bisect flaky: {st5}");
    assert_eq!(tip(&hub, &admin_tok, &p.name), c_only, "nothing reverted when parent fails");
}

/// Guarantee 4: Nothing hidden leaks: a revert, its message and its events name
/// only what each viewer can see (`docs/VISIBILITY.md`), and an embargoed
/// change is never reverted into the public before its release.
#[test]
fn nothing_hidden_leaks_in_revert_messages_events_or_status_and_embargo_never_reverts_early() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let admin_tok = p.admin.token();
    let dev_tok = p.dev.token();
    let fin_tok = p.fin.token();

    let bill_rule = format!("{BILL_DIR}/");
    let rules_toml = format!(
        "[branches.main]\nprotected = true\nrequired_checks = [\"ci/src\", \"ci/billing\"]\n\n\
         [checks.\"ci/src\"]\npaths = [\"src/\"]\n\n\
         [checks.\"ci/billing\"]\npaths = [\"{bill_rule}\"]\n"
    );
    let s0 = set_rules(&hub, &p, &rules_toml);

    // Mint a `ci/billing` runner from `fin` (narrowed to `[BILL_DIR]`).
    let bill_sess = ci_session(&hub, Some(&fin_tok), &json!({"project": p.name, "check": "ci/billing"}));
    assert_eq!(bill_sess.status, 200, "{}", body(&bill_sess));
    let bill_runner = bill_sess.json()["token"].as_str().unwrap().to_string();

    // Advance `main@tested` to `s0` by passing both required checks.
    // Note: `s0` only edited `.veilrules`, so for `bill_runner` (narrowed to `[BILL_DIR]`)
    // we also pass `ci/billing` via `fin_tok` on `fin`'s tip of `s0` so `s0` itself is marked tested.
    let s0_fin = tip(&hub, &fin_tok, &p.name);
    let r1 = post_check(&hub, Some(&admin_tok), &p.name, &json!({"snapshot": s0.hex(), "name": "ci/src", "state": "pass"}));
    assert_eq!(r1.status, 200, "{}", body(&r1));
    let r2 = post_check(&hub, Some(&fin_tok), &p.name, &json!({"snapshot": s0_fin.hex(), "name": "ci/billing", "state": "pass"}));
    assert_eq!(r2.status, 200, "{}", body(&r2));

    // Open SSE streams for `dev` and `fin`.
    let dev_sse = hub.api().get_unread(
        &format!("/v1/projects/{}/events", p.name),
        &[("authorization", &format!("Bearer {dev_tok}"))],
    );
    let fin_sse = hub.api().get_unread(
        &format!("/v1/projects/{}/events", p.name),
        &[("authorization", &format!("Bearer {fin_tok}"))],
    );

    // 4a. Pure `billing/` culprit: `fin` lands a change in `BILL_DIR/acme/secret.txt`.
    let dev_tip_before = tip(&hub, &dev_tok, &p.name);
    let secret_path = format!("{BILL_DIR}/acme/secret.txt");
    let (_, c_bill_cid) = land_edit(&hub, &p, &fin_tok, &secret_path, "SECRET-BILL-DATA\n", "secret billing edit");
    let c_bill_runner = tip(&hub, &bill_runner, &p.name);

    // `bill_runner` reports `fail` twice on `c_bill` (its parent `s0` already passed `ci/billing`).
    let rf1 = post_check(&hub, Some(&bill_runner), &p.name, &json!({"snapshot": c_bill_runner.hex(), "name": "ci/billing", "state": "fail"}));
    assert_eq!(rf1.status, 200, "{}", body(&rf1));
    // While in `confirming`, `dev` must get 404 on `/bisect/main`!
    assert_eq!(
        get_bisect(&hub, Some(&dev_tok), &p.name, "main").status,
        404,
        "dev must not see bisect of hidden billing check"
    );
    let rf2 = post_check(&hub, Some(&bill_runner), &p.name, &json!({"snapshot": c_bill_runner.hex(), "name": "ci/billing", "state": "fail"}));
    assert_eq!(rf2.status, 200, "{}", body(&rf2));

    // `fin` sees `phase == "reverted"`, `check == "ci/billing"`, `culprit`, and `revert`.
    let fin_st = get_bisect(&hub, Some(&fin_tok), &p.name, "main");
    assert_eq!(fin_st.status, 200, "{}", body(&fin_st));
    assert_eq!(fin_st.json()["phase"], "reverted", "{}", body(&fin_st));
    assert_eq!(fin_st.json()["check"], "ci/billing", "{}", body(&fin_st));
    assert_eq!(fin_st.json()["culprit_change_id"], c_bill_cid, "{}", body(&fin_st));

    // `dev` (and anonymous) sees 404 on `/bisect/main`, `dev`'s tip on `main` did not move,
    // and `dev`'s history does not contain the billing revert or `c_bill_cid`!
    assert_eq!(
        get_bisect(&hub, Some(&dev_tok), &p.name, "main").status,
        404,
        "dev must get 404 for a pure-billing bisect and revert"
    );
    assert_eq!(
        tip(&hub, &dev_tok, &p.name),
        dev_tip_before,
        "pure-billing revert must collapse in dev's view so dev's tip never moves"
    );
    let dev_show = body(&hub.api().get(Some(&dev_tok), &format!("/v1/projects/{}/q/show?rev=main", p.name)));
    assert!(
        !dev_show.contains(&c_bill_cid) && !dev_show.contains("ci/billing") && !dev_show.contains(BILL_DIR),
        "dev's show leaked billing culprit or revert: {dev_show}"
    );

    // 4b. Mixed `src/` + `billing/` commit reverted by `ci/billing`:
    // Advance `main@tested` to current tip first.
    let tip_after_bill = tip(&hub, &admin_tok, &p.name);
    let tip_after_bill_runner = tip(&hub, &bill_runner, &p.name);
    let rp1 = post_check(&hub, Some(&admin_tok), &p.name, &json!({"snapshot": tip_after_bill.hex(), "name": "ci/src", "state": "pass"}));
    assert_eq!(rp1.status, 200, "{}", body(&rp1));
    let rp2 = post_check(&hub, Some(&bill_runner), &p.name, &json!({"snapshot": tip_after_bill_runner.hex(), "name": "ci/billing", "state": "pass"}));
    assert_eq!(rp2.status, 200, "{}", body(&rp2));

    let ch_mixed = change(
        &hub,
        &admin_tok,
        &p.name,
        &json!({
            "base": tip_after_bill.hex(),
            "description": "mixed src and billing commit",
            "edits": [
                {"path": "src/mixed.rs", "put": {"text": "pub const MIXED: i32 = 1;\n"}},
                {"path": secret_path, "put": {"text": "MIXED-SECRET-BILL\n"}}
            ]
        }),
    )
    .json();
    let mixed_sub = ch_mixed["snapshot"].as_str().unwrap();
    let mixed_cid = ch_mixed["change_id"].as_str().unwrap().to_string();
    let l_mixed = land_req(&hub, &admin_tok, &p.name, &json!({"onto": "main", "snapshot": mixed_sub, "wait": true})).json();
    let c_mixed = ObjectId::from_hex(l_mixed["landed"][0].as_str().unwrap()).unwrap();

    // `bill_runner` fails twice on `c_mixed` (projected for `bill_runner`).
    let bill_mixed = tip(&hub, &bill_runner, &p.name);
    let rmf1 = post_check(&hub, Some(&bill_runner), &p.name, &json!({"snapshot": bill_mixed.hex(), "name": "ci/billing", "state": "fail"}));
    assert_eq!(rmf1.status, 200, "{}", body(&rmf1));
    let rmf2 = post_check(&hub, Some(&bill_runner), &p.name, &json!({"snapshot": bill_mixed.hex(), "name": "ci/billing", "state": "fail"}));
    assert_eq!(rmf2.status, 200, "{}", body(&rmf2));

    let admin_st = get_bisect(&hub, Some(&admin_tok), &p.name, "main").json();
    assert_eq!(admin_st["phase"], "reverted", "{admin_st}");
    assert_eq!(admin_st["culprit"], c_mixed.hex(), "{admin_st}");

    // What does `dev` see for the mixed revert?
    // `dev` CAN see `src/mixed.rs` being reverted (and `mixed_cid`),
    // but `check` is `null` (`ci/billing` is hidden from `dev`!).
    let dev_st = get_bisect(&hub, Some(&dev_tok), &p.name, "main");
    assert_eq!(dev_st.status, 200, "{}", body(&dev_st));
    let dev_st_json = dev_st.json();
    assert_eq!(dev_st_json["phase"], "reverted", "{dev_st_json}");
    assert!(dev_st_json["check"].is_null(), "hidden check name ci/billing must be omitted for dev: {dev_st_json}");
    assert_eq!(dev_st_json["culprit_change_id"], mixed_cid, "{dev_st_json}");
    assert!(
        !body(&dev_st).contains("ci/billing") && !body(&dev_st).contains(BILL_DIR),
        "dev bisect status must never leak ci/billing or BILL_DIR: {}",
        body(&dev_st)
    );

    // Check all SSE events received by `dev`: none may mention `ci/billing`, `BILL_DIR`, or `c_bill_cid`!
    let fin_events = collect_sse(fin_sse, 20, Duration::from_millis(500));
    assert!(fin_events.iter().any(|(ev, _)| ev == "reverted"), "fin must receive reverted event: {fin_events:?}");
    let dev_events = collect_sse(dev_sse, 20, Duration::from_millis(500));
    for (ev, data) in &dev_events {
        let s = format!("{ev}:{data}");
        for forbidden in ["ci/billing", BILL_DIR, &c_bill_cid, "SECRET-BILL-DATA", "MIXED-SECRET-BILL"] {
            assert!(!s.contains(forbidden), "dev SSE event leaked {forbidden}: {s}");
        }
    }

    // 4c. Embargoed change is never bisected or reverted into public `main` before its release (Threat 9):
    p.admin.ok(&p.dir, &["group", "add", "devs", &p.sec.name]);
    let sec_dir = p.sec.dir("emb-work");
    p.sec.ok(p.sec.home.path(), &["clone", &hub.url(&p.name), sec_dir.to_str().unwrap()]);
    write_files(&sec_dir, &[("src/sec.rs", "CONFIDENTIAL-EMBARGO-FIX\n")]);
    p.sec.ok(&sec_dir, &["commit", "--no-advance", "-m", "embargoed security fix"]);
    let merge_out = p.sec.ok(
        &sec_dir,
        &[
            "merge",
            "@-",
            "--into",
            "main",
            "--embargo-for",
            "security",
            "--until",
            "2099-01-01T00:00:00Z",
            "-m",
            "embargoed security fix",
        ],
    );
    let eid = merge_out
        .split_whitespace()
        .map(|w| w.trim_end_matches(':'))
        .find(|w| w.len() == 10 && w.bytes().all(|b| b.is_ascii_hexdigit()))
        .expect("embargo id in merge output")
        .to_string();
    p.sec.ok(&sec_dir, &["push"]);
    let emb_branch = format!("embargo/{eid}");
    let sec_tok = p.sec.token();
    let emb_snap = hub.api().tips(Some(&sec_tok), &p.name).unwrap().branches[&emb_branch];

    // Even if an admin posts failing checks on `emb_snap`, the server must NEVER bisect
    // `embargo/<eid>` or revert `emb_snap` onto `main`!
    post_check(&hub, Some(&admin_tok), &p.name, &json!({"snapshot": emb_snap.hex(), "name": "ci/src", "state": "fail"}));
    post_check(&hub, Some(&admin_tok), &p.name, &json!({"snapshot": emb_snap.hex(), "name": "ci/src", "state": "fail"}));
    assert_eq!(
        get_bisect(&hub, Some(&admin_tok), &p.name, &emb_branch).status,
        404,
        "embargo/* branches must never be bisected or auto-reverted"
    );
    let main_st = get_bisect(&hub, Some(&admin_tok), &p.name, "main").json();
    assert_ne!(main_st["culprit"], emb_snap.hex(), "embargoed snapshot must never appear in main bisect");
    let dev_commits = walk_first_parent(&hub, &dev_tok, &p.name, tip(&hub, &dev_tok, &p.name), dev_tip_before);
    let dev_commits_str = serde_json::to_string(&dev_commits).unwrap();
    assert!(
        !dev_commits_str.contains(&eid) && !dev_commits_str.contains("CONFIDENTIAL-EMBARGO-FIX"),
        "embargoed change must never leak into public history: {dev_commits_str}"
    );
}

/// Guarantee 5: Bounded and safe across two servers and restarts: one bisect
/// per branch at a time, and a revert lands at most once.
#[test]
fn bisect_and_revert_are_bounded_and_safe_across_two_servers_and_restarts() {
    let mut hub1 = TestHub::start();
    let hub2 = TestHub::beside(&hub1);
    let p = setup_project(&hub1);
    let admin_tok = p.admin.token();
    let dev_tok = p.dev.token();

    let rules_toml = "[branches.main]\nprotected = true\nrequired_checks = [\"ci/src\"]\n\n\
                      [checks.\"ci/src\"]\npaths = [\"src/\"]\n";
    let s0 = set_rules(&hub1, &p, rules_toml);
    post_check(&hub1, Some(&admin_tok), &p.name, &json!({"snapshot": s0.hex(), "name": "ci/src", "state": "pass"}));

    // Land 4 commits on `main`: `c0`, `c1` (culprit), `c2`, `c3`.
    let mut snaps = Vec::new();
    let mut cids = Vec::new();
    for i in 0..4 {
        let (s, cid) = land_edit(
            &hub1,
            &p,
            &dev_tok,
            &format!("src/s5_{i}.rs"),
            &format!("pub const V: usize = {i};\n"),
            &format!("s5 commit {i}"),
        );
        snaps.push(s);
        cids.push(cid);
    }

    // 5a. Hold `bisect_leases` on `main` briefly as a fake foreign holder: verify a check report
    // does not corrupt or overwrite the leased branch, and once expired/released, bisect proceeds.
    let pid = project_id(&hub1, &p.name);
    let now_ms = veil_core::now_millis();
    let h1_arc = hub1.hub();
    hub1.rt.block_on(async {
        sqlx::query(
            "INSERT INTO bisect_leases (project_id, branch, holder, epoch, expires_at) VALUES ($1, 'main', 'held-by-other', 1, $2) \
             ON CONFLICT (project_id, branch) DO UPDATE SET holder = 'held-by-other', epoch = bisect_leases.epoch + 1, expires_at = $2",
        )
        .bind(pid)
        .bind(now_ms + 60_000)
        .execute(&h1_arc.db)
        .await
        .unwrap();
    });
    // While lease is held by another server, reporting a check records the check row
    // without starting a second concurrent bisect on `main`.
    let r_held = post_check(&hub2, Some(&admin_tok), &p.name, &json!({"snapshot": snaps[3].hex(), "name": "ci/src", "state": "fail"}));
    assert_eq!(r_held.status, 200, "{}", body(&r_held));
    assert_eq!(get_bisect(&hub1, Some(&admin_tok), &p.name, "main").status, 404);

    // Expire the foreign lease and report `fail` on `snaps[3]` to `hub1` and `hub2` concurrently!
    hub1.rt.block_on(async {
        sqlx::query("UPDATE bisect_leases SET expires_at = 0 WHERE project_id = $1 AND branch = 'main'")
            .bind(pid)
            .execute(&h1_arc.db)
            .await
            .unwrap();
    });
    drop(h1_arc);

    std::thread::scope(|s| {
        let h1 = &hub1;
        let h2 = &hub2;
        let tok1 = admin_tok.clone();
        let tok2 = admin_tok.clone();
        let pname1 = p.name.clone();
        let pname2 = p.name.clone();
        let tip_hex = snaps[3].hex();
        let t1 = s.spawn(move || {
            post_check(h1, Some(&tok1), &pname1, &json!({"snapshot": tip_hex, "name": "ci/src", "state": "fail"}))
        });
        let tip_hex2 = snaps[3].hex();
        let t2 = s.spawn(move || {
            post_check(h2, Some(&tok2), &pname2, &json!({"snapshot": tip_hex2, "name": "ci/src", "state": "fail"}))
        });
        assert_eq!(t1.join().unwrap().status, 200);
        assert_eq!(t2.join().unwrap().status, 200);
    });

    // Report probe results across `hub1` and `hub2` (`snaps[0]` passes, `snaps[1]` fails, `snaps[2]` fails).
    post_check(&hub2, Some(&admin_tok), &p.name, &json!({"snapshot": snaps[1].hex(), "name": "ci/src", "state": "fail"}));
    post_check(&hub1, Some(&admin_tok), &p.name, &json!({"snapshot": snaps[0].hex(), "name": "ci/src", "state": "pass"}));

    // Now bisect is in `confirming` for culprit `snaps[1]`!
    let st_mid = get_bisect(&hub2, Some(&admin_tok), &p.name, "main").json();
    assert_eq!(st_mid["phase"], "confirming", "{st_mid}");
    assert_eq!(st_mid["culprit"], snaps[1].hex(), "{st_mid}");

    // Restart `hub1` mid-bisect (`confirming` state persisted in `bisects`).
    hub1 = hub1.restart(|url| {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let db = veil_server::db::connect(url, 1).await.unwrap();
            let _ = sqlx::query("UPDATE landing_leases SET expires_at = 0 WHERE project_id = $1")
                .bind(pid)
                .execute(&db)
                .await;
            db.close().await;
        });
    });

    // After restart, send the confirming `fail` on `snaps[1]` to BOTH `hub1` and `hub2` concurrently!
    std::thread::scope(|s| {
        let h1 = &hub1;
        let h2 = &hub2;
        let tok1 = admin_tok.clone();
        let tok2 = admin_tok.clone();
        let pname1 = p.name.clone();
        let pname2 = p.name.clone();
        let c_hex1 = snaps[1].hex();
        let c_hex2 = snaps[1].hex();
        let t1 = s.spawn(move || {
            post_check(h1, Some(&tok1), &pname1, &json!({"snapshot": c_hex1, "name": "ci/src", "state": "fail"}))
        });
        let t2 = s.spawn(move || {
            post_check(h2, Some(&tok2), &pname2, &json!({"snapshot": c_hex2, "name": "ci/src", "state": "fail"}))
        });
        assert_eq!(t1.join().unwrap().status, 200);
        assert_eq!(t2.join().unwrap().status, 200);
    });

    // Wait for the revert to finish landing.
    let mut st_end = get_bisect(&hub1, Some(&admin_tok), &p.name, "main").json();
    for _ in 0..20 {
        if st_end["phase"] == "reverted" {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
        st_end = get_bisect(&hub1, Some(&admin_tok), &p.name, "main").json();
    }
    assert_eq!(st_end["phase"], "reverted", "{st_end}");
    assert_eq!(st_end["culprit"], snaps[1].hex(), "{st_end}");

    // Verify the revert landed AT MOST ONCE in `main`'s commit history!
    let log_commits = walk_first_parent(&hub1, &admin_tok, &p.name, tip(&hub1, &admin_tok, &p.name), s0);
    let revert_desc = format!("revert {}", cids[1]);
    let revert_count = log_commits
        .iter()
        .filter(|c| c["description"].as_str() == Some(revert_desc.as_str()))
        .count();
    assert_eq!(
        revert_count, 1,
        "revert of culprit must land at most once across concurrent servers and restarts: {log_commits:?}"
    );

    // Even if another failing check is reported for `snaps[1]` afterwards, it is not reverted again.
    post_check(&hub1, Some(&admin_tok), &p.name, &json!({"snapshot": snaps[1].hex(), "name": "ci/src", "state": "fail"}));
    let log_commits_after = walk_first_parent(&hub1, &admin_tok, &p.name, tip(&hub1, &admin_tok, &p.name), s0);
    let revert_count_after = log_commits_after
        .iter()
        .filter(|c| c["description"].as_str() == Some(revert_desc.as_str()))
        .count();
    assert_eq!(revert_count_after, 1);
}
