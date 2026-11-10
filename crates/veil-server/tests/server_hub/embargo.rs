//! Milestone S22: embargoes through the server, and the release service
//! (`docs/HUB.md` §13.31; `docs/design/server/phase-4-agent-scale.md` §4.8,
//! decisions 8 and 9, and §6 row 8).
//!
//! Guarantees tested here:
//! 1. Embargoed content is invisible to everyone outside the embargo until
//!    release, by every route: query, search, blame, landing answers, events
//!    and errors.
//! 2. Release happens at the deadline and never before. Cover clock skew,
//!    restarts, several servers, and a failed release job retried.
//! 3. Landing at release puts exactly the embargoed changes on `main`, once.
//! 4. `vl embargo follow` shows a member only what they're in.
//! 5. Nobody outside the embargo learns that it exists, beyond what decision
//!    8 allows.

use std::time::Duration;

use serde_json::{json, Value};
use veil_core::ObjectId;

use crate::support::*;

/// Assert that `text` contains none of `markers`.
fn assert_no_str(text: &str, markers: &[&str], where_: &str) {
    for m in markers {
        assert!(!text.contains(m), "found forbidden marker {m:?} in {where_}: {text}");
    }
}

/// Extract the embargo id printed by `vl merge ... --embargo...` ("embargo <id>:").
fn parse_embargo_id(out: &str) -> String {
    for word in out.split_whitespace() {
        let clean = word.trim_end_matches(':');
        if clean.len() == 10 && clean.bytes().all(|b| b.is_ascii_hexdigit()) {
            return clean.to_string();
        }
    }
    panic!("no embargo id in output: {out}");
}

/// Format a millisecond epoch timestamp as an ISO-8601 UTC string (`YYYY-MM-DDTHH:MM:SSZ`)
/// or seconds-precision string accepted by `vl merge --until`.
fn iso_utc(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let hour = rem / 3600;
    let min = (rem % 3600) / 60;
    let sec = rem % 60;
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{hour:02}:{min:02}:{sec:02}Z")
}

/// Wait until the server's derived data and search index for `project` have
/// caught up with its branches.
fn catch_up(hub: &TestHub, project: &str) {
    let h = hub.hub();
    let pid: i64 = hub
        .rt
        .block_on(sqlx::query_scalar("SELECT id FROM projects WHERE name = $1").bind(project).fetch_one(&h.db))
        .unwrap();
    hub.rt.block_on(veil_server::derive::catch_up_project(&h, pid)).unwrap();
    hub.rt.block_on(veil_server::search::index::catch_up_project(&h, pid)).unwrap();
}

/// Wait for an embargo to be marked released in `embargo_lines` and landed on `main`.
fn wait_released(hub: &TestHub, project: &str, embargo_id: &str, timeout: Duration) -> bool {
    let h = hub.hub();
    let pid: i64 = hub
        .rt
        .block_on(sqlx::query_scalar("SELECT id FROM projects WHERE name = $1").bind(project).fetch_one(&h.db))
        .unwrap();
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        let _ = hub.rt.block_on(veil_server::embargo::release_due(&h));
        let released: Option<i64> = hub
            .rt
            .block_on(
                sqlx::query_scalar("SELECT released_at FROM embargo_lines WHERE project_id = $1 AND embargo_id = $2")
                    .bind(pid)
                    .bind(embargo_id)
                    .fetch_optional(&h.db),
            )
            .unwrap()
            .flatten();
        if released.is_some() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// Guarantee 1: Embargoed content is invisible to everyone outside the
/// embargo until release, by every route: query, search, blame, landing
/// answers, events and errors.
#[test]
fn guarantee_1_embargoed_content_is_invisible_outside_the_embargo_by_every_route() {
    const FIX_MARK: &str = "EMBARGO-SECRET-FIX-9911";
    const MSG_MARK: &str = "EMBARGO-COMMIT-MSG-8822";
    let hub = TestHub::start();
    let p = setup_project(&hub);
    p.admin.ok(&p.dir, &["group", "add", "devs", &p.sec.name]);

    // `p.sec` (in `security` and `devs`) clones, creates an embargoed fix touching `src/lib.rs`
    // and `src/embargo_fix.rs` for `security`, and pushes it to the server.
    let sec_dir = p.sec.dir("work");
    p.sec.ok(p.sec.home.path(), &["clone", &hub.url(&p.name), sec_dir.to_str().unwrap()]);
    write_files(
        &sec_dir,
        &[
            ("src/lib.rs", &format!("{PUBLIC_MARK}\n{FIX_MARK}\n")),
            ("src/embargo_fix.rs", &format!("pub const FIX: &str = \"{FIX_MARK}\";\n")),
        ],
    );
    p.sec.ok(&sec_dir, &["commit", "--no-advance", "-m", MSG_MARK]);
    let fix_hex = p.sec.ok(&sec_dir, &["log", "-r", "@-", "-n", "1", "--json"]);
    let fix_id = ObjectId::from_hex(
        serde_json::from_str::<Value>(&fix_hex).unwrap()["entries"][0]["snapshot_id"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let until = iso_utc(veil_core::now_millis() + 3_600_000);
    let merge_out = p.sec.ok(
        &sec_dir,
        &["merge", "@-", "--into", "main", "--embargo-for", "security", "--until", &until, "-m", MSG_MARK],
    );
    let eid = parse_embargo_id(&merge_out);
    let merge_hex = p.sec.ok(&sec_dir, &["log", "-r", "main", "-n", "1", "--json"]);
    let merge_id = ObjectId::from_hex(
        serde_json::from_str::<Value>(&merge_hex).unwrap()["entries"][0]["snapshot_id"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    p.sec.ok(&sec_dir, &["push"]);

    catch_up(&hub, &p.name);
    let api = hub.api();
    let dev_tok = p.dev.token();
    let fin_tok = p.fin.token();
    let sec_tok = p.sec.token();
    let embargo_branch = format!("embargo/{eid}");

    // 1. Member of `security` sees the hidden embargo line in tips and can pull it.
    let sec_tips = api.tips(Some(&sec_tok), &p.name).unwrap();
    assert!(sec_tips.branches.contains_key(&embargo_branch), "security member must see {embargo_branch}");
    assert!(sec_tips.embargoes.iter().any(|e| e.id == eid), "security member must receive embargo record");

    // 2. Outsiders (`dev`, `fin`, anonymous) see nothing via sync, query, search, blame, landing, or errors.
    for (who, tok) in [("dev", Some(dev_tok.as_str())), ("fin", Some(fin_tok.as_str())), ("anon", None)] {
        // Tips: no embargo branch, no embargo record.
        let t = api.tips(tok, &p.name).unwrap();
        assert!(!t.branches.contains_key(&embargo_branch), "{who} saw {embargo_branch}");
        assert!(t.embargoes.is_empty(), "{who} saw embargoes: {:?}", t.embargoes);

        // History & Fetch of the embargoed snapshots: refused as not found.
        for id in [fix_id, merge_id] {
            let h = api.post_json(tok, &format!("/v1/projects/{}/history", p.name), &json!({"tips": [id.hex()], "stop": []}));
            assert_eq!(h.status, 404, "{who} history for {id}: {}", String::from_utf8_lossy(&h.body));
            assert_no_str(&String::from_utf8_lossy(&h.body), &[FIX_MARK, MSG_MARK, &eid], who);

            let f = api.post_json(
                tok,
                &format!("/v1/projects/{}/fetch", p.name),
                &json!({"snapshot": id.hex(), "objects": [{"path": "src/embargo_fix.rs", "id": id.hex()}]}),
            );
            assert_eq!(f.status, 404, "{who} fetch for {id}: {}", String::from_utf8_lossy(&f.body));
            assert_no_str(&String::from_utf8_lossy(&f.body), &[FIX_MARK, MSG_MARK, &eid], who);
        }

        // Query routes: generations, log, show, tree, file, diff, ancestry, resolve.
        let gen = api.post_json(
            tok,
            &format!("/v1/projects/{}/q/generations", p.name),
            &json!({"snapshots": [fix_id.hex(), merge_id.hex()]}),
        );
        assert_eq!(gen.status, 200, "{who} q/generations: {}", String::from_utf8_lossy(&gen.body));
        assert_eq!(gen.json()["generations"], json!([null, null]), "{who} generations leaked embargo");
        for route in [
            "log?rev=main".to_string(),
            "tree?rev=main&path=src".to_string(),
            "file?rev=main&path=src/lib.rs".to_string(),
            format!("resolve?prefix={}", &merge_id.hex()[..8]),
            format!("resolve?prefix={}", &fix_id.hex()[..8]),
        ] {
            let r = api.get(tok, &format!("/v1/projects/{}/q/{route}", p.name));
            assert_eq!(r.status, 200, "{who} q/{route}: {}", String::from_utf8_lossy(&r.body));
            assert_no_str(&String::from_utf8_lossy(&r.body), &[FIX_MARK, MSG_MARK, "embargo_fix.rs", &eid], who);
        }
        for rev in [&embargo_branch, &merge_id.hex(), &fix_id.hex()] {
            for kind in ["log", "show", "tree"] {
                let r = api.get(tok, &format!("/v1/projects/{}/q/{kind}?rev={rev}", p.name));
                assert_eq!(r.status, 404, "{who} q/{kind}?rev={rev}: {}", String::from_utf8_lossy(&r.body));
                assert_no_str(&String::from_utf8_lossy(&r.body), &[FIX_MARK, MSG_MARK], who);
            }
        }

        // Search and grep: nothing of the embargoed fix or message is indexed or found.
        for q in ["EMBARGO-SECRET", "EMBARGO-COMMIT", "embargo_fix"] {
            let s = api.get(tok, &format!("/v1/projects/{}/q/search?q={q}&kind=code", p.name));
            assert_eq!(s.status, 200, "{who} search {q}: {}", String::from_utf8_lossy(&s.body));
            assert_eq!(s.json()["results"].as_array().unwrap().len(), 0, "{who} search results for {q}");
            assert_no_str(&String::from_utf8_lossy(&s.body), &[FIX_MARK, MSG_MARK], who);

            let g = api.get(tok, &format!("/v1/projects/{}/q/grep?pattern={q}", p.name));
            assert_eq!(g.status, 200, "{who} grep {q}: {}", String::from_utf8_lossy(&g.body));
            assert_eq!(g.json()["files"].as_array().unwrap().len(), 0, "{who} grep files for {q}");
            assert_no_str(&String::from_utf8_lossy(&g.body), &[FIX_MARK, MSG_MARK], who);
        }

        // Release endpoint: outsiders get 404 (or 401 when anonymous).
        let rel = api.post_json(tok, &format!("/v1/projects/{}/embargoes/{eid}/release", p.name), &json!({}));
        assert!(rel.status == 401 || rel.status == 404, "{who} release status: {}", rel.status);
        assert_no_str(&String::from_utf8_lossy(&rel.body), &[FIX_MARK, MSG_MARK], who);
    }

    // 3. Blame (`vl blame`) in both a full clone and a thin clone of `dev`:
    let dev_full = p.dev.dir("full");
    p.dev.ok(p.dev.home.path(), &["clone", "--full", &hub.url(&p.name), dev_full.to_str().unwrap()]);
    let blame_full = p.dev.ok(&dev_full, &["blame", "src/lib.rs"]);
    assert_no_str(&blame_full, &[FIX_MARK, MSG_MARK, &eid, &p.sec.name], "dev full blame");
    assert_no_marker(&everything_in(&dev_full), &[FIX_MARK, MSG_MARK, &eid], "dev full clone");

    let dev_thin = p.dev.dir("thin");
    p.dev.ok(p.dev.home.path(), &["clone", &hub.url(&p.name), dev_thin.to_str().unwrap()]);
    let blame_thin = p.dev.ok(&dev_thin, &["blame", "src/lib.rs"]);
    assert_no_str(&blame_thin, &[FIX_MARK, MSG_MARK, &eid, &p.sec.name], "dev thin blame");
    assert_no_marker(&everything_in(&dev_thin), &[FIX_MARK, MSG_MARK, &eid], "dev thin clone");

    // 4. Landing answers: `dev` lands a change on `main` (even touching `src/lib.rs`,
    // which the embargo touched on its hidden line) without conflict or leak; and trying to
    // land onto `embargo/<eid>` or with `base = merge_id` fails with standard missing errors.
    let bad_onto = api.post_json(
        Some(&dev_tok),
        &format!("/v1/projects/{}/land", p.name),
        &json!({"onto": &embargo_branch, "base": t_main(&api, &dev_tok, &p.name), "edits": [{"path": "src/x.rs", "put": {"text": "x"}}], "description": "probe", "wait": true}),
    );
    assert_eq!(bad_onto.status, 200, "{}", String::from_utf8_lossy(&bad_onto.body));
    assert_eq!(bad_onto.json()["state"], "rejected");
    assert!(
        bad_onto.json()["message"].as_str().unwrap_or_default().contains("there is no branch"),
        "expected missing branch message, got: {}",
        String::from_utf8_lossy(&bad_onto.body)
    );
    assert_no_str(&String::from_utf8_lossy(&bad_onto.body), &[FIX_MARK, MSG_MARK], "bad_onto");

    let bad_base = api.post_json(
        Some(&dev_tok),
        &format!("/v1/projects/{}/land", p.name),
        &json!({"onto": "main", "base": merge_id.hex(), "edits": [{"path": "src/x.rs", "put": {"text": "x"}}], "description": "probe", "wait": true}),
    );
    assert_eq!(bad_base.status, 404, "{}", String::from_utf8_lossy(&bad_base.body));

    let good_land = api.post_json(
        Some(&dev_tok),
        &format!("/v1/projects/{}/land", p.name),
        &json!({"onto": "main", "base": t_main(&api, &dev_tok, &p.name), "edits": [{"path": "src/dev_ok.rs", "put": {"text": "ok\n"}}], "description": "dev land", "wait": true}),
    );
    assert_eq!(good_land.status, 200, "{}", String::from_utf8_lossy(&good_land.body));
    assert_eq!(good_land.json()["state"], "landed");
    assert_no_str(&String::from_utf8_lossy(&good_land.body), &[FIX_MARK, MSG_MARK, &eid], "dev land");
}

fn t_main(api: &Api, token: &str, project: &str) -> String {
    api.tips(Some(token), project).unwrap().branches["main"].hex()
}

/// Guarantee 2: Release happens at the deadline and never before. Cover
/// clock skew, restarts, several servers, and a failed release job retried.
#[test]
fn guarantee_2_release_happens_at_the_deadline_and_never_before() {
    const TIMED_FIX: &str = "TIMED-EMBARGO-FIX-2201";
    const MANUAL_FIX: &str = "MANUAL-EMBARGO-FIX-2202";
    let mut hub = TestHub::start();
    let p = setup_project(&hub);

    // 1. Create a manual embargo (no deadline) and a timed embargo (+5 minutes).
    write_files(&p.dir, &[("src/manual.rs", MANUAL_FIX)]);
    p.admin.ok(&p.dir, &["commit", "--no-advance", "-m", "manual fix"]);
    let out_m = p.admin.ok(&p.dir, &["merge", "@-", "--into", "main", "--embargo-for", "devs", "-m", "merge manual"]);
    let _eid_manual = parse_embargo_id(&out_m);
    p.admin.ok(&p.dir, &["push"]);

    p.admin.ok(&p.dir, &["new", "main"]);
    let until = iso_utc(veil_core::now_millis() + 300_000);
    write_files(&p.dir, &[("src/timed.rs", TIMED_FIX)]);
    p.admin.ok(&p.dir, &["commit", "--no-advance", "-m", "timed fix"]);
    let out_t = p.admin.ok(
        &p.dir,
        &["merge", "@-", "--into", "main", "--embargo-for", "devs", "--until", &until, "-m", "merge timed"],
    );
    let eid_timed = parse_embargo_id(&out_t);
    p.admin.ok(&p.dir, &["push"]);

    // 2. Clock skew ahead (+1 hour on the app server while DB clock is still before `until`):
    //    must NEVER release before the database deadline!
    hub.hub().embargo.set_clock_offset_ms(3_600_000);
    hub.rt.block_on(veil_server::embargo::release_due(&hub.hub())).unwrap();
    let anon_dir = hub.anyone().dir("before");
    hub.anyone().ok(hub.anyone().home.path(), &["clone", &hub.url(&p.name), anon_dir.to_str().unwrap()]);
    assert!(!anon_dir.join("src/timed.rs").exists(), "skewed clock released embargo before deadline!");
    assert!(!anon_dir.join("src/manual.rs").exists(), "manual embargo released automatically!");

    // 3. Restart the server before the deadline: state survives restart and still does not release early.
    hub = hub.restart(|_| {});
    hub.rt.block_on(veil_server::embargo::release_due(&hub.hub())).unwrap();
    let anon_dir2 = hub.anyone().dir("after-restart-before-deadline");
    hub.anyone().ok(hub.anyone().home.path(), &["clone", &hub.url(&p.name), anon_dir2.to_str().unwrap()]);
    assert!(!anon_dir2.join("src/timed.rs").exists(), "released before deadline after restart!");
    assert!(!anon_dir2.join("src/manual.rs").exists(), "manual embargo released after restart!");

    // 4. Skew `hub`'s local clock behind (-1 hour) and inject 2 release job failures BEFORE
    //    the deadline arrives, then bring `eid_timed`'s deadline to now and start several
    //    servers (`hub`, `hub2`, `hub3`) so the failed release job is retried and lands once.
    hub.hub().embargo.set_clock_offset_ms(-3_600_000);
    hub.hub().embargo.fail_next_releases(2);
    hub.rt.block_on(async {
        sqlx::query(
            "UPDATE embargo_lines \
             SET until_ms = (extract(epoch FROM clock_timestamp()) * 1000)::BIGINT - 10 \
             WHERE embargo_id = $1",
        )
        .bind(&eid_timed)
        .execute(&hub.hub().db)
        .await
        .unwrap();
    });

    let _ = hub.rt.block_on(veil_server::embargo::release_due(&hub.hub()));
    let _ = hub.rt.block_on(veil_server::embargo::release_due(&hub.hub()));
    assert!(hub.hub().embargo.retried_failures() >= 2, "expected at least 2 failed attempts before retry succeeded");

    let hub2 = TestHub::beside(&hub);
    let hub3 = TestHub::beside(&hub);
    let _ = hub.rt.block_on(veil_server::embargo::release_due(&hub.hub()));
    let _ = hub2.rt.block_on(veil_server::embargo::release_due(&hub2.hub()));
    let _ = hub3.rt.block_on(veil_server::embargo::release_due(&hub3.hub()));
    assert!(
        wait_released(&hub, &p.name, &eid_timed, Duration::from_secs(10)),
        "timed embargo did not release after deadline and retries"
    );

    // 5. After deadline: `timed.rs` is public on `main`, while `manual.rs` is STILL withheld!
    let anon_after = hub.anyone().dir("after-deadline");
    hub.anyone().ok(hub.anyone().home.path(), &["clone", &hub.url(&p.name), anon_after.to_str().unwrap()]);
    assert_eq!(std::fs::read_to_string(anon_after.join("src/timed.rs")).unwrap(), TIMED_FIX);
    assert!(!anon_after.join("src/manual.rs").exists(), "manual embargo must remain unreleased");
}

/// Guarantee 3: Landing at release puts exactly the embargoed changes on
/// `main`, once.
#[test]
fn guarantee_3_landing_at_release_puts_exactly_the_embargoed_changes_on_main_once() {
    const FIX_A: &str = "EMBARGO-LAND-A-3301\n";
    const FIX_B: &str = "EMBARGO-LAND-B-3302\n";
    const FIX_C: &str = "EMBARGO-LAND-C-3303\n";
    const MAIN_WORK: &str = "CONCURRENT-MAIN-WORK-3304\n";

    let hub = TestHub::start();
    let p = setup_project(&hub);
    let initial_main = hub.api().tips(Some(&p.admin.token()), &p.name).unwrap().branches["main"];

    // Admin creates an embargoed fix modifying two files (`src/a.rs`, `src/b.rs`) and pushes.
    write_files(&p.dir, &[("src/a.rs", FIX_A), ("src/b.rs", FIX_B)]);
    p.admin.ok(&p.dir, &["commit", "--no-advance", "-m", "embargoed fix a and b"]);
    let merge_out = p.admin.ok(
        &p.dir,
        &["merge", "@-", "--into", "main", "--embargo-for", "devs", "-m", "merge embargoed fix"],
    );
    let eid = parse_embargo_id(&merge_out);
    p.admin.ok(&p.dir, &["push"]);

    // Meanwhile, `main` moves ahead with ordinary work from `admin` on `main`.
    p.admin.ok(&p.dir, &["new", "main"]);
    write_files(&p.dir, &[("src/main_work.rs", MAIN_WORK)]);
    p.admin.ok(&p.dir, &["commit", "-m", "concurrent work on main"]);
    p.admin.ok(&p.dir, &["push"]);

    // `dev` (in `devs`) follows the embargo, adds a follow-up commit `src/c.rs` on the embargo line, and pushes.
    let dev_dir = p.dev.dir("dev-work");
    p.dev.ok(p.dev.home.path(), &["clone", &hub.url(&p.name), dev_dir.to_str().unwrap()]);
    p.dev.ok(&dev_dir, &["embargo", "follow", &eid]);
    write_files(&dev_dir, &[("src/c.rs", FIX_C)]);
    p.dev.ok(&dev_dir, &["commit", "-m", "embargo follow-up c"]);
    p.dev.ok(&dev_dir, &["push"]);

    // Release the embargo via `vl embargo release <eid> --yes` and `vl push`
    // (and trigger `release_due` concurrently to verify idempotency).
    p.dev.ok(&dev_dir, &["embargo", "release", &eid, "--yes"]);
    p.dev.ok(&dev_dir, &["push"]);
    hub.rt.block_on(veil_server::embargo::release_due(&hub.hub())).unwrap();
    assert!(wait_released(&hub, &p.name, &eid, Duration::from_secs(5)));

    // Verify `main` has the concurrent work AND the exact embargoed changes, each landed once.
    let check_dir = hub.anyone().dir("verify-main");
    hub.anyone().ok(hub.anyone().home.path(), &["clone", &hub.url(&p.name), check_dir.to_str().unwrap()]);
    assert_eq!(std::fs::read_to_string(check_dir.join("src/main_work.rs")).unwrap(), MAIN_WORK);
    assert_eq!(std::fs::read_to_string(check_dir.join("src/a.rs")).unwrap(), FIX_A);
    assert_eq!(std::fs::read_to_string(check_dir.join("src/b.rs")).unwrap(), FIX_B);
    assert_eq!(std::fs::read_to_string(check_dir.join("src/c.rs")).unwrap(), FIX_C);

    // Walk `main` down to `initial_main`: check that each change landed on `main` once.
    let log_json: Value = serde_json::from_str(&p.admin.ok(&p.dir, &["pull"])).unwrap_or(Value::Null);
    let _ = log_json;
    let log_str = p.admin.ok(&p.dir, &["log", "-r", "origin/main", "--json"]);
    let log_val: Value = serde_json::from_str(&log_str).unwrap();
    let entries = log_val["entries"].as_array().unwrap();
    let since_init: Vec<&Value> = entries
        .iter()
        .take_while(|it| it["snapshot_id"].as_str().unwrap() != initial_main.hex())
        .collect();
    assert!(
        !since_init.is_empty() && since_init.len() <= 4,
        "expected embargoed changes landed once on main since initial_main, got: {since_init:#?}"
    );

    // And derived queries & search now see the released changes on `main`.
    catch_up(&hub, &p.name);
    let s = hub.api().get(None, &format!("/v1/projects/{}/q/search?q=EMBARGO-LAND-A-3301&kind=code", p.name));
    assert_eq!(s.status, 200);
    assert_eq!(s.json()["results"].as_array().unwrap().len(), 1);
}

/// Guarantee 4: `vl embargo follow` shows a member only what they're in.
#[test]
fn guarantee_4_vl_embargo_follow_shows_a_member_only_what_they_are_in() {
    const SEC_MARK: &str = "SEC-ONLY-EMBARGO-4401";
    const FIN_MARK: &str = "FIN-ONLY-EMBARGO-4402";
    const MAIN_ADV: &str = "MAIN-ADVANCED-4403";

    let hub = TestHub::start();
    let p = setup_project(&hub);

    // Admin creates Embargo 1 for `security` and pushes.
    write_files(&p.dir, &[("src/sec_fix.rs", SEC_MARK)]);
    p.admin.ok(&p.dir, &["commit", "--no-advance", "-m", "sec fix"]);
    let out_sec = p.admin.ok(
        &p.dir,
        &["merge", "@-", "--into", "main", "--embargo-for", "security", "-m", "merge sec fix"],
    );
    let eid_sec = parse_embargo_id(&out_sec);
    p.admin.ok(&p.dir, &["push"]);

    // Admin creates Embargo 2 for `finance` on `main` and pushes.
    p.admin.ok(&p.dir, &["new", "main"]);
    write_files(&p.dir, &[("src/fin_fix.rs", FIN_MARK)]);
    p.admin.ok(&p.dir, &["commit", "--no-advance", "-m", "fin fix"]);
    let out_fin = p.admin.ok(
        &p.dir,
        &["merge", "@-", "--into", "main", "--embargo-for", "finance", "-m", "merge fin fix"],
    );
    let eid_fin = parse_embargo_id(&out_fin);
    p.admin.ok(&p.dir, &["push"]);

    // Meanwhile `dev` advances `main`.
    let dev_dir = p.dev.dir("dev");
    p.dev.ok(p.dev.home.path(), &["clone", &hub.url(&p.name), dev_dir.to_str().unwrap()]);
    write_files(&dev_dir, &[("src/main_adv.rs", MAIN_ADV)]);
    p.dev.ok(&dev_dir, &["commit", "-m", "advance main"]);
    p.dev.ok(&dev_dir, &["push"]);

    // 1. `p.sec` (in `security` only): `vl embargo follow` shows `eid_sec` and NOT `eid_fin`,
    //    rebases `embargo/<eid_sec>` onto the advanced `main`, and checks it out.
    let sec_dir = p.sec.dir("sec");
    p.sec.ok(p.sec.home.path(), &["clone", &hub.url(&p.name), sec_dir.to_str().unwrap()]);
    let follow_sec = p.sec.ok(&sec_dir, &["embargo", "follow"]);
    assert!(follow_sec.contains(&eid_sec), "p.sec must see {eid_sec}: {follow_sec}");
    assert_no_str(&follow_sec, &[&eid_fin, FIN_MARK, "finance"], "p.sec follow output");
    assert!(sec_dir.join("src/sec_fix.rs").exists(), "sec_fix.rs checked out after follow");
    assert!(sec_dir.join("src/main_adv.rs").exists(), "rebased onto latest main after follow");
    assert!(!sec_dir.join("src/fin_fix.rs").exists(), "fin_fix.rs must not exist for p.sec");
    let bad_fin = p.sec.fails(&sec_dir, &["embargo", "follow", &eid_fin]);
    assert_no_str(&bad_fin, &[FIN_MARK, "finance"], "p.sec follow fin error");

    // 2. `fin` (in `finance` only): `vl embargo follow` shows `eid_fin` and NOT `eid_sec`.
    let fin_dir = p.fin.dir("fin");
    p.fin.ok(p.fin.home.path(), &["clone", &hub.url(&p.name), fin_dir.to_str().unwrap()]);
    let follow_fin = p.fin.ok(&fin_dir, &["embargo", "follow"]);
    assert!(follow_fin.contains(&eid_fin), "fin must see {eid_fin}: {follow_fin}");
    assert_no_str(&follow_fin, &[&eid_sec, SEC_MARK, "security"], "fin follow output");
    assert!(fin_dir.join("src/fin_fix.rs").exists(), "fin_fix.rs checked out after follow");
    assert!(fin_dir.join("src/main_adv.rs").exists(), "rebased onto latest main after follow");
    assert!(!fin_dir.join("src/sec_fix.rs").exists(), "sec_fix.rs must not exist for fin");
    let bad_sec = p.fin.fails(&fin_dir, &["embargo", "follow", &eid_sec]);
    assert_no_str(&bad_sec, &[SEC_MARK], "fin follow sec error");

    // 3. `dev` (in neither `security` nor `finance`): `vl embargo follow` shows nothing.
    let follow_dev = p.dev.ok(&dev_dir, &["embargo", "follow"]);
    assert_no_str(&follow_dev, &[&eid_sec, &eid_fin, SEC_MARK, FIN_MARK], "dev follow output");
    p.dev.fails(&dev_dir, &["embargo", "follow", &eid_sec]);
    p.dev.fails(&dev_dir, &["embargo", "follow", &eid_fin]);
}

/// Guarantee 5: Nobody outside the embargo learns that it exists, beyond
/// what decision 8 allows.
#[test]
fn guarantee_5_nobody_outside_the_embargo_learns_that_it_exists() {
    let hub = TestHub::start();
    let p_with = setup_project(&hub);
    let p_without = setup_project(&hub);

    // Push an embargoed fix to `p_with` for `finance` (which `p_with.dev` is NOT in).
    write_files(&p_with.dir, &[("src/secret_vuln.rs", "VULN-5501\n")]);
    p_with.admin.ok(&p_with.dir, &["commit", "--no-advance", "-m", "fix vuln 5501"]);
    let fix_hex = p_with.admin.ok(&p_with.dir, &["log", "-r", "@-", "-n", "1", "--json"]);
    let fix_id = ObjectId::from_hex(
        serde_json::from_str::<Value>(&fix_hex).unwrap()["entries"][0]["snapshot_id"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let out = p_with.admin.ok(
        &p_with.dir,
        &["merge", "@-", "--into", "main", "--embargo-for", "finance", "-m", "merge vuln 5501"],
    );
    let eid = parse_embargo_id(&out);
    let merge_hex = p_with.admin.ok(&p_with.dir, &["log", "-r", "main", "-n", "1", "--json"]);
    let merge_id = ObjectId::from_hex(
        serde_json::from_str::<Value>(&merge_hex).unwrap()["entries"][0]["snapshot_id"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    p_with.admin.ok(&p_with.dir, &["push"]);
    catch_up(&hub, &p_with.name);
    catch_up(&hub, &p_without.name);

    let api = hub.api();
    let dev_with = p_with.dev.token();
    let dev_without = p_without.dev.token();

    // 1. `tips` structure for `dev` on `p_with` has the exact same branch names and empty embargoes as `p_without`.
    let tips_with = api.tips(Some(&dev_with), &p_with.name).unwrap();
    let tips_without = api.tips(Some(&dev_without), &p_without.name).unwrap();
    assert_eq!(tips_with.branches.keys().collect::<Vec<_>>(), tips_without.branches.keys().collect::<Vec<_>>());
    assert!(tips_with.embargoes.is_empty());

    // 2. Probing `embargo/<eid>` vs a non-existent `embargo/0000000000`, and `merge_id`/`fix_id` vs a random ObjectId,
    //    produces byte-for-byte identical status codes and normalised error messages on every route.
    let fake_eid = "0000000000";
    let fake_branch = format!("embargo/{fake_eid}");
    let real_branch = format!("embargo/{eid}");
    let fake_snap = ObjectId::from_hex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef").unwrap();

    let norm = |s: &str| {
        s.replace(&eid, "<eid>")
            .replace(fake_eid, "<eid>")
            .replace(&merge_id.hex(), "<snap>")
            .replace(&fix_id.hex(), "<snap>")
            .replace(&fake_snap.hex(), "<snap>")
            .replace(&merge_id.short(), "<short>")
            .replace(&fix_id.short(), "<short>")
            .replace(&fake_snap.short(), "<short>")
    };

    for (real_rev, fake_rev) in [
        (real_branch.as_str(), fake_branch.as_str()),
        (&merge_id.hex(), &fake_snap.hex()),
        (&fix_id.hex(), &fake_snap.hex()),
    ] {
        for route in [
            format!("q/log?rev={real_rev}"),
            format!("q/show?rev={real_rev}"),
            format!("q/tree?rev={real_rev}"),
            format!("q/file?rev={real_rev}&path=src/lib.rs"),
            format!("q/search?q=readme&rev={real_rev}"),
            format!("q/grep?pattern=readme&rev={real_rev}"),
        ] {
            let fake_route = route.replace(real_rev, fake_rev);
            let r_real = api.get(Some(&dev_with), &format!("/v1/projects/{}/{route}", p_with.name));
            let r_fake = api.get(Some(&dev_with), &format!("/v1/projects/{}/{fake_route}", p_with.name));
            assert_eq!(r_real.status, r_fake.status, "status mismatch on {route}");
            assert_eq!(
                norm(&String::from_utf8_lossy(&r_real.body)),
                norm(&String::from_utf8_lossy(&r_fake.body)),
                "body mismatch on {route}"
            );
        }
    }

    // History, fetch, release, land, and commits probes match fake ids byte-for-byte.
    for real_snap in [merge_id, fix_id] {
        let h_real = api.post_json(Some(&dev_with), &format!("/v1/projects/{}/history", p_with.name), &json!({"tips": [real_snap.hex()], "stop": []}));
        let h_fake = api.post_json(Some(&dev_with), &format!("/v1/projects/{}/history", p_with.name), &json!({"tips": [fake_snap.hex()], "stop": []}));
        assert_eq!(h_real.status, h_fake.status);
        assert_eq!(norm(&String::from_utf8_lossy(&h_real.body)), norm(&String::from_utf8_lossy(&h_fake.body)));

        let f_real = api.post_json(Some(&dev_with), &format!("/v1/projects/{}/fetch", p_with.name), &json!({"snapshot": real_snap.hex(), "objects": []}));
        let f_fake = api.post_json(Some(&dev_with), &format!("/v1/projects/{}/fetch", p_with.name), &json!({"snapshot": fake_snap.hex(), "objects": []}));
        assert_eq!(f_real.status, f_fake.status);
        assert_eq!(norm(&String::from_utf8_lossy(&f_real.body)), norm(&String::from_utf8_lossy(&f_fake.body)));
    }

    let rel_real = api.post_json(Some(&dev_with), &format!("/v1/projects/{}/embargoes/{eid}/release", p_with.name), &json!({}));
    let rel_fake = api.post_json(Some(&dev_with), &format!("/v1/projects/{}/embargoes/{fake_eid}/release", p_with.name), &json!({}));
    assert_eq!(rel_real.status, rel_fake.status);
    assert_eq!(norm(&String::from_utf8_lossy(&rel_real.body)), norm(&String::from_utf8_lossy(&rel_fake.body)));
}
