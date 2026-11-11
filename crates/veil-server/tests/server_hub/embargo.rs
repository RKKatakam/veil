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
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        let active: i64 = hub
            .rt
            .block_on(sqlx::query_scalar("SELECT COUNT(*) FROM view_fills WHERE project_id = $1").bind(pid).fetch_one(&h.db))
            .unwrap();
        if active == 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
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
            catch_up(hub, project);
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
            "log?rev=main&path=src/lib.rs".to_string(),
            "log?rev=main&path=src/embargo_fix.rs".to_string(),
            "tree?rev=main&path=src".to_string(),
            "file?rev=main&path=src/lib.rs".to_string(),
            format!("resolve?prefix={}", &merge_id.hex()[..8]),
            format!("resolve?prefix={}", &fix_id.hex()[..8]),
        ] {
            let r = api.get(tok, &format!("/v1/projects/{}/q/{route}", p.name));
            assert_eq!(r.status, 200, "{who} q/{route}: {}", String::from_utf8_lossy(&r.body));
            assert_no_str(&String::from_utf8_lossy(&r.body), &[FIX_MARK, MSG_MARK, "embargo_fix.rs", &eid], who);
        }
        let log_embargo_file = api.get(tok, &format!("/v1/projects/{}/q/log?rev=main&path=src/embargo_fix.rs", p.name));
        assert_eq!(log_embargo_file.status, 200);
        assert_no_str(&String::from_utf8_lossy(&log_embargo_file.body), &[FIX_MARK, MSG_MARK, "embargo_fix.rs", &eid], who);
        for rev in [&embargo_branch, &merge_id.hex(), &fix_id.hex()] {
            for kind in ["log", "show", "tree"] {
                let r = api.get(tok, &format!("/v1/projects/{}/q/{kind}?rev={rev}", p.name));
                assert_eq!(r.status, 404, "{who} q/{kind}?rev={rev}: {}", String::from_utf8_lossy(&r.body));
                assert_no_str(&String::from_utf8_lossy(&r.body), &[FIX_MARK, MSG_MARK], who);
            }
            let rf = api.get(tok, &format!("/v1/projects/{}/q/file?rev={rev}&path=src/lib.rs", p.name));
            assert_eq!(rf.status, 404, "{who} q/file?rev={rev}: {}", String::from_utf8_lossy(&rf.body));
            assert_no_str(&String::from_utf8_lossy(&rf.body), &[FIX_MARK, MSG_MARK], who);
            let rd = api.get(tok, &format!("/v1/projects/{}/q/diff?from=main&to={rev}", p.name));
            assert_eq!(rd.status, 404, "{who} q/diff?to={rev}: {}", String::from_utf8_lossy(&rd.body));
            assert_no_str(&String::from_utf8_lossy(&rd.body), &[FIX_MARK, MSG_MARK], who);
            let ra = api.post_json(tok, &format!("/v1/projects/{}/q/ancestry", p.name), &json!({"pairs": [["main", rev]]}));
            assert_eq!(ra.status, 404, "{who} q/ancestry {rev}: {}", String::from_utf8_lossy(&ra.body));
            assert_no_str(&String::from_utf8_lossy(&ra.body), &[FIX_MARK, MSG_MARK], who);
        }

        // Search and grep: nothing of the embargoed fix or message is indexed or found.
        for q in ["EMBARGO-SECRET", "EMBARGO-COMMIT", "embargo_fix"] {
            for kind in ["code", "path"] {
                let s = api.get(tok, &format!("/v1/projects/{}/q/search?q={q}&kind={kind}", p.name));
                assert_eq!(s.status, 200, "{who} search {q} ({kind}): {}", String::from_utf8_lossy(&s.body));
                assert_eq!(s.json()["results"].as_array().unwrap().len(), 0, "{who} search results for {q} ({kind})");
                assert_no_str(&String::from_utf8_lossy(&s.body), &[FIX_MARK, MSG_MARK], who);
            }

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

    // 3. Blame (`vl blame`) and file history (`vl log`) in both a full clone and a thin clone of `dev`:
    let dev_full = p.dev.dir("full");
    p.dev.ok(p.dev.home.path(), &["clone", "--full", &hub.url(&p.name), dev_full.to_str().unwrap()]);
    let blame_full = p.dev.ok(&dev_full, &["blame", "src/lib.rs"]);
    assert_no_str(&blame_full, &[FIX_MARK, MSG_MARK, &eid, &p.sec.name], "dev full blame");
    let fhist_full = p.dev.ok(&dev_full, &["log", "src/lib.rs"]);
    assert_no_str(&fhist_full, &[FIX_MARK, MSG_MARK, &eid, &p.sec.name], "dev full file history");
    assert_no_marker(&everything_in(&dev_full), &[FIX_MARK, MSG_MARK, &eid], "dev full clone");

    let dev_thin = p.dev.dir("thin");
    p.dev.ok(p.dev.home.path(), &["clone", &hub.url(&p.name), dev_thin.to_str().unwrap()]);
    let blame_thin = p.dev.ok(&dev_thin, &["blame", "src/lib.rs"]);
    assert_no_str(&blame_thin, &[FIX_MARK, MSG_MARK, &eid, &p.sec.name], "dev thin blame");
    let fhist_thin = p.dev.ok(&dev_thin, &["log", "src/lib.rs"]);
    assert_no_str(&fhist_thin, &[FIX_MARK, MSG_MARK, &eid, &p.sec.name], "dev thin file history");
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
    catch_up(&hub, &p.name);
    hub = hub.restart(|url| {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let db = veil_server::db::connect(url, 1).await.unwrap();
            let _ = sqlx::query("DELETE FROM view_fills").execute(&db).await;
            db.close().await;
        });
    });
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

    let r1 = hub.rt.block_on(veil_server::embargo::release_due(&hub.hub()));
    assert!(r1.is_err(), "injected release failure 1 must return Err");
    let r2 = hub.rt.block_on(veil_server::embargo::release_due(&hub.hub()));
    assert!(r2.is_err(), "injected release failure 2 must return Err");
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

    // Walk `main` down to `initial_main`: check that each change landed on `main` once,
    // and that every snapshot signed at release records its author in `snapshots.author` (BUG-1581).
    catch_up(&hub, &p.name);
    let qlog = hub.api().get(Some(&p.admin.token()), &format!("/v1/projects/{}/q/log?rev=main&n=20", p.name));
    assert_eq!(qlog.status, 200);
    let entries = qlog.json()["entries"].as_array().unwrap().clone();
    let since_init: Vec<&Value> = entries
        .iter()
        .take_while(|it| it["snapshot_id"].as_str().unwrap() != initial_main.hex())
        .collect();
    assert_eq!(
        since_init.len(),
        3,
        "expected concurrent work + 2 embargoed changes landed once on main since initial_main, got: {since_init:#?}"
    );
    let h = hub.hub();
    for entry in &since_init {
        let sid = entry["snapshot_id"].as_str().unwrap();
        let author_id: i64 = hub
            .rt
            .block_on(sqlx::query_scalar("SELECT author FROM snapshots WHERE id = $1").bind(sid).fetch_one(&h.db))
            .unwrap();
        assert!(author_id > 0, "snapshot {sid} landed at release must record snapshots.author > 0");
    }

    // And derived queries & search now see the released changes on `main`.
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
        assert_eq!(h_real.status, 404);
        assert_eq!(h_real.status, h_fake.status);
        assert_eq!(norm(&String::from_utf8_lossy(&h_real.body)), norm(&String::from_utf8_lossy(&h_fake.body)));

        let f_real = api.post_json(Some(&dev_with), &format!("/v1/projects/{}/fetch", p_with.name), &json!({"snapshot": real_snap.hex(), "objects": []}));
        let f_fake = api.post_json(Some(&dev_with), &format!("/v1/projects/{}/fetch", p_with.name), &json!({"snapshot": fake_snap.hex(), "objects": []}));
        assert_eq!(f_real.status, 404);
        assert_eq!(f_real.status, f_fake.status);
        assert_eq!(norm(&String::from_utf8_lossy(&f_real.body)), norm(&String::from_utf8_lossy(&f_fake.body)));

        let c_real = api.post_json(
            Some(&dev_with),
            &format!("/v1/projects/{}/changes", p_with.name),
            &json!({"base": real_snap.hex(), "edits": [{"path": "src/x.rs", "put": {"text": "x"}}], "description": "probe"}),
        );
        let c_fake = api.post_json(
            Some(&dev_with),
            &format!("/v1/projects/{}/changes", p_with.name),
            &json!({"base": fake_snap.hex(), "edits": [{"path": "src/x.rs", "put": {"text": "x"}}], "description": "probe"}),
        );
        assert_eq!(c_real.status, 404);
        assert_eq!(c_real.status, c_fake.status);
        assert_eq!(norm(&String::from_utf8_lossy(&c_real.body)), norm(&String::from_utf8_lossy(&c_fake.body)));

        let l_real = api.post_json(
            Some(&dev_with),
            &format!("/v1/projects/{}/land", p_with.name),
            &json!({"onto": "main", "base": real_snap.hex(), "edits": [{"path": "src/x.rs", "put": {"text": "x"}}], "description": "probe", "wait": true}),
        );
        let l_fake = api.post_json(
            Some(&dev_with),
            &format!("/v1/projects/{}/land", p_with.name),
            &json!({"onto": "main", "base": fake_snap.hex(), "edits": [{"path": "src/x.rs", "put": {"text": "x"}}], "description": "probe", "wait": true}),
        );
        assert_eq!(l_real.status, 404);
        assert_eq!(l_real.status, l_fake.status);
        assert_eq!(norm(&String::from_utf8_lossy(&l_real.body)), norm(&String::from_utf8_lossy(&l_fake.body)));
    }

    let rel_real = api.post_json(Some(&dev_with), &format!("/v1/projects/{}/embargoes/{eid}/release", p_with.name), &json!({}));
    let rel_fake = api.post_json(Some(&dev_with), &format!("/v1/projects/{}/embargoes/{fake_eid}/release", p_with.name), &json!({}));
    assert_eq!(rel_real.status, 404);
    assert_eq!(rel_real.status, rel_fake.status);
    assert_eq!(norm(&String::from_utf8_lossy(&rel_real.body)), norm(&String::from_utf8_lossy(&rel_fake.body)));
}

/// Review 1 (S22 × S14): blame and file history (`q/blame`, `q/history`, with
/// `follow` across renames) never show embargoed content, paths or versions to
/// anyone outside the embargo, and answer exactly as for a missing path.
#[test]
fn s14_blame_and_file_history_never_show_embargoed_content_paths_or_versions() {
    const EMB_LINE: &str = "EMBARGO-BLAME-SECRET-7101";
    const EMB_MSG: &str = "EMBARGO-BLAME-MSG-7102";
    const ORIG_LINE: &str = "PUBLIC-BEFORE-RENAME-7103";

    let hub = TestHub::start();
    let p = setup_project(&hub);

    // 1. Add a public file `src/orig.rs` on `main` and rename it on `main` to `src/pub_renamed.rs`
    //    so `follow=true` has a public rename control, while also keeping `src/stay.rs` to be
    //    renamed inside the embargo.
    write_files(
        &p.dir,
        &[
            ("src/orig.rs", &format!("{ORIG_LINE}\n")),
            ("src/stay.rs", &format!("{ORIG_LINE}\n")),
        ],
    );
    p.admin.ok(&p.dir, &["commit", "-m", "add orig and stay"]);
    std::fs::remove_file(p.dir.join("src/orig.rs")).unwrap();
    write_files(&p.dir, &[("src/pub_renamed.rs", &format!("{ORIG_LINE}\n"))]);
    p.admin.ok(&p.dir, &["commit", "-m", "rename orig to pub_renamed"]);
    p.admin.ok(&p.dir, &["push"]);

    // 2. `p.sec` creates an embargo for `security` that:
    //    - modifies `src/lib.rs` with `EMB_LINE`,
    //    - renames `src/stay.rs` to `src/emb_renamed.rs` (adding `EMB_LINE`),
    //    - adds `src/emb_only.rs`.
    p.admin.ok(&p.dir, &["group", "add", "devs", &p.sec.name]);
    let sec_dir = p.sec.dir("sec-blame");
    p.sec.ok(p.sec.home.path(), &["clone", &hub.url(&p.name), sec_dir.to_str().unwrap()]);
    std::fs::remove_file(sec_dir.join("src/stay.rs")).unwrap();
    write_files(
        &sec_dir,
        &[
            ("src/lib.rs", &format!("{PUBLIC_MARK}\n{EMB_LINE}\n")),
            ("src/emb_renamed.rs", &format!("{ORIG_LINE}\n{EMB_LINE}\n")),
            ("src/emb_only.rs", &format!("{EMB_LINE}\n")),
        ],
    );
    p.sec.ok(&sec_dir, &["commit", "--no-advance", "-m", EMB_MSG]);
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
        &["merge", "@-", "--into", "main", "--embargo-for", "security", "--until", &until, "-m", EMB_MSG],
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
    let ebranch = format!("embargo/{eid}");
    let markers = [EMB_LINE, EMB_MSG, "emb_renamed.rs", "emb_only.rs", &eid];

    for (who, tok) in [("dev", Some(dev_tok.as_str())), ("fin", Some(fin_tok.as_str())), ("anon", None)] {
        for follow in [false, true] {
            // (a) Control: public rename on `main` works and `follow=true` crosses the public rename.
            let b_pub = api.get(tok, &format!("/v1/projects/{}/q/blame?rev=main&path=src/pub_renamed.rs&follow={follow}", p.name));
            assert_eq!(b_pub.status, 200, "{who} blame pub_renamed follow={follow}: {}", String::from_utf8_lossy(&b_pub.body));
            let h_pub = api.get(tok, &format!("/v1/projects/{}/q/history?rev=main&path=src/pub_renamed.rs&follow={follow}", p.name));
            assert_eq!(h_pub.status, 200, "{who} history pub_renamed follow={follow}: {}", String::from_utf8_lossy(&h_pub.body));
            if follow {
                assert_eq!(h_pub.json()["entries"].as_array().unwrap().len(), 2, "public rename history with follow=true");
            }

            // (b) Existing paths `src/lib.rs` and `src/stay.rs` on `main`: never show embargoed content, paths or versions.
            for path in ["src/lib.rs", "src/stay.rs"] {
                let b = api.get(tok, &format!("/v1/projects/{}/q/blame?rev=main&path={path}&follow={follow}", p.name));
                assert_eq!(b.status, 200, "{who} blame {path}: {}", String::from_utf8_lossy(&b.body));
                assert_no_str(&String::from_utf8_lossy(&b.body), &markers, who);
                let h = api.get(tok, &format!("/v1/projects/{}/q/history?rev=main&path={path}&follow={follow}", p.name));
                assert_eq!(h.status, 200, "{who} history {path}: {}", String::from_utf8_lossy(&h.body));
                assert_no_str(&String::from_utf8_lossy(&h.body), &markers, who);
            }

            // (c) Embargo-only paths (`src/emb_only.rs` and renamed `src/emb_renamed.rs`) on `main`
            //     answer byte-for-byte identically to a missing path (`src/no_such_path_7100.rs`).
            let b_miss = api.get(tok, &format!("/v1/projects/{}/q/blame?rev=main&path=src/no_such_path_7100.rs&follow={follow}", p.name));
            let h_miss = api.get(tok, &format!("/v1/projects/{}/q/history?rev=main&path=src/no_such_path_7100.rs&follow={follow}", p.name));
            assert_eq!(b_miss.status, 404);
            assert_eq!(h_miss.status, 404);
            for epath in ["src/emb_only.rs", "src/emb_renamed.rs"] {
                let b_emb = api.get(tok, &format!("/v1/projects/{}/q/blame?rev=main&path={epath}&follow={follow}", p.name));
                let h_emb = api.get(tok, &format!("/v1/projects/{}/q/history?rev=main&path={epath}&follow={follow}", p.name));
                assert_eq!(b_emb.status, b_miss.status);
                assert_eq!(b_emb.body, b_miss.body, "{who} blame {epath} vs missing path");
                assert_eq!(h_emb.status, h_miss.status);
                assert_eq!(h_emb.body, h_miss.body, "{who} history {epath} vs missing path");
            }

            // (d) Asking at embargo revisions (`embargo/<eid>`, `merge_id`, `fix_id`) is refused with 404,
            //     identical to a fake revision.
            let fake_rev = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
            let b_fake = api.get(tok, &format!("/v1/projects/{}/q/blame?rev={fake_rev}&path=src/lib.rs&follow={follow}", p.name));
            let h_fake = api.get(tok, &format!("/v1/projects/{}/q/history?rev={fake_rev}&path=src/lib.rs&follow={follow}", p.name));
            assert_eq!(b_fake.status, 404);
            assert_eq!(h_fake.status, 404);
            for rev in [ebranch.as_str(), &merge_id.hex(), &fix_id.hex()] {
                for path in ["src/lib.rs", "src/stay.rs", "src/emb_only.rs", "src/emb_renamed.rs"] {
                    let b_r = api.get(tok, &format!("/v1/projects/{}/q/blame?rev={rev}&path={path}&follow={follow}", p.name));
                    let h_r = api.get(tok, &format!("/v1/projects/{}/q/history?rev={rev}&path={path}&follow={follow}", p.name));
                    assert_eq!(b_r.status, 404);
                    assert_eq!(b_r.body, b_fake.body);
                    assert_eq!(h_r.status, 404);
                    assert_eq!(h_r.body, h_fake.body);
                }
            }

            // (e) Forging a history `after` cursor pointing at `merge_id` or `fix_id` is refused with 404.
            for id in [merge_id, fix_id] {
                let cursor = format!("{}.{}", id.hex(), hex::encode("src/lib.rs"));
                let hc = api.get(tok, &format!("/v1/projects/{}/q/history?after={cursor}&follow={follow}", p.name));
                assert_eq!(hc.status, 404, "{who} forged cursor {cursor}: {}", String::from_utf8_lossy(&hc.body));
                assert_no_str(&String::from_utf8_lossy(&hc.body), &markers, who);
            }
        }
    }
}

/// Review 2 (S22 × S11): an agent session sees and lands embargoed work only if
/// its person is in the embargo; a narrowed session stays within its paths
/// there too; and the release landing goes through the same agent rules if an
/// agent asks for it.
#[test]
fn s11_agent_sessions_and_narrowing_on_embargoes_and_release_landing() {
    const EMB_IN_MARK: &str = "EMBARGO-AGENT-INSIDE-7201";
    const EMB_OUT_MARK: &str = "EMBARGO-AGENT-OUTSIDE-7202";
    const NARROWED_WRITE: &str = "this agent session is narrowed: this would change files outside its paths";
    const NARROWED_MOVE: &str = "this agent session is narrowed: this would change files outside its paths";
    const ACCESS_MOVE: &str = "an agent session never moves a branch onto a change of a file that decides access or review (.veilpolicy, .veilrules)";

    let hub = TestHub::start();
    let p = setup_project(&hub);
    p.admin.ok(&p.dir, &["group", "add", "devs", &p.sec.name]);
    let api = hub.api();

    // Put `src/api/in.rs` and `src/other/out.rs` on `main`.
    write_files(
        &p.dir,
        &[
            ("src/api/in.rs", "pub fn inside() {}\n"),
            ("src/other/out.rs", "pub fn outside() {}\n"),
        ],
    );
    p.admin.ok(&p.dir, &["commit", "-m", "initial api and other"]);
    p.admin.ok(&p.dir, &["push"]);

    // `p.sec` creates an embargo for `security` touching `src/api/in.rs` and `src/other/out.rs`.
    let sec_dir = p.sec.dir("sec-s11");
    p.sec.ok(p.sec.home.path(), &["clone", &hub.url(&p.name), sec_dir.to_str().unwrap()]);
    write_files(
        &sec_dir,
        &[
            ("src/api/in.rs", &format!("pub fn inside() {{}} // {EMB_IN_MARK}\n")),
            ("src/other/out.rs", &format!("pub fn outside() {{}} // {EMB_OUT_MARK}\n")),
        ],
    );
    p.sec.ok(&sec_dir, &["commit", "--no-advance", "-m", "embargoed in and out"]);
    let until = iso_utc(veil_core::now_millis() + 3_600_000);
    let merge_out = p.sec.ok(
        &sec_dir,
        &["merge", "@-", "--into", "main", "--embargo-for", "security", "--until", &until, "-m", "merge embargo s11"],
    );
    let eid = parse_embargo_id(&merge_out);
    p.sec.ok(&sec_dir, &["push"]);
    let ebranch = format!("embargo/{eid}");

    let make_agent = |tok: &str, only: &[&str]| -> String {
        let r = api.post_json(
            Some(tok),
            "/v1/sessions/agent",
            &json!({"project": p.name, "attribution": {"agent": "claude-code/2.3", "task": "TASK-S22"}, "only": only}),
        );
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        r.json()["token"].as_str().unwrap().to_string()
    };

    let dev_agent = make_agent(&p.dev.token(), &[]);
    let sec_agent_wide = make_agent(&p.sec.token(), &[]);
    let sec_agent_narrow = make_agent(&p.sec.token(), &["src/api"]);

    // 1. Outsider's agent session (`dev_agent`, `dev` not in `security`) cannot see or release the embargo.
    let dev_tips = api.tips(Some(&dev_agent), &p.name).unwrap();
    assert!(!dev_tips.branches.contains_key(&ebranch));
    assert!(dev_tips.embargoes.is_empty());
    let dev_rel = api.post_json(Some(&dev_agent), &format!("/v1/projects/{}/embargoes/{eid}/release", p.name), &json!({}));
    assert_eq!(dev_rel.status, 404, "outsider agent release: {}", String::from_utf8_lossy(&dev_rel.body));

    // 2. Insider's agent session (`sec_agent_wide`, `p.sec` in `security`) sees the embargo branch and record.
    let sec_tips = api.tips(Some(&sec_agent_wide), &p.name).unwrap();
    let etip_proj = sec_tips.branches[&ebranch];
    assert!(sec_tips.embargoes.iter().any(|e| e.id == eid));

    // 3. Insider's narrowed agent session (`sec_agent_narrow`, narrowed to `src/api`):
    //    - `fetch` on `etip_proj` serves `src/api/in.rs`, and refuses `src/other/out.rs` with 404.
    let h_res = api.history(&sec_agent_narrow, &p.name, &[etip_proj]);
    assert_eq!(h_res.status, 200, "{}", String::from_utf8_lossy(&h_res.body));
    // Find object ids of `src/api/in.rs` and `src/other/out.rs` using `sec_agent_wide`.
    let root_tree = {
        let (_, raw) = h_res.frames().into_iter().find(|(id, _)| *id == etip_proj).unwrap();
        match veil_core::object::Object::decode(&raw).unwrap() {
            veil_core::object::Object::Snapshot(s) => s.tree,
            _ => panic!("expected snapshot"),
        }
    };
    let fetch_wide = api.post_json(
        Some(&sec_agent_wide),
        &format!("/v1/projects/{}/fetch", p.name),
        &json!({"snapshot": etip_proj.hex(), "objects": [{"path": "", "id": root_tree.hex()}]}),
    );
    assert_eq!(fetch_wide.status, 200);
    let src_tree_id = match veil_core::object::Object::decode(&fetch_wide.frames()[0].1).unwrap() {
        veil_core::object::Object::Tree(t) => t.get("src").unwrap().id,
        _ => panic!("expected tree"),
    };
    let fetch_src = api.post_json(
        Some(&sec_agent_wide),
        &format!("/v1/projects/{}/fetch", p.name),
        &json!({"snapshot": etip_proj.hex(), "objects": [{"path": "src", "id": src_tree_id.hex()}]}),
    );
    let (api_tree_id, other_tree_id) = match veil_core::object::Object::decode(&fetch_src.frames()[0].1).unwrap() {
        veil_core::object::Object::Tree(t) => (t.get("api").unwrap().id, t.get("other").unwrap().id),
        _ => panic!("expected tree"),
    };
    let fetch_api_other = api.post_json(
        Some(&sec_agent_wide),
        &format!("/v1/projects/{}/fetch", p.name),
        &json!({"snapshot": etip_proj.hex(), "objects": [{"path": "src/api", "id": api_tree_id.hex()}, {"path": "src/other", "id": other_tree_id.hex()}]}),
    );
    let frames = fetch_api_other.frames();
    let in_blob_id = match veil_core::object::Object::decode(&frames[0].1).unwrap() {
        veil_core::object::Object::Tree(t) => t.get("in.rs").unwrap().id,
        _ => panic!("expected tree"),
    };
    let out_blob_id = match veil_core::object::Object::decode(&frames[1].1).unwrap() {
        veil_core::object::Object::Tree(t) => t.get("out.rs").unwrap().id,
        _ => panic!("expected tree"),
    };

    // Narrowed session fetches `src/api/in.rs` (200) and is refused on `src/other/out.rs` (404).
    let f_in = api.post_json(
        Some(&sec_agent_narrow),
        &format!("/v1/projects/{}/fetch", p.name),
        &json!({"snapshot": etip_proj.hex(), "objects": [{"path": "src/api/in.rs", "id": in_blob_id.hex()}]}),
    );
    assert_eq!(f_in.status, 200);
    assert!(String::from_utf8_lossy(&f_in.frames()[0].1).contains(EMB_IN_MARK));

    let f_out = api.post_json(
        Some(&sec_agent_narrow),
        &format!("/v1/projects/{}/fetch", p.name),
        &json!({"snapshot": etip_proj.hex(), "objects": [{"path": "src/other/out.rs", "id": out_blob_id.hex()}]}),
    );
    assert_eq!(f_out.status, 404);
    assert_no_str(&String::from_utf8_lossy(&f_out.body), &[EMB_OUT_MARK], "narrowed fetch outside");

    //    - Narrowed session writing outside its paths on `etip_proj` is refused with `NARROWED_WRITE`.
    let w_out = api.post_json(
        Some(&sec_agent_narrow),
        &format!("/v1/projects/{}/changes", p.name),
        &json!({"base": etip_proj.hex(), "description": "outside", "edits": [{"path": "src/other/out.rs", "put": {"text": "bad\n"}}]}),
    );
    assert_eq!(w_out.status, 403);
    assert_eq!(w_out.json()["code"], "agent_session");
    assert_eq!(w_out.json()["message"], NARROWED_WRITE);

    //    - Narrowed session calling `/embargoes/{eid}/release` on an embargo that touches `src/other/out.rs`
    //      (outside `src/api`) is refused by `landing::agent_stack` with `403 agent_session` (`NARROWED_MOVE`)!
    let rel_narrow = api.post_json(
        Some(&sec_agent_narrow),
        &format!("/v1/projects/{}/embargoes/{eid}/release", p.name),
        &json!({}),
    );
    assert_eq!(rel_narrow.status, 403, "narrowed agent release outside paths: {}", String::from_utf8_lossy(&rel_narrow.body));
    assert_eq!(rel_narrow.json()["code"], "agent_session");
    assert_eq!(rel_narrow.json()["message"], NARROWED_MOVE);

    //    - Unnarrowed agent session (`sec_agent_wide`) CAN release `eid` because `eid` only touches normal code files.
    let rel_wide = api.post_json(
        Some(&sec_agent_wide),
        &format!("/v1/projects/{}/embargoes/{eid}/release", p.name),
        &json!({}),
    );
    assert_eq!(rel_wide.status, 200, "wide agent release: {}", String::from_utf8_lossy(&rel_wide.body));
    assert_eq!(rel_wide.json()["released"], true);

    // 4. An embargo created by an admin that changes `.veilrules` (an access/review file):
    //    any agent session (`admin_agent`) asking to release it is refused with `ACCESS_MOVE`,
    //    whereas the admin's own person session releases it.
    p.admin.ok(&p.dir, &["pull"]);
    p.admin.ok(&p.dir, &["new", "main"]);
    write_files(&p.dir, &[(".veilrules", "[protected]\nbranches = []\n")]);
    p.admin.ok(&p.dir, &["commit", "--no-advance", "-m", "embargoed veilrules"]);
    let out_rules = p.admin.ok(
        &p.dir,
        &["merge", "@-", "--into", "main", "--embargo-for", "security", "--until", &until, "-m", "merge veilrules embargo"],
    );
    let eid_rules = parse_embargo_id(&out_rules);
    p.admin.ok(&p.dir, &["push"]);

    let admin_agent = make_agent(&p.admin.token(), &[]);
    let rel_rules_agent = api.post_json(
        Some(&admin_agent),
        &format!("/v1/projects/{}/embargoes/{eid_rules}/release", p.name),
        &json!({}),
    );
    assert_eq!(rel_rules_agent.status, 403, "agent releasing .veilrules embargo: {}", String::from_utf8_lossy(&rel_rules_agent.body));
    assert_eq!(rel_rules_agent.json()["code"], "agent_session");
    assert_eq!(rel_rules_agent.json()["message"], ACCESS_MOVE);

    // Control: the admin's person session releases `eid_rules` and it lands.
    let rel_rules_person = api.post_json(
        Some(&p.admin.token()),
        &format!("/v1/projects/{}/embargoes/{eid_rules}/release", p.name),
        &json!({}),
    );
    assert_eq!(rel_rules_person.status, 200, "person releasing .veilrules embargo: {}", String::from_utf8_lossy(&rel_rules_person.body));
    assert_eq!(rel_rules_person.json()["released"], true);

    // 5. A narrowed session (`sec_agent_narrow`, narrowed to `src/api`) CAN release an embargo whose
    //    changes are wholly inside `src/api`!
    p.sec.ok(&sec_dir, &["pull"]);
    p.sec.ok(&sec_dir, &["new", "main"]);
    write_files(&sec_dir, &[("src/api/only_in.rs", "pub const IN: u32 = 1;\n")]);
    p.sec.ok(&sec_dir, &["commit", "--no-advance", "-m", "embargo inside src/api"]);
    let out_in = p.sec.ok(
        &sec_dir,
        &["merge", "@-", "--into", "main", "--embargo-for", "security", "--until", &until, "-m", "merge inside src/api"],
    );
    let eid_in = parse_embargo_id(&out_in);
    p.sec.ok(&sec_dir, &["push"]);

    let rel_in_narrow = api.post_json(
        Some(&sec_agent_narrow),
        &format!("/v1/projects/{}/embargoes/{eid_in}/release", p.name),
        &json!({}),
    );
    assert_eq!(rel_in_narrow.status, 200, "narrowed agent releasing embargo inside its paths: {}", String::from_utf8_lossy(&rel_in_narrow.body));
    assert_eq!(rel_in_narrow.json()["released"], true);
}

/// Review 3 (S22 × S6): the daemon never serves an embargoed object to a
/// client outside the embargo. A grant for a projection without the embargo
/// must not reach its objects.
#[test]
fn s6_daemon_never_serves_an_embargoed_object_outside_the_embargo() {
    use std::{
        io::{Read, Write},
        os::unix::net::UnixStream,
    };
    use veil_core::hub::grant::{sign_request, BatchRequest, ChainWant, Grant};

    const EMB_BLOB_MARK: &str = "EMBARGO-DAEMON-SECRET-7301";
    let hub = TestHub::start();
    let p = setup_project(&hub);
    p.admin.ok(&p.dir, &["group", "add", "devs", &p.sec.name]);

    // 1. Start the daemon in `p.sec`'s Veil home and warm it with an embargoed line's objects.
    let daemon_out = p.sec.ok(p.sec.home.path(), &["daemon", "start"]);
    assert!(daemon_out.contains("the Veil daemon runs"), "{daemon_out}");
    let socket = p.sec.home.path().join("veil/daemon/sock");

    let sec_dir = p.sec.dir("sec-daemon");
    p.sec.ok(p.sec.home.path(), &["clone", &hub.url(&p.name), sec_dir.to_str().unwrap()]);
    write_files(
        &sec_dir,
        &[
            ("src/lib.rs", &format!("{PUBLIC_MARK}\n{EMB_BLOB_MARK}\n")),
            ("src/emb_daemon.rs", &format!("pub const S: &str = \"{EMB_BLOB_MARK}\";\n")),
        ],
    );
    p.sec.ok(&sec_dir, &["commit", "--no-advance", "-m", "embargo for daemon test"]);
    let until = iso_utc(veil_core::now_millis() + 3_600_000);
    let merge_out = p.sec.ok(
        &sec_dir,
        &["merge", "@-", "--into", "main", "--embargo-for", "security", "--until", &until, "-m", "merge embargo daemon"],
    );
    let eid = parse_embargo_id(&merge_out);
    p.sec.ok(&sec_dir, &["push"]);
    let ebranch = format!("embargo/{eid}");

    let api = hub.api();
    let upstream = hub.authority();
    let ask_daemon = |req: &Value| -> (Vec<(ObjectId, Vec<u8>)>, Value) {
        let mut s = UnixStream::connect(&socket).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
        let mut body = vec![1u8];
        body.extend_from_slice(&serde_json::to_vec(req).unwrap());
        let mut msg = vec![b'Q'];
        msg.extend_from_slice(&(body.len() as u32).to_be_bytes());
        msg.extend_from_slice(&body);
        s.write_all(&msg).unwrap();
        let mut got = Vec::new();
        loop {
            let mut head = [0u8; 5];
            s.read_exact(&mut head).unwrap();
            let len = u32::from_be_bytes(head[1..].try_into().unwrap()) as usize;
            let mut payload = vec![0u8; len];
            s.read_exact(&mut payload).unwrap();
            match head[0] {
                b'A' | b'P' => {}
                b'O' => {
                    let id = ObjectId(payload[..32].try_into().unwrap());
                    got.push((id, payload[32..].to_vec()));
                }
                b'E' => return (got, serde_json::from_slice(&payload).unwrap()),
                k => panic!("unexpected daemon frame {k}"),
            }
        }
    };

    // 2. `p.sec` walks `embargo/<eid>` through the daemon so that the embargo's root tree,
    //    `src` tree, and embargoed blobs are all stored in the daemon's local cache!
    let sec_tips = api.tips(Some(&p.sec.token()), &p.name).unwrap();
    let sec_grant_str = sec_tips.grants.get(&ebranch).expect("sec gets grant for embargo branch").clone();
    let grant_key = sec_tips.grant_key.as_ref().unwrap().clone();
    let sec_grant = Grant::verify(&sec_grant_str, &grant_key).unwrap();
    let sec_id = p.sec.identity();
    let emb_root = sec_grant.body.root;

    let batch_with = |grant_str: &str, signer: Option<&veil_core::Identity>, wants: Vec<ChainWant>| -> (Vec<(ObjectId, Vec<u8>)>, Value) {
        let ids: Vec<ObjectId> = wants.iter().map(|w| w.id).collect();
        let ts = veil_core::now_millis();
        let signature = Grant::verify(grant_str, &grant_key).and_then(|g| signer.map(|i| sign_request(i, &g, ts, &ids)));
        let req = BatchRequest {
            grant: grant_str.to_string(),
            ts,
            signature,
            wants,
            skip: Vec::new(),
        };
        ask_daemon(&json!({"op": "batch", "upstream": upstream, "project": p.name, "batch": req}))
    };

    let (got_root, _) = batch_with(&sec_grant_str, Some(&sec_id), vec![ChainWant { chain: vec![], id: emb_root }]);
    assert_eq!(got_root.len(), 1);
    let emb_src_tree = match veil_core::object::Object::decode(&got_root[0].1).unwrap() {
        veil_core::object::Object::Tree(t) => t.get("src").unwrap().id,
        _ => panic!("expected tree"),
    };
    let (got_src, _) = batch_with(
        &sec_grant_str,
        Some(&sec_id),
        vec![ChainWant { chain: vec![emb_root], id: emb_src_tree }],
    );
    assert_eq!(got_src.len(), 1);
    let (emb_lib_blob, emb_new_blob) = match veil_core::object::Object::decode(&got_src[0].1).unwrap() {
        veil_core::object::Object::Tree(t) => (t.get("lib.rs").unwrap().id, t.get("emb_daemon.rs").unwrap().id),
        _ => panic!("expected tree"),
    };
    let (got_blobs, _) = batch_with(
        &sec_grant_str,
        Some(&sec_id),
        vec![
            ChainWant { chain: vec![emb_root, emb_src_tree], id: emb_lib_blob },
            ChainWant { chain: vec![emb_root, emb_src_tree], id: emb_new_blob },
        ],
    );
    assert_eq!(got_blobs.len(), 2);
    assert!(got_blobs.iter().any(|(_, b)| String::from_utf8_lossy(b).contains(EMB_BLOB_MARK)));

    // Confirm warm store hit for `p.sec` (poll until epochs are confirmed in the daemon store).
    let t0 = std::time::Instant::now();
    loop {
        let (got_warm, end) = batch_with(
            &sec_grant_str,
            Some(&sec_id),
            vec![ChainWant { chain: vec![emb_root, emb_src_tree], id: emb_new_blob }],
        );
        assert_eq!(got_warm.len(), 1);
        if end["from_store"] == 1 {
            break;
        }
        assert!(t0.elapsed() < Duration::from_secs(10), "p.sec must hit the warm daemon store: {end}");
        std::thread::sleep(Duration::from_millis(20));
    }

    // 3. Outsiders (`dev`, `fin`, anonymous) have grants for `main` (without the embargo).
    //    First warm their grants so their epochs are confirmed in the daemon, and find their `main` trees.
    for who in [Some(&p.dev), Some(&p.fin), None] {
        let tips = api.tips(who.map(|u| u.token()).as_deref(), &p.name).unwrap();
        assert!(!tips.grants.contains_key(&ebranch), "outsider must not receive a grant for {ebranch}");
        let g_str = tips.grants["main"].clone();
        let g = Grant::verify(&g_str, &grant_key).unwrap();
        let signer = who.map(|u| u.identity());
        let main_root = g.body.root;

        let (got_mr, _) = batch_with(&g_str, signer.as_ref(), vec![ChainWant { chain: vec![], id: main_root }]);
        assert_eq!(got_mr.len(), 1);
        let main_src = match veil_core::object::Object::decode(&got_mr[0].1).unwrap() {
            veil_core::object::Object::Tree(t) => t.get("src").unwrap().id,
            _ => panic!("expected tree"),
        };
        let (got_ms, _) = batch_with(&g_str, signer.as_ref(), vec![ChainWant { chain: vec![main_root], id: main_src }]);
        assert_eq!(got_ms.len(), 1);

        // Try every chain the outsider can construct to reach the embargoed trees and blobs
        // under their confirmed `main` grant:
        for want in [
            ChainWant { chain: vec![], id: emb_root },
            ChainWant { chain: vec![main_root], id: emb_src_tree },
            ChainWant { chain: vec![main_root, main_src], id: emb_lib_blob },
            ChainWant { chain: vec![main_root, main_src], id: emb_new_blob },
            ChainWant { chain: vec![main_root, emb_src_tree], id: emb_lib_blob },
            ChainWant { chain: vec![main_root, emb_src_tree], id: emb_new_blob },
            ChainWant { chain: vec![emb_root, emb_src_tree], id: emb_lib_blob },
            ChainWant { chain: vec![emb_root, emb_src_tree], id: emb_new_blob },
        ] {
            let (got, end) = batch_with(&g_str, signer.as_ref(), vec![want.clone()]);
            assert!(got.is_empty(), "daemon leaked embargoed object {:?} to outsider!", want.id);
            assert!(end.get("from_store").is_none(), "daemon answered from store for outsider: {end}");
            assert_no_str(&end.to_string(), &[EMB_BLOB_MARK], "daemon batch end");
        }

        // Also try replaying `sec_grant_str` signed with the outsider's device key (or unsigned): refused!
        let (got_forged, end_forged) = batch_with(
            &sec_grant_str,
            signer.as_ref(),
            vec![ChainWant { chain: vec![emb_root, emb_src_tree], id: emb_new_blob }],
        );
        assert!(got_forged.is_empty(), "daemon served embargoed object under another device's grant!");
        assert!(end_forged.get("from_store").is_none(), "daemon answered forged grant from store: {end_forged}");
        assert_eq!(end_forged["status"], 401);
    }

    // 4. Thin clone of `dev` (using `dev`'s own daemon) sees no embargoed marker.
    let dev_thin = p.dev.dir("dev-thin-daemon");
    p.dev.ok(p.dev.home.path(), &["clone", &hub.url(&p.name), dev_thin.to_str().unwrap()]);
    assert!(!dev_thin.join("src/emb_daemon.rs").exists());
    assert_no_marker(&everything_in(&dev_thin), &[EMB_BLOB_MARK, &eid], "dev thin clone");
}

/// Review 4 (S22 × S17): the release landing records `snapshots.author`,
/// gives back its bulkhead places before waiting (`limits::leave_gates`), and
/// lands once across two servers.
#[test]
fn s17_release_landing_records_author_leaves_bulkhead_gates_and_lands_once_across_two_servers() {
    const EMB_STACK_1: &str = "EMBARGO-S17-STACK-1-7401\n";
    const EMB_STACK_2: &str = "EMBARGO-S17-STACK-2-7402\n";

    let hub = TestHub::start();
    let p = setup_project(&hub);
    p.admin.ok(&p.dir, &["group", "add", "devs", &p.sec.name]);
    let h = hub.hub();
    let pid: i64 = hub
        .rt
        .block_on(sqlx::query_scalar("SELECT id FROM projects WHERE name = $1").bind(&p.name).fetch_one(&h.db))
        .unwrap();
    let initial_main = hub.api().tips(Some(&p.admin.token()), &p.name).unwrap().branches["main"];

    // 1. `p.sec` creates a 2-change embargoed stack (an embargoed merge by `p.sec` + a follow-up commit by `p.dev`)
    //    so that two distinct authors' commits are on `embargo/<eid>`.
    let sec_dir = p.sec.dir("sec-s17");
    p.sec.ok(p.sec.home.path(), &["clone", &hub.url(&p.name), sec_dir.to_str().unwrap()]);
    write_files(&sec_dir, &[("src/s17_1.rs", EMB_STACK_1)]);
    p.sec.ok(&sec_dir, &["commit", "--no-advance", "-m", "s17 change 1"]);
    let until = iso_utc(veil_core::now_millis() + 3_600_000);
    let merge_out = p.sec.ok(
        &sec_dir,
        &["merge", "@-", "--into", "main", "--embargo-for", "devs", "--until", &until, "-m", "s17 merge 1"],
    );
    let eid = parse_embargo_id(&merge_out);
    p.sec.ok(&sec_dir, &["push"]);

    let dev_dir = p.dev.dir("dev-s17");
    p.dev.ok(p.dev.home.path(), &["clone", &hub.url(&p.name), dev_dir.to_str().unwrap()]);
    p.dev.ok(&dev_dir, &["embargo", "follow", &eid]);
    write_files(&dev_dir, &[("src/s17_2.rs", EMB_STACK_2)]);
    p.dev.ok(&dev_dir, &["commit", "-m", "s17 change 2"]);
    p.dev.ok(&dev_dir, &["push"]);

    // 2. Hold `main`'s landing lease elsewhere so that release requests wait in `release_one`,
    //    and spawn 16 concurrent callers across `POST /v1/projects/{p}/embargoes/{eid}/release`
    //    on TWO servers (`hub` and `hub2`). Verify that while all 16 wait for the landing outcome,
    //    both servers' project and server bulkhead gates are 0 (`limits::leave_gates`), and `tips`
    //    requests on both servers answer 200 immediately!
    let hub2 = TestHub::beside(&hub);
    let h2 = hub2.hub();
    hub.rt
        .block_on(
            sqlx::query("INSERT INTO landing_leases (project_id, branch, holder, epoch, expires_at) VALUES ($1, 'main', 'elsewhere', 1, $2)")
                .bind(pid)
                .bind(i64::MAX / 2)
                .execute(&h.db),
        )
        .unwrap();

    let sec_tok = p.sec.token();
    let dev_tok = p.dev.token();
    // (The release's ticket: one per tip of the line.)
    let ticket = format!("embargo-{pid}-{eid}-%");

    std::thread::scope(|s| {
        let mut waiters = Vec::new();
        for i in 0..16 {
            let target_hub = if i % 2 == 0 { &hub } else { &hub2 };
            let tok = if i % 2 == 0 { &sec_tok } else { &dev_tok };
            let pname = &p.name;
            let eid = &eid;
            waiters.push(s.spawn(move || {
                let r = target_hub.api().post_json(
                    Some(tok),
                    &format!("/v1/projects/{pname}/embargoes/{eid}/release"),
                    &json!({}),
                );
                assert_eq!(r.status, 200, "caller {i} release failed: {}", String::from_utf8_lossy(&r.body));
                assert_eq!(r.json()["released"], true);
            }));
        }

        // Wait until the deterministic ticket is queued and all 16 callers have released their bulkhead gates.
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        loop {
            let queued: i64 = hub
                .rt
                .block_on(
                    sqlx::query_scalar("SELECT COUNT(*) FROM landing_queue WHERE project_id = $1 AND ticket LIKE $2 AND state = 'queued'")
                        .bind(pid)
                        .bind(&ticket)
                        .fetch_one(&h.db),
                )
                .unwrap();
            if queued == 1
                && h.limits.load(Some(&p.name)) == (0, 0)
                && h.limits.load(None) == (0, 0)
                && h2.limits.load(Some(&p.name)) == (0, 0)
                && h2.limits.load(None) == (0, 0)
            {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "queued={queued}, h1_proj={:?}, h1_srv={:?}, h2_proj={:?}, h2_srv={:?}",
                h.limits.load(Some(&p.name)),
                h.limits.load(None),
                h2.limits.load(Some(&p.name)),
                h2.limits.load(None),
            );
            std::thread::sleep(Duration::from_millis(50));
        }

        // While all 16 release calls are waiting, pulls and `tips` on both servers succeed immediately.
        for srv in [&hub, &hub2] {
            let r = srv.api().get(Some(&dev_tok), &format!("/v1/projects/{}/tips", p.name));
            assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        }

        // Now release the landing lease and trigger `release_due` + `landing::ensure` on both servers simultaneously!
        hub.rt
            .block_on(sqlx::query("DELETE FROM landing_leases WHERE project_id = $1").bind(pid).execute(&h.db))
            .unwrap();
        {
            let _g1 = hub.rt.enter();
            veil_server::landing::ensure(&h, pid, "main");
            let _g2 = hub2.rt.enter();
            veil_server::landing::ensure(&h2, pid, "main");
        }
        let _ = hub.rt.block_on(veil_server::embargo::release_due(&h));
        let _ = hub2.rt.block_on(veil_server::embargo::release_due(&h2));

        for w in waiters {
            w.join().unwrap();
        }
    });

    // 3. Verify the stack landed once on `main` across the two servers, and every snapshot has its exact author in `snapshots.author`.
    catch_up(&hub, &p.name);
    let qlog = hub.api().get(Some(&p.admin.token()), &format!("/v1/projects/{}/q/log?rev=main&n=20", p.name));
    assert_eq!(qlog.status, 200);
    let entries = qlog.json()["entries"].as_array().unwrap().clone();
    let since_init: Vec<&Value> = entries
        .iter()
        .take_while(|it| it["snapshot_id"].as_str().unwrap() != initial_main.hex())
        .collect();
    assert_eq!(since_init.len(), 2, "expected 2 embargoed commits landed once on main: {since_init:#?}");

    let sec_pid: i64 = hub
        .rt
        .block_on(sqlx::query_scalar("SELECT id FROM people WHERE name = $1").bind(&p.sec.name).fetch_one(&h.db))
        .unwrap();
    let dev_pid: i64 = hub
        .rt
        .block_on(sqlx::query_scalar("SELECT id FROM people WHERE name = $1").bind(&p.dev.name).fetch_one(&h.db))
        .unwrap();

    // Newest (`since_init[0]`) was authored by `dev`, older (`since_init[1]`) was authored by `sec`.
    let newest_sid = since_init[0]["snapshot_id"].as_str().unwrap();
    let older_sid = since_init[1]["snapshot_id"].as_str().unwrap();
    let newest_author: i64 = hub
        .rt
        .block_on(sqlx::query_scalar("SELECT author FROM snapshots WHERE project_id = $1 AND id = $2").bind(pid).bind(newest_sid).fetch_one(&h.db))
        .unwrap();
    let older_author: i64 = hub
        .rt
        .block_on(sqlx::query_scalar("SELECT author FROM snapshots WHERE project_id = $1 AND id = $2").bind(pid).bind(older_sid).fetch_one(&h.db))
        .unwrap();
    assert_eq!(newest_author, dev_pid, "newest landed snapshot must record dev's author id");
    assert_eq!(older_author, sec_pid, "older landed snapshot must record sec's author id");
}

/// Review 5 (S24 part B × S22): the consolidated background transaction
/// (`derive::landing`) never derives, memoizes or indexes a hidden embargo
/// branch or its snapshots before release (`hidden_for_embargo IS NULL` in
/// every derive, memo and search query, and `is_withheld_for_query` in
/// `derive::ensure`), even when public landings trigger `derive::landing`
/// alongside the embargo. After release they are derived once.
#[test]
fn s24b_consolidated_derive_pass_never_derives_memoizes_or_indexes_hidden_embargo_before_release_and_derives_once_after() {
    const EMB_CODE: &str = "EMBARGO-S24B-SECRET-TOKEN-9942";
    const EMB_PATH: &str = "src/embargo_s24b_secret.rs";

    let hub = TestHub::start();
    let p = setup_project(&hub);
    p.admin.ok(&p.dir, &["group", "add", "devs", &p.sec.name]);
    let h = hub.hub();
    let pid: i64 = hub
        .rt
        .block_on(sqlx::query_scalar("SELECT id FROM projects WHERE name = $1").bind(&p.name).fetch_one(&h.db))
        .unwrap();

    // 1. `p.sec` pushes an embargoed change to `embargo/<eid>`.
    let sec_dir = p.sec.dir("sec-s24b");
    p.sec.ok(p.sec.home.path(), &["clone", &hub.url(&p.name), sec_dir.to_str().unwrap()]);
    write_files(&sec_dir, &[(EMB_PATH, &format!("pub const S24B: &str = \"{EMB_CODE}\";\n"))]);
    p.sec.ok(&sec_dir, &["commit", "--no-advance", "-m", "embargoed s24b fix"]);
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
        &["merge", "@-", "--into", "main", "--embargo-for", "security", "--until", &until, "-m", "embargo s24b merge"],
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
    let ebranch = format!("embargo/{eid}");

    // 2. Now `p.dev` lands a normal public change on `main`, triggering S24b's
    //    consolidated `derive::landing` pass (`prepare_landing_run` + `finish_landing_run`),
    //    and we also invoke `derive::landing`, `derive::resume`, `search::index::resume`,
    //    and `derive::ensure` directly.
    let api = hub.api();
    let dev_tok = p.dev.token();
    let main_base = api.tips(Some(&dev_tok), &p.name).unwrap().branches["main"];
    let r_pub = api.post_json(
        Some(&dev_tok),
        &format!("/v1/projects/{}/land", p.name),
        &json!({
            "onto": "main",
            "base": main_base.hex(),
            "description": "public change alongside embargo",
            "edits": [{"path": "src/public_s24b.rs", "put": {"text": "pub const PUB: u32 = 1;\n"}}],
            "wait": true
        }),
    );
    assert_eq!(r_pub.status, 200, "{}", String::from_utf8_lossy(&r_pub.body));
    assert_eq!(r_pub.json()["state"], "landed");

    let stats = hub.rt.block_on(veil_server::derive::landing(&h, pid, vec!["main".into(), ebranch.clone()])).unwrap();
    assert!(!stats.branches.contains(&ebranch), "derive::landing must skip hidden embargo branch: {stats:?}");
    hub.rt.block_on(veil_server::derive::resume(h.clone(), Some(pid)));
    hub.rt.block_on(veil_server::search::index::resume(h.clone(), Some(pid)));

    // Calling `derive::ensure` on an unreleased embargo snapshot is refused as not_found.
    for embargo_snap in [fix_id, merge_id] {
        let err = hub.rt.block_on(veil_server::derive::ensure(&h, pid, embargo_snap)).unwrap_err();
        assert!(format!("{err:?}").contains("no such snapshot"), "derive::ensure must refuse embargo snapshot: {err:?}");
    }

    // 3. Verify that in the database, `graph`, `derive_progress`, `file_history`,
    //    `view_graph`, `view_file_history`, and `search_heads` have ZERO rows for
    //    `embargo/<eid>` or its snapshots (`fix_id`, `merge_id`), and `health` does
    //    not count `embargo/<eid>` in `derive.branches` or `derive.branches_behind`.
    let emb_snaps: Vec<String> = hub
        .rt
        .block_on(
            sqlx::query_scalar("SELECT snapshot FROM embargo_snapshots WHERE project_id = $1 AND embargo_id = $2")
                .bind(pid)
                .bind(&eid)
                .fetch_all(&h.db),
        )
        .unwrap();
    assert!(!emb_snaps.is_empty(), "embargo_snapshots must record embargoed snapshots");

    let graph_cnt: i64 = hub
        .rt
        .block_on(
            sqlx::query_scalar("SELECT COUNT(*) FROM graph WHERE project_id = $1 AND snapshot = ANY($2)")
                .bind(pid)
                .bind(&emb_snaps)
                .fetch_one(&h.db),
        )
        .unwrap();
    assert_eq!(graph_cnt, 0, "no embargo snapshot may be in graph before release");

    let fh_cnt: i64 = hub
        .rt
        .block_on(
            sqlx::query_scalar("SELECT COUNT(*) FROM file_history WHERE project_id = $1 AND snapshot = ANY($2)")
                .bind(pid)
                .bind(&emb_snaps)
                .fetch_one(&h.db),
        )
        .unwrap();
    assert_eq!(fh_cnt, 0, "no embargo snapshot may be in file_history before release");

    let dp_cnt: i64 = hub
        .rt
        .block_on(
            sqlx::query_scalar("SELECT COUNT(*) FROM derive_progress WHERE project_id = $1 AND branch = $2")
                .bind(pid)
                .bind(&ebranch)
                .fetch_one(&h.db),
        )
        .unwrap();
    assert_eq!(dp_cnt, 0, "hidden embargo branch must not appear in derive_progress");

    let vg_cnt: i64 = hub
        .rt
        .block_on(
            sqlx::query_scalar("SELECT COUNT(*) FROM view_graph WHERE project_id = $1 AND snapshot = ANY($2)")
                .bind(pid)
                .bind(&emb_snaps)
                .fetch_one(&h.db),
        )
        .unwrap();
    assert_eq!(vg_cnt, 0, "no embargo snapshot may be memoized in view_graph before release");

    let vfh_cnt: i64 = hub
        .rt
        .block_on(
            sqlx::query_scalar("SELECT COUNT(*) FROM view_file_history WHERE project_id = $1 AND snapshot = ANY($2)")
                .bind(pid)
                .bind(&emb_snaps)
                .fetch_one(&h.db),
        )
        .unwrap();
    assert_eq!(vfh_cnt, 0, "no embargo snapshot may be memoized in view_file_history before release");

    let sh_cnt: i64 = hub
        .rt
        .block_on(
            sqlx::query_scalar("SELECT COUNT(*) FROM search_heads WHERE project_id = $1 AND branch = $2")
                .bind(pid)
                .bind(&ebranch)
                .fetch_one(&h.db),
        )
        .unwrap();
    assert_eq!(sh_cnt, 0, "hidden embargo branch must not appear in search_heads");

    // Search for `EMB_CODE` and `embargo_s24b_secret` returns 0 hits even for admin before release.
    let admin_tok = p.admin.token();
    let g_res = api.get(Some(&admin_tok), &format!("/v1/projects/{}/q/grep?pattern={EMB_CODE}", p.name));
    assert_eq!(g_res.status, 200, "{}", String::from_utf8_lossy(&g_res.body));
    assert_eq!(g_res.json()["files"].as_array().unwrap().len(), 0);
    let s_res = api.get(Some(&admin_tok), &format!("/v1/projects/{}/q/search?q=embargo_s24b_secret&kind=path", p.name));
    assert_eq!(s_res.status, 200, "{}", String::from_utf8_lossy(&s_res.body));
    assert_eq!(s_res.json()["results"].as_array().unwrap().len(), 0);

    // Health endpoint reports `branches_behind == 0` (the hidden embargo branch is excluded).
    let health = api.get(Some(&admin_tok), &format!("/v1/projects/{}/health", p.name));
    assert_eq!(health.status, 200);
    assert_eq!(health.json()["derive"]["branches_behind"], 0, "{}", health.json());

    // 4. Release the embargo: the changes land on `main`, and the consolidated
    //    background pass (`derive::landing`) derives, memoizes and indexes them once.
    let rel = api.post_json(
        Some(&p.sec.token()),
        &format!("/v1/projects/{}/embargoes/{eid}/release", p.name),
        &json!({}),
    );
    assert_eq!(rel.status, 200, "{}", String::from_utf8_lossy(&rel.body));
    assert_eq!(rel.json()["released"], true);

    let stats_after = hub.rt.block_on(veil_server::derive::landing(&h, pid, vec!["main".into()])).unwrap();
    let stats_second = hub.rt.block_on(veil_server::derive::landing(&h, pid, vec!["main".into()])).unwrap();
    assert_eq!(stats_second.snapshots, 0, "after release, a second derive pass derives 0 new snapshots (derived once): {stats_after:?}, {stats_second:?}");

    let g_after = api.get(Some(&dev_tok), &format!("/v1/projects/{}/q/grep?pattern={EMB_CODE}", p.name));
    assert_eq!(g_after.status, 200, "{}", String::from_utf8_lossy(&g_after.body));
    assert_eq!(g_after.json()["files"].as_array().unwrap().len(), 1, "after release, grep finds the landed embargo code");
    let s_after = api.get(Some(&dev_tok), &format!("/v1/projects/{}/q/search?q=embargo_s24b_secret&kind=path", p.name));
    assert_eq!(s_after.status, 200, "{}", String::from_utf8_lossy(&s_after.body));
    assert_eq!(s_after.json()["results"].as_array().unwrap().len(), 1, "after release, filename search finds the landed embargo file");
}


