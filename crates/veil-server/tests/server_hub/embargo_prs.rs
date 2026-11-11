//! Milestone S23: embargoed PRs (`docs/HUB.md` §13.38;
//! `docs/design/server/phase-4-agent-scale.md` §4.9, decision 8, §8).
//!
//! Guarantees, each a test that asserts the primary action succeeded (or the
//! exact refusal) before checking anything else:
//! 1. Until release, an embargoed PR is visible only to embargo members (who
//!    can also read every touched path) and project admins: its title,
//!    description, revisions, diff, threads, comments, reviews, risk, checks
//!    and events. To everyone else it doesn't exist, by every route (list,
//!    search, show, events, errors, counts), and reads exactly like a missing
//!    PR.
//! 2. Only embargo members review and approve it. Review rules for protected
//!    branches hold, and an agent session never approves (S21).
//! 3. At release it becomes visible exactly as an ordinary PR, once, across
//!    two servers. If it was set to land at release, it lands through S17
//!    once, with S21's review rules met.
//! 4. Nothing about it leaks into public search, blame, history or the
//!    landing queue's visible state before release.
//! 5. CI runners (S19) refused on its writes; narrowed agent sessions (S11)
//!    only within their paths.

use std::time::Duration;

use serde_json::{json, Value};
use veil_core::{
    crypto::domains::SIG_CONTEXT_HUB_PR_REVIEW,
    hub::pr::review_message,
    ObjectId,
};

use crate::support::*;

fn body_str(r: &Reply) -> String {
    String::from_utf8_lossy(&r.body).into_owned()
}

fn assert_no_str(text: &str, markers: &[&str], where_: &str) {
    for m in markers {
        assert!(!text.contains(m), "found forbidden marker {m:?} in {where_}: {text}");
    }
}

fn parse_embargo_id(out: &str) -> String {
    for word in out.split_whitespace() {
        let clean = word.trim_end_matches(':');
        if clean.len() == 10 && clean.bytes().all(|b| b.is_ascii_hexdigit()) {
            return clean.to_string();
        }
    }
    panic!("no embargo id in output: {out}");
}

fn iso_utc(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let hour = rem / 3600;
    let min = (rem % 3600) / 60;
    let sec = rem % 60;
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

fn sign_review(person: &Person, project: &str, pr_id: &str, patch: &str, verdict: &str) -> String {
    person
        .identity()
        .sign(SIG_CONTEXT_HUB_PR_REVIEW, &review_message(project, pr_id, patch, verdict))
}

fn set_main_file(hub: &TestHub, p: &Project, path: &str, text: &str, desc: &str) -> ObjectId {
    let admin = p.admin.token();
    let base = hub.api().tips(Some(&admin), &p.name).unwrap().branches["main"];
    let ch = hub.api().post_json(
        Some(&admin),
        &format!("/v1/projects/{}/changes", p.name),
        &json!({
            "base": base.hex(),
            "description": desc,
            "edits": [{"path": path, "put": {"text": text}}],
        }),
    );
    assert_eq!(ch.status, 200, "{}", body_str(&ch));
    let snap = ch.json()["snapshot"].as_str().unwrap().to_string();
    let landed = hub.api().post_json(
        Some(&admin),
        &format!("/v1/projects/{}/land", p.name),
        &json!({"onto": "main", "snapshot": snap, "wait": true}),
    );
    assert_eq!(landed.status, 200, "{}", body_str(&landed));
    ObjectId::from_hex(landed.json()["landed"][0].as_str().unwrap()).unwrap()
}

/// Push an embargoed commit touching `files` onto `embargo/<id>` for `group`,
/// returning `(embargo_id, fix_snap, merge_snap, work_dir)`.
#[allow(clippy::too_many_arguments)]
fn push_embargo(
    hub: &TestHub,
    project: &str,
    author: &Person,
    dir_tag: &str,
    group: &str,
    until_ms: Option<i64>,
    files: &[(&str, &str)],
    msg: &str,
) -> (String, ObjectId, ObjectId, std::path::PathBuf) {
    let dir = author.dir(dir_tag);
    author.ok(author.home.path(), &["clone", &hub.url(project), dir.to_str().unwrap()]);
    write_files(&dir, files);
    author.ok(&dir, &["commit", "--no-advance", "-m", msg]);
    let fix_json = author.ok(&dir, &["log", "-r", "@-", "-n", "1", "--json"]);
    let fix_id = ObjectId::from_hex(
        serde_json::from_str::<Value>(&fix_json).unwrap()["entries"][0]["snapshot_id"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let merge_out = if let Some(ms) = until_ms {
        let u = iso_utc(ms);
        author.ok(&dir, &["merge", "@-", "--into", "main", "--embargo-for", group, "--until", &u, "-m", msg])
    } else {
        author.ok(&dir, &["merge", "@-", "--into", "main", "--embargo-for", group, "-m", msg])
    };
    let eid = parse_embargo_id(&merge_out);
    let merge_json = author.ok(&dir, &["log", "-r", "main", "-n", "1", "--json"]);
    let merge_id = ObjectId::from_hex(
        serde_json::from_str::<Value>(&merge_json).unwrap()["entries"][0]["snapshot_id"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    author.ok(&dir, &["push"]);
    (eid, fix_id, merge_id, dir)
}

/// Guarantee 1: Until release, an embargoed PR is visible only to embargo
/// members (who also read every touched path) and project admins: its title,
/// description, revisions, diff, threads, comments, reviews, risk, checks and
/// events. To everyone else it doesn't exist, by every route (list, search,
/// show, events, errors, counts), and reads exactly like a missing PR.
#[test]
fn guarantee_1_embargoed_pr_is_visible_only_to_members_and_admins_and_nonexistent_to_outsiders() {
    const TITLE_MARK: &str = "EMBARGO-PR-TITLE-7733";
    const BODY_MARK: &str = "EMBARGO-PR-BODY-7744";
    const FIX_MARK: &str = "EMBARGO-PR-FIX-7711";
    const FIX2_MARK: &str = "EMBARGO-PR-FIX2-7712";
    const MSG_MARK: &str = "EMBARGO-PR-MSG-7722";
    const THREAD_MARK: &str = "EMBARGO-PR-THREAD-7755";
    const REPLY_MARK: &str = "EMBARGO-PR-REPLY-7766";
    const REVIEW_MARK: &str = "EMBARGO-PR-REVIEW-7777";
    const CHECK_MARK: &str = "EMBARGO-PR-CHECK-7788";

    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();

    let sec2 = hub.person("sec2");
    let sec_only = hub.person("seconly");
    p.admin.ok(&p.dir, &["group", "add", "devs", &p.sec.name]);
    p.admin.ok(&p.dir, &["group", "add", "security", &sec2.name]);
    p.admin.ok(&p.dir, &["group", "add", "devs", &sec2.name]);
    p.admin.ok(&p.dir, &["group", "add", "security", &sec_only.name]);
    p.admin.ok(&p.dir, &["group", "add", "devs", &sec_only.name]);
    // Give `p.sec` access to `finance` as well for the restricted-folder embargo check later.
    p.admin.ok(&p.dir, &["group", "add", "finance", &p.sec.name]);

    // Configure `.veilrules` so `ci/src` is scoped to `src/`.
    set_main_file(
        &hub,
        &p,
        ".veilrules",
        "[checks.\"ci/src\"]\npaths = [\"src/\"]\n",
        "configure ci/src check path",
    );

    // First, `p.dev` opens one ordinary public PR so list counts are non-zero (1).
    let mut dev_c = Craft::new(&api, &p.dev, &p.name, "main");
    dev_c.file("src/public_feature.rs", "pub fn ordinary() {}\n");
    let dev_ch = dev_c.push_to("dev-pub", None);
    assert_eq!(dev_ch.status, 200, "{}", body_str(&dev_ch));
    let pub_pr = api.post_json(
        Some(&p.dev.token()),
        &format!("/v1/projects/{}/prs", p.name),
        &json!({
            "head": "dev-pub",
            "title": "Ordinary public feature",
            "body": "Public body",
        }),
    );
    assert_eq!(pub_pr.status, 200, "{}", body_str(&pub_pr));
    let pub_pr_id = pub_pr.json()["id"].as_str().unwrap().to_string();

    let sec_tok = p.sec.token();
    let sec2_tok = sec2.token();
    let sec_only_tok = sec_only.token();
    let admin_tok = p.admin.token();
    let dev_tok = p.dev.token();
    let fin_tok = p.fin.token();

    // Open SSE streams for `sec2` (embargo member), `admin`, and `dev` (outsider) BEFORE embargoed PR actions.
    let sec2_sse = api.get_unread(
        &format!("/v1/projects/{}/events", p.name),
        &[("authorization", &format!("Bearer {sec2_tok}"))],
    );
    let admin_sse = api.get_unread(
        &format!("/v1/projects/{}/events", p.name),
        &[("authorization", &format!("Bearer {admin_tok}"))],
    );
    let dev_sse = api.get_unread(
        &format!("/v1/projects/{}/events", p.name),
        &[("authorization", &format!("Bearer {dev_tok}"))],
    );

    // `p.sec` pushes an embargoed fix for `security`.
    let until_ms = veil_core::now_millis() + 3_600_000;
    let (eid, fix_id, merge_id, sec_dir) = push_embargo(
        &hub,
        &p.name,
        &p.sec,
        "g1-sec",
        "security",
        Some(until_ms),
        &[
            ("src/lib.rs", &format!("{PUBLIC_MARK}\n{FIX_MARK}\n")),
            ("src/embargo_vuln.rs", &format!("pub const FIX: &str = \"{FIX_MARK}\";\n")),
        ],
        MSG_MARK,
    );
    let ebranch = format!("embargo/{eid}");

    // Primary action: `p.sec` creates the embargoed PR from `embargo/<eid>`.
    let created = api.post_json(
        Some(&sec_tok),
        &format!("/v1/projects/{}/prs", p.name),
        &json!({
            "head": ebranch,
            "title": TITLE_MARK,
            "body": BODY_MARK,
        }),
    );
    assert_eq!(created.status, 200, "embargo member create PR failed: {}", body_str(&created));
    let pr_json = created.json();
    let pr_id = pr_json["id"].as_str().unwrap().to_string();
    assert_eq!(pr_json["title"], TITLE_MARK);
    assert_eq!(pr_json["body"], BODY_MARK);
    assert_eq!(pr_json["embargo"], eid);
    assert_eq!(pr_json["land_at_release"], false);
    assert_eq!(pr_json["revision"], 1);
    assert!(pr_json["risk"].is_string());

    // `p.sec` opens an anchored thread and replies.
    let th = api.post_json(
        Some(&sec_tok),
        &format!("/v1/projects/{}/prs/{pr_id}/threads", p.name),
        &json!({
            "body": THREAD_MARK,
            "anchor": {"path": "src/embargo_vuln.rs", "start": 1, "end": 1, "side": "new"},
        }),
    );
    assert_eq!(th.status, 200, "{}", body_str(&th));
    let tid = th.json()["id"].as_str().unwrap().to_string();

    let rep = api.post_json(
        Some(&sec2_tok),
        &format!("/v1/projects/{}/prs/{pr_id}/threads/{tid}", p.name),
        &json!({"body": REPLY_MARK}),
    );
    assert_eq!(rep.status, 200, "{}", body_str(&rep));

    // `sec2` approves revision 1.
    let patch1 = pr_json["patch"].as_str().unwrap().to_string();
    let sig1 = sign_review(&sec2, &p.name, &pr_id, &patch1, "approve");
    let rev_resp = api.post_json(
        Some(&sec2_tok),
        &format!("/v1/projects/{}/prs/{pr_id}/reviews", p.name),
        &json!({"patch": patch1, "verdict": "approve", "body": REVIEW_MARK, "signature": sig1}),
    );
    assert_eq!(rev_resp.status, 200, "{}", body_str(&rev_resp));

    // `p.sec` pushes a 2nd commit onto `embargo/<eid>` and updates the PR to revision 2.
    write_files(
        &sec_dir,
        &[("src/embargo_vuln.rs", &format!("pub const FIX: &str = \"{FIX_MARK}\";\n// {FIX2_MARK}\n"))],
    );
    p.sec.ok(&sec_dir, &["commit", "-m", "second embargo commit"]);
    p.sec.ok(&sec_dir, &["push"]);
    let upd = api.post_json(
        Some(&sec_tok),
        &format!("/v1/projects/{}/prs/{pr_id}/revisions", p.name),
        &json!({"head": ebranch}),
    );
    assert_eq!(upd.status, 200, "{}", body_str(&upd));
    assert_eq!(upd.json()["revision"], 2);
    let rev2_head_sec = upd.json()["revisions"][1]["head"].as_str().unwrap().to_string();

    // Mint a CI runner from `p.sec` (`ci/src`) and post a check on revision 2's head.
    let runner_sess = api.post_json(
        Some(&sec_tok),
        "/v1/sessions/ci",
        &json!({"project": p.name, "check": "ci/src"}),
    );
    assert_eq!(runner_sess.status, 200, "{}", body_str(&runner_sess));
    let runner_tok = runner_sess.json()["token"].as_str().unwrap().to_string();
    let chk = api.post_json(
        Some(&runner_tok),
        &format!("/v1/projects/{}/checks", p.name),
        &json!({
            "snapshot": rev2_head_sec,
            "name": "ci/src",
            "state": "pass",
            "summary": CHECK_MARK,
        }),
    );
    assert_eq!(chk.status, 200, "{}", body_str(&chk));

    // Verify embargo members (`p.sec`, `sec2`) and `p.admin` see everything on every route.
    for (who, tok) in [("sec", &sec_tok), ("sec2", &sec2_tok), ("admin", &admin_tok)] {
        let ls = api.get(Some(tok), &format!("/v1/projects/{}/prs?state=all", p.name));
        assert_eq!(ls.status, 200, "{who} list: {}", body_str(&ls));
        assert_eq!(ls.json()["count"], 2, "{who} must see both PRs: {}", body_str(&ls));

        let search = api.get(Some(tok), &format!("/v1/projects/{}/prs?q=EMBARGO-PR", p.name));
        assert_eq!(search.status, 200, "{who} search: {}", body_str(&search));
        assert_eq!(search.json()["count"], 1, "{who} search count: {}", body_str(&search));
        assert_eq!(search.json()["prs"][0]["id"], pr_id);

        let sh = api.get(Some(tok), &format!("/v1/projects/{}/prs/{pr_id}", p.name));
        assert_eq!(sh.status, 200, "{who} show: {}", body_str(&sh));
        let sj = sh.json();
        assert_eq!(sj["title"], TITLE_MARK, "{who}");
        assert_eq!(sj["body"], BODY_MARK, "{who}");
        assert_eq!(sj["embargo"], eid, "{who}");
        assert_eq!(sj["revision"], 2, "{who}");
        assert_eq!(sj["open_threads"], 1, "{who}");
        assert_eq!(sj["review"]["reviews"][0]["body"], REVIEW_MARK, "{who}");
        assert_eq!(sj["checks"][0]["summary"], CHECK_MARK, "{who}");

        let df = api.get(Some(tok), &format!("/v1/projects/{}/prs/{pr_id}/diff", p.name));
        assert_eq!(df.status, 200, "{who} diff: {}", body_str(&df));
        assert!(body_str(&df).contains(FIX_MARK) && body_str(&df).contains(FIX2_MARK), "{who} diff missing content: {}", body_str(&df));

        let ths = api.get(Some(tok), &format!("/v1/projects/{}/prs/{pr_id}/threads", p.name));
        assert_eq!(ths.status, 200, "{who} threads: {}", body_str(&ths));
        assert!(body_str(&ths).contains(THREAD_MARK) && body_str(&ths).contains(REPLY_MARK), "{who} threads: {}", body_str(&ths));

        let chks = api.get(Some(tok), &format!("/v1/projects/{}/checks?rev=embargo%2F{eid}", p.name));
        assert_eq!(chks.status, 200, "{who} checks by embargo branch: {}", body_str(&chks));
        assert!(body_str(&chks).contains(CHECK_MARK), "{who} checks: {}", body_str(&chks));
    }

    // Class intersection rule: an embargoed PR touching `BILL_DIR/` is hidden even from
    // an embargo member (`sec_only`) who cannot read `BILL_DIR/`!
    let (bill_eid, _, _, _) = push_embargo(
        &hub,
        &p.name,
        &p.sec,
        "g1-bill-sec",
        "security",
        Some(until_ms),
        &[(&format!("{BILL_DIR}/acme/embargo_bill.txt"), "BILL-EMBARGO-999\n")],
        "billing embargo",
    );
    let bill_pr = api.post_json(
        Some(&sec_tok),
        &format!("/v1/projects/{}/prs", p.name),
        &json!({
            "head": format!("embargo/{bill_eid}"),
            "title": "Billing embargo PR",
        }),
    );
    assert_eq!(bill_pr.status, 200, "{}", body_str(&bill_pr));
    let bill_pr_id = bill_pr.json()["id"].as_str().unwrap().to_string();
    assert_eq!(
        api.get(Some(&sec_only_tok), &format!("/v1/projects/{}/prs/{bill_pr_id}", p.name)).status,
        404,
        "embargo member without folder read access must not see PR touching hidden folder"
    );
    assert_eq!(
        api.get(Some(&sec_only_tok), &format!("/v1/projects/{}/prs?state=all", p.name)).json()["count"],
        2,
        "sec_only must see pub_pr + src embargo PR, not billing embargo PR"
    );

    // Mutate `.veilpolicy` on `main` to force `class::reclassify` on the next PR query,
    // ensuring reclassification preserves `embargo` and never leaks to outsiders!
    let cur_policy = std::fs::read_to_string(p.dir.join(".veilpolicy")).unwrap();
    set_main_file(
        &hub,
        &p,
        ".veilpolicy",
        &format!("{cur_policy}docs/ public devs\n"),
        "add docs/ rule to trigger reclassify",
    );

    // Verify outsiders (`dev`, `fin`, anonymous) see ZERO trace on every route,
    // byte-for-byte identical to a missing PR (`pr-00000000`)!
    let missing_id = "pr-00000000";
    let forbidden_markers = [
        TITLE_MARK,
        BODY_MARK,
        FIX_MARK,
        FIX2_MARK,
        MSG_MARK,
        THREAD_MARK,
        REPLY_MARK,
        REVIEW_MARK,
        CHECK_MARK,
        &eid,
        &bill_eid,
        &pr_id,
        &bill_pr_id,
    ];

    for (who, tok) in [("dev", Some(dev_tok.as_str())), ("fin", Some(fin_tok.as_str())), ("anon", None)] {
        // List & counts & search.
        let ls = api.get(tok, &format!("/v1/projects/{}/prs?state=all", p.name));
        assert_eq!(ls.status, 200, "{who} list: {}", body_str(&ls));
        assert_eq!(ls.json()["count"], 1, "{who} count must be 1 (only ordinary PR): {}", body_str(&ls));
        assert_eq!(ls.json()["prs"][0]["id"], pub_pr_id, "{who}");
        assert_no_str(&body_str(&ls), &forbidden_markers, &format!("{who} list"));

        for q_term in ["EMBARGO", "7733", "7744", "Billing"] {
            let sr = api.get(tok, &format!("/v1/projects/{}/prs?state=all&q={q_term}", p.name));
            assert_eq!(sr.status, 200, "{who} search {q_term}");
            assert_eq!(sr.json()["count"], 0, "{who} search {q_term}: {}", body_str(&sr));
            assert_eq!(sr.json()["prs"], json!([]), "{who}");
        }

        // Show, diff, threads, thread get: exact status & body match with `pr-00000000`.
        for suffix in ["", "/diff", "/threads", &format!("/threads/{tid}")] {
            let got = api.get(tok, &format!("/v1/projects/{}/prs/{pr_id}{suffix}", p.name));
            let miss = api.get(tok, &format!("/v1/projects/{}/prs/{missing_id}{suffix}", p.name));
            assert_eq!(got.status, 404, "{who} GET {suffix}");
            assert_eq!((got.status, got.body), (miss.status, miss.body), "{who} GET {suffix} differs from missing PR");
        }

        // Write routes for signed-in outsiders (`dev`, `fin`): exact match with `pr-00000000`.
        if tok.is_some() {
            for (suffix, payload) in [
                ("/revisions", json!({"head": "main"})),
                ("/close", json!({})),
                ("/threads", json!({"body": "probe"})),
                (&format!("/threads/{tid}"), json!({"body": "probe"})),
                ("/reviews", json!({"patch": patch1, "verdict": "approve", "signature": "00"})),
                ("/land", json!({})),
                ("/land", json!({"at_release": true})),
            ] {
                let got = api.post_json(tok, &format!("/v1/projects/{}/prs/{pr_id}{suffix}", p.name), &payload);
                let miss = api.post_json(tok, &format!("/v1/projects/{}/prs/{missing_id}{suffix}", p.name), &payload);
                assert_eq!(got.status, 404, "{who} POST {suffix}: {}", body_str(&got));
                assert_eq!((got.status, got.body), (miss.status, miss.body), "{who} POST {suffix} differs from missing PR");
            }

            // Outsider opening a PR from or onto `embargo/<eid>` or its snapshots gets 404 identical to missing rev.
            let miss_create = api.post_json(
                tok,
                &format!("/v1/projects/{}/prs", p.name),
                &json!({"head": "no-such-branch-zzz", "title": "probe"}),
            );
            assert_eq!(miss_create.status, 404);
            for bad_req in [
                json!({"head": ebranch, "title": "probe"}),
                json!({"head": fix_id.hex(), "title": "probe"}),
                json!({"head": merge_id.hex(), "title": "probe"}),
                json!({"head": "dev-pub", "onto": ebranch, "title": "probe"}),
            ] {
                let got = api.post_json(tok, &format!("/v1/projects/{}/prs", p.name), &bad_req);
                assert_eq!((got.status, &got.body), (miss_create.status, &miss_create.body), "{who} create probe {bad_req}");
            }
        }

        // Checks, tested, and tips must never reveal `embargo/<eid>` or its snapshots!
        let miss_chk = api.get(tok, &format!("/v1/projects/{}/checks?rev=no-such-branch-zzz", p.name));
        assert_eq!(miss_chk.status, 404);
        for rev in [
            format!("embargo%2F{eid}"),
            fix_id.hex(),
            merge_id.hex(),
            rev2_head_sec.clone(),
        ] {
            let got = api.get(tok, &format!("/v1/projects/{}/checks?rev={rev}", p.name));
            assert_eq!((got.status, &got.body), (miss_chk.status, &miss_chk.body), "{who} checks rev={rev}");
        }
        let got_tested = api.get(tok, &format!("/v1/projects/{}/tested/embargo%2F{eid}", p.name));
        assert_eq!(got_tested.status, 404, "{who} tested embargo branch: {}", body_str(&got_tested));
        let tips = api.tips(tok, &p.name).unwrap();
        assert!(!tips.branches.contains_key(&ebranch), "{who} tips.branches leaked {ebranch}");
        assert!(!tips.tested.contains_key(&ebranch), "{who} tips.tested leaked {ebranch}");
    }

    // SSE events: `sec2` and `admin` received `pr.*` events for `pr_id`; `dev` received NONE!
    let sec2_events = collect_sse(sec2_sse, 10, Duration::from_millis(800));
    let admin_events = collect_sse(admin_sse, 10, Duration::from_millis(800));
    assert!(
        sec2_events.iter().any(|(ev, d)| ev == "pr.opened" && d["id"] == pr_id),
        "embargo member must receive pr.opened SSE event, got: {sec2_events:?}"
    );
    assert!(
        sec2_events.iter().any(|(ev, d)| ev == "pr.revision" && d["id"] == pr_id),
        "embargo member must receive pr.revision SSE event, got: {sec2_events:?}"
    );
    assert!(
        admin_events.iter().any(|(ev, d)| ev == "pr.opened" && d["id"] == pr_id),
        "admin must receive pr.opened SSE event, got: {admin_events:?}"
    );
    let dev_events = collect_sse(dev_sse, 10, Duration::from_millis(400));
    for (ev, d) in &dev_events {
        let s = format!("{ev}:{d}");
        assert_no_str(&s, &forbidden_markers, "outsider SSE stream");
    }
}

/// Guarantee 2: Only embargo members review and approve it. Review rules for
/// protected branches hold, and an agent session never approves (S21).
#[test]
fn guarantee_2_only_embargo_members_review_and_protected_branch_and_agent_rules_hold() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();

    let rev1 = hub.person("rev1");
    let rev2 = hub.person("rev2");
    let ro_sec = hub.person("rosec");
    p.admin.ok(&p.dir, &["group", "create", "writers"]);
    p.admin.ok(&p.dir, &["group", "add", "devs", &p.sec.name]);
    p.admin.ok(&p.dir, &["group", "add", "writers", &p.sec.name]);
    p.admin.ok(&p.dir, &["group", "add", "security", &rev1.name]);
    p.admin.ok(&p.dir, &["group", "add", "devs", &rev1.name]);
    p.admin.ok(&p.dir, &["group", "add", "writers", &rev1.name]);
    p.admin.ok(&p.dir, &["group", "add", "security", &rev2.name]);
    p.admin.ok(&p.dir, &["group", "add", "devs", &rev2.name]);
    p.admin.ok(&p.dir, &["group", "add", "writers", &rev2.name]);
    p.admin.ok(&p.dir, &["group", "add", "security", &ro_sec.name]);
    // `p.dev` is in `writers` and `devs`, NOT in `security`.
    p.admin.ok(&p.dir, &["group", "add", "writers", &p.dev.name]);

    // `.veilpolicy`: `src/guarded/` is `public` (readable by everyone, including `ro_sec`),
    // and writable only by `writers` (and admins).
    let base_policy = std::fs::read_to_string(p.dir.join(".veilpolicy")).unwrap();
    set_main_file(
        &hub,
        &p,
        ".veilpolicy",
        &format!("{base_policy}src/guarded/ public writers\n"),
        "add guarded folder write rule",
    );
    // `.veilrules`: protect `main` and require 1 human approval (`src/unrelated.rs` checks-only for unrelated rebase setup).
    set_main_file(
        &hub,
        &p,
        ".veilrules",
        "[branches.main]\nprotected = true\n\n[review]\nlow = { approvals = 1, people_only = true }\nnormal = { approvals = 1, people_only = true }\nhigh = { approvals = 1, people_only = true }\nchecks_only = [\"src/unrelated.rs\"]\n",
        "protect main and require 1 approval",
    );

    let until_ms = veil_core::now_millis() + 3_600_000;
    let (eid, _, _, _sec_dir) = push_embargo(
        &hub,
        &p.name,
        &p.sec,
        "g2-sec",
        "security",
        Some(until_ms),
        &[("src/guarded/fix.rs", "pub fn guarded_fix() -> u32 { 1 }\n")],
        "guarded embargo fix",
    );
    let ebranch = format!("embargo/{eid}");

    let created = api.post_json(
        Some(&p.sec.token()),
        &format!("/v1/projects/{}/prs", p.name),
        &json!({"head": ebranch, "title": "Guarded embargo PR"}),
    );
    assert_eq!(created.status, 200, "{}", body_str(&created));
    let pr_id = created.json()["id"].as_str().unwrap().to_string();
    let patch1 = created.json()["patch"].as_str().unwrap().to_string();
    assert_eq!(created.json()["review"]["ready"], false);
    assert_eq!(created.json()["review"]["needs"]["approvals"], 1);

    // 1. Outsider with write access (`p.dev`) cannot review: 404.
    let dev_sig = sign_review(&p.dev, &p.name, &pr_id, &patch1, "approve");
    let dev_rev = api.post_json(
        Some(&p.dev.token()),
        &format!("/v1/projects/{}/prs/{pr_id}/reviews", p.name),
        &json!({"patch": patch1, "verdict": "approve", "signature": dev_sig}),
    );
    assert_eq!(dev_rev.status, 404, "outsider review must 404: {}", body_str(&dev_rev));

    // 2. Read-only embargo member (`ro_sec`) sees the PR (200) but cannot review (403).
    assert_eq!(api.get(Some(&ro_sec.token()), &format!("/v1/projects/{}/prs/{pr_id}", p.name)).status, 200);
    let ro_sig = sign_review(&ro_sec, &p.name, &pr_id, &patch1, "approve");
    let ro_rev = api.post_json(
        Some(&ro_sec.token()),
        &format!("/v1/projects/{}/prs/{pr_id}/reviews", p.name),
        &json!({"patch": patch1, "verdict": "approve", "signature": ro_sig}),
    );
    assert_eq!(ro_rev.status, 403, "read-only embargo member review must 403: {}", body_str(&ro_rev));

    // 3. Author (`p.sec`) cannot self-approve (403).
    let self_sig = sign_review(&p.sec, &p.name, &pr_id, &patch1, "approve");
    let self_rev = api.post_json(
        Some(&p.sec.token()),
        &format!("/v1/projects/{}/prs/{pr_id}/reviews", p.name),
        &json!({"patch": patch1, "verdict": "approve", "signature": self_sig}),
    );
    assert_eq!(self_rev.status, 403, "self-approval must 403: {}", body_str(&self_rev));

    // 4. S11 agent session of `rev1` never approves (`403 agent_session`).
    let agent_sess = api.post_json(
        Some(&rev1.token()),
        "/v1/sessions/agent",
        &json!({
            "project": p.name,
            "attribution": {"agent": "claude-code/2.3", "task": "S23-G2", "run": "r1"},
            "only": ["src/guarded"],
        }),
    );
    assert_eq!(agent_sess.status, 200, "{}", body_str(&agent_sess));
    let agent_tok = agent_sess.json()["token"].as_str().unwrap().to_string();
    let agent_sig = sign_review(&rev1, &p.name, &pr_id, &patch1, "approve");
    let agent_rev = api.post_json(
        Some(&agent_tok),
        &format!("/v1/projects/{}/prs/{pr_id}/reviews", p.name),
        &json!({"patch": patch1, "verdict": "approve", "signature": agent_sig}),
    );
    assert_eq!(agent_rev.status, 403, "agent approve must 403: {}", body_str(&agent_rev));
    assert_eq!(agent_rev.json()["code"], "agent_session", "{}", body_str(&agent_rev));

    // 5. Arming `land_at_release` before approval is refused (`409 not_ready`).
    let unready_land = api.post_json(
        Some(&p.sec.token()),
        &format!("/v1/projects/{}/prs/{pr_id}/land", p.name),
        &json!({"at_release": true}),
    );
    assert_eq!(unready_land.status, 409, "{}", body_str(&unready_land));
    assert_eq!(unready_land.json()["code"], "not_ready", "{}", body_str(&unready_land));

    // 6. `rev1` requests changes -> holds the PR even after `rev2` approves!
    let rc_sig = sign_review(&rev1, &p.name, &pr_id, &patch1, "request-changes");
    let rc = api.post_json(
        Some(&rev1.token()),
        &format!("/v1/projects/{}/prs/{pr_id}/reviews", p.name),
        &json!({"patch": patch1, "verdict": "request-changes", "body": "fix edge case", "signature": rc_sig}),
    );
    assert_eq!(rc.status, 200, "{}", body_str(&rc));
    assert_eq!(rc.json()["review"]["ready"], false);

    let r2_sig = sign_review(&rev2, &p.name, &pr_id, &patch1, "approve");
    let r2 = api.post_json(
        Some(&rev2.token()),
        &format!("/v1/projects/{}/prs/{pr_id}/reviews", p.name),
        &json!({"patch": patch1, "verdict": "approve", "signature": r2_sig}),
    );
    assert_eq!(r2.status, 200, "{}", body_str(&r2));
    assert_eq!(r2.json()["review"]["approvals"], 1);
    assert_eq!(r2.json()["review"]["ready"], false, "request-changes must still hold PR");

    // 7. `rev1` approves -> releases `rev1`'s hold, `ready == true`, `approvals == 2`.
    let r1_sig = sign_review(&rev1, &p.name, &pr_id, &patch1, "approve");
    let r1 = api.post_json(
        Some(&rev1.token()),
        &format!("/v1/projects/{}/prs/{pr_id}/reviews", p.name),
        &json!({"patch": patch1, "verdict": "approve", "signature": r1_sig}),
    );
    assert_eq!(r1.status, 200, "{}", body_str(&r1));
    assert_eq!(r1.json()["review"]["approvals"], 2);
    assert_eq!(r1.json()["review"]["ready"], true);

    // 8. Removing `rev2` and `rev1` from `security` immediately invalidates their approvals in `gate`!
    p.admin.ok(&p.dir, &["group", "remove", "security", &rev2.name]);
    p.admin.ok(&p.dir, &["group", "remove", "security", &rev1.name]);
    let after_rm = api.get(Some(&p.sec.token()), &format!("/v1/projects/{}/prs/{pr_id}", p.name)).json();
    assert_eq!(after_rm["review"]["approvals"], 0, "removed embargo members must not count: {after_rm}");
    assert_eq!(after_rm["review"]["ready"], false);
    // Re-adding `rev1` restores their approval.
    p.admin.ok(&p.dir, &["group", "add", "security", &rev1.name]);
    let after_readd = api.get(Some(&p.sec.token()), &format!("/v1/projects/{}/prs/{pr_id}", p.name)).json();
    assert_eq!(after_readd["review"]["approvals"], 1);
    assert_eq!(after_readd["review"]["ready"], true);

    // 9. Unrelated change on `main` + `vl embargo follow` rebase preserves `patch` and keeps approval!
    set_main_file(&hub, &p, "src/unrelated.rs", "pub const UNRELATED: u32 = 1;\n", "unrelated main update");
    let follow_dir = p.sec.dir("g2-follow");
    p.sec.ok(p.sec.home.path(), &["clone", &hub.url(&p.name), follow_dir.to_str().unwrap()]);
    p.sec.ok(&follow_dir, &["embargo", "follow", &eid]);
    p.sec.ok(&follow_dir, &["push"]);
    let rebased = api.post_json(
        Some(&p.sec.token()),
        &format!("/v1/projects/{}/prs/{pr_id}/revisions", p.name),
        &json!({"head": ebranch}),
    );
    assert_eq!(rebased.status, 200, "{}", body_str(&rebased));
    assert_eq!(rebased.json()["revision"], 2);
    assert_eq!(rebased.json()["patch"], patch1, "rebase over unrelated change must keep patch hash");
    assert_eq!(rebased.json()["review"]["ready"], true, "approval must survive unrelated rebase");

    // 10. Changing `src/guarded/fix.rs` changes `patch` and dismisses the approval!
    write_files(&follow_dir, &[("src/guarded/fix.rs", "pub fn guarded_fix() -> u32 { 2 }\n")]);
    p.sec.ok(&follow_dir, &["commit", "-m", "modify guarded_fix"]);
    p.sec.ok(&follow_dir, &["push"]);
    let modified = api.post_json(
        Some(&p.sec.token()),
        &format!("/v1/projects/{}/prs/{pr_id}/revisions", p.name),
        &json!({"head": ebranch}),
    );
    assert_eq!(modified.status, 200, "{}", body_str(&modified));
    assert_eq!(modified.json()["revision"], 3);
    assert_ne!(modified.json()["patch"].as_str().unwrap(), patch1);
    assert_eq!(modified.json()["review"]["approvals"], 0, "file change must dismiss approval");
    assert_eq!(modified.json()["review"]["ready"], false);
}

/// Guarantee 3: At release the line lands through S17 once, with S21's
/// review rules met (its own PR's approvals count), and its PR is landed; a
/// PR onto the line becomes visible exactly as an ordinary PR, once, across
/// two servers (or lands too, if it was set to land at release and is
/// ready). Unapproved, a release onto a protected branch is held: nothing
/// lands, nothing turns public, and it lands once approved (BUG-1861,
/// BUG-1875).
#[test]
fn guarantee_3_release_turns_pr_ordinary_or_lands_once_across_two_servers() {
    let hub1 = TestHub::start();
    let hub2 = TestHub::beside(&hub1);
    let p = setup_project(&hub1);
    let api1 = hub1.api();
    let api2 = hub2.api();

    let rev1 = hub1.person("rev1");
    p.admin.ok(&p.dir, &["group", "add", "devs", &p.sec.name]);
    p.admin.ok(&p.dir, &["group", "add", "security", &rev1.name]);
    p.admin.ok(&p.dir, &["group", "add", "devs", &rev1.name]);

    // Protect `main` with S21 review rules (`approvals = 1, people_only = true`).
    set_main_file(
        &hub1,
        &p,
        ".veilrules",
        "[branches.main]\nprotected = true\n\n[review]\nlow = { approvals = 1, people_only = true }\nnormal = { approvals = 1, people_only = true }\nhigh = { approvals = 1, people_only = true }\n",
        "protect main for guarantee 3",
    );

    let sec_tok = p.sec.token();
    let rev1_tok = rev1.token();
    let dev_tok = p.dev.token();

    // Open an ordinary PR on `hub1` so we can verify exact ordinary-PR JSON keys after release.
    let mut ord_c = Craft::new(&api1, &p.dev, &p.name, "main");
    ord_c.file("src/ord_ref.rs", "pub const ORD: u8 = 1;\n");
    let ord_ch = ord_c.push_to("ord-ref", None);
    assert_eq!(ord_ch.status, 200, "{}", body_str(&ord_ch));
    let ord_pr = api1
        .post_json(
            Some(&dev_tok),
            &format!("/v1/projects/{}/prs", p.name),
            &json!({"head": "ord-ref", "title": "Ordinary reference PR"}),
        )
        .json();
    let mut ord_keys: Vec<String> = ord_pr.as_object().unwrap().keys().cloned().collect();
    ord_keys.sort();

    // ---- Case A: the line lands at release with its approved PR, armed or not (BUG-1875); a PR onto the
    //      line, not armed, becomes an ordinary open PR once across 2 servers ----
    let main_before_a = api1.tips(Some(&dev_tok), &p.name).unwrap().branches["main"];
    let until_a = veil_core::now_millis() + 60_000;
    let (eid_a, _, _, _) = push_embargo(
        &hub1,
        &p.name,
        &p.sec,
        "g3-a",
        "security",
        Some(until_a),
        &[("src/release_ordinary.rs", "pub const ORDINARY_AFTER_RELEASE: &str = \"CASE-A-3301\";\n")],
        "case A embargo",
    );
    let pr_a = api1.post_json(
        Some(&sec_tok),
        &format!("/v1/projects/{}/prs", p.name),
        &json!({
            "head": format!("embargo/{eid_a}"),
            "title": "Case A embargo PR",
            "body": "Lands with the line",
        }),
    );
    assert_eq!(pr_a.status, 200, "{}", body_str(&pr_a));
    let pr_a_id = pr_a.json()["id"].as_str().unwrap().to_string();
    let patch_a = pr_a.json()["patch"].as_str().unwrap().to_string();

    // An approval of `pr_a` (the line's own PR), keeping `land_at_release = false`.
    let sig_a = sign_review(&rev1, &p.name, &pr_a_id, &patch_a, "approve");
    let app_a = api1.post_json(
        Some(&rev1_tok),
        &format!("/v1/projects/{}/prs/{pr_a_id}/reviews", p.name),
        &json!({"patch": patch_a, "verdict": "approve", "signature": sig_a}),
    );
    assert_eq!(app_a.status, 200);
    assert_eq!(app_a.json()["review"]["ready"], true);

    // A follow-up built on the line's tip, as a PR onto the line: not armed, with a thread.
    let line_a = api1.tips(Some(&sec_tok), &p.name).unwrap().branches[&format!("embargo/{eid_a}")];
    let follow_a = api1.post_json(
        Some(&sec_tok),
        &format!("/v1/projects/{}/changes", p.name),
        &json!({
            "base": line_a.hex(),
            "description": "case A follow-up",
            "edits": [{"path": "src/release_followup.rs", "put": {"text": "pub const FOLLOW_UP: &str = \"CASE-A-FOLLOWUP-3304\";\n"}}],
        }),
    );
    assert_eq!(follow_a.status, 200, "{}", body_str(&follow_a));
    let follow_a_snap = follow_a.json()["snapshot"].as_str().unwrap().to_string();
    let pr_a2 = api1.post_json(
        Some(&sec_tok),
        &format!("/v1/projects/{}/prs", p.name),
        &json!({"head": follow_a_snap, "onto": format!("embargo/{eid_a}"), "title": "Case A follow-up PR", "body": "Stays open at release"}),
    );
    assert_eq!(pr_a2.status, 200, "{}", body_str(&pr_a2));
    assert_eq!(pr_a2.json()["embargo"], eid_a.as_str(), "{}", body_str(&pr_a2));
    let pr_a2_id = pr_a2.json()["id"].as_str().unwrap().to_string();
    let patch_a2 = pr_a2.json()["patch"].as_str().unwrap().to_string();
    let th_a = api1.post_json(
        Some(&sec_tok),
        &format!("/v1/projects/{}/prs/{pr_a2_id}/threads", p.name),
        &json!({"body": "Thread preserved across release"}),
    );
    assert_eq!(th_a.status, 200);

    // Expire `until_a` in PostgreSQL (`release_due` strictly uses `clock_timestamp()`) and race `release_due` across both servers!
    hub1.rt.block_on(async {
        sqlx::query(
            "UPDATE embargo_lines SET until_ms = (extract(epoch FROM clock_timestamp()) * 1000)::BIGINT - 10 WHERE embargo_id = $1",
        )
        .bind(&eid_a)
        .execute(&hub1.hub().db)
        .await
        .unwrap();
    });
    let (n1, n2) = std::thread::scope(|s| {
        let t1 = s.spawn(|| hub1.rt.block_on(veil_server::embargo::release_due(&hub1.hub())).unwrap());
        let t2 = s.spawn(|| hub2.rt.block_on(veil_server::embargo::release_due(&hub2.hub())).unwrap());
        (t1.join().unwrap(), t2.join().unwrap())
    });
    assert!(n1 + n2 <= 1, "at most one server may win the release transition (got {n1} and {n2})");
    let rel_a: Option<i64> = hub1
        .rt
        .block_on(sqlx::query_scalar("SELECT released_at FROM embargo_lines WHERE embargo_id = $1").bind(&eid_a).fetch_one(&hub1.hub().db))
        .unwrap();
    assert!(rel_a.is_some(), "eid_a must be marked released");

    // The line landed on `main`, once, under `pr_a`'s approval: the release never drops it (BUG-1875).
    let main_after_a = api1.tips(Some(&dev_tok), &p.name).unwrap().branches["main"];
    assert_ne!(main_after_a, main_before_a, "the released line must land on main");
    let main_file_a = api1.get(Some(&dev_tok), &format!("/v1/projects/{}/q/file?rev=main&path=src/release_ordinary.rs", p.name));
    assert_eq!(main_file_a.status, 200, "{}", body_str(&main_file_a));
    assert!(body_str(&main_file_a).contains("CASE-A-3301"));
    // The follow-up did not land with it (not armed, not approved).
    let no_follow = api1.get(Some(&dev_tok), &format!("/v1/projects/{}/q/file?rev=main&path=src/release_followup.rs", p.name));
    assert_eq!(no_follow.status, 404, "{}", body_str(&no_follow));
    assert!(!api1.tips(Some(&sec_tok), &p.name).unwrap().branches.contains_key(&format!("embargo/{eid_a}")), "the line is retired");

    for (srv, api) in [("hub1", &api1), ("hub2", &api2)] {
        // `pr_a` landed with the line.
        let sh = api.get(Some(&dev_tok), &format!("/v1/projects/{}/prs/{pr_a_id}", p.name));
        assert_eq!(sh.status, 200, "{srv} outsider show after release: {}", body_str(&sh));
        assert_eq!(sh.json()["state"], "landed", "{srv}: {}", body_str(&sh));
        assert!(sh.json().get("embargo").is_none(), "{srv}: {}", body_str(&sh));

        // Outsider `p.dev` now sees the follow-up PR, with the exact keys of an ordinary PR!
        let sh = api.get(Some(&dev_tok), &format!("/v1/projects/{}/prs/{pr_a2_id}", p.name));
        assert_eq!(sh.status, 200, "{srv} outsider show after release: {}", body_str(&sh));
        let sj = sh.json();
        let mut keys: Vec<String> = sj.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        assert_eq!(keys, ord_keys, "{srv} released PR must have exact ordinary PR JSON shape: {sj}");
        assert_eq!(sj["state"], "open", "{srv}");
        assert_eq!(sj["open_threads"], 1, "{srv}");
        assert_eq!(sj["review"]["ready"], false, "{srv}");
        assert_eq!(sj["patch"], patch_a2.as_str(), "{srv}: the PR's revision is the one that was reviewable before release");

        let df = api.get(Some(&dev_tok), &format!("/v1/projects/{}/prs/{pr_a2_id}/diff", p.name));
        assert_eq!(df.status, 200, "{srv} diff after release: {}", body_str(&df));
        assert!(body_str(&df).contains("CASE-A-FOLLOWUP-3304"), "{srv}");
        assert!(!body_str(&df).contains("CASE-A-3301"), "{srv}: the follow-up PR is its own change only");
    }

    // And the follow-up PR, retargeted at `main`, lands as an ordinary PR via `POST /prs/{id}/land`
    // once approved: exactly its own change, on top of the line's.
    let unapproved = api2.post_json(Some(&sec_tok), &format!("/v1/projects/{}/prs/{pr_a2_id}/land", p.name), &json!({}));
    assert_eq!(unapproved.status, 409, "an unapproved ordinary PR does not land on protected main: {}", body_str(&unapproved));
    let sig_a2 = sign_review(&rev1, &p.name, &pr_a2_id, &patch_a2, "approve");
    let app_a2 = api2.post_json(
        Some(&rev1_tok),
        &format!("/v1/projects/{}/prs/{pr_a2_id}/reviews", p.name),
        &json!({"patch": patch_a2, "verdict": "approve", "signature": sig_a2}),
    );
    assert_eq!(app_a2.status, 200, "{}", body_str(&app_a2));
    let land_a = api2.post_json(
        Some(&sec_tok),
        &format!("/v1/projects/{}/prs/{pr_a2_id}/land", p.name),
        &json!({}),
    );
    assert_eq!(land_a.status, 200, "ordinary land after release failed: {}", body_str(&land_a));
    assert_eq!(land_a.json()["state"], "landed");
    let log_a = api2.get(Some(&dev_tok), &format!("/v1/projects/{}/q/log?rev=main&n=2", p.name)).json();
    assert_eq!(
        log_a["entries"][1]["snapshot_id"].as_str().unwrap(),
        main_after_a.hex(),
        "the retargeted PR lands its own change only, on the released line: {log_a}"
    );

    // ---- Case B: `land_at_release = true` with S21 review rules met -> lands once via S17 across 2 servers ----
    let main_before_b = api1.tips(Some(&dev_tok), &p.name).unwrap().branches["main"];
    let until_b = veil_core::now_millis() + 3_600_000;
    let (eid_b, _, _, _) = push_embargo(
        &hub1,
        &p.name,
        &p.sec,
        "g3-b",
        "security",
        Some(until_b),
        &[("src/land_at_release.rs", "pub const LANDED_AT_RELEASE: &str = \"CASE-B-3302\";\n")],
        "case B embargo",
    );
    let pr_b = api1.post_json(
        Some(&sec_tok),
        &format!("/v1/projects/{}/prs", p.name),
        &json!({
            "head": format!("embargo/{eid_b}"),
            "title": "Case B land-at-release PR",
        }),
    );
    assert_eq!(pr_b.status, 200, "{}", body_str(&pr_b));
    let pr_b_id = pr_b.json()["id"].as_str().unwrap().to_string();
    let patch_b = pr_b.json()["patch"].as_str().unwrap().to_string();

    let sig_b = sign_review(&rev1, &p.name, &pr_b_id, &patch_b, "approve");
    let app_b = api1.post_json(
        Some(&rev1_tok),
        &format!("/v1/projects/{}/prs/{pr_b_id}/reviews", p.name),
        &json!({"patch": patch_b, "verdict": "approve", "signature": sig_b}),
    );
    assert_eq!(app_b.status, 200);
    assert_eq!(app_b.json()["review"]["ready"], true);

    // Immediate landing before release (empty body) is refused with 409!
    let imm_land = api1.post_json(
        Some(&sec_tok),
        &format!("/v1/projects/{}/prs/{pr_b_id}/land", p.name),
        &json!({}),
    );
    assert_eq!(imm_land.status, 409, "immediate land before release must 409: {}", body_str(&imm_land));

    // Arm `land_at_release` via `{"at_release": true}`!
    let arm_b = api1.post_json(
        Some(&sec_tok),
        &format!("/v1/projects/{}/prs/{pr_b_id}/land", p.name),
        &json!({"at_release": true}),
    );
    assert_eq!(arm_b.status, 200, "arm land_at_release failed: {}", body_str(&arm_b));
    assert_eq!(arm_b.json()["land_at_release"], true);
    assert_eq!(arm_b.json()["state"], "open");

    // Race `release_due` across `hub1` and `hub2`!
    hub1.rt.block_on(async {
        sqlx::query(
            "UPDATE embargo_lines SET until_ms = (extract(epoch FROM clock_timestamp()) * 1000)::BIGINT - 10 WHERE embargo_id = $1",
        )
        .bind(&eid_b)
        .execute(&hub1.hub().db)
        .await
        .unwrap();
    });
    let (b1, b2) = std::thread::scope(|s| {
        let t1 = s.spawn(|| hub1.rt.block_on(veil_server::embargo::release_due(&hub1.hub())).unwrap());
        let t2 = s.spawn(|| hub2.rt.block_on(veil_server::embargo::release_due(&hub2.hub())).unwrap());
        (t1.join().unwrap(), t2.join().unwrap())
    });
    assert!(b1 + b2 <= 1, "at most one server may finalize land-at-release (got {b1} and {b2})");
    let rel_b: Option<i64> = hub1
        .rt
        .block_on(sqlx::query_scalar("SELECT released_at FROM embargo_lines WHERE embargo_id = $1").bind(&eid_b).fetch_one(&hub1.hub().db))
        .unwrap();
    assert!(rel_b.is_some(), "eid_b must be marked released");

    let main_after_b = api1.tips(Some(&dev_tok), &p.name).unwrap().branches["main"];
    assert_ne!(main_after_b, main_before_b, "main must advance when land_at_release PR releases");
    let main_file_b = api1.get(
        Some(&dev_tok),
        &format!("/v1/projects/{}/q/file?rev=main&path=src/land_at_release.rs", p.name),
    );
    assert_eq!(main_file_b.status, 200, "{}", body_str(&main_file_b));
    assert!(body_str(&main_file_b).contains("CASE-B-3302"));

    // Verify S17 recorded `snapshots.author > 0` and landed exactly once (`parent == main_before_b`).
    let pid: i64 = hub1
        .rt
        .block_on(sqlx::query_scalar("SELECT id FROM projects WHERE name = $1").bind(&p.name).fetch_one(&hub1.hub().db))
        .unwrap();
    let real_main_after_b: String = hub1
        .rt
        .block_on(
            sqlx::query_scalar("SELECT target FROM branches WHERE project_id = $1 AND name = 'main'")
                .bind(pid)
                .fetch_one(&hub1.hub().db),
        )
        .unwrap();
    let author_id: Option<i64> = hub1
        .rt
        .block_on(
            sqlx::query_scalar("SELECT author FROM snapshots WHERE project_id = $1 AND id = $2")
                .bind(pid)
                .bind(&real_main_after_b)
                .fetch_one(&hub1.hub().db),
        )
        .unwrap();
    assert!(author_id.unwrap_or(0) > 0, "S17 server-signed snapshot must record snapshots.author: {author_id:?}");

    let log_b = api2
        .get(Some(&dev_tok), &format!("/v1/projects/{}/q/log?rev=main&n=2", p.name))
        .json();
    assert_eq!(
        log_b["entries"][1]["snapshot_id"].as_str().unwrap(),
        main_before_b.hex(),
        "land_at_release must land once on main (parent of new tip must be main_before_b)"
    );

    for (srv, api) in [("hub1", &api1), ("hub2", &api2)] {
        let sh = api.get(Some(&dev_tok), &format!("/v1/projects/{}/prs/{pr_b_id}", p.name)).json();
        assert_eq!(sh["state"], "landed", "{srv}: {sh}");
        assert!(sh.get("embargo").is_none(), "{srv} landed ordinary PR must have no embargo field: {sh}");
    }

    // ---- Case C: WITHOUT S21 approval the release is held: nothing lands on protected `main`, nothing turns
    //      public, the embargo's groups are told, and it lands once approved (BUG-1861) ----
    let main_before_c = main_after_b;
    let until_c = veil_core::now_millis() + 3_600_000;
    let (eid_c, _, _, _) = push_embargo(
        &hub1,
        &p.name,
        &p.sec,
        "g3-c",
        "security",
        Some(until_c),
        &[("src/unapproved_release.rs", "pub const UNAPPROVED: &str = \"CASE-C-3303\";\n")],
        "case C unapproved embargo",
    );
    let pr_c = api1.post_json(
        Some(&sec_tok),
        &format!("/v1/projects/{}/prs", p.name),
        &json!({
            "head": format!("embargo/{eid_c}"),
            "title": "Case C unapproved land-at-release PR",
            "land_at_release": true,
        }),
    );
    assert_eq!(pr_c.status, 200, "{}", body_str(&pr_c));
    let pr_c_id = pr_c.json()["id"].as_str().unwrap().to_string();
    assert_eq!(pr_c.json()["land_at_release"], true);
    assert_eq!(pr_c.json()["review"]["ready"], false);

    hub1.rt.block_on(async {
        sqlx::query(
            "UPDATE embargo_lines SET until_ms = (extract(epoch FROM clock_timestamp()) * 1000)::BIGINT - 10 WHERE embargo_id = $1",
        )
        .bind(&eid_c)
        .execute(&hub1.hub().db)
        .await
        .unwrap();
    });
    // (The service is the whole database's: what it released of other tests is not counted.)
    hub1.rt.block_on(veil_server::embargo::release_due(&hub1.hub())).unwrap();
    let released_c = || -> Option<i64> {
        hub1.rt
            .block_on(sqlx::query_scalar("SELECT released_at FROM embargo_lines WHERE embargo_id = $1").bind(&eid_c).fetch_one(&hub1.hub().db))
            .unwrap()
    };
    assert!(released_c().is_none(), "eid_c is held, not released");

    // Protected `main` did NOT accept the unapproved change, and nothing turned public.
    assert_eq!(
        api1.tips(Some(&dev_tok), &p.name).unwrap().branches["main"],
        main_before_c,
        "an unapproved release must never bypass S21 review rules on protected main"
    );
    let dev_tips = api2.tips(Some(&dev_tok), &p.name).unwrap();
    assert!(dev_tips.embargoes.is_empty(), "an outsider saw the held embargo: {:?}", dev_tips.embargoes);
    assert!(!dev_tips.branches.contains_key(&format!("embargo/{eid_c}")));
    let hidden_pr = api2.get(Some(&dev_tok), &format!("/v1/projects/{}/prs/{pr_c_id}", p.name));
    assert_eq!(hidden_pr.status, 404, "a held embargo's PR stays hidden: {}", body_str(&hidden_pr));
    let hidden_file = api2.get(Some(&dev_tok), &format!("/v1/projects/{}/q/file?rev=main&path=src/unapproved_release.rs", p.name));
    assert_eq!(hidden_file.status, 404, "{}", body_str(&hidden_file));
    // The embargo's groups are told why it waits (on both servers).
    let sec_tips = api2.tips(Some(&sec_tok), &p.name).unwrap();
    let rec_c = sec_tips.embargoes.iter().find(|e| e.id == eid_c).expect("a member still sees the held embargo");
    assert_eq!(rec_c.state.as_deref(), Some("waiting_for_approval"), "{rec_c:?}");
    assert!(rec_c.reason.as_deref().is_some_and(|r| r.contains("approval")), "{rec_c:?}");
    assert!(rec_c.released_at.is_none(), "{rec_c:?}");
    assert!(sec_tips.branches.contains_key(&format!("embargo/{eid_c}")), "the held line stays");
    // Trying again changes nothing while it is unapproved.
    hub2.rt.block_on(veil_server::embargo::release_due(&hub2.hub())).unwrap();
    assert!(released_c().is_none());

    // Approved (on the other server), it lands at once and is released.
    let patch_c = pr_c.json()["patch"].as_str().unwrap().to_string();
    let sig_c = sign_review(&rev1, &p.name, &pr_c_id, &patch_c, "approve");
    let app_c = api2.post_json(
        Some(&rev1_tok),
        &format!("/v1/projects/{}/prs/{pr_c_id}/reviews", p.name),
        &json!({"patch": patch_c, "verdict": "approve", "signature": sig_c}),
    );
    assert_eq!(app_c.status, 200, "{}", body_str(&app_c));
    assert!(released_c().is_some(), "an approved, held release lands at once");
    let main_file_c = api1.get(Some(&dev_tok), &format!("/v1/projects/{}/q/file?rev=main&path=src/unapproved_release.rs", p.name));
    assert_eq!(main_file_c.status, 200, "{}", body_str(&main_file_c));
    assert!(body_str(&main_file_c).contains("CASE-C-3303"));
    let sh_c = api1.get(Some(&dev_tok), &format!("/v1/projects/{}/prs/{pr_c_id}", p.name)).json();
    assert_eq!(sh_c["state"], "landed", "{sh_c}");
    assert!(sh_c.get("embargo").is_none());
    let sec_after = api1.tips(Some(&sec_tok), &p.name).unwrap();
    let rec_after = sec_after.embargoes.iter().find(|e| e.id == eid_c);
    assert!(rec_after.is_none_or(|r| r.released_at.is_some() && r.state.is_none()), "{rec_after:?}");
}

/// Guarantee 4: Nothing about it leaks into public search, blame, history or
/// the landing queue's visible state before release.
#[test]
fn guarantee_4_nothing_leaks_into_search_blame_history_or_landing_queue_before_release() {
    const CANARY_CODE: &str = "LEAK-CANARY-CODE-4499";
    const CANARY_PR: &str = "LEAK-CANARY-PR-4488";
    const CANARY_MSG: &str = "LEAK-CANARY-MSG-4477";

    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();

    let rev1 = hub.person("rev1");
    p.admin.ok(&p.dir, &["group", "add", "devs", &p.sec.name]);
    p.admin.ok(&p.dir, &["group", "add", "security", &rev1.name]);
    p.admin.ok(&p.dir, &["group", "add", "devs", &rev1.name]);

    set_main_file(
        &hub,
        &p,
        ".veilrules",
        "[branches.main]\nprotected = true\n\n[review]\nlow = { approvals = 1, people_only = true }\n",
        "protect main for guarantee 4",
    );

    let sec_tok = p.sec.token();
    let rev1_tok = rev1.token();
    let dev_tok = p.dev.token();
    let admin_tok = p.admin.token();

    let dev_sse = api.get_unread(
        &format!("/v1/projects/{}/events", p.name),
        &[("authorization", &format!("Bearer {dev_tok}"))],
    );

    // `p.sec` edits `src/lib.rs` and adds `src/canary.rs` under embargo.
    let until_ms = veil_core::now_millis() + 3_600_000;
    let (eid, fix_id, merge_id, _) = push_embargo(
        &hub,
        &p.name,
        &p.sec,
        "g4-sec",
        "security",
        Some(until_ms),
        &[
            ("src/lib.rs", &format!("{PUBLIC_MARK}\n// {CANARY_CODE}\n")),
            ("src/canary.rs", &format!("pub const CANARY: &str = \"{CANARY_CODE}\";\n")),
        ],
        CANARY_MSG,
    );

    // Open embargoed PR, view it, diff it, comment on it, request-changes on `src/lib.rs`,
    // then approve it and arm `land_at_release = true`!
    let created = api.post_json(
        Some(&sec_tok),
        &format!("/v1/projects/{}/prs", p.name),
        &json!({
            "head": format!("embargo/{eid}"),
            "title": CANARY_PR,
            "body": format!("Details: {CANARY_PR}"),
        }),
    );
    assert_eq!(created.status, 200, "{}", body_str(&created));
    let pr_id = created.json()["id"].as_str().unwrap().to_string();
    let patch = created.json()["patch"].as_str().unwrap().to_string();

    // Exercise diff & show as both `p.sec` (shares `view_key` with `p.dev`!) and `p.admin`!
    for tok in [&sec_tok, &admin_tok] {
        assert_eq!(api.get(Some(tok), &format!("/v1/projects/{}/prs/{pr_id}", p.name)).status, 200);
        let df = api.get(Some(tok), &format!("/v1/projects/{}/prs/{pr_id}/diff", p.name));
        assert_eq!(df.status, 200, "{}", body_str(&df));
        assert!(body_str(&df).contains(CANARY_CODE));
    }

    // `rev1` posts `request-changes` on the embargoed PR touching `src/lib.rs`.
    let rc_sig = sign_review(&rev1, &p.name, &pr_id, &patch, "request-changes");
    let rc = api.post_json(
        Some(&rev1_tok),
        &format!("/v1/projects/{}/prs/{pr_id}/reviews", p.name),
        &json!({"patch": patch, "verdict": "request-changes", "body": CANARY_PR, "signature": rc_sig}),
    );
    assert_eq!(rc.status, 200, "{}", body_str(&rc));

    // CRITICAL: `p.dev` opens a public PR touching `src/lib.rs` while `rev1`'s embargoed
    // `request-changes` is active — `rev1`'s embargo hold must NOT leak onto `p.dev`'s public PR!
    let mut dev_c = Craft::new(&api, &p.dev, &p.name, "main");
    dev_c.file("src/lib.rs", &format!("{PUBLIC_MARK}\n// public edit\n"));
    let dev_ch = dev_c.push_to("dev-lib-edit", None);
    assert_eq!(dev_ch.status, 200, "{}", body_str(&dev_ch));
    let dev_pr = api.post_json(
        Some(&dev_tok),
        &format!("/v1/projects/{}/prs", p.name),
        &json!({"head": "dev-lib-edit", "title": "Public lib PR"}),
    );
    assert_eq!(dev_pr.status, 200, "{}", body_str(&dev_pr));
    assert!(
        !body_str(&dev_pr).contains(&rev1.name),
        "embargoed request-changes hold leaked onto outsider's public PR: {}",
        body_str(&dev_pr)
    );

    // Now `rev1` approves `pr_id` and `p.sec` arms `land_at_release = true`.
    let app_sig = sign_review(&rev1, &p.name, &pr_id, &patch, "approve");
    assert_eq!(
        api.post_json(
            Some(&rev1_tok),
            &format!("/v1/projects/{}/prs/{pr_id}/reviews", p.name),
            &json!({"patch": patch, "verdict": "approve", "signature": app_sig}),
        )
        .status,
        200
    );
    let armed = api.post_json(
        Some(&sec_tok),
        &format!("/v1/projects/{}/prs/{pr_id}/land", p.name),
        &json!({"at_release": true}),
    );
    assert_eq!(armed.status, 200, "{}", body_str(&armed));
    assert_eq!(armed.json()["land_at_release"], true);

    // Run derive & search indexers to full catch-up.
    catch_up(&hub, &p.name);

    let markers = [CANARY_CODE, CANARY_PR, CANARY_MSG, "canary.rs", &eid, &pr_id];

    // Check public (`dev`) AND `admin` query/search/blame/history routes: nothing indexed before release!
    for (who, tok) in [("dev", Some(dev_tok.as_str())), ("admin", Some(admin_tok.as_str())), ("anon", None)] {
        for q_str in ["LEAK-CANARY", "4499", "4488", "canary"] {
            let sr = api.get(tok, &format!("/v1/projects/{}/q/search?q={q_str}", p.name));
            assert_eq!(sr.status, 200, "{who} q/search: {}", body_str(&sr));
            assert_eq!(sr.json()["results"], json!([]), "{who} q/search leaked results: {}", body_str(&sr));
        }

        let bl = api.get(tok, &format!("/v1/projects/{}/q/blame?rev=main&path=src/lib.rs", p.name));
        assert_eq!(bl.status, 200, "{who} q/blame: {}", body_str(&bl));
        assert_no_str(&body_str(&bl), &markers, &format!("{who} q/blame"));

        let hs_lib = api.get(tok, &format!("/v1/projects/{}/q/history?rev=main&path=src/lib.rs&follow=true", p.name));
        assert_eq!(hs_lib.status, 200, "{who} q/history src/lib.rs: {}", body_str(&hs_lib));
        assert_no_str(&body_str(&hs_lib), &markers, &format!("{who} q/history src/lib.rs"));

        let hs_can = api.get(tok, &format!("/v1/projects/{}/q/history?rev=main&path=src/canary.rs&follow=true", p.name));
        let hs_miss = api.get(tok, &format!("/v1/projects/{}/q/history?rev=main&path=src/no_such_file.rs&follow=true", p.name));
        assert_eq!(hs_can.status, 404, "{who} q/history src/canary.rs: {}", body_str(&hs_can));
        assert_eq!((hs_can.status, hs_can.body), (hs_miss.status, hs_miss.body), "{who} q/history src/canary.rs");

        let lg = api.get(tok, &format!("/v1/projects/{}/q/log?rev=main", p.name));
        assert_eq!(lg.status, 200, "{who} q/log: {}", body_str(&lg));
        assert_no_str(&body_str(&lg), &markers, &format!("{who} q/log"));

        let gen = api.post_json(
            tok,
            &format!("/v1/projects/{}/q/generations", p.name),
            &json!({"snapshots": [fix_id.hex(), merge_id.hex()]}),
        );
        assert_eq!(gen.status, 200);
        assert_eq!(gen.json()["generations"], json!([null, null]), "{who} view_graph leaked embargo snapshots!");

        for prefix in [&fix_id.hex()[..8], &merge_id.hex()[..8]] {
            let rs = api.get(tok, &format!("/v1/projects/{}/q/resolve?prefix={prefix}", p.name));
            assert_eq!(rs.status, 200, "{who} q/resolve {prefix}: {}", body_str(&rs));
            assert_eq!(rs.json()["snapshots"], json!([]), "{who} q/resolve {prefix} leaked snapshots: {}", body_str(&rs));
            assert_eq!(rs.json()["changes"], json!([]), "{who} q/resolve {prefix} leaked changes: {}", body_str(&rs));
        }
    }

    // Verify `landing_queue` has NO embargo ticket before release and `GET /land/...` returns 404!
    let pid: i64 = hub
        .rt
        .block_on(sqlx::query_scalar("SELECT id FROM projects WHERE name = $1").bind(&p.name).fetch_one(&hub.hub().db))
        .unwrap();
    let queued_count: i64 = hub
        .rt
        .block_on(
            sqlx::query_scalar("SELECT COUNT(*) FROM landing_queue WHERE project_id = $1 AND ticket LIKE 'embargo%'")
                .bind(pid)
                .fetch_one(&hub.hub().db),
        )
        .unwrap();
    assert_eq!(queued_count, 0, "armed land_at_release must not enter landing_queue before release");

    for ticket_probe in [
        format!("embargo-{pid}-{eid}"),
        format!("embargo-pr-{pid}-{pr_id}"),
    ] {
        let lr = api.get(Some(&dev_tok), &format!("/v1/projects/{}/land/{ticket_probe}", p.name));
        assert_eq!(lr.status, 404, "landing ticket probe leaked: {}", body_str(&lr));
    }

    let dev_events = collect_sse(dev_sse, 10, Duration::from_millis(300));
    for (ev, d) in &dev_events {
        assert_no_str(&format!("{ev}:{d}"), &markers, "dev SSE");
    }
}

/// Guarantee 5: CI runners (S19) refused on its writes; narrowed agent sessions
/// (S11) only within their paths.
#[test]
fn guarantee_5_ci_runners_refused_on_writes_and_narrowed_agents_restricted_to_their_paths() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();

    let rev1 = hub.person("rev1");
    p.admin.ok(&p.dir, &["group", "add", "devs", &p.sec.name]);
    p.admin.ok(&p.dir, &["group", "add", "security", &rev1.name]);
    p.admin.ok(&p.dir, &["group", "add", "devs", &rev1.name]);

    set_main_file(&hub, &p, "src/api/mod.rs", "pub fn init() {}\n", "seed src/api");
    set_main_file(&hub, &p, "src/other/mod.rs", "pub fn other() {}\n", "seed src/other");
    set_main_file(
        &hub,
        &p,
        ".veilrules",
        "[branches.main]\nprotected = true\n\n[review]\nlow = { approvals = 1, people_only = true }\n\n[checks.\"ci/api\"]\npaths = [\"src/api/\"]\n",
        "configure ci/api and review rules",
    );

    let sec_tok = p.sec.token();
    let rev1_tok = rev1.token();
    let dev_tok = p.dev.token();

    // Push two embargo lines for `security`:
    // 1. `eid_in`: touches ONLY `src/api/fix.rs` (inside `src/api`).
    // 2. `eid_out`: touches `src/api/fix2.rs` AND `src/other/out.rs` (outside `src/api`).
    let until_ms = veil_core::now_millis() + 3_600_000;
    let (eid_in, _, _, sec_in_dir) = push_embargo(
        &hub,
        &p.name,
        &p.sec,
        "g5-in",
        "security",
        Some(until_ms),
        &[("src/api/fix.rs", "pub fn api_fix() -> u32 { 10 }\n")],
        "embargo inside src/api",
    );
    let (eid_out, _, _, _) = push_embargo(
        &hub,
        &p.name,
        &p.sec,
        "g5-out",
        "security",
        Some(until_ms),
        &[
            ("src/api/fix2.rs", "pub fn api_fix2() {}\n"),
            ("src/other/out.rs", "pub fn outside() {}\n"),
        ],
        "embargo spanning outside src/api",
    );

    // ---- Part 1: Narrowed S11 agent sessions ----
    let agent_api = api
        .post_json(
            Some(&sec_tok),
            "/v1/sessions/agent",
            &json!({
                "project": p.name,
                "attribution": {"agent": "claude-code/2.3", "task": "S23-G5-API", "run": "1"},
                "only": ["src/api"],
            }),
        )
        .json()["token"]
        .as_str()
        .unwrap()
        .to_string();

    let agent_other = api
        .post_json(
            Some(&sec_tok),
            "/v1/sessions/agent",
            &json!({
                "project": p.name,
                "attribution": {"agent": "claude-code/2.3", "task": "S23-G5-OTHER", "run": "1"},
                "only": ["src/other"],
            }),
        )
        .json()["token"]
        .as_str()
        .unwrap()
        .to_string();

    // Primary action (positive): `agent_api` (`only: ["src/api"]`) opens an embargoed PR on `eid_in`!
    let pr_in_resp = api.post_json(
        Some(&agent_api),
        &format!("/v1/projects/{}/prs", p.name),
        &json!({
            "head": format!("embargo/{eid_in}"),
            "title": "Agent-opened embargo PR inside src/api",
        }),
    );
    assert_eq!(pr_in_resp.status, 200, "narrowed agent inside paths must open embargo PR: {}", body_str(&pr_in_resp));
    let pr_in = pr_in_resp.json()["id"].as_str().unwrap().to_string();
    let patch_in = pr_in_resp.json()["patch"].as_str().unwrap().to_string();

    // `agent_api` can view, diff, open a thread, and post `request-changes` on `pr_in`.
    assert_eq!(api.get(Some(&agent_api), &format!("/v1/projects/{}/prs/{pr_in}", p.name)).status, 200);
    assert_eq!(api.get(Some(&agent_api), &format!("/v1/projects/{}/prs/{pr_in}/diff", p.name)).status, 200);
    let th_in = api.post_json(
        Some(&agent_api),
        &format!("/v1/projects/{}/prs/{pr_in}/threads", p.name),
        &json!({"body": "Agent note"}),
    );
    assert_eq!(th_in.status, 200, "{}", body_str(&th_in));
    let tid_in = th_in.json()["id"].as_str().unwrap().to_string();

    // Meanwhile `agent_other` (`only: ["src/other"]`, even though its person is in `security`!)
    // cannot see or touch `pr_in` on ANY route (404, list count 0)!
    assert_eq!(
        api.get(Some(&agent_other), &format!("/v1/projects/{}/prs?state=all", p.name)).json()["count"],
        0,
        "agent narrowed to src/other must not list PR in src/api"
    );
    assert_eq!(api.get(Some(&agent_other), &format!("/v1/projects/{}/prs/{pr_in}", p.name)).status, 404);
    assert_eq!(api.get(Some(&agent_other), &format!("/v1/projects/{}/prs/{pr_in}/diff", p.name)).status, 404);
    assert_eq!(
        api.post_json(
            Some(&agent_other),
            &format!("/v1/projects/{}/prs/{pr_in}/threads", p.name),
            &json!({"body": "probe"}),
        )
        .status,
        404
    );

    // `agent_api` trying to open an embargoed PR on `eid_out` (touches `src/other/out.rs`) is refused with `403 agent_session`!
    let bad_agent_create = api.post_json(
        Some(&agent_api),
        &format!("/v1/projects/{}/prs", p.name),
        &json!({
            "head": format!("embargo/{eid_out}"),
            "title": "Out of scope embargo PR",
        }),
    );
    assert_eq!(bad_agent_create.status, 403, "{}", body_str(&bad_agent_create));
    assert_eq!(bad_agent_create.json()["code"], "agent_session", "{}", body_str(&bad_agent_create));

    // Human `p.sec` opens `pr_out` on `eid_out`; `agent_api` cannot see `pr_out` (404) and cannot release `eid_out` (`403 agent_session`)!
    let pr_out_resp = api.post_json(
        Some(&sec_tok),
        &format!("/v1/projects/{}/prs", p.name),
        &json!({
            "head": format!("embargo/{eid_out}"),
            "title": "Human embargo PR spanning src/other",
        }),
    );
    assert_eq!(pr_out_resp.status, 200, "{}", body_str(&pr_out_resp));
    let pr_out = pr_out_resp.json()["id"].as_str().unwrap().to_string();
    assert_eq!(api.get(Some(&agent_api), &format!("/v1/projects/{}/prs/{pr_out}", p.name)).status, 404);
    let bad_rel = api.post_json(
        Some(&agent_api),
        &format!("/v1/projects/{}/embargoes/{eid_out}/release", p.name),
        &json!({}),
    );
    assert_eq!(bad_rel.status, 403, "narrowed agent must not release embargo touching outside paths: {}", body_str(&bad_rel));
    assert_eq!(bad_rel.json()["code"], "agent_session", "{}", body_str(&bad_rel));

    // Human `rev1` approves `pr_in`; `agent_api` CAN arm `land_at_release` on `pr_in` (all paths inside `src/api`)!
    let sig_in = sign_review(&rev1, &p.name, &pr_in, &patch_in, "approve");
    assert_eq!(
        api.post_json(
            Some(&rev1_tok),
            &format!("/v1/projects/{}/prs/{pr_in}/reviews", p.name),
            &json!({"patch": patch_in, "verdict": "approve", "signature": sig_in}),
        )
        .status,
        200
    );
    let agent_arm = api.post_json(
        Some(&agent_api),
        &format!("/v1/projects/{}/prs/{pr_in}/land", p.name),
        &json!({"at_release": true}),
    );
    assert_eq!(agent_arm.status, 200, "narrowed agent inside paths can arm land_at_release: {}", body_str(&agent_arm));
    assert_eq!(agent_arm.json()["land_at_release"], true);

    // ---- Part 2: S19 CI runners refused on EVERY write route ----
    let runner_resp = api.post_json(
        Some(&sec_tok),
        "/v1/sessions/ci",
        &json!({"project": p.name, "check": "ci/api"}),
    );
    assert_eq!(runner_resp.status, 200, "{}", body_str(&runner_resp));
    let runner_tok = runner_resp.json()["token"].as_str().unwrap().to_string();

    // Runner in embargo group narrowed to `src/api` CAN read `pr_in` (200), CANNOT read `pr_out` (404),
    // and CAN post a check result on `pr_in`'s head!
    let runner_show = api.get(Some(&runner_tok), &format!("/v1/projects/{}/prs/{pr_in}", p.name));
    assert_eq!(runner_show.status, 200, "{}", body_str(&runner_show));
    assert_eq!(api.get(Some(&runner_tok), &format!("/v1/projects/{}/prs/{pr_out}", p.name)).status, 404);
    let head_for_runner = runner_show.json()["revisions"][0]["head"].as_str().unwrap().to_string();
    let chk_ok = api.post_json(
        Some(&runner_tok),
        &format!("/v1/projects/{}/checks", p.name),
        &json!({"snapshot": head_for_runner, "name": "ci/api", "state": "pass", "summary": "runner check ok"}),
    );
    assert_eq!(chk_ok.status, 200, "{}", body_str(&chk_ok));
    assert_eq!(api.get(Some(&dev_tok), &format!("/v1/projects/{}/checks?rev={head_for_runner}", p.name)).status, 404);

    // Every PR write route + embargo release route refuses the CI runner (`403 agent_session`)!
    for (route, payload) in [
        (format!("/v1/projects/{}/prs", p.name), json!({"head": format!("embargo/{eid_in}"), "title": "runner pr"})),
        (format!("/v1/projects/{}/prs/{pr_in}/revisions", p.name), json!({"head": format!("embargo/{eid_in}")})),
        (format!("/v1/projects/{}/prs/{pr_in}/close", p.name), json!({})),
        (format!("/v1/projects/{}/prs/{pr_in}/threads", p.name), json!({"body": "runner comment"})),
        (format!("/v1/projects/{}/prs/{pr_in}/threads/{tid_in}", p.name), json!({"body": "runner reply"})),
        (format!("/v1/projects/{}/prs/{pr_in}/reviews", p.name), json!({"patch": patch_in, "verdict": "request-changes", "signature": "00"})),
        (format!("/v1/projects/{}/prs/{pr_in}/reviews/dismiss", p.name), json!({"person": rev1.name})),
        (format!("/v1/projects/{}/prs/{pr_in}/land", p.name), json!({"at_release": false})),
        (format!("/v1/projects/{}/embargoes/{eid_in}/release", p.name), json!({})),
    ] {
        let r = api.post_json(Some(&runner_tok), &route, &payload);
        assert_eq!(r.status, 403, "runner write {route} must 403: {}", body_str(&r));
        assert_eq!(r.json()["code"], "agent_session", "runner write {route} must return agent_session: {}", body_str(&r));
        assert!(
            r.json()["message"].as_str().unwrap_or("").contains("CI runner"),
            "runner refusal message on {route}: {}",
            body_str(&r)
        );
    }

    // Finally, if human `p.sec` pushes a commit onto `embargo/<eid_in>` touching `src/other/leak.rs`,
    // `agent_api` trying `POST /prs/{pr_in}/revisions` onto it is refused with `403 agent_session`!
    write_files(&sec_in_dir, &[("src/other/leak.rs", "pub fn leak() {}\n")]);
    p.sec.ok(&sec_in_dir, &["commit", "-m", "touch outside src/api"]);
    p.sec.ok(&sec_in_dir, &["push"]);
    let bad_upd = api.post_json(
        Some(&agent_api),
        &format!("/v1/projects/{}/prs/{pr_in}/revisions", p.name),
        &json!({"head": format!("embargo/{eid_in}")}),
    );
    assert_eq!(bad_upd.status, 403, "narrowed agent update outside paths must 403: {}", body_str(&bad_upd));
    assert_eq!(bad_upd.json()["code"], "agent_session", "{}", body_str(&bad_upd));
}

// ---- review rv-new (BUG-1875) -------------------------------------------------------

/// BUG-1875: an embargo that ever had a PR (`embargo_lines.has_pr`, never
/// cleared) releases through `prs::embargo::release_embargo_prs`, which lands
/// only armed, approved, open PRs and then deletes the `embargo/<id>`
/// branch. With its PR closed (opened by mistake, or replaced), the fix
/// lands nowhere and no branch holds it any more: at the release an
/// embargoed fix silently leaves every branch. Without a PR the same
/// embargo lands on its target (S22).
#[test]
fn bug_1875_a_released_embargo_whose_pr_was_closed_keeps_its_fix_on_a_branch() {
    const FIX: &str = "RVNEW_EMBARGOED_FIX_1875";
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    p.admin.ok(&p.dir, &["group", "add", "devs", &p.sec.name]);
    let (eid, _, _, _) = push_embargo(
        &hub,
        &p.name,
        &p.sec,
        "rv-1875",
        "security",
        Some(veil_core::now_millis() + 3_600_000),
        &[("src/fix_1875.rs", &format!("pub const FIX: &str = \"{FIX}\";\n"))],
        "an embargoed fix",
    );
    let (admin, sec) = (p.admin.token(), p.sec.token());
    let file_on = |branch: &str| api.get(Some(&admin), &format!("/v1/projects/{}/q/file?rev={branch}&path=src/fix_1875.rs", p.name));

    // A PR on the embargoed fix, opened and closed again.
    let pr = api.post_json(Some(&sec), &format!("/v1/projects/{}/prs", p.name), &json!({"head": format!("embargo/{eid}"), "title": "the fix"}));
    assert_eq!(pr.status, 200, "{}", body_str(&pr));
    let id = pr.json()["id"].as_str().unwrap().to_string();
    let closed = api.post_json(Some(&sec), &format!("/v1/projects/{}/prs/{id}/close", p.name), &json!({}));
    assert_eq!(closed.status, 200, "{}", body_str(&closed));
    assert_eq!(closed.json()["state"], "closed", "{}", body_str(&closed));

    // The admin releases the embargo.
    let rel = api.post_json(Some(&admin), &format!("/v1/projects/{}/embargoes/{eid}/release", p.name), &json!({}));
    assert_eq!(rel.status, 200, "{}", body_str(&rel));
    let released: Option<i64> = hub
        .rt
        .block_on(sqlx::query_scalar("SELECT released_at FROM embargo_lines WHERE embargo_id = $1").bind(&eid).fetch_one(&hub.hub().db))
        .unwrap();
    assert!(released.is_some(), "the embargo is released");

    // The fix is on a branch: its target's, or at least the line it was on.
    let tips = api.tips(Some(&admin), &p.name).unwrap();
    let holders: Vec<&String> = tips
        .branches
        .keys()
        .filter(|b| {
            let r = file_on(b);
            r.status == 200 && String::from_utf8_lossy(&r.body).contains(FIX)
        })
        .collect();
    assert!(!holders.is_empty(), "the released fix is on no branch (branches: {:?})", tips.branches.keys().collect::<Vec<_>>());
}

/// BUG-1875, the other way round: a PR **onto** the embargo line from an
/// ordinary branch. The release never lands the line (it has a PR), lands
/// at most the PR's own changes, and deletes `embargo/<id>`: the embargoed
/// fix is then on no branch and no PR revision names it (the PR's head is
/// the ordinary branch), so nothing keeps it from the collector.
#[test]
fn bug_1875_a_released_embargo_with_a_pr_onto_its_line_keeps_its_fix_on_a_branch() {
    const FIX: &str = "RVNEW_EMBARGOED_FIX_ONTO_1875";
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    p.admin.ok(&p.dir, &["group", "add", "devs", &p.sec.name]);
    // An ordinary branch, before the embargo.
    let mut c = Craft::new(&api, &p.dev, &p.name, "main");
    c.file("src/followup_1875.rs", "pub const FOLLOWUP: u8 = 1;\n");
    let pushed = c.push_to("followup-1875", None);
    assert_eq!(pushed.status, 200, "{}", body_str(&pushed));
    let (eid, _, _, _) = push_embargo(
        &hub,
        &p.name,
        &p.sec,
        "rv-1875-onto",
        "security",
        Some(veil_core::now_millis() + 3_600_000),
        &[("src/fix_onto_1875.rs", &format!("pub const FIX: &str = \"{FIX}\";\n"))],
        "an embargoed fix",
    );
    let (admin, sec) = (p.admin.token(), p.sec.token());

    // A PR of the ordinary branch onto the embargo line.
    let pr = api.post_json(
        Some(&sec),
        &format!("/v1/projects/{}/prs", p.name),
        &json!({"head": "followup-1875", "onto": format!("embargo/{eid}"), "title": "a follow-up for the fix"}),
    );
    assert_eq!(pr.status, 200, "{}", body_str(&pr));
    assert_eq!(pr.json()["embargo"], eid.as_str(), "{}", body_str(&pr));

    // The admin releases the embargo.
    let rel = api.post_json(Some(&admin), &format!("/v1/projects/{}/embargoes/{eid}/release", p.name), &json!({}));
    assert_eq!(rel.status, 200, "{}", body_str(&rel));
    let released: Option<i64> = hub
        .rt
        .block_on(sqlx::query_scalar("SELECT released_at FROM embargo_lines WHERE embargo_id = $1").bind(&eid).fetch_one(&hub.hub().db))
        .unwrap();
    assert!(released.is_some(), "the embargo is released");

    // The fix is on a branch.
    let tips = api.tips(Some(&admin), &p.name).unwrap();
    let holders: Vec<&String> = tips
        .branches
        .keys()
        .filter(|b| {
            let r = api.get(Some(&admin), &format!("/v1/projects/{}/q/file?rev={b}&path=src/fix_onto_1875.rs", p.name));
            r.status == 200 && String::from_utf8_lossy(&r.body).contains(FIX)
        })
        .collect();
    assert!(!holders.is_empty(), "the released fix is on no branch (branches: {:?})", tips.branches.keys().collect::<Vec<_>>());
}

// ---- BUG-1861 and BUG-1875: a release lands the line, approved, or it is held ---------

/// A project whose `main` is protected with the default review rules (a
/// change of source code needs one approval), and `rev1`: like `sec`, in
/// `security` (the embargoes' group) and in `devs` (who write `src/`).
fn protected_project(hub: &TestHub) -> (Project, Person) {
    let p = setup_project(hub);
    let rev1 = hub.person("rev1");
    p.admin.ok(&p.dir, &["group", "add", "devs", &p.sec.name]);
    p.admin.ok(&p.dir, &["group", "add", "security", &rev1.name]);
    p.admin.ok(&p.dir, &["group", "add", "devs", &rev1.name]);
    set_main_file(hub, &p, ".veilrules", "[branches.main]\nprotected = true\n", "protect main");
    (p, rev1)
}

/// `who` approves the current revision of the PR `pr` (its JSON).
fn approve(api: &Api, who: &Person, project: &str, pr: &Value) -> Reply {
    let (id, patch) = (pr["id"].as_str().unwrap(), pr["patch"].as_str().unwrap());
    let sig = sign_review(who, project, id, patch, "approve");
    api.post_json(
        Some(&who.token()),
        &format!("/v1/projects/{project}/prs/{id}/reviews"),
        &json!({"patch": patch, "verdict": "approve", "signature": sig}),
    )
}

fn released_at(hub: &TestHub, eid: &str) -> Option<i64> {
    hub.rt
        .block_on(sqlx::query_scalar("SELECT released_at FROM embargo_lines WHERE embargo_id = $1").bind(eid).fetch_one(&hub.hub().db))
        .unwrap()
}

/// BUG-1861: a release onto a protected branch meets S21's review rules like
/// any landing. Asked for early by a member, with no approval, it is held:
/// nothing lands, the embargo stays hidden, its groups are told that it
/// waits for approval, and it lands once an embargo PR of the line is
/// approved, without being asked for again.
#[test]
fn bug_1861_an_unapproved_release_is_held_hidden_and_lands_once_approved() {
    const FIX: &str = "HELD_RELEASE_FIX_1861";
    let hub = TestHub::start();
    let (p, rev1) = protected_project(&hub);
    let api = hub.api();
    let (sec, dev) = (p.sec.token(), p.dev.token());
    let before = api.tips(Some(&dev), &p.name).unwrap().branches["main"];
    // An embargo with no deadline.
    let (eid, _, _, _) = push_embargo(
        &hub,
        &p.name,
        &p.sec,
        "held-1861",
        "security",
        None,
        &[("src/held_1861.rs", &format!("pub const FIX: &str = \"{FIX}\";\n"))],
        "an embargoed fix",
    );
    let line = format!("embargo/{eid}");
    let file_on_main = || api.get(Some(&dev), &format!("/v1/projects/{}/q/file?rev=main&path=src/held_1861.rs", p.name));
    let release = || api.post_json(Some(&sec), &format!("/v1/projects/{}/embargoes/{eid}/release", p.name), &json!({}));

    // A member asks for its release: held, with the refusal a direct landing gets.
    let rel = release();
    assert_eq!(rel.status, 409, "{}", body_str(&rel));
    assert_eq!(rel.json()["code"], "not_ready", "{}", body_str(&rel));
    assert!(body_str(&rel).contains("waits for approval") && body_str(&rel).contains("not ready to land"), "{}", body_str(&rel));
    let held = |when: &str| {
        assert!(released_at(&hub, &eid).is_none(), "{when}: held, not released");
        assert_eq!(api.tips(Some(&dev), &p.name).unwrap().branches["main"], before, "{when}: nothing landed");
        assert_eq!(file_on_main().status, 404, "{when}: the fix is not public");
        let dev_tips = api.tips(Some(&dev), &p.name).unwrap();
        assert!(dev_tips.embargoes.is_empty() && !dev_tips.branches.contains_key(&line), "{when}: an outsider saw the held embargo");
        // Its groups are told.
        let sec_tips = api.tips(Some(&sec), &p.name).unwrap();
        assert!(sec_tips.branches.contains_key(&line), "{when}: the line stays");
        let rec = sec_tips.embargoes.iter().find(|e| e.id == eid).expect("a member sees the held embargo");
        assert_eq!(rec.state.as_deref(), Some("waiting_for_approval"), "{when}: {rec:?}");
        assert!(rec.reason.as_deref().is_some_and(|r| r.contains("needs 1 approval")), "{when}: {rec:?}");
        assert!(rec.released_at.is_none(), "{when}: {rec:?}");
    };
    held("after the release was asked for");
    // The release service tries it again and holds it again; asking again changes nothing.
    hub.rt.block_on(veil_server::embargo::release_due(&hub.hub())).unwrap();
    held("after the release service ran");
    assert_eq!(release().status, 409);

    // An embargo PR of the line; while it is unapproved the release stays held.
    let pr = api.post_json(Some(&sec), &format!("/v1/projects/{}/prs", p.name), &json!({"head": line, "title": "the fix"}));
    assert_eq!(pr.status, 200, "{}", body_str(&pr));
    let pr_id = pr.json()["id"].as_str().unwrap().to_string();
    hub.rt.block_on(veil_server::embargo::release_due(&hub.hub())).unwrap();
    held("with an unapproved PR");

    // Approved: the held release lands, with nobody asking again.
    let ok = approve(&api, &rev1, &p.name, &pr.json());
    assert_eq!(ok.status, 200, "{}", body_str(&ok));
    assert!(released_at(&hub, &eid).is_some(), "an approved, held release lands at once");
    let f = file_on_main();
    assert_eq!(f.status, 200, "{}", body_str(&f));
    assert!(body_str(&f).contains(FIX));
    let log = api.get(Some(&dev), &format!("/v1/projects/{}/q/log?rev=main&n=2", p.name)).json();
    assert_eq!(log["entries"][1]["snapshot_id"].as_str().unwrap(), before.hex(), "the fix landed once: {log}");
    let shown = api.get(Some(&dev), &format!("/v1/projects/{}/prs/{pr_id}", p.name));
    assert_eq!(shown.status, 200, "{}", body_str(&shown));
    assert_eq!(shown.json()["state"], "landed", "{}", body_str(&shown));
    assert!(!api.tips(Some(&sec), &p.name).unwrap().branches.contains_key(&line), "the line is retired");
}

/// BUG-1875, the review's lead: a PR **onto** the embargo line holds only
/// the changes on top of the line, and its approval is of those. A release
/// never lands the line's own changes under that review: with the top PR
/// approved and armed but the line itself unapproved, the release is held
/// and nothing lands; once the line's own PR is approved, the line lands
/// under it, and then the armed PR lands its own change.
#[test]
fn bug_1875_a_pr_onto_the_line_never_lands_the_lines_changes_under_its_own_review() {
    const FIX: &str = "LINE_FIX_UNDER_ITS_OWN_REVIEW_1875";
    const TOP: &str = "TOP_CHANGE_1875";
    let hub = TestHub::start();
    let (p, rev1) = protected_project(&hub);
    let api = hub.api();
    let (sec, dev) = (p.sec.token(), p.dev.token());
    let before = api.tips(Some(&dev), &p.name).unwrap().branches["main"];
    let (eid, _, _, _) = push_embargo(
        &hub,
        &p.name,
        &p.sec,
        "lead-1875",
        "security",
        Some(veil_core::now_millis() + 3_600_000),
        &[("src/line_1875.rs", &format!("pub const FIX: &str = \"{FIX}\";\n"))],
        "an embargoed fix",
    );
    let line = format!("embargo/{eid}");
    let on_main = |path: &str| api.get(Some(&dev), &format!("/v1/projects/{}/q/file?rev=main&path={path}", p.name));

    // A change on top of the line's tip, as a PR onto the line: approved, and armed to land at release.
    let tip = api.tips(Some(&sec), &p.name).unwrap().branches[&line];
    let top = api.post_json(
        Some(&sec),
        &format!("/v1/projects/{}/changes", p.name),
        &json!({
            "base": tip.hex(),
            "description": "on top of the fix",
            "edits": [{"path": "src/top_1875.rs", "put": {"text": format!("pub const TOP: &str = \"{TOP}\";\n")}}],
        }),
    );
    assert_eq!(top.status, 200, "{}", body_str(&top));
    let top_snap = top.json()["snapshot"].as_str().unwrap().to_string();
    let top_pr = api.post_json(
        Some(&sec),
        &format!("/v1/projects/{}/prs", p.name),
        &json!({"head": top_snap, "onto": line, "title": "on top of the fix"}),
    );
    assert_eq!(top_pr.status, 200, "{}", body_str(&top_pr));
    let top_id = top_pr.json()["id"].as_str().unwrap().to_string();
    let diff = api.get(Some(&sec), &format!("/v1/projects/{}/prs/{top_id}/diff", p.name));
    assert_eq!(diff.status, 200, "{}", body_str(&diff));
    assert!(body_str(&diff).contains(TOP) && !body_str(&diff).contains(FIX), "the PR onto the line is the top change only");
    let ok = approve(&api, &rev1, &p.name, &top_pr.json());
    assert_eq!(ok.status, 200, "{}", body_str(&ok));
    assert_eq!(ok.json()["review"]["ready"], true, "{}", body_str(&ok));
    let armed = api.post_json(Some(&sec), &format!("/v1/projects/{}/prs/{top_id}/land", p.name), &json!({"at_release": true}));
    assert_eq!(armed.status, 200, "{}", body_str(&armed));
    assert_eq!(armed.json()["land_at_release"], true, "{}", body_str(&armed));

    // The release is held: the line's own changes have no approval, whatever the PR on top has.
    let rel = api.post_json(Some(&sec), &format!("/v1/projects/{}/embargoes/{eid}/release", p.name), &json!({}));
    assert_eq!(rel.status, 409, "{}", body_str(&rel));
    assert_eq!(rel.json()["code"], "not_ready", "{}", body_str(&rel));
    assert!(released_at(&hub, &eid).is_none(), "held, not released");
    assert_eq!(api.tips(Some(&dev), &p.name).unwrap().branches["main"], before, "nothing landed under the top change's review");
    assert_eq!((on_main("src/line_1875.rs").status, on_main("src/top_1875.rs").status), (404, 404));
    let hidden = api.get(Some(&dev), &format!("/v1/projects/{}/prs/{top_id}", p.name));
    assert_eq!(hidden.status, 404, "the held embargo's PR stays hidden: {}", body_str(&hidden));

    // The line's own PR, approved: the line lands under it, then the armed PR lands its own change.
    let line_pr = api.post_json(Some(&sec), &format!("/v1/projects/{}/prs", p.name), &json!({"head": line, "title": "the fix"}));
    assert_eq!(line_pr.status, 200, "{}", body_str(&line_pr));
    let line_id = line_pr.json()["id"].as_str().unwrap().to_string();
    let ok = approve(&api, &rev1, &p.name, &line_pr.json());
    assert_eq!(ok.status, 200, "{}", body_str(&ok));
    assert!(released_at(&hub, &eid).is_some(), "approved, the held release lands");
    let (f, t) = (on_main("src/line_1875.rs"), on_main("src/top_1875.rs"));
    assert_eq!((f.status, t.status), (200, 200), "{} {}", body_str(&f), body_str(&t));
    assert!(body_str(&f).contains(FIX) && body_str(&t).contains(TOP));
    for id in [&line_id, &top_id] {
        let shown = api.get(Some(&dev), &format!("/v1/projects/{}/prs/{id}", p.name));
        assert_eq!(shown.status, 200, "{}", body_str(&shown));
        assert_eq!(shown.json()["state"], "landed", "{}", body_str(&shown));
    }
}

/// BUG-1875: a PR onto the line is never retargeted at release to land
/// changes its revision does not list. An admin moves the line off the fix
/// the PR stands on; at release the PR's landing would carry that fix under
/// the review of the top change only, so the PR is closed and nothing of it
/// lands.
#[test]
fn bug_1875_a_pr_onto_a_rewritten_line_is_closed_at_release_and_lands_nothing_unreviewed() {
    const FIX: &str = "DROPPED_LINE_FIX_1875";
    let hub = TestHub::start();
    let (p, rev1) = protected_project(&hub);
    let api = hub.api();
    let (admin, sec, dev) = (p.admin.token(), p.sec.token(), p.dev.token());
    let before = api.tips(Some(&dev), &p.name).unwrap().branches["main"];
    let (eid, _, _, _) = push_embargo(
        &hub,
        &p.name,
        &p.sec,
        "rewritten-1875",
        "security",
        Some(veil_core::now_millis() + 3_600_000),
        &[("src/dropped_1875.rs", &format!("pub const FIX: &str = \"{FIX}\";\n"))],
        "an embargoed fix",
    );
    let line = format!("embargo/{eid}");
    let tip = api.tips(Some(&sec), &p.name).unwrap().branches[&line];
    let top = api.post_json(
        Some(&sec),
        &format!("/v1/projects/{}/changes", p.name),
        &json!({
            "base": tip.hex(),
            "description": "on top of the fix",
            "edits": [{"path": "src/top_rewritten_1875.rs", "put": {"text": "pub const TOP: u8 = 1;\n"}}],
        }),
    );
    assert_eq!(top.status, 200, "{}", body_str(&top));
    let top_pr = api.post_json(
        Some(&sec),
        &format!("/v1/projects/{}/prs", p.name),
        &json!({"head": top.json()["snapshot"], "onto": line, "title": "on top of the fix", "land_at_release": true}),
    );
    assert_eq!(top_pr.status, 200, "{}", body_str(&top_pr));
    let top_id = top_pr.json()["id"].as_str().unwrap().to_string();
    let ok = approve(&api, &rev1, &p.name, &top_pr.json());
    assert_eq!(ok.status, 200, "{}", body_str(&ok));
    assert_eq!(ok.json()["review"]["ready"], true, "{}", body_str(&ok));

    // The admin takes the fix off the line (the line is main's tip again).
    let admin_tip = api.tips(Some(&admin), &p.name).unwrap();
    let moved = api.post_json(
        Some(&admin),
        &format!("/v1/projects/{}/push", p.name),
        &json!({"updates": [{"branch": line, "expected": admin_tip.branches[&line].hex(), "new": admin_tip.branches["main"].hex()}], "force": true}),
    );
    assert_eq!(moved.status, 200, "{}", body_str(&moved));
    assert_eq!(api.tips(Some(&admin), &p.name).unwrap().branches[&line], admin_tip.branches["main"], "{}", body_str(&moved));

    // The release: the line holds nothing to land; the PR on the dropped fix is closed, not landed.
    let rel = api.post_json(Some(&sec), &format!("/v1/projects/{}/embargoes/{eid}/release", p.name), &json!({}));
    assert_eq!(rel.status, 200, "{}", body_str(&rel));
    assert!(released_at(&hub, &eid).is_some(), "released");
    assert_eq!(api.tips(Some(&dev), &p.name).unwrap().branches["main"], before, "the dropped fix landed under the top change's review");
    let f = api.get(Some(&dev), &format!("/v1/projects/{}/q/file?rev=main&path=src/dropped_1875.rs", p.name));
    assert_eq!(f.status, 404, "{}", body_str(&f));
    let shown = api.get(Some(&dev), &format!("/v1/projects/{}/prs/{top_id}", p.name));
    assert_eq!(shown.status, 200, "{}", body_str(&shown));
    assert_eq!(shown.json()["state"], "closed", "{}", body_str(&shown));
    let land = api.post_json(Some(&sec), &format!("/v1/projects/{}/prs/{top_id}/land", p.name), &json!({}));
    assert_eq!(land.status, 409, "a closed PR does not land: {}", body_str(&land));
    assert_eq!(api.tips(Some(&dev), &p.name).unwrap().branches["main"], before);
}

/// BUG-1875: the collector's roots keep an embargoed fix until it has
/// landed. The embargo's only PR is closed and its release is held (no
/// approval); garbage collection, past its retention window, keeps the fix
/// (the held line is a root), and once approved it lands whole.
#[test]
fn bug_1875_the_collector_keeps_a_held_embargos_fix_until_it_lands() {
    use veil_server::pack_gc::{self, Options};
    const FIX_FILE: &str = "pub const FIX: &str = \"GC_KEEPS_HELD_FIX_1875\";\n";
    let hub = TestHub::start();
    let (p, rev1) = protected_project(&hub);
    let api = hub.api();
    let (sec, dev) = (p.sec.token(), p.dev.token());
    let h = hub.hub();
    let pid: i64 = hub.rt.block_on(sqlx::query_scalar("SELECT id FROM projects WHERE name = $1").bind(&p.name).fetch_one(&h.db)).unwrap();
    let (eid, _, _, _) = push_embargo(
        &hub,
        &p.name,
        &p.sec,
        "gc-1875",
        "security",
        Some(veil_core::now_millis() + 3_600_000),
        &[("src/gc_1875.rs", FIX_FILE)],
        "an embargoed fix",
    );
    let line = format!("embargo/{eid}");
    let blob = ObjectId::hash(&veil_core::object::Object::Blob(FIX_FILE.as_bytes().to_vec()).encode());

    // The embargo's PR, closed again; then its release is asked for, and held.
    let pr = api.post_json(Some(&sec), &format!("/v1/projects/{}/prs", p.name), &json!({"head": line, "title": "the fix"}));
    assert_eq!(pr.status, 200, "{}", body_str(&pr));
    let closed = api.post_json(Some(&sec), &format!("/v1/projects/{}/prs/{}/close", p.name, pr.json()["id"].as_str().unwrap()), &json!({}));
    assert_eq!(closed.status, 200, "{}", body_str(&closed));
    let rel = api.post_json(Some(&sec), &format!("/v1/projects/{}/embargoes/{eid}/release", p.name), &json!({}));
    assert_eq!(rel.status, 409, "{}", body_str(&rel));
    assert!(released_at(&hub, &eid).is_none(), "held, not released");

    // Two collections, the second past the retention window.
    for now_offset_ms in [0, 180_000] {
        let opts = Options { min_packs_to_merge: 2, run_gc: true, retention_window_ms: 60_000, pack_grace_ms: 0, now_offset_ms, ..Options::default() };
        let r = hub.rt.block_on(pack_gc::run_project(&h, pid, &opts)).unwrap();
        assert!(!r.skipped, "{r:?}");
    }
    let fresh = veil_server::store::Objects::with_db(h.objects.blob_store().clone(), 1 << 10, Some(h.db.clone()));
    assert!(hub.rt.block_on(fresh.exists(pid, &blob)).unwrap(), "the collector deleted a held embargo's fix");
    assert!(api.tips(Some(&sec), &p.name).unwrap().branches.contains_key(&line), "the held line stays");

    // A new PR of the line, approved: the fix lands whole.
    let pr2 = api.post_json(Some(&sec), &format!("/v1/projects/{}/prs", p.name), &json!({"head": line, "title": "the fix, again"}));
    assert_eq!(pr2.status, 200, "{}", body_str(&pr2));
    let ok = approve(&api, &rev1, &p.name, &pr2.json());
    assert_eq!(ok.status, 200, "{}", body_str(&ok));
    assert!(released_at(&hub, &eid).is_some(), "approved, the held release lands");
    let f = api.get(Some(&dev), &format!("/v1/projects/{}/q/file?rev=main&path=src/gc_1875.rs", p.name));
    assert_eq!(f.status, 200, "{}", body_str(&f));
    assert!(body_str(&f).contains("GC_KEEPS_HELD_FIX_1875"), "{}", body_str(&f));
}

/// BUG-1875: a release's landing ticket is of one tip of the line. A ticket
/// that landed (a release that landed and did not finish; made here by
/// renaming two landed tickets of the project: to the ticket's name before
/// the fix, and to the first tip's) never stands in for commits pushed to
/// the line since: the release lands them too, and only then retires the
/// line.
#[test]
fn bug_1875_a_ticket_that_landed_an_earlier_tip_never_retires_later_commits_unlanded() {
    const FIX: &str = "FIRST_TIP_FIX_1875";
    const MORE: &str = "PUSHED_SINCE_1875";
    let hub = TestHub::start();
    let p = setup_project(&hub);
    p.admin.ok(&p.dir, &["group", "add", "devs", &p.sec.name]);
    let api = hub.api();
    let (sec, dev) = (p.sec.token(), p.dev.token());
    let h = hub.hub();
    let pid: i64 = hub.rt.block_on(sqlx::query_scalar("SELECT id FROM projects WHERE name = $1").bind(&p.name).fetch_one(&h.db)).unwrap();
    // Two ordinary landings: their tickets are renamed below.
    set_main_file(&hub, &p, "docs/a_1875.md", "a\n", "an ordinary landing");
    set_main_file(&hub, &p, "docs/b_1875.md", "b\n", "another");
    let (eid, _, _, _) = push_embargo(
        &hub,
        &p.name,
        &p.sec,
        "ticket-1875",
        "security",
        Some(veil_core::now_millis() + 3_600_000),
        &[("src/first_tip_1875.rs", &format!("pub const FIX: &str = \"{FIX}\";\n"))],
        "an embargoed fix",
    );
    let line = format!("embargo/{eid}");
    let tip1 = api.tips(Some(&sec), &p.name).unwrap().branches[&line];
    let real_tip1: String = hub
        .rt
        .block_on(sqlx::query_scalar("SELECT target FROM branches WHERE project_id = $1 AND name = $2").bind(pid).bind(&line).fetch_one(&h.db))
        .unwrap();
    let landed: Vec<String> = hub
        .rt
        .block_on(
            sqlx::query_scalar("SELECT ticket FROM landing_queue WHERE project_id = $1 AND state = 'landed' ORDER BY created_at DESC LIMIT 2")
                .bind(pid)
                .fetch_all(&h.db),
        )
        .unwrap();
    assert_eq!(landed.len(), 2, "{landed:?}");
    for (old, new) in landed.iter().zip([format!("embargo-{pid}-{eid}"), format!("embargo-{pid}-{eid}-{}", &real_tip1[..16])]) {
        let n = hub
            .rt
            .block_on(sqlx::query("UPDATE landing_queue SET ticket = $1 WHERE project_id = $2 AND ticket = $3").bind(&new).bind(pid).bind(old).execute(&h.db))
            .unwrap()
            .rows_affected();
        assert_eq!(n, 1, "{old} -> {new}");
    }

    // More work, pushed onto the line since.
    let more = api.post_json(
        Some(&sec),
        &format!("/v1/projects/{}/changes", p.name),
        &json!({
            "base": tip1.hex(),
            "description": "more of the fix",
            "edits": [{"path": "src/pushed_since_1875.rs", "put": {"text": format!("pub const MORE: &str = \"{MORE}\";\n")}}],
        }),
    );
    assert_eq!(more.status, 200, "{}", body_str(&more));
    let more_snap = more.json()["snapshot"].as_str().unwrap().to_string();
    let pushed = api.post_json(
        Some(&sec),
        &format!("/v1/projects/{}/push", p.name),
        &json!({"updates": [{"branch": line, "expected": tip1.hex(), "new": more_snap}]}),
    );
    assert_eq!(pushed.status, 200, "{}", body_str(&pushed));
    assert_eq!(api.tips(Some(&sec), &p.name).unwrap().branches[&line].hex(), more_snap, "{}", body_str(&pushed));

    // The release lands the whole line.
    let rel = api.post_json(Some(&sec), &format!("/v1/projects/{}/embargoes/{eid}/release", p.name), &json!({}));
    assert_eq!(rel.status, 200, "{}", body_str(&rel));
    assert!(released_at(&hub, &eid).is_some(), "released");
    for (path, mark) in [("src/first_tip_1875.rs", FIX), ("src/pushed_since_1875.rs", MORE)] {
        let f = api.get(Some(&dev), &format!("/v1/projects/{}/q/file?rev=main&path={path}", p.name));
        assert_eq!(f.status, 200, "{path} is on no branch after the release: {}", body_str(&f));
        assert!(body_str(&f).contains(mark), "{}", body_str(&f));
    }
}

/// BUG-1880 with BUG-1861: a landing batch asks the review rules again in
/// its own transaction, and for an embargo's release they are the rules its
/// submit met: the embargo PR's approvals count. A release queued behind
/// another server's lease, whose approval is taken back while it waits, is
/// refused: nothing lands, the embargo stays hidden and waits for approval
/// (it is not left `failed`). Approved again, the same release lands
/// through the batch under its embargo PR, without being asked for again.
#[test]
fn bug_1880_a_queued_release_meets_its_embargo_prs_approval_again_in_the_batch() {
    const FIX: &str = "QUEUED_RELEASE_FIX_1880";
    let hub = TestHub::start();
    let (p, rev1) = protected_project(&hub);
    let api = hub.api();
    let (sec, dev) = (p.sec.token(), p.dev.token());
    let pid: i64 = hub.rt.block_on(sqlx::query_scalar("SELECT id FROM projects WHERE name = $1").bind(&p.name).fetch_one(&hub.hub().db)).unwrap();
    let before = api.tips(Some(&dev), &p.name).unwrap().branches["main"];
    let (eid, _, _, _) = push_embargo(
        &hub,
        &p.name,
        &p.sec,
        "queued-1880",
        "security",
        None,
        &[("src/queued_1880.rs", &format!("pub const FIX: &str = \"{FIX}\";\n"))],
        "an embargoed fix",
    );
    let line = format!("embargo/{eid}");
    let file_on_main = || api.get(Some(&dev), &format!("/v1/projects/{}/q/file?rev=main&path=src/queued_1880.rs", p.name));

    // The line's embargo PR, approved by a member who may write its paths.
    let pr = api.post_json(Some(&sec), &format!("/v1/projects/{}/prs", p.name), &json!({"head": line, "title": "the fix"}));
    assert_eq!(pr.status, 200, "{}", body_str(&pr));
    let pr = pr.json();
    let pr_id = pr["id"].as_str().unwrap().to_string();
    let ok = approve(&api, &rev1, &p.name, &pr);
    assert_eq!(ok.status, 200, "{}", body_str(&ok));
    assert_eq!(ok.json()["review"]["ready"], true, "{}", body_str(&ok));
    assert!(released_at(&hub, &eid).is_none(), "an approval alone releases nothing");

    // Another server holds main's landing lease: the release is queued, and waits.
    hub.rt
        .block_on(
            sqlx::query(
                "INSERT INTO landing_leases (project_id, branch, holder, epoch, expires_at) \
                 VALUES ($1, 'main', 'another-server-1880', 1, (extract(epoch FROM clock_timestamp()) * 1000)::BIGINT + 600000) \
                 ON CONFLICT (project_id, branch) DO UPDATE SET holder = EXCLUDED.holder, epoch = landing_leases.epoch + 1, expires_at = EXCLUDED.expires_at",
            )
            .bind(pid)
            .execute(&hub.hub().db),
        )
        .unwrap();
    let (api_rel, tok_rel, url_rel) = (hub.api(), sec.clone(), format!("/v1/projects/{}/embargoes/{eid}/release", p.name));
    let release = std::thread::spawn(move || api_rel.post_json(Some(&tok_rel), &url_rel, &json!({})));
    let until = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        let queued: i64 = hub
            .rt
            .block_on(
                sqlx::query_scalar("SELECT COUNT(*) FROM landing_queue WHERE project_id = $1 AND ticket LIKE 'embargo-%' AND state = 'queued'")
                    .bind(pid)
                    .fetch_one(&hub.hub().db),
            )
            .unwrap();
        if queued == 1 {
            break;
        }
        assert!(std::time::Instant::now() < until, "the approved release was never queued");
        std::thread::sleep(Duration::from_millis(50));
    }

    // Its reviewer takes the approval back while it waits.
    let patch = pr["patch"].as_str().unwrap();
    let sig = sign_review(&rev1, &p.name, &pr_id, patch, "request-changes");
    let back = api.post_json(
        Some(&rev1.token()),
        &format!("/v1/projects/{}/prs/{pr_id}/reviews", p.name),
        &json!({"patch": patch, "verdict": "request-changes", "signature": sig}),
    );
    assert_eq!(back.status, 200, "{}", body_str(&back));
    assert_eq!(back.json()["review"]["ready"], false, "{}", body_str(&back));

    // The lease ends: the batch refuses the release, which is held.
    hub.rt
        .block_on(
            sqlx::query("DELETE FROM landing_leases WHERE project_id = $1 AND branch = 'main' AND holder = 'another-server-1880'")
                .bind(pid)
                .execute(&hub.hub().db),
        )
        .unwrap();
    let rel = release.join().unwrap();
    assert_eq!(rel.status, 409, "{}", body_str(&rel));
    assert_eq!(rel.json()["code"], "not_ready", "{}", body_str(&rel));
    assert!(body_str(&rel).contains("waits for approval") && body_str(&rel).contains("not ready to land"), "{}", body_str(&rel));
    assert!(released_at(&hub, &eid).is_none(), "a release whose approval was withdrawn while queued was released");
    assert_eq!(api.tips(Some(&dev), &p.name).unwrap().branches["main"], before, "it landed on protected main");
    assert_eq!(file_on_main().status, 404, "the fix is public");
    let sec_tips = api.tips(Some(&sec), &p.name).unwrap();
    assert!(sec_tips.branches.contains_key(&line), "the line stays");
    let rec = sec_tips.embargoes.iter().find(|e| e.id == eid).expect("a member sees the held embargo");
    assert_eq!(rec.state.as_deref(), Some("waiting_for_approval"), "{rec:?}");

    // Approved again: the held release is queued again and lands in a
    // batch, under its embargo PR's approval.
    let ok = approve(&api, &rev1, &p.name, &pr);
    assert_eq!(ok.status, 200, "{}", body_str(&ok));
    assert!(released_at(&hub, &eid).is_some(), "an approved, held release lands at once");
    let f = file_on_main();
    assert_eq!(f.status, 200, "{}", body_str(&f));
    assert!(body_str(&f).contains(FIX));
    let shown = api.get(Some(&dev), &format!("/v1/projects/{}/prs/{pr_id}", p.name));
    assert_eq!(shown.status, 200, "{}", body_str(&shown));
    assert_eq!(shown.json()["state"], "landed", "{}", body_str(&shown));
}
