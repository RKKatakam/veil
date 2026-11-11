//! The whole-codebase review of 2026-11-10, area "who can see and change
//! what on the server": each test here shows one guarantee of
//! `docs/VISIBILITY.md` or `docs/HUB.md` failing, and stays ignored under its
//! bug number until the bug is fixed (`docs/BUGS.md`, BUG-1850 to BUG-1859).

use serde_json::{json, Value};
use veil_core::ObjectId;

use crate::support::*;

fn body(r: &Reply) -> String {
    String::from_utf8_lossy(&r.body).into_owned()
}

fn main_tip(hub: &TestHub, token: Option<&str>, project: &str) -> ObjectId {
    hub.api().tips(token, project).expect("the project's tips").branches["main"]
}

fn post_check(hub: &TestHub, token: &str, project: &str, req: &Value) -> Reply {
    hub.api().post_json(Some(token), &format!("/v1/projects/{project}/checks"), req)
}

/// A project of the admin's with `files`, and the access lines `rules`
/// (each the arguments of one `vl access`).
fn project_with(hub: &TestHub, files: &[(&str, &str)], rules: &[&[&str]]) -> (String, Person) {
    let admin = hub.person("admin");
    let name = unique("rva");
    let dir = admin.dir("proj");
    std::fs::create_dir_all(&dir).unwrap();
    admin.ok(&dir, &["init"]);
    write_files(&dir, files);
    admin.ok(&dir, &["remote", "add", "origin", &hub.url(&name)]);
    admin.commit_main(&dir, "initial import");
    let out = admin.ok(&dir, &["push"]);
    assert!(out.contains("Created project"), "{out}");
    for r in rules {
        let mut args = vec!["access"];
        args.extend_from_slice(r);
        admin.ok(&dir, &args);
    }
    admin.commit_main(&dir, "access rules");
    admin.ok(&dir, &["push"]);
    (name, admin)
}

const DRAFT_MARK: &str = "MARKER-ADMIN-ONLY-DRAFT-5d1c7e90";
const LOG_MARK: &str = "MARKER-CI-LOG-OF-A-FULL-VIEW-63b0f2aa";

/// `docs/HUB.md` §13.35, guarantee 1, and the design's threat 10 ("a CI job
/// with broad access posts a status … a status is shown only to people who
/// can see every path the job's session could read"): a check result posted
/// from an admin's whole view of the project is not shown to someone who
/// sees only its public folder.
///
/// The server decides "admins only" from the root folder's entries alone
/// (`ci.rs`, `readable_footprint`): an entry counts as covered as soon as
/// any access line is at or **below** it. Here `docs/guide/` is public and
/// `docs/drafts/` has no line (admins only), so the root's one entry,
/// `docs`, counts as covered, and the result's readers are those of
/// `docs/guide/`: everyone on Earth.
#[test]
#[ignore = "BUG-1850: a check result posted from an admin's whole view is shown to everyone who reads the folders that have access lines, when the admin-only files sit beside them below the root"]
fn bug_1850_a_check_posted_from_an_admins_whole_view_is_not_shown_to_public_readers() {
    let hub = TestHub::start();
    let (project, admin) = project_with(
        &hub,
        &[("docs/guide/intro.md", "the public guide\n"), ("docs/drafts/plan.md", DRAFT_MARK)],
        &[&["access", "docs/guide/", "public"][1..]],
    );
    let admin_tok = admin.token();
    let tip = main_tip(&hub, Some(&admin_tok), &project);

    // The admin's CI job, with the admin's whole view (it can read
    // `docs/drafts/`), reports a failing check whose output quotes what it
    // tested.
    let r = post_check(
        &hub,
        &admin_tok,
        &project,
        &json!({
            "snapshot": tip.hex(),
            "name": "ci/all",
            "state": "fail",
            "summary": format!("{LOG_MARK}: docs/drafts/plan.md failed the style check"),
            "log": format!("docs/drafts/plan.md:1: {DRAFT_MARK}"),
        }),
    );
    assert_eq!(r.status, 200, "the admin posts the check: {}", body(&r));
    // Control: the admin reads it back.
    let mine = hub.api().get(Some(&admin_tok), &format!("/v1/projects/{project}/checks"));
    assert_eq!(mine.status, 200, "{}", body(&mine));
    assert_eq!(mine.json()["checks"].as_array().map(Vec::len), Some(1), "the admin sees their check: {}", body(&mine));

    // Control: someone not signed in sees the project (its public folder),
    // and not the drafts.
    let file = hub.api().get(None, &format!("/v1/projects/{project}/q/file?path=docs/drafts/plan.md"));
    assert_eq!(file.status, 404, "the drafts are the admins' only: {}", body(&file));

    // The guarantee: they are not shown the result of a job that could read
    // the drafts.
    let anon = hub.api().get(None, &format!("/v1/projects/{project}/checks"));
    assert_eq!(anon.status, 200, "anyone lists the checks of the public tip: {}", body(&anon));
    let text = body(&anon);
    assert!(!text.contains(DRAFT_MARK), "a public reader received the admin-only file's content in a check log: {text}");
    assert!(!text.contains(LOG_MARK), "a public reader received the summary of a check run on the admin's whole view: {text}");
    assert_eq!(anon.json()["checks"].as_array().map(Vec::len), Some(0), "{text}");
}

fn parse_embargo_id(out: &str) -> String {
    out.split_whitespace()
        .map(|w| w.trim_end_matches(':'))
        .find(|w| w.len() == 10 && w.bytes().all(|b| b.is_ascii_hexdigit()))
        .unwrap_or_else(|| panic!("no embargo id in output: {out}"))
        .to_string()
}

/// `2026-12-01T10:00:00Z` for `ms` since the epoch (what `vl merge --until` reads).
fn iso_utc(ms: i64) -> String {
    let (days, secs) = (ms.div_euclid(86_400_000), ms.rem_euclid(86_400_000) / 1000);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", secs / 3600, secs % 3600 / 60, secs % 60)
}

const FIX_MARK: &str = "MARKER-EMBARGOED-FIX-c41d07b9";

/// `sec` (in `security` and `devs`) pushes a fix of `src/` embargoed for
/// `security` until an hour from now; the embargo's id.
fn embargoed_fix(hub: &TestHub, p: &Project) -> String {
    p.admin.ok(&p.dir, &["group", "add", "devs", &p.sec.name]);
    let dir = p.sec.dir("work");
    p.sec.ok(p.sec.home.path(), &["clone", &hub.url(&p.name), dir.to_str().unwrap()]);
    write_files(&dir, &[("src/embargo_fix.rs", &format!("pub const FIX: &str = \"{FIX_MARK}\";\n"))]);
    p.sec.ok(&dir, &["commit", "--no-advance", "-m", "the embargoed fix"]);
    let until = iso_utc(veil_core::now_millis() + 3_600_000);
    let out = p.sec.ok(&dir, &["merge", "@-", "--into", "main", "--embargo-for", "security", "--until", &until, "-m", "merge the embargoed fix"]);
    let eid = parse_embargo_id(&out);
    p.sec.ok(&dir, &["push"]);
    eid
}

/// `docs/VISIBILITY.md`, "Hidden changes (embargoes)": everyone outside the
/// groups named sees nothing of an embargoed change until its deadline, or
/// until "someone with the right runs `vl embargo release`"; `docs/HUB.md`
/// §13.31: "a member of the embargo (or an admin)".
///
/// A push may carry embargo records on their own. The server checks that the
/// pusher is in the groups **the pushed record names** (`embargo.rs`,
/// `prepare_push`, step 1), never in the groups of the embargo already
/// stored under that id, and then releases the stored embargo
/// (`sync.rs`: `release_one` for every pushed record with `released_at`) or
/// moves its deadline (`record_in_tx`: `until_ms = EXCLUDED.until_ms`). So
/// anyone in any group of the project who knows an embargo's id publishes
/// it: here someone who was in `security` when the fix was pushed, and was
/// then removed from it.
#[test]
#[ignore = "BUG-1851: anyone in any group who knows an embargo's id releases it with a push of a record that names their own group"]
fn bug_1851_only_the_embargos_own_groups_release_it_through_a_push() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    // `fin` is in `security` while the fix is pushed, and learns its id.
    p.admin.ok(&p.dir, &["group", "add", "security", &p.fin.name]);
    let eid = embargoed_fix(&hub, &p);
    let api = hub.api();
    let (fin_tok, sec_tok) = (p.fin.token(), p.sec.token());
    let line = format!("embargo/{eid}");
    assert!(api.tips(Some(&fin_tok), &p.name).unwrap().branches.contains_key(&line), "control: a member of security sees the hidden line");

    // An admin takes `fin` out of `security`: at once, `fin` (still in
    // `finance`) is outside the embargo.
    p.admin.ok(&p.dir, &["group", "remove", "security", &p.fin.name]);
    let tips = api.tips(Some(&fin_tok), &p.name).unwrap();
    assert!(!tips.branches.contains_key(&line) && tips.embargoes.is_empty(), "control: removed from security, fin no longer sees the embargo");
    let asked = api.post_json(Some(&fin_tok), &format!("/v1/projects/{}/embargoes/{eid}/release", p.name), &json!({}));
    assert_eq!(asked.status, 404, "control: the release route refuses someone outside the embargo: {}", body(&asked));
    let main_before = main_tip(&hub, None, &p.name);

    // `fin` pushes no branch at all, only a record under the embargo's id
    // that names `finance` and says "released".
    let now = veil_core::now_millis();
    let r = api.post_json(
        Some(&fin_tok),
        &format!("/v1/projects/{}/push", p.name),
        &json!({
            "updates": [],
            "embargoes": [{
                "format": veil_core::keychain::EMBARGO_FORMAT,
                "id": eid,
                "scope": "finance",
                "until": null,
                "released_at": now,
                "created": now,
            }],
        }),
    );
    // The guarantee: refused, and the embargo stays as it was.
    assert!(matches!(r.status, 400 | 403 | 404), "someone outside the embargo released it with a push: {} {}", r.status, body(&r));
    assert!(api.tips(Some(&sec_tok), &p.name).unwrap().branches.contains_key(&line), "the embargo's hidden line is gone: it was released");
    assert_eq!(main_tip(&hub, None, &p.name), main_before, "the public main moved: the embargoed fix landed on it before its deadline");
    let file = api.get(None, &format!("/v1/projects/{}/q/file?path=src/embargo_fix.rs", p.name));
    assert_eq!(file.status, 404, "everyone on Earth reads the embargoed fix: {}", body(&file));
    assert!(!body(&file).contains(FIX_MARK));
}

fn change(hub: &TestHub, token: &str, project: &str, req: &Value) -> Reply {
    hub.api().post_json(Some(token), &format!("/v1/projects/{project}/changes"), req)
}

/// Land one file's new text on `main` as `token`; the real tip after it.
fn land_edit(hub: &TestHub, p: &Project, token: &str, path: &str, text: &str, desc: &str) -> ObjectId {
    let base = main_tip(hub, Some(token), &p.name);
    let c = change(hub, token, &p.name, &json!({"base": base.hex(), "description": desc, "edits": [{"path": path, "put": {"text": text}}]}));
    assert_eq!(c.status, 200, "{}", body(&c));
    let l = hub.api().post_json(
        Some(token),
        &format!("/v1/projects/{}/land", p.name),
        &json!({"onto": "main", "snapshot": c.json()["snapshot"], "wait": true}),
    );
    assert_eq!(l.status, 200, "{}", body(&l));
    assert_eq!(l.json()["state"], "landed", "{}", body(&l));
    main_tip(hub, Some(&p.admin.token()), &p.name)
}

/// `docs/VISIBILITY.md`: "Folder access means read and write; `public` means
/// read for everyone on Earth. Writing a public folder needs a named group
/// or person", and "every change is checked". `main` is protected, so only
/// the landing service moves it.
///
/// Check results decide what the server itself lands: two failing results
/// on a landed change and a passing one on its parent make the server revert
/// the change on the protected branch (`docs/HUB.md` §13.36). The server
/// takes those results from **anyone who takes part in the project**
/// (`ci.rs`, `post_check_route`: `signed_in` and `participant`), whatever
/// they may write. Here `fin` (in `finance`: she reads `src/` because it is
/// public, and may not write it) has the server take a developer's landed
/// change out of `src/`.
#[test]
#[ignore = "BUG-1852: anyone who takes part in a project has the server revert a landed change in a folder they may not write, by posting failing check results"]
fn bug_1852_someone_who_may_not_write_a_folder_cannot_have_a_landed_change_in_it_reverted() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let (admin_tok, dev_tok, fin_tok) = (p.admin.token(), p.dev.token(), p.fin.token());
    let rules = "[branches.main]\nprotected = true\nrequired_checks = [\"ci/src\"]\n\n[checks.\"ci/src\"]\npaths = [\"src/\"]\n\n\
                 [review]\nnormal = { approvals = 0 }\nhigh = { approvals = 0 }\n";
    let s0 = land_edit(&hub, &p, &admin_tok, ".veilrules", rules, "configure .veilrules");
    // The project's own CI passes the rules' snapshot: `main@tested`.
    let r = post_check(&hub, &admin_tok, &p.name, &json!({"snapshot": s0.hex(), "name": "ci/src", "state": "pass"}));
    assert_eq!(r.status, 200, "{}", body(&r));
    // A developer lands a change of `src/`.
    let landed = land_edit(&hub, &p, &dev_tok, "src/feature.rs", "pub const FEATURE: u32 = 1;\n", "the feature");
    assert_eq!(main_tip(&hub, Some(&admin_tok), &p.name), landed);

    // Control: `fin` reads `src/` and may not write it.
    let fin_tip = main_tip(&hub, Some(&fin_tok), &p.name);
    let read = hub.api().get(Some(&fin_tok), &format!("/v1/projects/{}/q/file?path=src/feature.rs", p.name));
    assert_eq!(read.status, 200, "control: src/ is public: {}", body(&read));
    let write = change(
        &hub,
        &fin_tok,
        &p.name,
        &json!({"base": fin_tip.hex(), "description": "remove the feature", "onto": {"branch": "main", "expected": fin_tip.hex()},
                "edits": [{"path": "src/feature.rs", "delete": true}]}),
    );
    assert_eq!(write.status, 403, "control: fin may not write src/: {}", body(&write));
    assert_eq!(main_tip(&hub, Some(&admin_tok), &p.name), landed, "control: fin's own change of src/ did not land");

    // `fin` reports the change as failing, twice (the confirmation the
    // server asks for). Whether the server takes the results or refuses
    // them, the change stays.
    for run in 1..=2 {
        let r = post_check(&hub, &fin_tok, &p.name, &json!({"snapshot": fin_tip.hex(), "name": "ci/src", "state": "fail", "summary": format!("run {run}")}));
        assert!(matches!(r.status, 200 | 403), "run {run}: {} {}", r.status, body(&r));
    }
    // A revert lands through the queue: give it time.
    for _ in 0..40 {
        if main_tip(&hub, Some(&admin_tok), &p.name) != landed {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let now = main_tip(&hub, Some(&admin_tok), &p.name);
    let show = hub.api().get(Some(&admin_tok), &format!("/v1/projects/{}/q/show?rev={}", p.name, now.hex()));
    assert_eq!(now, landed, "main moved on the word of someone who may not write src/: {}", body(&show));
    let file = hub.api().get(Some(&admin_tok), &format!("/v1/projects/{}/q/file?path=src/feature.rs", p.name));
    assert_eq!(file.status, 200, "the developer's landed file is gone from main: {}", body(&file));
}

fn ring_scopes(r: &Reply) -> Vec<String> {
    r.json().as_array().expect("a list of key rings").iter().map(|k| k["scope"].as_str().unwrap_or_default().to_string()).collect()
}

/// `docs/VISIBILITY.md`: "Nobody receives a file, or a name, from a folder
/// they cannot see." Access lines live in `.veilpolicy`, which is private
/// like everything at the root, so which folders have lines is hidden from
/// someone who reads only their own folder. The server already treats a
/// hash that confirms a guess of a hidden folder's name as a leak (BUG-1080:
/// the grant holds "no view key (an unkeyed hash of every access line,
/// hidden ones included, would confirm guesses of hidden folder names)").
///
/// `GET …/rings` hands every participant every key ring of the project
/// (`api.rs`, `get_rings`), and a per-line ring is named
/// `rule-` + an unkeyed BLAKE3 of the line's path
/// (`veil_core::policy::rule_scope_of`). So carol, who is named on her own
/// folder only, confirms that a folder called `bill-…` has an access line,
/// and reads which devices hold its key.
#[test]
#[ignore = "BUG-1853: every participant receives every key ring, named by an unkeyed hash of its access line's path: a guess of a hidden folder's name is confirmed, and who holds its key is listed"]
fn bug_1853_key_rings_of_folders_a_participant_cannot_read_are_not_handed_to_them() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let hidden = veil_core::policy::rule_scope_of(BILL_DIR);
    let rings = format!("/v1/projects/{}/rings", p.name);

    // Control: finance, who reads the folder, receives its ring.
    let fin = api.get(Some(&p.fin.token()), &rings);
    assert_eq!(fin.status, 200, "{}", body(&fin));
    assert!(ring_scopes(&fin).contains(&hidden), "control: the folder's ring exists and its readers receive it: {:?}", ring_scopes(&fin));

    // Control: carol takes part in the project and cannot see the folder.
    let carol_tok = p.carol.token();
    let tree = api.get(Some(&carol_tok), &format!("/v1/projects/{}/q/tree?path={BILL_DIR}", p.name));
    assert_eq!(tree.status, 404, "control: carol cannot see the billing folder: {}", body(&tree));

    // The guarantee: nothing she receives confirms the folder's name.
    let carol = api.get(Some(&carol_tok), &rings);
    assert_eq!(carol.status, 200, "a participant lists the key rings she may read: {}", body(&carol));
    assert!(
        !ring_scopes(&carol).contains(&hidden),
        "carol received the ring named by the hash of a folder she cannot see ({hidden} = rule_scope_of({BILL_DIR:?})): {:?}",
        ring_scopes(&carol)
    );
    let one = api.get(Some(&carol_tok), &format!("{rings}/{hidden}"));
    assert_eq!(one.status, 404, "asked by its name, the ring answers carol: {}", body(&one));
}

/// `docs/VISIBILITY.md`: "Admins decide who may manage each group", and
/// taking access away "takes effect at the very next request". An admin who
/// made someone a group's manager can take that right away again, and from
/// then on the former manager changes nobody's membership.
///
/// The server has no such route (`api.rs`: `…/groups/{g}/managers` only
/// adds; `group_managers` rows are deleted only with the whole group), and
/// `vl group manager` has no way to remove. A manager who left the company
/// keeps adding people to the group (and so giving them its folders) for as
/// long as they can open the project: as long as it has one public folder,
/// or they are in any other group.
#[test]
#[ignore = "BUG-1854: a group manager's right can never be taken away: there is no route and no command for it, short of deleting the group"]
fn bug_1854_an_admin_takes_a_group_managers_right_away() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let (admin_tok, carol_tok) = (p.admin.token(), p.carol.token());
    let members = format!("/v1/projects/{}/groups/finance/members", p.name);
    p.admin.ok(&p.dir, &["group", "manager", "finance", &p.carol.name]);
    // Control: as its manager, carol adds dev to finance.
    let add = api.post_json(Some(&carol_tok), &members, &json!({"people": [p.dev.name]}));
    assert_eq!(add.status, 200, "control: a manager adds people: {}", body(&add));
    let undo = api.post_json(Some(&admin_tok), &format!("{members}/remove"), &json!({"people": [p.dev.name]}));
    assert_eq!(undo.status, 200, "{}", body(&undo));

    // The admin takes carol's right away (the route that mirrors
    // `…/members/remove`).
    let revoke = api.post_json(
        Some(&admin_tok),
        &format!("/v1/projects/{}/groups/finance/managers/remove", p.name),
        &json!({"people": [p.carol.name]}),
    );
    assert_eq!(revoke.status, 200, "an admin cannot take a manager's right away: {} {}", revoke.status, body(&revoke));
    assert_eq!(revoke.json()["managers"], json!([]), "{}", body(&revoke));
    // At the very next request, carol changes nobody's membership.
    let again = api.post_json(Some(&carol_tok), &members, &json!({"people": [p.dev.name]}));
    assert_eq!(again.status, 403, "the former manager still adds people to the group: {}", body(&again));
    let file = api.get(Some(&p.dev.token()), &format!("/v1/projects/{}/q/tree?path={BILL_DIR}", p.name));
    assert_eq!(file.status, 404, "dev reads billing: the former manager's addition took effect: {}", body(&file));
}

/// BUG-1850's class, second way in: the session's **own** view is replaced
/// by the paths `.veilrules` lists for the check's name
/// (`readable_footprint`: `rules.checks.get(check_name)` when the session is
/// not narrowed). A session that reads `billing/` and reports under a check
/// name configured for `src/` is taken to have read `src/` only, so its
/// result is shown to everyone who reads `src/`: the design's threat 10
/// word for word ("a job session with `billing/` posts on a public change:
/// invisible to public viewers").
#[test]
#[ignore = "BUG-1850: a result posted by a session that reads billing/, under a check name whose .veilrules paths are src/, is shown to everyone who reads src/"]
fn bug_1850_a_check_posted_by_a_session_that_reads_billing_is_not_shown_to_public_readers() {
    const BILLING_LOG: &str = "MARKER-BILLING-TEST-OUTPUT-0c9e1f57";
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let (admin_tok, fin_tok) = (p.admin.token(), p.fin.token());
    let rules = "[branches.main]\nrequired_checks = [\"ci/src\"]\n\n[checks.\"ci/src\"]\npaths = [\"src/\"]\n";
    let base = main_tip(&hub, Some(&admin_tok), &p.name);
    let r = change(
        &hub,
        &admin_tok,
        &p.name,
        &json!({"base": base.hex(), "description": "configure .veilrules", "onto": {"branch": "main", "expected": base.hex()},
                "edits": [{"path": ".veilrules", "put": {"text": rules}}]}),
    );
    assert_eq!(r.status, 200, "{}", body(&r));
    assert_eq!(r.json()["branch"]["status"], "ok", "{}", body(&r));

    // finance's CI job runs with fin's own session (it reads `billing/`),
    // and reports under `ci/src`.
    let fin_tip = main_tip(&hub, Some(&fin_tok), &p.name);
    let bill = hub.api().get(Some(&fin_tok), &format!("/v1/projects/{}/q/file?path={BILL_DIR}/acme/invoice.txt", p.name));
    assert_eq!(bill.status, 200, "control: the posting session reads billing: {}", body(&bill));
    let r = post_check(
        &hub,
        &fin_tok,
        &p.name,
        &json!({"snapshot": fin_tip.hex(), "name": "ci/src", "state": "fail", "summary": BILLING_LOG, "log": format!("{BILL_DIR}/acme/invoice.txt: {BILL_MARK}")}),
    );
    assert_eq!(r.status, 200, "fin posts the check: {}", body(&r));
    let mine = hub.api().get(Some(&fin_tok), &format!("/v1/projects/{}/checks", p.name));
    assert_eq!(mine.status, 200, "{}", body(&mine));
    assert!(body(&mine).contains(BILLING_LOG), "control: fin reads her check back: {}", body(&mine));

    // Someone not signed in reads `src/` only.
    let anon = hub.api().get(None, &format!("/v1/projects/{}/checks", p.name));
    assert_eq!(anon.status, 200, "anyone lists the checks of the public tip: {}", body(&anon));
    let text = body(&anon);
    assert!(!text.contains(BILL_MARK) && !text.contains(BILL_DIR), "a public reader received billing's name and content in a check log: {text}");
    assert!(!text.contains(BILLING_LOG), "a public reader received the result of a job that could read billing: {text}");
}

/// `docs/VISIBILITY.md`, "Hidden changes (embargoes)": "Everyone else, the
/// public included, sees nothing of it until it's released. **Anything built
/// on top of it stays hidden too.**" A push keeps that promise: a branch
/// whose new tip stands on an unreleased embargo is diverted to the hidden
/// line (`embargo.rs`, `prepare_push`, step 3).
///
/// The landing route does not: a member of the embargo (or their agent)
/// who commits follow-up work on the hidden line through the API and lands
/// it on an ordinary branch puts the embargoed fix itself on that branch,
/// where nothing marks it as embargoed, and everyone who reads its folder
/// receives it.
#[test]
#[ignore = "BUG-1855: work built on an embargoed change and landed on an ordinary branch (POST …/changes, POST …/land) is not hidden: everyone who reads its folder receives the embargoed change"]
fn bug_1855_work_landed_on_top_of_an_embargoed_change_stays_hidden() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let eid = embargoed_fix(&hub, &p);
    let api = hub.api();
    let (dev_tok, sec_tok) = (p.dev.token(), p.sec.token());

    // An ordinary branch, at main's tip (a developer outside the embargo makes it).
    let dev_main = main_tip(&hub, Some(&dev_tok), &p.name);
    let made = api.post_json(Some(&dev_tok), &format!("/v1/projects/{}/push", p.name), &json!({"updates": [{"branch": "work", "expected": null, "new": dev_main.hex()}]}));
    assert_eq!(made.status, 200, "{}", body(&made));
    assert_eq!(made.json()["results"][0]["ok"], json!(true), "{}", body(&made));

    // A member of the embargo commits follow-up work on the hidden line
    // through the API, and lands it on the ordinary branch.
    let hidden_tip = api.tips(Some(&sec_tok), &p.name).unwrap().branches[&format!("embargo/{eid}")];
    let c = change(
        &hub,
        &sec_tok,
        &p.name,
        &json!({"base": hidden_tip.hex(), "description": "follow-up to the fix", "edits": [{"path": "src/followup.rs", "put": {"text": "pub const FOLLOW_UP: u32 = 2;\n"}}]}),
    );
    assert_eq!(c.status, 200, "a member commits on the hidden line: {}", body(&c));
    let l = api.post_json(Some(&sec_tok), &format!("/v1/projects/{}/land", p.name), &json!({"onto": "work", "snapshot": c.json()["snapshot"], "wait": true}));
    // Hidden with the embargo, or refused: either keeps the promise.
    assert!(matches!(l.status, 200 | 400 | 403 | 404 | 409), "{} {}", l.status, body(&l));

    // Whatever the landing answered: nobody outside the embargo reads the
    // fix, on any branch.
    for (who, tok) in [("someone not signed in", None), ("a developer outside the embargo", Some(dev_tok.as_str()))] {
        let file = api.get(tok, &format!("/v1/projects/{}/q/file?rev=work&path=src/embargo_fix.rs", p.name));
        assert!(!body(&file).contains(FIX_MARK), "{who} reads the embargoed fix on the branch 'work' (landing answered {}): {}", body(&l), body(&file));
        assert_eq!(file.status, 404, "{who}: {}", body(&file));
    }
}

/// `docs/VISIBILITY.md`, "Who can do what": an admin is "the creator, and
/// anyone they make admin", and admins "add admins" (`docs/HUB.md` §5.3:
/// "add admins | admins"). A project's creator makes a second admin, who
/// from the next request sees everything and changes groups.
///
/// The server has no route that adds a row to `project_admins` (only
/// `create_project` writes one) and `vl` has no command for it: a project
/// has exactly one admin for ever, and when that person leaves or loses
/// their devices nobody can change its groups, access or keys.
#[test]
#[ignore = "BUG-1856: an admin cannot make anyone else an admin: no route and no command adds one, so a project has its creator as its only admin for ever"]
fn bug_1856_an_admin_makes_someone_else_an_admin() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let (admin_tok, dev_tok) = (p.admin.token(), p.dev.token());
    assert!(!api.tips(Some(&dev_tok), &p.name).unwrap().admin, "control: dev is no admin yet");
    // The route that mirrors `…/groups/{g}/members`.
    let r = api.post_json(Some(&admin_tok), &format!("/v1/projects/{}/admins", p.name), &json!({"people": [p.dev.name]}));
    assert_eq!(r.status, 200, "an admin cannot add an admin: {} {}", r.status, body(&r));
    assert!(api.tips(Some(&dev_tok), &p.name).unwrap().admin, "dev is an admin from the next request");
    let made = api.post_json(Some(&dev_tok), &format!("/v1/projects/{}/groups/ops", p.name), &json!({}));
    assert_eq!(made.status, 200, "the new admin creates a group: {}", body(&made));
    // Not anyone's to take: someone who is no admin adds none.
    let no = api.post_json(Some(&p.fin.token()), &format!("/v1/projects/{}/admins", p.name), &json!({"people": [p.fin.name]}));
    assert_eq!(no.status, 403, "{}", body(&no));
}

fn project_id(hub: &TestHub, name: &str) -> i64 {
    let h = hub.hub();
    hub.rt.block_on(sqlx::query_scalar("SELECT id FROM projects WHERE name = $1").bind(name).fetch_one(&h.db)).unwrap()
}

fn set_deadline(hub: &TestHub, project: i64, embargo: &str, until_ms: Option<i64>) {
    let h = hub.hub();
    let n = hub
        .rt
        .block_on(sqlx::query("UPDATE embargo_lines SET until_ms = $1 WHERE project_id = $2 AND embargo_id = $3").bind(until_ms).bind(project).bind(embargo).execute(&h.db))
        .unwrap()
        .rows_affected();
    assert_eq!(n, 1, "the embargo is recorded");
}

fn released_at(hub: &TestHub, project: i64, embargo: &str) -> Option<i64> {
    let h = hub.hub();
    hub.rt
        .block_on(sqlx::query_scalar("SELECT released_at FROM embargo_lines WHERE project_id = $1 AND embargo_id = $2").bind(project).bind(embargo).fetch_one(&h.db))
        .unwrap()
}

/// Takes a test's stuck embargo out of the deadline service when the test
/// ends, however it ends: the service is the whole database's.
struct NoDeadline<'a>(&'a TestHub, i64, String);
impl Drop for NoDeadline<'_> {
    fn drop(&mut self) {
        let h = self.0.hub();
        let _ = self.0.rt.block_on(sqlx::query("UPDATE embargo_lines SET until_ms = NULL WHERE project_id = $1 AND embargo_id = $2").bind(self.1).bind(&self.2).execute(&h.db));
    }
}

/// `docs/VISIBILITY.md`: "`vl embargo release`, or the deadline, makes it
/// public"; `docs/HUB.md` §13.31, guarantee 2: "release happens at the
/// deadline". An embargo whose release conflicts with its target branch
/// is kept "for a member to rebase and push again": that is its own
/// project's matter.
///
/// The deadline service walks every due embargo of every project, oldest
/// deadline first, and stops at the first one that fails (`embargo.rs`,
/// `release_due`: `release_one(…).await?` inside the loop). A conflicted
/// embargo stays due and stays first, so from then on **no later embargo of
/// any project on the server is released at its deadline**. Anyone can make
/// one: a project of their own, an embargo, a conflicting change on `main`.
#[test]
#[ignore = "BUG-1857: one embargo whose release conflicts stops the deadline service for every later embargo of every project: they are never released at their deadline"]
fn bug_1857_one_projects_conflicted_embargo_does_not_keep_another_projects_from_its_deadline() {
    let hub = TestHub::start();
    // Someone's own project, with an embargo whose release will conflict:
    // `main` gets another file at the fix's path first.
    let theirs = setup_project(&hub);
    let stuck = embargoed_fix(&hub, &theirs);
    land_edit(&hub, &theirs, &theirs.dev.token(), "src/embargo_fix.rs", "pub const FIX: &str = \"another change at the same path\";\n", "conflicts with the fix");
    // Another project, with an embargo of its own.
    let ours = setup_project(&hub);
    let due = embargoed_fix(&hub, &ours);
    let (theirs_id, ours_id) = (project_id(&hub, &theirs.name), project_id(&hub, &ours.name));

    // Both deadlines pass: the conflicted one first, ours after it.
    let _cleanup = NoDeadline(&hub, theirs_id, stuck.clone());
    set_deadline(&hub, theirs_id, &stuck, Some(1_000));
    set_deadline(&hub, ours_id, &due, Some(2_000));
    let h = hub.hub();
    let mut last = String::new();
    for _ in 0..40 {
        last = format!("{:?}", hub.rt.block_on(veil_server::embargo::release_due(&h)).map_err(|e| format!("{e:?}")));
        if released_at(&hub, ours_id, &due).is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    // Control: the first embargo is the conflicted one, kept for its members.
    assert_eq!(released_at(&hub, theirs_id, &stuck), None, "control: the conflicted embargo is not released ({last})");
    // The guarantee: ours is released at its deadline, and public.
    assert!(released_at(&hub, ours_id, &due).is_some(), "our embargo is past its deadline and still hidden; the deadline service answered: {last}");
    let file = hub.api().get(None, &format!("/v1/projects/{}/q/file?path=src/embargo_fix.rs", ours.name));
    assert_eq!(file.status, 200, "past its deadline, the fix is public: {}", body(&file));
    assert!(body(&file).contains(FIX_MARK), "{}", body(&file));
}

fn push(hub: &TestHub, token: &str, project: &str, branch: &str, expected: Option<ObjectId>, new: ObjectId) -> Reply {
    hub.api().post_json(
        Some(token),
        &format!("/v1/projects/{project}/push"),
        &json!({"updates": [{"branch": branch, "expected": expected.map(|e| e.hex()), "new": new.hex()}]}),
    )
}

/// `docs/HUB.md` §4.5, check 2: "**Write access by path:** every file the
/// push adds, changes or removes is in a folder the pusher has access to";
/// `docs/VISIBILITY.md`: "Writing a public folder needs a named group or
/// person." The landing service applies it to whoever lands
/// (`landing/service.rs`: "you may not write '…'").
///
/// A push checks write access only for the snapshots it **uploads**
/// (`sync.rs`, `check_changes`). A push that uploads nothing and moves a
/// branch forward to a snapshot the server already holds (another branch's
/// tip) is checked for nothing but being a fast-forward: `fin`, who reads
/// `src/` because it is public and may not write it, puts a developer's
/// unfinished branch on `main`.
#[test]
#[ignore = "BUG-1858: a push that moves a branch forward to a snapshot the server already holds is not checked for write access: someone who may not write src/ puts another branch's src/ changes on main"]
fn bug_1858_a_push_that_moves_a_branch_to_an_existing_snapshot_needs_write_access_to_what_it_changes() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let (admin_tok, dev_tok, fin_tok) = (p.admin.token(), p.dev.token(), p.fin.token());
    // A developer's work in progress, on a branch of its own.
    let dev_main = main_tip(&hub, Some(&dev_tok), &p.name);
    let made = push(&hub, &dev_tok, &p.name, "wip", None, dev_main);
    assert_eq!(made.status, 200, "{}", body(&made));
    assert_eq!(made.json()["results"][0]["ok"], json!(true), "{}", body(&made));
    let c = change(
        &hub,
        &dev_tok,
        &p.name,
        &json!({"base": dev_main.hex(), "description": "work in progress", "onto": {"branch": "wip", "expected": dev_main.hex()},
                "edits": [{"path": "src/unfinished.rs", "put": {"text": "pub fn unfinished() { todo!() }\n"}}]}),
    );
    assert_eq!(c.status, 200, "{}", body(&c));
    assert_eq!(c.json()["branch"]["status"], "ok", "{}", body(&c));
    let main_before = main_tip(&hub, Some(&admin_tok), &p.name);

    // Control: `fin` may not write `src/` herself.
    let tips = hub.api().tips(Some(&fin_tok), &p.name).unwrap();
    let (fin_main, fin_wip) = (tips.branches["main"], tips.branches["wip"]);
    let write = change(
        &hub,
        &fin_tok,
        &p.name,
        &json!({"base": fin_main.hex(), "description": "fin writes src/", "onto": {"branch": "main", "expected": fin_main.hex()},
                "edits": [{"path": "src/unfinished.rs", "put": {"text": "fin's\n"}}]}),
    );
    assert_eq!(write.status, 403, "control: fin may not write src/: {}", body(&write));

    // She moves `main` to the developer's branch: a push that uploads nothing.
    let moved = push(&hub, &fin_tok, &p.name, "main", Some(fin_main), fin_wip);
    let refused = moved.status == 403 || (moved.status == 200 && moved.json()["results"][0]["ok"] == json!(false));
    assert!(refused, "someone who may not write src/ changed src/ on main with a push: {} {}", moved.status, body(&moved));
    assert_eq!(main_tip(&hub, Some(&admin_tok), &p.name), main_before, "main moved");
    let file = hub.api().get(Some(&admin_tok), &format!("/v1/projects/{}/q/file?path=src/unfinished.rs", p.name));
    assert_eq!(file.status, 404, "the unfinished file is on main: {}", body(&file));
}
