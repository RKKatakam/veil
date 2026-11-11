//! The gaps review (2026-11-11): what the six area reviews did not reach.
//! Rate limits against sign-ups, thin clones of people who see part of a
//! project (and after access changes), search after access changes.

use std::path::Path;

use veil_core::Identity;
use veil_server::limits::{bucket::Rate, Settings};

use crate::support::*;

/// One command's answer as compared between clones: whether it succeeded
/// and its output (JSON without each clone's own working copy).
fn answer(who: &Person, dir: &Path, args: &[&str]) -> (bool, String) {
    let o = who.run(dir, args);
    let out = String::from_utf8_lossy(&o.stdout).to_string();
    let err = String::from_utf8_lossy(&o.stderr).to_string();
    let text = match serde_json::from_str::<serde_json::Value>(out.trim()) {
        Ok(mut v) => {
            if let Some(e) = v.get_mut("entries").and_then(|e| e.as_array_mut()) {
                e.retain(|x| x["current"] != serde_json::json!(true));
            }
            v.to_string()
        }
        Err(_) => format!("{out}{err}"),
    };
    (o.status.success(), text)
}

/// The commands whose answers differ between `full` and `thin`.
fn differences(who: &Person, full: &Path, thin: &Path, cmds: &[Vec<&str>]) -> Vec<String> {
    let mut out = Vec::new();
    for args in cmds {
        let want = answer(who, full, args);
        let got = answer(who, thin, args);
        if got != want {
            let cut = |t: &str| t.chars().take(700).collect::<String>();
            out.push(format!("`vl {}`:\nfull clone ({}):\n{}\nthin clone ({}):\n{}", args.join(" "), want.0, cut(&want.1), got.0, cut(&got.1)));
        }
    }
    out
}

fn read_cmds() -> Vec<Vec<&'static str>> {
    vec![
        vec!["log", "--json"],
        vec!["log", "--json", "-r", "::main"],
        vec!["show", "--json", "main"],
        vec!["show", "--json", "main-"],
        vec!["show", "--json", "main--"],
        vec!["diff", "--json", "-r", "main"],
        vec!["diff", "--json", "-r", "main-"],
        vec!["files", "-r", "main"],
        vec!["ls", "-r", "main"],
        vec!["cat", "-r", "main", "src/lib.rs"],
        vec!["cat", "-r", "main-", "src/lib.rs"],
        vec!["grep", "MARKER", "-r", "main"],
        vec!["grep", "MARKER", "-r", "main--"],
        vec!["blame", "src/lib.rs", "-r", "main", "--json"],
        vec!["blame", "src/moved.txt", "-r", "main", "--json"],
        vec!["tag", "list"],
        vec!["log", "--json", "src/lib.rs"],
        vec!["evolog", "-r", "main"],
        // A file moved in from the billing folder: for finance a rename to
        // follow, for the others a file added there.
        vec!["log", "--json", "src/moved.txt"],
        vec!["log", "--json", "--follow", "src/moved.txt"],
        vec!["blame", "--follow", "src/moved.txt", "-r", "main", "--json"],
        vec!["diff", "--json", "-r", "main--"],
    ]
}

/// More history on the standard project: a change of public and hidden
/// files at once, a file moved from a hidden folder into the public one
/// and one moved out of it, and a public-only change.
fn more_history(p: &Project) {
    write_files(&p.dir, &[("src/lib.rs", &format!("{PUBLIC_MARK}\nsecond line\n")), (&format!("{BILL_DIR}/acme/invoice.txt"), &format!("{BILL_MARK}\nthird"))]);
    p.admin.commit_main(&p.dir, "public and billing at once");
    std::fs::rename(p.dir.join(format!("{BILL_DIR}/acme/invoice.txt")), p.dir.join("src/moved.txt")).unwrap();
    write_files(&p.dir, &[("src/out.txt", "going out\n")]);
    p.admin.commit_main(&p.dir, "billing file moved into src");
    std::fs::rename(p.dir.join("src/out.txt"), p.dir.join(format!("{BILL_DIR}/out.txt"))).unwrap();
    p.admin.commit_main(&p.dir, "a src file moved into billing");
    write_files(&p.dir, &[("src/lib.rs", &format!("{PUBLIC_MARK}\nsecond line\nthird line\n"))]);
    p.admin.commit_main(&p.dir, "public only");
    p.admin.ok(&p.dir, &["push"]);
}

/// A thin clone of someone who sees part of the project answers as their
/// full clone does (the parity tests of `thin.rs` clone as the admin):
/// history, files, content, grep and blame, across changes that touch
/// hidden and public folders at once and files moved between them.
#[test]
fn rvgaps_thin_clone_of_a_partial_viewer_answers_as_their_full_clone() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    more_history(&p);
    let mut all = Vec::new();
    for (who, name) in [(&p.dev, "dev"), (&p.fin, "fin"), (&p.sec, "sec")] {
        let full = who.dir("full");
        who.clone_trusting(&hub.url(&p.name), &full, &p.fp);
        let thin = who.dir("thin");
        who.ok(who.home.path(), &["clone", &hub.url(&p.name), thin.to_str().unwrap()]);
        for d in differences(who, &full, &thin, &read_cmds()) {
            all.push(format!("{name}: {d}"));
        }
        // Each is an answer, not a refusal both clones share.
        for args in read_cmds() {
            let (ok, text) = answer(who, &full, &args);
            assert!(ok, "{name}: `vl {}` in the full clone: {text}", args.join(" "));
        }
    }
    assert!(all.is_empty(), "{}", all.join("\n\n"));
}

/// The description of the change each line of `file` at `rev` is from, as
/// `vl blame --json` in `dir` says (which must succeed).
fn blamed(who: &Person, dir: &Path, file: &str, rev: &str) -> Vec<String> {
    let v: serde_json::Value = serde_json::from_str(&who.ok(dir, &["blame", file, "-r", rev, "--json"])).expect("blame --json");
    let lines = v["lines"].as_array().expect("lines");
    let changes = v["changes"].as_array().expect("changes");
    lines
        .iter()
        .map(|l| {
            let c = changes.iter().find(|c| c["change_id"] == l["change"]).unwrap_or_else(|| panic!("line {} names a change the answer lists", l["line"]));
            c["description"].as_str().expect("a description").to_string()
        })
        .collect()
}

/// BUG-1893: the server's blame (a thin clone's and the web client's
/// answer) gives each line to the change a full clone's does, for the admin
/// and for people who see part of the project, where its line maps differed
/// from the engine's `map_lines`:
/// - a last line that gains its newline (with lines after it, or alone) or
///   goes on is that change's line (`src/lib.rs` starts without a newline:
///   the server left its first line with "initial import");
/// - a changed line equal to an unchanged one further on pairs with it as
///   in the engine's diff (`src/pairs.txt`);
/// - a long file whose first line is removed, or has something put before
///   it, has its own lines (`src/long.txt`: the blame job read the byte
///   before the text and panicked, or split the new first line in two).
#[test]
fn bug_1893_the_servers_blame_is_a_full_clones_at_a_last_line_without_its_newline() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let long: String = (0..100).map(|i| format!("line {i} of a file long enough for its lines to be reused\n")).collect();
    for (desc, lib, long, pairs) in [
        ("step one", format!("{PUBLIC_MARK}\nsecond"), format!("the first line\n{long}"), "x\ny\nb\n"),
        ("step two", format!("{PUBLIC_MARK}\nsecond line"), long.clone(), "b\nz\nb\n"),
        ("step three", format!("{PUBLIC_MARK}\nsecond line\n"), format!("// {long}"), "b\nz\nb\nc"),
    ] {
        write_files(&p.dir, &[("src/lib.rs", &lib), ("src/long.txt", &long), ("src/pairs.txt", pairs)]);
        p.admin.commit_main(&p.dir, desc);
    }
    p.admin.ok(&p.dir, &["push"]);
    let mut long_lines = vec!["step three"];
    long_lines.resize(100, "step one");
    for (who, name) in [(&p.admin, "admin"), (&p.dev, "dev"), (&p.fin, "fin"), (&p.sec, "sec")] {
        let full = who.dir("full-1893");
        who.ok(who.home.path(), &["clone", "--full", &hub.url(&p.name), full.to_str().unwrap()]);
        let thin = who.dir("thin-1893");
        who.ok(who.home.path(), &["clone", &hub.url(&p.name), thin.to_str().unwrap()]);
        for (clone, dir) in [("full", &full), ("thin", &thin)] {
            assert_eq!(blamed(who, dir, "src/lib.rs", "main"), ["step one", "step three"], "{name}, {clone} clone");
            assert_eq!(blamed(who, dir, "src/lib.rs", "main-"), ["step one", "step two"], "{name}, {clone} clone");
            assert_eq!(blamed(who, dir, "src/lib.rs", "main--"), ["step one", "step one"], "{name}, {clone} clone");
            assert_eq!(blamed(who, dir, "src/pairs.txt", "main-"), ["step one", "step two", "step two"], "{name}, {clone} clone");
            assert_eq!(blamed(who, dir, "src/pairs.txt", "main"), ["step one", "step two", "step two", "step three"], "{name}, {clone} clone");
            assert_eq!(blamed(who, dir, "src/long.txt", "main-"), vec!["step one"; 100], "{name}, {clone} clone");
            assert_eq!(blamed(who, dir, "src/long.txt", "main"), long_lines, "{name}, {clone} clone");
        }
        for file in ["src/lib.rs", "src/pairs.txt", "src/long.txt"] {
            for rev in ["main", "main-", "main--"] {
                let args = ["blame", file, "-r", rev, "--json"];
                assert_eq!(who.ok(&thin, &args), who.ok(&full, &args), "{name}: vl blame {file} -r {rev}");
            }
        }
    }
}

/// A new person signed in through the API: their session token.
fn signed_up(api: &Api) -> String {
    api.login(&Identity::generate("rvgaps"), Some(&unique("rvg"))).expect("signs up")
}

/// Guarantee (`docs/HUB.md` §13.25): one caller cannot evade its rate with
/// a new device. A person's devices and agent sessions share an umbrella of
/// ten times the device rate; anyone on Earth has their address's rate
/// (1,000 an hour). One address that signs up new people (an unknown key
/// under a new name: two anonymous requests each) was served each one's
/// whole device rate (BUG-1890): here 20 sign-ups, each then sending its 20
/// an hour, 400 served. People nobody else vouches for now also pay their
/// address's bucket, a person's umbrella: the first has their whole device
/// rate, all of them together an umbrella, and a new person past it is
/// refused from their first request.
#[test]
fn bug_1890_one_address_signing_up_new_people_stays_within_a_persons_rate() {
    let device = Rate { per_second: 20, per_hour: 20 };
    let hub = TestHub::start_with_limits(Settings { device, ..Settings::default() });
    let api = hub.api();
    // What one person gets from any number of devices: ten times a device.
    let umbrella = 10 * device.per_hour as usize;
    let started = std::time::Instant::now();
    let (mut served, mut refused_at_once) = (0, 0);
    // 20 sign-ups are 40 anonymous requests: within the address's 1,000 an
    // hour, paced within its 20 a second.
    for person in 0..20 {
        std::thread::sleep(std::time::Duration::from_millis(120));
        let token = signed_up(&api);
        for i in 0..device.per_hour {
            std::thread::sleep(std::time::Duration::from_millis(55));
            let r = api.get(Some(&token), "/v1/projects/no-such-project/tips");
            if person == 0 {
                assert_ne!(r.status, 429, "the first person has their whole device rate (request {i}): {}", String::from_utf8_lossy(&r.body));
            }
            match r.status {
                429 => {
                    refused_at_once += usize::from(i == 0);
                    break;
                }
                _ => served += 1,
            }
        }
    }
    // The address's bucket refills over the hour while the test runs.
    let refilled = (started.elapsed().as_secs_f64() * umbrella as f64 / 3600.0).ceil() as usize;
    assert!(
        served <= umbrella + refilled,
        "one address was served {served} signed-in requests within a minute through 20 sign-ups; a person's devices together get {umbrella} an hour, and an address without a session 1,000"
    );
    assert!(served >= device.per_hour as usize, "{served} served");
    assert!(refused_at_once >= 8, "past the umbrella a new person is refused from their first request: {refused_at_once} of the last 10 were ({served} served)");
}

/// New people from this test's address, each sending requests until one is
/// refused, until one is refused from their first request: how many were
/// served. The address's bucket for people nobody vouches for is then empty.
fn address_spent_by_sign_ups(api: &Api, device: Rate) -> usize {
    let mut served = 0;
    for _ in 0..40 {
        let token = signed_up(api);
        let mine = (0..device.per_hour).take_while(|_| api.get(Some(&token), "/v1/projects/no-such-project/tips").status != 429).count();
        served += mine;
        if mine == 0 {
            return served;
        }
    }
    panic!("40 new people from one address were served {served} requests and none was refused at once");
}

/// BUG-1890's fix counts only people nobody vouches for against their
/// address. Someone a project's admin put in a group (dev) or named in a
/// rule (carol) counts alone: when sign-ups from their own address (an
/// office's NAT) have spent the address's bucket, each still has their
/// whole rate, and the new people are still refused.
#[test]
fn bug_1890_people_a_project_vouches_for_keep_their_rate_behind_a_spent_address() {
    let device = Rate { per_second: 100_000, per_hour: 500 };
    let hub = TestHub::start_with_limits(Settings { device, ..TestHub::limits() });
    let p = setup_project(&hub);
    let api = hub.api();
    let tips = format!("/v1/projects/{}/tips", p.name);
    let members = [("dev", p.dev.token()), ("carol", p.carol.token())];
    // The server meets each of them in the project (its permissions for
    // them are in memory from the first request on).
    for (who, token) in &members {
        for _ in 0..2 {
            assert_eq!(api.get(Some(token), &tips).status, 200, "{who} reads the project's tips");
        }
    }
    let umbrella = 10 * device.per_hour as usize;
    let started = std::time::Instant::now();
    let served = address_spent_by_sign_ups(&api, device);
    let refilled = (started.elapsed().as_secs_f64() * umbrella as f64 / 3600.0).ceil() as usize;
    assert!(served <= umbrella + refilled, "new people from one address were served {served}; together they get a person's {umbrella} an hour");
    for (who, token) in &members {
        let answers: Vec<u16> = (0..100).map(|_| api.get(Some(token), &tips).status).collect();
        assert!(answers.iter().all(|s| *s == 200), "{who}, in the project by its admin's choice, has their own rate behind the spent address: {answers:?}");
    }
    // Those 200 did not come out of the address's bucket: it is still empty
    // for someone new (but for what refills meanwhile, under 2 a second).
    let token = signed_up(&api);
    let answers: Vec<u16> = (0..100).map(|_| api.get(Some(&token), "/v1/projects/no-such-project/tips").status).collect();
    let refused = answers.iter().filter(|s| **s == 429).count();
    assert!(refused >= 80, "a new person behind the spent address is still refused: {refused} of 100: {answers:?}");
}

/// BUG-1890's second instance: a request under a read grant paid the
/// grant's device alone, never the person's umbrella, so the object routes
/// gave a person each device's whole rate again. dev's agent sessions (ten,
/// each within its own rate) use dev's umbrella; a read under dev's grant,
/// whose device has nearly all of its own rate left, is then refused as
/// dev's own session is.
#[test]
fn bug_1890_requests_under_a_read_grant_pay_the_persons_umbrella() {
    use veil_core::hub::grant::{sign_request, Grant};
    let device = Rate { per_second: 100_000, per_hour: 500 };
    let hub = TestHub::start_with_limits(Settings { device, ..TestHub::limits() });
    let p = setup_project(&hub);
    let api = hub.api();
    let dev = p.dev.token();
    let tips_path = format!("/v1/projects/{}/tips", p.name);
    let tips = api.tips(Some(&dev), &p.name).expect("dev sees the project");
    let grant = tips.grants.get("main").expect("a grant").clone();
    let verified = Grant::verify(&grant, tips.grant_key.as_deref().expect("the server's grant key")).expect("the grant verifies");
    assert!(verified.body.device.is_some(), "the grant names dev's device");
    let (root, identity) = (verified.body.root, p.dev.identity());
    let object = format!("/v1/objects/{}/{}", p.name, root.hex());
    // dev's device signs each read, as `vl` does.
    let under_grant = || {
        let ts = veil_core::now_millis();
        let signature = format!("{ts}.{}", sign_request(&identity, &verified, ts, &[root]));
        api.get_with(&object, &[("veil-grant", &grant), ("veil-chain", ""), ("veil-signature", &signature)]).status
    };
    assert_eq!(under_grant(), 200, "dev reads the root under the grant");
    // A batch names its grant in its body: counted once the body is read.
    let batch = serde_json::to_vec(&serde_json::json!({ "grant": grant })).unwrap();
    let in_a_batch = || api.post(None, &format!("/v1/objects/{}:batch", p.name), &batch, true).status;
    assert_ne!(in_a_batch(), 429, "a batch under the grant is within dev's rates");
    let sessions: Vec<String> = (0..10)
        .map(|i| {
            let r = api.post_json(Some(&dev), "/v1/sessions/agent", &serde_json::json!({"project": p.name, "attribution": {"agent": "rv-gaps/1", "task": format!("BUG-1890-{i}")}}));
            assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
            r.json()["token"].as_str().unwrap().to_string()
        })
        .collect();
    // Each agent session sends its whole rate: together, dev's umbrella.
    let served: Vec<usize> = std::thread::scope(|s| {
        let sent: Vec<_> = sessions
            .iter()
            .map(|t| {
                let (api, tips_path) = (hub.api(), &tips_path);
                s.spawn(move || (0..device.per_hour).take_while(|_| api.get(Some(t), tips_path).status != 429).count())
            })
            .collect();
        sent.into_iter().map(|h| h.join().unwrap()).collect()
    });
    assert!(served.iter().all(|n| *n > 0), "each agent session was served: {served:?}");
    let umbrella = 10 * device.per_hour as usize;
    assert!(served.iter().sum::<usize>() <= umbrella, "dev's agent sessions together stay within dev's umbrella: {served:?}");
    // The umbrella is spent (it refills under 2 a second): dev's own
    // session is refused, and so is a read under dev's grant.
    let own: Vec<u16> = (0..20).map(|_| api.get(Some(&dev), &tips_path).status).collect();
    assert!(own.iter().filter(|s| **s == 429).count() >= 15, "dev's own session, past dev's umbrella: {own:?}");
    let granted: Vec<u16> = (0..20).map(|_| under_grant()).collect();
    assert!(granted.iter().all(|s| *s == 200 || *s == 429), "{granted:?}");
    assert!(
        granted.iter().filter(|s| **s == 429).count() >= 15,
        "reads under dev's grant were served past dev's umbrella (the grant's device has its own rate left): {granted:?}"
    );
    let batches: Vec<u16> = (0..20).map(|_| in_a_batch()).collect();
    assert!(batches.iter().filter(|s| **s == 429).count() >= 15, "batches under dev's grant were served past dev's umbrella: {batches:?}");
}

// ---- derived data after access changes -----------------------------------------------------

fn settled(api: &Api, token: Option<&str>, path: &str) -> Reply {
    let end = std::time::Instant::now() + std::time::Duration::from_secs(120);
    loop {
        let r = api.get(token, path);
        if !(r.status == 503 || behind(&r)) || std::time::Instant::now() >= end {
            return r;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// Is `r` a search or grep answer from an index still catching up with
/// the branch tip (`behind`, `docs/HUB.md` §13.23)? It is the answer of an
/// older snapshot, and says so: not what two views are compared by.
fn behind(r: &Reply) -> bool {
    r.status == 200 && serde_json::from_slice::<serde_json::Value>(&r.body).is_ok_and(|v| v["behind"] == true)
}

/// Without what differs between two askers of one view: the policy's
/// version and the work counters.
fn stripped(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::Object(m) => {
            for k in ["policy_version", "work"] {
                m.remove(k);
            }
            m.values_mut().for_each(stripped);
        }
        serde_json::Value::Array(a) => a.iter_mut().for_each(stripped),
        _ => {}
    }
}

/// Every query route's answer for `token`, as text, each served (200).
fn query_answers(api: &Api, project: &str, token: Option<&str>, who: &str) -> Vec<(String, String)> {
    let base = format!("/v1/projects/{project}/q");
    let log = settled(api, token, &format!("{base}/log?rev=main&n=50"));
    assert_eq!(log.status, 200, "{who}: log: {}", String::from_utf8_lossy(&log.body));
    let entries = log.json()["entries"].as_array().cloned().unwrap_or_default();
    assert!(!entries.is_empty(), "{who}: an empty log: {}", String::from_utf8_lossy(&log.body));
    let id_of = |e: &serde_json::Value| e["snapshot_id"].as_str().or(e["id"].as_str()).unwrap_or_else(|| panic!("no id in {e}")).to_string();
    let oldest = id_of(entries.last().unwrap());
    let paths = vec![
        "log?rev=main&n=50".to_string(),
        "log?rev=main&path=src".to_string(),
        "show?rev=main".to_string(),
        "show?rev=main&stat=true".to_string(),
        format!("show?rev={oldest}"),
        "tree?rev=main".to_string(),
        "tree?rev=main&path=src".to_string(),
        "file?rev=main&path=src/moved.txt".to_string(),
        format!("diff?from={oldest}&to=main"),
        format!("diff?from={oldest}&to=main&stat=true"),
        "blame?rev=main&path=src/moved.txt&follow=true".to_string(),
        "blame?rev=main&path=src/lib.rs".to_string(),
        "history?rev=main&path=src/moved.txt&follow=true".to_string(),
        "history?rev=main&path=src/lib.rs".to_string(),
        "grep?pattern=MARKER".to_string(),
        "grep?pattern=going".to_string(),
        format!("search?q={BILL_MARK}"),
        format!("search?q={PUBLIC_MARK}"),
        "search?q=invoice&kind=path".to_string(),
        "search?q=out&kind=path".to_string(),
        "search?q=moved&kind=path".to_string(),
    ];
    let mut out = Vec::new();
    for p in paths {
        let r = settled(api, token, &format!("{base}/{p}"));
        assert_eq!(r.status, 200, "{who}: {p}: {}", String::from_utf8_lossy(&r.body));
        assert!(!behind(&r), "{who}: {p}: the index never caught up with the tip: {}", String::from_utf8_lossy(&r.body));
        let text = match serde_json::from_slice::<serde_json::Value>(&r.body) {
            Ok(mut v) => {
                stripped(&mut v);
                v.to_string()
            }
            Err(_) => String::from_utf8_lossy(&r.body).to_string(),
        };
        out.push((p, text));
    }
    out
}

fn first_differences(a: &[(String, String)], b: &[(String, String)]) -> Vec<String> {
    let cut = |t: &str| t.chars().take(900).collect::<String>();
    a.iter().zip(b).filter(|(x, y)| x != y).map(|(x, y)| format!("{}:\n  {}\n  {}", x.0, cut(&x.1), cut(&y.1))).collect()
}

/// Guarantee (phase 3, projection equivalence, through the routes): after
/// a grant, a revocation and a public-folder change, every query answer is
/// the answer of the asker's view now. Someone added to `finance` gets
/// exactly what a finance member with the same view gets; removed again,
/// exactly what they got before; and the same for anyone on Earth while
/// billing is `public` and after it is private again.
#[test]
fn rvgaps_query_answers_follow_access_changes_exactly() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    more_history(&p);
    let api = hub.api();
    let (dev, fin) = (p.dev.token(), p.fin.token());
    let base_dev = query_answers(&api, &p.name, Some(&dev), "dev before");
    let base_anon = query_answers(&api, &p.name, None, "anyone before");
    let fin_ans = query_answers(&api, &p.name, Some(&fin), "fin");
    assert_ne!(base_dev, fin_ans, "fin sees billing, dev does not");
    assert!(!base_dev.iter().any(|(_, t)| t.contains(BILL_DIR) || t.contains("going out")), "dev sees nothing of billing before the grant");
    let mut all = Vec::new();
    // A grant: dev joins finance, and reads what fin reads.
    p.admin.ok(&p.dir, &["group", "add", "finance", &p.dev.name]);
    let granted = query_answers(&api, &p.name, Some(&dev), "dev granted");
    all.extend(first_differences(&granted, &fin_ans).into_iter().map(|d| format!("dev in finance, against fin: {d}")));
    // The revocation: exactly as before.
    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.dev.name]);
    let revoked = query_answers(&api, &p.name, Some(&dev), "dev revoked");
    all.extend(first_differences(&revoked, &base_dev).into_iter().map(|d| format!("dev removed again, against dev before: {d}")));
    // Billing made public: anyone reads what fin reads.
    p.admin.ok(&p.dir, &["access", &format!("{BILL_DIR}/"), "public", "finance"]);
    p.admin.commit_main(&p.dir, "billing public");
    p.admin.ok(&p.dir, &["push"]);
    let open = query_answers(&api, &p.name, None, "anyone, billing public");
    let fin_now = query_answers(&api, &p.name, Some(&fin), "fin, billing public");
    all.extend(first_differences(&open, &fin_now).into_iter().map(|d| format!("anyone while billing is public, against fin: {d}")));
    // Private again: exactly as before.
    p.admin.ok(&p.dir, &["access", &format!("{BILL_DIR}/"), "finance"]);
    p.admin.commit_main(&p.dir, "billing private again");
    p.admin.ok(&p.dir, &["push"]);
    let closed = query_answers(&api, &p.name, None, "anyone, billing private again");
    all.extend(first_differences(&closed, &base_anon).into_iter().map(|d| format!("anyone after billing is private again, against anyone before: {d}")));
    assert!(all.is_empty(), "{}", all.join("\n\n"));
}

/// Guarantee (S15 with an access change): from the moment a policy that
/// hides a folder is accepted, no search or grep answer shows it to
/// someone who no longer reads it: `indexing` (503) or nothing, never a
/// hit from the index built under the policy before.
#[test]
fn rvgaps_search_never_answers_from_the_index_of_the_policy_before() {
    const DEEP_MARK: &str = "MARKER-DEEP-CONTENT-5ac31e07";
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let base = format!("/v1/projects/{}/q", p.name);
    write_files(&p.dir, &[("src/deep-41c7/deepfile9731.txt", &format!("{DEEP_MARK}\n"))]);
    p.admin.commit_main(&p.dir, "a file that will be hidden");
    p.admin.ok(&p.dir, &["push"]);
    let dev = p.dev.token();
    let found = |token: Option<&str>| -> (u16, bool) {
        let mut hit = false;
        let mut status = 200;
        for q in [format!("search?q={DEEP_MARK}"), "search?q=deepfile9731&kind=path".to_string(), format!("grep?pattern={DEEP_MARK}")] {
            let r = api.get(token, &format!("{base}/{q}"));
            match r.status {
                200 => {
                    let v = r.json();
                    hit |= v["files"].as_u64().is_some_and(|n| n > 0)
                        || v["files"].as_array().is_some_and(|a| !a.is_empty())
                        || v["results"].as_array().is_some_and(|a| !a.is_empty());
                }
                503 => status = 503,
                s => panic!("{s}: {}", String::from_utf8_lossy(&r.body)),
            }
        }
        (status, hit)
    };
    // Indexed, and found by dev and by anyone, while src/ is public.
    let end = std::time::Instant::now() + std::time::Duration::from_secs(120);
    while found(Some(&dev)) != (200, true) || found(None) != (200, true) {
        assert!(std::time::Instant::now() < end, "never indexed");
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    p.admin.ok(&p.dir, &["access", "src/deep-41c7/", "security"]);
    p.admin.commit_main(&p.dir, "hide it");
    p.admin.ok(&p.dir, &["push"]);
    let mut leaks = 0;
    let mut settled_at = None;
    for i in 0..300 {
        for t in [Some(dev.as_str()), None] {
            let (status, hit) = found(t);
            leaks += usize::from(hit);
            if status == 200 && settled_at.is_none() {
                settled_at = Some(i);
            }
        }
    }
    assert_eq!(leaks, 0, "answers showed the hidden folder after its policy was accepted");
    assert!(settled_at.is_some(), "search never answered again under the new policy");
    // Its group still finds it.
    let sec = p.sec.token();
    let end = std::time::Instant::now() + std::time::Duration::from_secs(120);
    while found(Some(&sec)) != (200, true) {
        assert!(std::time::Instant::now() < end, "security no longer finds its folder");
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

// ---- right after a revocation ---------------------------------------------------------------

/// Guarantee (S3, S5, S6 with a revocation): a thin clone made while its
/// person read a folder holds ids of the history they saw then. Once they
/// are removed, neither the server nor the machine's daemon (whose store
/// another clone of theirs filled while they still had access) gives that
/// clone a file of the folder it never fetched, by any of those ids; and
/// the query routes answer an id of the view they had as an id nobody made.
#[test]
fn rvgaps_a_revoked_persons_thin_clone_and_old_ids_read_nothing_of_the_folder() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    more_history(&p);
    let api = hub.api();
    p.admin.ok(&p.dir, &["group", "add", "finance", &p.dev.name]);
    let url = hub.url(&p.name);
    let (first, second) = (p.dev.dir("thin-1"), p.dev.dir("thin-2"));
    for d in [&first, &second] {
        p.dev.ok(p.dev.home.path(), &["clone", &url, d.to_str().unwrap()]);
    }
    let log = p.dev.ok(&first, &["log", "--json", "-r", "main"]);
    let seen: String = serde_json::from_str::<serde_json::Value>(log.trim()).unwrap()["entries"][0]["snapshot_id"].as_str().unwrap().to_string();
    // Three changes back, billing's invoice held the marker: the second
    // clone reads it while dev has access (through the daemon they share).
    let old = format!("{seen}---");
    let invoice = format!("{BILL_DIR}/acme/invoice.txt");
    let out = p.dev.ok(&second, &["cat", "-r", &old, &invoice]);
    assert!(out.contains(BILL_MARK), "while in finance, dev reads the old invoice: {out}");
    let base = format!("/v1/projects/{}/q", p.name);
    let dev = p.dev.token();
    let shown = api.get(Some(&dev), &format!("{base}/file?rev={seen}&path={BILL_DIR}/out.txt"));
    assert_eq!(shown.status, 200, "while in finance, the id resolves: {}", String::from_utf8_lossy(&shown.body));

    p.admin.ok(&p.dir, &["group", "remove", "finance", &p.dev.name]);
    // The first clone never fetched the old invoice.
    let o = p.dev.run(&first, &["cat", "-r", &old, &invoice]);
    let text = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    assert!(!o.status.success() && !text.contains(BILL_MARK), "removed from finance, a thin clone still read the old invoice:\n{text}");
    let o = p.dev.run(&first, &["pull"]);
    assert!(o.status.success(), "pull after the removal: {}", String::from_utf8_lossy(&o.stderr));
    let o = p.dev.run(&first, &["cat", "-r", &old, &invoice]);
    let text = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    assert!(!o.status.success() && !text.contains(BILL_MARK), "after a pull, a thin clone still read the old invoice:\n{text}");
    // The query routes: the id of the view dev had answers as an id nobody made.
    let nobody = "ab".repeat(32);
    for q in [
        "show?rev=ID".to_string(),
        "log?rev=ID".to_string(),
        "tree?rev=ID".to_string(),
        format!("tree?rev=ID&path={BILL_DIR}"),
        format!("file?rev=ID&path={BILL_DIR}/out.txt"),
        "grep?rev=ID&pattern=going".to_string(),
        "blame?rev=ID&path=src/moved.txt&follow=true".to_string(),
        "history?rev=ID&path=src/moved.txt&follow=true".to_string(),
        "diff?from=ID&to=main".to_string(),
    ] {
        let got = api.get(Some(&dev), &format!("{base}/{}", q.replace("ID", &seen)));
        let none = api.get(Some(&dev), &format!("{base}/{}", q.replace("ID", &nobody)));
        let body = String::from_utf8_lossy(&got.body).replace(&seen, &nobody);
        assert_eq!((got.status, body.as_str()), (none.status, String::from_utf8_lossy(&none.body).as_ref()), "{q}");
    }
}
