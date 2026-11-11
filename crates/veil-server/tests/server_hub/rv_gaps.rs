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
    }
    assert!(all.is_empty(), "{}", all.join("\n\n"));
}

/// A new person signed in through the API: their session token.
fn signed_up(api: &Api) -> String {
    api.login(&Identity::generate("rvgaps"), Some(&unique("rvg"))).expect("signs up")
}

/// Guarantee (`docs/HUB.md` §13.25): one caller cannot evade its rate with
/// a new device. A person's devices and agent sessions share an umbrella of
/// ten times the device rate; anyone on Earth has their address's rate
/// (1,000 an hour). One address that signs up new people (an unknown key
/// under a new name: two anonymous requests each) is served each one's
/// whole device rate: here 20 sign-ups, each then sending its 20 an hour.
#[test]
#[ignore = "BUG-1890: every sign-up from one address gets a fresh device and person bucket, so one address is served any multiple of a person's rate"]
fn bug_1890_one_address_signing_up_new_people_stays_within_a_persons_rate() {
    let device = Rate { per_second: 20, per_hour: 20 };
    let hub = TestHub::start_with_limits(Settings { device, ..Settings::default() });
    let api = hub.api();
    // What one person gets from any number of devices: ten times a device.
    let umbrella = 10 * device.per_hour as usize;
    let mut served = 0;
    // 20 sign-ups are 40 anonymous requests: within the address's 1,000 an
    // hour, paced within its 20 a second.
    for person in 0..20 {
        std::thread::sleep(std::time::Duration::from_millis(120));
        let token = signed_up(&api);
        for i in 0..device.per_hour {
            std::thread::sleep(std::time::Duration::from_millis(55));
            let r = api.get(Some(&token), "/v1/projects/no-such-project/tips");
            if i == 0 {
                assert_ne!(r.status, 429, "person {person}: a new person's first request is served: {}", String::from_utf8_lossy(&r.body));
            }
            match r.status {
                429 => break,
                _ => served += 1,
            }
        }
    }
    assert!(
        served <= umbrella,
        "one address was served {served} signed-in requests within a minute through 20 sign-ups; a person's devices together get {umbrella} an hour, and an address without a session 1,000"
    );
}

// ---- derived data after access changes -----------------------------------------------------

fn settled(api: &Api, token: Option<&str>, path: &str) -> Reply {
    let end = std::time::Instant::now() + std::time::Duration::from_secs(120);
    loop {
        let r = api.get(token, path);
        if r.status != 503 || std::time::Instant::now() >= end {
            return r;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
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
