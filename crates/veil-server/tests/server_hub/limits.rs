//! Milestone S24's guarantees (`docs/HUB.md` §13.25): rate limits, request
//! bodies under a budget (BUG-1187), per-project bulkheads, connection
//! slots given back in bounded time, and health metrics for admins only.
//! Attackers are outside the trust boundary (`docs/ARCHITECTURE.md`,
//! "Threat model"): anyone on Earth, or a signed-in person or agent.

use std::{
    io::Read,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed},
        Arc,
    },
    time::{Duration, Instant},
};

use veil_core::Identity;
use veil_server::limits::Settings;

use crate::support::*;

/// A new person signed in through the API: their session token.
fn signed_up(api: &Api) -> String {
    api.login(&Identity::generate("limits"), Some(&unique("lim"))).expect("signs up")
}

/// A new private project of `token`'s person.
fn project(api: &Api, token: &str) -> String {
    let name = unique("lim");
    let r = api.post(Some(token), &format!("/v1/projects/{name}"), b"", false);
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    name
}

fn tips(p: &str) -> String {
    format!("/v1/projects/{p}/tips")
}

fn p99(mut v: Vec<Duration>) -> Duration {
    v.sort();
    v[(v.len() * 99 / 100).min(v.len() - 1)]
}

fn challenge(api: &Api) -> Reply {
    api.post_json(None, "/v1/auth/challenge", &serde_json::json!({"key": Identity::generate("x").verifying_hex()}))
}

/// Guarantee: a client within its limits is never refused. At the
/// server's defaults (60/s burst and 5,000/h a device, 20/s and 1,000/h an
/// address), one device sends its whole burst at once and then 40 a
/// second, and anyone on Earth signs in from one address 15 at once and
/// then 10 a second: every request is served.
#[test]
fn a_client_within_its_limits_is_never_refused() {
    let hub = TestHub::start_with_limits(Settings::default());
    let api = hub.api();
    let token = signed_up(&api);
    let p = project(&api, &token);
    for i in 0..55 {
        let r = api.get(Some(&token), &tips(&p));
        assert_eq!(r.status, 200, "request {i} of the burst: {}", String::from_utf8_lossy(&r.body));
    }
    let t = Instant::now();
    for i in 0..120u32 {
        if let Some(d) = (Duration::from_millis(25) * i).checked_sub(t.elapsed()) {
            std::thread::sleep(d);
        }
        let r = api.get(Some(&token), &tips(&p));
        assert_eq!(r.status, 200, "request {i} at 40/s: {}", String::from_utf8_lossy(&r.body));
    }
    // The address's burst refills after the sign-up.
    std::thread::sleep(Duration::from_millis(1500));
    for i in 0..15 {
        let r = challenge(&api);
        assert_eq!(r.status, 200, "anonymous request {i} of the burst: {}", String::from_utf8_lossy(&r.body));
    }
    let t = Instant::now();
    for i in 0..30u32 {
        if let Some(d) = (Duration::from_millis(100) * i).checked_sub(t.elapsed()) {
            std::thread::sleep(d);
        }
        let r = challenge(&api);
        assert_eq!(r.status, 200, "anonymous request {i} at 10/s: {}", String::from_utf8_lossy(&r.body));
    }
}

/// Guarantee: past its limits a client is refused `429` with
/// `retry_after_ms`, and the refusal reveals nothing about other projects
/// or people: it is the same for the client's own project, a project it
/// cannot see and one that does not exist, and names none of them. Others
/// (another device on the same address) are not refused; made-up session
/// tokens cost their address, so they reach the session lookup no faster
/// than the address's rate.
#[test]
fn past_its_limits_a_client_is_refused_and_told_when_naming_nothing() {
    // Devices at 10 an hour: a refused device stays refused for minutes.
    let device = veil_server::limits::bucket::Rate { per_second: 5, per_hour: 10 };
    let hub = TestHub::start_with_limits(Settings { device, ..Settings::default() });
    let api = hub.api();
    let (a, b) = (signed_up(&api), signed_up(&api));
    let (pa, pb) = (project(&api, &a), project(&api, &b));
    let mut refused = None;
    for _ in 0..20 {
        let r = api.get(Some(&a), &tips(&pa));
        if r.status == 429 {
            refused = Some(r);
            break;
        }
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    }
    let r = refused.expect("a device past its burst is refused");
    let shape = |r: &Reply| {
        assert_eq!(r.status, 429, "{}", String::from_utf8_lossy(&r.body));
        let mut v = r.json();
        let wait = v["retry_after_ms"].as_u64().expect("retry_after_ms");
        assert!((1..=360_000).contains(&wait), "{wait}: within the hour's refill of one");
        v.as_object_mut().unwrap().remove("retry_after_ms");
        v
    };
    let own = shape(&r);
    assert_eq!(own["code"], "rate_limited");
    assert_eq!(own.as_object().unwrap().len(), 2, "{own}");
    let hidden = shape(&api.get(Some(&a), &tips(&pb)));
    let nobody = shape(&api.get(Some(&a), &tips(&unique("nobody"))));
    assert_eq!(own, hidden, "a hidden project's refusal is the caller's own");
    assert_eq!(own, nobody);
    let text = own.to_string();
    assert!(!text.contains(&pa) && !text.contains(&pb), "{text}");
    // Another device on the same address is served.
    let r = api.get(Some(&b), &tips(&pb));
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));

    // Made-up tokens: each costs the address before any lookup.
    let t = Instant::now();
    let mut looked_up = 0;
    let mut limited = 0;
    for _ in 0..100 {
        let fake = hex::encode(veil_core::crypto::random_bytes::<32>());
        let r = api.get(Some(&fake), &tips(&pa));
        match r.status {
            401 => looked_up += 1,
            429 => limited += 1,
            s => panic!("{s}: {}", String::from_utf8_lossy(&r.body)),
        }
    }
    let most = 20 + (20.0 * t.elapsed().as_secs_f64()).ceil() as usize;
    assert!(limited > 0 && looked_up <= most, "{looked_up} lookups (at most {most}), {limited} refused");
    // The address is now refused for anyone on Earth (it refills 20 a
    // second: one of a quick few), the signed-in device is not.
    assert!((0..50).any(|_| challenge(&api).status == 429));
    assert_eq!(api.get(Some(&b), &tips(&pb)).status, 200);
}

/// Guarantee: one project's storm cannot starve another project. 64
/// clients flood project A with requests that each read the database
/// (its groups); a quiet client of project B measures its own requests
/// before and during the flood. A runs at most half the server's 16
/// connections at once (its gate), so B always finds one.
#[test]
fn a_flooded_project_does_not_starve_a_quiet_one() {
    let hub = TestHub::start();
    let api = hub.api();
    let (flooder, quiet) = (signed_up(&api), signed_up(&api));
    let (pa, pb) = (project(&api, &flooder), project(&api, &quiet));
    let groups = |p: &str| format!("/v1/projects/{p}/groups");
    let measure = |n: usize| -> Vec<Duration> {
        (0..n)
            .map(|_| {
                let t = Instant::now();
                let r = api.get(Some(&quiet), &groups(&pb));
                assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
                t.elapsed()
            })
            .collect()
    };
    let base = p99(measure(200));
    let server = hub.hub();
    let stop = Arc::new(AtomicBool::new(false));
    let (served, busy) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let floods: Vec<_> = (0..64)
        .map(|_| {
            let (api, stop, served, busy, flooder, path) = (hub.api(), stop.clone(), served.clone(), busy.clone(), flooder.clone(), groups(&pa));
            std::thread::spawn(move || {
                while !stop.load(Relaxed) {
                    let r = api.get(Some(&flooder), &path);
                    match r.status {
                        200 => served.fetch_add(1, Relaxed),
                        503 => busy.fetch_add(1, Relaxed),
                        s => panic!("{s}: {}", String::from_utf8_lossy(&r.body)),
                    };
                }
            })
        })
        .collect();
    let most = Arc::new(AtomicUsize::new(0));
    let sampler = {
        let (stop, most, server, pa) = (stop.clone(), most.clone(), server.clone(), pa.clone());
        std::thread::spawn(move || {
            while !stop.load(Relaxed) {
                most.fetch_max(server.limits.load(Some(&pa)).0, Relaxed);
                std::thread::sleep(Duration::from_millis(2));
            }
        })
    };
    std::thread::sleep(Duration::from_secs(1));
    let flooded = p99(measure(300));
    stop.store(true, Relaxed);
    for t in floods {
        t.join().unwrap();
    }
    sampler.join().unwrap();
    let (served, busy, most) = (served.load(Relaxed), busy.load(Relaxed), most.load(Relaxed));
    eprintln!("quiet project's p99: {base:?} alone, {flooded:?} beside the flood ({served} served, {busy} busy, at most {most} of A's running)");
    assert!(served > 0, "the flood was served too");
    assert!(most <= 8, "A ran {most} requests at once: more than half of the 16 connections");
    assert!(flooded <= (base * 20).max(Duration::from_millis(300)), "the quiet project's p99 went from {base:?} to {flooded:?}");
}

/// A request body that sends `left` bytes, then stops until its gate
/// closes (a client that went quiet).
struct Stops {
    left: usize,
    gate: std::sync::mpsc::Receiver<()>,
    sent: Arc<AtomicUsize>,
}

impl Read for Stops {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.left == 0 {
            let _ = self.gate.recv();
            return Err(std::io::Error::other("the client went away"));
        }
        let n = buf.len().min(self.left).min(64 << 10);
        buf[..n].fill(b' ');
        self.left -= n;
        self.sent.fetch_add(n, Relaxed);
        Ok(n)
    }
}

fn rss() -> usize {
    let s = std::fs::read_to_string("/proc/self/status").unwrap();
    let kib: usize = s.lines().find(|l| l.starts_with("VmRSS:")).and_then(|l| l.split_whitespace().nth(1)).unwrap().parse().unwrap();
    kib << 10
}

/// BUG-1187, and guarantee: server memory stays within a stated bound
/// however many slow or large requests arrive. 8 clients from anywhere
/// (no session) send 56 MiB to the batch route, and 8 signed-in devices
/// 6 MiB uploads (each within its quarter of the pool), and stop before
/// their end. At `--request-memory 64M`, the bodies held never pass the
/// budget (the accounting, exactly), and the process grows by about that
/// (before: every body held whole, +470 MiB for the anonymous ones alone).
#[test]
fn bug_1187_request_bodies_are_buffered_without_a_bound_on_how_many() {
    let hub = TestHub::start_with_limits(Settings { request_memory: 64 << 20, ..TestHub::limits() });
    let api = hub.api();
    let tokens: Vec<String> = (0..8).map(|_| signed_up(&api)).collect();
    let p = project(&api, &tokens[0]);
    let (n, len) = (8, 56usize << 20);
    let sent = Arc::new(AtomicUsize::new(0));
    std::thread::sleep(Duration::from_secs(1));
    let before = rss();
    let mut gates = Vec::new();
    let mut threads = Vec::new();
    for i in 0..2 * n {
        let (tx, gate) = std::sync::mpsc::channel::<()>();
        let (api, sent) = (hub.api(), sent.clone());
        let (token, path, left) = match i < n {
            true => (None, "/v1/objects/anything:batch".to_string(), len),
            false => (Some(tokens[i - n].clone()), format!("/v1/projects/{p}/objects"), 6 << 20),
        };
        threads.push(std::thread::spawn(move || drop(api.post_reader_as(token.as_deref(), &path, Stops { left, gate, sent }))));
        gates.push(tx);
    }
    // Until nothing more is taken in for two seconds.
    let t = Instant::now();
    let mut last = (0, Instant::now());
    while t.elapsed() < Duration::from_secs(60) && last.1.elapsed() < Duration::from_secs(2) {
        std::thread::sleep(Duration::from_millis(100));
        let s = sent.load(Relaxed);
        if s != last.0 {
            last = (s, Instant::now());
        }
    }
    let held = hub.hub().limits.bodies.held_kib();
    let grew = rss().saturating_sub(before) >> 20;
    drop(gates);
    for t in threads {
        t.join().unwrap();
    }
    eprintln!("server: {n} anonymous request bodies of {} MiB and {n} signed-in of 6 MiB, stopped before their end: {} MiB sent, held {held:?} KiB, RSS +{grew} MiB", len >> 20, sent.load(Relaxed) >> 20);
    assert!(held.0 <= 56 << 10 && held.1 <= 8 << 10, "{held:?} KiB held, past the 64 MiB budget");
    assert!(held.0 > 0, "the signed-in pool was used: the test measured something");
    assert!(grew <= 192, "{} unfinished request bodies grew the server by {grew} MiB", 2 * n);
}

/// Guarantee: every connection slot is given back in bounded time. With
/// `--max-connections 16` an address opens at most 2: two clients that
/// send 100 KiB of a body and stop hold them, and a third connection is
/// closed at once. The two are refused `408` within the grace plus 100 KiB
/// at the minimum rate (20 + 6.25 s), and their slots come back.
#[test]
fn every_connection_slot_comes_back_in_bounded_time() {
    let hub = TestHub::start_with_limits(Settings { max_connections: 16, ..TestHub::limits() });
    let start = Instant::now();
    let sent = Arc::new(AtomicUsize::new(0));
    let mut gates = Vec::new();
    for _ in 0..2 {
        let (tx, gate) = std::sync::mpsc::channel::<()>();
        let (api, sent) = (hub.api(), sent.clone());
        std::thread::spawn(move || drop(api.post_reader("/v1/objects/anything:batch", Stops { left: 100 << 10, gate, sent })));
        gates.push(tx);
    }
    while sent.load(Relaxed) < 200 << 10 && start.elapsed() < Duration::from_secs(10) {
        std::thread::sleep(Duration::from_millis(50));
    }
    std::thread::sleep(Duration::from_millis(500));
    let t = Instant::now();
    assert!(hub.api().try_get("/v1/epochs").is_err(), "a third connection from the address is closed");
    assert!(t.elapsed() < Duration::from_secs(5), "at once: {:?}", t.elapsed());
    let served = loop {
        std::thread::sleep(Duration::from_millis(500));
        match hub.api().try_get("/v1/epochs") {
            Ok(r) => break r,
            Err(_) if start.elapsed() < Duration::from_secs(60) => continue,
            Err(e) => panic!("no slot came back within 60 s: {e}"),
        }
    };
    let took = start.elapsed();
    drop(gates);
    eprintln!("slots back after {took:?}");
    assert_eq!(served.status, 401, "the route answers (signed-in only): {}", String::from_utf8_lossy(&served.body));
    assert!(took >= Duration::from_secs(20) && took < Duration::from_secs(40), "{took:?}");
    assert_eq!(hub.hub().limits.bodies.held_kib(), (0, 0));
}

/// Guarantee: health metrics are for the project's admins only and reveal
/// nothing hidden. The admin sees this project's counts exactly (requests
/// to another project are not in them); a member, someone outside, anyone
/// on Earth are refused, and for a private project someone outside gets
/// what a project that does not exist gets. The answer names no person,
/// path or other project; `vl stats` prints it for the admin and refuses a
/// member.
#[test]
fn health_metrics_are_for_admins_only_and_name_nothing_hidden() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let (admin, dev) = (p.admin.token(), p.dev.token());
    let other = signed_up(&api);
    let theirs = project(&api, &other);
    let health = |token: Option<&str>, project: &str| api.get(token, &format!("/v1/projects/{project}/health"));
    let first = health(Some(&admin), &p.name);
    assert_eq!(first.status, 200, "{}", String::from_utf8_lossy(&first.body));
    for _ in 0..5 {
        assert_eq!(api.get(Some(&admin), &tips(&p.name)).status, 200);
    }
    for _ in 0..7 {
        assert_eq!(api.get(Some(&other), &tips(&theirs)).status, 200);
    }
    let second = health(Some(&admin), &p.name);
    assert_eq!(second.status, 200);
    let (v1, v2) = (first.json(), second.json());
    assert_eq!(v2["schema"], "veil.health/1");
    let n = |v: &serde_json::Value, k: &str| v["since_start"][k].as_u64().unwrap();
    assert_eq!(n(&v2, "requests") - n(&v1, "requests"), 6, "five tips and the first health request: {v2}");
    assert!(n(&v2, "tips_hits") + n(&v2, "tips_misses") >= n(&v1, "tips_hits") + n(&v1, "tips_misses") + 5, "{v2}");
    assert!(v2["derive"]["branches"].as_i64().unwrap() >= 1, "{v2}");
    let body = String::from_utf8_lossy(&second.body).to_string();
    for hidden in restricted_markers().into_iter().map(str::to_string).chain([p.dev.name.clone(), p.fin.name.clone(), p.admin.name.clone(), theirs.clone()]) {
        assert!(!body.contains(&hidden), "the health answer names {hidden}: {body}");
    }
    let keys: Vec<&String> = v2.as_object().unwrap().keys().collect();
    assert_eq!(keys.len(), 6, "{keys:?}");

    // Only admins.
    assert_eq!(health(Some(&dev), &p.name).status, 403);
    assert_eq!(health(None, &p.name).status, 401);
    assert_eq!(health(Some(&other), &p.name).status, 403, "public folders let them see the project, not its health");
    let hidden = health(Some(&admin), &theirs);
    let nobody_name = unique("nobody");
    let nobody = health(Some(&admin), &nobody_name);
    assert_eq!((hidden.status, nobody.status), (404, 404));
    assert_eq!(
        String::from_utf8_lossy(&hidden.body).replace(&theirs, "P"),
        String::from_utf8_lossy(&nobody.body).replace(&nobody_name, "P"),
        "a hidden project's health is answered as one that does not exist"
    );

    // `vl stats`.
    let out = p.admin.ok(&p.dir, &["stats"]);
    assert!(out.contains("requests") && out.contains("derive lag"), "{out}");
    let json = p.admin.ok(&p.dir, &["stats", "--json"]);
    let v: serde_json::Value = serde_json::from_str(json.lines().last().unwrap()).unwrap();
    assert_eq!(v["schema"], "veil.health/1");
    let d = p.dev.dir("stats-clone");
    p.dev.ok(p.dev.home.path(), &["clone", &hub.url(&p.name), d.to_str().unwrap()]);
    let out = p.dev.fails(&d, &["stats"]);
    assert!(out.contains("admins"), "{out}");
}

/// BUG-1330: the server's answers are bounded in time, not by a memory
/// budget. 8 clients from anywhere ask for a 24 MiB public file and never
/// read the answer: each answer is held whole until the write deadline
/// cuts its client off (30 s + 24 MiB at 16 KiB/s: 26 minutes for one that
/// reads at the minimum), so the server holds about 8 × 24 MiB.
#[test]
#[ignore = "BUG-1330: answers being written are not counted against a memory budget"]
fn bug_1330_answers_to_clients_that_do_not_read_are_not_bounded_by_a_budget() {
    use veil_core::{hub::grant::Grant, object::Object};
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let big: String = "b".repeat(24 << 20);
    write_files(&p.dir, &[("src/big.bin", &big)]);
    p.admin.commit_main(&p.dir, "a large public file");
    p.admin.ok(&p.dir, &["push"]);
    let api = hub.api();
    let tips = api.tips(None, &p.name).expect("anyone on Earth sees the public folder");
    let grant = tips.grants.get("main").expect("a grant").clone();
    let root = Grant::read_unverified(&grant).unwrap().root;
    let get = |chain: &str, id: &veil_core::ObjectId| api.get_with(&format!("/v1/objects/{}/{}", p.name, id.hex()), &[("veil-grant", &grant), ("veil-chain", chain)]);
    let entry = |raw: &[u8], name: &str| match Object::decode(raw).unwrap() {
        Object::Tree(t) => t.get(name).unwrap().id,
        _ => panic!("not a tree"),
    };
    let r = get("", &root);
    assert_eq!(r.status, 200);
    let src = entry(&r.body, "src");
    let r = get(&root.hex(), &src);
    assert_eq!(r.status, 200);
    let file = entry(&r.body, "big.bin");
    let chain = format!("{},{}", root.hex(), src.hex());
    std::thread::sleep(Duration::from_secs(1));
    let before = rss();
    let stalled: Vec<_> = (0..8).map(|_| hub.api().get_unread(&format!("/v1/objects/{}/{}", p.name, file.hex()), &[("veil-grant", &grant), ("veil-chain", &chain)])).collect();
    std::thread::sleep(Duration::from_secs(3));
    let grew = rss().saturating_sub(before) >> 20;
    drop(stalled);
    eprintln!("8 unread answers of 24 MiB: RSS +{grew} MiB");
    assert!(grew <= 64, "8 answers nobody reads grew the server by {grew} MiB");
}

/// BUG-1331: `vl` does not wait out `retry_after_ms`. A clone at a device
/// rate of 2 a second sends its requests back to back: past the burst the
/// server answers `429 rate_limited` with the time to wait, and `vl` fails
/// instead of waiting it out.
#[test]
#[ignore = "BUG-1331: vl fails on 429 rate_limited and 503 busy instead of waiting retry_after_ms"]
fn bug_1331_vl_waits_out_a_rate_limit() {
    let device = veil_server::limits::bucket::Rate { per_second: 2, per_hour: 10_000 };
    let hub = TestHub::start_with_limits(Settings { device, ..TestHub::limits() });
    let p = setup_project(&hub);
    let d = p.dev.dir("rate-clone");
    for i in 0..5 {
        let o = p.dev.run(p.dev.home.path(), &["clone", &hub.url(&p.name), d.join(i.to_string()).to_str().unwrap()]);
        assert!(o.status.success(), "clone {i}: {}", String::from_utf8_lossy(&o.stderr));
    }
}
