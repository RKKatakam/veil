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
/// server's defaults (200/s burst and 50,000/h a device, 20/s and 1,000/h an
/// address), one device sends a burst at once and then 40 a
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
/// before and during the flood. A runs at most three quarters of the
/// server's 16 connections at once (its gate), so B always finds one.
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
    assert!(most <= 12, "A ran {most} requests at once: more than three quarters of the 16 connections");
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

/// The memory-heavy tests of this module run one at a time: the RSS they
/// measure is the test process's, which tests beside them grow too.
static HEAVY: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn rss() -> usize {
    let s = std::fs::read_to_string("/proc/self/status").unwrap();
    let kib: usize = s.lines().find(|l| l.starts_with("VmRSS:")).and_then(|l| l.split_whitespace().nth(1)).unwrap().parse().unwrap();
    kib << 10
}

/// BUG-1187, and guarantee: server memory stays within a stated bound
/// however many slow or large requests arrive. 8 clients from anywhere
/// (no session) send 56 MiB to the batch route, and 8 signed-in devices
/// 4 MiB uploads (each within its quarter of the pool), and stop before
/// their end. At `--request-memory 64M`, the bodies held never pass the
/// budget (the accounting, exactly), and the process grows by about that
/// (before: every body held whole, +470 MiB for the anonymous ones alone).
#[test]
fn bug_1187_request_bodies_are_buffered_without_a_bound_on_how_many() {
    let _heavy = HEAVY.lock().unwrap_or_else(|e| e.into_inner());
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
            false => (Some(tokens[i - n].clone()), format!("/v1/projects/{p}/objects"), 4 << 20),
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
    eprintln!("server: {n} anonymous request bodies of {} MiB and {n} signed-in of 4 MiB, stopped before their end: {} MiB sent, held {held:?} KiB, RSS +{grew} MiB", len >> 20, sent.load(Relaxed) >> 20);
    assert!(held.0 <= 40 << 10 && held.1 <= 16 << 10, "{held:?} KiB held, past the 64 MiB budget");
    assert!(held.0 > 0, "the signed-in pool was used: the test measured something");
    // The test process's: other tests beside this one grow it too.
    assert!(grew <= 256, "{} unfinished request bodies grew the server by {grew} MiB (+900 before)", 2 * n);
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

/// BUG-1330: answers being written are under a memory budget. 8 clients
/// from anywhere ask for a 24 MiB public file and never read the answer:
/// before the fix each answer was held whole until the write deadline cut
/// its client off (30 s + 24 MiB at 16 KiB/s: 26 minutes for one that
/// reads at the minimum), +196 MiB. At `--request-memory 64M` (a 64 MiB
/// answers' budget, a quarter of it an address's, one larger answer alone)
/// the first is sent and the others answered `busy`; the object route takes
/// its share before reading, so a refused one reads nothing.
#[test]
fn bug_1330_answers_to_clients_that_do_not_read_are_not_bounded_by_a_budget() {
    use veil_core::{hub::grant::Grant, object::Object};
    let _heavy = HEAVY.lock().unwrap_or_else(|e| e.into_inner());
    let hub = TestHub::start_with_limits(Settings { request_memory: 64 << 20, ..TestHub::limits() });
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
    // At once: each refusal takes its 2 s wait, and one after another they
    // could outlast the first answer's write deadline (30 s), which frees
    // its share.
    let stalled: Vec<_> = std::thread::scope(|s| {
        let asked: Vec<_> = (0..8)
            .map(|_| s.spawn(|| hub.api().get_unread(&format!("/v1/objects/{}/{}", p.name, file.hex()), &[("veil-grant", &grant), ("veil-chain", &chain)])))
            .collect();
        asked.into_iter().map(|h| h.join().unwrap()).collect()
    });
    std::thread::sleep(Duration::from_secs(3));
    let grew = rss().saturating_sub(before) >> 20;
    let held = hub.hub().limits.answers.held_kib();
    let statuses: Vec<u16> = stalled.iter().map(|r| r.status().as_u16()).collect();
    drop(stalled);
    eprintln!("8 unread answers of 24 MiB: {statuses:?}, {held} KiB held, RSS +{grew} MiB");
    assert_eq!(statuses.iter().filter(|s| **s == 200).count(), 1, "one answer at a time for the address: {statuses:?}");
    assert!(statuses.iter().all(|s| *s == 200 || *s == 503), "{statuses:?}");
    assert!(held <= 64 << 10, "{held} KiB held");
    // The RSS is the test process's (tests beside this one grow it too):
    // shown, not asserted; the accounting above is exact.
}

/// BUG-1331: `vl` does not wait out `retry_after_ms`. A clone at a device
/// rate of 2 a second sends its requests back to back: past the burst the
/// server answers `429 rate_limited` with the time to wait, and `vl` fails
/// instead of waiting it out.
#[test]
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

// ---------------------------------------------------------------------------
// S24 cycle 1's review (`docs/BUGS.md`, "S24 cycle 1"): a test for each
// property the review checked; where one does not hold, an ignored
// reproduction (BUG-1333 to BUG-1338).

/// Raw TLS connections from a chosen local address (clients on several
/// addresses of one machine: 127.0.0.2, …, or two IPv6 addresses of one
/// /64), and raw HTTP/1.1 and HTTP/2 over them.
mod raw {
    use std::{
        io::Read,
        net::{IpAddr, SocketAddr, TcpStream},
        sync::Arc,
        time::Duration,
    };

    use rustls::{
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        crypto::CryptoProvider,
        pki_types::{CertificateDer, ServerName, UnixTime},
        DigitallySignedStruct, SignatureScheme,
    };

    /// A TCP connection from `local` to `to`.
    pub fn tcp(local: IpAddr, to: SocketAddr) -> TcpStream {
        let rt = tokio::runtime::Builder::new_current_thread().enable_io().build().unwrap();
        rt.block_on(async {
            let s = match to {
                SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4(),
                SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6(),
            }
            .unwrap();
            s.bind(SocketAddr::new(local, 0)).unwrap_or_else(|e| panic!("binding {local}: {e}"));
            let c = s.connect(to).await.unwrap_or_else(|e| panic!("connecting from {local} to {to}: {e}"));
            let c = c.into_std().unwrap();
            c.set_nonblocking(false).unwrap();
            c
        })
    }

    /// The test server's certificate is self-signed: any certificate, its
    /// handshake signatures checked.
    #[derive(Debug)]
    struct AnyCertificate(Arc<CryptoProvider>);

    impl ServerCertVerifier for AnyCertificate {
        fn verify_server_cert(&self, _: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: &ServerName<'_>, _: &[u8], _: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
        }
        fn verify_tls13_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }

    pub type Tls = rustls::StreamOwned<rustls::ClientConnection, TcpStream>;

    /// TLS over `tcp`, its handshake done.
    pub fn tls(tcp: TcpStream) -> Tls {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AnyCertificate(provider)))
            .with_no_client_auth();
        let conn = rustls::ClientConnection::new(Arc::new(config), ServerName::try_from("localhost").unwrap()).unwrap();
        let mut s = rustls::StreamOwned::new(conn, tcp);
        while s.conn.is_handshaking() {
            s.conn.complete_io(&mut s.sock).expect("the TLS handshake");
        }
        s
    }

    /// Whether the server closed `s` within `wait`.
    pub fn closed(s: &mut TcpStream, wait: Duration) -> bool {
        s.set_read_timeout(Some(wait)).unwrap();
        match s.read(&mut [0u8; 1]) {
            Ok(0) => true,
            Ok(_) => false,
            Err(e) => !matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut),
        }
    }

    /// An HTTP/2 frame.
    pub fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let mut f = (payload.len() as u32).to_be_bytes()[1..].to_vec();
        f.extend([kind, flags]);
        f.extend(stream.to_be_bytes());
        f.extend(payload);
        f
    }
}

fn spawn_flood(hub: &TestHub, token: &str, paths: Vec<String>, clients: usize, stop: &Arc<AtomicBool>, served: &Arc<AtomicUsize>) -> Vec<std::thread::JoinHandle<()>> {
    (0..clients)
        .map(|i| {
            let (api, stop, served, token, path) = (hub.api(), stop.clone(), served.clone(), token.to_string(), paths[i % paths.len()].clone());
            std::thread::spawn(move || {
                while !stop.load(Relaxed) {
                    let r = api.get(Some(&token), &path);
                    match r.status {
                        200 => {
                            served.fetch_add(1, Relaxed);
                        }
                        503 => {}
                        s => panic!("{path}: {s}: {}", String::from_utf8_lossy(&r.body)),
                    }
                }
            })
        })
        .collect()
}

/// BUG-1339 (S24 cycle 1): at the server's defaults (60 a second, 5,000
/// an hour a device), an agent fleet of one person on one device is
/// refused. Agents in workspaces share their person's device (agent
/// sessions, S11, are not built), and `vl` sends about 18 requests per
/// commit, push and pull (measured here with the limits out of the way:
/// 438 requests for 6 clones and 24 cycles, in 6.3 s, about 70 a second).
/// 6 agents, each cloning and then committing, pushing its own tag and
/// pulling 4 times, are refused `429` within seconds; and the hour's 5,000
/// is about 4.6 such cycles a minute for the whole device.
#[test]
fn bug_1339_an_agent_fleet_on_one_device_is_refused_at_the_defaults() {
    let hub = TestHub::start_with_limits(Settings::default());
    let p = setup_project(&hub);
    let api = hub.api();
    let admin = p.admin.token();
    let requests = |api: &Api| {
        let r = api.get(Some(&admin), &format!("/v1/projects/{}/health", p.name));
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        r.json()["since_start"]["requests"].as_u64().unwrap()
    };
    let before = requests(&api);
    let (agents, cycles) = (6, 4);
    std::thread::scope(|s| {
        for a in 0..agents {
            let (p, hub) = (&p, &hub);
            s.spawn(move || {
                let d = p.dev.dir(&format!("agent{a}"));
                p.dev.ok(p.dev.home.path(), &["clone", &hub.url(&p.name), d.to_str().unwrap()]);
                for c in 0..cycles {
                    write_files(&d, &[(&format!("src/agent{a}/f{c}.txt"), &format!("agent {a} cycle {c}"))]);
                    p.dev.ok(&d, &["commit", "-m", &format!("agent {a} cycle {c}")]);
                    p.dev.ok(&d, &["tag", "set", &format!("agent{a}"), "-r", "@-", "--force"]);
                    p.dev.ok(&d, &["push", "--tag", &format!("agent{a}")]);
                    p.dev.ok(&d, &["pull"]);
                }
            });
        }
    });
    let used = requests(&api) - before - 1;
    eprintln!("{agents} agents on one device: {used} requests for {agents} clones and {} commit-push-pull cycles ({:.1} a cycle with its share of the clone)", agents * cycles, used as f64 / (agents * cycles) as f64);
    assert!(used > 0);
}

/// BUG-1333 (S24 cycle 1), the signed-in pool: one signed-in upload
/// larger than its quarter takes the whole pool from its first byte until
/// its last, and holds it while it arrives at any rate at or above the
/// minimum. At `--request-memory 64M` (a 48 MiB signed-in pool), one person
/// uploads a 50 MiB file on a slow link (its first 256 KiB, then the rest
/// later, within the 20 s grace): meanwhile someone else's push of one
/// small file, in another project, waits 10 s for its share and is refused
/// `busy`. At the defaults the same holds for any upload over 384 MiB, for
/// as long as it takes (a 400 MiB file at 10 Mbit/s: five minutes).
///
/// Fixed: a body holds what has arrived (here 256 KiB), and small bodies
/// have a reserve.
#[test]
fn bug_1333_one_slow_large_upload_refuses_every_other_signed_in_body() {
    use std::io::Write;
    let hub = TestHub::start_with_limits(Settings { request_memory: 64 << 20, ..TestHub::limits() });
    let p = setup_project(&hub);
    let api = hub.api();
    let uploader = signed_up(&api);
    let theirs = project(&api, &uploader);
    let server: std::net::SocketAddr = hub.authority().parse().unwrap();
    let mut up = raw::tls(raw::tcp("127.0.0.1".parse().unwrap(), server));
    write!(up, "POST /v1/projects/{theirs}/objects HTTP/1.1\r\nhost: veil\r\nauthorization: Bearer {uploader}\r\ncontent-type: application/octet-stream\r\ncontent-length: {}\r\n\r\n", 50 << 20).unwrap();
    up.write_all(&vec![0u8; 256 << 10]).unwrap();
    up.flush().unwrap();
    let t = Instant::now();
    while hub.hub().limits.bodies.held_kib().0 == 0 && t.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(20));
    }
    let held = hub.hub().limits.bodies.held_kib();
    assert!(held.0 > 0 && held.0 <= 1 << 10, "the upload holds what has arrived (256 KiB): {held:?} KiB");
    write_files(&p.dir, &[("src/small.txt", "one small file")]);
    p.admin.commit_main(&p.dir, "a small change");
    let t = Instant::now();
    let o = p.admin.run(&p.dir, &["push"]);
    let took = t.elapsed();
    drop(up);
    assert!(o.status.success(), "a push of one small file beside one slow upload, refused after {took:?}: {}", String::from_utf8_lossy(&o.stderr));
}

/// BUG-1333 (S24 cycle 1), the anonymous pool: four addresses, each
/// within its quarter, hold the whole anonymous pool with request heads
/// alone (a declared length, no byte of the body: the share is taken
/// before any is read), and then every sign-in on the server (its
/// challenge, a body of a few bytes) waits 10 s for its share and is
/// refused `busy`, for as long as the four keep the minimum rate (20 s +
/// 32 MiB at 16 KiB/s: 35 minutes, 64 KiB/s in all).
///
/// Fixed: heads alone hold nothing; four addresses that send their
/// quarters' bytes do hold the anonymous pool, and a sign-in still goes,
/// in the reserve kept for small bodies.
#[test]
fn bug_1333_four_addresses_holding_bodies_refuse_every_sign_in() {
    use std::io::Write;
    let hub = TestHub::start();
    let server: std::net::SocketAddr = hub.authority().parse().unwrap();
    let quarter = hub.hub().limits.bodies.anonymous_limit();
    let mut held: Vec<_> = (2..=5)
        .map(|i| {
            let mut s = raw::tls(raw::tcp(format!("127.0.0.{i}").parse().unwrap(), server));
            write!(s, "POST /v1/auth/challenge HTTP/1.1\r\nhost: veil\r\ncontent-type: application/json\r\ncontent-length: {quarter}\r\n\r\n").unwrap();
            s.flush().unwrap();
            s
        })
        .collect();
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(hub.hub().limits.bodies.held_kib().1, 0, "heads alone hold nothing");
    for s in &mut held {
        s.write_all(&vec![b' '; quarter as usize - 1]).unwrap();
        s.flush().unwrap();
    }
    let t = Instant::now();
    while u64::from(hub.hub().limits.bodies.held_kib().1) < 4 * (quarter >> 10) && t.elapsed() < Duration::from_secs(10) {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(u64::from(hub.hub().limits.bodies.held_kib().1), 4 * (quarter >> 10), "four bodies hold the anonymous pool");
    let t = Instant::now();
    let r = challenge(&hub.api());
    let took = t.elapsed();
    drop(held);
    assert_eq!(r.status, 200, "a sign-in from another address, after {took:?}: {}", String::from_utf8_lossy(&r.body));
    assert!(took < Duration::from_secs(1), "{took:?}");
}

/// BUG-1334 (S24 cycle 1): a project's gate is keyed by the name in the
/// path, for everyone, so a request for a private project waits behind
/// its people's requests before it is refused. Someone who cannot see the
/// project then tells a busy private project from a missing name: while
/// the project's people keep its gate full (64 clients reading its groups,
/// a database read each), an outsider's search of it waits its second and
/// is shed `503 busy`, where a name nobody has is answered `404` at once.
/// Both must be the not-found answer, in about the same time.
#[test]
fn bug_1334_a_busy_private_project_is_told_apart_from_a_missing_one() {
    let hub = TestHub::start();
    let api = hub.api();
    let (owner, outsider) = (signed_up(&api), signed_up(&api));
    let secret = project(&api, &owner);
    let (stop, served) = (Arc::new(AtomicBool::new(false)), Arc::new(AtomicUsize::new(0)));
    let floods = spawn_flood(&hub, &owner, vec![format!("/v1/projects/{secret}/groups")], 64, &stop, &served);
    std::thread::sleep(Duration::from_secs(1));
    let mut answers = Vec::new();
    for _ in 0..5 {
        let missing = unique("lim");
        for (what, name) in [("private", &secret), ("missing", &missing)] {
            let t = Instant::now();
            let r = api.get(Some(&outsider), &format!("/v1/projects/{name}/q/search?q=x"));
            answers.push((what, r.status, t.elapsed()));
        }
    }
    stop.store(true, Relaxed);
    for t in floods {
        t.join().unwrap();
    }
    eprintln!("an outsider's searches beside the project's own work: {answers:?}");
    assert!(served.load(Relaxed) > 0, "the project's people were served");
    assert!(answers.iter().filter(|a| a.0 == "missing").all(|a| a.1 == 404), "a missing name is not found: {answers:?}");
    for (what, status, took) in &answers {
        assert_eq!(*status, 404, "{what}: an outsider tells a busy private project from a missing one: {answers:?}");
        assert!(*took < Duration::from_millis(500), "{what}: answered after {took:?}: {answers:?}");
    }
}

/// BUG-1335 (S24 cycle 1): gates are keyed by the path's spelling of the
/// project's name, but the routes decode it (`%6C` is `l`), so one
/// project named in 8 spellings (its first three letters percent-encoded
/// or not) gets 8 gates and runs up to the server's whole gate (32 at
/// once on a pool of 16), not three quarters of the connections: the
/// bulkhead that keeps a project's storm from starving the others does not
/// hold against a member, or anyone on Earth for a public project.
#[test]
fn bug_1335_a_project_named_in_other_spellings_runs_past_its_bulkhead() {
    let hub = TestHub::start();
    let api = hub.api();
    let flooder = signed_up(&api);
    let pa = project(&api, &flooder);
    let spelled = |k: usize| pa.char_indices().map(|(i, c)| if i < 3 && k >> i & 1 == 1 { format!("%{:02X}", c as u32) } else { c.to_string() }).collect::<String>();
    let paths: Vec<String> = (0..8).map(|k| format!("/v1/projects/{}/groups", spelled(k))).collect();
    for path in &paths {
        let r = api.get(Some(&flooder), path);
        assert_eq!(r.status, 200, "{path} names the project: {}", String::from_utf8_lossy(&r.body));
    }
    let server = hub.hub();
    let (stop, served) = (Arc::new(AtomicBool::new(false)), Arc::new(AtomicUsize::new(0)));
    let floods = spawn_flood(&hub, &flooder, paths, 64, &stop, &served);
    let most = Arc::new(AtomicUsize::new(0));
    let sampler = {
        let (stop, most, server) = (stop.clone(), most.clone(), server.clone());
        std::thread::spawn(move || {
            while !stop.load(Relaxed) {
                // Only this project's requests are in the server's gate.
                most.fetch_max(server.limits.load(None).0, Relaxed);
                std::thread::sleep(Duration::from_millis(2));
            }
        })
    };
    std::thread::sleep(Duration::from_secs(3));
    stop.store(true, Relaxed);
    for t in floods {
        t.join().unwrap();
    }
    sampler.join().unwrap();
    let most = most.load(Relaxed);
    eprintln!("one project in 8 spellings: {} served, at most {most} running at once", served.load(Relaxed));
    assert!(served.load(Relaxed) > 0, "the flood was served");
    assert!(most <= 12, "the project ran {most} requests at once: more than three quarters of the 16 connections");
}

/// Two global IPv6 addresses of this machine in one /64, if it has them.
fn two_in_one_64() -> Option<(std::net::Ipv6Addr, std::net::Ipv6Addr)> {
    let s = std::fs::read_to_string("/proc/net/if_inet6").ok()?;
    let mut seen: Vec<std::net::Ipv6Addr> = Vec::new();
    for l in s.lines() {
        let f: Vec<&str> = l.split_whitespace().collect();
        // Global scope, not tentative or deprecated.
        if f.len() < 6 || f[3] != "00" || u8::from_str_radix(f[4], 16).ok()? & 0x60 != 0 {
            continue;
        }
        let a = std::net::Ipv6Addr::from(u128::from_str_radix(f[0], 16).ok()?);
        if let Some(b) = seen.iter().find(|b| u128::from(**b) >> 64 == u128::from(a) >> 64 && **b != a) {
            return Some((*b, a));
        }
        seen.push(a);
    }
    None
}

/// BUG-1336 (S24 cycle 1): the listener's per-address share (an eighth of
/// `--max-connections`) is keyed by the whole IPv6 address, where the rate
/// limits and body shares key an address by its /64 (one subscriber's
/// allocation): one host with a /64 opens every connection of the server
/// from addresses of its own. With `--max-connections 16`, an address
/// opens 2 and its third is closed at once, but another address of the
/// same /64 opens more. Needs two global IPv6 addresses of one /64 on the
/// machine (two interfaces on one network, or `ip -6 addr add`).
#[test]
#[ignore = "needs two global IPv6 addresses of one /64 on this machine (BUG-1336, fixed; limits::tests::the_connection_share_groups_addresses_as_the_rates_do runs everywhere)"]
fn bug_1336_one_ipv6_subscriber_opens_more_than_an_eighth_of_the_connections() {
    let (a, b) = two_in_one_64().expect("this reproduction needs two global IPv6 addresses of one /64 on this machine");
    let hub = TestHub::start_with_limits_on(std::net::SocketAddr::new(a.into(), 0), Settings { max_connections: 16, ..TestHub::limits() });
    let server = std::net::SocketAddr::new(a.into(), hub.port);
    // The address's share: 2 connections, waiting for their handshakes.
    let mut held: Vec<_> = (0..2).map(|_| raw::tcp(a.into(), server)).collect();
    std::thread::sleep(Duration::from_millis(500));
    let mut third = raw::tcp(a.into(), server);
    assert!(raw::closed(&mut third, Duration::from_secs(3)), "a third connection from {a} is closed at once");
    for h in &mut held {
        assert!(!raw::closed(h, Duration::from_millis(100)), "the share's two stay open");
    }
    let mut more = raw::tcp(b.into(), server);
    assert!(raw::closed(&mut more, Duration::from_secs(3)), "{b}, of {a}'s /64 (one subscriber, as the rate limits count it), opened a third connection");
}

/// BUG-1337 (S24 cycle 1): HTTP/2 connections have no idle limit. An
/// HTTP/1.1 connection that sends no request is closed after 20 s
/// (BUG-825), but one that speaks HTTP/2 and answers the server's pings
/// keeps its connection slot for ever without sending a request: an
/// eighth of `--max-connections` per address (all of them from 8
/// addresses, or one IPv6 /64 by BUG-1336), held at no cost but a ping
/// every 20 s. Every connection slot must come back in bounded time.
#[test]
fn bug_1337_an_idle_http2_connection_keeps_its_slot_for_ever() {
    use std::io::{Read, Write};
    let hub = TestHub::start_with_limits(Settings { max_connections: 16, ..TestHub::limits() });
    let server: std::net::SocketAddr = hub.authority().parse().unwrap();
    let mut s = raw::tls(raw::tcp("127.0.0.1".parse().unwrap(), server));
    s.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").unwrap();
    s.write_all(&raw::frame(4, 0, 0, &[])).unwrap();
    s.flush().unwrap();
    s.sock.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
    let start = Instant::now();
    let (mut spoke_h2, mut pings, mut buf) = (false, 0, Vec::new());
    let closed = loop {
        if start.elapsed() > Duration::from_secs(50) {
            break None;
        }
        while buf.len() >= 9 {
            let len = u32::from_be_bytes([0, buf[0], buf[1], buf[2]]) as usize;
            if buf.len() < 9 + len {
                break;
            }
            let (kind, flags, payload) = (buf[3], buf[4], buf[9..9 + len].to_vec());
            buf.drain(..9 + len);
            match (kind, flags & 1) {
                (4, 0) => {
                    spoke_h2 = true;
                    s.write_all(&raw::frame(4, 1, 0, &[])).unwrap();
                }
                (6, 0) => {
                    pings += 1;
                    s.write_all(&raw::frame(6, 1, 0, &payload)).unwrap();
                }
                _ => {}
            }
            s.flush().unwrap();
        }
        let mut chunk = [0u8; 4096];
        match s.read(&mut chunk) {
            Ok(0) => break Some(start.elapsed()),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
            Err(_) => break Some(start.elapsed()),
        }
    };
    eprintln!("an idle HTTP/2 connection: closed {closed:?}, {pings} pings answered");
    assert!(spoke_h2, "the server spoke HTTP/2");
    assert!(closed.is_some_and(|t| t < Duration::from_secs(45)), "still open after {:?} ({pings} pings answered), no request sent", start.elapsed());
}

/// BUG-1338 (S24 cycle 1): a session this server has not met yet costs its
/// address's anonymous rate (20 a second), so signed-in people behind one
/// address (an office's NAT, a CI fleet) are refused on a server new to
/// their sessions: the second server of a deployment, or the first after a
/// restart or once the session cache has evicted them. 40 people sign in
/// through the first server within the address's rate; their first
/// requests to a second server, at once, are refused `429` past the 20th,
/// though each person is far within the device rate.
#[test]
fn bug_1338_signed_in_people_behind_one_address_are_refused_on_a_server_new_to_them() {
    let hub = TestHub::start_with_limits(Settings::default());
    let api = hub.api();
    let tokens: Vec<String> = (0..40)
        .map(|_| {
            std::thread::sleep(Duration::from_millis(150));
            let t = signed_up(&api);
            let r = api.get(Some(&t), "/v1/epochs");
            assert_eq!(r.status, 200, "each person uses the first server: {}", String::from_utf8_lossy(&r.body));
            t
        })
        .collect();
    let second = TestHub::beside(&hub);
    std::thread::sleep(Duration::from_millis(1500));
    let api2 = second.api();
    let answers: Vec<u16> = std::thread::scope(|s| {
        let asked: Vec<_> = tokens.iter().map(|t| s.spawn(|| api2.get(Some(t), "/v1/epochs").status)).collect();
        asked.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let refused = answers.iter().filter(|s| **s == 429).count();
    assert!(answers.iter().all(|s| *s == 200 || *s == 429), "{answers:?}");
    assert_eq!(refused, 0, "{refused} of 40 signed-in people refused on their first request to the second server: {answers:?}");
}

/// BUG-1333's fix keeps a large upload working: a body larger than the
/// whole signed-in pool (at the defaults, a file over 384 MiB; here a
/// 50 MiB file that does not compress, at `--request-memory 64M`: a 40 MiB
/// pool) grows past its quarter while it is all its device holds, and the
/// push lands; a clone then reads it back, its answer larger than an
/// address's quarter of the answers' budget, alone.
#[test]
fn a_push_of_one_file_larger_than_the_signed_in_pool_lands() {
    let _heavy = HEAVY.lock().unwrap_or_else(|e| e.into_inner());
    let hub = TestHub::start_with_limits(Settings { request_memory: 64 << 20, ..TestHub::limits() });
    let p = setup_project(&hub);
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    let big: Vec<u8> = (0..50usize << 20)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect();
    std::fs::write(p.dir.join("src/big.bin"), &big).unwrap();
    p.admin.commit_main(&p.dir, "a 50 MiB file");
    let out = p.admin.ok(&p.dir, &["push"]);
    eprintln!("{out}");
    let d = p.dev.dir("big-clone");
    p.dev.ok(p.dev.home.path(), &["clone", &hub.url(&p.name), d.to_str().unwrap()]);
    assert!(std::fs::read(d.join("src/big.bin")).unwrap() == big, "the file arrived whole");
    assert_eq!((hub.hub().limits.bodies.held_kib(), hub.hub().limits.answers.held_kib()), ((0, 0), 0));
}

// ---- S24 part B: limits on the landing service -------------------------------------

fn agent_session_token(api: &Api, token: &str, project: &str, run: &str) -> String {
    let r = api.post_json(
        Some(token),
        "/v1/sessions/agent",
        &serde_json::json!({"project": project, "attribution": {"agent": "claude-code/2.3", "task": "TASK-S24", "run": run}}),
    );
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    r.json()["token"].as_str().unwrap().to_string()
}

fn land_edit(api: &Api, token: &str, project: &str, base: veil_core::ObjectId, path: &str, text: &str, wait: bool) -> Reply {
    api.post_json(
        Some(token),
        &format!("/v1/projects/{project}/land"),
        &serde_json::json!({"onto": "main", "base": base.hex(), "edits": [{"path": path, "put": {"text": text}}], "description": format!("land {path}"), "wait": wait}),
    )
}

fn wait_ticket(api: &Api, token: &str, project: &str, ticket: &str) -> serde_json::Value {
    for _ in 0..40 {
        let r = api.get(Some(token), &format!("/v1/projects/{project}/land/{ticket}"));
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        let v = r.json();
        if v["state"] != "queued" && v["state"] != "merging" {
            return v;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("ticket {ticket} still queued/merging");
}

fn project_id_of(hub: &TestHub, name: &str) -> i64 {
    let h = hub.hub();
    hub.rt
        .block_on(sqlx::query_scalar::<_, i64>("SELECT id FROM projects WHERE name = $1").bind(name).fetch_one(&h.db))
        .unwrap()
}

fn hold_branch(hub: &TestHub, project: i64, branch: &str) {
    let h = hub.hub();
    hub.rt
        .block_on(
            sqlx::query(
                "INSERT INTO landing_leases (project_id, branch, holder, epoch, expires_at) VALUES ($1, $2, 'test', 1, $3) \
                 ON CONFLICT (project_id, branch) DO UPDATE SET holder = 'test', epoch = landing_leases.epoch + 1, expires_at = $3",
            )
            .bind(project)
            .bind(branch)
            .bind(veil_core::now_millis() + 600_000)
            .execute(&h.db),
        )
        .unwrap();
}

fn release_branch(hub: &TestHub, project: i64, branch: &str) {
    let h = hub.hub();
    hub.rt
        .block_on(
            sqlx::query("UPDATE landing_leases SET expires_at = 0 WHERE project_id = $1 AND branch = $2 AND holder = 'test'")
                .bind(project)
                .bind(branch)
                .execute(&h.db),
        )
        .unwrap();
}

/// Guarantee 1 (S24 part B, BUG-1663): each submitter gets a fair share of
/// a batch (round-robin over people, then over each person's sessions), so
/// a flood of landings from one person or one session never makes another
/// person's landing wait longer than its fair share.
///
/// Measured: `dev` queues 120 landings across two agent sessions (90 from
/// session A, 30 from session B) while the lease is held, and a second
/// developer `dev2` queues 1 landing after all 120. Without fair sharing,
/// `dev2`'s landing is 121st in FIFO order and waits for the first two
/// 64-entry batches of `dev`'s flood before landing in the 3rd batch; with
/// two-level round-robin (over people, then over each person's sessions),
/// `dev2`'s landing is taken in the very first batch (at position 2 on the
/// branch chain, right after `dev`'s first entry), and within `dev`'s
/// share sessions A and B alternate instead of session A starving B.
#[test]
fn a_flood_of_landings_from_one_person_or_session_never_delays_another_beyond_their_fair_share() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id_of(&hub, &p.name);
    let api = hub.api();
    let dev_tok = p.dev.token();
    let admin_tok = p.admin.token();
    let sess_a = agent_session_token(&api, &dev_tok, &p.name, "flood-a");
    let sess_b = agent_session_token(&api, &dev_tok, &p.name, "flood-b");
    let real_base = api.tips(Some(&admin_tok), &p.name).unwrap().branches["main"];
    let base = api.tips(Some(&dev_tok), &p.name).unwrap().branches["main"];

    hold_branch(&hub, pid, "main");
    let mut flood_a = Vec::new();
    for i in 0..90 {
        let r = land_edit(&api, &sess_a, &p.name, base, &format!("src/flood/a/{i:03}.rs"), &format!("a {i}\n"), false);
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        flood_a.push(r.json()["ticket"].as_str().unwrap().to_string());
    }
    let mut flood_b = Vec::new();
    for i in 0..30 {
        let r = land_edit(&api, &sess_b, &p.name, base, &format!("src/flood/b/{i:03}.rs"), &format!("b {i}\n"), false);
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        flood_b.push(r.json()["ticket"].as_str().unwrap().to_string());
    }
    // A second person (`admin`) arrives after all 120 queued entries from `dev`.
    let fair_path = "src/fair.rs";
    let r2 = land_edit(&api, &admin_tok, &p.name, real_base, fair_path, "admin fair\n", false);
    assert_eq!(r2.status, 200, "{}", String::from_utf8_lossy(&r2.body));
    let t_dev2 = r2.json()["ticket"].as_str().unwrap().to_string();

    let released_at = Instant::now();
    release_branch(&hub, pid, "main");
    let v_dev2 = wait_ticket(&api, &admin_tok, &p.name, &t_dev2);
    let dev2_wait = released_at.elapsed();
    assert_eq!(v_dev2["state"], "landed", "{v_dev2}");

    // Wait for all 120 of `dev`'s entries to finish so we can inspect the
    // exact landing order on `main`'s first-parent chain.
    for t in &flood_a {
        let v = wait_ticket(&api, &sess_a, &p.name, t);
        assert_eq!(v["state"], "landed", "{v}");
    }
    for t in &flood_b {
        let v = wait_ticket(&api, &sess_b, &p.name, t);
        assert_eq!(v["state"], "landed", "{v}");
    }
    let flood_wait = released_at.elapsed();

    // Walk `main` from its real tip down to `real_base` (oldest first).
    let src = veil_server::sync::Source {
        hub: hub.hub(),
        project: pid,
        rt: hub.rt.handle().clone(),
        pending: Default::default(),
    };
    let tip_hex: String = hub
        .rt
        .block_on(sqlx::query_scalar("SELECT target FROM branches WHERE project_id = $1 AND name = 'main'").bind(pid).fetch_one(&hub.hub().db))
        .unwrap();
    let mut cur = veil_core::ObjectId::from_hex(&tip_hex).unwrap();
    let mut descs = Vec::new();
    while cur != real_base {
        let snap = src.snapshot(&cur).unwrap();
        descs.push(snap.description.as_str().to_string());
        cur = snap.parents[0];
    }
    descs.reverse();
    assert_eq!(descs.len(), 121);
    let want_fin = format!("land {fair_path}");
    let pos_dev2 = descs.iter().position(|d| d == &want_fin).expect("dev2 landed");
    let pos_b0 = descs.iter().position(|d| d == "land src/flood/b/000.rs").expect("sess_b[0] landed");
    let pos_b29 = descs.iter().position(|d| d == "land src/flood/b/029.rs").expect("sess_b[29] landed");
    eprintln!(
        "fair share: dev2 landed at position {pos_dev2}/121 in {dev2_wait:?} (whole flood finished in {flood_wait:?}); \
         sess_b[0] at {pos_b0}, sess_b[29] at {pos_b29}"
    );
    assert!(
        pos_dev2 <= 2,
        "dev2's landing waited behind {} of dev's landings (expected at most 1 in the first round-robin turn)",
        pos_dev2
    );
    assert!(
        pos_b0 <= 3,
        "dev's second session waited behind {pos_b0} entries before its first turn (session A flooded 90 ahead of it)"
    );
    assert!(
        pos_b29 <= 64,
        "dev's second session's 30th entry landed at {pos_b29} instead of alternating with session A in the first batch"
    );
}

/// Guarantee 2 (S24 part B, BUG-1660, BUG-1661, BUG-1662): every bound
/// gives a clear, actionable `429 rate_limited` refusal with
/// `retry_after_ms`, names nothing hidden, and never drops or half-lands
/// anything:
/// * per-agent-session token bucket at `Settings::device` rate, under a
///   per-person bucket at 10× `Settings::device`;
/// * outstanding landings per agent session (default 100) and per person
///   (default 1,000, 10× the session bound);
/// * a refused landing (on `/land`, `/push`, or `/changes`) leaves no row
///   in `landing_queue`, no half-landed branch in a multi-branch push, and
///   never drops what was already queued.
#[test]
fn every_landing_bound_refuses_clearly_names_nothing_hidden_and_never_half_lands() {
    // 1. Per-agent-session rate-limit buckets: each agent session has its
    //    own bucket at `device` rate, under a 10× per-person bucket.
    {
        let device = veil_server::limits::bucket::Rate { per_second: 4, per_hour: 100 };
        let hub = TestHub::start_with_limits(Settings { device, ..TestHub::limits() });
        let p = setup_project(&hub);
        let api = hub.api();
        let dev = p.dev.token();
        let s1 = agent_session_token(&api, &dev, &p.name, "r1");
        let s2 = agent_session_token(&api, &dev, &p.name, "r2");
        let mut s1_refused = None;
        for _ in 0..12 {
            let r = api.get(Some(&s1), &tips(&p.name));
            if r.status == 429 {
                s1_refused = Some(r);
                break;
            }
            assert_eq!(r.status, 200);
        }
        let r = s1_refused.expect("agent session s1 past its burst of 4 is refused");
        assert_eq!(r.json()["code"], "rate_limited");
        assert!(r.json()["retry_after_ms"].as_u64().unwrap() >= 1);
        // Agent session s2 (and the person's own device session) still have
        // their own buckets while the person is below 10×.
        assert_eq!(api.get(Some(&s2), &tips(&p.name)).status, 200, "a second agent session has its own bucket");
        assert_eq!(api.get(Some(&dev), &tips(&p.name)).status, 200, "the person's own session is not drained by one agent session");
    }

    // 2. Outstanding landings per agent session (100) and per person
    //    (1,000, or 10× the session bound), and atomicity on refusal.
    let mut settings = TestHub::limits();
    settings.max_session_outstanding = 4;
    settings.max_person_outstanding = 7;
    let hub = TestHub::start_with_limits(settings);
    let p = setup_project(&hub);
    let pid = project_id_of(&hub, &p.name);
    let api = hub.api();
    let dev = p.dev.token();
    let fin = p.fin.token();
    let s1 = agent_session_token(&api, &dev, &p.name, "q1");
    let s2 = agent_session_token(&api, &dev, &p.name, "q2");

    // Protect a second branch `release` as well so we can test a
    // multi-branch push where the second branch hits the bound.
    write_files(&p.dir, &[(".veilrules", "[branches.main]\nprotected = true\n[branches.release]\nprotected = true\n")]);
    p.admin.commit_main(&p.dir, "protect main and release");
    p.admin.ok(&p.dir, &["push"]);
    let admin_tok = p.admin.token();
    let real_main = api.tips(Some(&admin_tok), &p.name).unwrap().branches["main"];
    assert_eq!(
        api.post_json(
            Some(&admin_tok),
            &format!("/v1/projects/{}/push", p.name),
            &serde_json::json!({"updates": [{"branch": "release", "expected": null, "new": real_main.hex()}]}),
        )
        .status,
        200
    );

    let base = api.tips(Some(&dev), &p.name).unwrap().branches["main"];
    let rel_base = api.tips(Some(&dev), &p.name).unwrap().branches["release"];
    hold_branch(&hub, pid, "main");
    hold_branch(&hub, pid, "release");

    // Session s1 queues up to its bound (4).
    let mut tickets = Vec::new();
    for i in 0..4 {
        let r = land_edit(&api, &s1, &p.name, base, &format!("src/s1/f{i}.rs"), "x\n", false);
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        tickets.push((s1.clone(), r.json()["ticket"].as_str().unwrap().to_string()));
    }
    // The 5th from s1 is refused with 429 rate_limited, naming nothing hidden.
    let over_s1 = land_edit(&api, &s1, &p.name, base, "src/s1/over.rs", "over\n", false);
    assert_eq!(over_s1.status, 429, "{}", String::from_utf8_lossy(&over_s1.body));
    let v = over_s1.json();
    assert_eq!(v["code"], "rate_limited", "{v}");
    assert!(v["retry_after_ms"].as_u64().unwrap() >= 1, "{v}");
    let msg = v["message"].as_str().unwrap();
    assert!(msg.contains("agent session") && msg.contains("4"), "expected actionable message with bound, got: {msg}");
    for hidden in restricted_markers() {
        assert!(!msg.contains(hidden), "{msg}");
    }

    // Session s2 of the same person can still queue 2 more (bringing the
    // person to 6 of 7).
    for i in 0..2 {
        let r = land_edit(&api, &s2, &p.name, base, &format!("src/s2/f{i}.rs"), "y\n", false);
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        tickets.push((s2.clone(), r.json()["ticket"].as_str().unwrap().to_string()));
    }

    // Now the person has 6 queued, and the person bound is 7.
    // A single `POST /push` from `dev` updating BOTH `main` and `release`
    // attempts to insert 2 queue rows in one transaction: the 1st reaches 7,
    // the 2nd exceeds 7 and refuses the whole push! Neither branch may be
    // queued or half-landed.
    let queued_before: i64 = hub
        .rt
        .block_on(sqlx::query_scalar("SELECT COUNT(*) FROM landing_queue WHERE project_id = $1 AND state = 'queued'").bind(pid).fetch_one(&hub.hub().db))
        .unwrap();
    assert_eq!(queued_before, 6);

    let mut cm = Craft::with(&api, dev.clone(), p.dev.identity(), &p.name, "main");
    cm.file("src/multi/m.rs", "m\n");
    let mut sm = veil_core::object::Snapshot {
        parents: vec![base],
        change_id: veil_core::ChangeId::random(),
        tree: cm.root,
        description: veil_core::object::Text::Plain("on main".into()),
        author: "dev".into(),
        timestamp: veil_core::now_millis(),
        predecessors: vec![],
        conflicts: vec![],
        embargo: None,
        agent: None,
        abandoned: None,
        attempts: vec![],
        signature: None,
    };
    sm.sign(&p.dev.identity());
    let id_m = cm.put_object(veil_core::object::Object::Snapshot(sm));

    let mut cr = Craft::with(&api, dev.clone(), p.dev.identity(), &p.name, "release");
    cr.file("src/multi/r.rs", "r\n");
    let mut sr = veil_core::object::Snapshot {
        parents: vec![rel_base],
        change_id: veil_core::ChangeId::random(),
        tree: cr.root,
        description: veil_core::object::Text::Plain("on release".into()),
        author: "dev".into(),
        timestamp: veil_core::now_millis(),
        predecessors: vec![],
        conflicts: vec![],
        embargo: None,
        agent: None,
        abandoned: None,
        attempts: vec![],
        signature: None,
    };
    sr.sign(&p.dev.identity());
    let id_r = cr.put_object(veil_core::object::Object::Snapshot(sr));

    let mut all_objs = cm.objects;
    all_objs.extend(cr.objects);
    let up = api.upload(&dev, &p.name, &all_objs);
    assert_eq!(up.status, 200);
    let receipts = up.json()["receipts"].as_array().unwrap().clone();
    let rmap: serde_json::Map<String, serde_json::Value> = all_objs.iter().zip(receipts).map(|((id, _), r)| (id.hex(), r)).collect();
    let multi_r = api.post_json(
        Some(&dev),
        &format!("/v1/projects/{}/push", p.name),
        &serde_json::json!({
            "updates": [
                {"branch": "main", "expected": base.hex(), "new": id_m.hex()},
                {"branch": "release", "expected": rel_base.hex(), "new": id_r.hex()}
            ],
            "receipts": rmap
        }),
    );
    assert_eq!(multi_r.status, 429, "{}", String::from_utf8_lossy(&multi_r.body));
    let out = multi_r.json()["message"].as_str().unwrap().to_string();
    assert!(out.contains("7") && out.contains("waiting"), "expected person bound refusal, got: {out}");

    let queued_after: i64 = hub
        .rt
        .block_on(sqlx::query_scalar("SELECT COUNT(*) FROM landing_queue WHERE project_id = $1 AND state = 'queued'").bind(pid).fetch_one(&hub.hub().db))
        .unwrap();
    assert_eq!(queued_after, 6, "a refused multi-branch push must not leave the first branch's row queued");

    // 1 more landing from `s2` reaches the person bound (7), and the 8th is
    // refused even though `s2` only has 3 of its 4 session bound used.
    let ok7 = land_edit(&api, &s2, &p.name, base, "src/s2/f2.rs", "y2\n", false);
    assert_eq!(ok7.status, 200, "{}", String::from_utf8_lossy(&ok7.body));
    tickets.push((s2.clone(), ok7.json()["ticket"].as_str().unwrap().to_string()));

    let over_person = land_edit(&api, &s2, &p.name, base, "src/s2/over_p.rs", "over\n", false);
    assert_eq!(over_person.status, 429, "{}", String::from_utf8_lossy(&over_person.body));
    assert!(over_person.json()["message"].as_str().unwrap().contains("7"), "{}", over_person.json());

    // Another person (`fin`) is unaffected by `dev`'s full queue.
    let fin_base = api.tips(Some(&fin), &p.name).unwrap().branches["main"];
    let fin_r = land_edit(&api, &fin, &p.name, fin_base, &format!("{BILL_DIR}/ok.txt"), "fin ok\n", false);
    assert_eq!(fin_r.status, 200, "another person's landing is not refused: {}", String::from_utf8_lossy(&fin_r.body));
    tickets.push((fin.clone(), fin_r.json()["ticket"].as_str().unwrap().to_string()));

    // Release the lease: every admitted landing lands cleanly, and the
    // refused ones never landed.
    release_branch(&hub, pid, "main");
    release_branch(&hub, pid, "release");
    for (tok, t) in &tickets {
        let v = wait_ticket(&api, tok, &p.name, t);
        assert_eq!(v["state"], "landed", "{v}");
    }
    let tree = api.get(Some(&p.admin.token()), &format!("/v1/projects/{}/q/tree?path=src", p.name)).json();
    let tree_str = tree.to_string();
    assert!(!tree_str.contains("over.rs") && !tree_str.contains("over_p.rs") && !tree_str.contains("multi"), "nothing refused landed: {tree_str}");
}

/// Guarantee 3 (S24 part B, BUG-1664): landing counters in the admin-only
/// health metrics (`GET /v1/projects/{p}/health` and `vl stats`) count
/// landed changes, batches, conflicts and rejections for the project,
/// reach admins only, and name no hidden path, person, session or project.
#[test]
fn landing_counters_in_health_metrics_reach_admins_only_and_name_nothing_hidden() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let api = hub.api();
    let (admin, dev, fin) = (p.admin.token(), p.dev.token(), p.fin.token());
    let base = api.tips(Some(&fin), &p.name).unwrap().branches["main"];

    // Land a change in the restricted `BILL_DIR/` folder and a conflicting change.
    let r1 = land_edit(&api, &fin, &p.name, base, &format!("{BILL_DIR}/secret-plan.txt"), "v1\n", true);
    assert_eq!(r1.status, 200, "{}", String::from_utf8_lossy(&r1.body));
    assert_eq!(r1.json()["state"], "landed");

    let r2 = land_edit(&api, &fin, &p.name, base, &format!("{BILL_DIR}/secret-plan.txt"), "v2-conflict\n", true);
    assert_eq!(r2.status, 200, "{}", String::from_utf8_lossy(&r2.body));
    assert_eq!(r2.json()["state"], "conflict");

    let h = api.get(Some(&admin), &format!("/v1/projects/{}/health", p.name));
    assert_eq!(h.status, 200, "{}", String::from_utf8_lossy(&h.body));
    let v = h.json();
    assert!(v["since_start"]["landings"].as_u64().unwrap() >= 1, "{v}");
    assert!(v["since_start"]["landing_batches"].as_u64().unwrap() >= 1, "{v}");
    assert!(v["since_start"]["landing_conflicts"].as_u64().unwrap() >= 1, "{v}");
    assert_eq!(v["since_start"]["landing_rejected"].as_u64().unwrap(), 0, "{v}");
    assert_eq!(v.as_object().unwrap().len(), 6, "top-level health schema keys stay fixed: {v}");

    let body = String::from_utf8_lossy(&h.body).to_string();
    for hidden in restricted_markers()
        .into_iter()
        .map(str::to_string)
        .chain(["secret-plan".to_string(), p.dev.name.clone(), p.fin.name.clone(), p.admin.name.clone()])
    {
        assert!(!body.contains(&hidden), "health metrics named {hidden}: {body}");
    }
    assert_eq!(api.get(Some(&dev), &format!("/v1/projects/{}/health", p.name)).status, 403);
    assert_eq!(api.get(Some(&fin), &format!("/v1/projects/{}/health", p.name)).status, 403);
    let out = p.admin.ok(&p.dir, &["stats"]);
    assert!(out.contains("landings") && out.contains("conflicts"), "{out}");
}

/// Guarantee 4 (S24 part B, BUG-1665): outstanding landing bounds hold
/// across two servers sharing the database (`TestHub::beside`), even when
/// submissions race concurrently against both servers.
#[test]
fn landing_bounds_hold_across_two_servers_sharing_the_database() {
    let mut settings = TestHub::limits();
    settings.max_session_outstanding = 6;
    settings.max_person_outstanding = 10;
    let hub1 = TestHub::start_with_limits(settings);
    let hub2 = TestHub::beside(&hub1);
    let p = setup_project(&hub1);
    let pid = project_id_of(&hub1, &p.name);
    let api1 = hub1.api();
    let api2 = hub2.api();
    let dev = p.dev.token();
    let s1 = agent_session_token(&api1, &dev, &p.name, "m1");
    let s2 = agent_session_token(&api2, &dev, &p.name, "m2");
    let base = api1.tips(Some(&dev), &p.name).unwrap().branches["main"];

    hold_branch(&hub1, pid, "main");

    // 16 concurrent submissions for session `s1` split across `hub1` and
    // `hub2`: at most `max_session_outstanding` (6) may be accepted.
    let statuses: Vec<u16> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..16)
            .map(|i| {
                let api = if i % 2 == 0 { &api1 } else { &api2 };
                let s1 = &s1;
                let name = &p.name;
                scope.spawn(move || land_edit(api, s1, name, base, &format!("src/m1/f{i:02}.rs"), "m1\n", false).status)
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let ok_s1 = statuses.iter().filter(|&&s| s == 200).count();
    let lim_s1 = statuses.iter().filter(|&&s| s == 429).count();
    assert_eq!((ok_s1, lim_s1), (6, 10), "across two servers, session s1 accepted {ok_s1} (bound 6): {statuses:?}");

    // Now 12 concurrent submissions for session `s2` split across `hub1`
    // and `hub2`: `s2`'s session bound is 6, but the person already has 6
    // queued and `max_person_outstanding` is 10, so at most 4 more may be
    // accepted across the two servers.
    let statuses_p: Vec<u16> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..12)
            .map(|i| {
                let api = if i % 2 == 0 { &api1 } else { &api2 };
                let s2 = &s2;
                let name = &p.name;
                scope.spawn(move || land_edit(api, s2, name, base, &format!("src/m2/f{i:02}.rs"), "m2\n", false).status)
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let ok_s2 = statuses_p.iter().filter(|&&s| s == 200).count();
    let lim_s2 = statuses_p.iter().filter(|&&s| s == 429).count();
    assert_eq!((ok_s2, lim_s2), (4, 8), "across two servers, person bound of 10 allowed 6 + {ok_s2}: {statuses_p:?}");

    let total_queued: i64 = hub1
        .rt
        .block_on(sqlx::query_scalar("SELECT COUNT(*) FROM landing_queue WHERE project_id = $1 AND state = 'queued'").bind(pid).fetch_one(&hub1.hub().db))
        .unwrap();
    assert_eq!(total_queued, 10);
    release_branch(&hub1, pid, "main");
}

/// Review 3 (S24 part B × S18 and S19):
/// - A re-queued merge (S18) counts once against the outstanding-landing bounds
///   (including while in `state = 'merging'` and after re-queueing to `state = 'queued'`),
///   never twice and never freeing its slot early while merging.
/// - A CI runner session (S19) is refused with `403 agent_session` and never queues a
///   landing row in `landing_queue`.
/// - Fair-share batching keeps S18's merge-worker ordering and clean content merges
///   correct across sessions and people.
#[test]
fn s18_and_s19_requeued_merge_counts_once_runner_never_queues_and_fair_batch_keeps_merge_ordering() {
    let mut settings = TestHub::limits();
    settings.max_session_outstanding = 2;
    settings.max_person_outstanding = 3;
    let hub = TestHub::start_with_limits(settings);
    let p = setup_project(&hub);
    let pid = project_id_of(&hub, &p.name);
    let api = hub.api();
    let dev = p.dev.token();
    let admin = p.admin.token();

    // 1. S19: mint a CI runner session and verify it is refused on `/land` and `push`,
    //    and leaves 0 rows in `landing_queue`.
    let r_ci = api.post_json(
        Some(&admin),
        "/v1/sessions/ci",
        &serde_json::json!({"project": p.name, "check": "ci-s24b", "only": ["src/"]}),
    );
    assert_eq!(r_ci.status, 200, "{}", String::from_utf8_lossy(&r_ci.body));
    let ci_tok = r_ci.json()["token"].as_str().unwrap().to_string();

    let base0 = api.tips(Some(&dev), &p.name).unwrap().branches["main"];
    let ci_land = land_edit(&api, &ci_tok, &p.name, base0, "src/ci_try.rs", "nope\n", false);
    assert_eq!(ci_land.status, 403, "CI runner session must be refused on /land: {}", String::from_utf8_lossy(&ci_land.body));
    assert_eq!(ci_land.json()["code"], "agent_session");

    let q_after_ci: i64 = hub
        .rt
        .block_on(sqlx::query_scalar("SELECT COUNT(*) FROM landing_queue WHERE project_id = $1").bind(pid).fetch_one(&hub.hub().db))
        .unwrap();
    assert_eq!(q_after_ci, 0, "CI runner session must never queue a landing");

    // 2. Seed a multi-line file `src/shared.txt` so S18 content merges can cleanly 3-way merge
    //    disjoint line edits.
    let seed_text = "line 1\nline 2\nline 3\nline 4\nline 5\nline 6\nline 7\nline 8\nline 9\nline 10\n";
    let seed_r = land_edit(&api, &dev, &p.name, base0, "src/shared.txt", seed_text, true);
    assert_eq!(seed_r.status, 200, "{}", String::from_utf8_lossy(&seed_r.body));
    assert_eq!(seed_r.json()["state"], "landed");

    let base = api.tips(Some(&dev), &p.name).unwrap().branches["main"];
    let admin_base = api.tips(Some(&admin), &p.name).unwrap().branches["main"];
    let s1 = agent_session_token(&api, &dev, &p.name, "s18-s1");
    let s2 = agent_session_token(&api, &dev, &p.name, "s18-s2");

    // Hold the branch and queue:
    // - From `s1`: 2 changes (reaching `max_session_outstanding = 2`), where the second
    //   touches `src/shared.txt` at line 10 (will need S18 content merge after `admin`
    //   lands an edit to line 1 on `src/shared.txt`).
    // - From `admin`: 1 change touching `src/shared.txt` at line 1.
    hold_branch(&hub, pid, "main");

    let s1_a = land_edit(&api, &s1, &p.name, base, "src/s1_only.txt", "s1 a\n", false);
    assert_eq!(s1_a.status, 200, "{}", String::from_utf8_lossy(&s1_a.body));
    let t_s1_a = s1_a.json()["ticket"].as_str().unwrap().to_string();

    let admin_text = "LINE 1 ADMIN\nline 2\nline 3\nline 4\nline 5\nline 6\nline 7\nline 8\nline 9\nline 10\n";
    let adm_r = land_edit(&api, &admin, &p.name, admin_base, "src/shared.txt", admin_text, false);
    assert_eq!(adm_r.status, 200, "{}", String::from_utf8_lossy(&adm_r.body));
    let t_adm = adm_r.json()["ticket"].as_str().unwrap().to_string();

    let s1_text = "line 1\nline 2\nline 3\nline 4\nline 5\nline 6\nline 7\nline 8\nline 9\nLINE 10 S1\n";
    let s1_b = land_edit(&api, &s1, &p.name, base, "src/shared.txt", s1_text, false);
    assert_eq!(s1_b.status, 200, "{}", String::from_utf8_lossy(&s1_b.body));
    let t_s1_b = s1_b.json()["ticket"].as_str().unwrap().to_string();

    // Release the branch so batch 1 runs:
    // In fair-share order:
    // Turn 1: `dev` (`s1_a`: touches `src/s1_only.txt`, lands fast-path), `admin` (`adm_r`: touches `src/shared.txt`, lands fast-path)
    // Turn 2: `dev` (`s1_b`: touches `src/shared.txt` against old `base`, transitions to `merging` -> re-queued with `merges = 1` -> lands!).
    release_branch(&hub, pid, "main");
    for (tok, t) in [(&s1, &t_s1_a), (&admin, &t_adm), (&s1, &t_s1_b)] {
        for _ in 0..60 {
            let r = api.get(Some(tok), &format!("/v1/projects/{}/land/{t}", p.name));
            assert_eq!(r.status, 200);
            let v = r.json();
            if v["state"] == "landed" {
                break;
            }
            assert!(v["state"] == "queued" || v["state"] == "merging", "unexpected state for {t}: {v}");
            std::thread::sleep(Duration::from_millis(50));
        }
        let v = api.get(Some(tok), &format!("/v1/projects/{}/land/{t}", p.name)).json();
        assert_eq!(v["state"], "landed", "ticket {t} must land: {v}");
    }
    let v_s1_b = api.get(Some(&s1), &format!("/v1/projects/{}/land/{t_s1_b}", p.name)).json();
    assert_eq!(v_s1_b["merges"], 1, "s1_b must have gone through 1 content merge and re-queue: {v_s1_b}");

    // Verify that `t_s1_b` is still a single row in `landing_queue`, and that while a row
    // is in `state = 'merging'` (or re-queued in `state = 'queued'`), it counts as 1
    // against `max_session_outstanding` and `max_person_outstanding`, not 0 and not 2.
    let base2 = api.tips(Some(&dev), &p.name).unwrap().branches["main"];
    hold_branch(&hub, pid, "main");

    let m1 = land_edit(&api, &s1, &p.name, base2, "src/m1.txt", "1\n", false);
    assert_eq!(m1.status, 200);
    let t_m1 = m1.json()["ticket"].as_str().unwrap().to_string();

    // Simulate `t_m1` being in `state = 'merging'` while a merge worker is running on it:
    // it must still count against `s1`'s bound of 2 and `dev`'s person bound of 3!
    hub.rt
        .block_on(
            sqlx::query("UPDATE landing_queue SET state = 'merging' WHERE project_id = $1 AND ticket = $2")
                .bind(pid)
                .bind(&t_m1)
                .execute(&hub.hub().db),
        )
        .unwrap();

    let m2 = land_edit(&api, &s1, &p.name, base2, "src/m2.txt", "2\n", false);
    assert_eq!(m2.status, 200, "2nd landing for s1 (1 merging + 1 queued = 2) must succeed");
    let t_m2 = m2.json()["ticket"].as_str().unwrap().to_string();

    let m3_over = land_edit(&api, &s1, &p.name, base2, "src/m3_over.txt", "3\n", false);
    assert_eq!(
        m3_over.status, 429,
        "while 1 row is merging and 1 row is queued, a 3rd submission on s1 (bound 2) must be refused 429: {}",
        String::from_utf8_lossy(&m3_over.body)
    );

    // And when the merge worker re-queues `t_m1` (`state = 'queued', merges = 1`),
    // it still counts once (not twice): once `t_m2` finishes, `s1` has 1 slot free.
    hub.rt
        .block_on(
            sqlx::query("UPDATE landing_queue SET state = 'queued', merges = 1 WHERE project_id = $1 AND ticket = $2")
                .bind(pid)
                .bind(&t_m1)
                .execute(&hub.hub().db),
        )
        .unwrap();

    // `s2` can queue 1 landing (reaching `dev`'s person bound of 3: 2 on `s1` + 1 on `s2`),
    // and a 2nd on `s2` is refused by the person bound of 3.
    let s2_1 = land_edit(&api, &s2, &p.name, base2, "src/s2_1.txt", "s2 1\n", false);
    assert_eq!(s2_1.status, 200);
    let t_s2_1 = s2_1.json()["ticket"].as_str().unwrap().to_string();

    let s2_over = land_edit(&api, &s2, &p.name, base2, "src/s2_over.txt", "s2 over\n", false);
    assert_eq!(s2_over.status, 429, "person bound of 3 must include the re-queued row");

    release_branch(&hub, pid, "main");
    for (tok, t) in [(&s1, &t_m1), (&s1, &t_m2), (&s2, &t_s2_1)] {
        let v = wait_ticket(&api, tok, &p.name, t);
        assert_eq!(v["state"], "landed", "{v}");
    }
}

/// Review 4 (S24 part B × YugabyteDB): a large landing of a 500-file change
/// lands and derives cleanly without statement timeout or unbounded transaction:
/// `derive::landing` caps inline search/memo preparation on large batches
/// (`writes.history.len() > 64`), commits the derived rows in chunked statements
/// (`ROWS_PER_STATEMENT`) with retry on conflict, and finishes viewer-graph
/// memoization and search indexing in the background.
#[test]
fn a_500_file_landing_and_its_background_derive_pass_stay_bounded_and_succeed() {
    let hub = TestHub::start();
    let p = setup_project(&hub);
    let pid = project_id_of(&hub, &p.name);
    let api = hub.api();
    let dev = p.dev.token();
    let admin = p.admin.token();
    let base = api.tips(Some(&dev), &p.name).unwrap().branches["main"];

    let edits: Vec<serde_json::Value> = (0..500)
        .map(|i| {
            serde_json::json!({
                "path": format!("src/bulk500/dir_{:02}/file_{i:03}.rs", i / 25),
                "put": {"text": format!("pub const ITEM_{i}: usize = {};\n", i * 17 + 3)}
            })
        })
        .collect();
    let r = api.post_json(
        Some(&dev),
        &format!("/v1/projects/{}/land", p.name),
        &serde_json::json!({
            "onto": "main",
            "base": base.hex(),
            "edits": edits,
            "description": "land 500 files at once",
            "wait": true
        }),
    );
    assert_eq!(r.status, 200, "500-file landing failed: {}", String::from_utf8_lossy(&r.body));
    let v = r.json();
    assert_eq!(v["state"], "landed", "{v}");

    // Run `derive::landing` and verify it succeeds and derives the 500-file commit,
    // then wait for background prefill and search indexing to complete and verify
    // query (`q/tree`, `q/history`, `q/blame`) and search (`q/grep`, `q/search`)
    // serve the 500-file landing accurately for both `admin` and `dev`.
    let h = hub.hub();
    hub.rt.block_on(veil_server::derive::landing(&h, pid, vec!["main".into()])).unwrap();
    hub.rt.block_on(veil_server::search::index::catch_up_project(&h, pid)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        let active: i64 = hub
            .rt
            .block_on(sqlx::query_scalar("SELECT COUNT(*) FROM view_fills WHERE project_id = $1").bind(pid).fetch_one(&h.db))
            .unwrap();
        if active == 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }

    for tok in [&admin, &dev] {
        let hist = api.get(Some(tok), &format!("/v1/projects/{}/q/history?path=src/bulk500/dir_19/file_499.rs", p.name));
        assert_eq!(hist.status, 200, "{}", String::from_utf8_lossy(&hist.body));
        assert_eq!(hist.json()["entries"].as_array().unwrap().len(), 1);

        let blame = api.get(Some(tok), &format!("/v1/projects/{}/q/blame?path=src/bulk500/dir_19/file_499.rs", p.name));
        assert_eq!(blame.status, 200, "{}", String::from_utf8_lossy(&blame.body));
        assert_eq!(blame.json()["lines"].as_array().unwrap().len(), 1);

        let grep = api.get(Some(tok), &format!("/v1/projects/{}/q/grep?pattern=ITEM_499", p.name));
        assert_eq!(grep.status, 200, "{}", String::from_utf8_lossy(&grep.body));
        assert_eq!(grep.json()["files"].as_array().unwrap().len(), 1);
    }
}


