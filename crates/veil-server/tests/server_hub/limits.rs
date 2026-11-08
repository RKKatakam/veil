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
    assert!(held.0 <= 48 << 10 && held.1 <= 16 << 10, "{held:?} KiB held, past the 64 MiB budget");
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
#[ignore = "BUG-1339: the default device rate refuses an agent fleet of one device (about 18 requests a commit-push-pull)"]
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
#[test]
#[ignore = "BUG-1333: a few slow bodies hold a whole pool of the request budget: every other body on the server is refused busy"]
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
    assert_eq!(held.0, 48 << 10, "the upload holds the whole signed-in pool: {held:?} KiB");
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
#[test]
#[ignore = "BUG-1333: a few slow bodies hold a whole pool of the request budget: every other body on the server is refused busy"]
fn bug_1333_four_addresses_holding_bodies_refuse_every_sign_in() {
    use std::io::Write;
    let hub = TestHub::start();
    let server: std::net::SocketAddr = hub.authority().parse().unwrap();
    let quarter = hub.hub().limits.bodies.anonymous_limit();
    let held: Vec<_> = (2..=5)
        .map(|i| {
            let mut s = raw::tls(raw::tcp(format!("127.0.0.{i}").parse().unwrap(), server));
            write!(s, "POST /v1/auth/challenge HTTP/1.1\r\nhost: veil\r\ncontent-type: application/json\r\ncontent-length: {quarter}\r\n\r\n").unwrap();
            s.flush().unwrap();
            s
        })
        .collect();
    let t = Instant::now();
    while u64::from(hub.hub().limits.bodies.held_kib().1) < 4 * (quarter >> 10) && t.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(u64::from(hub.hub().limits.bodies.held_kib().1), 4 * (quarter >> 10), "four heads hold the anonymous pool");
    let t = Instant::now();
    let r = challenge(&hub.api());
    let took = t.elapsed();
    drop(held);
    assert_eq!(r.status, 200, "a sign-in from another address, after {took:?}: {}", String::from_utf8_lossy(&r.body));
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
#[ignore = "BUG-1334: a busy private project's gate tells an outsider it exists (503 after a wait instead of 404)"]
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
#[ignore = "BUG-1335: a project named in percent-encoded spellings gets a gate per spelling and runs past its bulkhead"]
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
#[ignore = "BUG-1336: the per-address connection share counts each IPv6 address, not its /64"]
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
#[ignore = "BUG-1337: an idle HTTP/2 connection that answers pings keeps its connection slot for ever"]
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
#[ignore = "BUG-1338: a known person's first request to a server that has not cached their session is charged to their address"]
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
