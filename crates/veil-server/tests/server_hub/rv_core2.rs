//! Whole-codebase review, 2026-11-11, `rv-core2`: request budgets (BUG-1882).

use std::{
    sync::{
        atomic::Ordering,
        Arc,
    },
    time::{Duration, Instant},
};

use serde_json::json;
use veil_core::ObjectId;

use crate::support::*;

struct Stalls {
    left: usize,
    gate: std::sync::mpsc::Receiver<()>,
    sent: Arc<std::sync::atomic::AtomicUsize>,
}

impl std::io::Read for Stalls {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.left == 0 {
            let _ = self.gate.recv();
            return Err(std::io::Error::other("the client went away"));
        }
        let n = buf.len().min(self.left).min(64 << 10);
        buf[..n].fill(b' ');
        self.left -= n;
        self.sent.fetch_add(n, Ordering::Relaxed);
        Ok(n)
    }
}

/// Five sessions of one person, each sending 4 MiB of an upload slowly,
/// hold at most that person's quarter of the signed-in pool, and everyone
/// else's upload succeeds.
#[test]
fn bug_1882_one_persons_agent_sessions_take_the_whole_signed_in_body_pool() {
    use veil_server::limits::Settings;
    let hub = TestHub::start_with_limits(Settings { request_memory: 64 << 20, ..TestHub::limits() });
    let api = hub.api();
    let sign_up = |prefix: &str| api.login(&veil_core::Identity::generate("rv-core2"), Some(&unique(prefix))).expect("signs up");
    let project = |token: &str| {
        let name = unique("rvlim");
        let r = api.post(Some(token), &format!("/v1/projects/{name}"), b"", false);
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        name
    };
    let (mallory, victim) = (sign_up("rvmal"), sign_up("rvvic"));
    let (pm, pv) = (project(&mallory), project(&victim));
    let sessions: Vec<String> = (0..5)
        .map(|i| {
            let r = api.post_json(
                Some(&mallory),
                "/v1/sessions/agent",
                &json!({"project": pm, "attribution": {"agent": "rv-core2/1", "task": format!("BUG-1882-{i}")}}),
            );
            assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
            r.json()["token"].as_str().unwrap().to_string()
        })
        .collect();
    // A 2 MiB blob that does not compress: an upload past the small bodies' reserve.
    let blob = |seed: u64| {
        let mut x = seed | 1;
        let bytes: Vec<u8> = (0..2usize << 20)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect();
        let raw = veil_core::object::Object::Blob(bytes).encode();
        (ObjectId::hash(&raw), raw)
    };
    let h = hub.hub();
    let signed_in_kib = || h.limits.bodies.held_kib().0;
    // Each token in turn sends 4 MiB of an upload of unknown length (8 MiB held), and stops.
    let stall = |tokens: &[String]| {
        let mut gates = Vec::new();
        let mut threads = Vec::new();
        for t in tokens {
            let sent = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let (tx, gate) = std::sync::mpsc::channel::<()>();
            let (api, sent2, token, path) = (hub.api(), sent.clone(), t.clone(), format!("/v1/projects/{pm}/objects"));
            threads.push(std::thread::spawn(move || drop(api.post_reader_as(Some(&token), &path, Stalls { left: 4 << 20, gate, sent: sent2 }))));
            gates.push(tx);
            // Until the server took it all in, or refused it (nothing more is sent for a second).
            let t = Instant::now();
            let mut last = (0, Instant::now());
            while t.elapsed() < Duration::from_secs(60) && last.1.elapsed() < Duration::from_secs(1) {
                std::thread::sleep(Duration::from_millis(50));
                let s = sent.load(Ordering::Relaxed);
                if s != last.0 {
                    last = (s, Instant::now());
                }
            }
        }
        (gates, threads)
    };

    // One device: five such bodies, one after another, hold at most its quarter
    // (10 MiB of 40: the first is held, the others refused), and others upload.
    let (gates, threads) = stall(&vec![mallory.clone(); 5]);
    let held = signed_in_kib();
    assert!(held > 0 && held <= 10 << 10, "one device holds at most a quarter of the signed-in pool: {held} KiB");
    let r = api.upload(&victim, &pv, &[blob(1)]);
    assert_eq!(r.status, 200, "beside one device's stalled uploads: {}", String::from_utf8_lossy(&r.body));
    drop(gates);
    for t in threads {
        t.join().unwrap();
    }
    let t = Instant::now();
    while signed_in_kib() > 0 && t.elapsed() < Duration::from_secs(60) {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(signed_in_kib(), 0, "the stalled bodies were let go");

    // The same person's five agent sessions: the same five bodies.
    let (gates, threads) = stall(&sessions);
    let held = signed_in_kib();
    let r = api.upload(&victim, &pv, &[blob(2)]);
    let status = r.status;
    drop(gates);
    for t in threads {
        t.join().unwrap();
    }
    assert_eq!(
        status,
        200,
        "one person's agent sessions hold {held} KiB of the 40960 KiB signed-in pool, and another person's 2 MiB upload is refused: {}",
        String::from_utf8_lossy(&r.body)
    );
    assert!(held <= 10 << 10, "one person holds at most a quarter of the signed-in pool: {held} KiB");
}

/// BUG-1882 (answers budget): six agent sessions of one person stalling
/// unread 12 MiB answers hold at most that person's 16 MiB quarter of a
/// 64 MiB answers budget, so another person's 12 MiB read still succeeds.
#[test]
fn bug_1882_one_persons_agent_sessions_share_one_quarter_of_the_answers_budget() {
    use veil_server::limits::Settings;
    let hub = TestHub::start_with_limits(Settings { request_memory: 64 << 20, ..TestHub::limits() });
    let p = setup_project(&hub);
    let big = "x".repeat(12 << 20);
    write_files(&p.dir, &[("src/big.txt", &big)]);
    p.admin.commit_main(&p.dir, "12 MiB public file");
    p.admin.ok(&p.dir, &["push"]);

    let api = hub.api();
    let sessions: Vec<String> = (0..6)
        .map(|i| {
            let r = api.post_json(
                Some(&p.dev.token()),
                "/v1/sessions/agent",
                &json!({"project": p.name, "attribution": {"agent": "rv-core2/1", "task": format!("BUG-1882-ans-{i}")}}),
            );
            assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
            r.json()["token"].as_str().unwrap().to_string()
        })
        .collect();

    let path = format!("/v1/projects/{}/q/file?rev=main&path=src/big.txt", p.name);
    let stalled: Vec<_> = std::thread::scope(|s| {
        let asked: Vec<_> = sessions
            .iter()
            .map(|tok| {
                let api2 = hub.api();
                let auth = format!("Bearer {tok}");
                let path = path.clone();
                s.spawn(move || api2.get_unread(&path, &[("authorization", &auth)]))
            })
            .collect();
        asked.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let held = hub.hub().limits.answers.held_kib();
    let ok_count = stalled.iter().filter(|r| r.status().as_u16() == 200).count();
    let victim_r = api.get(Some(&p.admin.token()), &path);
    drop(stalled);
    assert_eq!(ok_count, 1, "one person's 6 agent sessions hold at most one 12 MiB answer in a 16 MiB quarter");
    assert!(held <= 16 << 10, "one person holds at most a quarter of the 64 MiB answers budget: {held} KiB");
    assert_eq!(victim_r.status, 200, "another person's read succeeds beside stalled agent-session answers");
}
