//! The S3 store against a store that is not ready (BUG-1953): a fake S3
//! service on a local port answers as a MinIO does while it stops (the
//! Bitnami image stops the MinIO it started for its setup about five seconds
//! after that one answers `/minio/health/live`, then starts it again): 499
//! ("client closed request", the answer MinIO gives a request whose context
//! its own shutdown cancelled), 503, or a closed connection.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use veil_core::ObjectId;
use veil_server::store::{BlobStore, Objects, S3Store, StoreUnavailable};

/// A fake S3 bucket: the first `refuse` PUTs are answered `status` (none
/// stored); after them, PUTs store and GETs read.
#[derive(Default)]
struct Fake {
    refuse: usize,
    status: u16,
    puts: AtomicUsize,
    stored: Mutex<std::collections::HashMap<String, Bytes>>,
}

async fn put(State(f): State<Arc<Fake>>, Path(key): Path<String>, body: Bytes) -> StatusCode {
    if f.puts.fetch_add(1, Ordering::SeqCst) < f.refuse {
        return StatusCode::from_u16(f.status).unwrap();
    }
    f.stored.lock().unwrap().insert(key, body);
    StatusCode::OK
}

async fn get(State(f): State<Arc<Fake>>, Path(key): Path<String>) -> Result<Bytes, StatusCode> {
    f.stored.lock().unwrap().get(&key).cloned().ok_or(StatusCode::NOT_FOUND)
}

fn fake(rt: &tokio::runtime::Runtime, refuse: usize, status: u16) -> (Arc<Fake>, S3Store) {
    let f = Arc::new(Fake { refuse, status, ..Fake::default() });
    let app = axum::Router::new()
        .route("/bucket/{*key}", axum::routing::put(put).get(get))
        .with_state(f.clone());
    let listener = rt.block_on(tokio::net::TcpListener::bind("127.0.0.1:0")).unwrap();
    let addr = listener.local_addr().unwrap();
    rt.spawn(async move { axum::serve(listener, app).await.unwrap() });
    let store = S3Store::new(&format!("http://{addr}"), "bucket", "us-east-1", "key", "secret").unwrap();
    (f, store)
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap()
}

/// A PUT answered 499 by a store that is stopping is tried again, as a 503
/// or a closed connection is, and stores the object once the store answers.
#[test]
fn bug_1953_a_put_answered_499_by_a_store_that_is_stopping_is_tried_again() {
    let rt = runtime();
    for status in [499, 503] {
        let (f, store) = fake(&rt, 3, status);
        let data = Bytes::from(vec![7u8; 165_000]);
        let put = rt.block_on(store.put("p/1/o/ab", data.clone()));
        assert!(put.is_ok(), "a PUT answered {status} three times, then 200: {put:?}");
        assert_eq!(f.puts.load(Ordering::SeqCst), 4, "{status}: three refused tries and the one that stored");
        assert_eq!(rt.block_on(store.get("p/1/o/ab")).unwrap(), Some(data), "{status}: the object as written");
    }
}

/// A store that keeps answering 499 is refused within the retry bound
/// (`S3_RETRY_FOR`, 10 s), clearly, and the object is not recorded: the
/// object cache does not serve what the store did not take.
#[test]
fn bug_1953_a_store_that_keeps_answering_499_is_refused_within_a_bound_and_nothing_is_recorded() {
    let rt = runtime();
    let (f, store) = fake(&rt, usize::MAX, 499);
    let objects = Objects::new(Arc::new(store), 1 << 20);
    let raw = axum::body::Bytes::from_static(b"veil:blob\nnot stored");
    let id = ObjectId::hash(&raw);
    let start = Instant::now();
    let err = rt.block_on(objects.put(1, &id, raw)).unwrap_err();
    let took = start.elapsed();
    assert!(format!("{err:#}").starts_with("S3 PUT answered HTTP 499 "), "{err:#}");
    assert!(veil_server::error::caused_by::<StoreUnavailable>(&err), "an unavailable store, answered `busy` by a route: {err:#}");
    assert!(took >= Duration::from_secs(5) && took < Duration::from_secs(15), "tried again within the bound: {took:?}");
    assert!(f.puts.load(Ordering::SeqCst) > 3, "tried again: {} tries", f.puts.load(Ordering::SeqCst));
    assert!(f.stored.lock().unwrap().is_empty());
    assert!(rt.block_on(objects.get(1, &id)).unwrap().is_none(), "the object a refused PUT did not store is not served");
}

/// Every `503 Slow Down` (and `429`) a store answers is counted, as is a
/// request that still fails when the retries run out: `stats.json`'s
/// `s3_slow_down` and `s3_gave_up`, which the `spaces` gate of the
/// deployment kit records against DigitalOcean Spaces' rate limit
/// (BUG-2290). The counters are the process's, so other tests can only
/// add to them: each is held to at least what this test caused.
#[test]
fn bug_2290_slow_down_answers_and_requests_given_up_are_counted() {
    use veil_server::store::{S3_GAVE_UP, S3_SLOW_DOWN};
    let rt = runtime();
    let (f, store) = fake(&rt, 4, 503);
    let slow_before = S3_SLOW_DOWN.load(Ordering::SeqCst);
    let put = rt.block_on(store.put("p/1/o/cd", Bytes::from_static(b"slowed")));
    assert!(put.is_ok(), "a PUT answered 503 four times, then 200: {put:?}");
    assert_eq!(f.puts.load(Ordering::SeqCst), 5, "four refused tries and the one that stored");
    assert!(S3_SLOW_DOWN.load(Ordering::SeqCst) - slow_before >= 4, "the four 503 answers are counted");

    let (f, store) = fake(&rt, usize::MAX, 429);
    let (slow_before, gave_up_before) = (S3_SLOW_DOWN.load(Ordering::SeqCst), S3_GAVE_UP.load(Ordering::SeqCst));
    let put = rt.block_on(store.put("p/1/o/ef", Bytes::from_static(b"never stored")));
    let err = put.unwrap_err();
    assert!(format!("{err:#}").starts_with("S3 PUT answered HTTP 429 "), "a store that keeps answering 429 is refused: {err:#}");
    let tries = f.puts.load(Ordering::SeqCst) as u64;
    assert!(tries > 3, "tried again: {tries} tries");
    assert!(S3_SLOW_DOWN.load(Ordering::SeqCst) - slow_before >= tries, "every 429 is counted ({tries} tries)");
    assert!(S3_GAVE_UP.load(Ordering::SeqCst) - gave_up_before >= 1, "the request given up is counted");
}

/// How [`switched_proxy`] treats requests: passed through to the store,
/// answered 429, or their connections closed unanswered.
const PASS: u8 = 0;
const SLOW_DOWN: u8 = 1;
const CLOSE: u8 = 2;

/// A TCP proxy to `upstream` (host:port) that does what `mode` says, read
/// for each new connection; a connection passed through is closed as soon
/// as `mode` leaves [`PASS`], so a pooled connection does not slip past.
/// Returns its URL.
fn switched_proxy(upstream: String, mode: Arc<std::sync::atomic::AtomicU8>) -> String {
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpListener, TcpStream};
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    std::thread::spawn(move || {
        for c in l.incoming() {
            let Ok(mut c) = c else { continue };
            let (up, mode) = (upstream.clone(), mode.clone());
            std::thread::spawn(move || match mode.load(Ordering::SeqCst) {
                SLOW_DOWN => {
                    // Read the request (its head, then the body its
                    // Content-Length names) before answering, so the
                    // client reads the answer, not a reset.
                    let _ = c.set_read_timeout(Some(Duration::from_secs(5)));
                    let mut got = Vec::new();
                    let mut buf = [0u8; 65536];
                    let mut need = None;
                    while need.is_none_or(|n| got.len() < n) {
                        let Ok(k) = c.read(&mut buf) else { return };
                        if k == 0 {
                            return;
                        }
                        got.extend_from_slice(&buf[..k]);
                        if need.is_none() {
                            if let Some(end) = got.windows(4).position(|w| w == b"\r\n\r\n") {
                                let head = String::from_utf8_lossy(&got[..end]).to_ascii_lowercase();
                                let len = head.lines().find_map(|l| l.strip_prefix("content-length:")).and_then(|v| v.trim().parse().ok()).unwrap_or(0);
                                need = Some(end + 4 + len);
                            }
                        }
                    }
                    let _ = c.write_all(b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                }
                CLOSE => {
                    let _ = c.shutdown(Shutdown::Both);
                }
                _ => {
                    let Ok(u) = TcpStream::connect(&up) else { return };
                    let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
                    let pipe = |mut from: TcpStream, mut to: TcpStream, done: Arc<std::sync::atomic::AtomicBool>| {
                        std::thread::spawn(move || {
                            let _ = std::io::copy(&mut from, &mut to);
                            let _ = to.shutdown(Shutdown::Write);
                            done.store(true, Ordering::SeqCst);
                        })
                    };
                    let a = pipe(c.try_clone().unwrap(), u.try_clone().unwrap(), done.clone());
                    let b = pipe(u.try_clone().unwrap(), c.try_clone().unwrap(), done.clone());
                    while !done.load(Ordering::SeqCst) && mode.load(Ordering::SeqCst) == PASS {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    let _ = c.shutdown(Shutdown::Both);
                    let _ = u.shutdown(Shutdown::Both);
                    let _ = (a.join(), b.join());
                }
            });
        }
    });
    format!("http://{addr}")
}

/// BUG-2430. An object store that stays busy (429 on every request, as the
/// run's MinIO answered when overloaded) or unreachable (connections
/// closed, as while it restarted) for longer than the server's retries
/// (`S3_RETRY_FOR`) fails a push's upload with `503 busy` and a time to come
/// back, never `500 internal`; the 429s are tried again meanwhile. Once the
/// store answers, the same upload succeeds.
#[test]
fn bug_2430_a_store_busy_or_unreachable_past_the_retries_answers_busy_and_the_retry_succeeds() {
    use crate::support::*;
    use veil_core::object::Object as O;
    use veil_server::store::S3_SLOW_DOWN;
    let Ok(endpoint) = std::env::var("VEIL_TEST_S3_ENDPOINT") else {
        eprintln!("bug_2430: skipped (no VEIL_TEST_S3_ENDPOINT: run scripts/verify-server.sh)");
        return;
    };
    let upstream = endpoint.trim_start_matches("http://").trim_end_matches('/').to_string();
    let mode = Arc::new(std::sync::atomic::AtomicU8::new(PASS));
    let proxy = switched_proxy(upstream, mode.clone());
    let hub = TestHub::start_with_s3(&std::env::var("VEIL_TEST_DATABASE_URL").unwrap(), Duration::from_secs(3600), Some(proxy));
    let admin = hub.person("admin");
    let name = unique("busystore");
    let dir = admin.dir("proj");
    std::fs::create_dir_all(&dir).unwrap();
    admin.ok(&dir, &["init"]);
    write_files(&dir, &[("src/a.txt", "stored before the store went away")]);
    admin.ok(&dir, &["remote", "add", "origin", &hub.url(&name)]);
    admin.commit_main(&dir, "one file");
    let out = admin.ok(&dir, &["push"]);
    assert!(out.contains("Created project"), "{out}");
    let (api, token) = (hub.api(), admin.token());

    for (how, m) in [("answering 429", SLOW_DOWN), ("closing connections", CLOSE)] {
        let raw = O::Blob(format!("bug 2430: stored once the store is back ({how})\n").into_bytes()).encode();
        let id = veil_core::ObjectId::hash(&raw);
        let slowed = S3_SLOW_DOWN.load(Ordering::SeqCst);
        mode.store(m, Ordering::SeqCst);
        // Connections the proxy passed through before the switch notice it
        // within 10 ms and close; until they do, a pooled one could still
        // reach the store (BUG-2434: the upload then answered 200).
        std::thread::sleep(Duration::from_millis(200));
        let start = Instant::now();
        let up = api.upload(&token, &name, &[(id, raw.clone())]);
        let took = start.elapsed();
        mode.store(PASS, Ordering::SeqCst);
        let body = String::from_utf8_lossy(&up.body).to_string();
        assert_eq!(up.status, 503, "a store {how} past the retries: {body}");
        assert_eq!(up.json()["code"], "busy", "{how}: {body}");
        assert!(up.json()["retry_after_ms"].as_u64().is_some_and(|ms| ms > 0), "{how}: a time to come back: {body}");
        assert!(!body.contains("127.0.0.1") && !body.contains("S3"), "{how}: the answer names nothing of the store: {body}");
        assert!(took >= Duration::from_secs(5), "{how}: answered after the server's retries, not at once ({took:?})");
        if m == SLOW_DOWN {
            assert!(S3_SLOW_DOWN.load(Ordering::SeqCst) - slowed > 3, "the 429s were tried again, each counted");
        }

        let up = api.upload(&token, &name, &[(id, raw)]);
        assert_eq!(up.status, 200, "{how}: the upload again, once the store answers: {}", String::from_utf8_lossy(&up.body));
        assert_eq!(up.json()["receipts"].as_array().map(Vec::len), Some(1), "{}", String::from_utf8_lossy(&up.body));
    }
    // The project is whole: a clone through the store has the file.
    let c = admin.dir("clone");
    admin.ok(admin.home.path(), &["clone", &hub.url(&name), c.to_str().unwrap()]);
    assert_eq!(std::fs::read_to_string(c.join("src/a.txt")).unwrap(), "stored before the store went away");
}
