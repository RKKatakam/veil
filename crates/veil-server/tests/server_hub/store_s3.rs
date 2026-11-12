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
use veil_server::store::{BlobStore, Objects, S3Store};

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
    assert_eq!(format!("{err:#}"), "S3 PUT: HTTP 499");
    assert!(took >= Duration::from_secs(5) && took < Duration::from_secs(15), "tried again within the bound: {took:?}");
    assert!(f.puts.load(Ordering::SeqCst) > 3, "tried again: {} tries", f.puts.load(Ordering::SeqCst));
    assert!(f.stored.lock().unwrap().is_empty());
    assert!(rt.block_on(objects.get(1, &id)).unwrap().is_none(), "the object a refused PUT did not store is not served");
}
