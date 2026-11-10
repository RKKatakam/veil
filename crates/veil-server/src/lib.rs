//! The Veil server (the Hub): projects, people, groups and folder access,
//! and sync for `vl` (`docs/HUB.md`; milestone S1).
//!
//! | Module | |
//! |---|---|
//! | [`api`] | the HTTPS routes |
//! | [`auth`] | challenge-response sign-in, session tokens |
//! | [`caches`] | sessions, permissions, snapshot resolution and tips in memory, versioned by access epochs |
//! | [`perm`] | the permission model: admins, groups, the accepted policy |
//! | [`shares`] | person-to-person secret shares (ciphertext and the admins' audit) |
//! | [`sync`] | projected history, fetch by id, push validation, branch CAS |
//! | [`changes`] | commits through the API: edits on a revision, the push's checks, one commit |
//! | [`grant`] | read grants, the object routes, the access-epoch feed |
//! | [`cache`] | the regional cache (`veil-server cache`, S9), and the epoch feed it polls |
//! | [`landing`] | the landing service: the queue, leases, batches, the fast path, content merges, protected branches (S17, S18) |
//! | [`events`] | the project event stream: SSE outcomes and branch moves per viewer (S18) |
//! | [`mod@derive`] | derived history data: commit graph, changed paths, per-rule lists (S12) |
//! | [`query`] | the query API: history answered per viewer (S13) |
//! | [`limits`] | rate limits, request bodies under a budget, per-project bulkheads, shedding, health metrics (S24) |
//! | [`db`] | PostgreSQL / YugabyteDB, migrations, serialisable retries |
//! | [`store`] | object storage: local directory or S3 |
//! | [`tls`] | TLS configuration |

pub mod api;
pub mod auth;
pub mod cache;
pub mod caches;
pub mod changes;
pub mod ci;
pub mod db;
pub mod derive;
pub mod error;
pub mod events;
pub mod grant;
pub mod landing;
pub mod limits;
pub mod perm;
pub mod query;
pub mod search;
pub mod shares;
pub mod store;
pub mod sync;
pub mod tls;

use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use veil_core::{cache::LruCache, object::Tree, object::TreeEncoding, Identity};

/// The stack of every thread that runs the server's work (the runtime's
/// workers and blocking threads): enough for the walks that recurse once
/// per folder level (projection, the graft, an API commit's edits) at
/// `veil_core::tree::MAX_TREE_DEPTH` levels, the deepest a tree may be
/// (BUG-1052). Whoever builds the runtime `start` runs on sets it
/// (`main.rs`, the tests). Address space only: a thread uses what it
/// touches.
pub const THREAD_STACK: usize = 64 << 20;

/// Shared server state.
pub struct Hub {
    pub db: sqlx::PgPool,
    pub objects: Arc<store::Objects>,
    /// Decoded trees, by [`store::Objects::tree_key`].
    pub trees: LruCache<(Arc<Tree>, TreeEncoding)>,
    /// The server's own signing identity: projected snapshots are signed
    /// with it.
    pub identity: Identity,
    /// The MAC key of upload receipts (`sync::receipt`), derived from the
    /// random secret in `<data>/hub-receipt-key`.
    pub receipt_key: [u8; 32],
    /// The grant key (`<data>/hub-grant-key`) and what it needs
    /// (`grant`).
    pub grants: grant::Grants,
    /// The hash of the regional caches' token (`<data>/hub-cache-token`):
    /// what `POST /v1/cache/epochs` accepts (`cache::feed`).
    pub cache_token: blake3::Hash,
    pub session_ttl_ms: i64,
    /// The TLS certificate (leaf, DER): sign-in accepts only signatures
    /// for a server name it is valid for.
    pub certificate: rustls::pki_types::CertificateDer<'static>,
    /// Request-path caches (`caches`): never stale for a permission.
    pub caches: caches::Caches,
    /// The derive workers (`derive::landed`).
    pub derive: derive::Workers,
    /// The query API's caches and the viewer-graph fills running here
    /// (`query::graph`).
    pub query: query::graph::State,
    /// The landing services running here, and the submitters waiting here.
    pub landing: landing::Services,
    /// Active SSE streams (`GET …/events`, S18).
    pub events: events::Events,
    /// Rate limits, the request budget, bulkheads and health (S24).
    pub limits: limits::Limits,
}

pub type HubState = Arc<Hub>;

/// Where objects are stored.
#[derive(Clone, Debug)]
pub enum Storage {
    Dir(PathBuf),
    S3 {
        endpoint: String,
        bucket: String,
        region: String,
        key: String,
        secret: String,
    },
}

#[derive(Clone, Debug)]
pub struct Config {
    pub listen: SocketAddr,
    pub database_url: String,
    pub storage: Storage,
    pub tls: tls::TlsSource,
    /// The server's identity and the self-signed certificate live here.
    pub data_dir: PathBuf,
    pub session_ttl: Duration,
    /// The requests' connections; the background deriver has its own
    /// `derive::DERIVE_CONNECTIONS` more.
    pub db_connections: u32,
    /// Derive, in the background once serving, every branch a landing left
    /// underived (`derive::resume`), and start the landing services of
    /// every branch with queued landings (`landing::resume`). Servers do;
    /// tests that count their own derive runs, or share a database between
    /// servers with separate object stores, turn it off.
    pub catch_up_at_start: bool,
    /// Rate limits, connections and the request budget (S24).
    pub limits: limits::Settings,
}

/// A running server.
pub struct Running {
    pub addr: SocketAddr,
    /// The certificate's PEM (what `vl login --ca` is given for a
    /// self-signed one).
    pub cert_pem: String,
    pub hub: HubState,
    shutdown: tokio::sync::watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl Running {
    pub async fn stop(self) {
        let _ = self.shutdown.send(true);
        let _ = self.task.await;
    }
}

/// Load or create the server's signing identity in `data_dir`.
fn server_identity(data_dir: &std::path::Path) -> Result<Identity> {
    let path = data_dir.join("hub-identity.json");
    if path.exists() {
        return Ok(Identity::from_json(&std::fs::read_to_string(&path)?)?);
    }
    let id = Identity::generate("hub");
    tls::write_private(&path, id.to_json().as_bytes())?;
    Ok(id)
}

/// Load or create the server's upload-receipt secret in `data_dir`, and
/// derive the receipt MAC key from it. Servers sharing the data directory
/// accept each other's receipts.
fn receipt_key(data_dir: &std::path::Path) -> Result<[u8; 32]> {
    let path = data_dir.join("hub-receipt-key");
    if !path.exists() {
        let _ = tls::write_private(&path, hex::encode(veil_core::crypto::random_bytes::<32>()).as_bytes());
    }
    let secret = hex::decode(std::fs::read_to_string(&path)?.trim()).context("reading hub-receipt-key")?;
    anyhow::ensure!(secret.len() == 32, "hub-receipt-key must hold 32 bytes in hex");
    Ok(blake3::derive_key(veil_core::crypto::domains::HUB_UPLOAD_RECEIPT, &secret))
}

/// Connect, migrate and start serving.
pub async fn start(config: Config) -> Result<Running> {
    std::fs::create_dir_all(&config.data_dir)?;
    let identity = server_identity(&config.data_dir)?;
    let receipt_key = receipt_key(&config.data_dir)?;
    let grants = grant::Grants::load(&config.data_dir).context("reading hub-grant-key")?;
    let cache_token = cache::feed::load_token(&config.data_dir).context("reading hub-cache-token")?;
    let (tls, cert_pem, certificate) = tls::server_config(&config.tls, &config.data_dir)?;
    let db = db::connect(&config.database_url, config.db_connections).await.context("connecting to the database")?;
    db::migrate(&db).await.context("migrating the database")?;
    // The background deriver's own connections (BUG-911), opened when a
    // run first needs one.
    let derive_db = db::connect_lazy(&config.database_url, derive::DERIVE_CONNECTIONS)?;
    let blob: Arc<dyn store::BlobStore> = match &config.storage {
        Storage::Dir(d) => Arc::new(store::FsStore::new(d)),
        Storage::S3 {
            endpoint,
            bucket,
            region,
            key,
            secret,
        } => {
            let s = store::S3Store::new(endpoint, bucket, region, key, secret)?;
            s.ensure_bucket().await?;
            Arc::new(s)
        }
    };
    let hub = Arc::new(Hub {
        db,
        objects: Arc::new(store::Objects::new(blob, 256 << 20)),
        trees: LruCache::new(256 << 20),
        identity,
        receipt_key,
        grants,
        cache_token,
        session_ttl_ms: config.session_ttl.as_millis() as i64,
        certificate,
        caches: caches::Caches::default(),
        derive: derive::Workers::new(derive_db),
        query: query::graph::State::default(),
        landing: landing::Services::default(),
        events: events::Events::default(),
        limits: limits::Limits::new(config.limits, config.db_connections),
    });
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    let addr = listener.local_addr()?;
    let (tx, rx) = tokio::sync::watch::channel(false);
    let app = api::router(hub.clone());
    // Push notices drop other servers' cached tips (`caches::listen`).
    tokio::spawn(caches::listen(hub.clone(), rx.clone()));
    let pace = cache::deadline::Pace { stall: ANSWER_STALL, grace: ANSWER_STALL, min_rate: limits::body::MIN_RATE };
    let connections = ConnectionLimits { pace, max_connections: config.limits.max_connections, buffer: HTTP_BUFFER };
    let task = tokio::spawn(serve(listener, tls, app, rx, Some(connections), Some(hub.limits.connections.clone())));
    if config.catch_up_at_start {
        tokio::spawn({
            let hub = hub.clone();
            async move {
                derive::resume(hub.clone(), None).await;
                // The search index follows (S15, BUG-1231).
                crate::search::index::resume(hub, None).await;
            }
        });
        // Landings queued when a server stopped are landed.
        tokio::spawn(landing::resume(hub.clone()));
    }
    Ok(Running {
        addr,
        cert_pem,
        hub,
        shutdown: tx,
        task,
    })
}

/// How long a connection may take to finish its TLS handshake, or to send
/// a request's head.
const IDLE_LIMIT: Duration = Duration::from_secs(20);

/// What a regional cache bounds per connection (BUG-1181, BUG-1183), so
/// that its memory is `--memory` plus `max_connections` times what one
/// connection holds (`docs/HUB.md` §13.18), and every connection slot is
/// given back in bounded time.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ConnectionLimits {
    /// A connection whose writes stall, or fall below the minimum rate, is
    /// closed.
    pub pace: cache::deadline::Pace,
    /// At most this many are open at once; the next waits in the
    /// listener's queue until one closes.
    pub max_connections: usize,
    /// The HTTP layer's read and write buffers per connection. HTTP/1.1
    /// only: HTTP/2 would keep a send buffer per stream.
    pub buffer: usize,
}

/// TLS records waiting to be sent per connection, with [`ConnectionLimits`]:
/// one record (rustls's default is 64 KiB).
const TLS_SEND_BUFFER: usize = 16 << 10;

/// The server's answers (S24, as the regional cache's, BUG-1183): a write
/// pending this long closes the connection, and so does one that brings
/// the time writes waited past this plus a second per 16 KiB written.
const ANSWER_STALL: Duration = Duration::from_secs(30);
/// The server's HTTP/1.1 buffer per connection: a request head with the
/// longest `Veil-Chain` (`MAX_CHAIN` ids, about 67 KB) fits.
const HTTP_BUFFER: usize = 128 << 10;
/// HTTP/2 per connection (S24): streams at once, and the bytes a client
/// may send ahead on the connection and on one stream, and the answer bytes
/// queued per stream.
const H2_STREAMS: u32 = 16;
const H2_CONNECTION_WINDOW: u32 = 256 << 10;
const H2_STREAM_WINDOW: u32 = 64 << 10;
const H2_SEND_BUFFER: usize = 32 << 10;

/// Serve `app` over TLS until `stop`, with `limits` (the regional cache's,
/// HTTP/1.1 only) or none.
pub(crate) async fn serve_tls(
    listener: tokio::net::TcpListener,
    tls: Arc<rustls::ServerConfig>,
    app: axum::Router,
    stop: tokio::sync::watch::Receiver<bool>,
    limits: Option<ConnectionLimits>,
) {
    serve(listener, tls, app, stop, limits, None).await
}

/// Requests of one connection whose answers are not finished, and since
/// when it has had none: what the idle limit reads (BUG-1337).
struct Activity(std::sync::Mutex<(usize, tokio::time::Instant)>);

/// One request's part of [`Activity`], until its answer's body is done.
struct Active(Arc<Activity>);

impl Activity {
    fn start(self: &Arc<Self>) -> Active {
        self.0.lock().unwrap().0 += 1;
        Active(self.clone())
    }

    fn idle_for(&self) -> Duration {
        let (n, since) = *self.0.lock().unwrap();
        if n > 0 {
            Duration::ZERO
        } else {
            since.elapsed()
        }
    }
}

impl Drop for Active {
    fn drop(&mut self) {
        let mut a = self.0 .0.lock().unwrap();
        a.0 -= 1;
        a.1 = tokio::time::Instant::now();
    }
}

/// An answer's body that keeps its request [`Active`] until it is done.
struct Answering {
    body: axum::body::Body,
    _active: Active,
}

impl hyper::body::Body for Answering {
    type Data = bytes::Bytes;
    type Error = axum::Error;

    fn poll_frame(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Option<Result<hyper::body::Frame<bytes::Bytes>, axum::Error>>> {
        std::pin::Pin::new(&mut self.body).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.body.size_hint()
    }
}

/// Serve `app` over TLS until `stop`. With `limits`: at most
/// `max_connections` open, bounded buffers, answers that must keep the
/// minimum rate, and a connection with no request in flight for
/// [`IDLE_LIMIT`] closed, HTTP/1.1 or HTTP/2 (BUG-1337: a graceful close,
/// then at once after as long again). With `server` (the Veil server's
/// listener, S24): HTTP/2 too (bounded per connection by [`H2_STREAMS`] and
/// its windows), and an address opens at most its share of the connections
/// (`limits::Connections`; past it a connection is closed at once).
/// Without (a regional cache): HTTP/1.1 only, and each request carries its
/// client's address to the cache's routes (`limits::CLIENT_ADDRESS`).
pub(crate) async fn serve(
    listener: tokio::net::TcpListener,
    tls: Arc<rustls::ServerConfig>,
    app: axum::Router,
    mut stop: tokio::sync::watch::Receiver<bool>,
    limits: Option<ConnectionLimits>,
    server: Option<Arc<limits::Connections>>,
) {
    let acceptor = tokio_rustls::TlsAcceptor::from(tls);
    let open = limits.map(|l| Arc::new(tokio::sync::Semaphore::new(l.max_connections.max(1))));
    loop {
        let slot = match &open {
            Some(open) => tokio::select! {
                s = open.clone().acquire_owned() => s.ok(),
                _ = stop.changed() => return,
            },
            None => None,
        };
        let (tcp, peer) = tokio::select! {
            r = listener.accept() => match r {
                Ok(c) => c,
                // Out of file descriptors, say: back off instead of spinning.
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
            _ = stop.changed() => return,
        };
        let _ = tcp.set_nodelay(true);
        let address = match &server {
            Some(c) => match c.open(peer.ip()) {
                Some(a) => Some(a),
                // Past its address's share: closed at once.
                None => continue,
            },
            None => None,
        };
        let acceptor = acceptor.clone();
        let app = app.clone();
        let h2 = server.is_some();
        tokio::spawn(async move {
            let _slot = (slot, address);
            // A connection that never finishes its handshake, or never sends
            // a request's head, is closed: idle sockets cannot pile up.
            let Ok(Ok(mut stream)) = tokio::time::timeout(IDLE_LIMIT, acceptor.accept(tcp)).await else { return };
            if limits.is_some() {
                stream.get_mut().1.set_buffer_limit(Some(TLS_SEND_BUFFER));
            }
            // Each request knows its client's address (`limits::Peer`); a
            // cache's routes pass it on to the server.
            let ip = peer.ip();
            let app = tower::ServiceExt::map_request(app, move |mut r: axum::http::Request<hyper::body::Incoming>| {
                r.extensions_mut().insert(limits::Peer(ip));
                if !h2 {
                    if let Ok(v) = axum::http::HeaderValue::from_str(&ip.to_string()) {
                        r.headers_mut().insert(limits::CLIENT_ADDRESS, v);
                    }
                }
                r
            });
            let activity = Arc::new(Activity(std::sync::Mutex::new((0, tokio::time::Instant::now()))));
            let counting = activity.clone();
            let app = tower::ServiceExt::map_future(app, move |answer| {
                let active = counting.start();
                async move {
                    let r: Result<axum::response::Response, std::convert::Infallible> = answer.await;
                    r.map(|resp| resp.map(|body| axum::body::Body::new(Answering { body, _active: active })))
                }
            });
            let service = hyper_util::service::TowerToHyperService::new(app);
            let mut b = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
            b.http1().timer(hyper_util::rt::TokioTimer::new()).header_read_timeout(IDLE_LIMIT);
            if let Some(l) = limits {
                b.http1().max_buf_size(l.buffer);
                if h2 {
                    b.http2()
                        .timer(hyper_util::rt::TokioTimer::new())
                        .max_concurrent_streams(H2_STREAMS)
                        .initial_connection_window_size(H2_CONNECTION_WINDOW)
                        .initial_stream_window_size(H2_STREAM_WINDOW)
                        .max_send_buf_size(H2_SEND_BUFFER)
                        .max_header_list_size(HTTP_BUFFER as u32)
                        .keep_alive_interval(Some(IDLE_LIMIT))
                        .keep_alive_timeout(IDLE_LIMIT);
                } else {
                    b = b.http1_only();
                }
            }
            let stream = cache::deadline::WriteDeadline::new(stream, limits.map(|l| l.pace));
            let conn = b.serve_connection(hyper_util::rt::TokioIo::new(stream), service);
            tokio::pin!(conn);
            if limits.is_none() {
                let _ = conn.await;
                return;
            }
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            let mut closing: Option<tokio::time::Instant> = None;
            loop {
                tokio::select! {
                    _ = conn.as_mut() => return,
                    _ = tick.tick() => match closing {
                        None if activity.idle_for() >= IDLE_LIMIT => {
                            conn.as_mut().graceful_shutdown();
                            closing = Some(tokio::time::Instant::now());
                        }
                        Some(t) if t.elapsed() >= IDLE_LIMIT => return,
                        _ => {}
                    },
                }
            }
        });
    }
}

/// Record an action in the audit log (best effort: never fails a request).
pub async fn audit(db: &sqlx::PgPool, project: Option<i64>, actor: Option<i64>, action: &str, details: &str) {
    let _ = sqlx::query("INSERT INTO audit_log (project_id, at, actor, action, details) VALUES ($1, $2, $3, $4, $5)")
        .bind(project)
        .bind(veil_core::now_millis())
        .bind(actor)
        .bind(action)
        .bind(details)
        .execute(db)
        .await;
}
