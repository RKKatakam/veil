//! The Veil server (the Hub): projects, people, groups and folder access,
//! and sync for `vl` (`docs/HUB.md`; milestone S1).
//!
//! | Module | |
//! |---|---|
//! | [`api`] | the HTTPS routes |
//! | [`auth`] | challenge-response sign-in, session tokens |
//! | [`perm`] | the permission model: admins, groups, the accepted policy |
//! | [`sync`] | projected history, fetch by id, push validation, branch CAS |
//! | [`changes`] | commits through the API: edits on a revision, the push's checks, one commit |
//! | [`mod@derive`] | derived history data: commit graph, changed paths, per-rule lists (S12) |
//! | [`db`] | PostgreSQL / YugabyteDB, migrations, serialisable retries |
//! | [`store`] | object storage: local directory or S3 |
//! | [`tls`] | TLS configuration |

pub mod api;
pub mod auth;
pub mod changes;
pub mod db;
pub mod derive;
pub mod error;
pub mod perm;
pub mod store;
pub mod sync;
pub mod tls;

use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use veil_core::{cache::LruCache, object::Tree, object::TreeEncoding, Identity};

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
    pub session_ttl_ms: i64,
    /// The TLS certificate (leaf, DER): sign-in accepts only signatures
    /// for a server name it is valid for.
    pub certificate: rustls::pki_types::CertificateDer<'static>,
    /// The derive workers (`derive::landed`).
    pub derive: derive::Workers,
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
    pub db_connections: u32,
    /// Derive, in the background once serving, every branch a landing left
    /// underived (`derive::resume`). Servers do; tests that count
    /// their own derive runs turn it off.
    pub catch_up_at_start: bool,
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
    let (tls, cert_pem, certificate) = tls::server_config(&config.tls, &config.data_dir)?;
    let db = db::connect(&config.database_url, config.db_connections).await.context("connecting to the database")?;
    db::migrate(&db).await.context("migrating the database")?;
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
        session_ttl_ms: config.session_ttl.as_millis() as i64,
        certificate,
        derive: derive::Workers::default(),
    });
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    let addr = listener.local_addr()?;
    let (tx, rx) = tokio::sync::watch::channel(false);
    let app = api::router(hub.clone());
    let task = tokio::spawn(serve_tls(listener, tls, app, rx));
    if config.catch_up_at_start {
        tokio::spawn(derive::resume(hub.clone(), None));
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

async fn serve_tls(
    listener: tokio::net::TcpListener,
    tls: Arc<rustls::ServerConfig>,
    app: axum::Router,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let acceptor = tokio_rustls::TlsAcceptor::from(tls);
    loop {
        let (tcp, _) = tokio::select! {
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
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            // A connection that never finishes its handshake, or never sends
            // a request's head, is closed: idle sockets cannot pile up.
            let Ok(Ok(stream)) = tokio::time::timeout(IDLE_LIMIT, acceptor.accept(tcp)).await else { return };
            let service = hyper_util::service::TowerToHyperService::new(app);
            let mut b = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
            b.http1().timer(hyper_util::rt::TokioTimer::new()).header_read_timeout(IDLE_LIMIT);
            let _ = b.serve_connection(hyper_util::rt::TokioIo::new(stream), service).await;
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
