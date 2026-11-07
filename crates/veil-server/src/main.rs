//! `veil-server`: run the Veil server (`docs/HUB.md`).
//!
//! ```text
//! veil-server --database-url postgres://… --data ./hub [--listen 127.0.0.1:8443]
//!             [--storage DIR | --s3-endpoint URL --s3-bucket B]
//!             [--tls-cert cert.pem --tls-key key.pem]   (default: self-signed)
//! veil-server migrate --database-url postgres://…   (apply migrations, then exit)
//! ```

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use clap::{Parser, Subcommand};
use veil_server::{tls::TlsSource, Config, Storage};

#[derive(Parser)]
#[command(name = "veil-server", about = "The Veil server (the Hub)", args_conflicts_with_subcommands = true)]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,
    /// Address to listen on (HTTPS).
    #[arg(long, default_value = "127.0.0.1:8443")]
    listen: SocketAddr,
    /// PostgreSQL or YugabyteDB connection URL (default: VEIL_DATABASE_URL).
    #[arg(long)]
    database_url: Option<String>,
    /// Directory for the server's identity and its self-signed certificate.
    #[arg(long, required = true)]
    data: Option<PathBuf>,
    /// Keep objects in this directory (default: DATA/objects).
    #[arg(long, conflicts_with = "s3_endpoint")]
    storage: Option<PathBuf>,
    /// Keep objects in S3 at this endpoint (credentials in
    /// VEIL_S3_ACCESS_KEY and VEIL_S3_SECRET_KEY).
    #[arg(long, requires = "s3_bucket")]
    s3_endpoint: Option<String>,
    #[arg(long)]
    s3_bucket: Option<String>,
    #[arg(long, default_value = "us-east-1")]
    s3_region: String,
    /// TLS certificate chain (PEM); without it, a self-signed certificate.
    #[arg(long, requires = "tls_key")]
    tls_cert: Option<PathBuf>,
    #[arg(long)]
    tls_key: Option<PathBuf>,
    /// How long a session lasts, in seconds.
    #[arg(long, default_value_t = 12 * 3600)]
    session_seconds: u64,
    /// Database connections.
    #[arg(long, default_value_t = 32)]
    db_connections: u32,
}

#[derive(Subcommand)]
enum Command {
    /// Apply the database migrations once, then exit: run it before
    /// starting (or restarting) servers. A server that finds the schema
    /// current changes nothing in it.
    Migrate {
        /// PostgreSQL or YugabyteDB connection URL (default: VEIL_DATABASE_URL).
        #[arg(long)]
        database_url: Option<String>,
    },
}

fn database_url(given: Option<String>) -> anyhow::Result<String> {
    match given {
        Some(u) => Ok(u),
        None => std::env::var("VEIL_DATABASE_URL").map_err(|_| anyhow::anyhow!("give --database-url or VEIL_DATABASE_URL")),
    }
}

/// jemalloc, not glibc's malloc (BUG-864): glibc gives each of the
/// server's threads (32 workers, up to 512 blocking) its own arena and
/// returns little of it, so a 1 GB push left the server at 2.4 GB for under
/// 1 GB of data. Two arenas (each thread keeps a small cache in
/// front of them) and background threads returning memory unused for a
/// second keep it near what it holds (`docs/design/scale/BASELINE.md`,
/// "The server's allocator"). `_RJEM_MALLOC_CONF` overrides these settings.
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// jemalloc reads its settings from this symbol at start (a C string).
#[used]
#[export_name = "_rjem_malloc_conf"]
static MALLOC_CONF: &[u8; 70] = b"narenas:2,background_thread:true,dirty_decay_ms:1000,muzzy_decay_ms:0\0";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let a = Args::parse();
    if let Some(Command::Migrate { database_url: url }) = a.command {
        let db = veil_server::db::connect(&database_url(url)?, 2).await?;
        veil_server::db::migrate(&db).await?;
        println!("veil-server: the database schema is current");
        return Ok(());
    }
    let data = a.data.expect("clap requires --data");
    let storage = match a.s3_endpoint {
        Some(endpoint) => Storage::S3 {
            endpoint,
            bucket: a.s3_bucket.unwrap_or_default(),
            region: a.s3_region,
            key: std::env::var("VEIL_S3_ACCESS_KEY").unwrap_or_default(),
            secret: std::env::var("VEIL_S3_SECRET_KEY").unwrap_or_default(),
        },
        None => Storage::Dir(a.storage.unwrap_or_else(|| data.join("objects"))),
    };
    let tls = match (a.tls_cert, a.tls_key) {
        (Some(cert), Some(key)) => TlsSource::Files { cert, key },
        _ => TlsSource::SelfSigned,
    };
    let running = veil_server::start(Config {
        listen: a.listen,
        database_url: database_url(a.database_url)?,
        storage,
        tls,
        data_dir: data.clone(),
        session_ttl: Duration::from_secs(a.session_seconds),
        db_connections: a.db_connections,
    })
    .await?;
    println!("veil-server listening on https://{}", running.addr);
    if matches!(running.cert_pem.as_str(), s if !s.is_empty()) {
        println!("certificate: {}", data.join("self-signed-cert.pem").display());
    }
    tokio::signal::ctrl_c().await?;
    running.stop().await;
    Ok(())
}
