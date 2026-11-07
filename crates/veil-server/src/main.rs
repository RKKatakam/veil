//! `veil-server`: run the Veil server (`docs/HUB.md`).
//!
//! ```text
//! veil-server --database-url postgres://… --data ./hub [--listen 127.0.0.1:8443]
//!             [--storage DIR | --s3-endpoint URL --s3-bucket B]
//!             [--tls-cert cert.pem --tls-key key.pem]   (default: self-signed)
//! veil-server migrate --database-url postgres://…   (apply migrations, then exit)
//! ```
//!
//! On `SIGUSR1` the server writes its request-path counters (storage
//! writes and reads, cache hits and misses) to `DATA/stats.json`, for the
//! benchmarks' cost gates (`docs/design/server/storage-and-cost.md` §9).

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
    /// Database connections for requests (the background deriver opens 8
    /// more of its own).
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

fn main() -> anyhow::Result<()> {
    // Deep trees recurse on every server thread (BUG-1052).
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_stack_size(veil_server::THREAD_STACK)
        .build()?
        .block_on(serve())
}

async fn serve() -> anyhow::Result<()> {
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
        catch_up_at_start: true,
    })
    .await?;
    println!("veil-server listening on https://{}", running.addr);
    if matches!(running.cert_pem.as_str(), s if !s.is_empty()) {
        println!("certificate: {}", data.join("self-signed-cert.pem").display());
    }
    let hub = running.hub.clone();
    let mut usr1 = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1())?;
    let mut n = 0u64;
    // Written once at start: it says this server answers SIGUSR1.
    let _ = std::fs::write(data.join("stats.json"), serde_json::to_vec(&stats(&hub, 0))?);
    loop {
        tokio::select! {
            r = tokio::signal::ctrl_c() => { r?; break; }
            _ = usr1.recv() => {
                n += 1;
                let path = data.join("stats.json");
                let tmp = data.join("stats.json.tmp");
                let written = std::fs::write(&tmp, serde_json::to_vec(&stats(&hub, n))?).and_then(|_| std::fs::rename(&tmp, &path));
                if let Err(e) = written {
                    eprintln!("veil-server: writing {}: {e}", path.display());
                }
            }
        }
    }
    running.stop().await;
    Ok(())
}

/// The counters `SIGUSR1` writes (`n` counts the signals).
fn stats(hub: &veil_server::Hub, n: u64) -> serde_json::Value {
    use std::sync::atomic::Ordering::Relaxed;
    let c = &hub.caches.stats;
    serde_json::json!({
        "n": n,
        "storage_writes": hub.objects.writes.load(Relaxed),
        "storage_written_bytes": hub.objects.written_bytes.load(Relaxed),
        "storage_reads": hub.objects.reads.load(Relaxed),
        "session_hits": c.session_hits.load(Relaxed),
        "session_misses": c.session_misses.load(Relaxed),
        "permission_hits": c.permission_hits.load(Relaxed),
        "permission_misses": c.permission_misses.load(Relaxed),
        "tips_hits": c.tips_hits.load(Relaxed),
        "tips_misses": c.tips_misses.load(Relaxed),
        "notices": hub.caches.notices.load(Relaxed),
        "landing_batches": hub.landing.stats.batches.load(Relaxed),
        "landing_landed": hub.landing.stats.landed.load(Relaxed),
        "landing_conflicts": hub.landing.stats.conflicts.load(Relaxed),
        "landing_rejected": hub.landing.stats.rejected.load(Relaxed),
        "landing_build_us": hub.landing.stats.build_us.load(Relaxed),
        "landing_store_us": hub.landing.stats.store_us.load(Relaxed),
        "landing_commit_us": hub.landing.stats.commit_us.load(Relaxed),
    })
}
