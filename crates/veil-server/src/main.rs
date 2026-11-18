//! `veil-server`: run the Veil server (`docs/HUB.md`).
//!
//! ```text
//! veil-server --database-url postgres://… --data ./hub [--listen 127.0.0.1:8443]
//!             [--storage DIR | --s3-endpoint URL --s3-bucket B]
//!             [--object-layout packs|objects]
//!             [--tls-cert cert.pem --tls-key key.pem]   (default: self-signed)
//!             [--device-rate 200/50000] [--anonymous-rate 20/1000]
//!             [--max-connections 1024] [--request-memory 512M]   (docs/HUB.md §13.25)
//! veil-server migrate --database-url postgres://…   (apply migrations, then exit)
//! veil-server gc --database-url postgres://… [--data ./hub] [--project NAME] [--dry-run]
//!             [--storage DIR | --s3-endpoint URL --s3-bucket B]   (offline GC: docs/HUB.md §13.37)
//! veil-server cache --upstream https://hub:8443 --token-file TOKEN --dir DIR
//!             [--listen 127.0.0.1:8444] [--size 10G] [--memory 128M] [--max-connections 1024]
//!             [--upstream-ca PEM]
//!             (a regional cache: docs/HUB.md §13.18)
//! ```
//!
//! On `SIGUSR1` the server writes its request-path counters (storage
//! writes and reads, cache hits and misses) to `DATA/stats.json`, for the
//! benchmarks' cost gates (`docs/design/server/storage-and-cost.md` §9).

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use clap::{Parser, Subcommand};
use veil_server::{tls::TlsSource, Config, ObjectLayout, Storage};

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
    /// VEIL_S3_ACCESS_KEY and VEIL_S3_SECRET_KEY; a CA of its own, in
    /// PEM, in the file VEIL_S3_CA names).
    #[arg(long, requires = "s3_bucket")]
    s3_endpoint: Option<String>,
    #[arg(long)]
    s3_bucket: Option<String>,
    #[arg(long, default_value = "us-east-1")]
    s3_region: String,
    /// How this server keeps new objects: `packs` or `objects` (default:
    /// VEIL_OBJECT_LAYOUT, or `packs`).
    #[arg(long)]
    object_layout: Option<ObjectLayout>,
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
    /// Requests per signed-in device (one person's agents share it): a
    /// burst a second, then the most an hour (`429` with `retry_after_ms`
    /// past it). A person's devices and agent sessions together have ten
    /// times it, and so have the people of one address whom no project
    /// but their own names.
    #[arg(long, default_value = "200/50000", value_parser = rate)]
    device_rate: veil_server::limits::bucket::Rate,
    /// Requests per address without a session this server knows
    /// (anonymous reads of public folders, sign-in), as --device-rate.
    #[arg(long, default_value = "20/1000", value_parser = rate)]
    anonymous_rate: veil_server::limits::bucket::Rate,
    /// Most client connections open at once (the next waits until one
    /// closes; one address, an IPv6 /56, opens at most an eighth of them,
    /// a regional cache's as many as it needs).
    #[arg(long, default_value_t = 1024)]
    max_connections: usize,
    /// Most bytes of request bodies held at once, all requests together
    /// (an eighth kept for small bodies, a quarter for requests without a
    /// session), and as many of answers being written (K, M, G suffixes).
    #[arg(long, default_value = "512M", value_parser = bytes)]
    request_memory: u64,
}

fn rate(s: &str) -> Result<veil_server::limits::bucket::Rate, String> {
    veil_server::limits::bucket::Rate::parse(s)
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
    /// Run offline garbage collection on one or all projects, refusing if any
    /// `veil-server` is serving the database (`docs/HUB.md` §13.37).
    Gc {
        /// PostgreSQL connection URL (default: VEIL_DATABASE_URL).
        #[arg(long)]
        database_url: Option<String>,
        /// Server data directory (default object directory: DATA/objects).
        #[arg(long)]
        data: Option<PathBuf>,
        /// Keep objects in this directory (default: DATA/objects).
        #[arg(long, conflicts_with = "s3_endpoint")]
        storage: Option<PathBuf>,
        /// Keep objects in S3 at this endpoint (credentials in
        /// VEIL_S3_ACCESS_KEY and VEIL_S3_SECRET_KEY; a CA of its own, in
        /// PEM, in the file VEIL_S3_CA names).
        #[arg(long, requires = "s3_bucket")]
        s3_endpoint: Option<String>,
        #[arg(long)]
        s3_bucket: Option<String>,
        #[arg(long, default_value = "us-east-1")]
        s3_region: String,
        /// Collect only this project (default: every project in the database).
        #[arg(long)]
        project: Option<String>,
        /// Report what would be deleted without modifying the database or storage.
        #[arg(long)]
        dry_run: bool,
    },
    /// Run a regional cache of the object routes in front of a Veil
    /// server (`docs/HUB.md` §13.18). It holds objects only, no key and no
    /// database, and serves one only under a grant the server signed.
    Cache {
        /// The Veil server: `https://host:port`.
        #[arg(long)]
        upstream: String,
        /// The server's certificate (PEM), for a self-signed one.
        #[arg(long)]
        upstream_ca: Option<PathBuf>,
        /// The file holding the server's `hub-cache-token`.
        #[arg(long)]
        token_file: PathBuf,
        /// The cache's directory (its objects, its certificate).
        #[arg(long)]
        dir: PathBuf,
        /// Address to listen on (HTTPS).
        #[arg(long, default_value = "127.0.0.1:8444")]
        listen: SocketAddr,
        /// Most bytes of objects kept on disk (K, M, G suffixes).
        #[arg(long, default_value = "10G", value_parser = bytes)]
        size: u64,
        /// About the most memory for decoded trees, the store's index,
        /// batch requests and answers being sent (K, M, G suffixes).
        #[arg(long, default_value = "128M", value_parser = bytes)]
        memory: u64,
        /// Most client connections open at once (the next waits until one
        /// closes): each may hold about 368 KiB beyond --memory (its TLS and
        /// HTTP buffers), so the defaults bound the cache at about 496 MiB.
        #[arg(long, default_value_t = 1024)]
        max_connections: usize,
        /// TLS certificate chain (PEM); without it, a self-signed certificate.
        #[arg(long, requires = "tls_key")]
        tls_cert: Option<PathBuf>,
        #[arg(long)]
        tls_key: Option<PathBuf>,
    },
}

fn server_err(e: veil_server::error::Error) -> anyhow::Error {
    match e {
        veil_server::error::Error::Api { message, .. } => anyhow::anyhow!("{message}"),
        veil_server::error::Error::Db(e) => anyhow::Error::from(e),
        veil_server::error::Error::Other(e) => e,
    }
}

/// `123`, `64K`, `256M`, `10G`.
fn bytes(s: &str) -> Result<u64, String> {
    let (n, shift) = match s.char_indices().last() {
        Some((i, 'K' | 'k')) => (&s[..i], 10),
        Some((i, 'M' | 'm')) => (&s[..i], 20),
        Some((i, 'G' | 'g')) => (&s[..i], 30),
        _ => (s, 0),
    };
    n.parse::<u64>().ok().and_then(|n| n.checked_mul(1 << shift)).filter(|n| *n > 0).ok_or_else(|| format!("{s}: a size such as 512M or 10G"))
}

fn database_url(given: Option<String>) -> anyhow::Result<String> {
    match given {
        Some(u) => Ok(u),
        None => std::env::var("VEIL_DATABASE_URL").map_err(|_| anyhow::anyhow!("give --database-url or VEIL_DATABASE_URL")),
    }
}

fn object_layout(given: Option<ObjectLayout>, env: Option<&str>) -> anyhow::Result<ObjectLayout> {
    match (given, env) {
        (Some(l), _) => Ok(l),
        (None, Some(s)) => s.parse::<ObjectLayout>().map_err(|e| anyhow::anyhow!("VEIL_OBJECT_LAYOUT: {e}")),
        (None, None) => Ok(ObjectLayout::Packs),
    }
}

/// jemalloc, not glibc's malloc (BUG-864): glibc gives each of the
/// server's threads (32 workers, up to 512 blocking) its own arena and
/// returns little of it, so a 1 GB push left the server at 2.4 GB for under
/// 1 GB of data. Two arenas (each thread keeps a small cache in
/// front of them) and background threads returning memory unused for a
/// moment keep it near what it holds (`docs/design/scale/BASELINE.md`,
/// "The server's allocator"). `_RJEM_MALLOC_CONF` overrides these settings.
///
/// BUG-2456 (`docs/design/scale/LOAD.md`, "The full clone's memory, by
/// the allocator"): a full clone of the 1 GB project sat at the 1 GB gate
/// with the same live memory. What its peak had besides live memory:
/// pages freed and not yet returned (up to 90 MiB with a second's decay,
/// about 40 at 250 ms), and slabs left part empty when the object cache
/// swapped its small entries for the clone's larger ones (about 110 MiB, in
/// the 448- to 1,280-byte classes, whose slabs hold 16 to 64 regions; with
/// slabs of one page, 3 to 9, more of them empty out whole). Pulls' rate
/// and CPU and the clone's time were unchanged.
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// jemalloc reads its settings from this symbol at start (a C string).
#[used]
#[export_name = "_rjem_malloc_conf"]
static MALLOC_CONF: &[u8; 89] = b"narenas:2,background_thread:true,dirty_decay_ms:250,muzzy_decay_ms:0,slab_sizes:1-1280:1\0";

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
    if let Some(Command::Gc {
        database_url: url,
        data,
        storage,
        s3_endpoint,
        s3_bucket,
        s3_region,
        project,
        dry_run,
    }) = a.command
    {
        let db_url = database_url(url)?;
        let store = match (s3_endpoint, storage, data) {
            (Some(endpoint), _, _) => Storage::S3 {
                endpoint,
                bucket: s3_bucket.unwrap_or_default(),
                region: s3_region,
                key: std::env::var("VEIL_S3_ACCESS_KEY").unwrap_or_default(),
                secret: std::env::var("VEIL_S3_SECRET_KEY").unwrap_or_default(),
            },
            (None, Some(dir), _) => Storage::Dir(dir),
            (None, None, Some(d)) => Storage::Dir(d.join("objects")),
            (None, None, None) => anyhow::bail!("give --data, --storage, or --s3-endpoint"),
        };
        let hub = veil_server::open_offline(&db_url, &store).await?;
        // No server is serving while `OfflineGcFence` is held, so unreachable
        // objects, superseded packs, and abandoned staged uploads can all be
        // reclaimed in one offline maintenance pass without waiting on online
        // retention or grace windows.
        let opts = veil_server::pack_gc::Options {
            retention_window_ms: 0,
            pack_grace_ms: 0,
            staged_grace_ms: 0,
            ..veil_server::pack_gc::Options::default()
        };
        if dry_run {
            let reports = veil_server::pack_gc::dry_run_offline(&hub, project.as_deref(), &opts)
                .await
                .map_err(server_err)?;
            let mut tot = veil_server::pack_gc::DryRunReport::default();
            for (name, r) in &reports {
                println!(
                    "project {name}: would delete {} loose objects, {} packed objects, {} expired snapshots; \
                     rewrite {} packs; sweep {} discarded packs, {} staged uploads ({} newly unreferenced, {} in retention window)",
                    r.loose_objects_to_delete,
                    r.packed_objects_to_delete,
                    r.expired_snapshots_to_purge,
                    r.packs_to_rewrite,
                    r.discarded_packs_to_sweep,
                    r.staged_packs_to_sweep,
                    r.newly_unreferenced,
                    r.unreferenced_in_window,
                );
                tot.newly_unreferenced += r.newly_unreferenced;
                tot.unreferenced_in_window += r.unreferenced_in_window;
                tot.loose_objects_to_delete += r.loose_objects_to_delete;
                tot.packed_objects_to_delete += r.packed_objects_to_delete;
                tot.expired_snapshots_to_purge += r.expired_snapshots_to_purge;
                tot.packs_to_rewrite += r.packs_to_rewrite;
                tot.discarded_packs_to_sweep += r.discarded_packs_to_sweep;
                tot.staged_packs_to_sweep += r.staged_packs_to_sweep;
            }
            println!(
                "veil-server gc (dry run, {} projects): would delete {} loose objects, {} packed objects, {} expired snapshots; \
                 rewrite {} packs; sweep {} discarded packs, {} staged uploads",
                reports.len(),
                tot.loose_objects_to_delete,
                tot.packed_objects_to_delete,
                tot.expired_snapshots_to_purge,
                tot.packs_to_rewrite,
                tot.discarded_packs_to_sweep,
                tot.staged_packs_to_sweep,
            );
        } else {
            let reports = veil_server::pack_gc::run_offline(&hub, project.as_deref(), &opts)
                .await
                .map_err(server_err)?;
            let mut tot = veil_server::pack_gc::Report::default();
            for (name, r) in &reports {
                println!(
                    "project {name}: deleted {} loose objects, {} packed objects; merged {} packs into {} ({} objects kept); \
                     swept {} discarded packs, {} staged uploads",
                    r.loose_objects_deleted,
                    r.packed_objects_deleted,
                    r.packs_merged,
                    r.packs_written,
                    r.objects_kept,
                    r.discarded_packs_swept,
                    r.staged_packs_swept,
                );
                tot.packs_merged += r.packs_merged;
                tot.packs_written += r.packs_written;
                tot.objects_kept += r.objects_kept;
                tot.packed_objects_deleted += r.packed_objects_deleted;
                tot.loose_objects_deleted += r.loose_objects_deleted;
                tot.discarded_packs_swept += r.discarded_packs_swept;
                tot.staged_packs_swept += r.staged_packs_swept;
            }
            println!(
                "veil-server gc ({} projects): deleted {} loose objects, {} packed objects; merged {} packs into {}; \
                 swept {} discarded packs, {} staged uploads",
                reports.len(),
                tot.loose_objects_deleted,
                tot.packed_objects_deleted,
                tot.packs_merged,
                tot.packs_written,
                tot.discarded_packs_swept,
                tot.staged_packs_swept,
            );
        }
        return Ok(());
    }
    if let Some(Command::Cache { upstream, upstream_ca, token_file, dir, listen, size, memory, max_connections, tls_cert, tls_key }) = a.command {
        return cache(veil_server::cache::Config {
            listen,
            upstream,
            upstream_ca: upstream_ca.map(std::fs::read_to_string).transpose()?,
            token: std::fs::read_to_string(&token_file).map_err(|e| anyhow::anyhow!("reading {}: {e}", token_file.display()))?,
            dir,
            tls: match (tls_cert, tls_key) {
                (Some(cert), Some(key)) => TlsSource::Files { cert, key },
                _ => TlsSource::SelfSigned,
            },
            size,
            memory,
            max_connections,
        })
        .await;
    }
    let data = a.data.expect("clap requires --data");
    let env_layout = match std::env::var("VEIL_OBJECT_LAYOUT") {
        Ok(s) => Some(s),
        Err(std::env::VarError::NotPresent) => None,
        Err(e) => anyhow::bail!("VEIL_OBJECT_LAYOUT: {e}"),
    };
    let object_layout = object_layout(a.object_layout, env_layout.as_deref())?;
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
        object_layout,
        tls,
        data_dir: data.clone(),
        session_ttl: Duration::from_secs(a.session_seconds),
        db_connections: a.db_connections,
        catch_up_at_start: true,
        limits: veil_server::limits::Settings {
            device: a.device_rate,
            anonymous: a.anonymous_rate,
            max_connections: a.max_connections,
            request_memory: a.request_memory,
            ..Default::default()
        },
    })
    .await?;
    println!("veil-server listening on https://{}", running.addr);
    println!("object layout: {}", running.hub.objects.layout());
    if matches!(running.cert_pem.as_str(), s if !s.is_empty()) {
        println!("certificate: {}", data.join("self-signed-cert.pem").display());
    }
    let hub = running.hub.clone();
    let mut usr1 = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1())?;
    // SIGTERM stops it cleanly too, as SIGINT does (BUG-1970).
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut n = 0u64;
    // Written once at start: it says this server answers SIGUSR1.
    let _ = std::fs::write(data.join("stats.json"), serde_json::to_vec(&veil_server::stats_json(&hub, 0))?);
    loop {
        tokio::select! {
            r = tokio::signal::ctrl_c() => { r?; break; }
            _ = term.recv() => break,
            _ = usr1.recv() => {
                n += 1;
                let path = data.join("stats.json");
                let tmp = data.join("stats.json.tmp");
                let written = std::fs::write(&tmp, serde_json::to_vec(&veil_server::stats_json(&hub, n))?).and_then(|_| std::fs::rename(&tmp, &path));
                if let Err(e) = written {
                    eprintln!("veil-server: writing {}: {e}", path.display());
                }
            }
        }
    }
    running.stop().await;
    Ok(())
}

/// Run a regional cache until interrupted; `SIGUSR1` writes its counters to
/// `DIR/stats.json`.
async fn cache(config: veil_server::cache::Config) -> anyhow::Result<()> {
    let dir = config.dir.clone();
    let running = veil_server::cache::start(config).await?;
    println!("veil-server cache listening on https://{}", running.addr);
    let mut usr1 = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1())?;
    let write = |n: u64| {
        let mut v = veil_server::cache::stats_json(&running.cache);
        v["n"] = n.into();
        let (path, tmp) = (dir.join("stats.json"), dir.join("stats.json.tmp"));
        if let Err(e) = std::fs::write(&tmp, v.to_string()).and_then(|_| std::fs::rename(&tmp, &path)) {
            eprintln!("veil-server cache: writing {}: {e}", path.display());
        }
    };
    write(0);
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut n = 0;
    loop {
        tokio::select! {
            r = tokio::signal::ctrl_c() => { r?; break; }
            _ = term.recv() => break,
            _ = usr1.recv() => { n += 1; write(n); }
        }
    }
    running.stop().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::ffi::{c_char, c_int, c_void, CString};

    extern "C" {
        // jemalloc's own (tikv-jemalloc-sys, prefixed): read a setting.
        fn _rjem_mallctl(name: *const c_char, oldp: *mut c_void, oldlenp: *mut usize, newp: *mut c_void, newlen: usize) -> c_int;
    }

    fn read<T: Default>(name: &str) -> T {
        let n = CString::new(name).unwrap();
        let mut v = T::default();
        let mut len = std::mem::size_of::<T>();
        // SAFETY: `v` is a `T` of `len` bytes, the size jemalloc's setting has.
        let r = unsafe { _rjem_mallctl(n.as_ptr(), &mut v as *mut T as *mut c_void, &mut len, std::ptr::null_mut(), 0) };
        assert_eq!((r, len), (0, std::mem::size_of::<T>()), "reading {name}");
        v
    }

    /// BUG-2456: every one of [`super::MALLOC_CONF`]'s settings took (a
    /// setting jemalloc cannot read is only warned about at start).
    #[test]
    fn bug_2456_the_allocators_settings_take() {
        assert!(std::env::var_os("_RJEM_MALLOC_CONF").is_none(), "the settings under test are the compiled ones");
        assert_eq!(read::<u32>("opt.narenas"), 2);
        assert!(read::<bool>("opt.background_thread"));
        assert_eq!(read::<isize>("opt.dirty_decay_ms"), 250);
        assert_eq!(read::<isize>("opt.muzzy_decay_ms"), 0);
        // One page a slab for the classes up to 1,280 bytes, the default above.
        let (classes, page) = (read::<u32>("arenas.nbins"), read::<usize>("arenas.page"));
        let (mut small, mut above) = (0, 0);
        for j in 0..classes {
            let (size, slab) = (read::<usize>(&format!("arenas.bin.{j}.size")), read::<usize>(&format!("arenas.bin.{j}.slab_size")));
            if size <= 1280 {
                assert_eq!(slab, page, "the {size}-byte class's slab");
                small += 1;
            } else if size == 1536 {
                assert!(slab > page, "the {size}-byte class keeps its default slab ({slab})");
                above += 1;
            }
        }
        assert!(small >= 20 && above == 1, "{small} classes up to 1,280 bytes, {above} at 1,536");
    }

    #[test]
    fn object_layout_flag_and_env() {
        use clap::Parser;
        use veil_server::ObjectLayout::{Objects, Packs};

        assert_eq!(super::object_layout(None, None).unwrap(), Packs);
        assert_eq!(super::object_layout(None, Some("packs")).unwrap(), Packs);
        assert_eq!(super::object_layout(None, Some("objects")).unwrap(), Objects);
        assert_eq!(super::object_layout(Some(Objects), Some("packs")).unwrap(), Objects);
        assert_eq!(super::object_layout(Some(Packs), Some("objects")).unwrap(), Packs);
        let err = super::object_layout(None, Some("blobs")).unwrap_err().to_string();
        assert_eq!(err, "VEIL_OBJECT_LAYOUT: blobs: expected `packs` or `objects`");

        let parsed = super::Args::try_parse_from(["veil-server", "--data", "/tmp/h", "--object-layout", "objects"]).unwrap();
        assert_eq!(parsed.object_layout, Some(Objects));
        assert!(super::Args::try_parse_from(["veil-server", "--data", "/tmp/h", "--object-layout", "blobs"]).is_err());
    }
}
