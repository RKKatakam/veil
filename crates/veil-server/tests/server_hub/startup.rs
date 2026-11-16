//! Servers starting together, and requests while the schema changes
//! (BUG-838): migrations are applied once, by one process; a server that
//! finds the schema current runs no DDL; requests that lose a race with a
//! schema change are run again, not failed.

use std::{
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    time::Duration,
};

use serde_json::json;
use veil_core::Identity;

use crate::support::*;

/// A new, empty database on the test server, as a URL (with `user` and
/// `password` when given). Left behind; its name starts with
/// `VEIL_TEST_DB_PREFIX`, so `scripts/verify-server.sh` drops it afterwards.
fn fresh_database(rt: &tokio::runtime::Runtime) -> (String, String) {
    let admin = std::env::var("VEIL_TEST_DATABASE_URL").unwrap();
    let name = format!("{}{}", crate::support::test_db_prefix(), unique("veil_fresh_"));
    rt.block_on(async {
        let db = veil_server::db::connect(&admin, 1).await.unwrap();
        sqlx::raw_sql(&format!("CREATE DATABASE {name}")).execute(&db).await.unwrap();
        db.close().await;
    });
    let (base, _) = admin.rsplit_once('/').unwrap();
    (format!("{base}/{name}"), name)
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread().enable_all().worker_threads(2).build().unwrap()
}

#[test]
fn servers_starting_together_migrate_once() {
    let rt = runtime();
    let (url, _) = fresh_database(&rt);
    let hubs: Vec<TestHub> = std::thread::scope(|s| {
        let started: Vec<_> = (0..4).map(|_| s.spawn(|| TestHub::start_on(&url, Duration::from_secs(3600)))).collect();
        started.into_iter().map(|h| h.join().expect("every server starts")).collect()
    });
    // Each migration was applied once, and every server serves.
    rt.block_on(async {
        let db = veil_server::db::connect(&url, 1).await.unwrap();
        let rows: Vec<(i64, i64)> =
            sqlx::query_as("SELECT version, count(*) FROM schema_migrations GROUP BY version ORDER BY version").fetch_all(&db).await.unwrap();
        let want: Vec<(i64, i64)> = veil_server::db::MIGRATIONS.iter().map(|(v, _, _)| (*v, 1)).collect();
        assert_eq!(rows, want);
        assert!(veil_server::db::schema_current(&db).await.unwrap());
        db.close().await;
    });
    for h in &hubs {
        h.api().login(&Identity::generate("x"), Some(&unique("starter"))).expect("signs up");
    }
}

/// A server whose database role may only read and write rows (no DDL at
/// all) starts on a current schema and serves: starting runs no DDL.
#[test]
fn a_server_on_a_current_schema_runs_no_ddl() {
    let rt = runtime();
    let (url, name) = fresh_database(&rt);
    let role = unique("veil_dml_");
    rt.block_on(async {
        let db = veil_server::db::connect(&url, 1).await.unwrap();
        veil_server::db::migrate(&db).await.unwrap();
        for q in [
            format!("CREATE ROLE {role} LOGIN PASSWORD 'dml-only'"),
            "REVOKE CREATE ON SCHEMA public FROM PUBLIC".to_string(),
            format!("REVOKE CREATE ON DATABASE {name} FROM PUBLIC"),
            format!("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {role}"),
            format!("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {role}"),
        ] {
            // On YugabyteDB the catalog is shared: other tests' DDL can
            // abort this one (`40001`); run it again, as migrations do.
            let mut attempt = 0;
            loop {
                attempt += 1;
                match sqlx::raw_sql(&q).execute(&db).await {
                    Ok(_) => break,
                    Err(sqlx::Error::Database(e)) if e.code().as_deref() == Some("40001") && attempt < 50 => {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    Err(e) => panic!("{q}: {e}"),
                }
            }
        }
        db.close().await;
    });
    let (scheme_user, host_db) = url.split_once('@').unwrap();
    let scheme = &scheme_user[..scheme_user.find("://").unwrap() + 3];
    let hub = TestHub::start_on(&format!("{scheme}{role}:dml-only@{host_db}"), Duration::from_secs(3600));
    let api = hub.api();
    let token = api.login(&Identity::generate("x"), Some(&unique("dml"))).expect("signs up");
    let project = unique("p");
    let r = api.post_json(Some(&token), &format!("/v1/projects/{project}"), &json!({}));
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert!(api.tips(Some(&token), &project).is_some());
}

/// While a migration changes a table every request uses, requests on a
/// running server do not fail: they wait, or run again within their
/// deadline (on YugabyteDB the catalog change aborts them).
#[test]
fn requests_survive_a_schema_change() {
    let rt = runtime();
    let (url, _) = fresh_database(&rt);
    let hub = TestHub::start_on(&url, Duration::from_secs(3600));
    let api = hub.api();
    let token = api.login(&Identity::generate("x"), Some(&unique("ddl"))).unwrap();
    let project = unique("p");
    assert_eq!(api.post_json(Some(&token), &format!("/v1/projects/{project}"), &json!({})).status, 200);
    let stop = AtomicBool::new(false);
    let (done, changes) = (AtomicUsize::new(0), AtomicUsize::new(0));
    std::thread::scope(|s| {
        // Schema changes of the tables every request reads and writes.
        s.spawn(|| {
            // The workers stop when this thread ends, even by a panic.
            struct Stop<'a>(&'a AtomicBool);
            impl Drop for Stop<'_> {
                fn drop(&mut self) {
                    self.0.store(true, Ordering::Relaxed);
                }
            }
            let _stop = Stop(&stop);
            rt.block_on(async {
                let db = veil_server::db::connect(&url, 1).await.unwrap();
                let until = std::time::Instant::now() + Duration::from_secs(8);
                while std::time::Instant::now() < until {
                    for q in [
                        "ALTER TABLE sessions ALTER COLUMN expires_at SET DEFAULT 0",
                        "ALTER TABLE challenges ALTER COLUMN expires_at SET DEFAULT 0",
                        "ALTER TABLE sessions ALTER COLUMN expires_at DROP DEFAULT",
                        "ALTER TABLE challenges ALTER COLUMN expires_at DROP DEFAULT",
                    ] {
                        // A change may wait behind the requests' locks
                        // (PostgreSQL) past its lock timeout: not a failure
                        // of the requests.
                        match sqlx::raw_sql(q).execute(&db).await {
                            Ok(_) => {
                                changes.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(e) => eprintln!("schema change {q}: {e}"),
                        }
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                }
                db.close().await;
            });
        });
        for i in 0..6 {
            let (api, token, project, stop, done) = (&api, &token, &project, &stop, &done);
            s.spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    // Signed-in reads (the session table), and sign-ins
                    // (challenges and sessions written).
                    let t = api.get(Some(token), &format!("/v1/projects/{project}/tips"));
                    assert_eq!(t.status, 200, "tips: {}", String::from_utf8_lossy(&t.body));
                    if i % 2 == 0 {
                        api.login(&Identity::generate("x"), Some(&unique("ddl"))).unwrap_or_else(|r| panic!("login: {r:?}"));
                    }
                    done.fetch_add(1, Ordering::Relaxed);
                }
            });
        }
    });
    eprintln!("{} requests, {} schema changes", done.load(Ordering::Relaxed), changes.load(Ordering::Relaxed));
    assert!(changes.load(Ordering::Relaxed) >= 4 && done.load(Ordering::Relaxed) > 0);
}

/// The statement and lock timeout `s3rd3_migration_21_…` migrates under on
/// YugabyteDB (BUG-2521): above what its DDL costs on a loaded cluster,
/// far below what a clear growing with the table takes there.
const YB_MIGRATION_TIMEOUT: Duration = Duration::from_secs(3);

/// BUG-1383 (S3 redesign, cycle 3; property 4: the migration's cache clear
/// runs in bounded time on large tables). Migration 21 (19 when it was
/// filed) cleared the viewer graph with `DELETE FROM view_graph`, one
/// statement whose time grows with
/// the table, inside the migration's transaction, under every connection's
/// `statement_timeout` (`db::STATEMENT_TIMEOUT`, 15 s). Past what the
/// database deletes in that time (a few million rows on PostgreSQL, far
/// fewer on YugabyteDB: one row per projected snapshot and view key, so a
/// large project's graph for a dozen view keys), the statement is cancelled
/// (`57014`, which `migrate` runs again, the same way, until its ten-minute
/// deadline), and `veil-server migrate` never finishes: no server of the
/// release starts. Scaled down here: `VEIL_TEST_GRAPH_ROWS` rows (default
/// 2,000,000) and a statement timeout of 250 ms, the same ratio of rows to
/// time as 120 million rows in 15 s, or fewer on a slower disk. A clear
/// whose time does not grow with the table (`TRUNCATE`) finishes.
///
/// On YugabyteDB the timeout is [`YB_MIGRATION_TIMEOUT`] (BUG-2521): every
/// DDL statement there has a fixed cost, the catalog change, whatever its
/// table's size (on empty tables of the shared cluster, `CREATE TABLE` 100
/// to 840 ms, `ALTER TABLE` up to 400 ms, under load), and a migration
/// whose transaction times out is rolled back whole: under 250 ms the
/// migrations after 21 were begun again and again on statements that do
/// not grow with any table, and did not finish. 3 s still separates the
/// two clears: with `DELETE FROM view_graph` in migration 21 the test fails
/// there (checked), the delete of the 2,000,000 rows taking 22.7 s.
#[test]
fn s3rd3_migration_21_clears_a_large_viewer_graph_in_bounded_time() {
    let rt = runtime();
    let (url, name) = fresh_database(&rt);
    let rows: i64 = std::env::var("VEIL_TEST_GRAPH_ROWS").ok().and_then(|v| v.parse().ok()).unwrap_or(2_000_000);
    let timeout = rt.block_on(async {
        let db = veil_server::db::connect(&url, 1).await.unwrap();
        let version: String = sqlx::query_scalar("SELECT version()").fetch_one(&db).await.unwrap();
        let timeout = if veil_server::db::is_yugabyte(&version) { YB_MIGRATION_TIMEOUT } else { Duration::from_millis(250) };
        // The schema before migration 21, applied and recorded as `migrate` does.
        sqlx::raw_sql("CREATE TABLE IF NOT EXISTS schema_migrations (version BIGINT PRIMARY KEY, name TEXT NOT NULL, applied_at BIGINT NOT NULL)")
            .execute(&db)
            .await
            .unwrap();
        for (version, name, sql) in veil_server::db::MIGRATIONS.iter().filter(|m| m.0 < 21) {
            // Its statements, then its online index steps one by one
            // (BUG-2482), on an empty database.
            let parts = veil_server::db::migration_parts(sql).unwrap();
            let steps = parts.online.iter().map(|s| match s {
                veil_server::db::IndexStep::Create { sql, .. } => sql.clone(),
                veil_server::db::IndexStep::Drop { name } => format!("DROP INDEX IF EXISTS {name}"),
            });
            for sql in std::iter::once(parts.transactional.to_string()).chain(steps) {
                // YugabyteDB's catalog is shared: DDL can lose a race with
                // another database's, and is run again (as `migrate` does).
                let mut tries = 0;
                while let Err(e) = sqlx::raw_sql(&sql).execute(&db).await {
                    tries += 1;
                    let retryable = e.as_database_error().and_then(|d| d.code()).is_some_and(|c| c == "40001" || c == "40P01");
                    assert!(retryable && tries < 50, "migration {version}: {e}");
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }
            sqlx::query("INSERT INTO schema_migrations (version, name, applied_at) VALUES ($1, $2, 0)")
                .bind(version)
                .bind(name)
                .execute(&db)
                .await
                .unwrap();
        }
        assert!(!veil_server::db::schema_current(&db).await.unwrap(), "migration 21 is still to apply");
        // A large viewer graph, a batch per statement.
        let batch = 100_000i64;
        let mut lo = 0i64;
        let mut insert_tries = 0;
        while lo < rows {
            let hi = (lo + batch).min(rows);
            let inserted = sqlx::query(
                "INSERT INTO view_graph (project_id, view_key, snapshot, generation, depth, parents, flags, skip, down_id, real_id) \
                 SELECT 1 + i % 4, 'k' || (i % 12), md5(i::text) || md5((i + 1)::text), i, i, '[]', 0, '[]', '', '' \
                 FROM generate_series($1::BIGINT, $2::BIGINT - 1) i",
            )
            .bind(lo)
            .bind(hi)
            .execute(&db)
            .await;
            match inserted {
                Ok(_) => lo = hi,
                // YugabyteDB: another database's DDL can invalidate this
                // statement's catalog snapshot (40001); the batch did not
                // apply, so it is run again (BUG-1984).
                Err(e) => {
                    let retryable = e.as_database_error().and_then(|d| d.code()).is_some_and(|c| c == "40001" || c == "40P01");
                    insert_tries += 1;
                    assert!(retryable && insert_tries < 50, "view_graph rows {lo}..{hi}: {e}");
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }
        }
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM view_graph").fetch_one(&db).await.unwrap();
        assert_eq!(n, rows);
        db.close().await;
        timeout
    });
    let started = std::time::Instant::now();
    let migrated = rt.block_on(async {
        let opts: sqlx::postgres::PgConnectOptions = url.parse().unwrap();
        let ms = timeout.as_millis().to_string();
        let opts = opts.options([("statement_timeout", ms.as_str()), ("lock_timeout", ms.as_str())]);
        let pool = sqlx::postgres::PgPoolOptions::new().max_connections(1).connect_with(opts).await.unwrap();
        let r = tokio::time::timeout(Duration::from_secs(60), veil_server::db::migrate(&pool)).await;
        pool.close().await;
        r
    });
    let took = started.elapsed();
    assert!(
        matches!(migrated, Ok(Ok(()))),
        "migrating {rows} viewer graph rows under a {timeout:?} statement timeout did not finish within 60 s ({took:?}): {:?}",
        migrated.map(|r| r.map_err(|e| e.to_string()))
    );
    eprintln!("migrated {rows} viewer graph rows under a {timeout:?} statement timeout in {took:?}");
    rt.block_on(async {
        let db = veil_server::db::connect(&url, 1).await.unwrap();
        assert!(veil_server::db::schema_current(&db).await.unwrap());
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM view_graph").fetch_one(&db).await.unwrap();
        assert_eq!(n, 0, "the viewer graph (a cache) is cleared");
        db.close().await;
        // The test's own database goes (the shared server keeps no leftovers).
        let admin = veil_server::db::connect(&std::env::var("VEIL_TEST_DATABASE_URL").unwrap(), 1).await.unwrap();
        sqlx::raw_sql(&format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)")).execute(&admin).await.unwrap();
        admin.close().await;
    });
}

/// A PostgreSQL that requires TLS, as every managed one does: a listener in
/// front of the test database that starts TLS the way PostgreSQL does (the
/// client's `SSLRequest`, the answer `S`, then the handshake), with a
/// certificate for `localhost` signed by a private CA, and that refuses a
/// client starting without TLS, as a `pg_hba.conf` of `hostssl` lines does.
struct TlsDatabase {
    /// The database's URL without its host, port and query.
    before_host: String,
    after_port: String,
    port: u16,
    /// The private CA's certificate and another CA's (PEM files).
    ca: std::path::PathBuf,
    another_ca: std::path::PathBuf,
    /// Connections that finished a TLS handshake, and those that started
    /// without asking for one.
    over_tls: std::sync::Arc<AtomicUsize>,
    plain: std::sync::Arc<AtomicUsize>,
    _dir: tempfile::TempDir,
}

/// The certificate a [`TlsDatabase`] presents: for `localhost`, signed by
/// its CA; the same but expired; or signed by its own key.
#[derive(Clone, Copy, PartialEq)]
enum Leaf {
    Signed,
    Expired,
    SelfSigned,
}

impl TlsDatabase {
    fn start(rt: &tokio::runtime::Runtime, url: &str) -> TlsDatabase {
        Self::presenting(rt, url, Leaf::Signed)
    }

    fn presenting(rt: &tokio::runtime::Runtime, url: &str, leaf: Leaf) -> TlsDatabase {
        use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let authority = |name: &str| {
            let key = KeyPair::generate().unwrap();
            let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params.distinguished_name.push(DnType::CommonName, name);
            let pem = params.self_signed(&key).unwrap().pem();
            (params, key, pem)
        };
        let (ca_params, ca_key, ca_pem) = authority("Veil test CA");
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        if leaf == Leaf::Expired {
            (params.not_before, params.not_after) = (rcgen::date_time_ymd(2020, 1, 1), rcgen::date_time_ymd(2021, 1, 1));
        }
        let cert = match leaf {
            Leaf::SelfSigned => params.self_signed(&key).unwrap(),
            _ => params.signed_by(&key, &Issuer::from_params(&ca_params, &ca_key)).unwrap(),
        };
        let dir = tempfile::Builder::new().prefix("veil-tls-db").tempdir().unwrap();
        let (ca, another_ca) = (dir.path().join("ca.pem"), dir.path().join("another-ca.pem"));
        std::fs::write(&ca, ca_pem).unwrap();
        std::fs::write(&another_ca, authority("Another CA").2).unwrap();
        let config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], rustls::pki_types::PrivateKeyDer::try_from(key.serialize_der()).unwrap())
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config));

        // postgres://user:password@host:port/database
        let (scheme, rest) = url.split_once("://").unwrap();
        let (at, after_port) = rest.split_once('/').unwrap();
        let (user, database) = at.rsplit_once('@').map_or(("", at), |(user, host)| (user, host));
        let database = database.to_string();
        let listener = rt.block_on(tokio::net::TcpListener::bind("127.0.0.1:0")).unwrap();
        let port = listener.local_addr().unwrap().port();
        let over_tls = std::sync::Arc::new(AtomicUsize::new(0));
        let plain = std::sync::Arc::new(AtomicUsize::new(0));
        let counts = (over_tls.clone(), plain.clone());
        rt.spawn(async move {
            while let Ok((mut client, _)) = listener.accept().await {
                let (acceptor, database, (over_tls, plain)) = (acceptor.clone(), database.clone(), counts.clone());
                tokio::spawn(async move {
                    // The first message: its length, then its code (an
                    // SSLRequest is 8 bytes, code 80877103).
                    let mut first = [0u8; 8];
                    if client.read_exact(&mut first).await.is_err() {
                        return;
                    }
                    if first != [0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f] {
                        plain.fetch_add(1, Ordering::SeqCst);
                        let rest = (u32::from_be_bytes(first[..4].try_into().unwrap()) as usize).saturating_sub(8).min(1 << 16);
                        let _ = client.read_exact(&mut vec![0u8; rest]).await;
                        let fields = b"SFATAL\0VFATAL\0C28000\0Mno pg_hba.conf entry for this host, no encryption\0\0";
                        let mut refusal = vec![b'E'];
                        refusal.extend((fields.len() as u32 + 4).to_be_bytes());
                        refusal.extend(fields);
                        let _ = client.write_all(&refusal).await;
                        let _ = client.shutdown().await;
                        return;
                    }
                    if client.write_all(b"S").await.is_err() {
                        return;
                    }
                    let Ok(mut client) = acceptor.accept(client).await else { return };
                    over_tls.fetch_add(1, Ordering::SeqCst);
                    let Ok(mut database) = tokio::net::TcpStream::connect(&database).await else { return };
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut database).await;
                });
            }
        });
        let before_host = if user.is_empty() { format!("{scheme}://") } else { format!("{scheme}://{user}@") };
        TlsDatabase { before_host, after_port: after_port.to_string(), port, ca, another_ca, over_tls, plain, _dir: dir }
    }

    /// The database's URL through this listener, by the name `host`.
    fn url(&self, host: &str, query: &str) -> String {
        let query = if query.is_empty() { String::new() } else { format!("?{query}") };
        format!("{}{host}:{}/{}{query}", self.before_host, self.port, self.after_port)
    }

    /// (connections over TLS, connections that began without it) so far.
    fn seen(&self) -> (usize, usize) {
        (self.over_tls.load(Ordering::SeqCst), self.plain.load(Ordering::SeqCst))
    }
}

/// `SELECT 1` over a pool of the server's, opened on `url`.
fn select_one(rt: &tokio::runtime::Runtime, url: &str) -> Result<i64, String> {
    rt.block_on(async {
        let db = veil_server::db::connect(url, 1).await.map_err(|e| format!("{e:#}"))?;
        let one = sqlx::query_scalar("SELECT 1::BIGINT").fetch_one(&db).await.map_err(|e| e.to_string());
        db.close().await;
        one
    })
}

fn drop_database(rt: &tokio::runtime::Runtime, name: &str) {
    rt.block_on(async {
        let admin = veil_server::db::connect(&std::env::var("VEIL_TEST_DATABASE_URL").unwrap(), 1).await.unwrap();
        sqlx::raw_sql(&format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)")).execute(&admin).await.unwrap();
        admin.close().await;
    });
}

/// BUG-1928: an operator who asks for TLS to the database in words the
/// driver does not know got a connection with no TLS and no word about it
/// (`ssl=true`, a misspelt `sslmode`: the driver ignores parameters it does
/// not know). Each is refused before any connection is made, naming the
/// parameter and never the rest of the URL; a certificate file with no mode
/// and a mode that is no mode are refused too. The control, `sslmode=require`
/// and the verifying modes over TLS: `bug_1590_…` below.
#[test]
fn bug_1928_a_database_url_that_asks_for_tls_in_words_the_server_does_not_know_is_refused() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    // A listener that counts connections: none is made.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let connect = |query: &str| {
        let url = format!("postgres://someone:PASSWORD-9c1e@127.0.0.1:{port}/veil?{query}");
        let refused = rt.block_on(veil_server::db::connect(&url, 1)).map(|_| ()).map_err(|e| format!("{e:#}")).unwrap_err();
        assert!(!refused.contains("PASSWORD-9c1e") && !refused.contains("someone"), "the refusal names the URL: {refused}");
        assert!(listener.accept().is_err(), "a connection was made for `{query}`");
        refused
    };
    for (query, param) in [
        ("ssl=true", "ssl"),
        ("tls=1", "tls"),
        ("sslmod=require", "sslmod"),
        ("SSLMODE=require", "SSLMODE"),
        ("ssl_mode=require", "ssl_mode"),
        ("application_name=veil&useSSL=true", "useSSL"),
        ("requiressl=1", "requiressl"),
    ] {
        let refused = connect(query);
        assert!(
            refused.contains(&format!("the database URL's parameter '{param}' is not one this server knows")) && refused.contains("sslmode=require"),
            "`{query}`: {refused}"
        );
    }
    // A certificate file and no mode: the driver would not verify with it.
    if std::env::var_os("PGSSLMODE").is_none() {
        let refused = connect("sslrootcert=/nowhere/ca.pem");
        assert!(refused.contains("the database URL gives 'sslrootcert' and no sslmode"), "{refused}");
    }
    // A mode that is no mode.
    let refused = connect("sslmode=requrie");
    assert!(refused.contains("requrie"), "{refused}");
}

/// BUG-1590: the server could not use a database that requires TLS (managed
/// PostgreSQL services do: DigitalOcean's, for one). `veil-server`'s sqlx
/// was built without a TLS feature, so `sslmode=require` failed with "TLS
/// upgrade is not supported" before the handshake. Now `sslmode=require`
/// encrypts, `verify-ca` and `verify-full` also check the certificate
/// against `sslrootcert` and its name, and a URL without `sslmode` asks for
/// no TLS, as before. (`verify-ca` does not check the name: BUG-1909.)
#[test]
fn bug_1590_the_server_connects_to_a_database_that_requires_tls() {
    let rt = runtime();
    let (url, name) = fresh_database(&rt);
    let tls = TlsDatabase::start(&rt, &url);
    let (ca, another_ca) = (tls.ca.display().to_string(), tls.another_ca.display().to_string());
    let connect = |host: &str, query: &str| select_one(&rt, &tls.url(host, query));
    // `require`: encrypted, the certificate not checked (it is not for 127.0.0.1).
    assert_eq!(connect("127.0.0.1", "sslmode=require"), Ok(1));
    assert_eq!(tls.seen(), (1, 0));
    // `verify-ca`: the certificate is the private CA's.
    assert_eq!(connect("localhost", &format!("sslmode=verify-ca&sslrootcert={ca}")), Ok(1));
    assert_eq!(tls.seen(), (2, 0));
    // `verify-full`: and it names the host asked for.
    assert_eq!(connect("localhost", &format!("sslmode=verify-full&sslrootcert={ca}")), Ok(1));
    assert_eq!(tls.seen(), (3, 0));

    // A certificate for another name, of another CA, or of no public CA is refused.
    let refused = connect("127.0.0.1", &format!("sslmode=verify-full&sslrootcert={ca}")).unwrap_err();
    assert!(refused.contains("invalid peer certificate: certificate not valid for name \"127.0.0.1\""), "{refused}");
    let refused = connect("localhost", &format!("sslmode=verify-ca&sslrootcert={another_ca}")).unwrap_err();
    assert!(refused.contains("invalid peer certificate: UnknownIssuer"), "{refused}");
    let refused = connect("localhost", &format!("sslmode=verify-full&sslrootcert={another_ca}")).unwrap_err();
    assert!(refused.contains("invalid peer certificate: UnknownIssuer"), "{refused}");
    let refused = connect("localhost", "sslmode=verify-full").unwrap_err();
    assert!(refused.contains("invalid peer certificate: UnknownIssuer"), "{refused}");
    assert_eq!(tls.seen(), (3, 0), "no refused certificate carried a connection");

    // Without `sslmode` the server asks for no TLS, as before: this database refuses it.
    let refused = connect("127.0.0.1", "").unwrap_err();
    assert!(refused.contains("no pg_hba.conf entry for this host, no encryption"), "{refused}");
    assert_eq!(tls.seen(), (3, 1));

    // The whole server on it: migrations, then every pool it opens.
    let hub = TestHub::start_on(&tls.url("localhost", &format!("sslmode=verify-full&sslrootcert={ca}")), Duration::from_secs(3600));
    rt.block_on(async {
        assert!(veil_server::db::schema_current(&hub.hub().db).await.unwrap());
    });
    let (over_tls, plain) = tls.seen();
    assert!(over_tls > 3 && plain == 1, "the server's connections: {over_tls} over TLS, {plain} without");
    drop(hub);
    drop_database(&rt, &name);
}

/// BUG-1909: `sslmode=verify-ca` checks that the database's certificate is
/// the CA's and nothing about its name (a database reached by an address or
/// a private name its certificate does not carry). sqlx 0.8.6 forgave only
/// the name error older rustls versions gave, so with the rustls in the tree
/// (0.23.46) `verify-ca` refused what `verify-full` refuses; the workspace
/// patches `sqlx-core` (`vendor/sqlx-core`) to forgive both forms. A
/// certificate of another CA is still refused, whatever its name.
#[test]
fn bug_1909_verify_ca_does_not_check_the_certificates_name() {
    let rt = runtime();
    let (url, name) = fresh_database(&rt);
    let tls = TlsDatabase::start(&rt, &url);
    let (ca, another_ca) = (tls.ca.display().to_string(), tls.another_ca.display().to_string());
    // The certificate is for `localhost`; the CA is the one given.
    assert_eq!(select_one(&rt, &tls.url("127.0.0.1", &format!("sslmode=verify-ca&sslrootcert={ca}"))), Ok(1));
    assert_eq!(tls.seen(), (1, 0));
    // Not the CA given, and not the name either: refused for the CA.
    let refused = select_one(&rt, &tls.url("127.0.0.1", &format!("sslmode=verify-ca&sslrootcert={another_ca}"))).unwrap_err();
    assert!(refused.contains("invalid peer certificate: UnknownIssuer"), "{refused}");
    // `verify-full` still checks the name.
    let refused = select_one(&rt, &tls.url("127.0.0.1", &format!("sslmode=verify-full&sslrootcert={ca}"))).unwrap_err();
    assert!(refused.contains("invalid peer certificate: certificate not valid for name \"127.0.0.1\""), "{refused}");
    assert_eq!(tls.seen(), (1, 0), "no refused certificate carried a connection");
    drop_database(&rt, &name);
}

/// BUG-1909's patch forgives only the name: under `verify-ca`, a database
/// whose certificate is expired, or signed by its own key rather than the CA
/// given, is refused, reached by its certificate's name or by an address.
#[test]
fn bug_1909_verify_ca_still_refuses_an_expired_or_self_signed_certificate() {
    let rt = runtime();
    let (url, name) = fresh_database(&rt);
    for (leaf, why) in [(Leaf::Expired, "invalid peer certificate: certificate expired"), (Leaf::SelfSigned, "invalid peer certificate: UnknownIssuer")] {
        let tls = TlsDatabase::presenting(&rt, &url, leaf);
        let ca = tls.ca.display().to_string();
        for host in ["localhost", "127.0.0.1"] {
            let refused = select_one(&rt, &tls.url(host, &format!("sslmode=verify-ca&sslrootcert={ca}"))).unwrap_err();
            assert!(refused.contains(why), "{host}: {refused}");
        }
        assert_eq!(tls.seen(), (0, 0), "no refused certificate carried a connection");
    }
    drop_database(&rt, &name);
}

/// BUG-2135: on a YugabyteDB whose `READ COMMITTED` is snapshot isolation
/// (tablet servers without `yb_enable_read_committed_isolation=true`) the
/// server refuses to start, naming the flag; with read committed on, and on
/// PostgreSQL (never asked), it starts.
#[test]
fn bug_2135_a_yugabytedb_without_read_committed_is_refused_at_start() {
    use veil_server::db::{is_yugabyte, isolation_refusal, read_committed_is_read_committed};
    assert_eq!(isolation_refusal("read committed"), None);
    for level in ["repeatable read", "serializable"] {
        let m = isolation_refusal(level).expect("refused");
        assert!(m.contains("--yb_enable_read_committed_isolation=true") && m.contains(level), "{m}");
    }
    assert!(is_yugabyte("PostgreSQL 15.12-YB-2025.2.8.1-b0 on x86_64-pc-linux-gnu"));
    assert!(!is_yugabyte("PostgreSQL 17.6 on x86_64-pc-linux-musl"));

    // The test database: the check passes (the test YugabyteDB runs with
    // read committed on), and on YugabyteDB it read what a READ COMMITTED
    // transaction of the server's pool runs at.
    let rt = runtime();
    let url = std::env::var("VEIL_TEST_DATABASE_URL").unwrap();
    rt.block_on(async {
        let db = veil_server::db::connect(&url, 1).await.unwrap();
        read_committed_is_read_committed(&db).await.expect("the test database runs read committed");
        let version: String = sqlx::query_scalar("SELECT version()").fetch_one(&db).await.unwrap();
        if is_yugabyte(&version) {
            let mut tx = db.begin_with("BEGIN ISOLATION LEVEL READ COMMITTED").await.unwrap();
            let level: String = sqlx::query_scalar("SELECT yb_get_effective_transaction_isolation_level()::text").fetch_one(&mut *tx).await.unwrap();
            assert_eq!(level, "read committed");
            // What a repeatable read transaction runs at is refused, as a
            // cluster without read committed runs READ COMMITTED.
            tx.rollback().await.unwrap();
            let mut tx = db.begin_with("BEGIN ISOLATION LEVEL REPEATABLE READ").await.unwrap();
            let level: String = sqlx::query_scalar("SELECT yb_get_effective_transaction_isolation_level()::text").fetch_one(&mut *tx).await.unwrap();
            tx.rollback().await.unwrap();
            assert!(isolation_refusal(&level).is_some(), "{level}");
        }
        db.close().await;
    });
}

/// Whether `e` is a database error that is run again (the codes and texts
/// of `Error::is_retryable`): on YugabyteDB other tests' DDL changes the
/// shared catalog.
fn retryable(e: &sqlx::Error) -> bool {
    e.as_database_error().is_some_and(|d| {
            matches!(d.code().as_deref(), Some("40001" | "40P01" | "55P03" | "57014"))
                || ["Restart read required", "Try again", "catalog snapshot", "catalog version", "schema version mismatch"].iter().any(|m| d.message().contains(m))
        })
}

/// `q` on `db`, run again while it fails retryably (50 tries).
async fn exec_retrying(db: &sqlx::PgPool, q: &str) {
    let mut tries = 0;
    loop {
        match sqlx::raw_sql(q).execute(db).await {
            Ok(_) => return,
            Err(e) if retryable(&e) && tries < 50 => {
                tries += 1;
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Err(e) => panic!("{q}: {e}"),
        }
    }
}

/// BUG-2482: a fresh database migrated to the current schema, then put back
/// to before migration 41 (its index dropped and its record removed), with
/// one project of `rows` packs (two thirds listed). Returns the database's
/// URL and name, the project and whether it is YugabyteDB.
fn before_migration_41(rt: &tokio::runtime::Runtime, rows: i64) -> (String, String, i64, bool) {
    let (url, name) = fresh_database(rt);
    let (project, yb) = rt.block_on(async {
        let db = veil_server::db::connect(&url, 2).await.unwrap();
        veil_server::db::migrate(&db).await.expect("migrates");
        let version: String = sqlx::query_scalar("SELECT version()").fetch_one(&db).await.unwrap();
        exec_retrying(&db, "DROP INDEX packs_listed").await;
        exec_retrying(&db, "DELETE FROM schema_migrations WHERE version = 41").await;
        assert!(!veil_server::db::schema_current(&db).await.unwrap(), "migration 41 is to apply");
        exec_retrying(&db, "INSERT INTO people (name, created_at) VALUES ('bug2482', 0)").await;
        exec_retrying(
            &db,
            "INSERT INTO projects (name, created_by, created_at, default_branch, policy_text, policy_bindings, policy_version) \
             SELECT 'bug2482', id, 0, 'main', '', '{}', 0 FROM people WHERE name = 'bug2482'",
        )
        .await;
        let project: i64 = sqlx::query_scalar("SELECT id FROM projects WHERE name = 'bug2482'").fetch_one(&db).await.unwrap();
        let batch = 100_000i64;
        let mut lo = 0;
        while lo < rows {
            let hi = (lo + batch).min(rows);
            exec_retrying(
                &db,
                &format!(
                    "INSERT INTO packs (project_id, name, state, size, objects, created_at) \
                     SELECT {project}, 'p' || i, CASE WHEN i % 3 = 0 THEN 2 ELSE 1 END, i, 1, i FROM generate_series({lo}, {hi} - 1) i"
                ),
            )
            .await;
            lo = hi;
        }
        db.close().await;
        (project, veil_server::db::is_yugabyte(&version))
    });
    (url, name, project, yb)
}

/// Whether index `name` is valid (`None`: no such index).
async fn index_valid(c: &mut sqlx::PgConnection, name: &str) -> Option<bool> {
    sqlx::query_scalar("SELECT i.indisvalid FROM pg_index i WHERE i.indexrelid = to_regclass($1)").bind(name).fetch_optional(&mut *c).await.unwrap()
}

/// The project's listed packs read through `packs_listed` (the listing's
/// statement, `pack::Packs::refresh_in`, with every other plan made dearer,
/// and the plan checked), and read without it (`state + 0 = 1` is no
/// predicate of the partial index).
async fn listed_with_and_without_the_index(url: &str, project: i64) -> (Vec<String>, Vec<String>) {
    let db = veil_server::db::connect(url, 1).await.unwrap();
    let mut c = db.acquire().await.unwrap();
    assert_eq!(index_valid(&mut c, "packs_listed").await, Some(true), "packs_listed is built and valid");
    sqlx::raw_sql("SET enable_seqscan = off; SET enable_bitmapscan = off; SET enable_sort = off").execute(&mut *c).await.unwrap();
    let listing = "SELECT name FROM packs WHERE project_id = $1 AND state = 1 ORDER BY created_at, name";
    let plan: Vec<String> = sqlx::query_scalar(&format!("EXPLAIN {}", listing.replace("$1", &project.to_string()))).fetch_all(&mut *c).await.unwrap();
    assert!(plan.iter().any(|l| l.contains("packs_listed")), "the listing reads packs_listed: {plan:#?}");
    let mut with: Vec<String> = sqlx::query_scalar(listing).bind(project).fetch_all(&mut *c).await.unwrap();
    sqlx::raw_sql("RESET enable_seqscan; RESET enable_bitmapscan; RESET enable_sort").execute(&mut *c).await.unwrap();
    let mut without: Vec<String> =
        sqlx::query_scalar("SELECT name FROM packs WHERE project_id = $1 AND state + 0 = 1").bind(project).fetch_all(&mut *c).await.unwrap();
    drop(c);
    db.close().await;
    with.sort();
    without.sort();
    (with, without)
}

/// BUG-2482: migration 41's index, applied by two servers starting at once
/// on a large table that other connections keep writing, and under a
/// statement timeout shorter than its build (250 ms, against the build of
/// 4,000,000 rows on PostgreSQL, about 600 ms, or 300,000 on YugabyteDB,
/// about 4 s: the pool's is 15 s, and a large table's build takes longer).
/// Built in the migration's transaction, on PostgreSQL the build held every write off and passed the
/// timeout, so the migration was run again until its deadline and never
/// finished; on YugabyteDB it did not hold writes off, and rows written
/// during the build could be missing from it with no error. Built online:
/// both starts succeed, it is applied once, writes were made during the
/// build (begun once the index existed, done while it was not yet valid)
/// and are in it,
/// it holds every listed row (read through it, the plan checked), and the
/// connection's own timeouts are back afterwards.
#[test]
fn bug_2482_an_index_migration_on_a_large_table_written_meanwhile_holds_every_row() {
    let rt = runtime();
    let yb = rt.block_on(async {
        let db = veil_server::db::connect(&std::env::var("VEIL_TEST_DATABASE_URL").unwrap(), 1).await.unwrap();
        let v: String = sqlx::query_scalar("SELECT version()").fetch_one(&db).await.unwrap();
        db.close().await;
        veil_server::db::is_yugabyte(&v)
    });
    let rows = std::env::var("VEIL_TEST_PACK_ROWS").ok().and_then(|v| v.parse().ok()).unwrap_or(if yb { 300_000 } else { 4_000_000 });
    let (url, name, project, _) = before_migration_41(&rt, rows);
    let stop = AtomicBool::new(false);
    let during = std::sync::Mutex::new(Vec::<String>::new());
    let (results, written) = std::thread::scope(|s| {
        let writers: Vec<_> = (0..4)
            .map(|w| {
                let (url, stop, during, rt) = (&url, &stop, &during, &rt);
                s.spawn(move || {
                    rt.block_on(async {
                        let db = veil_server::db::connect(url, 1).await.unwrap();
                        let mut written = Vec::new();
                        let mut n = 0u64;
                        // The index's state as this connection reads it:
                        // `None` when it does not exist (or the read lost a
                        // race with DDL on YugabyteDB).
                        let pool = &db;
                        let state = move || async move {
                            sqlx::query_scalar::<_, bool>("SELECT i.indisvalid FROM pg_index i WHERE i.indexrelid = to_regclass('packs_listed')")
                                .fetch_optional(pool)
                                .await
                                .ok()
                                .flatten()
                        };
                        while !stop.load(Ordering::Relaxed) {
                            n += 1;
                            let name = format!("w{w}-{n}");
                            let before = state().await;
                            let r = sqlx::query("INSERT INTO packs (project_id, name, state, size, objects, created_at) VALUES ($1, $2, 1, 1, 1, $3)")
                                .bind(project)
                                .bind(&name)
                                .bind(rows + n as i64)
                                .execute(&db)
                                .await;
                            match r {
                                Ok(_) => {
                                    // Begun once the build had made the
                                    // index, done while it was not valid
                                    // yet: a write during the build.
                                    if before == Some(false) && state().await == Some(false) {
                                        during.lock().unwrap().push(name.clone());
                                    }
                                    written.push(name);
                                }
                                Err(e) => assert!(retryable(&e), "a write beside the migration failed: {e}"),
                            }
                        }
                        db.close().await;
                        written
                    })
                })
            })
            .collect();
        // Two servers' starts at once, each with a 250 ms statement and
        // lock timeout, as `veil-server` runs `migrate` (one connection).
        std::thread::sleep(Duration::from_millis(300));
        let starts: Vec<_> = (0..2)
            .map(|_| {
                let (url, rt) = (&url, &rt);
                s.spawn(move || {
                    rt.block_on(async {
                        let opts: sqlx::postgres::PgConnectOptions = url.parse().unwrap();
                        let opts = opts.options([("statement_timeout", "250"), ("lock_timeout", "250")]);
                        let pool = sqlx::postgres::PgPoolOptions::new().max_connections(1).connect_with(opts).await.unwrap();
                        let r = tokio::time::timeout(Duration::from_secs(180), veil_server::db::migrate(&pool)).await;
                        // The connection `migrate` used keeps its own timeouts.
                        let after: Option<String> = match r {
                            Ok(Ok(())) => Some(sqlx::query_scalar("SHOW statement_timeout").fetch_one(&pool).await.unwrap()),
                            _ => None,
                        };
                        pool.close().await;
                        (r.map(|r| r.map_err(|e| format!("{e:#}"))), after)
                    })
                })
            })
            .collect();
        let results: Vec<_> = starts.into_iter().map(|h| h.join().unwrap()).collect();
        std::thread::sleep(Duration::from_millis(300));
        stop.store(true, Ordering::Relaxed);
        let written: Vec<String> = writers.into_iter().flat_map(|h| h.join().unwrap()).collect();
        (results, written)
    });
    for (r, after) in &results {
        assert!(matches!(r, Ok(Ok(()))), "a start migrating beside writes under a 250 ms statement timeout: {r:?}");
        assert_eq!(after.as_deref(), Some("250ms"), "the migrating connection's statement timeout is its own again");
    }
    let during = during.into_inner().unwrap();
    assert!(!during.is_empty(), "rows were written while the index was built (begun after it existed, done before it was valid)");
    rt.block_on(async {
        let db = veil_server::db::connect(&url, 1).await.unwrap();
        let applied: i64 = sqlx::query_scalar("SELECT count(*) FROM schema_migrations WHERE version = 41").fetch_one(&db).await.unwrap();
        assert_eq!(applied, 1, "migration 41 is recorded once");
        assert!(veil_server::db::schema_current(&db).await.unwrap());
        db.close().await;
    });
    let (with, without) = rt.block_on(listed_with_and_without_the_index(&url, project));
    let missing: Vec<&String> = written.iter().filter(|n| with.binary_search(n).is_err()).collect();
    assert!(missing.is_empty(), "{} of {} rows written beside the build are missing from packs_listed: {:?}", missing.len(), written.len(), &missing[..missing.len().min(10)]);
    assert!(during.iter().all(|n| with.binary_search(n).is_ok()), "every row written during the build is in packs_listed");
    assert_eq!(with.len(), without.len(), "packs_listed holds every listed row");
    assert!(with == without, "packs_listed holds exactly the listed rows");
    eprintln!("{rows} packs; {} written beside the migration, {} during the build", written.len(), during.len());
    drop_database(&rt, &name);
}

/// BUG-2482: a concurrent build that did not finish (cancelled here by its
/// statement timeout, as a stopped server's would be) leaves its index
/// INVALID: never used, but written, and `IF NOT EXISTS` would keep it.
/// The next start drops it and builds it again: valid, holding every listed
/// row.
#[test]
fn bug_2482_an_interrupted_index_build_is_built_again_on_the_next_start() {
    let rt = runtime();
    let (url, name, project, yb) = before_migration_41(&rt, 300_000);
    let build = veil_server::db::migration_parts(veil_server::db::MIGRATIONS.iter().find(|m| m.0 == 41).unwrap().2).unwrap().online;
    let veil_server::db::IndexStep::Create { sql, .. } = &build[0] else { panic!("migration 41 builds packs_listed: {build:?}") };
    let left_invalid = rt.block_on(async {
        let db = veil_server::db::connect(&url, 1).await.unwrap();
        let mut c = db.acquire().await.unwrap();
        let mut left = None;
        for ms in [5, 10, 20, 50, 100, 200, 500, 1000, 2000] {
            sqlx::raw_sql(&format!("SET statement_timeout = {ms}")).execute(&mut *c).await.unwrap();
            let r = sqlx::raw_sql(sql).execute(&mut *c).await;
            sqlx::raw_sql("RESET statement_timeout").execute(&mut *c).await.unwrap();
            match index_valid(&mut c, "packs_listed").await {
                Some(false) => {
                    assert!(r.is_err(), "a build that left its index invalid failed");
                    left = Some(ms);
                    break;
                }
                Some(true) => panic!("the build finished within {ms} ms: no build to interrupt (more rows)"),
                None => {}
            }
        }
        drop(c);
        db.close().await;
        left
    });
    assert!(left_invalid.is_some(), "a cancelled build left packs_listed invalid (yugabyte: {yb})");
    rt.block_on(async {
        let db = veil_server::db::connect(&url, 2).await.unwrap();
        veil_server::db::migrate(&db).await.expect("the next start migrates");
        let applied: i64 = sqlx::query_scalar("SELECT count(*) FROM schema_migrations WHERE version = 41").fetch_one(&db).await.unwrap();
        assert_eq!(applied, 1);
        db.close().await;
    });
    let (with, without) = rt.block_on(listed_with_and_without_the_index(&url, project));
    assert_eq!(with.len(), 200_000, "two thirds of the 300,000 packs are listed");
    assert!(with == without, "the index built again holds exactly the listed rows");
    drop_database(&rt, &name);
}

/// BUG-2482, the class: every index a migration builds on a table that
/// existed before it is built online (in its `db::ONLINE_INDEXES`
/// section); an index in a migration's transaction is on a table the same
/// migration creates, which no running server writes. Every online section
/// holds only index steps, and the section's own checks refuse what is not
/// one.
#[test]
fn bug_2482_every_index_on_an_existing_table_is_built_online() {
    use veil_server::db::{migration_parts, IndexStep, ONLINE_INDEXES, MIGRATIONS};
    let words = |sql: &str| -> Vec<String> {
        sql.lines().map(|l| l.split("--").next().unwrap()).collect::<Vec<_>>().join(" ").split_whitespace().map(str::to_string).collect()
    };
    let mut online = Vec::new();
    for (version, name, sql) in MIGRATIONS {
        let parts = migration_parts(sql).unwrap_or_else(|e| panic!("migration {version} ({name}): {e}"));
        let w = words(parts.transactional);
        let created: Vec<&str> = w
            .windows(6)
            .filter(|x| x[..5] == ["CREATE", "TABLE", "IF", "NOT", "EXISTS"])
            .map(|x| x[5].trim_end_matches('('))
            .collect();
        for (i, word) in w.iter().enumerate() {
            if word == "INDEX" && i > 0 && (w[i - 1] == "CREATE" || (w[i - 1] == "UNIQUE" && i > 1 && w[i - 2] == "CREATE")) {
                let on = w[i..].iter().position(|x| x == "ON").map(|p| w[i + p + 1].as_str()).unwrap_or_else(|| panic!("migration {version}: an index on nothing"));
                assert!(created.contains(&on), "migration {version} ({name}) builds an index on {on}, a table it did not create, in its transaction");
            }
            if word == "ALTER" {
                let stmt: Vec<&String> = w[i..].iter().take_while(|x| !x.ends_with(';')).collect();
                assert!(
                    !stmt.iter().any(|x| ["UNIQUE", "PRIMARY", "EXCLUDE"].contains(&x.trim_matches(|c: char| !c.is_ascii_alphabetic()))),
                    "migration {version} ({name}) adds an index-backed constraint in its transaction: {stmt:?}"
                );
            }
        }
        // A migration with an online section commits its transactional part
        // before the steps, unrecorded: a step that fails runs it all again.
        if !parts.online.is_empty() {
            if let Some(stmt) = not_safe_to_run_again(parts.transactional) {
                panic!("migration {version} ({name}) has an online indexes section, and its transactional part is not safe to run again: {stmt}");
            }
        }
        online.extend(parts.online.into_iter().map(|s| (*version, s)));
    }
    // What the check above refuses, and what it lets through.
    for good in [
        "ALTER TABLE t ADD COLUMN IF NOT EXISTS a INT, ADD COLUMN IF NOT EXISTS b INT;",
        "CREATE TABLE IF NOT EXISTS t (a INT); CREATE UNIQUE INDEX IF NOT EXISTS t_a ON t (a); CREATE SEQUENCE IF NOT EXISTS s;",
        "INSERT INTO t VALUES (1) ON CONFLICT DO NOTHING; DROP INDEX IF EXISTS t_old; -- UPDATE t SET a = 1;",
    ] {
        assert_eq!(not_safe_to_run_again(good), None, "{good}");
    }
    for bad in [
        "INSERT INTO t VALUES (1);",
        "UPDATE t SET a = 1;",
        "ALTER TABLE t ADD COLUMN a INT;",
        "ALTER TABLE t ADD COLUMN IF NOT EXISTS a INT, ADD COLUMN b INT;",
        "ALTER TABLE t ADD a INT;",
        "CREATE TABLE t (a INT);",
        "CREATE INDEX t_a ON t (a);",
        "CREATE UNIQUE INDEX t_a ON t (a);",
        "CREATE SEQUENCE s;",
        "DROP INDEX t_a;",
    ] {
        assert!(not_safe_to_run_again(bad).is_some(), "refused: {bad}");
    }
    let created: Vec<(i64, &str)> = online
        .iter()
        .filter_map(|(v, s)| match s {
            IndexStep::Create { name, .. } => Some((*v, name.as_str())),
            IndexStep::Drop { .. } => None,
        })
        .collect();
    for want in [(3, "devices_by_fingerprint"), (11, "projections_own"), (36, "landing_queue_person_slot"), (40, "packs_unlisted"), (41, "packs_listed")] {
        assert!(created.contains(&want), "{want:?} is built online: {created:?}");
    }
    // What an online section may hold, and what it may not.
    let section = |body: &str| format!("ALTER TABLE t ADD COLUMN IF NOT EXISTS a INT;\n{ONLINE_INDEXES}\n{body}");
    let ok = section("-- a comment\nCREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS t_a\n    ON t (a) WHERE a > 0;\nDROP INDEX CONCURRENTLY IF EXISTS t_old;\n");
    let parts = migration_parts(&ok).expect("a well-formed section");
    assert_eq!(parts.transactional, "ALTER TABLE t ADD COLUMN IF NOT EXISTS a INT;\n");
    assert_eq!(
        parts.online,
        vec![
            IndexStep::Create { name: "t_a".into(), sql: "CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS t_a\n    ON t (a) WHERE a > 0".into() },
            IndexStep::Drop { name: "t_old".into() },
        ]
    );
    for bad in [
        "CREATE INDEX IF NOT EXISTS t_a ON t (a);",
        "CREATE INDEX CONCURRENTLY t_a ON t (a);",
        "ALTER TABLE t ADD COLUMN b INT;",
        "DROP INDEX IF EXISTS t_a;",
        "CREATE INDEX CONCURRENTLY IF NOT EXISTS T_A ON t (a);",
        "CREATE INDEX CONCURRENTLY IF NOT EXISTS t_a ON t (a) -- why\n;",
        "CREATE INDEX CONCURRENTLY IF NOT EXISTS t_a ON t (a)",
        "-- nothing\n",
        &format!("CREATE INDEX CONCURRENTLY IF NOT EXISTS t_a ON t (a);\n{ONLINE_INDEXES}\n"),
    ] {
        assert!(migration_parts(&section(bad)).is_err(), "refused: {bad}");
    }
}

/// The first statement of `sql` that would not do the same when run again
/// on what it made (BUG-2482 review): an `INSERT` without `ON CONFLICT`, an
/// `UPDATE`, an `ADD COLUMN`, `CREATE TABLE`, `CREATE INDEX` or `CREATE
/// SEQUENCE` without `IF NOT EXISTS`, a `DROP` without `IF EXISTS`.
fn not_safe_to_run_again(sql: &str) -> Option<String> {
    let text: String = sql.lines().map(|l| l.split("--").next().unwrap()).collect::<Vec<_>>().join(" ");
    for stmt in text.split(';') {
        let w: Vec<String> = stmt.split_whitespace().map(|x| x.to_ascii_uppercase()).collect();
        let at = |i: usize, want: &[&str]| w.len() >= i + want.len() && w[i..i + want.len()].iter().zip(want).all(|(a, b)| a == b);
        let refused = match w.first().map(String::as_str) {
            None => false,
            Some("INSERT") => !w.windows(2).any(|x| x[0] == "ON" && x[1] == "CONFLICT"),
            Some("UPDATE") => true,
            Some("DROP") => !at(2, &["IF", "EXISTS"]),
            Some("CREATE") => {
                let what = if at(1, &["UNIQUE"]) { 2 } else { 1 };
                ["TABLE", "INDEX", "SEQUENCE"].contains(&w[what].as_str()) && !at(what + 1, &["IF", "NOT", "EXISTS"])
            }
            Some("ALTER") => (0..w.len()).any(|i| w[i] == "ADD" && !(at(i + 1, &["COLUMN", "IF", "NOT", "EXISTS"]))),
            Some(_) => false,
        };
        if refused {
            return Some(stmt.trim().to_string());
        }
    }
    None
}
