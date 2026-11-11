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
#[test]
fn s3rd3_migration_21_clears_a_large_viewer_graph_in_bounded_time() {
    let rt = runtime();
    let (url, name) = fresh_database(&rt);
    let rows: i64 = std::env::var("VEIL_TEST_GRAPH_ROWS").ok().and_then(|v| v.parse().ok()).unwrap_or(2_000_000);
    rt.block_on(async {
        let db = veil_server::db::connect(&url, 1).await.unwrap();
        // The schema before migration 21, applied and recorded as `migrate` does.
        sqlx::raw_sql("CREATE TABLE IF NOT EXISTS schema_migrations (version BIGINT PRIMARY KEY, name TEXT NOT NULL, applied_at BIGINT NOT NULL)")
            .execute(&db)
            .await
            .unwrap();
        for (version, name, sql) in veil_server::db::MIGRATIONS.iter().filter(|m| m.0 < 21) {
            // YugabyteDB's catalog is shared: DDL can lose a race with
            // another database's, and is run again (as `migrate` does).
            let mut tries = 0;
            while let Err(e) = sqlx::raw_sql(sql).execute(&db).await {
                tries += 1;
                let retryable = e.as_database_error().and_then(|d| d.code()).is_some_and(|c| c == "40001" || c == "40P01");
                assert!(retryable && tries < 50, "migration {version}: {e}");
                tokio::time::sleep(Duration::from_millis(200)).await;
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
        while lo < rows {
            let hi = (lo + batch).min(rows);
            sqlx::query(
                "INSERT INTO view_graph (project_id, view_key, snapshot, generation, depth, parents, flags, skip, down_id, real_id) \
                 SELECT 1 + i % 4, 'k' || (i % 12), md5(i::text) || md5((i + 1)::text), i, i, '[]', 0, '[]', '', '' \
                 FROM generate_series($1::BIGINT, $2::BIGINT - 1) i",
            )
            .bind(lo)
            .bind(hi)
            .execute(&db)
            .await
            .unwrap();
            lo = hi;
        }
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM view_graph").fetch_one(&db).await.unwrap();
        assert_eq!(n, rows);
        db.close().await;
    });
    let started = std::time::Instant::now();
    let migrated = rt.block_on(async {
        let opts: sqlx::postgres::PgConnectOptions = url.parse().unwrap();
        let opts = opts.options([("statement_timeout", "250"), ("lock_timeout", "250")]);
        let pool = sqlx::postgres::PgPoolOptions::new().max_connections(1).connect_with(opts).await.unwrap();
        let r = tokio::time::timeout(Duration::from_secs(60), veil_server::db::migrate(&pool)).await;
        pool.close().await;
        r
    });
    let took = started.elapsed();
    assert!(
        matches!(migrated, Ok(Ok(()))),
        "migrating {rows} viewer graph rows under a 250 ms statement timeout did not finish within 60 s ({took:?}): {:?}",
        migrated.map(|r| r.map_err(|e| e.to_string()))
    );
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

impl TlsDatabase {
    fn start(rt: &tokio::runtime::Runtime, url: &str) -> TlsDatabase {
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
        let cert = CertificateParams::new(vec!["localhost".to_string()]).unwrap().signed_by(&key, &Issuer::from_params(&ca_params, &ca_key)).unwrap();
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
/// no TLS, as before. (`verify-ca` should not check the name: BUG-1909.)
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

/// BUG-1909: `sslmode=verify-ca` is to check that the database's
/// certificate is the CA's and nothing about its name (a database reached
/// by an address or a private name its certificate does not carry). sqlx
/// 0.8.6 forgives only the name error older rustls versions gave, so with
/// the rustls in the tree (0.23.46) `verify-ca` refuses what `verify-full`
/// refuses. It fails closed: nothing is accepted that should not be.
#[test]
#[ignore = "BUG-1909: sslmode=verify-ca also checks the certificate's name (sqlx 0.8.6 with rustls 0.23.46), so it refuses a database reached by a name its certificate lacks"]
fn bug_1909_verify_ca_does_not_check_the_certificates_name() {
    let rt = runtime();
    let (url, name) = fresh_database(&rt);
    let tls = TlsDatabase::start(&rt, &url);
    let ca = tls.ca.display();
    // The certificate is for `localhost`; the CA is the one given.
    assert_eq!(select_one(&rt, &tls.url("127.0.0.1", &format!("sslmode=verify-ca&sslrootcert={ca}"))), Ok(1));
    assert_eq!(tls.seen(), (1, 0));
    drop_database(&rt, &name);
}
