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
        let mut c = db.acquire().await.unwrap();
        sqlx::raw_sql("SET statement_timeout = 0").execute(&mut *c).await.unwrap();
        let mut tries = 0;
        loop {
            match sqlx::raw_sql(&format!("CREATE DATABASE {name}")).execute(&mut *c).await {
                Ok(_) => break,
                Err(e) if tries > 0 && e.as_database_error().and_then(|d| d.code()).as_deref() == Some("42P04") => break,
                Err(e) if retryable(&e) && tries < 50 => {
                    tries += 1;
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                Err(e) => panic!("CREATE DATABASE {name}: {e}"),
            }
        }
        drop(c);
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
    let (url, name) = fresh_database(&rt);
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
    drop(hubs);
    drop_database(&rt, &name);
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
/// with a statement that times out is applied again from the start (its
/// trigger, `TRUNCATE` and timed-out statement are real DDL again): under
/// 250 ms the migrations after 21 were begun again and again on statements
/// that do not grow with any table, and did not finish. 3 s still separates the
/// two clears: with `DELETE FROM view_graph` in migration 21 the test fails
/// there (checked), the delete of the 2,000,000 rows taking 22.7 s.
#[test]
fn s3rd3_migration_21_clears_a_large_viewer_graph_in_bounded_time() {
    let rt = runtime();
    let (url, name) = fresh_database(&rt);
    let rows: i64 = std::env::var("VEIL_TEST_GRAPH_ROWS").ok().and_then(|v| v.parse().ok()).unwrap_or(2_000_000);
    let (timeout, yb) = rt.block_on(async {
        let db = veil_server::db::connect(&url, 1).await.unwrap();
        let version: String = sqlx::query_scalar("SELECT version()").fetch_one(&db).await.unwrap();
        let yb = veil_server::db::is_yugabyte(&version);
        let timeout = if yb { YB_MIGRATION_TIMEOUT } else { Duration::from_millis(250) };
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
        (timeout, yb)
    });
    let started = std::time::Instant::now();
    let migrated = rt.block_on(async {
        let opts: sqlx::postgres::PgConnectOptions = url.parse().unwrap();
        let ms = timeout.as_millis().to_string();
        let opts = opts.options([("statement_timeout", ms.as_str()), ("lock_timeout", ms.as_str())]);
        let pool = sqlx::postgres::PgPoolOptions::new().max_connections(1).connect_with(opts).await.unwrap();
        let r = if yb {
            // On an existing hash-sharded YugabyteDB database, migration 46 is
            // offline-only (BUG-2931); exercise online migrations 21..45 under
            // the bounded timeout, then assert 46 refuses without `--offline`.
            tokio::time::timeout(Duration::from_secs(60), veil_server::db::migrate_through(&pool, 45)).await
        } else {
            tokio::time::timeout(Duration::from_secs(60), veil_server::db::migrate(&pool)).await
        };
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
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM view_graph").fetch_one(&db).await.unwrap();
        assert_eq!(n, 0, "the viewer graph (a cache) is cleared");
        if yb {
            let err = veil_server::db::migrate(&db).await.expect_err("existing YB DB must refuse migration 46 without --offline");
            assert!(err.to_string().contains("veil-server migrate --offline"), "expected --offline refusal, got: {err:?}");
            assert!(!veil_server::db::schema_current(&db).await.unwrap());
            veil_server::db::migrate_offline(&db).await.expect("offline migration 46 completes");
        }
        assert!(veil_server::db::schema_current(&db).await.unwrap());
        db.close().await;
    });
    // The test's own database goes (the shared server keeps no leftovers).
    drop_database(&rt, &name);
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
        let mut c = admin.acquire().await.unwrap();
        sqlx::raw_sql("SET statement_timeout = 0").execute(&mut *c).await.unwrap();
        let mut tries = 0;
        loop {
            match sqlx::raw_sql(&format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)")).execute(&mut *c).await {
                Ok(_) => break,
                Err(e) if retryable(&e) && tries < 50 => {
                    tries += 1;
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                Err(e) => panic!("DROP DATABASE IF EXISTS {name} WITH (FORCE): {e}"),
            }
        }
        drop(c);
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
    before_migration_41_at(rt, rows, None)
}

/// [`before_migration_41`], migrating only through `max_version` when `Some`
/// (used on YugabyteDB when testing online migrations 1..=45 under live
/// writers before verifying that migration 46 requires `--offline`, BUG-2931).
fn before_migration_41_at(rt: &tokio::runtime::Runtime, rows: i64, max_version: Option<i64>) -> (String, String, i64, bool) {
    let (url, name) = fresh_database(rt);
    let (project, yb) = rt.block_on(async {
        let db = veil_server::db::connect(&url, 2).await.unwrap();
        match max_version {
            Some(max) => veil_server::db::migrate_through(&db, max).await.expect("migrates"),
            None => veil_server::db::migrate(&db).await.expect("migrates"),
        }
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
/// connection's own timeouts are back afterwards. On YugabyteDB, online
/// migration stops at version 45 under the live writers, asserts that
/// migration 46 refuses without `--offline` while writers are active
/// (BUG-2931), then stops the writers, runs `migrate_offline`, and checks
/// every row and rebuilt index again.
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
    let (url, name, project, _) = before_migration_41_at(&rt, rows, yb.then_some(45));
    let stop = AtomicBool::new(false);
    let during = std::sync::Mutex::new(Vec::<String>::new());
    let (results, online_46_refusal, written) = std::thread::scope(|s| {
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
                        let r = if yb {
                            tokio::time::timeout(Duration::from_secs(180), veil_server::db::migrate_through(&pool, 45)).await
                        } else {
                            tokio::time::timeout(Duration::from_secs(180), veil_server::db::migrate(&pool)).await
                        };
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
        // On YugabyteDB, while writers are still live, assert that online
        // `db::migrate` refuses migration 46 with the `--offline` message.
        let online_46_refusal = if yb {
            Some(rt.block_on(async {
                let db = veil_server::db::connect(&url, 1).await.unwrap();
                let err = veil_server::db::migrate(&db).await.expect_err("online migrate must refuse migration 46 on live YB DB");
                let current = veil_server::db::schema_current(&db).await.unwrap();
                db.close().await;
                (err.to_string(), current)
            }))
        } else {
            None
        };
        std::thread::sleep(Duration::from_millis(300));
        stop.store(true, Ordering::Relaxed);
        let written: Vec<String> = writers.into_iter().flat_map(|h| h.join().unwrap()).collect();
        (results, online_46_refusal, written)
    });
    for (r, after) in &results {
        assert!(matches!(r, Ok(Ok(()))), "a start migrating beside writes under a 250 ms statement timeout: {r:?}");
        assert_eq!(after.as_deref(), Some("250ms"), "the migrating connection's statement timeout is its own again");
    }
    if let Some((msg, current)) = &online_46_refusal {
        assert!(msg.contains("veil-server migrate --offline"), "expected --offline refusal on live YB DB, got: {msg}");
        assert!(!current, "migration 46 must not be recorded before offline run");
    }
    let during = during.into_inner().unwrap();
    assert!(!during.is_empty(), "rows were written while the index was built (begun after it existed, done before it was valid)");
    if yb {
        // Verify online migration 41 held every row before offline migration 46 runs.
        let (with_pre, without_pre) = rt.block_on(listed_with_and_without_the_index(&url, project));
        let missing_pre: Vec<&String> = written.iter().filter(|n| with_pre.binary_search(n).is_err()).collect();
        assert!(
            missing_pre.is_empty(),
            "{} of {} rows written beside the build are missing from packs_listed before 46: {:?}",
            missing_pre.len(),
            written.len(),
            &missing_pre[..missing_pre.len().min(10)]
        );
        assert!(during.iter().all(|n| with_pre.binary_search(n).is_ok()), "every row written during the build is in packs_listed");
        assert_eq!(with_pre.len(), without_pre.len(), "packs_listed holds every listed row before 46");
        assert!(with_pre == without_pre, "packs_listed holds exactly the listed rows before 46");

        // Now that writers are stopped, apply migration 46 offline.
        rt.block_on(async {
            let db = veil_server::db::connect(&url, 1).await.unwrap();
            veil_server::db::migrate_offline(&db).await.expect("offline migration 46 completes after writers stop");
            db.close().await;
        });
    }
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

/// BUG-2571: set `flag` of index `index` false in `pg_index` (in database
/// `url`, a session of its own), as YugabyteDB left an index whose build lost
/// a stage and returned success (there `indisvalid`, the last stage's).
async fn lose_stage(url: &str, index: &str, flag: &str, yb: bool) {
    set_stage(url, index, flag, false, yb).await
}

/// Set `flag` of index `index` to `to` in `pg_index`, in a session of its
/// own.
async fn set_stage(url: &str, index: &str, flag: &str, to: bool, yb: bool) {
    let db = veil_server::db::connect(url, 1).await.unwrap();
    // YugabyteDB writes its catalog by hand only when asked to. (`index`
    // and `flag` are the tests' own lower-case names.)
    let update = format!("UPDATE pg_index SET {flag} = {to} WHERE indexrelid = to_regclass('{index}')");
    let q = if yb { format!("SET yb_non_ddl_txn_for_sys_tables_allowed = on; {update}; RESET yb_non_ddl_txn_for_sys_tables_allowed") } else { update };
    let mut tries = 0;
    loop {
        match sqlx::raw_sql(&q).execute(&db).await {
            Ok(done) => {
                assert_eq!(done.rows_affected(), 1, "index {index}'s {flag} set {to}");
                break;
            }
            Err(e) if retryable(&e) && tries < 50 => {
                tries += 1;
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Err(e) => panic!("setting {index}'s {flag} {to}: {e}"),
        }
    }
    db.close().await;
}

/// BUG-2571: index `name`'s `pg_index` stages (live, ready, valid), read in
/// a session of its own; `None` when there is no such index.
async fn index_stages(url: &str, name: &str) -> Option<(bool, bool, bool)> {
    let db = veil_server::db::connect(url, 1).await.unwrap();
    let r = sqlx::query_as("SELECT i.indislive, i.indisready, i.indisvalid FROM pg_index i WHERE i.indexrelid = to_regclass($1)")
        .bind(name)
        .fetch_optional(&db)
        .await
        .unwrap();
    db.close().await;
    r
}

/// BUG-2571: on YugabyteDB an online build returned success and its index
/// stayed invalid for good (`indisvalid` false minutes later, in new
/// sessions): the last stage's catalog version increment lost a race with
/// another database's DDL, and its write was lost with no error. The runner
/// waited for the index to read valid, then failed the migration, and with
/// it the server's start. Each build of migration 41's index here returns
/// with a stage lost (the first `indisvalid`, the second `indisready`, which
/// the runner did not read at all: an index made valid with `indisready`
/// lost is read while writes leave it out); the third is left whole. The
/// start succeeds, the index was built three times, and only then was the
/// migration recorded: once, with its index live, ready and valid, holding
/// every listed row.
#[test]
fn bug_2571_an_index_whose_build_returned_it_incomplete_is_built_again_before_the_migration_is_recorded() {
    let rt = runtime();
    let (url, name, project, yb) = before_migration_41(&rt, 30_000);
    let builds = std::sync::Arc::new(AtomicUsize::new(0));
    let counted = builds.clone();
    let at = url.clone();
    let hook: Box<veil_server::db::AfterBuild> = Box::new(move |index: String| {
        let n = if index == "packs_listed" { counted.fetch_add(1, Ordering::SeqCst) } else { usize::MAX };
        let at = at.clone();
        Box::pin(async move {
            if let Some(flag) = ["indisvalid", "indisready"].get(n) {
                lose_stage(&at, &index, flag, yb).await;
            }
        })
    });
    rt.block_on(async {
        let db = veil_server::db::connect(&url, 2).await.unwrap();
        veil_server::db::migrate_with(&db, Some(&*hook)).await.expect("the start migrates");
        assert!(veil_server::db::schema_current(&db).await.unwrap(), "every migration is applied");
        let applied: i64 = sqlx::query_scalar("SELECT count(*) FROM schema_migrations WHERE version = 41").fetch_one(&db).await.unwrap();
        assert_eq!(applied, 1, "migration 41 is recorded once");
        db.close().await;
    });
    assert_eq!(builds.load(Ordering::SeqCst), 3, "packs_listed was built three times: two builds lost a stage");
    assert_eq!(rt.block_on(index_stages(&url, "packs_listed")), Some((true, true, true)), "packs_listed is live, ready and valid");
    let (with, without) = rt.block_on(listed_with_and_without_the_index(&url, project));
    assert_eq!(with.len(), 20_000, "two thirds of the 30,000 packs are listed");
    assert!(with == without, "the index built again holds exactly the listed rows");
    drop_database(&rt, &name);
}

/// BUG-2571: a build that loses a stage every time fails the start after a
/// bounded number of builds, and the migration is not recorded; the
/// incomplete index it leaves is what the next start finds (a start that
/// died, or failed, part-way): that start drops it and builds it again,
/// and records the migration with its index live, ready and valid, holding
/// every listed row.
#[test]
fn bug_2571_an_index_no_build_made_whole_fails_the_start_unrecorded_and_the_next_start_builds_it() {
    let rt = runtime();
    let (url, name, project, yb) = before_migration_41(&rt, 30_000);
    let builds = std::sync::Arc::new(AtomicUsize::new(0));
    let counted = builds.clone();
    let at = url.clone();
    let hook: Box<veil_server::db::AfterBuild> = Box::new(move |index: String| {
        let lost = index == "packs_listed";
        if lost {
            counted.fetch_add(1, Ordering::SeqCst);
        }
        let at = at.clone();
        Box::pin(async move {
            if lost {
                lose_stage(&at, &index, "indisvalid", yb).await;
            }
        })
    });
    rt.block_on(async {
        let db = veil_server::db::connect(&url, 2).await.unwrap();
        let e = veil_server::db::migrate_with(&db, Some(&*hook)).await.expect_err("no build made packs_listed whole: the start fails");
        assert_eq!(
            e.to_string(),
            "index packs_listed is not built whole (live, ready and valid within 15s of its build, and holding its table's \
             rows) in 5 builds: the migration is not recorded, and the next start builds the index again"
        );
        assert!(!veil_server::db::schema_current(&db).await.unwrap(), "migration 41 is not applied");
        let applied: i64 = sqlx::query_scalar("SELECT count(*) FROM schema_migrations WHERE version = 41").fetch_one(&db).await.unwrap();
        assert_eq!(applied, 0, "migration 41 is not recorded");
        db.close().await;
    });
    assert_eq!(builds.load(Ordering::SeqCst), 5, "packs_listed was built five times");
    assert_eq!(rt.block_on(index_stages(&url, "packs_listed")), Some((true, true, false)), "the failed start left packs_listed invalid");
    rt.block_on(async {
        let db = veil_server::db::connect(&url, 2).await.unwrap();
        veil_server::db::migrate(&db).await.expect("the next start migrates");
        assert!(veil_server::db::schema_current(&db).await.unwrap(), "every migration is applied");
        let applied: i64 = sqlx::query_scalar("SELECT count(*) FROM schema_migrations WHERE version = 41").fetch_one(&db).await.unwrap();
        assert_eq!(applied, 1, "migration 41 is recorded once");
        db.close().await;
    });
    assert_eq!(rt.block_on(index_stages(&url, "packs_listed")), Some((true, true, true)), "packs_listed is live, ready and valid");
    let (with, without) = rt.block_on(listed_with_and_without_the_index(&url, project));
    assert_eq!(with.len(), 20_000, "two thirds of the 30,000 packs are listed");
    assert!(with == without, "the index built again holds exactly the listed rows");
    drop_database(&rt, &name);
}

/// Whether the test database is YugabyteDB.
fn on_yugabyte(rt: &tokio::runtime::Runtime) -> bool {
    rt.block_on(async {
        let db = veil_server::db::connect(&std::env::var("VEIL_TEST_DATABASE_URL").unwrap(), 1).await.unwrap();
        let v: String = sqlx::query_scalar("SELECT version()").fetch_one(&db).await.unwrap();
        db.close().await;
        veil_server::db::is_yugabyte(&v)
    })
}

/// BUG-2626: the indexes the runner built for its wait for every session
/// (`db::wait_for_every_session`: on `schema_migrations`, named
/// `veil_settle_` and sixteen hex digits) that are still in the catalog.
async fn settle_indexes_left(url: &str) -> Vec<String> {
    let db = veil_server::db::connect(url, 1).await.unwrap();
    let left = sqlx::query_scalar("SELECT c.relname::text FROM pg_class c JOIN pg_index i ON i.indexrelid = c.oid WHERE c.relname LIKE 'veil\\_settle\\_%'")
        .fetch_all(&db)
        .await
        .unwrap();
    db.close().await;
    left
}

/// BUG-2626: leave `packs_listed` as a YugabyteDB build left it: built by
/// its flags, and without rows other sessions wrote beside the build. A
/// session that reads the index not ready for writes inserts `rows` listed
/// packs named `<tag><i>` in `project`; then the index reads ready again.
/// Checked: the index is built, and exactly those rows are missing from it.
async fn rows_written_beside_the_build_are_missing(url: &str, project: i64, tag: &str, rows: usize) {
    let before = listed_with_and_without_the_index(url, project).await;
    assert!(before.0 == before.1, "the build itself left packs_listed whole");
    set_stage(url, "packs_listed", "indisready", false, true).await;
    // A new session: it reads the index as the catalog now has it.
    let db = veil_server::db::connect(url, 1).await.unwrap();
    exec_retrying(
        &db,
        &format!(
            "INSERT INTO packs (project_id, name, state, size, objects, created_at) \
             SELECT {project}, '{tag}' || i, 1, i, 1, i FROM generate_series(1, {rows}) i"
        ),
    )
    .await;
    db.close().await;
    set_stage(url, "packs_listed", "indisready", true, true).await;
    assert_eq!(index_stages(url, "packs_listed").await, Some((true, true, true)), "packs_listed reads live, ready and valid");
    let (with, without) = listed_with_and_without_the_index(url, project).await;
    let missing: Vec<&String> = without.iter().filter(|n| with.binary_search(n).is_err()).collect();
    assert_eq!(missing.len(), rows, "the rows written beside the build are missing from packs_listed");
    assert!(missing.iter().all(|n| n.starts_with(tag)), "only those rows are missing");
    assert_eq!(with.len() + rows, without.len(), "and the index holds no other row");
}

/// [`rows_written_beside_the_build_are_missing`], run to its end from a
/// migration hook (whose future must be `Send`; that one's is not, for
/// sqlx's executors).
fn miss_rows_written_beside_the_build(url: &str, project: i64, tag: &str, rows: usize) {
    tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(rows_written_beside_the_build_are_missing(url, project, tag, rows)))
}

/// BUG-2626: on YugabyteDB an online build ended with its index live, ready
/// and valid, and without the rows two sessions inserted during its
/// backfill (42,471 of 698,266 in one build of twelve, beside DDL in other
/// databases; in `bug_2482_…holds_every_row`, 1,504 of 9,011): the runner
/// read the three flags, recorded the migration, and the listing read an
/// index that did not hold every listed pack. Here the first build of
/// migration 41's index returns so (50 listed packs written by a session
/// that did not write the index, the flags all set); the second is left
/// whole. The start succeeds, the index was built twice, and only then was
/// the migration recorded: once, with an index that holds every listed
/// row, those 50 among them.
///
/// YugabyteDB only: PostgreSQL's online build waits for every transaction
/// that could write the table without the index, and the runner checks
/// nothing there.
#[test]
fn bug_2626_an_index_built_without_rows_written_beside_its_build_is_built_again_before_the_migration_is_recorded() {
    let rt = runtime();
    if !on_yugabyte(&rt) {
        return;
    }
    let (url, name, project, _) = before_migration_41(&rt, 30_000);
    let builds = std::sync::Arc::new(AtomicUsize::new(0));
    let counted = builds.clone();
    let at = url.clone();
    let hook: Box<veil_server::db::AfterBuild> = Box::new(move |index: String| {
        let n = if index == "packs_listed" { counted.fetch_add(1, Ordering::SeqCst) } else { usize::MAX };
        let at = at.clone();
        Box::pin(async move {
            if n == 0 {
                miss_rows_written_beside_the_build(&at, project, "beside-", 50);
            }
        })
    });
    rt.block_on(async {
        let db = veil_server::db::connect(&url, 2).await.unwrap();
        veil_server::db::migrate_with(&db, Some(&*hook)).await.expect("the start migrates");
        assert!(veil_server::db::schema_current(&db).await.unwrap(), "every migration is applied");
        let applied: i64 = sqlx::query_scalar("SELECT count(*) FROM schema_migrations WHERE version = 41").fetch_one(&db).await.unwrap();
        assert_eq!(applied, 1, "migration 41 is recorded once");
        db.close().await;
    });
    assert_eq!(builds.load(Ordering::SeqCst), 2, "packs_listed was built twice: the first build missed rows");
    assert_eq!(rt.block_on(index_stages(&url, "packs_listed")), Some((true, true, true)), "packs_listed is live, ready and valid");
    let (with, without) = rt.block_on(listed_with_and_without_the_index(&url, project));
    assert_eq!(with.len(), 20_050, "two thirds of the 30,000 packs are listed, and the 50 written beside the first build");
    assert!(with == without, "the index built again holds exactly the listed rows");
    // The indexes built for the waits before the two checks are dropped.
    // (The runner's drop is as far as it goes: one that fails, which the
    // server logs, leaves its index for a later start. None failed in a
    // start that migrated, as this one: none is left.)
    assert_eq!(rt.block_on(settle_indexes_left(&url)), Vec::<String>::new(), "an index the runner built for its wait is left");
    drop_database(&rt, &name);
}

/// BUG-2626: no start records the migration over an index that misses rows.
/// A build that misses rows every time fails the start after a bounded
/// number of builds, the migration unrecorded and the index dropped. A
/// start that ends after its build returned, before the record (it died),
/// leaves an index that reads built and misses rows: the next start finds
/// that by checking the index against its table, not by its flags (a built
/// index is kept by `IF NOT EXISTS`), drops it, builds it again and records
/// the migration with an index that holds every listed row.
///
/// YugabyteDB only, as the test before.
#[test]
fn bug_2626_an_index_that_misses_rows_is_never_recorded_and_the_next_start_checks_one_it_finds_built() {
    let rt = runtime();
    if !on_yugabyte(&rt) {
        return;
    }
    let (url, name, project, _) = before_migration_41(&rt, 30_000);
    // 1. Every build misses rows.
    let builds = std::sync::Arc::new(AtomicUsize::new(0));
    let counted = builds.clone();
    let at = url.clone();
    let hook: Box<veil_server::db::AfterBuild> = Box::new(move |index: String| {
        let n = if index == "packs_listed" { counted.fetch_add(1, Ordering::SeqCst) } else { usize::MAX };
        let at = at.clone();
        Box::pin(async move {
            if n != usize::MAX {
                miss_rows_written_beside_the_build(&at, project, &format!("build{n}-"), 10);
            }
        })
    });
    rt.block_on(async {
        let db = veil_server::db::connect(&url, 2).await.unwrap();
        let e = veil_server::db::migrate_with(&db, Some(&*hook)).await.expect_err("no build made packs_listed whole: the start fails");
        assert_eq!(
            e.to_string(),
            "index packs_listed is not built whole (live, ready and valid within 15s of its build, and holding its table's \
             rows) in 5 builds: the migration is not recorded, and the next start builds the index again"
        );
        assert!(!veil_server::db::schema_current(&db).await.unwrap(), "migration 41 is not applied");
        let applied: i64 = sqlx::query_scalar("SELECT count(*) FROM schema_migrations WHERE version = 41").fetch_one(&db).await.unwrap();
        assert_eq!(applied, 0, "migration 41 is not recorded");
        db.close().await;
    });
    assert_eq!(builds.load(Ordering::SeqCst), 5, "packs_listed was built five times");
    assert_eq!(rt.block_on(index_stages(&url, "packs_listed")), None, "the failed start dropped the index that missed rows");

    // 2. A start that dies after its build returned an index missing rows.
    let died = std::sync::Arc::new(tokio::sync::Notify::new());
    let dies = died.clone();
    let at = url.clone();
    let hook: Box<veil_server::db::AfterBuild> = Box::new(move |index: String| {
        let (at, dies) = (at.clone(), dies.clone());
        Box::pin(async move {
            if index == "packs_listed" {
                miss_rows_written_beside_the_build(&at, project, "died-", 10);
                dies.notify_one();
                std::future::pending::<()>().await;
            }
        })
    });
    rt.block_on(async {
        let db = veil_server::db::connect(&url, 2).await.unwrap();
        tokio::select! {
            r = veil_server::db::migrate_with(&db, Some(&*hook)) => panic!("the start ended before its build of packs_listed returned: {r:?}"),
            () = died.notified() => {}
        }
        // Its session ends, and with it the migrations' lock.
        db.close().await;
    });
    assert_eq!(rt.block_on(index_stages(&url, "packs_listed")), Some((true, true, true)), "the start that died left packs_listed reading built");
    let (with, without) = rt.block_on(listed_with_and_without_the_index(&url, project));
    assert_eq!((with.len(), without.len()), (20_050, 20_060), "and missing the 10 rows written beside its build");

    // 3. The next start.
    rt.block_on(async {
        let db = veil_server::db::connect(&url, 2).await.unwrap();
        veil_server::db::migrate(&db).await.expect("the next start migrates");
        assert!(veil_server::db::schema_current(&db).await.unwrap(), "every migration is applied");
        let applied: i64 = sqlx::query_scalar("SELECT count(*) FROM schema_migrations WHERE version = 41").fetch_one(&db).await.unwrap();
        assert_eq!(applied, 1, "migration 41 is recorded once");
        db.close().await;
    });
    assert_eq!(rt.block_on(index_stages(&url, "packs_listed")), Some((true, true, true)), "packs_listed is live, ready and valid");
    let (with, without) = rt.block_on(listed_with_and_without_the_index(&url, project));
    assert_eq!(with.len(), 20_060, "two thirds of the 30,000 packs are listed, and the 60 written beside the builds");
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
        // Every migration's transactional part runs again on what it made
        // (BUG-2570): one with an online section commits it before the
        // steps, unrecorded, and a step that fails runs it all again; and on
        // YugabyteDB, DDL in a transaction block commits statement by
        // statement (`yb_ddl_transaction_block_enabled` is off by default),
        // so a migration that fails part-way keeps its DDL and is applied
        // again on top of it. Statements checked by hand are named below.
        if let Some(stmt) = not_safe_to_run_again(parts.transactional) {
            assert!(
                RUN_AGAIN_CHECKED.iter().any(|(v, s, _)| v == version && s.split_whitespace().eq(stmt.split_whitespace())),
                "migration {version} ({name}): its transactional part is not safe to run again: {stmt}"
            );
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
    for want in [(3, "devices_by_fingerprint"), (11, "projections_own"), (36, "landing_queue_person_slot"), (40, "packs_unlisted"), (41, "packs_listed"), (42, "projections_by_projected_at")] {
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

/// Statements `not_safe_to_run_again` refuses that do the same when run
/// again, checked by hand: (migration, statement, why).
const RUN_AGAIN_CHECKED: &[(i64, &str, &str)] = &[(
    29,
    "UPDATE checks SET run_count = 1 WHERE run_count = 0 AND state IN ('pass', 'fail')",
    "it sets run_count only where it is 0, to 1: run again, it changes nothing",
)];

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

/// Q4: migration 46 (`-- veil: yugabyte-only`) is skipped on PostgreSQL and
/// rebuilds the 10 hot per-branch/per-change tables with composite hash keys
/// on YugabyteDB while preserving every row, keeping sequences owned/working,
/// and running idempotently if re-applied.
#[test]
fn q4_single_repo_hash_keys_migration_preserves_rows_and_is_idempotent() {
    use veil_server::db::{is_yugabyte, migration_parts, IndexStep, MIGRATIONS, ONLINE_INDEXES, YUGABYTE_ONLY};

    // Unit checks for `YUGABYTE_ONLY` parsing.
    let yb_sql = format!("{YUGABYTE_ONLY}\nSELECT 1;\n");
    let p = migration_parts(&yb_sql).expect("yugabyte-only");
    assert!(p.yugabyte_only && p.online.is_empty());
    let mixed = format!("{YUGABYTE_ONLY}\nSELECT 1;\n{ONLINE_INDEXES}\nDROP INDEX CONCURRENTLY IF EXISTS x;\n");
    assert!(migration_parts(&mixed).is_err(), "cannot mix yugabyte-only and online indexes");

    let rt = runtime();
    let (url, name) = fresh_database(&rt);
    rt.block_on(async {
        let db = veil_server::db::connect(&url, 2).await.unwrap();
        let version: String = sqlx::query_scalar("SELECT version()").fetch_one(&db).await.unwrap();
        let yb = is_yugabyte(&version);

        // Apply migrations 1..=45 cleanly on the fresh database.
        exec_retrying(
            &db,
            "CREATE TABLE IF NOT EXISTS schema_migrations (version BIGINT PRIMARY KEY, name TEXT NOT NULL, applied_at BIGINT NOT NULL)",
        )
        .await;
        for &(ver, mname, sql) in MIGRATIONS.iter().filter(|m| m.0 < 46) {
            let parts = migration_parts(sql).unwrap();
            assert!(!parts.yugabyte_only);
            let mut stmts = Vec::new();
            if parts.transactional.lines().any(|l| {
                let t = l.trim();
                !t.is_empty() && !t.starts_with("--")
            }) {
                stmts.push(parts.transactional.to_string());
            }
            for s in parts.online {
                match s {
                    IndexStep::Create { sql, .. } => stmts.push(sql),
                    IndexStep::Drop { name } => stmts.push(format!("DROP INDEX IF EXISTS {name}")),
                }
            }
            for s in stmts {
                exec_retrying(&db, &s).await;
            }
            sqlx::query("INSERT INTO schema_migrations (version, name, applied_at) VALUES ($1, $2, 0)")
                .bind(ver)
                .bind(mname)
                .execute(&db)
                .await
                .unwrap();
        }

        // Seed rows in all 10 tables rebuilt by migration 46.
        exec_retrying(&db, "INSERT INTO people (name, created_at) VALUES ('q4alice', 1)").await;
        exec_retrying(
            &db,
            "INSERT INTO projects (name, created_by, created_at, default_branch, policy_text, policy_bindings, policy_version) \
             SELECT 'q4proj', id, 1, 'main', '', '{}', 0 FROM people WHERE name = 'q4alice'",
        )
        .await;
        let pid: i64 = sqlx::query_scalar("SELECT id FROM projects WHERE name = 'q4proj'").fetch_one(&db).await.unwrap();
        let uid: i64 = sqlx::query_scalar("SELECT id FROM people WHERE name = 'q4alice'").fetch_one(&db).await.unwrap();

        for q in [
            format!("INSERT INTO branches (project_id, name, target) VALUES ({pid}, 'main', 'snap1'), ({pid}, 'agent-1', 'snap2')"),
            format!("INSERT INTO snapshots (project_id, id, author) VALUES ({pid}, 'snap1', {uid}), ({pid}, 'snap2', {uid})"),
            format!("INSERT INTO origins (project_id, real_id, origin_id) VALUES ({pid}, 'snap1', 'orig1')"),
            format!(
                "INSERT INTO projections (project_id, view_key, real_id, projected_id, created_at, collapsed) \
                 VALUES ({pid}, 'vk1', 'snap1', 'proj1', 100, false)"
            ),
            format!(
                "INSERT INTO landed_changes (project_id, branch, lineage, change_id, author, landed) \
                 VALUES ({pid}, 'main', 1, 'chg1', {uid}, 'snap1')"
            ),
            format!(
                "INSERT INTO landing_queue (project_id, branch, ticket, person_id, person_name, device_key, stack, lineage, \
                 person_epoch, project_epoch, state, created_at, priority, person_slot, session, session_slot) \
                 VALUES ({pid}, 'main', 'tkt-1', {uid}, 'q4alice', 'dev1', '[]', 1, 0, 0, 'queued', 100, 0, 0, 's1', 0)"
            ),
            format!(
                "INSERT INTO landings (project_id, branch, lineage, submitted, landed, at) \
                 VALUES ({pid}, 'main', 1, 'sub1', 'snap1', 100)"
            ),
            format!(
                "INSERT INTO landing_leases (project_id, branch, holder, epoch, expires_at, served, lock_epoch) \
                 VALUES ({pid}, 'main', 'hub1', 1, 9999, 2, 1)"
            ),
            format!(
                "INSERT INTO packs (project_id, name, state, person_id, size, objects, created_at) \
                 VALUES ({pid}, 'pack-listed', 1, NULL, 128, 3, 100), ({pid}, 'pack-staged', 0, {uid}, 64, 1, 101)"
            ),
            format!(
                "INSERT INTO change_refs (project_id, change_id, snapshot, created_by, created_at) \
                 VALUES ({pid}, 'chg1', 'snap1', {uid}, 100)"
            ),
        ] {
            exec_retrying(&db, &q).await;
        }

        // On hash-sharded YugabyteDB with existing rows, automatic online `migrate()`
        // must refuse (BUG-2920) without touching any table; `migrate_offline()`
        // executes the rebuild cleanly and is idempotent across re-runs.
        if yb {
            let err = veil_server::db::migrate(&db).await.expect_err("online migrate must refuse non-empty Q4 tables on YB");
            assert!(
                err.to_string().contains("--offline"),
                "expected --offline refusal guidance, got: {err:?}"
            );
            assert!(!veil_server::db::schema_current(&db).await.unwrap());
        }
        for pass in 1..=2 {
            if yb {
                veil_server::db::migrate_offline(&db).await.unwrap_or_else(|e| panic!("migrate_offline pass {pass}: {e:?}"));
            } else {
                veil_server::db::migrate(&db).await.unwrap_or_else(|e| panic!("migrate pass {pass}: {e:?}"));
            }
            assert!(veil_server::db::schema_current(&db).await.unwrap());

            let counts: (i64, i64, i64, i64, i64, i64, i64, i64, i64, i64) = sqlx::query_as(
                "SELECT \
                   (SELECT count(*) FROM branches WHERE project_id = $1), \
                   (SELECT count(*) FROM snapshots WHERE project_id = $1), \
                   (SELECT count(*) FROM origins WHERE project_id = $1), \
                   (SELECT count(*) FROM projections WHERE project_id = $1), \
                   (SELECT count(*) FROM landed_changes WHERE project_id = $1), \
                   (SELECT count(*) FROM landing_queue WHERE project_id = $1), \
                   (SELECT count(*) FROM landings WHERE project_id = $1), \
                   (SELECT count(*) FROM landing_leases WHERE project_id = $1), \
                   (SELECT count(*) FROM packs WHERE project_id = $1), \
                   (SELECT count(*) FROM change_refs WHERE project_id = $1)",
            )
            .bind(pid)
            .fetch_one(&db)
            .await
            .unwrap();
            assert_eq!(counts, (2, 2, 1, 1, 1, 1, 1, 1, 2, 1), "pass {pass} preserved all rows");

            if yb {
                for (tbl, want_hash) in [
                    ("branches", "(project_id, name) HASH"),
                    ("snapshots", "(project_id, id) HASH"),
                    ("origins", "(project_id, real_id) HASH"),
                    ("projections", "(project_id, view_key, real_id) HASH"),
                    ("landed_changes", "(project_id, branch) HASH"),
                    ("landing_queue", "(project_id, branch) HASH"),
                    ("landings", "(project_id, branch) HASH"),
                    ("landing_leases", "(project_id, branch) HASH"),
                    ("packs", "(project_id, name) HASH"),
                    ("change_refs", "(project_id, change_id) HASH"),
                ] {
                    let def: String = sqlx::query_scalar(
                        "SELECT pg_get_indexdef(i.indexrelid) FROM pg_index i \
                         WHERE i.indrelid = to_regclass($1) AND i.indisprimary",
                    )
                    .bind(tbl)
                    .fetch_one(&db)
                    .await
                    .unwrap();
                    assert!(def.contains(want_hash), "pass {pass}: {tbl} PK missing {want_hash}: {def}");
                }
                let has_bp: Option<String> = sqlx::query_scalar("SELECT to_regclass('branches_by_project')::text").fetch_one(&db).await.unwrap();
                assert!(has_bp.is_some(), "branches_by_project must exist on YB");
            }

            if pass == 1 {
                exec_retrying(&db, "DELETE FROM schema_migrations WHERE version = 46").await;
            }
        }

        // Verify landing_queue_seq_seq still works via DEFAULT after rebuild.
        exec_retrying(
            &db,
            &format!(
                "INSERT INTO landing_queue (project_id, branch, ticket, person_id, person_name, device_key, stack, lineage, \
                 person_epoch, project_epoch, state, created_at, priority, person_slot, session, session_slot) \
                 VALUES ({pid}, 'agent-1', 'tkt-2', {uid}, 'q4alice', 'dev1', '[]', 1, 0, 0, 'queued', 102, 0, 1, 's1', 1)"
            ),
        )
        .await;
        let qcount: i64 = sqlx::query_scalar("SELECT count(*) FROM landing_queue WHERE project_id = $1").bind(pid).fetch_one(&db).await.unwrap();
        assert_eq!(qcount, 2);

        db.close().await;
    });
    drop_database(&rt, &name);
}

struct DropFreshDb<'a>(&'a tokio::runtime::Runtime, String);

impl Drop for DropFreshDb<'_> {
    fn drop(&mut self) {
        drop_database(self.0, &self.1);
    }
}

fn fresh_colocated_database(rt: &tokio::runtime::Runtime) -> (String, String) {
    let admin = std::env::var("VEIL_TEST_DATABASE_URL").unwrap();
    let name = format!("{}{}", crate::support::test_db_prefix(), unique("veil_coloc_"));
    rt.block_on(async {
        let db = veil_server::db::connect(&admin, 1).await.unwrap();
        let mut c = db.acquire().await.unwrap();
        sqlx::raw_sql("SET statement_timeout = 0").execute(&mut *c).await.unwrap();
        let mut tries = 0;
        loop {
            match sqlx::raw_sql(&format!("CREATE DATABASE {name} WITH COLOCATION = true")).execute(&mut *c).await {
                Ok(_) => break,
                Err(e) if tries > 0 && e.as_database_error().and_then(|d| d.code()).as_deref() == Some("42P04") => break,
                Err(e) if retryable(&e) && tries < 50 => {
                    tries += 1;
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                Err(e) => panic!("CREATE DATABASE {name} WITH COLOCATION = true: {e}"),
            }
        }
        drop(c);
        db.close().await;
    });
    let (base, _) = admin.rsplit_once('/').unwrap();
    (format!("{base}/{name}"), name)
}

async fn apply_migrations_through(db: &sqlx::PgPool, max_version: i64) {
    use veil_server::db::{migration_parts, IndexStep, MIGRATIONS};
    exec_retrying(
        db,
        "CREATE TABLE IF NOT EXISTS schema_migrations (version BIGINT PRIMARY KEY, name TEXT NOT NULL, applied_at BIGINT NOT NULL)",
    )
    .await;
    for &(ver, mname, sql) in MIGRATIONS {
        if ver > max_version {
            break;
        }
        let parts = migration_parts(sql).unwrap();
        let mut stmts = Vec::new();
        if parts.transactional.lines().any(|l| {
            let t = l.trim();
            !t.is_empty() && !t.starts_with("--")
        }) {
            stmts.push(parts.transactional.to_string());
        }
        for s in parts.online {
            match s {
                IndexStep::Create { sql, .. } => stmts.push(sql),
                IndexStep::Drop { name } => stmts.push(format!("DROP INDEX IF EXISTS {name}")),
            }
        }
        for s in stmts {
            exec_retrying(db, &s).await;
        }
        sqlx::query("INSERT INTO schema_migrations (version, name, applied_at) VALUES ($1, $2, 0)")
            .bind(ver)
            .bind(mname)
            .execute(db)
            .await
            .unwrap();
    }
}

/// BUG-2920 (YugabyteDB): migration 0046 rebuilds each table in three
/// non-transactional steps. Automatic online `db::migrate()` must refuse to
/// touch non-empty or interrupted tables without `--offline`, and an offline
/// retry (`db::migrate_offline()`) after an interrupted attempt must drop stale
/// `<t>_q4` staging tables and re-copy fresh rows so updates committed before
/// the retry are never silently reverted.
#[test]
fn bug_2920_migration_46_never_reverts_updates_committed_during_or_before_retry() {
    let rt = runtime();
    if !on_yugabyte(&rt) {
        return;
    }
    let (url, name) = fresh_database(&rt);
    let _drop = DropFreshDb(&rt, name);
    rt.block_on(async {
        let db = veil_server::db::connect(&url, 2).await.unwrap();
        apply_migrations_through(&db, 45).await;

        exec_retrying(&db, "INSERT INTO people (name, created_at) VALUES ('b2920alice', 1)").await;
        exec_retrying(
            &db,
            "INSERT INTO projects (name, created_by, created_at, default_branch, policy_text, policy_bindings, policy_version) \
             SELECT 'b2920proj', id, 1, 'main', '', '{}', 0 FROM people WHERE name = 'b2920alice'",
        )
        .await;
        let pid: i64 = sqlx::query_scalar("SELECT id FROM projects WHERE name = 'b2920proj'").fetch_one(&db).await.unwrap();
        let uid: i64 = sqlx::query_scalar("SELECT id FROM people WHERE name = 'b2920alice'").fetch_one(&db).await.unwrap();

        exec_retrying(
            &db,
            &format!("INSERT INTO branches (project_id, name, target) VALUES ({pid}, 'main', 'snap-old')"),
        )
        .await;
        exec_retrying(
            &db,
            &format!(
                "INSERT INTO packs (project_id, name, state, person_id, size, objects, created_at) \
                 VALUES ({pid}, 'pack-refused', 0, {uid}, 64, 1, 100)"
            ),
        )
        .await;

        // Simulate attempt 1 completing steps 1 and 2 for `branches` and `packs`
        // before aborting (leaving stale `<t>_q4` staging tables behind).
        let sql46 = veil_server::db::MIGRATIONS
            .iter()
            .find(|(v, _, _)| *v == 46)
            .expect("migration 46")
            .2;
        let steps = veil_server::db::migration_steps(sql46);
        let find_step = |needle: &str| {
            steps
                .iter()
                .find(|s| s.contains(needle))
                .unwrap_or_else(|| panic!("missing 0046 step containing {needle}"))
                .as_str()
        };
        // Steps 1 & 2 for `branches` and `packs` (create `_q4` + copy existing rows).
        exec_retrying(&db, find_step("CREATE TABLE IF NOT EXISTS branches_q4")).await;
        exec_retrying(&db, find_step("INSERT INTO branches_q4")).await;
        exec_retrying(&db, find_step("CREATE TABLE IF NOT EXISTS packs_q4")).await;
        exec_retrying(&db, find_step("INSERT INTO packs_q4")).await;

        // A live server commits a push advancing `main` and refuses `pack-refused`
        // (`state = 2` DISCARDED) before the offline retry begins.
        exec_retrying(
            &db,
            &format!("UPDATE branches SET target = 'snap-committed' WHERE project_id = {pid} AND name = 'main'"),
        )
        .await;
        exec_retrying(
            &db,
            &format!("UPDATE packs SET state = 2, discarded_at = 200 WHERE project_id = {pid} AND name = 'pack-refused'"),
        )
        .await;

        // Online `db::migrate()` must refuse without `--offline` and leave live rows untouched.
        let err = veil_server::db::migrate(&db).await.expect_err("online migrate must refuse migration 46 with existing rows/staging");
        assert!(err.to_string().contains("--offline"), "expected --offline refusal, got: {err:?}");
        assert!(!veil_server::db::schema_current(&db).await.unwrap());

        // Offline retry (`veil-server migrate --offline`) drops stale `_q4` tables,
        // re-copies the latest rows, swaps cleanly, verifies indexes, and preserves
        // every committed update.
        veil_server::db::migrate_offline(&db).await.expect("offline migration 46 completes");
        assert!(veil_server::db::schema_current(&db).await.unwrap());

        let target: String = sqlx::query_scalar("SELECT target FROM branches WHERE project_id = $1 AND name = 'main'")
            .bind(pid)
            .fetch_one(&db)
            .await
            .unwrap();
        let pack_state: i16 = sqlx::query_scalar("SELECT state FROM packs WHERE project_id = $1 AND name = 'pack-refused'")
            .bind(pid)
            .fetch_one(&db)
            .await
            .unwrap();
        db.close().await;

        assert!(
            target == "snap-committed" && pack_state == 2,
            "migration 0046 silently reverted committed updates: branches.target={target:?} (expected \"snap-committed\"), packs.state={pack_state} (expected 2 DISCARDED)"
        );
    });
}

/// BUG-2921 (YugabyteDB): the deployment kit defaults to `YB_LAYOUT=colocated`
/// (`CREATE DATABASE veil WITH COLOCATION = true`), but `db::migrate_once`
/// checks only `is_yugabyte(version)` and executes migration 0046's
/// `PRIMARY KEY ((...) HASH)` / `CREATE INDEX (... HASH)` DDL on colocated
/// databases, which YugabyteDB rejects with `cannot colocate hash partitioned table`.
#[test]
fn bug_2921_migration_46_succeeds_on_colocated_yugabytedb_database() {
    let rt = runtime();
    if !on_yugabyte(&rt) {
        return;
    }
    let (url, name) = fresh_colocated_database(&rt);
    let _drop = DropFreshDb(&rt, name);
    rt.block_on(async {
        let db = veil_server::db::connect(&url, 2).await.unwrap();
        let colocated: bool = sqlx::query_scalar("SELECT yb_is_database_colocated()").fetch_one(&db).await.unwrap();
        assert!(colocated, "test database must be colocated");
        let res = veil_server::db::migrate(&db).await;
        db.close().await;
        res.expect("veil-server migrate must succeed on a colocated YugabyteDB database");
    });
}

/// BUG-2922 (PostgreSQL): migration 0045 must never lose a concurrent access
/// revocation committed by a pre-0045 server at any point during the migration:
///   1. revocation fired while step 1's transaction is open (blocked on
///      `SHARE ROW EXCLUSIVE` of `access_epochs` until step 1 commits, then
///      mirrors into `person_epochs` via `veil_access_epochs_mirror_person`);
///   2. revocation committed between step 1's commit and step 2's backfill
///      (preserved by `ON CONFLICT (person_id) DO NOTHING`);
///   3. revocation fired while step 2's backfill transaction is open (waits on
///      step 2's `person_epochs` row lock, then overwrites the backfilled value
///      via `ON CONFLICT (person_id) DO UPDATE`).
#[test]
fn bug_2922_migration_45_never_loses_concurrent_revocation_from_person_epochs() {
    let rt = runtime();
    if on_yugabyte(&rt) {
        return;
    }
    let (url, name) = fresh_database(&rt);
    let _drop = DropFreshDb(&rt, name);
    rt.block_on(async {
        let db = veil_server::db::connect(&url, 6).await.unwrap();
        apply_migrations_through(&db, 44).await;

        for person in ["b2922alice", "b2922bob", "b2922carol"] {
            exec_retrying(&db, &format!("INSERT INTO people (name, created_at) VALUES ('{person}', 1)")).await;
        }
        exec_retrying(
            &db,
            "INSERT INTO projects (name, created_by, created_at, default_branch, policy_text, policy_bindings, policy_version) \
             SELECT 'b2922proj', id, 1, 'main', '', '{}', 0 FROM people WHERE name = 'b2922alice'",
        )
        .await;
        let pid: i64 = sqlx::query_scalar("SELECT id FROM projects WHERE name = 'b2922proj'").fetch_one(&db).await.unwrap();
        let alice: i64 = sqlx::query_scalar("SELECT id FROM people WHERE name = 'b2922alice'").fetch_one(&db).await.unwrap();
        let bob: i64 = sqlx::query_scalar("SELECT id FROM people WHERE name = 'b2922bob'").fetch_one(&db).await.unwrap();
        let carol: i64 = sqlx::query_scalar("SELECT id FROM people WHERE name = 'b2922carol'").fetch_one(&db).await.unwrap();
        exec_retrying(&db, &format!("INSERT INTO groups (project_id, name) VALUES ({pid}, 'eng')")).await;
        let gid: i64 = sqlx::query_scalar("SELECT id FROM groups WHERE project_id = $1 AND name = 'eng'")
            .bind(pid)
            .fetch_one(&db)
            .await
            .unwrap();
        for uid in [alice, bob, carol] {
            exec_retrying(&db, &format!("INSERT INTO group_members (group_id, person_id) VALUES ({gid}, {uid})")).await;
        }

        let mut before = Vec::new();
        for uid in [alice, bob, carol] {
            let e: i64 = sqlx::query_scalar("SELECT epoch FROM access_epochs WHERE project_id = 0 AND person_id = $1")
                .bind(uid)
                .fetch_one(&db)
                .await
                .unwrap();
            assert_ne!(e, 0, "group membership insert bumped access_epochs");
            before.push(e);
        }

        let sql45 = veil_server::db::MIGRATIONS
            .iter()
            .find(|(v, _, _)| *v == 45)
            .expect("migration 45")
            .2;
        let steps = veil_server::db::migration_steps(sql45);
        assert_eq!(steps.len(), 2, "migration 45 must run in 2 committed steps");

        // Window 1: start step 1 transaction; concurrently revoke Alice while
        // step 1 holds `SHARE ROW EXCLUSIVE` on `access_epochs`, then commit step 1.
        let mut tx1 = db.begin().await.unwrap();
        sqlx::raw_sql(&steps[0]).execute(&mut *tx1).await.unwrap();
        let db_alice = db.clone();
        let revoke_alice = tokio::spawn(async move {
            sqlx::query("DELETE FROM group_members WHERE group_id = $1 AND person_id = $2")
                .bind(gid)
                .bind(alice)
                .execute(&db_alice)
                .await
                .unwrap();
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        tx1.commit().await.unwrap();
        revoke_alice.await.unwrap();

        // Window 2: revoke Bob after step 1 commits and before step 2 starts.
        sqlx::query("DELETE FROM group_members WHERE group_id = $1 AND person_id = $2")
            .bind(gid)
            .bind(bob)
            .execute(&db)
            .await
            .unwrap();

        // Window 3: run step 2's backfill in a transaction, pause before COMMIT
        // while Carol is concurrently revoked, then commit step 2.
        let mut tx2 = db.begin().await.unwrap();
        sqlx::raw_sql(&steps[1]).execute(&mut *tx2).await.unwrap();
        sqlx::query("INSERT INTO schema_migrations (version, name, applied_at) VALUES (45, 'person_epochs', 0)")
            .execute(&mut *tx2)
            .await
            .unwrap();
        let db_carol = db.clone();
        let revoke_carol = tokio::spawn(async move {
            sqlx::query("DELETE FROM group_members WHERE group_id = $1 AND person_id = $2")
                .bind(gid)
                .bind(carol)
                .execute(&db_carol)
                .await
                .unwrap();
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        tx2.commit().await.unwrap();
        revoke_carol.await.unwrap();

        for (label, uid, e_before) in [("alice (during step 1)", alice, before[0]), ("bob (between steps)", bob, before[1]), ("carol (during step 2)", carol, before[2])] {
            let e_revoked: i64 = sqlx::query_scalar("SELECT epoch FROM access_epochs WHERE project_id = 0 AND person_id = $1")
                .bind(uid)
                .fetch_one(&db)
                .await
                .unwrap();
            assert_ne!(e_revoked, e_before, "{label}: revocation bumped access_epochs");
            let read = veil_server::caches::read_epochs(&db, uid, Some(pid)).await.unwrap();
            assert_eq!(
                read.person, e_revoked,
                "{label}: new server reading person_epochs must see revoked epoch {e_revoked}, not pre-revocation epoch {e_before}"
            );
        }
        db.close().await;
    });
}

/// BUG-2924: migration 0044 drops `landing_queue_ticket (ticket)` in the same
/// migration that creates `(project_id, ticket)`. Any pre-0044 server still
/// running during a rolling upgrade executes `bisect::revert_confirmed_culprit`
/// with `ON CONFLICT (ticket) DO NOTHING`, which fails with PostgreSQL `42P10`.
#[test]
fn bug_2924_migration_44_preserves_pre_44_bisect_on_conflict_ticket_during_rolling_upgrade() {
    let rt = runtime();
    let (url, name) = fresh_database(&rt);
    let _drop = DropFreshDb(&rt, name);
    rt.block_on(async {
        let db = veil_server::db::connect(&url, 2).await.unwrap();
        apply_migrations_through(&db, 44).await;

        exec_retrying(&db, "INSERT INTO people (name, created_at) VALUES ('b2924admin', 1)").await;
        exec_retrying(
            &db,
            "INSERT INTO projects (name, created_by, created_at, default_branch, policy_text, policy_bindings, policy_version) \
             SELECT 'b2924proj', id, 1, 'main', '', '{}', 0 FROM people WHERE name = 'b2924admin'",
        )
        .await;
        let pid: i64 = sqlx::query_scalar("SELECT id FROM projects WHERE name = 'b2924proj'").fetch_one(&db).await.unwrap();
        let uid: i64 = sqlx::query_scalar("SELECT id FROM people WHERE name = 'b2924admin'").fetch_one(&db).await.unwrap();

        // Exact SQL issued by pre-0044 servers (`3d0a690b:crates/veil-server/src/bisect.rs:1813-1820`).
        let res = sqlx::query(
            "INSERT INTO landing_queue ( \
                project_id, branch, ticket, person_id, person_name, device_key, stack, lineage, \
                person_epoch, project_epoch, priority, state, created_at \
             ) VALUES ($1, 'main', 'revert-1-main-1-0000', $2, 'b2924admin', 'dev1', '[]', 1, 0, 0, 1, 'queued', 100) \
             ON CONFLICT (ticket) DO NOTHING",
        )
        .bind(pid)
        .bind(uid)
        .execute(&db)
        .await;
        db.close().await;

        res.expect("pre-0044 bisect ON CONFLICT (ticket) DO NOTHING must keep working during rolling upgrade");
    });
}

/// BUG-2925 (YugabyteDB): migration 0046 changes `landing_queue_finished`,
/// `landings_at`, and `packs_unlisted` to composite hash keys
/// `((project_id, branch) HASH, ...)` / `((project_id, name) HASH)`, which do
/// not match `landing::service::clean` (`WHERE project_id = $1 AND done_at < $2` /
/// `at < $2`) or `pack_gc::sweep_*` (`WHERE project_id = $1 AND state ...`), so
/// YugabyteDB ignores all three indexes and scans the primary keys across tablets.
#[test]
fn bug_2925_migration_46_keeps_sweep_and_retention_indexes_usable_on_yugabytedb() {
    let rt = runtime();
    if !on_yugabyte(&rt) {
        return;
    }
    let (url, name) = fresh_database(&rt);
    let _drop = DropFreshDb(&rt, name);
    rt.block_on(async {
        let db = veil_server::db::connect(&url, 2).await.unwrap();
        veil_server::db::migrate(&db).await.unwrap();

        // Populate a small realistic dataset and ANALYZE: under YugabyteDB 2025.2's
        // default `yb_enable_base_scans_cost_model = on`, empty/unanalyzed tables
        // always favor `*_pkey` (startup cost 21.00 < secondary index 24.00) even
        // on pre-0046 schemas. With stats present, composite-hash indexes are still
        // ignored while covering `(project_id HASH, ...) INCLUDE (...)` indexes get
        // chosen for `Index Only Scan`.
        exec_retrying(
            &db,
            "INSERT INTO landing_queue ( \
                project_id, branch, ticket, person_id, person_name, device_key, stack, lineage, \
                person_epoch, project_epoch, state, created_at, done_at \
             ) SELECT 1, 'b' || g, 't' || g, 1, 'a', 'd', '[]', 1, 0, 0, \
                      CASE WHEN g <= 10 THEN 'landed' ELSE 'queued' END, 50, \
                      CASE WHEN g <= 10 THEN 50 ELSE NULL END \
               FROM generate_series(1, 500) g",
        )
        .await;
        exec_retrying(
            &db,
            "INSERT INTO landings (project_id, branch, lineage, submitted, landed, at) \
             SELECT 1, 'b' || g, 1, 's' || g, 'l' || g, CASE WHEN g <= 10 THEN 50 ELSE 5000 END \
             FROM generate_series(1, 500) g",
        )
        .await;
        exec_retrying(
            &db,
            "INSERT INTO packs (project_id, name, state, person_id, size, objects, created_at, discarded_at) \
             SELECT 1, 'p' || g, CASE WHEN g <= 5 THEN 0 ELSE 1 END, 1, 100, 1, 50, NULL \
             FROM generate_series(1, 500) g",
        )
        .await;
        exec_retrying(&db, "ANALYZE landing_queue, landings, packs").await;

        let explain = |sql: &str| {
            let db = db.clone();
            let q = format!("EXPLAIN {sql}");
            async move {
                let rows: Vec<String> = sqlx::query_scalar(&q).fetch_all(&db).await.unwrap();
                rows.join("\n")
            }
        };

        let p_finished = explain(
            "SELECT project_id, branch, seq FROM landing_queue \
             WHERE project_id = 1 AND done_at < 100 AND state NOT IN ('queued', 'merging') LIMIT 500",
        )
        .await;
        let p_landings = explain(
            "SELECT project_id, branch, lineage, submitted FROM landings \
             WHERE project_id = 1 AND at < 100 LIMIT 500",
        )
        .await;
        let p_packs_due = explain(
            "SELECT min(discarded_at) FILTER (WHERE state = 2), count(*) FILTER (WHERE state = 0 AND person_id IS NULL), \
             min(created_at) FILTER (WHERE state = 0 AND person_id IS NOT NULL) FROM packs WHERE project_id = 1 AND state <> 1",
        )
        .await;
        let p_packs_staged = explain(
            "SELECT name FROM packs WHERE project_id = 1 AND state = 0 AND (person_id IS NULL OR created_at <= 100)",
        )
        .await;
        db.close().await;

        let mut failures: Vec<String> = Vec::new();
        if !p_finished.contains("landing_queue_finished") {
            failures.push(format!("landing::clean ignored landing_queue_finished:\n{p_finished}"));
        }
        if !p_landings.contains("landings_at") {
            failures.push(format!("landing::clean ignored landings_at:\n{p_landings}"));
        }
        if !p_packs_due.contains("packs_unlisted") {
            failures.push(format!("pack_gc::sweep_due ignored packs_unlisted:\n{p_packs_due}"));
        }
        if !p_packs_staged.contains("packs_unlisted") {
            failures.push(format!("pack_gc::sweep_staged ignored packs_unlisted:\n{p_packs_staged}"));
        }
        assert!(failures.is_empty(), "BUG-2925 unusable indexes:\n{}", failures.join("\n---\n"));
    });
}

/// BUG-2930 (YugabyteDB): migration 0045 (`BUG-2922` fix) still loses concurrent
/// revocations on YugabyteDB during a normal rolling upgrade (no crash) AND on
/// an interrupted retry between step 1 and step 2.
///
/// 1. Normal rolling upgrade: `db::migrate_once` executes `-- veil: step`
///    migrations without waiting for active backends to adopt step 1's catalog
///    version (`wait_for_every_session`). On YugabyteDB `CREATE TRIGGER` neither
///    acquires a table lock blocking `access_epochs` DML nor drains in-flight
///    transactions that already wrote `access_epochs` under the pre-step-1
///    catalog. Step 2's MVCC snapshot reads the pre-revocation epoch and records
///    version 45; when the in-flight `READ COMMITTED` revocation (`remove_members`,
///    `bar_device`, …) commits, `access_epochs (0, person)` holds the revoked
///    epoch while `person_epochs (person)` stays permanently at the old epoch.
/// 2. Interrupted retry: re-running step 1 executes `DROP TRIGGER IF EXISTS`
///    before `CREATE TRIGGER`. Because YugabyteDB commits DDL immediately
///    outside the transaction block, a revocation between those two DDL
///    statements updates `access_epochs` without firing the mirror trigger, and
///    step 2's `ON CONFLICT (person_id) DO NOTHING` leaves `person_epochs` stuck
///    at the stale pre-retry epoch permanently.
#[test]
#[ignore = "BUG-2930: migration 0045 loses concurrent revocations on YugabyteDB (no session barrier between steps; DROP TRIGGER commits before CREATE TRIGGER on retry)"]
fn bug_2930_migration_45_yugabytedb_loses_concurrent_revocation_in_person_epochs() {
    let rt = runtime();
    if !on_yugabyte(&rt) {
        return;
    }

    let mut failures: Vec<String> = Vec::new();

    // Part A: normal rolling upgrade (no crash).
    {
        let (url, name) = fresh_database(&rt);
        let _drop = DropFreshDb(&rt, name);
        rt.block_on(async {
            let db = veil_server::db::connect(&url, 6).await.unwrap();
            apply_migrations_through(&db, 44).await;

            exec_retrying(&db, "INSERT INTO people (name, created_at) VALUES ('b2930alice', 1)").await;
            exec_retrying(
                &db,
                "INSERT INTO projects (name, created_by, created_at, default_branch, policy_text, policy_bindings, policy_version) \
                 SELECT 'b2930proj', id, 1, 'main', '', '{}', 0 FROM people WHERE name = 'b2930alice'",
            )
            .await;
            let pid: i64 = sqlx::query_scalar("SELECT id FROM projects WHERE name = 'b2930proj'").fetch_one(&db).await.unwrap();
            let alice: i64 = sqlx::query_scalar("SELECT id FROM people WHERE name = 'b2930alice'").fetch_one(&db).await.unwrap();
            // Seed one branch row so `db::migrate(&db)` applies migration 45 and
            // stops cleanly at migration 46's offline guard (isolating 0045).
            exec_retrying(&db, &format!("INSERT INTO branches (project_id, name, target) VALUES ({pid}, 'main', 'snap0')")).await;
            exec_retrying(&db, &format!("INSERT INTO groups (project_id, name) VALUES ({pid}, 'eng')")).await;
            let gid: i64 = sqlx::query_scalar("SELECT id FROM groups WHERE project_id = $1 AND name = 'eng'")
                .bind(pid)
                .fetch_one(&db)
                .await
                .unwrap();
            exec_retrying(&db, &format!("INSERT INTO group_members (group_id, person_id) VALUES ({gid}, {alice})")).await;

            let e_before: i64 = sqlx::query_scalar("SELECT epoch FROM access_epochs WHERE project_id = 0 AND person_id = $1")
                .bind(alice)
                .fetch_one(&db)
                .await
                .unwrap();
            assert_ne!(e_before, 0, "group insert bumped access_epochs");

            // Pre-0045 server begins a READ COMMITTED revocation transaction
            // (`api::change_group` / `Op::RemoveMember`) and deletes Alice from
            // `group_members`, bumping `access_epochs (0, alice)` before step 1.
            let mut rev_tx = db.begin().await.unwrap();
            let deleted = sqlx::query("DELETE FROM group_members WHERE group_id = $1 AND person_id = $2")
                .bind(gid)
                .bind(alice)
                .execute(&mut *rev_tx)
                .await
                .unwrap()
                .rows_affected();
            assert_eq!(deleted, 1, "alice removed from group_members in open tx");

            // Concurrently, a new server runs `db::migrate(&db)` (applies 0045
            // step 1 + step 2 and records version 45, then refuses 0046 online).
            let mig_err = veil_server::db::migrate(&db)
                .await
                .expect_err("0046 refuses online because branches has a row");
            assert!(
                mig_err.to_string().contains("--offline"),
                "expected 0046 --offline refusal after 0045, got: {mig_err:?}"
            );
            let applied_45: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = 45)")
                .fetch_one(&db)
                .await
                .unwrap();
            assert!(applied_45, "migration 45 must be recorded in schema_migrations");

            // The pre-0045 revocation finishes its trailing `group_info` read
            // and commits cleanly.
            let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM group_members WHERE group_id = $1")
                .bind(gid)
                .fetch_one(&mut *rev_tx)
                .await
                .unwrap();
            assert_eq!(remaining, 0);
            rev_tx.commit().await.expect("pre-0045 revocation tx commits");

            let e_revoked: i64 = sqlx::query_scalar("SELECT epoch FROM access_epochs WHERE project_id = 0 AND person_id = $1")
                .bind(alice)
                .fetch_one(&db)
                .await
                .unwrap();
            assert_ne!(e_revoked, e_before, "committed revocation updated access_epochs");

            let read = veil_server::caches::read_epochs(&db, alice, Some(pid)).await.unwrap();
            db.close().await;
            if read.person != e_revoked {
                failures.push(format!(
                    "Part A (normal rolling upgrade) lost revocation: person_epochs={} (pre-revocation {}), access_epochs={}",
                    read.person, e_before, e_revoked
                ));
            }
        });
    }

    // Part B: interrupted retry between step 1 and step 2 on YugabyteDB.
    {
        let (url, name) = fresh_database(&rt);
        let _drop = DropFreshDb(&rt, name);
        rt.block_on(async {
            let db = veil_server::db::connect(&url, 6).await.unwrap();
            apply_migrations_through(&db, 44).await;

            exec_retrying(&db, "INSERT INTO people (name, created_at) VALUES ('b2930bob', 1)").await;
            exec_retrying(
                &db,
                "INSERT INTO projects (name, created_by, created_at, default_branch, policy_text, policy_bindings, policy_version) \
                 SELECT 'b2930proj2', id, 1, 'main', '', '{}', 0 FROM people WHERE name = 'b2930bob'",
            )
            .await;
            let pid: i64 = sqlx::query_scalar("SELECT id FROM projects WHERE name = 'b2930proj2'").fetch_one(&db).await.unwrap();
            let bob: i64 = sqlx::query_scalar("SELECT id FROM people WHERE name = 'b2930bob'").fetch_one(&db).await.unwrap();
            exec_retrying(&db, &format!("INSERT INTO groups (project_id, name) VALUES ({pid}, 'eng')")).await;
            let gid: i64 = sqlx::query_scalar("SELECT id FROM groups WHERE project_id = $1 AND name = 'eng'")
                .bind(pid)
                .fetch_one(&db)
                .await
                .unwrap();

            let sql45 = veil_server::db::MIGRATIONS
                .iter()
                .find(|(v, _, _)| *v == 45)
                .expect("migration 45")
                .2;
            let steps = veil_server::db::migration_steps(sql45);
            assert_eq!(steps.len(), 2);

            // Attempt 1 applies step 1 then fails before step 2.
            exec_retrying(&db, &steps[0]).await;

            // While step 1 is in place, Bob is added to `eng`, mirroring `e1`
            // into both `access_epochs` and `person_epochs`.
            exec_retrying(&db, &format!("INSERT INTO group_members (group_id, person_id) VALUES ({gid}, {bob})")).await;
            let e1_ae: i64 = sqlx::query_scalar("SELECT epoch FROM access_epochs WHERE project_id = 0 AND person_id = $1")
                .bind(bob)
                .fetch_one(&db)
                .await
                .unwrap();
            let e1_pe: i64 = sqlx::query_scalar("SELECT epoch FROM person_epochs WHERE person_id = $1")
                .bind(bob)
                .fetch_one(&db)
                .await
                .unwrap();
            assert_eq!(e1_pe, e1_ae, "mirror trigger populated person_epochs with e1");

            // Attempt 2 re-runs step 1 inside a transaction block. On YugabyteDB,
            // step 1's `DROP TRIGGER IF EXISTS` commits immediately before
            // `CREATE TRIGGER` executes.
            assert!(
                steps[0].contains("DROP TRIGGER IF EXISTS veil_access_epochs_mirror_person ON access_epochs"),
                "0045 step 1 drops the mirror trigger before recreating it"
            );
            let mut retry_tx = db.begin().await.unwrap();
            sqlx::raw_sql("DROP TRIGGER IF EXISTS veil_access_epochs_mirror_person ON access_epochs")
                .execute(&mut *retry_tx)
                .await
                .unwrap();

            // A concurrent revocation commits in the window before CREATE TRIGGER.
            let deleted = sqlx::query("DELETE FROM group_members WHERE group_id = $1 AND person_id = $2")
                .bind(gid)
                .bind(bob)
                .execute(&db)
                .await
                .unwrap()
                .rows_affected();
            assert_eq!(deleted, 1);

            // Retry finishes step 1 and then runs step 2 (`ON CONFLICT DO NOTHING`).
            sqlx::raw_sql(
                "CREATE TRIGGER veil_access_epochs_mirror_person \
                 AFTER INSERT OR UPDATE ON access_epochs \
                 FOR EACH ROW \
                 WHEN (NEW.project_id = 0 AND NEW.person_id > 0) \
                 EXECUTE FUNCTION veil_mirror_person_epoch()",
            )
            .execute(&mut *retry_tx)
            .await
            .unwrap();
            retry_tx.commit().await.unwrap();

            let mut tx2 = db.begin().await.unwrap();
            sqlx::raw_sql(&steps[1]).execute(&mut *tx2).await.unwrap();
            sqlx::query("INSERT INTO schema_migrations (version, name, applied_at) VALUES (45, 'person_epochs', 0)")
                .execute(&mut *tx2)
                .await
                .unwrap();
            tx2.commit().await.unwrap();

            let e2_ae: i64 = sqlx::query_scalar("SELECT epoch FROM access_epochs WHERE project_id = 0 AND person_id = $1")
                .bind(bob)
                .fetch_one(&db)
                .await
                .unwrap();
            assert_ne!(e2_ae, e1_ae, "revocation bumped access_epochs to e2");

            let read = veil_server::caches::read_epochs(&db, bob, Some(pid)).await.unwrap();
            db.close().await;
            if read.person != e2_ae {
                failures.push(format!(
                    "Part B (interrupted retry DROP TRIGGER window) lost revocation: person_epochs={} (stale e1={}), access_epochs={}",
                    read.person, e1_ae, e2_ae
                ));
            }
        });
    }

    assert!(failures.is_empty(), "BUG-2930 YugabyteDB 0045 failures:\n{}", failures.join("\n"));
}

/// BUG-2931 (YugabyteDB): migration 0046 must never run automatically without
/// `--offline` on an existing database (even when all rebuilt tables are empty
/// because no project has received a push yet). Only a migrate run that created
/// the schema from scratch (`schema_migrations` absent or empty when it took
/// the migrations lock) may apply 0046 without `--offline`.
#[test]
fn bug_2931_migration_46_online_guard_misses_existing_live_org_without_pushes() {
    let rt = runtime();
    if !on_yugabyte(&rt) {
        return;
    }
    let (url, name) = fresh_database(&rt);
    let _drop = DropFreshDb(&rt, name);
    rt.block_on(async {
        let db = veil_server::db::connect(&url, 2).await.unwrap();
        apply_migrations_through(&db, 45).await;

        // Existing live deployment: users, project, and active session exist,
        // pre-0046 servers are serving, but no push has populated the rebuilt
        // tables yet.
        exec_retrying(&db, "INSERT INTO people (name, created_at) VALUES ('b2931admin', 1)").await;
        exec_retrying(
            &db,
            "INSERT INTO projects (name, created_by, created_at, default_branch, policy_text, policy_bindings, policy_version) \
             SELECT 'b2931proj', id, 1, 'main', '', '{}', 0 FROM people WHERE name = 'b2931admin'",
        )
        .await;

        let res = veil_server::db::migrate(&db).await;
        let err = res.expect_err("online db::migrate() must refuse migration 46 on an existing non-empty org database");
        assert!(err.to_string().contains("veil-server migrate --offline"), "expected --offline refusal, got: {err:?}");
        assert!(!veil_server::db::schema_current(&db).await.unwrap(), "migration 46 must not be recorded");

        veil_server::db::migrate_offline(&db).await.expect("offline migration 46 succeeds");
        assert!(veil_server::db::schema_current(&db).await.unwrap());
        db.close().await;
    });
}

/// BUG-2931 (YugabyteDB): no emptiness gate — even a database already migrated
/// through version 45 where every rebuilt table (and `people`/`projects`) is
/// completely empty must refuse migration 46 without `--offline`, and then
/// apply it cleanly with `migrate_offline`.
#[test]
fn bug_2931_migration_46_refuses_existing_db_with_empty_tables_without_offline() {
    let rt = runtime();
    if !on_yugabyte(&rt) {
        return;
    }
    let (url, name) = fresh_database(&rt);
    let _drop = DropFreshDb(&rt, name);
    rt.block_on(async {
        let db = veil_server::db::connect(&url, 2).await.unwrap();
        veil_server::db::migrate_through(&db, 45).await.expect("migrate through 45");

        // Confirm every table rebuilt by 0046 is empty.
        for tbl in [
            "branches",
            "snapshots",
            "origins",
            "projections",
            "landed_changes",
            "landing_queue",
            "landings",
            "landing_leases",
            "packs",
            "change_refs",
            "access_epochs",
        ] {
            let count: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM {tbl}")).fetch_one(&db).await.unwrap();
            assert_eq!(count, 0, "{tbl} must be empty");
        }

        let err = veil_server::db::migrate(&db)
            .await
            .expect_err("existing DB at 45 with all rebuilt tables empty must still refuse 46 without --offline");
        assert!(err.to_string().contains("veil-server migrate --offline"), "expected --offline refusal, got: {err:?}");
        assert!(!veil_server::db::schema_current(&db).await.unwrap(), "migration 46 must not be recorded");

        veil_server::db::migrate_offline(&db).await.expect("offline migration 46 applies cleanly");
        assert!(veil_server::db::schema_current(&db).await.unwrap());
        db.close().await;
    });
}

/// BUG-2932 (YugabyteDB): `verify_rebuilt_indexes` only checks indexes currently
/// present in `pg_index` and never checks that the 15 required secondary indexes
/// exist. Following its own error message ("drop/rebuild it and re-run
/// `veil-server migrate --offline`") after dropping a bad index causes
/// `migrate --offline` to skip the already-rebuilt table and record version 46
/// with a missing UNIQUE index (e.g. `landing_queue_ticket`), breaking
/// `ON CONFLICT (ticket) DO NOTHING`.
#[test]
#[ignore = "BUG-2932: verify_rebuilt_indexes records migration 46 even when required rebuilt secondary/UNIQUE indexes are missing"]
fn bug_2932_verify_rebuilt_indexes_does_not_check_required_indexes_exist() {
    let rt = runtime();
    if !on_yugabyte(&rt) {
        return;
    }
    let (url, name) = fresh_database(&rt);
    let _drop = DropFreshDb(&rt, name);
    rt.block_on(async {
        let db = veil_server::db::connect(&url, 2).await.unwrap();
        veil_server::db::migrate_offline(&db).await.unwrap();

        // Simulate an unrecorded retry where a bad rebuilt index was dropped
        // before re-running `veil-server migrate --offline`.
        exec_retrying(&db, "DELETE FROM schema_migrations WHERE version = 46").await;
        exec_retrying(&db, "DROP INDEX landing_queue_ticket").await;

        let res = veil_server::db::migrate_offline(&db).await;
        let has_ticket: Option<String> = sqlx::query_scalar("SELECT to_regclass('landing_queue_ticket')::text")
            .fetch_one(&db)
            .await
            .unwrap();
        db.close().await;

        assert!(
            res.is_err() || has_ticket.is_some(),
            "migrate_offline recorded migration 46 with required UNIQUE index landing_queue_ticket missing"
        );
    });
}


