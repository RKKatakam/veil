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

/// BUG-1590: the server cannot use a database that requires TLS (managed
/// PostgreSQL services do: DigitalOcean's, for one). `veil-server`'s sqlx
/// is built without a TLS feature, so `sslmode=require` fails with "TLS
/// upgrade is not supported" before the handshake. Needs a database with
/// `ssl = on` (the shared `postgres:17-alpine` container has it off), so
/// its fix brings a TLS-enabled database into `scripts/verify-server.sh`.
#[test]
#[ignore = "BUG-1590: veil-server's sqlx has no TLS feature, so a database that requires TLS (every managed PostgreSQL) is unusable"]
fn bug_1590_the_server_connects_to_a_database_that_requires_tls() {
    let rt = runtime();
    let (url, _) = fresh_database(&rt);
    let sep = if url.contains('?') { '&' } else { '?' };
    let url = format!("{url}{sep}sslmode=require");
    rt.block_on(async {
        let db = veil_server::db::connect(&url, 1).await.expect("connects over TLS");
        let one: (i64,) = sqlx::query_as("SELECT 1").fetch_one(&db).await.unwrap();
        assert_eq!(one.0, 1);
        db.close().await;
    });
}
