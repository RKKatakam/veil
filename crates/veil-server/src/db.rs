//! Metadata in PostgreSQL (development and CI) or YugabyteDB (production),
//! with portable SQL only (`docs/HUB.md` §2.1).
//!
//! * Read-check-write transactions are SERIALIZABLE ([`serializable`]);
//!   branch moves, which are one-row compare-and-swaps, READ COMMITTED, and
//!   so are the hot ones whose races unique keys and row locks decide:
//!   sign-in, project and group creation, group changes (BUG-847: on
//!   YugabyteDB a SERIALIZABLE read blocks every insert into the table it
//!   read until it commits).
//!   Both go through [`transaction`], which runs them again when they lose
//!   a race, within a deadline.
//! * Every connection sets `statement_timeout` and `lock_timeout`: no
//!   statement waits forever, on PostgreSQL or YugabyteDB.
//! * Migrations ([`migrate`]) run once, by one process holding an
//!   advisory lock, in order, each in its own transaction, recorded in
//!   `schema_migrations`; an index on a table servers already write is
//!   built online, outside the transaction ([`ONLINE_INDEXES`], BUG-2482).
//!   A server that finds the schema current runs no DDL (BUG-838).
//! * Every request runs again, within [`TRANSACTION_DEADLINE`], when it
//!   fails on a retryable database error (a lost race, a restarted read, a
//!   catalog changed by a migration) before anything it did was committed
//!   ([`retry_requests`]).

use std::{
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use axum::{
    body::Body,
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use sqlx::{postgres::PgPoolOptions, PgConnection, PgPool};

use crate::error::{Error, Result};

/// The migrations, in order. Never change what one that shipped makes: add
/// a new one. (Migrations 3, 11, 23, 24, 26, 28, 30, 35, 36 and 40 moved
/// their indexes on tables that existed before them into an
/// [`ONLINE_INDEXES`] section, BUG-2482: the
/// same indexes, built online; the runner keeps no checksums, and a
/// database that applied one never applies it again.)
pub const MIGRATIONS: &[(i64, &str, &str)] = &[
    (1, "initial", include_str!("../migrations/0001_initial.sql")),
    (2, "device_vouches", include_str!("../migrations/0002_device_vouches.sql")),
    (3, "invites_and_key_sharing", include_str!("../migrations/0003_invites_and_key_sharing.sql")),
    (4, "derived", include_str!("../migrations/0004_derived.sql")),
    (5, "change_refs", include_str!("../migrations/0005_change_refs.sql")),
    (6, "access_epochs", include_str!("../migrations/0006_access_epochs.sql")),
    (9, "secret_shares", include_str!("../migrations/0009_secret_shares.sql")),
    (10, "view_graph", include_str!("../migrations/0010_view_graph.sql")),
    (11, "landing", include_str!("../migrations/0011_landing.sql")),
    (13, "packs", include_str!("../migrations/0013_packs.sql")),
    (15, "file_history_and_blame", include_str!("../migrations/0015_file_history_and_blame.sql")),
    (16, "search", include_str!("../migrations/0016_search.sql")),
    (17, "prs", include_str!("../migrations/0017_prs.sql")),
    (20, "agent_sessions", include_str!("../migrations/0020_agent_sessions.sql")),
    (21, "view_graph_changes", include_str!("../migrations/0021_view_graph_changes.sql")),
    (22, "landing_merge", include_str!("../migrations/0022_landing_merge.sql")),
    (23, "embargoes", include_str!("../migrations/0023_embargoes.sql")),
    (24, "landing_limits", include_str!("../migrations/0024_landing_limits.sql")),
    (25, "ci_and_tested", include_str!("../migrations/0025_ci_and_tested.sql")),
    (26, "bisect_and_revert", include_str!("../migrations/0026_bisect_and_revert.sql")),
    (27, "pack_gc", include_str!("../migrations/0027_pack_gc.sql")),
    (28, "embargo_prs", include_str!("../migrations/0028_embargo_prs.sql")),
    (29, "checks_run_count", include_str!("../migrations/0029_checks_run_count.sql")),
    (30, "bisect_revert_change_id", include_str!("../migrations/0030_bisect_revert_change_id.sql")),
    (31, "pr_source_branch", include_str!("../migrations/0031_pr_source_branch.sql")),
    (32, "blame_line_maps", include_str!("../migrations/0032_blame_line_maps.sql")),
    (33, "web_secrets", include_str!("../migrations/0033_web_secrets.sql")),
    (34, "branch_changes_recorded", include_str!("../migrations/0034_branch_changes_recorded.sql")),
    (35, "bisect_revert_patch", include_str!("../migrations/0035_bisect_revert_patch.sql")),
    (36, "landing_slots", include_str!("../migrations/0036_landing_slots.sql")),
    (37, "landing_served", include_str!("../migrations/0037_landing_served.sql")),
    (38, "review_writers", include_str!("../migrations/0038_review_writers.sql")),
    (39, "lease_locks", include_str!("../migrations/0039_lease_locks.sql")),
    (40, "packs_unlisted", include_str!("../migrations/0040_packs_unlisted.sql")),
    (41, "packs_listed", include_str!("../migrations/0041_packs_listed.sql")),
    (42, "projections_by_projected_at", include_str!("../migrations/0042_projections_by_projected_at.sql")),
    (43, "drop_hot_fks", include_str!("../migrations/0043_drop_hot_fks.sql")),
    (44, "prune_repair_indexes", include_str!("../migrations/0044_prune_repair_indexes.sql")),
    (45, "person_epochs", include_str!("../migrations/0045_person_epochs.sql")),
    (46, "single_repo_hash_keys", include_str!("../migrations/0046_single_repo_hash_keys.sql")),
];

pub async fn connect(url: &str, max: u32) -> anyhow::Result<PgPool> {
    let (pool, opts) = options(url, max)?;
    Ok(pool.connect_with(opts).await?)
}

/// A pool that opens its connections when they are first needed (the
/// background deriver's: BUG-911).
pub fn connect_lazy(url: &str, max: u32) -> anyhow::Result<PgPool> {
    let (pool, opts) = options(url, max)?;
    Ok(pool.connect_lazy_with(opts))
}

/// The database URL's parameters about TLS that this server's driver reads:
/// the mode, and the certificate files.
const TLS_PARAMS: &[&str] = &["sslmode", "ssl-mode", "sslrootcert", "ssl-root-cert", "ssl-ca", "sslcert", "ssl-cert", "sslkey", "ssl-key"];

/// An operator who asked for TLS to the database in any recognisable way
/// gets TLS or a refusal at start-up (BUG-1928): the driver ignores a
/// parameter it does not know, so `ssl=true`, `tls=1`, `SSLMODE=require` or
/// a misspelt `sslmod=require` would connect with no TLS and say nothing.
/// Any parameter whose name speaks of TLS and is not one of [`TLS_PARAMS`]
/// is refused, and so is a certificate file given with no mode (the
/// driver's default would not verify with it). The refusal names the
/// parameter only, never its value or the rest of the URL.
fn tls_params_known(url: &str) -> anyhow::Result<()> {
    let query = url.split_once('?').map_or("", |(_, q)| q.split('#').next().unwrap_or(""));
    let keys: Vec<&str> = query.split('&').filter(|p| !p.is_empty()).map(|p| p.split_once('=').map_or(p, |(k, _)| k)).collect();
    const HOW: &str = "for TLS to the database say sslmode=require, or sslmode=verify-ca or sslmode=verify-full with sslrootcert=<file>";
    for k in &keys {
        let lower = k.to_ascii_lowercase();
        if (lower.contains("ssl") || lower.contains("tls")) && !TLS_PARAMS.contains(k) {
            anyhow::bail!("the database URL's parameter '{k}' is not one this server knows, and no TLS would come of it: {HOW}");
        }
    }
    let mode = keys.iter().any(|k| matches!(*k, "sslmode" | "ssl-mode")) || std::env::var_os("PGSSLMODE").is_some();
    if let (false, Some(k)) = (mode, keys.iter().find(|k| TLS_PARAMS.contains(k))) {
        anyhow::bail!("the database URL gives '{k}' and no sslmode, so no TLS would come of it: {HOW}");
    }
    Ok(())
}

fn options(url: &str, max: u32) -> anyhow::Result<(PgPoolOptions, sqlx::postgres::PgConnectOptions)> {
    tls_params_known(url)?;
    let opts: sqlx::postgres::PgConnectOptions = url.parse()?;
    // TLS to the database is the operator's choice (BUG-1590): `sslmode=` in
    // the URL (or `PGSSLMODE`) says `require`, `verify-ca` or `verify-full`.
    // A URL that says nothing asks for no TLS, as before there was any;
    // sqlx's own default (`prefer`) would try it against every database.
    let said = url.split_once('?').is_some_and(|(_, query)| query.split('&').any(|pair| pair.starts_with("sslmode=") || pair.starts_with("ssl-mode=")));
    let opts = if said || std::env::var_os("PGSSLMODE").is_some() { opts } else { opts.ssl_mode(sqlx::postgres::PgSslMode::Disable) };
    let opts = opts.options([
        ("statement_timeout", format!("{}", STATEMENT_TIMEOUT.as_millis())),
        ("lock_timeout", format!("{}", LOCK_TIMEOUT.as_millis())),
    ]);
    Ok((PgPoolOptions::new().max_connections(max).acquire_timeout(Duration::from_secs(30)), opts))
}

/// Refuse to serve on a YugabyteDB that runs `READ COMMITTED` as snapshot
/// isolation (BUG-2135). YugabyteDB does unless its tablet servers run with
/// `yb_enable_read_committed_isolation=true`, and then every reasoning of
/// [`Isolation::ReadCommitted`] that a statement sees what committed before
/// it (the review gate's reads after the gate, BUG-1886) is wrong without a
/// word. Asked of a `READ COMMITTED` transaction of the server's own pool,
/// as every one of its transactions begins; PostgreSQL is not asked.
pub async fn read_committed_is_read_committed(pool: &PgPool) -> anyhow::Result<()> {
    let version: String = sqlx::query_scalar("SELECT version()").fetch_one(pool).await?;
    if !is_yugabyte(&version) {
        return Ok(());
    }
    let mut tx = pool.begin_with("BEGIN ISOLATION LEVEL READ COMMITTED").await?;
    let effective: String = sqlx::query_scalar("SELECT yb_get_effective_transaction_isolation_level()::text").fetch_one(&mut *tx).await?;
    tx.rollback().await?;
    isolation_refusal(&effective).map_or(Ok(()), |m| Err(anyhow::anyhow!(m)))
}

/// Whether `version()` names YugabyteDB.
pub fn is_yugabyte(version: &str) -> bool {
    version.contains("-YB-")
}

/// What the server says, refusing, when a YugabyteDB's `READ COMMITTED`
/// transaction runs at `effective`; `None` when it is read committed.
pub fn isolation_refusal(effective: &str) -> Option<String> {
    (!effective.trim().eq_ignore_ascii_case("read committed")).then(|| {
        format!(
            "this YugabyteDB runs READ COMMITTED transactions as {effective}: start every tablet server with \
             --yb_enable_read_committed_isolation=true (the server's landings rely on read committed)"
        )
    })
}

/// The advisory lock that one migrating process holds (any key; both
/// databases support session advisory locks).
const MIGRATION_LOCK: i64 = 0x7665_696c_6d69_6772; // "veilmigr"
/// How long a process waits for another's migrations to finish.
const MIGRATION_DEADLINE: Duration = Duration::from_secs(600);

/// Whether every migration is applied. Reads only: no DDL.
pub async fn schema_current(pool: &PgPool) -> anyhow::Result<bool> {
    schema_current_in(pool).await.map_err(|e| match e {
        Error::Db(e) => e.into(),
        Error::Other(e) => e,
        e => anyhow::anyhow!("{e:?}"),
    })
}

async fn schema_current_in(pool: &PgPool) -> Result<bool> {
    schema_current_through_in(pool, None).await
}

async fn schema_current_through_in(pool: &PgPool, max_version: Option<i64>) -> Result<bool> {
    let table: Option<String> = sqlx::query_scalar("SELECT to_regclass('schema_migrations')::text").fetch_one(pool).await?;
    if table.is_none() {
        return Ok(false);
    }
    let applied: Vec<i64> = sqlx::query_scalar("SELECT version FROM schema_migrations").fetch_all(pool).await?;
    Ok(MIGRATIONS.iter().filter(|(v, _, _)| max_version.is_none_or(|max| *v <= max)).all(|(v, _, _)| applied.contains(v)))
}

/// Apply every migration not applied yet (BUG-838).
///
/// * A schema that is current is only read: no DDL, so servers starting
///   together (a rolling restart) never change the catalog under the
///   servers already running.
/// * Otherwise one process applies them, holding an advisory lock; the
///   others wait for the lock (up to ten minutes) and then find
///   the schema current.
///
/// `veil-server migrate` runs it on its own, before servers start.
pub async fn migrate(pool: &PgPool) -> anyhow::Result<()> {
    migrate_with_options(pool, None, false, None).await
}

/// Apply every migration, permitting offline maintenance migrations that
/// rebuild existing tables (such as migration 0046 on an existing hash-sharded
/// YugabyteDB database). Every `veil-server` instance must be stopped before
/// running `veil-server migrate --offline` (BUG-2920, BUG-2931).
pub async fn migrate_offline(pool: &PgPool) -> anyhow::Result<()> {
    migrate_with_options(pool, None, true, None).await
}

/// What [`migrate_with`] runs after each online index build returns, before
/// the index is read, given the index's name.
#[doc(hidden)]
pub type AfterBuild = dyn Fn(String) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync;

/// [`migrate`], with `after_build` run after each online index build. For
/// tests only (`startup::bug_2571_…`): a build that returns with its index
/// left incomplete, as YugabyteDB's did (BUG-2571), made at will.
#[doc(hidden)]
pub async fn migrate_with(pool: &PgPool, after_build: Option<&AfterBuild>) -> anyhow::Result<()> {
    migrate_with_options(pool, after_build, false, None).await
}

/// [`migrate`], applying only migrations up to `max_version` (inclusive).
/// For tests only (`startup::bug_2482_…`, `startup::s3rd3_migration_21_…`):
/// lets YugabyteDB tests exercise online migrations through 45 before
/// verifying that migration 46 requires [`migrate_offline`] (BUG-2931).
#[doc(hidden)]
pub async fn migrate_through(pool: &PgPool, max_version: i64) -> anyhow::Result<()> {
    migrate_with_options(pool, None, false, Some(max_version)).await
}

async fn migrate_with_options(
    pool: &PgPool,
    after_build: Option<&AfterBuild>,
    offline: bool,
    max_version: Option<i64>,
) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + MIGRATION_DEADLINE;
    let mut check_attempt: u32 = 0;
    loop {
        match schema_current_through_in(pool, max_version).await {
            Ok(true) => return Ok(()),
            Ok(false) => break,
            Err(e) if e.is_retryable() && tokio::time::Instant::now() < deadline => {
                check_attempt += 1;
                eprintln!("veil-server: checking schema_migrations, retrying: {e:?}");
                tokio::time::sleep(Duration::from_millis(100 * u64::from(check_attempt.min(20)))).await;
            }
            Err(Error::Db(e)) => return Err(e.into()),
            Err(Error::Other(e)) => return Err(e),
            Err(e) => anyhow::bail!("{e:?}"),
        }
    }
    let mut c = pool.acquire().await?;
    // Polled, not a blocking `pg_advisory_lock`: every statement has a
    // timeout, and the wait must have a deadline. Retry retryable errors
    // (short statement timeouts, YugabyteDB catalog/RPC races) within the
    // deadline, as `migrate_locked` does (BUG-2625).
    let mut lock_attempt: u32 = 0;
    loop {
        match sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_lock($1)").bind(MIGRATION_LOCK).fetch_one(&mut *c).await {
            Ok(true) => break,
            Ok(false) => {
                lock_attempt = 0;
                anyhow::ensure!(tokio::time::Instant::now() < deadline, "another server's migrations did not finish within {MIGRATION_DEADLINE:?}");
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Err(e) => {
                let err = Error::Db(e);
                if err.is_retryable() && tokio::time::Instant::now() < deadline {
                    lock_attempt += 1;
                    eprintln!("veil-server: waiting for migrations lock, retrying: {err:?}");
                    // Close the connection in case the lock was acquired before
                    // the statement timed out, then acquire a fresh one.
                    let _ = sqlx::Connection::close(c.detach()).await;
                    tokio::time::sleep(Duration::from_millis(200 * u64::from(lock_attempt.min(10)))).await;
                    c = pool.acquire().await?;
                } else {
                    return Err(match err {
                        Error::Db(e) => e.into(),
                        _ => unreachable!(),
                    });
                }
            }
        }
    }
    let r = migrate_locked(&mut c, deadline, after_build, offline, max_version).await;
    // The lock is the session's: release it, and reset the online index
    // steps' timeouts in case a step's own reset failed
    // (`online_index_step`), or close the connection so that neither goes
    // back into the pool.
    let reset = sqlx::raw_sql("RESET statement_timeout; RESET lock_timeout").execute(&mut *c).await;
    let unlocked = sqlx::query_scalar::<_, bool>("SELECT pg_advisory_unlock($1)").bind(MIGRATION_LOCK).fetch_one(&mut *c).await;
    if reset.is_err() || !matches!(unlocked, Ok(true)) {
        let _ = sqlx::Connection::close(c.detach()).await;
    }
    r
}

/// The migrations not applied yet, by the holder of [`MIGRATION_LOCK`].
/// DDL can still lose a race with other databases' catalog changes on
/// YugabyteDB (the catalog is shared): each step runs again, within the
/// deadline, on a retryable error.
async fn migrate_locked(
    c: &mut PgConnection,
    deadline: tokio::time::Instant,
    after_build: Option<&AfterBuild>,
    offline: bool,
    max_version: Option<i64>,
) -> anyhow::Result<()> {
    let mut attempt: u32 = 0;
    // Per-index completed build counts persist across retryable restarts of
    // `migrate_once` so no index is built more than `BUILD_ATTEMPTS` times
    // in one start (BUG-2625).
    let mut builds: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    // Whether this lock hold created the schema from nothing (`schema_migrations`
    // absent or empty when `migrate_once` first inspected it). Persisted across
    // retryable restarts within the same `MIGRATION_LOCK` hold so a fresh-DB
    // bootstrap that retries a transient YB 40001 mid-migration-46 still knows
    // it created the schema itself and no earlier server can be writing (BUG-2931).
    let mut created_from_scratch: Option<bool> = None;
    loop {
        attempt += 1;
        match migrate_once(&mut *c, deadline, after_build, &mut builds, offline, max_version, &mut created_from_scratch).await {
            Ok(()) => return Ok(()),
            Err(e) if e.is_retryable() && tokio::time::Instant::now() < deadline => {
                eprintln!("veil-server: migrating, retrying: {e:?}");
                tokio::time::sleep(Duration::from_millis(100 * u64::from(attempt.min(20)))).await;
            }
            Err(Error::Db(e)) => return Err(e.into()),
            Err(Error::Other(e)) => return Err(e),
            Err(e) => anyhow::bail!("{e:?}"),
        }
    }
}

async fn migrate_once(
    c: &mut PgConnection,
    deadline: tokio::time::Instant,
    after_build: Option<&AfterBuild>,
    builds: &mut std::collections::HashMap<String, u32>,
    offline: bool,
    max_version: Option<i64>,
    created_from_scratch: &mut Option<bool>,
) -> Result<()> {
    let table: Option<String> = sqlx::query_scalar("SELECT to_regclass('schema_migrations')::text").fetch_one(&mut *c).await?;
    if table.is_none() {
        sqlx::raw_sql("CREATE TABLE IF NOT EXISTS schema_migrations (version BIGINT PRIMARY KEY, name TEXT NOT NULL, applied_at BIGINT NOT NULL)")
            .execute(&mut *c)
            .await?;
    }
    let applied: Vec<i64> = sqlx::query_scalar("SELECT version FROM schema_migrations").fetch_all(&mut *c).await?;
    let from_scratch = *created_from_scratch.get_or_insert_with(|| table.is_none() || applied.is_empty());
    let mut yugabyte = None;
    for &(version, name, sql) in MIGRATIONS {
        if max_version.is_some_and(|max| version > max) {
            continue;
        }
        if applied.contains(&version) {
            continue;
        }
        eprintln!("veil-server: applying migration {version} ({name})");
        let parts = migration_parts(sql).map_err(|e| Error::Other(anyhow::anyhow!("migration {version} ({name}): {e}")))?;
        let record = "INSERT INTO schema_migrations (version, name, applied_at) VALUES ($1, $2, $3)";
        if parts.yugabyte_only {
            let yb = match yugabyte {
                Some(yb) => yb,
                None => {
                    let version: String = sqlx::query_scalar("SELECT version()").fetch_one(&mut *c).await?;
                    *yugabyte.insert(is_yugabyte(&version))
                }
            };
            if yb {
                // Colocated YugabyteDB databases reject hash-partitioned DDL
                // (`cannot colocate hash partitioned table`, BUG-2921): skip
                // hash-sharding migrations on colocated databases and record
                // them as applied, matching PostgreSQL.
                let colocated: bool = sqlx::query_scalar("SELECT yb_is_database_colocated()").fetch_one(&mut *c).await?;
                if !colocated {
                    if version == 46 {
                        // Migration 46 rebuilds hot tables outside a transaction
                        // and is never rolling-upgrade safe on an existing database,
                        // even if those tables happen to be empty (BUG-2920, BUG-2931).
                        // Allow it without `--offline` only when this same lock hold
                        // created the schema from nothing (applying migration 1 itself).
                        if !offline && !from_scratch {
                            return Err(Error::Other(anyhow::anyhow!(
                                "migration 46 (0046_single_repo_hash_keys) rebuilds hot tables on an existing hash-sharded \
                                 YugabyteDB database and is not rolling-upgrade safe: stop all veil-server instances and run \
                                 `veil-server migrate --offline`"
                            )));
                        }
                        yugabyte_only_steps(&mut *c, parts.transactional, deadline).await?;
                        verify_rebuilt_indexes(&mut *c, Q4_REBUILT_TABLES, deadline).await?;
                    } else {
                        yugabyte_only_steps(&mut *c, parts.transactional, deadline).await?;
                    }
                }
            }
            sqlx::query(record).bind(version).bind(name).bind(veil_core::now_millis()).execute(&mut *c).await?;
            continue;
        }
        let steps = migration_steps(parts.transactional);
        if parts.online.is_empty() {
            // Each step in its own committed transaction; the final step
            // records `schema_migrations` atomically with its statements.
            // Multi-step migrations (separated by `-- veil: step`) commit
            // earlier DDL/triggers before later backfill steps so concurrent
            // pre-migration sessions cannot miss the new triggers (BUG-2922).
            // Migration files are idempotent (`IF NOT EXISTS`): YugabyteDB
            // applies DDL in a transaction block statement by statement unless
            // transactional DDL is enabled, so a migration interrupted half-way
            // is applied again from the start.
            let last = steps.len().saturating_sub(1);
            for (i, step) in steps.iter().enumerate() {
                let mut tx = sqlx::Connection::begin(&mut *c).await?;
                sqlx::raw_sql(step).execute(&mut *tx).await?;
                if i == last {
                    sqlx::query(record).bind(version).bind(name).bind(veil_core::now_millis()).execute(&mut *tx).await?;
                }
                tx.commit().await?;
            }
            if steps.is_empty() {
                sqlx::query(record).bind(version).bind(name).bind(veil_core::now_millis()).execute(&mut *c).await?;
            }
            continue;
        }
        // The statements before the online section in committed transaction(s),
        // not recorded; then the online index steps one by one; then the
        // record. A migration that fails anywhere is not recorded and is
        // applied again from the start (both parts are idempotent).
        for step in &steps {
            let mut tx = sqlx::Connection::begin(&mut *c).await?;
            sqlx::raw_sql(step).execute(&mut *tx).await?;
            tx.commit().await?;
        }
        let yb = match yugabyte {
            Some(yb) => yb,
            None => {
                let version: String = sqlx::query_scalar("SELECT version()").fetch_one(&mut *c).await?;
                *yugabyte.insert(is_yugabyte(&version))
            }
        };
        if yb {
            // YugabyteDB's online build holds every row only while it
            // waits for every backend to see each stage of the index.
            let off: Option<String> =
                sqlx::query_scalar("SELECT current_setting('yb_disable_wait_for_backends_catalog_version', true)").fetch_one(&mut *c).await?;
            if off.as_deref() == Some("on") {
                return Err(Error::Other(anyhow::anyhow!(
                    "this YugabyteDB runs with yb_disable_wait_for_backends_catalog_version on, so an index built online \
                     could miss rows written during its build: set it off (its default) to migrate"
                )));
            }
        }
        online_index_steps(&mut *c, yb, &parts.online, deadline, after_build, builds).await?;
        sqlx::query(record).bind(version).bind(name).bind(veil_core::now_millis()).execute(&mut *c).await?;
    }
    Ok(())
}

/// Split a migration's SQL at [`YUGABYTE_STEP`] (`-- veil: step`) lines,
/// dropping empty or comment-only chunks.
pub fn migration_steps(sql: &str) -> Vec<String> {
    let mut step = String::new();
    let mut steps = Vec::new();
    for line in sql.lines() {
        if line.trim() == YUGABYTE_STEP {
            if has_statements(&step) {
                steps.push(std::mem::take(&mut step));
            } else {
                step.clear();
            }
        } else {
            step.push_str(line);
            step.push('\n');
        }
    }
    if has_statements(&step) {
        steps.push(step);
    }
    steps
}

/// Run a [`YUGABYTE_ONLY`] migration's [`YUGABYTE_STEP`]-delimited steps one by
/// one outside a transaction block, under the remaining migration deadline's
/// statement and lock timeouts (resetting both afterwards).
async fn yugabyte_only_steps(c: &mut PgConnection, sql: &str, deadline: tokio::time::Instant) -> Result<()> {
    let steps = migration_steps(sql);
    let left = deadline.saturating_duration_since(tokio::time::Instant::now()).max(STATEMENT_TIMEOUT);
    let ms = left.as_millis();
    sqlx::raw_sql(&format!("SET statement_timeout = {ms}; SET lock_timeout = {ms}")).execute(&mut *c).await?;
    let mut res = Ok(());
    for s in &steps {
        if let Err(e) = sqlx::raw_sql(s).execute(&mut *c).await {
            res = Err(Error::from(e));
            break;
        }
    }
    let reset = sqlx::raw_sql("RESET statement_timeout; RESET lock_timeout").execute(&mut *c).await;
    res?;
    reset?;
    Ok(())
}

/// The eleven hot tables rebuilt by migration 0046 (`0046_single_repo_hash_keys.sql`)
/// on hash-sharded YugabyteDB databases.
const Q4_REBUILT_TABLES: &[&str] = &[
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
];

/// On YugabyteDB: verify that every secondary index on the tables rebuilt by
/// migration 0046 reads live/ready/valid and passes `yb_index_check` before
/// recording the migration (BUG-2920 / BUG-2626).
async fn verify_rebuilt_indexes(c: &mut PgConnection, tables: &[&str], deadline: tokio::time::Instant) -> Result<()> {
    let left = deadline.saturating_duration_since(tokio::time::Instant::now()).max(STATEMENT_TIMEOUT);
    let ms = left.as_millis();
    sqlx::raw_sql(&format!("SET statement_timeout = {ms}; SET lock_timeout = {ms}")).execute(&mut *c).await?;
    let res = async {
        let indexes: Vec<(String, bool)> = sqlx::query_as(
            "SELECT c.relname::text, (i.indislive AND i.indisready AND i.indisvalid) \
             FROM pg_index i \
             JOIN pg_class c ON c.oid = i.indexrelid \
             JOIN pg_class t ON t.oid = i.indrelid \
             JOIN pg_namespace n ON n.oid = t.relnamespace \
             WHERE n.nspname = current_schema() \
               AND NOT i.indisprimary \
               AND t.relname = ANY($1) \
             ORDER BY c.relname",
        )
        .bind(tables)
        .fetch_all(&mut *c)
        .await?;
        for (name, built) in indexes {
            if !built {
                return Err(Error::Other(anyhow::anyhow!(
                    "migration 46 rebuilt index {name} is not live, ready, and valid: drop/rebuild it and re-run `veil-server migrate --offline`"
                )));
            }
            if let Err(e) = sqlx::query("SELECT yb_index_check(to_regclass($1))").bind(&name).execute(&mut *c).await {
                let code = e.as_database_error().and_then(|d| d.code()).map(|code| code.into_owned());
                return Err(match code.as_deref() {
                    Some("XX002") => Error::Other(anyhow::anyhow!(
                        "migration 46 rebuilt index {name} failed yb_index_check ({e}): drop/rebuild it and re-run `veil-server migrate --offline`"
                    )),
                    Some("57014" | "55P03") => Error::Other(anyhow::anyhow!(
                        "checking rebuilt index {name} against its table did not finish within {MIGRATION_DEADLINE:?} ({e}): \
                         the migration is not recorded, and the next `veil-server migrate --offline` checks again"
                    )),
                    Some("42883") => Error::Other(anyhow::anyhow!(
                        "this YugabyteDB has no yb_index_check ({e}), so rebuilt index {name} cannot be verified against its table"
                    )),
                    _ => Error::from(e),
                });
            }
        }
        Ok(())
    }
    .await;
    let reset = sqlx::raw_sql("RESET statement_timeout; RESET lock_timeout").execute(&mut *c).await;
    res?;
    reset?;
    Ok(())
}

/// The line of a migration after which its statements are index steps
/// applied online, one by one, outside its transaction (BUG-2482): every
/// index on a table that servers already write (a rolling upgrade's
/// running servers write it while the index is built).
///
/// * Built in a transaction block, an index holds every write to its table
///   off for the whole build on PostgreSQL (a large table's stalls every
///   push, and the build can pass the 15 s statement timeout, so the
///   migration never finishes); on YugabyteDB it is built without holding
///   writes off, and rows written during the build can be missing from it
///   with no error.
/// * Outside one, `CREATE INDEX CONCURRENTLY` is PostgreSQL's online build
///   and YugabyteDB's (its default outside a transaction block: the index
///   takes writes before its backfill, then is made valid).
/// * A step is `CREATE [UNIQUE] INDEX CONCURRENTLY IF NOT EXISTS <name> …;`
///   or `DROP INDEX CONCURRENTLY IF EXISTS <name>;` (the runner drops with
///   `DROP INDEX IF EXISTS` on YugabyteDB, which has no concurrent drop);
///   whole-line `--` comments only, no other statement ([`migration_parts`]).
/// * An index is built when `pg_index` reads it live, ready and valid
///   (`indislive`, `indisready`, `indisvalid`; `index_built`). One that
///   is not (a failed build left it invalid: `IF NOT EXISTS` would keep it,
///   and the database would never use it, or a unique one would refuse
///   rows while not serving reads) is dropped before the build. After the
///   build the index must read built within `VALID_WAIT` (on YugabyteDB,
///   under load, a build returned about 200 ms before its session read the
///   index valid, BUG-2482); if it does not, it is dropped and built again,
///   up to `BUILD_ATTEMPTS` builds: on YugabyteDB a build can return
///   success with a stage of its index lost for good (BUG-2571: its last
///   step's catalog version increment lost a race with another database's
///   DDL, and `indisvalid` stayed false). An index that no build made
///   built fails the migration, which is not recorded.
/// * On YugabyteDB the indexes a migration's steps built are then checked
///   against their tables (`yb_index_check`, `checked_on_yugabyte`),
///   whoever built them: an online build there ended live, ready and valid
///   without the rows other sessions wrote during its backfill (BUG-2626).
///   Every session of the database is waited for first (one more online
///   build, of an index on the migrations' own table, made for its wait
///   and dropped): a session that writes without the index does so until
///   it takes in the build's last stage. An index that misses a row, or
///   holds one its table does not, is dropped and built again, up to
///   `BUILD_ATTEMPTS` builds; a migration is recorded only over indexes
///   that passed. The check reads the whole index and its table rows
///   (200,000 rows in 1.2 s on the test cluster; 5.1 million in 33 s beside
///   two inserting sessions), under the steps' timeouts: one that does not
///   finish fails the start, and the next start checks again with the
///   whole deadline. PostgreSQL's online build waits out every transaction
///   that could write the table without the index, and is not checked.
/// * An index step runs under statement and lock timeouts of what is left
///   of the migrations' deadline (at least [`STATEMENT_TIMEOUT`]), not the
///   pool's: a large table's build takes longer than 15 s, and the
///   concurrent build waits for the transactions already running. A build
///   that needs longer than is left fails, saying how to build the index by
///   hand (BUG-2520: it would time out at every start).
///
/// An index on a table created by the same migration needs none of this
/// (no server writes a table it does not know): it stays in the transaction.
pub const ONLINE_INDEXES: &str = "-- veil: online indexes";

/// First line of a migration whose SQL uses YugabyteDB-only hash-sharding DDL
/// (such as composite hash keys `PRIMARY KEY ((a, b) HASH)`). On PostgreSQL
/// (`!is_yugabyte(version)`) and on colocated YugabyteDB databases
/// (`yb_is_database_colocated()`, BUG-2921) the runner skips executing the SQL
/// and records the migration as applied; on non-colocated YugabyteDB its
/// [`YUGABYTE_STEP`]-delimited steps run one by one outside a transaction block.
pub const YUGABYTE_ONLY: &str = "-- veil: yugabyte-only";

/// Step boundary inside a [`YUGABYTE_ONLY`] migration: each step runs as its
/// own top-level query outside a transaction block.
pub const YUGABYTE_STEP: &str = "-- veil: step";

/// A migration's statements: those applied in one transaction (or step by step
/// on YugabyteDB when `yugabyte_only` is set), then its [`ONLINE_INDEXES`]
/// steps.
#[derive(Debug)]
pub struct MigrationParts<'a> {
    pub transactional: &'a str,
    pub online: Vec<IndexStep>,
    pub yugabyte_only: bool,
}

/// One step of a migration's [`ONLINE_INDEXES`] section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexStep {
    /// Build index `name` with `sql` (`CREATE … INDEX CONCURRENTLY IF NOT EXISTS`).
    Create { name: String, sql: String },
    /// Drop index `name`, if it exists.
    Drop { name: String },
}

/// Split a migration at its [`ONLINE_INDEXES`] line, and read its steps;
/// what the section holds that is not a step is refused.
pub fn migration_parts(sql: &str) -> std::result::Result<MigrationParts<'_>, String> {
    let yugabyte_only = sql.lines().next().is_some_and(|l| l.trim() == YUGABYTE_ONLY);
    let at = sql.match_indices(ONLINE_INDEXES).map(|(i, _)| i).find(|&i| i == 0 || sql.as_bytes()[i - 1] == b'\n');
    let Some(at) = at else {
        return Ok(MigrationParts { transactional: sql, online: Vec::new(), yugabyte_only });
    };
    if yugabyte_only {
        return Err("a yugabyte-only migration may not hold an online indexes section".into());
    }
    let rest = &sql[at..];
    let section = rest.split_once('\n').map_or("", |(_, after)| after);
    if section.lines().any(|l| l.trim_start().starts_with(ONLINE_INDEXES)) {
        return Err("more than one online indexes section".into());
    }
    let text: String = section.lines().filter(|l| !l.trim_start().starts_with("--")).collect::<Vec<_>>().join("\n");
    if !text.trim_end().is_empty() && !text.trim_end().ends_with(';') {
        return Err("the online indexes section's last statement does not end with ';'".into());
    }
    let mut online = Vec::new();
    for stmt in text.split(';').map(str::trim).filter(|s| !s.is_empty()) {
        if stmt.contains("--") || stmt.contains("/*") || stmt.contains('$') {
            return Err(format!("an online index step may hold no comment or dollar quote: {stmt}"));
        }
        let words: Vec<&str> = stmt.split_whitespace().collect();
        let identifier = |w: &str| {
            !w.is_empty()
                && w.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
                && !w.as_bytes()[0].is_ascii_digit()
        };
        let create = match words.as_slice() {
            ["CREATE", "INDEX", "CONCURRENTLY", "IF", "NOT", "EXISTS", name, "ON", _, ..] => Some(*name),
            ["CREATE", "UNIQUE", "INDEX", "CONCURRENTLY", "IF", "NOT", "EXISTS", name, "ON", _, ..] => Some(*name),
            _ => None,
        };
        match (create, words.as_slice()) {
            (Some(name), _) if identifier(name) => online.push(IndexStep::Create { name: name.to_string(), sql: stmt.to_string() }),
            (None, ["DROP", "INDEX", "CONCURRENTLY", "IF", "EXISTS", name]) if identifier(name) => {
                online.push(IndexStep::Drop { name: name.to_string() })
            }
            _ => {
                return Err(format!(
                    "an online index step is `CREATE [UNIQUE] INDEX CONCURRENTLY IF NOT EXISTS <name> ON …` or \
                     `DROP INDEX CONCURRENTLY IF EXISTS <name>` (a lower-case name): {stmt}"
                ))
            }
        }
    }
    if online.is_empty() {
        return Err("an online indexes section with no step".into());
    }
    Ok(MigrationParts { transactional: &sql[..at], online, yugabyte_only })
}

/// Whether `sql` holds anything but blank lines and `--` comments.
fn has_statements(sql: &str) -> bool {
    sql.lines().any(|l| {
        let l = l.trim();
        !l.is_empty() && !l.starts_with("--")
    })
}

/// Whether index `name` exists, and if so whether it is built: live,
/// ready and valid in `pg_index`, each stage of an online build. `None`
/// when no relation has the name, `Some(None)` when one does that is not
/// an index.
///
/// Valid alone is not enough on YugabyteDB: a stage's catalog write can be
/// lost while its build returns success (BUG-2571, where `indisvalid` was
/// lost), and an index made valid with `indisready` lost would be read
/// while writes leave it out.
async fn index_built(c: &mut PgConnection, name: &str) -> Result<Option<Option<bool>>> {
    let row: Option<(Option<bool>,)> = sqlx::query_as(
        "SELECT (SELECT i.indislive AND i.indisready AND i.indisvalid FROM pg_index i WHERE i.indexrelid = r.oid) \
         FROM (SELECT to_regclass($1) AS oid) r WHERE r.oid IS NOT NULL",
    )
    .bind(name)
    .fetch_optional(&mut *c)
    .await?;
    Ok(row.map(|(v,)| v))
}

/// Drop index `name` if it exists, online where the database can.
async fn drop_index(c: &mut PgConnection, yugabyte: bool, name: &str) -> Result<()> {
    // `name` is a checked lower-case identifier (`migration_parts`).
    let q = if yugabyte { format!("DROP INDEX IF EXISTS {name}") } else { format!("DROP INDEX CONCURRENTLY IF EXISTS {name}") };
    sqlx::raw_sql(&q).execute(&mut *c).await?;
    Ok(())
}

/// Apply a migration's [`ONLINE_INDEXES`] steps, one by one; then, on
/// YugabyteDB, check the indexes they built against their tables
/// ([`checked_on_yugabyte`]), and build again those that miss rows (dropped
/// as that was found), up to `BUILD_ATTEMPTS` builds of an index, while
/// the deadline lasts (BUG-2626). It returns only with every index whole.
async fn online_index_steps(
    c: &mut PgConnection,
    yugabyte: bool,
    steps: &[IndexStep],
    deadline: tokio::time::Instant,
    after_build: Option<&AfterBuild>,
    builds: &mut std::collections::HashMap<String, u32>,
) -> Result<()> {
    let mut pending: Vec<&IndexStep> = steps.iter().collect();
    loop {
        for step in &pending {
            online_index_step(&mut *c, yugabyte, step, deadline, after_build, builds).await?;
        }
        pending.retain(|step| matches!(step, IndexStep::Create { .. }));
        if !yugabyte || pending.is_empty() {
            return Ok(());
        }
        let left = deadline.saturating_duration_since(tokio::time::Instant::now()).max(STATEMENT_TIMEOUT);
        let ms = left.as_millis();
        sqlx::raw_sql(&format!("SET statement_timeout = {ms}; SET lock_timeout = {ms}")).execute(&mut *c).await?;
        let r = checked_on_yugabyte(&mut *c, &pending).await;
        let reset = sqlx::raw_sql("RESET statement_timeout; RESET lock_timeout").execute(&mut *c).await;
        let whole = r?;
        pending = pending.into_iter().zip(whole).filter(|(_, whole)| !whole).map(|(step, _)| step).collect();
        if pending.is_empty() {
            reset?;
            return Ok(());
        }
        let exhausted = pending.iter().find_map(|step| match step {
            IndexStep::Create { name, .. } => {
                let tried = builds.get(name.as_str()).copied().unwrap_or(0);
                (tried >= BUILD_ATTEMPTS).then_some((name, tried))
            }
            IndexStep::Drop { .. } => None,
        });
        if let Some((name, tried)) = exhausted {
            return Err(not_built_whole(name, tried));
        }
        let Some(IndexStep::Create { name, .. }) = pending.first() else {
            reset?;
            return Ok(());
        };
        let tried = builds.get(name.as_str()).copied().unwrap_or(0);
        if tokio::time::Instant::now() >= deadline {
            return Err(not_built_whole(name, tried.max(1)));
        }
        reset?;
        if tried == 0 {
            eprintln!("veil-server: index {name} found built is not whole: building it again");
        } else {
            eprintln!("veil-server: index {name} is not built whole after build {tried} returned: building it again");
        }
    }
}

/// What a start says of an index no build made whole.
fn not_built_whole(name: &str, builds: u32) -> Error {
    Error::Other(anyhow::anyhow!(
        "index {name} is not built whole (live, ready and valid within {VALID_WAIT:?} of its build, and holding its \
         table's rows) in {builds} builds: the migration is not recorded, and the next start builds the index again"
    ))
}

/// On YugabyteDB: whether each of `built` (index steps whose indexes read
/// built) holds a row for every row of its table, and no other; one that
/// does not is dropped ([`index_holds_every_row`]).
///
/// First every session of the database is waited for (BUG-2626): one that
/// writes the table without the index goes on until it takes in the
/// build's last stage (seen: at its next statement on the build's own
/// node, within 2 ms of the stage being written; on another node, once
/// that node has heard of the stage; a statement already running, until
/// it ends),
/// and rows it writes after the check has read are not seen by it.
/// YugabyteDB waits for every backend only inside an online index build
/// (after its first stage, for every backend of the database to be at that
/// stage's catalog version, which is past the last of the builds before
/// it), so one is made here for that wait alone
/// ([`wait_for_every_session`]). The wait covers a transaction that wrote without the
/// index and has not ended: a session keeps its catalog version for the
/// whole of a transaction, and is waited for until the transaction ends
/// (measured: a build on another table did not return while a session
/// was idle in a transaction that had written, nor while that
/// transaction ran another statement and stayed open). So what was
/// written without the index is committed, or gone, when the check reads.
async fn checked_on_yugabyte(c: &mut PgConnection, built: &[&IndexStep]) -> Result<Vec<bool>> {
    wait_for_every_session(&mut *c).await?;
    let mut whole = Vec::with_capacity(built.len());
    for step in built {
        whole.push(match step {
            IndexStep::Create { name, .. } => match index_built(&mut *c, name).await? {
                Some(Some(true)) => index_holds_every_row(&mut *c, name).await?,
                Some(Some(false)) | None => {
                    eprintln!("veil-server: index {name} does not read built after waiting for every session: building it again");
                    false
                }
                Some(None) => return Err(Error::Other(anyhow::anyhow!("{name} is not an index, so the index of that name was not built"))),
            },
            IndexStep::Drop { .. } => true,
        });
    }
    Ok(whole)
}

/// On YugabyteDB: wait until every backend of the database has taken in
/// every catalog change made so far, by an online build made for that wait
/// alone ([`checked_on_yugabyte`]): of an index on the migrations' own
/// table, under a name of its own, dropped at once.
///
/// The wait is done when the index reads **ready**: an online build sets
/// `indisready` only after its wait for every backend at its first stage.
/// That is what is looked at, not the statement's answer: under other
/// databases' DDL the statement was seen to commit its live and ready
/// stages and then fail with "relation … already exists", of its own index
/// (13 ms after the ready stage; the database running the statement again
/// from its start is the likely reason), and a build can also answer
/// success with a stage lost (BUG-2571). An index that does not read ready
/// is dropped and another is built, up to `BUILD_ATTEMPTS`; then the start
/// fails, unrecorded.
async fn wait_for_every_session(c: &mut PgConnection) -> Result<()> {
    drop_settle_indexes(&mut *c).await;
    let mut last = None;
    for _ in 0..BUILD_ATTEMPTS {
        let name = format!("{SETTLE_PREFIX}{}", hex::encode(veil_core::crypto::random_bytes::<8>()));
        let built = sqlx::raw_sql(&format!("CREATE INDEX CONCURRENTLY {name} ON schema_migrations (version)")).execute(&mut *c).await;
        // Read from the catalog itself, not through the session's names.
        let ready: Option<bool> =
            sqlx::query_scalar("SELECT i.indisready FROM pg_class c JOIN pg_index i ON i.indexrelid = c.oid WHERE c.relname = $1").bind(&name).fetch_optional(&mut *c).await?;
        drop_settle_indexes(&mut *c).await;
        match (built, ready) {
            (_, Some(true)) => return Ok(()),
            // Its own name taken: the statement was run again before its wait.
            (Err(e), _) if e.as_database_error().and_then(|d| d.code()).is_some_and(|code| code == "42P07") => last = Some(e.to_string()),
            (Err(e), _) => return Err(e.into()),
            (Ok(_), _) => last = Some("the build answered, and its index does not read ready".into()),
        }
        eprintln!("veil-server: the build made to wait for every session did not reach its ready stage ({}): another", last.as_deref().unwrap_or_default());
    }
    Err(Error::Other(anyhow::anyhow!(
        "no online build reached its ready stage in {BUILD_ATTEMPTS} tries ({}), so the sessions that may write without a new index were not \
         waited for and the index cannot be checked: the migration is not recorded, and the next start tries again",
        last.unwrap_or_default()
    )))
}

/// Drop the indexes [`wait_for_every_session`] made (this one's, one a
/// start that died left, one whose drop the database lost). As far as it
/// goes: one left is a small index on the migrations' table, dropped by a
/// later start.
async fn drop_settle_indexes(c: &mut PgConnection) {
    let names: std::result::Result<Vec<String>, sqlx::Error> = sqlx::query_scalar(
        "SELECT c.relname::text FROM pg_class c JOIN pg_index i ON i.indexrelid = c.oid \
         WHERE i.indrelid = to_regclass('schema_migrations') AND c.relname LIKE $1",
    )
    .bind(format!("{}%", SETTLE_PREFIX.replace('_', "\\_")))
    .fetch_all(&mut *c)
    .await;
    for name in names.unwrap_or_default() {
        // Its own names only: the prefix and sixteen hex digits.
        let own = name.strip_prefix(SETTLE_PREFIX).is_some_and(|rest| rest.len() == 16 && rest.bytes().all(|b| b.is_ascii_hexdigit()));
        if own {
            if let Err(e) = sqlx::raw_sql(&format!("DROP INDEX IF EXISTS {name}")).execute(&mut *c).await {
                eprintln!("veil-server: dropping {name}, an index made to wait for every session: {e} (a later start drops it)");
            }
        }
    }
}

/// What the name of an index [`wait_for_every_session`] builds begins with.
const SETTLE_PREFIX: &str = "veil_settle_";

/// Apply one [`ONLINE_INDEXES`] step, outside any transaction, under
/// statement and lock timeouts of what is left of the migrations' deadline
/// (at least the pool's own statement timeout), then the connection's own
/// again (`migrate` resets them too, or closes the connection). An index
/// that does not read built after its build is built again, up to
/// `BUILD_ATTEMPTS` builds, while the deadline lasts (BUG-2571).
async fn online_index_step(
    c: &mut PgConnection,
    yugabyte: bool,
    step: &IndexStep,
    deadline: tokio::time::Instant,
    after_build: Option<&AfterBuild>,
    builds: &mut std::collections::HashMap<String, u32>,
) -> Result<()> {
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now()).max(STATEMENT_TIMEOUT);
        let ms = left.as_millis();
        sqlx::raw_sql(&format!("SET statement_timeout = {ms}; SET lock_timeout = {ms}")).execute(&mut *c).await?;
        let r = online_index_step_now(&mut *c, yugabyte, step, after_build, builds).await;
        let reset = sqlx::raw_sql("RESET statement_timeout; RESET lock_timeout").execute(&mut *c).await;
        let built = r?;
        let name = match (built, step) {
            (true, _) | (_, IndexStep::Drop { .. }) => {
                reset?;
                return Ok(());
            }
            (false, IndexStep::Create { name, .. }) => name,
        };
        let tried = builds.get(name.as_str()).copied().unwrap_or(0);
        if tried >= BUILD_ATTEMPTS || tokio::time::Instant::now() >= deadline {
            return Err(not_built_whole(name, tried.max(1)));
        }
        reset?;
        // Dropped by the next build, before it begins.
        eprintln!("veil-server: index {name} is not built (live, ready and valid) {VALID_WAIT:?} after build {tried} returned: building it again");
    }
}

/// One try at a step: `false` when a build returned and its index did not
/// read built within `VALID_WAIT`.
async fn online_index_step_now(
    c: &mut PgConnection,
    yugabyte: bool,
    step: &IndexStep,
    after_build: Option<&AfterBuild>,
    builds: &mut std::collections::HashMap<String, u32>,
) -> Result<bool> {
    let (name, sql) = match step {
        IndexStep::Drop { name } => return drop_index(&mut *c, yugabyte, name).await.map(|()| true),
        IndexStep::Create { name, sql } => (name, sql),
    };
    match index_built(&mut *c, name).await? {
        Some(Some(true)) => return Ok(true),
        Some(Some(false)) => {
            let tried = builds.get(name.as_str()).copied().unwrap_or(0);
            if tried >= BUILD_ATTEMPTS {
                return Err(not_built_whole(name, tried));
            }
            eprintln!("veil-server: index {name} was left incomplete by a build that did not finish: dropping it to build it again");
            drop_index(&mut *c, yugabyte, name).await?;
        }
        Some(None) => return Err(Error::Other(anyhow::anyhow!("{name} is not an index, so the index of that name was not built"))),
        None => {
            let tried = builds.get(name.as_str()).copied().unwrap_or(0);
            if tried >= BUILD_ATTEMPTS {
                return Err(not_built_whole(name, tried));
            }
        }
    }
    if let Err(e) = sqlx::raw_sql(sql).execute(&mut *c).await {
        // A failed build leaves its index invalid: not used, but written
        // (and a unique one refusing rows). Dropped now when it can be, or
        // before the build is tried again.
        if let Ok(Some(Some(false))) = index_built(&mut *c, name).await {
            let _ = drop_index(&mut *c, yugabyte, name).await;
        }
        // Its timeouts are what was left of the migrations' deadline: a
        // build that needs longer would time out at every start, dropped
        // and begun again (BUG-2520). Say how to build it by hand instead.
        let timed_out = e.as_database_error().and_then(|d| d.code()).is_some_and(|code| code == "57014" || code == "55P03");
        if timed_out {
            // On YugabyteDB the start that finds it built still checks it
            // against its table before it records anything (BUG-2626).
            let then = match yugabyte {
                true => "it finds the index built, checks it against its table (`yb_index_check`, which reads all of both, within the same time), and records the migration",
                false => "it finds the index built and records the migration",
            };
            return Err(Error::Other(anyhow::anyhow!(
                "building index {name} did not finish within what was left of the migrations' {MIGRATION_DEADLINE:?} ({e}): \
                 build it by hand, as long as it takes, with `{sql}` (if that build fails, first drop the invalid index it \
                 leaves with `DROP INDEX IF EXISTS {name}`), then start the server again: {then}"
            )));
        }
        return Err(e.into());
    }
    *builds.entry(name.clone()).or_default() += 1;
    if let Some(after_build) = after_build {
        after_build(name.clone()).await;
    }
    // On YugabyteDB, under load, the build can return before this session
    // reads its index valid (seen in `verify-server.sh`), or reads it at
    // all: read again, for at most `VALID_WAIT`.
    let began = tokio::time::Instant::now();
    let until = began + VALID_WAIT;
    let mut looks = 0u32;
    loop {
        looks += 1;
        match index_built(&mut *c, name).await {
            Ok(Some(Some(true))) => {
                if looks > 1 {
                    eprintln!("veil-server: index {name} read built {:?} after its build returned", began.elapsed());
                }
                return Ok(true);
            }
            Ok(Some(Some(false)) | None) if tokio::time::Instant::now() < until => tokio::time::sleep(Duration::from_millis(200)).await,
            Ok(Some(Some(false)) | None) => return Ok(false),
            Ok(Some(None)) => return Err(Error::Other(anyhow::anyhow!("{name} is not an index, so the index of that name was not built"))),
            Err(e) if e.is_retryable() && tokio::time::Instant::now() < until => {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Err(e) => return Err(e),
        }
    }
}

/// On YugabyteDB: whether index `name`, which reads built, holds a row for
/// every row of its table and no other (`yb_index_check`: every index row
/// against its table row, and the two counts). One that does not is dropped
/// here, and `false` is the answer: it is built again.
///
/// BUG-2626: an online build there ended live, ready and valid with the
/// rows sessions inserted during its backfill missing (2 builds of 40,
/// beside DDL in other databases: 42,471 of 698,266 rows, 12,527 of
/// 221,002): its flags say what the build did, not what the other
/// sessions wrote. A built index that was dropped only for its flags would
/// stay (`IF NOT EXISTS`), so it is dropped by what the check finds.
async fn index_holds_every_row(c: &mut PgConnection, name: &str) -> Result<bool> {
    let e = match sqlx::query("SELECT yb_index_check(to_regclass($1))").bind(name).execute(&mut *c).await {
        Ok(_) => return Ok(true),
        Err(e) => e,
    };
    let db_err = e.as_database_error();
    let code = db_err.and_then(|d| d.code()).map(|code| code.into_owned());
    match code.as_deref() {
        // `index_corrupted`: a row missing from the index, or one in it
        // that its table does not hold.
        Some("XX002") => {
            eprintln!("veil-server: index {name} reads built and does not hold its table's rows ({e}): dropping it to build it again");
            drop_index(&mut *c, true, name).await?;
            Ok(false)
        }
        // `internal_error` when `yb_index_check` sees `indisvalid = false`
        // (BUG-2625: e.g. a stale `pg_index` read saw it valid before the
        // catalog refreshed). Drop only if `index_built` still reads it valid,
        // so the next pass cannot skip rebuilding while leaving an invalid
        // index in place if `BUILD_ATTEMPTS` is exhausted.
        Some("XX000") if db_err.is_some_and(|d| d.message().contains("is marked invalid")) => {
            eprintln!("veil-server: index {name} is marked invalid ({e}): building it again");
            if index_built(&mut *c, name).await? == Some(Some(true)) {
                drop_index(&mut *c, true, name).await?;
            }
            Ok(false)
        }
        // Under what was left of the migrations' deadline, as the build.
        Some("57014" | "55P03") => Err(Error::Other(anyhow::anyhow!(
            "checking index {name} against its table did not finish within what was left of the migrations' {MIGRATION_DEADLINE:?} \
             ({e}): the migration is not recorded, and the next start checks the index again, with the whole of that time"
        ))),
        Some("42883") => Err(Error::Other(anyhow::anyhow!(
            "this YugabyteDB has no yb_index_check ({e}), so an index built online cannot be checked against its table, and \
             the migration is not recorded: YugabyteDB 2025.2 has it"
        ))),
        _ => Err(e.into()),
    }
}

/// How long an index that its build returned from may take to read built
/// (live, ready and valid) before it is built again. The lag seen was about
/// 200 ms (BUG-2482); a build whose stage was lost (BUG-2571) read invalid
/// minutes later, in new sessions, and is not waited for longer.
const VALID_WAIT: Duration = Duration::from_secs(15);
/// How many times one migration step builds an index that does not read
/// built after its build (BUG-2571), within the migrations' deadline.
const BUILD_ATTEMPTS: u32 = 5;

pub type TxFuture<'t, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 't>>;

/// What a database commit was made for, counted where it is made
/// ([`Commits::count`]; BUG-2350): the server's counters (`SIGUSR1`) give the
/// load tool's cost gates (`storage-and-cost.md` §9) the commits by kind,
/// so a push is charged its own and not the background work beside it.
/// The staged-pack rows are counted apart (`Objects::pack_rows`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Commit {
    /// A push's one transaction (`sync::push_with`), one that queues no landing.
    Push,
    /// A push's transaction that queues a landing (`POST …/land`, a push
    /// to a protected branch): the landing's submit.
    LandSubmit,
    /// A landing batch of the landing service.
    LandBatch,
    /// The landing service's lease and clean-up rows.
    LandService,
    /// The deriver's transactions (S12; one a landing run, BUG-1593).
    Derive,
    /// A view key's fill (`query::graph`, `query::files`): its rows, its
    /// lease, and the projection memos it stores.
    Fill,
    /// A projection memo stored by a request on its own (a viewer's first
    /// look at a snapshot no transaction memoised).
    Memo,
    /// The search index's own transactions (an update the deriver's run
    /// did not take).
    Search,
    /// Pack merges and garbage collection (S29).
    PackGc,
    /// The notices that drop every server's cached tips, sent after the
    /// commits that moved them (`caches::send_notices`, BUG-2459).
    Notice,
}

impl Commit {
    const ALL: [Commit; 10] = [
        Commit::Push,
        Commit::LandSubmit,
        Commit::LandBatch,
        Commit::LandService,
        Commit::Derive,
        Commit::Fill,
        Commit::Memo,
        Commit::Search,
        Commit::PackGc,
        Commit::Notice,
    ];

    fn name(self) -> &'static str {
        match self {
            Commit::Push => "push",
            Commit::LandSubmit => "land_submit",
            Commit::LandBatch => "land_batch",
            Commit::LandService => "land_service",
            Commit::Derive => "derive",
            Commit::Fill => "fill",
            Commit::Memo => "memo",
            Commit::Search => "search",
            Commit::PackGc => "pack_gc",
            Commit::Notice => "notice",
        }
    }
}

/// A server's database commits by kind ([`Commit`]), `Hub::commits`.
#[derive(Default)]
pub struct Commits([std::sync::atomic::AtomicU64; Commit::ALL.len()]);

impl Commits {
    /// Count one database commit of `kind` (a transaction that committed,
    /// or a write that committed on its own).
    pub fn count(&self, kind: Commit) {
        self.0[kind as usize].fetch_add(1, Ordering::Relaxed);
    }

    /// The commits of `kind` counted so far.
    pub fn of(&self, kind: Commit) -> u64 {
        self.0[kind as usize].load(Ordering::Relaxed)
    }

    /// The commits counted so far, by kind (`{"push": n, …}`).
    pub fn by_kind(&self) -> serde_json::Value {
        Commit::ALL.iter().map(|k| (k.name().to_string(), serde_json::json!(self.of(*k)))).collect::<serde_json::Map<_, _>>().into()
    }
}

/// How long one statement may run, or wait for a lock, before the database
/// cancels it (every connection sets these): nothing waits forever.
pub const STATEMENT_TIMEOUT: Duration = Duration::from_secs(15);
pub const LOCK_TIMEOUT: Duration = Duration::from_secs(10);
/// How long one transaction, retries included, may take before the request
/// fails with "the database is busy".
pub const TRANSACTION_DEADLINE: Duration = Duration::from_secs(45);

/// Isolation of a [`transaction`].
#[derive(Clone, Copy, Debug)]
pub enum Isolation {
    /// For read-check-write sequences whose race no unique key or row lock
    /// decides.
    Serializable,
    /// For compare-and-swaps that are atomic on their own (a branch move is
    /// one conditional `UPDATE` of one row), and for transactions whose
    /// races unique keys and row locks decide (sign-in, project and group
    /// creation, group changes: BUG-847). SERIALIZABLE would add read
    /// locks that make racing pushers block one another; on YugabyteDB they
    /// queued for minutes. (YugabyteDB runs it as REPEATABLE READ unless
    /// read committed is enabled; both fail fast on a conflict.)
    ReadCommitted,
    /// For several reads that must be of one moment of the database
    /// (`REPEATABLE READ READ ONLY`: one snapshot, on PostgreSQL and
    /// YugabyteDB): pack GC's reference stamp with the roots it stands for
    /// (BUG-2602).
    Snapshot,
}

/// Run `f` in a SERIALIZABLE transaction ([`transaction`]).
pub async fn serializable<T, F>(pool: &PgPool, f: F) -> Result<T>
where
    F: for<'t> FnMut(&'t mut PgConnection) -> TxFuture<'t, T>,
{
    transaction(pool, Isolation::Serializable, f).await
}

/// Run `f` in a transaction, again (with capped, jittered backoff) while it
/// loses a race, until [`TRANSACTION_DEADLINE`]: then a clear error. `f`
/// may run several times, so it must not have effects outside the
/// transaction.
pub async fn transaction<T, F>(pool: &PgPool, isolation: Isolation, mut f: F) -> Result<T>
where
    F: for<'t> FnMut(&'t mut PgConnection) -> TxFuture<'t, T>,
{
    let begin = match isolation {
        Isolation::Serializable => "BEGIN ISOLATION LEVEL SERIALIZABLE",
        Isolation::ReadCommitted => "BEGIN ISOLATION LEVEL READ COMMITTED",
        Isolation::Snapshot => "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY",
    };
    let deadline = tokio::time::Instant::now() + TRANSACTION_DEADLINE;
    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        let once = async {
            let mut tx = pool.begin_with(begin).await?;
            match f(&mut tx).await {
                Ok(v) => {
                    let r = tx.commit().await.map(|_| v).map_err(Error::from);
                    // Whatever the outcome, the request may have changed
                    // something now: [`retry_requests`] does not run it again.
                    crate::limits::mark_committed();
                    // A commit that timed out may have committed: neither is
                    // `f` run again (BUG-890). Its text only: the database
                    // error itself would be found retryable (BUG-2340).
                    match r {
                        Err(Error::Db(e)) if e.as_database_error().is_some_and(|d| crate::error::is_rpc_timeout(d.message())) => {
                            Err(Error::Other(anyhow::anyhow!("the commit timed out; its outcome is unknown: {e}")))
                        }
                        r => r,
                    }
                }
                Err(e) => {
                    let _ = tx.rollback().await;
                    Err(e)
                }
            }
        };
        // The review gate's writers this attempt announced are removed when
        // it ends, committed or not (BUG-2110, `prs::review_gate`).
        let r = match tokio::time::timeout_at(deadline, crate::prs::review_gate::scoped(pool, once)).await {
            Ok(r) => r,
            Err(_) => return Err(Error::busy()),
        };
        match r {
            Err(e) if e.is_retryable() => {
                let cap = 5u64 << attempt.min(6);
                let jitter = u64::from(u16::from_le_bytes(veil_core::crypto::random_bytes::<2>()));
                let wake = tokio::time::Instant::now() + Duration::from_millis(cap / 2 + jitter % cap);
                if wake >= deadline {
                    return Err(Error::busy());
                }
                tokio::time::sleep_until(wake).await;
            }
            r => return r,
        }
    }
}

/// A response that failed on a retryable database error
/// ([`Error::is_retryable`]); set by the error's `IntoResponse`.
#[derive(Clone, Copy, Debug)]
pub struct Retryable;

/// Most bytes of a request body: what the routes accept
/// (`api::router`'s `DefaultBodyLimit`s).
pub fn body_limit(path: &str) -> usize {
    if path.ends_with("/objects") {
        2 << 30
    } else if !path.is_empty() && !path.starts_with("/v1/") {
        256 << 10
    } else {
        64 << 20
    }
}

/// Middleware: run a request again, with capped and jittered backoff until
/// [`TRANSACTION_DEADLINE`], when it fails on a retryable database error
/// outside a [`transaction`] (which retries itself): an autocommit read
/// racing a schema change on YugabyteDB, a restarted read (BUG-838). A
/// request runs again only while nothing it did was committed by a
/// transaction; what it did outside one is idempotent (content-addressed
/// objects, `ON CONFLICT DO NOTHING` memos, single-use challenges that
/// fail closed). The body is buffered (as the handlers' extractors do).
pub async fn retry_requests(req: Request, next: Next) -> Response {
    let (parts, body) = req.into_parts();
    let body = match axum::body::to_bytes(body, body_limit(parts.uri.path())).await {
        Ok(b) => b,
        Err(_) => return (StatusCode::PAYLOAD_TOO_LARGE, "request body too large or unreadable").into_response(),
    };
    let deadline = tokio::time::Instant::now() + TRANSACTION_DEADLINE;
    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        let req = Request::from_parts(parts.clone(), Body::from(body.clone()));
        let committed = Arc::new(AtomicBool::new(false));
        let response = crate::limits::with_committed(committed.clone(), next.clone().run(req)).await;
        if response.extensions().get::<Retryable>().is_none() || committed.load(Ordering::Acquire) {
            return response;
        }
        let cap = 5u64 << attempt.min(6);
        let jitter = u64::from(u16::from_le_bytes(veil_core::crypto::random_bytes::<2>()));
        let wake = tokio::time::Instant::now() + Duration::from_millis(cap / 2 + jitter % cap);
        if wake >= deadline {
            return Error::busy().into_response();
        }
        tokio::time::sleep_until(wake).await;
    }
}
