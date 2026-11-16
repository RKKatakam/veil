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
    let table: Option<String> = sqlx::query_scalar("SELECT to_regclass('schema_migrations')::text").fetch_one(pool).await?;
    if table.is_none() {
        return Ok(false);
    }
    let applied: Vec<i64> = sqlx::query_scalar("SELECT version FROM schema_migrations").fetch_all(pool).await?;
    Ok(MIGRATIONS.iter().all(|(v, _, _)| applied.contains(v)))
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
    if schema_current(pool).await? {
        return Ok(());
    }
    let mut c = pool.acquire().await?;
    let deadline = tokio::time::Instant::now() + MIGRATION_DEADLINE;
    // Polled, not a blocking `pg_advisory_lock`: every statement has a
    // timeout, and the wait must have a deadline.
    loop {
        let got: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)").bind(MIGRATION_LOCK).fetch_one(&mut *c).await?;
        if got {
            break;
        }
        anyhow::ensure!(tokio::time::Instant::now() < deadline, "another server's migrations did not finish within {MIGRATION_DEADLINE:?}");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let r = migrate_locked(&mut c, deadline).await;
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
async fn migrate_locked(c: &mut PgConnection, deadline: tokio::time::Instant) -> anyhow::Result<()> {
    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        match migrate_once(&mut *c, deadline).await {
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

async fn migrate_once(c: &mut PgConnection, deadline: tokio::time::Instant) -> Result<()> {
    let table: Option<String> = sqlx::query_scalar("SELECT to_regclass('schema_migrations')::text").fetch_one(&mut *c).await?;
    if table.is_none() {
        sqlx::raw_sql("CREATE TABLE IF NOT EXISTS schema_migrations (version BIGINT PRIMARY KEY, name TEXT NOT NULL, applied_at BIGINT NOT NULL)")
            .execute(&mut *c)
            .await?;
    }
    let applied: Vec<i64> = sqlx::query_scalar("SELECT version FROM schema_migrations").fetch_all(&mut *c).await?;
    let mut yugabyte = None;
    for &(version, name, sql) in MIGRATIONS {
        if applied.contains(&version) {
            continue;
        }
        eprintln!("veil-server: applying migration {version} ({name})");
        let parts = migration_parts(sql).map_err(|e| Error::Other(anyhow::anyhow!("migration {version} ({name}): {e}")))?;
        let record = "INSERT INTO schema_migrations (version, name, applied_at) VALUES ($1, $2, $3)";
        if parts.online.is_empty() {
            // Each migration in its own transaction. Migration files are
            // idempotent (`IF NOT EXISTS`): YugabyteDB applies DDL in a
            // transaction block statement by statement unless transactional
            // DDL is enabled, so a migration interrupted half-way is applied
            // again from the start.
            let mut tx = sqlx::Connection::begin(&mut *c).await?;
            sqlx::raw_sql(sql).execute(&mut *tx).await?;
            sqlx::query(record).bind(version).bind(name).bind(veil_core::now_millis()).execute(&mut *tx).await?;
            tx.commit().await?;
            continue;
        }
        // The statements before the online section in one transaction, not
        // recorded; then the online index steps one by one; then the
        // record. A migration that fails anywhere is not recorded and is
        // applied again from the start (both parts are idempotent).
        if has_statements(parts.transactional) {
            let mut tx = sqlx::Connection::begin(&mut *c).await?;
            sqlx::raw_sql(parts.transactional).execute(&mut *tx).await?;
            tx.commit().await?;
        }
        let yb = match yugabyte {
            Some(yb) => yb,
            None => {
                let version: String = sqlx::query_scalar("SELECT version()").fetch_one(&mut *c).await?;
                *yugabyte.insert(is_yugabyte(&version))
            }
        };
        for step in &parts.online {
            online_index_step(&mut *c, yb, step, deadline).await?;
        }
        sqlx::query(record).bind(version).bind(name).bind(veil_core::now_millis()).execute(&mut *c).await?;
    }
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
/// * An index a failed build left invalid (`pg_index.indisvalid` false:
///   `IF NOT EXISTS` would keep it, and the database would never use it,
///   or a unique one would refuse rows while not serving reads) is dropped
///   before the build; after it the index must be valid, or the migration
///   fails and is not recorded.
/// * An index step runs under statement and lock timeouts of what is left
///   of the migrations' deadline (at least [`STATEMENT_TIMEOUT`]), not the
///   pool's: a large table's build takes longer than 15 s, and the
///   concurrent build waits for the transactions already running.
///
/// An index on a table created by the same migration needs none of this
/// (no server writes a table it does not know): it stays in the transaction.
pub const ONLINE_INDEXES: &str = "-- veil: online indexes";

/// A migration's statements: those applied in one transaction, then its
/// [`ONLINE_INDEXES`] steps.
#[derive(Debug)]
pub struct MigrationParts<'a> {
    pub transactional: &'a str,
    pub online: Vec<IndexStep>,
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
    let at = sql.match_indices(ONLINE_INDEXES).map(|(i, _)| i).find(|&i| i == 0 || sql.as_bytes()[i - 1] == b'\n');
    let Some(at) = at else {
        return Ok(MigrationParts { transactional: sql, online: Vec::new() });
    };
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
    Ok(MigrationParts { transactional: &sql[..at], online })
}

/// Whether `sql` holds anything but blank lines and `--` comments.
fn has_statements(sql: &str) -> bool {
    sql.lines().any(|l| {
        let l = l.trim();
        !l.is_empty() && !l.starts_with("--")
    })
}

/// Whether index `name` exists, and if so whether it is valid: `None`
/// when no relation has the name, `Some(None)` when one does that is not
/// an index.
async fn index_valid(c: &mut PgConnection, name: &str) -> Result<Option<Option<bool>>> {
    let row: Option<(Option<bool>,)> = sqlx::query_as(
        "SELECT (SELECT i.indisvalid FROM pg_index i WHERE i.indexrelid = r.oid) FROM (SELECT to_regclass($1) AS oid) r WHERE r.oid IS NOT NULL",
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

/// Apply one [`ONLINE_INDEXES`] step, outside any transaction, under
/// statement and lock timeouts of what is left of the migrations' deadline
/// (at least the pool's own statement timeout), then the connection's own
/// again (`migrate` resets them too, or closes the connection).
async fn online_index_step(c: &mut PgConnection, yugabyte: bool, step: &IndexStep, deadline: tokio::time::Instant) -> Result<()> {
    let left = deadline.saturating_duration_since(tokio::time::Instant::now()).max(STATEMENT_TIMEOUT);
    let ms = left.as_millis();
    sqlx::raw_sql(&format!("SET statement_timeout = {ms}; SET lock_timeout = {ms}")).execute(&mut *c).await?;
    let r = online_index_step_now(&mut *c, yugabyte, step).await;
    let reset = sqlx::raw_sql("RESET statement_timeout; RESET lock_timeout").execute(&mut *c).await;
    r?;
    reset?;
    Ok(())
}

async fn online_index_step_now(c: &mut PgConnection, yugabyte: bool, step: &IndexStep) -> Result<()> {
    let (name, sql) = match step {
        IndexStep::Drop { name } => return drop_index(&mut *c, yugabyte, name).await,
        IndexStep::Create { name, sql } => (name, sql),
    };
    if index_valid(&mut *c, name).await? == Some(Some(false)) {
        eprintln!("veil-server: index {name} was left invalid by a build that did not finish: dropping it to build it again");
        drop_index(&mut *c, yugabyte, name).await?;
    }
    if let Err(e) = sqlx::raw_sql(sql).execute(&mut *c).await {
        // A failed build leaves its index invalid: not used, but written
        // (and a unique one refusing rows). Dropped now when it can be, or
        // before the build is tried again.
        if let Ok(Some(Some(false))) = index_valid(&mut *c, name).await {
            let _ = drop_index(&mut *c, yugabyte, name).await;
        }
        return Err(e.into());
    }
    match index_valid(&mut *c, name).await? {
        Some(Some(true)) => Ok(()),
        Some(Some(false)) => Err(Error::Other(anyhow::anyhow!("index {name} is not valid after its build"))),
        Some(None) => Err(Error::Other(anyhow::anyhow!("{name} is not an index, so the index of that name was not built"))),
        None => Err(Error::Other(anyhow::anyhow!("index {name} does not exist after its build"))),
    }
}

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
