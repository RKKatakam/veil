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
//!   `schema_migrations`. A server that finds the schema current runs no
//!   DDL (BUG-838).
//! * Every request runs again, within [`TRANSACTION_DEADLINE`], when it
//!   fails on a retryable database error (a lost race, a restarted read, a
//!   catalog changed by a migration) before anything it did was committed
//!   ([`retry_requests`]).

use std::{cell::Cell, future::Future, pin::Pin, time::Duration};

use axum::{
    body::Body,
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use sqlx::{postgres::PgPoolOptions, PgConnection, PgPool};

use crate::error::{Error, Result};

/// The migrations, in order. Never edit one that shipped: add a new one.
pub const MIGRATIONS: &[(i64, &str, &str)] = &[
    (1, "initial", include_str!("../migrations/0001_initial.sql")),
    (2, "device_vouches", include_str!("../migrations/0002_device_vouches.sql")),
    (3, "invites_and_key_sharing", include_str!("../migrations/0003_invites_and_key_sharing.sql")),
    (4, "derived", include_str!("../migrations/0004_derived.sql")),
    (5, "change_refs", include_str!("../migrations/0005_change_refs.sql")),
    (6, "access_epochs", include_str!("../migrations/0006_access_epochs.sql")),
    (9, "secret_shares", include_str!("../migrations/0009_secret_shares.sql")),
    (10, "view_graph", include_str!("../migrations/0010_view_graph.sql")),
    (17, "prs", include_str!("../migrations/0017_prs.sql")),
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

fn options(url: &str, max: u32) -> anyhow::Result<(PgPoolOptions, sqlx::postgres::PgConnectOptions)> {
    let opts: sqlx::postgres::PgConnectOptions = url.parse()?;
    let opts = opts.options([
        ("statement_timeout", format!("{}", STATEMENT_TIMEOUT.as_millis())),
        ("lock_timeout", format!("{}", LOCK_TIMEOUT.as_millis())),
    ]);
    Ok((PgPoolOptions::new().max_connections(max).acquire_timeout(Duration::from_secs(30)), opts))
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
    // The lock is the session's: release it, or close the connection so
    // that the lock never goes back into the pool.
    let unlocked = sqlx::query_scalar::<_, bool>("SELECT pg_advisory_unlock($1)").bind(MIGRATION_LOCK).fetch_one(&mut *c).await;
    if !matches!(unlocked, Ok(true)) {
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
        match migrate_once(&mut *c).await {
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

async fn migrate_once(c: &mut PgConnection) -> Result<()> {
    let table: Option<String> = sqlx::query_scalar("SELECT to_regclass('schema_migrations')::text").fetch_one(&mut *c).await?;
    if table.is_none() {
        sqlx::raw_sql("CREATE TABLE IF NOT EXISTS schema_migrations (version BIGINT PRIMARY KEY, name TEXT NOT NULL, applied_at BIGINT NOT NULL)")
            .execute(&mut *c)
            .await?;
    }
    let applied: Vec<i64> = sqlx::query_scalar("SELECT version FROM schema_migrations").fetch_all(&mut *c).await?;
    for &(version, name, sql) in MIGRATIONS {
        if applied.contains(&version) {
            continue;
        }
        eprintln!("veil-server: applying migration {version} ({name})");
        // Each migration in its own transaction. Migration files are
        // idempotent (`IF NOT EXISTS`): YugabyteDB applies DDL in a
        // transaction block statement by statement unless transactional
        // DDL is enabled, so a migration interrupted half-way is applied
        // again from the start.
        let mut tx = sqlx::Connection::begin(&mut *c).await?;
        sqlx::raw_sql(sql).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO schema_migrations (version, name, applied_at) VALUES ($1, $2, $3)")
            .bind(version)
            .bind(name)
            .bind(veil_core::now_millis())
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
    }
    Ok(())
}

pub type TxFuture<'t, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 't>>;

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
                    let _ = COMMITTED.try_with(|c| c.set(true));
                    // A commit that timed out may have committed: neither is
                    // `f` run again (BUG-890).
                    match r {
                        Err(Error::Db(e)) if e.as_database_error().is_some_and(|d| crate::error::is_rpc_timeout(d.message())) => {
                            Err(Error::Other(anyhow::Error::new(e).context("the commit timed out; its outcome is unknown")))
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
        let r = match tokio::time::timeout_at(deadline, once).await {
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

tokio::task_local! {
    /// Set when a [`transaction`] of the current request committed (or
    /// tried to): from then on the request is not run again.
    static COMMITTED: Cell<bool>;
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
        let (committed, response) = COMMITTED
            .scope(Cell::new(false), async {
                let r = next.clone().run(req).await;
                (COMMITTED.with(|c| c.get()), r)
            })
            .await;
        if response.extensions().get::<Retryable>().is_none() || committed {
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
