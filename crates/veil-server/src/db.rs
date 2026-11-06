//! Metadata in PostgreSQL (development and CI) or YugabyteDB (production),
//! with portable SQL only (`docs/HUB.md` §2.1).
//!
//! * Read-check-write transactions are SERIALIZABLE ([`serializable`]);
//!   branch moves, which are one-row compare-and-swaps, READ COMMITTED.
//!   Both go through [`transaction`], which runs them again when they lose
//!   a race, within a deadline.
//! * Every connection sets `statement_timeout` and `lock_timeout`: no
//!   statement waits forever, on PostgreSQL or YugabyteDB.
//! * Migrations ([`migrate`]) run in order, each in its own transaction,
//!   recorded in `schema_migrations`; two servers starting at once race on
//!   that table's primary key and the loser re-checks. Migration files are
//!   idempotent (`IF NOT EXISTS`) because YugabyteDB applies DDL in a
//!   transaction block statement by statement unless transactional DDL is
//!   enabled.

use std::{future::Future, pin::Pin, time::Duration};

use sqlx::{postgres::PgPoolOptions, PgConnection, PgPool};

use crate::error::{Error, Result};

/// The migrations, in order. Never edit one that shipped: add a new one.
pub const MIGRATIONS: &[(i64, &str, &str)] = &[(1, "initial", include_str!("../migrations/0001_initial.sql"))];

pub async fn connect(url: &str, max: u32) -> anyhow::Result<PgPool> {
    let opts: sqlx::postgres::PgConnectOptions = url.parse()?;
    let opts = opts.options([
        ("statement_timeout", format!("{}", STATEMENT_TIMEOUT.as_millis())),
        ("lock_timeout", format!("{}", LOCK_TIMEOUT.as_millis())),
    ]);
    Ok(PgPoolOptions::new()
        .max_connections(max)
        .acquire_timeout(Duration::from_secs(30))
        .connect_with(opts)
        .await?)
}

/// Apply every migration not applied yet.
pub async fn migrate(pool: &PgPool) -> anyhow::Result<()> {
    // Servers starting together race on creating the table itself
    // (IF NOT EXISTS is not atomic on either database): try again.
    let mut attempt = 0;
    loop {
        attempt += 1;
        let r = sqlx::raw_sql(
            "CREATE TABLE IF NOT EXISTS schema_migrations (version BIGINT PRIMARY KEY, name TEXT NOT NULL, applied_at BIGINT NOT NULL)",
        )
        .execute(pool)
        .await;
        match r {
            Ok(_) => break,
            Err(e) if attempt < 20 => {
                eprintln!("veil-server: creating schema_migrations, retrying: {e}");
                tokio::time::sleep(Duration::from_millis(100 * attempt)).await;
            }
            Err(e) => return Err(e.into()),
        }
    }
    for &(version, name, sql) in MIGRATIONS {
        let mut attempt = 0;
        loop {
            attempt += 1;
            let r: Result<()> = async {
                let mut tx = pool.begin().await?;
                let done: Option<i64> = sqlx::query_scalar("SELECT version FROM schema_migrations WHERE version = $1")
                    .bind(version)
                    .fetch_optional(&mut *tx)
                    .await?;
                if done.is_some() {
                    return Ok(());
                }
                sqlx::raw_sql(sql).execute(&mut *tx).await?;
                sqlx::query("INSERT INTO schema_migrations (version, name, applied_at) VALUES ($1, $2, $3)")
                    .bind(version)
                    .bind(name)
                    .bind(veil_core::now_millis())
                    .execute(&mut *tx)
                    .await?;
                tx.commit().await?;
                Ok(())
            }
            .await;
            match r {
                Ok(()) => break,
                // Another server applied it at the same time (YugabyteDB
                // reports the conflict, and cannot retry a multi-statement
                // script itself): back off and look again.
                Err(e) if attempt < 60 => {
                    if attempt % 10 == 1 {
                        eprintln!("veil-server: migration {version} retrying: {e:?}");
                    }
                    let jitter = u64::from(veil_core::crypto::random_bytes::<1>()[0]);
                    tokio::time::sleep(Duration::from_millis((50 * attempt).min(1000) + jitter * 4)).await;
                }
                Err(Error::Db(e)) => return Err(e.into()),
                Err(Error::Other(e)) => return Err(e),
                Err(e) => anyhow::bail!("{e:?}"),
            }
        }
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
    /// For read-check-write sequences (group changes, sign-up, project
    /// creation).
    Serializable,
    /// For compare-and-swaps that are atomic on their own (a branch move is
    /// one conditional `UPDATE` of one row). SERIALIZABLE would add read
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
                Ok(v) => tx.commit().await.map(|_| v).map_err(Error::from),
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
