//! Metadata in PostgreSQL (development and CI) or YugabyteDB (production),
//! with portable SQL only (`docs/HUB.md` §2.1).
//!
//! * Every read-write transaction is SERIALIZABLE and goes through
//!   [`serializable`], which runs it again when it loses a race.
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
    Ok(PgPoolOptions::new()
        .max_connections(max)
        .acquire_timeout(Duration::from_secs(30))
        .connect(url)
        .await?)
}

/// Apply every migration not applied yet.
pub async fn migrate(pool: &PgPool) -> anyhow::Result<()> {
    sqlx::raw_sql(
        "CREATE TABLE IF NOT EXISTS schema_migrations (version BIGINT PRIMARY KEY, name TEXT NOT NULL, applied_at BIGINT NOT NULL)",
    )
    .execute(pool)
    .await?;
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
                // Another server applied it at the same time: look again.
                Err(e) if attempt < 10 => {
                    eprintln!("veil-server: migration {version} retrying: {e:?}");
                    tokio::time::sleep(Duration::from_millis(100 * attempt)).await;
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

/// Run `f` in a SERIALIZABLE transaction, again (with backoff) while it
/// loses serialisation races, up to a bound. `f` may run several times, so
/// it must not have effects outside the transaction.
pub async fn serializable<T, F>(pool: &PgPool, mut f: F) -> Result<T>
where
    F: for<'t> FnMut(&'t mut PgConnection) -> TxFuture<'t, T>,
{
    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        let mut tx = pool.begin().await?;
        let r = async {
            sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE").execute(&mut *tx).await?;
            f(&mut tx).await
        }
        .await;
        let r = match r {
            Ok(v) => tx.commit().await.map(|_| v).map_err(Error::from),
            Err(e) => {
                let _ = tx.rollback().await;
                Err(e)
            }
        };
        match r {
            Err(e) if e.is_retryable() && attempt < 30 => {
                let jitter = u64::from(veil_core::crypto::random_bytes::<1>()[0]);
                tokio::time::sleep(Duration::from_millis(u64::from(attempt.min(10)) * 5 + jitter % 20)).await;
            }
            r => return r,
        }
    }
}
