//! The review gate of a project (BUG-1886, BUG-2061, BUG-2110, BUG-2111).
//!
//! Every landing meets the review rules, holds and approvals in force when
//! it commits. The gate is a per-project transaction-scoped advisory lock:
//! a landing batch's transaction takes it **shared** before it reads again
//! anything the review rules come from, and every write that can make a
//! change not ready takes it **exclusively** (`close_review_gate`). Either
//! the write commits before the batch reads (the batch sees it), or it
//! waits until the batch has committed. That is all the correctness rests
//! on, on PostgreSQL and on YugabyteDB alike.
//!
//! A writer is never starved by a stream of batches, though YugabyteDB
//! grants a later shared request past a waiting exclusive one (BUG-2110):
//! before it asks for the gate, a writer **announces** itself in
//! `review_writers`, a row committed on its own (migration 43), and a
//! batch asks for the gate only when no writer is announced in the same
//! statement's snapshot. A batch that finds one rolls back, waits outside
//! any transaction until the writers it found are gone
//! (`wait_review_writers`), and runs again without looking at writers
//! announced later: those wait for it. So once a writer's row is
//! committed, only the batches that looked before can still ask for the
//! gate, each once: a writer waits at most for the batches already
//! committing; a batch waits at most for the writers announced before it
//! looked. Neither relies on how the database queues lock requests.
//!
//! A writer's row goes when its transaction ends (`db::transaction` deletes
//! it after the commit or the rollback). A row whose writer went away
//! without (a server stopped) is found by the advisory lock its transaction
//! held (`writer_key`): one announced more than `STALE_MS` ago whose lock
//! nobody holds is removed by the batch waiting for it.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use sqlx::{PgConnection, PgPool};

use crate::error::Result;

/// The gate's advisory-lock key is `REVIEW_GATE_BASE ^ project`.
const REVIEW_GATE_BASE: i64 = 0x7665_696c_7276_6774; // "veilrvgt"
/// A writer's own advisory-lock key, held by its transaction: `-id`, below
/// zero, so never another lock's key (each other one is a positive base
/// XOR a project; BUG-2130: `0x7665_696c_7277_7472 ^ id` was the review
/// gate of project `id ^ 70406`).
fn writer_key(id: i64) -> i64 {
    -id
}
/// A writer's row older than this, whose lock nobody holds, is of a writer
/// that went away.
const STALE_MS: i64 = 2_000;
/// How long a batch waits for the writers it found before it asks for the
/// gate anyway (the gate keeps every landing right; only the writer's
/// precedence is given up): a lease's half, as for its objects.
const WAIT_AT_MOST: Duration = Duration::from_secs(1);
/// How long a writer waits for a connection to announce itself on.
const ANNOUNCE_WAIT: Duration = Duration::from_millis(100);

/// The writers' rows of one attempt of a `db::transaction`, deleted when it
/// ends.
#[derive(Clone)]
pub(crate) struct Writers {
    db: PgPool,
    /// `(project, id)`.
    ids: Arc<Mutex<Vec<(i64, i64)>>>,
}

tokio::task_local! {
    static WRITERS: Writers;
}

impl Writers {
    fn take(&self) -> Vec<i64> {
        std::mem::take(&mut *self.ids.lock().unwrap_or_else(|e| e.into_inner())).into_iter().map(|(_, id)| id).collect()
    }
}

/// The rows of an attempt dropped before it ended (its request's client
/// went away, the deadline, a panic): deleted on their own (BUG-2132).
struct Leftover(Writers);

impl Drop for Leftover {
    fn drop(&mut self) {
        let ids = self.0.take();
        if let (false, Ok(rt)) = (ids.is_empty(), tokio::runtime::Handle::try_current()) {
            let db = self.0.db.clone();
            rt.spawn(async move {
                let _ = sqlx::query("DELETE FROM review_writers WHERE id = ANY($1)").bind(&ids).execute(&db).await;
            });
        }
    }
}

/// Run one attempt of a transaction (`fut`), then delete the rows of the
/// writers it announced, whether it committed or not.
pub(crate) async fn scoped<F: std::future::Future>(db: &PgPool, fut: F) -> F::Output {
    let w = Leftover(Writers {
        db: db.clone(),
        ids: Arc::default(),
    });
    let r = WRITERS.scope(w.0.clone(), fut).await;
    let ids = w.0.take();
    if !ids.is_empty() {
        // Should this fail, a batch waiting for them removes them once
        // stale (their transaction is over, so their locks are free).
        let _ = sqlx::query("DELETE FROM review_writers WHERE id = ANY($1)").bind(&ids).execute(db).await;
    }
    r
}

/// Take the review gate of `project` exclusively, for this transaction:
/// announced first (a row committed on its own, on another connection of
/// `db::transaction`'s pool, if one is free within `ANNOUNCE_WAIT`), so
/// that no batch asks for the gate after it.
/// Inside a `db::transaction` only (every writer is): outside one the gate
/// is taken without the announcement.
pub(crate) async fn close_review_gate(c: &mut PgConnection, project: i64) -> Result<()> {
    let gate = REVIEW_GATE_BASE ^ project;
    let Ok(scope) = WRITERS.try_with(Clone::clone) else {
        debug_assert!(false, "the review gate taken outside a db::transaction");
        sqlx::query("SELECT pg_advisory_xact_lock($1)").bind(gate).execute(&mut *c).await?;
        return Ok(());
    };
    let known = scope.ids.lock().unwrap().iter().find(|(p, _)| *p == project).map(|(_, id)| *id);
    let id = match known {
        Some(id) => id,
        None => {
            // Its transaction holds one of the pool's connections: writers
            // filling the pool would each wait for another (BUG-2131). One
            // that gets none soon asks for the gate unannounced (the gate
            // keeps every landing right; only its precedence is given up).
            let Ok(conn) = tokio::time::timeout(ANNOUNCE_WAIT, scope.db.acquire()).await else {
                sqlx::query("SELECT pg_advisory_xact_lock($1)").bind(gate).execute(&mut *c).await?;
                return Ok(());
            };
            let id: i64 = sqlx::query_scalar(
                "INSERT INTO review_writers (project_id, since_ms) VALUES ($1, (extract(epoch FROM clock_timestamp()) * 1000)::BIGINT) RETURNING id",
            )
            .bind(project)
            .fetch_one(&mut *conn?)
            .await?;
            scope.ids.lock().unwrap().push((project, id));
            id
        }
    };
    sqlx::query("SELECT pg_advisory_xact_lock($1), pg_advisory_xact_lock($2)")
        .bind(writer_key(id))
        .bind(gate)
        .execute(&mut *c)
        .await?;
    Ok(())
}

/// Take the review gate of `project` shared, for this transaction, unless
/// a writer is announced: then the gate is not taken and the answer is
/// those writers' ids, to wait for ([`wait_review_writers`]) before the
/// transaction runs again with `writers: false` (writers announced since
/// wait for it). Both in one statement: a writer's row committed before it
/// is seen.
pub async fn share_review_gate(c: &mut PgConnection, project: i64, writers: bool) -> Result<Vec<i64>> {
    let gate = REVIEW_GATE_BASE ^ project;
    if !writers {
        sqlx::query("SELECT pg_advisory_xact_lock_shared($1)").bind(gate).execute(&mut *c).await?;
        return Ok(Vec::new());
    }
    let (ids, _): (Vec<i64>, Option<String>) = sqlx::query_as(
        "WITH w AS (SELECT COALESCE(array_agg(id), '{}') AS ids FROM review_writers WHERE project_id = $2) \
         SELECT w.ids, CASE WHEN cardinality(w.ids) = 0 THEN pg_advisory_xact_lock_shared($1)::text END FROM w",
    )
    .bind(gate)
    .bind(project)
    .fetch_one(&mut *c)
    .await?;
    Ok(ids)
}

/// Wait, outside any transaction, until the writers `ids` of `project` are
/// gone (at most `WAIT_AT_MOST`), removing those that went away.
pub async fn wait_review_writers(db: &PgPool, project: i64, ids: &[i64]) -> Result<()> {
    let until = tokio::time::Instant::now() + WAIT_AT_MOST;
    let mut pause = Duration::from_millis(1);
    loop {
        let left: Vec<(i64, bool)> = sqlx::query_as(
            "SELECT id, since_ms < (extract(epoch FROM clock_timestamp()) * 1000)::BIGINT - $3 FROM review_writers \
             WHERE project_id = $1 AND id = ANY($2)",
        )
        .bind(project)
        .bind(ids)
        .bind(STALE_MS)
        .fetch_all(db)
        .await?;
        if left.is_empty() {
            return Ok(());
        }
        for (id, _) in left.iter().filter(|(_, stale)| *stale) {
            // Its transaction is over if its lock is free.
            let mut tx = db.begin().await?;
            let free: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1)").bind(writer_key(*id)).fetch_one(&mut *tx).await?;
            if free {
                sqlx::query("DELETE FROM review_writers WHERE id = $1").bind(id).execute(&mut *tx).await?;
            }
            tx.commit().await?;
        }
        if tokio::time::Instant::now() >= until {
            return Ok(());
        }
        tokio::time::sleep(pause).await;
        pause = (pause * 2).min(Duration::from_millis(8));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BUG-2130: no writer's key is the review gate of a project (nor any
    /// other lock's key: each is a positive base XOR a project).
    #[test]
    fn a_writers_key_is_no_projects_review_gate() {
        for id in (1..=1_000_000).chain([1 << 31, 1 << 40, i64::MAX]) {
            let key = writer_key(id);
            let project = key ^ REVIEW_GATE_BASE;
            assert!(project < 0, "writer {id}'s key is project {project}'s review gate");
            assert!(key < 0, "writer {id}'s key {key} may be another lock's");
        }
    }
}
