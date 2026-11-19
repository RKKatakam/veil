//! Staged upload container sweeping (`docs/HUB.md` §13.37).
//!
//! Veil v1 storage is **append-only** with **no garbage collection** of
//! unreachable history and **no online pack merging**:
//!
//! * New objects are written under their own keys (`p/<project>/ab/cdef…`,
//!   [`crate::store::ObjectLayout::Objects`]). Existing `LISTED` packs written
//!   by older servers remain readable indefinitely.
//! * Uploads (`POST …/objects`) still land in temporary staged upload
//!   containers (`packs` rows with `state = STAGED`) so nothing an upload
//!   carried is visible before its push or API commit passes every check, and
//!   any unread plain-text secret beside a landing or refused push is
//!   discarded immediately.
//! * This module sweeps **only** uncommitted staged upload containers past
//!   [`DEFAULT_STAGED_GRACE_MS`] (abandoned uploads, or legacy interrupted
//!   `person_id IS NULL` staged packs) and `DISCARDED` upload containers past
//!   [`DEFAULT_PACK_GRACE_MS`] (containers whose immediate storage delete
//!   failed or was interrupted by a crash). It never touches `LISTED` packs or
//!   loose project objects.

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
};

use crate::{
    error::{Error, Result},
    pack::{self, DISCARDED, LISTED, STAGED},
    Hub,
};

/// Advisory lock namespace for per-project upload-container sweeps
/// (`"veilpkgc"` ^ `project_id`).
const LOCK_BASE: i64 = 0x7665_696c_706b_6763;

/// Storage deletes issued at once by [`sweep_discarded`].
const AT_ONCE: usize = 32;

/// Maximum `DISCARDED` upload containers swept in one pass.
const MAX_SWEEP_PER_PASS: usize = 256;

/// Default grace period before a `DISCARDED` container's storage object and
/// row are swept (15 minutes).
pub const DEFAULT_PACK_GRACE_MS: i64 = 900_000;

/// Default grace period before an uncommitted `STAGED` upload container is
/// considered abandoned and discarded (1 hour).
pub const DEFAULT_STAGED_GRACE_MS: i64 = 3_600_000;

/// Longest wait between sweeper checks while a project still has unlisted
/// containers pending their grace window, or after a skipped pass.
pub const SWEEP_RECHECK: std::time::Duration = std::time::Duration::from_secs(10);

/// How often [`sweep_scan`] looks for projects with staged/discarded
/// containers to sweep, starting once at server start-up.
pub const SWEEP_SCAN: std::time::Duration = std::time::Duration::from_secs(600);

/// Coalescing delay before background deletion of consumed `packs` rows whose
/// storage containers were already deleted synchronously (`P5-B`).
pub const PURGE_FLUSH_DELAY: std::time::Duration = std::time::Duration::from_millis(250);

/// Flush a project's queued consumed-pack row deletions early once this many
/// rows accumulate.
const PURGE_BATCH_SIZE: usize = 256;

/// Upper bound on queued consumed-pack row names in memory per server. Excess
/// rows remain `DISCARDED (objects = -1)` in `packs` and are swept later by
/// [`sweep_discarded`].
const MAX_QUEUED_PURGES: usize = 16_384;

/// Async test hook (used by `embargo::State::before_review`).
#[derive(Clone)]
pub struct SwitchHook(
    pub Arc<dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> + Send + Sync>,
);

impl std::fmt::Debug for SwitchHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SwitchHook(..)")
    }
}

/// Options controlling one staged/discarded container sweep pass on a project.
#[derive(Clone, Copy, Debug)]
pub struct SweepOptions {
    /// Grace window in milliseconds before an abandoned `STAGED` upload
    /// container is discarded.
    pub staged_grace_ms: i64,
    /// Grace window in milliseconds before a `DISCARDED` container's storage
    /// object and row are deleted.
    pub pack_grace_ms: i64,
    /// Simulated clock offset in milliseconds (for tests).
    pub now_offset_ms: i64,
}

impl Default for SweepOptions {
    fn default() -> Self {
        SweepOptions {
            staged_grace_ms: DEFAULT_STAGED_GRACE_MS,
            pack_grace_ms: DEFAULT_PACK_GRACE_MS,
            now_offset_ms: 0,
        }
    }
}

impl SweepOptions {
    fn now_ms(self) -> i64 {
        veil_core::now_millis().saturating_add(self.now_offset_ms)
    }
}

/// Statistics returned by [`sweep_project`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SweepReport {
    /// Another server held the project's sweep advisory lock.
    pub skipped: bool,
    /// Number of `DISCARDED` containers whose storage files and rows were swept.
    pub discarded_packs_swept: usize,
    /// Number of stale `STAGED` upload containers discarded and swept.
    pub staged_packs_swept: usize,
}

/// Pending consumed `packs` row names whose storage objects were already
/// deleted, coalesced per project for batched `DELETE FROM packs`.
#[derive(Default)]
struct PurgedQueue {
    by_project: HashMap<i64, Vec<String>>,
    total: usize,
    running: bool,
}

/// Per-server background upload-container sweeper state on [`Hub`].
#[derive(Default)]
pub struct State {
    /// Projects with a sweeper task on this server ([`schedule_sweep`]),
    /// each with whether it was asked again since it last looked.
    sweeping: Mutex<HashMap<i64, bool>>,
    /// Consumed `packs` rows awaiting background batched `DELETE`.
    purged: Mutex<PurgedQueue>,
    /// Wakes the purged-row flusher early when a project hits [`PURGE_BATCH_SIZE`].
    purged_wake: tokio::sync::Notify,
    /// Sweeper tasks currently running on this server ([`stop`]).
    at_work: std::sync::atomic::AtomicUsize,
    /// Notified when `at_work` reaches zero.
    idle: tokio::sync::Notify,
    /// Sweep passes completed (for tests).
    pub runs: AtomicU64,
    /// Sweeper passes that discarded or deleted containers (for tests).
    pub sweeps: AtomicU64,
}

struct AtWork(Arc<Hub>);

impl AtWork {
    fn new(hub: &Arc<Hub>) -> Self {
        hub.pack_gc.at_work.fetch_add(1, Ordering::SeqCst);
        AtWork(hub.clone())
    }
}

impl Drop for AtWork {
    fn drop(&mut self) {
        if self.0.pack_gc.at_work.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.0.pack_gc.idle.notify_waiters();
        }
    }
}

/// How long a clean stop waits for background upload-container sweepers to exit.
const STOP_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// Wait for every active background upload-container sweeper task on `hub` to
/// exit after `landing::stop` has flagged shutdown (BUG-2635).
pub async fn stop(hub: &Arc<Hub>) {
    let until = tokio::time::Instant::now() + STOP_WAIT;
    loop {
        let notified = hub.pack_gc.idle.notified();
        if hub.pack_gc.at_work.load(Ordering::SeqCst) == 0 {
            return;
        }
        if tokio::time::timeout_at(until, notified).await.is_err() {
            let left = hub.pack_gc.at_work.load(Ordering::SeqCst);
            if left > 0 {
                eprintln!("veil-server: {left} upload-container sweepers still at work at the stop");
            }
            return;
        }
    }
}

/// Queue consumed `packs` row names (already `DISCARDED` with `objects < 0`
/// and deleted from object storage) for background batched `DELETE FROM packs`.
///
/// Moving the `DELETE` out of the foreground push removes one DB commit per
/// push while preserving immediate storage deletion of staged containers; if
/// the server crashes before the batch runs, [`sweep_project`] removes the
/// `DISCARDED` rows after [`DEFAULT_PACK_GRACE_MS`].
pub fn enqueue_deleted_rows(hub: &Arc<Hub>, project: i64, names: Vec<String>) {
    if names.is_empty() {
        return;
    }
    let (spawn, hit_batch) = {
        let mut q = hub.pack_gc.purged.lock().unwrap();
        let room = MAX_QUEUED_PURGES.saturating_sub(q.total);
        if room > 0 {
            let take = names.len().min(room);
            let entry = q.by_project.entry(project).or_default();
            entry.extend(names.into_iter().take(take));
            q.total += take;
        }
        let hit_batch = q.by_project.get(&project).is_some_and(|v| v.len() >= PURGE_BATCH_SIZE);
        let spawn = if !q.running && !hub.landing.stopping() {
            q.running = true;
            true
        } else {
            false
        };
        (spawn, hit_batch)
    };
    if spawn {
        let hub = hub.clone();
        let at_work = AtWork::new(&hub);
        tokio::spawn(async move {
            let _at_work = at_work;
            loop {
                tokio::select! {
                    biased;
                    _ = hub.landing.wait_stop() => {
                        let _ = flush_purged(&hub).await;
                        hub.pack_gc.purged.lock().unwrap().running = false;
                        return;
                    }
                    _ = hub.pack_gc.purged_wake.notified() => {}
                    _ = tokio::time::sleep(PURGE_FLUSH_DELAY) => {}
                }
                if let Err(e) = flush_purged(&hub).await {
                    eprintln!("veil-server: flushing consumed pack rows: {e:?}");
                }
                let mut q = hub.pack_gc.purged.lock().unwrap();
                if q.by_project.is_empty() || hub.landing.stopping() {
                    q.running = false;
                    return;
                }
            }
        });
    } else if hit_batch {
        hub.pack_gc.purged_wake.notify_one();
    }
}

/// Delete all queued consumed `packs` rows (whose storage containers were
/// already deleted) in bounded per-project batches.
pub async fn flush_purged(hub: &Hub) -> Result<usize> {
    let pending = {
        let mut q = hub.pack_gc.purged.lock().unwrap();
        q.total = 0;
        std::mem::take(&mut q.by_project)
    };
    let mut deleted = 0usize;
    for (project, names) in pending {
        deleted += delete_purged_rows(hub, project, &names).await?;
    }
    Ok(deleted)
}

/// Delete queued consumed `packs` rows for a single project (used by
/// [`sweep_project`] before [`sweep_discarded`]).
async fn flush_purged_project(hub: &Hub, project: i64) -> Result<usize> {
    let names = {
        let mut q = hub.pack_gc.purged.lock().unwrap();
        match q.by_project.remove(&project) {
            Some(v) => {
                q.total = q.total.saturating_sub(v.len());
                v
            }
            None => return Ok(0),
        }
    };
    delete_purged_rows(hub, project, &names).await
}

async fn delete_purged_rows(hub: &Hub, project: i64, names: &[String]) -> Result<usize> {
    let mut deleted = 0usize;
    for chunk in names.chunks(PURGE_BATCH_SIZE) {
        let r = sqlx::query(
            "DELETE FROM packs WHERE project_id = $1 AND name = ANY($2) AND state = $3 AND objects < 0",
        )
        .bind(project)
        .bind(chunk)
        .bind(DISCARDED)
        .execute(&hub.db)
        .await?;
        let n = r.rows_affected() as usize;
        if n > 0 {
            hub.objects.pack_rows.fetch_add(1, Ordering::Relaxed);
            deleted += n;
        }
    }
    Ok(deleted)
}

/// Sweep `project`'s abandoned `STAGED` and `DISCARDED` upload containers as
/// each becomes due, until none is left. Non-blocking; at most one task per
/// project on this server.
pub fn schedule_sweep(hub: &Arc<Hub>, project: i64) {
    if hub.landing.stopping() {
        return;
    }
    {
        let mut sweeping = hub.pack_gc.sweeping.lock().unwrap();
        if let Some(again) = sweeping.get_mut(&project) {
            *again = true;
            return;
        }
        sweeping.insert(project, false);
    }
    let hub = hub.clone();
    let at_work = AtWork::new(&hub);
    tokio::spawn(async move {
        let _at_work = at_work;
        loop {
            if hub.landing.stopping() {
                hub.pack_gc.sweeping.lock().unwrap().remove(&project);
                return;
            }
            let wait = match sweep_due(&hub, project).await {
                Ok(None) => {
                    let mut sweeping = hub.pack_gc.sweeping.lock().unwrap();
                    let again = sweeping.entry(project).or_insert(false);
                    if !*again || hub.landing.stopping() {
                        sweeping.remove(&project);
                        return;
                    }
                    *again = false;
                    continue;
                }
                Ok(Some(due)) => {
                    let now = veil_core::now_millis();
                    if due > now {
                        std::time::Duration::from_millis((due - now) as u64).min(SWEEP_RECHECK)
                    } else if hub.landing.stopping() {
                        hub.pack_gc.sweeping.lock().unwrap().remove(&project);
                        return;
                    } else {
                        match sweep_project(&hub, project, SweepOptions::default()).await {
                            Ok(r) if !r.skipped && r.discarded_packs_swept + r.staged_packs_swept > 0 => {
                                hub.pack_gc.sweeps.fetch_add(1, Ordering::Relaxed);
                                std::time::Duration::ZERO
                            }
                            _ => SWEEP_RECHECK,
                        }
                    }
                }
                Err(_) => SWEEP_RECHECK,
            };
            tokio::select! {
                biased;
                _ = hub.landing.wait_stop() => {
                    hub.pack_gc.sweeping.lock().unwrap().remove(&project);
                    return;
                }
                _ = tokio::time::sleep(wait) => {}
            }
        }
    });
}

/// When `project` next has an unlisted container to sweep ([`schedule_sweep`]),
/// in milliseconds since the epoch; `None` if none remain.
async fn sweep_due(hub: &Hub, project: i64) -> Result<Option<i64>> {
    const _: () = assert!(LISTED == 1);
    let (discarded, jobs, upload): (Option<i64>, i64, Option<i64>) = sqlx::query_as(
        "SELECT min(discarded_at) FILTER (WHERE state = $2), count(*) FILTER (WHERE state = $3 AND person_id IS NULL), \
         min(created_at) FILTER (WHERE state = $3 AND person_id IS NOT NULL) FROM packs WHERE project_id = $1 AND state <> 1",
    )
    // `state <> 1` (LISTED) is written literally so the partial index
    // `packs_unlisted` (migration 40) serves it under a generic plan too.
    .bind(project)
    .bind(DISCARDED)
    .bind(STAGED)
    .fetch_one(&hub.db)
    .await?;
    let now = veil_core::now_millis();
    Ok([
        discarded.map(|t| t.saturating_add(DEFAULT_PACK_GRACE_MS)),
        (jobs > 0).then_some(now),
        upload.map(|t| t.saturating_add(DEFAULT_STAGED_GRACE_MS)),
    ]
    .into_iter()
    .flatten()
    .min())
}

/// Every [`SWEEP_SCAN`], starting at server start-up, start a sweeper
/// ([`schedule_sweep`]) on every project with abandoned staged uploads or
/// discarded containers to sweep.
pub async fn sweep_scan(hub: Arc<Hub>, mut stop: tokio::sync::watch::Receiver<bool>) {
    loop {
        if hub.landing.stopping() {
            return;
        }
        for project in projects_to_sweep(&hub).await.unwrap_or_default() {
            schedule_sweep(&hub, project);
        }
        tokio::select! {
            biased;
            _ = hub.landing.wait_stop() => return,
            _ = stop.changed() => return,
            _ = tokio::time::sleep(SWEEP_SCAN) => {}
        }
    }
}

/// Projects [`sweep_scan`] starts a sweeper on: those with a `DISCARDED`
/// container, a legacy `person_id IS NULL` staged pack, or a `STAGED` upload
/// container older than [`DEFAULT_STAGED_GRACE_MS`].
pub async fn projects_to_sweep(hub: &Hub) -> Result<Vec<i64>> {
    let cutoff = veil_core::now_millis().saturating_sub(DEFAULT_STAGED_GRACE_MS);
    const _: () = assert!(LISTED == 1);
    Ok(sqlx::query_scalar(
        "SELECT DISTINCT project_id FROM packs WHERE state <> 1 \
         AND (state = $1 OR (state = $2 AND (person_id IS NULL OR created_at <= $3)))",
    )
    .bind(DISCARDED)
    .bind(STAGED)
    .bind(cutoff)
    .fetch_all(&hub.db)
    .await?)
}

/// Run one bounded sweep of abandoned `STAGED` upload containers and
/// `DISCARDED` containers on `project`. Never touches `LISTED` packs or
/// project objects.
pub async fn sweep_project(hub: &Arc<Hub>, project: i64, opts: SweepOptions) -> Result<SweepReport> {
    if hub.landing.stopping() {
        return Ok(SweepReport {
            skipped: true,
            ..SweepReport::default()
        });
    }
    let hub = hub.clone();
    let at_work = AtWork::new(&hub);
    tokio::spawn(async move {
        let _at_work = at_work;
        tokio::select! {
            biased;
            _ = hub.landing.wait_stop() => {
                return Ok(SweepReport {
                    skipped: true,
                    ..SweepReport::default()
                });
            }
            _ = hub.limits.derive_turn() => {}
        }
        let permit = tokio::select! {
            biased;
            _ = hub.landing.wait_stop() => {
                return Ok(SweepReport {
                    skipped: true,
                    ..SweepReport::default()
                });
            }
            p = hub.derive.permit() => p?,
        };
        let mut lock_conn = tokio::select! {
            biased;
            _ = hub.landing.wait_stop() => {
                return Ok(SweepReport {
                    skipped: true,
                    ..SweepReport::default()
                });
            }
            c = hub.derive.db.acquire() => c?,
        };
        let lock_key = LOCK_BASE ^ project;
        let got: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
            .bind(lock_key)
            .fetch_one(&mut *lock_conn)
            .await?;
        if !got {
            return Ok(SweepReport {
                skipped: true,
                ..SweepReport::default()
            });
        }
        let res = if hub.landing.stopping() {
            Ok(SweepReport {
                skipped: true,
                ..SweepReport::default()
            })
        } else {
            let now_ms = opts.now_ms();
            let mut report = SweepReport::default();
            async {
                sweep_staged(&hub, project, now_ms, opts.staged_grace_ms, &mut report).await?;
                if !hub.landing.stopping() {
                    let flushed = flush_purged_project(&hub, project).await?;
                    report.discarded_packs_swept += flushed;
                }
                if !hub.landing.stopping() {
                    sweep_discarded(&hub, project, now_ms, opts.pack_grace_ms, MAX_SWEEP_PER_PASS, &mut report).await?;
                }
                Ok(report)
            }
            .await
        };
        let _ = sqlx::query("SELECT pg_advisory_unlock($1)")
            .bind(lock_key)
            .execute(&mut *lock_conn)
            .await;
        drop((lock_conn, permit));
        if res.as_ref().is_ok_and(|r| !r.skipped) {
            hub.pack_gc.runs.fetch_add(1, Ordering::Relaxed);
        }
        res
    })
    .await
    .map_err(|e| Error::Other(e.into()))?
}

/// Discard and delete any stale uncommitted `STAGED` upload containers older
/// than `staged_grace_ms` (and any legacy `person_id IS NULL` staged packs).
async fn sweep_staged(
    hub: &Arc<Hub>,
    project: i64,
    now_ms: i64,
    staged_grace_ms: i64,
    report: &mut SweepReport,
) -> Result<()> {
    let cutoff = now_ms.saturating_sub(staged_grace_ms.max(0));
    const _: () = assert!(STAGED == 0);
    let stale: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM packs WHERE project_id = $1 AND state = 0 AND (person_id IS NULL OR created_at <= $2)",
    )
    .bind(project)
    .bind(cutoff)
    .fetch_all(&hub.db)
    .await?;
    if !stale.is_empty() {
        let arcs: Vec<Arc<str>> = stale.iter().map(|s| Arc::<str>::from(s.as_str())).collect();
        hub.objects.discard(project, &arcs).await.map_err(Error::Other)?;
        report.staged_packs_swept += arcs.len();
    }
    Ok(())
}

/// Delete storage objects and `packs` rows of `DISCARDED` containers whose
/// `discarded_at` timestamp is at or before `now_ms - pack_grace_ms`.
async fn sweep_discarded(
    hub: &Arc<Hub>,
    project: i64,
    now_ms: i64,
    pack_grace_ms: i64,
    max_sweep: usize,
    report: &mut SweepReport,
) -> Result<()> {
    let cutoff = now_ms.saturating_sub(pack_grace_ms.max(0));
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM packs WHERE project_id = $1 AND state = $2 AND COALESCE(discarded_at, $4) <= $3 LIMIT $5",
    )
    .bind(project)
    .bind(DISCARDED)
    .bind(cutoff)
    .bind(now_ms)
    .bind(max_sweep as i64)
    .fetch_all(&hub.db)
    .await?;

    if rows.is_empty() {
        return Ok(());
    }

    let mut deleted_names: Vec<String> = Vec::with_capacity(rows.len());
    let mut arcs: Vec<Arc<str>> = Vec::with_capacity(rows.len());
    for chunk in rows.chunks(AT_ONCE) {
        hub.limits.derive_turn().await;
        let mut deletes = tokio::task::JoinSet::new();
        for name in chunk {
            let (hub, k) = (hub.clone(), pack::key(project, name));
            deletes.spawn(async move { hub.objects.delete_key(&k).await });
        }
        while let Some(r) = deletes.join_next().await {
            r.map_err(|e| Error::Other(e.into()))?.map_err(Error::Other)?;
        }
        for name in chunk {
            arcs.push(Arc::<str>::from(name.as_str()));
            deleted_names.push(name.clone());
        }
    }
    hub.objects.forget_packs(project, &arcs);

    let swept = sqlx::query("DELETE FROM packs WHERE project_id = $1 AND name = ANY($2) AND state = $3")
        .bind(project)
        .bind(&deleted_names)
        .bind(DISCARDED)
        .execute(&hub.db)
        .await?;
    if swept.rows_affected() > 0 {
        hub.commits.count(crate::db::Commit::PackGc);
    }

    report.discarded_packs_swept += deleted_names.len();
    Ok(())
}
