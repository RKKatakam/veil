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
//! * The per-project GC epoch (`access_epochs (project_id, -1)`) and root
//!   writers' gate (`GUARD_SQL`, [`guard_root_write`]) remain inert in v1:
//!   nothing ever raises the epoch.

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
};

use sqlx::PgConnection;

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

/// Per-server background upload-container sweeper state on [`Hub`].
#[derive(Default)]
pub struct State {
    /// Projects with a sweeper task on this server ([`schedule_sweep`]),
    /// each with whether it was asked again since it last looked.
    sweeping: Mutex<HashMap<i64, bool>>,
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

/// Inert error marker for GC-epoch mismatch. In Veil v1 there is no GC, so
/// `access_epochs (project_id, -1)` never advances and this error is never
/// raised.
#[derive(Debug)]
pub struct GcEpochChanged;

impl std::fmt::Display for GcEpochChanged {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("project GC epoch changed during root write")
    }
}

impl std::error::Error for GcEpochChanged {}

pub fn gc_epoch_changed(e: &anyhow::Error) -> bool {
    crate::error::caused_by::<GcEpochChanged>(e)
}

pub fn is_gc_epoch_changed(e: &Error) -> bool {
    matches!(e, Error::Other(a) if gc_epoch_changed(a))
}

/// Ensure the project's GC epoch row (`access_epochs (project, -1)`) exists,
/// read its current value, and synchronize `hub`'s in-memory caches.
/// Inert in v1: nothing raises the epoch.
pub async fn read_gc_epoch(hub: &Hub, project: i64) -> Result<i64> {
    let epoch: Option<i64> = sqlx::query_scalar(
        "SELECT epoch FROM access_epochs WHERE project_id = $1 AND person_id = -1",
    )
    .bind(project)
    .fetch_optional(&hub.db)
    .await?;
    let epoch = match epoch {
        Some(e) => e,
        None => {
            sqlx::query(
                "INSERT INTO access_epochs (project_id, person_id, epoch, changed_at) \
                 VALUES ($1, -1, 0, 0) ON CONFLICT (project_id, person_id) DO NOTHING",
            )
            .bind(project)
            .execute(&hub.db)
            .await?;
            sqlx::query_scalar(
                "SELECT COALESCE((SELECT epoch FROM access_epochs WHERE project_id = $1 AND person_id = -1), 0)",
            )
            .bind(project)
            .fetch_one(&hub.db)
            .await?
        }
    };
    hub.observe_gc_epoch(project, epoch);
    Ok(epoch)
}

/// [`read_gc_epoch`] for a push, reusing the epoch the session check read once
/// this server has seen the row exist. Inert in v1.
pub async fn push_gc_epoch(hub: &Hub, project: i64, read: Option<(i64, i64)>) -> Result<i64> {
    if let Some((p, epoch)) = read {
        if p == project && hub.caches.gc_row_known(project) {
            return Ok(epoch);
        }
    }
    let epoch = read_gc_epoch(hub, project).await?;
    hub.caches.know_gc_row(project);
    Ok(epoch)
}

/// Advisory lock namespace for the inert root-writers' gate (`"veilgcgt"` ^ `project_id`).
const GATE_BASE: i64 = 0x7665_696c_6763_6774;

/// Inert root-writers' gate query: takes a shared advisory lock and locks
/// `access_epochs (project, -1)` `FOR SHARE`. Nothing takes either lock
/// exclusively in v1.
pub(crate) const GUARD_SQL: &str = "SELECT e.epoch FROM (SELECT pg_advisory_xact_lock_shared($2)) g, access_epochs e \
     WHERE e.project_id = $1 AND e.person_id = -1 FOR SHARE OF e";

pub(crate) fn gate_key(project: i64) -> i64 {
    GATE_BASE ^ project
}

/// Verify the project's inert GC epoch still matches `expected_epoch`.
pub async fn guard_root_write(
    c: &mut PgConnection,
    project: i64,
    expected_epoch: i64,
) -> Result<()> {
    let cur: Option<i64> = sqlx::query_scalar(GUARD_SQL)
        .bind(project)
        .bind(gate_key(project))
        .fetch_optional(&mut *c)
        .await?;
    if cur != Some(expected_epoch) {
        return Err(Error::Other(anyhow::Error::new(GcEpochChanged)));
    }
    Ok(())
}
