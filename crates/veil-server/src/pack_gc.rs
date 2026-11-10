//! Pack compaction and garbage collection (milestone S29;
//! `docs/HUB.md` §13.37; `docs/design/server/storage-and-cost.md` §8).
//!
//! * **Merging small packs.** A push stores its objects in one storage object
//!   (a pack, S28). Once a project's small listed packs reach the threshold
//!   ([`MERGE_MIN_PACKS`], or when run directly), one background job per
//!   project (under a per-project database advisory lock and S24's shedding
//!   budget [`crate::limits::DERIVE_PAUSE`]) merges batches of small listed
//!   packs into larger ones (capped at [`MAX_MERGED_BYTES`] and
//!   [`crate::pack::MAX_OBJECTS`]), deduplicating objects across the packs
//!   merged and checking every entry's header and encoding.
//! * **Crash-safe write-then-switch-then-delete.** No pack is ever edited in
//!   place:
//!   1. the replacement pack is recorded in `packs` as `STAGED` (`person_id`
//!      `None`) before its bytes are written to storage;
//!   2. a single transaction checks that the replaced packs are still `LISTED`
//!      (and, for GC rewrites, that no push or ref change raced the mark),
//!      lists the replacement pack(s), and marks the replaced packs `DISCARDED`
//!      with `discarded_at = now_ms`;
//!   3. this server drops the replaced packs from its in-memory map
//!      ([`crate::store::Objects::forget_packs`]), while other servers prune
//!      them on their next listing refresh or when a ranged read finds a
//!      swept pack gone;
//!   4. once `now_ms - discarded_at >= grace_ms`, the sweep deletes the
//!      discarded packs' storage objects and then their rows in `packs` (and
//!      discards stale `STAGED` uploads past `staged_grace_ms`).
//! * **Garbage collection with a retention window.** GC marks every object
//!   reachable from the project's live roots:
//!   - all `branches` (including hidden embargo branches `embargo/<id>` with
//!     `hidden_for_embargo IS NOT NULL`),
//!   - tags (any `tags` table if present, and `Atag` objects),
//!   - PR revisions (any `pr_revisions` or `prs` table if present),
//!   - embargo lines and snapshots (`embargo_lines`, `embargo_snapshots`, S22),
//!   - the landing queue (`landing_queue` stack and landed results, `landings`,
//!     `landed_from`, `landed_changes`, S17/S18),
//!   - recorded dead-end attempts (`Snapshot.attempts`, S11),
//!   - CI results (`checks`, `tested`, S19),
//!   - API change refs (`change_refs`, S10),
//!   - projection memos (`projections` and `origins` for reachable snapshots,
//!     and standalone projection memos),
//!   - derived changed-path objects (`graph.changed`, S12) and live search
//!     segments (`search_shards.segments`, S15),
//!   - and every object in an active `STAGED` upload pack (so a racing push
//!     can never lose an object it uploaded or is about to reference).
//!   Any stored object (in a listed pack or loose in `p/<project>/…`,
//!   including superseded S15 search segments) not in the reachable set gets a
//!   `since_ms` timestamp in `unreferenced_objects` when first seen
//!   unreferenced, and is deleted only once `now_ms - since_ms >= retention_ms`
//!   (thin clones keep no server anchors). Objects referenced again have their
//!   `unreferenced_objects` rows cleared.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
};

use anyhow::anyhow;
use bytes::Bytes;
use sqlx::PgConnection;
use veil_core::{
    object::{EntryKind, Object},
    ObjectId,
};

use crate::{
    error::{Error, Result},
    pack::{self, Held, Index, Slot, DISCARDED, LISTED, STAGED},
    store::{object_key, ReadAhead},
    sync::builtin,
    Hub,
};

/// Advisory lock namespace for pack merge and GC (`"veilpkgc"` ^ `project_id`).
const LOCK_BASE: i64 = 0x7665_696c_706b_6763;

/// Default minimum number of small listed packs before background compaction
/// triggers automatically (`storage-and-cost.md` §7, §8).
pub const MERGE_MIN_PACKS: usize = 64;

/// A listed pack at or below this byte size (and below `MAX_OBJECTS / 2`) is a
/// candidate for merging with other small packs.
pub const SMALL_PACK_BYTES: u64 = 8 << 20;

/// Target maximum byte size of a merged pack.
pub const MAX_MERGED_BYTES: u64 = 32 << 20;

/// Maximum number of source packs merged in one pass (bounds work per run).
pub const MAX_PACKS_PER_RUN: usize = 64;

/// Maximum bytes read in a single storage range request when copying entries
/// from a source pack during merge/GC.
const COPY_SPAN: u64 = 2 << 20;

/// Default grace period before a `DISCARDED` pack's storage object and row are
/// deleted (`storage-and-cost.md` §8: long enough for in-flight reads to
/// finish).
pub const DEFAULT_PACK_GRACE_MS: i64 = 60_000;

/// Default grace period before an uncommitted `STAGED` upload pack is
/// considered abandoned and discarded (`storage-and-cost.md` §8).
pub const DEFAULT_STAGED_GRACE_MS: i64 = 3_600_000;

/// Default retention window for unreferenced objects (`storage-and-cost.md`
/// §8: thin clones keep no server anchors, and racing pushes may reference
/// recently uploaded or probed objects).
pub const DEFAULT_RETENTION_WINDOW_MS: i64 = 3_600_000;

/// Options controlling one merge / GC pass on a project.
#[derive(Clone, Debug)]
pub struct Options {
    /// Minimum number of small listed packs required to trigger merging
    /// (`1` or `2` to force merging whenever at least 2 small packs exist).
    pub min_packs_to_merge: usize,
    /// Maximum number of listed packs to merge in one pass.
    pub max_packs_per_run: usize,
    /// Maximum byte size of a pack considered "small" for merging.
    pub small_pack_bytes: u64,
    /// Maximum byte size of each output merged pack.
    pub max_merged_bytes: u64,
    /// Maximum objects per output merged pack (`<= pack::MAX_OBJECTS`).
    pub max_merged_objects: usize,
    /// Whether to run reachability marking and garbage-collect unreferenced
    /// packed and loose objects (and unreferenced S15 search segments).
    pub run_gc: bool,
    /// Retention window in milliseconds before an unreferenced object may be
    /// deleted.
    pub retention_window_ms: i64,
    /// Grace window in milliseconds before a `DISCARDED` pack's storage object
    /// and row are deleted.
    pub pack_grace_ms: i64,
    /// Grace window in milliseconds before an abandoned `STAGED` upload pack
    /// is discarded.
    pub staged_grace_ms: i64,
    /// Simulated clock offset in milliseconds (for tests).
    pub now_offset_ms: i64,
    /// Crash injection hook for tests.
    pub crash: Option<CrashPoint>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            min_packs_to_merge: 2,
            max_packs_per_run: MAX_PACKS_PER_RUN,
            small_pack_bytes: SMALL_PACK_BYTES,
            max_merged_bytes: MAX_MERGED_BYTES,
            max_merged_objects: pack::MAX_OBJECTS,
            run_gc: true,
            retention_window_ms: DEFAULT_RETENTION_WINDOW_MS,
            pack_grace_ms: DEFAULT_PACK_GRACE_MS,
            staged_grace_ms: DEFAULT_STAGED_GRACE_MS,
            now_offset_ms: 0,
            crash: None,
        }
    }
}

impl Options {
    /// Options for merging small packs only (no GC mark/sweep of unreferenced
    /// objects).
    pub fn merge_only() -> Self {
        Options {
            min_packs_to_merge: 2,
            run_gc: false,
            ..Options::default()
        }
    }

    fn now_ms(&self) -> i64 {
        veil_core::now_millis().saturating_add(self.now_offset_ms)
    }
}

/// Points during a merge where a test can simulate a server crash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrashPoint {
    /// Stop after writing the new `STAGED` pack(s) to storage, before the
    /// database transaction switches the listing.
    AfterWriteBeforeSwitch,
    /// Stop immediately after the database transaction switches the new pack(s)
    /// to `LISTED` and the old packs to `DISCARDED`, before `forget_packs` or
    /// storage deletion runs.
    AfterSwitchBeforeDelete,
}

/// Statistics returned by a merge / GC run.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// Another server held the project's pack-GC advisory lock.
    pub skipped: bool,
    /// Number of old listed packs replaced by merged/rewritten packs (or
    /// discarded as empty).
    pub packs_merged: usize,
    /// Number of new listed packs written.
    pub packs_written: usize,
    /// Number of packed objects kept in rewritten/merged packs.
    pub objects_kept: usize,
    /// Number of unreferenced objects removed from packs.
    pub packed_objects_deleted: usize,
    /// Number of unreferenced loose objects (including S15 search segments)
    /// deleted from storage.
    pub loose_objects_deleted: usize,
    /// Number of `DISCARDED` packs whose storage files and rows were swept.
    pub discarded_packs_swept: usize,
    /// Number of stale `STAGED` packs discarded and swept.
    pub staged_packs_swept: usize,
}

/// Per-server background pack-GC state on [`Hub`].
#[derive(Default)]
pub struct State {
    active: Mutex<HashSet<i64>>,
    pub runs: AtomicU64,
}

/// Trigger a background pack-merge check for `project` if its small listed
/// pack count has reached [`MERGE_MIN_PACKS`]. Non-blocking; yields to
/// landings and pushes via `limits.derive_turn()`.
pub fn maybe_schedule(hub: &Arc<Hub>, project: i64) {
    {
        let mut active = hub.pack_gc.active.lock().unwrap();
        if !active.insert(project) {
            return;
        }
    }
    let hub = hub.clone();
    tokio::spawn(async move {
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM packs WHERE project_id = $1 AND state = $2 AND size <= $3",
        )
        .bind(project)
        .bind(LISTED)
        .bind(SMALL_PACK_BYTES as i64)
        .fetch_one(&hub.derive.db)
        .await
        .unwrap_or(0);
        if count as usize >= MERGE_MIN_PACKS {
            let opts = Options {
                min_packs_to_merge: MERGE_MIN_PACKS,
                run_gc: false,
                ..Options::default()
            };
            let _ = run_project(&hub, project, &opts).await;
        }
        hub.pack_gc.active.lock().unwrap().remove(&project);
    });
}

/// Run one bounded merge and/or garbage-collection pass on `project`.
pub async fn run_project(hub: &Arc<Hub>, project: i64, opts: &Options) -> Result<Report> {
    let hub = hub.clone();
    let opts = opts.clone();
    tokio::spawn(async move { run_locked(&hub, project, &opts).await })
        .await
        .map_err(|e| Error::Other(e.into()))?
}

async fn run_locked(hub: &Arc<Hub>, project: i64, opts: &Options) -> Result<Report> {
    // Yield to pushes and landings under S24's shedding budget.
    hub.limits.derive_turn().await;
    let permit = hub.derive.permit().await?;
    let mut lock_conn = hub.derive.db.acquire().await?;
    let lock_key = LOCK_BASE ^ project;
    let got: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
        .bind(lock_key)
        .fetch_one(&mut *lock_conn)
        .await?;
    if !got {
        return Ok(Report {
            skipped: true,
            ..Report::default()
        });
    }
    let res = run_with_lock(hub, project, opts).await;
    let _ = sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(lock_key)
        .execute(&mut *lock_conn)
        .await;
    drop((lock_conn, permit));
    hub.pack_gc.runs.fetch_add(1, Ordering::Relaxed);
    res
}

#[derive(Clone, Debug)]
struct PackRow {
    name: Arc<str>,
    size: u64,
    objects: usize,
    created_at: i64,
}

/// Fingerprint of the project's refs and history so GC can detect any push,
/// API commit, landing, or staged upload that arrived while reachability was
/// being walked.
#[derive(Clone, Debug, PartialEq, Eq)]
struct RefStamp {
    branches: Vec<(String, String, i64, Option<String>)>,
    snapshots_count: i64,
    staged_packs: Vec<String>,
    change_refs_count: i64,
    landing_queue_max: Option<i64>,
    embargo_count: i64,
    checks_max: Option<i64>,
    tested_max: Option<i64>,
}

async fn read_ref_stamp(c: &mut PgConnection, project: i64) -> Result<RefStamp> {
    let branches: Vec<(String, String, i64, Option<String>)> = sqlx::query_as(
        "SELECT name, target, lineage, hidden_for_embargo FROM branches WHERE project_id = $1 ORDER BY name",
    )
    .bind(project)
    .fetch_all(&mut *c)
    .await?;
    let snapshots_count: i64 = sqlx::query_scalar("SELECT count(*) FROM snapshots WHERE project_id = $1")
        .bind(project)
        .fetch_one(&mut *c)
        .await?;
    let staged_packs: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM packs WHERE project_id = $1 AND state = $2 AND person_id IS NOT NULL ORDER BY name",
    )
    .bind(project)
    .bind(STAGED)
    .fetch_all(&mut *c)
    .await?;
    let change_refs_count: i64 = sqlx::query_scalar("SELECT count(*) FROM change_refs WHERE project_id = $1")
        .bind(project)
        .fetch_one(&mut *c)
        .await?;
    let landing_queue_max: Option<i64> = sqlx::query_scalar("SELECT max(seq) FROM landing_queue WHERE project_id = $1")
        .bind(project)
        .fetch_one(&mut *c)
        .await?;
    let embargo_count: i64 = sqlx::query_scalar("SELECT count(*) FROM embargo_snapshots WHERE project_id = $1")
        .bind(project)
        .fetch_one(&mut *c)
        .await?;
    let checks_max: Option<i64> = sqlx::query_scalar("SELECT max(updated_at) FROM checks WHERE project_id = $1")
        .bind(project)
        .fetch_one(&mut *c)
        .await?;
    let tested_max: Option<i64> = sqlx::query_scalar("SELECT max(updated_at) FROM tested WHERE project_id = $1")
        .bind(project)
        .fetch_one(&mut *c)
        .await?;
    Ok(RefStamp {
        branches,
        snapshots_count,
        staged_packs,
        change_refs_count,
        landing_queue_max,
        embargo_count,
        checks_max,
        tested_max,
    })
}

async fn run_with_lock(hub: &Arc<Hub>, project: i64, opts: &Options) -> Result<Report> {
    let mut report = Report::default();
    let now_ms = opts.now_ms();

    // 1. Clean up any leftover uncommitted job packs (`state = STAGED AND person_id IS NULL`)
    // from an earlier crashed merge/GC run on this project, and discard stale
    // client upload packs (`state = STAGED AND person_id IS NOT NULL`) older
    // than `staged_grace_ms`.
    sweep_staged(hub, project, now_ms, opts.staged_grace_ms, &mut report).await?;

    // 2. If `run_gc` is enabled, compute the reachable object closure and
    // update `unreferenced_objects`, returning the set of objects that are
    // unreferenced AND past `retention_window_ms` (eligible for deletion now).
    let gc_state = if opts.run_gc {
        hub.limits.derive_turn().await;
        Some(mark_and_sweep_loose(hub, project, opts, now_ms, &mut report).await?)
    } else {
        None
    };

    // 3. Load listed packs for `project`, oldest first.
    let listed_rows: Vec<(String, i64, i64, i64)> = sqlx::query_as(
        "SELECT name, size, objects, created_at FROM packs WHERE project_id = $1 AND state = $2 ORDER BY created_at, name",
    )
    .bind(project)
    .bind(LISTED)
    .fetch_all(&hub.db)
    .await?;

    let listed: Vec<PackRow> = listed_rows
        .into_iter()
        .map(|(name, size, objects, created_at)| PackRow {
            name: name.into(),
            size: size.max(0) as u64,
            objects: objects.max(0) as usize,
            created_at,
        })
        .collect();

    // Determine which packs to rewrite/merge in this bounded pass:
    // - any small pack (`size <= opts.small_pack_bytes` and `objects <= opts.max_merged_objects / 2`)
    //   when there are at least `opts.min_packs_to_merge` such packs;
    // - plus, when `run_gc` is true, any pack that holds at least one
    //   expired-unreferenced object (or duplicate object already held by
    //   another pack in the batch).
    let (batch, expired_unreferenced, ref_stamp) = select_batch(hub, project, &listed, opts, gc_state).await?;

    if !batch.is_empty() {
        let crashed = compact_batch(
            hub,
            project,
            &batch,
            &expired_unreferenced,
            ref_stamp.as_ref(),
            opts,
            now_ms,
            &mut report,
        )
        .await?;
        if crashed {
            return Ok(report);
        }
    }

    // 4. Sweep `DISCARDED` packs whose `discarded_at` is past `pack_grace_ms`.
    sweep_discarded(
        hub,
        project,
        now_ms,
        opts.pack_grace_ms,
        opts.max_packs_per_run.max(256) * 2,
        &mut report,
    )
    .await?;

    Ok(report)
}

struct GcState {
    /// Objects that are NOT reachable and whose `since_ms` in
    /// `unreferenced_objects` is `<= now_ms - retention_window_ms`.
    expired_unreferenced: HashSet<ObjectId>,
    /// Fingerprint of refs before reachability was computed.
    stamp: RefStamp,
}

async fn select_batch(
    hub: &Arc<Hub>,
    project: i64,
    listed: &[PackRow],
    opts: &Options,
    gc: Option<GcState>,
) -> Result<(Vec<PackRow>, HashSet<ObjectId>, Option<RefStamp>)> {
    let max_per_run = opts.max_packs_per_run.max(1);
    let mut small: Vec<PackRow> = listed
        .iter()
        .filter(|p| p.size <= opts.small_pack_bytes && p.objects <= opts.max_merged_objects / 2)
        .cloned()
        .collect();
    small.sort_by(|a, b| {
        (a.objects, a.size, a.created_at, &a.name).cmp(&(b.objects, b.size, b.created_at, &b.name))
    });

    let Some(gc) = gc else {
        if small.len() < opts.min_packs_to_merge {
            return Ok((Vec::new(), HashSet::new(), None));
        }
        let batch = small.into_iter().take(max_per_run).collect();
        return Ok((batch, HashSet::new(), None));
    };

    let mut chosen: Vec<PackRow> = Vec::new();
    let mut chosen_names: HashSet<Arc<str>> = HashSet::new();

    if small.len() >= opts.min_packs_to_merge {
        for p in small.into_iter().take(max_per_run) {
            chosen_names.insert(p.name.clone());
            chosen.push(p);
        }
    }

    // If GC found expired unreferenced objects, check which listed packs hold
    // any of them (or are not yet in `chosen`), up to `max_per_run`.
    if !gc.expired_unreferenced.is_empty() && chosen.len() < max_per_run {
        let store = hub.objects.blob_store();
        let bound = hub.objects.index_bound();
        for p in listed {
            if chosen.len() >= max_per_run {
                break;
            }
            if chosen_names.contains(&p.name) {
                continue;
            }
            hub.limits.derive_turn().await;
            let k = pack::key(project, &p.name);
            hub.objects.reads.fetch_add(1, Ordering::Relaxed);
            let Some(held) = pack::read_index(&**store, &k, bound).await.map_err(Error::Other)? else {
                continue;
            };
            let has_dead = held.index.iter().any(|(id, _)| gc.expired_unreferenced.contains(id));
            drop(held);
            if has_dead {
                chosen_names.insert(p.name.clone());
                chosen.push(p.clone());
            }
        }
    }

    Ok((chosen, gc.expired_unreferenced, Some(gc.stamp)))
}

/// Merge and/or GC-filter `batch` of listed packs into one or more replacement
/// packs. Returns `Ok(true)` if a simulated crash stopped the pass early.
#[allow(clippy::too_many_arguments)]
async fn compact_batch(
    hub: &Arc<Hub>,
    project: i64,
    batch: &[PackRow],
    expired_unreferenced: &HashSet<ObjectId>,
    expected_stamp: Option<&RefStamp>,
    opts: &Options,
    now_ms: i64,
    report: &mut Report,
) -> Result<bool> {
    let store = hub.objects.blob_store();
    let bound = hub.objects.index_bound();

    // 1. Read the index of each pack in `batch` one at a time (so we hold only
    // one index share at a time!) and collect the live slots to copy,
    // deduplicating across `batch` (keeping the newest pack's copy, or first
    // seen).
    let mut seen: HashSet<ObjectId> = HashSet::new();
    let mut dead_count = 0usize;
    // Per pack in `batch` (newest first so newest copy wins if duplicated, then
    // reversed back to chronological pack order): `(PackRow, Vec<(ObjectId, Slot)>)`.
    let mut plan: Vec<(PackRow, Vec<(ObjectId, Slot)>)> = Vec::with_capacity(batch.len());

    for p in batch.iter().rev() {
        hub.limits.derive_turn().await;
        let k = pack::key(project, &p.name);
        hub.objects.reads.fetch_add(1, Ordering::Relaxed);
        let Some(held) = pack::read_index(&**store, &k, bound).await.map_err(Error::Other)? else {
            // Pack was already replaced by another run.
            return Ok(false);
        };
        let mut keep_slots: Vec<(ObjectId, Slot)> = Vec::new();
        for (id, slot) in held.index.iter() {
            if expired_unreferenced.contains(id) {
                dead_count += 1;
                continue;
            }
            if seen.insert(*id) {
                keep_slots.push((*id, *slot));
            }
        }
        // Sort by offset so we read contiguous/nearby spans in few range requests.
        keep_slots.sort_unstable_by_key(|(_, s)| s.offset);
        drop(held);
        plan.push((p.clone(), keep_slots));
    }
    plan.reverse();

    // If only 1 pack is in the batch and no objects were removed from it,
    // there is nothing to rewrite.
    if batch.len() == 1 && dead_count == 0 {
        return Ok(false);
    }

    // 2. Stream/read the kept entries from the source packs in bounded range
    // spans under `ReadAhead`, building replacement packs capped at
    // `opts.max_merged_bytes` and `opts.max_merged_objects`.
    let max_bytes = opts.max_merged_bytes.max(1 << 20);
    let max_objs = opts.max_merged_objects.clamp(1, pack::MAX_OBJECTS);

    let mut written_packs: Vec<(Arc<str>, Held, u64, usize)> = Vec::new();
    let mut cur_objects: Vec<(ObjectId, Bytes)> = Vec::new();
    let mut cur_bytes: u64 = 14; // MAGIC + count
    let mut total_kept = 0usize;

    for (p, slots) in &plan {
        if slots.is_empty() {
            continue;
        }
        let k = pack::key(project, &p.name);
        let mut i = 0;
        while i < slots.len() {
            hub.limits.derive_turn().await;
            let start_off = slots[i].1.offset;
            let mut end_idx = i;
            while end_idx + 1 < slots.len() {
                let next_last = slots[end_idx + 1].1.last();
                if next_last - start_off + 1 > COPY_SPAN {
                    break;
                }
                end_idx += 1;
            }
            let end_off = slots[end_idx].1.last();
            let span_len = end_off - start_off + 1;
            let _ra = ReadAhead::wait(span_len).await;
            hub.objects.reads.fetch_add(1, Ordering::Relaxed);
            let (bytes, _) = store
                .get_range(&k, start_off, end_off)
                .await
                .map_err(Error::Other)?
                .ok_or_else(|| Error::Other(anyhow!("source pack {} missing during merge", p.name)))?;
            if (bytes.len() as u64) < span_len {
                return Err(Error::Other(anyhow!("source pack {} shorter than its index", p.name)));
            }
            for &(id, slot) in &slots[i..=end_idx] {
                let from = (slot.offset - start_off) as usize;
                let to = (slot.last() - start_off) as usize;
                let enc_slice = pack::entry(&id, slot, &bytes[from..=to]).map_err(Error::Other)?;
                let enc = Bytes::copy_from_slice(enc_slice);
                let entry_cost = 44 + 36 + enc.len() as u64;
                if !cur_objects.is_empty()
                    && (cur_objects.len() >= max_objs || cur_bytes + entry_cost > max_bytes)
                {
                    let count = cur_objects.len();
                    let batch_objs = std::mem::take(&mut cur_objects);
                    cur_bytes = 14;
                    let (name, held) = crate::store::not_own(hub.objects.put_job_pack(project, batch_objs))
                        .await
                        .map_err(Error::Other)?;
                    let sz = held.size;
                    written_packs.push((name, held, sz, count));
                }
                cur_bytes += entry_cost;
                cur_objects.push((id, enc));
                total_kept += 1;
            }
            drop(_ra);
            i = end_idx + 1;
        }
    }

    if !cur_objects.is_empty() {
        let count = cur_objects.len();
        let batch_objs = std::mem::take(&mut cur_objects);
        let (name, held) = crate::store::not_own(hub.objects.put_job_pack(project, batch_objs))
            .await
            .map_err(Error::Other)?;
        let sz = held.size;
        written_packs.push((name, held, sz, count));
    }

    // Simulated crash after writing the staged replacement pack(s), before
    // switching the database rows.
    if opts.crash == Some(CrashPoint::AfterWriteBeforeSwitch) {
        return Ok(true);
    }

    // 3. Switch the database rows in a single transaction:
    // - verify every pack in `batch` is still `LISTED` (locking the rows);
    // - if `expected_stamp` is Some (a GC run that drops unreferenced objects),
    //   verify the project's ref/push stamp has not changed (or if no objects
    //   were dropped, pure compaction is safe regardless of concurrent pushes!);
    // - mark the new pack(s) `LISTED` (giving them `created_at` matching the
    //   newest replaced pack so pack chronological order is preserved);
    // - mark the old packs `DISCARDED` with `discarded_at = now_ms`.
    let old_names: Vec<String> = batch.iter().map(|p| p.name.to_string()).collect();
    let new_names: Vec<String> = written_packs.iter().map(|(n, _, _, _)| n.to_string()).collect();
    let newest_created_at = batch.iter().map(|p| p.created_at).max().unwrap_or(now_ms);
    let check_stamp = if dead_count > 0 { expected_stamp.cloned() } else { None };
    let expired_hexes: Vec<String> = if dead_count > 0 {
        expired_unreferenced.iter().map(|id| id.hex()).collect()
    } else {
        Vec::new()
    };

    let switched = crate::db::transaction(&hub.db, crate::db::Isolation::ReadCommitted, |c| {
        let old_names = old_names.clone();
        let new_names = new_names.clone();
        let check_stamp = check_stamp.clone();
        let expired_hexes = expired_hexes.clone();
        Box::pin(async move {
            if let Some(expected) = &check_stamp {
                let cur = read_ref_stamp(c, project).await?;
                if &cur != expected {
                    return Ok(false);
                }
            }
            let locked: Vec<String> = sqlx::query_scalar(
                "SELECT name FROM packs WHERE project_id = $1 AND name = ANY($2) AND state = $3 FOR UPDATE",
            )
            .bind(project)
            .bind(&old_names)
            .bind(LISTED)
            .fetch_all(&mut *c)
            .await?;
            if locked.len() != old_names.len() {
                return Ok(false);
            }
            if !new_names.is_empty() {
                sqlx::query(
                    "UPDATE packs SET state = $3, created_at = $4 WHERE project_id = $1 AND name = ANY($2) AND state = $5",
                )
                .bind(project)
                .bind(&new_names)
                .bind(LISTED)
                .bind(newest_created_at)
                .bind(STAGED)
                .execute(&mut *c)
                .await?;
            }
            sqlx::query(
                "UPDATE packs SET state = $3, discarded_at = $4 WHERE project_id = $1 AND name = ANY($2) AND state = $5",
            )
            .bind(project)
            .bind(&old_names)
            .bind(DISCARDED)
            .bind(now_ms)
            .bind(LISTED)
            .execute(&mut *c)
            .await?;
            if !expired_hexes.is_empty() {
                sqlx::query(
                    "DELETE FROM unreferenced_objects WHERE project_id = $1 AND object_id = ANY($2)",
                )
                .bind(project)
                .bind(&expired_hexes)
                .execute(&mut *c)
                .await?;
            }
            Ok(true)
        })
    })
    .await?;

    if !switched {
        // A racing push or another state change intervened; discard the staged
        // replacement packs we wrote.
        let discard_names: Vec<Arc<str>> = written_packs.into_iter().map(|(n, _, _, _)| n).collect();
        hub.objects.discard(project, &discard_names).await.map_err(Error::Other)?;
        return Ok(false);
    }

    report.packs_merged += batch.len();
    report.packs_written += written_packs.len();
    report.objects_kept += total_kept;
    report.packed_objects_deleted += dead_count;

    // Simulated crash right after the switch transaction commits, before
    // `listed_here` / `forget_packs` or storage deletion runs.
    if opts.crash == Some(CrashPoint::AfterSwitchBeforeDelete) {
        return Ok(true);
    }

    let for_listed: Vec<(Arc<str>, Arc<Index>)> = written_packs
        .into_iter()
        .map(|(n, held, _, _)| (n, held.index.clone()))
        .collect();
    if !for_listed.is_empty() {
        hub.objects.listed_here(project, for_listed);
    }
    let old_arcs: Vec<Arc<str>> = batch.iter().map(|p| p.name.clone()).collect();
    hub.objects.forget_packs(project, &old_arcs);

    Ok(false)
}

/// Discard and delete any uncommitted compaction/GC packs (`state = STAGED AND
/// person_id IS NULL`) left by an interrupted run, and any abandoned client
/// upload packs (`state = STAGED AND person_id IS NOT NULL`) older than
/// `staged_grace_ms`, plus any orphan pack files in storage that have no row in
/// `packs`.
async fn sweep_staged(
    hub: &Arc<Hub>,
    project: i64,
    now_ms: i64,
    staged_grace_ms: i64,
    report: &mut Report,
) -> Result<()> {
    let cutoff = now_ms.saturating_sub(staged_grace_ms.max(0));
    let stale: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM packs WHERE project_id = $1 AND state = $2 AND (person_id IS NULL OR created_at <= $3)",
    )
    .bind(project)
    .bind(STAGED)
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

/// Delete storage objects and `packs` rows of `DISCARDED` packs whose
/// `discarded_at` timestamp is at or before `now_ms - pack_grace_ms`.
/// Note: when `pack_grace_ms == 0`, all `DISCARDED` packs of the project are
/// swept; when `pack_grace_ms > 0`, only `DISCARDED` rows that have a
/// `discarded_at` timestamp (set by compaction/GC or `discard`) at or before
/// `now_ms - pack_grace_ms` are deleted.
async fn sweep_discarded(
    hub: &Arc<Hub>,
    project: i64,
    now_ms: i64,
    pack_grace_ms: i64,
    max_sweep: usize,
    report: &mut Report,
) -> Result<()> {
    let cutoff = now_ms.saturating_sub(pack_grace_ms.max(0));
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM packs WHERE project_id = $1 AND state = $2 AND COALESCE(discarded_at, $4) <= $3 ORDER BY name LIMIT $5",
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

    let store = hub.objects.blob_store();
    let mut deleted_names: Vec<String> = Vec::with_capacity(rows.len());
    let mut arcs: Vec<Arc<str>> = Vec::with_capacity(rows.len());
    for name in rows {
        hub.limits.derive_turn().await;
        store
            .delete(&pack::key(project, &name))
            .await
            .map_err(Error::Other)?;
        arcs.push(Arc::<str>::from(name.as_str()));
        deleted_names.push(name);
    }
    hub.objects.forget_packs(project, &arcs);

    sqlx::query("DELETE FROM packs WHERE project_id = $1 AND name = ANY($2) AND state = $3")
        .bind(project)
        .bind(&deleted_names)
        .bind(DISCARDED)
        .execute(&hub.db)
        .await?;

    report.discarded_packs_swept += deleted_names.len();
    Ok(())
}

/// Walk all live roots of `project`, compute the full reachable object set,
/// update `unreferenced_objects`, and delete loose objects (including S15
/// search segments) that have been unreferenced for at least
/// `opts.retention_window_ms`.
async fn mark_and_sweep_loose(
    hub: &Arc<Hub>,
    project: i64,
    opts: &Options,
    now_ms: i64,
    report: &mut Report,
) -> Result<GcState> {
    let mut conn = hub.db.acquire().await?;
    let stamp = read_ref_stamp(&mut conn, project).await?;
    let roots = collect_db_roots(&mut conn, project).await?;
    drop(conn);

    // Walk object graph from `roots` to find all reachable `ObjectId`s.
    let mut reachable = walk_reachable(hub, project, &roots).await?;

    // Also include all objects in active `STAGED` upload packs so a push in
    // flight can never lose an object it staged or is about to reference.
    let store = hub.objects.blob_store();
    let bound = hub.objects.index_bound();
    for staged_name in &stamp.staged_packs {
        let k = pack::key(project, staged_name);
        if let Some(held) = pack::read_index(&**store, &k, bound).await.map_err(Error::Other)? {
            for (id, _) in held.index.iter() {
                reachable.insert(*id);
            }
        }
    }

    // Now enumerate all objects currently stored in `project`:
    // (a) in `LISTED` packs, and
    // (b) loose under `p/<project>/xx/yyyy...`.
    let listed_names: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM packs WHERE project_id = $1 AND state = $2 ORDER BY created_at, name",
    )
    .bind(project)
    .bind(LISTED)
    .fetch_all(&hub.db)
    .await?;

    let mut all_stored: HashSet<ObjectId> = HashSet::new();
    for name in &listed_names {
        hub.limits.derive_turn().await;
        let k = pack::key(project, name);
        hub.objects.reads.fetch_add(1, Ordering::Relaxed);
        if let Some(held) = pack::read_index(&**store, &k, bound).await.map_err(Error::Other)? {
            for (id, _) in held.index.iter() {
                all_stored.insert(*id);
            }
        }
    }

    let prefix = format!("p/{project}/");
    let keys = store.list(&prefix).await.map_err(Error::Other)?;
    let mut loose_ids: Vec<ObjectId> = Vec::new();
    for k in keys {
        let Some(rest) = k.strip_prefix(&prefix) else { continue };
        if rest.starts_with("pack/") {
            continue;
        }
        // Loose object key is `p/<project>/<2 hex>/<62 hex>`.
        let parts: Vec<&str> = rest.split('/').collect();
        if parts.len() == 2 && parts[0].len() == 2 && parts[1].len() == 62 {
            let hex_str = format!("{}{}", parts[0], parts[1]);
            if let Ok(id) = ObjectId::from_hex(&hex_str) {
                all_stored.insert(id);
                loose_ids.push(id);
            }
        }
    }

    // Reconcile `unreferenced_objects`:
    // 1. Any object in `unreferenced_objects` that is now in `reachable` (or no
    //    longer in `all_stored`) is removed from `unreferenced_objects`.
    // 2. Any object in `all_stored` that is NOT in `reachable` is inserted into
    //    `unreferenced_objects (project_id, object_id, since_ms) ON CONFLICT DO NOTHING`.
    let existing_unreferenced: Vec<(String, i64)> = sqlx::query_as(
        "SELECT object_id, since_ms FROM unreferenced_objects WHERE project_id = $1",
    )
    .bind(project)
    .fetch_all(&hub.db)
    .await?;

    let mut unref_map: HashMap<ObjectId, i64> = HashMap::new();
    let mut to_clear: Vec<String> = Vec::new();
    for (hex_id, since) in existing_unreferenced {
        match ObjectId::from_hex(&hex_id) {
            Ok(id) if !reachable.contains(&id) && all_stored.contains(&id) => {
                unref_map.insert(id, since);
            }
            _ => to_clear.push(hex_id),
        }
    }

    if !to_clear.is_empty() {
        for chunk in to_clear.chunks(500) {
            sqlx::query("DELETE FROM unreferenced_objects WHERE project_id = $1 AND object_id = ANY($2)")
                .bind(project)
                .bind(chunk)
                .execute(&hub.db)
                .await?;
        }
    }

    let mut newly_unref: Vec<String> = Vec::new();
    for id in &all_stored {
        if !reachable.contains(id) && !unref_map.contains_key(id) {
            unref_map.insert(*id, now_ms);
            newly_unref.push(id.hex());
        }
    }

    if !newly_unref.is_empty() {
        for chunk in newly_unref.chunks(500) {
            sqlx::query(
                "INSERT INTO unreferenced_objects (project_id, object_id, since_ms) \
                 SELECT $1, u, $3 FROM UNNEST($2::text[]) AS t(u) \
                 ON CONFLICT (project_id, object_id) DO NOTHING",
            )
            .bind(project)
            .bind(chunk)
            .bind(now_ms)
            .execute(&hub.db)
            .await?;
        }
    }

    let cutoff = now_ms.saturating_sub(opts.retention_window_ms.max(0));
    let expired_unreferenced: HashSet<ObjectId> = unref_map
        .into_iter()
        .filter_map(|(id, since)| (since <= cutoff).then_some(id))
        .collect();

    // Delete expired unreferenced loose objects (after verifying `read_ref_stamp`
    // is unchanged so no racing push referenced them).
    if !loose_ids.is_empty() && !expired_unreferenced.is_empty() {
        let cur_stamp = {
            let mut conn = hub.db.acquire().await?;
            read_ref_stamp(&mut conn, project).await?
        };
        if cur_stamp == stamp {
            let mut deleted_hexes = Vec::new();
            for id in loose_ids {
                if expired_unreferenced.contains(&id) {
                    hub.limits.derive_turn().await;
                    store.delete(&object_key(project, &id)).await.map_err(Error::Other)?;
                    deleted_hexes.push(id.hex());
                    report.loose_objects_deleted += 1;
                }
            }
            if !deleted_hexes.is_empty() {
                for chunk in deleted_hexes.chunks(500) {
                    sqlx::query(
                        "DELETE FROM unreferenced_objects WHERE project_id = $1 AND object_id = ANY($2)",
                    )
                    .bind(project)
                    .bind(chunk)
                    .execute(&hub.db)
                    .await?;
                }
            }
        }
    }

    Ok(GcState {
        expired_unreferenced,
        stamp,
    })
}

/// Roots collected from the database before walking the object graph.
#[derive(Default)]
struct DbRoots {
    /// Root object IDs (snapshots, trees, tags, blobs) to walk.
    walk_objects: HashSet<ObjectId>,
    /// Leaf object IDs (S15 search segments, S12 `graph.changed` objects) that
    /// are directly referenced and do not wrap standard `veil_core::Object`s.
    leaf_objects: HashSet<ObjectId>,
    /// All snapshot IDs in `snapshots` for `project`.
    known_snapshots: HashSet<ObjectId>,
    /// `origins`: `real_id -> origin_id`.
    origins: HashMap<ObjectId, ObjectId>,
    /// `projections`: `real_id -> Vec<projected_id>`.
    projections: HashMap<ObjectId, Vec<ObjectId>>,
    /// `graph.changed`: `snapshot_id -> changed_object_id`.
    graph_changed: HashMap<ObjectId, ObjectId>,
}

fn insert_hex(set: &mut HashSet<ObjectId>, hex: &str) {
    if let Ok(id) = ObjectId::from_hex(hex.trim()) {
        set.insert(id);
    }
}

async fn collect_db_roots(c: &mut PgConnection, project: i64) -> Result<DbRoots> {
    let mut r = DbRoots::default();

    // 1. All branches (public AND hidden embargo branches `hidden_for_embargo IS NOT NULL`).
    let branch_targets: Vec<String> = sqlx::query_scalar("SELECT target FROM branches WHERE project_id = $1")
        .bind(project)
        .fetch_all(&mut *c)
        .await?;
    for t in branch_targets {
        insert_hex(&mut r.walk_objects, &t);
    }

    // 2. Embargo lines and embargo snapshots (S22).
    let embargo_snaps: Vec<String> = sqlx::query_scalar("SELECT snapshot FROM embargo_snapshots WHERE project_id = $1")
        .bind(project)
        .fetch_all(&mut *c)
        .await?;
    for s in embargo_snaps {
        insert_hex(&mut r.walk_objects, &s);
    }
    let embargo_records: Vec<String> = sqlx::query_scalar("SELECT record_json FROM embargo_lines WHERE project_id = $1")
        .bind(project)
        .fetch_all(&mut *c)
        .await?;
    for rec in embargo_records {
        collect_hex_ids_from_json(&rec, &mut r.walk_objects);
    }

    // 3. Change refs (S10 API changes).
    let change_snaps: Vec<String> = sqlx::query_scalar("SELECT snapshot FROM change_refs WHERE project_id = $1")
        .bind(project)
        .fetch_all(&mut *c)
        .await?;
    for s in change_snaps {
        insert_hex(&mut r.walk_objects, &s);
    }

    // 4. Landing queue entries (S17, S18): `stack` JSON and `result` JSON, plus
    // active `landings` rows.
    let queue_rows: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT stack, result FROM landing_queue WHERE project_id = $1",
    )
    .bind(project)
    .fetch_all(&mut *c)
    .await?;
    for (stack, result) in queue_rows {
        collect_hex_ids_from_json(&stack, &mut r.walk_objects);
        if let Some(res) = result {
            collect_hex_ids_from_json(&res, &mut r.walk_objects);
        }
    }
    let landing_rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT submitted, landed FROM landings WHERE project_id = $1",
    )
    .bind(project)
    .fetch_all(&mut *c)
    .await?;
    for (sub, landed) in landing_rows {
        insert_hex(&mut r.walk_objects, &sub);
        insert_hex(&mut r.walk_objects, &landed);
    }

    // 5. CI results (S19): `checks` and `tested`.
    let check_snaps: Vec<String> = sqlx::query_scalar("SELECT DISTINCT snapshot FROM checks WHERE project_id = $1")
        .bind(project)
        .fetch_all(&mut *c)
        .await?;
    for s in check_snaps {
        insert_hex(&mut r.walk_objects, &s);
    }
    let tested_snaps: Vec<String> = sqlx::query_scalar("SELECT snapshot FROM tested WHERE project_id = $1")
        .bind(project)
        .fetch_all(&mut *c)
        .await?;
    for s in tested_snaps {
        insert_hex(&mut r.walk_objects, &s);
    }

    // 6. Optional tables (`tags`, `prs`, `pr_revisions`) if created by another
    // milestone or test.
    for (table, col) in [
        ("tags", "target"),
        ("tags", "snapshot"),
        ("tags", "atag"),
        ("pr_revisions", "head"),
        ("pr_revisions", "base"),
        ("pr_revisions", "changes"),
        ("prs", "head"),
        ("prs", "base"),
    ] {
        if table_has_column(c, table, col).await? {
            let query = format!("SELECT {col}::text FROM {table} WHERE project_id = $1 AND {col} IS NOT NULL");
            let vals: Vec<String> = sqlx::query_scalar(&query).bind(project).fetch_all(&mut *c).await?;
            for v in vals {
                collect_hex_ids_from_json(&v, &mut r.walk_objects);
            }
        }
    }

    // 7. Known snapshots, origins, and projection memos.
    let snaps: Vec<String> = sqlx::query_scalar("SELECT id FROM snapshots WHERE project_id = $1")
        .bind(project)
        .fetch_all(&mut *c)
        .await?;
    for s in snaps {
        insert_hex(&mut r.known_snapshots, &s);
    }
    let origins: Vec<(String, String)> = sqlx::query_as("SELECT real_id, origin_id FROM origins WHERE project_id = $1")
        .bind(project)
        .fetch_all(&mut *c)
        .await?;
    for (real_hex, orig_hex) in origins {
        if let (Ok(real), Ok(orig)) = (ObjectId::from_hex(&real_hex), ObjectId::from_hex(&orig_hex)) {
            r.origins.insert(real, orig);
        }
    }
    let projections: Vec<(String, String)> = sqlx::query_as(
        "SELECT real_id, projected_id FROM projections WHERE project_id = $1",
    )
    .bind(project)
    .fetch_all(&mut *c)
    .await?;
    for (real_hex, proj_hex) in projections {
        if let (Ok(real), Ok(proj)) = (ObjectId::from_hex(&real_hex), ObjectId::from_hex(&proj_hex)) {
            // If `real` is a standalone projection memo not in `snapshots`,
            // treat both `real` and `proj` as direct roots; otherwise `proj` is
            // walked whenever `real` is reachable!
            if !r.known_snapshots.contains(&real) {
                r.walk_objects.insert(real);
                r.walk_objects.insert(proj);
            } else {
                r.projections.entry(real).or_default().push(proj);
            }
        }
    }

    // 8. S12 `graph.changed` objects for reachable snapshots.
    let changed_rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT snapshot, changed FROM graph WHERE project_id = $1 AND changed IS NOT NULL",
    )
    .bind(project)
    .fetch_all(&mut *c)
    .await?;
    for (snap_hex, ch_hex) in changed_rows {
        if let (Ok(snap), Ok(ch)) = (ObjectId::from_hex(&snap_hex), ObjectId::from_hex(&ch_hex)) {
            r.graph_changed.insert(snap, ch);
        }
    }

    // 9. S15 `search_shards.segments` for live branches and the project-wide
    // `names` index (`branch = ''`).
    let live_branches: HashSet<String> = sqlx::query_scalar(
        "SELECT name FROM branches WHERE project_id = $1 AND hidden_for_embargo IS NULL",
    )
    .bind(project)
    .fetch_all(&mut *c)
    .await?
    .into_iter()
    .collect();
    let shard_rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT branch, segments FROM search_shards WHERE project_id = $1",
    )
    .bind(project)
    .fetch_all(&mut *c)
    .await?;
    for (branch, seg_json) in shard_rows {
        if branch.is_empty() || live_branches.contains(&branch) {
            collect_hex_ids_from_json(&seg_json, &mut r.leaf_objects);
        }
    }

    Ok(r)
}

async fn table_has_column(c: &mut PgConnection, table: &str, column: &str) -> Result<bool> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = $1 AND column_name = $2)",
    )
    .bind(table)
    .bind(column)
    .fetch_one(&mut *c)
    .await?;
    Ok(exists)
}

/// Extract any 64-character hex `ObjectId`s embedded in a JSON string or plain
/// hex value.
fn collect_hex_ids_from_json(s: &str, out: &mut HashSet<ObjectId>) {
    let s = s.trim();
    if s.len() == 64 {
        if let Ok(id) = ObjectId::from_hex(s) {
            out.insert(id);
            return;
        }
    }
    let bytes = s.as_bytes();
    let mut i = 0;
    while i + 64 <= bytes.len() {
        let slice = &bytes[i..i + 64];
        if slice.iter().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b)) {
            let before_ok = i == 0 || !bytes[i - 1].is_ascii_hexdigit();
            let after_ok = i + 64 == bytes.len() || !bytes[i + 64].is_ascii_hexdigit();
            if before_ok && after_ok {
                if let Ok(hex_str) = std::str::from_utf8(slice) {
                    if let Ok(id) = ObjectId::from_hex(hex_str) {
                        out.insert(id);
                    }
                }
                i += 64;
                continue;
            }
        }
        i += 1;
    }
}

/// Traverse the object graph starting from `roots.walk_objects`, expanding
/// snapshots (trees, parents, predecessors, S11 `attempts`, `origins`,
/// `projections`, S12 `graph.changed`), trees (subtrees, blobs, sealed blobs,
/// conflicts), and annotated tags (`Atag`).
async fn walk_reachable(hub: &Arc<Hub>, project: i64, roots: &DbRoots) -> Result<HashSet<ObjectId>> {
    let mut reachable: HashSet<ObjectId> = roots.leaf_objects.clone();
    let mut queue: VecDeque<ObjectId> = roots.walk_objects.iter().copied().collect();

    while let Some(id) = queue.pop_front() {
        if builtin(&id).is_some() || !reachable.insert(id) {
            continue;
        }
        // If `id` is a real snapshot with an origin, projection memos, or S12
        // `graph.changed` object, enqueue those too.
        if let Some(&orig) = roots.origins.get(&id) {
            if !reachable.contains(&orig) {
                queue.push_back(orig);
            }
        }
        if let Some(projs) = roots.projections.get(&id) {
            for &p in projs {
                if !reachable.contains(&p) {
                    queue.push_back(p);
                }
            }
        }
        if let Some(&ch) = roots.graph_changed.get(&id) {
            reachable.insert(ch);
        }

        hub.limits.derive_turn().await;
        let cost = hub.objects.read_cost(project, &id, 0).await.unwrap_or(4096);
        let _ra = ReadAhead::wait(cost).await;
        let Some(raw) = hub.objects.get(project, &id).await.map_err(Error::Other)? else {
            continue;
        };
        let Ok(obj) = Object::decode(&raw) else {
            // Derived object (such as S12 `Changed` or S15 `Segment`): leaf.
            continue;
        };
        drop(raw);
        drop(_ra);

        match obj {
            Object::Snapshot(s) => {
                if !reachable.contains(&s.tree) {
                    queue.push_back(s.tree);
                }
                for p in s.parents {
                    if !reachable.contains(&p) {
                        queue.push_back(p);
                    }
                }
                for pred in s.predecessors {
                    if !reachable.contains(&pred) {
                        queue.push_back(pred);
                    }
                }
                for att in s.attempts {
                    if !reachable.contains(&att) {
                        queue.push_back(att);
                    }
                }
            }
            Object::Tree(t) => {
                // Collect child IDs; leaf blobs/sealed objects that are known
                // leaves don't even need to be decoded!
                let mut child_dirs = Vec::new();
                for entry in &t.entries {
                    match entry.kind {
                        EntryKind::File | EntryKind::Symlink => {
                            reachable.insert(entry.id);
                        }
                        EntryKind::Dir | EntryKind::Conflict => {
                            if !reachable.contains(&entry.id) {
                                child_dirs.push(entry.id);
                            }
                        }
                    }
                }
                for child in child_dirs {
                    queue.push_back(child);
                }
            }
            Object::Conflict(c) => {
                for term in c.interleaved().flatten() {
                    reachable.insert(term.id);
                }
            }
            Object::Atag(a) => {
                if !reachable.contains(&a.target) {
                    queue.push_back(a.target);
                }
            }
            Object::Blob(_) | Object::Sealed(_) => {}
        }
    }

    Ok(reachable)
}
