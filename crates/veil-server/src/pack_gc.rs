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
//!      (and, for GC rewrites, that no root written since the mark names an
//!      object they drop: `roots_at_switch`),
//!      lists the replacement pack(s), and marks the replaced packs `DISCARDED`
//!      with `discarded_at = now_ms`;
//!   3. this server drops the replaced packs from its in-memory map
//!      ([`crate::store::Objects::forget_packs`]), while other servers prune
//!      them on their next listing refresh or when a ranged read finds a
//!      swept pack gone;
//!   4. once `now_ms - discarded_at >= grace_ms`, the sweep deletes the
//!      discarded packs' storage objects and then their rows in `packs` (and
//!      discards stale `STAGED` uploads past `staged_grace_ms`).
//! * **Offline-only garbage collection with a retention window.** In v1,
//!   unreachable-object collection (`veil-server gc`, [`run_project`] with
//!   `run_gc: true`) runs **offline only**: every serving `veil-server` holds
//!   [`ServingLock`] (shared session advisory lock on [`SERVING_LOCK_KEY`]),
//!   and offline GC acquires [`OfflineGcFence`] (exclusive), refusing if any
//!   server is serving and refusing server start-up while GC runs. Online
//!   servers only merge small packs (`run_gc: false`) and sweep superseded
//!   packs and stale staged uploads. GC marks every object reachable from the
//!   project's live roots:
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
//!
//!   Any stored object (in a listed pack or loose in `p/<project>/…`,
//!   including superseded S15 search segments) not in the reachable set gets a
//!   `since_ms` timestamp in `unreferenced_objects` when first seen
//!   unreferenced, and is deleted only once `now_ms - since_ms >= retention_ms`
//!   (thin clones keep no server anchors). Objects referenced again have their
//!   `unreferenced_objects` rows cleared.
//! * **A switch that drops objects reads the roots again (BUG-2602).** The
//!   pass keeps what its walks reached (`Marks`). Before the switch, and
//!   in its transaction behind the root writers' gate, it reads the roots
//!   as they are then and walks from where its marks stop: what a root
//!   written since the mark reaches is kept, the rest of what the mark
//!   found is deleted. Past a bound on that walk under the gate
//!   ([`SWITCH_WALK_MAX`]), the switch deletes nothing.
//! * **Loose objects are deleted under the gate too (BUG-2621):** after the
//!   purge's commit, in chunks (`delete_loose_chunk`), each with the gate
//!   held on a session from the reading of the roots to the GC epoch's
//!   raise after the last delete.
//! * **An entry's kind is a claim (BUG-2622):** what a tree names as a file
//!   is kept as a leaf and not read, and an object so named that the walk
//!   also meets as a directory or a root is read and expanded.

use std::{
    collections::{BTreeSet, HashMap, HashSet, VecDeque},
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

/// Maximum number of source packs one background merge pass takes
/// ([`maybe_schedule`]): past [`MAX_PACKS_PER_RUN`], only while the batch
/// stays within [`MAX_MERGED_BYTES`] (one merged pack). BUG-2462: a push
/// lists about two packs, so at 1,500 pushes a second one project lists
/// 3,000 a second, and passes of 64 packs fell behind (each pass also
/// lists every listed pack): its packs grew to 147,000 in a minute and a
/// half, and every lookup walked them.
pub const BACKGROUND_PACKS_PER_RUN: usize = 4096;

/// Storage requests one merge or sweep pass makes at once (BUG-2462: one
/// after another, a pass of 64 packs took 110 ms on MinIO): reads of packs
/// at most [`pack::FIRST_READ`] long (index and entries in one request;
/// a larger pack's index alone), range reads together at most
/// [`COPY_SPAN`] bytes, deletes.
const AT_ONCE: usize = 32;

/// A size class of small packs spans a factor of 2^`TIER_BITS` (16) in
/// bytes ([`Options::size_tiers`]): merging [`TIER_MIN_PACKS`] to
/// [`MAX_PACKS_PER_RUN`] packs of one class makes a pack one or two classes
/// up, so an object is copied about once a class (4 or 5 times from a
/// 1 KB push to [`SMALL_PACK_BYTES`]), and fewer than `TIER_MIN_PACKS`
/// packs of each class are left listed.
pub const TIER_BITS: u32 = 4;

/// The fewest packs of one size class a background merge merges.
pub const TIER_MIN_PACKS: usize = 16;

/// Maximum bytes read in a single storage range request when copying entries
/// from a source pack during merge/GC.
const COPY_SPAN: u64 = 2 << 20;

/// Default grace period before a `DISCARDED` pack's storage object and row are
/// deleted (`storage-and-cost.md` §8: 15 minutes — generous enough that
/// concurrent readers finish without cross-server coordination, accepting
/// brief duplicate pack storage instead of delicate reader tracking).
pub const DEFAULT_PACK_GRACE_MS: i64 = 900_000;

/// Default grace period before an uncommitted `STAGED` upload pack is
/// considered abandoned and discarded (`storage-and-cost.md` §8).
pub const DEFAULT_STAGED_GRACE_MS: i64 = 3_600_000;

/// Default retention window for unreferenced objects (`storage-and-cost.md`
/// §8: thin clones keep no server anchors, and racing pushes may reference
/// recently uploaded or probed objects).
pub const DEFAULT_RETENTION_WINDOW_MS: i64 = 3_600_000;

/// The most objects and staged upload indexes a switch that drops objects
/// reads from the store while it holds the root writers' gate (BUG-2602):
/// what the roots written since its pass last read them reach. Past it the
/// switch gives way (deletes nothing), as it does for any root write before
/// BUG-2602.
pub const SWITCH_WALK_MAX: usize = 256;

/// The longest those reads may take ([`SWITCH_WALK_MAX`]): they may wait
/// on budgets that requests waiting for the switch hold, so past it the
/// switch gives way.
pub const SWITCH_WALK_TIME: std::time::Duration = std::time::Duration::from_secs(1);

/// The most loose objects a pass deletes from the store in one hold of the
/// root writers' gate (BUG-2621, `delete_loose_chunk`), `AT_ONCE` at a
/// time.
pub const LOOSE_DELETE_CHUNK: usize = 256;

/// How long one chunk's deletes of loose objects go on starting new
/// batches ([`LOOSE_DELETE_CHUNK`], `AT_ONCE` a batch): looked at between
/// batches, never inside one (a batch is joined to its end, however long
/// the store takes). Past it the rest are left for the next pass.
pub const LOOSE_DELETE_TIME: std::time::Duration = std::time::Duration::from_secs(10);

/// The most rounds a pass reads the roots again before a switch, outside
/// its transaction ([`catch_up`]): each costs what was written during the
/// one before.
const CATCH_UP_ROUNDS: usize = 6;

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
    /// Optional hook invoked right before GC verifies `RefStamp` and switches
    /// packs / deletes loose objects (for deterministic race tests).
    pub before_switch: Option<SwitchHook>,
    /// Optional hook invoked after the switch that drops loose objects has
    /// committed and before the first of them is deleted from the store
    /// (for a deterministic test of that window, BUG-2621).
    pub before_loose_delete: Option<SwitchHook>,
    /// Optional hook invoked in a chunk of loose deletes, once it holds the
    /// root writers' gate and has read the roots, before its first delete
    /// (for a deterministic test of a writer that waits for it, BUG-2621).
    pub during_loose_delete: Option<SwitchHook>,
    /// Optional failures of a pass's store requests under a switch's lock
    /// (for tests).
    pub fault: Option<Fault>,
    /// Merge small packs by size class ([`TIER_BITS`]): only packs of one
    /// class, the class with the most packs of those with at least
    /// `min_packs_to_merge` (the background merges, BUG-2230; the most, not
    /// the smallest, BUG-2462). Without it the smallest small
    /// packs are merged together whatever their sizes, so a merged pack
    /// that is still small is copied again by every later pass until it
    /// passes `small_pack_bytes`.
    pub size_tiers: bool,
}

/// Where a test's [`Fault`] is asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultPoint {
    /// Before the walk of a switch's transaction reads an object from the
    /// store (`roots_at_switch`).
    SwitchRead,
    /// Before a chunk of loose deletes deletes an object.
    LooseDelete,
    /// Before each commit of a chunk of loose deletes (its first
    /// transaction, and each try of the epoch's raise after the deletes):
    /// an error is that commit's failure.
    LooseCommit,
}

/// Async callback that may fail a store request of a GC pass (for tests of
/// what a failure in the middle of a switch leaves): asked at each
/// [`FaultPoint`] with the object; an error it answers is that request's.
#[derive(Clone)]
pub struct Fault(pub Arc<dyn Fn(FaultPoint, ObjectId) -> FaultAnswer + Send + Sync>);

/// What a [`Fault`] answers: `Ok` lets the request go on.
pub type FaultAnswer = std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>>;

impl std::fmt::Debug for Fault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Fault(..)")
    }
}

/// Async callback invoked right before GC verifies `RefStamp` and commits a switch.
#[derive(Clone)]
pub struct SwitchHook(
    pub Arc<dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> + Send + Sync>,
);

impl std::fmt::Debug for SwitchHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SwitchHook(..)")
    }
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
            before_switch: None,
            before_loose_delete: None,
            during_loose_delete: None,
            fault: None,
            size_tiers: false,
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

    /// Options for a pass that only sweeps (BUG-2280, [`schedule_sweep`]):
    /// it merges nothing and drops no object.
    pub fn sweep_only() -> Self {
        Options {
            min_packs_to_merge: usize::MAX,
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
    /// Projects with a background merge task on this server, each with
    /// whether a push listed a pack since the task last counted (it counts
    /// again before it stops).
    active: Mutex<HashMap<i64, bool>>,
    pub runs: AtomicU64,
    /// Background merge passes that merged packs (for tests).
    pub background_merges: AtomicU64,
    /// Projects with a sweeper task on this server ([`schedule_sweep`]),
    /// each with whether it was asked again since it last looked.
    sweeping: Mutex<HashMap<i64, bool>>,
    /// Sweeper passes that deleted or discarded packs (for tests).
    pub sweeps: AtomicU64,
}

/// The least time between two counts of a project's small packs by one
/// server's background task while nothing is to merge: a push that lists a
/// pack meanwhile is counted when the gap ends, so the last pushes of a
/// burst are never left uncounted, and under steady pushes the count runs
/// at most once a gap, not once a push.
pub const CHECK_GAP: std::time::Duration = std::time::Duration::from_millis(500);

/// A push listed packs in `project` (BUG-2230): merge its small listed packs
/// in the background once they reach [`MERGE_MIN_PACKS`]. Non-blocking. At
/// most one task per project on this server: a push while it runs only
/// marks the project to be counted again. The task runs merge-only passes
/// ([`Options`] with `run_gc: false`: no object is dropped, so the switch
/// takes neither the GC epoch row nor the root writers' gate and never
/// waits for, or holds up, a push or a landing's transaction) by size
/// class ([`Options::size_tiers`]: the class with the most packs of those
/// with at least [`TIER_MIN_PACKS`], at most [`BACKGROUND_PACKS_PER_RUN`]
/// of them a pass, their storage requests `AT_ONCE` at a time),
/// one after another while one merged, each under the project's advisory
/// lock (one server at a time; another server's run makes this one's a
/// skip), a derive worker permit and S24's shedding (`derive_turn` before
/// each step). The old packs stay listed until the merged pack and its row
/// are durable, and stay stored for [`DEFAULT_PACK_GRACE_MS`] after.
pub fn maybe_schedule(hub: &Arc<Hub>, project: i64) {
    {
        let mut active = hub.pack_gc.active.lock().unwrap();
        if let Some(again) = active.get_mut(&project) {
            *again = true;
            return;
        }
        active.insert(project, false);
    }
    let hub = hub.clone();
    tokio::spawn(async move {
        loop {
            let merged = merge_small_packs(&hub, project).await;
            if !merged {
                tokio::time::sleep(CHECK_GAP).await;
            }
            let mut active = hub.pack_gc.active.lock().unwrap();
            let again = active.entry(project).or_insert(false);
            if !merged && !*again {
                active.remove(&project);
                return;
            }
            *again = false;
        }
    });
}

/// In [`crate::store::ObjectLayout::Objects`], merge a project's leftover
/// small packs once when its listing is loaded and holds at least
/// [`MERGE_MIN_PACKS`] small packs (`object-layout.md` §5.1).
pub fn wire_leftover_merges(hub: &Arc<Hub>) {
    if hub.objects.layout() != crate::store::ObjectLayout::Objects {
        return;
    }
    let weak = Arc::downgrade(hub);
    hub.objects.packs().set_leftover_merge(Arc::new(move |project| {
        if let Some(hub) = weak.upgrade() {
            maybe_schedule(&hub, project);
        }
    }));
}

/// One background merge-only pass on `project` if its small listed packs
/// reach [`MERGE_MIN_PACKS`]: whether it merged any (so another may follow).
async fn merge_small_packs(hub: &Arc<Hub>, project: i64) -> bool {
    const _: () = assert!(LISTED == 1);
    // `state = 1` (LISTED) is written literally so the partial index
    // `packs_listed` (migration 41) serves it under a generic plan too.
    let count: i64 = match sqlx::query_scalar(
        "SELECT count(*) FROM packs WHERE project_id = $1 AND state = 1 AND size <= $2",
    )
    .bind(project)
    .bind(SMALL_PACK_BYTES as i64)
    .fetch_one(&hub.derive.db)
    .await
    {
        Ok(n) => n,
        Err(_) => return false,
    };
    if (count as usize) < MERGE_MIN_PACKS {
        return false;
    }
    // In `objects` mode no push lists packs to fill intermediate size classes
    // later: merge leftover small packs across classes in one pass.
    let opts = if hub.objects.layout() == crate::store::ObjectLayout::Objects {
        Options {
            max_packs_per_run: BACKGROUND_PACKS_PER_RUN,
            ..Options::merge_only()
        }
    } else {
        Options {
            min_packs_to_merge: TIER_MIN_PACKS,
            max_packs_per_run: BACKGROUND_PACKS_PER_RUN,
            run_gc: false,
            size_tiers: true,
            ..Options::default()
        }
    };
    let res = run_project(hub, project, &opts).await;
    match res {
        Ok(r) if !r.skipped && r.packs_merged > 0 => {
            hub.pack_gc.background_merges.fetch_add(1, Ordering::Relaxed);
            // The packs it replaced are deleted once their grace period
            // has passed, whether or not anything pushes again (BUG-2280).
            schedule_sweep(hub, project);
            true
        }
        _ => false,
    }
}

/// The longest a sweeper ([`schedule_sweep`]) waits before it looks at its
/// project again, and its wait after a pass that swept nothing (skipped:
/// another server's pass holds the project's lock).
pub const SWEEP_RECHECK: std::time::Duration = std::time::Duration::from_secs(10);

/// How often a server looks for projects with packs to sweep
/// ([`sweep_scan`]), the first time at start-up.
pub const SWEEP_SCAN: std::time::Duration = std::time::Duration::from_secs(600);

/// Sweep `project`'s packs as each becomes due, until none is left
/// (BUG-2280): packs a merge replaced (`DISCARDED`, once
/// [`DEFAULT_PACK_GRACE_MS`] has passed since), a merge's staged pack
/// that no merge holds (an interrupted one's: at once) and an upload
/// staged and never listed (after [`DEFAULT_STAGED_GRACE_MS`]).
/// Non-blocking; at most one task per project on this server (a call
/// while it runs makes it look again before it stops). Each pass is
/// [`Options::sweep_only`] through [`run_project`]: the project's advisory
/// lock (another server's pass, or a merge, makes it a skip, tried again
/// after [`SWEEP_RECHECK`]), a derive worker permit and S24's shedding,
/// and only `sweep_staged` and `sweep_discarded`, which delete nothing
/// but rows they find `DISCARDED` past the grace period (a discarded row
/// never turns listed) and discard only rows still `STAGED`. The task
/// looks again at least every [`SWEEP_RECHECK`], so it never sleeps past
/// what another server swept or discarded meanwhile; after each pass it
/// ran it calls [`maybe_schedule`], so a background merge skipped while
/// the pass held the lock is not left undone.
pub fn schedule_sweep(hub: &Arc<Hub>, project: i64) {
    {
        let mut sweeping = hub.pack_gc.sweeping.lock().unwrap();
        if let Some(again) = sweeping.get_mut(&project) {
            *again = true;
            return;
        }
        sweeping.insert(project, false);
    }
    let hub = hub.clone();
    tokio::spawn(async move {
        loop {
            let wait = match sweep_due(&hub, project).await {
                Ok(None) => {
                    let mut sweeping = hub.pack_gc.sweeping.lock().unwrap();
                    let again = sweeping.entry(project).or_insert(false);
                    if !*again {
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
                    } else {
                        let r = run_project(&hub, project, &Options::sweep_only()).await;
                        if matches!(&r, Ok(r) if !r.skipped) {
                            // A background merge that found the lock held
                            // by this pass counts again.
                            maybe_schedule(&hub, project);
                        }
                        match r {
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
            tokio::time::sleep(wait).await;
        }
    });
}

/// When `project` next has a pack to sweep ([`schedule_sweep`]), in
/// milliseconds since the epoch; `None`: nothing to sweep. A discarded
/// row with no `discarded_at` (none is written so) is never due, as in
/// `sweep_discarded`.
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

/// Every [`SWEEP_SCAN`], the first time at start-up, start a sweeper
/// ([`schedule_sweep`]) on every project with packs to sweep (BUG-2280):
/// those a server stopped before sweeping (a merge interrupted, or the
/// replaced packs of one whose server stopped within their grace period)
/// are swept whether or not the project is pushed to again. Reads only
/// the rows of packs not listed (`packs_unlisted`, migration 40).
pub async fn sweep_scan(hub: Arc<Hub>, mut stop: tokio::sync::watch::Receiver<bool>) {
    loop {
        for project in projects_to_sweep(&hub).await.unwrap_or_default() {
            schedule_sweep(&hub, project);
        }
        tokio::select! {
            _ = tokio::time::sleep(SWEEP_SCAN) => {}
            _ = stop.changed() => return,
        }
    }
}

/// The projects [`sweep_scan`] starts a sweeper on: those with a pack
/// discarded, a merge's pack staged, or an upload staged for longer than
/// [`DEFAULT_STAGED_GRACE_MS`].
pub async fn projects_to_sweep(hub: &Hub) -> Result<Vec<i64>> {
    let cutoff = veil_core::now_millis().saturating_sub(DEFAULT_STAGED_GRACE_MS);
    // `state <> 1` written out (`LISTED`), so the partial index serves it.
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

/// Two-integer PostgreSQL session advisory lock (`"veil"`, `-"gcof"`) held
/// shared by every serving `veil-server` on a dedicated connection, and
/// exclusively by offline garbage collection (`veil-server gc`, or
/// [`run_project`] with `run_gc: true`).
///
/// `k2 < 0` keeps it disjoint from [`crate::landing::lease_lock`]'s
/// two-integer keys (`k2 = (epoch & 0x7fff_ffff) >= 0`), and two-integer keys
/// occupy a separate `pg_locks` namespace (`objsubid = 2`) from every
/// one-`bigint` advisory lock in the server.
pub const SERVING_LOCK_KEY: (i32, i32) = (0x7665_696c, -0x6763_6f66);

/// Shared session advisory lock held on a dedicated database connection for
/// the whole serving lifetime of a `veil-server`, preventing offline garbage
/// collection from running concurrently and refusing server start-up while
/// `veil-server gc` holds [`OfflineGcFence`].
pub struct ServingLock {
    conn: PgConnection,
}

impl ServingLock {
    /// Acquire the shared serving session lock without waiting, or fail with
    /// a clear error if offline garbage collection holds [`OfflineGcFence`].
    pub async fn acquire(db: &sqlx::PgPool) -> anyhow::Result<ServingLock> {
        use sqlx::Connection as _;
        let opts = (*db.connect_options()).clone().application_name("veil-server-serving");
        let mut conn = PgConnection::connect_with(&opts).await?;
        let (k1, k2) = SERVING_LOCK_KEY;
        let got: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock_shared($1, $2)")
            .bind(k1)
            .bind(k2)
            .fetch_one(&mut conn)
            .await?;
        if !got {
            let _ = conn.close().await;
            anyhow::bail!(
                "cannot start veil-server while offline garbage collection (`veil-server gc`) is running on this database"
            );
        }
        Ok(ServingLock { conn })
    }

    /// Close the dedicated session connection, releasing the shared lock at
    /// once on PostgreSQL.
    pub async fn release(self) {
        use sqlx::Connection as _;
        let _ = self.conn.close().await;
    }
}

/// Exclusive session advisory lock held on a dedicated database connection
/// while offline garbage collection runs, refusing if any `veil-server` holds
/// [`ServingLock`] (or another offline GC is running) and preventing any
/// `veil-server` from starting until GC finishes.
pub struct OfflineGcFence {
    conn: PgConnection,
}

impl OfflineGcFence {
    /// Acquire the exclusive offline-GC session lock without waiting, or fail
    /// with a `409 Conflict` error if any server is serving the database (or
    /// another offline GC holds the fence).
    pub async fn acquire(db: &sqlx::PgPool) -> Result<OfflineGcFence> {
        use sqlx::Connection as _;
        let opts = (*db.connect_options()).clone().application_name("veil-server-gc");
        let mut conn = PgConnection::connect_with(&opts).await.map_err(sqlx::Error::from)?;
        let (k1, k2) = SERVING_LOCK_KEY;
        let got: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1, $2)")
            .bind(k1)
            .bind(k2)
            .fetch_one(&mut conn)
            .await?;
        if !got {
            let _ = conn.close().await;
            return Err(Error::conflict(
                "cannot run garbage collection while a server is serving this database (or another `veil-server gc` is running); stop all veil-server instances first",
            ));
        }
        Ok(OfflineGcFence { conn })
    }

    /// Close the dedicated session connection, releasing the exclusive lock at
    /// once on PostgreSQL.
    pub async fn release(self) {
        use sqlx::Connection as _;
        let _ = self.conn.close().await;
    }
}

/// Read-only inspection report for `veil-server gc --dry-run` on one project.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DryRunReport {
    /// Stored objects unreferenced now and not yet recorded in `unreferenced_objects`.
    pub newly_unreferenced: usize,
    /// Stored unreferenced objects still inside `retention_window_ms`.
    pub unreferenced_in_window: usize,
    /// Expired unreferenced loose objects that a collection pass would delete.
    pub loose_objects_to_delete: usize,
    /// Expired unreferenced packed objects that pack rewrites would drop.
    pub packed_objects_to_delete: usize,
    /// Expired unreferenced `snapshots` rows whose database records would be purged.
    pub expired_snapshots_to_purge: usize,
    /// Listed packs that would be merged or rewritten (small packs or packs holding expired objects).
    pub packs_to_rewrite: usize,
    /// `DISCARDED` packs that would be deleted from storage and `packs`.
    pub discarded_packs_to_sweep: usize,
    /// Stale `STAGED` packs that would be discarded and deleted.
    pub staged_packs_to_sweep: usize,
}

async fn resolve_target_projects(db: &sqlx::PgPool, project_name: Option<&str>) -> Result<Vec<(i64, String)>> {
    match project_name {
        Some(name) => {
            let row: Option<(i64, String)> = sqlx::query_as("SELECT id, name FROM projects WHERE name = $1")
                .bind(name)
                .fetch_optional(db)
                .await?;
            match row {
                Some(p) => Ok(vec![p]),
                None => Err(Error::not_found(format!("project '{name}' does not exist"))),
            }
        }
        None => Ok(sqlx::query_as("SELECT id, name FROM projects ORDER BY id").fetch_all(db).await?),
    }
}

/// Run offline garbage collection across `project_name` (`None`: every project
/// in the database), holding [`OfflineGcFence`] across the whole run.
pub async fn run_offline(hub: &Arc<Hub>, project_name: Option<&str>, opts: &Options) -> Result<Vec<(String, Report)>> {
    let fence = OfflineGcFence::acquire(&hub.db).await?;
    let res: Result<Vec<(String, Report)>> = async {
        let projects = resolve_target_projects(&hub.db, project_name).await?;
        let mut out = Vec::with_capacity(projects.len());
        for (pid, name) in projects {
            let listed_count: i64 = sqlx::query_scalar("SELECT count(*) FROM packs WHERE project_id = $1 AND state = 1")
                .bind(pid)
                .fetch_one(&hub.db)
                .await?;
            let max_passes = (listed_count.max(0) as usize).saturating_add(2).max(16);
            let mut total = Report::default();
            for _ in 0..max_passes {
                let r = run_locked(hub, pid, opts, true).await?;
                if r.skipped {
                    total.skipped = true;
                    break;
                }
                total.packs_merged += r.packs_merged;
                total.packs_written += r.packs_written;
                total.objects_kept += r.objects_kept;
                total.packed_objects_deleted += r.packed_objects_deleted;
                total.loose_objects_deleted += r.loose_objects_deleted;
                total.discarded_packs_swept += r.discarded_packs_swept;
                total.staged_packs_swept += r.staged_packs_swept;
                if r.packs_merged == 0 && r.loose_objects_deleted == 0 && r.discarded_packs_swept == 0 {
                    break;
                }
            }
            out.push((name, total));
        }
        Ok(out)
    }
    .await;
    fence.release().await;
    res
}

/// Inspect what offline garbage collection would delete across `project_name`
/// (`None`: every project in the database), holding [`OfflineGcFence`] across
/// the whole inspection without modifying the database or object store.
pub async fn dry_run_offline(
    hub: &Arc<Hub>,
    project_name: Option<&str>,
    opts: &Options,
) -> Result<Vec<(String, DryRunReport)>> {
    let fence = OfflineGcFence::acquire(&hub.db).await?;
    let res: Result<Vec<(String, DryRunReport)>> = async {
        let projects = resolve_target_projects(&hub.db, project_name).await?;
        let mut out = Vec::with_capacity(projects.len());
        for (pid, name) in projects {
            out.push((name, dry_run_project(hub, pid, opts).await?));
        }
        Ok(out)
    }
    .await;
    fence.release().await;
    res
}

async fn dry_run_project(hub: &Arc<Hub>, project: i64, opts: &Options) -> Result<DryRunReport> {
    let now_ms = opts.now_ms();
    let staged_cutoff = now_ms.saturating_sub(opts.staged_grace_ms.max(0));
    let staged_packs_to_sweep: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM packs WHERE project_id = $1 AND state = 0 AND (person_id IS NULL OR created_at <= $2)",
    )
    .bind(project)
    .bind(staged_cutoff)
    .fetch_one(&hub.db)
    .await?;

    let discarded_cutoff = now_ms.saturating_sub(opts.pack_grace_ms.max(0));
    let discarded_packs_to_sweep: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM packs WHERE project_id = $1 AND state = $2 AND COALESCE(discarded_at, $4) <= $3",
    )
    .bind(project)
    .bind(DISCARDED)
    .bind(discarded_cutoff)
    .bind(now_ms)
    .fetch_one(&hub.db)
    .await?;

    let (stamp, roots) = read_stamp_and_roots(hub, project, None).await?;
    let (roots, uploads) = roots.expect("read with no stamp to compare");
    let mut marks = Marks { leaves: roots.leaf_objects.clone(), fault: opts.fault.clone(), ..Marks::default() };
    walk_from_roots(hub, project, roots.walk_objects.iter().copied(), &mut marks, &roots, None).await?;

    let store = hub.objects.blob_store();
    let bound = hub.objects.index_bound();
    let surviving_staged: HashSet<String> = sqlx::query_scalar(
        "SELECT name FROM packs WHERE project_id = $1 AND state = 0 AND person_id IS NOT NULL AND created_at > $2",
    )
    .bind(project)
    .bind(staged_cutoff)
    .fetch_all(&hub.db)
    .await?
    .into_iter()
    .collect();
    marks.uploads = uploads.into_iter().filter(|name| !surviving_staged.contains(name)).collect();
    for staged_name in &stamp.staged_packs {
        if surviving_staged.contains(staged_name) {
            marks.read_upload(hub, project, staged_name).await?;
        }
    }

    let listed_rows: Vec<(String, i64, i64, i64)> = sqlx::query_as(
        "SELECT name, size, objects, created_at FROM packs WHERE project_id = $1 AND state = 1 ORDER BY created_at, name",
    )
    .bind(project)
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

    let mut packed_stored: HashSet<ObjectId> = HashSet::new();
    let mut all_stored: HashSet<ObjectId> = HashSet::new();
    let mut pack_dead_counts: Vec<(usize, bool)> = Vec::with_capacity(listed.len());
    let mut pack_entries: Vec<Vec<ObjectId>> = Vec::with_capacity(listed.len());
    for p in &listed {
        let k = pack::key(project, &p.name);
        let mut ids = Vec::new();
        if let Some(held) = pack::read_index(&**store, &k, bound).await.map_err(Error::Other)? {
            for (id, _) in held.index.iter() {
                packed_stored.insert(*id);
                all_stored.insert(*id);
                ids.push(*id);
            }
        }
        pack_entries.push(ids);
    }

    let prefix = format!("p/{project}/");
    let keys = store.list(&prefix).await.map_err(Error::Other)?;
    let mut loose_ids: HashSet<ObjectId> = HashSet::new();
    for k in keys {
        let Some(rest) = k.strip_prefix(&prefix) else { continue };
        if rest.starts_with("pack/") {
            continue;
        }
        let parts: Vec<&str> = rest.split('/').collect();
        if parts.len() == 2 && parts[0].len() == 2 && parts[1].len() == 62 {
            let hex_str = format!("{}{}", parts[0], parts[1]);
            if let Ok(id) = ObjectId::from_hex(&hex_str) {
                all_stored.insert(id);
                loose_ids.insert(id);
            }
        }
    }

    let existing_unreferenced: Vec<(String, i64)> = sqlx::query_as(
        "SELECT object_id, since_ms FROM unreferenced_objects WHERE project_id = $1",
    )
    .bind(project)
    .fetch_all(&hub.db)
    .await?;

    let mut unref_map: HashMap<ObjectId, i64> = HashMap::new();
    for (hex_id, since) in existing_unreferenced {
        if let Ok(id) = ObjectId::from_hex(&hex_id) {
            if !marks.live(&id) && all_stored.contains(&id) {
                unref_map.insert(id, since);
            }
        }
    }

    let mut newly_unreferenced = 0usize;
    for id in &all_stored {
        if !marks.live(id) && !unref_map.contains_key(id) {
            unref_map.insert(*id, now_ms);
            newly_unreferenced += 1;
        }
    }

    let cutoff = now_ms.saturating_sub(opts.retention_window_ms.max(0));
    let mut expired_unreferenced: HashSet<ObjectId> = unref_map
        .iter()
        .filter_map(|(&id, &since)| (since <= cutoff).then_some(id))
        .collect();

    let mut retained_snaps: Vec<ObjectId> = Vec::new();
    for &s in &roots.known_snapshots {
        if marks.live(&s) {
            continue;
        }
        if !all_stored.contains(&s) {
            expired_unreferenced.insert(s);
        } else if !expired_unreferenced.contains(&s) {
            retained_snaps.push(s);
        }
    }
    if !retained_snaps.is_empty() && !expired_unreferenced.is_empty() {
        walk_from_roots(hub, project, retained_snaps, &mut marks, &roots, None).await?;
        expired_unreferenced.retain(|id| !marks.live(id));
    }

    let unreferenced_in_window = unref_map
        .keys()
        .filter(|id| !marks.live(id) && !expired_unreferenced.contains(id))
        .count();
    let loose_objects_to_delete = loose_ids.iter().filter(|id| expired_unreferenced.contains(id)).count();
    let packed_objects_to_delete = packed_stored.iter().filter(|id| expired_unreferenced.contains(id)).count();
    let expired_snapshots_to_purge = roots.known_snapshots.iter().filter(|id| expired_unreferenced.contains(id)).count();

    let small_count = listed
        .iter()
        .filter(|p| p.size <= opts.small_pack_bytes && p.objects <= opts.max_merged_objects / 2)
        .count();
    let merge_small = small_count >= opts.min_packs_to_merge;
    for (p, ids) in listed.iter().zip(&pack_entries) {
        let is_small = merge_small && p.size <= opts.small_pack_bytes && p.objects <= opts.max_merged_objects / 2;
        let has_dead = ids.iter().any(|id| expired_unreferenced.contains(id));
        pack_dead_counts.push((ids.len(), is_small || has_dead));
    }
    let packs_to_rewrite = pack_dead_counts.iter().filter(|(_, rw)| *rw).count();
    let discarded_from_rewrites = packs_to_rewrite;

    Ok(DryRunReport {
        newly_unreferenced,
        unreferenced_in_window,
        loose_objects_to_delete,
        packed_objects_to_delete,
        expired_snapshots_to_purge,
        packs_to_rewrite,
        discarded_packs_to_sweep: (discarded_packs_to_sweep.max(0) as usize)
            + if opts.pack_grace_ms <= 0 { discarded_from_rewrites } else { 0 },
        staged_packs_to_sweep: staged_packs_to_sweep.max(0) as usize,
    })
}

/// Run one bounded merge and/or garbage-collection pass on `project`.
///
/// When `opts.run_gc` is `true`, garbage collection is **offline-only**: it
/// acquires [`OfflineGcFence`] and refuses with `409 Conflict` if any
/// `veil-server` is serving the database (or another offline GC is running).
pub async fn run_project(hub: &Arc<Hub>, project: i64, opts: &Options) -> Result<Report> {
    let hub = hub.clone();
    let opts = opts.clone();
    tokio::spawn(async move { run_locked(&hub, project, &opts, false).await })
        .await
        .map_err(|e| Error::Other(e.into()))?
}

async fn run_locked(hub: &Arc<Hub>, project: i64, opts: &Options, fenced: bool) -> Result<Report> {
    let fence = if opts.run_gc && !fenced {
        Some(OfflineGcFence::acquire(&hub.db).await?)
    } else {
        None
    };
    let res = async {
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
    .await;
    if let Some(fence) = fence {
        fence.release().await;
    }
    res
}

#[derive(Clone, Debug)]
struct PackRow {
    name: Arc<str>,
    size: u64,
    objects: usize,
    created_at: i64,
}

/// Content fingerprint of every table that names GC roots or staged uploads for
/// a project (`BUG-1782`), so GC detects any concurrent insert, delete, or
/// in-place update (`change_refs` amend, `pr_revisions` push, `bisects` step,
/// `bisect_reverts` record, landing rewrite, staged upload, etc.) while
/// reachability was walked or replacement packs were written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefStamp {
    digests: Vec<(String, i64, i64, i64, i64)>,
    staged_packs: Vec<String>,
}

/// `(table_name, row_expr, extra_where)` stamped by [`read_ref_stamp`].
/// Every table GC takes roots from is here, with each of its root columns
/// in its row ([`unstamped_root_columns`] lists any that is not: BUG-1923).
const STAMP_TABLES: &[(&str, &str, &str)] = &[
    ("branches", "concat_ws(chr(31), name, target, lineage::text, COALESCE(hidden_for_embargo, ''))", ""),
    ("snapshots", "concat_ws(chr(31), id, author::text)", ""),
    ("packs", "concat_ws(chr(31), name, person_id::text, size::text, objects::text)", " AND state = $2 AND person_id IS NOT NULL"),
    ("change_refs", "concat_ws(chr(31), change_id, snapshot, created_by::text, created_at::text)", ""),
    ("landing_queue", "concat_ws(chr(31), seq::text, branch, state, stack, COALESCE(result, ''))", ""),
    ("landings", "concat_ws(chr(31), branch, lineage::text, submitted, landed, at::text)", ""),
    ("embargo_snapshots", "concat_ws(chr(31), snapshot, embargo_id)", ""),
    ("embargo_lines", "concat_ws(chr(31), embargo_id, target_branch, embargo_branch, COALESCE(released_at::text, ''), record_json)", ""),
    ("checks", "concat_ws(chr(31), snapshot, name, state, updated_at::text)", ""),
    ("tested", "concat_ws(chr(31), branch, lineage::text, snapshot, depth::text, updated_at::text)", ""),
    ("pr_revisions", "concat_ws(chr(31), pr, n::text, base, head, changes)", ""),
    ("bisects", "concat_ws(chr(31), branch, lineage::text, check_name, phase, good, bad, candidates, probes, COALESCE(culprit, ''), COALESCE(culprit_parent, ''), COALESCE(revert_snapshot, ''), updated_at::text)", ""),
    ("bisect_reverts", "concat_ws(chr(31), branch, lineage::text, culprit, check_name, ticket, COALESCE(revert_snapshot, ''), state)", ""),
    // BUG-1923: the two root tables the stamp left out. A shard's counters
    // are not in its row: only what names a segment moves the stamp.
    ("search_shards", "concat_ws(chr(31), kind, branch, line_key, segments)", ""),
    ("pr_review_rules", "checked", ""),
];

/// Error marker raised inside a root-adding transaction when the project's GC
/// epoch (`access_epochs (project_id, -1)`) moved since the caller checked its
/// objects (`BUG-1881`). Handled by `db::retry_requests` (and background worker
/// loops) by rerunning the operation from its object checks under the new epoch.
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
/// read its current value, and synchronize `hub`'s in-memory caches (`BUG-1881`).
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

/// [`read_gc_epoch`] for a push, which carries the epoch its request read
/// (`read`: the session check's `access_epochs (project, -1)`, read before
/// anything the push checks, as `read_gc_epoch` would be): taken as it is
/// once this server saw the row exist (rows are never deleted; the request
/// read 0 for a missing one, which [`guard_root_write`] would refuse), so a
/// push does not read it twice. A switch after that read fails the push's
/// guard (`GcEpochChanged`), and the request runs again, as before.
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

/// The advisory lock that queues a project's root-adding transactions and
/// GC's switch in arrival order (`"veilgcgt"` ^ `project_id`). The epoch row's
/// lock alone is what makes the switch safe, but PostgreSQL lets a new
/// `FOR SHARE` join the row's sharers ahead of a waiting `FOR UPDATE`: under
/// steady pushes GC's switch never got the row (64 writers at once: none in
/// 5 s, three times; behind this lock: 1 ms). The lock manager is fair, so
/// the switch waits only for the writers already in their transactions.
const GATE_BASE: i64 = 0x7665_696c_6763_6774;

/// One statement of a root-adding transaction, its first: wait in line with
/// GC's switch (the advisory lock, shared: writers never wait for each
/// other), then lock the project's GC epoch row `FOR SHARE` and read it. A
/// switch that committed while the statement waited is seen: the row is
/// locked and read as last committed. Binds: the project, [`gate_key`].
pub(crate) const GUARD_SQL: &str = "SELECT e.epoch FROM (SELECT pg_advisory_xact_lock_shared($2)) g, access_epochs e \
     WHERE e.project_id = $1 AND e.person_id = -1 FOR SHARE OF e";

pub(crate) fn gate_key(project: i64) -> i64 {
    GATE_BASE ^ project
}

/// Lock the project's GC epoch row `FOR SHARE` and verify it still matches
/// `expected_epoch` (`BUG-1881`), serializing every root-adding transaction
/// against GC's `FOR UPDATE` switch. It is the transaction's first
/// statement, so a writer waiting here holds no lock the switch needs.
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

/// Lock the project's GC epoch row `FOR UPDATE` at the start of a GC switch
/// transaction (`BUG-1881`), waiting for any in-flight root-adding transaction
/// before reading `read_ref_stamp` or purging records.
async fn lock_gc_epoch_tx(c: &mut PgConnection, project: i64) -> Result<()> {
    // In line with the writers first ([`GATE_BASE`]): those that come after
    // wait behind this, so the row below is free once the earlier ones end.
    sqlx::query("SELECT pg_advisory_xact_lock($1)").bind(gate_key(project)).execute(&mut *c).await?;
    let got: Option<i64> = sqlx::query_scalar(
        "SELECT epoch FROM access_epochs WHERE project_id = $1 AND person_id = -1 FOR UPDATE",
    )
    .bind(project)
    .fetch_optional(&mut *c)
    .await?;
    if got.is_none() {
        sqlx::query(
            "INSERT INTO access_epochs (project_id, person_id, epoch, changed_at) \
             VALUES ($1, -1, 0, 0) ON CONFLICT (project_id, person_id) DO NOTHING",
        )
        .bind(project)
        .execute(&mut *c)
        .await?;
        sqlx::query_scalar::<_, i64>(
            "SELECT epoch FROM access_epochs WHERE project_id = $1 AND person_id = -1 FOR UPDATE",
        )
        .bind(project)
        .fetch_one(&mut *c)
        .await?;
    }
    Ok(())
}

/// The root columns of the registry ([`OBJECT_SCHEMA_COLUMNS`]: `GcRoot` and
/// `GcConditionalLeafRoot`) that the reference stamp does not read: their
/// table is not in `STAMP_TABLES`, or its stamped row leaves the column
/// out. Empty, or GC would not give way to a row written right before its
/// switch (BUG-1923); a test holds it empty, so a root table registered
/// later cannot be left unstamped.
pub fn unstamped_root_columns() -> Vec<(&'static str, &'static str)> {
    OBJECT_SCHEMA_COLUMNS
        .iter()
        .filter(|(_, _, role)| matches!(role, SchemaColumnRole::GcRoot | SchemaColumnRole::GcConditionalLeafRoot))
        .filter(|(table, col, _)| {
            !STAMP_TABLES
                .iter()
                .any(|(t, expr, _)| t == table && expr.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).any(|word| word == *col))
        })
        .map(|&(table, col, _)| (table, col))
        .collect()
}

/// Names of all tables fingerprinted by [`project_ref_stamp`].
pub fn stamped_root_tables() -> Vec<&'static str> {
    STAMP_TABLES.iter().map(|&(t, _, _)| t).collect()
}

/// Read the current [`RefStamp`] of `project` from `db` (exposed for tests).
pub async fn project_ref_stamp(db: &sqlx::PgPool, project: i64) -> Result<RefStamp> {
    let mut conn = db.acquire().await?;
    read_ref_stamp(&mut conn, project).await
}

async fn read_ref_stamp(c: &mut PgConnection, project: i64) -> Result<RefStamp> {
    let arms: Vec<String> = STAMP_TABLES
        .iter()
        .enumerate()
        .map(|(idx, &(table, expr, extra))| {
            format!(
                "SELECT {idx}::int AS ord, '{table}'::text AS tbl, count(*)::bigint, \
                 COALESCE(bit_xor(('x' || substr(md5(e), 1, 16))::bit(64)::bigint), 0) AS coalesce, \
                 COALESCE(bit_xor(('x' || substr(md5(e), 17, 16))::bit(64)::bigint), 0) AS coalesce_2, \
                 COALESCE(mod(sum(('x' || substr(md5('s:' || e), 1, 15))::bit(60)::bigint), 1152921504606846976), 0)::bigint AS coalesce_3 \
                 FROM (SELECT {expr} AS e FROM {table} WHERE project_id = $1{extra}) s"
            )
        })
        .collect();
    let sql = format!(
        "SELECT tbl, count, coalesce, coalesce_2, coalesce_3 FROM ({}) u ORDER BY ord",
        arms.join(" UNION ALL ")
    );
    let mut digests: Vec<(String, i64, i64, i64, i64)> = sqlx::query_as(&sql)
        .bind(project)
        .bind(STAGED)
        .fetch_all(&mut *c)
        .await?;
    let staged_packs: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM packs WHERE project_id = $1 AND state = $2 AND person_id IS NOT NULL ORDER BY name",
    )
    .bind(project)
    .bind(STAGED)
    .fetch_all(&mut *c)
    .await?;

    // Also stamp optional dynamic `tags` table if present.
    if table_has_column(c, "tags", "project_id").await? {
        let tag_row: (i64, i64, i64, i64) = sqlx::query_as(
            "SELECT count(*)::bigint, \
             COALESCE(bit_xor(('x' || substr(md5(e), 1, 16))::bit(64)::bigint), 0), \
             COALESCE(bit_xor(('x' || substr(md5(e), 17, 16))::bit(64)::bigint), 0), \
             COALESCE(mod(sum(('x' || substr(md5('s:' || e), 1, 15))::bit(60)::bigint), 1152921504606846976), 0)::bigint \
             FROM (SELECT row_to_json(t)::text AS e FROM tags t WHERE project_id = $1) s",
        )
        .bind(project)
        .fetch_one(&mut *c)
        .await?;
        digests.push(("tags".to_string(), tag_row.0, tag_row.1, tag_row.2, tag_row.3));
    }

    Ok(RefStamp { digests, staged_packs })
}

async fn run_with_lock(hub: &Arc<Hub>, project: i64, opts: &Options) -> Result<Report> {
    let mut report = Report::default();
    let now_ms = opts.now_ms();

    read_gc_epoch(hub, project).await?;

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
    // `state = 1` (LISTED) literally: `packs_listed` (migration 41).
    let listed_rows: Vec<(String, i64, i64, i64)> = sqlx::query_as(
        "SELECT name, size, objects, created_at FROM packs WHERE project_id = $1 AND state = 1 ORDER BY created_at, name",
    )
    .bind(project)
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
    let (batch, complete_dead_sweep) = select_batch(hub, project, &listed, opts, gc_state.as_deref()).await?;

    if !batch.is_empty() {
        let crashed = compact_batch(
            hub,
            project,
            &batch,
            gc_state.as_ref(),
            complete_dead_sweep,
            opts,
            now_ms,
            &mut report,
        )
        .await?;
        if crashed {
            return Ok(report);
        }
    } else if let Some(gc) = &gc_state {
        if !gc.lock().await.expired_unreferenced.is_empty() {
            catch_up(hub, project, gc).await?;
        }
        if !gc.lock().await.expired_unreferenced.is_empty() {
            if let Some(hook) = &opts.before_switch {
                (hook.0)().await;
            }
            let maybe_gce: Option<i64> =
                gc_transaction(hub, |c| {
                    let (hub, gc) = (hub.clone(), gc.clone());
                    Box::pin(async move {
                        lock_gc_epoch_tx(c, project).await?;
                        let mut gc = gc.lock().await;
                        if !roots_at_switch(&hub, project, c, &mut gc).await? || gc.expired_unreferenced.is_empty() {
                            return Ok(None);
                        }
                        let expired_hexes: Vec<String> = gc.expired_unreferenced.iter().map(ObjectId::hex).collect();
                        purge_expired_db_records(&hub, c, project, &expired_hexes).await?;
                        for chunk in expired_hexes.chunks(500) {
                            sqlx::query(
                                "DELETE FROM unreferenced_objects WHERE project_id = $1 AND object_id = ANY($2)",
                            )
                            .bind(project)
                            .bind(chunk)
                            .execute(&mut *c)
                            .await?;
                        }
                        let gce = bump_gc_epoch_tx(c, project).await?;
                        Ok(Some(gce))
                    })
                })
                .await?;
            if let Some(gce) = maybe_gce {
                notify_gc_epoch(hub, project, gce).await;
            }
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
    /// `unreferenced_objects` is `<= now_ms - retention_window_ms`: what
    /// the pass may delete. It only shrinks ([`catch_up_round`]), and holds
    /// nothing of `marks`.
    expired_unreferenced: HashSet<ObjectId>,
    /// Fingerprint of the roots `marks` last covered: read in one snapshot
    /// with them, or under a switch's lock.
    stamp: RefStamp,
    /// What the pass's walks reached.
    marks: Marks,
}

/// What a GC pass's walks know of the project's objects (BUG-2602).
#[derive(Default)]
struct Marks {
    /// The closed set: every object a walk read and expanded. Every object
    /// a member names is in it too, or in `leaves` or `unread`, so a later
    /// walk stops at a member: nothing behind it is unknown. It only grows.
    reachable: HashSet<ObjectId>,
    /// Objects named as leaves and not read: what a tree's file or symlink
    /// entry or a conflict's term names, a `graph.changed` object, a
    /// search segment. Kept, and **not taken for expanded** (BUG-2622): an
    /// entry's kind is a claim of whoever wrote the tree, so a walk that
    /// meets one of them as a directory, a snapshot or a root reads it and
    /// expands what it is.
    leaves: HashSet<ObjectId>,
    /// Ids a walk reached and could not read: not stored then (a
    /// predecessor never pushed, the tree of a signed origin). What they
    /// name is unknown, so they are not in `reachable`; a walk does not
    /// read one again (a project holds many, each a miss) unless a client
    /// upload the pass read holds it (`staged_ids`; [`catch_up_round`]).
    /// What such an id is (measured in the tests' projects: 5 to 40 each):
    /// a predecessor never pushed (a client's snapshot), or the tree of a
    /// projection (a memo's snapshot, whose trees the server derives when
    /// asked). A client's object comes to be stored by an upload, which is
    /// read here. A snapshot the server makes (a landing, a merge, an API
    /// commit) holds its own time and the server's signature, so its id is
    /// never one already named. What is left is derived data the server
    /// stores again (a projection's objects): GC follows that from
    /// `projections` as read and purges it with its objects, and does not
    /// read it again here (BUG-2623 is that class's open bug).
    unread: HashSet<ObjectId>,
    /// The client uploads (rows of `packs` with a person) the pass knows:
    /// those listed or discarded when the marks were made (the walk read
    /// what they hold) and those whose index was read since (a pack's
    /// bytes never change), and
    uploads: HashSet<String>,
    /// the objects of the uploads read: kept, never expanded, so not in
    /// `reachable` (a root that names one is walked).
    staged_ids: HashSet<ObjectId>,
    /// A test's failures of the reads a switch's walk makes
    /// ([`Options::fault`]).
    fault: Option<Fault>,
}

impl Marks {
    /// Reached by a walk (read, named as a leaf, or not stored), or in an
    /// upload read.
    fn live(&self, id: &ObjectId) -> bool {
        self.reachable.contains(id) || self.leaves.contains(id) || self.staged_ids.contains(id) || self.unread.contains(id)
    }

    /// Read the index of the client upload `name` if it was not yet: its
    /// objects are kept. Whether the store was read. (An upload recorded
    /// and not written yet has no index: read again next time.)
    async fn read_upload(&mut self, hub: &Arc<Hub>, project: i64, name: &str) -> Result<bool> {
        if self.uploads.contains(name) {
            return Ok(false);
        }
        let k = pack::key(project, name);
        if let Some(held) = pack::read_index(&**hub.objects.blob_store(), &k, hub.objects.index_bound()).await.map_err(Error::Other)? {
            self.staged_ids.extend(held.index.iter().map(|(id, _)| *id));
            self.uploads.insert(name.to_string());
        }
        Ok(true)
    }
}

/// The names of `project`'s client uploads, in any state (staged, listed,
/// replaced by a merge and not swept yet: no row of a pack is deleted
/// while a pass holds the project's lock).
async fn upload_names(c: &mut PgConnection, project: i64) -> Result<Vec<String>> {
    Ok(sqlx::query_scalar("SELECT name FROM packs WHERE project_id = $1 AND person_id IS NOT NULL")
        .bind(project)
        .fetch_all(&mut *c)
        .await?)
}

/// The reference stamp and the roots of `project`, of one moment of the
/// database (one snapshot: no row is in the stamp and missing from the
/// roots). With `known`, a stamp equal to it answers no roots: they are
/// the ones it was read with.
async fn read_stamp_and_roots(hub: &Hub, project: i64, known: Option<&RefStamp>) -> Result<(RefStamp, Option<(DbRoots, Vec<String>)>)> {
    let known = known.cloned();
    crate::db::transaction(&hub.db, crate::db::Isolation::Snapshot, |c| {
        let known = known.clone();
        Box::pin(async move {
            let stamp = read_ref_stamp(c, project).await?;
            if known.as_ref() == Some(&stamp) {
                return Ok((stamp, None));
            }
            let roots = collect_db_roots(c, project).await?;
            let uploads = upload_names(c, project).await?;
            Ok((stamp, Some((roots, uploads))))
        })
    })
    .await
}

/// One round of a pass's catching up with the roots (BUG-2602): `roots`
/// and their `stamp`, read after the marks were made (in one snapshot, or
/// under a switch's lock). Walks what they reach that the marks do not
/// hold, and takes everything reached or kept out of the candidates
/// (`expired_unreferenced`), so that afterwards no candidate is reachable
/// from `roots`:
/// * every walk root, and every `snapshots` row that is not a candidate
///   (BUG-1780: a row that stays keeps its whole closure), is walked,
///   stopping at the closed set;
/// * what a walk could not read before, and a client upload made since
///   (`uploads`: every upload's name) holds, is walked;
/// * the `origins` and `projections` rows of the snapshots already
///   reached are followed as they are now, as those of the snapshots the
///   walk newly reaches;
/// * search segments, `graph.changed` objects and the objects of every
///   upload made since the marks are kept (one index read for each
///   upload not read yet).
///
/// `limit`: the most store reads it may make (under the lock; `None`
/// outside, where it also yields to requests). Answers the reads it made,
/// or `None` past the limit. **Past the limit, or on an error, the walk is
/// unfinished and the marks no longer closed** (an object it read is in
/// the set, what that object names is not: a later walk would stop at it),
/// so the candidates are emptied: the pass deletes nothing more, whatever
/// runs after (a switch's transaction is run again on an error that may
/// pass: BUG-2602's review).
async fn catch_up_round(
    hub: &Arc<Hub>,
    project: i64,
    gc: &mut GcState,
    stamp: RefStamp,
    roots: DbRoots,
    uploads: Vec<String>,
    limit: Option<usize>,
) -> Result<Option<usize>> {
    match catch_up_round_in(hub, project, gc, stamp, roots, uploads, limit).await {
        Ok(Some(reads)) => Ok(Some(reads)),
        unfinished => {
            gc.expired_unreferenced.clear();
            unfinished
        }
    }
}

async fn catch_up_round_in(
    hub: &Arc<Hub>,
    project: i64,
    gc: &mut GcState,
    stamp: RefStamp,
    roots: DbRoots,
    uploads: Vec<String>,
    limit: Option<usize>,
) -> Result<Option<usize>> {
    let mut reads = 0usize;
    let over = |reads: usize| limit.is_some_and(|l| reads > l);
    for name in &uploads {
        if gc.marks.read_upload(hub, project, name).await? {
            reads += 1;
            if over(reads) {
                return Ok(None);
            }
        }
    }
    let marks = &mut gc.marks;
    // What a walk could not read and an upload holds is read again: stored
    // once the upload is listed (until then, read again every round).
    let mut seeds: Vec<ObjectId> = marks.unread.iter().filter(|id| marks.staged_ids.contains(id)).copied().collect();
    for id in &seeds {
        marks.unread.remove(id);
    }
    seeds.extend(roots.walk_objects.iter().copied());
    seeds.extend(roots.known_snapshots.iter().filter(|s| !gc.expired_unreferenced.contains(s)).copied());
    for (real, origin) in &roots.origins {
        if marks.reachable.contains(real) {
            seeds.push(*origin);
        }
    }
    for (real, projected) in &roots.projections {
        if marks.reachable.contains(real) {
            seeds.extend(projected.iter().copied());
        }
    }
    marks.leaves.extend(roots.leaf_objects.iter().copied());
    for (snapshot, changed) in &roots.graph_changed {
        if marks.reachable.contains(snapshot) {
            marks.leaves.insert(*changed);
        }
    }
    let left = limit.map(|l| l - reads);
    let Some(walked) = walk_from_roots(hub, project, seeds, marks, &roots, left).await? else {
        return Ok(None);
    };
    let marks = &gc.marks;
    gc.expired_unreferenced.retain(|id| !marks.live(id));
    gc.stamp = stamp;
    Ok(Some(reads + walked))
}

/// Before a switch that drops objects, outside its transaction (BUG-2602):
/// read the roots again and walk what was written since the marks
/// ([`catch_up_round`], no limit), round after round until one reads
/// little (what is left for the switch, under its lock, is what is written
/// during that round) or [`CATCH_UP_ROUNDS`] ran. A round that finds the
/// stamp of the last one reads no roots: nothing moved.
async fn catch_up(hub: &Arc<Hub>, project: i64, gc: &tokio::sync::Mutex<GcState>) -> Result<()> {
    let mut gc = gc.lock().await;
    for _ in 0..CATCH_UP_ROUNDS {
        if gc.expired_unreferenced.is_empty() {
            break;
        }
        let (stamp, Some((roots, uploads))) = read_stamp_and_roots(hub, project, Some(&gc.stamp)).await? else {
            break;
        };
        let reads = catch_up_round(hub, project, &mut gc, stamp, roots, uploads, None).await?.unwrap_or(0);
        if reads <= SWITCH_WALK_MAX / 8 {
            break;
        }
    }
    Ok(())
}

/// In a switch that drops objects, after [`lock_gc_epoch_tx`] (BUG-2602):
/// whether the pass may delete its candidates. No root writer commits
/// until the switch does, so the rows read here are the project's roots
/// at the switch.
/// * The stamp equals the one the marks last covered: yes, and nothing
///   else is read (the switch as it was before BUG-2602).
/// * Otherwise the roots are read again on the switch's connection and
///   walked from where the marks stop ([`catch_up_round`]), within
///   [`SWITCH_WALK_MAX`] store reads and [`SWITCH_WALK_TIME`]: what they
///   reach leaves the candidates. Past either limit, or on an error of
///   the walk: no, and the candidates are emptied (the switch gives way,
///   as it did for any root write), also for the transaction's next run.
///
/// It does not yield to requests (`derive_turn`): they wait for it.
async fn roots_at_switch(hub: &Arc<Hub>, project: i64, c: &mut PgConnection, gc: &mut GcState) -> Result<bool> {
    // Nothing left to delete (a round gave way or failed, in this run of
    // the transaction or one before): the marks may not be closed.
    if gc.expired_unreferenced.is_empty() {
        return Ok(false);
    }
    let cur = read_ref_stamp(c, project).await?;
    if cur == gc.stamp {
        return Ok(true);
    }
    let roots = collect_db_roots(c, project).await?;
    let uploads = upload_names(c, project).await?;
    match tokio::time::timeout(SWITCH_WALK_TIME, catch_up_round(hub, project, gc, cur, roots, uploads, Some(SWITCH_WALK_MAX))).await {
        Ok(r) => Ok(r?.is_some()),
        Err(_) => {
            gc.expired_unreferenced.clear();
            Ok(false)
        }
    }
}

async fn select_batch(
    hub: &Arc<Hub>,
    project: i64,
    listed: &[PackRow],
    opts: &Options,
    gc: Option<&tokio::sync::Mutex<GcState>>,
) -> Result<(Vec<PackRow>, bool)> {
    let max_per_run = opts.max_packs_per_run.max(1);
    let mut small: Vec<PackRow> = listed
        .iter()
        .filter(|p| p.size <= opts.small_pack_bytes && p.objects <= opts.max_merged_objects / 2)
        .cloned()
        .collect();
    small.sort_by(|a, b| {
        (a.objects, a.size, a.created_at, &a.name).cmp(&(b.objects, b.size, b.created_at, &b.name))
    });

    if opts.size_tiers {
        // The class with the most packs, of those with enough (the smaller
        // on a tie), alone (sorted by size within). BUG-2462: the smallest
        // class with enough was picked, and a busy project's pushes refill
        // the smallest class within every pass, so the class above it,
        // where the other pack of each push falls, was never merged.
        let class = |p: &PackRow| (u64::BITS - p.size.max(1).leading_zeros()) / TIER_BITS;
        let mut counts: std::collections::BTreeMap<u32, usize> = std::collections::BTreeMap::new();
        for p in &small {
            *counts.entry(class(p)).or_default() += 1;
        }
        let pick = counts
            .iter()
            .filter(|(_, n)| **n >= opts.min_packs_to_merge.max(2))
            .max_by_key(|(c, n)| (**n, std::cmp::Reverse(**c)))
            .map(|(c, _)| *c);
        small.retain(|p| Some(class(p)) == pick);
        small.sort_by(|a, b| (a.size, a.created_at, &a.name).cmp(&(b.size, b.created_at, &b.name)));
    }

    let Some(gc) = gc else {
        if small.len() < opts.min_packs_to_merge {
            return Ok((Vec::new(), false));
        }
        // Past `MAX_PACKS_PER_RUN`, only while the batch stays within one
        // merged pack (BUG-2462: many tiny packs a pass, never gigabytes).
        let mut bytes = 0u64;
        let batch = small
            .into_iter()
            .take(max_per_run)
            .enumerate()
            .take_while(|(i, p)| {
                bytes += p.size;
                *i < MAX_PACKS_PER_RUN || bytes <= opts.max_merged_bytes
            })
            .map(|(_, p)| p)
            .collect();
        return Ok((batch, false));
    };
    let gc = gc.lock().await;

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
    let mut complete_dead_sweep = true;
    if !gc.expired_unreferenced.is_empty() {
        let store = hub.objects.blob_store();
        let bound = hub.objects.index_bound();
        for p in listed {
            if chosen_names.contains(&p.name) {
                continue;
            }
            if chosen.len() >= max_per_run {
                complete_dead_sweep = false;
                break;
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

    Ok((chosen, complete_dead_sweep))
}

/// The replacement packs a merge writes as it copies entries, each at
/// most `max_merged_bytes` and `max_merged_objects` ([`Options`]).
struct Merged {
    objects: Vec<(ObjectId, Bytes)>,
    /// What `objects` makes a pack of: its head and entries.
    bytes: u64,
    max_bytes: u64,
    max_objects: usize,
    /// Staged, recorded before written: `(name, index, size, objects)`.
    written: Vec<(Arc<str>, Held, u64, usize)>,
    kept: usize,
}

impl Merged {
    fn new(opts: &Options) -> Merged {
        Merged {
            objects: Vec::new(),
            bytes: 14, // MAGIC + count
            max_bytes: opts.max_merged_bytes.max(1 << 20),
            max_objects: opts.max_merged_objects.clamp(1, pack::MAX_OBJECTS),
            written: Vec::new(),
            kept: 0,
        }
    }

    /// Add an entry, writing the pack so far first if it would pass a cap.
    async fn push(&mut self, hub: &Arc<Hub>, project: i64, id: ObjectId, enc: Bytes) -> Result<()> {
        let entry_cost = 44 + 36 + enc.len() as u64;
        if !self.objects.is_empty() && (self.objects.len() >= self.max_objects || self.bytes + entry_cost > self.max_bytes) {
            self.write(hub, project).await?;
        }
        self.bytes += entry_cost;
        self.objects.push((id, enc));
        self.kept += 1;
        Ok(())
    }

    /// Write the entries added since the last pack as a staged job pack.
    async fn write(&mut self, hub: &Arc<Hub>, project: i64) -> Result<()> {
        if self.objects.is_empty() {
            return Ok(());
        }
        let count = self.objects.len();
        let objects = std::mem::take(&mut self.objects);
        self.bytes = 14;
        let (name, held) = crate::store::not_own(hub.objects.put_job_pack(project, objects)).await.map_err(Error::Other)?;
        let size = held.size;
        self.written.push((name, held, size, count));
        Ok(())
    }

    /// Discard the packs written so far (the merge gave way).
    async fn discard(self, hub: &Arc<Hub>, project: i64) -> Result<()> {
        let names: Vec<Arc<str>> = self.written.into_iter().map(|(n, _, _, _)| n).collect();
        if !names.is_empty() {
            hub.objects.discard(project, &names).await.map_err(Error::Other)?;
        }
        Ok(())
    }
}

/// Merge and/or GC-filter `batch` of listed packs into one or more replacement
/// packs. Returns `Ok(true)` if a simulated crash stopped the pass early.
#[allow(clippy::too_many_arguments)]
async fn compact_batch(
    hub: &Arc<Hub>,
    project: i64,
    batch: &[PackRow],
    gc: Option<&Arc<tokio::sync::Mutex<GcState>>>,
    complete_dead_sweep: bool,
    opts: &Options,
    now_ms: i64,
    report: &mut Report,
) -> Result<bool> {
    // A pass that drops objects reads the roots again before it copies
    // (BUG-2602): what a root written since the marks names is copied, not
    // dropped (a dropped object named again later loses the switch).
    if let Some(gc) = gc {
        catch_up(hub, project, gc).await?;
    }
    let held = match gc {
        Some(gc) => Some(gc.lock().await),
        None => None,
    };
    let nothing = HashSet::new();
    let expired_unreferenced: &HashSet<ObjectId> = held.as_ref().map_or(&nothing, |gc| &gc.expired_unreferenced);
    let mut seen: HashSet<ObjectId> = HashSet::new();
    let mut dead_count = 0usize;
    let mut dead_ids: HashSet<ObjectId> = HashSet::new();
    let mut out = Merged::new(opts);

    if batch.len() > 1 && batch.iter().all(|p| p.size <= pack::FIRST_READ) {
        // Every pack whole in one read (the background merges' tiny packs,
        // BUG-2462): its index and its entries in one request, `AT_ONCE`
        // packs at a time (their shares of the bound and their bytes
        // under 3 MB, their bytes at most 2 MB), copied newest first, so the newest copy of
        // an object is kept.
        for chunk in batch.rchunks(AT_ONCE) {
            hub.limits.derive_turn().await;
            let _ra = ReadAhead::wait(chunk.iter().map(|p| p.size).sum()).await;
            let mut reads = tokio::task::JoinSet::new();
            for (i, p) in chunk.iter().enumerate() {
                let (hub, k) = (hub.clone(), pack::key(project, &p.name));
                hub.objects.reads.fetch_add(1, Ordering::Relaxed);
                reads.spawn(async move { (i, pack::read_whole(&**hub.objects.blob_store(), &k, hub.objects.index_bound()).await) });
            }
            let mut got: Vec<Option<(Held, Bytes)>> = (0..chunk.len()).map(|_| None).collect();
            while let Some(r) = reads.join_next().await {
                let (i, r) = r.map_err(|e| Error::Other(e.into()))?;
                let Some(whole) = r.map_err(Error::Other)? else {
                    // Pack was already replaced by another run.
                    out.discard(hub, project).await?;
                    return Ok(false);
                };
                got[i] = Some(whole);
            }
            let mut entries: Vec<(ObjectId, Bytes)> = Vec::new();
            for (p, whole) in chunk.iter().zip(got).rev() {
                let (held, bytes) = whole.expect("every read answered");
                for &(id, slot) in held.index.iter() {
                    if expired_unreferenced.contains(&id) {
                        dead_count += 1;
                        dead_ids.insert(id);
                        continue;
                    }
                    if seen.insert(id) {
                        let at = bytes
                            .get(slot.offset as usize..=slot.last() as usize)
                            .ok_or_else(|| Error::Other(anyhow!("source pack {} shorter than its index", p.name)))?;
                        let enc = pack::entry(&id, slot, at).map_err(Error::Other)?;
                        entries.push((id, Bytes::copy_from_slice(enc)));
                    }
                }
            }
            // The chunk's index shares are back before a merged pack is
            // written: writing one takes a share of its own, and waiting
            // for it while holding others could wait on ourselves.
            for (id, enc) in entries {
                out.push(hub, project, id, enc).await?;
            }
        }
    } else {
        // 1. Read the index of each pack in `batch` (a small pack's with
        // others, `AT_ONCE` at a time; a larger one's alone) and collect the
        // live slots to copy, deduplicating across `batch` (keeping the
        // newest pack's copy, or first seen).
        // Per pack in `batch` (newest first so newest copy wins if duplicated, then
        // reversed back to chronological pack order): `(PackRow, Vec<(ObjectId, Slot)>)`.
        let mut plan: Vec<(PackRow, Vec<(ObjectId, Slot)>)> = Vec::with_capacity(batch.len());
        let newest_first: Vec<&PackRow> = batch.iter().rev().collect();
        let mut at = 0;
        while at < newest_first.len() {
            hub.limits.derive_turn().await;
            // Packs whole in an index read's first read, `AT_ONCE` at a time
            // (BUG-2462: their shares of the bound together stay under 3 MB);
            // a larger pack alone, as before.
            let n = newest_first[at..]
                .iter()
                .take(AT_ONCE)
                .take_while(|p| p.size <= pack::FIRST_READ)
                .count()
                .max(1);
            let chunk = &newest_first[at..at + n];
            at += n;
            let mut reads = tokio::task::JoinSet::new();
            for (i, p) in chunk.iter().enumerate() {
                let (hub, k) = (hub.clone(), pack::key(project, &p.name));
                hub.objects.reads.fetch_add(1, Ordering::Relaxed);
                reads.spawn(async move { (i, pack::read_index(&**hub.objects.blob_store(), &k, hub.objects.index_bound()).await) });
            }
            let mut helds: Vec<Option<Held>> = (0..n).map(|_| None).collect();
            while let Some(r) = reads.join_next().await {
                let (i, r) = r.map_err(|e| Error::Other(e.into()))?;
                let Some(held) = r.map_err(Error::Other)? else {
                    // Pack was already replaced by another run.
                    return Ok(false);
                };
                helds[i] = Some(held);
            }
            // In order, newest first, so the newest copy of an object is kept.
            for (p, held) in chunk.iter().zip(helds) {
                let held = held.expect("every read answered");
                let mut keep_slots: Vec<(ObjectId, Slot)> = Vec::new();
                for (id, slot) in held.index.iter() {
                    if expired_unreferenced.contains(id) {
                        dead_count += 1;
                        dead_ids.insert(*id);
                        continue;
                    }
                    if seen.insert(*id) {
                        keep_slots.push((*id, *slot));
                    }
                }
                // Sort by offset so we read contiguous/nearby spans in few range requests.
                keep_slots.sort_unstable_by_key(|(_, s)| s.offset);
                drop(held);
                plan.push(((*p).clone(), keep_slots));
            }
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
        // Each pack's kept slots in spans of at most `COPY_SPAN` bytes:
        // `(pack in plan, its slots first..=last)`.
        let mut spans: Vec<(usize, usize, usize)> = Vec::new();
        for (pi, (_, slots)) in plan.iter().enumerate() {
            let mut i = 0;
            while i < slots.len() {
                let start_off = slots[i].1.offset;
                let mut end_idx = i;
                while end_idx + 1 < slots.len() {
                    let next_last = slots[end_idx + 1].1.last();
                    if next_last - start_off + 1 > COPY_SPAN {
                        break;
                    }
                    end_idx += 1;
                }
                spans.push((pi, i, end_idx));
                i = end_idx + 1;
            }
        }
        let span_len = |&(pi, i, e): &(usize, usize, usize)| plan[pi].1[e].1.last() - plan[pi].1[i].1.offset + 1;
        let mut s = 0;
        while s < spans.len() {
            hub.limits.derive_turn().await;
            // Up to `AT_ONCE` spans read at once, together at most `COPY_SPAN`
            // bytes (BUG-2462), under one `ReadAhead`.
            let mut e = s + 1;
            let mut chunk_len = span_len(&spans[s]);
            while e < spans.len() && e - s < AT_ONCE && chunk_len + span_len(&spans[e]) <= COPY_SPAN {
                chunk_len += span_len(&spans[e]);
                e += 1;
            }
            let _ra = ReadAhead::wait(chunk_len).await;
            let mut reads = tokio::task::JoinSet::new();
            for (j, &(pi, i, end_idx)) in spans[s..e].iter().enumerate() {
                let (p, slots) = &plan[pi];
                let (start_off, end_off) = (slots[i].1.offset, slots[end_idx].1.last());
                let (hub, k, name) = (hub.clone(), pack::key(project, &p.name), p.name.clone());
                hub.objects.reads.fetch_add(1, Ordering::Relaxed);
                reads.spawn(async move {
                    let got = hub.objects.blob_store().get_range(&k, start_off, end_off).await.map_err(Error::Other)?;
                    let (bytes, _) = got.ok_or_else(|| Error::Other(anyhow!("source pack {name} missing during merge")))?;
                    if (bytes.len() as u64) < end_off - start_off + 1 {
                        return Err(Error::Other(anyhow!("source pack {name} shorter than its index")));
                    }
                    Ok((j, bytes))
                });
            }
            let mut got: Vec<Bytes> = vec![Bytes::new(); e - s];
            while let Some(r) = reads.join_next().await {
                let (j, bytes) = r.map_err(|e| Error::Other(e.into()))??;
                got[j] = bytes;
            }
            for (&(pi, i, end_idx), bytes) in spans[s..e].iter().zip(got) {
                let slots = &plan[pi].1;
                let start_off = slots[i].1.offset;
                for &(id, slot) in &slots[i..=end_idx] {
                    let from = (slot.offset - start_off) as usize;
                    let to = (slot.last() - start_off) as usize;
                    let enc = pack::entry(&id, slot, &bytes[from..=to]).map_err(Error::Other)?;
                    out.push(hub, project, id, Bytes::copy_from_slice(enc)).await?;
                }
            }
            s = e;
        }
    }
    out.write(hub, project).await?;
    let Merged { written: written_packs, kept: total_kept, .. } = out;
    drop(held);

    // Simulated crash after writing the staged replacement pack(s), before
    // switching the database rows.
    if opts.crash == Some(CrashPoint::AfterWriteBeforeSwitch) {
        return Ok(true);
    }

    // The switch of a pass that dropped objects (pure compaction is safe
    // regardless of concurrent pushes). Once more outside it: what was
    // written while the packs were copied (BUG-2602).
    let check = if dead_count > 0 { gc.cloned() } else { None };
    if let Some(gc) = &check {
        catch_up(hub, project, gc).await?;
    }

    if let Some(hook) = &opts.before_switch {
        (hook.0)().await;
    }

    // 3. Switch the database rows in a single transaction:
    // - verify every pack in `batch` is still `LISTED` (locking the rows);
    // - if objects were dropped, make sure no root names a candidate
    //   ([`roots_at_switch`]) and that none of the dropped ones was named
    //   again since they were left out of the replacement packs: otherwise
    //   give way;
    // - mark the new pack(s) `LISTED` (giving them `created_at` matching the
    //   newest replaced pack so pack chronological order is preserved);
    // - mark the old packs `DISCARDED` with `discarded_at = now_ms`.
    let old_names: Vec<String> = batch.iter().map(|p| p.name.to_string()).collect();
    let new_names: Vec<String> = written_packs.iter().map(|(n, _, _, _)| n.to_string()).collect();
    let newest_created_at = batch.iter().map(|p| p.created_at).max().unwrap_or(now_ms);
    let dead_ids = Arc::new(dead_ids);
    let dead_hexes: Vec<String> = if dead_count > 0 && complete_dead_sweep {
        dead_ids.iter().map(ObjectId::hex).collect()
    } else {
        Vec::new()
    };

    let switched: Option<Option<i64>> =
        gc_transaction(hub, |c| {
            let old_names = old_names.clone();
            let new_names = new_names.clone();
            let (hub, check, dead_ids) = (hub.clone(), check.clone(), dead_ids.clone());
            let dead_hexes = dead_hexes.clone();
            Box::pin(async move {
                let mut all_expired_hexes: Vec<String> = Vec::new();
                if let Some(gc) = &check {
                    lock_gc_epoch_tx(c, project).await?;
                    let mut gc = gc.lock().await;
                    if !roots_at_switch(&hub, project, c, &mut gc).await?
                        || dead_ids.iter().any(|id| !gc.expired_unreferenced.contains(id))
                    {
                        return Ok(None);
                    }
                    all_expired_hexes = gc.expired_unreferenced.iter().map(ObjectId::hex).collect();
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
                    return Ok(None);
                }
                // The replacement packs must still be this run's, staged
                // (BUG-2270): another server that took the project's lock
                // after this one's lock session ended (its connection
                // dropped while the run went on) discards a staged job
                // pack as an interrupted run's and deletes its bytes;
                // replacing the old packs by it would lose their objects
                // once the grace period passed.
                if !new_names.is_empty() {
                    let staged: Vec<String> = sqlx::query_scalar(
                        "SELECT name FROM packs WHERE project_id = $1 AND name = ANY($2) AND state = $3 FOR UPDATE",
                    )
                    .bind(project)
                    .bind(&new_names)
                    .bind(STAGED)
                    .fetch_all(&mut *c)
                    .await?;
                    if staged.len() != new_names.len() {
                        return Ok(None);
                    }
                }
                if !all_expired_hexes.is_empty() {
                    purge_expired_db_records(&hub, c, project, &all_expired_hexes).await?;
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
                for chunk in dead_hexes.chunks(500) {
                    sqlx::query(
                        "DELETE FROM unreferenced_objects WHERE project_id = $1 AND object_id = ANY($2)",
                    )
                    .bind(project)
                    .bind(chunk)
                    .execute(&mut *c)
                    .await?;
                }
                let new_gce = if dead_count > 0 {
                    Some(bump_gc_epoch_tx(c, project).await?)
                } else {
                    None
                };
                Ok(Some(new_gce))
            })
        })
        .await?;

    let Some(switched_gce) = switched else {
        // A racing push or another state change intervened; discard the staged
        // replacement packs we wrote.
        let discard_names: Vec<Arc<str>> = written_packs.into_iter().map(|(n, _, _, _)| n).collect();
        hub.objects.discard(project, &discard_names).await.map_err(Error::Other)?;
        return Ok(false);
    };

    report.packs_merged += batch.len();
    report.packs_written += written_packs.len();
    report.objects_kept += total_kept;
    report.packed_objects_deleted += dead_count;

    // Simulated crash right after the switch transaction commits, before
    // `listed_here` / `forget_packs` or storage deletion runs.
    if opts.crash == Some(CrashPoint::AfterSwitchBeforeDelete) {
        return Ok(true);
    }

    if let Some(gce) = switched_gce {
        notify_gc_epoch(hub, project, gce).await;
    }

    let for_listed: Vec<(Arc<str>, Arc<Index>)> = written_packs
        .into_iter()
        .map(|(n, held, _, _)| (n, held.index.clone()))
        .collect();
    // Into the lookup map only: a job pack's objects are not cached
    // (`Objects::put_job_pack`), so there is nothing to move to the
    // project's keys, and walking a merged index for it costs a hash an
    // object.
    if !for_listed.is_empty() {
        hub.objects.packs().listed_here(project, for_listed);
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
    // `state = 0` (STAGED) is written literally so the partial index
    // `packs_unlisted` (migration 40) serves it under a generic plan too:
    // by the primary key alone every pass read every row of the project,
    // listed and discarded (BUG-2462).
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
        // Any due rows, not the first by name: sorting every due row to
        // take a few walked all of them each pass (BUG-2462: about 300,000
        // at 5,000 packs merged a second and the 60 s grace period).
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
        // `AT_ONCE` at a time (BUG-2462); a failed delete fails the pass
        // before any row goes, as one at a time did.
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
) -> Result<Arc<tokio::sync::Mutex<GcState>>> {
    // The stamp and the roots it stands for, of one snapshot (BUG-2602: a
    // row in the stamp and missing from the roots would never be walked).
    let (stamp, roots) = read_stamp_and_roots(hub, project, None).await?;
    let (roots, uploads) = roots.expect("read with no stamp to compare");

    // Walk object graph from `roots` to find all reachable `ObjectId`s.
    let mut marks = Marks { leaves: roots.leaf_objects.clone(), fault: opts.fault.clone(), ..Marks::default() };
    walk_from_roots(hub, project, roots.walk_objects.iter().copied(), &mut marks, &roots, None).await?;

    // Also keep all objects in active `STAGED` upload packs so a push in
    // flight can never lose an object it staged or is about to reference
    // (kept, not walked: `Marks::staged_ids`).
    let store = hub.objects.blob_store();
    let bound = hub.objects.index_bound();
    // The uploads listed (or discarded) at that moment are known: the walk
    // read what they hold. One made later is read when the pass catches up.
    marks.uploads = uploads.into_iter().filter(|name| !stamp.staged_packs.contains(name)).collect();
    for staged_name in &stamp.staged_packs {
        marks.read_upload(hub, project, staged_name).await?;
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

    let mut packed_stored: HashSet<ObjectId> = HashSet::new();
    let mut all_stored: HashSet<ObjectId> = HashSet::new();
    for name in &listed_names {
        hub.limits.derive_turn().await;
        let k = pack::key(project, name);
        hub.objects.reads.fetch_add(1, Ordering::Relaxed);
        if let Some(held) = pack::read_index(&**store, &k, bound).await.map_err(Error::Other)? {
            for (id, _) in held.index.iter() {
                packed_stored.insert(*id);
                all_stored.insert(*id);
            }
        }
    }

    let prefix = format!("p/{project}/");
    let keys = hub.objects.list_keys(&prefix).await.map_err(Error::Other)?;
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
            Ok(id) if !marks.live(&id) && all_stored.contains(&id) => {
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
        if !marks.live(id) && !unref_map.contains_key(id) {
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
    let mut expired_unreferenced: HashSet<ObjectId> = unref_map
        .into_iter()
        .filter_map(|(id, since)| (since <= cutoff).then_some(id))
        .collect();

    // Any unreferenced `snapshots` row whose snapshot object is already absent
    // from storage must also be purged; conversely, any unreferenced `snapshots`
    // row still inside its retention window retains its full object closure so
    // the server never holds a `snapshots` row with missing objects (BUG-1780).
    let mut retained_snaps: Vec<ObjectId> = Vec::new();
    for &s in &roots.known_snapshots {
        if marks.live(&s) {
            continue;
        }
        if !all_stored.contains(&s) {
            expired_unreferenced.insert(s);
        } else if !expired_unreferenced.contains(&s) {
            retained_snaps.push(s);
        }
    }
    if !retained_snaps.is_empty() && !expired_unreferenced.is_empty() {
        // From where the marks stop: nothing behind a member of the closed
        // set is a candidate. What it reaches joins the set (it is kept;
        // its marks in `unreferenced_objects` stay: nothing references it).
        walk_from_roots(hub, project, retained_snaps, &mut marks, &roots, None).await?;
        expired_unreferenced.retain(|id| !marks.live(id));
    }
    drop(roots);
    let gc = Arc::new(tokio::sync::Mutex::new(GcState { expired_unreferenced, stamp, marks }));

    // Delete expired unreferenced loose objects, in a switch that first
    // makes sure no root names them ([`roots_at_switch`]: no racing push,
    // PR, change_ref, or bisect), purging DB records in the same step.
    let any_loose = |gc: &GcState| loose_ids.iter().any(|id| gc.expired_unreferenced.contains(id));
    if any_loose(&*gc.lock().await) {
        catch_up(hub, project, &gc).await?;
    }
    if any_loose(&*gc.lock().await) {
        if let Some(hook) = &opts.before_switch {
            (hook.0)().await;
        }
        let switched: Option<i64> = gc_transaction(hub, |c| {
            let (hub, gc) = (hub.clone(), gc.clone());
            Box::pin(async move {
                lock_gc_epoch_tx(c, project).await?;
                let mut gc = gc.lock().await;
                if !roots_at_switch(&hub, project, c, &mut gc).await? || gc.expired_unreferenced.is_empty() {
                    return Ok(None);
                }
                let expired_hexes: Vec<String> = gc.expired_unreferenced.iter().map(ObjectId::hex).collect();
                purge_expired_db_records(&hub, c, project, &expired_hexes).await?;
                let gce = bump_gc_epoch_tx(c, project).await?;
                // The purge moved the stamp; the roots are those just read,
                // less what it purged.
                gc.stamp = read_ref_stamp(c, project).await?;
                Ok(Some(gce))
            })
        })
        .await?;
        let Some(gce) = switched else {
            // Gave way (or every candidate is named again): the pass
            // deletes nothing more.
            gc.lock().await.expired_unreferenced.clear();
            return Ok(gc);
        };
        notify_gc_epoch(hub, project, gce).await;
        if let Some(hook) = &opts.before_loose_delete {
            (hook.0)().await;
        }

        // The deletes (BUG-2621), in chunks, each under the root writers'
        // gate ([`delete_loose_chunk`]). Deleted after the purge's commit
        // and outside any lock, as they were, a writer could find an object
        // still stored, commit, and lose it to the delete.
        let loose: Vec<ObjectId> = {
            let gc = gc.lock().await;
            let mut loose: Vec<ObjectId> = loose_ids.into_iter().filter(|id| gc.expired_unreferenced.contains(id)).collect();
            loose.sort_unstable();
            loose
        };
        for chunk in loose.chunks(LOOSE_DELETE_CHUNK) {
            hub.limits.derive_turn().await;
            let packed_too: HashSet<ObjectId> = chunk.iter().filter(|id| packed_stored.contains(id)).copied().collect();
            let (deleted, more) = delete_loose_chunk(hub, project, &gc, chunk, &packed_too, opts).await?;
            report.loose_objects_deleted += deleted;
            if !more {
                break;
            }
        }
    }

    Ok(gc)
}

/// How often a chunk of loose deletes tries to raise the GC epoch after its
/// deletes before it gives up ([`delete_loose_chunk`]); it holds the root
/// writers' gate meanwhile.
const EPOCH_AFTER_DELETES_TRIES: u32 = 20;

/// Delete one chunk of loose objects under the root writers' gate
/// (BUG-2621): the objects deleted, and whether the pass goes on to the
/// next chunk.
///
/// The gate ([`GATE_BASE`]) is taken **on a session**, exclusively, and held
/// from before the roots are read until the epoch is raised after the last
/// delete, so no step in between (a commit that fails, a delete that fails)
/// lets a waiting root writer through:
/// 1. a transaction locks the epoch row, reads the roots again
///    ([`roots_at_switch`]: a root committed since the purge keeps what it
///    names, and that object leaves the chunk), clears the marks of what is
///    still a candidate and raises the epoch, and commits. If anything of it
///    fails, nothing has been deleted: the pass ends there.
/// 2. the store deletes, [`AT_ONCE`] at a time, each batch joined to its end
///    (a request is never dropped in flight: one the store already has
///    would be applied later, after a writer stored the object again). A
///    delete that fails, or [`LOOSE_DELETE_TIME`] passing between batches,
///    stops the rest (an object left stored lost its mark: the next pass
///    marks it again).
/// 3. a second transaction raises the epoch again, tried again while it
///    fails ([`EPOCH_AFTER_DELETES_TRIES`]), the gate still held: a writer
///    that checked an object while the deletes ran (the first raise came
///    before its check) starts over.
///
/// So for every object deleted: a writer that committed before the gate was
/// taken is seen by step 1; one that waits at the gate reads an epoch
/// raised after the delete and checks again; one that begins later finds
/// the object gone. What is left: a server that stops, or the gate's
/// session ending (checked before every batch), between a delete and step
/// 3: the writers that checked that object while the deletes ran keep the
/// epoch they read. (The first raise covers those that checked before;
/// when the session ended and the server lives, it raises the epoch from
/// another connection at once, which covers those not yet at their guard.)
///
/// A store that does not answer a delete holds the gate until it does
/// (BUG-2624, accepted): giving the request up would let the store apply
/// it later, after a writer had stored the object again.
async fn delete_loose_chunk(
    hub: &Arc<Hub>,
    project: i64,
    gc: &Arc<tokio::sync::Mutex<GcState>>,
    chunk: &[ObjectId],
    packed_too: &HashSet<ObjectId>,
    opts: &Options,
) -> Result<(usize, bool)> {
    let mut conn = hub.db.acquire().await?;
    // The session ends with this connection, whatever ends the chunk (an
    // error, a panic, this future dropped): one that holds the gate, or an
    // open transaction, never goes back to the pool.
    conn.close_on_drop();
    // Nothing is held if this fails (the wait for the writers in their
    // transactions is bounded by the connection's lock timeout).
    sqlx::query("SELECT pg_advisory_lock($1)").bind(gate_key(project)).execute(&mut *conn).await?;
    let deleting = std::sync::atomic::AtomicBool::new(false);
    let done = loose_chunk_under_gate(hub, project, &mut conn, gc, chunk, packed_too, opts, &deleting).await;
    // The gate goes back: by its unlock, or with the session.
    if done.is_ok() {
        let _ = sqlx::query("SELECT pg_advisory_unlock($1)").bind(gate_key(project)).execute(&mut *conn).await;
    }
    drop(conn);
    if done.is_err() && deleting.load(Ordering::SeqCst) {
        // The chunk ended after its deletes began and before its second
        // raise (the gate's session ended, or the raise failed every
        // time): the gate is open with the epoch as the first raise left
        // it. Raise it from here, as best we can: raising it only ever
        // sends writers back to their checks. It covers the writers that
        // have not reached their guard yet; one that passed it since the
        // gate opened is not sent back.
        let mut raised = None;
        for _ in 0..3 {
            let r = gc_transaction(hub, |c| {
                Box::pin(async move {
                    lock_gc_epoch_tx(c, project).await?;
                    bump_gc_epoch_tx(c, project).await
                })
            })
            .await;
            match r {
                Ok(epoch) => {
                    raised = Some(epoch);
                    break;
                }
                Err(e) => eprintln!("veil-server: pack GC of project {project}: the GC epoch was not raised after a chunk of loose deletes lost its gate: {e:?}"),
            }
        }
        if let Some(epoch) = raised {
            notify_gc_epoch(hub, project, epoch).await;
        }
    }
    let (deleted, more, epochs, failed) = done?;
    for epoch in epochs {
        notify_gc_epoch(hub, project, epoch).await;
    }
    match failed {
        // A delete failed: the epoch is raised for the deletes made, and
        // the pass ends with the error.
        Some(e) => Err(Error::Other(anyhow!("deleting a loose object: {e}"))),
        None => Ok((deleted, more)),
    }
}

/// [`delete_loose_chunk`] with the gate held on `conn`'s session: the
/// objects deleted, whether the pass goes on, the epochs raised, and a
/// delete's failure. `deleting` is set once the deletes begin.
#[allow(clippy::too_many_arguments)]
async fn loose_chunk_under_gate(
    hub: &Arc<Hub>,
    project: i64,
    conn: &mut PgConnection,
    gc: &Arc<tokio::sync::Mutex<GcState>>,
    chunk: &[ObjectId],
    packed_too: &HashSet<ObjectId>,
    opts: &Options,
    deleting: &std::sync::atomic::AtomicBool,
) -> Result<(usize, bool, Vec<i64>, Option<String>)> {
    let fault = |point: FaultPoint, id: ObjectId| {
        let fault = opts.fault.clone();
        async move {
            match &fault {
                Some(fault) => (fault.0)(point, id).await,
                None => Ok(()),
            }
        }
    };
    // 1. The roots, the marks, the epoch.
    sqlx::query("BEGIN ISOLATION LEVEL READ COMMITTED").execute(&mut *conn).await?;
    lock_gc_epoch_tx(conn, project).await?;
    let ids: Vec<ObjectId> = {
        let mut gc = gc.lock().await;
        if !roots_at_switch(hub, project, conn, &mut gc).await? {
            // Gave way (the bound on its walk): the pass deletes nothing more.
            sqlx::query("ROLLBACK").execute(&mut *conn).await?;
            return Ok((0, false, Vec::new(), None));
        }
        if let Some(hook) = &opts.during_loose_delete {
            (hook.0)().await;
        }
        chunk.iter().filter(|id| gc.expired_unreferenced.contains(id)).copied().collect()
    };
    if ids.is_empty() {
        // Every one is named again: nothing deleted, no writer sent back.
        sqlx::query("ROLLBACK").execute(&mut *conn).await?;
        return Ok((0, true, Vec::new(), None));
    }
    let loose_only: Vec<String> = ids.iter().filter(|id| !packed_too.contains(id)).map(ObjectId::hex).collect();
    for hexes in loose_only.chunks(500) {
        sqlx::query("DELETE FROM unreferenced_objects WHERE project_id = $1 AND object_id = ANY($2)")
            .bind(project)
            .bind(hexes)
            .execute(&mut *conn)
            .await?;
    }
    let mut epochs = vec![bump_gc_epoch_tx(conn, project).await?];
    fault(FaultPoint::LooseCommit, ids[0]).await?;
    sqlx::query("COMMIT").execute(&mut *conn).await?;
    hub.commits.count(crate::db::Commit::PackGc);

    // 2. The deletes.
    deleting.store(true, Ordering::SeqCst);
    let (mut deleted, mut failed) = (0usize, None::<String>);
    let began = std::time::Instant::now();
    let mut gate_held = true;
    for batch in ids.chunks(AT_ONCE) {
        if began.elapsed() > LOOSE_DELETE_TIME {
            failed = Some(format!("the deletes took longer than {LOOSE_DELETE_TIME:?}"));
            break;
        }
        // The gate is this session's: without it, no more deletes.
        if sqlx::query("SELECT 1").execute(&mut *conn).await.is_err() {
            failed = Some("the session holding the root writers' gate ended".into());
            gate_held = false;
            break;
        }
        let mut set = tokio::task::JoinSet::new();
        for id in batch {
            let (hub, k, id, fault) = (hub.clone(), object_key(project, id), *id, opts.fault.clone());
            set.spawn(async move {
                if let Some(fault) = &fault {
                    (fault.0)(FaultPoint::LooseDelete, id).await?;
                }
                hub.objects.delete_key(&k).await.map_err(Error::Other)
            });
        }
        while let Some(r) = set.join_next().await {
            match r.map_err(|e| Error::Other(e.into())).and_then(|r| r) {
                Ok(()) => deleted += 1,
                Err(e) => failed = Some(format!("{e:?}")),
            }
        }
        if failed.is_some() {
            break;
        }
    }
    if !gate_held {
        return Err(Error::Other(anyhow!("deleting loose objects: {}", failed.unwrap_or_default())));
    }

    // 3. The epoch again, for what was checked while the deletes ran.
    let mut tries = 0;
    loop {
        tries += 1;
        let raised: Result<i64> = async {
            sqlx::query("BEGIN ISOLATION LEVEL READ COMMITTED").execute(&mut *conn).await?;
            let epoch = bump_gc_epoch_tx(conn, project).await?;
            fault(FaultPoint::LooseCommit, ids[0]).await?;
            sqlx::query("COMMIT").execute(&mut *conn).await?;
            Ok(epoch)
        }
        .await;
        match raised {
            Ok(epoch) => {
                hub.commits.count(crate::db::Commit::PackGc);
                epochs.push(epoch);
                break;
            }
            Err(e) if tries >= EPOCH_AFTER_DELETES_TRIES => {
                return Err(Error::Other(anyhow!("the GC epoch could not be raised after {deleted} loose objects were deleted: {e:?}")));
            }
            Err(e) => {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                // The session is gone, and the gate with it: no use trying here.
                if sqlx::query("SELECT 1").execute(&mut *conn).await.is_err() {
                    return Err(Error::Other(anyhow!("the session holding the root writers' gate ended after {deleted} loose objects were deleted: {e:?}")));
                }
                tokio::time::sleep(std::time::Duration::from_millis(50 * u64::from(tries))).await;
            }
        }
    }
    Ok((deleted, failed.is_none(), epochs, failed))
}

async fn bump_gc_epoch_tx(c: &mut PgConnection, project: i64) -> Result<i64> {
    sqlx::query("SELECT veil_bump_epoch($1, -1)")
        .bind(project)
        .execute(&mut *c)
        .await?;
    let epoch: i64 = sqlx::query_scalar(
        "SELECT epoch FROM access_epochs WHERE project_id = $1 AND person_id = -1",
    )
    .bind(project)
    .fetch_one(&mut *c)
    .await?;
    Ok(epoch)
}

async fn notify_gc_epoch(hub: &Hub, project: i64, epoch: i64) {
    hub.observe_gc_epoch(project, epoch);
    if hub.caches.notices.load(Ordering::Relaxed) {
        let payload = format!("gc:{project}:{epoch}");
        let _ = sqlx::query("SELECT pg_notify($1, $2)")
            .bind(crate::caches::TIPS_CHANNEL)
            .bind(payload)
            .execute(&hub.db)
            .await;
    }
}

/// Keep only `raw_cands` whose real first parent does NOT also project to
/// `projected_id` under `view_key` (BUG-2671: excludes collapsed single-parent
/// commits from pre-0011 rows and collapsed multi-parent hidden merges that may
/// carry `collapsed = FALSE`).
async fn filter_uncollapsed_candidates(
    hub: &Hub,
    c: &mut PgConnection,
    project: i64,
    view_key: &str,
    projected_id: &str,
    raw_cands: Vec<String>,
) -> Result<Vec<String>> {
    if raw_cands.is_empty() {
        return Ok(Vec::new());
    }
    let graph_rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT snapshot, parents FROM graph WHERE project_id = $1 AND snapshot = ANY($2)",
    )
    .bind(project)
    .bind(&raw_cands)
    .fetch_all(&mut *c)
    .await?;
    let graph_map: HashMap<String, String> = graph_rows.into_iter().collect();

    let mut first_parents: Vec<(String, Option<String>)> = Vec::with_capacity(raw_cands.len());
    let mut fp_set: HashSet<String> = HashSet::new();
    for r in raw_cands {
        let fp = if let Some(parents_json) = graph_map.get(&r) {
            match serde_json::from_str::<Vec<ObjectId>>(parents_json) {
                Ok(ps) => ps.first().map(ObjectId::hex),
                Err(_) => continue,
            }
        } else {
            // Un-derived snapshot: fall back to decoded Snapshot.parents.first().
            let Ok(oid) = ObjectId::from_hex(&r) else { continue };
            let Some(raw) = hub.objects.get(project, &oid).await? else { continue };
            match Object::decode(&raw) {
                Ok(Object::Snapshot(s)) => s.parents.first().map(ObjectId::hex),
                _ => continue,
            }
        };
        if let Some(ref p) = fp {
            fp_set.insert(p.clone());
        }
        first_parents.push((r, fp));
    }

    let fp_proj: HashMap<String, String> = if fp_set.is_empty() {
        HashMap::new()
    } else {
        let fp_vec: Vec<String> = fp_set.into_iter().collect();
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT real_id, projected_id FROM projections \
             WHERE project_id = $1 AND view_key = $2 AND real_id = ANY($3)",
        )
        .persistent(false)
        .bind(project)
        .bind(view_key)
        .bind(&fp_vec)
        .fetch_all(&mut *c)
        .await?;
        rows.into_iter().collect()
    };

    let root_hex = crate::sync::root_snapshot_id().hex();
    let mut out = Vec::with_capacity(first_parents.len());
    for (r, fp) in first_parents {
        let collapses_into_p0 = match fp.as_deref() {
            Some(p) => {
                fp_proj.get(p).map(String::as_str) == Some(projected_id)
                    || (p == root_hex.as_str() && projected_id == root_hex.as_str())
            }
            None => false,
        };
        if !collapses_into_p0 {
            out.push(r);
        }
    }
    Ok(out)
}

/// Before deleting `view_graph` rows whose `real_id` is expiring, repoint any
/// `(view_key, snapshot)` row that still has a surviving uncollapsed real
/// snapshot projecting to `snapshot` (BUG-2670 & BUG-2671,
/// `docs/design/server/change-sized-cleanup.md` §5.3 item 2).
///
/// Queries `projections_own` (`NOT collapsed`) first, falling back to
/// `projections_by_view` (`collapsed`) for pre-0011 rows when no uncollapsed
/// survivor is found; drops any candidate whose real first parent also projects
/// to `snapshot`; and orders surviving candidates by `(is_withheld ASC, real_id ASC)`
/// so unembargoed survivors always win over embargoed siblings.
async fn repoint_surviving_view_graph(
    hub: &Hub,
    c: &mut PgConnection,
    project: i64,
    expired_hexes: &[String],
) -> Result<()> {
    if expired_hexes.is_empty() {
        return Ok(());
    }
    let expired_set: HashSet<&str> = expired_hexes.iter().map(String::as_str).collect();
    let mut affected: BTreeSet<(String, String)> = BTreeSet::new();
    for chunk in expired_hexes.chunks(500) {
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT view_key, snapshot FROM view_graph WHERE project_id = $1 AND real_id = ANY($2)",
        )
        .persistent(false)
        .bind(project)
        .bind(chunk)
        .fetch_all(&mut *c)
        .await?;
        for (vk, snap) in rows {
            if !expired_set.contains(snap.as_str()) {
                affected.insert((vk, snap));
            }
        }
    }
    if affected.is_empty() {
        return Ok(());
    }

    let mut cand_vks: Vec<String> = Vec::new();
    let mut cand_ps: Vec<String> = Vec::new();
    let mut cand_rs: Vec<String> = Vec::new();

    for (vk, p0) in affected {
        let own_raw: Vec<String> = sqlx::query_scalar(
            "SELECT real_id FROM projections \
             WHERE project_id = $1 AND view_key = $2 AND projected_id = $3 AND NOT collapsed",
        )
        .persistent(false)
        .bind(project)
        .bind(&vk)
        .bind(&p0)
        .fetch_all(&mut *c)
        .await?
        .into_iter()
        .filter(|r: &String| !expired_set.contains(r.as_str()))
        .collect();

        let mut survivors = filter_uncollapsed_candidates(hub, c, project, &vk, &p0, own_raw).await?;
        if survivors.is_empty() {
            // Pre-0011 fallback: rows written before `0011_landing.sql`
            // defaulted to `collapsed = TRUE` even when uncollapsed.
            let legacy_raw: Vec<String> = sqlx::query_scalar(
                "SELECT real_id FROM projections \
                 WHERE project_id = $1 AND view_key = $2 AND projected_id = $3 AND collapsed",
            )
            .persistent(false)
            .bind(project)
            .bind(&vk)
            .bind(&p0)
            .fetch_all(&mut *c)
            .await?
            .into_iter()
            .filter(|r: &String| !expired_set.contains(r.as_str()))
            .collect();
            survivors = filter_uncollapsed_candidates(hub, c, project, &vk, &p0, legacy_raw).await?;
        }
        for r in survivors {
            cand_vks.push(vk.clone());
            cand_ps.push(p0.clone());
            cand_rs.push(r);
        }
    }

    if !cand_vks.is_empty() {
        sqlx::query(
            "UPDATE view_graph vg \
             SET real_id = chosen.real_id \
             FROM ( \
                 SELECT DISTINCT ON (c.view_key, c.projected_id) c.view_key, c.projected_id, c.real_id \
                 FROM UNNEST($2::text[], $3::text[], $4::text[]) AS c(view_key, projected_id, real_id) \
                 WHERE NOT (c.real_id = ANY($5)) \
                 ORDER BY c.view_key, c.projected_id, \
                          EXISTS ( \
                              SELECT 1 \
                              FROM embargo_snapshots es \
                              JOIN embargo_lines el \
                                ON el.project_id = es.project_id AND el.embargo_id = es.embargo_id \
                              WHERE es.project_id = $1 \
                                AND es.snapshot = c.real_id \
                                AND el.released_at IS NULL \
                          ) ASC, \
                          c.real_id ASC \
             ) chosen \
             WHERE vg.project_id = $1 \
               AND vg.view_key = chosen.view_key \
               AND vg.snapshot = chosen.projected_id \
               AND vg.real_id = ANY($5)",
        )
        .persistent(false)
        .bind(project)
        .bind(&cand_vks)
        .bind(&cand_ps)
        .bind(&cand_rs)
        .bind(expired_hexes)
        .execute(&mut *c)
        .await?;
    }
    Ok(())
}

async fn purge_expired_db_records(
    hub: &Hub,
    c: &mut PgConnection,
    project: i64,
    expired_hexes: &[String],
) -> Result<()> {
    // Repoint any surviving shared projections in `view_graph` BEFORE deleting
    // `projections`, `graph`, or `view_graph` rows (BUG-2670).
    repoint_surviving_view_graph(hub, c, project, expired_hexes).await?;

    let expired_set: HashSet<&str> = expired_hexes.iter().map(String::as_str).collect();
    let mut deleted_vg_pairs: BTreeSet<(String, String)> = BTreeSet::new();

    for chunk in expired_hexes.chunks(500) {
        for q in [
            "DELETE FROM snapshots WHERE project_id = $1 AND id = ANY($2)",
            "DELETE FROM origins WHERE project_id = $1 AND (real_id = ANY($2) OR origin_id = ANY($2))",
            "DELETE FROM projections WHERE project_id = $1 AND (real_id = ANY($2) OR projected_id = ANY($2))",
            "DELETE FROM landed_from WHERE project_id = $1 AND (source = ANY($2) OR landed = ANY($2))",
            "DELETE FROM landed_changes WHERE project_id = $1 AND landed = ANY($2)",
            "DELETE FROM graph WHERE project_id = $1 AND (snapshot = ANY($2) OR changed = ANY($2))",
            "DELETE FROM file_history WHERE project_id = $1 AND snapshot = ANY($2)",
            "DELETE FROM rule_history WHERE project_id = $1 AND snapshot = ANY($2)",
            "DELETE FROM derive_progress WHERE project_id = $1 AND through_snapshot = ANY($2)",
        ] {
            sqlx::query(q).bind(project).bind(chunk).execute(&mut *c).await?;
        }
        // Delete `view_graph` rows whose snapshot or remaining (un-repointed)
        // `real_id` expired, recording `(view_key, snapshot)` so derived view
        // rows (`view_file_history`, `view_changes`, `blame_*`) are never orphaned.
        let del_by_snap: Vec<(String, String)> = sqlx::query_as(
            "DELETE FROM view_graph WHERE project_id = $1 AND snapshot = ANY($2) RETURNING view_key, snapshot",
        )
        .bind(project)
        .bind(chunk)
        .fetch_all(&mut *c)
        .await?;
        deleted_vg_pairs.extend(del_by_snap);
        let del_by_real: Vec<(String, String)> = sqlx::query_as(
            "DELETE FROM view_graph WHERE project_id = $1 AND real_id = ANY($2) RETURNING view_key, snapshot",
        )
        .persistent(false)
        .bind(project)
        .bind(chunk)
        .fetch_all(&mut *c)
        .await?;
        deleted_vg_pairs.extend(del_by_real);

        for q in [
            "DELETE FROM view_changes WHERE project_id = $1 AND snapshot = ANY($2)",
            "DELETE FROM view_file_history WHERE project_id = $1 AND snapshot = ANY($2)",
            "DELETE FROM blame_memo WHERE project_id = $1 AND snapshot = ANY($2)",
            "DELETE FROM blame_ends WHERE project_id = $1 AND snapshot = ANY($2)",
            "DELETE FROM blame_jobs WHERE project_id = $1 AND snapshot = ANY($2)",
            "DELETE FROM search_heads WHERE project_id = $1 AND branch <> '' AND snapshot = ANY($2)",
        ] {
            sqlx::query(q).bind(project).bind(chunk).execute(&mut *c).await?;
        }
    }

    // Clean up derived viewer rows for any `view_graph` row deleted via its
    // expiring `real_id` whose projected `snapshot` was not itself in `expired_hexes`.
    let extra_pairs: Vec<(String, String)> = deleted_vg_pairs
        .into_iter()
        .filter(|(_, snap)| !expired_set.contains(snap.as_str()))
        .collect();
    for chunk in extra_pairs.chunks(500) {
        let vks: Vec<&str> = chunk.iter().map(|(vk, _)| vk.as_str()).collect();
        let snaps: Vec<&str> = chunk.iter().map(|(_, s)| s.as_str()).collect();
        for q in [
            "DELETE FROM view_changes t USING UNNEST($2::text[], $3::text[]) AS d(vk, snap) \
             WHERE t.project_id = $1 AND t.view_key = d.vk AND t.snapshot = d.snap",
            "DELETE FROM view_file_history t USING UNNEST($2::text[], $3::text[]) AS d(vk, snap) \
             WHERE t.project_id = $1 AND t.view_key = d.vk AND t.snapshot = d.snap",
            "DELETE FROM blame_memo t USING UNNEST($2::text[], $3::text[]) AS d(vk, snap) \
             WHERE t.project_id = $1 AND t.view_key = d.vk AND t.snapshot = d.snap",
            "DELETE FROM blame_ends t USING UNNEST($2::text[], $3::text[]) AS d(vk, snap) \
             WHERE t.project_id = $1 AND t.view_key = d.vk AND t.snapshot = d.snap",
            "DELETE FROM blame_jobs t USING UNNEST($2::text[], $3::text[]) AS d(vk, snap) \
             WHERE t.project_id = $1 AND t.view_key = d.vk AND t.snapshot = d.snap",
        ] {
            sqlx::query(q).bind(project).bind(&vks).bind(&snaps).execute(&mut *c).await?;
        }
    }

    sqlx::query(
        "DELETE FROM derive_progress WHERE project_id = $1 AND branch <> '' \
         AND branch NOT IN (SELECT name FROM branches WHERE project_id = $1)",
    )
    .bind(project)
    .execute(&mut *c)
    .await?;
    sqlx::query(
        "DELETE FROM search_heads WHERE project_id = $1 AND branch <> '' \
         AND branch NOT IN (SELECT name FROM branches WHERE project_id = $1 AND hidden_for_embargo IS NULL)",
    )
    .bind(project)
    .execute(&mut *c)
    .await?;
    sqlx::query(
        "DELETE FROM search_shards WHERE project_id = $1 AND branch <> '' \
         AND branch NOT IN (SELECT name FROM branches WHERE project_id = $1 AND hidden_for_embargo IS NULL)",
    )
    .bind(project)
    .execute(&mut *c)
    .await?;
    Ok(())
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

/// Role of a database column in `public` with respect to S29 pack garbage
/// collection (`BUG-1782`). Every `(table, column)` in the schema must be
/// registered in [`OBJECT_SCHEMA_COLUMNS`] or [`NON_OBJECT_SCHEMA_COLUMNS`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchemaColumnRole {
    /// Authoritative `ObjectId` root (plain 64-hex or JSON containing 64-hex
    /// IDs) whose reachable closure is retained by `collect_db_roots`, and
    /// whose table is fingerprinted in `read_ref_stamp`.
    GcRoot,
    /// Conditional leaf `ObjectId` root (`search_shards.segments` for live
    /// non-embargo branches and `branch = ''`), retained without graph walk and
    /// fingerprinted in `read_ref_stamp`.
    GcConditionalLeafRoot,
    /// Conditional graph attachment or retained history (`snapshots.id` within
    /// `retention_window_ms`, `origins`, `projections`, `graph.changed`),
    /// retained while its owning snapshot is live/retained and purged when
    /// expired.
    GcAttachmentOrRetainedHistory,
    /// Derived index, history row, or ephemeral pagination cursor referencing
    /// `ObjectId`s (`landed_from`, `landed_changes`, `graph`, `file_history`,
    /// `rule_history`, `derive_progress`, `view_graph`, `view_changes`,
    /// `view_file_history`, `blame_memo`, `blame_ends`, `blame_jobs`,
    /// `search_heads`, `log_cursors`), purged or invalidated when expired.
    DerivedOrEphemeralObjectRef,
    /// GC's own unreferenced-object age table (`unreferenced_objects.object_id`).
    GcBookkeeping,
    /// Column never holds content-addressed `ObjectId`s.
    NonObject,
}

/// Every schema column that holds (or may hold) content-addressed `ObjectId`s.
pub const OBJECT_SCHEMA_COLUMNS: &[(&str, &str, SchemaColumnRole)] = &[
    // Authoritative GC roots (`GcRoot`) — automatically queried by `collect_db_roots`:
    ("branches", "target", SchemaColumnRole::GcRoot),
    ("embargo_snapshots", "snapshot", SchemaColumnRole::GcRoot),
    ("embargo_lines", "record_json", SchemaColumnRole::GcRoot),
    ("change_refs", "snapshot", SchemaColumnRole::GcRoot),
    ("landing_queue", "stack", SchemaColumnRole::GcRoot),
    ("landing_queue", "result", SchemaColumnRole::GcRoot),
    ("landings", "submitted", SchemaColumnRole::GcRoot),
    ("landings", "landed", SchemaColumnRole::GcRoot),
    ("checks", "snapshot", SchemaColumnRole::GcRoot),
    ("tested", "snapshot", SchemaColumnRole::GcRoot),
    ("pr_revisions", "base", SchemaColumnRole::GcRoot),
    ("pr_revisions", "head", SchemaColumnRole::GcRoot),
    ("pr_revisions", "changes", SchemaColumnRole::GcRoot),
    ("pr_review_rules", "checked", SchemaColumnRole::GcRoot),
    ("bisects", "good", SchemaColumnRole::GcRoot),
    ("bisects", "bad", SchemaColumnRole::GcRoot),
    ("bisects", "candidates", SchemaColumnRole::GcRoot),
    ("bisects", "probes", SchemaColumnRole::GcRoot),
    ("bisects", "culprit", SchemaColumnRole::GcRoot),
    ("bisects", "culprit_parent", SchemaColumnRole::GcRoot),
    ("bisects", "revert_snapshot", SchemaColumnRole::GcRoot),
    ("bisect_reverts", "culprit", SchemaColumnRole::GcRoot),
    ("bisect_reverts", "revert_snapshot", SchemaColumnRole::GcRoot),
    // Conditional leaf roots (`GcConditionalLeafRoot`):
    ("search_shards", "segments", SchemaColumnRole::GcConditionalLeafRoot),
    // Conditional attachments and retained snapshot history (`GcAttachmentOrRetainedHistory`):
    ("snapshots", "id", SchemaColumnRole::GcAttachmentOrRetainedHistory),
    ("origins", "real_id", SchemaColumnRole::GcAttachmentOrRetainedHistory),
    ("origins", "origin_id", SchemaColumnRole::GcAttachmentOrRetainedHistory),
    ("projections", "real_id", SchemaColumnRole::GcAttachmentOrRetainedHistory),
    ("projections", "projected_id", SchemaColumnRole::GcAttachmentOrRetainedHistory),
    ("graph", "changed", SchemaColumnRole::GcAttachmentOrRetainedHistory),
    // Derived indexes, history tables, and ephemeral cursors (`DerivedOrEphemeralObjectRef`):
    ("blame_ends", "snapshot", SchemaColumnRole::DerivedOrEphemeralObjectRef),
    ("blame_jobs", "snapshot", SchemaColumnRole::DerivedOrEphemeralObjectRef),
    ("blame_memo", "snapshot", SchemaColumnRole::DerivedOrEphemeralObjectRef),
    ("derive_progress", "through_snapshot", SchemaColumnRole::DerivedOrEphemeralObjectRef),
    ("file_history", "snapshot", SchemaColumnRole::DerivedOrEphemeralObjectRef),
    ("graph", "snapshot", SchemaColumnRole::DerivedOrEphemeralObjectRef),
    ("graph", "parents", SchemaColumnRole::DerivedOrEphemeralObjectRef),
    ("graph", "skip", SchemaColumnRole::DerivedOrEphemeralObjectRef),
    ("landed_changes", "landed", SchemaColumnRole::DerivedOrEphemeralObjectRef),
    ("landed_from", "source", SchemaColumnRole::DerivedOrEphemeralObjectRef),
    ("landed_from", "landed", SchemaColumnRole::DerivedOrEphemeralObjectRef),
    ("log_cursors", "frontier", SchemaColumnRole::DerivedOrEphemeralObjectRef),
    ("rule_history", "snapshot", SchemaColumnRole::DerivedOrEphemeralObjectRef),
    ("search_heads", "snapshot", SchemaColumnRole::DerivedOrEphemeralObjectRef),
    ("view_changes", "snapshot", SchemaColumnRole::DerivedOrEphemeralObjectRef),
    ("view_file_history", "snapshot", SchemaColumnRole::DerivedOrEphemeralObjectRef),
    ("view_file_history", "change", SchemaColumnRole::DerivedOrEphemeralObjectRef),
    ("view_graph", "snapshot", SchemaColumnRole::DerivedOrEphemeralObjectRef),
    ("view_graph", "parents", SchemaColumnRole::DerivedOrEphemeralObjectRef),
    ("view_graph", "skip", SchemaColumnRole::DerivedOrEphemeralObjectRef),
    ("view_graph", "down_id", SchemaColumnRole::DerivedOrEphemeralObjectRef),
    ("view_graph", "real_id", SchemaColumnRole::DerivedOrEphemeralObjectRef),
    // GC bookkeeping (`GcBookkeeping`):
    ("unreferenced_objects", "object_id", SchemaColumnRole::GcBookkeeping),
];

/// Non-object columns across every table in `public`.
pub const NON_OBJECT_SCHEMA_COLUMNS: &[(&str, &[&str])] = &[
    ("access_epochs", &["project_id", "person_id", "epoch", "changed_at"]),
    ("audit_log", &["id", "project_id", "at", "actor", "action", "details"]),
    ("bisect_leases", &["project_id", "branch", "holder", "epoch", "expires_at"]),
    ("bisect_reverts", &["project_id", "branch", "lineage", "check_name", "ticket", "state", "created_at", "culprit_change_id", "culprit_patch"]),
    ("bisects", &["project_id", "branch", "lineage", "check_name", "lo", "hi", "phase", "culprit_fails", "parent_passes", "confirm_requested_at", "session_paths", "admin_only", "revert_ticket", "created_at", "updated_at"]),
    ("blame_ends", &["project_id", "view_key", "path_key", "follow", "held", "kept_bytes", "path_keys", "created_at"]),
    ("blame_jobs", &["project_id", "view_key", "path_key", "follow", "holder", "expires_at"]),
    ("blame_memo", &["project_id", "view_key", "path_key", "follow", "body", "bytes", "created_at", "path_keys"]),
    ("blame_paths", &["project_id", "path_key", "path"]),
    ("branches", &["project_id", "name", "lineage", "hidden_for_embargo", "changes_recorded"]),
    ("browser_device_rings", &["device_id", "project_id", "scope", "body"]),
    ("challenges", &["challenge", "signing_key", "expires_at"]),
    ("change_refs", &["project_id", "change_id", "created_by", "created_at"]),
    ("checks", &["project_id", "name", "state", "summary", "url", "log", "runner_id", "runner_name", "session_paths", "admin_only", "updated_at", "run_count"]),
    ("derive_progress", &["project_id", "index_name", "index_version", "branch"]),
    ("device_bars", &["project_id", "device_id", "created_at"]),
    ("device_expected", &["person_id", "fingerprint", "expires_at"]),
    ("device_vouches", &["device_id", "voucher_key", "signature", "created_at"]),
    ("devices", &["id", "person_id", "signing_key", "public_identity", "created_at", "removed_at", "pending", "fingerprint", "browser", "prf_supported"]),
    ("embargo_lines", &["project_id", "embargo_id", "group_names", "target_branch", "embargo_branch", "until_ms", "released_at", "created_by", "created_at", "has_pr"]),
    ("embargo_snapshots", &["project_id", "embargo_id"]),
    ("file_history", &["project_id", "path_key", "depth"]),
    ("graph", &["project_id", "generation", "depth", "change_id", "flags"]),
    ("group_managers", &["group_id", "person_id"]),
    ("group_members", &["group_id", "person_id"]),
    ("groups", &["id", "project_id", "name"]),
    ("invites", &["project_id", "invite_key", "person", "group_id", "expires_at", "created_by", "created_at", "used_at", "device_id", "signature"]),
    ("key_requests", &["project_id", "person_id", "created_at"]),
    ("landed_changes", &["project_id", "branch", "lineage", "change_id", "author"]),
    ("landed_from", &["project_id"]),
    ("landing_leases", &["project_id", "branch", "holder", "epoch", "expires_at", "served", "lock_epoch"]),
    ("landing_queue", &["project_id", "branch", "seq", "ticket", "person_id", "person_name", "device_key", "lineage", "person_epoch", "project_epoch", "state", "created_at", "done_at", "merges", "agent_session", "session", "priority", "person_slot", "session_slot"]),
    ("landings", &["project_id", "branch", "lineage", "at"]),
    ("log_cursors", &["project_id", "view_key", "id", "created_at"]),
    ("origins", &["project_id"]),
    ("packs", &["project_id", "name", "state", "person_id", "size", "objects", "created_at", "discarded_at"]),
    ("people", &["id", "name", "created_at"]),
    ("pr_classes", &["project_id", "class_id", "policy_key", "lines", "embargo"]),
    ("pr_comments", &["project_id", "pr", "thread", "id", "author", "body", "at"]),
    ("pr_embargo_holds", &["project_id", "embargo", "person", "path", "pr", "at"]),
    ("pr_holds", &["project_id", "person", "path", "pr", "at"]),
    ("pr_paths", &["project_id", "pr", "path"]),
    ("pr_review_rules", &["project_id", "state"]),
    ("pr_reviews", &["project_id", "pr", "revision", "person", "verdict", "patch", "agent", "device", "signature", "body", "at"]),
    ("pr_revisions", &["project_id", "pr", "n", "patch", "files", "risk", "reasons", "rules_key", "files_count", "pushed_by", "at"]),
    ("pr_threads", &["project_id", "pr", "id", "anchor", "now_at", "state", "author", "created_at"]),
    ("project_admins", &["project_id", "person_id"]),
    ("projections", &["project_id", "view_key", "created_at", "collapsed"]),
    ("projects", &["id", "name", "created_by", "created_at", "default_branch", "policy_text", "policy_bindings", "policy_version", "web_secrets"]),
    ("prs", &["project_id", "id", "class_id", "policy_key", "target", "source_branch", "author", "title", "body", "state", "revision", "created_at", "updated_at", "embargo", "land_at_release"]),
    ("review_writers", &["id", "project_id", "since_ms"]),
    ("rings", &["project_id", "scope", "body"]),
    ("rule_history", &["project_id", "line_key", "generation"]),
    ("rule_lines", &["project_id", "line_key", "ready"]),
    ("schema_migrations", &["version", "name", "applied_at"]),
    ("search_heads", &["project_id", "kind", "branch", "lines", "version"]),
    ("search_shards", &["project_id", "kind", "branch", "line_key", "docs", "text_docs", "text_bytes", "dead"]),
    ("secret_share_quota", &["project_id", "sharer_id", "used"]),
    ("secret_shares", &["project_id", "path", "sharer_id", "recipient_id", "version", "created_at", "updated_at", "unshared_at", "body"]),
    ("sessions", &["token_hash", "device_id", "person_id", "expires_at", "agent", "agent_project", "agent_only", "parent_hash", "agent_runner"]),
    ("snapshots", &["project_id", "author"]),
    ("tested", &["project_id", "branch", "lineage", "depth", "updated_at"]),
    ("unreferenced_objects", &["project_id", "since_ms"]),
    ("view_access", &["project_id", "access", "changed_at"]),
    ("view_changes", &["project_id", "view_key", "change_id", "flags"]),
    ("view_file_history", &["project_id", "view_key", "path_key", "depth"]),
    ("view_fills", &["project_id", "view_key", "holder", "expires_at"]),
    ("view_graph", &["project_id", "view_key", "generation", "depth", "flags", "files"]),    ("web_enrollments", &["code_hash", "person_id", "label", "created_at", "expires_at", "used_at"]),
    ("webauthn_challenges", &["challenge", "kind", "person_id", "code_hash", "prf_salt", "origin", "rp_id", "expires_at", "address"]),
    ("webauthn_credentials", &["credential_id", "person_id", "device_id", "alg", "public_key", "sign_count", "prf_salt", "created_at", "label"]),
];

/// Look up the registered [`SchemaColumnRole`] of `(table, column)` in `public`.
pub fn classify_schema_column(table: &str, column: &str) -> Option<SchemaColumnRole> {
    for &(t, c, role) in OBJECT_SCHEMA_COLUMNS {
        if t == table && c == column {
            return Some(role);
        }
    }
    for &(t, cols) in NON_OBJECT_SCHEMA_COLUMNS {
        if t == table && cols.contains(&column) {
            return Some(SchemaColumnRole::NonObject);
        }
    }
    None
}

/// Compare `information_schema.columns` (`table_schema = 'public'`) against
/// `pack_gc`'s registered schema columns, returning `(unregistered_in_db,
/// missing_from_db)`.
pub async fn audit_schema_columns(
    c: &mut PgConnection,
) -> Result<(Vec<(String, String, String)>, Vec<(String, String)>)> {
    let actual: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT table_name::text, column_name::text, data_type::text \
         FROM information_schema.columns \
         WHERE table_schema = 'public' \
         ORDER BY table_name, column_name",
    )
    .fetch_all(&mut *c)
    .await?;

    let mut actual_set: HashSet<(&str, &str)> = HashSet::with_capacity(actual.len());
    let mut unregistered = Vec::new();
    for (t, col, dt) in &actual {
        actual_set.insert((t.as_str(), col.as_str()));
        if classify_schema_column(t, col).is_none() {
            unregistered.push((t.clone(), col.clone(), dt.clone()));
        }
    }

    let mut missing = Vec::new();
    let mut seen_reg = HashSet::new();
    for &(t, col, _) in OBJECT_SCHEMA_COLUMNS {
        if !seen_reg.insert((t, col)) || !actual_set.contains(&(t, col)) {
            missing.push((t.to_string(), col.to_string()));
        }
    }
    for &(t, cols) in NON_OBJECT_SCHEMA_COLUMNS {
        for &col in cols {
            if !seen_reg.insert((t, col)) || !actual_set.contains(&(t, col)) {
                missing.push((t.to_string(), col.to_string()));
            }
        }
    }
    Ok((unregistered, missing))
}

async fn collect_db_roots(c: &mut PgConnection, project: i64) -> Result<DbRoots> {
    let mut r = DbRoots::default();

    // 1. All registered `SchemaColumnRole::GcRoot` columns across every table
    // (`branches`, `embargo_snapshots`, `embargo_lines`, `change_refs`,
    // `landing_queue`, `landings`, `checks`, `tested`, `pr_revisions`,
    // `pr_review_rules`, `bisects`, `bisect_reverts`, and any future table
    // registered as `GcRoot`), grouped per table in one UNION ALL query.
    let mut root_tables: Vec<(&str, Vec<&str>)> = Vec::new();
    for &(table, col, role) in OBJECT_SCHEMA_COLUMNS {
        if role == SchemaColumnRole::GcRoot {
            if let Some((_, cols)) = root_tables.iter_mut().find(|(t, _)| *t == table) {
                cols.push(col);
            } else {
                root_tables.push((table, vec![col]));
            }
        }
    }
    let union_arms: Vec<String> = root_tables
        .iter()
        .map(|(table, cols)| {
            let expr = if cols.len() == 1 {
                format!("{}::text", cols[0])
            } else {
                let cast_cols: Vec<String> = cols.iter().map(|c| format!("{c}::text")).collect();
                format!("concat_ws(' ', {})", cast_cols.join(", "))
            };
            let non_null: Vec<String> = cols.iter().map(|c| format!("{c} IS NOT NULL")).collect();
            format!(
                "SELECT {expr} FROM {table} WHERE project_id = $1 AND ({})",
                non_null.join(" OR ")
            )
        })
        .collect();
    let root_sql = union_arms.join(" UNION ALL ");
    let root_vals: Vec<String> = sqlx::query_scalar(&root_sql)
        .bind(project)
        .fetch_all(&mut *c)
        .await?;
    for val in root_vals {
        collect_hex_ids_from_json(&val, &mut r.walk_objects);
    }

    // 2. Optional dynamic `tags` table if created by a test or future feature.
    for col in ["target", "snapshot", "atag"] {
        if table_has_column(c, "tags", col).await? {
            let query = format!("SELECT {col}::text FROM tags WHERE project_id = $1 AND {col} IS NOT NULL");
            let vals: Vec<String> = sqlx::query_scalar(&query).bind(project).fetch_all(&mut *c).await?;
            for v in vals {
                collect_hex_ids_from_json(&v, &mut r.walk_objects);
            }
        }
    }

    // 3. Known snapshots, origins, and projection memos.
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

    // 4. S12 `graph.changed` objects for reachable snapshots.
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

    // 5. S15 `search_shards.segments` for live branches and the project-wide
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

/// Traverse the object graph from `initial`, expanding snapshots (trees,
/// parents, predecessors, S11 `attempts`, `origins`, `projections`, S12
/// `graph.changed`), trees (subtrees, blobs, sealed blobs, conflicts), and
/// annotated tags (`Atag`), and stopping at what `marks` already holds
/// (its closed set) and at what an earlier walk could not read
/// (`Marks::unread`). What it reads joins the set; what it cannot read is
/// noted. What a tree names as a file, and a conflict as a term, is kept
/// as a leaf and not read; an object so named that the walk also meets as
/// a directory, a parent or a root is read and expanded as what it is
/// (`Marks::leaves`, BUG-2622).
///
/// `limit`: the most objects it may read (BUG-2602: under a switch's
/// lock, where it does not yield to requests either). Answers the objects
/// it read, or `None` past the limit: the set is then no longer closed.
async fn walk_from_roots(
    hub: &Arc<Hub>,
    project: i64,
    initial: impl IntoIterator<Item = ObjectId>,
    marks: &mut Marks,
    roots: &DbRoots,
    limit: Option<usize>,
) -> Result<Option<usize>> {
    let mut queue: VecDeque<ObjectId> = initial.into_iter().collect();
    let mut reads = 0usize;
    let Marks { reachable, unread, leaves, fault, .. } = marks;

    while let Some(id) = queue.pop_front() {
        if builtin(&id).is_some() || reachable.contains(&id) || unread.contains(&id) {
            continue;
        }
        if limit.is_some_and(|l| reads >= l) {
            return Ok(None);
        }
        reads += 1;
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
            leaves.insert(ch);
        }

        if limit.is_none() {
            hub.limits.derive_turn().await;
        } else if let Some(fault) = fault {
            (fault.0)(FaultPoint::SwitchRead, id).await?;
        }
        let cost = hub.objects.read_cost(project, &id, 0).await.unwrap_or(4096);
        let _ra = ReadAhead::wait(cost).await;
        let Some(raw) = hub.objects.get(project, &id).await.map_err(Error::Other)? else {
            unread.insert(id);
            continue;
        };
        reachable.insert(id);
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
                            leaves.insert(entry.id);
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
                    leaves.insert(term.id);
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

    Ok(Some(reads))
}

/// A READ COMMITTED `db::transaction` of the merges and garbage collection,
/// counted as theirs (`db::Commit::PackGc`) when it commits.
async fn gc_transaction<T, F>(hub: &crate::Hub, f: F) -> Result<T>
where
    F: for<'t> FnMut(&'t mut sqlx::PgConnection) -> crate::db::TxFuture<'t, T>,
{
    let r = crate::db::transaction(&hub.db, crate::db::Isolation::ReadCommitted, f).await;
    if r.is_ok() {
        hub.commits.count(crate::db::Commit::PackGc);
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serving_lock_key_is_disjoint_from_landing_lease_keys() {
        assert!(SERVING_LOCK_KEY.1 < 0, "k2 must stay negative so it never collides with landing lease epochs");
        for project in [0, 1, 2, -1, i64::MAX] {
            for epoch in [0, 1, 42, i64::MAX, -1] {
                let k = crate::landing::lease_lock::key(project, "main", epoch);
                assert!(k.1 >= 0);
                assert_ne!(k, SERVING_LOCK_KEY);
            }
        }
    }
}
