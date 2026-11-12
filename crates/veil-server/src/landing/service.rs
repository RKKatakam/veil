//! One branch's landing service (`docs/design/server/phase-4-agent-scale.md`
//! §4.2): the lease, batches, the fast path, the landing check, pipelining
//! and one database commit per batch.
//!
//! ```text
//! loop:
//!   entries := the ready queue rows not in the batch being committed, in order,
//!              at most MAX_BATCH, and at most BATCH_BYTES of new objects held
//!              (the batch being committed counted too)
//!   build on the tip the batch being committed leaves (pipelined), in memory:
//!     an entry that changes .veilpolicy or .veilrules ends the batch before it, and lands alone
//!     access changed since the submit (epochs): write access first, before anything about the tip
//!     for each change of an entry's stack:
//!       on the tip already: it lands as it is
//!       else: the fast path (every edited path as its base had it) or `conflict`;
//!             apply its edits; the landing check; a new snapshot, signed by the server
//!       access changed, or the tip's .veilpolicy differs from its base's: the push's
//!       checks again (`sync::complete`) on the new parents
//!     projections of every new snapshot, onto each kept view key's last memo (never a walk)
//!   wait for the batch being committed; if it lost (the tip moved, the lease was lost): discard, start again
//!   store the new objects, then one transaction: the lease's epoch (fencing), the queue rows
//!   (still queued, or nothing lands), snapshots, projection memos, the branch's compare-and-swap
//! ```
//!
//! **Projections without walks** (BUG-1100, BUG-1106). The service keeps,
//! for each view key of the project's people (and anyone on Earth's), the
//! projection of its tip, and projects each new snapshot onto it. A key it
//! does not keep is attached from its newest memo on the branch's recent
//! first-parent line (the last [`RECENT`] snapshots this service knows),
//! projecting only what came after; a key with no memo there is handed to
//! S13's background fill (`query::graph::prefill`), and its submitters'
//! answers are projected by their own requests. Every projection the
//! service makes is stored in the batch's commit, and a stored memo always
//! wins: one written meanwhile with another value rolls the batch back.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque},
    sync::{atomic::Ordering, Arc},
    time::{Duration, Instant},
};

use bytes::Bytes;
use tokio::sync::Notify;
use veil_core::{
    hub::{
        access::AccessPolicy,
        land::{LandResult, LandState},
        project::{Change, Projector},
    },
    object::{Object, Snapshot},
    policy::POLICY_FILE,
    ObjectId,
};

use super::{edits, rules::RULES_FILE, Entry, LEASE_MS, MAX_BATCH};
use crate::{
    auth::{Caller, Person},
    caches::Epochs,
    error::{Error, Result},
    perm::{Project, Viewer},
    sync::{self, Source},
    Hub,
};

/// How long a service with nothing to land keeps its lease.
const IDLE: Duration = Duration::from_secs(5);
/// Renew the lease this often while idle (a batch's transaction renews it).
const RENEW: Duration = Duration::from_millis(500);
/// View keys whose projections a service keeps up to date, at most.
const MAX_KEYS: usize = 64;
/// The recent first-parent line a view key is attached from.
const RECENT: usize = 1024;
/// Most bytes of new objects a batch holds, with the batch being committed
/// (BUG-1107): an entry is left for the next batch past it (the first
/// entry of a batch always goes). Decoded, a folder listing takes about
/// three times its bytes, and each change in a big folder decodes several:
/// 8 MiB keeps 400 changes in a 30,000-file folder near 200 MiB in all,
/// while ordinary changes (a few KiB of listings each) still fill batches
/// of hundreds.
pub const BATCH_BYTES: usize = 8 << 20;
/// Most projections one batch makes to attach view keys (each over what
/// came after its memo on the recent line); a key past it is the
/// background fill's.
pub const ATTACH_BUDGET: usize = 256;
/// Most bytes a batch's content merges read (the three versions of each
/// file merged; BUG-1956): the batch ends before an entry that needs more,
/// which a later batch merges whatever its size once it comes first in it
/// (`docs/HUB.md` §13.30; each file is at most
/// `merge::MAX_MERGE_FILE_BYTES`). A line merge's cost is linear in what it
/// reads (`veil_core::textmerge`).
const MERGE_BYTES: usize = 4 << 20;
/// A view key with no memo on the recent line is handed to the background
/// fill at most this often.
const PREFILL_EVERY: Duration = Duration::from_secs(5);
/// Finished queue rows (a ticket's outcome) and `landings` rows are kept
/// this long, then deleted (BUG-1303): every [`CLEAN_EVERY`], also while the
/// branch is busy, at most [`CLEAN_CHUNK`] of each table a pass (4,000 rows
/// a second: four times what 1,000 landings a second add). At 1,000
/// landings a second, an hour is about 3.6 million rows in each.
const KEEP_DONE_MS: i64 = 3600 * 1000;
const CLEAN_EVERY: Duration = Duration::from_secs(5);
const CLEAN_CHUNK: i64 = 20_000;

/// The database's clock, in milliseconds.
const DB_NOW: &str = "(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT";

/// Take the lease of `branch`: its fencing epoch, or `None` while another
/// server holds it.
async fn take_lease(hub: &Hub, project: i64, branch: &str) -> Result<Option<i64>> {
    Ok(sqlx::query_scalar(&format!(
        "INSERT INTO landing_leases (project_id, branch, holder, epoch, expires_at) VALUES ($1, $2, $3, 1, {DB_NOW} + $4) \
         ON CONFLICT (project_id, branch) DO UPDATE SET holder = EXCLUDED.holder, epoch = landing_leases.epoch + 1, \
         expires_at = EXCLUDED.expires_at WHERE landing_leases.expires_at < {DB_NOW} OR landing_leases.holder = EXCLUDED.holder \
         RETURNING epoch"
    ))
    .bind(project)
    .bind(branch)
    .bind(&hub.landing.holder)
    .bind(LEASE_MS)
    .fetch_optional(&hub.db)
    .await?)
}

/// Renew the lease; `false` if it was lost.
async fn renew(hub: &Hub, project: i64, branch: &str, epoch: i64) -> Result<bool> {
    let n = sqlx::query(&format!(
        "UPDATE landing_leases SET expires_at = {DB_NOW} + $5 WHERE project_id = $1 AND branch = $2 AND holder = $3 AND epoch = $4"
    ))
    .bind(project)
    .bind(branch)
    .bind(&hub.landing.holder)
    .bind(epoch)
    .bind(LEASE_MS)
    .execute(&hub.db)
    .await?
    .rows_affected();
    Ok(n == 1)
}

/// Is anything queued or merging for `branch`?
pub(super) async fn has_ready(hub: &Hub, project: i64, branch: &str) -> Result<bool> {
    let n: Option<i64> = sqlx::query_scalar("SELECT seq FROM landing_queue WHERE project_id = $1 AND branch = $2 AND state IN ('queued', 'merging') LIMIT 1")
        .bind(project)
        .bind(branch)
        .fetch_optional(&hub.db)
        .await?;
    Ok(n.is_some())
}

/// A queue row.
#[derive(Clone)]
struct Row {
    seq: i64,
    ticket: String,
    person: Person,
    /// Each change with its base (`landing::stack`).
    stack: Vec<Entry>,
    /// The branch's lineage its stack was judged under.
    lineage: i64,
    epochs: (i64, i64),
    merges: u32,
    agent_session: Option<String>,
}

/// Per-entry review check state (`BUG-1880`): what `prs::verify_landing_review`
/// is asked again inside the batch's transaction.
#[derive(Clone)]
struct EntryReviewCheck {
    project: Arc<Project>,
    viewer: Viewer,
    diff: crate::prs::StackReviewDiff,
    claim: Option<super::ReviewClaim>,
}

/// Batch-level review rules state verified inside `Service::commit`'s single
/// transaction (`BUG-1880`).
#[derive(Clone)]
struct BatchReviewGuard {
    ctx: crate::prs::BranchReviewContext,
    project_epoch: i64,
    protected: bool,
    /// The server has reverted some change of the project twice: such a
    /// change needs a person's approval on any branch (BUG-1884).
    reverted_twice: bool,
}

/// Metadata of a row in a built batch.
/// How long a batch's tickets wait for its landed PRs' source branches to
/// be deleted (BUG-1924) before they are resolved; the deletion goes on.
const PR_CLEANUP_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

#[derive(Clone)]
struct RowMeta {
    seq: i64,
    ticket: String,
    person_id: i64,
    merges: u32,
    change_id: Option<veil_core::ChangeId>,
    agent_session: Option<String>,
    epochs: (i64, i64),
    user_entry: bool,
    review_check: Option<EntryReviewCheck>,
    /// The PR this entry lands, at its revision (`ReviewClaim::Pr`): the
    /// batch that lands it marks it landed (BUG-1924).
    pr: Option<(String, i32)>,
}

/// Someone a projection is made for, now.
#[derive(Clone)]
struct As {
    project: Arc<Project>,
    viewer: Viewer,
    /// `None` for an admin (who sees real snapshots).
    key: Option<String>,
}

/// A view key the service keeps: one of its viewers (any gives the same
/// view), and the projection of the tip for it.
#[derive(Clone)]
struct Kept {
    who: As,
    at: ObjectId,
}

/// The branch as the service last left it (or predicts it, after the batch
/// being committed).
#[derive(Clone, Default)]
struct State {
    tip: Option<ObjectId>,
    /// The branch's lineage (BUG-1300): moved only within it.
    lineage: i64,
    /// The first-parent line ending at `tip`, oldest first, at most
    /// [`RECENT`] long.
    recent: VecDeque<ObjectId>,
    keys: BTreeMap<String, Kept>,
    /// The objects of the batch that made `tip`, which may not be stored
    /// yet while it commits: the next batch is built on them.
    made: Arc<HashMap<ObjectId, Bytes>>,
    made_bytes: usize,
}

/// The project's view keys, as of its access epoch (re-read when it
/// changes), and when each unkept one was last handed to the fill.
#[derive(Default)]
struct Known {
    epoch: Option<i64>,
    views: BTreeMap<String, As>,
    prefilled: HashMap<String, Instant>,
}

/// An entry ready to build.
#[derive(Clone)]
struct Prepared {
    row: Row,
    who: Result<As, String>,
    /// Access changed since it was submitted: write access is decided first,
    /// and the push's checks run again.
    recheck: bool,
    epochs: (i64, i64),
    review_refusal: Option<String>,
    review_check: Option<EntryReviewCheck>,
}

/// A batch's inputs, read before it is built.
#[derive(Clone)]
struct Inputs {
    entries: Vec<Prepared>,
    /// View keys to attach: `(key, who, position on the recent line, memo there)`.
    attach: Vec<(String, As, usize, ObjectId)>,
    /// Stored memos the batch may need, by `(view key, real)`.
    memo: HashMap<(String, ObjectId), ObjectId>,
    /// Origins (`sync::push`) of the stack snapshots that have one.
    origins: HashMap<ObjectId, ObjectId>,
    /// Stack changes that landed already, in the branch's lineage
    /// (`landings`).
    landed: HashMap<ObjectId, Record>,
    review_guard: Option<BatchReviewGuard>,
}

/// Where a stack change landed already (its edits are on the branch).
#[derive(Clone)]
struct Record {
    landed: ObjectId,
    /// The change (its id) it landed, for `landed_changes` (BUG-1522);
    /// `None` for a record read back or a tip moved from.
    change: Option<String>,
}

/// What one entry came to.
enum Outcome {
    /// Where each change of the stack landed (real snapshots), and whether
    /// any of them was merged by content onto the tip (S18, BUG-1956).
    Landed { reals: Vec<ObjectId>, merged: bool },
    /// Could not be content-merged: conflict report (S18).
    Conflict(super::merge::ConflictReport),
    Rejected(String),
}

/// A batch built in memory.
struct Built {
    rows: Vec<RowMeta>,
    outcomes: Vec<Outcome>,
    objects: Vec<(ObjectId, Bytes)>,
    bytes: usize,
    /// How many times the objects held were stored mid-build (`flush`).
    flushes: usize,
    /// Bytes of every new object of the batch, stored mid-build or not:
    /// what decides whether another entry joins it.
    made: usize,
    snapshots: Vec<ObjectId>,
    /// The other parents of the merges landed: the lines they bring onto
    /// the branch, of snapshots the server already held (BUG-1524).
    merged: Vec<ObjectId>,
    /// Stack changes landed: `(submitted, landed, record)`.
    landings: Vec<(ObjectId, Record)>,
    /// New memo rows `(view key, real, projected)`.
    memos: Vec<(String, ObjectId, ObjectId, bool)>,
    old_tip: Option<ObjectId>,
    after: State,
    /// It changed `.veilpolicy` or `.veilrules`: landed alone.
    alone: bool,
    /// What its content merges read (`MERGE_BYTES`).
    merge_read: usize,
    /// The default branch's new access lines, for its one entry.
    accept: Option<String>,
    /// The default branch's `.veilrules` at the new tip (S21).
    rules_file: Option<crate::prs::state::RulesFile>,
    review_guard: Option<BatchReviewGuard>,
}

impl Built {
    fn object(&mut self, src: &mut Source, id: ObjectId, raw: Bytes) {
        self.bytes += raw.len();
        self.made += raw.len();
        src.pending.insert(id, raw.clone());
        self.objects.push((id, raw));
    }

    /// Once the objects held (with the batch being committed's, `before`)
    /// pass [`BATCH_BYTES`], store them now and hold them no longer: no
    /// entry and no batch, its first included, holds more (BUG-1107,
    /// BUG-1272). Objects stored for an entry that then does not land are
    /// unreferenced, as a discarded batch's are.
    fn flush(&mut self, hub: &Arc<Hub>, src: &mut Source, before: usize) -> Result<()> {
        if before + self.bytes < BATCH_BYTES || self.objects.is_empty() {
            return Ok(());
        }
        let t = Instant::now();
        let objects = std::mem::take(&mut self.objects);
        for (id, _) in &objects {
            src.pending.remove(id);
        }
        src.rt.block_on(sync::put_all(hub, src.project, objects))?;
        hub.landing.stats.store_us.fetch_add(t.elapsed().as_micros() as u64, Ordering::Relaxed);
        self.bytes = 0;
        self.flushes += 1;
        Ok(())
    }
}

/// A batch's objects being stored (`sync::put_all`): its transaction runs
/// meanwhile and waits for them only before it commits (BUG-1955: the
/// store and then the transaction, one after the other, were the service's
/// longest step). Waited once; a transaction run again finds the outcome.
enum Storing {
    Running(tokio::task::JoinHandle<Result<()>>),
    Stored,
    Failed(String),
}

impl Storing {
    async fn wait(this: &tokio::sync::Mutex<Storing>) -> Result<()> {
        let mut s = this.lock().await;
        if let Storing::Running(task) = &mut *s {
            *s = match task.await {
                Ok(Ok(())) => Storing::Stored,
                Ok(Err(e)) => Storing::Failed(format!("{e:?}")),
                Err(e) => Storing::Failed(e.to_string()),
            };
        }
        match &*s {
            Storing::Failed(e) => Err(Error::Other(anyhow::anyhow!("storing the batch's objects: {e}"))),
            _ => Ok(()),
        }
    }
}

/// `f` as [`crate::db::transaction`] takes it, so that it can be passed by
/// reference and run again.
fn tx_fn<T, F>(f: F) -> F
where
    F: for<'t> FnMut(&'t mut sqlx::PgConnection) -> crate::db::TxFuture<'t, T>,
{
    f
}

/// How a batch's commit ended.
enum Committed {
    Ok,
    /// The branch moved under it (an admin's forced push), or a memo was
    /// stored meanwhile with another value: nothing landed; built again
    /// from the database.
    Moved,
    /// Another server took the lease: stop.
    LeaseLost,
}

/// Run the service of `branch` while it has work, then release the lease.
/// `Ok(true)`: another server holds the lease.
pub(super) async fn run(hub: &Arc<Hub>, project: i64, branch: &str, wake: Arc<Notify>) -> Result<bool> {
    if hub.landing.stopping() {
        return Ok(false);
    }
    let Some(epoch) = take_lease(hub, project, branch).await? else { return Ok(true) };
    let name: Option<String> = sqlx::query_scalar("SELECT name FROM projects WHERE id = $1").bind(project).fetch_optional(&hub.db).await?;
    let Some(name) = name else { return Ok(false) };
    let s = Service {
        hub: hub.clone(),
        project,
        name,
        branch: branch.to_string(),
        epoch,
        won: Default::default(),
    };
    let r = s.run(wake).await;
    let _ = sqlx::query("UPDATE landing_leases SET expires_at = 0 WHERE project_id = $1 AND branch = $2 AND holder = $3 AND epoch = $4")
        .bind(project)
        .bind(branch)
        .bind(&hub.landing.holder)
        .bind(epoch)
        .execute(&hub.db)
        .await;
    r.map(|_| false)
}

struct Service {
    hub: Arc<Hub>,
    project: i64,
    name: String,
    branch: String,
    epoch: i64,
    /// Stored memos that won over a batch's own (`MEMO_RACE`): the batch
    /// built again uses them, so it lands with what is stored instead of
    /// racing it again (a snapshot made again exactly as one landed before,
    /// whose projections were stored then).
    won: Arc<std::sync::Mutex<HashMap<(String, ObjectId), ObjectId>>>,
}

/// A batch being committed.
struct InFlight {
    task: tokio::task::JoinHandle<Result<Committed>>,
    seqs: HashSet<i64>,
    alone: bool,
    after: State,
}

impl Service {
    async fn run(&self, wake: Arc<Notify>) -> Result<()> {
        let mut state = self.load().await?;
        let mut known = Known::default();
        let mut last_gc_epoch: Option<i64> = None;
        let mut inflight: Option<InFlight> = None;
        let mut idle = Instant::now();
        let mut renewed = Instant::now();
        let mut cleaned: Option<Instant> = None;
        loop {
            // A clean stop (BUG-1970): the batch being committed ends, and
            // nothing more is built; `run` then gives the lease up.
            if self.hub.landing.stopping() {
                if let Some(f) = inflight.take() {
                    self.finish(f, &mut state).await?;
                }
                return Ok(());
            }
            // A change of access or rules is committed before anything is
            // built after it: later entries are checked against it.
            if inflight.as_ref().is_some_and(|f| f.alone) {
                if !self.finish(inflight.take().expect("checked"), &mut state).await? {
                    return Ok(());
                }
                continue;
            }
            // Retention runs whether or not the branch is busy (BUG-1303).
            if cleaned.is_none_or(|t| t.elapsed() > CLEAN_EVERY) {
                self.clean().await?;
                cleaned = Some(Instant::now());
            }
            let has_merging = self.reclaim_expired_merges().await?;
            let exclude = inflight.as_ref().map(|f| f.seqs.clone()).unwrap_or_default();
            let rows = self.ready(&exclude).await?;
            if rows.is_empty() {
                if let Some(f) = inflight.take() {
                    if !self.finish(f, &mut state).await? {
                        return Ok(());
                    }
                    continue;
                }
                if has_merging {
                    idle = Instant::now();
                } else if idle.elapsed() > IDLE {
                    return Ok(());
                }
                let _ = tokio::time::timeout(Duration::from_millis(250), wake.notified()).await;
                if renewed.elapsed() > RENEW {
                    if !renew(&self.hub, self.project, &self.branch, self.epoch).await? {
                        return Ok(());
                    }
                    renewed = Instant::now();
                }
                continue;
            }
            idle = Instant::now();
            let gc_epoch = crate::pack_gc::read_gc_epoch(&self.hub, self.project).await?;
            if last_gc_epoch.replace(gc_epoch) != Some(gc_epoch) {
                known = Known::default();
            }
            // The batch being committed holds its objects; a committed one's
            // are stored (BUG-1107).
            let on = inflight.as_ref().map(|f| f.after.clone()).unwrap_or_else(|| State { made_bytes: 0, ..state.clone() });
            let t = Instant::now();
            let inputs = self.prepare(rows, &on, state.tip, &mut known).await?;
            self.hub.landing.stats.prepare_us.fetch_add(t.elapsed().as_micros() as u64, Ordering::Relaxed);
            let t = Instant::now();
            // The lease is renewed while the batch builds (its merges may take
            // a while, BUG-1956): a build never outlives it, to be fenced and
            // built again by the next holder, and again.
            let built = {
                let build = self.build(inputs, on, build_threads());
                tokio::pin!(build);
                loop {
                    tokio::select! {
                        built = &mut build => break built?,
                        _ = tokio::time::sleep(RENEW) => {
                            renew(&self.hub, self.project, &self.branch, self.epoch).await?;
                        }
                    }
                }
            };
            // Stopping: built for nothing (the batch being committed ends at
            // the top of the loop).
            if self.hub.landing.stopping() {
                continue;
            }
            self.hub.landing.stats.build_us.fetch_add(t.elapsed().as_micros() as u64, Ordering::Relaxed);
            // Its objects are stored while the batch before it commits (they
            // are content-addressed: stored for a batch that is then
            // discarded, they are unreferenced, as a refused push's are).
            let store = {
                let (hub, project, objects) = (self.hub.clone(), self.project, built.objects.clone());
                tokio::spawn(async move {
                    let t = Instant::now();
                    let r = sync::put_all(&hub, project, objects).await;
                    hub.landing.stats.store_us.fetch_add(t.elapsed().as_micros() as u64, Ordering::Relaxed);
                    r
                })
            };
            if let Some(f) = inflight.take() {
                if !self.finish(f, &mut state).await? {
                    return Ok(());
                }
                // Built on a tip that did not come to be (the batch before
                // it lost): discarded, and built again from the database's.
                if state.tip != built.old_tip {
                    continue;
                }
            }
            if built.rows.is_empty() {
                continue;
            }
            renewed = Instant::now();
            let seqs = built.rows.iter().map(|r| r.seq).collect();
            let (alone, after) = (built.alone, built.after.clone());
            let s = Arc::new(self.clone_handle());
            let task = tokio::spawn(async move { s.commit(built, gc_epoch, Arc::new(tokio::sync::Mutex::new(Storing::Running(store)))).await });
            inflight = Some(InFlight { task, seqs, alone, after });
        }
    }

    fn clone_handle(&self) -> Service {
        Service {
            hub: self.hub.clone(),
            project: self.project,
            name: self.name.clone(),
            branch: self.branch.clone(),
            epoch: self.epoch,
            won: self.won.clone(),
        }
    }

    /// Finished rows, and `landings` rows, of the whole project (so a
    /// deleted branch's go too) older than [`KEEP_DONE_MS`] go, at most
    /// [`CLEAN_CHUNK`] of each.
    async fn clean(&self) -> Result<()> {
        let before = veil_core::now_millis() - KEEP_DONE_MS;
        sqlx::query(
            "DELETE FROM landing_queue WHERE (project_id, branch, seq) IN (SELECT project_id, branch, seq FROM landing_queue \
             WHERE project_id = $1 AND done_at < $2 AND state NOT IN ('queued', 'merging') LIMIT $3)",
        )
        .bind(self.project)
        .bind(before)
        .bind(CLEAN_CHUNK)
        .execute(&self.hub.db)
        .await?;
        sqlx::query(
            "DELETE FROM landings WHERE (project_id, branch, lineage, submitted) IN (SELECT project_id, branch, lineage, submitted \
             FROM landings WHERE project_id = $1 AND at < $2 LIMIT $3)",
        )
        .bind(self.project)
        .bind(before)
        .bind(CLEAN_CHUNK)
        .execute(&self.hub.db)
        .await?;
        Ok(())
    }

    /// Wait for the batch being committed: `state` becomes what it left,
    /// or what the database holds if it lost. `false`: the lease is lost.
    async fn finish(&self, f: InFlight, state: &mut State) -> Result<bool> {
        match f.task.await.map_err(|e| Error::Other(e.into()))? {
            Ok(Committed::Ok) => {
                *state = f.after;
                Ok(true)
            }
            Ok(Committed::Moved) => {
                *state = self.load().await?;
                Ok(true)
            }
            Ok(Committed::LeaseLost) => Ok(false),
            Err(e) => {
                // Nothing of it committed (the transaction rolled back): the
                // entries are still queued, built again from the database.
                if !crate::pack_gc::is_gc_epoch_changed(&e) {
                    eprintln!("veil-server: a landing batch of project {} failed: {e:?}", self.project);
                }
                *state = self.load().await?;
                tokio::time::sleep(Duration::from_millis(50)).await;
                Ok(true)
            }
        }
    }

    /// The branch's tip, from the database (no view key kept yet).
    async fn load(&self) -> Result<State> {
        let t: Option<(String, i64)> =
            sqlx::query_as("SELECT target, lineage FROM branches WHERE project_id = $1 AND name = $2 AND hidden_for_embargo IS NULL")
                .bind(self.project)
                .bind(&self.branch)
                .fetch_optional(&self.hub.db)
                .await?;
        let lineage = t.as_ref().map_or(0, |t| t.1);
        let tip = t.map(|t| ObjectId::from_hex(&t.0).map_err(|e| Error::Other(e.into()))).transpose()?;
        Ok(State {
            tip,
            lineage,
            recent: tip.into_iter().collect(),
            ..State::default()
        })
    }

    /// Reclaim `merging` rows on this branch whose worker claim expired (or had
    /// none), fenced on this service's live branch lease (`BUG-1883`). Returns
    /// whether any live `merging` rows remain on the branch.
    async fn reclaim_expired_merges(&self) -> Result<bool> {
        let (total, expired): (i64, i64) = sqlx::query_as(&format!(
            "SELECT COUNT(*), COUNT(*) FILTER (WHERE result IS NULL OR (result::jsonb->>'expires_at')::BIGINT < {DB_NOW}) \
             FROM landing_queue WHERE project_id = $1 AND branch = $2 AND state = 'merging'"
        ))
        .bind(self.project)
        .bind(&self.branch)
        .fetch_one(&self.hub.db)
        .await?;
        if expired > 0 {
            sqlx::query(&format!(
                "UPDATE landing_queue AS q SET state = 'queued', result = NULL \
                 WHERE q.project_id = $1 AND q.branch = $2 AND q.state = 'merging' \
                   AND (q.result IS NULL OR (q.result::jsonb->>'expires_at')::BIGINT < {DB_NOW}) \
                   AND EXISTS (SELECT 1 FROM landing_leases l WHERE l.project_id = $1 AND l.branch = $2 \
                               AND l.holder = $3 AND l.epoch = $4 AND l.expires_at >= {DB_NOW})"
            ))
            .bind(self.project)
            .bind(&self.branch)
            .bind(&self.hub.landing.holder)
            .bind(self.epoch)
            .execute(&self.hub.db)
            .await?;
        }
        Ok(total > expired)
    }

    /// The ready rows, leaving out those being committed: reverts first
    /// (S20, `priority > 0`, in their order), then the rest in fair-share
    /// order (`limits::landing::fair_batch`, S24 part B), from a bounded
    /// read of the queue (`limits::landing::pick_batch`, BUG-1941).
    async fn ready(&self, exclude: &HashSet<i64>) -> Result<Vec<Row>> {
        let picked = {
            let mut c = self.hub.db.acquire().await?;
            crate::limits::landing::pick_batch(&mut c, self.project, &self.branch, exclude, MAX_BATCH).await?
        };
        let stats = &self.hub.landing.stats;
        stats.pick_statements.fetch_add(picked.statements as u64, Ordering::Relaxed);
        stats.pick_rows.fetch_add(picked.read as u64, Ordering::Relaxed);
        picked
            .rows
            .into_iter()
            .map(|r| {
                Ok(Row {
                    seq: r.seq,
                    ticket: r.ticket,
                    person: Person { id: r.person_id, name: r.person_name, device_key: r.device_key, agent: None },
                    stack: super::decode_stack(&r.stack)?,
                    lineage: r.lineage,
                    epochs: (r.person_epoch, r.project_epoch),
                    merges: r.merges.max(0) as u32,
                    agent_session: r.agent_session,
                })
            })
            .collect()
    }

    /// The project's view keys (what `derive::memo_tips` keeps warm): each
    /// non-admin participant's and anyone on Earth's, at most [`MAX_KEYS`].
    async fn enumerate(&self, known: &mut Known) -> Result<()> {
        let hub = &self.hub;
        let mut c = hub.db.acquire().await?;
        let Some(project) = crate::perm::load_project(&mut c, &self.name).await? else { return Ok(()) };
        let admins: HashSet<i64> = sqlx::query_scalar("SELECT person_id FROM project_admins WHERE project_id = $1")
            .bind(self.project)
            .fetch_all(&mut *c)
            .await?
            .into_iter()
            .collect();
        let members: Vec<(i64, i64)> =
            sqlx::query_as("SELECT m.person_id, g.id FROM group_members m JOIN groups g ON g.id = m.group_id WHERE g.project_id = $1")
                .bind(self.project)
                .fetch_all(&mut *c)
                .await?;
        drop(c);
        let mut people: BTreeMap<i64, HashSet<i64>> = BTreeMap::new();
        for (p, g) in members {
            people.entry(p).or_default().insert(g);
        }
        for b in project.bindings.values() {
            if let crate::perm::Binding::Person(p) = b {
                people.entry(*p).or_default();
            }
        }
        let project = Arc::new(project);
        let mut viewers = vec![Viewer::default()];
        // The service never acts for a session: a session's view key is its
        // person's (`View::key`), and `recheck` re-evaluates only whether the
        // person's access or `.veilpolicy` changed since submit (session
        // narrowing and agent rules were already enforced before queueing).
        viewers.extend(people.into_iter().filter(|(p, _)| !admins.contains(p)).map(|(p, groups)| Viewer {
            person: Some(p),
            admin: false,
            groups,
            only: None,
            agent: false,
        }));
        known.views.clear();
        for v in viewers {
            let view = project.view(&v);
            if !view.sees_anything() {
                continue;
            }
            let key = view.key();
            if known.views.len() < MAX_KEYS && !known.views.contains_key(&key) {
                known.views.insert(key.clone(), As { project: project.clone(), viewer: v, key: Some(key) });
            }
        }
        Ok(())
    }

    /// Who each entry lands as now and whether its checks must run again;
    /// which view keys to attach from the recent line `on.recent`; and the
    /// stored memos and origins the batch will read. Never a walk of
    /// history: a view key with no memo on the recent line is handed to
    /// the background fill, at `committed` (the tip in the database).
    async fn prepare(&self, rows: Vec<Row>, on: &State, committed: Option<ObjectId>, known: &mut Known) -> Result<Inputs> {
        let hub = &self.hub;
        // The access epochs now, of every submitter and of the project, in
        // one statement.
        let people: Vec<i64> = {
            let mut p: Vec<i64> = rows.iter().map(|r| r.person.id).collect();
            p.sort_unstable();
            p.dedup();
            p
        };
        let epochs: Vec<(i64, i64, i64)> = sqlx::query_as(
            "SELECT project_id, person_id, epoch FROM access_epochs WHERE (project_id = 0 AND person_id = ANY($1)) \
             OR (project_id = $2 AND person_id IN (0, -1))",
        )
        .bind(&people)
        .bind(self.project)
        .fetch_all(&hub.db)
        .await?;
        let project_epoch = epochs.iter().find(|e| e.0 == self.project && e.1 == 0).map_or(0, |e| e.2);
        let gc_epoch = epochs.iter().find(|e| e.0 == self.project && e.1 == -1).map_or(0, |e| e.2);
        hub.observe_gc_epoch(self.project, gc_epoch);
        let person_epoch = |p: i64| epochs.iter().find(|e| e.0 == 0 && e.1 == p).map_or(0, |e| e.2);
        if known.epoch != Some(project_epoch) {
            self.enumerate(known).await?;
            known.epoch = Some(project_epoch);
        }
        let mut who: HashMap<(i64, String, Option<String>), Result<As, String>> = HashMap::new();
        let mut grants: HashMap<String, Option<Arc<crate::auth::AgentGrant>>> = HashMap::new();
        let mut entries = Vec::new();
        for mut row in rows {
            if let Some(sh) = &row.agent_session {
                if !grants.contains_key(sh) {
                    let g = crate::auth::load_agent_session(&hub.db, sh, row.person.id, self.project).await?;
                    grants.insert(sh.clone(), g);
                }
                row.person.agent = grants.get(sh).cloned().flatten();
            }
            let k = (row.person.id, row.person.device_key.clone(), row.agent_session.clone());
            if !who.contains_key(&k) {
                let w = if row.agent_session.is_some() && row.person.agent.is_none() {
                    Err("this agent session has expired or been revoked: sign in again".to_string())
                } else {
                    let caller = Caller {
                        person: Some(row.person.clone()),
                        epochs: Epochs {
                            person: person_epoch(row.person.id),
                            project: Some((self.project, project_epoch)),
                            gc: Some((self.project, gc_epoch)),
                        },
                    };
                    match crate::perm::open(hub, &self.name, &caller).await {
                        Ok((p, v)) if p.participant(&v) => {
                            let key = (!v.admin).then(|| p.view(&v).key());
                            Ok(As { project: Arc::new(p), viewer: v, key })
                        }
                        Ok(_) => Err("you are no longer in this project".to_string()),
                        Err(Error::Api { code: "not_found", .. }) => Err("you are no longer in this project".to_string()),
                        Err(Error::Api { message, code: "forbidden", .. }) => Err(message),
                        Err(e) => return Err(e),
                    }
                };
                if let Ok(a) = &w {
                    if let Some(key) = &a.key {
                        if known.views.len() < MAX_KEYS || known.views.contains_key(key) {
                            let mut unnarrowed = a.clone();
                            unnarrowed.viewer.only = None;
                            unnarrowed.viewer.agent = false;
                            known.views.entry(key.clone()).or_insert(unnarrowed);
                        }
                    }
                }
                who.insert(k.clone(), w);
            }
            let w = who[&k].clone();
            let cur_epochs = (person_epoch(row.person.id), project_epoch);
            let recheck = row.epochs != cur_epochs;
            entries.push(Prepared {
                row,
                who: w,
                recheck,
                epochs: cur_epochs,
                review_refusal: None,
                review_check: None,
            });
        }
        // Every entry meets the review rules again here, as its submit did
        // (BUG-1880), an embargo's release among them (BUG-1861: its claim
        // names the embargo whose PRs may carry the approvals). Only the
        // server's own reverts are exempt.
        let is_user_entry = |ticket: &str| !ticket.starts_with("revert-");
        let review_guard = if let Some(first_proj) = entries
            .iter()
            .find(|e| is_user_entry(&e.row.ticket))
            .and_then(|e| e.who.as_ref().ok().map(|a| a.project.clone()))
        {
            let ctx = crate::prs::branch_review_context(hub, &first_proj, &self.branch, on.tip, on.made.clone()).await?;
            let is_protected = ctx.protected.contains(&self.branch);
            // On any branch, a change the server reverted twice needs a
            // person's approval (BUG-1884): the reverts' outcomes first, then
            // whether the project has such a change at all.
            crate::bisect::settle_queued_reverts(hub, self.project).await?;
            let reverted_twice = {
                let mut c = hub.db.acquire().await?;
                crate::bisect::has_reverted_twice(&mut c, self.project).await?
            };
            if is_protected || reverted_twice {
                let pending_stacks: Vec<(usize, Vec<Entry>)> = entries
                    .iter()
                    .enumerate()
                    .filter(|(_, e)| is_user_entry(&e.row.ticket) && e.who.is_ok() && !e.row.stack.is_empty())
                    .map(|(i, e)| (i, e.row.stack.clone()))
                    .collect();
                let diffs: Vec<(usize, crate::prs::StackReviewDiff)> = if pending_stacks.is_empty() {
                    Vec::new()
                } else {
                    // Each stack's diff on its own, on several threads (a
                    // third of a millisecond each, one after another: 22 ms
                    // of a protected branch's batch, BUG-1955); the first
                    // that fails is the batch's error, as before.
                    sync::blocking(hub, self.project, move |src| {
                        on_threads(&pending_stacks, build_threads(), |(i, st)| Ok((*i, crate::prs::stack_review_diff(src, st)?))).into_iter().collect()
                    })
                    .await?
                };
                if !diffs.is_empty() {
                    // All of them in a few statements (BUG-1942).
                    let items: Vec<crate::prs::LandingReview<'_>> = diffs
                        .iter()
                        .filter_map(|(idx, diff)| {
                            let e = &entries[*idx];
                            let a = e.who.as_ref().ok()?;
                            Some(crate::prs::LandingReview {
                                project: &a.project,
                                viewer: &a.viewer,
                                diff,
                                claim: e.row.stack.first().and_then(|x| x.review.as_ref()),
                            })
                        })
                        .collect();
                    let answers = {
                        let mut c = hub.db.acquire().await?;
                        crate::prs::verify_landing_reviews(
                            &mut c,
                            self.project,
                            &self.branch,
                            &ctx.rules,
                            &items,
                            is_protected,
                            reverted_twice,
                            &hub.landing.stats.review_asks,
                        )
                        .await?
                    };
                    drop(items);
                    for ((idx, diff), answer) in diffs.into_iter().zip(answers) {
                        let e = &mut entries[idx];
                        let Ok(a) = &e.who else { continue };
                        match answer {
                            Ok(_) => {
                                e.review_check = Some(EntryReviewCheck {
                                    project: a.project.clone(),
                                    viewer: a.viewer.clone(),
                                    diff,
                                    claim: e.row.stack.first().and_then(|x| x.review.clone()),
                                });
                            }
                            Err(why) => {
                                e.review_refusal = Some(why);
                            }
                        }
                    }
                }
            }
            Some(BatchReviewGuard {
                ctx,
                project_epoch,
                protected: is_protected,
                reverted_twice,
            })
        } else {
            None
        };
        // View keys known and not kept: attached from their newest memo on
        // the recent line, or handed to the background fill.
        let recent: Vec<ObjectId> = on.recent.iter().copied().collect();
        // (A key handed to the fill is looked for again only after a while.)
        let unkept: Vec<(String, As)> = known
            .views
            .iter()
            .filter(|(k, _)| !on.keys.contains_key(*k) && known.prefilled.get(*k).is_none_or(|t| t.elapsed() > PREFILL_EVERY))
            .take(MAX_KEYS.saturating_sub(on.keys.len()))
            .map(|(k, a)| (k.clone(), a.clone()))
            .collect();
        let mut attach = Vec::new();
        if !unkept.is_empty() && !recent.is_empty() {
            let keys: Vec<String> = unkept.iter().map(|u| u.0.clone()).collect();
            let found = memos(hub, self.project, &keys, &recent).await?;
            let mut budget = ATTACH_BUDGET;
            for (k, a) in unkept {
                let newest = recent.iter().enumerate().rev().find_map(|(i, x)| found.get(&(k.clone(), *x)).map(|m| (i, *m)));
                // Each attach projects what came after its memo: within the
                // batch's budget, else the background fill's work.
                let newest = newest.filter(|(i, _)| recent.len() - (i + 1) <= budget);
                match newest {
                    Some((i, m)) => {
                        budget -= recent.len() - (i + 1);
                        attach.push((k, a, i, m))
                    }
                    None => {
                        known.prefilled.insert(k.clone(), Instant::now());
                        hub.landing.stats.prefilled.fetch_add(1, Ordering::Relaxed);
                        if let Some(tip) = committed {
                            if let Err(e) = crate::query::graph::prefill(hub, &a.project, &a.viewer, &[tip]).await {
                                eprintln!("veil-server: queueing a view's fill for project {}: {e:?}", self.project);
                            }
                        }
                    }
                }
            }
        }
        // The memos the batch may read: of the stack snapshots (landed as
        // they are), their other parents and predecessors, and of the other
        // parents and predecessors of the recent snapshots an attached key
        // is projected over; and the stack snapshots' origins.
        let stacks: Vec<ObjectId> = entries.iter().flat_map(|e| e.row.stack.iter().map(|x| x.id)).collect();
        let first_gap = attach.iter().map(|a| a.2 + 1).min().unwrap_or(recent.len());
        let gap: Vec<ObjectId> = recent[first_gap.min(recent.len())..].to_vec();
        let (s2, g2) = (stacks.clone(), gap.clone());
        let mut ids: Vec<ObjectId> = sync::blocking(hub, self.project, move |src| {
            let mut ids = s2.clone();
            for x in s2.iter().chain(&g2) {
                // A recent snapshot may be the batch's being committed, not
                // stored yet: its parents are then on the line itself.
                let Ok(s) = src.snapshot(x) else { continue };
                ids.extend(s.parents.iter().skip(1).copied());
                ids.extend(s.predecessors.iter().copied());
                ids.extend(s.attempts.iter().copied());
            }
            Ok(ids)
        })
        .await?;
        ids.sort_unstable();
        ids.dedup();
        let keys: Vec<String> = on.keys.keys().cloned().chain(attach.iter().map(|a| a.0.clone())).collect();
        let mut memo = match keys.is_empty() || ids.is_empty() {
            true => HashMap::new(),
            false => memos(hub, self.project, &keys, &ids).await?,
        };
        memo.extend(self.won.lock().unwrap().drain());
        // (No origins: a projection equal to a pusher's own snapshot is
        // that pusher's view key's, whose memo the push stored.)
        let origins = HashMap::new();
        // Stack changes (or their pre-merge predecessors) another stack
        // landed already, in the branch's lineage (BUG-1270, BUG-1300).
        let landed: HashMap<ObjectId, Record> = if ids.is_empty() {
            HashMap::new()
        } else {
            let hex: Vec<String> = ids.iter().map(ObjectId::hex).collect();
            let rows: Vec<(String, String)> = sqlx::query_as(
                "SELECT l.submitted, l.landed FROM landings l \
                 WHERE l.project_id = $1 AND l.branch = $3 AND l.lineage = $4 AND l.submitted = ANY($2) \
                 AND NOT EXISTS (SELECT 1 FROM bisect_reverts br WHERE br.project_id = l.project_id AND br.branch = l.branch AND br.lineage = l.lineage AND br.culprit = l.landed AND br.state = 'reverted')",
            )
            .bind(self.project)
            .bind(&hex)
            .bind(&self.branch)
            .bind(on.lineage)
            .fetch_all(&hub.db)
            .await?;
            rows.into_iter().filter_map(|(s, l)| Some((ObjectId::from_hex(&s).ok()?, Record { landed: ObjectId::from_hex(&l).ok()?, change: None }))).collect()
        };
        Ok(Inputs { entries, attach, memo, origins, landed, review_guard })
    }

    /// Build the batch on `on` (on a blocking thread: trees, hashes,
    /// signatures), its entries read ahead on `threads` threads.
    async fn build(&self, inputs: Inputs, on: State, threads: usize) -> Result<Built> {
        let (hub, project, branch) = (self.hub.clone(), self.project, self.branch.clone());
        let rt = tokio::runtime::Handle::current();
        // The default branch's tip, for a landing on another branch: the
        // landed work a change may take there (`sync::Landed`, BUG-1920).
        let default_tip: Option<String> = sqlx::query_scalar(
            "SELECT b.target FROM projects p JOIN branches b ON b.project_id = p.id AND b.name = p.default_branch \
             WHERE p.id = $1 AND p.default_branch <> $2 AND b.hidden_for_embargo IS NULL",
        )
        .bind(project)
        .bind(&branch)
        .fetch_optional(&hub.db)
        .await?;
        let default_tip = match default_tip {
            Some(t) => Some(ObjectId::from_hex(&t).map_err(|e| Error::Other(e.into()))?),
            None => None,
        };
        tokio::task::spawn_blocking(move || build(hub, rt, project, &branch, default_tip, inputs, on, threads)).await.map_err(|e| Error::Other(e.into()))?
    }

    /// Commit the batch (its objects stored already) in one transaction;
    /// then tell the waiters here, spawn merge workers, and emit events.
    async fn commit(&self, b: Built, gc_epoch: i64, stored: Arc<tokio::sync::Mutex<Storing>>) -> Result<Committed> {
        let t = Instant::now();
        let hub = &self.hub;
        let moved = b.after.tip != b.old_tip;
        let results: Vec<LandResult> = b
            .rows
            .iter()
            .zip(&b.outcomes)
            .map(|(meta, o)| match o {
                Outcome::Landed { reals, merged } => {
                    let mut r = super::queued(&meta.ticket);
                    r.state = LandState::Landed;
                    r.landed = reals.clone();
                    r.merges = meta.merges + u32::from(*merged);
                    r
                }
                Outcome::Conflict(report) => report.clone().into_result(&meta.ticket, &self.branch),
                Outcome::Rejected(why) => {
                    let mut r = super::queued(&meta.ticket);
                    r.state = LandState::Rejected;
                    r.message = Some(why.clone());
                    r.merges = meta.merges;
                    r
                }
            })
            .collect();
        let (pid, branch, holder, epoch, name) = (self.project, self.branch.clone(), hub.landing.holder.clone(), self.epoch, self.name.clone());
        let old = b.old_tip.map(|t| t.hex());
        let new = b.after.tip.map(|t| t.hex());
        let seqs: Vec<i64> = b.rows.iter().map(|r| r.seq).collect();
        let snapshots: Vec<String> = b.snapshots.iter().map(ObjectId::hex).collect();
        // The tip this batch moves from is on the branch too: recorded as
        // landed as itself, so a submit on any tip an agent read since the
        // service began finds its base in one lookup (`landing::stack`),
        // never walking the branch nor waiting for the deriver.
        let from = b.old_tip.filter(|_| moved).map(|t| (t, Record { landed: t, change: None }));
        // One row per submitted snapshot.
        let rows: BTreeMap<ObjectId, ObjectId> = b.landings.iter().chain(from.iter()).map(|(s, r)| (*s, r.landed)).collect();
        let ls: Vec<String> = rows.keys().map(ObjectId::hex).collect();
        let ll: Vec<String> = rows.values().map(ObjectId::hex).collect();
        // Each change landed, by its id and author, for the branch's lineage:
        // "already landed" asks it whatever its submitted snapshot (BUG-1522,
        // BUG-1527).
        // The authors the server recorded, of all of them in one statement
        // (they were asked one landing after another, a round trip each:
        // BUG-1955); one it did not record is found as before.
        let recorded: HashMap<ObjectId, (Vec<ObjectId>, i64)> = {
            let hex: Vec<String> = b.landings.iter().filter(|(_, r)| r.change.is_some()).map(|(sid, _)| sid.hex()).collect();
            let rows: Vec<(String, i64)> = match hex.is_empty() {
                true => Vec::new(),
                false => {
                    sqlx::query_as("SELECT id, author FROM snapshots WHERE project_id = $1 AND id = ANY($2) AND author <> 0")
                        .bind(self.project)
                        .bind(&hex)
                        .fetch_all(&hub.db)
                        .await?
                }
            };
            rows.into_iter().filter_map(|(id, a)| Some((ObjectId::from_hex(&id).ok()?, (Vec::new(), a)))).collect()
        };
        let mut snap_authors: HashMap<ObjectId, i64> = HashMap::new();
        let (mut cc, mut ca, mut cl) = (Vec::new(), Vec::new(), Vec::new());
        for (sid, r) in &b.landings {
            if let Some(c) = &r.change {
                if let Some(a) = super::snapshot_author(hub, self.project, *sid, &recorded).await? {
                    snap_authors.insert(r.landed, a);
                    cc.push(c.clone());
                    ca.push(a);
                    cl.push(r.landed.hex());
                }
            }
        }
        let snapshot_authors: Vec<i64> = b.snapshots.iter().map(|s| snap_authors.get(s).copied().unwrap_or(0)).collect();
        let lineage = b.after.lineage;
        // What the merges of the batch bring from other lines: changes of
        // snapshots the server already held, recorded with the batch's own
        // (`landing::reached`, bounded); past the bound the branch's changes
        // are no longer all recorded (BUG-1524).
        let mut recorded = true;
        if moved && !b.merged.is_empty() {
            match super::reached(hub, self.project, &self.branch, b.merged.clone(), b.old_tip).await? {
                Some((l, (c, a, s))) if l == lineage => {
                    cc.extend(c);
                    ca.extend(a);
                    cl.extend(s);
                }
                _ => recorded = false,
            }
        }
        let mk: Vec<String> = b.memos.iter().map(|m| m.0.clone()).collect();
        let mr: Vec<String> = b.memos.iter().map(|m| m.1.hex()).collect();
        let mp: Vec<String> = b.memos.iter().map(|m| m.2.hex()).collect();
        let mc: Vec<bool> = b.memos.iter().map(|m| m.3).collect();
        let accept = b.accept.clone();
        let rules_landing = match (moved, b.after.tip, b.rules_file.clone()) {
            (true, Some(new), Some(file)) => Some(crate::prs::state::Landing {
                old: b.old_tip,
                new,
                file,
                fast_forward: true,
            }),
            _ => None,
        };
        let landed = b.outcomes.iter().filter(|o| matches!(o, Outcome::Landed { .. })).count();
        // The PRs the batch lands (BUG-1924): marked landed in its
        // transaction, whether or not the request that queued them still
        // waits; their source branches are cleaned after it (`prs::pr_landed`).
        let landed_prs: Vec<(String, i32, i64)> = b
            .rows
            .iter()
            .zip(&b.outcomes)
            .filter_map(|(meta, o)| match (o, &meta.pr) {
                (Outcome::Landed { .. }, Some((id, revision))) => Some((id.clone(), *revision, meta.person_id)),
                _ => None,
            })
            .collect();
        let tx_landed_prs = landed_prs.clone();
        let notify = hub.caches.notices.load(Ordering::SeqCst);
        let active_agents: Vec<(i64, String, (i64, i64))> = b
            .rows
            .iter()
            .zip(&b.outcomes)
            .filter_map(|(meta, o)| match (o, &meta.agent_session) {
                (Outcome::Landed { .. }, Some(sh)) => Some((meta.person_id, sh.clone(), meta.epochs)),
                _ => None,
            })
            .collect();
        let has_active_user_entries = b
            .rows
            .iter()
            .zip(&b.outcomes)
            .any(|(meta, o)| meta.user_entry && matches!(o, Outcome::Landed { .. }));
        let active_review_checks: Vec<EntryReviewCheck> = b
            .rows
            .iter()
            .zip(&b.outcomes)
            .filter_map(|(meta, o)| match (o, &meta.review_check) {
                (Outcome::Landed { .. }, Some(rc)) => Some(rc.clone()),
                _ => None,
            })
            .collect();
        let review_guard = b.review_guard.clone();
        let old_tip_id = b.old_tip;
        let tx_results = results.clone();
        let tx_hub = hub.clone();
        let stored_outside = stored.clone();
        let mut run = tx_fn(move |c| {
            let (ls, ll, mc, cc, ca, cl, snapshot_authors, active_agents, rules_landing, active_review_checks, review_guard) = (
                ls.clone(),
                ll.clone(),
                mc.clone(),
                cc.clone(),
                ca.clone(),
                cl.clone(),
                snapshot_authors.clone(),
                active_agents.clone(),
                rules_landing.clone(),
                active_review_checks.clone(),
                review_guard.clone(),
            );
            let (branch, holder, old, new, seqs, snapshots, mk, mr, mp, accept, name, mut results) = (
                branch.clone(),
                holder.clone(),
                old.clone(),
                new.clone(),
                seqs.clone(),
                snapshots.clone(),
                mk.clone(),
                mr.clone(),
                mp.clone(),
                accept.clone(),
                name.clone(),
                tx_results.clone(),
            );
            let landed_prs = tx_landed_prs.clone();
            let tx_hub = tx_hub.clone();
            let stored = stored.clone();
            Box::pin(async move {
                crate::pack_gc::guard_root_write(&mut *c, pid, gc_epoch).await?;
                // Fencing: only the lease's current holder moves the branch.
                // (And the entries it has served: what a submit reads the
                // service's rate from, `limits::pressure`.)
                let held = sqlx::query(&format!(
                    "UPDATE landing_leases SET expires_at = {DB_NOW} + $5, served = served + $6 \
                     WHERE project_id = $1 AND branch = $2 AND holder = $3 AND epoch = $4"
                ))
                .bind(pid)
                .bind(&branch)
                .bind(&holder)
                .bind(epoch)
                .bind(LEASE_MS)
                .bind(seqs.len() as i64)
                .execute(&mut *c)
                .await?
                .rows_affected();
                if held != 1 {
                    return Err(Error::conflict(LEASE_LOST));
                }
                // Any submitting agent session whose entry lands or merges in
                // this batch must still be active and at the epochs it was
                // prepared under: if it expired or was revoked meanwhile, rebuild.
                for (person_id, sh, expected_epochs) in &active_agents {
                    if crate::auth::load_agent_session(&mut *c, sh, *person_id, pid).await?.is_none() {
                        return Err(Error::conflict(MOVED));
                    }
                    let cur: (i64, i64) = sqlx::query_as(
                        "SELECT COALESCE((SELECT epoch FROM access_epochs WHERE project_id = 0 AND person_id = $1), 0), \
                         COALESCE((SELECT epoch FROM access_epochs WHERE project_id = $2 AND person_id = 0), 0)",
                    )
                    .bind(person_id)
                    .bind(pid)
                    .fetch_one(&mut *c)
                    .await?;
                    if cur != *expected_epochs {
                        return Err(Error::conflict(MOVED));
                    }
                }
                // The branch is where the batch was judged, in the same
                // lineage, also when nothing of it moves the branch
                // (BUG-1304, BUG-1300): else it is built again on the tip.
                let n = match &old {
                    Some(_) => sqlx::query(
                        "UPDATE branches SET target = $1, changes_recorded = changes_recorded AND $6 \
                         WHERE project_id = $2 AND name = $3 AND target = $4 AND lineage = $5 AND hidden_for_embargo IS NULL",
                    )
                    .bind(&new)
                    .bind(pid)
                    .bind(&branch)
                    .bind(&old)
                    .bind(lineage)
                    .bind(recorded)
                    .execute(&mut *c)
                    .await?
                    .rows_affected(),
                    None => {
                        let there: Option<i64> =
                            sqlx::query_scalar("SELECT lineage FROM branches WHERE project_id = $1 AND name = $2 AND hidden_for_embargo IS NULL")
                                .bind(pid)
                                .bind(&branch)
                                .fetch_optional(&mut *c)
                                .await?;
                        u64::from(there.is_none())
                    }
                };
                if n != 1 {
                    return Err(Error::conflict(MOVED));
                }
                // The review gate, before anything the review rules come
                // from is read again (BUG-1886, BUG-2061): exclusively by a
                // batch that changes them (the default branch's
                // `.veilrules`), shared by every other batch with a
                // person's entry. Whatever changes the rules or the holds
                // commits before this reads, or waits for this commit.
                let rules_change = match &rules_landing {
                    Some(l) => crate::prs::state::changes_rules(&mut *c, pid, l).await?,
                    None => false,
                };
                if rules_change {
                    crate::prs::close_review_gate(&mut *c, pid).await?;
                } else if has_active_user_entries && review_guard.is_some() {
                    crate::prs::share_review_gate(&mut *c, pid).await?;
                }
                // Re-verify the review rules and PR gates inside the batch's
                // commit transaction before recording new rules or updating
                // queue rows (`BUG-1880`): a protected branch's, an embargo
                // PR's approvals for a release, a change reverted twice.
                if has_active_user_entries {
                    if let Some(guard) = &review_guard {
                        let cur_proj_epoch: i64 = sqlx::query_scalar(
                            "SELECT COALESCE((SELECT epoch FROM access_epochs WHERE project_id = $1 AND person_id = 0), 0)",
                        )
                        .bind(pid)
                        .fetch_one(&mut *c)
                        .await?;
                        if cur_proj_epoch != guard.project_epoch {
                            return Err(Error::conflict(MOVED));
                        }
                        if !crate::prs::rules_unchanged_in_tx(&mut *c, pid, &branch, old_tip_id, &guard.ctx).await? {
                            return Err(Error::conflict(MOVED));
                        }
                        // A change reverted twice since the entries were
                        // read: they are read again under that rule.
                        if !guard.reverted_twice && crate::bisect::has_reverted_twice(&mut *c, pid).await? {
                            return Err(Error::conflict(MOVED));
                        }
                        if guard.protected || guard.reverted_twice {
                            // Read under the review gate (taken above): a
                            // verdict, hold or new revision written meanwhile
                            // is read here or waits for this commit (BUG-1886).
                            // In a few statements for the whole batch
                            // (BUG-1942): this transaction holds the
                            // branch's row.
                            let items: Vec<crate::prs::LandingReview<'_>> = active_review_checks
                                .iter()
                                .map(|rc| crate::prs::LandingReview {
                                    project: &rc.project,
                                    viewer: &rc.viewer,
                                    diff: &rc.diff,
                                    claim: rc.claim.as_ref(),
                                })
                                .collect();
                            let answers = crate::prs::verify_landing_reviews(
                                &mut *c,
                                pid,
                                &branch,
                                &guard.ctx.rules,
                                &items,
                                guard.protected,
                                guard.reverted_twice,
                                &tx_hub.landing.stats.review_asks,
                            )
                            .await?;
                            if answers.iter().any(|a| a.is_err()) {
                                return Err(Error::conflict(MOVED));
                            }
                        }
                    }
                }
                if let Some(l) = &rules_landing {
                    crate::prs::state::record_landing(&mut *c, pid, l).await?;
                }
                if let Some(text) = &accept {
                    // Bumps the project's access epoch (a trigger): later
                    // entries are checked against it.
                    crate::perm::accept_policy(&mut *c, pid, text).await?;
                    if let Some(p) = crate::perm::load_project(&mut *c, &name).await? {
                        for r in results.iter_mut().filter(|r| r.state == LandState::Landed) {
                            r.warnings = crate::perm::accepted_listing(&p);
                        }
                    }
                }
                let now_ms = veil_core::now_millis();
                let states: Vec<String> = results
                    .iter()
                    .map(|r| state_name(r.state).to_string())
                    .collect();
                let texts: Vec<String> = results.iter().map(|r| serde_json::to_string(r).unwrap_or_default()).collect();
                let dones: Vec<i64> = vec![now_ms; results.len()];
                let n = sqlx::query(
                    "UPDATE landing_queue AS q \
                     SET state = v.state, result = v.result, done_at = v.done_at \
                     FROM unnest($3::BIGINT[], $4::TEXT[], $5::TEXT[], $6::BIGINT[]) AS v(seq, state, result, done_at) \
                     WHERE q.project_id = $1 AND q.branch = $2 AND q.seq = v.seq AND q.state = 'queued'",
                )
                .bind(pid)
                .bind(&branch)
                .bind(&seqs)
                .bind(&states)
                .bind(&texts)
                .bind(&dones)
                .execute(&mut *c)
                .await?
                .rows_affected();
                if n != seqs.len() as u64 {
                    return Err(Error::conflict(MOVED));
                }
                // Which of the batch's PRs this commit marked landed (one
                // an embargo holds is its release's to mark).
                let mut marked: Vec<bool> = Vec::with_capacity(landed_prs.len());
                for (id, revision, _) in &landed_prs {
                    let n = crate::prs::mark_landed(&mut *c, pid, id, *revision, now_ms).await?;
                    marked.push(n);
                }
                if !snapshots.is_empty() {
                    sqlx::query(
                        "INSERT INTO snapshots (project_id, id, author) SELECT $1, s, a FROM unnest($2::TEXT[], $3::BIGINT[]) AS v(s, a) \
                         ON CONFLICT (project_id, id) DO UPDATE SET author = EXCLUDED.author WHERE snapshots.author = 0",
                    )
                    .bind(pid)
                    .bind(&snapshots)
                    .bind(&snapshot_authors)
                    .execute(&mut *c)
                    .await?;
                }
                if !ls.is_empty() {
                    sqlx::query(
                        "INSERT INTO landings (project_id, branch, lineage, submitted, landed, at) \
                         SELECT $1, $5, $6, s, l, $4 FROM unnest($2::TEXT[], $3::TEXT[]) AS v(s, l) \
                         ON CONFLICT (project_id, branch, lineage, submitted) DO UPDATE SET landed = EXCLUDED.landed, at = EXCLUDED.at",
                    )
                    .bind(pid)
                    .bind(&ls)
                    .bind(&ll)
                    .bind(veil_core::now_millis())
                    .bind(&branch)
                    .bind(lineage)
                    .execute(&mut *c)
                    .await?;
                    // What each landing was made from, for good (one row a
                    // landed snapshot, as `snapshots`): "already landed" is
                    // read from it, never from rows that expire (BUG-1465).
                    sqlx::query(
                        "INSERT INTO landed_from (project_id, source, landed) SELECT $1, s, l FROM unnest($2::TEXT[], $3::TEXT[]) AS v(s, l) \
                         WHERE s <> l ON CONFLICT DO NOTHING",
                    )
                    .bind(pid)
                    .bind(&ls)
                    .bind(&ll)
                    .execute(&mut *c)
                    .await?;
                }
                if !cc.is_empty() {
                    crate::landing::record_changes(&mut *c, pid, &branch, lineage, &cc, &ca, &cl).await?;
                }
                if !mk.is_empty() {
                    let stored: Vec<(String, String)> = sqlx::query_as(
                        "INSERT INTO projections (project_id, view_key, real_id, projected_id, created_at, collapsed) \
                         SELECT $1, k, r, p, $5, c FROM unnest($2::TEXT[], $3::TEXT[], $4::TEXT[], $6::BOOL[]) AS v(k, r, p, c) ON CONFLICT DO NOTHING \
                         RETURNING view_key, real_id",
                    )
                    .bind(pid)
                    .bind(&mk)
                    .bind(&mr)
                    .bind(&mp)
                    .bind(veil_core::now_millis())
                    .bind(&mc)
                    .fetch_all(&mut *c)
                    .await?;
                    // A memo stored meanwhile (a background fill) wins: if it
                    // is another value, this batch built on one nobody has.
                    if stored.len() < mk.len() {
                        let have: Vec<(String, String, String)> = sqlx::query_as(
                            "SELECT p.view_key, p.real_id, p.projected_id FROM projections p \
                             JOIN unnest($2::TEXT[], $3::TEXT[]) AS v(k, r) ON p.view_key = v.k AND p.real_id = v.r WHERE p.project_id = $1",
                        )
                        .bind(pid)
                        .bind(&mk)
                        .bind(&mr)
                        .fetch_all(&mut *c)
                        .await?;
                        let ours: HashMap<(&str, &str), &str> =
                            mk.iter().zip(&mr).zip(&mp).map(|((k, r), p)| ((k.as_str(), r.as_str()), p.as_str())).collect();
                        if have.iter().any(|(k, r, p)| ours.get(&(k.as_str(), r.as_str())).is_some_and(|o| o != p)) {
                            return Err(Error::conflict(MEMO_RACE));
                        }
                    }
                }
                sqlx::query("INSERT INTO audit_log (project_id, at, actor, action, details) VALUES ($1, $2, NULL, 'land', $3)")
                    .bind(pid)
                    .bind(veil_core::now_millis())
                    .bind(format!("{landed} of {} landed on {branch}", seqs.len()))
                    .execute(&mut *c)
                    .await?;
                if notify && moved {
                    sqlx::query("SELECT pg_notify($1, $2)")
                        .bind(crate::caches::TIPS_CHANNEL)
                        .bind(pid.to_string())
                        .execute(&mut *c)
                        .await?;
                }
                // What the batch made is stored before the branch names it:
                // waited for here a little only, so that a slow store never
                // holds the lease's row (and the branch's other servers)
                // for long; past that, outside the transaction, which then
                // runs again (BUG-1982).
                if tokio::time::timeout(STORE_IN_TRANSACTION, Storing::wait(&stored)).await.is_err() {
                    return Err(Error::conflict(STORE_SLOW));
                }
                Storing::wait(&stored).await?;
                Ok((results, marked))
            })
        });
        let r = loop {
            match crate::db::transaction(&hub.db, crate::db::Isolation::ReadCommitted, &mut run).await {
                Err(Error::Api { code: "conflict", message, .. }) if message == STORE_SLOW => Storing::wait(&stored_outside).await?,
                r => break r,
            }
        };
        let (results, marked_prs) = match r {
            Ok(r) => r,
            Err(Error::Api { code: "conflict", message, .. }) if message == LEASE_LOST => {
                hub.landing.stats.lease_lost.fetch_add(1, Ordering::Relaxed);
                return Ok(Committed::LeaseLost);
            }
            Err(Error::Api { code: "conflict", message, .. }) if message == MOVED => return Ok(Committed::Moved),
            Err(Error::Api { code: "conflict", message, .. }) if message == MEMO_RACE => {
                hub.landing.stats.memo_races.fetch_add(1, Ordering::Relaxed);
                // What is stored wins: the batch built again projects onto it.
                let keys: Vec<String> = b.memos.iter().map(|m| m.0.clone()).collect::<BTreeSet<_>>().into_iter().collect();
                let reals: Vec<ObjectId> = b.memos.iter().map(|m| m.1).collect::<BTreeSet<_>>().into_iter().collect();
                let stored = memos(hub, self.project, &keys, &reals).await?;
                self.won.lock().unwrap().extend(stored);
                return Ok(Committed::Moved);
            }
            Err(e) => return Err(e),
        };
        for s in &b.snapshots {
            hub.caches.put_committed(self.project, s);
        }
        for (k, real, proj, _) in &b.memos {
            hub.caches.put_memo(self.project, k, real, proj);
        }
        if moved {
            hub.caches.tips_changed(self.project);
            crate::derive::landed(hub, self.project, vec![self.branch.clone()]);
        }
        let st = &hub.landing.stats;
        let conflicts = b.outcomes.iter().filter(|o| matches!(o, Outcome::Conflict(_))).count() as u64;
        let rejected = b.outcomes.iter().filter(|o| matches!(o, Outcome::Rejected(_))).count() as u64;
        st.kept.store(b.after.keys.len() as u64, Ordering::Relaxed);
        st.batches.fetch_add(1, Ordering::Relaxed);
        st.landed.fetch_add(landed as u64, Ordering::Relaxed);
        st.conflicts.fetch_add(conflicts, Ordering::Relaxed);
        st.rejected.fetch_add(rejected, Ordering::Relaxed);
        st.commit_us.fetch_add(t.elapsed().as_micros() as u64, Ordering::Relaxed);
        hub.limits.health.record(
            self.project,
            &crate::limits::health::Counts {
                landings: landed as u64,
                landing_batches: 1,
                landing_conflicts: conflicts,
                landing_rejected: rejected,
                ..Default::default()
            },
        );
        for outcome in &b.outcomes {
            if let Outcome::Landed { merged: true, .. } = outcome {
                st.merging.fetch_add(1, Ordering::Relaxed);
            }
        }
        for (meta, r) in b.rows.iter().zip(results.iter()) {
            let (ev, st_str) = match r.state {
                LandState::Landed => ("land.landed", "landed"),
                LandState::Conflict => ("land.conflict", "conflict"),
                LandState::Rejected => ("land.rejected", "rejected"),
                LandState::Queued => ("land.queued", "queued"),
            };
            let mut ev_r = r.clone();
            if ev_r.change_id.is_none() {
                ev_r.change_id = meta.change_id;
            }
            if ev_r.state == LandState::Landed && ev_r.onto.is_none() {
                ev_r.onto = ev_r.landed.last().copied().or(b.after.tip);
            }
            crate::events::emit_ticket(hub, self.project, &self.branch, meta.person_id, ev, st_str, ev_r).await;
        }
        if moved {
            if let Some(new_tip) = b.after.tip {
                crate::events::emit_moved(hub, self.project, &self.branch, b.old_tip, new_tip, &b.snapshots).await;
            }
        }
        let terminal: Vec<(String, LandResult)> = b
            .rows
            .iter()
            .zip(results.iter())
            .map(|(m, r)| (m.ticket.clone(), r.clone()))
            .collect();
        let has_revert = terminal.iter().any(|(t, _)| t.starts_with("revert-"));
        // Each landed PR's event and its source branch's deletion: tasks of
        // their own, so they finish whoever waits; the tickets are resolved
        // after them as a rule (the request that waited answers with the
        // branch gone), and never held up by them for long.
        let cleanups: Vec<_> = landed_prs
            .into_iter()
            .zip(marked_prs)
            .map(|((id, revision, person), marked)| {
                let (hub, project) = (hub.clone(), self.project);
                tokio::spawn(async move { crate::prs::pr_landed(&hub, project, &id, revision, person, marked).await })
            })
            .collect();
        if !cleanups.is_empty() {
            let _ = tokio::time::timeout(PR_CLEANUP_WAIT, async {
                for h in cleanups {
                    let _ = h.await;
                }
            })
            .await;
        }
        hub.landing.resolve(terminal);
        if has_revert {
            let _ = crate::bisect::sync_revert_outcome(hub, self.project, &self.branch).await;
        }
        Ok(Committed::Ok)
    }
}

/// Stored memos of `project` for `keys` × `reals`, in one statement (the
/// server's memory first when it holds them all).
async fn memos(hub: &Hub, project: i64, keys: &[String], reals: &[ObjectId]) -> Result<HashMap<(String, ObjectId), ObjectId>> {
    let mut out = HashMap::new();
    let mut missing = false;
    for k in keys {
        for r in reals {
            match hub.caches.memo(project, k, r) {
                Some(p) => {
                    out.insert((k.clone(), *r), p);
                }
                None => missing = true,
            }
        }
    }
    if !missing {
        return Ok(out);
    }
    let gce = hub.caches.gc_epoch(project);
    let hex: Vec<String> = reals.iter().map(ObjectId::hex).collect();
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT view_key, real_id, projected_id FROM projections WHERE project_id = $1 AND view_key = ANY($2) AND real_id = ANY($3)",
    )
    .bind(project)
    .bind(keys)
    .bind(&hex)
    .fetch_all(&hub.db)
    .await?;
    for (k, r, p) in rows {
        if let (Ok(r), Ok(p)) = (ObjectId::from_hex(&r), ObjectId::from_hex(&p)) {
            hub.caches.put_memo_at(project, gce, &k, &r, &p);
            out.insert((k, r), p);
        }
    }
    Ok(out)
}

const LEASE_LOST: &str = "the landing lease was lost";
const MOVED: &str = "the branch moved under the landing service";
/// A batch's objects were not stored within [`STORE_IN_TRANSACTION`] of its
/// transaction's last statement: it is rolled back, waits for them without
/// holding anything, and runs again (BUG-1982).
const STORE_SLOW: &str = "the batch's objects are still being stored";
/// How long a batch's transaction waits for its objects before it lets go
/// of the lease's row: half the lease.
const STORE_IN_TRANSACTION: Duration = Duration::from_millis(LEASE_MS as u64 / 2);
/// An entry whose stack was judged under another lineage of the branch.
const RESET: &str = "the branch was reset since this change was submitted (a forced push, or deleted and made again): submit it again";
const MEMO_RACE: &str = "a projection memo was stored meanwhile with another value";

fn state_name(s: LandState) -> &'static str {
    match s {
        LandState::Queued => "queued",
        LandState::Landed => "landed",
        LandState::Conflict => "conflict",
        LandState::Rejected => "rejected",
    }
}

/// The projection of real snapshot `x` (whose first parent's projection is
/// `pp`) for kept key `k`: a stored memo, else made here from stored memos
/// only (never a walk). `None` when it needs a projection nobody stored
/// (another parent's): the key is then not kept. The bool: made here (to
/// store).
#[allow(clippy::too_many_arguments)]
fn project_onto(
    src: &Source,
    who: &As,
    k: &str,
    x: ObjectId,
    pp: ObjectId,
    memo: &HashMap<(String, ObjectId), ObjectId>,
    origins: &HashMap<ObjectId, ObjectId>,
    identity: &veil_core::Identity,
) -> Result<Option<(ObjectId, Option<Bytes>, bool)>> {
    if let Some(px) = memo.get(&(k.to_string(), x)) {
        return Ok(Some((*px, None, false)));
    }
    let s = src.snapshot(&x)?;
    let mut pparents = vec![pp];
    for p in s.parents.iter().skip(1) {
        let Some(q) = memo.get(&(k.to_string(), *p)) else { return Ok(None) };
        if !pparents.contains(q) {
            pparents.push(*q);
        }
    }
    // A predecessor without a stored projection is left out (as one the
    // viewer's history has no version of).
    let mut ppreds = Vec::new();
    for pred in &s.predecessors {
        if let Some(q) = memo.get(&(k.to_string(), *pred)) {
            if src.snapshot(q)?.change_id == src.snapshot(pred)?.change_id && !ppreds.contains(q) {
                ppreds.push(*q);
            }
        }
    }
    let mut pattempts = Vec::with_capacity(s.attempts.len());
    for a in &s.attempts {
        let Some(q) = memo.get(&(k.to_string(), *a)) else { return Ok(None) };
        pattempts.push(*q);
    }
    let view = who.project.view(&who.viewer);
    let (px, raw) = sync::project_one(src, &view, x, &s, pparents, ppreds, pattempts, origins.get(&x).copied(), identity)?;
    Ok(Some((px, raw, true)))
}

/// The batch, built on `on`: the attached view keys, then each entry in
/// order, until one that must land alone, or the batch holds
/// [`BATCH_BYTES`].
/// What the build of an entry reads that no other entry of its batch
/// changes: its stack's snapshots, and each change's edit set and base
/// tree. They are objects read by their ids, so they are the same read
/// before the batch is built or in the entry's turn: the entries of a
/// batch are read on several threads ([`read_ahead`]), and then built on
/// the tip, one after another, as before.
struct Read {
    snaps: Vec<Arc<Snapshot>>,
    sets: Vec<Vec<Change>>,
    base_trees: Vec<ObjectId>,
}

fn read_entry(src: &Source, stack: &[Entry]) -> veil_core::Result<Read> {
    let snaps: Vec<Arc<Snapshot>> = stack.iter().map(|e| src.snapshot(&e.id)).collect::<veil_core::Result<_>>()?;
    // Each change's edits: its own, against its first parent (a merge
    // based on another parent: against that one, BUG-1271). Every change of
    // a stack is one its submitter sees whole (`landing::stack`).
    let mut sets: Vec<Vec<Change>> = Vec::new();
    let mut base_trees: Vec<ObjectId> = Vec::new();
    for (e, s) in stack.iter().zip(&snaps) {
        let against = if s.parents.get(1..).is_some_and(|o| o.contains(&e.base)) { e.base } else { s.parents[0] };
        let old = src.snapshot(&against)?.tree;
        sets.push(edits::edit_set(src, s.tree, old)?);
        base_trees.push(old);
    }
    Ok(Read { snaps, sets, base_trees })
}

/// The threads a batch's entries are read on: the machine's, at most 8
/// (the build itself, on the tip, is one thread's).
fn build_threads() -> usize {
    std::thread::available_parallelism().map_or(1, |n| n.get()).min(8)
}

/// `f` of each of `items`, in their order, on up to `threads` threads (at
/// least 8 items a thread; with one thread, or few items, here).
fn on_threads<T: Sync, R: Send>(items: &[T], threads: usize, f: impl Fn(&T) -> R + Sync) -> Vec<R> {
    let per = items.len().div_ceil(threads.max(1)).max(8);
    if threads < 2 || items.len() <= per {
        return items.iter().map(f).collect();
    }
    let f = &f;
    std::thread::scope(|s| {
        let parts: Vec<_> = items.chunks(per).map(|part| s.spawn(move || part.iter().map(f).collect::<Vec<R>>())).collect();
        parts.into_iter().flat_map(|h| h.join().unwrap_or_else(|panic| std::panic::resume_unwind(panic))).collect()
    })
}

/// [`read_entry`] of each entry, on `threads` threads (BUG-1955: a batch
/// was built on one core of the machine's). `None` for an entry whose read
/// failed, and for all with one thread: [`entry`] reads it in its turn, and
/// answers what it always did.
fn read_ahead(src: &Source, entries: &[Prepared], threads: usize) -> Vec<Option<Read>> {
    match threads {
        0 | 1 => entries.iter().map(|_| None).collect(),
        _ => on_threads(entries, threads, |p| read_entry(src, &p.row.stack).ok()),
    }
}

#[allow(clippy::too_many_arguments)]
fn build(
    hub: Arc<Hub>,
    rt: tokio::runtime::Handle,
    project: i64,
    branch: &str,
    default_tip: Option<ObjectId>,
    inputs: Inputs,
    on: State,
    threads: usize,
) -> Result<Built> {
    let mut src = Source {
        hub: hub.clone(),
        project,
        rt,
        pending: (*on.made).clone(),
        staged: None,
    };
    let Inputs { entries, attach, mut memo, origins, landed, review_guard } = inputs;
    let mut b = Built {
        rows: Vec::new(),
        outcomes: Vec::new(),
        objects: Vec::new(),
        bytes: 0,
        flushes: 0,
        made: 0,
        snapshots: Vec::new(),
        merged: Vec::new(),
        landings: Vec::new(),
        memos: Vec::new(),
        old_tip: on.tip,
        after: on.clone(),
        alone: false,
        merge_read: 0,
        accept: None,
        rules_file: None,
        review_guard,
    };
    // Attached keys: projected from their memo over what came after it.
    for (k, who, at, m) in attach {
        let mut p = m;
        let mut made = Vec::new();
        let mut ok = true;
        for x in on.recent.iter().skip(at + 1) {
            match project_onto(&src, &who, &k, *x, p, &memo, &origins, &hub.identity)? {
                Some((px, raw, new)) => {
                    // Held at once: the next projection reads it (BUG-1110).
                    if let Some(raw) = &raw {
                        src.pending.insert(px, raw.clone());
                    }
                    if new {
                        // Collapsed into its parent's projection: hidden from
                        // that view (BUG-1468).
                        made.push((*x, px, raw, px == p));
                    }
                    p = px;
                }
                None => {
                    ok = false;
                    break;
                }
            }
        }
        if !ok {
            continue;
        }
        for (x, px, raw, collapsed) in made {
            if let Some(raw) = raw {
                b.object(&mut src, px, raw);
            }
            memo.insert((k.clone(), x), px);
            b.memos.push((k.clone(), x, px, collapsed));
            hub.landing.stats.projected.fetch_add(1, Ordering::Relaxed);
        }
        b.flush(&hub, &mut src, on.made_bytes)?;
        b.after.keys.insert(k, Kept { who, at: p });
        hub.landing.stats.attached.fetch_add(1, Ordering::Relaxed);
    }
    let read = read_ahead(&src, &entries, threads);
    for (p, read) in entries.into_iter().zip(read) {
        if b.alone {
            break;
        }
        // Bounded in bytes, with the batch being committed (BUG-1107): no
        // entry joins a batch that made this much (one alone may: it is
        // stored as it goes, `Built::flush`).
        if !b.rows.is_empty() && on.made_bytes + b.made >= BATCH_BYTES {
            break;
        }
        let mark = (b.objects.len(), b.bytes, b.snapshots.len(), b.memos.len(), b.landings.len(), b.flushes);
        let merged = b.merged.len();
        let last_cid = match &read {
            Some(r) => r.snaps.last().map(|s| s.change_id),
            None => p.row.stack.last().and_then(|e| src.snapshot(&e.id).ok().map(|s| s.change_id)),
        };
        let user_entry = !p.row.ticket.starts_with("revert-");
        let row = RowMeta {
            seq: p.row.seq,
            ticket: p.row.ticket.clone(),
            person_id: p.row.person.id,
            merges: p.row.merges,
            change_id: last_cid,
            agent_session: p.row.agent_session.clone(),
            epochs: p.epochs,
            user_entry,
            review_check: p.review_check.clone(),
            pr: match p.row.stack.first().and_then(|e| e.review.as_ref()) {
                Some(super::ReviewClaim::Pr { id, revision, .. }) => Some((id.clone(), *revision)),
                _ => None,
            },
        };
        let outcome = match entry(&hub, &mut src, branch, default_tip, &p, read, &mut b, &mut memo, &origins, &landed, on.made_bytes) {
            Ok(Some(o)) => o,
            // It changes access or rules, or needs more merging than the
            // batch has left, and others come before it: it comes first in
            // the next batch (nothing of it stays).
            Ok(None) => {
                if b.flushes == mark.5 {
                    b.objects.truncate(mark.0);
                    b.bytes = mark.1;
                } else {
                    b.objects.clear();
                    b.bytes = 0;
                }
                b.snapshots.truncate(mark.2);
                b.merged.truncate(merged);
                b.memos.truncate(mark.3);
                b.landings.truncate(mark.4);
                break;
            }
            Err(e) => {
                eprintln!("veil-server: landing ticket {} of project {project}: {e:?}", p.row.ticket);
                Outcome::Rejected("the server could not land this change (an error it logged); submit it again".into())
            }
        };
        if !matches!(outcome, Outcome::Landed { .. }) {
            // Nothing of it stays (what was stored for it is unreferenced).
            if b.flushes == mark.5 {
                b.objects.truncate(mark.0);
                b.bytes = mark.1;
            } else {
                b.objects.clear();
                b.bytes = 0;
            }
            b.snapshots.truncate(mark.2);
            b.merged.truncate(merged);
            b.memos.truncate(mark.3);
            b.landings.truncate(mark.4);
            if b.alone && b.rows.is_empty() {
                b.alone = false;
                b.accept = None;
            }
        }
        b.rows.push(row);
        b.outcomes.push(outcome);
    }
    // Nothing landed: the tip is still the one `on.made` made.
    if !b.objects.is_empty() {
        b.after.made = Arc::new(b.objects.iter().cloned().collect());
        b.after.made_bytes = b.bytes;
    }
    Ok(b)
}

/// Land one entry's stack on `b.after`'s tip: its outcome (and, when it
/// landed, `b.after` moved on), or `None` when it must land alone and does
/// not come first.
#[allow(clippy::too_many_arguments)]
fn entry(
    hub: &Arc<Hub>,
    src: &mut Source,
    branch: &str,
    default_tip: Option<ObjectId>,
    p: &Prepared,
    read: Option<Read>,
    b: &mut Built,
    memo: &mut HashMap<(String, ObjectId), ObjectId>,
    origins: &HashMap<ObjectId, ObjectId>,
    landed_before: &HashMap<ObjectId, Record>,
    before: usize,
) -> Result<Option<Outcome>> {
    let Some(tip) = b.after.tip else { return Ok(Some(Outcome::Rejected(format!("there is no branch '{branch}'")))) };
    let who = match &p.who {
        Ok(a) => a.clone(),
        Err(why) => return Ok(Some(Outcome::Rejected(why.clone()))),
    };
    if p.row.stack.is_empty() {
        return Ok(Some(Outcome::Rejected("nothing to land".into())));
    }
    // Judged under another lineage: what it took as on the branch may no
    // longer be (BUG-1300).
    if p.row.lineage != b.after.lineage {
        return Ok(Some(Outcome::Rejected(RESET.into())));
    }
    // The stack's snapshots, and each change's edits and base tree: read
    // ahead with the batch's other entries, or now.
    let Read { snaps, sets, base_trees } = match read {
        Some(r) => r,
        None => read_entry(src, &p.row.stack)?,
    };
    // A merge whose base is its first parent (as the submitter saw it):
    // lands as a merge, on the tip it was made on (except an embargoed
    // merge landing at release, whose edits land on the current tip).
    let as_merge = |s: &Snapshot, base: ObjectId| s.embargo.is_none() && s.parents.len() > 1 && !s.parents[1..].contains(&base);
    // Access changed since the submit (or after a re-queued merge): it
    // decides first, whatever happened on the tip since, so the answer to
    // someone who may no longer see or write a path never says whether it
    // changed or leaks a hidden path name (BUG-1104, S18 Guarantee 1).
    let view = who.project.view(&who.viewer);
    let default = branch == who.project.default_branch;
    if p.recheck || p.row.merges > 0 || view.is_agent() {
        for ((s, set), e) in snaps.iter().zip(&sets).zip(&p.row.stack) {
            let against = if s.parents.get(1..).is_some_and(|o| o.contains(&e.base)) { e.base } else { s.parents[0] };
            if view.is_agent() {
                match sync::agent_tip(src, &view, default, Some(against), e.id)? {
                    Some(sync::AgentTip::Narrowed) => return Ok(Some(Outcome::Rejected(sync::NARROWED_MOVE.into()))),
                    Some(sync::AgentTip::Access) => return Ok(Some(Outcome::Rejected(sync::AGENT_ACCESS_MOVE.into()))),
                    Some(sync::AgentTip::DefaultBranch) => return Ok(Some(Outcome::Rejected(sync::AGENT_DEFAULT_BRANCH.into()))),
                    None => {}
                }
                if let Some(c) = set.iter().find(|c| veil_core::hub::agent::decides_access(&c.path)) {
                    return Ok(Some(Outcome::Rejected(format!(
                        "an agent session never changes '{}', which decides access or review",
                        c.path
                    ))));
                }
            }
            if !as_merge(s, e.base) {
                if !who.viewer.admin && set.iter().any(|c| !view.read(&c.path)) {
                    return Ok(Some(Outcome::Rejected(
                        "your access changed since this change was submitted, and it holds edits you cannot see: make it again".into(),
                    )));
                }
                if let Some(c) = set.iter().find(|c| !view.write(&c.path)) {
                    if !view.within_narrowing(&c.path) {
                        return Ok(Some(Outcome::Rejected(sync::NARROWED_MOVE.into())));
                    }
                    return Ok(Some(Outcome::Rejected(format!("you may not write '{}'", c.path))));
                }
            }
        }
    }
    // The one write rule of a branch's move (`sync::branch_move_write_refusal`,
    // BUG-1920), where the service moves it: every path a change's edits
    // differ at needs its submitter's write access, whoever made the change
    // and whatever its shape (a held change of someone else's seen whole, a
    // merge and what it takes from its other parents), unless the default
    // branch holds that version where the change joins it (landed work
    // taken onto another branch). Asked of every entry, every time, after
    // the answers above to someone whose access changed.
    for (e, set) in p.row.stack.iter().zip(&sets) {
        let mut landed = sync::Landed::new(default_tip, e.id);
        for c in set.iter().filter(|c| !view.write(&c.path)) {
            if landed.holds(src, &mut sync::PushRows::default(), &c.path, c.new.as_ref())? {
                continue;
            }
            if !view.within_narrowing(&c.path) {
                return Ok(Some(Outcome::Rejected(sync::NARROWED_MOVE.into())));
            }
            if !view.read(&c.path) {
                return Ok(Some(Outcome::Rejected("you may not land changes outside your view".into())));
            }
            return Ok(Some(Outcome::Rejected(format!("you may not write '{}'", c.path))));
        }
    }
    if let Some(why) = &p.review_refusal {
        return Ok(Some(Outcome::Rejected(why.clone())));
    }
    if sets.iter().flatten().any(|c| c.path == POLICY_FILE || c.path == RULES_FILE) {
        if !b.rows.is_empty() {
            return Ok(None);
        }
        b.alone = true;
    }
    // The stack, change by change, on the tip: each as a new snapshot, never
    // the submitted one, so nothing hidden below it shows in the answer
    // (S17 cycle 3).
    let mut chain = tip;
    let tip_tree = src.snapshot(&tip)?.tree;
    let mut chain_tree = tip_tree;
    let mut landed: Vec<(ObjectId, Arc<Snapshot>)> = Vec::new();
    // Where each change of the stack is on the branch (a change another
    // stack landed already counts there, BUG-1270).
    let mut reals: Vec<ObjectId> = Vec::new();
    let last_cid = snaps.last().map(|s| s.change_id);
    let mut merged = false;
    for (i, s) in snaps.iter().enumerate() {
        let e = &p.row.stack[i];
        let sid = e.id;
        let set = &sets[i];
        let earlier = b
            .landings
            .iter()
            .rev()
            .find(|l| l.0 == sid || (p.row.merges > 0 && s.predecessors.contains(&l.0)))
            .map(|l| l.1.clone())
            .or_else(|| {
                landed_before
                    .get(&sid)
                    .cloned()
                    .or_else(|| (p.row.merges > 0).then(|| s.predecessors.iter().find_map(|pr| landed_before.get(pr).cloned())).flatten())
            });
        if let Some(r) = earlier {
            // Its edits are on the branch already (another stack's, or a
            // prior landing of the same re-queued change).
            reals.push(r.landed);
            continue;
        }
        let parent_tree = base_trees[i];
        let against = if s.parents.get(1..).is_some_and(|o| o.contains(&e.base)) { e.base } else { s.parents[0] };
        let merge = as_merge(s, e.base);
        if merge && e.base != chain {
            return Ok(Some(Outcome::Rejected(
                "a merge lands only on the tip it was made on: merge the branch's new tip and land again".into(),
            )));
        }
        // Its paths changed on the tip since its base: merged by content onto
        // the tip as it is here, after everything before it in the queue's
        // order, or answered `conflict` (BUG-1956: a merge made off the
        // batch was overtaken, at most three times, by the next).
        let mut merged_set = None;
        if edits::fast_path(src, parent_tree, chain_tree, set)?.is_some() {
            match super::merge::merge_onto(src, &view, s.parents.len(), set, parent_tree, chain_tree)? {
                Some(m) => {
                    // A batch's merges are bounded in what they read: past
                    // it, the entry comes first in the next batch.
                    if !b.rows.is_empty() && b.merge_read + m.read > MERGE_BYTES {
                        return Ok(None);
                    }
                    b.merge_read += m.read;
                    for (id, raw) in m.blobs {
                        b.object(src, id, raw);
                    }
                    merged_set = Some(m.set);
                    merged = true;
                }
                None => {
                    let report = super::merge::build_conflict(
                        src,
                        &view,
                        against,
                        parent_tree,
                        chain,
                        chain_tree,
                        set,
                        p.row.merges,
                        last_cid,
                    )?;
                    return Ok(Some(Outcome::Conflict(report)));
                }
            }
        }
        let merged_here = merged_set.is_some();
        let set: &[Change] = merged_set.as_deref().unwrap_or(set);
        let mut made = HashMap::new();
        let tree = match edits::apply(src, chain_tree, set, &mut made)? {
            Ok(t) => t,
            Err(edits::Blocked(_)) => {
                let report = super::merge::build_conflict(
                    src,
                    &view,
                    against,
                    parent_tree,
                    chain,
                    chain_tree,
                    &sets[i],
                    p.row.merges,
                    last_cid,
                )?;
                return Ok(Some(Outcome::Conflict(report)));
            }
        };
        for (id, (raw, _)) in made {
            b.object(src, id, Bytes::from(raw));
        }
        b.flush(hub, src, before)?;
        // The landing check: the new snapshot's diff is exactly the
        // change's edits.
        if !edits::same_edits(&edits::edit_set(src, tree, chain_tree)?, set) {
            eprintln!(
                "veil-server: BUG: the landing check failed for ticket {} (snapshot {} onto {}): not landed",
                p.row.ticket,
                sid.short(),
                chain.short()
            );
            return Ok(Some(Outcome::Rejected(
                "the server could not land this change: its landing check failed (a bug in the server, logged there)".into(),
            )));
        }
        let mut parents = vec![chain];
        if merge {
            parents.extend(s.parents[1..].iter().copied());
            b.merged.extend(s.parents[1..].iter().copied());
        }
        let mut preds = vec![sid];
        if p.row.merges > 0 {
            for pr in &s.predecessors {
                if !preds.contains(pr) {
                    preds.push(*pr);
                }
            }
        }
        let mut n = Snapshot {
            parents: parents.clone(),
            change_id: s.change_id,
            tree,
            description: s.description.clone(),
            author: s.author.clone(),
            timestamp: s.timestamp,
            predecessors: preds,
            conflicts: vec![],
            embargo: None,
            // A landed snapshot keeps the submitted snapshot's own agent
            // attribution and attempts; an abandoned attempt never lands.
            agent: s.agent.clone(),
            abandoned: None,
            attempts: s.attempts.clone(),
            signature: None,
        };
        n.sign(&hub.identity);
        let raw = Bytes::from(Object::Snapshot(n.clone()).encode());
        let id = ObjectId::hash(&raw);
        b.object(src, id, raw);
        b.snapshots.push(id);
        b.landings.push((sid, Record { landed: id, change: Some(s.change_id.to_string()) }));
        if p.row.merges > 0 {
            for pr in &s.predecessors {
                b.landings.push((*pr, Record { landed: id, change: Some(s.change_id.to_string()) }));
            }
        }
        let snap = Arc::new(n);
        if view.is_agent() {
            match sync::agent_tip(src, &view, default, Some(chain), id)? {
                Some(sync::AgentTip::Narrowed) => return Ok(Some(Outcome::Rejected(sync::NARROWED_MOVE.into()))),
                Some(sync::AgentTip::Access) => return Ok(Some(Outcome::Rejected(sync::AGENT_ACCESS_MOVE.into()))),
                Some(sync::AgentTip::DefaultBranch) => return Ok(Some(Outcome::Rejected(sync::AGENT_DEFAULT_BRANCH.into()))),
                None => {}
            }
        }
        // The push's checks again, on the new parents, when what they read
        // may have changed: access (epochs), or the policy file the
        // classification reads; and always for a merge (every parent).
        let policy_moved = sync::entry_at(src, &parent_tree, POLICY_FILE)? != sync::entry_at(src, &chain_tree, POLICY_FILE)?;
        if p.recheck || p.row.merges > 0 || policy_moved || merge || merged_here {
            if policy_moved && !who.viewer.admin {
                let tip_policy = AccessPolicy::parse(&sync::policy_text(src, &chain_tree)?);
                let tip_proj = Project {
                    id: who.project.id,
                    name: who.project.name.clone(),
                    default_branch: who.project.default_branch.clone(),
                    policy: tip_policy,
                    policy_text: String::new(),
                    bindings: who.project.bindings.clone(),
                };
                let tip_view = tip_proj.view(&who.viewer);
                if set.iter().any(|c| !tip_view.read(&c.path)) {
                    return Ok(Some(Outcome::Rejected(
                        "your access changed since this change was submitted, and it holds edits you cannot see: make it again".into(),
                    )));
                }
            }
            hub.landing.stats.rechecked.fetch_add(1, Ordering::Relaxed);
            if let Err(why) = recheck(src, &who, &snap, &parents, set, &hub.identity)? {
                return Ok(Some(Outcome::Rejected(why)));
            }
        }
        reals.push(id);
        landed.push((id, snap));
        chain = id;
        chain_tree = tree;
    }
    if branch == who.project.default_branch {
        // A change of who has access: an admin's only (the accepted policy).
        if b.alone {
            let text = sync::policy_text(src, &chain_tree)?;
            if !AccessPolicy::parse(&text).same_rules(&who.project.policy) {
                if !who.viewer.admin {
                    return Ok(Some(Outcome::Rejected("only admins may change who has access (the default branch's .veilpolicy)".into())));
                }
                b.accept = Some(text);
            }
        }
        // The branch rules: an admin's only, judged against the default
        // branch's tip, never against a parent's (BUG-1102).
        if !who.viewer.admin && sync::entry_at(src, &chain_tree, RULES_FILE)? != sync::entry_at(src, &tip_tree, RULES_FILE)? {
            return Ok(Some(Outcome::Rejected("only admins may change the branch rules (.veilrules)".into())));
        }
        b.rules_file = Some(crate::prs::state::file_at(src, chain_tree)?);
    }
    // Projections of every new snapshot for every kept view key, onto its
    // last memo.
    let mut new_memos = Vec::new();
    let mut dropped = Vec::new();
    let mut keys = b.after.keys.clone();
    for (x, _) in &landed {
        for (k, kept) in keys.iter_mut() {
            if dropped.contains(k) {
                continue;
            }
            match project_onto(src, &kept.who, k, *x, kept.at, memo, origins, &hub.identity)? {
                Some((px, raw, new)) => {
                    // Held at once: the next change's projection reads it
                    // (BUG-1110).
                    if let Some(raw) = &raw {
                        src.pending.insert(px, raw.clone());
                    }
                    if new {
                        new_memos.push((k.clone(), *x, px, raw, px == kept.at));
                    }
                    memo.insert((k.clone(), *x), px);
                    kept.at = px;
                }
                None => dropped.push(k.clone()),
            }
        }
    }
    for k in &dropped {
        keys.remove(k);
        hub.landing.stats.dropped.fetch_add(1, Ordering::Relaxed);
    }
    for (k, x, px, raw, collapsed) in new_memos {
        if keys.contains_key(&k) {
            if let Some(raw) = raw {
                b.object(src, px, raw);
            }
            b.memos.push((k, x, px, collapsed));
            hub.landing.stats.projected.fetch_add(1, Ordering::Relaxed);
        }
    }
    b.flush(hub, src, before)?;
    b.after.keys = keys;
    for (x, _) in &landed {
        b.after.recent.push_back(*x);
        if b.after.recent.len() > RECENT {
            b.after.recent.pop_front();
        }
    }
    b.after.tip = Some(chain);
    Ok(Some(Outcome::Landed { reals, merged }))
}

/// For tests (`landing_hold`): the batch `branch`'s service would build
/// now, built with its entries read on one thread and on `threads`, each
/// build told line by line: every object made (by id; its id is its bytes'), the
/// snapshots, memos and landing records, the tip, and each entry's outcome
/// as its submitter is answered. Nothing is stored, queued or committed.
#[doc(hidden)]
pub async fn build_both_ways(hub: &Arc<Hub>, project: i64, branch: &str, threads: usize) -> Result<[Vec<String>; 2]> {
    let name: String = sqlx::query_scalar("SELECT name FROM projects WHERE id = $1").bind(project).fetch_one(&hub.db).await?;
    let s = Service { hub: hub.clone(), project, name, branch: branch.to_string(), epoch: 0, won: Default::default() };
    let state = s.load().await?;
    let rows = s.ready(&HashSet::new()).await?;
    let inputs = s.prepare(rows, &state, state.tip, &mut Known::default()).await?;
    let mut told = Vec::new();
    for threads in [1, threads] {
        let b = s.build(inputs.clone(), State { made_bytes: 0, ..state.clone() }, threads).await?;
        let mut lines = vec![format!("tip {:?} -> {:?}, alone {}, accept {:?}", b.old_tip, b.after.tip, b.alone, b.accept)];
        // (By id: the trees an entry makes are held in a map, in no order.)
        let mut objects: Vec<String> = b.objects.iter().map(|(id, raw)| format!("object {} is {} ({} bytes)", id.hex(), ObjectId::hash(raw).hex(), raw.len())).collect();
        objects.sort();
        lines.extend(objects);
        lines.extend(b.snapshots.iter().map(|x| format!("snapshot {}", x.hex())));
        lines.extend(b.merged.iter().map(|x| format!("merged {}", x.hex())));
        lines.extend(b.landings.iter().map(|(x, r)| format!("landing {} as {} ({:?})", x.hex(), r.landed.hex(), r.change)));
        lines.extend(b.memos.iter().map(|(k, x, px, collapsed)| format!("memo {k} {} {} {collapsed}", x.hex(), px.hex())));
        lines.extend(b.after.recent.iter().map(|x| format!("recent {}", x.hex())));
        lines.extend(b.after.keys.iter().map(|(k, kept)| format!("key {k} at {}", kept.at.hex())));
        for (row, o) in b.rows.iter().zip(&b.outcomes) {
            lines.push(match o {
                Outcome::Landed { reals, merged } => {
                    format!("{} landed as {:?} merged {merged}", row.ticket, reals.iter().map(ObjectId::hex).collect::<Vec<_>>())
                }
                Outcome::Conflict(report) => {
                    format!("{} conflict {}", row.ticket, serde_json::to_string(&report.clone().into_result(&row.ticket, branch)).map_err(|e| Error::Other(e.into()))?)
                }
                Outcome::Rejected(why) => format!("{} rejected: {why}", row.ticket),
            });
        }
        told.push(lines);
    }
    Ok([told.remove(0), told.remove(0)])
}

/// The push's checks (`sync::complete`) for candidate `real` (a real
/// snapshot) on its real `parents` (every one: a merge takes changes from
/// the others, BUG-1105), as `who` sees it now: the tree they would push is
/// their projection of it, grafted back onto the first parent; the graft
/// must give back exactly the candidate's tree. `Ok(Err(why))` when it is
/// refused.
fn recheck(
    src: &mut Source,
    who: &As,
    real: &Snapshot,
    parents: &[ObjectId],
    set: &[Change],
    identity: &veil_core::Identity,
) -> Result<std::result::Result<(), String>> {
    let view = who.project.view(&who.viewer);
    let (ptree, created, mut known) = {
        let mut pr = Projector::new(&*src, &view);
        let ptree = pr.root(real.tree)?;
        let mut known = HashSet::new();
        for c in set {
            if let Some(e) = &c.new {
                known.extend(sync::named_ids(src, e)?);
            }
            let parts: Vec<String> = c.path.split('/').map(str::to_string).collect();
            known.extend(crate::changes::walk(&pr, ptree, &parts)?.0);
        }
        let created: Vec<(ObjectId, Bytes)> = pr.created.iter().map(|(id, (_, raw))| (*id, Bytes::from(raw.clone()))).collect();
        (ptree, created, known)
    };
    for (id, raw) in created {
        known.insert(id);
        src.pending.insert(id, raw);
    }
    let n = Snapshot {
        parents: parents.to_vec(),
        tree: ptree,
        signature: None,
        ..real.clone()
    };
    let c = match sync::complete(src, &who.project, &who.viewer, &known, &n, parents, &real.attempts, identity, &mut sync::PushRows::default()) {
        Ok(c) => c,
        Err(Error::Api { message, code: "forbidden" | "bad_request" | crate::auth::AGENT_SESSION, .. }) => return Ok(Err(message)),
        Err(e) => return Err(e),
    };
    let tree = match &c.raw {
        Some(raw) => match Object::decode(raw)? {
            Object::Snapshot(s) => s.tree,
            _ => return Err(Error::Other(anyhow::anyhow!("complete makes snapshots"))),
        },
        None => n.tree,
    };
    if tree != real.tree {
        return Ok(Err("your access changed since this change was submitted, and it no longer lands as it was made: make it again".into()));
    }
    Ok(Ok(()))
}
