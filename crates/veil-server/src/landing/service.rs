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

/// Is anything queued for `branch`?
pub(super) async fn has_ready(hub: &Hub, project: i64, branch: &str) -> Result<bool> {
    let n: Option<i64> = sqlx::query_scalar("SELECT seq FROM landing_queue WHERE project_id = $1 AND branch = $2 AND state = 'queued' LIMIT 1")
        .bind(project)
        .bind(branch)
        .fetch_optional(&hub.db)
        .await?;
    Ok(n.is_some())
}

/// A queue row.
struct Row {
    seq: i64,
    ticket: String,
    person: Person,
    session: String,
    /// Each change with its base (`landing::stack`).
    stack: Vec<Entry>,
    /// The branch's lineage its stack was judged under.
    lineage: i64,
    epochs: (i64, i64),
    merges: u32,
    agent_session: Option<String>,
}

/// Per-entry protected-branch review check state (`BUG-1880`).
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
}

/// Metadata of a row in a built batch.
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
}

impl crate::limits::landing::QueuedEntry for Row {
    fn seq(&self) -> i64 {
        self.seq
    }
    fn person_id(&self) -> i64 {
        self.person.id
    }
    fn session_key(&self) -> &str {
        if self.session.is_empty() {
            &self.person.device_key
        } else {
            &self.session
        }
    }
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
    /// Where each change of the stack landed (real snapshots).
    Landed { reals: Vec<ObjectId> },
    /// Handed to a merge worker (`state = 'merging'`, S18).
    Merging(super::merge::Job),
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
    /// Stack changes landed: `(submitted, landed, record)`.
    landings: Vec<(ObjectId, Record)>,
    /// New memo rows `(view key, real, projected)`.
    memos: Vec<(String, ObjectId, ObjectId, bool)>,
    old_tip: Option<ObjectId>,
    after: State,
    /// It changed `.veilpolicy` or `.veilrules`: landed alone.
    alone: bool,
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
            let exclude = inflight.as_ref().map(|f| f.seqs.clone()).unwrap_or_default();
            let rows = self.ready(&exclude).await?;
            if rows.is_empty() {
                if let Some(f) = inflight.take() {
                    if !self.finish(f, &mut state).await? {
                        return Ok(());
                    }
                    continue;
                }
                if idle.elapsed() > IDLE {
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
            let built = self.build(inputs, on).await?;
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
            let task = tokio::spawn(async move {
                store.await.map_err(|e| Error::Other(e.into()))??;
                s.commit(built, gc_epoch).await
            });
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

    /// The ready rows, leaving out those being committed: reverts first
    /// (S20, `priority > 0`, in their order), then the rest in fair-share
    /// order (`limits::landing::fair_batch`, S24 part B).
    async fn ready(&self, exclude: &HashSet<i64>) -> Result<Vec<Row>> {
        type R = (i64, String, i64, String, String, String, String, i64, i64, i64, i64, Option<String>, bool);
        let rows: Vec<R> = sqlx::query_as(
            "SELECT seq, ticket, person_id, person_name, device_key, session, stack, lineage, person_epoch, project_epoch, merges, agent_session, priority > 0 FROM landing_queue \
             WHERE project_id = $1 AND branch = $2 AND state = 'queued' ORDER BY priority DESC, created_at, seq",
        )
        .bind(self.project)
        .bind(&self.branch)
        .fetch_all(&self.hub.db)
        .await?;
        let (mut reverts, mut all) = (Vec::new(), Vec::with_capacity(rows.len()));
        for (seq, ticket, id, name, device_key, session, stack, lineage, pe, je, merges, agent_session, revert) in rows {
            let into = if revert { &mut reverts } else { &mut all };
            into.push(Row {
                seq,
                ticket,
                person: Person { id, name, device_key, agent: None },
                session,
                stack: super::decode_stack(&stack)?,
                lineage,
                epochs: (pe, je),
                merges: merges.max(0) as u32,
                agent_session,
            });
        }
        // Reverts are never held back by fair sharing (S20).
        reverts.retain(|r| !exclude.contains(&r.seq));
        reverts.truncate(MAX_BATCH);
        let rest = MAX_BATCH - reverts.len();
        reverts.extend(crate::limits::landing::fair_batch(all, exclude, rest));
        Ok(reverts)
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
        let is_user_entry = |ticket: &str| !ticket.starts_with("revert-") && !ticket.starts_with("embargo-");
        let review_guard = if let Some(first_proj) = entries
            .iter()
            .find(|e| is_user_entry(&e.row.ticket))
            .and_then(|e| e.who.as_ref().ok().map(|a| a.project.clone()))
        {
            let ctx = crate::prs::branch_review_context(hub, &first_proj, &self.branch, on.tip, on.made.clone()).await?;
            let is_protected = ctx.protected.contains(&self.branch);
            if is_protected {
                let pending_stacks: Vec<(usize, Vec<Entry>)> = entries
                    .iter()
                    .enumerate()
                    .filter(|(_, e)| is_user_entry(&e.row.ticket) && e.who.is_ok() && !e.row.stack.is_empty())
                    .map(|(i, e)| (i, e.row.stack.clone()))
                    .collect();
                let diffs: Vec<(usize, crate::prs::StackReviewDiff)> = if pending_stacks.is_empty() {
                    Vec::new()
                } else {
                    sync::blocking(hub, self.project, move |src| {
                        pending_stacks
                            .into_iter()
                            .map(|(i, st)| Ok((i, crate::prs::stack_review_diff(src, &st)?)))
                            .collect()
                    })
                    .await?
                };
                if !diffs.is_empty() {
                    let mut c = hub.db.acquire().await?;
                    for (idx, diff) in diffs {
                        let e = &mut entries[idx];
                        let Ok(a) = &e.who else { continue };
                        let claim = e.row.stack.first().and_then(|x| x.review.clone());
                        match crate::prs::verify_landing_review(
                            &mut c,
                            &a.project,
                            &a.viewer,
                            &self.branch,
                            &diff,
                            &ctx.rules,
                            claim.as_ref(),
                        )
                        .await?
                        {
                            Ok(_) => {
                                e.review_check = Some(EntryReviewCheck {
                                    project: a.project.clone(),
                                    viewer: a.viewer.clone(),
                                    diff,
                                    claim,
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
                "SELECT submitted, landed FROM landings WHERE project_id = $1 AND branch = $3 AND lineage = $4 AND submitted = ANY($2)",
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
    /// signatures).
    async fn build(&self, inputs: Inputs, on: State) -> Result<Built> {
        let (hub, project, branch) = (self.hub.clone(), self.project, self.branch.clone());
        let rt = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || build(hub, rt, project, &branch, inputs, on)).await.map_err(|e| Error::Other(e.into()))?
    }

    /// Commit the batch (its objects stored already) in one transaction;
    /// then tell the waiters here, spawn merge workers, and emit events.
    async fn commit(&self, b: Built, gc_epoch: i64) -> Result<Committed> {
        let t = Instant::now();
        let hub = &self.hub;
        let moved = b.after.tip != b.old_tip;
        let results: Vec<Option<LandResult>> = b
            .rows
            .iter()
            .zip(&b.outcomes)
            .map(|(meta, o)| match o {
                Outcome::Merging(_) => None,
                Outcome::Landed { reals } => {
                    let mut r = super::queued(&meta.ticket);
                    r.state = LandState::Landed;
                    r.landed = reals.clone();
                    r.merges = meta.merges;
                    Some(r)
                }
                Outcome::Conflict(report) => Some(report.clone().into_result(&meta.ticket, &self.branch)),
                Outcome::Rejected(why) => {
                    let mut r = super::queued(&meta.ticket);
                    r.state = LandState::Rejected;
                    r.message = Some(why.clone());
                    r.merges = meta.merges;
                    Some(r)
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
        let empty_fresh = HashMap::new();
        let mut snap_authors: HashMap<ObjectId, i64> = HashMap::new();
        let (mut cc, mut ca, mut cl) = (Vec::new(), Vec::new(), Vec::new());
        for (sid, r) in &b.landings {
            if let Some(c) = &r.change {
                if let Some(a) = super::snapshot_author(hub, self.project, *sid, &empty_fresh).await? {
                    snap_authors.insert(r.landed, a);
                    cc.push(c.clone());
                    ca.push(a);
                    cl.push(r.landed.hex());
                }
            }
        }
        let snapshot_authors: Vec<i64> = b.snapshots.iter().map(|s| snap_authors.get(s).copied().unwrap_or(0)).collect();
        let lineage = b.after.lineage;
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
        let notify = hub.caches.notices.load(Ordering::SeqCst);
        let active_agents: Vec<(i64, String, (i64, i64))> = b
            .rows
            .iter()
            .zip(&b.outcomes)
            .filter_map(|(meta, o)| match (o, &meta.agent_session) {
                (Outcome::Landed { .. } | Outcome::Merging(_), Some(sh)) => Some((meta.person_id, sh.clone(), meta.epochs)),
                _ => None,
            })
            .collect();
        let has_active_user_entries = b
            .rows
            .iter()
            .zip(&b.outcomes)
            .any(|(meta, o)| meta.user_entry && matches!(o, Outcome::Landed { .. } | Outcome::Merging(_)));
        let active_review_checks: Vec<EntryReviewCheck> = b
            .rows
            .iter()
            .zip(&b.outcomes)
            .filter_map(|(meta, o)| match (o, &meta.review_check) {
                (Outcome::Landed { .. } | Outcome::Merging(_), Some(rc)) => Some(rc.clone()),
                _ => None,
            })
            .collect();
        let review_guard = b.review_guard.clone();
        let old_tip_id = b.old_tip;
        let tx_results = results.clone();
        let r = crate::db::transaction(&hub.db, crate::db::Isolation::ReadCommitted, move |c| {
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
            Box::pin(async move {
                crate::pack_gc::guard_root_write(&mut *c, pid, gc_epoch).await?;
                // Fencing: only the lease's current holder moves the branch.
                let held = sqlx::query(&format!(
                    "UPDATE landing_leases SET expires_at = {DB_NOW} + $5 WHERE project_id = $1 AND branch = $2 AND holder = $3 AND epoch = $4"
                ))
                .bind(pid)
                .bind(&branch)
                .bind(&holder)
                .bind(epoch)
                .bind(LEASE_MS)
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
                        "UPDATE branches SET target = $1 WHERE project_id = $2 AND name = $3 AND target = $4 AND lineage = $5 AND hidden_for_embargo IS NULL",
                    )
                    .bind(&new)
                    .bind(pid)
                    .bind(&branch)
                    .bind(&old)
                    .bind(lineage)
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
                // Re-verify protected-branch review rules and PR gates inside
                // the batch's commit transaction before recording new rules or
                // updating queue rows (`BUG-1880`).
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
                        if guard.protected {
                            for rc in &active_review_checks {
                                if crate::prs::verify_landing_review(
                                    &mut *c,
                                    &rc.project,
                                    &rc.viewer,
                                    &branch,
                                    &rc.diff,
                                    &guard.ctx.rules,
                                    rc.claim.as_ref(),
                                )
                                .await?
                                .is_err()
                                {
                                    return Err(Error::conflict(MOVED));
                                }
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
                        for r in results.iter_mut().flatten().filter(|r| r.state == LandState::Landed) {
                            r.warnings = crate::perm::accepted_listing(&p);
                        }
                    }
                }
                let now_ms = veil_core::now_millis();
                let states: Vec<String> = results
                    .iter()
                    .map(|r| match r {
                        Some(r) => state_name(r.state).to_string(),
                        None => "merging".to_string(),
                    })
                    .collect();
                let texts: Vec<Option<String>> = results
                    .iter()
                    .map(|r| r.as_ref().map(|x| serde_json::to_string(x).unwrap_or_default()))
                    .collect();
                let dones: Vec<Option<i64>> = results.iter().map(|r| r.as_ref().map(|_| now_ms)).collect();
                let n = sqlx::query(
                    "UPDATE landing_queue AS q SET state = v.state, result = v.result, done_at = v.done_at \
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
                Ok(results)
            })
        })
        .await;
        let results = match r {
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
            if let Outcome::Merging(job) = outcome {
                super::merge::spawn(hub, job.clone());
            }
        }
        for (meta, res) in b.rows.iter().zip(results.iter()) {
            if let Some(r) = res {
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
            .filter_map(|(m, r)| Some((m.ticket.clone(), r.clone()?)))
            .collect();
        let has_revert = terminal.iter().any(|(t, _)| t.starts_with("revert-"));
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
fn build(hub: Arc<Hub>, rt: tokio::runtime::Handle, project: i64, branch: &str, inputs: Inputs, on: State) -> Result<Built> {
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
        landings: Vec::new(),
        memos: Vec::new(),
        old_tip: on.tip,
        after: on.clone(),
        alone: false,
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
    for p in entries {
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
        let last_cid = p.row.stack.last().and_then(|e| src.snapshot(&e.id).ok().map(|s| s.change_id));
        let user_entry = !p.row.ticket.starts_with("revert-") && !p.row.ticket.starts_with("embargo-");
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
        };
        let outcome = match entry(&hub, &mut src, branch, &p, &mut b, &mut memo, &origins, &landed, on.made_bytes) {
            Ok(Some(o)) => o,
            // It changes access or rules and others come before it: it lands
            // alone, in the next batch.
            Ok(None) => break,
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
    p: &Prepared,
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
    let snaps: Vec<Arc<Snapshot>> = p.row.stack.iter().map(|e| src.snapshot(&e.id)).collect::<veil_core::Result<_>>()?;
    // Each change's edits: its own, against its first parent (a merge
    // based on another parent: against that one, BUG-1271). Every change of
    // a stack is one its submitter sees whole (`landing::stack`).
    let mut sets: Vec<Vec<Change>> = Vec::new();
    let mut base_trees: Vec<ObjectId> = Vec::new();
    for (e, s) in p.row.stack.iter().zip(&snaps) {
        let against = if s.parents.get(1..).is_some_and(|o| o.contains(&e.base)) { e.base } else { s.parents[0] };
        let old = src.snapshot(&against)?.tree;
        sets.push(edits::edit_set(src, s.tree, old)?);
        base_trees.push(old);
    }
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
        if edits::fast_path(src, parent_tree, chain_tree, set)?.is_some() {
            if super::merge::can_merge(src, &view, p.row.merges, &snaps[i..], &sets[i..], &base_trees[i..], chain_tree)? {
                return Ok(Some(Outcome::Merging(super::merge::Job {
                    project: src.project,
                    project_name: who.project.name.clone(),
                    branch: branch.to_string(),
                    seq: p.row.seq,
                    ticket: p.row.ticket.clone(),
                    person: p.row.person.clone(),
                    agent_session: p.row.agent_session.clone(),
                    stack: p.row.stack[i..].to_vec(),
                    lineage: p.row.lineage,
                    merges: p.row.merges,
                    tip: chain,
                })));
            }
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
                    set,
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
        if p.recheck || p.row.merges > 0 || policy_moved || merge {
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
    Ok(Some(Outcome::Landed { reals }))
}

/// [`recheck`] exposed for `landing::merge`.
pub(super) fn recheck_merged(
    src: &mut Source,
    project: &Arc<Project>,
    viewer: &Viewer,
    real: &Snapshot,
    parents: &[ObjectId],
    set: &[Change],
    identity: &veil_core::Identity,
) -> Result<std::result::Result<(), String>> {
    let who = As {
        project: project.clone(),
        viewer: viewer.clone(),
        key: (!viewer.admin).then(|| project.view(viewer).key()),
    };
    recheck(src, &who, real, parents, set, identity)
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
