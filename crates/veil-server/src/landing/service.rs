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
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
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

use super::{edits, rules::RULES_FILE, LEASE_MS, MAX_BATCH};
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
/// A view key with no memo on the recent line is handed to the background
/// fill at most this often.
const PREFILL_EVERY: Duration = Duration::from_secs(5);
/// Finished queue rows are kept this long (a ticket's outcome), then
/// deleted, a branch at a time, at most this often.
const KEEP_DONE_MS: i64 = 24 * 3600 * 1000;
const CLEAN_EVERY: Duration = Duration::from_secs(60);

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
    stack: Vec<ObjectId>,
    epochs: (i64, i64),
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
}

/// What one entry came to.
enum Outcome {
    /// Where each change of the stack landed (real snapshots).
    Landed { reals: Vec<ObjectId> },
    Conflict { paths: Vec<String> },
    Rejected(String),
}

/// A batch built in memory.
struct Built {
    rows: Vec<(i64, String)>,
    outcomes: Vec<Outcome>,
    objects: Vec<(ObjectId, Bytes)>,
    bytes: usize,
    snapshots: Vec<ObjectId>,
    /// Submitted snapshots made again: `(submitted, landed)`.
    landings: Vec<(ObjectId, ObjectId)>,
    /// New memo rows `(view key, real, projected)`.
    memos: Vec<(String, ObjectId, ObjectId)>,
    old_tip: Option<ObjectId>,
    after: State,
    /// It changed `.veilpolicy` or `.veilrules`: landed alone.
    alone: bool,
    /// The default branch's new access lines, for its one entry.
    accept: Option<String>,
}

impl Built {
    fn object(&mut self, src: &mut Source, id: ObjectId, raw: Bytes) {
        self.bytes += raw.len();
        src.pending.insert(id, raw.clone());
        self.objects.push((id, raw));
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
            let exclude = inflight.as_ref().map(|f| f.seqs.clone()).unwrap_or_default();
            let rows = self.ready(&exclude).await?;
            if rows.is_empty() {
                if let Some(f) = inflight.take() {
                    if !self.finish(f, &mut state).await? {
                        return Ok(());
                    }
                    continue;
                }
                if cleaned.is_none_or(|t| t.elapsed() > CLEAN_EVERY) {
                    self.clean().await?;
                    cleaned = Some(Instant::now());
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
            let seqs = built.rows.iter().map(|r| r.0).collect();
            let (alone, after) = (built.alone, built.after.clone());
            let s = Arc::new(self.clone_handle());
            let task = tokio::spawn(async move {
                store.await.map_err(|e| Error::Other(e.into()))??;
                s.commit(built).await
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
        }
    }

    /// Finished rows older than [`KEEP_DONE_MS`] go.
    async fn clean(&self) -> Result<()> {
        sqlx::query("DELETE FROM landing_queue WHERE project_id = $1 AND branch = $2 AND state <> 'queued' AND done_at < $3")
            .bind(self.project)
            .bind(&self.branch)
            .bind(veil_core::now_millis() - KEEP_DONE_MS)
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
                eprintln!("veil-server: a landing batch of project {} failed: {e:?}", self.project);
                *state = self.load().await?;
                tokio::time::sleep(Duration::from_millis(50)).await;
                Ok(true)
            }
        }
    }

    /// The branch's tip, from the database (no view key kept yet).
    async fn load(&self) -> Result<State> {
        let t: Option<String> = sqlx::query_scalar("SELECT target FROM branches WHERE project_id = $1 AND name = $2")
            .bind(self.project)
            .bind(&self.branch)
            .fetch_optional(&self.hub.db)
            .await?;
        let tip = t.map(|t| ObjectId::from_hex(&t).map_err(|e| Error::Other(e.into()))).transpose()?;
        Ok(State {
            tip,
            recent: tip.into_iter().collect(),
            ..State::default()
        })
    }

    /// The ready rows, in order, leaving out those being committed.
    async fn ready(&self, exclude: &HashSet<i64>) -> Result<Vec<Row>> {
        type R = (i64, String, i64, String, String, String, i64, i64);
        let rows: Vec<R> = sqlx::query_as(
            "SELECT seq, ticket, person_id, person_name, device_key, stack, person_epoch, project_epoch FROM landing_queue \
             WHERE project_id = $1 AND branch = $2 AND state = 'queued' ORDER BY created_at, seq LIMIT $3",
        )
        .bind(self.project)
        .bind(&self.branch)
        .bind((MAX_BATCH + exclude.len()) as i64)
        .fetch_all(&self.hub.db)
        .await?;
        let mut out = Vec::new();
        for (seq, ticket, id, name, device_key, stack, pe, je) in rows {
            if exclude.contains(&seq) {
                continue;
            }
            let stack: Vec<String> = serde_json::from_str(&stack).map_err(|e| Error::Other(e.into()))?;
            let stack = stack.iter().map(|s| ObjectId::from_hex(s).map_err(|e| Error::Other(e.into()))).collect::<Result<_>>()?;
            out.push(Row {
                seq,
                ticket,
                person: Person { id, name, device_key },
                stack,
                epochs: (pe, je),
            });
            if out.len() == MAX_BATCH {
                break;
            }
        }
        Ok(out)
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
        viewers.extend(people.into_iter().filter(|(p, _)| !admins.contains(p)).map(|(p, groups)| Viewer {
            person: Some(p),
            admin: false,
            groups,
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
             OR (project_id = $2 AND person_id = 0)",
        )
        .bind(&people)
        .bind(self.project)
        .fetch_all(&hub.db)
        .await?;
        let project_epoch = epochs.iter().find(|e| e.0 == self.project).map_or(0, |e| e.2);
        let person_epoch = |p: i64| epochs.iter().find(|e| e.0 == 0 && e.1 == p).map_or(0, |e| e.2);
        if known.epoch != Some(project_epoch) {
            self.enumerate(known).await?;
            known.epoch = Some(project_epoch);
        }
        let mut who: HashMap<(i64, String), Result<As, String>> = HashMap::new();
        let mut entries = Vec::new();
        for row in rows {
            let k = (row.person.id, row.person.device_key.clone());
            if !who.contains_key(&k) {
                let caller = Caller {
                    person: Some(row.person.clone()),
                    epochs: Epochs {
                        person: person_epoch(row.person.id),
                        project: Some((self.project, project_epoch)),
                    },
                };
                let w = match crate::perm::open(hub, &self.name, &caller).await {
                    Ok((p, v)) if p.participant(&v) => {
                        let key = (!v.admin).then(|| p.view(&v).key());
                        Ok(As { project: Arc::new(p), viewer: v, key })
                    }
                    Ok(_) => Err("you are no longer in this project".to_string()),
                    Err(Error::Api { code: "not_found", .. }) => Err("you are no longer in this project".to_string()),
                    Err(Error::Api { message, code: "forbidden", .. }) => Err(message),
                    Err(e) => return Err(e),
                };
                if let Ok(a) = &w {
                    if let Some(key) = &a.key {
                        if known.views.len() < MAX_KEYS || known.views.contains_key(key) {
                            known.views.entry(key.clone()).or_insert_with(|| a.clone());
                        }
                    }
                }
                who.insert(k.clone(), w);
            }
            let w = who[&k].clone();
            let recheck = row.epochs != (person_epoch(row.person.id), project_epoch);
            entries.push(Prepared { row, who: w, recheck });
        }
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
            for (k, a) in unkept {
                let newest = recent.iter().enumerate().rev().find_map(|(i, x)| found.get(&(k.clone(), *x)).map(|m| (i, *m)));
                match newest {
                    Some((i, m)) => attach.push((k, a, i, m)),
                    None => {
                        known.prefilled.insert(k.clone(), Instant::now());
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
        let stacks: Vec<ObjectId> = entries.iter().flat_map(|e| e.row.stack.iter().copied()).collect();
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
            }
            Ok(ids)
        })
        .await?;
        ids.sort_unstable();
        ids.dedup();
        let keys: Vec<String> = on.keys.keys().cloned().chain(attach.iter().map(|a| a.0.clone())).collect();
        let memo = match keys.is_empty() || ids.is_empty() {
            true => HashMap::new(),
            false => memos(hub, self.project, &keys, &ids).await?,
        };
        let origins: HashMap<ObjectId, ObjectId> = if stacks.is_empty() {
            HashMap::new()
        } else {
            let hex: Vec<String> = stacks.iter().map(ObjectId::hex).collect();
            let rows: Vec<(String, String)> = sqlx::query_as("SELECT real_id, origin_id FROM origins WHERE project_id = $1 AND real_id = ANY($2)")
                .bind(self.project)
                .bind(&hex)
                .fetch_all(&hub.db)
                .await?;
            rows.into_iter().filter_map(|(r, o)| Some((ObjectId::from_hex(&r).ok()?, ObjectId::from_hex(&o).ok()?))).collect()
        };
        Ok(Inputs { entries, attach, memo, origins })
    }

    /// Build the batch on `on` (on a blocking thread: trees, hashes,
    /// signatures).
    async fn build(&self, inputs: Inputs, on: State) -> Result<Built> {
        let (hub, project, branch) = (self.hub.clone(), self.project, self.branch.clone());
        let rt = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || build(hub, rt, project, &branch, inputs, on)).await.map_err(|e| Error::Other(e.into()))?
    }

    /// Commit the batch (its objects stored already) in one transaction;
    /// then tell the waiters here.
    async fn commit(&self, b: Built) -> Result<Committed> {
        let t = Instant::now();
        let hub = &self.hub;
        let moved = b.after.tip != b.old_tip;
        let results: Vec<LandResult> = b
            .rows
            .iter()
            .zip(&b.outcomes)
            .map(|((_, ticket), o)| {
                let mut r = super::queued(ticket);
                match o {
                    Outcome::Landed { reals } => {
                        r.state = LandState::Landed;
                        r.landed = reals.clone();
                    }
                    Outcome::Conflict { paths } => {
                        r.state = LandState::Conflict;
                        r.message = Some(format!(
                            "a path this change edits changed on '{}' since its base: get the branch's new tip, redo the change on it, and land it again",
                            self.branch
                        ));
                        r.paths = paths.clone();
                    }
                    Outcome::Rejected(why) => {
                        r.state = LandState::Rejected;
                        r.message = Some(why.clone());
                    }
                }
                r
            })
            .collect();
        let (pid, branch, holder, epoch, name) = (self.project, self.branch.clone(), hub.landing.holder.clone(), self.epoch, self.name.clone());
        let old = b.old_tip.map(|t| t.hex());
        let new = b.after.tip.map(|t| t.hex());
        let seqs: Vec<i64> = b.rows.iter().map(|r| r.0).collect();
        let snapshots: Vec<String> = b.snapshots.iter().map(ObjectId::hex).collect();
        let (ls, ll): (Vec<String>, Vec<String>) = b.landings.iter().map(|(s, l)| (s.hex(), l.hex())).unzip();
        let mk: Vec<String> = b.memos.iter().map(|m| m.0.clone()).collect();
        let mr: Vec<String> = b.memos.iter().map(|m| m.1.hex()).collect();
        let mp: Vec<String> = b.memos.iter().map(|m| m.2.hex()).collect();
        let accept = b.accept.clone();
        let landed = b.outcomes.iter().filter(|o| matches!(o, Outcome::Landed { .. })).count();
        let notify = hub.caches.notices.load(Ordering::SeqCst);
        let tx_results = results.clone();
        let r = crate::db::transaction(&hub.db, crate::db::Isolation::ReadCommitted, move |c| {
            let (ls, ll) = (ls.clone(), ll.clone());
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
                if moved {
                    let n = sqlx::query("UPDATE branches SET target = $1 WHERE project_id = $2 AND name = $3 AND target = $4")
                        .bind(&new)
                        .bind(pid)
                        .bind(&branch)
                        .bind(&old)
                        .execute(&mut *c)
                        .await?
                        .rows_affected();
                    if n != 1 {
                        return Err(Error::conflict(MOVED));
                    }
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
                let states: Vec<String> = results.iter().map(|r| state_name(r.state).to_string()).collect();
                let texts: Vec<String> = results.iter().map(|r| serde_json::to_string(r).unwrap_or_default()).collect();
                let n = sqlx::query(
                    "UPDATE landing_queue AS q SET state = v.state, result = v.result, done_at = $6 \
                     FROM unnest($3::BIGINT[], $4::TEXT[], $5::TEXT[]) AS v(seq, state, result) \
                     WHERE q.project_id = $1 AND q.branch = $2 AND q.seq = v.seq AND q.state = 'queued'",
                )
                .bind(pid)
                .bind(&branch)
                .bind(&seqs)
                .bind(&states)
                .bind(&texts)
                .bind(veil_core::now_millis())
                .execute(&mut *c)
                .await?
                .rows_affected();
                if n != seqs.len() as u64 {
                    return Err(Error::conflict(MOVED));
                }
                if !snapshots.is_empty() {
                    sqlx::query("INSERT INTO snapshots (project_id, id) SELECT $1, unnest($2::TEXT[]) ON CONFLICT DO NOTHING")
                        .bind(pid)
                        .bind(&snapshots)
                        .execute(&mut *c)
                        .await?;
                }
                if !ls.is_empty() {
                    sqlx::query(
                        "INSERT INTO landings (project_id, submitted, landed) SELECT $1, s, l FROM unnest($2::TEXT[], $3::TEXT[]) AS v(s, l) \
                         ON CONFLICT DO NOTHING",
                    )
                    .bind(pid)
                    .bind(&ls)
                    .bind(&ll)
                    .execute(&mut *c)
                    .await?;
                }
                if !mk.is_empty() {
                    let stored: Vec<(String, String)> = sqlx::query_as(
                        "INSERT INTO projections (project_id, view_key, real_id, projected_id, created_at) \
                         SELECT $1, k, r, p, $5 FROM unnest($2::TEXT[], $3::TEXT[], $4::TEXT[]) AS v(k, r, p) ON CONFLICT DO NOTHING \
                         RETURNING view_key, real_id",
                    )
                    .bind(pid)
                    .bind(&mk)
                    .bind(&mr)
                    .bind(&mp)
                    .bind(veil_core::now_millis())
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
                            return Err(Error::conflict(MOVED));
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
            Err(e) => return Err(e),
        };
        for s in &b.snapshots {
            hub.caches.put_committed(self.project, s);
        }
        for (k, real, proj) in &b.memos {
            hub.caches.put_memo(self.project, k, real, proj);
        }
        if moved {
            hub.caches.tips_changed(self.project);
            crate::derive::landed(hub, self.project, vec![self.branch.clone()]);
        }
        let st = &hub.landing.stats;
        st.batches.fetch_add(1, Ordering::Relaxed);
        st.landed.fetch_add(landed as u64, Ordering::Relaxed);
        st.conflicts.fetch_add(b.outcomes.iter().filter(|o| matches!(o, Outcome::Conflict { .. })).count() as u64, Ordering::Relaxed);
        st.rejected.fetch_add(b.outcomes.iter().filter(|o| matches!(o, Outcome::Rejected(_))).count() as u64, Ordering::Relaxed);
        st.commit_us.fetch_add(t.elapsed().as_micros() as u64, Ordering::Relaxed);
        hub.landing.resolve(b.rows.iter().map(|r| r.1.clone()).zip(results));
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
            hub.caches.put_memo(project, &k, &r, &p);
            out.insert((k, r), p);
        }
    }
    Ok(out)
}

const LEASE_LOST: &str = "the landing lease was lost";
const MOVED: &str = "the branch moved under the landing service";

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
    let view = who.project.view(&who.viewer);
    let (px, raw) = sync::project_one(src, &view, x, &s, pparents, ppreds, origins.get(&x).copied(), identity)?;
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
    };
    let Inputs { entries, attach, mut memo, origins } = inputs;
    let mut b = Built {
        rows: Vec::new(),
        outcomes: Vec::new(),
        objects: Vec::new(),
        bytes: 0,
        snapshots: Vec::new(),
        landings: Vec::new(),
        memos: Vec::new(),
        old_tip: on.tip,
        after: on.clone(),
        alone: false,
        accept: None,
    };
    // Attached keys: projected from their memo over what came after it.
    for (k, who, at, m) in attach {
        let mut p = m;
        let mut made = Vec::new();
        let mut ok = true;
        for x in on.recent.iter().skip(at + 1) {
            match project_onto(&src, &who, &k, *x, p, &memo, &origins, &hub.identity)? {
                Some((px, raw, new)) => {
                    if new {
                        made.push((*x, px, raw));
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
        for (x, px, raw) in made {
            if let Some(raw) = raw {
                b.object(&mut src, px, raw);
            }
            memo.insert((k.clone(), x), px);
            b.memos.push((k.clone(), x, px));
            hub.landing.stats.projected.fetch_add(1, Ordering::Relaxed);
        }
        b.after.keys.insert(k, Kept { who, at: p });
    }
    for p in entries {
        if b.alone {
            break;
        }
        // Bounded in bytes, with the batch being committed (BUG-1107).
        if !b.rows.is_empty() && on.made_bytes + b.bytes >= BATCH_BYTES {
            break;
        }
        let mark = (b.objects.len(), b.bytes, b.snapshots.len(), b.memos.len(), b.landings.len());
        let row = (p.row.seq, p.row.ticket.clone());
        let outcome = match entry(&hub, &mut src, branch, &p, &mut b, &mut memo, &origins) {
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
            // Nothing of it stays.
            b.objects.truncate(mark.0);
            b.bytes = mark.1;
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
fn entry(
    hub: &Arc<Hub>,
    src: &mut Source,
    branch: &str,
    p: &Prepared,
    b: &mut Built,
    memo: &mut HashMap<(String, ObjectId), ObjectId>,
    origins: &HashMap<ObjectId, ObjectId>,
) -> Result<Option<Outcome>> {
    let Some(tip) = b.after.tip else { return Ok(Some(Outcome::Rejected(format!("there is no branch '{branch}'")))) };
    let who = match &p.who {
        Ok(a) => a.clone(),
        Err(why) => return Ok(Some(Outcome::Rejected(why.clone()))),
    };
    if p.row.stack.is_empty() {
        return Ok(Some(Outcome::Rejected("nothing to land".into())));
    }
    let snaps: Vec<Arc<Snapshot>> = p.row.stack.iter().map(|s| src.snapshot(s)).collect::<veil_core::Result<_>>()?;
    let mut sets: Vec<Vec<Change>> = Vec::new();
    for s in &snaps {
        let parent = src.snapshot(&s.parents[0])?;
        sets.push(edits::edit_set(src, s.tree, parent.tree)?);
    }
    if sets.iter().flatten().any(|c| c.path == POLICY_FILE || c.path == RULES_FILE) {
        if !b.rows.is_empty() {
            return Ok(None);
        }
        b.alone = true;
    }
    // Access changed since the submit: it decides first, whatever happened
    // on the tip since, so the answer to someone who may no longer write a
    // path never says whether it changed (BUG-1104). (A merge's paths taken
    // from another parent are the push's checks', below.)
    if p.recheck {
        let view = who.project.view(&who.viewer);
        for (s, set) in snaps.iter().zip(&sets) {
            if s.parents.len() == 1 {
                if let Some(c) = set.iter().find(|c| !view.write(&c.path)) {
                    return Ok(Some(Outcome::Rejected(format!("you may not write '{}'", c.path))));
                }
            }
        }
    }
    // The stack, change by change, on the tip.
    let mut chain = tip;
    let tip_tree = src.snapshot(&tip)?.tree;
    let mut chain_tree = tip_tree;
    let mut landed: Vec<(ObjectId, Arc<Snapshot>)> = Vec::new();
    for (i, (s, set)) in snaps.iter().zip(&sets).enumerate() {
        let sid = p.row.stack[i];
        let parent = s.parents[0];
        let parent_tree = src.snapshot(&parent)?.tree;
        let (id, snap, parents) = if parent == chain {
            (sid, s.clone(), s.parents.clone())
        } else {
            if s.parents.len() > 1 {
                return Ok(Some(Outcome::Rejected(
                    "a merge lands only on the tip it was made on: merge the branch's new tip and land again".into(),
                )));
            }
            if edits::fast_path(src, parent_tree, chain_tree, set)?.is_some() {
                // Every path of the change that moved (all its own paths).
                let mut paths = Vec::new();
                for c in set {
                    if edits::fast_path(src, parent_tree, chain_tree, std::slice::from_ref(c))?.is_some() {
                        paths.push(c.path.clone());
                    }
                }
                return Ok(Some(Outcome::Conflict { paths }));
            }
            let mut made = HashMap::new();
            let tree = match edits::apply(src, chain_tree, set, &mut made)? {
                Ok(t) => t,
                Err(edits::Blocked(path)) => return Ok(Some(Outcome::Conflict { paths: vec![path] })),
            };
            for (id, (raw, _)) in made {
                b.object(src, id, Bytes::from(raw));
            }
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
            let mut n = Snapshot {
                parents: vec![chain],
                change_id: s.change_id,
                tree,
                description: s.description.clone(),
                author: s.author.clone(),
                timestamp: s.timestamp,
                predecessors: vec![sid],
                conflicts: vec![],
                embargo: None,
                signature: None,
            };
            n.sign(&hub.identity);
            let raw = Bytes::from(Object::Snapshot(n.clone()).encode());
            let id = ObjectId::hash(&raw);
            b.object(src, id, raw);
            b.snapshots.push(id);
            b.landings.push((sid, id));
            (id, Arc::new(n), vec![chain])
        };
        // The push's checks again, on the new parents, when what they read
        // may have changed: access (epochs), or the policy file the
        // classification reads.
        let policy_moved = sync::entry_at(src, &parent_tree, POLICY_FILE)? != sync::entry_at(src, &chain_tree, POLICY_FILE)?;
        if p.recheck || policy_moved {
            if let Err(why) = recheck(src, &who, &snap, &parents, set, &hub.identity)? {
                return Ok(Some(Outcome::Rejected(why)));
            }
        }
        landed.push((id, snap));
        chain = id;
        chain_tree = landed.last().expect("pushed").1.tree;
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
                    if new {
                        new_memos.push((k.clone(), *x, px, raw));
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
    }
    for (k, x, px, raw) in new_memos {
        if keys.contains_key(&k) {
            if let Some(raw) = raw {
                b.object(src, px, raw);
            }
            b.memos.push((k, x, px));
            hub.landing.stats.projected.fetch_add(1, Ordering::Relaxed);
        }
    }
    b.after.keys = keys;
    for (x, _) in &landed {
        b.after.recent.push_back(*x);
        if b.after.recent.len() > RECENT {
            b.after.recent.pop_front();
        }
    }
    b.after.tip = Some(chain);
    Ok(Some(Outcome::Landed {
        reals: landed.iter().map(|l| l.0).collect(),
    }))
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
    let c = match sync::complete(src, &who.project, &who.viewer, &known, &n, parents, identity) {
        Ok(c) => c,
        Err(Error::Api { message, code: "forbidden" | "bad_request", .. }) => return Ok(Err(message)),
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
