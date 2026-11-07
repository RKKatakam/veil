//! One branch's landing service (`docs/design/server/phase-4-agent-scale.md`
//! §4.2): the lease, batches, the fast path, the landing check, pipelining
//! and one database commit per batch.
//!
//! ```text
//! loop:
//!   entries := the ready queue rows not in the batch being committed, in order, at most MAX_BATCH
//!   build on the tip the batch being committed leaves (pipelined), in memory:
//!     an entry that changes .veilpolicy or .veilrules ends the batch before it, and lands alone
//!     for each change of an entry's stack:
//!       on the tip already: it lands as it is
//!       else: the fast path (every edited path as its base had it) or `conflict`;
//!             apply its edits; the landing check; a new snapshot, signed by the server
//!       access changed since the submit (epochs), or the tip's .veilpolicy differs from
//!       its base's: the push's checks again (`sync::complete`) on the new parent
//!     projections of every new snapshot for the view keys in use
//!   wait for the batch being committed; if it lost (the tip moved, the lease was lost): discard, start again
//!   store the new objects, then one transaction: the lease's epoch (fencing), the queue rows
//!   (still queued, or nothing lands), snapshots, projection memos, the branch's compare-and-swap
//! ```

use std::{
    collections::{BTreeMap, HashMap, HashSet},
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

/// Who an entry lands as, now.
#[derive(Clone)]
struct As {
    project: Arc<Project>,
    viewer: Viewer,
    /// `None` for an admin (who sees real snapshots).
    key: Option<String>,
}

/// The branch as the service last left it (or predicts it, after the batch
/// being committed).
#[derive(Clone, Default)]
struct State {
    tip: Option<ObjectId>,
    /// The view keys kept up to date: who has each (any viewer of that key
    /// gives the same view), and the projection of `tip` for it.
    keys: BTreeMap<String, (As, ObjectId, Instant)>,
    /// The objects of the batch that made `tip`, which may not be stored
    /// yet while it commits: the next batch is built on them.
    made: Arc<HashMap<ObjectId, Bytes>>,
}

/// An entry ready to build.
struct Prepared {
    row: Row,
    who: Result<As, String>,
    /// Re-run the push's checks when it lands: access changed since it was
    /// submitted.
    recheck: bool,
    /// The submitter's projections of the stack's snapshots.
    psub: Vec<ObjectId>,
}

/// What one entry came to.
enum Outcome {
    Landed { seen: Vec<ObjectId> },
    Conflict { paths: Vec<String> },
    Rejected(String),
}

/// A batch built in memory.
struct Built {
    rows: Vec<(i64, String)>,
    outcomes: Vec<Outcome>,
    objects: Vec<(ObjectId, Bytes)>,
    snapshots: Vec<ObjectId>,
    memos: Vec<(String, ObjectId, ObjectId)>,
    old_tip: Option<ObjectId>,
    after: State,
    /// It changed `.veilpolicy` or `.veilrules`: landed alone.
    alone: bool,
    /// The default branch's new access lines, for its one entry.
    accept: Option<String>,
}

/// How a batch's commit ended.
enum Committed {
    Ok,
    /// The branch moved under it (an admin's forced push): nothing landed.
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
        let mut inflight: Option<InFlight> = None;
        let mut idle = Instant::now();
        let mut renewed = Instant::now();
        loop {
            // A change of access or rules is committed before anything is
            // built after it: later entries are checked against it.
            if inflight.as_ref().is_some_and(|f| f.alone) {
                match self.finish(inflight.take().expect("checked"), &mut state).await? {
                    true => {}
                    false => return Ok(()),
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
            let on = inflight.as_ref().map(|f| f.after.clone()).unwrap_or_else(|| state.clone());
            let prepared = match self.prepare(rows, &on, inflight.is_some()).await? {
                Some(p) => p,
                None => {
                    // A view key new to this service needs the tip committed.
                    if let Some(f) = inflight.take() {
                        if !self.finish(f, &mut state).await? {
                            return Ok(());
                        }
                    }
                    continue;
                }
            };
            let t = Instant::now();
            let built = self.build(prepared, on).await?;
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

    /// The branch's tip, from the database.
    async fn load(&self) -> Result<State> {
        let t: Option<String> = sqlx::query_scalar("SELECT target FROM branches WHERE project_id = $1 AND name = $2")
            .bind(self.project)
            .bind(&self.branch)
            .fetch_optional(&self.hub.db)
            .await?;
        Ok(State {
            tip: t.map(|t| ObjectId::from_hex(&t).map_err(|e| Error::Other(e.into()))).transpose()?,
            keys: BTreeMap::new(),
            made: Arc::default(),
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

    /// Who each entry lands as now, whether its checks must run again, its
    /// submitter's projections, and the projection of the tip `on` for
    /// every view key in use. `None` when a view key new to this service
    /// needs `on` committed first (`pipelined`).
    async fn prepare(&self, rows: Vec<Row>, on: &State, pipelined: bool) -> Result<Option<(Vec<Prepared>, Vec<(String, As, ObjectId)>)>> {
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
        let mut who: HashMap<(i64, String), Result<As, String>> = HashMap::new();
        let mut out = Vec::new();
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
                who.insert(k.clone(), w);
            }
            let w = who[&k].clone();
            let recheck = row.epochs != (person_epoch(row.person.id), project_epoch);
            let mut psub = Vec::new();
            if let Ok(a) = &w {
                for s in &row.stack {
                    psub.push(sync::projected(hub, &a.project, &a.viewer, *s).await?);
                }
            }
            out.push(Prepared { row, who: w, recheck, psub });
        }
        // The tip as each view key new to this service sees it.
        let mut new_keys: Vec<(String, As, ObjectId)> = Vec::new();
        if let Some(tip) = on.tip {
            for p in &out {
                let Ok(a) = &p.who else { continue };
                let Some(k) = &a.key else { continue };
                if on.keys.contains_key(k) || new_keys.iter().any(|(m, _, _)| m == k) {
                    continue;
                }
                if pipelined {
                    return Ok(None);
                }
                new_keys.push((k.clone(), a.clone(), sync::projected(hub, &a.project, &a.viewer, tip).await?));
            }
        }
        Ok(Some((out, new_keys)))
    }

    /// Build the batch on `on` (on a blocking thread: trees, hashes,
    /// signatures).
    async fn build(&self, (prepared, new_keys): (Vec<Prepared>, Vec<(String, As, ObjectId)>), mut on: State) -> Result<Built> {
        let now = Instant::now();
        for (k, a, seen) in new_keys {
            on.keys.insert(k, (a, seen, now));
        }
        // Keys nobody landed with for a minute are no longer kept up to date
        // (their viewers' next requests project on demand, as before).
        on.keys.retain(|_, v| v.2.elapsed() < Duration::from_secs(60));
        while on.keys.len() > MAX_KEYS {
            let oldest = on.keys.iter().min_by_key(|(_, v)| v.2).map(|(k, _)| k.clone()).expect("not empty");
            on.keys.remove(&oldest);
        }
        let (hub, project, branch) = (self.hub.clone(), self.project, self.branch.clone());
        let rt = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || build(hub, rt, project, &branch, prepared, on)).await.map_err(|e| Error::Other(e.into()))?
    }

    /// Commit the batch (its objects stored already) in one transaction;
    /// then tell the waiters here.
    async fn commit(&self, b: Built) -> Result<Committed> {
        let t = Instant::now();
        let hub = &self.hub;
        let moved = b.after.tip != b.old_tip;
        let mut results: Vec<LandResult> = b
            .rows
            .iter()
            .zip(&b.outcomes)
            .map(|((_, ticket), o)| {
                let mut r = super::queued(ticket);
                match o {
                    Outcome::Landed { seen, .. } => {
                        r.state = LandState::Landed;
                        r.landed = seen.clone();
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
        let (mk, mr, mp): (Vec<String>, Vec<String>, Vec<String>) = {
            let mut k = Vec::new();
            let mut r = Vec::new();
            let mut p = Vec::new();
            for (key, real, proj) in &b.memos {
                k.push(key.clone());
                r.push(real.hex());
                p.push(proj.hex());
            }
            (k, r, p)
        };
        let accept = b.accept.clone();
        let landed = b.outcomes.iter().filter(|o| matches!(o, Outcome::Landed { .. })).count();
        let notify = hub.caches.notices.load(Ordering::SeqCst);
        let tx_results = results.clone();
        let r = crate::db::transaction(&hub.db, crate::db::Isolation::ReadCommitted, move |c| {
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
                if !mk.is_empty() {
                    sqlx::query(
                        "INSERT INTO projections (project_id, view_key, real_id, projected_id, created_at) \
                         SELECT $1, k, r, p, $5 FROM unnest($2::TEXT[], $3::TEXT[], $4::TEXT[]) AS v(k, r, p) ON CONFLICT DO NOTHING",
                    )
                    .bind(pid)
                    .bind(&mk)
                    .bind(&mr)
                    .bind(&mp)
                    .bind(veil_core::now_millis())
                    .execute(&mut *c)
                    .await?;
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
        let stored = match r {
            Ok(r) => r,
            Err(Error::Api { code: "conflict", message, .. }) if message == LEASE_LOST => {
                hub.landing.stats.lease_lost.fetch_add(1, Ordering::Relaxed);
                return Ok(Committed::LeaseLost);
            }
            Err(Error::Api { code: "conflict", message, .. }) if message == MOVED => return Ok(Committed::Moved),
            Err(e) => return Err(e),
        };
        results = stored;
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

/// The batch, built on `on`: each entry in order, until one that must land
/// alone.
fn build(hub: Arc<Hub>, rt: tokio::runtime::Handle, project: i64, branch: &str, prepared: Vec<Prepared>, on: State) -> Result<Built> {
    let mut src = Source {
        hub: hub.clone(),
        project,
        rt,
        pending: (*on.made).clone(),
    };
    let mut b = Built {
        rows: Vec::new(),
        outcomes: Vec::new(),
        objects: Vec::new(),
        snapshots: Vec::new(),
        memos: Vec::new(),
        old_tip: on.tip,
        after: on.clone(),
        alone: false,
        accept: None,
    };
    for p in prepared {
        if b.alone {
            break;
        }
        let mark = (b.objects.len(), b.snapshots.len(), b.memos.len(), src.pending.len());
        let row = (p.row.seq, p.row.ticket.clone());
        let outcome = match entry(&hub, &mut src, branch, &p, &mut b) {
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
            b.snapshots.truncate(mark.1);
            b.memos.truncate(mark.2);
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
    }
    Ok(b)
}

/// Land one entry's stack on `b.after`'s tip: its outcome (and, when it
/// landed, `b.after` moved on), or `None` when it must land alone and does
/// not come first.
fn entry(hub: &Arc<Hub>, src: &mut Source, branch: &str, p: &Prepared, b: &mut Built) -> Result<Option<Outcome>> {
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
    // The stack, change by change, on the tip.
    let mut chain = tip;
    let mut chain_tree = src.snapshot(&tip)?.tree;
    let mut landed: Vec<(ObjectId, Arc<Snapshot>, bool)> = Vec::new();
    for (i, (s, set)) in snaps.iter().zip(&sets).enumerate() {
        let sid = p.row.stack[i];
        let parent = s.parents[0];
        let parent_tree = src.snapshot(&parent)?.tree;
        let (id, snap, rebuilt) = if parent == chain {
            (sid, s.clone(), false)
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
                let raw = Bytes::from(raw);
                src.pending.insert(id, raw.clone());
                b.objects.push((id, raw));
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
            src.pending.insert(id, raw.clone());
            b.objects.push((id, raw));
            b.snapshots.push(id);
            (id, Arc::new(n), true)
        };
        // The push's checks again, on the new parent, when what they read
        // may have changed: access (epochs), or the policy file the
        // classification reads.
        let policy_moved = sync::entry_at(src, &parent_tree, POLICY_FILE)? != sync::entry_at(src, &chain_tree, POLICY_FILE)?;
        if p.recheck || policy_moved {
            if let Err(why) = recheck(src, &who, &snap, chain, set, &hub.identity)? {
                return Ok(Some(Outcome::Rejected(why)));
            }
        }
        landed.push((id, snap, rebuilt));
        chain = id;
        chain_tree = landed.last().expect("pushed").1.tree;
    }
    // A change of who has access, on the default branch: an admin's only.
    if b.alone && branch == who.project.default_branch {
        let text = sync::policy_text(src, &chain_tree)?;
        if !AccessPolicy::parse(&text).same_rules(&who.project.policy) {
            if !who.viewer.admin {
                return Ok(Some(Outcome::Rejected("only admins may change who has access (the default branch's .veilpolicy)".into())));
            }
            b.accept = Some(text);
        }
    }
    // Projections of every new snapshot for every view key in use; the
    // submitter's are their answer.
    let mut seen = Vec::new();
    for (i, (x, snap, rebuilt)) in landed.iter().enumerate() {
        let keys: Vec<String> = b.after.keys.keys().cloned().collect();
        for k in keys {
            let (a, pp, _) = b.after.keys[&k].clone();
            let mine = who.key.as_deref() == Some(k.as_str());
            let px = if mine && !rebuilt {
                // Landed as it was submitted: its projection is the submit's.
                p.psub[i]
            } else {
                let mut ppreds = Vec::new();
                for pred in &snap.predecessors {
                    let pp = match p.row.stack.iter().position(|s| s == pred) {
                        Some(j) if mine => Some(p.psub[j]),
                        _ => hub.caches.memo(src.project, &k, pred),
                    };
                    if let Some(pp) = pp {
                        if src.snapshot(&pp)?.change_id == src.snapshot(pred)?.change_id && !ppreds.contains(&pp) {
                            ppreds.push(pp);
                        }
                    }
                }
                let view = a.project.view(&a.viewer);
                let (px, raw) = sync::project_one(src, &view, *x, snap, vec![pp], ppreds, None, &hub.identity)?;
                if let Some(raw) = raw {
                    src.pending.insert(px, raw.clone());
                    b.objects.push((px, raw));
                }
                px
            };
            b.memos.push((k.clone(), *x, px));
            if let Some(e) = b.after.keys.get_mut(&k) {
                e.1 = px;
                if mine {
                    e.2 = Instant::now();
                }
            }
            if mine {
                seen.push(px);
            }
        }
        if who.key.is_none() {
            seen.push(*x);
        }
    }
    b.after.tip = Some(chain);
    Ok(Some(Outcome::Landed { seen }))
}

/// The push's checks (`sync::complete`) for candidate `real` (a real
/// snapshot) on real parent `parent`, as `who` sees it now: the tree they
/// would push is their projection of it, grafted back onto the parent; the
/// graft must give back exactly the candidate's tree. `Ok(Err(why))` when
/// it is refused.
fn recheck(src: &mut Source, who: &As, real: &Snapshot, parent: ObjectId, set: &[Change], identity: &veil_core::Identity) -> Result<std::result::Result<(), String>> {
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
        parents: vec![parent],
        tree: ptree,
        signature: None,
        ..real.clone()
    };
    let c = match sync::complete(src, &who.project, &who.viewer, &known, &n, &[parent], identity) {
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
