//! Derived history data (milestone S12;
//! `docs/design/server/phase-3-server-history.md` §3.1–§3.4, §4.2).
//!
//! **One mechanism:** each index's value for a snapshot is a function of the
//! snapshot and its parents' values. The server computes it on real
//! (unprojected) history, because it is trusted with code; projection
//! happens when an answer is served ([`view`]), never when it is computed.
//!
//! | Index | Value per snapshot | Stored |
//! |---|---|---|
//! | [`graph`] | generation, first-parent depth, parents, change id, embargo flags, jump table | `graph` rows |
//! | [`changes`] | changed paths with old and new entries, copies and renames, file history (`prev`) | an object per snapshot, `file_history` rows |
//! | [`lines`] | the access lines whose paths the snapshot changed | `rule_history` rows |
//!
//! **When.** Eagerly after every landing ([`landed`], called by `sync::push`
//! once its transaction committed: the push never waits), and on demand
//! ([`ensure`], for a query on a snapshot not derived yet). Both run
//! [`catch_up`]: under a per-project database advisory lock (one deriver per
//! project across all servers), it builds the lists a new accepted policy
//! needs, then derives every snapshot the branches reach that has no value
//! yet, parents first, and records how far each branch is derived
//! (`derive_progress`). Then the deriver projects each branch tip once for
//! every view key of the project's people ([`memo_tips`]), so a viewer's
//! first pull after a landing finds its projection memoised (phase 4
//! §4.5).
//!
//! **Idempotent and resumable.** Values are functions of immutable inputs,
//! so recomputing gives the same rows and the same object bytes. A batch
//! writes, in order, objects, `file_history` and `rule_history` rows, and
//! last the `graph` rows, which mark the snapshots derived: a crash at any
//! point leaves rows that the next run writes again identically
//! (`ON CONFLICT DO NOTHING`), and nothing marked derived without its
//! values. Every statement is retried on a retryable database error.
//!
//! **Bounded (BUG-911).** At most [`DERIVERS`] runs derive at once in a
//! server process, on the deriver's own pool ([`Workers::db`], two
//! connections per run: the lock's and one statement's): however many
//! projects land, background derivation never takes a connection that
//! requests need, and runs waiting their turn (or for another server's
//! lock) hold nothing. The derived data lags instead, and catches up.
//!
//! **The query API** (S13, `crate::query`) does not read these: it answers
//! from each viewer's own graph (`query::graph`), which [`memo_tips`]
//! extends with the projections. [`read`] and [`view`] stay the internal
//! reads of blame, file history and search (S14, S15).

pub mod blame;
pub mod changes;
pub mod graph;
pub mod lines;
pub mod view;

use std::{
    cell::Cell,
    collections::{BTreeSet, HashMap, HashSet},
    future::Future,
    sync::{Arc, Mutex},
    time::Duration,
};

use bytes::Bytes;
use sqlx::PgPool;
use veil_core::{cache::LruCache, hub::access::AccessPolicy, hub::project::Change, ObjectId};

use self::{
    changes::{Changed, PathChange, MANY, NONE, WITHHELD},
    graph::{Graph, GraphRow, FLAG_EMBARGO_LINE},
    lines::Lines,
};
use crate::{
    error::{Error, Result},
    sync::{root_snapshot_id, Source},
    Hub,
};

/// The name and version of the derived history in `derive_progress` (the
/// three indexes are derived together).
pub const INDEX: (&str, i32) = ("history", 1);
/// Snapshots derived between two writes to the database.
const FLUSH_EVERY: usize = 512;
/// Rows per insert statement: small enough that one stays well inside the
/// statement timeout on a busy YugabyteDB.
const ROWS_PER_STATEMENT: usize = 1_000;
/// How long a deriver waits for another server's deriver of the same
/// project; after that the other one (or the next landing) derives it.
const LOCK_WAIT: Duration = Duration::from_secs(60);
/// Retries of one statement on a retryable error (a statement timeout
/// included). The deriver works in the background, so it may wait out a
/// busy database longer than a request does.
const STATEMENT_DEADLINE: Duration = Duration::from_secs(120);
/// The advisory lock of project `p` is `LOCK_BASE ^ p`.
const LOCK_BASE: i64 = 0x7665_696c_6472_0000; // "veildr"
/// Most runs deriving at once in one server process (BUG-911); the others
/// wait their turn, holding no connection.
pub const DERIVERS: usize = 4;
/// Connections of the deriver's own pool: each run holds the project
/// lock's and at most one statement's at a time.
pub const DERIVE_CONNECTIONS: u32 = 2 * DERIVERS as u32;

/// The derive workers' state in one server process.
pub struct Workers {
    /// The deriver's own pool ([`DERIVE_CONNECTIONS`]), apart from the
    /// requests' (BUG-911).
    pub db: PgPool,
    /// One permit per run deriving or memoising ([`DERIVERS`]).
    permits: tokio::sync::Semaphore,
    /// Projects being derived here, with the branches landed on meanwhile.
    active: Mutex<HashMap<i64, BTreeSet<String>>>,
    /// Graph rows by `(project, snapshot)` (rows never change).
    rows: LruCache<Arc<GraphRow>>,
}

impl Workers {
    /// The workers, deriving on `db` (a pool of [`DERIVE_CONNECTIONS`]).
    pub fn new(db: PgPool) -> Workers {
        Workers {
            db,
            permits: tokio::sync::Semaphore::new(DERIVERS),
            active: Mutex::new(HashMap::new()),
            rows: LruCache::new(64 << 20),
        }
    }

    pub(crate) async fn permit(&self) -> Result<tokio::sync::SemaphorePermit<'_>> {
        self.permits.acquire().await.map_err(|e| Error::Other(e.into()))
    }

    /// Forget the cached graph rows, as a restarted server would (the
    /// tests' crash and resume).
    pub fn clear_cache(&self) {
        self.rows.clear();
    }
}

fn row_key(project: i64, id: &ObjectId) -> ObjectId {
    let mut h = blake3::Hasher::new();
    h.update(b"graph");
    h.update(&project.to_le_bytes());
    h.update(&id.0);
    ObjectId(*h.finalize().as_bytes())
}

thread_local! {
    /// Set on the thread of a derive run ([`locked`]): its statements go to
    /// the deriver's pool.
    static DERIVING: Cell<bool> = const { Cell::new(false) };
}

/// Run `f` as a derive run on this thread ([`DERIVING`]).
fn deriving<T>(f: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            DERIVING.set(false);
        }
    }
    DERIVING.set(true);
    let _reset = Reset;
    f()
}

fn bad(e: impl std::fmt::Display) -> Error {
    Error::Other(anyhow::anyhow!("derived data: {e}"))
}

/// One project's derived data, read and written on a blocking thread.
pub struct Cx {
    pub src: Source,
}

impl Cx {
    pub fn hub(&self) -> &Arc<Hub> {
        &self.src.hub
    }

    pub fn project(&self) -> i64 {
        self.src.project
    }

    /// The pool of this thread's statements: the deriver's own in a derive
    /// run, the requests' in a query's read (BUG-911).
    pub fn pool(&self) -> &PgPool {
        if DERIVING.get() {
            &self.hub().derive.db
        } else {
            &self.hub().db
        }
    }

    /// Run a statement, again while it fails on a retryable error.
    pub fn db<T, F, Fut>(&self, f: F) -> Result<T>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = std::result::Result<T, sqlx::Error>>,
    {
        self.src.rt.block_on(async {
            let deadline = tokio::time::Instant::now() + STATEMENT_DEADLINE;
            let mut attempt = 0u32;
            loop {
                attempt += 1;
                match f().await {
                    Ok(v) => return Ok(v),
                    Err(e) => {
                        let e = Error::from(e);
                        if !e.is_retryable() || tokio::time::Instant::now() >= deadline {
                            return Err(e);
                        }
                        tokio::time::sleep(Duration::from_millis(5 << attempt.min(6))).await;
                    }
                }
            }
        })
    }

    /// The stored (complete) graph row of `id`.
    pub fn stored_row(&self, id: &ObjectId) -> Result<Option<Arc<GraphRow>>> {
        let k = row_key(self.project(), id);
        if let Some(r) = self.hub().derive.rows.get(&k) {
            return Ok(Some(r));
        }
        type Row = (i64, i64, String, String, i32, String, Option<String>);
        let pool = self.pool();
        let hex = id.hex();
        let row: Option<Row> = self.db(|| {
            sqlx::query_as("SELECT generation, depth, parents, change_id, flags, skip, changed FROM graph WHERE project_id = $1 AND snapshot = $2")
                .bind(self.project())
                .bind(&hex)
                .fetch_optional(pool)
        })?;
        let Some((generation, depth, parents, change_id, flags, skip, changed)) = row else { return Ok(None) };
        let r = Arc::new(GraphRow {
            generation,
            depth,
            parents: serde_json::from_str(&parents).map_err(bad)?,
            change_id,
            flags,
            skip: serde_json::from_str(&skip).map_err(bad)?,
            changed,
        });
        self.hub().derive.rows.insert(k, r.clone(), 256);
        Ok(Some(r))
    }

    /// The changed paths of a snapshot whose row says `changed`; `None`
    /// for `many` and `withheld` (queries walk the trees, or wait for the
    /// release).
    pub fn changed(&self, changed: &str) -> Result<Option<Changed>> {
        match changed {
            NONE => Ok(Some(Changed {
                similar: true,
                ..Changed::default()
            })),
            MANY | WITHHELD => Ok(None),
            id => Ok(Some(Changed::decode(&self.src.raw(&ObjectId::from_hex(id).map_err(bad)?)?)?)),
        }
    }

    /// The accepted policy and its lists.
    pub fn lines(&self) -> Result<Lines> {
        let pool = self.pool();
        let text: String = self.db(|| sqlx::query_scalar("SELECT policy_text FROM projects WHERE id = $1").bind(self.project()).fetch_one(pool))?;
        Ok(Lines::new(&AccessPolicy::parse(&text)))
    }
}

fn cx(hub: &Arc<Hub>, project: i64) -> Cx {
    Cx {
        src: Source {
            hub: hub.clone(),
            project,
            rt: tokio::runtime::Handle::current(),
            pending: Default::default(),
            staged: None,
        },
    }
}

/// Read derived data of `project` on a blocking thread (the internal reads
/// for S13's queries and the tests): `f` gets the project's graph.
pub async fn read<T: Send + 'static>(hub: &Arc<Hub>, project: i64, f: impl FnOnce(&Graph) -> Result<T> + Send + 'static) -> Result<T> {
    let cx = cx(hub, project);
    tokio::task::spawn_blocking(move || f(&Graph::new(&cx))).await.map_err(|e| Error::Other(e.into()))?
}

/// A landing moved `branches` of `project`: derive them in the background.
/// The caller never waits; a landing while this project is being derived
/// here makes the worker run once more, for the branches that landing
/// moved. Only moved branches are touched (BUG-870): the work of a landing
/// never grows with how many branches the project has.
pub fn landed(hub: &Arc<Hub>, project: i64, branches: Vec<String>) {
    if branches.is_empty() {
        return;
    }
    {
        let mut active = hub.derive.active.lock().unwrap();
        if let Some(waiting) = active.get_mut(&project) {
            waiting.extend(branches);
            return;
        }
        active.insert(project, BTreeSet::new());
    }
    let hub = hub.clone();
    tokio::spawn(async move {
        let mut branches = branches;
        loop {
            if let Err(e) = landing(&hub, project, branches).await {
                eprintln!("veil-server: deriving the history of project {project}: {e:?}");
            }
            let next = {
                let mut active = hub.derive.active.lock().unwrap();
                let next = active.get_mut(&project).map(std::mem::take).unwrap_or_default();
                if next.is_empty() {
                    active.remove(&project);
                }
                next
            };
            if next.is_empty() {
                break;
            }
            branches = next.into_iter().collect();
        }
    });
}

/// What [`landed`] runs for the branches a landing moved: derive them, then
/// memoise their tips' projections for every view key.
pub async fn landing(hub: &Arc<Hub>, project: i64, branches: Vec<String>) -> Result<Stats> {
    let stats = catch_up(hub, project, Scope::Branches(branches)).await?;
    // Memoising runs on the requests' pool, so under a permit too: at most
    // [`DERIVERS`] of its connections at once (BUG-911).
    // Derive work is shed second under load (S24): it waits a little.
    hub.limits.derive_turn().await;
    let permit = hub.derive.permit().await?;
    memo_tips(hub, project, &stats.branches).await?;
    drop(permit);
    // The search index (S15) follows the derived branches, in its own task.
    crate::search::index::landed(hub, project, stats.branches.clone());
    Ok(stats)
}

/// At start-up: resume every project (or only `project`) with a branch
/// whose derived tip is not its target (a landing skipped, failed or cut
/// by a restart), one project at a time, in the background (BUG-982).
pub async fn resume(hub: Arc<Hub>, project: Option<i64>) {
    let projects: Result<Vec<i64>> = sqlx::query_scalar(
        "SELECT DISTINCT b.project_id FROM branches b LEFT JOIN derive_progress d \
         ON d.project_id = b.project_id AND d.index_name = $1 AND d.index_version = $2 AND d.branch = b.name \
         WHERE b.hidden_for_embargo IS NULL AND d.through_snapshot IS DISTINCT FROM b.target AND ($3::bigint IS NULL OR b.project_id = $3)",
    )
    .bind(INDEX.0)
    .bind(INDEX.1)
    .bind(project)
    .fetch_all(&hub.db)
    .await
    .map_err(Error::from);
    match projects {
        Ok(projects) => {
            for p in projects {
                if let Err(e) = landing(&hub, p, Vec::new()).await {
                    eprintln!("veil-server: resuming the derived history of project {p}: {e:?}");
                }
            }
        }
        Err(e) => eprintln!("veil-server: finding underived branches: {e:?}"),
    }
}

/// Derive `snapshot` of `project` (committed history) and everything below
/// it now, for a query that needs it.
pub async fn ensure(hub: &Arc<Hub>, project: i64, snapshot: ObjectId) -> Result<Stats> {
    if snapshot != root_snapshot_id() {
        let known: Option<String> = sqlx::query_scalar("SELECT id FROM snapshots WHERE project_id = $1 AND id = $2")
            .bind(project)
            .bind(snapshot.hex())
            .fetch_optional(&hub.db)
            .await?;
        if known.is_none() {
            return Err(Error::not_found("no such snapshot"));
        }
    }
    catch_up(hub, project, Scope::Snapshot(snapshot)).await
}

/// What one run derived.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Branches whose tips the run derived (and recorded in
    /// `derive_progress`).
    pub branches: Vec<String>,
    /// Snapshots derived.
    pub snapshots: usize,
    /// Snapshots added to lists a new policy needed.
    pub rebuilt: usize,
    /// Another server held the project's lock throughout: nothing done here.
    pub skipped: bool,
}

/// What a run derives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Scope {
    /// Every branch: a full catch-up.
    All,
    /// These branches (what a landing moved), and any branch whose derived
    /// tip is not its target (a landing skipped, failed or cut short:
    /// BUG-982); the others are not touched.
    Branches(Vec<String>),
    /// One snapshot of committed history and what is below it (on demand).
    Snapshot(ObjectId),
}

/// Derive every public branch of `project` and prefill viewer graphs.
pub async fn catch_up_project(hub: &Arc<Hub>, project: i64) -> Result<Stats> {
    let stats = catch_up(hub, project, Scope::All).await?;
    if !stats.branches.is_empty() {
        memo_tips(hub, project, &stats.branches).await?;
    }
    Ok(stats)
}

/// Derive what `scope` reaches and is not derived yet, under the project's
/// lock. Runs in its own task: a caller that stops waiting (a request whose
/// client went away) never leaves the lock held on a pooled connection.
pub async fn catch_up(hub: &Arc<Hub>, project: i64, scope: Scope) -> Result<Stats> {
    let hub = hub.clone();
    tokio::spawn(async move { locked(&hub, project, scope).await })
        .await
        .map_err(|e| Error::Other(e.into()))?
}

async fn locked(hub: &Arc<Hub>, project: i64, scope: Scope) -> Result<Stats> {
    let key = LOCK_BASE ^ project;
    let deadline = tokio::time::Instant::now() + LOCK_WAIT;
    // A permit, then a connection of the deriver's pool, held only while
    // the lock is (BUG-911): a run waiting for another server's deriver
    // gives both back between tries.
    let (permit, mut c) = loop {
        // Derive work is shed second under load (S24): it waits a little.
        hub.limits.derive_turn().await;
        let permit = hub.derive.permit().await?;
        let mut c = hub.derive.db.acquire().await?;
        let got: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)").bind(key).fetch_one(&mut *c).await?;
        if got {
            break (permit, c);
        }
        drop((c, permit));
        if tokio::time::Instant::now() >= deadline {
            return Ok(Stats {
                skipped: true,
                ..Stats::default()
            });
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    let cx = cx(hub, project);
    let r = tokio::task::spawn_blocking(move || deriving(|| run(&cx, scope))).await.map_err(|e| Error::Other(e.into()));
    // The lock is the session's: release it, or close the connection so
    // that the lock never goes back into the pool.
    let unlocked = sqlx::query_scalar::<_, bool>("SELECT pg_advisory_unlock($1)").bind(key).fetch_one(&mut *c).await;
    if !matches!(unlocked, Ok(true)) {
        let _ = sqlx::Connection::close(c.detach()).await;
    }
    drop(permit);
    r?
}

/// The snapshot that last changed `path` along `at`'s first parents (`at`
/// included): where `path`'s file history at `at` starts. `at` must be
/// derived.
pub fn last_change(cx: &Cx, path: &str, at: ObjectId) -> Result<Option<ObjectId>> {
    let mut b = Batch::new(cx)?;
    Ok(b.last_changes(&[(path.to_string(), at)])?.pop().flatten())
}

/// Most rows (`file_history` and `rule_history`) and object bytes a batch
/// queues before writing (BUG-867): what one batch holds in memory stays
/// bounded whatever its snapshots changed. A single snapshot's own rows are
/// queued whole (its change list is in memory anyway).
const MAX_QUEUED_ROWS: usize = 100_000;
const MAX_QUEUED_BYTES: usize = 64 << 20;

/// Rows waiting to be written.
#[derive(Default)]
struct Writes {
    objects: Vec<(ObjectId, Bytes)>,
    /// Bytes of `objects`.
    bytes: usize,
    /// `(path key, depth, snapshot)`
    history: Vec<(String, i64, String)>,
    /// `(line key, generation, snapshot)`
    rules: Vec<(String, i64, String)>,
    graph: Vec<(ObjectId, Arc<GraphRow>)>,
}

impl Writes {
    /// Time to write: by snapshots, rows or bytes, whichever comes first.
    fn full(&self) -> bool {
        self.graph.len() >= FLUSH_EVERY || self.history.len() + self.rules.len() >= MAX_QUEUED_ROWS || self.bytes >= MAX_QUEUED_BYTES
    }
}

/// One run of the deriver.
pub struct Batch<'a> {
    cx: &'a Cx,
    pub graph: Graph<'a>,
    lines: Lines,
    /// `file_history` rows of this batch not written yet, by path key.
    history: HashMap<String, Vec<(i64, ObjectId)>>,
    writes: Writes,
    pub stats: Stats,
}

fn run(cx: &Cx, scope: Scope) -> Result<Stats> {
    let pool = cx.pool();
    let mut b = Batch::new(cx)?;
    b.prepare_lists()?;
    let rows: Vec<(String, String)> = match &scope {
        Scope::Snapshot(_) => Vec::new(),
        Scope::All => cx.db(|| {
            sqlx::query_as("SELECT name, target FROM branches WHERE project_id = $1 AND hidden_for_embargo IS NULL")
                .bind(cx.project())
                .fetch_all(pool)
        })?,
        Scope::Branches(names) => cx.db(|| {
            sqlx::query_as(
                "SELECT b.name, b.target FROM branches b LEFT JOIN derive_progress d \
                 ON d.project_id = b.project_id AND d.index_name = $3 AND d.index_version = $4 AND d.branch = b.name \
                 WHERE b.project_id = $1 AND b.hidden_for_embargo IS NULL \
                 AND (b.name = ANY($2) OR d.through_snapshot IS DISTINCT FROM b.target)",
            )
            .bind(cx.project())
            .bind(names)
            .bind(INDEX.0)
            .bind(INDEX.1)
            .fetch_all(pool)
        })?,
    };
    let tips: Vec<(String, ObjectId)> = rows.into_iter().filter_map(|(n, t)| ObjectId::from_hex(&t).ok().map(|t| (n, t))).collect();
    let roots = match scope {
        Scope::Snapshot(s) => vec![s],
        _ => tips.iter().map(|(_, t)| *t).collect(),
    };
    b.derive_from(&roots)?;
    b.flush()?;
    let mut names = Vec::new();
    let mut through = Vec::new();
    for (name, tip) in &tips {
        if b.graph.row(tip)?.is_some() {
            names.push(name.clone());
            through.push(tip.hex());
        }
    }
    if !names.is_empty() {
        cx.db(|| {
            sqlx::query(
                "INSERT INTO derive_progress (project_id, index_name, index_version, branch, through_snapshot) \
                 SELECT $1, $2, $3, * FROM UNNEST($4::text[], $5::text[]) \
                 ON CONFLICT (project_id, index_name, index_version, branch) DO UPDATE SET through_snapshot = EXCLUDED.through_snapshot",
            )
            .bind(cx.project())
            .bind(INDEX.0)
            .bind(INDEX.1)
            .bind(&names)
            .bind(&through)
            .execute(pool)
        })?;
    }
    b.stats.branches = names;
    Ok(b.stats)
}

impl<'a> Batch<'a> {
    fn new(cx: &'a Cx) -> Result<Batch<'a>> {
        Ok(Batch {
            cx,
            graph: Graph::new(cx),
            lines: cx.lines()?,
            history: HashMap::new(),
            writes: Writes::default(),
            stats: Stats::default(),
        })
    }

    /// Make the lists the accepted policy needs complete before deriving
    /// anything under it: a line whose paths changed gets its list built
    /// from every derived snapshot's changed paths (design §3.4, "Policy
    /// changes"). Lists the policy no longer has stop being kept.
    fn prepare_lists(&mut self) -> Result<()> {
        let cx = self.cx;
        let pool = cx.pool();
        let want = self.lines.all();
        let have: Vec<(String, bool)> = cx.db(|| {
            sqlx::query_as("SELECT line_key, ready FROM rule_lines WHERE project_id = $1").bind(cx.project()).fetch_all(pool)
        })?;
        let ready: HashSet<String> = have.iter().filter(|(_, r)| *r).map(|(k, _)| k.clone()).collect();
        let missing: Vec<String> = want.iter().filter(|k| !ready.contains(*k)).cloned().collect();
        let stale: Vec<String> = have.iter().map(|(k, _)| k.clone()).filter(|k| !want.contains(k)).collect();
        if !stale.is_empty() {
            cx.db(|| {
                sqlx::query("DELETE FROM rule_lines WHERE project_id = $1 AND line_key = ANY($2)")
                    .bind(cx.project())
                    .bind(&stale)
                    .execute(pool)
            })?;
        }
        if missing.is_empty() {
            return Ok(());
        }
        cx.db(|| {
            sqlx::query("INSERT INTO rule_lines (project_id, line_key, ready) SELECT $1, k, FALSE FROM UNNEST($2::text[]) AS t(k) ON CONFLICT DO NOTHING")
                .bind(cx.project())
                .bind(&missing)
                .execute(pool)
        })?;
        let missing_set: HashSet<&str> = missing.iter().map(String::as_str).collect();
        let mut after = String::new();
        loop {
            type Row = (String, i64, String, String);
            let page: Vec<Row> = cx.db(|| {
                sqlx::query_as(
                    "SELECT snapshot, generation, parents, changed FROM graph WHERE project_id = $1 AND snapshot > $2 \
                     AND changed IS NOT NULL ORDER BY snapshot LIMIT 1000",
                )
                .bind(cx.project())
                .bind(&after)
                .fetch_all(pool)
            })?;
            let Some(last) = page.last() else { break };
            after = last.0.clone();
            for (snap, generation, parents, changed) in page {
                let keys = match changed.as_str() {
                    NONE | WITHHELD => continue,
                    MANY => {
                        // Not listed: walk the trees again.
                        let id = ObjectId::from_hex(&snap).map_err(bad)?;
                        let parents: Vec<ObjectId> = serde_json::from_str(&parents).map_err(bad)?;
                        let (ch, dirs) = self.tree_changes(id, &parents)?;
                        self.keys_of(&ch, &dirs)
                    }
                    id => {
                        let c = Changed::decode(&cx.src.raw(&ObjectId::from_hex(id).map_err(bad)?)?)?;
                        let ch: Vec<Change> = c
                            .paths
                            .into_iter()
                            .map(|p| Change {
                                path: p.path,
                                old: p.old,
                                new: p.new,
                            })
                            .collect();
                        self.keys_of(&ch, &c.dirs)
                    }
                };
                for k in keys.into_iter().filter(|k| missing_set.contains(k.as_str())) {
                    self.writes.rules.push((k, generation, snap.clone()));
                    self.stats.rebuilt += 1;
                }
            }
            self.flush()?;
        }
        cx.db(|| {
            sqlx::query("UPDATE rule_lines SET ready = TRUE WHERE project_id = $1 AND line_key = ANY($2)")
                .bind(cx.project())
                .bind(&missing)
                .execute(pool)
        })?;
        Ok(())
    }

    /// The lists the sides of `changes`, and the folders `dirs`, belong to.
    fn keys_of(&self, changes: &[Change], dirs: &[String]) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for c in changes {
            for side in [&c.old, &c.new].into_iter().flatten() {
                out.insert(self.lines.key_of(&c.path, side).to_string());
            }
        }
        for d in dirs {
            out.insert(self.lines.dir_key(d).to_string());
        }
        out
    }

    /// What snapshot `id` (with `parents`) changed against its first parent:
    /// the leaves, and the folders that changed with no leaf below them
    /// ([`changes::diff`]).
    fn tree_changes(&self, id: ObjectId, parents: &[ObjectId]) -> Result<(Vec<Change>, Vec<String>)> {
        let src = &self.cx.src;
        let tree = src.snapshot(&id)?.tree;
        let base = match parents.first() {
            Some(p) => src.snapshot(p)?.tree,
            None => veil_core::hub::project::empty_tree_id(),
        };
        changes::diff(src, base, tree)
    }

    /// Derive, parents first, every snapshot `roots` reach that has no
    /// value yet.
    fn derive_from(&mut self, roots: &[ObjectId]) -> Result<()> {
        let mut done: HashSet<ObjectId> = HashSet::new();
        let mut expanded: HashSet<ObjectId> = HashSet::new();
        let mut stack: Vec<(ObjectId, bool)> = roots.iter().map(|r| (*r, false)).collect();
        while let Some((x, ready)) = stack.pop() {
            if done.contains(&x) {
                continue;
            }
            if ready {
                self.derive_one(x)?;
                done.insert(x);
                if self.writes.full() {
                    self.flush()?;
                }
                continue;
            }
            if expanded.contains(&x) {
                continue;
            }
            if self.graph.row(&x)?.is_some() {
                done.insert(x);
                continue;
            }
            let s = self.cx.src.snapshot(&x)?;
            expanded.insert(x);
            stack.push((x, true));
            for p in s.parents.iter().rev() {
                if !done.contains(p) {
                    stack.push((*p, false));
                }
            }
        }
        Ok(())
    }

    /// Compute and queue every value of `x`, whose parents are derived.
    fn derive_one(&mut self, x: ObjectId) -> Result<()> {
        let src = &self.cx.src;
        let s = src.snapshot(&x)?;
        let mut prows = Vec::with_capacity(s.parents.len());
        for p in &s.parents {
            prows.push((*p, self.graph.get(p)?));
        }
        let mut row = GraphRow::compute(&s, &prows);
        let hex = x.hex();
        if row.flags & FLAG_EMBARGO_LINE != 0 {
            row.changed = Some(WITHHELD.into());
        } else {
            let (ch, dirs) = self.tree_changes(x, &s.parents)?;
            for k in self.keys_of(&ch, &dirs) {
                self.writes.rules.push((k, row.generation, hex.clone()));
            }
            // `none` only when the tree is the first parent's (BUG-871): a
            // tree that changed with no leaf changed (an empty folder) is
            // listed under the lines deciding its folders, like any change.
            if ch.is_empty() && dirs.is_empty() {
                row.changed = Some(NONE.into());
            } else {
                // Every changed path has its file history row, `many` or not
                // (BUG-868): only the object is capped.
                for c in &ch {
                    let key = changes::path_key(&c.path);
                    self.writes.history.push((key.clone(), row.depth, hex.clone()));
                    self.history.entry(key).or_default().push((row.depth, x));
                }
                // Folders count against the cap too (BUG-981).
                if ch.len() + dirs.len() > changes::MAX_PATHS {
                    row.changed = Some(MANY.into());
                } else {
                    let (from, capped, similar) = changes::sources(src, &ch)?;
                    let wants: Vec<(String, ObjectId)> =
                        ch.iter().flat_map(|c| s.parents.iter().map(move |p| (c.path.clone(), *p))).collect();
                    let mut prevs = self.last_changes(&wants)?.into_iter();
                    let mut paths = Vec::with_capacity(ch.len());
                    for ((c, from), capped) in ch.into_iter().zip(from).zip(capped) {
                        paths.push(PathChange {
                            prev: prevs.by_ref().take(s.parents.len()).collect(),
                            path: c.path,
                            old: c.old,
                            new: c.new,
                            from,
                            capped,
                        });
                    }
                    let raw = Changed { paths, similar, dirs }.encode();
                    let id = ObjectId::hash(&raw);
                    self.writes.bytes += raw.len();
                    self.writes.objects.push((id, Bytes::from(raw)));
                    row.changed = Some(id.hex());
                }
            }
        }
        let row = Arc::new(row);
        self.graph.pending.insert(x, row.clone());
        self.writes.graph.push((x, row));
        self.stats.snapshots += 1;
        Ok(())
    }

    /// For each `(path, at)`: the snapshot that last changed `path` along
    /// `at`'s first parents (`at` itself included), i.e. the one that
    /// introduced `at`'s version of it. Candidates are the path's
    /// `file_history` rows at or above `at`'s depth, deepest first (every
    /// changed path has one, `many` snapshots included); the first on
    /// `at`'s first-parent line is the answer.
    pub fn last_changes(&mut self, wants: &[(String, ObjectId)]) -> Result<Vec<Option<ObjectId>>> {
        let mut out: Vec<Option<ObjectId>> = vec![None; wants.len()];
        let mut ask: Vec<usize> = Vec::new();
        let mut depth_of = Vec::with_capacity(wants.len());
        for (i, (path, at)) in wants.iter().enumerate() {
            let d = self.graph.get(at)?.depth;
            depth_of.push(d);
            // A row of this batch on `at`'s line is final: anything deeper on
            // that line was derived after it, so is in this batch too.
            let mut mine: Vec<(i64, ObjectId)> = self
                .history
                .get(&changes::path_key(path))
                .into_iter()
                .flatten()
                .filter(|(dd, _)| *dd <= d)
                .copied()
                .collect();
            mine.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
            for (dd, c) in mine {
                if self.graph.at_depth(*at, dd)? == Some(c) {
                    out[i] = Some(c);
                    break;
                }
            }
            if out[i].is_none() {
                ask.push(i);
            }
        }
        if ask.is_empty() {
            return Ok(out);
        }
        // One query per [`ROWS_PER_STATEMENT`] paths: the deepest few rows of
        // each. (One query for all of a snapshot's 100,000 paths ran past
        // the statement timeout on a busy YugabyteDB: BUG-912.)
        const FIRST: usize = 8;
        const NEXT: i64 = 64;
        let keys: Vec<String> = ask.iter().map(|&i| changes::path_key(&wants[i].0)).collect();
        let maxd: Vec<i64> = ask.iter().map(|&i| depth_of[i]).collect();
        let pool = self.cx.pool();
        let project = self.cx.project();
        let mut found: HashMap<usize, Vec<(i64, String)>> = HashMap::new();
        for (part, (keys, maxd)) in keys.chunks(ROWS_PER_STATEMENT).zip(maxd.chunks(ROWS_PER_STATEMENT)).enumerate() {
            let rows: Vec<(i64, i64, String)> = self.cx.db(|| {
                sqlx::query_as(
                    "SELECT k.n, f.depth, f.snapshot FROM UNNEST($2::text[], $3::bigint[]) WITH ORDINALITY AS k(path_key, maxd, n) \
                     CROSS JOIN LATERAL (SELECT depth, snapshot FROM file_history \
                       WHERE project_id = $1 AND path_key = k.path_key AND depth <= k.maxd \
                       ORDER BY depth DESC, snapshot DESC LIMIT 8) f",
                )
                .bind(project)
                .bind(keys)
                .bind(maxd)
                .fetch_all(pool)
            })?;
            for (n, d, s) in rows {
                found.entry(part * ROWS_PER_STATEMENT + n as usize - 1).or_default().push((d, s));
            }
        }
        for (j, &i) in ask.iter().enumerate() {
            let at = wants[i].1;
            let mut page = found.remove(&j).unwrap_or_default();
            let mut full = page.len() >= FIRST;
            out[i] = loop {
                let mut hit = None;
                for (d, c) in &page {
                    let c = ObjectId::from_hex(c).map_err(bad)?;
                    if self.graph.at_depth(at, *d)? == Some(c) {
                        hit = Some((*d, c));
                        break;
                    }
                }
                if hit.is_some() || !full {
                    break hit.map(|(_, c)| c);
                }
                // Every row so far is on another line: the next rows.
                let (ld, ls) = page.last().cloned().unwrap();
                let key = &keys[j];
                page = self.cx.db(|| {
                    sqlx::query_as(
                        "SELECT depth, snapshot FROM file_history WHERE project_id = $1 AND path_key = $2 \
                         AND (depth, snapshot) < ($3, $4) ORDER BY depth DESC, snapshot DESC LIMIT $5",
                    )
                    .bind(project)
                    .bind(key)
                    .bind(ld)
                    .bind(&ls)
                    .bind(NEXT)
                    .fetch_all(pool)
                })?;
                full = page.len() as i64 >= NEXT;
            };
        }
        Ok(out)
    }

    /// Write what is queued: objects, file history and list rows, then the
    /// graph rows that mark the snapshots derived.
    fn flush(&mut self) -> Result<()> {
        let cx = self.cx;
        let w = std::mem::take(&mut self.writes);
        let hub = cx.hub().clone();
        let project = cx.project();
        cx.src.rt.block_on(async {
            let mut set = tokio::task::JoinSet::new();
            let mut it = w.objects.into_iter();
            loop {
                while set.len() < 32 {
                    let Some((id, raw)) = it.next() else { break };
                    let h = hub.clone();
                    set.spawn(async move { h.objects.put(project, &id, raw).await });
                }
                match set.join_next().await {
                    Some(r) => r.map_err(|e| Error::Other(e.into()))?.map_err(Error::Other)?,
                    None => break,
                }
            }
            Ok::<(), Error>(())
        })?;
        let pool = cx.pool();
        for (sql, rows) in [
            (
                "INSERT INTO file_history (project_id, path_key, depth, snapshot) SELECT $1, * FROM UNNEST($2::text[], $3::bigint[], $4::text[]) \
                 ON CONFLICT DO NOTHING",
                &w.history,
            ),
            (
                "INSERT INTO rule_history (project_id, line_key, generation, snapshot) SELECT $1, * FROM UNNEST($2::text[], $3::bigint[], $4::text[]) \
                 ON CONFLICT DO NOTHING",
                &w.rules,
            ),
        ] {
            for chunk in rows.chunks(ROWS_PER_STATEMENT) {
                let a: Vec<&str> = chunk.iter().map(|r| r.0.as_str()).collect();
                let b: Vec<i64> = chunk.iter().map(|r| r.1).collect();
                let c: Vec<&str> = chunk.iter().map(|r| r.2.as_str()).collect();
                cx.db(|| sqlx::query(sql).bind(project).bind(&a).bind(&b).bind(&c).execute(pool))?;
            }
        }
        for chunk in w.graph.chunks(ROWS_PER_STATEMENT) {
            let ids: Vec<String> = chunk.iter().map(|(id, _)| id.hex()).collect();
            let gens: Vec<i64> = chunk.iter().map(|(_, r)| r.generation).collect();
            let depths: Vec<i64> = chunk.iter().map(|(_, r)| r.depth).collect();
            let parents: Vec<String> = chunk.iter().map(|(_, r)| serde_json::to_string(&r.parents).unwrap()).collect();
            let change_ids: Vec<&str> = chunk.iter().map(|(_, r)| r.change_id.as_str()).collect();
            let flags: Vec<i32> = chunk.iter().map(|(_, r)| r.flags).collect();
            let skips: Vec<String> = chunk.iter().map(|(_, r)| serde_json::to_string(&r.skip).unwrap()).collect();
            let changed: Vec<Option<&str>> = chunk.iter().map(|(_, r)| r.changed.as_deref()).collect();
            cx.db(|| {
                sqlx::query(
                    "INSERT INTO graph (project_id, snapshot, generation, depth, parents, change_id, flags, skip, changed) \
                     SELECT $1, * FROM UNNEST($2::text[], $3::bigint[], $4::bigint[], $5::text[], $6::text[], $7::int[], $8::text[], $9::text[]) \
                     ON CONFLICT DO NOTHING",
                )
                .bind(project)
                .bind(&ids)
                .bind(&gens)
                .bind(&depths)
                .bind(&parents)
                .bind(&change_ids)
                .bind(&flags)
                .bind(&skips)
                .bind(&changed)
                .execute(pool)
            })?;
            for (id, r) in chunk {
                cx.hub().derive.rows.insert(row_key(project, id), r.clone(), 256);
            }
        }
        // Written rows are read from the cache or the database from now on.
        self.graph.pending.clear();
        self.history.clear();
        Ok(())
    }
}

/// Project the tips of `branches` of `project` for each view key of its
/// people and of anyone on Earth, so that their next pull finds the
/// projection memoised (phase 4 §4.5), and extend each view key's graph
/// (admins' included) for the query API (S13): both by the view key's fill,
/// queued here and run in the background (`query::graph::prefill`). Only
/// the branches named (a landing's) are touched (BUG-870).
pub async fn memo_tips(hub: &Arc<Hub>, project_id: i64, branches: &[String]) -> Result<()> {
    let Some((project, viewers)) = viewers_of(hub, project_id).await? else { return Ok(()) };
    let branches: Vec<String> =
        sqlx::query_scalar("SELECT target FROM branches WHERE project_id = $1 AND name = ANY($2) AND hidden_for_embargo IS NULL")
            .bind(project_id)
            .bind(branches)
            .fetch_all(&hub.db)
            .await?;
    let tips: Vec<ObjectId> = branches.iter().map(|t| ObjectId::from_hex(t).map_err(bad)).collect::<Result<_>>()?;
    let mut keys = HashSet::new();
    let mut failed = Ok(());
    for v in viewers {
        let view = project.view(&v);
        if !view.sees_anything() || !keys.insert(view.key()) {
            continue;
        }
        // Queue the fill that memoises the projections and extends the
        // viewer's graph (`query::graph::prefill`: the one fill of this
        // view key, which a query that needs it joins). Never waited for
        // here: the deriver holds nothing while fills run (BUG-911).
        if let Err(e) = crate::query::graph::prefill(hub, &project, &v, &tips).await {
            if failed.is_ok() {
                failed = Err(e);
            }
        }
    }
    // What view keys no viewer has now keep is dropped (BUG-1413).
    if let Err(e) = crate::query::files::sweep_keys(hub, project_id).await {
        if failed.is_ok() {
            failed = Err(e);
        }
    }
    failed
}

/// The project `project_id` and its viewers: anyone on Earth, each person
/// in one of its groups or named by a rule (not an admin), and the admins.
async fn viewers_of(hub: &Hub, project_id: i64) -> Result<Option<(crate::perm::Project, Vec<crate::perm::Viewer>)>> {
    let mut c = hub.db.acquire().await?;
    let name: Option<String> = sqlx::query_scalar("SELECT name FROM projects WHERE id = $1").bind(project_id).fetch_optional(&mut *c).await?;
    let Some(name) = name else { return Ok(None) };
    let Some(project) = crate::perm::load_project(&mut c, &name).await? else { return Ok(None) };
    let admins: HashSet<i64> = sqlx::query_scalar("SELECT person_id FROM project_admins WHERE project_id = $1")
        .bind(project_id)
        .fetch_all(&mut *c)
        .await?
        .into_iter()
        .collect();
    let members: Vec<(i64, i64)> =
        sqlx::query_as("SELECT m.person_id, g.id FROM group_members m JOIN groups g ON g.id = m.group_id WHERE g.project_id = $1")
            .bind(project_id)
            .fetch_all(&mut *c)
            .await?;
    drop(c);
    let mut people: HashMap<i64, HashSet<i64>> = HashMap::new();
    for (p, g) in members {
        people.entry(p).or_default().insert(g);
    }
    for b in project.bindings.values() {
        if let crate::perm::Binding::Person(p) = b {
            people.entry(*p).or_default();
        }
    }
    let mut viewers = vec![crate::perm::Viewer::default()];
    for (person, groups) in people {
        if !admins.contains(&person) {
            viewers.push(crate::perm::Viewer {
                person: Some(person),
                admin: false,
                groups,
                only: None,
                agent: false,
            });
        }
    }
    // The admins' graph of the query API too (S13): it holds real history.
    viewers.push(crate::perm::Viewer {
        admin: true,
        ..Default::default()
    });
    Ok(Some((project, viewers)))
}

/// The view keys of `project_id`'s viewers now (those who see anything):
/// the keys whose per-key rows the query API keeps (BUG-1413).
pub async fn view_keys(hub: &Hub, project_id: i64) -> Result<HashSet<String>> {
    let Some((project, viewers)) = viewers_of(hub, project_id).await? else { return Ok(HashSet::new()) };
    Ok(viewers
        .iter()
        .map(|v| project.view(v))
        .filter(|v| v.sees_anything())
        .map(|v| v.key())
        .collect())
}
