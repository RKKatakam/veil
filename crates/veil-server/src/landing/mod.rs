//! The landing service (milestone S17; `docs/HUB.md` §13.19;
//! `docs/design/server/phase-4-agent-scale.md` §4.1–4.6).
//!
//! **Submitting** (`POST …/land`, and `vl push` to a protected branch): the
//! change is built and checked exactly as a push or an API commit is (the
//! same code: `sync::complete` and check 9, through `sync::push` or
//! `changes::create`), its snapshots become committed history, and one row
//! joins the queue, all in the request's one database commit. The answer is
//! a ticket.
//!
//! **Landing** (`service`): one landing service per branch, on whichever
//! server holds the branch's lease, takes every ready entry (in order, at
//! most [`MAX_BATCH`]) and lands those whose edited paths still hold, on
//! the tip, what their base had ([`edits::fast_path`]): each change becomes
//! its own snapshot on top of the one before, and the branch moves **once**
//! per batch, in one transaction. A change that overlaps is answered
//! `conflict`, never landed over (content merges are S18).
//!
//! **Protected branches** ([`rules`]): only the landing service moves them;
//! a push to one lands its new changes instead.

pub mod edits;
pub mod merge;
pub mod rules;
mod service;
pub use service::ATTACH_BUDGET;

use std::{
    collections::HashMap,
    sync::{atomic::AtomicU64, Arc, Mutex},
    time::{Duration, Instant},
};

use sqlx::PgConnection;
use tokio::sync::{oneshot, Notify};
use veil_core::{
    hub::land::{LandResult, LandState},
    ObjectId,
};

use crate::{
    auth::Person,
    error::{Error, Result},
    sync::Source,
    Hub,
};

/// Most entries one batch takes. The design says up to 500; measured, a
/// batch's object writes cost more per landing the more there are at once
/// (about 0.9 ms a landing in batches of 10–25, 1.5 ms in batches of
/// 150–300: synced writes contend), so a service that once fell behind
/// stayed behind with large batches, at a p50 of seconds. At 64 it drains a
/// backlog in small batches (`docs/design/scale/LOAD.md`, "The landing
/// service"); the branch still moves once for up to 64 changes.
pub const MAX_BATCH: usize = 64;
/// How long a submit waits for its outcome before answering `queued`.
pub const WAIT: Duration = Duration::from_secs(30);
/// How long a lease lasts unless renewed, in milliseconds: another server
/// takes the branch over this long after its holder stops.
pub const LEASE_MS: i64 = 2_000;

/// Who submitted, and the access epochs the submit's checks ran under.
#[derive(Clone, Debug)]
pub struct Submitter {
    pub person: Person,
    pub epochs: crate::caches::Epochs,
}

/// One change of a stack ([`stack`]): its real snapshot, and its base (the
/// change below it that lands, or the snapshot on the branch where the
/// stack starts). Its edits are its diff against its first parent (a merge
/// based on another parent: that one).
#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    pub id: ObjectId,
    pub base: ObjectId,
}

impl Entry {
    pub fn plain(id: ObjectId, base: ObjectId) -> Entry {
        Entry { id, base }
    }
}

/// A stack as its queue row holds it: `[snapshot, base]` pairs.
pub fn encode_stack(stack: &[Entry]) -> String {
    let rows: Vec<[String; 2]> = stack.iter().map(|e| [e.id.hex(), e.base.hex()]).collect();
    serde_json::to_string(&rows).unwrap_or_default()
}

/// [`encode_stack`]'s inverse.
pub fn decode_stack(text: &str) -> Result<Vec<Entry>> {
    let rows: Vec<[String; 2]> = serde_json::from_str(text).map_err(|e| Error::Other(e.into()))?;
    let hex = |s: &str| ObjectId::from_hex(s).map_err(|e| Error::Other(e.into()));
    rows.iter().map(|[s, b]| Ok(Entry::plain(hex(s)?, hex(b)?))).collect()
}

/// One queue row to insert in the submit's transaction.
#[derive(Clone, Debug)]
pub struct Queued {
    pub ticket: String,
    pub branch: String,
    /// The stack, oldest first ([`stack`]).
    pub stack: Vec<Entry>,
    /// The branch's lineage the stack was judged under: it lands only under
    /// that one (BUG-1300).
    pub lineage: i64,
    /// Changes of the line left out as landed already with the same edits
    /// (`Judged::skipped`; not stored): the submit's answer names them.
    pub skipped: Arc<Mutex<Vec<ObjectId>>>,
}

/// What an answer says of the changes a stack left out as landed already
/// with the same edits: never silent.
pub async fn skipped_warnings(hub: &Arc<Hub>, project: i64, branch: &str, skipped: &[ObjectId]) -> Result<Vec<String>> {
    if skipped.is_empty() {
        return Ok(Vec::new());
    }
    let ids = skipped.to_vec();
    let cids = crate::sync::blocking(hub, project, move |src| ids.iter().map(|x| Ok(src.snapshot(x)?.change_id.to_string())).collect::<Result<Vec<_>>>()).await?;
    Ok(cids.into_iter().map(|c| format!("change {c} already landed on '{branch}' with the same edits: not landed again")).collect())
}

/// A new random ticket.
pub fn ticket() -> String {
    format!("land-{}", hex::encode(veil_core::crypto::random_bytes::<16>()))
}

/// Insert `q` for `who` into the queue of `project`, in the caller's
/// transaction.
pub async fn insert(c: &mut PgConnection, project: i64, who: &Submitter, q: &Queued) -> Result<()> {
    sqlx::query(
        "INSERT INTO landing_queue (project_id, branch, ticket, person_id, person_name, device_key, stack, lineage, person_epoch, \
         project_epoch, agent_session, state, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'queued', \
         (extract(epoch FROM clock_timestamp()) * 1000000)::BIGINT)",
    )
    .bind(project)
    .bind(&q.branch)
    .bind(&q.ticket)
    .bind(who.person.id)
    .bind(&who.person.name)
    .bind(&who.person.device_key)
    .bind(encode_stack(&q.stack))
    .bind(q.lineage)
    .bind(who.epochs.person)
    .bind(who.epochs.project.map_or(0, |(_, e)| e))
    .bind(who.person.agent.as_ref().map(|a| a.session_hash.as_str()))
    .execute(&mut *c)
    .await?;
    Ok(())
}

/// Record, in the caller's transaction, that the changes `changes` (their
/// ids, by `authors`: the person whose signature is on each) landed on
/// `branch` in its lineage `lineage` as the snapshots `landed` (BUG-1522,
/// BUG-1527, BUG-1547, BUG-1548, BUG-1579, BUG-1580: "already landed" asks
/// by change id and author, whatever route moved the branch: the landing
/// service, a push, an API commit `onto`). The first landing of a change by
/// an author on a lineage is kept.
pub async fn record_changes(
    c: &mut PgConnection,
    project: i64,
    branch: &str,
    lineage: i64,
    changes: &[String],
    authors: &[i64],
    landed: &[String],
) -> Result<()> {
    sqlx::query(
        "INSERT INTO landed_changes (project_id, branch, lineage, change_id, author, landed) \
         SELECT $1, $2, $3, c, a, l FROM unnest($4::TEXT[], $5::BIGINT[], $6::TEXT[]) AS v(c, a, l) ON CONFLICT DO NOTHING",
    )
    .bind(project)
    .bind(branch)
    .bind(lineage)
    .bind(changes)
    .bind(authors)
    .bind(landed)
    .execute(&mut *c)
    .await?;
    Ok(())
}

/// The person (`people.id`) whose change `x` is: recorded in `snapshots`
/// by `x`'s own id whenever the server commits a snapshot (a push, an API
/// commit, the landing service, BUG-1581; `fresh` before the commit), or
/// from `x`'s own device signature (or its `origins` row's). Answered in
/// one lookup with no bound, and never by change id alone.
pub(crate) async fn snapshot_author(
    hub: &Arc<Hub>,
    project: i64,
    x: ObjectId,
    fresh: &HashMap<ObjectId, (Vec<ObjectId>, i64)>,
) -> Result<Option<i64>> {
    if let Some((_, a)) = fresh.get(&x) {
        return Ok(Some(*a));
    }
    let a: Option<i64> = sqlx::query_scalar("SELECT author FROM snapshots WHERE project_id = $1 AND id = $2 AND author <> 0")
        .bind(project)
        .bind(x.hex())
        .fetch_optional(&hub.db)
        .await?;
    if a.is_some() {
        return Ok(a);
    }
    let server_key = hub.identity.verifying_hex();
    let key = crate::sync::blocking(hub, project, move |src| Ok(src.snapshot(&x)?.signature.as_ref().map(|g| g.key.clone()))).await?;
    let Some(k) = key else { return Ok(None) };
    if k != server_key {
        let p: Option<i64> = sqlx::query_scalar("SELECT person_id FROM devices WHERE signing_key = $1")
            .bind(&k)
            .fetch_optional(&hub.db)
            .await?;
        return Ok(p);
    }
    let orig: Option<String> = sqlx::query_scalar("SELECT origin_id FROM origins WHERE project_id = $1 AND real_id = $2")
        .bind(project)
        .bind(x.hex())
        .fetch_optional(&hub.db)
        .await?;
    if let Some(orig) = orig.and_then(|o| ObjectId::from_hex(&o).ok()) {
        let okey = crate::sync::blocking(hub, project, move |src| Ok(src.snapshot(&orig)?.signature.as_ref().map(|g| g.key.clone()))).await?;
        if let Some(ok) = okey {
            let p: Option<i64> = sqlx::query_scalar("SELECT person_id FROM devices WHERE signing_key = $1")
                .bind(&ok)
                .fetch_optional(&hub.db)
                .await?;
            return Ok(p);
        }
    }
    Ok(None)
}


/// The protected branches of a project: the rules of its default branch's
/// tip `default_tip` (real), if it has one. A `.veilrules` that does not
/// parse protects nothing (only admins write it, and their push refuses one
/// that does not parse; an older project's may predate the rules).
pub fn protected(src: &Source, default_tip: Option<ObjectId>) -> Result<std::collections::BTreeSet<String>> {
    let Some(tip) = default_tip else { return Ok(Default::default()) };
    let tree = src.snapshot(&tip)?.tree;
    Ok(match crate::sync::entry_at(src, &tree, rules::RULES_FILE)? {
        Some(e) if e.kind == veil_core::object::EntryKind::File => match veil_core::object::Object::decode(&src.raw(&e.id)?)? {
            veil_core::object::Object::Blob(b) => rules::Rules::parse(&String::from_utf8_lossy(&b)).map(|r| r.protected).unwrap_or_default(),
            _ => Default::default(),
        },
        _ => Default::default(),
    })
}

/// Counters for the benchmarks (`DATA/stats.json`).
#[derive(Default)]
pub struct Stats {
    pub batches: AtomicU64,
    pub landed: AtomicU64,
    pub conflicts: AtomicU64,
    pub rejected: AtomicU64,
    /// Microseconds spent building batches (the landing service's CPU on
    /// the request path), storing their objects, and committing them (the
    /// transaction).
    pub build_us: AtomicU64,
    /// Microseconds spent reading what a batch needs before it is built
    /// (who lands as whom, memos, view keys to attach).
    pub prepare_us: AtomicU64,
    pub store_us: AtomicU64,
    pub commit_us: AtomicU64,
    /// Batches refused at commit because the lease had moved (fencing).
    pub lease_lost: AtomicU64,
    /// Projections the services made (each new snapshot, for each view key
    /// kept, and the recent line for a key attached).
    pub projected: AtomicU64,
    /// View keys attached from the recent line, handed to the background
    /// fill, and dropped (a projection they needed was not stored); batches
    /// rolled back for a memo stored meanwhile; the keys the last batch kept.
    pub attached: AtomicU64,
    pub prefilled: AtomicU64,
    pub dropped: AtomicU64,
    pub memo_races: AtomicU64,
    pub kept: AtomicU64,
    /// Entries whose submit's checks ran again (access changed meanwhile).
    pub rechecked: AtomicU64,
    /// Statements the branches' pollers made (`poll`).
    pub polls: AtomicU64,
    /// Submits whose stack asked the derived graph, or walked, whether a
    /// change is on the branch: neither its tip nor a landing (BUG-1275).
    pub walks: AtomicU64,
}

/// A waiting ticket's answer channel, and the branch it waits on.
type Waiting = (oneshot::Sender<LandResult>, Option<(i64, String)>);

struct Running {
    wake: Arc<Notify>,
}

/// The landing services this server runs, and the submitters waiting here.
pub struct Services {
    /// This server's name as a lease holder (random per start).
    holder: String,
    running: Mutex<HashMap<(i64, String), Running>>,
    /// When a service here last failed to take a branch's lease (another
    /// server holds it): not tried again sooner than [`RETRY_LEASE`].
    held_elsewhere: Mutex<HashMap<(i64, String), Instant>>,
    /// Each waiting ticket: where its answer goes, and (once its request
    /// waits) the branch it lands on, for that branch's poller.
    waiters: Mutex<HashMap<String, Waiting>>,
    /// How many tickets each person currently has actively waiting in [`wait`].
    waiting_by_person: Mutex<HashMap<i64, usize>>,
    /// The branches whose waiters here a poller answers (`poll`).
    pollers: Mutex<std::collections::HashSet<(i64, String)>>,
    /// Content merge workers running on this server (S18).
    pub merges: merge::Workers,
    pub stats: Stats,
}

const RETRY_LEASE: Duration = Duration::from_millis(500);

impl Default for Services {
    fn default() -> Self {
        Services {
            holder: format!("{}-{}", std::process::id(), hex::encode(veil_core::crypto::random_bytes::<8>())),
            running: Mutex::new(HashMap::new()),
            held_elsewhere: Mutex::new(HashMap::new()),
            waiters: Mutex::new(HashMap::new()),
            waiting_by_person: Mutex::new(HashMap::new()),
            pollers: Mutex::new(Default::default()),
            merges: merge::Workers::default(),
            stats: Stats::default(),
        }
    }
}

/// Most landings waiting for their outcome on one server at once (they hold
/// no bulkhead place while they wait, BUG-1635); the rest answer at once.
pub const MAX_WAITING: usize = 10_000;
/// Most landings one person may have waiting for their outcome on one server
/// at once (S24).
pub const MAX_WAITING_PER_PERSON: usize = 128;

/// A submitter's wait for its ticket, registered before the submit commits
/// so that the outcome is never missed.
pub struct Waiter {
    ticket: String,
    rx: oneshot::Receiver<LandResult>,
}

impl Services {
    /// Wait here for `ticket`'s outcome.
    pub fn register(&self, ticket: &str) -> Waiter {
        let (tx, rx) = oneshot::channel();
        self.waiters.lock().unwrap().insert(ticket.to_string(), (tx, None));
        Waiter { ticket: ticket.to_string(), rx }
    }

    fn forget(&self, ticket: &str) {
        self.waiters.lock().unwrap().remove(ticket);
    }

    /// Give each waiter here its outcome.
    fn resolve(&self, outcomes: impl IntoIterator<Item = (String, LandResult)>) {
        let mut w = self.waiters.lock().unwrap();
        for (t, r) in outcomes {
            if let Some((tx, _)) = w.remove(&t) {
                let _ = tx.send(r);
            }
        }
    }
}

/// Make sure a landing service runs for `branch` of `project` (here, if no
/// other server holds its lease), and wake it.
pub fn ensure(hub: &Arc<Hub>, project: i64, branch: &str) {
    let key = (project, branch.to_string());
    let s = &hub.landing;
    {
        let running = s.running.lock().unwrap();
        if let Some(r) = running.get(&key) {
            r.wake.notify_one();
            return;
        }
    }
    if s.held_elsewhere.lock().unwrap().get(&key).is_some_and(|t| t.elapsed() < RETRY_LEASE) {
        return;
    }
    let wake = Arc::new(Notify::new());
    {
        let mut running = s.running.lock().unwrap();
        if running.contains_key(&key) {
            return;
        }
        running.insert(key.clone(), Running { wake: wake.clone() });
    }
    let hub = hub.clone();
    tokio::spawn(async move {
        let held_elsewhere = match service::run(&hub, project, &key.1, wake).await {
            Ok(h) => h,
            Err(e) => {
                eprintln!("veil-server: the landing service of project {project} stopped: {e:?}");
                // Not straight back into the same failure.
                tokio::time::sleep(Duration::from_millis(200)).await;
                false
            }
        };
        if held_elsewhere {
            hub.landing.held_elsewhere.lock().unwrap().insert(key.clone(), Instant::now());
        }
        hub.landing.running.lock().unwrap().remove(&key);
        // An entry submitted while it was stopping is not left waiting.
        if !held_elsewhere && service::has_ready(&hub, project, &key.1).await.unwrap_or(false) {
            ensure(&hub, project, &key.1);
        }
    });
}

/// Start the services of every branch with queued entries (a server
/// starting after another stopped).
pub async fn resume(hub: Arc<Hub>) {
    let _ = sqlx::query("UPDATE landing_queue SET state = 'queued' WHERE state = 'merging'")
        .execute(&hub.db)
        .await;
    let rows: std::result::Result<Vec<(i64, String)>, _> =
        sqlx::query_as("SELECT DISTINCT project_id, branch FROM landing_queue WHERE state = 'queued'").fetch_all(&hub.db).await;
    match rows {
        Ok(rows) => {
            for (p, b) in rows {
                ensure(&hub, p, &b);
            }
        }
        Err(e) => eprintln!("veil-server: finding queued landings: {e:?}"),
    }
}

/// `r` as `viewer` sees it: the snapshots it landed, projected, and any
/// conflict report filtered and projected for `viewer` (S18). (Outcomes
/// hold real snapshots; each answer is projected for its asker, from the
/// memo the landing stored where it kept their view key, else as a pull
/// would, in the asker's own request.)
pub async fn seen(hub: &Arc<Hub>, project: &crate::perm::Project, viewer: &crate::perm::Viewer, mut r: LandResult) -> Result<LandResult> {
    let mut out = Vec::with_capacity(r.landed.len());
    for x in &r.landed {
        out.push(crate::sync::projected(hub, project, viewer, *x).await?);
    }
    r.landed = out;
    if let Some(onto) = r.onto {
        r.onto = Some(crate::sync::projected(hub, project, viewer, onto).await?);
    }
    if let Some(base) = r.base {
        r.base = Some(crate::sync::projected(hub, project, viewer, base).await?);
    }
    let view = project.view(viewer);
    let can_see = |p: &str| view.read(p) && view.within_narrowing(p);
    if (!viewer.admin || view.is_narrowed())
        && (r.paths.iter().any(|p| !can_see(p)) || r.conflicts.iter().any(|c| !can_see(&c.path)))
    {
        r.paths.clear();
        r.conflicts.clear();
        r.landed_since.clear();
        r.message = Some(merge::HIDDEN_CONFLICT.to_string());
    }
    if view.is_narrowed() && r.state == LandState::Rejected {
        if let Some(msg) = &r.message {
            let mut rest = msg.as_str();
            let mut outside = false;
            while let Some(i) = rest.find('\'') {
                rest = &rest[i + 1..];
                let Some(j) = rest.find('\'') else { break };
                let quoted = &rest[..j];
                rest = &rest[j + 1..];
                if (quoted.contains('/') || quoted.starts_with('.')) && !view.within_narrowing(quoted) {
                    outside = true;
                    break;
                }
            }
            if outside {
                r.message = Some(crate::sync::NARROWED_MOVE.to_string());
            }
        }
    }
    if !r.landed_since.is_empty() {
        let mut since = Vec::with_capacity(r.landed_since.len());
        for x in &r.landed_since {
            let px = crate::sync::projected(hub, project, viewer, *x).await?;
            if !viewer.admin || view.is_narrowed() {
                let y = *x;
                let (p0, touches_visible) = crate::sync::blocking(hub, project.id, {
                    let (policy_text, bindings, v) = (project.policy_text.clone(), project.bindings.clone(), viewer.clone());
                    move |src| {
                        let s = src.snapshot(&y)?;
                        let Some(p0) = s.parents.first().copied() else { return Ok((None, false)) };
                        let ps = src.snapshot(&p0)?;
                        let p = crate::perm::Project {
                            id: src.project,
                            name: String::new(),
                            default_branch: String::new(),
                            policy: veil_core::hub::access::AccessPolicy::parse(&policy_text),
                            policy_text,
                            bindings,
                        };
                        let view = p.view(&v);
                        let step = edits::edit_set(src, s.tree, ps.tree)?;
                        let vis = step.iter().any(|c| view.read(&c.path) && view.within_narrowing(&c.path));
                        Ok((Some(p0), vis))
                    }
                })
                .await?;
                if !touches_visible {
                    continue;
                }
                if let Some(p0) = p0 {
                    let pp0 = crate::sync::projected(hub, project, viewer, p0).await?;
                    if px == pp0 {
                        continue;
                    }
                }
            }
            if !since.contains(&px) {
                since.push(px);
            }
        }
        r.landed_since = since;
    }
    Ok(r)
}

/// The outcome of `ticket` as stored (real snapshots: [`seen`]), if it is
/// `person`'s.
pub async fn read(hub: &Hub, project: i64, person: i64, ticket: &str) -> Result<Option<(String, LandResult)>> {
    let row: Option<(String, String, Option<String>, i64)> =
        sqlx::query_as("SELECT branch, state, result, merges FROM landing_queue WHERE ticket = $1 AND project_id = $2 AND person_id = $3")
            .bind(ticket)
            .bind(project)
            .bind(person)
            .fetch_optional(&hub.db)
            .await?;
    let Some((branch, state, result, merges)) = row else { return Ok(None) };
    let r = match (state.as_str(), result) {
        ("queued" | "merging", _) | (_, None) => {
            let mut q = queued(ticket);
            q.merges = merges as u32;
            q
        }
        (_, Some(r)) => serde_json::from_str(&r).map_err(|e| Error::Other(e.into()))?,
    };
    Ok(Some((branch, r)))
}

/// A ticket's answer while it waits.
pub fn queued(ticket: &str) -> LandResult {
    LandResult {
        ticket: ticket.to_string(),
        state: LandState::Queued,
        change_id: None,
        landed: Vec::new(),
        message: None,
        paths: Vec::new(),
        onto: None,
        base: None,
        conflicts: Vec::new(),
        landed_since: Vec::new(),
        merges: 0,
        warnings: Vec::new(),
    }
}

/// Wait for `w`'s outcome until `deadline`: from the service here as soon as
/// it commits; else from the branch's poller here, which reads the rows of
/// the branch finished since it last looked, in one statement (every
/// 250 ms while another server runs the branch's service, every 5 s as a
/// fallback while this one does): its cost follows the landings, never the
/// number of waiters (BUG-1108). Gives the request's bulkhead places back
/// before waiting (BUG-1635), so the waiters here are bounded by
/// [`MAX_WAITING`] instead: past it, the answer is the row as it is now
/// (`queued` and its ticket, for `vl land --status`), without a wait.
pub async fn wait(hub: &Arc<Hub>, project: i64, person: i64, branch: &str, mut w: Waiter, deadline: tokio::time::Instant) -> Result<LandResult> {
    let over_person = {
        let mut by_p = hub.landing.waiting_by_person.lock().unwrap();
        let n = by_p.entry(person).or_insert(0);
        if *n >= MAX_WAITING_PER_PERSON {
            true
        } else {
            *n += 1;
            false
        }
    };
    struct PersonWaitGuard<'a> {
        s: &'a Services,
        person: i64,
        active: bool,
    }
    impl Drop for PersonWaitGuard<'_> {
        fn drop(&mut self) {
            if self.active {
                let mut by_p = self.s.waiting_by_person.lock().unwrap();
                if let Some(n) = by_p.get_mut(&self.person) {
                    *n = n.saturating_sub(1);
                    if *n == 0 {
                        by_p.remove(&self.person);
                    }
                }
            }
        }
    }
    let _person_guard = PersonWaitGuard {
        s: &hub.landing,
        person,
        active: !over_person,
    };
    if over_person || hub.landing.waiters.lock().unwrap().len() > MAX_WAITING {
        let out = match read(hub, project, person, &w.ticket).await? {
            Some((_, r)) => r,
            None => queued(&w.ticket),
        };
        hub.landing.forget(&w.ticket);
        return Ok(out);
    }
    crate::limits::leave_gates();
    if let Some(e) = hub.landing.waiters.lock().unwrap().get_mut(&w.ticket) {
        e.1 = Some((project, branch.to_string()));
    }
    if let Some((_, r)) = read(hub, project, person, &w.ticket).await? {
        if r.state != LandState::Queued {
            hub.landing.forget(&w.ticket);
            return Ok(r);
        }
    }
    poll(hub, project, branch);
    let out = match tokio::time::timeout_at(deadline, &mut w.rx).await {
        Ok(Ok(r)) => r,
        // The deadline: the row as it is now.
        _ => match read(hub, project, person, &w.ticket).await? {
            Some((_, r)) => r,
            None => queued(&w.ticket),
        },
    };
    hub.landing.forget(&w.ticket);
    Ok(out)
}

/// Make sure a poller answers this server's waiters of `branch` (see
/// [`wait`]); it stops once none waits, and keeps a service running.
fn poll(hub: &Arc<Hub>, project: i64, branch: &str) {
    let key = (project, branch.to_string());
    if !hub.landing.pollers.lock().unwrap().insert(key.clone()) {
        return;
    }
    let hub = hub.clone();
    tokio::spawn(async move {
        // Rows finished since (servers' clocks differ: a margin, and what
        // is read twice is answered once).
        let mut since = veil_core::now_millis() - 60_000;
        let mut read_at = Instant::now();
        loop {
            tokio::time::sleep(Duration::from_millis(250)).await;
            // A service here answers its waiters itself: the row is read
            // only as a fallback, every 5 s.
            let local = hub.landing.running.lock().unwrap().contains_key(&key);
            if local && read_at.elapsed() < Duration::from_secs(5) {
                continue;
            }
            read_at = Instant::now();
            let waiting: std::collections::HashSet<String> = {
                let w = hub.landing.waiters.lock().unwrap();
                let waiting: std::collections::HashSet<String> =
                    w.iter().filter(|(_, (_, at))| at.as_ref() == Some(&key)).map(|(t, _)| t.clone()).collect();
                if waiting.is_empty() {
                    // Under the waiters' lock: a waiter registering now finds
                    // no poller and starts one.
                    hub.landing.pollers.lock().unwrap().remove(&key);
                    return;
                }
                waiting
            };
            let now = veil_core::now_millis();
            hub.landing.stats.polls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let rows: std::result::Result<Vec<(String, String)>, _> = sqlx::query_as(
                "SELECT ticket, result FROM landing_queue WHERE project_id = $1 AND branch = $2 AND done_at >= $3 AND result IS NOT NULL",
            )
            .bind(key.0)
            .bind(&key.1)
            .bind(since - 5_000)
            .fetch_all(&hub.db)
            .await;
            match rows {
                Ok(rows) => {
                    since = now;
                    // Only the tickets waiting here.
                    let mine = rows.into_iter().filter(|(t, _)| waiting.contains(t));
                    hub.landing.resolve(mine.filter_map(|(t, r)| Some((t, serde_json::from_str(&r).ok()?))))
                }
                Err(e) => eprintln!("veil-server: reading landing outcomes: {e:?}"),
            }
            if !local {
                ensure(&hub, key.0, &key.1);
            }
        }
    });
}

/// Unregister a waiter whose submit failed.
pub fn abandon(hub: &Hub, w: Waiter) {
    hub.landing.forget(&w.ticket);
}

/// `POST …/land`: build and check the change as a push (an uploaded
/// `snapshot`) or an API commit (`edits` on `base`) is, queue it in the
/// same commit, and answer with its ticket: at once with `wait: false`,
/// else once it is decided (up to [`WAIT`]).
pub async fn submit(
    hub: &Arc<Hub>,
    project: &crate::perm::Project,
    viewer: &crate::perm::Viewer,
    caller: &crate::auth::Caller,
    who: Submitter,
    req: veil_core::hub::land::LandRequest,
) -> Result<LandResult> {
    use veil_core::hub::{
        changes::ChangeRequest,
        wire::{BranchUpdate, PushRequest},
    };
    veil_core::commands::validate_tag_name(&req.onto).map_err(|_| Error::bad_request(format!("invalid branch name {:?}", req.onto)))?;
    if !project.participant(viewer) {
        return Err(Error::forbidden("you are not in this project"));
    }
    match (req.snapshot, req.base) {
        (Some(snapshot), None) if req.edits.is_empty() && req.change_id.is_none() && req.description.is_empty() => {
            let push = PushRequest {
                updates: vec![BranchUpdate {
                    branch: req.onto.clone(),
                    expected: None,
                    new: Some(snapshot),
                }],
                force: false,
                receipts: req.receipts,
            };
            let (pushed, mut landings) = crate::sync::push_with(hub, project, viewer, &who, push, true, req.wait).await?;
            match landings.pop() {
                // Projected for the pusher by `push_with`.
                Some(l) => Ok(l),
                // Refused before it was queued (nothing new, no branch, …).
                None => Err(Error::bad_request(
                    pushed.results.into_iter().find_map(|r| r.message).unwrap_or_else(|| "nothing to land".into()),
                )),
            }
        }
        (None, Some(base)) => {
            let q = Queued {
                ticket: ticket(),
                branch: req.onto.clone(),
                stack: Vec::new(),
                lineage: 0,
                skipped: Default::default(),
            };
            let w = hub.landing.register(&q.ticket);
            let change = ChangeRequest {
                base,
                change_id: req.change_id,
                description: req.description,
                edits: req.edits,
                onto: None,
                receipts: req.receipts,
            };
            let made = match crate::changes::create_with(hub, project, viewer, caller, change, Some((who.clone(), q.clone()))).await {
                Ok(m) => m,
                Err(e) => {
                    abandon(hub, w);
                    return Err(e);
                }
            };
            ensure(hub, project.id, &q.branch);
            let mut r = match req.wait {
                true => wait(hub, project.id, who.person.id, &q.branch, w, tokio::time::Instant::now() + WAIT).await?,
                false => {
                    abandon(hub, w);
                    queued(&q.ticket)
                }
            };
            r.change_id = Some(made.change_id);
            let skipped = q.skipped.lock().unwrap().clone();
            r.warnings.extend(skipped_warnings(hub, project.id, &q.branch, &skipped).await?);
            seen(hub, project, viewer, r).await
        }
        _ => Err(Error::bad_request("a landing names either an uploaded `snapshot`, or `edits` on a `base`")),
    }
}

/// The answer to a landing with nothing in it to land: every change is on
/// the branch already, or one its submitter does not see whole (left for
/// someone who does).
pub const NOTHING_TO_LAND: &str =
    "nothing to land: every change here is on the branch already, or holds edits you cannot see (whoever sees all of it can land it)";

/// Most snapshots one submit reads, of its submitted line and of its walk
/// down the branch (`Ancestry`), when neither `landings` nor the derived
/// graph answers; past it the submit is answered `warming` (changes hidden
/// from the submitter count toward nothing they are told, BUG-1313).
pub const WALK_BUDGET: usize = 4_096;
///Most frontier snapshots of that walk the derived graph is asked about.
const FRONTIER_LIMIT: usize = 64;

/// Whether a change of a stack landed already ([`Ancestry::landed`]).
#[derive(Clone, Copy, PartialEq)]
enum Landed {
    No,
    /// With the same edits: skipped.
    Same,
    /// A revision with other edits: refused.
    Other,
}

/// A stack, and the branch's lineage it was judged under (`branch`:
/// false when there is no such branch: the service answers so).
pub struct Judged {
    pub stack: Vec<Entry>,
    pub lineage: i64,
    pub branch: bool,
    /// Changes of the line landed already with the same edits, left out
    /// (real ids): the answer names them, never silent.
    pub skipped: Vec<ObjectId>,
}

/// How far the walk down from the tip reads while the line is read (a base
/// a few landings below a tip the deriver has not reached yet); the rest of
/// [`WALK_BUDGET`] is spent only once the line is read.
const NEAR_WALK: usize = 256;

/// One change of a submitted line the submitter sees.
struct Link {
    id: ObjectId,
    held: bool,
    /// It is theirs to land (seen whole, not landed already).
    lands: bool,
    /// Whether it is on the branch was not decided while the line was read
    /// (the derived graph is behind the tip).
    unknown: bool,
}

/// What a held change is to its submitter (its own edits, against its
/// first parent or the base it lands on).
enum Class {
    /// Every edit at a path they cannot read: not in their history.
    Hidden,
    /// Seen whole: theirs to land.
    Whole,
    /// Seen in part: left for whoever sees it whole.
    Part,
}

/// The stack a landing of `new` (real) on `branch` lands (§4.6), whichever
/// route submits it (a push, `vl land`, edits on a base): the changes
/// between the branch and `new` **that the submitter sees whole**, oldest
/// first (`docs/HUB.md` §13.19). `new`'s first-parent line is read change by
/// change as the submitter sees it:
///
/// * a held change on the branch (the branch's real ancestry in its current
///   lineage: `Ancestry::near`, then `Ancestry::has`) ends it; a merge
///   with a parent on the branch ends it with that parent as its base
///   (BUG-1271);
/// * a run of changes hidden from the submitter is stepped over in one step
///   by their projection and the derived graph (`Ancestry::below_hidden`),
///   counting toward nothing (BUG-1409); while the graph is behind it, each
///   is read, at most [`WALK_BUDGET`], then `warming`;
/// * a change whose edits are on the branch already (`landings`, or a
///   revision of it there by the same author: `Ancestry::landed`) is skipped
///   (BUG-1408); one the submitter sees only in part is left for whoever sees
///   it whole; one with conflicts they can see is refused;
/// * at most [`WALK_BUDGET`] changes they see are read, and at most
///   `MAX_LAND_STACK` land.
///
/// `Err(why)` to refuse (naming no path).
pub async fn stack(
    hub: &Arc<Hub>,
    project: &crate::perm::Project,
    viewer: &crate::perm::Viewer,
    branch: &str,
    new: ObjectId,
    fresh: &HashMap<ObjectId, (Vec<ObjectId>, i64)>,
) -> Result<std::result::Result<Judged, String>> {
    let root = crate::sync::root_snapshot_id();
    let pid = project.id;
    let max = veil_core::hub::land::MAX_LAND_STACK;
    let row: Option<(String, i64)> = sqlx::query_as("SELECT target, lineage FROM branches WHERE project_id = $1 AND name = $2")
        .bind(pid)
        .bind(branch)
        .fetch_optional(&hub.db)
        .await?;
    let Some((tip, lineage)) = row else { return Ok(Ok(Judged { stack: Vec::new(), lineage: 0, branch: false, skipped: Vec::new() })) };
    let tip = ObjectId::from_hex(&tip).map_err(|e| Error::Other(e.into()))?;
    let mut anc = Ancestry::new(hub.clone(), pid, branch, tip, lineage);
    let too_many = || Ok(Err(format!("more than {max} changes between the branch's tip and this one: land them in parts, or have an admin push with --force")));
    let key = (!viewer.admin).then(|| project.view(viewer).key());
    let mut line: Vec<Link> = Vec::new();
    // Changes landed already with the same edits, left out (and said so).
    let mut skipped: Vec<ObjectId> = Vec::new();
    let (mut seen, mut hidden, mut kept) = (0usize, 0usize, 0usize);
    let mut reached_tip = false;
    let mut floor = root;
    let mut x = new;
    loop {
        if x == tip {
            reached_tip = true;
            floor = x;
            break;
        }
        if x == root {
            break;
        }
        let held = !fresh.contains_key(&x);
        let parents = match fresh.get(&x) {
            Some((p, _)) => p.clone(),
            None => {
                let y = x;
                crate::sync::blocking(hub, pid, move |src| Ok(src.snapshot(&y)?.parents.clone())).await?
            }
        };
        let mut unknown = false;
        let mut class = None;
        if held {
            match anc.near(x).await? {
                Some(true) => {
                    floor = x;
                    break;
                }
                Some(false) => {}
                None => unknown = true,
            }
            if let Some(k) = &key {
                match anc.below_hidden(project, viewer, k, x).await? {
                    // A run hidden from them, stepped over.
                    Some(v) if v != x => {
                        x = v;
                        continue;
                    }
                    Some(_) => {}
                    // The derived graph is behind: the change itself is read.
                    None => {
                        let c = classify(hub, project, viewer, x, parents[0]).await?;
                        match c {
                            Err(why) => return Ok(Err(why)),
                            Ok(Class::Hidden) => {
                                hidden += 1;
                                if hidden > WALK_BUDGET {
                                    let h = hub.clone();
                                    tokio::spawn(async move {
                                        let _ = crate::derive::ensure(&h, pid, new).await;
                                    });
                                    return Err(crate::query::graph::warming());
                                }
                                x = parents[0];
                                continue;
                            }
                            Ok(c) => class = Some(c),
                        }
                    }
                }
            }
        }
        seen += 1;
        if seen > WALK_BUDGET {
            return Err(crate::query::graph::warming());
        }
        // A merge with a parent on the branch ends the stack (BUG-1271).
        let mut ends = None;
        if parents.len() > 1 && !anc.has(parents[0]).await? {
            for p in &parents[1..] {
                if anc.has(*p).await? {
                    ends = Some(*p);
                    break;
                }
            }
        }
        // Theirs to land: a change seen whole (their own, or held and seen
        // whole); one seen in part or hidden is left out, and is never
        // judged as landed by edits they cannot see (BUG-1526).
        let whole = !held
            || viewer.admin
            || {
                let c = match (class, ends) {
                    (Some(c), None) => c,
                    _ => match classify(hub, project, viewer, x, ends.unwrap_or(parents[0])).await? {
                        Ok(c) => c,
                        Err(why) => return Ok(Err(why)),
                    },
                };
                matches!(c, Class::Whole)
            };
        let landed = whole
            && match anc.landed(x, held, fresh).await? {
                Landed::No => false,
                Landed::Same => {
                    skipped.push(x);
                    true
                }
                Landed::Other => {
                    return Ok(Err(format!(
                        "this change already landed on '{branch}' with other edits: make a new change for the further edits"
                    )))
                }
            };
        let lands = whole && !landed;
        if lands {
            kept += 1;
            if kept > max && !line.iter().any(|l| l.unknown) && !unknown {
                return too_many();
            }
        }
        line.push(Link { id: x, held, lands, unknown });
        if let Some(p) = ends {
            floor = p;
            break;
        }
        x = parents[0];
    }
    // Changes whose place was not decided as the line was read: above the
    // tip none is on the branch; else the first that is cuts the line.
    if !reached_tip {
        for i in 0..line.len() {
            if line[i].unknown && line[i].held && anc.has(line[i].id).await? {
                floor = line[i].id;
                line.truncate(i);
                break;
            }
        }
    }
    let lands: Vec<ObjectId> = line.iter().filter(|l| l.lands).map(|l| l.id).collect();
    if lands.len() > max {
        return too_many();
    }
    // Oldest first, each on the one below it that lands (or where the stack
    // starts).
    let mut stack = Vec::with_capacity(lands.len());
    let mut base = floor;
    for id in lands.into_iter().rev() {
        stack.push(Entry::plain(id, base));
        base = id;
    }
    Ok(Ok(Judged { stack, lineage, branch: true, skipped }))
}

/// The one rule of every tip an agent session sets (`sync::agent_tip`), for a
/// landing stack `judged` up to real `to` on `branch` (BUG-1636): judged from
/// the stack's base (the parent of its first change, which the service diffs
/// against to apply the stack on the tip) to `to`, before the landing is
/// queued. With `per_branch` (a push to a protected branch), a narrowing
/// refusal comes back as `Ok(Some(NARROWED_MOVE))` for the branch's
/// `BranchResult`; on `POST …/land` (`per_branch == false`), every refusal is
/// `403 agent_session`, matching `sync::agent_tip_of` and `changes`.
pub(crate) async fn agent_stack(
    hub: &Arc<Hub>,
    project: &crate::perm::Project,
    viewer: &crate::perm::Viewer,
    branch: &str,
    judged: &Judged,
    to: ObjectId,
    per_branch: bool,
) -> Result<Option<&'static str>> {
    if !viewer.agent {
        return Ok(None);
    }
    let default = branch == project.default_branch;
    let (view_policy, view_bindings, v, j_branch, entries) = (
        project.policy_text.clone(),
        project.bindings.clone(),
        viewer.clone(),
        judged.branch,
        judged.stack.clone(),
    );
    let refused = crate::sync::blocking(hub, project.id, move |src| {
        let base = if !j_branch && default {
            None
        } else if let Some(e) = entries.first() {
            let s = src.snapshot(&e.id)?;
            Some(if s.parents.get(1..).is_some_and(|o| o.contains(&e.base)) {
                e.base
            } else {
                s.parents.first().copied().unwrap_or_else(crate::sync::root_snapshot_id)
            })
        } else {
            return Ok(None);
        };
        let p = crate::perm::Project {
            id: src.project,
            name: String::new(),
            default_branch: String::new(),
            policy: veil_core::hub::access::AccessPolicy::parse(&view_policy),
            policy_text: view_policy,
            bindings: view_bindings,
        };
        let view = p.view(&v);
        if let Some(r) = crate::sync::agent_tip(src, &view, default, base, to)? {
            return Ok(Some(r));
        }
        for e in &entries {
            let s = src.snapshot(&e.id)?;
            let against = if s.parents.get(1..).is_some_and(|o| o.contains(&e.base)) {
                e.base
            } else {
                s.parents.first().copied().unwrap_or_else(crate::sync::root_snapshot_id)
            };
            if let Some(r) = crate::sync::agent_tip(src, &view, default, Some(against), e.id)? {
                return Ok(Some(r));
            }
        }
        Ok(None)
    })
    .await?;
    match refused {
        Some(crate::sync::AgentTip::Narrowed) if per_branch => Ok(Some(crate::sync::NARROWED_MOVE)),
        Some(crate::sync::AgentTip::Narrowed) => Err(crate::sync::agent_refusal(crate::sync::NARROWED_MOVE)),
        Some(crate::sync::AgentTip::Access) => Err(crate::sync::agent_refusal(crate::sync::AGENT_ACCESS_MOVE)),
        Some(crate::sync::AgentTip::DefaultBranch) => Err(crate::sync::agent_refusal(crate::sync::AGENT_DEFAULT_BRANCH)),
        None => Ok(None),
    }
}

/// What held change `x` is to `viewer`: its own edits against `against`
/// (its first parent, or the base a merge lands on). `Err` to refuse it
/// (conflicts they can see).
async fn classify(
    hub: &Arc<Hub>,
    project: &crate::perm::Project,
    viewer: &crate::perm::Viewer,
    x: ObjectId,
    against: ObjectId,
) -> Result<std::result::Result<Class, String>> {
    let (view_policy, view_bindings, v) = (project.policy_text.clone(), project.bindings.clone(), viewer.clone());
    crate::sync::blocking(hub, project.id, move |src| {
        let p = crate::perm::Project {
            id: src.project,
            name: String::new(),
            default_branch: String::new(),
            policy: veil_core::hub::access::AccessPolicy::parse(&view_policy),
            policy_text: view_policy,
            bindings: view_bindings,
        };
        let view = p.view(&v);
        let s = src.snapshot(&x)?;
        if s.conflicts.iter().any(|c| view.read(c)) {
            return Ok(Err("a change with unresolved conflicts never lands: resolve them first".to_string()));
        }
        if v.admin {
            return Ok(Ok(Class::Whole));
        }
        let own = edits::edit_set(src, s.tree, src.snapshot(&against)?.tree)?;
        let readable = own.iter().filter(|c| view.read(&c.path)).count();
        Ok(Ok(if s.parents.len() == 1 && !own.is_empty() && readable == 0 {
            Class::Hidden
        } else if readable == own.len() {
            Class::Whole
        } else {
            Class::Part
        }))
    })
    .await
}

/// Is a real snapshot on a branch at `tip` (its real ancestry, in its
/// current `lineage`)? Cheapest first, for one submit ([`stack`]): the tip;
/// a snapshot `landings` says is on it (one the service landed, or moved
/// the branch from); the derived commit graph when it holds the tip; else
/// one walk down from the tip, shared by every question of the submit, at
/// most [`WALK_BUDGET`] snapshots, whose frontier the graph then answers
/// for, else `warming` (BUG-1302).
pub(crate) struct Ancestry {
    hub: Arc<Hub>,
    project: i64,
    branch: String,
    tip: ObjectId,
    lineage: i64,
    known: HashMap<ObjectId, bool>,
    /// Does the derived graph hold the tip (asked once)?
    graph: Option<bool>,
    walk: Option<Walk>,
}

/// The walk down from the tip: what it found, what is left to read.
struct Walk {
    seen: std::collections::HashSet<ObjectId>,
    todo: std::collections::VecDeque<ObjectId>,
    read: usize,
    done: bool,
}

impl Ancestry {
    pub(crate) fn new(hub: Arc<Hub>, project: i64, branch: &str, tip: ObjectId, lineage: i64) -> Ancestry {
        Ancestry {
            hub,
            project,
            branch: branch.to_string(),
            tip,
            lineage,
            known: HashMap::new(),
            graph: None,
            walk: None,
        }
    }

    /// Is `x` a snapshot `landings` says is on the branch (`landed`: one the
    /// service landed, or moved the branch from)?
    async fn recorded(&self, x: ObjectId) -> Result<bool> {
        let n: Option<i32> =
            sqlx::query_scalar("SELECT 1 FROM landings WHERE project_id = $1 AND branch = $2 AND lineage = $3 AND landed = $4 LIMIT 1")
                .bind(self.project)
                .bind(&self.branch)
                .bind(self.lineage)
                .bind(x.hex())
                .fetch_optional(&self.hub.db)
                .await?;
        Ok(n.is_some())
    }

    /// Does the derived graph hold the tip (then it answers every question
    /// of ancestry, by its jump table)?
    async fn graph(&mut self) -> Result<bool> {
        if self.graph.is_none() {
            let tip = self.tip;
            self.graph = Some(crate::derive::read(&self.hub, self.project, move |g| Ok(g.row(&tip)?.is_some())).await?);
        }
        Ok(self.graph == Some(true))
    }

    /// Is `x` the tip or below it, as far as a short walk tells while the
    /// line is read? `None`: not decided yet (`Ancestry::has` decides).
    async fn near(&mut self, x: ObjectId) -> Result<Option<bool>> {
        if x == self.tip || x == crate::sync::root_snapshot_id() {
            return Ok(Some(true));
        }
        if let Some(v) = self.known.get(&x) {
            return Ok(Some(*v));
        }
        if self.recorded(x).await? {
            self.known.insert(x, true);
            return Ok(Some(true));
        }
        self.hub.landing.stats.walks.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let tip = self.tip;
        if self.graph().await? {
            let v = crate::derive::read(&self.hub, self.project, move |g| Ok(g.row(&x)?.is_some() && g.is_ancestor(x, tip)?)).await?;
            self.known.insert(x, v);
            return Ok(Some(v));
        }
        let (found, done) = self.walk_until(x, NEAR_WALK).await?;
        if found || done {
            self.known.insert(x, found);
            return Ok(Some(found));
        }
        Ok(None)
    }

    /// Is `x` the tip or below it?
    pub(crate) async fn has(&mut self, x: ObjectId) -> Result<bool> {
        if let Some(v) = self.near(x).await? {
            return Ok(v);
        }
        let v = self.walk_to(x).await?;
        self.known.insert(x, v);
        Ok(v)
    }

    /// Has change `x` landed on the branch already (BUG-1522, BUG-1527,
    /// BUG-1547, BUG-1548, BUG-1579, BUG-1580: by its change id and author,
    /// whatever its snapshot or predecessors)? `landings` first (a fast path
    /// whose absence means nothing), then the branch's record of its changes
    /// in its lineage (`landed_changes` keyed on `(project, branch, lineage,
    /// change_id, author)`: one lookup no bound limits, BUG-1521; no
    /// predecessor list is read), the landed revision then checked to be the
    /// tip or below it ([`Ancestry::has`]: `warming` when that cannot be
    /// told). `Same`: its own edits are among the landed revision's (the
    /// same change, or rebased on a tip that holds it: skip it); `Other`:
    /// it brings further edits (refused: they are a new change's). A row
    /// with another author is ignored (`No`).
    async fn landed(&mut self, x: ObjectId, held: bool, fresh: &HashMap<ObjectId, (Vec<ObjectId>, i64)>) -> Result<Landed> {
        let n: Option<i32> = if !held {
            None
        } else {
            sqlx::query_scalar("SELECT 1 FROM landings WHERE project_id = $1 AND branch = $2 AND lineage = $3 AND submitted = $4 LIMIT 1")
                .bind(self.project)
                .bind(&self.branch)
                .bind(self.lineage)
                .bind(x.hex())
                .fetch_optional(&self.hub.db)
                .await?
        };
        if n.is_some() {
            return Ok(Landed::Same);
        }
        let Some(author) = snapshot_author(&self.hub, self.project, x, fresh).await? else { return Ok(Landed::No) };
        let cid = crate::sync::blocking(&self.hub, self.project, move |src| Ok(src.snapshot(&x)?.change_id.to_string())).await?;
        let row: Option<String> = sqlx::query_scalar(
            "SELECT landed FROM landed_changes WHERE project_id = $1 AND branch = $2 AND lineage = $3 AND change_id = $4 AND author = $5",
        )
        .bind(self.project)
        .bind(&self.branch)
        .bind(self.lineage)
        .bind(&cid)
        .bind(author)
        .fetch_optional(&self.hub.db)
        .await?;
        let Some(r) = row.and_then(|r| ObjectId::from_hex(&r).ok()) else { return Ok(Landed::No) };
        if r == x {
            return Ok(Landed::Same);
        }
        if !self.has(r).await? {
            return Ok(Landed::No);
        }
        // Nothing beyond the landed revision's edits (paths and what they
        // become), whatever the base: the same change, or one rebased on a
        // tip that holds it already (no edits of its own).
        let same = crate::sync::blocking(&self.hub, self.project, move |src| {
            let own = |id: ObjectId| -> Result<Vec<(String, Option<veil_core::TreeEntry>)>> {
                let s = src.snapshot(&id)?;
                let base = s.parents.first().copied().unwrap_or_else(crate::sync::root_snapshot_id);
                Ok(edits::edit_set(src, s.tree, src.snapshot(&base)?.tree)?.into_iter().map(|c| (c.path, c.new)).collect())
            };
            let (a, b) = (own(x)?, own(r)?);
            Ok(a.iter().all(|p| {
                b.iter().any(|q| {
                    p.0 == q.0
                        && match (&p.1, &q.1) {
                            (None, None) => true,
                            (Some(e), Some(f)) => e.same_content(f),
                            _ => false,
                        }
                })
            }))
        })
        .await?;
        Ok(if same { Landed::Same } else { Landed::Other })
    }

    /// The change of `viewer`'s history that held `x` stands for (view key
    /// `key`): `x` itself when it is one, else (`x` hidden from them) the
    /// one its projection is: of that view's real snapshots with `x`'s
    /// projection, the one that did not collapse into its parent's
    /// (`projections_own`: one index row, however long the run, BUG-1468).
    /// `None` when that is not one row (memos older than the column, or two
    /// changes alike for the view): the caller reads `x` itself.
    async fn below_hidden(&mut self, project: &crate::perm::Project, viewer: &crate::perm::Viewer, key: &str, x: ObjectId) -> Result<Option<ObjectId>> {
        let px = crate::sync::projected(&self.hub, project, viewer, x).await?;
        let own: Vec<String> = sqlx::query_scalar(
            "SELECT real_id FROM projections WHERE project_id = $1 AND view_key = $2 AND projected_id = $3 AND NOT collapsed \
             ORDER BY real_id LIMIT 2",
        )
        .bind(self.project)
        .bind(key)
        .bind(px.hex())
        .fetch_all(&self.hub.db)
        .await?;
        let Some(v) = (match own.as_slice() {
            [v] => ObjectId::from_hex(v).ok(),
            _ => None,
        }) else {
            return Ok(None);
        };
        if v == x {
            return Ok(Some(x));
        }
        // The step goes down, where the derived graph can tell (memos older
        // than the column count as collapsed, so one row is unique).
        let below = crate::derive::read(&self.hub, self.project, move |g| {
            Ok(match (g.row(&x)?, g.row(&v)?) {
                (Some(_), Some(_)) => g.is_ancestor(v, x)?,
                _ => true,
            })
        })
        .await?;
        Ok(below.then_some(v))
    }

    /// The shared walk down from the tip, on until it finds `x`, ends, or has
    /// read `budget` snapshots in all: (found, ended).
    async fn walk_until(&mut self, x: ObjectId, budget: usize) -> Result<(bool, bool)> {
        let root = crate::sync::root_snapshot_id();
        let w = self.walk.take().unwrap_or_else(|| Walk {
            seen: std::collections::HashSet::from([self.tip]),
            todo: std::collections::VecDeque::from([self.tip]),
            read: 0,
            done: false,
        });
        let w = crate::sync::blocking(&self.hub, self.project, move |src| {
            let mut w = w;
            while !w.seen.contains(&x) && !w.done && w.read < budget {
                let Some(y) = w.todo.pop_front() else {
                    w.done = true;
                    break;
                };
                w.read += 1;
                for p in &src.snapshot(&y)?.parents {
                    if *p != root && w.seen.insert(*p) {
                        w.todo.push_back(*p);
                    }
                }
            }
            if w.todo.is_empty() {
                w.done = true;
            }
            Ok(w)
        })
        .await?;
        let out = (w.seen.contains(&x), w.done);
        self.walk = Some(w);
        Ok(out)
    }

    /// The shared walk, on until it finds `x`, ends, or spends its budget;
    /// then its frontier by the derived graph, else `warming`.
    async fn walk_to(&mut self, x: ObjectId) -> Result<bool> {
        let (found, done) = self.walk_until(x, WALK_BUDGET).await?;
        let frontier: Vec<ObjectId> = self.walk.as_ref().map(|w| w.todo.iter().copied().collect()).unwrap_or_default();
        if found || done {
            return Ok(found);
        }
        if frontier.len() > FRONTIER_LIMIT {
            return Err(crate::query::graph::warming());
        }
        let answer = crate::derive::read(&self.hub, self.project, move |g| {
            for f in &frontier {
                if g.row(f)?.is_none() {
                    return Ok(None);
                }
            }
            if g.row(&x)?.is_none() {
                return Ok(Some(false));
            }
            for f in &frontier {
                if g.is_ancestor(x, *f)? {
                    return Ok(Some(true));
                }
            }
            Ok(Some(false))
        })
        .await?;
        answer.ok_or_else(crate::query::graph::warming)
    }
}

/// The branch rules (`.veilrules`) a move of the default branch to real tree
/// `new` would change, against its tip's `tip` (BUG-1102): only an admin's
/// move may. The accepted rules are the tip's, never a parent's.
pub fn rules_changed(src: &Source, new: &ObjectId, tip: Option<&ObjectId>) -> Result<bool> {
    let at = |t: &ObjectId| crate::sync::entry_at(src, t, rules::RULES_FILE);
    let before = match tip {
        Some(t) => at(t)?,
        None => None,
    };
    let after = at(new)?;
    Ok(match (after, before) {
        (None, None) => false,
        (Some(a), Some(b)) => !a.same_content(&b),
        _ => true,
    })
}

