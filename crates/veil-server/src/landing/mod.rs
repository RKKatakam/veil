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

/// One change of a stack ([`stack`]): its real snapshot, its base (the
/// change below it, or the snapshot on the branch where the stack starts),
/// and, when something the submitter cannot see lies between the two (a
/// change left out of their history, or hidden edits of its own), what
/// they saw of them.
#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    pub id: ObjectId,
    pub base: ObjectId,
    pub seen: Option<Seen>,
}

/// The submitter's projections of an entry's tree and of its base's
/// (stored at submit): the entry's edits are the diff of these, so it
/// lands what they saw, under any later access.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Seen {
    pub new: ObjectId,
    pub old: ObjectId,
    /// They saw all of the change's own edits (else it lands in part).
    pub whole: bool,
}

impl Entry {
    pub fn plain(id: ObjectId, base: ObjectId) -> Entry {
        Entry { id, base, seen: None }
    }

    /// All of the change's own edits land with it.
    pub fn whole(&self) -> bool {
        self.seen.is_none_or(|s| s.whole)
    }
}

/// A stack as its queue row holds it: `[snapshot, base]`, or
/// `[snapshot, base, seen tree, seen base tree, "whole" | "part"]`.
pub fn encode_stack(stack: &[Entry]) -> String {
    let rows: Vec<Vec<String>> = stack
        .iter()
        .map(|e| match &e.seen {
            None => vec![e.id.hex(), e.base.hex()],
            Some(v) => vec![e.id.hex(), e.base.hex(), v.new.hex(), v.old.hex(), (if v.whole { "whole" } else { "part" }).to_string()],
        })
        .collect();
    serde_json::to_string(&rows).unwrap_or_default()
}

/// [`encode_stack`]'s inverse.
pub fn decode_stack(text: &str) -> Result<Vec<Entry>> {
    let rows: Vec<Vec<String>> = serde_json::from_str(text).map_err(|e| Error::Other(e.into()))?;
    let hex = |s: &str| ObjectId::from_hex(s).map_err(|e| Error::Other(e.into()));
    rows.iter()
        .map(|r| match r.as_slice() {
            [s, b] => Ok(Entry::plain(hex(s)?, hex(b)?)),
            [s, b, n, o, w] => Ok(Entry {
                id: hex(s)?,
                base: hex(b)?,
                seen: Some(Seen { new: hex(n)?, old: hex(o)?, whole: w == "whole" }),
            }),
            _ => Err(Error::Other(anyhow::anyhow!("a queue row's stack entry has {} fields", r.len()))),
        })
        .collect()
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
         project_epoch, state, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'queued', \
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
    .execute(&mut *c)
    .await?;
    Ok(())
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
    /// The branches whose waiters here a poller answers (`poll`).
    pollers: Mutex<std::collections::HashSet<(i64, String)>>,
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
            pollers: Mutex::new(Default::default()),
            stats: Stats::default(),
        }
    }
}

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

/// `r` as `viewer` sees it: the snapshots it landed, projected. (Outcomes
/// hold real snapshots; each answer is projected for its asker, from the
/// memo the landing stored where it kept their view key, else as a pull
/// would, in the asker's own request.)
pub async fn seen(hub: &Arc<Hub>, project: &crate::perm::Project, viewer: &crate::perm::Viewer, mut r: LandResult) -> Result<LandResult> {
    let mut out = Vec::with_capacity(r.landed.len());
    for x in &r.landed {
        out.push(crate::sync::projected(hub, project, viewer, *x).await?);
    }
    r.landed = out;
    Ok(r)
}

/// The outcome of `ticket` as stored (real snapshots: [`seen`]), if it is
/// `person`'s.
pub async fn read(hub: &Hub, project: i64, person: i64, ticket: &str) -> Result<Option<(String, LandResult)>> {
    let row: Option<(String, String, Option<String>)> =
        sqlx::query_as("SELECT branch, state, result FROM landing_queue WHERE ticket = $1 AND project_id = $2 AND person_id = $3")
            .bind(ticket)
            .bind(project)
            .bind(person)
            .fetch_optional(&hub.db)
            .await?;
    let Some((branch, state, result)) = row else { return Ok(None) };
    let r = match (state.as_str(), result) {
        ("queued", _) | (_, None) => queued(ticket),
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
        warnings: Vec::new(),
    }
}

/// Wait for `w`'s outcome until `deadline`: from the service here as soon as
/// it commits; else from the branch's poller here, which reads the rows of
/// the branch finished since it last looked, in one statement (every
/// 250 ms while another server runs the branch's service, every 5 s as a
/// fallback while this one does): its cost follows the landings, never the
/// number of waiters (BUG-1108).
pub async fn wait(hub: &Arc<Hub>, project: i64, person: i64, branch: &str, mut w: Waiter, deadline: tokio::time::Instant) -> Result<LandResult> {
    if let Some(e) = hub.landing.waiters.lock().unwrap().get_mut(&w.ticket) {
        e.1 = Some((project, branch.to_string()));
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
            seen(hub, project, viewer, r).await
        }
        _ => Err(Error::bad_request("a landing names either an uploaded `snapshot`, or `edits` on a `base`")),
    }
}

/// How deep [`stack`] reads a submitted snapshot's first-parent line (the
/// changes it may bring, hidden ones among them).
pub const LINE_LIMIT: usize = 1_024;
/// Most snapshots one submit's walk down the branch reads (`Ancestry`)
/// when neither `landings` nor the derived graph answers; past it the
/// submit is answered `warming`.
pub const WALK_BUDGET: usize = 4_096;
/// Most frontier snapshots of that walk the derived graph is asked about.
const FRONTIER_LIMIT: usize = 64;

/// A stack, and the branch's lineage it was judged under (`branch`:
/// false when there is no such branch: the service answers so).
pub struct Judged {
    pub stack: Vec<Entry>,
    pub lineage: i64,
    pub branch: bool,
}

/// One snapshot of a submitted first-parent line.
struct Link {
    id: ObjectId,
    parents: Vec<ObjectId>,
    /// The server held it before this request (else the request brought it,
    /// checked as this submitter's).
    held: bool,
}

/// The stack a landing of `new` (real) on `branch` lands (§4.6), whichever
/// route submits it (a push, `vl land`, edits on a base): **the submitter's
/// own history** between the branch and `new`, oldest first (S17 cycle 3,
/// `docs/HUB.md` §13.19):
///
/// * `new`'s first-parent line down to the first snapshot on the branch
///   (`Ancestry`: the branch's real ancestry, in its current lineage);
///   those this request brought (`fresh`, with their real parents) and those
///   the server already held. A merge with a parent on the branch ends the
///   stack, with that parent as its base (BUG-1271).
/// * A held change whose own edits are all at paths `viewer` cannot read is
///   not in their history: it is left out (and stays unlanded). One with
///   unresolved conflicts they can see is refused.
/// * Each change's base is the change below it in the stack, or where the
///   stack starts; when something hidden from `viewer` lies between (a
///   change left out, or hidden edits of its own), the entry holds their
///   projections of both trees ([`Seen`], stored here), whose diff is its
///   edits. Nothing they cannot see decides anything else.
///
/// `Err(why)` to refuse (naming no path).
pub async fn stack(
    hub: &Arc<Hub>,
    project: &crate::perm::Project,
    viewer: &crate::perm::Viewer,
    branch: &str,
    new: ObjectId,
    fresh: &HashMap<ObjectId, Vec<ObjectId>>,
) -> Result<std::result::Result<Judged, String>> {
    let root = crate::sync::root_snapshot_id();
    let pid = project.id;
    let row: Option<(String, i64)> = sqlx::query_as("SELECT target, lineage FROM branches WHERE project_id = $1 AND name = $2")
        .bind(pid)
        .bind(branch)
        .fetch_optional(&hub.db)
        .await?;
    let Some((tip, lineage)) = row else { return Ok(Ok(Judged { stack: Vec::new(), lineage: 0, branch: false })) };
    let tip = ObjectId::from_hex(&tip).map_err(|e| Error::Other(e.into()))?;
    let key = if viewer.admin { String::new() } else { project.view(viewer).key() };
    let mut anc = Ancestry::new(hub.clone(), pid, branch, tip, lineage, key);
    let too_many = || {
        Ok(Err(format!(
            "more than {} changes between the branch's tip and this one: land them in parts, or have an admin push with --force",
            veil_core::hub::land::MAX_LAND_STACK
        )))
    };
    // 1. The line, down to the tip, the root, or a snapshot `landings` says
    // is on the branch (looked up in growing groups: the first held one
    // alone, as an agent's base is its own last landing).
    let mut line: Vec<Link> = Vec::new();
    let mut reached_tip = false;
    let mut ended = false;
    let mut pending: Vec<usize> = Vec::new();
    let mut group = 1;
    let mut x = new;
    loop {
        if x == tip {
            reached_tip = true;
            break;
        }
        if x == root {
            ended = true;
            break;
        }
        if line.len() == LINE_LIMIT {
            break;
        }
        let held = !fresh.contains_key(&x);
        let parents = match fresh.get(&x) {
            Some(p) => p.clone(),
            None => {
                let y = x;
                crate::sync::blocking(hub, pid, move |src| Ok(src.snapshot(&y)?.parents.clone())).await?
            }
        };
        let id = x;
        x = parents[0];
        line.push(Link { id, parents, held });
        if held {
            pending.push(line.len() - 1);
        }
        if pending.len() >= group {
            if let Some(i) = anc.recorded_first(&line, &pending).await? {
                line.truncate(i);
                ended = true;
                break;
            }
            pending.clear();
            group = (group * 2).min(64);
        }
    }
    if !reached_tip && !ended && !pending.is_empty() {
        if let Some(i) = anc.recorded_first(&line, &pending).await? {
            line.truncate(i);
            ended = true;
        }
    }
    // 2. Where the branch's history starts on it: the first held change on
    // the branch (none above the tip is: each is a descendant of it), or a
    // merge with a parent there.
    let mut merge_base: Option<ObjectId> = None;
    let mut cut = line.len();
    for i in 0..line.len() {
        if line[i].held && !reached_tip && anc.has(line[i].id).await? {
            cut = i;
            ended = true;
            break;
        }
        if line[i].parents.len() > 1 {
            let p0_on = match line.get(i + 1) {
                Some(next) => next.held && !reached_tip && anc.has(next.id).await?,
                None => reached_tip || ended,
            };
            if !p0_on {
                let mut found = None;
                for p in &line[i].parents[1..] {
                    if anc.has(*p).await? {
                        found = Some(*p);
                        break;
                    }
                }
                if let Some(p) = found {
                    merge_base = Some(p);
                    cut = i + 1;
                    ended = true;
                    break;
                }
            }
        }
    }
    line.truncate(cut);
    if !reached_tip && !ended {
        // Deeper than the line is read, with nothing on the branch found.
        return too_many();
    }
    // 3. The submitter's history in it, oldest first, each with its base.
    let floor = match (merge_base, line.last()) {
        (Some(p), _) => p,
        (None, Some(l)) => l.parents[0],
        (None, None) => return Ok(Ok(Judged { stack: Vec::new(), lineage, branch: true })),
    };
    let links: Vec<(ObjectId, Vec<ObjectId>, bool)> = line.iter().rev().map(|l| (l.id, l.parents.clone(), l.held)).collect();
    let (view_policy, view_bindings, v) = (project.policy_text.clone(), project.bindings.clone(), viewer.clone());
    let made = crate::sync::blocking(hub, pid, move |src| {
        let p = crate::perm::Project {
            id: src.project,
            name: String::new(),
            default_branch: String::new(),
            policy: veil_core::hub::access::AccessPolicy::parse(&view_policy),
            policy_text: view_policy,
            bindings: view_bindings,
        };
        let view = p.view(&v);
        let mut pr = veil_core::hub::project::Projector::new(src, &view);
        let mut out: Vec<Entry> = Vec::new();
        let mut base = floor;
        // Something hidden from the submitter lies between `base` and the
        // next change kept.
        let mut hidden_between = false;
        for (id, parents, held) in &links {
            let s = src.snapshot(id)?;
            let mut whole = true;
            if *held && s.conflicts.iter().any(|c| view.read(c)) {
                return Ok(Err("a change with unresolved conflicts never lands: resolve them first"));
            }
            if *held && !v.admin {
                // Its own edits: against its first parent (a merge: against
                // its base, what it lands as).
                let against = if parents.len() == 1 { parents[0] } else { base };
                let own = edits::edit_set(src, s.tree, src.snapshot(&against)?.tree)?;
                let seen = own.iter().filter(|c| view.read(&c.path)).count();
                // Not in their history at all.
                if parents.len() == 1 && !own.is_empty() && seen == 0 {
                    hidden_between = true;
                    continue;
                }
                whole = seen == own.len();
            }
            let entry = if hidden_between || !whole {
                let old = src.snapshot(&base)?.tree;
                Entry {
                    id: *id,
                    base,
                    seen: Some(Seen { new: pr.root(s.tree)?, old: pr.root(old)?, whole }),
                }
            } else {
                Entry::plain(*id, base)
            };
            out.push(entry);
            base = *id;
            hidden_between = false;
        }
        let created: Vec<(ObjectId, bytes::Bytes)> = pr.created.iter().map(|(id, (_, raw))| (*id, bytes::Bytes::from(raw.clone()))).collect();
        Ok(Ok((out, created)))
    })
    .await?;
    let (stack, created) = match made {
        Ok(m) => m,
        Err(why) => return Ok(Err(why.to_string())),
    };
    if stack.len() > veil_core::hub::land::MAX_LAND_STACK {
        return too_many();
    }
    // What the service reads the edits from.
    crate::sync::put_all(hub, pid, created).await?;
    Ok(Ok(Judged { stack, lineage, branch: true }))
}

/// Is a real snapshot on a branch at `tip` (its real ancestry, in its
/// current `lineage`)? Cheapest first, for one submit ([`stack`]): the tip;
/// `landings` of the lineage (what the service landed there, the tips it
/// moved from, and submitted snapshots landed whole or for this view:
/// `key`); the derived commit graph when it holds the tip; else one walk
/// down from the tip, shared by every question of the submit, at most
/// [`WALK_BUDGET`] snapshots, whose frontier the graph then answers for,
/// else `warming` (BUG-1302).
pub(crate) struct Ancestry {
    hub: Arc<Hub>,
    project: i64,
    branch: String,
    tip: ObjectId,
    lineage: i64,
    key: String,
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
    pub(crate) fn new(hub: Arc<Hub>, project: i64, branch: &str, tip: ObjectId, lineage: i64, key: String) -> Ancestry {
        Ancestry {
            hub,
            project,
            branch: branch.to_string(),
            tip,
            lineage,
            key,
            known: HashMap::new(),
            graph: None,
            walk: None,
        }
    }

    /// Which of `ids` `landings` says are on the branch, in one statement
    /// (each half by its own index).
    async fn recorded(&self, ids: &[ObjectId]) -> Result<std::collections::HashSet<ObjectId>> {
        let hex: Vec<String> = ids.iter().map(ObjectId::hex).collect();
        let rows: Vec<String> = sqlx::query_scalar(
            "SELECT landed FROM landings WHERE project_id = $1 AND branch = $2 AND lineage = $3 AND landed = ANY($4) \
             UNION ALL SELECT submitted FROM landings WHERE project_id = $1 AND branch = $2 AND lineage = $3 AND submitted = ANY($4) \
             AND (whole OR view_key = $5)",
        )
        .bind(self.project)
        .bind(&self.branch)
        .bind(self.lineage)
        .bind(&hex)
        .bind(&self.key)
        .fetch_all(&self.hub.db)
        .await?;
        Ok(rows.iter().filter_map(|r| ObjectId::from_hex(r).ok()).collect())
    }

    /// The first (topmost) of `line`'s links at `at` that `landings` says
    /// is on the branch.
    async fn recorded_first(&mut self, line: &[Link], at: &[usize]) -> Result<Option<usize>> {
        let ids: Vec<ObjectId> = at.iter().map(|i| line[*i].id).collect();
        let on = self.recorded(&ids).await?;
        for i in at {
            self.known.entry(line[*i].id).or_insert(on.contains(&line[*i].id));
            if on.contains(&line[*i].id) {
                return Ok(Some(*i));
            }
        }
        Ok(None)
    }

    /// Is `x` the tip or below it?
    pub(crate) async fn has(&mut self, x: ObjectId) -> Result<bool> {
        if x == self.tip || x == crate::sync::root_snapshot_id() {
            return Ok(true);
        }
        if let Some(true) = self.known.get(&x) {
            return Ok(true);
        }
        if !self.known.contains_key(&x) && self.recorded(&[x]).await?.contains(&x) {
            self.known.insert(x, true);
            return Ok(true);
        }
        self.hub.landing.stats.walks.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let tip = self.tip;
        if self.graph.is_none() {
            self.graph = Some(crate::derive::read(&self.hub, self.project, move |g| Ok(g.row(&tip)?.is_some())).await?);
        }
        let v = if self.graph == Some(true) {
            // Everything below a derived snapshot is derived.
            crate::derive::read(&self.hub, self.project, move |g| Ok(g.row(&x)?.is_some() && g.is_ancestor(x, tip)?)).await?
        } else {
            self.walk_to(x).await?
        };
        self.known.insert(x, v);
        Ok(v)
    }

    /// The shared walk, on until it finds `x`, ends, or spends its budget;
    /// then its frontier by the derived graph, else `warming`.
    async fn walk_to(&mut self, x: ObjectId) -> Result<bool> {
        let root = crate::sync::root_snapshot_id();
        let w = self.walk.take().unwrap_or_else(|| Walk {
            seen: std::collections::HashSet::from([self.tip]),
            todo: std::collections::VecDeque::from([self.tip]),
            read: 0,
            done: false,
        });
        let w = crate::sync::blocking(&self.hub, self.project, move |src| {
            let mut w = w;
            while !w.seen.contains(&x) && !w.done && w.read < WALK_BUDGET {
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
        let (found, done) = (w.seen.contains(&x), w.done);
        let frontier: Vec<ObjectId> = w.todo.iter().copied().collect();
        self.walk = Some(w);
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

