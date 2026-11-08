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
    /// `landings` says its edits are on the branch already.
    landed: bool,
}

/// The stack a landing of `new` (real) on `branch` lands (§4.6), whichever
/// route submits it (a push, `vl land`, edits on a base): the changes
/// between the branch and `new` **that the submitter sees whole**, oldest
/// first (`docs/HUB.md` §13.19):
///
/// * `new`'s first-parent line down to the first snapshot on the branch
///   (the branch's real ancestry in its current lineage: `Ancestry`), judged
///   change by change: one whose edits `landings` says are on the branch is
///   skipped, and the line read on below it (BUG-1311). A merge with a
///   parent on the branch ends the stack, with that parent as its base
///   (BUG-1271).
/// * Those this request brought (`fresh`) are the submitter's; of those the
///   server held, one whose own edits are all at paths `viewer` can read
///   lands, and one hidden from them or seen only in part is left for
///   someone who sees it whole. One with conflicts they can see is refused.
/// * At most `MAX_LAND_STACK` changes they see, counted as they are found;
///   the line is read at most [`WALK_BUDGET`] deep, else `warming`.
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
    let max = veil_core::hub::land::MAX_LAND_STACK;
    let row: Option<(String, i64)> = sqlx::query_as("SELECT target, lineage FROM branches WHERE project_id = $1 AND name = $2")
        .bind(pid)
        .bind(branch)
        .fetch_optional(&hub.db)
        .await?;
    let Some((tip, lineage)) = row else { return Ok(Ok(Judged { stack: Vec::new(), lineage: 0, branch: false })) };
    let tip = ObjectId::from_hex(&tip).map_err(|e| Error::Other(e.into()))?;
    let mut anc = Ancestry::new(hub.clone(), pid, branch, tip, lineage);
    let too_many = || Ok(Err(format!("more than {max} changes between the branch's tip and this one: land them in parts, or have an admin push with --force")));
    // 1. The line, down to the tip, the root, or a snapshot on the branch by
    // `landings` (looked up in growing groups: the first held one alone, as
    // an agent's base is its own last landing).
    let mut line: Vec<Link> = Vec::new();
    let mut reached_tip = false;
    let mut at_root = false;
    // Ended at a snapshot on the branch.
    let mut ended = false;
    let mut pending: Vec<usize> = Vec::new();
    let mut group = 1;
    let mut fresh_seen = 0;
    let mut x = new;
    loop {
        if x == tip {
            reached_tip = true;
            break;
        }
        if x == root {
            at_root = true;
            break;
        }
        if line.len() == WALK_BUDGET {
            return Err(crate::query::graph::warming());
        }
        let held = !fresh.contains_key(&x);
        if !held {
            fresh_seen += 1;
            if fresh_seen > max {
                return too_many();
            }
        }
        let parents = match fresh.get(&x) {
            Some(p) => p.clone(),
            None => {
                let y = x;
                crate::sync::blocking(hub, pid, move |src| Ok(src.snapshot(&y)?.parents.clone())).await?
            }
        };
        let id = x;
        x = parents[0];
        line.push(Link { id, parents, held, landed: false });
        if held {
            pending.push(line.len() - 1);
        }
        if pending.len() >= group {
            if let Some(i) = anc.look_up(&mut line, &pending).await? {
                line.truncate(i);
                ended = true;
                break;
            }
            pending.clear();
            group = (group * 2).min(64);
        }
    }
    if !reached_tip && !ended && !pending.is_empty() {
        if let Some(i) = anc.look_up(&mut line, &pending).await? {
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
        if line[i].held && !line[i].landed && !reached_tip && anc.has(line[i].id).await? {
            cut = i;
            break;
        }
        if line[i].parents.len() > 1 {
            let p0_on = match line.get(i + 1) {
                Some(next) => next.held && !next.landed && !reached_tip && anc.has(next.id).await?,
                None => reached_tip || ended || at_root,
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
                    break;
                }
            }
        }
    }
    line.truncate(cut);
    // 3. What of it the submitter lands, counted as it is found (at most
    // `max` changes they see), each with its base.
    let floor = match (merge_base, line.last()) {
        (Some(p), _) => p,
        (None, Some(l)) => l.parents[0],
        (None, None) => return Ok(Ok(Judged { stack: Vec::new(), lineage, branch: true })),
    };
    let links: Vec<(ObjectId, Vec<ObjectId>, bool, bool)> = line.iter().map(|l| (l.id, l.parents.clone(), l.held, l.landed)).collect();
    let (view_policy, view_bindings, v) = (project.policy_text.clone(), project.bindings.clone(), viewer.clone());
    let kept = crate::sync::blocking(hub, pid, move |src| {
        let p = crate::perm::Project {
            id: src.project,
            name: String::new(),
            default_branch: String::new(),
            policy: veil_core::hub::access::AccessPolicy::parse(&view_policy),
            policy_text: view_policy,
            bindings: view_bindings,
        };
        let view = p.view(&v);
        // Top-down: (id, lands).
        let mut out: Vec<ObjectId> = Vec::new();
        let n = links.len();
        for (i, (id, parents, held, landed)) in links.iter().enumerate() {
            if *landed {
                continue;
            }
            if *held {
                let s = src.snapshot(id)?;
                if s.conflicts.iter().any(|c| view.read(c)) {
                    return Ok(Err("a change with unresolved conflicts never lands: resolve them first".to_string()));
                }
                if !v.admin {
                    // Its own edits: against its first parent (the merge
                    // ending the stack: against its base, what it lands as).
                    let against = match merge_base {
                        Some(m) if i + 1 == n => m,
                        _ => parents[0],
                    };
                    let own = edits::edit_set(src, s.tree, src.snapshot(&against)?.tree)?;
                    if own.iter().any(|c| !view.read(&c.path)) {
                        continue;
                    }
                }
            }
            out.push(*id);
            if out.len() > max {
                return Ok(Err(format!(
                    "more than {max} changes between the branch's tip and this one: land them in parts, or have an admin push with --force"
                )));
            }
        }
        Ok(Ok(out))
    })
    .await?;
    let kept = match kept {
        Ok(k) => k,
        Err(why) => return Ok(Err(why)),
    };
    // Oldest first, each on the one below it that lands (or where the stack
    // starts).
    let mut stack = Vec::with_capacity(kept.len());
    let mut base = floor;
    for id in kept.into_iter().rev() {
        stack.push(Entry::plain(id, base));
        base = id;
    }
    Ok(Ok(Judged { stack, lineage, branch: true }))
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

    /// Of `ids`, those on the branch (`landed` rows: a snapshot the service
    /// landed, or moved the branch from) and those whose edits are on it
    /// (`submitted` rows), in one statement (each half by its own index).
    async fn recorded(&self, ids: &[ObjectId]) -> Result<(std::collections::HashSet<ObjectId>, std::collections::HashSet<ObjectId>)> {
        let hex: Vec<String> = ids.iter().map(ObjectId::hex).collect();
        let rows: Vec<(String, bool)> = sqlx::query_as(
            "SELECT landed, true FROM landings WHERE project_id = $1 AND branch = $2 AND lineage = $3 AND landed = ANY($4) \
             UNION ALL SELECT submitted, false FROM landings WHERE project_id = $1 AND branch = $2 AND lineage = $3 AND submitted = ANY($4)",
        )
        .bind(self.project)
        .bind(&self.branch)
        .bind(self.lineage)
        .bind(&hex)
        .fetch_all(&self.hub.db)
        .await?;
        let (mut on, mut done) = (std::collections::HashSet::new(), std::collections::HashSet::new());
        for (id, branch) in rows {
            if let Ok(id) = ObjectId::from_hex(&id) {
                if branch {
                    on.insert(id);
                } else {
                    done.insert(id);
                }
            }
        }
        Ok((on, done))
    }

    /// Look `line`'s links at `at` up: marks those landed already, and
    /// gives the first (topmost) that is on the branch.
    async fn look_up(&mut self, line: &mut [Link], at: &[usize]) -> Result<Option<usize>> {
        let ids: Vec<ObjectId> = at.iter().map(|i| line[*i].id).collect();
        let (on, done) = self.recorded(&ids).await?;
        for i in at {
            let id = line[*i].id;
            if on.contains(&id) {
                self.known.insert(id, true);
                return Ok(Some(*i));
            }
            line[*i].landed = done.contains(&id);
        }
        Ok(None)
    }

    /// Is `x` the tip or below it?
    pub(crate) async fn has(&mut self, x: ObjectId) -> Result<bool> {
        if x == self.tip || x == crate::sync::root_snapshot_id() {
            return Ok(true);
        }
        if let Some(v) = self.known.get(&x) {
            return Ok(*v);
        }
        if self.recorded(&[x]).await?.0.contains(&x) {
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

