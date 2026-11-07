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

/// One queue row to insert in the submit's transaction.
#[derive(Clone, Debug)]
pub struct Queued {
    pub ticket: String,
    pub branch: String,
    /// The real submitted snapshots, oldest first, each with its base: the
    /// parent its edits are against (its first parent, or for a merge with
    /// a parent on the branch, that parent: `stack`).
    pub stack: Vec<(ObjectId, ObjectId)>,
}

/// A new random ticket.
pub fn ticket() -> String {
    format!("land-{}", hex::encode(veil_core::crypto::random_bytes::<16>()))
}

/// Insert `q` for `who` into the queue of `project`, in the caller's
/// transaction.
pub async fn insert(c: &mut PgConnection, project: i64, who: &Submitter, q: &Queued) -> Result<()> {
    let stack: Vec<[String; 2]> = q.stack.iter().map(|(s, b)| [s.hex(), b.hex()]).collect();
    sqlx::query(
        "INSERT INTO landing_queue (project_id, branch, ticket, person_id, person_name, device_key, stack, person_epoch, project_epoch, \
         state, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'queued', (extract(epoch FROM clock_timestamp()) * 1000000)::BIGINT)",
    )
    .bind(project)
    .bind(&q.branch)
    .bind(&q.ticket)
    .bind(who.person.id)
    .bind(&who.person.name)
    .bind(&who.person.device_key)
    .bind(serde_json::to_string(&stack).map_err(|e| Error::Other(e.into()))?)
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

/// The stack a landing of `new` (real) on a branch at `tip` lands (§4.6),
/// whichever route submits it (a push, `vl land`, edits on a base): every
/// change from the branch's tip up to `new`, oldest first, on `new`'s
/// first-parent line, each with its **base** (what its edits are against):
///
/// * those the request brought (`fresh`, with their real parents: they
///   passed the push's checks as this submitter's), and those the server
///   already held (on another branch, an API commit, a landing answered
///   `conflict`), down to the first that is on the branch (the tip or below
///   it, or a submitted snapshot that landed: `landings`; BUG-1103,
///   BUG-1112);
/// * a merge with a parent on the branch ends the stack: its edits against
///   that parent are everything the branch lacks (a conflicted change with
///   the branch merged into it and resolved, BUG-1271);
/// * a held change must touch only paths `viewer` may read, so that no
///   answer about the stack (a conflict, a refusal) can name one they
///   cannot (BUG-1111), and must hold no conflicts.
///
/// `Err(why)` to refuse (naming no path).
#[allow(clippy::too_many_arguments)]
pub async fn stack(
    hub: &Arc<Hub>,
    project: &crate::perm::Project,
    viewer: &crate::perm::Viewer,
    new: ObjectId,
    tip: ObjectId,
    fresh: &HashMap<ObjectId, Vec<ObjectId>>,
) -> Result<std::result::Result<Vec<(ObjectId, ObjectId)>, String>> {
    let root = crate::sync::root_snapshot_id();
    let pid = project.id;
    let mut out = Vec::new();
    let mut x = new;
    while x != tip && x != root {
        if out.len() == veil_core::hub::land::MAX_LAND_STACK {
            return Ok(Err(format!(
                "more than {} changes between the branch's tip and this one: land them in parts, or have an admin push with --force",
                veil_core::hub::land::MAX_LAND_STACK
            )));
        }
        let held = !fresh.contains_key(&x);
        if held && on_branch_or_landed(hub, pid, x, tip).await? {
            break;
        }
        let parents = match fresh.get(&x) {
            Some(p) => p.clone(),
            None => {
                let y = x;
                crate::sync::blocking(hub, pid, move |src| Ok(src.snapshot(&y)?.parents.clone())).await?
            }
        };
        // A merge with a parent on the branch: its edits against that one.
        let mut base = parents[0];
        let mut last = false;
        if parents.len() > 1 && !on_branch_or_landed(hub, pid, parents[0], tip).await? {
            for p in &parents[1..] {
                if on_branch_or_landed(hub, pid, *p, tip).await? {
                    base = *p;
                    last = true;
                    break;
                }
            }
        }
        if held {
            let (y, b, view_policy, view_bindings, v) = (x, base, project.policy_text.clone(), project.bindings.clone(), viewer.clone());
            let refusal = crate::sync::blocking(hub, pid, move |src| {
                let s = src.snapshot(&y)?;
                if !s.conflicts.is_empty() {
                    return Ok(Some("a change with unresolved conflicts never lands: resolve them first"));
                }
                let p = crate::perm::Project {
                    id: src.project,
                    name: String::new(),
                    default_branch: String::new(),
                    policy: veil_core::hub::access::AccessPolicy::parse(&view_policy),
                    policy_text: view_policy,
                    bindings: view_bindings,
                };
                let view = p.view(&v);
                let set = edits::edit_set(src, s.tree, src.snapshot(&b)?.tree)?;
                Ok(set.iter().any(|c| !view.read(&c.path)).then_some(
                    "the changes under this one touch folders you cannot see: ask someone who can see them to land them",
                ))
            })
            .await?;
            if let Some(why) = refusal {
                return Ok(Err(why.to_string()));
            }
        }
        out.push((x, base));
        if last {
            break;
        }
        x = parents[0];
    }
    out.reverse();
    Ok(Ok(out))
}

/// Is real snapshot `x` on the branch at `tip` (the tip or below it), or a
/// submitted snapshot whose landing is?
async fn on_branch_or_landed(hub: &Arc<Hub>, project: i64, x: ObjectId, tip: ObjectId) -> Result<bool> {
    if on_branch(hub, project, x, tip).await? {
        return Ok(true);
    }
    let landed: Option<String> = sqlx::query_scalar("SELECT landed FROM landings WHERE project_id = $1 AND submitted = $2")
        .bind(project)
        .bind(x.hex())
        .fetch_optional(&hub.db)
        .await?;
    match landed.and_then(|l| ObjectId::from_hex(&l).ok()) {
        Some(l) if l != x => on_branch(hub, project, l, tip).await,
        _ => Ok(false),
    }
}

/// Is real snapshot `x` the branch tip `tip` or below it? From the derived
/// commit graph (S12; the tip is derived first if the deriver has not yet),
/// else by walking.
async fn on_branch(hub: &Arc<Hub>, project: i64, x: ObjectId, tip: ObjectId) -> Result<bool> {
    if x == tip {
        return Ok(true);
    }
    let ask = || {
        crate::derive::read(hub, project, move |g| {
            Ok(match g.row(&tip)? {
                None => None,
                // Everything below a derived snapshot is derived.
                Some(_) => Some(g.row(&x)?.is_some() && g.is_ancestor(x, tip)?),
            })
        })
    };
    if let Some(a) = ask().await? {
        return Ok(a);
    }
    crate::derive::ensure(hub, project, tip).await?;
    match ask().await? {
        Some(a) => Ok(a),
        // Another server's deriver holds the project.
        None => crate::sync::is_ancestor(hub, project, x, tip).await,
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

