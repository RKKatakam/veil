//! Request-path caches (`docs/HUB.md` §13.14;
//! `docs/design/server/storage-and-cost.md` §4, §5): sessions, permissions,
//! snapshot resolution and branch tips, in each server's memory.
//!
//! **A cache never serves a decision a permission change has made stale,
//! on any server.** Sessions and permissions are versioned by the
//! **access epochs** in the database (`migrations/0006_access_epochs.sql`):
//!
//! * `(0, person)`: the person's sessions, devices, admin rights, groups and
//!   device bars; `(project, 0)`: the project's accepted policy, bindings and
//!   groups. Database triggers bump them in the transaction of every write to
//!   those tables, whichever route (or operator) makes it.
//! * **Every request reads its epochs** ([`read_epochs`], one statement of
//!   two primary-key lookups) before it uses a cached session or permission,
//!   and an entry is used only if it was built under exactly those epochs.
//!   An entry is built by reading the epochs *first* and the records after
//!   (or in the same statement), so it is never tagged with an epoch set
//!   after its data was read. Epochs are random values, new at each change
//!   (never a count): only equality is compared.
//!   So a cached answer is the answer the database gives at the moment of
//!   the request: **staleness is zero.** A change committed before a request
//!   starts is seen by that request, on every server.
//! * Expired sessions are refused from the cache by their expiry; nothing is
//!   cached for an unknown token, a missing project or a refused device.
//!
//! **Snapshot resolution** caches only facts that never change: that a
//! snapshot is committed history (rows are never deleted), a viewer's
//! projection of a real snapshot under a view key (the key is a hash of
//! what the viewer may read, and a memo row is never rewritten), and a real
//! snapshot a projected id stands for. Every answer is still projected
//! for the asker's current view, so none of them grants anything.
//!
//! **Branch tips** are not permissions (each viewer gets them projected for
//! their own, current view). Each server keeps a project's branch rows for
//! at most [`TIPS_TTL`]; every push sends a notice (`NOTIFY`, when the
//! database delivers notices) that makes every server drop its copy, so a
//! pull may see a tip at most that old. A push never trusts the cache: it
//! compares and swaps against the database.

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use veil_core::{cache::LruCache, ObjectId};

use crate::{
    auth::Person,
    error::Result,
    perm::{Project, Viewer},
};

/// How long a server serves a project's branch rows without reading them
/// again, when no notice of a push arrived (`phase-2-thin-clients.md` §5.1).
pub const TIPS_TTL: Duration = Duration::from_millis(100);
/// The notice channel every push notifies, with the project's id.
pub const TIPS_CHANNEL: &str = "veil_tips";

/// The access epochs one request read ([`read_epochs`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Epochs {
    /// The signed-in person's epoch (0 for anyone on Earth).
    pub person: i64,
    /// The project the request names, and its epoch, when it was read.
    pub project: Option<(i64, i64)>,
}

pub struct SessionEntry {
    pub person: Person,
    pub expires_at: i64,
    /// The person's epoch the entry was built under.
    pub epoch: i64,
}

pub struct ProjectEntry {
    pub project: Project,
    pub epoch: i64,
}

pub struct ViewerEntry {
    pub viewer: Viewer,
    /// An admin barred this device from the project (BUG-843).
    pub barred: bool,
    pub project_epoch: i64,
    pub person_epoch: i64,
}

/// A project's branch rows: `(name, target)` as stored.
pub type BranchRows = Arc<Vec<(String, String)>>;

#[derive(Default)]
struct TipsSlot {
    /// Bumped by every notice for the project: rows read before a notice
    /// are never stored after it.
    generation: u64,
    /// The rows, when they were read, and what they weigh.
    rows: Option<(Instant, BranchRows, usize)>,
    /// The read in flight, if one started within [`TIPS_TTL`]: others wait
    /// for it instead of reading too (under load, a herd of readers made
    /// every read slower than the expiry, so nothing was ever kept).
    reading: Option<(Instant, Arc<tokio::sync::Notify>)>,
}

/// What [`Caches::tips`] says to do.
pub enum TipsLookup {
    /// The rows, read within [`TIPS_TTL`] and no notice since.
    Hit(BranchRows),
    /// Another request is reading them: wait for its notice, then ask again.
    Wait(Arc<tokio::sync::Notify>),
    /// Read them, then [`Caches::put_tips`] (or [`Caches::tips_failed`]).
    Read(TipsRead),
}

/// One read of a project's branch rows, in flight.
pub struct TipsRead {
    generation: (u64, u64),
    done: Arc<tokio::sync::Notify>,
}

#[derive(Default)]
struct Tips {
    slots: HashMap<i64, TipsSlot>,
    /// Bumped when every slot is dropped (a lost notice connection, a full
    /// map).
    generation: u64,
    /// What the kept rows weigh in all ([`TIPS_BUDGET`]).
    bytes: usize,
    /// Rows kept, oldest first: expired ones are freed as time passes, and
    /// the oldest go first when the budget is full (BUG-913).
    order: std::collections::VecDeque<(Instant, i64)>,
}

impl Tips {
    /// Free the rows of `project` read at `at`, if they are still the kept ones.
    fn free(&mut self, project: i64, at: Option<Instant>) {
        if let Some(slot) = self.slots.get_mut(&project) {
            if let Some((read, _, w)) = &slot.rows {
                if at.is_none_or(|at| *read == at) {
                    self.bytes -= *w;
                    slot.rows = None;
                }
            }
        }
    }

    /// Free expired rows, then the oldest until `room` more bytes fit.
    fn sweep(&mut self, room: usize) {
        while let Some(&(at, project)) = self.order.front() {
            if at.elapsed() < TIPS_TTL && self.bytes + room <= TIPS_BUDGET {
                break;
            }
            self.order.pop_front();
            self.free(project, Some(at));
        }
    }
}

/// Most projects whose tips one server holds; past it, all are dropped.
const MAX_TIP_PROJECTS: usize = 100_000;

/// Byte budgets of the caches (BUG-913: every entry is weighed by what it
/// holds, never counted as one, since its size is the asker's to choose).
pub const SESSIONS_BUDGET: usize = 16 << 20;
pub const PROJECTS_BUDGET: usize = 32 << 20;
pub const VIEWERS_BUDGET: usize = 32 << 20;
pub const SNAPSHOTS_BUDGET: usize = 64 << 20;
pub const TIPS_BUDGET: usize = 32 << 20;

/// What one entry costs the LRU itself: its key, slot and recency record.
const ENTRY: usize = 192;
/// One snapshot-resolution entry.
const SNAPSHOT_ENTRY: usize = ENTRY + 32;

/// A heap string: its header, its bytes (rounded as the allocator does) and
/// the allocation's own overhead.
fn string_bytes(s: &str) -> usize {
    24 + s.len().next_multiple_of(16) + 16
}

/// What a parsed policy holds.
fn policy_bytes(p: &veil_core::hub::access::AccessPolicy) -> usize {
    let rule = |r: &veil_core::hub::access::AccessRule| {
        64 + string_bytes(&r.path) + 16 + r.names.iter().map(|n| string_bytes(n)).sum::<usize>()
    };
    24 + p.rules.iter().map(rule).sum::<usize>() + 24 + p.warnings.iter().map(|w| string_bytes(w)).sum::<usize>()
}

/// What a cached project holds: its name, accepted policy (as text and
/// parsed) and bindings.
pub fn project_bytes(p: &Project) -> usize {
    ENTRY
        + string_bytes(&p.name)
        + string_bytes(&p.default_branch)
        + string_bytes(&p.policy_text)
        + policy_bytes(&p.policy)
        + p.bindings.keys().map(|k| string_bytes(k) + 48).sum::<usize>()
}

/// What a cached view holds: its group set (a hash table of ids).
fn viewer_bytes(v: &Viewer) -> usize {
    let buckets = (v.groups.capacity() * 8 / 7 + 1).next_power_of_two();
    ENTRY + 96 + buckets * 9
}

fn session_bytes(e: &SessionEntry) -> usize {
    let agent = e.person.agent.as_ref().map_or(0, |a| {
        let t = &a.attribution;
        ENTRY
            + string_bytes(&t.agent)
            + t.task.as_ref().map_or(0, |x| string_bytes(x))
            + t.prompt.as_ref().map_or(0, |x| string_bytes(x))
            + t.run.as_ref().map_or(0, |x| string_bytes(x))
            + a.only.as_ref().map_or(0, |o| o.iter().map(|x| string_bytes(x) + 24).sum())
    });
    ENTRY + 64 + string_bytes(&e.person.name) + string_bytes(&e.person.device_key) + agent
}

/// What a project's branch rows hold.
fn rows_bytes(rows: &[(String, String)]) -> usize {
    64 + rows.iter().map(|(n, t)| string_bytes(n) + string_bytes(t)).sum::<usize>()
}

pub struct Caches {
    sessions: LruCache<Arc<SessionEntry>>,
    projects: LruCache<Arc<ProjectEntry>>,
    viewers: LruCache<Arc<ViewerEntry>>,
    /// Committed snapshots, projection memos and resolutions, by [`key`].
    snapshots: LruCache<ObjectId>,
    tips: Mutex<Tips>,
    /// Whether the database delivers this server's notices (checked when the
    /// listener starts); without them, tips expire after [`TIPS_TTL`] only.
    pub notices: AtomicBool,
    /// Request-path counters, for the benchmarks.
    pub stats: Stats,
}

/// Counters a benchmark reads (`veil-server` prints them on `SIGUSR1`).
#[derive(Default)]
pub struct Stats {
    pub session_hits: AtomicU64,
    pub session_misses: AtomicU64,
    pub permission_hits: AtomicU64,
    pub permission_misses: AtomicU64,
    pub tips_hits: AtomicU64,
    pub tips_misses: AtomicU64,
}

/// A cache key: a hash of a tag and length-prefixed parts, so keys of
/// different kinds never meet.
fn key(tag: &str, parts: &[&[u8]]) -> ObjectId {
    let mut h = blake3::Hasher::new_derive_key("veil-server request cache 2026-11-07");
    h.update(tag.as_bytes());
    for p in parts {
        h.update(&(p.len() as u64).to_le_bytes());
        h.update(p);
    }
    ObjectId(*h.finalize().as_bytes())
}

impl Default for Caches {
    fn default() -> Self {
        Caches {
            sessions: LruCache::new(SESSIONS_BUDGET),
            projects: LruCache::new(PROJECTS_BUDGET),
            viewers: LruCache::new(VIEWERS_BUDGET),
            snapshots: LruCache::new(SNAPSHOTS_BUDGET),
            tips: Mutex::new(Tips::default()),
            notices: AtomicBool::new(false),
            stats: Stats::default(),
        }
    }
}

impl Caches {
    // ---- sessions and permissions: checked against the epochs -----------------

    pub fn session(&self, token_hash: &str) -> Option<Arc<SessionEntry>> {
        self.sessions.get(&key("session", &[token_hash.as_bytes()]))
    }

    pub fn put_session(&self, token_hash: &str, e: SessionEntry) {
        let weight = session_bytes(&e);
        self.sessions.insert(key("session", &[token_hash.as_bytes()]), Arc::new(e), weight);
    }

    pub fn project(&self, name: &str) -> Option<Arc<ProjectEntry>> {
        self.projects.get(&key("project", &[name.as_bytes()]))
    }

    pub fn put_project(&self, e: ProjectEntry) -> Arc<ProjectEntry> {
        let e = Arc::new(e);
        let weight = project_bytes(&e.project);
        self.projects.insert(key("project", &[e.project.name.as_bytes()]), e.clone(), weight);
        e
    }

    pub fn viewer(&self, project: i64, person: &Person) -> Option<Arc<ViewerEntry>> {
        self.viewers.get(&viewer_key(project, person))
    }

    pub fn put_viewer(&self, project: i64, person: &Person, e: ViewerEntry) -> Arc<ViewerEntry> {
        let weight = viewer_bytes(&e.viewer) + string_bytes(&person.device_key);
        let e = Arc::new(e);
        self.viewers.insert(viewer_key(project, person), e.clone(), weight);
        e
    }

    // ---- snapshot resolution: facts that never change ---------------------------

    /// Is `id` committed history of `project` (known to this server)?
    pub fn committed(&self, project: i64, id: &ObjectId) -> bool {
        self.snapshots.get(&key("committed", &[&project.to_le_bytes(), &id.0])).is_some()
    }

    pub fn put_committed(&self, project: i64, id: &ObjectId) {
        self.snapshots.insert(key("committed", &[&project.to_le_bytes(), &id.0]), *id, SNAPSHOT_ENTRY);
    }

    /// The projection of real snapshot `real` under `view_key`, if known.
    pub fn memo(&self, project: i64, view_key: &str, real: &ObjectId) -> Option<ObjectId> {
        self.snapshots.get(&key("memo", &[&project.to_le_bytes(), view_key.as_bytes(), &real.0]))
    }

    /// Record that `real` projects to `projected` under `view_key` (a row of
    /// `projections` as stored), and so that, for that view, `projected`
    /// stands for `real`.
    pub fn put_memo(&self, project: i64, view_key: &str, real: &ObjectId, projected: &ObjectId) {
        self.snapshots.insert(key("memo", &[&project.to_le_bytes(), view_key.as_bytes(), &real.0]), *projected, SNAPSHOT_ENTRY);
        self.snapshots.insert(key("resolved", &[&project.to_le_bytes(), view_key.as_bytes(), &projected.0]), *real, SNAPSHOT_ENTRY);
    }

    /// A real snapshot that projects to `id` under `view_key` (`sync::resolve`):
    /// for a viewer of that view, any of them gives the same tree and
    /// history. Never another view's (BUG-915): the same projected id can
    /// stand for other real snapshots in another view.
    pub fn resolved(&self, project: i64, view_key: &str, id: &ObjectId) -> Option<ObjectId> {
        self.snapshots.get(&key("resolved", &[&project.to_le_bytes(), view_key.as_bytes(), &id.0]))
    }

    // ---- branch tips: dropped on notice, expire after TIPS_TTL ------------------

    /// The project's branch rows, if read within [`TIPS_TTL`] and no notice
    /// came since; otherwise a read to wait for, or one to make.
    pub fn tips(&self, project: i64) -> TipsLookup {
        let mut t = self.tips.lock().unwrap();
        t.sweep(0);
        let global = t.generation;
        let slot = t.slots.entry(project).or_default();
        if let Some((at, rows, _)) = &slot.rows {
            if at.elapsed() < TIPS_TTL {
                self.stats.tips_hits.fetch_add(1, Ordering::Relaxed);
                return TipsLookup::Hit(rows.clone());
            }
        }
        if let Some((started, done)) = &slot.reading {
            if started.elapsed() < TIPS_TTL {
                return TipsLookup::Wait(done.clone());
            }
        }
        self.stats.tips_misses.fetch_add(1, Ordering::Relaxed);
        let done = Arc::new(tokio::sync::Notify::new());
        slot.reading = Some((Instant::now(), done.clone()));
        TipsLookup::Read(TipsRead {
            generation: (global, slot.generation),
            done,
        })
    }

    /// Is `done`'s read of `project` still in flight?
    pub fn tips_reading(&self, project: i64, done: &Arc<tokio::sync::Notify>) -> bool {
        let t = self.tips.lock().unwrap();
        t.slots.get(&project).and_then(|s| s.reading.as_ref()).is_some_and(|(_, d)| Arc::ptr_eq(d, done))
    }

    /// Keep rows read from the database (the read started at `read_at`)
    /// unless a notice for the project came since the read was handed out;
    /// wake whoever waits for it.
    pub fn put_tips(&self, project: i64, read: TipsRead, read_at: Instant, rows: Vec<(String, String)>) {
        let mut t = self.tips.lock().unwrap();
        let fits = t.generation == read.generation.0 && t.slots.len() <= MAX_TIP_PROJECTS;
        if t.slots.len() > MAX_TIP_PROJECTS {
            Self::drop_slots(&mut t);
        }
        let weight = rows_bytes(&rows);
        let fresh = t.slots.get(&project).is_none_or(|s| s.generation == read.generation.1);
        // Rows heavier than the whole budget are not kept (BUG-913).
        if fits && fresh && weight <= TIPS_BUDGET {
            t.free(project, None);
            t.sweep(weight);
            // Its age counts from before the read: never older than TIPS_TTL.
            t.slots.entry(project).or_default().rows = Some((read_at, Arc::new(rows), weight));
            t.bytes += weight;
            t.order.push_back((read_at, project));
        }
        let slot = t.slots.entry(project).or_default();
        Self::finish(slot, &read.done);
    }

    /// The read failed: wake whoever waits for it (one of them reads again).
    pub fn tips_failed(&self, project: i64, read: TipsRead) {
        let mut t = self.tips.lock().unwrap();
        let slot = t.slots.entry(project).or_default();
        Self::finish(slot, &read.done);
    }

    fn finish(slot: &mut TipsSlot, done: &Arc<tokio::sync::Notify>) {
        if slot.reading.as_ref().is_some_and(|(_, d)| Arc::ptr_eq(d, done)) {
            slot.reading = None;
        }
        done.notify_waiters();
    }

    fn drop_slots(t: &mut Tips) {
        for slot in t.slots.values() {
            if let Some((_, d)) = &slot.reading {
                d.notify_waiters();
            }
        }
        t.slots.clear();
        t.order.clear();
        t.bytes = 0;
        t.generation += 1;
    }

    /// A push moved a branch of `project` (a notice, or this server's own).
    pub fn tips_changed(&self, project: i64) {
        let mut t = self.tips.lock().unwrap();
        t.free(project, None);
        t.slots.entry(project).or_default().generation += 1;
    }

    /// Notices may have been missed (the listener's connection was lost).
    pub fn drop_all_tips(&self) {
        Self::drop_slots(&mut self.tips.lock().unwrap());
    }
}

fn viewer_key(project: i64, person: &Person) -> ObjectId {
    key("viewer", &[&project.to_le_bytes(), &person.id.to_le_bytes(), person.device_key.as_bytes()])
}

/// The access epochs of `person` (0: anyone on Earth) and of `project`, in
/// one statement. Rows that do not exist yet read as 0.
pub async fn read_epochs(db: &sqlx::PgPool, person: i64, project: Option<i64>) -> Result<Epochs> {
    let (pe, je): (i64, i64) = sqlx::query_as(
        "SELECT COALESCE((SELECT epoch FROM access_epochs WHERE project_id = 0 AND person_id = $1), 0), \
         COALESCE((SELECT epoch FROM access_epochs WHERE project_id = $2 AND person_id = 0), 0)",
    )
    .bind(person)
    .bind(project.unwrap_or(-1))
    .fetch_one(db)
    .await?;
    Ok(Epochs {
        person: pe,
        project: project.map(|p| (p, je)),
    })
}

/// Listen for push notices on `TIPS_CHANNEL`, dropping each project's tips
/// as they arrive, until `stop`. First checks that the database delivers
/// them (YugabyteDB does not unless `ysql_yb_enable_listen_notify` is on):
/// if it does not, tips only expire after [`TIPS_TTL`].
pub async fn listen(hub: Arc<crate::Hub>, mut stop: tokio::sync::watch::Receiver<bool>) {
    let mut listener = match start_listener(&hub).await {
        Some(l) => l,
        None => {
            eprintln!("veil-server: the database does not deliver notices; branch tips expire after {TIPS_TTL:?} instead");
            return;
        }
    };
    hub.caches.notices.store(true, Ordering::SeqCst);
    loop {
        let n = tokio::select! {
            n = listener.try_recv() => n,
            _ = stop.changed() => return,
        };
        match n {
            Ok(Some(n)) => match n.payload().parse::<i64>() {
                Ok(p) => hub.caches.tips_changed(p),
                Err(_) => hub.caches.drop_all_tips(),
            },
            // The connection was lost: notices may be missing until it is
            // back (try_recv reconnects and listens again).
            Ok(None) => hub.caches.drop_all_tips(),
            Err(_) => {
                hub.caches.drop_all_tips();
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }
}

async fn start_listener(hub: &crate::Hub) -> Option<sqlx::postgres::PgListener> {
    let mut l = sqlx::postgres::PgListener::connect_with(&hub.db).await.ok()?;
    l.listen(TIPS_CHANNEL).await.ok()?;
    // Does a notice come back? (`0` names no project.)
    sqlx::query("SELECT pg_notify($1, '0')").bind(TIPS_CHANNEL).execute(&hub.db).await.ok()?;
    match tokio::time::timeout(Duration::from_secs(5), l.try_recv()).await {
        Ok(Ok(Some(n))) if n.payload() == "0" => Some(l),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn person(id: i64, device: &str) -> Person {
        Person {
            id,
            name: format!("p{id}"),
            device_key: device.into(),
            agent: None,
        }
    }

    #[test]
    fn keys_of_different_kinds_never_meet() {
        let id = ObjectId::hash(b"x");
        assert_ne!(key("memo", &[b"ab", b"c"]), key("memo", &[b"a", b"bc"]));
        assert_ne!(key("committed", &[&id.0]), key("resolved", &[&id.0]));
        let c = Caches::default();
        c.put_committed(1, &id);
        assert!(c.committed(1, &id));
        assert!(!c.committed(2, &id), "projects never share entries");
        assert_eq!(c.resolved(1, "k", &id), None);
        // A view's resolution is its own (BUG-915).
        let real = ObjectId::hash(b"real");
        c.put_memo(1, "devs", &real, &id);
        assert_eq!(c.resolved(1, "devs", &id), Some(real));
        assert_eq!(c.resolved(1, "finance", &id), None, "another view's real snapshot is never answered");
    }

    #[test]
    fn viewers_are_per_device() {
        let c = Caches::default();
        let e = || ViewerEntry {
            viewer: Viewer::default(),
            barred: false,
            project_epoch: 0,
            person_epoch: 0,
        };
        c.put_viewer(1, &person(5, "aa"), e());
        assert!(c.viewer(1, &person(5, "aa")).is_some());
        assert!(c.viewer(1, &person(5, "bb")).is_none(), "a barred device must not share its person's entry");
        assert!(c.viewer(2, &person(5, "aa")).is_none());
    }

    fn read(c: &Caches, p: i64) -> TipsRead {
        match c.tips(p) {
            TipsLookup::Read(r) => r,
            _ => panic!("expected to read"),
        }
    }

    /// The cached rows, if any (a read this starts is ended at once).
    fn rows(c: &Caches, p: i64) -> Option<BranchRows> {
        match c.tips(p) {
            TipsLookup::Hit(r) => Some(r),
            TipsLookup::Read(r) => {
                c.tips_failed(p, r);
                None
            }
            TipsLookup::Wait(_) => None,
        }
    }

    #[test]
    fn a_notice_beats_a_read_that_started_before_it() {
        let c = Caches::default();
        let r = read(&c, 7);
        let at = Instant::now();
        c.tips_changed(7);
        c.put_tips(7, r, at, vec![("main".into(), "old".into())]);
        assert!(rows(&c, 7).is_none(), "rows read before the notice are not kept");
        let r = read(&c, 7);
        c.put_tips(7, r, Instant::now(), vec![("main".into(), "new".into())]);
        assert_eq!(rows(&c, 7).unwrap()[0].1, "new");
        // A lost listener connection drops everything, and reads in flight.
        let r = read(&c, 8);
        c.drop_all_tips();
        c.put_tips(8, r, Instant::now(), vec![]);
        assert!(rows(&c, 7).is_none() && rows(&c, 8).is_none());
    }

    #[test]
    fn one_read_at_a_time_and_tips_expire() {
        let c = Caches::default();
        let r = read(&c, 1);
        let TipsLookup::Wait(done) = c.tips(1) else { panic!("a second asker waits") };
        assert!(c.tips_reading(1, &done));
        c.put_tips(1, r, Instant::now() - TIPS_TTL, vec![]);
        assert!(!c.tips_reading(1, &done), "the read finished");
        assert!(rows(&c, 1).is_none(), "rows as old as TIPS_TTL are read again");
        let r = read(&c, 1);
        c.tips_failed(1, r);
        assert!(matches!(c.tips(1), TipsLookup::Read(_)), "after a failed read, the next asker reads");
    }
}
