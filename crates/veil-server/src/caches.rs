//! Request-path caches (`docs/HUB.md` §13.13;
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
//!   (or in the same statement), so it is never tagged newer than its data.
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
    rows: Option<(Instant, BranchRows)>,
}

#[derive(Default)]
struct Tips {
    slots: HashMap<i64, TipsSlot>,
    /// Bumped when every slot is dropped (a lost notice connection, a full
    /// map).
    generation: u64,
}

/// Most projects whose tips one server holds; past it, all are dropped.
const MAX_TIP_PROJECTS: usize = 100_000;

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
            sessions: LruCache::new(100_000),
            // By bytes: a project's accepted policy may be long.
            projects: LruCache::new(64 << 20),
            viewers: LruCache::new(100_000),
            snapshots: LruCache::new(500_000),
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
        self.sessions.insert(key("session", &[token_hash.as_bytes()]), Arc::new(e), 1);
    }

    pub fn project(&self, name: &str) -> Option<Arc<ProjectEntry>> {
        self.projects.get(&key("project", &[name.as_bytes()]))
    }

    pub fn put_project(&self, e: ProjectEntry) -> Arc<ProjectEntry> {
        let e = Arc::new(e);
        let weight = 1024 + 3 * e.project.policy_text.len() + 64 * e.project.bindings.len();
        self.projects.insert(key("project", &[e.project.name.as_bytes()]), e.clone(), weight);
        e
    }

    pub fn viewer(&self, project: i64, person: &Person) -> Option<Arc<ViewerEntry>> {
        self.viewers.get(&viewer_key(project, person))
    }

    pub fn put_viewer(&self, project: i64, person: &Person, e: ViewerEntry) -> Arc<ViewerEntry> {
        let e = Arc::new(e);
        self.viewers.insert(viewer_key(project, person), e.clone(), 1);
        e
    }

    // ---- snapshot resolution: facts that never change ---------------------------

    /// Is `id` committed history of `project` (known to this server)?
    pub fn committed(&self, project: i64, id: &ObjectId) -> bool {
        self.snapshots.get(&key("committed", &[&project.to_le_bytes(), &id.0])).is_some()
    }

    pub fn put_committed(&self, project: i64, id: &ObjectId) {
        self.snapshots.insert(key("committed", &[&project.to_le_bytes(), &id.0]), *id, 1);
    }

    /// The projection of real snapshot `real` under `view_key`, if known.
    pub fn memo(&self, project: i64, view_key: &str, real: &ObjectId) -> Option<ObjectId> {
        self.snapshots.get(&key("memo", &[&project.to_le_bytes(), view_key.as_bytes(), &real.0]))
    }

    /// Record that `real` projects to `projected` under `view_key` (a row of
    /// `projections` as stored), and that `projected` stands for `real`.
    pub fn put_memo(&self, project: i64, view_key: &str, real: &ObjectId, projected: &ObjectId) {
        self.snapshots.insert(key("memo", &[&project.to_le_bytes(), view_key.as_bytes(), &real.0]), *projected, 1);
        self.put_resolved(project, projected, real);
    }

    /// A real snapshot projected id `id` stands for (`sync::resolve`).
    pub fn resolved(&self, project: i64, id: &ObjectId) -> Option<ObjectId> {
        self.snapshots.get(&key("resolved", &[&project.to_le_bytes(), &id.0]))
    }

    pub fn put_resolved(&self, project: i64, id: &ObjectId, real: &ObjectId) {
        self.snapshots.insert(key("resolved", &[&project.to_le_bytes(), &id.0]), *real, 1);
    }

    // ---- branch tips: dropped on notice, expire after TIPS_TTL ------------------

    /// The project's branch rows, if read within [`TIPS_TTL`] and no notice
    /// came since; otherwise the generation to give [`Caches::put_tips`].
    pub fn tips(&self, project: i64) -> std::result::Result<BranchRows, (u64, u64)> {
        let mut t = self.tips.lock().unwrap();
        let global = t.generation;
        let slot = t.slots.entry(project).or_default();
        match &slot.rows {
            Some((at, rows)) if at.elapsed() < TIPS_TTL => {
                self.stats.tips_hits.fetch_add(1, Ordering::Relaxed);
                Ok(rows.clone())
            }
            _ => {
                self.stats.tips_misses.fetch_add(1, Ordering::Relaxed);
                Err((global, slot.generation))
            }
        }
    }

    /// Keep rows read from the database (the read started at `read_at`)
    /// unless a notice for the project came since `generation`.
    pub fn put_tips(&self, project: i64, generation: (u64, u64), read_at: Instant, rows: Vec<(String, String)>) {
        let mut t = self.tips.lock().unwrap();
        if t.generation != generation.0 {
            return;
        }
        if t.slots.len() > MAX_TIP_PROJECTS {
            t.slots.clear();
            t.generation += 1;
            return;
        }
        let slot = t.slots.entry(project).or_default();
        if slot.generation == generation.1 {
            // Its age counts from before the read: never older than TIPS_TTL.
            slot.rows = Some((read_at, Arc::new(rows)));
        }
    }

    /// A push moved a branch of `project` (a notice, or this server's own).
    pub fn tips_changed(&self, project: i64) {
        let mut t = self.tips.lock().unwrap();
        let slot = t.slots.entry(project).or_default();
        slot.generation += 1;
        slot.rows = None;
    }

    /// Notices may have been missed (the listener's connection was lost).
    pub fn drop_all_tips(&self) {
        let mut t = self.tips.lock().unwrap();
        t.slots.clear();
        t.generation += 1;
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
        assert_eq!(c.resolved(1, &id), None);
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

    #[test]
    fn a_notice_beats_a_read_that_started_before_it() {
        let c = Caches::default();
        let g = c.tips(7).unwrap_err();
        let at = Instant::now();
        c.tips_changed(7);
        c.put_tips(7, g, at, vec![("main".into(), "old".into())]);
        assert!(c.tips(7).is_err(), "rows read before the notice are not kept");
        let g = c.tips(7).unwrap_err();
        c.put_tips(7, g, Instant::now(), vec![("main".into(), "new".into())]);
        assert_eq!(c.tips(7).unwrap()[0].1, "new");
        // A lost listener connection drops everything, and reads in flight.
        let g = c.tips(8).unwrap_err();
        c.drop_all_tips();
        c.put_tips(8, g, Instant::now(), vec![]);
        assert!(c.tips(7).is_err() && c.tips(8).is_err());
    }

    #[test]
    fn tips_expire() {
        let c = Caches::default();
        let g = c.tips(1).unwrap_err();
        c.put_tips(1, g, Instant::now() - TIPS_TTL, vec![]);
        assert!(c.tips(1).is_err(), "rows as old as TIPS_TTL are read again");
    }
}
