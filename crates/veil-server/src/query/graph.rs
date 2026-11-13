//! The viewer graph (milestone S13): the commit graph of one viewer's
//! projected history (`docs/HUB.md` §13.4), as the viewer's own copy of the
//! project would derive it.
//!
//! **Why not the real graph.** Real generations count hidden snapshots (a
//! hidden change dated far ahead raises everything built on it), and a walk
//! of real history between two visible snapshots costs one step per hidden
//! one (phase-3 design §10, the two items S12 left to S13). So every query
//! walks this graph instead: its rows are a function of the viewer's
//! projected snapshots alone, its walks visit only snapshots the viewer
//! sees, and its order is the order their copy has.
//!
//! **A row** per (project, view key, projected snapshot): the generation
//! (the client's corrected commit date, timestamps clamped as in
//! [`crate::derive::graph`]), the first-parent depth, the parents
//! (projected ids), the embargo flags, the first-parent jump table (the
//! first parent, then the ancestors at the multiple of 16, 256 and 4096 just
//! below), `down` (the nearest snapshot below on the first-parent line that
//! does not have exactly one parent: a merge, or the root) and `real`, one
//! real snapshot of the viewer's history that it projects (where its trees
//! come from). Admins have one too (view key `admin`, `real` = itself), so
//! every viewer runs the same code.
//!
//! **Filled** from the projection memo, in two parts (BUG-1943, BUG-1949):
//!
//! * **the rows** ([`extend_rows`]): one read of each new snapshot and a
//!   few statements, so their cost is what is new and nothing else. Every
//!   query but the two that read file history needs only these, and waits
//!   for them ([`ensure`]) until its deadline;
//! * **the file history** of those rows ([`extend`], S14: a diff of every
//!   new snapshot's trees), which marks each row `files` once its file
//!   history and that of everything below it is written. Blame and the
//!   history of a path wait for it ([`ensure_files`]); nothing else does.
//!
//! Both run eagerly: a landing queues the file history's fill, which
//! writes the rows it finds missing with it (`derive::memo_tips`); a push
//! of many snapshots queues the rows' fill at once, and that one the file
//! history's (`derive::rows_of_tips`). And a query that names a tip not
//! filled yet fills its rows: by one background fill of each part per view
//! key. Rows are written parents
//! first, each insert `ON CONFLICT DO NOTHING`: a row's presence means its
//! ancestors' are present, and two servers extending at once write the same
//! rows (`real` may name either of two real snapshots with one projection;
//! both have the same projected trees).
//!
//! **Walks** ([`G`]) count the rows and objects they read
//! ([`G::work`]): a function of the viewer's graph only, which the
//! projection-equivalence test compares with the copy's.

use std::{
    cell::{Cell, RefCell},
    collections::{BinaryHeap, HashMap, HashSet},
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

use tokio::sync::watch;

use axum::http::StatusCode;
use veil_core::{cache::LruCache, id::ChangeId, object::Snapshot, ObjectId};

use super::{files::Fill as FileFill, trees::Trees};
use crate::{
    derive::{
        graph::{FLAG_EMBARGO, FLAG_EMBARGO_LINE},
        Cx,
    },
    error::{Error, Result},
    perm::{Project, Viewer},
    sync::{self, Source},
    Hub,
};

/// The universal root's id (computed once).
pub fn root() -> ObjectId {
    static ROOT: OnceLock<ObjectId> = OnceLock::new();
    *ROOT.get_or_init(sync::root_snapshot_id)
}

/// The jump-table levels after the first parent (as the real graph's).
const LEVELS: [i64; 3] = [16, 256, 4096];

/// Rows per insert statement.
const ROWS_PER_STATEMENT: usize = 500;

/// One snapshot of a viewer's graph.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VRow {
    pub generation: i64,
    pub depth: i64,
    pub parents: Vec<ObjectId>,
    pub flags: i32,
    /// `[first parent, at multiple of 16, of 256, of 4096]`; empty for the root.
    pub skip: Vec<ObjectId>,
    /// The nearest snapshot below on the first-parent line that does not
    /// have exactly one parent (a merge, or the root).
    pub down: ObjectId,
    /// A real snapshot this one projects.
    pub real: ObjectId,
}

impl VRow {
    pub fn root() -> VRow {
        VRow {
            generation: 0,
            depth: 0,
            parents: Vec::new(),
            flags: 0,
            skip: Vec::new(),
            down: root(),
            real: root(),
        }
    }

    /// The row of projected snapshot `s`, whose parents' rows are
    /// `parents` (in order), projecting real snapshot `real`. The same
    /// arithmetic as the real graph (`derive::graph::GraphRow::compute`).
    pub fn compute(s: &Snapshot, parents: &[(ObjectId, Arc<VRow>)], real: ObjectId) -> VRow {
        // `veil_core`'s one arithmetic, the clients' too (BUG-1316).
        let generation = veil_core::graph_index::generation(s.timestamp, parents.iter().map(|(_, p)| p.generation as u64)) as i64;
        let mut flags = if s.embargo.is_some() { FLAG_EMBARGO | FLAG_EMBARGO_LINE } else { 0 };
        for (_, p) in parents {
            flags |= p.flags & FLAG_EMBARGO_LINE;
        }
        let (skip, depth, down) = match parents.first() {
            None => (Vec::new(), 0, root()),
            Some((p0, p)) => {
                let mut skip = vec![*p0];
                for (i, level) in LEVELS.iter().enumerate() {
                    let at = if p.depth % level == 0 { *p0 } else { p.skip.get(i + 1).copied().unwrap_or(*p0) };
                    skip.push(at);
                }
                let down = if p.parents.len() == 1 { p.down } else { *p0 };
                (skip, p.depth.saturating_add(1), down)
            }
        };
        VRow {
            generation,
            depth,
            parents: parents.iter().map(|(id, _)| *id).collect(),
            flags,
            skip,
            down,
            real,
        }
    }

    /// On an embargo line: withheld from every viewer until its release
    /// (S22), as the derived data withholds it.
    pub fn withheld(&self) -> bool {
        self.flags & FLAG_EMBARGO_LINE != 0
    }
}

fn bad(e: impl std::fmt::Display) -> Error {
    Error::Other(anyhow::anyhow!("viewer graph: {e}"))
}

/// A query that ran past its deadline: an error, never a shorter answer
/// (a cut that depended on time would depend on the machine, and could
/// depend on what the viewer cannot see).
pub fn too_slow() -> Error {
    Error::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "deadline",
        "the query did not finish within its deadline; try again, or ask for less",
    )
}

fn cache_key(project: i64, gc_epoch: i64, vk: &str, id: &ObjectId) -> ObjectId {
    let mut h = blake3::Hasher::new();
    h.update(b"view-graph");
    h.update(&project.to_le_bytes());
    h.update(&gc_epoch.to_le_bytes());
    h.update(&(vk.len() as u64).to_le_bytes());
    h.update(vk.as_bytes());
    h.update(&id.0);
    ObjectId(*h.finalize().as_bytes())
}

/// Return a cached [`VRow`] if already present in `hub.query.rows`.
pub fn cached_row(hub: &crate::Hub, project: i64, vk: &str, id: &ObjectId) -> Option<Arc<VRow>> {
    if *id == root() {
        return Some(Arc::new(VRow::root()));
    }
    hub.query.rows.get(&cache_key(project, hub.caches.gc_epoch(project), vk, id))
}

/// Reads of one viewer's graph, on a blocking thread.
pub struct G<'a> {
    pub cx: &'a Cx,
    pub vk: &'a str,
    local: RefCell<HashMap<ObjectId, Arc<VRow>>>,
    work: Cell<u64>,
    deadline: Option<Instant>,
}

impl<'a> G<'a> {
    pub fn new(cx: &'a Cx, vk: &'a str, deadline: Option<Instant>) -> G<'a> {
        G {
            cx,
            vk,
            local: RefCell::new(HashMap::new()),
            work: Cell::new(0),
            deadline,
        }
    }

    /// Rows and objects read so far.
    pub fn work(&self) -> u64 {
        self.work.get()
    }

    /// Count one read, and stop at the deadline.
    pub fn tick(&self) -> Result<()> {
        self.work.set(self.work.get() + 1);
        if self.deadline.is_some_and(|d| Instant::now() > d) {
            return Err(too_slow());
        }
        Ok(())
    }

    /// The row of `id`, if the viewer's graph has it.
    pub fn row(&self, id: &ObjectId) -> Result<Option<Arc<VRow>>> {
        self.tick()?;
        if *id == root() {
            return Ok(Some(Arc::new(VRow::root())));
        }
        if let Some(r) = self.local.borrow().get(id) {
            return Ok(Some(r.clone()));
        }
        let hub = self.cx.hub();
        let k = cache_key(self.cx.project(), hub.caches.gc_epoch(self.cx.project()), self.vk, id);
        if let Some(r) = hub.query.rows.get(&k) {
            self.local.borrow_mut().insert(*id, r.clone());
            return Ok(Some(r));
        }
        type Row = (i64, i64, String, i32, String, String, String);
        let hex = id.hex();
        let row: Option<Row> = self.cx.db(|| {
            sqlx::query_as(
                "SELECT generation, depth, parents, flags, skip, down_id, real_id FROM view_graph \
                 WHERE project_id = $1 AND view_key = $2 AND snapshot = $3",
            )
            .bind(self.cx.project())
            .bind(self.vk)
            .bind(&hex)
            .fetch_optional(&hub.db)
        })?;
        let Some((generation, depth, parents, flags, skip, down, real)) = row else { return Ok(None) };
        let r = Arc::new(VRow {
            generation,
            depth,
            parents: serde_json::from_str(&parents).map_err(bad)?,
            flags,
            skip: serde_json::from_str(&skip).map_err(bad)?,
            down: ObjectId::from_hex(&down).map_err(bad)?,
            real: ObjectId::from_hex(&real).map_err(bad)?,
        });
        hub.query.rows.insert(k, r.clone(), 320);
        self.local.borrow_mut().insert(*id, r.clone());
        Ok(Some(r))
    }

    /// The cached generation of `id`, if already in `local` or `hub.query.rows`.
    pub fn cached_generation(&self, id: &ObjectId) -> Option<i64> {
        if *id == root() {
            return Some(0);
        }
        if let Some(r) = self.local.borrow().get(id) {
            return Some(r.generation);
        }
        let hub = self.cx.hub();
        let k = cache_key(self.cx.project(), hub.caches.gc_epoch(self.cx.project()), self.vk, id);
        if let Some(r) = hub.query.rows.get(&k) {
            let g = r.generation;
            self.local.borrow_mut().insert(*id, r);
            return Some(g);
        }
        None
    }

    /// Keep `row` of `id`, computed and not written yet (a fill's), for
    /// the walks of this reader only (BUG-1714: `hub.query.rows` holds only
    /// rows whose `view_file_history` and `view_graph` rows are written).
    pub fn keep(&self, id: ObjectId, row: Arc<VRow>) {
        self.local.borrow_mut().insert(id, row);
    }

    /// The row of `id`, which the viewer's graph must have (a parent of a
    /// row, a step of the jump table).
    pub fn get(&self, id: &ObjectId) -> Result<Arc<VRow>> {
        self.row(id)?.ok_or_else(|| bad(format!("{} has no row", id.short())))
    }

    /// The snapshot object `id` (a projected one, or a real one).
    pub fn snapshot(&self, id: &ObjectId) -> Result<Arc<Snapshot>> {
        self.tick()?;
        Ok(self.cx.src.snapshot(id)?)
    }

    /// Which of `ids` have rows (one statement, and none for the rows
    /// this server holds); with `files`, which have rows marked as having
    /// their file history.
    fn present(&self, ids: &[ObjectId], files: bool) -> Result<HashSet<ObjectId>> {
        let hub = self.cx.hub();
        let (project, gce) = (self.cx.project(), hub.caches.gc_epoch(self.cx.project()));
        let held = |i: &ObjectId| *i == root() || (!files && hub.query.rows.get(&cache_key(project, gce, self.vk, i)).is_some());
        let mut out: HashSet<ObjectId> = ids.iter().copied().filter(held).collect();
        let ask: Vec<String> = ids.iter().filter(|i| !out.contains(i)).map(|i| i.hex()).collect();
        if ask.is_empty() {
            return Ok(out);
        }
        let found: Vec<String> = self.cx.db(|| {
            sqlx::query_scalar(
                "SELECT snapshot FROM view_graph WHERE project_id = $1 AND view_key = $2 AND snapshot = ANY($3) AND (files IS TRUE OR NOT $4)",
            )
            .bind(project)
            .bind(self.vk)
            .bind(&ask)
            .bind(files)
            .fetch_all(&hub.db)
        })?;
        out.extend(found.iter().filter_map(|s| ObjectId::from_hex(s).ok()));
        Ok(out)
    }

    /// Is the file history of each of `ids` and of everything below them
    /// written (the `files` mark of their rows)? What blame and the history
    /// of a path read; every other query reads rows and trees only.
    pub fn have_files(&self, ids: &[ObjectId]) -> Result<bool> {
        Ok(self.present(ids, true)?.len() == ids.iter().collect::<HashSet<_>>().len())
    }

    /// Write `rows` (parents before children, each with its projected
    /// snapshot's change id). With `files`, they are marked as having
    /// their file history (S14: written before them, in the same
    /// transaction), whether they were there before or not; without, rows
    /// already there are left as they are. Their change ids go first, to
    /// `view_changes` (`q/resolve`'s change id prefixes from the viewer's
    /// own rows, BUG-1317): a row of `view_graph` is never there without
    /// its change id; one written only to `view_changes` is written again
    /// by the next fill. A row without the `files` mark (the rows' own
    /// fill's, or an S13 server's: BUG-1210) answers every query but blame
    /// and the history of a path; the file history's fill marks it.
    pub(crate) async fn write_rows_tx(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        project: i64,
        vk: &str,
        rows: &[(ObjectId, Arc<VRow>, ChangeId)],
        files: bool,
    ) -> std::result::Result<(), sqlx::Error> {
        for chunk in rows.chunks(ROWS_PER_STATEMENT) {
            let ids: Vec<String> = chunk.iter().map(|(i, _, _)| i.hex()).collect();
            let gens: Vec<i64> = chunk.iter().map(|(_, r, _)| r.generation).collect();
            let depths: Vec<i64> = chunk.iter().map(|(_, r, _)| r.depth).collect();
            let parents: Vec<String> = chunk.iter().map(|(_, r, _)| serde_json::to_string(&r.parents).unwrap()).collect();
            let flags: Vec<i32> = chunk.iter().map(|(_, r, _)| r.flags).collect();
            let skips: Vec<String> = chunk.iter().map(|(_, r, _)| serde_json::to_string(&r.skip).unwrap()).collect();
            let downs: Vec<String> = chunk.iter().map(|(_, r, _)| r.down.hex()).collect();
            let reals: Vec<String> = chunk.iter().map(|(_, r, _)| r.real.hex()).collect();
            let changes: Vec<String> = chunk.iter().map(|(_, _, c)| hex::encode(c.0)).collect();
            sqlx::query(
                "INSERT INTO view_changes (project_id, view_key, change_id, snapshot, flags) \
                 SELECT $1, $2, * FROM UNNEST($3::text[], $4::text[], $5::int[]) \
                 ON CONFLICT DO NOTHING",
            )
            .bind(project)
            .bind(vk)
            .bind(&changes)
            .bind(&ids)
            .bind(&flags)
            .execute(&mut **tx)
            .await?;
            sqlx::query(match files {
                true => {
                    "INSERT INTO view_graph (project_id, view_key, snapshot, generation, depth, parents, flags, skip, down_id, real_id, files) \
                     SELECT $1, $2, *, TRUE FROM UNNEST($3::text[], $4::bigint[], $5::bigint[], $6::text[], $7::int[], $8::text[], $9::text[], $10::text[]) \
                     ON CONFLICT (project_id, view_key, snapshot) DO UPDATE SET files = TRUE WHERE view_graph.files IS NOT TRUE"
                }
                false => {
                    "INSERT INTO view_graph (project_id, view_key, snapshot, generation, depth, parents, flags, skip, down_id, real_id, files) \
                     SELECT $1, $2, *, FALSE FROM UNNEST($3::text[], $4::bigint[], $5::bigint[], $6::text[], $7::int[], $8::text[], $9::text[], $10::text[]) \
                     ON CONFLICT (project_id, view_key, snapshot) DO NOTHING"
                }
            })
            .bind(project)
            .bind(vk)
            .bind(&ids)
            .bind(&gens)
            .bind(&depths)
            .bind(&parents)
            .bind(&flags)
            .bind(&skips)
            .bind(&downs)
            .bind(&reals)
            .execute(&mut **tx)
            .await?;
        }
        Ok(())
    }

    // ---- walks ---------------------------------------------------------------

    /// The first-parent ancestor of `x` (or `x`) at depth `d`; `None` when
    /// `d` is deeper than `x`.
    pub fn at_depth(&self, x: ObjectId, d: i64) -> Result<Option<ObjectId>> {
        let mut x = x;
        let mut row = self.get(&x)?;
        if d > row.depth || d < 0 {
            return Ok(None);
        }
        while row.depth > d {
            let mut next = row.skip[0];
            for i in (1..row.skip.len()).rev() {
                if self.get(&row.skip[i])?.depth >= d {
                    next = row.skip[i];
                    break;
                }
            }
            x = next;
            row = self.get(&x)?;
        }
        Ok(Some(x))
    }

    /// Where a walk that may pass over one-parent snapshots of generation
    /// above `floor` goes from `x`: `x` itself if it is a merge, the root,
    /// or at or below `floor`; else the first snapshot down its first-parent
    /// line that is. Every snapshot passed over has one parent and a
    /// generation above `floor`. Jumps along a merge-free run (`down` says
    /// where it ends) through the jump table: a long line costs tens of
    /// rows, not one per snapshot.
    pub fn run_end(&self, x: ObjectId, floor: i64) -> Result<ObjectId> {
        let mut z = x;
        loop {
            let r = self.get(&z)?;
            if r.parents.len() != 1 || r.generation <= floor {
                return Ok(z);
            }
            let rd = self.get(&r.down)?;
            if rd.generation > floor {
                z = r.down;
                continue;
            }
            // The run crosses `floor`: go as far as stays above it. A jump
            // target above `floor` is above the run's end (which is not,
            // and generations decrease down the line), so inside the run.
            let mut next = r.parents[0];
            for i in (1..r.skip.len()).rev() {
                let t = r.skip[i];
                if self.get(&t)?.generation > floor {
                    next = t;
                    break;
                }
            }
            z = next;
        }
    }

    /// Is `a` an ancestor of `b`, or `b` itself? A walk from `b` that stops
    /// below `a`'s generation and passes over merge-free runs above it
    /// ([`G::run_end`]): `a` is never passed over (its generation is not
    /// above its own).
    pub fn is_ancestor(&self, a: ObjectId, b: ObjectId) -> Result<bool> {
        if a == b {
            return Ok(true);
        }
        let ra = self.get(&a)?;
        let rb = self.get(&b)?;
        if rb.generation <= ra.generation {
            return Ok(false);
        }
        if self.at_depth(b, ra.depth)? == Some(a) {
            return Ok(true);
        }
        let floor = ra.generation;
        let mut seen = HashSet::new();
        let mut stack = vec![b];
        while let Some(x) = stack.pop() {
            if x == a {
                return Ok(true);
            }
            if !seen.insert(x) {
                continue;
            }
            for p in self.get(&x)?.parents.clone() {
                if self.get(&p)?.generation < floor {
                    continue;
                }
                let y = self.run_end(p, floor)?;
                if self.get(&y)?.generation >= floor {
                    stack.push(y);
                }
            }
        }
        Ok(false)
    }

    /// The best common ancestors of `a` and `b` (none an ancestor of
    /// another), sorted by id: the client's paint-down by generation, where
    /// a snapshot painted by one side only is passed over while its
    /// generation is above everything the other side can reach (the other
    /// tip's generation): such snapshots can never be common, and only push
    /// their first parent.
    pub fn merge_bases(&self, a: ObjectId, b: ObjectId) -> Result<Vec<ObjectId>> {
        if self.is_ancestor(a, b)? {
            return Ok(vec![a]);
        }
        if self.is_ancestor(b, a)? {
            return Ok(vec![b]);
        }
        let (ga, gb) = (self.get(&a)?.generation, self.get(&b)?.generation);
        let mut paint = Paint::default();
        paint.push(self, a, A)?;
        paint.push(self, b, B)?;
        let mut found = Vec::new();
        while paint.live > 0 {
            let Some((_, x)) = paint.heap.pop() else { break };
            paint.popped(x);
            let mut f = paint.flags[&x];
            if f & (A | B) == A | B && f & STALE == 0 {
                found.push(x);
                f |= STALE;
                paint.set(x, f);
            }
            for p in self.get(&x)?.parents.clone() {
                let p = match f {
                    A => self.run_end(p, gb)?,
                    B => self.run_end(p, ga)?,
                    _ => p,
                };
                let pf = paint.flags.get(&p).copied().unwrap_or(0);
                if pf & f != f {
                    paint.set(p, pf | f);
                    paint.push(self, p, 0)?;
                }
            }
        }
        self.reduce(found)
    }

    /// `ids` without any that is an ancestor of another, sorted, deduplicated.
    pub fn reduce(&self, mut ids: Vec<ObjectId>) -> Result<Vec<ObjectId>> {
        ids.sort();
        ids.dedup();
        let mut out = Vec::new();
        for (i, x) in ids.iter().enumerate() {
            let mut below = false;
            for (j, y) in ids.iter().enumerate() {
                if i != j && self.is_ancestor(*x, *y)? {
                    below = true;
                    break;
                }
            }
            if !below {
                out.push(*x);
            }
        }
        Ok(out)
    }
}

const A: u8 = 1;
const B: u8 = 2;
const STALE: u8 = 4;

/// The paint-down queue: by generation, counting the queued snapshots
/// that are not below a common ancestor yet (`live`).
#[derive(Default)]
struct Paint {
    heap: BinaryHeap<(i64, ObjectId)>,
    flags: HashMap<ObjectId, u8>,
    queued: HashMap<ObjectId, usize>,
    live: usize,
}

impl Paint {
    fn stale(&self, x: &ObjectId) -> bool {
        self.flags.get(x).copied().unwrap_or(0) & STALE != 0
    }

    fn push(&mut self, g: &G, x: ObjectId, with: u8) -> Result<()> {
        if with != 0 {
            let f = self.flags.get(&x).copied().unwrap_or(0) | with;
            self.set(x, f);
        }
        let q = self.queued.entry(x).or_default();
        if *q == 0 && self.flags.get(&x).copied().unwrap_or(0) & STALE == 0 {
            self.live += 1;
        }
        *self.queued.get_mut(&x).unwrap() += 1;
        self.heap.push((g.get(&x)?.generation, x));
        Ok(())
    }

    fn popped(&mut self, x: ObjectId) {
        let q = self.queued.get_mut(&x).unwrap();
        *q -= 1;
        if *q == 0 && !self.stale(&x) {
            self.live -= 1;
        }
    }

    fn set(&mut self, x: ObjectId, f: u8) {
        let queued = self.queued.get(&x).copied().unwrap_or(0) > 0;
        if queued && !self.stale(&x) && f & STALE != 0 {
            self.live -= 1;
        }
        self.flags.insert(x, f);
    }
}

// ---- filling ---------------------------------------------------------------------

/// Run `f` on a blocking thread with `project`'s derived-data context.
pub async fn blocking<T: Send + 'static>(hub: &Arc<Hub>, project: i64, f: impl FnOnce(&Cx) -> Result<T> + Send + 'static) -> Result<T> {
    let cx = Cx {
        src: Source {
            hub: hub.clone(),
            project,
            rt: tokio::runtime::Handle::current(),
            pending: Default::default(),
            staged: None,
        },
    };
    tokio::task::spawn_blocking(move || f(&cx)).await.map_err(|e| Error::Other(e.into()))?
}

/// Make `viewer`'s graph hold `tips` (real snapshots of committed history)
/// and everything below them, **with their file history** (S14); answer
/// each tip's id in the viewer's history. The projections come from the
/// memo (`sync::projected`, which fills it first); hidden snapshots are
/// walked here once per view key, never by a query that finds their rows.
/// Blame and the history of a path call it through [`ensure_files`], a
/// landing through [`prefill`]: once per view key, in the background.
/// Rows a query's own fill wrote before it ([`extend_rows`]) are marked.
pub async fn extend(hub: &Arc<Hub>, project: &Project, viewer: &Viewer, tips: &[ObjectId]) -> Result<Vec<ObjectId>> {
    walk_tips(hub, project, viewer, tips, true, &Progress::default(), None).await
}

/// [`extend`] without the file history (BUG-1943): the rows of `tips` and
/// of everything below them that has none, which is all that every query
/// but blame and the history of a path reads. One read of each new
/// snapshot (two for a viewer who is not an admin: the real one and its
/// projection) and a few statements for all of them, so a fill costs what
/// is new: a push of 10,000 snapshots is read at once, and a tip the
/// server named a moment ago is a few rows away. The rows are the same
/// ones [`extend`] writes, from the same projections: only their `files`
/// mark is left for it.
pub async fn extend_rows(hub: &Arc<Hub>, project: &Project, viewer: &Viewer, tips: &[ObjectId]) -> Result<Vec<ObjectId>> {
    walk_tips(hub, project, viewer, tips, false, &Progress::default(), None).await
}

/// Read a push's new `snapshots` into the object cache, sixteen at a time,
/// for the fills that will walk them one after another (BUG-1943: a fill
/// learns each snapshot's id from the one above it, so by itself it reads
/// them one round trip at a time: 11 s for 10,000 from an object store).
/// Only a head start: a snapshot not read here is read by the walk.
pub async fn read_ahead(hub: &Arc<Hub>, project: i64, snapshots: Vec<ObjectId>) {
    for chunk in snapshots.chunks(2048) {
        hub.objects.prefetch(project, chunk).await;
        let mut set = tokio::task::JoinSet::new();
        let mut it = chunk.iter().copied();
        loop {
            while set.len() < 16 {
                let Some(id) = it.next() else { break };
                let hub = hub.clone();
                set.spawn(async move { hub.objects.get(project, &id).await.is_ok() });
            }
            if set.join_next().await.is_none() {
                break;
            }
        }
    }
}

/// How far a fill is, for the queries that give up waiting for it (their
/// `warming` answer says it, and a client waits on while it changes):
///
/// * `rows`: the rows it wrote, which are the viewer's own snapshots and
///   nothing else;
/// * `steps`: everything it did (the projections it memoised, the
///   snapshots it read on its way down, the rows it wrote). **Never
///   answered**: for a viewer who is not an admin it counts real
///   snapshots, hidden ones among them. An answer carries only
///   [`FillProgress::token`], which says that it changed.
#[derive(Debug)]
pub struct FillProgress {
    rows: std::sync::atomic::AtomicU64,
    steps: std::sync::atomic::AtomicU64,
    /// Never leaves the server: what makes the token say nothing of `steps`.
    salt: [u8; 16],
}

pub type Progress = Arc<FillProgress>;

impl Default for FillProgress {
    fn default() -> Self {
        FillProgress {
            rows: Default::default(),
            steps: Default::default(),
            salt: veil_core::crypto::random_bytes::<16>(),
        }
    }
}

impl FillProgress {
    fn step(&self) {
        self.steps.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn wrote(&self, rows: u64) {
        self.rows.fetch_add(rows, std::sync::atomic::Ordering::Relaxed);
        self.steps.fetch_add(rows, std::sync::atomic::Ordering::Relaxed);
    }

    /// The viewer's own snapshots this fill has written rows for.
    pub fn rows(&self) -> u64 {
        self.rows.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Four hex digits that change when the fill has done anything since
    /// they were last read (a keyed hash of `steps` under this fill's own
    /// random key: how much it did cannot be read from them).
    pub fn token(&self) -> String {
        let steps = self.steps.load(std::sync::atomic::Ordering::Relaxed);
        let mut key = [0u8; 32];
        key[..16].copy_from_slice(&self.salt);
        hex::encode(&blake3::keyed_hash(&key, &steps.to_le_bytes()).as_bytes()[..2])
    }
}

tokio::task_local! {
    /// The fill this task projects for (`sync::projected` counts each
    /// projection it memoises here: a viewer's first fill of a long
    /// history spends most of its time there).
    pub(crate) static FILLING: Progress;
}

/// One projection memoised by the fill this task runs, if it runs one.
pub(crate) fn projected_one() {
    let _ = FILLING.try_with(|p| p.step());
}

/// [`extend`] (`files`) or [`extend_rows`]; the walk runs in one of
/// `slots` (the projections before it hold none).
async fn walk_tips(
    hub: &Arc<Hub>,
    project: &Project,
    viewer: &Viewer,
    tips: &[ObjectId],
    files: bool,
    progress: &Progress,
    slots: Option<&Arc<tokio::sync::Semaphore>>,
) -> Result<Vec<ObjectId>> {
    let mut ps = Vec::with_capacity(tips.len());
    for t in tips {
        ps.push(FILLING.scope(progress.clone(), sync::projected(hub, project, viewer, *t)).await?);
    }
    let _slot = match slots {
        Some(s) => Some(s.clone().acquire_owned().await.map_err(|e| Error::Other(e.into()))?),
        None => None,
    };
    let vk = project.view(viewer).key();
    let admin = viewer.admin;
    let pairs: Vec<(ObjectId, ObjectId)> = tips.iter().copied().zip(ps.iter().copied()).collect();
    let (project, viewer, progress) = (project.clone(), viewer.clone(), progress.clone());
    blocking(hub, project.id, move |cx| {
        let g = G::new(cx, &vk, None);
        let view = project.view(&viewer);
        let t = Trees::new(&g, &view);
        let mut w = Walk::new(&g, &t, admin, files, HashMap::from([(root(), root())]));
        w.progress = Some(progress);
        let r = (|| {
            for (t, p) in &pairs {
                w.pmap.insert(*t, *p);
                w.walk(*t)?;
            }
            Ok(())
        })();
        // What was computed is kept, also when the walk failed: the next
        // one goes on from there.
        w.flush()?;
        r
    })
    .await?;
    Ok(ps)
}

/// Most snapshots one [`Walk::learn`] asks about at once.
const AHEAD: usize = 512;

/// One extension of a viewer's graph: its rows, and with `files` its file
/// history (S14: `files::Fill`, the rows of each snapshot's changed paths,
/// written before the graph rows, which are then marked `files`).
struct Walk<'w, 'g, 'a> {
    g: &'g G<'a>,
    t: &'w Trees<'g, 'a>,
    fill: FileFill,
    admin: bool,
    /// The file history too: then only a row marked `files` is present
    /// (one without the mark is computed again, and marked).
    files: bool,
    /// Real snapshot → its projection (the memo's).
    pmap: HashMap<ObjectId, ObjectId>,
    /// Projected ids known to have rows, and known not to have them yet.
    present: HashSet<ObjectId>,
    absent: HashSet<ObjectId>,
    /// Rows computed by this walk.
    rows: HashMap<ObjectId, Arc<VRow>>,
    /// Rows not written yet, parents first, with their change ids.
    pending: Vec<(ObjectId, Arc<VRow>, ChangeId)>,
    inline_cap: bool,
    /// How many snapshots the next [`Walk::learn`] asks about: one, then
    /// four times as many each time, up to [`AHEAD`]. A landing's one new
    /// snapshot costs one statement (none when this server holds its
    /// parent's row), a push of thousands one per [`AHEAD`].
    ahead: usize,
    /// Snapshots [`Walk::learn`] read ahead, for the walk to take.
    read: HashMap<ObjectId, Arc<Snapshot>>,
    progress: Option<Progress>,
}

impl<'w, 'g, 'a> Walk<'w, 'g, 'a> {
    fn new(g: &'g G<'a>, t: &'w Trees<'g, 'a>, admin: bool, files: bool, pmap: HashMap<ObjectId, ObjectId>) -> Self {
        Walk {
            g,
            t,
            fill: FileFill::default(),
            admin,
            files,
            pmap,
            present: HashSet::new(),
            absent: HashSet::new(),
            rows: HashMap::new(),
            pending: Vec::new(),
            inline_cap: false,
            ahead: 1,
            read: HashMap::new(),
            progress: None,
        }
    }

    fn has(&mut self, p: &ObjectId) -> Result<bool> {
        if self.rows.contains_key(p) || self.present.contains(p) {
            return Ok(true);
        }
        if self.absent.contains(p) {
            return Ok(false);
        }
        self.mark(&[*p])?;
        Ok(self.present.contains(p))
    }

    /// Is it known whether projected snapshot `p` has a row?
    fn known(&self, p: &ObjectId) -> bool {
        self.rows.contains_key(p) || self.present.contains(p) || self.absent.contains(p)
    }

    /// Real snapshot `x`, read ahead or now.
    fn snapshot(&mut self, x: &ObjectId) -> Result<Arc<Snapshot>> {
        match self.read.remove(x) {
            Some(s) => Ok(s),
            None => self.reading(x),
        }
    }

    fn reading(&self, x: &ObjectId) -> Result<Arc<Snapshot>> {
        if !self.files {
            self.g.cx.hub().query.fill_reads.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        if let Some(p) = &self.progress {
            p.step();
        }
        self.g.snapshot(x)
    }

    /// Does this server hold the row of real snapshot `x` (its projection
    /// and its row are in memory)? Then nothing is asked about it, nor
    /// read below it: a fill on top of what this server filled last reads
    /// the new snapshots only. (Not with `files`: memory holds no marks.)
    fn held(&mut self, x: &ObjectId) -> bool {
        if self.files {
            return false;
        }
        let (hub, project, vk) = (self.g.cx.hub(), self.g.cx.project(), self.g.vk);
        let p = match self.pmap.get(x) {
            Some(p) => *p,
            None if self.admin => *x,
            None => match hub.caches.memo(project, vk, x) {
                Some(p) => p,
                None => return false,
            },
        };
        if p != root() && cached_row(hub, project, vk, &p).is_none() {
            return false;
        }
        self.pmap.insert(*x, p);
        self.present.insert(p);
        true
    }

    /// The projections of `ids` (real), from the memo, and which of those
    /// have rows: one statement each for all of them, **and for the
    /// snapshots below them** that the walk will come to next, up to
    /// [`Walk::ahead`] in all (BUG-1943: a statement per snapshot made a
    /// fill of 10,000 take 10,000 round trips).
    fn learn(&mut self, ids: &[ObjectId]) -> Result<()> {
        let unknown = |w: &Self, i: &ObjectId| w.pmap.get(i).is_none_or(|p| !w.known(p));
        let mut queue: std::collections::VecDeque<ObjectId> = ids.iter().copied().filter(|i| unknown(self, i)).collect();
        queue.retain(|i| !self.held(i));
        if queue.is_empty() {
            return Ok(());
        }
        let mut seen: HashSet<ObjectId> = queue.iter().copied().collect();
        let mut ask: Vec<ObjectId> = Vec::new();
        while let Some(x) = queue.pop_front() {
            ask.push(x);
            if ask.len() + queue.len() >= self.ahead {
                continue;
            }
            // Below what was asked for: whatever cannot be read ahead is
            // left for the walk to ask about, if it gets there.
            let Ok(s) = self.reading(&x) else { continue };
            for p in &s.parents {
                if *p != root() && unknown(self, p) && !self.held(p) && seen.insert(*p) {
                    queue.push_back(*p);
                }
            }
            self.read.insert(x, s);
        }
        self.ahead = (self.ahead * 4).min(AHEAD);
        let lack: Vec<ObjectId> = ask.iter().copied().filter(|i| !self.pmap.contains_key(i)).collect();
        if !lack.is_empty() {
            if self.admin {
                self.pmap.extend(lack.iter().map(|i| (*i, *i)));
            } else {
                let cx = self.g.cx;
                let hub = cx.hub();
                let hex: Vec<String> = lack.iter().map(|i| i.hex()).collect();
                let rows: Vec<(String, String)> = cx.db(|| {
                    sqlx::query_as("SELECT real_id, projected_id FROM projections WHERE project_id = $1 AND view_key = $2 AND real_id = ANY($3)")
                        .bind(cx.project())
                        .bind(self.g.vk)
                        .bind(&hex)
                        .fetch_all(&hub.db)
                })?;
                for (r, p) in rows {
                    self.pmap.insert(ObjectId::from_hex(&r).map_err(bad)?, ObjectId::from_hex(&p).map_err(bad)?);
                }
                if let Some(m) = ids.iter().find(|i| !self.pmap.contains_key(i)) {
                    return Err(bad(format!("{} has no memoised projection", m.short())));
                }
            }
        }
        let mut ps: Vec<ObjectId> = ask.iter().filter_map(|i| self.pmap.get(i).copied()).filter(|p| !self.known(p)).collect();
        ps.sort();
        ps.dedup();
        self.mark(&ps)
    }

    /// Ask which of `ps` have rows.
    fn mark(&mut self, ps: &[ObjectId]) -> Result<()> {
        if ps.is_empty() {
            return Ok(());
        }
        let found = self.g.present(ps, self.files)?;
        for p in ps {
            if found.contains(p) {
                self.present.insert(*p);
            } else {
                self.absent.insert(*p);
            }
        }
        Ok(())
    }

    fn walk(&mut self, tip: ObjectId) -> Result<()> {
        let mut stack = vec![(tip, false)];
        while let Some((x, expanded)) = stack.pop() {
            let px = self.pmap[&x];
            if self.has(&px)? {
                continue;
            }
            let s = self.snapshot(&x)?;
            self.learn(&s.parents)?;
            let pps: Vec<ObjectId> = s.parents.iter().map(|p| self.pmap[p]).collect();
            if !expanded {
                if pps.first() == Some(&px) {
                    // Not in the viewer's history: it stands for its first
                    // parent's projection.
                    stack.push((s.parents[0], false));
                    continue;
                }
                if pps.contains(&px) {
                    return Err(bad(format!("{} projects to a parent other than its first", x.short())));
                }
                stack.push((x, true));
                for p in s.parents.iter().rev() {
                    stack.push((*p, false));
                }
                continue;
            }
            let ps = if self.admin { s.clone() } else { self.g.snapshot(&px)? };
            let mut want: Vec<ObjectId> = Vec::new();
            for q in pps {
                if !want.contains(&q) {
                    want.push(q);
                }
            }
            if ps.parents != want {
                return Err(bad(format!("the projection of {} does not name its parents' projections", x.short())));
            }
            let mut parents = Vec::with_capacity(want.len());
            for q in &want {
                let r = match self.rows.get(q) {
                    Some(r) => r.clone(),
                    None => self.g.get(q)?,
                };
                parents.push((*q, r));
            }
            let row = Arc::new(VRow::compute(&ps, &parents, x));
            self.g.keep(px, row.clone());
            self.rows.insert(px, row.clone());
            if self.files {
                self.fill.add(self.g, self.t, px, &row)?;
            }
            self.pending.push((px, row, ps.change_id));
            if self.inline_cap && (self.pending.len() >= 16 || self.fill.pending.len() >= 64) {
                return Err(bad("inline fill exceeded cap"));
            }
            if self.pending.len() >= ROWS_PER_STATEMENT || self.fill.pending.len() >= 4 * ROWS_PER_STATEMENT {
                self.flush()?;
            }
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let cx = self.g.cx;
        let hub = cx.hub();
        let project = cx.project();
        let vk = self.g.vk;
        let files = std::mem::take(&mut self.fill.pending);
        let graph = std::mem::take(&mut self.pending);
        self.fill.forget_if_large();
        let gce = hub.caches.gc_epoch(project);
        // File history first: a graph row's `files` mark means its file
        // history is there.
        let marked = self.files;
        cx.db(|| async {
            let mut tx = hub.db.begin().await?;
            if marked {
                FileFill::write_rows_tx(&mut tx, project, vk, &files).await?;
            }
            G::write_rows_tx(&mut tx, project, vk, &graph, marked).await?;
            tx.commit().await?;
            Ok(())
        })?;
        for (i, r, _) in &graph {
            hub.query.rows.insert(cache_key(project, gce, vk, i), r.clone(), 320);
        }
        if let Some(p) = &self.progress {
            p.wrote(graph.len() as u64);
        }
        Ok(())
    }
}

/// Prepared projection memos and viewer-graph rows for a landing's
/// background derive transaction (BUG-1593).
pub(crate) struct PreparedViewKey {
    pub viewer: Viewer,
    pub vk: String,
    pub projections: Vec<(ObjectId, ObjectId, bool)>,
    pub files: Vec<(String, i64, ObjectId, String)>,
    pub graph: Vec<(ObjectId, Arc<VRow>, ChangeId)>,
}

#[derive(Default)]
pub(crate) struct PreparedMemo {
    pub keys: Vec<PreparedViewKey>,
    pub fallback: Vec<Viewer>,
}

pub(crate) async fn prepare_memo(
    hub: &Arc<Hub>,
    project: &Project,
    viewers: Vec<Viewer>,
    tips: &[ObjectId],
) -> Result<PreparedMemo> {
    let mut out = PreparedMemo::default();
    if tips.is_empty() {
        return Ok(out);
    }
    let now = veil_core::now_millis();
    let leased: HashSet<String> = sqlx::query_scalar("SELECT view_key FROM view_fills WHERE project_id = $1 AND expires_at >= $2")
        .bind(project.id)
        .bind(now)
        .fetch_all(&hub.db)
        .await?
        .into_iter()
        .collect();
    let mut seen_keys = HashSet::new();
    for viewer in viewers {
        let view = project.view(&viewer);
        if !view.sees_anything() {
            continue;
        }
        let vk = view.key();
        if !seen_keys.insert(vk.clone()) {
            continue;
        }
        let running = hub.query.fills.lock().unwrap().contains_key(&(project.id, vk.clone(), true));
        if running || leased.contains(&vk) {
            out.fallback.push(viewer);
            continue;
        }
        if warm(hub, project.id, &vk, viewer.admin, tips, true).await?.is_some() {
            continue;
        }
        let mut deferred = sync::Deferred::default();
        let mut ps = Vec::with_capacity(tips.len());
        let mut proj_ok = true;
        for t in tips {
            match sync::projected_inner(hub, project, &viewer, *t, Some(&mut deferred)).await {
                Ok(p) => ps.push(p),
                Err(_) => {
                    proj_ok = false;
                    break;
                }
            }
        }
        if !proj_ok {
            out.fallback.push(viewer);
            continue;
        }
        let mut projections = Vec::with_capacity(deferred.rows.len());
        let mut pmap = HashMap::from([(root(), root())]);
        for (_, r, p) in &deferred.rows {
            pmap.insert(*r, *p);
            projections.push((*r, *p, deferred.collapsed.contains(r)));
        }
        for (t, p) in tips.iter().copied().zip(ps.iter().copied()) {
            pmap.insert(t, p);
        }
        let admin = viewer.admin;
        let vk2 = vk.clone();
        let (project2, viewer2, tips2) = (project.clone(), viewer.clone(), tips.to_vec());
        let walked = blocking(hub, project.id, move |cx| {
            let g = G::new(cx, &vk2, None);
            let view = project2.view(&viewer2);
            let t = Trees::new(&g, &view);
            let mut w = Walk::new(&g, &t, admin, true, pmap);
            w.inline_cap = true;
            for tip in &tips2 {
                w.walk(*tip)?;
            }
            Ok((w.fill.pending, w.pending))
        })
        .await;
        match walked {
            Ok((files, graph)) => {
                out.keys.push(PreparedViewKey {
                    viewer,
                    vk,
                    projections,
                    files,
                    graph,
                });
            }
            Err(_) => {
                out.fallback.push(viewer);
            }
        }
    }
    Ok(out)
}

pub(crate) async fn write_prepared_memo(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    project_id: i64,
    memo: &PreparedMemo,
) -> Result<(Vec<Viewer>, HashSet<String>)> {
    let mut fallback = Vec::new();
    let mut skip_vks = HashSet::new();
    let now = veil_core::now_millis();
    for k in &memo.keys {
        if !k.projections.is_empty() {
            let vks: Vec<&str> = k.projections.iter().map(|_| k.vk.as_str()).collect();
            let reals: Vec<String> = k.projections.iter().map(|(r, _, _)| r.hex()).collect();
            let projs: Vec<String> = k.projections.iter().map(|(_, p, _)| p.hex()).collect();
            let collapsed: Vec<bool> = k.projections.iter().map(|(_, _, c)| *c).collect();
            let stored: Vec<(String, String)> = sqlx::query_as(
                "INSERT INTO projections (project_id, view_key, real_id, projected_id, created_at, collapsed) \
                 SELECT $1, $2, r, p, $5, c FROM UNNEST($3::text[], $4::text[], $6::bool[]) AS t(r, p, c) \
                 ON CONFLICT (project_id, view_key, real_id) DO UPDATE SET created_at = projections.created_at \
                 RETURNING real_id, projected_id",
            )
            .bind(project_id)
            .bind(&k.vk)
            .bind(&reals)
            .bind(&projs)
            .bind(now)
            .bind(&collapsed)
            .fetch_all(&mut **tx)
            .await?;
            let _ = vks;
            let mut mismatch = false;
            let want: HashMap<&str, &str> = reals.iter().map(String::as_str).zip(projs.iter().map(String::as_str)).collect();
            for (r, p) in &stored {
                if want.get(r.as_str()).copied() != Some(p.as_str()) {
                    mismatch = true;
                    break;
                }
            }
            if mismatch {
                skip_vks.insert(k.vk.clone());
                fallback.push(k.viewer.clone());
                continue;
            }
        }
        if !k.files.is_empty() {
            FileFill::write_rows_tx(tx, project_id, &k.vk, &k.files).await?;
        }
        if !k.graph.is_empty() {
            G::write_rows_tx(tx, project_id, &k.vk, &k.graph, true).await?;
        }
    }
    Ok((fallback, skip_vks))
}

pub(crate) fn cache_prepared_memo(hub: &Hub, project_id: i64, memo: &PreparedMemo, skip_vks: &HashSet<String>) {
    for k in &memo.keys {
        if skip_vks.contains(&k.vk) {
            continue;
        }
        for (r, p, _) in &k.projections {
            hub.caches.put_memo(project_id, &k.vk, r, p);
        }
        for (id, row, _) in &k.graph {
            hub.query
                .rows
                .insert(cache_key(project_id, hub.caches.gc_epoch(project_id), &k.vk, id), row.clone(), 320);
        }
    }
}

// ---- filling once ----------------------------------------------------------------

/// The fills running in one server process, by project, view key and part.
type Fills = HashMap<(i64, String, bool), (Fill, Progress)>;

/// The query API's state in one server process.
pub struct State {
    /// Rows of viewers' graphs, by project, view key and snapshot.
    pub rows: LruCache<Arc<VRow>>,
    /// Fills running here, by project, view key and part (`true`: the file
    /// history; `false`: the rows): their outcome once done, and how far
    /// they are.
    fills: Mutex<Fills>,
    /// Fills of rows, and of file history, started here, per project (the
    /// tests count them).
    started: Mutex<HashMap<i64, (u64, u64)>>,
    /// One per fill of file history running here: at most [`MAX_FILLS`] at
    /// once.
    slots: Arc<tokio::sync::Semaphore>,
    /// One per fill of rows walking here: at most [`MAX_FILLS`] at once,
    /// apart from the file history's (which take minutes on a long
    /// history: no query's rows wait behind them).
    row_slots: Arc<tokio::sync::Semaphore>,
    /// Real snapshots the walks of the rows' fills read here: the tests
    /// count them, to show a fill reads what is new and nothing else
    /// (BUG-1943).
    pub fill_reads: std::sync::atomic::AtomicU64,
    /// The blame jobs of this server (S14 cycle 3).
    pub jobs: super::files::Jobs,
    /// Versions blamed (computed, not read kept) here: the tests count
    /// them, to show no version is blamed twice.
    pub blame_steps: std::sync::atomic::AtomicU64,
}

type Fill = watch::Receiver<Option<std::result::Result<(), (bool, String)>>>;

impl Default for State {
    fn default() -> Self {
        State {
            rows: LruCache::new(64 << 20),
            fills: Mutex::new(HashMap::new()),
            started: Mutex::new(HashMap::new()),
            slots: Arc::new(tokio::sync::Semaphore::new(MAX_FILLS)),
            row_slots: Arc::new(tokio::sync::Semaphore::new(MAX_FILLS)),
            fill_reads: std::sync::atomic::AtomicU64::new(0),
            jobs: super::files::Jobs::default(),
            blame_steps: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

impl State {
    /// How many fills of rows (the ones queries wait for) this process
    /// started for `project`.
    pub fn fills_started(&self, project: i64) -> u64 {
        self.started.lock().unwrap().get(&project).map_or(0, |s| s.0)
    }

    /// How many fills of file history this process started for `project`.
    pub fn file_fills_started(&self, project: i64) -> u64 {
        self.started.lock().unwrap().get(&project).map_or(0, |s| s.1)
    }

    /// Take every slot of the rows' fills until the permit is dropped: no
    /// such fill walks here meanwhile, as on a server whose fills are all
    /// busy (the tests make a server answer `warming` this way: the rows'
    /// fills take no lease another server could be shown to hold).
    pub async fn hold_row_fills(&self) -> tokio::sync::OwnedSemaphorePermit {
        self.row_slots.clone().acquire_many_owned(MAX_FILLS as u32).await.expect("the semaphore is never closed")
    }
}

/// A query whose viewer's graph is being filled: the fill goes on in the
/// background; the caller tries again.
pub fn warming() -> Error {
    Error::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "warming",
        "this history is being prepared for you; try again in a few seconds",
    )
}

/// [`warming`], from a query that waited for a fill: with how many of the
/// viewer's own snapshots the fill has written, and its token
/// ([`FillProgress`]: nothing of what the viewer cannot see, not even how
/// much of it there is). A client that asks again sees whether the server
/// is getting on: `vl` waits on while the answer changes (BUG-1943).
fn warming_at(progress: &FillProgress) -> Error {
    Error::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "warming",
        format!(
            "this history is being prepared for you ({} snapshots ready, step {}); try again in a few seconds",
            progress.rows(),
            progress.token()
        ),
    )
}

/// How long a fill waits for another server's fill of the same view key
/// before it goes ahead itself (it then finds that one's rows).
const FILL_LOCK_WAIT: Duration = Duration::from_secs(600);
/// Most fills of one part running at once on one server (BUG-1073). A fill
/// runs its statements one at a time, so fills hold at most twice this
/// many of the pool's connections, and only while a statement runs. Past
/// it, a fill waits for a slot in its own task: a query waits for the fill
/// until its deadline (then `warming`, and the fill stays queued), a
/// landing until it is done.
pub const MAX_FILLS: usize = 4;
/// How long a fill's lease lasts unless renewed, and how often it is.
const LEASE: Duration = Duration::from_secs(120);
const LEASE_RENEW: Duration = Duration::from_secs(30);

/// The viewer's ids of real snapshots `tips`, once the viewer's graph holds
/// their rows. A graph that does not hold them yet is filled by **one**
/// task per project and view key on this server ([`extend_rows`]), at most
/// [`MAX_FILLS`] walking at once on a server: every caller that needs it
/// joins that task. It costs what is new (BUG-1943, BUG-1949): a tip the
/// server named a moment ago is filled within the query that reads it.
/// The task runs in the background to the end, whoever stops waiting;
/// a caller with a `deadline` gets [`warming`] when it passes (a query's
/// deadline never bounds, nor pays for, a first fill).
///
/// View keys come from the server's records only (the accepted policy and
/// who is an admin, in which groups, or named on a line: `perm`), never
/// from a request, so the fills anyone can cause are one per distinct way
/// the project's people read it, plus anyone on Earth's and the admins';
/// `derive::memo_tips` keeps each of those warm at every landing.
pub async fn ensure(hub: &Arc<Hub>, project: &Project, viewer: &Viewer, tips: &[ObjectId], deadline: Option<Instant>) -> Result<Vec<ObjectId>> {
    filled(hub, project, viewer, tips, deadline, false).await
}

/// [`ensure`], and the file history of `tips` and of everything below them
/// (S14), which only blame and the history of a path read: filled by one
/// task per project and view key too ([`extend`]: one server at a time, by
/// a lease row in `view_fills`), which [`ensure`]'s fill and every landing
/// queue, and which a query waits for until its deadline.
pub async fn ensure_files(hub: &Arc<Hub>, project: &Project, viewer: &Viewer, tips: &[ObjectId], deadline: Option<Instant>) -> Result<Vec<ObjectId>> {
    filled(hub, project, viewer, tips, deadline, true).await
}

async fn filled(hub: &Arc<Hub>, project: &Project, viewer: &Viewer, tips: &[ObjectId], deadline: Option<Instant>, files: bool) -> Result<Vec<ObjectId>> {
    let vk = project.view(viewer).key();
    // A fill this call started and saw finish: if its rows are still not
    // there, something is wrong; never loop on it.
    let mut ours_done = false;
    loop {
        if let Some(ps) = warm(hub, project.id, &vk, viewer.admin, tips, files).await? {
            return Ok(ps);
        }
        if ours_done {
            return Err(bad("a fill finished without the rows it was for"));
        }
        // Another caller's fill may be for other tips: wait for it, then
        // look again (and start ours).
        let (mut rx, progress, started) = start_or_join(hub, project, viewer, &vk, tips, files);
        let done = async { rx.wait_for(|d| d.is_some()).await.ok().and_then(|d| d.clone()) };
        let outcome = match deadline {
            Some(d) => tokio::time::timeout_at(d.into(), done)
                .await
                .map_err(|_| warming_at(&progress))?,
            None => done.await,
        };
        if let Some(Err((full, e))) = outcome {
            if full {
                return Err(Error::Other(anyhow::Error::new(crate::pack::IndexesFull)));
            }
            return Err(Error::Other(anyhow::anyhow!("filling a viewer graph: {e}")));
        }
        ours_done = started;
    }
}

/// Queue the fill of `viewer`'s graph up to `tips`, its rows with their
/// file history, unless it holds them already, and return at once: what a
/// landing does for each view key (`derive::memo_tips`). One fill and one
/// transaction a batch for both, as a landing's fill always was (a query
/// that needs a row sooner fills it itself, [`ensure`]). The deriver never
/// waits for a fill, so a long first fill cannot hold up deriving this or
/// any project, and waiting it holds no connection, lock or slot (the
/// fill's own task waits for those).
pub async fn prefill(hub: &Arc<Hub>, project: &Project, viewer: &Viewer, tips: &[ObjectId]) -> Result<()> {
    let vk = project.view(viewer).key();
    if warm(hub, project.id, &vk, viewer.admin, tips, true).await?.is_none() {
        start_or_join(hub, project, viewer, &vk, tips, true);
    }
    Ok(())
}

/// [`prefill`], the rows first: their fill, which queues the file
/// history's when it is done. What a push of many snapshots does for each
/// view key (`derive::rows_of_tips`, BUG-1943): its people read it within
/// the second, and the history of its files some minutes later.
pub async fn prefill_rows(hub: &Arc<Hub>, project: &Project, viewer: &Viewer, tips: &[ObjectId]) -> Result<()> {
    let vk = project.view(viewer).key();
    if warm(hub, project.id, &vk, viewer.admin, tips, false).await?.is_none() {
        start_or_join(hub, project, viewer, &vk, tips, false);
        return Ok(());
    }
    prefill(hub, project, viewer, tips).await
}

/// The viewer's ids of `tips` if their graph holds them all: their rows,
/// and with `files` their file history too.
async fn warm(hub: &Arc<Hub>, project: i64, vk: &str, admin: bool, tips: &[ObjectId], files: bool) -> Result<Option<Vec<ObjectId>>> {
    let mut out = Vec::with_capacity(tips.len());
    for t in tips {
        let p = if admin || *t == root() {
            *t
        } else {
            let p: Option<String> = sqlx::query_scalar("SELECT projected_id FROM projections WHERE project_id = $1 AND view_key = $2 AND real_id = $3")
                .bind(project)
                .bind(vk)
                .bind(t.hex())
                .fetch_optional(&hub.db)
                .await?;
            match p.and_then(|p| ObjectId::from_hex(&p).ok()) {
                Some(p) => p,
                None => return Ok(None),
            }
        };
        // A row this server holds is there; whether its file history is
        // too, only the row's mark says.
        let cached = p == root() || (!files && hub.query.rows.get(&cache_key(project, hub.caches.gc_epoch(project), vk, &p)).is_some());
        if !cached {
            let found: Option<String> = sqlx::query_scalar(
                "SELECT snapshot FROM view_graph WHERE project_id = $1 AND view_key = $2 AND snapshot = $3 AND (files IS TRUE OR NOT $4)",
            )
            .bind(project)
            .bind(vk)
            .bind(p.hex())
            .bind(files)
            .fetch_optional(&hub.db)
            .await?;
            if found.is_none() {
                return Ok(None);
            }
        }
        out.push(p);
    }
    Ok(Some(out))
}

/// Join the fill (of rows, or with `files` of file history) running for
/// (`project`, `vk`), or register one for `tips` and start its task at
/// once (BUG-1074: a fill is queued the moment anyone needs it, whoever
/// stops waiting); how far it is, and whether this call started it. The
/// task of a file history's fill waits for the view key's lease, then for
/// one of the server's [`MAX_FILLS`] slots ([`leased_fill`]); the task of
/// the rows' fill projects, then walks in a slot of its own kind, and
/// queues the file history's fill when it is done.
fn start_or_join(hub: &Arc<Hub>, project: &Project, viewer: &Viewer, vk: &str, tips: &[ObjectId], files: bool) -> (Fill, Progress, bool) {
    let key = (project.id, vk.to_string(), files);
    let mut fills = hub.query.fills.lock().unwrap();
    if let Some((rx, progress)) = fills.get(&key) {
        return (rx.clone(), progress.clone(), false);
    }
    let (tx, rx) = watch::channel(None);
    let progress = Progress::default();
    fills.insert(key.clone(), (rx.clone(), progress.clone()));
    {
        let mut started = hub.query.started.lock().unwrap();
        let n = started.entry(project.id).or_default();
        match files {
            true => n.1 += 1,
            false => n.0 += 1,
        }
    }
    drop(fills);
    let (hub, project, viewer, tips, at) = (hub.clone(), project.clone(), viewer.clone(), tips.to_vec(), progress.clone());
    tokio::spawn(async move {
        let r = match files {
            true => leased_fill(&hub, &project, &viewer, &key.1, &tips, &at).await,
            false => walk_tips(&hub, &project, &viewer, &tips, false, &at, Some(&hub.query.row_slots)).await.map(|_| ()),
        };
        if let Err(e) = &r {
            eprintln!("veil-server: filling a viewer graph of project {}: {e:?}", project.id);
        }
        hub.query.fills.lock().unwrap().remove(&key);
        let rows_done = !files && r.is_ok();
        let _ = tx.send(Some(r.map_err(|e| {
            let full = matches!(&e, Error::Other(a) if crate::pack::indexes_full(a));
            (full, format!("{e:?}"))
        })));
        // The rows are there: their file history next, in the background
        // (nobody waits for it but blame and the history of a path).
        if rows_done {
            match warm(&hub, project.id, &key.1, viewer.admin, &tips, true).await {
                Ok(None) => drop(start_or_join(&hub, &project, &viewer, &key.1, &tips, true)),
                Ok(Some(_)) => {}
                Err(e) => eprintln!("veil-server: queueing the file history of project {}: {e:?}", project.id),
            }
        }
    });
    (rx, progress, true)
}

/// [`extend`] under the lease of (`project`, `vk`) in `view_fills`, so that
/// two servers do not fill one view key's file history at once, and in one
/// of this server's [`MAX_FILLS`] slots. The lease comes first (BUG-1075):
/// a fill that waits for another server's lease holds no slot meanwhile.
/// Taking, renewing and giving back the lease are single statements: no
/// connection is held while the fill runs (BUG-1073). A lease another
/// server holds is waited for (one statement every 250 ms) up to
/// [`FILL_LOCK_WAIT`]; a lease left by a server that stopped expires after
/// [`LEASE`].
async fn leased_fill(hub: &Arc<Hub>, project: &Project, viewer: &Viewer, vk: &str, tips: &[ObjectId], progress: &Progress) -> Result<()> {
    let holder = hex::encode(veil_core::crypto::random_bytes::<16>());
    let take = || async {
        let now = veil_core::now_millis();
        let got: Option<String> = sqlx::query_scalar(
            "INSERT INTO view_fills (project_id, view_key, holder, expires_at) VALUES ($1, $2, $3, $4) \
             ON CONFLICT (project_id, view_key) DO UPDATE SET holder = EXCLUDED.holder, expires_at = EXCLUDED.expires_at \
             WHERE view_fills.expires_at < $5 RETURNING holder",
        )
        .bind(project.id)
        .bind(vk)
        .bind(&holder)
        .bind(now + LEASE.as_millis() as i64)
        .bind(now)
        .fetch_optional(&hub.db)
        .await?;
        Ok::<bool, Error>(got.is_some())
    };
    let wait = tokio::time::Instant::now() + FILL_LOCK_WAIT;
    let mut leased = take().await?;
    while !leased && tokio::time::Instant::now() < wait {
        tokio::time::sleep(Duration::from_millis(250)).await;
        leased = take().await?;
    }
    let renew = leased.then(|| {
        let (hub, id, vk, holder) = (hub.clone(), project.id, vk.to_string(), holder.clone());
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(LEASE_RENEW).await;
                let _ = sqlx::query("UPDATE view_fills SET expires_at = $1 WHERE project_id = $2 AND view_key = $3 AND holder = $4")
                    .bind(veil_core::now_millis() + LEASE.as_millis() as i64)
                    .bind(id)
                    .bind(&vk)
                    .bind(&holder)
                    .execute(&hub.db)
                    .await;
            }
        })
    });
    let r = match hub.query.slots.clone().acquire_owned().await {
        Ok(_slot) => walk_tips(hub, project, viewer, tips, true, progress, None).await.map(|_| ()),
        Err(e) => Err(Error::Other(e.into())),
    };
    if let Some(renew) = renew {
        renew.abort();
        let _ = sqlx::query("DELETE FROM view_fills WHERE project_id = $1 AND view_key = $2 AND holder = $3")
            .bind(project.id)
            .bind(vk)
            .bind(&holder)
            .execute(&hub.db)
            .await;
    }
    r
}
