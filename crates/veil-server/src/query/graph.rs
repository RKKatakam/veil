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
//! **Filled** from the projection memo ([`extend`]): eagerly when a landing
//! memoises its tips for every view key (`derive::memo_tips`), and when a
//! query names a tip not in it yet: either way by one background fill per
//! view key ([`ensure`]), which a query waits for until its deadline only. Rows are written parents
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
use veil_core::{cache::LruCache, object::Snapshot, ObjectId};

use super::{files::Fill as FileFill, trees::Trees};
use crate::{
    derive::{
        graph::{FLAG_EMBARGO, FLAG_EMBARGO_LINE, MAX_STAMP},
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
        let stamp = s.timestamp.clamp(0, MAX_STAMP);
        let generation = parents.iter().map(|(_, p)| p.generation.saturating_add(1)).max().unwrap_or(0).max(stamp);
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

fn cache_key(project: i64, vk: &str, id: &ObjectId) -> ObjectId {
    let mut h = blake3::Hasher::new();
    h.update(b"view-graph");
    h.update(&project.to_le_bytes());
    h.update(&(vk.len() as u64).to_le_bytes());
    h.update(vk.as_bytes());
    h.update(&id.0);
    ObjectId(*h.finalize().as_bytes())
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
        let k = cache_key(self.cx.project(), self.vk, id);
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

    /// Keep `row` of `id`, computed and not written yet (a fill's), for
    /// the walks of this reader.
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

    /// Which of `ids` have rows (one statement).
    fn present(&self, ids: &[ObjectId]) -> Result<HashSet<ObjectId>> {
        let mut out: HashSet<ObjectId> = ids.iter().copied().filter(|i| *i == root() || self.local.borrow().contains_key(i)).collect();
        let ask: Vec<String> = ids.iter().filter(|i| !out.contains(i)).map(|i| i.hex()).collect();
        if ask.is_empty() {
            return Ok(out);
        }
        let hub = self.cx.hub();
        let found: Vec<String> = self.cx.db(|| {
            sqlx::query_scalar("SELECT snapshot FROM view_graph WHERE project_id = $1 AND view_key = $2 AND snapshot = ANY($3)")
                .bind(self.cx.project())
                .bind(self.vk)
                .bind(&ask)
                .fetch_all(&hub.db)
        })?;
        out.extend(found.iter().filter_map(|s| ObjectId::from_hex(s).ok()));
        Ok(out)
    }

    /// Write `rows` (parents before children) and keep them.
    fn add(&self, rows: &[(ObjectId, Arc<VRow>)]) -> Result<()> {
        let hub = self.cx.hub();
        for chunk in rows.chunks(ROWS_PER_STATEMENT) {
            let ids: Vec<String> = chunk.iter().map(|(i, _)| i.hex()).collect();
            let gens: Vec<i64> = chunk.iter().map(|(_, r)| r.generation).collect();
            let depths: Vec<i64> = chunk.iter().map(|(_, r)| r.depth).collect();
            let parents: Vec<String> = chunk.iter().map(|(_, r)| serde_json::to_string(&r.parents).unwrap()).collect();
            let flags: Vec<i32> = chunk.iter().map(|(_, r)| r.flags).collect();
            let skips: Vec<String> = chunk.iter().map(|(_, r)| serde_json::to_string(&r.skip).unwrap()).collect();
            let downs: Vec<String> = chunk.iter().map(|(_, r)| r.down.hex()).collect();
            let reals: Vec<String> = chunk.iter().map(|(_, r)| r.real.hex()).collect();
            self.cx.db(|| {
                sqlx::query(
                    "INSERT INTO view_graph (project_id, view_key, snapshot, generation, depth, parents, flags, skip, down_id, real_id) \
                     SELECT $1, $2, * FROM UNNEST($3::text[], $4::bigint[], $5::bigint[], $6::text[], $7::int[], $8::text[], $9::text[], $10::text[]) \
                     ON CONFLICT DO NOTHING",
                )
                .bind(self.cx.project())
                .bind(self.vk)
                .bind(&ids)
                .bind(&gens)
                .bind(&depths)
                .bind(&parents)
                .bind(&flags)
                .bind(&skips)
                .bind(&downs)
                .bind(&reals)
                .execute(&hub.db)
            })?;
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
        },
    };
    tokio::task::spawn_blocking(move || f(&cx)).await.map_err(|e| Error::Other(e.into()))?
}

/// Make `viewer`'s graph hold `tips` (real snapshots of committed history)
/// and everything below them; answer each tip's id in the viewer's
/// history. The projections come from the memo (`sync::projected`, which
/// fills it first); hidden snapshots are walked here once per view key,
/// never by a query that finds their rows. Queries and landings call it
/// through [`ensure`], which runs it once per view key, in the background.
pub async fn extend(hub: &Arc<Hub>, project: &Project, viewer: &Viewer, tips: &[ObjectId]) -> Result<Vec<ObjectId>> {
    let mut ps = Vec::with_capacity(tips.len());
    for t in tips {
        ps.push(sync::projected(hub, project, viewer, *t).await?);
    }
    let vk = project.view(viewer).key();
    let admin = viewer.admin;
    let pairs: Vec<(ObjectId, ObjectId)> = tips.iter().copied().zip(ps.iter().copied()).collect();
    let (project, viewer) = (project.clone(), viewer.clone());
    blocking(hub, project.id, move |cx| {
        let g = G::new(cx, &vk, None);
        let view = project.view(&viewer);
        let t = Trees::new(&g, &view);
        let mut w = Walk {
            g: &g,
            t: &t,
            fill: FileFill::default(),
            admin,
            pmap: HashMap::from([(root(), root())]),
            present: HashSet::new(),
            absent: HashSet::new(),
            rows: HashMap::new(),
            pending: Vec::new(),
        };
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

/// One extension of a viewer's graph, with its file history (S14:
/// `files::Fill`, the rows of each snapshot's changed paths, written
/// before the graph rows).
struct Walk<'w, 'g, 'a> {
    g: &'g G<'a>,
    t: &'w Trees<'g, 'a>,
    fill: FileFill,
    admin: bool,
    /// Real snapshot → its projection (the memo's).
    pmap: HashMap<ObjectId, ObjectId>,
    /// Projected ids known to have rows, and known not to have them yet.
    present: HashSet<ObjectId>,
    absent: HashSet<ObjectId>,
    /// Rows computed by this walk.
    rows: HashMap<ObjectId, Arc<VRow>>,
    /// Rows not written yet, parents first.
    pending: Vec<(ObjectId, Arc<VRow>)>,
}

impl Walk<'_, '_, '_> {
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

    /// The projections of `ids` (real), from the memo, and which of those
    /// have rows: one statement each for all of them.
    fn learn(&mut self, ids: &[ObjectId]) -> Result<()> {
        let ask: Vec<ObjectId> = ids.iter().copied().filter(|i| !self.pmap.contains_key(i)).collect();
        if !ask.is_empty() {
            if self.admin {
                self.pmap.extend(ask.iter().map(|i| (*i, *i)));
            } else {
                let cx = self.g.cx;
                let hub = cx.hub();
                let hex: Vec<String> = ask.iter().map(|i| i.hex()).collect();
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
                if let Some(m) = ask.iter().find(|i| !self.pmap.contains_key(i)) {
                    return Err(bad(format!("{} has no memoised projection", m.short())));
                }
            }
        }
        let ps: Vec<ObjectId> = ids
            .iter()
            .map(|i| self.pmap[i])
            .filter(|p| !self.rows.contains_key(p) && !self.present.contains(p) && !self.absent.contains(p))
            .collect();
        self.mark(&ps)
    }

    /// Ask which of `ps` have rows.
    fn mark(&mut self, ps: &[ObjectId]) -> Result<()> {
        if ps.is_empty() {
            return Ok(());
        }
        let found = self.g.present(ps)?;
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
            let s = self.g.snapshot(&x)?;
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
            self.fill.add(self.g, self.t, px, &row)?;
            self.pending.push((px, row));
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
        // File history first: a graph row's presence means its file
        // history is there.
        self.fill.flush(self.g)?;
        self.g.add(&self.pending)?;
        self.pending.clear();
        Ok(())
    }
}

// ---- filling once ----------------------------------------------------------------

/// The query API's state in one server process.
pub struct State {
    /// Rows of viewers' graphs, by project, view key and snapshot.
    pub rows: LruCache<Arc<VRow>>,
    /// Fills running here, by project and view key: their outcome once done.
    fills: Mutex<HashMap<(i64, String), Fill>>,
    /// Fills started here, per project (the tests count them).
    started: Mutex<HashMap<i64, u64>>,
    /// One per fill running here: at most [`MAX_FILLS`] at once.
    slots: Arc<tokio::sync::Semaphore>,
    /// One per blame computing here (S14): at most
    /// [`super::files::BLAMES_AT_ONCE`] at once, so what blames hold in all
    /// is bounded whatever the number of requests.
    pub blames: Arc<tokio::sync::Semaphore>,
}

type Fill = watch::Receiver<Option<std::result::Result<(), String>>>;

impl Default for State {
    fn default() -> Self {
        State {
            rows: LruCache::new(64 << 20),
            fills: Mutex::new(HashMap::new()),
            started: Mutex::new(HashMap::new()),
            slots: Arc::new(tokio::sync::Semaphore::new(MAX_FILLS)),
            blames: Arc::new(tokio::sync::Semaphore::new(super::files::BLAMES_AT_ONCE)),
        }
    }
}

impl State {
    /// How many fills this process started for `project`.
    pub fn fills_started(&self, project: i64) -> u64 {
        self.started.lock().unwrap().get(&project).copied().unwrap_or(0)
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

/// How long a fill waits for another server's fill of the same view key
/// before it goes ahead itself (it then finds that one's rows).
const FILL_LOCK_WAIT: Duration = Duration::from_secs(600);
/// Most fills running at once on one server (BUG-1073). A fill runs its
/// statements one at a time, so fills hold at most this many of the
/// pool's connections, and only while a statement runs. Past it, a fill
/// waits for a slot in its own task: a query waits for the fill until its
/// deadline (then `warming`, and the fill stays queued), a landing until
/// it is done.
pub const MAX_FILLS: usize = 4;
/// How long a fill's lease lasts unless renewed, and how often it is.
const LEASE: Duration = Duration::from_secs(120);
const LEASE_RENEW: Duration = Duration::from_secs(30);

/// The viewer's ids of real snapshots `tips`, once the viewer's graph holds
/// them. A graph that does not hold them yet is filled by **one** task per
/// project and view key on this server (and one server at a time, by a
/// lease row in `view_fills`), at most [`MAX_FILLS`] at once on a server:
/// every caller that needs it joins that task.
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
    let vk = project.view(viewer).key();
    // A fill this call started and saw finish: if its rows are still not
    // there, something is wrong; never loop on it.
    let mut ours_done = false;
    loop {
        if let Some(ps) = warm(hub, project.id, &vk, viewer.admin, tips).await? {
            return Ok(ps);
        }
        if ours_done {
            return Err(bad("a fill finished without the rows it was for"));
        }
        // Another caller's fill may be for other tips: wait for it, then
        // look again (and start ours).
        let (mut rx, started) = start_or_join(hub, project, viewer, &vk, tips);
        let done = async { rx.wait_for(|d| d.is_some()).await.ok().and_then(|d| d.clone()) };
        let outcome = match deadline {
            Some(d) => tokio::time::timeout_at(d.into(), done).await.map_err(|_| warming())?,
            None => done.await,
        };
        if let Some(Err(e)) = outcome {
            return Err(Error::Other(anyhow::anyhow!("filling a viewer graph: {e}")));
        }
        ours_done = started;
    }
}

/// Queue the fill of `viewer`'s graph up to `tips` unless it holds them
/// already, and return at once: what a landing does for each view key
/// (`derive::memo_tips`). The deriver never waits for a fill, so a long
/// first fill cannot hold up deriving this or any project, and waiting it
/// holds no connection, lock or slot (the fill's own task waits for those).
pub async fn prefill(hub: &Arc<Hub>, project: &Project, viewer: &Viewer, tips: &[ObjectId]) -> Result<()> {
    let vk = project.view(viewer).key();
    if warm(hub, project.id, &vk, viewer.admin, tips).await?.is_none() {
        start_or_join(hub, project, viewer, &vk, tips);
    }
    Ok(())
}

/// The viewer's ids of `tips` if their graph holds them all.
async fn warm(hub: &Arc<Hub>, project: i64, vk: &str, admin: bool, tips: &[ObjectId]) -> Result<Option<Vec<ObjectId>>> {
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
        let cached = p == root() || hub.query.rows.get(&cache_key(project, vk, &p)).is_some();
        if !cached {
            let found: Option<String> = sqlx::query_scalar("SELECT snapshot FROM view_graph WHERE project_id = $1 AND view_key = $2 AND snapshot = $3")
                .bind(project)
                .bind(vk)
                .bind(p.hex())
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

/// Join the fill running for (`project`, `vk`), or register one for
/// `tips` and start its task at once (BUG-1074: a fill is queued the moment
/// anyone needs it, whoever stops waiting); whether this call started it.
/// The task waits for the view key's lease, then for one of the server's
/// [`MAX_FILLS`] slots ([`leased_fill`]).
fn start_or_join(hub: &Arc<Hub>, project: &Project, viewer: &Viewer, vk: &str, tips: &[ObjectId]) -> (Fill, bool) {
    let key = (project.id, vk.to_string());
    let mut fills = hub.query.fills.lock().unwrap();
    if let Some(rx) = fills.get(&key) {
        return (rx.clone(), false);
    }
    let (tx, rx) = watch::channel(None);
    fills.insert(key.clone(), rx.clone());
    *hub.query.started.lock().unwrap().entry(project.id).or_default() += 1;
    drop(fills);
    let (hub, project, viewer, tips) = (hub.clone(), project.clone(), viewer.clone(), tips.to_vec());
    tokio::spawn(async move {
        let r = leased_fill(&hub, &project, &viewer, &key.1, &tips).await;
        if let Err(e) = &r {
            eprintln!("veil-server: filling a viewer graph of project {}: {e:?}", project.id);
        }
        hub.query.fills.lock().unwrap().remove(&key);
        let _ = tx.send(Some(r.map(|_| ()).map_err(|e| format!("{e:?}"))));
    });
    (rx, true)
}

/// [`extend`] under the lease of (`project`, `vk`) in `view_fills`, so that
/// two servers do not fill one view key at once, and in one of this
/// server's [`MAX_FILLS`] slots. The lease comes first (BUG-1075): a fill
/// that waits for another server's lease holds no slot meanwhile. Taking,
/// renewing and giving back the lease are single statements: no connection
/// is held while the fill runs (BUG-1073). A lease another server holds is
/// waited for (one statement every 250 ms) up to [`FILL_LOCK_WAIT`]; a
/// lease left by a server that stopped expires after [`LEASE`].
async fn leased_fill(hub: &Arc<Hub>, project: &Project, viewer: &Viewer, vk: &str, tips: &[ObjectId]) -> Result<()> {
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
        Ok(_slot) => extend(hub, project, viewer, tips).await.map(|_| ()),
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
