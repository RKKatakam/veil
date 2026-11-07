//! File history and blame, per viewer (milestone S14;
//! `docs/design/server/phase-3-server-history.md` §3.1, §3.6).
//!
//! **The viewer's file history** (`view_file_history`): for each snapshot
//! of a viewer's graph, one row per path its change against its first
//! parent touched, as **their** projected trees show it: the old and new
//! entries, and per parent the snapshot (with its first-parent depth) that
//! last changed the path along that parent's first parents (`prev`, the
//! version that parent holds). The rows are written by the fill that
//! writes the viewer's graph rows ([`Fill`], `graph::extend`), before
//! them, so a graph row's presence means its file history is there too.
//! They are what S12's `file_history` and `prev` are on real history,
//! computed on the projected snapshots alone: exactly what the viewer's own
//! copy of the project derives. A query reads only them and the viewer's
//! graph; no real depth, generation or hidden row is ever read, so neither
//! an answer nor its cost depends on hidden work.
//!
//! **Blame** ([`Blamer`]) walks versions, not snapshots: a version is the
//! snapshot that introduced it and the path there, and its parent versions
//! are its row's `prev` (with `follow`, a file added by a rename from a
//! path the viewer reads continues at the source's version). Each
//! version's blame is computed from its parents' and one diff each
//! ([`crate::derive::blame::step`]), so a blame costs the file's visible
//! versions, never the history's length. Blames are kept as objects
//! (`blame_memo`, per view key): every [`CHECKPOINT`]th version and every
//! version asked for, so the next blame of the file starts from the
//! nearest. A blame that runs out of its budget or deadline keeps what it
//! computed, and the next request goes on from there.
//!
//! **Boundary cuts** (§3.6) need nothing of their own: a source in a
//! folder the viewer cannot read is absent from their projected trees, so
//! a file moved or copied out of it is added there for them, and its lines
//! are the adding change's; a file moved into it is deleted.

use std::{
    cell::RefCell,
    collections::{BinaryHeap, HashMap, HashSet},
    sync::Arc,
};

use axum::http::StatusCode;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use veil_core::{
    object::{EntryKind, TreeEntry},
    ObjectId,
};

use super::{
    graph::{VRow, G},
    trees::{self, entry_json, Trees, MAX_TEXT_BYTES},
};
use crate::{
    derive::{
        blame::{step, Blame, Text},
        changes::{self, path_key},
    },
    error::{Error, Result},
};

/// Blames computing at once in one server process: with
/// [`BlameLimits::held`], what blames hold in all.
pub const BLAMES_AT_ONCE: usize = 4;
/// Versions between two kept blames of one file (and every version asked
/// for is kept too).
pub const CHECKPOINT: u64 = 32;
/// Largest kept blame object; above it a blame is computed each time.
pub const MAX_BLAME_OBJECT: usize = 8 << 20;
/// Most lines a decoded blame object may hold (a file of at most
/// [`MAX_TEXT_BYTES`] has at most that many lines).
const MAX_LINES: usize = MAX_TEXT_BYTES as usize;
/// Rows of one path read per statement: few first (the version asked for
/// is usually near), then more.
const PAGES: [i64; 4] = [8, 64, 512, 1000];
/// Rows per insert statement.
const ROWS_PER_STATEMENT: usize = 500;
/// Rows a fill remembers before it forgets them (they are written by
/// then; later lookups read them back).
const KNOWN_ROWS: usize = 200_000;

fn bad(e: impl std::fmt::Display) -> Error {
    Error::Other(anyhow::anyhow!("file history: {e}"))
}

/// One path's change in one snapshot of a viewer's history.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FChange {
    pub old: Option<TreeEntry>,
    pub new: Option<TreeEntry>,
    /// Per parent of the snapshot, in order: the depth and id of the
    /// snapshot that last changed the path along that parent's first
    /// parents (`None`: never).
    pub prev: Vec<Option<(i64, ObjectId)>>,
}

// ---- filling ----------------------------------------------------------------------

/// The file-history rows of one fill of a viewer's graph (`graph::extend`).
#[derive(Default)]
pub struct Fill {
    /// Rows this fill computed (since it last forgot), by path key:
    /// `(depth, snapshot)`.
    known: HashMap<String, Vec<(i64, ObjectId)>>,
    known_rows: usize,
    /// For each snapshot this fill computed (since it last forgot): the
    /// lowest depth of the run of such snapshots down its first parents.
    fresh: HashMap<ObjectId, i64>,
    /// Rows not written yet: `(path key, depth, snapshot, change)`.
    pub pending: Vec<(String, i64, ObjectId, String)>,
}

impl Fill {
    /// Compute the rows of projected snapshot `id` (row `row`, computed by
    /// this fill; its parents' rows are present or computed before it).
    pub fn add(&mut self, g: &G, t: &Trees, id: ObjectId, row: &VRow) -> Result<()> {
        if row.withheld() {
            // An embargo line has no file history until its release (S22).
            return Ok(());
        }
        let (now, before) = t.roots_of(row)?;
        let (ch, _) = changes::diff(t, before, now)?;
        t.forget();
        for c in ch {
            let key = path_key(&c.path);
            let mut prev = Vec::with_capacity(row.parents.len());
            for q in &row.parents {
                prev.push(self.intro(g, *q, &c.path, &key)?);
            }
            let change = FChange { old: c.old, new: c.new, prev };
            self.known.entry(key.clone()).or_default().push((row.depth, id));
            self.known_rows += 1;
            self.pending.push((key, row.depth, id, serde_json::to_string(&change).map_err(bad)?));
        }
        let low = row.parents.first().and_then(|q| self.fresh.get(q)).copied().unwrap_or(row.depth);
        self.fresh.insert(id, low);
        Ok(())
    }

    /// The snapshot that last changed `path` along `at`'s first parents.
    /// Along the run of snapshots this fill computed down from `at`, its
    /// own rows are all there is; below the run, the written rows. (Only
    /// along such a run: a fill that ran at the same time, after a lease
    /// expired, may have written rows this one skipped.)
    fn intro(&self, g: &G, at: ObjectId, path: &str, key: &str) -> Result<Option<(i64, ObjectId)>> {
        let Some(&low) = self.fresh.get(&at) else { return Files::new(g).intro(at, path) };
        let d = g.get(&at)?.depth;
        let mut mine: Vec<(i64, ObjectId)> = self.known.get(key).into_iter().flatten().filter(|(dd, _)| *dd <= d && *dd >= low).copied().collect();
        mine.sort_by(|a, b| b.cmp(a));
        for (dd, c) in mine {
            if g.at_depth(at, dd)? == Some(c) {
                return Ok(Some((dd, c)));
            }
        }
        // Below the run's lowest snapshot is its first parent; the root
        // (depth 0) changed nothing.
        if low <= 1 {
            return Ok(None);
        }
        Files::new(g).intro_at(at, path, low - 1)
    }

    /// Write the pending rows (before the graph rows that mark their
    /// snapshots present), and forget what this fill knows once it is a
    /// lot: it is all written.
    pub fn flush(&mut self, g: &G) -> Result<()> {
        let cx = g.cx;
        let pool = &cx.hub().db;
        for chunk in self.pending.chunks(ROWS_PER_STATEMENT) {
            let keys: Vec<&str> = chunk.iter().map(|r| r.0.as_str()).collect();
            let depths: Vec<i64> = chunk.iter().map(|r| r.1).collect();
            let ids: Vec<String> = chunk.iter().map(|r| r.2.hex()).collect();
            let changes: Vec<&str> = chunk.iter().map(|r| r.3.as_str()).collect();
            cx.db(|| {
                sqlx::query(
                    "INSERT INTO view_file_history (project_id, view_key, path_key, depth, snapshot, change) \
                     SELECT $1, $2, * FROM UNNEST($3::text[], $4::bigint[], $5::text[], $6::text[]) ON CONFLICT DO NOTHING",
                )
                .bind(cx.project())
                .bind(g.vk)
                .bind(&keys)
                .bind(&depths)
                .bind(&ids)
                .bind(&changes)
                .execute(pool)
            })?;
        }
        self.pending.clear();
        if self.known_rows > KNOWN_ROWS {
            self.known.clear();
            self.known_rows = 0;
            self.fresh.clear();
        }
        Ok(())
    }
}

// ---- reading ----------------------------------------------------------------------

/// Rows of one path read so far, from below `top` down, deepest first.
struct Window {
    top: (i64, ObjectId),
    rows: Vec<(i64, ObjectId, Arc<FChange>)>,
    at: HashMap<ObjectId, usize>,
    done: bool,
    pages: usize,
}

/// A viewer's file history, read on their graph `g`.
pub struct Files<'g, 'a> {
    pub g: &'g G<'a>,
    windows: RefCell<HashMap<String, Window>>,
}

fn top_of(depth: i64) -> (i64, ObjectId) {
    (depth.saturating_add(1), ObjectId([0; 32]))
}

impl<'g, 'a> Files<'g, 'a> {
    pub fn new(g: &'g G<'a>) -> Files<'g, 'a> {
        Files {
            g,
            windows: RefCell::new(HashMap::new()),
        }
    }

    /// Read the next page of `path`'s window.
    fn more(&self, w: &mut Window, key: &str) -> Result<()> {
        let limit = PAGES[w.pages.min(PAGES.len() - 1)];
        w.pages += 1;
        let (d, s) = w.rows.last().map(|(d, s, _)| (*d, *s)).unwrap_or(w.top);
        let cx = self.g.cx;
        self.g.tick()?;
        let rows: Vec<(i64, String, String)> = cx.db(|| {
            sqlx::query_as(
                "SELECT depth, snapshot, change FROM view_file_history WHERE project_id = $1 AND view_key = $2 AND path_key = $3 \
                 AND (depth, snapshot) < ($4, $5) ORDER BY depth DESC, snapshot DESC LIMIT $6",
            )
            .bind(cx.project())
            .bind(self.g.vk)
            .bind(key)
            .bind(d)
            .bind(s.hex())
            .bind(limit)
            .fetch_all(&cx.hub().db)
        })?;
        w.done = (rows.len() as i64) < limit;
        for (d, s, c) in rows {
            self.g.tick()?;
            let s = ObjectId::from_hex(&s).map_err(bad)?;
            let c: FChange = serde_json::from_str(&c).map_err(bad)?;
            w.at.insert(s, w.rows.len());
            w.rows.push((d, s, Arc::new(c)));
        }
        Ok(())
    }

    /// The window of `path` holding rows at depth `depth`: the one read so
    /// far if it does, else a new one from just above `depth`.
    fn window(&self, path: &str, depth: i64) -> std::cell::RefMut<'_, Window> {
        let key = path_key(path);
        let mut ws = self.windows.borrow_mut();
        let fresh = ws.get(&key).is_none_or(|w| w.top.0 <= depth);
        if fresh {
            ws.insert(
                key.clone(),
                Window {
                    top: top_of(depth),
                    rows: Vec::new(),
                    at: HashMap::new(),
                    done: false,
                    pages: 0,
                },
            );
        }
        std::cell::RefMut::map(ws, |ws| ws.get_mut(&key).unwrap())
    }

    /// The change of `path` in snapshot `id` (at first-parent depth
    /// `depth`), if it changed it.
    pub fn find(&self, path: &str, depth: i64, id: ObjectId) -> Result<Option<Arc<FChange>>> {
        let key = path_key(path);
        let above = self.windows.borrow().get(&key).is_some_and(|w| w.top.0 <= depth);
        if above {
            // Above the rows read so far (a history walks by generation,
            // not depth): one row, by its key.
            let cx = self.g.cx;
            self.g.tick()?;
            let c: Option<String> = cx.db(|| {
                sqlx::query_scalar(
                    "SELECT change FROM view_file_history WHERE project_id = $1 AND view_key = $2 AND path_key = $3 AND depth = $4 AND snapshot = $5",
                )
                .bind(cx.project())
                .bind(self.g.vk)
                .bind(&key)
                .bind(depth)
                .bind(id.hex())
                .fetch_optional(&cx.hub().db)
            })?;
            return c.map(|c| serde_json::from_str(&c).map(Arc::new).map_err(bad)).transpose();
        }
        let mut w = self.window(path, depth);
        loop {
            if let Some(&i) = w.at.get(&id) {
                return Ok(Some(w.rows[i].2.clone()));
            }
            let below = w.rows.last().is_some_and(|(d, s, _)| (*d, *s) < (depth, id));
            if w.done || below {
                return Ok(None);
            }
            self.more(&mut w, &key)?;
        }
    }

    /// The snapshot that last changed `path` along `at`'s first parents
    /// (`at` included): the one that introduced `at`'s version. The path's
    /// rows at or above `at`'s depth, deepest first; the first on `at`'s
    /// first-parent line is the answer (S12's search, on the viewer's
    /// graph).
    pub fn intro(&self, at: ObjectId, path: &str) -> Result<Option<(i64, ObjectId)>> {
        let d = self.g.get(&at)?.depth;
        self.intro_at(at, path, d)
    }

    /// [`Files::intro`] among the rows at depth `d` or less.
    pub fn intro_at(&self, at: ObjectId, path: &str, d: i64) -> Result<Option<(i64, ObjectId)>> {
        let key = path_key(path);
        let mut w = self.window(path, d);
        let mut i = 0;
        loop {
            while i < w.rows.len() {
                let (dd, c, _) = w.rows[i];
                i += 1;
                if dd <= d && self.g.at_depth(at, dd)? == Some(c) {
                    return Ok(Some((dd, c)));
                }
            }
            if w.done {
                return Ok(None);
            }
            self.more(&mut w, &key)?;
        }
    }
}

/// The path `path` was renamed from in the viewer's snapshot `row` (its
/// change against its first parent, renames paired as `diff` pairs them,
/// from sources the viewer may read).
fn renamed_from(t: &Trees, row: &VRow, path: &str) -> Result<Option<String>> {
    let (now, before) = t.roots_of(row)?;
    let ch = t.changes(before, now, "")?;
    let (from, _, _) = changes::sources_with(&t.g.cx.src, &ch, &|| t.g.tick())?;
    let (pairs, _) = trees::pairs(&ch, &from);
    Ok(ch
        .iter()
        .position(|c| c.path == path)
        .and_then(|i| pairs[i])
        .and_then(|(s, _, rename)| rename.then(|| ch[s].path.clone())))
}

// ---- versions ---------------------------------------------------------------------

/// A version of a file: the snapshot that introduced it, its depth there,
/// and the path.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Version {
    pub id: ObjectId,
    pub depth: i64,
    pub path: String,
}

/// Does entry `e` hold a version the server may read lines of (a plain,
/// not secret, file of at most [`MAX_TEXT_BYTES`])?
fn texty(e: &Option<TreeEntry>) -> bool {
    e.as_ref().is_some_and(|e| e.kind == EntryKind::File && e.visibility.is_public() && e.size <= MAX_TEXT_BYTES)
}

/// The versions version `v` (whose change is `c`) came from, per parent
/// of its snapshot: the parent's version of the path, or with `follow`,
/// for a file the change added, the version of the path it was renamed
/// from (first parent only, as the changed paths record sources).
fn parents_of(f: &Files, t: &Trees, v: &Version, c: &FChange, follow: bool, renames: &mut HashMap<ObjectId, Option<String>>) -> Result<Vec<Option<Version>>> {
    let mut out: Vec<Option<Version>> = c
        .prev
        .iter()
        .map(|p| p.map(|(depth, id)| Version { id, depth, path: v.path.clone() }))
        .collect();
    if follow && c.old.is_none() && !out.is_empty() {
        let from = match renames.get(&v.id) {
            Some(r) => r.clone(),
            None => {
                let r = renamed_from(t, &*f.g.get(&v.id)?, &v.path)?;
                renames.insert(v.id, r.clone());
                r
            }
        };
        if let Some(q) = from {
            let qc = f.find(&q, v.depth, v.id)?.ok_or_else(|| bad("a rename's source has no row"))?;
            out[0] = qc.prev.first().copied().flatten().map(|(depth, id)| Version { id, depth, path: q });
        }
    }
    Ok(out)
}

// ---- blame ------------------------------------------------------------------------

/// What one blame may spend.
#[derive(Clone, Copy, Debug)]
pub struct BlameLimits {
    /// Diff work ([`veil_core::blame::map_cost`]); past it the blame
    /// stops, keeping what it computed.
    pub work: u64,
    /// Work of the walk down to the versions a blame starts from (rows,
    /// objects and trees read: [`G::tick`]); past it the walk stops and
    /// keeps where it got to, and the next request blames those deeper
    /// versions first (BUG-1212).
    pub walk: u64,
    /// Bytes of texts and blames held at once.
    pub held: usize,
    /// Lines a page shows.
    pub lines: usize,
}

impl Default for BlameLimits {
    fn default() -> Self {
        BlameLimits {
            work: veil_core::blame::DEFAULT_WORK_BUDGET,
            walk: 20_000,
            held: 64 << 20,
            lines: 10_000,
        }
    }
}

/// A blame that stopped at its budget: what it computed is kept.
pub fn partial() -> Error {
    Error::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "partial",
        "this file has a long history: part of its blame was computed and kept; ask again to go on",
    )
}

fn too_wide() -> Error {
    Error::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        "too_wide",
        "this file's history holds too many versions at once to blame within the server's memory bound",
    )
}

/// What a version's blame needs, found by the walk down.
struct Node {
    change: Arc<FChange>,
    parents: Vec<Option<Version>>,
    /// Its kept blame, if any (then nothing below it is walked).
    kept: Option<ObjectId>,
    /// Versions above it, in this walk, not computed yet.
    left: usize,
}

/// A computed version: its text and blame (`None`: no plain-text version).
type Done = Option<(Arc<Text>, Arc<Blame>)>;

/// One viewer's blames.
pub struct Blamer<'f, 'g, 'a, 'h, 'b> {
    pub f: &'f Files<'g, 'a>,
    pub t: &'f Trees<'h, 'b>,
    pub follow: bool,
    pub limits: BlameLimits,
    kept: HashMap<String, HashMap<ObjectId, ObjectId>>,
    renames: HashMap<ObjectId, Option<String>>,
    /// Kept blames to write: `(path key, snapshot, object id, bytes)`.
    writes: Vec<(String, ObjectId, ObjectId, Vec<u8>)>,
    /// The last version computed and not kept: kept when the blame stops,
    /// so every request that computes something leaves progress.
    last: Option<(Version, Arc<Blame>)>,
    /// Walks down cut before (`blame_walks`): from a version, the deeper
    /// versions it reached, which are blamed first.
    walked: HashMap<Version, Vec<Version>>,
    /// Walks cut by this request, to write.
    cut: Vec<(Version, Vec<Version>)>,
}

/// Most versions a cut walk keeps as where it got to.
const MAX_FRONTIER: usize = 64;
/// Most walks followed down from one version within a request.
const MAX_RESUMES: usize = 10_000;

impl<'f, 'g, 'a, 'h, 'b> Blamer<'f, 'g, 'a, 'h, 'b> {
    pub fn new(f: &'f Files<'g, 'a>, t: &'f Trees<'h, 'b>, follow: bool, limits: BlameLimits) -> Self {
        Blamer {
            f,
            t,
            follow,
            limits,
            kept: HashMap::new(),
            renames: HashMap::new(),
            writes: Vec::new(),
            last: None,
            walked: HashMap::new(),
            cut: Vec::new(),
        }
    }

    /// The kept blame of `v`, if any (every kept blame of the path is read
    /// at once: at most one per [`CHECKPOINT`] versions, plus those asked).
    fn kept_of(&mut self, v: &Version) -> Result<Option<ObjectId>> {
        let key = path_key(&v.path);
        if !self.kept.contains_key(&key) {
            let g = self.f.g;
            let cx = g.cx;
            g.tick()?;
            let rows: Vec<(String, String)> = cx.db(|| {
                sqlx::query_as("SELECT snapshot, object FROM blame_memo WHERE project_id = $1 AND view_key = $2 AND path_key = $3 AND follow = $4")
                    .bind(cx.project())
                    .bind(g.vk)
                    .bind(&key)
                    .bind(self.follow)
                    .fetch_all(&cx.hub().db)
            })?;
            let mut m = HashMap::new();
            for (s, o) in rows {
                g.tick()?;
                m.insert(ObjectId::from_hex(&s).map_err(bad)?, ObjectId::from_hex(&o).map_err(bad)?);
            }
            self.kept.insert(key.clone(), m);
        }
        Ok(self.kept[&key].get(&v.id).copied())
    }

    /// What the walk down needs of version `v`: its change, the versions
    /// it came from (none when its blame is kept, or it is not text), and
    /// its kept blame.
    #[allow(clippy::type_complexity)]
    fn expand(&mut self, v: &Version) -> Result<(Arc<FChange>, Vec<Option<Version>>, Option<ObjectId>)> {
        let change = self.f.find(&v.path, v.depth, v.id)?.ok_or_else(|| bad(format!("no row for a version at {}", v.id.short())))?;
        let kept = if texty(&change.new) { self.kept_of(v)? } else { None };
        let parents = if texty(&change.new) && kept.is_none() {
            parents_of(self.f, self.t, v, &change, self.follow, &mut self.renames)?
        } else {
            Vec::new()
        };
        Ok((change, parents, kept))
    }

    /// The text of entry `e`, if it is plain text the server may read.
    fn text(&self, e: &Option<TreeEntry>) -> Result<Option<Arc<Text>>> {
        if !texty(e) {
            return Ok(None);
        }
        let e = e.as_ref().unwrap();
        let (blob, bytes) = self.t.content(&e.id)?;
        if !blob || bytes.len() as u64 > MAX_TEXT_BYTES || bytes.contains(&0) || std::str::from_utf8(&bytes).is_err() {
            return Ok(None);
        }
        Ok(Some(Text::new(e.id, bytes)))
    }

    /// The text and blame of version `start`; `None` when it is not plain
    /// text. Kept blames are written, also when it stops.
    pub fn blame(&mut self, start: &Version) -> Result<Done> {
        let r = self.resumed(start);
        if r.is_err() {
            if let Some((v, b)) = self.last.take() {
                self.keep(&v, &b);
            }
        }
        let w = self.write().and_then(|_| self.write_cuts());
        let out = r?;
        w?;
        Ok(out)
    }

    /// Blame `start`, first blaming (and keeping) the deepest versions an
    /// earlier walk down from it reached before it was cut, so that every
    /// request leaves progress whatever stops it (BUG-1212).
    fn resumed(&mut self, start: &Version) -> Result<Done> {
        let mut tried: HashSet<Version> = HashSet::new();
        loop {
            let mut v = start.clone();
            for _ in 0..MAX_RESUMES {
                let mut next = None;
                for x in self.walked_from(&v)? {
                    if !tried.contains(&x) && self.kept_of(&x)?.is_none() {
                        next = Some(x);
                        break;
                    }
                }
                match next {
                    Some(x) => v = x,
                    None => break,
                }
            }
            if v == *start {
                return self.run(start);
            }
            tried.insert(v.clone());
            self.run(&v)?;
        }
    }

    /// Where a cut walk down from `v` got to (`blame_walks`).
    fn walked_from(&mut self, v: &Version) -> Result<Vec<Version>> {
        if let Some(w) = self.walked.get(v) {
            return Ok(w.clone());
        }
        let g = self.f.g;
        let cx = g.cx;
        g.tick()?;
        let row: Option<String> = cx.db(|| {
            sqlx::query_scalar(
                "SELECT frontier FROM blame_walks WHERE project_id = $1 AND view_key = $2 AND path_key = $3 AND follow = $4 AND snapshot = $5",
            )
            .bind(cx.project())
            .bind(g.vk)
            .bind(path_key(&v.path))
            .bind(self.follow)
            .bind(v.id.hex())
            .fetch_optional(&cx.hub().db)
        })?;
        let w: Vec<Version> = match row {
            Some(r) => serde_json::from_str(&r).map_err(bad)?,
            None => Vec::new(),
        };
        self.walked.insert(v.clone(), w.clone());
        Ok(w)
    }

    /// Write the walks this request cut.
    fn write_cuts(&mut self) -> Result<()> {
        let cx = self.f.g.cx;
        for (v, frontier) in std::mem::take(&mut self.cut) {
            let text = serde_json::to_string(&frontier).map_err(bad)?;
            cx.db(|| {
                sqlx::query(
                    "INSERT INTO blame_walks (project_id, view_key, path_key, follow, snapshot, frontier) VALUES ($1, $2, $3, $4, $5, $6) \
                     ON CONFLICT (project_id, view_key, path_key, follow, snapshot) DO UPDATE SET frontier = EXCLUDED.frontier",
                )
                .bind(cx.project())
                .bind(self.f.g.vk)
                .bind(path_key(&v.path))
                .bind(self.follow)
                .bind(v.id.hex())
                .bind(&text)
                .execute(&cx.hub().db)
            })?;
        }
        Ok(())
    }

    fn run(&mut self, start: &Version) -> Result<Done> {
        // Down: the versions to compute, parents before children, each
        // once, stopping at kept blames.
        let mut nodes: HashMap<Version, Node> = HashMap::new();
        let mut order: Vec<Version> = Vec::new();
        let mut stack: Vec<(Version, bool)> = vec![(start.clone(), false)];
        let mut held = 0usize;
        let began = self.f.g.work();
        while let Some((v, ready)) = stack.pop() {
            if ready {
                order.push(v);
                continue;
            }
            if nodes.contains_key(&v) {
                continue;
            }
            // Stopped (its work, its memory, or the deadline): where it got
            // to is kept, and blamed first next time (BUG-1212).
            let over = self.f.g.work() - began > self.limits.walk || held > self.limits.held;
            let r = if over { Err(partial()) } else { self.expand(&v) };
            let (change, parents, kept) = match r {
                Ok(x) => x,
                Err(e) => {
                    stack.push((v, false));
                    let mut frontier: Vec<Version> = Vec::new();
                    for (x, ready) in stack.iter().rev() {
                        if !ready && !nodes.contains_key(x) && !frontier.contains(x) && *x != *start && frontier.len() < MAX_FRONTIER {
                            frontier.push(x.clone());
                        }
                    }
                    if !frontier.is_empty() {
                        self.cut.push((start.clone(), frontier));
                    }
                    return Err(e);
                }
            };
            held += 256 + v.path.len();
            stack.push((v.clone(), true));
            for p in parents.iter().rev().flatten() {
                if !nodes.contains_key(p) {
                    stack.push((p.clone(), false));
                }
            }
            nodes.insert(v, Node { change, parents, kept, left: 0 });
        }
        let edges: Vec<Version> = nodes.values().flat_map(|n| n.parents.iter().flatten().cloned()).collect();
        for p in edges {
            if let Some(n) = nodes.get_mut(&p) {
                n.left += 1;
            }
        }
        // Up: each version from its parents', each dropped once every
        // version above it is computed.
        let mut done: HashMap<Version, Done> = HashMap::new();
        let mut cost = 0u64;
        for v in order {
            let (change, parents, kept) = {
                let n = &nodes[&v];
                (n.change.clone(), n.parents.clone(), n.kept)
            };
            let out: Done = match kept {
                Some(obj) => {
                    self.f.g.tick()?;
                    let raw = self.f.g.cx.src.raw(&obj)?;
                    let b = Blame::decode(&raw, MAX_LINES)?;
                    match self.text(&change.new)? {
                        Some(t) if t.lines.len() == b.lines.len() => Some((t, Arc::new(b))),
                        Some(_) => return Err(bad("a kept blame does not match its version")),
                        None => None,
                    }
                }
                None => match self.text(&change.new)? {
                    None => None,
                    Some(text) => {
                        let inputs: Vec<Option<(&Text, &Blame)>> = parents
                            .iter()
                            .map(|p| p.as_ref().and_then(|p| done.get(p)).and_then(|d| d.as_ref()).map(|(t, b)| (&**t, &**b)))
                            .collect();
                        let (b, c) = step((v.id, &v.path), &text, &inputs);
                        cost = cost.saturating_add(c);
                        let b = Arc::new(b);
                        if b.vd % CHECKPOINT == 0 || v == *start {
                            self.keep(&v, &b);
                            self.last = None;
                        } else {
                            self.last = Some((v.clone(), b.clone()));
                        }
                        Some((text, b))
                    }
                },
            };
            if let Some((t, b)) = &out {
                held += t.weight() + b.weight();
            }
            for p in parents.iter().flatten() {
                let pn = nodes.get_mut(p).unwrap();
                pn.left -= 1;
                if pn.left == 0 && p != start {
                    if let Some(Some((t, b))) = done.remove(p) {
                        held -= t.weight() + b.weight();
                    }
                }
            }
            done.insert(v.clone(), out);
            if held > self.limits.held {
                return Err(too_wide());
            }
            if cost > self.limits.work {
                return Err(partial());
            }
            if self.writes.len() >= 32 {
                self.write()?;
            }
        }
        Ok(done.remove(start).flatten())
    }

    /// Keep blame `b` of version `v` (unless it is too large to).
    fn keep(&mut self, v: &Version, b: &Blame) {
        let raw = b.encode();
        if raw.len() <= MAX_BLAME_OBJECT {
            self.writes.push((path_key(&v.path), v.id, ObjectId::hash(&raw), raw));
        }
    }

    /// Write the kept blames computed so far: the objects, then their rows.
    fn write(&mut self) -> Result<()> {
        if self.writes.is_empty() {
            return Ok(());
        }
        let w = std::mem::take(&mut self.writes);
        let cx = self.f.g.cx;
        let (hub, project) = (cx.hub().clone(), cx.project());
        let objects: Vec<(ObjectId, Bytes)> = w.iter().map(|(_, _, o, raw)| (*o, Bytes::from(raw.clone()))).collect();
        cx.src.rt.block_on(async {
            let mut set = tokio::task::JoinSet::new();
            let mut it = objects.into_iter();
            loop {
                while set.len() < 16 {
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
        let keys: Vec<&str> = w.iter().map(|r| r.0.as_str()).collect();
        let snaps: Vec<String> = w.iter().map(|r| r.1.hex()).collect();
        let objs: Vec<String> = w.iter().map(|r| r.2.hex()).collect();
        cx.db(|| {
            sqlx::query(
                "INSERT INTO blame_memo (project_id, view_key, path_key, follow, snapshot, object) \
                 SELECT $1, $2, k, $3, s, o FROM UNNEST($4::text[], $5::text[], $6::text[]) AS t(k, s, o) ON CONFLICT DO NOTHING",
            )
            .bind(project)
            .bind(self.f.g.vk)
            .bind(self.follow)
            .bind(&keys)
            .bind(&snaps)
            .bind(&objs)
            .execute(&cx.hub().db)
        })?;
        for (k, s, o, _) in w {
            self.kept.entry(k).or_default().insert(s, o);
        }
        Ok(())
    }
}

/// The JSON of blame `b` of `text` (path `path` at snapshot `rev`): lines
/// `after + 1` on, at most `n`, each with its origin, and the changes they
/// name, newest first (the viewer's generations).
#[allow(clippy::too_many_arguments)]
pub fn blame_json(g: &G, rev: ObjectId, path: &str, follow: bool, text: &Text, b: &Blame, after: usize, n: usize) -> Result<Value> {
    let total = text.lines.len();
    let from = after.min(total);
    let to = from.saturating_add(n).min(total);
    let mut lines = Vec::with_capacity(to - from);
    let mut snaps: HashMap<ObjectId, Arc<veil_core::object::Snapshot>> = HashMap::new();
    for i in from..to {
        let (id, p, l) = b.origin(i);
        if !snaps.contains_key(id) {
            snaps.insert(*id, g.snapshot(id)?);
        }
        let s = &snaps[id];
        let raw = text.line(i);
        let raw = raw.strip_suffix(b"\n").unwrap_or(raw);
        let raw = raw.strip_suffix(b"\r").unwrap_or(raw);
        lines.push(json!({
            "line": i + 1,
            "text": String::from_utf8_lossy(raw),
            "snapshot": id.hex(),
            "change": s.change_id.to_string(),
            "change_short": s.change_id.short(),
            "path": p,
            "origin_line": l,
        }));
    }
    let mut order: Vec<(i64, ObjectId)> = Vec::new();
    for id in snaps.keys() {
        order.push((g.get(id)?.generation, *id));
    }
    order.sort_by(|a, b| b.cmp(a));
    let changes: Vec<Value> = order
        .iter()
        .map(|(_, id)| {
            let s = &snaps[id];
            json!({
                "snapshot_id": id.hex(),
                "snapshot_short": id.short(),
                "change_id": s.change_id.to_string(),
                "change_short": s.change_id.short(),
                "author": s.author,
                "timestamp": s.timestamp,
                "description": s.description.as_str(),
            })
        })
        .collect();
    let next = (to < total).then_some(to);
    Ok(json!({
        "schema": "veil.blame/2",
        "path": path,
        "rev": { "snapshot_id": rev.hex(), "snapshot_short": rev.short() },
        "follow": follow,
        "coarse": b.coarse,
        "line_count": total,
        "lines": lines,
        "changes": changes,
        "truncated": next.is_some(),
        "next": next,
    }))
}

// ---- file history -----------------------------------------------------------------

/// Most bytes of a history's frontier (its cursor's text): a page ends
/// before a step would pass it, so a kept cursor is at most about this
/// (BUG-1213).
pub const FRONTIER_BYTES: usize = 1 << 20;

/// The bytes a version takes in a cursor.
fn cursor_bytes(v: &Version) -> usize {
    66 + 2 * v.path.len()
}

/// A history cursor: `snapshot.hex(path)` for each version still to walk.
pub fn cursor(nodes: &[Version]) -> String {
    nodes.iter().map(|v| format!("{}.{}", v.id.hex(), hex::encode(v.path.as_bytes()))).collect::<Vec<_>>().join(",")
}

/// The versions a cursor names (syntax only; the walk checks each against
/// the viewer's graph and file history).
pub fn parse_cursor(s: &str, max: usize) -> Result<Vec<(ObjectId, String)>> {
    let invalid = || Error::bad_request("invalid cursor");
    let parts: Vec<&str> = s.split(',').filter(|p| !p.is_empty()).collect();
    if parts.len() > max {
        return Err(Error::bad_request("cursor too long"));
    }
    let mut out = Vec::new();
    for p in parts {
        let (id, path) = p.split_once('.').ok_or_else(invalid)?;
        let id = (id.len() == 64).then(|| ObjectId::from_hex(id).ok()).flatten().ok_or_else(invalid)?;
        let path = String::from_utf8(hex::decode(path).map_err(|_| invalid())?).map_err(|_| invalid())?;
        let path = trees::clean_path(&path).map_err(|_| invalid())?;
        if path.is_empty() {
            return Err(invalid());
        }
        out.push((id, path));
    }
    Ok(out)
}

/// One page of the file history from `starts`: the versions newest first
/// by the viewer's generation (ties by id, then path), each with the
/// snapshot that made it; a version's parents are its row's `prev`, and
/// with `follow`, a rename's source. Stops at `n` entries, `page_bytes`, a
/// work budget, or before the frontier would pass `frontier` versions or
/// [`FRONTIER_BYTES`]. Answers the page without `next`, and the versions
/// still to walk (the caller makes the cursor: `query::history`).
#[allow(clippy::too_many_arguments)]
pub fn history_page(
    f: &Files,
    t: &Trees,
    starts: Vec<Version>,
    follow: bool,
    n: usize,
    page_bytes: usize,
    work: u64,
    frontier: usize,
    snapshot_json: impl Fn(&ObjectId, &veil_core::object::Snapshot) -> Value,
) -> Result<(Value, Vec<Version>)> {
    let g = f.g;
    let invalid = || Error::bad_request("invalid cursor");
    let mut heap: BinaryHeap<(i64, ObjectId, String, i64)> = BinaryHeap::new();
    let mut queued: HashSet<(ObjectId, String)> = HashSet::new();
    for v in starts {
        if queued.insert((v.id, v.path.clone())) {
            let r = g.get(&v.id)?;
            heap.push((r.generation, v.id, v.path, v.depth));
        }
    }
    let mut renames = HashMap::new();
    let mut frontier_bytes: usize = heap.iter().map(|(_, _, p, _)| 66 + 2 * p.len()).sum();
    let begin = g.work();
    let mut entries = Vec::new();
    let mut bytes = 0usize;
    let mut took = false;
    while entries.len() < n && g.work() - begin < work {
        let Some((_, id, path, depth)) = heap.peek().cloned() else { break };
        let v = Version { id, depth, path };
        let c = f.find(&v.path, v.depth, v.id)?.ok_or_else(invalid)?;
        let parents = parents_of(f, t, &v, &c, follow, &mut renames)?;
        let fresh: Vec<Version> = {
            let mut seen = HashSet::new();
            parents.iter().flatten().filter(|p| !queued.contains(&(p.id, p.path.clone())) && seen.insert((p.id, p.path.clone()))).cloned().collect()
        };
        let grows: usize = fresh.iter().map(cursor_bytes).sum::<usize>();
        if heap.len() - 1 + fresh.len() > frontier || frontier_bytes - cursor_bytes(&v) + grows > FRONTIER_BYTES {
            break;
        }
        heap.pop();
        frontier_bytes = frontier_bytes - cursor_bytes(&v) + grows;
        took = true;
        for p in fresh {
            queued.insert((p.id, p.path.clone()));
            let r = g.get(&p.id)?;
            heap.push((r.generation, p.id, p.path, p.depth));
        }
        let s = g.snapshot(&v.id)?;
        let mut e = snapshot_json(&v.id, &s);
        let from = match (&c.old, &c.new) {
            (None, Some(_)) if follow => parents.first().cloned().flatten().filter(|p| p.path != v.path).map(|p| p.path),
            _ => None,
        };
        e["path"] = json!(v.path);
        e["status"] = json!(match (&c.old, &c.new, &from) {
            (None, _, Some(_)) => "renamed",
            (None, _, None) => "added",
            (_, None, _) => "deleted",
            _ => "modified",
        });
        if let Some(fp) = from {
            e["from"] = json!(fp);
        }
        e["old"] = entry_json(c.old.as_ref());
        e["new"] = entry_json(c.new.as_ref());
        bytes += e.to_string().len();
        entries.push(e);
        if bytes >= page_bytes {
            break;
        }
    }
    let mut rest: Vec<Version> = heap.into_iter().map(|(_, id, path, depth)| Version { id, depth, path }).collect();
    rest.sort();
    if !took && n > 0 && !rest.is_empty() {
        return Err(Error::bad_request("this file history is too wide to page (more open lines than a cursor holds)"));
    }
    Ok((
        json!({
            "schema": "veil.history/1",
            "entries": entries,
            "truncated": !rest.is_empty(),
        }),
        rest,
    ))
}
