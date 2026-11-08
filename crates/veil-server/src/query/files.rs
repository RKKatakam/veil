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
//! versions, never the history's length. A request answers from the
//! **kept blame** of its version (`blame_memo`, per view key); a version
//! not kept yet is blamed by a **blame job** ([`wait_for_blame`]), one per
//! (view key, version, `follow`) across servers, in a bounded pool, in
//! memory, which the request waits for until its deadline (then
//! `warming`; the job goes on). A job keeps every [`CHECKPOINT`]th version
//! and the one asked for, so later blames of the file start from the
//! nearest; nothing else is persisted. Kept blames take at most 128 + 128
//! bytes a line (paths stored once per project, `blame_paths`) and
//! [`KEPT_BYTES`] a view key (BUG-1308: nothing one view key keeps drops
//! another's).
//!
//! **Boundary cuts** (§3.6) need nothing of their own: a source in a
//! folder the viewer cannot read is absent from their projected trees, so
//! a file moved or copied out of it is added there for them, and its lines
//! are the adding change's; a file moved into it is deleted.

use std::{
    cell::RefCell,
    collections::{BinaryHeap, HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

use axum::http::StatusCode;
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
        blame::{step, Blame, Meta, Origin, Text},
        changes::{self, path_key},
    },
    error::{Error, Result},
};

/// A version this far below the rows of its path read so far is read from
/// a window of its own (not by paging down from where the rows are).
const REANCHOR: i64 = 256;
/// Versions between two kept blames of one file (and every version asked
/// for is kept too).
pub const CHECKPOINT: u64 = 32;
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
    /// About the bytes of the rows its windows hold (a blame job counts
    /// them against its bound: BUG-1219).
    loaded: std::cell::Cell<usize>,
}

fn top_of(depth: i64) -> (i64, ObjectId) {
    (depth.saturating_add(1), ObjectId([0; 32]))
}

impl<'g, 'a> Files<'g, 'a> {
    pub fn new(g: &'g G<'a>) -> Files<'g, 'a> {
        Files {
            g,
            windows: RefCell::new(HashMap::new()),
            loaded: std::cell::Cell::new(0),
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
            // The row as held: its entries' names, its parents and the
            // window's slot and index entry.
            self.loaded.set(self.loaded.get() + 192 + c.len());
            let c: FChange = serde_json::from_str(&c).map_err(bad)?;
            w.at.insert(s, w.rows.len());
            w.rows.push((d, s, Arc::new(c)));
        }
        Ok(())
    }

    /// About the bytes of the file-history rows read so far.
    pub fn loaded_bytes(&self) -> usize {
        self.loaded.get()
    }

    /// The window of `path` holding rows at depth `depth`: the one read so
    /// far if it does, else a new one from just above `depth`.
    fn window(&self, path: &str, depth: i64) -> std::cell::RefMut<'_, Window> {
        let key = path_key(path);
        let mut ws = self.windows.borrow_mut();
        let fresh = ws.get(&key).is_none_or(|w| w.top.0 <= depth);
        if fresh {
            // The window itself, and its key.
            self.loaded.set(self.loaded.get() + 256 + key.len());
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
        // Far below the rows read so far: a window of its own, so that
        // reaching a deep version never costs the rows above it (BUG-1215).
        let last = w.rows.last().map(|(d, _, _)| *d).unwrap_or(w.top.0);
        if !w.at.contains_key(&id) && !w.done && last > depth.saturating_add(REANCHOR) {
            *w = Window {
                top: top_of(depth),
                rows: Vec::new(),
                at: HashMap::new(),
                done: false,
                pages: 0,
            };
        }
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
    /// Shared by every copy of the version (a walk's stack, order and
    /// edges): one path's bytes, however often it is named (BUG-1219).
    #[serde(with = "shared_str")]
    pub path: Arc<str>,
}

/// `Arc<str>` as a JSON string.
mod shared_str {
    use std::sync::Arc;

    pub fn serialize<S: serde::Serializer>(v: &Arc<str>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(v)
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Arc<str>, D::Error> {
        let s: String = serde::Deserialize::deserialize(d)?;
        Ok(Arc::from(s))
    }
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
            let q: Arc<str> = Arc::from(q);
            out[0] = qc.prev.first().copied().flatten().map(|(depth, id)| Version { id, depth, path: q });
        }
    }
    Ok(out)
}

// ---- blame ------------------------------------------------------------------------

/// What one blame job may hold, and a page show.
#[derive(Clone, Copy, Debug)]
pub struct BlameLimits {
    /// Bytes a job holds at once: the versions it walked, their texts and
    /// blames, the paths it interned and the kept blames it has not
    /// written yet (`too_wide` past it).
    pub held: usize,
    /// Lines a page shows.
    pub lines: usize,
    /// Bytes of kept blames one view key keeps; each write drops that view
    /// key's oldest past it (BUG-1218), and nothing else (BUG-1308).
    pub kept_bytes: usize,
    /// How long a job waits for another server's lease on its key before
    /// it ends `warming` (BUG-1307: it never computes without the lease).
    pub wait: Duration,
}

impl Default for BlameLimits {
    fn default() -> Self {
        BlameLimits {
            held: 64 << 20,
            lines: 10_000,
            kept_bytes: KEPT_BYTES,
            wait: JOB_WAIT,
        }
    }
}

/// Bytes of kept blames one view key of a project keeps (its oldest
/// dropped first). A project keeps at most this times the view keys in
/// use: one per distinct access (a person's groups and grants), not per
/// agent (a narrowed agent session has its person's view key).
pub const KEPT_BYTES: usize = 32 << 20;
/// About the most bytes of checkpoints one job writes: checkpoints are
/// spaced to keep to it (S14 cycle 3), at least [`CHECKPOINT`] versions
/// apart; a quarter of a view key's [`KEPT_BYTES`].
pub const JOB_CHECKPOINT_BYTES: u64 = 8 << 20;

/// The spacing of checkpoints (in version depth) for a job that computes
/// `versions` versions whose blames take about `bytes` each: a power of
/// two, at least [`CHECKPOINT`], so that their checkpoints take about
/// [`JOB_CHECKPOINT_BYTES`] at most (a power of two, so that jobs of
/// different starts mostly keep the same versions).
fn spacing(versions: u64, bytes: usize) -> u64 {
    (versions.saturating_mul(bytes as u64) / JOB_CHECKPOINT_BYTES).max(CHECKPOINT).next_power_of_two()
}
/// Kept blames written at once: at most this many bytes, or [`BATCH_BLAMES`].
const BATCH_BYTES: usize = 4 << 20;
const BATCH_BLAMES: usize = 64;

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
    /// Kept already (then nothing below it is walked).
    kept: bool,
    /// Versions above it, in this walk, not computed yet.
    left: usize,
}

/// A computed version: its text and blame (`None`: no plain-text version).
type Done = Option<(Arc<Text>, Arc<Blame>)>;

/// One viewer's blames: a blame job's work (S14 cycle 3), or a request's
/// reading of a kept blame. Everything a job holds is in memory, within
/// [`BlameLimits::held`]; nothing but kept blames outlives it.
pub struct Blamer<'f, 'g, 'a, 'h, 'b> {
    pub f: &'f Files<'g, 'a>,
    pub t: &'f Trees<'h, 'b>,
    pub follow: bool,
    pub limits: BlameLimits,
    /// The versions kept, by path key.
    kept: HashMap<String, HashSet<ObjectId>>,
    /// Every path the job's blames name, interned once (S14 cycle 3), and
    /// the bytes they take.
    paths: HashMap<String, Arc<str>>,
    path_bytes: usize,
    /// What an answer shows of each snapshot the job's blames name.
    metas: HashMap<ObjectId, Arc<Meta>>,
    renames: HashMap<ObjectId, Option<String>>,
    /// A job's lease: once it is not live, the job stops at its next
    /// version (BUG-1307).
    pub lease: Option<Arc<Lease>>,
    /// Kept blames to write: `(path key, snapshot, bytes, the path keys
    /// they name)`, and the paths they name; [`Blamer::pending_bytes`] of
    /// them.
    writes: Vec<(String, ObjectId, Vec<u8>, String)>,
    write_paths: HashMap<String, String>,
    pending_bytes: usize,
}

impl<'f, 'g, 'a, 'h, 'b> Blamer<'f, 'g, 'a, 'h, 'b> {
    pub fn new(f: &'f Files<'g, 'a>, t: &'f Trees<'h, 'b>, follow: bool, limits: BlameLimits) -> Self {
        Blamer {
            f,
            t,
            follow,
            limits,
            kept: HashMap::new(),
            paths: HashMap::new(),
            path_bytes: 0,
            metas: HashMap::new(),
            renames: HashMap::new(),
            lease: None,
            writes: Vec::new(),
            write_paths: HashMap::new(),
            pending_bytes: 0,
        }
    }

    /// Is `v`'s blame kept? (The kept versions of the path are read at
    /// once, in one statement.)
    pub fn is_kept(&mut self, v: &Version) -> Result<bool> {
        let key = path_key(&v.path);
        if !self.kept.contains_key(&key) {
            let g = self.f.g;
            let cx = g.cx;
            g.tick()?;
            let rows: Vec<String> = cx.db(|| {
                sqlx::query_scalar("SELECT snapshot FROM blame_memo WHERE project_id = $1 AND view_key = $2 AND path_key = $3 AND follow = $4")
                    .bind(cx.project())
                    .bind(g.vk)
                    .bind(&key)
                    .bind(self.follow)
                    .fetch_all(&cx.hub().db)
            })?;
            let set = rows.iter().map(|s| ObjectId::from_hex(s).map_err(bad)).collect::<Result<_>>()?;
            self.kept.insert(key.clone(), set);
        }
        Ok(self.kept[&key].contains(&v.id))
    }

    /// What the job holds besides its walk and blames (BUG-1219): the
    /// file-history rows read, the renames found, the kept versions read,
    /// and the paths and snapshot details its blames name.
    fn side_bytes(&self) -> usize {
        let renames: usize = self.renames.values().map(|r| 96 + r.as_ref().map_or(0, |r| r.len())).sum();
        let kept: usize = self.kept.iter().map(|(k, s)| 96 + k.len() + s.len() * 48).sum();
        self.f.loaded_bytes() + renames + kept + self.path_bytes + self.metas.len() * 512
    }

    /// Stop if the job's lease was lost (BUG-1307).
    fn stopped(&self) -> Result<()> {
        if self.lease.as_ref().is_some_and(|l| !l.live()) {
            return Err(warming());
        }
        Ok(())
    }

    /// The interned path `p`.
    fn intern(&mut self, p: &str) -> Arc<str> {
        if let Some(a) = self.paths.get(p) {
            return a.clone();
        }
        let a: Arc<str> = Arc::from(p);
        self.path_bytes += 64 + p.len();
        self.paths.insert(p.to_string(), a.clone());
        a
    }

    /// What an answer shows of the viewer's snapshot `id`.
    fn meta(&mut self, id: &ObjectId) -> Result<Arc<Meta>> {
        if let Some(m) = self.metas.get(id) {
            return Ok(m.clone());
        }
        let g = self.f.g;
        let m = Arc::new(Meta::of(&*g.snapshot(id)?, g.get(id)?.generation));
        self.metas.insert(*id, m.clone());
        Ok(m)
    }

    /// The kept blame of `v`, if it is (still) kept: one statement, the
    /// blame and the paths it names (S14 cycle 3: an answer reads nothing
    /// else of history).
    pub fn kept_blame(&mut self, v: &Version) -> Result<Option<Blame>> {
        let g = self.f.g;
        let cx = g.cx;
        g.tick()?;
        let row: Option<(Vec<u8>, Vec<String>)> = cx.db(|| {
            sqlx::query_as(
                "SELECT m.body, ARRAY(SELECT p.path_key || ':' || p.path FROM blame_paths p \
                     WHERE p.project_id = m.project_id AND p.path_key = ANY(string_to_array(m.path_keys, ','))) \
                 FROM blame_memo m WHERE m.project_id = $1 AND m.view_key = $2 AND m.path_key = $3 AND m.follow = $4 AND m.snapshot = $5",
            )
            .bind(cx.project())
            .bind(g.vk)
            .bind(path_key(&v.path))
            .bind(self.follow)
            .bind(v.id.hex())
            .fetch_optional(&cx.hub().db)
        })?;
        let Some((body, named)) = row else { return Ok(None) };
        let mut by_key: HashMap<String, Arc<str>> = HashMap::new();
        for kp in named {
            let (k, p) = kp.split_once(':').ok_or_else(|| bad("a stored path"))?;
            let a = self.intern(p);
            by_key.insert(k.to_string(), a);
        }
        let b = Blame::decode(&body, MAX_LINES, |k| by_key.get(k).cloned())?;
        for (id, _, m) in &b.origins {
            self.metas.entry(*id).or_insert_with(|| m.clone());
        }
        Ok(Some(b))
    }

    /// What the walk down needs of version `v`: its change, the versions
    /// it came from (none when its blame is kept, or it is not text), and
    /// whether it is kept.
    #[allow(clippy::type_complexity)]
    fn expand(&mut self, v: &Version) -> Result<(Arc<FChange>, Vec<Option<Version>>, bool)> {
        let change = self.f.find(&v.path, v.depth, v.id)?.ok_or_else(|| bad(format!("no row for a version at {}", v.id.short())))?;
        let kept = texty(&change.new) && self.is_kept(v)?;
        let parents = if texty(&change.new) && !kept {
            parents_of(self.f, self.t, v, &change, self.follow, &mut self.renames)?
        } else {
            Vec::new()
        };
        Ok((change, parents, kept))
    }

    /// The text of entry `e`, if it is plain text the server may read.
    pub fn text(&self, e: &Option<TreeEntry>) -> Result<Option<Arc<Text>>> {
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

    /// A blame job: blame version `start` (and keep it), walking down to
    /// kept blames or the file's first version and back up, in memory;
    /// `None` when it is not plain text. What it kept is written, also
    /// when it fails.
    pub fn blame(&mut self, start: &Version) -> Result<Done> {
        let r = self.run(start);
        let w = self.write();
        let out = r?;
        w?;
        Ok(out)
    }

    fn run(&mut self, start: &Version) -> Result<Done> {
        // Down: the versions to compute, parents before children, each
        // once, stopping at kept blames.
        let mut nodes: HashMap<Version, Node> = HashMap::new();
        let mut order: Vec<Version> = Vec::new();
        let mut stack: Vec<(Version, bool)> = vec![(start.clone(), false)];
        // What the walk holds (BUG-1219): every version's node, key and
        // slot in `order`, its parents and their stack entries (paths are
        // shared: each counted once, where it is made), the file-history
        // rows read, the renames found, and the projector's trees (reset
        // after each use).
        const VERSION: usize = std::mem::size_of::<Version>() + 16;
        let mut held = 0usize;
        let mut paths: HashSet<*const u8> = HashSet::new();
        let mut path_bytes = 0usize;
        while let Some((v, ready)) = stack.pop() {
            if ready {
                order.push(v);
                continue;
            }
            if nodes.contains_key(&v) {
                continue;
            }
            self.stopped()?;
            let (change, parents, kept) = self.expand(&v)?;
            self.t.forget_now();
            held += 3 * VERSION + std::mem::size_of::<Node>() + 64 + parents.len() * 2 * VERSION;
            for p in std::iter::once(&v.path).chain(parents.iter().flatten().map(|p| &p.path)) {
                if paths.insert(Arc::as_ptr(p) as *const u8) {
                    path_bytes += 32 + p.len();
                }
            }
            if held + path_bytes + self.side_bytes() > self.limits.held {
                return Err(too_wide());
            }
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
        held += path_bytes;
        // Up: each version from its parents', each dropped once every
        // version above it is computed; kept as it goes.
        let mut done: HashMap<Version, Done> = HashMap::new();
        let computed = nodes.values().filter(|n| !n.kept).count() as u64;
        for v in order {
            let (change, parents, kept) = {
                let n = &nodes[&v];
                (n.change.clone(), n.parents.clone(), n.kept)
            };
            let out: Done = if kept {
                match (self.kept_blame(&v)?, self.text(&change.new)?) {
                    (Some(b), Some(t)) if t.lines.len() == b.lines.len() => Some((t, Arc::new(b))),
                    (Some(_), Some(_)) => return Err(bad("a kept blame does not match its version")),
                    (_, None) => None,
                    // Dropped since (the view key's cap): computed again,
                    // from scratch below it.
                    (None, Some(_)) => return Err(Error::new(StatusCode::SERVICE_UNAVAILABLE, "warming", "this blame is being prepared; try again in a few seconds")),
                }
            } else {
                match self.text(&change.new)? {
                    None => None,
                    Some(text) => {
                        let inputs: Vec<Option<(&Text, &Blame)>> =
                            parents.iter().map(|p| p.as_ref().and_then(|p| done.get(p)).and_then(|d| d.as_ref()).map(|(t, b)| (&**t, &**b))).collect();
                        self.stopped()?;
                        let me: Origin = (v.id, self.intern(&v.path), self.meta(&v.id)?);
                        let (b, _) = step(&me, &text, &inputs);
                        self.f.g.cx.hub().query.blame_steps.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let b = Arc::new(b);
                        if b.vd % spacing(computed, b.stored_estimate()) == 0 || v == *start {
                            self.keep(&v, &b);
                        }
                        Some((text, b))
                    }
                }
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
            if held + self.pending_bytes + self.side_bytes() > self.limits.held {
                return Err(too_wide());
            }
            if self.writes.len() >= BATCH_BLAMES || self.pending_bytes >= BATCH_BYTES.min(self.limits.held / 4) {
                self.write()?;
            }
        }
        Ok(done.remove(start).flatten())
    }

    /// Keep blame `b` of version `v` (written with the next batch).
    fn keep(&mut self, v: &Version, b: &Blame) {
        let raw = b.encode(path_key);
        self.pending_bytes += raw.len() + 128;
        let mut named: Vec<String> = Vec::new();
        let mut seen: HashSet<*const u8> = HashSet::new();
        for (_, p, _) in &b.origins {
            if !seen.insert(Arc::as_ptr(p) as *const u8) {
                continue;
            }
            let k = path_key(p);
            if !self.write_paths.contains_key(&k) {
                self.pending_bytes += p.len() + 64;
                self.write_paths.insert(k.clone(), p.to_string());
            }
            named.push(k);
        }
        named.sort();
        named.dedup();
        self.pending_bytes += named.len() * 33;
        self.writes.push((path_key(&v.path), v.id, raw, named.join(",")));
    }

    /// Write the kept blames held: their paths, then the blames; then drop
    /// the view key's oldest past [`BlameLimits::kept_bytes`] (BUG-1218;
    /// only the view key's own: BUG-1308).
    fn write(&mut self) -> Result<()> {
        if self.writes.is_empty() {
            return Ok(());
        }
        let w = std::mem::take(&mut self.writes);
        let paths = std::mem::take(&mut self.write_paths);
        self.pending_bytes = 0;
        let cx = self.f.g.cx;
        let (pool, project, vk) = (&cx.hub().db, cx.project(), self.f.g.vk);
        let (pk, pp): (Vec<String>, Vec<String>) = paths.into_iter().unzip();
        for (k, p) in pk.chunks(ROWS_PER_STATEMENT).zip(pp.chunks(ROWS_PER_STATEMENT)) {
            cx.db(|| {
                sqlx::query("INSERT INTO blame_paths (project_id, path_key, path) SELECT $1, * FROM UNNEST($2::text[], $3::text[]) ON CONFLICT DO NOTHING")
                    .bind(project)
                    .bind(k)
                    .bind(p)
                    .execute(pool)
            })?;
        }
        // One statement for the batch, then one for the view key's cap.
        let now = veil_core::now_millis();
        let keys: Vec<&str> = w.iter().map(|r| r.0.as_str()).collect();
        let snaps: Vec<String> = w.iter().map(|r| r.1.hex()).collect();
        let bodies: Vec<&[u8]> = w.iter().map(|r| r.2.as_slice()).collect();
        let sizes: Vec<i64> = w.iter().map(|r| r.2.len() as i64).collect();
        let named: Vec<&str> = w.iter().map(|r| r.3.as_str()).collect();
        cx.db(|| {
            sqlx::query(
                "INSERT INTO blame_memo (project_id, view_key, path_key, follow, snapshot, body, bytes, created_at, path_keys) \
                 SELECT $1, $2, k, $3, s, b, n, $4, p FROM UNNEST($5::text[], $6::text[], $7::bytea[], $8::bigint[], $9::text[]) AS t(k, s, b, n, p) \
                 ON CONFLICT DO NOTHING",
            )
            .bind(project)
            .bind(vk)
            .bind(self.follow)
            .bind(now)
            .bind(&keys)
            .bind(&snaps)
            .bind(&bodies)
            .bind(&sizes)
            .bind(&named)
            .execute(pool)
        })?;
        cx.db(|| {
            sqlx::query(
                "DELETE FROM blame_memo WHERE project_id = $1 AND view_key = $2 AND (path_key, follow, snapshot) IN ( \
                     SELECT path_key, follow, snapshot FROM ( \
                         SELECT path_key, follow, snapshot, \
                             SUM(bytes) OVER (ORDER BY created_at DESC, path_key, follow, snapshot) AS kept \
                         FROM blame_memo WHERE project_id = $1 AND view_key = $2) t \
                     WHERE kept > $3)",
            )
            .bind(project)
            .bind(vk)
            .bind(self.limits.kept_bytes as i64)
            .execute(pool)
        })?;
        for (k, s, _, _) in w {
            self.kept.entry(k).or_default().insert(s);
        }
        Ok(())
    }
}

/// The page of the kept blame of `start` (path `start.path` at the
/// viewer's snapshot `rev`), if it is kept: what a request answers.
#[allow(clippy::too_many_arguments)]
pub fn kept_answer(f: &Files, t: &Trees, rev: ObjectId, start: &Version, follow: bool, after: usize, n: usize, limits: BlameLimits) -> Result<Option<Value>> {
    let mut b = Blamer::new(f, t, follow, limits);
    let Some(bl) = b.kept_blame(start)? else { return Ok(None) };
    let change = f.find(&start.path, start.depth, start.id)?.ok_or_else(|| bad("no row for the version asked"))?;
    let Some(text) = b.text(&change.new)? else { return Ok(None) };
    if text.lines.len() != bl.lines.len() {
        return Err(bad("a kept blame does not match its version"));
    }
    blame_json(f.g, rev, &start.path, follow, &text, &bl, after, n).map(Some)
}

// ---- blame jobs -------------------------------------------------------------------

/// Blame jobs computing at once in one server (each runs its statements
/// one at a time: at most this many of the pool's connections, and only
/// while a statement runs). A freed slot goes to the next project in turn
/// with a job waiting for one (BUG-1306).
pub const BLAME_JOBS: usize = 2;
/// Blame jobs one project may have waiting in one server, past which its
/// requests answer `warming` without queuing one (BUG-1306: a project
/// fills its own share only).
pub const MAX_PENDING_JOBS: usize = 256;
/// Blame jobs waiting in one server, all projects: past it, a project
/// below its fair share (this ÷ the projects with jobs waiting) still
/// queues, up to twice this in all.
pub const MAX_PENDING_ALL: usize = 4096;
/// A job's lease on its key: how long it lasts unless renewed, how often
/// it is, how long before its end a holder stops computing (clocks of
/// servers may differ a little), and how long a job waits for another
/// server's (then it ends `warming`, never computing: BUG-1307).
const JOB_LEASE: Duration = Duration::from_secs(120);
const JOB_RENEW: Duration = Duration::from_secs(30);
const JOB_MARGIN: Duration = Duration::from_secs(20);
const JOB_WAIT: Duration = Duration::from_secs(600);
/// Too-wide records a view key keeps (BUG-1309; its oldest dropped).
const KEPT_ENDS: i64 = 4096;

/// How a blame job ended, for every request waiting on it.
#[derive(Clone, Debug)]
pub enum JobEnd {
    /// Kept (or found kept, by another server's job).
    Kept,
    /// The version holds no plain text.
    NoText,
    Failed(StatusCode, &'static str, String),
}

impl JobEnd {
    fn of(r: Result<bool>) -> JobEnd {
        match r {
            Ok(true) => JobEnd::Kept,
            Ok(false) => JobEnd::NoText,
            Err(Error::Api { status, code, message }) => JobEnd::Failed(status, code, message),
            Err(e) => JobEnd::Failed(StatusCode::INTERNAL_SERVER_ERROR, "internal", format!("{e:?}")),
        }
    }

    fn too_wide() -> JobEnd {
        JobEnd::of(Err(too_wide()))
    }
}

/// A job's key: project, view key, path key, `follow`, snapshot.
pub type JobKey = (i64, String, String, bool, ObjectId);
type JobRx = tokio::sync::watch::Receiver<Option<JobEnd>>;

/// The blame jobs of one server.
pub struct Jobs {
    waiting: std::sync::Mutex<Waiting>,
    slots: Arc<Slots>,
    /// Jobs started here (the tests count them).
    pub started: std::sync::atomic::AtomicU64,
}

#[derive(Default)]
struct Waiting {
    jobs: HashMap<JobKey, JobRx>,
    /// Jobs waiting, by project.
    per: HashMap<i64, usize>,
}

impl Default for Jobs {
    fn default() -> Self {
        Jobs {
            waiting: std::sync::Mutex::new(Waiting::default()),
            slots: Arc::new(Slots { state: std::sync::Mutex::new(SlotState { free: BLAME_JOBS, queues: std::collections::BTreeMap::new(), last: i64::MIN }) }),
            started: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

/// This server's [`BLAME_JOBS`] slots, handed out fairly (BUG-1306): a
/// freed slot goes to the project after the one last served, in turn,
/// among those with a job waiting (first come first served within one).
struct Slots {
    state: std::sync::Mutex<SlotState>,
}

struct SlotState {
    free: usize,
    queues: std::collections::BTreeMap<i64, std::collections::VecDeque<tokio::sync::oneshot::Sender<Slot>>>,
    last: i64,
}

/// A slot held; given back (to the next in turn) when dropped.
struct Slot {
    slots: Option<Arc<Slots>>,
}

impl Drop for Slot {
    fn drop(&mut self) {
        if let Some(s) = self.slots.take() {
            Slots::give(s);
        }
    }
}

impl Slots {
    async fn take(self: &Arc<Self>, project: i64) -> Slot {
        let rx = {
            let mut st = self.state.lock().unwrap();
            // A free slot means nobody (still) waits: a freed one goes to a
            // waiter first.
            if st.free > 0 {
                st.free -= 1;
                st.last = project;
                return Slot { slots: Some(self.clone()) };
            }
            let (tx, rx) = tokio::sync::oneshot::channel();
            st.queues.entry(project).or_default().push_back(tx);
            rx
        };
        // A sender is dropped only once sent (a job's task is never
        // cancelled while it waits).
        rx.await.expect("a blame slot")
    }

    fn give(me: Arc<Self>) {
        let mut guard = me.state.lock().unwrap();
        let st = &mut *guard;
        loop {
            let next = st.queues.range(st.last.saturating_add(1)..).next().or_else(|| st.queues.iter().next()).map(|(p, _)| *p);
            let Some(p) = next else {
                st.free += 1;
                return;
            };
            let q = st.queues.get_mut(&p).unwrap();
            let tx = q.pop_front().unwrap();
            if q.is_empty() {
                st.queues.remove(&p);
            }
            st.last = p;
            match tx.send(Slot { slots: Some(me.clone()) }) {
                Ok(()) => return,
                // The waiter left: the next in turn.
                Err(mut s) => s.slots = None,
            }
        }
    }
}

/// A job's hold of its key's lease (BUG-1307): lost when a renewal finds
/// the row taken over, or when the lease's end (less `JOB_MARGIN`)
/// passes without a renewal. A job computes only while it is live, and
/// checks at every version.
pub struct Lease {
    lost: std::sync::atomic::AtomicBool,
    /// Milliseconds: past this, the job stops.
    until: std::sync::atomic::AtomicI64,
}

impl Lease {
    fn new(now: i64) -> Lease {
        Lease { lost: Default::default(), until: std::sync::atomic::AtomicI64::new(now + (JOB_LEASE - JOB_MARGIN).as_millis() as i64) }
    }

    pub fn live(&self) -> bool {
        !self.lost.load(std::sync::atomic::Ordering::Relaxed) && veil_core::now_millis() < self.until.load(std::sync::atomic::Ordering::Relaxed)
    }
}

fn warming() -> Error {
    Error::new(StatusCode::SERVICE_UNAVAILABLE, "warming", "this blame is being prepared; try again in a few seconds")
}

/// Wait, until `deadline`, for the blame of `start` to be kept: answer
/// from a record that it is too wide (BUG-1309), or start its job, or join
/// the one running here (and through its lease, another server's). The
/// job goes on when the wait ends (`warming`).
pub async fn wait_for_blame(
    hub: &Arc<crate::Hub>,
    project: &crate::perm::Project,
    viewer: &crate::perm::Viewer,
    start: &Version,
    follow: bool,
    limits: BlameLimits,
    deadline: std::time::Instant,
) -> Result<JobEnd> {
    let vk = project.view(viewer).key();
    let key: JobKey = (project.id, vk, path_key(&start.path), follow, start.id);
    let joined = hub.query.jobs.waiting.lock().unwrap().jobs.get(&key).cloned();
    let mut rx = match joined {
        Some(rx) => rx,
        None => {
            if let Some(end) = settled(hub, &key, limits).await? {
                return Ok(end);
            }
            let mut w = hub.query.jobs.waiting.lock().unwrap();
            match w.jobs.get(&key) {
                Some(rx) => rx.clone(),
                None => {
                    let mine = w.per.get(&project.id).copied().unwrap_or(0);
                    let busy = w.per.len() + usize::from(mine == 0);
                    let all = w.jobs.len();
                    if mine >= MAX_PENDING_JOBS || (all >= MAX_PENDING_ALL && (mine >= MAX_PENDING_ALL / busy || all >= 2 * MAX_PENDING_ALL)) {
                        return Err(warming());
                    }
                    let (tx, rx) = tokio::sync::watch::channel(None);
                    w.jobs.insert(key.clone(), rx.clone());
                    *w.per.entry(project.id).or_default() += 1;
                    drop(w);
                    hub.query.jobs.started.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let (hub, project, viewer, start) = (hub.clone(), project.clone(), viewer.clone(), start.clone());
                    tokio::spawn(async move {
                        let r = leased_job(&hub, &project, &viewer, &key, &start, follow, limits).await;
                        if let Err(e) = &r {
                            if !matches!(e, Error::Api { code: "warming" | "too_wide", .. }) {
                                eprintln!("veil-server: a blame job of project {}: {e:?}", project.id);
                            }
                        }
                        {
                            let mut w = hub.query.jobs.waiting.lock().unwrap();
                            w.jobs.remove(&key);
                            if let Some(n) = w.per.get_mut(&project.id) {
                                *n -= 1;
                                if *n == 0 {
                                    w.per.remove(&project.id);
                                }
                            }
                        }
                        let _ = tx.send(Some(JobEnd::of(r)));
                    });
                    rx
                }
            }
        }
    };
    let done = async { rx.wait_for(|d| d.is_some()).await.ok().and_then(|d| d.clone()) };
    match tokio::time::timeout_at(deadline.into(), done).await {
        Ok(Some(end)) => Ok(end),
        Ok(None) => Err(warming()),
        Err(_) => Err(warming()),
    }
}

/// How the job of `key` ended already, if it did (one statement): its
/// blame kept, or recorded too wide under a bound no smaller than
/// `limits.held` (BUG-1309).
async fn settled(hub: &crate::Hub, key: &JobKey, limits: BlameLimits) -> Result<Option<JobEnd>> {
    let (kept, wide): (bool, bool) = sqlx::query_as(
        "SELECT EXISTS (SELECT 1 FROM blame_memo WHERE project_id = $1 AND view_key = $2 AND path_key = $3 AND follow = $4 AND snapshot = $5), \
                EXISTS (SELECT 1 FROM blame_ends WHERE project_id = $1 AND view_key = $2 AND path_key = $3 AND follow = $4 AND snapshot = $5 AND held >= $6)",
    )
    .bind(key.0)
    .bind(&key.1)
    .bind(&key.2)
    .bind(key.3)
    .bind(key.4.hex())
    .bind(limits.held as i64)
    .fetch_one(&hub.db)
    .await?;
    Ok(if kept {
        Some(JobEnd::Kept)
    } else if wide {
        Some(JobEnd::too_wide())
    } else {
        None
    })
}

/// Record that the blame of `key` passed the memory bound `held`, and
/// drop the view key's oldest records past [`KEPT_ENDS`].
async fn record_too_wide(hub: &crate::Hub, key: &JobKey, held: usize) -> Result<()> {
    sqlx::query(
        "INSERT INTO blame_ends (project_id, view_key, path_key, follow, snapshot, held, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT (project_id, view_key, path_key, follow, snapshot) DO UPDATE SET held = GREATEST(blame_ends.held, EXCLUDED.held), created_at = EXCLUDED.created_at",
    )
    .bind(key.0)
    .bind(&key.1)
    .bind(&key.2)
    .bind(key.3)
    .bind(key.4.hex())
    .bind(held as i64)
    .bind(veil_core::now_millis())
    .execute(&hub.db)
    .await?;
    sqlx::query(
        "DELETE FROM blame_ends WHERE project_id = $1 AND view_key = $2 AND (path_key, follow, snapshot) IN ( \
             SELECT path_key, follow, snapshot FROM blame_ends WHERE project_id = $1 AND view_key = $2 \
             ORDER BY created_at DESC, path_key, follow, snapshot OFFSET $3)",
    )
    .bind(key.0)
    .bind(&key.1)
    .bind(KEPT_ENDS)
    .execute(&hub.db)
    .await?;
    Ok(())
}

/// The job, under its key's lease (`blame_jobs`: one server at a time),
/// in one of this server's [`BLAME_JOBS`] slots: whether it ended kept
/// (`false`: no plain text). It computes only while it holds the lease
/// (BUG-1307): it takes the lease first, keeps renewing it while it waits
/// for a slot and while it computes, and stops at its next version once a
/// renewal fails; a job waiting for another server's lease stops as soon
/// as that server's job ends, and after [`BlameLimits::wait`] ends
/// `warming`.
async fn leased_job(
    hub: &Arc<crate::Hub>,
    project: &crate::perm::Project,
    viewer: &crate::perm::Viewer,
    key: &JobKey,
    start: &Version,
    follow: bool,
    limits: BlameLimits,
) -> Result<bool> {
    let holder = hex::encode(veil_core::crypto::random_bytes::<16>());
    let take = || async {
        let now = veil_core::now_millis();
        let got: Option<String> = sqlx::query_scalar(
            "INSERT INTO blame_jobs (project_id, view_key, path_key, follow, snapshot, holder, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (project_id, view_key, path_key, follow, snapshot) DO UPDATE SET holder = EXCLUDED.holder, expires_at = EXCLUDED.expires_at \
             WHERE blame_jobs.expires_at < $8 RETURNING holder",
        )
        .bind(key.0)
        .bind(&key.1)
        .bind(&key.2)
        .bind(key.3)
        .bind(key.4.hex())
        .bind(&holder)
        .bind(now + JOB_LEASE.as_millis() as i64)
        .bind(now)
        .fetch_optional(&hub.db)
        .await?;
        Ok::<Option<i64>, Error>(got.map(|_| now))
    };
    let ended = |end: JobEnd| match end {
        JobEnd::Kept => Ok(true),
        JobEnd::NoText => Ok(false),
        JobEnd::Failed(status, code, message) => Err(Error::Api { status, code, message }),
    };
    if let Some(end) = settled(hub, key, limits).await? {
        return ended(end);
    }
    let wait = tokio::time::Instant::now() + limits.wait;
    let mut pause = Duration::from_millis(250);
    let taken = loop {
        if let Some(at) = take().await? {
            break at;
        }
        if tokio::time::Instant::now() >= wait {
            return Err(warming());
        }
        tokio::time::sleep(pause).await;
        pause = (pause * 2).min(Duration::from_secs(4));
        if let Some(end) = settled(hub, key, limits).await? {
            return ended(end);
        }
    };
    let lease = Arc::new(Lease::new(taken));
    let renew = {
        let (hub, key, holder, lease) = (hub.clone(), key.clone(), holder.clone(), lease.clone());
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(JOB_RENEW).await;
                let now = veil_core::now_millis();
                let r = sqlx::query(
                    "UPDATE blame_jobs SET expires_at = $1 WHERE project_id = $2 AND view_key = $3 AND path_key = $4 AND follow = $5 AND snapshot = $6 AND holder = $7",
                )
                .bind(now + JOB_LEASE.as_millis() as i64)
                .bind(key.0)
                .bind(&key.1)
                .bind(&key.2)
                .bind(key.3)
                .bind(key.4.hex())
                .bind(&holder)
                .execute(&hub.db)
                .await;
                match r {
                    Ok(r) if r.rows_affected() == 1 => lease.until.store(now + (JOB_LEASE - JOB_MARGIN).as_millis() as i64, std::sync::atomic::Ordering::Relaxed),
                    // Taken over: stop now. (A failed statement leaves the
                    // job until its lease's end, less the margin.)
                    Ok(_) => {
                        lease.lost.store(true, std::sync::atomic::Ordering::Relaxed);
                        return;
                    }
                    Err(_) => {}
                }
            }
        })
    };
    let r = async {
        let _slot = hub.query.jobs.slots.take(key.0).await;
        if let Some(end) = settled(hub, key, limits).await? {
            return ended(end);
        }
        if !lease.live() {
            return Err(warming());
        }
        let (project, viewer, vk, start, lease) = (project.clone(), viewer.clone(), key.1.clone(), start.clone(), lease.clone());
        super::graph::blocking(hub, project.id, move |cx| {
            let g = G::new(cx, &vk, None);
            let view = project.view(&viewer);
            let t = Trees::new(&g, &view);
            let f = Files::new(&g);
            let mut b = Blamer::new(&f, &t, follow, limits);
            b.lease = Some(lease);
            Ok(b.blame(&start)?.is_some())
        })
        .await
    }
    .await;
    renew.abort();
    if matches!(r, Err(Error::Api { code: "too_wide", .. })) {
        record_too_wide(hub, key, limits.held).await?;
    }
    let _ = sqlx::query("DELETE FROM blame_jobs WHERE project_id = $1 AND view_key = $2 AND path_key = $3 AND follow = $4 AND snapshot = $5 AND holder = $6")
        .bind(key.0)
        .bind(&key.1)
        .bind(&key.2)
        .bind(key.3)
        .bind(key.4.hex())
        .bind(&holder)
        .execute(&hub.db)
        .await;
    r
}

/// The JSON of blame `b` of `text` (path `path` at snapshot `rev`): lines
/// `after + 1` on, at most `n`, each with its origin, and the changes they
/// name, newest first (the viewer's generations).
#[allow(clippy::too_many_arguments)]
pub fn blame_json(_g: &G, rev: ObjectId, path: &str, follow: bool, text: &Text, b: &Blame, after: usize, n: usize) -> Result<Value> {
    let total = text.lines.len();
    let from = after.min(total);
    let to = from.saturating_add(n).min(total);
    let mut lines = Vec::with_capacity(to - from);
    // What an answer shows of each change is kept with the blame (S14
    // cycle 3): no snapshot is read here.
    let mut named: HashMap<ObjectId, Arc<Meta>> = HashMap::new();
    for i in from..to {
        let (id, p, l) = b.origin(i);
        let m = b.meta(i);
        named.entry(*id).or_insert_with(|| m.clone());
        let raw = text.line(i);
        let raw = raw.strip_suffix(b"\n").unwrap_or(raw);
        let raw = raw.strip_suffix(b"\r").unwrap_or(raw);
        lines.push(json!({
            "line": i + 1,
            "text": String::from_utf8_lossy(raw),
            "snapshot": id.hex(),
            "change": m.change_id,
            "change_short": m.change_id.get(..8).unwrap_or(&m.change_id),
            "path": p,
            "origin_line": l,
        }));
    }
    let mut order: Vec<(i64, ObjectId)> = named.iter().map(|(id, m)| (m.generation, *id)).collect();
    order.sort_by(|a, b| b.cmp(a));
    let changes: Vec<Value> = order
        .iter()
        .map(|(_, id)| {
            let m = &named[id];
            json!({
                "snapshot_id": id.hex(),
                "snapshot_short": id.short(),
                "change_id": m.change_id,
                "change_short": m.change_id.get(..8).unwrap_or(&m.change_id),
                "author": m.author,
                "timestamp": m.timestamp,
                "summary": m.summary,
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
    let mut heap: BinaryHeap<(i64, ObjectId, Arc<str>, i64)> = BinaryHeap::new();
    let mut queued: HashSet<(ObjectId, Arc<str>)> = HashSet::new();
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

#[cfg(test)]
mod tests {
    use super::*;

    /// BUG-1306: a freed slot goes to the next project in turn, not to the
    /// project that queued the most first.
    #[test]
    fn slots_go_to_projects_in_turn() {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let slots = Arc::new(Slots { state: std::sync::Mutex::new(SlotState { free: 1, queues: Default::default(), last: i64::MIN }) });
            let held = slots.take(1).await;
            let order = Arc::new(std::sync::Mutex::new(Vec::new()));
            let mut tasks = Vec::new();
            for p in [1, 1, 1, 2, 3] {
                let (slots, order) = (slots.clone(), order.clone());
                tasks.push(tokio::spawn(async move {
                    let s = slots.take(p).await;
                    order.lock().unwrap().push(p);
                    drop(s);
                }));
                tokio::task::yield_now().await;
            }
            drop(held);
            for t in tasks {
                t.await.unwrap();
            }
            assert_eq!(*order.lock().unwrap(), vec![2, 3, 1, 1, 1]);
            assert_eq!(slots.state.lock().unwrap().free, 1, "every slot given back");
        });
    }

    /// BUG-1307: a lease not renewed stops being live before it ends (less
    /// the margin), and a lost one at once.
    #[test]
    fn a_lease_not_renewed_is_not_live() {
        let now = veil_core::now_millis();
        assert!(Lease::new(now).live());
        assert!(!Lease::new(now - (JOB_LEASE - JOB_MARGIN).as_millis() as i64).live());
        let l = Lease::new(now);
        l.lost.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(!l.live());
    }
}
