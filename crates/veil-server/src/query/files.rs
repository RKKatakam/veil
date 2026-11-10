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
        blame::{Blame, Meta, Origin, Text},
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
const PAGES: [i64; 3] = [64, 512, 1000];
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
    /// How long a job's lease lasts unless renewed: it is renewed every
    /// quarter of this, and a holder stops computing a sixth of it before
    /// its end without a renewal (clocks of servers may differ a little).
    pub lease: Duration,
}

impl Default for BlameLimits {
    fn default() -> Self {
        BlameLimits {
            held: 64 << 20,
            lines: 10_000,
            kept_bytes: KEPT_BYTES,
            wait: JOB_WAIT,
            lease: JOB_LEASE,
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

/// A blame larger than one kept blame may be (BUG-1411).
fn too_large() -> Error {
    Error::new(StatusCode::UNPROCESSABLE_ENTITY, "too_wide", "this file's blame is larger than the server keeps for one blame")
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
    /// The path keys of the versions the walk reached: a too-wide record
    /// names them, and is dropped when blames of any of them are kept
    /// (BUG-1412).
    pub reached: HashSet<String>,
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
            reached: HashSet::new(),
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
        if !blob || bytes.len() as u64 > MAX_TEXT_BYTES || std::ffi::CStr::from_bytes_until_nul(&bytes).is_ok() || std::str::from_utf8(&bytes).is_err() {
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
        // Containers are counted by their capacity (a hash map or vector
        // holds up to twice what it has in it).
        const VERSION: usize = std::mem::size_of::<Version>();
        const SLOT: usize = std::mem::size_of::<(Version, Node)>() + 1;
        let mut held = 0usize;
        let mut paths: HashSet<*const u8> = HashSet::new();
        let mut path_bytes = 0usize;
        let walk = |nodes: &HashMap<Version, Node>, order: &Vec<Version>, stack: &Vec<(Version, bool)>, paths: &HashSet<*const u8>| {
            nodes.capacity() * SLOT + order.capacity() * VERSION + stack.capacity() * (VERSION + 8) + paths.capacity() * 9
        };
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
            // Each node's parents (its own vector) and their copies in
            // `edges` below.
            held += parents.capacity() * std::mem::size_of::<Option<Version>>() + parents.len() * VERSION + 32;
            for p in std::iter::once(&v.path).chain(parents.iter().flatten().map(|p| &p.path)) {
                if paths.insert(Arc::as_ptr(p) as *const u8) {
                    path_bytes += 32 + p.len();
                    if self.reached.insert(path_key(p)) {
                        path_bytes += 96;
                    }
                }
            }
            if held + path_bytes + walk(&nodes, &order, &stack, &paths) + self.side_bytes() > self.limits.held {
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
        held += path_bytes + walk(&nodes, &order, &stack, &paths);
        // Up: each version from its parents', each dropped once every
        // version above it is computed; kept as it goes.
        let mut done: HashMap<Version, Done> = HashMap::new();
        let computed = nodes.values().filter(|n| !n.kept).count() as u64;
        // First load the kept blames at the bottom of the walk.
        for v in &order {
            let n = &nodes[v];
            if !n.kept {
                continue;
            }
            let out: Done = match (self.kept_blame(v)?, self.text(&n.change.new)?) {
                (Some(b), Some(t)) if t.lines.len() == b.lines.len() => Some((t, Arc::new(b))),
                (Some(_), Some(_)) => return Err(bad("a kept blame does not match its version")),
                (_, None) => None,
                // Dropped since (the view key's cap): computed again,
                // from scratch below it.
                (None, Some(_)) => return Err(Error::new(StatusCode::SERVICE_UNAVAILABLE, "warming", "this blame is being prepared; try again in a few seconds")),
            };
            if let Some((t, b)) = &out {
                held += t.weight() + b.weight();
            }
            done.insert(v.clone(), out);
            if held + done.capacity() * (std::mem::size_of::<(Version, Done)>() + 1) + self.pending_bytes + self.side_bytes() > self.limits.held {
                return Err(too_wide());
            }
        }
        // Process unkept versions in chunks so texts, snapshot metadata, and
        // parent-to-child line diffs are computed in parallel across a bounded
        // pool while keeping memory strictly within `self.limits.held`.
        let unkept: Vec<Version> = order.into_iter().filter(|v| !nodes[v].kept).collect();
        const CHUNK: usize = 128;
        const WORKERS: usize = 8;
        let src = &self.t.g.cx.src;
        let load_text = |e: &Option<TreeEntry>| -> Result<Option<Arc<Text>>> {
            if !texty(e) {
                return Ok(None);
            }
            let e = e.as_ref().unwrap();
            let raw = src.raw(&e.id)?;
            if !veil_core::object::Object::is_blob_raw(&raw) {
                return Ok(None);
            }
            let veil_core::object::Object::Blob(bytes) = veil_core::object::Object::decode(&raw)? else {
                return Ok(None);
            };
            if bytes.len() as u64 > MAX_TEXT_BYTES || std::ffi::CStr::from_bytes_until_nul(&bytes).is_ok() || std::str::from_utf8(&bytes).is_err() {
                return Ok(None);
            }
            Ok(Some(Text::new(e.id, bytes)))
        };
        let mut idx = 0usize;
        while idx < unkept.len() {
            self.stopped()?;
            // Take up to CHUNK versions whose texts fit well within the remaining held budget.
            let mut end = idx;
            let mut chunk_text_est = 0usize;
            while end < unkept.len() && end - idx < CHUNK {
                let sz = nodes[&unkept[end]].change.new.as_ref().map_or(0, |e| e.size as usize * 2 + 256);
                let budget_used = held + done.capacity() * (std::mem::size_of::<(Version, Done)>() + 1) + self.pending_bytes + self.side_bytes();
                if end > idx && budget_used + chunk_text_est + sz > self.limits.held.saturating_sub(self.limits.held / 8) {
                    break;
                }
                chunk_text_est += sz;
                end += 1;
            }
            let slice = &unkept[idx..end];
            idx = end;
            // 1. Load texts and snapshot metadata for all versions in `slice` in parallel.
            self.f.g.tick()?;
            let mut missing_metas: Vec<ObjectId> = slice
                .iter()
                .map(|v| v.id)
                .filter(|id| !self.metas.contains_key(id))
                .collect();
            missing_metas.sort_unstable();
            missing_metas.dedup();
            let mut gens: HashMap<ObjectId, i64> = HashMap::with_capacity(missing_metas.len());
            let mut db_ids: Vec<String> = Vec::new();
            for &id in &missing_metas {
                if id == super::graph::root() {
                    gens.insert(id, 0);
                } else {
                    db_ids.push(id.hex());
                }
            }
            if !db_ids.is_empty() {
                let cx = self.f.g.cx;
                let rows: Vec<(String, i64)> = cx.db(|| {
                    sqlx::query_as("SELECT snapshot, generation FROM view_graph WHERE project_id = $1 AND view_key = $2 AND snapshot = ANY($3)")
                        .bind(cx.project())
                        .bind(self.f.g.vk)
                        .bind(&db_ids)
                        .fetch_all(&cx.hub().db)
                })?;
                for (s, g) in rows {
                    if let Ok(id) = ObjectId::from_hex(&s) {
                        gens.insert(id, g);
                    }
                }
            }
            let entries: Vec<Option<TreeEntry>> = slice.iter().map(|v| nodes[v].change.new.clone()).collect();
            let (loaded_texts, loaded_snaps): (Vec<Result<Option<Arc<Text>>>>, Vec<Result<(ObjectId, Arc<veil_core::object::Snapshot>)>>) =
                if slice.len() <= 2 && missing_metas.len() <= 2 {
                    (
                        entries.iter().map(&load_text).collect(),
                        missing_metas.iter().map(|&id| Ok((id, src.snapshot(&id)?))).collect(),
                    )
                } else {
                    let next_t = std::sync::atomic::AtomicUsize::new(0);
                    let next_s = std::sync::atomic::AtomicUsize::new(0);
                    let out_t: Vec<std::sync::Mutex<Option<Result<Option<Arc<Text>>>>>> = (0..slice.len()).map(|_| std::sync::Mutex::new(None)).collect();
                    let out_s: Vec<std::sync::Mutex<Option<Result<(ObjectId, Arc<veil_core::object::Snapshot>)>>>> =
                        (0..missing_metas.len()).map(|_| std::sync::Mutex::new(None)).collect();
                    std::thread::scope(|s| {
                        for _ in 0..WORKERS.min(slice.len() + missing_metas.len()) {
                            s.spawn(|| {
                                loop {
                                    let i = next_t.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    if i >= entries.len() {
                                        break;
                                    }
                                    let r = load_text(&entries[i]);
                                    *out_t[i].lock().unwrap() = Some(r);
                                }
                                loop {
                                    let j = next_s.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    if j >= missing_metas.len() {
                                        break;
                                    }
                                    let id = missing_metas[j];
                                    let r = src.snapshot(&id).map(|sn| (id, sn)).map_err(Error::from);
                                    *out_s[j].lock().unwrap() = Some(r);
                                }
                            });
                        }
                    });
                    (
                        out_t.into_iter().map(|m| m.into_inner().unwrap().unwrap()).collect(),
                        out_s.into_iter().map(|m| m.into_inner().unwrap().unwrap()).collect(),
                    )
                };
            for r in loaded_snaps {
                let (id, sn) = r?;
                let gen = match gens.get(&id).copied() {
                    Some(g) => g,
                    None => self.f.g.get(&id)?.generation,
                };
                self.metas.insert(id, Arc::new(Meta::of(&sn, gen)));
            }
            let mut chunk_texts: HashMap<Version, Option<Arc<Text>>> = HashMap::with_capacity(slice.len());
            for (v, r) in slice.iter().zip(loaded_texts) {
                chunk_texts.insert(v.clone(), r?);
            }
            // 2. Precompute parent-to-child line diffs in parallel for all versions in `slice`.
            let mut diff_jobs: Vec<(Version, usize, Arc<Text>, Arc<Text>)> = Vec::new();
            for v in slice {
                let Some(Some(text)) = chunk_texts.get(v) else { continue };
                for (pi, p) in nodes[v].parents.iter().enumerate() {
                    let Some(p) = p else { continue };
                    let pt = chunk_texts
                        .get(p)
                        .and_then(|t| t.as_ref())
                        .or_else(|| done.get(p).and_then(|d| d.as_ref().map(|(t, _)| t)));
                    if let Some(pt) = pt {
                        diff_jobs.push((v.clone(), pi, pt.clone(), text.clone()));
                    }
                }
            }
            let mut pre_maps: HashMap<(Version, usize), crate::derive::blame::ParentMap> = HashMap::with_capacity(diff_jobs.len());
            if diff_jobs.len() <= 1 {
                for (v, pi, pt, text) in diff_jobs {
                    pre_maps.insert((v, pi), crate::derive::blame::diff_parent(&pt, &text));
                }
            } else {
                let next = std::sync::atomic::AtomicUsize::new(0);
                let out: Vec<std::sync::Mutex<Option<crate::derive::blame::ParentMap>>> = (0..diff_jobs.len()).map(|_| std::sync::Mutex::new(None)).collect();
                std::thread::scope(|s| {
                    for _ in 0..WORKERS.min(diff_jobs.len()) {
                        s.spawn(|| loop {
                            let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            if i >= diff_jobs.len() {
                                break;
                            }
                            let (_, _, ref pt, ref text) = diff_jobs[i];
                            let m = crate::derive::blame::diff_parent(pt, text);
                            *out[i].lock().unwrap() = Some(m);
                        });
                    }
                });
                for ((v, pi, _, _), m) in diff_jobs.into_iter().zip(out) {
                    pre_maps.insert((v, pi), m.into_inner().unwrap().unwrap());
                }
            }
            // 3. Propagate blames sequentially in topological order and maintain exact held accounting.
            for v in slice {
                let parents = nodes[v].parents.clone();
                let out: Done = match chunk_texts.remove(v).flatten() {
                    None => None,
                    Some(text) => {
                        self.stopped()?;
                        let inputs: Vec<Option<(&Blame, crate::derive::blame::ParentMap)>> = parents
                            .iter()
                            .enumerate()
                            .map(|(pi, p)| {
                                let p = p.as_ref()?;
                                let (_, pb) = done.get(p)?.as_ref()?;
                                let pm = pre_maps.remove(&(v.clone(), pi))?;
                                Some((&**pb, pm))
                            })
                            .collect();
                        let me: Origin = (v.id, self.intern(&v.path), self.meta(&v.id)?);
                        let (b, _) = crate::derive::blame::step_mapped(&me, text.lines.len(), &inputs);
                        self.f.g.cx.hub().query.blame_steps.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let b = Arc::new(b);
                        let should_keep = *v == *start || (b.vd % CHECKPOINT == 0 && b.vd % spacing(computed, b.stored_estimate()) == 0);
                        if should_keep && !self.keep(v, &b) && *v == *start {
                            return Err(too_large());
                        }
                        Some((text, b))
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
                if held + done.capacity() * (std::mem::size_of::<(Version, Done)>() + 1) + self.pending_bytes + self.side_bytes() > self.limits.held {
                    return Err(too_wide());
                }
                if self.writes.len() >= BATCH_BLAMES || self.pending_bytes >= self.batch_bytes() {
                    self.write()?;
                }
            }
        }
        Ok(done.remove(start).flatten())
    }

    /// Most bytes of one kept blame: a quarter of a view key's cap, so a
    /// kept blame and the batch written with it never pass the cap
    /// (BUG-1411).
    fn one_kept(&self) -> usize {
        self.limits.kept_bytes / 4
    }

    /// Bytes of kept blames held before they are written: at most a
    /// quarter of the memory bound and of a view key's cap, so a batch
    /// (with the one blame past it) takes at most half the cap.
    fn batch_bytes(&self) -> usize {
        BATCH_BYTES.min(self.limits.held / 4).min(self.one_kept())
    }

    /// Keep blame `b` of version `v` (written with the next batch); `false`
    /// when it is larger than [`Blamer::one_kept`] (not kept).
    fn keep(&mut self, v: &Version, b: &Blame) -> bool {
        let raw = b.encode(path_key);
        if raw.len() > self.one_kept() {
            return false;
        }
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
        true
    }

    /// Write the kept blames held: their paths, then the blames; then drop
    /// the view key's too-wide records whose walks reached the paths kept
    /// (their walks would stop at these now: BUG-1412), and the view key's
    /// oldest kept blames past [`BlameLimits::kept_bytes`] (BUG-1218; only
    /// the view key's own: BUG-1308), never one just written (BUG-1411).
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
        // One statement for the batch, one for the records, one for the
        // view key's cap.
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
        let mut kept_paths: Vec<&str> = keys.clone();
        kept_paths.sort_unstable();
        kept_paths.dedup();
        cx.db(|| {
            sqlx::query(
                "DELETE FROM blame_ends WHERE project_id = $1 AND view_key = $2 AND follow = $3 \
                 AND (path_key = ANY($4::text[]) OR string_to_array(path_keys, ',') && $4::text[])",
            )
            .bind(project)
            .bind(vk)
            .bind(self.follow)
            .bind(&kept_paths)
            .execute(pool)
        })?;
        // The rows just written are counted first (newest) and never
        // dropped: they take at most half the cap (`batch_bytes`).
        cx.db(|| {
            sqlx::query(
                "DELETE FROM blame_memo WHERE project_id = $1 AND view_key = $2 AND (path_key, follow, snapshot) IN ( \
                     SELECT path_key, follow, snapshot FROM ( \
                         SELECT path_key, follow, snapshot, \
                             SUM(bytes) OVER (ORDER BY (follow = $4 AND (path_key, snapshot) IN (SELECT * FROM UNNEST($5::text[], $6::text[]))) DESC, \
                                 created_at DESC, path_key, follow, snapshot) AS kept, \
                             (follow = $4 AND (path_key, snapshot) IN (SELECT * FROM UNNEST($5::text[], $6::text[]))) AS mine \
                         FROM blame_memo WHERE project_id = $1 AND view_key = $2) t \
                     WHERE kept > $3 AND NOT mine)",
            )
            .bind(project)
            .bind(vk)
            .bind(self.limits.kept_bytes as i64)
            .bind(self.follow)
            .bind(&keys)
            .bind(&snaps)
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
/// while a statement runs). A freed slot goes to the next requester in
/// turn with a job waiting for one (BUG-1306, BUG-1410, BUG-1553).
pub const BLAME_JOBS: usize = 2;
/// Blame jobs one requester (a signed-in person; every caller without an
/// account together) may have waiting in one server, all its projects and
/// view keys together; past it, its requests answer `warming` without
/// queuing one. That is the only at-once refusal, so it is a function of
/// the requester's own jobs alone (BUG-1553, BUG-1554).
pub const MAX_PENDING_JOBS: usize = 256;
/// Blame jobs waiting in one server in all: at this ceiling a new job
/// takes the place of the newest waiting job (not computing) of the
/// requester with the most waiting, the furthest past its fair share
/// (this ÷ the requesters waiting), which ends `warming` (BUG-1554).
pub const MAX_PENDING_ALL: usize = 4096;
/// A job's lease on its key ([`BlameLimits::lease`]), and how long a job
/// waits for another server's ([`BlameLimits::wait`]; then it ends
/// `warming`, never computing: BUG-1307).
const JOB_LEASE: Duration = Duration::from_secs(120);
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
/// Who shares a server's queue and slots: the signed-in person who asked
/// first for a job, or `None` for every caller without an account
/// together (BUG-1553: a view key is shared by many people, and one person
/// has many).
pub type Requester = Option<i64>;

/// The blame jobs of one server.
pub struct Jobs {
    waiting: std::sync::Mutex<Waiting>,
    slots: Arc<Slots>,
    /// Jobs started here (the tests count them).
    pub started: std::sync::atomic::AtomicU64,
}

/// A job waiting or computing here.
struct Entry {
    rx: JobRx,
    requester: Requester,
    /// Its place in the order jobs were queued.
    seq: u64,
    ticket: Arc<Ticket>,
}

/// What a job and the table share: whether it was refused at the ceiling
/// (it then ends `warming` where it waits: for a lease, or for a slot),
/// and whether it computes (then it is never refused). Both change only
/// under the table's lock.
#[derive(Default)]
struct Ticket {
    refused: std::sync::atomic::AtomicBool,
    computing: std::sync::atomic::AtomicBool,
    wake: tokio::sync::Notify,
}

impl Ticket {
    fn refused(&self) -> bool {
        self.refused.load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[derive(Default)]
struct Waiting {
    jobs: HashMap<JobKey, Entry>,
    /// Jobs waiting, by requester.
    per: HashMap<Requester, usize>,
    seq: u64,
}

impl Waiting {
    /// Whether a new job of `who` may queue, with `per` jobs a requester
    /// and `all` in all: `None` when `who` has `per` waiting already (the
    /// only refusal); else the job it takes the place of at the ceiling,
    /// if any (removed here): the newest job not computing of the
    /// requester with the most waiting.
    fn admit(&mut self, who: Requester, per: usize, all: usize) -> Option<Option<(JobKey, Entry)>> {
        if self.per.get(&who).copied().unwrap_or(0) >= per {
            return None;
        }
        if self.jobs.len() < all {
            return Some(None);
        }
        let mut most: Vec<(usize, Requester)> = self.per.iter().map(|(r, n)| (*n, *r)).collect();
        most.sort_unstable_by(|a, b| b.cmp(a));
        for (_, r) in most {
            let newest = self
                .jobs
                .iter()
                .filter(|(_, e)| e.requester == r && !e.ticket.computing.load(std::sync::atomic::Ordering::Relaxed))
                .max_by_key(|(_, e)| e.seq)
                .map(|(k, _)| k.clone());
            if let Some(k) = newest {
                let e = self.remove(&k).unwrap();
                e.ticket.refused.store(true, std::sync::atomic::Ordering::Relaxed);
                e.ticket.wake.notify_one();
                return Some(Some((k, e)));
            }
        }
        // Every job computes: more than `all` slots (never so).
        None
    }

    fn insert(&mut self, key: JobKey, rx: JobRx, requester: Requester) -> (u64, Arc<Ticket>) {
        self.seq += 1;
        let ticket = Arc::new(Ticket::default());
        *self.per.entry(requester).or_default() += 1;
        self.jobs.insert(key, Entry { rx, requester, seq: self.seq, ticket: ticket.clone() });
        (self.seq, ticket)
    }

    fn remove(&mut self, key: &JobKey) -> Option<Entry> {
        let e = self.jobs.remove(key)?;
        if let Some(n) = self.per.get_mut(&e.requester) {
            *n -= 1;
            if *n == 0 {
                self.per.remove(&e.requester);
            }
        }
        Some(e)
    }
}

impl Default for Jobs {
    fn default() -> Self {
        Jobs {
            waiting: std::sync::Mutex::new(Waiting::default()),
            slots: Arc::new(Slots::new(BLAME_JOBS)),
            started: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

/// This server's [`BLAME_JOBS`] slots, handed out fairly (BUG-1306,
/// BUG-1410, BUG-1553): a freed slot goes to the requester after the one
/// last served, in turn, among those with a job waiting for one; within a
/// requester, first come first served. So no requester holds another back
/// by more than one job a slot, whatever projects and view keys they ask
/// in.
struct Slots {
    state: std::sync::Mutex<SlotState>,
}

type Waiter = tokio::sync::oneshot::Sender<Slot>;

struct SlotState {
    free: usize,
    /// Waiters by requester.
    queues: std::collections::BTreeMap<Requester, std::collections::VecDeque<Waiter>>,
    /// The requester last served.
    last: Option<Requester>,
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

/// The key of `map` after `after` in turn (wrapping), if any.
fn next_in_turn<K: Ord + Clone, V>(map: &std::collections::BTreeMap<K, V>, after: Option<&K>) -> Option<K> {
    let past = match after {
        Some(a) => map.range((std::ops::Bound::Excluded(a.clone()), std::ops::Bound::Unbounded)).next(),
        None => None,
    };
    past.or_else(|| map.iter().next()).map(|(k, _)| k.clone())
}

impl Slots {
    fn new(n: usize) -> Slots {
        Slots { state: std::sync::Mutex::new(SlotState { free: n, queues: Default::default(), last: None }) }
    }

    /// A slot for `who`; a waiter that leaves before its turn (a job
    /// refused at the ceiling) gives its turn to the next.
    async fn take(self: &Arc<Self>, who: Requester) -> Slot {
        let rx = {
            let mut st = self.state.lock().unwrap();
            // A free slot means nobody (still) waits: a freed one goes to a
            // waiter first.
            if st.free > 0 {
                st.free -= 1;
                st.last = Some(who);
                return Slot { slots: Some(self.clone()) };
            }
            let (tx, rx) = tokio::sync::oneshot::channel();
            st.queues.entry(who).or_default().push_back(tx);
            rx
        };
        // A sender is dropped only once sent.
        rx.await.expect("a blame slot")
    }

    fn give(me: Arc<Self>) {
        let mut guard = me.state.lock().unwrap();
        let st = &mut *guard;
        loop {
            let Some(r) = next_in_turn(&st.queues, st.last.as_ref()) else {
                st.free += 1;
                return;
            };
            let q = st.queues.get_mut(&r).unwrap();
            let tx = q.pop_front().unwrap();
            if q.is_empty() {
                st.queues.remove(&r);
            }
            st.last = Some(r);
            match tx.send(Slot { slots: Some(me.clone()) }) {
                Ok(()) => return,
                // The waiter left: the next in turn.
                Err(mut s) => s.slots = None,
            }
        }
    }
}

/// A job's hold of its key's lease (BUG-1307): lost when a renewal finds
/// the row taken over, or when the lease's end (less a sixth of the lease,
/// for clocks) passes without a renewal. A job computes only while it is
/// live, and checks at every version.
pub struct Lease {
    lost: std::sync::atomic::AtomicBool,
    /// Milliseconds: past this, the job stops.
    until: std::sync::atomic::AtomicI64,
    /// How long it lives from a renewal (the lease, less the margin).
    span: i64,
}

impl Lease {
    fn new(now: i64, lease: Duration) -> Lease {
        let span = (lease - lease / 6).as_millis() as i64;
        Lease { lost: Default::default(), until: std::sync::atomic::AtomicI64::new(now + span), span }
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
    let joined = hub.query.jobs.waiting.lock().unwrap().jobs.get(&key).map(|e| e.rx.clone());
    let mut rx = match joined {
        Some(rx) => rx,
        None => {
            if let Some(end) = settled(hub, &key, limits).await? {
                return Ok(end);
            }
            let mut w = hub.query.jobs.waiting.lock().unwrap();
            match w.jobs.get(&key) {
                Some(e) => e.rx.clone(),
                None => {
                    let who: Requester = viewer.person;
                    // At the ceiling the job whose place this one takes is
                    // told so (it ends `warming` where it waits); its task
                    // leaves the table as it is.
                    if w.admit(who, MAX_PENDING_JOBS, MAX_PENDING_ALL).is_none() {
                        return Err(warming());
                    }
                    let (tx, rx) = tokio::sync::watch::channel(None);
                    let (seq, ticket) = w.insert(key.clone(), rx.clone(), who);
                    drop(w);
                    hub.query.jobs.started.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let (hub, project, viewer, start) = (hub.clone(), project.clone(), viewer.clone(), start.clone());
                    tokio::spawn(async move {
                        let r = leased_job(&hub, &project, &viewer, &key, &start, follow, limits, &ticket).await;
                        if let Err(e) = &r {
                            if !matches!(e, Error::Api { code: "warming" | "too_wide", .. }) {
                                eprintln!("veil-server: a blame job of project {}: {e:?}", project.id);
                            }
                        }
                        {
                            let mut w = hub.query.jobs.waiting.lock().unwrap();
                            if w.jobs.get(&key).is_some_and(|e| e.seq == seq) {
                                w.remove(&key);
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
/// blame kept, or recorded too wide under limits no smaller than these
/// (BUG-1309).
async fn settled(hub: &crate::Hub, key: &JobKey, limits: BlameLimits) -> Result<Option<JobEnd>> {
    let (kept, wide): (bool, bool) = sqlx::query_as(
        "SELECT EXISTS (SELECT 1 FROM blame_memo WHERE project_id = $1 AND view_key = $2 AND path_key = $3 AND follow = $4 AND snapshot = $5), \
                EXISTS (SELECT 1 FROM blame_ends WHERE project_id = $1 AND view_key = $2 AND path_key = $3 AND follow = $4 AND snapshot = $5 \
                        AND held >= $6 AND kept_bytes >= $7)",
    )
    .bind(key.0)
    .bind(&key.1)
    .bind(&key.2)
    .bind(key.3)
    .bind(key.4.hex())
    .bind(limits.held as i64)
    .bind(limits.kept_bytes as i64)
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

/// Record that the blame of `key` is too wide under `limits`, naming the
/// paths its walk reached (`reached`: a kept blame of any of them drops
/// the record, BUG-1412), and drop the view key's oldest records past
/// [`KEPT_ENDS`]. Only if no blame of the view key, `follow` and a path
/// reached was kept at or after `since` (the job's start, less a margin
/// for clocks), in the same statement: the job's own checkpoints, or
/// another job's of the key, cut the next walk short, which then goes
/// further (BUG-1555).
async fn record_too_wide(hub: &crate::Hub, key: &JobKey, limits: BlameLimits, reached: &[String], since: i64) -> Result<()> {
    let mut paths: Vec<&str> = reached.iter().map(String::as_str).collect();
    paths.push(&key.2);
    sqlx::query(
        "INSERT INTO blame_ends (project_id, view_key, path_key, follow, snapshot, held, kept_bytes, path_keys, created_at) \
         SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9 \
         WHERE NOT EXISTS (SELECT 1 FROM blame_memo WHERE project_id = $1 AND view_key = $2 AND follow = $4 \
                           AND path_key = ANY($10::text[]) AND created_at >= $11) \
         ON CONFLICT (project_id, view_key, path_key, follow, snapshot) DO UPDATE \
         SET held = EXCLUDED.held, kept_bytes = EXCLUDED.kept_bytes, path_keys = EXCLUDED.path_keys, created_at = EXCLUDED.created_at",
    )
    .bind(key.0)
    .bind(&key.1)
    .bind(&key.2)
    .bind(key.3)
    .bind(key.4.hex())
    .bind(limits.held as i64)
    .bind(limits.kept_bytes as i64)
    .bind(reached.join(","))
    .bind(veil_core::now_millis())
    .bind(&paths)
    .bind(since)
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

/// Drop the kept blames, too-wide records and kept history cursors of
/// `project`'s view keys that no viewer has, once its access has changed
/// (BUG-1413): one statement compares what view keys are a function of
/// (its policy and bindings, its admins and its groups' members, as a
/// digest) with what `view_access` last recorded; when they differ, the
/// one server that records the change drops the rows written before it
/// under keys no viewer has now. A row written after the change under a
/// key out of use (a request that loaded its viewer before the change) is
/// dropped at the next change. Run after every write of such rows and at
/// every landing (`derive::memo_tips`).
pub async fn sweep_keys(hub: &crate::Hub, project: i64) -> Result<()> {
    let row: Option<(String, Option<String>)> = sqlx::query_as(
        "SELECT md5(p.policy_text || '|' || p.policy_bindings || '|' || \
             COALESCE((SELECT string_agg(a.person_id::text, ',' ORDER BY a.person_id) FROM project_admins a WHERE a.project_id = p.id), '') || '|' || \
             COALESCE((SELECT string_agg(m.person_id::text || ':' || m.group_id::text, ',' ORDER BY m.person_id, m.group_id) \
                       FROM group_members m JOIN groups g ON g.id = m.group_id WHERE g.project_id = p.id), '')), \
             (SELECT v.access FROM view_access v WHERE v.project_id = p.id) \
         FROM projects p WHERE p.id = $1",
    )
    .bind(project)
    .fetch_optional(&hub.db)
    .await?;
    let Some((access, recorded)) = row else { return Ok(()) };
    if recorded.as_deref() == Some(access.as_str()) {
        return Ok(());
    }
    let now = veil_core::now_millis();
    // Recorded by one server (the first look records only: nothing was
    // written under an access before it).
    let changed: bool = match &recorded {
        None => {
            sqlx::query("INSERT INTO view_access (project_id, access, changed_at) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING")
                .bind(project)
                .bind(&access)
                .bind(now)
                .execute(&hub.db)
                .await?;
            false
        }
        Some(old) => sqlx::query("UPDATE view_access SET access = $2, changed_at = $3 WHERE project_id = $1 AND access = $4")
            .bind(project)
            .bind(&access)
            .bind(now)
            .bind(old)
            .execute(&hub.db)
            .await?
            .rows_affected()
            == 1,
    };
    if changed {
        let keys = crate::derive::view_keys(hub, project).await?;
        drop_out_of_use(hub, project, &keys, now).await?;
    }
    Ok(())
}

/// Drop the kept blames, too-wide records and kept cursors of `project`'s
/// view keys not in `in_use`, written before `before` (milliseconds).
async fn drop_out_of_use(hub: &crate::Hub, project: i64, in_use: &HashSet<String>, before: i64) -> Result<()> {
    let keys: Vec<&str> = in_use.iter().map(String::as_str).collect();
    for table in ["blame_memo", "blame_ends", "log_cursors"] {
        sqlx::query(&format!("DELETE FROM {table} WHERE project_id = $1 AND view_key <> ALL($2::text[]) AND created_at < $3"))
            .bind(project)
            .bind(&keys)
            .bind(before)
            .execute(&hub.db)
            .await?;
    }
    Ok(())
}

/// How a job's computing ended: kept or not plain text, or too wide (the
/// message, and the path keys its walk reached).
enum Outcome {
    Done(bool),
    TooWide(String, Vec<String>),
}

/// The job, under its key's lease (`blame_jobs`: one server at a time),
/// in one of this server's [`BLAME_JOBS`] slots: whether it ended kept
/// (`false`: no plain text). It computes only while it holds the lease
/// (BUG-1307): it takes the lease first, keeps renewing it while it waits
/// for a slot and while it computes, and stops at its next version once a
/// renewal fails; a job waiting for another server's lease stops as soon
/// as that server's job ends, and after [`BlameLimits::wait`] ends
/// `warming`.
#[allow(clippy::too_many_arguments)]
async fn leased_job(
    hub: &Arc<crate::Hub>,
    project: &crate::perm::Project,
    viewer: &crate::perm::Viewer,
    key: &JobKey,
    start: &Version,
    follow: bool,
    limits: BlameLimits,
    ticket: &Ticket,
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
        .bind(now + limits.lease.as_millis() as i64)
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
        tokio::select! {
            _ = tokio::time::sleep(pause) => {}
            _ = ticket.wake.notified() => {}
        }
        if ticket.refused() {
            return Err(warming());
        }
        pause = (pause * 2).min(Duration::from_secs(4));
        if let Some(end) = settled(hub, key, limits).await? {
            return ended(end);
        }
    };
    let lease = Arc::new(Lease::new(taken, limits.lease));
    let renew = {
        let (hub, key, holder, lease) = (hub.clone(), key.clone(), holder.clone(), lease.clone());
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(limits.lease / 4).await;
                let now = veil_core::now_millis();
                let r = sqlx::query(
                    "UPDATE blame_jobs SET expires_at = $1 WHERE project_id = $2 AND view_key = $3 AND path_key = $4 AND follow = $5 AND snapshot = $6 AND holder = $7",
                )
                .bind(now + limits.lease.as_millis() as i64)
                .bind(key.0)
                .bind(&key.1)
                .bind(&key.2)
                .bind(key.3)
                .bind(key.4.hex())
                .bind(&holder)
                .execute(&hub.db)
                .await;
                match r {
                    Ok(r) if r.rows_affected() == 1 => lease.until.store(now + lease.span, std::sync::atomic::Ordering::Relaxed),
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
    let mut since = i64::MAX;
    let r: Result<Outcome> = async {
        let who: Requester = viewer.person;
        let _slot = tokio::select! {
            s = hub.query.jobs.slots.take(who) => s,
            // Refused at the ceiling while it waits for a slot.
            _ = ticket.wake.notified() => return Err(warming()),
        };
        if let Some(end) = settled(hub, key, limits).await? {
            return ended(end).map(Outcome::Done);
        }
        if !lease.live() {
            return Err(warming());
        }
        // It computes from here, unless it was refused first (both under
        // the table's lock, where refusals are made).
        {
            let _w = hub.query.jobs.waiting.lock().unwrap();
            if ticket.refused() {
                return Err(warming());
            }
            ticket.computing.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        // Kept blames written from here on are this job's or another's of
        // the same key: a too-wide record is written only if none of a path
        // the walk reached was (BUG-1555); the margin is for clocks.
        since = veil_core::now_millis() - (limits.lease / 6).as_millis() as i64;
        let (project, viewer, vk, start, lease) = (project.clone(), viewer.clone(), key.1.clone(), start.clone(), lease.clone());
        super::graph::blocking(hub, project.id, move |cx| {
            let g = G::new(cx, &vk, None);
            let view = project.view(&viewer);
            let t = Trees::new(&g, &view);
            let f = Files::new(&g);
            let mut b = Blamer::new(&f, &t, follow, limits);
            b.lease = Some(lease);
            match b.blame(&start) {
                Ok(d) => Ok(Outcome::Done(d.is_some())),
                Err(Error::Api { code: "too_wide", message, .. }) => {
                    let mut reached: Vec<String> = b.reached.into_iter().collect();
                    reached.sort();
                    Ok(Outcome::TooWide(message, reached))
                }
                Err(e) => Err(e),
            }
        })
        .await
    }
    .await;
    renew.abort();
    let r = match r {
        Ok(Outcome::TooWide(message, reached)) => {
            record_too_wide(hub, key, limits, &reached, since).await?;
            Err(Error::Api { status: StatusCode::UNPROCESSABLE_ENTITY, code: "too_wide", message })
        }
        Ok(Outcome::Done(kept)) => Ok(kept),
        Err(e) => Err(e),
    };
    let _ = sqlx::query("DELETE FROM blame_jobs WHERE project_id = $1 AND view_key = $2 AND path_key = $3 AND follow = $4 AND snapshot = $5 AND holder = $6")
        .bind(key.0)
        .bind(&key.1)
        .bind(&key.2)
        .bind(key.3)
        .bind(key.4.hex())
        .bind(&holder)
        .execute(&hub.db)
        .await;
    // Rows of view keys out of use since the access changed (BUG-1413).
    sweep_keys(hub, key.0).await?;
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
        "visited": b.vd,
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

    /// BUG-1306, BUG-1410 and BUG-1553: a freed slot goes to the next
    /// requester in turn, not to whoever queued the most first, whatever
    /// projects and view keys they ask in.
    #[test]
    fn slots_go_to_requesters_in_turn() {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let slots = Arc::new(Slots::new(1));
            let held = slots.take(Some(1)).await;
            let order = Arc::new(std::sync::Mutex::new(Vec::new()));
            let mut tasks = Vec::new();
            // Person 1: three jobs; then everyone without an account, and
            // person 2, one each.
            for who in [Some(1), Some(1), Some(1), None, Some(2)] {
                let (slots, order) = (slots.clone(), order.clone());
                tasks.push(tokio::spawn(async move {
                    let s = slots.take(who).await;
                    order.lock().unwrap().push(who);
                    drop(s);
                }));
                tokio::task::yield_now().await;
            }
            drop(held);
            for t in tasks {
                t.await.unwrap();
            }
            assert_eq!(*order.lock().unwrap(), [Some(2), None, Some(1), Some(1), Some(1)]);
            assert_eq!(slots.state.lock().unwrap().free, 1, "every slot given back");
        });
    }

    /// BUG-1553 and BUG-1554: a requester is refused at once only when it
    /// has its share waiting itself; at the ceiling a new job takes the
    /// place of the newest waiting job (not computing) of the requester
    /// with the most waiting.
    #[test]
    fn the_queue_refuses_only_on_the_requesters_own_jobs() {
        let mut w = Waiting::default();
        let key = |i: u8| -> JobKey { (1, "k".into(), format!("p{i}"), false, ObjectId::hash(&[i])) };
        let rx = || tokio::sync::watch::channel(None).1;
        let (per, all) = (3, 5);
        // Person 1 takes its share of 3; a fourth is refused, whoever else
        // waits.
        for i in 0..3 {
            assert!(matches!(w.admit(Some(1), per, all), Some(None)));
            w.insert(key(i), rx(), Some(1));
        }
        assert!(w.admit(Some(1), per, all).is_none(), "past its own share");
        // Person 2 and everyone without an account fill the ceiling of 5.
        assert!(matches!(w.admit(Some(2), per, all), Some(None)));
        w.insert(key(3), rx(), Some(2));
        assert!(matches!(w.admit(None, per, all), Some(None)));
        w.insert(key(4), rx(), None);
        // Person 3 at the ceiling: person 1's newest waiting job goes (its
        // ticket is told), not one computing.
        w.jobs[&key(2)].ticket.computing.store(true, std::sync::atomic::Ordering::Relaxed);
        let (gone, e) = w.admit(Some(3), per, all).unwrap().expect("a place taken");
        assert_eq!(gone, key(1), "person 1's newest job not computing");
        assert!(e.ticket.refused(), "told");
        w.insert(key(5), rx(), Some(3));
        assert_eq!(w.jobs.len(), all, "the ceiling holds");
        assert_eq!(w.per[&Some(1)], 2);
        // Person 2, below its share, is admitted too.
        assert!(matches!(w.admit(Some(2), per, all), Some(Some(_))));
    }

    /// Guarantee 3: a computing job is never displaced at the ceiling, and
    /// a waiter that leaves `Slots` before its turn (displaced at the
    /// ceiling while waiting for a slot) gives its turn and releases the
    /// slot cleanly.
    #[test]
    fn a_computing_job_is_never_displaced_and_a_refused_waiter_releases_its_slot() {
        let mut w = Waiting::default();
        let key = |i: u8| -> JobKey { (1, "k".into(), format!("p{i}"), false, ObjectId::hash(&[i])) };
        let rx = || tokio::sync::watch::channel(None).1;
        let (per, all) = (2, 2);
        // Person 1 has 2 jobs, filling the ceiling of 2; both are marked
        // computing under the lock.
        for i in 0..2 {
            assert!(matches!(w.admit(Some(1), per, all), Some(None)));
            let (_, ticket) = w.insert(key(i), rx(), Some(1));
            ticket.computing.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        // Neither computing job is displaced: admit returns None and leaves
        // both tickets unrefused.
        assert!(w.admit(Some(2), per, all).is_none(), "computing jobs are never displaced");
        for i in 0..2 {
            assert!(!w.jobs[&key(i)].ticket.refused(), "computing job {i} not refused");
        }
        // If only the newest job of the requester with the most waiting (2)
        // is computing, its older non-computing job is displaced first; if
        // all of that requester's jobs are computing, the next requester in
        // `most` with a non-computing job gives its newest waiting place;
        // and a requester with fewer waiting jobs (`Some(99)` with 1 job) is
        // never displaced while any requester with more waiting jobs (`Some(2)`
        // with 2 waiting jobs) has a non-computing job.
        let mut w2 = Waiting::default();
        let (per2, all2) = (3, 5);
        let (_, t0) = w2.insert(key(0), rx(), Some(1));
        let (_, t1) = w2.insert(key(1), rx(), Some(1));
        let (_, t_few) = w2.insert(key(9), rx(), Some(99));
        let (_, t2) = w2.insert(key(2), rx(), Some(2));
        let (_, t3) = w2.insert(key(3), rx(), Some(2));
        t0.computing.store(true, std::sync::atomic::Ordering::Relaxed);
        t1.computing.store(true, std::sync::atomic::Ordering::Relaxed);
        let (gone, _) = w2.admit(Some(99), per2, all2).unwrap().expect("a waiting job gives its place");
        assert_eq!(gone, key(3), "newest non-computing job of the requester with the most waiting gives its place");
        assert!(!t0.refused() && !t1.refused() && !t_few.refused() && !t2.refused() && t3.refused());

        // In `Slots`, a waiter cancelled before its turn (as when `ticket.wake`
        // wins the `select!` in `leased_job`) drops its receiver; when the
        // held slot drops, `Slots::give` skips the cancelled waiter, hands
        // the slot to the next requester in turn, and ends with all slots free.
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let slots = Arc::new(Slots::new(1));
            let held = slots.take(Some(1)).await;
            let cancel = Arc::new(tokio::sync::Notify::new());
            let (slots2, cancel2) = (slots.clone(), cancel.clone());
            let displaced = tokio::spawn(async move {
                tokio::select! {
                    _ = slots2.take(Some(2)) => panic!("displaced waiter should not take a slot"),
                    _ = cancel2.notified() => "warming",
                }
            });
            tokio::task::yield_now().await;
            let order = Arc::new(std::sync::Mutex::new(Vec::new()));
            let (slots3, order3) = (slots.clone(), order.clone());
            let third = tokio::spawn(async move {
                let s = slots3.take(Some(3)).await;
                order3.lock().unwrap().push(3);
                drop(s);
            });
            tokio::task::yield_now().await;
            cancel.notify_one();
            assert_eq!(displaced.await.unwrap(), "warming");
            drop(held);
            third.await.unwrap();
            assert_eq!(*order.lock().unwrap(), [3]);
            assert_eq!(slots.state.lock().unwrap().free, 1, "slot released cleanly after a displaced waiter");
        });
    }

    /// BUG-1307: a lease not renewed stops being live before it ends (less
    /// a sixth of it), and a lost one at once.
    #[test]
    fn a_lease_not_renewed_is_not_live() {
        let now = veil_core::now_millis();
        assert!(Lease::new(now, JOB_LEASE).live());
        assert!(!Lease::new(now - (JOB_LEASE - JOB_LEASE / 6).as_millis() as i64, JOB_LEASE).live());
        let l = Lease::new(now, JOB_LEASE);
        l.lost.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(!l.live());
    }
}
