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
const PAGES: [i64; 3] = [64, 512, 10_000];
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

impl FChange {
    fn parse(s: &str) -> Result<FChange> {
        if let Some(fc) = Self::parse_fast(s) {
            return Ok(fc);
        }
        serde_json::from_str(s).map_err(bad)
    }

    fn parse_fast(s: &str) -> Option<FChange> {
        let rest = s.strip_prefix("{\"old\":")?;
        let (old, rest) = Self::parse_opt_entry(rest)?;
        let rest = rest.strip_prefix(",\"new\":")?;
        let (new, rest) = Self::parse_opt_entry(rest)?;
        let rest = rest.strip_prefix(",\"prev\":[")?;
        let rest = rest.strip_suffix("]}")?;
        let mut prev = Vec::with_capacity(1);
        if !rest.is_empty() {
            for item in rest.split("],[") {
                let item = item.trim_start_matches('[').trim_end_matches(']');
                if item == "null" {
                    prev.push(None);
                } else {
                    let (d_str, id_str) = item.split_once(',')?;
                    let d: i64 = d_str.parse().ok()?;
                    let hex = id_str.strip_prefix('"')?.strip_suffix('"')?;
                    let id = ObjectId::from_hex(hex).ok()?;
                    prev.push(Some((d, id)));
                }
            }
        }
        Some(FChange { old, new, prev })
    }

    fn parse_opt_entry(s: &str) -> Option<(Option<TreeEntry>, &str)> {
        if let Some(rest) = s.strip_prefix("null") {
            return Some((None, rest));
        }
        let rest = s.strip_prefix("{\"name\":\"")?;
        let name_end = rest.find('"')?;
        let name = &rest[..name_end];
        if name.as_bytes().contains(&b'\\') {
            return None;
        }
        let rest = &rest[name_end + 1..];
        let rest = rest.strip_prefix(",\"kind\":\"")?;
        let kind_end = rest.find('"')?;
        let kind = match &rest[..kind_end] {
            "file" => EntryKind::File,
            "dir" => EntryKind::Dir,
            "symlink" => EntryKind::Symlink,
            _ => return None,
        };
        let rest = &rest[kind_end + 1..];
        let rest = rest.strip_prefix(",\"id\":\"")?;
        if rest.len() < 65 || rest.as_bytes()[64] != b'"' {
            return None;
        }
        let id = ObjectId::from_hex(&rest[..64]).ok()?;
        let mut rest = &rest[65..];
        let mut size = 0u64;
        if let Some(r) = rest.strip_prefix(",\"size\":") {
            let end = r.find([',', '}'])?;
            size = r[..end].parse().ok()?;
            rest = &r[end..];
        }
        let rest = rest.strip_prefix('}')?;
        Some((
            Some(TreeEntry {
                name: name.to_string(),
                kind,
                id,
                size,
                executable: false,
                visibility: veil_core::object::Visibility::Public,
            }),
            rest,
        ))
    }
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
        let pending = std::mem::take(&mut self.pending);
        if !pending.is_empty() {
            cx.db(|| async {
                let mut tx = pool.begin().await?;
                Self::write_rows_tx(&mut tx, cx.project(), g.vk, &pending).await?;
                tx.commit().await?;
                cx.hub().commits.count(crate::db::Commit::Fill);
                Ok(())
            })?;
        }
        self.forget_if_large();
        Ok(())
    }

    pub(crate) fn forget_if_large(&mut self) {
        if self.known_rows > KNOWN_ROWS {
            self.known.clear();
            self.known_rows = 0;
            self.fresh.clear();
        }
    }

    pub(crate) async fn write_rows_tx(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        project: i64,
        vk: &str,
        rows: &[(String, i64, ObjectId, String)],
    ) -> std::result::Result<(), sqlx::Error> {
        for chunk in rows.chunks(ROWS_PER_STATEMENT) {
            let keys: Vec<&str> = chunk.iter().map(|r| r.0.as_str()).collect();
            let depths: Vec<i64> = chunk.iter().map(|r| r.1).collect();
            let ids: Vec<String> = chunk.iter().map(|r| r.2.hex()).collect();
            let changes: Vec<&str> = chunk.iter().map(|r| r.3.as_str()).collect();
            sqlx::query(
                "INSERT INTO view_file_history (project_id, view_key, path_key, depth, snapshot, change) \
                 SELECT $1, $2, * FROM UNNEST($3::text[], $4::bigint[], $5::text[], $6::text[]) ON CONFLICT DO NOTHING",
            )
            .bind(project)
            .bind(vk)
            .bind(&keys)
            .bind(&depths)
            .bind(&ids)
            .bind(&changes)
            .execute(&mut **tx)
            .await?;
        }
        Ok(())
    }
}

// ---- reading ----------------------------------------------------------------------

/// Rows of one path read so far, from below `top` down, deepest first.
#[derive(Clone)]
pub struct Window {
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
    /// Start windows at page size `PAGES[1]` (512 rows) instead of `PAGES[0]` (64)
    /// when a blame job has ample memory budget.
    fast_pages: std::cell::Cell<bool>,
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
            fast_pages: std::cell::Cell::new(false),
        }
    }

    pub fn set_fast_pages(&self, fast: bool) {
        self.fast_pages.set(fast);
    }

    pub fn take_window(&self, path: &str) -> Option<(Window, usize)> {
        let key = path_key(path);
        self.windows.borrow_mut().remove(&key).map(|w| (w, self.loaded.get()))
    }

    pub fn seed_window(&self, path: &str, w: Window, loaded: usize) {
        let key = path_key(path);
        self.loaded.set(self.loaded.get() + loaded);
        self.windows.borrow_mut().insert(key, w);
    }

    /// Read the next page of `path`'s window.
    fn more(&self, w: &mut Window, key: &str) -> Result<()> {
        let p_idx = if self.fast_pages.get() { PAGES.len() - 1 } else { w.pages.min(PAGES.len() - 1) };
        let limit = PAGES[p_idx];
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
            let c = FChange::parse(&c)?;
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
            return c.map(|c| FChange::parse(&c).map(Arc::new)).transpose();
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
    /// Cached `path_key` per interned path pointer.
    path_keys: HashMap<*const u8, String>,
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
    total_kept_bytes: Option<i64>,
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
            path_keys: HashMap::new(),
            path_bytes: 0,
            metas: HashMap::new(),
            renames: HashMap::new(),
            lease: None,
            reached: HashSet::new(),
            writes: Vec::new(),
            write_paths: HashMap::new(),
            pending_bytes: 0,
            total_kept_bytes: None,
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
            if self.total_kept_bytes.is_none() && rows.is_empty() && self.kept.is_empty() {
                self.total_kept_bytes = Some(0);
            }
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
        self.path_keys.insert(Arc::as_ptr(&a) as *const u8, path_key(p));
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
        if !blob || bytes.len() as u64 > MAX_TEXT_BYTES {
            return Ok(None);
        }
        Ok(Text::try_plain(e.id, bytes))
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

    #[allow(clippy::type_complexity)]
    fn run(&mut self, start: &Version) -> Result<Done> {
        self.f.fast_pages.set(self.limits.held >= 4 << 20);
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
        const CHUNK: usize = 2500;
        const WORKERS: usize = 32;
        let src = &self.t.g.cx.src;
        let load_raw = |e: &Option<TreeEntry>| -> Result<Option<(ObjectId, bytes::Bytes)>> {
            if !texty(e) {
                return Ok(None);
            }
            let e = e.as_ref().unwrap();
            let raw = src.raw_ephemeral(&e.id)?;
            if !veil_core::object::Object::is_blob_raw(&raw) {
                return Ok(None);
            }
            let body_len = raw.len() - 10;
            if body_len as u64 > MAX_TEXT_BYTES {
                return Ok(None);
            }
            Ok(Some((e.id, raw.slice(10..))))
        };
        let mut gens: HashMap<ObjectId, i64> = HashMap::new();
        if self.limits.held >= 4 << 20 && !unkept.is_empty() {
            let cx = self.f.g.cx;
            cx.src.rt.block_on(cx.hub().objects.warm_packs(cx.project()))?;
        }
        let dummy_meta = Arc::new(Meta {
            change_id: String::new(),
            author: String::new(),
            timestamp: 0,
            summary: String::new(),
            generation: 0,
        });
        let mut pending_keeps: Vec<(Version, Arc<Blame>)> = Vec::new();
        let max_chunk = if self.limits.held >= 32 << 20 { 5000 } else if self.limits.held >= 4 << 20 { CHUNK } else { 512 };
        let mut idx = 0usize;
        let mut chain_last: Option<Version> = None;
        let mut chain_counts: Vec<u32> = Vec::new();
        while idx < unkept.len() {
            self.stopped()?;
            // Take up to `max_chunk` versions. For linear single-parent chains
            // under a normal held budget (`>= 4 MiB`), the worker pool holds only a
            // sliding window of `WORKERS` texts in memory at once and drops each
            // version's text as soon as its child's diff is computed.
            let mut end = idx;
            let mut chunk_text_est = 0usize;
            let mut max_entry_sz = 0usize;
            let mut all_linear = self.limits.held >= 4 << 20;
            while end < unkept.len() && end - idx < max_chunk {
                let v = &unkept[end];
                let n = &nodes[v];
                let sz = n.change.new.as_ref().map_or(0, |e| {
                    if self.limits.held >= 4 << 20 {
                        e.size as usize + 256
                    } else {
                        e.size as usize * 3 / 2 + 256
                    }
                });
                max_entry_sz = max_entry_sz.max(sz);
                if all_linear {
                    let linear_step = n.parents.len() <= 1
                        && n.left <= 1
                        && (end == idx || n.parents.first().and_then(|p| p.as_ref()) == Some(&unkept[end - 1]));
                    if !linear_step {
                        all_linear = false;
                    }
                }
                let est = if all_linear {
                    max_entry_sz.saturating_mul(WORKERS * 2)
                } else {
                    chunk_text_est + sz
                };
                let budget_used = held + done.capacity() * (std::mem::size_of::<(Version, Done)>() + 1) + self.pending_bytes + self.side_bytes();
                if end > idx && budget_used + est > self.limits.held.saturating_sub(self.limits.held / 8) {
                    break;
                }
                chunk_text_est += sz;
                end += 1;
            }
            let slice = &unkept[idx..end];
            idx = end;
            // 1. Load texts and parent-to-child line diffs for all versions in `slice` in a single thread-pool scope.
            self.f.g.tick()?;
            let load_meta = |id: ObjectId, gen: i64| -> Result<(ObjectId, Meta)> {
                if !src.pending.contains_key(&id) {
                    let raw = src.raw(&id)?;
                    if let Some(m) = Meta::from_raw_snapshot(&raw, gen) {
                        return Ok((id, m));
                    }
                }
                let sn = src.snapshot(&id)?;
                Ok((id, Meta::of(&sn, gen)))
            };
            let entries: Vec<Option<TreeEntry>> = slice.iter().map(|v| nodes[v].change.new.clone()).collect();
            let parent_done: Option<Arc<Text>> = entries.iter().position(texty).and_then(|fi| {
                nodes[&slice[fi]]
                    .parents
                    .iter()
                    .flatten()
                    .find_map(|p| done.get(p).and_then(|d| d.as_ref().map(|(t, _)| t.clone())))
            });
            let mut slice_idx: HashMap<&Version, usize> = HashMap::with_capacity(slice.len());
            for (vi, v) in slice.iter().enumerate() {
                slice_idx.insert(v, vi);
            }
            let mut diff_specs: Vec<(usize, usize, Option<usize>, Option<Arc<Text>>)> = Vec::new();
            let mut uses_left: Vec<usize> = slice
                .iter()
                .enumerate()
                .map(|(vi, v)| if vi + 1 == slice.len() || nodes[v].left > 1 || *v == *start { 1 } else { 0 })
                .collect();
            for (vi, v) in slice.iter().enumerate() {
                if !texty(&entries[vi]) {
                    continue;
                }
                for (pi, p) in nodes[v].parents.iter().enumerate() {
                    let Some(p) = p else { continue };
                    if let Some(&p_idx) = slice_idx.get(p) {
                        if texty(&entries[p_idx]) {
                            diff_specs.push((vi, pi, Some(p_idx), None));
                            uses_left[vi] += 1;
                            uses_left[p_idx] += 1;
                        }
                    } else if let Some(pt) = done.get(p).and_then(|d| d.as_ref().map(|(t, _)| t.clone())) {
                        diff_specs.push((vi, pi, None, Some(pt)));
                        uses_left[vi] += 1;
                    }
                }
            }
            // Stored per version: `Some((id, line_count))` if plain text, plus `Option<Arc<Text>>` if retained past the chunk.
            let mut chunk_info: Vec<Option<(ObjectId, usize, Option<Arc<Text>>)>> = Vec::with_capacity(slice.len());
            let mut pre_maps: Vec<Vec<Option<crate::derive::blame::ParentMap>>> = slice.iter().map(|v| vec![None; nodes[v].parents.len()]).collect();
            let used_pool = !(slice.len() <= 2 && diff_specs.len() <= 1);
            if !used_pool {
                let mut loaded: Vec<Option<Arc<Text>>> = Vec::with_capacity(slice.len());
                let mut prev_text: Option<Arc<Text>> = parent_done.clone();
                for e in &entries {
                    self.stopped()?;
                    let t = load_raw(e)?.and_then(|(id, bytes)| match &prev_text {
                        Some(bt) => Text::try_plain_from_parent(id, bytes, bt),
                        None => Text::try_plain(id, bytes),
                    });
                    if let Some(ref tr) = t {
                        prev_text = Some(tr.clone());
                    }
                    loaded.push(t);
                }
                for (vi, pi, p_idx, done_pt) in diff_specs {
                    let child_opt = loaded[vi].as_ref();
                    let parent_opt = match p_idx {
                        Some(pi_idx) => loaded[pi_idx].as_ref(),
                        None => done_pt.as_ref(),
                    };
                    if let (Some(pt), Some(text)) = (parent_opt, child_opt) {
                        pre_maps[vi][pi] = Some(crate::derive::blame::diff_parent(pt, text));
                    }
                }
                for t in loaded {
                    chunk_info.push(t.map(|arc| (arc.id, arc.lines.len(), Some(arc))));
                }
            } else {
                let n_workers = WORKERS.min(slice.len().max(diff_specs.len()).max(1));
                let next_i = std::sync::atomic::AtomicUsize::new(0);
                let diffs_done = std::sync::atomic::AtomicUsize::new(0);
                let out_meta: Vec<std::sync::OnceLock<Result<Option<(ObjectId, usize)>>>> = (0..slice.len()).map(|_| std::sync::OnceLock::new()).collect();
                let out_text: Vec<std::sync::Mutex<Option<Arc<Text>>>> = (0..slice.len()).map(|_| std::sync::Mutex::new(None)).collect();
                let rem_uses: Vec<std::sync::atomic::AtomicUsize> = uses_left.iter().map(|&u| std::sync::atomic::AtomicUsize::new(u)).collect();
                let out_d: Vec<std::sync::Mutex<Option<crate::derive::blame::ParentMap>>> = (0..diff_specs.len()).map(|_| std::sync::Mutex::new(None)).collect();
                let mut diffs_by_max: Vec<Vec<usize>> = vec![Vec::new(); slice.len()];
                for (di, &(vi, _, p_idx, _)) in diff_specs.iter().enumerate() {
                    let trigger = p_idx.map_or(vi, |pi| vi.max(pi));
                    diffs_by_max[trigger].push(di);
                }
                let aborted = std::sync::atomic::AtomicBool::new(false);
                let lease_ref = self.lease.as_deref();
                let steps_counter = &self.f.g.cx.hub().query.blame_steps;
                let base_ref = &parent_done;
                let specs_ref = &diff_specs;
                let by_max_ref = &diffs_by_max;
                let get_text = |idx: usize| -> Option<Arc<Text>> {
                    loop {
                        if let Some(res) = out_meta[idx].get() {
                            res.as_ref().ok().and_then(|o| *o)?;
                            return out_text[idx].lock().unwrap().clone();
                        }
                        if aborted.load(std::sync::atomic::Ordering::Acquire) {
                            return None;
                        }
                        std::hint::spin_loop();
                    }
                };
                let release_use = |idx: usize| {
                    if rem_uses[idx].fetch_sub(1, std::sync::atomic::Ordering::AcqRel) == 1 {
                        *out_text[idx].lock().unwrap() = None;
                    }
                };
                std::thread::scope(|s| {
                    for _ in 0..n_workers {
                        s.spawn(|| {
                            let mut prev_text: Option<Arc<Text>> = base_ref.clone();
                            loop {
                                if aborted.load(std::sync::atomic::Ordering::Acquire) || lease_ref.is_some_and(|l| !l.live()) {
                                    aborted.store(true, std::sync::atomic::Ordering::Release);
                                    return;
                                }
                                let i = next_i.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                if i >= entries.len() {
                                    break;
                                }
                                if all_linear {
                                    while i > diffs_done.load(std::sync::atomic::Ordering::Acquire) + WORKERS * 2 {
                                        if aborted.load(std::sync::atomic::Ordering::Acquire) || lease_ref.is_some_and(|l| !l.live()) {
                                            aborted.store(true, std::sync::atomic::Ordering::Release);
                                            return;
                                        }
                                        std::hint::spin_loop();
                                    }
                                }
                                let r = load_raw(&entries[i]).map(|opt| {
                                    opt.and_then(|(id, bytes)| match &prev_text {
                                        Some(bt) => Text::try_plain_from_parent(id, bytes, bt),
                                        None => Text::try_plain(id, bytes),
                                    })
                                });
                                if aborted.load(std::sync::atomic::Ordering::Acquire) || lease_ref.is_some_and(|l| !l.live()) {
                                    aborted.store(true, std::sync::atomic::Ordering::Release);
                                    return;
                                }
                                let meta_res = match r {
                                    Ok(Some(t)) => {
                                        let m = Some((t.id, t.lines.len()));
                                        prev_text = Some(t.clone());
                                        if rem_uses[i].load(std::sync::atomic::Ordering::Acquire) > 0 {
                                            *out_text[i].lock().unwrap() = Some(t);
                                        }
                                        Ok(m)
                                    }
                                    Ok(None) => Ok(None),
                                    Err(e) => Err(e),
                                };
                                let is_text = matches!(meta_res, Ok(Some(_)));
                                let _ = out_meta[i].set(meta_res);
                                for &di in &by_max_ref[i] {
                                    if aborted.load(std::sync::atomic::Ordering::Acquire) || lease_ref.is_some_and(|l| !l.live()) {
                                        aborted.store(true, std::sync::atomic::Ordering::Release);
                                        return;
                                    }
                                    let (vi, _, p_idx, ref done_pt) = specs_ref[di];
                                    let child_opt = get_text(vi);
                                    let parent_opt = match p_idx {
                                        Some(pi_idx) => get_text(pi_idx),
                                        None => done_pt.clone(),
                                    };
                                    if let (Some(pt), Some(text)) = (parent_opt, child_opt) {
                                        let m = crate::derive::blame::diff_parent(&pt, &text);
                                        if aborted.load(std::sync::atomic::Ordering::Acquire) || lease_ref.is_some_and(|l| !l.live()) {
                                            aborted.store(true, std::sync::atomic::Ordering::Release);
                                            return;
                                        }
                                        *out_d[di].lock().unwrap() = Some(m);
                                    }
                                    release_use(vi);
                                    if let Some(pi_idx) = p_idx {
                                        release_use(pi_idx);
                                    }
                                    diffs_done.fetch_add(1, std::sync::atomic::Ordering::Release);
                                }
                                if aborted.load(std::sync::atomic::Ordering::Acquire) || lease_ref.is_some_and(|l| !l.live()) {
                                    aborted.store(true, std::sync::atomic::Ordering::Release);
                                    return;
                                }
                                if is_text {
                                    steps_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                }
                            }
                        });
                    }
                });
                if aborted.load(std::sync::atomic::Ordering::Acquire) {
                    return Err(warming());
                }
                self.stopped()?;
                for (m, t_lock) in out_meta.into_iter().zip(out_text) {
                    let meta_opt = m.into_inner().unwrap()?;
                    let t_opt = t_lock.into_inner().unwrap();
                    chunk_info.push(meta_opt.map(|(id, n_lines)| (id, n_lines, t_opt)));
                }
                for ((vi, pi, _, _), m) in diff_specs.into_iter().zip(out_d) {
                    if let Some(pm) = m.into_inner().unwrap() {
                        pre_maps[vi][pi] = Some(pm);
                    }
                }
            }
            // 2. Propagate blames sequentially in topological order and maintain exact held accounting.
            for (vi, v) in slice.iter().enumerate() {
                if vi & 15 == 0 {
                    self.stopped()?;
                }
                let parents = nodes[v].parents.clone();
                // If `v` has a single parent `p` whose blame is ready to be
                // consumed (`pn.left == 1 && p != start`), take `p` from `done`
                // up front so we can mutate its `Blame` in place via
                // `Arc::make_mut` without cloning `lines` or `origins`.
                let mut single_taken: Option<(Version, Done)> = None;
                if parents.len() == 1 {
                    if let Some(p) = &parents[0] {
                        if nodes[p].left == 1 && p != start {
                            if let Some(d) = done.remove(p) {
                                if let Some((ref t, ref b)) = d {
                                    held -= t.weight() + b.weight();
                                }
                                nodes.get_mut(p).unwrap().left = 0;
                                single_taken = Some((p.clone(), d));
                            }
                        }
                    }
                }
                let out: Done = match chunk_info[vi].take() {
                    None => {
                        chain_last = None;
                        chain_counts.clear();
                        None
                    }
                    Some((text_id, n_lines, opt_text)) => {
                        if parents.len() != 1 || parents[0].as_ref() != chain_last.as_ref() {
                            chain_counts.clear();
                        }
                        let meta_for_v = if self.limits.held >= 4 << 20 {
                            self.metas.get(&v.id).cloned().unwrap_or_else(|| dummy_meta.clone())
                        } else {
                            self.meta(&v.id)?
                        };
                        let me: Origin = (v.id, self.intern(&v.path), meta_for_v);
                        let b: Arc<Blame> = if let Some((ref p, Some((_, mut pb_arc)))) = single_taken.take() {
                            if let Some(pm) = pre_maps[vi][0].take() {
                                let pb_mut = Arc::make_mut(&mut pb_arc);
                                crate::derive::blame::step_mapped_in_place(pb_mut, &me, n_lines, &pm, &mut chain_counts);
                                pb_arc
                            } else {
                                let inputs = [None];
                                let (b, _) = crate::derive::blame::step_mapped_with_counts(&me, n_lines, &inputs, &mut chain_counts);
                                let _ = p;
                                Arc::new(b)
                            }
                        } else {
                            let inputs: Vec<Option<(&Blame, crate::derive::blame::ParentMap)>> = parents
                                .iter()
                                .enumerate()
                                .map(|(pi, p)| {
                                    let p = p.as_ref()?;
                                    let (_, pb) = done.get(p)?.as_ref()?;
                                    let pm = pre_maps[vi][pi].take()?;
                                    Some((&**pb, pm))
                                })
                                .collect();
                            let (b, _) = crate::derive::blame::step_mapped_with_counts(&me, n_lines, &inputs, &mut chain_counts);
                            Arc::new(b)
                        };
                        chain_last = Some(v.clone());
                        if !used_pool {
                            self.f.g.cx.hub().query.blame_steps.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                        let should_keep = *v == *start || (b.vd.is_multiple_of(CHECKPOINT) && b.vd.is_multiple_of(spacing(computed, b.stored_estimate())));
                        if should_keep {
                            if self.limits.held >= 4 << 20 {
                                pending_keeps.push((v.clone(), b.clone()));
                            } else if !self.keep(v, &b) && *v == *start {
                                return Err(too_large());
                            }
                        }
                        let text = opt_text.unwrap_or_else(|| {
                            Arc::new(Text {
                                id: text_id,
                                data: bytes::Bytes::new(),
                                lines: Vec::new(),
                            })
                        });
                        Some((text, b))
                    }
                };
                if let Some((t, b)) = &out {
                    held += t.weight() + b.weight();
                }
                for p in parents.iter().flatten() {
                    let pn = nodes.get_mut(p).unwrap();
                    if pn.left > 0 {
                        pn.left -= 1;
                        if pn.left == 0 && p != start {
                            if let Some(Some((t, b))) = done.remove(p) {
                                held -= t.weight() + b.weight();
                            }
                        }
                    }
                }
                done.insert(v.clone(), out);
                if held + done.capacity() * (std::mem::size_of::<(Version, Done)>() + 1) + self.pending_bytes + self.side_bytes() > self.limits.held && !self.writes.is_empty() {
                    self.write()?;
                }
                if held + done.capacity() * (std::mem::size_of::<(Version, Done)>() + 1) + self.pending_bytes + self.side_bytes() > self.limits.held {
                    return Err(too_wide());
                }
                if self.writes.len() >= BATCH_BLAMES || self.pending_bytes >= self.batch_bytes() {
                    self.write()?;
                }
            }
            if !pending_keeps.is_empty() && (idx == unkept.len() || pending_keeps.len() >= BATCH_BLAMES) {
                self.stopped()?;
                let mut needed_ids: Vec<ObjectId> = Vec::new();
                for (_, kb) in &pending_keeps {
                    for &(o, _) in &kb.lines {
                        let (oid, _, m) = &kb.origins[o as usize];
                        if Arc::ptr_eq(m, &dummy_meta) && !self.metas.contains_key(oid) {
                            needed_ids.push(*oid);
                        }
                    }
                }
                needed_ids.sort_unstable();
                needed_ids.dedup();
                if !needed_ids.is_empty() {
                    let mut db_ids: Vec<String> = Vec::new();
                    for &id in &needed_ids {
                        if let std::collections::hash_map::Entry::Vacant(e) = gens.entry(id) {
                            if id == super::graph::root() {
                                e.insert(0);
                            } else if let Some(g) = self.f.g.cached_generation(&id) {
                                e.insert(g);
                            } else {
                                db_ids.push(id.hex());
                            }
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
                    for &id in &needed_ids {
                        if let std::collections::hash_map::Entry::Vacant(e) = gens.entry(id) {
                            e.insert(self.f.g.get(&id)?.generation);
                        }
                    }
                    if needed_ids.len() <= 2 {
                        for &id in &needed_ids {
                            let (id, m) = load_meta(id, gens[&id])?;
                            self.metas.insert(id, Arc::new(m));
                        }
                    } else {
                        let n_m = WORKERS.min(needed_ids.len());
                        let next_m = std::sync::atomic::AtomicUsize::new(0);
                        let out_m: Vec<std::sync::Mutex<Option<Result<(ObjectId, Meta)>>>> = (0..needed_ids.len()).map(|_| std::sync::Mutex::new(None)).collect();
                        let gens_ref = &gens;
                        let ids_ref = &needed_ids;
                        std::thread::scope(|s| {
                            for _ in 0..n_m {
                                s.spawn(|| loop {
                                    let j = next_m.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    if j >= ids_ref.len() {
                                        break;
                                    }
                                    let id = ids_ref[j];
                                    let r = load_meta(id, gens_ref[&id]);
                                    *out_m[j].lock().unwrap() = Some(r);
                                });
                            }
                        });
                        for m in out_m {
                            let (id, meta) = m.into_inner().unwrap().unwrap()?;
                            self.metas.insert(id, Arc::new(meta));
                        }
                    }
                }
                for (kv, kb) in &mut pending_keeps {
                    if kb.origins.iter().any(|(_, _, m)| Arc::ptr_eq(m, &dummy_meta)) {
                        let b_mut = Arc::make_mut(kb);
                        for (oid, _, m) in &mut b_mut.origins {
                            if Arc::ptr_eq(m, &dummy_meta) {
                                if let Some(found) = self.metas.get(oid) {
                                    *m = found.clone();
                                }
                            }
                        }
                        if let Some(Some((_, ref mut done_b))) = done.get_mut(kv) {
                            *done_b = kb.clone();
                        }
                    }
                }
                let encoded: Vec<Vec<u8>> = if pending_keeps.len() == 1 {
                    let p_keys = &self.path_keys;
                    vec![pending_keeps[0].1.encode(|p| {
                        p_keys
                            .get(&(p.as_ptr()))
                            .cloned()
                            .unwrap_or_else(|| path_key(p))
                    })]
                } else {
                    let mut pk_by_str: HashMap<&str, &str> = HashMap::with_capacity(self.paths.len());
                    for (s, arc) in &self.paths {
                        if let Some(k) = self.path_keys.get(&(Arc::as_ptr(arc) as *const u8)) {
                            pk_by_str.insert(s.as_str(), k.as_str());
                        }
                    }
                    let n_enc = WORKERS.min(pending_keeps.len());
                    let next_k = std::sync::atomic::AtomicUsize::new(0);
                    let out_k: Vec<std::sync::Mutex<Option<Vec<u8>>>> = (0..pending_keeps.len()).map(|_| std::sync::Mutex::new(None)).collect();
                    let keeps_ref = &pending_keeps;
                    let pk_ref = &pk_by_str;
                    std::thread::scope(|s| {
                        for _ in 0..n_enc {
                            s.spawn(|| loop {
                                let k = next_k.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                if k >= keeps_ref.len() {
                                    break;
                                }
                                let raw = keeps_ref[k].1.encode(|p| {
                                    pk_ref
                                        .get(p)
                                        .map(|&s| s.to_string())
                                        .unwrap_or_else(|| path_key(p))
                                });
                                *out_k[k].lock().unwrap() = Some(raw);
                            });
                        }
                    });
                    out_k.into_iter().map(|m| m.into_inner().unwrap().unwrap()).collect()
                };
                for ((kv, kb), raw) in std::mem::take(&mut pending_keeps).into_iter().zip(encoded) {
                    if !self.keep_encoded(&kv, &kb, raw) && kv == *start {
                        return Err(too_large());
                    }
                    if held + done.capacity() * (std::mem::size_of::<(Version, Done)>() + 1) + self.pending_bytes + self.side_bytes() > self.limits.held && !self.writes.is_empty() {
                        self.write()?;
                    }
                    if held + done.capacity() * (std::mem::size_of::<(Version, Done)>() + 1) + self.pending_bytes + self.side_bytes() > self.limits.held {
                        return Err(too_wide());
                    }
                    if self.writes.len() >= BATCH_BLAMES || self.pending_bytes >= self.batch_bytes() {
                        self.write()?;
                    }
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
        let p_keys = &self.path_keys;
        let raw = b.encode(|p| {
            p_keys
                .get(&(p.as_ptr()))
                .cloned()
                .unwrap_or_else(|| path_key(p))
        });
        self.keep_encoded(v, b, raw)
    }

    fn keep_encoded(&mut self, v: &Version, b: &Blame, raw: Vec<u8>) -> bool {
        if raw.len() > self.one_kept() {
            return false;
        }
        self.pending_bytes += raw.len() + 128;
        let mut named: Vec<String> = Vec::new();
        let mut seen: HashSet<*const u8> = HashSet::new();
        for (_, p, _) in &b.origins {
            let ptr = Arc::as_ptr(p) as *const u8;
            if !seen.insert(ptr) {
                continue;
            }
            let k = self
                .path_keys
                .get(&ptr)
                .cloned()
                .unwrap_or_else(|| path_key(p));
            if !self.write_paths.contains_key(&k) {
                self.pending_bytes += p.len() + 64;
                self.write_paths.insert(k.clone(), p.to_string());
            }
            named.push(k);
        }
        named.sort();
        named.dedup();
        self.pending_bytes += named.len() * 33;
        let vk = self
            .path_keys
            .get(&(Arc::as_ptr(&v.path) as *const u8))
            .cloned()
            .unwrap_or_else(|| path_key(&v.path));
        self.writes.push((vk, v.id, raw, named.join(",")));
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
        self.stopped()?;
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
        let now = veil_core::now_millis();
        let keys: Vec<&str> = w.iter().map(|r| r.0.as_str()).collect();
        let snaps: Vec<String> = w.iter().map(|r| r.1.hex()).collect();
        let bodies: Vec<&[u8]> = w.iter().map(|r| r.2.as_slice()).collect();
        let sizes: Vec<i64> = w.iter().map(|r| r.2.len() as i64).collect();
        let batch_sum: i64 = sizes.iter().sum();
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
        let prev_total = match self.total_kept_bytes {
            Some(t) => t,
            None => cx.db(|| {
                sqlx::query_scalar("SELECT COALESCE(SUM(bytes)::bigint, 0) FROM blame_memo WHERE project_id = $1 AND view_key = $2")
                    .bind(project)
                    .bind(vk)
                    .fetch_one(pool)
            })?,
        };
        let new_total = if self.total_kept_bytes.is_some() { prev_total + batch_sum } else { prev_total };
        self.total_kept_bytes = Some(new_total.min(self.limits.kept_bytes as i64));
        // The rows just written are counted first (newest) and never
        // dropped: they take at most half the cap (`batch_bytes`).
        if new_total > self.limits.kept_bytes as i64 {
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
        }
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
    /// Kept in `blame_memo` (re-read by the caller: BUG-1715).
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
    async fn take(self: &Arc<Self>, who: Requester) -> (Slot, bool) {
        let rx = {
            let mut st = self.state.lock().unwrap();
            // A free slot means nobody (still) waits: a freed one goes to a
            // waiter first.
            if st.free > 0 {
                st.free -= 1;
                st.last = Some(who);
                return (Slot { slots: Some(self.clone()) }, false);
            }
            let (tx, rx) = tokio::sync::oneshot::channel();
            st.queues.entry(who).or_default().push_back(tx);
            rx
        };
        // A sender is dropped only once sent.
        (rx.await.expect("a blame slot"), true)
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
#[allow(clippy::too_many_arguments)]
pub async fn wait_for_blame(
    hub: &Arc<crate::Hub>,
    project: &crate::perm::Project,
    viewer: &crate::perm::Viewer,
    start: &Version,
    follow: bool,
    limits: BlameLimits,
    deadline: std::time::Instant,
    seeded_window: Option<(Window, usize)>,
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
                        let r = leased_job(&hub, &project, &viewer, &key, &start, follow, limits, &ticket, seeded_window).await;
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
pub(crate) async fn current_view_access(hub: &crate::Hub, project: i64) -> Result<Option<(String, Option<String>)>> {
    sqlx::query_as(
        "SELECT md5(p.policy_text || '|' || p.policy_bindings || '|' || \
             COALESCE((SELECT string_agg(a.person_id::text, ',' ORDER BY a.person_id) FROM project_admins a WHERE a.project_id = p.id), '') || '|' || \
             COALESCE((SELECT string_agg(m.person_id::text || ':' || m.group_id::text, ',' ORDER BY m.person_id, m.group_id) \
                       FROM group_members m JOIN groups g ON g.id = m.group_id WHERE g.project_id = p.id), '')), \
             (SELECT v.access FROM view_access v WHERE v.project_id = p.id) \
         FROM projects p WHERE p.id = $1",
    )
    .bind(project)
    .fetch_optional(&hub.db)
    .await
    .map_err(Error::from)
}

pub async fn sweep_keys(hub: &crate::Hub, project: i64) -> Result<()> {
    let Some((access, recorded)) = current_view_access(hub, project).await? else { return Ok(()) };
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
    mut seeded_window: Option<(Window, usize)>,
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
    let wait = tokio::time::Instant::now() + limits.wait;
    let mut pause = Duration::from_millis(250);
    let mut waited_lease = false;
    let taken = loop {
        if let Some(at) = take().await? {
            break at;
        }
        waited_lease = true;
        if let Some(end) = settled(hub, key, limits).await? {
            return ended(end);
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
        let (_slot, waited_slot) = tokio::select! {
            s = hub.query.jobs.slots.take(who) => s,
            // Refused at the ceiling while it waits for a slot.
            _ = ticket.wake.notified() => return Err(warming()),
        };
        if waited_lease || waited_slot {
            seeded_window = None;
        }
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
        // Sweep any prior access change before writing under this job's key,
        // so the post-job sweep does not record an earlier change after the
        // write and drop rows written after that change (BUG-1711).
        sweep_keys(hub, key.0).await?;
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
            if let Some((w, loaded)) = seeded_window {
                f.seed_window(&start.path, w, loaded);
            }
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
    let mut named: HashMap<ObjectId, Arc<Meta>> = HashMap::with_capacity(b.origins.len());
    let origin_hex: Vec<String> = b.origins.iter().map(|(id, _, _)| id.hex()).collect();
    for i in from..to {
        let (o, l) = b.lines[i];
        let (id, p, m) = &b.origins[o as usize];
        named.entry(*id).or_insert_with(|| m.clone());
        let raw = text.line(i);
        let raw = raw.strip_suffix(b"\n").unwrap_or(raw);
        let raw = raw.strip_suffix(b"\r").unwrap_or(raw);
        lines.push(json!({
            "line": i + 1,
            "text": std::str::from_utf8(raw).unwrap_or(""),
            "snapshot": &origin_hex[o as usize],
            "change": &m.change_id,
            "change_short": m.change_id.get(..8).unwrap_or(&m.change_id),
            "path": &**p,
            "origin_line": l,
        }));
    }
    let mut order: Vec<(i64, ObjectId)> = named.iter().map(|(id, m)| (m.generation, *id)).collect();
    order.sort_by(|a, b| b.cmp(a));
    let changes: Vec<Value> = order
        .iter()
        .map(|(_, id)| {
            let m = &named[id];
            let hex = id.hex();
            json!({
                "snapshot_id": &hex,
                "snapshot_short": &hex[..8],
                "change_id": &m.change_id,
                "change_short": m.change_id.get(..8).unwrap_or(&m.change_id),
                "author": &m.author,
                "timestamp": m.timestamp,
                "summary": &m.summary,
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
