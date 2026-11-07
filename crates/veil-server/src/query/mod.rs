//! The query API (milestone S13; `docs/design/server/phase-3-server-history.md`
//! §3.3): history answered by the server, per viewer, with no checkout.
//!
//! | Route (`/v1/projects/{p}/q/…`) | Answers |
//! |---|---|
//! | `GET log?rev=&n=&path=&after=` | a page of the viewer's history from `rev`, children first, newest first by generation (`vl log`'s order wherever every snapshot is dated after its parents); with `path`, only snapshots that changed something the viewer may read at or under it |
//! | `GET show?rev=&path=&stat=` | a snapshot's fields and its diff against its first parent (the viewer's part) |
//! | `GET tree?rev=&path=&after=` | a folder of the viewer's projected tree |
//! | `GET file?rev=&path=` | a file's bytes (a secret's ciphertext) |
//! | `GET diff?from=&to=&base=&path=&stat=` | the diff from the merge base of `from` and `to` (`base=merge`, the default) or from `from` itself (`base=from`), to `to` |
//! | `POST ancestry {pairs}` | `is_ancestor` and merge bases, for pairs of revisions |
//! | `GET blame?rev=&path=&follow=&after=&n=` | who introduced each line of a file (S14, [`files`]): a page of its lines, each with the change that introduced it, its path and line there |
//! | `GET history?rev=&path=&follow=&n=&after=` | the changes that made each version of a file (S14), newest first; with `follow`, across renames between paths the viewer reads |
//!
//! **Every answer is computed on the viewer's projected history** (the
//! history pulls give them, `docs/HUB.md` §13.4): its graph
//! ([`graph`], one row per projected snapshot) and its trees ([`trees`],
//! projected by path). Nothing hidden is walked, read, counted or ranked
//! by a query, so each answer, and the work it took, equals what a copy of
//! the project holding only that history would give (the
//! projection-equivalence test). Real snapshot ids are accepted only from
//! admins; anyone else names a revision by branch or by an id of their own
//! history. A hidden path or revision and a missing one get the same
//! error, by the same code path.
//!
//! Bounds: `n` ≤ 1,000 a page, and 8 MiB; a log stops after a fixed amount
//! of work (which a log filtered by path reaches) and answers a cursor
//! (`next`) to go on from; cursors
//! name at most 1,000 snapshots; a diff lists 10,000 files and 8 MiB of
//! changed lines; a folder listing 10,000 entries; 100 ancestry pairs; and
//! every query has a 2 s deadline, past which it fails (never answers less).
//! A viewer's graph not filled yet is filled once, in the background
//! (`graph::ensure`); a query waits for it until its deadline, then answers
//! `warming`.
//! Every answer carries the policy version it was computed under, and its
//! `work` (rows and objects read).

pub mod files;
pub mod graph;
pub mod trees;

use std::{
    collections::{BinaryHeap, HashMap, HashSet},
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    extract::{Path, Query, State},
    http::header,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use veil_core::{object::Snapshot, ObjectId};

use self::{
    graph::{blocking, ensure, root, VRow, G},
    trees::{clean_path, entry_json, DiffLimits, Trees},
};
use crate::{
    auth::Caller,
    error::{Error, Result},
    perm::{self, Project, Viewer},
    Hub, HubState,
};

/// The bounds of one query.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Most entries of a log page, and about the most bytes (a page ends
    /// after the entry that reaches it).
    pub page: usize,
    pub page_bytes: usize,
    /// Work (rows and objects read) after which a log answers what it found
    /// so far, with a cursor (a log filtered by path reaches it; others
    /// hardly can).
    pub work: u64,
    pub diff: DiffLimits,
    /// Most entries of a folder listing.
    pub list: usize,
    /// Most snapshots a cursor names itself; a wider one is kept by the
    /// server and named by a token (BUG-1076).
    pub cursor: usize,
    /// Most snapshots a log's frontier (and a kept cursor) may hold: a page
    /// ends before a step would pass it.
    pub frontier: usize,
    /// How long a kept cursor lives from its last writing, and the most
    /// bytes of kept cursors a project holds (oldest dropped first).
    pub kept_for: Duration,
    pub kept_bytes: usize,
    /// Most ancestry pairs.
    pub pairs: usize,
    /// What one blame may spend and show (S14).
    pub blame: files::BlameLimits,
    pub deadline: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            page: 1_000,
            page_bytes: 8 << 20,
            work: 20_000,
            diff: DiffLimits::default(),
            list: 10_000,
            cursor: 1_000,
            frontier: 10_000,
            kept_for: Duration::from_secs(3600),
            kept_bytes: 32 << 20,
            pairs: 100,
            blame: files::BlameLimits::default(),
            deadline: Duration::from_secs(2),
        }
    }
}

/// Who asks, in which project.
#[derive(Clone, Debug)]
pub struct Ask {
    pub project: Project,
    pub viewer: Viewer,
    pub policy_version: i64,
}

impl Ask {
    pub async fn open(hub: &Hub, project: &str, caller: &Caller) -> Result<Ask> {
        // Read before the policy itself: an answer is never labelled with a
        // version newer than the policy it was computed under.
        let policy_version: Option<i64> = sqlx::query_scalar("SELECT policy_version FROM projects WHERE name = $1")
            .bind(project)
            .fetch_optional(&hub.db)
            .await?;
        let (project, viewer) = perm::open(hub, project, caller).await?;
        let policy_version = policy_version.unwrap_or(0);
        Ok(Ask {
            project,
            viewer,
            policy_version,
        })
    }

    fn key(&self) -> String {
        self.project.view(&self.viewer).key()
    }
}

fn no_revision() -> Error {
    Error::not_found("no such revision that you can see")
}

fn no_path() -> Error {
    Error::not_found("no such path at this revision that you can see")
}

fn parse_id(s: &str) -> Option<ObjectId> {
    (s.len() == 64).then(|| ObjectId::from_hex(s).ok()).flatten()
}

/// The viewer's id of revision `rev`: a branch, or a snapshot id of their
/// own history (any committed snapshot for an admin). Hidden, withheld and
/// missing revisions are all "no such revision".
pub async fn resolve(hub: &Arc<Hub>, ask: &Ask, rev: &str, deadline: Instant) -> Result<ObjectId> {
    let vk = ask.key();
    let project = ask.project.id;
    let row_of = |id: ObjectId| {
        let vk = vk.clone();
        blocking(hub, project, move |cx| G::new(cx, &vk, None).row(&id))
    };
    let real = match parse_id(rev) {
        Some(id) => {
            if let Some(r) = row_of(id).await? {
                return if r.withheld() { Err(no_revision()) } else { Ok(id) };
            }
            let real: Option<String> = if ask.viewer.admin {
                if id == root() {
                    Some(id.hex())
                } else {
                    sqlx::query_scalar("SELECT id FROM snapshots WHERE project_id = $1 AND id = $2")
                        .bind(project)
                        .bind(id.hex())
                        .fetch_optional(&hub.db)
                        .await?
                }
            } else {
                // Only an id this viewer was given: a projection memoised
                // under their view key.
                sqlx::query_scalar("SELECT real_id FROM projections WHERE project_id = $1 AND view_key = $2 AND projected_id = $3 LIMIT 1")
                    .bind(project)
                    .bind(&vk)
                    .bind(id.hex())
                    .fetch_optional(&hub.db)
                    .await?
            };
            real.and_then(|r| ObjectId::from_hex(&r).ok()).ok_or_else(no_revision)?
        }
        None => {
            if rev.is_empty() || rev.len() > 255 {
                return Err(no_revision());
            }
            let target: Option<String> = sqlx::query_scalar("SELECT target FROM branches WHERE project_id = $1 AND name = $2")
                .bind(project)
                .bind(rev)
                .fetch_optional(&hub.db)
                .await?;
            target.and_then(|t| ObjectId::from_hex(&t).ok()).ok_or_else(no_revision)?
        }
    };
    let p = ensure(hub, &ask.project, &ask.viewer, &[real], Some(deadline)).await?[0];
    match row_of(p).await? {
        Some(r) if !r.withheld() && (parse_id(rev).is_none() || parse_id(rev) == Some(p)) => Ok(p),
        _ => Err(no_revision()),
    }
}

/// Run `f` on the viewer's graph on a blocking thread, with the deadline;
/// adds `policy_version` and `work` to the answer.
async fn on_graph(
    hub: &Arc<Hub>,
    ask: &Ask,
    deadline: Instant,
    f: impl FnOnce(&G, &Trees) -> Result<Value> + Send + 'static,
) -> Result<Value> {
    let (vk, project, viewer, version) = (ask.key(), ask.project.clone(), ask.viewer.clone(), ask.policy_version);
    blocking(hub, project.id, move |cx| {
        let view = project.view(&viewer);
        let g = G::new(cx, &vk, Some(deadline));
        let t = Trees::new(&g, &view);
        let mut v = f(&g, &t).map_err(|e| if Instant::now() > deadline { graph::too_slow() } else { e })?;
        v["policy_version"] = json!(version);
        v["work"] = json!(g.work());
        Ok(v)
    })
    .await
}

/// A snapshot as a log entry or a `show` shows it.
fn snapshot_json(id: &ObjectId, s: &Snapshot, empty: bool) -> Value {
    let is_root = *id == root();
    json!({
        "snapshot_id": id.hex(),
        "snapshot_short": id.short(),
        "change_id": s.change_id.to_string(),
        "change_short": s.change_id.short(),
        "root": is_root,
        "author": (!is_root).then(|| s.author.clone()),
        "timestamp": (!is_root).then_some(s.timestamp),
        "signature": s.signature.as_ref().map(|g| json!({ "signer": g.signer, "key": g.key })),
        "description": s.description.as_str(),
        "conflicts": s.conflicts,
        "empty": empty,
        "parents": s.parents.iter().map(|p| json!({ "snapshot_id": p.hex(), "snapshot_short": p.short() })).collect::<Vec<_>>(),
    })
}

// ---- log ---------------------------------------------------------------------------

/// The log's walk on a viewer's graph: newest first by generation (the
/// corrected commit date: a snapshot's timestamp, raised above its
/// parents'), ties by id. Generations strictly decrease from child to
/// parent, so children always come before their parents. Every read is one
/// row (BUG-1071, BUG-1078): a snapshot's parents wait in `pending` and
/// are read one at a time before the next snapshot is taken, so a page can
/// stop between any two reads. What is left to walk is exactly the
/// frontier (the heap and `pending`), which the cursor names.
struct LogWalk<'g, 'a> {
    g: &'g G<'a>,
    heap: BinaryHeap<(i64, ObjectId)>,
    rows: HashMap<ObjectId, Arc<VRow>>,
    queued: HashSet<ObjectId>,
    pending: Vec<ObjectId>,
}

impl<'g, 'a> LogWalk<'g, 'a> {
    fn new(g: &'g G<'a>, roots: &[ObjectId]) -> LogWalk<'g, 'a> {
        let mut w = LogWalk {
            g,
            heap: BinaryHeap::new(),
            rows: HashMap::new(),
            queued: HashSet::new(),
            pending: Vec::new(),
        };
        for r in roots {
            if w.queued.insert(*r) {
                w.pending.push(*r);
            }
        }
        w
    }

    /// Read one waiting snapshot's row into the heap; false if none waits.
    /// A snapshot a cursor names that is not in the viewer's graph (or is
    /// withheld) is no revision of theirs.
    fn read_one(&mut self) -> Result<bool> {
        let Some(id) = self.pending.pop() else { return Ok(false) };
        let row = match self.g.row(&id)? {
            Some(r) if !r.withheld() => r,
            _ => return Err(no_revision()),
        };
        self.heap.push((row.generation, id));
        self.rows.insert(id, row);
        Ok(true)
    }

    /// The next snapshot of the log and its row, once nothing waits, unless
    /// taking it would make the frontier wider than `max`. Every child of a
    /// snapshot has a larger generation, so it was taken (and queued this
    /// one) before this one is: none is queued twice or after it is taken.
    fn take(&mut self, max: usize) -> Option<(ObjectId, Arc<VRow>)> {
        debug_assert!(self.pending.is_empty());
        let &(_, id) = self.heap.peek()?;
        let row = self.rows[&id].clone();
        let grows = row.parents.iter().filter(|p| !self.queued.contains(p)).count();
        if self.heap.len() - 1 + grows > max {
            return None;
        }
        self.heap.pop();
        self.rows.remove(&id);
        for p in &row.parents {
            if self.queued.insert(*p) {
                self.pending.push(*p);
            }
        }
        Some((id, row))
    }

    /// The snapshots the rest of the log starts from: the walk of the rest
    /// from them is exactly the rest of this one.
    fn frontier(&self) -> Vec<ObjectId> {
        let mut out: Vec<ObjectId> = self.heap.iter().map(|(_, id)| *id).chain(self.pending.iter().copied()).collect();
        out.sort();
        out
    }
}

/// A cursor naming more than `Limits::cursor` snapshots is kept by the
/// server (BUG-1076), under the hash of what it names and the viewer's key,
/// and handed out as `frontier-<hash>`: a function of the viewer's history,
/// as the cursor itself is (the same page always writes the same row).
const STORED_CURSOR: &str = "frontier-";

/// Keep a wide cursor (BUG-1076), and bound what the project keeps: one
/// row per request, at most `Limits::frontier` snapshots in it (about
/// 65 bytes each); a row lives `Limits::kept_for` from its last writing
/// (the same frontier written again is the same row, refreshed); and every
/// write deletes the project's expired rows, then its oldest rows past
/// `Limits::kept_bytes` in all. A cursor so dropped is refused when sent
/// back (`invalid cursor`): the log is asked for again from its start.
fn keep_cursor(cx: &crate::derive::Cx, vk: &str, id: &str, text: &str, limits: &Limits) -> Result<()> {
    let now = veil_core::now_millis();
    let pool = &cx.hub().db;
    cx.db(|| {
        sqlx::query(
            "INSERT INTO log_cursors (project_id, view_key, id, frontier, created_at) VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (project_id, view_key, id) DO UPDATE SET created_at = EXCLUDED.created_at",
        )
        .bind(cx.project())
        .bind(vk)
        .bind(id)
        .bind(text)
        .bind(now)
        .execute(pool)
    })?;
    let expired = now - limits.kept_for.as_millis() as i64;
    cx.db(|| {
        sqlx::query("DELETE FROM log_cursors WHERE project_id = $1 AND created_at < $2")
            .bind(cx.project())
            .bind(expired)
            .execute(pool)
    })?;
    cx.db(|| {
        sqlx::query(
            "DELETE FROM log_cursors WHERE project_id = $1 AND (view_key, id) IN ( \
                 SELECT view_key, id FROM ( \
                     SELECT view_key, id, SUM(LENGTH(frontier)) OVER (ORDER BY created_at DESC, view_key, id) AS kept \
                     FROM log_cursors WHERE project_id = $1) t \
                 WHERE kept > $2)",
        )
        .bind(cx.project())
        .bind(limits.kept_bytes as i64)
        .execute(pool)
    })?;
    Ok(())
}

fn cursor_id(ids: &[ObjectId]) -> String {
    let mut h = blake3::Hasher::new_derive_key("veil 2026 hub log cursor v1");
    for id in ids {
        h.update(&id.0);
    }
    hex::encode(&h.finalize().as_bytes()[..16])
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct LogParams {
    pub rev: Option<String>,
    pub n: Option<usize>,
    pub path: Option<String>,
    pub after: Option<String>,
}

/// A page of the viewer's log.
pub async fn log(hub: &Arc<Hub>, ask: &Ask, q: LogParams, limits: Limits) -> Result<Value> {
    let deadline = Instant::now() + limits.deadline;
    let n = q.n.unwrap_or(50).min(limits.page);
    let path = clean_path(q.path.as_deref().unwrap_or(""))?;
    let after = q.after.clone();
    let roots: Vec<ObjectId> = match &after {
        Some(a) if a.starts_with(STORED_CURSOR) => Vec::new(),
        Some(a) => {
            let ids: Vec<&str> = a.split(',').filter(|s| !s.is_empty()).collect();
            if ids.len() > limits.cursor {
                return Err(Error::bad_request("cursor too long"));
            }
            let mut out = Vec::new();
            for s in ids {
                // A cursor names snapshots of the viewer's own graph.
                let id = parse_id(s).ok_or_else(|| Error::bad_request("invalid cursor"))?;
                out.push(id);
            }
            out
        }
        None => vec![resolve(hub, ask, q.rev.as_deref().unwrap_or(&ask.project.default_branch), deadline).await?],
    };
    on_graph(hub, ask, deadline, move |g, t| {
        let mut roots = roots;
        if let Some(token) = after.as_deref().and_then(|a| a.strip_prefix(STORED_CURSOR)) {
            g.tick()?;
            let (cx, vk) = (g.cx, g.vk);
            let fresh = veil_core::now_millis() - limits.kept_for.as_millis() as i64;
            let stored: Option<String> = cx.db(|| {
                sqlx::query_scalar("SELECT frontier FROM log_cursors WHERE project_id = $1 AND view_key = $2 AND id = $3 AND created_at >= $4")
                    .bind(cx.project())
                    .bind(vk)
                    .bind(token)
                    .bind(fresh)
                    .fetch_optional(&cx.hub().db)
            })?;
            let stored = stored.ok_or_else(|| Error::bad_request("invalid cursor"))?;
            roots = stored.split(',').map(|s| parse_id(s).ok_or_else(|| Error::bad_request("invalid cursor"))).collect::<Result<_>>()?;
        }
        let mut walk = LogWalk::new(g, &roots);
        let start = g.work();
        let mut entries = Vec::new();
        let mut bytes = 0usize;
        // Whether the page took a snapshot: reading the cursor's rows alone
        // is no progress (BUG-1079), and a page that only reads them would
        // hand back the cursor it was given.
        let mut took = false;
        while entries.len() < n && g.work() - start < limits.work {
            if walk.read_one()? {
                continue;
            }
            let Some((id, row)) = walk.take(limits.frontier) else { break };
            took = true;
            if !path.is_empty() {
                let (now, before) = t.roots_of(&row)?;
                if !t.differs_at(now, before, &path)? {
                    continue;
                }
            }
            let s = g.snapshot(&id)?;
            let empty = match s.parents.first() {
                Some(p) => g.snapshot(p)?.tree == s.tree,
                None => true,
            };
            let e = snapshot_json(&id, &s, empty);
            bytes += e.to_string().len();
            entries.push(e);
            if bytes >= limits.page_bytes {
                break;
            }
        }
        let heads = walk.frontier();
        if !took && n > 0 && !heads.is_empty() {
            // Nothing could be taken without a frontier wider than the
            // server keeps: an error, never a cursor that goes nowhere.
            return Err(Error::bad_request("this history is too wide to page (more open lines than the server keeps in a cursor)"));
        }
        let next = if heads.is_empty() {
            None
        } else if heads.len() <= limits.cursor {
            Some(heads.iter().map(|h| h.hex()).collect::<Vec<_>>().join(","))
        } else {
            let id = cursor_id(&heads);
            let text = heads.iter().map(|h| h.hex()).collect::<Vec<_>>().join(",");
            let (cx, vk) = (g.cx, g.vk);
            keep_cursor(cx, vk, &id, &text, &limits)?;
            Some(format!("{STORED_CURSOR}{id}"))
        };
        Ok(json!({
            "schema": "veil.log/2",
            "entries": entries,
            "truncated": next.is_some(),
            "next": next,
        }))
    })
    .await
}

// ---- show, tree, file, diff ----------------------------------------------------------

#[derive(Clone, Debug, Default, Deserialize)]
pub struct ShowParams {
    pub rev: Option<String>,
    pub path: Option<String>,
    pub stat: Option<bool>,
}

/// A snapshot and the viewer's part of its changes against its first parent.
pub async fn show(hub: &Arc<Hub>, ask: &Ask, q: ShowParams, limits: Limits) -> Result<Value> {
    let deadline = Instant::now() + limits.deadline;
    let path = clean_path(q.path.as_deref().unwrap_or(""))?;
    let id = resolve(hub, ask, q.rev.as_deref().unwrap_or(&ask.project.default_branch), deadline).await?;
    let content = !q.stat.unwrap_or(false);
    on_graph(hub, ask, deadline, move |g, t| {
        let row = g.get(&id)?;
        let s = g.snapshot(&id)?;
        let (now, before) = t.roots_of(&row)?;
        let mut v = snapshot_json(&id, &s, s.parents.is_empty() || now == before);
        v["schema"] = json!("veil.show/2");
        v["diff"] = t.diff(before, now, &path, content, limits.diff)?;
        Ok(v)
    })
    .await
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct TreeParams {
    pub rev: Option<String>,
    pub path: Option<String>,
    pub after: Option<String>,
}

/// A folder of the viewer's projected tree at a revision.
pub async fn tree(hub: &Arc<Hub>, ask: &Ask, q: TreeParams, limits: Limits) -> Result<Value> {
    let deadline = Instant::now() + limits.deadline;
    let path = clean_path(q.path.as_deref().unwrap_or(""))?;
    let id = resolve(hub, ask, q.rev.as_deref().unwrap_or(&ask.project.default_branch), deadline).await?;
    on_graph(hub, ask, deadline, move |g, t| {
        let root = t.root_of(&*g.get(&id)?)?;
        let dir = if path.is_empty() {
            root
        } else {
            match t.entry_at(root, &path)? {
                Some(e) if e.kind == veil_core::object::EntryKind::Dir => e.id,
                _ => return Err(no_path()),
            }
        };
        let Some(tree) = t.tree(&dir)? else { return Err(no_path()) };
        let after = q.after.unwrap_or_default();
        let mut entries = Vec::new();
        let mut truncated = false;
        for e in tree.entries.iter().filter(|e| e.name.as_str() > after.as_str()) {
            if entries.len() == limits.list {
                truncated = true;
                break;
            }
            let mut v = entry_json(Some(e));
            v["name"] = json!(e.name);
            entries.push(v);
        }
        let next = truncated.then(|| entries.last().map(|e| e["name"].clone())).flatten();
        Ok(json!({
            "schema": "veil.tree/1",
            "snapshot_id": id.hex(),
            "path": path,
            "id": dir.hex(),
            "entries": entries,
            "truncated": truncated,
            "next": next,
        }))
    })
    .await
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct FileParams {
    pub rev: Option<String>,
    pub path: String,
}

/// A file of the viewer's projected tree at a revision: its entry, and its
/// bytes (a blob's content; for a secret or a conflict, the stored object,
/// which only key holders can open).
pub async fn file(hub: &Arc<Hub>, ask: &Ask, q: FileParams, limits: Limits) -> Result<(Value, Vec<u8>)> {
    let deadline = Instant::now() + limits.deadline;
    let path = clean_path(&q.path)?;
    if path.is_empty() {
        return Err(no_path());
    }
    let id = resolve(hub, ask, q.rev.as_deref().unwrap_or(&ask.project.default_branch), deadline).await?;
    let out = Arc::new(std::sync::Mutex::new(Vec::new()));
    let out2 = out.clone();
    let meta = on_graph(hub, ask, deadline, move |g, t| {
        let root = t.root_of(&*g.get(&id)?)?;
        let e = t.entry_at(root, &path)?.ok_or_else(no_path)?;
        if e.kind == veil_core::object::EntryKind::Dir {
            return Err(Error::bad_request("a folder: list it with `tree`"));
        }
        let (blob, bytes) = t.content(&e.id)?;
        *out2.lock().unwrap() = bytes;
        let mut v = entry_json(Some(&e));
        v["schema"] = json!("veil.file/1");
        v["snapshot_id"] = json!(id.hex());
        v["path"] = json!(path);
        v["encoding"] = json!(if blob { "content" } else { "object" });
        Ok(v)
    })
    .await?;
    let bytes = std::mem::take(&mut *out.lock().unwrap());
    Ok((meta, bytes))
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct DiffParams {
    pub from: String,
    pub to: Option<String>,
    pub base: Option<String>,
    pub path: Option<String>,
    pub stat: Option<bool>,
}

/// The diff between two revisions, from their merge base by default.
pub async fn diff(hub: &Arc<Hub>, ask: &Ask, q: DiffParams, limits: Limits) -> Result<Value> {
    let deadline = Instant::now() + limits.deadline;
    let path = clean_path(q.path.as_deref().unwrap_or(""))?;
    let merge = match q.base.as_deref().unwrap_or("merge") {
        "merge" => true,
        "from" => false,
        _ => return Err(Error::bad_request("base is `merge` or `from`")),
    };
    let from = resolve(hub, ask, &q.from, deadline).await?;
    let to = resolve(hub, ask, q.to.as_deref().unwrap_or(&ask.project.default_branch), deadline).await?;
    let content = !q.stat.unwrap_or(false);
    on_graph(hub, ask, deadline, move |g, t| {
        let bases = if merge { g.merge_bases(from, to)? } else { vec![from] };
        // Every history starts at the root, so there is always one.
        let base = bases[0];
        let (old, new) = (t.root_of(&*g.get(&base)?)?, t.root_of(&*g.get(&to)?)?);
        let mut v = t.diff(old, new, &path, content, limits.diff)?;
        v["schema"] = json!("veil.diff/2");
        v["from"] = json!(from.hex());
        v["to"] = json!(to.hex());
        v["base"] = json!(base.hex());
        v["merge_bases"] = json!(bases.iter().map(|b| b.hex()).collect::<Vec<_>>());
        Ok(v)
    })
    .await
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct AncestryRequest {
    pub pairs: Vec<(String, String)>,
}

/// `is_ancestor` and the merge bases of each pair.
pub async fn ancestry(hub: &Arc<Hub>, ask: &Ask, q: AncestryRequest, limits: Limits) -> Result<Value> {
    let deadline = Instant::now() + limits.deadline;
    if q.pairs.len() > limits.pairs {
        return Err(Error::bad_request(format!("at most {} pairs", limits.pairs)));
    }
    let mut pairs = Vec::new();
    for (a, b) in &q.pairs {
        pairs.push((resolve(hub, ask, a, deadline).await?, resolve(hub, ask, b, deadline).await?));
    }
    on_graph(hub, ask, deadline, move |g, _| {
        let mut out = Vec::new();
        for (a, b) in pairs {
            out.push(json!({
                "a": a.hex(),
                "b": b.hex(),
                "is_ancestor": g.is_ancestor(a, b)?,
                "merge_bases": g.merge_bases(a, b)?.iter().map(|m| m.hex()).collect::<Vec<_>>(),
            }));
        }
        Ok(json!({ "schema": "veil.ancestry/1", "results": out }))
    })
    .await
}

// ---- blame and file history (S14) ------------------------------------------------------

#[derive(Clone, Debug, Default, Deserialize)]
pub struct BlameParams {
    pub rev: Option<String>,
    pub path: String,
    pub follow: Option<bool>,
    /// Lines shown start after this one (a page's `next`).
    pub after: Option<usize>,
    pub n: Option<usize>,
}

/// The version of a file a blame or history starts from, at the viewer's
/// snapshot `id`: its entry there must be a file (a missing and a hidden
/// path are the same: absent from the projected tree).
fn file_entry(g: &G, t: &Trees, id: &ObjectId, path: &str) -> Result<Option<veil_core::TreeEntry>> {
    let root = t.root_of(&*g.get(id)?)?;
    let e = t.entry_at(root, path)?;
    if e.as_ref().is_some_and(|e| e.kind == veil_core::object::EntryKind::Dir) {
        return Err(Error::bad_request("a folder: blame and file history are of files (`log` takes a folder)"));
    }
    Ok(e)
}

/// Who introduced each line of a file at a revision: computed on the
/// viewer's projected history from its versions' kept blames
/// ([`files::Blamer`]), a page of lines at a time.
pub async fn blame(hub: &Arc<Hub>, ask: &Ask, q: BlameParams, limits: Limits) -> Result<Value> {
    let deadline = Instant::now() + limits.deadline;
    let path = clean_path(&q.path)?;
    if path.is_empty() {
        return Err(no_path());
    }
    let id = resolve(hub, ask, q.rev.as_deref().unwrap_or(&ask.project.default_branch), deadline).await?;
    let follow = q.follow.unwrap_or(false);
    let (after, n) = (q.after.unwrap_or(0), q.n.unwrap_or(limits.blame.lines).min(limits.blame.lines));
    // One of the process's blames (BUG-1072's lesson: bounded whatever
    // the number of requests), waited for until the deadline.
    let _slot = tokio::time::timeout_at(deadline.into(), hub.query.blames.clone().acquire_owned())
        .await
        .map_err(|_| graph::too_slow())?
        .map_err(|e| Error::Other(e.into()))?;
    on_graph(hub, ask, deadline, move |g, t| {
        let e = file_entry(g, t, &id, &path)?.ok_or_else(no_path)?;
        if !e.visibility.is_public() {
            return Err(Error::bad_request("a secret: its content is encrypted, and the server cannot read it"));
        }
        let f = files::Files::new(g);
        let (depth, x) = f.intro(id, &path)?.ok_or_else(|| Error::Other(anyhow::anyhow!("file history: no version of a file present")))?;
        let start = files::Version { id: x, depth, path: path.clone() };
        let mut b = files::Blamer::new(&f, t, follow, limits.blame);
        let Some((text, bl)) = b.blame(&start)? else {
            return Err(Error::bad_request("not a plain-text file of at most 1 MiB: nothing to blame line by line"));
        };
        files::blame_json(g, id, &path, follow, &text, &bl, after, n)
    })
    .await
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct HistoryParams {
    pub rev: Option<String>,
    pub path: Option<String>,
    pub follow: Option<bool>,
    pub n: Option<usize>,
    pub after: Option<String>,
}

/// A page of a file's history: the changes that made each of its versions,
/// newest first; with `follow`, across renames between readable paths.
pub async fn history(hub: &Arc<Hub>, ask: &Ask, q: HistoryParams, limits: Limits) -> Result<Value> {
    let deadline = Instant::now() + limits.deadline;
    let n = q.n.unwrap_or(50).min(limits.page);
    let follow = q.follow.unwrap_or(false);
    let start = match &q.after {
        Some(a) => Err(files::parse_cursor(a, limits.cursor)?),
        None => {
            let path = clean_path(q.path.as_deref().unwrap_or(""))?;
            if path.is_empty() {
                return Err(no_path());
            }
            Ok((resolve(hub, ask, q.rev.as_deref().unwrap_or(&ask.project.default_branch), deadline).await?, path))
        }
    };
    on_graph(hub, ask, deadline, move |g, t| {
        let f = files::Files::new(g);
        let starts = match start {
            Ok((id, path)) => {
                file_entry(g, t, &id, &path)?;
                let (depth, x) = f.intro(id, &path)?.ok_or_else(no_path)?;
                vec![files::Version { id: x, depth, path }]
            }
            Err(nodes) => {
                let mut out = Vec::new();
                for (id, path) in nodes {
                    // A cursor names versions of the viewer's own graph.
                    let r = match g.row(&id)? {
                        Some(r) if !r.withheld() => r,
                        _ => return Err(no_revision()),
                    };
                    out.push(files::Version { id, depth: r.depth, path });
                }
                out
            }
        };
        files::history_page(&f, t, starts, follow, n, limits.page_bytes, limits.work, limits.cursor, |id, s| snapshot_json(id, s, false))
    })
    .await
}

// ---- routes ---------------------------------------------------------------------------

pub async fn log_route(State(hub): State<HubState>, caller: Caller, Path(p): Path<String>, Query(q): Query<LogParams>) -> Result<Json<Value>> {
    let ask = Ask::open(&hub, &p, &caller).await?;
    Ok(Json(log(&hub, &ask, q, Limits::default()).await?))
}

pub async fn show_route(State(hub): State<HubState>, caller: Caller, Path(p): Path<String>, Query(q): Query<ShowParams>) -> Result<Json<Value>> {
    let ask = Ask::open(&hub, &p, &caller).await?;
    Ok(Json(show(&hub, &ask, q, Limits::default()).await?))
}

pub async fn tree_route(State(hub): State<HubState>, caller: Caller, Path(p): Path<String>, Query(q): Query<TreeParams>) -> Result<Json<Value>> {
    let ask = Ask::open(&hub, &p, &caller).await?;
    Ok(Json(tree(&hub, &ask, q, Limits::default()).await?))
}

pub async fn file_route(State(hub): State<HubState>, caller: Caller, Path(p): Path<String>, Query(q): Query<FileParams>) -> Result<Response> {
    let ask = Ask::open(&hub, &p, &caller).await?;
    let (meta, bytes) = file(&hub, &ask, q, Limits::default()).await?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (header::HeaderName::from_static("x-veil-file"), ascii_json(&meta)),
        ],
        bytes,
    )
        .into_response())
}

/// `v` as JSON in visible ASCII only (a header value): every other
/// character escaped as `\\uXXXX`.
fn ascii_json(v: &Value) -> String {
    let mut out = String::new();
    for c in v.to_string().chars() {
        if (' '..='~').contains(&c) {
            out.push(c);
        } else {
            let mut units = [0u16; 2];
            for u in c.encode_utf16(&mut units) {
                out.push_str(&format!("\\u{u:04x}"));
            }
        }
    }
    out
}

pub async fn diff_route(State(hub): State<HubState>, caller: Caller, Path(p): Path<String>, Query(q): Query<DiffParams>) -> Result<Json<Value>> {
    let ask = Ask::open(&hub, &p, &caller).await?;
    Ok(Json(diff(&hub, &ask, q, Limits::default()).await?))
}

pub async fn blame_route(State(hub): State<HubState>, caller: Caller, Path(p): Path<String>, Query(q): Query<BlameParams>) -> Result<Json<Value>> {
    let ask = Ask::open(&hub, &p, &caller).await?;
    Ok(Json(blame(&hub, &ask, q, Limits::default()).await?))
}

pub async fn history_route(State(hub): State<HubState>, caller: Caller, Path(p): Path<String>, Query(q): Query<HistoryParams>) -> Result<Json<Value>> {
    let ask = Ask::open(&hub, &p, &caller).await?;
    Ok(Json(history(&hub, &ask, q, Limits::default()).await?))
}

pub async fn ancestry_route(State(hub): State<HubState>, caller: Caller, Path(p): Path<String>, Json(q): Json<AncestryRequest>) -> Result<Json<Value>> {
    let ask = Ask::open(&hub, &p, &caller).await?;
    Ok(Json(ancestry(&hub, &ask, q, Limits::default()).await?))
}

#[cfg(test)]
mod tests {
    use super::trees::clean_path;

    #[test]
    fn header_json_is_ascii() {
        let v = serde_json::json!({ "path": "dé/日本\u{7f}\n\u{1F600}" });
        let h = super::ascii_json(&v);
        assert!(h.bytes().all(|b| (b' '..=b'~').contains(&b)), "{h}");
        assert_eq!(serde_json::from_str::<serde_json::Value>(&h).unwrap(), v);
        assert!(axum::http::HeaderValue::from_str(&h).is_ok());
    }

    #[test]
    fn paths_are_checked_by_syntax_alone() {
        assert_eq!(clean_path("").unwrap(), "");
        assert_eq!(clean_path("src/").unwrap(), "src");
        assert_eq!(clean_path("src/a.rs").unwrap(), "src/a.rs");
        for bad in ["/src", "src//a", "./a", "a/../b", "..", "a/./b", "a\0b", "//"] {
            assert!(clean_path(bad).is_err(), "{bad:?}");
        }
        assert!(clean_path(&"a/".repeat(2000)).is_err());
    }
}
