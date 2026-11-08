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

// ---- resolve: names by id prefix (S3 cycle 3) ----------------------------------------

/// Most matches of each kind a `resolve` answers (two already make a name
/// ambiguous).
const RESOLVE_MATCHES: usize = 16;

#[derive(Clone, Debug, Default, Deserialize)]
pub struct ResolveParams {
    pub prefix: String,
}

/// The smallest string above every string that starts with `prefix`, in
/// the alphabet `digits` (ascending): `None` when there is none (all the
/// alphabet's last digit). Comparisons stay within `[0-9a-z]`, which every
/// collation orders as ASCII does.
fn prefix_end(prefix: &str, digits: &str) -> Option<String> {
    let mut chars: Vec<char> = prefix.chars().collect();
    while let Some(c) = chars.pop() {
        let i = digits.find(c)?;
        if let Some(next) = digits[i + 1..].chars().next() {
            chars.push(next);
            return Some(chars.into_iter().collect());
        }
    }
    None
}

/// The snapshots of the viewer's own projected history whose id, or whose
/// change id, starts with `prefix` (S3 cycle 3, BUG-1261 and 1266: a thin
/// clone resolves the names its held history cannot decide). A snapshot
/// id prefix is 4 to 64 hex digits; a change id prefix, as `vl` writes it,
/// 1 to 32 letters k–z (a pulled tag of any length is checked).
///
/// **What the caller sees, and nothing else** (the S3 redesign review):
/// a snapshot counts only if it is in the caller's projected history as
/// the branches reach it (BUG-1268: not an old version a rewrite left
/// behind) and not withheld (an embargo line). A change the caller cannot
/// see is not in their history: its projection is its parent's, whose
/// change id differs. Rows are read in a fixed order a chunk at a time,
/// and those that do not count are dropped before anything is counted:
/// the answer, its 16-match bound and `more` depend only on what counts
/// (BUG-1269); what does not count costs only work, under the query's
/// deadline.
pub async fn resolve_prefix(hub: &Arc<Hub>, ask: &Ask, prefix: &str, limits: Limits) -> Result<Value> {
    let deadline = Instant::now() + limits.deadline;
    let prefix = prefix.trim().to_ascii_lowercase();
    const HEX: &str = "0123456789abcdef";
    const CHUNK: i64 = 64;
    let snapshot = (4..=64).contains(&prefix.len()) && prefix.chars().all(|c| HEX.contains(c));
    let change = match (1..=32).contains(&prefix.len()) {
        true => veil_core::id::ChangeId::reverse_hex_to_hex(&prefix),
        false => None,
    };
    let empty = json!({ "snapshots": [], "changes": [], "more": false, "policy_version": ask.policy_version });
    if !snapshot && change.is_none() {
        return Ok(empty);
    }
    // The viewer's graph over every branch (filled once, as for any query).
    let rows: Vec<String> = sqlx::query_scalar("SELECT target FROM branches WHERE project_id = $1")
        .bind(ask.project.id)
        .fetch_all(&hub.db)
        .await?;
    let tips: Vec<ObjectId> = rows.iter().filter_map(|t| ObjectId::from_hex(t).ok()).collect();
    if tips.is_empty() {
        return Ok(empty);
    }
    let ptips = ensure(hub, &ask.project, &ask.viewer, &tips, Some(deadline)).await?;
    let (vk, project) = (ask.key(), ask.project.id);
    // Of `ids`, in order, those of the viewer's history as the branches
    // reach it, not withheld, and (for a change) of a change id with the
    // prefix.
    let counted = |ids: Vec<ObjectId>, change: Option<String>| {
        let (vk, ptips) = (vk.clone(), ptips.clone());
        blocking(hub, project, move |cx| {
            let g = G::new(cx, &vk, Some(deadline));
            let mut out = Vec::new();
            for id in ids {
                if g.row(&id)?.is_none_or(|r| r.withheld()) {
                    continue;
                }
                if let Some(h) = &change {
                    if !hex::encode(g.snapshot(&id)?.change_id.0).starts_with(h.as_str()) {
                        continue;
                    }
                }
                let mut reached = false;
                for t in &ptips {
                    if g.is_ancestor(id, *t)? {
                        reached = true;
                        break;
                    }
                }
                if reached {
                    out.push(id);
                }
            }
            Ok(out)
        })
    };
    let past = || Instant::now() > deadline;
    let mut snapshots: Vec<ObjectId> = Vec::new();
    if snapshot {
        let end = prefix_end(&prefix, HEX);
        let mut after: Option<String> = None;
        while snapshots.len() <= RESOLVE_MATCHES {
            let lo = after.clone().unwrap_or_else(|| prefix.clone());
            let op = if after.is_some() { ">" } else { ">=" };
            let sql = format!(
                "SELECT snapshot FROM view_graph WHERE project_id = $1 AND view_key = $2 AND snapshot {op} $3 {} \
                 AND (flags & {}) = 0 ORDER BY snapshot LIMIT {CHUNK}",
                if end.is_some() { "AND snapshot < $4" } else { "" },
                crate::derive::graph::FLAG_EMBARGO_LINE
            );
            let mut q = sqlx::query_scalar::<_, String>(&sql).bind(project).bind(&vk).bind(&lo);
            if let Some(e) = &end {
                q = q.bind(e);
            }
            let found: Vec<String> = q.fetch_all(&hub.db).await?;
            let Some(last) = found.last().cloned() else { break };
            let ids: Vec<ObjectId> = found.iter().filter(|s| s.starts_with(&prefix)).filter_map(|s| ObjectId::from_hex(s).ok()).collect();
            for id in counted(ids, None).await? {
                if !snapshots.contains(&id) {
                    snapshots.push(id);
                }
            }
            if (found.len() as i64) < CHUNK {
                break;
            }
            if past() {
                return Err(graph::too_slow());
            }
            after = Some(last);
        }
    }
    let mut changes: Vec<ObjectId> = Vec::new();
    if let Some(hexp) = change {
        let end = prefix_end(&hexp, HEX);
        let mut after: Option<(String, String)> = None;
        while changes.len() <= RESOLVE_MATCHES {
            let (lo_c, lo_s) = after.clone().unwrap_or_else(|| (hexp.clone(), String::new()));
            let sql = format!(
                "SELECT change_id, snapshot FROM graph WHERE project_id = $1 AND (change_id, snapshot) > ($2, $3) {} \
                 ORDER BY change_id, snapshot LIMIT {CHUNK}",
                if end.is_some() { "AND change_id < $4" } else { "" }
            );
            let mut q = sqlx::query_as::<_, (String, String)>(&sql).bind(project).bind(&lo_c).bind(&lo_s);
            if let Some(e) = &end {
                q = q.bind(e);
            }
            let found: Vec<(String, String)> = q.fetch_all(&hub.db).await?;
            let Some(last) = found.last().cloned() else { break };
            let reals: Vec<ObjectId> = found.iter().filter(|(c, _)| c.starts_with(&hexp)).filter_map(|(_, s)| ObjectId::from_hex(s).ok()).collect();
            if !reals.is_empty() {
                let projected = ensure(hub, &ask.project, &ask.viewer, &reals, Some(deadline)).await?;
                for id in counted(projected, Some(hexp.clone())).await? {
                    if !changes.contains(&id) {
                        changes.push(id);
                    }
                }
            }
            if (found.len() as i64) < CHUNK {
                break;
            }
            if past() {
                return Err(graph::too_slow());
            }
            after = Some(last);
        }
    }
    let more = snapshots.len() > RESOLVE_MATCHES || changes.len() > RESOLVE_MATCHES;
    snapshots.truncate(RESOLVE_MATCHES);
    changes.truncate(RESOLVE_MATCHES);
    Ok(json!({
        "snapshots": snapshots.iter().map(|i| i.hex()).collect::<Vec<_>>(),
        "changes": changes.iter().map(|i| i.hex()).collect::<Vec<_>>(),
        "more": more,
        "policy_version": ask.policy_version,
    }))
}

/// The generations of `snapshots` in the viewer's own history (S3: a thin
/// clone's history index takes those of its boundary from here, so it
/// never needs the ancestry below). The viewer graph's rows, filled as for
/// any query; `None` for a snapshot it has no row for, or a withheld one.
/// Nothing but numbers of snapshots the caller already names.
pub async fn generations(hub: &Arc<Hub>, ask: &Ask, snapshots: Vec<ObjectId>, limits: Limits) -> Result<Value> {
    let deadline = Instant::now() + limits.deadline;
    if snapshots.len() > veil_core::hub::wire::MAX_GENERATIONS {
        return Err(Error::bad_request(format!("at most {} snapshots", veil_core::hub::wire::MAX_GENERATIONS)));
    }
    let rows: Vec<String> = sqlx::query_scalar("SELECT target FROM branches WHERE project_id = $1")
        .bind(ask.project.id)
        .fetch_all(&hub.db)
        .await?;
    let tips: Vec<ObjectId> = rows.iter().filter_map(|t| ObjectId::from_hex(t).ok()).collect();
    if !tips.is_empty() {
        ensure(hub, &ask.project, &ask.viewer, &tips, Some(deadline)).await?;
    }
    let (vk, project) = (ask.key(), ask.project.id);
    blocking(hub, project, move |cx| {
        let g = G::new(cx, &vk, Some(deadline));
        let mut out = Vec::new();
        for id in &snapshots {
            out.push(g.row(id)?.filter(|r| !r.withheld()).map(|r| r.generation.max(0) as u64));
        }
        Ok(json!({ "generations": out }))
    })
    .await
}

pub async fn generations_route(
    State(hub): State<HubState>,
    caller: Caller,
    Path(p): Path<String>,
    Json(q): Json<veil_core::hub::wire::GenerationsRequest>,
) -> Result<Json<Value>> {
    let ask = Ask::open(&hub, &p, &caller).await?;
    Ok(Json(generations(&hub, &ask, q.snapshots, Limits::default()).await?))
}

/// Which of `ids` (projected snapshots of `viewer`'s) the viewer's branches
/// reach: their projected history as a full clone of it holds it (S3: what
/// a thin clone is told about, never an old version a rewrite left behind,
/// BUG-1268). The viewer graph, filled as for any query; withheld ones are
/// not reached.
pub async fn reached_from_branches(hub: &Arc<Hub>, project: &Project, viewer: &Viewer, ids: Vec<ObjectId>) -> Result<Vec<bool>> {
    let deadline = Instant::now() + Limits::default().deadline;
    let rows: Vec<String> = sqlx::query_scalar("SELECT target FROM branches WHERE project_id = $1")
        .bind(project.id)
        .fetch_all(&hub.db)
        .await?;
    let tips: Vec<ObjectId> = rows.iter().filter_map(|t| ObjectId::from_hex(t).ok()).collect();
    if tips.is_empty() {
        return Ok(vec![false; ids.len()]);
    }
    let ptips = ensure(hub, project, viewer, &tips, Some(deadline)).await?;
    let vk = project.view(viewer).key();
    blocking(hub, project.id, move |cx| {
        let g = G::new(cx, &vk, Some(deadline));
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            let mut reached = false;
            if g.row(&id)?.is_some_and(|r| !r.withheld()) {
                for t in &ptips {
                    if g.is_ancestor(id, *t)? {
                        reached = true;
                        break;
                    }
                }
            }
            out.push(reached);
        }
        Ok(out)
    })
    .await
}

pub async fn resolve_route(State(hub): State<HubState>, caller: Caller, Path(p): Path<String>, Query(q): Query<ResolveParams>) -> Result<Json<Value>> {
    let ask = Ask::open(&hub, &p, &caller).await?;
    Ok(Json(resolve_prefix(&hub, &ask, &q.prefix, Limits::default()).await?))
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
