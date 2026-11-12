//! Automatic bisect and revert (milestone S20; `docs/HUB.md` §13.36;
//! `docs/design/server/phase-4-agent-scale.md` §3.2, §4.7, §4.10, §5.1, §5.2,
//! §6 rows 9, 10, 14; product decision 11).
//!
//! When `<branch>@tested` stops advancing because a required check fails on a
//! snapshot ahead of `<branch>@tested`, the server finds the first failing
//! landing since `<branch>@tested` using the same CI runners and `checks`
//! results as S19:
//!
//! 1. **Bounded, path-narrowed search:** Candidates between `<branch>@tested`
//!    (`good`) and the failing snapshot (`bad`) on the branch's first-parent
//!    chain are filtered to those that modified paths inside the check's
//!    configured `[checks.<name>].paths` and inside the runner's readable
//!    footprint (`session_paths`). Because a runner cannot read or observe
//!    changes outside its footprint, bisect never asks for a check result a
//!    runner cannot produce. With `k` parallel probes (`[checks.<name>].parallel`,
//!    default `1`), bisect probes $k$ evenly spaced midpoints per round in at
//!    most $\lceil \log_{k+1}(N) \rceil$ rounds via `check.requested` SSE
//!    events.
//! 2. **Confirmation before revert (Threat 14):** Once the search narrows to a
//!    single candidate `C` with first parent `P`, bisect enters the
//!    `confirming` phase and requests a confirmation re-run of the failing
//!    check on `C` (and on `P` until `P` has passed twice). Only when `C` has
//!    failed twice and `P` has passed twice is `C` confirmed; a flaky check
//!    (where `C` passes on re-run or `P` fails) aborts the bisect (`flaky`) and
//!    never reverts anything.
//! 3. **Priority-lane revert through S17 (`landing_queue`, `priority = 1`):**
//!    On a protected branch whose rules allow automatic revert (`protected =
//!    true` and `auto_revert` not `false`, product decision 11), the server
//!    creates a server-signed revert snapshot with `parents = [C]` and
//!    `tree = P.tree`, attributed to `"server"` with `C`'s `change_id` named,
//!    and queues it in `landing_queue` with `priority = 1` under the
//!    deterministic ticket `revert-<project>-<branch>-<lineage>-<C>`. The
//!    landing service lands it ahead of normal submissions (`priority DESC`),
//!    reversing *only* `C`'s edits (via fast-path or S18 3-way content merge)
//!    and never another change's.
//! 4. **Visibility (`docs/VISIBILITY.md`, Threat 9):** Hidden branches
//!    (`hidden_for_embargo IS NOT NULL`) and embargoed snapshots are never
//!    bisected or reverted into public history before release. The revert
//!    snapshot's description (`revert <change_id>`) names only the random
//!    `change_id`, never any check name, summary, log or path; `check.requested`,
//!    `reverted` and `GET /v1/projects/{p}/bisect/{branch}` filter and project
//!    every field for each viewer.
//! 5. **Fenced across servers and restarts:** `bisect_leases` and
//!    `bisect_reverts` ensure at most one bisect per branch at a time and that
//!    a revert for a given `(project, branch, lineage, culprit)` lands at most
//!    once across multiple servers and restarts.

use std::{collections::HashMap, sync::Arc};

use axum::{
    extract::{Path, State},
    Json,
};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use veil_core::{
    hub::{
        access::AccessPolicy,
        ci::CheckState,
        land::LandState,
    },
    object::{Attribution, Object, Snapshot, Text},
    ChangeId, ObjectId,
};

use crate::{
    auth::{Caller, Person},
    error::{Error, Result},
    landing::{edits, rules::Rules, Entry},
    perm::{self, Project, Viewer},
    sync, Hub, HubState,
};

/// Most first-parent landings walked between `<branch>@tested` and the failing
/// snapshot when starting a bisect.
pub const MAX_BISECT_LANDINGS: usize = 1024;

/// How long a bisect lease lasts unless renewed, in milliseconds.
const BISECT_LEASE_MS: i64 = 5_000;

/// Database clock in milliseconds.
const DB_NOW: &str = "(extract(epoch FROM clock_timestamp()) * 1000)::BIGINT";

/// Stored row in `bisects`.
#[derive(Clone, Debug)]
struct BisectRow {
    project_id: i64,
    branch: String,
    lineage: i64,
    check_name: String,
    good: ObjectId,
    bad: ObjectId,
    candidates: Vec<ObjectId>,
    lo: usize,
    hi: usize,
    phase: String,
    probes: Vec<ObjectId>,
    culprit: Option<ObjectId>,
    culprit_parent: Option<ObjectId>,
    culprit_fails: i32,
    parent_passes: i32,
    confirm_requested_at: i64,
    session_paths: Vec<String>,
    admin_only: bool,
    revert_ticket: Option<String>,
    revert_snapshot: Option<ObjectId>,
    updated_at: i64,
    gc_epoch: i64,
}

/// Public response for `GET /v1/projects/{p}/bisect/{branch}`, projected and
/// visibility-filtered for the caller.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BisectStatus {
    pub branch: String,
    pub phase: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub check: Option<String>,
    pub good: ObjectId,
    pub bad: ObjectId,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidates: Vec<ObjectId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub probes: Vec<ObjectId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub culprit: Option<ObjectId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub culprit_change_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original: Option<ObjectId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_change_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revert: Option<ObjectId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revert_ticket: Option<String>,
    pub updated_at: i64,
}

/// The reverts "reverted twice" counts, by each of the two names a reverted
/// change has (BUG-1884, BUG-1921): its change id, which its submitter
/// chooses, and what its edits were (`prs::edits_id`, recorded with the
/// revert), which a new change id does not change. `$1` is the project.
const REVERTED_KEYS: &str = "SELECT culprit_change_id AS k, branch FROM bisect_reverts \
     WHERE project_id = $1 AND culprit_change_id <> '' AND state = 'reverted' \
     UNION ALL \
     SELECT culprit_patch AS k, branch FROM bisect_reverts \
     WHERE project_id = $1 AND culprit_patch <> '' AND state = 'reverted'";

/// Whether any of `ids` (the change ids of some changes, and what their
/// edits are: `prs::edits_id`) names a change the server has automatically
/// reverted at least twice in `project_id` (BUG-1884, BUG-1921). Counted
/// across rebases and lineages, and never reset.
pub async fn any_reverted_twice(hub: &Hub, project_id: i64, ids: &[String]) -> Result<bool> {
    if ids.is_empty() {
        return Ok(false);
    }
    sync_queued_reverts(hub, project_id, None).await?;
    let mut c = hub.db.acquire().await?;
    any_reverted_twice_conn(&mut c, project_id, ids).await
}

/// [`any_reverted_twice`] on a connection, of the reverts as recorded: the
/// caller has brought the queued ones up to date ([`settle_queued_reverts`]).
/// A landing batch asks inside its transaction (BUG-1880).
pub async fn any_reverted_twice_conn(c: &mut sqlx::PgConnection, project_id: i64, ids: &[String]) -> Result<bool> {
    if ids.is_empty() {
        return Ok(false);
    }
    let hit: Option<String> =
        sqlx::query_scalar(&format!("SELECT k FROM ({REVERTED_KEYS}) r WHERE k = ANY($2) GROUP BY k HAVING COUNT(*) >= 2 LIMIT 1"))
            .bind(project_id)
            .bind(ids)
            .fetch_optional(&mut *c)
            .await?;
    Ok(hit.is_some())
}

/// Which of `ids` name a change the server has reverted at least twice
/// ([`any_reverted_twice_conn`], for all the entries of a landing batch in
/// one statement: BUG-1942).
pub async fn reverted_twice_among(c: &mut sqlx::PgConnection, project_id: i64, ids: &[String]) -> Result<std::collections::HashSet<String>> {
    if ids.is_empty() {
        return Ok(Default::default());
    }
    let hit: Vec<String> = sqlx::query_scalar(&format!("SELECT k FROM ({REVERTED_KEYS}) r WHERE k = ANY($2) GROUP BY k HAVING COUNT(*) >= 2"))
        .bind(project_id)
        .bind(ids)
        .fetch_all(&mut *c)
        .await?;
    Ok(hit.into_iter().collect())
}

/// Record the outcome of every revert of `project_id` whose landing ended,
/// before reverts are counted on a connection ([`any_reverted_twice_conn`]).
pub async fn settle_queued_reverts(hub: &Hub, project_id: i64) -> Result<()> {
    sync_queued_reverts(hub, project_id, None).await
}

/// Whether the server has reverted any change of the project twice, of the
/// reverts as recorded. A landing batch that finds none reads nothing of
/// its changes for the rule (BUG-1884), and checks in its transaction that
/// there is still none (BUG-1880).
pub async fn has_reverted_twice(c: &mut sqlx::PgConnection, project_id: i64) -> Result<bool> {
    Ok(sqlx::query_scalar(&format!("SELECT EXISTS (SELECT 1 FROM ({REVERTED_KEYS}) r GROUP BY k HAVING COUNT(*) >= 2)"))
        .bind(project_id)
        .fetch_one(&mut *c)
        .await?)
}

/// Whether `branch` itself has any change reverted twice by the server (by
/// change id or by its edits), so even a direct fast-forward onto an
/// unprotected branch still checks changes reverted twice there while
/// leaving topic branches free.
pub async fn branch_has_reverted_twice(hub: &Hub, project_id: i64, branch: &str) -> Result<bool> {
    sync_queued_reverts(hub, project_id, Some(branch)).await?;
    let hit: Option<String> =
        sqlx::query_scalar(&format!("SELECT k FROM ({REVERTED_KEYS}) r WHERE branch = $2 GROUP BY k HAVING COUNT(*) >= 2 LIMIT 1"))
            .bind(project_id)
            .bind(branch)
            .fetch_optional(&hub.db)
            .await?;
    Ok(hit.is_some())
}

/// Acquire a short database lease for `(project_id, branch)` in `bisect_leases`.
async fn acquire_lease(hub: &Hub, project_id: i64, branch: &str) -> Result<Option<(String, i64)>> {
    let holder = format!("{}-{}", std::process::id(), hex::encode(veil_core::crypto::random_bytes::<8>()));
    let epoch: Option<i64> = sqlx::query_scalar(&format!(
        "INSERT INTO bisect_leases (project_id, branch, holder, epoch, expires_at) \
         VALUES ($1, $2, $3, 1, {DB_NOW} + $4) \
         ON CONFLICT (project_id, branch) DO UPDATE \
         SET holder = EXCLUDED.holder, epoch = bisect_leases.epoch + 1, expires_at = EXCLUDED.expires_at \
         WHERE bisect_leases.expires_at < {DB_NOW} OR bisect_leases.holder = EXCLUDED.holder \
         RETURNING epoch"
    ))
    .bind(project_id)
    .bind(branch)
    .bind(&holder)
    .bind(BISECT_LEASE_MS)
    .fetch_optional(&hub.db)
    .await?;
    Ok(epoch.map(|e| (holder, e)))
}

async fn release_lease(hub: &Hub, project_id: i64, branch: &str, holder: &str, epoch: i64) {
    let _ = sqlx::query(
        "UPDATE bisect_leases SET expires_at = 0 WHERE project_id = $1 AND branch = $2 AND holder = $3 AND epoch = $4",
    )
    .bind(project_id)
    .bind(branch)
    .bind(holder)
    .bind(epoch)
    .execute(&hub.db)
    .await;
}

/// Load the current `bisects` row for `(project_id, branch)`.
async fn load_bisect(hub: &Hub, project_id: i64, branch: &str) -> Result<Option<BisectRow>> {
    use sqlx::Row;
    let gc_epoch = crate::pack_gc::read_gc_epoch(hub, project_id).await?;
    let row = sqlx::query(
        "SELECT project_id, branch, lineage, check_name, good, bad, candidates, lo, hi, phase, probes, \
         culprit, culprit_parent, culprit_fails, parent_passes, confirm_requested_at, session_paths, \
         admin_only, revert_ticket, revert_snapshot, updated_at \
         FROM bisects WHERE project_id = $1 AND branch = $2",
    )
    .bind(project_id)
    .bind(branch)
    .fetch_optional(&hub.db)
    .await?;
    let Some(r) = row else {
        return Ok(None);
    };
    let parse_id = |s: &str| ObjectId::from_hex(s).map_err(|e| Error::Other(e.into()));
    let candidates_json: String = r.get("candidates");
    let probes_json: String = r.get("probes");
    let session_paths_json: String = r.get("session_paths");
    let good_str: String = r.get("good");
    let bad_str: String = r.get("bad");
    let culprit_opt: Option<String> = r.get("culprit");
    let culprit_parent_opt: Option<String> = r.get("culprit_parent");
    let revert_snapshot_opt: Option<String> = r.get("revert_snapshot");
    let lo: i32 = r.get("lo");
    let hi: i32 = r.get("hi");

    let cand_hexes: Vec<String> = serde_json::from_str(&candidates_json).unwrap_or_default();
    let mut candidates = Vec::with_capacity(cand_hexes.len());
    for h in cand_hexes {
        candidates.push(parse_id(&h)?);
    }
    let probe_hexes: Vec<String> = serde_json::from_str(&probes_json).unwrap_or_default();
    let mut probes = Vec::with_capacity(probe_hexes.len());
    for h in probe_hexes {
        probes.push(parse_id(&h)?);
    }
    let session_paths: Vec<String> = serde_json::from_str(&session_paths_json).unwrap_or_default();
    Ok(Some(BisectRow {
        project_id: r.get("project_id"),
        branch: r.get("branch"),
        lineage: r.get("lineage"),
        check_name: r.get("check_name"),
        good: parse_id(&good_str)?,
        bad: parse_id(&bad_str)?,
        candidates,
        lo: lo.max(0) as usize,
        hi: hi.max(0) as usize,
        phase: r.get("phase"),
        probes,
        culprit: culprit_opt.as_deref().map(parse_id).transpose()?,
        culprit_parent: culprit_parent_opt.as_deref().map(parse_id).transpose()?,
        culprit_fails: r.get("culprit_fails"),
        parent_passes: r.get("parent_passes"),
        confirm_requested_at: r.get("confirm_requested_at"),
        session_paths,
        admin_only: r.get("admin_only"),
        revert_ticket: r.get("revert_ticket"),
        revert_snapshot: revert_snapshot_opt.as_deref().map(parse_id).transpose()?,
        updated_at: r.get("updated_at"),
        gc_epoch,
    }))
}

/// Save `b` in `bisects` under the lease `(holder, epoch)`. Returns `Ok(false)` if the lease was lost.
async fn save_bisect(hub: &Hub, b: &BisectRow, holder: &str, epoch: i64) -> Result<bool> {
    let cand_json = serde_json::to_string(&b.candidates.iter().map(ObjectId::hex).collect::<Vec<_>>())
        .map_err(|e| Error::Other(e.into()))?;
    let probes_json = serde_json::to_string(&b.probes.iter().map(ObjectId::hex).collect::<Vec<_>>())
        .map_err(|e| Error::Other(e.into()))?;
    let paths_json = serde_json::to_string(&b.session_paths).map_err(|e| Error::Other(e.into()))?;
    let now = veil_core::now_millis();
    let pid = b.project_id;
    let gc_epoch = b.gc_epoch;
    let branch = b.branch.clone();
    let lineage = b.lineage;
    let check_name = b.check_name.clone();
    let good = b.good.hex();
    let bad = b.bad.hex();
    let lo = b.lo as i32;
    let hi = b.hi as i32;
    let phase = b.phase.clone();
    let culprit = b.culprit.map(|x| x.hex());
    let culprit_parent = b.culprit_parent.map(|x| x.hex());
    let culprit_fails = b.culprit_fails;
    let parent_passes = b.parent_passes;
    let confirm_requested_at = b.confirm_requested_at;
    let admin_only = b.admin_only;
    let revert_ticket = b.revert_ticket.clone();
    let revert_snapshot = b.revert_snapshot.map(|x| x.hex());
    let holder = holder.to_string();

    crate::db::transaction(&hub.db, crate::db::Isolation::ReadCommitted, move |c| {
        let (
            branch,
            check_name,
            good,
            bad,
            cand_json,
            probes_json,
            phase,
            culprit,
            culprit_parent,
            paths_json,
            revert_ticket,
            revert_snapshot,
            holder,
        ) = (
            branch.clone(),
            check_name.clone(),
            good.clone(),
            bad.clone(),
            cand_json.clone(),
            probes_json.clone(),
            phase.clone(),
            culprit.clone(),
            culprit_parent.clone(),
            paths_json.clone(),
            revert_ticket.clone(),
            revert_snapshot.clone(),
            holder.clone(),
        );
        Box::pin(async move {
            crate::pack_gc::guard_root_write(&mut *c, pid, gc_epoch).await?;
            let held = sqlx::query(&format!(
                "UPDATE bisect_leases SET expires_at = {DB_NOW} + $5 \
                 WHERE project_id = $1 AND branch = $2 AND holder = $3 AND epoch = $4"
            ))
            .bind(pid)
            .bind(&branch)
            .bind(&holder)
            .bind(epoch)
            .bind(BISECT_LEASE_MS)
            .execute(&mut *c)
            .await?
            .rows_affected();
            if held != 1 {
                return Ok(false);
            }
            sqlx::query(
                "INSERT INTO bisects ( \
                    project_id, branch, lineage, check_name, good, bad, candidates, lo, hi, phase, probes, \
                    culprit, culprit_parent, culprit_fails, parent_passes, confirm_requested_at, \
                    session_paths, admin_only, revert_ticket, revert_snapshot, created_at, updated_at \
                 ) VALUES ( \
                    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, \
                    $12, $13, $14, $15, $16, \
                    $17, $18, $19, $20, $21, $21 \
                 ) ON CONFLICT (project_id, branch) DO UPDATE SET \
                    lineage = EXCLUDED.lineage, \
                    check_name = EXCLUDED.check_name, \
                    good = EXCLUDED.good, \
                    bad = EXCLUDED.bad, \
                    candidates = EXCLUDED.candidates, \
                    lo = EXCLUDED.lo, \
                    hi = EXCLUDED.hi, \
                    phase = EXCLUDED.phase, \
                    probes = EXCLUDED.probes, \
                    culprit = EXCLUDED.culprit, \
                    culprit_parent = EXCLUDED.culprit_parent, \
                    culprit_fails = EXCLUDED.culprit_fails, \
                    parent_passes = EXCLUDED.parent_passes, \
                    confirm_requested_at = EXCLUDED.confirm_requested_at, \
                    session_paths = EXCLUDED.session_paths, \
                    admin_only = EXCLUDED.admin_only, \
                    revert_ticket = EXCLUDED.revert_ticket, \
                    revert_snapshot = EXCLUDED.revert_snapshot, \
                    updated_at = EXCLUDED.updated_at",
            )
            .bind(pid)
            .bind(&branch)
            .bind(lineage)
            .bind(&check_name)
            .bind(&good)
            .bind(&bad)
            .bind(&cand_json)
            .bind(lo)
            .bind(hi)
            .bind(&phase)
            .bind(&probes_json)
            .bind(&culprit)
            .bind(&culprit_parent)
            .bind(culprit_fails)
            .bind(parent_passes)
            .bind(confirm_requested_at)
            .bind(&paths_json)
            .bind(admin_only)
            .bind(&revert_ticket)
            .bind(&revert_snapshot)
            .bind(now)
            .execute(&mut *c)
            .await?;
            Ok(true)
        })
    })
    .await
}

/// Compute the evenly-spaced probe indices in `(lo..hi)` for `k`-way bisect.
/// With `k == 1` (standard binary search), picks the midpoint `(lo + hi) / 2`.
/// With `k > 1`, picks up to `k` interior points dividing `lo..=hi` into `k + 1`
/// roughly equal segments.
pub fn probe_indices(lo: usize, hi: usize, k: usize) -> Vec<usize> {
    if hi <= lo {
        return Vec::new();
    }
    let count = hi - lo;
    let k = k.clamp(1, 8).min(count);
    let mut out = Vec::with_capacity(k);
    for i in 1..=k {
        let idx = lo + (i * count) / (k + 1);
        let idx = idx.min(hi - 1);
        if out.last().copied() != Some(idx) {
            out.push(idx);
        }
    }
    out
}

/// Does `path` fall within `prefix` (either equal to `prefix` or inside directory `prefix/`)?
fn path_under(path: &str, prefix: &str) -> bool {
    let prefix = prefix.trim_end_matches('/');
    if prefix.is_empty() {
        return true;
    }
    path == prefix || (path.starts_with(prefix) && path.as_bytes().get(prefix.len()) == Some(&b'/'))
}

/// Resume any active bisects or pending revert landings on startup (`lib.rs`).
pub async fn resume(hub: Arc<Hub>) {
    type ResumeRow = (i64, String, String, Option<String>);
    let rows: std::result::Result<Vec<ResumeRow>, _> = sqlx::query_as(
        "SELECT project_id, branch, phase, revert_ticket FROM bisects WHERE phase IN ('searching', 'confirming', 'reverting')",
    )
    .fetch_all(&hub.db)
    .await;
    let Ok(rows) = rows else { return };
    for (pid, branch, phase, ticket) in rows {
        if phase == "reverting" || ticket.is_some() {
            crate::landing::ensure(&hub, pid, &branch);
            let _ = sync_revert_outcome(&hub, pid, &branch).await;
        } else if matches!(phase.as_str(), "searching" | "confirming") {
            if let Ok(Some(name)) = sqlx::query_scalar::<_, String>("SELECT name FROM projects WHERE id = $1")
                .bind(pid)
                .fetch_optional(&hub.db)
                .await
            {
                if let Ok(mut conn) = hub.db.acquire().await {
                    if let Ok(Some(project)) = perm::load_project(&mut conn, &name).await {
                        drop(conn);
                        let _ = reconcile_branch(&hub, &project, &branch).await;
                    }
                }
            }
        }
    }
}

/// Reconcile an active (`searching` or `confirming`) bisect on `branch` against
/// stored `checks` rows if its lease is currently free.
pub async fn reconcile_branch(hub: &Arc<Hub>, project: &Project, branch: &str) -> Result<()> {
    if branch.starts_with("embargo/") {
        return Ok(());
    }
    let Some(peek) = load_bisect(hub, project.id, branch).await? else {
        return Ok(());
    };
    if !matches!(peek.phase.as_str(), "searching" | "confirming") {
        return Ok(());
    }
    let Some((holder, epoch)) = acquire_lease(hub, project.id, branch).await? else {
        return Ok(());
    };
    let step = || async {
        let Some(mut b) = load_bisect(hub, project.id, branch).await? else {
            return Ok(());
        };
        if !matches!(b.phase.as_str(), "searching" | "confirming") {
            return Ok(());
        }
        let branches: Vec<(String, String, i64)> = sqlx::query_as(
            "SELECT name, target, lineage FROM branches WHERE project_id = $1 AND hidden_for_embargo IS NULL",
        )
        .bind(project.id)
        .fetch_all(&hub.db)
        .await?;
        let Some((_, _, lineage)) = branches.iter().find(|(n, _, _)| n == branch) else {
            return Ok(());
        };
        if b.lineage != *lineage {
            return Ok(());
        }
        let default_tip = branches
            .iter()
            .find(|(n, _, _)| n == &project.default_branch)
            .and_then(|(_, t, _)| ObjectId::from_hex(t).ok());
        let rules = sync::blocking(hub, project.id, move |src| crate::landing::rules(src, default_tip)).await?;
        drive_bisect(hub, project, &rules, &mut b, true, &holder, epoch).await
    };
    // Again from its reads when garbage collection switched meanwhile
    // (BUG-1881's guard, BUG-1899), as a report's own step is.
    let mut res: Result<()> = Ok(());
    for _ in 0..8 {
        res = step().await;
        match &res {
            Err(e) if crate::pack_gc::is_gc_epoch_changed(e) => continue,
            _ => break,
        }
    }
    release_lease(hub, project.id, branch, &holder, epoch).await;
    res
}

/// Called by `ci::post_check_route` whenever a `pass` or `fail` check result is
/// recorded on `real_snapshot`.
#[allow(clippy::too_many_arguments)]
pub async fn on_check_recorded(
    hub: &Arc<Hub>,
    project: &Project,
    real_snapshot: ObjectId,
    check_name: &str,
    state: CheckState,
    session_paths: &[String],
    admin_only: bool,
    recorded_at: i64,
) -> Result<()> {
    // Only non-embargoed branches participate in bisect and automatic revert
    // (Threat 9: an embargoed change is never bisected/reverted into public).
    let branches: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT name, target, lineage FROM branches WHERE project_id = $1 AND hidden_for_embargo IS NULL ORDER BY name",
    )
    .bind(project.id)
    .fetch_all(&hub.db)
    .await?;
    if branches.is_empty() {
        return Ok(());
    }
    let default_tip = branches
        .iter()
        .find(|(n, _, _)| n == &project.default_branch)
        .and_then(|(_, t, _)| ObjectId::from_hex(t).ok());
    let rules = sync::blocking(hub, project.id, move |src| crate::landing::rules(src, default_tip)).await?;

    for (branch, target_hex, lineage) in branches {
        if branch.starts_with("embargo/") {
            continue;
        }
        let Ok(target) = ObjectId::from_hex(&target_hex) else { continue };
        // Check if this branch allows automatic revert and lists this check in `required_checks`.
        let is_required = rules
            .required_checks
            .get(&branch)
            .is_some_and(|reqs| reqs.iter().any(|r| r == check_name));
        if !is_required || !rules.allows_auto_revert(&branch) {
            continue;
        }
        step_branch(
            hub,
            project,
            &rules,
            &branch,
            target,
            lineage,
            real_snapshot,
            check_name,
            state,
            session_paths,
            admin_only,
            recorded_at,
        )
        .await?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn step_branch(
    hub: &Arc<Hub>,
    project: &Project,
    rules: &Rules,
    branch: &str,
    branch_tip: ObjectId,
    lineage: i64,
    reported_snap: ObjectId,
    check_name: &str,
    state: CheckState,
    session_paths: &[String],
    admin_only: bool,
    recorded_at: i64,
) -> Result<()> {
    let Some((holder, epoch)) = acquire_lease(hub, project.id, branch).await? else {
        spawn_step_after_lease(
            hub.clone(),
            project.clone(),
            branch.to_string(),
            reported_snap,
            check_name.to_string(),
            state,
            session_paths.to_vec(),
            admin_only,
            recorded_at,
        );
        return Ok(());
    };
    let res = step_branch_retrying(
        hub,
        project,
        rules,
        branch,
        branch_tip,
        lineage,
        reported_snap,
        check_name,
        state,
        session_paths,
        admin_only,
        recorded_at,
        &holder,
        epoch,
    )
    .await;
    release_lease(hub, project.id, branch, &holder, epoch).await;
    res
}

/// [`step_branch_leased`], run again from its reads when garbage collection
/// switched the project's packs before the step wrote (BUG-1881's guard on
/// `save_bisect`): by the report's own request, and by the step that runs
/// once a held lease comes free (BUG-1899: that one ran once, so a switch
/// at that moment left the result uncounted and the bisect waiting for it).
#[allow(clippy::too_many_arguments)]
async fn step_branch_retrying(
    hub: &Arc<Hub>,
    project: &Project,
    rules: &Rules,
    branch: &str,
    branch_tip: ObjectId,
    lineage: i64,
    reported_snap: ObjectId,
    check_name: &str,
    state: CheckState,
    session_paths: &[String],
    admin_only: bool,
    recorded_at: i64,
    holder: &str,
    epoch: i64,
) -> Result<()> {
    let mut res = Ok(());
    for _ in 0..8 {
        res = step_branch_leased(
            hub,
            project,
            rules,
            branch,
            branch_tip,
            lineage,
            reported_snap,
            check_name,
            state,
            session_paths,
            admin_only,
            recorded_at,
            holder,
            epoch,
        )
        .await;
        match &res {
            Err(e) if crate::pack_gc::is_gc_epoch_changed(e) => continue,
            _ => break,
        }
    }
    res
}

#[allow(clippy::too_many_arguments)]
fn spawn_step_after_lease(
    hub: Arc<Hub>,
    project: Project,
    branch: String,
    reported_snap: ObjectId,
    check_name: String,
    state: CheckState,
    session_paths: Vec<String>,
    admin_only: bool,
    recorded_at: i64,
) {
    tokio::spawn(async move {
        let deadline = tokio::time::Instant::now()
            + std::time::Duration::from_millis((BISECT_LEASE_MS as u64) + 1_500);
        let mut leased = None;
        while tokio::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            match acquire_lease(&hub, project.id, &branch).await {
                Ok(Some(pair)) => {
                    leased = Some(pair);
                    break;
                }
                Ok(None) => continue,
                Err(_) => return,
            }
        }
        let Some((holder, epoch)) = leased else {
            return;
        };
        let res: Result<()> = async {
            let mut conn = hub.db.acquire().await?;
            let Some(project) = perm::load_project(&mut conn, &project.name).await? else {
                return Ok(());
            };
            drop(conn);
            let branches: Vec<(String, String, i64)> = sqlx::query_as(
                "SELECT name, target, lineage FROM branches WHERE project_id = $1 AND hidden_for_embargo IS NULL",
            )
            .bind(project.id)
            .fetch_all(&hub.db)
            .await?;
            let Some((_, target_hex, lineage)) = branches.iter().find(|(n, _, _)| n == &branch) else {
                return Ok(());
            };
            let Ok(target) = ObjectId::from_hex(target_hex) else {
                return Ok(());
            };
            let default_tip = branches
                .iter()
                .find(|(n, _, _)| n == &project.default_branch)
                .and_then(|(_, t, _)| ObjectId::from_hex(t).ok());
            let rules = sync::blocking(&hub, project.id, move |src| crate::landing::rules(src, default_tip)).await?;
            let is_required = rules
                .required_checks
                .get(&branch)
                .is_some_and(|reqs| reqs.iter().any(|r| r == &check_name));
            if !is_required || !rules.allows_auto_revert(&branch) {
                return Ok(());
            }
            step_branch_retrying(
                &hub,
                &project,
                &rules,
                &branch,
                target,
                *lineage,
                reported_snap,
                &check_name,
                state,
                &session_paths,
                admin_only,
                recorded_at,
                &holder,
                epoch,
            )
            .await
        }
        .await;
        let _ = res;
        release_lease(&hub, project.id, &branch, &holder, epoch).await;
    });
}

#[allow(clippy::too_many_arguments)]
async fn step_branch_leased(
    hub: &Arc<Hub>,
    project: &Project,
    rules: &Rules,
    branch: &str,
    branch_tip: ObjectId,
    lineage: i64,
    reported_snap: ObjectId,
    check_name: &str,
    state: CheckState,
    session_paths: &[String],
    admin_only: bool,
    _recorded_at: i64,
    holder: &str,
    epoch: i64,
) -> Result<()> {
    // Look up current `<branch>@tested` in the current lineage.
    let tested_row: Option<String> = sqlx::query_scalar(
        "SELECT snapshot FROM tested WHERE project_id = $1 AND branch = $2 AND lineage = $3",
    )
    .bind(project.id)
    .bind(branch)
    .bind(lineage)
    .fetch_optional(&hub.db)
    .await?;
    let tested_snap = tested_row
        .and_then(|h| ObjectId::from_hex(&h).ok())
        .unwrap_or_else(sync::root_snapshot_id);

    let mut cur = load_bisect(hub, project.id, branch).await?;

    // If there is an active bisect (`searching` or `confirming`) in the current lineage
    // and this check report is for one of its probes/candidates/culprit/parent, advance it first
    // (even if a passing re-run on `b.bad` just caused `advance_tested` to advance `tested_snap`
    // to `b.bad`, so `b` transitions cleanly to `flaky`).
    if let Some(b) = &mut cur {
        if b.lineage == lineage
            && matches!(b.phase.as_str(), "searching" | "confirming")
            && b.check_name == check_name
            && (b.probes.contains(&reported_snap)
                || b.candidates.contains(&reported_snap)
                || b.culprit == Some(reported_snap)
                || b.culprit_parent == Some(reported_snap))
        {
            drive_bisect(hub, project, rules, b, true, holder, epoch).await?;
            return Ok(());
        }
    }

    // If there is an existing bisect on this branch from an older lineage, or whose
    // `bad` is now at or behind `<branch>@tested` (because `<branch>@tested` advanced past it),
    // retire it.
    if let Some(b) = &cur {
        if b.lineage != lineage || b.bad == tested_snap {
            cur = None;
        } else if matches!(b.phase.as_str(), "searching" | "confirming") {
            let bad = b.bad;
            let t = tested_snap;
            let still_ahead = sync::blocking(hub, project.id, move |src| {
                is_first_parent_above(src, bad, t)
            })
            .await?;
            if !still_ahead {
                cur = None;
            }
        }
    }

    // If there is still an active bisect (`searching` or `confirming`) on this branch,
    // reconcile it with stored `checks` rows first; if it remains active, wait for it.
    if let Some(mut b) = cur {
        if matches!(b.phase.as_str(), "searching" | "confirming") {
            drive_bisect(hub, project, rules, &mut b, true, holder, epoch).await?;
            if matches!(b.phase.as_str(), "searching" | "confirming" | "reverting") {
                return Ok(());
            }
        }
    }

    // Otherwise, no bisect is currently active on `branch`.
    // Only start a new bisect when a required check FAILS on a snapshot strictly
    // above `<branch>@tested` on `branch`'s first-parent chain!
    if state != CheckState::Fail {
        return Ok(());
    }

    // Never start bisect on an unreleased embargo snapshot.
    if crate::embargo::is_withheld_for_query(hub, project.id, &reported_snap).await? {
        return Ok(());
    }

    // Walk `branch_tip` down to `tested_snap` along first parents and verify `reported_snap`
    // is on the branch's first-parent line above `tested_snap`.
    let gc_epoch = crate::pack_gc::read_gc_epoch(hub, project.id).await?;
    let check_paths = rules.checks.get(check_name).cloned().unwrap_or_default();
    let sess_paths = session_paths.to_vec();
    let tip = branch_tip;
    let bad = reported_snap;
    let good = tested_snap;

    let walked = sync::blocking(hub, project.id, move |src| {
        collect_candidates(src, tip, bad, good, &check_paths, &sess_paths, admin_only)
    })
    .await?;

    let Some(candidates) = walked else {
        // `reported_snap` is not on `branch`'s first-parent chain above `tested_snap`,
        // or no candidate in `(good..=bad]` could have been observed by the runner.
        return Ok(());
    };
    if candidates.is_empty() {
        return Ok(());
    }

    // Check if the only candidate has already been reverted for this `(project, branch, lineage, culprit)`:
    if candidates.len() == 1 {
        let already: Option<String> = sqlx::query_scalar(
            "SELECT state FROM bisect_reverts WHERE project_id = $1 AND branch = $2 AND lineage = $3 AND culprit = $4",
        )
        .bind(project.id)
        .bind(branch)
        .bind(lineage)
        .bind(candidates[0].hex())
        .fetch_optional(&hub.db)
        .await?;
        if already.is_some() {
            return Ok(());
        }
    }

    let mut b = BisectRow {
        project_id: project.id,
        branch: branch.to_string(),
        lineage,
        check_name: check_name.to_string(),
        good,
        bad,
        candidates,
        lo: 0,
        hi: 0,
        phase: "searching".to_string(),
        probes: Vec::new(),
        culprit: None,
        culprit_parent: None,
        culprit_fails: 0,
        parent_passes: 0,
        confirm_requested_at: 0,
        session_paths: session_paths.to_vec(),
        admin_only,
        revert_ticket: None,
        revert_snapshot: None,
        updated_at: veil_core::now_millis(),
        gc_epoch,
    };
    b.hi = b.candidates.len() - 1;

    // Incorporate any existing check results on `b.candidates` and drive the state machine
    // until it needs a runner probe or finishes.
    drive_bisect(hub, project, rules, &mut b, false, holder, epoch).await
}

fn is_first_parent_above(src: &sync::Source, top: ObjectId, bottom: ObjectId) -> Result<bool> {
    if top == bottom {
        return Ok(false);
    }
    let root = sync::root_snapshot_id();
    let mut cur = top;
    for _ in 0..MAX_BISECT_LANDINGS {
        if cur == bottom {
            return Ok(true);
        }
        if cur == root {
            return Ok(false);
        }
        let Ok(s) = src.snapshot(&cur) else { return Ok(false) };
        match s.parents.first().copied() {
            Some(p) => cur = p,
            None => return Ok(bottom == root),
        }
    }
    Ok(false)
}

/// Walk `branch_tip` down to `good` (`<branch>@tested` or root). Verify `bad` is
/// on that first-parent chain above `good`, and return the oldest-first list of
/// candidate snapshots in `(good..=bad]` that touched at least one path inside
/// `check_paths` (if non-empty) and inside `session_paths` (unless `admin_only`).
fn collect_candidates(
    src: &sync::Source,
    branch_tip: ObjectId,
    bad: ObjectId,
    good: ObjectId,
    check_paths: &[String],
    session_paths: &[String],
    admin_only: bool,
) -> Result<Option<Vec<ObjectId>>> {
    let root = sync::root_snapshot_id();
    // 1. Walk from `branch_tip` down to `bad` (so we know `bad` is on the branch).
    let mut cur = branch_tip;
    let mut found_bad = cur == bad;
    for _ in 0..MAX_BISECT_LANDINGS {
        if found_bad {
            break;
        }
        if cur == good || cur == root {
            return Ok(None);
        }
        let Ok(s) = src.snapshot(&cur) else { return Ok(None) };
        match s.parents.first().copied() {
            Some(p) => {
                cur = p;
                if cur == bad {
                    found_bad = true;
                }
            }
            None => return Ok(None),
        }
    }
    if !found_bad || bad == good {
        return Ok(None);
    }

    // 2. Walk from `bad` down to `good`, collecting `(snap_id, snap, parent_id)`.
    let mut chain = Vec::new();
    let mut x = bad;
    let mut reached_good = false;
    for _ in 0..MAX_BISECT_LANDINGS {
        if x == good {
            reached_good = true;
            break;
        }
        if x == root {
            if good == root {
                reached_good = true;
            }
            break;
        }
        let Ok(s) = src.snapshot(&x) else { break };
        if s.embargo.is_some() {
            // Never bisect across an embargoed snapshot.
            return Ok(None);
        }
        let parent = s.parents.first().copied().unwrap_or(root);
        chain.push((x, s, parent));
        x = parent;
        if x == good {
            reached_good = true;
            break;
        }
    }
    if !reached_good || chain.is_empty() {
        return Ok(None);
    }

    // `chain` is newest-first (`bad` at 0); reverse to oldest-first.
    chain.reverse();

    // 3. Filter candidates to those whose edits against their first parent touch
    //    the check's path narrowing (`check_paths`) and the runner's readable
    //    footprint (`session_paths`), so bisect never asks a runner for a check
    //    result on a snapshot that collapsed or didn't touch its paths (Guarantee 1).
    let mut out = Vec::with_capacity(chain.len());
    for (id, snap, parent) in chain {
        let parent_tree = src.snapshot(&parent)?.tree;
        if snap.tree == parent_tree {
            continue;
        }
        let set = edits::edit_set(src, snap.tree, parent_tree)?;
        if set.is_empty() {
            continue;
        }
        if !check_paths.is_empty() && !set.iter().any(|c| check_paths.iter().any(|p| path_under(&c.path, p))) {
            continue;
        }
        if !admin_only && !session_paths.is_empty() && !set.iter().any(|c| session_paths.iter().any(|p| path_under(&c.path, p))) {
            continue;
        }
        out.push(id);
    }
    Ok(Some(out))
}

async fn load_known_checks(
    hub: &Arc<Hub>,
    project: &Project,
    rules: &Rules,
    check_name: &str,
    snaps: &[String],
) -> Result<HashMap<ObjectId, (CheckState, i64)>> {
    if snaps.is_empty() {
        return Ok(HashMap::new());
    }
    type BisectCheckRow = (String, String, i64, i64, String, bool);
    let rows: Vec<BisectCheckRow> = sqlx::query_as(
        "SELECT snapshot, state, run_count, runner_id, session_paths, admin_only \
         FROM checks WHERE project_id = $1 AND name = $2 AND snapshot = ANY($3)",
    )
    .bind(project.id)
    .bind(check_name)
    .bind(snaps)
    .fetch_all(&hub.db)
    .await?;

    let people: Vec<i64> = rows
        .iter()
        .map(|r| r.3)
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    let roles = if people.is_empty() {
        std::collections::BTreeMap::new()
    } else {
        let mut conn = hub.db.acquire().await?;
        crate::ci::load_poster_roles(&mut conn, project.id, &people).await?
    };

    let mut known: HashMap<ObjectId, (CheckState, i64)> = HashMap::new();
    for (s_hex, st_str, run_count, runner_id, paths_json, admin_only) in rows {
        if run_count <= 0 {
            continue;
        }
        let (adm, grps) = roles.get(&runner_id).cloned().unwrap_or_default();
        let paths: Vec<String> = serde_json::from_str(&paths_json).unwrap_or_default();
        if !crate::ci::stored_check_counts(project, runner_id, adm, &grps, &paths, admin_only, rules, check_name) {
            continue;
        }
        let (Ok(id), Some(st)) = (ObjectId::from_hex(&s_hex), CheckState::parse(&st_str)) else {
            continue;
        };
        let effective = match st {
            CheckState::Pass => CheckState::Pass,
            CheckState::Fail | CheckState::Pending | CheckState::Error => CheckState::Fail,
        };
        known.insert(id, (effective, run_count));
    }
    Ok(known)
}

/// Drive the bisect state machine forward as far as stored check results allow,
/// emitting `check.requested` when waiting on a runner or landing a priority
/// revert when the culprit is confirmed.
async fn drive_bisect(
    hub: &Arc<Hub>,
    project: &Project,
    rules: &Rules,
    b: &mut BisectRow,
    persisted: bool,
    holder: &str,
    epoch: i64,
) -> Result<()> {
    let mut query_snaps: Vec<String> = b.candidates.iter().map(ObjectId::hex).collect();
    query_snaps.push(b.good.hex());
    if let Some(p) = b.culprit_parent {
        query_snaps.push(p.hex());
    }
    query_snaps.sort();
    query_snaps.dedup();

    let mut known = load_known_checks(hub, project, rules, &b.check_name, &query_snaps).await?;
    let mut transitioned_to_confirming = false;

    if b.phase == "searching" {
        let prev_search = (b.good, b.bad, b.lo, b.hi, b.probes.clone());
        // Apply any known pass/fail results inside `lo..=hi` to tighten `[lo, hi]`.
        loop {
            let mut progressed = false;
            for idx in b.lo..=b.hi {
                let cand = b.candidates[idx];
                if let Some((st, _)) = known.get(&cand).copied() {
                    match st {
                        CheckState::Pass => {
                            if idx >= b.lo {
                                b.good = cand;
                                if idx < b.hi {
                                    b.lo = idx + 1;
                                    progressed = true;
                                    break;
                                } else {
                                    // Even `hi` passed on re-run -> flaky!
                                    b.phase = "flaky".to_string();
                                    b.probes.clear();
                                    save_bisect(hub, b, holder, epoch).await?;
                                    return Ok(());
                                }
                            }
                        }
                        CheckState::Fail if idx < b.hi => {
                            b.hi = idx;
                            b.bad = cand;
                            progressed = true;
                            break;
                        }
                        _ => {}
                    }
                }
            }
            if !progressed {
                break;
            }
        }

        if b.lo < b.hi {
            // Need to probe `k` midpoints in `b.lo..b.hi`.
            let k = rules.check_parallel.get(&b.check_name).copied().unwrap_or(1);
            let indices = probe_indices(b.lo, b.hi, k);
            let new_probes: Vec<ObjectId> = indices.into_iter().map(|i| b.candidates[i]).collect();
            let to_request: Vec<ObjectId> = new_probes
                .iter()
                .copied()
                .filter(|p| !b.probes.contains(p))
                .collect();
            b.probes = new_probes;
            let changed = !persisted
                || (b.good, b.bad, b.lo, b.hi, &b.probes)
                    != (prev_search.0, prev_search.1, prev_search.2, prev_search.3, &prev_search.4);
            if changed && save_bisect(hub, b, holder, epoch).await? {
                for probe in to_request {
                    crate::events::emit_check_requested(
                        hub,
                        project.id,
                        &b.branch,
                        probe,
                        &b.check_name,
                        &b.session_paths,
                        b.admin_only,
                        "bisect",
                    )
                    .await;
                }
            }
            return Ok(());
        }

        // `b.lo == b.hi`: we have narrowed to a single culprit candidate `C = b.candidates[b.lo]`.
        let culprit = b.candidates[b.lo];
        let parent = sync::blocking(hub, project.id, move |src| {
            Ok(src
                .snapshot(&culprit)?
                .parents
                .first()
                .copied()
                .unwrap_or_else(sync::root_snapshot_id))
        })
        .await?;

        let parent_target = choose_confirm_parent(hub, project.id, parent, b.good, &b.session_paths, b.admin_only).await?;
        let parent_hex = parent_target.hex();
        if parent_target != sync::root_snapshot_id() && !query_snaps.contains(&parent_hex) {
            let extra = load_known_checks(hub, project, rules, &b.check_name, &[parent_hex]).await?;
            known.extend(extra);
        }

        b.phase = "confirming".to_string();
        b.probes.clear();
        b.culprit = Some(culprit);
        b.culprit_parent = Some(parent_target);
        b.culprit_fails = 0;
        b.parent_passes = if parent_target == sync::root_snapshot_id() { 2 } else { 0 };
        transitioned_to_confirming = true;
    }

    if b.phase == "confirming" {
        let Some(culprit) = b.culprit else { return Ok(()) };
        let parent_target = b.culprit_parent.unwrap_or_else(sync::root_snapshot_id);
        let prev_confirm = (b.culprit_fails, b.parent_passes, b.probes.clone());

        match known.get(&culprit).copied() {
            Some((CheckState::Pass, _)) => {
                // Failed first, passed on confirmation re-run -> flaky! (Threat 14)
                b.phase = "flaky".to_string();
                b.probes.clear();
                save_bisect(hub, b, holder, epoch).await?;
                return Ok(());
            }
            Some((CheckState::Fail, count)) => {
                b.culprit_fails = b.culprit_fails.max(count.min(i32::MAX as i64) as i32);
            }
            _ => {}
        }

        if parent_target == sync::root_snapshot_id() {
            b.parent_passes = b.parent_passes.max(2);
        } else {
            match known.get(&parent_target).copied() {
                Some((CheckState::Fail, _)) => {
                    // Parent failed -> not introduced by `culprit` (or flaky check)!
                    b.phase = "flaky".to_string();
                    b.probes.clear();
                    save_bisect(hub, b, holder, epoch).await?;
                    return Ok(());
                }
                Some((CheckState::Pass, count)) => {
                    b.parent_passes = b.parent_passes.max(count.min(i32::MAX as i64) as i32);
                }
                _ => {}
            }
        }

        // `culprit` must fail at least twice (`checks.run_count >= 2` with `state = 'fail'`)
        // and `parent_target` must pass at least once (`state = 'pass'`).
        let mut needed_probes = Vec::new();
        if b.parent_passes < 1 && parent_target != sync::root_snapshot_id() {
            needed_probes.push(parent_target);
        }
        if b.culprit_fails < 2 {
            needed_probes.push(culprit);
        }

        if !needed_probes.is_empty() {
            let to_request: Vec<ObjectId> = needed_probes
                .iter()
                .copied()
                .filter(|p| !b.probes.contains(p))
                .collect();
            b.probes = needed_probes;
            let changed = !persisted
                || transitioned_to_confirming
                || (b.culprit_fails, b.parent_passes, &b.probes)
                    != (prev_confirm.0, prev_confirm.1, &prev_confirm.2);
            if changed {
                b.confirm_requested_at = veil_core::now_millis();
                if save_bisect(hub, b, holder, epoch).await? {
                    for p in to_request {
                        crate::events::emit_check_requested(
                            hub,
                            project.id,
                            &b.branch,
                            p,
                            &b.check_name,
                            &b.session_paths,
                            b.admin_only,
                            "confirm",
                        )
                        .await;
                    }
                }
            }
            return Ok(());
        }

        // Both `b.culprit_fails >= 2` and `b.parent_passes >= 1`!
        // The culprit is CONFIRMED!
        b.probes.clear();
        if !rules.allows_auto_revert(&b.branch) {
            b.phase = "confirmed".to_string();
            save_bisect(hub, b, holder, epoch).await?;
            return Ok(());
        }

        // Revert the confirmed culprit on the protected branch via S17!
        revert_confirmed_culprit(hub, project, b, culprit, holder, epoch).await?;
    }
    Ok(())
}

/// If `parent` is visible to the runner's footprint (`session_paths`) and did
/// not collapse into its parent for that footprint, return `parent`; otherwise
/// walk down to `good` to find the nearest ancestor that changed something in
/// `session_paths` (or `good` itself).
async fn choose_confirm_parent(
    hub: &Arc<Hub>,
    project_id: i64,
    parent: ObjectId,
    good: ObjectId,
    session_paths: &[String],
    admin_only: bool,
) -> Result<ObjectId> {
    if parent == sync::root_snapshot_id() || parent == good || admin_only || session_paths.is_empty() {
        return Ok(parent);
    }
    let paths = session_paths.to_vec();
    sync::blocking(hub, project_id, move |src| {
        let root = sync::root_snapshot_id();
        let mut cur = parent;
        for _ in 0..MAX_BISECT_LANDINGS {
            if cur == good || cur == root {
                return Ok(cur);
            }
            let s = src.snapshot(&cur)?;
            let p0 = s.parents.first().copied().unwrap_or(root);
            let p_tree = src.snapshot(&p0)?.tree;
            let set = edits::edit_set(src, s.tree, p_tree)?;
            if set.iter().any(|c| paths.iter().any(|p| path_under(&c.path, p))) {
                return Ok(cur);
            }
            cur = p0;
        }
        Ok(good)
    })
    .await
}

/// Ensure any `bisect_reverts` rows on `project_id` (optionally filtered to
/// `branch`) whose `landing_queue` ticket already finished are updated before
/// checking `revert_snapshot` or revert counts.
async fn sync_queued_reverts(hub: &Hub, project_id: i64, branch: Option<&str>) -> Result<()> {
    let pending: Vec<(String, i64, String, String)> = match branch {
        Some(br) => {
            sqlx::query_as(
                "SELECT branch, lineage, culprit, ticket FROM bisect_reverts \
                 WHERE project_id = $1 AND branch = $2 AND state = 'queued'",
            )
            .bind(project_id)
            .bind(br)
            .fetch_all(&hub.db)
            .await?
        }
        None => {
            sqlx::query_as(
                "SELECT branch, lineage, culprit, ticket FROM bisect_reverts \
                 WHERE project_id = $1 AND state = 'queued'",
            )
            .bind(project_id)
            .fetch_all(&hub.db)
            .await?
        }
    };
    for (br, lin, culprit_hex, ticket) in pending {
        let row: Option<(String, Option<String>)> = sqlx::query_as(
            "SELECT state, result FROM landing_queue WHERE project_id = $1 AND ticket = $2",
        )
        .bind(project_id)
        .bind(&ticket)
        .fetch_optional(&hub.db)
        .await?;
        let Some((st, Some(res_json))) = row else { continue };
        if st == "queued" || st == "merging" {
            continue;
        }
        let Ok(outcome) = serde_json::from_str::<veil_core::hub::land::LandResult>(&res_json) else {
            continue;
        };
        if outcome.state == LandState::Landed {
            let landed_hex = outcome.landed.first().map(ObjectId::hex);
            record_revert_landed(hub, project_id, &br, lin, &culprit_hex, landed_hex.as_deref(), "", true).await?;
            clear_reverted_landing_marks(hub, project_id, &br, lin, &culprit_hex).await?;
        } else if matches!(outcome.state, LandState::Conflict | LandState::Rejected) {
            sqlx::query(
                "UPDATE bisect_reverts SET state = 'conflict' \
                 WHERE project_id = $1 AND branch = $2 AND lineage = $3 AND culprit = $4 AND state = 'queued'",
            )
            .bind(project_id)
            .bind(&br)
            .bind(lin)
            .bind(&culprit_hex)
            .execute(&hub.db)
            .await?;
        }
    }
    Ok(())
}

/// Record that the server's revert of `culprit_hex` landed as `landed_hex`.
/// `bisect_reverts.revert_snapshot` is a root, so the write waits behind
/// GC's switch like every other root writer (BUG-1881): the guard is the
/// transaction's first statement, and a switch in between reruns it under
/// the new epoch. `only_queued`: only a row still `queued` changes (else any
/// row not yet `reverted`). An empty `culprit_cid` leaves the stored one.
/// Answers how many rows changed.
#[allow(clippy::too_many_arguments)]
async fn record_revert_landed(
    hub: &Hub,
    project_id: i64,
    branch: &str,
    lineage: i64,
    culprit_hex: &str,
    landed_hex: Option<&str>,
    culprit_cid: &str,
    only_queued: bool,
) -> Result<u64> {
    for attempt in 0..8 {
        let gc_epoch = crate::pack_gc::read_gc_epoch(hub, project_id).await?;
        let (branch, culprit_hex, landed_hex, culprit_cid) =
            (branch.to_string(), culprit_hex.to_string(), landed_hex.map(str::to_string), culprit_cid.to_string());
        let res = crate::db::transaction(&hub.db, crate::db::Isolation::ReadCommitted, move |c| {
            let (branch, culprit_hex, landed_hex, culprit_cid) = (branch.clone(), culprit_hex.clone(), landed_hex.clone(), culprit_cid.clone());
            Box::pin(async move {
                crate::pack_gc::guard_root_write(&mut *c, project_id, gc_epoch).await?;
                // A change reverted twice needs a person's approval from
                // now on: a batch that read the reverts before commits
                // first (BUG-2061).
                crate::prs::close_review_gate(&mut *c, project_id).await?;
                Ok(sqlx::query(
                    "UPDATE bisect_reverts \
                     SET state = 'reverted', revert_snapshot = $5, \
                         culprit_change_id = CASE WHEN culprit_change_id = '' THEN $6 ELSE culprit_change_id END \
                     WHERE project_id = $1 AND branch = $2 AND lineage = $3 AND culprit = $4 \
                       AND CASE WHEN $7 THEN state = 'queued' ELSE state <> 'reverted' END",
                )
                .bind(project_id)
                .bind(&branch)
                .bind(lineage)
                .bind(&culprit_hex)
                .bind(&landed_hex)
                .bind(&culprit_cid)
                .bind(only_queued)
                .execute(&mut *c)
                .await?
                .rows_affected())
            })
        })
        .await;
        match res {
            Err(e) if crate::pack_gc::is_gc_epoch_changed(&e) && attempt < 7 => continue,
            r => return r,
        }
    }
    unreachable!("the last attempt returns")
}

/// Remove deduplication rows for a reverted snapshot (`landed_changes`, and
/// `landings` where `submitted <> landed`) so re-landing or rewriting the
/// reverted `change_id` is judged afresh rather than skipped or rejected as
/// already landed.
async fn clear_reverted_landing_marks(
    hub: &Hub,
    project_id: i64,
    branch: &str,
    lineage: i64,
    culprit_hex: &str,
) -> Result<()> {
    sqlx::query(
        "DELETE FROM landed_changes WHERE project_id = $1 AND branch = $2 AND lineage = $3 AND landed = $4",
    )
    .bind(project_id)
    .bind(branch)
    .bind(lineage)
    .bind(culprit_hex)
    .execute(&hub.db)
    .await?;
    sqlx::query(
        "DELETE FROM landings WHERE project_id = $1 AND branch = $2 AND lineage = $3 AND landed = $4 AND submitted <> landed",
    )
    .bind(project_id)
    .bind(branch)
    .bind(lineage)
    .bind(culprit_hex)
    .execute(&hub.db)
    .await?;
    Ok(())
}

/// If `culprit` is a revert the server made itself on `(project_id, branch)`,
/// return the `(original_snapshot, original_change_id)` that revert undid.
async fn server_revert_origin(
    hub: &Arc<Hub>,
    project_id: i64,
    branch: &str,
    culprit: ObjectId,
) -> Result<Option<(ObjectId, String)>> {
    sync_queued_reverts(hub, project_id, Some(branch)).await?;
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT culprit, culprit_change_id FROM bisect_reverts \
         WHERE project_id = $1 AND branch = $2 AND revert_snapshot = $3 LIMIT 1",
    )
    .bind(project_id)
    .bind(branch)
    .bind(culprit.hex())
    .fetch_optional(&hub.db)
    .await?;
    let Some((orig_hex, mut orig_cid)) = row else {
        return Ok(None);
    };
    let orig = ObjectId::from_hex(&orig_hex).map_err(|e| Error::Other(e.into()))?;
    if orig_cid.is_empty() {
        orig_cid = sync::blocking(hub, project_id, move |src| {
            Ok(src.snapshot(&orig)?.change_id.to_string())
        })
        .await?;
    }
    Ok(Some((orig, orig_cid)))
}

/// Build and land the priority revert for confirmed `culprit` through S17
/// (`landing_queue` with `priority = 1`), idempotently across servers and
/// restarts.
async fn revert_confirmed_culprit(
    hub: &Arc<Hub>,
    project: &Project,
    b: &mut BisectRow,
    culprit: ObjectId,
    holder: &str,
    epoch: i64,
) -> Result<()> {
    //Never revert an unreleased embargoed snapshot.
    if crate::embargo::is_withheld_for_query(hub, project.id, &culprit).await? {
        b.phase = "unconfirmed".to_string();
        save_bisect(hub, b, holder, epoch).await?;
        return Ok(());
    }

    // BUG-1884: the server never reverts a revert it made itself. Stop the
    // bisect as `needs a person` without reverting, and notify participants
    // who see the culprit or original change through the event stream.
    if let Some((original, original_cid)) = server_revert_origin(hub, project.id, &b.branch, culprit).await? {
        let culprit_cid = sync::blocking(hub, project.id, move |src| {
            Ok(src.snapshot(&culprit)?.change_id.to_string())
        })
        .await?;
        b.phase = "needs a person".to_string();
        b.probes.clear();
        if save_bisect(hub, b, holder, epoch).await? {
            crate::events::emit_needs_person(
                hub,
                project.id,
                &b.branch,
                culprit,
                &culprit_cid,
                original,
                &original_cid,
                &b.check_name,
                &b.session_paths,
                b.admin_only,
            )
            .await;
        }
        return Ok(());
    }

    // Refuse to auto-revert changes to `.veilpolicy` or `.veilrules` (only an admin's
    // explicit push/change may alter access or branch rules).
    let (culprit_parent, culprit_cid, culprit_patch, touches_policy_or_rules, revert_snap_id, revert_raw) =
        sync::blocking(hub, project.id, {
            let identity = hub.identity.clone();
            move |src| {
                let cs = src.snapshot(&culprit)?;
                let p0 = cs
                    .parents
                    .first()
                    .copied()
                    .unwrap_or_else(sync::root_snapshot_id);
                let ps = src.snapshot(&p0)?;
                let set = edits::edit_set(src, cs.tree, ps.tree)?;
                let touches_special = set.iter().any(|c| {
                    c.path == veil_core::policy::POLICY_FILE
                        || c.path == crate::landing::rules::RULES_FILE
                        || veil_core::hub::agent::decides_access(&c.path)
                });
                let cid_str = cs.change_id.to_string();
                // What the culprit's edits were, whatever change id carries
                // them (BUG-1921).
                let patch = crate::prs::edits_id(src, culprit, p0)?.unwrap_or_default();
                // Deterministic change_id for the revert of `(culprit, lineage)` so
                // concurrent servers construct the exact same revertchange_id.
                let mut h = blake3::Hasher::new();
                h.update(b"veil-bisect-revert-1:");
                h.update(&src.project.to_le_bytes());
                h.update(&culprit.0);
                let rev_cid = ChangeId(h.finalize().as_bytes()[..16].try_into().unwrap());
                let mut rev_snap = Snapshot {
                    parents: vec![culprit],
                    change_id: rev_cid,
                    tree: ps.tree,
                    description: Text::Plain(format!("revert {cid_str}")),
                    author: "server".to_string(),
                    timestamp: cs.timestamp.saturating_add(1),
                    predecessors: Vec::new(),
                    conflicts: Vec::new(),
                    embargo: None,
                    agent: Some(Attribution {
                        agent: "server/bisect".to_string(),
                        task: Some(format!("revert:{cid_str}")),
                        prompt: None,
                        run: None,
                    }),
                    abandoned: None,
                    attempts: Vec::new(),
                    signature: None,
                };
                rev_snap.sign(&identity);
                let raw = Bytes::from(Object::Snapshot(rev_snap).encode());
                let id = ObjectId::hash(&raw);
                Ok((p0, cid_str, patch, touches_special, id, raw))
            }
        })
        .await?;
    let _ = culprit_parent;

    if touches_policy_or_rules {
        b.phase = "conflict".to_string();
        save_bisect(hub, b, holder, epoch).await?;
        return Ok(());
    }

    // Store the revert snapshot object in the object store.
    hub.objects.put(project.id, &revert_snap_id, revert_raw).await?;

    // Find a project admin to stand for the queue row's `person_id` foreign key
    // (as `embargo.rs` does for scheduled embargo releases).
    let (admin_id, admin_name, admin_device_key): (i64, String, String) = sqlx::query_as(
        "SELECT p.id, p.name, COALESCE((SELECT d.signing_key FROM devices d WHERE d.person_id = p.id AND d.removed_at IS NULL LIMIT 1), '') \
         FROM project_admins a JOIN people p ON p.id = a.person_id WHERE a.project_id = $1 ORDER BY a.person_id LIMIT 1",
    )
    .bind(project.id)
    .fetch_one(&hub.db)
    .await?;

    let (_, _, epochs) = perm::open_at(
        hub,
        &project.name,
        &Caller {
            person: Some(Person {
                id: admin_id,
                name: admin_name.clone(),
                device_key: admin_device_key.clone(),
                agent: None,
            }),
            epochs: crate::caches::Epochs::default(),
        },
    )
    .await?;

    // Deterministic ticket so that even across multiple servers or restarts, at most
    // one revert is queued in `landing_queue` for `(project, branch, lineage, culprit)`.
    let ticket = format!(
        "revert-{}-{}-{}-{}",
        project.id,
        b.branch,
        b.lineage,
        &culprit.hex()[..16]
    );
    let stack = vec![Entry::plain(revert_snap_id, culprit)];
    let stack_json = crate::landing::encode_stack(&stack);

    let pid = project.id;
    let branch_name = b.branch.clone();
    let lineage = b.lineage;
    let culprit_hex = culprit.hex();
    let check_name = b.check_name.clone();
    let rev_hex = revert_snap_id.hex();
    let ticket2 = ticket.clone();
    let p_epoch = epochs.person;
    let j_epoch = epochs.project.map_or(0, |(_, e)| e);
    let gc_epoch = b.gc_epoch;

    let culprit_cid2 = culprit_cid.clone();
    crate::db::transaction(&hub.db, crate::db::Isolation::ReadCommitted, move |c| {
        let culprit_patch = culprit_patch.clone();
        let (branch_name, culprit_hex, culprit_cid2, check_name, rev_hex, ticket2, admin_name, admin_device_key, stack_json) = (
            branch_name.clone(),
            culprit_hex.clone(),
            culprit_cid2.clone(),
            check_name.clone(),
            rev_hex.clone(),
            ticket2.clone(),
            admin_name.clone(),
            admin_device_key.clone(),
            stack_json.clone(),
        );
        Box::pin(async move {
            crate::pack_gc::guard_root_write(&mut *c, pid, gc_epoch).await?;
            sqlx::query(
                "INSERT INTO snapshots (project_id, id, author) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
            )
            .bind(pid)
            .bind(&rev_hex)
            .bind(admin_id)
            .execute(&mut *c)
            .await?;

            let inserted = sqlx::query(
                "INSERT INTO bisect_reverts (project_id, branch, lineage, culprit, culprit_change_id, check_name, ticket, state, created_at, culprit_patch) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, 'queued', (extract(epoch FROM clock_timestamp()) * 1000)::BIGINT, $8) \
                 ON CONFLICT (project_id, branch, lineage, culprit) DO NOTHING",
            )
            .bind(pid)
            .bind(&branch_name)
            .bind(lineage)
            .bind(&culprit_hex)
            .bind(&culprit_cid2)
            .bind(&check_name)
            .bind(&ticket2)
            .bind(&culprit_patch)
            .execute(&mut *c)
            .await?
            .rows_affected();

            if inserted == 1 {
                sqlx::query(
                    "INSERT INTO landing_queue ( \
                        project_id, branch, ticket, person_id, person_name, device_key, stack, lineage, \
                        person_epoch, project_epoch, priority, state, created_at \
                     ) VALUES ( \
                        $1, $2, $3, $4, $5, $6, $7, $8, \
                        $9, $10, 1, 'queued', (extract(epoch FROM clock_timestamp()) * 1000000)::BIGINT \
                     ) ON CONFLICT (ticket) DO NOTHING",
                )
                .bind(pid)
                .bind(&branch_name)
                .bind(&ticket2)
                .bind(admin_id)
                .bind(&admin_name)
                .bind(&admin_device_key)
                .bind(&stack_json)
                .bind(lineage)
                .bind(p_epoch)
                .bind(j_epoch)
                .execute(&mut *c)
                .await?;
            }
            Ok(())
        })
    })
    .await?;

    hub.caches.put_committed(project.id, &revert_snap_id);
    b.phase = "reverting".to_string();
    b.revert_ticket = Some(ticket.clone());
    save_bisect(hub, b, holder, epoch).await?;

    // Wait for the landing service (unless its lease is held externally by a test,
    // in which case we return after a short wait and `sync_revert_outcome` updates
    // the row when the landing completes).
    let w = hub.landing.register(&ticket);
    if let Some((_, cur)) = crate::landing::read(hub, project.id, admin_id, &ticket).await? {
        let outcome = if cur.state == LandState::Queued {
            crate::landing::ensure(hub, project.id, &b.branch);
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(6_000);
            crate::landing::wait(hub, project.id, admin_id, &b.branch, w, deadline).await?
        } else {
            crate::landing::abandon(hub, w);
            cur
        };
        apply_revert_outcome(hub, project.id, b, culprit, &culprit_cid, &ticket, outcome, holder, epoch).await?;
    } else {
        crate::landing::abandon(hub, w);
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn apply_revert_outcome(
    hub: &Arc<Hub>,
    project_id: i64,
    b: &mut BisectRow,
    culprit: ObjectId,
    culprit_cid: &str,
    ticket: &str,
    outcome: veil_core::hub::land::LandResult,
    holder: &str,
    epoch: i64,
) -> Result<()> {
    match outcome.state {
        LandState::Landed => {
            let landed_snap = outcome.landed.first().copied();
            b.phase = "reverted".to_string();
            b.revert_snapshot = landed_snap;
            for attempt in 0..8 {
                b.gc_epoch = crate::pack_gc::read_gc_epoch(hub, project_id).await?;
                match save_bisect(hub, b, holder, epoch).await {
                    Ok(_) => break,
                    Err(e) if crate::pack_gc::is_gc_epoch_changed(&e) && attempt < 7 => continue,
                    Err(e) => return Err(e),
                }
            }
            let landed_hex = landed_snap.map(|x| x.hex());
            let culprit_hex = culprit.hex();
            let notified =
                record_revert_landed(hub, project_id, &b.branch, b.lineage, &culprit_hex, landed_hex.as_deref(), culprit_cid, false).await?;
            clear_reverted_landing_marks(hub, project_id, &b.branch, b.lineage, &culprit_hex).await?;
            if notified == 1 {
                if let Some(rev_real) = landed_snap {
                    crate::events::emit_reverted(
                        hub,
                        project_id,
                        &b.branch,
                        culprit,
                        culprit_cid,
                        rev_real,
                        &b.check_name,
                        &b.session_paths,
                        b.admin_only,
                    )
                    .await;
                }
            }
        }
        LandState::Conflict | LandState::Rejected => {
            b.phase = "conflict".to_string();
            for attempt in 0..8 {
                b.gc_epoch = crate::pack_gc::read_gc_epoch(hub, project_id).await?;
                match save_bisect(hub, b, holder, epoch).await {
                    Ok(_) => break,
                    Err(e) if crate::pack_gc::is_gc_epoch_changed(&e) && attempt < 7 => continue,
                    Err(e) => return Err(e),
                }
            }
            sqlx::query(
                "UPDATE bisect_reverts SET state = 'conflict' \
                 WHERE project_id = $1 AND branch = $2 AND lineage = $3 AND culprit = $4",
            )
            .bind(project_id)
            .bind(&b.branch)
            .bind(b.lineage)
            .bind(culprit.hex())
            .execute(&hub.db)
            .await?;
        }
        LandState::Queued => {}
    }
    let _ = ticket;
    Ok(())
}

/// Synchronize a `reverting` bisect row with its `landing_queue` outcome if it
/// finished after `revert_confirmed_culprit` returned.
pub async fn sync_revert_outcome(hub: &Arc<Hub>, project_id: i64, branch: &str) -> Result<()> {
    let Some(mut b) = load_bisect(hub, project_id, branch).await? else {
        return Ok(());
    };
    if b.phase != "reverting" {
        return Ok(());
    };
    let (Some(ticket), Some(culprit)) = (b.revert_ticket.clone(), b.culprit) else {
        return Ok(());
    };
    let row: Option<(String, Option<String>)> = sqlx::query_as(
        "SELECT state, result FROM landing_queue WHERE project_id = $1 AND ticket = $2",
    )
    .bind(project_id)
    .bind(&ticket)
    .fetch_optional(&hub.db)
    .await?;
    let Some((state, res_opt)) = row else {
        return Ok(());
    };
    if state == "queued" || state == "merging" {
        crate::landing::ensure(hub, project_id, branch);
        return Ok(());
    }
    let Some(res_json) = res_opt else {
        return Ok(());
    };
    let Ok(outcome) = serde_json::from_str::<veil_core::hub::land::LandResult>(&res_json) else {
        return Ok(());
    };
    let culprit_cid = sync::blocking(hub, project_id, move |src| {
        Ok(src.snapshot(&culprit)?.change_id.to_string())
    })
    .await?;
    let Some((holder, epoch)) = acquire_lease(hub, project_id, branch).await? else {
        return Ok(());
    };
    let r = apply_revert_outcome(hub, project_id, &mut b, culprit, &culprit_cid, &ticket, outcome, &holder, epoch).await;
    release_lease(hub, project_id, branch, &holder, epoch).await;
    r
}

/// `GET /v1/projects/{p}/bisect/{branch}`: the current or last bisect on
/// `branch`, projected and visibility-filtered for the caller.
pub async fn status_route(
    State(hub): State<HubState>,
    caller: Caller,
    Path((p, branch)): Path<(String, String)>,
) -> Result<Json<BisectStatus>> {
    let (project, viewer) = perm::open(&hub, &p, &caller).await?;
    // Reconcile any stored check results or pending revert outcome before answering.
    let _ = reconcile_branch(&hub, &project, &branch).await;
    let _ = sync_revert_outcome(&hub, project.id, &branch).await;

    let Some(b) = load_bisect(&hub, project.id, &branch).await? else {
        return Err(Error::not_found(format!("no bisect on branch '{branch}'")));
    };

    // Check if the viewer can see the bisect's check or any of the bisect's snapshots.
    let sees_check = crate::ci::can_see_check(&project, &viewer, &b.session_paths, b.admin_only);

    // Filter `b.candidates` and `b.probes` to snapshots that are visible to `viewer`
    // (not withheld by an embargo and not collapsed into their parent's projection).
    let mut vis_candidates = Vec::new();
    for &c in &b.candidates {
        if let Some(pc) = visible_projection(&hub, &project, &viewer, c).await? {
            if !vis_candidates.contains(&pc) {
                vis_candidates.push(pc);
            }
        }
    }
    if vis_candidates.is_empty() {
        return Err(Error::not_found(format!("no bisect on branch '{branch}'")));
    }

    let mut vis_probes = Vec::new();
    for &pr in &b.probes {
        if let Some(ppr) = visible_projection(&hub, &project, &viewer, pr).await? {
            if !vis_probes.contains(&ppr) {
                vis_probes.push(ppr);
            }
        }
    }

    let mut vis_culprit = None;
    let mut vis_culprit_cid = None;
    let mut vis_original = None;
    let mut vis_original_cid = None;
    if let Some(c) = b.culprit {
        if let Some(pc) = visible_projection(&hub, &project, &viewer, c).await? {
            vis_culprit = Some(pc);
            let cid = sync::blocking(&hub, project.id, move |src| {
                Ok(src.snapshot(&c)?.change_id.to_string())
            })
            .await?;
            vis_culprit_cid = Some(cid);
        }
        if b.phase == "needs a person" {
            if let Some((orig, ocid)) = server_revert_origin(&hub, project.id, &b.branch, c).await? {
                if let Some(po) = visible_projection(&hub, &project, &viewer, orig).await? {
                    vis_original = Some(po);
                    vis_original_cid = Some(ocid);
                }
            }
        }
    }

    let mut vis_revert = None;
    if let Some(r) = b.revert_snapshot {
        vis_revert = visible_projection(&hub, &project, &viewer, r).await?;
    }

    // If the viewer cannot see the check AND neither a culprit nor a revert (nor
    // the original change undid by a culprit revert) is visible to them, the
    // bisect does not exist in their view (`404`).
    if !sees_check && vis_culprit.is_none() && vis_revert.is_none() && vis_original.is_none() {
        return Err(Error::not_found(format!("no bisect on branch '{branch}'")));
    }
    if b.culprit.is_some() && vis_culprit.is_none() && vis_revert.is_none() && vis_original.is_none() {
        return Err(Error::not_found(format!("no bisect on branch '{branch}'")));
    }

    if crate::embargo::is_withheld_from_viewer(&hub, &project, &viewer, &b.good).await?
        || crate::embargo::is_withheld_from_viewer(&hub, &project, &viewer, &b.bad).await?
    {
        return Err(Error::not_found(format!("no bisect on branch '{branch}'")));
    }
    let p_good = sync::projected(&hub, &project, &viewer, b.good).await?;
    let p_bad = sync::projected(&hub, &project, &viewer, b.bad).await?;
    if p_good == p_bad && !sees_check {
        return Err(Error::not_found(format!("no bisect on branch '{branch}'")));
    }

    Ok(Json(BisectStatus {
        branch: b.branch,
        phase: b.phase,
        check: sees_check.then_some(b.check_name),
        good: p_good,
        bad: p_bad,
        candidates: vis_candidates,
        probes: vis_probes,
        culprit: vis_culprit,
        culprit_change_id: vis_culprit_cid,
        original: vis_original,
        original_change_id: vis_original_cid,
        revert: vis_revert,
        revert_ticket: (viewer.admin || vis_revert.is_some()).then_some(b.revert_ticket).flatten(),
        updated_at: b.updated_at,
    }))
}

/// Project `real` for `viewer`, returning `Some(proj)` only if `real` is not
/// withheld by an embargo and did not collapse into its first parent's
/// projection (and, for a narrowed session, touched at least one path inside
/// the session's narrowing).
async fn visible_projection(
    hub: &Arc<Hub>,
    project: &Project,
    viewer: &Viewer,
    real: ObjectId,
) -> Result<Option<ObjectId>> {
    if real == sync::root_snapshot_id() {
        return Ok(None);
    }
    if crate::embargo::is_withheld_from_viewer(hub, project, viewer, &real).await? {
        return Ok(None);
    }
    let proj = sync::projected(hub, project, viewer, real).await?;
    if viewer.admin && viewer.only.is_none() {
        return Ok(Some(proj));
    }
    let (policy_text, bindings, v) = (project.policy_text.clone(), project.bindings.clone(), viewer.clone());
    let (parent, touches_visible) = sync::blocking(hub, project.id, move |src| {
        let s = src.snapshot(&real)?;
        let Some(p0) = s.parents.first().copied() else {
            return Ok((None, false));
        };
        let ps = src.snapshot(&p0)?;
        let p = Project {
            id: src.project,
            name: String::new(),
            default_branch: String::new(),
            policy: AccessPolicy::parse(&policy_text),
            policy_text,
            bindings,
        };
        let view = p.view(&v);
        let step = edits::edit_set(src, s.tree, ps.tree)?;
        let vis = step.iter().any(|c| view.read(&c.path) && view.within_narrowing(&c.path));
        Ok((Some(p0), vis))
    })
    .await?;
    if !touches_visible {
        return Ok(None);
    }
    if let Some(p0) = parent {
        let pp0 = sync::projected(hub, project, viewer, p0).await?;
        if pp0 == proj {
            return Ok(None);
        }
    }
    Ok(Some(proj))
}
