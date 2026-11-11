//! Embargoes through the server, hidden embargo lines, and the scheduled
//! release service (`docs/HUB.md` §13.31;
//! `docs/design/server/phase-4-agent-scale.md` §4.8, decisions 8 and 9, and
//! §6 row 8; milestone S22).
//!
//! * **No encryption**: embargoes are server-enforced visibility boundaries
//!   that turn public at a deadline. The server holds the real history on a
//!   hidden branch `embargo/<id>` (`branches.hidden_for_embargo = <id>`) and
//!   returns it in `tips` (with the signed [`EmbargoRecord`] in
//!   `Tips.embargoes`) only to members of the embargo's groups and project
//!   admins.
//! * **Invisibility outside the embargo**: every non-sync route (`query`,
//!   `search`, `derive`, `changes`, `landing`) ignores branches with
//!   `hidden_for_embargo IS NOT NULL`, and snapshots recorded in
//!   `embargo_snapshots` for an unreleased embargo are withheld from outsiders
//!   (and from query/search routes until release), returning the same
//!   not-found answers as a missing branch or snapshot.
//! * **Scheduled release and landing**: a background release ticker checks
//!   `embargo_lines` against PostgreSQL's `clock_timestamp()` (never the app
//!   server's local clock) and queues a deterministic landing ticket
//!   (`embargo-<project>-<id>`) onto `target_branch` (`main`), landing the
//!   embargoed changes once, stripping the `embargo` marker on the landed
//!   snapshots, and deleting the hidden `embargo/<id>` branch and its
//!   `embargo_snapshots` rows.

use std::{
    collections::{HashMap, HashSet},
    sync::{
        atomic::{AtomicI64, AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use axum::{
    extract::{Path, State as AxumState},
    Json,
};
use sqlx::PgConnection;
use veil_core::{
    embargo::{embargo_branch, embargo_id_of_branch},
    hub::{
        land::LandState,
        wire::PushRequest,
    },
    keychain::EmbargoRecord,
    object::Snapshot,
    ObjectId,
};

use crate::{
    auth::{Caller, Person},
    error::{Error, Result},
    perm::{self, Binding, Project, Viewer},
    Hub, HubState,
};

/// Shared embargo release service state on [`Hub`].
#[derive(Default)]
pub struct State {
    clock_offset_ms: AtomicI64,
    fail_next: AtomicU64,
    retried_failures: AtomicU64,
    wake: tokio::sync::Notify,
}

impl State {
    pub fn set_clock_offset_ms(&self, offset_ms: i64) {
        self.clock_offset_ms.store(offset_ms, Ordering::SeqCst);
    }

    pub fn clock_offset_ms(&self) -> i64 {
        self.clock_offset_ms.load(Ordering::SeqCst)
    }

    pub fn fail_next_releases(&self, count: u64) {
        self.fail_next.store(count, Ordering::SeqCst);
    }

    pub fn retried_failures(&self) -> u64 {
        self.retried_failures.load(Ordering::SeqCst)
    }

    pub fn wake(&self) {
        self.wake.notify_waiters();
    }
}

/// An embargo line row created or updated during a push transaction.
#[derive(Clone, Debug)]
pub struct LineUpsert {
    pub embargo_id: String,
    pub group_names: Vec<String>,
    pub target_branch: String,
    pub embargo_branch: String,
    pub until_ms: Option<i64>,
    pub released_at: Option<i64>,
    pub record_json: String,
    pub created_by: String,
    pub created_at: i64,
}

/// What [`can_see_groups`] knows without the database: `Some(true)` for an
/// admin or a member of a group the policy binds one of `group_names` to,
/// `Some(false)` when `viewer` is in no group or no group is named.
fn in_bound_groups(project: &Project, viewer: &Viewer, group_names: &[String]) -> Option<bool> {
    if viewer.admin {
        return Some(true);
    }
    if viewer.groups.is_empty() || group_names.is_empty() {
        return Some(false);
    }
    let bound = group_names.iter().any(|g| matches!(project.bindings.get(g), Some(Binding::Group(gid)) if viewer.groups.contains(gid)));
    bound.then_some(true)
}

/// Does `viewer` belong to at least one of `group_names` in `project` (or is
/// `viewer` an admin of `project`)?
pub async fn can_see_groups(hub: &Hub, project: &Project, viewer: &Viewer, group_names: &[String]) -> Result<bool> {
    if let Some(known) = in_bound_groups(project, viewer, group_names) {
        return Ok(known);
    }
    let mut c = hub.db.acquire().await?;
    can_see_groups_conn(&mut c, project, viewer, group_names).await
}

/// [`can_see_groups`] on a connection.
async fn can_see_groups_conn(c: &mut PgConnection, project: &Project, viewer: &Viewer, group_names: &[String]) -> Result<bool> {
    if let Some(known) = in_bound_groups(project, viewer, group_names) {
        return Ok(known);
    }
    let gids: Vec<i64> = sqlx::query_scalar("SELECT id FROM groups WHERE project_id = $1 AND name = ANY($2)")
        .bind(project.id)
        .bind(group_names)
        .fetch_all(&mut *c)
        .await?;
    Ok(gids.into_iter().any(|gid| viewer.groups.contains(&gid)))
}

/// Can `viewer` see the embargo `embargo_id` in `project`?
pub async fn can_see(hub: &Hub, project: &Project, viewer: &Viewer, embargo_id: &str) -> Result<bool> {
    if viewer.admin {
        return Ok(true);
    }
    let mut c = hub.db.acquire().await?;
    can_see_conn(&mut c, project, viewer, embargo_id).await
}

/// [`can_see`] on a connection (a landing batch counts an embargoed PR's
/// approvals inside its transaction: BUG-1880).
pub async fn can_see_conn(c: &mut PgConnection, project: &Project, viewer: &Viewer, embargo_id: &str) -> Result<bool> {
    if viewer.admin {
        return Ok(true);
    }
    let row: Option<(Vec<String>, Option<i64>)> =
        sqlx::query_as("SELECT group_names, released_at FROM embargo_lines WHERE project_id = $1 AND embargo_id = $2")
            .bind(project.id)
            .bind(embargo_id)
            .fetch_optional(&mut *c)
            .await?;
    let Some((groups, released_at)) = row else {
        return Ok(false);
    };
    if released_at.is_some() {
        return Ok(true);
    }
    can_see_groups_conn(c, project, viewer, &groups).await
}

/// Filter branch `(name, target)` rows from `branches` so that hidden embargo
/// branches (`embargo/<id>`) are only visible to members of that embargo's
/// groups (and admins).
pub async fn filter_branches(
    hub: &Hub,
    project: &Project,
    viewer: &Viewer,
    rows: &[(String, String)],
) -> Result<Vec<(String, String)>> {
    if viewer.admin || !rows.iter().any(|(name, _)| embargo_id_of_branch(name).is_some()) {
        return Ok(rows.to_vec());
    }
    let mut out = Vec::with_capacity(rows.len());
    for (name, target) in rows {
        if let Some(eid) = embargo_id_of_branch(name) {
            if !can_see(hub, project, viewer, eid).await? {
                continue;
            }
        }
        out.push((name.clone(), target.clone()));
    }
    Ok(out)
}

/// The [`EmbargoRecord`]s in `project` visible to `viewer` (active embargoes
/// they are in, plus recently released ones so `vl pull` can mark local
/// keychain records released). Outsiders receive an empty list.
pub async fn embargoes_for(hub: &Hub, project: &Project, viewer: &Viewer) -> Result<Vec<EmbargoRecord>> {
    let rows: Vec<(Vec<String>, String)> = sqlx::query_as(
        "SELECT group_names, record_json FROM embargo_lines WHERE project_id = $1 ORDER BY created_at, embargo_id",
    )
    .bind(project.id)
    .fetch_all(&hub.db)
    .await?;
    let mut out = Vec::new();
    for (groups, json) in rows {
        if can_see_groups(hub, project, viewer, &groups).await? {
            if let Ok(rec) = serde_json::from_str::<EmbargoRecord>(&json) {
                out.push(rec);
            }
        }
    }
    Ok(out)
}

/// Is `snapshot` (real or projected) on an active embargo line in `project`?
/// Used by the query API to withhold unreleased embargo snapshots from every
/// viewer (including admins) until release.
pub async fn is_withheld_for_query(hub: &Hub, project: i64, snapshot: &ObjectId) -> Result<bool> {
    let hex = snapshot.hex();
    let eid: Option<String> = sqlx::query_scalar(
        "SELECT s.embargo_id FROM embargo_snapshots s \
         JOIN embargo_lines l ON l.project_id = s.project_id AND l.embargo_id = s.embargo_id \
         WHERE s.project_id = $1 \
           AND (s.snapshot = $2 OR s.snapshot IN (SELECT real_id FROM projections WHERE project_id = $1 AND projected_id = $2)) \
           AND l.released_at IS NULL LIMIT 1",
    )
    .bind(project)
    .bind(&hex)
    .fetch_optional(&hub.db)
    .await?;
    Ok(eid.is_some())
}

/// Is `snapshot` (real or projected) withheld from `viewer` in sync routes
/// (`history`, `fetch`, `resolve_for`) because it belongs to an unreleased
/// embargo that `viewer` is not in?
pub async fn is_withheld_from_viewer(hub: &Hub, project: &Project, viewer: &Viewer, snapshot: &ObjectId) -> Result<bool> {
    if viewer.admin {
        return Ok(false);
    }
    let hex = snapshot.hex();
    let groups: Option<Vec<String>> = sqlx::query_scalar(
        "SELECT l.group_names FROM embargo_snapshots s \
         JOIN embargo_lines l ON l.project_id = s.project_id AND l.embargo_id = s.embargo_id \
         WHERE s.project_id = $1 \
           AND (s.snapshot = $2 OR s.snapshot IN (SELECT real_id FROM projections WHERE project_id = $1 AND projected_id = $2)) \
           AND l.released_at IS NULL LIMIT 1",
    )
    .bind(project.id)
    .bind(&hex)
    .fetch_optional(&hub.db)
    .await?;
    let Some(groups) = groups else {
        return Ok(false);
    };
    Ok(!can_see_groups(hub, project, viewer, &groups).await?)
}

/// Return every unreleased `embargo_id` in `project_id` carried by any real
/// snapshot in `starts` or its ancestors (decided from the content's ancestry,
/// regardless of which route created the snapshot).
pub async fn active_embargoes_of(
    hub: &Arc<Hub>,
    project_id: i64,
    starts: &[ObjectId],
    fresh: &HashMap<ObjectId, (Vec<ObjectId>, i64)>,
    staged: Option<Arc<crate::sync::Staged>>,
) -> Result<std::collections::BTreeSet<String>> {
    use std::collections::BTreeSet;
    if starts.is_empty() {
        return Ok(BTreeSet::new());
    }
    let active_ids: Vec<String> = sqlx::query_scalar(
        "SELECT embargo_id FROM embargo_lines WHERE project_id = $1 AND released_at IS NULL",
    )
    .bind(project_id)
    .fetch_all(&hub.db)
    .await?;
    if active_ids.is_empty() {
        return Ok(BTreeSet::new());
    }
    let active_set: HashSet<String> = active_ids.into_iter().collect();

    let snap_rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT s.snapshot, s.embargo_id FROM embargo_snapshots s \
         JOIN embargo_lines l ON l.project_id = s.project_id AND l.embargo_id = s.embargo_id \
         WHERE s.project_id = $1 AND l.released_at IS NULL",
    )
    .bind(project_id)
    .fetch_all(&hub.db)
    .await?;
    let mut tagged: HashMap<ObjectId, Vec<String>> = HashMap::new();
    for (s_hex, eid) in snap_rows {
        if let Ok(oid) = ObjectId::from_hex(&s_hex) {
            tagged.entry(oid).or_default().push(eid);
        }
    }

    let branch_rows: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT target, hidden_for_embargo FROM branches WHERE project_id = $1",
    )
    .bind(project_id)
    .fetch_all(&hub.db)
    .await?;
    let mut public_tips: Vec<ObjectId> = Vec::new();
    for (t_hex, hidden) in branch_rows {
        let Ok(oid) = ObjectId::from_hex(&t_hex) else { continue };
        match hidden {
            Some(eid) if active_set.contains(&eid) => {
                let v = tagged.entry(oid).or_default();
                if !v.contains(&eid) {
                    v.push(eid);
                }
            }
            None => public_tips.push(oid),
            _ => {}
        }
    }

    let root = crate::sync::root_snapshot_id();
    let starts_vec = starts.to_vec();
    let fresh_map: HashMap<ObjectId, Vec<ObjectId>> =
        fresh.iter().map(|(k, (ps, _))| (*k, ps.clone())).collect();

    crate::sync::blocking_staged(hub, project_id, staged, move |src| {
        let mut public_ancs: HashSet<ObjectId> = HashSet::new();
        let mut p_stack = public_tips;
        while let Some(cur) = p_stack.pop() {
            if cur == root || public_ancs.len() >= 512 || tagged.contains_key(&cur) {
                continue;
            }
            let Ok(s) = src.snapshot(&cur) else { continue };
            if s.embargo.as_ref().is_some_and(|e| active_set.contains(e)) {
                continue;
            }
            if public_ancs.insert(cur) {
                p_stack.extend(s.parents.iter().copied());
            }
        }

        let mut found: BTreeSet<String> = BTreeSet::new();
        let mut visited: HashSet<ObjectId> = HashSet::new();
        let mut stack = starts_vec;
        while let Some(cur) = stack.pop() {
            if cur == root || !visited.insert(cur) || visited.len() > 8_192 {
                continue;
            }
            if let Some(eids) = tagged.get(&cur) {
                found.extend(eids.iter().cloned());
            }
            if public_ancs.contains(&cur) {
                continue;
            }
            if let Some(ps) = fresh_map.get(&cur) {
                stack.extend(ps.iter().copied());
            } else if let Ok(s) = src.snapshot(&cur) {
                if let Some(eid) = &s.embargo {
                    if active_set.contains(eid) {
                        found.insert(eid.clone());
                    }
                }
                stack.extend(s.parents.iter().copied());
            }
        }
        Ok(found)
    })
    .await
}

/// Validate `req.embargoes` and any embargoed snapshots in `parents_of`,
/// rewrite `req.updates` (when `divert_branches` is true) so pushes of
/// embargoed changes divert to `embargo/<id>`, and return `(upserts, releases, diverted)`
/// to apply in / after the push transaction.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn prepare_push(
    hub: &Arc<Hub>,
    project: &Project,
    viewer: &Viewer,
    pusher_key: &str,
    req: &mut PushRequest,
    parents_of: &HashMap<ObjectId, Arc<Snapshot>>,
    order: &[ObjectId],
    real_of: &HashMap<ObjectId, ObjectId>,
    staged: Option<Arc<crate::sync::Staged>>,
    divert_branches: bool,
) -> Result<(Vec<LineUpsert>, Vec<(String, EmbargoRecord)>, HashMap<String, String>)> {
    let mut records_by_id: HashMap<String, EmbargoRecord> = HashMap::new();
    let mut releases: Vec<(String, EmbargoRecord)> = Vec::new();
    let mut upserts: Vec<LineUpsert> = Vec::new();

    let mut pushed_eids: HashSet<String> = HashSet::new();
    for id in order {
        if let Some(eid) = &parents_of[id].embargo {
            pushed_eids.insert(eid.clone());
        }
    }
    for u in &req.updates {
        if let Some(eid) = embargo_id_of_branch(&u.branch) {
            pushed_eids.insert(eid.to_string());
        }
    }

    // 1. Validate every EmbargoRecord in `req.embargoes` against the stored
    //    embargo line when one exists (never trusting the pushed record's groups
    //    or deadline over the stored row).
    for rec in &req.embargoes {
        if rec.format != veil_core::keychain::EMBARGO_FORMAT {
            return Err(Error::bad_request(format!("unsupported embargo record format {}", rec.format)));
        }
        if rec.id.len() != 10 || !rec.id.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) {
            return Err(Error::bad_request("an embargo id is 10 lowercase hex characters"));
        }
        let existing: Option<(Vec<String>, String)> = sqlx::query_as(
            "SELECT group_names, record_json FROM embargo_lines WHERE project_id = $1 AND embargo_id = $2",
        )
        .bind(project.id)
        .bind(&rec.id)
        .fetch_optional(&hub.db)
        .await?;

        if let Some((stored_groups, stored_json)) = existing {
            if !can_see_groups(hub, project, viewer, &stored_groups).await? {
                return Err(Error::not_found(format!("no embargo '{}'", rec.id)));
            }
            let stored_rec: EmbargoRecord =
                serde_json::from_str(&stored_json).map_err(|e| Error::Other(e.into()))?;
            if rec.groups() != stored_groups
                || rec.scope != stored_rec.scope
                || rec.until != stored_rec.until
                || rec.created != stored_rec.created
            {
                return Err(Error::bad_request(format!(
                    "embargo {} record conflicts with the stored embargo (scope, deadline, or creation time differs)",
                    rec.id
                )));
            }
        } else {
            if !pushed_eids.contains(&rec.id) {
                return Err(Error::not_found(format!("no embargo '{}'", rec.id)));
            }
            let groups = rec.groups();
            if groups.is_empty() {
                return Err(Error::bad_request("an embargo must name at least one group"));
            }
            let found: Vec<String> = sqlx::query_scalar("SELECT name FROM groups WHERE project_id = $1 AND name = ANY($2)")
                .bind(project.id)
                .bind(&groups)
                .fetch_all(&hub.db)
                .await?;
            for g in &groups {
                if !found.contains(g) {
                    return Err(Error::bad_request(format!("no group named '{g}' in this project")));
                }
            }
            if !can_see_groups(hub, project, viewer, &groups).await? {
                return Err(Error::forbidden(
                    "you must be an admin or a member of the embargo's group to push or release it",
                ));
            }
        }
        records_by_id.insert(rec.id.clone(), rec.clone());
        if rec.released_at.is_some() {
            releases.push((rec.id.clone(), rec.clone()));
        }
    }

    // 2. Check known (`real_of`) and new (`order`) snapshots for `n.embargo` or
    //    ancestry from an active embargo line.
    let mut snap_embargo: HashMap<ObjectId, String> = HashMap::new();
    let root = crate::sync::root_snapshot_id();
    for (pushed, real) in real_of {
        if *real == root {
            continue;
        }
        let eids = active_embargoes_of(hub, project.id, &[*real], &HashMap::new(), staged.clone()).await?;
        if eids.len() > 1 {
            return Err(Error::bad_request("a snapshot cannot combine multiple active embargoes"));
        }
        if let Some(eid) = eids.into_iter().next() {
            if !can_see(hub, project, viewer, &eid).await? {
                return Err(Error::bad_request(format!("snapshot {} was not uploaded", pushed.short())));
            }
            snap_embargo.insert(*pushed, eid);
        }
    }

    for id in order {
        let n = &parents_of[id];
        let mut parent_eid: Option<String> = None;
        for p in &n.parents {
            if let Some(pe) = snap_embargo.get(p) {
                if let Some(prev) = &parent_eid {
                    if prev != pe {
                        return Err(Error::bad_request("a snapshot cannot combine multiple active embargoes"));
                    }
                } else {
                    parent_eid = Some(pe.clone());
                }
            }
        }
        if let Some(eid) = &n.embargo {
            if eid.len() != 10 || !eid.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) {
                return Err(Error::bad_request("invalid embargo id on snapshot"));
            }
            if let Some(pe) = &parent_eid {
                if pe != eid {
                    return Err(Error::bad_request("a snapshot cannot combine multiple active embargoes"));
                }
            }
            // Must have a matching record validated in step 1 or already in `embargo_lines`
            // whose stored groups include the pusher.
            if !records_by_id.contains_key(eid) {
                let existing_groups: Option<Vec<String>> = sqlx::query_scalar(
                    "SELECT group_names FROM embargo_lines WHERE project_id = $1 AND embargo_id = $2",
                )
                .bind(project.id)
                .bind(eid)
                .fetch_optional(&hub.db)
                .await?;
                let authorized = match existing_groups {
                    Some(gs) => can_see_groups(hub, project, viewer, &gs).await?,
                    None => false,
                };
                if !authorized {
                    return Err(Error::bad_request(format!(
                        "snapshot {} carries embargo {}, which was not included in the push",
                        id.short(),
                        eid
                    )));
                }
            }
            snap_embargo.insert(*id, eid.clone());
        } else if let Some(eid) = parent_eid {
            snap_embargo.insert(*id, eid);
        }
    }

    // 3. Divert branch updates whose new tip is on an unreleased embargo line
    //    to `embargo/<id>`, and record the `LineUpsert` for each active embargo line.
    //    When `divert_branches` is false (`POST …/land`), ordinary branch names
    //    are not diverted here so `landing::stack` refuses them cleanly.
    let mut diverted: HashMap<String, String> = HashMap::new();
    for u in &mut req.updates {
        let explicit_eid = embargo_id_of_branch(&u.branch).map(|s| s.to_string());
        let tip_eid = u.new.and_then(|n| snap_embargo.get(&n).cloned());
        if let (Some(ex), Some(te)) = (&explicit_eid, &tip_eid) {
            if ex != te {
                return Err(Error::bad_request("a snapshot cannot combine multiple active embargoes"));
            }
        }
        if explicit_eid.is_none() && !divert_branches {
            continue;
        }
        let Some(eid) = explicit_eid.clone().or(tip_eid) else {
            continue;
        };
        // Check that the pusher can see or create this embargo.
        let existing_row: Option<(Vec<String>, String, Option<i64>, String)> = sqlx::query_as(
            "SELECT group_names, target_branch, released_at, record_json FROM embargo_lines WHERE project_id = $1 AND embargo_id = $2",
        )
        .bind(project.id)
        .bind(&eid)
        .fetch_optional(&hub.db)
        .await?;

        let (groups, target_branch, rec) = match (existing_row, records_by_id.get(&eid)) {
            (Some((groups, target, released_at, json)), _) => {
                if !can_see_groups(hub, project, viewer, &groups).await? {
                    return Err(Error::not_found(format!("no branch '{}'", u.branch)));
                }
                let rec = serde_json::from_str::<EmbargoRecord>(&json).map_err(|e| Error::Other(e.into()))?;
                let _ = released_at;
                (groups, target, rec)
            }
            (None, Some(rec)) => {
                let groups = rec.groups();
                let target = if explicit_eid.is_some() {
                    project.default_branch.clone()
                } else {
                    u.branch.clone()
                };
                let mut initial = rec.clone();
                initial.released_at = None;
                initial.state = None;
                initial.reason = None;
                (groups, target, initial)
            }
            (None, None) => {
                return Err(Error::not_found(format!("no branch '{}'", u.branch)));
            }
        };

        let ebranch = embargo_branch(&eid);
        if u.branch != ebranch {
            diverted.insert(ebranch.clone(), u.branch.clone());
            u.branch = ebranch.clone();
            // When diverting a push of `main` to `embargo/<id>`, `expected` was
            // for `main`, whereas `embargo/<id>` is either being created or updated.
            u.expected = None;
        }
        if !upserts.iter().any(|x| x.embargo_id == eid) {
            upserts.push(LineUpsert {
                embargo_id: eid.clone(),
                group_names: groups,
                target_branch,
                embargo_branch: ebranch,
                until_ms: rec.until,
                released_at: None,
                record_json: serde_json::to_string(&rec).unwrap_or_default(),
                created_by: pusher_key.to_string(),
                created_at: rec.created,
            });
        }
    }

    Ok((upserts, releases, diverted))
}

/// Write `embargo_lines`, `branches.hidden_for_embargo`, and `embargo_snapshots`
/// inside the push transaction.
pub(crate) async fn record_in_tx(
    c: &mut PgConnection,
    project_id: i64,
    upserts: &[LineUpsert],
    embargo_snaps: &[(String, String)],
) -> Result<()> {
    for u in upserts {
        let inserted = sqlx::query(
            "INSERT INTO embargo_lines (project_id, embargo_id, group_names, target_branch, embargo_branch, until_ms, released_at, record_json, created_by, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
             ON CONFLICT (project_id, embargo_id) DO NOTHING",
        )
        .bind(project_id)
        .bind(&u.embargo_id)
        .bind(&u.group_names)
        .bind(&u.target_branch)
        .bind(&u.embargo_branch)
        .bind(u.until_ms)
        .bind(u.released_at)
        .bind(&u.record_json)
        .bind(&u.created_by)
        .bind(u.created_at)
        .execute(&mut *c)
        .await?
        .rows_affected();

        if inserted == 0 {
            let cur_json: Option<String> = sqlx::query_scalar(
                "SELECT record_json FROM embargo_lines WHERE project_id = $1 AND embargo_id = $2 AND released_at IS NULL",
            )
            .bind(project_id)
            .bind(&u.embargo_id)
            .fetch_optional(&mut *c)
            .await?;
            if let Some(json) = cur_json {
                if let Ok(mut rec) = serde_json::from_str::<EmbargoRecord>(&json) {
                    if matches!(rec.state.as_deref(), Some("failed" | "waiting_for_approval")) {
                        rec.state = None;
                        rec.reason = None;
                        if let Ok(cleared) = serde_json::to_string(&rec) {
                            sqlx::query(
                                "UPDATE embargo_lines SET record_json = $1 WHERE project_id = $2 AND embargo_id = $3 AND released_at IS NULL",
                            )
                            .bind(cleared)
                            .bind(project_id)
                            .bind(&u.embargo_id)
                            .execute(&mut *c)
                            .await?;
                        }
                    }
                }
                // (The embargo's release tickets, of whatever tip: ids are hex, no LIKE wildcard.)
                let tickets = format!("embargo-{project_id}-{}-%", u.embargo_id);
                sqlx::query(
                    "DELETE FROM landing_queue WHERE project_id = $1 AND ticket LIKE $2 AND state NOT IN ('queued', 'merging', 'landed')",
                )
                .bind(project_id)
                .bind(tickets)
                .execute(&mut *c)
                .await?;
            }
        }

        sqlx::query("UPDATE branches SET hidden_for_embargo = $1 WHERE project_id = $2 AND name = $3")
            .bind(&u.embargo_id)
            .bind(project_id)
            .bind(&u.embargo_branch)
            .execute(&mut *c)
            .await?;
    }
    for (snap, eid) in embargo_snaps {
        sqlx::query("INSERT INTO embargo_snapshots (project_id, snapshot, embargo_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING")
            .bind(project_id)
            .bind(snap)
            .bind(eid)
            .execute(&mut *c)
            .await?;
    }
    Ok(())
}

/// How often a release that is stuck is tried again: one that failed (a
/// conflict waits for a member to rebase; a database error passes), or one
/// that waits for an approval (BUG-1857, BUG-1861). An approval tries it at
/// once ([`try_release_waiting`]), and a push to the line makes it fresh
/// (`record_in_tx`); this is for whatever else lets it through (a rule
/// change, a change of who is in a group). Seldom, so that embargoes left
/// stuck cost every server next to nothing.
const RETRY_STUCK: Duration = Duration::from_secs(30);

/// Background loop that releases embargoes at their deadlines
/// ([`release_due`]), and tries the stuck ones again every `RETRY_STUCK`.
pub async fn run_loop(hub: Arc<Hub>, mut stop: tokio::sync::watch::Receiver<bool>) {
    let mut check_db = true;
    let mut retry_at = tokio::time::Instant::now() + RETRY_STUCK;
    loop {
        let next_wait = if check_db {
            match next_waits(&hub).await {
                Ok((None, false)) => {
                    check_db = false;
                    None
                }
                Ok((fresh, stuck)) => {
                    let fresh = fresh.map(|ms| Duration::from_millis(ms.clamp(100, 1_000) as u64));
                    let stuck = stuck.then(|| {
                        retry_at
                            .saturating_duration_since(tokio::time::Instant::now())
                            .max(Duration::from_millis(100))
                    });
                    fresh.into_iter().chain(stuck).min()
                }
                Err(_) => Some(Duration::from_secs(1)),
            }
        } else {
            None
        };
        tokio::select! {
            _ = async {
                match next_wait {
                    Some(d) => tokio::time::sleep(d).await,
                    None => std::future::pending::<()>().await,
                }
            } => {
                let now = tokio::time::Instant::now();
                let stuck = now >= retry_at;
                if stuck {
                    retry_at = now + RETRY_STUCK;
                }
                let _ = release_pending(&hub, stuck).await;
            }
            _ = hub.embargo.wake.notified() => {
                check_db = true;
            }
            _ = stop.changed() => {
                if *stop.borrow() {
                    break;
                }
            }
        }
    }
}

/// Is the release recorded in `record_json` stuck (it failed, or it waits
/// for an approval)?
fn is_stuck(record_json: &str) -> bool {
    serde_json::from_str::<EmbargoRecord>(record_json).ok().and_then(|r| r.state).is_some()
}

/// What the release loop waits for: the milliseconds until the next deadline
/// of an embargo whose release is not stuck, and whether a stuck one is due.
async fn next_waits(hub: &Arc<Hub>) -> Result<(Option<i64>, bool)> {
    let rows: Vec<(i64, String)> = sqlx::query_as(
        "SELECT until_ms - (extract(epoch FROM clock_timestamp()) * 1000)::BIGINT, record_json FROM embargo_lines \
         WHERE released_at IS NULL AND until_ms IS NOT NULL",
    )
    .fetch_all(&hub.db)
    .await?;
    let mut fresh: Option<i64> = None;
    let mut stuck = false;
    for (ms, json) in rows {
        if !is_stuck(&json) {
            fresh = Some(fresh.map_or(ms, |f| f.min(ms)));
        } else if ms <= 0 {
            stuck = true;
        }
    }
    Ok((fresh, stuck))
}

pub(crate) fn failure_reason(e: &Error) -> String {
    match e {
        Error::Api { message, .. } => message.clone(),
        Error::Db(_) => "database error while releasing embargo; will retry".into(),
        Error::Other(_) => "internal error while releasing embargo".into(),
    }
}

/// Record on an unreleased embargo why its release did not happen (`state`
/// and `reason` of its record, which only its groups and admins read), or
/// clear it.
pub(crate) async fn record_embargo_status(
    hub: &Arc<Hub>,
    project_id: i64,
    embargo_id: &str,
    state: Option<&str>,
    reason: Option<&str>,
) -> Result<()> {
    record_embargo_status_inner(hub, project_id, embargo_id, state, reason, false).await
}

/// Hold an unapproved release onto a protected branch (BUG-1861): the
/// embargo stays unreleased and hidden, its record says
/// `waiting_for_approval` and why (to its groups and admins), and its
/// release is due from now on (`until_ms`: asked for early, or with no
/// deadline, it is still tried again and lands once it is approved).
pub(crate) async fn hold_embargo_for_approval(
    hub: &Arc<Hub>,
    project_id: i64,
    embargo_id: &str,
    reason: &str,
) -> Result<()> {
    record_embargo_status_inner(hub, project_id, embargo_id, Some("waiting_for_approval"), Some(reason), true).await
}

async fn record_embargo_status_inner(
    hub: &Arc<Hub>,
    project_id: i64,
    embargo_id: &str,
    state: Option<&str>,
    reason: Option<&str>,
    mark_due: bool,
) -> Result<()> {
    let cur: Option<(bool, String)> = sqlx::query_as(
        "SELECT (until_ms IS NOT NULL AND until_ms <= (extract(epoch FROM clock_timestamp()) * 1000)::BIGINT), record_json \
         FROM embargo_lines WHERE project_id = $1 AND embargo_id = $2 AND released_at IS NULL",
    )
    .bind(project_id)
    .bind(embargo_id)
    .fetch_optional(&hub.db)
    .await?;
    let Some((due, old_json)) = cur else {
        return Ok(());
    };
    let Ok(mut rec) = serde_json::from_str::<EmbargoRecord>(&old_json) else {
        return Ok(());
    };
    let new_state = state.map(str::to_string);
    let new_reason = reason.map(str::to_string);
    if rec.state == new_state && rec.reason == new_reason && (!mark_due || due) {
        return Ok(());
    }
    rec.state = new_state;
    rec.reason = new_reason;
    let Ok(new_json) = serde_json::to_string(&rec) else {
        return Ok(());
    };
    let notify = hub.caches.notices.load(Ordering::SeqCst);
    let eid = embargo_id.to_string();
    let changed = crate::db::transaction(&hub.db, crate::db::Isolation::ReadCommitted, move |c| {
        let new_json = new_json.clone();
        let eid = eid.clone();
        Box::pin(async move {
            // `mark_due`: the release was asked for, so it is due now.
            let n = sqlx::query(
                "UPDATE embargo_lines SET record_json = $1, \
                     until_ms = CASE WHEN $4 THEN LEAST(COALESCE(until_ms, (extract(epoch FROM clock_timestamp()) * 1000)::BIGINT), \
                                                        (extract(epoch FROM clock_timestamp()) * 1000)::BIGINT) \
                                     ELSE until_ms END \
                 WHERE project_id = $2 AND embargo_id = $3 AND released_at IS NULL",
            )
            .bind(&new_json)
            .bind(project_id)
            .bind(&eid)
            .bind(mark_due)
            .execute(&mut *c)
            .await?
            .rows_affected();
            if n > 0 && notify {
                sqlx::query("SELECT pg_notify($1, $2)")
                    .bind(crate::caches::TIPS_CHANNEL)
                    .bind(project_id.to_string())
                    .execute(&mut *c)
                    .await?;
            }
            Ok(n > 0)
        })
    })
    .await?;
    if changed {
        hub.caches.tips_changed(project_id);
        hub.embargo.wake();
    }
    Ok(())
}

/// Release `embargo_id` for the server (no person asks): `true` when this
/// call released it. A release that is not approved is held by
/// [`release_one`]; any other failure is recorded on the embargo (BUG-1857),
/// and the next one is tried all the same. A passing failure (the database,
/// not the release's own answer) never replaces what the embargo's groups
/// were told already (that it waits for an approval, or its conflict).
async fn release_for_server(hub: &Arc<Hub>, project_id: i64, embargo_id: &str) -> bool {
    match release_one(hub, project_id, embargo_id, None, None).await {
        Ok(released) => released,
        Err(Error::Api { code: "not_ready", .. }) => false,
        Err(e) => {
            let told: Option<String> =
                sqlx::query_scalar("SELECT record_json FROM embargo_lines WHERE project_id = $1 AND embargo_id = $2")
                    .bind(project_id)
                    .bind(embargo_id)
                    .fetch_optional(&hub.db)
                    .await
                    .ok()
                    .flatten();
            if matches!(e, Error::Api { .. }) || told.is_some_and(|json| !is_stuck(&json)) {
                let reason = failure_reason(&e);
                let _ = record_embargo_status(hub, project_id, embargo_id, Some("failed"), Some(&reason)).await;
            }
            false
        }
    }
}

/// Try the release of `embargo_id` again, if it is due (a held release is):
/// called when an approval of one of its PRs arrives, so that a release
/// that waited for it lands at once (BUG-1861).
pub(crate) async fn try_release_waiting(hub: &Arc<Hub>, project_id: i64, embargo_id: &str) {
    let due: Option<bool> = sqlx::query_scalar(
        "SELECT (until_ms IS NOT NULL AND until_ms <= (extract(epoch FROM clock_timestamp()) * 1000)::BIGINT) \
         FROM embargo_lines WHERE project_id = $1 AND embargo_id = $2 AND released_at IS NULL",
    )
    .bind(project_id)
    .bind(embargo_id)
    .fetch_optional(&hub.db)
    .await
    .ok()
    .flatten();
    if due == Some(true) {
        release_for_server(hub, project_id, embargo_id).await;
    }
}

/// [`try_release_waiting`] for every embargo of the project that is due: a
/// request for changes that held their paths was dismissed.
pub(crate) async fn try_release_waiting_in_project(hub: &Arc<Hub>, project_id: i64) {
    let ids: Vec<String> = sqlx::query_scalar(
        "SELECT embargo_id FROM embargo_lines WHERE project_id = $1 AND released_at IS NULL AND until_ms IS NOT NULL \
         AND until_ms <= (extract(epoch FROM clock_timestamp()) * 1000)::BIGINT ORDER BY until_ms, embargo_id",
    )
    .bind(project_id)
    .fetch_all(&hub.db)
    .await
    .unwrap_or_default();
    for eid in ids {
        release_for_server(hub, project_id, &eid).await;
    }
}

/// Is `branch` protected by the rules in force (`.veilrules` at the default
/// branch's tip)?
pub(crate) async fn is_protected_branch(
    hub: &Arc<Hub>,
    project_id: i64,
    default_branch: &str,
    branch: &str,
) -> Result<bool> {
    let tip_hex: Option<String> = sqlx::query_scalar(
        "SELECT target FROM branches WHERE project_id = $1 AND name = $2 AND hidden_for_embargo IS NULL",
    )
    .bind(project_id)
    .bind(default_branch)
    .fetch_optional(&hub.db)
    .await?;
    let default_tip = tip_hex.map(|h| ObjectId::from_hex(&h)).transpose().map_err(|e| Error::Other(e.into()))?;
    let b = branch.to_string();
    crate::sync::blocking(hub, project_id, move |src| {
        Ok(crate::landing::protected(src, default_tip)?.contains(&b))
    })
    .await
}

/// Who submits a release's landing of `stack` (the landing service lands
/// only what its submitter may write, and bounds their outstanding
/// landings): the person releasing, if they may write every path of it;
/// else the embargo's creator, if they still may; else an admin of the
/// project (the first). Also the viewer the review rules answer: the person
/// releasing, or at a deadline the creator.
pub(crate) async fn choose_submitter(
    hub: &Arc<Hub>,
    project: &Project,
    stack: &[crate::landing::Entry],
    creator: &(i64, String, String),
    manual: Option<(&Viewer, &crate::landing::Submitter)>,
) -> Result<(Viewer, crate::landing::Submitter)> {
    let paths = crate::prs::stack_touched_paths(hub, project.id, stack, None).await?;
    let may_submit = |v: &Viewer| project.participant(v) && (v.admin || crate::prs::review::writes_all(project, v, &paths));
    if let Some((v, sub)) = manual {
        if may_submit(v) {
            return Ok((v.clone(), sub.clone()));
        }
    }
    let creator_person = Person {
        id: creator.0,
        name: creator.1.clone(),
        device_key: creator.2.clone(),
        agent: None,
    };
    let (_, creator_viewer, creator_epochs) = perm::open_at(
        hub,
        &project.name,
        &Caller {
            person: Some(creator_person.clone()),
            epochs: crate::caches::Epochs::default(),
        },
    )
    .await?;
    let release_viewer = manual.map(|(v, _)| v.clone()).unwrap_or_else(|| creator_viewer.clone());
    if may_submit(&creator_viewer) {
        return Ok((
            release_viewer,
            crate::landing::Submitter {
                person: creator_person,
                epochs: creator_epochs,
            },
        ));
    }
    let (admin_id, admin_name, admin_key): (i64, String, String) = sqlx::query_as(
        "SELECT p.id, p.name, COALESCE((SELECT d.signing_key FROM devices d WHERE d.person_id = p.id AND d.removed_at IS NULL \
                                        ORDER BY d.signing_key LIMIT 1), '') \
         FROM project_admins a JOIN people p ON p.id = a.person_id WHERE a.project_id = $1 ORDER BY p.id LIMIT 1",
    )
    .bind(project.id)
    .fetch_one(&hub.db)
    .await?;
    let admin_person = Person {
        id: admin_id,
        name: admin_name,
        device_key: admin_key,
        agent: None,
    };
    let (_, _, admin_epochs) = perm::open_at(
        hub,
        &project.name,
        &Caller {
            person: Some(admin_person.clone()),
            epochs: crate::caches::Epochs::default(),
        },
    )
    .await?;
    Ok((
        release_viewer,
        crate::landing::Submitter {
            person: admin_person,
            epochs: admin_epochs,
        },
    ))
}

/// A release's landing ticket, whoever queued it: its submitter and its
/// state.
pub(crate) async fn read_embargo_ticket(
    hub: &Hub,
    project_id: i64,
    ticket: &str,
) -> Result<Option<(i64, veil_core::hub::land::LandResult)>> {
    let row: Option<(i64, String, Option<String>, i64)> = sqlx::query_as(
        "SELECT person_id, state, result, merges FROM landing_queue WHERE ticket = $1 AND project_id = $2",
    )
    .bind(ticket)
    .bind(project_id)
    .fetch_optional(&hub.db)
    .await?;
    let Some((person_id, state, result, merges)) = row else {
        return Ok(None);
    };
    let r = match (state.as_str(), result) {
        ("queued" | "merging", _) | (_, None) => {
            let mut q = crate::landing::queued(ticket);
            q.merges = merges as u32;
            q
        }
        (_, Some(r)) => serde_json::from_str(&r).map_err(|e| Error::Other(e.into()))?,
    };
    Ok(Some((person_id, r)))
}

/// Queue a release's landing of `judged` on `branch` under the deterministic
/// `ticket` (once, whichever server or retry asks: the embargo's row is
/// locked while the ticket is looked for), through `landing::insert` like
/// every landing (its submitter's outstanding-landing bounds, S24), and wait
/// for the landing service (S17). A ticket that failed is queued again only
/// when a person asks (`manual_retry`); a push to the line removes it
/// (`record_in_tx`). `gc_epoch`: the project's GC epoch as read before
/// `judged` was computed (BUG-1881).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn queue_and_wait_embargo_landing(
    hub: &Arc<Hub>,
    project: &Project,
    embargo_id: &str,
    ticket: &str,
    branch: &str,
    judged: crate::landing::Judged,
    who: &crate::landing::Submitter,
    manual_retry: bool,
    gc_epoch: i64,
) -> Result<veil_core::hub::land::LandResult> {
    let existing = read_embargo_ticket(hub, project.id, ticket).await?;
    let need_queue = match &existing {
        None => true,
        Some((_, r)) => manual_retry && !matches!(r.state, LandState::Queued | LandState::Landed),
    };
    if need_queue && !judged.stack.is_empty() {
        let q = crate::landing::Queued {
            ticket: ticket.to_string(),
            branch: branch.to_string(),
            stack: judged.stack,
            lineage: judged.lineage,
            skipped: Arc::new(std::sync::Mutex::new(judged.skipped)),
        };
        let pid = project.id;
        let eid = embargo_id.to_string();
        let who2 = who.clone();
        crate::db::transaction(&hub.db, crate::db::Isolation::ReadCommitted, move |c| {
            let eid = eid.clone();
            let q = q.clone();
            let who2 = who2.clone();
            Box::pin(async move {
                // The queue row holds the stack's snapshots (roots): in line
                // with GC's switch before any other lock (BUG-1881).
                crate::pack_gc::guard_root_write(&mut *c, pid, gc_epoch).await?;
                let unreleased: Option<bool> = sqlx::query_scalar(
                    "SELECT released_at IS NULL FROM embargo_lines WHERE project_id = $1 AND embargo_id = $2 FOR UPDATE",
                )
                .bind(pid)
                .bind(&eid)
                .fetch_optional(&mut *c)
                .await?;
                if unreleased != Some(true) {
                    return Ok(());
                }
                if manual_retry {
                    sqlx::query(
                        "DELETE FROM landing_queue WHERE project_id = $1 AND ticket = $2 AND state NOT IN ('queued', 'merging', 'landed')",
                    )
                    .bind(pid)
                    .bind(&q.ticket)
                    .execute(&mut *c)
                    .await?;
                }
                let already: Option<i32> = sqlx::query_scalar("SELECT 1 FROM landing_queue WHERE project_id = $1 AND ticket = $2")
                    .bind(pid)
                    .bind(&q.ticket)
                    .fetch_optional(&mut *c)
                    .await?;
                if already.is_none() {
                    crate::landing::insert(&mut *c, pid, &who2, &q).await?;
                }
                Ok(())
            })
        })
        .await?;
    }

    let w = hub.landing.register(ticket);
    match read_embargo_ticket(hub, project.id, ticket).await {
        Ok(Some((q_person, cur))) if cur.state == LandState::Queued => {
            crate::limits::leave_gates();
            crate::landing::ensure(hub, project.id, branch);
            let deadline = tokio::time::Instant::now() + crate::landing::WAIT;
            crate::landing::wait(hub, project.id, q_person, branch, w, deadline).await
        }
        Ok(Some((_, cur))) => {
            crate::landing::abandon(hub, w);
            Ok(cur)
        }
        // No ticket: nothing was left to land, or another server released
        // the embargo meanwhile (the release's last step finds out which).
        Ok(None) => {
            crate::landing::abandon(hub, w);
            let mut r = crate::landing::queued(ticket);
            r.state = LandState::Landed;
            Ok(r)
        }
        Err(e) => {
            crate::landing::abandon(hub, w);
            Err(e)
        }
    }
}

/// Release every embargo across all projects whose `until_ms` has arrived
/// according to PostgreSQL's `clock_timestamp()`, each on its own: one that
/// fails, or waits for an approval, keeps no other from its deadline
/// (BUG-1857).
///
/// Using the database clock (`clock_timestamp()`) guarantees that app-server
/// clock skew never releases an embargo early or late, and survives restarts
/// and multiple servers.
pub async fn release_due(hub: &Arc<Hub>) -> Result<usize> {
    release_pending(hub, true).await
}

/// [`release_due`]; with `stuck` false, only the embargoes whose release is
/// not stuck (the release loop tries the stuck ones every [`RETRY_STUCK`],
/// not at every tick).
async fn release_pending(hub: &Arc<Hub>, stuck: bool) -> Result<usize> {
    let due: Vec<(i64, String, String)> = sqlx::query_as(
        "SELECT project_id, embargo_id, record_json FROM embargo_lines \
         WHERE released_at IS NULL AND until_ms IS NOT NULL \
         AND until_ms <= (extract(epoch FROM clock_timestamp()) * 1000)::BIGINT \
         ORDER BY until_ms, project_id, embargo_id",
    )
    .fetch_all(&hub.db)
    .await?;
    // The fresh ones first, each in the order of its deadline: a stuck one
    // never delays a deadline.
    let (fresh, old): (Vec<_>, Vec<_>) = due.into_iter().partition(|(_, _, json)| !is_stuck(json));
    let due: Vec<(i64, String)> = fresh.into_iter().chain(old.into_iter().filter(|_| stuck)).map(|(p, e, _)| (p, e)).collect();

    if due.is_empty() {
        return Ok(0);
    }

    // Failure injection for testing retried release jobs (Guarantee 2).
    let mut injected = false;
    loop {
        let n = hub.embargo.fail_next.load(Ordering::SeqCst);
        if n == 0 {
            break;
        }
        if hub.embargo.fail_next.compare_exchange(n, n - 1, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
            injected = true;
            break;
        }
    }
    if injected {
        hub.embargo.retried_failures.fetch_add(1, Ordering::SeqCst);
        return Err(Error::Other(anyhow::anyhow!("injected release job failure")));
    }

    let mut released = 0;
    for (project_id, embargo_id) in due {
        if release_for_server(hub, project_id, &embargo_id).await {
            released += 1;
        }
    }
    Ok(released)
}

/// Release one embargo `embargo_id` in `project_id`, for the person
/// `submitter` (an early release) or for the server (its deadline):
///
/// 1. **Land the line.** The changes on `embargo/<id>` land on
///    `target_branch` through the landing service (S17), under one
///    deterministic ticket per tip of the line, whatever PRs the embargo has
///    and whatever their state (BUG-1875: the line is never dropped without
///    landing). Onto a
///    protected branch the landing meets S21's review rules like every
///    landing, and the approvals of the embargo's own PR count (BUG-1861):
///    unapproved, the release is **held** (`hold_embargo_for_approval`) and
///    this answers `409 not_ready`; nothing lands and nothing turns public.
/// 2. **Finish** (`prs::embargo::finish_release`): the embargo's PRs that
///    are armed and ready land too, and in one transaction `released_at` is
///    set, its PRs become ordinary, and the hidden line and the embargo's
///    snapshot rows go (the line only at the tip that landed).
///
/// `Ok(true)` when this call released it; `Ok(false)` when it was released
/// already (or by another server meanwhile).
pub async fn release_one(
    hub: &Arc<Hub>,
    project_id: i64,
    embargo_id: &str,
    pushed_record: Option<EmbargoRecord>,
    submitter: Option<(&Viewer, &crate::landing::Submitter)>,
) -> Result<bool> {
    loop {
        match release_one_once(hub, project_id, embargo_id, pushed_record.clone(), submitter).await {
            Err(e) if crate::pack_gc::is_gc_epoch_changed(&e) => {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            other => return other,
        }
    }
}

async fn release_one_once(
    hub: &Arc<Hub>,
    project_id: i64,
    embargo_id: &str,
    pushed_record: Option<EmbargoRecord>,
    submitter: Option<(&Viewer, &crate::landing::Submitter)>,
) -> Result<bool> {
    let gc_epoch = crate::pack_gc::read_gc_epoch(hub, project_id).await?;
    type Line = (Vec<String>, String, String, Option<i64>, String, String);
    let row: Option<Line> = sqlx::query_as(
        "SELECT group_names, target_branch, embargo_branch, released_at, record_json, created_by \
         FROM embargo_lines WHERE project_id = $1 AND embargo_id = $2",
    )
    .bind(project_id)
    .bind(embargo_id)
    .fetch_optional(&hub.db)
    .await?;
    let Some((group_names, target_branch, ebranch, released_at, record_json, created_by)) = row else {
        return Ok(false);
    };
    if released_at.is_some() {
        return Ok(false);
    }

    let mut c = hub.db.acquire().await?;
    let pname: String = sqlx::query_scalar("SELECT name FROM projects WHERE id = $1")
        .bind(project_id)
        .fetch_one(&mut *c)
        .await?;
    let Some(project) = perm::load_project(&mut c, &pname).await? else {
        return Ok(false);
    };
    if let Some((v, _)) = submitter {
        if !can_see_groups(hub, &project, v, &group_names).await? {
            return Err(Error::not_found(format!("no embargo '{embargo_id}'")));
        }
    }
    let etip: Option<String> = sqlx::query_scalar("SELECT target FROM branches WHERE project_id = $1 AND name = $2")
        .bind(project_id)
        .bind(&ebranch)
        .fetch_optional(&mut *c)
        .await?;

    // The embargo's creator (the person whose device pushed it), or the
    // project's first admin when that device is gone.
    let signer: Option<(i64, String, String)> = sqlx::query_as(
        "SELECT p.id, p.name, d.signing_key FROM devices d JOIN people p ON p.id = d.person_id \
         WHERE d.signing_key = $1 AND d.removed_at IS NULL LIMIT 1",
    )
    .bind(&created_by)
    .fetch_optional(&mut *c)
    .await?;
    let creator: (i64, String, String) = match signer {
        Some(s) => s,
        None => {
            sqlx::query_as(
                "SELECT p.id, p.name, COALESCE((SELECT d.signing_key FROM devices d WHERE d.person_id = p.id ORDER BY d.signing_key LIMIT 1), '') \
                 FROM project_admins a JOIN people p ON p.id = a.person_id WHERE a.project_id = $1 ORDER BY p.id LIMIT 1",
            )
            .bind(project_id)
            .fetch_one(&mut *c)
            .await?
        }
    };
    drop(c);

    // S11: an agent session releases only what its narrowing covers.
    if let Some((v, _)) = submitter {
        crate::prs::embargo::agent_may_release(hub, &project, embargo_id, v).await?;
    }

    let admin_viewer = Viewer {
        person: Some(creator.0),
        admin: true,
        groups: HashSet::new(),
        only: None,
        agent: false,
    };
    let manual = submitter.is_some() || pushed_record.is_some();

    // 1. Land the line.
    if let Some(etip_hex) = &etip {
        let etip_id = ObjectId::from_hex(etip_hex).map_err(|e| Error::Other(e.into()))?;
        let mut judged = match crate::landing::stack_for_embargo(
            hub,
            &project,
            &admin_viewer,
            &target_branch,
            etip_id,
            &HashMap::new(),
            None,
            Some(embargo_id),
        )
        .await?
        {
            Ok(j) if j.branch => j,
            Ok(_) => {
                let why = format!("target branch '{target_branch}' does not exist");
                let _ = record_embargo_status(hub, project_id, embargo_id, Some("failed"), Some(&why)).await;
                return Err(Error::conflict(why));
            }
            Err(why) => {
                let _ = record_embargo_status(hub, project_id, embargo_id, Some("failed"), Some(&why)).await;
                return Err(Error::conflict(why));
            }
        };
        // S11's agent rule (`agent_stack`) applies when an agent session asks for release.
        if let Some((v, _)) = submitter {
            crate::landing::agent_stack(hub, &project, v, &target_branch, &judged, etip_id, false, None).await?;
        }
        if !judged.stack.is_empty() {
            let (release_viewer, who) = choose_submitter(hub, &project, &judged.stack, &creator, submitter).await?;
            // The review rules of a protected branch (BUG-1861); on any branch,
            // a change the server reverted twice needs a person (BUG-1884).
            let protected = is_protected_branch(hub, project_id, &project.default_branch, &target_branch).await?;
            let waits = |message: &str| {
                Error::new(
                    axum::http::StatusCode::CONFLICT,
                    "not_ready",
                    veil_core::embargo::held_release_warning(embargo_id, message),
                )
            };
            match crate::prs::check_landing_review_for_embargo(
                hub,
                &project,
                &release_viewer,
                &target_branch,
                &judged.stack,
                None,
                protected,
                Some(embargo_id),
            )
            .await
            {
                // What the landing batch checks again in its own transaction
                // (BUG-1880): this embargo's PRs may carry the approvals.
                Ok(claim) => {
                    if let (Some(first), Some(claim)) = (judged.stack.first_mut(), claim) {
                        first.review = Some(claim);
                    }
                }
                Err(e) => {
                    let Error::Api { code: "not_ready", message, .. } = &e else {
                        return Err(e);
                    };
                    let _ = hold_embargo_for_approval(hub, project_id, embargo_id, message).await;
                    return Err(waits(message));
                }
            }
            // One ticket per tip of the line: servers and retries that land the
            // same tip share it, and a ticket that landed an earlier tip never
            // stands in for commits pushed to the line since (BUG-1875).
            let ticket = format!("embargo-{project_id}-{embargo_id}-{}", &etip_hex[..16]);
            let outcome =
                queue_and_wait_embargo_landing(hub, &project, embargo_id, &ticket, &target_branch, judged, &who, manual, gc_epoch).await?;
            if outcome.state != LandState::Landed {
                let msg = outcome
                    .message
                    .unwrap_or_else(|| "embargo release landing did not complete".into());
                // The batch refused it under the review rules: an approval was
                // withdrawn while it was queued (BUG-1880). It waits for
                // approval as a release refused before queueing does, and the
                // refused ticket goes, so that the approval queues it again.
                if outcome.state == LandState::Rejected && msg.starts_with(crate::prs::NOT_READY) {
                    sqlx::query("DELETE FROM landing_queue WHERE project_id = $1 AND ticket = $2 AND state NOT IN ('queued', 'merging', 'landed')")
                        .bind(project_id)
                        .bind(&ticket)
                        .execute(&hub.db)
                        .await?;
                    let _ = hold_embargo_for_approval(hub, project_id, embargo_id, &msg).await;
                    return Err(waits(&msg));
                }
                let _ = record_embargo_status(hub, project_id, embargo_id, Some("failed"), Some(&msg)).await;
                return Err(Error::conflict(msg));
            }
        }
    }

    // 2. Finish: the embargo's PRs, `released_at`, the hidden line.
    crate::prs::embargo::finish_release(
        hub,
        &project,
        embargo_id,
        &target_branch,
        &ebranch,
        etip.as_deref(),
        &creator,
        pushed_record,
        &record_json,
        submitter,
    )
    .await
}

/// `POST /v1/projects/{p}/embargoes/{id}/release`: early release of an embargo
/// by a member of its groups or an admin. Outsiders receive 404 (not found),
/// identical to a non-existent embargo id.
pub async fn release_route(
    AxumState(hub): AxumState<HubState>,
    caller: Caller,
    Path((p, id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>> {
    // A release lands: never by a CI runner session (S19, merge of S22).
    let person = caller.not_runner()?.clone();
    let (project, viewer) = perm::open(&hub, &p, &caller).await?;
    let not_found = || Error::not_found(format!("no embargo '{id}'"));
    if id.len() != 10 || !id.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) {
        return Err(not_found());
    }
    if !can_see(&hub, &project, &viewer, &id).await? {
        return Err(not_found());
    }
    let who = crate::landing::Submitter {
        person,
        epochs: caller.epochs,
    };
    release_one(&hub, project.id, &id, None, Some((&viewer, &who))).await?;
    Ok(Json(serde_json::json!({ "id": id, "released": true })))
}
