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

/// Does `viewer` belong to at least one of `group_names` in `project` (or is
/// `viewer` an admin of `project`)?
pub async fn can_see_groups(hub: &Hub, project: &Project, viewer: &Viewer, group_names: &[String]) -> Result<bool> {
    if viewer.admin {
        return Ok(true);
    }
    if viewer.groups.is_empty() || group_names.is_empty() {
        return Ok(false);
    }
    for g in group_names {
        if let Some(Binding::Group(gid)) = project.bindings.get(g) {
            if viewer.groups.contains(gid) {
                return Ok(true);
            }
        }
    }
    let gids: Vec<i64> = sqlx::query_scalar("SELECT id FROM groups WHERE project_id = $1 AND name = ANY($2)")
        .bind(project.id)
        .bind(group_names)
        .fetch_all(&hub.db)
        .await?;
    Ok(gids.into_iter().any(|gid| viewer.groups.contains(&gid)))
}

/// Can `viewer` see the embargo `embargo_id` in `project`?
pub async fn can_see(hub: &Hub, project: &Project, viewer: &Viewer, embargo_id: &str) -> Result<bool> {
    if viewer.admin {
        return Ok(true);
    }
    let row: Option<(Vec<String>, Option<i64>)> =
        sqlx::query_as("SELECT group_names, released_at FROM embargo_lines WHERE project_id = $1 AND embargo_id = $2")
            .bind(project.id)
            .bind(embargo_id)
            .fetch_optional(&hub.db)
            .await?;
    let Some((groups, released_at)) = row else {
        return Ok(false);
    };
    if released_at.is_some() {
        return Ok(true);
    }
    can_see_groups(hub, project, viewer, &groups).await
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
        sqlx::query(
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
        .await?;

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

/// Background loop that periodically runs [`release_due`].
pub async fn run_loop(hub: Arc<Hub>, mut stop: tokio::sync::watch::Receiver<bool>) {
    let mut check_db = true;
    loop {
        let next_wait = if check_db {
            match next_due_wait_ms(&hub).await {
                Ok(Some(ms)) => Some(Duration::from_millis(ms.clamp(100, 1_000) as u64)),
                Ok(None) => {
                    check_db = false;
                    None
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
                let _ = release_due(&hub).await;
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

async fn next_due_wait_ms(hub: &Arc<Hub>) -> Result<Option<i64>> {
    let ms: Option<i64> = sqlx::query_scalar(
        "SELECT MIN(until_ms) - (extract(epoch FROM clock_timestamp()) * 1000)::BIGINT \
         FROM embargo_lines WHERE released_at IS NULL AND until_ms IS NOT NULL",
    )
    .fetch_optional(&hub.db)
    .await?
    .flatten();
    if ms.is_some_and(|m| m <= 0) {
        let _ = release_due(hub).await;
        return Ok(Some(250));
    }
    Ok(ms)
}

/// Release every embargo across all projects whose `until_ms` has arrived
/// according to PostgreSQL's `clock_timestamp()`.
///
/// Using the database clock (`clock_timestamp()`) guarantees that app-server
/// clock skew never releases an embargo early or late, and survives restarts
/// and multiple servers.
pub async fn release_due(hub: &Arc<Hub>) -> Result<usize> {
    let due: Vec<(i64, String)> = sqlx::query_as(
        "SELECT project_id, embargo_id FROM embargo_lines \
         WHERE released_at IS NULL AND until_ms IS NOT NULL \
         AND until_ms <= (extract(epoch FROM clock_timestamp()) * 1000)::BIGINT \
         ORDER BY until_ms, project_id, embargo_id",
    )
    .fetch_all(&hub.db)
    .await?;

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
        if release_one(hub, project_id, &embargo_id, None, None).await? {
            released += 1;
        }
    }
    Ok(released)
}

/// Release one embargo `embargo_id` in `project_id`: land the commits on
/// `embargo/<id>` onto `target_branch` (`main`) once via the landing service,
/// mark `embargo_lines.released_at`, remove the hidden `embargo/<id>` branch,
/// and clear `embargo_snapshots`.
pub async fn release_one(
    hub: &Arc<Hub>,
    project_id: i64,
    embargo_id: &str,
    pushed_record: Option<EmbargoRecord>,
    agent_viewer: Option<&Viewer>,
) -> Result<bool> {
    let row: Option<(Vec<String>, String, String, Option<i64>, String, String, bool)> = sqlx::query_as(
        "SELECT group_names, target_branch, embargo_branch, released_at, record_json, created_by, \
                (has_pr OR EXISTS (SELECT 1 FROM prs WHERE project_id = $1 AND embargo = $2)) \
         FROM embargo_lines WHERE project_id = $1 AND embargo_id = $2",
    )
    .bind(project_id)
    .bind(embargo_id)
    .fetch_optional(&hub.db)
    .await?;
    let Some((group_names, target_branch, ebranch, released_at, record_json, created_by, has_pr)) = row else {
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
    if let Some(v) = agent_viewer {
        if !can_see_groups(hub, &project, v, &group_names).await? {
            return Err(Error::not_found(format!("no embargo '{embargo_id}'")));
        }
    }
    let etip: Option<String> = sqlx::query_scalar("SELECT target FROM branches WHERE project_id = $1 AND name = $2")
        .bind(project_id)
        .bind(&ebranch)
        .fetch_optional(&mut *c)
        .await?;

    // Find the submitter (the device/person who created the embargo, or a project admin).
    let signer: Option<(i64, String, String)> = sqlx::query_as(
        "SELECT p.id, p.name, d.signing_key FROM devices d JOIN people p ON p.id = d.person_id \
         WHERE d.signing_key = $1 AND d.removed_at IS NULL LIMIT 1",
    )
    .bind(&created_by)
    .fetch_optional(&mut *c)
    .await?;
    let (person_id, person_name, device_key) = match signer {
        Some(s) => s,
        None => {
            sqlx::query_as(
                "SELECT p.id, p.name, COALESCE((SELECT d.signing_key FROM devices d WHERE d.person_id = p.id LIMIT 1), '') \
                 FROM project_admins a JOIN people p ON p.id = a.person_id WHERE a.project_id = $1 LIMIT 1",
            )
            .bind(project_id)
            .fetch_one(&mut *c)
            .await?
        }
    };
    drop(c);

    if has_pr {
        return crate::prs::embargo::release_embargo_prs(
            hub,
            &project,
            embargo_id,
            &target_branch,
            &ebranch,
            person_id,
            &person_name,
            &device_key,
            pushed_record,
            &record_json,
            agent_viewer,
        )
        .await;
    }

    let admin_viewer = Viewer {
        person: Some(person_id),
        admin: true,
        groups: HashSet::new(),
        only: None,
        agent: false,
    };

    // Deterministic ticket so concurrent servers / retries queue the embargo landing at most once!
    let ticket = format!("embargo-{project_id}-{embargo_id}");
    if let Some(etip_hex) = etip {
        let etip_id = ObjectId::from_hex(&etip_hex).map_err(|e| Error::Other(e.into()))?;
        let existing_outcome = crate::landing::read(hub, project_id, person_id, &ticket).await?;
        let need_queue = existing_outcome.is_none();
        if need_queue || agent_viewer.is_some_and(|v| v.agent) {
            let judged = match crate::landing::stack_for_embargo(hub, &project, &admin_viewer, &target_branch, etip_id, &HashMap::new(), None, Some(embargo_id)).await? {
                Ok(j) => j,
                Err(why) => return Err(Error::conflict(why)),
            };
            // S11's agent rule (`agent_stack`) applies when an agent session asks for release.
            if let Some(v) = agent_viewer {
                crate::landing::agent_stack(hub, &project, v, &target_branch, &judged, etip_id, false, None).await?;
            }
            if need_queue && !judged.stack.is_empty() {
                let (_, _, epochs) = perm::open_at(
                    hub,
                    &pname,
                    &Caller {
                        person: Some(Person {
                            id: person_id,
                            name: person_name.clone(),
                            device_key: device_key.clone(),
                            agent: None,
                        }),
                        epochs: crate::caches::Epochs::default(),
                    },
                )
                .await?;
                let who = crate::landing::Submitter {
                    person: Person {
                        id: person_id,
                        name: person_name.clone(),
                        device_key: device_key.clone(),
                        agent: None,
                    },
                    epochs,
                };
                let q = crate::landing::Queued {
                    ticket: ticket.clone(),
                    branch: target_branch.clone(),
                    stack: judged.stack,
                    lineage: judged.lineage,
                    skipped: Arc::new(std::sync::Mutex::new(judged.skipped)),
                };
                sqlx::query(
                    "INSERT INTO landing_queue (project_id, branch, ticket, person_id, person_name, device_key, stack, lineage, person_epoch, \
                     project_epoch, state, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'queued', \
                     (extract(epoch FROM clock_timestamp()) * 1000000)::BIGINT) ON CONFLICT (ticket) DO NOTHING",
                )
                .bind(project_id)
                .bind(&q.branch)
                .bind(&q.ticket)
                .bind(who.person.id)
                .bind(&who.person.name)
                .bind(&who.person.device_key)
                .bind(crate::landing::encode_stack(&q.stack))
                .bind(q.lineage)
                .bind(who.epochs.person)
                .bind(who.epochs.project.map_or(0, |(_, e)| e))
                .execute(&hub.db)
                .await?;
            }
        }

        // If `ticket` is in `landing_queue`, ensure the landing service runs and wait for it.
        let w = hub.landing.register(&ticket);
        if let Some((_, cur)) = crate::landing::read(hub, project_id, person_id, &ticket).await? {
            let outcome = if cur.state == LandState::Queued {
                crate::limits::leave_gates();
                crate::landing::ensure(hub, project_id, &target_branch);
                let deadline = tokio::time::Instant::now() + crate::landing::WAIT;
                crate::landing::wait(hub, project_id, person_id, &target_branch, w, deadline).await?
            } else {
                crate::landing::abandon(hub, w);
                cur
            };
            if outcome.state != LandState::Landed {
                return Err(Error::conflict(
                    outcome.message.unwrap_or_else(|| "embargo release landing did not complete".into()),
                ));
            }
        } else {
            crate::landing::abandon(hub, w);
        }
    }

    // Finalize the release in one transaction: set `released_at`, update `record_json`,
    // delete `embargo/<id>` from `branches`, and delete its `embargo_snapshots`.
    let now_ms: i64 = sqlx::query_scalar("SELECT (extract(epoch FROM clock_timestamp()) * 1000)::BIGINT")
        .fetch_one(&hub.db)
        .await?;
    let mut rec: EmbargoRecord = serde_json::from_str(&record_json).map_err(|e| Error::Other(e.into()))?;
    rec.released_at = Some(pushed_record.and_then(|r| r.released_at).unwrap_or(now_ms));
    let new_json = serde_json::to_string(&rec).unwrap_or(record_json);
    let eid = embargo_id.to_string();
    let ebranch2 = ebranch.clone();
    let notify = hub.caches.notices.load(Ordering::SeqCst);

    let updated = crate::db::transaction(&hub.db, crate::db::Isolation::ReadCommitted, move |c| {
        let eid = eid.clone();
        let ebranch2 = ebranch2.clone();
        let new_json = new_json.clone();
        Box::pin(async move {
            let n = sqlx::query(
                "UPDATE embargo_lines SET released_at = COALESCE(released_at, $1), record_json = $2 \
                 WHERE project_id = $3 AND embargo_id = $4 AND released_at IS NULL",
            )
            .bind(now_ms)
            .bind(&new_json)
            .bind(project_id)
            .bind(&eid)
            .execute(&mut *c)
            .await?
            .rows_affected();
            sqlx::query("DELETE FROM branches WHERE project_id = $1 AND name = $2")
                .bind(project_id)
                .bind(&ebranch2)
                .execute(&mut *c)
                .await?;
            sqlx::query("DELETE FROM embargo_snapshots WHERE project_id = $1 AND embargo_id = $2")
                .bind(project_id)
                .bind(&eid)
                .execute(&mut *c)
                .await?;
            if notify {
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

    hub.caches.tips_changed(project_id);
    crate::derive::landed(hub, project_id, vec![target_branch]);
    if updated {
        crate::events::emit_embargo_released(hub, project_id, embargo_id).await;
    }
    Ok(updated)
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
    caller.not_runner()?;
    let (project, viewer) = perm::open(&hub, &p, &caller).await?;
    let not_found = || Error::not_found(format!("no embargo '{id}'"));
    if id.len() != 10 || !id.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) {
        return Err(not_found());
    }
    if !can_see(&hub, &project, &viewer, &id).await? {
        return Err(not_found());
    }
    release_one(&hub, project.id, &id, None, Some(&viewer)).await?;
    Ok(Json(serde_json::json!({ "id": id, "released": true })))
}
