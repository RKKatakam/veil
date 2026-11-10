//! Embargoed PRs (milestone S23; `docs/HUB.md` §13.38;
//! `docs/design/server/phase-4-agent-scale.md` §4.9, decision 8, §8).
//!
//! * **Permission-based, never encrypted**: an embargoed PR's class hashes
//!   `(policy_key, deciding_lines, embargo_id)`. Only project admins and
//!   members of the embargo's groups who also read every touched path satisfy
//!   the class; to everyone else it reads as `404` on every route.
//! * **Zero derived-index footprint before release**: revisions, projections,
//!   and diffs of an unreleased embargoed PR are computed directly over real
//!   snapshots and `Projector` (`sync::projected`, `Trees::root`) without
//!   touching `view_graph`, `view_changes`, `file_history`, `search`, or
//!   public `pr_holds`.
//! * **Release and land-at-release**: when `embargo::release_one` fires, PRs
//!   with `land_at_release = true` whose S21 review gate is ready land once
//!   onto the target branch via S17 (`embargo-pr-<project>-<pr>`); all PRs of
//!   the embargo then move to their plain (`embargo = ''`) visibility class
//!   in the release transaction.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    sync::{atomic::Ordering, Arc},
    time::Instant,
};

use axum::http::StatusCode;
use serde_json::{json, Value};
use veil_core::{
    hub::land::LandState,
    keychain::EmbargoRecord,
    object::EntryKind,
    ChangeId, ObjectId,
};

use super::{
    class, review,
    revision::{self, Computed, StackChange, MAX_PATHS, MAX_STACK, NOTHING_TO_REVIEW},
    rules::{classify, FileChange, Review, Risk},
    state, PrRow, DEADLINE,
};
use crate::{
    auth::{Caller, Person},
    db::{transaction, Isolation},
    derive::changes,
    error::{Error, Result},
    perm::{self, Project, Viewer},
    query::{
        self,
        graph::{blocking, ensure, G},
        trees::{DiffLimits, Trees},
        Ask,
    },
    Hub,
};

/// All server `embargo_id`s in `project` that `viewer` may currently see.
pub async fn visible_embargoes(hub: &Hub, project: &Project, viewer: &Viewer) -> Result<HashSet<String>> {
    let rows: Vec<(String, Vec<String>, Option<i64>)> = sqlx::query_as(
        "SELECT embargo_id, group_names, released_at FROM embargo_lines WHERE project_id = $1",
    )
    .bind(project.id)
    .fetch_all(&hub.db)
    .await?;
    let mut out = HashSet::new();
    for (eid, groups, released_at) in rows {
        if viewer.admin
            || released_at.is_some()
            || crate::embargo::can_see_groups(hub, project, viewer, &groups).await?
        {
            out.insert(eid);
        }
    }
    Ok(out)
}

/// Resolve target branch `onto` for `ask`, returning `(real_onto_tip, onto_embargo_id)`.
/// Outsiders naming a hidden `embargo/<id>` branch receive the exact `404` of a
/// missing branch.
pub async fn resolve_onto(
    hub: &Arc<Hub>,
    ask: &Ask,
    onto: &str,
    deadline: Instant,
) -> Result<(ObjectId, Option<String>)> {
    let not_found = || Error::not_found("no such revision that you can see");
    let hidden: Option<(String, String)> = sqlx::query_as(
        "SELECT b.target, b.hidden_for_embargo \
         FROM branches b JOIN embargo_lines l \
           ON l.project_id = b.project_id AND l.embargo_id = b.hidden_for_embargo \
         WHERE b.project_id = $1 AND b.name = $2 AND b.hidden_for_embargo IS NOT NULL AND l.released_at IS NULL",
    )
    .bind(ask.project.id)
    .bind(onto)
    .fetch_optional(&hub.db)
    .await?;
    if let Some((target_hex, eid)) = hidden {
        if !crate::embargo::can_see(hub, &ask.project, &ask.viewer, &eid).await? {
            return Err(not_found());
        }
        let real = ObjectId::from_hex(&target_hex).map_err(|e| Error::Other(e.into()))?;
        let _ = crate::sync::projected(hub, &ask.project, &ask.viewer, real).await?;
        return Ok((real, Some(eid)));
    }
    query::resolve(hub, ask, onto, deadline).await?;
    let tip_hex: Option<String> = sqlx::query_scalar(
        "SELECT target FROM branches WHERE project_id = $1 AND name = $2 AND hidden_for_embargo IS NULL",
    )
    .bind(ask.project.id)
    .bind(onto)
    .fetch_optional(&hub.db)
    .await?;
    let tip_hex = tip_hex.ok_or_else(not_found)?;
    let tip = ObjectId::from_hex(&tip_hex).map_err(|e| Error::Other(e.into()))?;
    Ok((tip, None))
}

/// Resolve `head_spec` (an `embargo/<id>` branch, an embargoed real/projected
/// snapshot hex or prefix, or an ordinary revision) for `ask`, returning
/// `(real_head, head_embargo_id)`.
pub async fn resolve_head(
    hub: &Arc<Hub>,
    ask: &Ask,
    head_spec: &str,
    deadline: Instant,
) -> Result<(ObjectId, Option<String>)> {
    let spec = head_spec.trim();
    let not_found = || Error::not_found("no such revision that you can see");

    // 1. Hidden `embargo/<id>` branch name.
    let hidden_branch: Option<(String, String)> = sqlx::query_as(
        "SELECT b.target, b.hidden_for_embargo \
         FROM branches b JOIN embargo_lines l \
           ON l.project_id = b.project_id AND l.embargo_id = b.hidden_for_embargo \
         WHERE b.project_id = $1 AND b.name = $2 AND b.hidden_for_embargo IS NOT NULL AND l.released_at IS NULL",
    )
    .bind(ask.project.id)
    .bind(spec)
    .fetch_optional(&hub.db)
    .await?;
    if let Some((target_hex, eid)) = hidden_branch {
        if !crate::embargo::can_see(hub, &ask.project, &ask.viewer, &eid).await? {
            return Err(not_found());
        }
        let real = ObjectId::from_hex(&target_hex).map_err(|e| Error::Other(e.into()))?;
        let _ = crate::sync::projected(hub, &ask.project, &ask.viewer, real).await?;
        return Ok((real, Some(eid)));
    }

    // 2. Snapshot id or prefix recorded in `embargo_snapshots` for an unreleased embargo.
    if (4..=64).contains(&spec.len()) && spec.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) {
        let rows: Vec<(String, String)> = if spec.len() == 64 {
            sqlx::query_as(
                "SELECT s.snapshot, s.embargo_id FROM embargo_snapshots s \
                 JOIN embargo_lines l ON l.project_id = s.project_id AND l.embargo_id = s.embargo_id \
                 WHERE s.project_id = $1 AND s.snapshot = $2 AND l.released_at IS NULL LIMIT 4",
            )
            .bind(ask.project.id)
            .bind(spec)
            .fetch_all(&hub.db)
            .await?
        } else {
            let upper = format!("{spec}g");
            sqlx::query_as(
                "SELECT s.snapshot, s.embargo_id FROM embargo_snapshots s \
                 JOIN embargo_lines l ON l.project_id = s.project_id AND l.embargo_id = s.embargo_id \
                 WHERE s.project_id = $1 AND s.snapshot >= $2 AND s.snapshot < $3 AND l.released_at IS NULL LIMIT 8",
            )
            .bind(ask.project.id)
            .bind(spec)
            .bind(&upper)
            .fetch_all(&hub.db)
            .await?
        };
        let mut cands: Vec<(ObjectId, String)> = Vec::new();
        let view_key = ask.project.view(&ask.viewer).key();
        for (snap_hex, eid) in rows {
            if !crate::embargo::can_see(hub, &ask.project, &ask.viewer, &eid).await? {
                continue;
            }
            let Ok(snap_id) = ObjectId::from_hex(&snap_hex) else { continue };
            if let Some(real) = real_for_viewer(hub, &ask.project, &ask.viewer, &view_key, snap_id).await? {
                if !cands.iter().any(|(r, e)| *r == real && *e == eid) {
                    cands.push((real, eid));
                }
            }
        }
        if cands.len() == 1 {
            let (real, eid) = cands.remove(0);
            return Ok((real, Some(eid)));
        }
        if cands.len() > 1 {
            return Err(Error::bad_request("ambiguous revision prefix"));
        }
    }

    // 3. Ordinary revision resolution (which withholds unreleased embargo snapshots as 404).
    let (_, real) = query::resolve_real(hub, ask, head_spec, deadline).await?;
    Ok((real, None))
}

async fn real_for_viewer(
    hub: &Arc<Hub>,
    project: &Project,
    viewer: &Viewer,
    view_key: &str,
    id: ObjectId,
) -> Result<Option<ObjectId>> {
    let is_real: Option<String> = sqlx::query_scalar("SELECT id FROM snapshots WHERE project_id = $1 AND id = $2")
        .bind(project.id)
        .bind(id.hex())
        .fetch_optional(&hub.db)
        .await?;
    if is_real.is_some() {
        if viewer.admin || crate::sync::projected(hub, project, viewer, id).await? == id {
            return Ok(Some(id));
        }
    }
    let proj_real: Option<String> = sqlx::query_scalar(
        "SELECT real_id FROM projections WHERE project_id = $1 AND view_key = $2 AND projected_id = $3 AND NOT collapsed ORDER BY real_id LIMIT 1",
    )
    .bind(project.id)
    .bind(view_key)
    .bind(id.hex())
    .fetch_optional(&hub.db)
    .await?;
    if let Some(real) = proj_real.and_then(|h| ObjectId::from_hex(&h).ok()) {
        if crate::sync::projected(hub, project, viewer, real).await? == id {
            return Ok(Some(real));
        }
    }
    Ok(None)
}

/// Combine `head`'s and `onto`'s embargo ids into the PR's single embargo id (`""` if none).
pub fn combine_embargo(ask: &Ask, head_emb: Option<String>, onto_emb: Option<String>) -> Result<String> {
    match (head_emb, onto_emb) {
        (None, None) => Ok(String::new()),
        (Some(e), None) | (None, Some(e)) => Ok(e),
        (Some(a), Some(b)) if a == b => Ok(a),
        (Some(_), Some(_)) => {
            if ask.viewer.admin {
                Err(Error::bad_request("a PR belongs to at most one embargo"))
            } else {
                Err(super::not_a_pr())
            }
        }
    }
}

/// Compute an unreleased embargoed PR revision directly over `cx.src` without
/// writing `head` or any embargoed ancestor into `view_graph`, `view_changes`,
/// or `file_history`.
pub async fn compute(
    hub: &Arc<Hub>,
    ask: &Ask,
    head: ObjectId,
    onto: ObjectId,
    onto_is_hidden: bool,
    embargo_id: &str,
    rules: Review,
) -> Result<Computed> {
    let deadline = Instant::now() + DEADLINE;
    if !onto_is_hidden {
        let admin = Viewer {
            admin: true,
            ..Viewer::default()
        };
        ensure(hub, &ask.project, &admin, &[onto], Some(deadline)).await?;
    }
    let eid = embargo_id.to_string();
    let r = blocking(hub, ask.project.id, move |cx| {
        let g = G::new(cx, "admin", Some(deadline));
        let hidden_ancs: HashSet<ObjectId> = if onto_is_hidden {
            let mut set = HashSet::new();
            let mut st = vec![onto];
            while let Some(cur) = st.pop() {
                if !set.insert(cur) || cur == crate::sync::root_snapshot_id() {
                    continue;
                }
                g.tick()?;
                if let Ok(s) = cx.src.snapshot(&cur) {
                    for p in &s.parents {
                        st.push(*p);
                    }
                }
            }
            set
        } else {
            HashSet::new()
        };
        let is_onto_anc = |x: ObjectId| -> Result<bool> {
            if x == onto {
                return Ok(true);
            }
            if onto_is_hidden {
                return Ok(hidden_ancs.contains(&x));
            }
            Ok(g.row(&x)?.is_some() && g.is_ancestor(x, onto)?)
        };

        let mut chain = Vec::new();
        let mut seen: HashSet<ChangeId> = HashSet::new();
        let mut x = head;
        while !is_onto_anc(x)? {
            g.tick()?;
            let s = cx.src.snapshot(&x)?;
            let parent = if s.parents.len() == 1 {
                s.parents[0]
            } else if s.embargo.as_deref() == Some(eid.as_str())
                && !s.parents.is_empty()
                && is_onto_anc(s.parents[0])?
            {
                s.parents[0]
            } else {
                return Err(Error::bad_request(format!(
                    "{} is a merge (or the root): a PR is a stack of changes with one parent each; rebase it onto the target",
                    s.change_id.short()
                )));
            };
            if !seen.insert(s.change_id) {
                return Err(Error::bad_request(format!(
                    "change {} is in the stack twice",
                    s.change_id.short()
                )));
            }
            if chain.len() == MAX_STACK {
                return Err(Error::bad_request(format!("a PR holds at most {MAX_STACK} changes")));
            }
            chain.push((x, parent, s.change_id, s.tree));
            x = parent;
        }
        if chain.is_empty() {
            return Err(Error::bad_request(format!(
                "{NOTHING_TO_REVIEW}: that revision is already part of the target"
            )));
        }
        chain.reverse();
        let mut touched = BTreeSet::new();
        let mut files: BTreeMap<String, FileChange> = BTreeMap::new();
        let mut patch = blake3::Hasher::new_derive_key("veil 2026 hub pr patch v1");
        let mut out = Vec::new();
        for (snap, parent, change, tree) in &chain {
            let ptree = cx.src.snapshot(parent)?.tree;
            let (leaves, dirs) = changes::diff(&cx.src, ptree, *tree)?;
            if !leaves.is_empty() {
                patch.update(&change.0);
                patch.update(&(leaves.len() as u64).to_le_bytes());
            }
            for c in &leaves {
                g.tick()?;
                patch.update(&(c.path.len() as u64).to_le_bytes());
                patch.update(c.path.as_bytes());
                revision::entry_bytes(&mut patch, c.old.as_ref());
                revision::entry_bytes(&mut patch, c.new.as_ref());
                let secret = [&c.old, &c.new]
                    .iter()
                    .any(|e| e.as_ref().is_some_and(|e| !e.visibility.is_public()));
                let executable = c.new.as_ref().is_some_and(|e| e.executable);
                let regular = [&c.old, &c.new]
                    .iter()
                    .all(|e| e.as_ref().is_none_or(|e| e.kind == EntryKind::File));
                let f = files.entry(c.path.clone()).or_insert(FileChange {
                    path: c.path.clone(),
                    secret,
                    executable,
                    regular,
                });
                f.secret |= secret;
                f.executable |= executable;
                f.regular &= regular;
                touched.insert(c.path.clone());
            }
            touched.extend(dirs.into_iter().filter(|d| !d.is_empty()));
            if touched.len() > MAX_PATHS {
                return Err(Error::bad_request(format!(
                    "a PR touches at most {MAX_PATHS} paths; land larger changes in parts"
                )));
            }
            out.push(StackChange {
                change: change.to_string(),
                snapshot: snap.hex(),
                parent: parent.hex(),
            });
        }
        let files: Vec<FileChange> = files.into_values().collect();
        let (risk, reasons) = classify(&files, &rules);
        Ok(Computed {
            base: x,
            head,
            changes: out,
            touched,
            files,
            patch: patch.finalize().to_hex().to_string(),
            risk,
            reasons,
            rules_key: rules.risk_key(),
        })
    })
    .await;
    match r {
        Err(Error::Api {
            code: "bad_request",
            message,
            ..
        }) if !ask.viewer.admin && !message.starts_with(NOTHING_TO_REVIEW) => Err(super::not_a_pr()),
        r => r,
    }
}

/// Project `reals` for `ask`'s viewer via `sync::projected` (without filling
/// `view_graph`) and tag any new projected snapshot ids in `embargo_snapshots`
/// while `embargo_id` remains unreleased.
pub async fn projected(
    hub: &Arc<Hub>,
    ask: &Ask,
    embargo_id: &str,
    reals: &[ObjectId],
) -> Result<HashMap<ObjectId, ObjectId>> {
    let mut map = HashMap::with_capacity(reals.len());
    let mut extra_projected: Vec<String> = Vec::new();
    for &r in reals {
        let p = crate::sync::projected(hub, &ask.project, &ask.viewer, r).await?;
        if p != r {
            extra_projected.push(p.hex());
        }
        map.insert(r, p);
    }
    if !extra_projected.is_empty() {
        extra_projected.sort();
        extra_projected.dedup();
        sqlx::query(
            "INSERT INTO embargo_snapshots (project_id, snapshot, embargo_id) \
             SELECT $1, p, $2 FROM UNNEST($3::text[]) AS p \
             WHERE EXISTS (SELECT 1 FROM embargo_lines WHERE project_id = $1 AND embargo_id = $2 AND released_at IS NULL) \
             ON CONFLICT DO NOTHING",
        )
        .bind(ask.project.id)
        .bind(embargo_id)
        .bind(&extra_projected)
        .execute(&hub.db)
        .await?;
    }
    Ok(map)
}

/// Compute `veil.diff/2` between `from_real` and `to_real` in `ask.viewer`'s
/// projected tree view without touching `view_graph`.
pub async fn diff(
    hub: &Arc<Hub>,
    ask: &Ask,
    from_real: ObjectId,
    to_real: ObjectId,
    from_proj: ObjectId,
    to_proj: ObjectId,
    stat: Option<bool>,
) -> Result<Value> {
    let deadline = Instant::now() + DEADLINE;
    let content = !stat.unwrap_or(false);
    let project = ask.project.clone();
    let viewer = ask.viewer.clone();
    let view_key = project.view(&viewer).key();
    let mut v = blocking(hub, project.id, move |cx| {
        let view = project.view(&viewer);
        let g = G::new(cx, &view_key, Some(deadline));
        let t = Trees::new(&g, &view);
        let old = t.root(cx.src.snapshot(&from_real)?.tree)?;
        let new = t.root(cx.src.snapshot(&to_real)?.tree)?;
        t.diff(old, new, "", content, DiffLimits::default())
    })
    .await?;
    v["schema"] = json!("veil.diff/2");
    v["from"] = json!(from_proj.hex());
    v["to"] = json!(to_proj.hex());
    v["base"] = json!(from_proj.hex());
    v["merge_bases"] = json!(vec![from_proj.hex()]);
    v["policy_version"] = json!(ask.policy_version);
    Ok(v)
}

/// Handle `POST /prs/{id}/land` for an unreleased embargoed PR:
/// - `at_release: Some(true)` arms `land_at_release` once the review gate is ready;
/// - `at_release: Some(false)` disarms `land_at_release`;
/// - `at_release: None` refuses immediate landing before release (`409 embargoed`).
pub async fn land_embargoed(
    hub: &Arc<Hub>,
    ask: &Ask,
    me: i64,
    pr: &PrRow,
    at_release: Option<bool>,
) -> Result<Value> {
    let paths = review::paths_of(hub, ask.project.id, &pr.id).await?;
    if pr.author != me && !review::writes_all(&ask.project, &ask.viewer, &paths) {
        return Err(Error::forbidden(
            "only the author, or someone who may write every file of this PR, lands it",
        ));
    }
    if pr.state != "open" {
        return Err(Error::conflict(format!("the PR is {}", pr.state)));
    }
    if ask.viewer.only.is_some() && paths.iter().any(|p| !ask.viewer.within_narrowing(p)) {
        return Err(crate::sync::agent_refusal(crate::sync::NARROWED_MOVE));
    }
    if ask.viewer.agent && paths.iter().any(|p| veil_core::hub::agent::decides_access(p)) {
        return Err(crate::sync::agent_refusal(crate::sync::AGENT_ACCESS_MOVE));
    }
    if at_release == Some(false) {
        let now = veil_core::now_millis();
        sqlx::query("UPDATE prs SET land_at_release = FALSE, updated_at = $1 WHERE project_id = $2 AND id = $3 AND state = 'open'")
            .bind(now)
            .bind(ask.project.id)
            .bind(&pr.id)
            .execute(&hub.db)
            .await?;
        let out = super::show(hub, ask, &pr.id).await?;
        return Ok(out);
    }
    let (_, g) = super::gate(hub, ask, pr).await?;
    if !g.ready {
        return Err(Error::new(
            StatusCode::CONFLICT,
            "not_ready",
            format!("not ready to land: {}", g.reasons.join("; ")),
        ));
    }
    match at_release {
        Some(true) => {
            let now = veil_core::now_millis();
            sqlx::query("UPDATE prs SET land_at_release = TRUE, updated_at = $1 WHERE project_id = $2 AND id = $3 AND state = 'open'")
                .bind(now)
                .bind(ask.project.id)
                .bind(&pr.id)
                .execute(&hub.db)
                .await?;
            super::show(hub, ask, &pr.id).await
        }
        Some(false) => unreachable!(),
        None => Err(Error::new(
            StatusCode::CONFLICT,
            "embargoed",
            "this PR's embargo is not released yet; set at_release to land it when the embargo releases",
        )),
    }
}

/// Release an embargo (`has_pr = true`) whose changes are tracked by one or
/// more embargoed PRs.
#[allow(clippy::too_many_arguments)]
pub async fn release_embargo_prs(
    hub: &Arc<Hub>,
    project: &Project,
    embargo_id: &str,
    target_branch: &str,
    ebranch: &str,
    person_id: i64,
    person_name: &str,
    device_key: &str,
    pushed_record: Option<EmbargoRecord>,
    record_json: &str,
    agent_viewer: Option<&Viewer>,
) -> Result<bool> {
    type CandRow = (String, String, i64, String, String, String, String, i32, i64, i64, bool);
    let prs: Vec<CandRow> = sqlx::query_as(
        "SELECT p.id, p.target, p.author, pe.name, p.title, p.body, p.state, p.revision, p.created_at, p.updated_at, p.land_at_release \
         FROM prs p JOIN people pe ON pe.id = p.author \
         WHERE p.project_id = $1 AND p.embargo = $2 ORDER BY p.created_at, p.id",
    )
    .bind(project.id)
    .bind(embargo_id)
    .fetch_all(&hub.db)
    .await?;

    // Enforce S11 agent narrowing & access-file rules if an agent session asked for early release.
    if let Some(v) = agent_viewer {
        for (pr_id, ..) in &prs {
            let paths = review::paths_of(hub, project.id, pr_id).await?;
            if v.only.is_some() && paths.iter().any(|p| !v.within_narrowing(p)) {
                return Err(crate::sync::agent_refusal(crate::sync::NARROWED_MOVE));
            }
            if v.agent && paths.iter().any(|p| veil_core::hub::agent::decides_access(p)) {
                return Err(crate::sync::agent_refusal(crate::sync::AGENT_ACCESS_MOVE));
            }
        }
    }

    let admin_viewer = Viewer {
        person: Some(person_id),
        admin: true,
        groups: HashSet::new(),
        only: None,
        agent: false,
    };

    let rules = state::rules_in_force(hub, project, &project.default_branch).await?;
    let mut landed_prs: HashSet<String> = HashSet::new();
    let mut touched_branches: BTreeSet<String> = BTreeSet::new();

    for (id, pr_target, author, author_name, title, body, state_str, revision, created_at, updated_at, land_at_release) in &prs {
        if state_str != "open" || !*land_at_release {
            continue;
        }
        // Re-check that the embargo has not already been finalized by another server.
        let still_unreleased: Option<bool> = sqlx::query_scalar(
            "SELECT released_at IS NULL FROM embargo_lines WHERE project_id = $1 AND embargo_id = $2",
        )
        .bind(project.id)
        .bind(embargo_id)
        .fetch_optional(&hub.db)
        .await?;
        if still_unreleased != Some(true) {
            break;
        }

        let pr_row = PrRow {
            id: id.clone(),
            target: pr_target.clone(),
            author: *author,
            author_name: author_name.clone(),
            title: title.clone(),
            body: body.clone(),
            state: state_str.clone(),
            revision: *revision,
            created_at: *created_at,
            updated_at: *updated_at,
            embargo: embargo_id.to_string(),
            land_at_release: *land_at_release,
        };
        let revs = super::rated(hub, project.id, &pr_row.id, &rules).await?;
        let Some(current) = revs.iter().find(|r| r.n == pr_row.revision) else {
            continue;
        };
        let gate = review::gate(
            hub,
            project,
            &admin_viewer,
            &pr_row,
            &current.patch,
            Risk::parse(&current.risk),
            &rules,
        )
        .await?;
        if !gate.ready {
            // S21's review rules are not met: do not land onto the branch;
            // the PR will release as an ordinary open PR instead.
            continue;
        }

        let land_branch = if pr_target == ebranch {
            target_branch.to_string()
        } else {
            pr_target.clone()
        };
        let ticket = format!("embargo-pr-{}-{id}", project.id);
        let existing_outcome = crate::landing::read(hub, project.id, person_id, &ticket).await?;
        let need_queue = existing_outcome.is_none();
        if need_queue || agent_viewer.is_some_and(|v| v.agent) {
            let judged = match crate::landing::stack(
                hub,
                project,
                &admin_viewer,
                &land_branch,
                current.head,
                &HashMap::new(),
                None,
            )
            .await?
            {
                Ok(j) if j.branch => j,
                Ok(_) => continue,
                Err(why) => {
                    if pushed_record.is_some() || agent_viewer.is_some() {
                        return Err(Error::conflict(why));
                    }
                    continue;
                }
            };
            if let Some(v) = agent_viewer {
                crate::landing::agent_stack(hub, project, v, &land_branch, &judged, current.head, false, None).await?;
            }
            if need_queue && judged.stack.is_empty() {
                landed_prs.insert(id.clone());
                continue;
            }
            if need_queue && !judged.stack.is_empty() {
                let (_, _, epochs) = perm::open_at(
                    hub,
                    &project.name,
                    &Caller {
                        person: Some(Person {
                            id: person_id,
                            name: person_name.to_string(),
                            device_key: device_key.to_string(),
                            agent: None,
                        }),
                        epochs: crate::caches::Epochs::default(),
                    },
                )
                .await?;
                let who = crate::landing::Submitter {
                    person: Person {
                        id: person_id,
                        name: person_name.to_string(),
                        device_key: device_key.to_string(),
                        agent: None,
                    },
                    epochs,
                };
                let q = crate::landing::Queued {
                    ticket: ticket.clone(),
                    branch: land_branch.clone(),
                    stack: judged.stack,
                    lineage: judged.lineage,
                    skipped: Arc::new(std::sync::Mutex::new(judged.skipped)),
                };
                sqlx::query(
                    "INSERT INTO landing_queue (project_id, branch, ticket, person_id, person_name, device_key, stack, lineage, person_epoch, \
                     project_epoch, state, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'queued', \
                     (extract(epoch FROM clock_timestamp()) * 1000000)::BIGINT) ON CONFLICT (ticket) DO NOTHING",
                )
                .bind(project.id)
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

        let w = hub.landing.register(&ticket);
        if let Some((_, cur)) = crate::landing::read(hub, project.id, person_id, &ticket).await? {
            let outcome = if cur.state == LandState::Queued {
                crate::limits::leave_gates();
                crate::landing::ensure(hub, project.id, &land_branch);
                let deadline = tokio::time::Instant::now() + crate::landing::WAIT;
                crate::landing::wait(hub, project.id, person_id, &land_branch, w, deadline).await?
            } else {
                crate::landing::abandon(hub, w);
                cur
            };
            if outcome.state == LandState::Landed {
                landed_prs.insert(id.clone());
                touched_branches.insert(land_branch);
            } else if pushed_record.is_some() || agent_viewer.is_some() {
                return Err(Error::conflict(
                    outcome
                        .message
                        .unwrap_or_else(|| "embargo PR landing did not complete".into()),
                ));
            }
        } else {
            crate::landing::abandon(hub, w);
        }
    }

    let now_ms: i64 = sqlx::query_scalar("SELECT (extract(epoch FROM clock_timestamp()) * 1000)::BIGINT")
        .fetch_one(&hub.db)
        .await?;
    let mut rec: EmbargoRecord = match pushed_record {
        Some(r) => r,
        None => serde_json::from_str(record_json).map_err(|e| Error::Other(e.into()))?,
    };
    if rec.released_at.is_none() {
        rec.released_at = Some(now_ms);
    }
    let new_json = serde_json::to_string(&rec).unwrap_or_else(|_| record_json.to_string());
    let pid = project.id;
    let policy = project.policy.clone();
    let policy_key = class::policy_key(&policy);
    let eid = embargo_id.to_string();
    let ebranch2 = ebranch.to_string();
    let tbranch2 = target_branch.to_string();
    let landed_set = landed_prs.clone();
    let notify = hub.caches.notices.load(Ordering::SeqCst);

    let (updated, transitioned): (bool, Vec<(String, bool)>) =
        transaction(&hub.db, Isolation::ReadCommitted, move |c| {
            let policy = policy.clone();
            let policy_key = policy_key.clone();
            let eid = eid.clone();
            let ebranch2 = ebranch2.clone();
            let tbranch2 = tbranch2.clone();
            let new_json = new_json.clone();
            let landed_set = landed_set.clone();
            Box::pin(async move {
                let n = sqlx::query(
                    "UPDATE embargo_lines SET released_at = COALESCE(released_at, $1), record_json = $2 \
                     WHERE project_id = $3 AND embargo_id = $4 AND released_at IS NULL",
                )
                .bind(now_ms)
                .bind(&new_json)
                .bind(pid)
                .bind(&eid)
                .execute(&mut *c)
                .await?
                .rows_affected();
                if n == 0 {
                    return Ok((false, Vec::new()));
                }

                let pr_ids: Vec<String> = sqlx::query_scalar(
                    "SELECT id FROM prs WHERE project_id = $1 AND embargo = $2 ORDER BY id",
                )
                .bind(pid)
                .bind(&eid)
                .fetch_all(&mut *c)
                .await?;

                let mut done = Vec::new();
                for pr_id in pr_ids {
                    let paths: Vec<String> = sqlx::query_scalar(
                        "SELECT path FROM pr_paths WHERE project_id = $1 AND pr = $2",
                    )
                    .bind(pid)
                    .bind(&pr_id)
                    .fetch_all(&mut *c)
                    .await?;
                    let lines = class::lines_of(&policy, paths.iter().map(String::as_str));
                    let plain_class = class::put_class_for(&mut *c, pid, &policy_key, &lines, "").await?;
                    let did_land = landed_set.contains(&pr_id);
                    sqlx::query(
                        "UPDATE prs SET \
                           embargo = '', \
                           land_at_release = FALSE, \
                           class_id = $1, \
                           policy_key = $2, \
                           target = CASE WHEN target = $3 THEN $4 ELSE target END, \
                           state = CASE WHEN $5 AND state = 'open' THEN 'landed' ELSE state END, \
                           updated_at = $6 \
                         WHERE project_id = $7 AND id = $8",
                    )
                    .bind(&plain_class)
                    .bind(&policy_key)
                    .bind(&ebranch2)
                    .bind(&tbranch2)
                    .bind(did_land)
                    .bind(now_ms)
                    .bind(pid)
                    .bind(&pr_id)
                    .execute(&mut *c)
                    .await?;
                    done.push((pr_id, did_land));
                }

                // Retarget any remaining PRs that targeted `embargo/<id>`.
                sqlx::query("UPDATE prs SET target = $1 WHERE project_id = $2 AND target = $3")
                    .bind(&tbranch2)
                    .bind(pid)
                    .bind(&ebranch2)
                    .execute(&mut *c)
                    .await?;

                // Promote active `pr_embargo_holds` on PRs that remain open into `pr_holds`, then clear.
                sqlx::query(
                    "INSERT INTO pr_holds (project_id, person, path, pr, at) \
                     SELECT h.project_id, h.person, h.path, h.pr, h.at \
                     FROM pr_embargo_holds h JOIN prs p ON p.project_id = h.project_id AND p.id = h.pr \
                     WHERE h.project_id = $1 AND h.embargo = $2 AND p.state = 'open' \
                     ON CONFLICT (project_id, person, path) DO UPDATE \
                       SET pr = EXCLUDED.pr, at = EXCLUDED.at WHERE pr_holds.at < EXCLUDED.at",
                )
                .bind(pid)
                .bind(&eid)
                .execute(&mut *c)
                .await?;
                sqlx::query("DELETE FROM pr_embargo_holds WHERE project_id = $1 AND embargo = $2")
                    .bind(pid)
                    .bind(&eid)
                    .execute(&mut *c)
                    .await?;

                sqlx::query("DELETE FROM branches WHERE project_id = $1 AND name = $2")
                    .bind(pid)
                    .bind(&ebranch2)
                    .execute(&mut *c)
                    .await?;
                sqlx::query("DELETE FROM embargo_snapshots WHERE project_id = $1 AND embargo_id = $2")
                    .bind(pid)
                    .bind(&eid)
                    .execute(&mut *c)
                    .await?;
                if notify {
                    sqlx::query("SELECT pg_notify($1, $2)")
                        .bind(crate::caches::TIPS_CHANNEL)
                        .bind(pid.to_string())
                        .execute(&mut *c)
                        .await?;
                }
                Ok((n > 0, done))
            })
        })
        .await?;

    hub.caches.tips_changed(project.id);
    if !touched_branches.is_empty() {
        crate::derive::landed(hub, project.id, touched_branches.into_iter().collect());
    }
    if updated {
        crate::events::emit_embargo_released(hub, project.id, embargo_id).await;
        for (pr_id, did_land) in transitioned {
            let ev = if did_land { "pr.landed" } else { "pr.opened" };
            crate::events::emit_pr(hub, project.id, &pr_id, ev).await;
        }
    }
    Ok(updated)
}
