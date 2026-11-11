//! CI through the API and `main@tested` (`docs/HUB.md` §13.35;
//! `docs/design/server/phase-4-agent-scale.md` §4.6, §4.7, §5.2):
//!
//! * `POST /v1/sessions/ci`: mints a narrow CI runner session from a person's
//!   session (`agent_runner = TRUE`). If `check` is named in `.veilrules`
//!   (`[checks.<name>] paths = [...]`) and `only` is empty, the session is
//!   narrowed to those paths automatically. A runner session reads only what
//!   its grant allows and writes only check results.
//! * `POST /v1/projects/{p}/checks`: records a check result on a snapshot.
//!   Stores the paths the runner's session could read (`session_paths`,
//!   `admin_only`) so a result is shown only to viewers who may read every
//!   path the runner could read. Enforces per-result, per-tip and per-runner
//!   bounds on results and logs.
//! * `GET /v1/projects/{p}/checks?rev=…`: lists the check results on `rev`
//!   that the caller may see, with `snapshot` projected for the caller.
//! * `GET /v1/projects/{p}/tested/{branch}`: returns `<branch>@tested`, the
//!   newest snapshot on the branch (within its current lineage) whose
//!   required checks all passed. `tested` moves only forward (`depth` from
//!   the root increases monotonically).

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    Json,
};
use serde::Deserialize;
use veil_core::{
    hub::{
        agent::{AgentSession, AgentSessionRequest},
        ci::{
            validate_check_name, validate_log, validate_summary, validate_url, CheckRequest, CheckResult, CheckState, ChecksResponse,
            CiSessionRequest, TestedTip, MAX_CHECKS_PER_SNAPSHOT, MAX_RUNNER_CHECKS, MAX_RUNNER_LOG_BYTES, MAX_TIP_LOG_BYTES,
        },
    },
    object::Attribution,
    ObjectId,
};

use crate::{
    auth::Caller,
    error::{Error, Result},
    perm::{self, Project, Viewer},
    sync, Hub, HubState,
};

/// Most distinct check names one runner may record on one snapshot.
pub const MAX_RUNNER_CHECKS_PER_SNAPSHOT: i64 = 32;

/// `POST /v1/sessions/ci`: mint a CI runner session.
pub async fn ci_session(
    State(hub): State<HubState>,
    headers: HeaderMap,
    caller: Caller,
    Json(req): Json<CiSessionRequest>,
) -> Result<Json<AgentSession>> {
    caller.person_only()?;
    if let Some(check) = &req.check {
        validate_check_name(check).map_err(Error::bad_request)?;
    }
    let mut only = req.only;
    if only.is_empty() {
        if let Some(check) = &req.check {
            let (project, viewer) = perm::open(&hub, &req.project, &caller).await?;
            let default_tip = branch_tip(&hub, &project, &viewer, &project.default_branch).await?;
            let rules = sync::blocking(&hub, project.id, move |src| crate::landing::rules(src, default_tip)).await?;
            if let Some(paths) = rules.checks.get(check) {
                only = paths.clone();
            }
        }
    }
    let attribution = req.attribution.unwrap_or_else(|| Attribution {
        agent: req.check.unwrap_or_else(|| "ci".to_string()),
        task: None,
        prompt: None,
        run: None,
    });
    crate::auth::agent_session(
        State(hub),
        headers,
        caller,
        Json(AgentSessionRequest {
            project: req.project,
            attribution,
            only,
            seconds: req.seconds,
            runner: true,
        }),
    )
    .await
}

/// `POST /v1/projects/{p}/checks`: record a check result on a snapshot.
pub async fn post_check_route(
    State(hub): State<HubState>,
    caller: Caller,
    Path(p): Path<String>,
    Json(req): Json<CheckRequest>,
) -> Result<Json<CheckResult>> {
    let me = caller.signed_in()?.clone();
    let (project, viewer) = perm::open(&hub, &p, &caller).await?;
    if !project.participant(&viewer) {
        return Err(Error::forbidden("you are not in this project"));
    }
    validate_check_name(&req.name).map_err(Error::bad_request)?;
    validate_summary(&req.summary).map_err(Error::bad_request)?;
    if let Some(u) = &req.url {
        validate_url(u).map_err(Error::bad_request)?;
    }
    if let Some(l) = &req.log {
        validate_log(l).map_err(Error::bad_request)?;
    }

    let Some(real_id) = resolve_snapshot(&hub, &project, &viewer, &req.snapshot).await? else {
        return Err(Error::not_found("no such snapshot in your view of this project"));
    };
    let proj_id = req.snapshot;

    let rules = default_branch_rules(&hub, &project).await?;
    let counts = can_post_check_results(&project, &viewer, &rules, &req.name);
    let required_on_protected = rules.protected.iter().any(|b| {
        rules
            .required_checks
            .get(b)
            .is_some_and(|reqs| reqs.iter().any(|r| r == &req.name))
    });
    if required_on_protected && !counts {
        return Err(Error::forbidden(
            "only an admin or someone who may write every path this check covers may report it",
        ));
    }

    let (session_paths, admin_only) = readable_footprint(&project, &viewer)?;

    let now = veil_core::now_millis();
    let pid = project.id;
    let real_hex = real_id.hex();
    let name = req.name.clone();
    let state_str = req.state.as_str().to_string();
    let summary = req.summary.clone();
    let url = req.url.clone();
    let log = req.log.clone();
    let runner_id = me.id;
    let runner_name = me.name.clone();
    let paths_json = serde_json::to_string(&session_paths).map_err(|e| Error::Other(e.into()))?;
    let project_for_tx = project.clone();
    let rules_for_tx = rules.clone();

    crate::db::transaction(&hub.db, crate::db::Isolation::ReadCommitted, move |c| {
        let real_hex = real_hex.clone();
        let name = name.clone();
        let state_str = state_str.clone();
        let summary = summary.clone();
        let url = url.clone();
        let log = log.clone();
        let runner_name = runner_name.clone();
        let paths_json = paths_json.clone();
        let project_for_tx = project_for_tx.clone();
        let rules_for_tx = rules_for_tx.clone();
        Box::pin(async move {
            let existing: Option<(i64, String, bool)> = sqlx::query_as(
                "SELECT runner_id, session_paths, admin_only FROM checks WHERE project_id = $1 AND snapshot = $2 AND name = $3",
            )
            .bind(pid)
            .bind(&real_hex)
            .bind(&name)
            .fetch_optional(&mut *c)
            .await?;
            if let Some((ex_runner, ex_paths_json, ex_admin_only)) = &existing {
                if !counts {
                    let roles = load_poster_roles(&mut *c, pid, &[*ex_runner]).await?;
                    let (ex_adm, ex_grps) = roles.get(ex_runner).cloned().unwrap_or_default();
                    let ex_paths: Vec<String> = serde_json::from_str(ex_paths_json).unwrap_or_default();
                    if stored_check_counts(
                        &project_for_tx,
                        *ex_runner,
                        ex_adm,
                        &ex_grps,
                        &ex_paths,
                        *ex_admin_only,
                        &rules_for_tx,
                        &name,
                    ) {
                        return Err(Error::forbidden(
                            "only an admin or someone who may write every path this check covers may replace its result",
                        ));
                    }
                }
            } else {
                let tip_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM checks WHERE project_id = $1 AND snapshot = $2")
                    .bind(pid)
                    .bind(&real_hex)
                    .fetch_one(&mut *c)
                    .await?;
                if tip_count >= MAX_CHECKS_PER_SNAPSHOT as i64 {
                    return Err(Error::bad_request(format!(
                        "a snapshot keeps at most {MAX_CHECKS_PER_SNAPSHOT} distinct checks"
                    )));
                }
                let runner_tip_count: i64 =
                    sqlx::query_scalar("SELECT COUNT(*) FROM checks WHERE project_id = $1 AND snapshot = $2 AND runner_id = $3")
                        .bind(pid)
                        .bind(&real_hex)
                        .bind(runner_id)
                        .fetch_one(&mut *c)
                        .await?;
                if runner_tip_count >= MAX_RUNNER_CHECKS_PER_SNAPSHOT {
                    return Err(Error::bad_request(format!(
                        "a runner may record at most {MAX_RUNNER_CHECKS_PER_SNAPSHOT} checks on one snapshot"
                    )));
                }
            }
            let initial_run_count: i64 = if counts && matches!(state_str.as_str(), "pass" | "fail") {
                1
            } else {
                0
            };
            sqlx::query(
                "INSERT INTO checks (project_id, snapshot, name, state, summary, url, log, runner_id, runner_name, session_paths, admin_only, updated_at, run_count) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) \
                 ON CONFLICT (project_id, snapshot, name) DO UPDATE \
                 SET state = EXCLUDED.state, \
                     summary = EXCLUDED.summary, \
                     url = EXCLUDED.url, \
                     log = EXCLUDED.log, \
                     runner_id = EXCLUDED.runner_id, \
                     runner_name = EXCLUDED.runner_name, \
                     session_paths = EXCLUDED.session_paths, \
                     admin_only = EXCLUDED.admin_only, \
                     updated_at = EXCLUDED.updated_at, \
                     run_count = CASE \
                         WHEN NOT $14 THEN 0 \
                         WHEN EXCLUDED.state = 'pass' THEN \
                             CASE WHEN checks.state = 'pass' THEN checks.run_count + 1 ELSE 1 END \
                         WHEN EXCLUDED.state = 'fail' THEN \
                             CASE WHEN checks.state IN ('fail', 'pending', 'error') THEN checks.run_count + 1 ELSE 1 END \
                         ELSE \
                             CASE WHEN checks.state IN ('fail', 'pending', 'error') THEN checks.run_count ELSE 0 END \
                     END",
            )
            .bind(pid)
            .bind(&real_hex)
            .bind(&name)
            .bind(&state_str)
            .bind(&summary)
            .bind(&url)
            .bind(&log)
            .bind(runner_id)
            .bind(&runner_name)
            .bind(&paths_json)
            .bind(admin_only)
            .bind(now)
            .bind(initial_run_count)
            .bind(counts)
            .execute(&mut *c)
            .await?;

            // Bound total log bytes on this tip.
            sqlx::query(
                "UPDATE checks SET log = NULL \
                 WHERE project_id = $1 AND snapshot = $2 AND log IS NOT NULL AND name IN ( \
                     SELECT name FROM ( \
                         SELECT name, SUM(LENGTH(log)) OVER (ORDER BY updated_at DESC, name) AS kept \
                         FROM checks WHERE project_id = $1 AND snapshot = $2 AND log IS NOT NULL \
                     ) t WHERE kept > $3 \
                 )",
            )
            .bind(pid)
            .bind(&real_hex)
            .bind(MAX_TIP_LOG_BYTES as i64)
            .execute(&mut *c)
            .await?;

            // Bound total log bytes and total rows for this runner in this project.
            sqlx::query(
                "UPDATE checks SET log = NULL \
                 WHERE project_id = $1 AND runner_id = $2 AND log IS NOT NULL AND (snapshot, name) IN ( \
                     SELECT snapshot, name FROM ( \
                         SELECT snapshot, name, SUM(LENGTH(log)) OVER (ORDER BY updated_at DESC, snapshot, name) AS kept \
                         FROM checks WHERE project_id = $1 AND runner_id = $2 AND log IS NOT NULL \
                     ) t WHERE kept > $3 \
                 )",
            )
            .bind(pid)
            .bind(runner_id)
            .bind(MAX_RUNNER_LOG_BYTES as i64)
            .execute(&mut *c)
            .await?;

            sqlx::query(
                "DELETE FROM checks \
                 WHERE project_id = $1 AND runner_id = $2 AND (snapshot, name) IN ( \
                     SELECT snapshot, name FROM checks \
                     WHERE project_id = $1 AND runner_id = $2 \
                     ORDER BY updated_at DESC, snapshot, name \
                     OFFSET $3 \
                 )",
            )
            .bind(pid)
            .bind(runner_id)
            .bind(MAX_RUNNER_CHECKS as i64)
            .execute(&mut *c)
            .await?;

            Ok(())
        })
    })
    .await?;

    if counts && req.state == CheckState::Pass {
        advance_tested(&hub, &project).await?;
    }
    if counts && matches!(req.state, CheckState::Pass | CheckState::Fail) {
        crate::bisect::on_check_recorded(
            &hub,
            &project,
            real_id,
            &req.name,
            req.state,
            &session_paths,
            admin_only,
            now,
        )
        .await?;
    }

    Ok(Json(CheckResult {
        snapshot: proj_id,
        name: req.name,
        state: req.state,
        summary: req.summary,
        url: req.url,
        log: req.log,
        runner: me.name,
        updated_at: now,
    }))
}

#[derive(Deserialize)]
pub struct ChecksQuery {
    #[serde(default)]
    pub rev: Option<String>,
}

/// `GET /v1/projects/{p}/checks?rev=…`: list the check results on `rev`
/// that the caller may see.
pub async fn list_checks_route(
    State(hub): State<HubState>,
    caller: Caller,
    Path(p): Path<String>,
    Query(q): Query<ChecksQuery>,
) -> Result<Json<ChecksResponse>> {
    let (project, viewer) = perm::open(&hub, &p, &caller).await?;
    let rev = q.rev.as_deref().unwrap_or(&project.default_branch);
    let (proj_id, reals) = resolve_rev_for_read(&hub, &project, &viewer, rev).await?;
    let checks = checks_for(&hub, &project, &viewer, proj_id, &reals).await?;
    Ok(Json(ChecksResponse {
        snapshot: proj_id,
        checks,
    }))
}

/// The check results on `reals` (projected as `proj_id`) that `viewer` may see.
pub async fn checks_for(
    hub: &Hub,
    project: &Project,
    viewer: &Viewer,
    proj_id: ObjectId,
    reals: &[ObjectId],
) -> Result<Vec<CheckResult>> {
    type Row = (String, String, String, Option<String>, Option<String>, String, String, bool, i64);
    let hexes: Vec<String> = reals.iter().map(ObjectId::hex).collect();
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT name, state, summary, url, log, runner_name, session_paths, admin_only, updated_at \
         FROM checks WHERE project_id = $1 AND snapshot = ANY($2) \
         ORDER BY name, updated_at DESC",
    )
    .bind(project.id)
    .bind(&hexes)
    .fetch_all(&hub.db)
    .await?;

    let mut checks = Vec::new();
    let mut seen_names = HashSet::new();
    for (name, state_s, summary, url, log, runner, paths_json, admin_only, updated_at) in rows {
        let Some(state) = CheckState::parse(&state_s) else { continue };
        let session_paths: Vec<String> = serde_json::from_str(&paths_json).unwrap_or_default();
        if !can_see_check(project, viewer, &session_paths, admin_only) {
            continue;
        }
        if !seen_names.insert(name.clone()) {
            continue;
        }
        checks.push(CheckResult {
            snapshot: proj_id,
            name,
            state,
            summary,
            url,
            log,
            runner,
            updated_at,
        });
    }
    Ok(checks)
}

/// `GET /v1/projects/{p}/tested/{branch}`: the newest snapshot on `branch`
/// whose required checks all passed, projected for the caller.
pub async fn tested_route(
    State(hub): State<HubState>,
    caller: Caller,
    Path((p, branch)): Path<(String, String)>,
) -> Result<Json<TestedTip>> {
    let (project, viewer) = perm::open(&hub, &p, &caller).await?;
    let Some(snapshot) = tested_for(&hub, &project, &viewer, &branch).await? else {
        return Err(Error::not_found(format!("branch '{branch}' has no tested snapshot yet")));
    };
    Ok(Json(TestedTip { branch, snapshot }))
}

async fn tested_real(hub: &Arc<Hub>, project: &Project, viewer: &Viewer, branch: &str) -> Result<Option<ObjectId>> {
    let row: Option<String> = sqlx::query_scalar(
        "SELECT t.snapshot FROM tested t JOIN branches b ON b.project_id = t.project_id AND b.name = t.branch \
         WHERE t.project_id = $1 AND t.branch = $2 AND t.lineage = b.lineage AND b.hidden_for_embargo IS NULL",
    )
    .bind(project.id)
    .bind(branch)
    .fetch_optional(&hub.db)
    .await?;
    let Some(real) = row.and_then(|h| ObjectId::from_hex(&h).ok()) else {
        return Ok(None);
    };
    if crate::embargo::is_withheld_from_viewer(hub, project, viewer, &real).await? {
        return Ok(None);
    }
    Ok(Some(real))
}

/// `<branch>@tested` as `viewer` sees it (`None` when the branch does not
/// exist or has no tested snapshot in its current lineage).
pub async fn tested_for(hub: &Arc<Hub>, project: &Project, viewer: &Viewer, branch: &str) -> Result<Option<ObjectId>> {
    let Some(real) = tested_real(hub, project, viewer, branch).await? else {
        return Ok(None);
    };
    let proj = sync::projected(hub, project, viewer, real).await?;
    Ok(Some(proj))
}

/// All `<branch>@tested` pointers in `project` as `viewer` sees them, for
/// [`veil_core::hub::wire::Tips::tested`].
pub async fn all_tested_for(hub: &Arc<Hub>, project: &Project, viewer: &Viewer) -> Result<BTreeMap<String, ObjectId>> {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT t.branch, t.snapshot FROM tested t JOIN branches b ON b.project_id = t.project_id AND b.name = t.branch \
         WHERE t.project_id = $1 AND t.lineage = b.lineage AND b.hidden_for_embargo IS NULL ORDER BY t.branch",
    )
    .bind(project.id)
    .fetch_all(&hub.db)
    .await?;
    let mut out = BTreeMap::new();
    for (branch, hex) in rows {
        if let Ok(real) = ObjectId::from_hex(&hex) {
            if crate::embargo::is_withheld_from_viewer(hub, project, viewer, &real).await? {
                continue;
            }
            let proj = sync::projected(hub, project, viewer, real).await?;
            out.insert(branch, proj);
        }
    }
    Ok(out)
}

/// What paths `viewer`'s session could read in `project`. A check result is
/// shown only to readers whose view can read every one of these paths (and
/// who are unnarrowed admins when `admin_only` is true).
fn readable_footprint(project: &Project, viewer: &Viewer) -> Result<(Vec<String>, bool)> {
    let view = project.view(viewer);
    if let Some(only) = &viewer.only {
        let mut paths = Vec::new();
        for p in only.iter() {
            if !view.sees_under(p) {
                return Err(Error::forbidden("this session cannot read the paths it is narrowed to"));
            }
            if view.read(p) {
                paths.push(p.clone());
            }
            for r in &project.policy.rules {
                if veil_core::hub::access::covers(p, &r.path) && view.read(&r.path) {
                    paths.push(r.path.clone());
                }
            }
        }
        paths.sort();
        paths.dedup();
        let all = paths.clone();
        paths.retain(|p| !all.iter().any(|o| o != p && veil_core::hub::access::covers(o, p) && same_access(project, o, p)));
        if paths.is_empty() {
            return Err(Error::forbidden("this session cannot read any path in this project"));
        }
        Ok((paths, false))
    } else if viewer.admin {
        Ok((Vec::new(), true))
    } else {
        let mut paths: Vec<String> = project
            .policy
            .rules
            .iter()
            .filter(|r| view.read(&r.path))
            .map(|r| r.path.clone())
            .collect();
        paths.sort();
        paths.dedup();
        if paths.is_empty() {
            return Err(Error::forbidden("this session cannot read any path in this project"));
        }
        Ok((paths, false))
    }
}

fn same_access(project: &Project, a: &str, b: &str) -> bool {
    project.policy.deciding(a) == project.policy.deciding(b)
}

/// May `viewer` see a check result posted by a session whose readable paths
/// were `(session_paths, admin_only)`?
pub(crate) fn can_see_check(project: &Project, viewer: &Viewer, session_paths: &[String], admin_only: bool) -> bool {
    if admin_only {
        return viewer.admin && viewer.only.is_none();
    }
    if session_paths.is_empty() {
        return false;
    }
    let view = project.view(viewer);
    session_paths.iter().all(|p| view.read(p) && viewer.within_narrowing(p))
}

/// Resolve a projected snapshot `id` in `viewer`'s view to a real snapshot via
/// [`sync::resolve_exact_for`], enforcing S22 embargo withholding on reads and
/// writes while attaching historical checks to the uncollapsed commit `id` stands for.
async fn resolve_snapshot(
    hub: &Arc<Hub>,
    project: &Project,
    viewer: &Viewer,
    id: &ObjectId,
) -> Result<Option<ObjectId>> {
    let Some(real) = sync::resolve_exact_for(hub, project, viewer, id).await? else {
        return Ok(None);
    };
    if sync::projected(hub, project, viewer, real).await? != *id {
        return Ok(None);
    }
    Ok(Some(real))
}

/// Resolve `rev` (a branch name, `<branch>@tested`, or a 64-hex snapshot id
/// in `viewer`'s view) to `(proj_id, real_candidates)`.
async fn resolve_rev_for_read(
    hub: &Arc<Hub>,
    project: &Project,
    viewer: &Viewer,
    rev: &str,
) -> Result<(ObjectId, Vec<ObjectId>)> {
    let rev = rev.trim();
    if rev.is_empty() || rev.len() > 255 {
        return Err(Error::not_found("no such revision that you can see"));
    }
    if let Some(branch) = rev.strip_suffix("@tested") {
        let Some(real) = tested_real(hub, project, viewer, branch).await? else {
            return Err(Error::not_found(format!("branch '{branch}' has no tested snapshot yet")));
        };
        let proj_id = sync::projected(hub, project, viewer, real).await?;
        let mut out = vec![real];
        if let Some(r) = resolve_snapshot(hub, project, viewer, &proj_id).await? {
            if !out.contains(&r) {
                out.push(r);
            }
        }
        return Ok((proj_id, out));
    }
    if rev.len() == 64 {
        if let Ok(id) = ObjectId::from_hex(rev) {
            let Some(real) = resolve_snapshot(hub, project, viewer, &id).await? else {
                return Err(Error::not_found("no such revision that you can see"));
            };
            let mut out = vec![real];
            if let Some(tip) = branch_tip(hub, project, viewer, &project.default_branch).await? {
                if !out.contains(&tip) && sync::projected(hub, project, viewer, tip).await? == id {
                    out.push(tip);
                }
            }
            return Ok((id, out));
        }
    }
    let Some(tip) = branch_tip(hub, project, viewer, rev).await? else {
        return Err(Error::not_found("no such revision that you can see"));
    };
    let proj_id = sync::projected(hub, project, viewer, tip).await?;
    let mut out = vec![tip];
    if let Some(r) = resolve_snapshot(hub, project, viewer, &proj_id).await? {
        if !out.contains(&r) {
            out.push(r);
        }
    }
    Ok((proj_id, out))
}

async fn branch_tip(hub: &Arc<Hub>, project: &Project, viewer: &Viewer, branch: &str) -> Result<Option<ObjectId>> {
    let target: Option<String> = sqlx::query_scalar(
        "SELECT target FROM branches WHERE project_id = $1 AND name = $2 AND hidden_for_embargo IS NULL",
    )
    .bind(project.id)
    .bind(branch)
    .fetch_optional(&hub.db)
    .await?;
    let Some(real) = target.and_then(|t| ObjectId::from_hex(&t).ok()) else {
        return Ok(None);
    };
    if crate::embargo::is_withheld_from_viewer(hub, project, viewer, &real).await? {
        return Ok(None);
    }
    Ok(Some(real))
}

/// Most first-parent steps walked above `<branch>@tested` (or the root) when
/// evaluating `<branch>@tested`.
const MAX_TESTED_WALK: usize = 1024;

/// Re-evaluate `<branch>@tested` for every branch of `project`, advancing
/// `tested` monotonically to the newest snapshot on the branch's
/// first-parent chain whose required checks have all passed.
pub async fn advance_tested(hub: &Arc<Hub>, project: &Project) -> Result<()> {
    let branches: Vec<(String, String, i64)> =
        sqlx::query_as("SELECT name, target, lineage FROM branches WHERE project_id = $1 AND hidden_for_embargo IS NULL ORDER BY name")
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

    let cur_tested: Vec<(String, i64, String, i64)> =
        sqlx::query_as("SELECT branch, lineage, snapshot, depth FROM tested WHERE project_id = $1")
            .bind(project.id)
            .fetch_all(&hub.db)
            .await?;
    let cur_map: BTreeMap<String, (i64, ObjectId, i64)> = cur_tested
        .into_iter()
        .filter_map(|(b, l, s, d)| Some((b, (l, ObjectId::from_hex(&s).ok()?, d))))
        .collect();

    // Walk first-parent chains in `blocking`: for each branch, collect the
    // snapshots from `target` down to `cur_tested` (with their exact
    // first-parent depth from `sync::root_snapshot_id()`).
    let branches_for_walk = branches.clone();
    let cur_for_walk = cur_map.clone();
    let (rules, chains) = sync::blocking(hub, project.id, move |src| {
        let rules = crate::landing::rules(src, default_tip)?;
        let root = sync::root_snapshot_id();
        let mut chains: BTreeMap<String, (i64, Vec<(ObjectId, i64)>)> = BTreeMap::new();
        for (name, target_hex, lineage) in branches_for_walk {
            let Ok(target) = ObjectId::from_hex(&target_hex) else { continue };
            let stop_at = cur_for_walk.get(&name).and_then(|(l, s, d)| (*l == lineage).then_some((*s, *d)));
            let mut above = Vec::new();
            let mut cur = target;
            let mut base_depth = None;
            loop {
                if let Some((stop_snap, stop_depth)) = stop_at {
                    if cur == stop_snap {
                        base_depth = Some(stop_depth);
                        break;
                    }
                }
                if cur == root {
                    base_depth = Some(0);
                    break;
                }
                if above.len() >= MAX_TESTED_WALK {
                    break;
                }
                let Ok(snap) = src.snapshot(&cur) else { break };
                above.push(cur);
                match snap.parents.first().copied() {
                    Some(p) => cur = p,
                    None => {
                        base_depth = Some(0);
                        break;
                    }
                }
            }
            if let Some(d0) = base_depth {
                // `above` is newest first (`target` at index 0, child of
                // `stop` at `above.len() - 1`).
                let len = above.len() as i64;
                let with_depths: Vec<(ObjectId, i64)> = above
                    .into_iter()
                    .enumerate()
                    .map(|(i, id)| (id, d0 + (len - i as i64)))
                    .collect();
                chains.insert(name, (lineage, with_depths));
            }
        }
        Ok((rules, chains))
    })
    .await?;

    let mut all_cands: HashSet<String> = HashSet::new();
    for (_, chain) in chains.values() {
        for (id, _) in chain {
            all_cands.insert(id.hex());
        }
    }
    if all_cands.is_empty() {
        return Ok(());
    }
    let cand_vec: Vec<String> = all_cands.into_iter().collect();
    type CheckRow = (String, String, String, i64, String, bool);
    let check_rows: Vec<CheckRow> = sqlx::query_as(
        "SELECT snapshot, name, state, runner_id, session_paths, admin_only FROM checks WHERE project_id = $1 AND snapshot = ANY($2)",
    )
    .bind(project.id)
    .bind(&cand_vec)
    .fetch_all(&hub.db)
    .await?;

    let people: Vec<i64> = check_rows.iter().map(|r| r.3).collect::<HashSet<_>>().into_iter().collect();
    let roles = if people.is_empty() {
        BTreeMap::new()
    } else {
        let mut conn = hub.db.acquire().await?;
        load_poster_roles(&mut conn, project.id, &people).await?
    };

    let mut by_snap: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    for (snap, name, state, runner_id, paths_json, admin_only) in check_rows {
        let (adm, grps) = roles.get(&runner_id).cloned().unwrap_or_default();
        let paths: Vec<String> = serde_json::from_str(&paths_json).unwrap_or_default();
        if !stored_check_counts(project, runner_id, adm, &grps, &paths, admin_only, &rules, &name) {
            continue;
        }
        by_snap.entry(snap).or_default().insert(name, state);
    }

    let now = veil_core::now_millis();
    for (branch, (lineage, chain)) in chains {
        let Some(reqs) = rules.required_checks.get(&branch).filter(|r| !r.is_empty()) else {
            continue;
        };
        // `chain` is newest first (`target` first): pick the first snapshot
        // whose required checks all passed.
        let passed = chain.into_iter().find(|(id, _)| {
            let Some(states) = by_snap.get(&id.hex()) else { return false };
            reqs.iter().all(|r| states.get(r).map(String::as_str) == Some("pass"))
        });
        if let Some((winner, depth)) = passed {
            sqlx::query(
                "INSERT INTO tested (project_id, branch, lineage, snapshot, depth, updated_at) \
                 VALUES ($1, $2, $3, $4, $5, $6) \
                 ON CONFLICT (project_id, branch) DO UPDATE \
                 SET lineage = EXCLUDED.lineage, \
                     snapshot = EXCLUDED.snapshot, \
                     depth = EXCLUDED.depth, \
                     updated_at = EXCLUDED.updated_at \
                 WHERE (tested.lineage = EXCLUDED.lineage AND tested.depth < EXCLUDED.depth) \
                    OR (tested.lineage < EXCLUDED.lineage AND tested.depth < EXCLUDED.depth)",
            )
            .bind(project.id)
            .bind(&branch)
            .bind(lineage)
            .bind(winner.hex())
            .bind(depth)
            .bind(now)
            .execute(&hub.db)
            .await?;
        }
    }
    Ok(())
}

/// `.veilrules` on `project`'s default branch.
pub(crate) async fn default_branch_rules(hub: &Arc<Hub>, project: &Project) -> Result<crate::landing::rules::Rules> {
    let target: Option<String> = sqlx::query_scalar(
        "SELECT target FROM branches WHERE project_id = $1 AND name = $2 AND hidden_for_embargo IS NULL",
    )
    .bind(project.id)
    .bind(&project.default_branch)
    .fetch_optional(&hub.db)
    .await?;
    let tip = target.and_then(|t| ObjectId::from_hex(&t).ok());
    sync::blocking(hub, project.id, move |src| crate::landing::rules(src, tip)).await
}

/// May `viewer` (a person, agent, or CI runner session) post authoritative
/// results for `check_name` — results that count toward `<branch>@tested`,
/// bisect, and automatic revert?
///
/// Allowed when the caller's person (narrowed by `viewer.only`, if any) may
/// write every path `[checks.<check_name>].paths` names, or is an unnarrowed
/// admin when the check names no paths (so it covers the whole tree). CI
/// runner sessions (`Caller::is_runner`) keep their minting person's write
/// scope (`for_agent(false)`), even though code-writing routes refuse them.
pub(crate) fn can_post_check_results(
    project: &Project,
    viewer: &Viewer,
    rules: &crate::landing::rules::Rules,
    check_name: &str,
) -> bool {
    let write_view = project.view(viewer).for_agent(false);
    match rules.checks.get(check_name).filter(|p| !p.is_empty()) {
        Some(paths) => paths.iter().all(|p| write_view.write(p)),
        None => viewer.admin && viewer.only.is_none(),
    }
}

/// Whether a stored `checks` row (recorded by `poster_id` with
/// `(session_paths, admin_only)`) counts under the current permissions and
/// `rules`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn stored_check_counts(
    project: &Project,
    poster_id: i64,
    poster_admin: bool,
    poster_groups: &HashSet<i64>,
    session_paths: &[String],
    admin_only: bool,
    rules: &crate::landing::rules::Rules,
    check_name: &str,
) -> bool {
    let v = Viewer {
        person: Some(poster_id),
        admin: poster_admin,
        groups: poster_groups.clone(),
        only: (!admin_only).then(|| Arc::new(session_paths.to_vec())),
        agent: false,
    };
    can_post_check_results(project, &v, rules, check_name)
}

/// Current `(admin, groups)` in `project_id` for `people`.
pub(crate) async fn load_poster_roles(
    c: &mut sqlx::PgConnection,
    project_id: i64,
    people: &[i64],
) -> Result<BTreeMap<i64, (bool, HashSet<i64>)>> {
    let mut out: BTreeMap<i64, (bool, HashSet<i64>)> = people.iter().map(|&p| (p, (false, HashSet::new()))).collect();
    if people.is_empty() {
        return Ok(out);
    }
    let admins: Vec<i64> =
        sqlx::query_scalar("SELECT person_id FROM project_admins WHERE project_id = $1 AND person_id = ANY($2)")
            .bind(project_id)
            .bind(people)
            .fetch_all(&mut *c)
            .await?;
    for a in admins {
        if let Some(entry) = out.get_mut(&a) {
            entry.0 = true;
        }
    }
    let members: Vec<(i64, i64)> = sqlx::query_as(
        "SELECT m.person_id, m.group_id FROM group_members m JOIN groups g ON g.id = m.group_id \
         WHERE g.project_id = $1 AND m.person_id = ANY($2)",
    )
    .bind(project_id)
    .bind(people)
    .fetch_all(&mut *c)
    .await?;
    for (p, g) in members {
        if let Some(entry) = out.get_mut(&p) {
            entry.1.insert(g);
        }
    }
    Ok(out)
}
