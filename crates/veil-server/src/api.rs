//! The HTTPS routes (`docs/HUB.md` §4; [`veil_core::hub::wire`]).

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::header,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use sqlx::PgConnection;
use veil_core::{
    hub::wire::{vouch_valid, AccessInfo, Devices, FetchRequest, GroupChange, GroupInfo, HistoryRequest, PushRequest, PushResult, Tips, Vouch, VouchRequest, MAX_WANTS},
    keychain::{validate_scope_name, KeyRing, Keychain, RingMerge},
    policy::valid_principal_name,
    MemoryBackend, StorageBackend, VPath,
};

use crate::{
    auth::{self, Caller},
    error::{Error, Result},
    perm::{self, Binding, Project, Viewer},
    sync, HubState,
};

pub fn router(hub: HubState) -> Router {
    Router::new()
        .route("/v1/auth/challenge", post(auth::challenge))
        .route("/v1/auth/login", post(auth::login))
        .route("/v1/people/{name}/devices", get(devices))
        .route("/v1/devices/vouch", post(vouch))
        .route("/v1/projects/{p}", post(create_project))
        .route("/v1/projects/{p}/tips", get(tips))
        .route("/v1/projects/{p}/history", post(history))
        .route("/v1/projects/{p}/fetch", post(fetch))
        .route("/v1/projects/{p}/objects", post(objects).layer(DefaultBodyLimit::max(2 << 30)))
        .route("/v1/projects/{p}/push", post(push))
        .route("/v1/projects/{p}/access", get(access))
        .route("/v1/projects/{p}/groups", get(list_groups))
        .route("/v1/projects/{p}/groups/{g}", post(create_group).delete(delete_group))
        .route("/v1/projects/{p}/groups/{g}/members", post(add_members))
        .route("/v1/projects/{p}/groups/{g}/members/remove", post(remove_members))
        .route("/v1/projects/{p}/groups/{g}/managers", post(add_managers))
        .route("/v1/projects/{p}/rings", get(get_rings))
        .route("/v1/projects/{p}/rings/{scope}", post(post_ring))
        .layer(DefaultBodyLimit::max(64 << 20))
        .with_state(hub)
}

fn frames(body: Vec<u8>) -> Response {
    ([(header::CONTENT_TYPE, "application/octet-stream")], body).into_response()
}

async fn devices(State(hub): State<HubState>, caller: Caller, Path(name): Path<String>) -> Result<Json<Devices>> {
    caller.signed_in()?;
    device_list(&hub, &name).await
}

/// A person's devices with the vouches the server stores. The server's
/// list is not what wraps a key: admins' `vl` check the vouches
/// (`docs/HUB.md` §13.11).
async fn device_list(hub: &HubState, name: &str) -> Result<Json<Devices>> {
    let rows: Vec<(String, bool)> = sqlx::query_as(
        "SELECT d.public_identity, d.pending FROM devices d JOIN people p ON p.id = d.person_id \
         WHERE p.name = $1 AND d.removed_at IS NULL ORDER BY d.id",
    )
    .bind(name)
    .fetch_all(&hub.db)
    .await?;
    if rows.is_empty() {
        return Err(Error::not_found(format!("no person named '{name}'")));
    }
    let vouches: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT d.public_identity, v.voucher_key, v.signature FROM device_vouches v JOIN devices d ON d.id = v.device_id \
         JOIN people p ON p.id = d.person_id WHERE p.name = $1 AND d.removed_at IS NULL ORDER BY d.id, v.voucher_key",
    )
    .bind(name)
    .fetch_all(&hub.db)
    .await?;
    let (pending, active): (Vec<_>, Vec<_>) = rows.into_iter().partition(|(_, p)| *p);
    Ok(Json(Devices {
        person: name.to_string(),
        identities: active.into_iter().map(|(i, _)| i).collect(),
        pending: pending.into_iter().map(|(i, _)| i).collect(),
        vouches: vouches.into_iter().map(|(device, by, signature)| Vouch { device, by, signature }).collect(),
    }))
}

/// The signed-in device vouches for another device of its person: the
/// device becomes active (a pending one may then sign in).
async fn vouch(State(hub): State<HubState>, caller: Caller, Json(req): Json<VouchRequest>) -> Result<Json<Devices>> {
    let me = caller.signed_in()?.clone();
    let v = Vouch {
        device: req.device.clone(),
        by: me.device_key.clone(),
        signature: req.signature,
    };
    if !vouch_valid(&v) {
        return Err(Error::bad_request("the vouch does not verify under this device's key"));
    }
    let person = me.id;
    let n = crate::db::serializable(&hub.db, move |c| {
        let v = v.clone();
        Box::pin(async move {
            let device: Option<i64> = sqlx::query_scalar(
                "SELECT id FROM devices WHERE person_id = $1 AND public_identity = $2 AND removed_at IS NULL",
            )
            .bind(person)
            .bind(&v.device)
            .fetch_optional(&mut *c)
            .await?;
            let Some(device) = device else {
                return Err(Error::not_found("no device of yours with that identity"));
            };
            sqlx::query(
                "INSERT INTO device_vouches (device_id, voucher_key, signature, created_at) VALUES ($1, $2, $3, $4) \
                 ON CONFLICT (device_id, voucher_key) DO NOTHING",
            )
            .bind(device)
            .bind(&v.by)
            .bind(&v.signature)
            .bind(veil_core::now_millis())
            .execute(&mut *c)
            .await?;
            sqlx::query("UPDATE devices SET pending = FALSE WHERE id = $1").bind(device).execute(&mut *c).await?;
            Ok(device)
        })
    })
    .await?;
    crate::audit(&hub.db, None, Some(me.id), "vouch for device", &format!("device {n}")).await;
    device_list(&hub, &me.name).await
}

async fn create_project(State(hub): State<HubState>, caller: Caller, Path(name): Path<String>) -> Result<Json<Tips>> {
    let me = caller.signed_in()?.clone();
    if !perm::valid_project_name(&name) {
        return Err(Error::bad_request("a project name is 1 to 64 lowercase letters, digits, '-', '_' or '.'"));
    }
    let n = name.clone();
    crate::db::serializable(&hub.db, move |c| {
        let n = n.clone();
        Box::pin(async move {
            let exists: Option<i64> = sqlx::query_scalar("SELECT id FROM projects WHERE name = $1").bind(&n).fetch_optional(&mut *c).await?;
            if exists.is_some() {
                return Err(Error::conflict(format!("a project named '{n}' exists")));
            }
            // The creator is the admin; everything is private (no rules).
            let id: i64 = sqlx::query_scalar(
                "INSERT INTO projects (name, created_by, created_at, default_branch, policy_text, policy_bindings, policy_version) \
                 VALUES ($1, $2, $3, 'main', '', '{}', 0) RETURNING id",
            )
            .bind(&n)
            .bind(me.id)
            .bind(veil_core::now_millis())
            .fetch_one(&mut *c)
            .await?;
            sqlx::query("INSERT INTO project_admins (project_id, person_id) VALUES ($1, $2)")
                .bind(id)
                .bind(me.id)
                .execute(&mut *c)
                .await?;
            Ok(())
        })
    })
    .await?;
    crate::audit(&hub.db, None, caller.person.as_ref().map(|p| p.id), "create project", &name).await;
    tips(State(hub), caller, Path(name)).await
}

async fn tips(State(hub): State<HubState>, caller: Caller, Path(p): Path<String>) -> Result<Json<Tips>> {
    let (project, viewer) = perm::open(&hub.db, &p, &caller).await?;
    let branches = sync::tips(&hub, &project, &viewer).await?.into_iter().collect();
    Ok(Json(Tips {
        branches,
        default_branch: project.default_branch,
        you: caller.person.map(|p| p.name),
        admin: viewer.admin,
    }))
}

async fn history(State(hub): State<HubState>, caller: Caller, Path(p): Path<String>, Json(req): Json<HistoryRequest>) -> Result<Response> {
    let (project, viewer) = perm::open(&hub.db, &p, &caller).await?;
    Ok(frames(sync::history(&hub, &project, &viewer, &req.tips, &req.stop).await?))
}

async fn fetch(State(hub): State<HubState>, caller: Caller, Path(p): Path<String>, Json(req): Json<FetchRequest>) -> Result<Response> {
    if req.objects.len() > MAX_WANTS {
        return Err(Error::bad_request(format!("at most {MAX_WANTS} objects per request")));
    }
    let (project, viewer) = perm::open(&hub.db, &p, &caller).await?;
    Ok(frames(sync::fetch(&hub, &project, &viewer, req.snapshot, req.objects).await?))
}

async fn objects(State(hub): State<HubState>, caller: Caller, Path(p): Path<String>, body: Bytes) -> Result<Json<veil_core::hub::wire::Uploaded>> {
    let me = caller.signed_in()?.id;
    let (project, viewer) = perm::open(&hub.db, &p, &caller).await?;
    if !project.participant(&viewer) {
        return Err(Error::forbidden("you are not in this project"));
    }
    let receipts = sync::upload(&hub, project.id, me, body).await?;
    Ok(Json(veil_core::hub::wire::Uploaded {
        stored: receipts.len(),
        receipts,
    }))
}

async fn push(State(hub): State<HubState>, caller: Caller, Path(p): Path<String>, Json(req): Json<PushRequest>) -> Result<Json<PushResult>> {
    let me = caller.signed_in()?.id;
    let (project, viewer) = perm::open(&hub.db, &p, &caller).await?;
    Ok(Json(sync::push(&hub, &project, &viewer, me, req).await?))
}

#[derive(Deserialize)]
struct PathQuery {
    path: String,
}

async fn names_of(c: &mut PgConnection, table: &str, id: i64) -> Result<Vec<String>> {
    let q = match table {
        "group_members" => "SELECT p.name FROM group_members m JOIN people p ON p.id = m.person_id WHERE m.group_id = $1 ORDER BY p.name",
        "group_managers" => "SELECT p.name FROM group_managers m JOIN people p ON p.id = m.person_id WHERE m.group_id = $1 ORDER BY p.name",
        _ => "SELECT p.name FROM project_admins a JOIN people p ON p.id = a.person_id WHERE a.project_id = $1 ORDER BY p.name",
    };
    Ok(sqlx::query_scalar(q).bind(id).fetch_all(&mut *c).await?)
}

/// Who may see `path`, and which rule decides. Only a participant who may
/// read the path gets an answer.
async fn access(State(hub): State<HubState>, caller: Caller, Path(p): Path<String>, Query(q): Query<PathQuery>) -> Result<Json<AccessInfo>> {
    let (project, viewer) = perm::open(&hub.db, &p, &caller).await?;
    let path = q.path.trim_matches('/').to_string();
    let view = project.view(&viewer);
    // Who has access names groups and people: for the project's own
    // participants only, and only for a path they may read.
    if !project.participant(&viewer) || !view.read(&path) {
        return Err(Error::not_found("no such path that you can see"));
    }
    let mut c = hub.db.acquire().await?;
    let admins = names_of(&mut c, "admins", project.id).await?;
    let rule = project.policy.deciding(&path).map(|i| &project.policy.rules[i]);
    let (mut groups, mut people) = (Vec::new(), Vec::new());
    if let Some(r) = rule {
        for n in &r.names {
            match project.bindings.get(n) {
                Some(Binding::Group(_)) => groups.push(n.clone()),
                Some(Binding::Person(_)) => people.push(n.clone()),
                None => {}
            }
        }
    }
    Ok(Json(AccessInfo {
        path: path.clone(),
        rule: rule.map(|r| format!("{}/", r.path)),
        line: rule.map(|r| r.line),
        public: rule.is_some_and(|r| r.public),
        groups,
        people,
        admins,
        you_write: view.write(&path),
    }))
}

async fn group_id(c: &mut PgConnection, project: i64, name: &str) -> Result<i64> {
    let id: Option<i64> = sqlx::query_scalar("SELECT id FROM groups WHERE project_id = $1 AND name = $2")
        .bind(project)
        .bind(name)
        .fetch_optional(&mut *c)
        .await?;
    id.ok_or_else(|| Error::not_found(format!("no group '{name}'")))
}

async fn group_info(c: &mut PgConnection, project: i64, name: &str) -> Result<GroupInfo> {
    let g = group_id(c, project, name).await?;
    Ok(GroupInfo {
        name: name.to_string(),
        members: names_of(c, "group_members", g).await?,
        managers: names_of(c, "group_managers", g).await?,
    })
}

async fn list_groups(State(hub): State<HubState>, caller: Caller, Path(p): Path<String>) -> Result<Json<Vec<GroupInfo>>> {
    let me = caller.signed_in()?.id;
    let (project, viewer) = perm::open(&hub.db, &p, &caller).await?;
    let mut c = hub.db.acquire().await?;
    let names: Vec<String> = sqlx::query_scalar("SELECT name FROM groups WHERE project_id = $1 ORDER BY name")
        .bind(project.id)
        .fetch_all(&mut *c)
        .await?;
    let mut out = Vec::new();
    for n in names {
        let info = group_info(&mut c, project.id, &n).await?;
        // Admins see every group; others the groups they are in or manage.
        let mine = info.members.iter().chain(&info.managers).any(|m| caller.person.as_ref().is_some_and(|p| &p.name == m));
        if viewer.admin || mine {
            out.push(info);
        }
    }
    let _ = me;
    Ok(Json(out))
}

fn require_admin(viewer: &Viewer) -> Result<()> {
    if viewer.admin {
        Ok(())
    } else {
        Err(Error::forbidden("only an admin of this project may do that"))
    }
}

async fn create_group(State(hub): State<HubState>, caller: Caller, Path((p, g)): Path<(String, String)>) -> Result<Json<GroupInfo>> {
    let me = caller.signed_in()?.id;
    let (project, viewer) = perm::open(&hub.db, &p, &caller).await?;
    require_admin(&viewer)?;
    if !valid_principal_name(&g) {
        return Err(Error::bad_request("a group name is 1 to 64 lowercase letters, digits, '-', '_' or '.', and not a tier word"));
    }
    let pid = project.id;
    let g2 = g.clone();
    let info = crate::db::serializable(&hub.db, move |c| {
        let g = g2.clone();
        Box::pin(async move {
            let r = sqlx::query("INSERT INTO groups (project_id, name) VALUES ($1, $2) ON CONFLICT DO NOTHING")
                .bind(pid)
                .bind(&g)
                .execute(&mut *c)
                .await?;
            if r.rows_affected() == 0 {
                return Err(Error::conflict(format!("group '{g}' exists")));
            }
            // A group always wins: an accepted access line naming it now
            // names this group, never the person who signed up under its
            // name, nor a deleted group of that name.
            let gid = group_id(c, pid, &g).await?;
            let text: String = sqlx::query_scalar("SELECT policy_bindings FROM projects WHERE id = $1").bind(pid).fetch_one(&mut *c).await?;
            let mut bindings: std::collections::BTreeMap<String, Binding> = serde_json::from_str(&text).unwrap_or_default();
            if let Some(b) = bindings.get_mut(&g) {
                *b = Binding::Group(gid);
                sqlx::query("UPDATE projects SET policy_bindings = $1 WHERE id = $2")
                    .bind(serde_json::to_string(&bindings).map_err(|e| Error::Other(e.into()))?)
                    .bind(pid)
                    .execute(&mut *c)
                    .await?;
            }
            group_info(c, pid, &g).await
        })
    })
    .await?;
    crate::audit(&hub.db, Some(pid), Some(me), "group create", &g).await;
    Ok(Json(info))
}

async fn delete_group(State(hub): State<HubState>, caller: Caller, Path((p, g)): Path<(String, String)>) -> Result<Json<GroupInfo>> {
    let me = caller.signed_in()?.id;
    let (project, viewer) = perm::open(&hub.db, &p, &caller).await?;
    require_admin(&viewer)?;
    let pid = project.id;
    let g2 = g.clone();
    let info = crate::db::serializable(&hub.db, move |c| {
        let g = g2.clone();
        Box::pin(async move {
            let info = group_info(c, pid, &g).await?;
            let id = group_id(c, pid, &g).await?;
            for t in ["DELETE FROM group_members WHERE group_id = $1", "DELETE FROM group_managers WHERE group_id = $1", "DELETE FROM groups WHERE id = $1"] {
                sqlx::query(t).bind(id).execute(&mut *c).await?;
            }
            Ok(info)
        })
    })
    .await?;
    crate::audit(&hub.db, Some(pid), Some(me), "group delete", &g).await;
    Ok(Json(info))
}

/// The ids of `names` (people), or which one does not exist.
async fn people_ids(c: &mut PgConnection, names: &[String]) -> Result<Vec<(String, i64)>> {
    let mut out = Vec::new();
    for n in names {
        let id: Option<i64> = sqlx::query_scalar("SELECT id FROM people WHERE name = $1").bind(n).fetch_optional(&mut *c).await?;
        out.push((n.clone(), id.ok_or_else(|| Error::not_found(format!("no person named '{n}'")))?));
    }
    Ok(out)
}

#[derive(Clone, Copy, PartialEq)]
enum Op {
    AddMember,
    RemoveMember,
    AddManager,
}

/// Change a group's people. Members: admins and the group's managers, but
/// a manager never adds themselves (an admin does). Managers: admins.
async fn change_group(hub: HubState, caller: Caller, p: String, g: String, op: Op, req: GroupChange) -> Result<Json<GroupInfo>> {
    let me = caller.signed_in()?.id;
    let (project, viewer) = perm::open(&hub.db, &p, &caller).await?;
    let pid = project.id;
    let admin = viewer.admin;
    let (g2, people) = (g.clone(), req.people.clone());
    let info = crate::db::serializable(&hub.db, move |c| {
        let (g, people) = (g2.clone(), people.clone());
        Box::pin(async move {
            let gid = group_id(c, pid, &g).await?;
            let manager = perm::is_manager(c, gid, me).await?;
            let ids = people_ids(c, &people).await?;
            match op {
                Op::AddManager if !admin => return Err(Error::forbidden("only an admin may choose a group's managers")),
                Op::AddMember | Op::RemoveMember if !admin && !manager => {
                    return Err(Error::forbidden(format!("only an admin or a manager of '{g}' may change its people")))
                }
                Op::AddMember if !admin && ids.iter().any(|(_, id)| *id == me) => {
                    return Err(Error::forbidden("managers add other people; ask an admin to add you"))
                }
                _ => {}
            }
            for (_, id) in &ids {
                let q = match op {
                    Op::AddMember => "INSERT INTO group_members (group_id, person_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                    Op::RemoveMember => "DELETE FROM group_members WHERE group_id = $1 AND person_id = $2",
                    Op::AddManager => "INSERT INTO group_managers (group_id, person_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                };
                sqlx::query(q).bind(gid).bind(id).execute(&mut *c).await?;
            }
            group_info(c, pid, &g).await
        })
    })
    .await?;
    let what = match op {
        Op::AddMember => "group add",
        Op::RemoveMember => "group remove",
        Op::AddManager => "group manager",
    };
    crate::audit(&hub.db, Some(pid), Some(me), what, &format!("{g}: {:?}", req.people)).await;
    Ok(Json(info))
}

async fn add_members(State(hub): State<HubState>, caller: Caller, Path((p, g)): Path<(String, String)>, Json(req): Json<GroupChange>) -> Result<Json<GroupInfo>> {
    change_group(hub, caller, p, g, Op::AddMember, req).await
}

async fn remove_members(State(hub): State<HubState>, caller: Caller, Path((p, g)): Path<(String, String)>, Json(req): Json<GroupChange>) -> Result<Json<GroupInfo>> {
    change_group(hub, caller, p, g, Op::RemoveMember, req).await
}

async fn add_managers(State(hub): State<HubState>, caller: Caller, Path((p, g)): Path<(String, String)>, Json(req): Json<GroupChange>) -> Result<Json<GroupInfo>> {
    change_group(hub, caller, p, g, Op::AddManager, req).await
}

/// Key rings of secret scopes. Only participants read them (they name the
/// scope's members). The server cannot open them and is not their
/// authority: each change is signed by a ring admin's device and verified
/// by every reader; the server only keeps the longest log that verifies.
async fn get_rings(State(hub): State<HubState>, caller: Caller, Path(p): Path<String>) -> Result<Json<Vec<serde_json::Value>>> {
    caller.signed_in()?;
    let (project, viewer) = perm::open(&hub.db, &p, &caller).await?;
    if !project.participant(&viewer) {
        return Err(Error::forbidden("you are not in this project"));
    }
    let bodies: Vec<String> = sqlx::query_scalar("SELECT body FROM rings WHERE project_id = $1 ORDER BY scope")
        .bind(project.id)
        .fetch_all(&hub.db)
        .await?;
    Ok(Json(bodies.iter().filter_map(|b| serde_json::from_str(b).ok()).collect()))
}

async fn post_ring(
    State(hub): State<HubState>,
    caller: Caller,
    Path((p, scope)): Path<(String, String)>,
    Json(ring): Json<KeyRing>,
) -> Result<Json<serde_json::Value>> {
    caller.signed_in()?;
    let (project, viewer) = perm::open(&hub.db, &p, &caller).await?;
    if !project.participant(&viewer) {
        return Err(Error::forbidden("you are not in this project"));
    }
    validate_scope_name(&scope).map_err(|e| Error::bad_request(e.to_string()))?;
    if ring.scope != scope {
        return Err(Error::bad_request("the ring is for another scope"));
    }
    // Whoever starts a ring is its admin and holds its key: only an admin
    // of the project starts one. Later changes verify against the ring's
    // own signed log (`merge_ring`).
    if !viewer.admin {
        let exists: Option<i32> = sqlx::query_scalar("SELECT 1 FROM rings WHERE project_id = $1 AND scope = $2")
            .bind(project.id)
            .bind(&scope)
            .fetch_optional(&hub.db)
            .await?;
        if exists.is_none() {
            return Err(Error::forbidden(format!("only an admin of this project starts a key ring (scope '{scope}')")));
        }
    }
    merge_ring(&hub, &project, ring).await
}

/// Merge `ring` into the stored ring: read, merge in memory with the
/// engine's own replay (it verifies every change), then write with a
/// one-row compare-and-swap on the old body, again if someone else wrote
/// first. No serialisable transaction: YugabyteDB reports range conflicts
/// between unrelated projects' rings as deadlocks.
async fn merge_ring(hub: &HubState, project: &Project, ring: KeyRing) -> Result<Json<serde_json::Value>> {
    let pid = project.id;
    for _ in 0..50 {
        let current: Option<String> = sqlx::query_scalar("SELECT body FROM rings WHERE project_id = $1 AND scope = $2")
            .bind(pid)
            .bind(&ring.scope)
            .fetch_optional(&hub.db)
            .await?;
        let merged = {
            let mem = Arc::new(MemoryBackend::new());
            let path = VPath::new(&format!(".veil/meta/keyrings/{}.json", ring.scope)).map_err(Error::from)?;
            if let Some(b) = &current {
                mem.write(&path, b.as_bytes()).map_err(Error::from)?;
            }
            let keys = Keychain::new(mem.clone(), None, "hub".into());
            keys.set_format(veil_core::repo::REPO_FORMAT);
            match keys.merge_ring(&ring).map_err(Error::from)? {
                RingMerge::Rejected(why) => return Err(Error::conflict(why)),
                RingMerge::Unchanged => None,
                RingMerge::Updated => Some(String::from_utf8(mem.read(&path).map_err(Error::from)?).map_err(|e| Error::Other(e.into()))?),
            }
        };
        let Some(body) = merged else {
            return Ok(Json(current.and_then(|b| serde_json::from_str(&b).ok()).unwrap_or(serde_json::Value::Null)));
        };
        let rows = match &current {
            None => sqlx::query("INSERT INTO rings (project_id, scope, body) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING")
                .bind(pid)
                .bind(&ring.scope)
                .bind(&body)
                .execute(&hub.db)
                .await?
                .rows_affected(),
            Some(old) => sqlx::query("UPDATE rings SET body = $1 WHERE project_id = $2 AND scope = $3 AND body = $4")
                .bind(&body)
                .bind(pid)
                .bind(&ring.scope)
                .bind(old)
                .execute(&hub.db)
                .await?
                .rows_affected(),
        };
        if rows == 1 {
            return Ok(Json(serde_json::from_str(&body).unwrap_or(serde_json::Value::Null)));
        }
    }
    Err(Error::conflict("the key ring kept changing; try again"))
}
