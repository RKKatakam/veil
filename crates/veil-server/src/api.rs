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
    hub::wire::{
        join_valid, vouch_valid, AccessInfo, Devices, FetchRequest, GroupChange, GroupInfo, HistoryRequest, InviteRequest, Join, JoinRequest,
        Joined, PendingDevice, PushRequest, PushResult, RemoveDevice, Tips, Vouch, VouchRequest, MAX_WANTS,
    },
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
        .route("/v1/people/{name}/pending/{fingerprint}", get(pending_device))
        .route("/v1/devices/vouch", post(vouch))
        .route("/v1/devices/remove", post(remove_device))
        .route("/v1/projects/{p}/invites", post(create_invite))
        .route("/v1/projects/{p}/invites/join", post(join))
        .route("/v1/projects/{p}/keys/pending", get(pending_keys))
        .route("/v1/projects/{p}", post(create_project))
        .route("/v1/projects/{p}/tips", get(tips))
        .route("/v1/projects/{p}/history", post(history))
        .route("/v1/projects/{p}/fetch", post(fetch))
        .route("/v1/projects/{p}/objects", post(objects).layer(DefaultBodyLimit::max(crate::db::body_limit("/objects"))))
        .route("/v1/projects/{p}/push", post(push))
        .route("/v1/projects/{p}/access", get(access))
        .route("/v1/projects/{p}/groups", get(list_groups))
        .route("/v1/projects/{p}/groups/{g}", post(create_group).delete(delete_group))
        .route("/v1/projects/{p}/groups/{g}/members", post(add_members))
        .route("/v1/projects/{p}/groups/{g}/members/remove", post(remove_members))
        .route("/v1/projects/{p}/groups/{g}/managers", post(add_managers))
        .route("/v1/projects/{p}/rings", get(get_rings))
        .route("/v1/projects/{p}/rings/{scope}", post(post_ring).get(get_ring))
        .layer(DefaultBodyLimit::max(crate::db::body_limit("")))
        .layer(axum::middleware::from_fn(crate::db::retry_requests))
        .with_state(hub)
}

fn frames(body: Vec<u8>) -> Response {
    ([(header::CONTENT_TYPE, "application/octet-stream")], body).into_response()
}

async fn devices(State(hub): State<HubState>, caller: Caller, Path(name): Path<String>) -> Result<Json<Devices>> {
    caller.signed_in()?;
    device_list(&hub, &name, None).await
}

/// A person's devices with the vouches the server stores. The server's
/// list is not what wraps a key: admins' `vl` check the vouches
/// (`docs/HUB.md` §13.11). In `project`, a device an admin removed from it
/// is listed as removed (BUG-843), so its devices revoke it from its rings.
async fn device_list(hub: &HubState, name: &str, project: Option<i64>) -> Result<Json<Devices>> {
    let person: Option<i64> = sqlx::query_scalar("SELECT id FROM people WHERE name = $1").bind(name).fetch_optional(&hub.db).await?;
    let Some(person) = person else {
        return Err(Error::not_found(format!("no person named '{name}'")));
    };
    let barred = "EXISTS (SELECT 1 FROM device_bars b WHERE b.device_id = d.id AND b.project_id = $2)";
    let active: Vec<String> = sqlx::query_scalar(&format!(
        "SELECT d.public_identity FROM devices d WHERE d.person_id = $1 AND d.removed_at IS NULL AND NOT d.pending \
         AND NOT {barred} ORDER BY d.id"
    ))
    .bind(person)
    .bind(project.unwrap_or(-1))
    .fetch_all(&hub.db)
    .await?;
    // Only the newest few pending devices: anyone can make pending devices
    // under a name, so their number must not cost the person anything.
    let mut pending: Vec<String> = sqlx::query_scalar(
        "SELECT public_identity FROM devices WHERE person_id = $1 AND removed_at IS NULL AND pending ORDER BY id DESC LIMIT $2",
    )
    .bind(person)
    .bind(crate::auth::LISTED_PENDING)
    .fetch_all(&hub.db)
    .await?;
    pending.reverse();
    let vouches: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT d.public_identity, v.voucher_key, v.signature FROM device_vouches v JOIN devices d ON d.id = v.device_id \
         JOIN people p ON p.id = d.person_id WHERE p.name = $1 AND d.removed_at IS NULL AND NOT d.pending ORDER BY d.id, v.voucher_key",
    )
    .bind(name)
    .fetch_all(&hub.db)
    .await?;
    let joins: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT i.invite_key, d.public_identity, i.signature FROM invites i JOIN devices d ON d.id = i.device_id \
         JOIN people p ON p.id = d.person_id WHERE p.name = $1 AND d.removed_at IS NULL AND i.signature IS NOT NULL \
         ORDER BY i.used_at",
    )
    .bind(name)
    .fetch_all(&hub.db)
    .await?;
    let removed: Vec<String> = sqlx::query_scalar(&format!(
        "SELECT d.public_identity FROM devices d WHERE d.person_id = $1 AND NOT d.pending \
         AND (d.removed_at IS NOT NULL OR {barred}) ORDER BY d.id"
    ))
    .bind(person)
    .bind(project.unwrap_or(-1))
    .fetch_all(&hub.db)
    .await?;
    Ok(Json(Devices {
        person: name.to_string(),
        identities: active,
        pending,
        vouches: vouches.into_iter().map(|(device, by, signature)| Vouch { device, by, signature }).collect(),
        joins: joins.into_iter().map(|(key, device, signature)| Join { key, device, signature }).collect(),
        removed,
    }))
}

/// One of the caller's own pending devices, by fingerprint (`vl identity
/// confirm`): however many pending devices others made under the name, the
/// one the person reads off their new device is found (§13.12).
async fn pending_device(
    State(hub): State<HubState>,
    caller: Caller,
    Path((name, fingerprint)): Path<(String, String)>,
) -> Result<Json<PendingDevice>> {
    let me = caller.signed_in()?;
    let fp = veil_core::hub::wire::normalize_fingerprint(&fingerprint).ok_or_else(|| Error::bad_request("not a device fingerprint"))?;
    let found: Option<String> = if me.name == name {
        sqlx::query_scalar(
            "SELECT public_identity FROM devices WHERE person_id = $1 AND pending AND removed_at IS NULL \
             AND fingerprint = $2 AND created_at > $3 ORDER BY id DESC LIMIT 1",
        )
        .bind(me.id)
        .bind(&fp)
        .bind(veil_core::now_millis() - crate::auth::PENDING_TTL_MS)
        .fetch_optional(&hub.db)
        .await?
    } else {
        None
    };
    if let Some(identity) = found {
        return Ok(Json(PendingDevice { identity }));
    }
    if me.name == name {
        // Kept for the person: their device, signing in again, is never
        // pushed out by the bound on pending devices (auth.rs).
        let now = veil_core::now_millis();
        sqlx::query(
            "INSERT INTO device_expected (person_id, fingerprint, expires_at) VALUES ($1, $2, $3) \
             ON CONFLICT (person_id, fingerprint) DO UPDATE SET expires_at = EXCLUDED.expires_at",
        )
        .bind(me.id)
        .bind(&fp)
        .bind(now + crate::auth::EXPECTED_TTL_MS)
        .execute(&hub.db)
        .await?;
        sqlx::query(
            "DELETE FROM device_expected WHERE person_id = $1 AND (expires_at < $2 OR fingerprint NOT IN \
             (SELECT fingerprint FROM device_expected WHERE person_id = $1 ORDER BY expires_at DESC LIMIT $3))",
        )
        .bind(me.id)
        .bind(now)
        .bind(crate::auth::EXPECTED_PER_PERSON)
        .execute(&hub.db)
        .await?;
    }
    Err(Error::not_found(format!(
        "no device of yours waits with the fingerprint {fp}: sign in on it again (`vl login URL --name {name}`), then run \
         this again (it is kept for you for an hour)"
    )))
}

/// Queue "share keys for `person`" in `project`, or in every project they
/// take part in (an admin, or in a group): a hint for the devices that
/// share keys in the background (`GET …/keys/pending`), never a grant.
async fn queue_key_request(c: &mut PgConnection, person: i64, project: Option<i64>) -> Result<()> {
    let now = veil_core::now_millis();
    sqlx::query("DELETE FROM key_requests WHERE created_at < $1").bind(now - KEY_REQUEST_TTL_MS).execute(&mut *c).await?;
    let projects: Vec<i64> = match project {
        Some(p) => vec![p],
        None => sqlx::query_scalar(
            "SELECT project_id FROM project_admins WHERE person_id = $1 UNION \
             SELECT g.project_id FROM groups g JOIN group_members m ON m.group_id = g.id WHERE m.person_id = $1",
        )
        .bind(person)
        .fetch_all(&mut *c)
        .await?,
    };
    for p in projects {
        sqlx::query(
            "INSERT INTO key_requests (project_id, person_id, created_at) VALUES ($1, $2, $3) \
             ON CONFLICT (project_id, person_id) DO UPDATE SET created_at = EXCLUDED.created_at",
        )
        .bind(p)
        .bind(person)
        .bind(now)
        .execute(&mut *c)
        .await?;
    }
    Ok(())
}

/// How long a key request stays listed.
const KEY_REQUEST_TTL_MS: i64 = 7 * 24 * 3600 * 1000;
/// Longest an invite may be valid.
const MAX_INVITE_MS: i64 = 30 * 24 * 3600 * 1000;

/// The people whose devices may be waiting for keys in this project, with
/// their devices, vouches, joins and removed devices (participants only).
/// A hint: the device that shares decides from the key rings.
async fn pending_keys(State(hub): State<HubState>, caller: Caller, Path(p): Path<String>) -> Result<Json<Vec<Devices>>> {
    caller.signed_in()?;
    let (project, viewer) = perm::open(&hub.db, &p, &caller).await?;
    if !project.participant(&viewer) {
        return Err(Error::forbidden("you are not in this project"));
    }
    let names: Vec<String> = sqlx::query_scalar(
        "SELECT p.name FROM key_requests k JOIN people p ON p.id = k.person_id WHERE k.project_id = $1 AND k.created_at > $2 ORDER BY p.name",
    )
    .bind(project.id)
    .bind(veil_core::now_millis() - KEY_REQUEST_TTL_MS)
    .fetch_all(&hub.db)
    .await?;
    let mut out = Vec::new();
    for n in names {
        out.push(device_list(&hub, &n, Some(project.id)).await?.0);
    }
    Ok(Json(out))
}

/// Remove a device. Its person may, from another of their devices: it is
/// removed everywhere and its sessions end at once. An admin of `project`
/// in which the person takes part may remove it **from that project only**
/// (BUG-843): it can no longer use the project, and nothing a project's
/// admin does reaches the person's other projects. Key rings revoke it on
/// the devices that hold them (`vl identity remove`, and in the background).
async fn remove_device(State(hub): State<HubState>, caller: Caller, Json(req): Json<RemoveDevice>) -> Result<Json<Devices>> {
    let me = caller.signed_in()?.clone();
    let admin_of = match &req.project {
        Some(p) => {
            let (project, viewer) = perm::open(&hub.db, p, &caller).await?;
            viewer.admin.then_some(project.id)
        }
        None => None,
    };
    let device = req.device.clone();
    let (person, name) = crate::db::serializable(&hub.db, move |c| {
        let device = device.clone();
        let me = me.clone();
        Box::pin(async move {
            let row: Option<(i64, i64, String, String)> = sqlx::query_as(
                "SELECT d.id, d.person_id, d.signing_key, p.name FROM devices d JOIN people p ON p.id = d.person_id \
                 WHERE d.public_identity = $1 AND d.removed_at IS NULL",
            )
            .bind(&device)
            .fetch_optional(&mut *c)
            .await?;
            let Some((id, person, key, name)) = row else {
                return Err(Error::not_found("no such device"));
            };
            let allowed = person == me.id
                || match admin_of {
                    Some(project) => {
                        let takes_part: Option<i64> = sqlx::query_scalar(
                            "SELECT person_id FROM project_admins WHERE project_id = $1 AND person_id = $2 UNION \
                             SELECT m.person_id FROM groups g JOIN group_members m ON m.group_id = g.id WHERE g.project_id = $1 AND m.person_id = $2",
                        )
                        .bind(project)
                        .bind(person)
                        .fetch_optional(&mut *c)
                        .await?;
                        takes_part.is_some()
                    }
                    None => false,
                };
            if !allowed {
                return Err(Error::not_found("no such device"));
            }
            if key == me.device_key {
                return Err(Error::bad_request("this is the device you are using: remove it from another of your devices"));
            }
            if person == me.id {
                sqlx::query("UPDATE devices SET removed_at = $1 WHERE id = $2").bind(veil_core::now_millis()).bind(id).execute(&mut *c).await?;
                sqlx::query("DELETE FROM sessions WHERE device_id = $1").bind(id).execute(&mut *c).await?;
                queue_key_request(c, person, None).await?;
            } else {
                let project = admin_of.expect("allowed only as an admin of the project");
                sqlx::query("INSERT INTO device_bars (project_id, device_id, created_at) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING")
                    .bind(project)
                    .bind(id)
                    .bind(veil_core::now_millis())
                    .execute(&mut *c)
                    .await?;
                queue_key_request(c, person, Some(project)).await?;
            }
            Ok((person, name))
        })
    })
    .await?;
    let own = person == caller.signed_in()?.id;
    let what = if own { "remove device" } else { "remove device from project" };
    crate::audit(&hub.db, admin_of, Some(caller.signed_in()?.id), what, &format!("{name} ({person}): {}", &req.device[..req.device.len().min(69)])).await;
    device_list(&hub, &name, if own { None } else { admin_of }).await
}

/// An admin records an invite: its public key, for whom, into which group,
/// until when. The invite's secret is never sent (`docs/HUB.md` §13.12).
async fn create_invite(State(hub): State<HubState>, caller: Caller, Path(p): Path<String>, Json(req): Json<InviteRequest>) -> Result<Json<InviteRequest>> {
    let me = caller.signed_in()?.id;
    let (project, viewer) = perm::open(&hub.db, &p, &caller).await?;
    require_admin(&viewer)?;
    if !veil_core::keychain::valid_verifying_key(&req.key) || req.key != req.key.to_ascii_lowercase() {
        return Err(Error::bad_request("an invite key is an Ed25519 public key in lowercase hex"));
    }
    if !valid_principal_name(&req.person) {
        return Err(Error::bad_request("not a valid person name"));
    }
    let now = veil_core::now_millis();
    if req.expires_at <= now || req.expires_at > now + MAX_INVITE_MS {
        return Err(Error::bad_request("an invite expires within 30 days"));
    }
    let (pid, r) = (project.id, req.clone());
    crate::db::serializable(&hub.db, move |c| {
        let r = r.clone();
        Box::pin(async move {
            let gid = group_id(c, pid, &r.group).await?;
            let done = sqlx::query(
                "INSERT INTO invites (project_id, invite_key, person, group_id, expires_at, created_by, created_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING",
            )
            .bind(pid)
            .bind(&r.key)
            .bind(&r.person)
            .bind(gid)
            .bind(r.expires_at)
            .bind(me)
            .bind(veil_core::now_millis())
            .execute(&mut *c)
            .await?;
            if done.rows_affected() == 0 {
                return Err(Error::conflict("that invite exists"));
            }
            Ok(())
        })
    })
    .await?;
    crate::audit(&hub.db, Some(project.id), Some(me), "invite", &format!("{} to {}", req.person, req.group)).await;
    Ok(Json(req))
}

/// The signed-in device joins under an invite: once, before it expires,
/// for the invited person only. The server checks the join's signature too,
/// but key rings decide keys (`docs/HUB.md` §13.12).
async fn join(State(hub): State<HubState>, caller: Caller, Path(p): Path<String>, Json(req): Json<JoinRequest>) -> Result<Json<Joined>> {
    let me = caller.signed_in()?.clone();
    let mut c = hub.db.acquire().await?;
    let project = perm::load_project(&mut c, &p).await?.ok_or_else(|| Error::not_found("no such invite"))?;
    drop(c);
    let pid = project.id;
    let r = req.clone();
    let (group, person) = crate::db::serializable(&hub.db, move |c| {
        let (r, me) = (r.clone(), me.clone());
        Box::pin(async move {
            let row: Option<(String, i64, i64, Option<i64>)> =
                sqlx::query_as("SELECT person, group_id, expires_at, used_at FROM invites WHERE project_id = $1 AND invite_key = $2")
                    .bind(pid)
                    .bind(&r.key)
                    .fetch_optional(&mut *c)
                    .await?;
            let Some((person, gid, expires_at, used_at)) = row else {
                return Err(Error::not_found("no such invite"));
            };
            if used_at.is_some() {
                return Err(Error::conflict("this invite was already used: ask your admin for a new one"));
            }
            if expires_at < veil_core::now_millis() {
                return Err(Error::conflict("this invite has expired: ask your admin for a new one"));
            }
            if person != me.name {
                return Err(Error::forbidden(format!("this invite is for {person}")));
            }
            let mine: Option<(i64, String)> =
                sqlx::query_as("SELECT id, public_identity FROM devices WHERE signing_key = $1 AND removed_at IS NULL AND NOT pending")
                    .bind(&me.device_key)
                    .fetch_optional(&mut *c)
                    .await?;
            let Some((device_id, identity)) = mine.filter(|(_, i)| *i == r.device) else {
                return Err(Error::bad_request("a device joins for itself"));
            };
            let barred: Option<i64> = sqlx::query_scalar("SELECT device_id FROM device_bars WHERE project_id = $1 AND device_id = $2")
                .bind(pid)
                .bind(device_id)
                .fetch_optional(&mut *c)
                .await?;
            if barred.is_some() {
                return Err(Error::forbidden("an admin removed this device from this project"));
            }
            if !join_valid(&r.key, &person, &identity, &r.signature) {
                return Err(Error::bad_request("the join does not verify under the invite's key"));
            }
            let done = sqlx::query(
                "UPDATE invites SET used_at = $1, device_id = $2, signature = $3 WHERE project_id = $4 AND invite_key = $5 AND used_at IS NULL",
            )
            .bind(veil_core::now_millis())
            .bind(device_id)
            .bind(&r.signature)
            .bind(pid)
            .bind(&r.key)
            .execute(&mut *c)
            .await?;
            if done.rows_affected() != 1 {
                return Err(Error::conflict("this invite was already used: ask your admin for a new one"));
            }
            sqlx::query("INSERT INTO group_members (group_id, person_id) VALUES ($1, $2) ON CONFLICT DO NOTHING")
                .bind(gid)
                .bind(me.id)
                .execute(&mut *c)
                .await?;
            queue_key_request(c, me.id, Some(pid)).await?;
            let group: String = sqlx::query_scalar("SELECT name FROM groups WHERE id = $1").bind(gid).fetch_one(&mut *c).await?;
            Ok((group, person))
        })
    })
    .await?;
    crate::audit(&hub.db, Some(pid), Some(caller.signed_in()?.id), "join", &format!("{person} to {group}")).await;
    Ok(Json(Joined { project: project.name, group, person }))
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
            queue_key_request(c, person, None).await?;
            Ok(device)
        })
    })
    .await?;
    crate::audit(&hub.db, None, Some(me.id), "vouch for device", &format!("device {n}")).await;
    device_list(&hub, &me.name, None).await
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
        revision: veil_core::hub::wire::REVISION,
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
    let stream = sync::fetch(&hub, &project, &viewer, req.snapshot, req.objects).await?;
    Ok(([(header::CONTENT_TYPE, "application/octet-stream")], axum::body::Body::new(stream)).into_response())
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
            for t in [
                "DELETE FROM group_members WHERE group_id = $1",
                "DELETE FROM group_managers WHERE group_id = $1",
                "DELETE FROM invites WHERE group_id = $1",
                "DELETE FROM groups WHERE id = $1",
            ] {
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
            // A removal takes back the invites to the group not used yet,
            // also of a name nobody has signed up with (BUG-842).
            let mut people = people;
            if op == Op::RemoveMember && (admin || manager) {
                let mut kept = Vec::new();
                for n in people {
                    let cancelled = sqlx::query("DELETE FROM invites WHERE project_id = $1 AND group_id = $2 AND person = $3 AND used_at IS NULL")
                        .bind(pid)
                        .bind(gid)
                        .bind(&n)
                        .execute(&mut *c)
                        .await?
                        .rows_affected();
                    let known: Option<i64> = sqlx::query_scalar("SELECT id FROM people WHERE name = $1").bind(&n).fetch_optional(&mut *c).await?;
                    if cancelled == 0 || known.is_some() {
                        kept.push(n);
                    }
                }
                people = kept;
            }
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
                if op == Op::AddMember {
                    queue_key_request(c, *id, Some(pid)).await?;
                }
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

async fn get_ring(State(hub): State<HubState>, caller: Caller, Path((p, scope)): Path<(String, String)>) -> Result<Json<serde_json::Value>> {
    caller.signed_in()?;
    let (project, viewer) = perm::open(&hub.db, &p, &caller).await?;
    if !project.participant(&viewer) {
        return Err(Error::forbidden("you are not in this project"));
    }
    let body: Option<String> = sqlx::query_scalar("SELECT body FROM rings WHERE project_id = $1 AND scope = $2")
        .bind(project.id)
        .bind(&scope)
        .fetch_optional(&hub.db)
        .await?;
    body.and_then(|b| serde_json::from_str(&b).ok()).map(Json).ok_or_else(|| Error::not_found(format!("no key ring '{scope}'")))
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
    let exists: Option<i32> = sqlx::query_scalar("SELECT 1 FROM rings WHERE project_id = $1 AND scope = $2")
        .bind(project.id)
        .bind(&scope)
        .fetch_optional(&hub.db)
        .await?;
    if exists.is_none() {
        if !viewer.admin {
            return Err(Error::forbidden(format!("only an admin of this project starts a key ring (scope '{scope}')")));
        }
        // A new ring must name this project, as its devices check (BUG-845):
        // its signed genesis carries the id of the project's `team` ring.
        if scope != veil_core::policy::DEFAULT_SCOPE {
            let team: Option<String> = sqlx::query_scalar("SELECT body FROM rings WHERE project_id = $1 AND scope = $2")
                .bind(project.id)
                .bind(veil_core::policy::DEFAULT_SCOPE)
                .fetch_optional(&hub.db)
                .await?;
            let id = |r: &KeyRing| r.verify().ok().and_then(|st| st.project);
            let mine = team.and_then(|b| serde_json::from_str::<KeyRing>(&b).ok()).as_ref().and_then(id);
            if mine.is_none() || id(&ring) != mine {
                return Err(Error::bad_request(format!(
                    "the key ring '{scope}' does not belong to this project (its genesis must name the project's 'team' key ring, sent first)"
                )));
            }
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
    // The project's `team` ring, which every other ring must name (the
    // engine's `Keychain::bound`, BUG-845). Its genesis never changes.
    let team: Option<String> = if ring.scope == veil_core::policy::DEFAULT_SCOPE {
        None
    } else {
        sqlx::query_scalar("SELECT body FROM rings WHERE project_id = $1 AND scope = $2")
            .bind(pid)
            .bind(veil_core::policy::DEFAULT_SCOPE)
            .fetch_optional(&hub.db)
            .await?
    };
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
            if let Some(t) = &team {
                let tp = VPath::new(&format!(".veil/meta/keyrings/{}.json", veil_core::policy::DEFAULT_SCOPE)).map_err(Error::from)?;
                mem.write(&tp, t.as_bytes()).map_err(Error::from)?;
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
