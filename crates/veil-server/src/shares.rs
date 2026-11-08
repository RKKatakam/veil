//! Person-to-person secret shares (`docs/HUB.md` §13.17): a member's copy
//! of one secret file, sealed on their device for another member's
//! confirmed devices (`veil_core::secret_share`).
//!
//! The server holds each share's latest signed version (ciphertext) and,
//! in plain text for the admins' audit, who shares which path with whom and
//! when. It cannot open a share, and it is not the authority for who can:
//! that is the sharing device's choice of confirmed devices, and the
//! signature every recipient checks against the key rings. What the server
//! decides is who may **write** a share (a participant who may read the
//! path, for another participant, of a secret file only) and who is
//! **served** it (its recipient, while the sharer may still read the path
//! and the recipient still takes part in the project).
//!
//! Every write is one autocommit statement with a compare-and-swap on the
//! share's version: an update built on an old version, or one that would
//! bring back a share its sharer ended, is refused (409).

use std::collections::HashMap;

use axum::{
    extract::{Path, State},
    Json,
};
use veil_core::{
    policy::Policy,
    secret_share::{shareable, ShareInfo, SharePut, ShareRecord, ShareRemove, MAX_SHARES_PER_SHARER},
};

use crate::{
    auth::Caller,
    error::{Error, Result},
    perm::{self, Project, Viewer},
    HubState,
};

/// Another person's standing in `project` (admin, groups): who a share is
/// for, or whether its sharer may still read its path.
async fn viewer_of(db: &sqlx::PgPool, project: i64, person: i64) -> Result<Viewer> {
    let admin: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM project_admins WHERE project_id = $1 AND person_id = $2)")
        .bind(project)
        .bind(person)
        .fetch_one(db)
        .await?;
    let groups: Vec<i64> = sqlx::query_scalar(
        "SELECT g.id FROM groups g JOIN group_members m ON m.group_id = g.id WHERE g.project_id = $1 AND m.person_id = $2",
    )
    .bind(project)
    .bind(person)
    .fetch_all(db)
    .await?;
    Ok(Viewer {
        person: Some(person),
        admin,
        groups: groups.into_iter().collect(),
        only: None,
        agent: false,
    })
}

/// Why a share is not served now, if it is not.
fn paused(project: &Project, sharer: &Viewer, recipient: &Viewer, path: &str, names: (&str, &str)) -> Option<String> {
    if !project.view(sharer).read(path) {
        return Some(format!("{} may no longer read {path}", names.0));
    }
    if !project.participant(recipient) {
        return Some(format!("{} no longer takes part in this project", names.1));
    }
    None
}

type Row = (String, String, String, i64, i64, i64, Option<i64>, Option<String>, i64, i64);

/// `GET /v1/projects/{p}/shares`: admins, every share of the project (the
/// audit: never a share's content); others, the shares they make or
/// receive. A share's record (ciphertext) goes only to its sharer and its
/// recipient, and only while it is active.
pub async fn list(State(hub): State<HubState>, caller: Caller, Path(p): Path<String>) -> Result<Json<Vec<ShareInfo>>> {
    let me = caller.signed_in()?.clone();
    let (project, viewer) = perm::open(&hub, &p, &caller).await?;
    if !project.participant(&viewer) {
        return Err(Error::forbidden("you are not in this project"));
    }
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT s.path, a.name, b.name, s.version, s.created_at, s.updated_at, s.unshared_at, s.body, s.sharer_id, s.recipient_id \
         FROM secret_shares s JOIN people a ON a.id = s.sharer_id JOIN people b ON b.id = s.recipient_id \
         WHERE s.project_id = $1 AND ($2 OR s.sharer_id = $3 OR s.recipient_id = $3) ORDER BY s.path, a.name, b.name",
    )
    .bind(project.id)
    .bind(viewer.admin)
    .bind(me.id)
    .fetch_all(&hub.db)
    .await?;
    let mut viewers: HashMap<i64, Viewer> = HashMap::new();
    let mut out = Vec::new();
    for (path, sharer, recipient, version, created_at, updated_at, unshared_at, body, sid, rid) in rows {
        for id in [sid, rid] {
            if let std::collections::hash_map::Entry::Vacant(e) = viewers.entry(id) {
                e.insert(viewer_of(&hub.db, project.id, id).await?);
            }
        }
        let why = match unshared_at {
            Some(_) => None,
            None => paused(&project, &viewers[&sid], &viewers[&rid], &path, (&sharer, &recipient)),
        };
        let active = unshared_at.is_none() && why.is_none();
        let theirs = me.id == sid || me.id == rid;
        let record = match (active && theirs, body) {
            (true, Some(b)) => serde_json::from_str::<ShareRecord>(&b).ok(),
            _ => None,
        };
        out.push(ShareInfo {
            path,
            sharer,
            recipient,
            version: version as u64,
            created_at,
            updated_at,
            unshared_at,
            active,
            paused: why,
            record,
        });
    }
    Ok(Json(out))
}

async fn person_id(db: &sqlx::PgPool, name: &str) -> Result<Option<i64>> {
    Ok(sqlx::query_scalar("SELECT id FROM people WHERE name = $1").bind(name).fetch_optional(db).await?)
}

/// The stored share: (version, unshared_at, body, created_at).
async fn stored(db: &sqlx::PgPool, project: i64, path: &str, sharer: i64, recipient: i64) -> Result<Option<(i64, Option<i64>, Option<String>, i64)>> {
    Ok(sqlx::query_as(
        "SELECT version, unshared_at, body, created_at FROM secret_shares WHERE project_id = $1 AND path = $2 AND sharer_id = $3 AND recipient_id = $4",
    )
    .bind(project)
    .bind(path)
    .bind(sharer)
    .bind(recipient)
    .fetch_optional(db)
    .await?)
}

/// `POST /v1/projects/{p}/shares`: store a new version of the caller's
/// share. The record must be signed by the device sending it, be of a
/// secret file the caller may read, for another participant, and follow the
/// version stored (`expect`).
pub async fn put(State(hub): State<HubState>, caller: Caller, Path(p): Path<String>, Json(req): Json<SharePut>) -> Result<Json<ShareInfo>> {
    let me = caller.person_only()?.clone();
    let (project, viewer) = perm::open(&hub, &p, &caller).await?;
    if !project.participant(&viewer) {
        return Err(Error::forbidden("you are not in this project"));
    }
    let r = &req.record;
    r.verify().map_err(Error::bad_request)?;
    if r.sharer != me.name || r.signer != me.device_key {
        return Err(Error::bad_request("a share is sealed and signed by the device that sends it, under its person's name"));
    }
    if r.version != req.expect.saturating_add(1) {
        return Err(Error::bad_request("the share's version must follow the one it was built on"));
    }
    let path = r.path.as_str();
    if !project.view(&viewer).read(path) {
        return Err(Error::not_found("no such path that you can see"));
    }
    shareable(&Policy::parse(&project.policy_text), path).map_err(Error::forbidden)?;
    if r.recipient == me.name {
        return Err(Error::bad_request("share it with someone else"));
    }
    let recipient = person_id(&hub.db, &r.recipient)
        .await?
        .ok_or_else(|| Error::not_found(format!("no person named '{}'", r.recipient)))?;
    if !project.participant(&viewer_of(&hub.db, project.id, recipient).await?) {
        return Err(Error::not_found(format!("{} takes no part in this project", r.recipient)));
    }
    let body = serde_json::to_string(r).map_err(|e| Error::Other(e.into()))?;
    let now = veil_core::now_millis();
    let version = r.version as i64;
    let rows = if req.expect == 0 {
        // The limit is reserved in the transaction that inserts (BUG-1061):
        // the quota row orders this person's new shares in the project, and
        // an insert that finds the share there gives the reservation back.
        let (pid, sid, path_s, body_s) = (project.id, me.id, path.to_string(), body.clone());
        let created = crate::db::transaction(&hub.db, crate::db::Isolation::ReadCommitted, move |c| {
            let (path_s, body_s) = (path_s.clone(), body_s.clone());
            Box::pin(async move {
                let used: Option<i64> = sqlx::query_scalar(
                    "INSERT INTO secret_share_quota (project_id, sharer_id, used) \
                     SELECT $1, $2, n + 1 FROM (SELECT count(*) AS n FROM secret_shares WHERE project_id = $1 AND sharer_id = $2) t \
                     WHERE n < $3 \
                     ON CONFLICT (project_id, sharer_id) DO UPDATE SET used = secret_share_quota.used + 1 \
                     WHERE secret_share_quota.used < $3 RETURNING used",
                )
                .bind(pid)
                .bind(sid)
                .bind(MAX_SHARES_PER_SHARER)
                .fetch_optional(&mut *c)
                .await?;
                if used.is_none() {
                    return Err(Error::forbidden(format!("you have {MAX_SHARES_PER_SHARER} shares in this project, the most one person may")));
                }
                let rows = sqlx::query(
                    "INSERT INTO secret_shares (project_id, path, sharer_id, recipient_id, version, created_at, updated_at, body) \
                     VALUES ($1, $2, $3, $4, 1, $5, $5, $6) ON CONFLICT DO NOTHING",
                )
                .bind(pid)
                .bind(&path_s)
                .bind(sid)
                .bind(recipient)
                .bind(now)
                .bind(&body_s)
                .execute(&mut *c)
                .await?
                .rows_affected();
                if rows == 0 {
                    return Err(Error::conflict("the share exists"));
                }
                Ok(())
            })
        })
        .await;
        match created {
            Ok(()) => 1,
            Err(Error::Api { code: "conflict", .. }) => 0,
            Err(e) => return Err(e),
        }
    } else {
        sqlx::query(
            "UPDATE secret_shares SET version = $5, updated_at = $6, body = $7, unshared_at = NULL \
             WHERE project_id = $1 AND path = $2 AND sharer_id = $3 AND recipient_id = $4 AND version = $8 \
             AND (unshared_at IS NULL OR $9)",
        )
        .bind(project.id)
        .bind(path)
        .bind(me.id)
        .bind(recipient)
        .bind(version)
        .bind(now)
        .bind(&body)
        .bind(req.expect as i64)
        .bind(req.reshare)
        .execute(&hub.db)
        .await?
        .rows_affected()
    };
    let now_stored = stored(&hub.db, project.id, path, me.id, recipient).await?;
    // Not written, unless this very record is what is stored (the request
    // ran again after its write committed).
    if rows != 1 && now_stored.as_ref().and_then(|s| s.2.as_deref()) != Some(body.as_str()) {
        return Err(Error::conflict(match now_stored {
            Some((v, Some(_), _, _)) => format!("you ended this share (version {v}); share it again with `vl secret share`"),
            Some((v, None, _, _)) => format!("the share changed meanwhile (it is at version {v})"),
            None => "the share does not exist yet".to_string(),
        }));
    }
    crate::audit(&hub.db, Some(project.id), Some(me.id), "secret_share", &format!("{path} with {} (version {version})", r.recipient)).await;
    Ok(Json(ShareInfo {
        path: path.to_string(),
        sharer: me.name.clone(),
        recipient: r.recipient.clone(),
        version: r.version,
        created_at: now_stored.map_or(now, |s| s.3),
        updated_at: now,
        unshared_at: None,
        active: true,
        paused: None,
        record: None,
    }))
}

/// `POST /v1/projects/{p}/shares/remove`: the sharer ends a share. Its row
/// stays for the audit, without the record; its version moves on, so no
/// update built before brings it back.
pub async fn remove(State(hub): State<HubState>, caller: Caller, Path(p): Path<String>, Json(req): Json<ShareRemove>) -> Result<Json<ShareInfo>> {
    let me = caller.person_only()?.clone();
    let (project, _) = perm::open(&hub, &p, &caller).await?;
    let gone = || Error::not_found(format!("you share no secret '{}' with '{}' here", req.path, req.recipient));
    let recipient = person_id(&hub.db, &req.recipient).await?.ok_or_else(gone)?;
    let now = veil_core::now_millis();
    let row: Option<(i64, i64)> = sqlx::query_as(
        "UPDATE secret_shares SET unshared_at = $5, updated_at = $5, body = NULL, version = version + 1 \
         WHERE project_id = $1 AND path = $2 AND sharer_id = $3 AND recipient_id = $4 AND unshared_at IS NULL \
         RETURNING version, created_at",
    )
    .bind(project.id)
    .bind(&req.path)
    .bind(me.id)
    .bind(recipient)
    .bind(now)
    .fetch_optional(&hub.db)
    .await?;
    let (version, created_at) = match row {
        Some(r) => r,
        // Ended already (also: this request ran again after it committed).
        None => match stored(&hub.db, project.id, &req.path, me.id, recipient).await? {
            Some((v, Some(_), _, c)) => (v, c),
            _ => return Err(gone()),
        },
    };
    crate::audit(&hub.db, Some(project.id), Some(me.id), "secret_unshare", &format!("{} with {}", req.path, req.recipient)).await;
    Ok(Json(ShareInfo {
        path: req.path.clone(),
        sharer: me.name.clone(),
        recipient: req.recipient.clone(),
        version: version as u64,
        created_at,
        updated_at: now,
        unshared_at: Some(now),
        active: false,
        paused: None,
        record: None,
    }))
}
