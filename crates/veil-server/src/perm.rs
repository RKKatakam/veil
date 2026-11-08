//! The permission model on the server (`docs/VISIBILITY.md`; `docs/HUB.md`
//! §5): one place builds a viewer's [`View`] from the server's records
//! (admins, groups, members) and the **accepted** policy, and every read
//! and write goes through it. Labels inside snapshots are never consulted.
//!
//! * The accepted policy is the `.veilpolicy` of the default branch as last
//!   accepted from an admin's push. When it is accepted, every name in its
//!   access lines is bound to a group of the project or a person
//!   ([`bind_names`]), and the bindings are stored with it: a person who
//!   later signs up under a group's name, or a group created later under a
//!   person's name, never inherits a rule.
//! * A name bound to a group that was deleted since grants nothing.

use std::collections::{BTreeMap, HashSet};

use serde::{Deserialize, Serialize};
use sqlx::PgConnection;
use veil_core::hub::access::{AccessPolicy, View};

use std::sync::atomic::Ordering;

use crate::{
    auth::{Caller, Person},
    error::{Error, Result},
    Hub,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Binding {
    Group(i64),
    Person(i64),
}

/// A project and its accepted policy.
#[derive(Clone, Debug)]
pub struct Project {
    pub id: i64,
    pub name: String,
    pub default_branch: String,
    pub policy_text: String,
    pub policy: AccessPolicy,
    pub bindings: BTreeMap<String, Binding>,
}

/// Who is asking, in one project.
#[derive(Clone, Debug, Default)]
pub struct Viewer {
    pub person: Option<i64>,
    pub admin: bool,
    pub groups: HashSet<i64>,
    /// An agent session's narrowing (`docs/HUB.md` §13.27): it writes, and
    /// the file routes let it read, only at or below these paths. Its
    /// history is its person's: [`View::key`] ignores it.
    pub only: Option<std::sync::Arc<Vec<String>>>,
}

impl Viewer {
    /// May this viewer reach file or folder `path` through the routes that
    /// serve files? Always, but for a narrowed agent session.
    pub fn within_narrowing(&self, path: &str) -> bool {
        self.only.as_ref().is_none_or(|o| veil_core::hub::agent::within(o, path))
    }

    /// May this viewer have the tree of folder `dir`: inside the narrowing,
    /// or on the way to it (its entries then name what the person sees
    /// there, never what is below them).
    pub fn toward_narrowing(&self, dir: &str) -> bool {
        self.only.as_ref().is_none_or(|o| veil_core::hub::agent::within(o, dir) || veil_core::hub::agent::toward(o, dir))
    }

    /// Refuse a file route's `path` outside the narrowing, as a path that
    /// is not there.
    pub fn narrowed_to(&self, path: &str) -> Result<()> {
        if self.within_narrowing(path) {
            return Ok(());
        }
        Err(Error::new(
            axum::http::StatusCode::FORBIDDEN,
            crate::auth::AGENT_SESSION,
            "this agent session is narrowed to other paths: ask for a path inside them",
        ))
    }
}

impl Project {
    pub fn view<'a>(&'a self, viewer: &Viewer) -> View<'a> {
        View::new(&self.policy, viewer.admin, |_, name| match self.bindings.get(name) {
            Some(Binding::Group(g)) => viewer.groups.contains(g),
            Some(Binding::Person(p)) => viewer.person == Some(*p),
            None => false,
        })
        .narrowed(viewer.only.as_deref().map(|o| o.as_slice()))
    }

    /// Does `viewer` take part in the project (an admin, in one of its
    /// groups, or named by a rule)? Only they may upload, push or read
    /// key rings.
    pub fn participant(&self, viewer: &Viewer) -> bool {
        viewer.admin
            || !viewer.groups.is_empty()
            || viewer
                .person
                .is_some_and(|p| self.bindings.values().any(|b| *b == Binding::Person(p)))
    }
}

/// Most groups one project may have (BUG-913): bounds what a person's view
/// of it holds.
pub const MAX_GROUPS: i64 = 1_000;

pub fn valid_project_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_' | b'.'))
}

type ProjectRow = (i64, String, String, String, String);

pub async fn load_project(c: &mut PgConnection, name: &str) -> Result<Option<Project>> {
    if !valid_project_name(name) {
        return Ok(None);
    }
    let row: Option<ProjectRow> =
        sqlx::query_as("SELECT id, name, default_branch, policy_text, policy_bindings FROM projects WHERE name = $1")
            .bind(name)
            .fetch_optional(&mut *c)
            .await?;
    Ok(row.map(|(id, name, default_branch, policy_text, bindings)| Project {
        id,
        name,
        default_branch,
        policy: AccessPolicy::parse(&policy_text),
        policy_text,
        bindings: serde_json::from_str(&bindings).unwrap_or_default(),
    }))
}

/// `person`'s view of `project` from the database, and whether an admin
/// barred their device from it (BUG-843), in one statement.
pub async fn load_viewer(c: &mut PgConnection, project: i64, person: &Person) -> Result<(Viewer, bool)> {
    let (admin, barred, groups): (bool, bool, Vec<i64>) = sqlx::query_as(
        "SELECT EXISTS (SELECT 1 FROM project_admins WHERE project_id = $1 AND person_id = $2), \
         EXISTS (SELECT 1 FROM device_bars b JOIN devices d ON d.id = b.device_id WHERE b.project_id = $1 AND d.signing_key = $3), \
         ARRAY(SELECT g.id FROM groups g JOIN group_members m ON m.group_id = g.id WHERE g.project_id = $1 AND m.person_id = $2)",
    )
    .bind(project)
    .bind(person.id)
    .bind(&person.device_key)
    .fetch_one(&mut *c)
    .await?;
    Ok((
        Viewer {
            person: Some(person.id),
            admin,
            groups: groups.into_iter().collect(),
            only: None,
        },
        barred,
    ))
}

/// A project and the caller's view of it. A project the caller can see
/// nothing of is reported as not found, whether or not it exists.
///
/// Served from the server's caches when they were built under the access
/// epochs this request read (`caches`): a group, admin, device, policy or
/// binding change on any server bumps an epoch in its own transaction, so
/// the answer is always the database's at the moment of the request.
pub async fn open(hub: &Hub, name: &str, caller: &Caller) -> Result<(Project, Viewer)> {
    open_at(hub, name, caller).await.map(|(p, v, _)| (p, v))
}

/// [`open`], with the access epochs the view was built under: read before
/// its rows were. Anything issued from this view (a read grant) must carry
/// these, never a later read of the epochs, so it can never be newer than
/// the access it was decided on.
pub async fn open_at(hub: &Hub, name: &str, caller: &Caller) -> Result<(Project, Viewer, crate::caches::Epochs)> {
    let not_found = || Error::not_found(format!("no project '{name}' that you can see"));
    if !valid_project_name(name) {
        return Err(not_found());
    }
    let stats = &hub.caches.stats;
    let cached = hub.caches.project(name);
    // The project's epoch as this request read it (the session check reads it
    // when the project was cached), or now, before anything it is used for.
    let project_epoch = match (&cached, caller.epochs.project) {
        (Some(e), Some((id, epoch))) if e.project.id == id => Some(epoch),
        (Some(e), _) => {
            let p = caller.person.as_ref().map_or(0, |p| p.id);
            crate::caches::read_epochs(&hub.db, p, Some(e.project.id)).await?.project.map(|(_, epoch)| epoch)
        }
        (None, _) => None,
    };
    let entry = match (cached, project_epoch) {
        (Some(e), Some(epoch)) if e.epoch == epoch => e,
        _ => {
            // The row and its epoch in one statement.
            let row: Option<(i64, String, String, String, String, i64)> = sqlx::query_as(
                "SELECT id, name, default_branch, policy_text, policy_bindings, \
                 COALESCE((SELECT epoch FROM access_epochs e WHERE e.project_id = projects.id AND e.person_id = 0), 0) \
                 FROM projects WHERE name = $1",
            )
            .bind(name)
            .fetch_optional(&hub.db)
            .await?;
            let (id, name, default_branch, policy_text, bindings, epoch) = row.ok_or_else(not_found)?;
            let e = crate::caches::ProjectEntry {
                project: Project {
                    id,
                    name,
                    default_branch,
                    policy: AccessPolicy::parse(&policy_text),
                    policy_text,
                    bindings: serde_json::from_str(&bindings).unwrap_or_default(),
                },
                epoch,
            };
            hub.caches.put_project(e)
        }
    };
    let project = entry.project.clone();
    let mut person_epoch = caller.epochs.person;
    let viewer = match &caller.person {
        None => Viewer::default(),
        Some(p) => {
            let fresh = |v: &crate::caches::ViewerEntry| v.project_epoch == entry.epoch && v.person_epoch == caller.epochs.person;
            let v = match hub.caches.viewer(project.id, p).filter(|v| fresh(v)) {
                Some(v) => {
                    stats.permission_hits.fetch_add(1, Ordering::Relaxed);
                    v
                }
                None => {
                    stats.permission_misses.fetch_add(1, Ordering::Relaxed);
                    // Read after both epochs were (by the session check, and
                    // with the project row): never tagged newer than its data.
                    let (viewer, barred) = load_viewer(&mut *hub.db.acquire().await?, project.id, p).await?;
                    hub.caches.put_viewer(
                        project.id,
                        p,
                        crate::caches::ViewerEntry {
                            viewer,
                            barred,
                            project_epoch: entry.epoch,
                            person_epoch: caller.epochs.person,
                        },
                    )
                }
            };
            if v.barred {
                return Err(Error::forbidden(
                    "an admin removed this device from this project: use another of your devices (`vl identity confirm` a new one)",
                ));
            }
            person_epoch = v.person_epoch;
            let mut viewer = v.viewer.clone();
            // An agent session works in its own project only, narrowed.
            if let Some(a) = &p.agent {
                if a.project != project.id {
                    return Err(not_found());
                }
                viewer.only = a.only.clone();
            }
            viewer
        }
    };
    if !project.view(&viewer).sees_anything() && !project.participant(&viewer) {
        return Err(not_found());
    }
    let epochs = crate::caches::Epochs {
        person: person_epoch,
        project: Some((project.id, entry.epoch)),
    };
    Ok((project, viewer, epochs))
}

/// Bind every name of `policy`: to the project's group of that name if
/// there is one (a group always wins, so a person who signs up under a
/// group's name takes over nothing), else to the person of that name, else
/// refuse. The admin's push lists every binding (`sync::push`).
pub async fn bind_names(c: &mut PgConnection, project: i64, policy: &AccessPolicy) -> Result<BTreeMap<String, Binding>> {
    let mut out = BTreeMap::new();
    for name in policy.names() {
        let group: Option<i64> = sqlx::query_scalar("SELECT id FROM groups WHERE project_id = $1 AND name = $2")
            .bind(project)
            .bind(&name)
            .fetch_optional(&mut *c)
            .await?;
        let b = match group {
            Some(g) => Binding::Group(g),
            None => {
                let person: Option<i64> = sqlx::query_scalar("SELECT id FROM people WHERE name = $1")
                    .bind(&name)
                    .fetch_optional(&mut *c)
                    .await?;
                match person {
                    Some(p) => Binding::Person(p),
                    None => {
                        return Err(Error::bad_request(format!(
                            "'{name}' in .veilpolicy is neither a group of this project nor a person; create the group first (`vl group create {name}`)"
                        )))
                    }
                }
            }
        };
        out.insert(name, b);
    }
    Ok(out)
}

/// Accept `text` as the project's policy (the default branch moved to it,
/// by an admin), binding its names ([`bind_names`]), inside the caller's
/// transaction.
pub async fn accept_policy(c: &mut PgConnection, project: i64, text: &str) -> Result<()> {
    let policy = AccessPolicy::parse(text);
    let bindings = bind_names(&mut *c, project, &policy).await?;
    sqlx::query("UPDATE projects SET policy_text = $1, policy_bindings = $2, policy_version = policy_version + 1 WHERE id = $3")
        .bind(text)
        .bind(serde_json::to_string(&bindings).map_err(|e| Error::Other(e.into()))?)
        .bind(project)
        .execute(&mut *c)
        .await?;
    Ok(())
}

/// After [`accept_policy`], never silently: who can now see what, as the
/// admin is told.
pub fn accepted_listing(project: &Project) -> Vec<String> {
    let mut out = Vec::new();
    for r in &project.policy.rules {
        let mut who: Vec<String> = Vec::new();
        if r.public {
            who.push("everyone on Earth (public, read)".into());
        }
        for n in &r.names {
            who.push(match project.bindings.get(n) {
                Some(Binding::Group(_)) => format!("group {n}"),
                _ => format!("person {n}"),
            });
        }
        out.push(format!("access accepted: {}/ → {}", r.path, who.join(", ")));
    }
    out.extend(project.policy.warnings.iter().cloned());
    out
}

/// Is `person` a manager of `group`? The row is locked (`FOR SHARE`) for
/// the rest of the transaction: a concurrent removal of the manager waits.
pub async fn is_manager(c: &mut PgConnection, group: i64, person: i64) -> Result<bool> {
    let r: Option<i64> = sqlx::query_scalar("SELECT person_id FROM group_managers WHERE group_id = $1 AND person_id = $2 FOR SHARE")
        .bind(group)
        .bind(person)
        .fetch_optional(&mut *c)
        .await?;
    Ok(r.is_some())
}
