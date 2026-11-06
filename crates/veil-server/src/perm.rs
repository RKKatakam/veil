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

use crate::{
    auth::Caller,
    error::{Error, Result},
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
}

impl Project {
    pub fn view<'a>(&'a self, viewer: &Viewer) -> View<'a> {
        View::new(&self.policy, viewer.admin, |_, name| match self.bindings.get(name) {
            Some(Binding::Group(g)) => viewer.groups.contains(g),
            Some(Binding::Person(p)) => viewer.person == Some(*p),
            None => false,
        })
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

pub async fn load_viewer(c: &mut PgConnection, project: i64, caller: &Caller) -> Result<Viewer> {
    let Some(p) = &caller.person else {
        return Ok(Viewer::default());
    };
    // One round trip: an admin? and is this device barred from the project
    // (an admin removed it from this project only, BUG-843)?
    let (admin, barred): (bool, bool) = sqlx::query_as(
        "SELECT EXISTS (SELECT 1 FROM project_admins WHERE project_id = $1 AND person_id = $2), \
         EXISTS (SELECT 1 FROM device_bars b JOIN devices d ON d.id = b.device_id WHERE b.project_id = $1 AND d.signing_key = $3)",
    )
    .bind(project)
    .bind(p.id)
    .bind(&p.device_key)
    .fetch_one(&mut *c)
    .await?;
    if barred {
        return Err(Error::forbidden(
            "an admin removed this device from this project: use another of your devices (`vl identity confirm` a new one)",
        ));
    }
    let groups: Vec<i64> = sqlx::query_scalar(
        "SELECT g.id FROM groups g JOIN group_members m ON m.group_id = g.id WHERE g.project_id = $1 AND m.person_id = $2",
    )
    .bind(project)
    .bind(p.id)
    .fetch_all(&mut *c)
    .await?;
    Ok(Viewer {
        person: Some(p.id),
        admin,
        groups: groups.into_iter().collect(),
    })
}

/// A project and the caller's view of it. A project the caller can see
/// nothing of is reported as not found, whether or not it exists.
pub async fn open(db: &sqlx::PgPool, name: &str, caller: &Caller) -> Result<(Project, Viewer)> {
    let mut c = db.acquire().await?;
    let not_found = || Error::not_found(format!("no project '{name}' that you can see"));
    let project = load_project(&mut c, name).await?.ok_or_else(not_found)?;
    let viewer = load_viewer(&mut c, project.id, caller).await?;
    if !project.view(&viewer).sees_anything() && !project.participant(&viewer) {
        return Err(not_found());
    }
    Ok((project, viewer))
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

pub async fn is_manager(c: &mut PgConnection, group: i64, person: i64) -> Result<bool> {
    let r: Option<i64> = sqlx::query_scalar("SELECT person_id FROM group_managers WHERE group_id = $1 AND person_id = $2")
        .bind(group)
        .bind(person)
        .fetch_optional(&mut *c)
        .await?;
    Ok(r.is_some())
}
