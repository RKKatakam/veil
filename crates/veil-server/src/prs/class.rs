//! Visibility classes (phase-4 design §4.9): who may see a PR, without
//! work per PR.
//!
//! * A PR is visible only to people who can read **every path any of its
//!   revisions touched** (`docs/VISIBILITY.md`, "Who can see a PR"). Each
//!   path is decided by one access line (the last that covers it) or by
//!   none (admins only), so the PR's **class** is the set of those lines:
//!   their paths, `""` standing for "no line". A viewer satisfies a class
//!   when they may read every line's path (admins: every class).
//!   Equivalent to reading every touched path: if line `i` decides path
//!   `t`, it also decides its own path (a later line covering `i`'s path
//!   would cover `t` too), so `View::read` of the line's path is the
//!   viewer's decision for `t`.
//! * **Classes are few** (sets of lines), so a list, count or search reads
//!   the project's classes, keeps those the viewer satisfies, and reads
//!   only PRs in them (`prs_by_class`). No hidden PR is read, counted or
//!   ranked by anyone's request.
//! * **A class belongs to one set of access lines** (`policy_key`, a hash
//!   of the lines' paths in order: who a line names does not change which
//!   line decides a path). When the lines change, each PR's class is
//!   computed again from its touched paths ([`reclassify`]) before any PR
//!   answer is given. A PR whose class is of other lines is in no list and
//!   visible to nobody until then: never shown under lines that no longer
//!   hold.
//! * The embargo (S23) is part of the class; nothing sets it yet.

use std::collections::BTreeSet;

use veil_core::hub::access::{AccessPolicy, View};

use crate::{
    error::Result,
    perm::{Project, Viewer},
    Hub,
};

/// The key of a set of access lines: their paths, in order.
pub fn policy_key(policy: &AccessPolicy) -> String {
    let mut h = blake3::Hasher::new_derive_key("veil 2026 hub pr policy-key v1");
    for r in &policy.rules {
        h.update(&(r.path.len() as u64).to_le_bytes());
        h.update(r.path.as_bytes());
    }
    hex::encode(&h.finalize().as_bytes()[..16])
}

/// The lines deciding `paths` (`""`: no line, admins only).
pub fn lines_of<'a>(policy: &AccessPolicy, paths: impl IntoIterator<Item = &'a str>) -> BTreeSet<String> {
    paths
        .into_iter()
        .map(|p| match policy.deciding(p) {
            Some(i) => policy.rules[i].path.clone(),
            None => String::new(),
        })
        .collect()
}

/// A class's id: its lines, under `policy_key`, with its embargo.
pub fn class_id(policy_key: &str, lines: &BTreeSet<String>, embargo: &str) -> String {
    let mut h = blake3::Hasher::new_derive_key("veil 2026 hub pr class v1");
    for part in std::iter::once(policy_key).chain(lines.iter().map(String::as_str)).chain(std::iter::once(embargo)) {
        h.update(&(part.len() as u64).to_le_bytes());
        h.update(part.as_bytes());
    }
    hex::encode(&h.finalize().as_bytes()[..16])
}

/// Does the viewer satisfy a class of these lines (and no embargo)?
pub fn satisfies(view: &View, lines: &BTreeSet<String>, embargo: &str) -> bool {
    // An embargoed class is S23's: visible to nobody until it is built.
    embargo.is_empty() && (view.admin || lines.iter().all(|l| !l.is_empty() && view.read(l)))
}

/// Make sure the class row exists (in the caller's transaction).
pub async fn put_class(c: &mut sqlx::PgConnection, project: i64, policy_key: &str, lines: &BTreeSet<String>) -> Result<String> {
    let id = class_id(policy_key, lines, "");
    sqlx::query(
        "INSERT INTO pr_classes (project_id, class_id, policy_key, lines, embargo) VALUES ($1, $2, $3, $4, '') \
         ON CONFLICT (project_id, class_id) DO NOTHING",
    )
    .bind(project)
    .bind(&id)
    .bind(policy_key)
    .bind(serde_json::to_string(lines).expect("strings"))
    .execute(&mut *c)
    .await?;
    Ok(id)
}

/// The classes of the project's current lines that `viewer` satisfies.
pub async fn satisfied(hub: &Hub, project: &Project, viewer: &Viewer) -> Result<Vec<String>> {
    let key = policy_key(&project.policy);
    let rows: Vec<(String, String, String)> =
        sqlx::query_as("SELECT class_id, lines, embargo FROM pr_classes WHERE project_id = $1 AND policy_key = $2")
            .bind(project.id)
            .bind(&key)
            .fetch_all(&hub.db)
            .await?;
    let view = project.view(viewer);
    Ok(rows
        .into_iter()
        .filter(|(_, lines, embargo)| {
            let lines: BTreeSet<String> = serde_json::from_str(lines).unwrap_or_else(|_| BTreeSet::from([String::new()]));
            satisfies(&view, &lines, embargo)
        })
        .map(|(id, _, _)| id)
        .collect())
}

/// How many PRs one pass of [`reclassify`] takes.
const RECLASSIFY_BATCH: i64 = 200;

/// Compute again the class of every PR whose class is of other access lines
/// than the project's current ones. Every PR request runs it first; it
/// does nothing unless the lines changed. Idempotent: servers doing it at
/// once write the same rows.
pub async fn reclassify(hub: &Hub, project: &Project) -> Result<()> {
    let key = policy_key(&project.policy);
    loop {
        let stale: Vec<(String, String)> =
            // Two range scans of `prs_by_policy`, empty unless the lines
            // changed (`<>` would read every PR's entry).
            sqlx::query_as("SELECT id, policy_key FROM prs WHERE project_id = $1 AND (policy_key < $2 OR policy_key > $2) LIMIT $3")
                .bind(project.id)
                .bind(&key)
                .bind(RECLASSIFY_BATCH)
                .fetch_all(&hub.db)
                .await?;
        if stale.is_empty() {
            return Ok(());
        }
        let ids: Vec<String> = stale.iter().map(|s| s.0.clone()).collect();
        let paths: Vec<(String, String)> = sqlx::query_as("SELECT pr, path FROM pr_paths WHERE project_id = $1 AND pr = ANY($2)")
            .bind(project.id)
            .bind(&ids)
            .fetch_all(&hub.db)
            .await?;
        let mut by_pr: std::collections::HashMap<&str, Vec<&str>> = std::collections::HashMap::new();
        for (pr, path) in &paths {
            by_pr.entry(pr.as_str()).or_default().push(path.as_str());
        }
        let mut c = hub.db.acquire().await?;
        for (id, old) in &stale {
            let lines = lines_of(&project.policy, by_pr.get(id.as_str()).cloned().unwrap_or_default());
            let class = put_class(&mut c, project.id, &key, &lines).await?;
            sqlx::query("UPDATE prs SET class_id = $1, policy_key = $2 WHERE project_id = $3 AND id = $4 AND policy_key = $5")
                .bind(&class)
                .bind(&key)
                .bind(project.id)
                .bind(id)
                .bind(old)
                .execute(&mut *c)
                .await?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: &str = "pub/ public devs\npub/sec/ security\nfin/ finance\ncarol-d/ carol\n";

    #[test]
    fn a_class_is_read_exactly_when_every_path_is() {
        let policy = AccessPolicy::parse(POLICY);
        let paths = ["pub/a.rs", "pub/sec/k", "fin/x", "carol-d/n", "top.txt", "pub/sec", "pub/deep/x", "pubx/y"];
        // Every viewer the policy can tell apart: subsets of its names.
        let names = ["devs", "security", "finance", "carol"];
        for mask in 0..16u32 {
            for admin in [false, true] {
                let me: Vec<&str> = names.iter().enumerate().filter(|(i, _)| mask & (1 << i) != 0).map(|(_, n)| *n).collect();
                let view = View::new(&policy, admin, |_, n| me.contains(&n));
                for sub in 1..(1u32 << paths.len()) {
                    let touched: Vec<&str> = paths.iter().enumerate().filter(|(i, _)| sub & (1 << i) != 0).map(|(_, p)| *p).collect();
                    let direct = touched.iter().all(|p| view.read(p));
                    assert_eq!(satisfies(&view, &lines_of(&policy, touched.iter().copied()), ""), direct, "{me:?} admin {admin} {touched:?}");
                }
            }
        }
    }

    #[test]
    fn classes_follow_the_lines_not_the_names() {
        let a = AccessPolicy::parse(POLICY);
        let b = AccessPolicy::parse("pub/ public devs ops\npub/sec/ security\nfin/ finance\ncarol-d/ carol\n");
        let c = AccessPolicy::parse("pub/ public devs\nfin/ finance\ncarol-d/ carol\n");
        assert_eq!(policy_key(&a), policy_key(&b));
        assert_ne!(policy_key(&a), policy_key(&c));
        let lines = lines_of(&a, ["pub/a", "fin/b"]);
        assert_ne!(class_id(&policy_key(&a), &lines, ""), class_id(&policy_key(&c), &lines, ""));
        assert_ne!(class_id("k", &lines, ""), class_id("k", &lines, "e1"));
        let view = View::admin(&a);
        assert!(!satisfies(&view, &lines, "e1"), "embargoed classes are S23's");
    }
}
