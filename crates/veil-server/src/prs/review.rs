//! Approvals and the review gate (phase-4 design §4.9, threats 15 and 16;
//! product decision 12).
//!
//! * **Who reviews:** someone who sees the PR and may write every path it
//!   touches (an admin, or the groups and people the deciding lines name),
//!   and is not its author. A review is a verdict on the current revision,
//!   signed by the reviewer's device (`veil_core::hub::pr::review_message`)
//!   and bound to the revision's patch.
//! * **What counts** ([`gate`]): each reviewer's latest verdict on any
//!   revision with the current patch (a rebase over unrelated changes keeps
//!   approvals; any change to the files dismisses them), checked again
//!   against the reviewer's access now. Approvals from agent sessions never
//!   count where the rule says `people_only` (always for high risk). The
//!   author's never count. A request for changes, on any revision, holds
//!   the PR until that reviewer approves or an admin dismisses it
//!   ([`dismiss`]); nothing the author does releases it.

use std::collections::{BTreeMap, HashMap};

use serde_json::{json, Value};

use super::{rules::Review, rules::Risk, PrRow};
use crate::{
    error::Result,
    perm::{Project, Viewer},
    Hub,
};

/// One reviewer's latest verdict that applies to the current patch.
#[derive(Clone, Debug)]
pub struct Verdict {
    pub person: i64,
    pub name: String,
    pub revision: i32,
    pub verdict: String,
    pub agent: bool,
    pub body: String,
    pub at: i64,
    pub current: bool,
}

/// The access of `person` in `project` now, from the database.
pub async fn viewer_of(hub: &Hub, project: i64, person: i64) -> Result<Viewer> {
    let (admin, groups): (bool, Vec<i64>) = sqlx::query_as(
        "SELECT EXISTS (SELECT 1 FROM project_admins WHERE project_id = $1 AND person_id = $2), \
         ARRAY(SELECT g.id FROM groups g JOIN group_members m ON m.group_id = g.id WHERE g.project_id = $1 AND m.person_id = $2)",
    )
    .bind(project)
    .bind(person)
    .fetch_one(&hub.db)
    .await?;
    Ok(Viewer {
        person: Some(person),
        admin,
        groups: groups.into_iter().collect(),
    })
}

/// May `viewer` write every one of `paths`?
pub fn writes_all(project: &Project, viewer: &Viewer, paths: &[String]) -> bool {
    let view = project.view(viewer);
    view.admin || paths.iter().all(|p| view.write(p))
}

/// The PR's touched paths.
pub async fn paths_of(hub: &Hub, project: i64, pr: &str) -> Result<Vec<String>> {
    Ok(sqlx::query_scalar("SELECT path FROM pr_paths WHERE project_id = $1 AND pr = $2 ORDER BY path")
        .bind(project)
        .bind(pr)
        .fetch_all(&hub.db)
        .await?)
}

/// Every reviewer's latest verdict on the PR, marked `current` if it was
/// given on a revision with patch `patch`.
pub async fn verdicts(hub: &Hub, project: i64, pr: &str, patch: &str) -> Result<Vec<Verdict>> {
    type Row = (i64, String, i32, String, bool, String, i64, String);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT r.person, pe.name, r.revision, r.verdict, r.agent, r.body, r.at, r.patch FROM pr_reviews r JOIN people pe ON pe.id = r.person \
         WHERE r.project_id = $1 AND r.pr = $2 ORDER BY r.at, r.revision",
    )
    .bind(project)
    .bind(pr)
    .fetch_all(&hub.db)
    .await?;
    let mut latest: BTreeMap<i64, Verdict> = BTreeMap::new();
    for (person, name, revision, verdict, agent, body, at, p) in rows {
        latest.insert(
            person,
            Verdict {
                person,
                name,
                revision,
                verdict,
                agent,
                body,
                at,
                current: p == patch,
            },
        );
    }
    Ok(latest.into_values().collect())
}

/// What the PR needs and has, and whether it may land.
pub struct Gate {
    pub risk: Risk,
    pub approvals: u32,
    pub needed: u32,
    pub people_only: bool,
    pub ready: bool,
    pub reasons: Vec<String>,
    pub reviews: Vec<(Verdict, bool)>,
}

impl Gate {
    pub fn json(&self) -> Value {
        json!({
            "risk": self.risk.name(),
            "needs": { "approvals": self.needed, "people_only": self.people_only },
            "approvals": self.approvals,
            "ready": self.ready,
            "reasons": self.reasons,
            "reviews": self.reviews.iter().map(|(v, counted)| json!({
                "by": v.name,
                "verdict": v.verdict,
                "revision": v.revision,
                "current": v.current,
                "counted": counted,
                "agent": v.agent,
                "body": v.body,
                "at": v.at,
            })).collect::<Vec<_>>(),
        })
    }
}

/// The review gate of `pr`, whose current revision has `patch`, under
/// `rules`, as `viewer` is shown it.
pub async fn gate(hub: &Hub, project: &Project, viewer: &Viewer, pr: &PrRow, patch: &str, rules: &Review) -> Result<Gate> {
    let risk = Risk::parse(&pr.risk);
    let need = rules.need(risk);
    let paths = paths_of(hub, project.id, &pr.id).await?;
    let mut reviews = Vec::new();
    let (mut approvals, mut held) = (0u32, Vec::new());
    let mut access: HashMap<i64, bool> = HashMap::new();
    for v in verdicts(hub, project.id, &pr.id, patch).await? {
        let reviewer = v.person != pr.author;
        // An approval counts while its reviewer may write every path now.
        let counted = reviewer && v.current && v.verdict == "approve" && !(need.people_only && v.agent) && {
            match access.get(&v.person) {
                Some(w) => *w,
                None => {
                    let w = writes_all(project, &viewer_of(hub, project.id, v.person).await?, &paths);
                    access.insert(v.person, w);
                    w
                }
            }
        };
        if counted {
            approvals += 1;
        }
        // A request for changes holds the PR, given on any revision, until
        // that reviewer approves or an admin dismisses it (BUG-1259): never
        // released by what the author does, nor by access changing (a later
        // revision may hide the PR from them; it stays held).
        if reviewer && v.verdict == "request-changes" {
            held.push(v.name.clone());
        }
        reviews.push((v, counted));
    }
    // `.veilrules` is the admins' file (no line names the root): its
    // warnings quote it, so only admins read them.
    let mut reasons: Vec<String> = if project.view(viewer).admin {
        rules.warnings.clone()
    } else if rules.warnings.is_empty() {
        Vec::new()
    } else {
        vec![format!("the project's review rules ({}) need an admin's attention", super::rules::RULES_FILE)]
    };
    if pr.state != "open" {
        reasons.push(format!("the PR is {}", pr.state));
    }
    if approvals < need.approvals {
        reasons.push(format!(
            "{} risk needs {} approval{}{}; it has {approvals}",
            risk.name(),
            need.approvals,
            if need.approvals == 1 { "" } else { "s" },
            if need.people_only { " from people (not agents)" } else { "" },
        ));
    }
    for h in &held {
        reasons.push(format!("{h} asked for changes"));
    }
    let ready = pr.state == "open" && approvals >= need.approvals && held.is_empty();
    Ok(Gate {
        risk,
        approvals,
        needed: need.approvals,
        people_only: need.people_only,
        ready,
        reasons,
        reviews,
    })
}

/// An admin dismisses `person`'s requests for changes on the PR (BUG-1259):
/// the only way one stops holding but the reviewer's own approval. The
/// rows are kept, as `dismissed`. Answers how many were dismissed.
pub async fn dismiss(hub: &Hub, project: i64, pr: &str, person: i64) -> Result<u64> {
    Ok(sqlx::query("UPDATE pr_reviews SET verdict = 'dismissed' WHERE project_id = $1 AND pr = $2 AND person = $3 AND verdict = 'request-changes'")
        .bind(project)
        .bind(pr)
        .bind(person)
        .execute(&hub.db)
        .await?
        .rows_affected())
}
