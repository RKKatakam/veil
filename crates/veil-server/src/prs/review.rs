//! Approvals and the review gate (phase-4 design §4.9, threats 15 and 16;
//! product decision 12).
//!
//! * **Who reviews:** someone who sees the PR and may write every path it
//!   touches (an admin, or the groups and people the deciding lines name),
//!   and is not its author. A review is a verdict on the current revision,
//!   signed by the reviewer's device (`veil_core::hub::pr::review_message`)
//!   and bound to the revision's patch.
//! * **What counts** ([`gate`]): the current revision's files are rated
//!   under the rules in force now (BUG-1424), and each reviewer's latest
//!   verdict on any revision with the current patch counts (a rebase over unrelated changes keeps
//!   approvals; any change to the files dismisses them), checked again
//!   against the reviewer's access now. Approvals from agent sessions never
//!   count where the rule says `people_only` (always for high risk). The
//!   author's never count. A request for changes, on any revision, holds
//!   the PR until that reviewer approves or an admin dismisses it
//!   ([`dismiss`]); nothing the author does releases it.

use std::collections::HashMap;

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
    /// Its text, if it is one of the reviews an answer shows.
    pub body: Option<String>,
    /// Bytes of its text.
    pub size: i64,
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

/// Reviews a PR answer shows (the latest ones), and the bytes of their
/// texts it reads.
pub const REVIEWS_SHOWN: usize = 100;
pub const REVIEW_BYTES: usize = 256 << 10;

/// Every reviewer's latest verdict on the PR, without its text (one row per
/// reviewer, chosen in the query), marked `current` if it was given on a
/// revision with patch `patch`; the texts of the latest
/// [`REVIEWS_SHOWN`] within [`REVIEW_BYTES`] are read after.
pub async fn verdicts(hub: &Hub, project: i64, pr: &str, patch: &str) -> Result<Vec<Verdict>> {
    type Row = (i64, String, i32, String, bool, i64, String, i64);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT DISTINCT ON (r.person) r.person, pe.name, r.revision, r.verdict, r.agent, r.at, r.patch, octet_length(r.body)::BIGINT \
         FROM pr_reviews r JOIN people pe ON pe.id = r.person WHERE r.project_id = $1 AND r.pr = $2 \
         ORDER BY r.person, r.at DESC, r.revision DESC",
    )
    .bind(project)
    .bind(pr)
    .fetch_all(&hub.db)
    .await?;
    let mut out: Vec<Verdict> = rows
        .into_iter()
        .map(|(person, name, revision, verdict, agent, at, p, size)| Verdict { person, name, revision, verdict, agent, body: None, size, at, current: p == patch })
        .collect();
    out.sort_by_key(|a| std::cmp::Reverse((a.at, a.person)));
    let mut bytes = 0usize;
    let mut want: Vec<(i64, i32)> = Vec::new();
    for v in out.iter().take(REVIEWS_SHOWN) {
        if bytes + v.size as usize > REVIEW_BYTES {
            break;
        }
        bytes += v.size as usize;
        want.push((v.person, v.revision));
    }
    if !want.is_empty() {
        let (people, revs): (Vec<i64>, Vec<i32>) = want.iter().copied().unzip();
        let bodies: Vec<(i64, i32, String)> = sqlx::query_as(
            "SELECT r.person, r.revision, r.body FROM UNNEST($3::bigint[], $4::int[]) AS w(person, revision) \
             JOIN pr_reviews r ON r.project_id = $1 AND r.pr = $2 AND r.person = w.person AND r.revision = w.revision",
        )
        .bind(project)
        .bind(pr)
        .bind(&people)
        .bind(&revs)
        .fetch_all(&hub.db)
        .await?;
        let bodies: HashMap<(i64, i32), String> = bodies.into_iter().map(|(p, r, b)| ((p, r), b)).collect();
        for v in out.iter_mut() {
            v.body = bodies.get(&(v.person, v.revision)).cloned();
        }
    }
    Ok(out)
}

/// One verdict, as every verdict is written: the review row, and the holds
/// (BUG-1278, BUG-1323, BUG-1326). A request for changes holds every PR
/// touching any path this PR touches, whoever opened it; an approval
/// releases a hold for the PR approved only ([`gate`]), and only an
/// admin's dismissal deletes it. With
/// `only_current`, nothing is written unless `revision` is still the PR's
/// and the PR is open; answers whether it was written.
#[allow(clippy::too_many_arguments)]
pub async fn put_verdict(
    hub: &Hub,
    project: i64,
    pr: &str,
    revision: i32,
    person: i64,
    verdict: &str,
    patch: &str,
    agent: bool,
    device: &str,
    signature: &str,
    body: &str,
    only_current: bool,
) -> Result<bool> {
    let (pr, verdict, patch, device, signature, body) = (pr.to_string(), verdict.to_string(), patch.to_string(), device.to_string(), signature.to_string(), body.to_string());
    let now = veil_core::now_millis();
    crate::db::transaction(&hub.db, crate::db::Isolation::ReadCommitted, move |c| {
        let (pr, verdict, patch, device, signature, body) = (pr.clone(), verdict.clone(), patch.clone(), device.clone(), signature.clone(), body.clone());
        Box::pin(async move {
            let stored = sqlx::query(
                "INSERT INTO pr_reviews (project_id, pr, revision, person, verdict, patch, agent, device, signature, body, at) \
                 SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11 WHERE NOT $12 OR EXISTS \
                   (SELECT 1 FROM prs WHERE project_id = $1 AND id = $2 AND revision = $3 AND state = 'open') \
                 ON CONFLICT (project_id, pr, revision, person) DO UPDATE SET verdict = EXCLUDED.verdict, patch = EXCLUDED.patch, \
                   agent = EXCLUDED.agent, device = EXCLUDED.device, signature = EXCLUDED.signature, body = EXCLUDED.body, at = EXCLUDED.at",
            )
            .bind(project)
            .bind(&pr)
            .bind(revision)
            .bind(person)
            .bind(&verdict)
            .bind(&patch)
            .bind(agent)
            .bind(&device)
            .bind(&signature)
            .bind(&body)
            .bind(now)
            .bind(only_current)
            .execute(&mut *c)
            .await?
            .rows_affected();
            if stored == 0 {
                return Ok(false);
            }
            if verdict == "request-changes" {
                let paths: Vec<String> = sqlx::query_scalar("SELECT path FROM pr_paths WHERE project_id = $1 AND pr = $2")
                    .bind(project)
                    .bind(&pr)
                    .fetch_all(&mut *c)
                    .await?;
                sqlx::query(
                    "INSERT INTO pr_holds (project_id, person, path, pr, at) SELECT $1, $2, p, $4, $5 FROM UNNEST($3::text[]) AS p \
                     ON CONFLICT (project_id, person, path) DO UPDATE SET pr = EXCLUDED.pr, at = EXCLUDED.at",
                )
                .bind(project)
                .bind(person)
                .bind(&paths)
                .bind(&pr)
                .bind(now)
                .execute(&mut *c)
                .await?;
            }
            Ok(true)
        })
    })
    .await
}

/// The reviewers whose requests for changes are at any of `paths`
/// (BUG-1326: whoever opened the PR), with the time of each one's latest
/// hold there.
pub async fn holds_on(hub: &Hub, project: i64, paths: &[String]) -> Result<Vec<(i64, String, i64)>> {
    Ok(sqlx::query_as(
        "SELECT h.person, pe.name, MAX(h.at) FROM pr_holds h JOIN people pe ON pe.id = h.person \
         WHERE h.project_id = $1 AND h.path = ANY($2) GROUP BY h.person, pe.name ORDER BY pe.name",
    )
    .bind(project)
    .bind(paths)
    .fetch_all(&hub.db)
    .await?)
}

/// What the PR needs and has, and whether it may land.
pub struct Gate {
    pub risk: Risk,
    pub approvals: u32,
    pub needed: u32,
    pub people_only: bool,
    pub ready: bool,
    pub reasons: Vec<String>,
    /// The latest reviews (at most [`REVIEWS_SHOWN`]), and how many
    /// reviewers there are.
    pub reviews: Vec<(Verdict, bool)>,
    pub total: usize,
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
            "reviews_total": self.total,
        })
    }
}

/// The review gate of `pr`, whose current revision has `patch` and risk
/// `risk` (rated under `rules`, the rules in force: BUG-1424), as
/// `viewer` is shown it. Every route asks through [`super::gate`].
pub async fn gate(hub: &Hub, project: &Project, viewer: &Viewer, pr: &PrRow, patch: &str, risk: Risk, rules: &Review) -> Result<Gate> {
    let need = rules.need(risk);
    let paths = paths_of(hub, project.id, &pr.id).await?;
    let mut reviews = Vec::new();
    let mut approvals = 0u32;
    let mut access: HashMap<i64, bool> = HashMap::new();
    let latest = verdicts(hub, project.id, &pr.id, patch).await?;
    // Requests for changes at any of these paths, whoever opened this PR
    // (BUG-1326): released for this PR only by that reviewer's approval of
    // it (its current patch, given after the hold), for every PR by an
    // admin's dismissal.
    let held: Vec<String> = holds_on(hub, project.id, &paths)
        .await?
        .into_iter()
        .filter(|(person, _, at)| !latest.iter().any(|v| v.person == *person && v.verdict == "approve" && v.current && v.at >= *at))
        .map(|(_, name, _)| name)
        .collect();
    for v in latest {
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
        reviews.push((v, counted));
    }
    let total = reviews.len();
    reviews.truncate(REVIEWS_SHOWN);
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
        total,
    })
}

/// An admin dismisses `person`'s requests for changes on the PR (BUG-1259,
/// BUG-1326): the only way one stops holding but the reviewer's own
/// approval of a PR. Their holds at this PR's paths go, for every PR there;
/// their review rows stay, shown as `dismissed`. Answers how many holds
/// went (one statement: of two admins at once, one dismisses, the other
/// finds none).
pub async fn dismiss(hub: &Hub, project: i64, pr: &PrRow, person: i64) -> Result<u64> {
    let paths = paths_of(hub, project, &pr.id).await?;
    let gone = sqlx::query("DELETE FROM pr_holds WHERE project_id = $1 AND person = $2 AND path = ANY($3)")
        .bind(project)
        .bind(person)
        .bind(&paths)
        .execute(&hub.db)
        .await?
        .rows_affected();
    if gone > 0 {
        sqlx::query("UPDATE pr_reviews SET verdict = 'dismissed' WHERE project_id = $1 AND pr = $2 AND person = $3 AND verdict = 'request-changes'")
            .bind(project)
            .bind(&pr.id)
            .bind(person)
            .execute(&hub.db)
            .await?;
    }
    Ok(gone)
}
