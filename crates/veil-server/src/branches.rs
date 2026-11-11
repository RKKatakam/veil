//! Merged branches can be cleaned up (`BUG-1885`): whether a branch's tip is
//! contained in another branch, S11's agent rule for a deletion, and the
//! source branch of a PR, deleted when the PR lands.
//!
//! Only the `branches` row goes. The branch's search heads and derived rows
//! are left to the purges and GC that exist, and its objects stay while
//! anything else reaches them: the tip is on the target, or what it landed as.

use std::sync::{atomic::Ordering, Arc};

use veil_core::{hub::access::AccessPolicy, ObjectId};

use crate::{
    db::{transaction, Isolation},
    error::{Error, Result},
    landing::Ancestry,
    perm::{Project, Viewer},
    sync::{agent_tip, blocking_staged, AgentTip, Staged},
    Hub,
};

/// Most `landed_from` rows of one snapshot that [`contained`] reads (a
/// snapshot lands once on a branch; more only when it landed on several).
const LANDED_ROWS: i64 = 16;

/// The real `(tip, lineage)` of `branch`, unless it is an embargo's hidden line.
pub(crate) async fn tip_of(hub: &Hub, project: i64, branch: &str) -> Result<Option<(ObjectId, i64)>> {
    let row: Option<(String, i64)> =
        sqlx::query_as("SELECT target, lineage FROM branches WHERE project_id = $1 AND name = $2 AND hidden_for_embargo IS NULL")
            .bind(project)
            .bind(branch)
            .fetch_optional(&hub.db)
            .await?;
    match row {
        Some((t, lineage)) => Ok(Some((ObjectId::from_hex(&t).map_err(|e| Error::Other(e.into()))?, lineage))),
        None => Ok(None),
    }
}

/// A branch that a merged-branch cleanup never deletes, whoever asks: the
/// default branch, a protected one, an embargo's line.
pub(crate) fn kept(name: &str, default_branch: &str, protected: &std::collections::BTreeSet<String>) -> bool {
    name == default_branch
        || protected.contains(name)
        || name.starts_with(veil_core::embargo::EMBARGO_BRANCH_PREFIX)
        || veil_core::embargo::embargo_id_of_branch(name).is_some()
}

/// Is `tip` contained in the branch `anc` answers for (at `target_tip`)? It
/// is the tip or below it; or the landing service landed it there
/// (`landed_from`, kept for good: a landing lands a snapshot's whole stack,
/// as other snapshots), and what it landed as is the tip or below it.
/// Bounded as a landing's own question ([`Ancestry::has`]): `warming` while
/// the derived graph cannot tell.
pub(crate) async fn contained(hub: &Hub, project: i64, anc: &mut Ancestry, target_tip: ObjectId, tip: ObjectId) -> Result<bool> {
    if tip == target_tip || anc.has(tip).await? {
        return Ok(true);
    }
    let landed: Vec<String> = sqlx::query_scalar("SELECT landed FROM landed_from WHERE project_id = $1 AND source = $2 LIMIT $3")
        .bind(project)
        .bind(tip.hex())
        .bind(LANDED_ROWS)
        .fetch_all(&hub.db)
        .await?;
    for hex in landed {
        let l = ObjectId::from_hex(&hex).map_err(|e| Error::Other(e.into()))?;
        if l == target_tip || anc.has(l).await? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// S11's rule ([`agent_tip`]) for an agent session that deletes a branch at
/// `tip`: only a branch it may move, so one whose tip it could have set from
/// each of that tip's parents. A narrowed session's first question is asked
/// of every parent before any other (BUG-1481).
pub(crate) async fn agent_may_delete(
    hub: &Arc<Hub>,
    project: &Project,
    viewer: &Viewer,
    tip: ObjectId,
    staged: Option<Arc<Staged>>,
) -> Result<Option<AgentTip>> {
    if !viewer.agent {
        return Ok(None);
    }
    let (v, text, bindings) = (viewer.clone(), project.policy_text.clone(), project.bindings.clone());
    blocking_staged(hub, project.id, staged, move |src| {
        let p = Project {
            id: src.project,
            name: String::new(),
            default_branch: String::new(),
            policy: AccessPolicy::parse(&text),
            policy_text: String::new(),
            bindings,
        };
        let view = p.view(&v);
        let mut access = false;
        for parent in src.snapshot(&tip)?.parents.clone() {
            match agent_tip(src, &view, false, Some(parent), tip)? {
                Some(AgentTip::Narrowed) => return Ok(Some(AgentTip::Narrowed)),
                Some(AgentTip::Access) => access = true,
                Some(AgentTip::DefaultBranch) | None => {}
            }
        }
        Ok(access.then_some(AgentTip::Access))
    })
    .await
}

/// The branch a PR's head was named by, if `head` names one (not the target,
/// not an embargo's line) whose tip is that head: the PR's source branch.
pub(crate) async fn source_of_pr(hub: &Hub, project: i64, head: &str, target: &str, head_id: ObjectId) -> Result<Option<String>> {
    if head == target
        || head.starts_with(veil_core::embargo::EMBARGO_BRANCH_PREFIX)
        || veil_core::embargo::embargo_id_of_branch(head).is_some()
        || veil_core::commands::validate_tag_name(head).is_err()
    {
        return Ok(None);
    }
    Ok(tip_of(hub, project, head).await?.filter(|(tip, _)| *tip == head_id).map(|_| head.to_string()))
}

/// A PR landed: delete its source branch, when the branch still points at
/// the head that landed (so everything on it is on the target now). Never
/// the default branch, the target, a protected branch or an embargo's line;
/// not at all with `[branches] delete_merged = false` in `.veilrules`. The
/// deletion is one compare-and-swap on the branch's tip. Best effort, after
/// the landing: a branch it leaves is deleted by anyone who may write.
pub(crate) async fn delete_landed_pr_branch(hub: &Arc<Hub>, project: &Project, pr: &str, revision: i32, actor: i64) -> Result<()> {
    let row: Option<(Option<String>, String, String)> = sqlx::query_as(
        "SELECT p.source_branch, p.target, r.head FROM prs p JOIN pr_revisions r ON r.project_id = p.project_id AND r.pr = p.id AND r.n = $3 \
         WHERE p.project_id = $1 AND p.id = $2 AND p.state = 'landed'",
    )
    .bind(project.id)
    .bind(pr)
    .bind(revision)
    .fetch_optional(&hub.db)
    .await?;
    let Some((Some(source), target, head)) = row else {
        return Ok(());
    };
    let default_tip = tip_of(hub, project.id, &project.default_branch).await?.map(|(t, _)| t);
    let rules = blocking_staged(hub, project.id, None, move |src| crate::landing::rules(src, default_tip)).await?;
    if !rules.delete_merged() || source == target || kept(&source, &project.default_branch, &rules.protected) {
        return Ok(());
    }
    let notify = hub.caches.notices.load(Ordering::SeqCst);
    let (pid, pr) = (project.id, pr.to_string());
    let deleted = transaction(&hub.db, Isolation::ReadCommitted, move |c| {
        let (source, head, pr) = (source.clone(), head.clone(), pr.clone());
        Box::pin(async move {
            let n = sqlx::query("DELETE FROM branches WHERE project_id = $1 AND name = $2 AND target = $3 AND hidden_for_embargo IS NULL")
                .bind(pid)
                .bind(&source)
                .bind(&head)
                .execute(&mut *c)
                .await?
                .rows_affected();
            if n == 1 {
                sqlx::query("INSERT INTO audit_log (project_id, at, actor, action, details) VALUES ($1, $2, $3, 'push', $4)")
                    .bind(pid)
                    .bind(veil_core::now_millis())
                    .bind(actor)
                    .bind(format!("deleted the branch {source:?}: the PR {pr} landed"))
                    .execute(&mut *c)
                    .await?;
                if notify {
                    sqlx::query("SELECT pg_notify($1, $2)").bind(crate::caches::TIPS_CHANNEL).bind(pid.to_string()).execute(&mut *c).await?;
                }
            }
            Ok(n == 1)
        })
    })
    .await?;
    if deleted {
        hub.caches.tips_changed(pid);
    }
    Ok(())
}
