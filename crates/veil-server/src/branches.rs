//! Merged-branch cleanup (`BUG-1885`): containment checks on the real history,
//! narrowed-agent checks for branch deletion, and automatic source-branch
//! cleanup when a PR lands.

use std::{
    collections::{HashMap, HashSet},
    sync::{atomic::Ordering, Arc},
};

use veil_core::{hub::access::AccessPolicy, ObjectId};

use crate::{
    db::{transaction, Isolation},
    error::{Error, Result},
    landing::{Ancestry, Landed},
    perm::{Project, Viewer},
    sync::{agent_tip, blocking_staged, root_snapshot_id, AgentTip, Staged},
    Hub,
};

/// Current real `(tip, lineage)` of visible branch `branch`, if it exists.
pub async fn lineage_of(hub: &Hub, project_id: i64, branch: &str) -> Result<Option<(ObjectId, i64)>> {
    let row: Option<(String, i64)> = sqlx::query_as(
        "SELECT target, lineage FROM branches WHERE project_id = $1 AND name = $2 AND hidden_for_embargo IS NULL",
    )
    .bind(project_id)
    .bind(branch)
    .fetch_optional(&hub.db)
    .await?;
    let Some((t, lineage)) = row else {
        return Ok(None);
    };
    let tip = ObjectId::from_hex(&t).map_err(|e| Error::Other(e.into()))?;
    Ok(Some((tip, lineage)))
}

async fn direct_ancestor(
    hub: &Arc<Hub>,
    project_id: i64,
    staged: Option<Arc<Staged>>,
    a: ObjectId,
    b: ObjectId,
) -> Result<bool> {
    blocking_staged(hub, project_id, staged, move |src| {
        let root = root_snapshot_id();
        let mut seen = HashSet::new();
        let mut stack = vec![b];
        while let Some(x) = stack.pop() {
            if x == a {
                return Ok(true);
            }
            if !seen.insert(x) || x == root {
                continue;
            }
            stack.extend(src.snapshot(&x)?.parents.iter().copied());
        }
        Ok(false)
    })
    .await
}

async fn anc_has(
    hub: &Arc<Hub>,
    project_id: i64,
    staged: &Option<Arc<Staged>>,
    anc: &mut Ancestry,
    target_tip: ObjectId,
    x: ObjectId,
) -> Result<bool> {
    match anc.has(x).await {
        Ok(v) => Ok(v),
        Err(Error::Api { code: "warming", .. }) => direct_ancestor(hub, project_id, staged.clone(), x, target_tip).await,
        Err(e) => Err(e),
    }
}

async fn landed_from_on_target(
    hub: &Arc<Hub>,
    project_id: i64,
    staged: &Option<Arc<Staged>>,
    anc: &mut Ancestry,
    target_tip: ObjectId,
    source: ObjectId,
) -> Result<bool> {
    let rows: Vec<String> = sqlx::query_scalar("SELECT landed FROM landed_from WHERE project_id = $1 AND source = $2")
        .bind(project_id)
        .bind(source.hex())
        .fetch_all(&hub.db)
        .await?;
    for hex in rows {
        if let Ok(lid) = ObjectId::from_hex(&hex) {
            if anc_has(hub, project_id, staged, anc, target_tip, lid).await? {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Is `branch_tip` completely contained in `target_branch` (at `target_tip`,
/// `target_lineage`) in the real history — either as a direct ancestor/equal
/// of `target_tip` or with every change along its line already landed on
/// `target_branch` with the same edits?
pub async fn contained_in_branch(
    hub: &Arc<Hub>,
    project_id: i64,
    staged: Option<Arc<Staged>>,
    branch_tip: ObjectId,
    target_branch: &str,
    target_tip: ObjectId,
    target_lineage: i64,
) -> Result<bool> {
    let root = root_snapshot_id();
    if branch_tip == target_tip || branch_tip == root {
        return Ok(true);
    }
    let mut anc = Ancestry::new_staged(
        hub.clone(),
        project_id,
        target_branch,
        target_tip,
        target_lineage,
        staged.clone(),
    );
    if anc_has(hub, project_id, &staged, &mut anc, target_tip, branch_tip).await? {
        return Ok(true);
    }
    let empty_fresh = HashMap::new();
    let mut seen = HashSet::new();
    let mut stack = vec![branch_tip];
    while let Some(y) = stack.pop() {
        if !seen.insert(y) || y == root || y == target_tip {
            continue;
        }
        if anc_has(hub, project_id, &staged, &mut anc, target_tip, y).await? {
            continue;
        }
        let landed_same = match anc.landed(y, true, &empty_fresh).await {
            Ok(Landed::Same) => true,
            Ok(Landed::Other) => return Ok(false),
            Ok(Landed::No) => landed_from_on_target(hub, project_id, &staged, &mut anc, target_tip, y).await?,
            Err(Error::Api { code: "warming", .. }) => {
                landed_from_on_target(hub, project_id, &staged, &mut anc, target_tip, y).await?
            }
            Err(e) => return Err(e),
        };
        if !landed_same {
            return Ok(false);
        }
        let st = staged.clone();
        let parents = blocking_staged(hub, project_id, st, move |src| Ok(src.snapshot(&y)?.parents.clone())).await?;
        stack.extend(parents);
    }
    Ok(true)
}

/// S11's `agent_tip` check applied to deleting a merged branch at `branch_tip`:
/// an agent session may delete only a branch whose tip change it could move
/// (`Narrowed` checked across all parents before `Access`, preserving BUG-1481).
pub(crate) async fn agent_delete_check(
    hub: &Arc<Hub>,
    project: &Project,
    viewer: &Viewer,
    branch_tip: ObjectId,
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
        let parents = src.snapshot(&branch_tip)?.parents.clone();
        let mut saw_access = false;
        for parent in parents {
            match agent_tip(src, &view, false, Some(parent), branch_tip)? {
                Some(AgentTip::Narrowed) => return Ok(Some(AgentTip::Narrowed)),
                Some(AgentTip::Access) => saw_access = true,
                Some(AgentTip::DefaultBranch) => return Ok(Some(AgentTip::DefaultBranch)),
                None => {}
            }
        }
        Ok(saw_access.then_some(AgentTip::Access))
    })
    .await
}

/// If `head_arg` names an existing non-embargo branch distinct from `onto`
/// whose current tip is `head_id`, return its name as the PR's source branch.
pub async fn pr_source_branch(
    hub: &Hub,
    project_id: i64,
    head_arg: &str,
    onto: &str,
    head_id: ObjectId,
) -> Result<Option<String>> {
    if head_arg == onto
        || head_arg.starts_with(veil_core::embargo::EMBARGO_BRANCH_PREFIX)
        || veil_core::embargo::embargo_id_of_branch(head_arg).is_some()
        || veil_core::commands::validate_tag_name(head_arg).is_err()
    {
        return Ok(None);
    }
    let Some((tip, _)) = lineage_of(hub, project_id, head_arg).await? else {
        return Ok(None);
    };
    Ok((tip == head_id).then(|| head_arg.to_string()))
}

/// Best-effort cleanup of a landed PR's source branch (`BUG-1885`): deletes it
/// iff `[branches] delete_merged` is enabled (the default), the branch is
/// neither the default branch, the PR's target, a protected branch, nor an
/// embargo line, and its current tip is contained in the PR's target branch.
pub async fn delete_merged_pr_branch(hub: &Arc<Hub>, project_id: i64, pr_id: &str, actor: i64) -> Result<()> {
    let row: Option<(Option<String>, String, String)> = sqlx::query_as(
        "SELECT p.source_branch, p.target, prj.default_branch \
         FROM prs p JOIN projects prj ON prj.id = p.project_id \
         WHERE p.project_id = $1 AND p.id = $2",
    )
    .bind(project_id)
    .bind(pr_id)
    .fetch_optional(&hub.db)
    .await?;
    let Some((Some(src_branch), target_branch, default_branch)) = row else {
        return Ok(());
    };
    if src_branch == default_branch
        || src_branch == target_branch
        || src_branch.starts_with(veil_core::embargo::EMBARGO_BRANCH_PREFIX)
        || veil_core::embargo::embargo_id_of_branch(&src_branch).is_some()
    {
        return Ok(());
    }
    let default_tip = lineage_of(hub, project_id, &default_branch).await?.map(|(t, _)| t);
    let rules = blocking_staged(hub, project_id, None, move |src| crate::landing::rules(src, default_tip)).await?;
    if !rules.delete_merged() || rules.protected.contains(&src_branch) {
        return Ok(());
    }
    let Some((src_tip, _)) = lineage_of(hub, project_id, &src_branch).await? else {
        return Ok(());
    };
    let Some((target_tip, target_lineage)) = lineage_of(hub, project_id, &target_branch).await? else {
        return Ok(());
    };
    if !contained_in_branch(
        hub,
        project_id,
        None,
        src_tip,
        &target_branch,
        target_tip,
        target_lineage,
    )
    .await?
    {
        return Ok(());
    }
    let notify = hub.caches.notices.load(Ordering::SeqCst);
    let src_hex = src_tip.hex();
    let pr_id_owned = pr_id.to_string();
    let src_for_tx = src_branch.clone();
    let target_for_tx = target_branch.clone();
    let deleted = transaction(&hub.db, Isolation::ReadCommitted, move |c| {
        let src_b = src_for_tx.clone();
        let tgt_b = target_for_tx.clone();
        let src_h = src_hex.clone();
        let pr_s = pr_id_owned.clone();
        Box::pin(async move {
            let n = sqlx::query(
                "DELETE FROM branches \
                 WHERE project_id = $1 AND name = $2 AND target = $3 AND hidden_for_embargo IS NULL \
                 AND EXISTS (SELECT 1 FROM branches WHERE project_id = $1 AND name = $4 AND lineage = $5)",
            )
            .bind(project_id)
            .bind(&src_b)
            .bind(&src_h)
            .bind(&tgt_b)
            .bind(target_lineage)
            .execute(&mut *c)
            .await?
            .rows_affected();
            if n == 1 {
                sqlx::query("INSERT INTO audit_log (project_id, at, actor, action, details) VALUES ($1, $2, $3, 'push', $4)")
                    .bind(project_id)
                    .bind(veil_core::now_millis())
                    .bind((actor > 0).then_some(actor))
                    .bind(format!("deleted merged PR branch {src_b:?} ({pr_s})"))
                    .execute(&mut *c)
                    .await?;
                if notify {
                    sqlx::query("SELECT pg_notify($1, $2)")
                        .bind(crate::caches::TIPS_CHANNEL)
                        .bind(project_id.to_string())
                        .execute(&mut *c)
                        .await?;
                }
            }
            Ok(n == 1)
        })
    })
    .await?;
    if deleted {
        hub.caches.tips_changed(project_id);
    }
    Ok(())
}
