//! `vl checks` and `vl tested` (`docs/HUB.md` §13.35): CI check reporting,
//! inspection, and `main@tested` resolution.

use std::process::ExitCode;

use anyhow::{anyhow, bail, Result};
use veil_core::{
    hub::ci::{CheckRequest, CheckState},
    ObjectId,
};

use crate::{
    ctx::Ctx,
    hub_cmd::client_for,
    render::{bold, cyan, dim, green, red, safe, yellow},
};

/// Default base for `vl ws new` when `-r` is not specified: `main@tested`
/// from the local `origin/main@tested` remote tag (or `origin` when not yet
/// pulled locally) when a tested snapshot exists, else `None` (caller falls
/// back to `@-`).
pub fn default_ws_base(ctx: &mut Ctx) -> Result<Option<ObjectId>> {
    if let Some(&tested_id) = ctx.repo.view().remote_tags.get("origin/main@tested") {
        if ctx.repo.store().has(&tested_id) {
            return Ok(Some(tested_id));
        }
    }
    if let Ok((client, cfg)) = client_for(ctx, "origin") {
        if let Ok(Some(tips)) = client.tips() {
            let branch = &tips.default_branch;
            if let Some(&tested_id) = tips.tested.get(branch) {
                if !ctx.repo.store().has(&tested_id) {
                    let _ = crate::hub::pull(&mut ctx.repo, "origin", &client, cfg.only.as_deref());
                }
                if ctx.repo.store().has(&tested_id) {
                    return Ok(Some(tested_id));
                }
            }
        }
    }
    Ok(None)
}

#[allow(clippy::too_many_arguments)]
pub fn checks(
    ctx: &mut Ctx,
    rev: Option<&str>,
    name: Option<&str>,
    state: Option<&str>,
    summary: Option<&str>,
    url: Option<&str>,
    log: Option<&str>,
    json: bool,
) -> Result<ExitCode> {
    let (client, _) = client_for(ctx, "origin")?;
    if let Some(state_str) = state {
        let Some(check_name) = name else {
            bail!("give `--name CHECK` when recording a check result with `--state`");
        };
        let state = match state_str {
            "pending" => CheckState::Pending,
            "pass" => CheckState::Pass,
            "fail" => CheckState::Fail,
            "error" => CheckState::Error,
            other => bail!("unknown check state '{other}' (expected pending, pass, fail, or error)"),
        };
        let snap = match rev {
            Some(r) => ObjectId::from_hex(r).or_else(|_| ctx.rev(r))?,
            None => {
                let tips = client.tips()?.ok_or_else(|| anyhow!("no project {} that you can see", safe(&client.url.project)))?;
                *tips
                    .branches
                    .get(&tips.default_branch)
                    .ok_or_else(|| anyhow!("no default branch on origin; give `-r SNAPSHOT`"))?
            }
        };
        let res = client.post_check(&CheckRequest {
            snapshot: snap,
            name: check_name.to_string(),
            state,
            summary: summary.unwrap_or_default().to_string(),
            url: url.map(str::to_string),
            log: log.map(str::to_string),
        })?;
        if json {
            println!("{}", serde_json::to_string_pretty(&res)?);
        } else {
            println!("{} {} on {}", format_state(res.state), bold(&safe(&res.name)), res.snapshot.short());
        }
        return Ok(ExitCode::SUCCESS);
    }

    let resp = client.checks(rev)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&resp)?);
        return Ok(ExitCode::SUCCESS);
    }
    println!("Checks on {}:", bold(&resp.snapshot.short()));
    if resp.checks.is_empty() {
        println!("  {}", dim("(no checks reported)"));
    }
    for c in &resp.checks {
        print!("  {} {}", format_state(c.state), bold(&safe(&c.name)));
        if !c.summary.is_empty() {
            print!(" — {}", safe(&c.summary));
        }
        if let Some(u) = &c.url {
            print!(" ({})", cyan(&safe(u)));
        }
        println!();
    }
    Ok(ExitCode::SUCCESS)
}

pub fn tested(ctx: &mut Ctx, branch: &str, json: bool) -> Result<ExitCode> {
    let (client, _) = client_for(ctx, "origin")?;
    let Some(t) = client.tested(branch)? else {
        bail!("no tested snapshot on '{branch}' yet");
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&t)?);
    } else {
        println!("{}", t.snapshot.hex());
    }
    Ok(ExitCode::SUCCESS)
}

fn format_state(s: CheckState) -> String {
    match s {
        CheckState::Pass => green("pass"),
        CheckState::Fail => red("fail"),
        CheckState::Error => red("error"),
        CheckState::Pending => yellow("pending"),
    }
}
