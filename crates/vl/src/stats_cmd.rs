//! `vl stats`: the project's health on its Veil server (milestone S24,
//! `docs/HUB.md` §13.25), for its admins. The server counts and decides who
//! may see it; `vl` prints its answer.

use std::process::ExitCode;

use anyhow::Result;
use clap::Args;

use crate::{
    cli::JsonOut,
    ctx::Ctx,
    hub_cmd::client_for,
    render::{bold, dim, safe},
};

/// `vl stats [--json]`.
#[derive(Args, Debug)]
pub struct StatsArgs {
    #[command(flatten)]
    pub out: JsonOut,
}

pub fn stats(ctx: &mut Ctx, a: &StatsArgs) -> Result<ExitCode> {
    let (client, _) = client_for(ctx, "origin")?;
    let v = client.health()?;
    if a.out.json {
        println!("{v}");
        return Ok(ExitCode::SUCCESS);
    }
    let n = |w: &str, k: &str| v[w][k].as_u64().unwrap_or(0);
    let rate = |hits: &str, misses: &str| {
        let (h, m) = (n("since_start", hits), n("since_start", misses));
        if h + m == 0 {
            "-".to_string()
        } else {
            format!("{:.1} %", 100.0 * h as f64 / (h + m) as f64)
        }
    };
    println!("{}", bold(&safe(v["project"].as_str().unwrap_or(""))));
    println!("{}", dim("on this server, since it started (last whole minute)"));
    for (label, k) in [
        ("requests", "requests"),
        ("rate-limited", "rate_limited"),
        ("busy (shed)", "busy"),
        ("timed out", "timeouts"),
        ("landings", "landings"),
        ("batches", "landing_batches"),
        ("conflicts", "landing_conflicts"),
        ("rejected", "landing_rejected"),
    ] {
        println!("  {label:<16} {:>10}  ({})", n("since_start", k), n("last_minute", k));
    }
    println!("  {:<16} {:>10}", "tips cache", rate("tips_hits", "tips_misses"));
    println!("  {:<16} {:>10}", "permission cache", rate("permission_hits", "permission_misses"));
    let (branches, behind) = (v["derive"]["branches"].as_i64().unwrap_or(0), v["derive"]["branches_behind"].as_i64().unwrap_or(0));
    println!("  {:<16} {:>10}", "derive lag", format!("{behind} of {branches} branches"));
    Ok(ExitCode::SUCCESS)
}
