//! `vl session agent`: an agent session for a harness (`docs/HUB.md`
//! §13.27). The server makes it from this person's session, for the
//! project of `origin`; `vl` prints it once and keeps nothing.

use std::process::ExitCode;

use anyhow::{bail, Result};
use veil_core::{hub::agent::AgentSessionRequest, object::Attribution};

use crate::{agent::AgentArgs, ctx::Ctx, hub_cmd::client_for};

pub fn agent(ctx: &mut Ctx, only: &[String], a: &AgentArgs) -> Result<ExitCode> {
    let Some(agent) = a.agent.clone() else {
        bail!("name the agent: `vl session agent --agent NAME [--task T] [--prompt-ref R] [--run ID] [--only PATH…]`");
    };
    let attribution = Attribution {
        agent,
        task: a.task.clone(),
        prompt: a.prompt_ref.clone(),
        run: a.run.clone(),
    };
    if let Err(why) = attribution.validate() {
        bail!("--agent: {why}");
    }
    // Paths as typed here, from the project root (as `.veilpolicy`'s).
    let only: Vec<String> = only.iter().map(|p| p.trim_start_matches("./").to_string()).collect();
    let (client, _) = client_for(ctx, "origin")?;
    let session = client.agent_session(&AgentSessionRequest {
        project: client.url.project.clone(),
        attribution,
        only,
        seconds: None,
    })?;
    println!("{}", serde_json::to_string_pretty(&session)?);
    Ok(ExitCode::SUCCESS)
}
