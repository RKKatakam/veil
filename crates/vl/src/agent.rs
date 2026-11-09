//! Agent attribution as `vl` sets it (`Snapshot::agent`;
//! `docs/design/scale/7-agent-attribution.md`): **only from this `vl`
//! process's own arguments and environment**, never from anything in the
//! repository, the working copy or a sandbox.
//!
//! * `VEIL_AGENT`, `VEIL_AGENT_TASK`, `VEIL_AGENT_PROMPT_REF` and
//!   `VEIL_AGENT_RUN`, for an agent (or harness) that drives `vl` itself:
//!   every snapshot the command creates carries them.
//! * `vl ws exec NAME --agent A [--task T] [--prompt-ref R] [--run ID]`: the
//!   recorded snapshot carries them (the flags win over the environment).
//!   A command inside the sandbox cannot reach the repository at all, so
//!   whatever it sets in its own environment never reaches a snapshot.
//!
//! The workspace socket (S8) stamps through [`current`] too, ignoring any
//! attribution its caller sends.

use std::sync::Mutex;

use anyhow::{bail, Result};
use clap::Args;
use veil_core::object::Attribution;

/// `vl ws exec`'s attribution flags.
#[derive(Args, Debug, Clone, Default)]
pub struct AgentArgs {
    /// Record the run as made by this agent (e.g. "claude-code opus-5.5"); also $VEIL_AGENT.
    #[arg(long, value_name = "AGENT")]
    pub agent: Option<String>,
    /// The agent's task: an id or title (with --agent); also $VEIL_AGENT_TASK.
    #[arg(long, value_name = "TASK", requires = "agent")]
    pub task: Option<String>,
    /// A reference to the agent's prompt: a URL, transcript id or digest (with --agent); also $VEIL_AGENT_PROMPT_REF.
    #[arg(long, value_name = "REF", requires = "agent")]
    pub prompt_ref: Option<String>,
    /// The harness's run or session id (with --agent); also $VEIL_AGENT_RUN.
    #[arg(long, value_name = "ID", requires = "agent")]
    pub run: Option<String>,
}

/// Set by [`set_from_args`]; read by [`current`].
static FROM_ARGS: Mutex<Option<Attribution>> = Mutex::new(None);

/// Checked attribution from its parts; the error names the field, never
/// its value (it may hold escapes).
fn checked(agent: String, task: Option<String>, prompt: Option<String>, run: Option<String>, source: &str) -> Result<Attribution> {
    let a = Attribution {
        agent,
        task: task.filter(|t| !t.is_empty()),
        prompt: prompt.filter(|p| !p.is_empty()),
        run: run.filter(|r| !r.is_empty()),
    };
    if let Err(why) = a.validate() {
        bail!("{source}: {why}");
    }
    Ok(a)
}

/// Take the attribution of `vl ws exec`'s flags for this process.
pub fn set_from_args(args: &AgentArgs) -> Result<()> {
    if let Some(agent) = &args.agent {
        let a = checked(agent.clone(), args.task.clone(), args.prompt_ref.clone(), args.run.clone(), "--agent")?;
        *FROM_ARGS.lock().unwrap_or_else(|e| e.into_inner()) = Some(a);
    }
    Ok(())
}

fn env(name: &str) -> Result<Option<String>> {
    match std::env::var(name) {
        Ok(v) if v.is_empty() => Ok(None),
        Ok(v) => Ok(Some(v)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => bail!("${name} is not valid UTF-8"),
    }
}

/// This process's attribution: `vl ws exec`'s flags, else the
/// environment, else none.
pub fn current() -> Result<Option<Attribution>> {
    if let Some(a) = FROM_ARGS.lock().unwrap_or_else(|e| e.into_inner()).clone() {
        return Ok(Some(a));
    }
    let Some(agent) = env("VEIL_AGENT")? else {
        for other in ["VEIL_AGENT_TASK", "VEIL_AGENT_PROMPT_REF", "VEIL_AGENT_RUN"] {
            if env(other)?.is_some() {
                bail!("${other} is set without $VEIL_AGENT");
            }
        }
        return Ok(None);
    };
    checked(agent, env("VEIL_AGENT_TASK")?, env("VEIL_AGENT_PROMPT_REF")?, env("VEIL_AGENT_RUN")?, "$VEIL_AGENT").map(Some)
}
