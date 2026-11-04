//! Hooks: the runner, the `.veilhooks` parser and the per-device trust
//! store, `vl hooks`, and `--no-verify`.
//!
//! Owned by stream K of the Git-parity round (feature 5a:
//! `docs/design/git-parity/5-hooks-submodules-signed-tags.md`). Stream 0
//! wired the CLI surface; every handler here still refuses with "not
//! implemented yet".

use std::process::ExitCode;

use anyhow::{bail, Result};
use clap::{Args, Subcommand};

use crate::ctx::Ctx;

/// `vl hooks show|trust`.
#[derive(Subcommand, Debug)]
#[expect(dead_code, reason = "stream-0 stub: stream K reads these")]
pub enum HooksCmd {
    /// Show the hooks that would run: device-local ones, and the
    /// repository's `.veilhooks` with its digests and whether this device
    /// trusts them.
    Show,
    /// Trust the repository's `.veilhooks` and every script it names, as
    /// they are now (pinned by digest, recorded on this device only).
    Trust {
        /// Do not ask for confirmation (required when stdin is not a
        /// terminal).
        #[arg(long, short = 'y')]
        yes: bool,
        /// Also trust commands that run a build tool (make, npm, cargo, …),
        /// which read files the trust record cannot pin.
        #[arg(long)]
        i_understand_indirect: bool,
    },
}

/// `--no-verify`, on the commands that run hooks.
#[derive(Args, Debug, Clone, Copy, Default)]
pub struct NoVerifyArgs {
    /// Do not run hooks for this command (not implemented yet).
    #[arg(long)]
    pub no_verify: bool,
}

/// `vl hooks`.
pub fn run(_ctx: &mut Ctx, _cmd: &HooksCmd) -> Result<ExitCode> {
    bail!("`vl hooks` is not implemented yet")
}

/// Commands run as before without `--no-verify`; the flag is refused until
/// stream K implements hooks.
pub fn require_no_verify_unset(a: &NoVerifyArgs) -> Result<()> {
    if a.no_verify {
        bail!("`--no-verify` is not implemented yet");
    }
    Ok(())
}
