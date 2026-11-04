//! Colocated Git mode: `vl init --colocate`, `vl git colocate`,
//! `vl git uncolocate`, `vl git check-push` (the `pre-push` guard) and
//! `vl policy import-gitignore`.
//!
//! Owned by stream C of the Git-parity round (feature 9:
//! `docs/design/git-parity/9-colocated-git.md`). Stream 0 wired the CLI
//! surface; every handler here still refuses with "not implemented yet".

use std::process::ExitCode;

use anyhow::{bail, Result};
use clap::Args;

use crate::ctx::Ctx;

/// `vl init --colocate`.
#[derive(Args, Debug, Clone, Copy, Default)]
pub struct InitColocateArgs {
    /// Create (or adopt) a real `.git` beside the working copy, kept in step
    /// with Veil (not implemented yet).
    #[arg(long)]
    pub colocate: bool,
}

/// `vl git colocate [--experimental] [--status | --prune]`.
#[derive(Args, Debug)]
#[expect(dead_code, reason = "stream-0 stub: stream C reads these")]
pub struct ColocateArgs {
    /// Required while colocated mode is experimental.
    #[arg(long)]
    pub experimental: bool,
    /// Report the guards instead: exclude block, skip-worktree count, held
    /// local commits, Git version, `pre-push` hook.
    #[arg(long, conflicts_with = "prune")]
    pub status: bool,
    /// Expire the reflogs of superseded local commits and run
    /// `git gc --prune=now`.
    #[arg(long)]
    pub prune: bool,
}

/// `vl git uncolocate`.
#[derive(Args, Debug)]
pub struct UncolocateArgs {}

/// `vl git check-push [REMOTE [URL]]`: Git's `pre-push` hook arguments; the
/// refs to push are read from standard input, as Git gives them.
#[derive(Args, Debug)]
#[expect(dead_code, reason = "stream-0 stub: stream C reads these")]
pub struct CheckPushArgs {
    /// Name of the Git remote being pushed to.
    pub remote: Option<String>,
    /// URL of the Git remote being pushed to.
    pub url: Option<String>,
}

/// `vl policy import-gitignore`.
#[derive(Args, Debug)]
pub struct ImportGitignoreArgs {}

/// `vl init` runs as before without `--colocate`; the flag is refused until
/// stream C implements it (before anything is created).
pub fn require_no_init_colocate(a: &InitColocateArgs) -> Result<()> {
    if a.colocate {
        bail!("`vl init --colocate` is not implemented yet");
    }
    Ok(())
}

/// `vl git colocate`.
pub fn colocate(_ctx: &mut Ctx, _args: &ColocateArgs) -> Result<ExitCode> {
    bail!("`vl git colocate` is not implemented yet")
}

/// `vl git uncolocate`.
pub fn uncolocate(_ctx: &mut Ctx, _args: &UncolocateArgs) -> Result<ExitCode> {
    bail!("`vl git uncolocate` is not implemented yet")
}

/// `vl git check-push`.
pub fn check_push(_ctx: &mut Ctx, _args: &CheckPushArgs) -> Result<ExitCode> {
    bail!("`vl git check-push` is not implemented yet")
}

/// `vl policy import-gitignore`.
pub fn import_gitignore(_ctx: &mut Ctx, _args: &ImportGitignoreArgs) -> Result<()> {
    bail!("`vl policy import-gitignore` is not implemented yet")
}
