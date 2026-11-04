//! History rewrites that copy changes: `vl duplicate` and its Git-style
//! alias `vl cherry-pick`.
//!
//! Owned by stream R of the Git-parity round (feature 1:
//! `docs/design/git-parity/1-blame-bisect-duplicate.md`). Stream 0 wired the
//! CLI surface; every handler here still refuses with "not implemented yet".

use std::process::ExitCode;

use anyhow::{bail, Result};
use clap::Args;

use crate::{cli::JsonOut, ctx::Ctx};

/// The description of each duplicate.
#[derive(Args, Debug)]
#[expect(dead_code, reason = "stream-0 stub: stream R reads these")]
pub struct DuplicateDescription {
    /// Keep each source's description as it is (the default; a sealed
    /// description stays sealed).
    #[arg(long, conflicts_with = "message")]
    pub keep_description: bool,
    /// Description of the duplicates instead of the sources' own.
    #[arg(short, long)]
    pub message: Option<String>,
    /// Append `(duplicated from change ID)` to a plain description.
    #[arg(short = 'x')]
    pub record_origin: bool,
}

/// `vl duplicate REV… [-d DEST…] [--keep-description | -m MSG] [-x] [--json]`.
#[derive(Args, Debug)]
#[expect(dead_code, reason = "stream-0 stub: stream R reads these")]
pub struct DuplicateArgs {
    /// Changes to duplicate.
    #[arg(required = true)]
    pub revs: Vec<String>,
    /// Parent of the duplicates (repeat for a merge; default: each source's
    /// own parents).
    #[arg(short, long, value_name = "DEST")]
    pub destination: Vec<String>,
    #[command(flatten)]
    pub description: DuplicateDescription,
    #[command(flatten)]
    pub out: JsonOut,
}

/// `vl cherry-pick REV… [--keep-description | -m MSG] [-x] [--json]`:
/// `vl duplicate REV… -d @-`, then `@` is rebased on top.
#[derive(Args, Debug)]
#[expect(dead_code, reason = "stream-0 stub: stream R reads these")]
pub struct CherryPickArgs {
    /// Changes to copy onto the working copy's parent.
    #[arg(required = true)]
    pub revs: Vec<String>,
    #[command(flatten)]
    pub description: DuplicateDescription,
    #[command(flatten)]
    pub out: JsonOut,
}

/// `vl duplicate`.
pub fn duplicate(_ctx: &mut Ctx, _args: &DuplicateArgs) -> Result<ExitCode> {
    bail!("`vl duplicate` is not implemented yet")
}

/// `vl cherry-pick`.
pub fn cherry_pick(_ctx: &mut Ctx, _args: &CherryPickArgs) -> Result<ExitCode> {
    bail!("`vl cherry-pick` is not implemented yet")
}
