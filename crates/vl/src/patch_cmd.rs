//! Patches: `vl format-patch` (export, Git's mbox format) and `vl am`
//! (import, as new changes).
//!
//! Owned by stream P of the Git-parity round (feature 4:
//! `docs/design/git-parity/4-patches.md`). Stream 0 wired the CLI surface;
//! every handler here still refuses with "not implemented yet".

use std::{path::PathBuf, process::ExitCode};

use anyhow::{bail, Result};
use clap::{Args, ValueEnum};

use crate::ctx::Ctx;

/// Whose view of the history a patch shows.
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Audience {
    /// Exactly what the Git export shows: no cloaked content, no cloaked
    /// descriptions, embargo-withheld snapshots refused.
    Public,
    /// Everything you can read, cloaked content included (each patch says
    /// which scopes in an `X-Veil-Audience` header).
    Me,
}

/// `vl format-patch REVSET [-o DIR | --stdout] [--audience public|me] [--include-embargoed ID]
/// [--yes] [--cover-letter] [--binary] [-M]`.
#[derive(Args, Debug)]
#[expect(dead_code, reason = "stream-0 stub: stream P reads these")]
pub struct FormatPatchArgs {
    /// Snapshots to export: `A..B`, `::B` or a single snapshot.
    pub revset: String,
    /// Write one patch file per snapshot into DIR.
    #[arg(short, long, value_name = "DIR", conflicts_with = "stdout")]
    pub output_directory: Option<PathBuf>,
    /// Write the patches to standard output as one mbox.
    #[arg(long)]
    pub stdout: bool,
    /// Whose view to export. `me` includes cloaked content and is never the
    /// default.
    #[arg(long, value_enum, default_value_t = Audience::Public)]
    pub audience: Audience,
    /// With `--audience me`: also include content of this unreleased
    /// embargo (repeatable).
    #[arg(long, value_name = "ID")]
    pub include_embargoed: Vec<String>,
    /// With `--audience me --stdout` to a pipe or file: confirm that the
    /// output holds cloaked content.
    #[arg(long)]
    pub yes: bool,
    /// Also write a cover letter (patch 0).
    #[arg(long)]
    pub cover_letter: bool,
    /// Include binary files as `GIT binary patch` literals.
    #[arg(long)]
    pub binary: bool,
    /// Detect renames.
    #[arg(short = 'M', long)]
    pub find_renames: bool,
}

/// `vl am INPUT [-d DEST] [--3way] [--keep-author | --author-as-me] [--signoff]`.
#[derive(Args, Debug)]
#[expect(dead_code, reason = "stream-0 stub: stream P reads these")]
pub struct AmArgs {
    /// An mbox or patch file, a directory of them, or `-` for standard input.
    #[arg(value_name = "INPUT")]
    pub input: String,
    /// Apply the series on top of this snapshot.
    #[arg(short, long, value_name = "DEST", default_value = "@-")]
    pub destination: String,
    /// Fall back to a three-way merge when a patch's pre-image is known.
    #[arg(long = "3way")]
    pub three_way: bool,
    /// Record each patch's `From:` as the change's author (the default).
    #[arg(long, conflicts_with = "author_as_me")]
    pub keep_author: bool,
    /// Record yourself as the author of every change.
    #[arg(long)]
    pub author_as_me: bool,
    /// Add a `Signed-off-by:` line to each description.
    #[arg(long)]
    pub signoff: bool,
}

/// `vl format-patch`.
pub fn format_patch(_ctx: &mut Ctx, _args: &FormatPatchArgs) -> Result<ExitCode> {
    bail!("`vl format-patch` is not implemented yet")
}

/// `vl am`.
pub fn am(_ctx: &mut Ctx, _args: &AmArgs) -> Result<ExitCode> {
    bail!("`vl am` is not implemented yet")
}
