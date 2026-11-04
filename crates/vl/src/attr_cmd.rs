//! Per-path attributes (`.gitattributes`) and line endings: `vl attr` and
//! `vl renormalize`.
//!
//! Owned by stream W (phase W2) of the Git-parity round (feature 7:
//! `docs/design/git-parity/7-attributes-line-endings.md`). Stream 0 wired
//! the CLI surface; every handler here still refuses with "not implemented
//! yet".

use std::process::ExitCode;

use anyhow::{bail, Result};
use clap::{Args, Subcommand};

use crate::ctx::Ctx;

/// `vl attr check PATH…`.
#[derive(Args, Debug)]
pub struct AttrArgs {
    #[command(subcommand)]
    pub cmd: AttrCmd,
}

/// The `vl attr` subcommands.
#[derive(Subcommand, Debug)]
#[expect(dead_code, reason = "stream-0 stub: stream W reads these")]
pub enum AttrCmd {
    /// Show the attributes that apply to each path, and those Veil does not
    /// support (like `git check-attr`).
    Check {
        /// Paths to check.
        #[arg(required = true)]
        paths: Vec<String>,
    },
}

/// `vl renormalize [PATH…]`.
#[derive(Args, Debug)]
#[expect(dead_code, reason = "stream-0 stub: stream W reads these")]
pub struct RenormalizeArgs {
    /// Files or directories to re-record (default: all).
    pub paths: Vec<String>,
}

/// `vl attr`.
pub fn attr(_ctx: &mut Ctx, _args: &AttrArgs) -> Result<ExitCode> {
    bail!("`vl attr` is not implemented yet")
}

/// `vl renormalize`.
pub fn renormalize(_ctx: &mut Ctx, _args: &RenormalizeArgs) -> Result<ExitCode> {
    bail!("`vl renormalize` is not implemented yet")
}
