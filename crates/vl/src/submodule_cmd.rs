//! Submodules (Git gitlinks): `vl submodule`.
//!
//! Owned by stream G of the Git-parity round (feature 5b:
//! `docs/design/git-parity/5-hooks-submodules-signed-tags.md`). Stream 0
//! wired the CLI surface; every handler here still refuses with "not
//! implemented yet".

use std::process::ExitCode;

use anyhow::{bail, Result};
use clap::Subcommand;

use crate::ctx::Ctx;

/// `vl submodule status|update|set|add`.
#[derive(Subcommand, Debug)]
#[expect(dead_code, reason = "stream-0 stub: stream G reads these")]
pub enum SubmoduleCmd {
    /// Show each submodule's pinned commit and the commit checked out in it.
    Status {
        /// Only these submodules (default: all).
        paths: Vec<String>,
    },
    /// Clone or fetch submodules with `git` (URLs from `.gitmodules`) and
    /// check out their pinned commits.
    Update {
        /// Only these submodules (default: all).
        paths: Vec<String>,
        /// Allow `.gitmodules` URLs that are local paths or `file://`.
        #[arg(long)]
        allow_local: bool,
    },
    /// Pin the submodule at PATH to COMMIT.
    Set {
        /// Path of the submodule.
        path: String,
        /// Full Git commit id to pin.
        commit: String,
    },
    /// Record a Git repository as a submodule at PATH (cloning URL there if
    /// PATH does not exist yet).
    Add {
        /// URL of the submodule's repository (written to `.gitmodules`).
        url: String,
        /// Where the submodule lives (default: the URL's last component).
        path: Option<String>,
    },
}

/// `vl submodule`.
pub fn run(_ctx: &mut Ctx, _cmd: &SubmoduleCmd) -> Result<ExitCode> {
    bail!("`vl submodule` is not implemented yet")
}
