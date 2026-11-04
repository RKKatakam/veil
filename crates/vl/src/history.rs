//! History read tools: `vl blame`, `vl grep`, `vl bisect`, the `vl log`
//! filters and the rename flags of `vl diff` / `vl show`.
//!
//! Owned by stream H of the Git-parity round (features 1, 2 and 3:
//! `docs/design/git-parity/1-blame-bisect-duplicate.md`,
//! `2-renames.md`, `3-history-search-grep.md`). Stream 0 wired the CLI
//! surface; every handler here still refuses with "not implemented yet".

use std::process::ExitCode;

use anyhow::{bail, Result};
use clap::{Args, Subcommand};

use crate::{cli::JsonOut, ctx::Ctx};

// ---- vl blame -----------------------------------------------------------------

/// `vl blame PATH [-r REV] [-L START,END] [--follow] [--max-changes N] [--public] [--json]`.
#[derive(Args, Debug)]
#[expect(dead_code, reason = "stream-0 stub: stream H reads these")]
pub struct BlameArgs {
    /// File to annotate.
    pub path: String,
    /// Snapshot whose version of the file to annotate.
    #[arg(short, long, default_value = "@")]
    pub rev: String,
    /// Only annotate lines START to END (1-based, inclusive).
    #[arg(short = 'L', value_name = "START,END")]
    pub lines: Option<String>,
    /// Follow the file across renames.
    #[arg(long)]
    pub follow: bool,
    /// Stop after visiting this many snapshots; lines still open are
    /// reported as unattributed.
    #[arg(long, value_name = "N", default_value_t = 100_000)]
    pub max_changes: usize,
    /// Annotate as a public mirror sees the history (no cloaked versions).
    #[arg(long)]
    pub public: bool,
    #[command(flatten)]
    pub out: JsonOut,
}

/// `vl blame`.
pub fn blame(_ctx: &mut Ctx, _args: &BlameArgs) -> Result<ExitCode> {
    bail!("`vl blame` is not implemented yet")
}

// ---- vl grep ------------------------------------------------------------------

/// `vl grep PATTERN [-r REV] [-i] [-F] [-w] [-n] [-l] [-c] [--max-count N] [-a] [--json] [--] [PATH…]`.
#[derive(Args, Debug)]
#[expect(dead_code, reason = "stream-0 stub: stream H reads these")]
pub struct GrepArgs {
    /// Regular expression (or, with -F, literal string) to search for.
    pub pattern: String,
    /// Only search these files or directories.
    pub paths: Vec<String>,
    /// Snapshot to search (never the working copy itself).
    #[arg(short, long, default_value = "@")]
    pub rev: String,
    /// Match case-insensitively.
    #[arg(short, long)]
    pub ignore_case: bool,
    /// Take PATTERN as a literal string, not a regular expression.
    #[arg(short = 'F', long)]
    pub fixed_strings: bool,
    /// Match whole words only.
    #[arg(short, long)]
    pub word_regexp: bool,
    /// Print line numbers.
    #[arg(short = 'n', long)]
    pub line_number: bool,
    /// Print only the names of files that match.
    #[arg(short = 'l', long)]
    pub files_with_matches: bool,
    /// Print only the number of matching lines per file.
    #[arg(short, long)]
    pub count: bool,
    /// Stop after N matching lines per file.
    #[arg(long, value_name = "N")]
    pub max_count: Option<usize>,
    /// Search binary files as text.
    #[arg(short = 'a', long)]
    pub text: bool,
    #[command(flatten)]
    pub out: JsonOut,
}

/// `vl grep`.
pub fn grep(_ctx: &mut Ctx, _args: &GrepArgs) -> Result<ExitCode> {
    bail!("`vl grep` is not implemented yet")
}

// ---- vl bisect ----------------------------------------------------------------

/// `vl bisect start|good|bad|skip|run|reset|log`.
#[derive(Subcommand, Debug)]
#[expect(dead_code, reason = "stream-0 stub: stream H reads these")]
pub enum BisectCmd {
    /// Start a bisection between a bad and one or more good snapshots.
    Start {
        /// A snapshot that has the problem.
        #[arg(long, value_name = "REV")]
        bad: String,
        /// A snapshot that does not have the problem (repeatable).
        #[arg(long, value_name = "REV", required = true)]
        good: Vec<String>,
    },
    /// Mark the current candidate (or REV) good.
    Good {
        /// Snapshot to mark (default: the current candidate).
        rev: Option<String>,
        /// Move on even if the candidate's change holds edits (they stay in
        /// that change).
        #[arg(long)]
        discard: bool,
    },
    /// Mark the current candidate (or REV) bad.
    Bad {
        /// Snapshot to mark (default: the current candidate).
        rev: Option<String>,
        /// Move on even if the candidate's change holds edits (they stay in
        /// that change).
        #[arg(long)]
        discard: bool,
    },
    /// Skip the current candidate (or REV): it cannot be tested.
    Skip {
        /// Snapshot to skip (default: the current candidate).
        rev: Option<String>,
        /// Move on even if the candidate's change holds edits (they stay in
        /// that change).
        #[arg(long)]
        discard: bool,
    },
    /// Bisect automatically: run CMD on each candidate in a throwaway
    /// sandbox (exit 0 good, 125 skip, 1-127 bad, anything else aborts).
    Run {
        /// Copy local-only (isolated) files such as .env into each sandbox.
        #[arg(long)]
        with_isolated: bool,
        /// Trust verdicts on candidates you cannot fully read (by default
        /// they are skipped).
        #[arg(long)]
        trust_partial: bool,
        /// Command and arguments (put them after `--`).
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// End the bisection and return to where it started.
    Reset,
    /// Show the bisection's steps so far.
    Log,
}

/// `vl bisect`.
pub fn bisect(_ctx: &mut Ctx, _cmd: &BisectCmd) -> Result<ExitCode> {
    bail!("`vl bisect` is not implemented yet")
}

// ---- vl log filters -----------------------------------------------------------

/// The filters `vl log` gains:
/// `[-r REVSET] [--author PAT] [--signed-by MEMBER] [-S STRING | -G REGEX] [-i] [--pickaxe-all]
/// [--show-skipped] [--max-changes N] [--follow] [--] [PATH…]`.
#[derive(Args, Debug, Clone, Default)]
pub struct LogFilterArgs {
    /// Only snapshots that change these files or directories (not
    /// implemented yet).
    pub paths: Vec<String>,
    /// Snapshots to show: `A..B` or `::B` (not implemented yet).
    #[arg(short, long = "rev", value_name = "REVSET")]
    pub revset: Option<String>,
    /// Only snapshots whose author matches this regular expression. The
    /// author is a claim anyone can write; see --signed-by (not implemented
    /// yet).
    #[arg(long, value_name = "PAT")]
    pub author: Option<String>,
    /// Only snapshots with a verified signature by MEMBER (not implemented
    /// yet).
    #[arg(long, value_name = "MEMBER")]
    pub signed_by: Option<String>,
    /// Only snapshots that change the number of occurrences of STRING (not
    /// implemented yet).
    #[arg(short = 'S', value_name = "STRING", conflicts_with = "pickaxe_regex")]
    pub pickaxe_string: Option<String>,
    /// Only snapshots that add or remove a line matching REGEX (not
    /// implemented yet).
    #[arg(short = 'G', value_name = "REGEX")]
    pub pickaxe_regex: Option<String>,
    /// Match -G case-insensitively (not implemented yet).
    #[arg(short, long)]
    pub ignore_case: bool,
    /// With -S or -G, show every changed file of a matching snapshot (not
    /// implemented yet).
    #[arg(long)]
    pub pickaxe_all: bool,
    /// List snapshots that could not be searched (sealed for you) instead of
    /// leaving them out (not implemented yet).
    #[arg(long)]
    pub show_skipped: bool,
    /// Stop searching after this many snapshots (not implemented yet).
    #[arg(long, value_name = "N")]
    pub max_changes: Option<usize>,
    /// Follow a single file across renames (not implemented yet).
    #[arg(long)]
    pub follow: bool,
}

impl LogFilterArgs {
    /// The filters given on the command line, as their flags.
    fn given(&self) -> Vec<&'static str> {
        let LogFilterArgs {
            paths,
            revset,
            author,
            signed_by,
            pickaxe_string,
            pickaxe_regex,
            ignore_case,
            pickaxe_all,
            show_skipped,
            max_changes,
            follow,
        } = self;
        [
            (!paths.is_empty(), "PATH"),
            (revset.is_some(), "-r"),
            (author.is_some(), "--author"),
            (signed_by.is_some(), "--signed-by"),
            (pickaxe_string.is_some(), "-S"),
            (pickaxe_regex.is_some(), "-G"),
            (*ignore_case, "-i"),
            (*pickaxe_all, "--pickaxe-all"),
            (*show_skipped, "--show-skipped"),
            (max_changes.is_some(), "--max-changes"),
            (*follow, "--follow"),
        ]
        .into_iter()
        .filter_map(|(set, flag)| set.then_some(flag))
        .collect()
    }
}

/// `vl log` without filters runs as before; any filter is refused until
/// stream H implements them.
pub fn require_no_log_filter(f: &LogFilterArgs) -> Result<()> {
    let given = f.given();
    if !given.is_empty() {
        bail!("`vl log {}` is not implemented yet", given.join(" "));
    }
    Ok(())
}

// ---- rename detection flags (vl diff, vl show) --------------------------------

/// Rename and copy detection in `vl diff` and `vl show`:
/// `[--no-renames | -M[N] | -C]`.
#[derive(Args, Debug, Clone, Default)]
pub struct RenameArgs {
    /// Do not detect renames (not implemented yet).
    #[arg(long, conflicts_with_all = ["find_renames", "find_copies"])]
    pub no_renames: bool,
    /// Detect renames; `-M=N` (or `--find-renames=N`) sets the similarity
    /// threshold in percent, default 50 (not implemented yet).
    #[arg(
        short = 'M',
        long,
        value_name = "N",
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "50",
        value_parser = clap::value_parser!(u8).range(0..=100)
    )]
    pub find_renames: Option<u8>,
    /// Detect copies as well as renames (not implemented yet).
    #[arg(short = 'C', long)]
    pub find_copies: bool,
}

/// `vl diff` / `vl show` without rename flags run as before; any is refused
/// until stream H implements them.
pub fn require_no_rename_flags(r: &RenameArgs) -> Result<()> {
    let RenameArgs { no_renames, find_renames, find_copies } = r;
    let given: Vec<&str> = [(*no_renames, "--no-renames"), (find_renames.is_some(), "-M"), (*find_copies, "-C")]
        .into_iter()
        .filter_map(|(set, flag)| set.then_some(flag))
        .collect();
    if !given.is_empty() {
        bail!("rename detection ({}) is not implemented yet", given.join(" "));
    }
    Ok(())
}
