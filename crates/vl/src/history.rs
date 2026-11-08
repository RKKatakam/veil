//! History read tools: `vl blame`, `vl grep`, `vl bisect`, the `vl log`
//! filters and the rename flags of `vl diff` / `vl show`.
//!
//! Stream H of the Git-parity round (features 1, 2 and 3:
//! `docs/design/git-parity/1-blame-bisect-duplicate.md`, `2-renames.md`,
//! `3-history-search-grep.md`). The engines are in `veil_core::{blame,
//! bisect, grep, search, rename}`; every one reads history as this reader
//! may see it (`veil_core::blame::readable_version`), and none reads the
//! working copy.

use std::{
    io::{Read as _, Write as _},
    path::PathBuf,
    process::{Command, ExitCode},
};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use veil_core::{
    bisect::{self, Step, Verdict},
    blame::Reader,
    grep::GrepOptions,
    rename::RenameOptions,
    revset,
    search::{compile_regex, LogFilter, Pickaxe},
    vfs::{SandboxFs, StorageBackend},
    ObjectId, VPath,
};

use crate::{
    api::{self, Renames},
    cli::JsonOut,
    ctx::Ctx,
    render::{dim, one_line, safe, warn},
};

// ---- vl blame -----------------------------------------------------------------

/// `vl blame PATH [-r REV] [-L START,END] [--follow] [--max-changes N] [--public] [--json]`.
#[derive(Args, Debug)]
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
    /// Annotate as a public mirror sees the history: no secret files, and
    /// nothing an unreleased embargo withholds (refused for such a revision).
    #[arg(long)]
    pub public: bool,
    #[command(flatten)]
    pub out: JsonOut,
}

/// `START,END` of `-L`.
fn line_range(s: &str) -> Result<(usize, usize)> {
    let (a, b) = s.split_once(',').ok_or_else(|| anyhow!("-L {}: give START,END (for example -L 10,20)", safe(s)))?;
    let parse = |x: &str| x.trim().parse::<usize>().map_err(|_| anyhow!("-L {}: START and END are line numbers", safe(s)));
    let (a, b) = (parse(a)?, parse(b)?);
    if a == 0 || b < a {
        bail!("-L {}: give START,END with 1 <= START <= END", safe(s));
    }
    Ok((a, b))
}

/// The `veil.blame/2` document of `a` (`vl blame`, and `vl serve`'s
/// `blame` method).
pub fn blame_doc(ctx: &Ctx, a: &BlameArgs) -> Result<api::BlameDoc> {
    let lines = a.lines.as_deref().map(line_range).transpose()?;
    if a.max_changes == 0 {
        bail!("--max-changes must be at least 1");
    }
    api::blame(ctx, &api::BlameRequest { path: &a.path, rev: &a.rev, lines, follow: a.follow, max_changes: a.max_changes, public: a.public })
}

/// `vl blame`.
pub fn blame(ctx: &mut Ctx, a: &BlameArgs) -> Result<ExitCode> {
    let doc = blame_doc(ctx, a)?;
    match a.out.json {
        true => api::emit_json(&doc)?,
        false => api::text::blame(&doc),
    }
    Ok(ExitCode::SUCCESS)
}

// ---- vl grep ------------------------------------------------------------------

/// `vl grep PATTERN [-r REV] [-i] [-F] [-w] [-n] [-l] [-c] [--max-count N] [-a] [--json] [--] [PATH…]`.
#[derive(Args, Debug)]
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

/// The `veil.grep/2` document of `a` (`vl grep`, and `vl serve`'s `grep`
/// method).
pub fn grep_doc(ctx: &Ctx, a: &GrepArgs) -> Result<api::GrepDoc> {
    let opts = GrepOptions {
        ignore_case: a.ignore_case,
        fixed: a.fixed_strings,
        word: a.word_regexp,
        max_count: a.max_count,
        text: a.text,
        paths: Vec::new(),
        reader: Reader::Me,
    };
    api::grep(ctx, api::GrepRequest { pattern: &a.pattern, rev: &a.rev, paths: &a.paths, opts })
}

/// `vl grep`: exit 0 when something matched, 1 when nothing did.
pub fn grep(ctx: &mut Ctx, a: &GrepArgs) -> Result<ExitCode> {
    let doc = grep_doc(ctx, a)?;
    match a.out.json {
        true => api::emit_json(&doc)?,
        false => api::text::grep(
            &doc,
            api::text::GrepStyle { line_number: a.line_number, files_with_matches: a.files_with_matches, count: a.count },
        ),
    }
    Ok(if doc.files.is_empty() { ExitCode::from(1) } else { ExitCode::SUCCESS })
}

// ---- vl log filters -----------------------------------------------------------

/// The filters `vl log` gains:
/// `[-r REVSET] [--author PAT] [--signed-by MEMBER] [--agent PATTERN] [-S STRING | -G REGEX] [-i] [--pickaxe-all]
/// [--show-skipped] [--max-changes N] [--follow] [--] [PATH…]`.
#[derive(Args, Debug, Clone, Default)]
pub struct LogFilterArgs {
    /// Only snapshots that change these files or directories.
    pub paths: Vec<String>,
    /// Snapshots to show: `X`, `A..B`, `::B`, `..B` or `A..`.
    #[arg(short, long = "rev", value_name = "REVSET")]
    pub revset: Option<String>,
    /// Only snapshots whose author matches this regular expression. The
    /// author is a claim anyone who can push writes; --signed-by is the
    /// authenticated filter.
    #[arg(long, value_name = "PAT")]
    pub author: Option<String>,
    /// Only snapshots with a good signature by MEMBER (a member name or
    /// member id, as verified by your key rings).
    #[arg(long, value_name = "MEMBER")]
    pub signed_by: Option<String>,
    /// Only snapshots made by an agent whose name matches PATTERN (the name
    /// exactly, or a glob such as `claude-*`); the same as `-r 'agent(PATTERN)'`.
    #[arg(long, value_name = "PATTERN")]
    pub agent: Option<String>,
    /// Only snapshots that change the number of occurrences of STRING in a
    /// file you can read.
    #[arg(short = 'S', value_name = "STRING", conflicts_with = "pickaxe_regex")]
    pub pickaxe_string: Option<String>,
    /// Only snapshots that add or remove a line matching REGEX in a file
    /// you can read.
    #[arg(short = 'G', value_name = "REGEX")]
    pub pickaxe_regex: Option<String>,
    /// Match -S, -G and --author case-insensitively.
    #[arg(short, long)]
    pub ignore_case: bool,
    /// With -S or -G, list every changed file of a matching snapshot.
    #[arg(long)]
    pub pickaxe_all: bool,
    /// List snapshots that could not be searched (sealed for you) instead of
    /// leaving them out.
    #[arg(long)]
    pub show_skipped: bool,
    /// Stop searching after this many snapshots (default with -S or -G:
    /// 100000).
    #[arg(long, value_name = "N")]
    pub max_changes: Option<usize>,
    /// Follow a single file across renames.
    #[arg(long)]
    pub follow: bool,
}

/// Default `--max-changes` of a pickaxe search.
const PICKAXE_MAX_CHANGES: usize = 100_000;

impl LogFilterArgs {
    /// The query these flags ask for.
    pub fn query(&self, ctx: &Ctx, limit: Option<usize>) -> Result<api::LogQuery> {
        let ids = self.revset.as_deref().map(|r| revset::resolve_set(&ctx.repo, r, &ctx.ws)).transpose()?;
        let paths: Vec<VPath> = self.paths.iter().map(|p| ctx.repo_path(p)).collect::<Result<_>>()?;
        if self.follow && paths.len() != 1 {
            bail!("--follow follows exactly one file: give one PATH");
        }
        let pickaxe = match (&self.pickaxe_string, &self.pickaxe_regex) {
            (Some(s), _) => Some(Pickaxe::string(s, self.ignore_case)?),
            (_, Some(r)) => Some(Pickaxe::regex(r, self.ignore_case)?),
            _ => None,
        };
        if self.pickaxe_all && pickaxe.is_none() {
            bail!("--pickaxe-all goes with -S or -G");
        }
        if self.max_changes == Some(0) {
            bail!("--max-changes must be at least 1");
        }
        let author = self.author.as_deref().map(|a| compile_regex(a, self.ignore_case)).transpose()?;
        let max_changes = self.max_changes.or(pickaxe.is_some().then_some(PICKAXE_MAX_CHANGES));
        let agent = self.agent.as_deref().map(revset::agent_matcher).transpose()?;
        let filter = LogFilter {
            paths,
            author,
            agent,
            signed_by: self.signed_by.clone(),
            pickaxe,
            pickaxe_all: self.pickaxe_all,
            follow: self.follow,
            reader: Reader::Me,
            renames: RenameOptions::default(),
        };
        Ok(api::LogQuery { limit, ids, filter: Some(filter), show_skipped: self.show_skipped, max_changes })
    }
}

/// `vl log`, with or without filters.
pub fn log(ctx: &Ctx, limit: Option<usize>, f: &LogFilterArgs, json: bool) -> Result<()> {
    let q = f.query(ctx, limit)?;
    match json {
        true => api::emit_json(&api::log_with(&ctx.repo, &ctx.ws, q)?),
        false => api::text::log(api::log_entries_with(&ctx.repo, &ctx.ws, q)?),
    }
}

// ---- rename detection flags (vl diff, vl show) --------------------------------

/// Rename and copy detection in `vl diff` and `vl show`:
/// `[--no-renames | -M[=N] | -C]`. Detection is on by default.
#[derive(Args, Debug, Clone, Default)]
pub struct RenameArgs {
    /// Do not detect renames.
    #[arg(long, conflicts_with_all = ["find_renames", "find_copies"])]
    pub no_renames: bool,
    /// Detect renames; `-M=N` (or `--find-renames=N`) sets the similarity
    /// threshold in percent, default 50.
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
    /// Detect copies as well as renames.
    #[arg(short = 'C', long)]
    pub find_copies: bool,
}

impl RenameArgs {
    pub fn renames(&self) -> Renames {
        if self.no_renames {
            return Renames::off();
        }
        let mut r = Renames::default();
        if let Some(n) = self.find_renames {
            r.opts.threshold = n.max(1);
        }
        r.opts.copies = self.find_copies;
        r
    }
}

/// `vl diff`.
pub fn diff(ctx: &Ctx, rev: Option<&str>, from: Option<&str>, to: Option<&str>, stat: bool, r: &RenameArgs, json: bool) -> Result<()> {
    let t = api::diff_trees_for(ctx, rev, from, to)?;
    let renames = r.renames();
    match json {
        true => api::emit_json(&api::diff_with(&ctx.repo, &t, stat, &renames)?),
        false => api::text::diff(&ctx.repo, &t.from, &t.to, stat, &renames),
    }
}

/// `vl show`.
pub fn show(ctx: &Ctx, rev: &str, stat: bool, r: &RenameArgs, json: bool) -> Result<()> {
    let renames = r.renames();
    match json {
        true => api::emit_json(&api::show_with(ctx, rev, stat, &renames)?),
        false => api::text::show(&ctx.repo, &api::show_header(ctx, rev, stat)?, &renames),
    }
}

// ---- vl bisect ----------------------------------------------------------------

/// `vl bisect start|good|bad|skip|run|reset|log`.
#[derive(Subcommand, Debug)]
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
    /// The working copy is never touched, and nothing is recorded.
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

/// Format of `.veil/local/bisect.json`.
const STATE_VERSION: u32 = 1;
/// Larger state files are damaged (a bisection has a few hundred steps).
const MAX_STATE: u64 = 1 << 20;

/// `.veil/local/bisect.json`: device-local, read by `vl bisect` only.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
struct State {
    version: u32,
    workspace: String,
    /// The working copy when the bisection started, and its parents (if
    /// it was empty and abandoned on the way, `reset` starts a new change
    /// on them instead).
    started_from: String,
    started_parents: Vec<String>,
    bad: String,
    good: Vec<String>,
    #[serde(default)]
    skip: Vec<String>,
    /// The candidate being tested by hand, and the change id of the
    /// working-copy change made on it.
    #[serde(default)]
    current: Option<String>,
    #[serde(default)]
    step_change: Option<String>,
    #[serde(default)]
    found: Option<String>,
    #[serde(default)]
    log: Vec<LogLine>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
struct LogLine {
    /// `start-bad`, `start-good`, `good`, `bad`, `skip`, `found`.
    action: String,
    snapshot: String,
    /// `run`: the command's exit code.
    #[serde(default)]
    code: Option<i32>,
}

fn state_path(ctx: &Ctx) -> PathBuf {
    veil_core::repo::state_dir(&ctx.root).join("local").join("bisect.json")
}

const RESET_HINT: &str = "run `vl bisect reset` to end it";

fn damaged(why: &str) -> anyhow::Error {
    anyhow!("the bisection state (.veil/local/bisect.json) {why}; {RESET_HINT}")
}

/// The bisection in progress, if any. Anything unexpected in the file
/// (another version, bad JSON, not a regular file, too large, unknown
/// snapshots) is refused with the reset hint; nothing else reads it.
fn load(ctx: &Ctx) -> Result<Option<(State, Ids)>> {
    let path = state_path(ctx);
    let meta = match std::fs::symlink_metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(damaged(&format!("cannot be read ({e})"))),
    };
    if !meta.is_file() {
        return Err(damaged("is not a regular file"));
    }
    let mut raw = Vec::new();
    std::fs::File::open(&path)
        .and_then(|f| f.take(MAX_STATE + 1).read_to_end(&mut raw))
        .map_err(|e| damaged(&format!("cannot be read ({e})")))?;
    if raw.len() as u64 > MAX_STATE {
        return Err(damaged("is too large"));
    }
    let s: State = serde_json::from_slice(&raw).map_err(|_| damaged("is damaged or from another version of vl"))?;
    if s.version != STATE_VERSION {
        return Err(damaged(&format!("has version {}, this vl reads version {STATE_VERSION}", s.version)));
    }
    if s.workspace != ctx.ws {
        bail!(
            "the bisection runs in workspace {} (this is {}): switch to it, or {RESET_HINT} there",
            safe(&s.workspace),
            safe(&ctx.ws)
        );
    }
    let ids = Ids::of(ctx, &s)?;
    Ok(Some((s, ids)))
}

/// The snapshots a state names, checked to still exist here.
struct Ids {
    bad: ObjectId,
    good: Vec<ObjectId>,
    skip: Vec<ObjectId>,
}

impl Ids {
    fn of(ctx: &Ctx, s: &State) -> Result<Ids> {
        let one = |h: &str| -> Result<ObjectId> {
            let id = ObjectId::from_hex(h).map_err(|_| damaged("names something that is not a snapshot id"))?;
            match ctx.repo.exact().snapshot(&id) {
                Ok(Some(_)) => Ok(id),
                _ => Err(anyhow!(
                    "snapshot {} of the bisection is no longer in this repository (abandoned and collected by `vl gc`?); {RESET_HINT}",
                    id.short()
                )),
            }
        };
        let many = |v: &[String]| v.iter().map(|h| one(h)).collect::<Result<Vec<_>>>();
        Ok(Ids { bad: one(&s.bad)?, good: many(&s.good)?, skip: many(&s.skip)? })
    }
}

/// Write the state durably (temp file, fsync, rename), readable by the
/// user only.
fn save(ctx: &Ctx, s: &State) -> Result<()> {
    let path = state_path(ctx);
    let dir = path.parent().expect("a parent");
    std::fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(".bisect.json.{}.tmp", std::process::id()));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp).with_context(|| format!("writing {}", tmp.display()))?;
    f.write_all(serde_json::to_string_pretty(s)?.as_bytes())?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, &path).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

fn note(s: &mut State, action: &str, id: &ObjectId, code: Option<i32>) {
    s.log.push(LogLine { action: action.to_string(), snapshot: id.hex(), code });
}

/// Files of `tree` this reader cannot read (sealed secrets of another
/// scope): a verdict there may be misleading.
fn unreadable_files(ctx: &Ctx, tree: &ObjectId) -> Result<usize> {
    let store = ctx.repo.store();
    let mut n = 0;
    let files = veil_core::tree::walk_files(store, tree)?;
    // Readability is read by id: in a thin clone, each asked for at its
    // own path first (BUG-1506).
    veil_core::tree::prefetch_files(store, tree, files.iter().filter(|(_, e)| e.kind == veil_core::EntryKind::File).map(|(p, e)| (p, e)))?;
    for (_, e) in files {
        if e.kind == veil_core::EntryKind::File && !store.entry_readable(&e) {
            n += 1;
        }
    }
    Ok(n)
}

/// Act on `step`: check out the next candidate by hand (unless `run`),
/// or report the result. Returns the candidate to test.
fn take_step(ctx: &mut Ctx, s: &mut State, step: Step, by_hand: bool) -> Result<Option<ObjectId>> {
    match step {
        Step::Test { candidate, remaining, steps } => {
            println!(
                "Bisecting: {} snapshot(s) left to test after this one (about {steps} step(s))",
                remaining.saturating_sub(1) / 2
            );
            println!("Testing {}", one_line(&ctx.repo, &candidate));
            let tree = ctx.repo.snapshot(&candidate)?.tree;
            let hidden = unreadable_files(ctx, &tree)?;
            if hidden > 0 {
                warn(&format!(
                    "{hidden} file(s) of this snapshot are secrets sealed for others (left out): \
                     a verdict here may be misleading{}",
                    if by_hand { "; `vl bisect skip` if you cannot tell" } else { "" }
                ));
            }
            s.current = Some(candidate.hex());
            if by_hand {
                let ws = ctx.ws.clone();
                let wc = ctx.repo.new_change(&ws, vec![candidate], "")?;
                s.step_change = Some(ctx.repo.snapshot(&wc)?.change_id.display());
            }
            Ok(Some(candidate))
        }
        Step::Found(id) => {
            println!("The first bad snapshot is {}", one_line(&ctx.repo, &id));
            note(s, "found", &id, None);
            s.found = Some(id.hex());
            s.current = None;
            Ok(None)
        }
        Step::Undecided { bad, skipped } => {
            println!("Only skipped snapshots are left: the first bad snapshot is one of");
            for id in std::iter::once(&bad).chain(&skipped) {
                println!("  {}", one_line(&ctx.repo, id));
            }
            s.current = None;
            Ok(None)
        }
    }
}

fn mark(ids: &mut Ids, s: &mut State, verdict: Verdict, id: ObjectId, code: Option<i32>) {
    match verdict {
        Verdict::Good => {
            ids.good.push(id);
            s.good.push(id.hex());
            note(s, "good", &id, code);
        }
        Verdict::Bad => {
            ids.bad = id;
            s.bad = id.hex();
            note(s, "bad", &id, code);
        }
        Verdict::Skip => {
            ids.skip.push(id);
            s.skip.push(id.hex());
            note(s, "skip", &id, code);
        }
        Verdict::Abort => {}
    }
}

/// `vl bisect`.
pub fn bisect(ctx: &mut Ctx, cmd: &BisectCmd) -> Result<ExitCode> {
    match cmd {
        BisectCmd::Start { bad, good } => {
            match load(ctx) {
                Ok(None) => {}
                Ok(Some(_)) => bail!("a bisection is already in progress (`vl bisect log` shows it); {RESET_HINT}"),
                Err(e) => return Err(e),
            }
            let bad = ctx.rev(bad)?;
            let good: Vec<ObjectId> = good.iter().map(|g| ctx.rev(g)).collect::<Result<_>>()?;
            let wc = ctx.wc()?;
            let mut s = State {
                version: STATE_VERSION,
                workspace: ctx.ws.clone(),
                started_from: wc.hex(),
                started_parents: ctx.repo.snapshot(&wc)?.parents.iter().map(|p| p.hex()).collect(),
                bad: bad.hex(),
                good: good.iter().map(|g| g.hex()).collect(),
                skip: Vec::new(),
                current: None,
                step_change: None,
                found: None,
                log: Vec::new(),
            };
            note(&mut s, "start-bad", &bad, None);
            for g in &good {
                note(&mut s, "start-good", g, None);
            }
            let step = bisect::next(&ctx.repo, &bad, &good, &[])?;
            take_step(ctx, &mut s, step, true)?;
            save(ctx, &s)?;
            Ok(ExitCode::SUCCESS)
        }
        BisectCmd::Good { rev, discard } | BisectCmd::Bad { rev, discard } | BisectCmd::Skip { rev, discard } => {
            let verdict = match cmd {
                BisectCmd::Good { .. } => Verdict::Good,
                BisectCmd::Bad { .. } => Verdict::Bad,
                _ => Verdict::Skip,
            };
            let (mut s, mut ids) = load(ctx)?.ok_or_else(|| anyhow!("no bisection in progress (`vl bisect start --bad REV --good REV`)"))?;
            let id = match rev {
                Some(r) => ctx.rev(r)?,
                None => match &s.current {
                    Some(h) => ObjectId::from_hex(h).map_err(|_| damaged("names something that is not a snapshot id"))?,
                    None => bail!("no candidate is being tested: give the snapshot to mark"),
                },
            };
            // Edits made on the candidate stay in its change: refuse to
            // move off it unless asked (they are never lost either way).
            let wc = ctx.wc()?;
            let here = ctx.repo.snapshot(&wc)?;
            if !discard && s.step_change.as_deref() == Some(here.change_id.display().as_str()) && !ctx.repo.is_empty_change(&wc)? {
                bail!(
                    "the working-copy change {} holds edits made while testing: record them elsewhere first (`vl new`, `vl squash`), \
                     or pass --discard to move on and leave them in that change",
                    here.change_id.short()
                );
            }
            mark(&mut ids, &mut s, verdict, id, None);
            let step = bisect::next(&ctx.repo, &ids.bad, &ids.good, &ids.skip)?;
            s.step_change = None;
            take_step(ctx, &mut s, step, true)?;
            save(ctx, &s)?;
            Ok(ExitCode::SUCCESS)
        }
        BisectCmd::Run { with_isolated, trust_partial, command } => {
            let (mut s, mut ids) = load(ctx)?.ok_or_else(|| anyhow!("no bisection in progress (`vl bisect start --bad REV --good REV`)"))?;
            loop {
                let step = bisect::next(&ctx.repo, &ids.bad, &ids.good, &ids.skip)?;
                let Some(candidate) = take_step(ctx, &mut s, step, false)? else {
                    save(ctx, &s)?;
                    return Ok(ExitCode::SUCCESS);
                };
                let (code, partial) = run_on(ctx, &candidate, *with_isolated, command)?;
                let mut verdict = bisect::verdict(code);
                if verdict == Verdict::Abort {
                    s.current = None;
                    save(ctx, &s)?;
                    bail!(
                        "bisect run stopped: `{}` exited with {code} on {} (0 good, 125 skip, 1-127 bad; anything else aborts)",
                        safe(&command.join(" ")),
                        candidate.short()
                    );
                }
                if partial && !trust_partial && verdict != Verdict::Skip {
                    eprintln!("{}", dim("  skipped: you cannot read every file of this snapshot (--trust-partial keeps the verdict)"));
                    verdict = Verdict::Skip;
                }
                let word = match verdict {
                    Verdict::Good => "good",
                    Verdict::Bad => "bad",
                    _ => "skip",
                };
                println!("  {word} (exit {code})");
                mark(&mut ids, &mut s, verdict, candidate, Some(code));
                save(ctx, &s)?;
            }
        }
        BisectCmd::Reset => {
            let state = match load(ctx) {
                Ok(s) => s,
                Err(e) => {
                    // A damaged state: remove it, leave the working copy.
                    let path = state_path(ctx);
                    if std::fs::symlink_metadata(&path).is_ok() {
                        std::fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
                        println!("Removed the bisection state ({}); the working copy stays where it is", e.root_cause());
                        return Ok(ExitCode::SUCCESS);
                    }
                    return Err(e);
                }
            };
            let Some((s, _)) = state else {
                println!("No bisection in progress");
                return Ok(ExitCode::SUCCESS);
            };
            let ws = ctx.ws.clone();
            let from = ObjectId::from_hex(&s.started_from).ok();
            // Is the snapshot bisect started from still visible? Asked of the
            // history above it only (exactly, in a thin clone).
            let visible = |f: &ObjectId| -> Result<bool> {
                let want: std::collections::HashSet<ObjectId> = [*f].into_iter().collect();
                Ok(ctx.repo.exact().visible_among(&want)?.contains(f))
            };
            let from = match from {
                Some(f) if visible(&f)? => Some(f),
                _ => None,
            };
            match from {
                Some(f) => ctx.repo.edit(&ws, f)?,
                None => {
                    let parents: Vec<ObjectId> = s
                        .started_parents
                        .iter()
                        .filter_map(|h| ObjectId::from_hex(h).ok())
                        .filter(|p| ctx.repo.exact().snapshot(p).ok().flatten().is_some())
                        .collect();
                    if !parents.is_empty() {
                        ctx.repo.new_change(&ws, parents, "")?;
                    }
                }
            }
            std::fs::remove_file(state_path(ctx))?;
            println!("Bisection ended; working copy now at {}", one_line(&ctx.repo, &ctx.wc()?));
            Ok(ExitCode::SUCCESS)
        }
        BisectCmd::Log => {
            let (s, _) = load(ctx)?.ok_or_else(|| anyhow!("no bisection in progress"))?;
            for l in &s.log {
                let id = ObjectId::from_hex(&l.snapshot).map_err(|_| damaged("names something that is not a snapshot id"))?;
                let code = l.code.map(|c| format!(" (exit {c})")).unwrap_or_default();
                println!("{:<10} {}{code}", safe(&l.action), one_line(&ctx.repo, &id));
            }
            if let Some(c) = &s.current {
                if let Ok(id) = ObjectId::from_hex(c) {
                    println!("{:<10} {}", "testing", one_line(&ctx.repo, &id));
                }
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

/// Run `command` on `candidate` in a throwaway sandbox (`vl ws exec
/// --ephemeral`'s directory: `0700` under `$TMPDIR`, removed afterwards,
/// a reaper removes it if `vl` dies), recording nothing. Returns the exit
/// code (128 + the signal for a killed command) and whether this reader
/// could not materialise every file.
fn run_on(ctx: &Ctx, candidate: &ObjectId, with_isolated: bool, command: &[String]) -> Result<(i32, bool)> {
    let tree = ctx.repo.snapshot(candidate)?.tree;
    let sb = crate::sandbox::Sandbox::create("bisect")?;
    let dir = sb.path().to_path_buf();
    let fs = SandboxFs::new(&dir, None, false);
    let report = ctx.repo.checkout_tree(&fs, None, &tree)?;
    let partial = !report.redacted.is_empty() || !report.from_fallback.is_empty() || !report.failed.is_empty();
    if with_isolated {
        // The vault copies of local-only files (`ws exec --with-isolated`).
        for (p, hexdata) in ctx.repo.vault_load()?.files {
            fs.write(&VPath::new(&p)?, &hex::decode(hexdata)?)?;
        }
    }
    sb.make_private()?;
    eprintln!("{} {} in {}", dim("running"), safe(&command.join(" ")), dir.display());
    let status = Command::new(&command[0])
        .args(&command[1..])
        .current_dir(&dir)
        // Git run inside must not find the repository above the sandbox.
        .env("GIT_CEILING_DIRECTORIES", &dir)
        .status()
        .with_context(|| format!("failed to run {}", safe(&command[0])));
    drop(sb);
    let status = status?;
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            return Ok((128 + sig, partial));
        }
    }
    Ok((status.code().unwrap_or(1), partial))
}
