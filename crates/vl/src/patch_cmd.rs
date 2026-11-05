//! Patches: `vl format-patch` (export, Git's mbox format) and `vl am`
//! (import, as new changes).
//!
//! Feature 4 of the Git-parity round (`docs/design/git-parity/4-patches.md`);
//! the engine is `veil_core::patch`. This module reads and writes the
//! files, and holds the CLI's own guards: `--audience me` is never the
//! default, cannot be abbreviated, and needs `--yes` to go to a pipe or a
//! file; `-o DIR` writes into a temp directory inside `DIR` and renames
//! the patches into place only once every one of them is ready.

use std::{
    collections::BTreeSet,
    io::{IsTerminal, Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::{bail, Context, Result};
use clap::{Args, ValueEnum};
use veil_core::{
    git::{default_git_dir, GitBridge},
    patch::{self, AmOptions, ExportOptions, Limits},
    ObjectId,
};

use crate::{
    ctx::Ctx,
    render::{self, safe, warn, warn_untrusted},
};

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
/// [--yes] [--cover-letter] [--binary] [-M[=N]] [-C[=N]]`.
#[derive(Args, Debug)]
pub struct FormatPatchArgs {
    /// Snapshots to export: `A..B` (ancestors of B that are not ancestors
    /// of A), `::B` (every ancestor of B) or a single snapshot.
    pub revset: String,
    /// Write one patch file per snapshot into DIR (default: the current
    /// directory).
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
    /// Write binary files as `GIT binary patch` data, which `git am` and
    /// `vl am` apply (without it: `Binary files … differ`). Sealed content
    /// is never written this way.
    #[arg(long)]
    pub binary: bool,
    /// Detect renames, on the exported view only: `-M` or `-M=N` (N: the
    /// similarity in percent a pair needs, 50 by default).
    #[arg(short = 'M', long, value_name = "N", num_args = 0..=1, require_equals = true,
          default_missing_value = "50", value_parser = clap::value_parser!(u8).range(0..=100))]
    pub find_renames: Option<u8>,
    /// Detect copies (and renames): `-C` or `-C=N`. A copy's source is a
    /// file changed in the same snapshot.
    #[arg(short = 'C', long, value_name = "N", num_args = 0..=1, require_equals = true,
          default_missing_value = "50", value_parser = clap::value_parser!(u8).range(0..=100))]
    pub find_copies: Option<u8>,
}

/// `vl am INPUT [-d DEST] [--3way] [--keep-author | --author-as-me] [--signoff]`.
#[derive(Args, Debug)]
pub struct AmArgs {
    /// An mbox or patch file, a directory of them, or `-` for standard input.
    #[arg(value_name = "INPUT")]
    pub input: String,
    /// Apply the series on top of this snapshot.
    #[arg(short, long, value_name = "DEST", default_value = "@-")]
    pub destination: String,
    /// When a hunk does not apply, merge three ways with the version the
    /// patch was made from (its `index` line), if this repository's history
    /// of the file holds it. A conflict is recorded as a conflict of the new
    /// change, for `vl resolve`.
    #[arg(short = '3', long = "3way")]
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

// ---- format-patch ----------------------------------------------------------

/// The snapshots `spec` names, parents before children (see
/// [`FormatPatchArgs::revset`]).
fn resolve_range(ctx: &Ctx, spec: &str) -> Result<Vec<ObjectId>> {
    let root = ctx.repo.root_id();
    let (exclude, tip) = if let Some(tip) = spec.strip_prefix("::") {
        (None, tip)
    } else if let Some((a, b)) = spec.split_once("..") {
        if a.is_empty() || b.is_empty() {
            bail!("'{spec}': a range needs both ends (`A..B`), or use `::B`");
        }
        (Some(ctx.rev(a)?), b)
    } else {
        let id = ctx.rev(spec)?;
        if id == root {
            bail!("the root snapshot has no patch");
        }
        return Ok(vec![id]);
    };
    let tip = ctx.rev(tip)?;
    let excluded = match exclude {
        Some(a) => ctx.repo.ancestors(&a)?,
        None => Default::default(),
    };
    let mut order = ctx.repo.topo_children_first([tip])?;
    order.retain(|id| *id != root && !excluded.contains(id));
    order.reverse();
    Ok(order)
}

/// `vl format-patch`.
pub fn format_patch(ctx: &mut Ctx, args: &FormatPatchArgs) -> Result<ExitCode> {
    let me = args.audience == Audience::Me;
    if !args.include_embargoed.is_empty() && !me {
        bail!("--include-embargoed needs --audience me (the public view never holds unreleased embargo content)");
    }
    if me && args.stdout && !std::io::stdout().is_terminal() && !args.yes {
        bail!(
            "--audience me writes cloaked content, and standard output is not a terminal: \
             add --yes to confirm (never mail such a patch to a public list)"
        );
    }
    let ids = resolve_range(ctx, &args.revset)?;
    if ids.is_empty() {
        bail!("'{}' names no snapshot", args.revset);
    }
    // The bridge creates its repository, but not the directory around it
    // (BUG-640).
    let git_dir = default_git_dir(&ctx.root);
    if let Some(parent) = git_dir.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    let mut bridge = GitBridge::open(&ctx.repo, &git_dir)?;
    let opts = ExportOptions {
        audience: if me { patch::Audience::Me } else { patch::Audience::Public },
        include_embargoed: args.include_embargoed.iter().cloned().collect::<BTreeSet<_>>(),
        cover_letter: args.cover_letter,
        find_renames: args.find_renames.is_some() || args.find_copies.is_some(),
        find_copies: args.find_copies.is_some(),
        rename_threshold: args.find_copies.or(args.find_renames),
        binary: args.binary,
        signature: format!("vl {}", env!("CARGO_PKG_VERSION")),
    };
    let export = patch::format_patches(&ctx.repo, &mut bridge, &ids, &opts)?;
    for w in &export.warnings {
        warn_untrusted(w);
    }
    // Changes are named by id only: a description may be sealed, and this
    // output is meant to leave the device.
    let change = |id: &ObjectId| -> Result<String> { Ok(ctx.repo.snapshot(id)?.change_id.short()) };
    for id in &export.skipped {
        eprintln!("skipped change {} (a merge has no patch)", change(id)?);
    }
    if export.patches.is_empty() {
        bail!("nothing to export: '{}' holds only merges", args.revset);
    }
    for (n, p) in export.patches.iter().enumerate() {
        if let (true, Some(id)) = (p.empty, p.snapshot) {
            warn(&format!("patch {n} (change {}) shows no file change in this view", change(&id)?));
        }
    }
    if me {
        let mut what: Vec<String> = export.scopes.iter().map(|s| format!("scope '{}'", safe(s))).collect();
        what.extend(export.embargoes.iter().map(|e| format!("unreleased embargo {}", safe(e))));
        if what.is_empty() {
            warn("--audience me: these patches hold no sealed content");
        } else {
            warn(&format!(
                "--audience me: these patches hold content of {} (each says so in its X-Veil-Audience header). \
                 Never send them to anyone outside those scopes",
                what.join(", ")
            ));
        }
    }
    if args.stdout {
        let mut out = std::io::stdout().lock();
        for p in &export.patches {
            out.write_all(&p.text)?;
        }
        out.flush()?;
        return Ok(ExitCode::SUCCESS);
    }
    let dir = match &args.output_directory {
        Some(d) => d.clone(),
        None => std::env::current_dir()?,
    };
    for path in write_patches(&dir, &export.patches)? {
        println!("{}", path.display());
    }
    Ok(ExitCode::SUCCESS)
}

/// Write `patches` into `dir`: first into a fresh private directory inside
/// it, then renamed into place, so an error leaves no partial series.
fn write_patches(dir: &Path, patches: &[patch::ExportedPatch]) -> Result<Vec<PathBuf>> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let tmp = dir.join(format!(".vl-format-patch.{}.{nanos:08x}", std::process::id()));
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
    let result = (|| -> Result<Vec<PathBuf>> {
        for p in patches {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(tmp.join(&p.file_name))
                .with_context(|| format!("writing {}", p.file_name))?;
            f.write_all(&p.text)?;
            f.sync_all()?;
        }
        let mut out = Vec::new();
        for p in patches {
            let to = dir.join(&p.file_name);
            // A rename replaces a symlink there, never what it points to.
            std::fs::rename(tmp.join(&p.file_name), &to).with_context(|| format!("writing {}", to.display()))?;
            out.push(to);
        }
        Ok(out)
    })();
    // Only files this command created are in `tmp`.
    for p in patches {
        let _ = std::fs::remove_file(tmp.join(&p.file_name));
    }
    let _ = std::fs::remove_dir(&tmp);
    result
}

// ---- am --------------------------------------------------------------------

/// Read at most `limit` bytes from `r`, refusing more.
fn read_capped(r: impl Read, limit: usize, what: &str) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    r.take(limit as u64 + 1).read_to_end(&mut data).with_context(|| format!("reading {what}"))?;
    if data.len() > limit {
        bail!("{what} is larger than {limit} bytes, the most a patch series may be");
    }
    Ok(data)
}

/// The input of `vl am`: a file, standard input, or every regular file of
/// a directory (by name, each an mbox), joined.
fn read_input(input: &str, limit: usize) -> Result<(Vec<u8>, String)> {
    if input == "-" {
        return Ok((read_capped(std::io::stdin().lock(), limit, "standard input")?, "standard input".into()));
    }
    let path = Path::new(input);
    let meta = std::fs::metadata(path).with_context(|| format!("reading {input}"))?;
    if !meta.is_dir() {
        let f = std::fs::File::open(path).with_context(|| format!("reading {input}"))?;
        return Ok((read_capped(f, limit, input)?, input.to_string()));
    }
    let mut names = Vec::new();
    for e in std::fs::read_dir(path).with_context(|| format!("reading {input}"))? {
        let e = e?;
        let name = e.file_name();
        let shown = name.to_string_lossy().into_owned();
        if shown.starts_with('.') {
            continue;
        }
        // Not followed: only the directory's own regular files.
        if e.file_type()?.is_file() {
            names.push((shown, e.path()));
        }
    }
    names.sort();
    if names.is_empty() {
        bail!("{input} holds no patch file");
    }
    let mut data = Vec::new();
    for (shown, p) in &names {
        let f = std::fs::File::open(p).with_context(|| format!("reading {}", p.display()))?;
        let part = read_capped(f, limit.saturating_sub(data.len()), &format!("{input} (all its files)"))?;
        if names.len() > 1 && !part.starts_with(b"From ") {
            bail!("{}: not a patch mail (each file of a directory must start with a 'From ' line)", safe(shown));
        }
        data.extend_from_slice(&part);
        if !data.ends_with(b"\n") {
            data.push(b'\n');
        }
    }
    Ok((data, input.to_string()))
}

/// `vl am`.
pub fn am(ctx: &mut Ctx, args: &AmArgs) -> Result<ExitCode> {
    let limits = Limits::default();
    // Read and parse everything before the repository is locked.
    let (data, name) = read_input(&args.input, limits.max_input)?;
    let series = patch::parse(data, &limits)?;
    let ws = ctx.ws.clone();
    let opts = AmOptions {
        author_as_me: args.author_as_me,
        signoff: args.signoff,
        limits,
        default_description: format!("Apply a patch from {name}"),
        three_way: args.three_way,
    };
    let report = patch::apply_series(&mut ctx.repo, &ws, &args.destination, &series, &opts)?;
    println!("Applied {} patch(es):", report.changes.len());
    for id in &report.changes {
        println!("  {}", render::one_line(&ctx.repo, id));
    }
    for n in &report.skipped {
        println!("  (message {n}, a cover letter, skipped)");
    }
    for n in &report.empty {
        warn(&format!("patch {n} changes no file: recorded as an empty change"));
    }
    for (n, p) in &report.merged {
        println!("  patch {n}: {} merged three ways with the version it was made from", safe(p.as_str()));
    }
    for (n, p, why) in &report.link_warnings {
        warn(&format!("patch {n}: symlink {} {}", safe(p.as_str()), safe(why)));
    }
    if !report.conflicts.is_empty() {
        for (n, p) in &report.conflicts {
            warn(&format!("patch {n}: {} has a conflict (the patch and this repository changed the same lines)", safe(p.as_str())));
        }
        eprintln!("The conflicts are recorded in the new changes: edit the files (or `vl resolve`) to resolve them.");
    }
    if report.rebased.is_some() {
        println!("The working copy was rebased onto the last of them.");
    } else if !report.changes.is_empty() {
        let last = report.changes.last().expect("a change");
        println!(
            "The working copy did not move (it is not a child of {}); `vl new {}` works on top of the series.",
            safe(&args.destination),
            ctx.repo.snapshot(last)?.change_id.short()
        );
    }
    render::print_policy_held_back(&report.policy_held_back, false, false);
    Ok(ExitCode::SUCCESS)
}
