//! History rewrites that copy changes: `vl duplicate` and its Git-style
//! alias `vl cherry-pick` (engine: `veil_core::duplicate`), and the report
//! of renames a merge, rebase or copy followed.
//!
//! Stream R of the Git-parity round (features 1 and 2:
//! `docs/design/git-parity/1-blame-bisect-duplicate.md`, `2-renames.md`).

use std::{collections::HashSet, process::ExitCode};

use anyhow::{bail, Result};
use clap::Args;
use serde::Serialize;
use veil_core::{
    duplicate::{DuplicateOptions, Duplicated},
    merge::{FollowedRename, RenameMerge},
    revset, ObjectId, Repo,
};

use crate::{
    api::{self, OpRef},
    cli::JsonOut,
    ctx::Ctx,
    render::{dim, one_line, safe, warn_untrusted, yellow},
};

/// JSON schema of `vl duplicate --json` and `vl cherry-pick --json`.
pub const DUPLICATE_SCHEMA: &str = "veil.duplicate/1";

/// The description of each duplicate.
#[derive(Args, Debug)]
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

impl DuplicateDescription {
    fn options(&self) -> Result<DuplicateOptions> {
        if let Some(m) = &self.message {
            api::check_message(m)?;
        }
        Ok(DuplicateOptions {
            message: self.message.clone(),
            record_origin: self.record_origin,
        })
    }
}

/// `vl duplicate REV… [-d DEST…] [--keep-description | -m MSG] [-x] [--json]`.
#[derive(Args, Debug)]
pub struct DuplicateArgs {
    /// Changes to duplicate (ranges such as `A..B` name several).
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
pub struct CherryPickArgs {
    /// Changes to copy onto the working copy's parent, in this order
    /// (ranges such as `A..B` name several, oldest first).
    #[arg(required = true)]
    pub revs: Vec<String>,
    #[command(flatten)]
    pub description: DuplicateDescription,
    #[command(flatten)]
    pub out: JsonOut,
}

/// `veil.duplicate/1`: the copies made (ids only: no description, so
/// nothing sealed can appear here), and for cherry-pick where `@` and the
/// tags went.
#[derive(Serialize, Debug)]
pub struct DuplicateDoc {
    pub schema: &'static str,
    pub duplicates: Vec<CopyDoc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub working_copy: Option<IdsDoc>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tags_advanced: Vec<String>,
    pub operation: OpRef,
}

#[derive(Serialize, Debug)]
pub struct IdsDoc {
    pub snapshot_id: String,
    pub change_id: Option<String>,
}

#[derive(Serialize, Debug)]
pub struct CopyDoc {
    pub source: IdsDoc,
    pub duplicate: IdsDoc,
    pub conflicts: Vec<String>,
    pub renames: Vec<RenameDoc>,
}

/// A rename a merge, rebase or copy followed (this reader's report).
#[derive(Serialize, Debug)]
pub struct RenameDoc {
    pub from: String,
    pub to: String,
    pub score: u8,
    /// `followed`, `both`, `rename/delete` or `rename/rename`.
    pub how: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub other: Option<String>,
    /// The audience the file stays sealed for at its new path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sealed: Option<String>,
}

fn ids(repo: &Repo, id: &ObjectId) -> IdsDoc {
    IdsDoc {
        snapshot_id: id.hex(),
        change_id: repo.snapshot(id).ok().map(|s| s.change_id.display()),
    }
}

pub fn rename_doc(r: &FollowedRename) -> RenameDoc {
    let (how, other) = match &r.how {
        RenameMerge::Followed => ("followed", None),
        RenameMerge::Both => ("both", None),
        RenameMerge::RenameDelete => ("rename/delete", None),
        RenameMerge::RenameRename { other } => ("rename/rename", Some(other.to_string())),
    };
    RenameDoc {
        from: r.from.to_string(),
        to: r.to.to_string(),
        score: r.score,
        how,
        other,
        sealed: r.sealed.as_ref().map(|v| v.label()),
    }
}

/// Print the renames a merge, rebase or copy followed (to stderr, escaped).
pub fn print_renames(renames: &[FollowedRename]) {
    for r in renames {
        let (from, to) = (safe(r.from.as_str()), safe(r.to.as_str()));
        let line = match &r.how {
            RenameMerge::Followed => format!("followed rename {from} -> {to}"),
            RenameMerge::Both => format!("both sides renamed {from} -> {to}"),
            RenameMerge::RenameDelete => format!("conflict: {from} was renamed to {to} on one side and deleted on the other"),
            RenameMerge::RenameRename { other } => {
                format!("conflict: {from} was renamed to {to} and to {}; keep one with `vl resolve`", safe(other.as_str()))
            }
        };
        eprintln!("  {} {line}", dim("rename:"));
        if let Some(v) = &r.sealed {
            eprintln!(
                "    {} {to} stays sealed ({}) at its new path; `vl expose {to}` publishes it",
                yellow("note:"),
                safe(&v.label())
            );
        }
    }
}

/// Each spec's snapshots, parents before children, each once.
fn resolve_all(ctx: &Ctx, specs: &[String]) -> Result<Vec<ObjectId>> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for spec in specs {
        let mut set = revset::resolve_set(&ctx.repo, spec, &ctx.ws)?;
        set.reverse();
        for id in set {
            if seen.insert(id) {
                out.push(id);
            }
        }
    }
    if out.is_empty() {
        bail!("nothing to duplicate: {} names no change", safe(&specs.join(" ")));
    }
    Ok(out)
}

fn copies_doc(repo: &Repo, done: &[Duplicated]) -> Vec<CopyDoc> {
    done.iter()
        .map(|d| CopyDoc {
            source: ids(repo, &d.source),
            duplicate: ids(repo, &d.duplicate),
            conflicts: d.conflicts.iter().map(|p| p.to_string()).collect(),
            renames: d.renames.iter().map(rename_doc).collect(),
        })
        .collect()
}

fn print_copies(repo: &Repo, done: &[Duplicated]) {
    for d in done {
        println!("Duplicated {}", one_line(repo, &d.source));
        println!("        as {}", one_line(repo, &d.duplicate));
        print_renames(&d.renames);
        if !d.conflicts.is_empty() {
            let list: Vec<String> = d.conflicts.iter().map(|p| p.to_string()).collect();
            warn_untrusted(&format!("conflicts in: {}", list.join(", ")));
        }
    }
}

/// `vl duplicate`.
pub fn duplicate(ctx: &mut Ctx, args: &DuplicateArgs) -> Result<ExitCode> {
    let o = args.description.options()?;
    let sources = resolve_all(ctx, &args.revs)?;
    let dest = args.destination.iter().map(|d| ctx.rev(d)).collect::<Result<Vec<_>>>()?;
    let done = ctx.repo.duplicate(&sources, &dest, &o)?;
    match args.out.json {
        true => api::emit_json(&DuplicateDoc {
            schema: DUPLICATE_SCHEMA,
            duplicates: copies_doc(&ctx.repo, &done),
            working_copy: None,
            tags_advanced: vec![],
            operation: api::op_ref(&ctx.repo),
        })?,
        false => print_copies(&ctx.repo, &done),
    }
    Ok(ExitCode::SUCCESS)
}

/// `vl cherry-pick`.
pub fn cherry_pick(ctx: &mut Ctx, args: &CherryPickArgs) -> Result<ExitCode> {
    let o = args.description.options()?;
    let sources = resolve_all(ctx, &args.revs)?;
    let ws = ctx.ws.clone();
    let r = ctx.repo.cherry_pick(&ws, &sources, &o)?;
    match args.out.json {
        true => api::emit_json(&DuplicateDoc {
            schema: DUPLICATE_SCHEMA,
            duplicates: copies_doc(&ctx.repo, &r.duplicates),
            working_copy: Some(ids(&ctx.repo, &r.wc)),
            tags_advanced: r.advanced.clone(),
            operation: api::op_ref(&ctx.repo),
        })?,
        false => {
            print_copies(&ctx.repo, &r.duplicates);
            if !r.advanced.is_empty() {
                let names: Vec<String> = r.advanced.iter().map(|n| safe(n).into_owned()).collect();
                println!("Moved {} to the last copy", names.join(", "));
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}
