//! `vl split` and `vl squash` (`veil.split/2`, `veil.squash/2`), shared by
//! the command line and `vl serve --local` (`split`, `squash`).
//!
//! What to take is a [`Choice`]: paths, hunk specs (`--hunks`, `--plan`),
//! or an interactive picker (the command line only: `crate::picker`). Every
//! way ends in a `veil_core::selection::Selection`, checked against the
//! change's units before anything is written, so a script never gets a
//! split it did not ask for.

use std::path::Path;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use veil_core::{
    selection::{self, HunkRef, Selection, Spec, Unit},
    ObjectId, VPath,
};

use super::{op_ref, snapshot_ref, OpRef, SnapshotRef};
use crate::ctx::Ctx;

pub const SPLIT_SCHEMA: &str = "veil.split/2";
pub const SQUASH_SCHEMA: &str = "veil.squash/2";

/// What to take of a change.
#[derive(Clone, Debug, Default)]
pub struct Choice {
    /// Paths taken whole (with a picker: the paths it asks about).
    pub paths: Vec<VPath>,
    /// Files with the hunks taken.
    pub specs: Vec<Spec>,
}

impl Choice {
    pub fn is_empty(&self) -> bool {
        self.paths.is_empty() && self.specs.is_empty()
    }

    fn reads_hunks(&self) -> bool {
        self.specs.iter().any(|s| s.hunks.is_some())
    }

    fn all_specs(&self) -> Vec<Spec> {
        let mut v: Vec<Spec> = self.paths.iter().map(|p| Spec { path: p.clone(), hunks: None }).collect();
        v.extend(self.specs.iter().cloned());
        v
    }
}

/// An interactive picker: from the units (and the paths it may ask about,
/// all if empty) to a selection.
pub type PickFn<'a> = &'a mut dyn FnMut(&[Unit], &[VPath]) -> Result<Selection>;

/// `--hunks PATH:LIST`: `path` resolves the path part (relative to the
/// working directory on the command line).
pub fn parse_hunks_arg(arg: &str, path: impl Fn(&str) -> Result<VPath>) -> Result<Spec> {
    let Some((p, list)) = arg.rsplit_once(':') else {
        bail!("--hunks {arg}: expected PATH:LIST, e.g. src/main.rs:1,3 (name the path alone to take the whole file)");
    };
    let hunks = list.split(',').map(HunkRef::parse).collect::<veil_core::Result<Vec<_>>>().with_context(|| format!("--hunks {arg}"))?;
    Ok(Spec { path: path(p)?, hunks: Some(hunks) })
}

/// A `--plan` document.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    /// Optional; `veil.plan/1` if given.
    #[serde(default)]
    pub schema: Option<String>,
    pub files: Vec<PlanFile>,
}

pub const PLAN_SCHEMA: &str = "veil.plan/1";

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct PlanFile {
    /// Relative to the repository root.
    pub path: String,
    /// Hunks (`1`, `"3.2"`, `"mode"`); absent or `null`: the whole file
    /// (or directory).
    #[serde(default)]
    pub hunks: Option<Vec<PlanHunk>>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum PlanHunk {
    Number(usize),
    Text(String),
}

impl Plan {
    pub fn parse(text: &str) -> Result<Plan> {
        let plan: Plan = serde_json::from_str(text).context("reading the plan")?;
        if let Some(s) = &plan.schema {
            if s != PLAN_SCHEMA {
                bail!("the plan's schema is {s:?}; this version of vl reads {PLAN_SCHEMA:?}");
            }
        }
        Ok(plan)
    }

    pub fn read(file: &Path) -> Result<Plan> {
        let text = if file == Path::new("-") {
            let mut s = String::new();
            std::io::Read::read_to_string(&mut std::io::stdin().lock(), &mut s).context("reading the plan from standard input")?;
            s
        } else {
            std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?
        };
        Plan::parse(&text)
    }

    /// The plan as specs (paths relative to the repository root).
    pub fn specs(&self) -> Result<Vec<Spec>> {
        let mut out = Vec::new();
        for f in &self.files {
            let path = match f.path.trim_matches('/') {
                "" | "." => VPath::root(),
                p => VPath::new(p).with_context(|| format!("plan: path {:?}", f.path))?,
            };
            let hunks = match &f.hunks {
                None => None,
                Some(list) => Some(
                    list.iter()
                        .map(|h| match h {
                            PlanHunk::Number(n) => HunkRef::parse(&n.to_string()),
                            PlanHunk::Text(t) => HunkRef::parse(t),
                        })
                        .collect::<veil_core::Result<Vec<_>>>()
                        .with_context(|| format!("plan: hunks of {:?}", f.path))?,
                ),
            };
            if hunks.as_ref().is_some_and(|h| h.is_empty()) {
                bail!("plan: {:?} lists no hunks (leave `hunks` out to take the whole file)", f.path);
            }
            out.push(Spec { path, hunks });
        }
        Ok(out)
    }
}

/// One unit that was taken, as reported.
#[derive(Serialize, Debug)]
pub struct Taken {
    pub path: String,
    /// The whole file (every hunk, or a file that moves only whole).
    pub whole: bool,
    /// The hunks taken when not whole: `"1"`, `"2.1"` (block 1 of hunk 2),
    /// `"mode"`.
    pub hunks: Vec<String>,
}

fn taken(units: &[Unit], sel: &Selection) -> Vec<Taken> {
    let mut out = Vec::new();
    for u in units {
        let Some(pick) = sel.get(&u.path) else { continue };
        if u.is_none(pick) {
            continue;
        }
        if u.is_all(pick) {
            out.push(Taken { path: u.path.to_string(), whole: true, hunks: vec![] });
            continue;
        }
        let mut hunks = Vec::new();
        if pick.mode {
            hunks.push(HunkRef::Mode.to_string());
        }
        if let Some(t) = u.text() {
            for (h, hunk) in t.diff.hunks.iter().enumerate() {
                let n = (0..hunk.blocks.len()).filter(|b| pick.blocks.contains(&(h, *b))).count();
                if n == hunk.blocks.len() {
                    hunks.push(HunkRef::Hunk(h + 1).to_string());
                } else {
                    hunks.extend((0..hunk.blocks.len()).filter(|b| pick.blocks.contains(&(h, *b))).map(|b| HunkRef::Block(h + 1, b + 1).to_string()));
                }
            }
        }
        out.push(Taken { path: u.path.to_string(), whole: false, hunks });
    }
    out
}

/// `vl split` (`veil.split/2`).
#[derive(Serialize, Debug)]
pub struct Split {
    pub schema: &'static str,
    /// The new change with what was chosen.
    pub first: SnapshotRef,
    /// The change that was split (same change id), now with the rest, on
    /// top of `first`.
    pub second: SnapshotRef,
    /// What went into the first change.
    pub chosen: Vec<Taken>,
    pub operation: OpRef,
    #[serde(skip)]
    pub(crate) ids: (ObjectId, ObjectId),
}

pub fn split(ctx: &mut Ctx, rev: &str, choice: &Choice, message: Option<&str>, picker: Option<PickFn<'_>>) -> Result<Split> {
    if let Some(m) = message {
        super::check_message(m)?;
    }
    let id = ctx.rev(rev)?;
    if picker.is_none() && choice.is_empty() {
        bail!("choose what goes in the first change: name files or directories, or use -i, --hunks or --plan");
    }
    let parts = ctx.repo.change_parts(&id, picker.is_some() || choice.reads_hunks())?;
    if parts.units.is_empty() {
        bail!("{} has no changes to split", id.short());
    }
    let sel = match picker {
        Some(pick) => pick(&parts.units, &choice.paths)?,
        None => {
            selection::check_hidden(&parts.hidden, &choice.all_specs())?;
            selection::select(&parts.units, &choice.all_specs())?
        }
    };
    let r = ctx.repo.split(&parts, &sel, message)?;
    let repo = &ctx.repo;
    Ok(Split {
        schema: SPLIT_SCHEMA,
        first: snapshot_ref(repo, &r.first),
        second: snapshot_ref(repo, &r.second),
        chosen: taken(&parts.units, &sel),
        operation: op_ref(repo),
        ids: (r.first, r.second),
    })
}

/// `vl squash` (`veil.squash/2`).
#[derive(Serialize, Debug)]
pub struct Squash {
    pub schema: &'static str,
    /// The destination, with what moved.
    pub destination: SnapshotRef,
    /// The source with what stayed; `null` when everything moved (the
    /// source was abandoned).
    pub source: Option<SnapshotRef>,
    pub source_abandoned: bool,
    /// What moved (every file, for a whole squash).
    pub moved: Vec<Taken>,
    pub operation: OpRef,
    #[serde(skip)]
    pub(crate) ids: (ObjectId, Option<ObjectId>),
}

pub fn squash(ctx: &mut Ctx, rev: &str, into: Option<&str>, choice: &Choice, picker: Option<PickFn<'_>>) -> Result<Squash> {
    let id = ctx.rev(rev)?;
    let into = into.map(|r| ctx.rev(r)).transpose()?;
    let partial = picker.is_some() || !choice.is_empty();
    let r = if partial {
        let parts = ctx.repo.change_parts(&id, picker.is_some() || choice.reads_hunks())?;
        let sel = match picker {
            Some(pick) => pick(&parts.units, &choice.paths)?,
            None => {
                selection::check_hidden(&parts.hidden, &choice.all_specs())?;
                selection::select(&parts.units, &choice.all_specs())?
            }
        };
        let r = ctx.repo.squash_into(id, into, Some((&parts, &sel)))?;
        (r, taken(&parts.units, &sel))
    } else {
        // Reported only: a whole squash reads nothing (and works under an
        // embargo, whose trees cannot be listed by unit).
        let units = ctx.repo.change_parts(&id, false).map(|p| p.units).unwrap_or_default();
        let everything: Selection = units.iter().map(|u| (u.path.clone(), u.everything())).collect();
        let r = ctx.repo.squash_into(id, into, None)?;
        (r, taken(&units, &everything))
    };
    let (r, moved) = r;
    let repo = &ctx.repo;
    Ok(Squash {
        schema: SQUASH_SCHEMA,
        destination: snapshot_ref(repo, &r.destination),
        source: r.source.map(|s| snapshot_ref(repo, &s)),
        source_abandoned: r.source.is_none(),
        moved,
        operation: op_ref(repo),
        ids: (r.destination, r.source),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plans_and_hunk_args_parse() {
        let p = Plan::parse(r#"{"files": [{"path": "src/a.rs", "hunks": [1, "2.1", "mode"]}, {"path": "docs/"}]}"#).unwrap();
        let specs = p.specs().unwrap();
        assert_eq!(specs[0].hunks.as_ref().unwrap(), &[HunkRef::Hunk(1), HunkRef::Block(2, 1), HunkRef::Mode]);
        assert_eq!(specs[1].path.as_str(), "docs");
        assert!(specs[1].hunks.is_none());
        assert!(Plan::parse(r#"{"files": [], "extra": 1}"#).is_err(), "unknown fields are refused");
        assert!(Plan::parse(r#"{"schema": "veil.plan/2", "files": []}"#).is_err());
        assert!(Plan::parse(r#"{"files": [{"path": "a", "hunks": []}]}"#).unwrap().specs().is_err());
        assert!(Plan::parse(r#"{"files": [{"path": "a", "hunks": [0]}]}"#).unwrap().specs().is_err());
        let path = |s: &str| Ok(VPath::new(s)?);
        let s = parse_hunks_arg("a:b.txt:1,2.3", path).unwrap();
        assert_eq!(s.path.as_str(), "a:b.txt");
        assert_eq!(s.hunks.unwrap(), [HunkRef::Hunk(1), HunkRef::Block(2, 3)]);
        assert!(parse_hunks_arg("a.txt", path).is_err());
        assert!(parse_hunks_arg("a.txt:", path).is_err());
    }
}
