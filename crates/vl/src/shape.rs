//! `vl split` and `vl squash` on the command line: arguments to an
//! `api::shape::Choice`, the interactive picker on standard input and
//! standard error, and the text output.

use std::io::IsTerminal;

use anyhow::Result;
use veil_core::{
    selection::{Selection, Unit},
    VPath,
};

use crate::{
    api::{
        self,
        shape::{parse_hunks_arg, Choice, Plan},
    },
    cli::{JsonOut, PickArgs},
    ctx::Ctx,
    picker::{Picker, Purpose},
    render::{one_line, safe},
};

fn choice(ctx: &Ctx, paths: &[String], pick: &PickArgs) -> Result<Choice> {
    let mut c = Choice { paths: paths.iter().map(|p| ctx.repo_path(p)).collect::<Result<_>>()?, specs: vec![] };
    for h in &pick.hunks {
        c.specs.push(parse_hunks_arg(h, |p| ctx.repo_path(p))?);
    }
    if let Some(file) = &pick.plan {
        c.specs.extend(Plan::read(file)?.specs()?);
    }
    Ok(c)
}

/// The picker on standard input (a terminal or a pipe of answers) and
/// standard error.
fn interactive(purpose: Purpose) -> impl FnMut(&[Unit], &[VPath]) -> Result<Selection> {
    move |units, only| {
        let color = std::env::var_os("NO_COLOR").is_none() && std::io::stderr().is_terminal();
        let stdin = std::io::stdin();
        let echo = !stdin.is_terminal();
        Picker::new(stdin.lock(), std::io::stderr().lock(), color, purpose).echo(echo).run(units, only)
    }
}

pub fn cmd_split(ctx: &mut Ctx, paths: &[String], rev: &str, message: Option<&str>, pick: &PickArgs, out: &JsonOut) -> Result<()> {
    let c = choice(ctx, paths, pick)?;
    let mut picker = interactive(Purpose::Split);
    let doc = api::shape::split(ctx, rev, &c, message, pick.interactive.then_some(&mut picker as api::shape::PickFn<'_>))?;
    if out.json {
        return api::emit_json(&doc);
    }
    println!("First part:  {}", one_line(&ctx.repo, &doc.ids.0));
    println!("Second part: {}", one_line(&ctx.repo, &doc.ids.1));
    Ok(())
}

pub fn cmd_squash(ctx: &mut Ctx, paths: &[String], rev: &str, into: Option<&str>, pick: &PickArgs, out: &JsonOut) -> Result<()> {
    let c = choice(ctx, paths, pick)?;
    let mut picker = interactive(Purpose::Squash);
    let doc = api::shape::squash(ctx, rev, into, &c, pick.interactive.then_some(&mut picker as api::shape::PickFn<'_>))?;
    if out.json {
        return api::emit_json(&doc);
    }
    println!("Squashed into {}", one_line(&ctx.repo, &doc.ids.0));
    if let Some(s) = doc.ids.1 {
        let n = doc.moved.len();
        println!("Moved {n} file{} ({}); the rest stays in {}", if n == 1 { "" } else { "s" }, moved_list(&doc.moved), one_line(&ctx.repo, &s));
    }
    Ok(())
}

fn moved_list(moved: &[api::shape::Taken]) -> String {
    let mut parts: Vec<String> = moved
        .iter()
        .take(5)
        .map(|t| match t.whole {
            true => safe(&t.path).into_owned(),
            false => format!("{}:{}", safe(&t.path), t.hunks.join(",")),
        })
        .collect();
    if moved.len() > 5 {
        parts.push(format!("and {} more", moved.len() - 5));
    }
    parts.join(", ")
}
