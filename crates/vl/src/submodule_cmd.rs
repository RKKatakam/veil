//! Submodules (Git gitlinks): `vl submodule status|update|set|add`.
//!
//! Feature 5b of the Git-parity round
//! (`docs/design/git-parity/5-hooks-submodules-signed-tags.md`). The engine
//! side (validation, the `git` runner) is `veil_core::submodule`. Nothing
//! here runs on its own: a pull or checkout never fetches a submodule, only
//! `vl submodule update` does.

use std::process::ExitCode;

use anyhow::{bail, Result};
use clap::Subcommand;
use veil_core::{
    submodule::{self, GitRunner, Gitlink, Submodule, UpdateOutcome},
    VPath,
};

use crate::{
    ctx::Ctx,
    render::{cyan, dim, green, red, safe, yellow},
};

/// `vl submodule status|update|set|add`.
#[derive(Subcommand, Debug)]
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
        /// The submodule's name in `.gitmodules` (default: its path).
        #[arg(long)]
        name: Option<String>,
        /// Allow a URL that is a local path or `file://`.
        #[arg(long)]
        allow_local: bool,
    },
}

/// `vl submodule`.
pub fn run(ctx: &mut Ctx, cmd: &SubmoduleCmd) -> Result<ExitCode> {
    match cmd {
        SubmoduleCmd::Status { paths } => status(ctx, paths),
        SubmoduleCmd::Update { paths, allow_local } => update(ctx, paths, *allow_local),
        SubmoduleCmd::Set { path, commit } => set(ctx, path, commit),
        SubmoduleCmd::Add {
            url,
            path,
            name,
            allow_local,
        } => add(ctx, url, path.as_deref(), name.as_deref(), *allow_local),
    }
}

fn short(c: &str) -> &str {
    &c[..c.len().min(12)]
}

/// The gitlinks of `@` and its `.gitmodules`, restricted to `paths`.
fn listing(ctx: &Ctx, paths: &[String]) -> Result<(Vec<Gitlink>, Vec<Submodule>)> {
    let tree = ctx.repo.snapshot(&ctx.wc()?)?.tree;
    let mut links = submodule::gitlinks(ctx.repo.store(), &tree)?;
    let modules = submodule::gitmodules_of(ctx.repo.store(), &tree)?;
    if !paths.is_empty() {
        let wanted: Vec<VPath> = paths.iter().map(|p| ctx.repo_path(p)).collect::<Result<_>>()?;
        for w in &wanted {
            if !links.iter().any(|l| l.path == *w) {
                bail!("{w} is not a submodule");
            }
        }
        links.retain(|l| wanted.contains(&l.path));
    }
    Ok((links, modules))
}

fn module_for<'a>(modules: &'a [Submodule], path: &VPath) -> Option<&'a Submodule> {
    modules.iter().find(|m| m.path.as_deref().map(|p| p.trim_end_matches('/')) == Some(path.as_str()))
}

fn status(ctx: &mut Ctx, paths: &[String]) -> Result<ExitCode> {
    let (links, modules) = listing(ctx, paths)?;
    if links.is_empty() {
        println!("{}", dim("No submodules"));
    }
    for l in &links {
        let m = module_for(&modules, &l.path);
        let pinned = l.commit.as_deref();
        let head = submodule::checked_out(&ctx.root, m.map(|m| m.name.as_str()), &l.path);
        let state = match (pinned, head.as_deref()) {
            (None, _) => yellow("pinned commit sealed"),
            (Some(_), None) => dim("not checked out (`vl submodule update`)"),
            (Some(p), Some(h)) if p == h => green("up to date"),
            (Some(_), Some(h)) => yellow(&format!("checked out {} (differs)", short(h))),
        };
        let pin = pinned.map(short).unwrap_or("-");
        let url = m
            .and_then(|m| m.url.as_deref())
            .map(|u| safe(&veil_core::git::redact_url(u)).into_owned())
            .unwrap_or_else(|| red("no .gitmodules entry"));
        println!("{}  {pin}  {state}  {}", cyan(&safe(l.path.as_str())), dim(&url));
    }
    Ok(ExitCode::SUCCESS)
}

/// The URL of submodule `m`, a relative one resolved against the Git
/// remote (`origin`, else the only one).
fn url_of(ctx: &Ctx, m: &Submodule) -> Result<String> {
    let Some(url) = m.url.clone() else {
        bail!("submodule '{}' has no url in .gitmodules", safe(&m.name));
    };
    if !submodule::is_relative(&url) {
        return Ok(url);
    }
    let remotes = veil_core::git::remotes(&ctx.repo)?;
    let base = remotes
        .get("origin")
        .or_else(|| (remotes.len() == 1).then(|| remotes.values().next()).flatten())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "submodule '{}' has a relative URL ({}), which needs the project's Git remote (`origin`)",
                safe(&m.name),
                safe(&url)
            )
        })?;
    submodule::resolve_relative(&url, base)
        .ok_or_else(|| anyhow::anyhow!("cannot resolve relative URL {} against the Git remote", safe(&url)))
}

fn update(ctx: &mut Ctx, paths: &[String], allow_local: bool) -> Result<ExitCode> {
    let (links, modules) = listing(ctx, paths)?;
    let runner = GitRunner { allow_local };
    let mut failed = 0;
    for l in &links {
        let p = cyan(&safe(l.path.as_str()));
        let result = (|| -> Result<UpdateOutcome> {
            let Some(commit) = &l.commit else {
                bail!("its pinned commit is sealed for a scope you are not in");
            };
            let Some(m) = module_for(&modules, &l.path) else {
                bail!("no .gitmodules entry names this path");
            };
            submodule::validate_name(&m.name)?;
            let url = url_of(ctx, m)?;
            submodule::validate_url(&url, allow_local)?;
            Ok(submodule::update(&runner, &ctx.root, &m.name, &l.path, &url, commit)?)
        })();
        match result {
            Ok(o) => {
                let what = match o {
                    UpdateOutcome::Cloned => "cloned",
                    UpdateOutcome::Fetched => "fetched",
                    UpdateOutcome::CheckedOut => "checked out",
                    UpdateOutcome::UpToDate => "up to date",
                };
                let c = l.commit.as_deref().map(short).unwrap_or("");
                println!("  {} {p} at {c}", green(what));
            }
            Err(e) => {
                failed += 1;
                println!("  {} {p}: {}", red("failed"), safe(&format!("{e:#}")));
            }
        }
    }
    if failed > 0 {
        eprintln!("{failed} submodule(s) not updated");
        return Ok(ExitCode::FAILURE);
    }
    Ok(ExitCode::SUCCESS)
}

fn set(ctx: &mut Ctx, path: &str, commit: &str) -> Result<ExitCode> {
    let vp = submodule::validate_path(ctx.repo_path(path)?.as_str())?;
    let commit = submodule::parse_commit_arg(commit)?;
    let ws = ctx.ws.clone();
    let old = submodule::set_pin(&mut ctx.repo, &ws, &vp, &commit, false)?;
    match old {
        Some(o) if o == commit => println!("{} is already pinned to {}", cyan(vp.as_str()), short(&commit)),
        Some(o) => println!("Pinned {} to {} (was {})", cyan(vp.as_str()), short(&commit), short(&o)),
        None => println!("Pinned {} to {}", cyan(vp.as_str()), short(&commit)),
    }
    if submodule::checked_out(&ctx.root, None, &vp).is_some_and(|h| h != commit) {
        eprintln!("{} check it out with `vl submodule update {vp}`", dim("hint:"));
    }
    Ok(ExitCode::SUCCESS)
}

fn add(ctx: &mut Ctx, url: &str, path: Option<&str>, name: Option<&str>, allow_local: bool) -> Result<ExitCode> {
    let resolved = if submodule::is_relative(url) {
        url_of(
            ctx,
            &Submodule {
                name: String::new(),
                path: None,
                url: Some(url.to_string()),
            },
        )?
    } else {
        url.to_string()
    };
    submodule::validate_url(&resolved, allow_local)?;
    let default = url
        .trim_end_matches('/')
        .rsplit(['/', ':'])
        .next()
        .unwrap_or("")
        .trim_end_matches(".git")
        .to_string();
    let path = match path {
        Some(p) => ctx.repo_path(p)?,
        None => VPath::new(&default).map_err(|_| anyhow::anyhow!("give the submodule's path: none can be derived from the URL"))?,
    };
    let path = submodule::validate_path(path.as_str())?;
    let name = name.map(str::to_string).unwrap_or_else(|| path.as_str().to_string());
    submodule::validate_name(&name)?;
    // `.gitmodules` is written as a regular file only (never through a link).
    let gm = ctx.root.join(submodule::GITMODULES);
    let existing = match std::fs::symlink_metadata(&gm) {
        Ok(m) if m.is_file() => std::fs::read_to_string(&gm)?,
        Ok(_) => bail!("{} is not a regular file; Veil never writes through it", submodule::GITMODULES),
        Err(_) => String::new(),
    };
    let text = submodule::add_section(&existing, &name, &path, url)?;
    let commit = submodule::clone_new(&GitRunner { allow_local }, &ctx.root, &name, &path, &resolved)?;
    let ws = ctx.ws.clone();
    submodule::set_pin(&mut ctx.repo, &ws, &path, &commit, true)?;
    std::fs::write(&gm, text)?;
    println!("Added submodule {} at {} ({})", cyan(&safe(path.as_str())), short(&commit), dim(&safe(&veil_core::git::redact_url(url))));
    Ok(ExitCode::SUCCESS)
}
