// Every `println!` / `eprintln!` in this crate (these definitions shadow
// std's in all modules declared below) goes through `render`, which survives
// a closed pipe instead of panicking (`vl log | head`; see `render::Out`).
macro_rules! println {
    () => {
        $crate::render::out_line(format_args!(""))
    };
    ($($arg:tt)*) => {
        $crate::render::out_line(format_args!($($arg)*))
    };
}

macro_rules! eprintln {
    () => {
        $crate::render::err_line(format_args!(""))
    };
    ($($arg:tt)*) => {
        $crate::render::err_line(format_args!($($arg)*))
    };
}

mod api;
mod attr_cmd;
mod auto_gc;
mod cli;
mod confine;
mod ctx;
mod doctor;
#[cfg(test)]
mod docgen;
mod history;
mod hub;
mod hub_cmd;
mod hub_keys;
mod hooks;
mod mount;
mod picker;
mod render;
mod rewrite_cmd;
mod sandbox;
mod serve;
mod shape;
mod team_secret;

use std::{
    io::{IsTerminal, Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use clap::{CommandFactory, Parser};
use veil_core::{
    checkout::{behind_special, Materialised},
    commands::{CommitResult, EmbargoSpec, TagKept, RELEASE_OP_PREFIX},
    now_millis,
    keychain::{validate_scope_name, ReleaseState},
    policy::{escape_field, escape_literal, format_rule, has_glob_syntax, Policy, Tier, POLICY_FILE},
    remote,
    repo::{RemoteConfig, DEFAULT_WORKSPACE},
    tree::lookup,
    vfs::NodeKind,
    DiskBackend, Identity, Repo, SftpBackend, SshUrl, StorageBackend, VPath,
};

use crate::{
    cli::*,
    ctx::{load_identity, save_checkout, user_for, CheckoutState, Ctx},
    render::*,
};

const DEFAULT_POLICY: &str = "\
# Veil visibility policy — the last matching rule wins.
#
#   <pattern>          public | public! | cloak [scope] | isolate | ignore
#
#   public    plaintext, synced everywhere (default)
#   public!   public with secret scanning disabled (deliberate exposure)
#   cloak     encrypted for members of a scope (default scope: team)
#   isolate   local-only: never snapshotted, never pushed
#   ignore    not tracked at all
#
# Patterns are globs. Escape * ? [ ] { } # and spaces with \\ to match them
# literally (`vl cloak <existing path>` does this for you).
#
# Access lines name who may see a folder on the Veil server (the last
# matching line wins; everything else is private to admins):
#
#   src/                 public          everyone on Earth may read
#   billing/             finance         the group finance, or a person
#
# Engine-enforced: .env, .env.*, *.pem, *.key, id_rsa, … are secrets and
# cannot be made public by a plain `public` rule. Public files are scanned
# for credentials on every snapshot and quarantined on a hit.

target/                  ignore
node_modules/            ignore

";

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    if args.next().is_some_and(|a| a == sandbox::REAPER_ARG) {
        return sandbox::reaper_main(args.collect());
    }
    let cli = Cli::parse();
    let json = cli.cmd.wants_json();
    render::exit_status(match run(cli) {
        Ok(code) => code,
        Err(e) => {
            let message = format!("{e:#}");
            // Errors may quote repository data (names, paths): escape them.
            eprintln!("{} {}", red("error:"), safe(&message));
            let hint = error_hint(&e);
            if let Some(h) = hint {
                eprintln!("{} {h}", yellow("hint:"));
            }
            // `--json`: the failure as this invocation's one document,
            // unless the command already printed its own (then only stderr
            // and the exit status tell).
            if json && !api::json_emitted() {
                let _ = api::emit_json(&api::ErrorDoc::new(message, hint.map(String::from)));
            }
            ExitCode::FAILURE
        }
    })
}

/// The `hint:` printed after an error, if it has one (also the `hint` of
/// its `veil.error/1` document, on the command line and over `vl serve`).
fn error_hint(e: &anyhow::Error) -> Option<&'static str> {
    e.chain()
        .any(|c| matches!(c.downcast_ref::<veil_core::VeilError>(), Some(veil_core::VeilError::NameCollision(_))))
        .then_some(
            "the repository already moved to that snapshot. To work here meanwhile, move the working copy \
             back without touching files: `vl --no-snapshot undo` (or `vl --no-snapshot edit <rev>`)",
        )
}

fn open(cli: &Cli) -> Result<Ctx> {
    // `vl commit` records the directory in its own transaction (one
    // operation with the commit, `Ctx::commit`).
    Ctx::open(cli.repository.as_deref(), !cli.no_snapshot && !matches!(cli.cmd, Cmd::Commit { .. }))
}

fn run(cli: Cli) -> Result<ExitCode> {
    match &cli.cmd {
        Cmd::Init { path } => cmd_init(path.as_deref()),
        Cmd::Clone { source, dest, only } => match hub::HubUrl::parse(source) {
            Some(url) => hub_cmd::clone(&url?, dest.as_deref(), only.as_deref()),
            None if only.is_some() => bail!("--only works with a Veil server project (veil://host/project)"),
            None => cmd_clone(source, dest.as_deref()),
        },
        Cmd::Login { url, name, ca } => hub_cmd::login(url, name.as_deref(), ca.as_deref()),
        // Through the server's API, not the working copy: no snapshot.
        Cmd::Change(c) => hub_cmd::change(cli.repository.as_deref(), c),
        Cmd::Identity(c) => cmd_identity(c),
        Cmd::Fsck { verbose } => cmd_fsck(cli.repository.as_deref(), *verbose),
        Cmd::Doctor { remotes } => doctor::run(cli.repository.as_deref(), *remotes),
        Cmd::Completions { shell } => {
            clap_complete::generate(*shell, &mut Cli::command(), "vl", &mut render::Out);
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Man { out_dir } => cmd_man(out_dir.as_deref()),
        Cmd::Join { link } => hub_keys::join(link).map(|()| ExitCode::SUCCESS),
        Cmd::Upgrade { dry_run, rule_keys: true, .. } => {
            let mut ctx = open(&cli)?;
            let code = hub_keys::upgrade_rule_keys(&mut ctx, *dry_run)?;
            ctx.finish()?;
            Ok(code)
        }
        Cmd::Upgrade { dry_run, sync_secrets: true, .. } => {
            let mut ctx = open(&cli)?;
            let code = cmd_sync_secrets(&mut ctx, *dry_run)?;
            ctx.finish()?;
            Ok(code)
        }
        Cmd::Upgrade { dry_run, remote, force, .. } => cmd_upgrade(cli.repository.as_deref(), *dry_run, remote.as_deref(), *force),
        Cmd::Scan { policy_from: Some(file), out } => cmd_scan_gate(cli.repository.as_deref(), file, out.json),
        // Bypasses `Ctx::open` too: the server opens the repository afresh
        // for every request.
        Cmd::Serve { call: Some(method), params, .. } => serve::call(cli.repository.as_deref(), method, params.as_deref()),
        Cmd::Serve { .. } => serve::run(cli.repository.as_deref(), !cli.no_snapshot),
        // The serving process must not hold a `Ctx` while it serves.
        Cmd::Workspace(WsCmd::Mount {
            name,
            dir,
            foreground,
            record_every,
        }) => mount::cmd_mount(
            cli.repository.as_deref(),
            !cli.no_snapshot,
            &mount::MountArgs {
                name,
                dir,
                foreground: *foreground,
                record_every: *record_every,
            },
        ),
        _ => {
            let mut ctx = open(&cli)?;
            refuse_bare(&ctx, runs_in_a_bare_repository(&cli.cmd))?;
            let before = hooks::checkout_point(&ctx);
            let code = dispatch(&mut ctx, &cli)?;
            ctx.finish()?;
            hooks::post_checkout(&ctx, &cli.cmd, before);
            if !matches!(cli.cmd, Cmd::Gc { .. }) {
                auto_gc::maybe_spawn(&ctx);
            }
            if !matches!(cli.cmd, Cmd::ShareKeys) {
                hub_keys::maybe_spawn(&ctx);
            }
            Ok(code)
        }
    }
}

/// Refuse a command that needs a working copy in a bare repository.
fn refuse_bare(ctx: &Ctx, runs_bare: bool) -> Result<()> {
    if ctx.bare && !runs_bare {
        bail!(
            "{} is a bare repository (a remote): it has no working copy. Here `vl -R` runs only \
             `log`, `show`, `tag list`, `op log`, `gc` and `fsck`",
            ctx.root.display()
        );
    }
    Ok(())
}

/// The commands that work in a bare repository (BUG-284): they read
/// history, or garbage-collect it, and never need a working copy.
fn runs_in_a_bare_repository(cmd: &Cmd) -> bool {
    matches!(
        cmd,
        Cmd::Log { .. } | Cmd::Show { .. } | Cmd::Tag(TagCmd::List { .. }) | Cmd::Op(OpCmd::Log { .. }) | Cmd::Gc { .. }
    )
}

fn dispatch(ctx: &mut Ctx, cli: &Cli) -> Result<ExitCode> {
    match &cli.cmd {
        Cmd::Init { .. }
        | Cmd::Clone { .. }
        | Cmd::Login { .. }
        | Cmd::Change(_)
        | Cmd::Join { .. }
        | Cmd::Identity(_)
        | Cmd::Fsck { .. }
        | Cmd::Doctor { .. }
        | Cmd::Completions { .. }
        | Cmd::Man { .. }
        | Cmd::Upgrade { .. }
        | Cmd::Serve { .. } => unreachable!(),
        // The read commands: a structured result (`api`), shown as text or
        // as one JSON document.
        Cmd::Status { out } => match out.json {
            true => api::emit_json(&api::status(ctx)?)?,
            false => api::text::status(&api::status(ctx)?),
        },
        Cmd::Log { limit, filter, out } => history::log(ctx, *limit, filter, out.json)?,
        Cmd::Show { rev, stat, renames, out } => history::show(ctx, rev, *stat, renames, out.json)?,
        Cmd::Diff { rev, from, to, stat, renames, out } => {
            history::diff(ctx, rev.as_deref(), from.as_deref(), to.as_deref(), *stat, renames, out.json)?
        }
        Cmd::Files { rev } => {
            let id = ctx.rev(rev)?;
            print_files(&ctx.repo, &ctx.repo.snapshot(&id)?.tree)?;
        }
        Cmd::Ls { paths, rev, all, out } => {
            let ls = api::ls(ctx, rev, paths, *all, !cli.no_snapshot)?;
            match out.json {
                true => api::emit_json(&ls)?,
                false => api::text::ls(&ls),
            }
        }
        Cmd::Cat { path, rev } => {
            let id = ctx.rev(rev)?;
            let p = ctx.repo_path(path)?;
            let e = match p.is_root() {
                true => None,
                false => lookup(ctx.repo.store(), &ctx.repo.snapshot(&id)?.tree, &p)?,
            };
            match &e {
                // A symlink prints its target.
                Some(e) if e.kind.is_file_like() || e.kind.is_special() => {}
                Some(_) => bail!("{} is a directory in {}, not a file (`vl files -r {}` lists its files)", safe(p.as_str()), id.short(), id.short()),
                None if p.is_root() => bail!("'{}' is the repository's root directory, not a file", safe(path)),
                None => bail!("{} does not exist in {}", safe(p.as_str()), id.short()),
            }
            let e = e.expect("a file");
            let data = read_file(&ctx.repo, &p, &e)?;
            render::Out.write_all(&data)?;
        }
        Cmd::Evolog { rev } => {
            let mut cur = Some(ctx.rev(rev)?);
            while let Some(id) = cur {
                let s = match ctx.repo.snapshot(&id) {
                    Err(veil_core::VeilError::Missing(_)) => {
                        println!("{}", dim("(older versions were removed by `vl gc`)"));
                        break;
                    }
                    r => r?,
                };
                println!("{}  {}", dim(&fmt_time(s.timestamp)), one_line(&ctx.repo, &id));
                cur = s.predecessors.first().copied();
            }
        }
        Cmd::Blame(a) => return history::blame(ctx, a),
        Cmd::Grep(a) => return history::grep(ctx, a),
        Cmd::Bisect(c) => return history::bisect(ctx, c),
        // Shared with `vl serve --local` (`api`, write methods).
        Cmd::Describe { rev, message, hooks } => {
            // `pre-commit` and `commit-msg` run for a describe of `@`.
            let message = match ctx.rev(rev)? == ctx.wc()? {
                true => hooks::before_commit(ctx, hooks, message, !cli.no_snapshot, "describe")?,
                false => message.clone(),
            };
            let d = api::describe(ctx, rev, &message)?;
            println!("Described {}", one_line(&ctx.repo, &d.id));
        }
        Cmd::New { revs, message } => {
            api::new_change(ctx, revs, message)?;
        }
        Cmd::Commit { message, no_advance, hooks } => {
            let message = hooks::before_commit(ctx, hooks, message, !cli.no_snapshot, "commit")?;
            let c = api::commit(ctx, &message, !*no_advance, !cli.no_snapshot)?;
            println!("Committed {}", one_line(&ctx.repo, &c.result.committed));
            print_tags_kept(&ctx.repo, &c.result);
        }
        Cmd::Edit { rev } => {
            let id = ctx.rev(rev)?;
            let ws = ctx.ws.clone();
            ctx.repo.edit(&ws, id)?;
        }
        Cmd::Abandon { rev } => {
            let id = ctx.rev(rev)?;
            let line = one_line(&ctx.repo, &id);
            ctx.repo.abandon(id)?;
            println!("Abandoned {line}");
        }
        Cmd::Rebase { source, destination } => {
            let src = ctx.rev(source)?;
            let dest = destination.iter().map(|d| ctx.rev(d)).collect::<Result<Vec<_>>>()?;
            let (new, renames) = ctx.repo.rebase_reporting(src, dest)?;
            println!("Rebased {}", one_line(&ctx.repo, &new));
            rewrite_cmd::print_renames(&renames);
            let s = ctx.repo.snapshot(&new)?;
            if !s.conflicts.is_empty() {
                warn_untrusted(&format!("conflicts in: {}", s.conflicts.join(", ")));
            }
        }
        Cmd::Resolve {
            paths,
            list,
            ours,
            theirs,
            base,
            side,
            rev,
            out,
        } => {
            let pick = match (*ours, *theirs, *base, *side) {
                (true, ..) => Some(veil_core::conflict::Pick::Ours),
                (_, true, ..) => Some(veil_core::conflict::Pick::Theirs),
                (_, _, true, _) => Some(veil_core::conflict::Pick::Base),
                (.., Some(n)) => Some(veil_core::conflict::Pick::Side(n)),
                _ => None,
            };
            match pick {
                Some(_) if *list => unreachable!("clap refuses --list with a version"),
                None => {
                    let doc = api::resolve_list(ctx, rev, paths)?;
                    match out.json {
                        true => api::emit_json(&doc)?,
                        false => api::text::resolve_list(&doc),
                    }
                }
                Some(_) if out.json => bail!("--json lists conflicts; it does not resolve them"),
                Some(_) if paths.is_empty() => {
                    bail!("name the conflicted files to resolve (`vl resolve --list` lists them)")
                }
                Some(pick) => {
                    let ps: Vec<VPath> = paths.iter().map(|p| ctx.repo_path(p)).collect::<Result<_>>()?;
                    let ws = ctx.ws.clone();
                    let done = ctx.repo.resolve_conflicts(&ws, &ps, pick)?;
                    for p in &done {
                        println!("Resolved {}", safe(p.as_str()));
                    }
                }
            }
        }
        Cmd::Split { paths, rev, message, pick, out } => shape::cmd_split(ctx, paths, rev, message.as_deref(), pick, out)?,
        Cmd::Squash { paths, rev, into, pick, out } => shape::cmd_squash(ctx, paths, rev, into.as_deref(), pick, out)?,
        Cmd::Restore { paths, from } => cmd_restore(ctx, paths, from.as_deref())?,
        Cmd::Duplicate(a) => return rewrite_cmd::duplicate(ctx, a),
        Cmd::CherryPick(a) => return rewrite_cmd::cherry_pick(ctx, a),
        Cmd::Merge {
            revs,
            into,
            message,
            embargo,
            until,
            scope,
        } => cmd_merge(ctx, revs, into.as_deref(), message.as_deref(), *embargo, until.as_deref(), scope)?,
        Cmd::Embargo(c) => cmd_embargo(ctx, c)?,
        Cmd::Tag(c) => cmd_tag(ctx, c)?,
        Cmd::Cloak { patterns, scope } => {
            validate_scope_name(scope)?;
            if !ctx.repo.keys().is_member(scope) {
                bail!("{}", not_a_member(ctx, scope)?);
            }
            cmd_policy_rules(ctx, patterns, Tier::Cloaked(scope.clone()), false)?
        }
        Cmd::Isolate { patterns } => cmd_policy_rules(ctx, patterns, Tier::Isolated, false)?,
        Cmd::Expose { patterns, force } => cmd_policy_rules(ctx, patterns, Tier::Public, *force)?,
        Cmd::Ignore { patterns } => cmd_policy_rules(ctx, patterns, Tier::Ignored, false)?,
        Cmd::Policy(c) => cmd_policy(ctx, c)?,
        Cmd::Attr(a) => return attr_cmd::attr(ctx, a),
        Cmd::Renormalize(a) => return attr_cmd::renormalize(ctx, a),
        Cmd::Scan { out, .. } => {
            let scan = api::scan(ctx)?;
            match out.json {
                true => api::emit_json(&scan)?,
                false => api::text::scan(&scan),
            }
            return Ok(scan_status(&scan));
        }
        Cmd::Secret(c) => cmd_secret(ctx, c)?,
        Cmd::Run {
            command,
            scopes,
            local_only,
            remember,
        } => return cmd_run(ctx, command, scopes, *local_only, *remember),
        Cmd::Scope(c) => cmd_scope(ctx, c)?,
        Cmd::Workspace(c) => return cmd_ws(ctx, c),
        Cmd::Op(OpCmd::Log { limit, out }) => match out.json {
            true => api::emit_json(&api::op_log(&ctx.repo, *limit)?)?,
            false => api::text::op_log(&api::op_log(&ctx.repo, *limit)?),
        },
        // Both keep uncommitted working-copy edits: the automatic snapshot
        // taken before the command is not what the user wants to undo.
        Cmd::Op(OpCmd::Heads { out }) => {
            let heads = api::op_heads(&ctx.repo)?;
            match out.json {
                true => api::emit_json(&heads)?,
                false => api::text::op_log(&heads),
            }
        }
        Cmd::Op(OpCmd::Restore { id, force }) => {
            let op = ctx.repo.ops().resolve_prefix(id)?;
            let ws = ctx.ws.clone();
            // Work other workspaces (agents) recorded after the target would
            // leave the view: refuse unless asked (it stays in the op log).
            let others = ctx.repo.other_workspaces_since(op, &ws)?;
            if !others.is_empty() && !*force {
                let mut list = String::new();
                for (id, o) in others.iter().take(10) {
                    list.push_str(&format!(
                        "\n  {} {} (workspace '{}')",
                        id.short(),
                        safe(&o.description),
                        safe(o.workspace.as_deref().unwrap_or_default())
                    ));
                }
                if others.len() > 10 {
                    list.push_str(&format!("\n  … and {} more", others.len() - 10));
                }
                bail!(
                    "other workspaces recorded {} operation(s) after {}, whose work would leave the view:{list}\n\
                     Nothing was changed. Undo a single operation with `vl undo --op <id>`, or restore anyway with `vl op restore {} --force` (their work stays in the op log)",
                    others.len(),
                    op.short(),
                    safe(id)
                );
            }
            let outside = ctx.repo.manual_undo_since(op)?;
            // Releases are not in the view: take back the staged ones made
            // since, and say which published ones stay (BUG-109).
            let (staged, published) = ctx.repo.releases_after(&op)?;
            ctx.repo.restore_operation_keeping_edits(&ws, op)?;
            for e in &staged {
                ctx.repo.keys().take_back_release(e)?;
            }
            println!("Restored to operation {}", op.short());
            for e in &staged {
                println!("  embargo {}: release taken back (its key had not left this repository)", safe(e));
            }
            for e in &published {
                warn(&format!(
                    "embargo {} stays released: its key was published after that operation, and a published key cannot be taken back",
                    safe(e)
                ));
            }
            for o in outside {
                warn(&format!(
                    "not reverted: '{}' ({})",
                    safe(&o.description),
                    safe(o.manual_undo.as_deref().unwrap_or_default())
                ));
            }
        }
        Cmd::Undo { op } => {
            let ws = ctx.ws.clone();
            ctx.repo.reload()?;
            let target = match op {
                Some(id) => ctx.repo.ops().resolve_prefix(id)?,
                None => ctx.repo.undo_target(&ws)?,
            };
            // The attachment is not in the view: undoing `vl ws switch` is
            // switching back (each workspace keeps its own edits).
            if let Some(from) = ctx.repo.undo_switch(&ws, &target)? {
                ctx.attach(&from)?;
                ctx.repo.record_workspace_switch_undo(&ws, &from, target)?;
                println!("Undid: switch the project directory from workspace '{}' to '{}'", safe(&from), safe(&ws));
                return Ok(ExitCode::SUCCESS);
            }
            let (_, undone) = ctx.repo.undo_operation_keeping_edits(&ws, target)?;
            println!("Undid: {}", safe(&undone));
            if let Some(remote) = undone.strip_prefix("push to ") {
                println!(
                    "The remote still has what was pushed: only what this repository remembers about it ({}/<tag>) went back. `vl pull {}` reads it again.",
                    safe(remote),
                    safe(remote)
                );
            }
            if let Some(e) = undone.strip_prefix(RELEASE_OP_PREFIX) {
                println!("Embargo {} is unreleased again: its key had not left this repository.", safe(e));
            }
        }
        Cmd::Redo => {
            let ws = ctx.ws.clone();
            ctx.repo.reload()?;
            let (undo, target) = ctx.repo.redo_target(&ws)?;
            if let Some(to) = ctx.repo.redo_switch(&ws, &target)? {
                ctx.attach(&to)?;
                ctx.repo.record_workspace_switch_redo(&ws, &to, undo)?;
                println!("Redid: switch the project directory from workspace '{}' to '{}'", safe(&ws), safe(&to));
                return Ok(ExitCode::SUCCESS);
            }
            let (_, redone) = ctx.repo.redo_keeping_edits(&ws)?;
            println!("Redid: {}", safe(&redone));
        }
        Cmd::Watch { interval_ms } => cmd_watch(ctx, *interval_ms)?,
        Cmd::Remote(c) => cmd_remote(ctx, c)?,
        Cmd::Group(c) => hub_cmd::group(ctx, c)?,
        Cmd::Invite { person, to } => hub_cmd::invite(ctx, person, to)?,
        Cmd::ShareKeys => hub_cmd::share_keys(ctx)?,
        Cmd::Access { path, who } => hub_cmd::access(ctx, path, who)?,
        Cmd::Push { remote, tag, force, dry_run: false, delete, .. }
            if delete.is_empty() && hub_cmd::is_hub_remote(ctx, remote.as_deref().unwrap_or("origin")) =>
        {
            return hub_cmd::push(ctx, remote.as_deref().unwrap_or("origin"), tag, *force);
        }
        Cmd::Pull { remote, .. } if hub_cmd::is_hub_remote(ctx, remote) => hub_cmd::pull(ctx, remote)?,
        Cmd::Push { remote, .. } if hub_cmd::is_hub_remote(ctx, remote.as_deref().unwrap_or("origin")) => {
            bail!("--dry-run and --delete are not available for a Veil server remote yet (docs/HUB.md §13.8)")
        }
        Cmd::Push {
            remote,
            tag,
            force,
            force_tags,
            dry_run: true,
            json,
            ..
        } => {
            // A dry run sends nothing: no `pre-push` (`--no-verify` is moot).
            return cmd_push_dry_run(ctx, remote.as_deref(), tag, (*force, *force_tags), *json);
        }
        Cmd::Push {
            remote,
            tag,
            force,
            force_tags,
            full,
            delete,
            hooks,
            no_resume,
            ..
        } => {
            let opts = remote::SyncOptions {
                full: *full,
                force_tags: *force_tags,
                no_resume: *no_resume,
                chunk: push_chunk()?,
                ..Default::default()
            };
            return cmd_push(ctx, remote.as_deref().unwrap_or("origin"), tag, *force, &opts, delete, hooks);
        }
        Cmd::Pull { remote, full } => cmd_pull(ctx, remote, *full)?,
        Cmd::Hooks(c) => return hooks::run(ctx, c),
        Cmd::Gc {
            keep_ops_days,
            grace_minutes,
            prune_now,
            level,
            no_deltas,
            auto,
        } if !*auto => cmd_gc(ctx, *keep_ops_days, *grace_minutes, *prune_now, *level, *no_deltas)?,
        Cmd::Gc { .. } => auto_gc::run(ctx)?,
    }
    Ok(ExitCode::SUCCESS)
}

// ---- setup ---------------------------------------------------------------

fn cmd_init(path: Option<&Path>) -> Result<ExitCode> {
    let root = match path {
        Some(p) => p.to_path_buf(),
        None => std::env::current_dir()?,
    };
    std::fs::create_dir_all(&root)?;
    let root = root.canonicalize()?;
    let identity = load_identity()?;
    let fs = Arc::new(DiskBackend::new(&root));
    let mut repo = Repo::init(fs.clone(), Some(identity.clone()), &user_for(&identity))?;
    let policy = VPath::new(POLICY_FILE)?;
    // Anything there (a symlinked or unreadable policy too) is kept.
    if std::fs::symlink_metadata(root.join(POLICY_FILE)).is_err() {
        let text = format!("{DEFAULT_POLICY}{}", veil_core::policy::SYNCED_SECRETS_POLICY);
        fs.write(&policy, text.as_bytes())?;
    }
    let out = repo.snapshot_workspace(DEFAULT_WORKSPACE, &*fs)?;
    repo.capture_local_files(&*fs, &out.report)?;
    save_checkout(&fs, &CheckoutState::new(DEFAULT_WORKSPACE, out.snapshot, Materialised::default()))?;
    println!("Initialized Veil repository in {}", root.join(".veil").display());
    println!("  identity   {} ({})", identity.name, dim(&identity.public_hex()));
    println!("  scope      team (you are the only member)");
    println!("  recorded   {} files", out.report.files);
    let local = out.report.local_only();
    if !local.is_empty() {
        println!(
            "  local-only {}",
            local.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ")
        );
    }
    print_build_warnings(&out.report);
    Ok(ExitCode::SUCCESS)
}

fn cmd_clone(source: &str, dest: Option<&Path>) -> Result<ExitCode> {
    // An SSH remote, or a local path.
    let (backend, url, shown): (Arc<dyn StorageBackend>, String, String) = match SshUrl::parse(source) {
        Some(url) => {
            let url = url?;
            let name = url
                .last_component()
                .ok_or_else(|| anyhow!("cannot derive a directory name from {source}; give one"))?
                .to_string();
            let dest = dest.map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from(name));
            return clone_into(connect_sftp(&url)?, source.to_string(), url.to_string(), &dest);
        }
        None => {
            let path = Path::new(source)
                .canonicalize()
                .with_context(|| format!("remote {source} not found"))?;
            let shown = path.display().to_string();
            (Arc::new(DiskBackend::new(&path)), shown.clone(), shown)
        }
    };
    let dest = match dest {
        Some(d) => d.to_path_buf(),
        None => PathBuf::from(
            Path::new(&url)
                .file_name()
                .ok_or_else(|| anyhow!("cannot derive a directory name"))?,
        ),
    };
    clone_into(backend, url, shown, &dest)
}

fn connect_sftp(url: &SshUrl) -> Result<Arc<dyn StorageBackend>> {
    Ok(Arc::new(
        SftpBackend::connect(url).with_context(|| format!("connecting to {url}"))?,
    ))
}

/// Clone the repository on `backend` (configured as `origin` → `url`) into
/// `dest`. On failure, whatever the clone created is removed: the whole
/// destination if it did not exist, otherwise its contents (it was empty).
fn clone_into(backend: Arc<dyn StorageBackend>, url: String, shown: String, dest: &Path) -> Result<ExitCode> {
    if dest.exists() && std::fs::read_dir(dest)?.next().is_some() {
        bail!("destination {} is not empty", dest.display());
    }
    let created = !dest.exists();
    std::fs::create_dir_all(dest)?;
    let dest = dest.canonicalize()?;
    let result = clone_populate(backend, url, shown, &dest);
    if result.is_err() {
        let cleaned = if created {
            std::fs::remove_dir_all(&dest)
        } else {
            empty_dir(&dest)
        };
        if let Err(e) = cleaned {
            warn(&format!("could not remove the partial clone in {}: {e}", dest.display()));
        }
    }
    result
}

/// Remove everything inside `dir` (not following symlinks).
fn empty_dir(dir: &Path) -> std::io::Result<()> {
    for e in std::fs::read_dir(dir)? {
        let e = e?;
        if e.file_type()?.is_dir() {
            std::fs::remove_dir_all(e.path())?;
        } else {
            std::fs::remove_file(e.path())?;
        }
    }
    Ok(())
}

fn clone_populate(backend: Arc<dyn StorageBackend>, url: String, shown: String, dest: &Path) -> Result<ExitCode> {
    let identity = load_identity()?;
    let fs = Arc::new(DiskBackend::new(dest));
    // Same format as the source, so that what the clone writes can be
    // pushed back and read by everyone who reads the source.
    let source_config = veil_core::repo::read_config(&*backend)?;
    source_config.check_supported()?;
    ctx::mark_clone_incomplete(&fs)?;
    let mut repo = Repo::init_for_clone_at(fs.clone(), Some(identity.clone()), &user_for(&identity), source_config.format)?;
    let mut config = repo.config().clone();
    config.remotes.insert("origin".into(), RemoteConfig { url, public: false, only: None });
    repo.save_config(config)?;
    let report = remote::pull(&mut repo, "origin", backend)?;
    for w in &report.warnings {
        warn_untrusted(w);
    }
    let target = ["main", "trunk", "master"]
        .iter()
        .find_map(|t| repo.view().tags.get(*t).map(|t| t.target))
        .or_else(|| repo.view().tags.values().next().map(|t| t.target))
        .unwrap_or(repo.root_id());
    let wc = repo.new_change(DEFAULT_WORKSPACE, vec![target], "")?;
    let to = repo.snapshot(&wc)?.tree;
    // Journalled (BUG-830). The record remembers what could not be
    // materialised (no key yet, an unreleased embargo), so it is filled in
    // once it becomes readable instead of being recorded as deleted.
    let (state, co) = repo.check_out_new(&*fs, DEFAULT_WORKSPACE, wc, None)?;
    ctx::mark_clone_complete(&fs)?;
    let hidden_by_embargo = state.materialised.view().is_some();
    println!(
        "Cloned {} into {} ({} objects, {} files)",
        safe(&shown),
        dest.display(),
        report.objects_copied,
        co.written
    );
    print_clone_redactions(&repo, &to, &co.redacted, &identity);
    if hidden_by_embargo {
        println!(
            "  {} an embargoed merge is not readable to you yet; you see its pre-merge content until it is released.",
            yellow("note:")
        );
    }
    Ok(ExitCode::SUCCESS)
}

/// After a clone: explain the cloaked files left out of the working copy
/// (`redacted`, paths in `tree`).
/// A team remote delivers them sealed (a grant and a pull make them
/// readable); a public remote never delivers them at all.
fn print_clone_redactions(repo: &Repo, tree: &veil_core::ObjectId, redacted: &[VPath], identity: &Identity) {
    use veil_core::object::Visibility;
    let (mut sealed, mut withheld) = (0, 0);
    let mut scopes = std::collections::BTreeSet::new();
    for p in redacted {
        // Embargoed content has a note of its own (below).
        let Ok(Some(e)) = lookup(repo.store(), tree, p) else {
            continue;
        };
        let Visibility::Cloaked { scope } = &e.visibility else {
            continue;
        };
        scopes.insert(safe(scope).into_owned());
        if repo.store().has(&e.id) {
            sealed += 1;
        } else {
            withheld += 1;
        }
    }
    let scopes: Vec<String> = scopes.into_iter().collect();
    let scope = scopes.first().cloned().unwrap_or_default();
    let named = format!(" (scope {})", scopes.iter().map(|s| format!("'{s}'")).collect::<Vec<_>>().join(", "));
    if sealed > 0 {
        println!(
            "  {} {sealed} cloaked file(s){named} you hold no key for. Share your public key ({}) with a member\n  and ask them to run `vl scope grant {scope} <key>` and push. They appear here on your next `vl pull` after that.",
            yellow("note:"),
            identity.public_id()
        );
    }
    if withheld > 0 {
        println!(
            "  {} {withheld} cloaked file(s){named} withheld: this is a public remote, and public remotes never deliver\n  cloaked content. To read them, ask a member to grant you (`vl scope grant {scope} <key>`; your key is in\n  `vl identity show`), then clone or pull from a team remote.",
            yellow("note:"),
        );
    }
}

fn cmd_identity(c: &IdentityCmd) -> Result<ExitCode> {
    match c {
        IdentityCmd::Show => {
            let id = load_identity()?;
            println!("name        {}", id.name);
            println!("device      {}", hub::fingerprint(&id.public_id()).unwrap_or_default());
            println!("public key  {}", id.public_id());
            println!("member id   {}", id.public_hex());
            println!("signing key {}", id.verifying_hex());
            if id.signing_key_is_derived() {
                println!("            (legacy: derived from the encryption key; `vl identity new` creates independent keys)");
            }
            println!("stored at   {}", ctx::identity_path().display());
            if let Some(line) = hub_keys::clone_here().as_ref().and_then(hub_keys::project_line) {
                println!("project     {line}");
            }
        }
        IdentityCmd::New { name, force } => {
            let path = ctx::identity_path();
            let previous = if path.exists() {
                if !force {
                    bail!("an identity already exists (use --force to replace it; you will lose access to scopes granted to it)");
                }
                warn_sole_admin_scopes();
                Some(retire_identity(&path)?)
            } else {
                None
            };
            let id = Identity::generate(&name.clone().unwrap_or_else(ctx::default_user_name));
            if previous.is_some() {
                ctx::write_identity(&id)?;
            } else if !ctx::create_identity(&id)? {
                // Another `vl` created one in the meantime (BUG-360).
                bail!("an identity already exists (use --force to replace it; you will lose access to scopes granted to it)");
            }
            println!("Created identity {} {}", id.name, id.public_id());
            if let Some((kept, old)) = previous {
                println!(
                    "The replaced identity was kept at {} (delete it once no vault needs it)",
                    kept.display()
                );
                // The vault key is derived from the identity: re-key the vault
                // of the repository we are in now, while the old one is at hand.
                if let (Some(old), Some(root)) = (old, std::env::current_dir().ok().and_then(|d| ctx::find_root(&d))) {
                    let repo = Repo::open(Arc::new(DiskBackend::new(&root)), Some(id.clone()), &user_for(&id))?;
                    if repo.vault_rekey(&old)? {
                        println!("Re-keyed the local vault of {}", root.display());
                    }
                }
                warn(
                    "other repositories' local vaults are still sealed by the replaced identity; run \
                     `vl identity recover-vault` in each. Scope admins must grant the new public key again; \
                     where you were an admin, `vl identity recover-admin` hands your admin rights over.",
                );
            }
        }
        IdentityCmd::Confirm { fingerprint, server } => hub_cmd::confirm_device(fingerprint, server.as_deref())?,
        IdentityCmd::Remove { fingerprint, server } => hub_keys::remove_device(fingerprint, server.as_deref())?,
        IdentityCmd::RecoverAdmin { from, revoke_old } => {
            use veil_core::keychain::AdminRecovery;
            let id = load_identity()?;
            let cwd = std::env::current_dir()?;
            let root = ctx::find_root(&cwd)
                .ok_or_else(|| anyhow!("no Veil repository found in {} or its parents", cwd.display()))?;
            let repo = Repo::open(Arc::new(DiskBackend::new(&root)), Some(id.clone()), &user_for(&id))?;
            let candidates: Vec<PathBuf> = match from {
                Some(f) => vec![f.clone()],
                None => retired_identities()?,
            };
            let mut handed = 0;
            let mut not_admin = Vec::new();
            let mut tried = 0;
            for path in &candidates {
                let Some(old) = std::fs::read_to_string(path)
                    .ok()
                    .and_then(|s| Identity::from_json(&s).ok())
                else {
                    continue;
                };
                if old.public_hex() == id.public_hex() {
                    continue;
                }
                tried += 1;
                for (scope, outcome) in repo.keys().recover_admin(&old, *revoke_old)? {
                    let scope = safe(&scope).to_string();
                    match outcome {
                        AdminRecovery::HandedOver { revoked } => {
                            handed += 1;
                            println!(
                                "Scope {scope}: {} granted you admin rights{}",
                                path.display(),
                                if revoked { "; it was then revoked (key rotated)" } else { "" }
                            );
                        }
                        AdminRecovery::AlreadyAdmin => println!("Scope {scope}: you are already an admin"),
                        AdminRecovery::RetiredNotAdmin => not_admin.push(scope),
                        AdminRecovery::Unverifiable => warn(&format!("scope {scope}: its key ring does not verify; left alone")),
                    }
                }
            }
            for scope in &not_admin {
                println!("Scope {scope}: the replaced identity was a member, not an admin; ask an admin to grant your new public key");
            }
            if handed > 0 {
                println!("Push to share the updated key rings.");
                if !revoke_old {
                    println!(
                        "The replaced identity is still a member; once no device uses it, run `vl identity recover-admin --revoke-old` \
                         (or `vl scope revoke <scope> <its member id>`)."
                    );
                }
            } else if tried == 0 {
                bail!(
                    "no replaced identity found{}",
                    if from.is_none() {
                        format!(" (looked in {}; pass --from <identity.json>)", retired_dir().display())
                    } else {
                        String::new()
                    }
                );
            }
        }
        IdentityCmd::RecoverVault { from } => {
            let id = load_identity()?;
            let cwd = std::env::current_dir()?;
            let root = ctx::find_root(&cwd)
                .ok_or_else(|| anyhow!("no Veil repository found in {} or its parents", cwd.display()))?;
            let repo = Repo::open(Arc::new(DiskBackend::new(&root)), Some(id.clone()), &user_for(&id))?;
            if !repo.vault_unreadable()? {
                println!("The local vault already opens with the current identity; nothing to do");
                return Ok(ExitCode::SUCCESS);
            }
            let candidates: Vec<PathBuf> = match from {
                Some(f) => vec![f.clone()],
                None => retired_identities()?,
            };
            for path in &candidates {
                let Some(old) = std::fs::read_to_string(path)
                    .ok()
                    .and_then(|s| Identity::from_json(&s).ok())
                else {
                    continue;
                };
                if repo.vault_rekey(&old)? {
                    println!("Re-keyed the local vault with the identity in {}", path.display());
                    return Ok(ExitCode::SUCCESS);
                }
            }
            bail!(
                "none of {} identity file(s) opens the local vault{}",
                candidates.len(),
                if from.is_none() {
                    format!(" (looked in {}; pass --from <identity.json>)", retired_dir().display())
                } else {
                    String::new()
                }
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Before `vl identity new --force`: in the repository we are in, name the
/// scopes whose only admin is the identity about to be replaced (BUG-089).
fn warn_sole_admin_scopes() {
    use veil_core::keychain::Role;
    let Ok(id) = load_identity() else { return };
    let Some(root) = std::env::current_dir().ok().and_then(|d| ctx::find_root(&d)) else { return };
    let Ok(repo) = Repo::open(Arc::new(DiskBackend::new(&root)), Some(id.clone()), &user_for(&id)) else { return };
    let mut sole = Vec::new();
    for ring in repo.keys().rings().unwrap_or_default() {
        let Ok(st) = ring.verify() else { continue };
        let admins: Vec<&String> = st.members.iter().filter(|(_, m)| m.role == Role::Admin).map(|(k, _)| k).collect();
        if admins == [&id.public_hex()] {
            sole.push(safe(&ring.scope).to_string());
        }
    }
    if !sole.is_empty() {
        warn(&format!(
            "you are the only admin of scope(s) {} in {}: the new identity will not be. Afterwards run \
             `vl identity recover-admin` here (the replaced identity, kept in {}, signs the hand-over), then push",
            sole.join(", "),
            root.display(),
            retired_dir().display()
        ));
    }
}

/// Where `vl identity new --force` keeps replaced identities.
fn retired_dir() -> PathBuf {
    ctx::veil_home().join("retired")
}

fn retired_identities() -> Result<Vec<PathBuf>> {
    let dir = retired_dir();
    if !dir.is_dir() {
        return Ok(vec![]);
    }
    let mut out: Vec<PathBuf> = std::fs::read_dir(&dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    out.sort();
    out.reverse(); // newest first
    Ok(out)
}

/// Copy the identity file at `path` into [`retired_dir`] (owner-only, never
/// world-readable, not even briefly) before it is replaced. Returns where it
/// went and the identity, if the file parses.
fn retire_identity(path: &Path) -> Result<(PathBuf, Option<Identity>)> {
    let raw = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let dir = retired_dir();
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let dest = dir.join(format!("identity-{}.json", now_millis()));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&dest).with_context(|| format!("creating {}", dest.display()))?;
    f.write_all(&raw)?;
    f.sync_all()?;
    let old = std::str::from_utf8(&raw).ok().and_then(|s| Identity::from_json(s).ok());
    Ok((dest, old))
}

// ---- inspection ----------------------------------------------------------

/// Tags a commit left at its parent, and how to move them on purpose.
fn print_tags_kept(repo: &Repo, r: &CommitResult) {
    let (cloaked, plain): (Vec<_>, Vec<_>) = r.kept.iter().partition(|(_, why)| matches!(why, TagKept::CloakedLine(_)));
    let names = |v: &[&(String, TagKept)]| v.iter().map(|(n, _)| safe(n).into_owned()).collect::<Vec<_>>().join(", ");
    let change = repo
        .snapshot(&r.committed)
        .map(|s| s.change_id.short())
        .unwrap_or_else(|_| r.committed.short());
    if let Some((_, TagKept::CloakedLine(scope))) = cloaked.first() {
        let first = safe(&cloaked[0].0).into_owned();
        eprintln!(
            "{} {} not moved: this is a line cloaked for '{}', and a commit there never moves an uncloaked tag (public remotes would receive it)",
            yellow("note:"),
            names(&cloaked),
            safe(scope)
        );
        eprintln!(
            "  {} publish the work with `vl merge {change} --into {first}` (add `--embargo` to keep it hidden until a release), or move the tag yourself: `vl tag set {first} -r {change}`",
            dim("hint:")
        );
    }
    let (release, plain): (Vec<_>, Vec<_>) = plain.into_iter().partition(|(_, why)| matches!(why, TagKept::Release));
    if !plain.is_empty() {
        eprintln!("{} {} not moved (--no-advance)", dim("note:"), names(&plain));
    }
    if !release.is_empty() {
        eprintln!("{} {} not moved (annotated release tags are immutable)", dim("note:"), names(&release));
    }
}

fn cmd_restore(ctx: &mut Ctx, paths: &[String], from: Option<&str>) -> Result<()> {
    let wc = ctx.repo.snapshot(&ctx.wc()?)?;
    let wc_tree = wc.tree;
    // By default, what `vl status` compares with: the parents of `@`,
    // merged for a merge (BUG-208).
    let (src_tree, shown, label) = match from {
        Some(rev) => {
            let src = ctx.rev(rev)?;
            // A revision an unreleased embargo keeps back (its fix, work on
            // it, its line) is restored only into a change inside that
            // embargo: elsewhere it would be an ordinary edit, published
            // before the release (BUG-681).
            let wc_id = ctx.wc()?;
            veil_core::confinement::Confinement::new(&ctx.repo)?.check_copy(&ctx.repo, "cannot restore from", &[src], &[wc_id])?;
            (ctx.repo.snapshot(&src)?.tree, one_line(&ctx.repo, &src), rev.to_string())
        }
        None => {
            let shown = match wc.parents.as_slice() {
                [p] => one_line(&ctx.repo, p),
                ps => format!("the {} merged parents of @", ps.len()),
            };
            (ctx.repo.parents_tree(&wc.parents)?.tree, shown, "@-".to_string())
        }
    };
    let filters: Vec<VPath> = paths.iter().map(|p| ctx.repo_path(p)).collect::<Result<_>>()?;
    let wanted = |p: &VPath| filters.is_empty() || filters.iter().any(|f| p.starts_with(f));
    let policy_path = VPath::new(POLICY_FILE)?;
    let changes = veil_core::tree::diff_trees(ctx.repo.store(), Some(&wc_tree), Some(&src_tree))?;
    let mut done: std::collections::HashSet<VPath> = changes.iter().filter(|c| wanted(&c.path)).map(|c| c.path.clone()).collect();
    // A version put back keeps its audience: a sealed version, or a
    // conflict, is recorded as the entry it was written from, never as a
    // public edit of `@`'s (BUG-481). A sealed version this reader cannot
    // read is not put back at all (its last public version is not it).
    let mut unreadable: Vec<VPath> = Vec::new();
    let mut moves_audience = false;
    for c in changes.iter().filter(|c| wanted(&c.path)) {
        let Some(e) = &c.new else { continue };
        if e.kind.holds_blob() && !ctx.repo.store().entry_readable(e) {
            unreadable.push(c.path.clone());
        } else if restored_as_recorded(&ctx.repo, e)? {
            let same = c.old.as_ref().is_some_and(|o| o.kind.holds_blob() && o.kind == e.kind && o.visibility == e.visibility);
            moves_audience |= !same;
        }
    }
    // Under an unreleased embargo, the working copy's tree is the
    // embargo's; a version with another audience cannot be put into it as
    // it is, and taking it in as an edit would seal it under the embargo
    // (whose release publishes it).
    let embargoed = veil_core::embargo::unreleased_wrapper(ctx.repo.store(), &wc_tree)?.is_some();
    if embargoed && moves_audience {
        bail!(
            "the working copy is under an unreleased embargo: restoring a version sealed for another audience, or a conflict, into it would put that version under the embargo's key (its release would publish it); restore it into a change outside the embargo"
        );
    }
    for p in &unreadable {
        eprintln!("  {} {} (unreadable here; not restored)", render::yellow("redacted"), safe(p.as_str()));
    }
    let wanted = |p: &VPath| wanted(p) && !unreadable.contains(p);
    // Removals before writes, nothing in the way deleted, emptied
    // directories removed: checkout's rules (BUG-201, BUG-209).
    let r = ctx.restore(&wc_tree, &src_tree, &wanted)?;
    let skipped: usize =
        r.kept_local.len() + r.blocked.len() + r.obstructed.len() + r.nested.len() + r.failed.len() + r.redacted.len() + unreadable.len();
    let not_written = |p: &VPath| {
        r.kept_local.contains(p)
            || r.blocked.contains(p)
            || r.redacted.contains(p)
            || r.protected.contains(p)
            || r.obstructed.iter().any(|(o, _)| p.starts_with(o))
            || r.nested.iter().any(|(o, _)| p.starts_with(o))
            || r.failed.iter().any(|(o, _)| p.starts_with(o))
    };
    let mut carried: Vec<(VPath, veil_core::TreeEntry)> = Vec::new();
    for c in changes.iter().filter(|c| !embargoed && wanted(&c.path) && !not_written(&c.path)) {
        if let Some(e) = c.new.as_ref().filter(|e| e.kind.is_file_like() || e.kind.is_special()) {
            if restored_as_recorded(&ctx.repo, e)? {
                carried.push((c.path.clone(), with_fallback_of(e, c.old.as_ref())));
            }
        }
    }
    let mut n = done.len().saturating_sub(skipped);
    // A quarantined edit is not in the working-copy tree (it keeps the
    // previous version), so the diff above cannot see it: restore it too.
    for p in ctx.report.quarantine_kept.clone() {
        if done.contains(&p) || !wanted(&p) {
            continue;
        }
        done.insert(p.clone());
        if behind_special(&*ctx.fs, &p)? {
            skipped_special(&p);
            continue;
        }
        let mut carry = None;
        let res = match veil_core::tree::lookup(ctx.repo.store(), &src_tree, &p)? {
            Some(e) if e.kind.is_file_like() => {
                let data = read_file(&ctx.repo, &p, &e)?;
                if !embargoed && restored_as_recorded(&ctx.repo, &e)? {
                    let was = veil_core::tree::lookup(ctx.repo.store(), &wc_tree, &p)?;
                    carry = Some((p.clone(), with_fallback_of(&e, was.as_ref())));
                }
                let exec = match e.kind {
                    veil_core::EntryKind::Conflict => {
                        veil_core::conflict::materialize_entry(ctx.repo.store(), &e, veil_core::conflict::Audience::Reader)?.executable
                    }
                    _ => e.executable,
                };
                ctx.fs.write(&p, &data).and_then(|_| ctx.fs.set_executable(&p, exec))
            }
            // A quarantined link (a token in its target) put back.
            Some(e) if e.kind == veil_core::EntryKind::Symlink => {
                let target = read_file(&ctx.repo, &p, &e)?;
                if !embargoed && restored_as_recorded(&ctx.repo, &e)? {
                    let was = veil_core::tree::lookup(ctx.repo.store(), &wc_tree, &p)?;
                    carry = Some((p.clone(), with_fallback_of(&e, was.as_ref())));
                }
                ctx.fs.write_link(&p, &target)
            }
            _ => ctx.fs.remove_file(&p),
        };
        match res {
            Ok(()) => {
                n += 1;
                carried.extend(carry);
            }
            Err(veil_core::VeilError::Io { source, .. }) => ctx::print_failed(&[(p.clone(), source.to_string())]),
            Err(e) => return Err(e.into()),
        }
    }
    // A command of its own (not an automatic snapshot), so `vl undo` brings
    // the discarded edits back.
    let what = if paths.is_empty() { "everything".to_string() } else { paths.join(" ") };
    let description = format!("restore {what} from {label}");
    // A `.veilpolicy` put back from REV arrived from REV, not from the
    // member's hand: it goes through the accepted policy like a pulled one.
    // (`done` holds every path restore wrote or removed, or skipped.)
    ctx.snapshot_restored(description, done.contains(&policy_path), &carried)?;
    println!("Restored {n} path(s) from {shown}");
    Ok(())
}

/// Sealed version `e` put back over `was`: what readers without its key
/// see stays what they saw at that path (`was`'s public version, as the
/// builder carries it for a sealed edit), not the fallback `e` had where
/// it came from. A conflict is put back as it is.
fn with_fallback_of(e: &veil_core::TreeEntry, was: Option<&veil_core::TreeEntry>) -> veil_core::TreeEntry {
    if !matches!(e.kind, veil_core::EntryKind::File | veil_core::EntryKind::Symlink) {
        return e.clone();
    }
    let fallback = match was.filter(|w| w.kind == e.kind) {
        Some(w) if w.visibility.is_public() && w.fallback.is_none() => Some(w.id),
        Some(w) if w.visibility == e.visibility => w.fallback,
        _ => None,
    };
    veil_core::TreeEntry { fallback, ..e.clone() }
}

/// Is version `e`, put back by `vl restore`, recorded as it is (rather
/// than judged as an edit of the working copy's file)? A conflict always
/// is (it is put back as the same conflict); a file whose content is
/// sealed (cloaked, or under an embargo) is, so that it keeps its
/// audience. A plaintext file is an ordinary edit: the policy and the
/// working copy's line decide its sealing, and it may only end up
/// narrower. Labels are claims: a file labelled sealed whose object is
/// plaintext is plaintext (`verify_sealing`).
fn restored_as_recorded(repo: &veil_core::repo::Repo, e: &veil_core::TreeEntry) -> Result<bool> {
    use veil_core::builder::{verify_sealing, Sealing};
    Ok(match e.kind {
        veil_core::EntryKind::Conflict => true,
        // A symlink's target is content too.
        veil_core::EntryKind::File | veil_core::EntryKind::Symlink => match verify_sealing(repo.store(), e)? {
            Sealing::Relabelled(actual) => !actual.is_public(),
            _ => !e.visibility.is_public(),
        },
        veil_core::EntryKind::Dir => false,
    })
}

fn skipped_special(p: &VPath) {
    warn_untrusted(&format!("skipped {p}: a symlink or special file is in the way; Veil never writes through or over it"));
}

/// The furthest an embargo deadline may lie in the future.
const MAX_DEADLINE_MS: i64 = 100 * 366 * 86_400_000;

fn parse_time(s: &str) -> Result<i64> {
    parse_time_at(s, now_millis())
}

/// Parse an embargo deadline (`+7d`, RFC 3339 or `YYYY-MM-DD`) relative to
/// `now`. Deadlines in the past or more than a century ahead are rejected:
/// either would be a typo, and a past deadline releases the embargo at once.
fn parse_time_at(s: &str, now: i64) -> Result<i64> {
    use chrono::{Local, NaiveDate};
    let t = if let Some(rest) = s.strip_prefix('+') {
        let (num, unit) = rest.split_at(rest.len().saturating_sub(1));
        let mult: i64 = match unit {
            "s" => 1_000,
            "m" => 60_000,
            "h" => 3_600_000,
            "d" => 86_400_000,
            "w" => 7 * 86_400_000,
            _ => bail!("bad duration unit in '{s}' (use s, m, h, d or w)"),
        };
        if num.is_empty() || !num.bytes().all(|b| b.is_ascii_digit()) {
            bail!("bad duration '{s}' (expected a whole number such as +7d)");
        }
        let too_far = || anyhow!("duration '{s}' is too far in the future (at most 100 years)");
        let n: i64 = num.parse().map_err(|_| too_far())?;
        let ms = n.checked_mul(mult).filter(|ms| *ms <= MAX_DEADLINE_MS).ok_or_else(too_far)?;
        now.checked_add(ms).ok_or_else(too_far)?
    } else if let Ok(t) = chrono::DateTime::parse_from_rfc3339(s) {
        t.timestamp_millis()
    } else if let Some(t) = NaiveDate::parse_from_str(s, "%Y-%m-%d")
        .ok()
        .and_then(|d| d.and_hms_opt(0, 0, 0))
        .and_then(|t| t.and_local_timezone(Local).single())
    {
        t.timestamp_millis()
    } else {
        bail!("cannot parse time '{s}' (use RFC 3339, YYYY-MM-DD or +7d/+12h/+30m)")
    };
    if t <= now {
        bail!(
            "'{s}' is in the past; an embargo deadline must be in the future \
             (use `vl embargo release` to publish now)"
        );
    }
    if t - now > MAX_DEADLINE_MS {
        bail!("'{s}' is too far in the future (at most 100 years)");
    }
    Ok(t)
}

fn cmd_merge(
    ctx: &mut Ctx,
    revs: &[String],
    into: Option<&str>,
    message: Option<&str>,
    embargo: bool,
    until: Option<&str>,
    scope: &str,
) -> Result<()> {
    let into = match into {
        Some(r) => ctx.rev(r)?,
        None => {
            let wc = ctx.wc()?;
            if ctx.repo.is_empty_change(&wc)? {
                ctx.rev("@-")?
            } else {
                wc
            }
        }
    };
    let others = revs.iter().map(|r| ctx.rev(r)).collect::<Result<Vec<_>>>()?;
    let deadline = until.map(parse_time).transpose()?;
    let spec = if embargo || until.is_some() {
        Some(EmbargoSpec {
            scope: scope.to_string(),
            until: deadline,
        })
    } else {
        None
    };
    let message = match message {
        Some(m) => m.to_string(),
        None => format!("merge {}", revs.join(", ")),
    };
    let ws = ctx.ws.clone();
    let res = ctx.repo.merge(&ws, into, others, &message, spec)?;
    println!("Merged {}", one_line(&ctx.repo, &res.snapshot));
    if let Some(e) = &res.embargo {
        println!(
            "  {} {e}: changed files are sealed for scope '{scope}'; everyone else sees the pre-merge content {}.",
            yellow("embargo"),
            match deadline {
                Some(t) => format!("until {}, or an earlier `vl embargo release {e}`", fmt_deadline(t)),
                None => format!("until `vl embargo release {e}`"),
            }
        );
    }
    // A file of the merged-in cloaked line is public now, or (under an
    // embargo, this merge's or the destination's) once that is released.
    let merged = ctx.repo.snapshot(&res.snapshot)?.tree;
    let (mut published, mut on_release) = (Vec::new(), Vec::new());
    for p in &res.declassified {
        let visibility = match VPath::new(p) {
            Ok(vp) => lookup(ctx.repo.store(), &merged, &vp)?.map(|e| e.visibility),
            Err(_) => None,
        };
        match visibility {
            Some(veil_core::object::Visibility::Embargoed { .. }) => on_release.push(p.as_str()),
            _ => published.push(p.as_str()),
        }
    }
    if !published.is_empty() {
        println!(
            "  {} (secret-scanned): {}",
            yellow("published from the cloaked line"),
            safe(&published.join(", "))
        );
    }
    if !on_release.is_empty() {
        println!(
            "  {} (from the cloaked line; secret-scanned): {}",
            yellow("public on release"),
            safe(&on_release.join(", "))
        );
    }
    if !res.quarantined.is_empty() {
        warn_untrusted(&format!(
            "quarantined, left out of the merge (they hold secrets): {}",
            res.quarantined.join(", ")
        ));
    }
    rewrite_cmd::print_renames(&res.renames);
    // Warnings quote paths from the merged trees: escaped (BUG-680).
    for w in &res.warnings {
        warn_untrusted(w);
    }
    if !res.conflicts.is_empty() {
        warn_untrusted(&format!("conflicts in: {}", res.conflicts.join(", ")));
    }
    Ok(())
}

fn cmd_embargo(ctx: &mut Ctx, c: &EmbargoCmd) -> Result<()> {
    match c {
        EmbargoCmd::List => {
            let list = ctx.repo.keys().embargoes()?;
            if list.is_empty() {
                println!("No embargoes.");
            }
            for r in list {
                let pending = || match r.until {
                    Some(u) => yellow(&format!("until {}", fmt_deadline(u))),
                    None => yellow("manual release"),
                };
                let state = match ctx.repo.keys().release_state(&r.id) {
                    ReleaseState::Released => green("released"),
                    ReleaseState::Staged => format!(
                        "{} {}",
                        green("released"),
                        yellow("(not pushed yet: `vl undo` takes it back)")
                    ),
                    ReleaseState::Rejected(why) => format!("{} {}", pending(), red(&format!("(release ignored: {})", safe(&why)))),
                    ReleaseState::Unreleased => pending(),
                };
                let key = if ctx.repo.keys().has(&format!("embargo/{}", r.id)) {
                    ""
                } else {
                    " (no key)"
                };
                // Records carry no description; one written by an early
                // version is still shown.
                let desc = match first_line(&r.description) {
                    d if d.trim().is_empty() => String::new(),
                    d => format!("  {d}"),
                };
                println!("{}  scope:{}  {state}{key}{desc}", bold(&safe(&r.id)), safe(&r.scope));
            }
        }
        EmbargoCmd::Release { id, yes } => cmd_embargo_release(ctx, id, *yes)?,
    }
    Ok(())
}

/// `vl embargo release`: a previewed, confirmed release (BUG-109). The
/// release is staged in this repository; the next push publishes the key, and until then `vl undo` takes it back.
fn cmd_embargo_release(ctx: &mut Ctx, id: &str, yes: bool) -> Result<()> {
    let keys = ctx.repo.keys();
    let Some(rec) = keys.load_embargo(id)? else {
        bail!("no embargo '{}' (see `vl embargo list`)", safe(id));
    };
    match keys.release_state(id) {
        ReleaseState::Released => {
            println!("Embargo {} is already released.", safe(id));
            return Ok(());
        }
        ReleaseState::Staged => {
            println!("Embargo {} is already released here; your next push publishes it (`vl undo` right after the release takes it back).", safe(id));
            return Ok(());
        }
        ReleaseState::Unreleased | ReleaseState::Rejected(_) => {}
    }
    // What becomes public.
    println!(
        "Releasing embargo {} (scope {}) publishes its key: everyone who receives your next push can read the fix.",
        bold(&safe(id)),
        safe(&rec.scope)
    );
    let mut merges = Vec::new();
    let mut tags = Vec::new();
    for sid in ctx.repo.visible_snapshots()? {
        let s = ctx.repo.snapshot(&sid)?;
        if s.embargo.as_deref() == Some(id) {
            merges.push((sid, first_line(&ctx.repo.description(&s)).to_string()));
        }
    }
    for (name, t) in &ctx.repo.view().tags {
        if ctx.repo.carried_embargo(&t.target)?.as_deref() == Some(id) {
            tags.push(safe(name).into_owned());
        }
    }
    for (sid, d) in &merges {
        println!("  {} {} {}", yellow("merge"), blue(&sid.short()), safe(d));
    }
    let history = remote::withheld_by_embargo(&ctx.repo, id)?;
    if !history.is_empty() {
        println!("  {} snapshot(s) of the fix's history, withheld until now:", history.len());
        for sid in history.iter().take(10) {
            let d = ctx.repo.snapshot(sid).map(|s| first_line(&ctx.repo.description(&s)).to_string()).unwrap_or_default();
            let d = if d.trim().is_empty() { dim("(no description set)") } else { safe(&d).into_owned() };
            println!("    {} {d}", blue(&sid.short()));
        }
        if history.len() > 10 {
            println!("    … and {} more", history.len() - 10);
        }
    }
    if !tags.is_empty() {
        println!("  on: {}", cyan(&tags.join(", ")));
    }
    let remotes: Vec<String> = ctx
        .repo
        .config()
        .remotes
        .iter()
        .map(|(n, r)| if r.public { format!("{} (public)", safe(n)) } else { safe(n).into_owned() })
        .collect();
    if remotes.is_empty() {
        println!("  No remote is configured yet; the first push publishes it.");
    } else {
        println!("  Your next push to any remote publishes it (remotes: {}).", remotes.join(", "));
    }
    println!("  Until you push, `vl undo` takes the release back. After that it cannot be undone.");
    if !yes {
        if !std::io::stdin().is_terminal() {
            bail!("not released: confirm with `vl embargo release {} --yes`", safe(id));
        }
        eprint!("Release embargo {}? [y/N] ", safe(id));
        std::io::stderr().flush().ok();
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            println!("Not released.");
            return Ok(());
        }
    }
    ctx.repo.release_embargo(id)?;
    println!(
        "Released embargo {} in this repository. Your next push publishes the key; until then `vl undo` takes it back.",
        safe(id)
    );
    Ok(())
}

fn cmd_tag(ctx: &mut Ctx, c: &TagCmd) -> Result<()> {
    match c {
        TagCmd::List { out } => match out.json {
            true => api::emit_json(&api::tag_list(&ctx.repo))?,
            false => api::text::tag_list(&api::tag_list(&ctx.repo)),
        },
        TagCmd::Set {
            name,
            rev,
            cloak,
            allow_backwards,
            annotate,
            message,
            force,
        } => {
            let id = ctx.rev(rev)?;
            let spec = veil_core::commands::TagSpec {
                cloak: cloak.clone(),
                allow_backwards: *allow_backwards,
                annotate: (*annotate || message.is_some()).then(|| message.clone().unwrap_or_default()),
                force: *force,
            };
            let out = ctx.repo.set_tag_with(name, id, &spec)?;
            match out.annotation {
                Some(_) if out.unchanged => println!("Release tag {} already → {}", cyan(name), one_line(&ctx.repo, &id)),
                Some(_) => println!(
                    "Release tag {} → {} ({})",
                    cyan(name),
                    one_line(&ctx.repo, &id),
                    if out.signed { "signed" } else { "unsigned: no identity" }
                ),
                None => println!("Tag {} → {}", cyan(name), one_line(&ctx.repo, &id)),
            }
            if out.replaced.is_some() {
                eprintln!("{} replaced release tag {name}", dim("note:"));
            }
        }
        TagCmd::Verify { name } => {
            let Some(c) = ctx.repo.tag_annotation(name)? else {
                bail!("tag '{name}' is a plain tag, not an annotated release tag: there is nothing to verify");
            };
            let target = ctx.repo.view().tags[name.as_str()].target;
            println!("{} {} → {}", bold("tag"), cyan(&safe(name)), one_line(&ctx.repo, &target));
            let kind = match c.atag.kind {
                veil_core::tag_object::AtagKind::Annotated => "annotated",
            };
            println!("{}   {kind}", dim("kind:"));
            if !c.atag.tagger.is_empty() {
                println!("{} {} {}", dim("tagger:"), safe(&c.atag.tagger), dim(&fmt_time(c.atag.timestamp)));
            }
            match &c.message {
                Some(m) if !m.is_empty() => {
                    for l in m.lines() {
                        println!("    {}", safe(l));
                    }
                }
                Some(_) => {}
                None => println!("    {}", dim("(message sealed)")),
            }
            match (&c.signer, c.verified) {
                (Some(who), true) => println!("{} good signature by {}", green("verified:"), safe(who)),
                _ => {
                    let why = match c.verification {
                        veil_core::tag_object::AtagVerification::Signed { .. } => "signed by a key no ring of this repository knows".to_string(),
                        ref v => v.describe(),
                    };
                    bail!("tag '{name}' is not verified: {why}");
                }
            }
        }
        TagCmd::Delete { name } => {
            ctx.repo.delete_tag(name)?;
            println!("Deleted tag {name}");
        }
    }
    Ok(())
}

// ---- visibility ----------------------------------------------------------

/// The `.veilpolicy` pattern for a command-line argument, and whether it
/// was taken literally. An argument naming an existing path matches exactly
/// that path, even if the name contains glob characters (`config[prod].yml`,
/// Next.js `app/[id]/`); anything else is a glob. Whitespace and `#` are
/// always escaped so the rule stays one field.
fn rule_pattern(ctx: &Ctx, arg: &str) -> (String, bool) {
    let arg = arg.trim();
    if has_glob_syntax(arg) && !arg.contains('\\') {
        let lead = if arg.starts_with('/') { "/" } else { "" };
        let core = arg.trim_start_matches('/');
        let trail = if core.ends_with('/') { "/" } else { "" };
        let core = core.trim_end_matches('/');
        let exists_at = |vp: Option<VPath>| vp.and_then(|vp| ctx.fs.metadata(&vp).ok().flatten()).is_some();
        // Patterns are relative to the root; a bare name matches at any
        // depth, so also look for it below the current directory.
        let exists = exists_at(VPath::new(core).ok())
            || (lead.is_empty() && !core.contains('/') && exists_at(ctx.repo_path(core).ok()));
        if exists {
            return (format!("{lead}{}{trail}", escape_literal(core)), true);
        }
        if arg.contains(['[', ']', '{', '}']) {
            warn_untrusted(&format!(
                "'{arg}' is not an existing path, so it is a glob pattern; to match a file with this literal name, escape the characters with '\\' (e.g. {})",
                escape_literal(arg)
            ));
        }
    }
    (escape_field(arg), false)
}

/// Why `vl cloak --scope <scope>` cannot seal for `scope`, and what to do:
/// create the scope if it does not exist; otherwise ask one of its admins
/// for a grant (with this member's public key).
fn not_a_member(ctx: &Ctx, scope: &str) -> Result<String> {
    use veil_core::keychain::Role;
    let keys = ctx.repo.keys();
    let Some(ring) = keys.load_ring(scope)? else {
        return Ok(format!(
            "there is no scope '{scope}' in this repository yet: create it with `vl scope create {scope}` \
             (or `vl pull` first if a teammate created it)"
        ));
    };
    let me = keys.identity().map(|i| i.public_id()).unwrap_or_default();
    let admins: Vec<String> = match ring.verify() {
        Ok(state) => state
            .members
            .values()
            .filter(|m| m.role == Role::Admin)
            .map(|m| safe(&m.name).into_owned())
            .collect(),
        Err(_) => Vec::new(),
    };
    let who = match admins.as_slice() {
        [] => "an admin of the scope".to_string(),
        names => format!("an admin of the scope ({})", names.join(", ")),
    };
    let lost = if keys.has(scope) { " Your access was revoked." } else { "" };
    Ok(format!(
        "you are not a member of scope '{scope}', so you cannot cloak files for it.{lost} Ask {who} to grant you \
         access (`vl scope grant {scope} <your key> --name <your name>`, then `vl push`), then `vl pull` and run \
         this again. Your public key: {me}"
    ))
}

fn cmd_policy_rules(ctx: &mut Ctx, patterns: &[String], tier: Tier, force: bool) -> Result<()> {
    use veil_core::policy::{read_policy_file, PolicyFile};
    let path = VPath::new(POLICY_FILE)?;
    let mut text = match read_policy_file(&*ctx.fs)? {
        PolicyFile::File(b) => String::from_utf8_lossy(&b).into_owned(),
        // Writing would replace the link (and its rules) with a new file.
        PolicyFile::Linked(_) => bail!(
            "{POLICY_FILE} is a symlink; Veil reads its rules but never writes through or over it. Add the rule to \
             the file it leads to, or replace the link with a copy"
        ),
        PolicyFile::Unavailable(why) => bail!("cannot read {POLICY_FILE} ({why}); fix it first"),
        // Missing: start from the recorded version, so that adding one rule
        // does not drop every other.
        PolicyFile::Absent => {
            // The working copy's snapshot has recorded the deletion already.
            let wc = ctx.repo.snapshot(&ctx.wc()?)?;
            let recorded = match lookup(ctx.repo.store(), &wc.tree, &path)? {
                Some(e) => Some(e),
                None => lookup(ctx.repo.store(), &ctx.repo.parents_tree(&wc.parents)?.tree, &path)?,
            };
            match recorded {
                Some(e) => {
                    let b = read_file(&ctx.repo, &path, &e)?;
                    eprintln!("{} {POLICY_FILE} was missing; restored the recorded version", dim("note:"));
                    String::from_utf8_lossy(&b).into_owned()
                }
                None => DEFAULT_POLICY.to_string(),
            }
        }
    };
    if !text.ends_with('\n') {
        text.push('\n');
    }
    // Files already recorded in plaintext history before this rule.
    let parent_tree = {
        let wc = ctx.repo.snapshot(&ctx.wc()?)?;
        ctx.repo.parents_tree(&wc.parents)?.tree
    };
    let history = tree_paths(&ctx.repo, &parent_tree)?;
    for p in patterns {
        let (pattern, literal) = rule_pattern(ctx, p);
        let line = format_rule(&pattern, &tier, force);
        text.push_str(&line);
        text.push('\n');
        let note = if literal { dim("  (literal path: glob characters escaped)") } else { String::new() };
        println!("Added rule  {}{note}", bold(line.trim()));
        if matches!(tier, Tier::Cloaked(_) | Tier::Isolated) {
            let single = Policy::parse(&line);
            let exposed: Vec<&VPath> = history
                .iter()
                .filter(|(path, vis)| {
                    vis.is_public()
                        && single.rules().last().is_some_and(|r| r.matches(path, false))
                })
                .map(|(p, _)| p)
                .collect();
            if !exposed.is_empty() {
                warn_untrusted(&format!(
                    "{} matching file(s) already exist in plaintext in earlier snapshots (e.g. {}). New snapshots are protected; rotate any secrets they contain.",
                    exposed.len(),
                    exposed[0]
                ));
            }
        }
    }
    ctx.fs.write(&path, text.as_bytes())?;
    // A command of its own (not an automatic snapshot), so `vl undo` reverts it.
    let verb = match &tier {
        Tier::Public => "expose",
        Tier::Cloaked(_) => "cloak",
        Tier::Isolated => "isolate",
        Tier::Ignored => "ignore",
    };
    ctx.snapshot_as(format!("{verb} {}", patterns.join(" ")))?;
    Ok(())
}

/// The edit of `.veilpolicy` a command made in virtual workspace `ws` that
/// its recordings hold back (BUG-560): the `.veilpolicy` its mount's
/// overlay or its `vl ws exec` sandbox holds, where that differs from the
/// workspace's recorded one.
fn held_policy_edit(ctx: &Ctx, ws: &str) -> Result<Vec<u8>> {
    let wc = ctx.repo.workspace_wc(ws)?;
    let tree = ctx.repo.snapshot(&wc)?.tree;
    let recorded = match lookup(ctx.repo.store(), &tree, &VPath::new(POLICY_FILE)?)? {
        Some(e) => Some(ctx.repo.store().read_entry(&e)?),
        None => None,
    };
    let places = [
        ("its mount", mount::Paths::new(&ctx.root, ws).upper),
        ("its sandbox", veil_core::sandbox::SandboxPaths::new(&ctx.root, ws).files),
    ];
    let mut found: Vec<(&str, Vec<u8>)> = Vec::new();
    for (place, dir) in places {
        let path = dir.join(POLICY_FILE);
        // A regular file only, never through a symlink.
        if !std::fs::symlink_metadata(&path).is_ok_and(|m| m.is_file()) {
            continue;
        }
        let data = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        if recorded.as_ref() != Some(&data) && !found.iter().any(|(_, d)| *d == data) {
            found.push((place, data));
        }
    }
    match found.len() {
        0 => bail!(
            "nothing to accept: neither the sandbox nor the mount of workspace '{}' holds a {POLICY_FILE} that differs \
             from the recorded one",
            safe(ws)
        ),
        1 => Ok(found.remove(0).1),
        _ => bail!(
            "{} and {} of workspace '{}' hold different edits of {POLICY_FILE}; make them agree (or remove one) first",
            found[0].0,
            found[1].0,
            safe(ws)
        ),
    }
}

fn cmd_policy(ctx: &mut Ctx, c: &PolicyCmd) -> Result<()> {
    // What snapshots apply: `.veilpolicy`, guarded by the accepted policy.
    let policy = ctx.repo.effective_policy(&*ctx.fs)?;
    match c {
        PolicyCmd::Show => {
            for name in veil_core::policy::BUILTIN_VCS_DIRS {
                let what = if *name == ".git" { "dirs and files, any depth" } else { "dirs, any depth" };
                println!("{:<12}  {}  {}", dim("built-in"), format_rule(name, &Tier::Ignored, false), dim(&format!("({what})")));
            }
            for pattern in veil_core::policy::SCRATCH_PATTERNS {
                println!("{:<12}  {}  {}", dim("built-in"), format_rule(pattern, &Tier::Ignored, false), dim("(editor scratch files)"));
            }
            println!(
                "{:<12}  {}",
                dim("built-in"),
                dim("editor and backup artefacts of an isolated, cloaked or ignored file (.x.swp, x~, x.bak, …) take its protection")
            );
            for r in policy.rules() {
                let origin = if r.builtin { dim("built-in") } else { cyan(".veilpolicy") };
                println!("{origin:<12}  {}", r.to_line());
            }
            for w in &policy.warnings {
                warn(w);
            }
            let held = ctx.repo.policy_held_back(&*ctx.fs)?;
            if !held.is_empty() {
                println!();
                println!(
                    "{} (they keep the protection you accepted on this device):",
                    bold("Not yet accepted: .veilpolicy would weaken the protection of local files")
                );
                for h in &held {
                    println!("  {}: {} → {}", safe(&h.shown_path()), h.accepted, yellow(&h.wanted));
                }
                println!("Run `vl policy accept` to apply .veilpolicy in full.");
            }
        }
        PolicyCmd::Accept { workspace: Some(ws) } => {
            if *ws == ctx.ws {
                bail!("workspace '{}' is attached to the project directory: run `vl policy accept` there", safe(ws));
            }
            let text = held_policy_edit(ctx, ws)?;
            let (out, held) = ctx.repo.accept_workspace_policy(ws, &text)?;
            print_build_warnings(&out.report);
            if held.is_empty() {
                println!("Recorded the edit of {POLICY_FILE} in workspace '{}'; it weakens the protection of no file", safe(ws));
            } else {
                println!(
                    "Recorded the edit of {POLICY_FILE} in workspace '{}'. Protection weakened for {} path(s):",
                    safe(ws),
                    held.len()
                );
                for h in &held {
                    println!("  {}: {} → {}", safe(&h.shown_path()), h.accepted, yellow(&h.wanted));
                }
            }
            if out.changed {
                println!("Recorded {}", one_line(&ctx.repo, &out.snapshot));
            }
        }
        PolicyCmd::Accept { workspace: None } => {
            let held = ctx.repo.accept_policy(&*ctx.fs)?;
            ctx.repo.record_outside_view(
                format!("accept {POLICY_FILE}"),
                format!(
                    "the accepted policy is device-local state outside the operation log; edit {POLICY_FILE} back \
                     and run `vl policy accept` again"
                ),
            )?;
            if held.is_empty() {
                println!("Accepted {POLICY_FILE}; it weakens the protection of no local file");
            } else {
                println!("Accepted {POLICY_FILE}. Protection weakened for {} local file(s):", held.len());
                for h in &held {
                    println!("  {}: {} → {}", safe(&h.shown_path()), h.accepted, yellow(&h.wanted));
                }
            }
            ctx.snapshot()?;
        }
        PolicyCmd::Check { paths } => {
            for p in paths {
                let vp = ctx.repo_path(p)?;
                // As a snapshot walks: it never looks inside an ignored
                // directory (Git's rule), so no later rule re-includes a
                // file below one, nor inside a nested repository (BUG-203).
                let mut skipped = None;
                for a in vp.ancestors() {
                    let c = policy.classify(&a, true);
                    if c.tier == Tier::Ignored {
                        let via = c.rule.map(|r| format!("rule '{r}'")).unwrap_or_else(|| "default".into());
                        skipped = Some(format!(
                            "{} via {via} (on its directory {}/: a snapshot never looks inside it, so no later rule can \
                             re-include a file below it)",
                            bold(&c.tier.label()),
                            safe(a.as_str())
                        ));
                        break;
                    }
                    if veil_core::vfs::is_nested_repository(&*ctx.fs, &a)? {
                        skipped = Some(format!(
                            "{}: {}/ is a Veil repository of its own, which this one never records",
                            bold("not recorded"),
                            safe(a.as_str())
                        ));
                        break;
                    }
                }
                if let Some(why) = skipped {
                    println!("{}: {why}", safe(vp.as_str()));
                    continue;
                }
                let is_dir = ctx.fs.metadata(&vp)?.is_some_and(|m| m.kind == NodeKind::Dir);
                let c = policy.classify(&vp, is_dir);
                let why = match (&c.rule, c.builtin_secret) {
                    (Some(r), true) => format!("built-in secret rule '{r}'"),
                    (Some(r), false) if c.builtin_vcs => format!("built-in VCS metadata rule '{r}'"),
                    (Some(r), false) if c.builtin_artefact && c.artefact_of.is_none() => {
                        format!("built-in editor scratch rule '{r}'")
                    }
                    (Some(r), false) => format!("rule '{r}'"),
                    (None, _) => "default".into(),
                };
                let mut extra = String::new();
                if let Some(base) = &c.artefact_of {
                    extra.push_str(&format!(" (an editor or backup artefact of {}, so it has that file's protection)", safe(base.as_str())));
                }
                if c.blocked_exposure {
                    extra.push_str(" (a `public` rule was ignored: use `public!`)");
                }
                if c.allow_secrets {
                    extra.push_str(" (secret scanning disabled)");
                }
                if let Some((tier, force)) = &c.held_back {
                    extra.push_str(&format!(
                        " (accepted on this device; {POLICY_FILE} says '{}', not yet accepted: `vl policy accept`)",
                        veil_core::policy::tier_keyword(tier, *force)
                    ));
                }
                println!("{vp}: {} via {why}{extra}", bold(&c.tier.label()));
            }
        }
    }
    Ok(())
}

/// `vl scan` exits 1 when a public file contains a secret.
fn scan_status(scan: &api::Scan) -> ExitCode {
    match scan.clean {
        true => ExitCode::SUCCESS,
        false => ExitCode::from(1),
    }
}

/// `vl scan --policy-from FILE`: the CI gate. It bypasses `Ctx::open` (no
/// identity, no snapshot, no repository needed) and takes nothing from the
/// scanned directory but its files: the rules come from FILE, a policy the
/// pull request cannot edit. A CI checkout publishes every file whatever a
/// `.veilpolicy` says, so only FILE's `public!` paths are
/// exempt; isolated, cloaked and ignored paths are scanned too, and only
/// VCS metadata (`.git`, …) and `.veil/` are skipped.
fn cmd_scan_gate(repo_arg: Option<&Path>, file: &Path, json: bool) -> Result<ExitCode> {
    let start = match repo_arg {
        Some(p) => p.to_path_buf(),
        None => std::env::current_dir()?,
    };
    let root = ctx::find_root(&start).unwrap_or(start);
    let scan = scan_gate(&root, file, &file.display().to_string())?;
    match json {
        true => api::emit_json(&scan)?,
        false => api::text::scan(&scan),
    }
    Ok(scan_status(&scan))
}

/// The gate scan of the files under `root`, with the rules of `file`
/// (shown as `shown`). Shared with `vl serve --local`.
fn scan_gate(root: &Path, file: &Path, shown: &str) -> Result<api::Scan> {
    let rules = std::fs::read(file).with_context(|| format!("reading the trusted policy {shown}"))?;
    let policy = Policy::parse(&String::from_utf8_lossy(&rules));
    for w in &policy.warnings {
        warn_untrusted(&format!("{shown}: {w}"));
    }
    api::scan_gate(&DiskBackend::new(root), &policy, shown)
}

// ---- secrets & identities ------------------------------------------------

fn cmd_secret(ctx: &mut Ctx, c: &SecretCmd) -> Result<()> {
    match c {
        SecretCmd::Set { name, value, scope } => {
            let value = match value {
                Some(v) => v.clone(),
                None => {
                    let mut s = String::new();
                    std::io::stdin().read_to_string(&mut s)?;
                    s.trim_end_matches(['\n', '\r']).to_string()
                }
            };
            if let Some(scope) = scope {
                return team_secret::set(ctx, scope, name, &value);
            }
            let previous = ctx.repo.vault_update(|vault| Ok(vault.secrets.insert(name.clone(), value)))?;
            ctx.repo.record_outside_view(
                format!("store secret {name} in the local vault"),
                match previous {
                    Some(_) => format!(
                        "the local vault is not part of the operation log, and the previous value of {name} was replaced; \
                         set it again with `vl secret set {name}`"
                    ),
                    None => format!("the local vault is not part of the operation log; run `vl secret rm {name}`"),
                },
            )?;
            println!("Stored secret {name} in the local vault");
        }
        SecretCmd::Get { name, scope: Some(scope) } => team_secret::get(ctx, scope, name)?,
        SecretCmd::List {
            scope: Some(scope),
            exposed_to,
            out,
        } => team_secret::list(ctx, scope, exposed_to.as_deref(), out.json)?,
        SecretCmd::Rm { name, scope: Some(scope) } => team_secret::rm(ctx, scope, name)?,
        SecretCmd::Get { name, scope: None } => {
            let vault = ctx.repo.vault_load()?;
            let v = vault.secrets.get(name).ok_or_else(|| anyhow!("no secret named '{name}'"))?;
            println!("{v}");
        }
        // Names only: no value ever enters the result.
        SecretCmd::List { scope: None, out, .. } => match out.json {
            true => api::emit_json(&api::secret_list(&ctx.repo)?)?,
            false => api::text::secret_list(&api::secret_list(&ctx.repo)?),
        },
        SecretCmd::Rm { name, scope: None } => {
            if !ctx.repo.vault_update(|vault| Ok(vault.secrets.remove(name).is_some()))? {
                bail!("no secret named '{name}'");
            }
            ctx.repo.record_outside_view(
                format!("remove secret {name} from the local vault"),
                format!("the local vault is not part of the operation log and the value is gone; set it again with `vl secret set {name}`"),
            )?;
            println!("Removed secret {name}");
        }
        SecretCmd::Files => {
            let vault = ctx.repo.vault_load()?;
            for p in vault.files.keys() {
                println!("{}", safe(p));
            }
            for (p, r) in &vault.removed {
                println!(
                    "{}  {}",
                    safe(p),
                    dim(&format!("(gone from the working copy since {}; `vl secret recover {}`)", fmt_time(r.removed_at), safe(p)))
                );
            }
        }
        SecretCmd::Recover { path } => {
            let p = ctx.repo_path(path)?;
            if !ctx.repo.vault_recover_file(&*ctx.fs, &p)? {
                bail!("the local vault holds no backup of {}", safe(p.as_str()));
            }
            println!("Recovered {} from the local vault", safe(p.as_str()));
        }
        SecretCmd::Import { file } => {
            let text = std::fs::read_to_string(file)?;
            let mut pairs = Vec::new();
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let line = line.strip_prefix("export ").unwrap_or(line);
                if let Some((k, v)) = line.split_once('=') {
                    let v = v.trim().trim_matches('"').trim_matches('\'');
                    pairs.push((k.trim().to_string(), v.to_string()));
                }
            }
            let n = pairs.len();
            let names: Vec<String> = pairs.iter().map(|(k, _)| k.clone()).collect();
            ctx.repo.vault_update(|vault| {
                vault.secrets.extend(pairs);
                Ok(())
            })?;
            ctx.repo.record_outside_view(
                format!("import {n} secret(s) into the local vault"),
                format!(
                    "the local vault is not part of the operation log; remove what was imported with `vl secret rm` ({})",
                    names.join(", ")
                ),
            )?;
            println!("Imported {n} secret(s) from {}", file.display());
        }
    }
    Ok(())
}

/// `vl run`: team-vault secrets first, then the local vault's, which
/// override them (`team_secret::run_env`).
fn cmd_run(ctx: &mut Ctx, command: &[String], scopes: &[String], local_only: bool, remember: bool) -> Result<ExitCode> {
    if remember {
        if scopes.is_empty() && !local_only {
            bail!("`vl run --remember` needs the scopes to remember (`--scope S`, repeatable), or `--local-only` for none");
        }
        team_secret::remember(ctx, scopes)?;
        if command.is_empty() {
            return Ok(ExitCode::SUCCESS);
        }
    }
    let vault = ctx.repo.vault_load()?;
    let team = team_secret::run_env(ctx, scopes, local_only, &vault.secrets)?;
    // BUG-523: say what is too big, instead of passing on E2BIG.
    let mut env: std::collections::BTreeMap<std::ffi::OsString, std::ffi::OsString> = std::env::vars_os().collect();
    env.extend(team.vars.iter().chain(&vault.secrets).map(|(k, v)| (k.into(), v.into())));
    let (total, limit) = (team_secret::exec_size(command, &env), team_secret::arg_max());
    if total > limit {
        return Err(team_secret::too_big(total, limit, &team));
    }
    let status = match std::process::Command::new(&command[0])
        .args(&command[1..])
        .envs(&team.vars)
        .envs(&vault.secrets)
        .status()
    {
        Err(e) if e.raw_os_error() == Some(libc::E2BIG) => return Err(team_secret::too_big(total, limit, &team)),
        r => r.with_context(|| format!("failed to run {}", command[0]))?,
    };
    Ok(ExitCode::from(status.code().unwrap_or(1).clamp(0, 255) as u8))
}

fn cmd_scope(ctx: &mut Ctx, c: &ScopeCmd) -> Result<()> {
    use veil_core::keychain::Role;
    let store = ctx.repo.store().clone();
    let keys = &store.keys;
    match c {
        ScopeCmd::List => {
            let me = keys.identity().map(|i| i.public_hex()).unwrap_or_default();
            for ring in keys.rings()? {
                let state = match ring.verify() {
                    Ok(st) => st,
                    Err(e) => {
                        println!(
                            "{}  {}",
                            bold(&safe(&ring.scope)),
                            red(&safe(&format!("INVALID key ring ({e}); no access")))
                        );
                        continue;
                    }
                };
                let access = if keys.is_member(&ring.scope) {
                    match state.members.get(&me).map(|m| m.role) {
                        Some(Role::Admin) => green("admin"),
                        _ => green("member"),
                    }
                } else if keys.has(&ring.scope) {
                    yellow("revoked (history only)")
                } else {
                    dim("no access")
                };
                let kind = if state.legacy {
                    yellow("unsigned legacy ring")
                } else {
                    dim(&format!("generation {}, {} changes", state.generation, state.len))
                };
                println!("{}  {access}  {kind}", bold(&safe(&ring.scope)));
                for (pk, m) in &state.members {
                    let you = if *pk == me { cyan(" (you)") } else { String::new() };
                    let role = if m.role == Role::Admin { "admin " } else { "member" };
                    let unsigned = if m.signing_key.is_none() && !state.legacy {
                        yellow(" (no signing key)")
                    } else {
                        String::new()
                    };
                    println!("    {:<12} {role} {}{unsigned}{you}", safe(&m.name), dim(&safe(pk)));
                }
            }
        }
        ScopeCmd::Create { name } => {
            keys.create_scope(name)?;
            ctx.repo.record_outside_view(
                format!("create scope {name}"),
                "key rings are append-only, so a scope cannot be removed; it stays unused if nothing is cloaked under it",
            )?;
            println!("Created scope {name} (you are its admin)");
        }
        ScopeCmd::Grant {
            scope,
            public_key,
            name,
            admin,
        } => {
            let role = if *admin { Role::Admin } else { Role::Member };
            keys.grant_role(scope, public_key, name, role)?;
            ctx.repo.record_outside_view(
                format!("grant scope {scope} to {name}"),
                format!(
                    "key rings are append-only; take the access back with `vl scope revoke {scope} {public_key}` \
                     (until you push, nobody else has received the key)"
                ),
            )?;
            println!("Granted scope {scope} to {}; push to share the updated key ring", safe(name));
            if veil_core::identity::parse_public_identity(public_key)?.ed25519.is_none() {
                warn("that is a short public key without a signing key: their signatures will show as unknown.\n  Ask them for the full key from `vl identity show` and grant again.");
            }
        }
        ScopeCmd::Revoke { scope, public_key } => {
            if let Some(vault_report) = keys.revoke_with_vault(scope, public_key)? {
                ctx.repo.record_outside_view(
                    format!("revoke {public_key} from scope {scope}"),
                    format!(
                        "a revocation and its key rotation cannot be taken back; grant the key again with \
                         `vl scope grant {scope} {public_key} --name <name>` (it receives the new generation)"
                    ),
                )?;
                let generation = keys.ring_state(scope)?.and_then(|r| r.ok()).map(|s| s.generation).unwrap_or(0);
                println!(
                    "Revoked. Scope {scope} rotated to key generation {generation}: new content is sealed with a key\n\
                     the revoked identity never receives. Content they already decrypted cannot be recalled; rotate secrets.\n\
                     Push to share the updated key ring."
                );
                team_secret::print_revoke_report(scope, &vault_report);
                warn_unreachable_members(keys, scope);
            } else {
                bail!("that key is not a member of '{scope}'");
            }
        }
        ScopeCmd::Rotate { scope } => {
            let g = keys.rotate(scope)?;
            ctx.repo.record_outside_view(
                format!("rotate scope {scope}"),
                "a key rotation cannot be taken back; members keep access through the new generation",
            )?;
            println!("Scope {scope} rotated to key generation {g}; push to share the updated key ring");
            warn_unreachable_members(keys, scope);
        }
        ScopeCmd::Log { scope } => {
            let ring = keys
                .load_ring(scope)?
                .ok_or_else(|| anyhow!("no scope named '{scope}'"))?;
            if ring.is_legacy() {
                println!("{}", yellow("unsigned legacy ring: no membership log (an admin change upgrades it)"));
                return Ok(());
            }
            if let Err(e) = ring.verify() {
                warn_untrusted(&format!("this ring does not verify: {e}"));
            }
            let mut names: std::collections::BTreeMap<String, String> = Default::default();
            for c in &ring.log {
                match &c.op {
                    veil_core::keychain::RingOp::Genesis { members, .. } => {
                        names.extend(members.iter().map(|m| (m.id.clone(), m.name.clone())))
                    }
                    veil_core::keychain::RingOp::Grant { member } | veil_core::keychain::RingOp::Share { member, .. } => {
                        names.insert(member.id.clone(), member.name.clone());
                    }
                    _ => {}
                }
            }
            for c in &ring.log {
                let who = names.get(&c.signer).cloned().unwrap_or_else(|| c.signer[..17].to_string());
                let what = match &c.op {
                    veil_core::keychain::RingOp::Revoke { member, rotation }
                    | veil_core::keychain::RingOp::RevokeOwn { member, rotation } => format!(
                        "revoke {} → generation {}",
                        names.get(member).cloned().unwrap_or_else(|| member.clone()),
                        rotation.generation
                    ),
                    op => op.summary(),
                };
                println!(
                    "#{:<3} {} {} {}",
                    c.seq,
                    dim(&fmt_time(c.timestamp)),
                    yellow(&safe(&who)),
                    safe(&what)
                );
            }
        }
    }
    Ok(())
}

/// After a rotation: name the members who received no key (BUG-070).
fn warn_unreachable_members(keys: &veil_core::keychain::Keychain, scope: &str) {
    for (id, name) in keys.unreachable_members(scope) {
        warn(&format!(
            "member {} ({id}) of scope {scope} has an invalid (low-order) key and received no key; \
             revoke it with `vl scope revoke {scope} {id}`",
            safe(&name)
        ));
    }
}

// ---- workspaces ----------------------------------------------------------

fn cmd_ws(ctx: &mut Ctx, c: &WsCmd) -> Result<ExitCode> {
    match c {
        WsCmd::List { out } => match out.json {
            true => api::emit_json(&api::workspace_list(&ctx.repo, &ctx.ws))?,
            false => api::text::workspace_list(&api::workspace_list(&ctx.repo, &ctx.ws)),
        },
        WsCmd::New { name, rev, cloak } => {
            let bases = match rev {
                Some(r) => vec![ctx.rev(r)?],
                None => ctx.repo.snapshot(&ctx.wc()?)?.parents.clone(),
            };
            let wc = ctx.repo.create_workspace(name, bases, cloak.clone())?;
            println!("Created virtual workspace {} at {}", bold(name), one_line(&ctx.repo, &wc));
            println!(
                "  {} no directory was created. Use `vl ws exec {name} -- <cmd>` or `vl ws switch {name}`.",
                dim("hint:")
            );
        }
        WsCmd::Switch { name } => {
            if *name == ctx.ws {
                println!("Project directory already attached to workspace {}", bold(name));
                return Ok(ExitCode::SUCCESS);
            }
            mount::refuse_if_mounted(&ctx.root, name, "switch to")?;
            let from = ctx.ws.clone();
            ctx.attach(name)?;
            // An operation of its own, so `vl undo` right after it does not
            // undo the snapshot of the workspace just left (BUG-100). The
            // files move when the command finishes, journalled (BUG-113).
            ctx.repo.record_workspace_switch(&from, name)?;
            println!("Project directory attached to workspace {}", bold(name));
        }
        WsCmd::Rm { name, force } => {
            if *name == ctx.ws {
                bail!("workspace '{name}' is attached to the project directory; switch away first");
            }
            let had_mount = mount::check_removable(&ctx.root, name, *force)?;
            let had_sandbox = sandbox::remove_workspace(ctx, name, *force)?;
            if had_mount {
                mount::remove_state(&ctx.root, name);
            }
            println!("Removed workspace {name}{}", if had_sandbox { " and its sandbox" } else { "" });
        }
        WsCmd::Cat { name, path } => {
            let wc = ctx.repo.workspace_wc(name)?;
            let view = ctx.repo.tree_view(&wc)?;
            let p = VPath::new(path)?;
            if p.is_root() || view.metadata(&p).ok().flatten().is_some_and(|m| m.kind == veil_core::vfs::NodeKind::Dir) {
                bail!("'{}' is a directory in workspace {}, not a file", safe(path), safe(name));
            }
            let data = match view.read(&p) {
                Err(err) if err.is_unreadable() => {
                    let tree = ctx.repo.snapshot(&wc)?.tree;
                    match lookup(ctx.repo.store(), &tree, &p)?.and_then(|e| hidden_explanation(&ctx.repo, &p, &e)) {
                        Some(why) => bail!(why),
                        None => return Err(err.into()),
                    }
                }
                r => r?,
            };
            render::Out.write_all(&data)?;
        }
        WsCmd::Write { name, path } => {
            if *name == ctx.ws {
                bail!("workspace '{name}' is attached to the project directory; edit the file directly");
            }
            let mut data = Vec::new();
            std::io::stdin().read_to_end(&mut data)?;
            let _wc = veil_core::lock::WcLock::acquire(&veil_core::repo::state_dir(&ctx.root), name)?;
            let overlay = ctx.repo.workspace_overlay(name)?;
            let vp = VPath::new(path)?;
            overlay.write(&vp, &data)?;
            let out = ctx.repo.snapshot_workspace(name, &overlay)?;
            print_build_warnings(&out.report);
            // Say what the builder did with it, not what was asked (BUG-102).
            let tree = ctx.repo.snapshot(&out.snapshot)?.tree;
            let recorded = match lookup(ctx.repo.store(), &tree, &vp)? {
                Some(e) => ctx.repo.store().read_entry(&e).is_ok_and(|d| d == data),
                None => false,
            };
            if !recorded {
                let r = &out.report;
                let why = if r.isolated.contains(&vp) {
                    "the policy isolates it (local-only): it never enters history, and a virtual workspace has no local files"
                        .to_string()
                } else if r.quarantined.iter().any(|(p, _)| *p == vp) {
                    "it looks like it contains a secret, so it was quarantined".to_string()
                } else if r.held_back.iter().any(|(p, _)| *p == vp) {
                    "it is held back under an embargo this identity holds no key for".to_string()
                } else if r.cloak_failures.iter().any(|(p, _)| *p == vp) {
                    "it should be cloaked but no key is available".to_string()
                } else {
                    let class = ctx.repo.effective_policy(&overlay)?.classify(&vp, false);
                    match class.tier {
                        Tier::Ignored => "the policy ignores it".to_string(),
                        Tier::Isolated => "the policy isolates it (local-only)".to_string(),
                        _ => "the policy or the scanner kept it out".to_string(),
                    }
                };
                bail!("{} was not recorded in workspace '{}': {why}", safe(path), safe(name));
            }
            println!("Recorded {} in {}", safe(path), one_line(&ctx.repo, &out.snapshot));
        }
        WsCmd::Mount { .. } => unreachable!("handled before the context opens"),
        WsCmd::Unmount { name } => mount::cmd_unmount(ctx, name)?,
        WsCmd::Exec {
            name,
            ephemeral,
            rev,
            message,
            with_isolated,
            only,
            record_only,
            confine,
            command,
        } => {
            return sandbox::exec(
                ctx,
                &sandbox::Exec {
                    name: name.as_deref(),
                    ephemeral: *ephemeral,
                    rev,
                    message,
                    with_isolated: *with_isolated,
                    only,
                    record_only: *record_only,
                    confine,
                    command,
                },
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// One tick of `vl watch` (and of a `vl serve` watch with
/// `working_copy`): snapshot the directory, unless another command moved
/// the working copy and may still be checking it out. `false` if it yielded.
fn watch_step(ctx: &mut Ctx, behind_since: &mut Option<std::time::Instant>, interval_ms: u64) -> Result<bool> {
    // Another command may have moved the working copy since the last
    // tick: never judge the directory against a pointer read earlier
    // (BUG-117).
    ctx.refresh()?;
    if ctx.behind()? {
        // That command may still be checking the directory out. Leave it
        // alone; only if it stays behind (the command died) recover it
        // as any command would.
        let since = *behind_since.get_or_insert_with(std::time::Instant::now);
        if since.elapsed() < ctx::WATCH_YIELD.max(Duration::from_millis(interval_ms.saturating_mul(2))) {
            return Ok(false);
        }
    }
    *behind_since = None;
    ctx.snapshot()?;
    Ok(true)
}

fn cmd_watch(ctx: &mut Ctx, interval_ms: u64) -> Result<()> {
    eprintln!("Watching {} (Ctrl-C to stop)", ctx.root.display());
    let mut last = ctx.wc()?;
    let mut behind_since: Option<std::time::Instant> = None;
    loop {
        std::thread::sleep(Duration::from_millis(interval_ms));
        if !watch_step(ctx, &mut behind_since, interval_ms)? {
            continue;
        }
        let now = ctx.wc()?;
        if now != last {
            println!("{}  snapshot {}", dim(&fmt_time(now_millis())), one_line(&ctx.repo, &now));
            if stdout_closed() {
                // Nobody is watching any more (`vl watch | head -1`).
                return Ok(());
            }
            last = now;
        }
    }
}

// ---- sync ----------------------------------------------------------------

fn remote_backend(ctx: &Ctx, name: &str) -> Result<(Arc<dyn StorageBackend>, RemoteConfig)> {
    let r = ctx
        .repo
        .config()
        .remotes
        .get(name)
        .cloned()
        .ok_or_else(|| anyhow!("no remote named '{name}' (add one with `vl remote add {name} <path>`)"))?;
    if let Some(url) = SshUrl::parse(&r.url) {
        return Ok((connect_sftp(&url?)?, r));
    }
    let path = PathBuf::from(&r.url);
    let path = if path.is_absolute() { path } else { ctx.root.join(path) };
    Ok((Arc::new(DiskBackend::new(path)), r))
}

fn cmd_remote(ctx: &mut Ctx, c: &RemoteCmd) -> Result<()> {
    match c {
        RemoteCmd::Add { name, url, public } => {
            if let Some(parsed) = hub::HubUrl::parse(url) {
                if parsed?.project.is_empty() {
                    bail!("a Veil server remote names a project: veil://host[:port]/project");
                }
                if *public {
                    bail!("--public is for path and SSH remotes; on a Veil server, `vl access PATH public` makes folders public");
                }
            } else if let Some(parsed) = SshUrl::parse(url) {
                parsed?;
            }
            remote::add_remote(&mut ctx.repo, name, url, *public)?;
            println!(
                "Added {} remote {} → {}",
                if *public { "public" } else { "team" },
                safe(name),
                safe(url)
            );
        }
        RemoteCmd::List => {
            for (name, r) in &ctx.repo.config().remotes {
                let kind = if r.public { yellow("public") } else { green("team") };
                println!("{}  {kind}  {}", bold(&safe(name)), safe(&r.url));
            }
        }
        RemoteCmd::Rm { name } => {
            remote::remove_remote(&mut ctx.repo, name)?;
            println!("Removed remote {} and its remote tags", safe(name));
        }
    }
    Ok(())
}

fn cmd_push(
    ctx: &mut Ctx,
    name: &str,
    tags: &[String],
    force: bool,
    opts: &remote::SyncOptions,
    delete: &[String],
    verify: &hooks::NoVerifyArgs,
) -> Result<ExitCode> {
    // A remote that does not exist fails below, as before; nothing is
    // connected to here unless a `pre-push` hook will run.
    if let Some(cfg) = ctx.repo.config().remotes.get(name).cloned() {
        let kind = if cfg.public { "public" } else { "team" };
        hooks::before_push(ctx, verify, name, &cfg.url, kind, |ctx| {
            if tags.is_empty() && !delete.is_empty() {
                return Ok(hooks::delete_lines(&ctx.repo, name, delete, cfg.public));
            }
            let (backend, cfg) = remote_backend(ctx, name)?;
            let plan = veil_core::push_plan::plan_push_with(&ctx.repo, backend, cfg.public, tags, force, opts.force_tags)?;
            Ok(hooks::veil_push_lines(&ctx.repo, &plan, name, delete))
        })?;
    }
    if !delete.is_empty() {
        let (backend, _) = remote_backend(ctx, name)?;
        let d = remote::delete_remote_tags(&mut ctx.repo, name, backend, delete, force)?;
        for t in &d.tags_deleted {
            println!("  {} {} on {name}", red("deleted"), cyan(&safe(t)));
        }
        for (t, why) in &d.tags_skipped {
            println!("  {} deleting {} ({})", red("rejected"), safe(t), safe(why));
        }
        for w in &d.warnings {
            warn(w);
        }
        if tags.is_empty() {
            return Ok(push_status(
                &d.tags_rejected,
                &format!("{name} has work on them you have not seen. Run `vl pull {name}` first (or `vl push --delete --force`)"),
                &[],
            ));
        }
        if !d.tags_rejected.is_empty() {
            push_status(&d.tags_rejected, &format!("run `vl pull {name}` first"), &[]);
            return Ok(ExitCode::FAILURE);
        }
    }
    let (backend, cfg) = remote_backend(ctx, name)?;
    // The journal of an interrupted push to this remote (its URL) is
    // resumed: what it staged there is not sent again.
    let opts = remote::SyncOptions {
        journal: Some(cfg.url.clone()),
        ..opts.clone()
    };
    let r = remote::push_with(&mut ctx.repo, backend, cfg.public, tags, force, &opts)?;
    remote::record_pushed_tags(&mut ctx.repo, name, &r)?;
    for (t, id) in &r.tags_updated {
        println!("  {} {} → {}", green("pushed"), cyan(&safe(t)), id.short());
    }
    let mut rejected = Vec::new();
    let mut withheld = Vec::new();
    for (t, why) in &r.tags_skipped {
        if r.tags_rejected.contains(t) {
            let why = match why.starts_with("release tag") {
                true => safe(why).into_owned(),
                false => "remote has diverged: not a fast-forward".to_string(),
            };
            println!("  {} {} ({why})", red("rejected"), safe(t));
            rejected.push(t.clone());
        } else {
            println!("  {} {} ({})", yellow("skipped"), safe(t), safe(why));
            if tags.contains(t) {
                withheld.push(t.clone());
            }
        }
    }
    for w in &r.warnings {
        warn_untrusted(w);
    }
    for e in &r.releases_published {
        println!(
            "  {} embargo {} (its key is in the pushed record now; the release can no longer be undone)",
            green("published"),
            safe(e)
        );
    }
    println!(
        "Pushed {} object(s) to {}{name}{}",
        r.objects_copied,
        if cfg.public { "public remote " } else { "" },
        if r.redacted > 0 {
            format!("; {} cloaked/embargoed object(s) withheld", r.redacted)
        } else {
            String::new()
        }
    );
    let first = rejected.first().map(|t| safe(t).into_owned()).unwrap_or_default();
    // A release tag the remote moved is never merged or pulled into ours
    // (BUG-703): someone has to decide which one is the release.
    // A release is never replaced on the remote without --force-tags
    // (BUG-710).
    let release = rejected.iter().find(|t| {
        r.tags_skipped.iter().any(|(n, why)| n == *t && why.starts_with("release tag"))
            || ctx.repo.view().tags.get(*t).is_some_and(|t| t.annotation.is_some())
    });
    let fix = match release {
        Some(t) => {
            let t = safe(t);
            format!(
                "{name} holds release tag {t} at another target. Replace it there with yours with `vl push {name} -t {t} --force-tags`, or take theirs with `vl tag set {t} -r {name}/{t} --force`"
            )
        }
        None => format!(
            "{name} has changes you don't have. Run `vl pull {name}`, `vl merge {name}/{first}`, and push again (or `vl push --force` to overwrite them)"
        ),
    };
    Ok(push_status(&rejected, &fix, &withheld))
}

/// The largest pack a push stages (`VEIL_PUSH_CHUNK`, e.g. `8M`; default
/// 32 MiB): what one dropped connection makes a retry send again.
fn push_chunk() -> Result<u64> {
    match std::env::var("VEIL_PUSH_CHUNK") {
        Ok(v) => match veil_core::vfs::parse_size(&v) {
            Some(n) if n > 0 => Ok(n),
            _ => bail!("VEIL_PUSH_CHUNK={v:?} is not a size (like 32M)"),
        },
        Err(_) => Ok(0),
    }
}

/// `vl push --dry-run`: the plan, per remote. Exits 1 where the push would
/// fail: a remote that cannot be planned, a tag the remote would reject, or
/// a tag named with `-t` that would be held back.
fn cmd_push_dry_run(ctx: &mut Ctx, remote: Option<&str>, tags: &[String], (force, force_tags): (bool, bool), json: bool) -> Result<ExitCode> {
    let doc = api::push_plan(ctx, remote, tags, force, force_tags)?;
    match json {
        true => api::emit_json(&doc)?,
        false => api::text::push_plan(&doc),
    }
    let fails = doc.remotes.iter().any(|r| {
        r.error.is_some()
            || r.tags.iter().any(|t| t.action == "rejected" || (t.action == "skipped" && tags.contains(&t.name)))
    });
    Ok(if fails { ExitCode::FAILURE } else { ExitCode::SUCCESS })
}

/// Exit status of a push that did not send every tag it was asked to:
/// failure if the remote rejected any (`rejected`, with `fix` saying what
/// to do), or if a tag named on the command line was held back. Tags held
/// back by design from an all-tags push (cloaked tags on a public remote,
/// unreleased embargoes) do not fail it: a script tells "nothing to do"
/// (0) from "partially rejected" (1) by the status alone.
fn push_status(rejected: &[String], fix: &str, withheld: &[String]) -> ExitCode {
    let list = |tags: &[String]| tags.iter().map(|t| safe(t).into_owned()).collect::<Vec<_>>().join(", ");
    if !rejected.is_empty() {
        eprintln!(
            "{} {} {} rejected ({}): {fix}",
            red("error:"),
            rejected.len(),
            if rejected.len() == 1 { "tag was" } else { "tags were" },
            list(rejected)
        );
    }
    if !withheld.is_empty() {
        eprintln!(
            "{} requested {} not pushed: {} (see `skipped` above)",
            red("error:"),
            if withheld.len() == 1 { "tag was" } else { "tags were" },
            list(withheld)
        );
    }
    if rejected.is_empty() && withheld.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn cmd_pull(ctx: &mut Ctx, name: &str, full: bool) -> Result<()> {
    let (backend, _) = remote_backend(ctx, name)?;
    let r = remote::pull_with(&mut ctx.repo, name, backend, &remote::SyncOptions { full, ..Default::default() })?;
    for (t, id) in &r.tags_updated {
        println!("  {} {} → {}", green("updated"), cyan(&safe(t)), id.short());
    }
    for t in &r.remote_tags_removed {
        println!("  {} {} (gone from {name})", yellow("pruned"), safe(t));
    }
    for (t, local, theirs) in &r.release_tags_kept {
        warn_untrusted(&format!(
            "{name} moved release tag {t} from {} to {}; your release tag {t} stays at {} (release tags never move; compare with `vl diff --from {t} --to {name}/{t}`, take theirs with `vl tag set {t} -r {name}/{t} --force`)",
            local.short(),
            theirs.short(),
            local.short()
        ));
    }
    for t in &r.tags_kept_deleted {
        println!(
            "  {} {} (deleted here; still on {name}: `vl push {name} --delete {}` deletes it there)",
            dim("kept deleted"),
            safe(t),
            safe(t)
        );
    }
    for w in &r.warnings {
        warn_untrusted(w);
    }
    println!("Pulled {} object(s) from {name}", r.objects_copied);
    Ok(())
}

// ---- integrity -----------------------------------------------------------

/// `vl fsck` deliberately bypasses `Ctx::open`: it must not snapshot or
/// write anything, and it has to work when the operation head is damaged.
fn cmd_fsck(repo_arg: Option<&Path>, verbose: bool) -> Result<ExitCode> {
    use veil_core::fsck::{fsck, Severity};
    let start = match repo_arg {
        Some(p) => p.to_path_buf(),
        None => std::env::current_dir()?,
    };
    let root = ctx::find_root(&start)
        .ok_or_else(|| anyhow!("no Veil repository found in {} or its parents", start.display()))?;
    let identity = load_identity()?;
    let report = fsck(Arc::new(DiskBackend::new(&root)), Some(identity))?;
    for f in &report.findings {
        let show = verbose || matches!(f.severity, Severity::Corrupt | Severity::Warning);
        if !show {
            continue;
        }
        let label = match f.severity {
            Severity::Corrupt => red(f.severity.label()),
            Severity::Warning => yellow(f.severity.label()),
            Severity::Redacted | Severity::Note => dim(f.severity.label()),
        };
        println!("{label}: {}", safe(&f.message));
    }
    println!(
        "Checked {} objects ({} snapshots, {} trees, {} files; {} unreachable), {} operations, {} key rings, {} embargo records",
        report.objects_checked,
        report.snapshots,
        report.trees,
        report.files,
        report.objects_unreachable,
        report.operations,
        report.keyrings,
        report.embargoes
    );
    let (redacted, notes) = (report.count(Severity::Redacted), report.count(Severity::Note));
    if !verbose && redacted + notes > 0 {
        println!("  {redacted} redacted (expected), {notes} note(s); use --verbose to list them");
    }
    if report.is_ok() {
        println!("{}", green("No corruption found"));
        Ok(ExitCode::SUCCESS)
    } else {
        println!("{} {} problem(s) found", red("Corrupt:"), report.count(Severity::Corrupt));
        Ok(ExitCode::FAILURE)
    }
}

/// `vl upgrade` bypasses `Ctx::open` too: it must not snapshot, and it
/// works on bare remotes.
/// `vl upgrade --sync-secrets`: an existing repository starts sealing and
/// syncing its shared secrets only through this explicit step, which lists
/// the files first (`docs/VISIBILITY.md`, "Existing repositories").
fn cmd_sync_secrets(ctx: &mut Ctx, dry_run: bool) -> Result<ExitCode> {
    use veil_core::policy::{Policy, Tier, SYNCED_SECRETS_POLICY};
    let file = VPath::new(POLICY_FILE)?;
    let text = String::from_utf8_lossy(&ctx.fs.read(&file).unwrap_or_default()).into_owned();
    let current = Policy::parse(&text);
    let wanted = Policy::parse(&format!("{text}\n{SYNCED_SECRETS_POLICY}"));
    if matches!(current.classify(&VPath::new(".env")?, false).tier, Tier::Cloaked(_)) {
        println!("Shared secrets already sync in this repository ({POLICY_FILE} seals .env).");
        return Ok(ExitCode::SUCCESS);
    }
    // Every file kept on this device today that would start syncing.
    let mut files = Vec::new();
    let mut stack = vec![ctx.root.clone()];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir)?.flatten() {
            let p = e.path();
            let rel = p.strip_prefix(&ctx.root)?.to_string_lossy().replace('\\', "/");
            if rel == ".veil" {
                continue;
            }
            let Ok(vp) = VPath::new(&rel) else { continue };
            let ft = e.file_type()?;
            if ft.is_dir() {
                if !matches!(current.classify(&vp, true).tier, Tier::Ignored) {
                    stack.push(p);
                }
            } else if ft.is_file()
                && current.classify(&vp, false).tier == Tier::Isolated
                && matches!(wanted.classify(&vp, false).tier, Tier::Cloaked(_))
            {
                files.push(rel);
            }
        }
    }
    files.sort();
    println!(
        "These files would start syncing, encrypted under the key of the access line that gives their folder (the admins' \
         'team' key where no line names anyone); only devices holding it open them:"
    );
    for f in &files {
        println!("  {}", safe(f));
    }
    if files.is_empty() {
        println!("  (none today; new .env files would)");
    }
    if dry_run {
        println!("Dry run: nothing changed. Run without --dry-run to add the rules to {POLICY_FILE}.");
        return Ok(ExitCode::SUCCESS);
    }
    let keys = ctx.repo.keys();
    if keys.ring_state(veil_core::policy::DEFAULT_SCOPE)?.is_none() {
        keys.create_scope(veil_core::policy::DEFAULT_SCOPE)?;
    }
    let mut out = text;
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push('\n');
    out.push_str(SYNCED_SECRETS_POLICY);
    ctx.fs.write(&file, out.as_bytes())?;
    println!("Added the rules to {POLICY_FILE}; the next snapshot seals these files. Push to share them.");
    Ok(ExitCode::SUCCESS)
}

fn cmd_upgrade(repo_arg: Option<&Path>, dry_run: bool, remote_name: Option<&str>, force: bool) -> Result<ExitCode> {
    use veil_core::upgrade::{upgrade, UpgradeOptions};
    let start = match repo_arg {
        Some(p) => p.to_path_buf(),
        None => std::env::current_dir()?,
    };
    let root = ctx::find_root(&start)
        .ok_or_else(|| anyhow!("no Veil repository found in {} or its parents", start.display()))?;
    let (backend, label, identity) = match remote_name {
        None => (
            Arc::new(DiskBackend::new(&root)) as Arc<dyn StorageBackend>,
            "this repository".to_string(),
            Some(load_identity()?),
        ),
        Some(name) => {
            let config = veil_core::repo::read_config(&DiskBackend::new(&root))?;
            let r = config
                .remotes
                .get(name)
                .ok_or_else(|| anyhow!("no remote named '{name}'"))?;
            // A remote is checked structurally: its sealed content is not ours
            // to open. SSH remotes are resolved as push and pull do (BUG-072).
            let backend: Arc<dyn StorageBackend> = match SshUrl::parse(&r.url) {
                Some(url) => connect_sftp(&url?)?,
                None => {
                    let path = PathBuf::from(&r.url);
                    let path = if path.is_absolute() { path } else { root.join(path) };
                    Arc::new(DiskBackend::new(path))
                }
            };
            (backend, format!("remote '{name}' ({})", safe(&r.url)), None)
        }
    };
    let opts = UpgradeOptions {
        dry_run,
        force,
        ..UpgradeOptions::default()
    };
    let r = upgrade(backend, identity, &opts)?;
    if r.up_to_date {
        println!("{label} is already at format {} (the newest)", r.to);
        for n in &r.notes {
            println!("  {} {n}", dim("note:"));
        }
        return Ok(ExitCode::SUCCESS);
    }
    if r.from == r.to {
        // Already at the format; only the key-ring step was pending (BUG-071).
        println!(
            "{} the key rings of {label} (format {}) to HPKE key wrapping",
            if dry_run { "Would move" } else { "Moved" },
            r.to
        );
    } else {
        let verb = if dry_run { "Would upgrade" } else { "Upgraded" };
        println!(
            "{verb} {label} from format {} to format {}{}",
            r.from,
            r.to,
            if r.resumed { " (resumed an interrupted upgrade)" } else { "" }
        );
    }
    println!(
        "  objects    {} ({} JSON tree(s), {} binary tree(s))",
        r.objects, r.trees_json, r.trees_binary
    );
    println!("  steps      {}", r.steps.join(", "));
    for c in &r.corrupt {
        println!("  {} {}", red("corrupt:"), safe(c));
    }
    for n in &r.notes {
        println!("  {} {n}", dim("note:"));
    }
    if dry_run && !r.corrupt.is_empty() && !force {
        println!("{}", yellow("The upgrade would be refused until `vl fsck` is clean (or --force)."));
        return Ok(ExitCode::FAILURE);
    }
    Ok(ExitCode::SUCCESS)
}

// ---- storage -------------------------------------------------------------

fn cmd_gc(
    ctx: &mut Ctx,
    keep_ops_days: Option<f64>,
    grace_minutes: f64,
    prune_now: bool,
    level: i32,
    no_deltas: bool,
) -> Result<()> {
    use veil_core::gc::{gc, GcOptions};
    let secs = |x: f64, what: &str| -> Result<Duration> {
        Duration::try_from_secs_f64(x).map_err(|_| anyhow!("invalid {what}: {x}"))
    };
    let opts = GcOptions {
        keep_ops: keep_ops_days.map(|d| secs(d * 86_400.0, "--keep-ops-days")).transpose()?,
        grace: if prune_now {
            Duration::ZERO
        } else {
            secs(grace_minutes * 60.0, "--grace-minutes")?
        },
        level,
        deltas: !no_deltas,
        extra_roots: ctx.checkout_roots(),
        ..GcOptions::default()
    };
    let r = gc(&mut ctx.repo, &opts)?;
    let mib = |b: u64| b as f64 / (1024.0 * 1024.0);
    println!(
        "Objects: {} before ({} loose, {} pack(s)), {} reachable, {} deleted, {} pending deletion",
        r.objects_before, r.loose_before, r.packs_before, r.reachable, r.deleted, r.pending
    );
    if r.rescued > 0 {
        println!("Kept {} object(s) that another process started using", r.rescued);
    }
    if let Some(name) = &r.pack {
        let s = &r.pack_stats;
        let more = match r.packs.len() {
            0 | 1 => String::new(),
            n => format!(" and {} more pack(s)", n - 1),
        };
        println!(
            "Packed {} object(s) into pack-{}{more} ({} delta, {} compressed, {} stored)",
            s.objects,
            &name[..12],
            s.deltas,
            s.compressed,
            s.stored
        );
    }
    if opts.keep_ops.is_some() {
        println!("Operations: pruned {} of {}", r.ops_pruned, r.ops_before);
    }
    println!("Storage: {:.2} MiB -> {:.2} MiB", mib(r.bytes_before), mib(r.bytes_after));
    for why in &r.incomplete {
        println!("{} {why}", yellow("warning:"));
    }
    if !r.incomplete.is_empty() {
        println!(
            "{} part of the history could not be read, so nothing was deleted",
            yellow("warning:")
        );
    }
    if let Some(why) = &r.deferred {
        println!("{} {why}", yellow("note:"));
    }
    if r.merged > 0 {
        println!("Merged {} small pack(s) into one", r.merged);
    }
    if r.debris_removed > 0 {
        println!("Removed {} leftover(s) of interrupted commands", r.debris_removed);
    }
    Ok(())
}

// ---- packaging ---------------------------------------------------------------

/// `vl man`: the man page on stdout, or `vl.1` plus one `vl-<command>.1` page
/// per (sub)command in `out_dir`. Packagers run this at release time.
fn cmd_man(out_dir: Option<&Path>) -> Result<ExitCode> {
    let cmd = Cli::command();
    match out_dir {
        None => clap_mangen::Man::new(cmd).render(&mut render::Out)?,
        Some(dir) => {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
            clap_mangen::generate_to(cmd, dir).with_context(|| format!("writing man pages to {}", dir.display()))?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_790_000_000_000;
    const DAY: i64 = 86_400_000;

    #[test]
    fn durations_are_checked() {
        assert_eq!(parse_time_at("+7d", NOW).unwrap(), NOW + 7 * DAY);
        assert_eq!(parse_time_at("+90m", NOW).unwrap(), NOW + 90 * 60_000);
        assert_eq!(parse_time_at("+36500d", NOW).unwrap(), NOW + 36_500 * DAY);
        for bad in [
            "+213503955787d",       // overflows i64 milliseconds (BUG-024)
            "+9223372036854775807s", // n * 1000 overflows
            "+99999999999999999999w", // does not fit an i64 at all
            "+36700d",               // more than a century
            "+-5d",                  // negative: would release at once
            "+0s",                   // not in the future
            "+d",
            "+5x",
            "+",
        ] {
            assert!(parse_time_at(bad, NOW).is_err(), "{bad} accepted");
        }
    }

    #[test]
    fn absolute_times_must_be_in_the_near_future() {
        let ok = chrono::DateTime::from_timestamp_millis(NOW + DAY).unwrap().to_rfc3339();
        assert_eq!(parse_time_at(&ok, NOW).unwrap(), NOW + DAY);
        let past = chrono::DateTime::from_timestamp_millis(NOW - DAY).unwrap().to_rfc3339();
        assert!(parse_time_at(&past, NOW).is_err());
        assert!(parse_time_at("1954-01-01", NOW).is_err());
        assert!(parse_time_at("9999-12-31", NOW).is_err());
        assert!(parse_time_at("+262143-12-31T00:00:00Z", NOW).is_err());
    }
}
