mod cli;
mod ctx;
mod render;
mod sandbox;

use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use veil_core::{
    checkout::behind_special,
    commands::EmbargoSpec,
    now_millis,
    keychain::validate_scope_name,
    policy::{escape_field, escape_literal, format_rule, has_glob_syntax, Policy, Tier, POLICY_FILE},
    remote,
    repo::{RemoteConfig, DEFAULT_WORKSPACE},
    secrets,
    tree::lookup,
    vfs::{walk_files, NodeKind},
    DiskBackend, Identity, Repo, SftpBackend, SshUrl, StorageBackend, VPath,
};

use crate::{
    cli::*,
    ctx::{load_identity, print_working_copy_warnings, save_checkout, user_for, CheckoutState, Ctx},
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
# Engine-enforced: .env, .env.*, *.pem, *.key, id_rsa, … are isolated by
# default and cannot be made public by a plain `public` rule. Public files are
# scanned for credentials on every snapshot and quarantined on a hit.

target/                  ignore
node_modules/            ignore
";

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    if args.next().is_some_and(|a| a == sandbox::REAPER_ARG) {
        return sandbox::reaper_main(args.next().as_deref());
    }
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            // Errors may quote repository data (names, paths): escape them.
            eprintln!("{} {}", red("error:"), safe(&format!("{e:#}")));
            ExitCode::FAILURE
        }
    }
}

fn open(cli: &Cli) -> Result<Ctx> {
    Ctx::open(cli.repository.as_deref(), !cli.no_snapshot)
}

fn run(cli: Cli) -> Result<ExitCode> {
    match &cli.cmd {
        Cmd::Init { path } => cmd_init(path.as_deref()),
        Cmd::Clone { source, dest } => cmd_clone(source, dest.as_deref()),
        Cmd::Identity(c) => cmd_identity(c),
        Cmd::Fsck { verbose } => cmd_fsck(cli.repository.as_deref(), *verbose),
        _ => {
            let mut ctx = open(&cli)?;
            let code = dispatch(&mut ctx, &cli)?;
            ctx.finish()?;
            Ok(code)
        }
    }
}

fn dispatch(ctx: &mut Ctx, cli: &Cli) -> Result<ExitCode> {
    match &cli.cmd {
        Cmd::Init { .. } | Cmd::Clone { .. } | Cmd::Identity(_) | Cmd::Fsck { .. } => unreachable!(),
        Cmd::Status => cmd_status(ctx)?,
        Cmd::Log { limit } => print_log(&ctx.repo, &ctx.ws, *limit)?,
        Cmd::Show { rev, stat } => cmd_show(ctx, rev, *stat)?,
        Cmd::Diff { rev, from, to, stat } => {
            let (a, b) = match (from, to) {
                (None, None) => {
                    let id = ctx.rev(rev.as_deref().unwrap_or("@"))?;
                    let s = ctx.repo.snapshot(&id)?;
                    (ctx.repo.parents_tree(&s.parents)?.tree, s.tree)
                }
                _ => {
                    let a = ctx.rev(from.as_deref().unwrap_or("@"))?;
                    let b = ctx.rev(to.as_deref().unwrap_or("@"))?;
                    (ctx.repo.snapshot(&a)?.tree, ctx.repo.snapshot(&b)?.tree)
                }
            };
            print_diff(&ctx.repo, &a, &b, *stat)?;
        }
        Cmd::Files { rev } => {
            let id = ctx.rev(rev)?;
            print_files(&ctx.repo, &ctx.repo.snapshot(&id)?.tree)?;
        }
        Cmd::Cat { path, rev } => {
            let id = ctx.rev(rev)?;
            let p = ctx.repo_path(path)?;
            let e = lookup(ctx.repo.store(), &ctx.repo.snapshot(&id)?.tree, &p)?
                .ok_or_else(|| anyhow!("{p} does not exist in {}", id.short()))?;
            let data = ctx.repo.store().read_entry(&e)?;
            std::io::stdout().write_all(&data)?;
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
        Cmd::Describe { rev, message } => {
            let id = ctx.rev(rev)?;
            let new = ctx.repo.describe(id, message)?;
            println!("Described {}", one_line(&ctx.repo, &new));
        }
        Cmd::New { revs, message } => {
            let parents = if revs.is_empty() {
                vec![ctx.wc()?]
            } else {
                revs.iter().map(|r| ctx.rev(r)).collect::<Result<_>>()?
            };
            let ws = ctx.ws.clone();
            ctx.repo.new_change(&ws, parents, message)?;
        }
        Cmd::Commit { message } => {
            let ws = ctx.ws.clone();
            let (c, _) = ctx.repo.commit_working_copy(&ws, message)?;
            println!("Committed {}", one_line(&ctx.repo, &c));
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
            let new = ctx.repo.rebase(src, dest)?;
            println!("Rebased {}", one_line(&ctx.repo, &new));
            let s = ctx.repo.snapshot(&new)?;
            if !s.conflicts.is_empty() {
                warn_untrusted(&format!("conflicts in: {}", s.conflicts.join(", ")));
            }
        }
        Cmd::Squash { rev } => {
            let id = ctx.rev(rev)?;
            let p = ctx.repo.squash(id)?;
            println!("Squashed into {}", one_line(&ctx.repo, &p));
        }
        Cmd::Restore { paths, from } => cmd_restore(ctx, paths, from)?,
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
                bail!("you hold no current key for scope '{scope}' (create it with `vl scope create {scope}`)");
            }
            cmd_policy_rules(ctx, patterns, Tier::Cloaked(scope.clone()), false)?
        }
        Cmd::Isolate { patterns } => cmd_policy_rules(ctx, patterns, Tier::Isolated, false)?,
        Cmd::Expose { patterns, force } => cmd_policy_rules(ctx, patterns, Tier::Public, *force)?,
        Cmd::Ignore { patterns } => cmd_policy_rules(ctx, patterns, Tier::Ignored, false)?,
        Cmd::Policy(c) => cmd_policy(ctx, c)?,
        Cmd::Scan => return cmd_scan(ctx),
        Cmd::Secret(c) => cmd_secret(ctx, c)?,
        Cmd::Run { command } => return cmd_run(ctx, command),
        Cmd::Scope(c) => cmd_scope(ctx, c)?,
        Cmd::Workspace(c) => return cmd_ws(ctx, c),
        Cmd::Op(OpCmd::Log { limit }) => {
            for (id, op) in ctx.repo.op_log(*limit)? {
                println!(
                    "{} {} {} {}",
                    blue(&id.short()),
                    dim(&fmt_time(op.timestamp)),
                    yellow(&safe(&op.user)),
                    safe(&op.description)
                );
            }
        }
        // Both keep uncommitted working-copy edits: the automatic snapshot
        // taken before the command is not what the user wants to undo.
        Cmd::Op(OpCmd::Restore { id }) => {
            let op = ctx.repo.ops().resolve_prefix(id)?;
            let ws = ctx.ws.clone();
            ctx.repo.restore_operation_keeping_edits(&ws, op)?;
            println!("Restored to operation {}", op.short());
        }
        Cmd::Undo => {
            let ws = ctx.ws.clone();
            let (_, undone) = ctx.repo.undo_keeping_edits(&ws)?;
            println!("Undid: {}", safe(&undone));
        }
        Cmd::Watch { interval_ms } => cmd_watch(ctx, *interval_ms)?,
        Cmd::Remote(c) => cmd_remote(ctx, c)?,
        Cmd::Push { remote, tag, force, full } => cmd_push(ctx, remote, tag, *force, *full)?,
        Cmd::Pull { remote, full } => cmd_pull(ctx, remote, *full)?,
        Cmd::Gc {
            keep_ops_days,
            grace_minutes,
            prune_now,
            level,
            no_deltas,
        } => cmd_gc(ctx, *keep_ops_days, *grace_minutes, *prune_now, *level, *no_deltas)?,
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
    if !fs.exists(&policy)? {
        fs.write(&policy, DEFAULT_POLICY.as_bytes())?;
    }
    let out = repo.snapshot_workspace(DEFAULT_WORKSPACE, &*fs)?;
    repo.capture_local_files(&*fs, &out.report)?;
    save_checkout(
        &fs,
        &CheckoutState {
            workspace: DEFAULT_WORKSPACE.into(),
            snapshot: out.snapshot,
        },
    )?;
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

/// Clone the repository on `backend` (configured as `origin` → `url`) into `dest`.
fn clone_into(backend: Arc<dyn StorageBackend>, url: String, shown: String, dest: &Path) -> Result<ExitCode> {
    if dest.exists() && std::fs::read_dir(dest)?.next().is_some() {
        bail!("destination {} is not empty", dest.display());
    }
    std::fs::create_dir_all(dest)?;
    let dest = dest.canonicalize()?;
    let identity = load_identity()?;
    let fs = Arc::new(DiskBackend::new(&dest));
    let mut repo = Repo::init_for_clone(fs.clone(), Some(identity.clone()), &user_for(&identity))?;
    let mut config = repo.config().clone();
    config.remotes.insert("origin".into(), RemoteConfig { url, public: false });
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
    let co = repo.checkout_tree(&*fs, None, &to)?;
    save_checkout(
        &fs,
        &CheckoutState {
            workspace: DEFAULT_WORKSPACE.into(),
            snapshot: wc,
        },
    )?;
    println!(
        "Cloned {} into {} ({} objects, {} files)",
        safe(&shown),
        dest.display(),
        report.objects_copied,
        co.written
    );
    if !co.redacted.is_empty() {
        println!(
            "  {} {} cloaked file(s) you hold no key for. Share your public key ({}) with a member\n  and ask them to run `vl scope grant team <key>` and push.",
            yellow("note:"),
            co.redacted.len(),
            identity.public_id()
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_identity(c: &IdentityCmd) -> Result<ExitCode> {
    match c {
        IdentityCmd::Show => {
            let id = load_identity()?;
            println!("name        {}", id.name);
            println!("public key  {}", id.public_id());
            println!("member id   {}", id.public_hex());
            println!("signing key {}", id.verifying_hex());
            println!("stored at   {}", ctx::identity_path().display());
        }
        IdentityCmd::New { name, force } => {
            let path = ctx::identity_path();
            let previous = if path.exists() {
                if !force {
                    bail!("an identity already exists (use --force to replace it; you will lose access to scopes granted to it)");
                }
                Some(retire_identity(&path)?)
            } else {
                None
            };
            let id = Identity::generate(&name.clone().unwrap_or_else(ctx::default_user_name));
            ctx::write_identity(&id)?;
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
                     `vl identity recover-vault` in each. Scope admins must grant the new public key again.",
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

fn cmd_status(ctx: &mut Ctx) -> Result<()> {
    let wc = ctx.wc()?;
    let s = ctx.repo.snapshot(&wc)?;
    let base = ctx.repo.parents_tree(&s.parents)?.tree;
    let changes = veil_core::tree::diff_trees(ctx.repo.store(), Some(&base), Some(&s.tree))?;
    if changes.is_empty() {
        println!("The working copy has no changes.");
    } else {
        println!("Working copy changes:");
        print_changes_summary(&ctx.repo, &changes);
    }
    println!("Workspace    : {}{}", green(&safe(&ctx.ws)), match &ctx.repo.view().workspace(&ctx.ws)?.cloak {
        Some(c) => magenta(&format!(" [cloaked:{}]", safe(c))),
        None => String::new(),
    });
    println!("Working copy : {} {}", bold(&green("@")), one_line(&ctx.repo, &wc));
    for p in &s.parents {
        println!("Parent       : {}", one_line(&ctx.repo, p));
    }
    if !ctx.report.isolated.is_empty() {
        println!("{}", dim("Local-only (isolated; never snapshotted or pushed):"));
        for p in &ctx.report.isolated {
            println!("  {} {}", dim("L"), safe(p.as_str()));
        }
    }
    if !ctx.report.quarantined.is_empty() {
        println!("{}", yellow("Quarantined (secrets detected; kept local):"));
        for (p, f) in &ctx.report.quarantined {
            let state = if ctx.report.quarantine_kept.contains(p) {
                "edit held back; history keeps the previous version"
            } else {
                "never recorded"
            };
            println!("  {} {}  ({}; {state})", yellow("Q"), safe(p.as_str()), f[0].rule);
        }
    }
    if !ctx.report.carried.is_empty() {
        println!("{}", dim("Redacted (no key; kept in history, absent on disk):"));
        for p in &ctx.report.carried {
            println!("  {} {}", dim("R"), safe(p.as_str()));
        }
    }
    if !s.conflicts.is_empty() {
        println!("{}", red("Unresolved conflicts:"));
        for c in &s.conflicts {
            println!("  {} {}", red("C"), safe(c));
        }
    }
    Ok(())
}

fn cmd_show(ctx: &mut Ctx, rev: &str, stat: bool) -> Result<()> {
    let id = ctx.rev(rev)?;
    let s = ctx.repo.snapshot(&id)?;
    println!("Change ID : {}", bold(&magenta(&s.change_id.display())));
    println!("Snapshot  : {}", blue(&id.hex()));
    println!("Author    : {} at {}", safe(&s.author), fmt_time(s.timestamp));
    if id != ctx.repo.root_id() {
        println!("Signature : {}", signature_detail(&ctx.repo.keys().snapshot_status(&s), &s));
    }
    if s.parents.len() > 1 {
        for p in &s.parents {
            println!("Parent    : {}", one_line(&ctx.repo, p));
        }
    }
    let tags: Vec<&String> = ctx.repo.view().tags.iter().filter(|(_, t)| t.target == id).map(|(n, _)| n).collect();
    if !tags.is_empty() {
        println!("Tags      : {}", cyan(&tags.iter().map(|t| safe(t)).collect::<Vec<_>>().join(", ")));
    }
    if let Some(c) = &s.cloak {
        println!("Cloaked   : {}", magenta(&safe(c)));
    }
    if let Some(e) = &s.embargo {
        let rec = ctx.repo.keys().load_embargo(e)?;
        let state = match rec {
            Some(r) if r.is_released() => "released".to_string(),
            Some(r) => match r.until {
                Some(u) => format!("until {}", fmt_time(u)),
                None => "until manually released".into(),
            },
            None => "unknown".into(),
        };
        println!("Embargo   : {} ({state})", yellow(&safe(e)));
    }
    println!();
    let desc = ctx.repo.description(&s);
    if desc.trim().is_empty() {
        println!("    {}", dim("(no description set)"));
    } else {
        for l in safe_lines(&desc) {
            println!("    {l}");
        }
    }
    println!();
    let base = ctx.repo.parents_tree(&s.parents)?.tree;
    print_diff(&ctx.repo, &base, &s.tree, stat)
}

fn cmd_restore(ctx: &mut Ctx, paths: &[String], from: &str) -> Result<()> {
    let src = ctx.rev(from)?;
    let src_tree = ctx.repo.snapshot(&src)?.tree;
    let wc_tree = ctx.repo.snapshot(&ctx.wc()?)?.tree;
    let filters: Vec<VPath> = paths.iter().map(|p| ctx.repo_path(p)).collect::<Result<_>>()?;
    let changes = veil_core::tree::diff_trees(ctx.repo.store(), Some(&wc_tree), Some(&src_tree))?;
    let wanted = |p: &VPath| filters.is_empty() || filters.iter().any(|f| p.starts_with(f));
    let mut n = 0;
    let mut done = std::collections::HashSet::new();
    for c in changes {
        if !wanted(&c.path) {
            continue;
        }
        done.insert(c.path.clone());
        if behind_special(&*ctx.fs, &c.path)? {
            skipped_special(&c.path);
            continue;
        }
        match &c.new {
            Some(e) => {
                let data = ctx.repo.store().read_entry(e)?;
                ctx.fs.write(&c.path, &data)?;
                ctx.fs.set_executable(&c.path, e.executable)?;
            }
            None => ctx.fs.remove_file(&c.path)?,
        }
        n += 1;
    }
    // A quarantined edit is not in the working-copy tree (it keeps the
    // previous version), so the diff above cannot see it: restore it too.
    for p in ctx.report.quarantine_kept.clone() {
        if done.contains(&p) || !wanted(&p) {
            continue;
        }
        if behind_special(&*ctx.fs, &p)? {
            skipped_special(&p);
            continue;
        }
        match veil_core::tree::lookup(ctx.repo.store(), &src_tree, &p)? {
            Some(e) if e.kind == veil_core::EntryKind::File => {
                ctx.fs.write(&p, &ctx.repo.store().read_entry(&e)?)?;
                ctx.fs.set_executable(&p, e.executable)?;
            }
            _ => ctx.fs.remove_file(&p)?,
        }
        n += 1;
    }
    ctx.snapshot()?;
    println!("Restored {n} path(s) from {}", one_line(&ctx.repo, &src));
    Ok(())
}

fn skipped_special(p: &VPath) {
    warn(&format!("skipped {p}: a symlink or special file is in the way; Veil never writes through or over it"));
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
    let spec = if embargo || until.is_some() {
        Some(EmbargoSpec {
            scope: scope.to_string(),
            until: until.map(parse_time).transpose()?,
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
            "  {} {e}: changed files are sealed for scope '{scope}'; everyone else sees the pre-merge content{}.",
            yellow("embargo"),
            match until {
                Some(u) => format!(" until {u}"),
                None => " until `vl embargo release`".into(),
            }
        );
    }
    if !res.declassified.is_empty() {
        println!(
            "  {} (secret-scanned): {}",
            yellow("published from the cloaked line"),
            res.declassified.join(", ")
        );
    }
    if !res.quarantined.is_empty() {
        warn(&format!(
            "quarantined, left out of the merge (they hold secrets): {}",
            res.quarantined.join(", ")
        ));
    }
    for w in &res.warnings {
        warn(w);
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
                let state = if r.is_released() {
                    green("released")
                } else {
                    match r.until {
                        Some(u) => yellow(&format!("until {}", fmt_time(u))),
                        None => yellow("manual release"),
                    }
                };
                let key = if ctx.repo.keys().has(&format!("embargo/{}", r.id)) {
                    ""
                } else {
                    " (no key)"
                };
                println!(
                    "{}  scope:{}  {state}{key}  {}",
                    bold(&safe(&r.id)),
                    safe(&r.scope),
                    first_line(&r.description)
                );
            }
        }
        EmbargoCmd::Release { id } => {
            ctx.repo.release_embargo(id)?;
            println!("Released embargo {id}; push to publish it.");
        }
    }
    Ok(())
}

fn cmd_tag(ctx: &mut Ctx, c: &TagCmd) -> Result<()> {
    match c {
        TagCmd::List => {
            for (name, t) in &ctx.repo.view().tags {
                let cloak = t
                    .cloak
                    .as_ref()
                    .map(|c| magenta(&format!(" [cloaked:{}]", safe(c))))
                    .unwrap_or_default();
                println!("{}{cloak}: {}", cyan(&safe(name)), one_line(&ctx.repo, &t.target));
            }
            for (name, t) in &ctx.repo.view().remote_tags {
                println!("{}: {}", dim(&safe(name)), one_line(&ctx.repo, t));
            }
        }
        TagCmd::Set {
            name,
            rev,
            cloak,
            allow_backwards,
        } => {
            let id = ctx.rev(rev)?;
            ctx.repo.set_tag(name, id, cloak.clone(), *allow_backwards)?;
            println!("Tag {} → {}", cyan(name), one_line(&ctx.repo, &id));
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
            warn(&format!(
                "'{arg}' is not an existing path, so it is a glob pattern; to match a file with this literal name, escape the characters with '\\' (e.g. {})",
                escape_literal(arg)
            ));
        }
    }
    (escape_field(arg), false)
}

fn cmd_policy_rules(ctx: &mut Ctx, patterns: &[String], tier: Tier, force: bool) -> Result<()> {
    let path = VPath::new(POLICY_FILE)?;
    let mut text = match ctx.fs.read_opt(&path)? {
        Some(b) => String::from_utf8_lossy(&b).into_owned(),
        None => DEFAULT_POLICY.to_string(),
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
                warn(&format!(
                    "{} matching file(s) already exist in plaintext in earlier snapshots (e.g. {}). New snapshots are protected; rotate any secrets they contain.",
                    exposed.len(),
                    exposed[0]
                ));
            }
        }
    }
    ctx.fs.write(&path, text.as_bytes())?;
    ctx.snapshot()?;
    Ok(())
}

fn cmd_policy(ctx: &mut Ctx, c: &PolicyCmd) -> Result<()> {
    let policy = Policy::load(&*ctx.fs)?;
    match c {
        PolicyCmd::Show => {
            for r in policy.rules() {
                let origin = if r.builtin { dim("built-in") } else { cyan(".veilpolicy") };
                println!("{origin:<12}  {}", r.to_line());
            }
            for w in &policy.warnings {
                warn_untrusted(w);
            }
        }
        PolicyCmd::Check { paths } => {
            for p in paths {
                let vp = ctx.repo_path(p)?;
                let is_dir = ctx.fs.metadata(&vp)?.is_some_and(|m| m.kind == NodeKind::Dir);
                let c = policy.classify(&vp, is_dir);
                let why = match (&c.rule, c.builtin_secret) {
                    (Some(r), true) => format!("built-in secret rule '{r}'"),
                    (Some(r), false) => format!("rule '{r}'"),
                    (None, _) => "default".into(),
                };
                let mut extra = String::new();
                if c.blocked_exposure {
                    extra.push_str(" (a `public` rule was ignored: use `public!`)");
                }
                if c.allow_secrets {
                    extra.push_str(" (secret scanning disabled)");
                }
                println!("{vp}: {} via {why}{extra}", bold(&c.tier.label()));
            }
        }
    }
    Ok(())
}

fn cmd_scan(ctx: &mut Ctx) -> Result<ExitCode> {
    let policy = Policy::load(&*ctx.fs)?;
    let skip = |p: &VPath| {
        p.as_str() == ".veil" || policy.classify(p, true).tier == Tier::Ignored
    };
    let mut exposed = 0;
    let mut contained = 0;
    for path in walk_files(&*ctx.fs, &VPath::root(), &skip)? {
        let class = policy.classify(&path, false);
        if class.tier == Tier::Ignored || class.allow_secrets {
            continue;
        }
        let findings = secrets::scan(&ctx.fs.read(&path)?);
        if findings.is_empty() {
            continue;
        }
        let (label, safe) = match &class.tier {
            Tier::Public => (red("PUBLIC   "), false),
            Tier::Cloaked(s) => (magenta(&format!("cloaked:{s}")), true),
            _ => (dim("isolated "), true),
        };
        for f in &findings {
            println!("{label} {path}:{}  {} {}", f.line, f.rule, dim(&f.excerpt));
        }
        if safe {
            contained += 1;
        } else {
            exposed += 1;
        }
    }
    if exposed == 0 {
        println!("{} no secrets in public files ({contained} protected file(s) contain secrets)", green("ok:"));
        Ok(ExitCode::SUCCESS)
    } else {
        println!(
            "{} {exposed} public file(s) contain secrets; they are quarantined from snapshots until cloaked, isolated or fixed",
            red("found:")
        );
        Ok(ExitCode::from(1))
    }
}

// ---- secrets & identities ------------------------------------------------

fn cmd_secret(ctx: &mut Ctx, c: &SecretCmd) -> Result<()> {
    match c {
        SecretCmd::Set { name, value } => {
            let value = match value {
                Some(v) => v.clone(),
                None => {
                    let mut s = String::new();
                    std::io::stdin().read_to_string(&mut s)?;
                    s.trim_end_matches(['\n', '\r']).to_string()
                }
            };
            ctx.repo.vault_update(|vault| {
                vault.secrets.insert(name.clone(), value);
                Ok(())
            })?;
            println!("Stored secret {name} in the local vault");
        }
        SecretCmd::Get { name } => {
            let vault = ctx.repo.vault_load()?;
            let v = vault.secrets.get(name).ok_or_else(|| anyhow!("no secret named '{name}'"))?;
            println!("{v}");
        }
        SecretCmd::List => {
            for k in ctx.repo.vault_load()?.secrets.keys() {
                println!("{k}");
            }
        }
        SecretCmd::Rm { name } => {
            if !ctx.repo.vault_update(|vault| Ok(vault.secrets.remove(name).is_some()))? {
                bail!("no secret named '{name}'");
            }
            println!("Removed secret {name}");
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
            ctx.repo.vault_update(|vault| {
                vault.secrets.extend(pairs);
                Ok(())
            })?;
            println!("Imported {n} secret(s) from {}", file.display());
        }
    }
    Ok(())
}

fn cmd_run(ctx: &mut Ctx, command: &[String]) -> Result<ExitCode> {
    let vault = ctx.repo.vault_load()?;
    let status = std::process::Command::new(&command[0])
        .args(&command[1..])
        .envs(&vault.secrets)
        .status()
        .with_context(|| format!("failed to run {}", command[0]))?;
    Ok(ExitCode::from(status.code().unwrap_or(1).clamp(0, 255) as u8))
}

fn cmd_scope(ctx: &mut Ctx, c: &ScopeCmd) -> Result<()> {
    use veil_core::keychain::Role;
    let keys = ctx.repo.keys();
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
            println!("Granted scope {scope} to {name}; push to share the updated key ring");
            if veil_core::identity::parse_public_identity(public_key)?.ed25519.is_none() {
                warn("that is a short public key without a signing key: their signatures will show as unknown.\n  Ask them for the full key from `vl identity show` and grant again.");
            }
        }
        ScopeCmd::Revoke { scope, public_key } => {
            if keys.revoke(scope, public_key)? {
                let generation = keys.ring_state(scope)?.and_then(|r| r.ok()).map(|s| s.generation).unwrap_or(0);
                println!(
                    "Revoked. Scope {scope} rotated to key generation {generation}: new content is sealed with a key\n\
                     the revoked identity never receives. Content they already decrypted cannot be recalled; rotate secrets.\n\
                     Push to share the updated key ring."
                );
            } else {
                bail!("that key is not a member of '{scope}'");
            }
        }
        ScopeCmd::Rotate { scope } => {
            let g = keys.rotate(scope)?;
            println!("Scope {scope} rotated to key generation {g}; push to share the updated key ring");
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
                    veil_core::keychain::RingOp::Grant { member } => {
                        names.insert(member.id.clone(), member.name.clone());
                    }
                    _ => {}
                }
            }
            for c in &ring.log {
                let who = names.get(&c.signer).cloned().unwrap_or_else(|| c.signer[..17].to_string());
                let what = match &c.op {
                    veil_core::keychain::RingOp::Revoke { member, rotation } => format!(
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

// ---- workspaces ----------------------------------------------------------

fn run_in(dir: &Path, command: &[String]) -> Result<i32> {
    let status = std::process::Command::new(&command[0])
        .args(&command[1..])
        .current_dir(dir)
        .status()
        .with_context(|| format!("failed to run {}", command[0]))?;
    Ok(status.code().unwrap_or(1))
}

fn cmd_ws(ctx: &mut Ctx, c: &WsCmd) -> Result<ExitCode> {
    match c {
        WsCmd::List => {
            for (name, w) in &ctx.repo.view().workspaces {
                let here = if *name == ctx.ws { green("* ") } else { "  ".into() };
                let cloak = w
                    .cloak
                    .as_ref()
                    .map(|c| magenta(&format!(" [cloaked:{}]", safe(c))))
                    .unwrap_or_default();
                println!("{here}{}{cloak}: {}", bold(&safe(name)), one_line(&ctx.repo, &w.wc));
            }
        }
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
            ctx.attach(name)?;
            println!("Project directory attached to workspace {}", bold(name));
        }
        WsCmd::Rm { name } => {
            if *name == ctx.ws {
                bail!("workspace '{name}' is attached to the project directory; switch away first");
            }
            ctx.repo.remove_workspace(name)?;
            println!("Removed workspace {name}");
        }
        WsCmd::Cat { name, path } => {
            let wc = ctx.repo.workspace_wc(name)?;
            let view = ctx.repo.tree_view(&wc)?;
            let data = view.read(&VPath::new(path)?)?;
            std::io::stdout().write_all(&data)?;
        }
        WsCmd::Write { name, path } => {
            if *name == ctx.ws {
                bail!("workspace '{name}' is attached to the project directory; edit the file directly");
            }
            let mut data = Vec::new();
            std::io::stdin().read_to_end(&mut data)?;
            let overlay = ctx.repo.workspace_overlay(name)?;
            overlay.write(&VPath::new(path)?, &data)?;
            let out = ctx.repo.snapshot_workspace(name, &overlay)?;
            print_build_warnings(&out.report);
            println!("Recorded {} in {}", path, one_line(&ctx.repo, &out.snapshot));
        }
        WsCmd::Exec {
            name,
            ephemeral,
            rev,
            message,
            with_isolated,
            command,
        } => {
            let (label, base_snapshot) = if *ephemeral {
                ("ephemeral".to_string(), ctx.rev(rev)?)
            } else {
                let name = name.as_deref().ok_or_else(|| anyhow!("give a workspace name or --ephemeral"))?;
                if name == ctx.ws {
                    bail!("workspace '{name}' is attached to the project directory; just run the command");
                }
                (name.to_string(), ctx.repo.workspace_wc(name)?)
            };
            let sb = sandbox::Sandbox::create(&label)?;
            let dir = sb.path().to_path_buf();
            let sandbox = DiskBackend::new(&dir);
            let result = (|| -> Result<i32> {
                let tree = ctx.repo.snapshot(&base_snapshot)?.tree;
                ctx.repo.checkout_tree(&sandbox, None, &tree)?;
                let mut injected = None;
                if *with_isolated {
                    let mut files = Vec::new();
                    for (p, hexdata) in ctx.repo.vault_load()?.files {
                        let data = hex::decode(hexdata)?;
                        sandbox.write(&VPath::new(&p)?, &data)?;
                        files.push((p, data));
                    }
                    // Whatever the command does with these, they must not be
                    // recorded under another name.
                    injected = Some(veil_core::builder::InjectedSecrets::from_files(
                        files.iter().map(|(p, d)| (p.as_str(), d.as_slice())),
                    ));
                }
                sb.make_private()?;
                eprintln!("{} {} in {}", dim("running"), command.join(" "), dir.display());
                let code = run_in(&dir, command)?;
                if *ephemeral {
                    let (id, report) =
                        ctx.repo
                            .commit_fs_as_child_injected(base_snapshot, &sandbox, message, injected.as_ref())?;
                    print_build_warnings(&report);
                    print_working_copy_warnings(&report);
                    eprintln!("Recorded {}", one_line(&ctx.repo, &id));
                } else {
                    let out = ctx
                        .repo
                        .snapshot_workspace_injected(&label, &sandbox, None, injected.as_ref())?;
                    print_build_warnings(&out.report);
                    print_working_copy_warnings(&out.report);
                    if !message.is_empty() {
                        ctx.repo.describe(out.snapshot, message)?;
                    }
                    let wc = ctx.repo.workspace_wc(&label)?;
                    // stderr: stdout belongs to the sandboxed command.
                    eprintln!(
                        "{} {}",
                        if out.changed { "Recorded" } else { "No changes in" },
                        one_line(&ctx.repo, &wc)
                    );
                }
                Ok(code)
            })();
            drop(sb);
            let code = result?;
            return Ok(ExitCode::from(code.clamp(0, 255) as u8));
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_watch(ctx: &mut Ctx, interval_ms: u64) -> Result<()> {
    eprintln!("Watching {} (Ctrl-C to stop)", ctx.root.display());
    let mut last = ctx.wc()?;
    loop {
        std::thread::sleep(Duration::from_millis(interval_ms));
        ctx.repo.reload()?;
        ctx.snapshot()?;
        let now = ctx.wc()?;
        if now != last {
            println!("{}  snapshot {}", dim(&fmt_time(now_millis())), one_line(&ctx.repo, &now));
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
    let mut config = ctx.repo.config().clone();
    match c {
        RemoteCmd::Add { name, url, public } => {
            if config.remotes.contains_key(name) {
                bail!("remote '{name}' already exists");
            }
            if let Some(parsed) = SshUrl::parse(url) {
                parsed?;
            }
            config.remotes.insert(
                name.clone(),
                RemoteConfig {
                    url: url.clone(),
                    public: *public,
                },
            );
            println!("Added {} remote {name} → {url}", if *public { "public" } else { "team" });
        }
        RemoteCmd::List => {
            for (name, r) in &config.remotes {
                let kind = if r.public { yellow("public") } else { green("team") };
                println!("{}  {kind}  {}", bold(name), r.url);
            }
            return Ok(());
        }
        RemoteCmd::Rm { name } => {
            config
                .remotes
                .remove(name)
                .ok_or_else(|| anyhow!("no remote named '{name}'"))?;
            println!("Removed remote {name}");
        }
    }
    ctx.repo.save_config(config)?;
    Ok(())
}

fn cmd_push(ctx: &mut Ctx, name: &str, tags: &[String], force: bool, full: bool) -> Result<()> {
    let (backend, cfg) = remote_backend(ctx, name)?;
    let opts = remote::SyncOptions { full };
    let r = remote::push_with(&mut ctx.repo, backend, cfg.public, tags, force, &opts)?;
    for (t, id) in &r.tags_updated {
        println!("  {} {} → {}", green("pushed"), cyan(&safe(t)), id.short());
    }
    for (t, why) in &r.tags_skipped {
        println!("  {} {} ({})", yellow("skipped"), safe(t), safe(why));
    }
    for w in &r.warnings {
        warn_untrusted(w);
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
    Ok(())
}

fn cmd_pull(ctx: &mut Ctx, name: &str, full: bool) -> Result<()> {
    let (backend, _) = remote_backend(ctx, name)?;
    let r = remote::pull_with(&mut ctx.repo, name, backend, &remote::SyncOptions { full })?;
    for (t, id) in &r.tags_updated {
        println!("  {} {} → {}", green("updated"), cyan(&safe(t)), id.short());
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
        println!(
            "Packed {} object(s) into pack-{} ({} delta, {} compressed, {} stored)",
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
    Ok(())
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
