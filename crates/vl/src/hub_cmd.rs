//! The `vl` commands that talk to a Veil server: `login`, `clone` of a
//! server project, `push`/`pull` to one, `group` and `access`
//! (`docs/HUB.md`, `docs/VISIBILITY.md`).

use std::{
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
};

use anyhow::{anyhow, bail, Context, Result};
use veil_core::{
    policy::{split_fields, valid_principal_name, POLICY_FILE},
    repo::{RemoteConfig, DEFAULT_WORKSPACE},
    DiskBackend, Repo, StorageBackend, VPath,
};

use crate::{
    cli::{AdminCmd, GroupCmd},
    ctx::{load_identity, user_for, Ctx},
    hub::{self, Client, HubUrl},
    render::{bold, cyan, dim, green, safe, warn_untrusted, yellow},
};

pub fn client_for(ctx: &Ctx, remote: &str) -> Result<(Client, RemoteConfig)> {
    let r = ctx
        .repo
        .config()
        .remotes
        .get(remote)
        .cloned()
        .ok_or_else(|| anyhow!("no remote named '{remote}' (add one with `vl remote add {remote} veil://host/project`)"))?;
    let url = HubUrl::parse(&r.url).ok_or_else(|| {
        anyhow!(
            "remote '{remote}' ({}) is not a Veil server; vl syncs only through a Veil server now. Replace it: `vl remote rm {remote}`, then `vl remote add {remote} veil://host/project`",
            crate::render::safe(&r.url)
        )
    })??;
    Ok((Client::new(&url, load_identity()?)?, r))
}

pub fn login(url: &str, name: Option<&str>, ca: Option<&Path>) -> Result<ExitCode> {
    let u = HubUrl::parse(url).ok_or_else(|| anyhow!("expected veil://host[:port] or https://host[:port]"))??;
    if let Some(ca) = ca {
        let pem = std::fs::read_to_string(ca).with_context(|| format!("reading {}", ca.display()))?;
        Client::trust_ca(&u.authority, &pem)?;
    }
    let identity = load_identity()?;
    let fp = hub::fingerprint(&identity.public_id()).unwrap_or_default();
    let client = Client::new(&u, identity)?;
    let s = client.login(name)?;
    println!("Signed in to {} as {}", safe(&u.authority), bold(&safe(&s.person)));
    println!("  this device {}", bold(&fp));
    println!("  server key  {}", dim(&s.hub_key));
    Ok(ExitCode::SUCCESS)
}

/// The server a device command is for: `server`, or the only one this
/// device is signed in to. `(authority, who this device is there)`.
pub fn resolve_server(server: Option<&str>) -> Result<(String, String)> {
    let servers = hub::signed_in_servers()?;
    Ok(match server {
        Some(s) => {
            let a = HubUrl::parse(s).ok_or_else(|| anyhow!("expected veil://host[:port]"))??.authority;
            servers
                .into_iter()
                .find(|(x, _)| *x == a)
                .ok_or_else(|| anyhow!("this device is not signed in to {a} (`vl login veil://{a}`)"))?
        }
        None => match <[_; 1]>::try_from(servers) {
            Ok([one]) => one,
            Err(v) if v.is_empty() => bail!("this device is not signed in to a Veil server (`vl login`)"),
            Err(_) => bail!("this device is signed in to several servers: give one with --server veil://host[:port]"),
        },
    })
}

/// `vl identity confirm FINGERPRINT`: vouch, with this device's key, for
/// the device of this person's with that fingerprint (`docs/HUB.md`
/// §13.11). The fingerprint is read off the new device by its owner, so
/// the server cannot substitute another device; it is looked up by that
/// fingerprint, so pending devices others make under the name cannot hide
/// it (§13.12). In a clone of a project, this device then shares its keys
/// with the new one at once.
///
/// In a clone of a project, a fingerprint that is the project's (the
/// server's `team` ring has it) confirms the project instead: this device
/// then trusts its key rings (BUG-845).
pub fn confirm_device(fingerprint: &str, server: Option<&str>) -> Result<()> {
    let fp = veil_core::hub::wire::normalize_fingerprint(fingerprint)
        .ok_or_else(|| anyhow!("a fingerprint is 20 hex digits, as `vl identity show` prints it (4F2A-9C1E-…)"))?;
    let mut in_clone = false;
    if server.is_none() {
        if let Some(mut ctx) = crate::hub_keys::clone_here() {
            in_clone = true;
            let (client, _) = client_for(&ctx, "origin")?;
            // A probe: if the server's `team` ring cannot be read here, the
            // fingerprint may still be a device's.
            if crate::hub_keys::confirm_project(Some(ctx.repo.keys()), &client, &fp).unwrap_or(false) {
                println!(
                    "Confirmed the fingerprint {} of project {}: this device trusts its secret keys",
                    bold(&fp),
                    safe(&client.url.project)
                );
                for w in crate::hub_keys::merge_server_rings(ctx.repo.keys(), &client.url, client.rings()?)? {
                    warn_untrusted(&w);
                }
                ctx.finish()?;
                return Ok(());
            }
        }
    }
    let (authority, me) = resolve_server(server)?;
    let url = HubUrl::parse(&format!("veil://{authority}")).ok_or_else(|| anyhow!("bad server"))??;
    let client = Client::new(&url, load_identity()?)?;
    let device = match client.pending_device(&me, &fp)? {
        Some(d) => d,
        None => client
            .devices(&me)?
            .identities
            .into_iter()
            .find(|d| hub::fingerprint(d).as_deref() == Some(fp.as_str()))
            .ok_or_else(|| {
                anyhow!(
                    "none of {me}'s devices on {authority} has the fingerprint {fp}{}: check it on the new device (`vl identity show`), \
                     sign in there again (`vl login veil://{authority} --name {me}`), then run this again",
                    if in_clone { ", and it is not the fingerprint of this project's keys on the server" } else { "" }
                )
            })?,
    };
    if hub::fingerprint(&device).as_deref() != Some(fp.as_str()) {
        bail!("the server answered with a device whose fingerprint is not {fp}");
    }
    client.vouch(&device)?;
    println!("Confirmed device {} as {}'s on {}", bold(&fp), safe(&me), safe(&authority));
    println!("  it may sign in now (`vl login`)");
    crate::hub_keys::confirmed_here(&authority);
    Ok(())
}

/// `thin`: a thin clone with this cache bound (S3), or `None` for a full
/// clone (`--full`).
pub fn clone(url: &HubUrl, dest: Option<&Path>, only: Option<&str>, thin: Option<u64>) -> Result<ExitCode> {
    if url.project.is_empty() {
        bail!("give a project: veil://host[:port]/project");
    }
    let only = match only {
        Some(o) => {
            let o = o.trim_matches('/');
            VPath::new(o).map_err(|_| anyhow!("--only takes a directory path from the project root"))?;
            Some(o.to_string())
        }
        None => None,
    };
    let dest = dest.map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from(&url.project));
    if dest.exists() && std::fs::read_dir(&dest)?.next().is_some() {
        bail!("destination {} is not empty", dest.display());
    }
    // A clone of one directory keeps its S1 form (every snapshot, that
    // directory's files): S3 does not combine it with a thin clone.
    let thin = if only.is_some() { None } else { thin };
    let created = !dest.exists();
    std::fs::create_dir_all(&dest)?;
    let dest = dest.canonicalize()?;
    let r = clone_populate(url, &dest, only.as_deref(), thin);
    if r.is_err() {
        let _ = if created {
            std::fs::remove_dir_all(&dest)
        } else {
            std::fs::read_dir(&dest).and_then(|d| {
                for e in d.flatten() {
                    let p = e.path();
                    if p.is_dir() {
                        std::fs::remove_dir_all(&p)?;
                    } else {
                        std::fs::remove_file(&p)?;
                    }
                }
                Ok(())
            })
        };
    }
    r
}

fn clone_populate(url: &HubUrl, dest: &Path, only: Option<&str>, mut thin: Option<u64>) -> Result<ExitCode> {
    let identity = load_identity()?;
    let client = Client::new(url, identity.clone())?;
    let fs = Arc::new(DiskBackend::new(dest));
    crate::ctx::mark_clone_incomplete(&fs)?;
    let mut repo = Repo::init_for_clone_at(fs.clone(), Some(identity.clone()), &user_for(&identity), veil_core::repo::REPO_FORMAT)?;
    let mut config = repo.config().clone();
    config.remotes.insert(
        "origin".into(),
        RemoteConfig {
            url: format!("veil://{}/{}", url.authority, url.project),
            public: false,
            only: only.map(str::to_string),
            unknown: Default::default(),
        },
    );
    // Thin by default (S3): the `partial` marker, at this release's format
    // (10; S3's release wrote 9), written before anything is fetched, so an
    // interrupted clone is never read as a full one. A server too old for thin clones gets a full one.
    if thin.is_some() && client.tips()?.is_some_and(|t| t.revision < crate::hub::HISTORY_PAGES) {
        println!("  {} the server is older than this vl: making a full clone", yellow("note:"));
        thin = None;
    }
    if let Some(limit) = thin {
        config.partial = Some(veil_core::repo::PartialConfig { remote: "origin".into(), cache_limit: limit });
    }
    repo.save_config(config)?;
    crate::thin::attach(&repo, &identity);
    // The project fingerprint this device confirmed, if any: the only `team`
    // ring it takes (BUG-845).
    repo.keys().set_anchor(&hub::anchor_for(&url.authority, &url.project)?.unwrap_or_default())?;
    let report = hub::pull(&mut repo, "origin", &client, only).context("fetching from the server")?;
    for w in &report.warnings {
        warn_untrusted(w);
    }
    let target = ["main", "trunk", "master"]
        .iter()
        .find_map(|t| repo.view().tags.get(*t).map(|t| t.target))
        .or_else(|| repo.view().tags.values().next().map(|t| t.target))
        .unwrap_or(repo.root_id());
    let wc = repo.new_change(DEFAULT_WORKSPACE, vec![target], "").context("starting a change")?;
    let to = repo.snapshot(&wc)?.tree;
    let mut partial = None;
    if let Some(o) = only {
        if veil_core::tree::lookup(repo.store(), &to, &VPath::new(o)?)?.is_none_or(|e| e.kind != veil_core::EntryKind::Dir) {
            bail!("no directory '{o}' that you can see in this project");
        }
        // Only `o` is written; the rest was never fetched, never shown, and
        // every snapshot keeps it unchanged.
        let (_, hidden) = hub::restrict_to(repo.store(), to, o)?;
        partial = Some((hub::without(repo.store(), to, o)?, hidden));
    }
    // Journalled, so a clone killed here is finished by the next command
    // (BUG-830).
    let (_, co) = repo.check_out_new(&*fs, DEFAULT_WORKSPACE, wc, partial).context("checking out")?;
    crate::ctx::mark_clone_complete(&fs)?;
    println!(
        "Cloned {} into {} ({} objects, {} files{}{})",
        safe(&format!("veil://{}/{}", url.authority, url.project)),
        dest.display(),
        report.objects_copied,
        co.written,
        only.map(|o| format!(", only {o}/")).unwrap_or_default(),
        if thin.is_some() { ", thin: the rest is fetched when read" } else { "" }
    );
    if !co.redacted.is_empty() && only.is_none() {
        println!(
            "  {} {} secret file(s) you hold no key for yet; an admin grants keys by adding you to a group",
            yellow("note:"),
            co.redacted.len()
        );
    }
    Ok(ExitCode::SUCCESS)
}

pub fn pull(ctx: &mut Ctx, remote: &str) -> Result<()> {
    let (client, cfg) = client_for(ctx, remote)?;
    let mv = if moves() { hub::MoveView::IfChanged } else { hub::MoveView::No };
    let (r, moved) = hub::pull_moving(&mut ctx.repo, remote, &client, cfg.only.as_deref(), false, mv)?;
    MOVED.store(true, std::sync::atomic::Ordering::SeqCst);
    if let Some(m) = moved {
        report_move(ctx, &m)?;
    }
    for (t, id) in &r.tags_updated {
        println!("  {} {} → {}", green("updated"), cyan(&safe(t)), id.short());
    }
    for w in &r.warnings {
        warn_untrusted(w);
    }
    println!("Pulled {} object(s) from {remote}", r.objects_copied);
    crate::share_cmd::after_pull(ctx, &client);
    Ok(())
}

/// Whether this process moved its clone to the person's current view
/// already (or pulled, which does when needed): at most once a command
/// (BUG-1509).
static MOVED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Debug builds only: `VEIL_TEST_NO_VIEW_MOVE` keeps a clone in the view it
/// has, for the tests of what each command does in a view that changed
/// (BUG-1508), which the move otherwise leaves after the first.
fn moves() -> bool {
    !(cfg!(debug_assertions) && std::env::var_os("VEIL_TEST_NO_VIEW_MOVE").is_some())
}

/// After a command: if what it read showed that the person's view changed
/// (the server named a snapshot of this clone under another id), move the
/// clone to their current view, once, in one operation (BUG-1509). `true`
/// when it moved. Never after `vl undo`, `vl redo` or `vl op`: those go
/// where the person asked, a move included.
pub fn move_if_view_changed(ctx: &mut Ctx, cmd: &crate::cli::Cmd) -> Result<bool> {
    use crate::cli::Cmd;
    if !moves() || matches!(cmd, Cmd::Undo { .. } | Cmd::Redo | Cmd::Op(..) | Cmd::Pull { .. }) || MOVED.load(std::sync::atomic::Ordering::SeqCst) {
        return Ok(false);
    }
    if !ctx.repo.store().view_changed() {
        return Ok(false);
    }
    move_now(ctx, hub::MoveView::Always)
}

/// Before a push: what it sends stands on server snapshots this clone met
/// in a view its person no longer has? Then the clone moves first, and the
/// push sends the work as the current view has it, which the server grafts
/// (BUG-1509).
pub fn move_before_push(ctx: &mut Ctx, remote: &str, only_tags: &[String]) -> Result<bool> {
    if !moves() || MOVED.load(std::sync::atomic::Ordering::SeqCst) || !ctx.repo.is_partial() {
        return Ok(false);
    }
    if ctx.repo.config().partial.as_ref().is_none_or(|p| p.remote != remote) {
        return Ok(false);
    }
    // What the push sends: the tags it names (all, without `-t`) that are
    // not where the remote has them (BUG-1565).
    let store = ctx.repo.store().clone();
    let v = ctx.repo.view();
    let mut stack: Vec<veil_core::ObjectId> = v
        .tags
        .iter()
        .filter(|(n, _)| only_tags.is_empty() || only_tags.contains(n))
        .filter(|(n, t)| v.remote_tags.get(&format!("{remote}/{n}")) != Some(&t.target))
        .map(|(_, t)| t.target)
        .collect();
    if stack.is_empty() {
        return Ok(false);
    }
    // What the server's current tips reach needs no question. A tip this
    // clone does not hold (someone pushed since its last pull) is paged in
    // first, once for all of them, as a pull would: else nothing is reached
    // and every server snapshot the push stands on is asked about, one
    // request a tag (BUG-1575).
    let (client, _) = client_for(ctx, remote)?;
    let current: Vec<veil_core::ObjectId> = client.tips()?.map(|t| t.branches.values().copied().collect()).unwrap_or_default();
    let unheld: Vec<veil_core::ObjectId> = current.iter().copied().filter(|t| !store.has(t)).collect();
    if !unheld.is_empty() {
        ctx.repo.deepen(&unheld, veil_core::promisor::HISTORY_PAGE)?;
    }
    let reached = store.reached_by(&current);
    let mut seen = std::collections::HashSet::new();
    let root = ctx.repo.root_id();
    while let Some(id) = stack.pop() {
        if id == root || reached.contains(&id) || !seen.insert(id) || seen.len() > 10_000 {
            continue;
        }
        if store.is_servers(&id)? {
            if store.current_projection(&id)?.is_some_and(|n| n != id) {
                return move_now(ctx, hub::MoveView::Always);
            }
            continue;
        }
        stack.extend(ctx.repo.snapshot(&id)?.parents.iter().copied());
    }
    Ok(false)
}

fn move_now(ctx: &mut Ctx, mv: hub::MoveView) -> Result<bool> {
    MOVED.store(true, std::sync::atomic::Ordering::SeqCst);
    let Some(remote) = ctx.repo.config().partial.as_ref().map(|p| p.remote.clone()) else { return Ok(false) };
    let (client, cfg) = client_for(ctx, &remote)?;
    let (_, moved) = hub::pull_moving(&mut ctx.repo, &remote, &client, cfg.only.as_deref(), false, mv)?;
    match moved {
        Some(m) => {
            report_move(ctx, &m)?;
            Ok(true)
        }
        None => Ok(false),
    }
}

/// The one line a move prints, what it kept and why, and the folders the
/// working copy's change lost, recorded before the working copy follows.
fn report_move(ctx: &mut Ctx, m: &veil_core::transaction::ViewMove) -> Result<()> {
    eprintln!(
        "{}",
        yellow(&format!("your access changed; moved {} change{} to your current view", m.moved, if m.moved == 1 { "" } else { "s" }))
    );
    for k in &m.kept {
        let folder = if k.folder.is_root() { "a folder it cannot tell".to_string() } else { format!("{}/", safe(k.folder.as_str())) };
        eprintln!(
            "  {} {} (it edits {folder}, which you no longer have access to){}",
            yellow("kept where it is:"),
            crate::render::one_line(&ctx.repo, &k.id),
            if m.kept_with > 0 { format!("; {} change(s) built with it stay too", m.kept_with) } else { String::new() }
        );
    }
    if let Some(paths) = m.lost.get(&ctx.ws).cloned() {
        ctx.mark_lost(&paths)?;
    }
    Ok(())
}

pub fn push(ctx: &mut Ctx, remote: &str, tags: &[String], force: bool, verify: &crate::hooks::NoVerifyArgs) -> Result<ExitCode> {
    let (client, cfg) = client_for(ctx, remote)?;
    crate::hooks::before_push(ctx, verify, remote, &cfg.url, tags)?;
    let out = hub::push(&mut ctx.repo, remote, &client, tags, force)?;
    if out.created {
        println!("Created project {} on {}: you are its admin, and everything is private", client.url.project, client.url.authority);
    }
    for (b, tip) in &out.moved {
        let what = if out.landed.contains(b) { "landed" } else { "pushed" };
        println!("  {} {} → {}", green(what), cyan(&safe(b)), tip.short());
    }
    for b in &out.deleted {
        println!("  {} {}", green("deleted"), cyan(&safe(b)));
    }
    for w in &out.warnings {
        println!("  {} {}", dim("note:"), safe(w));
    }
    for (b, why) in &out.rejected {
        println!("  {} {}: {}", yellow("rejected"), cyan(&safe(b)), safe(why));
    }
    if out.moved.is_empty() && out.deleted.is_empty() && out.rejected.is_empty() {
        println!("Everything up to date");
    } else {
        println!("Sent {} object(s) to {remote}", out.uploaded);
    }
    Ok(if out.rejected.is_empty() { ExitCode::SUCCESS } else { ExitCode::from(1) })
}

/// `vl land` (`docs/HUB.md` §13.19).
pub fn land(ctx: &mut Ctx, remote: &str, rev: Option<&str>, onto: Option<&str>, wait: bool, status: Option<&str>) -> Result<ExitCode> {
    use veil_core::hub::land::LandState;
    let (client, _) = client_for(ctx, remote)?;
    let (result, uploaded) = match status {
        Some(ticket) => (client.land_status(ticket, wait)?, None),
        None => {
            let id = ctx.rev(rev.unwrap_or("@-"))?;
            let onto = match onto {
                Some(b) => b.to_string(),
                None => client.tips()?.ok_or_else(|| anyhow!("no project '{}' that you can see", client.url.project))?.default_branch,
            };
            let out = hub::land(&mut ctx.repo, remote, &client, id, &onto, wait)?;
            (out.result, Some((out.uploaded, onto)))
        }
    };
    let onto = uploaded.as_ref().map(|(_, b)| b.as_str()).unwrap_or("the branch");
    match result.state {
        LandState::Landed => {
            let tip = result.landed.last().map(|t| t.short()).unwrap_or_default();
            println!("  {} {} → {} ({} change(s))", green("landed"), cyan(&safe(onto)), tip, result.landed.len());
            for w in &result.warnings {
                println!("  {} {}", dim("note:"), safe(w));
            }
        }
        LandState::Queued => println!("  {} as {} (`vl land --status {}`)", yellow("queued"), bold(&result.ticket), result.ticket),
        LandState::Conflict => {
            println!("  {} {}", yellow("conflict"), safe(result.message.as_deref().unwrap_or("")));
            for p in &result.paths {
                println!("    {}", safe(p));
            }
        }
        LandState::Rejected => println!("  {} {}", yellow("rejected"), safe(result.message.as_deref().unwrap_or(""))),
    }
    if let Some((n, _)) = uploaded {
        println!("Sent {n} object(s) to {remote}");
    }
    Ok(match result.state {
        LandState::Landed | LandState::Queued => ExitCode::SUCCESS,
        _ => ExitCode::from(1),
    })
}

pub fn group(ctx: &mut Ctx, c: &GroupCmd) -> Result<()> {
    let (client, _) = client_for(ctx, "origin")?;
    let show = |g: &veil_core::hub::wire::GroupInfo| {
        println!(
            "{}  members: {}  managers: {}",
            bold(&safe(&g.name)),
            if g.members.is_empty() { "-".into() } else { g.members.join(", ") },
            if g.managers.is_empty() { "-".into() } else { g.managers.join(", ") }
        );
    };
    match c {
        GroupCmd::List => {
            for g in client.groups()? {
                show(&g);
            }
        }
        GroupCmd::Create { name } => show(&client.group("POST", name, "", &[])?),
        GroupCmd::Add { group, people, confirm } => {
            // A fingerprint vouches for one person's device: with several
            // people, the server could list it under another, and the key
            // ring would record it under the wrong name (BUG-835).
            if !confirm.is_empty() && people.len() > 1 {
                bail!("--confirm confirms one person's devices: add {} one at a time", people.join(", "));
            }
            show(&client.group("POST", group, "/members", people)?);
            crate::hub_keys::group_added(ctx, &client, group, people, confirm)?;
        }
        GroupCmd::Remove { group, people } => {
            show(&client.group("POST", group, "/members/remove", people)?);
            crate::hub_keys::group_removed(ctx, &client, group, people)?;
        }
        GroupCmd::Manager { group, people } => show(&client.group("POST", group, "/managers", people)?),
    }
    Ok(())
}

pub fn admin(ctx: &mut Ctx, c: &AdminCmd) -> Result<()> {
    let (client, _) = client_for(ctx, "origin")?;
    let show = |a: &veil_core::hub::wire::AdminsInfo| {
        println!(
            "{}  {}",
            bold("admins:"),
            if a.admins.is_empty() {
                "-".into()
            } else {
                a.admins.iter().map(|s| safe(s)).collect::<Vec<_>>().join(", ")
            }
        );
    };
    match c {
        AdminCmd::List => show(&client.admins_list()?),
        AdminCmd::Add { people, confirm } => {
            if !confirm.is_empty() && people.len() > 1 {
                bail!("--confirm confirms one person's devices: add {} one at a time", people.join(", "));
            }
            show(&client.admins("", people)?);
            crate::hub_keys::admin_added(ctx, &client, people, confirm)?;
        }
        AdminCmd::Remove { people } => {
            show(&client.admins("/remove", people)?);
            crate::hub_keys::admin_removed(ctx, &client, people)?;
        }
    }
    Ok(())
}

/// The path of an access line, as written: `billing/`.
fn line_path(p: &str) -> String {
    format!("{}/", p.trim_matches('/'))
}

pub fn access(ctx: &mut Ctx, path: &str, who: &[String]) -> Result<()> {
    let norm = veil_core::hub::access::normalize_access_path(path).map_err(|e| anyhow!(e))?;
    if who.is_empty() {
        let (client, _) = client_for(ctx, "origin")?;
        let a = client.access(&norm)?;
        match &a.rule {
            Some(r) => println!("{}  decided by `{}` (.veilpolicy line {})", bold(&safe(&a.path)), safe(r), a.line.unwrap_or(0)),
            None => println!("{}  private: no access line covers it", bold(&safe(&a.path))),
        }
        if a.public {
            println!("  {}  everyone on Earth may read", green("public"));
        }
        if !a.groups.is_empty() {
            println!("  groups  {}", a.groups.join(", "));
        }
        if !a.people.is_empty() {
            println!("  people  {}", a.people.join(", "));
        }
        println!("  admins  {}", a.admins.join(", "));
        println!("  you     {}", if a.you_write { "read and write" } else { "read" });
        return Ok(());
    }
    for w in who {
        if w != "public" && !valid_principal_name(w) {
            bail!("'{w}' is not a group or person name (lowercase letters, digits, '-', '_', '.') or `public`");
        }
    }
    let file = VPath::new(POLICY_FILE)?;
    // Rewrites `.veilpolicy` in the directory (BUG-1125).
    let wc_lock = ctx.lock_dir(None)?;
    let text = String::from_utf8(ctx.fs.read(&file).unwrap_or_default()).context(".veilpolicy is not UTF-8")?;
    let new_line = format!("{:<24}{}", line_path(&norm), who.join(" "));
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    let mut replaced = false;
    // The last matching line decides: edit that one.
    for l in lines.iter_mut().rev() {
        let f = split_fields(l);
        let access = veil_core::policy::is_access_line(&f) || (f.len() == 2 && (f[1] == "public" || f[1] == "public!"));
        if access && !replaced && veil_core::hub::access::normalize_access_path(&f[0]).ok().as_deref() == Some(norm.as_str()) {
            *l = new_line.clone();
            replaced = true;
        }
    }
    if !replaced {
        lines.push(new_line.clone());
    }
    let mut out = lines.join("\n");
    out.push('\n');
    ctx.fs.write(&file, out.as_bytes())?;
    drop(wc_lock);
    println!("{} .veilpolicy: {}", if replaced { "Updated" } else { "Added to" }, safe(&new_line));
    println!("  Push it to apply (only admins may change access; the last matching line wins).");
    // The line's secrets get their own key (docs/HUB.md §13.12).
    let client = client_for(ctx, "origin").ok().map(|(c, _)| c);
    crate::hub_keys::access_changed(ctx, client.as_ref(), &norm)?;
    Ok(())
}

/// `vl invite PERSON --to GROUP`.
pub fn invite(ctx: &mut Ctx, person: &str, group: &str) -> Result<()> {
    let (client, _) = client_for(ctx, "origin")?;
    crate::hub_keys::invite(ctx, &client, person, group)
}

/// `vl share-keys`: one pass of the background key sharing.
pub fn share_keys(ctx: &mut Ctx) -> Result<()> {
    let (client, _) = client_for(ctx, "origin")?;
    crate::hub_keys::run_pass(ctx, &client)
}

/// `vl change new`: a commit through the server's API (`docs/HUB.md`
/// §13.13), with no working copy involved. In a clone of the project,
/// secret files are sealed with its keys (the server takes them only as
/// ciphertext); every file is scanned for secrets here first, so one never
/// leaves the device.
pub fn change(repository: Option<&Path>, cmd: &crate::cli::ChangeCmd) -> Result<ExitCode> {
    use veil_core::{
        hub::changes::{ChangeRequest, Edit, Expected, Onto, Status},
        object::Object,
        policy::{Policy, Tier},
        ObjectId,
    };
    let crate::cli::ChangeCmd::New {
        project,
        edits,
        base,
        message,
        onto,
        expected,
        change,
    } = cmd;
    // The clone here (or at -R), if it is one of this project's.
    let start = match repository {
        Some(p) => p.to_path_buf(),
        None => std::env::current_dir()?,
    };
    let clone = crate::ctx::find_root(&start).and_then(|r| Ctx::open(Some(&r), false).ok()).filter(|c| {
        let origin = c.repo.config().remotes.get("origin").and_then(|r| HubUrl::parse(&r.url)).and_then(|u| u.ok());
        match project {
            Some(p) => origin.is_some_and(|o| HubUrl::parse(p).and_then(|u| u.ok()) == Some(o)),
            None => origin.is_some(),
        }
    });
    let url = match (project, &clone) {
        (Some(p), _) => HubUrl::parse(p).ok_or_else(|| anyhow!("expected veil://host[:port]/project"))??,
        (None, Some(c)) => HubUrl::parse(&c.repo.config().remotes["origin"].url).expect("checked")?,
        (None, None) => bail!("give the project (veil://host[:port]/project), or run this in a clone of it"),
    };
    if url.project.is_empty() {
        bail!("give a project: veil://host[:port]/project");
    }
    let text = if edits.as_os_str() == "-" {
        let mut s = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut s)?;
        s
    } else {
        std::fs::read_to_string(edits).with_context(|| format!("reading {}", edits.display()))?
    };
    let mut list: Vec<Edit> = serde_json::from_str(&text).context("the edits: a JSON list of {\"path\", \"put\": {\"text\"}} or {\"path\", \"delete\": true}")?;
    let client = Client::new(&url, load_identity()?)?;
    let policy = match &clone {
        Some(c) => {
            let checked_out_from = c
                .wc()
                .ok()
                .and_then(|wc| c.repo.snapshot(&wc).ok())
                .map(|s| s.tree);
            c.repo.effective_policy_from(&*c.fs, checked_out_from.as_ref())?
        }
        None => Policy::builtin(),
    };
    let mut frames = Vec::new();
    let mut sealed = Vec::new();
    for e in &mut list {
        let path = VPath::new(&e.path)
            .ok()
            .filter(|p| !p.components().any(veil_core::object::is_reserved_name))
            .ok_or_else(|| anyhow!("'{}' is not a valid path", safe(&e.path)))?;
        let Some(put) = &mut e.put else { continue };
        if veil_core::secret_share::personal_key(path.as_str()) {
            bail!("'{}' is a personal private key: it never leaves your device", safe(&e.path));
        }
        if put.text.is_some() == put.object.is_some() {
            bail!("'{}': put must name either 'text' or 'object'", safe(&e.path));
        }
        let class = policy.classify(&path, false);
        match class.tier {
            Tier::Isolated | Tier::Ignored => bail!(
                "'{}' stays on this device (a personal key, or a secret file the project does not share){}",
                safe(&e.path),
                if clone.is_none() { "; in a clone of the project, a shared secret file is encrypted and sent" } else { "" }
            ),
            Tier::Cloaked(scope) => {
                let c = clone.as_ref().expect("only a clone's policy shares secrets");
                if let Some(obj_id) = put.object {
                    if let Ok(raw) = c.repo.store().get_raw(&obj_id) {
                        if Object::sealed_scope(&raw).as_deref() != Some(scope.as_str()) {
                            bail!("'{}' is a secret file: object {} is not sealed for scope '{}'", safe(&e.path), obj_id.short(), safe(&scope));
                        }
                    }
                }
                if let Some(content) = put.text.as_ref() {
                    let obj = c
                        .repo
                        .store()
                        .seal(&Object::Blob(content.as_bytes().to_vec()), &scope)
                        .with_context(|| format!("'{}' is a secret: this clone has no key to encrypt it", safe(&e.path)))?;
                    let raw = obj.encode();
                    let id = ObjectId::hash(&raw);
                    veil_core::hub::wire::put_frame(&mut frames, &id, &raw);
                    sealed.push(id);
                    put.object = Some(id);
                    put.text = None;
                }
            }
            Tier::Public if !class.allow_secrets => {
                if let Some(content) = put.text.as_ref() {
                    if let Some(f) = veil_core::secrets::scan(content.as_bytes()).first() {
                        bail!(
                            "'{}' looks like it holds a secret ({}, line {}): put secrets in a secret file such as .env",
                            safe(&e.path),
                            f.rule,
                            f.line
                        );
                    }
                }
            }
            Tier::Public => {}
        }
    }
    let mut receipts = std::collections::BTreeMap::new();
    if !frames.is_empty() {
        for (id, r) in sealed.iter().zip(client.upload(frames)?) {
            receipts.insert(*id, r);
        }
    }
    let base = match base {
        Some(b) => match ObjectId::from_hex(b) {
            Ok(id) => id,
            Err(_) => {
                let tips = client.tips()?.ok_or_else(|| anyhow!("no project {} that you can see", safe(&url.project)))?;
                if let Some(branch) = b.strip_suffix("@tested") {
                    *tips.tested.get(branch).ok_or_else(|| anyhow!("no tested snapshot on '{branch}' yet"))?
                } else {
                    *tips
                        .branches
                        .get(b.as_str())
                        .ok_or_else(|| anyhow!("--base takes a snapshot id (hex), a branch name, or <branch>@tested"))?
                }
            }
        },
        None => {
            let tips = client.tips()?.ok_or_else(|| anyhow!("no project {} that you can see", safe(&url.project)))?;
            let branch = onto.clone().unwrap_or(tips.default_branch.clone());
            tips.tested
                .get(&branch)
                .or_else(|| tips.branches.get(&branch))
                .copied()
                .ok_or_else(|| anyhow!("no branch '{}' to start from: give --base", safe(&branch)))?
        }
    };
    let req = ChangeRequest {
        base,
        change_id: change.as_deref().map(veil_core::ChangeId::parse).transpose().map_err(|_| anyhow!("--change takes a change id"))?,
        description: message.clone().unwrap_or_default(),
        edits: list,
        onto: match onto {
            Some(b) => Some(Onto {
                branch: b.clone(),
                expected: match expected {
                    Some(t) => Expected::Tip(ObjectId::from_hex(t).map_err(|_| anyhow!("--expected takes a snapshot id (hex)"))?),
                    None => Expected::Rebase,
                },
            }),
            None => None,
        },
        receipts,
    };
    let r = client.change(&req)?;
    println!("Change {} (snapshot {})", bold(&r.change_id.to_string()), r.snapshot.hex());
    for w in &r.warnings {
        println!("  {}", yellow(&safe(w)));
    }
    Ok(match r.branch {
        None => ExitCode::SUCCESS,
        Some(b) if b.status == Status::Ok => {
            let again = match b.rebased {
                0 => String::new(),
                1 => " (applied to its new tip)".into(),
                n => format!(" (applied to its new tip; {n} tries)"),
            };
            println!("{} {}{again}", green("Moved"), safe(&b.branch));
            ExitCode::SUCCESS
        }
        Some(b) => {
            eprintln!(
                "{} did not move: {}. The change is kept on the server (the snapshot above); \
                 make a new revision of it on the new tip with `--change {}`",
                safe(&b.branch),
                safe(b.message.as_deref().unwrap_or("rejected")),
                r.change_id
            );
            ExitCode::FAILURE
        }
    })
}
