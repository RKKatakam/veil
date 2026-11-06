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
    checkout::Materialised,
    identity::parse_public_identity,
    keychain::Role,
    policy::{split_fields, valid_principal_name, Policy, Tier, POLICY_FILE},
    repo::{RemoteConfig, DEFAULT_WORKSPACE},
    DiskBackend, Repo, StorageBackend, VPath,
};

use crate::{
    cli::GroupCmd,
    ctx::{load_identity, save_checkout, user_for, CheckoutState, Ctx},
    hub::{self, Client, HubUrl},
    render::{bold, cyan, dim, green, safe, warn, warn_untrusted, yellow},
};

/// Is remote `name` a Veil server?
pub fn is_hub_remote(ctx: &Ctx, name: &str) -> bool {
    ctx.repo.config().remotes.get(name).is_some_and(|r| hub::is_hub_url(&r.url))
}

fn client_for(ctx: &Ctx, remote: &str) -> Result<(Client, RemoteConfig)> {
    let r = ctx
        .repo
        .config()
        .remotes
        .get(remote)
        .cloned()
        .ok_or_else(|| anyhow!("no remote named '{remote}'"))?;
    let url = HubUrl::parse(&r.url).ok_or_else(|| anyhow!("remote '{remote}' is not a Veil server (veil://host/project)"))??;
    Ok((Client::new(&url, load_identity()?)?, r))
}

pub fn login(url: &str, name: Option<&str>, ca: Option<&Path>) -> Result<ExitCode> {
    let u = HubUrl::parse(url).ok_or_else(|| anyhow!("expected veil://host[:port] or https://host[:port]"))??;
    if let Some(ca) = ca {
        let pem = std::fs::read_to_string(ca).with_context(|| format!("reading {}", ca.display()))?;
        Client::trust_ca(&u.authority, &pem)?;
    }
    let client = Client::new(&u, load_identity()?)?;
    let s = client.login(name)?;
    println!("Signed in to {} as {}", safe(&u.authority), bold(&safe(&s.person)));
    println!("  server key {}", dim(&s.hub_key));
    Ok(ExitCode::SUCCESS)
}

pub fn clone(url: &HubUrl, dest: Option<&Path>, only: Option<&str>) -> Result<ExitCode> {
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
    let created = !dest.exists();
    std::fs::create_dir_all(&dest)?;
    let dest = dest.canonicalize()?;
    let r = clone_populate(url, &dest, only.as_deref());
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

fn clone_populate(url: &HubUrl, dest: &Path, only: Option<&str>) -> Result<ExitCode> {
    let identity = load_identity()?;
    let client = Client::new(url, identity.clone())?;
    let fs = Arc::new(DiskBackend::new(dest));
    let mut repo = Repo::init_for_clone_at(fs.clone(), Some(identity.clone()), &user_for(&identity), veil_core::repo::REPO_FORMAT)?;
    let mut config = repo.config().clone();
    config.remotes.insert(
        "origin".into(),
        RemoteConfig {
            url: format!("veil://{}/{}", url.authority, url.project),
            public: false,
            only: only.map(str::to_string),
        },
    );
    repo.save_config(config)?;
    let report = hub::pull(&mut repo, "origin", &client, only)?;
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
    let mut record = Materialised::default();
    let co = repo.checkout_tree_recorded(&*fs, None, &to, &mut record, None)?;
    save_checkout(&fs, &CheckoutState::new(DEFAULT_WORKSPACE, wc, record))?;
    println!(
        "Cloned {} into {} ({} objects, {} files{})",
        safe(&format!("veil://{}/{}", url.authority, url.project)),
        dest.display(),
        report.objects_copied,
        co.written,
        only.map(|o| format!(", only {o}/")).unwrap_or_default()
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
    let r = hub::pull(&mut ctx.repo, remote, &client, cfg.only.as_deref())?;
    for (t, id) in &r.tags_updated {
        println!("  {} {} → {}", green("updated"), cyan(&safe(t)), id.short());
    }
    for w in &r.warnings {
        warn_untrusted(w);
    }
    println!("Pulled {} object(s) from {remote}", r.objects_copied);
    Ok(())
}

pub fn push(ctx: &mut Ctx, remote: &str, tags: &[String], force: bool) -> Result<ExitCode> {
    let (client, _) = client_for(ctx, remote)?;
    let out = hub::push(&mut ctx.repo, remote, &client, tags, force)?;
    if out.created {
        println!("Created project {} on {}: you are its admin, and everything is private", client.url.project, client.url.authority);
    }
    for (b, tip) in &out.moved {
        println!("  {} {} → {}", green("pushed"), cyan(&safe(b)), tip.short());
    }
    for (b, why) in &out.rejected {
        println!("  {} {}: {}", yellow("rejected"), cyan(&safe(b)), safe(why));
    }
    if out.moved.is_empty() && out.rejected.is_empty() {
        println!("Everything up to date");
    } else {
        println!("Sent {} object(s) to {remote}", out.uploaded);
    }
    Ok(if out.rejected.is_empty() { ExitCode::SUCCESS } else { ExitCode::from(1) })
}

/// The scopes that seal secrets in this project: those named by `cloak`
/// lines of the working copy's `.veilpolicy`.
fn secret_scopes(ctx: &Ctx) -> Vec<String> {
    let text = ctx.fs.read(&VPath::new(POLICY_FILE).unwrap()).unwrap_or_default();
    let mut out: Vec<String> = Vec::new();
    for r in Policy::parse(&String::from_utf8_lossy(&text)).rules() {
        if let Tier::Cloaked(s) = &r.tier {
            if !out.contains(s) {
                out.push(s.clone());
            }
        }
    }
    out
}

/// Grant (or revoke) the secret scopes to every registered device of
/// `people`, signed by this device as a ring admin, and send the rings.
/// The server's group list is never what wraps a key: this admin's
/// signature is (`docs/HUB.md` §6).
fn sync_secret_keys(ctx: &mut Ctx, client: &Client, people: &[String], grant: bool) -> Result<()> {
    let keys = ctx.repo.keys();
    let mut changed = Vec::new();
    for scope in secret_scopes(ctx) {
        let Some(Ok(state)) = keys.ring_state(&scope)? else { continue };
        let me = load_identity()?;
        let admin = state
            .members
            .get(&me.public_hex())
            .is_some_and(|m| m.role == Role::Admin);
        if !admin {
            if grant {
                warn(&format!(
                    "you are not an admin of the '{scope}' key ring: the new people cannot open its secrets until a ring admin adds them"
                ));
            }
            continue;
        }
        for person in people {
            let devices = client.devices(person)?;
            for id in &devices.identities {
                let member = parse_public_identity(id)?.member_id();
                let has = state.members.contains_key(&member);
                if grant && !has {
                    keys.grant_role(&scope, id, person, Role::Member)?;
                    changed.push(scope.clone());
                } else if !grant && has {
                    keys.revoke_with_vault(&scope, id)?;
                    changed.push(scope.clone());
                }
            }
        }
    }
    changed.dedup();
    let rings: Vec<_> = changed.iter().filter_map(|s| keys.load_ring(s).ok().flatten()).collect();
    for ring in &rings {
        client.post_ring(ring)?;
    }
    for scope in &changed {
        ctx.repo.record_outside_view(
            format!("{} secret keys of scope {scope}", if grant { "grant" } else { "revoke" }),
            "key rings are append-only".to_string(),
        )?;
        println!(
            "  {} the '{scope}' secret key {} {}",
            dim("keys:"),
            if grant { "granted to" } else { "rotated away from" },
            people.join(", ")
        );
    }
    Ok(())
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
        GroupCmd::Add { group, people } => {
            show(&client.group("POST", group, "/members", people)?);
            sync_secret_keys(ctx, &client, people, true)?;
        }
        GroupCmd::Remove { group, people } => {
            show(&client.group("POST", group, "/members/remove", people)?);
            // Rotate the secrets away from people now in no group at all.
            let groups = client.groups()?;
            let gone: Vec<String> = people
                .iter()
                .filter(|p| !groups.iter().any(|g| g.members.contains(p)))
                .cloned()
                .collect();
            if !gone.is_empty() {
                sync_secret_keys(ctx, &client, &gone, false)?;
            }
        }
        GroupCmd::Manager { group, people } => show(&client.group("POST", group, "/managers", people)?),
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
    let text = String::from_utf8(ctx.fs.read(&file).unwrap_or_default()).context(".veilpolicy is not UTF-8")?;
    let new_line = format!("{:<24}{}", line_path(&norm), who.join(" "));
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    let mut replaced = false;
    for l in lines.iter_mut() {
        let f = split_fields(l);
        if veil_core::policy::is_access_line(&f) || (f.len() == 2 && (f[1] == "public" || f[1] == "public!")) {
            if veil_core::hub::access::normalize_access_path(&f[0]).ok().as_deref() == Some(norm.as_str()) && !replaced {
                *l = new_line.clone();
                replaced = true;
            }
        }
    }
    if !replaced {
        lines.push(new_line.clone());
    }
    let mut out = lines.join("\n");
    out.push('\n');
    ctx.fs.write(&file, out.as_bytes())?;
    println!("{} .veilpolicy: {}", if replaced { "Updated" } else { "Added to" }, safe(&new_line));
    println!("  Push it to apply (only admins may change access; the last matching line wins).");
    Ok(())
}
