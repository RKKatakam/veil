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
    identity::parse_public_identity,
    keychain::Role,
    policy::{split_fields, valid_principal_name, Policy, Tier, POLICY_FILE},
    repo::{RemoteConfig, DEFAULT_WORKSPACE},
    DiskBackend, Repo, StorageBackend, VPath,
};

use crate::{
    cli::GroupCmd,
    ctx::{load_identity, user_for, Ctx},
    hub::{self, Client, HubUrl},
    render::{bold, cyan, dim, green, safe, warn, warn_untrusted, yellow},
};

/// Is remote `name` a Veil server?
fn client_for(ctx: &Ctx, remote: &str) -> Result<(Client, RemoteConfig)> {
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

/// `vl identity confirm FINGERPRINT`: vouch, with this device's key, for
/// the device of this person's with that fingerprint (`docs/HUB.md`
/// §13.11). The fingerprint is read off the new device by its owner, so
/// the server cannot substitute another device.
pub fn confirm_device(fingerprint: &str, server: Option<&str>) -> Result<()> {
    let fp = veil_core::hub::wire::normalize_fingerprint(fingerprint)
        .ok_or_else(|| anyhow!("a device fingerprint is 20 hex digits, as `vl identity show` prints it (4F2A-9C1E-…)"))?;
    let servers = hub::signed_in_servers()?;
    let (authority, me) = match server {
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
    };
    let url = HubUrl::parse(&format!("veil://{authority}")).ok_or_else(|| anyhow!("bad server"))??;
    let client = Client::new(&url, load_identity()?)?;
    let devices = client.devices(&me)?;
    let device = devices
        .identities
        .iter()
        .chain(&devices.pending)
        .find(|d| hub::fingerprint(d).as_deref() == Some(fp.as_str()))
        .ok_or_else(|| anyhow!("none of {me}'s devices on {authority} has the fingerprint {fp}: check it on the new device (`vl identity show`)"))?
        .clone();
    client.vouch(&device)?;
    println!("Confirmed device {} as {}'s on {}", bold(&fp), safe(&me), safe(&authority));
    println!("  it may sign in now (`vl login`); admins grant it secret keys when they next add you to a group");
    Ok(())
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
    crate::ctx::mark_clone_incomplete(&fs)?;
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

pub fn push(ctx: &mut Ctx, remote: &str, tags: &[String], force: bool, verify: &crate::hooks::NoVerifyArgs) -> Result<ExitCode> {
    let (client, cfg) = client_for(ctx, remote)?;
    crate::hooks::before_push(ctx, verify, remote, &cfg.url, tags)?;
    let out = hub::push(&mut ctx.repo, remote, &client, tags, force)?;
    if out.created {
        println!("Created project {} on {}: you are its admin, and everything is private", client.url.project, client.url.authority);
    }
    for (b, tip) in &out.moved {
        println!("  {} {} → {}", green("pushed"), cyan(&safe(b)), tip.short());
    }
    for w in &out.warnings {
        println!("  {} {}", dim("note:"), safe(w));
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

/// The devices of `person` that are vouched for outside the server
/// (`docs/HUB.md` §13.11), as listed public identities: those whose
/// signing key a verified key ring records under `person`, those whose
/// fingerprint is in `confirm` (each match is removed from it), and,
/// repeatedly, those with a vouch that verifies under one of these
/// devices' keys. The server's list alone never makes a device trusted.
fn confirmed_devices(
    person: &str,
    devices: &veil_core::hub::wire::Devices,
    rings: &[veil_core::keychain::RingState],
    confirm: &mut Vec<String>,
) -> Vec<String> {
    let mut keys: std::collections::HashSet<String> = rings
        .iter()
        .flat_map(|st| st.members.values())
        .filter(|m| m.name == person)
        .filter_map(|m| m.signing_key.clone())
        .collect();
    // Listed devices with a binding (the identity's keys belong together).
    let listed: Vec<(&String, String, String)> = devices
        .identities
        .iter()
        .filter_map(|i| {
            let p = parse_public_identity(i).ok().filter(|p| p.binding.is_some())?;
            Some((i, p.signing_hex()?, veil_core::hub::wire::device_fingerprint(&p)?))
        })
        .collect();
    for (_, key, fp) in &listed {
        if let Some(at) = confirm.iter().position(|c| c == fp) {
            confirm.remove(at);
            keys.insert(key.clone());
        }
    }
    loop {
        let before = keys.len();
        for v in &devices.vouches {
            if !keys.contains(&v.by) || !veil_core::hub::wire::vouch_valid(v) {
                continue;
            }
            let Some(fp) = hub::fingerprint(&v.device) else { continue };
            if let Some((_, key, _)) = listed.iter().find(|(_, _, f)| *f == fp) {
                keys.insert(key.clone());
            }
        }
        if keys.len() == before {
            break;
        }
    }
    listed.into_iter().filter(|(_, k, _)| keys.contains(k)).map(|(i, _, _)| i.clone()).collect()
}

/// Grant (or revoke) the secret scopes to `people`, signed by this device
/// as a ring admin, and send the rings. The server's group list is never
/// what wraps a key: this admin's signature is (`docs/HUB.md` §6), and
/// only for devices vouched for outside the server (§13.11). Revoking
/// takes every ring member recorded under the person's name, not only the
/// devices the server lists.
fn sync_secret_keys(ctx: &mut Ctx, client: &Client, group: &str, people: &[String], grant: bool, confirm: &[String]) -> Result<()> {
    let keys = ctx.repo.keys();
    let me = load_identity()?;
    let mut rings = Vec::new();
    let mut admin_of = Vec::new();
    for scope in secret_scopes(ctx) {
        let Some(Ok(state)) = keys.ring_state(&scope)? else { continue };
        if state.members.get(&me.public_hex()).is_some_and(|m| m.role == Role::Admin) {
            admin_of.push(scope);
        }
        rings.push(state);
    }
    let admin_somewhere = !admin_of.is_empty();
    let mut confirm: Vec<String> = confirm
        .iter()
        .map(|c| {
            veil_core::hub::wire::normalize_fingerprint(c)
                .ok_or_else(|| anyhow!("'{c}' is not a device fingerprint (20 hex digits, as `vl identity show` prints it)"))
        })
        .collect::<Result<_>>()?;
    // Decide everything first: a fingerprint that matches nothing stops
    // the command before any key is wrapped.
    let mut plan: Vec<(String, String)> = Vec::new(); // (person, device or member id)
    let mut unconfirmed: Vec<(String, String)> = Vec::new(); // (person, fingerprint)
    if admin_somewhere {
        for person in people {
            let devices = client.devices(person)?;
            if grant {
                let ok = confirmed_devices(person, &devices, &rings, &mut confirm);
                for id in &devices.identities {
                    if ok.contains(id) {
                        plan.push((person.clone(), id.clone()));
                    } else {
                        unconfirmed.push((person.clone(), hub::fingerprint(id).unwrap_or_else(|| "(no signing key)".into())));
                    }
                }
            } else {
                let mut gone: Vec<String> = devices
                    .identities
                    .iter()
                    .filter_map(|i| parse_public_identity(i).ok().map(|p| p.member_id()))
                    .collect();
                for st in &rings {
                    gone.extend(st.members.iter().filter(|(id, m)| m.name == *person && **id != me.public_hex()).map(|(id, _)| id.clone()));
                }
                gone.sort();
                gone.dedup();
                plan.extend(gone.into_iter().map(|g| (person.clone(), g)));
            }
        }
    }
    if admin_somewhere && !confirm.is_empty() {
        bail!(
            "no device of {} on the server has the fingerprint {}: the server lists a different device than the one you \
             checked. No secret key was granted",
            people.join(", "),
            confirm.join(", ")
        );
    }
    let mut changed = Vec::new();
    for scope in &admin_of {
        let Some(Ok(state)) = keys.ring_state(scope)? else { continue };
        for (person, id) in &plan {
            let member = parse_public_identity(id)?.member_id();
            let has = state.members.contains_key(&member);
            if grant && !has {
                keys.grant_role(scope, id, person, Role::Member)?;
                changed.push(scope.clone());
            } else if !grant && has {
                keys.revoke_with_vault(scope, id)?;
                changed.push(scope.clone());
            }
        }
    }
    for (person, fp) in &unconfirmed {
        println!("  {} confirm {}'s device: {}", yellow("keys:"), safe(person), bold(fp));
        println!(
            "        compare it with `vl identity show` on their device, then: vl group add {} {} --confirm {}",
            safe(group),
            safe(person),
            fp
        );
    }
    if grant && !admin_somewhere {
        warn(
            "they get the project's secret keys (.env and the like) only when a key-ring admin's device signs them in: \
             ask a project admin to run this `vl group add` too",
        );
    }
    // A manager's clone may not read `.veilpolicy`: the server's rings say
    // whether the project has secret keys at all.
    if !grant && !admin_somewhere && client.rings().is_ok_and(|r| !r.is_empty()) {
        warn(&format!(
            "the secret key was not rotated: only a key-ring admin's device rotates it. Until then {} can open new secrets \
             if they get them; ask a project admin to run this `vl group remove` too",
            people.join(", ")
        ));
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
        let whom: Vec<&str> = plan.iter().map(|(p, _)| p.as_str()).collect::<std::collections::BTreeSet<_>>().into_iter().collect();
        println!(
            "  {} the '{scope}' secret key {} {}",
            dim("keys:"),
            if grant { "granted to" } else { "rotated away from" },
            whom.join(", ")
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
        GroupCmd::Add { group, people, confirm } => {
            // A fingerprint vouches for one person's device: with several
            // people, the server could list it under another, and the key
            // ring would record it under the wrong name (BUG-835).
            if !confirm.is_empty() && people.len() > 1 {
                bail!("--confirm confirms one person's devices: add {} one at a time", people.join(", "));
            }
            show(&client.group("POST", group, "/members", people)?);
            sync_secret_keys(ctx, &client, group, people, true, confirm)?;
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
            // The server's group list decides this: never silently
            // (BUG-836).
            for person in people.iter().filter(|p| !gone.contains(p)) {
                let other: Vec<&str> = groups.iter().filter(|g| g.members.contains(person)).map(|g| g.name.as_str()).collect();
                println!(
                    "  {} {} is still in {}: the secret key was not rotated away from them",
                    yellow("keys:"),
                    safe(person),
                    safe(&other.join(", "))
                );
            }
            if !gone.is_empty() {
                sync_secret_keys(ctx, &client, group, &gone, false, &[])?;
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
    println!("{} .veilpolicy: {}", if replaced { "Updated" } else { "Added to" }, safe(&new_line));
    println!("  Push it to apply (only admins may change access; the last matching line wins).");
    Ok(())
}
