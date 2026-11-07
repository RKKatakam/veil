//! Person-to-person secret shares (`docs/HUB.md` §13.13): `vl secret share
//! PATH --with PERSON`, `vl secret unshare PATH --from PERSON`, `vl secret
//! shares`, and the background pass that keeps them up to date.
//!
//! * **A share is a copy of one secret file**, sealed on the sharer's device
//!   for the recipient's **confirmed** devices (and the sharing device), and
//!   signed by it (`veil_core::secret_share`). It holds no key of the access
//!   line that covers the file: it opens that one file, nothing else.
//! * **Confirmed means confirmed outside the server**, as for every key
//!   (`hub_keys::person_devices`): a device a verified key ring holds under
//!   the person's name, one the sharer compared by fingerprint
//!   (`--confirm`), one with a join under an invite for them, or one vouched
//!   for by one of these. A device a ring once held and revoked counts only
//!   if a ring holds it again or the sharer compares it again.
//! * **Updates:** the sharing device's background pass seals a new version
//!   when its copy of the file changes, or when the recipient's confirmed
//!   devices change (a new one is added; a removed one is left out of every
//!   later version). Unsharing stops every later version; it cannot take
//!   back what the recipient already received.
//! * **Delivery:** the recipient's `vl pull`, `vl secret shares` and
//!   background pass write the file at its path, where it stays on their
//!   device (an isolated file: never recorded, backed up in the local vault,
//!   given to agents by `vl ws exec --with-isolated`). Each version is
//!   checked first: signed by a device a verified key ring holds under the
//!   sharer's name, for this project, newer than the last one received. A
//!   file the recipient changed is never written over.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use veil_core::{
    identity::parse_public_identity,
    policy::{valid_principal_name, Policy, Tier, DEFAULT_SCOPE, RULE_SCOPE, SYNCED_SECRETS_POLICY},
    secret_share::{shareable, ShareInfo, SharePut, ShareRecord, ShareTarget, MAX_SHARE_BYTES},
    StorageBackend, VPath,
};

use crate::{
    api,
    ctx::{load_identity, Ctx},
    hub::{self, Client},
    hub_keys::{local_states, person_devices, How},
    render::{bold, dim, fmt_time, green, safe, warn, warn_untrusted, yellow},
};

pub const SHARE_SCHEMA: &str = "veil.secret.share/1";
pub const SHARES_SCHEMA: &str = "veil.secret.shares/1";

/// Device-local memory of this clone's shares: the last version received of
/// each (sharer, path), kept to refuse an older one and to recognise the
/// copy this clone wrote. Records only (ciphertext for this device).
const STATE_FILE: &str = ".veil/local/secret-shares.json";

#[derive(Default, Serialize, Deserialize)]
struct State {
    #[serde(default)]
    received: BTreeMap<String, ShareRecord>,
}

fn state_key(sharer: &str, path: &str) -> String {
    format!("{sharer}\u{0}{path}")
}

fn load_state(ctx: &Ctx) -> State {
    VPath::new(STATE_FILE)
        .ok()
        .and_then(|p| ctx.fs.read_opt(&p).ok().flatten())
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn save_state(ctx: &Ctx, st: &State) -> Result<()> {
    ctx.fs.write(&VPath::new(STATE_FILE)?, &serde_json::to_vec(st)?)?;
    Ok(())
}

/// Does this clone take part in shares (it made or received one)? Then the
/// background pass runs here even without a key of its own.
pub fn takes_part(ctx: &Ctx) -> bool {
    VPath::new(STATE_FILE).is_ok_and(|p| ctx.fs.exists(&p).unwrap_or(false))
}

/// The client of this clone's server, and who this device is there.
fn client(ctx: &Ctx) -> Result<(Client, String)> {
    let (client, _) = crate::hub_cmd::client_for(ctx, "origin")?;
    let me = hub::signed_in_servers()?
        .into_iter()
        .find(|(a, _)| *a == client.url.authority)
        .map(|(_, p)| p)
        .ok_or_else(|| anyhow!("this device is not signed in to {} (`vl login`)", client.url.authority))?;
    Ok((client, me))
}

/// The project this clone's device trusts the key rings of (BUG-845): what
/// every share is bound to.
fn project_id(ctx: &Ctx) -> Result<String> {
    ctx.repo.keys().project_id().filter(|_| ctx.repo.keys().anchor().is_some_and(|a| !a.is_empty())).ok_or_else(|| {
        anyhow!(
            "this device does not trust this project's key rings yet: compare the project's fingerprint with an admin, \
             then run `vl identity confirm FINGERPRINT` here (`vl pull` shows the one the server claims)"
        )
    })
}

/// A recipient's devices: those a share may be sealed for (member id, full
/// identity), and the fingerprints of the listed ones nothing confirms.
type Recipient = (Vec<(String, String)>, Vec<String>);

fn recipient_devices(ctx: &Ctx, client: &Client, person: &str, confirm: &[String]) -> Result<Recipient> {
    let rings = local_states(ctx);
    let pd = person_devices(ctx, client, &[person.to_string()], confirm)?.pop().ok_or_else(|| anyhow!("no devices"))?;
    let mut ok = Vec::new();
    for (id, how) in &pd.confirmed {
        let Ok(p) = parse_public_identity(id) else { continue };
        let member = p.member_id();
        // A device a ring took the key from keeps its person's old vouch: it
        // counts again only if a ring holds it now, or the sharer compared
        // its fingerprint in this command.
        let revoked = rings.iter().any(|st| {
            !st.members.contains_key(&member)
                && (st.ever_members.contains(&member) || p.signing_hex().is_some_and(|k| st.ever_signers.contains_key(&k)))
        });
        if revoked && !matches!(how, How::Ring | How::Fingerprint) {
            continue;
        }
        ok.push((member, id.clone()));
    }
    let unconfirmed = pd
        .devices
        .identities
        .iter()
        .filter(|i| !ok.iter().any(|(_, x)| x == *i))
        .filter_map(|i| hub::fingerprint(i))
        .collect();
    Ok((ok, unconfirmed))
}

/// The share of `path` with `recipient` on the server, if any.
fn find<'a>(shares: &'a [ShareInfo], me: &str, path: &str, recipient: &str) -> Option<&'a ShareInfo> {
    shares.iter().find(|s| s.sharer == me && s.path == path && s.recipient == recipient)
}

#[derive(Serialize)]
struct ShareDoc {
    schema: &'static str,
    path: String,
    recipient: String,
    version: u64,
    /// `shared`, `unshared`.
    action: &'static str,
    /// Fingerprints of the recipient's devices this version is sealed for.
    devices: Vec<String>,
    /// Their listed devices nobody confirmed: not sealed for.
    unconfirmed: Vec<String>,
}

/// `vl secret share PATH --with PERSON [--confirm FINGERPRINT]`.
pub fn share(ctx: &mut Ctx, path: &str, with: &str, confirm: &[String], json: bool) -> Result<()> {
    let (client, me) = client(ctx)?;
    let identity = load_identity()?;
    if with == me {
        bail!("share it with someone else: you are {me}");
    }
    if !valid_principal_name(with) {
        bail!("'{}' is not a person's name (lowercase letters, digits, '-', '_', '.')", safe(with));
    }
    let vp = ctx.repo_path(path)?;
    secret_path(ctx, vp.as_str()).map_err(|e| anyhow!(e))?;
    let content = ctx.fs.read_opt(&vp)?.ok_or_else(|| anyhow!("there is no file {} in the working copy", safe(vp.as_str())))?;
    if content.len() > MAX_SHARE_BYTES {
        bail!("{} is {} bytes; a share carries at most {} KiB", safe(vp.as_str()), content.len(), MAX_SHARE_BYTES >> 10);
    }
    let project = project_id(ctx)?;
    let (devices, unconfirmed) = recipient_devices(ctx, &client, with, confirm)?;
    if devices.is_empty() {
        print_unconfirmed(with, vp.as_str(), &unconfirmed);
        bail!(
            "no device of {} is confirmed: nothing was shared. Compare a fingerprint above with what `vl identity show` \
             prints on their device, then run this again with `--confirm FINGERPRINT`",
            safe(with)
        );
    }
    let mut ids: Vec<String> = devices.iter().map(|(m, _)| m.clone()).collect();
    ids.push(identity.public_hex());
    let mut version = 0;
    for attempt in 0..8u64 {
        let expect = find(&client.shares()?, &me, vp.as_str(), with).map_or(0, |s| s.version);
        let target = ShareTarget {
            project: &project,
            path: vp.as_str(),
            sharer: &me,
            recipient: with,
            version: expect + 1,
        };
        let record = ShareRecord::seal(&identity, &target, veil_core::now_millis(), &content, &ids)?;
        match client.put_share(&SharePut { expect, reshare: true, record })? {
            Ok(()) => {
                version = expect + 1;
                break;
            }
            Err(_) if attempt < 7 => std::thread::sleep(std::time::Duration::from_millis(20 + attempt * 40)),
            Err(why) => bail!("the share kept changing on the server: {why}"),
        }
    }
    save_state(ctx, &load_state(ctx))?;
    ctx.repo.record_outside_view(
        format!("share secret {} with {with}", vp.as_str()),
        format!(
            "shares are not part of the operation log, and {with} may have received it already: end it with \
             `vl secret unshare {} --from {with}`",
            vp.as_str()
        ),
    )?;
    let fps: Vec<String> = devices.iter().filter_map(|(_, i)| hub::fingerprint(i)).collect();
    if json {
        return api::emit_json(&ShareDoc {
            schema: SHARE_SCHEMA,
            path: vp.as_str().to_string(),
            recipient: with.to_string(),
            version,
            action: "shared",
            devices: fps,
            unconfirmed,
        });
    }
    println!(
        "Shared {} with {} (version {version}, {} device{})",
        bold(&safe(vp.as_str())),
        bold(&safe(with)),
        fps.len(),
        if fps.len() == 1 { "" } else { "s" }
    );
    println!(
        "  {} only {}'s confirmed devices and yours can open it; admins see that it is shared, never what it holds",
        dim("note:"),
        safe(with)
    );
    println!("  {} your later edits of it, and their new devices, reach them in the background until you unshare it", dim("note:"));
    print_unconfirmed(with, vp.as_str(), &unconfirmed);
    Ok(())
}

fn print_unconfirmed(person: &str, path: &str, fps: &[String]) {
    for fp in fps {
        println!("  {} confirm {}'s device: {}", yellow("keys:"), safe(person), bold(fp));
        println!(
            "        compare it with `vl identity show` on their device, then: vl secret share {} --with {} --confirm {fp}",
            safe(path),
            safe(person)
        );
    }
}

/// `vl secret unshare PATH --from PERSON`.
pub fn unshare(ctx: &mut Ctx, path: &str, from: &str, json: bool) -> Result<()> {
    let (client, _) = client(ctx)?;
    let vp = ctx.repo_path(path)?;
    let info = client.remove_share(vp.as_str(), from)?;
    ctx.repo.record_outside_view(
        format!("unshare secret {} from {from}", vp.as_str()),
        format!("shares are not part of the operation log; share it again with `vl secret share {} --with {from}`", vp.as_str()),
    )?;
    if json {
        return api::emit_json(&ShareDoc {
            schema: SHARE_SCHEMA,
            path: info.path,
            recipient: info.recipient,
            version: info.version,
            action: "unshared",
            devices: vec![],
            unconfirmed: vec![],
        });
    }
    println!("Unshared {} from {}", bold(&safe(vp.as_str())), bold(&safe(from)));
    println!(
        "  {} {} keeps what they already received (an unshare cannot take that back) and gets no later version. \
         Rotate the secret if that matters",
        yellow("note:"),
        safe(from)
    );
    Ok(())
}

#[derive(Serialize)]
struct SharesDoc {
    schema: &'static str,
    shares: Vec<ShareItem>,
}

#[derive(Serialize)]
struct ShareItem {
    path: String,
    sharer: String,
    recipient: String,
    version: u64,
    created_at: i64,
    updated_at: i64,
    unshared_at: Option<i64>,
    active: bool,
    paused: Option<String>,
}

/// `vl secret shares`: the shares you make and receive (admins: every
/// share of the project), never their content. Delivers what is new for you
/// first.
pub fn list(ctx: &mut Ctx, json: bool) -> Result<()> {
    let (client, me) = client(ctx)?;
    let shares = client.shares()?;
    let notes = receive(ctx, &me, &shares);
    let items: Vec<ShareItem> = shares
        .into_iter()
        .map(|s| ShareItem {
            path: s.path,
            sharer: s.sharer,
            recipient: s.recipient,
            version: s.version,
            created_at: s.created_at,
            updated_at: s.updated_at,
            unshared_at: s.unshared_at,
            active: s.active,
            paused: s.paused,
        })
        .collect();
    if json {
        for n in &notes {
            eprintln!("{} {}", dim("shares:"), safe(n));
        }
        return api::emit_json(&SharesDoc { schema: SHARES_SCHEMA, shares: items });
    }
    for n in &notes {
        println!("{} {}", dim("shares:"), safe(n));
    }
    if items.is_empty() {
        println!("No secret shares");
    }
    for s in &items {
        let state = match (&s.unshared_at, &s.paused) {
            (Some(t), _) => dim(&format!("ended {}", fmt_time(*t))),
            (None, Some(why)) => yellow(&format!("paused: {}", safe(why))),
            (None, None) => green("active"),
        };
        println!(
            "{}  {} → {}  version {}  since {}  {state}",
            bold(&safe(&s.path)),
            safe(&s.sharer),
            safe(&s.recipient),
            s.version,
            fmt_time(s.created_at)
        );
    }
    Ok(())
}

/// After `vl pull` from a server: deliver what is new for this device.
pub fn after_pull(ctx: &mut Ctx, client: &Client) {
    let Some(me) = hub::signed_in_servers().ok().and_then(|v| v.into_iter().find(|(a, _)| *a == client.url.authority)).map(|(_, p)| p) else {
        return;
    };
    match client.shares() {
        Ok(shares) => {
            for n in receive(ctx, &me, &shares) {
                println!("  {} {}", dim("shares:"), safe(&n));
            }
        }
        Err(e) => warn(&format!("secret shares not checked: {e:#}")),
    }
}

/// The background pass (`vl share-keys`): keep this device's shares up to
/// date, then deliver what is new for it. What it did, one line each.
pub fn pass(ctx: &mut Ctx, client: &Client) -> Result<Vec<String>> {
    let Some(me) = hub::signed_in_servers()?.into_iter().find(|(a, _)| *a == client.url.authority).map(|(_, p)| p) else {
        return Ok(vec![]);
    };
    let shares = client.shares()?;
    let mut out = Vec::new();
    if shares.iter().any(|s| s.sharer == me && s.active) {
        out.extend(update(ctx, client, &me, &shares)?);
    }
    out.extend(receive(ctx, &me, &shares));
    if !shares.is_empty() && !takes_part(ctx) {
        save_state(ctx, &load_state(ctx))?;
    }
    Ok(out)
}

/// Seal a new version of each active share this device made whose file
/// changed here, or whose recipient's confirmed devices changed.
fn update(ctx: &mut Ctx, client: &Client, me: &str, shares: &[ShareInfo]) -> Result<Vec<String>> {
    let identity = load_identity()?;
    let project = project_id(ctx)?;
    let mut out = Vec::new();
    // Each recipient's devices, asked once per pass.
    let mut devices_of: BTreeMap<String, std::result::Result<BTreeSet<String>, String>> = BTreeMap::new();
    for s in shares.iter().filter(|s| s.sharer == me && s.active) {
        // Only the device that sealed the latest version keeps it up to
        // date: two devices with different copies would take turns. What
        // is sealed, and for whom, comes from that signed record, never from
        // the server's listing: a listing that moved this device's record
        // to another recipient, path or project is ignored.
        let Some(rec) = s.record.as_ref().filter(|r| r.signer == identity.verifying_hex() && r.version == s.version) else { continue };
        let ours = rec.sharer == me && rec.recipient == s.recipient && rec.path == s.path && rec.project == project;
        if rec.verify().is_err() || !ours {
            continue;
        }
        let Ok(previous) = rec.open(&identity) else { continue };
        let Ok(vp) = VPath::new(&rec.path) else { continue };
        let Some(content) = ctx.fs.read_opt(&vp)? else { continue };
        if content.len() > MAX_SHARE_BYTES {
            out.push(format!("{} is larger than a share may be ({} KiB): not updated", rec.path, MAX_SHARE_BYTES >> 10));
            continue;
        }
        let devices = devices_of
            .entry(rec.recipient.clone())
            .or_insert_with(|| {
                recipient_devices(ctx, client, &rec.recipient, &[]).map(|(d, _)| d.into_iter().map(|(m, _)| m).collect()).map_err(|e| format!("{e:#}"))
            })
            .clone();
        let mut want = match devices {
            Ok(d) => d,
            Err(e) => {
                out.push(format!("share of {} with {}: not updated ({e})", rec.path, rec.recipient));
                continue;
            }
        };
        want.insert(identity.public_hex());
        let have: BTreeSet<String> = rec.devices().into_iter().collect();
        if content == previous && want == have {
            continue;
        }
        let target = ShareTarget {
            project: &rec.project,
            path: &rec.path,
            sharer: me,
            recipient: &rec.recipient,
            version: rec.version + 1,
        };
        let ids: Vec<String> = want.into_iter().collect();
        let record = ShareRecord::seal(&identity, &target, veil_core::now_millis(), &content, &ids)?;
        // Built on the version listed; if the share moved on (ended,
        // updated elsewhere) the server refuses it and the next pass decides
        // again.
        if let Ok(()) = client.put_share(&SharePut {
            expect: rec.version,
            reshare: false,
            record,
        })? {
            out.push(format!("share of {} with {}: version {}", rec.path, rec.recipient, rec.version + 1));
        }
    }
    Ok(out)
}

/// Is `path` a secret file this device may share or receive? A shared
/// secret by its name (`.env`, `.env.*`, `.envrc`, Terraform state), or one
/// the working copy's `.veilpolicy` seals. Only admins' clones hold the
/// root `.veilpolicy`; the server checks every share against the project's
/// accepted one. Never a personal key.
fn secret_path(ctx: &Ctx, path: &str) -> std::result::Result<VPath, String> {
    let named = shareable(&Policy::parse(SYNCED_SECRETS_POLICY), path);
    if named.is_ok() {
        return named;
    }
    match Policy::load(&*ctx.fs) {
        Ok(p) => shareable(&p, path).map_err(|_| named.unwrap_err()),
        Err(_) => named,
    }
}

/// Would this device record `path` (seal it and sync it to everyone who may
/// see its folder) if it were in the working copy? A received copy is
/// written only where it stays on the device. In doubt, yes.
fn would_record(ctx: &Ctx, path: &VPath) -> bool {
    let Ok(policy) = Policy::load(&*ctx.fs) else { return true };
    match policy.classify(path, false).tier {
        // Classification names the access line's scope (`rule-…`), or
        // `rule` itself where no line decides: the admins' `team`.
        Tier::Cloaked(s) => ctx.repo.keys().is_member(if s == RULE_SCOPE { DEFAULT_SCOPE } else { &s }),
        Tier::Isolated | Tier::Ignored => false,
        Tier::Public => true,
    }
}

/// Deliver the active shares for `me` this device can open and has not
/// written yet. Never writes over a file the person changed. What it did
/// or why not, one line each.
fn receive(ctx: &Ctx, me: &str, shares: &[ShareInfo]) -> Vec<String> {
    let mine: Vec<&ShareInfo> = shares.iter().filter(|s| s.recipient == me && s.active).collect();
    if mine.is_empty() {
        return vec![];
    }
    let identity = match load_identity() {
        Ok(i) => i,
        Err(e) => return vec![format!("not received: {e:#}")],
    };
    let project = match project_id(ctx) {
        Ok(p) => p,
        Err(e) => return vec![format!("{} secret share(s) for you not received: {e:#}", mine.len())],
    };
    let rings = local_states(ctx);
    let only = ctx.repo.config().remotes.get("origin").and_then(|r| r.only.clone());
    let mut state = load_state(ctx);
    let mut out = Vec::new();
    let mut changed = false;
    for s in mine {
        let Some(rec) = &s.record else { continue };
        let from = format!("{} from {}", rec.path, s.sharer);
        // Every check is the record's own, against this device's key rings:
        // the server's listing is a hint.
        let bound = rec.recipient == me && rec.sharer == s.sharer && rec.path == s.path && rec.project == project;
        if rec.verify().is_err() || !bound {
            warn_untrusted(&format!("secret share {from}: refused, it is not a valid share for you in this project"));
            continue;
        }
        let by_sharer = rings
            .iter()
            .any(|st| st.members.values().any(|m| m.name == rec.sharer && m.signing_key.as_deref() == Some(rec.signer.as_str())));
        if !by_sharer {
            warn_untrusted(&format!(
                "secret share {from}: refused, it is not signed by a device the project's key rings record as {}'s",
                rec.sharer
            ));
            continue;
        }
        let key = state_key(&rec.sharer, &rec.path);
        let last = state.received.get(&key);
        if last == Some(rec) {
            continue;
        }
        if last.is_some_and(|l| l.version >= rec.version) {
            warn_untrusted(&format!("secret share {from}: refused version {}, older than the one received", rec.version));
            continue;
        }
        let vp = match secret_path(ctx, &rec.path) {
            Ok(vp) => vp,
            Err(e) => {
                out.push(format!("{from}: not written ({e})"));
                continue;
            }
        };
        if only.as_deref().is_some_and(|o| !(vp.as_str().starts_with(o) && vp.as_str().as_bytes().get(o.len()) == Some(&b'/'))) {
            out.push(format!("{from}: not written (outside this clone's directory)"));
            continue;
        }
        let content = match rec.open(&identity) {
            Ok(c) => c,
            Err(_) => {
                out.push(format!("{from}: not sealed for this device yet (it is once {}'s device sees it confirmed)", rec.sharer));
                continue;
            }
        };
        let current = ctx.fs.read_opt(&vp).ok().flatten();
        let previous = last.and_then(|l| l.open(&identity).ok());
        let write = match &current {
            None => true,
            Some(c) if *c == content => false,
            Some(c) => match &previous {
                Some(p) if p == c => true,
                _ => {
                    out.push(format!("{from}: version {} not written over your own {}", rec.version, rec.path));
                    continue;
                }
            },
        };
        if write {
            if would_record(ctx, &vp) {
                out.push(format!(
                    "{from}: not written: this device holds the key of its folder's secrets, so it would record the copy \
                     for everyone who may see that folder"
                ));
                continue;
            }
            if let Err(e) = ctx.fs.write(&vp, &content) {
                out.push(format!("{from}: not written ({e})"));
                continue;
            }
            out.push(format!("received {from} (version {}): it stays on this device", rec.version));
        }
        state.received.insert(key, rec.clone());
        changed = true;
    }
    if changed {
        if let Err(e) = save_state(ctx, &state) {
            out.push(format!("could not remember the shares received: {e:#}"));
        }
    }
    out
}
