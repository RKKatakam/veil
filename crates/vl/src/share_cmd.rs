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

/// Device-local memory of this clone's shares (`docs/HUB.md` §13.13): what
/// it received (the last version written here of each (sharer, path), and
/// the newest genuine version seen, written or not), and **the shares this
/// clone made**, which are the only ones its background pass keeps up to
/// date (BUG-1060, BUG-1063). Records are ciphertext for this device;
/// contents only as keyed hashes.
const STATE_FILE: &str = ".veil/local/secret-shares.json";
/// Where a received copy goes when this device would now record it.
const HELD_DIR: &str = ".veil/local/secret-shares-held";
/// The most content hashes kept per share made here.
const MAX_SEALED: usize = 256;

#[derive(Default, Serialize, Deserialize)]
struct State {
    #[serde(default)]
    received: BTreeMap<String, ShareRecord>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    seen: BTreeMap<String, u64>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    made: BTreeMap<String, Made>,
}

/// A share this clone made with `vl secret share`.
#[derive(Clone, Serialize, Deserialize)]
struct Made {
    /// `secret_share::share_id` of (project, path, sharer, recipient).
    id: String,
    /// The last version this clone sealed.
    version: u64,
    /// Keyed hashes of every content it sealed, oldest first; the last is
    /// the current version's.
    sealed: Vec<String>,
    /// The workspace whose files it follows, and the revisions its working
    /// copy was on when the last content was sealed.
    workspace: String,
    base: Vec<Base>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Base {
    snapshot: String,
    change: String,
}

fn state_key(sharer: &str, path: &str) -> String {
    format!("{sharer}\u{0}{path}")
}

fn made_key(path: &str, recipient: &str) -> String {
    format!("{path}\u{0}{recipient}")
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

/// A keyed hash of a content this clone sealed (key derived from the
/// device-local vault key, so the file reveals nothing and allows no
/// guessing of a secret).
fn content_hash(ctx: &Ctx, identity: &veil_core::Identity, content: &[u8]) -> String {
    let key = blake3::derive_key(veil_core::crypto::domains::HUB_SHARE_HISTORY, &identity.local_key(ctx.repo.repo_id()));
    blake3::keyed_hash(&key, content).to_hex().to_string()
}

/// The revisions the working copy of `ws` is on now (the view read
/// afresh: a background pass's own view is as old as the pass).
fn fresh_bases(ctx: &mut Ctx, ws: &str) -> Vec<Base> {
    let _ = ctx.repo.reload();
    bases(ctx, ws)
}

/// The revisions the working copy of `ws` is on, in this process's view.
fn bases(ctx: &Ctx, ws: &str) -> Vec<Base> {
    let Some(wc) = ctx.repo.view().workspaces.get(ws).map(|w| w.wc) else { return vec![] };
    let Ok(snap) = ctx.repo.snapshot(&wc) else { return vec![] };
    snap.parents
        .iter()
        .filter_map(|p| ctx.repo.snapshot(p).ok().map(|s| Base { snapshot: p.to_string(), change: hex::encode(s.change_id.0) }))
        .collect()
}

/// Is the working copy of `made.workspace` on (a descendant of) every
/// revision the last content was sealed on? By change identity too, so a
/// rewritten revision (described, rebased) still counts. Checking out an
/// older revision does not.
fn forward(ctx: &Ctx, made: &Made, now: &[Base]) -> bool {
    if now.is_empty() {
        return made.base.is_empty();
    }
    made.base.iter().all(|b| {
        let Ok(id) = veil_core::ObjectId::from_hex(&b.snapshot) else { return false };
        now.iter().any(|n| {
            let Ok(nid) = veil_core::ObjectId::from_hex(&n.snapshot) else { return false };
            if ctx.repo.is_ancestor(&id, &nid).unwrap_or(false) {
                return true;
            }
            // The same change, rewritten, among the newest ancestors.
            let mut stack = vec![nid];
            let mut seen = std::collections::HashSet::new();
            while let Some(x) = stack.pop() {
                if seen.len() > 10_000 || !seen.insert(x) {
                    continue;
                }
                let Ok(Some(sn)) = ctx.repo.snapshot_opt(&x) else { continue };
                if hex::encode(sn.change_id.0) == b.change {
                    return true;
                }
                stack.extend(sn.parents.iter().copied());
            }
            false
        })
    })
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
    // This clone becomes the share's source before anything is sent: a
    // background pass never updates a share it does not record.
    let key = made_key(vp.as_str(), with);
    let hash = content_hash(ctx, &identity, &content);
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
    let mut st = load_state(ctx);
    let mut sealed = st.made.remove(&key).map(|m| m.sealed).unwrap_or_default();
    if sealed.last() != Some(&hash) {
        sealed.push(hash);
    }
    let excess = sealed.len().saturating_sub(MAX_SEALED);
    sealed.drain(..excess);
    st.made.insert(
        key,
        Made {
            id: veil_core::secret_share::share_id(&project, vp.as_str(), &me, with),
            version,
            sealed,
            workspace: ctx.ws.clone(),
            base: bases(ctx, &ctx.ws),
        },
    );
    save_state(ctx, &st)?;
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
    println!(
        "  {} your later edits of it in this clone, and their new devices, reach them in the background until you unshare it; \
         updates follow your working copy forward",
        dim("note:")
    );
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
    // Forgotten here first: whatever the server says later, this clone never
    // seals another version of it (BUG-1060).
    let mut st = load_state(ctx);
    if st.made.remove(&made_key(vp.as_str(), from)).is_some() {
        save_state(ctx, &st)?;
    }
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

/// The background pass (`vl share-keys`): keep the shares this clone made
/// up to date, then deliver what is new for this device. What it did, one
/// line each.
pub fn pass(ctx: &mut Ctx, client: &Client) -> Result<Vec<String>> {
    let Some(me) = hub::signed_in_servers()?.into_iter().find(|(a, _)| *a == client.url.authority).map(|(_, p)| p) else {
        return Ok(vec![]);
    };
    let shares = client.shares()?;
    let mut out = Vec::new();
    if !load_state(ctx).made.is_empty() {
        out.extend(update(ctx, client, &me, &shares)?);
    }
    out.extend(receive(ctx, &me, &shares));
    if !shares.is_empty() && !takes_part(ctx) {
        save_state(ctx, &load_state(ctx))?;
    }
    Ok(out)
}

/// Seal a new version of each share **this clone made** (its local record,
/// never the server's listing: BUG-1060, BUG-1063) whose file changed here,
/// or whose recipient's confirmed devices changed. A content change is
/// sealed only forward: never a value the share held before, and never
/// while this working copy is on an older revision than the one the last
/// content was sealed on (an explicit `vl secret share` does both on
/// purpose). A share the server lists as ended, paused or moved on is
/// forgotten here: only a new `vl secret share` starts it again.
fn update(ctx: &mut Ctx, client: &Client, me: &str, shares: &[ShareInfo]) -> Result<Vec<String>> {
    let identity = load_identity()?;
    let project = project_id(ctx)?;
    let mut st = load_state(ctx);
    let mut out = Vec::new();
    let mut changed = false;
    // Each recipient's devices, asked once per pass.
    let mut devices_of: BTreeMap<String, std::result::Result<BTreeSet<String>, String>> = BTreeMap::new();
    for (key, made) in st.made.clone() {
        let Some((path, recipient)) = key.split_once('\u{0}') else { continue };
        let label = format!("share of {path} with {recipient}");
        let Some(s) = shares.iter().find(|s| s.sharer == me && s.path == path && s.recipient == recipient) else { continue };
        if s.unshared_at.is_some() || !s.active || s.version > made.version {
            let why = match (&s.unshared_at, &s.paused) {
                (Some(_), _) => "ended".to_string(),
                (None, Some(p)) => format!("paused ({p})"),
                _ => "shared again from elsewhere".to_string(),
            };
            out.push(format!("{label}: {why}; this clone no longer keeps it up to date (`vl secret share` starts it again)"));
            st.made.remove(&key);
            changed = true;
            continue;
        }
        // The version this clone sealed last, as the server holds it: what is
        // sealed and for whom comes from that signed record and the local
        // one, never from the listing.
        let Some(rec) = s.record.as_ref().filter(|r| r.version == made.version && r.signer == identity.verifying_hex()) else { continue };
        let ours = rec.sharer == me && rec.recipient == recipient && rec.path == path && rec.project == project;
        if rec.verify().is_err() || !ours || veil_core::secret_share::share_id(&project, path, me, recipient) != made.id {
            continue;
        }
        let Ok(vp) = VPath::new(path) else { continue };
        // The revision, then the file, then the revision again: a file read
        // while the working copy moved is not sealed (the next pass decides).
        let before = fresh_bases(ctx, &made.workspace);
        let Some(content) = ctx.fs.read_opt(&vp)? else { continue };
        let moved = |ctx: &mut Ctx| {
            let after = fresh_bases(ctx, &made.workspace);
            after.len() != before.len() || after.iter().zip(&before).any(|(a, b)| a.snapshot != b.snapshot)
        };
        if content.len() > MAX_SHARE_BYTES {
            out.push(format!("{label}: not updated: the file is larger than a share may be ({} KiB)", MAX_SHARE_BYTES >> 10));
            continue;
        }
        let hash = content_hash(ctx, &identity, &content);
        let new_content = made.sealed.last() != Some(&hash);
        if new_content && made.sealed.contains(&hash) {
            out.push(format!(
                "{label}: not updated: the file holds a value the share held before (`vl secret share` sends it on purpose)"
            ));
            continue;
        }
        if new_content && !forward(ctx, &made, &before) {
            out.push(format!(
                "{label}: not updated: this working copy is on an older revision than the one the last version was sealed on; \
                 updates follow your working copy forward (`vl secret share` sends it on purpose)"
            ));
            continue;
        }
        let devices = devices_of
            .entry(recipient.to_string())
            .or_insert_with(|| {
                recipient_devices(ctx, client, recipient, &[]).map(|(d, _)| d.into_iter().map(|(m, _)| m).collect()).map_err(|e| format!("{e:#}"))
            })
            .clone();
        let mut want = match devices {
            Ok(d) => d,
            Err(e) => {
                out.push(format!("{label}: not updated ({e})"));
                continue;
            }
        };
        want.insert(identity.public_hex());
        let have: BTreeSet<String> = rec.devices().into_iter().collect();
        if !new_content && want == have {
            continue;
        }
        let target = ShareTarget {
            project: &project,
            path,
            sharer: me,
            recipient,
            version: made.version + 1,
        };
        let ids: Vec<String> = want.into_iter().collect();
        let record = ShareRecord::seal(&identity, &target, veil_core::now_millis(), &content, &ids)?;
        if new_content && moved(ctx) {
            continue;
        }
        // Built on this clone's last version; if the share moved on the
        // server refuses it, and the next pass decides again.
        if let Ok(()) = client.put_share(&SharePut {
            expect: made.version,
            reshare: false,
            record,
        })? {
            let m = st.made.get_mut(&key).expect("the share is recorded");
            m.version += 1;
            if new_content {
                m.sealed.push(hash);
                let excess = m.sealed.len().saturating_sub(MAX_SEALED);
                m.sealed.drain(..excess);
                m.base = before.clone();
            }
            changed = true;
            out.push(format!("{label}: version {}", made.version + 1));
        }
    }
    if changed {
        save_state(ctx, &st)?;
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
fn would_record(ctx: &Ctx, policy: Option<&Policy>, path: &VPath) -> bool {
    let Some(policy) = policy else { return true };
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
    let policy = Policy::load(&*ctx.fs).ok();
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
        let last = state.received.get(&key).cloned();
        if last.as_ref() == Some(rec) {
            continue;
        }
        // Older than a genuine version seen here (written or not), or
        // another record of the version written: refused.
        let seen = state.seen.get(&key).copied().unwrap_or(0).max(last.as_ref().map_or(0, |l| l.version));
        if rec.version < seen || last.as_ref().is_some_and(|l| l.version >= rec.version) {
            warn_untrusted(&format!("secret share {from}: refused version {}, older than the one received", rec.version));
            continue;
        }
        if rec.version > seen {
            state.seen.insert(key.clone(), rec.version);
            changed = true;
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
        // What is at the path, from its own directory entry (BUG-1062): only
        // nothing at all, or a regular file, is ever considered; a link, a
        // folder or a special file is the person's, and so is a file that
        // cannot be read.
        let current = match std::fs::symlink_metadata(ctx.root.join(vp.as_str())) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Ok(m) if m.file_type().is_file() => match ctx.fs.read_opt(&vp) {
                Ok(Some(c)) => Some(c),
                _ => {
                    out.push(format!("{from}: not written: your {} cannot be read", rec.path));
                    continue;
                }
            },
            Ok(_) => {
                out.push(format!("{from}: not written: your {} is not a regular file (a link, a folder, …)", rec.path));
                continue;
            }
            Err(e) => {
                out.push(format!("{from}: not written ({e})"));
                continue;
            }
        };
        let previous = last.as_ref().and_then(|l| l.open(&identity).ok());
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
            if would_record(ctx, policy.as_ref(), &vp) {
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

/// Before a snapshot records this working copy: move every copy of a
/// received share that this device would now record (it holds the key of
/// the file's folder since, an admin's say) out of the working copy, into
/// `.veil/local/secret-shares-held/`, so it never enters history for
/// everyone in the folder. A file the project itself tracks there is left
/// alone. Cheap when the clone received nothing.
pub fn hold_back_received(ctx: &Ctx) {
    if !takes_part(ctx) {
        return;
    }
    let st = load_state(ctx);
    if st.received.is_empty() {
        return;
    }
    let policy = Policy::load(&*ctx.fs).ok();
    let tree = ctx.repo.view().workspaces.get(&ctx.ws).and_then(|w| ctx.repo.snapshot(&w.wc).ok()).map(|s| s.tree);
    for rec in st.received.values() {
        let Ok(vp) = VPath::new(&rec.path) else { continue };
        if !std::fs::symlink_metadata(ctx.root.join(vp.as_str())).is_ok_and(|m| m.file_type().is_file()) || !would_record(ctx, policy.as_ref(), &vp) {
            continue;
        }
        let tracked = match &tree {
            Some(t) => veil_core::tree::lookup(ctx.repo.store(), t, &vp).map(|e| e.is_some()).unwrap_or(true),
            None => true,
        };
        if tracked {
            continue;
        }
        let held = format!("{HELD_DIR}/{}", veil_core::secret_share::share_id(&rec.project, &rec.path, &rec.sharer, &rec.recipient));
        let moved = (|| -> Result<()> {
            let data = ctx.fs.read_opt(&vp)?.ok_or_else(|| anyhow!("gone"))?;
            ctx.fs.write(&VPath::new(&held)?, &data)?;
            ctx.fs.remove_file(&vp)?;
            Ok(())
        })();
        match moved {
            Ok(()) => warn(&format!(
                "{}: the copy {} shared with you was moved to {held}: this device now holds the key of its folder's secrets \
                 and would record it for everyone who may see that folder",
                safe(&rec.path),
                safe(&rec.sharer)
            )),
            Err(e) => warn(&format!("{}: the copy {} shared with you could not be moved out of the working copy: {e:#}", safe(&rec.path), safe(&rec.sharer))),
        }
    }
}
