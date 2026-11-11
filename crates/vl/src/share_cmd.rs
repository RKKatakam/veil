//! Person-to-person secret shares (`docs/HUB.md` §13.17): `vl secret share
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
//! * **Updates are explicit:** a new version of the content is sealed only
//!   when the sharer runs `vl secret share` again ("send what I have now").
//!   The background pass of the clone that shared it only seals **the same
//!   content again** for the recipient's current confirmed devices (a device
//!   they add receives it; a removed one is left out of every later
//!   version), taken from the sharer's own signed last version, never from
//!   the working copy. Unsharing stops every later version; it cannot take
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

/// Device-local memory of this clone's shares (`docs/HUB.md` §13.17): what
/// it received (the last version written here of each (sharer, path), and
/// the newest genuine version seen, written or not), and **the shares this
/// clone made**, which are the only ones its background pass touches
/// (BUG-1060, BUG-1063). Records are ciphertext for this device. Every
/// change is made under [`with_state`]'s lock (BUG-1066).
const STATE_FILE: &str = ".veil/local/secret-shares.json";
const STATE_LOCK: &str = ".veil/local/secret-shares.lock";
/// Where a received copy goes when this device would now record it.
const HELD_DIR: &str = ".veil/local/secret-shares-held";

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
}

fn state_key(sharer: &str, path: &str) -> String {
    format!("{sharer}\u{0}{path}")
}

fn made_key(path: &str, recipient: &str) -> String {
    format!("{path}\u{0}{recipient}")
}

/// The record as it is now (no lock: for deciding what to try; every change
/// goes through [`with_state`]).
fn load_state(ctx: &Ctx) -> State {
    VPath::new(STATE_FILE)
        .ok()
        .and_then(|p| ctx.fs.read_opt(&p).ok().flatten())
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

/// Change the record: under an exclusive lock of this clone's record (held
/// for no network call), read it afresh, let `f` apply this command's own
/// change to what is there now, and write it back (atomically). `f` never
/// re-inserts an entry another command removed, nor an older version.
fn with_state<T>(ctx: &Ctx, f: impl FnOnce(&mut State) -> T) -> Result<T> {
    let lock_path = ctx.root.join(STATE_LOCK);
    if let Some(dir) = lock_path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let lock = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(&lock_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        // SAFETY: a valid descriptor; released when `lock` is closed.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
            bail!("locking {}: {}", lock_path.display(), std::io::Error::last_os_error());
        }
    }
    let mut st = load_state(ctx);
    let out = f(&mut st);
    ctx.fs.write(&VPath::new(STATE_FILE)?, &serde_json::to_vec(&st)?)?;
    drop(lock);
    Ok(out)
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
    // This clone is now the share's source (any other clone of the person's
    // sees the version move on and stops).
    let id = veil_core::secret_share::share_id(&project, vp.as_str(), &me, with);
    with_state(ctx, |st| {
        let m = st.made.entry(made_key(vp.as_str(), with)).or_insert(Made { id, version });
        m.version = m.version.max(version);
    })?;
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
        "  {} run this again to send a new version; devices they add receive this one automatically, until you unshare it",
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
    with_state(ctx, |st| st.made.remove(&made_key(vp.as_str(), from)))?;
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
/// sealed for their recipients' current confirmed devices, then deliver
/// what is new for this device. What it did, one line each.
pub fn pass(ctx: &mut Ctx, client: &Client) -> Result<Vec<String>> {
    let Some(me) = hub::signed_in_servers()?.into_iter().find(|(a, _)| *a == client.url.authority).map(|(_, p)| p) else {
        return Ok(vec![]);
    };
    // The record before the listing: a listing is then never older than
    // the entries it is judged against. Read the other way round, an unshare
    // and a new share of the same file between the two reads made a stale
    // "ended" look like the end of the new share, which was then forgotten.
    let made = load_state(ctx).made;
    let shares = client.shares()?;
    let mut out = Vec::new();
    if !made.is_empty() {
        out.extend(rewrap(ctx, client, &me, made, &shares)?);
    }
    out.extend(receive(ctx, &me, &shares));
    if !shares.is_empty() && !takes_part(ctx) {
        with_state(ctx, |_| ())?;
    }
    Ok(out)
}

/// For each share **this clone made** (its own record, never the server's
/// listing: BUG-1060, BUG-1063) whose recipient's confirmed devices are
/// not the ones its last version is sealed for, seal **that same content**
/// again for them. The content comes from the sharer's own last version
/// (this device is sealed for it), never from the working copy: a new
/// content goes out only with `vl secret share`. A share the server lists
/// as ended, paused or shared again elsewhere is forgotten here: only a new
/// `vl secret share` starts it again.
fn rewrap(ctx: &mut Ctx, client: &Client, me: &str, made_now: BTreeMap<String, Made>, shares: &[ShareInfo]) -> Result<Vec<String>> {
    let identity = load_identity()?;
    let project = project_id(ctx)?;
    let mut out = Vec::new();
    for (key, made) in made_now {
        let Some((path, recipient)) = key.split_once('\u{0}') else { continue };
        let label = format!("share of {path} with {recipient}");
        let Some(s) = shares.iter().find(|s| s.sharer == me && s.path == path && s.recipient == recipient) else { continue };
        // A listing older than what this clone recorded says nothing about
        // it (a lying server, or a race): never acted on.
        if s.version < made.version {
            continue;
        }
        if s.unshared_at.is_some() || !s.active || s.version > made.version {
            let why = match (&s.unshared_at, &s.paused) {
                (Some(_), _) => "ended".to_string(),
                (None, Some(p)) => format!("paused ({p})"),
                _ => "shared again from elsewhere".to_string(),
            };
            // Forgotten only as it was seen: a newer version recorded since
            // (a `vl secret share` meanwhile) stays.
            let gone = with_state(ctx, |st| match st.made.get(&key) {
                Some(m) if m.version == made.version => st.made.remove(&key).is_some(),
                _ => false,
            })?;
            if gone {
                out.push(format!("{label}: {why}; this clone no longer keeps it sealed for their devices (`vl secret share` starts it again)"));
            }
            continue;
        }
        // This clone's last version, as the server holds it: signed by this
        // device, at the version recorded here, for this share.
        let Some(rec) = s.record.as_ref().filter(|r| r.version == made.version && r.signer == identity.verifying_hex()) else { continue };
        let ours = rec.sharer == me && rec.recipient == recipient && rec.path == path && rec.project == project;
        if rec.verify().is_err() || !ours || veil_core::secret_share::share_id(&project, path, me, recipient) != made.id {
            continue;
        }
        let mut want: BTreeSet<String> = match recipient_devices(ctx, client, recipient, &[]) {
            Ok((d, _)) => d.into_iter().map(|(m, _)| m).collect(),
            Err(e) => {
                out.push(format!("{label}: not sealed for their devices again ({e:#})"));
                continue;
            }
        };
        want.insert(identity.public_hex());
        if want == rec.devices().into_iter().collect::<BTreeSet<_>>() {
            continue;
        }
        let Ok(content) = rec.open(&identity) else { continue };
        let target = ShareTarget {
            project: &project,
            path,
            sharer: me,
            recipient,
            version: made.version + 1,
        };
        let ids: Vec<String> = want.into_iter().collect();
        let record = ShareRecord::seal(&identity, &target, veil_core::now_millis(), &content, &ids)?;
        // Built on this clone's last version; if the share moved on the
        // server refuses it, and the next pass decides again.
        if let Ok(()) = client.put_share(&SharePut {
            expect: made.version,
            reshare: false,
            record,
        })? {
            // Recorded only if the share is still this clone's at the version
            // it was built on (an unshare or a share meanwhile wins).
            with_state(ctx, |st| {
                if let Some(m) = st.made.get_mut(&key).filter(|m| m.version == made.version) {
                    m.version += 1;
                }
            })?;
            out.push(format!("{label}: version {} (sealed again for their devices)", made.version + 1));
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
    match ctx.repo.effective_policy(&*ctx.fs) {
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
    let policy = ctx.repo.effective_policy(&*ctx.fs).ok();
    let only = ctx.repo.config().remotes.get("origin").and_then(|r| r.only.clone());
    // Decided on the record as it is now; recorded under the lock, keeping
    // only what moves forward (BUG-1066).
    let state = load_state(ctx);
    let mut seen_now: Vec<(String, u64)> = Vec::new();
    let mut written: Vec<(String, ShareRecord)> = Vec::new();
    let mut out = Vec::new();
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
            seen_now.push((key.clone(), rec.version));
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
            if let Err(e) = ctx.fs.write_secret(&vp, &content, false) {
                out.push(format!("{from}: not written ({e})"));
                continue;
            }
            out.push(format!("received {from} (version {}): it stays on this device", rec.version));
        }
        written.push((key, rec.clone()));
    }
    if !seen_now.is_empty() || !written.is_empty() {
        let r = with_state(ctx, |st| {
            for (k, v) in seen_now {
                let e = st.seen.entry(k).or_insert(0);
                *e = (*e).max(v);
            }
            for (k, rec) in written {
                if st.received.get(&k).is_none_or(|l| l.version < rec.version) {
                    st.received.insert(k, rec);
                }
            }
        });
        if let Err(e) = r {
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
    let policy = ctx.repo.effective_policy(&*ctx.fs).ok();
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
        // A new name each time, never over a copy held before (BUG-1067);
        // and the path is no longer "received": what the person puts there
        // later is theirs to record.
        let id = veil_core::secret_share::share_id(&rec.project, &rec.path, &rec.sharer, &rec.recipient);
        let mut held = String::new();
        let moved = (|| -> Result<()> {
            let data = ctx.fs.read_opt(&vp)?.ok_or_else(|| anyhow!("gone"))?;
            let mut n = 0u32;
            loop {
                held = match n {
                    0 => format!("{HELD_DIR}/{id}"),
                    _ => format!("{HELD_DIR}/{id}-{n}"),
                };
                if ctx.fs.create_new_secret(&VPath::new(&held)?, &data)? {
                    break;
                }
                n += 1;
            }
            ctx.fs.remove_file(&vp)?;
            let key = state_key(&rec.sharer, &rec.path);
            with_state(ctx, |st| {
                if st.received.get(&key).is_some_and(|r| r.version == rec.version) {
                    st.received.remove(&key);
                }
            })?;
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
