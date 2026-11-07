//! Secret keys of a project on a Veil server (`docs/HUB.md` §13.11,
//! §13.12): one key ring per access line, kept by admins' `vl access`,
//! `vl group add|remove`, `vl invite` and `vl upgrade --rule-keys`; joins
//! under invites; device removal; and the pass that shares keys with a
//! confirmed device, in the background or right after `vl identity
//! confirm`.
//!
//! **The key ring is the authority.** What the server lists (devices,
//! vouches, joins, groups) only makes this device *try* a change; the ring's
//! replay (`KeyRing::verify`) refuses any share that is not proved by a
//! signature the server cannot make. Every change goes through
//! [`ring_update`]: decided on the latest ring, built in memory, sent, and
//! stored in this repository only once the server accepted it.

use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    path::Path,
    sync::Arc,
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use veil_core::{
    hub::{
        access::{AccessPolicy, AccessRule},
        wire::{self, Devices, GroupInfo, InviteKey},
    },
    identity::parse_public_identity,
    keychain::{project_fingerprint, KeyRing, Keychain, RingMerge, RingState, Role, ShareProof},
    policy::{rule_scope_of, valid_principal_name, Policy, Tier, DEFAULT_SCOPE, POLICY_FILE, RULE_SCOPE},
    MemoryBackend, StorageBackend, VPath,
};

use crate::{
    ctx::{load_identity, Ctx},
    hub::{self, Client, HubUrl},
    render::{bold, dim, safe, warn, warn_untrusted, yellow},
};

/// How long an invite lasts.
pub const INVITE_DAYS: i64 = 7;

// ---- the project's secret rings ---------------------------------------------------------

/// One key ring of the project's secrets.
#[derive(Clone, Debug)]
pub struct SecretRing {
    pub scope: String,
    /// The access line whose secrets it seals. `None`: `team`, the
    /// admins' ring (secrets no line names anyone for).
    pub rule: Option<AccessRule>,
}

impl SecretRing {
    /// What the ring is for, as people read it.
    pub fn label(&self) -> String {
        match &self.rule {
            Some(r) => format!("{}/", r.path),
            None if self.scope == DEFAULT_SCOPE => format!("'{DEFAULT_SCOPE}' (the admins')"),
            None => format!("scope '{}'", self.scope),
        }
    }
}

/// The working copy's `.veilpolicy`.
pub fn policy_text(ctx: &Ctx) -> String {
    String::from_utf8_lossy(&ctx.fs.read(&VPath::new(POLICY_FILE).unwrap()).unwrap_or_default()).into_owned()
}

/// Does the project seal shared secrets per access line (`cloak rule`)?
pub fn per_rule(text: &str) -> bool {
    Policy::parse(text).rules().iter().any(|r| r.tier == Tier::Cloaked(RULE_SCOPE.into()))
}

/// The rings of a per-rule project: `team`, and one for each path whose
/// deciding access line names a group or person.
pub fn rule_rings(access: &AccessPolicy) -> Vec<SecretRing> {
    let mut out = vec![SecretRing {
        scope: DEFAULT_SCOPE.to_string(),
        rule: None,
    }];
    for (i, r) in access.rules.iter().enumerate() {
        // The last line for a path decides it.
        if r.names.is_empty() || access.rules[i + 1..].iter().any(|l| l.path == r.path) {
            continue;
        }
        out.push(SecretRing {
            scope: rule_scope_of(&r.path),
            rule: Some(r.clone()),
        });
    }
    out
}

/// The scopes of `cloak SCOPE` lines (milestone S1's way: everyone an admin
/// adds to a group gets them). In a per-rule project, `team` is the admins'
/// and is not among them.
fn cloak_scopes(text: &str) -> Vec<String> {
    let rule = per_rule(text);
    let mut out: Vec<String> = Vec::new();
    for r in Policy::parse(text).rules() {
        if let Tier::Cloaked(s) = &r.tier {
            if s != RULE_SCOPE && !(rule && s == DEFAULT_SCOPE) && !out.contains(s) {
                out.push(s.clone());
            }
        }
    }
    out
}

/// The people a rule's ring is for, admins aside, by the server's groups:
/// person → the names on the line that give it to them. A name binds to
/// the group of that name first, as the server binds it.
fn entitled(rule: &AccessRule, groups: &[GroupInfo]) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for n in &rule.names {
        match groups.iter().find(|g| g.name == *n) {
            Some(g) => {
                for m in &g.members {
                    out.entry(m.clone()).or_default().push(n.clone());
                }
            }
            None => out.entry(n.clone()).or_default().push(n.clone()),
        }
    }
    out
}

// ---- confirmed devices ------------------------------------------------------------------

/// How a device of a person was confirmed outside the server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum How {
    /// A verified key ring holds it now, under the person's name.
    Ring,
    /// This command's `--confirm`: the admin compared its fingerprint now.
    Fingerprint,
    /// This device confirmed it in an earlier command, or the person
    /// vouched for it: not enough to give back a key a ring took from it
    /// (a removed device keeps its old vouch).
    Known,
    /// Its join under this invite verifies.
    Invite(String, String),
}

/// The listed devices of `person` that are confirmed outside the server
/// (`docs/HUB.md` §13.11, §13.12), with how: devices a verified ring
/// records under `person`; devices this device confirmed by fingerprint
/// (`confirm`: each match is removed from it and remembered); devices with
/// a join that verifies under an invite for `person` (a ring's, or one this
/// device made); and, repeatedly, devices vouched for by one of these.
fn confirmed_devices(
    authority: &str,
    person: &str,
    devices: &Devices,
    rings: &[RingState],
    confirm: &mut Vec<String>,
) -> Result<Vec<(String, How)>> {
    let (remembered, my_invites) = hub::remembered(authority)?;
    let mut keys: BTreeMap<String, How> = rings
        .iter()
        .flat_map(|st| st.members.values())
        .filter(|m| m.name == person)
        .filter_map(|m| Some((m.signing_key.clone()?, How::Ring)))
        .collect();
    for k in remembered.get(person).into_iter().flatten() {
        keys.entry(k.clone()).or_insert(How::Known);
    }
    // Listed devices with a binding (the identity's keys belong together).
    let listed: Vec<(&String, String, String)> = devices
        .identities
        .iter()
        .filter_map(|i| {
            let p = parse_public_identity(i).ok().filter(|p| p.binding.is_some())?;
            Some((i, p.signing_hex()?, wire::device_fingerprint(&p)?))
        })
        .collect();
    for (_, key, fp) in &listed {
        if let Some(at) = confirm.iter().position(|c| c == fp) {
            confirm.remove(at);
            hub::remember_device(authority, person, key)?;
            keys.insert(key.clone(), How::Fingerprint);
        }
    }
    let invite_for = |key: &str| {
        rings.iter().any(|st| st.invites.get(key).is_some_and(|i| i.person == person))
            || my_invites.get(key).is_some_and(|p| p == person)
    };
    for j in &devices.joins {
        let Some((_, key, _)) = listed.iter().find(|(i, _, _)| **i == j.device) else { continue };
        if invite_for(&j.key) && wire::join_valid(&j.key, person, &j.device, &j.signature) {
            keys.entry(key.clone()).or_insert_with(|| How::Invite(j.key.clone(), j.signature.clone()));
        }
    }
    loop {
        let before = keys.len();
        for v in &devices.vouches {
            if !keys.contains_key(&v.by) || !wire::vouch_valid(v) {
                continue;
            }
            if let Some((_, key, _)) = listed.iter().find(|(i, _, _)| **i == v.device) {
                keys.entry(key.clone()).or_insert(How::Known);
            }
        }
        if keys.len() == before {
            break;
        }
    }
    Ok(listed
        .into_iter()
        .filter_map(|(i, k, _)| keys.get(&k).map(|h| (i.clone(), h.clone())))
        .collect())
}

// ---- the project's fingerprint (BUG-845) ------------------------------------------------

/// Make this clone's record of the project fingerprint it trusts
/// (`Keychain::anchor`) agree with what this device confirmed for the
/// project (`hub.json`): a clone of a server project always records one,
/// or that it trusts none of the project's key rings yet.
pub fn sync_anchor(keys: &Keychain, url: &HubUrl) -> Result<()> {
    let device = hub::anchor_for(&url.authority, &url.project)?;
    match keys.anchor() {
        Some(a) if !a.is_empty() => {
            if device.is_none() {
                hub::set_anchor_for(&url.authority, &url.project, &a)?;
            }
        }
        _ => keys.set_anchor(&device.unwrap_or_default())?,
    }
    Ok(())
}

/// After this device created the project on the server: the `team` ring
/// it made is the project's, and the one it trusts.
pub fn anchor_created(keys: &Keychain, url: &HubUrl) -> Result<()> {
    let Some(Ok(st)) = keys.load_ring(DEFAULT_SCOPE)?.map(|r| r.verify()) else { return Ok(()) };
    if let Some(p) = st.project {
        let fp = project_fingerprint(&p);
        keys.set_anchor(&fp)?;
        hub::set_anchor_for(&url.authority, &url.project, &fp)?;
    }
    Ok(())
}

/// The project fingerprint of a server's `team` ring (what it claims).
pub fn fingerprint_of(ring: &KeyRing) -> Option<String> {
    ring.verify().ok()?.project.map(|p| project_fingerprint(&p))
}

/// Confirm `fp` as the fingerprint of the project of `url`, against the
/// server's `team` ring; `Ok(false)` if the server's ring has another one.
pub fn confirm_project(keys: Option<&Keychain>, client: &Client, fp: &str) -> Result<bool> {
    let Some(team) = client.ring(DEFAULT_SCOPE)? else { return Ok(false) };
    if fingerprint_of(&team).as_deref() != Some(fp) {
        return Ok(false);
    }
    hub::set_anchor_for(&client.url.authority, &client.url.project, fp)?;
    if let Some(keys) = keys {
        keys.set_anchor(fp)?;
    }
    Ok(true)
}

// ---- taking rings from the server -------------------------------------------------------

/// Take `ring` from the server into this repository (`merge_ring`); a
/// warning if it was not taken. Only rings of this project are taken
/// (`Keychain::bound`, BUG-845): `team` only if it is the ring whose
/// fingerprint this device confirmed, every other one only if its signed
/// genesis names that project. A ring of a scope this repository does not
/// hold yet is taken only if a current member of its `team` ring (the
/// admins', on the server) started it: the server cannot make a ring of its
/// own that confirms its devices or seals secrets under its key (BUG-840,
/// BUG-841).
pub fn merge_server_ring(keys: &Keychain, ring: &KeyRing) -> Result<Option<String>> {
    if ring.scope == DEFAULT_SCOPE && keys.anchor().is_some_and(|a| a.is_empty()) {
        let fp = fingerprint_of(ring).unwrap_or_else(|| "(none: the server's ring names no project)".into());
        return Ok(Some(format!(
            "secret keys: this device does not trust this project's key rings yet. Compare the project's fingerprint {fp} \
             with an admin (`vl identity show` in their clone prints it; an invite link carries it), then run \
             `vl identity confirm {fp}` here"
        )));
    }
    if ring.scope != DEFAULT_SCOPE && keys.ring_state(DEFAULT_SCOPE)?.is_none_or(|s| s.is_err()) && keys.anchor().is_some() {
        // Nothing of this project is trusted yet: `team` said so.
        return Ok(None);
    }
    if ring.scope != DEFAULT_SCOPE && !matches!(keys.load_ring(&ring.scope), Ok(Some(_))) {
        let team = keys.ring_state(DEFAULT_SCOPE)?.and_then(|s| s.ok());
        let started_by_team = ring.log.first().is_some_and(|c| {
            team.as_ref().is_some_and(|st| st.members.values().any(|m| m.signing_key.as_deref() == Some(c.signing_key.as_str())))
        });
        if !started_by_team {
            return Ok(Some(format!(
                "key ring for scope '{}': refused, it was not started by a device of this project's admins",
                ring.scope
            )));
        }
    }
    Ok(match keys.merge_ring(ring)? {
        RingMerge::Rejected(w) => Some(w),
        _ => None,
    })
}

/// Take the server's rings ([`merge_server_ring`]), `team` first: it
/// decides which others are taken. The warnings.
pub fn merge_server_rings(keys: &Keychain, url: &HubUrl, mut rings: Vec<KeyRing>) -> Result<Vec<String>> {
    sync_anchor(keys, url)?;
    rings.sort_by_key(|r| r.scope != DEFAULT_SCOPE);
    let mut out = Vec::new();
    for r in &rings {
        out.extend(merge_server_ring(keys, r)?);
    }
    Ok(out)
}

// ---- changing a ring --------------------------------------------------------------------

/// Change the ring of `scope`: fast-forward this repository's ring to the
/// server's, let `f` change a copy of it in memory (`false`: nothing to
/// change), send that, and keep it here once the server accepted it. On a
/// race the server's ring is fetched and `f` decides again from scratch,
/// so a change is never made on an old ring and no device ever keeps a
/// key the server refused. `f` may create the ring.
fn ring_update(ctx: &mut Ctx, client: &Client, scope: &str, mut f: impl FnMut(&Keychain) -> Result<bool>) -> Result<bool> {
    let mut refused: Option<(Option<String>, String)> = None;
    sync_anchor(ctx.repo.keys(), &client.url)?;
    for attempt in 0..12u64 {
        let keys = ctx.repo.keys();
        let server = client.ring(scope)?;
        let head = server.as_ref().and_then(|r| r.hashes().last().cloned());
        // Refused, and the server's ring did not move: not a race.
        if let Some((h, why)) = refused.take() {
            if h == head {
                bail!("the server refused the key ring '{scope}': {why}");
            }
        }
        if let Some(r) = &server {
            if let Some(w) = merge_server_ring(keys, r)? {
                warn_untrusted(&w);
            }
        }
        let mem = Arc::new(MemoryBackend::new());
        // The ring, and `team` with the fingerprint this device trusts: the
        // copy decides as this repository does (`Keychain::bound`).
        for s in [scope, DEFAULT_SCOPE] {
            if let Some(r) = keys.load_ring(s)? {
                mem.write(&VPath::new(&format!(".veil/meta/keyrings/{s}.json"))?, &serde_json::to_vec_pretty(&r)?)?;
            }
        }
        let work = Keychain::new(mem.clone() as Arc<dyn StorageBackend>, keys.identity().cloned(), ctx.repo.repo_id().to_string());
        work.set_format(keys.format());
        if let Some(a) = keys.anchor() {
            work.set_anchor(&a)?;
        }
        if !f(&work)? {
            return Ok(false);
        }
        let Some(ring) = work.load_ring(scope)? else { return Ok(false) };
        match client.try_post_ring(&ring)? {
            Ok(()) => {
                if let RingMerge::Rejected(w) = keys.merge_ring(&ring)? {
                    bail!("{w}");
                }
                ctx.repo.record_outside_view(format!("change the secret keys of scope {scope}"), "key rings are append-only".to_string())?;
                return Ok(true);
            }
            Err(why) => refused = Some((head, why)),
        }
        std::thread::sleep(Duration::from_millis(20 + attempt * 30));
    }
    bail!("the key ring '{scope}' kept changing on the server; try again")
}

fn me_admin(st: &RingState, keys: &Keychain) -> bool {
    keys.identity().is_some_and(|me| st.is_admin(&me.public_hex(), &me.verifying_hex()))
}

/// Every verified ring of this repository.
pub(crate) fn local_states(ctx: &Ctx) -> Vec<RingState> {
    let keys = ctx.repo.keys();
    keys.rings().unwrap_or_default().iter().filter_map(|r| keys.trusted_state(r).ok()).collect()
}

/// A person's confirmed and unconfirmed listed devices.
pub(crate) struct PersonDevices {
    pub(crate) person: String,
    pub(crate) devices: Devices,
    pub(crate) confirmed: Vec<(String, How)>,
}

pub(crate) fn person_devices(ctx: &Ctx, client: &Client, people: &[String], confirm: &[String]) -> Result<Vec<PersonDevices>> {
    let rings = local_states(ctx);
    let mut confirm: Vec<String> = confirm
        .iter()
        .map(|c| {
            wire::normalize_fingerprint(c)
                .ok_or_else(|| anyhow!("'{c}' is not a device fingerprint (20 hex digits, as `vl identity show` prints it)"))
        })
        .collect::<Result<_>>()?;
    let mut out = Vec::new();
    for person in people {
        let devices = match client.devices(person) {
            Ok(d) => d,
            // Named on a line but never signed in: nothing to grant.
            Err(_) => Devices {
                person: person.clone(),
                ..Default::default()
            },
        };
        let confirmed = confirmed_devices(&client.url.authority, person, &devices, &rings, &mut confirm)?;
        out.push(PersonDevices {
            person: person.clone(),
            devices,
            confirmed,
        });
    }
    // A fingerprint that matches nothing stops everything before any key
    // is wrapped: the server lists another device than the one checked.
    if !confirm.is_empty() {
        bail!(
            "no device of {} on the server has the fingerprint {}: the server lists a different device than the one you \
             checked. No secret key was granted",
            people.join(", "),
            confirm.join(", ")
        );
    }
    Ok(out)
}

/// What one admin pass over a ring did.
#[derive(Default)]
struct Outcome {
    granted: BTreeSet<String>,
    revoked: BTreeSet<String>,
    /// Devices the ring held before, not given back: (person, fingerprint).
    held_before: BTreeSet<(String, String)>,
}

/// May an admin's device give `how`'s device the key of a ring that held it
/// before (`ever`)? Only if a ring holds it now, or the admin compared its
/// fingerprint in this command: a removed device keeps its person's old
/// vouch, which a compromised server can show again.
fn may_grant(how: &How, ever: bool) -> bool {
    !ever || matches!(how, How::Ring | How::Fingerprint)
}

/// Bring one ring up to date as an admin: create it if missing, grant the
/// confirmed devices of `targets` (person → why), and, with `revoke`,
/// revoke every member whose name is not a target and cancel their
/// invites. `only`: touch these people only. Returns `None` when this
/// device is not the ring's admin.
fn admin_sync(
    ctx: &mut Ctx,
    client: &Client,
    ring: &SecretRing,
    targets: &BTreeSet<String>,
    devices: &[PersonDevices],
    only: Option<&[String]>,
    revoke: bool,
) -> Result<Option<Outcome>> {
    let me = load_identity()?;
    let mut out = Outcome::default();
    let mut admin = true;
    let touch = |p: &str| only.is_none_or(|o| o.iter().any(|x| x == p));
    ring_update(ctx, client, &ring.scope, |w| {
        out = Outcome::default();
        // A ring made here is sent even if nobody else gets it yet: the
        // admins' own secrets need it (BUG-846).
        let mut changed = w.load_ring(&ring.scope)?.is_none();
        if changed {
            w.create_scope(&ring.scope)?;
        }
        let mut st = w.ring_state(&ring.scope)?.ok_or_else(|| anyhow!("no ring"))?.map_err(|e| anyhow!(e))?;
        if !me_admin(&st, w) {
            admin = false;
            return Ok(false);
        }
        for pd in devices.iter().filter(|d| targets.contains(&d.person) && touch(&d.person)) {
            for (id, how) in &pd.confirmed {
                let pk = parse_public_identity(id)?;
                let member = pk.member_id();
                if st.members.contains_key(&member) {
                    continue;
                }
                let ever = st.ever_members.contains(&member) || pk.signing_hex().is_some_and(|k| st.ever_signers.contains_key(&k));
                if !may_grant(how, ever) {
                    out.held_before.insert((pd.person.clone(), hub::fingerprint(id).unwrap_or_default()));
                    continue;
                }
                match how {
                    How::Invite(key, signature) if st.invites.get(key).is_some_and(|i| !i.used && i.person == pd.person) => {
                        let proof = ShareProof::Invite {
                            key: key.clone(),
                            signature: signature.clone(),
                        };
                        if let Err(e) = w.share(&ring.scope, id, &pd.person, proof) {
                            warn_untrusted(&format!("{}'s device not added to {}: {e}", pd.person, ring.label()));
                            continue;
                        }
                    }
                    _ => w.grant_role(&ring.scope, id, &pd.person, Role::Member)?,
                }
                out.granted.insert(pd.person.clone());
                changed = true;
                st = w.ring_state(&ring.scope)?.unwrap().map_err(|e| anyhow!(e))?;
            }
        }
        if revoke {
            let gone: Vec<(String, String)> = st
                .members
                .iter()
                .filter(|(id, m)| **id != me.public_hex() && !targets.contains(&m.name) && touch(&m.name))
                .map(|(id, m)| (id.clone(), m.name.clone()))
                .collect();
            for (id, name) in gone {
                w.revoke(&ring.scope, &id)?;
                out.revoked.insert(name);
                changed = true;
            }
            let invites: Vec<String> = st
                .invites
                .iter()
                .filter(|(_, i)| !i.used && !targets.contains(&i.person) && touch(&i.person))
                .map(|(k, _)| k.clone())
                .collect();
            for k in invites {
                changed |= w.uninvite(&ring.scope, &k)?;
            }
        }
        Ok(changed)
    })?;
    Ok(admin.then_some(out))
}

/// Who a ring is for: the admins, and for a rule ring the people its line
/// gives the folder to.
fn targets(ring: &SecretRing, groups: &[GroupInfo], admins: &[String]) -> (BTreeSet<String>, BTreeMap<String, Vec<String>>) {
    let why = ring.rule.as_ref().map(|r| entitled(r, groups)).unwrap_or_default();
    let mut t: BTreeSet<String> = why.keys().cloned().collect();
    t.extend(admins.iter().cloned());
    (t, why)
}

fn admins(client: &Client) -> Result<Vec<String>> {
    Ok(client.access(POLICY_FILE)?.admins)
}

fn print_unconfirmed(group: Option<&str>, devices: &[PersonDevices], only: Option<&[String]>) {
    for pd in devices.iter().filter(|d| only.is_none_or(|o| o.contains(&d.person))) {
        for id in &pd.devices.identities {
            if pd.confirmed.iter().any(|(i, _)| i == id) {
                continue;
            }
            let fp = hub::fingerprint(id).unwrap_or_else(|| "(no signing key)".into());
            println!("  {} confirm {}'s device: {}", yellow("keys:"), safe(&pd.person), bold(&fp));
            match group {
                Some(g) => println!(
                    "        compare it with `vl identity show` on their device, then: vl group add {} {} --confirm {fp}\n        \
                     (or send them an invite: vl invite {} --to {})",
                    safe(g),
                    safe(&pd.person),
                    safe(&pd.person),
                    safe(g)
                ),
                None => println!("        compare it with `vl identity show` on their device, then confirm it with `vl group add … --confirm {fp}`"),
            }
        }
    }
}

fn print_outcome(ring: &SecretRing, o: &Outcome) {
    for (person, fp) in &o.held_before {
        println!(
            "  {} {}'s device {} held the secret key of {} before and was removed: it gets it back only when you confirm it \
             again (`--confirm {fp}`, after comparing it with them)",
            yellow("keys:"),
            safe(person),
            bold(fp),
            safe(&ring.label())
        );
    }
    if !o.granted.is_empty() {
        let v: Vec<&str> = o.granted.iter().map(String::as_str).collect();
        println!("  {} the secret key of {} granted to {}", dim("keys:"), safe(&ring.label()), safe(&v.join(", ")));
    }
    if !o.revoked.is_empty() {
        let v: Vec<&str> = o.revoked.iter().map(String::as_str).collect();
        println!("  {} the secret key of {} rotated away from {}", dim("keys:"), safe(&ring.label()), safe(&v.join(", ")));
    }
}

// ---- admin commands ---------------------------------------------------------------------

/// After `vl group add GROUP PEOPLE`: an admin's device grants the keys of
/// the rules naming the group to the people's confirmed devices.
pub fn group_added(ctx: &mut Ctx, client: &Client, group: &str, people: &[String], confirm: &[String]) -> Result<()> {
    let text = policy_text(ctx);
    let devices = person_devices(ctx, client, people, confirm)?;
    let mut any_admin = false;
    let admin = is_admin(client);
    if per_rule(&text) && admin {
        let groups = client.groups()?;
        let admins = admins(client).unwrap_or_default();
        for ring in rule_rings(&AccessPolicy::parse(&text)) {
            let Some(rule) = &ring.rule else { continue };
            if !rule.names.iter().any(|n| n == group) {
                continue;
            }
            let (t, _) = targets(&ring, &groups, &admins);
            if let Some(o) = admin_sync(ctx, client, &ring, &t, &devices, Some(people), false)? {
                any_admin = true;
                print_outcome(&ring, &o);
            }
        }
    }
    any_admin |= legacy_grant(ctx, client, &text, &devices, true)?;
    // Their device takes the project's key rings only once it knows the
    // project's fingerprint (BUG-845): the same comparison, the other way.
    if !confirm.is_empty() {
        if let Some(p) = ctx.repo.keys().project_id() {
            let pfp = project_fingerprint(&p);
            println!(
                "  {} tell {} this project's fingerprint too: {} (they run `vl identity confirm {pfp}` in their clone)",
                dim("keys:"),
                safe(&people.join(", ")),
                bold(&pfp)
            );
        }
    }
    if any_admin {
        print_unconfirmed(Some(group), &devices, None);
    } else if admin {
        println!("  {} no access line names {} yet: its people get the keys of its folders' secrets with `vl access`", dim("keys:"), safe(group));
        print_unconfirmed(Some(group), &devices, None);
    } else {
        warn(
            "they get the keys of the folder's secrets (.env and the like) only when an admin's device grants them: \
             ask a project admin to run this `vl group add` too",
        );
    }
    Ok(())
}

fn is_admin(client: &Client) -> bool {
    client.tips().ok().flatten().is_some_and(|t| t.admin)
}

/// After `vl group remove GROUP PEOPLE`: an admin's device rotates the
/// keys of the rules naming the group away from the people it no longer
/// gives them to (by ring member names: a device the server hides is
/// revoked too), and says who keeps one and why.
pub fn group_removed(ctx: &mut Ctx, client: &Client, group: &str, people: &[String]) -> Result<()> {
    let text = policy_text(ctx);
    let groups = client.groups()?;
    let mut any_admin = false;
    if per_rule(&text) && is_admin(client) {
        let admins = admins(client).unwrap_or_default();
        for ring in rule_rings(&AccessPolicy::parse(&text)) {
            let Some(rule) = &ring.rule else { continue };
            if !rule.names.iter().any(|n| n == group) {
                continue;
            }
            let (t, why) = targets(&ring, &groups, &admins);
            // The server's records decide who keeps a key: never silently
            // (BUG-836).
            for p in people.iter().filter(|p| t.contains(*p)) {
                let through = why.get(p).cloned().unwrap_or_else(|| vec!["admins".into()]);
                println!(
                    "  {} {} keeps the secret key of {} through {}: it was not rotated away from them",
                    yellow("keys:"),
                    safe(p),
                    safe(&ring.label()),
                    safe(&through.join(", "))
                );
            }
            if let Some(o) = admin_sync(ctx, client, &ring, &t, &[], Some(people), true)? {
                any_admin = true;
                print_outcome(&ring, &o);
            }
        }
    }
    // S1's scopes: rotated away from people now in no group at all.
    let gone: Vec<String> = people.iter().filter(|p| !groups.iter().any(|g| g.members.contains(p))).cloned().collect();
    for person in people.iter().filter(|p| !gone.contains(p)) {
        let other: Vec<&str> = groups.iter().filter(|g| g.members.contains(person)).map(|g| g.name.as_str()).collect();
        if !cloak_scopes(&text).is_empty() {
            println!(
                "  {} {} is still in {}: the secret key was not rotated away from them",
                yellow("keys:"),
                safe(person),
                safe(&other.join(", "))
            );
        }
    }
    if !gone.is_empty() {
        let devices = person_devices(ctx, client, &gone, &[])?;
        any_admin |= legacy_grant(ctx, client, &text, &devices, false)?;
    }
    // A manager's clone may not read `.veilpolicy`: the server's rings say
    // whether the project has secret keys at all.
    if !any_admin && client.rings().is_ok_and(|r| !r.is_empty()) {
        warn(&format!(
            "the secret keys were not rotated: only an admin's device rotates them. Until then {} can open new secrets \
             if they get them; ask a project admin to run this `vl group remove` too",
            people.join(", ")
        ));
    }
    Ok(())
}

/// Milestone S1's scopes (`cloak SCOPE` lines): granted to every person an
/// admin adds to a group, revoked (by ring member names) from people in no
/// group. `true` if this device administers one of them.
fn legacy_grant(ctx: &mut Ctx, client: &Client, text: &str, devices: &[PersonDevices], grant: bool) -> Result<bool> {
    let me = load_identity()?;
    let mut any = false;
    for scope in cloak_scopes(text) {
        let Some(Ok(st)) = ctx.repo.keys().ring_state(&scope)? else { continue };
        if !st.is_admin(&me.public_hex(), &me.verifying_hex()) {
            continue;
        }
        any = true;
        let ring = SecretRing { scope: scope.clone(), rule: None };
        let mut o = Outcome::default();
        ring_update(ctx, client, &scope, |w| {
            o = Outcome::default();
            let st = w.ring_state(&scope)?.unwrap().map_err(|e| anyhow!(e))?;
            let mut changed = false;
            for pd in devices {
                if grant {
                    for (id, how) in &pd.confirmed {
                        let pk = parse_public_identity(id)?;
                        if st.members.contains_key(&pk.member_id()) {
                            continue;
                        }
                        let ever = st.ever_members.contains(&pk.member_id()) || pk.signing_hex().is_some_and(|k| st.ever_signers.contains_key(&k));
                        if !may_grant(how, ever) {
                            o.held_before.insert((pd.person.clone(), hub::fingerprint(id).unwrap_or_default()));
                            continue;
                        }
                        w.grant_role(&scope, id, &pd.person, Role::Member)?;
                        o.granted.insert(pd.person.clone());
                        changed = true;
                    }
                } else {
                    for id in st.members.iter().filter(|(id, m)| m.name == pd.person && **id != me.public_hex()).map(|(id, _)| id) {
                        w.revoke(&scope, id)?;
                        o.revoked.insert(pd.person.clone());
                        changed = true;
                    }
                }
            }
            Ok(changed)
        })?;
        print_outcome(&ring, &o);
    }
    Ok(any)
}

/// After an admin's `vl access PATH WHO`: the line's ring exists, holds the
/// confirmed devices of everyone the line gives the folder to, and no one
/// else (the key rotates away from people it no longer gives it to).
/// Before the project is on the server, the ring is created here only and
/// goes up with the first push.
pub fn access_changed(ctx: &mut Ctx, client: Option<&Client>, path: &str) -> Result<()> {
    let text = policy_text(ctx);
    if !per_rule(&text) {
        return Ok(());
    }
    let access = AccessPolicy::parse(&text);
    let Some(ring) = rule_rings(&access).into_iter().find(|r| r.rule.as_ref().is_some_and(|l| l.path == path)) else {
        return Ok(());
    };
    // Created here only before the project is on a server (its creator's
    // first push sends it): a clone's ring of its own would never match the
    // admin's.
    let tips = match client.map(Client::tips) {
        None | Some(Ok(None)) => {
            if ctx.repo.keys().load_ring(&ring.scope)?.is_none() {
                ctx.repo.keys().create_scope(&ring.scope)?;
                println!("  {} created the secret key of {} (it goes to the server with your push)", dim("keys:"), safe(&ring.label()));
            }
            return Ok(());
        }
        Some(Err(e)) => {
            warn(&format!("the secret key of {} was not set up: {e:#}; run this again when the server answers", ring.label()));
            return Ok(());
        }
        Some(Ok(Some(t))) => t,
    };
    let client = client.unwrap();
    if !tips.admin {
        return Ok(());
    }
    let groups = client.groups()?;
    let admins = admins(client)?;
    let (t, _) = targets(&ring, &groups, &admins);
    let people: Vec<String> = t.iter().cloned().collect();
    let devices = person_devices(ctx, client, &people, &[])?;
    if let Some(o) = admin_sync(ctx, client, &ring, &t, &devices, None, true)? {
        print_outcome(&ring, &o);
        print_unconfirmed(None, &devices, None);
    }
    Ok(())
}

/// `vl invite PERSON --to GROUP` (an admin): an invite whose secret is only
/// in the printed link (`docs/HUB.md` §13.12).
pub fn invite(ctx: &mut Ctx, client: &Client, person: &str, group: &str) -> Result<()> {
    if !valid_principal_name(person) {
        bail!("'{person}' is not a person's name (lowercase letters, digits, '-', '_', '.')");
    }
    let text = policy_text(ctx);
    if !per_rule(&text) {
        bail!("this project still seals every secret with one key: an admin runs `vl upgrade --rule-keys` first");
    }
    // The link names the project's `team` ring, so the invitee's device
    // trusts no other (BUG-845).
    sync_anchor(ctx.repo.keys(), &client.url)?;
    let project = ctx.repo.keys().project_id().ok_or_else(|| {
        anyhow!("this clone does not trust the project's key rings yet (`vl identity confirm` the project's fingerprint first)")
    })?;
    let pfp = project_fingerprint(&project);
    let key = InviteKey::generate();
    let public = key.public_hex();
    let expires_at = veil_core::now_millis() + INVITE_DAYS * 24 * 3600 * 1000;
    client.create_invite(&wire::InviteRequest {
        key: public.clone(),
        person: person.to_string(),
        group: group.to_string(),
        expires_at,
    })?;
    hub::remember_invite(&client.url.authority, &public, person)?;
    let groups = client.groups()?;
    let admins = admins(client)?;
    let mut rules = Vec::new();
    for ring in rule_rings(&AccessPolicy::parse(&text)) {
        if !ring.rule.as_ref().is_some_and(|r| r.names.iter().any(|n| n == group)) {
            continue;
        }
        let (t, _) = targets(&ring, &groups, &admins);
        admin_sync(ctx, client, &ring, &t, &[], Some(&[]), false)?;
        ring_update(ctx, client, &ring.scope, |w| {
            let st = w.ring_state(&ring.scope)?.ok_or_else(|| anyhow!("no ring"))?.map_err(|e| anyhow!(e))?;
            if st.invites.contains_key(&public) || !me_admin(&st, w) {
                return Ok(false);
            }
            w.invite(&ring.scope, person, &public, expires_at)?;
            Ok(true)
        })?;
        rules.push(ring.label());
    }
    let link = format!(
        "veil://{}/{}#invite={person}:{}:{}",
        client.url.authority,
        client.url.project,
        key.secret_hex(),
        pfp.replace('-', "")
    );
    println!("Invited {} to {} in {}. Send them this link (Slack, email):", bold(&safe(person)), safe(group), safe(&client.url.project));
    println!();
    println!("  {link}");
    println!();
    println!("  They run `vl join -` and paste it (on a shared machine, never put it on the command line).");
    println!(
        "  It works once, for {} days. The server never sees the secret in it: their device's keys{} come from it.",
        INVITE_DAYS,
        if rules.is_empty() { String::new() } else { format!(" for {}", rules.join(", ")) }
    );
    Ok(())
}

/// `vl join LINK` (`-`: read it from standard input, where other users of
/// the machine cannot see it): sign in (registering the invited name if it
/// is new), join under the invite with this device, and check that the
/// project's `team` key ring is the one the link names (BUG-845): the only
/// one this device then trusts.
pub fn join(link: &str) -> Result<()> {
    let link = if link == "-" {
        use std::io::Read;
        let mut s = String::new();
        std::io::stdin().take(64 << 10).read_to_string(&mut s).context("reading the invite link from standard input")?;
        s
    } else {
        link.to_string()
    };
    let bad = || anyhow!("expected the link `vl invite` printed: veil://host/project#invite=NAME:SECRET:FINGERPRINT");
    let (url, frag) = link.trim().split_once('#').ok_or_else(bad)?;
    let mut parts = frag.strip_prefix("invite=").ok_or_else(bad)?.split(':');
    let (Some(person), Some(secret), Some(pfp), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return Err(bad());
    };
    let key = InviteKey::from_hex(secret).ok_or_else(bad)?;
    let pfp = wire::normalize_fingerprint(pfp).ok_or_else(bad)?;
    if !valid_principal_name(person) {
        return Err(bad());
    }
    let url = HubUrl::parse(url).ok_or_else(bad)??;
    if url.project.is_empty() {
        return Err(bad());
    }
    let identity = load_identity()?;
    let fp = hub::fingerprint(&identity.public_id()).unwrap_or_default();
    let client = Client::new(&url, identity.clone())?;
    let s = client.login(Some(person)).map_err(|e| {
        anyhow!(
            "{e:#}\n  The invite is for {person}: on a device of {person}'s that is signed in, run `vl join` there, or \
             confirm this device first"
        )
    })?;
    if s.person != person {
        bail!("this device is signed in to {} as {}; the invite is for {person}", url.authority, s.person);
    }
    let device = identity.public_id();
    let signature = key
        .sign_join(person, &parse_public_identity(&device)?)
        .ok_or_else(|| anyhow!("this device's identity has no signing key"))?;
    let joined = client
        .join(&wire::JoinRequest {
            key: key.public_hex(),
            device,
            signature,
        })
        .context("joining")?;
    if !confirm_project(None, &client, &pfp)? {
        bail!(
            "joined {} as {}, but the server's key ring for this project is not the one your invite names (fingerprint {pfp}): \
             another project's, or one the server made. This device trusts none of its secret keys. Tell your admin",
            joined.project,
            joined.person
        );
    }
    println!(
        "Joined {} as {} (group {}). This device: {}",
        safe(&joined.project),
        bold(&safe(&joined.person)),
        safe(&joined.group),
        bold(&fp)
    );
    println!("  The project's fingerprint matches your invite: {}", bold(&pfp));
    println!("  Its keys for the folder's secrets arrive as soon as a teammate's or an admin's device is online.");
    println!("  Clone the project: vl clone veil://{}/{}", url.authority, url.project);
    Ok(())
}

// ---- sharing, in the background ---------------------------------------------------------

/// Share this device's keys with every listed device that has a proof (a
/// join under the ring's invite, or a vouch by a current device of the same
/// person), and revoke the devices the server says were removed, where
/// this device may (an admin; or the same person). Returns what changed,
/// as `(ring label, person, what)`.
pub fn share_pass(ctx: &mut Ctx, client: &Client) -> Result<Vec<(String, String, &'static str)>> {
    let pending = client.pending_keys()?;
    if pending.is_empty() {
        return Ok(vec![]);
    }
    let text = policy_text(ctx);
    let labels: BTreeMap<String, String> = rule_rings(&AccessPolicy::parse(&text)).into_iter().map(|r| (r.scope.clone(), r.label())).collect();
    let me = load_identity()?;
    let mut done = Vec::new();
    let scopes: Vec<String> = ctx.repo.keys().rings()?.into_iter().map(|r| r.scope).collect();
    for scope in scopes {
        if !ctx.repo.keys().is_member(&scope) {
            continue;
        }
        let label = labels.get(&scope).cloned().unwrap_or_else(|| format!("scope '{scope}'"));
        let mut changes: Vec<(String, String, &'static str)> = Vec::new();
        ring_update(ctx, client, &scope, |w| {
            changes.clear();
            let now = veil_core::now_millis();
            // Devices whose change this ring refused: never tried again in
            // this pass.
            let mut skip: BTreeSet<String> = BTreeSet::new();
            loop {
                let st = w.ring_state(&scope)?.ok_or_else(|| anyhow!("no ring"))?.map_err(|e| anyhow!(e))?;
                if !st.is_member_with_key(&me.public_hex(), &me.verifying_hex()) {
                    return Ok(!changes.is_empty());
                }
                let admin = me_admin(&st, w);
                let my_name = st.members.get(&me.public_hex()).map(|m| m.name.clone()).unwrap_or_default();
                let mut step = None;
                'people: for d in &pending {
                    for removed in &d.removed {
                        let Ok(id) = parse_public_identity(removed).map(|p| p.member_id()) else { continue };
                        if skip.contains(&id) {
                            continue;
                        }
                        if st.members.get(&id).is_some_and(|m| m.name == d.person) && id != me.public_hex() && (admin || my_name == d.person) {
                            step = Some((d.person.clone(), Step::Revoke(id)));
                            break 'people;
                        }
                    }
                    if !st.trusts(&d.person, now) {
                        continue;
                    }
                    for id in &d.identities {
                        if skip.contains(id) {
                            continue;
                        }
                        let Ok(p) = parse_public_identity(id) else { continue };
                        let (Some(k), Some(_)) = (p.signing_hex(), p.binding) else { continue };
                        if st.ever_members.contains(&p.member_id()) || st.ever_signers.contains_key(&k) {
                            continue;
                        }
                        let join = d.joins.iter().find(|j| {
                            j.device == *id
                                && st.invites.get(&j.key).is_some_and(|i| !i.used && i.person == d.person && now <= i.expires_at)
                                && wire::join_valid(&j.key, &d.person, id, &j.signature)
                        });
                        let proof = match join {
                            Some(j) => ShareProof::Invite {
                                key: j.key.clone(),
                                signature: j.signature.clone(),
                            },
                            None => {
                                let current: Vec<&String> =
                                    st.members.values().filter(|m| m.name == d.person).filter_map(|m| m.signing_key.as_ref()).collect();
                                let Some(v) = d.vouches.iter().find(|v| v.device == *id && current.contains(&&v.by) && wire::vouch_valid(v)) else {
                                    continue;
                                };
                                ShareProof::Vouch {
                                    by: v.by.clone(),
                                    signature: v.signature.clone(),
                                }
                            }
                        };
                        step = Some((d.person.clone(), Step::Share(id.clone(), proof)));
                        break 'people;
                    }
                }
                let Some((person, step)) = step else { return Ok(!changes.is_empty()) };
                match step {
                    Step::Revoke(id) => match w.revoke_device(&scope, &id) {
                        Ok(_) => changes.push((label.clone(), person, "rotated away from a removed device of")),
                        Err(e) => {
                            warn_untrusted(&format!("{person}'s removed device was not revoked from {label}: {e}"));
                            skip.insert(id);
                        }
                    },
                    Step::Share(id, proof) => match w.share(&scope, &id, &person, proof) {
                        Ok(()) => changes.push((label.clone(), person, "shared with a confirmed device of")),
                        Err(e) => {
                            warn_untrusted(&format!("{person}'s device was not given the key of {label}: {e}"));
                            skip.insert(id);
                        }
                    },
                }
            }
        })?;
        done.extend(changes);
    }
    Ok(done)
}

enum Step {
    Share(String, ShareProof),
    Revoke(String),
}

/// How often a clone starts a background pass at most.
const PASS_EVERY: Duration = Duration::from_secs(10);
/// The background pass's log is started afresh beyond this.
const LOG_LIMIT: u64 = 1 << 20;

/// After a command in a clone of a server project, on a device that holds a
/// secret key or takes part in a secret share: start `vl share-keys`
/// detached, at most every [`PASS_EVERY`] (`VEIL_KEY_SHARE=0` turns this
/// off). Best effort.
pub fn maybe_spawn(ctx: &Ctx) {
    if ctx.bare || std::env::var("VEIL_KEY_SHARE").is_ok_and(|v| v == "0") {
        return;
    }
    if !ctx.repo.config().remotes.get("origin").is_some_and(|r| hub::is_hub_url(&r.url)) {
        return;
    }
    let holds = ctx.repo.keys().rings().is_ok_and(|rs| rs.iter().any(|r| ctx.repo.keys().is_member(&r.scope)))
        || crate::share_cmd::takes_part(ctx);
    if !holds {
        return;
    }
    let local = ctx.root.join(".veil/local");
    let stamp = local.join("key-share.stamp");
    let recent = std::fs::metadata(&stamp)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.elapsed().ok())
        .is_some_and(|age| age < PASS_EVERY);
    if recent || std::fs::create_dir_all(&local).is_err() || std::fs::write(&stamp, b"").is_err() {
        return;
    }
    let _ = spawn(&ctx.root, &local.join("key-share.log"));
}

fn spawn(root: &Path, log: &Path) -> std::io::Result<()> {
    let mut o = std::fs::OpenOptions::new();
    o.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut out = o.open(log)?;
    if out.metadata()?.len() > LOG_LIMIT {
        out.set_len(0)?;
    }
    writeln!(out, "[{}] vl share-keys", veil_core::now_millis() / 1000)?;
    let err = out.try_clone()?;
    let mut cmd = std::process::Command::new(std::env::current_exe()?);
    cmd.args(["--no-snapshot", "share-keys"])
        .current_dir(root)
        // The child must not start another one.
        .env("VEIL_KEY_SHARE", "0")
        .env("VEIL_GC_AUTO", "0")
        .stdin(std::process::Stdio::null())
        .stdout(out)
        .stderr(err);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    cmd.spawn().map(drop)
}

/// `vl share-keys` (hidden; what the background runs): one pass, printed.
pub fn run_pass(ctx: &mut Ctx, client: &Client) -> Result<()> {
    let keys = share_pass(ctx, client);
    for (label, person, what) in keys.as_ref().map(Vec::as_slice).unwrap_or_default() {
        println!("  {} the secret key of {} {what} {}", dim("keys:"), safe(label), safe(person));
    }
    // Person-to-person secret shares (docs/HUB.md §13.17), whatever the
    // key pass did.
    for line in crate::share_cmd::pass(ctx, client)? {
        println!("  {} {}", dim("shares:"), safe(&line));
    }
    keys.map(drop)
}

// ---- devices ----------------------------------------------------------------------------

/// The repository here, if it is a clone of a project on `authority`.
pub fn clone_of(authority: &str) -> Option<Ctx> {
    let root = crate::ctx::find_root(&std::env::current_dir().ok()?)?;
    let ctx = Ctx::open(Some(&root), false).ok()?;
    let url = HubUrl::parse(&ctx.repo.config().remotes.get("origin")?.url)?.ok()?;
    (url.authority == authority).then_some(ctx)
}

/// The repository here, if it is a clone of a project on a Veil server.
pub fn clone_here() -> Option<Ctx> {
    let root = crate::ctx::find_root(&std::env::current_dir().ok()?)?;
    let ctx = Ctx::open(Some(&root), false).ok()?;
    HubUrl::parse(&ctx.repo.config().remotes.get("origin")?.url)?.ok()?;
    Some(ctx)
}

/// `vl identity show` in a clone of a server project: the project's
/// fingerprint this device trusts, or that it trusts none yet.
pub fn project_line(ctx: &Ctx) -> Option<String> {
    HubUrl::parse(&ctx.repo.config().remotes.get("origin")?.url)?.ok()?;
    Some(match ctx.repo.keys().project_id() {
        Some(p) if ctx.repo.keys().anchor().is_some() => project_fingerprint(&p),
        _ => "(not confirmed on this device: `vl pull` shows the fingerprint to compare)".to_string(),
    })
}

/// After `vl identity confirm` in a clone: share this device's keys with
/// the device just confirmed, now.
pub fn confirmed_here(authority: &str) {
    let Some(mut ctx) = clone_of(authority) else {
        println!("  its keys arrive when one of your (or a teammate's) devices next runs vl in each project");
        return;
    };
    let Ok((client, _)) = crate::hub_cmd::client_for(&ctx, "origin") else { return };
    match share_pass(&mut ctx, &client) {
        Ok(done) => {
            for (label, person, what) in &done {
                println!("  {} the secret key of {} {what} {}", dim("keys:"), safe(label), safe(person));
            }
            if done.is_empty() {
                println!("  its keys arrive when one of your (or a teammate's) devices next runs vl in each project");
            }
        }
        Err(e) => warn(&format!("keys not shared yet: {e:#}")),
    }
    let _ = ctx.finish();
}

/// `vl identity remove FINGERPRINT`: remove one of your devices (from
/// another) everywhere, or, as an admin of this clone's project, anyone's
/// device from this project only (BUG-843). Every ring of this clone that
/// holds it revokes it and rotates. The device is found among the **rings'**
/// members when the server does not list it.
pub fn remove_device(fingerprint: &str, server: Option<&str>) -> Result<()> {
    let fp = wire::normalize_fingerprint(fingerprint)
        .ok_or_else(|| anyhow!("a device fingerprint is 20 hex digits, as `vl identity show` prints it (4F2A-9C1E-…)"))?;
    let here = server.is_none().then(|| {
        let root = crate::ctx::find_root(&std::env::current_dir().ok()?)?;
        let cfg = veil_core::repo::read_config(&veil_core::DiskBackend::new(&root)).ok()?;
        Some(HubUrl::parse(&cfg.remotes.get("origin")?.url)?.ok()?.authority)
    });
    let (authority, me) = match here.flatten() {
        Some(a) => hub::signed_in_servers()?
            .into_iter()
            .find(|(x, _)| *x == a)
            .ok_or_else(|| anyhow!("this device is not signed in to {a} (`vl login veil://{a}`)"))?,
        None => crate::hub_cmd::resolve_server(server)?,
    };
    let identity = load_identity()?;
    if hub::fingerprint(&identity.public_id()).as_deref() == Some(fp.as_str()) {
        bail!("{fp} is this device: remove it from another of your devices");
    }
    let mut ctx = clone_of(&authority);
    let url = match &ctx {
        Some(c) => HubUrl::parse(&c.repo.config().remotes["origin"].url).unwrap()?,
        None => HubUrl::parse(&format!("veil://{authority}")).ok_or_else(|| anyhow!("bad server"))??,
    };
    let client = Client::new(&url, identity.clone())?;
    // The rings as they are now (a device shared to since this clone's
    // last pull is found too).
    if let Some(c) = &ctx {
        let _ = merge_server_rings(c.repo.keys(), &client.url, client.rings().unwrap_or_default());
    }
    // The device: one of mine the server lists, or a ring member's.
    let mine = client.devices(&me)?;
    let listed = mine.identities.iter().chain(&mine.pending).find(|d| hub::fingerprint(d).as_deref() == Some(fp.as_str())).cloned();
    let in_rings: Option<(String, String)> = ctx.as_ref().and_then(|c| {
        local_states(c).into_iter().flat_map(|st| st.members.into_iter()).find_map(|(id, m)| {
            let full = format!("{id}{}{}", m.signing_key?, m.binding?);
            (hub::fingerprint(&full).as_deref() == Some(fp.as_str())).then_some((full, m.name))
        })
    });
    let (device, person) = match (listed, in_rings) {
        (Some(d), _) => (d, me.clone()),
        (None, Some(found)) => found,
        (None, None) => bail!(
            "no device with the fingerprint {fp}: not one of {me}'s on {authority}{}",
            if ctx.is_some() { ", nor in this project's key rings" } else { " (run this in a clone of the project to find someone else's)" }
        ),
    };
    // An admin bars someone else's device from this project only; only its
    // person removes it everywhere (BUG-843).
    let project = (person != me).then(|| url.project.clone());
    match (client.remove_device(&device, project.as_deref()), &project) {
        (Ok(_), None) => println!("Removed {}'s device {} on {}: it can no longer sign in", safe(&person), bold(&fp), safe(&authority)),
        (Ok(_), Some(p)) => println!(
            "Removed {}'s device {} from project {}: it can no longer use this project (only {} can remove it everywhere)",
            safe(&person),
            bold(&fp),
            safe(p),
            safe(&person)
        ),
        // Already gone on the server (or hidden by it): the rings decide.
        (Err(e), _) => warn_untrusted(&format!("the server did not remove it: {e:#}")),
    }
    let Some(c) = ctx.as_mut() else {
        println!("  run this again in a clone of each of your projects to rotate the keys it held now; your devices also do it in the background");
        return Ok(());
    };
    let member = parse_public_identity(&device)?.member_id();
    let text = policy_text(c);
    let labels: BTreeMap<String, String> = rule_rings(&AccessPolicy::parse(&text)).into_iter().map(|r| (r.scope.clone(), r.label())).collect();
    let scopes: Vec<String> = c.repo.keys().rings()?.into_iter().map(|r| r.scope).collect();
    for scope in scopes {
        let holds = c.repo.keys().ring_state(&scope)?.and_then(|s| s.ok()).is_some_and(|st| st.members.contains_key(&member));
        if !holds {
            continue;
        }
        let changed = ring_update(c, &client, &scope, |w| {
            let st = w.ring_state(&scope)?.ok_or_else(|| anyhow!("no ring"))?.map_err(|e| anyhow!(e))?;
            if !st.members.contains_key(&member) {
                return Ok(false);
            }
            w.revoke_device(&scope, &member).map_err(Into::into)
        });
        let label = labels.get(&scope).cloned().unwrap_or_else(|| format!("scope '{scope}'"));
        match changed {
            Ok(true) => println!("  {} the secret key of {} rotated away from it", dim("keys:"), safe(&label)),
            Ok(false) => {}
            Err(e) => warn(&format!("the secret key of {label} was not rotated: {e:#}")),
        }
    }
    c.finish()?;
    Ok(())
}

// ---- migration from S1's one key --------------------------------------------------------

/// `vl upgrade --rule-keys` (an admin): move a project from S1's one `team`
/// key to one key per access line. Lists every secret with its new key and
/// who will hold it first; `dry_run` stops there. Then rewrites S1's lines
/// to `cloak rule`, creates and grants the rule rings, and revokes every
/// non-admin from `team`. The next commit re-seals each secret.
pub fn upgrade_rule_keys(ctx: &mut Ctx, dry_run: bool) -> Result<std::process::ExitCode> {
    // Rewrites `.veilpolicy` in the directory (BUG-1125).
    let _wc = ctx.lock_dir(None)?;
    let text = policy_text(ctx);
    // Already rewritten (also by a run that stopped before its keys were
    // moved, BUG-844): the keys are still brought up to date below.
    let already = per_rule(&text);
    if already {
        println!("This project already seals each folder's secrets with that folder's key (`cloak rule` in {POLICY_FILE}).");
    }
    let (client, _) = crate::hub_cmd::client_for(ctx, "origin")?;
    if !is_admin(&client) {
        if already {
            return Ok(std::process::ExitCode::SUCCESS);
        }
        bail!("only an admin of the project moves its secrets to keys per folder");
    }
    // S1's lines, rewritten in place.
    let mut changed = 0;
    let new_text: String = if already {
        text.clone()
    } else {
        text
            .lines()
            .map(|l| {
                let f = veil_core::policy::split_fields(l);
                if f.len() == 3
                    && matches!(f[1].as_str(), "cloak" | "cloaked")
                    && f[2] == DEFAULT_SCOPE
                    && veil_core::policy::S1_SYNCED_SECRETS_LINES.contains(&f[0].as_str())
                {
                    changed += 1;
                    format!("{:<25}cloak {RULE_SCOPE}", f[0])
                } else {
                    l.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n"
    };
    if changed == 0 && !already {
        bail!("{POLICY_FILE} has none of the lines milestone S1 wrote for shared secrets (`.env  cloak team`, …): nothing to move");
    }
    let new_policy = Policy::parse(&new_text);
    let access = AccessPolicy::parse(&new_text);
    let rings = rule_rings(&access);
    let groups = client.groups()?;
    let admins = admins(&client)?;
    println!("Each folder's secrets get their own key; only people who may see the folder (and admins) hold it:");
    for f in secret_files(ctx, &new_policy)? {
        let Tier::Cloaked(scope) = new_policy.classify(&VPath::new(&f)?, false).tier else { continue };
        let ring = rings.iter().find(|r| r.scope == scope);
        let who = ring.map(|r| targets(r, &groups, &admins).0.into_iter().collect::<Vec<_>>().join(", ")).unwrap_or_default();
        println!("  {}  →  key of {}  ({})", safe(&f), safe(&ring.map(|r| r.label()).unwrap_or(scope)), safe(&who));
    }
    if let Some(Ok(st)) = ctx.repo.keys().ring_state(DEFAULT_SCOPE)? {
        let gone: BTreeSet<&str> = st.members.values().filter(|m| !admins.contains(&m.name)).map(|m| m.name.as_str()).collect();
        if !gone.is_empty() {
            println!(
                "  the old project key ('{DEFAULT_SCOPE}') becomes the admins' only: rotated away from {} (they keep what they could already open)",
                safe(&gone.into_iter().collect::<Vec<_>>().join(", "))
            );
        }
    }
    if dry_run {
        println!("Dry run: nothing changed. Run without --dry-run to move them.");
        return Ok(std::process::ExitCode::SUCCESS);
    }
    if !already {
        ctx.fs.write(&VPath::new(POLICY_FILE)?, new_text.as_bytes())?;
    }
    let people: Vec<String> = rings.iter().flat_map(|r| targets(r, &groups, &admins).0).collect::<BTreeSet<_>>().into_iter().collect();
    let devices = person_devices(ctx, &client, &people, &[])?;
    for ring in &rings {
        let (t, _) = targets(ring, &groups, &admins);
        if let Some(o) = admin_sync(ctx, &client, ring, &t, &devices, None, true)? {
            print_outcome(ring, &o);
        }
    }
    print_unconfirmed(None, &devices, None);
    if already {
        println!("The keys of every folder are up to date. Commit and push any secret not yet re-sealed under its folder's key.");
        return Ok(std::process::ExitCode::SUCCESS);
    }
    println!("Rewrote {changed} line(s) of {POLICY_FILE} to `cloak rule`. Commit and push: the commit re-seals each secret under its folder's key.");
    println!("  Everyone else runs `vl pull`, then `vl policy accept` to take the new keys for their edits.");
    Ok(std::process::ExitCode::SUCCESS)
}

/// The working copy's files `policy` seals.
fn secret_files(ctx: &Ctx, policy: &Policy) -> Result<Vec<String>> {
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
                if !matches!(policy.classify(&vp, true).tier, Tier::Ignored) {
                    stack.push(p);
                }
            } else if ft.is_file() && matches!(policy.classify(&vp, false).tier, Tier::Cloaked(_)) {
                files.push(rel);
            }
        }
    }
    files.sort();
    Ok(files)
}
