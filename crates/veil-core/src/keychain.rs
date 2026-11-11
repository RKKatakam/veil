//! Scope keys and signed key rings (for secret files), and embargo records.
//!
//! Shared, publishable metadata lives under `.veil/meta/`:
//!
//! * `keyrings/<scope>.json` — the scope's **ring log**: an append-only,
//!   hash-chained list of membership changes, each signed with the Ed25519
//!   key of an admin who was authorised at that point of the log. The
//!   current membership and the key *generations* are derived by replaying
//!   the log; nothing in the file is trusted unless the replay verifies.
//! * `embargoes/<id>.json`   — an embargo's plain record: who may see the
//!   embargoed work (`scope`), its deadline and its release. Nothing in it
//!   is encrypted or signed: the server enforces embargoes as permissions.
//! * `vault/<scope>/<id>.json` — team-vault records (`crate::team_vault`):
//!   secrets sealed for a scope's members, each signed by its writer.
//!
//! Every write of these files, and the read that decides it, runs under the
//! repository lock (reentrantly, so also inside transactions): two
//! concurrent `grant`s, or a `grant` racing a `pull`, can never lose an
//! update.
//!
//! ## Key generations
//!
//! A scope starts at generation 0. Every revocation (and `vl scope rotate`)
//! starts a new generation with a fresh random key that is wrapped only to
//! the remaining members. Each new generation also carries the previous
//! generation's key sealed under the new one, so anyone holding the newest
//! key can walk back through the whole history, while a revoked member holds
//! at most the keys up to their revocation.
//!
//! Sealed objects name their generation in the envelope label:
//! `<scope>#<key-id>`, where `key-id` is the key fingerprint. A bare
//! `<scope>` label (every envelope written before generations existed) means
//! generation 0. The label is the AEAD associated data, so the generation is
//! authenticated, and the binary envelope format is unchanged.
//!
//! The special scope `local` is derived from the identity secret and the
//! repository id; it never exists anywhere on disk and therefore cannot be
//! synchronised.
//!
//! ## Constructions by repository format
//!
//! Scope keys are wrapped to members with HPKE in repository format 3 and
//! with the legacy sealed box in formats 1–2 (see `identity`); the keychain
//! learns the format from its store ([`Keychain::set_format`]). A ring that
//! holds any HPKE-wrapped key is ring format 3, which older vl refuse (no
//! keys) instead of misreading, and which a format-1/2 repository refuses to
//! store ("run `vl upgrade`"). Older generation keys (`prev-key:`) are
//! sealed with XChaCha20-Poly1305 under a random nonce in every format. Every domain-separation string is in
//! [`crate::crypto::domains`]; `docs/CRYPTO.md` reviews them.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc, RwLock,
    },
};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    crypto::{domains, random_bytes, random_key, Envelope, Key},
    error::{Result, VeilError},
    identity::{
        format_public_key, is_low_order_public_key, parse_public_identity, parse_public_key, verify_binding, wrap_key,
        wrap_key_legacy, Identity, Signature, WrappedKey,
    },
    lock::RepoLock,
    object::Snapshot,
    vfs::StorageBackend,
    vpath::VPath,
};

pub const LOCAL_SCOPE: &str = domains::LOCAL_LABEL;
/// Ring file format with a signed change log (legacy sealed-box wraps only).
pub const RING_FORMAT_SIGNED: u32 = 2;
/// Ring file format whose log may hold HPKE-wrapped keys (repository format
/// 3).
pub const RING_FORMAT_HPKE: u32 = 3;
/// Ring file format whose log may hold invites, shares by members and a
/// member's revocation of their own device (repository format 7,
/// `docs/HUB.md` §13.12); the newest this build reads.
pub const RING_FORMAT_SHARES: u32 = 4;
/// The newest ring format this build reads.
pub const RING_FORMAT: u32 = RING_FORMAT_SHARES;
/// Repository format that may hold HPKE-wrapped keys and ring format 3.
pub const HPKE_REPO_FORMAT: u32 = 3;
/// Repository format that may hold ring format 4.
pub const SHARES_REPO_FORMAT: u32 = 7;

/// Newest ring format a repository of `repo_format` may store.
pub fn max_ring_format(repo_format: u32) -> u32 {
    if repo_format >= SHARES_REPO_FORMAT {
        RING_FORMAT_SHARES
    } else if repo_format >= HPKE_REPO_FORMAT {
        RING_FORMAT_HPKE
    } else {
        RING_FORMAT_SIGNED
    }
}

/// Embargo record format: 2, the plain record. Format-1 records (no
/// `format` field) held an embargo key, removed with every encryption of
/// non-secret content: `vl upgrade` converts them, this build refuses them,
/// as it refuses a newer format (see `docs/FORMAT.md`) instead of reading,
/// and re-writing, half of it.
pub const EMBARGO_FORMAT: u32 = 2;

/// Refuse an embargo record not written in [`EMBARGO_FORMAT`].
pub fn check_embargo_format(raw: &[u8]) -> Result<()> {
    let v: serde_json::Value = serde_json::from_slice(raw)?;
    match v.get("format").map(|f| f.as_u64()) {
        Some(Some(f)) if f == u64::from(EMBARGO_FORMAT) => Ok(()),
        None => Err(VeilError::Unsupported(
            "an embargo record of an older format (it held an embargo key); run `vl upgrade`".into(),
        )),
        Some(f) => Err(VeilError::Unsupported(format!(
            "embargo record format {} needs a newer vl (this is vl {})",
            f.map_or("?".to_string(), |f| f.to_string()),
            env!("CARGO_PKG_VERSION")
        ))),
    }
}

const RING_SIG_CONTEXT: &str = domains::SIG_CONTEXT_RING_CHANGE;

/// Public fingerprint of a scope key.
pub fn key_fingerprint(key: &Key) -> String {
    hex::encode(&blake3::derive_key(domains::KEY_FINGERPRINT, key)[..8])
}

/// Envelope label for a scope key generation.
pub fn generation_label(scope: &str, key_id: &str) -> String {
    format!("{scope}{}{key_id}", domains::GENERATION_SEPARATOR)
}

/// Split an envelope label into `(scope, key id)`; a bare scope has no id.
pub fn split_label(label: &str) -> (&str, Option<&str>) {
    match label.split_once(domains::GENERATION_SEPARATOR) {
        Some((s, k)) => (s, Some(k)),
        None => (label, None),
    }
}

// ---- ring format ---------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// May grant, revoke and rotate.
    Admin,
    /// May read and write content of the scope.
    Member,
}

/// A member as introduced (or updated) by a genesis or grant change.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberGrant {
    /// Member id, `veil1<x25519-hex>`.
    pub id: String,
    pub name: String,
    /// Ed25519 verifying key (hex). Members without one cannot sign ring
    /// changes or have their signatures attributed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_key: Option<String>,
    /// The member's binding: `signing_key`'s signature (context
    /// `member-binding`) over the X25519 key of `id`, proving the holder of
    /// the signing key chose this member id (BUG-069). Ring format 3 only;
    /// grants recorded earlier (and in format-1/2 repositories) have none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<String>,
    pub role: Role,
    /// Generation of the key in `wrapped`.
    pub generation: u32,
    pub wrapped: WrappedKey,
}

/// An older key sealed under a newer generation's key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedKey {
    pub key_id: String,
    pub sealed: Envelope,
}

/// Start of a new key generation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rotation {
    pub generation: u32,
    pub key_id: String,
    /// Previous generation key(s), sealed under this generation's key.
    pub previous: Vec<SealedKey>,
    /// This generation's key wrapped to every remaining member.
    pub wrapped: BTreeMap<String, WrappedKey>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RingOp {
    /// First change: creates the scope (or adopts a legacy ring).
    Genesis {
        key_id: String,
        members: Vec<MemberGrant>,
        /// MAC under the generation-0 key binding this genesis to someone who
        /// knew the key. Checked by every reader who holds that key.
        proof: String,
        /// Ring format 4: the id of the project the ring belongs to (the
        /// hash of the project's `team` ring's genesis change, 32 hex
        /// digits). Every ring but `team` carries it from repository format
        /// 7 on; a ring for another project is refused (BUG-845,
        /// [`Keychain::bound`]). `team` itself never carries one: its
        /// genesis *is* the project's id.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        project: Option<String>,
    },
    /// Add a member, or change an existing member's name, role or signing key.
    Grant { member: MemberGrant },
    /// Remove a member and start a new key generation without them.
    Revoke { member: String, rotation: Rotation },
    /// Start a new key generation for the same members.
    Rotate { rotation: Rotation },
    /// Ring format 4, signed by an admin: whoever signs a join under `key`
    /// (the public half of an invite's secret, `hub::wire::InviteKey`) may
    /// have one device shared to them as `person`, until `expires_at`
    /// (`docs/HUB.md` §13.12).
    Invite { person: String, key: String, expires_at: i64 },
    /// Ring format 4, signed by an admin: the invite under `key` can no
    /// longer be used.
    Uninvite { key: String },
    /// Ring format 4, signed by **any current member**: add a device of a
    /// person the ring already trusts, at the current generation, with a
    /// proof the server cannot forge ([`ShareProof`]).
    Share { member: MemberGrant, proof: ShareProof },
    /// Ring format 4, signed by a current member: remove another device of
    /// **their own** (same name) and start a new key generation.
    RevokeOwn { member: String, rotation: Rotation },
}

/// Why a member may add a device to a ring ([`RingOp::Share`]). Both are
/// signatures over the new device's keys that only someone outside the
/// server can make.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ShareProof {
    /// A join signed (context `hub-invite`) under the key of an unused,
    /// unexpired invite for the person (`hub::wire::join_message`).
    Invite { key: String, signature: String },
    /// A vouch signed (context `hub-device`) by the signing key `by` of a
    /// current member with the same name (`hub::wire::vouch_message`).
    Vouch { by: String, signature: String },
}

impl RingOp {
    /// Is this an operation only ring format 4 may hold?
    fn needs_shares_format(&self) -> bool {
        matches!(self, RingOp::Invite { .. } | RingOp::Uninvite { .. } | RingOp::Share { .. } | RingOp::RevokeOwn { .. })
            || matches!(self, RingOp::Genesis { project: Some(_), .. })
    }
}

impl RingOp {
    pub fn summary(&self) -> String {
        match self {
            RingOp::Genesis { members, .. } => format!(
                "create scope ({})",
                members.iter().map(|m| m.name.as_str()).collect::<Vec<_>>().join(", ")
            ),
            RingOp::Grant { member } => format!(
                "grant {} ({})",
                member.name,
                if member.role == Role::Admin { "admin" } else { "member" }
            ),
            RingOp::Revoke { member, rotation } => {
                format!("revoke {} → generation {}", &member[..member.len().min(17)], rotation.generation)
            }
            RingOp::Rotate { rotation } => format!("rotate → generation {}", rotation.generation),
            RingOp::Invite { person, .. } => format!("invite {person}"),
            RingOp::Uninvite { key } => format!("cancel invite {}", &key[..key.len().min(16)]),
            RingOp::Share { member, proof } => format!(
                "share with {} ({})",
                member.name,
                match proof {
                    ShareProof::Invite { .. } => "invite",
                    ShareProof::Vouch { .. } => "confirmed by their device",
                }
            ),
            RingOp::RevokeOwn { member, rotation } => {
                format!("remove own device {} → generation {}", &member[..member.len().min(17)], rotation.generation)
            }
        }
    }
}

/// One signed entry of a ring log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RingChange {
    /// Position in the log (0 = genesis). Doubles as the ring epoch.
    pub seq: u64,
    /// Hash of the previous change (empty for the genesis).
    pub prev: String,
    pub timestamp: i64,
    /// Member id of the signer.
    pub signer: String,
    /// Ed25519 key that signed; must be the signer's registered key.
    pub signing_key: String,
    pub op: RingOp,
    pub signature: String,
}

#[derive(Serialize)]
struct ChangeBody<'a> {
    scope: &'a str,
    seq: u64,
    prev: &'a str,
    timestamp: i64,
    signer: &'a str,
    signing_key: &'a str,
    op: &'a RingOp,
}

impl RingChange {
    /// The exact bytes that are signed (context `ring-change`).
    pub fn signing_body(&self, scope: &str) -> Vec<u8> {
        serde_json::to_vec(&ChangeBody {
            scope,
            seq: self.seq,
            prev: &self.prev,
            timestamp: self.timestamp,
            signer: &self.signer,
            signing_key: &self.signing_key,
            op: &self.op,
        })
        .unwrap()
    }

    /// Chain hash of this change (covers the signature too).
    pub fn hash(&self, scope: &str) -> String {
        let mut h = blake3::Hasher::new_derive_key(domains::RING_CHANGE_HASH);
        h.update(&self.signing_body(scope));
        h.update(self.signature.as_bytes());
        h.finalize().to_hex()[..32].to_string()
    }

    fn signature_valid(&self, scope: &str) -> bool {
        crate::identity::verify_signature(&self.signing_key, RING_SIG_CONTEXT, &self.signing_body(scope), &self.signature)
    }
}

/// Legacy (format 1) ring member.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RingMember {
    pub name: String,
    pub wrapped: WrappedKey,
}

/// The on-disk key ring. Format 2 rings carry only `log`; legacy rings
/// (format 0/1, written before signed rings existed) carry `key_id` and an
/// unauthenticated `members` map and are still readable.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRing {
    pub scope: String,
    #[serde(default)]
    pub format: u32,
    /// Legacy: fingerprint of the (single) scope key.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub key_id: String,
    /// Legacy: wrapped keys by member id.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub members: BTreeMap<String, RingMember>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub log: Vec<RingChange>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberInfo {
    pub name: String,
    pub signing_key: Option<String>,
    /// The member's binding of `signing_key` to their id, if recorded.
    pub binding: Option<String>,
    pub role: Role,
}

/// Membership and key generations derived by replaying a ring.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingState {
    pub scope: String,
    pub legacy: bool,
    /// Current key generation.
    pub generation: u32,
    /// Key id per generation (index = generation).
    pub generations: Vec<String>,
    pub members: BTreeMap<String, MemberInfo>,
    /// Every signing key that ever belonged to a member: key → (id, name).
    /// A key belongs to one member id only (replay refuses a second).
    pub ever_signers: BTreeMap<String, (String, String)>,
    /// The keys of `ever_signers` whose binding to their member was proved
    /// in the ring (the others were granted before bindings existed).
    pub bound_signers: BTreeSet<String>,
    /// Hash of the last change (empty for legacy rings).
    pub head: String,
    pub len: usize,
    /// Every member id the ring ever held: a share never brings one back.
    pub ever_members: BTreeSet<String>,
    /// Invites by key (ring format 4).
    pub invites: BTreeMap<String, InviteState>,
    /// The project the ring belongs to (its genesis's `project`; for
    /// `team`, which carries none, the hash of its own genesis). `None`:
    /// a ring bound to no project (legacy, or made before ring format 4).
    pub project: Option<String>,
}

/// An invite as the ring's replay leaves it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InviteState {
    pub person: String,
    pub expires_at: i64,
    /// A device was shared to under it: it cannot be used again.
    pub used: bool,
}

impl RingState {
    pub fn key_id(&self) -> &str {
        &self.generations[self.generation as usize]
    }

    pub fn genesis_key_id(&self) -> &str {
        &self.generations[0]
    }

    pub fn is_admin(&self, member: &str, signing_key: &str) -> bool {
        self.members
            .get(member)
            .is_some_and(|m| m.role == Role::Admin && m.signing_key.as_deref() == Some(signing_key))
    }

    fn admins(&self) -> usize {
        self.members.values().filter(|m| m.role == Role::Admin).count()
    }

    /// Is `member` a current member whose registered signing key is
    /// `signing_key` (any role)?
    pub fn is_member_with_key(&self, member: &str, signing_key: &str) -> bool {
        self.members.get(member).is_some_and(|m| m.signing_key.as_deref() == Some(signing_key))
    }

    /// Does the ring trust `person` (`docs/HUB.md` §13.12): one of their
    /// devices is a current member, or a live invite names them?
    pub fn trusts(&self, person: &str, now: i64) -> bool {
        self.members.values().any(|m| m.name == person)
            || self.invites.values().any(|i| i.person == person && !i.used && now <= i.expires_at)
    }

    /// Current members whose member id is a low-order X25519 point: no key
    /// can be wrapped to them (a wrap would be readable by anyone), so
    /// rotations leave them out (BUG-070). Revoke them.
    pub fn unreachable_members(&self) -> Vec<(String, String)> {
        self.members
            .iter()
            .filter(|(id, _)| member_is_unreachable(id))
            .map(|(id, m)| (id.clone(), m.name.clone()))
            .collect()
    }
}

/// Is `member` (a member id) a key no scope key may be wrapped to? Low-order
/// X25519 points make the shared secret all zeros (BUG-010). Granting such a
/// key is refused, but rings granted before that fix, or by a hostile
/// admin, may hold one.
pub fn member_is_unreachable(member: &str) -> bool {
    parse_public_key(member).is_ok_and(|pk| is_low_order_public_key(&pk))
}

fn check_rotation(state: &RingState, r: &Rotation, members: &BTreeSet<&String>) -> std::result::Result<(), String> {
    if r.generation != state.generation + 1 {
        return Err(format!(
            "rotation to generation {} does not follow generation {}",
            r.generation, state.generation
        ));
    }
    if state.generations.contains(&r.key_id) {
        return Err(format!("rotation reuses key id {}", r.key_id));
    }
    // Exactly the remaining members, except that a member no key can be
    // wrapped to (a low-order point) may be left out: they receive nothing,
    // and refusing the rotation would stop every revocation (BUG-070).
    let wrapped: BTreeSet<&String> = r.wrapped.keys().collect();
    if !wrapped.is_subset(members) || members.difference(&wrapped).any(|m| !member_is_unreachable(m)) {
        return Err("rotation must wrap the new key to exactly the remaining members".into());
    }
    if !r.previous.iter().any(|p| p.key_id == state.key_id()) {
        return Err("rotation does not carry the previous generation key".into());
    }
    Ok(())
}

impl KeyRing {
    pub fn is_legacy(&self) -> bool {
        self.format < RING_FORMAT_SIGNED
    }

    /// Every wrapped key in the ring (legacy members and the whole log).
    fn wrapped_keys(&self) -> impl Iterator<Item = &WrappedKey> {
        let legacy = self.members.values().map(|m| &m.wrapped);
        let logged = self.log.iter().flat_map(|c| -> Box<dyn Iterator<Item = &WrappedKey> + '_> {
            match &c.op {
                RingOp::Genesis { members, .. } => Box::new(members.iter().map(|m| &m.wrapped)),
                RingOp::Grant { member } | RingOp::Share { member, .. } => Box::new(std::iter::once(&member.wrapped)),
                RingOp::Revoke { rotation, .. } | RingOp::Rotate { rotation } | RingOp::RevokeOwn { rotation, .. } => {
                    Box::new(rotation.wrapped.values())
                }
                RingOp::Invite { .. } | RingOp::Uninvite { .. } => Box::new(std::iter::empty()),
            }
        });
        legacy.chain(logged)
    }

    /// Does the ring hold HPKE-wrapped keys (so it needs ring format 3)?
    pub fn has_hpke_keys(&self) -> bool {
        self.wrapped_keys().any(WrappedKey::is_hpke)
    }

    /// Does any member grant carry a binding (so it needs ring format 3)?
    pub fn has_bindings(&self) -> bool {
        self.log.iter().any(|c| match &c.op {
            RingOp::Genesis { members, .. } => members.iter().any(|m| m.binding.is_some()),
            RingOp::Grant { member } | RingOp::Share { member, .. } => member.binding.is_some(),
            _ => false,
        })
    }

    /// Does the log hold an operation of ring format 4?
    pub fn has_shares(&self) -> bool {
        self.log.iter().any(|c| c.op.needs_shares_format())
    }

    /// The lowest ring format that can hold this ring's content.
    pub fn required_format(&self) -> u32 {
        if self.has_shares() {
            RING_FORMAT_SHARES
        } else if self.has_hpke_keys() || self.has_bindings() {
            RING_FORMAT_HPKE
        } else if self.is_legacy() {
            self.format
        } else {
            RING_FORMAT_SIGNED
        }
    }

    /// Replay and verify the ring: chain links, signatures, and that every
    /// change was signed by an admin authorised at that point of the log.
    pub fn verify(&self) -> std::result::Result<RingState, String> {
        validate_scope_name(&self.scope).map_err(|e| e.to_string())?;
        if self.format > RING_FORMAT {
            return Err(format!(
                "ring format {} needs a newer vl (this is vl {}, which reads ring formats up to {RING_FORMAT})",
                self.format,
                env!("CARGO_PKG_VERSION")
            ));
        }
        // An HPKE-wrapped key in a ring labelled older than format 3 would
        // reach vl releases that cannot read it (and a repository that
        // must not hold it).
        if self.format < RING_FORMAT_HPKE && self.has_hpke_keys() {
            return Err(format!(
                "ring format {} cannot hold HPKE-wrapped keys (needs ring format {RING_FORMAT_HPKE})",
                self.format
            ));
        }
        // Older readers would drop a binding and then fail the signature.
        if self.format < RING_FORMAT_HPKE && self.has_bindings() {
            return Err(format!(
                "ring format {} cannot hold member bindings (needs ring format {RING_FORMAT_HPKE})",
                self.format
            ));
        }
        // Older readers refuse these operations (a member's signature where
        // they expect an admin's): the ring must say so first.
        if self.format < RING_FORMAT_SHARES && self.has_shares() {
            return Err(format!(
                "ring format {} cannot hold invites or shares (needs ring format {RING_FORMAT_SHARES})",
                self.format
            ));
        }
        if self.is_legacy() {
            let mut members = BTreeMap::new();
            for (id, m) in &self.members {
                members.insert(
                    id.clone(),
                    MemberInfo {
                        name: m.name.clone(),
                        signing_key: None,
                        binding: None,
                        role: Role::Member,
                    },
                );
            }
            return Ok(RingState {
                scope: self.scope.clone(),
                legacy: true,
                generation: 0,
                generations: vec![self.key_id.clone()],
                members,
                ever_signers: BTreeMap::new(),
                bound_signers: BTreeSet::new(),
                head: String::new(),
                len: 0,
                ever_members: self.members.keys().cloned().collect(),
                invites: BTreeMap::new(),
                project: None,
            });
        }
        let scope = self.scope.as_str();
        let mut state: Option<RingState> = None;
        let mut prev = String::new();
        for (i, c) in self.log.iter().enumerate() {
            let at = |m: &str| format!("change #{i}: {m}");
            if c.seq != i as u64 {
                return Err(at("sequence number out of order"));
            }
            if c.prev != prev {
                return Err(at("does not link to the previous change (reordered, removed or tampered)"));
            }
            if !c.signature_valid(scope) {
                return Err(at("bad signature"));
            }
            parse_public_key(&c.signer).map_err(|e| at(&e.to_string()))?;
            match (&mut state, &c.op) {
                (None, RingOp::Genesis { key_id, members, project, .. }) => {
                    let project = match project {
                        None => (scope == crate::policy::DEFAULT_SCOPE).then(|| c.hash(scope)),
                        Some(_) if scope == crate::policy::DEFAULT_SCOPE => {
                            return Err(at("the 'team' ring is the project's own id and names no project"))
                        }
                        Some(p) if valid_project_id(p) => Some(p.clone()),
                        Some(_) => return Err(at("malformed project id")),
                    };
                    let mut st = RingState {
                        scope: scope.to_string(),
                        legacy: false,
                        generation: 0,
                        generations: vec![key_id.clone()],
                        members: BTreeMap::new(),
                        ever_signers: BTreeMap::new(),
                        bound_signers: BTreeSet::new(),
                        head: String::new(),
                        len: 0,
                        ever_members: BTreeSet::new(),
                        invites: BTreeMap::new(),
                        project,
                    };
                    for m in members {
                        if m.generation != 0 || parse_public_key(&m.id).is_err() || st.members.contains_key(&m.id) {
                            return Err(at("malformed genesis member"));
                        }
                        add_member(&mut st, m).map_err(|e| at(&e))?;
                    }
                    if !st.is_admin(&c.signer, &c.signing_key) {
                        return Err(at("genesis is not signed by one of its admins"));
                    }
                    state = Some(st);
                }
                (None, _) => return Err(at("the first change must be a genesis")),
                (Some(_), RingOp::Genesis { .. }) => return Err(at("a second genesis is not allowed")),
                (Some(st), op) => {
                    // A share or a member's revocation of their own device is
                    // signed by any current member; everything else by an admin.
                    let by_member = matches!(op, RingOp::Share { .. } | RingOp::RevokeOwn { .. });
                    if by_member {
                        if !st.is_member_with_key(&c.signer, &c.signing_key) {
                            return Err(at("signer is not a member of the scope at this point (forged change)"));
                        }
                    } else if !st.is_admin(&c.signer, &c.signing_key) {
                        return Err(at("signer is not an admin of the scope at this point (forged change)"));
                    }
                    match op {
                        RingOp::Genesis { .. } => unreachable!(),
                        RingOp::Grant { member } => {
                            if member.generation != st.generation {
                                return Err(at("grant wraps a key from the wrong generation"));
                            }
                            parse_public_key(&member.id).map_err(|e| at(&e.to_string()))?;
                            let demotes_last_admin = st.members.get(&member.id).is_some_and(|m| m.role == Role::Admin)
                                && member.role != Role::Admin
                                && st.admins() == 1;
                            if demotes_last_admin {
                                return Err(at("would leave the scope without an admin"));
                            }
                            add_member(st, member).map_err(|e| at(&e))?;
                        }
                        RingOp::Revoke { member, rotation } => {
                            let Some(info) = st.members.get(member) else {
                                return Err(at("revokes a non-member"));
                            };
                            if info.role == Role::Admin && st.admins() == 1 {
                                return Err(at("would leave the scope without an admin"));
                            }
                            let remaining: BTreeSet<&String> = st.members.keys().filter(|k| *k != member).collect();
                            check_rotation(st, rotation, &remaining).map_err(|e| at(&e))?;
                            st.members.remove(member);
                            st.generation = rotation.generation;
                            st.generations.push(rotation.key_id.clone());
                        }
                        RingOp::Rotate { rotation } => {
                            let all: BTreeSet<&String> = st.members.keys().collect();
                            check_rotation(st, rotation, &all).map_err(|e| at(&e))?;
                            st.generation = rotation.generation;
                            st.generations.push(rotation.key_id.clone());
                        }
                        RingOp::RevokeOwn { member, rotation } => {
                            let signer_name = &st.members[&c.signer].name;
                            let Some(info) = st.members.get(member) else {
                                return Err(at("revokes a non-member"));
                            };
                            if info.name != *signer_name {
                                return Err(at("a member may remove only their own devices"));
                            }
                            if info.role == Role::Admin && st.admins() == 1 {
                                return Err(at("would leave the scope without an admin"));
                            }
                            let remaining: BTreeSet<&String> = st.members.keys().filter(|k| *k != member).collect();
                            check_rotation(st, rotation, &remaining).map_err(|e| at(&e))?;
                            st.members.remove(member);
                            st.generation = rotation.generation;
                            st.generations.push(rotation.key_id.clone());
                        }
                        RingOp::Invite { person, key, expires_at } => {
                            if !crate::policy::valid_principal_name(person) {
                                return Err(at("invites an invalid name"));
                            }
                            if !valid_verifying_key(key) {
                                return Err(at("invite key is not an Ed25519 public key"));
                            }
                            if st.invites.contains_key(key) || st.ever_signers.contains_key(key) {
                                return Err(at("invite key is already in use"));
                            }
                            st.invites.insert(
                                key.clone(),
                                InviteState {
                                    person: person.clone(),
                                    expires_at: *expires_at,
                                    used: false,
                                },
                            );
                        }
                        RingOp::Uninvite { key } => {
                            let Some(i) = st.invites.get_mut(key) else {
                                return Err(at("cancels an unknown invite"));
                            };
                            i.used = true;
                        }
                        RingOp::Share { member, proof } => {
                            check_share(st, member, proof, c.timestamp).map_err(|e| at(&e))?;
                            add_member(st, member).map_err(|e| at(&e))?;
                        }
                    }
                }
            }
            prev = c.hash(scope);
        }
        let mut st = state.ok_or("empty ring log")?;
        st.head = prev;
        st.len = self.log.len();
        Ok(st)
    }

    /// Chain hashes, in order (empty for legacy rings).
    pub fn hashes(&self) -> Vec<String> {
        self.log.iter().map(|c| c.hash(&self.scope)).collect()
    }
}

/// Apply a genesis member or a grant to the replayed state. A signing key
/// must be a valid Ed25519 key, a binding must prove it chose this member id,
/// and a signing key can never move to another member (BUG-069: otherwise a
/// grant of Alice's public signing key to Mallory re-attributes everything
/// Alice signed).
fn add_member(st: &mut RingState, m: &MemberGrant) -> std::result::Result<(), String> {
    let pk = parse_public_key(&m.id).map_err(|e| e.to_string())?;
    match (&m.signing_key, &m.binding) {
        (None, Some(_)) => return Err("binding without a signing key".into()),
        (None, None) => {}
        (Some(k), binding) => {
            if parse_public_identity(&format!("{}{k}", m.id)).is_err() {
                return Err("invalid signing key".into());
            }
            if let Some(b) = binding {
                if !verify_binding(&pk, k, b) {
                    return Err(format!("the binding of {}'s signing key does not verify (forged grant)", m.id));
                }
            }
            if let Some((owner, _)) = st.ever_signers.get(k) {
                if *owner != m.id {
                    return Err(format!("signing key {} already belongs to member {owner}", &k[..k.len().min(16)]));
                }
            }
            st.ever_signers.insert(k.clone(), (m.id.clone(), m.name.clone()));
            if binding.is_some() {
                st.bound_signers.insert(k.clone());
            }
        }
    }
    st.ever_members.insert(m.id.clone());
    st.members.insert(
        m.id.clone(),
        MemberInfo {
            name: m.name.clone(),
            signing_key: m.signing_key.clone(),
            binding: m.binding.clone(),
            role: m.role,
        },
    );
    Ok(())
}

/// Is `key` an Ed25519 verifying key in hex?
pub fn valid_verifying_key(key: &str) -> bool {
    hex::decode(key)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .is_some_and(|b| ed25519_dalek::VerifyingKey::from_bytes(&b).is_ok())
}

/// Is `p` a project id: 32 lowercase hex digits (a ring change hash)?
pub fn valid_project_id(p: &str) -> bool {
    p.len() == 32 && p.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A project's fingerprint (`4F2A-9C1E-77B0-D3E5-A1C2`): the first 80 bits
/// of BLAKE3 `derive_key` ([`domains::HUB_PROJECT_FINGERPRINT`]) over its
/// id. What an invite link carries and what people compare before a device
/// trusts a project's key rings (`docs/HUB.md` §13.12, BUG-845).
pub fn project_fingerprint(project: &str) -> String {
    let h = blake3::derive_key(domains::HUB_PROJECT_FINGERPRINT, project.as_bytes());
    let hex = hex::encode_upper(&h[..10]);
    hex.as_bytes().chunks(4).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join("-")
}

/// Where a repository records the project fingerprint its device confirmed
/// (device-local; [`Keychain::bound`]).
pub const ANCHOR_FILE: &str = ".veil/local/project-anchor";

/// The replay's rules for a member's share (`docs/HUB.md` §13.12): a new,
/// bound device of a person the ring trusts, at the current generation,
/// proved by an invite join or by a vouch of that person's own device.
/// `at` is the share's signed time. Marks an invite used.
fn check_share(st: &mut RingState, m: &MemberGrant, proof: &ShareProof, at: i64) -> std::result::Result<(), String> {
    if m.role != Role::Member {
        return Err("a share adds a member, never an admin".into());
    }
    if m.generation != st.generation {
        return Err("share wraps a key from the wrong generation".into());
    }
    if st.ever_members.contains(&m.id) {
        return Err("shares to a device the ring held before (a removed device is never shared to again)".into());
    }
    let (Some(k), Some(_)) = (&m.signing_key, &m.binding) else {
        return Err("a shared device must carry its signing key and binding".into());
    };
    if st.ever_signers.contains_key(k) || st.invites.contains_key(k) {
        return Err("the shared device's signing key already belongs to someone in the ring".into());
    }
    let device = parse_public_identity(&format!("{}{k}{}", m.id, m.binding.as_deref().unwrap_or_default()))
        .map_err(|e| format!("malformed shared device: {e}"))?;
    match proof {
        ShareProof::Invite { key, signature } => {
            let Some(inv) = st.invites.get_mut(key) else {
                return Err("the invite is not in this ring".into());
            };
            if inv.used {
                return Err("the invite was already used".into());
            }
            if inv.person != m.name {
                return Err("the invite is for someone else".into());
            }
            if at > inv.expires_at {
                return Err("the invite had expired".into());
            }
            let msg = crate::hub::wire::join_message(&m.name, &device).ok_or("the device has no signing key")?;
            if !crate::identity::verify_signature(key, domains::SIG_CONTEXT_HUB_INVITE, &msg, signature) {
                return Err("the join does not verify under the invite's key".into());
            }
            inv.used = true;
        }
        ShareProof::Vouch { by, signature } => {
            if !st.members.values().any(|v| v.name == m.name && v.signing_key.as_deref() == Some(by.as_str())) {
                return Err("the vouch is not by a current device of the same person".into());
            }
            let msg = crate::hub::wire::vouch_message(&device).ok_or("the device has no signing key")?;
            if !crate::identity::verify_signature(by, domains::SIG_CONTEXT_HUB_DEVICE, &msg, signature) {
                return Err("the vouch does not verify".into());
            }
        }
    }
    Ok(())
}

fn genesis_proof(key: &Key, scope: &str, key_id: &str, signer: &str, signing_key: &str) -> String {
    let k = Zeroizing::new(blake3::derive_key(domains::RING_PROOF, key));
    let mut h = blake3::Hasher::new_keyed(&k);
    for part in [scope, key_id, signer, signing_key] {
        h.update(part.as_bytes());
        h.update(&[0]);
    }
    h.finalize().to_hex().to_string()
}

// ---- embargo records -----------------------------------------------------

/// An embargo, in plain text: the server keeps the embargoed work from
/// everyone outside `scope` until it is released (`docs/VISIBILITY.md`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmbargoRecord {
    /// Always [`EMBARGO_FORMAT`].
    pub format: u32,
    pub id: String,
    /// The group (scope) that may see the embargoed work before release.
    pub scope: String,
    /// Automatic release time (ms since epoch); `None` = manual release.
    pub until: Option<i64>,
    pub released_at: Option<i64>,
    pub created: i64,
    /// Server-recorded hold or failure state when release could not complete (e.g. `"failed"`, `"waiting_for_approval"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// Human-readable reason accompanying `state`, shown only to the embargo's groups and admins.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl EmbargoRecord {
    /// Released: by `vl embargo release`, or its deadline has passed without a server hold/failure.
    pub fn is_released(&self) -> bool {
        self.released_at.is_some()
            || (self.state.is_none() && self.until.is_some_and(|u| u <= crate::now_millis()))
    }

    /// The groups that may see the embargoed work before release.
    pub fn groups(&self) -> Vec<String> {
        self.scope
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect()
    }

    /// The fields fixed at creation (a record received with other ones is
    /// another embargo under the same id, and is refused).
    fn body(&self) -> (&str, &str, Option<i64>, i64) {
        (&self.id, &self.scope, self.until, self.created)
    }
}

/// Authenticity of a signed object, judged against the key rings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignatureStatus {
    Unsigned,
    /// Signature does not verify (tampered or transplanted).
    Bad,
    /// Valid signature by a key no ring knows (or by a key whose claimed
    /// identity does not match).
    Unknown { key: String },
    /// Valid signature by a known member's key.
    Good { member: String, name: String },
}

impl SignatureStatus {
    pub fn is_good(&self) -> bool {
        matches!(self, SignatureStatus::Good { .. })
    }

    pub fn label(&self) -> String {
        match self {
            SignatureStatus::Unsigned => "unsigned".into(),
            SignatureStatus::Bad => "BAD signature".into(),
            SignatureStatus::Unknown { key } => format!("signed by unknown key {}", &key[..key.len().min(16)]),
            SignatureStatus::Good { name, .. } => format!("signed by {name}"),
        }
    }
}

pub fn validate_scope_name(s: &str) -> Result<()> {
    let ok = !s.is_empty()
        && s.len() <= 64
        && s != LOCAL_SCOPE
        && s != crate::policy::RULE_SCOPE
        && !s.starts_with("embargo")
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
    if ok {
        Ok(())
    } else {
        Err(VeilError::Policy(format!(
            "invalid scope name '{s}' (use lowercase letters, digits, '-' or '_'; 'local', 'rule' and 'embargo*' are reserved)"
        )))
    }
}

/// What this identity can do with one scope.
#[derive(Default)]
struct ScopeAccess {
    /// Every generation key this identity can derive, by key id.
    keys: HashMap<String, Zeroizing<Key>>,
    /// Key id of generation 0 (what a bare-scope label means).
    genesis: String,
    /// Current generation's key id.
    current: String,
    legacy: bool,
}

/// Outcome of merging an incoming ring into the local one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RingMerge {
    Unchanged,
    Updated,
    /// Kept the local ring; the message explains why.
    Rejected(String),
}

/// Result of [`Keychain::migrate_to_hpke`] for one scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HpkeMigration {
    /// The current generation key was only ever wrapped with HPKE.
    AlreadyHpke,
    /// Rotated to this new generation, HPKE-wrapped to every member.
    Rotated(u32),
    /// Needs an admin of the scope (a legacy ring: a member).
    NotAdmin,
    /// The ring does not verify; left alone.
    Unverifiable(String),
}

/// Result of [`Keychain::recover_admin`] for one scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdminRecovery {
    /// The retired identity granted this one admin rights (and, if asked,
    /// was then revoked).
    HandedOver { revoked: bool },
    /// This identity already is an admin.
    AlreadyAdmin,
    /// The retired identity is a member but not an admin: ask an admin.
    RetiredNotAdmin,
    /// The ring does not verify; left alone.
    Unverifiable,
}

/// Was the current generation's key ever wrapped with the legacy sealed box
/// (to anyone, at any point of the log)?
pub fn current_key_has_legacy_wraps(ring: &KeyRing, state: &RingState) -> bool {
    if ring.is_legacy() {
        return true;
    }
    let g = state.generation;
    ring.log.iter().any(|c| match &c.op {
        RingOp::Genesis { members, .. } => g == 0 && members.iter().any(|m| !m.wrapped.is_hpke()),
        RingOp::Grant { member } | RingOp::Share { member, .. } => member.generation == g && !member.wrapped.is_hpke(),
        RingOp::Revoke { rotation, .. } | RingOp::Rotate { rotation } | RingOp::RevokeOwn { rotation, .. } => {
            rotation.generation == g && rotation.wrapped.values().any(|w| !w.is_hpke())
        }
        RingOp::Invite { .. } | RingOp::Uninvite { .. } => false,
    })
}

pub struct Keychain {
    backend: Arc<dyn StorageBackend>,
    identity: Option<Identity>,
    repo_id: String,
    access: RwLock<HashMap<String, Arc<ScopeAccess>>>,
    /// Repository format: decides how keys are wrapped and which ring
    /// formats may be stored.
    format: AtomicU32,
}

impl std::fmt::Debug for Keychain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Keychain({:?})", self.identity)
    }
}

impl Keychain {
    pub fn new(backend: Arc<dyn StorageBackend>, identity: Option<Identity>, repo_id: String) -> Self {
        Keychain {
            backend,
            identity,
            repo_id,
            access: RwLock::new(HashMap::new()),
            format: AtomicU32::new(crate::repo::REPO_FORMAT),
        }
    }

    /// Set the repository format (default: the newest). The object store
    /// forwards its own ([`crate::store::ObjectStore::set_format`]).
    pub fn set_format(&self, repo_format: u32) {
        self.format.store(repo_format, Ordering::SeqCst);
    }

    /// The repository format this keychain writes.
    pub fn format(&self) -> u32 {
        self.format.load(Ordering::Relaxed)
    }

    /// Wrap a scope key to a member with the construction of this
    /// repository's format: HPKE from format 3, the legacy sealed box before.
    pub fn wrap_for(&self, recipient: &[u8; 32], key: &Key, scope: &str) -> Result<WrappedKey> {
        if self.format() >= HPKE_REPO_FORMAT {
            wrap_key(recipient, key, scope)
        } else {
            wrap_key_legacy(recipient, key, scope)
        }
    }

    /// The binding to record in a grant: from ring format 3 (repository
    /// format 3) only, because older readers cannot verify a grant that
    /// carries one.
    fn binding_to_record(&self, binding: Option<String>) -> Option<String> {
        binding.filter(|_| self.format() >= HPKE_REPO_FORMAT)
    }

    pub fn identity(&self) -> Option<&Identity> {
        self.identity.as_ref()
    }

    /// The backend holding this keychain's metadata (`.veil/meta/`).
    pub(crate) fn backend(&self) -> &Arc<dyn StorageBackend> {
        &self.backend
    }

    /// Forget cached keys (after pulling new rings).
    pub fn invalidate(&self) {
        self.access.write().unwrap().clear();
    }

    /// The key for an envelope label, if this identity can obtain it:
    /// `local`, `<scope>#<key-id>` or a bare `<scope>` (= generation 0).
    pub fn key(&self, label: &str) -> Option<Key> {
        if label == LOCAL_SCOPE {
            return self.identity.as_ref().map(|i| i.local_key(&self.repo_id));
        }
        let (scope, kid) = split_label(label);
        let access = self.scope_access(scope);
        let kid = kid.unwrap_or(&access.genesis);
        access.keys.get(kid).map(|k| **k)
    }

    pub fn has(&self, label: &str) -> bool {
        self.key(label).is_some()
    }

    pub fn require(&self, label: &str) -> Result<Key> {
        self.key(label).ok_or_else(|| VeilError::Redacted {
            scope: label.to_string(),
        })
    }

    /// Label and key to seal *new* content for `scope`: the current
    /// generation. Labels that already name a generation (and `local`)
    /// are used as they are.
    pub fn sealing_key(&self, scope: &str) -> Result<(String, Key)> {
        if scope == LOCAL_SCOPE || scope.contains(domains::GENERATION_SEPARATOR) {
            return Ok((scope.to_string(), self.require(scope)?));
        }
        let access = self.scope_access(scope);
        let redacted = || VeilError::Redacted { scope: scope.to_string() };
        let key = access.keys.get(&access.current).ok_or_else(redacted)?;
        let label = if access.legacy {
            scope.to_string()
        } else {
            generation_label(scope, &access.current)
        };
        Ok((label, **key))
    }

    /// Can this identity seal new content for `scope` (a current member)?
    pub fn is_member(&self, scope: &str) -> bool {
        self.sealing_key(scope).is_ok()
    }

    fn scope_access(&self, scope: &str) -> Arc<ScopeAccess> {
        if let Some(a) = self.access.read().unwrap().get(scope) {
            return a.clone();
        }
        let a = Arc::new(self.load_ring(scope).ok().flatten().map(|r| self.derive_access(&r)).unwrap_or_default());
        self.access.write().unwrap().insert(scope.to_string(), a.clone());
        a
    }

    /// Every key of `ring` this identity can derive. A ring that does not
    /// verify yields nothing.
    fn derive_access(&self, ring: &KeyRing) -> ScopeAccess {
        let Ok(state) = ring.verify() else {
            return ScopeAccess::default();
        };
        // A ring of another project, or one this device has not anchored,
        // neither seals nor opens anything here (BUG-845).
        if self.bound(&state).is_err() {
            return ScopeAccess::default();
        }
        let mut access = ScopeAccess {
            genesis: state.genesis_key_id().to_string(),
            current: state.key_id().to_string(),
            legacy: state.legacy,
            ..Default::default()
        };
        let Some(me) = &self.identity else { return access };
        let my_id = me.public_hex();
        let scope = ring.scope.as_str();
        if ring.is_legacy() {
            if let Some(m) = ring.members.get(&my_id) {
                if let Ok(k) = me.unwrap_key(&m.wrapped, scope) {
                    let fp = key_fingerprint(&k);
                    if ring.key_id.is_empty() || ring.key_id == fp {
                        access.genesis = fp.clone();
                        access.current = fp.clone();
                        access.keys.insert(fp, Zeroizing::new(k));
                    }
                }
            }
            return access;
        }
        // Wrapped keys addressed to me, with their generation.
        let mut candidates: Vec<(u32, &WrappedKey)> = Vec::new();
        let mut rotations: BTreeMap<u32, &Rotation> = BTreeMap::new();
        for c in &ring.log {
            match &c.op {
                RingOp::Genesis { members, .. } => candidates.extend(members.iter().filter(|m| m.id == my_id).map(|m| (0, &m.wrapped))),
                RingOp::Grant { member } | RingOp::Share { member, .. } if member.id == my_id => {
                    candidates.push((member.generation, &member.wrapped))
                }
                RingOp::Grant { .. } | RingOp::Share { .. } | RingOp::Invite { .. } | RingOp::Uninvite { .. } => {}
                RingOp::Revoke { rotation, .. } | RingOp::Rotate { rotation } | RingOp::RevokeOwn { rotation, .. } => {
                    rotations.insert(rotation.generation, rotation);
                    if let Some(w) = rotation.wrapped.get(&my_id) {
                        candidates.push((rotation.generation, w));
                    }
                }
            }
        }
        candidates.sort_by_key(|(g, _)| std::cmp::Reverse(*g));
        let mut newest = None;
        for (g, w) in candidates {
            let Some(kid) = state.generations.get(g as usize) else { continue };
            if let Ok(k) = me.unwrap_key(w, scope) {
                if key_fingerprint(&k) == *kid {
                    newest = Some((g, Zeroizing::new(k)));
                    break;
                }
            }
        }
        let Some((mut g, mut key)) = newest else { return access };
        access.keys.insert(state.generations[g as usize].clone(), key.clone());
        // Walk back through the generations.
        while g > 0 {
            let Some(rot) = rotations.get(&g) else { break };
            let want = &state.generations[g as usize - 1];
            let mut next = None;
            for p in &rot.previous {
                let Ok(raw) = p.sealed.open(&key).map(Zeroizing::new) else { continue };
                let Ok(k) = <Key>::try_from(raw.as_slice()) else { continue };
                if key_fingerprint(&k) != p.key_id {
                    continue;
                }
                if p.key_id == *want {
                    next = Some(Zeroizing::new(k));
                }
                access.keys.insert(p.key_id.clone(), Zeroizing::new(k));
            }
            match next {
                Some(k) => key = k,
                None => break,
            }
            g -= 1;
        }
        access
    }

    // ---- locking -----------------------------------------------------------

    /// Take the repository lock for a read-modify-write of shared metadata
    /// (key rings, embargo records). Reentrant, so it also works inside a
    /// transaction on this thread (push and pull merge metadata there).
    /// Cached keys are dropped: another process may have changed the rings
    /// since they were derived.
    pub(crate) fn lock_meta(&self) -> Result<RepoLock> {
        let lock = RepoLock::acquire_reentrant(self.backend.clone())?;
        self.invalidate();
        Ok(lock)
    }

    // ---- key rings -------------------------------------------------------

    fn ring_path(scope: &str) -> VPath {
        VPath::new(&format!(".veil/meta/keyrings/{scope}.json")).unwrap()
    }

    pub fn load_ring(&self, scope: &str) -> Result<Option<KeyRing>> {
        validate_scope_name(scope)?;
        match self.backend.read_opt(&Self::ring_path(scope))? {
            Some(b) => {
                let ring: KeyRing = serde_json::from_slice(&b)?;
                if ring.scope != scope {
                    return Err(VeilError::Corrupt(
                        format!("key ring {scope}"),
                        format!("file claims scope '{}'", ring.scope),
                    ));
                }
                Ok(Some(ring))
            }
            None => Ok(None),
        }
    }

    pub fn save_ring(&self, ring: &KeyRing) -> Result<()> {
        let _lock = self.lock_meta()?;
        validate_scope_name(&ring.scope)?;
        let have = self.format();
        let needs = ring.format.max(ring.required_format());
        if needs > max_ring_format(have) {
            let (what, repo) = match needs {
                RING_FORMAT_HPKE => ("HPKE-wrapped keys", HPKE_REPO_FORMAT),
                _ => ("invites and shares", SHARES_REPO_FORMAT),
            };
            return Err(VeilError::Unsupported(format!(
                "this repository is at format {have} and cannot store the key ring of scope '{}' \
                 (ring format {needs}: {what}); upgrade it with `vl upgrade` \
                 once everyone who uses it runs vl {} or later",
                ring.scope,
                crate::repo::min_vl_for_format(repo)
            )));
        }
        self.backend
            .write(&Self::ring_path(&ring.scope), &serde_json::to_vec_pretty(ring)?)?;
        self.invalidate();
        Ok(())
    }

    /// Every ring that parses (malformed files are skipped), `team` first:
    /// it names the project the others must belong to ([`Keychain::bound`]),
    /// so whoever merges them in this order takes it first.
    pub fn rings(&self) -> Result<Vec<KeyRing>> {
        let dir = VPath::new(".veil/meta/keyrings")?;
        if !self.backend.exists(&dir)? {
            return Ok(vec![]);
        }
        let mut out = Vec::new();
        for e in self.backend.list_dir(&dir)? {
            if let Some(scope) = e.name.strip_suffix(".json") {
                if let Ok(Some(r)) = self.load_ring(scope) {
                    out.push(r);
                }
            }
        }
        out.sort_by(|a, b| (a.scope != crate::policy::DEFAULT_SCOPE, &a.scope).cmp(&(b.scope != crate::policy::DEFAULT_SCOPE, &b.scope)));
        Ok(out)
    }

    /// Verified state of a scope's ring.
    pub fn ring_state(&self, scope: &str) -> Result<Option<std::result::Result<RingState, String>>> {
        Ok(self.load_ring(scope)?.map(|r| self.trusted_state(&r)))
    }

    /// Replay `ring` and check that it is bound to this repository's
    /// project ([`Keychain::bound`]): what every decision about keys uses.
    pub fn trusted_state(&self, ring: &KeyRing) -> std::result::Result<RingState, String> {
        let st = ring.verify()?;
        self.bound(&st)?;
        Ok(st)
    }

    /// The project fingerprint this device confirmed for this repository
    /// ([`ANCHOR_FILE`]): `None` if the repository records none (it is not
    /// a clone of a server project); `Some("")` if it records that nothing
    /// is confirmed yet, so no key ring is trusted.
    pub fn anchor(&self) -> Option<String> {
        let raw = self.backend.read_opt(&VPath::new(ANCHOR_FILE).unwrap()).ok()??;
        let text = String::from_utf8_lossy(&raw);
        Some(crate::hub::wire::normalize_fingerprint(text.trim()).unwrap_or_default())
    }

    /// Record the project fingerprint this device confirmed (`""`: none
    /// yet, trust no ring). Device-local, never synced.
    pub fn set_anchor(&self, fingerprint: &str) -> Result<()> {
        self.backend.write(&VPath::new(ANCHOR_FILE)?, fingerprint.as_bytes())?;
        self.invalidate();
        Ok(())
    }

    /// The id of this repository's project: its `team` ring's genesis
    /// hash, if that ring verifies and is the one this device anchored.
    pub fn project_id(&self) -> Option<String> {
        let team = self.load_ring(crate::policy::DEFAULT_SCOPE).ok()??;
        let st = team.verify().ok()?;
        self.bound(&st).ok()?;
        st.project
    }

    /// Is a verified ring this repository's (BUG-845)? `team` must be the
    /// ring whose fingerprint this device anchored (when it records one,
    /// [`Keychain::anchor`]); every other ring must name this repository's
    /// project ([`Keychain::project_id`]) in its signed genesis. A ring
    /// bound to no project is accepted only where nothing is anchored (a
    /// repository that is not a clone of a server project).
    pub fn bound(&self, st: &RingState) -> std::result::Result<(), String> {
        let anchor = self.anchor();
        if st.scope == crate::policy::DEFAULT_SCOPE {
            return match (anchor, &st.project) {
                (None, _) => Ok(()),
                (Some(a), _) if a.is_empty() => Err(
                    "this device has not confirmed the project's fingerprint yet, so it trusts none of its key rings".into(),
                ),
                (Some(a), Some(p)) if project_fingerprint(p) == a => Ok(()),
                (Some(a), _) => Err(format!(
                    "it is not the project's key ring this device confirmed (fingerprint {a}): another project's, or one the \
                     server made"
                )),
            };
        }
        match (&st.project, anchor) {
            (Some(p), _) => match self.project_id() {
                Some(mine) if mine == *p => Ok(()),
                Some(_) => Err("it belongs to another project".into()),
                None => Err("it belongs to a project this repository holds no confirmed 'team' key ring of".into()),
            },
            (None, Some(_)) => Err("it is bound to no project (made before key rings named their project)".into()),
            (None, None) => Ok(()),
        }
    }

    fn me(&self) -> Result<&Identity> {
        self.identity
            .as_ref()
            .ok_or_else(|| VeilError::repo("no identity configured (run `vl identity new`)"))
    }

    fn signed_change(&self, ring: &KeyRing, op: RingOp) -> Result<RingChange> {
        let me = self.me()?;
        let mut c = RingChange {
            seq: ring.log.len() as u64,
            prev: ring.log.last().map(|c| c.hash(&ring.scope)).unwrap_or_default(),
            timestamp: crate::now_millis(),
            signer: me.public_hex(),
            signing_key: me.verifying_hex(),
            op,
            signature: String::new(),
        };
        c.signature = me.sign(RING_SIG_CONTEXT, &c.signing_body(&ring.scope));
        Ok(c)
    }

    fn append(&self, mut ring: KeyRing, op: RingOp) -> Result<KeyRing> {
        let c = self.signed_change(&ring, op)?;
        ring.log.push(c);
        ring.format = ring.format.max(ring.required_format());
        ring.verify().map_err(|e| VeilError::Policy(format!("refusing to write an invalid key ring: {e}")))?;
        self.save_ring(&ring)?;
        Ok(ring)
    }

    fn genesis(&self, scope: &str, key: &Key, members: Vec<MemberGrant>) -> Result<KeyRing> {
        let me = self.me()?;
        let key_id = key_fingerprint(key);
        let proof = genesis_proof(key, scope, &key_id, &me.public_hex(), &me.verifying_hex());
        let ring = KeyRing {
            scope: scope.to_string(),
            format: RING_FORMAT_SIGNED,
            ..Default::default()
        };
        // Every ring but `team` names its project, from format 7 on (BUG-845).
        let project = (scope != crate::policy::DEFAULT_SCOPE && self.format() >= SHARES_REPO_FORMAT)
            .then(|| self.project_id())
            .flatten();
        self.append(ring, RingOp::Genesis { key_id, members, proof, project })
    }

    /// Create a new scope whose only member (and admin) is this identity.
    pub fn create_scope(&self, scope: &str) -> Result<()> {
        let _lock = self.lock_meta()?;
        validate_scope_name(scope)?;
        if self.load_ring(scope)?.is_some() {
            return Err(VeilError::AlreadyExists(format!("scope '{scope}'")));
        }
        let me = self.me()?;
        let key = Zeroizing::new(random_key());
        let members = vec![MemberGrant {
            id: me.public_hex(),
            name: me.name.clone(),
            signing_key: Some(me.verifying_hex()),
            binding: self.binding_to_record(Some(me.binding_hex())),
            role: Role::Admin,
            generation: 0,
            wrapped: self.wrap_for(&me.public_key(), &key, scope)?,
        }];
        self.genesis(scope, &key, members)?;
        Ok(())
    }

    /// Load a ring for modification by this identity: upgrades a legacy
    /// ring (this identity becomes its first admin) and checks that this
    /// identity is an admin.
    fn ring_for_admin(&self, scope: &str, action: &str) -> Result<(KeyRing, RingState)> {
        let ring = self
            .load_ring(scope)?
            .ok_or_else(|| VeilError::NotFound(format!("scope '{scope}'")))?;
        let ring = if ring.is_legacy() { self.upgrade_legacy(ring)? } else { ring };
        let state = self
            .trusted_state(&ring)
            .map_err(|e| VeilError::Policy(format!("key ring for '{scope}' is not trusted: {e}")))?;
        let me = self.me()?;
        if !state.is_admin(&me.public_hex(), &me.verifying_hex()) {
            return Err(VeilError::Policy(format!("only an admin of scope '{scope}' can {action}")));
        }
        Ok((ring, state))
    }

    /// Convert a legacy ring into a signed one. Every legacy member keeps
    /// their wrapped key (generation 0); this identity becomes the admin.
    fn upgrade_legacy(&self, ring: KeyRing) -> Result<KeyRing> {
        let me = self.me()?;
        let scope = ring.scope.clone();
        let key = self.key(&scope).ok_or_else(|| {
            VeilError::Policy(format!("you are not a member of scope '{scope}', so you cannot change it"))
        })?;
        let key = Zeroizing::new(key);
        let my_id = me.public_hex();
        let mut members = Vec::new();
        for (id, m) in &ring.members {
            let mine = *id == my_id;
            members.push(MemberGrant {
                id: id.clone(),
                name: m.name.clone(),
                signing_key: mine.then(|| me.verifying_hex()),
                binding: self.binding_to_record(mine.then(|| me.binding_hex())),
                role: if mine { Role::Admin } else { Role::Member },
                generation: 0,
                wrapped: m.wrapped.clone(),
            });
        }
        self.genesis(&scope, &key, members)
    }

    /// Give an identity access to the scope's current key generation (or
    /// update an existing member's name, role or signing key). `public_key`
    /// is the full public identity (`vl identity show`); the short member
    /// id also works but leaves the member without a signing key. The
    /// earlier unbound full form (`veil1<x25519><ed25519>`) is refused:
    /// nothing proves its signing key belongs to that member (BUG-069).
    pub fn grant(&self, scope: &str, public_key: &str, name: &str) -> Result<()> {
        self.grant_role(scope, public_key, name, Role::Member)
    }

    pub fn grant_role(&self, scope: &str, public_key: &str, name: &str, role: Role) -> Result<()> {
        let _lock = self.lock_meta()?;
        let pk = parse_public_identity(public_key)?;
        if pk.is_unbound() {
            return Err(VeilError::Policy(format!(
                "that public identity has a signing key but no proof that it belongs to {} (it was printed by \
                 an earlier vl, or pieced together); ask {name} for the `public key` line of `vl identity show` \
                 from this vl, or grant just their member id {} (read access, no signing key)",
                pk.member_id(),
                pk.member_id()
            )));
        }
        let (ring, state) = self.ring_for_admin(scope, "grant access")?;
        if let Some(k) = pk.signing_hex() {
            if let Some((owner, owner_name)) = state.ever_signers.get(&k).filter(|(o, _)| *o != pk.member_id()) {
                return Err(VeilError::Policy(format!(
                    "that signing key already belongs to {} ({owner}) in scope '{scope}'; a signing key \
                     cannot move to another member",
                    owner_name
                )));
            }
        }
        let key = Zeroizing::new(self.require(&generation_label(scope, state.key_id()))?);
        let existing = state.members.get(&pk.member_id());
        let (signing_key, binding) = match (pk.signing_hex(), existing) {
            (Some(k), _) => (Some(k), pk.binding_hex()),
            (None, Some(m)) => (m.signing_key.clone(), m.binding.clone()),
            (None, None) => (None, None),
        };
        let member = MemberGrant {
            id: pk.member_id(),
            name: name.to_string(),
            signing_key,
            binding: self.binding_to_record(binding),
            role,
            generation: state.generation,
            wrapped: self.wrap_for(&pk.x25519, &key, scope).map_err(|e| {
                VeilError::Crypto(format!("cannot wrap the scope key to {name} ({}): {e}", pk.member_id()))
            })?,
        };
        self.append(ring, RingOp::Grant { member })?;
        Ok(())
    }

    /// Add an invite to `scope` (ring format 4; an admin): a device whose
    /// join verifies under `key` may be shared to as `person` until
    /// `expires_at` (`docs/HUB.md` §13.12).
    pub fn invite(&self, scope: &str, person: &str, key: &str, expires_at: i64) -> Result<()> {
        let _lock = self.lock_meta()?;
        let (ring, _) = self.ring_for_admin(scope, "invite people")?;
        self.append(
            ring,
            RingOp::Invite {
                person: person.to_string(),
                key: key.to_string(),
                expires_at,
            },
        )?;
        Ok(())
    }

    /// Cancel the invite under `key` (an admin); `false` if `scope` holds
    /// no usable invite under it.
    pub fn uninvite(&self, scope: &str, key: &str) -> Result<bool> {
        let _lock = self.lock_meta()?;
        let (ring, state) = self.ring_for_admin(scope, "cancel invites")?;
        if !state.invites.get(key).is_some_and(|i| !i.used) {
            return Ok(false);
        }
        self.append(ring, RingOp::Uninvite { key: key.to_string() })?;
        Ok(true)
    }

    /// Share the current key of `scope` with the device `public_identity`
    /// (full form) as `name` (any current member, ring format 4). The
    /// replay refuses it unless `proof` holds (`docs/HUB.md` §13.12).
    pub fn share(&self, scope: &str, public_identity: &str, name: &str, proof: ShareProof) -> Result<()> {
        let _lock = self.lock_meta()?;
        let pk = parse_public_identity(public_identity)?;
        let (Some(signing_key), Some(binding)) = (pk.signing_hex(), pk.binding_hex()) else {
            return Err(VeilError::Policy("a device is shared to only with its full public identity".into()));
        };
        let (ring, state) = self.ring_for_member(scope)?;
        let key = Zeroizing::new(self.require(&generation_label(scope, state.key_id()))?);
        let member = MemberGrant {
            id: pk.member_id(),
            name: name.to_string(),
            signing_key: Some(signing_key),
            binding: Some(binding),
            role: Role::Member,
            generation: state.generation,
            wrapped: self.wrap_for(&pk.x25519, &key, scope)?,
        };
        self.append(ring, RingOp::Share { member, proof })?;
        Ok(())
    }

    /// Remove the device `member` (a member id) from `scope` and rotate: as
    /// an admin, any device; as a member, only one of their own (same
    /// name). `false` if it is not a member.
    pub fn revoke_device(&self, scope: &str, member: &str) -> Result<bool> {
        let _lock = self.lock_meta()?;
        let id = format_public_key(&parse_public_key(member)?);
        let (ring, state) = self.ring_for_member(scope)?;
        let Some(info) = state.members.get(&id) else { return Ok(false) };
        let me = self.me()?;
        let admin = state.is_admin(&me.public_hex(), &me.verifying_hex());
        if !admin && state.members.get(&me.public_hex()).is_none_or(|m| m.name != info.name) {
            return Err(VeilError::Policy(format!(
                "only an admin of scope '{scope}' removes someone else's device"
            )));
        }
        let remaining: Vec<&String> = state.members.keys().filter(|k| **k != id).collect();
        let rotation = self.rotation(scope, &state, &remaining)?;
        let op = if admin {
            RingOp::Revoke { member: id, rotation }
        } else {
            RingOp::RevokeOwn { member: id, rotation }
        };
        self.append(ring, op)?;
        Ok(true)
    }

    /// Load a ring for a change by this identity as a current member (any
    /// role).
    fn ring_for_member(&self, scope: &str) -> Result<(KeyRing, RingState)> {
        let ring = self
            .load_ring(scope)?
            .ok_or_else(|| VeilError::NotFound(format!("scope '{scope}'")))?;
        let state = self
            .trusted_state(&ring)
            .map_err(|e| VeilError::Policy(format!("key ring for '{scope}' is not trusted: {e}")))?;
        let me = self.me()?;
        if !state.is_member_with_key(&me.public_hex(), &me.verifying_hex()) {
            return Err(VeilError::Policy(format!("this device is not a member of scope '{scope}'")));
        }
        Ok((ring, state))
    }

    /// Current members of `scope` that no key can be wrapped to (low-order
    /// member ids, see [`RingState::unreachable_members`]): rotations leave
    /// them out. `(member id, name)`.
    pub fn unreachable_members(&self, scope: &str) -> Vec<(String, String)> {
        match self.ring_state(scope) {
            Ok(Some(Ok(st))) => st.unreachable_members(),
            _ => Vec::new(),
        }
    }

    fn rotation(&self, scope: &str, state: &RingState, members: &[&String]) -> Result<Rotation> {
        let old = Zeroizing::new(self.require(&generation_label(scope, state.key_id()))?);
        let new = Zeroizing::new(random_key());
        let new_id = key_fingerprint(&new);
        let mut wrapped = BTreeMap::new();
        for m in members {
            // A low-order member id gets nothing (a wrap to it would publish
            // the key); replay allows exactly this omission (BUG-070).
            if member_is_unreachable(m) {
                continue;
            }
            let w = parse_public_key(m).and_then(|pk| self.wrap_for(&pk, &new, scope)).map_err(|e| {
                let name = state.members.get(*m).map_or("?", |i| i.name.as_str());
                VeilError::Crypto(format!(
                    "cannot wrap the new key of scope '{scope}' to member {name} ({m}): {e}; revoke them first"
                ))
            })?;
            wrapped.insert((*m).clone(), w);
        }
        Ok(Rotation {
            generation: state.generation + 1,
            key_id: new_id.clone(),
            previous: vec![SealedKey {
                key_id: state.key_id().to_string(),
                sealed: Envelope::seal_random(
                    &new,
                    &format!("{}{}", domains::PREV_KEY_LABEL_PREFIX, generation_label(scope, &new_id)),
                    &*old,
                )?,
            }],
            wrapped,
        })
    }

    /// Remove a member and rotate the scope key: content sealed from now on
    /// uses a new generation the revoked member never receives. They keep
    /// whatever they could already decrypt.
    pub fn revoke(&self, scope: &str, public_key: &str) -> Result<bool> {
        let _lock = self.lock_meta()?;
        let id = format_public_key(&parse_public_key(public_key)?);
        let (ring, state) = self.ring_for_admin(scope, "revoke access")?;
        if !state.members.contains_key(&id) {
            return Ok(false);
        }
        let remaining: Vec<&String> = state.members.keys().filter(|k| **k != id).collect();
        let rotation = self.rotation(scope, &state, &remaining)?;
        self.append(ring, RingOp::Revoke { member: id, rotation })?;
        Ok(true)
    }

    /// Start a new key generation for the current members.
    pub fn rotate(&self, scope: &str) -> Result<u32> {
        let _lock = self.lock_meta()?;
        let (ring, state) = self.ring_for_admin(scope, "rotate the key")?;
        let all: Vec<&String> = state.members.keys().collect();
        let rotation = self.rotation(scope, &state, &all)?;
        let g = rotation.generation;
        self.append(ring, RingOp::Rotate { rotation })?;
        Ok(g)
    }

    /// Move a scope's key wrapping to HPKE (`vl upgrade` to format 3): if
    /// the current key generation was ever wrapped with the legacy sealed
    /// box, start a new generation whose key is HPKE-wrapped to every
    /// current member (a signed `Rotate` change; the previous key stays
    /// reachable through the rotation, so history stays readable).
    ///
    /// The legacy wraps already in the log stay there: the log is
    /// append-only and signed, and removing them would not un-publish them.
    /// Content sealed under generations up to now therefore keeps depending
    /// on the legacy construction; content sealed from now on does not.
    pub fn migrate_to_hpke(&self, scope: &str) -> Result<HpkeMigration> {
        let _lock = self.lock_meta()?;
        if self.format() < HPKE_REPO_FORMAT {
            return Err(VeilError::repo(format!(
                "this repository is at format {}; HPKE key wrapping needs format {HPKE_REPO_FORMAT}",
                self.format()
            )));
        }
        let Some(ring) = self.load_ring(scope)? else {
            return Err(VeilError::NotFound(format!("scope '{scope}'")));
        };
        let state = match ring.verify() {
            Ok(st) => st,
            Err(e) => return Ok(HpkeMigration::Unverifiable(e)),
        };
        if !current_key_has_legacy_wraps(&ring, &state) {
            return Ok(HpkeMigration::AlreadyHpke);
        }
        let me = self.me()?;
        let allowed = if ring.is_legacy() {
            self.is_member(scope)
        } else {
            state.is_admin(&me.public_hex(), &me.verifying_hex())
        };
        if !allowed {
            return Ok(HpkeMigration::NotAdmin);
        }
        Ok(HpkeMigration::Rotated(self.rotate(scope)?))
    }

    /// Scopes whose current key still has legacy wraps (the `3:hpke-ring-keys`
    /// step is pending for them), with whether this identity may move them
    /// to HPKE (an admin; for a legacy ring, a member).
    pub fn hpke_migration_pending(&self) -> Result<Vec<(String, bool)>> {
        let mut out = Vec::new();
        let me = self.identity.as_ref();
        for ring in self.rings()? {
            let Ok(state) = ring.verify() else { continue };
            if !current_key_has_legacy_wraps(&ring, &state) {
                continue;
            }
            let allowed = match me {
                None => false,
                Some(_) if ring.is_legacy() => self.is_member(&ring.scope),
                Some(me) => state.is_admin(&me.public_hex(), &me.verifying_hex()),
            };
            out.push((ring.scope.clone(), allowed));
        }
        Ok(out)
    }

    /// Hand the admin rights of `retired` (an identity this device used
    /// before `vl identity new --force`) over to this identity, in every
    /// scope (BUG-089): the retired identity signs a grant that makes this
    /// identity an admin, with its full public identity. With
    /// `revoke_retired`, this identity then revokes the retired one (which
    /// rotates the key). Scopes where this identity is already an admin, or
    /// where the retired one is not, are reported and left alone.
    pub fn recover_admin(&self, retired: &Identity, revoke_retired: bool) -> Result<Vec<(String, AdminRecovery)>> {
        let _lock = self.lock_meta()?;
        let me = self.me()?.clone();
        if me.public_hex() == retired.public_hex() {
            return Err(VeilError::repo("that is the current identity, not a replaced one"));
        }
        let old = Keychain::new(self.backend.clone(), Some(retired.clone()), self.repo_id.clone());
        old.set_format(self.format());
        let mut out = Vec::new();
        for ring in self.rings()? {
            let scope = ring.scope.clone();
            let Ok(state) = ring.verify() else {
                out.push((scope, AdminRecovery::Unverifiable));
                continue;
            };
            let old_admin = if ring.is_legacy() {
                old.is_member(&scope)
            } else {
                state.is_admin(&retired.public_hex(), &retired.verifying_hex())
            };
            let me_admin = !ring.is_legacy() && state.is_admin(&me.public_hex(), &me.verifying_hex());
            let retired_member = state.members.contains_key(&retired.public_hex());
            let outcome = if !me_admin && !old_admin {
                if !retired_member {
                    continue;
                }
                AdminRecovery::RetiredNotAdmin
            } else {
                if !me_admin {
                    old.grant_role(&scope, &me.public_id(), &me.name, Role::Admin)?;
                    self.invalidate();
                }
                let revoked = revoke_retired && retired_member && self.revoke(&scope, &retired.public_hex())?;
                if me_admin && !revoked {
                    AdminRecovery::AlreadyAdmin
                } else {
                    AdminRecovery::HandedOver { revoked }
                }
            };
            out.push((scope, outcome));
        }
        Ok(out)
    }

    /// Checks only key holders can make: the genesis proof, and that every
    /// rotation's `previous` keys decrypt to the generation they claim.
    fn check_with_keys(&self, ring: &KeyRing, state: &RingState) -> std::result::Result<(), String> {
        if ring.is_legacy() {
            return Ok(());
        }
        let access = self.derive_access(ring);
        if let (Some(RingOp::Genesis { key_id, proof, .. }), Some(first)) = (ring.log.first().map(|c| &c.op), ring.log.first()) {
            if let Some(k) = access.keys.get(key_id) {
                if genesis_proof(k, &ring.scope, key_id, &first.signer, &first.signing_key) != *proof {
                    return Err("genesis proof does not match the scope key (forged ring)".into());
                }
            }
        }
        for c in &ring.log {
            if let RingOp::Revoke { rotation, .. } | RingOp::Rotate { rotation } | RingOp::RevokeOwn { rotation, .. } = &c.op {
                if access.keys.contains_key(&rotation.key_id) {
                    let prev = &state.generations[rotation.generation as usize - 1];
                    if !access.keys.contains_key(prev) {
                        return Err(format!(
                            "generation {} does not unlock generation {}",
                            rotation.generation,
                            rotation.generation - 1
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    /// Merge a ring received from another repository into this one.
    ///
    /// Rules (see ARCHITECTURE §3): an incoming ring must verify; a signed
    /// ring replaces the local one only if the local log is a prefix of it
    /// (fast-forward). An older prefix (a replayed ring) is ignored, and a
    /// diverged log keeps the local ring and reports it. Unsigned legacy
    /// rings never override a signed ring and are never merged as a union.
    pub fn merge_ring(&self, incoming: &KeyRing) -> Result<RingMerge> {
        let _lock = self.lock_meta()?;
        let scope = incoming.scope.as_str();
        let reject = |m: String| Ok(RingMerge::Rejected(format!("key ring for scope '{scope}': {m}")));
        let inc = match incoming.verify() {
            Ok(s) => s,
            Err(e) => return reject(format!("rejected, it does not verify ({e})")),
        };
        if let Err(e) = self.bound(&inc) {
            return reject(format!("refused: {e}"));
        }
        if let Err(e) = self.check_with_keys(incoming, &inc) {
            return reject(format!("rejected ({e})"));
        }
        let local = match self.load_ring(scope) {
            Ok(Some(l)) => l,
            Ok(None) => {
                self.save_ring(incoming)?;
                return Ok(RingMerge::Updated);
            }
            Err(_) => {
                self.save_ring(incoming)?;
                return Ok(RingMerge::Updated);
            }
        };
        if local == *incoming {
            return Ok(RingMerge::Unchanged);
        }
        let loc = match local.verify() {
            Ok(s) => s,
            Err(e) => {
                if incoming.is_legacy() {
                    return reject(format!("local ring does not verify ({e}) and the incoming one is unsigned"));
                }
                self.save_ring(incoming)?;
                return Ok(RingMerge::Updated);
            }
        };
        let different_keys = || {
            reject("exists on both sides with different keys; the incoming key ring was not merged".to_string())
        };
        if loc.genesis_key_id() != inc.genesis_key_id() && !loc.genesis_key_id().is_empty() {
            return different_keys();
        }
        match (local.is_legacy(), incoming.is_legacy()) {
            (true, true) => reject("both sides hold unsigned legacy rings that differ; kept the local one (an admin can upgrade it by granting, revoking or rotating)".into()),
            (true, false) => {
                self.save_ring(incoming)?;
                Ok(RingMerge::Updated)
            }
            (false, true) => reject("incoming ring is unsigned (legacy); the signed local ring supersedes it".into()),
            (false, false) => {
                let lh = local.hashes();
                let ih = incoming.hashes();
                if lh[0] != ih[0] {
                    return reject("has an unrelated history (different genesis); kept the local ring".into());
                }
                if ih.len() > lh.len() && ih[..lh.len()] == lh[..] {
                    self.save_ring(incoming)?;
                    Ok(RingMerge::Updated)
                } else if lh.len() >= ih.len() && lh[..ih.len()] == ih[..] {
                    Ok(RingMerge::Unchanged)
                } else {
                    let fork = lh.iter().zip(&ih).take_while(|(a, b)| a == b).count();
                    let theirs: Vec<String> = incoming.log[fork..].iter().map(|c| c.op.summary()).collect();
                    reject(format!(
                        "has diverged at change #{fork}; kept the local ring (not applied: {})",
                        theirs.join("; ")
                    ))
                }
            }
        }
    }

    /// Every signing key known from any ring: key → (member id, name).
    ///
    /// Within a ring a key belongs to one member. Across rings, a key that
    /// two rings give to different members is resolved in favour of the
    /// rings where the binding was proved; if that still leaves more than
    /// one member (or none was proved), the key is left out, so its
    /// signatures show as unknown rather than as someone else's (BUG-069).
    pub fn known_signers(&self) -> BTreeMap<String, (String, String)> {
        // key → [(member, name, bound)]
        let mut claims: BTreeMap<String, Vec<(String, String, bool)>> = BTreeMap::new();
        for r in self.rings().unwrap_or_default() {
            if let Ok(st) = self.trusted_state(&r) {
                for (k, (member, name)) in st.ever_signers {
                    let bound = st.bound_signers.contains(&k);
                    claims.entry(k).or_default().push((member, name, bound));
                }
            }
        }
        let mut out = BTreeMap::new();
        for (k, c) in claims {
            let bound: Vec<&(String, String, bool)> = c.iter().filter(|x| x.2).collect();
            let pick = if bound.is_empty() { c.iter().collect::<Vec<_>>() } else { bound };
            if pick.iter().all(|x| x.0 == pick[0].0) {
                out.insert(k, (pick[0].0.clone(), pick[0].1.clone()));
            }
        }
        if let Some(me) = &self.identity {
            out.insert(me.verifying_hex(), (me.public_hex(), me.name.clone()));
        }
        out
    }

    fn judge(&self, sig: &Signature, valid: bool, signers: &BTreeMap<String, (String, String)>) -> SignatureStatus {
        if !valid {
            return SignatureStatus::Bad;
        }
        match signers.get(&sig.key) {
            Some((member, name)) if *member == sig.signer => SignatureStatus::Good {
                member: member.clone(),
                name: name.clone(),
            },
            _ => SignatureStatus::Unknown { key: sig.key.clone() },
        }
    }

    /// Signature status of a snapshot, against all rings.
    pub fn snapshot_status(&self, s: &Snapshot) -> SignatureStatus {
        self.snapshot_status_with(s, &self.known_signers())
    }

    /// Like [`Keychain::snapshot_status`] with a precomputed signer table
    /// (for rendering many snapshots).
    pub fn snapshot_status_with(&self, s: &Snapshot, signers: &BTreeMap<String, (String, String)>) -> SignatureStatus {
        match (&s.signature, s.signature_valid()) {
            (Some(sig), Some(valid)) => self.judge(sig, valid, signers),
            _ => SignatureStatus::Unsigned,
        }
    }

    // ---- embargoes -------------------------------------------------------

    fn embargo_path(id: &str) -> Result<VPath> {
        if id.is_empty() || !id.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err(VeilError::NotFound(format!("embargo '{id}'")));
        }
        VPath::new(&format!(".veil/meta/embargoes/{id}.json"))
    }

    pub fn load_embargo(&self, id: &str) -> Result<Option<EmbargoRecord>> {
        match self.backend.read_opt(&Self::embargo_path(id)?)? {
            Some(b) => {
                check_embargo_format(&b)?;
                let r: EmbargoRecord = serde_json::from_slice(&b)?;
                Ok((r.id == id).then_some(r))
            }
            None => Ok(None),
        }
    }

    pub fn save_embargo(&self, rec: &EmbargoRecord) -> Result<()> {
        let _lock = self.lock_meta()?;
        self.backend
            .write(&Self::embargo_path(&rec.id)?, &serde_json::to_vec_pretty(rec)?)?;
        Ok(())
    }

    pub fn embargoes(&self) -> Result<Vec<EmbargoRecord>> {
        let dir = VPath::new(".veil/meta/embargoes")?;
        if !self.backend.exists(&dir)? {
            return Ok(vec![]);
        }
        let mut out = Vec::new();
        for e in self.backend.list_dir(&dir)? {
            if let Some(id) = e.name.strip_suffix(".json") {
                if let Ok(Some(r)) = self.load_embargo(id) {
                    out.push(r);
                }
            }
        }
        out.sort_by_key(|r| r.created);
        Ok(out)
    }

    /// Is embargo `id` released *here*: its record is released
    /// ([`EmbargoRecord::is_released`]), or this identity staged a release
    /// that has not been pushed yet ([`Keychain::stage_release`]).
    pub fn embargo_released(&self, id: &str) -> bool {
        self.effective_embargo(id).is_some_and(|r| r.is_released())
    }

    /// The record as this repository acts on it: with a release this
    /// identity staged applied.
    pub fn effective_embargo(&self, id: &str) -> Option<EmbargoRecord> {
        let rec = self.load_embargo(id).ok()??;
        if rec.is_released() {
            return Some(rec);
        }
        Some(self.staged_release(&rec).unwrap_or(rec))
    }

    /// Where embargo `id` stands here (see [`ReleaseState`]).
    pub fn release_state(&self, id: &str) -> ReleaseState {
        match self.load_embargo(id).ok().flatten() {
            Some(rec) if rec.is_released() => ReleaseState::Released,
            Some(rec) if self.staged_release(&rec).is_some() => ReleaseState::Staged,
            _ => ReleaseState::Unreleased,
        }
    }

    /// A new embargo for the group(s) `scope`, released at `until` (or by
    /// hand). Plain text: who may see the work is a permission.
    pub fn create_embargo(&self, scope: &str, until: Option<i64>) -> Result<String> {
        let groups: Vec<&str> = scope.split(',').map(str::trim).filter(|s| !s.is_empty()).collect();
        if groups.is_empty() {
            validate_scope_name(scope)?;
        }
        for g in &groups {
            validate_scope_name(g)?;
        }
        let scope = groups.join(",");
        let id = hex::encode(random_bytes::<5>());
        let rec = EmbargoRecord {
            format: EMBARGO_FORMAT,
            id: id.clone(),
            scope,
            until,
            released_at: None,
            created: crate::now_millis(),
            state: None,
            reason: None,
        };
        self.save_embargo(&rec)?;
        Ok(id)
    }

    /// Release embargo `id` in its (synced) record now. Irreversible as soon
    /// as the record leaves this repository; `Repo::release_embargo` stages
    /// instead ([`Keychain::stage_release`]).
    pub fn release_embargo(&self, id: &str) -> Result<()> {
        let _lock = self.lock_meta()?;
        let mut rec = self
            .load_embargo(id)?
            .ok_or_else(|| VeilError::NotFound(format!("embargo '{id}'")))?;
        if rec.released_at.is_none() {
            rec.released_at = Some(crate::now_millis());
            self.save_embargo(&rec)?;
        }
        self.remove_staged(id)
    }

    /// The server holds the release of embargo `id` that this repository
    /// pushed, until it is approved (BUG-1861): the embargo is not released,
    /// so its record is unreleased again and says why, as the server's own
    /// record does (BUG-1894). Whether a release was recorded here.
    pub fn hold_release(&self, id: &str, why: &str) -> Result<bool> {
        let _lock = self.lock_meta()?;
        if Self::embargo_path(id).is_err() {
            return Ok(false);
        }
        let Some(mut rec) = self.load_embargo(id)? else { return Ok(false) };
        if rec.released_at.is_none() {
            return Ok(false);
        }
        rec.released_at = None;
        rec.state = Some("waiting_for_approval".to_string());
        rec.reason = Some(why.to_string());
        self.save_embargo(&rec)?;
        Ok(true)
    }

    fn staged_path(id: &str) -> Result<VPath> {
        Self::embargo_path(id)?;
        VPath::new(&format!("{STAGED_RELEASES}/{id}.json"))
    }

    fn remove_staged(&self, id: &str) -> Result<()> {
        let path = Self::staged_path(id)?;
        if self.backend.exists(&path)? {
            self.backend.remove_file(&path)?;
        }
        Ok(())
    }

    /// The record with the release this identity staged applied, if there is
    /// one.
    fn staged_release(&self, rec: &EmbargoRecord) -> Option<EmbargoRecord> {
        let raw = self.backend.read_opt(&Self::staged_path(&rec.id).ok()?).ok()??;
        let st: StagedRelease = serde_json::from_slice(&raw).ok()?;
        let mut r = rec.clone();
        r.released_at = Some(st.released_at);
        Some(r)
    }

    /// Release embargo `id` **in this repository only**: from now on this
    /// repository treats it as released (checkouts, snapshots, `vl log`),
    /// but the release is kept in device-local state (`.veil/local/releases/`,
    /// which no sync reads) and reaches the synced record only when this
    /// repository next pushes ([`Keychain::publish_staged_releases`]). Until then
    /// [`Keychain::take_back_release`] undoes it completely (BUG-109).
    pub fn stage_release(&self, id: &str) -> Result<StageOutcome> {
        let _lock = self.lock_meta()?;
        if self.load_embargo(id)?.is_none() {
            return Err(VeilError::NotFound(format!("embargo '{id}'")));
        }
        match self.release_state(id) {
            ReleaseState::Released => return Ok(StageOutcome::AlreadyReleased),
            ReleaseState::Staged => return Ok(StageOutcome::AlreadyStaged),
            ReleaseState::Unreleased => {}
        }
        let st = StagedRelease {
            released_at: crate::now_millis(),
        };
        self.backend
            .write(&Self::staged_path(id)?, &serde_json::to_vec_pretty(&st)?)?;
        Ok(StageOutcome::Staged)
    }

    /// Ids of the releases this identity staged and has not published.
    pub fn staged_releases(&self) -> Result<Vec<(String, i64)>> {
        let dir = VPath::new(STAGED_RELEASES)?;
        if !self.backend.exists(&dir)? {
            return Ok(vec![]);
        }
        let mut out = Vec::new();
        for e in self.backend.list_dir(&dir)? {
            let Some(id) = e.name.strip_suffix(".json") else { continue };
            if let Ok(Some(rec)) = self.load_embargo(id) {
                if !rec.is_released() {
                    if let Some(r) = self.staged_release(&rec) {
                        out.push((id.to_string(), r.released_at.unwrap_or_default()));
                    }
                }
            }
        }
        out.sort();
        Ok(out)
    }

    /// Write every staged release into its (synced) record. Called before
    /// anything leaves the repository: a push. From then on
    /// the release cannot be taken back. Returns the published ids.
    pub fn publish_staged_releases(&self) -> Result<Vec<String>> {
        let dir = VPath::new(STAGED_RELEASES)?;
        if !self.backend.exists(&dir)? {
            return Ok(vec![]);
        }
        let _lock = self.lock_meta()?;
        let mut published = Vec::new();
        for e in self.backend.list_dir(&dir)? {
            let Some(id) = e.name.strip_suffix(".json") else { continue };
            let Some(rec) = self.load_embargo(id).ok().flatten() else { continue };
            if rec.is_released() {
                self.remove_staged(id)?;
                continue;
            }
            if let Some(r) = self.staged_release(&rec) {
                self.save_embargo(&r)?;
                self.remove_staged(id)?;
                published.push(id.to_string());
            }
        }
        Ok(published)
    }

    /// Undo a release of embargo `id` if it is only staged (never pushed or
    /// exported). A published release cannot be taken back.
    pub fn take_back_release(&self, id: &str) -> Result<TakeBack> {
        let _lock = self.lock_meta()?;
        Ok(match self.release_state(id) {
            ReleaseState::Released => TakeBack::Published,
            ReleaseState::Staged => {
                self.remove_staged(id)?;
                TakeBack::TakenBack
            }
            ReleaseState::Unreleased => {
                self.remove_staged(id)?;
                TakeBack::NotReleased
            }
        })
    }

    /// Merge an embargo record received from another repository. Returns a
    /// warning when it was refused: a record whose fixed fields (scope,
    /// deadline, creation) differ from the local one's is another embargo
    /// under the same id. A release it carries is taken.
    pub fn merge_embargo(&self, incoming: &EmbargoRecord) -> Result<Option<String>> {
        let _lock = self.lock_meta()?;
        let id = &incoming.id;
        let groups = incoming.groups();
        if Self::embargo_path(id).is_err() || groups.is_empty() || groups.iter().any(|g| validate_scope_name(g).is_err()) {
            return Ok(Some(format!("embargo record with invalid id or scope '{id}' rejected")));
        }
        let Some(mut local) = self.load_embargo(id)? else {
            self.save_embargo(incoming)?;
            return Ok(None);
        };
        if local.body() != incoming.body() {
            return Ok(Some(format!(
                "embargo {id}: incoming record conflicts with the local one (another deadline or scope); kept the local record"
            )));
        }
        if local.released_at.is_none() && incoming.released_at.is_some() {
            local.released_at = incoming.released_at;
            local.state = None;
            local.reason = None;
            self.save_embargo(&local)?;
        } else if local.released_at.is_none()
            && (local.state != incoming.state || local.reason != incoming.reason)
        {
            local.state = incoming.state.clone();
            local.reason = incoming.reason.clone();
            self.save_embargo(&local)?;
        }
        Ok(None)
    }
}

/// Device-local directory of releases staged by this identity
/// ([`Keychain::stage_release`]). `.veil/local/` is never synced.
const STAGED_RELEASES: &str = ".veil/local/releases";

/// A staged release: the time that publishing writes into the record.
#[derive(Serialize, Deserialize)]
struct StagedRelease {
    released_at: i64,
}

/// Where an embargo's release stands in this repository.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReleaseState {
    Unreleased,
    /// Released by this identity, not yet pushed or exported: `vl undo`
    /// can still take it back.
    Staged,
    /// The record is released (published, or past its deadline).
    Released,
}

/// Result of [`Keychain::stage_release`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StageOutcome {
    Staged,
    AlreadyStaged,
    AlreadyReleased,
}

/// Result of [`Keychain::take_back_release`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TakeBack {
    /// The staged release was removed; the embargo is unreleased again.
    TakenBack,
    /// The release is in the record (pushed, exported or received): it
    /// cannot be taken back.
    Published,
    /// It was not released.
    NotReleased,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemoryBackend;

    fn chain(name: &str) -> (Keychain, Identity) {
        let id = Identity::generate(name);
        (Keychain::new(Arc::new(MemoryBackend::new()), Some(id.clone()), "r".into()), id)
    }

    #[test]
    fn rotation_keeps_history_and_excludes_the_revoked() {
        let (alice, _) = chain("alice");
        let bob = Identity::generate("bob");
        alice.create_scope("team").unwrap();
        alice.grant("team", &bob.public_id(), "bob").unwrap();
        let (g0_label, g0) = alice.sealing_key("team").unwrap();
        assert!(g0_label.starts_with("team#"));
        alice.revoke("team", &bob.public_id()).unwrap();
        let (g1_label, g1) = alice.sealing_key("team").unwrap();
        assert_ne!(g0_label, g1_label);
        assert_ne!(g0, g1);
        assert_eq!(alice.key(&g0_label), Some(g0), "admin still reads generation 0");
        assert_eq!(alice.key("team"), Some(g0), "bare label = generation 0");

        let ring = alice.load_ring("team").unwrap().unwrap();
        let bobs = Keychain::new(Arc::new(MemoryBackend::new()), Some(bob), "r".into());
        bobs.save_ring(&ring).unwrap();
        assert_eq!(bobs.key(&g0_label), Some(g0), "revoked member keeps old history");
        assert_eq!(bobs.key(&g1_label), None, "but never receives the new generation");
        assert!(!bobs.is_member("team"));
    }

    /// Pinned: where `binding` sits in a signed grant body (ring format 3).
    /// Grants without one keep the body they always had.
    #[test]
    fn grant_signing_body_with_and_without_a_binding() {
        let member = |binding: Option<&str>| MemberGrant {
            id: "veil1aa".into(),
            name: "bob".into(),
            signing_key: Some("bb".into()),
            binding: binding.map(str::to_string),
            role: Role::Member,
            generation: 0,
            wrapped: WrappedKey::Hpke(crate::identity::HpkeWrappedKey {
                hpke: "s".into(),
                enc: "e".into(),
                ct: "c".into(),
            }),
        };
        let body = |m| {
            let c = RingChange {
                seq: 1,
                prev: "p".into(),
                timestamp: 2,
                signer: "veil1cc".into(),
                signing_key: "dd".into(),
                op: RingOp::Grant { member: m },
                signature: String::new(),
            };
            String::from_utf8(c.signing_body("team")).unwrap()
        };
        let head = r#"{"scope":"team","seq":1,"prev":"p","timestamp":2,"signer":"veil1cc","signing_key":"dd","op":{"kind":"grant","member":{"id":"veil1aa","name":"bob","signing_key":"bb","#;
        let tail = r#""role":"member","generation":0,"wrapped":{"hpke":"s","enc":"e","ct":"c"}}}}"#;
        assert_eq!(body(member(None)), format!("{head}{tail}"));
        assert_eq!(body(member(Some("ee"))), format!(r#"{head}"binding":"ee",{tail}"#));
    }

    #[test]
    fn non_admins_cannot_change_the_ring() {
        let (alice, _) = chain("alice");
        let (bobs, bob) = chain("bob");
        alice.create_scope("team").unwrap();
        alice.grant("team", &bob.public_id(), "bob").unwrap();
        bobs.save_ring(&alice.load_ring("team").unwrap().unwrap()).unwrap();
        assert!(bobs.is_member("team"));
        let err = bobs.grant("team", &Identity::generate("eve").public_id(), "eve").unwrap_err();
        assert!(err.to_string().contains("only an admin"), "{err}");
    }
}
