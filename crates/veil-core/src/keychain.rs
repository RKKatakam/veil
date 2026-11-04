//! Scope keys, signed key rings and embargo records.
//!
//! Shared, publishable metadata lives under `.veil/meta/`:
//!
//! * `keyrings/<scope>.json` — the scope's **ring log**: an append-only,
//!   hash-chained list of membership changes, each signed with the Ed25519
//!   key of an admin who was authorised at that point of the log. The
//!   current membership and the key *generations* are derived by replaying
//!   the log; nothing in the file is trusted unless the replay verifies.
//! * `embargoes/<id>.json`   — an embargo key wrapped under a scope key, plus
//!   its release condition, signed by the scope member who created it; on
//!   release the plaintext key is published.
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
//! store ("run `vl upgrade`"). Older generation keys (`prev-key:`) and
//! embargo keys (`embargo-wrap:`) are sealed with XChaCha20-Poly1305 under a
//! random nonce in every format. Every domain-separation string is in
//! [`crate::crypto::domains`]; `docs/CRYPTO.md` reviews them.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc, RwLock,
    },
};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    crypto::{domains, parse_key_hex, random_bytes, random_key, Envelope, Key},
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
/// 3); the newest this build reads.
pub const RING_FORMAT: u32 = 3;
/// Repository format that may hold HPKE-wrapped keys and ring format 3.
pub const HPKE_REPO_FORMAT: u32 = 3;

/// Newest ring format a repository of `repo_format` may store.
pub fn max_ring_format(repo_format: u32) -> u32 {
    if repo_format >= HPKE_REPO_FORMAT {
        RING_FORMAT
    } else {
        RING_FORMAT_SIGNED
    }
}

/// Embargo record format. Format-1 records carry no `format` field; a later
/// format adds `"format": N`, which this build refuses (see
/// `docs/FORMAT.md`) instead of reading, and re-writing, half of it.
pub const EMBARGO_FORMAT: u32 = 1;

/// Refuse an embargo record written in a newer format.
pub fn check_embargo_format(raw: &[u8]) -> Result<()> {
    let v: serde_json::Value = serde_json::from_slice(raw)?;
    match v.get("format").map(|f| f.as_u64()) {
        None => Ok(()),
        Some(Some(f)) if f <= u64::from(EMBARGO_FORMAT) => Ok(()),
        Some(f) => Err(VeilError::Unsupported(format!(
            "embargo record format {} needs a newer vl (this is vl {})",
            f.map_or("?".to_string(), |f| f.to_string()),
            env!("CARGO_PKG_VERSION")
        ))),
    }
}

const RING_SIG_CONTEXT: &str = domains::SIG_CONTEXT_RING_CHANGE;
const EMBARGO_SIG_CONTEXT: &str = domains::SIG_CONTEXT_EMBARGO;
const RELEASE_SIG_CONTEXT: &str = domains::SIG_CONTEXT_EMBARGO_RELEASE;

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
    },
    /// Add a member, or change an existing member's name, role or signing key.
    Grant { member: MemberGrant },
    /// Remove a member and start a new key generation without them.
    Revoke { member: String, rotation: Rotation },
    /// Start a new key generation for the same members.
    Rotate { rotation: Rotation },
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
                RingOp::Grant { member } => Box::new(std::iter::once(&member.wrapped)),
                RingOp::Revoke { rotation, .. } | RingOp::Rotate { rotation } => Box::new(rotation.wrapped.values()),
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
            RingOp::Grant { member } => member.binding.is_some(),
            _ => false,
        })
    }

    /// The lowest ring format that can hold this ring's content.
    pub fn required_format(&self) -> u32 {
        if self.has_hpke_keys() || self.has_bindings() {
            RING_FORMAT
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
        if self.format < RING_FORMAT && self.has_hpke_keys() {
            return Err(format!(
                "ring format {} cannot hold HPKE-wrapped keys (needs ring format {RING_FORMAT})",
                self.format
            ));
        }
        // Older readers would drop a binding and then fail the signature.
        if self.format < RING_FORMAT && self.has_bindings() {
            return Err(format!(
                "ring format {} cannot hold member bindings (needs ring format {RING_FORMAT})",
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
                (None, RingOp::Genesis { key_id, members, .. }) => {
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
                    if !st.is_admin(&c.signer, &c.signing_key) {
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmbargoRecord {
    pub id: String,
    /// Scope whose members may read the embargoed content before release.
    pub scope: String,
    pub wrapped: Envelope,
    /// Automatic release time (ms since epoch); `None` = manual release.
    pub until: Option<i64>,
    pub released_key: Option<String>,
    pub released_at: Option<i64>,
    pub created: i64,
    /// Always empty: an embargo carries no description (the record is
    /// synced in plaintext, to public remotes too). Kept, and signed, so
    /// records stay readable by, and verifiable for, every version.
    pub description: String,
    /// Envelope label of the scope key generation `wrapped` is sealed under
    /// (absent on legacy records: the bare scope, i.e. generation 0).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_key: Option<String>,
    /// Fingerprint of the embargo key; a published `released_key` must match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    /// Signature of the creating member over everything above except the
    /// release fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<Signature>,
    /// Signature of the releasing member over `(id, released_key, released_at)`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_signature: Option<Signature>,
}

#[derive(Serialize)]
struct EmbargoBody<'a> {
    id: &'a str,
    scope: &'a str,
    wrapped: &'a Envelope,
    until: Option<i64>,
    created: i64,
    description: &'a str,
    scope_key: &'a Option<String>,
    key_id: &'a Option<String>,
}

impl EmbargoRecord {
    pub fn is_released(&self) -> bool {
        self.released_key.is_some()
    }

    /// The immutable, signed part of the record.
    fn body(&self) -> Vec<u8> {
        serde_json::to_vec(&EmbargoBody {
            id: &self.id,
            scope: &self.scope,
            wrapped: &self.wrapped,
            until: self.until,
            created: self.created,
            description: &self.description,
            scope_key: &self.scope_key,
            key_id: &self.key_id,
        })
        .unwrap()
    }

    fn release_body(&self) -> Vec<u8> {
        serde_json::to_vec(&(&self.id, &self.released_key, self.released_at)).unwrap()
    }

    /// Does the published key (if any) match the committed fingerprint?
    fn release_consistent(&self) -> bool {
        match (&self.released_key, &self.key_id) {
            (Some(k), Some(id)) => parse_key_hex(k).is_ok_and(|k| key_fingerprint(&k) == *id),
            (Some(k), None) => parse_key_hex(k).is_ok(),
            (None, _) => true,
        }
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
        && !s.starts_with("embargo")
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
    if ok {
        Ok(())
    } else {
        Err(VeilError::Policy(format!(
            "invalid scope name '{s}' (use lowercase letters, digits, '-' or '_'; 'local' and 'embargo*' are reserved)"
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
    /// Registered signing key → (member id, name) of every **current**
    /// member, from a verified signed ring; `None` when there is no such
    /// ring (a public clone, a legacy ring), i.e. when this repository
    /// cannot tell who may release the scope's embargoes (BUG-108).
    release_signers: Option<HashMap<String, (String, String)>>,
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
        RingOp::Grant { member } => member.generation == g && !member.wrapped.is_hpke(),
        RingOp::Revoke { rotation, .. } | RingOp::Rotate { rotation } => {
            rotation.generation == g && rotation.wrapped.values().any(|w| !w.is_hpke())
        }
    })
}

pub struct Keychain {
    backend: Arc<dyn StorageBackend>,
    identity: Option<Identity>,
    repo_id: String,
    access: RwLock<HashMap<String, Arc<ScopeAccess>>>,
    /// Release signatures already verified (a hash of body, key and
    /// signature): key lookups check them often, and the check is pure.
    verified_releases: RwLock<HashSet<[u8; 32]>>,
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
            verified_releases: RwLock::new(HashSet::new()),
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

    /// Forget cached keys (after pulling new rings or embargo records).
    pub fn invalidate(&self) {
        self.access.write().unwrap().clear();
    }

    /// The key for an envelope label, if this identity can obtain it:
    /// `local`, `embargo/<id>`, `<scope>#<key-id>` or a bare `<scope>`
    /// (= generation 0).
    pub fn key(&self, label: &str) -> Option<Key> {
        if label == LOCAL_SCOPE {
            return self.identity.as_ref().map(|i| i.local_key(&self.repo_id));
        }
        if let Some(id) = label.strip_prefix(domains::EMBARGO_LABEL_PREFIX) {
            return self.embargo_key(id);
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
    /// generation. Labels that already name a generation (and `local`,
    /// `embargo/…`) are used as they are.
    pub fn sealing_key(&self, scope: &str) -> Result<(String, Key)> {
        if scope == LOCAL_SCOPE
            || scope.starts_with(domains::EMBARGO_LABEL_PREFIX)
            || scope.contains(domains::GENERATION_SEPARATOR)
        {
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
        let mut access = ScopeAccess {
            genesis: state.genesis_key_id().to_string(),
            current: state.key_id().to_string(),
            legacy: state.legacy,
            release_signers: (!state.legacy && !ring.is_legacy()).then(|| {
                state
                    .members
                    .iter()
                    .filter_map(|(id, m)| Some((m.signing_key.clone()?, (id.clone(), m.name.clone()))))
                    .collect()
            }),
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
                RingOp::Grant { member } if member.id == my_id => candidates.push((member.generation, &member.wrapped)),
                RingOp::Grant { .. } => {}
                RingOp::Revoke { rotation, .. } | RingOp::Rotate { rotation } => {
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
    fn lock_meta(&self) -> Result<RepoLock> {
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
        if ring.format.max(ring.required_format()) > max_ring_format(have) {
            return Err(VeilError::Unsupported(format!(
                "this repository is at format {have} and cannot store the key ring of scope '{}' \
                 (ring format {RING_FORMAT}: HPKE-wrapped keys); upgrade it with `vl upgrade` \
                 (a remote: `vl upgrade --remote <name>`) once everyone who uses it runs vl {} or later",
                ring.scope,
                crate::repo::min_vl_for_format(HPKE_REPO_FORMAT)
            )));
        }
        self.backend
            .write(&Self::ring_path(&ring.scope), &serde_json::to_vec_pretty(ring)?)?;
        self.invalidate();
        Ok(())
    }

    /// Every ring that parses (malformed files are skipped).
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
        Ok(out)
    }

    /// Verified state of a scope's ring.
    pub fn ring_state(&self, scope: &str) -> Result<Option<std::result::Result<RingState, String>>> {
        Ok(self.load_ring(scope)?.map(|r| r.verify()))
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
        self.append(ring, RingOp::Genesis { key_id, members, proof })
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
        let state = ring
            .verify()
            .map_err(|e| VeilError::Policy(format!("key ring for '{scope}' does not verify: {e}")))?;
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
            if let RingOp::Revoke { rotation, .. } | RingOp::Rotate { rotation } = &c.op {
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
            if let Ok(st) = r.verify() {
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
        self.invalidate();
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

    fn embargo_key(&self, id: &str) -> Option<Key> {
        let rec = self.effective_embargo(id)?;
        if let Some(k) = &rec.released_key {
            return parse_key_hex(k).ok();
        }
        let label = rec.scope_key.clone().unwrap_or_else(|| rec.scope.clone());
        if split_label(&label).0 != rec.scope {
            return None;
        }
        let scope_key = Zeroizing::new(self.key(&label)?);
        let raw = Zeroizing::new(rec.wrapped.open(&scope_key).ok()?);
        let key: Key = raw.as_slice().try_into().ok()?;
        match &rec.key_id {
            Some(kid) if key_fingerprint(&key) != *kid => None,
            _ => Some(key),
        }
    }

    /// Is embargo `id` released *here*: its record carries a release this
    /// repository accepts ([`Keychain::release_rejection`]), or this
    /// identity staged one that has not been pushed yet
    /// ([`Keychain::stage_release`]).
    pub fn embargo_released(&self, id: &str) -> bool {
        self.effective_embargo(id).is_some_and(|r| r.is_released())
    }

    /// The record as this repository acts on it: a published release counts
    /// only if it is accepted here, and a release staged by this identity
    /// counts too. A rejected release is removed from the returned record.
    pub fn effective_embargo(&self, id: &str) -> Option<EmbargoRecord> {
        let mut rec = self.load_embargo(id).ok()??;
        if rec.is_released() && self.release_rejection(&rec).is_none() {
            return Some(rec);
        }
        if let Some(staged) = self.staged_release(&rec) {
            return Some(staged);
        }
        rec.released_key = None;
        rec.released_at = None;
        rec.release_signature = None;
        Some(rec)
    }

    /// Where embargo `id` stands here (see [`ReleaseState`]).
    pub fn release_state(&self, id: &str) -> ReleaseState {
        let Some(rec) = self.load_embargo(id).ok().flatten() else {
            return ReleaseState::Unreleased;
        };
        let rejected = rec.is_released().then(|| self.release_rejection(&rec)).flatten();
        if rec.is_released() && rejected.is_none() {
            ReleaseState::Released
        } else if self.staged_release(&rec).is_some() {
            ReleaseState::Staged
        } else if let Some(why) = rejected {
            ReleaseState::Rejected(why)
        } else {
            ReleaseState::Unreleased
        }
    }

    /// Why the release a record carries is not accepted here, if it is not.
    ///
    /// The published key must match the record's fingerprint and the
    /// release signature (if any) must verify. Where this repository holds
    /// a verified signed ring for the embargo's scope, the release must also
    /// be signed by a **current** member of that scope, with the signing key
    /// the ring registers for them, unless the record's deadline has passed
    /// (and its creation signature is good): then any key holder's engine
    /// would release it anyway. So a member revoked after the embargo was
    /// created, who still holds its key, cannot release it in-protocol
    /// (BUG-108). Without such a ring (a clone of a public remote, which
    /// never receives rings; a legacy ring) nobody can be judged, and the
    /// release is accepted on its fingerprint, as before.
    pub fn release_rejection(&self, rec: &EmbargoRecord) -> Option<String> {
        if !rec.is_released() {
            return None;
        }
        if !rec.release_consistent() {
            return Some("its published key does not match the record".into());
        }
        if let Some(rs) = &rec.release_signature {
            if !self.release_signature_valid(rec, rs) {
                return Some("its release signature is invalid".into());
            }
        }
        let access = self.scope_access(&rec.scope);
        let signers = access.release_signers.as_ref()?;
        if let Some(rs) = &rec.release_signature {
            if signers.get(&rs.key).is_some_and(|(member, _)| *member == rs.signer) {
                return None;
            }
        }
        if rec.until.is_some_and(|u| u <= crate::now_millis()) && self.embargo_trusted(rec) {
            return None;
        }
        Some(match &rec.release_signature {
            Some(rs) => format!(
                "it was released by {}, who is not a current member of '{}' (a member revoked after the embargo was created keeps its key, but may not release it before its deadline)",
                &rs.signer[..rs.signer.len().min(16)],
                rec.scope
            ),
            None => format!(
                "its release is unsigned; only a current member of '{}' may release it before its deadline",
                rec.scope
            ),
        })
    }

    fn release_signature_valid(&self, rec: &EmbargoRecord, rs: &Signature) -> bool {
        let mut h = blake3::Hasher::new();
        let body = rec.release_body();
        for part in [body.as_slice(), rs.signer.as_bytes(), rs.key.as_bytes(), rs.sig.as_bytes()] {
            h.update(&(part.len() as u64).to_le_bytes());
            h.update(part);
        }
        let digest = *h.finalize().as_bytes();
        if self.verified_releases.read().unwrap().contains(&digest) {
            return true;
        }
        let ok = rs.verify(RELEASE_SIG_CONTEXT, &body);
        if ok {
            self.verified_releases.write().unwrap().insert(digest);
        }
        ok
    }

    /// Authenticity of an embargo record's creation signature: the signer
    /// must be (or have been) a member of the record's scope.
    pub fn embargo_status(&self, rec: &EmbargoRecord) -> SignatureStatus {
        let Some(sig) = &rec.signature else {
            return SignatureStatus::Unsigned;
        };
        let signers = match self.load_ring(&rec.scope).ok().flatten().map(|r| r.verify()) {
            Some(Ok(st)) => st.ever_signers,
            _ => BTreeMap::new(),
        };
        self.judge(sig, sig.verify(EMBARGO_SIG_CONTEXT, &rec.body()), &signers)
    }

    /// May this record's deadline trigger an automatic release? Only when
    /// its creation is signed by a member: an unsigned or forged record
    /// could otherwise move `until` into the past.
    pub fn embargo_trusted(&self, rec: &EmbargoRecord) -> bool {
        self.embargo_status(rec).is_good()
    }

    pub fn create_embargo(&self, scope: &str, until: Option<i64>) -> Result<String> {
        let _lock = self.lock_meta()?;
        // Signed records are attributed through the ring, so a legacy
        // (unsigned) ring is upgraded first.
        if let Some(ring) = self.load_ring(scope)? {
            if ring.is_legacy() && self.is_member(scope) {
                self.upgrade_legacy(ring)?;
            }
        }
        let (label, scope_key) = self.sealing_key(scope).map_err(|_| {
            VeilError::Policy(format!("an embargo needs a scope you belong to; you have no key for '{scope}'"))
        })?;
        let scope_key = Zeroizing::new(scope_key);
        let id = hex::encode(random_bytes::<5>());
        let key = Zeroizing::new(random_key());
        let mut rec = EmbargoRecord {
            id: id.clone(),
            scope: scope.to_string(),
            wrapped: Envelope::seal_random(&scope_key, &format!("{}{id}", domains::EMBARGO_WRAP_LABEL_PREFIX), &*key)?,
            until,
            released_key: None,
            released_at: None,
            created: crate::now_millis(),
            description: String::new(),
            scope_key: Some(label),
            key_id: Some(key_fingerprint(&key)),
            signature: None,
            release_signature: None,
        };
        rec.signature = self.identity.as_ref().map(|me| Signature::create(me, EMBARGO_SIG_CONTEXT, &rec.body()));
        self.save_embargo(&rec)?;
        Ok(id)
    }

    /// `rec` released by this identity now, if this identity holds the key
    /// and may release it ([`Keychain::release_rejection`]).
    fn released_by_me(&self, rec: &EmbargoRecord) -> Result<EmbargoRecord> {
        let id = &rec.id;
        let key = self
            .key(&format!("{}{id}", domains::EMBARGO_LABEL_PREFIX))
            .ok_or_else(|| VeilError::Policy(format!("you do not hold the key for embargo '{id}'")))?;
        let mut r = rec.clone();
        r.released_key = Some(hex::encode(key));
        r.released_at = Some(crate::now_millis());
        r.release_signature = self
            .identity
            .as_ref()
            .map(|me| Signature::create(me, RELEASE_SIG_CONTEXT, &r.release_body()));
        if self.release_rejection(&r).is_some() {
            return Err(VeilError::Policy(format!(
                "cannot release embargo {id}: you are not a current member of '{}'. A member revoked after an embargo was created keeps its key, but only a current member may release it before its deadline",
                rec.scope
            )));
        }
        Ok(r)
    }

    /// Publish the embargo key in the record now, making the embargoed
    /// content readable to all once the record is synced. Irreversible as
    /// soon as the record leaves this repository; `Repo::release_embargo`
    /// stages instead ([`Keychain::stage_release`]).
    pub fn release_embargo(&self, id: &str) -> Result<()> {
        let _lock = self.lock_meta()?;
        let rec = self
            .load_embargo(id)?
            .ok_or_else(|| VeilError::NotFound(format!("embargo '{id}'")))?;
        if rec.is_released() && self.release_rejection(&rec).is_none() {
            return Ok(());
        }
        let rec = self.released_by_me(&rec)?;
        self.save_embargo(&rec)?;
        self.remove_staged(id)
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
        self.invalidate();
        Ok(())
    }

    /// The record with the release this identity staged applied, if there is
    /// one that is still valid here.
    fn staged_release(&self, rec: &EmbargoRecord) -> Option<EmbargoRecord> {
        let me = self.identity.as_ref()?;
        let raw = self.backend.read_opt(&Self::staged_path(&rec.id).ok()?).ok()??;
        let st: StagedRelease = serde_json::from_slice(&raw).ok()?;
        if st.release_signature.signer != me.public_hex() || st.release_signature.key != me.verifying_hex() {
            return None;
        }
        let mut r = rec.clone();
        r.released_key = Some(st.released_key);
        r.released_at = Some(st.released_at);
        r.release_signature = Some(st.release_signature);
        (r.release_signature.is_some() && self.release_rejection(&r).is_none()).then_some(r)
    }

    /// Release embargo `id` **in this repository only**: from now on this
    /// repository treats it as released (checkouts, snapshots, `vl log`),
    /// but the key is kept in device-local state (`.veil/local/releases/`,
    /// which no sync reads) and reaches the synced record only when this
    /// repository next pushes, or exports to Git
    /// ([`Keychain::publish_staged_releases`]). Until then
    /// [`Keychain::take_back_release`] undoes it completely: the key never
    /// left this repository through vl (BUG-109).
    pub fn stage_release(&self, id: &str) -> Result<StageOutcome> {
        let _lock = self.lock_meta()?;
        let rec = self
            .load_embargo(id)?
            .ok_or_else(|| VeilError::NotFound(format!("embargo '{id}'")))?;
        match self.release_state(id) {
            ReleaseState::Released => return Ok(StageOutcome::AlreadyReleased),
            ReleaseState::Staged => return Ok(StageOutcome::AlreadyStaged),
            ReleaseState::Unreleased | ReleaseState::Rejected(_) => {}
        }
        if self.identity.is_none() {
            return Err(VeilError::Policy("releasing an embargo needs an identity".into()));
        }
        let r = self.released_by_me(&rec)?;
        let st = StagedRelease {
            released_key: r.released_key.clone().expect("set"),
            released_at: r.released_at.expect("set"),
            release_signature: r.release_signature.clone().expect("an identity signs"),
        };
        self.backend
            .write(&Self::staged_path(id)?, &serde_json::to_vec_pretty(&st)?)?;
        self.invalidate();
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
                if !(rec.is_released() && self.release_rejection(&rec).is_none()) {
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
    /// anything leaves the repository: a push, a Git export. From then on
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
            if rec.is_released() && self.release_rejection(&rec).is_none() {
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
            ReleaseState::Unreleased | ReleaseState::Rejected(_) => {
                self.remove_staged(id)?;
                TakeBack::NotReleased
            }
        })
    }

    /// Does this repository hold a verifying ring for `scope` (so it can
    /// judge who may sign that scope's embargo records)?
    fn can_judge(&self, scope: &str) -> bool {
        matches!(self.ring_state(scope), Ok(Some(Ok(_))))
    }

    /// Merge an embargo record received from another repository. Returns a
    /// warning when (part of) the record was rejected.
    ///
    /// A repository without a ring for the record's scope (a clone of a
    /// public remote, which never receives rings, BUG-077) cannot tell who
    /// may sign it. It accepts the record unverified: it holds no key for
    /// the scope, so the record can never trigger a release here, and a
    /// published key is still checked against the record's fingerprint and
    /// then by the AEAD of the content it opens. A record that a ring later
    /// shows to be signed by a member replaces an unverified local one.
    pub fn merge_embargo(&self, incoming: &EmbargoRecord) -> Result<Option<String>> {
        let _lock = self.lock_meta()?;
        let id = &incoming.id;
        if Self::embargo_path(id).is_err() {
            return Ok(Some(format!("embargo record with invalid id '{id}' rejected")));
        }
        let status = self.embargo_status(incoming);
        let judged = self.can_judge(&incoming.scope);
        if status == SignatureStatus::Bad || (judged && matches!(status, SignatureStatus::Unknown { .. })) {
            return Ok(Some(format!(
                "embargo {id}: record rejected ({}; not signed by a member of '{}')",
                status.label(),
                incoming.scope
            )));
        }
        if !incoming.release_consistent() {
            return Ok(Some(format!("embargo {id}: published key does not match the record; rejected")));
        }
        if let Some(rs) = &incoming.release_signature {
            if !rs.verify(RELEASE_SIG_CONTEXT, &incoming.release_body()) {
                return Ok(Some(format!("embargo {id}: release signature is invalid; rejected")));
            }
        }
        // A release by someone who may not release it (BUG-108) is dropped;
        // the rest of the record is merged.
        let mut ignored = None;
        let stripped;
        let incoming = match self.release_rejection(incoming) {
            Some(why) => {
                ignored = Some(format!("embargo {id}: release ignored: {why}"));
                let mut r = incoming.clone();
                r.released_key = None;
                r.released_at = None;
                r.release_signature = None;
                stripped = r;
                &stripped
            }
            None => incoming,
        };
        let Some(mut local) = self.load_embargo(id)? else {
            self.save_embargo(incoming)?;
            let unsigned = (judged && status == SignatureStatus::Unsigned)
                .then(|| format!("embargo {id}: record is unsigned (legacy); it will never be released automatically"));
            return Ok(join_warnings(ignored, unsigned));
        };
        if local.body() != incoming.body() {
            if status.is_good() && !self.embargo_status(&local).is_good() {
                // The local record was accepted unverified (no ring then);
                // the signed one wins. Keep a local release only if it is
                // the key this record commits to.
                let mut rec = incoming.clone();
                if !rec.is_released() && local.is_released() {
                    rec.released_key = local.released_key.clone();
                    rec.released_at = local.released_at;
                    rec.release_signature = local.release_signature.clone();
                    let signed = rec
                        .release_signature
                        .as_ref()
                        .is_none_or(|rs| rs.verify(RELEASE_SIG_CONTEXT, &rec.release_body()));
                    if rec.key_id.is_none() || !rec.release_consistent() || !signed || self.release_rejection(&rec).is_some() {
                        rec.released_key = None;
                        rec.released_at = None;
                        rec.release_signature = None;
                    }
                }
                self.save_embargo(&rec)?;
                let replaced = format!(
                    "embargo {id}: replaced an unverified local record with the one signed by a member of '{}'",
                    rec.scope
                );
                return Ok(join_warnings(ignored, Some(replaced)));
            }
            return Ok(Some(format!(
                "embargo {id}: incoming record conflicts with the local one (tampered deadline, scope or key?); kept the local record"
            )));
        }
        let mut changed = false;
        if local.signature.is_none() && incoming.signature.is_some() {
            local.signature = incoming.signature.clone();
            changed = true;
        }
        // A local release that is not accepted here (one planted on a
        // remote with a key that does not match the fingerprint, or one by
        // a revoked member) is replaced by an accepted one.
        let local_ok = local.is_released() && self.release_rejection(&local).is_none();
        if !local_ok && incoming.is_released() {
            local.released_key = incoming.released_key.clone();
            local.released_at = incoming.released_at;
            local.release_signature = incoming.release_signature.clone();
            changed = true;
        }
        if changed {
            self.save_embargo(&local)?;
        }
        Ok(ignored)
    }
}

fn join_warnings(a: Option<String>, b: Option<String>) -> Option<String> {
    match (a, b) {
        (Some(a), Some(b)) => Some(format!("{a}; {b}")),
        (a, b) => a.or(b),
    }
}

/// Device-local directory of releases staged by this identity
/// ([`Keychain::stage_release`]). `.veil/local/` is never synced.
const STAGED_RELEASES: &str = ".veil/local/releases";

/// A staged release: the fields that publishing writes into the record.
#[derive(Serialize, Deserialize)]
struct StagedRelease {
    released_key: String,
    released_at: i64,
    release_signature: Signature,
}

/// Where an embargo's release stands in this repository.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReleaseState {
    Unreleased,
    /// Released by this identity, not yet pushed or exported: `vl undo`
    /// can still take it back.
    Staged,
    /// The record carries a release accepted here (published).
    Released,
    /// The record carries a release this repository does not accept
    /// (why), so it is treated as unreleased.
    Rejected(String),
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
