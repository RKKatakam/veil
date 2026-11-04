//! The team vault: secrets shared with the members of a scope
//! (`vl secret set|get|list|rm --scope S`), synced to team remotes.
//!
//! # Records
//!
//! Every write is one immutable **record**, a file
//! `.veil/meta/vault/<scope>/<id>.json` holding compact JSON
//! [`VaultRecord`]:
//!
//! * `sealed`: the entry's **name and value** (or, for a deletion, the name
//!   and no value) as JSON, padded with spaces to a multiple of
//!   [`PAD`] bytes, sealed with XChaCha20-Poly1305 under a random nonce
//!   (CRYPTO.md C2/C12) with the scope's *current* generation key at the
//!   time of the write. The label `vault:<scope>#<key-id>` names the
//!   generation and is authenticated. Names are sealed too: a team remote's
//!   operator sees opaque ids, sizes in [`PAD`]-byte steps, write times and
//!   who wrote.
//! * `timestamp`, `signature`: an Ed25519 signature (context `vault-entry`)
//!   by the writer over [`RecordBody`] (format, scope, the sealed envelope,
//!   timestamp, the writer's member id).
//! * The id is `BLAKE3` of the file's bytes, which must be exactly the
//!   compact JSON of the record (so a record has one id).
//!
//! # Who counts, and which write wins
//!
//! The vault's content is a pure function of the set of records and the
//! scope's verified ring, so replicas that hold the same records and ring
//! agree, whatever order they received them in:
//!
//! * A record **counts** if its signature verifies, it names a generation of
//!   the scope's ring, it opens with that generation's key, and its signer
//!   is a **current** member whose registered signing key made the
//!   signature. Writes of non-members, of revoked members (from the moment
//!   the revocation is in the ring, whenever they were written) and of
//!   members granted without a signing key never count.
//! * Per name, the counting record with the greatest `(timestamp, signing
//!   key, id)` wins. A winning deletion (no value) hides the name. A writer
//!   stamps `max(now, winner + 1)`, so a write always beats what its writer
//!   had seen, whatever the clocks say.
//!
//! **Compaction** deletes a record only when a newer record by the *same
//! signer* for the same name exists (both opened, both well signed).
//! Whatever any future ring says about that signer, the newer record
//! decides both or neither, so compaction never changes the vault's
//! content and replicas still converge. Records per name are bounded by
//! the number of members who ever wrote it.
//!
//! # Revocation
//!
//! [`Keychain::revoke_with_vault`] revokes a member and reports the entries
//! they could read (every live entry sealed under a generation they held:
//! the keys to rotate). The entries whose current version they wrote would
//! otherwise vanish (their writes stop counting); the revoking admin re-signs
//! those values under the new generation (they are in the report too).
//!
//! # Rotation
//!
//! After `vl scope rotate` (or a revocation) new writes are sealed under the
//! new generation; existing records keep their generation (members read
//! them through the ring's key chain) and are re-sealed when next written.
//!
//! # Sync
//!
//! Team remotes only ([`crate::remote`]): a record crosses if the receiver
//! lacks it and it passes the checks above against the receiver's ring
//! (merged first), except that records of *former* members are kept (they
//! count again if the member is granted again) with a warning on pull.
//! Public remotes and the Git bridge never receive the vault.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    crypto::{domains, Envelope},
    error::{Result, VeilError},
    identity::{format_public_key, parse_public_key, Signature},
    keychain::{generation_label, split_label, validate_scope_name, KeyRing, Keychain, RingOp, RingState},
    vfs::{NodeKind, StorageBackend},
    vpath::VPath,
};

/// Where team-vault records live (one directory per scope).
pub const TEAM_VAULT_DIR: &str = ".veil/meta/vault";
/// Record format this build writes and reads; a newer one is skipped with a
/// warning (never rewritten: records are immutable).
pub const RECORD_FORMAT: u32 = 1;
/// Sealed payloads are padded to a multiple of this many bytes.
pub const PAD: usize = 128;
/// Longest entry name.
pub const MAX_NAME_LEN: usize = 128;
/// Largest entry value.
pub const MAX_VALUE_LEN: usize = 64 * 1024;
/// Record files larger than this are not read.
const MAX_RECORD_FILE: u64 = 4 * MAX_VALUE_LEN as u64;
/// Records stamped further than this in the future are refused on sync.
pub const MAX_CLOCK_SKEW_MS: i64 = 24 * 3600 * 1000;

const SIG_CONTEXT: &str = domains::SIG_CONTEXT_VAULT_ENTRY;

/// One signed write of a team-vault entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultRecord {
    pub format: u32,
    pub scope: String,
    /// Name and value, sealed under `vault:<scope>#<key-id>`.
    pub sealed: Envelope,
    /// Milliseconds since the epoch (see the module documentation).
    pub timestamp: i64,
    pub signature: Signature,
}

/// What a record's signature covers. Never change it (FORMAT.md §2).
#[derive(Serialize)]
pub struct RecordBody<'a> {
    format: u32,
    scope: &'a str,
    sealed: &'a Envelope,
    timestamp: i64,
    signer: &'a str,
}

impl VaultRecord {
    /// The bytes the signature covers ([`RecordBody`]).
    pub fn signing_body(&self) -> Vec<u8> {
        serde_json::to_vec(&RecordBody {
            format: self.format,
            scope: &self.scope,
            sealed: &self.sealed,
            timestamp: self.timestamp,
            signer: &self.signature.signer,
        })
        .expect("serialisable")
    }

    /// The canonical file bytes (compact JSON).
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("serialisable")
    }

    /// The record id: BLAKE3 of [`VaultRecord::to_bytes`], hex.
    pub fn id(&self) -> String {
        blake3::hash(&self.to_bytes()).to_hex().to_string()
    }

    /// Build a record: `name` = `value` (`None`: a deletion), sealed with
    /// `keys`' current generation key of `scope` and signed by `signer`.
    /// Nothing is checked or written; [`Keychain::team_secret_write`] is the
    /// way to write one (tests use this to forge records).
    pub fn seal(
        keys: &Keychain,
        signer: &crate::identity::Identity,
        scope: &str,
        name: &str,
        value: Option<&str>,
        since: u32,
        timestamp: i64,
    ) -> Result<VaultRecord> {
        let (label, key) = keys.sealing_key(scope)?;
        let key = Zeroizing::new(key);
        if split_label(&label).1.is_none() {
            return Err(VeilError::repo(format!("scope '{scope}' has no key generation label; rotate it first")));
        }
        let mut pt = Zeroizing::new(serde_json::to_vec(&Payload {
            name: name.to_string(),
            value: value.map(str::to_string),
            since,
        })?);
        let padded = pt.len().div_ceil(PAD).max(1) * PAD;
        pt.resize(padded, b' ');
        let sealed = Envelope::seal_random(&key, &format!("{}{label}", domains::VAULT_LABEL_PREFIX), &pt)?;
        let mut rec = VaultRecord {
            format: RECORD_FORMAT,
            scope: scope.to_string(),
            sealed,
            timestamp,
            signature: Signature {
                signer: signer.public_hex(),
                key: signer.verifying_hex(),
                sig: String::new(),
            },
        };
        rec.signature = Signature::create(signer, SIG_CONTEXT, &rec.signing_body());
        Ok(rec)
    }

    /// Re-sign the record with `signer` (after editing a field).
    pub fn resign(&mut self, signer: &crate::identity::Identity) {
        self.signature = Signature::create(signer, SIG_CONTEXT, &self.signing_body());
    }

    /// Where the record is filed on a backend.
    pub fn path(&self) -> Result<VPath> {
        record_path(&self.scope, &self.id())
    }

    pub fn signature_valid(&self) -> bool {
        self.signature.verify(SIG_CONTEXT, &self.signing_body())
    }

    /// The generation key id the label names, if the label is
    /// `vault:<this scope>#<key-id>`.
    fn key_id(&self) -> Option<&str> {
        let label = self.sealed.scope.strip_prefix(domains::VAULT_LABEL_PREFIX)?;
        match split_label(label) {
            (s, Some(kid)) if s == self.scope && !kid.is_empty() => Some(kid),
            _ => None,
        }
    }
}

/// The sealed plaintext.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    name: String,
    /// `None`: the entry was deleted.
    value: Option<String>,
    /// The generation under which this exact value was first sealed: kept
    /// when the same value is written again (re-signed after a revocation,
    /// re-sealed after a rotation), so the revocation report still knows
    /// who could read it. At most the record's own generation.
    since: u32,
}

/// Check an entry name: `[A-Za-z_][A-Za-z0-9_.-]*`, at most
/// [`MAX_NAME_LEN`] bytes, so it is a usable environment variable name and
/// safe to print.
pub fn validate_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && name.bytes().next().is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'));
    if ok {
        Ok(())
    } else {
        Err(VeilError::repo(format!(
            "invalid secret name {name:?}: use letters, digits, '_', '.' and '-', starting with a letter or '_' \
             (at most {MAX_NAME_LEN} characters)"
        )))
    }
}

/// Check an entry value: no NUL (it becomes an environment variable), at
/// most [`MAX_VALUE_LEN`] bytes.
pub fn validate_value(value: &str) -> Result<()> {
    if value.len() > MAX_VALUE_LEN {
        return Err(VeilError::repo(format!(
            "secret value is {} bytes; the team vault holds at most {MAX_VALUE_LEN}",
            value.len()
        )));
    }
    if value.contains('\0') {
        return Err(VeilError::repo("secret value contains a NUL byte, which no environment variable can hold"));
    }
    Ok(())
}

fn scope_dir(scope: &str) -> Result<VPath> {
    validate_scope_name(scope)?;
    VPath::new(&format!("{TEAM_VAULT_DIR}/{scope}"))
}

fn record_path(scope: &str, id: &str) -> Result<VPath> {
    if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) {
        return Err(VeilError::NotFound(format!("vault record '{id}'")));
    }
    VPath::new(&format!("{TEAM_VAULT_DIR}/{scope}/{id}.json"))
}

/// Read and decode one record file. `Err` describes what is wrong.
fn parse_record(scope: &str, id: &str, raw: &[u8]) -> std::result::Result<VaultRecord, String> {
    if raw.len() as u64 > MAX_RECORD_FILE {
        return Err(format!("{} bytes, more than a record can hold", raw.len()));
    }
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(raw) {
        if let Some(f) = v.get("format").and_then(|f| f.as_u64()) {
            if f > u64::from(RECORD_FORMAT) {
                return Err(format!("record format {f} needs a newer vl"));
            }
        }
    }
    let rec: VaultRecord = serde_json::from_slice(raw).map_err(|e| format!("cannot be parsed: {e}"))?;
    if rec.format != RECORD_FORMAT {
        return Err(format!("record format {}", rec.format));
    }
    if rec.scope != scope {
        return Err(format!("filed under scope '{scope}' but is for '{}'", rec.scope));
    }
    if rec.to_bytes() != raw {
        return Err("not in canonical form".into());
    }
    if rec.id() != id {
        return Err("its name is not its id".into());
    }
    Ok(rec)
}

/// The ids of the records of `scope` on `backend` (file names only, nothing
/// is read).
fn list_ids(backend: &dyn StorageBackend, scope: &str) -> Result<BTreeSet<String>> {
    let dir = scope_dir(scope)?;
    if !backend.exists(&dir)? {
        return Ok(BTreeSet::new());
    }
    Ok(backend
        .list_dir(&dir)?
        .into_iter()
        .filter(|e| e.kind == NodeKind::File)
        .filter_map(|e| e.name.strip_suffix(".json").map(str::to_string))
        .filter(|id| record_path(scope, id).is_ok())
        .collect())
}

/// Read one record by id: `Ok(None)` if absent, `Err` text if it is not a
/// readable record.
fn read_record(backend: &dyn StorageBackend, scope: &str, id: &str) -> Result<Option<std::result::Result<VaultRecord, String>>> {
    let path = record_path(scope, id)?;
    if backend.metadata(&path)?.is_some_and(|m| m.len > MAX_RECORD_FILE) {
        return Ok(Some(Err(format!("vault record {path}: too large"))));
    }
    Ok(backend
        .read_opt(&path)?
        .map(|raw| parse_record(scope, id, &raw).map_err(|why| format!("vault record {path}: {why}"))))
}

/// Every record of `scope` on `backend`, by id, plus a description of each
/// file that is not a readable record.
pub fn load_records(backend: &dyn StorageBackend, scope: &str) -> Result<(BTreeMap<String, VaultRecord>, Vec<String>)> {
    let dir = scope_dir(scope)?;
    let mut out = BTreeMap::new();
    let mut bad = Vec::new();
    if !backend.exists(&dir)? {
        return Ok((out, bad));
    }
    for e in backend.list_dir(&dir)? {
        if e.name.starts_with('.') && e.name.contains(".vltmp") {
            continue;
        }
        let Some(id) = e.name.strip_suffix(".json").filter(|_| e.kind == NodeKind::File) else {
            bad.push(format!("unexpected entry {TEAM_VAULT_DIR}/{scope}/{}", e.name));
            continue;
        };
        if record_path(scope, id).is_err() {
            bad.push(format!("unexpected entry {TEAM_VAULT_DIR}/{scope}/{}", e.name));
            continue;
        }
        match read_record(backend, scope, id)? {
            Some(Ok(r)) => {
                out.insert(id.to_string(), r);
            }
            Some(Err(why)) => bad.push(why),
            None => {}
        }
    }
    Ok((out, bad))
}

/// Scopes that have a team-vault directory on `backend`.
pub fn vault_scopes(backend: &dyn StorageBackend) -> Result<Vec<String>> {
    let dir = VPath::new(TEAM_VAULT_DIR)?;
    if !backend.exists(&dir)? {
        return Ok(vec![]);
    }
    Ok(backend
        .list_dir(&dir)?
        .into_iter()
        .filter(|e| e.kind == NodeKind::Dir && validate_scope_name(&e.name).is_ok())
        .map(|e| e.name)
        .collect())
}

/// How many records `backend` holds, over all scopes (for warnings about
/// public remotes).
pub fn record_count(backend: &dyn StorageBackend) -> Result<usize> {
    let mut n = 0;
    for s in vault_scopes(backend)? {
        n += backend.list_dir(&scope_dir(&s)?)?.len();
    }
    Ok(n)
}

/// One entry as the vault shows it: the winning write for its name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    /// `None`: deleted.
    pub value: Option<String>,
    pub timestamp: i64,
    /// Member id of the writer.
    pub signer: String,
    /// Their name in the ring.
    pub signer_name: String,
    /// Generation the value is sealed under, and its key id.
    pub generation: u32,
    pub key_id: String,
    /// The generation under which this value was first sealed (see
    /// [`last_generation_held`]): it was readable to everyone who held that
    /// generation or a later one before the value changed.
    pub since: u32,
    /// The record's id.
    pub record: String,
}

/// A record that does not count, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ignored {
    pub record: String,
    pub reason: IgnoredReason,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IgnoredReason {
    /// Signed by someone who was a member of the scope and no longer is (or
    /// whose registered signing key changed): name from the ring.
    FormerMember(String),
    /// Signed by a key the scope's ring never registered.
    NotAMember,
    BadSignature,
    /// Names no generation of the ring.
    UnknownGeneration,
    /// The AEAD (or the payload) does not check out.
    Unreadable,
    /// The file is not a readable record (see the text).
    Malformed(String),
}

impl IgnoredReason {
    pub fn describe(&self) -> String {
        match self {
            IgnoredReason::FormerMember(n) => format!("written by {n}, no longer a member"),
            IgnoredReason::NotAMember => "signed by someone who was never a member".into(),
            IgnoredReason::BadSignature => "bad signature".into(),
            IgnoredReason::UnknownGeneration => "sealed under a key generation the scope's ring does not have".into(),
            IgnoredReason::Unreadable => "does not decrypt to a valid entry".into(),
            IgnoredReason::Malformed(w) => w.clone(),
        }
    }
}

/// The state of one scope's team vault, as this identity reads it.
#[derive(Clone, Debug, Default)]
pub struct TeamVault {
    /// Winning write per name, deletions included.
    pub entries: BTreeMap<String, Entry>,
    pub ignored: Vec<Ignored>,
}

impl TeamVault {
    /// Entries that hold a value (not deleted).
    pub fn live(&self) -> impl Iterator<Item = &Entry> {
        self.entries.values().filter(|e| e.value.is_some())
    }

    pub fn get(&self, name: &str) -> Option<&Entry> {
        self.entries.get(name).filter(|e| e.value.is_some())
    }
}

/// Checks that need no key: signature, generation, signer. `Ok` gives the
/// generation; `Err(FormerMember)` is a well-formed record of a former
/// member.
fn check_record(rec: &VaultRecord, state: &RingState) -> std::result::Result<u32, IgnoredReason> {
    if !rec.signature_valid() {
        return Err(IgnoredReason::BadSignature);
    }
    let Some(kid) = rec.key_id() else {
        return Err(IgnoredReason::UnknownGeneration);
    };
    let Some(generation) = state.generations.iter().position(|g| g == kid) else {
        return Err(IgnoredReason::UnknownGeneration);
    };
    let sig = &rec.signature;
    let current = state
        .members
        .get(&sig.signer)
        .is_some_and(|m| m.signing_key.as_deref() == Some(sig.key.as_str()));
    if !current {
        // A former member: the ring once registered this key for this
        // signer. Anything else (an unknown key, or a key claiming someone
        // else's member id) was never a member's write.
        return Err(match state.ever_signers.get(&sig.key) {
            Some((member, name)) if *member == sig.signer => IgnoredReason::FormerMember(name.clone()),
            _ => IgnoredReason::NotAMember,
        });
    }
    Ok(generation as u32)
}

/// Open a record with `keys` (any generation it can derive). `None` if it
/// has no key for the generation; `Some(Err)` if the record does not open
/// or holds an invalid entry.
/// An opened entry: name, value (`None`: deleted), first generation.
type Opened = (String, Option<String>, u32);

fn open_record(keys: &Keychain, rec: &VaultRecord) -> Option<std::result::Result<Opened, ()>> {
    let kid = rec.key_id()?;
    let key = Zeroizing::new(keys.key(&generation_label(&rec.scope, kid))?);
    let parsed = rec
        .sealed
        .open(&key)
        .ok()
        .map(Zeroizing::new)
        .and_then(|pt| serde_json::from_slice::<Payload>(&pt).ok())
        .filter(|p| validate_name(&p.name).is_ok() && p.value.as_deref().is_none_or(|v| validate_value(v).is_ok()));
    Some(parsed.map(|p| (p.name, p.value, p.since)).ok_or(()))
}

/// Sort key of a write: greater wins.
fn rank<'a>(rec: &'a VaultRecord, id: &'a str) -> (i64, &'a str, &'a str) {
    (rec.timestamp, rec.signature.key.as_str(), id)
}

fn verified_state(keys: &Keychain, scope: &str) -> Result<(KeyRing, RingState)> {
    let ring = keys
        .load_ring(scope)?
        .ok_or_else(|| VeilError::NotFound(format!("scope '{scope}'")))?;
    let state = ring
        .verify()
        .map_err(|e| VeilError::repo(format!("the key ring of scope '{scope}' does not verify: {e}")))?;
    if state.legacy || ring.is_legacy() {
        return Err(VeilError::repo(format!(
            "scope '{scope}' still has an unsigned legacy key ring, which cannot say who may write its team vault; \
             an admin change (`vl scope rotate {scope}`) upgrades it"
        )));
    }
    Ok((ring, state))
}

/// The vault of `scope` read from `backend` with `keys` (rings and keys).
fn read_vault(keys: &Keychain, backend: &dyn StorageBackend, scope: &str, state: &RingState) -> Result<TeamVault> {
    let (records, bad) = load_records(backend, scope)?;
    let mut out = TeamVault {
        ignored: bad
            .into_iter()
            .map(|w| Ignored {
                record: String::new(),
                reason: IgnoredReason::Malformed(w),
            })
            .collect(),
        ..Default::default()
    };
    let mut best: BTreeMap<String, (&str, &VaultRecord, u32, Option<String>, u32)> = BTreeMap::new();
    let mut former = Vec::new();
    for (id, rec) in &records {
        let generation = match check_record(rec, state) {
            Ok(g) => g,
            Err(reason @ IgnoredReason::FormerMember(_)) => {
                former.push((id.as_str(), rec, reason));
                continue;
            }
            Err(reason) => {
                out.ignored.push(Ignored { record: id.clone(), reason });
                continue;
            }
        };
        let (name, value, since) = match open_record(keys, rec) {
            Some(Ok(nv)) => nv,
            _ => {
                out.ignored.push(Ignored {
                    record: id.clone(),
                    reason: IgnoredReason::Unreadable,
                });
                continue;
            }
        };
        let better = best.get(&name).is_none_or(|(bid, brec, ..)| rank(rec, id) > rank(brec, bid));
        if better {
            best.insert(name, (id.as_str(), rec, generation, value, since.min(generation)));
        }
    }
    // A former member's write is worth reporting only where it would have
    // won: one that a counting write outranks changed nothing.
    for (id, rec, reason) in former {
        let outranked = match open_record(keys, rec) {
            Some(Ok((name, ..))) => best.get(&name).is_some_and(|(bid, brec, ..)| rank(brec, bid) > rank(rec, id)),
            _ => false,
        };
        if !outranked {
            out.ignored.push(Ignored {
                record: id.to_string(),
                reason,
            });
        }
    }
    for (name, (id, rec, generation, value, since)) in best {
        let signer_name = state
            .members
            .get(&rec.signature.signer)
            .map_or_else(String::new, |m| m.name.clone());
        out.entries.insert(
            name.clone(),
            Entry {
                name,
                value,
                timestamp: rec.timestamp,
                signer: rec.signature.signer.clone(),
                signer_name,
                generation,
                since,
                key_id: state.generations[generation as usize].clone(),
                record: id.to_string(),
            },
        );
    }
    Ok(out)
}

/// Delete, on `backend`, every record superseded by a newer record of the
/// same signer for the same name (both well signed and opened with
/// `keys`). Never changes what the vault holds (module documentation).
/// Returns how many records were deleted.
pub(crate) fn compact(keys: &Keychain, backend: &dyn StorageBackend, scope: &str) -> Result<usize> {
    let (records, _) = load_records(backend, scope)?;
    // (name, signer id, signing key) → newest (rank, id)
    type Newest<'a> = BTreeMap<(String, &'a str, &'a str), ((i64, &'a str, &'a str), &'a str)>;
    let mut newest: Newest = BTreeMap::new();
    let mut opened = Vec::new();
    for (id, rec) in &records {
        if !rec.signature_valid() {
            continue;
        }
        let Some(Ok((name, ..))) = open_record(keys, rec) else { continue };
        let k = (name, rec.signature.signer.as_str(), rec.signature.key.as_str());
        let r = rank(rec, id);
        if newest.get(&k).is_none_or(|(br, _)| r > *br) {
            newest.insert(k.clone(), (r, id.as_str()));
        }
        opened.push((k, id.as_str()));
    }
    let mut removed = 0;
    for (k, id) in opened {
        if newest.get(&k).is_some_and(|(_, keep)| *keep != id) {
            backend.remove_file(&record_path(scope, id)?)?;
            removed += 1;
        }
    }
    Ok(removed)
}

/// The last key generation `member` (a member id) received in `ring`:
/// the current one while they are a member. `None` if they never were.
/// Every generation up to it is readable to them (each rotation carries
/// the previous key).
pub fn last_generation_held(ring: &KeyRing, state: &RingState, member: &str) -> Option<u32> {
    if state.members.contains_key(member) {
        return Some(state.generation);
    }
    let mut last = None;
    for c in &ring.log {
        let g = match &c.op {
            RingOp::Genesis { members, .. } => members.iter().any(|m| m.id == member).then_some(0),
            RingOp::Grant { member: m } => (m.id == member).then_some(m.generation),
            RingOp::Revoke { rotation, .. } | RingOp::Rotate { rotation } => {
                rotation.wrapped.contains_key(member).then_some(rotation.generation)
            }
        };
        if g.is_some() {
            last = last.max(g);
        }
    }
    last
}

/// Find a member (current or former) of `ring` by public key, member id or
/// name. Returns `(member id, name)`.
pub fn resolve_member(ring: &KeyRing, state: &RingState, who: &str) -> Result<(String, String)> {
    let mut names: BTreeMap<String, String> = BTreeMap::new();
    for c in &ring.log {
        match &c.op {
            RingOp::Genesis { members, .. } => names.extend(members.iter().map(|m| (m.id.clone(), m.name.clone()))),
            RingOp::Grant { member } => {
                names.insert(member.id.clone(), member.name.clone());
            }
            _ => {}
        }
    }
    for (id, m) in &state.members {
        names.insert(id.clone(), m.name.clone());
    }
    if let Ok(pk) = parse_public_key(who) {
        let id = format_public_key(&pk);
        return match names.get(&id) {
            Some(n) => Ok((id, n.clone())),
            None => Err(VeilError::NotFound(format!("{id} was never a member of scope '{}'", ring.scope))),
        };
    }
    let found: Vec<(&String, &String)> = names.iter().filter(|(_, n)| n.as_str() == who).collect();
    match found.as_slice() {
        [(id, n)] => Ok(((*id).clone(), (*n).clone())),
        [] => Err(VeilError::NotFound(format!("no member named '{who}' in scope '{}'", ring.scope))),
        _ => Err(VeilError::repo(format!(
            "{} members of scope '{}' are named '{who}'; give the public key instead",
            found.len(),
            ring.scope
        ))),
    }
}

/// What [`Keychain::team_secret_write`] replaced.
#[derive(Clone, Debug, Default)]
pub struct WriteOutcome {
    /// The entry before the write (a deletion included).
    pub previous: Option<Entry>,
    /// The new record's id.
    pub record: String,
}

/// What [`Keychain::revoke_with_vault`] found.
#[derive(Clone, Debug, Default)]
pub struct RevokeReport {
    /// Live entries the revoked member could read: rotate them.
    pub exposed: Vec<String>,
    /// Entries whose current version the revoked member wrote, re-signed by
    /// this identity under the new generation so they do not vanish.
    pub adopted: Vec<String>,
    /// Set when the vault could not be read or adopted (the revocation
    /// itself happened).
    pub warning: Option<String>,
}

impl Keychain {
    /// The team vault of `scope`, for a current member.
    pub fn team_vault(&self, scope: &str) -> Result<TeamVault> {
        let (_, state) = verified_state(self, scope)?;
        if !self.is_member(scope) {
            return Err(VeilError::repo(format!(
                "you are not a member of scope '{scope}', so you cannot read its team vault"
            )));
        }
        read_vault(self, &**self.backend(), scope, &state)
    }

    /// The live secrets of `scope` (name → value), for `vl run`.
    pub fn team_secrets(&self, scope: &str) -> Result<BTreeMap<String, String>> {
        Ok(self
            .team_vault(scope)?
            .entries
            .into_values()
            .filter_map(|e| Some((e.name, e.value?)))
            .collect())
    }

    /// Scopes that have a team-vault directory here.
    pub fn team_vault_scopes(&self) -> Result<Vec<String>> {
        vault_scopes(&**self.backend())
    }

    /// Scopes this identity is a current member of (whether or not their
    /// vault holds anything).
    pub fn member_scopes(&self) -> Result<Vec<String>> {
        Ok(self
            .rings()?
            .into_iter()
            .map(|r| r.scope)
            .filter(|s| self.is_member(s))
            .collect())
    }

    /// Set (`Some`) or delete (`None`) the entry `name` of `scope`'s team
    /// vault: a new record sealed under the current generation and signed
    /// by this identity, which must be a current member with its signing
    /// key registered. Deleting a name that holds no value is `NotFound`.
    pub fn team_secret_write(&self, scope: &str, name: &str, value: Option<&str>) -> Result<WriteOutcome> {
        let _lock = self.lock_meta()?;
        validate_name(name)?;
        if let Some(v) = value {
            validate_value(v)?;
        }
        let (_, state) = verified_state(self, scope)?;
        let me = self
            .identity()
            .ok_or_else(|| VeilError::repo("no identity configured (run `vl identity new`)"))?;
        let my_id = me.public_hex();
        match state.members.get(&my_id) {
            None => {
                return Err(VeilError::repo(format!(
                    "you are not a member of scope '{scope}', so you cannot write its team vault"
                )))
            }
            Some(m) if m.signing_key.as_deref() != Some(me.verifying_hex().as_str()) => {
                return Err(VeilError::repo(format!(
                    "scope '{scope}' does not register your signing key (you were granted with the short member id, \
                     or before your identity changed), so teammates would ignore your writes; ask an admin to grant \
                     the full key from `vl identity show` again"
                )))
            }
            Some(_) => {}
        }
        let vault = read_vault(self, &**self.backend(), scope, &state)?;
        let previous = vault.entries.get(name).cloned();
        if value.is_none() && previous.as_ref().is_none_or(|p| p.value.is_none()) {
            return Err(VeilError::NotFound(format!("secret '{name}' in the team vault of scope '{scope}'")));
        }
        let floor = previous.as_ref().map_or(i64::MIN, |p| p.timestamp.saturating_add(1));
        // The same value written again keeps its first generation.
        let since = previous
            .as_ref()
            .filter(|p| p.value.is_some() && p.value.as_deref() == value)
            .map_or(state.generation, |p| p.since);
        let record = self.write_record(scope, name, value, since, crate::now_millis().max(floor))?;
        compact(self, &**self.backend(), scope)?;
        Ok(WriteOutcome { previous, record })
    }

    fn write_record(&self, scope: &str, name: &str, value: Option<&str>, since: u32, timestamp: i64) -> Result<String> {
        let me = self
            .identity()
            .ok_or_else(|| VeilError::repo("no identity configured (run `vl identity new`)"))?;
        let rec = VaultRecord::seal(self, me, scope, name, value, since, timestamp)?;
        let id = rec.id();
        self.backend().write(&record_path(scope, &id)?, &rec.to_bytes())?;
        Ok(id)
    }

    /// Live entries of `scope` that `member` (public key, member id or
    /// name; current or former) could read: those sealed under a generation
    /// they held. For a current member, all of them.
    pub fn team_vault_exposed_to(&self, scope: &str, member: &str) -> Result<(String, String, Vec<Entry>)> {
        let (ring, state) = verified_state(self, scope)?;
        let (id, name) = resolve_member(&ring, &state, member)?;
        let vault = self.team_vault(scope)?;
        let last = last_generation_held(&ring, &state, &id);
        let exposed = vault
            .live()
            .filter(|e| last.is_some_and(|g| e.since <= g))
            .cloned()
            .collect();
        Ok((id, name, exposed))
    }

    /// Revoke `public_key` from `scope` ([`Keychain::revoke`]) and report
    /// the team-vault entries they could read. Entries whose current version
    /// they wrote are re-signed by this identity (sealed under the new
    /// generation), so they do not vanish when the revoked member's writes
    /// stop counting. `Ok(None)`: not a member, nothing changed.
    pub fn revoke_with_vault(&self, scope: &str, public_key: &str) -> Result<Option<RevokeReport>> {
        let _lock = self.lock_meta()?;
        let member = format_public_key(&parse_public_key(public_key)?);
        let before = self.team_vault(scope).ok();
        if !self.revoke(scope, public_key)? {
            return Ok(None);
        }
        let mut report = RevokeReport::default();
        let Some(before) = before else {
            report.warning = Some(format!(
                "the team vault of scope '{scope}' could not be read; check it with `vl secret list --scope {scope} \
                 --exposed-to {member}`"
            ));
            return Ok(Some(report));
        };
        let mut adopt_failed = Vec::new();
        for e in before.entries.values().filter(|e| e.signer == member) {
            let ts = crate::now_millis().max(e.timestamp.saturating_add(1));
            match self.write_record(scope, &e.name, e.value.as_deref(), e.since, ts) {
                Ok(_) if e.value.is_some() => report.adopted.push(e.name.clone()),
                Ok(_) => {}
                Err(err) => adopt_failed.push(format!("{} ({err})", e.name)),
            }
        }
        if !adopt_failed.is_empty() {
            report.warning = Some(format!(
                "could not re-sign the entries the revoked member wrote: {}; set them again with `vl secret set --scope {scope}`",
                adopt_failed.join(", ")
            ));
        }
        compact(self, &**self.backend(), scope)?;
        let (ring, state) = verified_state(self, scope)?;
        let last = last_generation_held(&ring, &state, &member);
        // Their pre-revocation view: every live entry sealed under a
        // generation they held (all of them, before the revocation).
        report.exposed = before
            .live()
            .filter(|e| last.is_some_and(|g| e.since <= g))
            .map(|e| e.name.clone())
            .collect();
        Ok(Some(report))
    }
}

/// Copy the team-vault records of `src` that `dst` lacks into `dst`, for
/// every scope (team remotes only; `crate::remote::sync_meta`). Each
/// record is checked against `dst`'s ring (already merged): a record with a
/// bad signature, an unknown generation, a signer who was never a member,
/// a timestamp more than [`MAX_CLOCK_SKEW_MS`] ahead, or (where `local`
/// can open it) content that does not decrypt to a valid entry, is not
/// copied. Records of former members are copied but do not count. With
/// `warn`, every record that is not copied or does not count is reported
/// (once per scope and reason). Then `dst` is compacted with `local`'s
/// keys. `local` is the keychain with this identity (the source on push,
/// the destination on pull).
pub(crate) fn sync(src: &Keychain, dst: &Keychain, local: &Keychain, warn: bool, warnings: &mut Vec<String>) -> Result<()> {
    let now = crate::now_millis();
    let src_backend = &**src.backend();
    let dst_backend = &**dst.backend();
    for scope in vault_scopes(src_backend)? {
        let have = list_ids(dst_backend, &scope)?;
        let mut incoming = Vec::new();
        let mut problems: BTreeMap<String, usize> = BTreeMap::new();
        for id in list_ids(src_backend, &scope)?.difference(&have) {
            match read_record(src_backend, &scope, id)? {
                Some(Ok(rec)) => incoming.push((id.clone(), rec)),
                Some(Err(_)) if warn => *problems.entry("not copied (not a readable record)".into()).or_default() += 1,
                _ => {}
            }
        }
        if incoming.is_empty() {
            for (why, n) in problems {
                warnings.push(format!("team vault of scope '{scope}': {n} record(s) {why}"));
            }
            continue;
        }
        let state = match verified_state(dst, &scope) {
            Ok((_, st)) => st,
            Err(e) => {
                warnings.push(format!(
                    "team vault of scope '{scope}': {} record(s) not copied: {e}",
                    incoming.len()
                ));
                continue;
            }
        };
        let mut copied = 0usize;
        for (id, rec) in &incoming {
            let verdict = match check_record(rec, &state) {
                Ok(_) | Err(IgnoredReason::FormerMember(_)) if rec.timestamp > now.saturating_add(MAX_CLOCK_SKEW_MS) || rec.timestamp < 0 => {
                    Err("timestamp out of range".to_string())
                }
                Ok(_) => match open_record(local, rec) {
                    Some(Err(())) => Err(IgnoredReason::Unreadable.describe()),
                    _ => Ok(None),
                },
                Err(IgnoredReason::FormerMember(n)) => match open_record(local, rec) {
                    Some(Err(())) => Err(IgnoredReason::Unreadable.describe()),
                    _ => Ok(Some(IgnoredReason::FormerMember(n).describe())),
                },
                Err(r) => Err(r.describe()),
            };
            match verdict {
                Ok(note) => {
                    dst_backend.write(&record_path(&scope, id)?, &rec.to_bytes())?;
                    copied += 1;
                    if let Some(n) = note.filter(|_| warn) {
                        *problems.entry(format!("kept but ignored ({n})")).or_default() += 1;
                    }
                }
                Err(why) => {
                    if warn {
                        *problems.entry(format!("not copied ({why})")).or_default() += 1;
                    }
                }
            }
        }
        for (why, n) in problems {
            warnings.push(format!("team vault of scope '{scope}': {n} record(s) {why}"));
        }
        if copied > 0 && local.is_member(&scope) {
            compact(local, dst_backend, &scope)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Suite;

    fn fixed_record() -> VaultRecord {
        VaultRecord {
            format: 1,
            scope: "team".into(),
            sealed: Envelope {
                scope: "vault:team#0011223344556677".into(),
                suite: Suite::XChaCha20Poly1305 { nonce: [7; 24] },
                ciphertext: vec![1, 2, 3],
            },
            timestamp: 1_700_000_000_000,
            signature: Signature {
                signer: "veil1aa".into(),
                key: "bb".into(),
                sig: "cc".into(),
            },
        }
    }

    /// The signed body and the file encoding are fixed (FORMAT.md §2):
    /// changing either breaks every record already written.
    #[test]
    fn signing_body_and_encoding_never_change() {
        let r = fixed_record();
        assert_eq!(
            String::from_utf8(r.signing_body()).unwrap(),
            r#"{"format":1,"scope":"team","sealed":{"scope":"vault:team#0011223344556677","nonce":"070707070707070707070707070707070707070707070707","ciphertext":"010203"},"timestamp":1700000000000,"signer":"veil1aa"}"#
        );
        assert_eq!(
            String::from_utf8(r.to_bytes()).unwrap(),
            r#"{"format":1,"scope":"team","sealed":{"scope":"vault:team#0011223344556677","nonce":"070707070707070707070707070707070707070707070707","ciphertext":"010203"},"timestamp":1700000000000,"signature":{"signer":"veil1aa","key":"bb","sig":"cc"}}"#
        );
        assert_eq!(r.key_id(), Some("0011223344556677"));
        assert_eq!(parse_record("team", &r.id(), &r.to_bytes()).unwrap(), r);
    }

    #[test]
    fn labels_must_name_this_scope_and_a_generation() {
        let mut r = fixed_record();
        for bad in ["team#0011", "vault:ops#0011", "vault:team", "vault:team#", "embargo/x"] {
            r.sealed.scope = bad.into();
            assert_eq!(r.key_id(), None, "{bad}");
        }
    }

    #[test]
    fn unknown_fields_and_wrong_files_are_refused() {
        let r = fixed_record();
        let id = r.id();
        let mut v: serde_json::Value = serde_json::from_slice(&r.to_bytes()).unwrap();
        v["extra"] = 1.into();
        assert!(parse_record("team", &id, &serde_json::to_vec(&v).unwrap()).is_err());
        assert!(parse_record("ops", &id, &r.to_bytes()).is_err());
        assert!(parse_record("team", &"0".repeat(64), &r.to_bytes()).is_err());
        assert!(record_path("team", "../../x").is_err());
        assert!(record_path("team", &"A".repeat(64)).is_err());
        assert!(scope_dir("../keyrings").is_err());
    }

    #[test]
    fn name_rules() {
        for ok in ["A", "_x", "STRIPE_LIVE_KEY", "a.b-c_9"] {
            assert!(validate_name(ok).is_ok(), "{ok}");
        }
        for bad in ["", "9A", "-a", "a b", "a=b", "a/b", "é"] {
            assert!(validate_name(bad).is_err(), "{bad}");
        }
    }
}
