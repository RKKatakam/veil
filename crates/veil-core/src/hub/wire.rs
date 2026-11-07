//! The Veil server's protocol (`docs/HUB.md` §4): JSON messages over
//! HTTPS, and object frames for object bodies.
//!
//! ```text
//! POST /v1/auth/challenge                 ChallengeRequest  → Challenge
//! POST /v1/auth/login                     LoginRequest      → Session
//! GET  /v1/people/{name}/devices                            → Devices
//! GET  /v1/people/{name}/pending/{fp}                       → PendingDevice
//! POST /v1/devices/vouch                  VouchRequest      → Devices
//! POST /v1/devices/remove                 RemoveDevice      → Devices
//! POST /v1/projects/{p}/invites           InviteRequest     → InviteRequest
//! POST /v1/projects/{p}/invites/join      JoinRequest       → Joined
//! GET  /v1/projects/{p}/keys/pending                        → [Devices]
//! GET  /v1/projects/{p}/tips                                → Tips
//! POST /v1/projects/{p}/history           HistoryRequest    → frames (snapshots)
//! POST /v1/projects/{p}/fetch             FetchRequest      → frames (trees, blobs)
//! POST /v1/projects/{p}/objects           frames            → Uploaded
//! POST /v1/projects/{p}/push              PushRequest       → PushResult
//! GET  /v1/projects/{p}/access?path=P                       → AccessInfo
//! POST /v1/projects/{p}/groups/…          GroupChange       → GroupInfo
//! GET|POST /v1/projects/{p}/rings/{scope} ring JSON
//! ```
//!
//! An object frame is `id [32] ‖ len u32be ‖ the object's canonical
//! encoding`. Every receiver re-hashes the bytes against `id`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{
    error::{Result, VeilError},
    id::ObjectId,
};

/// Protocol version, in the `/v1/` of every path.
pub const PROTOCOL: u32 = 1;
/// What this side of `/v1/` supports beyond its first release, as
/// [`Tips::revision`] tells clients: 1, a fetch names objects of several
/// snapshots ([`Want::snapshot`]); 2, uploads may carry compressed
/// objects ([`super::encoding`]).
pub const REVISION: u32 = 2;
/// Largest object a frame may carry.
pub const MAX_FRAME_OBJECT: usize = 1 << 30;
/// Most objects one fetch request may name.
pub const MAX_WANTS: usize = 100_000;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChallengeRequest {
    /// The device's Ed25519 verifying key (hex).
    pub key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Challenge {
    /// 32 random bytes (hex), single use.
    pub challenge: String,
    pub expires_at: i64,
}

/// The message a device signs to sign in (context
/// [`crate::crypto::domains::SIG_CONTEXT_HUB_LOGIN`]): the server's name
/// as dialled, so a challenge answered for one server is useless at another.
pub fn login_message(hub: &str, challenge: &str) -> Vec<u8> {
    let mut m = hub.as_bytes().to_vec();
    m.push(0);
    m.extend_from_slice(challenge.as_bytes());
    m
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    pub key: String,
    pub challenge: String,
    /// The server's name as the client dialled it (`host:port`).
    pub hub: String,
    /// Ed25519 signature (hex) over [`login_message`].
    pub signature: String,
    /// The device's full public identity (`veil1<x25519><ed25519><binding>`,
    /// `vl identity show`): its Ed25519 part must be `key`.
    pub identity: String,
    /// Register this device as a new person with this name, when the key is
    /// not registered yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Session {
    pub token: String,
    pub person: String,
    pub expires_at: i64,
    /// The server's own signing key (hex): projected snapshots are signed
    /// with it.
    pub hub_key: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Tips {
    /// Branch → tip, as this viewer sees it (a projection).
    pub branches: BTreeMap<String, ObjectId>,
    pub default_branch: String,
    /// Who the server takes the caller to be (`None`: anyone on Earth).
    pub you: Option<String>,
    pub admin: bool,
    /// The server's [`REVISION`] (0: a server from before revisions).
    #[serde(default)]
    pub revision: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HistoryRequest {
    /// Snapshots to start from (as the caller knows them).
    pub tips: Vec<ObjectId>,
    /// Snapshots the caller already has: the walk stops there.
    #[serde(default)]
    pub stop: Vec<ObjectId>,
}

/// One object a client asks for: its id, and the path where it met it
/// under the request's snapshot (`""` for the root tree).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Want {
    pub path: String,
    pub id: ObjectId,
    /// The snapshot `path` is in (default: the request's): one fetch
    /// brings the new objects of every snapshot a pull receives (revision
    /// 1; an older server answers for the request's snapshot only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<ObjectId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FetchRequest {
    pub snapshot: ObjectId,
    pub objects: Vec<Want>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Uploaded {
    pub stored: usize,
    /// One receipt per object, in the order sent: what a push shows for
    /// the objects it names (BUG-824).
    #[serde(default)]
    pub receipts: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BranchUpdate {
    pub branch: String,
    /// The tip the client last saw (`None`: the branch must not exist).
    pub expected: Option<ObjectId>,
    /// The new tip (`None`: delete the branch).
    pub new: Option<ObjectId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PushRequest {
    pub updates: Vec<BranchUpdate>,
    #[serde(default)]
    pub force: bool,
    /// The upload receipts of the objects this push names, by id. Every
    /// object the push introduces needs one, unless it is the entry at the
    /// same path in one of the snapshot's parents (BUG-824).
    #[serde(default)]
    pub receipts: BTreeMap<ObjectId, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BranchResult {
    pub branch: String,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// The branch's tip afterwards, as the pusher sees it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tip: Option<ObjectId>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PushResult {
    pub results: Vec<BranchResult>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccessInfo {
    pub path: String,
    /// The line that decides, if any (`None`: private, admins only).
    pub rule: Option<String>,
    pub line: Option<usize>,
    pub public: bool,
    pub groups: Vec<String>,
    pub people: Vec<String>,
    pub admins: Vec<String>,
    /// May the caller write it?
    pub you_write: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupChange {
    #[serde(default)]
    pub people: Vec<String>,
}

/// A person's devices, as the server lists them, with the vouches it
/// stores. **Never enough on its own to wrap a key:** a device receives a
/// secret key only through a chain the server cannot forge (`docs/HUB.md`
/// §13.11).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Devices {
    pub person: String,
    /// Active devices, as full public identities.
    pub identities: Vec<String>,
    /// Devices that signed in under this person's name and wait for one of
    /// their devices to vouch for them.
    #[serde(default)]
    pub pending: Vec<String>,
    #[serde(default)]
    pub vouches: Vec<Vouch>,
    /// Their devices' joins under invites (any project's): a device whose
    /// join verifies under an invite a key ring holds may be shared to
    /// (`docs/HUB.md` §13.12).
    #[serde(default)]
    pub joins: Vec<Join>,
    /// Devices removed from the person (full public identities): devices
    /// that may revoke them in a key ring do (a revocation is never a
    /// grant, so the server's word is enough for it).
    #[serde(default)]
    pub removed: Vec<String>,
}

/// One device's join under an invite.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Join {
    /// The invite's public key (hex).
    pub key: String,
    /// The joining device's full public identity.
    pub device: String,
    /// Signature (context `hub-invite`) under `key` over [`join_message`].
    pub signature: String,
}

/// A pending device found by its fingerprint.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingDevice {
    pub identity: String,
}

/// `POST /v1/devices/remove`: remove a device (its person, from another
/// device; or an admin of `project` where the person takes part).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RemoveDevice {
    pub device: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
}

/// `POST …/invites` (an admin): the server's record of an invite, used to
/// join the group. Key rings hold the admin-signed record that grants keys.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InviteRequest {
    /// The invite's public key (hex).
    pub key: String,
    pub person: String,
    pub group: String,
    pub expires_at: i64,
}

/// `POST …/invites/join`: the signed-in device joins under an invite.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JoinRequest {
    pub key: String,
    /// The joining device: the caller's own.
    pub device: String,
    pub signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Joined {
    pub project: String,
    pub group: String,
    pub person: String,
}

/// One device's signature saying another device is its person's too.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vouch {
    /// The full public identity vouched for.
    pub device: String,
    /// The Ed25519 key (hex) that signed.
    pub by: String,
    /// Signature (context `hub-device`) over [`vouch_message`] of `device`.
    pub signature: String,
}

/// `POST /v1/devices/vouch`: the signed-in device vouches for another
/// device of its person (pending or not).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VouchRequest {
    pub device: String,
    pub signature: String,
}

/// What a vouch signs: the vouched device's X25519 ‖ Ed25519 public keys.
/// `None` for an identity without a signing key.
pub fn vouch_message(id: &crate::identity::PublicIdentity) -> Option<Vec<u8>> {
    let ed = id.ed25519?;
    let mut m = id.x25519.to_vec();
    m.extend_from_slice(&ed);
    Some(m)
}

/// What a join under an invite signs (context `hub-invite`): the invited
/// person's name, then the joining device's X25519 ‖ Ed25519 public keys.
/// `None` for an identity without a signing key.
pub fn join_message(person: &str, device: &crate::identity::PublicIdentity) -> Option<Vec<u8>> {
    let mut m = person.as_bytes().to_vec();
    m.push(0);
    m.extend(vouch_message(device)?);
    Some(m)
}

/// The secret of an invite (`vl invite`, `docs/HUB.md` §13.12): 32 random
/// bytes that only the admin's device and the invite link hold. The
/// server and the key rings get only the public half of the Ed25519 key
/// derived from it, so whoever has not seen the link cannot sign a join.
pub struct InviteKey {
    secret: zeroize::Zeroizing<[u8; 32]>,
}

impl InviteKey {
    pub fn generate() -> InviteKey {
        InviteKey { secret: zeroize::Zeroizing::new(crate::crypto::random_bytes::<32>()) }
    }

    /// From the 64 hex digits of a link.
    pub fn from_hex(s: &str) -> Option<InviteKey> {
        let b: [u8; 32] = hex::decode(s.trim()).ok()?.try_into().ok()?;
        Some(InviteKey { secret: zeroize::Zeroizing::new(b) })
    }

    /// The secret, for the link.
    pub fn secret_hex(&self) -> String {
        hex::encode(*self.secret)
    }

    fn signer(&self) -> crate::identity::SeedSigner {
        let seed = zeroize::Zeroizing::new(blake3::derive_key(crate::crypto::domains::HUB_INVITE_KEY, &*self.secret));
        crate::identity::SeedSigner::from_seed(&seed)
    }

    /// The public key (hex): what the server and the rings hold.
    pub fn public_hex(&self) -> String {
        self.signer().verifying_hex()
    }

    /// Sign the join of `device` as `person`.
    pub fn sign_join(&self, person: &str, device: &crate::identity::PublicIdentity) -> Option<String> {
        Some(self.signer().sign(crate::crypto::domains::SIG_CONTEXT_HUB_INVITE, &join_message(person, device)?))
    }
}

/// Does a join verify under the invite key `key`?
pub fn join_valid(key: &str, person: &str, device: &str, signature: &str) -> bool {
    let Ok(id) = crate::identity::parse_public_identity(device) else { return false };
    join_message(person, &id)
        .is_some_and(|m| crate::identity::verify_signature(key, crate::crypto::domains::SIG_CONTEXT_HUB_INVITE, &m, signature))
}

/// Does `v` verify for the device it names?
pub fn vouch_valid(v: &Vouch) -> bool {
    let Ok(id) = crate::identity::parse_public_identity(&v.device) else { return false };
    vouch_message(&id).is_some_and(|m| {
        crate::identity::verify_signature(&v.by, crate::crypto::domains::SIG_CONTEXT_HUB_DEVICE, &m, &v.signature)
    })
}

/// A device's fingerprint, `4F2A-9C1E-77B0-D3E5-A1C2`: the first 80 bits
/// of a BLAKE3 `derive_key` over its Ed25519 ‖ X25519 public keys. What
/// people compare out of band (`docs/HUB.md` §13.11). `None` for an
/// identity without a signing key.
pub fn device_fingerprint(id: &crate::identity::PublicIdentity) -> Option<String> {
    let ed = id.ed25519?;
    let mut h = blake3::Hasher::new_derive_key(crate::crypto::domains::HUB_DEVICE_FINGERPRINT);
    h.update(&ed);
    h.update(&id.x25519);
    let hex = hex::encode_upper(&h.finalize().as_bytes()[..10]);
    Some(hex.as_bytes().chunks(4).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join("-"))
}

/// A fingerprint as typed (any case, with or without dashes or spaces),
/// in the form [`device_fingerprint`] prints; `None` if it is not one.
pub fn normalize_fingerprint(s: &str) -> Option<String> {
    let hex: String = s.chars().filter(|c| !matches!(c, '-' | ' ')).collect::<String>().to_ascii_uppercase();
    (hex.len() == 20 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| hex.as_bytes().chunks(4).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join("-"))
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct GroupInfo {
    pub name: String,
    pub members: Vec<String>,
    pub managers: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
}

/// Append one object frame.
pub fn put_frame(out: &mut Vec<u8>, id: &ObjectId, raw: &[u8]) {
    out.extend_from_slice(&id.0);
    out.extend_from_slice(&(raw.len() as u32).to_be_bytes());
    out.extend_from_slice(raw);
}

/// Split a body of object frames, checking each object against its id.
pub fn read_frames(mut body: &[u8]) -> Result<Vec<(ObjectId, &[u8])>> {
    let bad = |m: &str| VeilError::Corrupt("frames".into(), m.to_string());
    let mut out = Vec::new();
    while !body.is_empty() {
        if body.len() < 36 {
            return Err(bad("truncated frame header"));
        }
        let id = ObjectId(body[..32].try_into().unwrap());
        let len = u32::from_be_bytes(body[32..36].try_into().unwrap()) as usize;
        if len > MAX_FRAME_OBJECT || body.len() - 36 < len {
            return Err(bad("truncated or oversized object"));
        }
        let raw = &body[36..36 + len];
        if ObjectId::hash(raw) != id {
            return Err(VeilError::Corrupt(id.hex(), "object does not match its id".into()));
        }
        out.push((id, raw));
        body = &body[36 + len..];
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip_and_reject_tampering() {
        let mut body = Vec::new();
        for raw in [&b"veil:blob\nhello"[..], b"veil:blob\n"] {
            put_frame(&mut body, &ObjectId::hash(raw), raw);
        }
        let f = read_frames(&body).unwrap();
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].1, b"veil:blob\nhello");
        let mut bad = body.clone();
        bad[40] ^= 1;
        assert!(read_frames(&bad).is_err());
        assert!(read_frames(&body[..body.len() - 1]).is_err());
    }

    #[test]
    fn vouches_and_fingerprints() {
        let alice = crate::Identity::generate("alice");
        let laptop = crate::Identity::generate("alice");
        let other = crate::Identity::generate("mal");
        let pid = |i: &crate::Identity| crate::identity::parse_public_identity(&i.public_id()).unwrap();
        let fp = device_fingerprint(&pid(&laptop)).unwrap();
        assert_eq!(fp.len(), 24);
        assert_eq!(normalize_fingerprint(&fp.to_lowercase().replace('-', " ")).as_deref(), Some(fp.as_str()));
        assert_ne!(fp, device_fingerprint(&pid(&other)).unwrap());
        assert!(normalize_fingerprint("4F2A-9C1E").is_none());
        let sig = alice.sign(crate::crypto::domains::SIG_CONTEXT_HUB_DEVICE, &vouch_message(&pid(&laptop)).unwrap());
        let v = Vouch { device: laptop.public_id(), by: alice.verifying_hex(), signature: sig };
        assert!(vouch_valid(&v));
        // Moved to another device, or claimed by another key: refused.
        assert!(!vouch_valid(&Vouch { device: other.public_id(), ..v.clone() }));
        assert!(!vouch_valid(&Vouch { by: other.verifying_hex(), ..v }));
    }
}
