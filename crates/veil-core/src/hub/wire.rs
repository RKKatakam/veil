//! The Veil server's protocol (`docs/HUB.md` §4): JSON messages over
//! HTTPS, and object frames for object bodies.
//!
//! ```text
//! POST /v1/auth/challenge                 ChallengeRequest  → Challenge
//! POST /v1/auth/login                     LoginRequest      → Session
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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FetchRequest {
    pub snapshot: ObjectId,
    pub objects: Vec<Want>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Uploaded {
    pub stored: usize,
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

/// A person's registered devices, as full public identities: what an
/// admin's device wraps secret keys to (`docs/HUB.md` §6).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Devices {
    pub person: String,
    pub identities: Vec<String>,
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
}
