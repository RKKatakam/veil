//! Commits through the API (`docs/HUB.md` §13.13; `docs/design/server/
//! phase-2-thin-clients.md` §5.5): the messages of `POST
//! /v1/projects/{p}/changes`.
//!
//! ```text
//! POST /v1/projects/{p}/changes   ChangeRequest → ChangeResult
//! ```
//!
//! A caller sends "these edits on top of revision `base`" and the server
//! builds the change on its full tree, with every check a push gets, keeps
//! it on a change ref and, with `onto`, moves a branch to it in the same
//! request. No clone is needed.

use std::collections::BTreeMap;

use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};

use crate::id::{ChangeId, ObjectId};

/// Most edits one request may carry.
pub const MAX_EDITS: usize = 10_000;
/// Most bytes of inline text (`put.text`) one request may carry; larger
/// changes upload objects first.
pub const MAX_INLINE_TEXT: usize = 64 << 20;
/// Most times the server reapplies the edits on a branch that moved
/// (`"expected": "rebase"`) before it answers `rejected`.
pub const MAX_REBASES: u32 = 5;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeRequest {
    /// The snapshot the edits are on: a projected id the caller may see
    /// (a branch tip, or a change this API returned).
    pub base: ObjectId,
    /// A new revision of a change of the caller's that this API made;
    /// absent: a new change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_id: Option<ChangeId>,
    #[serde(default)]
    pub description: String,
    pub edits: Vec<Edit>,
    /// Move a branch to the change in the same request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub onto: Option<Onto>,
    /// Upload receipts (`POST …/objects`) of the objects `put.object`
    /// names, by id. Without one, an object must already be the entry at
    /// that path in `base`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub receipts: BTreeMap<ObjectId, String>,
}

/// One edit: `put` or `delete` the file at `path` (from the project root).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Edit {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub put: Option<Put>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub delete: bool,
}

/// A file's new content: an uploaded object (a blob, or a secret sealed by
/// the caller's `vl`), or plain text.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Put {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object: Option<ObjectId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub executable: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Onto {
    pub branch: String,
    pub expected: Expected,
}

/// What the branch must be for the move: its tip as the caller sees it
/// (the compare-and-swap of a push), or `"rebase"`: the server reapplies
/// the edits on the tip when none of the edited paths changed since
/// `base`, up to [`MAX_REBASES`] times.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expected {
    Tip(ObjectId),
    Rebase,
}

impl Serialize for Expected {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Expected::Tip(id) => s.serialize_str(&id.hex()),
            Expected::Rebase => s.serialize_str("rebase"),
        }
    }
}

impl<'de> Deserialize<'de> for Expected {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        if s == "rebase" {
            return Ok(Expected::Rebase);
        }
        ObjectId::from_hex(&s).map(Expected::Tip).map_err(|_| D::Error::custom("expected: a snapshot id or \"rebase\""))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChangeResult {
    pub change_id: ChangeId,
    /// The change's snapshot, as the caller sees it.
    pub snapshot: ObjectId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<BranchOutcome>,
    /// What an admin's change of access lines made visible to whom (as a
    /// push lists it).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BranchOutcome {
    pub branch: String,
    pub status: Status,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// The branch's tip as the caller sees it now.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tip: Option<ObjectId>,
    /// How many times the server reapplied the edits on a moved tip.
    #[serde(default)]
    pub rebased: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Ok,
    Rejected,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_round_trip_and_refuse_unknown_fields() {
        let id = ObjectId::hash(b"x");
        let text = format!(
            r#"{{"base":"{0}","description":"d","edits":[{{"path":"a.txt","put":{{"text":"hi"}}}},{{"path":"b","delete":true}}],
               "onto":{{"branch":"main","expected":"rebase"}}}}"#,
            id.hex()
        );
        let r: ChangeRequest = serde_json::from_str(&text).unwrap();
        assert_eq!(r.edits.len(), 2);
        assert_eq!(r.onto.as_ref().unwrap().expected, Expected::Rebase);
        let back: ChangeRequest = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
        assert!(back.edits[1].delete);
        let tip = format!(r#"{{"branch":"main","expected":"{}"}}"#, id.hex());
        assert_eq!(serde_json::from_str::<Onto>(&tip).unwrap().expected, Expected::Tip(id));
        assert!(serde_json::from_str::<Onto>(r#"{"branch":"main","expected":"nope"}"#).is_err());
        assert!(serde_json::from_str::<Edit>(r#"{"path":"a","put":{"text":"x","mode":"777"}}"#).is_err());
    }
}
