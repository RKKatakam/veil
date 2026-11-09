//! The landing service's messages (`docs/HUB.md` §13.19; `docs/design/
//! server/phase-4-agent-scale.md` §4.1, §5.1).
//!
//! ```text
//! POST /v1/projects/{p}/land            LandRequest → LandResult
//! GET  /v1/projects/{p}/land/{ticket}   → LandResult    (?wait=false: at once)
//! ```
//!
//! A change is submitted to land on a branch, and the server answers with a
//! ticket: `queued`, then `landed`, `conflict` or `rejected`. The change
//! need not be on the branch's tip: the server puts it on top of the newest
//! tip when none of the paths it edits changed there since its base.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::changes::Edit;
use crate::id::{ChangeId, ObjectId};

/// Most changes one landing may stack (oldest first).
pub const MAX_LAND_STACK: usize = 64;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LandRequest {
    /// The branch to land on.
    pub onto: String,
    /// An uploaded snapshot, named as a push names one (the caller's view):
    /// it and the changes under it that the server does not hold yet land
    /// in order, all or none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<ObjectId>,
    /// Or a change made of edits on `base`, as `POST …/changes` takes them
    /// (without `onto`): built, checked and queued in one request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<ObjectId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub edits: Vec<Edit>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_id: Option<ChangeId>,
    /// Upload receipts of the objects the snapshot or the edits name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub receipts: BTreeMap<ObjectId, String>,
    /// Return only once the outcome is known (up to about 30 s), not at
    /// `queued`.
    #[serde(default = "yes", skip_serializing_if = "is_true")]
    pub wait: bool,
}

fn yes() -> bool {
    true
}

fn is_true(b: &bool) -> bool {
    *b
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LandState {
    Queued,
    Landed,
    /// A path the change edits changed on the branch since its base.
    Conflict,
    /// Refused by a check made when it was to land (access changed since it
    /// was submitted, a change below it did not land).
    Rejected,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LandResult {
    pub ticket: String,
    pub state: LandState,
    /// The change made of the request's edits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_id: Option<ChangeId>,
    /// `landed`: where each change of the stack landed, oldest first, as
    /// the caller sees it (the last is the branch's tip after it).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub landed: Vec<ObjectId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// `conflict`: the change's own paths that changed on the branch since
    /// its base.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
    /// What an admin's change of access lines made visible to whom.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_and_results_round_trip() {
        let r: LandRequest = serde_json::from_str(r#"{"onto":"main","base":"00","edits":[]}"#).unwrap_or_default();
        assert!(r.wait || r.onto.is_empty());
        let id = ObjectId::hash(b"x");
        let r: LandRequest = serde_json::from_str(&format!(r#"{{"onto":"main","snapshot":"{}"}}"#, id.hex())).unwrap();
        assert!(r.wait && r.snapshot == Some(id));
        assert!(serde_json::from_str::<LandRequest>(r#"{"onto":"main","force":true}"#).is_err());
        let out = LandResult {
            ticket: "t".into(),
            state: LandState::Conflict,
            change_id: None,
            landed: vec![],
            message: None,
            paths: vec!["a".into()],
            warnings: vec![],
        };
        let v = serde_json::to_value(&out).unwrap();
        assert_eq!(v["state"], "conflict");
        assert_eq!(serde_json::from_value::<LandResult>(v).unwrap().paths, ["a"]);
    }
}
