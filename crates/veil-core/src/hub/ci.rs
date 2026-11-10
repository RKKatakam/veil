//! CI through the API and `main@tested` (`docs/HUB.md` §13.35;
//! `docs/design/server/phase-4-agent-scale.md` §4.6, §4.7, §5.2):
//!
//! * CI runners authenticate with narrow CI runner sessions (`POST
//!   /v1/sessions/ci`, or `POST /v1/sessions/agent` with `"runner": true`):
//!   they read only what their grant allows (`only`) and write only check
//!   results (`POST /v1/projects/{p}/checks`). They cannot push, create
//!   changes, move branches or land anything.
//! * Check results carry a state (`pending`, `pass`, `fail`, `error`), a
//!   short summary, an optional URL and an optional bounded log. Because
//!   summaries, URLs and logs may quote code from the paths the runner read,
//!   a check result is shown only to viewers who can read every path the
//!   runner's session could read.
//! * `main@tested` (`GET /v1/projects/{p}/tested/{branch}`, and `<branch>@tested`
//!   in revisions) points at the newest snapshot on the branch whose required
//!   checks (`.veilrules`: `[branches.<name>] required_checks = [...]`) all
//!   passed. It moves only forward along the branch's lineage.

use serde::{Deserialize, Serialize};

use crate::{id::ObjectId, object::Attribution};

/// Longest check name, in bytes (`ci/build`, `lint`, ...).
pub const MAX_CHECK_NAME: usize = 128;
/// Longest check summary, in bytes.
pub const MAX_SUMMARY_BYTES: usize = 1_024;
/// Longest check URL, in bytes.
pub const MAX_URL_BYTES: usize = 1_024;
/// Longest inline log per check result, in bytes (64 KiB).
pub const MAX_LOG_BYTES: usize = 64 * 1024;
/// Most distinct check names recorded on one snapshot.
pub const MAX_CHECKS_PER_SNAPSHOT: usize = 64;
/// Most total bytes of check logs kept on one snapshot (256 KiB).
pub const MAX_TIP_LOG_BYTES: usize = 256 * 1024;
/// Most check results kept per runner in one project.
pub const MAX_RUNNER_CHECKS: usize = 256;
/// Most total bytes of check logs kept per runner in one project (1 MiB).
pub const MAX_RUNNER_LOG_BYTES: usize = 1024 * 1024;

/// A check's state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckState {
    Pending,
    Pass,
    Fail,
    Error,
}

impl CheckState {
    pub fn as_str(&self) -> &'static str {
        match self {
            CheckState::Pending => "pending",
            CheckState::Pass => "pass",
            CheckState::Fail => "fail",
            CheckState::Error => "error",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(CheckState::Pending),
            "pass" => Some(CheckState::Pass),
            "fail" => Some(CheckState::Fail),
            "error" => Some(CheckState::Error),
            _ => None,
        }
    }
}

/// `POST /v1/projects/{p}/checks`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckRequest {
    /// The snapshot the check ran on, as the caller sees it.
    pub snapshot: ObjectId,
    /// The check's name (e.g. `ci/test`).
    pub name: String,
    pub state: CheckState,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log: Option<String>,
}

/// One check result, as shown to a viewer who may see the snapshot and every
/// path the runner's session could read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckResult {
    /// The snapshot in the reader's view.
    pub snapshot: ObjectId,
    pub name: String,
    pub state: CheckState,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log: Option<String>,
    pub runner: String,
    pub updated_at: i64,
}

/// `GET /v1/projects/{p}/checks?rev=…`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChecksResponse {
    pub snapshot: ObjectId,
    pub checks: Vec<CheckResult>,
}

/// `GET /v1/projects/{p}/tested/{branch}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestedTip {
    pub branch: String,
    pub snapshot: ObjectId,
}

/// `POST /v1/sessions/ci`: mint a narrow CI runner session from a person's
/// session. It reads only what its grant allows and writes only check results.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CiSessionRequest {
    /// The project the runner tests.
    pub project: String,
    /// Optional check name from `.veilrules` (`[checks.<name>]`): when given
    /// and `only` is empty, the session is narrowed to that check's `paths`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check: Option<String>,
    /// Narrow the runner to these folders or files (from the project root).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub only: Vec<String>,
    /// How long the session lasts, in seconds (default and max: 12 hours).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seconds: Option<i64>,
    /// Optional attribution for the runner (defaults to `agent = "ci"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribution: Option<Attribution>,
}

/// Validate a check name (`ci/test`, `build`, ...): 1..=128 ASCII letters,
/// digits, `-`, `_`, `.`, `/`, no leading or trailing `/`, no `//` or `..`.
pub fn validate_check_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > MAX_CHECK_NAME {
        return Err(format!("a check name is 1 to {MAX_CHECK_NAME} characters"));
    }
    if name.starts_with('/') || name.ends_with('/') || name.contains("//") || name.split('/').any(|s| s == "." || s == "..") {
        return Err("a check name may not start or end with '/' or contain '..'".to_string());
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'/'))
    {
        return Err("a check name may contain only ASCII letters, digits, '-', '_', '.' and '/'".to_string());
    }
    Ok(())
}

/// Validate a check summary: at most [`MAX_SUMMARY_BYTES`] bytes and no
/// control characters (so terminal escapes never reach `vl checks`).
pub fn validate_summary(summary: &str) -> Result<(), String> {
    if summary.len() > MAX_SUMMARY_BYTES {
        return Err(format!("a check summary is at most {MAX_SUMMARY_BYTES} bytes"));
    }
    if summary.chars().any(|c| c.is_control()) {
        return Err("a check summary may not contain control characters".to_string());
    }
    Ok(())
}

/// Validate an optional check URL: `http://` or `https://`, at most
/// [`MAX_URL_BYTES`] bytes, no control characters or spaces.
pub fn validate_url(url: &str) -> Result<(), String> {
    if url.is_empty() || url.len() > MAX_URL_BYTES {
        return Err(format!("a check URL is 1 to {MAX_URL_BYTES} bytes"));
    }
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err("a check URL must start with https:// or http://".to_string());
    }
    if url.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("a check URL may not contain spaces or control characters".to_string());
    }
    Ok(())
}

/// Validate a check log: at most [`MAX_LOG_BYTES`] bytes and no NUL bytes.
pub fn validate_log(log: &str) -> Result<(), String> {
    if log.len() > MAX_LOG_BYTES {
        return Err(format!("a check log is at most {MAX_LOG_BYTES} bytes"));
    }
    if log.contains('\0') {
        return Err("a check log may not contain NUL bytes".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_field_validation() {
        assert!(validate_check_name("ci/test").is_ok());
        assert!(validate_check_name("build_linux-x86.64").is_ok());
        for bad in ["", "/ci", "ci/", "ci//test", "ci/../x", "ci test", "ci\x1b[2J"] {
            assert!(validate_check_name(bad).is_err(), "{bad:?}");
        }
        assert!(validate_check_name(&"a".repeat(MAX_CHECK_NAME + 1)).is_err());

        assert!(validate_summary("all 42 tests passed").is_ok());
        assert!(validate_summary("bad\x1b[31m").is_err());
        assert!(validate_summary(&"a".repeat(MAX_SUMMARY_BYTES + 1)).is_err());

        assert!(validate_url("https://ci.example/run/1").is_ok());
        assert!(validate_url("javascript:alert(1)").is_err());
        assert!(validate_url("https://ci.example/a b").is_err());

        assert!(validate_log("line 1\nline 2\n").is_ok());
        assert!(validate_log("bad\0log").is_err());
        assert!(validate_log(&"x".repeat(MAX_LOG_BYTES + 1)).is_err());
    }
}
