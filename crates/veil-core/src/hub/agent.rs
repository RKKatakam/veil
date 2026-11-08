//! Agent sessions (`docs/HUB.md` §13.27; phase 2 §5.6): the messages of
//! `POST /v1/sessions/agent` and the narrowing of a session to files.
//!
//! * An agent session is made from a person's own session, for one
//!   project. It is never an API key: nobody creates, stores or rotates
//!   one; it ends after at most [`MAX_AGENT_SESSION_MS`], and never after
//!   the session it was made from.
//! * It sees at most what its person sees, and with `only` less: it reads
//!   and writes files only at or below those paths. Its history (which
//!   changes, with their descriptions) is its person's projection.
//! * The server stamps every commit made with it through the API with its
//!   attribution, and ignores any the caller sends (the request has no
//!   field for one).

use serde::{Deserialize, Serialize};

use crate::{hub::access::covers, object::Attribution};

/// The longest an agent session lasts.
pub const MAX_AGENT_SESSION_MS: i64 = 12 * 3600 * 1000;
/// Most paths a session is narrowed to.
pub const MAX_ONLY: usize = 64;

/// `POST /v1/sessions/agent`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSessionRequest {
    /// The project the session works in; it is refused everywhere else.
    pub project: String,
    /// Who the session's commits through the API are attributed to.
    pub attribution: Attribution,
    /// Narrow it to these folders or files (from the project root); empty:
    /// all its person sees.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub only: Vec<String>,
    /// How long it lasts, in seconds (default and most: 12 hours, and never
    /// past the person's own session).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seconds: Option<i64>,
}

/// The answer: the session's token (shown once, kept only as a hash by the
/// server) and what it is.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentSession {
    pub token: String,
    pub project: String,
    pub person: String,
    pub expires_at: i64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub only: Vec<String>,
    pub attribution: Attribution,
}

/// `only` normalised: root-relative folder or file paths, no glob, no
/// `..`, sorted, a path below another one dropped. An error says why,
/// naming the path by its position only (it may hold escapes).
pub fn normalize_only(only: &[String]) -> Result<Vec<String>, String> {
    if only.len() > MAX_ONLY {
        return Err(format!("a session is narrowed to at most {MAX_ONLY} paths"));
    }
    let mut out: Vec<String> = Vec::new();
    for (i, p) in only.iter().enumerate() {
        let n = crate::hub::access::normalize_access_path(p).map_err(|_| format!("path {} of `only` is not a folder or file path from the project root", i + 1))?;
        if n.len() > 4096 || n.split('/').any(|c| crate::object::validate_entry_name(c).is_err()) {
            return Err(format!("path {} of `only` is not a valid path", i + 1));
        }
        out.push(n);
    }
    out.sort();
    out.dedup();
    let all = out.clone();
    out.retain(|p| !all.iter().any(|o| o != p && covers(o, p)));
    Ok(out)
}

/// Is `path` (a file, or a folder as a whole) at or below one of `only`?
pub fn within(only: &[String], path: &str) -> bool {
    only.iter().any(|o| covers(o, path))
}

/// Is folder `dir` on the way to one of `only` (the root, or a folder
/// above one of them)? Its tree is needed to walk there; nothing below it
/// but the way is.
pub fn toward(only: &[String], dir: &str) -> bool {
    dir.is_empty() || only.iter().any(|o| o.len() > dir.len() && covers(dir, o))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn narrowing_is_by_path_components() {
        let only = normalize_only(&s(&["src/api/", "src/api/x", "docs/a.md"])).unwrap();
        assert_eq!(only, s(&["docs/a.md", "src/api"]));
        assert!(within(&only, "src/api") && within(&only, "src/api/h.rs") && within(&only, "docs/a.md"));
        assert!(!within(&only, "src/apix") && !within(&only, "src") && !within(&only, "") && !within(&only, "docs/a.md.bak"));
        assert!(toward(&only, "") && toward(&only, "src") && toward(&only, "docs"));
        assert!(!toward(&only, "src/api") && !toward(&only, "sr") && !toward(&only, "billing"));
    }

    #[test]
    fn hostile_narrowings_are_refused() {
        for bad in ["", "/", "..", "a/../b", "src/*", "a\0b", ".veil", "a/.veil/b"] {
            assert!(normalize_only(&s(&[bad])).is_err(), "{bad:?}");
        }
        assert!(normalize_only(&vec!["a".to_string(); MAX_ONLY + 1]).is_err());
        let e = normalize_only(&s(&["ok", "\u{1b}[2J*"])).unwrap_err();
        assert!(!e.contains('\u{1b}'), "{e}");
    }
}
