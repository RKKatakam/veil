//! Web client helpers shared by `veil-server` and the portable WASM build
//! (`docs/HUB.md` §13.39; `docs/design/server/phase-4-agent-scale.md` §4.12).
//!
//! **No secrets in the browser (S25):** this module intentionally contains
//! **no** key ring, keychain, HPKE unwrap, or envelope decryption path.
//! Sealed entries and `Object::Sealed` envelopes are identified strictly as
//! `Sealed` ("open with `vl`") and their bytes are never opened.

use serde::{Deserialize, Serialize};

use crate::{
    crypto::domains::{HUB_WEB_CSRF, HUB_WEB_SESSION, SIG_CONTEXT_HUB_LOGIN, SIG_CONTEXT_HUB_PR_REVIEW},
    error::{Result, VeilError},
    hub::{
        grant::{Grant, GrantBody},
        pr::{review_message, VERDICTS},
        wire::{login_message, LoginRequest},
    },
    hunks::diff_text,
    identity::Identity,
    object::{EntryKind, Object},
    ObjectId,
};

/// Prefix of every short-lived web session token (`web-<64 hex>`).
pub const WEB_TOKEN_PREFIX: &str = "web-";

/// Default lifetime of a web session: 1 hour.
pub const DEFAULT_WEB_SESSION_MS: i64 = 3600 * 1000;

/// Maximum lifetime of a web session: 4 hours.
pub const MAX_WEB_SESSION_MS: i64 = 4 * 3600 * 1000;

/// Maximum plain-text bytes `diff_text_bounded` diffs in one file version.
pub const MAX_WEB_DIFF_BYTES: usize = 1 << 20;

/// `POST /v1/sessions/web`: mint a short-lived web session from a person's
/// device session.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebSessionRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seconds: Option<i64>,
}

/// Answer of `POST /v1/sessions/web`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebSession {
    pub token: String,
    pub person: String,
    pub csrf: String,
    pub expires_at: i64,
}

/// Stored `token_hash` of a `web-` token, domain-separated under
/// [`HUB_WEB_SESSION`] so pre-S25 servers never match it.
pub fn web_token_hash(token: &str) -> String {
    blake3::Hasher::new_derive_key(HUB_WEB_SESSION)
        .update(token.as_bytes())
        .finalize()
        .to_hex()
        .to_string()
}

/// Per-session CSRF token derived from the server's stored `session_hash`.
pub fn csrf_for_session(session_hash: &str) -> String {
    hex::encode(blake3::derive_key(HUB_WEB_CSRF, session_hash.as_bytes()))
}

/// Constant-time byte slice equality.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Verify `candidate` against the CSRF token of `session_hash` in constant time.
pub fn csrf_matches(session_hash: &str, candidate: &str) -> bool {
    let expected = csrf_for_session(session_hash);
    constant_time_eq(expected.as_bytes(), candidate.trim().as_bytes())
}

/// Escape arbitrary repository or user text for safe HTML text and double- or
/// single-quoted attribute contexts. Never renders HTML or scripts.
pub fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(ch),
        }
    }
    out
}

/// How the web client classifies a file's metadata (`veil.file/1` or tree entry).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebFileState {
    /// Encrypted secret file (or non-blob object): never served or opened in the browser.
    Sealed,
    /// Unresolved merge conflict entry.
    Conflict,
    /// Symbolic link entry.
    Symlink,
    /// Plain file whose content may be paged if UTF-8 text.
    PlainFile,
}

#[derive(Deserialize)]
struct MetaProbe {
    #[serde(default)]
    sealed: bool,
    #[serde(default)]
    encoding: Option<String>,
    #[serde(default)]
    kind: Option<String>,
}

/// Classify file metadata using both the visibility claim (`sealed`) and the
/// object encoding (`encoding == "content"`). Any sealed or non-content object
/// is reported as [`WebFileState::Sealed`].
pub fn classify_file_meta(meta_json: &str) -> Result<WebFileState> {
    let m: MetaProbe = serde_json::from_str(meta_json)
        .map_err(|e| VeilError::Corrupt("web-file-meta".into(), e.to_string()))?;
    if m.sealed {
        return Ok(WebFileState::Sealed);
    }
    if let Some(enc) = &m.encoding {
        if enc != "content" {
            return Ok(WebFileState::Sealed);
        }
    }
    match m.kind.as_deref() {
        Some("conflict") => Ok(WebFileState::Conflict),
        Some("symlink") => Ok(WebFileState::Symlink),
        _ => Ok(WebFileState::PlainFile),
    }
}

/// Summary of a decoded Veil object in the browser engine, with zero secret
/// decryption paths.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WebObjectSummary {
    Sealed,
    Blob {
        size: usize,
    },
    Tree {
        entries: Vec<WebTreeItem>,
    },
    Snapshot {
        id: String,
        author: String,
        timestamp: i64,
        parents: Vec<String>,
        change_id: String,
        signature_valid: Option<bool>,
    },
    Conflict,
    Atag {
        name: String,
        target: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebTreeItem {
    pub name: String,
    pub kind: String,
    pub id: String,
    pub size: u64,
    pub sealed: bool,
}

/// Decode and verify an object without ever decrypting or exposing sealed payloads.
pub fn inspect_object_no_secrets(raw: &[u8]) -> Result<WebObjectSummary> {
    if raw.starts_with(b"veil:seal\n") || raw.starts_with(b"veil:siv2\n") {
        return Ok(WebObjectSummary::Sealed);
    }
    let id = ObjectId::hash(raw).hex();
    match Object::decode(raw)? {
        Object::Sealed(_) => Ok(WebObjectSummary::Sealed),
        Object::Blob(b) => Ok(WebObjectSummary::Blob { size: b.len() }),
        Object::Tree(t) => {
            let entries = t
                .entries
                .iter()
                .map(|e| WebTreeItem {
                    name: e.name.clone(),
                    kind: match e.kind {
                        EntryKind::File => "file".into(),
                        EntryKind::Dir => "dir".into(),
                        EntryKind::Conflict => "conflict".into(),
                        EntryKind::Symlink => "symlink".into(),
                    },
                    id: e.id.hex(),
                    size: e.size,
                    sealed: !e.visibility.is_public(),
                })
                .collect();
            Ok(WebObjectSummary::Tree { entries })
        }
        Object::Snapshot(s) => Ok(WebObjectSummary::Snapshot {
            id,
            author: s.author.clone(),
            timestamp: s.timestamp,
            parents: s.parents.iter().map(ObjectId::hex).collect(),
            change_id: s.change_id.to_string(),
            signature_valid: s.signature_valid(),
        }),
        Object::Conflict(_) => Ok(WebObjectSummary::Conflict),
        Object::Atag(a) => Ok(WebObjectSummary::Atag {
            name: a.name,
            target: a.target.hex(),
        }),
    }
}

/// Verify a server-signed read grant token at `now_ms`.
pub fn verify_grant_token(token: &str, grant_key_hex: &str, now_ms: i64) -> Option<GrantBody> {
    let g = Grant::verify(token, grant_key_hex)?;
    (g.body.expires > now_ms).then_some(g.body)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebHunk {
    pub old_start: usize,
    pub old_lines: usize,
    pub new_start: usize,
    pub new_lines: usize,
    pub lines: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebDiff {
    pub binary: bool,
    pub too_large: bool,
    pub hunks: Vec<WebHunk>,
}

/// Compute bounded unified-diff hunks between two plain-text strings.
pub fn diff_text_bounded(old: &str, new: &str, max_bytes: usize) -> WebDiff {
    let cap = max_bytes.min(MAX_WEB_DIFF_BYTES);
    if old.as_bytes().contains(&0) || new.as_bytes().contains(&0) {
        return WebDiff { binary: true, too_large: false, hunks: Vec::new() };
    }
    if old.len() > cap || new.len() > cap {
        return WebDiff { binary: false, too_large: true, hunks: Vec::new() };
    }
    let d = diff_text(old, new);
    let hunks = d
        .hunks
        .into_iter()
        .map(|h| WebHunk {
            old_start: h.old_start,
            old_lines: h.old_lines,
            new_start: h.new_start,
            new_lines: h.new_lines,
            lines: h.lines.into_iter().map(|l| format!("{}{}", l.kind.prefix(), l.text)).collect(),
        })
        .collect();
    WebDiff { binary: false, too_large: false, hunks }
}

/// Sign a single-use login challenge (`hub-login`) in memory without exposing
/// private keys.
pub fn sign_web_login(identity_json: &str, hub: &str, challenge_hex: &str, name: Option<&str>) -> Result<LoginRequest> {
    let id = Identity::from_json(identity_json)?;
    if challenge_hex.len() != 64 || !challenge_hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(VeilError::Corrupt("challenge".into(), "challenge must be 32 bytes in lowercase hex".into()));
    }
    let msg = login_message(hub, challenge_hex);
    let signature = id.sign(SIG_CONTEXT_HUB_LOGIN, &msg);
    Ok(LoginRequest {
        key: id.verifying_hex(),
        challenge: challenge_hex.to_string(),
        hub: hub.to_string(),
        signature,
        identity: id.public_id(),
        name: name.map(str::to_string),
    })
}

/// Sign a PR review verdict (`hub-pr-review`) in memory without exposing
/// private keys.
pub fn sign_web_pr_review(identity_json: &str, project: &str, pr_id: &str, patch: &str, verdict: &str) -> Result<String> {
    if !VERDICTS.contains(&verdict) {
        return Err(VeilError::Policy("verdict must be approve or request-changes".into()));
    }
    let id = Identity::from_json(identity_json)?;
    let msg = review_message(project, pr_id, patch, verdict);
    Ok(id.sign(SIG_CONTEXT_HUB_PR_REVIEW, &msg))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        crypto::Envelope,
        hub::project::empty_tree_id,
        identity::verify_signature,
        object::Snapshot,
    };

    #[test]
    fn html_escape_escapes_all_active_characters() {
        let hostile = "<script>alert(\"xss\", '1') & </script>";
        let escaped = html_escape(hostile);
        assert_eq!(escaped, "&lt;script&gt;alert(&quot;xss&quot;, &#x27;1&#x27;) &amp; &lt;/script&gt;");
        assert!(!escaped.contains('<') && !escaped.contains('>') && !escaped.contains('"') && !escaped.contains('\''));
    }

    #[test]
    fn csrf_is_bound_to_session_hash_and_web_hash_is_domain_separated() {
        let tok = format!("{WEB_TOKEN_PREFIX}{}", "ab".repeat(32));
        let web_h = web_token_hash(&tok);
        let plain_h = blake3::hash(tok.as_bytes()).to_hex().to_string();
        assert_ne!(web_h, plain_h, "pre-S25 servers must never match a web- token");
        let csrf = csrf_for_session(&web_h);
        assert!(csrf_matches(&web_h, &csrf));
        assert!(!csrf_matches(&web_h, "wrong"));
        assert!(!csrf_matches(&plain_h, &csrf));
    }

    #[test]
    fn sealed_objects_and_metadata_never_expose_secret_bytes() {
        assert_eq!(classify_file_meta(r#"{"sealed":true,"encoding":"object","kind":"file"}"#).unwrap(), WebFileState::Sealed);
        assert_eq!(classify_file_meta(r#"{"sealed":false,"encoding":"object","kind":"file"}"#).unwrap(), WebFileState::Sealed);
        assert_eq!(classify_file_meta(r#"{"sealed":false,"encoding":"content","kind":"file"}"#).unwrap(), WebFileState::PlainFile);

        let key = [7u8; 32];
        let env = Envelope::seal_deterministic(&key, "team#0102030405060708", b"SUPER_SECRET_TOKEN=xyz123456").unwrap();
        let raw = Object::Sealed(env).encode();
        let summary = inspect_object_no_secrets(&raw).unwrap();
        assert_eq!(summary, WebObjectSummary::Sealed);
        let as_json = serde_json::to_string(&summary).unwrap();
        assert!(!as_json.contains("SUPER_SECRET_TOKEN"));
    }

    #[test]
    fn snapshot_verification_and_device_signing_work_in_memory() {
        let alice = Identity::generate("alice");
        let mut snap = Snapshot::root(empty_tree_id());
        snap.author = "alice".into();
        snap.timestamp = 1_750_000_000_000;
        snap.sign(&alice);
        let raw = Object::Snapshot(snap).encode();
        let summary = inspect_object_no_secrets(&raw).unwrap();
        match summary {
            WebObjectSummary::Snapshot { signature_valid, author, .. } => {
                assert_eq!(signature_valid, Some(true));
                assert_eq!(author, "alice");
            }
            other => panic!("unexpected summary: {other:?}"),
        }

        let chal = "11".repeat(32);
        let login = sign_web_login(&alice.to_json(), "veil.example:443", &chal, Some("alice")).unwrap();
        assert!(verify_signature(
            &login.key,
            SIG_CONTEXT_HUB_LOGIN,
            &login_message("veil.example:443", &chal),
            &login.signature
        ));

        let sig = sign_web_pr_review(&alice.to_json(), "acme", "pr-1234abcd", "patch-hash", "approve").unwrap();
        assert!(verify_signature(
            &alice.verifying_hex(),
            SIG_CONTEXT_HUB_PR_REVIEW,
            &review_message("acme", "pr-1234abcd", "patch-hash", "approve"),
            &sig
        ));
    }
}
