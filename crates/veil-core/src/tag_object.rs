//! Annotated tag objects (`veil:atag`, repository format 5).
//!
//! An annotated tag is a tag object: a name, the snapshot it points at, a
//! message, who made it and when, and optionally a signature. The view's
//! [`crate::oplog::Tag::annotation`] names one; a tag with an annotation is
//! a **release tag** (immutable), one without stays a branch-like tag.
//!
//! # Encoding
//!
//! `veil:atag\n` ‖ canonical JSON, exactly the bytes `serde_json` writes for
//! [`Atag`] (fields in declaration order, optional fields omitted when
//! absent). Like snapshots, a non-canonical encoding is refused: otherwise
//! one signed tag could be re-encoded under many ids, all with a valid
//! signature. Unknown fields are refused too (FORMAT.md rule 1).
//!
//! ```text
//! {"name":…,"target":…,"kind":"annotated",
//!  "message":{"plain":…}|{"sealed":…},"tagger":…,"timestamp":…,
//!  "signature"?:{signer,key,sig}}
//! ```
//!
//! # Signatures
//!
//! `Ed25519(identity signing key, SIG_PREFIX ‖ "tag" ‖ 0 ‖ unsigned-id)`
//! with [`SIG_CONTEXT_TAG`], where
//! the unsigned id is the id of the encoding without `signature`. The
//! signature therefore covers the name, the target, the kind, the
//! (possibly sealed) message, the tagger and the time: an
//! atag cannot be moved to another target or name without breaking it, and
//! [`Atag::verify`] also checks that the view entry naming it agrees with
//! its `name` and `target` (a valid atag of `v1.0` shown under `v2.0`, or
//! under `v1.0` pointing elsewhere, is "unverified (name mismatch)").
//!
//! # Confidentiality
//!
//! A cloaked tag seals its message under the tag's scope
//! ([`crate::store::ObjectStore::make_text`]): the atag object itself stays
//! plaintext (name, target, tagger and time are as visible as the tag's
//! view entry), and a public remote never receives an atag whose message
//! is sealed (`remote.rs` withholds it, as it withholds cloaked tags).

use serde::{Deserialize, Serialize};

use crate::{
    commands::validate_tag_name,
    crypto::domains::SIG_CONTEXT_TAG,
    error::{Result, VeilError},
    id::ObjectId,
    identity::{Identity, Signature},
    object::{Object, Text},
};

/// Largest message (plain or sealed, in bytes) an atag may carry: a
/// hostile object carrying more is corrupt.
pub const MAX_TAG_MESSAGE: usize = 1 << 20;
/// Largest tagger string.
pub const MAX_TAGGER: usize = 1024;

/// How the tag was made.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AtagKind {
    /// `vl tag set -a`.
    Annotated,
}

/// An annotated tag object; see the module documentation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Atag {
    /// The tag's name. The view entry naming this atag must have the same.
    pub name: String,
    /// The snapshot the tag points at.
    pub target: ObjectId,
    pub kind: AtagKind,
    /// Sealed under the tag's scope for a cloaked tag.
    pub message: Text,
    pub tagger: String,
    /// Milliseconds since the Unix epoch.
    pub timestamp: i64,
    /// Ed25519 over [`Atag::unsigned_id`] (context `tag`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<Signature>,
}

fn atag_corrupt(m: impl Into<String>) -> VeilError {
    VeilError::Corrupt("atag".into(), m.into())
}

/// What [`Atag::verify`] found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AtagVerification {
    /// A valid Veil signature by `signer` (hex X25519 member id) with
    /// signing key `key` (hex Ed25519). Whether that key belongs to a
    /// trusted member is for the caller (the ring) to decide.
    Signed { signer: String, key: String },
    /// No signature at all.
    Unsigned,
    /// A signature that does not verify (forged, or the atag was edited).
    BadSignature,
    /// The view entry's name is not the atag's (a transplanted atag).
    NameMismatch { atag: String },
    /// The view entry's target is not the atag's (a re-targeted tag).
    TargetMismatch { atag: ObjectId },
}

impl AtagVerification {
    /// True only for a valid Veil signature (the caller still checks the
    /// key against the ring).
    pub fn is_signed(&self) -> bool {
        matches!(self, AtagVerification::Signed { .. })
    }

    /// Short human description ("unverified (name mismatch)", …).
    pub fn describe(&self) -> String {
        match self {
            AtagVerification::Signed { signer, .. } => format!("signed by {}", &signer[..signer.len().min(16)]),
            AtagVerification::Unsigned => "unsigned".into(),
            AtagVerification::BadSignature => "unverified (bad signature)".into(),
            AtagVerification::NameMismatch { .. } => "unverified (name mismatch)".into(),
            AtagVerification::TargetMismatch { .. } => "unverified (target mismatch)".into(),
        }
    }
}

impl Atag {
    /// A new annotated tag, unsigned (see [`Atag::sign`]).
    pub fn annotated(name: &str, target: ObjectId, message: Text, tagger: &str, timestamp: i64) -> Atag {
        Atag {
            name: name.to_string(),
            target,
            kind: AtagKind::Annotated,
            message,
            tagger: tagger.to_string(),
            timestamp,
            signature: None,
        }
    }

    /// The payload (without the object tag): canonical JSON.
    pub fn encode_payload(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("atag serialises")
    }

    /// Decode a payload: canonical JSON only, every field checked.
    pub fn decode_payload(payload: &[u8]) -> Result<Atag> {
        let a: Atag = serde_json::from_slice(payload).map_err(|e| atag_corrupt(e.to_string()))?;
        if serde_json::to_vec(&a)? != payload {
            return Err(atag_corrupt("atag is not in canonical encoding"));
        }
        a.validate()?;
        Ok(a)
    }

    /// Structural checks every reader applies (the object comes from
    /// remotes and from `.veil/`: hostile).
    pub fn validate(&self) -> Result<()> {
        validate_tag_name(&self.name).map_err(|_| atag_corrupt("invalid tag name"))?;
        let message_len = self.message.as_str().len();
        if message_len > MAX_TAG_MESSAGE {
            return Err(atag_corrupt(format!("message over {MAX_TAG_MESSAGE} bytes")));
        }
        if self.tagger.len() > MAX_TAGGER || self.tagger.chars().any(char::is_control) {
            return Err(atag_corrupt("invalid tagger"));
        }
        Ok(())
    }

    /// Id of this atag's encoding without `signature`: the signed value.
    pub fn unsigned_id(&self) -> ObjectId {
        if self.signature.is_none() {
            return ObjectId::hash(&Object::Atag(self.clone()).encode());
        }
        let mut a = self.clone();
        a.signature = None;
        ObjectId::hash(&Object::Atag(a).encode())
    }

    /// Replace any signature with one by `identity` (context `tag`).
    pub fn sign(&mut self, identity: &Identity) {
        self.signature = None;
        let id = self.unsigned_id();
        self.signature = Some(Signature::create(identity, SIG_CONTEXT_TAG, &id.0));
    }

    /// `None` if unsigned, else whether the signature is cryptographically
    /// valid (says nothing about who the key belongs to).
    pub fn signature_valid(&self) -> Option<bool> {
        let sig = self.signature.as_ref()?;
        Some(sig.verify(SIG_CONTEXT_TAG, &self.unsigned_id().0))
    }

    /// Check this atag as the annotation of the view entry `name → target`.
    /// The name and target are checked first: a transplanted or re-targeted
    /// atag is never reported as signed, whatever its signature.
    pub fn verify(&self, name: &str, target: &ObjectId) -> AtagVerification {
        if self.name != name {
            return AtagVerification::NameMismatch { atag: self.name.clone() };
        }
        if self.target != *target {
            return AtagVerification::TargetMismatch { atag: self.target };
        }
        match (&self.signature, self.signature_valid()) {
            (Some(sig), Some(true)) => AtagVerification::Signed {
                signer: sig.signer.clone(),
                key: sig.key.clone(),
            },
            (Some(_), _) => AtagVerification::BadSignature,
            (None, _) => AtagVerification::Unsigned,
        }
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Atag {
        Atag::annotated("v1.0", ObjectId([7; 32]), Text::Plain("Release 1.0\n".into()), "alice", 1_700_000_000_000)
    }

    #[test]
    fn round_trips_canonically() {
        let mut a = sample();
        let id = Identity::generate("alice");
        a.sign(&id);
        let raw = Object::Atag(a.clone()).encode();
        assert!(raw.starts_with(b"veil:atag\n{\"name\":\"v1.0\",\"target\":"));
        assert_eq!(Object::decode(&raw).unwrap(), Object::Atag(a.clone()));
        assert_eq!(a.verify("v1.0", &ObjectId([7; 32])), AtagVerification::Signed {
            signer: id.public_hex(),
            key: id.verifying_hex()
        });
        // Whitespace, reordered fields or unknown fields: not canonical.
        let text = std::str::from_utf8(&raw[10..]).unwrap();
        for bad in [
            text.replacen(",", ", ", 1),
            text.replacen("{", "{\"extra\":1,", 1),
            text.replacen("}", ",\"extra\":1}", 1),
        ] {
            let mut r = b"veil:atag\n".to_vec();
            r.extend_from_slice(bad.as_bytes());
            assert!(matches!(Object::decode(&r), Err(VeilError::Corrupt(..))), "{bad}");
        }
    }

    #[test]
    fn forged_retargeted_and_transplanted_atags_do_not_verify() {
        let id = Identity::generate("alice");
        let mut a = sample();
        a.sign(&id);
        // Re-targeted: same signature, edited target.
        let mut moved = a.clone();
        moved.target = ObjectId([8; 32]);
        assert_eq!(moved.verify("v1.0", &ObjectId([8; 32])), AtagVerification::BadSignature);
        // Renamed: same signature, edited name.
        let mut renamed = a.clone();
        renamed.name = "v2.0".into();
        assert_eq!(renamed.verify("v2.0", &ObjectId([7; 32])), AtagVerification::BadSignature);
        // Transplanted: the genuine atag under another view name or target.
        assert!(matches!(a.verify("v2.0", &ObjectId([7; 32])), AtagVerification::NameMismatch { .. }));
        assert!(matches!(a.verify("v1.0", &ObjectId([9; 32])), AtagVerification::TargetMismatch { .. }));
        // Forged: another key's signature with the victim's signer id.
        let mallory = Identity::generate("mallory");
        let mut forged = sample();
        forged.sign(&mallory);
        let mut sig = forged.signature.clone().unwrap();
        sig.key = id.verifying_hex();
        forged.signature = Some(sig);
        assert_eq!(forged.verify("v1.0", &ObjectId([7; 32])), AtagVerification::BadSignature);
        // Cross-context replay: a snapshot-context signature over the same
        // unsigned id is not a tag signature.
        let mut replay = sample();
        let uid = replay.unsigned_id();
        replay.signature = Some(Signature::create(&id, crate::crypto::domains::SIG_CONTEXT_SNAPSHOT, &uid.0));
        assert_eq!(replay.verify("v1.0", &ObjectId([7; 32])), AtagVerification::BadSignature);
        // Stripping the signature changes the id (the id commits to it).
        let mut stripped = a.clone();
        stripped.signature = None;
        assert_ne!(ObjectId::hash(&Object::Atag(stripped).encode()), ObjectId::hash(&Object::Atag(a).encode()));
    }

    #[test]
    fn hostile_atags_are_refused() {
        let enc = |a: &Atag| Object::Atag(a.clone()).encode();
        let bad = |a: Atag| matches!(Object::decode(&enc(&a)), Err(VeilError::Corrupt(..)));
        for name in ["", "..", "a..b", "root", "x\u{1b}[31m", "a b", "tag@", "x-"] {
            let mut a = sample();
            a.name = name.into();
            assert!(bad(a), "{name:?}");
        }
        let mut a = sample();
        a.message = Text::Plain("x".repeat(MAX_TAG_MESSAGE + 1));
        assert!(bad(a));
        let mut a = sample();
        a.tagger = "evil\u{1b}]8;;http://x\u{7}".into();
        assert!(bad(a));
        let mut a = sample();
        a.tagger = "t".repeat(MAX_TAGGER + 1);
        assert!(bad(a));
        // A reserved encoding byte is "needs a newer vl".
        let mut r = b"veil:atag\n".to_vec();
        r.push(0x05);
        assert!(matches!(Object::decode(&r), Err(VeilError::Unsupported(_))));
        // Truncated JSON, empty payload.
        assert!(Object::decode(b"veil:atag\n{\"name\"").is_err());
        assert!(Object::decode(b"veil:atag\n").is_err());
    }
}
