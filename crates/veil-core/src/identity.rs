//! Public-key identities, key wrapping and signatures.
//!
//! Each person or agent has one 32-byte secret from which two keypairs are
//! derived:
//!
//! * an **X25519** keypair (the secret is used directly, as before) for
//!   *wrapping* scope keys: an ECIES-style sealed box (ephemeral X25519 →
//!   BLAKE3 KDF → XChaCha20-Poly1305). Wrapped keys are safe to publish, so
//!   key rings travel with the repository;
//! * an **Ed25519** signing keypair whose seed is
//!   `BLAKE3-derive("veil 2026 ed25519-seed v1", secret)`. Deriving it means
//!   identity files written before signatures existed keep loading and gain
//!   a stable signing key.
//!
//! The *member id* of an identity is `veil1<x25519-hex>` (64 hex digits, the
//! historical public key form). The *full public identity* appends the
//! Ed25519 verifying key: `veil1<x25519-hex><ed25519-hex>` (128 hex digits).
//! Only the full form lets a key ring bind a member to a signing key, so it is
//! what `vl identity show` prints.

use std::fmt;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::{
    crypto::{random_bytes, Envelope, Key},
    error::{Result, VeilError},
};

#[derive(Clone)]
pub struct Identity {
    pub name: String,
    secret: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Identity({}, {})", self.name, &self.public_hex()[..12])
    }
}

#[derive(Serialize, Deserialize)]
struct IdentityFile {
    name: String,
    public: String,
    secret: String,
    /// Informational: the Ed25519 verifying key (always re-derived on load).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signing: Option<String>,
}

/// A scope key encrypted to one recipient.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedKey {
    pub ephemeral: String,
    pub sealed: Envelope,
}

fn kek(shared: &[u8; 32], eph: &[u8; 32], recipient: &[u8; 32]) -> Zeroizing<Key> {
    let mut material = Zeroizing::new(Vec::with_capacity(96));
    material.extend_from_slice(shared);
    material.extend_from_slice(eph);
    material.extend_from_slice(recipient);
    Zeroizing::new(blake3::derive_key("veil 2026 key-wrap v1", &material))
}

/// A parsed public identity: the X25519 key, plus the Ed25519 verifying key
/// when the full form was given.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicIdentity {
    pub x25519: [u8; 32],
    pub ed25519: Option<[u8; 32]>,
}

impl PublicIdentity {
    pub fn member_id(&self) -> String {
        format_public_key(&self.x25519)
    }

    pub fn signing_hex(&self) -> Option<String> {
        self.ed25519.map(hex::encode)
    }
}

/// Parse `veil1<x25519>` or the full `veil1<x25519><ed25519>`.
pub fn parse_public_identity(s: &str) -> Result<PublicIdentity> {
    let s = s.trim().trim_start_matches("veil1");
    let v = hex::decode(s).map_err(|_| VeilError::Crypto(format!("invalid public key '{s}'")))?;
    match v.len() {
        32 => Ok(PublicIdentity {
            x25519: v.try_into().unwrap(),
            ed25519: None,
        }),
        64 => {
            let ed: [u8; 32] = v[32..].try_into().unwrap();
            VerifyingKey::from_bytes(&ed).map_err(|_| VeilError::Crypto("invalid Ed25519 verifying key".into()))?;
            Ok(PublicIdentity {
                x25519: v[..32].try_into().unwrap(),
                ed25519: Some(ed),
            })
        }
        _ => Err(VeilError::Crypto(
            "public key must be veil1 + 64 hex digits (or 128 for the full identity)".into(),
        )),
    }
}

/// The X25519 part of a public identity (either form).
pub fn parse_public_key(s: &str) -> Result<[u8; 32]> {
    Ok(parse_public_identity(s)?.x25519)
}

pub fn format_public_key(k: &[u8; 32]) -> String {
    format!("veil1{}", hex::encode(k))
}

/// Encrypt `key` so only the holder of `recipient`'s secret can recover it.
pub fn wrap_key(recipient: &[u8; 32], key: &Key, scope: &str) -> Result<WrappedKey> {
    let eph = StaticSecret::from(random_bytes::<32>());
    let eph_pub = PublicKey::from(&eph).to_bytes();
    let shared = eph.diffie_hellman(&PublicKey::from(*recipient));
    let k = kek(shared.as_bytes(), &eph_pub, recipient);
    Ok(WrappedKey {
        ephemeral: hex::encode(eph_pub),
        sealed: Envelope::seal(&k, &format!("wrap:{scope}"), key, false)?,
    })
}

/// The message actually signed: a domain-separated context plus the payload.
fn signed_message(context: &str, msg: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(16 + context.len() + msg.len());
    m.extend_from_slice(b"veil 2026 sig v1\0");
    m.extend_from_slice(context.as_bytes());
    m.push(0);
    m.extend_from_slice(msg);
    m
}

/// Verify an Ed25519 signature (hex) by `verifying_key` (hex) over `msg`
/// under `context`. Malformed input verifies as `false`.
pub fn verify_signature(verifying_key: &str, context: &str, msg: &[u8], signature: &str) -> bool {
    let Some(vk) = hex::decode(verifying_key)
        .ok()
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
        .and_then(|b| VerifyingKey::from_bytes(&b).ok())
    else {
        return false;
    };
    let Some(sig) = hex::decode(signature)
        .ok()
        .and_then(|v| <[u8; 64]>::try_from(v).ok())
        .map(|b| ed25519_dalek::Signature::from_bytes(&b))
    else {
        return false;
    };
    vk.verify_strict(&signed_message(context, msg), &sig).is_ok()
}

/// A detached Ed25519 signature plus the identity that claims it.
///
/// `signer` is the member id (`veil1<x25519>`) the signer claims to be and
/// `key` the Ed25519 verifying key that produced `sig`. A valid signature only
/// proves possession of `key`; whether `key` belongs to `signer` (and whether
/// that signer was authorised) is decided against the key rings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    pub signer: String,
    pub key: String,
    pub sig: String,
}

impl Signature {
    pub fn create(identity: &Identity, context: &str, msg: &[u8]) -> Signature {
        Signature {
            signer: identity.public_hex(),
            key: identity.verifying_hex(),
            sig: identity.sign(context, msg),
        }
    }

    pub fn verify(&self, context: &str, msg: &[u8]) -> bool {
        verify_signature(&self.key, context, msg, &self.sig)
    }
}

impl Identity {
    pub fn generate(name: &str) -> Identity {
        Identity {
            name: name.to_string(),
            secret: Zeroizing::new(random_bytes()),
        }
    }

    fn x25519_secret(&self) -> StaticSecret {
        StaticSecret::from(*self.secret)
    }

    fn signing_key(&self) -> SigningKey {
        let seed = Zeroizing::new(blake3::derive_key("veil 2026 ed25519-seed v1", &*self.secret));
        SigningKey::from_bytes(&seed)
    }

    pub fn public_key(&self) -> [u8; 32] {
        PublicKey::from(&self.x25519_secret()).to_bytes()
    }

    /// `veil1<hex>` — the member id (X25519 public key).
    pub fn public_hex(&self) -> String {
        format_public_key(&self.public_key())
    }

    /// Ed25519 verifying key.
    pub fn verifying_key(&self) -> [u8; 32] {
        self.signing_key().verifying_key().to_bytes()
    }

    pub fn verifying_hex(&self) -> String {
        hex::encode(self.verifying_key())
    }

    /// `veil1<x25519><ed25519>` — the full shareable public identity.
    pub fn public_id(&self) -> String {
        format!("{}{}", self.public_hex(), self.verifying_hex())
    }

    /// Sign `msg` under a domain-separation `context`; returns hex.
    pub fn sign(&self, context: &str, msg: &[u8]) -> String {
        hex::encode(self.signing_key().sign(&signed_message(context, msg)).to_bytes())
    }

    pub fn unwrap_key(&self, w: &WrappedKey, scope: &str) -> Result<Key> {
        if w.sealed.scope != format!("wrap:{scope}") {
            return Err(VeilError::Crypto("wrapped key belongs to a different scope".into()));
        }
        let eph: [u8; 32] = parse_public_key(&w.ephemeral)?;
        let shared = self.x25519_secret().diffie_hellman(&PublicKey::from(eph));
        let k = kek(shared.as_bytes(), &eph, &self.public_key());
        let raw = Zeroizing::new(w.sealed.open(&k)?);
        raw.as_slice()
            .try_into()
            .map_err(|_| VeilError::Crypto("wrapped key has the wrong size".into()))
    }

    /// Per-repository key that never leaves this device. Protects the local
    /// vault (isolated files and `vl secret` values).
    pub fn local_key(&self, repo_id: &str) -> Key {
        let mut material = Zeroizing::new(self.secret.to_vec());
        material.extend_from_slice(repo_id.as_bytes());
        blake3::derive_key("veil 2026 local-vault v1", &material)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(&IdentityFile {
            name: self.name.clone(),
            public: self.public_hex(),
            secret: hex::encode(*self.secret),
            signing: Some(self.verifying_hex()),
        })
        .unwrap()
    }

    pub fn from_json(s: &str) -> Result<Identity> {
        let f: IdentityFile = serde_json::from_str(s)?;
        let secret = Zeroizing::new(crate::crypto::parse_key_hex(&f.secret)?);
        let _wipe = Zeroizing::new(f.secret);
        Ok(Identity { name: f.name, secret })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_unwrap() {
        let alice = Identity::generate("alice");
        let bob = Identity::generate("bob");
        let key = crate::crypto::random_key();
        let w = wrap_key(&alice.public_key(), &key, "team").unwrap();
        assert_eq!(alice.unwrap_key(&w, "team").unwrap(), key);
        assert!(bob.unwrap_key(&w, "team").is_err());
        assert!(alice.unwrap_key(&w, "ops").is_err());
        let back = Identity::from_json(&alice.to_json()).unwrap();
        assert_eq!(back.public_key(), alice.public_key());
        assert_eq!(back.verifying_key(), alice.verifying_key());
    }

    #[test]
    fn legacy_identity_files_load_and_gain_a_stable_signing_key() {
        // The format written before signatures existed: no `signing` field.
        let legacy = r#"{"name":"old","public":"veil1ab","secret":"0101010101010101010101010101010101010101010101010101010101010101"}"#;
        let a = Identity::from_json(legacy).unwrap();
        let b = Identity::from_json(legacy).unwrap();
        assert_eq!(a.verifying_key(), b.verifying_key(), "deterministic derivation");
        assert_ne!(a.verifying_key(), a.public_key());
        let sig = a.sign("test", b"msg");
        assert!(verify_signature(&a.verifying_hex(), "test", b"msg", &sig));
        assert!(!verify_signature(&a.verifying_hex(), "other", b"msg", &sig), "context separates");
        assert!(!verify_signature(&a.verifying_hex(), "test", b"msg2", &sig));
        assert!(!verify_signature(&Identity::generate("x").verifying_hex(), "test", b"msg", &sig));
        assert!(!verify_signature("zz", "test", b"msg", &sig));
    }

    #[test]
    fn public_identity_forms() {
        let a = Identity::generate("a");
        let full = parse_public_identity(&a.public_id()).unwrap();
        assert_eq!(full.member_id(), a.public_hex());
        assert_eq!(full.ed25519, Some(a.verifying_key()));
        let short = parse_public_identity(&a.public_hex()).unwrap();
        assert_eq!(short.ed25519, None);
        assert_eq!(parse_public_key(&a.public_id()).unwrap(), a.public_key());
        assert!(parse_public_identity("veil1abcd").is_err());
    }
}
