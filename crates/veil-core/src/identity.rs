//! Public-key identities and key wrapping ("identity rings").
//!
//! Each person or agent has an X25519 keypair. Scope keys are distributed by
//! *wrapping* them to each member's public key (an ECIES-style sealed box:
//! ephemeral X25519 → BLAKE3 KDF → XChaCha20-Poly1305). Wrapped keys are safe
//! to publish, so key rings travel with the repository.

use std::fmt;

use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{
    crypto::{random_bytes, Envelope, Key},
    error::{Result, VeilError},
};

#[derive(Clone)]
pub struct Identity {
    pub name: String,
    secret: [u8; 32],
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
}

/// A scope key encrypted to one recipient.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedKey {
    pub ephemeral: String,
    pub sealed: Envelope,
}

fn kek(shared: &[u8; 32], eph: &[u8; 32], recipient: &[u8; 32]) -> Key {
    let mut material = Vec::with_capacity(96);
    material.extend_from_slice(shared);
    material.extend_from_slice(eph);
    material.extend_from_slice(recipient);
    blake3::derive_key("veil 2026 key-wrap v1", &material)
}

pub fn parse_public_key(s: &str) -> Result<[u8; 32]> {
    let s = s.trim().trim_start_matches("veil1");
    let v = hex::decode(s).map_err(|_| VeilError::Crypto(format!("invalid public key '{s}'")))?;
    v.try_into().map_err(|_| VeilError::Crypto("public key must be 32 bytes".into()))
}

pub fn format_public_key(k: &[u8; 32]) -> String {
    format!("veil1{}", hex::encode(k))
}

/// Encrypt `key` so only the holder of `recipient`'s secret can recover it.
pub fn wrap_key(recipient: &[u8; 32], key: &Key, scope: &str) -> Result<WrappedKey> {
    let eph = StaticSecret::from(random_bytes::<32>());
    let eph_pub = PublicKey::from(&eph).to_bytes();
    let shared = eph.diffie_hellman(&PublicKey::from(*recipient)).to_bytes();
    let k = kek(&shared, &eph_pub, recipient);
    Ok(WrappedKey {
        ephemeral: hex::encode(eph_pub),
        sealed: Envelope::seal(&k, &format!("wrap:{scope}"), key, false)?,
    })
}

impl Identity {
    pub fn generate(name: &str) -> Identity {
        Identity {
            name: name.to_string(),
            secret: random_bytes(),
        }
    }

    pub fn public_key(&self) -> [u8; 32] {
        PublicKey::from(&StaticSecret::from(self.secret)).to_bytes()
    }

    /// `veil1<hex>` — the shareable form of the public key.
    pub fn public_hex(&self) -> String {
        format_public_key(&self.public_key())
    }

    pub fn unwrap_key(&self, w: &WrappedKey, scope: &str) -> Result<Key> {
        if w.sealed.scope != format!("wrap:{scope}") {
            return Err(VeilError::Crypto("wrapped key belongs to a different scope".into()));
        }
        let eph: [u8; 32] = parse_public_key(&w.ephemeral)?;
        let shared = StaticSecret::from(self.secret)
            .diffie_hellman(&PublicKey::from(eph))
            .to_bytes();
        let k = kek(&shared, &eph, &self.public_key());
        let raw = w.sealed.open(&k)?;
        raw.try_into().map_err(|_| VeilError::Crypto("wrapped key has the wrong size".into()))
    }

    /// Per-repository key that never leaves this device. Protects the local
    /// vault (isolated files and `vl secret` values).
    pub fn local_key(&self, repo_id: &str) -> Key {
        let mut material = self.secret.to_vec();
        material.extend_from_slice(repo_id.as_bytes());
        blake3::derive_key("veil 2026 local-vault v1", &material)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(&IdentityFile {
            name: self.name.clone(),
            public: self.public_hex(),
            secret: hex::encode(self.secret),
        })
        .unwrap()
    }

    pub fn from_json(s: &str) -> Result<Identity> {
        let f: IdentityFile = serde_json::from_str(s)?;
        let secret = crate::crypto::parse_key_hex(&f.secret)?;
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
    }
}
