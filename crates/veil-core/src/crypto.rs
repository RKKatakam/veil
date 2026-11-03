//! Symmetric encryption envelopes (`VeilEnvelope`).
//!
//! Every cloaked node is an XChaCha20-Poly1305 ciphertext bound (as AEAD
//! associated data) to the *scope* that may decrypt it.
//!
//! Content-addressing and encryption are reconciled with **deterministic
//! (SIV-style) nonces**: the nonce is a keyed BLAKE3 hash of the plaintext.
//! Re-snapshotting an unchanged cloaked file therefore yields the *same*
//! object id (dedup, cheap no-op snapshots), while anyone without the scope
//! key learns nothing except equality of identical plaintexts under the same
//! scope — the same trade-off made by convergent-encryption backup systems.
//!
//! The envelope's `scope` field is a *label*: `<scope>` (generation 0, the
//! only form written before key rotation existed) or `<scope>#<key-id>` for a
//! specific key generation (see `keychain`). It is authenticated as AAD, so
//! the binary format is unchanged and old envelopes still open.

use std::fmt;

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{Result, VeilError};

pub type Key = [u8; 32];

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).expect("operating system RNG unavailable");
    b
}

pub fn random_key() -> Key {
    random_bytes()
}

pub fn parse_key_hex(s: &str) -> Result<Key> {
    let v = hex::decode(s.trim()).map_err(|_| VeilError::Crypto("invalid key encoding".into()))?;
    v.try_into().map_err(|_| VeilError::Crypto("key must be 32 bytes".into()))
}

/// An encrypted payload plus the scope whose key opens it.
#[derive(Clone, PartialEq, Eq)]
pub struct Envelope {
    pub scope: String,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

impl fmt::Debug for Envelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Envelope(scope={}, {} bytes)", self.scope, self.ciphertext.len())
    }
}

fn cipher(key: &Key) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new_from_slice(key).expect("32-byte key")
}

impl Envelope {
    /// Encrypt `plaintext` for `scope`. With `deterministic`, the nonce is
    /// derived from the plaintext (see module docs); otherwise it is random.
    pub fn seal(key: &Key, scope: &str, plaintext: &[u8], deterministic: bool) -> Result<Envelope> {
        let nonce: [u8; 24] = if deterministic {
            let nonce_key = zeroize::Zeroizing::new(blake3::derive_key("veil 2026 siv-nonce v1", key));
            let mut h = blake3::Hasher::new_keyed(&nonce_key);
            h.update(scope.as_bytes());
            h.update(&[0]);
            h.update(plaintext);
            h.finalize().as_bytes()[..24].try_into().unwrap()
        } else {
            random_bytes()
        };
        let ciphertext = cipher(key)
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: scope.as_bytes(),
                },
            )
            .map_err(|_| VeilError::Crypto("encryption failed".into()))?;
        Ok(Envelope {
            scope: scope.to_string(),
            nonce,
            ciphertext,
        })
    }

    pub fn open(&self, key: &Key) -> Result<Vec<u8>> {
        cipher(key)
            .decrypt(
                XNonce::from_slice(&self.nonce),
                Payload {
                    msg: &self.ciphertext,
                    aad: self.scope.as_bytes(),
                },
            )
            .map_err(|_| VeilError::Crypto(format!("authentication failed for scope '{}'", self.scope)))
    }

    /// Binary layout: `u16 BE scope_len | scope | nonce[24] | ciphertext`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + self.scope.len() + 24 + self.ciphertext.len());
        out.extend_from_slice(&(self.scope.len() as u16).to_be_bytes());
        out.extend_from_slice(self.scope.as_bytes());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<Envelope> {
        let bad = || VeilError::Corrupt("envelope".into(), "truncated".into());
        if b.len() < 2 {
            return Err(bad());
        }
        let n = u16::from_be_bytes([b[0], b[1]]) as usize;
        if b.len() < 2 + n + 24 {
            return Err(bad());
        }
        let scope = std::str::from_utf8(&b[2..2 + n]).map_err(|_| bad())?.to_string();
        let nonce = b[2 + n..2 + n + 24].try_into().unwrap();
        Ok(Envelope {
            scope,
            nonce,
            ciphertext: b[2 + n + 24..].to_vec(),
        })
    }

    /// Read only the scope from an encoded envelope.
    pub fn peek_scope(b: &[u8]) -> Option<String> {
        if b.len() < 2 {
            return None;
        }
        let n = u16::from_be_bytes([b[0], b[1]]) as usize;
        std::str::from_utf8(b.get(2..2 + n)?).ok().map(str::to_string)
    }
}

#[derive(Serialize, Deserialize)]
struct EnvelopeJson {
    scope: String,
    nonce: String,
    ciphertext: String,
}

impl Serialize for Envelope {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        EnvelopeJson {
            scope: self.scope.clone(),
            nonce: hex::encode(self.nonce),
            ciphertext: hex::encode(&self.ciphertext),
        }
        .serialize(s)
    }
}

impl<'de> Deserialize<'de> for Envelope {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let j = EnvelopeJson::deserialize(d)?;
        let nonce = hex::decode(&j.nonce)
            .ok()
            .and_then(|v| <[u8; 24]>::try_from(v).ok())
            .ok_or_else(|| D::Error::custom("bad nonce"))?;
        let ciphertext = hex::decode(&j.ciphertext).map_err(D::Error::custom)?;
        Ok(Envelope {
            scope: j.scope,
            nonce,
            ciphertext,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open() {
        let k = random_key();
        let e = Envelope::seal(&k, "team", b"hello", true).unwrap();
        assert_eq!(e.open(&k).unwrap(), b"hello");
        let e2 = Envelope::seal(&k, "team", b"hello", true).unwrap();
        assert_eq!(e, e2, "deterministic sealing is stable");
        assert!(e.open(&random_key()).is_err());
        let mut tampered = e.clone();
        tampered.scope = "public".into();
        assert!(tampered.open(&k).is_err(), "scope is authenticated");
        assert_eq!(Envelope::from_bytes(&e.to_bytes()).unwrap(), e);
    }
}
