//! Symmetric encryption envelopes (`Envelope`).
//!
//! An envelope is a ciphertext plus the *label* (the `scope` field) that
//! names the key opening it: `<scope>` (generation 0), `<scope>#<key-id>`
//! (a key generation, see `keychain`), `embargo/<id>`, `local`, or one of
//! the role prefixes in [`domains`]. The label is always authenticated as
//! associated data. Two constructions exist (see `docs/CRYPTO.md`):
//!
//! * [`Suite::AesSiv`] — **deterministic** sealing of objects, repository
//!   format 3 and later: AES-SIV (RFC 5297) with CMAC-AES-256 and
//!   CTR-AES-256 (the 512-bit-key variant), keyed with
//!   `HKDF-SHA256(scope key, info = domains::AES_SIV_SUBKEY)`, associated
//!   data `[label]`, no nonce. Unchanged plaintext under the same key and
//!   label always gives the same ciphertext, so content addressing still
//!   deduplicates and no-op snapshots stay no-ops; an observer without the
//!   key learns only equality of identical (label, plaintext) pairs, which
//!   is exactly the deterministic-AE security notion SIV is proven for.
//! * [`Suite::XChaCha20Poly1305`] — an explicit 24-byte nonce. Used with a
//!   **random** nonce for everything that need not be deterministic
//!   (descriptions, sealed keys, the vault), in every format. In formats
//!   1–2 it was also used for objects with a nonce derived by a keyed
//!   BLAKE3 hash of label and plaintext (a homemade SIV). That legacy
//!   construction is still *read* everywhere and still *written* by
//!   format-1/2 repositories only, so older vl can read what they write
//!   ([`Envelope::seal_deterministic_legacy`]).
//!
//! The object encoding tells the two apart: `veil:seal\n` holds an
//! XChaCha20-Poly1305 envelope and `veil:sea2\n` an AES-SIV one (see
//! `docs/FORMAT.md`).

pub mod domains;

use std::fmt;

use aes_siv::siv::Aes256Siv;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use serde::{de::Error as _, ser::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

use crate::error::{Result, VeilError};

pub type Key = [u8; 32];

/// Longest scope label an envelope can carry (its length is a `u16`).
pub const MAX_SCOPE_LEN: usize = u16::MAX as usize;

/// Length of the synthetic IV that starts every AES-SIV ciphertext.
pub const SIV_LEN: usize = 16;

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("operating system RNG unavailable");
    b
}

pub fn random_key() -> Key {
    random_bytes()
}

pub fn parse_key_hex(s: &str) -> Result<Key> {
    let v = Zeroizing::new(hex::decode(s.trim()).map_err(|_| VeilError::Crypto("invalid key encoding".into()))?);
    v.as_slice()
        .try_into()
        .map_err(|_| VeilError::Crypto("key must be 32 bytes".into()))
}

/// The AEAD construction of an envelope.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Suite {
    /// XChaCha20-Poly1305 with this explicit nonce (random; or, in legacy
    /// format-1/2 objects, derived from the plaintext).
    XChaCha20Poly1305 { nonce: [u8; 24] },
    /// AES-SIV-CMAC-512 (RFC 5297), deterministic; the ciphertext starts
    /// with the 16-byte synthetic IV.
    AesSiv,
}

/// An encrypted payload plus the label whose key opens it.
#[derive(Clone, PartialEq, Eq)]
pub struct Envelope {
    /// The label (associated data); historically called the scope.
    pub scope: String,
    pub suite: Suite,
    pub ciphertext: Vec<u8>,
}

impl fmt::Debug for Envelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let suite = match self.suite {
            Suite::XChaCha20Poly1305 { .. } => "xchacha20poly1305",
            Suite::AesSiv => "aes-siv",
        };
        write!(f, "Envelope(scope={}, {suite}, {} bytes)", self.scope, self.ciphertext.len())
    }
}

fn xchacha(key: &Key) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new_from_slice(key).expect("32-byte key")
}

/// The AES-SIV instance for a scope key: HKDF-SHA256 (RFC 5869) expands the
/// 32-byte scope key to the 64-byte AES-SIV key, so the raw scope key is
/// only ever used by XChaCha20-Poly1305 and never by two algorithms.
fn aes_siv(key: &Key) -> Aes256Siv {
    let mut k = Zeroizing::new([0u8; 64]);
    hkdf::Hkdf::<sha2::Sha256>::new(None, key)
        .expand(domains::AES_SIV_SUBKEY.as_bytes(), &mut *k)
        .expect("64 bytes is a valid HKDF-SHA256 output length");
    Aes256Siv::new(&(*k).into())
}

fn check_label(scope: &str) -> Result<()> {
    if scope.len() > MAX_SCOPE_LEN {
        return Err(VeilError::Crypto(format!(
            "scope label is {} bytes; at most {MAX_SCOPE_LEN} can be encoded",
            scope.len()
        )));
    }
    Ok(())
}

impl Envelope {
    /// Encrypt `plaintext` for `scope`: deterministically
    /// ([`Envelope::seal_deterministic`], AES-SIV) or with a random nonce
    /// ([`Envelope::seal_random`], XChaCha20-Poly1305).
    pub fn seal(key: &Key, scope: &str, plaintext: &[u8], deterministic: bool) -> Result<Envelope> {
        if deterministic {
            Envelope::seal_deterministic(key, scope, plaintext)
        } else {
            Envelope::seal_random(key, scope, plaintext)
        }
    }

    /// XChaCha20-Poly1305 with a fresh random 192-bit nonce.
    pub fn seal_random(key: &Key, scope: &str, plaintext: &[u8]) -> Result<Envelope> {
        Envelope::seal_xchacha(key, scope, plaintext, random_bytes())
    }

    /// AES-SIV (RFC 5297): the same key, label and plaintext always give the
    /// same envelope. What repository format 3 writes for objects.
    pub fn seal_deterministic(key: &Key, scope: &str, plaintext: &[u8]) -> Result<Envelope> {
        check_label(scope)?;
        let ciphertext = aes_siv(key)
            .encrypt([scope.as_bytes()], plaintext)
            .map_err(|_| VeilError::Crypto("encryption failed".into()))?;
        Ok(Envelope {
            scope: scope.to_string(),
            suite: Suite::AesSiv,
            ciphertext,
        })
    }

    /// **Legacy**: the format-1/2 deterministic envelope (XChaCha20-Poly1305
    /// with the nonce `keyed-BLAKE3(derive_key(LEGACY_SIV_NONCE, key),
    /// label ‖ 0 ‖ plaintext)[..24]`). Written only into repositories still
    /// at format 1 or 2, which older vl must keep reading.
    pub fn seal_deterministic_legacy(key: &Key, scope: &str, plaintext: &[u8]) -> Result<Envelope> {
        let nonce_key = Zeroizing::new(blake3::derive_key(domains::LEGACY_SIV_NONCE, key));
        let mut h = blake3::Hasher::new_keyed(&nonce_key);
        h.update(scope.as_bytes());
        h.update(&[0]);
        h.update(plaintext);
        let nonce: [u8; 24] = h.finalize().as_bytes()[..24].try_into().unwrap();
        Envelope::seal_xchacha(key, scope, plaintext, nonce)
    }

    fn seal_xchacha(key: &Key, scope: &str, plaintext: &[u8], nonce: [u8; 24]) -> Result<Envelope> {
        check_label(scope)?;
        let ciphertext = xchacha(key)
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad: scope.as_bytes(),
                },
            )
            .map_err(|_| VeilError::Crypto("encryption failed".into()))?;
        Ok(Envelope {
            scope: scope.to_string(),
            suite: Suite::XChaCha20Poly1305 { nonce },
            ciphertext,
        })
    }

    pub fn open(&self, key: &Key) -> Result<Vec<u8>> {
        let opened = match self.suite {
            Suite::XChaCha20Poly1305 { nonce } => xchacha(key)
                .decrypt(
                    &XNonce::from(nonce),
                    Payload {
                        msg: &self.ciphertext,
                        aad: self.scope.as_bytes(),
                    },
                )
                .ok(),
            Suite::AesSiv => aes_siv(key).decrypt([self.scope.as_bytes()], &self.ciphertext).ok(),
        };
        opened.ok_or_else(|| VeilError::Crypto(format!("authentication failed for scope '{}'", self.scope)))
    }

    /// Is this the deterministic AES-SIV construction (repository format 3)?
    pub fn is_aes_siv(&self) -> bool {
        self.suite == Suite::AesSiv
    }

    /// Binary layout: `u16 BE scope_len | scope | body`, where `body` is
    /// `nonce[24] | ciphertext` for XChaCha20-Poly1305 and `siv[16] |
    /// ciphertext` (the AES-SIV output) for AES-SIV. The layout does not say
    /// which: the object tag does (`docs/FORMAT.md`).
    ///
    /// # Panics
    ///
    /// If `scope` is longer than [`MAX_SCOPE_LEN`]. The constructors never
    /// produce such an envelope; only direct mutation of the public field
    /// can, and a silently truncated length would make the encoding
    /// ambiguous.
    pub fn to_bytes(&self) -> Vec<u8> {
        let len = u16::try_from(self.scope.len())
            .unwrap_or_else(|_| panic!("envelope scope label exceeds {MAX_SCOPE_LEN} bytes"));
        let mut out = Vec::with_capacity(2 + self.scope.len() + 24 + self.ciphertext.len());
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(self.scope.as_bytes());
        if let Suite::XChaCha20Poly1305 { nonce } = &self.suite {
            out.extend_from_slice(nonce);
        }
        out.extend_from_slice(&self.ciphertext);
        out
    }

    fn split_label(b: &[u8]) -> Result<(String, &[u8])> {
        let bad = || VeilError::Corrupt("envelope".into(), "truncated".into());
        if b.len() < 2 {
            return Err(bad());
        }
        let n = u16::from_be_bytes([b[0], b[1]]) as usize;
        let label = b.get(2..2 + n).ok_or_else(bad)?;
        let scope = std::str::from_utf8(label).map_err(|_| bad())?.to_string();
        Ok((scope, &b[2 + n..]))
    }

    /// Decode an XChaCha20-Poly1305 envelope (`veil:seal` objects, the vault).
    pub fn from_bytes(b: &[u8]) -> Result<Envelope> {
        let (scope, rest) = Envelope::split_label(b)?;
        if rest.len() < 24 {
            return Err(VeilError::Corrupt("envelope".into(), "truncated".into()));
        }
        Ok(Envelope {
            scope,
            suite: Suite::XChaCha20Poly1305 {
                nonce: rest[..24].try_into().unwrap(),
            },
            ciphertext: rest[24..].to_vec(),
        })
    }

    /// Decode an AES-SIV envelope (`veil:sea2` objects).
    pub fn from_bytes_aes_siv(b: &[u8]) -> Result<Envelope> {
        let (scope, rest) = Envelope::split_label(b)?;
        if rest.len() < SIV_LEN {
            return Err(VeilError::Corrupt("envelope".into(), "truncated".into()));
        }
        Ok(Envelope {
            scope,
            suite: Suite::AesSiv,
            ciphertext: rest.to_vec(),
        })
    }

    /// Read only the scope from an encoded envelope (either layout).
    pub fn peek_scope(b: &[u8]) -> Option<String> {
        if b.len() < 2 {
            return None;
        }
        let n = u16::from_be_bytes([b[0], b[1]]) as usize;
        std::str::from_utf8(b.get(2..2 + n)?).ok().map(str::to_string)
    }
}

/// JSON form (descriptions, sealed keys, embargo records): XChaCha20-Poly1305
/// only. It is part of signed bodies and must never change; AES-SIV
/// envelopes are only ever objects and have no JSON form.
#[derive(Serialize, Deserialize)]
struct EnvelopeJson {
    scope: String,
    nonce: String,
    ciphertext: String,
}

impl Serialize for Envelope {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        let Suite::XChaCha20Poly1305 { nonce } = &self.suite else {
            return Err(S::Error::custom("AES-SIV envelopes have no JSON form"));
        };
        EnvelopeJson {
            scope: self.scope.clone(),
            nonce: hex::encode(nonce),
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
            suite: Suite::XChaCha20Poly1305 { nonce },
            ciphertext,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tampered(e: &Envelope) -> Vec<Envelope> {
        let mut out = Vec::new();
        for i in [0, e.ciphertext.len() / 2, e.ciphertext.len() - 1] {
            let mut t = e.clone();
            t.ciphertext[i] ^= 0x01;
            out.push(t);
        }
        let mut t = e.clone();
        t.scope = "public".into();
        out.push(t);
        let mut t = e.clone();
        t.ciphertext.pop();
        out.push(t);
        if let Suite::XChaCha20Poly1305 { mut nonce } = e.suite {
            nonce[0] ^= 1;
            out.push(Envelope {
                suite: Suite::XChaCha20Poly1305 { nonce },
                ..e.clone()
            });
            // Re-labelled as the other construction.
            out.push(Envelope {
                suite: Suite::AesSiv,
                ..e.clone()
            });
        } else {
            out.push(Envelope {
                suite: Suite::XChaCha20Poly1305 { nonce: [0; 24] },
                ..e.clone()
            });
        }
        out
    }

    #[test]
    fn every_construction_round_trips_and_rejects_tampering() {
        let k = random_key();
        let cases = [
            ("aes-siv", Envelope::seal_deterministic(&k, "team#00aa", b"hello").unwrap()),
            ("random", Envelope::seal_random(&k, "team#00aa", b"hello").unwrap()),
            ("legacy", Envelope::seal_deterministic_legacy(&k, "team#00aa", b"hello").unwrap()),
            ("empty", Envelope::seal_deterministic(&k, "team", b"").unwrap()),
        ];
        for (name, e) in cases {
            assert_eq!(e.open(&k).unwrap(), if name == "empty" { &b""[..] } else { b"hello" }, "{name}");
            assert!(e.open(&random_key()).is_err(), "{name}: wrong key");
            for t in tampered(&e) {
                assert!(t.open(&k).is_err(), "{name}: tampered {t:?} opened");
            }
            let back = if e.is_aes_siv() {
                Envelope::from_bytes_aes_siv(&e.to_bytes())
            } else {
                Envelope::from_bytes(&e.to_bytes())
            };
            assert_eq!(back.unwrap(), e, "{name}");
            assert_eq!(Envelope::peek_scope(&e.to_bytes()).as_deref(), Some(e.scope.as_str()));
        }
    }

    #[test]
    fn deterministic_sealing_is_stable_and_label_bound() {
        let k = random_key();
        let a = Envelope::seal_deterministic(&k, "team", b"hello").unwrap();
        assert_eq!(a, Envelope::seal_deterministic(&k, "team", b"hello").unwrap());
        assert_eq!(a, Envelope::seal(&k, "team", b"hello", true).unwrap());
        assert_ne!(a, Envelope::seal_deterministic(&k, "ops", b"hello").unwrap());
        assert_ne!(a, Envelope::seal_deterministic(&k, "team", b"hellp").unwrap());
        assert_ne!(a, Envelope::seal_deterministic(&random_key(), "team", b"hello").unwrap());
        assert_eq!(a.ciphertext.len(), SIV_LEN + 5);
        // Legacy is deterministic too, and differs.
        let l = Envelope::seal_deterministic_legacy(&k, "team", b"hello").unwrap();
        assert_eq!(l, Envelope::seal_deterministic_legacy(&k, "team", b"hello").unwrap());
        assert_ne!(l.ciphertext, a.ciphertext);
        // Random sealing is not.
        assert_ne!(
            Envelope::seal_random(&k, "team", b"hello").unwrap(),
            Envelope::seal_random(&k, "team", b"hello").unwrap()
        );
    }

    #[test]
    fn aes_siv_has_no_json_form_and_json_is_unchanged() {
        let k = [7u8; 32];
        let siv = Envelope::seal_deterministic(&k, "team", b"x").unwrap();
        assert!(serde_json::to_string(&siv).is_err());
        let e = Envelope {
            scope: "s".into(),
            suite: Suite::XChaCha20Poly1305 { nonce: [1; 24] },
            ciphertext: vec![2, 3],
        };
        let j = serde_json::to_string(&e).unwrap();
        assert_eq!(
            j,
            r#"{"scope":"s","nonce":"010101010101010101010101010101010101010101010101","ciphertext":"0203"}"#
        );
        assert_eq!(serde_json::from_str::<Envelope>(&j).unwrap(), e);
    }

    #[test]
    fn truncated_encodings_are_corrupt() {
        assert!(Envelope::from_bytes(&[0, 1, b'a']).is_err());
        assert!(Envelope::from_bytes_aes_siv(&[0, 1, b'a', 0, 0]).is_err());
        assert!(Envelope::from_bytes_aes_siv(&[0, 9]).is_err());
        let mut ok = vec![0, 1, b'a'];
        ok.extend([0u8; SIV_LEN]);
        assert!(Envelope::from_bytes_aes_siv(&ok).is_ok());
    }

    /// Known answers for the exact construction Veil writes (HKDF-SHA256 →
    /// AES-SIV-512, label as the only associated-data component). Pinned:
    /// if this changes, sealed objects change ids.
    #[test]
    fn veil_aes_siv_known_answer() {
        let e = Envelope::seal_deterministic(&[0x42; 32], "team#0011223344556677", b"veil:blob\nhello\n").unwrap();
        assert_eq!(hex::encode(&e.ciphertext), "75c44b40cd2b1985f731da44dda8c528217c5e91114c1a0f5be29973a65e578b");
    }

    // ---- RFC known-answer tests of the primitives ----------------------------

    /// RFC 5297 Appendix A.1 (deterministic) and A.2 (nonce-based), run
    /// through the `aes-siv` crate's CMAC-SIV with AES-128 (the RFC's
    /// vectors use a 256-bit key; Veil uses the same generic code with
    /// AES-256 and a 512-bit key, checked by the next test).
    #[test]
    fn rfc5297_known_answers() {
        use aes_siv::siv::Aes128Siv;
        let h = |s: &str| hex::decode(s.replace(' ', "")).unwrap();
        let key: [u8; 32] = h("fffefdfc fbfaf9f8 f7f6f5f4 f3f2f1f0 f0f1f2f3 f4f5f6f7 f8f9fafb fcfdfeff")
            .try_into()
            .unwrap();
        let ad = h("10111213 14151617 18191a1b 1c1d1e1f 20212223 24252627");
        let pt = h("11223344 55667788 99aabbcc ddee");
        let out = Aes128Siv::new(&key.into()).encrypt([&ad], &pt).unwrap();
        assert_eq!(
            hex::encode(&out),
            "85632d07c6e8f37f950acd320a2ecc93".to_owned() + "40c02b9690c4dc04daef7f6afe5c"
        );
        assert_eq!(Aes128Siv::new(&key.into()).decrypt([&ad], &out).unwrap(), pt);

        let key: [u8; 32] = h("7f7e7d7c 7b7a7978 77767574 73727170 40414243 44454647 48494a4b 4c4d4e4f")
            .try_into()
            .unwrap();
        let ad1 = h("00112233 44556677 8899aabb ccddeeff deaddada deaddada ffeeddcc bbaa9988 77665544 33221100");
        let ad2 = h("10203040 50607080 90a0");
        let nonce = h("09f91102 9d74e35b d84156c5 635688c0");
        let pt = h("74686973 20697320 736f6d65 20706c61 696e7465 78742074 6f20656e 63727970 74207573 696e6720 5349562d 414553");
        let out = Aes128Siv::new(&key.into())
            .encrypt([&ad1, &ad2, &nonce], &pt)
            .unwrap();
        assert_eq!(
            hex::encode(&out),
            "7bdb6e3b432667eb06f4d14bff2fbd0f".to_owned()
                + "cb900f2fddbe404326601965c889bf17dba77ceb094fa663b7a3f748ba8af829ea64ad544a272e9c485b62a3fd5c0d"
        );
    }

    /// AES-CMAC-SIV with a 512-bit key (what Veil uses), from the vectors
    /// shipped with the RustCrypto `aes-siv` crate (Miscreant's set).
    #[test]
    fn aes_siv_512_known_answer() {
        let h = |s: &str| hex::decode(s).unwrap();
        let key: [u8; 64] = h("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f06f6e6d6c6b6a69686766656463626160f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f")
            .try_into()
            .unwrap();
        let out = Aes256Siv::new(&key.into())
            .encrypt([h("101112131415161718191a1b1c1d1e1f2021222324252627")], &h("112233445566778899aabbccddee"))
            .unwrap();
        assert_eq!(hex::encode(out), "f125274c598065cfc26b0e71575029088b035217e380cac8919ee800c126");
    }

    /// RFC 5869 Appendix A.1 (HKDF-SHA256), the KDF in front of AES-SIV.
    #[test]
    fn rfc5869_known_answer() {
        let h = |s: &str| hex::decode(s).unwrap();
        let mut okm = [0u8; 42];
        hkdf::Hkdf::<sha2::Sha256>::new(Some(&h("000102030405060708090a0b0c")), &h("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"))
            .expand(&h("f0f1f2f3f4f5f6f7f8f9"), &mut okm)
            .unwrap();
        assert_eq!(
            hex::encode(okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }
}
