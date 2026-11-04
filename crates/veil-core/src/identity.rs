//! Public-key identities, key wrapping and signatures.
//!
//! Each person or agent has two keypairs:
//!
//! * an **X25519** keypair for *receiving* scope keys. Scope keys are
//!   wrapped to it with **HPKE** (RFC 9180, base mode,
//!   DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305) in
//!   repository format 3 and later. Formats 1–2 used a homemade sealed box
//!   (ephemeral X25519 → BLAKE3 KDF → XChaCha20-Poly1305), which is still
//!   read, and still written into format-1/2 repositories so older vl can
//!   read their rings. Wrapped keys are safe to publish, so key rings travel
//!   with the repository;
//! * an **Ed25519** signing keypair. Identities created by this release
//!   have an **independent** random signing seed. Identities created
//!   earlier derive it from the X25519 secret
//!   (`BLAKE3-derive(LEGACY_ED25519_SEED, secret)`); they keep working
//!   unchanged, and [`Identity::signing_key_is_derived`] flags them.
//!
//! The *member id* of an identity is `veil1<x25519-hex>` (64 hex digits, the
//! historical public key form). The *full public identity* appends the
//! Ed25519 verifying key: `veil1<x25519-hex><ed25519-hex>` (128 hex digits).
//! Only the full form lets a key ring bind a member to a signing key, so it is
//! what `vl identity show` prints. The format is the same whether the signing
//! key is independent or derived: a verifier cannot (and need not) tell.

use std::fmt;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use hpke::{Deserializable as _, Serializable as _};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::{
    crypto::{domains, random_bytes, Envelope, Key},
    error::{Result, VeilError},
};

type HpkeKem = hpke::kem::X25519HkdfSha256;
type HpkeKdf = hpke::kdf::HkdfSha256;
type HpkeAead = hpke::aead::ChaCha20Poly1305;

/// The HPKE ciphersuite of a wrapped key: mode, KEM, KDF, AEAD (RFC 9180
/// identifiers 0x00, 0x0020, 0x0001, 0x0003). Any other value is refused.
pub const HPKE_SUITE: &str = "base/x25519-hkdf-sha256/hkdf-sha256/chacha20poly1305";

/// Newest identity file format this build reads.
pub const IDENTITY_FORMAT: u32 = 2;

#[derive(Clone)]
enum SigningSeed {
    /// Legacy: derived from the X25519 secret.
    Derived,
    /// Independent random Ed25519 seed.
    Independent(Zeroizing<[u8; 32]>),
}

#[derive(Clone)]
pub struct Identity {
    pub name: String,
    /// X25519 secret (encryption / key wrapping).
    secret: Zeroizing<[u8; 32]>,
    signing: SigningSeed,
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Identity({}, {})", self.name, &self.public_hex()[..12])
    }
}

/// `identity.json`. Two shapes:
///
/// * legacy (no `format`): `{name, public, secret, signing?}`, the signing
///   key derived from `secret`. Rewritten in the same shape.
/// * format 2: `{format: 2, name, public, signing, encryption_secret,
///   signing_secret}`. It has no `secret` field on purpose: an older vl
///   refuses the file instead of deriving a signing key the rings do not
///   know.
#[derive(Serialize, Deserialize)]
struct IdentityFile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    format: Option<u32>,
    name: String,
    public: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    secret: Option<String>,
    /// The Ed25519 verifying key (checked on load for format 2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signing: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    encryption_secret: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signing_secret: Option<String>,
}

impl Drop for IdentityFile {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        for s in [&mut self.secret, &mut self.encryption_secret, &mut self.signing_secret]
            .into_iter()
            .flatten()
        {
            s.zeroize();
        }
    }
}

// ---- wrapped keys ------------------------------------------------------------

/// A scope key wrapped to one recipient with HPKE (format 3+).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HpkeWrappedKey {
    /// Ciphersuite, always [`HPKE_SUITE`].
    pub hpke: String,
    /// The encapsulated key (the sender's ephemeral X25519 public key), hex.
    pub enc: String,
    /// HPKE ciphertext of the 32-byte key, with its 16-byte tag, hex.
    pub ct: String,
}

/// A scope key in the legacy sealed box (formats 1–2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyWrappedKey {
    pub ephemeral: String,
    pub sealed: Envelope,
}

/// A scope key encrypted to one recipient. The JSON shapes differ (HPKE:
/// `{hpke, enc, ct}`; legacy: `{ephemeral, sealed}`), and the legacy shape
/// is exactly what formats 1–2 wrote (it is inside signed ring changes).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum WrappedKey {
    Hpke(HpkeWrappedKey),
    Legacy(LegacyWrappedKey),
}

impl WrappedKey {
    pub fn is_hpke(&self) -> bool {
        matches!(self, WrappedKey::Hpke(_))
    }
}

fn legacy_kek(shared: &[u8; 32], eph: &[u8; 32], recipient: &[u8; 32]) -> Zeroizing<Key> {
    let mut material = Zeroizing::new(Vec::with_capacity(96));
    material.extend_from_slice(shared);
    material.extend_from_slice(eph);
    material.extend_from_slice(recipient);
    Zeroizing::new(blake3::derive_key(domains::LEGACY_KEY_WRAP, &material))
}

fn wrap_label(scope: &str) -> String {
    format!("{}{scope}", domains::WRAP_LABEL_PREFIX)
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

/// Encrypt `key` so only the holder of `recipient`'s X25519 secret can
/// recover it, bound to `scope`: HPKE base mode, `info` =
/// [`domains::HPKE_KEY_WRAP_INFO`], associated data `wrap:<scope>`. What
/// repository format 3 writes.
pub fn wrap_key(recipient: &[u8; 32], key: &Key, scope: &str) -> Result<WrappedKey> {
    wrap_key_with_rng(
        recipient,
        key,
        scope,
        &mut hpke::rand_core::UnwrapErr(getrandom::SysRng),
    )
}

/// [`wrap_key`] with an explicit RNG (known-answer tests).
pub fn wrap_key_with_rng(
    recipient: &[u8; 32],
    key: &Key,
    scope: &str,
    rng: &mut impl hpke::rand_core::CryptoRng,
) -> Result<WrappedKey> {
    let fail = || VeilError::Crypto("cannot wrap a key to this public key".into());
    let pk = <HpkeKem as hpke::Kem>::PublicKey::from_bytes(recipient).map_err(|_| fail())?;
    let (enc, ct) = hpke::single_shot_seal_with_rng::<HpkeAead, HpkeKdf, HpkeKem>(
        &hpke::OpModeS::Base,
        &pk,
        domains::HPKE_KEY_WRAP_INFO.as_bytes(),
        key,
        wrap_label(scope).as_bytes(),
        rng,
    )
    .map_err(|_| fail())?;
    Ok(WrappedKey::Hpke(HpkeWrappedKey {
        hpke: HPKE_SUITE.to_string(),
        enc: hex::encode(enc.to_bytes()),
        ct: hex::encode(ct),
    }))
}

/// **Legacy** (formats 1–2): the homemade sealed box. Written only into
/// repositories still at format 1 or 2, whose rings older vl must read.
///
/// A low-order recipient key would make the shared secret all zeros and
/// the wrapped key readable by anyone (BUG-010), so it is refused, as HPKE
/// refuses it.
pub fn wrap_key_legacy(recipient: &[u8; 32], key: &Key, scope: &str) -> Result<WrappedKey> {
    let eph = StaticSecret::from(random_bytes::<32>());
    let eph_pub = PublicKey::from(&eph).to_bytes();
    let shared = eph.diffie_hellman(&PublicKey::from(*recipient));
    if !shared.was_contributory() {
        return Err(VeilError::Crypto("cannot wrap a key to this public key".into()));
    }
    let k = legacy_kek(shared.as_bytes(), &eph_pub, recipient);
    Ok(WrappedKey::Legacy(LegacyWrappedKey {
        ephemeral: hex::encode(eph_pub),
        sealed: Envelope::seal_random(&k, &wrap_label(scope), key)?,
    }))
}

/// The message actually signed: a domain-separated context plus the payload.
fn signed_message(context: &str, msg: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(domains::SIG_PREFIX.len() + context.len() + 1 + msg.len());
    m.extend_from_slice(domains::SIG_PREFIX);
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

fn parse_secret(hex_str: &str) -> Result<Zeroizing<[u8; 32]>> {
    Ok(Zeroizing::new(crate::crypto::parse_key_hex(hex_str)?))
}

impl Identity {
    /// A new identity with independent encryption and signing keys.
    pub fn generate(name: &str) -> Identity {
        Identity {
            name: name.to_string(),
            secret: Zeroizing::new(random_bytes()),
            signing: SigningSeed::Independent(Zeroizing::new(random_bytes())),
        }
    }

    fn x25519_secret(&self) -> StaticSecret {
        StaticSecret::from(*self.secret)
    }

    fn signing_key(&self) -> SigningKey {
        match &self.signing {
            SigningSeed::Independent(seed) => SigningKey::from_bytes(seed),
            SigningSeed::Derived => {
                let seed = Zeroizing::new(blake3::derive_key(domains::LEGACY_ED25519_SEED, &*self.secret));
                SigningKey::from_bytes(&seed)
            }
        }
    }

    /// Legacy identity: the signing key is derived from the X25519 secret
    /// (identities created before format 3). Such an identity works
    /// everywhere; replacing it (`vl identity new`) gives independent keys.
    pub fn signing_key_is_derived(&self) -> bool {
        matches!(self.signing, SigningSeed::Derived)
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

    /// Recover a scope key wrapped to this identity for `scope` (either
    /// construction).
    pub fn unwrap_key(&self, w: &WrappedKey, scope: &str) -> Result<Key> {
        let raw = match w {
            WrappedKey::Hpke(h) => Zeroizing::new(self.unwrap_hpke(h, scope)?),
            WrappedKey::Legacy(l) => {
                if l.sealed.scope != wrap_label(scope) {
                    return Err(VeilError::Crypto("wrapped key belongs to a different scope".into()));
                }
                let eph: [u8; 32] = parse_public_key(&l.ephemeral)?;
                let shared = self.x25519_secret().diffie_hellman(&PublicKey::from(eph));
                let k = legacy_kek(shared.as_bytes(), &eph, &self.public_key());
                Zeroizing::new(l.sealed.open(&k)?)
            }
        };
        raw.as_slice()
            .try_into()
            .map_err(|_| VeilError::Crypto("wrapped key has the wrong size".into()))
    }

    fn unwrap_hpke(&self, h: &HpkeWrappedKey, scope: &str) -> Result<Vec<u8>> {
        let fail = || VeilError::Crypto("wrapped key does not open with this identity for this scope".into());
        if h.hpke != HPKE_SUITE {
            return Err(VeilError::Unsupported(format!(
                "wrapped key uses HPKE suite '{}', which vl {} does not know",
                h.hpke,
                env!("CARGO_PKG_VERSION")
            )));
        }
        let enc = hex::decode(&h.enc).map_err(|_| fail())?;
        let enc = <HpkeKem as hpke::Kem>::EncappedKey::from_bytes(&enc).map_err(|_| fail())?;
        let ct = hex::decode(&h.ct).map_err(|_| fail())?;
        let sk = <HpkeKem as hpke::Kem>::PrivateKey::from_bytes(&*self.secret).map_err(|_| fail())?;
        hpke::single_shot_open::<HpkeAead, HpkeKdf, HpkeKem>(
            &hpke::OpModeR::Base,
            &sk,
            &enc,
            domains::HPKE_KEY_WRAP_INFO.as_bytes(),
            &ct,
            wrap_label(scope).as_bytes(),
        )
        .map_err(|_| fail())
    }

    /// Per-repository key that never leaves this device. Protects the local
    /// vault (isolated files and `vl secret` values).
    pub fn local_key(&self, repo_id: &str) -> Key {
        let mut material = Zeroizing::new(self.secret.to_vec());
        material.extend_from_slice(repo_id.as_bytes());
        blake3::derive_key(domains::LOCAL_VAULT_KEY, &material)
    }

    pub fn to_json(&self) -> String {
        let file = match &self.signing {
            SigningSeed::Derived => IdentityFile {
                format: None,
                name: self.name.clone(),
                public: self.public_hex(),
                secret: Some(hex::encode(*self.secret)),
                signing: Some(self.verifying_hex()),
                encryption_secret: None,
                signing_secret: None,
            },
            SigningSeed::Independent(seed) => IdentityFile {
                format: Some(IDENTITY_FORMAT),
                name: self.name.clone(),
                public: self.public_hex(),
                secret: None,
                signing: Some(self.verifying_hex()),
                encryption_secret: Some(hex::encode(*self.secret)),
                signing_secret: Some(hex::encode(**seed)),
            },
        };
        serde_json::to_string_pretty(&file).unwrap()
    }

    pub fn from_json(s: &str) -> Result<Identity> {
        let f: IdentityFile = serde_json::from_str(s)?;
        let bad = |m: &str| VeilError::Crypto(format!("identity file: {m}"));
        match f.format {
            None | Some(1) => {
                let (Some(secret), None, None) = (&f.secret, &f.encryption_secret, &f.signing_secret) else {
                    return Err(bad("a legacy identity has exactly one secret"));
                };
                Ok(Identity {
                    name: f.name.clone(),
                    secret: parse_secret(secret)?,
                    signing: SigningSeed::Derived,
                })
            }
            Some(2) => {
                let (None, Some(enc), Some(sig)) = (&f.secret, &f.encryption_secret, &f.signing_secret) else {
                    return Err(bad("expected an encryption secret and a signing secret"));
                };
                let id = Identity {
                    name: f.name.clone(),
                    secret: parse_secret(enc)?,
                    signing: SigningSeed::Independent(parse_secret(sig)?),
                };
                if id.public_hex() != f.public || f.signing.as_deref().is_some_and(|s| s != id.verifying_hex()) {
                    return Err(bad("the public keys do not match the secrets (damaged file?)"));
                }
                Ok(id)
            }
            Some(n) => Err(VeilError::Unsupported(format!(
                "identity file format {n} needs a newer vl (this is vl {}, which reads formats up to {IDENTITY_FORMAT})",
                env!("CARGO_PKG_VERSION")
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hpke::Kem as _;

    const LEGACY: &str = r#"{"name":"old","public":"veil1ab","secret":"0101010101010101010101010101010101010101010101010101010101010101"}"#;

    #[test]
    fn wrap_unwrap_both_constructions() {
        let alice = Identity::generate("alice");
        let bob = Identity::generate("bob");
        let key = crate::crypto::random_key();
        for w in [
            wrap_key(&alice.public_key(), &key, "team").unwrap(),
            wrap_key_legacy(&alice.public_key(), &key, "team").unwrap(),
        ] {
            assert_eq!(alice.unwrap_key(&w, "team").unwrap(), key);
            assert!(bob.unwrap_key(&w, "team").is_err(), "wrong recipient");
            assert!(alice.unwrap_key(&w, "ops").is_err(), "scope is bound");
            let json = serde_json::to_string(&w).unwrap();
            assert_eq!(serde_json::from_str::<WrappedKey>(&json).unwrap(), w);
        }
        let back = Identity::from_json(&alice.to_json()).unwrap();
        assert_eq!(back.public_key(), alice.public_key());
        assert_eq!(back.verifying_key(), alice.verifying_key());
    }

    #[test]
    fn hpke_wraps_reject_tampering() {
        let alice = Identity::generate("alice");
        let key = crate::crypto::random_key();
        let WrappedKey::Hpke(h) = wrap_key(&alice.public_key(), &key, "team").unwrap() else { panic!() };
        assert_eq!(h.hpke, HPKE_SUITE);
        assert_eq!(h.enc.len(), 64);
        assert_eq!(h.ct.len(), 2 * (32 + 16));
        let flip = |s: &str, i: usize| {
            let mut b = hex::decode(s).unwrap();
            b[i] ^= 1;
            hex::encode(b)
        };
        let variants = [
            HpkeWrappedKey { enc: flip(&h.enc, 0), ..h.clone() },
            HpkeWrappedKey { enc: flip(&h.enc, 31), ..h.clone() },
            HpkeWrappedKey { ct: flip(&h.ct, 0), ..h.clone() },
            HpkeWrappedKey { ct: flip(&h.ct, 47), ..h.clone() },
            HpkeWrappedKey { ct: h.ct[..h.ct.len() - 2].to_string(), ..h.clone() },
            HpkeWrappedKey { enc: "00".repeat(32), ..h.clone() },
            HpkeWrappedKey { enc: "zz".into(), ..h.clone() },
        ];
        for v in variants {
            assert!(alice.unwrap_key(&WrappedKey::Hpke(v.clone()), "team").is_err(), "{v:?}");
        }
        let other = HpkeWrappedKey {
            hpke: "base/x25519-hkdf-sha256/hkdf-sha256/aes-128-gcm".into(),
            ..h.clone()
        };
        assert!(matches!(
            alice.unwrap_key(&WrappedKey::Hpke(other), "team"),
            Err(VeilError::Unsupported(_))
        ));
        // Unknown fields are refused (no ignorable fields), and an unknown
        // shape matches neither construction.
        let mut v = serde_json::to_value(WrappedKey::Hpke(h.clone())).unwrap();
        v["extra"] = 1.into();
        assert!(serde_json::from_value::<WrappedKey>(v).is_err());
        assert!(serde_json::from_str::<WrappedKey>(r#"{"enc":"00","ct":"00"}"#).is_err());
        assert_eq!(alice.unwrap_key(&WrappedKey::Hpke(h), "team").unwrap(), key);
    }

    #[test]
    fn hpke_refuses_low_order_recipients() {
        // The all-zero point (and other low-order points) make the DH
        // output zero; RFC 9180 requires the sender to abort.
        let mut one = [0u8; 32];
        one[0] = 1;
        for low in [[0u8; 32], one] {
            assert!(wrap_key(&low, &[1; 32], "team").is_err());
            assert!(wrap_key_legacy(&low, &[1; 32], "team").is_err(), "BUG-010 in the legacy box");
        }
    }

    #[test]
    fn new_identities_have_independent_signing_keys() {
        let a = Identity::generate("a");
        assert!(!a.signing_key_is_derived());
        let derived = SigningKey::from_bytes(&blake3::derive_key(domains::LEGACY_ED25519_SEED, &*a.secret));
        assert_ne!(a.verifying_key(), derived.verifying_key().to_bytes());
        let json = a.to_json();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["format"], 2);
        assert!(v.get("secret").is_none(), "older vl must refuse the file: {json}");
        let back = Identity::from_json(&json).unwrap();
        assert!(!back.signing_key_is_derived());
        assert_eq!(back.public_id(), a.public_id());
        let sig = back.sign("ctx", b"m");
        assert!(verify_signature(&a.verifying_hex(), "ctx", b"m", &sig));
        // Damaged or newer files are refused.
        let mut bad = v.clone();
        bad["public"] = Identity::generate("x").public_hex().into();
        assert!(Identity::from_json(&bad.to_string()).is_err());
        let mut bad = v.clone();
        bad["signing"] = Identity::generate("x").verifying_hex().into();
        assert!(Identity::from_json(&bad.to_string()).is_err());
        let mut bad = v.clone();
        bad["secret"] = "01".repeat(32).into();
        assert!(Identity::from_json(&bad.to_string()).is_err());
        let mut newer = v.clone();
        newer["format"] = 3.into();
        assert!(matches!(Identity::from_json(&newer.to_string()), Err(VeilError::Unsupported(_))));
    }

    #[test]
    fn legacy_identity_files_load_and_gain_a_stable_signing_key() {
        // The format written before signatures existed: no `signing` field.
        let a = Identity::from_json(LEGACY).unwrap();
        let b = Identity::from_json(LEGACY).unwrap();
        assert!(a.signing_key_is_derived());
        assert_eq!(a.verifying_key(), b.verifying_key(), "deterministic derivation");
        assert_ne!(a.verifying_key(), a.public_key());
        // Pinned: legacy identities must keep their signing key forever.
        assert_eq!(
            a.verifying_hex(),
            hex::encode(
                SigningKey::from_bytes(&blake3::derive_key("veil 2026 ed25519-seed v1", &[1u8; 32]))
                    .verifying_key()
                    .to_bytes()
            )
        );
        let sig = a.sign("test", b"msg");
        assert!(verify_signature(&a.verifying_hex(), "test", b"msg", &sig));
        assert!(!verify_signature(&a.verifying_hex(), "other", b"msg", &sig), "context separates");
        assert!(!verify_signature(&a.verifying_hex(), "test", b"msg2", &sig));
        assert!(!verify_signature(&Identity::generate("x").verifying_hex(), "test", b"msg", &sig));
        assert!(!verify_signature("zz", "test", b"msg", &sig));
        // A legacy identity is written back in the legacy shape.
        let v: serde_json::Value = serde_json::from_str(&a.to_json()).unwrap();
        assert!(v.get("format").is_none() && v.get("secret").is_some(), "{v}");
        assert!(Identity::from_json(&a.to_json()).unwrap().signing_key_is_derived());
        // Both secrets in one legacy file is malformed.
        let mut both: serde_json::Value = serde_json::from_str(LEGACY).unwrap();
        both["signing_secret"] = "02".repeat(32).into();
        assert!(Identity::from_json(&both.to_string()).is_err());
    }

    #[test]
    fn public_identity_forms() {
        for a in [Identity::generate("a"), Identity::from_json(LEGACY).unwrap()] {
            let full = parse_public_identity(&a.public_id()).unwrap();
            assert_eq!(full.member_id(), a.public_hex());
            assert_eq!(full.ed25519, Some(a.verifying_key()));
            let short = parse_public_identity(&a.public_hex()).unwrap();
            assert_eq!(short.ed25519, None);
            assert_eq!(parse_public_key(&a.public_id()).unwrap(), a.public_key());
        }
        assert!(parse_public_identity("veil1abcd").is_err());
    }

    /// The HPKE secret key Veil derives from an identity is the X25519 key
    /// of its member id (both clamp the same 32 bytes).
    #[test]
    fn hpke_and_x25519_agree_on_the_public_key() {
        let a = Identity::generate("a");
        let sk = <HpkeKem as hpke::Kem>::PrivateKey::from_bytes(&*a.secret).unwrap();
        assert_eq!(&HpkeKem::sk_to_pk(&sk).to_bytes()[..], &a.public_key()[..]);
    }

    /// An RNG that replays fixed bytes (known-answer tests only).
    struct Replay(Vec<u8>);

    impl hpke::rand_core::TryRng for Replay {
        type Error = std::convert::Infallible;
        fn try_next_u32(&mut self) -> std::result::Result<u32, Self::Error> {
            unreachable!()
        }
        fn try_next_u64(&mut self) -> std::result::Result<u64, Self::Error> {
            unreachable!()
        }
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> std::result::Result<(), Self::Error> {
            assert!(dst.len() <= self.0.len(), "known-answer RNG exhausted");
            dst.copy_from_slice(&self.0[..dst.len()]);
            self.0.drain(..dst.len());
            Ok(())
        }
    }

    impl hpke::rand_core::TryCryptoRng for Replay {}

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    /// RFC 9180 Appendix A.2.1: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
    /// ChaCha20Poly1305, base mode — the exact suite Veil uses. Checks key
    /// derivation, encapsulation (with the RFC's ephemeral key) and the
    /// first encryption, in both directions.
    #[test]
    fn rfc9180_a2_known_answer() {
        let info = h("4f6465206f6e2061204772656369616e2055726e");
        let ikm_e = h("909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b");
        let ikm_r = h("1ac01f181fdf9f352797655161c58b75c656a6cc2716dcb66372da835542e1df");
        let (sk_r, pk_r) = HpkeKem::derive_keypair(&ikm_r);
        // The crate stores the clamped scalar; the RFC prints it unclamped.
        let sk_rfc = h("8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb");
        let sk_rfc = <HpkeKem as hpke::Kem>::PrivateKey::from_bytes(&sk_rfc).unwrap();
        assert_eq!(sk_r.to_bytes(), sk_rfc.to_bytes());
        assert_eq!(hex::encode(pk_r.to_bytes()), "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a");
        let pt = h("4265617574792069732074727574682c20747275746820626561757479");
        let aad = h("436f756e742d30");
        let ct = "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28";
        let (enc, sealed) = hpke::single_shot_seal_with_rng::<HpkeAead, HpkeKdf, HpkeKem>(
            &hpke::OpModeS::Base,
            &pk_r,
            &info,
            &pt,
            &aad,
            &mut Replay(ikm_e),
        )
        .unwrap();
        assert_eq!(hex::encode(enc.to_bytes()), "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a");
        assert_eq!(hex::encode(&sealed), ct);
        let opened = hpke::single_shot_open::<HpkeAead, HpkeKdf, HpkeKem>(
            &hpke::OpModeR::Base,
            &sk_r,
            &enc,
            &info,
            &h(ct),
            &aad,
        )
        .unwrap();
        assert_eq!(opened, pt);
    }

    /// Veil's own use of HPKE, pinned: recipient from the RFC's `skRm`, the
    /// RFC's ephemeral input, Veil's `info` and `wrap:<scope>` aad.
    #[test]
    fn veil_key_wrap_known_answer() {
        let recipient = Identity {
            name: "kat".into(),
            secret: Zeroizing::new(h("8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb").try_into().unwrap()),
            signing: SigningSeed::Derived,
        };
        let w = wrap_key_with_rng(
            &recipient.public_key(),
            &[0x42; 32],
            "team",
            &mut Replay(h("909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b")),
        )
        .unwrap();
        assert_eq!(recipient.unwrap_key(&w, "team").unwrap(), [0x42; 32]);
        assert_eq!(
            serde_json::to_string(&w).unwrap(),
            r#"{"hpke":"base/x25519-hkdf-sha256/hkdf-sha256/chacha20poly1305","enc":"1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a","ct":"0c9109f2e9e3c63c6bc011ab10f8d79b8cffc11244cdbfbc15d21dba690f6bf0ed721e37a0ce46f8ad7f426eba735607"}"#
        );
    }
}
