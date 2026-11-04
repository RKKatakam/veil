//! Every domain-separation string Veil feeds to a cryptographic function.
//!
//! This module is the single list a reviewer has to audit: no other file
//! may spell a KDF context, MAC key context, HPKE `info`, signature prefix
//! or associated-data label prefix. `docs/CRYPTO.md` has the same table with
//! the construction, inputs, goal and limits of each.
//!
//! **Never change a value.** Each one is baked into data that is already on
//! disk (object ids, signatures, ring chain hashes, wrapped keys). A new
//! construction gets a new constant with a new version suffix, and readers
//! keep the old one (see `docs/FORMAT.md`).
//!
//! Naming: `"veil 2026 <purpose> v<N>"`, the BLAKE3 `derive_key`
//! recommendation (globally unique, application + date + purpose). BLAKE3
//! contexts are used with `blake3::derive_key` / `Hasher::new_derive_key`
//! only; keyed BLAKE3 (`new_keyed`) is always keyed with a key *derived*
//! under one of these contexts, never with a raw scope key.

// ---- symmetric sealing (crypto.rs) ----------------------------------------

/// HKDF-SHA256 `info` deriving the 64-byte AES-SIV key (CMAC-AES-256 ‖
/// CTR-AES-256) of a sealed object from its 32-byte scope key. Format 3+.
pub const AES_SIV_SUBKEY: &str = "veil 2026 sealed-object aes-siv-cmac-512 v1";

/// **Legacy (formats 1–2).** BLAKE3 `derive_key` context for the key of the
/// keyed-BLAKE3 hash that chose the XChaCha20-Poly1305 nonce of a
/// deterministic envelope. Still written by format-1/2 repositories (so
/// older vl can read them) and never by format 3.
pub const LEGACY_SIV_NONCE: &str = "veil 2026 siv-nonce v1";

// ---- key wrapping to a recipient (identity.rs) ----------------------------

/// HPKE (RFC 9180) `info` for wrapping a scope key to a member. Format 3+.
/// The scope travels as HPKE associated data (see [`WRAP_LABEL_PREFIX`]).
pub const HPKE_KEY_WRAP_INFO: &str = "veil 2026 key-wrap hpke v1";

/// **Legacy (formats 1–2).** BLAKE3 `derive_key` context of the homemade
/// sealed box (ephemeral X25519 → BLAKE3 KDF over `shared ‖ eph_pk ‖
/// recipient_pk` → XChaCha20-Poly1305). Still read; written only by
/// format-1/2 repositories.
pub const LEGACY_KEY_WRAP: &str = "veil 2026 key-wrap v1";

// ---- identities (identity.rs) ---------------------------------------------

/// **Legacy identities only.** BLAKE3 `derive_key` context deriving the
/// Ed25519 seed from the X25519 secret. Identities created since format 3
/// have an independent random signing seed.
pub const LEGACY_ED25519_SEED: &str = "veil 2026 ed25519-seed v1";

/// BLAKE3 `derive_key` context of the device-local vault key, over
/// `x25519_secret ‖ repo_id`.
pub const LOCAL_VAULT_KEY: &str = "veil 2026 local-vault v1";

/// Prefix of every Ed25519-signed message: `SIG_PREFIX ‖ context ‖ 0x00 ‖
/// payload`, with `context` one of the `SIG_CONTEXT_*` values below.
pub const SIG_PREFIX: &[u8] = b"veil 2026 sig v1\0";

/// Signature context: snapshots (over the id of the unsigned encoding).
pub const SIG_CONTEXT_SNAPSHOT: &str = "snapshot";
/// Signature context: ring changes (over `RingChange::signing_body`).
pub const SIG_CONTEXT_RING_CHANGE: &str = "ring-change";
/// Signature context: embargo creation (over `EmbargoRecord::body`).
pub const SIG_CONTEXT_EMBARGO: &str = "embargo";
/// Signature context: embargo release (over `(id, released_key, released_at)`).
pub const SIG_CONTEXT_EMBARGO_RELEASE: &str = "embargo-release";
/// Signature context: an identity's binding of its Ed25519 key to its
/// X25519 key (over the 32 raw bytes of the X25519 public key). Proves that
/// whoever holds the signing key chose that encryption key (BUG-069).
pub const SIG_CONTEXT_MEMBER_BINDING: &str = "member-binding";

/// Every signature context, for the uniqueness test.
pub const SIG_CONTEXTS: &[&str] = &[
    SIG_CONTEXT_SNAPSHOT,
    SIG_CONTEXT_RING_CHANGE,
    SIG_CONTEXT_EMBARGO,
    SIG_CONTEXT_EMBARGO_RELEASE,
    SIG_CONTEXT_MEMBER_BINDING,
];

// ---- key rings and embargoes (keychain.rs) --------------------------------

/// BLAKE3 `derive_key` context of a key's public fingerprint (first 8
/// bytes, hex) — the key id in `<scope>#<key-id>` labels.
pub const KEY_FINGERPRINT: &str = "veil 2026 key-fingerprint v1";

/// BLAKE3 `derive_key` context of a ring change's chain hash (over the
/// signed body and the signature; first 16 bytes, hex).
pub const RING_CHANGE_HASH: &str = "veil 2026 ring-change v1";

/// BLAKE3 `derive_key` context of the MAC key for a ring's genesis proof
/// (keyed BLAKE3 under `derive_key(RING_PROOF, generation-0 key)`).
pub const RING_PROOF: &str = "veil 2026 ring-proof v1";

// ---- associated-data labels (envelope `scope` field) ----------------------
//
// Every envelope authenticates its label as associated data. The label
// says which key opens it, and the prefixes keep the uses apart, so an
// envelope cannot be moved from one role to another under the same key.

/// `wrap:<scope>`: a scope key wrapped to a member (HPKE aad, or the label
/// of a legacy sealed box).
pub const WRAP_LABEL_PREFIX: &str = "wrap:";
/// `prev-key:<scope>#<new-key-id>`: an older generation key sealed under a
/// newer one (XChaCha20-Poly1305, random nonce).
pub const PREV_KEY_LABEL_PREFIX: &str = "prev-key:";
/// `embargo-wrap:<id>`: an embargo key sealed under a scope key
/// (XChaCha20-Poly1305, random nonce).
pub const EMBARGO_WRAP_LABEL_PREFIX: &str = "embargo-wrap:";
/// `embargo/<id>`: content sealed under an embargo key.
pub const EMBARGO_LABEL_PREFIX: &str = "embargo/";
/// `local`: the device-local vault and isolated files.
pub const LOCAL_LABEL: &str = "local";
/// Separator of `<scope>#<key-id>` generation labels.
pub const GENERATION_SEPARATOR: char = '#';

// ---- not secret, but derived ----------------------------------------------

/// BLAKE3 `derive_key` context mapping a Git commit id to a Veil change id
/// (Git bridge). Not a security boundary; listed for completeness.
pub const GIT_CHANGE_ID: &str = "veil 2026 git change-id v1";

/// Every BLAKE3 `derive_key` context, for the uniqueness test.
pub const BLAKE3_CONTEXTS: &[&str] = &[
    LEGACY_SIV_NONCE,
    LEGACY_KEY_WRAP,
    LEGACY_ED25519_SEED,
    LOCAL_VAULT_KEY,
    KEY_FINGERPRINT,
    RING_CHANGE_HASH,
    RING_PROOF,
    GIT_CHANGE_ID,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contexts_are_distinct_and_never_change() {
        let mut all: Vec<&str> = BLAKE3_CONTEXTS.to_vec();
        all.extend([AES_SIV_SUBKEY, HPKE_KEY_WRAP_INFO]);
        let unique: std::collections::BTreeSet<&str> = all.iter().copied().collect();
        assert_eq!(unique.len(), all.len(), "duplicate domain-separation string");
        // Pinned: these strings are part of data already on disk.
        let pinned = blake3::hash(all.join("\n").as_bytes()).to_hex().to_string();
        assert_eq!(
            &pinned[..16],
            "bdd6da15d799062f",
            "a domain-separation string changed; that breaks existing data. Add a new constant instead."
        );
        let contexts: std::collections::BTreeSet<&str> = SIG_CONTEXTS.iter().copied().collect();
        assert_eq!(contexts.len(), SIG_CONTEXTS.len(), "duplicate signature context");
        assert!(SIG_CONTEXTS.iter().all(|c| !c.contains('\0')));
        assert_eq!(
            &blake3::hash(SIG_CONTEXTS.join("\n").as_bytes()).to_hex()[..16],
            "028e842fb2475981",
            "a signature context changed; that breaks existing signatures. Add a new constant instead."
        );
        let labels = [
            WRAP_LABEL_PREFIX,
            PREV_KEY_LABEL_PREFIX,
            EMBARGO_WRAP_LABEL_PREFIX,
            EMBARGO_LABEL_PREFIX,
        ];
        for (i, a) in labels.iter().enumerate() {
            for b in &labels[i + 1..] {
                assert!(!a.starts_with(b) && !b.starts_with(a), "{a} / {b} overlap");
            }
        }
    }
}
