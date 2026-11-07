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

/// BLAKE3 `derive_key` context of the device-local team-vault history key,
/// over the local vault key (C8): a keyed BLAKE3 of each value a team vault
/// held, so going back to a value a revoked member read is still reported
/// (C12, BUG-521). Never stored or synced.
pub const TEAM_VAULT_HISTORY: &str = "veil 2026 team-vault history v1";

/// Prefix of every Ed25519-signed message: `SIG_PREFIX ‖ context ‖ 0x00 ‖
/// payload`, with `context` one of the `SIG_CONTEXT_*` values below.
pub const SIG_PREFIX: &[u8] = b"veil 2026 sig v1\0";

/// Signature context: snapshots (over the id of the unsigned encoding).
pub const SIG_CONTEXT_SNAPSHOT: &str = "snapshot";
/// Signature context: ring changes (over `RingChange::signing_body`).
pub const SIG_CONTEXT_RING_CHANGE: &str = "ring-change";
/// Retired signature context (signed embargo records, removed with
/// encrypted embargoes in repository format 8): reserved, never reused.
pub const SIG_CONTEXT_EMBARGO: &str = "embargo";
/// Retired signature context (embargo releases, removed in repository
/// format 8): reserved, never reused.
pub const SIG_CONTEXT_EMBARGO_RELEASE: &str = "embargo-release";
/// Signature context: an identity's binding of its Ed25519 key to its
/// X25519 key (over the 32 raw bytes of the X25519 public key). Proves that
/// whoever holds the signing key chose that encryption key (BUG-069).
pub const SIG_CONTEXT_MEMBER_BINDING: &str = "member-binding";
/// Signature context: a team-vault write (over `team_vault::RecordBody`):
/// a member of the scope set or deleted one entry.
pub const SIG_CONTEXT_VAULT_ENTRY: &str = "vault-entry";
/// Signature context: an annotated tag (`veil:atag`, repository format 5),
/// over the id of its encoding without `signature` (`Atag::unsigned_id`):
/// name, target, kind, message, tagger and time.
pub const SIG_CONTEXT_TAG: &str = "tag";
/// Signature context: signing in to a Veil server (`docs/HUB.md` §4.3),
/// over `hub ‖ 0x00 ‖ challenge` (the server's name as the client dialled
/// it, and the single-use random challenge it issued).
pub const SIG_CONTEXT_HUB_LOGIN: &str = "hub-login";
/// Signature context: one device's vouch that another device is its
/// person's too (`docs/HUB.md` §13.11), over the vouched device's X25519
/// ‖ Ed25519 public keys (`hub::wire::vouch_message`).
pub const SIG_CONTEXT_HUB_DEVICE: &str = "hub-device";
/// Signature context: a join under an invite (`docs/HUB.md` §13.12), by
/// the invite's key, over `person ‖ 0x00 ‖ X25519 ‖ Ed25519` of the
/// joining device (`hub::wire::join_message`).
pub const SIG_CONTEXT_HUB_INVITE: &str = "hub-invite";

/// Every signature context, for the uniqueness test.
pub const SIG_CONTEXTS: &[&str] = &[
    SIG_CONTEXT_SNAPSHOT,
    SIG_CONTEXT_RING_CHANGE,
    SIG_CONTEXT_EMBARGO,
    SIG_CONTEXT_EMBARGO_RELEASE,
    SIG_CONTEXT_MEMBER_BINDING,
    SIG_CONTEXT_VAULT_ENTRY,
    SIG_CONTEXT_TAG,
    SIG_CONTEXT_HUB_LOGIN,
    SIG_CONTEXT_HUB_DEVICE,
    SIG_CONTEXT_HUB_INVITE,
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
/// Retired label (`embargo-wrap:<id>`, embargo keys, removed in repository
/// format 8): reserved, never reused.
pub const EMBARGO_WRAP_LABEL_PREFIX: &str = "embargo-wrap:";
/// Retired label (`embargo/<id>`, content sealed under an embargo key,
/// removed in repository format 8): reserved, never reused.
pub const EMBARGO_LABEL_PREFIX: &str = "embargo/";
/// `vault:<scope>#<key-id>`: a team-vault entry (name and value) sealed
/// under a scope generation key (XChaCha20-Poly1305, random nonce). The
/// prefix keeps it apart from sealed secret files, which use the bare
/// `<scope>#<key-id>` label under the same key.
pub const VAULT_LABEL_PREFIX: &str = "vault:";
/// `local`: the device-local vault and isolated files.
pub const LOCAL_LABEL: &str = "local";
/// Separator of `<scope>#<key-id>` generation labels.
pub const GENERATION_SEPARATOR: char = '#';

/// BLAKE3 `derive_key` context of a Veil server's view key: the hash of the
/// paths one viewer may read under the accepted policy, under which the
/// server caches that viewer's projections (`hub::access::View::key`). Not
/// secret; equal for two viewers who read the same paths.
pub const HUB_VIEW_KEY: &str = "veil 2026 hub view-key v1";

/// BLAKE3 `derive_key` context of a device's fingerprint, over its Ed25519
/// ‖ X25519 public keys (first 10 bytes, shown as `4F2A-9C1E-…`): what an
/// admin compares with a person out of band before their device receives
/// a secret key (`docs/HUB.md` §13.11). Not secret.
pub const HUB_DEVICE_FINGERPRINT: &str = "veil 2026 hub device-fingerprint v1";

/// BLAKE3 `derive_key` context of a Veil server's upload-receipt MAC key,
/// from the server's random receipt secret: a receipt (keyed BLAKE3 over
/// project ‖ person ‖ object id, first 16 bytes) proves to the server that
/// this person uploaded that object, so a push may name it (BUG-824).
pub const HUB_UPLOAD_RECEIPT: &str = "veil 2026 hub upload-receipt v1";

/// BLAKE3 `derive_key` context of an invite's Ed25519 seed, from the 32
/// random bytes only the invite link holds (`hub::wire::InviteKey`). The
/// public half goes to the server and into the key rings; the secret never
/// leaves the admin's device and the link.
pub const HUB_INVITE_KEY: &str = "veil 2026 hub invite-key v1";

/// BLAKE3 `derive_key` context of a project's fingerprint, over its id (the
/// hash of its `team` key ring's genesis; first 10 bytes, shown as
/// `4F2A-9C1E-…`): what an invite link carries and what a person compares
/// before a device trusts the project's key rings (`docs/HUB.md` §13.12,
/// BUG-845). Not secret.
pub const HUB_PROJECT_FINGERPRINT: &str = "veil 2026 hub project-fingerprint v1";

/// BLAKE3 `derive_key` context of the scope name of an access line's
/// secrets (`policy::rule_scope`): `rule-` and the first 10 bytes (hex)
/// over the line's path. Not secret.
pub const POLICY_RULE_SCOPE: &str = "veil 2026 policy rule-scope v1";

/// Every BLAKE3 `derive_key` context, for the uniqueness test.
pub const BLAKE3_CONTEXTS: &[&str] = &[
    LEGACY_SIV_NONCE,
    LEGACY_KEY_WRAP,
    LEGACY_ED25519_SEED,
    LOCAL_VAULT_KEY,
    KEY_FINGERPRINT,
    RING_CHANGE_HASH,
    RING_PROOF,
    TEAM_VAULT_HISTORY,
    HUB_VIEW_KEY,
    HUB_DEVICE_FINGERPRINT,
    HUB_UPLOAD_RECEIPT,
    HUB_INVITE_KEY,
    POLICY_RULE_SCOPE,
    HUB_PROJECT_FINGERPRINT,
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
        // Contexts added after the first seven are pinned on their own.
        assert_eq!(
            BLAKE3_CONTEXTS[7..],
            [
                "veil 2026 team-vault history v1",
                "veil 2026 hub view-key v1",
                "veil 2026 hub device-fingerprint v1",
                "veil 2026 hub upload-receipt v1",
                "veil 2026 hub invite-key v1",
                "veil 2026 policy rule-scope v1",
                "veil 2026 hub project-fingerprint v1"
            ],
            "a context changed or was reordered"
        );
        let mut all: Vec<&str> = BLAKE3_CONTEXTS[..7].to_vec();
        all.extend([AES_SIV_SUBKEY, HPKE_KEY_WRAP_INFO]);
        // Pinned: these strings are part of data already on disk.
        let pinned = blake3::hash(all.join("\n").as_bytes()).to_hex().to_string();
        assert_eq!(
            &pinned[..16],
            "33c7c64265e3b514",
            "a domain-separation string changed; that breaks existing data. Add a new constant instead."
        );
        let contexts: std::collections::BTreeSet<&str> = SIG_CONTEXTS.iter().copied().collect();
        assert_eq!(contexts.len(), SIG_CONTEXTS.len(), "duplicate signature context");
        assert!(SIG_CONTEXTS.iter().all(|c| !c.contains('\0')));
        // The first five contexts are pinned as they were before the team
        // vault added `vault-entry`; each later one is pinned on its own.
        assert_eq!(
            &blake3::hash(SIG_CONTEXTS[..5].join("\n").as_bytes()).to_hex()[..16],
            "028e842fb2475981",
            "a signature context changed; that breaks existing signatures. Add a new constant instead."
        );
        assert_eq!(SIG_CONTEXTS[5..], ["vault-entry", "tag", "hub-login", "hub-device", "hub-invite"], "a signature context changed or was reordered");
        let labels = [
            WRAP_LABEL_PREFIX,
            PREV_KEY_LABEL_PREFIX,
            EMBARGO_WRAP_LABEL_PREFIX,
            EMBARGO_LABEL_PREFIX,
            VAULT_LABEL_PREFIX,
        ];
        for (i, a) in labels.iter().enumerate() {
            for b in &labels[i + 1..] {
                assert!(!a.starts_with(b) && !b.starts_with(a), "{a} / {b} overlap");
            }
        }
    }
}
