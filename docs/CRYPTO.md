# Veil cryptography, for review

This document lists every cryptographic construction in Veil: what it is,
the standard it follows, its inputs, what it is meant to guarantee and what
it does not. It is written for a security reviewer. The architecture is in
[ARCHITECTURE.md](ARCHITECTURE.md) (§2 store, §3 identities and rings, §7
embargoes, threat model), and the on-disk encodings are in
[FORMAT.md](FORMAT.md).

**What encryption is for.** Veil is server-centric
([OVERVIEW.md](OVERVIEW.md)): code is plain text on the Veil server, which
enforces who can see what ([VISIBILITY.md](VISIBILITY.md)). **Encryption is
for secret files (`.env`, keys) only** (owner, 2026-11-06); personal private
keys never leave the machine. Code, folders, descriptions, tags and
embargoes are not encrypted: they are plain text behind the server's
permissions. Repository formats 7 and earlier also sealed descriptions, tag
messages, embargoed merges and folders with these constructions; format 8
removed every such use (FORMAT.md §5, "Format 8"), and this document
describes what is left.

Code map:

| file | what |
|---|---|
| `crates/veil-core/src/crypto/domains.rs` | **every** domain-separation string (KDF contexts, HPKE `info`, signature prefix and contexts, label prefixes). Nothing else may spell one. |
| `crates/veil-core/src/crypto.rs` | envelopes: AES-SIV (deterministic) and XChaCha20-Poly1305 (random nonce, and the legacy deterministic form) |
| `crates/veil-core/src/identity.rs` | identities, HPKE key wrapping (and the legacy sealed box), Ed25519 signatures |
| `crates/veil-core/src/keychain.rs` | key generations, ring log (hash chain, signatures, genesis MAC); embargo records (plain, no cryptography) |
| `crates/veil-core/src/team_vault.rs` | team-vault records: sealed entries, their signatures and who counts (C12) |
| `crates/veil-core/src/secret_share.rs` | person-to-person secret shares: one secret file sealed for one person's devices, signed by the sharer's (C14) |
| `crates/veil-core/src/store.rs` | which construction a repository writes (by repository format) and what it accepts |
| `crates/veil-core/src/upgrade.rs` | the ring step of the migration to format 3 (HPKE), and the format-8 check |

## 1. Primitives and crates

No primitive or construction is implemented in Veil. Everything comes from
maintained crates, pinned to exact versions in the root `Cargo.toml` so a
review covers exactly what ships:

| crate | version | used for |
|---|---|---|
| `aes-siv` (RustCrypto; with `aes` 0.9.4, `cmac` 0.8.0, `ctr` 0.10.1) | =0.8.0 | AES-SIV-CMAC-512, RFC 5297 |
| `hkdf` / `sha2` (RustCrypto) | =0.13.0 / =0.11.0 | HKDF-SHA256, RFC 5869 |
| `hpke` (rozbb/rust-hpke, RustCrypto primitives underneath) | =0.15.1 | HPKE, RFC 9180 |
| `chacha20poly1305` (RustCrypto) | =0.11.0 | XChaCha20-Poly1305 |
| `x25519-dalek` / `ed25519-dalek` (dalek) | =3.0.0 | X25519 (legacy sealed box), Ed25519 (RFC 8032) |
| `blake3` | 1.8 | hashing, keyed hashing, `derive_key` KDF mode |
| `getrandom` | =0.4.3 | the OS CSPRNG (all keys, nonces, HPKE ephemerals) |
| `zeroize` | 1 | wiping secrets (the `aes-siv` and `chacha20poly1305` `zeroize` features are on) |

`Cargo.lock` has exactly one version of each of these.

## 2. Constructions

Legend: **(F3)** written by repository format 3 and later; **(legacy)**
read forever, written only by format-1/2 repositories (see §5); **(all)**
every format.

### C1. Sealed objects: AES-SIV (F3)

* **Standard.** AES-SIV, RFC 5297, CMAC-AES-256 + CTR-AES-256
  (512-bit key), used as a **deterministic** AEAD (DAE, Rogaway and
  Shrimpton 2006): no nonce, associated data is the vector `[label]`.
  The key is `HKDF-SHA256(salt = none, ikm = scope key, info =
  AES_SIV_SUBKEY, L = 64)` (RFC 5869).
* **Inputs.** The 32-byte scope key; the label (`<scope>#<key-id>`,
  `<scope>`); the plaintext is the canonical encoding of another object (a
  secret file's blob, or a symlink target). Formats 7 and earlier also
  sealed trees and used embargo keys (label `embargo/<id>`); format 8
  refuses both.
* **Encoding.** `veil:sea2\n ‖ u16be label_len ‖ label ‖ SIV[16] ‖ C`.
  The object id is `BLAKE3(encoding)`.
* **Goal.** Confidentiality and integrity of sealed secret files. The label
  is authenticated, so ciphertext cannot be moved to another scope or
  generation. **Determinism is required:**
  re-snapshotting unchanged content must give the same id (deduplication,
  no-op snapshots, unchanged directories keeping their tree ids).
* **Known limits.**
  * Equality leaks: two objects with the same label and plaintext are
    identical, which is the DAE notion and the reason SIV was chosen.
    Nothing else about the plaintext leaks, except its length.
  * Not key-committing (same as every standard AEAD here). Veil never
    tries several keys on one ciphertext except "the key the label names",
    so we do not rely on commitment.
  * The SIV bound is in the total number of blocks processed under one
    key (birthday bound on the 128-bit SIV). Scope keys rotate on every
    revocation and on `vl scope rotate`. Repositories are far below
    2^48 blocks per key.
  * S2V takes at most 126 AD components; Veil passes one.

**Why AES-SIV and not AES-GCM-SIV (RFC 8452).** Both are misuse-resistant
AEADs. AES-GCM-SIV is nonce-based: to be deterministic it needs a nonce
that is constant or derived from the content. A content-derived nonce is
the homemade construction we are replacing. A fixed nonce turns every
message under a scope key into a nonce repetition. That is allowed by
GCM-SIV's MRAE definition, but it gives up the per-nonce key derivation
its good bounds come from, so the bound degrades with the number and length
of messages under the one nonce. GCM-SIV also limits a message to 2^36
bytes. AES-SIV is specified and proven for exactly this use (RFC 5297
§1.3.2, "deterministic authenticated encryption"), takes a vector of
associated data natively, and has no practical message-length limit (128-bit
counter in the `aes-siv` crate). The cost is speed: S2V/CMAC is serial, so
AES-SIV is slower than GCM-SIV. That is acceptable for a VCS whose objects
are hashed and usually compressed anyway.

**Why HKDF in front.** It expands the 32-byte scope key to the 64-byte
AES-SIV key. It also gives key separation: the raw scope key is used only by
XChaCha20-Poly1305 (C2, and the legacy C1L), never by two different
algorithms.

### C1L. Legacy sealed objects: XChaCha20-Poly1305 with a derived nonce (legacy)

`veil:seal\n ‖ u16be label_len ‖ label ‖ nonce[24] ‖ XChaCha20-Poly1305(key, nonce, aad = label, pt)`,
with `nonce = BLAKE3-keyed(BLAKE3-derive_key(LEGACY_SIV_NONCE, key), label ‖ 0x00 ‖ pt)[..24]`.
This is a homemade SIV: a PRF of the plaintext used as the nonce of a
nonce-based AEAD, under the same key. It is plausibly sound (it is the
"SIV from a PRF and an IV-based scheme" pattern), but it is not a
standardised mode and has no proof in its exact form. It is the main reason
format 3 exists. It is still **read** everywhere, and still **written** by
repositories at format 1 or 2 (so that older vl can read them), see §5.

### C2. Random-nonce envelopes: XChaCha20-Poly1305 (all)

* **Standard.** XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha-03, the
  libsodium construction; ChaCha20-Poly1305 is RFC 8439), with a fresh
  192-bit nonce from the OS CSPRNG for every message.
* **Uses** (label, key):

  | use | label | key | where |
  |---|---|---|---|
  | older generation key | `prev-key:<scope>#<new-key-id>` | the new generation's key | ring `Rotation.previous` |
  | device-local vault | `local` | `local_key` (C8) | `.veil/local/vault.sealed` |
  | team-vault entry (name and value) | `vault:<scope>#<key-id>` | scope generation key | `.veil/meta/vault/` records (C12) |

* Formats 7 and earlier also sealed change descriptions and cloaked tags'
  messages (label `<scope>#<key-id>` or `embargo/<id>`) and embargo keys
  (label `embargo-wrap:<id>`); format 8 refuses all three, and the labels
  stay reserved.
* **Goal.** Ordinary nonce-based AEAD. The label is authenticated, so a
  sealed key cannot be presented as another role or generation. Scope names are `[a-z0-9_-]`, so a label prefix such as
  `wrap:` can never be read as a scope.
* **Why not AES-SIV here too.** These need no determinism. XChaCha20 with
  random 192-bit nonces has negligible collision probability at any
  realistic volume (about 2^-96 after 2^48 messages under one key), and it
  is constant-time without AES hardware. Keeping it also keeps the
  **signed** ring change bodies that carry `previous` unchanged. Changing
  them would have needed new signature contexts and would have broken every
  existing signature.
* **Known limits.** Not key-committing. The JSON form (`{scope, nonce,
  ciphertext}`) is part of signed bodies and must never change. AES-SIV
  envelopes have no JSON form.

### C3. Key wrapping to a member: HPKE (F3)

* **Standard.** HPKE, RFC 9180, **base mode**, suite
  DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305
  (`0x0020/0x0001/0x0003`), single-shot `Seal`/`Open`.
* **Inputs.** Recipient: the member's X25519 public key (their member id
  `veil1<hex>`). `info = HPKE_KEY_WRAP_INFO`. `aad = "wrap:" ‖ scope`.
  Plaintext: the 32-byte scope key.
* **Encoding** (inside the signed ring change):
  `{"hpke": "base/x25519-hkdf-sha256/hkdf-sha256/chacha20poly1305", "enc": hex(32), "ct": hex(48)}`.
  Unknown fields and any other suite string are refused.
* **Goal.** Only the holder of the recipient's X25519 secret learns the
  key. The wrap is bound to the scope (aad), to the recipient (DHKEM's KEM
  context includes `pkR`) and to Veil (info). Which *generation* a wrap
  holds is checked after unwrapping: the key's fingerprint must equal the
  ring's key id for that generation.
* **Sender authentication** is not HPKE's job here: every wrap sits inside
  a ring change signed by an admin authorised at that point of the log
  (C5). So base mode is enough, and auth mode would only add a second,
  weaker binding.
* **Known limits.** HPKE refuses low-order recipient keys (all-zero DH;
  BUG-010), and the legacy box now does too (`was_contributory`). Both are
  tested. A ring may still list such a member (granted before that fix, or
  by a hostile admin; replay accepts grants without opening wraps).
  Rotations leave that member out, and replay allows exactly that omission,
  so revocations and `vl upgrade` keep working (BUG-070); `vl scope rotate`,
  `revoke` and `upgrade` name the member, and `fsck` warns until it is
  revoked. Not post-quantum: the `hpke` crate offers X-Wing
  (ML-KEM-768 + X25519); moving to it later is a new suite string and ring
  format.

**Why HPKE and not age.** HPKE has associated data and `info` natively, so
the scope binding is part of the standard construction rather than a
convention inside the plaintext. It is an IETF standard with published test
vectors in the exact suite we use (checked in our tests). Its output is two
short fields that sit naturally inside a signed JSON ring change. age is a
file format (header, recipient stanzas, STREAM payload, armor) with no
associated data, and its crate pulls in much more code.

### C3L. Legacy key wrapping: homemade sealed box (legacy)

`ephemeral X25519 → kek = BLAKE3-derive_key(LEGACY_KEY_WRAP, shared ‖ eph_pk ‖ recipient_pk) → XChaCha20-Poly1305(kek, random nonce, aad = "wrap:" ‖ scope)`,
encoded `{"ephemeral": hex, "sealed": {scope, nonce, ciphertext}}`. ECIES
in shape, with a non-standard KDF. Until this change it did not reject
low-order recipient points (BUG-010, reopened: wraps made that way before
the fix publish their key to anyone; `vl fsck` does not detect them yet).
Read forever; written only into format-1/2 repositories.

### C4. Identities and signing keys

* Each identity has an X25519 secret (encryption: C3/C3L recipient, C8)
  and an Ed25519 signing key (RFC 8032; verification is `verify_strict`,
  which rejects non-canonical and small-order encodings).
* **(F3) Independent keys.** New identities (`identity.json` format 2:
  `{format: 2, name, public, signing, encryption_secret, signing_secret}`)
  have an independent random Ed25519 seed. The file deliberately has no
  `secret` field, so an older vl refuses it rather than derive a signing key
  the rings do not know. Loading checks that `public` and `signing` match
  the secrets.
* **(legacy) Derived key.** Older identity files (`{name, public, secret,
  signing?}`) keep `seed = BLAKE3-derive_key(LEGACY_ED25519_SEED, x25519_secret)`,
  flagged by `Identity::signing_key_is_derived()` and in `vl identity
  show`. They keep working and are rewritten in their own shape. Replacing
  one (`vl identity new --force`) means admins must grant the new public
  identity.
* **Public identity** `veil1<x25519-hex><ed25519-hex><binding-hex>` (256
  hex digits) is the same for both kinds. The **binding** is the identity's
  Ed25519 signature, context `member-binding` (C5), over the 32 raw bytes of
  its X25519 public key: proof that whoever holds the signing key chose this
  encryption key (BUG-069). Without it, anyone could paste their own X25519
  key in front of someone else's public signing key and have the ring
  attribute that person's signatures to them. Legacy identities make it the
  same way with their derived key (a verifier cannot tell the kinds apart;
  their two keys are bound by construction, and the binding makes that
  checkable). Ed25519 is deterministic, so a public identity never changes.
* **Rings bind member id ↔ signing key** in the signed `MemberGrant`:
  * `vl scope grant` refuses a full identity whose binding does not verify,
    and the earlier unbound form `veil1<x25519><ed25519>`; the short member
    id `veil1<x25519>` still grants read access without a signing key.
  * From repository format 3 the grant records the binding (`binding`, ring
    format 3), and replay checks it. Grants recorded earlier, and in
    format-1/2 repositories (whose readers include vl 0.1.0, which would
    drop the field and then fail the signature), carry none: the admin's vl
    checked it, but readers cannot.
  * Replay refuses a grant or genesis member whose signing key already
    belongs (now or earlier) to another member of that ring.
  * Across rings, `known_signers` gives a key to the member whose binding a
    ring proved; a key that unbound grants in different rings give to
    different members is attributed to nobody (its signatures show as
    unknown, never as someone else's).
* **Known limits.** One identity per device file, unencrypted at rest (mode
  0600). A legacy identity's two keys are not independent: a break of the
  X25519 secret is also a signing-key compromise. A hostile admin of a
  format-1/2 ring (or of a ring written before bindings) can still record an
  unbound grant of a key nobody in that ring holds yet; it is only believed
  where no ring proves a binding for that key.

### C5. Signatures (all)

`Ed25519(signing_key, SIG_PREFIX ‖ context ‖ 0x00 ‖ payload)`, contexts
`snapshot`, `ring-change`, `member-binding`, `vault-entry`, `tag`,
`hub-login`, `hub-device`, `hub-invite`, and the retired `embargo` and
`embargo-release` (signed embargo records, formats 7 and earlier; reserved,
never reused) (see the
domains table). Payloads are fixed encodings (FORMAT.md §2, "signed bodies never
change"). What a valid signature *means* (who may sign what) is decided
against the ring log (ARCHITECTURE §3).

* **Annotated tags (`tag`, repository format 5).** The payload is the
  32-byte *unsigned id* of the atag: the BLAKE3 id of its canonical
  encoding (`veil:atag\n` ‖ JSON) with `signature` omitted, as for
  snapshots. It therefore covers the tag's name, target, kind, message,
  tagger and time.
  Goals: a signature cannot be moved to another tag name or target (the
  atag changes, the signature fails), and a view entry that names a
  genuine atag under another name or target is reported as "unverified
  (name mismatch / target mismatch)" before the signature is even looked
  at (`Atag::verify`); a signature made in another context over the same
  32 bytes (a snapshot signature) does not verify. *Limits:* a valid
  signature proves only possession of the key; "verified" additionally
  needs the key to be a member's in the ring, which the caller checks. An
  older atag of the same name and target, signed then, stays valid: a
  release tag is immutable, so replaying it restores what the signer
  signed.

### C6. Ring log hash chain and genesis proof (all) — custom, kept

* **Chain.** `prev = BLAKE3-derive_key-mode(RING_CHANGE_HASH; signing_body ‖ signature)[..16]`,
  hex. Each change is Ed25519-signed (C5) over a body that includes `scope`,
  `seq` and `prev`. Goal: an append-only, tamper-evident membership log
  where replay of a prefix, reordering, removal and cross-scope transplant
  all fail.
* **Genesis proof.** `BLAKE3-keyed(derive_key(RING_PROOF, gen0_key), scope ‖ 0 ‖ key_id ‖ 0 ‖ signer ‖ 0 ‖ signing_key ‖ 0)`, hex.
  Goal: a forged genesis that claims an existing scope's key id (copying
  real wrapped keys and naming itself admin) fails for every reader who
  holds the generation-0 key. Keyed BLAKE3 is a standard MAC (BLAKE3 spec
  §2.3 keyed mode). The derived MAC key separates it from every other use of
  the scope key.
* **Known limits.** The chain hash is truncated to 128 bits: collision
  resistance about 2^64. That is enough for its job, because changes are
  also signed and the signer is authorised by replay, but a reviewer should
  confirm. Separators are `0x00` and inputs are hex or validated names
  without NUL, so the MAC input is unambiguous. Freshness is TOFU (threat
  model).

### C7. Embargoes — removed (format 8)

Embargoes are permissions, not cryptography. Formats 7 and earlier sealed an
embargoed merge's changed content under a random embargo key, wrapped that
key under the scope key (label `embargo-wrap:<id>`), signed the record
(contexts `embargo`, `embargo-release`) and published the key on release.
Format 8 has none of it: an embargo record is plain (`EmbargoRecord
{format: 2, id, scope, until, released_at, created}`), the embargoed merge
and the history it brings in are withheld from every push until the
release, and who may see them before it is a permission the server
enforces (`docs/VISIBILITY.md`). The labels and signature contexts stay
reserved in `domains.rs` and are never reused. What the client still
guarantees without cryptography: nothing of an unreleased embargo leaves
the repository through `vl` (ARCHITECTURE.md §7). What it no longer does:
judge who may release (BUG-108); a release in a record a remote hands over
is taken as it is, so the remote (the Veil server) is the authority.

### C8. Device-local vault key (all)

`local_key = BLAKE3-derive_key(LOCAL_VAULT_KEY, x25519_secret ‖ repo_id)`,
used with C2 (label `local`). Never stored or synced. The X25519 secret is
32 random bytes, and BLAKE3 `derive_key` is BLAKE3's specified KDF mode.

### C9. Key fingerprints (all)

`key_id = hex(BLAKE3-derive_key(KEY_FINGERPRINT, key)[..8])`: public, 64
bits. Goal: name a generation in labels and detect a wrong key after
unwrapping. A collision gives no key material. At 64 bits, a *chosen*
collision costs about 2^32. An admin could make two generations share an
id, but `check_rotation` refuses a reused key id.

### C10. Object ids and integrity checksums (all)

Object ids are unkeyed `BLAKE3(encoding)` (content addressing). Pack and
index trailers, the stat cache and the gc pending list end in an unkeyed
BLAKE3 checksum against accidental damage. These are not security
boundaries beyond collision resistance of BLAKE3-256.

### C13. Invites and shares (ring format 4) — custom composition of standard parts

What it is for (`docs/HUB.md` §13.12): a device receives a scope key
only through a proof made outside the Veil server, which stores the rings
and is trusted with code but never with secrets.

* **Invite key.** `secret` = 32 bytes from the OS RNG on the admin's
  device, only in the invite link (`#invite=NAME:<hex>`, a URL fragment `vl`
  never sends). `seed = BLAKE3-derive_key(HUB_INVITE_KEY, secret)`, the
  Ed25519 key from that seed. The admin's ring change `invite {person, key:
  the verifying key, expires_at}` (signed, C5/C6) and the server's record
  hold only the public key. A server that sees the join cannot sign another:
  that needs the seed (2^256 secrets; Ed25519 security for the key).
* **Join.** `Ed25519(invite key, "hub-invite" context, person ‖ 0x00 ‖
  X25519 ‖ Ed25519)` of the joining device (fixed-length keys after a name
  without NUL: unambiguous). Bound to the person and to both of the device's
  keys, so it cannot be moved to another device or name.
* **Vouch** (C5, `hub-device`, §13.11): the person's own device's signature
  over the new device's X25519 ‖ Ed25519.
* **Share.** A ring change (C6) signed by **any current member**, adding a
  bound member (C4 binding checked) at the current generation, with the key
  wrapped by HPKE (C3) as for an admin's grant. Every replay checks the proof:
  a join under an unused, unexpired `invite` of the same person (then marked
  used), or a vouch by a current member's signing key with the same name. A
  member id or signing key the ring ever held is refused, so a removed
  device never comes back.
* **`revoke_own`.** A member removes another device with their own name and
  rotates (the same rotation as a revocation, C6, C9). A key holder checks
  that its new generation unlocks the previous one, as for every rotation
  (`check_with_keys`).
* **Project binding (BUG-845).** A project's id is `team`'s genesis change
  hash (C6's chain hash, 128 bits: it commits to the genesis's random key id,
  members and signature). Every other ring's genesis carries the id in its
  signed body (`project`, ring format 4), so the binding is as strong as the
  genesis signature (C5) and the chain (C6): a server can neither move a
  ring to another project nor re-label one. A reader accepts a non-`team`
  ring only if its `project` equals its own `team`'s id.
* **Project fingerprint, the anchor.** `fp = BLAKE3-derive_key(
  HUB_PROJECT_FINGERPRINT, id)[..10]` (80 bits), shown as 20 hex digits. A
  clone of a server project trusts a `team` ring only if its fingerprint is
  the one the device anchored outside the server: from the invite link
  (inside the fragment the server never sees; `vl join` compares it with
  the server's `team`), from creating the project, or typed by the person
  after comparing it. Forging a `team` ring with a given fingerprint is a
  second preimage of 80 bits (about 2^80 genesis signatures, each with a
  fresh key or member list), as for device fingerprints. Until a device
  has an anchor it takes no ring of the project.
* **Not from a vouch.** A vouch (C5, `hub-device`) is checked by the
  *voucher's* peers, not by the new device, which knows no key of its
  person yet: anchors carried in a vouch would be the server's to choose.
* **Not covered.** Whether a member wraps the right key cannot be checked by
  a replay (true of admins' grants as well): a member could leak the key
  anyway. Freshness of the ring a member reads is TOFU, as for every ring (a
  server can withhold a rotation from one device: HUB.md §13.12, "Residual
  risks").

### C14. Person-to-person secret shares — standard parts (C2, C3, C5), one key per version

What it is for (`docs/HUB.md` §13.13): a member gives **one secret file**
to **one other member**, without an admin, so that only that person's
confirmed devices (and the sharing device) can open it, and the server,
which stores it, cannot.

* **Construction.** For each version the sharing device makes a fresh
  32-byte key `K` (OS RNG). The file (at most 64 KiB) is sealed under `K`
  with C2 (XChaCha20-Poly1305, random nonce), label `share:<id>#<version>`;
  `K` is wrapped with C3 (HPKE base mode, `info = HPKE_KEY_WRAP_INFO`) to
  each device, `aad = "wrap:" ‖ "share:<id>#<version>"`. `<id>` is
  `BLAKE3-derive_key(HUB_SHARE_ID, len‖project ‖ len‖path ‖ len‖sharer ‖
  len‖recipient)[..16]` (64-bit little-endian lengths). The record `{format,
  project, path, sharer, recipient, version, at, signer, sealed, wraps}` is
  signed by the sharing device (C5, context `hub-share`, over that exact
  JSON, `ShareRecord::signing_body`, pinned by a unit test).
* **Goal.** Only the devices wrapped for open the file: the recipient's
  confirmed devices and the sharing device (which re-reads its own last
  version to see whether its copy changed). The labels bind the sealed file
  and each wrap to the share and the version, so neither moves to another
  share, version or person; the signature binds the whole record to its
  signer, project, path, sharer and recipient, so the server can change
  nothing in it (it would no longer verify). No other key is involved: a
  share holds no ring key, so it opens nothing but the one file.
* **Why a key per version.** A device left out of a version (removed, or no
  longer confirmed) opens no later version, without any rotation protocol:
  each version is sealed afresh for the devices confirmed then.
* **Who the devices are, and who the signer is, are not cryptographic
  questions of C14.** The sharing device seals only for devices confirmed
  outside the server (HUB.md §13.11, §13.12: a verified ring, the sharer's
  fingerprint comparison, an invite join, a vouch by one of these); the
  receiving device accepts a record only if its `signer` is a current
  member, named as the sharer, of a key ring of this project it verifies
  (C6, project-bound by C13). The server's lists are never enough for
  either.
* **Freshness.** The recipient's device refuses a version older than the
  last one it received (device-local memory). A server can withhold a newer
  version (as for rings: TOFU freshness), never make one.
* **Not covered.** Taking back what a recipient already opened (an unshare
  stops later versions only); a sharer leaking the file some other way
  (trusted, §3.1 of HUB.md); a member's device holding the file's plaintext
  after the share ends.

### C12. Team-vault records (all)

* **Construction.** C2 (XChaCha20-Poly1305, random nonce) under the
  scope's current generation key, label `vault:<scope>#<key-id>`, over the
  JSON `{name, value, since}` padded with spaces to a multiple of 128 bytes.
  Then an Ed25519 signature (C5, context `vault-entry`) by the writer over
  `{format, scope, sealed, timestamp, signer}` (encrypt-then-sign). Record
  id = unkeyed BLAKE3 of the canonical file bytes (C10).
* **Goal.** Only members of the scope (holders of a generation key) read
  names and values. A record counts only if its signer is a *current*
  member with the signing key the verified ring registers (judged by every
  reader against the ring). The label binds
  the ciphertext to the scope and generation, and the signature binds the
  ciphertext to its writer, time and scope. Because the signature is over the
  ciphertext, a non-member relay can check who wrote a record without being
  able to open it.
* **Why random nonces, not AES-SIV (C1).** Nothing needs determinism: a
  record is written once and never re-derived. Determinism would leak
  equality: setting a secret back to an earlier value, or two entries with
  the same value, would give identical ciphertexts. The `vault:` prefix keeps
  these envelopes apart from sealed secret files, which use C1 with the
  bare `<scope>#<key-id>` label under the same key.
* **Why encrypt-then-sign.** The signer is a member who could read and
  re-sign any entry anyway, so signing the ciphertext gives up nothing and
  lets anyone holding the ring verify membership. A member can take
  another member's ciphertext and sign it as their own write. That gives
  them nothing they could not do by writing the value directly.
* **Known limits.**
  * Revocation is forward-only, as for content: a revoked member keeps the
    keys of the generations they held, so they can read every record sealed
    under them. `vl scope revoke` lists those entries.
  * Visible to a remote's operator: scope, record count, sizes in 128-byte
    steps, timestamps, the signer's member id and signing key. They can
    withhold or delete records (rollback for fresh clones). Freshness is
    TOFU, as for rings.
  * Timestamps are self-asserted. Ordering uses them only between counting
    writers (current members). Sync refuses records stamped more than a day
    ahead (push and pull both say so), and a writer stamps after everything
    they have pulled. A writer's own records stamped more than a day ahead
    (a clock that was wrong) are replaced by their next write of the name,
    here and, on the next push, on the remote (BUG-522).
  * **Stale rings** (BUG-524). A member who has not pulled a revocation
    seals under the generation their ring calls current, which the revoked
    member holds. `vl secret set --scope` first fast-forwards the ring from
    the team remotes (and warns when none answers); push re-seals the
    pusher's own records sealed under an older generation than the remote
    ring's current one before sending them. What stays: a record that
    reaches a remote another way (an older vl, a relay) is only *detected*.
    A record sealed under generation g, timestamped after generation g+1
    started and readable by a member revoked in between, is flagged on
    pull and in `vl secret list` (to set again), and counts as exposed
    (`since` ≤ g). Because timestamps are self-asserted, a writer can
    backdate it to escape the flag; but a counting writer could hand the
    value to the revoked member directly anyway, so the flag is for honest
    stale writers, not a defence against members.
  * **Exposure memory** (BUG-521). `since` is the first generation a
    *value* was sealed under, kept when the same value is written again. As
    compaction deletes superseded records, each device remembers, in
    `.veil/local/vault-history/<scope>.json`, a keyed BLAKE3 of every name
    and value it saw (key `derive_key(TEAM_VAULT_HISTORY, local_key)` from
    C8: without the identity the file reveals no names and allows no
    guessing of values) with the first generation of each value. A write of
    a value seen before takes that generation as `since`, so going back to a
    leaked value after a rotation or a deletion stays exposed on every
    replica. A device that never saw the earlier value cannot link it.
  * `vl run` does not take execution-affecting variables (`PATH`, `LD_*`,
    `BASH_ENV`, `NODE_OPTIONS`, `GIT_*`, …) from a team vault, and loads
    only the scopes chosen on the command line or remembered on the device
    (BUG-520). Other variables a member sets still reach the command next
    to the other loaded scopes' secrets: load only scopes whose members you
    trust with each other's secrets.

## 3. Domain-separation strings

All in `crates/veil-core/src/crypto/domains.rs`. A unit test checks they
are distinct and pins their exact bytes.

| constant | value | primitive | construction |
|---|---|---|---|
| `AES_SIV_SUBKEY` | `veil 2026 sealed-object aes-siv-cmac-512 v1` | HKDF-SHA256 `info` | C1 |
| `LEGACY_SIV_NONCE` | `veil 2026 siv-nonce v1` | BLAKE3 `derive_key` | C1L (legacy) |
| `HPKE_KEY_WRAP_INFO` | `veil 2026 key-wrap hpke v1` | HPKE `info` | C3 |
| `LEGACY_KEY_WRAP` | `veil 2026 key-wrap v1` | BLAKE3 `derive_key` | C3L (legacy) |
| `LEGACY_ED25519_SEED` | `veil 2026 ed25519-seed v1` | BLAKE3 `derive_key` | C4 (legacy identities) |
| `LOCAL_VAULT_KEY` | `veil 2026 local-vault v1` | BLAKE3 `derive_key` | C8 |
| `TEAM_VAULT_HISTORY` | `veil 2026 team-vault history v1` | BLAKE3 `derive_key` → keyed BLAKE3 | C12 (device-local value history) |
| `KEY_FINGERPRINT` | `veil 2026 key-fingerprint v1` | BLAKE3 `derive_key` | C9 |
| `RING_CHANGE_HASH` | `veil 2026 ring-change v1` | BLAKE3 `derive_key` mode as a hash | C6 |
| `RING_PROOF` | `veil 2026 ring-proof v1` | BLAKE3 `derive_key` → keyed BLAKE3 | C6 |
| `SIG_PREFIX` | `veil 2026 sig v1\0` | Ed25519 message prefix | C5 |
| `SIG_CONTEXT_SNAPSHOT` | `snapshot` | Ed25519 context | C5 |
| `SIG_CONTEXT_RING_CHANGE` | `ring-change` | Ed25519 context | C5, C6 |
| `SIG_CONTEXT_EMBARGO` | `embargo` | Ed25519 context | C5, C7 (retired in format 8: reserved, never reused) |
| `SIG_CONTEXT_EMBARGO_RELEASE` | `embargo-release` | Ed25519 context | C5, C7 (retired in format 8: reserved, never reused) |
| `SIG_CONTEXT_MEMBER_BINDING` | `member-binding` | Ed25519 context | C4, C5 |
| `SIG_CONTEXT_VAULT_ENTRY` | `vault-entry` | Ed25519 context | C5, C12 |
| `SIG_CONTEXT_TAG` | `tag` | Ed25519 context (format 5: annotated tags, over `Atag::unsigned_id`) | C5 |
| `SIG_CONTEXT_HUB_LOGIN` | `hub-login` | Ed25519 context (signing in to a Veil server, HUB.md §13.2) | C5 |
| `SIG_CONTEXT_HUB_DEVICE` | `hub-device` | Ed25519 context (a device vouching for another device of its person, over X25519 ‖ Ed25519 public keys, HUB.md §13.11) | C5, C13 |
| `SIG_CONTEXT_HUB_INVITE` | `hub-invite` | Ed25519 context (a join under an invite, by the invite's key, over `person ‖ 0 ‖ X25519 ‖ Ed25519` of the joining device, HUB.md §13.12) | C5, C13 |
| `SIG_CONTEXT_HUB_SHARE` | `hub-share` | Ed25519 context (one version of a person-to-person secret share, by the sharing device, over `ShareRecord::signing_body`, HUB.md §13.13) | C5, C14 |
| `HUB_VIEW_KEY` | `veil 2026 hub view-key v1` | BLAKE3 `derive_key` mode as a hash | server: projection cache key (not secret) |
| `HUB_DEVICE_FINGERPRINT` | `veil 2026 hub device-fingerprint v1` | BLAKE3 `derive_key` mode as a hash (first 80 bits) | device fingerprint compared out of band (HUB.md §13.11) |
| `HUB_UPLOAD_RECEIPT` | `veil 2026 hub upload-receipt v1` | BLAKE3 `derive_key` → keyed BLAKE3 (first 128 bits) | server: upload receipts over project ‖ person ‖ object id (HUB.md §13.5) |
| `HUB_INVITE_KEY` | `veil 2026 hub invite-key v1` | BLAKE3 `derive_key` → Ed25519 seed | C13: an invite's signing key, from the link's 32 random bytes |
| `HUB_PROJECT_FINGERPRINT` | `veil 2026 hub project-fingerprint v1` | BLAKE3 `derive_key` mode as a hash (first 80 bits) | C13: a project's fingerprint, over its id; in invite links and compared out of band (not secret) |
| `POLICY_RULE_SCOPE` | `veil 2026 policy rule-scope v1` | BLAKE3 `derive_key` mode as a hash (first 80 bits) | the scope name `rule-<hex>` of an access line's secrets (not secret) |
| `HUB_SHARE_ID` | `veil 2026 hub share-id v1` | BLAKE3 `derive_key` mode as a hash (first 128 bits) | C14: a share's id in its labels, over its project, path, sharer and recipient (not secret) |
| `WRAP_LABEL_PREFIX` | `wrap:` | AEAD associated data | C3, C3L |
| `PREV_KEY_LABEL_PREFIX` | `prev-key:` | AEAD associated data | C2 |
| `EMBARGO_WRAP_LABEL_PREFIX` | `embargo-wrap:` | AEAD associated data | C2, C7 (retired in format 8: reserved, never reused) |
| `EMBARGO_LABEL_PREFIX` | `embargo/` | AEAD associated data | C1, C2 (retired in format 8: reserved, never reused) |
| `LOCAL_LABEL` | `local` | AEAD associated data | C2, C8 |
| `VAULT_LABEL_PREFIX` | `vault:` | AEAD associated data | C2, C12 |
| `SHARE_LABEL_PREFIX` | `share:` | AEAD associated data (and, after `wrap:`, HPKE aad; no scope name has a `:`) | C2, C3, C14 |
| `GENERATION_SEPARATOR` | `#` | label syntax `<scope>#<key-id>` | C1, C2 |

Signature contexts never contain NUL and are followed by `0x00`, so
`context ‖ 0 ‖ payload` is unambiguous.

## 4. What remains custom, and why

* **The ring log** (C6): a signed, hash-chained membership log with
  replay-based authorisation. No standard covers "a group key ring with
  admin-signed membership changes" in this shape. MLS (RFC 9420) is the
  standard for group key agreement, but it is interactive (epochs, commits,
  welcome messages) and much heavier than an append-only file that travels
  with the repository. Its parts are standard: Ed25519, BLAKE3, HPKE.
* **The genesis MAC** (C6): keyed BLAKE3, a standard MAC, used for a
  Veil-specific purpose.
* **Key generations and the `previous` chain**: each generation key sealed
  under its successor (C2). This is key management, not a primitive.
* **BLAKE3 derivations** (§3): all through BLAKE3's specified KDF and keyed
  modes, with the contexts in one module.
* **Labels as associated data**: the convention that the envelope label
  both selects the key and is authenticated. All constructions use standard
  AEAD associated data for this.

## 5. Formats and migration

| repository format | sealed objects | wrapped ring keys | ring format | identities created |
|---|---|---|---|---|
| 1, 2 | C1L `veil:seal` | C3L | 0/1 (legacy), 2 | (older vl) derived signing key |
| 3 to 7 | C1 `veil:sea2` | C3 HPKE | 3 once it holds an HPKE wrap (4 for invites and shares, format 7) | independent signing key |
| 8 | C1 `veil:sea2`, for secret files only | C3 HPKE | 3, 4 | independent signing key |

Format 5 adds no construction: a sealed symlink target is a sealed blob
(C1), and an annotated tag's signature a C5 signature in the new context
`tag`. Format 8 adds none either: it removes every use of encryption but
secret files (FORMAT.md §5), and opens only format 8.

* **Readers** read every construction an upgraded repository can hold:
  `veil:seal` and `veil:sea2` objects, legacy and HPKE wraps, legacy and
  new identity files.
* **Writers** write the constructions of their **repository format**, as
  for tree encodings (FORMAT.md §1); this release writes format 8 only, so
  C1 and C3. Identity files are
  device-local, so new identities always get independent keys.
* **Refusals** (`Unsupported`, "upgrade it with `vl upgrade` / `vl upgrade
  --remote <name>`"): a format-1/2 repository refuses `veil:sea2` objects
  (`ObjectStore::check_storable`, called by `put_raw` and by the pack sink
  of incremental sync) and rings that hold HPKE wraps (`Keychain::save_ring`,
  so push and pull merges too). `fsck` reports either as corruption. An older
  vl refuses `veil:sea2` (unknown object kind), ring format 3 (no keys from
  that ring) and identity format 2 (missing `secret`).
* **`vl upgrade` to 3** runs `verify` and then `set-format`, the commit
  point. After that it runs `3:hpke-ring-keys`: for every scope this
  identity administers whose current key was ever wrapped with C3L, it
  appends a signed `Rotate` change. The rotation starts a new generation
  whose key is HPKE-wrapped to every current member and carries the
  previous key (C2), so history stays readable. A member who is not an
  admin gets a note asking an admin to run `vl upgrade` or `vl scope
  rotate`. A remote (`--remote`, no identity; SSH remotes over SFTP) is
  upgraded structurally; its rings move to HPKE when an upgraded admin
  pushes. The step is idempotent and journaled (resumes after a crash; the
  `crash.rs` sweep covers 1→3 and 2→3). It also runs on its own in a
  repository already at format 3 whenever one of this identity's rings is
  pending (BUG-071: a fresh clone of an upgraded remote, or a clone a
  non-admin upgraded). A scope it cannot rotate becomes a note; it never
  blocks the upgrade after its commit point.
* **Nothing is re-sealed.** Re-sealing history would change object ids, so
  every tree and snapshot above them, every snapshot signature and change
  id would change. Unchanged sealed files also keep
  their existing sealing when re-snapshotted (`matches_encoding` compares
  plaintext), so they keep their ids.

**What this means for the review.** After an upgrade, a repository holds
both constructions:

* Every object sealed before the upgrade stays C1L forever, under keys
  whose wraps in the ring log are C3L. If C1L or C3L were broken, that
  history would be exposed, because the legacy wraps are published in the
  append-only ring and cannot be withdrawn.
* Content sealed **after** the upgrade is C1 under a generation key that
  was only ever HPKE-wrapped. Its confidentiality does not depend on C1L or
  C3L. The exception is unchanged files, which keep their old sealing until
  they change.
* A scope whose admin has not yet upgraded keeps sealing new content under
  a C3L-wrapped key (C1 for objects, if the repository is format 3).

So the review must still cover C1L and C3L as read paths and as the
protection of pre-upgrade history. Rotating every scope and re-committing
every file would get new content off them, never old content.

## 6. Tests

* **Known answers against the RFCs.**
  * RFC 5297 A.1 (deterministic) and A.2 (nonce-based), through the crate's
    CMAC-SIV.
  * AES-CMAC-SIV-512, from the vectors the `aes-siv` crate ships.
  * RFC 5869 A.1 (HKDF-SHA256).
  * RFC 9180 A.2.1 (our exact HPKE suite): key derivation, encapsulation
    with the RFC's ephemeral input, the first encryption, and opening it.
  * Plus pinned known answers for Veil's own compositions: the AES-SIV
    envelope (also in `tests/fixtures/encodings.txt` as `sealed-aes-siv`),
    an HPKE key wrap with fixed randomness, the legacy derived signing key,
    the binding of a legacy identity, and the domain strings and signature
    contexts.
* **Round trip and tampering** for every construction: AES-SIV, random and
  legacy XChaCha20-Poly1305 (bit flips, truncation, relabelling,
  construction swap, wrong key), HPKE (enc/ct bit flips, truncation,
  all-zero enc, wrong scope, wrong recipient, unknown suite, unknown
  fields), legacy wraps, identity files (damaged, mixed, newer).
* **Cross-version and migration** (`tests/core_format/format_compat.rs`).
  * The format-8 set reads, verifies and `fsck`s, with only C1/C3 and a
    member with a legacy identity, and seals nothing but secret files.
  * Every older set is refused unchanged (formats 1 to 5 as no longer
    read; 6 and 7 naming what they hold that format 8 removed).
  * Until format 8 these suites also checked the 1→3 and 2→3 upgrades
    (rings rotated to HPKE, every object and id kept) and that format-3
    cryptography never reached a format-2 repository; those formats are no
    longer read.
* The adversarial suites (`adversarial_*`, `hostile_*`) run unchanged
  against both constructions where they construct legacy data explicitly.

## 7. Open questions for the reviewer

1. AES-SIV over AES-GCM-SIV with a fixed nonce (§2 C1): agree?
2. Ring chain hash truncated to 128 bits and key ids to 64 bits (C6, C9).
3. HPKE base mode, relying on the ring signature for sender authentication
   (C3).
4. The X25519 secret of an identity serves both C3 (HPKE) and the legacy
   C3L box, and derives the vault key (C8): the same DH key in two KEMs,
   with distinct KDFs.
8. The binding (C4) is a plain Ed25519 signature over the X25519 key under
   its own context. It does not cover a name, a scope or a time: it says
   "this signing key goes with this encryption key", which is all replay
   needs. Agree?
5. Whether `vl upgrade` should also offer to re-key a **legacy identity**
   (derived signing key). Today that needs `vl identity new` and fresh
   grants.
6. The `aes-siv` crate zeroizes the CTR key on drop but not the CMAC key
   state, and `hpke` copies the recipient secret into a temporary array
   while clamping. Both are upstream limits of memory hygiene.
7. Equality leakage of deterministic sealing (C1) is a product decision,
   documented in the threat model.
