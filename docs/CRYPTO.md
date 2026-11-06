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
for secrets (`.env`, keys) and embargoed changes only;** personal private
keys never leave the machine. Code is not encrypted, and there is no plan to
encrypt it. Today's client, before the server, also seals *cloaked* paths
with these constructions (C1 under a scope key); that is built and is
described here as a fact. With the server, cloaked paths become private
folders, and the same constructions protect secrets and embargoes
([HUB.md](HUB.md) §6, §8).

Code map:

| file | what |
|---|---|
| `crates/veil-core/src/crypto/domains.rs` | **every** domain-separation string (KDF contexts, HPKE `info`, signature prefix and contexts, label prefixes). Nothing else may spell one. |
| `crates/veil-core/src/crypto.rs` | envelopes: AES-SIV (deterministic) and XChaCha20-Poly1305 (random nonce, and the legacy deterministic form) |
| `crates/veil-core/src/identity.rs` | identities, HPKE key wrapping (and the legacy sealed box), Ed25519 signatures |
| `crates/veil-core/src/keychain.rs` | key generations, ring log (hash chain, signatures, genesis MAC), embargo key wrapping and release |
| `crates/veil-core/src/team_vault.rs` | team-vault records: sealed entries, their signatures and who counts (C12) |
| `crates/veil-core/src/store.rs` | which construction a repository writes (by repository format) and what it accepts |
| `crates/veil-core/src/upgrade.rs` | the migration to format 3 |

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
* **Inputs.** The 32-byte scope (or embargo) key; the label
  (`<scope>#<key-id>`, `<scope>`, `embargo/<id>`); the plaintext is the
  canonical encoding of another object (a blob or a tree).
* **Encoding.** `veil:sea2\n ‖ u16be label_len ‖ label ‖ SIV[16] ‖ C`.
  The object id is `BLAKE3(encoding)`.
* **Goal.** Confidentiality and integrity of cloaked and embargoed content
  and trees. The label is authenticated, so ciphertext cannot be moved to
  another scope, generation or embargo. **Determinism is required:**
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
  | cloaked change descriptions | `<scope>#<key-id>` / `embargo/<id>` | scope / embargo key | `Text::Sealed` in snapshots |
  | cloaked tag messages (format 5) | `<scope>#<key-id>` | scope generation key | `Text::Sealed` in annotated tags (`veil:atag`) |
  | older generation key | `prev-key:<scope>#<new-key-id>` | the new generation's key | ring `Rotation.previous` |
  | embargo key | `embargo-wrap:<id>` | scope key (generation in `scope_key`) | `EmbargoRecord.wrapped` |
  | device-local vault | `local` | `local_key` (C8) | `.veil/local/vault.sealed` |
  | team-vault entry (name and value) | `vault:<scope>#<key-id>` | scope generation key | `.veil/meta/vault/` records (C12) |

* A cloaked tag message shares its label with cloaked descriptions under
  the same key: a member could copy a sealed description into an atag of
  their own (it then shows as that tag's message), but not into anyone
  else's signed atag, whose signature covers the ciphertext. Both are text
  for the same audience, so no content changes audience.
* **Goal.** Ordinary nonce-based AEAD. The label is authenticated, so a
  sealed key cannot be presented as another role or for another embargo or
  generation. Scope names are `[a-z0-9_-]`, so a label prefix such as
  `wrap:` can never be read as a scope.
* **Why not AES-SIV here too.** These need no determinism. XChaCha20 with
  random 192-bit nonces has negligible collision probability at any
  realistic volume (about 2^-96 after 2^48 messages under one key), and it
  is constant-time without AES hardware. Keeping it also keeps three
  **signed** encodings unchanged (the embargo record body, ring change bodies
  that carry `previous`, and snapshot ids that cover descriptions). Changing
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
`snapshot`, `ring-change`, `embargo`, `embargo-release`, `member-binding`,
`vault-entry`, `tag` (see the domains table). Payloads are fixed encodings (FORMAT.md §2, "signed bodies never
change"). What a valid signature *means* (who may sign what) is decided
against the ring log (ARCHITECTURE §3).

* **Annotated tags (`tag`, repository format 5).** The payload is the
  32-byte *unsigned id* of the atag: the BLAKE3 id of its canonical
  encoding (`veil:atag\n` ‖ JSON) with `signature` omitted, as for
  snapshots. It therefore covers the tag's name, target, kind, message (as
  stored: the ciphertext of a sealed one), tagger and time.
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

### C7. Embargo key wrapping and release (all) — kept

* Creation: a random 32-byte embargo key, sealed under the scope's current
  generation key with C2 (label `embargo-wrap:<id>`, the generation named
  in `scope_key`). The record commits to `key_id = fingerprint(key)` (C9)
  and is signed (C5, `embargo`).
* Release: the plaintext key is published in the record (`released_key`),
  signed (C5, `embargo-release`). Every reader checks
  `fingerprint(released_key) == key_id` before using it.
* Goal: before release only scope members (holders of the generation key)
  can read embargoed content; after release everyone can, and nobody can
  publish a different key.
* Who may sign a record is judged against the scope's ring. A public
  remote holds no rings (BUG-077), so its clones accept records unverified:
  they hold no scope key, so a record can never trigger a release there,
  and a published key is still checked against `key_id` and then by the
  AEAD of the content it opens. A record a ring later shows to be signed by
  a member replaces an unverified local one.
* **Who may release (BUG-108).** A valid release signature is not enough.
  Where a repository holds a verified signed ring for the embargo's scope,
  it accepts a release only if its signer is a **current** member of that
  scope, signing with the key the ring registers for them, or if the
  record's (good-signed) deadline has passed. The check runs on every
  lookup, not only on pull, so a release accepted before a revocation
  arrived stops counting once it does; a pull drops an unaccepted release
  from the incoming record with a warning, and an accepted one replaces it
  later. Without such a ring (public clones, legacy rings) the release is
  judged by `key_id` alone, as before. A member granted by short member id
  has no registered signing key and cannot release before the deadline.
  What this does not prevent: a revoked member still holds the embargo key
  (revocation is forward-only, and rotating the scope does not re-key an
  embargo whose content is already sealed), so they can leak the key or
  the fix out of band. What it prevents is an in-protocol release that
  honest replicas act on, publishing the fix with their next public push.
* **Staged release (BUG-109).** `Repo::release_embargo` (`vl embargo
  release`) does not write the record. It stores the signed release fields
  in device-local state (`.veil/local/releases/<id>.json`), which no sync
  or remote reads, and which only the identity that signed it honours. The
  next push copies them into the record before the record is
  synced (`Keychain::publish_staged_releases`). So until then the key has
  not left the repository through vl, and `vl undo` deletes the staged
  release outright. After it, undo refuses: a published key cannot be
  taken back. No construction changes; the signed release body is the
  same.
* Known limits: time-based release is enforced by key holders' engines, not
  cryptography (threat model).

### C8. Device-local vault key (all)

`local_key = BLAKE3-derive_key(LOCAL_VAULT_KEY, x25519_secret ‖ repo_id)`,
used with C2 (label `local`). Never stored or synced. The X25519 secret is
32 random bytes, and BLAKE3 `derive_key` is BLAKE3's specified KDF mode.

### C9. Key fingerprints (all)

`key_id = hex(BLAKE3-derive_key(KEY_FINGERPRINT, key)[..8])`: public, 64
bits. Goal: name a generation in labels, detect a wrong key after unwrapping
and commit embargo records to their key. A collision gives no key material.
At 64 bits, a *chosen* collision costs about 2^32. An admin could make two
generations share an id, but `check_rotation` refuses a reused key id. An
embargo creator could commit to an id two keys share, but the creator is a
scope member who already holds the content.

### C10. Object ids and integrity checksums (all)

Object ids are unkeyed `BLAKE3(encoding)` (content addressing). Pack and
index trailers, the stat cache and the gc pending list end in an unkeyed
BLAKE3 checksum against accidental damage. These are not security
boundaries beyond collision resistance of BLAKE3-256.

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
  reader against the ring, as for embargo releases, C7). The label binds
  the ciphertext to the scope and generation, and the signature binds the
  ciphertext to its writer, time and scope. Because the signature is over the
  ciphertext, a non-member relay can check who wrote a record without being
  able to open it.
* **Why random nonces, not AES-SIV (C1).** Nothing needs determinism: a
  record is written once and never re-derived. Determinism would leak
  equality: setting a secret back to an earlier value, or two entries with
  the same value, would give identical ciphertexts. The `vault:` prefix keeps
  these envelopes apart from cloaked change descriptions, which use C2 with
  the bare `<scope>#<key-id>` label under the same key.
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
| `SIG_CONTEXT_EMBARGO` | `embargo` | Ed25519 context | C5, C7 |
| `SIG_CONTEXT_EMBARGO_RELEASE` | `embargo-release` | Ed25519 context | C5, C7 |
| `SIG_CONTEXT_MEMBER_BINDING` | `member-binding` | Ed25519 context | C4, C5 |
| `SIG_CONTEXT_VAULT_ENTRY` | `vault-entry` | Ed25519 context | C5, C12 |
| `SIG_CONTEXT_TAG` | `tag` | Ed25519 context (format 5: annotated tags, over `Atag::unsigned_id`) | C5 |
| `WRAP_LABEL_PREFIX` | `wrap:` | AEAD associated data | C3, C3L |
| `PREV_KEY_LABEL_PREFIX` | `prev-key:` | AEAD associated data | C2 |
| `EMBARGO_WRAP_LABEL_PREFIX` | `embargo-wrap:` | AEAD associated data | C2, C7 |
| `EMBARGO_LABEL_PREFIX` | `embargo/` | AEAD associated data | C1, C2 |
| `LOCAL_LABEL` | `local` | AEAD associated data | C2, C8 |
| `VAULT_LABEL_PREFIX` | `vault:` | AEAD associated data | C2, C12 |
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
* **Embargo wrapping and release** (C7): standard AEAD, plus a published
  key checked against a fingerprint commitment.
* **BLAKE3 derivations** (§3): all through BLAKE3's specified KDF and keyed
  modes, with the contexts in one module.
* **Labels as associated data**: the convention that the envelope label
  both selects the key and is authenticated. All constructions use standard
  AEAD associated data for this.

## 5. Formats and migration

| repository format | sealed objects | wrapped ring keys | ring format | identities created |
|---|---|---|---|---|
| 1, 2 | C1L `veil:seal` | C3L | 0/1 (legacy), 2 | (older vl) derived signing key |
| 3, 4, 5 | C1 `veil:sea2` | C3 HPKE | 3 once it holds an HPKE wrap | independent signing key |

Format 5 adds no construction: a sealed symlink target is a sealed blob
(C1), a cloaked tag message a C2 envelope, and an
annotated tag's signature a C5 signature in the new context `tag`.

* **Readers** read every construction forever: `veil:seal` and `veil:sea2`
  objects, legacy and HPKE wraps, legacy and new identity files.
* **Writers** write the constructions of their **repository format**, as
  for tree encodings (FORMAT.md §1). A format-1/2 repository keeps writing
  C1L and C3L, so older vl can keep reading it. Identity files are
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
  id would change. Unchanged cloaked files also keep
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
  * Every fixture set (formats 1, 2, 3) reads, verifies and `fsck`s.
  * The format-3 set has only C1/C3, plus a member with a legacy identity.
  * Its `upgraded/` repository, a format-2 set after `vl upgrade`, mixes
    both constructions, and every member reads exactly their share.
  * A format-2 repository keeps writing C1L/C3L.
  * Upgrading 1→3 and 2→3 rotates rings to HPKE, keeps every object and
    id, and keeps unchanged files' sealing. It is idempotent, resumes after
    a crash, and leaves rings alone (with a note) for a non-admin.
  * `veil:sea2` objects and HPKE rings never reach a format-2 repository
    (incremental and full sync, push and pull), and `fsck` reports them.
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
