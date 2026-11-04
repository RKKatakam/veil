# Known open issues

Collected from the agents' reports during rounds 1–2. Fixed adversarial
findings are in `docs/BUGS.md`; this file lists what is known and **not yet
fixed**. Severity: high / medium / low.

## Planned next: replace custom crypto constructions with standards

Approved to run right after round 3 merges, before the format is final.
The primitives are standard crates (`chacha20poly1305`, `x25519-dalek`,
`ed25519-dalek`, `blake3`); the risk is in how Veil combines them:

1. Deterministic sealing (`crypto.rs`, keyed-BLAKE3 nonce + XChaCha20-Poly1305,
   a homemade SIV) → a standard misuse-resistant AEAD: AES-GCM-SIV (RFC 8452)
   or AES-SIV (RFC 5297), RustCrypto crates.
2. Key wrapping to a recipient (`identity.rs`, homemade sealed box) → HPKE
   (RFC 9180) or the `age` format.
3. One secret for both X25519 and Ed25519 (derived) → independent encryption
   and signing keys per identity.
4. Keep, but isolate and document for review: the signed hash-chained ring
   log, the genesis MAC, embargo key wrapping and release, and every BLAKE3
   derivation context.

Requires: a format version bump and a migration (`vl upgrade`) that
re-seals content and re-wraps ring keys without losing access to history,
compatibility with the round-3 fixtures, and the adversarial and crash suites
staying green.

## Correctness

- **Medium: undo right after stale-working-copy recovery hides the
  recovered change.** Recoverable with `vl op restore`.

## Security and confidentiality

- **Trust on first use for key rings:** a fresh clone from a malicious remote
  can be served a valid but outdated ring. Needs a ring-head pin shared out of
  band.
- **Snapshot signatures are advisory:** no "require signed" policy yet;
  `author` is unverified.
- **Embargo metadata still visible:** that an embargo exists, parent ids,
  author, time, scope, deadline, ciphertext sizes on team remotes.
- **Scanner misses:** word-only passphrases, weak passwords, credentials
  in XML attributes (`<add key="DbPassword" value="…"/>`), camelCase
  generic tokens (`githubToken: …`), URL passwords that are words or
  numbers.
- **`DiskBackend::write` follows symlinked parent directories** if called
  directly (checkout and restore guard against it).
- **Retired identities stay on disk** (`$VEIL_HOME/retired/`, 0600) until
  the user deletes them, so vaults can be re-keyed.

## Usability

- **`vl commit` on top of a tagged change advances the tag:** developing a
  fix with `vl new main` + `vl commit` publishes it on `main` before any
  embargo. Use a separate workspace (the README tour does).
- **A quarantined file written by `ws exec` disappears with the sandbox.**
- **Non-UTF-8 file names are reported but not recorded.**

## Performance

- **Crash recovery after a takeover re-hashes up to an hour of loose
  objects** (clock-adjustment margin).
- **`gc` always rewrites everything into one in-memory pack;** no
  incremental or streaming packing yet.
- **Concurrent op-log merging:** writers serialise on the repository lock.
