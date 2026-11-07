# Known open issues

Collected from the agents' reports during the build rounds. Fixed adversarial
findings are in `docs/BUGS.md`; this file lists what is known and **not yet
fixed**. Severity: high / medium / low.

## The order (owner, 2026-11-05)

Veil is server-centric ([OVERVIEW.md](OVERVIEW.md)). The order is:

1. **Next: the Veil server and the permission model, built together**
   ([HUB.md](HUB.md) §11, [VISIBILITY.md](VISIBILITY.md)): the server, the
   database (YugabyteDB; PostgreSQL in dev and CI), object storage,
   sign-in, groups, admins, managers, folder access, `public`, encrypted
   secrets, and `vl` pushing and pulling through the server, each person
   receiving only what they may see.
2. **Then: a simplification pass.** Remove what the server makes
   unnecessary: SFTP and path remotes, offline assumptions, old storage
   formats (kept readable for `vl upgrade`) and old jargon (`cloak`,
   `scope`, `isolate`).
3. **Then: the server's features, in stages**
   ([design/scion-for-developers.md](design/scion-for-developers.md)):
   fetch on demand, server-side history and search, landing changes at
   agent scale, PR review and hidden PRs. Each is gated by the server's
   benchmark targets ([HUB.md](HUB.md) §9.2).

**Non-goals:** Git interop (permanent); offline use or plain-file remotes
(SFTP, shared drives); encrypting code.

### Client work, independent of the server
- **Copy-on-write file clones for project-directory checkouts** (`vl ws
  switch`, `vl edit`): `ws exec` sandboxes clone already
  (`StorageBackend::clone_known`); the project directory does not
  (`docs/design/scale/5-reflink-checkouts.md`).
- **Sandbox resource limits** (`docs/design/scale/8-sandbox-limits.md`).
- **Fix what the scale benchmark exposes** (the harness is built:
  `scripts/bench-scale.sh`; numbers in `docs/design/scale/BASELINE.md`; the
  ~5 GB run is still to do):
  - streaming large-file read/hash/seal (no whole file in memory);
  - content-defined chunking for large binaries (an LFS replacement).
- **Missing everyday commands:** `archive` (tarball of a snapshot).
- **Directory-rename detection in merges** (a file added on one side inside
  a directory the other side renamed goes to the new directory). Merges
  follow file renames, not directory renames.
- **Non-UTF-8 names** are not recorded.
- **Windows** support.
- **Maturity:** days of history; unaudited; no community or tutorials yet.

## Correctness

- **Medium: undo right after stale-working-copy recovery hides the
  recovered change.** Recoverable with `vl op restore`.

## Security and confidentiality

- **The identity file is protected only by file permissions:**
  `$VEIL_HOME/identity.json` (0600) holds the private keys in the clear.
  Anyone who copies it decrypts everything that member can, and an admin's
  file can grant others. Add an optional passphrase (Argon2id-wrapped keys)
  and OS keychain / hardware-key storage (macOS Keychain, Secret Service,
  FIDO2/age-plugin style), with a `vl identity protect` migration.
- **Names of sealed secret files are visible**: tree entries keep their
  names in plaintext for anyone who can read the repository.
  With the server, people without access to a folder receive neither its
  files nor their names (`docs/HUB.md` §5.4). Until then, keep secrets out
  of file and directory names.

- **Trust on first use for key rings** (today's client): a fresh clone from a
  malicious remote can be served a valid but outdated ring. With the server,
  group membership lives on the server; device keys for secrets need the
  checks in `docs/HUB.md` §6.3.
- **Snapshot signatures are advisory:** no "require signed" policy yet;
  `author` is unverified.
- **Embargo metadata still visible:** that an embargo exists, parent ids,
  author, time, its audience, deadline, ciphertext sizes.
- **Scanner misses:** word-only passphrases and passwords with spaces,
  weak passwords, URL passwords that are words or numbers, values whose
  key is on another line (except Kubernetes `value:` and XML elements),
  compressed archives (not decompressed). ~0.02–0.04 % of random
  16-character passwords are still taken for words, hashes or code (0.2 %
  of 16-character hex). The scanner v6 rules (camelCase keys, `pwd`, the
  newer `*_KEY` names, any `<WORD>_KEY`) are stricter about values: an
  unquoted value in code is not taken (`apiKey: someName,`, also a random
  one), nor a value on the next line; 0.1–0.35 % of random 16-character
  tokens (≤ 0.1 % at 20, up to 1.3 % if upper-case and digits only) are
  taken for words; `<WORD>_KEY` values need 16+ characters (32 hex).
  Keys not on the list (`credentials`, `pass`) are not seen.
- **Tags carry no provenance:** a hostile tag created by an older `vl pull`
  (before the BUG-105 fix) keeps shadowing a change id until the user
  deletes it; pulled tags are not attributed to the remote that sent them.
- **Retired identities stay on disk** (`$VEIL_HOME/retired/`, 0600) until
  the user deletes them, so vaults can be re-keyed.

## Build

- **`--all-features` does not resolve:** `vl`'s `fuse` and `macfuse`
  features name the `fuser` crate twice (`fuser` and `fuser_macos`), so
  `cargo build --all-features` and tools that run `cargo metadata
  --all-features` (cargo-nextest, docs.rs) fail. The verification script
  passes nextest default-feature metadata instead. Fix with one `fuser`
  dependency name and a cfg in code, tested on macOS.

## Usability

- **Non-UTF-8 file names are reported but not recorded.**

## Recorded limitations (later rounds)

- **Agent policy edits can be held back too eagerly:** the check that holds
  back a sandbox's or mount's weakening of `.veilpolicy` (BUG-560) treats
  any two rules as able to overlap, so an edit that only adds protection is
  occasionally held; `vl policy accept --workspace NAME` clears it.
- **Large files still pass through memory** when the FUSE mount renames a
  file it has not modified, and when the builder records a very large file
  (the streaming large-file item above).

- **Other scopes on an embargoed line** (today's client): later edits on an
  embargoed line to files cloaked under a *different* scope are readable by
  that scope's members before the release. Workaround: cloak and embargo
  under the same scope. With the server, only secrets are encrypted besides
  embargoes, so this narrows to secrets.
- **Old content keeps the old crypto:** `vl upgrade` to format 3 re-wraps
  ring keys under HPKE but never re-seals history; content sealed before the
  upgrade stays under the pre-standard construction (`docs/CRYPTO.md` §5).
- **The policy pin does not forget an accepted weakening** when a teammate
  later reverts it (only dropped `public!` rules are forgotten).
- ~~A hostile SFTP server can still force up to the 4 GiB read ceiling~~:
  gone with SFTP remotes (simplification pass, part 1).

## Optional (owner: "nice to have, not needed")

- **Admin governance:** a rogue or departed sole admin can remove everyone.
  Possible additions on the server: a minimum admin count, two-admin
  approval for removing an admin, and a break-glass recovery account.

## Performance

- Streaming `gc` and pull, incremental maintenance and the lock-free op log
  are built (scale streams G and O); see `docs/design/scale/BASELINE.md`.
