# Known open issues

Collected from the agents' reports during rounds 1–2. Fixed adversarial
findings are in `docs/BUGS.md`; this file lists what is known and **not yet
fixed**. Severity: high / medium / low.

## Before the Hub (owner-approved order: after all bugs are fixed)

> **Scion for developers** (`docs/design/scion-for-developers.md`, added
> 2026-11-04): a server-centred, agent-scale roadmap on top of the Hub.
> Its **phase 0** belongs here, in the scale round after Git parity:
> lock-free SFTP writes (pack first, lock only for the branch update),
> a lock-free op log, a history (commit-graph) index, the scale
> benchmark (including a mostly-cloaked profile), background cleanup
> instead of whole-store `gc`, and streaming Git import. Phases 1–4 are
> Hub work.

### Agent workspaces and scale
- **Copy-on-write file clones for project-directory checkouts** (`vl ws
  switch`, `vl edit`): `ws exec` sandboxes clone already
  (`StorageBackend::clone_known`); the project directory does not.
- **Scale benchmark** at 1 GB and ~5 GB (init, status, commit, gc, push,
  clone, peak RAM), then fix what it exposes:
  - streaming / incremental `gc` (no whole-store pack in memory);
  - streaming pull (packs written to disk, not held in RAM);
  - streaming large-file read/hash/seal (no whole file in memory);
  - content-defined chunking for large binaries (an LFS replacement);
  - partial and sparse clone;
  - a history index (like Git's commit-graph) so commands stop walking all
    history;
  - concurrent op-log merging instead of one repository lock.

### Gaps compared with Git and GitHub (core, before the Hub)
- **Colocated Git mode: experimental.** Shipped behind `--experimental`
  (`vl init --colocate`, `vl git colocate`; `docs/guide/colocated-git.md`).
  Left before it loses the flag: a dedicated adversarial pass, the
  Git-version matrix on 2.25 / 2.39 / latest and on macOS (tested with Git
  2.53 on Linux only), `vl serve`'s watch loop following Git, local Git tags
  imported as release tags (Git-side tags are not followed yet), and the
  skip-worktree entry for excluded paths present in other exported commits
  (design threat 8).
- **Missing everyday commands:** `archive` (tarball of a snapshot).
- **Directory-rename detection in merges** (Git's `ort`: a file added on one
  side inside a directory the other side renamed goes to the new
  directory). Merges follow file renames, not directory renames.
- **Non-UTF-8 names** are not recorded.
- **Git bridge gaps:** author time zones become UTC; Veil does not sign Git
  tags (GitHub shows release tags unverified).
- **Windows** support.
- **Maturity:** days of history versus Git's two decades; unaudited; no
  community, tutorials or Stack Overflow answers yet.

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
- **Names of cloaked files are visible:** tree entries keep their names in
  plaintext for anyone who can read the repository; only contents are
  sealed (sealed directory names need a future format bump, see
  `docs/HUB.md`). Until then, keep secrets out of file and directory names.

- **Trust on first use for key rings:** a fresh clone from a malicious remote
  can be served a valid but outdated ring. Needs a ring-head pin shared out of
  band.
- **Snapshot signatures are advisory:** no "require signed" policy yet;
  `author` is unverified.
- **Embargo metadata still visible:** that an embargo exists, parent ids,
  author, time, scope, deadline, ciphertext sizes on team remotes.
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

- **Other scopes on an embargoed line:** later edits on an embargoed line to
  files cloaked under a *different* scope are readable by that scope's
  members before the release. Workaround: cloak and embargo under the same
  scope.
- **Old content keeps the old crypto:** `vl upgrade` to format 3 re-wraps
  ring keys under HPKE but never re-seals history; content sealed before the
  upgrade stays under the pre-standard construction (`docs/CRYPTO.md` §5).
- **The policy pin does not forget an accepted weakening** when a teammate
  later reverts it (only dropped `public!` rules are forgotten).
- **Author time zones** are exported to Git as UTC.
- **Git maps from before the BUG-063 fix** carry no embargo "veil" for
  imported commits; delete `.veil/git/map` once to rebuild it.
- **SFTP lease renewals can stall on slow uplinks** (below roughly 4 Mbit/s,
  behind large pack writes), fencing the push; a per-operation in-flight cap
  would fix it.
- **A hostile SFTP server can still force up to the 4 GiB read ceiling**
  (`VEIL_SFTP_MAX_FILE`), since sizes come from the server.

## Optional (owner: "nice to have, not needed")

- **Scope governance:** a rogue or departed sole admin can revoke everyone;
  recovery today is manual (new scope, re-cloak, rotate real secrets).
  Possible additions: hold suspicious ring changes for `vl scope accept`,
  two-admin approval for admin revocations, a minimum admin count, a
  break-glass offline recovery identity, and a `vl scope recover` command
  that automates the re-key. Belongs with the Veil Hub's organisation model.

## Performance

- **`gc` always rewrites everything into one in-memory pack;** no
  incremental or streaming packing yet.
- **Concurrent op-log merging:** writers serialise on the repository lock.
