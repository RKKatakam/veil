# Known open issues

Collected from the agents' reports during rounds 1–2. Fixed adversarial
findings are in `docs/BUGS.md`; this file lists what is known and **not yet
fixed**. Severity: high / medium / low.

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
- **Scanner misses:** word-only passphrases and passwords with spaces,
  weak passwords, camelCase generic tokens (`githubToken: …`), URL
  passwords that are words or numbers, `*_KEY` names beyond the common
  ones, XML attributes other than `value`, values whose key is on another
  line (except Kubernetes `value:`), compressed archives (not
  decompressed). ~0.02–0.04 % of random 16-character passwords are still
  taken for words, hashes or code (0.2 % of 16-character hex).
- **Scanner throughput:** scanner v4 (BUG-090…095) is ~2× slower than v3
  on keyword-dense text (300–450 MiB/s vs 700–950 MiB/s; ~1.5 GiB/s on
  real source trees): every `key = expr` code line is now a candidate for
  the rest-of-line rule. A cheaper pre-filter for code lines would win it
  back.
- **`DiskBackend::write` follows symlinked parent directories** if called
  directly (checkout and restore guard against it).
- **Retired identities stay on disk** (`$VEIL_HOME/retired/`, 0600) until
  the user deletes them, so vaults can be re-keyed.

## Usability

- **A quarantined file written by `ws exec` disappears with the sandbox.**
- **Non-UTF-8 file names are reported but not recorded.**

## Recorded limitations (later rounds)

- **Other scopes on an embargoed line:** later edits on an embargoed line to
  files cloaked under a *different* scope are readable by that scope's
  members before the release. Workaround: cloak and embargo under the same
  scope.
- **Old content keeps the old crypto:** `vl upgrade` to format 3 re-wraps
  ring keys under HPKE but never re-seals history; content sealed before the
  upgrade stays under the pre-standard construction (`docs/CRYPTO.md` §5).
- **The policy pin does not forget an accepted weakening** when a teammate
  later reverts it (only dropped `public!` rules are forgotten).
- **Git tags are not synced** by the Git bridge (branches only); author time
  zones are exported as UTC.
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
