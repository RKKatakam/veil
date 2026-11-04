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
- **Scanner misses:** word-only passphrases, weak passwords, credentials
  in XML attributes (`<add key="DbPassword" value="…"/>`), camelCase
  generic tokens (`githubToken: …`), URL passwords that are words or
  numbers.
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

## Performance

- **`gc` always rewrites everything into one in-memory pack;** no
  incremental or streaming packing yet.
- **Concurrent op-log merging:** writers serialise on the repository lock.
