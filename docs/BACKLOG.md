# Known open issues

Collected from the agents' reports during rounds 1–2. Fixed adversarial
findings are in `docs/BUGS.md`; this file lists what is known and **not yet
fixed**. Severity: high / medium / low.

## Before the Hub (owner-approved order: after all bugs are fixed)

### Agent workspaces and scale
- **Copy-on-write file clones for project-directory checkouts** (`vl ws
  switch`, `vl edit`): `ws exec` sandboxes clone already
  (`StorageBackend::clone_known`); the project directory does not.
- **Sparse sandboxes:** `vl ws exec --only src/ tests/`.
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
- **Colocated Git mode:** a real `.git` next to `.veil` (as Jujutsu does) so
  IDEs, GUIs, `git blame`, pre-commit and other Git tools keep working.
- **Missing everyday commands:** `blame`/annotate, `bisect`,
  cherry-pick/duplicate, history
  search (`log -S`/`-G`, path and author filters), `grep` over a snapshot,
  `archive` (tarball of a snapshot), patch export/import.
- **Rename and copy detection** in `diff`, `log` and merge (today a rename is
  a delete plus an add, and merges are not rename-aware).
- **Repository attributes:** line-ending normalisation (CRLF), per-path diff
  and merge drivers, binary handling (`.gitattributes` equivalents).
- **Symlinks** are ignored; non-UTF-8 names are not recorded; submodules are
  not supported.
- **Hooks** (pre-commit / pre-push) and signed tags and releases.
- **Git bridge gaps:** tags are not synced; author time zones become UTC.
- **Windows** support.
- **Maturity:** days of history versus Git's two decades; unaudited; no
  community, tutorials or Stack Overflow answers yet.

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
- **`DiskBackend::write` follows symlinked parent directories** if called
  directly (checkout and restore guard against it).
- **Tags carry no provenance:** a hostile tag created by an older `vl pull`
  (before the BUG-105 fix) keeps shadowing a change id until the user
  deletes it; pulled tags are not attributed to the remote that sent them.
- **Retired identities stay on disk** (`$VEIL_HOME/retired/`, 0600) until
  the user deletes them, so vaults can be re-keyed.

## Usability

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
