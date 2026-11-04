# Known open issues

Collected from the agents' reports during rounds 1–2. Fixed adversarial
findings are in `docs/BUGS.md`; this file lists what is known and **not yet
fixed**. Severity: high / medium / low.

## Correctness

- **High: stale working copy when access is gained.** A file that was
  unreadable when the working copy was materialised (embargo not yet
  released, or cloned before being granted a scope) is absent on disk. When
  it becomes readable (release, grant + pull), the next snapshot records it
  as deleted. The working copy should remember what was hidden at checkout
  and fill it in once it becomes readable (`crates/vl/src/ctx.rs`,
  `checkout.rs`).
- **Medium: undo right after stale-working-copy recovery hides the
  recovered change.** Recoverable with `vl op restore`.
- **Low: `vl clone` failure leaves a half-created destination directory.**
- **Low: concurrent `vl remote add` can lose one** (`repo.json` is
  read-modify-written without the lock; local config only).

## Security and confidentiality

- **Trust on first use for key rings:** a fresh clone from a malicious remote
  can be served a valid but outdated ring. Needs a ring-head pin shared out of
  band.
- **Snapshot signatures are advisory:** no "require signed" policy yet;
  `author` is unverified.
- **Embargo metadata still visible:** that an embargo exists, parent ids,
  author, time, scope, deadline, ciphertext sizes on team remotes.
- **Scanner misses:** word-only passphrases, weak passwords, XML
  `<password>` elements, suffixed keys (`DB_PASSWORD_PROD=`).
- **`DiskBackend::write` follows symlinked parent directories** if called
  directly (checkout and restore guard against it).
- **Retired identities stay on disk** (`$VEIL_HOME/retired/`, 0600) until
  the user deletes them, so vaults can be re-keyed.
- **New warnings print paths unescaped** (unreadable/symlink/non-UTF-8
  warnings); should go through the CLI's escaping like everything else.

## Usability

- **`vl commit` on top of a tagged change advances the tag:** developing a
  fix with `vl new main` + `vl commit` publishes it on `main` before any
  embargo. Use a separate workspace (the README tour does).
- **Held-back edits on an embargoed line are reported as cloak failures**
  ("could not cloak X (held back: embargo …)"); deserves its own message.
- **A quarantined file written by `ws exec` disappears with the sandbox.**
- **Non-UTF-8 file names are reported but not recorded.**

## Performance

- **Crash recovery after a takeover re-hashes up to an hour of loose
  objects** (clock-adjustment margin).
- **`gc` always rewrites everything into one in-memory pack;** no
  incremental or streaming packing yet.
- **Concurrent op-log merging:** writers serialise on the repository lock.
