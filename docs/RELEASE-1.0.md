# Veil 1.0.0 release checklist

1.0.0 means **the `vl` client and the Veil server, with the permission
model, stable for the owner and their team on Linux and macOS**, and a
repository format that later versions will always read. Veil is
server-centric ([OVERVIEW.md](OVERVIEW.md)): the client is always connected
to the server, which stores the code and enforces who can see what
([VISIBILITY.md](VISIBILITY.md)). 1.0.0 does **not** mean audited or ready
for the general public; that follows dogfooding and a human security
review.

The order (OVERVIEW.md):
1. **The server and the permission model, built together** ([HUB.md](HUB.md) §11).
2. **A simplification pass:** remove SFTP and path remotes, offline
   assumptions, old formats (kept readable for `vl upgrade`) and old jargon.
3. **Then the server's later features,** in stages (fetch on demand,
   server-side history and search, landing at agent scale, PR review and
   hidden PRs). These come after 1.0.0.

Process: build, then an adversarial pass, then a fix wave, repeated until the
gates below hold.

## Quality gates (all must hold)

- [ ] Every known bug in `docs/BUGS.md` fixed (remaining: scanner wave
      BUG-090–095, the concurrent first-push race in `docs/BACKLOG.md`, and
      the Fable pass's findings).
- [ ] A final adversarial pass (Opus, high effort) with **no critical or high**
      findings left open.
- [ ] `cargo test --all-targets --no-fail-fast`, `cargo clippy --all-targets
      -- -D warnings` and `RUSTDOCFLAGS=-D warnings cargo doc --no-deps
      --workspace` clean.
- [x] Test files consolidated into a few test binaries (build time and cache
      size).
- [ ] Client scale benchmark at ~1 GB and ~5 GB (init, status, commit, gc,
      push, clone, peak RAM) passes, with streaming `gc` and pull so large
      repositories do not run out of memory.
- [ ] The server's benchmark gates for what 1.0.0 ships ([HUB.md](HUB.md)
      §9.2): a small pull under 100 ms of server time, permission checks a
      negligible share, pushes landing with no global lock.

## Features in 1.0.0

Built (the client engine):

- [x] Persistent, copy-on-write `vl ws exec` sandboxes (reflinks where the
      filesystem supports them) and sparse sandboxes.
- [x] `vl blame` / annotate and history search (`log` by path, author,
      `-S`/`-G`).
- [x] Rename detection in `diff` and `log`.
- [x] Cherry-pick / duplicate.
- [x] Symlinks; line endings and per-path attributes (binary, CRLF).
- [x] Lock-free op log, two-phase resumable pushes, history index,
      background maintenance.

To build:

- [ ] The Veil server: sign-in, devices, the sync protocol and push
      validation, YugabyteDB (PostgreSQL in dev and CI), object storage.
- [ ] The permission model: admins, groups, managers, folder access
      (`vl access`), `public`; every read and push checked by the server.
- [ ] Secrets encrypted automatically and synced by folder access, with
      member devices wrapping keys for new members; personal keys never
      uploaded.
- [ ] Embargoes through the server (`--embargo-for GROUPS`).
- [ ] Moving existing repositories onto the server (`vl upgrade`; nothing
      made public or decrypted silently).
- [ ] The simplification pass.

## Release mechanics

- [ ] Version `0.1.0 → 1.0.0` (`docs/FORMAT.md` already records formats 2 and
      3 as "first readable by vl 1.0.0").
- [ ] `CHANGELOG.md` with an honest known-limitations section
      (`docs/BACKLOG.md`).
- [ ] Owner fills in `SECURITY.md`'s contact placeholder and confirms the
      copyright holder in `LICENSE-MIT`.
- [ ] Repository pushed to GitHub; CI runs green on Linux **and macOS** (the
      first real macOS run; fix what it finds).
- [ ] Tag `v1.0.0`: release binaries, installer, Homebrew formula
      (`docs/RELEASING.md`).
- [ ] Veil hosts itself: this repository moved onto Veil.

## After 1.0.0

The server's later features: fetch on demand, server-side history and
search, landing changes at agent scale, PR review and hidden PRs, the
embargo deadline worker, CI machines, the web client. Also Windows and
content-defined chunking for large files.

## Never

- **Git interop:** no import, export, sync, colocation, submodules, Git file
  formats or Git-format patches (owner decision, 2026-11-05).
- **Offline use, or plain-file remotes** (SFTP, shared drives).
- **Encrypting code.** Only secrets and embargoed changes are encrypted.
