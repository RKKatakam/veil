# Veil 1.0.0 release checklist

1.0.0 means **stable for the owner and their team on Linux and macOS**, with
SSH/SFTP or path remotes (team and public),
and a repository format that later versions will always read. It does
**not** mean audited or ready for the general public; that follows
dogfooding and a human security review.

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
- [ ] Scale benchmark at ~1 GB and ~5 GB (init, status, commit, gc, push,
      clone, peak RAM) passes, with streaming `gc` and pull so large
      repositories do not run out of memory.

## Features in 1.0.0

- [x] Persistent, copy-on-write `vl ws exec` sandboxes (reflinks where the
      filesystem supports them) and sparse sandboxes.
- [x] `vl blame` / annotate and history search (`log` by path, author,
      `-S`/`-G`).
- [x] Rename detection in `diff` and `log`.
- [x] Cherry-pick / duplicate.
- [x] Symlinks; line endings and per-path attributes (binary, CRLF).

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

## Deferred to 1.1 and later

Windows; partial and sparse clones; content-defined chunking for large files;
first-class conflicts; `bisect`, hooks, signed tags, `grep`, `archive`; the
Veil Hub (`docs/HUB.md`). Never: Git interop (no import, export, sync,
colocation, submodules, Git file formats or Git-format patches; owner
decision, 2026-11-05).
