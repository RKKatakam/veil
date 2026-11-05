# Veil 1.0.0 release checklist

1.0.0 means **stable for the owner and their team on Linux and macOS**, with
GitHub as the public mirror and SSH/SFTP or path remotes for closed content,
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

- [ ] Persistent, copy-on-write `vl ws exec` sandboxes (reflinks where the
      filesystem supports them) and sparse sandboxes.
- [ ] `vl blame` / annotate and history search (`log` by path, author,
      `-S`/`-G`).
- [ ] Rename detection in `diff` and `log`.
- [ ] Cherry-pick / duplicate.
- [ ] Symlinks; line endings and per-path attributes (binary, CRLF).
- [ ] Git tags synced by the Git bridge (GitHub releases).

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
- [ ] Veil hosts itself: this repository moved onto Veil, mirrored to GitHub.

## Deferred to 1.1 and later

Colocated Git mode (a real `.git` beside `.veil`, so IDEs and Git tools keep
working) as 1.1's headline; Windows; partial and sparse clones; content-defined
chunking for large files; first-class conflicts; `bisect`, hooks, submodules,
signed tags, `grep`, `archive`, patch export/import; the Veil Hub
(`docs/HUB.md`).
