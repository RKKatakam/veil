# Veil

Veil (`vl`) is a version control system in Rust with per-path confidentiality: public, cloaked per scope (encrypted), and isolated (local only). It also has embargoes, secret scanning, change ids, an undoable op log, workspaces, a BLAKE3 content-addressed store, a Git bridge and SFTP remotes.

Crates:
- `crates/veil-core`: the engine;
- `crates/vl`: the CLI;
- `crates/veil-bench`: the scale benchmark, not a default workspace member.

Read `docs/ARCHITECTURE.md` (its "Threat model" section has the trust boundary), `docs/FORMAT.md` and `docs/BUGS.md`.

## Invariants (never break these)
- Cloaked, isolated and embargoed content never reaches public snapshots, remotes, the Git export, logs, JSON or error messages.
- Visibility labels are claims; objects are authority (`verify_sealing`).
- Old repository formats stay readable. A format change bumps the version and adds a `vl upgrade` path.
- Everything works offline. `veil-core` builds for WASM: Git-only code goes behind `#[cfg(feature = "git")]`.

## Checks to run, and show the output of
```sh
export CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=line-tables-only
cargo test --all-targets --no-fail-fast
cargo clippy --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
bash scripts/check-wasm.sh                 # needs target/debug/vl, so run it after the tests
cargo test --all-targets -- --ignored      # open BUG reproductions; only known bugs may fail
VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date   # after any CLI change
```

## Conventions
- **Never run `cargo fmt`.** The code base is not rustfmt-clean.
- Every bug has a `docs/BUGS.md` row and an `#[ignore = "BUG-NNN: …"]` reproduction until fixed.
- New tests join an existing test binary (`cli_security`, `core_engine`, …). Colocated tests stay in their own files.
- In tests, never name a tag that crosses a pull with only the letters k–z, and never substring-match random change ids.
- Scratch work goes in `.scratch/`, never `rm -rf` outside the worktree, and `target/` is deleted when done.
- Make the smallest change that closes the bug's whole class. Add no flags, options or abstractions the task doesn't need.
- Reviews follow the `veil-review` skill (`.claude/skills/veil-review/SKILL.md`).
