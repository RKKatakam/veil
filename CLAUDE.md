# Veil

Veil (`vl`) is a version control system in Rust with per-path confidentiality: public, cloaked per scope (encrypted), and isolated (local only). It also has embargoes, secret scanning, change ids, an undoable op log, workspaces, a BLAKE3 content-addressed store and SFTP remotes.

Crates:
- `crates/veil-core`: the engine;
- `crates/vl`: the CLI;
- `crates/veil-bench`: the scale benchmark, not a default workspace member.

Read `docs/ARCHITECTURE.md` (its "Threat model" section has the trust boundary), `docs/FORMAT.md` and `docs/BUGS.md`.

## Who can see what
**`docs/VISIBILITY.md` is the source of truth** for access, encryption, sharing, agents and the Hub. In short: one repository; paths are **public** (the internet), **company** (plaintext, enforced by the Hub's permission check), **secret** (`.env` and the like: the only encrypted tier, shared with the company by default) or **isolated** (never leaves the machine). Read it before designing anything about access.

## Invariants (never break these)
- Veil does not interoperate with Git (no import, export, sync, colocation, submodules, Git file formats or Git-format patches). Owner decision, 2026-11-05: permanent.
- Company, secret (cloaked), isolated and embargoed content never reaches public snapshots, public remotes, logs, JSON or error messages. Secret content is only ever stored encrypted. Isolated content never leaves the machine.
- Visibility labels are claims; objects are authority (`verify_sealing`).
- Old repository formats stay readable. A format change bumps the version and adds a `vl upgrade` path.
- Everything works offline. `veil-core` builds for WASM: OS-only code goes behind `#[cfg(feature = "os")]`.

## Checks to run, and show the output of
```sh
export CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=line-tables-only
# The whole check (~5 min): nextest + clippy + rustdoc in parallel, then WASM and ignored BUG tests.
# Prefer this to plain `cargo test --all-targets` (~25 min). It deletes target/ at the end.
bash ~/.cache/veil-orch/verify-fast.sh <name>
# While iterating, one test binary at a time:
cargo test -p vl --test cli_security -- <test name>
VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date   # after any CLI change
```

## Conventions
- **Never run `cargo fmt`.** The code base is not rustfmt-clean.
- Every bug has a `docs/BUGS.md` row and an `#[ignore = "BUG-NNN: …"]` reproduction until fixed.
- New tests join an existing test binary (`cli_security`, `core_engine`, …).
- In tests, never name a tag that crosses a pull with only the letters k–z, and never substring-match random change ids.
- Scratch work goes in `.scratch/`, never `rm -rf` outside the worktree, and `target/` is deleted when done.
- Make the smallest change that closes the bug's whole class. Add no flags, options or abstractions the task doesn't need.
- Reviews follow the `veil-review` skill (`.claude/skills/veil-review/SKILL.md`).
