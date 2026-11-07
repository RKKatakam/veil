# Veil

Veil (`vl`) is a **server-centric** version control system in Rust. **It is not Git and not offline-first:** the `vl` client is always connected to the Veil server (the Hub), which stores the code and enforces permissions. Access is the ordinary model in `docs/VISIBILITY.md`; code is plain text on the server, and only secrets are encrypted (embargoes are server-enforced permissions that turn public at a deadline). Read `docs/OVERVIEW.md` first. The built client engine has embargoes, secret scanning, change ids, an undoable op log, workspaces (with `vl ws exec` confined by bubblewrap on Linux) and a BLAKE3 content-addressed store. The server's milestone S1 is built (`docs/HUB.md` §13), and `vl` syncs only through it: path and SFTP remotes were removed in the simplification pass, part 1 (debug builds keep path remotes as a test fixture, `crates/vl/src/test_remotes.rs`, active only with `VEIL_TEST_PATH_REMOTES`). Part 2 removed every encryption but that of secret files (repository format 8).

Crates:
- `crates/veil-core`: the engine;
- `crates/vl`: the CLI;
- `crates/veil-server`: the Veil server (axum, sqlx for PostgreSQL/YugabyteDB, S3), not a default workspace member;
- `crates/veil-bench`: the scale benchmark and the OpenScion speed gates, not a default workspace member.

Read `docs/OVERVIEW.md`, `docs/VISIBILITY.md`, `docs/HUB.md` (the server design), `docs/ARCHITECTURE.md` (its "Threat model" section has the trust boundary), `docs/FORMAT.md` and `docs/BUGS.md`.

## Who can see what
**`docs/VISIBILITY.md` is the source of truth. Keep it simple; it's the ordinary permission model:**
- the creator is the admin;
- everything is **private** by default (admins only);
- admins create **groups**, add people, choose **group managers**, and give groups or people access to folders (`vl access billing/ finance`);
- **`public`** folders are visible to everyone on Earth.

Veil automatically **encrypts secrets** (`.env`, keys), which follow the same permissions, and keeps **personal private keys** on the machine. There is no separate company or team tier.

## Invariants (never break these)
- Veil does not interoperate with Git (no import, export, sync, colocation, submodules, Git file formats or Git-format patches). Owner decision, 2026-11-05: permanent.
- Private, secret and embargoed content never reaches public snapshots, public remotes, logs, JSON or error messages, and nobody receives a file they have no access to. Secrets are only ever stored encrypted. Personal private keys never leave the machine.
- **Only secret files (`.env`, keys) are ever encrypted.** Never encrypt code, descriptions, tags, embargoes, PRs or attribution; they are plain text behind the server's permissions (`docs/VISIBILITY.md`, "What is encrypted").
- Visibility labels are claims; objects are authority (`verify_sealing`).
- Old repository formats stay upgradable: a format change bumps the version and adds a `vl upgrade` path, which converts or clearly refuses, never drops silently. (Formats 1 to 5 were dropped with the owner's approval, 2026-11-06: format 8 opens only format 8, and upgrades 6 and 7.)
- **Veil is server-centric** (owner, 2026-11-05): the client is always connected to the Veil server, and the server enforces every permission. There is no offline mode and no plain-file remotes (SFTP); don't design for them. `veil-core` builds for WASM (the server's web client uses it): OS-only code goes behind `#[cfg(feature = "os")]`.

## Checks to run, and show the output of
```sh
export CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=line-tables-only
# The whole check (~5 min): nextest + clippy + rustdoc in parallel, then WASM and ignored BUG tests.
# Prefer this to plain `cargo test --all-targets` (~25 min). It deletes target/ at the end.
bash ~/.cache/veil-orch/verify-fast.sh <name>
# While iterating, one test binary at a time:
cargo test -p vl --test cli_security -- <test name>
VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date   # after any CLI change
# The server against PostgreSQL, YugabyteDB and MinIO in Docker (~5 min; not in verify-fast):
bash scripts/verify-server.sh
```

## Conventions
- **Never run `cargo fmt`.** The code base is not rustfmt-clean.
- Every bug has a `docs/BUGS.md` row and an `#[ignore = "BUG-NNN: …"]` reproduction until fixed.
- New tests join an existing test binary (`cli_security`, `core_engine`, …).
- In tests, never name a tag that crosses a pull with only the letters k–z, and never substring-match random change ids.
- Scratch work goes in `.scratch/`, never `rm -rf` outside the worktree, and `target/` is deleted when done.
- Make the smallest change that closes the bug's whole class. Add no flags, options or abstractions the task doesn't need.
- Reviews follow the `veil-review` skill (`.claude/skills/veil-review/SKILL.md`).
