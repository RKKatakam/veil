<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl ls`

List a snapshot's files with their tier: who can read each one, and what never leaves this machine.

One line per file: tier, size in bytes, path (`*` marks an executable), and a note in parentheses. Tiers: `public`; `embargoed` (plain, but an unreleased embargo withholds this version: no push sends it before the release); `cloaked:<scope>` (a secret file encrypted for a scope you are in); `redacted` (a secret sealed for someone else, or withheld from this repository: the note says for whom). For the working copy (`-r @`, the default) the local-only files are listed too: `isolated` (never snapshotted or pushed), `quarantined` (a secret was found in it) and, with `--all`, `ignored`. No content is ever printed.

```text
vl ls [OPTIONS] [PATHS]...
```

Arguments:

| | |
|---|---|
| `<PATHS>…` | Files or directories to list (default: all) |

Options:

| | |
|---|---|
| `-r, --rev <REV>` | Snapshot to list (default: `@`) |
| `-a, --all` | Also list ignored files and directories (working copy only) |
| `--json` | Print one JSON document instead of text (its schema is named in its `schema` field; see docs/reference/json.md). Errors then also print a `veil.error/1` document |

---

[All commands](README.md) · [User guide](../guide/README.md)
