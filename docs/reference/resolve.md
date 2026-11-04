<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl resolve`

List unresolved conflicts, or resolve one by keeping one of its versions.

With no `--ours`/`--theirs`/`--base`/`--side`, lists the conflicts of the working copy (or `-r REV`): each version with who can read it. Otherwise each conflict at or below PATHS in the working copy is replaced by the version named, exactly as it is recorded: a version sealed for a scope stays sealed for that scope, and a version with no file removes the path. To combine the versions instead, edit the file: a conflict is resolved once its markers are gone.

```text
vl resolve [OPTIONS] [PATHS]...
```

Arguments:

| | |
|---|---|
| `<PATHS>…` | Conflicted files (or directories) to resolve |

Options:

| | |
|---|---|
| `-l, --list` | List the conflicts (the default without a version to keep) |
| `--ours` | Keep the first side: the change merged into (for a rebase, the new parent) |
| `--theirs` | Keep the other side of a two-sided conflict |
| `--base` | Keep the base of a two-sided conflict |
| `--side <N>` | Keep side N (1-based) of a conflict with any number of sides |
| `-r, --rev <REV>` | Snapshot whose conflicts to list (default: `@`) |
| `--json` | Print one JSON document instead of text (its schema is named in its `schema` field; see docs/reference/json.md). Errors then also print a `veil.error/1` document |

---

[All commands](README.md) · [User guide](../guide/README.md)
