<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl log`

Show the snapshot graph

```text
vl log [OPTIONS] [PATHS]...
```

Arguments:

| | |
|---|---|
| `<PATHS>…` | Only snapshots that change these files or directories (not implemented yet) |

Options:

| | |
|---|---|
| `-n, --limit <LIMIT>` | Maximum number of snapshots to show |
| `-r, --rev <REVSET>` | Snapshots to show: `A..B` or `::B` (not implemented yet) |
| `--author <PAT>` | Only snapshots whose author matches this regular expression. The author is a claim anyone can write; see --signed-by (not implemented yet) |
| `--signed-by <MEMBER>` | Only snapshots with a verified signature by MEMBER (not implemented yet) |
| `-S <STRING>` | Only snapshots that change the number of occurrences of STRING (not implemented yet) |
| `-G <REGEX>` | Only snapshots that add or remove a line matching REGEX (not implemented yet) |
| `-i, --ignore-case` | Match -G case-insensitively (not implemented yet) |
| `--pickaxe-all` | With -S or -G, show every changed file of a matching snapshot (not implemented yet) |
| `--show-skipped` | List snapshots that could not be searched (sealed for you) instead of leaving them out (not implemented yet) |
| `--max-changes <N>` | Stop searching after this many snapshots (not implemented yet) |
| `--follow` | Follow a single file across renames (not implemented yet) |
| `--json` | Print one JSON document instead of text (its schema is named in its `schema` field; see docs/reference/json.md). Errors then also print a `veil.error/1` document |

---

[All commands](README.md) · [User guide](../guide/README.md)
