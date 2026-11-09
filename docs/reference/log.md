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
| `<PATHS>…` | Only snapshots that change these files or directories |

Options:

| | |
|---|---|
| `-n, --limit <LIMIT>` | Maximum number of snapshots to show |
| `-r, --rev <REVSET>` | Snapshots to show: `X`, `A..B`, `::B`, `..B` or `A..` |
| `--author <PAT>` | Only snapshots whose author matches this regular expression. The author is a claim anyone who can push writes; --signed-by is the authenticated filter |
| `--signed-by <MEMBER>` | Only snapshots with a good signature by MEMBER (a member name or member id, as verified by your key rings) |
| `--agent <PATTERN>` | Only snapshots made by an agent whose name matches PATTERN (the name exactly, or a glob such as `claude-*`); the same as `-r 'agent(PATTERN)'` |
| `-S <STRING>` | Only snapshots that change the number of occurrences of STRING in a file you can read |
| `-G <REGEX>` | Only snapshots that add or remove a line matching REGEX in a file you can read |
| `-i, --ignore-case` | Match -S, -G and --author case-insensitively |
| `--pickaxe-all` | With -S or -G, list every changed file of a matching snapshot |
| `--show-skipped` | List snapshots that could not be searched (sealed for you) instead of leaving them out |
| `--max-changes <N>` | Stop searching after this many snapshots (default with -S or -G: 100000) |
| `--follow` | Follow a single file across renames |
| `--json` | Print one JSON document instead of text (its schema is named in its `schema` field; see docs/reference/json.md). Errors then also print a `veil.error/1` document |

---

[All commands](README.md) · [User guide](../guide/README.md)
