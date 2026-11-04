<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl show`

Show a snapshot's metadata and diff

```text
vl show [OPTIONS] [REV]
```

Arguments:

| | |
|---|---|
| `<REV>` | Snapshot to show (default: `@`) |

Options:

| | |
|---|---|
| `--stat` | Only list changed paths |
| `--no-renames` | Do not detect renames (not implemented yet) |
| `-M, --find-renames [<N>]` | Detect renames; `-M=N` (or `--find-renames=N`) sets the similarity threshold in percent, default 50 (not implemented yet) |
| `-C, --find-copies` | Detect copies as well as renames (not implemented yet) |
| `--json` | Print one JSON document instead of text (its schema is named in its `schema` field; see docs/reference/json.md). Errors then also print a `veil.error/1` document |

---

[All commands](README.md) · [User guide](../guide/README.md)
