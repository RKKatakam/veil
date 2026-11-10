<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl merge`

Merge REVS into the current line of work

```text
vl merge [OPTIONS] <REVS>...
```

Arguments:

| | |
|---|---|
| `<REVS>…` | Snapshots to merge in (required) |

Options:

| | |
|---|---|
| `--into <INTO>` | Merge into this snapshot (default: @, or @- if @ is empty) |
| `-m, --message <MESSAGE>` | Description of the merge (default: "merge REVS") |
| `--embargo` | Delayed-visibility merge: the server keeps the merge and the history it brings in from anyone outside SCOPE until released (a permission; nothing is encrypted) |
| `--until <TIME>` | Release automatically at TIME (RFC 3339, YYYY-MM-DD, or +7d/+12h/+30m) |
| `--scope <SCOPE>` | Scope that can see the embargoed changes before release (default: `team`) |
| `--embargo-for <GROUP>` | Server groups that can see the embargoed changes before release (implies `--embargo`) |

---

[All commands](README.md) · [User guide](../guide/README.md)
