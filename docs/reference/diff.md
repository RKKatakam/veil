<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl diff`

Show changes in a snapshot, or between two snapshots

```text
vl diff [OPTIONS]
```

Options:

| | |
|---|---|
| `-r, --rev <REV>` | Snapshot whose changes to show (default: @). Not together with `--from` / `--to`, which compare two snapshots instead |
| `--from <FROM>` | Compare from this snapshot (default: @) |
| `--to <TO>` | Compare to this snapshot (default: @) |
| `--stat` | Only list changed paths |

---

[All commands](README.md) · [User guide](../guide/README.md)
