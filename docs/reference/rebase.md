<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl rebase`

Move a change (and its descendants) onto new parents

```text
vl rebase [OPTIONS] --destination <DESTINATION>
```

Options:

| | |
|---|---|
| `-s, --source <SOURCE>` | Change to move; its descendants follow (default: `@`; also `-r`) |
| `-d, --destination <DESTINATION>` | New parent (repeat for a merge) (required) |

---

[All commands](README.md) · [User guide](../guide/README.md)
