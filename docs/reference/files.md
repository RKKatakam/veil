<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl files`

List the files of a snapshot with their visibility.

The plain listing of recorded files, kept unchanged for scripts. `vl ls` shows more: tiers as this reader sees them, and the working copy's local-only files.

```text
vl files [OPTIONS]
```

Options:

| | |
|---|---|
| `-r, --rev <REV>` | Snapshot to list (default: `@`) |

---

[All commands](README.md) · [User guide](../guide/README.md)
