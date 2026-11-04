<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl undo`

Undo the last operation; run again to go further back.

Automatic snapshots (your unrecorded edits) and earlier undos are skipped, and the edits on disk are kept. `vl redo` re-applies what the latest undos took back.

```text
vl undo [OPTIONS]
```

---

[All commands](README.md) · [User guide](../guide/README.md)
