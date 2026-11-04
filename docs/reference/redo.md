<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl redo`

Re-apply what the latest `vl undo` took back.

Successive redos take back successive undos, newest first. Any other command after an undo leaves nothing to redo.

```text
vl redo [OPTIONS]
```

---

[All commands](README.md) · [User guide](../guide/README.md)
