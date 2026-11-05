<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl undo`

Undo the last operation; run again to go further back.

Automatic snapshots (your unrecorded edits) and earlier undos are skipped, and the edits on disk are kept. Only commands run in this workspace (and repository-wide ones: tags, push, pull, remotes) are undone: what other workspaces did since stays. `vl redo` re-applies what the latest undos took back.

```text
vl undo [OPTIONS]
```

Options:

| | |
|---|---|
| `--op <ID>` | Undo this operation (id or prefix, from `vl op log`) instead of the last command; what other operations changed since stays |

---

[All commands](README.md) · [User guide](../guide/README.md)
