<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl format-patch`

Export snapshots as patch emails in Git's format, public view by default (not implemented yet)

```text
vl format-patch [OPTIONS] <REVSET>
```

Arguments:

| | |
|---|---|
| `<REVSET>` | Snapshots to export: `A..B`, `::B` or a single snapshot (required) |

Options:

| | |
|---|---|
| `-o, --output-directory <DIR>` | Write one patch file per snapshot into DIR |
| `--stdout` | Write the patches to standard output as one mbox |
| `--audience <AUDIENCE>` | Whose view to export. `me` includes cloaked content and is never the default (default: `public`; one of `public`, `me`) |
| `--include-embargoed <ID>` | With `--audience me`: also include content of this unreleased embargo (repeatable) |
| `--yes` | With `--audience me --stdout` to a pipe or file: confirm that the output holds cloaked content |
| `--cover-letter` | Also write a cover letter (patch 0) |
| `--binary` | Include binary files as `GIT binary patch` literals |
| `-M, --find-renames` | Detect renames |

---

[All commands](README.md) · [User guide](../guide/README.md)
