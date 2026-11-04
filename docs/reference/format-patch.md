<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl format-patch`

Export snapshots as patch emails in Git's format.

The default view is the public one: exactly what `vl git push` shows (no cloaked files or descriptions, nothing of an unreleased embargo). `--audience me` includes what you can read, and says so.

```text
vl format-patch [OPTIONS] <REVSET>
```

Arguments:

| | |
|---|---|
| `<REVSET>` | Snapshots to export: `A..B` (ancestors of B that are not ancestors of A), `::B` (every ancestor of B) or a single snapshot (required) |

Options:

| | |
|---|---|
| `-o, --output-directory <DIR>` | Write one patch file per snapshot into DIR (default: the current directory) |
| `--stdout` | Write the patches to standard output as one mbox |
| `--audience <AUDIENCE>` | Whose view to export. `me` includes cloaked content and is never the default (default: `public`; one of `public`, `me`) |
| `--include-embargoed <ID>` | With `--audience me`: also include content of this unreleased embargo (repeatable) |
| `--yes` | With `--audience me --stdout` to a pipe or file: confirm that the output holds cloaked content |
| `--cover-letter` | Also write a cover letter (patch 0) |
| `--binary` | Include binary files as `GIT binary patch` literals (not supported yet: binary files are shown as `Binary files … differ`) |
| `-M, --find-renames` | Detect renames (not available yet: a rename shows as a deletion and an addition) |

---

[All commands](README.md) · [User guide](../guide/README.md)
