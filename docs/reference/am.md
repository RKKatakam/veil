<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl am`

Apply patch emails (Git's `format-patch` output, or a plain diff) as new changes on top of a snapshot.

One change per patch, keeping its author, date and message; all or nothing. Each patch is recorded like an incoming change: secrets are quarantined (which aborts the series), a weakening `.veilpolicy` is held back, and hostile paths are refused.

```text
vl am [OPTIONS] <INPUT>
```

Arguments:

| | |
|---|---|
| `<INPUT>` | An mbox or patch file, a directory of them, or `-` for standard input (required) |

Options:

| | |
|---|---|
| `-d, --destination <DEST>` | Apply the series on top of this snapshot (default: `@-`) |
| `-3, --3way` | When a hunk does not apply, merge three ways with the version the patch was made from (its `index` line), if this repository's history of the file holds it. A conflict is recorded as a conflict of the new change, for `vl resolve` |
| `--keep-author` | Record each patch's `From:` as the change's author (the default) |
| `--author-as-me` | Record yourself as the author of every change |
| `--signoff` | Add a `Signed-off-by:` line to each description |

---

[All commands](README.md) · [User guide](../guide/README.md)
