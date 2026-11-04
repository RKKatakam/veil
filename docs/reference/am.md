<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl am`

Apply patch emails as new changes on top of a snapshot (not implemented yet)

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
| `--3way` | Fall back to a three-way merge when a patch's pre-image is known |
| `--keep-author` | Record each patch's `From:` as the change's author (the default) |
| `--author-as-me` | Record yourself as the author of every change |
| `--signoff` | Add a `Signed-off-by:` line to each description |

---

[All commands](README.md) · [User guide](../guide/README.md)
