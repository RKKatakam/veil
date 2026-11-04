<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl duplicate`

Copy changes onto new parents, as new changes (not implemented yet)

```text
vl duplicate [OPTIONS] <REVS>...
```

Arguments:

| | |
|---|---|
| `<REVS>…` | Changes to duplicate (required) |

Options:

| | |
|---|---|
| `-d, --destination <DEST>` | Parent of the duplicates (repeat for a merge; default: each source's own parents) |
| `--keep-description` | Keep each source's description as it is (the default; a sealed description stays sealed) |
| `-m, --message <MESSAGE>` | Description of the duplicates instead of the sources' own |
| `-x` | Append `(duplicated from change ID)` to a plain description |
| `--json` | Print one JSON document instead of text (its schema is named in its `schema` field; see docs/reference/json.md). Errors then also print a `veil.error/1` document |

---

[All commands](README.md) · [User guide](../guide/README.md)
