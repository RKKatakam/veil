<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl cherry-pick`

Copy changes onto the working copy's parent: `vl duplicate REV… -d @-`, then the working copy moves on top

```text
vl cherry-pick [OPTIONS] <REVS>...
```

Arguments:

| | |
|---|---|
| `<REVS>…` | Changes to copy onto the working copy's parent, in this order (ranges such as `A..B` name several, oldest first) (required) |

Options:

| | |
|---|---|
| `--keep-description` | Keep each source's description as it is (the default; a sealed description stays sealed) |
| `-m, --message <MESSAGE>` | Description of the duplicates instead of the sources' own |
| `-x` | Append `(duplicated from change ID)` to a plain description |
| `--json` | Print one JSON document instead of text (its schema is named in its `schema` field; see docs/reference/json.md). Errors then also print a `veil.error/1` document |

---

[All commands](README.md) · [User guide](../guide/README.md)
