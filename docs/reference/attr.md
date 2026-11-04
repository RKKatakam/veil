<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl attr`

Per-path attributes from `.gitattributes`: line endings, binary files, diff and merge drivers

Subcommands:

* [`vl attr check`](#vl-attr-check): Show the attributes that apply to each path (like `git check-attr -a`), what Veil does with them (line endings, diff, merge), and those Veil does not support

## `vl attr check`

Show the attributes that apply to each path (like `git check-attr -a`), what Veil does with them (line endings, diff, merge), and those Veil does not support.

Read from the working copy's `.gitattributes` files and the device-local `.veil/local/attributes`.

```text
vl attr check [OPTIONS] <PATHS>...
```

Arguments:

| | |
|---|---|
| `<PATHS>…` | Paths to check (they need not exist) (required) |

Options:

| | |
|---|---|
| `--json` | Print one JSON document instead of text (its schema is named in its `schema` field; see docs/reference/json.md). Errors then also print a `veil.error/1` document |

---

[All commands](README.md) · [User guide](../guide/README.md)
