<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl attr`

Per-path attributes from `.gitattributes`: line endings, binary files, diff and merge drivers (not implemented yet)

Subcommands:

* [`vl attr check`](#vl-attr-check): Show the attributes that apply to each path, and those Veil does not support (like `git check-attr`)

## `vl attr check`

Show the attributes that apply to each path, and those Veil does not support (like `git check-attr`)

```text
vl attr check [OPTIONS] <PATHS>...
```

Arguments:

| | |
|---|---|
| `<PATHS>…` | Paths to check (required) |

---

[All commands](README.md) · [User guide](../guide/README.md)
