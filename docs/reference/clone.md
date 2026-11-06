<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl clone`

Copy a repository (and every tag you can see) into a new directory.

SOURCE is a Veil server project (`veil://host[:port]/project` or `https://host[:port]/project`): you receive only what you may see.

```text
vl clone [OPTIONS] <SOURCE> [DEST]
```

Arguments:

| | |
|---|---|
| `<SOURCE>` | The project's server URL: `veil://host[:port]/project` (required) |
| `<DEST>` | Directory to clone into (default: the project's name) |

Options:

| | |
|---|---|
| `--only <DIR>` | Fetch only this directory's files (the server sends only that subtree's objects) |

---

[All commands](README.md) · [User guide](../guide/README.md)
