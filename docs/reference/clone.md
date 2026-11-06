<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl clone`

Copy a repository (and every tag you can see) into a new directory.

SOURCE is a Veil server project (`veil://host[:port]/project` or `https://host[:port]/project`): you receive only what you may see. Today's client also clones a path, `ssh://[user@]host[:port]/path` or scp-style `[user@]host:path` (through your own `ssh`).

```text
vl clone [OPTIONS] <SOURCE> [DEST]
```

Arguments:

| | |
|---|---|
| `<SOURCE>` | Project or repository to clone: a server URL, a path or an SSH URL (required) |
| `<DEST>` | Directory to clone into (default: the source's last path component) |

Options:

| | |
|---|---|
| `--only <DIR>` | From a Veil server: fetch only this directory's files (the server sends only that subtree's objects) |

---

[All commands](README.md) · [User guide](../guide/README.md)
