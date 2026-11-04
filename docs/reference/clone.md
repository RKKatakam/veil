<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl clone`

Copy a repository (and every tag you can see) into a new directory.

SOURCE is a path, `ssh://[user@]host[:port]/path` or scp-style `[user@]host:path` (through your own `ssh`; the server needs only SSH with SFTP).

```text
vl clone [OPTIONS] <SOURCE> [DEST]
```

Arguments:

| | |
|---|---|
| `<SOURCE>` | Repository to clone: a path or an SSH URL (required) |
| `<DEST>` | Directory to clone into (default: the source's last path component) |

---

[All commands](README.md) · [User guide](../guide/README.md)
