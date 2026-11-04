<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl gc`

Pack objects and delete those no retained operation can reach.

Unreachable objects are deleted only once they have stayed unreachable for the grace period (seen by an earlier `vl gc`), so running `vl` commands are never affected.

```text
vl gc [OPTIONS]
```

Options:

| | |
|---|---|
| `--keep-ops-days <DAYS>` | Prune operations older than this many days (the current operation and its parents are always kept). Default: keep the whole op log |
| `--grace-minutes <MINUTES>` | Minutes an object must have been unreachable before deletion (default: `60`) |
| `--prune-now` | Delete unreachable objects now (grace period 0). Unsafe while another `vl` process is running |
| `--level <LEVEL>` | zstd compression level for packed objects (default: `3`) |
| `--no-deltas` | Do not delta-compress successive versions of a file |

---

[All commands](README.md) · [User guide](../guide/README.md)
