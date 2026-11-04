<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl op`

Inspect or restore the operation log

Subcommands:

* [`vl op log`](#vl-op-log): Show the operation log
* [`vl op restore`](#vl-op-restore): Restore the repository to the state after operation ID

## `vl op log`

Show the operation log

```text
vl op log [OPTIONS]
```

Options:

| | |
|---|---|
| `-n, --limit <LIMIT>` | Number of operations to show (default: `20`) |
| `--json` | Print one JSON document instead of text (its schema is named in its `schema` field; see docs/reference/json.md). Errors then also print a `veil.error/1` document |

## `vl op restore`

Restore the repository to the state after operation ID

```text
vl op restore [OPTIONS] <ID>
```

Arguments:

| | |
|---|---|
| `<ID>` | Operation id (or prefix), from `vl op log` (required) |

---

[All commands](README.md) · [User guide](../guide/README.md)
