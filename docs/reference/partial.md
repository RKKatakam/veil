<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl partial`

A thin clone: what it holds, the bound of its object cache, and fetching everything (`vl partial full`)

Subcommands:

* [`vl partial status`](#vl-partial-status): Show what this thin clone holds: its object cache, its bound and what the working copies pin
* [`vl partial limit`](#vl-partial-limit): Set the bound of the object cache (bytes, or with K, M or G)
* [`vl partial full`](#vl-partial-full): Fetch every snapshot and object you may see, and make this an ordinary (full) clone

## `vl partial status`

Show what this thin clone holds: its object cache, its bound and what the working copies pin

```text
vl partial status [OPTIONS]
```

## `vl partial limit`

Set the bound of the object cache (bytes, or with K, M or G)

```text
vl partial limit [OPTIONS] <SIZE>
```

Arguments:

| | |
|---|---|
| `<SIZE>` | The new bound, for instance `8G` (required) |

## `vl partial full`

Fetch every snapshot and object you may see, and make this an ordinary (full) clone

```text
vl partial full [OPTIONS]
```

---

[All commands](README.md) · [User guide](../guide/README.md)
