<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl remote`

Manage remotes: the Veil server projects this repository syncs with

Subcommands:

* [`vl remote add`](#vl-remote-add): Add a remote: a project on a Veil server (`veil://host[:port]/project`)
* [`vl remote list`](#vl-remote-list): List remotes
* [`vl remote rm`](#vl-remote-rm): Remove a remote

## `vl remote add`

Add a remote: a project on a Veil server (`veil://host[:port]/project`)

```text
vl remote add [OPTIONS] <NAME> <URL>
```

Arguments:

| | |
|---|---|
| `<NAME>` | Remote name (required) |
| `<URL>` | The project's server URL (required) |

## `vl remote list`

List remotes

```text
vl remote list [OPTIONS]
```

## `vl remote rm`

Remove a remote

```text
vl remote rm [OPTIONS] <NAME>
```

Arguments:

| | |
|---|---|
| `<NAME>` | Remote name (required) |

---

[All commands](README.md) · [User guide](../guide/README.md)
