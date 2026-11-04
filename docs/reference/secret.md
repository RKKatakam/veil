<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl secret`

Device-local encrypted secret vault

Subcommands:

* [`vl secret set`](#vl-secret-set): Store a secret (reads VALUE from stdin if omitted)
* [`vl secret get`](#vl-secret-get): Print a secret
* [`vl secret list`](#vl-secret-list): List secret names
* [`vl secret rm`](#vl-secret-rm): Delete a secret
* [`vl secret import`](#vl-secret-import): Import KEY=VALUE lines from a dotenv file

## `vl secret set`

Store a secret (reads VALUE from stdin if omitted)

```text
vl secret set [OPTIONS] <NAME> [VALUE]
```

Arguments:

| | |
|---|---|
| `<NAME>` | Secret name (the environment variable `vl run` sets) (required) |
| `<VALUE>` | Secret value (default: read from stdin) |

## `vl secret get`

Print a secret

```text
vl secret get [OPTIONS] <NAME>
```

Arguments:

| | |
|---|---|
| `<NAME>` | Secret name (required) |

## `vl secret list`

List secret names

```text
vl secret list [OPTIONS]
```

## `vl secret rm`

Delete a secret

```text
vl secret rm [OPTIONS] <NAME>
```

Arguments:

| | |
|---|---|
| `<NAME>` | Secret name (required) |

## `vl secret import`

Import KEY=VALUE lines from a dotenv file

```text
vl secret import [OPTIONS] <FILE>
```

Arguments:

| | |
|---|---|
| `<FILE>` | Dotenv file to read (required) |

---

[All commands](README.md) · [User guide](../guide/README.md)
