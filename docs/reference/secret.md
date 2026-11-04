<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl secret`

Device-local encrypted secret vault

Subcommands:

* [`vl secret set`](#vl-secret-set): Store a secret (reads VALUE from stdin if omitted)
* [`vl secret get`](#vl-secret-get): Print a secret
* [`vl secret list`](#vl-secret-list): List secret names
* [`vl secret rm`](#vl-secret-rm): Delete a secret
* [`vl secret files`](#vl-secret-files): List the vault's backups of isolated files (`.env` & co), including those of files gone from the working copy (kept 30 days)
* [`vl secret recover`](#vl-secret-recover): Write the vault's backup of an isolated file back into the working copy (never over an existing file)
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

Options:

| | |
|---|---|
| `--json` | Print one JSON document instead of text (its schema is named in its `schema` field; see docs/reference/json.md). Errors then also print a `veil.error/1` document |

## `vl secret rm`

Delete a secret

```text
vl secret rm [OPTIONS] <NAME>
```

Arguments:

| | |
|---|---|
| `<NAME>` | Secret name (required) |

## `vl secret files`

List the vault's backups of isolated files (`.env` & co), including those of files gone from the working copy (kept 30 days)

```text
vl secret files [OPTIONS]
```

## `vl secret recover`

Write the vault's backup of an isolated file back into the working copy (never over an existing file)

```text
vl secret recover [OPTIONS] <PATH>
```

Arguments:

| | |
|---|---|
| `<PATH>` | Path of the isolated file (required) |

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
