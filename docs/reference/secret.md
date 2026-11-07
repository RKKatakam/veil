<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl secret`

Encrypted secrets: the device-local vault, or a scope's team vault (`--scope`), sealed for the scope's members (it does not sync through the Veil server yet); and secret files shared from one member to another (`share`, `unshare`, `shares`)

Subcommands:

* [`vl secret set`](#vl-secret-set): Store a secret (reads VALUE from stdin if omitted)
* [`vl secret get`](#vl-secret-get): Print a secret's value to stdout
* [`vl secret list`](#vl-secret-list): List secret names (never values)
* [`vl secret rm`](#vl-secret-rm): Delete a secret (in a team vault: a signed deletion that syncs)
* [`vl secret files`](#vl-secret-files): List the vault's backups of isolated files (`.env` & co), including those of files gone from the working copy (kept 30 days)
* [`vl secret recover`](#vl-secret-recover): Write the vault's backup of an isolated file back into the working copy (never over an existing file)
* [`vl secret import`](#vl-secret-import): Import KEY=VALUE lines from a dotenv file
* [`vl secret share`](#vl-secret-share): Share one secret file (`.env`, …) with another member of the project, without an admin
* [`vl secret unshare`](#vl-secret-unshare): Stop sharing a secret file with a person: they get no later version. What they already received stays theirs
* [`vl secret shares`](#vl-secret-shares): List the secret shares you make and receive (admins: every share of the project), never their content; receives what is new for you

## `vl secret set`

Store a secret (reads VALUE from stdin if omitted)

```text
vl secret set [OPTIONS] <NAME> [VALUE]
```

Arguments:

| | |
|---|---|
| `<NAME>` | Secret name (the environment variable `vl run` sets) (required) |
| `<VALUE>` | Secret value (default: read from stdin, which keeps it out of your shell history) |

Options:

| | |
|---|---|
| `--scope <SCOPE>` | Store it in this scope's team vault (sealed for its members) instead of the local vault |

## `vl secret get`

Print a secret's value to stdout

```text
vl secret get [OPTIONS] <NAME>
```

Arguments:

| | |
|---|---|
| `<NAME>` | Secret name (required) |

Options:

| | |
|---|---|
| `--scope <SCOPE>` | Read it from this scope's team vault |

## `vl secret list`

List secret names (never values)

```text
vl secret list [OPTIONS]
```

Options:

| | |
|---|---|
| `--scope <SCOPE>` | List this scope's team vault, with who last set each name and when |
| `--exposed-to <MEMBER>` | Only the names MEMBER (public key, member id or name; current or revoked) could read: the secrets to rotate when they leave |
| `--json` | Print one JSON document instead of text (its schema is named in its `schema` field; see docs/reference/json.md). Errors then also print a `veil.error/1` document |

## `vl secret rm`

Delete a secret (in a team vault: a signed deletion that syncs)

```text
vl secret rm [OPTIONS] <NAME>
```

Arguments:

| | |
|---|---|
| `<NAME>` | Secret name (required) |

Options:

| | |
|---|---|
| `--scope <SCOPE>` | Delete it from this scope's team vault |

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

## `vl secret share`

Share one secret file (`.env`, …) with another member of the project, without an admin.

A copy of that one file is sealed on this device for the person's confirmed devices only (confirmed outside the server, as for every key): it opens nothing else of its folder. Your later edits of the file, and their newly confirmed devices, reach them in the background until you unshare it. Admins see that it is shared (who, what path, when), never what it holds. Their `vl pull` writes it at the same path, where it stays on their device (and reaches their agents with `vl ws exec --with-isolated`).

```text
vl secret share [OPTIONS] --with <PERSON> <PATH>
```

Arguments:

| | |
|---|---|
| `<PATH>` | The secret file, in the working copy (required) |

Options:

| | |
|---|---|
| `--with <PERSON>` | The person to share it with (required) |
| `--confirm <FINGERPRINT>` | A device fingerprint of theirs you compared with them (needed when no key ring records a device of theirs yet) |
| `--json` | Print one JSON document instead of text (its schema is named in its `schema` field; see docs/reference/json.md). Errors then also print a `veil.error/1` document |

## `vl secret unshare`

Stop sharing a secret file with a person: they get no later version. What they already received stays theirs

```text
vl secret unshare [OPTIONS] --from <PERSON> <PATH>
```

Arguments:

| | |
|---|---|
| `<PATH>` | The secret file (required) |

Options:

| | |
|---|---|
| `--from <PERSON>` | The person you shared it with (required) |
| `--json` | Print one JSON document instead of text (its schema is named in its `schema` field; see docs/reference/json.md). Errors then also print a `veil.error/1` document |

## `vl secret shares`

List the secret shares you make and receive (admins: every share of the project), never their content; receives what is new for you

```text
vl secret shares [OPTIONS]
```

Options:

| | |
|---|---|
| `--json` | Print one JSON document instead of text (its schema is named in its `schema` field; see docs/reference/json.md). Errors then also print a `veil.error/1` document |

---

[All commands](README.md) · [User guide](../guide/README.md)
