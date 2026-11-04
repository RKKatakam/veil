<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl remote`

Manage remotes

Subcommands:

* [`vl remote add`](#vl-remote-add): Add a remote: a path to another Veil repository, or an SSH remote (`ssh://[user@]host[:port]/path` or `[user@]host:path`), reached through your own `ssh` and its SFTP subsystem (`VEIL_SSH` overrides the command). Nothing but SSH is needed on the server
* [`vl remote list`](#vl-remote-list): List remotes
* [`vl remote rm`](#vl-remote-rm): Remove a remote

## `vl remote add`

Add a remote: a path to another Veil repository, or an SSH remote (`ssh://[user@]host[:port]/path` or `[user@]host:path`), reached through your own `ssh` and its SFTP subsystem (`VEIL_SSH` overrides the command). Nothing but SSH is needed on the server

```text
vl remote add [OPTIONS] <NAME> <URL>
```

Arguments:

| | |
|---|---|
| `<NAME>` | Remote name (required) |
| `<URL>` | Path or SSH URL (required) |

Options:

| | |
|---|---|
| `--public` | Public remote: cloaked content, cloaked tags and unreleased embargoes are never sent |

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
