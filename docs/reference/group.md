<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl group`

Groups of people on the Veil server (the origin remote's project)

Subcommands:

* [`vl group list`](#vl-group-list): List the groups you are in or manage (admins: every group)
* [`vl group create`](#vl-group-create): Create a group (admins only)
* [`vl group add`](#vl-group-add): Add people to a group (admins and the group's managers). An admin device also grants them the keys of the project's secrets, on their confirmed devices only
* [`vl group remove`](#vl-group-remove): Remove people from a group (admins and the group's managers)
* [`vl group manager`](#vl-group-manager): Let people manage a group: add and remove its people (admins only)

## `vl group list`

List the groups you are in or manage (admins: every group)

```text
vl group list [OPTIONS]
```

## `vl group create`

Create a group (admins only)

```text
vl group create [OPTIONS] <NAME>
```

Arguments:

| | |
|---|---|
| `<NAME>` | (required) |

## `vl group add`

Add people to a group (admins and the group's managers). An admin device also grants them the keys of the project's secrets, on their confirmed devices only.

A person's first device must be confirmed by you: `vl` shows `confirm alice's device: 4F2A-…`; compare it with what `vl identity show` prints on alice's device, then run the command again with `--confirm`. Their later devices are confirmed by themselves (`vl identity confirm`).

```text
vl group add [OPTIONS] <GROUP> <PEOPLE>...
```

Arguments:

| | |
|---|---|
| `<GROUP>` | (required) |
| `<PEOPLE>…` | (required) |

Options:

| | |
|---|---|
| `--confirm <FINGERPRINT>` | A device fingerprint you have checked with its owner (one person at a time) |

## `vl group remove`

Remove people from a group (admins and the group's managers)

```text
vl group remove [OPTIONS] <GROUP> <PEOPLE>...
```

Arguments:

| | |
|---|---|
| `<GROUP>` | (required) |
| `<PEOPLE>…` | (required) |

## `vl group manager`

Let people manage a group: add and remove its people (admins only)

```text
vl group manager [OPTIONS] <GROUP> <PEOPLE>...
```

Arguments:

| | |
|---|---|
| `<GROUP>` | (required) |
| `<PEOPLE>…` | (required) |

---

[All commands](README.md) · [User guide](../guide/README.md)
