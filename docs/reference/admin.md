<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl admin`

Admins of the project on the Veil server (the origin remote's project)

Subcommands:

* [`vl admin list`](#vl-admin-list): List the project's admins
* [`vl admin add`](#vl-admin-add): Make people admins of the project (admins only). An admin device also grants them the keys of the project's secrets, on their confirmed devices only
* [`vl admin remove`](#vl-admin-remove): Remove people as admins of the project (admins only; never the last admin)

## `vl admin list`

List the project's admins

```text
vl admin list [OPTIONS]
```

## `vl admin add`

Make people admins of the project (admins only). An admin device also grants them the keys of the project's secrets, on their confirmed devices only.

A person's first device must be confirmed by you: `vl` shows `confirm alice's device: 4F2A-…`; compare it with what `vl identity show` prints on alice's device, then run the command again with `--confirm`. Their later devices are confirmed by themselves (`vl identity confirm`).

```text
vl admin add [OPTIONS] <PEOPLE>...
```

Arguments:

| | |
|---|---|
| `<PEOPLE>…` | (required) |

Options:

| | |
|---|---|
| `--confirm <FINGERPRINT>` | A device fingerprint you have checked with its owner (one person at a time) |

## `vl admin remove`

Remove people as admins of the project (admins only; never the last admin)

```text
vl admin remove [OPTIONS] <PEOPLE>...
```

Arguments:

| | |
|---|---|
| `<PEOPLE>…` | (required) |

---

[All commands](README.md) · [User guide](../guide/README.md)
