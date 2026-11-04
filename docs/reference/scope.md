<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl scope`

Key scopes and their members (identity rings)

Subcommands:

* [`vl scope list`](#vl-scope-list): List scopes and members
* [`vl scope create`](#vl-scope-create): Create a scope with you as the only member
* [`vl scope grant`](#vl-scope-grant): Give an identity access to a scope (admins only). Use the full public key from `vl identity show` so the member's signatures are recognised
* [`vl scope revoke`](#vl-scope-revoke): Remove an identity from a scope and rotate its key (admins only)
* [`vl scope rotate`](#vl-scope-rotate): Start a new key generation for the current members (admins only)
* [`vl scope log`](#vl-scope-log): Show the signed membership log of a scope

## `vl scope list`

List scopes and members

```text
vl scope list [OPTIONS]
```

## `vl scope create`

Create a scope with you as the only member

```text
vl scope create [OPTIONS] <NAME>
```

Arguments:

| | |
|---|---|
| `<NAME>` | Scope name (required) |

## `vl scope grant`

Give an identity access to a scope (admins only). Use the full public key from `vl identity show` so the member's signatures are recognised

```text
vl scope grant [OPTIONS] <SCOPE> <PUBLIC_KEY>
```

Arguments:

| | |
|---|---|
| `<SCOPE>` | Scope name (required) |
| `<PUBLIC_KEY>` | The member's full public key, from their `vl identity show` (required) |

Options:

| | |
|---|---|
| `--name <NAME>` | Display name for the member (default: `member`) |
| `--admin` | Make the member an admin (may grant, revoke and rotate) |

## `vl scope revoke`

Remove an identity from a scope and rotate its key (admins only)

```text
vl scope revoke [OPTIONS] <SCOPE> <PUBLIC_KEY>
```

Arguments:

| | |
|---|---|
| `<SCOPE>` | Scope name (required) |
| `<PUBLIC_KEY>` | The member's public key or member id (required) |

## `vl scope rotate`

Start a new key generation for the current members (admins only)

```text
vl scope rotate [OPTIONS] <SCOPE>
```

Arguments:

| | |
|---|---|
| `<SCOPE>` | Scope name (required) |

## `vl scope log`

Show the signed membership log of a scope

```text
vl scope log [OPTIONS] <SCOPE>
```

Arguments:

| | |
|---|---|
| `<SCOPE>` | Scope name (required) |

---

[All commands](README.md) · [User guide](../guide/README.md)
