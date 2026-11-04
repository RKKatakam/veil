<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl identity`

Your public-key identity

Subcommands:

* [`vl identity show`](#vl-identity-show): Show your identity and public key
* [`vl identity new`](#vl-identity-new): Create a new identity (replaces the existing one with --force; the replaced one is kept so local vaults can be re-keyed)
* [`vl identity recover-vault`](#vl-identity-recover-vault): Re-key this repository's local vault, sealed by an identity that was replaced, to the current identity

## `vl identity show`

Show your identity and public key

```text
vl identity show [OPTIONS]
```

## `vl identity new`

Create a new identity (replaces the existing one with --force; the replaced one is kept so local vaults can be re-keyed)

```text
vl identity new [OPTIONS]
```

Options:

| | |
|---|---|
| `--name <NAME>` | Your name (default: $VEIL_USER, then $USER) |
| `--force` | Replace the existing identity |

## `vl identity recover-vault`

Re-key this repository's local vault, sealed by an identity that was replaced, to the current identity

```text
vl identity recover-vault [OPTIONS]
```

Options:

| | |
|---|---|
| `--from <FROM>` | Identity file to recover from (default: every identity replaced by `vl identity new --force`) |

---

[All commands](README.md) · [User guide](../guide/README.md)
