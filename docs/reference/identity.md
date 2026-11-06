<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl identity`

Your public-key identity

Subcommands:

* [`vl identity show`](#vl-identity-show): Show your identity and public key
* [`vl identity new`](#vl-identity-new): Create a new identity (replaces the existing one with --force; the replaced one is kept so local vaults can be re-keyed)
* [`vl identity recover-vault`](#vl-identity-recover-vault): Re-key this repository's local vault, sealed by an identity that was replaced, to the current identity
* [`vl identity recover-admin`](#vl-identity-recover-admin): Hand the scope admin rights of a replaced identity over to the current one, in this repository: the replaced identity signs a grant that makes the current identity an admin. Push to share it
* [`vl identity confirm`](#vl-identity-confirm): Confirm a fingerprint you checked out of band: another device of yours, or, in a clone, the project's
* [`vl identity remove`](#vl-identity-remove): Remove a device on a Veil server: a lost laptop, say. Run it on another of your devices to remove it everywhere; an admin may remove anyone's device from their project only (run it in a clone of the project)

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

## `vl identity recover-admin`

Hand the scope admin rights of a replaced identity over to the current one, in this repository: the replaced identity signs a grant that makes the current identity an admin. Push to share it

```text
vl identity recover-admin [OPTIONS]
```

Options:

| | |
|---|---|
| `--from <FROM>` | Identity file to recover from (default: every identity replaced by `vl identity new --force`, newest first) |
| `--revoke-old` | Then revoke the replaced identity from those scopes (rotates their keys). Leave it out while another device still uses it |

## `vl identity confirm`

Confirm a fingerprint you checked out of band: another device of yours, or, in a clone, the project's.

A device: the new device signs in with `vl login URL --name YOU` and shows its fingerprint. Run this on a device you already use: it signs that device with this one, and the server lets it sign in. Admins then grant it the project's secret keys without asking you again.

A project: a device trusts a project's secret keys only once it knows the project's fingerprint (an invite link carries it). In a clone that does not trust them yet, `vl clone` and `vl pull` show the fingerprint the server claims; compare it with an admin's, or with `vl identity show` in a clone on another of your devices, then run this in the clone.

```text
vl identity confirm [OPTIONS] <FINGERPRINT>
```

Arguments:

| | |
|---|---|
| `<FINGERPRINT>` | The new device's fingerprint (`vl identity show` on it), or the project's (required) |

Options:

| | |
|---|---|
| `--server <SERVER>` | The server (`veil://host[:port]`); default: the one this device is signed in to |

## `vl identity remove`

Remove a device on a Veil server: a lost laptop, say. Run it on another of your devices to remove it everywhere; an admin may remove anyone's device from their project only (run it in a clone of the project).

Your own device can no longer sign in, and in a clone of a project the keys of every secret it could open rotate away from it at once (your other devices, and admins', do the same in your other projects in the background). A device an admin removes can no longer use that project, and that project's keys rotate away from it; only its person removes it everywhere. It keeps what it already had.

```text
vl identity remove [OPTIONS] <FINGERPRINT>
```

Arguments:

| | |
|---|---|
| `<FINGERPRINT>` | The device's fingerprint (`vl identity show` on it, or the one `vl group add` showed) (required) |

Options:

| | |
|---|---|
| `--server <SERVER>` | The server (`veil://host[:port]`); default: this clone's, or the one this device is signed in to |

---

[All commands](README.md) · [User guide](../guide/README.md)
