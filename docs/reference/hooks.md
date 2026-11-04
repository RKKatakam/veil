<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl hooks`

Hooks run before commits and pushes; repository-suggested ones only once this device trusts them (not implemented yet)

Subcommands:

* [`vl hooks show`](#vl-hooks-show): Show the hooks that would run: device-local ones, and the repository's `.veilhooks` with its digests and whether this device trusts them
* [`vl hooks trust`](#vl-hooks-trust): Trust the repository's `.veilhooks` and every script it names, as they are now (pinned by digest, recorded on this device only)

## `vl hooks show`

Show the hooks that would run: device-local ones, and the repository's `.veilhooks` with its digests and whether this device trusts them

```text
vl hooks show [OPTIONS]
```

## `vl hooks trust`

Trust the repository's `.veilhooks` and every script it names, as they are now (pinned by digest, recorded on this device only)

```text
vl hooks trust [OPTIONS]
```

Options:

| | |
|---|---|
| `-y, --yes` | Do not ask for confirmation (required when stdin is not a terminal) |
| `--i-understand-indirect` | Also trust commands that run a build tool (make, npm, cargo, …), which read files the trust record cannot pin |

---

[All commands](README.md) · [User guide](../guide/README.md)
