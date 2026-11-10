<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl embargo`

Manage embargoes created by delayed-visibility merges

Subcommands:

* [`vl embargo list`](#vl-embargo-list): List embargoes: pending (with their deadline), released, or withdrawn (the embargoed merge was undone or abandoned, so nothing holds the fix back any more)
* [`vl embargo release`](#vl-embargo-release): Release an embargo: show what becomes public, ask, and release it in this repository. The next push publishes the release and the history it withheld; until then `vl undo` takes the release back
* [`vl embargo follow`](#vl-embargo-follow): Switch to an embargo's hidden line (`embargo/<id>`), rebasing it onto the newest tip of `main` first; with no ID, list and update the embargoes you are in

## `vl embargo list`

List embargoes: pending (with their deadline), released, or withdrawn (the embargoed merge was undone or abandoned, so nothing holds the fix back any more)

```text
vl embargo list [OPTIONS]
```

## `vl embargo release`

Release an embargo: show what becomes public, ask, and release it in this repository. The next push publishes the release and the history it withheld; until then `vl undo` takes the release back

```text
vl embargo release [OPTIONS] <ID>
```

Arguments:

| | |
|---|---|
| `<ID>` | Embargo id, from `vl embargo list` (required) |

Options:

| | |
|---|---|
| `-y, --yes` | Do not ask for confirmation (required when stdin is not a terminal) |

## `vl embargo follow`

Switch to an embargo's hidden line (`embargo/<id>`), rebasing it onto the newest tip of `main` first; with no ID, list and update the embargoes you are in

```text
vl embargo follow [OPTIONS] [ID]
```

Arguments:

| | |
|---|---|
| `<ID>` | Embargo id, from `vl embargo list` |

---

[All commands](README.md) · [User guide](../guide/README.md)
