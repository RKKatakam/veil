<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl tag`

Manage tags (named pointers into the snapshot graph)

Subcommands:

* [`vl tag list`](#vl-tag-list): List tags
* [`vl tag set`](#vl-tag-set): Create or move a tag
* [`vl tag delete`](#vl-tag-delete): Delete a tag

## `vl tag list`

List tags

```text
vl tag list [OPTIONS]
```

## `vl tag set`

Create or move a tag

```text
vl tag set [OPTIONS] <NAME>
```

Arguments:

| | |
|---|---|
| `<NAME>` | Tag name (required) |

Options:

| | |
|---|---|
| `-r, --rev <REV>` | Snapshot the tag points at (default: `@`) |
| `--cloak [<SCOPE>]` | Cloak the tag (default scope: team): never pushed to public remotes |
| `--allow-backwards` | Allow moving the tag to a snapshot that is not a descendant |

## `vl tag delete`

Delete a tag

```text
vl tag delete [OPTIONS] <NAME>
```

Arguments:

| | |
|---|---|
| `<NAME>` | Tag name (required) |

---

[All commands](README.md) · [User guide](../guide/README.md)
