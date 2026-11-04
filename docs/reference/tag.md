<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl tag`

Manage tags (named pointers into the snapshot graph)

Subcommands:

* [`vl tag list`](#vl-tag-list): List tags
* [`vl tag set`](#vl-tag-set): Create or move a tag
* [`vl tag delete`](#vl-tag-delete): Delete a tag
* [`vl tag verify`](#vl-tag-verify): Verify an annotated tag's signature: exits 1 unless it is a valid Veil signature by a key a ring of this repository knows (a Git signature is never verified by Veil)

## `vl tag list`

List tags

```text
vl tag list [OPTIONS]
```

Options:

| | |
|---|---|
| `--json` | Print one JSON document instead of text (its schema is named in its `schema` field; see docs/reference/json.md). Errors then also print a `veil.error/1` document |

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
| `-a, --annotate` | Make an annotated release tag: immutable, signed when you have an identity, exported to Git as `refs/tags/NAME` |
| `-m, --message <MESSAGE>` | The annotated tag's message (implies `-a`; sealed for a cloaked tag) |
| `--force` | Replace an existing annotated tag (or annotate a plain one). A release tag moved without `-m` keeps its message |

## `vl tag delete`

Delete a tag

```text
vl tag delete [OPTIONS] <NAME>
```

Arguments:

| | |
|---|---|
| `<NAME>` | Tag name (required) |

## `vl tag verify`

Verify an annotated tag's signature: exits 1 unless it is a valid Veil signature by a key a ring of this repository knows (a Git signature is never verified by Veil)

```text
vl tag verify [OPTIONS] <NAME>
```

Arguments:

| | |
|---|---|
| `<NAME>` | Tag name (required) |

---

[All commands](README.md) · [User guide](../guide/README.md)
