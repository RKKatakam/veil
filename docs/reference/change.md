<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl change`

Commit through the Veil server's API, without a checkout (scripts, CI, agents)

Subcommands:

* [`vl change new`](#vl-change-new): Make a change from a list of edits on the server: it builds the change on its own copy of the project, with every check a push gets, and can move a branch to it at once

## `vl change new`

Make a change from a list of edits on the server: it builds the change on its own copy of the project, with every check a push gets, and can move a branch to it at once.

FILE is a JSON list of edits, paths from the project root: `[{"path": "src/a.rs", "put": {"text": "…"}}, {"path": "old.rs", "delete": true}]` (`"executable": true` in a put for an executable file). Secret files (`.env`) are encrypted here first, which needs a clone of the project holding their key; anything that looks like a secret in an ordinary file is refused. With `--onto`, the branch moves to the change; when it moved since `--base`, the server applies the edits to its new tip instead, unless a file they edit changed there (`--expected` moves only from that tip).

```text
vl change new [OPTIONS] --edits <FILE> [PROJECT]
```

Arguments:

| | |
|---|---|
| `<PROJECT>` | The project, `veil://host[:port]/project` (default: this clone's origin) |

Options:

| | |
|---|---|
| `--edits <FILE>` | The edits, as JSON (`-` reads standard input) (required) |
| `--base <ID>` | The snapshot the edits are on, as the server shows it to you (default: the tip of `--onto`, or of the default branch) |
| `-m, --message <MESSAGE>` | The change's description |
| `--onto <BRANCH>` | Move this branch to the change |
| `--expected <ID>` | Move the branch only if its tip is still this snapshot id |
| `--change <CHANGE>` | Make a new revision of this change of yours (one made with `vl change new`) |

---

[All commands](README.md) · [User guide](../guide/README.md)
