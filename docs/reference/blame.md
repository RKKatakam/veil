<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl blame`

Show which change last touched each line of a file.

History is read as you may see it: a secret file sealed for a scope you are not in is never opened, and lines whose history is sealed for you are reported unattributed, never guessed. Prints change ids, never descriptions.

Alias: `vl annotate`.

```text
vl blame [OPTIONS] <PATH>
```

Arguments:

| | |
|---|---|
| `<PATH>` | File to annotate (required) |

Options:

| | |
|---|---|
| `-r, --rev <REV>` | Snapshot whose version of the file to annotate (default: `@`) |
| `-L <START,END>` | Only annotate lines START to END (1-based, inclusive) |
| `--follow` | Follow the file across renames |
| `--max-changes <N>` | Stop after visiting this many snapshots; lines still open are reported as unattributed (default: `100000`) |
| `--public` | Annotate as a public mirror sees the history: no secret files, and nothing an unreleased embargo withholds (refused for such a revision) |
| `--json` | Print one JSON document instead of text (its schema is named in its `schema` field; see docs/reference/json.md). Errors then also print a `veil.error/1` document |

---

[All commands](README.md) · [User guide](../guide/README.md)
