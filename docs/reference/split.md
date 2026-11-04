<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl split`

Split a change in two: what you choose, then the rest.

The first change, on the original's parents, holds what you choose: the changes at PATHS, the hunks named by `--hunks` or `--plan`, or the hunks you pick with `-i`. It gets a new change id and the description given with `-m` (none by default). The second change, its child, holds the rest and stays the change you split: the same change id, description and files, so its descendants, tags and the working copy follow it with nothing to rebase. No file changes visibility: a cloaked file's hunks stay sealed for its scope in both halves. Hunks of a file you cannot read, of a binary or conflicted file, or of a file whose visibility this change alters cannot be chosen one by one: such a file moves whole. A split that would leave either change empty is refused.

```text
vl split [OPTIONS] [PATHS]...
```

Arguments:

| | |
|---|---|
| `<PATHS>…` | Files or directories whose changes go in the first change (with `-i`: the files to ask about) |

Options:

| | |
|---|---|
| `-r, --rev <REV>` | Change to split (default: `@`) |
| `-m, --message <MESSAGE>` | Description of the first change |
| `-i, --interactive` | Choose hunk by hunk: each hunk is shown with a question (y, n, s to split it, q, a, d, ? for help). Answers are read from standard input, one per line, so they can be piped in; questions go to standard error |
| `--hunks <PATH:LIST>` | Choose hunks without asking: PATH:LIST, where LIST is hunk numbers as `vl diff -r REV --json` lists them (from 1), `N.M` for the M-th edit of hunk N, or `mode` for the executable bit, separated by commas (`--hunks src/main.rs:1,3.2`). Repeat for more files |
| `--plan <FILE>` | Choose from a JSON plan in FILE (`-` for standard input): `{"files": [{"path": "src/main.rs", "hunks": [1, "3.2"]}, {"path": "docs"}]}` with paths relative to the repository root; a file without `hunks` is taken whole |
| `--json` | Print one JSON document instead of text (its schema is named in its `schema` field; see docs/reference/json.md). Errors then also print a `veil.error/1` document |

---

[All commands](README.md) · [User guide](../guide/README.md)
