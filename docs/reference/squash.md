<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl squash`

Move a change, or part of it, into its parent or another change.

With no PATHS and no `-i`, `--hunks` or `--plan`, the whole change moves and is abandoned, its description joined to the destination's. Otherwise only what you choose moves; the change keeps the rest (and its description), and is abandoned only if nothing is left. Descendants are rebased. Squashing into a cloaked change seals what it brings for that change's scope.

```text
vl squash [OPTIONS] [PATHS]...
```

Arguments:

| | |
|---|---|
| `<PATHS>…` | Files or directories whose changes move (with `-i`: the files to ask about) |

Options:

| | |
|---|---|
| `-r, --rev <REV>` | Change to fold into its parent (or into `--into`) (default: `@`) |
| `--into <REV>` | Move into this change instead of the parent (an ancestor, a descendant or an unrelated change) |
| `-i, --interactive` | Choose hunk by hunk: each hunk is shown with a question (y, n, s to split it, q, a, d, ? for help). Answers are read from standard input, one per line, so they can be piped in; questions go to standard error |
| `--hunks <PATH:LIST>` | Choose hunks without asking: PATH:LIST, where LIST is hunk numbers as `vl diff -r REV --json` lists them (from 1), `N.M` for the M-th edit of hunk N, or `mode` for the executable bit, separated by commas (`--hunks src/main.rs:1,3.2`). Repeat for more files |
| `--plan <FILE>` | Choose from a JSON plan in FILE (`-` for standard input): `{"files": [{"path": "src/main.rs", "hunks": [1, "3.2"]}, {"path": "docs"}]}` with paths relative to the repository root; a file without `hunks` is taken whole |
| `--json` | Print one JSON document instead of text (its schema is named in its `schema` field; see docs/reference/json.md). Errors then also print a `veil.error/1` document |

---

[All commands](README.md) · [User guide](../guide/README.md)
