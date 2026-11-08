<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl search`

Search the project on its Veil server: code at a branch tip, ranked, or file names over all of its history (`--path`).

The server (`origin`) searches only what you may see: folders you cannot see are never found, counted or ranked, and secret files are found by name, never by content. Every word must occur (in any case). Exits 1 when nothing matches.

```text
vl search [OPTIONS] <WORDS>... [-- <PATH>]
```

Arguments:

| | |
|---|---|
| `<WORDS>…` | Words to find (all must occur; any case) (required) |
| `<PATH>` | Only files at or under this path (after `--`) |

Options:

| | |
|---|---|
| `--path` | Search file names over all of the project's history, not code |
| `--lang <LANG>` | Only files of this language (by extension: rust, python, go, …) |
| `-r, --rev <BRANCH>` | The branch whose tip to search (default: the project's default branch) |
| `-n, --limit <LIMIT>` | Results to show (default: `20`) |
| `--json` | Print one JSON document instead of text (its schema is named in its `schema` field; see docs/reference/json.md). Errors then also print a `veil.error/1` document |

---

[All commands](README.md) · [User guide](../guide/README.md)
