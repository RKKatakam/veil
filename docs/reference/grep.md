<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl grep`

Search the files of a snapshot (never the working copy's local-only files) for a pattern.

Searches recorded files only (default `@`, snapshotted first): isolated, quarantined and ignored files are never searched or counted. Files you cannot read (secrets sealed for others) are skipped. Exits 1 when nothing matches.

```text
vl grep [OPTIONS] <PATTERN> [PATHS]...
```

Arguments:

| | |
|---|---|
| `<PATTERN>` | Regular expression (or, with -F, literal string) to search for (required) |
| `<PATHS>…` | Only search these files or directories |

Options:

| | |
|---|---|
| `-r, --rev <REV>` | Snapshot to search (never the working copy itself) (default: `@`) |
| `-i, --ignore-case` | Match case-insensitively |
| `-F, --fixed-strings` | Take PATTERN as a literal string, not a regular expression |
| `-w, --word-regexp` | Match whole words only |
| `-n, --line-number` | Print line numbers |
| `-l, --files-with-matches` | Print only the names of files that match |
| `-c, --count` | Print only the number of matching lines per file |
| `--max-count <N>` | Stop after N matching lines per file |
| `-a, --text` | Search binary files as text |
| `--json` | Print one JSON document instead of text (its schema is named in its `schema` field; see docs/reference/json.md). Errors then also print a `veil.error/1` document |

---

[All commands](README.md) · [User guide](../guide/README.md)
