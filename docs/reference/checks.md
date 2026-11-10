<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl checks`

Show or record CI check results on a snapshot (`POST / GET …/checks`).

Without `--state`, lists the checks on REV (default: the server's default branch) that you can see. With `--name` and `--state`, records a check result on REV.

```text
vl checks [OPTIONS]
```

Options:

| | |
|---|---|
| `-r, --rev <REV>` | Snapshot or revision to inspect or record a check on (default: the server's default branch) |
| `--name <CHECK>` | Check name (`ci/build`, `ci/test`), when recording a result |
| `--state <STATE>` | Check state (`pending`, `pass`, `fail`, or `error`), when recording a result |
| `--summary <SUMMARY>` | Short summary of the check result (at most 1 KiB) |
| `--url <URL>` | URL to the check run (at most 1 KiB) |
| `--log <LOG>` | Log excerpt of the check run (at most 64 KiB) |
| `--json` | Print one JSON document instead of text (its schema is named in its `schema` field; see docs/reference/json.md). Errors then also print a `veil.error/1` document |

---

[All commands](README.md) · [User guide](../guide/README.md)
