<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl stats`

Show the project's health on its Veil server (admins only): requests and refusals, cache hits and how far derived history lags.

The counts are the server's (`origin`) since it started and over the last whole minute, for this project only; with several servers, each counts what it served. Only the project's admins may see them, since they include work by people and on folders others cannot see.

```text
vl stats [OPTIONS]
```

Options:

| | |
|---|---|
| `--json` | Print one JSON document instead of text (its schema is named in its `schema` field; see docs/reference/json.md). Errors then also print a `veil.error/1` document |

---

[All commands](README.md) · [User guide](../guide/README.md)
