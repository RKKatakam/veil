<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl cloak`

Encrypt matching secret files (.env, keys, ...) for a scope (default: team). Only secret files are ever encrypted; `vl access` decides who sees everything else

```text
vl cloak [OPTIONS] <PATTERNS>...
```

Arguments:

| | |
|---|---|
| `<PATTERNS>…` | Secret files (paths or glob patterns) (required) |

Options:

| | |
|---|---|
| `--scope <SCOPE>` | Scope to encrypt for (you must hold its key) (default: `team`) |

---

[All commands](README.md) · [User guide](../guide/README.md)
