<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl describe`

Set the description of a change

```text
vl describe [OPTIONS] --message <MESSAGE>
```

Options:

| | |
|---|---|
| `-r, --rev <REV>` | Change to describe (default: `@`) |
| `-m, --message <MESSAGE>` | The new description (required) |
| `--no-verify` | Do not run hooks for this command (device-local or `.veilhooks`) |

---

[All commands](README.md) · [User guide](../guide/README.md)
