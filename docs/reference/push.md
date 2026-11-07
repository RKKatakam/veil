<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl push`

Send tags and their history to the Veil server, which moves each branch only if nobody moved it meanwhile (and checks your access)

```text
vl push [OPTIONS] [REMOTE]
```

Arguments:

| | |
|---|---|
| `<REMOTE>` | Remote to push to (default: origin) |

Options:

| | |
|---|---|
| `-t, --tag <TAG>` | Only push these tags |
| `--force` | Overwrite branches that diverged on the server (admins only) |
| `--no-verify` | Do not run hooks for this command (device-local or `.veilhooks`) |

---

[All commands](README.md) · [User guide](../guide/README.md)
