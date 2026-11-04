<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl push`

Send tags and their history to a remote (visibility-filtered)

```text
vl push [OPTIONS] [REMOTE]
```

Arguments:

| | |
|---|---|
| `<REMOTE>` | Remote to push to (default: `origin`) |

Options:

| | |
|---|---|
| `-t, --tag <TAG>` | Only push these tags |
| `--force` | Overwrite tags that diverged on the remote |
| `--full` | Walk and verify every object instead of skipping what the remote provably has (repairs damaged or missing objects on the remote) |
| `-d, --delete <TAG>` | Delete this tag on the remote (repeatable). Delete it here first with `vl tag delete`. Refused if someone moved it there since (unless --force). With no --tag, nothing else is pushed |

---

[All commands](README.md) · [User guide](../guide/README.md)
