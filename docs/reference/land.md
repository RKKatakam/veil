<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl land`

Land a change on a branch through the server's landing service: the server puts it on the branch's newest tip when no path it edits changed there since its base, so you need not pull first.

REV and the changes under it that the server does not hold yet land in order, all or none, each as its own snapshot. A protected branch (`.veilrules`: `[branches.main] protected = true`) moves only this way, and `vl push` to one lands instead. Waits for the outcome: landed (your tag follows the change), conflict (the paths that changed meanwhile: pull, redo the change on the new tip, land again) or rejected.

```text
vl land [OPTIONS] [REV]
```

Arguments:

| | |
|---|---|
| `<REV>` | The change to land (default: `@-`, the change you last committed) |

Options:

| | |
|---|---|
| `--onto <BRANCH>` | The branch to land on (default: the server's default branch) |
| `--remote <REMOTE>` | The remote (default: `origin`) |
| `--no-wait` | Answer with the ticket at once, without waiting |
| `--status <TICKET>` | Show a submitted landing's outcome (waiting for it, unless --no-wait) |

---

[All commands](README.md) · [User guide](../guide/README.md)
