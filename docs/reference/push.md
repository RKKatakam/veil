<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl push`

Send tags and their history to a remote (visibility-filtered).

`--dry-run` shows what the push would send, writing nothing to the remote (it only reads the remote's tags): which tags it creates, moves or would have rejected, how many snapshots and objects it sends and their size, and what stays here (embargoed history). For a public remote it also lists every file whose content would become public there, and the files it withholds, with the reason.

```text
vl push [OPTIONS] [REMOTE]
```

Arguments:

| | |
|---|---|
| `<REMOTE>` | Remote to push to (default: origin; with --dry-run, every configured remote) |

Options:

| | |
|---|---|
| `-t, --tag <TAG>` | Only push these tags |
| `--force` | Overwrite tags that diverged on the remote |
| `--force-tags` | Move release tags (annotated: `vl tag set -a`) that the remote holds at another target. A release is otherwise never replaced, even by a fast-forward |
| `--full` | Walk and verify every object instead of skipping what the remote provably has (repairs damaged or missing objects on the remote) |
| `-d, --delete <TAG>` | Delete this tag on the remote (repeatable). Delete it here first with `vl tag delete`. Refused if someone moved it there since (unless --force). With no --tag, nothing else is pushed |
| `--no-resume` | Start the upload afresh instead of resuming an interrupted push of the same tags to this remote (what it uploaded is not reused) |
| `--dry-run` | Show what would be sent, and send nothing |
| `--json` | With --dry-run: print one JSON document (`veil.push.plan/1`; see docs/reference/json.md) instead of text. Errors then also print a `veil.error/1` document |
| `--no-verify` | Do not run hooks for this command (device-local or `.veilhooks`) |

---

[All commands](README.md) · [User guide](../guide/README.md)
