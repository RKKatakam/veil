<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl upgrade`

Upgrade the repository (or a remote) to the newest format.

Existing repositories keep working at their format without this; upgrading enables what the newer format adds (format 2: binary trees, which make `vl status` faster). Old objects keep their ids, nothing is rewritten, and older vl releases can no longer read the repository afterwards. Runs `fsck` first; resumable after a crash.

```text
vl upgrade [OPTIONS]
```

Options:

| | |
|---|---|
| `--dry-run` | Show what would happen without changing anything |
| `--remote <NAME>` | Upgrade this remote instead of the local repository |
| `--force` | Upgrade even if fsck reports corruption |
| `--sync-secrets` | Start encrypting and syncing shared secrets (`.env`, `.env.*`, `.envrc`, Terraform state) under the `team` key, as new repositories do: lists the files that would start syncing, then adds the rules to `.veilpolicy` (with --dry-run: only lists). Personal private keys stay on this device |
| `--rule-keys` | Give each folder's secrets their own key, instead of one key for every secret of the project (milestone S1's): lists every secret with its new key and who will hold it, then rewrites the lines and sets up the keys (with --dry-run: only lists). Admins of a Veil server project; commit and push afterwards |

---

[All commands](README.md) · [User guide](../guide/README.md)
