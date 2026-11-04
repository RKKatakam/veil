<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl scan`

Scan the working copy for secrets that would become public.

With `--policy-from`, scan as a CI gate on a checkout (no Veil repository needed): every file counts as public, because a Git checkout publishes all of them, except what FILE marks `public!`.

```text
vl scan [OPTIONS]
```

Options:

| | |
|---|---|
| `--policy-from <FILE>` | CI gate: take the rules from FILE (the base branch's `.veilpolicy`, e.g. from `git show`; an empty file for the built-in rules only) and disregard the scanned directory's own `.veilpolicy`, so a pull request cannot switch the scan off |

---

[All commands](README.md) · [User guide](../guide/README.md)
