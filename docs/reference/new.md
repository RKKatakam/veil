<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl new`

Start a new change on top of REVS (default: @). Several = merge.

Exits 3 (the work done all the same) while the working copy holds files the secret scanner quarantined, naming each: `vl isolate FILE` keeps one on this machine on purpose, `vl expose --force FILE` records one that is not a secret.

```text
vl new [OPTIONS] [REVS]...
```

Arguments:

| | |
|---|---|
| `<REVS>…` | Parents of the new change |

Options:

| | |
|---|---|
| `-m, --message <MESSAGE>` | Description of the new change (default: empty) |

---

[All commands](README.md) · [User guide](../guide/README.md)
