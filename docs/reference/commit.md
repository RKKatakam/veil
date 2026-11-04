<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl commit`

Describe the working-copy change and start a new one on top.

Tags that pointed at the change's parent move to it (`main` follows your commits), except on a cloaked line: there only tags cloaked under the same scope move, so cloaked work never reaches `main` by accident (publish it with `vl merge`).

```text
vl commit [OPTIONS] --message <MESSAGE>
```

Options:

| | |
|---|---|
| `-m, --message <MESSAGE>` | Description of the change being committed (required) |
| `--no-advance` | Move no tag, not even those at the parent |
| `--no-verify` | Do not run hooks for this command (not implemented yet) |

---

[All commands](README.md) · [User guide](../guide/README.md)
