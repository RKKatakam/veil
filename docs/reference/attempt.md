<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl attempt`

Recorded dead ends: keep an abandoned attempt on its change, with why it failed, instead of erasing it

Subcommands:

* [`vl attempt drop`](#vl-attempt-drop): Record REV's content as an abandoned attempt, with its reason, and start the change again from its parents

## `vl attempt drop`

Record REV's content as an abandoned attempt, with its reason, and start the change again from its parents.

The attempt stays on the change: `vl show` lists it ("Discarded attempts"), `vl evolog` shows it, and it is pushed and seen by exactly the people who see the change, so a later agent or reviewer sees what was tried and why it failed. It never lands and is never built on. A change keeps at most 32 attempts, each reason at most 64 KiB; they go when the change is abandoned.

```text
vl attempt drop [OPTIONS] --reason <REASON> [REV]
```

Arguments:

| | |
|---|---|
| `<REV>` | The change whose attempt to drop (default: `@`) |

Options:

| | |
|---|---|
| `--reason <REASON>` | Why the attempt failed (required) |

---

[All commands](README.md) · [User guide](../guide/README.md)
