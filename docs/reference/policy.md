<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl policy`

Inspect the visibility policy

Subcommands:

* [`vl policy show`](#vl-policy-show): Show all rules, built-in first, and any change not yet accepted
* [`vl policy check`](#vl-policy-check): Explain how paths are classified
* [`vl policy accept`](#vl-policy-accept): Apply the working copy's .veilpolicy in full, including changes that arrived by merge, pull or checkout and weaken the protection of local files (until now held back on this device)

## `vl policy show`

Show all rules, built-in first, and any change not yet accepted

```text
vl policy show [OPTIONS]
```

## `vl policy check`

Explain how paths are classified

```text
vl policy check [OPTIONS] <PATHS>...
```

Arguments:

| | |
|---|---|
| `<PATHS>…` | Paths to classify (required) |

## `vl policy accept`

Apply the working copy's .veilpolicy in full, including changes that arrived by merge, pull or checkout and weaken the protection of local files (until now held back on this device)

```text
vl policy accept [OPTIONS]
```

Options:

| | |
|---|---|
| `--workspace <NAME>` | Record instead the edit of .veilpolicy a command made in this virtual workspace's `vl ws exec` sandbox or mount, held back because it weakens the workspace's recorded policy |

---

[All commands](README.md) · [User guide](../guide/README.md)
