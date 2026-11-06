<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl invite`

Invite a person to a group (admins): prints a one-time link to send them (Slack, email).

The link holds a secret the server never sees. With it, `vl join` confirms the person's device and joins them to the group, and their device receives the keys of the group's folders' secrets from the next teammate's device that is online. It works once, for 7 days. `vl group add … --confirm FINGERPRINT` is the other way to confirm a person's first device.

```text
vl invite [OPTIONS] --to <GROUP> <PERSON>
```

Arguments:

| | |
|---|---|
| `<PERSON>` | The person's name on the server (a new name registers them) (required) |

Options:

| | |
|---|---|
| `--to <GROUP>` | The group to join (required) |

---

[All commands](README.md) · [User guide](../guide/README.md)
