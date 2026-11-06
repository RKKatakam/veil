<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl join`

Join a project with the link `vl invite` printed: signs this device in (registering the invited name if it is new), confirms it and joins the group.

The link also carries the project's fingerprint: `vl join` checks that the server's key ring for the project is that one, the only one this device then trusts with secrets. Give `-` to paste the link on standard input: a link on the command line can be read by other users of the machine while `vl join` runs.

```text
vl join [OPTIONS] <LINK>
```

Arguments:

| | |
|---|---|
| `<LINK>` | The invite link (`veil://host/project#invite=NAME:SECRET:FINGERPRINT`), or `-` to read it from standard input (safer on a shared machine) (required) |

---

[All commands](README.md) · [User guide](../guide/README.md)
