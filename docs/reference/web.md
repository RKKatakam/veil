<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl web`

Enroll a browser passkey on a Veil server.

Prints a short-lived, single-use link to open in the browser. The browser creates a passkey and its own separate device keys inside a Web Worker; confirm the fingerprint the browser shows with `vl identity confirm FINGERPRINT` so secret keys may be shared with it.

```text
vl web [OPTIONS]
```

Options:

| | |
|---|---|
| `--server <URL>` | The server (`veil://host[:port]`), when signed in to several |
| `--label <TEXT>` | Optional label for this browser device (for example `work-laptop`) |
| `--json` | Print the enrollment code and URL as JSON |

---

[All commands](README.md) · [User guide](../guide/README.md)
