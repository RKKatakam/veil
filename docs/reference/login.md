<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl login`

Sign in to a Veil server with this device's identity key.

URL is `veil://host[:port]` (a project URL works too). The first time, give `--name` to register this device as a new person. A session lasts hours and is renewed with the key without asking.

```text
vl login [OPTIONS] <URL>
```

Arguments:

| | |
|---|---|
| `<URL>` | The server: `veil://host[:port]` or `https://host[:port]` (required) |

Options:

| | |
|---|---|
| `--name <NAME>` | Register as a new person with this name |
| `--ca <FILE>` | Trust this certificate (PEM) for the server: a self-signed one, for development |

---

[All commands](README.md) · [User guide](../guide/README.md)
