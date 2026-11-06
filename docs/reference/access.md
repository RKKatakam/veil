<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl access`

Who may see a path; with WHO, give a group, a person or `public` access to it.

`vl access PATH` asks the server who can see PATH and which line of the accepted `.veilpolicy` decides. `vl access PATH WHO…` writes that line into `.veilpolicy` (replacing the line for the same path); push it to apply. Only admins may change access, and the last matching line wins. Folder access means read and write; `public` means everyone on Earth may read.

```text
vl access [OPTIONS] <PATH> [WHO]...
```

Arguments:

| | |
|---|---|
| `<PATH>` | A folder (`billing/`) or file, from the project root (required) |
| `<WHO>…` | Groups, people, or `public` |

---

[All commands](README.md) · [User guide](../guide/README.md)
