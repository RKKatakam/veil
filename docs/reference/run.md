<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl run`

Run a command with vault secrets injected as environment variables.

Loads the team vaults of your scopes first, then the local vault, whose secrets override a team secret of the same name. Variables already in the environment are overridden by both.

```text
vl run [OPTIONS] <COMMAND>...
```

Arguments:

| | |
|---|---|
| `<COMMAND>…` | Command and arguments (put them after `--`) (required) |

Options:

| | |
|---|---|
| `--scope <SCOPE>` | Load only these scopes' team vaults (repeatable). Default: every scope you are a member of. A name set in two loaded scopes is an error unless the local vault overrides it |
| `--local-only` | Load only the local vault, no team vault |

---

[All commands](README.md) · [User guide](../guide/README.md)
