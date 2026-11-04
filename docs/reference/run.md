<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl run`

Run a command with vault secrets injected as environment variables.

Loads the team vaults of the chosen scopes first, then the local vault, whose secrets override a team secret of the same name. Variables already in the environment are overridden by both. A team vault never sets variables that decide what the command runs or loads (PATH, LD_*, BASH_ENV, NODE_OPTIONS, GIT_*, …): any member of the scope could set them.

```text
vl run [OPTIONS] [COMMAND]...
```

Arguments:

| | |
|---|---|
| `<COMMAND>…` | Command and arguments (put them after `--`) |

Options:

| | |
|---|---|
| `--scope <SCOPE>` | Load these scopes' team vaults (repeatable). Default: the scopes chosen with `--remember` on this device, none until then. A name set in two loaded scopes is an error unless the local vault overrides it |
| `--local-only` | Load only the local vault, no team vault |
| `--remember` | Make the given `--scope`s (or, with `--local-only`, no team vault) this device's default; the command is optional |

---

[All commands](README.md) · [User guide](../guide/README.md)
