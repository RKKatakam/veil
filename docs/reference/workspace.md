<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# `vl workspace`

Virtual workspaces (replacing worktrees)

Alias: `vl ws`.

Subcommands:

* [`vl workspace list`](#vl-workspace-list): List workspaces
* [`vl workspace new`](#vl-workspace-new): Create a virtual workspace (no directory is created)
* [`vl workspace switch`](#vl-workspace-switch): Attach the project directory to another workspace
* [`vl workspace rm`](#vl-workspace-rm): Delete a workspace, and its `ws exec` sandbox
* [`vl workspace exec`](#vl-workspace-exec): Run a command in a workspace's sandbox and record the result
* [`vl workspace cat`](#vl-workspace-cat): Print a file from a workspace
* [`vl workspace write`](#vl-workspace-write): Write stdin to a file in a workspace (in memory, no checkout)

## `vl workspace list`

List workspaces

```text
vl workspace list [OPTIONS]
```

Options:

| | |
|---|---|
| `--json` | Print one JSON document instead of text (its schema is named in its `schema` field; see docs/reference/json.md). Errors then also print a `veil.error/1` document |

## `vl workspace new`

Create a virtual workspace (no directory is created)

```text
vl workspace new [OPTIONS] <NAME>
```

Arguments:

| | |
|---|---|
| `<NAME>` | Workspace name (required) |

Options:

| | |
|---|---|
| `-r, --rev <REV>` | Base revision (default: the parents of @, like a fresh checkout) |
| `--cloak [<SCOPE>]` | Cloak everything recorded in this workspace (default scope: team) |

## `vl workspace switch`

Attach the project directory to another workspace

```text
vl workspace switch [OPTIONS] <NAME>
```

Arguments:

| | |
|---|---|
| `<NAME>` | Workspace name (required) |

## `vl workspace rm`

Delete a workspace, and its `ws exec` sandbox

```text
vl workspace rm [OPTIONS] <NAME>
```

Arguments:

| | |
|---|---|
| `<NAME>` | Workspace name (required) |

Options:

| | |
|---|---|
| `--force` | Also when its sandbox holds quarantined files, which are in no snapshot |

## `vl workspace exec`

Run a command in a workspace's sandbox and record the result.

Each workspace keeps one sandbox, .veil/local/sandboxes/NAME/files, between runs: a run rewrites only what changed since the last one (copy-on-write clones where the filesystem has them), and files the command leaves that are not recorded (ignored build output) stay for the next run. A second run in the same workspace waits for the first. With --ephemeral, a one-shot workspace on REV runs in a throwaway directory instead.

With --only, the sandbox holds just the given files and directories (and .veilpolicy): everything else is recorded exactly as the workspace has it, and files the command writes elsewhere are not recorded (a warning lists them) and are removed from the sandbox.

```text
vl workspace exec [OPTIONS] [NAME] -- <COMMAND>...
```

Arguments:

| | |
|---|---|
| `<NAME>` | Workspace to run in (or use --ephemeral) |
| `<COMMAND>…` | Command and arguments (required; after `--`) |

Options:

| | |
|---|---|
| `--ephemeral` | Run in a one-shot workspace on REV and record the result as a new change on top of it |
| `-r, --rev <REV>` | Base revision for --ephemeral (default: `@-`) |
| `-m, --message <MESSAGE>` | Description to record (default: empty) |
| `--with-isolated` | Copy local-only (isolated) files such as .env into the sandbox for this run (they are taken out again afterwards) |
| `--only <PATH>` | Sparse sandbox: hold only these paths (files or directories of the workspace, relative to the current directory) |

## `vl workspace cat`

Print a file from a workspace

```text
vl workspace cat [OPTIONS] <NAME> <PATH>
```

Arguments:

| | |
|---|---|
| `<NAME>` | Workspace name (required) |
| `<PATH>` | File to print (required) |

## `vl workspace write`

Write stdin to a file in a workspace (in memory, no checkout)

```text
vl workspace write [OPTIONS] <NAME> <PATH>
```

Arguments:

| | |
|---|---|
| `<NAME>` | Workspace name (required) |
| `<PATH>` | File to write (required) |

---

[All commands](README.md) · [User guide](../guide/README.md)
