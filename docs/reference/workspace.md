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
* [`vl workspace mount`](#vl-workspace-mount): Mount a workspace as a directory (FUSE), without checking it out
* [`vl workspace unmount`](#vl-workspace-unmount): Record a mounted workspace and unmount it (also recovers a mount whose process died)

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

The command's output is never deleted when something fails: if vl is killed or the result cannot be recorded (the repository is busy), it stays in the sandbox, and the next run (or --record-only) records it first. SIGTERM and SIGHUP are forwarded to the command, as Ctrl-C is, and vl records what it left.

On Linux the command runs confined (bubblewrap): the sandbox appears at the project's real path, starting in the sub-folder you ran vl from; the computer's tools are read-only; HOME and /tmp are empty and private (~/.ssh, ~/.gnupg, the Veil identity and other projects are not there); only the sandbox's own processes are visible. A read-only allow-list shows toolchains and agent configuration (~/.cargo, ~/.rustup, ~/.claude, ...; more with --allow or [exec.confine] allow in .veil/local/config.toml or $VEIL_HOME/config.toml). When the command exits, everything it started stops. --memory, --cpus, --cpu-time, --pids and --timeout limit it ([exec.limits] gives defaults); vl itself stays outside the limits, so the run is always recorded.

```text
vl workspace exec [OPTIONS] [NAME] [-- <COMMAND>...]
```

Arguments:

| | |
|---|---|
| `<NAME>` | Workspace to run in (or use --ephemeral) |
| `<COMMAND>…` | Command and arguments (after `--`) |

Options:

| | |
|---|---|
| `--ephemeral` | Run in a one-shot workspace on REV and record the result as a new change on top of it |
| `-r, --rev <REV>` | Base revision for --ephemeral (default: `@-`) |
| `-m, --message <MESSAGE>` | Description to record (default: empty) |
| `--with-isolated` | Copy local-only (isolated) files such as .env into the sandbox for this run (they are taken out again afterwards) |
| `--only <PATH>` | Sparse sandbox: hold only these paths (files or directories of the workspace, relative to the current directory) |
| `--record-only` | Run nothing: record what an earlier run left unrecorded (vl was killed, or recording failed) |
| `--unconfined` | Run without confinement: the command can read and change everything your user can |
| `--allow <PATH>` | Also show PATH (a folder or file of this machine) to the command, read-only. Repeatable |
| `--no-network` | No network: the command gets only a private loopback |
| `--memory <SIZE>` | Memory limit, e.g. 4G or 512M |
| `--cpus <N>` | CPU rate limit, in CPUs, e.g. 2 or 0.5 |
| `--cpu-time <DURATION>` | Total CPU-time limit, e.g. 30m or 90s |
| `--pids <N>` | Limit on the number of processes and threads |
| `--timeout <DURATION>` | Wall-clock limit, e.g. 45m: at the deadline everything in the sandbox is stopped |
| `--limits <MODE>` | best-effort (the default): run, saying which limits are soft here; strict: refuse unless the kernel enforces every limit (one of `best-effort`, `strict`) |

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

## `vl workspace mount`

Mount a workspace as a directory (FUSE), without checking it out.

Reads come from the workspace's tree, as this identity may see it (secret files it cannot read are absent, as in a checkout). Writes go to an overlay kept in .veil/local/mounts/NAME and are recorded into the workspace, through the policy and the secret scanner: by `vl ws unmount`, before every other vl command, every --record-every seconds, and when the directory is unmounted from outside. Isolated, ignored and quarantined files stay in the mount and are never recorded. Without --foreground a background process serves the mount. Needs FUSE (/dev/fuse and fusermount3 on Linux; macFUSE and a `--features macfuse` build on macOS).

```text
vl workspace mount [OPTIONS] <NAME> <DIR>
```

Arguments:

| | |
|---|---|
| `<NAME>` | Workspace name (required) |
| `<DIR>` | Directory to mount it at: empty, outside the project directory (created if missing) (required) |

Options:

| | |
|---|---|
| `--foreground` | Serve the mount from this process until it is unmounted (Ctrl-C unmounts) |
| `--record-every <SECS>` | Also record the mount every SECS seconds while it has changes (0: never on a timer) (default: `60`) |

## `vl workspace unmount`

Record a mounted workspace and unmount it (also recovers a mount whose process died)

```text
vl workspace unmount [OPTIONS] <NAME>
```

Arguments:

| | |
|---|---|
| `<NAME>` | Workspace name (required) |

---

[All commands](README.md) · [User guide](../guide/README.md)
