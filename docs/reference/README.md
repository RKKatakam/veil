<!-- Generated from the CLI definition by crates/vl/src/docgen.rs. Do not edit:
     regenerate with `VEIL_BLESS_DOCS=1 cargo test -p vl --bin vl reference_is_up_to_date`. -->

# Command reference

Generated from `vl` itself (`vl <command> --help` shows the same text). For
explanations and worked examples, read the [user guide](../guide/README.md).

Veil — snapshot-first version control with engine-level secret protection (secret files are encrypted) and virtual workspaces.

There is no staging area: every `vl` invocation first records the working copy as a snapshot of the current change. Use `vl commit -m` to finish a change, `vl undo` to step back through the operation log.

```text
vl [OPTIONS] <COMMAND>
```

Global options (accepted by every command):

| | |
|---|---|
| `-R, --repository <PATH>` | Path to the repository (defaults to searching upward from the cwd) |
| `--no-snapshot` | Do not auto-snapshot the working copy before running the command |

## Commands

| Command | |
|---|---|
| [`vl init`](init.md) | Create a repository in PATH (default: current directory) |
| [`vl clone`](clone.md) | Copy a repository (and every tag you can see) into a new directory |
| [`vl login`](login.md) | Sign in to a Veil server with this device's identity key |
| [`vl group`](group.md) | Groups of people on the Veil server (the origin remote's project) |
| [`vl change`](change.md) | Commit through the Veil server's API, without a checkout (scripts, CI, agents) |
| [`vl invite`](invite.md) | Invite a person to a group (admins): prints a one-time link to send them (Slack, email) |
| [`vl join`](join.md) | Join a project with the link `vl invite` printed: signs this device in (registering the invited name if it is new), confirms it and joins the group |
| [`vl access`](access.md) | Who may see a path; with WHO, give a group, a person or `public` access to it |
| [`vl status`](status.md) | Show working-copy changes, local-only files and conflicts |
| [`vl log`](log.md) | Show the snapshot graph |
| [`vl show`](show.md) | Show a snapshot's metadata and diff |
| [`vl diff`](diff.md) | Show changes in a snapshot, or between two snapshots |
| [`vl files`](files.md) | List the files of a snapshot with their visibility |
| [`vl ls`](ls.md) | List a snapshot's files with their tier: who can read each one, and what never leaves this machine |
| [`vl cat`](cat.md) | Print a file's content at a snapshot |
| [`vl fsck`](fsck.md) | Verify repository integrity: object hashes, reachability, key rings, embargo records and the operation log. Exits 1 on corruption |
| [`vl upgrade`](upgrade.md) | Upgrade the repository to the newest format |
| [`vl evolog`](evolog.md) | Show how a change evolved (amends, rewrites, rebases) |
| [`vl blame`](blame.md) | Show which change last touched each line of a file |
| [`vl grep`](grep.md) | Search the files of a snapshot (never the working copy's local-only files) for a pattern |
| [`vl bisect`](bisect.md) | Find the change that introduced a problem by binary search |
| [`vl describe`](describe.md) | Set the description of a change |
| [`vl new`](new.md) | Start a new change on top of REVS (default: @). Several = merge |
| [`vl commit`](commit.md) | Describe the working-copy change and start a new one on top |
| [`vl edit`](edit.md) | Make REV the working-copy change |
| [`vl abandon`](abandon.md) | Discard a change; descendants are rebased onto its parent |
| [`vl rebase`](rebase.md) | Move a change (and its descendants) onto new parents |
| [`vl resolve`](resolve.md) | List unresolved conflicts, or resolve one by keeping one of its versions |
| [`vl split`](split.md) | Split a change in two: what you choose, then the rest |
| [`vl squash`](squash.md) | Move a change, or part of it, into its parent or another change |
| [`vl restore`](restore.md) | Restore paths in the working copy from another snapshot |
| [`vl duplicate`](duplicate.md) | Copy changes onto new parents, as new changes (merges follow renames; nothing changes audience) |
| [`vl cherry-pick`](cherry-pick.md) | Copy changes onto the working copy's parent: `vl duplicate REV… -d @-`, then the working copy moves on top |
| [`vl merge`](merge.md) | Merge REVS into the current line of work |
| [`vl embargo`](embargo.md) | Manage embargoes created by delayed-visibility merges |
| [`vl tag`](tag.md) | Manage tags (named pointers into the snapshot graph) |
| [`vl cloak`](cloak.md) | Encrypt matching secret files (.env, keys, ...) for a scope (default: team). Only secret files are ever encrypted; `vl access` decides who sees everything else |
| [`vl isolate`](isolate.md) | Keep matching paths local-only: never snapshotted, never synced |
| [`vl expose`](expose.md) | Make matching paths public |
| [`vl ignore`](ignore.md) | Do not track matching paths at all |
| [`vl policy`](policy.md) | Inspect the visibility policy |
| [`vl scan`](scan.md) | Scan the working copy for secrets that would become public |
| [`vl attr`](attr.md) | Per-path attributes from `.veilattributes`: line endings, binary files, diff and merge drivers |
| [`vl renormalize`](renormalize.md) | Re-record files with the line endings `.veilattributes` asks for now (changing `.veilattributes` alone never re-records a file). `vl undo` reverts it |
| [`vl secret`](secret.md) | Encrypted secrets: the device-local vault, or a scope's team vault (`--scope`), sealed for the scope's members (it does not sync through the Veil server yet); and secret files shared from one member to another (`share`, `unshare`, `shares`) |
| [`vl run`](run.md) | Run a command with vault secrets injected as environment variables |
| [`vl identity`](identity.md) | Your public-key identity |
| [`vl scope`](scope.md) | Key scopes and their members (identity rings) |
| [`vl workspace`](workspace.md) | Virtual workspaces (replacing worktrees) |
| [`vl op`](op.md) | Inspect or restore the operation log |
| [`vl undo`](undo.md) | Undo the last operation; run again to go further back |
| [`vl redo`](redo.md) | Re-apply what the latest `vl undo` took back |
| [`vl watch`](watch.md) | Snapshot continuously as files change |
| [`vl serve`](serve.md) | Serve this repository to editors and agents over a local socket |
| [`vl remote`](remote.md) | Manage remotes: the Veil server projects this repository syncs with |
| [`vl push`](push.md) | Send tags and their history to the Veil server, which moves each branch only if nobody moved it meanwhile (and checks your access) |
| [`vl land`](land.md) | Land a change on a branch through the server's landing service: the server puts it on the branch's newest tip when no path it edits changed there since its base, so you need not pull first |
| [`vl pull`](pull.md) | Fetch tags and history from the Veil server: what you may see |
| [`vl hooks`](hooks.md) | Hooks run before commits and pushes; repository-suggested ones only once this device trusts them (not implemented yet) |
| [`vl gc`](gc.md) | Pack objects and delete those no retained operation can reach |
| [`vl doctor`](doctor.md) | Check this machine's setup and explain every problem found: identity, VEIL_HOME, the repository and its lock, the stat cache, the filesystem (case sensitivity, fsync, network mounts), the clock, the vault and leftover sandboxes. Exits 1 if anything is broken |
| [`vl completions`](completions.md) | Print a shell completion script, e.g. `vl completions zsh > ~/.zfunc/_vl` |
| [`vl man`](man.md) | Print the man page (`vl man \| man -l -`), or write one page per command into DIR |

The read commands (`status`, `log`, `diff`, `show`, `workspace list`, `tag list`, `op log`,
`scan`, `secret list`, `ls`, `resolve --list`, `blame`, `grep`, `attr check`) take `--json`, and so do `split`,
`squash`, `duplicate` and `cherry-pick`: their schemas are in [JSON output](json.md).
