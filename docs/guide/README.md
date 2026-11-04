# Veil user guide

This guide is for people who **use** Veil (`vl`) day to day. Design notes for
developers and reviewers are in [`docs/ARCHITECTURE.md`](../ARCHITECTURE.md),
[`docs/FORMAT.md`](../FORMAT.md) and [`docs/CRYPTO.md`](../CRYPTO.md).

Every example here was run with the `vl` it documents. Output is real,
trimmed where marked (`…`); some paths and host names were shortened
(`/home/alice`, `build.example.com`). Your ids, keys and times will differ.

| Page | Read it when |
|---|---|
| 1. [Getting started](getting-started.md) | You are new to Veil: install, identity, `vl init`, the no-staging model, changes and revisions |
| 2. [Coming from Git](coming-from-git.md) | You know Git: concept map, cheat sheet, and the pitfalls |
| 3. [Using Veil with GitHub](github.md) | Your code lives on GitHub (CI, reviews, a public mirror) |
| 4. [Secrets and visibility](secrets-and-visibility.md) | You want to know what is protected, how, and what is not |
| 5. [Embargoes](embargoes.md) | You are fixing a security issue that must stay private until release |
| 6. [Workspaces and agents](workspaces-and-agents.md) | You want several lines of work at once, or run tools and AI agents in sandboxes |
| 7. [Teams and remotes](teams-and-remotes.md) | You share a repository with teammates, over a path or SSH |
| 8. [Maintenance](maintenance.md) | Housekeeping: `gc`, `fsck`, `doctor`, `upgrade`, backups, recovery |
| 9. [Troubleshooting and FAQ](troubleshooting.md) | A command printed a warning or an error you want explained |
| 10. [Scripting with `--json`](scripting.md) | An editor, CI job, agent or script needs `vl`'s output as data |
| 11. [Editors and agents](editors-and-agents.md) | An editor or agent talks to Veil all the time and should keep one connection open (`vl serve --local`) |

The [command reference](../reference/README.md) lists every command and
flag. It is generated from `vl` itself and cannot drift from it.

## Ten-second summary

```sh
vl init                          # a repository in the current directory
vl status                        # there is no `add`: every command snapshots the working copy
vl commit -m "What I did"        # describe this change and start a new one on top
vl log                           # the snapshot graph
vl undo                          # step back through the operation log (`vl redo` to step forward)
```

* There is **no staging area**. Every `vl` command first records the files on
  disk as a snapshot of the current change, `@`.
* **Secrets are handled by the engine.** `.env`, keys and similar files are
  never recorded, and a public file that contains a credential is
  quarantined (kept out of history) with a warning.
* **Cloaked paths** are encrypted for a *scope* (a group of people), inside
  the same repository. Public remotes and GitHub never receive them.
* **Tags** are Veil's branches. They follow rewrites of the change they
  point at, and move forward on `vl commit`, `vl merge` and pulls; nothing
  else moves them. See [the pitfalls](coming-from-git.md#pitfalls).
