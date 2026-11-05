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
| 2. [Secrets and visibility](secrets-and-visibility.md) | You want to know what is protected, how, and what is not |
| 3. [Embargoes](embargoes.md) | You are fixing a security issue that must stay private until release |
| 4. [Workspaces and agents](workspaces-and-agents.md) | You want several lines of work at once, or run tools and AI agents in sandboxes |
| 5. [Teams and remotes](teams-and-remotes.md) | You share a repository with teammates, over a path or SSH |
| 6. [Maintenance](maintenance.md) | Housekeeping: `gc`, `fsck`, `doctor`, `upgrade`, backups, recovery |
| 7. [Troubleshooting and FAQ](troubleshooting.md) | A command printed a warning or an error you want explained |
| 8. [Scripting with `--json`](scripting.md) | An editor, CI job, agent or script needs `vl`'s output as data |
| 9. [Embedding the engine](embedding.md) | You build on `veil-core` itself: in memory, in tests, or compiled to WebAssembly for a browser |
| 10. [Editors and agents](editors-and-agents.md) | An editor or agent talks to Veil all the time and should keep one connection open (`vl serve --local`) |
| 11. [Hooks](hooks.md) | You want checks before a commit or a push: your own hooks, or the ones a repository suggests in `.veilhooks` |
| 12. [Investigating history](investigating-history.md) | You want to know who wrote a line, when a string appeared, or which change broke something (`blame`, `grep`, `log -S`, `bisect`, renames) |
| 13. [Copying changes, and merges that follow renames](copying-changes.md) | You want a change on another line too (`vl duplicate`, `vl cherry-pick`), or wonder what a merge does with a moved file |
| 14. [Line endings and attributes](line-endings-and-attributes.md) | Your project has Windows line endings, binary files, or wants its own diff or merge driver (`.veilattributes`) |

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
  the same repository. Public remotes never receive them.
* **Tags** are Veil's branches. They follow rewrites of the change they
  point at, and move forward on `vl commit`, `vl merge` and pulls; nothing
  else moves them.
