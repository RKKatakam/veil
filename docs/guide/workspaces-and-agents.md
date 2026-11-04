# Workspaces and agents

A **workspace** is a line of work with its own working-copy change. Unlike a
Git worktree it needs no directory: it lives in the repository, and you
attach your project directory to it, run a command in a throwaway copy of
it, or read and write its files directly.

1. [Virtual workspaces](#virtual-workspaces)
2. [`vl ws exec`: run a command in a sandbox](#vl-ws-exec-run-a-command-in-a-sandbox)
3. [One-shot runs: `--ephemeral`](#one-shot-runs---ephemeral)
4. [Isolated files in sandboxes: `--with-isolated`](#with-isolated)
5. [Sandboxes](#sandboxes)
6. [Agents in the library: in-memory workspaces](#agents-in-the-library-in-memory-workspaces)

## Virtual workspaces

```text
$ vl ws new agent
Created virtual workspace agent at lqosxltm 1f6220ca (empty) (no description set)
  hint: no directory was created. Use `vl ws exec agent -- <cmd>` or `vl ws switch agent`.
$ vl ws list
  agent: lqosxltm 79607804 agent: add notes
* default: tnqynyzv 28f6843e (empty) (no description set)
```

`vl ws` is short for `vl workspace`.

| Command | Does |
|---|---|
| `vl ws new NAME [-r REV] [--cloak [S]]` | A workspace whose working copy is a new change on `REV` (default: the parents of `@`, like a fresh checkout). `--cloak` seals everything recorded in it (default scope `team`) |
| `vl ws list` | Workspaces and their working copies; `*` marks the one your directory is attached to |
| `vl ws switch NAME` | Attach the project directory to `NAME`: your files are recorded in the current workspace first, then replaced by `NAME`'s |
| `vl ws exec NAME -- CMD…` | Run `CMD` in a sandbox holding `NAME`'s files, and record the result in `NAME` |
| `vl ws cat NAME PATH` | Print a file from a workspace |
| `vl ws write NAME PATH < FILE` | Write stdin to a file in a workspace and record it, in memory |
| `vl ws rm NAME` | Delete a workspace (not the one your directory is attached to) |

In revisions, `NAME@` is a workspace's working copy: `vl diff -r agent@`,
`vl merge agent@`, `vl show fix-cve@`. In `vl log`, `agent@` marks it.

```text
$ echo "x" | vl ws write fix2 other.py
Recorded other.py in lkqqkqwr cd230bf6 (no description set)
$ vl ws cat agent NOTES.md
notes
```

**Committing in a workspace moves tags** exactly as in `default`: a
`vl commit` whose parent is `main` moves `main`. See
[the pitfalls](coming-from-git.md#vl-commit-moves-the-tags-at-the-parent).
When a workspace's work should land later, `vl describe` it and `vl merge
NAME@` when ready.

## `vl ws exec`: run a command in a sandbox

```text
$ vl ws exec agent -m "agent: add notes" -- sh -c 'echo "notes" > NOTES.md; ls -a'
running sh -c echo "notes" > NOTES.md; ls -a in /tmp/veil-ws-agent-1042683-a0f4da85
.
..
.veilpolicy
NOTES.md
app.py
cfg.js
Recorded lqosxltm 79607804 agent: add notes
```

* The sandbox is a fresh directory holding the workspace's files. Your
  project directory is not touched.
* What the command leaves behind is recorded in the workspace, through the
  same policy and secret scanner as your own snapshots, so a tool or agent
  cannot record a secret either.
* `-m MSG` describes the workspace's change.
* The result is recorded **whatever the command's exit status**, and `vl`
  exits with that status. `vl`'s own messages go to stderr; stdout is the
  command's.
* The sandbox has no `.veil` directory: the command cannot run `vl`
  against the repository from inside it.
* You can't `ws exec` the workspace your directory is attached to (`vl`
  says: just run the command).

## One-shot runs: `--ephemeral`

```text
$ vl ws exec --ephemeral -r @ -m "codegen" -- sh -c 'echo gen > gen.txt'
running sh -c echo gen > gen.txt in /tmp/veil-ws-ephemeral-1042697-40123ddb
Recorded zsspmtrn 7c5a91e0 codegen
```

`--ephemeral` needs no workspace: the sandbox holds `REV` (default `@-`),
and the result is a **new change on top of `REV`** that no workspace or tag
points at. Take it from there with its change id: `vl merge zsspmtrn`,
`vl tag set codegen -r zsspmtrn`, `vl edit zsspmtrn`, or
`vl abandon zsspmtrn`.

<a id="with-isolated"></a>
## Isolated files in sandboxes: `--with-isolated`

A sandbox only gets recorded files, so `.env` and other isolated files are
missing. `--with-isolated` copies them in from your local vault. Anything
the command writes that contains one of their values is **quarantined**, so
a copy under another name can't be recorded:

```text
$ vl ws exec agent --with-isolated -- sh -c 'cat .env; cp .env leaked.txt'
running sh -c cat .env; cp .env leaked.txt in /tmp/veil-ws-agent-1042703-3c70c6db
DB_URL=postgres://app:Xk29vLq8sPz@db/prod
warning: leaked.txt quarantined: looks like a secret (injected-isolated-secret at line 1: content of .env injected into the sandbox); not snapshotted. Fix it, or `vl cloak|isolate|expose --force leaked.txt`
No changes in lqosxltm 79607804 agent: add notes
```

What counts as an injected value: each `KEY=value` value that looks like a
secret (8+ characters, mixed character classes or 20+ characters, so
`localhost` or `3000` don't count), the whole file, and every 24+ character
line. The command itself can of course read and use the secrets (that is
the point); quarantine only keeps them out of history.

A quarantined file written in a sandbox **disappears with the sandbox**
(it was never recorded). Use the vault for secrets an agent needs
(`vl run`), not files it writes.

## Sandboxes

* Sandboxes are created in `$TMPDIR` (`/tmp` on Linux, a per-user directory
  under `/var/folders` on macOS), named `veil-ws-<workspace>-<pid>-<random>`,
  and made private to you before the command runs.
* They are removed when `vl` exits, including after `kill -9` (a small
  reaper process watches `vl`).
* `vl doctor` reports leftover sandboxes, if any.
* A sandbox is an isolation of **files**, not a security boundary: the
  command runs as you, with your network and your home directory. Run
  untrusted agents inside your own container or VM.

## Agents in the library: in-memory workspaces

The engine is a library (`veil-core`) and runs on any storage backend,
including memory. An agent can create a workspace over any snapshot in
O(1), write files to an in-memory overlay, and record the result, without
touching a disk. The same policy and scanner apply.

```rust
use std::sync::Arc;
use veil_core::{Identity, MemoryBackend, Repo, StorageBackend, VPath};

let backend = Arc::new(MemoryBackend::new());
let mut repo = Repo::init(backend, Some(Identity::generate("agent")), "agent")?;
let base = repo.root_id();

let ws = repo.ephemeral_workspace(base)?; // O(1): an overlay over a tree view
ws.write("src/lib.rs", "pub fn hello() {}")?;
let (snapshot, report) = repo.commit_ephemeral(&ws, "agent: add hello")?;
drop(ws); // the overlay vanishes; the snapshot stays
assert!(report.quarantined.is_empty());

// Read the result back without a checkout.
let view = repo.tree_view(&snapshot)?;
assert_eq!(view.read(&VPath::new("src/lib.rs")?)?, b"pub fn hello() {}");
```

To work in an existing repository on disk, open it with a
`DiskBackend` and record the agent's result as a tag the user can review:

```rust
let mut repo = Repo::open(Arc::new(veil_core::DiskBackend::new(path)), Some(identity), "agent")?;
let base = repo.root_id(); // or any revision: veil_core::revset::resolve(&repo, "main", "default")?
let ws = repo.ephemeral_workspace(base)?;
ws.write("NOTES.md", "written by an agent\n")?;
let (snapshot, _) = repo.commit_ephemeral(&ws, "agent: notes")?;
repo.set_tag("agent-result", snapshot, None, false)?;
```

* `identity` is an `Identity`: generate one for the agent
  (`Identity::generate("agent")`) or load one with `Identity::from_json`.
  An agent identity that isn't a scope member can't read cloaked files, and
  they are carried over unchanged in what it records.
* `report` (a `BuildReport`) lists what was quarantined, isolated or
  held back, as `vl status` would.
* Writes go through the repository lock, so the agent and your `vl`
  commands can run at the same time.
* Both examples are compiled and run by
  `crates/vl/tests/guide_library.rs`.

Next: [Teams and remotes](teams-and-remotes.md).
