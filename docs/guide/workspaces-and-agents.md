# Workspaces and agents

A **workspace** is a line of work with its own working-copy change. Unlike a
Git worktree it needs no directory: it lives in the repository, and you
attach your project directory to it, run commands in its sandbox (a
directory Veil keeps for it, so you never set up a worktree), or read and
write its files directly.

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
| `vl ws switch NAME` | Attach the project directory to `NAME`: your files are recorded in the current workspace first, then replaced by `NAME`'s. `vl undo` right after it switches back |
| `vl ws exec NAME -- CMD…` | Run `CMD` in `NAME`'s sandbox, which holds its files, and record the result in `NAME` |
| `vl ws cat NAME PATH` | Print a file from a workspace |
| `vl ws write NAME PATH < FILE` | Write stdin to a file in a workspace and record it, in memory. Fails, saying why, if the policy keeps the path out (an isolated `.env`, an ignored path) or the scanner quarantines it |
| `vl ws rm [--force] NAME` | Delete a workspace (not the one your directory is attached to) and its sandbox. Refused while a `ws exec` runs in it, and, without `--force`, while its sandbox holds quarantined files (they are in no snapshot) |

**Switching is safe to interrupt.** Before `vl ws switch` touches a file
it notes in `.veil/local/checkout.json` where the directory is going. If it
is killed half way (or the disk fills up), the next `vl` command finishes
the move (`Finished the interrupted move of the working copy to workspace
'NAME'`) before it records anything, so neither workspace ever records a
mix of both. Files that are in no snapshot (isolated, ignored, untracked,
quarantined) stay where they are; see
[the working copy and the filesystem](troubleshooting.md#the-working-copy-and-the-filesystem).

**Undo and switching.** `vl ws switch` is an operation of its own, and
`vl undo` right after it switches back (`vl redo` switches again): the
edits you had made in the workspace you left were recorded there and stay
there. Each workspace keeps its own unrecorded edits whatever you undo or
redo; an undo that would delete a workspace holding recorded edits (undoing
its `vl ws new`) is refused.

In revisions, `NAME@` is a workspace's working copy: `vl diff -r agent@`,
`vl merge agent@`, `vl show fix-cve@`. In `vl log`, `agent@` marks it.

```text
$ echo "x" | vl ws write fix2 other.py
Recorded other.py in lkqqkqwr cd230bf6 (no description set)
$ vl ws cat agent NOTES.md
notes
```

**Committing in a workspace moves tags** as in `default`: a `vl commit`
whose parent is `main` moves `main`. In a **cloaked** workspace it moves
only tags cloaked under the same scope, never `main`. See
[the pitfalls](coming-from-git.md#vl-commit-moves-the-tags-at-the-parent).
When an ordinary workspace's work should land later, `vl describe` it (or
`vl commit --no-advance`) and `vl merge NAME@` when ready.

## `vl ws exec`: run a command in a sandbox

```text
$ vl ws exec agent -m "agent: add notes" -- sh -c 'echo "notes" > NOTES.md; ls -a'
synced sandbox: 3 files written, 0 removed
running sh -c echo "notes" > NOTES.md; ls -a in /home/me/app/.veil/local/sandboxes/agent/files
.
..
.veilpolicy
NOTES.md
app.py
cfg.js
Recorded lqosxltm 79607804 agent: add notes
$ vl ws exec agent -- cargo build      # the second run rewrites nothing
running cargo build in /home/me/app/.veil/local/sandboxes/agent/files
```

* Each workspace has **one sandbox**, `.veil/local/sandboxes/NAME/files`,
  kept between runs like a Git worktree. Before each run, Veil brings it
  to the workspace's current files, rewriting only what changed since the
  last run (`synced sandbox: …` says how much). Files the command leaves
  that are not recorded (an ignored `target/` or `node_modules/`) stay for
  the next run, so incremental builds stay incremental. Your project
  directory is not touched.
* What the command leaves behind is recorded in the workspace, through the
  same policy and secret scanner as your own snapshots, so a tool or agent
  cannot record a secret either.
* `-m MSG` describes the workspace's change.
* The result is recorded **whatever the command's exit status**, and `vl`
  exits with that status. `vl`'s own messages go to stderr; stdout is the
  command's.
* The sandbox has no `.veil` directory, and neither `vl` nor `git` look
  above it for a repository: the command cannot act on your project
  directory through them.
* **One run at a time per workspace.** A second `vl ws exec` in the same
  workspace waits for the first (`waiting: another vl ws exec is running
  in workspace agent`); runs in different workspaces, or `--ephemeral`
  ones, run side by side.
* **Ctrl-C** stops the command; `vl` records what it left and exits with
  130, as for any other exit status.
* If the workspace moves while the command runs (a `vl ws write`, a rebase
  of it from another terminal), recording the sandbox would undo that. The
  result is saved as a change of its own on top of what the command
  started from instead (`workspace 'agent' moved while the command ran; its
  result was saved as change …`); merge it or abandon it.
* You can't `ws exec` the workspace your directory is attached to (`vl`
  says: just run the command).

## One-shot runs: `--ephemeral`

`--ephemeral` keeps no sandbox: each run gets a fresh throwaway copy.

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
running sh -c cat .env; cp .env leaked.txt in /home/me/app/.veil/local/sandboxes/agent/files
DB_URL=postgres://app:Xk29vLq8sPz@db/prod
warning: leaked.txt quarantined: looks like a secret (injected-isolated-secret at line 1: content of .env injected into the sandbox); not snapshotted. Fix it, or `vl cloak|isolate|expose --force leaked.txt`
  cleaned leaked.txt (they held an injected secret; quarantined and taken out of the sandbox)
No changes in lqosxltm 79607804 agent: add notes
```

What counts as an injected value: each `KEY=value` value that looks like a
secret (8+ characters, mixed character classes or 20+ characters, so
`localhost` or `3000` don't count), the whole file, and every 24+ character
line. The command itself can of course read and use the secrets (that is
the point); quarantine only keeps them out of history.

**Injected files live for one run.** After the run is recorded, the
injected files are taken out of the sandbox again (a file the sandbox had
at that path before is put back), and so is every file quarantined
because it holds an injected value: a tracked file gets its recorded
version back, a new one is removed (`cleaned leaked.txt (they held an
injected secret; …)`). So no copy is left for a later run, which no longer
guards against the injected values, to record. Copies in ignored or
isolated files (a build log under `target/`) are never recorded and stay.
Pass `--with-isolated` on every run that needs the files.

Other quarantined files (the scanner found what looks like a secret in
something the command wrote) stay in the sandbox, as they would in your
project directory, and are quarantined again on every run until fixed.
Use the vault for secrets an agent needs (`vl run`), not files it writes.

## Sandboxes

* A workspace's sandbox lives in `.veil/local/sandboxes/NAME/` (`0700`):
  `files/` (where the command runs), `manifest.json` (which snapshot the
  files are, whether a run is in progress), `statcache` (each file's size,
  times, inode, mode and content hash, so recording after a run only reads
  files whose stat changed) and `lock`. It is device-local, like the rest
  of `.veil/local/`, and `vl ws rm` deletes it.
* **Copy-on-write.** Where the filesystem supports clones (btrfs and XFS
  on Linux, APFS on macOS), files the sandbox shares with your project
  directory are cloned instead of copied: no time, no extra space until one
  side changes. Elsewhere (ext4, tmpfs) they are written normally, so a
  sandbox takes as much space as the workspace's files.
* **Crashes.** If `vl` dies during a run (`kill -9`, a crash, a power cut),
  the sandbox is wiped: by a small reaper process that watches `vl`, or by
  the next run, which finds the run unfinished (`Rebuilding the sandbox of
  workspace agent: the previous run did not finish`) and starts from a
  fresh copy. What the dead run changed is lost; what earlier runs recorded
  is not. The same happens after a reboot, and to a sandbox whose files
  were tampered with in a way Veil cannot trust.
* Files you edit in the sandbox yourself, between runs, are recorded by
  the next run, as if the command had written them.
* Tools that look in parent directories (Node's `node_modules` lookup,
  editor and linter configuration) can see your project directory above
  the sandbox. Install dependencies inside the sandbox if that matters.
* `--ephemeral` runs use a throwaway directory in `$TMPDIR` (`/tmp` on
  Linux, a per-user directory under `/var/folders` on macOS), named
  `veil-ws-ephemeral-<pid>-<random>`, private to you and removed when `vl`
  exits, including after `kill -9`.
* `vl doctor` reports leftover throwaway sandboxes, sandboxes of removed
  workspaces and interrupted runs.
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
