# Workspaces and agents

> Today's client, before the server; this changes when the server lands (see [OVERVIEW.md](../OVERVIEW.md) and [VISIBILITY.md](../VISIBILITY.md)). Where this page mentions cloaking, scopes, isolated files or path and SSH remotes, the server replaces them with folder access, encrypted secrets and pushes to the server.

A **workspace** is a line of work with its own working-copy change. Unlike a
Git worktree it needs no directory: it lives in the repository, and you
attach your project directory to it, mount it as a directory of its own
(`vl ws mount`), run commands in its sandbox (a directory Veil keeps for
it), or read and write its files directly. You never set up a worktree.

1. [Virtual workspaces](#virtual-workspaces)
2. [`vl ws exec`: run a command in a sandbox](#vl-ws-exec-run-a-command-in-a-sandbox)
3. [Confinement and limits (Linux)](#confinement-and-limits-linux)
4. [One-shot runs: `--ephemeral`](#one-shot-runs---ephemeral)
5. [Isolated files in sandboxes: `--with-isolated`](#with-isolated)
6. [Sandboxes](#sandboxes)
7. [`vl ws mount`: a workspace as a directory](#vl-ws-mount-a-workspace-as-a-directory)
8. [Agents in the library: in-memory workspaces](#agents-in-the-library-in-memory-workspaces)

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
| `vl ws mount NAME DIR` | Mount `NAME` at `DIR` (FUSE): its files, read and written in place, recorded into `NAME`. See [below](#vl-ws-mount-a-workspace-as-a-directory) |
| `vl ws unmount NAME` | Record what was written in the mount, and unmount it |
| `vl ws rm [--force] NAME` | Delete a workspace (not the one your directory is attached to) and its sandbox. Refused while a `ws exec` runs in it or it is mounted, and, without `--force`, while its sandbox or mount keeps files no snapshot has (quarantined, isolated or ignored ones) |

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

**Undo with agents at work.** In a repository at format 6 (`vl upgrade`),
commands never wait for each other: each records its operation without
taking the repository lock, and operations that ran at the same time are
merged by the next command. Undo then belongs to the workspace you run it
in: `vl undo` in the project directory undoes your last command there (or
a repository-wide one: tags, push, pull, remotes), never an agent's
`vl ws exec agent` or `vl ws write agent`, and keeps whatever the agents
did since. It reverts only what that command changed (a 3-way revert).
`vl undo --op ID` undoes one operation from `vl op log` (an agent's, say),
again keeping everything since. `vl op restore ID` puts the whole
repository back to an earlier operation; if other workspaces recorded work
after it, it lists their operations and refuses unless you pass `--force`
(their work stays in the op log either way).

When two commands change the same thing at the same time (both move one
tag, or one workspace), one change wins, the other target stays a visible
change, and the next command says so once: `warning: tag 'main' was moved
by concurrent commands; kept 1a2b3c4d, and the other target stays a
visible change`. A rewrite made at the same time as a new change on top of
the rewritten one (an amend while an agent commits on it) moves the new
change onto the rewritten one, as a single command would. A rewrite that
would move a change out of an unreleased embargo the other command had put
it in is not applied (`warning: a concurrent rewrite of change … was not
applied`), so nothing leaves an embargo through concurrency. `vl op heads`
lists the heads of the operation log: one, or several just before a
command merges them.

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
[Tags](getting-started.md#tags).
When an ordinary workspace's work should land later, `vl describe` it (or
`vl commit --no-advance`) and `vl merge NAME@` when ready.

## `vl ws exec`: run a command in a sandbox

```text
$ vl ws exec agent -m "agent: add notes" -- sh -c 'echo "notes" > NOTES.md; ls -a'
synced sandbox: 3 files written, 0 removed
running sh -c echo "notes" > NOTES.md; ls -a in /home/me/app/.veil/local/sandboxes/agent/files (confined at /home/me/app)
.
..
.veilpolicy
NOTES.md
app.py
cfg.js
Recorded lqosxltm 79607804 agent: add notes
$ vl ws exec agent -- cargo build      # the second run rewrites nothing
running cargo build in /home/me/app/.veil/local/sandboxes/agent/files (confined at /home/me/app)
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
* **Agents can't declassify.** In the sandbox the command edits
  `.veilpolicy`, not you, so its edit is treated like a policy that
  arrived from someone else. An edit that only protects more (new
  `ignore`, `isolate` or `cloak` rules) is recorded and applies at once.
  One that weakens the workspace's policy (emptying the file, deleting a
  rule, `public!`, `** public`, moving a cloaked directory to another
  scope) is **held back**: the workspace keeps its recorded `.veilpolicy`,
  every file keeps the protection it had (its stronger rules still
  apply), and `vl` says so:

  ```text
  $ vl ws exec agent -- my-agent "tidy the repo"
  …
  warning: .veilpolicy, as the command left it, would weaken the protection of 1 path(s): the edit is not recorded (a command is not you, so the recorded policy stays, and only the edit's stronger rules apply; these keep their recorded protection: secret/plan.md (cloak team → public)). It stays in the sandbox (…/.veil/local/sandboxes/agent/files): review it, then `vl policy accept --workspace agent` records it
  ```

  The edit stays in the sandbox, and every later run holds it back again.
  Read it (`cat .veil/local/sandboxes/agent/files/.veilpolicy`); if you
  want it, `vl policy accept --workspace agent` records it into the
  workspace and lists the files it exposes. If not, fix the file in the
  sandbox (or let the next run of the agent do it). The same holds in
  sparse runs and in mounts; an `--ephemeral` run has nowhere to keep the
  edit, so it is dropped (with the same warning). `vl ws write agent
  .veilpolicy < FILE` is your own command, and records what you give it.
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

## Confinement and limits (Linux)

On Linux every `vl ws exec` runs its command **confined**, through
[bubblewrap](https://github.com/containers/bubblewrap) (`bwrap`, the tool
Flatpak uses): an agent or a test suite can change only its own sandbox,
and cannot read your private files. It needs no root, copies nothing, and
adds a few milliseconds to a run.

```text
$ cd ~/app/src
$ vl ws exec agent -- sh -c 'pwd; ls -A ~; cat ~/.ssh/id_ed25519'
running sh -c … in /home/me/app/.veil/local/sandboxes/agent/files (confined at /home/me/app/src)
/home/me/app/src
.cargo  .claude  .rustup
cat: /home/me/.ssh/id_ed25519: No such file or directory
No changes in lqosxltm 79607804 agent: add notes
```

What the command sees:

| | |
|---|---|
| **The project** | the workspace's sandbox, read-write, **at the project's real path** (`/home/me/app`), starting in the sub-folder you ran `vl` from. Absolute paths and tools that look in parent directories behave as in the project; every write goes to the sandbox. Your project directory and its `.veil` are not there. |
| **The computer's tools** | `/usr`, `/bin`, `/lib`, `/etc`, `/opt`: read-only, live. |
| **`HOME`, `/tmp`, `/var/tmp`** | empty and private, gone after the run. `~/.ssh`, `~/.gnupg`, cloud credentials, other projects and the Veil identity are not there. |
| **The allow-list** | toolchains and agents' own configuration, **read-only**: `~/.cargo` (without its `credentials.toml`), `~/.rustup`, `~/.local/bin`, `~/.local/share/claude`, `~/.nvm`, `~/.pyenv`, `~/.volta`, `~/.bun`, `~/.deno`, `~/.claude`, `~/.claude.json`, `~/.codex`, `~/.gemini`, those that exist. |
| **Processes** | only its own: it cannot see or signal your other programs, or another workspace's run. |
| **Network** | on (agents call their model's API); `--no-network` leaves only a private loopback. |

* **More of the machine, read-only:** `--allow PATH` (repeatable), or for
  every run, in `.veil/local/config.toml` (this repository) or
  `$VEIL_HOME/config.toml` (all of them):

  ```toml
  [exec.confine]
  allow = ["~/.config/gh", "/srv/datasets"]
  ```

  Only these two device-local files count: nothing in the repository (a
  teammate's tracked `config.toml`) can widen what an agent sees. The Veil
  home, your project directory and cargo's credentials stay hidden even
  inside an allowed folder, or behind an allowed link to one; a path
  inside the Veil home or the project cannot be allowed. An agent that must
  write its configuration (a token refresh) cannot, here; a read-only
  folder still lets the command reach sockets and FIFOs in it.
* **When the command exits, everything it started stops** (a dev server
  too), and `kill -9` of `vl` stops it all as well. In the rare instant
  `bwrap` starts the sandbox, that is left to the reaper (with injected
  secrets or `--ephemeral`) or to the next `vl ws exec` in the workspace
  (or `vl ws rm`); the reaper then takes injected files out as before.
* **Ctrl-C, SIGTERM and SIGHUP** reach the command as before: the command
  has no terminal of its own (no keystrokes can be pushed into yours), so
  `vl` passes them on.
* **If bubblewrap is missing or does not work** (`vl doctor` says), the run
  fails before anything is touched: `install bubblewrap (apt install
  bubblewrap, …)`. `--unconfined` runs the command as before, with
  everything your user can reach, and says so.
* **Limits** (none by default):

  ```text
  vl ws exec agent --memory 4G --pids 1024 --cpu-time 30m --timeout 60m -- my-agent "…"
  ```

  | flag | stops |
  |---|---|
  | `--memory 4G` | memory over 4 GiB |
  | `--cpus 2` | caps the CPU rate at 2 CPUs |
  | `--cpu-time 30m` | CPU time over 30 minutes, all processes together |
  | `--pids 1024` | more than 1024 processes and threads (forks fail) |
  | `--timeout 60m` | the run after 60 minutes, background processes included |

  A limit that fires stops everything in the sandbox (SIGTERM, then SIGKILL
  after 10 s; a memory kill at once) and says so (`stopped: memory limit (4
  GiB) reached`). **`vl` is never inside the limits**: the run is
  recorded, scanned and cleaned up as always. Defaults go in
  `[exec.limits]` (`memory`, `cpus`, `cpu-time`, `pids`, `timeout`, `mode`)
  in the same two files; flags win. With a systemd user manager (any
  desktop Linux, or a server with lingering), the kernel enforces them
  (a systemd scope); without one, memory, process count and CPU time are
  polled every 100 ms (soft) and `--cpus` is not available, and `vl` says
  so. `--limits strict` refuses to run instead.
* **What confinement does not cover:** your environment variables are
  passed on (agents need their API keys); with the network on, the
  command can send anything it can read (the sandbox, injected secrets,
  the allow-list) anywhere, and reach abstract Unix sockets (X11's);
  kernel bugs. Give risky agents test keys and `--no-network`.
* **macOS** runs unconfined for now (`vl doctor` says so).

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

<a id="only"></a>
## Sparse sandboxes: `--only`

An agent working on one part of a big repository doesn't need the rest
of it on disk. `--only` gives the sandbox just the paths you name
(directories or files), plus `.veilpolicy`:

```text
$ vl ws new agent
$ vl ws exec agent --only src/ tests/ -m "agent: fix parser" -- my-agent "fix the parser bug"
sparse: sandbox holds src, tests
synced sandbox: 412 files written, 0 removed
running my-agent fix the parser bug in /home/me/app/.veil/local/sandboxes/agent/files (confined at /home/me/app)
warning: not recorded: 1 file(s) written outside --only src, tests (removed from the sandbox): NOTES.md
Recorded lqosxltm 5b0e44a1 agent: fix parser
$ vl ws exec agent --only src/ tests/ -- cargo test    # the next run rewrites nothing
```

That is the whole recipe for an agent that needs neither a worktree nor
a copy of the repository: `vl ws new agent`, then
`vl ws exec agent --only src/ -- …` as often as you like, and
`vl merge agent@` (or `vl diff -r agent@`) when it is done.

* **Everything outside the paths is recorded exactly as the workspace has
  it.** A sparse run never deletes or changes a file it doesn't hold, and
  cloaked files outside keep their sealing.
* **Inside the paths, it is an ordinary run**: edits, new files and
  deletions are recorded, through the policy and the secret scanner.
  Deleting `.veilpolicy`, or leaving it unreadable, a symlink or a
  directory, is not an edit of the policy, in any sandbox: the workspace
  keeps its recorded policy (with a warning, and a deleted one is put
  back), so no cloaked file is ever declassified that way. An edit of the
  file that weakens the policy is held back (see "Agents can't
  declassify" above).
* **Files the command writes outside the paths are not recorded.**
  `vl` lists them (`not recorded: … written outside --only`) and removes
  them from the sandbox, so a later run with more paths never mistakes
  them for the workspace's files. Ignored and isolated files are the
  exception: build output such as `target/` or `node_modules/` stays for
  the next run wherever it is (it would not be recorded anyway), as do
  quarantined files from earlier runs and files the command did not write
  (see below).
* **`.veilpolicy` is always there** (the snapshot needs it to classify
  anything). If the command edits it, the new policy applies to every
  file of the workspace, inside the paths or not, as for a full run: a
  newly cloaked directory outside the paths is recorded cloaked, and an
  edit that would weaken the protection of a file outside the paths is
  held back as in a full run. Files
  that were ignored or isolated before the edit are never removed as
  "written outside --only".
* **Removing a directory in the sandbox** (`rm -rf src` with
  `--only src/lib.rs`) deletes only the files of the paths under it;
  the rest of `src/` stays as the workspace has it.
* **Paths** follow the usual rules: relative to the current directory,
  never outside the repository (`..` that climbs out, or an absolute path
  elsewhere, is refused). Each must name a file or directory in the
  workspace (`--only nope` is an error; to start a new directory, name
  its parent). Overlapping paths are fine (`--only src src/lib.rs` is
  `--only src`), and `--only .` at the root is the whole tree. Nested
  repositories are never part of a workspace, so they can't be chosen.
* **Changing the paths is cheap.** The sandbox remembers its paths; a run
  with other paths (or none) only writes what joins and removes what
  leaves (`sparse: sandbox holds …` says when they change). Nothing
  unrecorded is lost: what a command writes is recorded (or reported)
  before the next run narrows, and a file you edited in the sandbox by
  hand that a narrower set leaves outside stays where it is, unrecorded,
  with a warning on each run, until a run whose paths hold it records
  it.
* **`--with-isolated` injects every isolated file**, inside the paths or
  not: they are what the command runs with (`.env` at the root of the
  project), not what it edits, and they are taken out again after the run
  as always. A copy of one written outside the paths is simply not
  recorded (and is removed); a copy inside is quarantined.
* **`--ephemeral --only`** works the same way: the throwaway directory
  holds only the paths, and the new change has every other file of `REV`.
* If the workspace moves while a sparse command runs, the result is saved
  as a change on top of what the command started from, as for a full
  run, with every file outside the paths as they were.

<a id="with-isolated"></a>
## Isolated files in sandboxes: `--with-isolated`

A sandbox only gets recorded files, so `.env` and other isolated files are
missing. `--with-isolated` copies them in from your local vault. Anything
the command writes that contains one of their values is **quarantined**, so
a copy under another name can't be recorded:

```text
$ vl ws exec agent --with-isolated -- sh -c 'cat .env; cp .env leaked.txt'
running sh -c cat .env; cp .env leaked.txt in /home/me/app/.veil/local/sandboxes/agent/files (confined at /home/me/app)
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
at that path before is put back), and so is every file that holds an
injected value, wherever it is: quarantined files, but also ignored or
isolated ones the snapshot never looks at (a build log under `target/`,
a `.env.bak`). A tracked file gets its recorded version back, anything
else is removed (`cleaned leaked.txt, target/app.log (they held an
injected secret; …)`). Pass `--with-isolated` on every run that needs the
files.

**The guard stays.** A sandbox that was given isolated files remembers
them (sealed, in `.veil/local/sandboxes/NAME/guard.sealed`), and every
later run in it guards against them, with or without `--with-isolated`:
a copy that turns up after the run (a dev server the command started in
the background, which writes its environment to a log a minute later) is
quarantined and taken out by the next run, never recorded. Unconfined,
`vl` does not kill background processes a command leaves running (a
confined run stops them with its command); `vl ws rm` forgets the guard
with the sandbox.

Other quarantined files (the scanner found what looks like a secret in
something the command wrote) stay in the sandbox, as they would in your
project directory, and are quarantined again on every run until fixed.
Use the vault for secrets an agent needs (`vl run`), not files it writes.

## Sandboxes

* A workspace's sandbox lives in `.veil/local/sandboxes/NAME/` (`0700`):
  `files/` (where the command runs), `manifest.json` (which snapshot the
  files are, which paths a sparse sandbox holds, whether a run is in
  progress), `statcache` (each file's size,
  times, inode, mode and content hash, so recording after a run only reads
  files whose stat changed) and `lock`. It is device-local, like the rest
  of `.veil/local/`, and `vl ws rm` deletes it.
* **Copy-on-write.** Where the filesystem supports clones (btrfs and XFS
  on Linux, APFS on macOS), files the sandbox shares with your project
  directory are cloned instead of copied: no time, no extra space until one
  side changes. Elsewhere (ext4, tmpfs) they are written normally, so a
  sandbox takes as much space as the workspace's files.
* **Nothing a command wrote is ever lost to a failure.** If `vl` is
  killed while the command runs (`kill -9`, a crash), or its result cannot
  be recorded (another `vl` held the repository for too long:
  `the command's output was not recorded: …; it stays in the sandbox`),
  the files stay where they are. The next run records them first
  (`Recording the output of an earlier run in workspace agent, which was
  not recorded`), or `vl ws exec agent --record-only` does, without
  running anything. If the run had `--with-isolated`, a small reaper
  process that watches `vl` takes the injected files out again.
* **SIGTERM and SIGHUP** (an IDE stopping a task, `kill`, closing the
  terminal) are passed on to the command, like Ctrl-C: it stops, and `vl`
  records what it left.
* **Rebuilds.** After a reboot (sandbox files are written without
  flushing them to disk, so a power cut can tear them), or when a run died
  before its command started (`Rebuilding the sandbox of workspace agent:
  the previous run did not finish`), or when the sandbox was tampered with
  in a way Veil cannot trust, the sandbox is rebuilt from the workspace.
  Work that is in no snapshot survives it: quarantined files and files
  kept outside `--only` paths are put back (`kept 2 file(s) of unrecorded
  work across the rebuild: …`), and if other files differ from the
  workspace (your own edits, or files the crash tore), or a run that was
  interrupted by a reboot was never recorded, the previous files are moved
  whole to `.veil/local/sandboxes/agent/unrecorded-…/`, with a warning:
  copy back what you need, then delete it. `vl doctor` lists them, and
  `vl ws rm` refuses to delete them without `--force`. Ignored build
  output (`target/`) does not survive a rebuild.
* Files you edit in the sandbox yourself, between runs, are recorded by
  the next run, as if the command had written them.
* Unconfined (`--unconfined`, macOS), tools that look in parent
  directories (Node's `node_modules` lookup, editor and linter
  configuration) can see your project directory above the sandbox.
  Confined, the sandbox is at the project's own path, with nothing above
  it.
* `--ephemeral` runs use a throwaway directory in `$TMPDIR` (`/tmp` on
  Linux, a per-user directory under `/var/folders` on macOS), named
  `veil-ws-ephemeral-<pid>-<random>`, private to you and removed when `vl`
  exits, including after `kill -9`.
* `vl doctor` reports leftover throwaway sandboxes, sandboxes of removed
  workspaces, interrupted and unrecorded runs, and files a rebuild kept.
* A sandbox never hands its command a **symlink that could lead out of
  it**. A tree's link is materialised only when its target is relative,
  climbs with `..` first and then names only, and stays inside the
  sandbox: `bin/tool -> ../lib/tool.sh` and `current -> releases/v2` are
  written as links. Any other link is not materialised (`failed: x -> …:
  … ; the link is not materialised in this sandbox`), and recording the
  run keeps it as it is:
  * a target that climbs out (`x -> ../../../../../.env`, which would reach
    the project's isolated `.env` without `--with-isolated`);
  * a `..` after a name (`x -> u/../../.env`): if `u` is itself a link, the
    kernel climbs from where `u` points, so two links that each look
    inside can together reach outside;
  * any absolute target (`/usr/share/dict/words` too): what it names
    depends on who reads it (`/proc/self/cwd/../../.env` is the sandbox
    itself, then the project above it).

  This holds for full, `--only` and `--ephemeral` sandboxes and for `vl
  bisect run` alike. A command that needs such a link can create it
  itself. A mounted workspace (`vl ws mount`) shows links as they are, as
  your project directory does.
* Confined (Linux), the command runs as you but sees only the sandbox,
  the computer's tools and the allow-list ([above](#confinement-and-limits-linux)).
  Unconfined, a sandbox is an isolation of **files**, not a security
  boundary: the command runs as you, with your network and your home
  directory. Either way, run hostile code inside your own VM.

## `vl ws mount`: a workspace as a directory

```text
$ vl ws mount agent ../agent
Mounted workspace agent at /home/me/agent (process 41022)
  `vl ws unmount agent` records it and unmounts; until then other vl commands record it before they run
$ cd ../agent && $EDITOR src/app.py && cargo test
$ vl -R ../app diff -r agent@ --stat
M src/app.py
$ vl ws unmount agent
Recorded lqosxltm 2b7d01aa (no description set)
Unmounted workspace agent from /home/me/agent
```

A mount is a workspace as a real directory, with nothing copied: files
are read from the workspace's snapshot when something reads them, and
only what you change takes space. Use it instead of a worktree: one
directory per line of work, any tool works in it, your project directory
stays where it is.

* **What you see** is what a checkout of the workspace would give you, as
  you: cloaked files you are a member for, in plaintext; cloaked files you
  are not, absent (or their last public version, as for an embargoed
  fix); conflicted files with their markers. When you are granted a
  scope (or an embargo is released) and pull, the files you can now read
  appear in the mount within about a second. Files you never saw are never
  recorded as deleted: if you delete a directory that held some, they
  stay in the workspace (and out of the mount). Nobody else on the
  machine, not even root, can enter the mount, and its files are `0600`
  (`0700` for executables).
* **What you write** (new files, edits, deletions, renames, `mkdir`,
  `chmod +x`, truncation) goes to a copy-on-write overlay in
  `.veil/local/mounts/NAME/`, private to you, and is recorded into the
  workspace through the same policy and secret scanner as your own
  snapshots. Files the policy isolates (`.env`), ignores (`target/`) or
  that look like a secret stay in the mount, as they would in your project
  directory, and are never recorded (`vl` warns once about each). Tools
  and agents write in mounts too, so an edit of `.veilpolicy` there is
  judged as in a sandbox: what weakens the policy is held back, stays in
  the mount, and `vl policy accept --workspace NAME` records it.
  Symlinks are created as they are and recorded as links (repository
  format 5; refused below it); the mount itself never follows one (the
  kernel resolves a link for the program that uses it). Hard links and
  special files are refused.
* **When it is recorded:** by `vl ws unmount`; before every other `vl`
  command (as your project directory is), so `vl diff -r agent@`,
  `vl merge agent@` or `vl commit` see what you wrote; every 60 seconds
  while there are changes (`--record-every SECS`, `0` to turn it off);
  and when something else unmounts it (`fusermount -u`). Edits reach the
  overlay on disk as they are made, and are durable once the file is
  closed (or `fsync`ed). These
  recordings are not commands: `vl undo` (and `vl redo`, `vl op
  restore`) skips them and keeps what they recorded, as it keeps your
  project directory's edits.
* **One process serves a mount**: a background `vl` (its messages go to
  `.veil/local/mounts/NAME/log`), or `vl ws mount --foreground`, which
  serves until Ctrl-C (or `vl ws unmount`). A second mount of the same
  workspace is refused.
* **The workspace moving under the mount** (a `vl ws write`, a `vl ws
  exec`, `vl describe -r agent@`, an undo) shows in the mount within about
  a second, and your edits stay. If that move changed a file you also
  changed in the mount since it was last recorded, your version is saved
  as a change of its own first, and the mount shows the workspace's
  (`workspace 'agent' changed under its mount …; the mount's version was
  saved as change yrynnxov …`, in the log and in the next command's
  output). Merge or abandon that change.
* **Crashes lose nothing written.** If the serving process dies (`kill
  -9`, a crash), the directory says `Transport endpoint is not connected`.
  `vl ws unmount agent` detaches it and records what the overlay holds;
  `vl ws mount agent DIR` again picks the overlay up as it is. `vl doctor`
  and every `vl` command point out a mount whose process died.
* **After unmounting**, files the workspace does not record (isolated,
  ignored, quarantined) are kept in `.veil/local/mounts/NAME/` and are
  there again at the next mount. `vl ws rm --force NAME` deletes them.
* You can't mount the workspace your directory is attached to, mount
  inside the project directory or inside any other Veil repository (its
  snapshots would walk into the mount and record what it shows, cloaked
  files in plaintext, as its own), or on a directory that is not empty.
  A repository created around a mount later never records it either. `vl ws switch` to a mounted workspace is
  refused: unmount it first.
* `vl ws unmount` refuses while something has a file open in the mount or
  a shell is `cd`ed in it (`… is busy`); everything is recorded anyway.
  Close it and run it again.
* `vl` itself does not work from inside a mount (there is no `.veil`
  there): use `vl -R <project> …`.
* Renaming a directory copies the files it holds that you have not
  changed into the overlay (a large tree costs a copy; files you changed
  are moved, at no cost). Open files are written in place on disk, never
  held in memory, so a sparse file (`truncate -s 2G`, a disk image) costs
  nothing until data is written. No file in a mount can grow past the
  largest object Veil records (`VEIL_MAX_OBJECT`, 4 GiB): a larger
  `truncate` or write fails with `File too large`.

**Requirements.** Linux: `/dev/fuse` and `fusermount3` (the `fuse3`
package), nothing else; `vl` mounts without libfuse. macOS: install
[macFUSE](https://macfuse.github.io) and build `vl` with
`cargo build --release --features macfuse` (release builds for macOS are
made without it, so they need no kernel extension). A `vl` built without
FUSE says so.

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
* The agent and your `vl` commands can run at the same time: at format 6
  nothing waits for a lock, and concurrent operations are merged; below
  format 6 writes go through the repository lock.
* Both examples are compiled and run by
  `crates/vl/tests/cli_workspaces/guide_library.rs`.

Next: [Teams and remotes](teams-and-remotes.md).
