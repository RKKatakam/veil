<img src="assets/icon.svg" width="64" height="64" alt="">

# Veil (`vl`)

**Version control built for AI agents.** Git assumes a few people who each
hold the whole history and take turns pushing. Veil assumes thousands of
agents working at once: each in its own sandbox, each seeing only the
folders it was given, all landing into one `main` without ever pulling,
rebasing or retrying. A server (the Hub) stores the code, decides who sees
what, and does the merging.

Veil is not Git, and doesn't interoperate with it. It's written in Rust.

**Where it came from.** Veil is the brainchild of two things. One is Theo's
(t3.gg) argument that Git is holding agents back, made in his video "Git is
holding us back": commits and branches were designed for people taking
turns, not for agents working all at once. The other is
[Scion](docs/design/scion-for-developers.md), the source control system
Anthropic described building for its own agents: a server at the centre,
thin clients, and landing done by the server. Veil takes that design and
tries to make it something any team can run, from one laptop up. It isn't
affiliated with or endorsed by either.

**Contact:** [@kittu_gamer](https://x.com/kittu_gamer) on X, or
[kittu.krish695@gmail.com](mailto:kittu.krish695@gmail.com). Questions,
ideas and bug reports are all welcome.

## Why it's built for agents

| What goes wrong with Git | What Veil does |
|---|---|
| An agent forgets `git add`, or ends up on a detached HEAD | **No staging and no index.** Every `vl` command records the working copy first. Work can't be lost by forgetting a step. |
| A conflict stops a rebase halfway, with markers in the tree | **A merge or rebase always finishes.** The conflict is stored as data in the change, to resolve later, by that agent or another. |
| Twenty agents need twenty clones or worktrees | **Workspaces.** `vl ws exec NAME --mount -- cmd` gives a command its own copy of the project in milliseconds, whatever the project's size; files load when read. |
| An agent runs on your machine with your SSH keys in reach | **Sandboxes** (bubblewrap, on Linux): its own files, home folder, processes and ports; limits on memory, CPU and time. A secret's value copied into another file is refused, not recorded. |
| Every push to `main` races every other; losers pull, rebase and try again | **`vl land`.** The server lands changes on the newest `main` in batches, so nobody retries. Only a real conflict comes back, to the agent that caused it. |
| A broken `main` blocks everyone until a person bisects it | **Land first, test after.** `main@tested` is the newest `main` that passed its checks, and agents start from it. The server bisects a failure and reverts the culprit; a change reverted twice needs a person. |
| Anyone who can clone sees everything | **Folder permissions, enforced by the server,** in every answer: files, log, blame, search, diffs, PRs, CI. An agent's session can be narrowed to the folders its task needs. |
| A failed approach is thrown away, and the next agent tries it again | **Recorded dead ends.** `vl attempt drop --reason "…"` keeps the failed version and why, on the change, for the next agent or reviewer. |
| "Who wrote this?" is a name anyone can type | **Signed attribution.** Each change records the agent, task and run that made it, under its person's signature. `vl log --agent 'claude-*'` filters by it. |
| `git reflog` archaeology after a bad step | **`vl undo`** takes back any command exactly, and `vl redo` brings it back. |

An agent's whole loop:

```sh
vl ws new fix-login                 # starts from main@tested, the last main that passed its checks
vl ws exec fix-login --mount --private-ports --memory 4G \
   --agent "claude-code" --task "TASK-812" -- my-agent "fix the login bug"
vl attempt drop fix-login@ --reason "locking order deadlocks"   # a dead end, kept with its reason
vl land fix-login@                  # the server puts it on main: no pull, no retry
```

Also built in: pull requests with risk-based approval rules, embargoes for
security fixes (hidden until a deadline), secrets encrypted automatically
(`.env`, keys), thin clones, a web client with passkey sign-in, and history,
blame and search answered by the server in milliseconds.

## Measured

Measured on 2026-11-12, on one 32-core machine that also ran the load
generator, PostgreSQL and the object store. The full tables, misses
included, are in [LOAD.md](docs/design/scale/LOAD.md) (landings) and
[OPENSCION.md](docs/design/scale/OPENSCION.md) (beside Git).

**Landing changes on one `main`** (10,000 agents of 100 people offering
1,000 a second; the target is 1,000 a second held, p99 under 1 s):

| | Veil | Note |
|---|---|---|
| Held for three minutes | **996 a second** (p50 280 ms, p99 1.19 s) | Protected `main`: 998 (p99 1.22 s). All agents one person's: 995 (p99 1.16 s). For comparison: 20 to 30 a second with pull, rebase, push and retry. |
| Three minutes, protected `main`, 3 % overlapping and 2 % conflicting changes | 951 a second (p50 1.36 s, p99 10.8 s) | |
| Ten minutes, with those overlapping changes | 808 a second | Holds about 1,000 for two minutes, then 650 to 800: BUG-1955, open |
| Offered 1.5 times what it can land | lands about 1,000 a second | Agents past capacity are told at once to come back; the backlog clears within about 20 s after the load drops |

The p99 is just over the target, and the runs with overlapping changes
miss it. These runs were made before two later changes: the early "come
back later" answer, and BUG-1956's fix (changes that merged cleanly were
refused as conflicts when several touched one file), merged since and not yet measured again.
An earlier version of this page gave 993 landings a second from a
15-second run, which ends before the queue grows.

**Beside Git**, on the same files (medians of 5 to 9):

| | Veil | Git |
|---|---|---|
| Import a 10,000-file folder | **282 to 326 ms** | 811 ms |
| Import a 1 GB project (35,000 files) | **4.2 s** | 10.9 s |
| Clone 1,000 files through the server | **159 to 163 ms** | 206 to 233 ms |
| Clone 10,000 files through the server | 566 to 621 ms | 569 to 573 ms |
| Commit one changed file among 10,000 | 9.2 to 10.0 ms | **8.1 to 8.6 ms** |
| Commit one changed file in the 1 GB project | **22 to 26 ms** | 26 to 28 ms (33 to 35 with `core.fsync=all`) |
| `status` in the 1 GB project | **8.6 to 11 ms** | 29 to 31 ms |
| `log -n 20` in the 1 GB project | 10 to 13 ms | **1 to 2 ms** |
| Clone one folder of the 1 GB project | 1.0 s | **0.4 s** |
| Default clone of the 1 GB project | **9.4 s** | 29 s |

**Other gates:** blame over 10,000 versions answers in 425 to 528 ms the
first time and 25 ms (p99) after; listing, searching, opening and updating
among 100,000 pull requests take 6 to 22 ms (median); a workspace of
200,000 files starts in under 300 ms.

## Where it stands

Veil is pre-release. Every planned feature is built; the work left is speed
and a run across several machines.

| Part | State |
|---|---|
| Client engine, workspaces, sandboxes | Built |
| Thin clones, caches, storage on S3 with PostgreSQL or YugabyteDB | Built |
| History, blame and search answered by the server | Built, speed gate passed |
| Landing at agent scale, CI, pull requests, embargoes, web client | Built; landing holds about 1,000 a second for three minutes, not yet ten with overlapping changes |
| Review of the whole code base (eight passes) | Done: about 75 bugs found, all but a handful fixed |
| Benchmarks on the final code | Run on 2026-11-12: 10 misses filed (BUG-1940 to BUG-1949); 5 fixed so far, the rest in progress |
| A run across several machines | Next |

The correctness suite is green: about 800 server tests, each run on
PostgreSQL and on YugabyteDB, and about 2,300 client and engine tests. Every
bug found is in [docs/BUGS.md](docs/BUGS.md) with the test that reproduces
it, the open ones included.

Not proven yet: scale across several machines (the numbers above are from
one), the gates that have no benchmark yet (bisect over 10,000 candidates,
server failover, workspaces of a million files), and the sandbox on macOS,
where commands run unconfined for now. By design there is no offline mode:
`vl` commits, splits, squashes and undoes locally, and everything shared
goes through the server.

## Who can see what

| | Veil |
|---|---|
| Access | The creator is the **admin**; everything is **private** by default; admins create **groups**, choose group **managers** and give groups or people access to folders (`vl access billing/ finance`); **`public`** folders are visible to everyone on Earth |
| Secrets | `.env`, keys and the like are **encrypted automatically** and follow the same folder access; every other file is secret-scanned and **quarantined** on a hit; **personal private keys** never leave the machine |
| Security fixes | **Embargoes**: a fix goes to chosen groups now and becomes public later; outsiders see none of it until release |
| Everyday work | Every command **auto-snapshots** the working copy; stable **change ids**; an undoable **op log** |
| Agents | **Virtual workspaces** and in-memory sandboxes; an agent sees what its person sees, with the same secrets |
| Scale | The Scion design: lock-free commits, an atomic branch move, fetch on demand, server-side merges, history and search, batched landings |

Start with [what Veil is](docs/OVERVIEW.md) and
[who can see what](docs/VISIBILITY.md).

## Documentation

* **[User guide](docs/guide/README.md)**: [getting started](docs/guide/getting-started.md),
  [secrets and visibility](docs/guide/secrets-and-visibility.md),
  [embargoes](docs/guide/embargoes.md), [workspaces and agents](docs/guide/workspaces-and-agents.md),
  [teams and remotes](docs/guide/teams-and-remotes.md), [maintenance](docs/guide/maintenance.md),
  [troubleshooting](docs/guide/troubleshooting.md).
* **[Command reference](docs/reference/README.md)**, generated from the CLI
  (also `vl <command> --help` and `vl man`).
* Design, for developers and reviewers: [what Veil is](docs/OVERVIEW.md),
  [who can see what](docs/VISIBILITY.md), the [Veil server (Hub) design](docs/HUB.md),
  [architecture and threat model](docs/ARCHITECTURE.md), [formats](docs/FORMAT.md),
  [cryptography](docs/CRYPTO.md), [releasing](docs/RELEASING.md).

## Install

Veil supports **Linux and macOS**, on x86_64 and aarch64 (Apple
silicon). Windows is not supported.

There is no release yet, so build `vl` from source, as below. The first
release will ship a binary for each platform with an installer script and a
Homebrew formula ([docs/RELEASING.md](docs/RELEASING.md)).

### With Cargo

From a clone of this repository (Rust 1.80 or newer and a C compiler, for
zstd):

```sh
cargo install --locked --path crates/vl
```

### Build from source

```sh
cargo build --release --locked        # binary at target/release/vl
```

The Veil server (`cargo build --release --locked -p veil-server`) also
needs `make` and a C compiler: it is built with jemalloc, from source
(BUG-864).

A static Linux binary, as releases ship it, needs the musl target and
`musl-gcc` (Debian/Ubuntu package `musl-tools`):

```sh
rustup target add x86_64-unknown-linux-musl
cargo build --release --locked -p vl --target x86_64-unknown-linux-musl
```

`vl --version` names the commit it was built from (set `VL_GIT_COMMIT` when
building outside a Git checkout), the repository format it reads and writes,
and the target.

### Running the tests

```sh
cargo test --all-targets --no-fail-fast
# or with cargo-nextest (one process per test); its own `cargo metadata
# --all-features` fails here (the fuse features), so hand it the metadata:
mkdir -p target && cargo metadata --format-version=1 > target/metadata.json
cargo nextest run --cargo-metadata target/metadata.json --workspace --all-targets

cargo test -p vl --test cli_conformance conformance_history::   # one suite
cargo test -p vl --test cli_adversarial -- --ignored adversarial9::   # its bug reproductions
```

The integration tests are a few binaries per crate, one per area
(`crates/veil-core/tests/core_*/`, `crates/vl/tests/cli_*/`); each former
suite is a module of one of them, so a module path filter selects it. The
benchmarks are `#[ignore]`d tests in `core_bench` and `cli_bench`.
`portable` stays a binary of its own (`scripts/check-wasm.sh` builds it
without default features).

### Shell completions and man pages

Release archives have them in `completions/` and `man/`; `vl` also prints
them itself:

```sh
vl completions bash > ~/.local/share/bash-completion/completions/vl
vl completions zsh  > ~/.zfunc/_vl      # with `fpath+=~/.zfunc` before `compinit` in ~/.zshrc
vl completions fish > ~/.config/fish/completions/vl.fish
vl man --out-dir ~/.local/share/man/man1    # one page per command: `man vl-commit`
vl man | man -l -                           # just read the main page (Linux)
```

Then run `vl doctor` to check the machine (see [Platform notes](#platform-notes)).
Maintainers: [docs/RELEASING.md](docs/RELEASING.md) explains how releases are cut.

## Quick start

### On your own, with no server

```sh
cd my-project
vl init                        # creates .veil/, a default .veilpolicy, your identity and a `team` scope
vl status                      # no `add`: the working copy is already snapshotted
vl commit -m "first change"    # describe @ and start a new change on top
vl log
```

```text
@  kquxsrzp alice ✓ 2026-11-11 14:28:42 default@ 38841d55 (empty)
│  (no description set)
○  krqtmlnx alice ✓ 2026-11-11 14:28:42 5294985a
│  first change
◆  zzzzzzzz 72edc798
   root()
```

Change ids (`krqtmlnx`, letters k–z) are stable across rewrites; snapshot ids
(`5294985a`, hex) are BLAKE3 content addresses. `✓` marks a good signature.
More in [Getting started](docs/guide/getting-started.md).

### With a server on your own machine

The Veil server keeps projects and decides who sees what
([VISIBILITY.md](docs/VISIBILITY.md)). It needs PostgreSQL; here that runs in
Docker, and `veil-server` is built from this repository
(`cargo build --release --locked -p veil-server`, then
`target/release/veil-server`):

```sh
docker run -d --name veil-pg -e POSTGRES_USER=veil -e POSTGRES_PASSWORD=veil -e POSTGRES_DB=veil -p 127.0.0.1:5432:5432 postgres:17-alpine
veil-server --database-url postgres://veil:veil@127.0.0.1:5432/veil --data ~/veil-hub --listen 127.0.0.1:8443
```

It makes a self-signed certificate in `~/veil-hub` and keeps running. In
another terminal, in `my-project`:

```sh
vl login veil://127.0.0.1:8443 --name alice --ca ~/veil-hub/self-signed-cert.pem
vl remote add origin veil://127.0.0.1:8443/acme
vl tag set main -r @-          # name the change: tags are what `vl push` sends (`@-` is the parent of @)
vl push                        # creates the project acme: you are its admin, and everything is private
echo "more" >> notes.txt       # any edit
vl commit -m "second change"
vl land                        # the server puts the change on the newest main
```

```text
Created project acme on 127.0.0.1:8443: you are its admin, and everything is private
  pushed main → 5294985a
Sent 4 object(s) to origin
…
  landed main → 6a1c8c53 (1 change(s))
Sent 3 object(s) to origin
```

Groups, folder access, thin clones, pull requests and the web client are in
[The Veil server](docs/guide/the-server.md).

## A tour

> Folders are restricted by the server's access rules ([VISIBILITY.md](docs/VISIBILITY.md)); only secret files are encrypted. An embargoed merge is pushed to a hidden line on the server, which only the groups it names see until its release ([Embargoes](docs/guide/embargoes.md), [HUB.md](docs/HUB.md) §13.31).

```sh
# Secrets: nothing to configure.
echo "DB_URL=postgres://…" > .env              # isolated: never snapshotted, never pushed
echo 'k = "AKIAIOSFODNN7EXAMPLE"' > cfg.js      # quarantined with a warning
vl scan                                          # CI-friendly: exit 1 if a public file holds a secret
vl secret import .env && vl run -- ./server      # encrypted device-local vault → env vars

# Secret files can also be sealed for a scope and synced (only secret files).
vl cloak config/.env.prod --scope ops
vl scope grant ops veil1<bob's public key> --name bob    # from bob's `vl identity show`
vl scope revoke ops veil1<…>    # rotates the key: new secrets are unreadable to them
vl ls                 # every file's tier: public, cloaked:ops, isolated, quarantined…

# Sync: through the Veil server, which sends each person only what they may see.
vl login veil://hub.example.com --name alice
vl remote add origin veil://hub.example.com/acme
vl push               # a new project: you are its admin, everything is private
vl access src/ public # who may see what (push it to apply)

# Delayed-visibility merge (e.g. a security fix): a permission, not encryption.
vl group create security && vl group add security alice   # who sees the fix before its release
vl ws new fix-cve -r main                         # or any change not on `main`
vl merge fix-cve@ --into main --embargo-for security --until +7d -m "Fix CVE-…"
vl push                   # to a hidden line on the server (`embargo/<id>`): only `security` and admins see it
vl embargo release <id>   # (or automatically after 7 days)
vl push                   # tells the server, which puts the fix on `main` (`vl pull` shows it there)
# Until release, `main` on the server stays where it was, and the merge and the
# history it brings in exist for nobody outside the group: no clone, pull, log,
# search or pull request shows them, and copies out of the embargo are refused.
# Veil keeps one unreleased embargo per line: a second `--embargo` merge into
# (or of) a line that still carries one is refused, and so is merging or rebasing
# two embargoed lines together. Release the earlier embargo first, then merge.

# Protection never widens by accident: rebase, `vl new`, squash and policy edits that
# arrive by merge keep sealed secrets sealed. Publishing a secret is explicit (`vl expose --force`).

# Virtual workspaces: no directories, no collisions.
vl ws new agent                                   # exists only in the DAG
vl ws exec agent -m "lint fixes" -- cargo fmt     # runs in the workspace's sandbox, records the result
vl ws exec --ephemeral -r main -- ./codegen.sh    # one-shot agent task on main
vl ws exec agent --only src/ -- ./agent.sh        # sparse sandbox: holds src/ only, records the rest unchanged
vl ws switch agent                                # attach the project dir to another workspace
vl ws mount agent ../agent                        # or mount it as a directory (FUSE): no worktree, no copy

# Everything is an operation.
vl op log
vl undo
```

## CLI grammar

```text
vl <command> [args]     global: -R <repo>  --no-snapshot

Setup        init [path] · clone <veil://host/project> [dest] [--only DIR] · identity show|new
             login <veil://host> [--name] [--ca FILE]
Inspect      status|st · log [-n N] · show [rev] · diff [-r rev | --from a --to b] [--stat]
             ls [-r rev] [paths…] [--all] · files [-r rev] · cat <path> [-r rev] · evolog [-r rev]
History      new [revs…] [-m] · commit -m · describe [-r rev] -m · edit <rev>
             abandon [rev] · rebase -s <rev> -d <dest…> · squash [-r rev]
             restore [paths…] [--from rev]
             merge <revs…> [--into rev] [-m] [--embargo] [--until TIME] [--scope S]
             embargo list|release <id> · tag list|set <name> [-r rev]|delete
Visibility   cloak <secret file…> [--scope S] · isolate <pat…> · expose <pat…> [--force] · ignore <pat…>
             policy show|check <paths…>|accept · scan
Secrets      secret set|get|list|rm|import · run -- <cmd…>
Access       scope list|create <S>|grant <S> <pubkey> [--name] [--admin]|revoke <S> <pubkey>
             scope rotate <S> · scope log <S>
Workspaces   ws list|new <name> [-r rev]|switch <name>|rm <name>
             ws exec <name>|--ephemeral [-r rev] [-m] [--with-isolated] [--only <path>…] -- <cmd…>
             ws cat <name> <path> · ws write <name> <path> < stdin
             ws mount <name> <dir> [--foreground] [--record-every SECS] · ws unmount <name>
Op log       op log [-n N] · op restore <id> · undo · watch [--interval-ms N]
Sync         remote add <name> <veil://host/project>|list|rm
             push [remote] [-t tag…] [--force] · pull [remote]
Server       group list|create|add|remove|manager · access <path> [who…]
Maintenance  gc [--keep-ops-days N] [--grace-minutes M | --prune-now] [--level L] [--no-deltas]
             fsck [-v] · upgrade [--dry-run] [--force] [--sync-secrets]
```

Revisions: `@` (working copy), `name@` (another workspace), `root`, tags,
`origin/main`, change-id or snapshot-id prefixes, and `X-` / `X--` for parents.

### `.veilpolicy`

`.veilpolicy` holds folder access (`billing/ finance`, `src/ public`), which
the server enforces and only admins can change ([VISIBILITY.md](docs/VISIBILITY.md)),
and the device-side rules:

```text
# <pattern>        <tier or who> [scope]     — last matching rule wins
billing/            finance                  # access: plain text, the server decides
config/.env.prod    cloak ops                # a secret file, sealed for `ops`
*.local.json        isolate
target/             ignore
tests/fixtures/     public!                  # deliberate exposure, secret scanning off
```

Built-in rules (`.env`, `.env.*`, `*.pem`, `*.key`, `id_rsa`, `*.tfstate`, …)
come first and **cannot be overridden by a plain `public` rule**, only by
`cloak` (encrypted sharing) or an explicit `public!`. **Only secret files are
ever encrypted:** a `cloak` line on anything else (`secrets/`, `src/`) keeps it
on the device, as `isolate` does, with a warning; give a folder to a group
with `vl access` instead.

Patterns are globs; `\` escapes a character (`config\[prod\].yml`,
`my\ notes.txt`). `vl cloak|isolate|expose|ignore <path>` on an existing path
writes it escaped, so `app/[id]/` means that directory. Built-in secret rules
and `cloak`/`isolate` rules ignore case (`.ENV`, `Secrets/`). `public`,
`public!` and `ignore` rules are case-sensitive. A rule with an invalid scope
(`local`, `rule`, `UPPER`), an unknown tier or no tier is treated as
`isolate`, with a warning.

`.veilpolicy` is shared, but **a change to it that you did not make never
weakens the protection of your local files silently.** Your device keeps
the policy you last accepted. When a merge, pull, checkout, rebase or undo
brings a `.veilpolicy` that would publish, uncloak, re-scope
or stop scanning a file in your working copy (say a PR adds `.env public!`),
that file keeps the protection you accepted, every command warns about it,
and `vl status` lists it as `P`. Review the change with `vl policy show`.
Apply it with `vl policy accept`. Your own edits of `.veilpolicy`, by hand
or with `vl cloak|isolate|expose|ignore`, apply at once, and so do new
`isolate`/`ignore` rules from others.

## Platform notes

Veil runs on Linux and macOS. What differs between them is mostly the
filesystem, and `vl doctor` tells you what yours does.

### Case-insensitive filesystems

On a default macOS volume (APFS or HFS+), and on FAT, exFAT, SMB shares and
case-insensitive ext4 directories, `README` and `readme` are the same file.
Veil detects this per repository (it looks `.veil` up again with its case
swapped and checks that it is the same file), and adapts:

* **Names that collide there are refused, not overwritten.** If a snapshot
  has two entries in one directory that differ only in case (or in Unicode
  normalisation, below), checking it out on such a filesystem fails with an
  error instead of silently writing one file over the other. To catch this
  before a macOS teammate does, `vl` warns on *every* platform, Linux
  included, whenever it snapshots such a pair: rename one of them.
* **Aliases keep the recorded spelling.** If a tool rewrites `README.md` as
  `Readme.md` on a case-insensitive filesystem, the file is still the same
  entry, so Veil keeps its recorded name rather than recording a rename.
* **A rename that only changes case is not recorded** for the same reason.
  Rename through an intermediate name, letting `vl` snapshot in between:
  `mv README.md tmp && vl status && mv tmp Readme.md && vl status`.
* **`.veil` is reserved** in any case (`.VEIL`, `.Veil`), at any depth,
  including spellings with characters HFS+ ignores; a snapshot holding such a
  name is refused, so nobody can plant files in your repository's metadata.

### Unicode normalisation

macOS also treats canonically equivalent names as one: `café` with a
precomposed `é` (NFC) and with `e` + a combining accent (NFD). Veil records
new names in NFC there (as Git does with `core.precomposeUnicode`, the macOS
default), and keeps the recorded spelling when the filesystem hands back the
other form. Names already in a snapshot are never re-normalised, as that would
change snapshot ids. Linux filesystems compare names byte by byte, so two
files whose names differ only in normalisation can coexist there, and get the
collision warning above.

`VEIL_FS_FOLDING` overrides the detection: `exact`, `case`, `unicode`,
`macos` (both) or `auto` (the default). Use it to rehearse a macOS checkout
on Linux (`VEIL_FS_FOLDING=macos vl edit <rev>` refuses what a Mac would), or when `vl doctor` reports
that the detection is wrong.

### Durability, locks and temporary files

* On macOS, `fsync` hands data to the drive without flushing its cache. Veil
  uses `F_FULLFSYNC`, once per batch of writes, and falls back to `fsync` on
  filesystems that do not support it.
* The repository lock records the machine and process that hold it, so a
  lock left by a crashed `vl` is taken over safely. It uses the boot ID and
  PID namespace on Linux, and a per-boot UUID and the local host name
  (stable across network changes) on macOS. On a network filesystem a lock
  can only be proven stale from the machine that took it.
* A workspace's `vl ws exec` sandbox lives in `.veil/local/sandboxes/`
  (private to you) and is kept between runs; it is wiped if a run is
  killed, and removed by `vl ws rm`. `--ephemeral` sandboxes live in
  `$TMPDIR` (`/tmp` on Linux, a per-user directory under `/var/folders` on
  macOS) and are removed when `vl` exits, even after `kill -9`.
* A `vl ws mount` keeps what you write in the mount in
  `.veil/local/mounts/` (private to you), recorded into the workspace by
  `vl ws unmount` and before every other `vl` command. It needs FUSE:
  `fusermount3` on Linux; macFUSE and a `--features macfuse` build on
  macOS.

### `vl doctor`

`vl doctor` checks this machine and the repository you are in, changes
nothing you care about, and explains every problem it finds. It exits 1 if
something is broken:

* **Setup:** `VEIL_HOME` (exists, yours, not world-writable), your identity
  (readable, valid, mode `0600`, also for retired identities) and leftover
  `ws exec` sandboxes.
* **Repository:** `.veil/repo.json` is valid and its format is one this `vl`
  supports (newer: upgrade `vl`; older: a warning), the repository opens,
  the workspace the directory is attached to exists, the lock (free, held by
  a live process, stale, or stuck), the stat cache and the vault.
* **Filesystem:** its type (warns on NFS, SMB, sshfs and other network
  mounts); a durable write, timed (warns if `fsync` looks like a no-op, or
  is very slow); and how it compares names, measured with real files and
  compared with what Veil assumes (it suggests a `VEIL_FS_FOLDING` value if
  they differ).
* **Clock:** set, not behind the last recorded operation, and in step with
  the filesystem's clock (a network share's server).

## Repository layout

```text
crates/
  veil-core/   the engine library (no direct std::fs use outside DiskBackend)
    src/vfs/          StorageBackend + Disk / Memory / Overlay backends
    src/crypto.rs     VeilEnvelope (XChaCha20-Poly1305, SIV-style nonces)
    src/identity.rs   X25519 + Ed25519 identities, key wrapping, signatures
    src/keychain.rs   signed key-ring logs, key generations, embargo records, `local`
    src/object.rs     Blob / Tree / Snapshot / Sealed objects
    src/store.rs      BLAKE3 CAS with transparent decryption, bounded caches
    src/pack.rs       packfiles (zstd, deltas, fan-out index)   src/gc.rs  garbage collection
    src/policy.rs     visibility tiers   src/secrets.rs  secret scanner
    src/builder.rs    working copy → tree (policy enforcement point)
    src/checkout.rs   tree → working copy    src/merge.rs  3-way tree merge
    src/oplog.rs      views + operation log  src/transaction.rs  auto-rebase
    src/workspace.rs  workspaces, ephemeral overlays
    src/embargo.rs    delayed-visibility merges
    src/remote.rs     what a pull from the server writes; the in-process, visibility-filtered transfer
    src/hub/          the permission model and wire protocol shared with the server
    src/vault.rs      device-local encrypted vault
    src/upgrade.rs    `vl upgrade`: journaled repository format migrations
    tests/fixtures/   golden repositories written by every format's release
    tests/core_*/     integration tests, one binary per area (core_engine/engine.rs:
                      end-to-end, entirely in memory)
  vl/          the CLI (clap); tests/cli_*/ drive the real binary
  veil-server/ the Veil server (axum, PostgreSQL/YugabyteDB, S3); tests/server_hub/
docs/ARCHITECTURE.md  design, data model, threat model, roadmap
docs/FORMAT.md        on-disk formats, compatibility rules, migrations
```

## Repository formats

A repository records its format in `.veil/repo.json`. This release reads and
writes format 8 (only secret files are encrypted). `vl upgrade` brings a
format-6 or format-7 repository to it without rewriting history (ids and
signatures stay valid), unless it holds what earlier releases could still
encrypt (descriptions, tags, embargoes, folders): then it refuses, naming
each thing. Formats 1 to 5 are no longer read. See
[docs/FORMAT.md](docs/FORMAT.md).

## Embedding the engine (in-memory, e.g. for agents)

```rust
use std::sync::Arc;
use veil_core::{Identity, MemoryBackend, Repo};

let backend = Arc::new(MemoryBackend::new());
let mut repo = Repo::init(backend, Some(Identity::generate("agent")), "agent")?;
let base = repo.root_id();

let ws = repo.ephemeral_workspace(base)?;       // O(1): overlay over a tree view
ws.write("src/lib.rs", "pub fn hello() {}")?;
let (snapshot, _report) = repo.commit_ephemeral(&ws, "agent: add hello")?;
drop(ws);                                       // vanishes; the snapshot remains
```

## Status

See [Where it stands](#where-it-stands) at the top. Known limits are in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#limitations-and-roadmap), and
every known bug, open or fixed, is in [docs/BUGS.md](docs/BUGS.md). The
checks are `cargo test` for the client and engine and
`scripts/verify-server.sh` for the server. The engine also builds for
WebAssembly ([docs/guide/embedding.md](docs/guide/embedding.md)).

## Contact

Veil is built by kittu. Reach me on X at
[@kittu_gamer](https://x.com/kittu_gamer), or by email at
[kittu.krish695@gmail.com](mailto:kittu.krish695@gmail.com).

## Credits

Thanks to okpom, who helped with the idea for Veil.

The idea owes a great deal to Theo (t3.gg), whose case that Git is holding
agents back is what Veil sets out to answer, and to Anthropic's public
description of Scion, whose design Veil follows. Neither is affiliated with
Veil or has endorsed it.
