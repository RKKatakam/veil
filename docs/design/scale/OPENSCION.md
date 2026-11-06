# OpenScion speed gates: first measurement through the server (Hub S1)

The four OpenScion workloads (`docs/OVERVIEW.md`, "Speed gates"), measured
by `veil-bench openscion` (`crates/veil-bench/src/openscion.rs`) on
2026-11-06, branch of Hub milestone S1 (based on `integration` @ `cbfe9ee`).

- **Machine:** Intel i9-13900KF (32 threads), ext4 on NVMe, Linux; release
  builds; the bench directory on that disk.
- **Server:** a release `veil-server` on `127.0.0.1` over TLS (self-signed),
  PostgreSQL 17 in Docker, objects in a local directory. The clones sign in
  as the project's admin (so no projection work) and fetch on demand: one
  request per tree level.
- **Repositories:** 4 KiB files in directories of 100 (`d000/f000.txt`);
  "one directory" is 100 files at both sizes.
- **Times:** median of 5 runs, each a separate process. Git 2.53 on the
  same machine is the reference (`git clone --no-local file://`; one
  directory: `--filter=blob:none --sparse` and `sparse-checkout set`).

| Files | Workload | Veil (ms) | Git (ms) | Target (ms) | Meets target | Beats Git | Veil, path remote (ms) |
|---:|---|---:|---:|---:|---|---|---:|
| 1000 | import a directory | 101.1 | 100.7 | 22.0 | no | no | – |
| 1000 | clone everything (server) | 1074.6 | 270.8 | 51.0 | no | no | 1073.7 |
| 1000 | commit one changed file | 33.7 | 13.6 | 2.5 | no | no | – |
| 1000 | clone one directory (server) | 188.9 | 78.5 | 6.1 | no | no | – |
| 10000 | import a directory | 708.1 | 789.5 | 245.0 | no | yes | – |
| 10000 | clone everything (server) | 9872.0 | 578.7 | 544.0 | no | no | 10134.7 |
| 10000 | commit one changed file | 44.5 | 6.7 | 22.0 | no | no | – |
| 10000 | clone one directory (server) | 193.0 | 62.5 | 25.0 | no | no | – |

## What the numbers say

- **The server adds nothing measurable to a clone.** Cloning through the
  server takes what cloning the same repository from a path remote takes
  (last column: 1,074 vs 1,075 ms; 10,135 vs 9,872 ms). During a 10k clone
  the server used 0.3–0.9 s of CPU and the client 1.8 s; the rest is
  waiting on the disk.
- **The cost is the checkout's durability, not the transfer** (BUG-818,
  pre-existing, fixed since: see "After BUG-818" below): checkout writes every file to a temporary file, `fsync`s
  it, renames it and `fsync`s its directory: 20,154 `fsync`s for 10,001
  files, 7.3 s of the 9.4 s clone under `strace -w`. Git does not `fsync`
  working-tree files. The figures in `OVERVIEW.md` (50 / 483 ms) do not
  reproduce on this machine with today's checkout; they were measured on
  another setup.
- **Clone one directory** fetches 100 files and their trees (the server
  sends only that subtree's objects) and stays flat from 1k to 10k files
  (189 → 193 ms): fetch on demand works as designed; the remaining time is
  the same per-file checkout cost plus the fixed cost of `vl` starting,
  creating a repository and signing in.
- **Commit one changed file** and **import** are client costs measured for
  the record; S1 did not change them.

## After BUG-818: one barrier per checkout (2026-11-06)

Checkout now stages every file beside its path (unsynced), makes them all
durable with one barrier (the object store's parallel `fsync`s), renames
them into place and syncs their directories once
(`docs/ARCHITECTURE.md`, BUG-818). Same machine, same method: release
builds, median of 5, the bench directory in the worktree on the ext4 NVMe
disk (never `/tmp`, which is tmpfs here). "Before" is the S1 branch
(`ab4304a`), measured again the same hour, so both columns share the
machine's state; the server and the bench binary are the same build in
both.

| Files | Workload | Before (ms) | After (ms) | Git (ms) | Target (ms) | Meets target | Beats Git |
|---:|---|---:|---:|---:|---:|---|---|
| 1000 | import a directory | 115.3 | 117.6 | 116.9 | 22.0 | no | no |
| 1000 | clone everything (server) | 1059.3 | **124.4** | 171.1 | 51.0 | no | **yes** |
| 1000 | clone everything (path remote) | 1037.6 | **133.0** | – | – | – | – |
| 1000 | commit one changed file | 32.2 | 30.2 | 4.4 | 2.5 | no | no |
| 1000 | clone one directory (server) | 170.9 | **62.0** | 47.2 | 6.1 | no | no |
| 10000 | import a directory | 694.7 | 788.2 | 814.4 | 245.0 | no | yes |
| 10000 | clone everything (server) | 10043.8 | **1014.2** | 582.6 | 544.0 | no | no |
| 10000 | clone everything (path remote) | 10363.1 | **1178.1** | – | – | – | – |
| 10000 | commit one changed file | 54.9 | 44.7 | 9.0 | 22.0 | no | no |
| 10000 | clone one directory (server) | 188.3 | **74.0** | 81.7 | 25.0 | no | **yes** |

- **Clone is 8.5× (1k) to 9.9× (10k) faster**, and clone one directory
  2.5×. A 10k clone makes 10,155 `fsync`s instead of 20,154 (one per file,
  32 at a time, plus one per directory), so ext4 commits them in a few
  journal transactions instead of one each.
- **Import and commit one file** do not check anything out; their changes
  are run-to-run noise.
- **Barriers compared** (10k path-remote clone, median of 5, the same
  disk): the parallel `fsync`s 1,108 ms; `syncfs` 906 ms; starting each
  file's writeback when it is staged (`sync_file_range`) and then the
  `fsync`s, 1,710 ms. `syncfs` is not used: before Linux 5.8 it does not
  report writeback errors (a failed write would go unnoticed), after it
  reports other files' errors as ours, it waits for every other process's
  dirty data on the file system, and macOS has no equivalent. Under a
  sustained writer on the same disk both varied between 1.3 and 2.5 s.
- **What is left of a 10k clone** (about 1.0 s): roughly 16 `openat` per
  file for the no-follow walks of checkout's steps (`vfs::beneath`), the
  file `fsync`s, and the transfer. Times cluster in steps of about 100 ms
  (1,106 / 1,208 ms) from run to run, which is not checkout's.

## Performance round 1: commit one changed file and import (2026-11-06)

**Goal** (orchestrator, revised the same day): beat Git on the same
machine, on a real disk, with full durability. OpenScion's own numbers
come from an in-memory build (no disk, no fsync, no compression, client
and server in one process, no process start; its `benchmarks/README.md`),
so its 2.5 ms and 22 ms are not like-for-like targets for a durable CLI:
the in-memory column below measures Veil that way.

**Method.** Release builds, the bench directory in the worktree's
`.scratch/` on the ext4 NVMe disk (never `/tmp`), the bench's own
commands (`vl init` in a copy of the generated tree; `vl commit -m` after
rewriting `d001/f001.txt`; Git: `git init && git add -A && git commit`,
`git commit -qam`), 2 s between import and the commits (the bench pushes
in between, so nothing is racy for either tool). Base (`integration` @
`b78e52d`), this round and Git run **interleaved**, run by run: other
processes' writes share the ext4 journal and move every fsync's latency,
so only measurements taken in the same minutes compare. Median of 5 runs,
three sessions each (the range is over the sessions). The server is not
involved in these two workloads.

| Files | Workload | Before (ms) | After (ms) | Git (ms) | Veil in memory, in process (ms) | Target (ms) | Beats Git |
|---:|---|---:|---:|---:|---:|---:|---|
| 1000 | import a directory | 99–105 | **48–58** | 87–94 | 8.8 | 22.0 | **yes** (1.7×) |
| 1000 | commit one changed file | 24–40 | **20–27** | 6–16 | 0.9 | 2.5 | no |
| 10000 | import a directory | 597–616 | **202–208** | 763–764 | 86 | 245.0 | **yes** (3.7×) |
| 10000 | commit one changed file | 52–53 | **43–44** | 9–10 | 7.4 | 22.0 | no |

- **In memory** (`veil-bench openscion-memory`: `MemoryBackend`, one
  process, the same engine work: scanning, sealing, the stat cache, the op
  log), Veil meets all three of these OpenScion targets, before and after
  this round: clone everything 32 / 303 ms (targets 51 / 544). "Clone one
  directory" fetches on demand from the server and has no in-memory form.
- Git makes **no fsync** in either workload here (`strace`: none for
  `git commit -qam`). Veil's commit makes every object, operation and
  head durable before it returns.

### Where the time went (spans, instrumented build, 1k / 10k)

| Commit one file | Before | After |
|---|---:|---:|
| process start, arguments | 0.5–1.7 | 0.3–0.6 |
| identity, `Repo::open` (op heads, history index) | 1.5 / 0.4 | 0.5 / 0.3 |
| stat cache load | 1.1 / 3.1 | 0.4 / 1.7 |
| policy (parsing, glob compilation) | 2.5 / 3.0 | 1.3 / 0.8 |
| scan of the working copy (stat, classify, stat-cache lookups, the changed file) | 7.8 / 27 | 6.4 / 20 |
| of which: the scanner's rules compiled for the changed file | 4.6 / 5–6 | 0–2 (the token rules on another thread; the assignment rule not at all) |
| snapshot transaction (objects, op, head, index) | 4.6 / 4.5 | 4.0 / 3.7 |
| stat cache save (fsynced, 940 KB at 10k) | 1.2 / 2.4 | 0 |
| commit transaction | 9.2 / 4.0 (index compaction) | 4.4 / 3.8 |
| `checkout.json` (twice), finish | 1.9 / 1.5 | 1.6 / 1.5 |
| **total in the process** | **33 / 47** | **20 / 33** |

The commit's floor is its durability: two transactions (the automatic
snapshot, then the commit), each with about eight sequential journal
commits (objects, their renames, the operation file and its directory,
the head file and its directory, the history-index layer and its
directory), plus `checkout.json` twice: about 20 journal commits of
0.35–0.45 ms on this disk, 7–8 ms, against Git's none.

| Import (`vl init`, 10k) | Before | After |
|---|---:|---:|
| scan: read, hash, scan each file, write each object (spans) | 251 ms | |
| publish the objects (spans) | 410 ms | |
| whole command (above) | 597–616 ms | 202–208 ms |
| `fsync` calls (`strace -c -f`) | 10,915 | 407 |
| `rename` calls | 20,216 | 218 |
| new objects on disk | about 10,100 loose files | the 10,000 file contents in 2 packs (the 32 MiB buffer spilled once); 109 trees and snapshots loose |

### What changed

1. **Barriers fsync a transaction's files on a thread each** (from two
   files on; directories stay one worker per 16). A one-file commit's
   barriers used to fsync their 2–5 files one after another, a journal
   commit each (`vfs/disk.rs`).
2. **A transaction's many new file contents are one pack** (256 or more,
   not in memory): buffered (32 MiB, spilled as a pack beyond), compressed
   a few MiB at a time on up to 8 threads, the `.pack` durable before its
   `.idx`, as a pull writes them. Trees and snapshots stay loose until gc,
   as before, so history reads never decompress them (and the scale
   benchmark still counts snapshot reads). An import of 10,000 files makes
   407 fsyncs instead of 10,915 (`store.rs`, `pack.rs`).
3. **The history index merges once:** what the geometric rule merges in
   several steps is written as one layer (a commit used to write up to
   five layer files, two fsyncs each) (`graph_index.rs`).
4. **The scanner compiles what it uses:** the token rules on a thread
   started with the command (`secrets::prepare`); the assignment rule's
   regexes (the costliest, 3.5–6 ms) only for the first text with a
   keyword, the only text it searches; each rule's capture regex for its
   first match. What is found is unchanged (`secrets.rs`).
5. **The stat cache is not rewritten for a record that can never vouch**
   (learnt inside the racy window, as every commit right after an edit
   is): at 10,000 files that was a 940 KB fsynced write per commit
   (`statcache.rs`).
6. **Policy:** glob matchers are no longer compiled one by one (the
   `GlobSet` does the matching), and the accepted policy is not parsed a
   second time when it is the working copy's text (`policy.rs`).
7. `VPath::new` takes an already normal path without splitting and
   joining it (`vpath.rs`).

Measured and **not** kept: a parallel stat prefetch for the scan (as Git's
preload-index): 1.2 ms (5%) at 10,000 files, not worth its threads.

**The 1 GB profile's memory gate** (512 MiB per case), on one generated
tree, base and this round with `/usr/bin/time`: `vl init` 392 → 405 MiB
(4.3 → 3.6 s), `vl status` right after it 459 → 462 MiB. A first version
packed trees and snapshots too and kept a compressed copy of the whole
buffer: 497 and 525 MiB, over the gate; both were changed. The one
regression left: that status lists all 35,000 files just imported and
verifies each one's sealing against its object, which for a packed file
content means decompressing it, as after any `vl gc`: 1.5 → 2.0 s.

### What remains, and why

- **Commit one file vs Git** needs one of three changes that are owner
  decisions, not overhead:
  1. *One transaction per `vl commit`* (the automatic snapshot and the
     commit as one operation): halves the journal commits (about 4 ms),
     but changes what `vl op log` shows and what `vl undo` takes back.
     **Done in round 2** (owner decision).
  2. *The history index as designed:* `graph_index.rs` documents its
     layers as "never synced" (a checksummed cache, rebuilt when damaged),
     but writes them with `create_new`, which fsyncs the file and its
     directory: 0.8–1.5 ms per transaction. This round kept every fsync.
     **Done in round 2.**
  3. *No scan* (a file-system watcher daemon, Git's fsmonitor): the
     10,000-file scan is 14 ms of CPU.
- **Import** beats Git 1.7–3.7×. What is left is reading each file
  through the no-follow walk (about 12 system calls per file), hashing,
  scanning and compressing, on one thread except the compression.

## Performance round 2: clone, one-operation commit, BUG-838, load (2026-11-06)

**Goal** (orchestrator): beat Git on the same machine, on a real disk,
with full durability, for clone everything (10k: 1,014 ms against Git's
583) and clone one directory (1k: 62 against 47); `vl commit` as one
operation (owner decision); history-index layers not synced (as
designed); a load test of the server (`docs/design/scale/LOAD.md`).

**Method.** As in round 1: release builds, the bench directories in the
worktree's `.scratch/` on the ext4 NVMe disk, base (`integration` @
`a9f4fa8`), this round and Git **interleaved run by run** (each Veil
build with its own server and PostgreSQL database), median of 5. Three
sessions; the table shows the first (before the last changes, on a
quieter machine) and the **final** one (the code as committed). A second
session, taken while another agent's containers ran, moved every number
(base's one-directory clone 47.5 → 95.0 ms) and is left out; compare
within a session.

| Files | Workload | Base (ms) | This round (ms) | Git (ms) | Target (ms) | Meets target | Beats Git |
|---:|---|---:|---:|---:|---:|---|---|
| 1000 | import a directory | 56.9 / 56.1 | 53.0 / 57.2 | 96.0 / 97.0 | 22.0 | no | **yes** |
| 1000 | clone everything (server) | 135.0 / 138.8 | **114.2 / 118.6** | 169.3 / 191.8 | 51.0 | no | **yes** (1.5–1.6×) |
| 1000 | commit one changed file | 23.5 / 26.6 | **17.2 / 21.1** | 8.7 / 16.1 | 2.5 | no | no |
| 1000 | clone one directory (server) | 47.5 / 58.5 | 55.2 / 69.1 | 49.6 / 50.9 | 6.1 | no | no |
| 10000 | import a directory | 228.8 / 221.4 | 237.8 / 258.1 | 805.6 / 776.9 | 245.0 | yes / no | **yes** |
| 10000 | clone everything (server) | 1003.3 / 1015.7 | **436.8 / 449.2** | 562.9 / 588.6 | 544.0 | **yes** | **yes** (1.3×) |
| 10000 | commit one changed file | 53.6 / 50.5 | **49.1 / 43.3** | 38.0 / 26.6 | 22.0 | no | no |
| 10000 | clone one directory (server) | 84.7 / 77.8 | 92.2 / 68.8 | 51.5 / 55.8 | 25.0 | no | no |

(first session / final session)

- **Clone everything, 10k: 2.3× faster, beats Git (1.3×) and meets its
  544 ms target**, with every file still durable before the checkout is
  recorded. Clone everything at 1k beats Git in every session.
- **Clone one directory does not beat Git** (69 against 51–56 ms in the
  final session). It is a fixed cost: about 60 `fsync`s in sequence
  (initialising the repository, the pull's and the new change's
  transactions, `repo.json` twice, the `--only` view's two trees,
  `checkout.json` twice), against Git's none, plus process start and three
  requests. This round removed six (`init`'s objects under one barrier)
  and 100 loose objects' worth (a pull of 16 or more objects is a pack);
  measured alone on a quiet machine it took 36–40 ms (Git 47–50), but no
  interleaved session put it below Git.
- **Commit one changed file** is one transaction instead of two (owner
  decision): 4–7 ms less. Git makes no fsync here.
- **Import** is unchanged by this round (the import at 10k varies with
  the disk's load from run to run).

### Where a 10k clone's time went (phases, instrumented build)

| Phase | Before | After |
|---|---:|---:|
| start, `init`, tips, history, the trees | 25–35 | 15–25 |
| the files: request, transfer, frames | 120 | 75–95 (8 requests at once) |
| decode, check and pack what arrived | 150 | 50–55 (compression on 8 threads) |
| checkout: read and stage the files | 280 | 125–175 with the barrier (16 threads; 8 as committed, about 80 ms more) |
| checkout: the barrier (10,000 `fsync`s) | 235–310 | (included above: 256 threads) |
| checkout: renames into place | 75 | 25 (on as many threads) |
| **total** | **about 985** | **about 320–420** |

| `strace -c -f`, 10k clone | Before | After |
|---|---:|---:|
| `fsync` | 10,157 | 10,155 |
| `openat` | 140,741 | 110,669 |
| `statx` (failed) | 70,748 (60,574) | 60,565 (50,371) |

### What changed

1. **Barriers fsync on up to 256 threads** (was 32): ext4 commits
   concurrent fsyncs in one journal transaction. A 10,000-file barrier
   took 310 ms at 32 threads, 125 at 128, 60–65 at 256, no less at 512 or
   1,024 (`vfs/disk.rs`). The threads have 64 KiB stacks; if the system
   gives fewer threads, the barrier uses what it gets.
2. **Checkout reads and stages files of up to 256 KiB on up to 8
   threads, and renames on as many** (`checkout.rs`): the checks that
   decide what to write stay in order on one thread; the outcomes are
   taken in order. Every no-follow walk, hash check and durability step is
   the same. Each thread reading packed objects raises peak memory: 16
   threads took the 1 GB profile's checkout from 28 to 593 MiB (over its
   512 MiB gate), 8 threads and large files on the calling thread keep it
   under (below). A 10k clone: 365 ms at 16 threads, 445 at 8.
3. **One read per file:** checkout no longer reads each object twice (a
   readability probe for backends that clone files ran for every
   backend: `StorageBackend::clones`), and a local store reads an object
   it holds in a pack without probing for a loose copy first (`store.rs`).
4. **What a pull receives is packed on several threads** (`PackSink`
   compresses objects without an earlier version at their path in
   batches of 4 MiB, on 8 threads; deltas as before), **from 16 objects**
   (was 256: a clone of one directory brings a hundred).
5. **The fetch:** a level of more than 2,000 objects goes as up to 8
   requests at once (`Client::fetch_all`); a fresh clone does not probe its
   empty store object by object; **revision 1** of the protocol lets one
   request name objects of several snapshots (a pull behind by many
   landings: one request per level instead of one per snapshot and level;
   `HUB.md` §13.5). Old servers are asked the old way.
6. **`init`'s first objects under one barrier** (`repo.rs`, `InitWrites`):
   the operation that names them stays durable and `repo.json` last; an
   `init` that crashed before `repo.json` has its torn objects removed by
   the next (`crash_during_init`).
7. **`vl commit` is one operation** (owner decision): the automatic
   snapshot and the commit are one transaction (`SnapshotOptions::commit`);
   `vl undo` takes back both (`ARCHITECTURE.md`).
8. **History-index layers are never synced** (`create_new_unsynced`), as
   designed: a torn layer fails its checksum and the index is rebuilt
   (`crash::a_power_loss_tears_history_index_layers_and_they_are_rebuilt`).

Measured and not kept: 512 and 1,024 sync threads (no faster); fewer sync
threads for small barriers (16–64 at 1k files: no difference beyond
noise); 16 staging threads (the 1 GB gate failed).

**The 1 GB profile's memory gate** (512 MiB per case, `scripts/bench-scale.sh
1g`, SFTP and agents phases skipped): passes, with less margin than
before. Highest: `clone, full` (path remote) 502.9 MiB (about 452 before
this round, BUG-813), `status, clean` 460.4, `init` 407.5, `checkout main
(full tree)` 351.8 MiB (28–66 before: the parallel staging's reads of
packed, deltified objects; 593.5 with 16 threads). Finding what each
reading thread holds (about 40 MiB on this profile, 6 MiB on the small
one) would let checkout use more threads within the gate.

### The server under load

`veil-bench load` and its curves are in `docs/design/scale/LOAD.md`. In
short, on this one machine with PostgreSQL: about 2,500 pulls/s while
`main` moves (target 1,000), about 2,000 landings/s across 100 projects
(aim 1,000; bounded by the database's WAL), and one project's `main`
saturating at 20–30 landings/s with many agents (collisions; phase 4's
batched landing).

## Next

1. **Clone one directory** (Git's level, not below): the ~60 sequential
   `fsync`s of `init`, two transactions and the checkout record. Folding
   the clone's pull, new change and checkout record into fewer durable
   steps is the next lever.
2. **Path walks:** about 11 `openat` per file remain in a checkout (each
   step walks from the root without following links); one directory
   descriptor per directory for all of checkout's steps would remove most.
3. **Commit one changed file** (one transaction now): the scan and the
   transaction's journal commits; Git makes no fsync.
4. **Server:** permission lookups cached per person and folder, fewer
   commits per landing, then batched landing (`LOAD.md`).
