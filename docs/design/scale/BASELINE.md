# Scale baseline: 1 GB, `integration` @ b549e1e

These are the first numbers from the scale benchmark (`9-scale-benchmark.md`), measured on `integration` @ **b549e1e** before any scale stream lands. They rank the streams: see [the ranked list](#ranked-offenders) and [what it means for the plan](#what-this-means-for-the-plan).

- **Machine:**
  - 32 CPUs (i9-13900KF), 30 GB RAM;
  - Linux 7.0.0-42, ext4 (no reflinks);
  - warm page cache.
- **Neighbours:** other agents were building at the same time, so the absolute times carry some noise.
- **Run:** `scripts/bench-scale.sh 1g -- --rtt 0,2`, 2026-11-05. It took 21.5 minutes end to end, including 4 minutes of generation, then deleted everything it generated.
- **Raw results** (not committed): `.scratch/bench-results/1g-seed1-*.json` and `.md`.

## Memory after streaming pack writes (BUG-800, G1)

`scripts/bench-scale.sh 1g`, 2026-11-05, on the BUG-800 branch (streaming `PackWriter`, prefetch spooled to disk; see `4-background-cleanup-streaming.md`, G1). Same machine. The run took 13 minutes, every phase included. Raw results (not committed): `.scratch/bench-results/1g-seed1-20261105T052050Z.md`.

"Before" is the base `integration` @ b4ec8db (the read-side wave: `SLURP_BUDGET`, 128 MiB gc packs), measured the same day with `/usr/bin/time` on the same generated repository and a path remote. Pull of one snapshot was not measured on the base.

| case | baseline (b549e1e) | before (b4ec8db) | after, path | after, SFTP | gate (512 MiB) |
|---|---:|---:|---:|---:|---|
| clone, full | 1,975 MiB | 1,230 MiB | **367 MiB** | **424 MiB** | passes |
| pull, 1 new snapshot | 950 MiB | – | **171 MiB** | **172 MiB** | passes |
| pull, nothing new | 559 MiB | 151 MiB | **139 MiB** | **139 MiB** | passes |
| gc, first (packs 3.38 GB loose) | 867 MiB | 366 MiB | **297 MiB** | | passes |
| gc, again (nothing new) | 998 MiB | 540 MiB | **467 MiB** | | passes |
| push, initial (all tags) | 310 MiB | 283 MiB | **220 MiB** | **341 MiB** | passes |

Times are unchanged (clone 59 s, gc 17 s, initial push 12.9 s).

What still grows with the store: the per-object tables (gc's inventory, reachability set and path hints; a sync's `seen` set and the remote's inventory), a few tens of bytes per object, and the bounded caches (delta bases 64 MiB, packs held whole 64 MiB, a sync's last versions 64 MiB). Most of `gc, again` is its mark phase: the caches fill, and the tables are built (instrumented run: +207 MiB during marking, +92 MiB while packing). At 5 GB, gc's tables are the first thing to watch (the prune bitmap of item 4 replaces them).

## The harness

- **The crate:** `crates/veil-bench` is a workspace member, but not one of the `default-members`, so `cargo test --all-targets` never builds it. It is driven by `scripts/bench-scale.sh [tiny|small|1g|5g] [--cloaked] [-- flags]`.
- **Generator:** builds the history in-process through `veil_core`, with ephemeral workspaces and transactions.
- **Real processes:** every measured command is a separate process of the release `vl` binary.
- **Determinism:** the generator is deterministic from `--seed` (file contents, paths, history shape). Change ids, timestamps and signatures stay random.

| profile | tree | files | history | other content |
|---|---|---|---|---|
| `1g` (this run) | 1.15 GB on disk | 35,006 | 10,073 snapshots: 10,000 on `main` (11 import chunks), 199 merges, 536 renames, 516 deletions, 20 tags | 70 % source / 20 % JSON+YAML / 10 % binaries of 100 KB–20 MB; directory depth up to 8, fan-out up to 20 |
| | | | a `release` line (20 snapshots) | a cloaked fix line of 50 snapshots, merged into `release` under an unreleased embargo (`vl merge --embargo`) |
| | | | | 26 `cloak` rules for scopes `a` and `b` (about 3 % of files); 5 isolated `.env` files |
| `5g` (script ready, not run) | ~4 GB of files plus 4 binaries of 200–400 MB | 150,000 | 20,000 snapshots | as `1g` |
| `--cloaked` (any size) | | | | 85 % of the files under cloak rules for `a` and `b` (only smoke-tested, at `tiny`) |
| `small`, `tiny` | 100 MB and 10 MB | | | for no-regression checks and smoke tests |

**Store size.** The generated store was **3.38 GB loose, in 337,642 files**, for a 1.15 GB tree. `vl gc` packs it to **0.67 GB in 10,162 files**.

**Peak RSS** is the `vl` child's `ru_maxrss`, read with `wait4`.
- Linux keeps the parent's high-water mark across vfork+exec, so no value can read below the harness's own peak.
- The generator therefore runs in a child process, and traces are parsed as streams.
- The floor this run was 28 MiB.

**The walk and lock detector needs no product hook.** Selected cases run once more under `strace -f -y`, and the harness reads the trace.
- **Snapshot reads.** An `openat` of a loose object listed in the generator's `snapshots.txt` is a snapshot decode.
- **Lock times.** `linkat(…, "lock")` returning `EEXIST` is a failed attempt; the successful `linkat` is the acquisition; `unlinkat(…, "lock")` is the release. This gives each command's wait and hold on `.veil/lock`, and on the remote's lock: a path remote shows up in `vl`'s own trace, and an SFTP remote in the trace of `sftp-server`, which the stand-in `ssh` runs under strace.
- **Limitations:**
  - strace slows each traced syscall, so traced runs give counts and the shares of time under the lock, never the reported times;
  - a packed store reads objects without one open each, so snapshot counts exist only before `gc`. The table marks pull in a clone, which is packed, as n/a.

## Results (1 GB)

"Snapshots read" is the number of distinct snapshots decoded, out of 10,073. "Lock held" comes from the traced run, which strace slows roughly 3–5×; compare it with that run's total, given in brackets.

### Local, loose store (before `gc`)

| case | median | peak RSS | snapshots read | `.veil/lock` held (traced run) |
|---|---:|---:|---:|---:|
| checkout `main` (full tree, 35k files) | **32.7 s** | 66 MiB | | |
| `merge --embargo` (fix line of 50) | 4.8 s | 70 MiB | | |
| switch `release` → `main` | 6.5 s | 81 MiB | | |
| `init` (import of the final tree) | 3.8 s | 308 MiB | | |
| `status`, clean | 0.21 s | 69 MiB | 3 | 607 ms (of 636) |
| `status`, 1 modified file | 0.26 s | 64 MiB | **10,073 (100 %)** | 1,657 ms (of 1,713) |
| `status`, 100 modified files | 0.46 s | 65 MiB | **10,073** | 1,445 ms (of 1,538) |
| `commit`, 100 modified files | 0.32 s | 66 MiB | **10,073** | 1,302 ms (of 1,344) |
| `log -n 20` | 0.23 s | 62 MiB | **10,073** | 599 ms (of 1,107) |
| `log -n 20 -- <hot file>` | 0.24 s | 62 MiB | **10,073** | 599 ms (of 1,154) |
| `log` (all history; exempt) | 1.44 s | 78 MiB | 10,073 | 610 ms |
| `log -S` (all history; exempt) | 3.6 s | 117 MiB | 10,073 | 639 ms |
| `blame` of the hot file (441 edits; exempt) | 0.54 s | 78 MiB | 10,002 | 647 ms |
| `blame -r <oldest tag>` | 0.19 s | 61 MiB | 502 | 605 ms |
| `tag set` | 0.17 s | 61 MiB | 1 | 645 ms (of 672) |
| `ws exec --ephemeral --only docs -- true` | 0.29 s | 61 MiB | 1 | 898 ms (of 1,582) |
| `gc`, first (packs 3.38 GB loose) | **18.7 s** | **867 MiB** | | |
| `gc`, again (nothing new) | **18.7 s** | **998 MiB** | | |

The same commands after `gc` (packed store):

| command | median | peak RSS |
|---|---:|---:|
| `status`, clean / 1 file / 100 files | 0.18 / 0.28 / 0.33 s | 78–82 MiB |
| `commit` | 0.33 s | 81 MiB |
| `log -n 20` | 0.27 s | 78 MiB |
| `log` (all history) | 1.79 s | 166 MiB |
| `log -S` | **7.4 s** | 220 MiB |
| `blame` | 0.69 s | 114 MiB |
| `tag set` | 0.19 s | 78 MiB |
| `ws exec --only` | 0.35 s | 78 MiB |

`log -S` is **2× slower packed than loose**: delta chains are decoded for every version.

### Remotes

| case | path | SFTP, 0 ms | SFTP, 2 ms RTT |
|---|---:|---:|---:|
| push, initial (all tags; 0.85 GB on the remote) | 13.6 s, 310 MiB | 17.9 s, 402 MiB | 24.9 s, 402 MiB |
| push, nothing new | 0.30 s, 106 MiB | 0.35 s | 0.53 s |
| push, 1 new snapshot | 0.32 s, 107 MiB | 0.39 s | 0.60 s |
| clone, full (2.0 GB on disk) | **54.5 s, 1,975 MiB** | **52.7 s, 1,985 MiB** | **48.3 s, 1,986 MiB** |
| pull, 1 new snapshot | 1.5 s, **950 MiB** | 2.7 s, **951 MiB** | 2.0 s, **952 MiB** |
| pull, nothing new | 0.47 s, **559 MiB** | 0.82 s, 560 MiB | 0.63 s, 561 MiB |
| `status` in the clone, clean | 0.20 s, 169 MiB | 0.36 s | 0.21 s |

On the path remote, push of 1 snapshot or of nothing new decodes **all 10,073 snapshots**, holds the local lock for 616 ms of its 1,211 ms traced run, and holds the **remote** lock for only 49 ms.

Pull of 1 snapshot holds the clone's local lock for 3,009 ms of its 3,074 ms traced run. It cannot be counted for snapshot reads, because the clone is packed. The spread of the pull runs is high (154–228 %): the first run pays for reading the packs.

### N agents (path remote)

Each agent loops 10 times through three commands against one shared path remote:
1. `vl ws exec --ephemeral -r agent-I --only <subtree> -m … -- <append to 1–10 files>`;
2. `vl tag set agent-I -r <new change>`;
3. `vl push agents -t agent-I`, retried up to 5 times.

| N | wall | landings / min | failures | retries | exec p50 / p95 | push p50 / p95 | iteration p50 / p95 |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 4 | 24 s | **99** | 0 | 0 | 0.66 / 1.25 s | 0.74 / 1.32 s | 2.4 / 3.3 s |
| 16 | 100 s | **97** | 0 | 0 | 2.4 / 8.1 s | 1.9 / 7.7 s | 8.2 / 16.9 s |
| 64 | 294 s | **91** | **194 of 640** | 91 | 10.0 / 23.9 s | 9.5 / 23.4 s | 26 / 58 s |

64 agents is twice the CPU count, the harness's cap; this run did not need capping. The failures are all `repository is locked: another process holds the lock` (BUG-801).

Lock time in the traced repetition (2 iterations each; sums over all commands):

| N | command | `.veil/lock` wait | `.veil/lock` hold | remote lock wait | remote lock hold (max) |
|---:|---|---:|---:|---:|---:|
| 4 | exec / tag / push | 15.9 / 15.7 / 7.9 s | 6.1 / 5.4 / 5.2 s | 0 | 115 ms (16 ms) |
| 16 | exec / tag / push | 352 / 247 / 209 s | 22.7 / 20.3 / 21.2 s | 5 ms | 469 ms (23 ms) |
| 64 | exec / tag / push | 2,218 / 219 / 154 s | 40.6 / 13.9 / 15.0 s | 0 | 317 ms (17 ms) |

**Throughput is flat from N = 4 to N = 64** (99 → 91 landings per minute): the agents are fully serialised. One iteration is three commands, each holding `.veil/lock` for about 0.2 s untraced, so the ceiling is roughly 100 iterations per minute. The remote's lock is never the bottleneck: its waits are near 0, and each hold is at most 23 ms.

## Ranked offenders

Each entry gives the operation, its cost at 1 GB, the cause (located in the code), and the stream that owns the fix.

1. **Every command serialises on `.veil/lock` for the whole working-copy scan.**
   - **Cost:**
     - agent throughput is capped at about 95 landings per minute whatever N is;
     - p95 latency is 24 s at N = 64;
     - **30 % of iterations fail at N = 64** with "repository is locked" (BUG-801);
     - even a clean `status`, a `log` or a `tag set` holds the lock for 90–95 % of its run.
   - **Cause:** every `vl` command records the project directory first. `Repo::snapshot_workspace_with` (`workspace.rs:280`) opens its transaction, which takes `.veil/lock`, *before* `build_tree_cached` scans 35k files (`:312`). Contenders poll with back-off for at most 15 s (`LockOptions::default().wait`) and then fail.
   - **Fix:** stream **O** (the lock-free op log, and the compare-and-swap working-copy snapshot of `2-lock-free-oplog.md`).
2. **Memory grows with the store size** (BUG-800).
   - **Cost:**
     - `clone` 1.98 GB;
     - `gc` 0.87–1.0 GB;
     - `pull` of 1 snapshot 950 MB, and `pull` with nothing new 560 MB;
     - each is over gate 3's 512 MiB already at 1 GB, and at 5g they would be several GB.
   - **Cause:** `Pack::whole` (`pack.rs:415`) reads a whole pack into memory once it has served 64 reads, for any pack of at most 256 MiB. The limit is per pack, and nothing bounds the total. A command that walks history (pull, clone, gc) touches every pack, so it ends up holding all of them.
   - **Fix:** stream **G2** (`store.rs`'s read path and pack caching); then stream **X** if the large-file builder is over the limit at `5g`.
3. **Everyday commands walk the whole history.** Each decodes all 10,073 snapshots:

   | command | path to the walk | owning stream |
   |---|---|---|
   | `status` or `commit` with any change | rewriting `@` makes `Transaction::commit` run `rebase_descendants` (`transaction.rs:337`), which calls `topo_children_first` over every ref | **O**, through **I1** |
   | `log -n 20` and `log -n 20 -- PATH` | `log_entries_with` sorts `visible_snapshots()` (`api.rs:924`), then truncates | **I** |
   | push of 1 snapshot, or of nothing new | `sendable_tags` → `embargo_withheld` walks `visible_snapshots()` plus `ancestors()` of each embargo merge (`remote.rs:964`), then `push_closure` runs from the tips (`remote.rs:1019`, under the remote's lock) | **P** |

   - **Cost** at 1 GB: 0.05–0.25 s per command, linear in history (so about 1 s on the 40k-snapshot twin), and it adds to the time under `.veil/lock` in item 1.
4. **Checkout is fsync-bound.**
   - **Cost:**
     - a full checkout of 35k files takes **32.7 s**, against 3.8 s to import the same tree;
     - `clone` (54 s) is mostly this;
     - `ws switch` and every checkout pay it per file.
   - **Cause:** `checkout` writes each file with a durable `DiskBackend::write` (temp file, fsync, rename, fsync of the directory: `checkout.rs:931` → `disk.rs:732`), so 2 fsyncs per file and no batching.
   - **Fix:** stream **R** owns `apply_changes`. One sync barrier per checkout, as the object store already does, or reflinks where the file system has them. This is not one of O, P or G2, but it is the largest single wall time in the run.
5. **`gc` is a full repack every time.**
   - **Cost:**
     - the second `gc`, with nothing new, takes as long as the first: **18.7 s, 1 GB RSS**;
     - meanwhile an unattended loose store grows to about 3× the tree (3.38 GB in 337k files).
   - **Cause:** no geometric or incremental packing, and no background maintenance.
   - **Fix:** stream **G2** (`maintenance.rs`).
6. **Smaller costs:**
   - `log -S` is 2× slower on a packed store (delta decoding; exempt from the gates);
   - the initial push takes 13.6–24.9 s, which is acceptable;
   - `merge --embargo` takes 4.8 s.

## Which operations walk all history or hold locks

| operation | walks all history? | `.veil/lock` | remote lock |
|---|---|---|---|
| `status`, clean | no (3 snapshots; ~2,900 trees) | **held for nearly the whole command** (the working-copy snapshot) | – |
| `status` / `commit` with changes | **yes** (`rebase_descendants`) | held for the whole command | – |
| `log -n 20`, `log -n 20 -- PATH` | **yes** (`visible_snapshots`) | held for the snapshot at the start (~55 % of the run) | – |
| `log`, `log -S`, `blame` of an old file | yes (exempt) | as above | – |
| `blame -r <old tag>` | the file's own history (5 %) | as above | – |
| `tag set` | no (1) | held for nearly the whole command | – |
| `ws exec --ephemeral --only` | no (1) | held for ~57 % of the run (the snapshot, then the recording) | – |
| push of 1 snapshot, or nothing new | **yes** (`embargo_withheld`, `push_closure`) | held ~50 % | held 38–49 ms (traced) |
| pull of 1 snapshot | not countable (packed clone) | held for the whole command (3.0 of 3.1 s traced) | – |
| `gc` | yes (exempt) | – | – |

## What this means for the plan

- **O goes first.** It removes the lock waits that make 64 agents fail, and gives the largest gain for the agent scenario (Scion phase 0's reason to exist).
- **G2 second.** Memory is over gate 3 at 1 GB already, and grows with the store. Bounding the pack cache is small and contained; geometric repacking also fixes item 5.
- **P third.** At 1 GB the remote's lock is not contended: waits are about 0, holds are at most 23 ms traced, and that already fits gate 1's `20 × RTT + 250 ms`. P's value here is removing the push's history walks (item 3) and resumability, which matter more over a slow link than on this machine.
- **I** (in parallel, as planned) removes the walks in `log` and, with O, in `status`/`commit`. At 1 GB they cost less than a quarter of a second; they will matter on the 4× history twin.
- **R** should batch checkout's fsyncs even where reflinks are unavailable, which is this ext4 machine.

## Gates (from `9-scale-benchmark.md`) at this baseline

| gate | status at 1 GB |
|---|---|
| 1. no `.veil/lock` waits in the N-agents profile | **fails** (seconds to minutes; 30 % failures at N = 64) |
| 1. remote lock hold ≤ 20 × RTT + 250 ms | passes on a path remote (≤ 49 ms traced). Independence of pack size not measured yet (no 200 MB push case) |
| 2. no full walks in `status`, `commit`, `log -n 20`, `log -- PATH -n 20`, push/pull of 1 snapshot, `ws exec`, `tag set` | **fails** for status/commit with changes, both `log -n 20`, and push. Passes for clean status, `tag set` and `ws exec`. Pull not measurable yet (packed clone) |
| 3. peak RSS ≤ 512 MiB | **fails** already at 1 GB: clone 1.98 GB, gc 1.0 GB, pull 950 MB |
| 4. no regression on `small` | baseline recorded below |

## Not measured yet

- **Profiles:**
  - `5g` (the script is ready: `scripts/bench-scale.sh 5g`, only when nothing else builds; it refuses while `cargo` or `rustc` runs, unless `FORCE=1`);
  - `cloaked-1g` (`scripts/bench-scale.sh 1g --cloaked`);
  - the 4×-history twin `1g-h4`.
- **Cases:**
  - a 200 MB binary push;
  - `rebase`;
  - `ws switch` between trees that differ by 200 MB;
  - partial clone;
  - the contention variant (every agent lands on `main`);
  - cold-cache runs.
- **The CLI has no merge-base query** (the revset language has no `heads()` or `&`), so that case was dropped.
- **Product hooks wanted** (not added: this stream changes no product code):
  - `VEIL_TRACE` as `9-scale-benchmark.md` designs it, so snapshot decodes can be counted on packed stores and in clones, and lock waits can be attributed without strace's overhead;
  - a `walk` event per graph walk would also name *which* walk ran.

## Findings

| ID | severity | finding |
|---|---|---|
| BUG-800 | medium | Pack slurping is bounded per pack, not per store: memory grows with the store (`clone` 1.98 GB, `pull` 950 MB at 1 GB). Reproduced by `crates/veil-core/tests/scale_findings.rs` (ignored). |
| BUG-801 | medium | Concurrent commands fail with `repository is locked` after 15 s instead of queueing: 194 of 640 iterations at N = 64; 15 of 64 concurrent `vl status` on 20k files. Reproduced by `crates/vl/tests/scale_findings_cli.rs` (ignored). |

The run hit no crashes and no wrong results: every case succeeded, the embargo merge included.

## `small` baseline (for gate 4)

`small` profile, seed 1:
- 1,073 snapshots;
- 3,506 files, 0.11 GB;
- same machine, same commit.

Rows under "local, packed store" come after `gc`. RSS floor: 16 MiB.

| case | group | median | spread | runs | peak RSS | snapshots read | local lock held | remote lock held | ok |
|---|---|---:|---:|---:|---:|---:|---:|---:|---|
| checkout main (full tree) | setup | 3.459 s | 0 % | 1 | 28 MiB |  |  |  | yes |
| init (import of the final tree) | local | 0.396 s | 0 % | 1 | 44 MiB |  |  |  | yes |
| status, clean | local, loose store | 0.099 s | 93 % ⚠ | 3 | 30 MiB | 3 (0.3 %) | 88 ms | – | yes |
| status, 1 modified file | local, loose store | 0.048 s | 50 % ⚠ | 3 | 21 MiB | 1073 (100.0 %) | 149 ms | – | yes |
| status, 100 modified files | local, loose store | 0.071 s | 13 % | 3 | 22 MiB | 1073 (100.0 %) | 234 ms | – | yes |
| commit, 100 modified files | local, loose store | 0.081 s | 21 % ⚠ | 3 | 22 MiB | 1073 (100.0 %) | 234 ms | – | yes |
| log -n 20 | local, loose store | 0.030 s | 44 % ⚠ | 3 | 17 MiB | 1073 (100.0 %) | 65 ms | – | yes |
| log (all history) | local, loose store | 0.083 s | 7 % | 3 | 21 MiB | 1073 (100.0 %) | 72 ms | – | yes |
| log -S <needle> (all history) | local, loose store | 0.303 s | 0 % | 1 | 54 MiB | 1073 (100.0 %) | 76 ms | – | yes |
| blame <hot file, oldest> | local, loose store | 0.067 s | 1 % | 3 | 21 MiB | 1002 (93.4 %) | 79 ms | – | yes |
| tag set | local, loose store | 0.023 s | 29 % ⚠ | 3 | 17 MiB | 1 (0.1 %) | 70 ms | – | yes |
| push, initial (all tags) | remote: path | 1.320 s | 0 % | 1 | 193 MiB |  |  |  | yes |
| push, 1 new snapshot | remote: path | 0.051 s | 36 % ⚠ | 3 | 22 MiB | 1073 (100.0 %) | 91 ms | 12 ms | yes |
| clone, full | remote: path | 4.676 s | 0 % | 1 | 353 MiB |  |  |  | yes |
| pull, 1 new snapshot | remote: path | 0.186 s | 137 % ⚠ | 3 | 126 MiB | n/a (packed) | 316 ms | – | yes |
| gc, first (packs the loose store) | local | 1.657 s | 0 % | 1 | 130 MiB |  |  |  | yes |
| gc, again (nothing new) | local | 1.616 s | 0 % | 1 | 268 MiB |  |  |  | yes |
| status, clean | local, packed store | 0.042 s | 2 % | 3 | 77 MiB |  |  |  | yes |
| log -n 20 | local, packed store | 0.053 s | 7 % | 3 | 77 MiB |  |  |  | yes |
| push, 1 new snapshot | remote: sftp | 0.080 s | 4 % | 3 | 82 MiB |  |  |  | yes |
| clone, full | remote: sftp | 4.807 s | 0 % | 1 | 354 MiB |  |  |  | yes |

| N agents (`small`, 5 iterations) | landings / min | failures | exec p50 / p95 |
|---:|---:|---:|---:|
| 4 | 336 | 0 | 0.12 / 0.65 s |
| 16 | 416 | 0 | 0.36 / 2.34 s |
| 64 | 397 | 1 | 1.82 / 11.30 s |

**Spread.** Runs whose spread is above 15 % (⚠) are sub-0.1 s commands, timed beside other agents' builds. Gate 4 should compare medians of 5 runs, on a quiet machine.

## After stream O (lock-free op log), `small`

`scripts/bench-scale.sh small`, seed 1, branch `scale-o-oplog` @ 1f43144 (format 6), same machine (32 CPUs, ext4, warm cache), 2026-11-05. Full table: `.scratch/bench-results/small-seed1-20261105T083320Z.md` of that worktree (not kept).

**Gate 1 (no `.veil/lock` waits in the N-agents profile): passes.** Every command of every agent, at N = 4, 16 and 64, waited 0 ms for `.veil/lock` and held it 0 ms (traced runs); no iteration failed and none was retried.

| N agents (`small`, 10 iterations) | landings / min | failures | retries | exec p50 / p95 | push p50 / p95 | iteration p50 / p95 | before (5 iterations) |
|---:|---:|---:|---:|---:|---:|---:|---|
| 4 | **959** | 0 | 0 | 0.09 / 0.14 s | 0.07 / 0.13 s | 0.23 / 0.32 s | 336 / min, 0 failures |
| 16 | **1,058** | 0 | 0 | 0.29 / 0.48 s | 0.28 / 0.37 s | 0.88 / 1.14 s | 416 / min, 0 failures |
| 64 | **647** | 0 | 0 | 2.93 / 4.41 s | 1.07 / 2.71 s | 5.68 / 8.22 s | 397 / min, 1 failure |

Lock time in the traced repetition (2 iterations each, sums over all commands):

| N | command | `.veil/lock` wait / hold | remote lock wait | remote lock hold (max) |
|---:|---|---:|---:|---:|
| 4 | exec / tag / push | 0 / 0 ms | 0 | 78 ms (11 ms) |
| 16 | exec / tag / push | 0 / 0 ms | 0 | 601 ms (31 ms) |
| 64 | exec / tag / push | 0 / 0 ms | 511 ms | 7,038 ms (98 ms) |

- **Throughput is no longer flat**: 2.5–2.9× the baseline at N = 4–16. At N = 64 (twice the CPU count) it drops to 647 a minute: CPU-bound agents plus the remote's lock, now the only shared lock (its waits appear at N = 64, 511 ms in all; each hold is at most 98 ms traced). Stream P (lock-free pushes) owns that.
- **Single-command cases** are unchanged within noise (`status, clean` 0.089 s loose / 0.021 s packed; `tag set` 0.024 s; `commit, 100 modified files` 0.081 s), and the "local lock held" column is empty: no local command took `.veil/lock`.
