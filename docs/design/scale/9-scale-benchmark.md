# 9. The scale benchmark

Status: harness built (`crates/veil-bench`, `scripts/bench-scale.sh`); the 1 GB baseline on b549e1e is in [`BASELINE.md`](BASELINE.md). The trace hooks below are not built: the harness counts snapshot decodes and lock waits from an `strace` of each command instead (Scion 6.6, and the backlog's "Scale benchmark at 1 GB and ~5 GB"). **It is built first:** its baseline on `integration` @ 4a62259 ranks the other streams, and its gates decide when phase 0 is done.

## Design sketch

### The harness: `crates/veil-bench`

- **A crate**: a workspace member with `publish = false`, outside `default-members`, so `cargo test --all-targets` and `verify-ignored.sh` never build it.
- **One binary**, `veil-bench`:

```text
veil-bench gen     --profile small|1g|5g|cloaked-1g --seed N --out DIR
veil-bench run     --profile … --vl target/release/vl [--rtt 2,50] [--bandwidth 4M] [--agents 1,4,16,32] [--only CASE…]
veil-bench report  RESULTS.json… > docs/design/scale/BENCH.md (appends a dated section)
```

- **Real processes.** It drives the **release `vl` binary** as separate processes, so locks, the op log and SFTP are real.
- **Building history** goes through `veil_core`'s API in-process (ephemeral workspaces, as `sftp_bench.rs` does), because 10,000 commits through the CLI would dominate the run. Every *measured* command is a `vl` process.

### Data profiles (deterministic from the seed)

| profile | working tree | files | history | content |
|---|---|---|---|---|
| `small` | 100 MB | 3,500 | 1,000 snapshots | smoke test; minutes |
| `1g` | 1 GB | 35,000 | 10,000 snapshots, a merge every 50, 20 tags | 70 % synthetic source (zstd ratio about 4), 20 % JSON/YAML, 10 % incompressible binaries of 100 KB–20 MB |
| `5g` | 5 GB | 150,000 | 20,000 snapshots | as `1g`, plus 4 binaries of 200–400 MB (the large-file paths) |
| `cloaked-1g` | 1 GB | 35,000 | 10,000 snapshots | 85 % of files under `cloak` rules for scopes `a` and `b`; one cloaked line; one unreleased embargo whose fix line has 50 snapshots; isolated `.env` files |

- **Directory shape:** fan-out of about 20 and depth up to 8, with file sizes log-normal around 30 KB.
- **Edits per snapshot:** 1–20 files, with renames and deletions at about 2 %.
- **The scaling twins:** `1g` is also generated with **4× the history on the same final tree** (`1g-h4`).

### Cases (each one a `vl` process; repeated 3 times; the median is reported)

- **`init`** with the first snapshot of the generated tree.
- **`status`** clean, then with 100 modified files and with 1 modified file.
- **`commit`**.
- **`log -n 20`**, `log -- <old file>`, and `log` with no limit (exempt).
- **`blame`** of the oldest file.
- **`rebase`** of the tip onto `main~1`.
- **`merge-base`** of two tags (`vl log -r 'heads(::a & ::b)'` or the API equivalent).
- **`gc`**: the first run, then after 100 commits.
- **`push`**: the first one to an empty SFTP remote, then 1 new snapshot, then 200 MB of new binaries.
- **`clone`**: full, then (once item 6 lands) `--partial --recent 1` and `--only`.
- **`pull`** of 1 snapshot.
- **`ws exec`**: sparse (`--only`) create and record, and a full sandbox create.
- **`ws switch`** between two workspaces whose trees differ by 200 MB.

**The remote** is the local OpenSSH `sftp-server` behind the RTT shim of `crates/veil-core/tests/sftp_support`, copied into the bench crate. It adds a bandwidth cap (`--bandwidth`, token bucket) for the slow-uplink lease case. RTTs are 2 ms and 50 ms.

### The N-agents profile

- **Workspaces.** N ∈ {1, 4, 16, 32} virtual workspaces `agent-i` on `1g`, each with an `--only` subtree of about 50 MB (sparse, so N = 32 fits on disk without reflinks).
- **Each agent loop**, for K = 20 iterations:
  1. `vl ws exec agent-i --only <subtree-i> -m "step k" -- edit.sh` (an edit script changing 1–10 files);
  2. `vl tag set agent/i -r agent-i@-`;
  3. `vl push origin -t agent/i`.
- **The contention variant:** every agent lands on `main` with a pull-and-retry loop.
- **Reported:** throughput (landings per minute), p50 and p99 latency per command, the total time spent waiting on `.veil/lock` and on the remote lock, the remote lock's hold time per push, and peak RSS.

### Instrumentation (`crates/veil-core/src/trace.rs`, stream B)

- **Enabled** with `VEIL_TRACE=<file>`: JSON lines appended, the file created 0600 with `O_APPEND`, and one summary line per process at exit.
- **Events and counters:**
  - `lock.wait` and `lock.hold`: lock path relative to `.veil` (`lock`, `gc.lock`, `wc/<n>.lock`), backend kind, milliseconds;
  - `store.read`: counts of snapshot, tree and blob decodes, split into cache hits and misses;
  - `walk`: one event per call to `topo_children_first`, `visible_snapshots`, `ancestors`, `committed_closure`, `push_closure`, `embargo_withheld`, `ancestors_in` and `GraphIndex` walks, with a static label and the number of snapshots visited;
  - the process's peak RSS (`getrusage`), and bytes read and written (`/proc/self/io`).
- **Never** a path inside the repository, a file name, a description or any content (threat 3).
- **The harness** also takes each child's `ru_maxrss` from `wait4`.

### Gates (phase 0 is done when all hold on `1g`, `cloaked-1g` and `5g`)

1. **Locks.**
   - In the N-agents profile, no local command waits on `.veil/lock` except metadata commands (`scope`, `secret`, `embargo`), which the profile does not run. So the wait total is 0.
   - The remote lock's hold time per push is at most `20 × RTT + 250 ms`, and **independent of the pack size**: pushing 200 MB holds the lock for at most 1.5× the hold for pushing 1 snapshot.
2. **History walks.** For `status`, `commit`, `log -n 20`, `log -- PATH -n 20`, a push or pull of 1 snapshot, `ws exec` record, `rebase` of the tip, `tag set` and `merge-base`:
   - snapshot decodes on `1g-h4` are at most `1.2 × (decodes on 1g) + 50`;
   - and the trace has no `walk` event visiting more than 10 % of the history.
   - **Exempt:** `log` with no limit; `log -S`/`-G` without a path or limit; `::X` revsets; `fsck`; gc's prune task; `push`/`pull --full`; `agent()` filters; `blame` of a file as old as the history (bounded by the file's own history).
3. **Memory.** Peak RSS is at most 512 MiB for every case on `5g`, except `clone --full` (512 MiB plus the in-flight window).
4. **No regression.** Every case on `small` stays within 10 % of the baseline's time; a known trade-off has to be written into BENCH.md.

### Disk (the hard constraint)

Measured on this machine: **17 GB free** on `/` (ext4, no reflinks) and 7 GB on `/tmp` (tmpfs, RAM-backed, not used for benchmarks). The brief's 35 GB is not available today.

| profile | peak disk | how |
|---|---|---|
| `small` | under 1 GB | — |
| `1g` | about 5 GB | working tree 1 GB, store about 0.4 GB, remote 0.4 GB, clone 1.4 GB, 32 sparse sandboxes about 1.6 GB |
| `cloaked-1g` | about 6 GB | sealed objects neither compress nor delta: store and remote about 1 GB each |
| `5g` | about 10 GB | phases in sequence: init, status, commit and gc (5 + 1.5); push (+1.5); **delete the source working tree** (−5); clone (+6.5); delete the clone before the next case |

- **Location.** Everything lives under `.scratch/bench/` of the bench's worktree.
- **Pre-flight.** Before every phase, `statvfs` must show the phase's need plus 2 GB, or the run stops and says why.
- **Cleanup.** `--keep` is off by default, so nothing is left behind.
- **`5g` runs only when no build is running** (the orchestrator runs it once at baseline and once at the end). `1g` needs one free build slot.

### Cold and warm

- **Warm** runs are the default.
- **"Cold"** runs drop the repository's pages with `posix_fadvise(POSIX_FADV_DONTNEED)` over every file first. This needs no root, and approximates a cold cache without `drop_caches`.

## Threat review (the harness is a measuring instrument)

1. **Filling the disk** that other worktrees and builds share.
   - *Invariant:* the pre-flight space check runs before every phase, and cleanup runs on every exit path (including Ctrl-C).
   - *Test:* run with a fake `statvfs` reporting too little space; it stops before writing.
2. **Misleading numbers** (page cache, CPU frequency, noisy neighbours).
   - *Invariant:* every result records the `vl` commit, the machine, the kernel, the file system, free memory, warm or cold, and the spread of the 3 runs; a spread above 15 % is flagged in the report.
   - *Test:* `report` refuses to compare results from different file systems without `--force`.
3. **The trace leaks content.** `VEIL_TRACE` on a cloaked repository must not write file names, descriptions or values.
   - *Invariant:* trace events carry only fixed labels, counts, durations and `.veil`-relative lock paths.
   - *Test:* run `cloaked-1g` with tracing, then grep the trace for every generated file name and every cloaked token: none.
4. **`VEIL_TRACE` as a write primitive.**
   - *Invariant:* the file is opened `O_APPEND | O_CREAT` with mode 0600, never truncated, never followed if it is a symlink (`O_NOFOLLOW`), and a failure only disables tracing.
   - *Test:* point it at a symlink; nothing is written through it.
5. **The instrumentation costs too much.**
   - *Invariant:* with `VEIL_TRACE` unset, every hook is one relaxed atomic load.
   - *Test:* `small` with and without the hooks compiled in differs by under 2 %.

## Open decisions

1. **A crate or an `xtask`.**
   - *Recommendation:* a crate outside `default-members`. It needs `veil-core` as a library to build histories quickly.
2. **History lengths.**
   - *Recommendation:* 10,000 snapshots and 40,000 (the scaling twin) on `1g`; 20,000 on `5g`.
3. **Where results live.**
   - *Recommendation:* the summary table in `docs/design/scale/BENCH.md`, and the raw JSON in `.scratch/bench/` (not committed).
