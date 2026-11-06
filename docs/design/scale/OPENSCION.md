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

## Next

1. The transfer and the per-file walks are what separate the 10k clone
   (1,014 ms) from the 544 ms gate and from Git (583 ms): one request per
   level, streamed responses and the pack format on the wire on the
   server's side; on the client, one directory descriptor per directory
   for checkout's steps instead of a walk from the root for each.
2. Clone one directory (74 ms at 10k, 62 ms at 1k) is now mostly the fixed
   cost of `vl` starting, creating a repository and signing in.
3. Commit one changed file: the fixed per-command overhead (opening the
   repository, keys, the op log, the working-copy scan).
