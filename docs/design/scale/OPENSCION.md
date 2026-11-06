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
  pre-existing): checkout writes every file to a temporary file, `fsync`s
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

## Next

1. BUG-818: batch the checkout's durability (write every file, then one
   barrier: `StorageBackend::write_unsynced` and the existing batch
   barrier already do this for objects).
2. Then re-measure; the transfer itself (about 1 s of the 10k clone today)
   is the server's share to bring under the 544 ms gate (one request per
   level, streamed responses, the pack format on the wire).
