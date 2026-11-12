# The server under load: scaling curves (performance round 2)

`veil-bench load` (`crates/veil-bench/src/load.rs`) runs hundreds to
thousands of simulated agents against one Veil server and measures how
pulls and landings scale. The owner's questions (2026-11-06): does Veil
scale **toward 1,000 operations per second**; do merges in different
projects contend; where does one project's `main` saturate; and how does
the server behave at Anthropic's rate (30,000 merges a day, 0.35/s), its
10× peaks, compressed into minutes, and as fast as possible?

## Method

- **Agents speak the server's API as `vl` does**, in process (one `vl`
  process per operation would measure process starts, not the server):
  - a **pull** asks for the tips; when `main` moved, the history down to
    the tip it holds, then the new trees and files level by level, only
    what it lacks (`vl pull`, `crates/vl/src/hub.rs`);
  - a **landing** is a pull, then one new file in the agent's own
    directory on top of that `main` (a blob, the trees above it, a signed
    snapshot), uploaded, then pushed as the compare-and-swap of `main`. If
    `main` moved between the pull and the push (a **collision**: HTTP 409,
    or a refused branch result), the agent pulls and tries again, as an
    agent rebasing would. Changes never overlap, so every retry is a race
    lost on the one row, never a content conflict.
- **Realistic permissions:** agents are members of group `agents`, which
  may read and write `w/`; `.veilpolicy` is private to the admin. So every
  agent reads projected history, and the server completes every landing
  (grafting what the agent cannot see), the real path, not an admin's
  shortcut. All agents of a run sign in as one person, as agents run by
  one person do (one view key, so projections are shared).
- **A run is one point of a curve:** `projects` new projects, `clients`
  agents spread over them, measured for 15 s after a 3 s warm-up. Landings
  run **closed loop** (`max`: every agent lands again as soon as it is
  done) or **open loop** at a target aggregate rate (landings scheduled at
  that rate, latency counted from the scheduled time, so a backlog shows).
  Pulls run closed loop while one lander per project moves `main` at
  `--background` landings per second (0: `main` never moves, so every pull
  is the up-to-date check).
- **Measured:** operations per second; latency p50 and p99; collisions per
  landing (counted when they happen, so a landing that never finishes
  still counts its lost races); how many agents finished an operation in
  the window (fairness); requests per operation; the server's CPU per
  operation and in cores; the database's CPU (its processes on this
  machine, `--db-container`) and statements per operation
  (`pg_stat_statements`); the load tool's own CPU.
- **Machine:** the development machine of `OPENSCION.md` (i9-13900KF, 32
  threads, ext4 on NVMe), shared by the load tool (up to 2,000 threads with
  TLS connections), the server and the database. **Server:** a release
  `veil-server`, 64 database connections, objects in a local directory
  (each object written with `fsync`). **PostgreSQL 17** in Docker with
  `pg_stat_statements`, `synchronous_commit = on`. Absolute numbers are
  this machine's; the tool takes the `--url` of a running server (and
  `--database-url` for statement counts; `--server-pid` and
  `--db-container` for CPU when they run on the tool's machine), so the
  same runs can go against other servers and database nodes.
- **Noise:** the machine is shared with other work; repeated points vary
  by up to 2× (the quiet-pull curve below is not monotonic for that
  reason). Read the curves for their shape and the order of magnitude.

`scripts/bench-server.sh load` starts PostgreSQL and MinIO in Docker, a
server per curve, and runs a reduced set of the points below
(`OBJECTS=local` for objects in a local directory); by hand:

```sh
veil-bench load --mode pull --server target/release/veil-server \
  --database-url postgres://… --db-container ID --projects 1 \
  --clients 10,100,500,1000,2000 --background 20 --dir D --out pulls.json
veil-bench load --mode land … --projects 1,10,100,300 --clients 1 --rates max
veil-bench load --mode land … --projects 1 --clients 50 --rates 1,5,10,20,40,80
```

## 1. Pulls per second (one project, one server)

**Target: 1,000 pulls/s. Met:** about 2,100–2,500 pulls/s when `main`
moves 20 times a second (each pull then brings the changes landed since
the agent's last pull), and 5,000–19,000 per second when `main` is quiet
(the up-to-date check, one request).

| `main` moves (/s) | Clients | Pulls/s | p50 (ms) | p99 (ms) | Requests per pull | Server CPU (ms/pull) | Server cores | DB CPU (ms/pull) | DB cores | DB statements per pull | Load tool cores |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 0 | 10 | 10,123 | 0.8 | 3.0 | 1.0 | 0.20 | 2.1 | 0.34 | 3.4 | 6.0 | 0.8 |
| 0 | 100 | 4,994 | 18.8 | 45.1 | 1.0 | 0.18 | 0.9 | 0.45 | 2.2 | 6.0 | 0.5 |
| 0 | 500 | 10,073 | 33.6 | 141.2 | 1.0 | 0.17 | 1.8 | 0.35 | 3.5 | 6.0 | 1.0 |
| 0 | 1,000 | 9,654 | 83.2 | 206.5 | 1.0 | 0.17 | 1.7 | 0.33 | 3.1 | 6.0 | 0.9 |
| 0 | 2,000 | 18,877 | 105.6 | 117.8 | 1.0 | 0.20 | 3.7 | 0.35 | 6.7 | 6.0 | 2.0 |
| 20 | 10 | 5,756 | 0.9 | 18.7 | 1.2 | 0.30 | 1.7 | 0.51 | 2.9 | 7.5 | 0.7 |
| 20 | 100 | 3,810 | 38.8 | 54.7 | 4.2 | 0.95 | 3.6 | 1.68 | 6.4 | 26.8 | 1.9 |
| 20 | 500 | 2,142 | 226.6 | 334.7 | 7.1 | 1.78 | 3.8 | 2.89 | 6.2 | 46.6 | 1.8 |
| 20 | 1,000 | 2,467 | 371.9 | 509.0 | 7.0 | 1.84 | 4.5 | 2.82 | 7.0 | 46.7 | 2.1 |
| 20 | 2,000 | 2,533 | 724.1 | 973.2 | 7.0 | 1.85 | 4.7 | 2.82 | 7.1 | 46.6 | 2.1 |

**Where it saturates, and why.** With `main` moving, throughput flattens
at about 2,500 pulls/s from 500 clients, and latency grows with the
number of clients. Profiled at 500 clients (`vmstat`, `pg_stat_activity`
wait events sampled, `pg_stat_statements`): the machine's CPU was 78%
busy (41% user, 38% system: 1.7 million context switches a second, TLS
and the network for the load tool, the server and the database on one
box), and the database's sessions waited on the server (`ClientRead`),
never on locks or I/O. Of the 46 statements a pull costs:

- **per request, about 4:** the session lookup, the project, group
  membership and admin checks (`auth::Caller`, `perm::open`). The design
  calls for permission checks *cached per person and folder*
  (`docs/OVERVIEW.md`); none is cached yet;
- **per new snapshot, 2:** `fetch` resolves each snapshot a want names
  (`projections` by projected id, then `snapshots`), and history and tips
  look up the projection memo.

So pulls are bounded here by CPU per pull (about 1.8 ms of server and
2.8 ms of database CPU), not by a lock or a single row; more server
processes and database nodes add capacity. A per-person permission cache
and a per-snapshot resolution cache would cut most of the statements.

## 2. Merges per second across many projects

**Aim: 1,000 merges/s in aggregate. Met:** 2,094 landings/s with 100
projects (one agent each), and no contention between projects: with one
agent per project, no landing ever collided, and the cost per landing
stayed flat (37 statements, 3.5–3.9 ms of server CPU) from 1 to 300
projects.

| Projects | Agents | Landings/s | p50 (ms) | p99 (ms) | Collisions per landing | Requests per landing | Server CPU (ms) | Server cores | DB CPU (ms) | DB cores | DB statements per landing |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 1 | 74 | 12.3 | 27.3 | 0 | 3.0 | 4.93 | 0.4 | 3.26 | 0.2 | 37.0 |
| 10 | 10 | 779 | 12.7 | 19.2 | 0 | 3.0 | 3.50 | 2.7 | 2.33 | 1.8 | 37.0 |
| 100 | 100 | 2,094 | 46.8 | 73.7 | 0 | 3.0 | 3.74 | 7.8 | 2.57 | 5.4 | 37.0 |
| 300 | 300 | 1,894 | 154.9 | 229.1 | 0 | 3.0 | 3.94 | 7.5 | 2.80 | 5.3 | 37.1 |
| 100 | 400 (4 each) | 568 | 170.0 | 293.5 | 1.52 | 16.6 | 11.58 | 6.6 | 10.53 | 6.0 | 153.3 |

**Where it saturates, and why.** At about 2,000 landings/s neither the
server (8 cores) nor the database (5 cores) is busy; the bottleneck is
the **database's write-ahead log**. Sampling the active sessions during
the 100-project run: 256 of 355 samples waited on `LWLock:WALWrite`, 19
more on WAL I/O, 26 were on CPU; the disk wrote about 500 MB/s with 20%
I/O wait. A landing commits about 8 times: the push's branch move, and
each of its other writes on its own (the snapshot and origin rows, the
projection memo, the audit row), plus the server's object writes (an
`fsync` per object in the local object directory). The cost per landing
is flat, so more database nodes (YugabyteDB) and fewer commits per
landing (the memo, origin and audit rows in the push's transaction) raise
the ceiling; nothing in it is a per-project lock.

With four agents per project the aggregate falls to 568/s: every project
is then a hot row (section 3).

## 3. Merges per second into ONE project's `main`

This is the hot-row case that phase 4's batched landing fixes; **batching
is not built** (owner). The baseline:

| Agents | Target (/s) | Landed (/s) | Agents that landed | p50 (ms) | p99 (ms) | Collisions per landing | Requests per landing | Server CPU (ms) | DB statements per landing |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | max | 87 | 1 | 10.4 | 27.9 | 0 | 3.0 | 4.48 | 37 |
| 4 | max | 83 | 1 | 11.2 | 22.8 | 1.99 | 20.9 | 14.41 | 182 |
| 16 | max | 78 | 3 | 12.4 | 21.5 | 9.82 | 91.4 | 50.21 | 752 |
| 64 | max | 36 | 2 | 27.2 | 39.9 | 35.17 | 319.4 | 174.45 | 2,678 |
| 50 | 1 | 1.0 | 15 | 36.0 | 49.6 | 0 | 9.0 | 8.67 | 121 |
| 50 | 5 | 5.0 | 42 | 160.7 | 726.2 | 0.52 | 13.7 | 24.13 | 310 |
| 50 | 10 | 9.9 | 50 | 53.8 | 92.4 | 0.01 | 9.1 | 19.80 | 354 |
| 50 | 20 | 20.1 | 50 | 61.3 | 70.5 | 0.61 | 14.5 | 21.00 | 397 |
| 50 | 40 | 29.2 | 50 | 121.3 | 2,872.3 | 11.75 | 113.7 | 75.05 | 1,114 |
| 50 | 80 | 39.0 | 3 | 5,371.5 | 8,852.7 | 27.50 | 250.6 | 133.81 | 2,100 |

- **The ceiling of one `main` is about 80–90 landings/s for one agent
  landing alone** (a landing takes 10–12 ms: pull, upload, push), **and
  20–30 landings/s for many agents.** Collisions dominate from there:
  - **It bends between 20 and 40 landings/s** with 50 agents: at 20/s a
    landing collides 0.6 times; at a target of 40/s only 29/s land, each
    after 12 collisions, p99 2.9 s; at 80/s, 39/s land, 27 collisions
    each, p50 5.4 s.
  - **The cause is the catch-up pull, not the database.** An agent that
    lands rarely is behind by many landings; its pull (history,
    projection and the new trees of every snapshot since) takes longer
    than the gap between two landings, so its push loses, it pulls again,
    and so on. A collision costs a whole pull and push: server CPU per
    landing grows from 4.5 ms to 134 ms, and database statements from 37
    to 2,100.
  - **It is unfair:** in closed loop the agent that just landed holds the
    new tip and lands again at once, while the others, always one pull
    behind, starve (1 to 3 of 4–64 agents landed anything in 15 s).
- With batched landing (phase 4) the server would merge non-overlapping
  changes itself: a landing becomes one upload and one request, and the
  hot row moves once per batch.

## 4. Anthropic's rate

| Run | Projects | Agents | Target (/s) | Landed (/s) | p50 (ms) | p99 (ms) | Collisions per landing | DB statements per landing |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 30,000 a day, real time (60 s) | 1 | 100 | 0.35 | 0.35 | 33.2 | 140.1 | 0 | 128 |
| 10× peak (30 s) | 1 | 100 | 3.5 | 3.5 | 184.2 | 1,001.3 | 0.28 | 416 |
| a day in 14 minutes | 10 | 100 | 35 | 35.0 | 26.2 | 71.1 | 0 | 86 |
| 10× that | 10 | 100 | 350 | 349.9 | 40.7 | 48.5 | 0.96 | 182 |
| as fast as possible | see sections 2 and 3 | | | | | | | |

- **Anthropic's rate is easy for one server:** 0.35/s lands in 33 ms
  (p50). Its 10× peaks land too, but in one project with 100 agents each
  landing every 30 s, every landing starts with a catch-up pull of about
  100 snapshots (p50 184 ms, 416 statements). A day compressed into 14
  minutes over 10 projects lands at 26 ms (p50) without a collision, and
  10× that (350/s) at 41 ms with about one collision per landing (35/s per
  project, the knee of section 3).

## 5. YugabyteDB

The same tool against **YugabyteDB 2025.2, one node in Docker** on the
same machine (`yugabyted`, default settings; the server and agents as
above). A single node is the worst case for a distributed database: every
statement pays the distributed transaction path with none of the scale-out.

| Run | Projects | Agents | Target (/s) | Done (/s) | p50 (ms) | p99 (ms) | Collisions per landing | DB CPU (ms/op) | DB cores | DB statements per op |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| pulls, `main` moving 20/s | 1 | 10 | max | 2,739 | 2.2 | 19.8 | – | 2.86 | 7.8 | 9.2 |
| pulls, `main` moving 20/s | 1 | 100 | max | 1,030 | 92.9 | 164.3 | – | 19.38 | 19.9 | 45.1 |
| pulls, `main` moving 20/s | 1 | 500 | max | 898 | 515.4 | 1,131.6 | – | 19.65 | 17.6 | 45.6 |
| landings | 1 | 1 | max | 27 | 42.7 | 56.5 | 0 | 48.32 | 1.3 | 35.9 |
| landings | 10 | 10 | max | 259 | 34.4 | 68.7 | 0 | 30.56 | 7.9 | 34.2 |
| landings | 100 | 100 | max | 1,069 | 92.1 | 138.3 | 0 | 15.96 | 17.1 | 34.4 |
| landings, one `main` | 1 | 50 | 5 | 4.9 | 395.7 | 622.4 | 0.88 | 390.27 | 1.9 | 342.7 |
| landings, one `main` | 1 | 50 | 20 | 19.9 | 263.9 | 391.6 | 2.49 | 215.37 | 4.3 | 507.1 |
| landings, one `main` | 1 | 50 | 40 | 21.3 | 3,653.6 | 7,198.7 | 25.01 | 857.40 | 18.2 | 1,904.4 |
| a day in 14 minutes | 10 | 100 | 35 | 34.9 | 107.5 | 289.4 | 0.01 | 102.56 | 3.6 | 113.4 |
| 10× that | 10 | 100 | 350 | 121.9 | 6,620.9 | 11,448.6 | 4.26 | 160.43 | 19.6 | 357.6 |

- **Both 1,000/s aims are met on one YugabyteDB node** (1,030 pulls/s,
  1,069 landings/s across 100 projects), each at its limit: the database
  used 17–20 of the 32 cores. The server's CPU per operation is the same
  as with PostgreSQL; the database's is 6–8 times higher per statement.
- **One project's `main` saturates at about 20 landings/s** (collisions,
  as on PostgreSQL, and slower catch-up pulls), and the 10× compressed
  day (350/s over 10 projects) reaches only 122/s on one node.
- What a cluster of YugabyteDB nodes adds (capacity per node) is for the
  DigitalOcean runs: the tool takes the `--url` of a remote server and
  the `--database-url` of its database (statement counts); the CPU
  columns need the processes on the tool's machine (`--server-pid`,
  `--db-container`), so on separate machines read CPU there.

## Re-measured on `bfa691a`, with MinIO (2026-11-06)

`scripts/bench-server.sh load` on `integration` @ **`bfa691a`**: the same
tool and method, a reduced set of points (15 s each), each curve with its
own fresh server; PostgreSQL 17 in Docker with `pg_stat_statements`; the
server's objects in **MinIO** (S3, in Docker on the same machine) and, in
a second session, in a local directory as above. The machine was heavily
loaded by other agents' builds (load average 35–62 on 32 threads), so
read the shape, not the last digit.

| Run | Projects | Agents | Target (/s) | MinIO: done (/s) | p50 / p99 (ms) | Local: done (/s) | p50 / p99 (ms) | DB statements per op (MinIO / local) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| pulls, `main` moving 20/s | 1 | 10 | max | 8,704 | 0.9 / 8.0 | 9,314 | 0.9 / 7.2 | 7.0 / 6.9 |
| pulls, `main` moving 20/s | 1 | 100 | max | 4,821 | 6.0 / 46.4 | 5,200 | 5.7 / 45.7 | 22.4 / 21.2 |
| pulls, `main` moving 20/s | 1 | 1,000 | max | **2,267** | 414 / 568 | **2,066** | 409 / 832 | 46.1 / 47.0 |
| landings | 1 | 1 | max | 86 | 9.9 / 39.4 | 42 | 23.7 / 61.8 | 34.0 / 34.0 |
| landings | 10 | 10 | max | 459 | 18.4 / 74.7 | 481 | 14.8 / 76.1 | 34.0 / 34.0 |
| landings | 100 | 100 | max | **376** | 259 / 523 | **1,051** | 91 / 183 | 34.1 / 34.0 |
| landings, one `main` | 1 | 50 | 5 | 5.0 | 54 / 67 | 5.0 | 57 / 66 | 311 / 306 |
| landings, one `main` | 1 | 50 | 20 | 20.0 | 45 / 86 | 19.9 | 67 / 212 | 376 / 400 |
| landings, one `main` | 1 | 50 | 40 | 18.7 | 3,032 / 11,040 | 21.9 | 5,781 / 7,221 | 2,238 / 2,082 |

- **Pulls:** about 2,100–2,300 pulls/s at 1,000 agents with `main`
  moving, as before (target 1,000: **met**), with MinIO or without; a pull
  costs 46–47 statements, unchanged.
- **Landings across projects: 1,051/s with local objects, 376/s with
  MinIO** (target 1,000: met with local objects, **not with MinIO** on
  this machine). A landing writes its objects to the store; with MinIO each
  is an HTTP PUT to a single MinIO container sharing the loaded machine,
  and the server and database were mostly idle (1.0 and 1.2 cores): the
  object store bounds it. Statements per landing are 34 (37 in round 2).
- **One project's `main`** still saturates at about 20 landings/s with 50
  agents (collisions, 28–31 per landing at a target of 40/s), as in round
  2: phase 4's batched landing is the fix.
- **BUG-861 (fixed, server bench fixes):** in a first MinIO run, 1,239
  uploads at 100 projects failed with HTTP 500; the server's log of the
  second run shows why: S3 requests on connections MinIO had reset, which
  the server did not try again. It now tries each S3 request again, for up
  to 10 s with waits doubling to 1 s, when its connection closes or
  resets or the store answers 5xx.

Raw results (not committed): `.scratch/bench-results/server-load-bfa691a-20261106T202331Z-*` (MinIO, with the server logs) and `…T202730Z-*` (local objects).

## Commits through the API (S10, 2026-11-07)

`scripts/bench-server.sh load` on `5ea7197` (PostgreSQL 17 with `pg_stat_statements`, MinIO, one release server, 15 s per point, the machine shared with other agents: load average 8 before, 87 after). `--mode api`: each agent commits one new file through `POST …/changes` with `onto main` and `"rebase"` (no pull, no upload; `docs/HUB.md` §13.13); `--mode land` is the push path of §2–3, in the same run. "Commits" are explicit `COMMIT`s; "writes" are `INSERT`/`UPDATE`/`DELETE` statements, in a transaction or not.

| Mode | Projects | Agents | Target (/s) | Done (/s) | p50 (ms) | p99 (ms) | Collisions per landing | Server CPU (ms/op) | DB statements per op | Commits per op | Writes per op | Errors |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| land | 1 | 1 | max | 88.1 | 10.7 | 23.0 | 0 | 3.22 | 34.0 | 1.00 | 5.0 | 0 |
| **api** | 1 | 1 | max | **125.3** | **7.4** | 19.8 | 0 | **2.66** | **13.0** | **1.00** | 5.0 | 0 |
| land | 10 | 10 | max | 422.9 | 19.5 | 100.6 | 0 | 3.23 | 34.0 | 1.00 | 5.0 | 0 |
| **api** | 10 | 10 | max | **767.6** | 11.3 | 47.5 | 0 | 2.14 | 13.0 | 1.00 | 5.0 | 0 |
| land | 100 | 100 | max | 283.3 | 354.4 | 711.2 | 0 | 2.59 | 34.0 | 1.01 | 5.0 | 0 |
| **api** | 100 | 100 | max | **1,000.7** | 80.2 | 290.0 | 0 | 1.98 | 13.9 | 1.00 | 5.0 | 2,118 (MinIO resets, BUG-861) |
| land | 1 (one `main`) | 50 | 20 | 6.6 | 5,034 | 15,621 | 27.4 | 117.9 | 2,033 | 27.4 | 91.0 | 0 |
| **api** | 1 (one `main`) | 50 | 20 | **19.9** | **8.1** | **95.1** | 1.05 | 2.34 | 17.3 | 1.00 | 5.1 | 0 |
| **api** | 1 (one `main`) | 50 | 50 | 34.7 | 1,076 | 7,524 | 26.0 | 39.5 | 210 | 5.10 | 47.0 | 6 (BUG-861) |
| **api** | 1 (one `main`) | 50 | 100 | 32.2 | 4,365 | 11,118 | 32.7 | 51.5 | 261 | 6.21 | 58.3 | 0 |

* **One database commit per API commit.** Every write of a landing (the branch's compare-and-swap, the snapshot row, the caller's projection memo, the change ref, the audit row) is in its one transaction: 1 commit and 5 writes per landing, against the push's 1 transaction plus 2 writes outside it (the projection memo and the audit row: 3 commits). Statements per landing fall from 34 to 13.
* **Storage writes:** a one-file change by a non-admin stores 6 objects (the blob, the three full trees on its path, the server's snapshot, the caller's projection; `server_hub` `changes`). Packs (S28) make that one write.
* **Across projects** the API lands 1,000/s, 2–3.5× the push path, limited by MinIO (its connection resets are BUG-861).
* **Into one `main`,** the API lands 20/s with 50 agents at p99 95 ms (the push path manages 6.6/s with 27 collisions per landing), and peaks at about 35/s: **the phase 2 target of 100/s is not met.** Each lost race rebuilds the change and stores its objects again inside the window between reading the tip and its compare-and-swap (about 10 ms with MinIO), so above about 30/s most attempts lose and collisions climb to 26–33 per landing. Batched landing (S17) is the planned fix; shortening the window (one storage write per landing with packs, S28) helps first.

## S4: request-path caches and one commit per push (2026-11-07)

`scripts/bench-server.sh load` (now with the up-to-date pull, the
`branches` curve and the cost gates, `storage-and-cost.md` §9), objects in a
local directory, PostgreSQL 17 in Docker, through
`~/.cache/veil-orch/bench-quiet.sh`. **Before:** `integration` @ `7a3a9b0`
(S12 merged, S4 not); **after:** the S4 branch @ `64012c5` (on `integration`
@ `d58a952`). The same `veil-bench` measured both. The machine was shared
with other agents' builds (load average 14 at the start of each run, 49–64
at the end), so read the shape: points taken later in a run are noisier.

| Run | Clients | Before (/s) | p50 / p99 (ms) | After (/s) | p50 / p99 (ms) | DB statements per op (before → after) |
|---|---:|---:|---:|---:|---:|---:|
| pull, up to date (`main` quiet) | 10 | 9,934 | 1.0 / 1.7 | 9,763 | 0.6 / 5.0 | 6.0 → **1.0** |
| pull, up to date | 100 | 17,375 | 5.7 / 7.1 | 19,073 | 3.9 / 21.2 | 6.0 → **1.0** |
| pull, up to date | 1,000 | 16,936 | 58.7 / 65.1 | 20,422 | 42.5 / 204 | 6.0 → **1.0** |
| pull, `main` moving 20/s | 10 | 8,909 | 1.0 / 8.0 | **29,305** | 0.3 / 0.9 | 7.0 → 1.1 |
| pull, `main` moving 20/s | 100 | 3,909 | 39.9 / 48.9 | **32,355** | 1.6 / 24.0 | 26.4 → 1.4 |
| pull, `main` moving 20/s | 1,000 | 2,076 | 437 / 584 | 2,079 | 394 / 1,188 | 47.6 → 6.5 |
| landings, own branches, one project | 100 | 386 | 227 / 712 | **1,412** | 65 / 174 | 136.7 → 15.4 |
| landings into one `main`, 50 agents, target 20/s | 50 | 19 | 80 / 520 | **20** | 13 / 17 | 456 → 37 |
| landings into one `main`, target 40/s | 50 | 31 | 3,097 / 7,234 | **40** | 12 / 21 | 2,064 → 37 |
| landings into one `main`, target 80/s | 50 | 33 | 6,111 / 9,983 | 43 | 3,245 / 10,884 | 2,072 → 551 |

With MinIO (`OBJECTS` unset; before `b3ac86e`, after the S4 server), the
same shape: up-to-date pulls 10,922 / 16,721 / 16,165 → 38,218 / 51,611 /
42,072 per second, pulls with `main` moving 9,003 / 2,485 / 2,067 → 35,945 /
36,298 / 5,988, landings on own branches at 100 agents 437 → 773.

**Cost per operation** (the gates: at most 1 database commit per landing,
at most 5 statements per up-to-date pull; **all met after, none before**):

| | Before | After |
|---|---:|---:|
| Database commits per landing, the push's | 3.0 | **1.0** |
| Database commits per landing, S12's deriver (background) | 4.0 | 4.0 |
| Statements per landing (one agent, one project) | 51 | 31 (15 of them the push's request path; the rest the deriver's) |
| Statements per request, warm caches | 6 | **1** (its access epochs) |
| Statements per pull bringing new snapshots (7 requests) | 46–48 | 6.5 |
| Session / permission cache hits | – | 100 % / 100 % |
| Storage writes per landing | – | 9 (one per new object: the agent's 6, the graft's trees, the real snapshot) |

**Where a pull's database time goes** (`pg_stat_statements`, 100 agents,
`main` moving 20/s, per pull; S4 without S12's deriver):

| Statement | Before (calls, ms) | After (calls, ms) |
|---|---:|---:|
| admin and device bar (`project_admins`, `device_bars`) | 6.3, 0.23 | – |
| session (`sessions` ⋈ `devices` ⋈ `people`) | 6.3, 0.20 | – |
| groups (`groups` ⋈ `group_members`) | 6.3, 0.13 | – |
| project (`projects`) | 6.3, 0.11 | – |
| snapshot resolution (`projections` by projected id, `snapshots`) | 9.9, 0.18 | – |
| projection memo (`projections` by real id) | 2.6, 0.05 | – |
| access epochs (the one statement) | – | 1.6, **0.03** |

Sessions and permissions were 0.67 ms of the 1.0 ms of database time a
pull cost; now 0.03 ms: negligible, as `OVERVIEW.md` asks.

**One `main`.** Landings into one `main` no longer collapse at 40/s: a
landing is 4 requests and 37 statements instead of a catch-up pull's 7
requests and up to 46 statements each time, so the gap between two
landings is no longer shorter than a catch-up. An interleaved run of both
servers on the same quiet minute (load average 14): at 20/s, before 0.99
collisions per landing, p50 70 ms; after 0.02, p50 14 ms; at 40/s, before
23–27 landed per second, after 40 with 0.01 collisions, p50 13 ms. At 80/s
both bend (43 vs 33 landed).

**Across 100 projects** nothing lands, before or after: S12's deriver holds
every database connection (BUG-911). Across 1 and 10 projects, one agent
each, both servers interleaved on the same minutes (load average 9–21):
one project 84 and 73 landings/s before, **105 and 114** after (p50 10–12
→ 8 ms); ten projects 659 and 649 before, **775 and 875** after (p50 14 →
11 ms). (The run of the first table measured 30 and 317 for these points
late in a run, at load 49: noise.)

**Notices.** PostgreSQL delivers the push's `NOTIFY`: another server saw a
push 5–15 ms later in the tests. YugabyteDB 2025.2 does not by default, and
the server falls back to the 100 ms expiry.

## The landing service (S17, 2026-11-07)

`scripts/bench-server.sh landing` (`veil-bench load --mode landing`): one
project's `main`, open loop, each agent landing one new file in its own
folder through `POST …/land` on the snapshot it last saw (its own last
landing: nobody pulls), waiting for the outcome; the agents are one person's
(one view key). Release builds, PostgreSQL 17 in Docker, objects in a local
directory (each object written with `fsync`), 15 s per point after a 3 s
warm-up, through `~/.cache/veil-orch/bench-quiet.sh`. Latency is from the
scheduled time, so a backlog shows. Phase 4's gates (§7): **1,000/s
sustained, p50 under 150 ms, p99 under 1 s, at most 1.5 database commits per
landing.**

**Quiet machine** (load average 7 before, 76 after; `bench4`):

| Agents | Target (/s) | Landed (/s) | p50 (ms) | p99 (ms) | Landings per batch | Build CPU (ms/landing) | Store objects (ms/batch) | Transaction (ms/batch) | DB commits per landing (the deriver's aside) | DB statements per landing | Storage writes per landing | Server CPU (ms/landing) | Refused |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1,000 | 1,000 | **1,084** | 196 | 1,785 | 14.7 | 0.27 | 13.3 | 4.2 | **1.06** | 11.5 | 13.7 | 6.6 | 0 |
| 1,000 | 2,000 | **1,353** | 4,167 | 6,417 | 332.9 | 0.30 | 296.1 | 44.9 | 1.00 | 11.1 | 13.3 | 7.2 | 0 |

**10,000 agents** (load average 19 before, 3 after; `bench5`; agents start
from the tips, without a clone):

| Agents | Target (/s) | Landed (/s) | p50 (ms) | p99 (ms) | Agents that landed | Landings per batch | Build CPU (ms/landing) | Store objects (ms/batch) | Transaction (ms/batch) | DB commits per landing | DB statements per landing | Storage writes per landing | Refused |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 10,000 | 1,000 | **995** | 152 | 1,596 | 9,975 | 26.6 | 0.36 | 23.8 | 9.8 | **1.06** | 11.1 | 14.0 | 0 |

**The whole curve, on a busier machine** (load 16 at the start, up to 199
during the later points as other agents built; `bench3`):

| Agents | Target (/s) | Landed (/s) | p50 (ms) | p99 (ms) | DB commits per landing | DB statements per landing | Refused |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 50 | 100 | 100 | 9.0 | 165 | 5.6 (2.0 without the deriver: one landing per batch) | 35 | 0 |
| 50 | 1,000 | 865 | 570 | 2,585 | 1.16 | 11.1 | 0 |
| 50 | 2,000 | 876 | 5,223 | 9,982 | 1.17 | 11.1 | 0 |
| 1,000 | 100 | 100 | 10.7 | 190 | 5.5 (2.0) | 35 | 0 |
| 1,000 | 1,000 | 841 | 2,033 | 3,083 | 1.02 | 12.8 | 0 |
| 1,000 | 2,000 | 524 | 7,351 | 12,289 | 1.10 | 16.5 | 0 |

* **1,000 landings/s into one `main`: reached on a quiet machine** (1,084/s
  at the 1,000/s target with 1,000 agents, 1,353/s at most; 995/s with
  10,000 agents), with no collision and no agent
  ever pulling: one `main` was bent at 20–40/s before (§3), 35/s through
  the API (S10). Every change is its own snapshot; `main` moved 74 times a
  second at 1,000/s (14.7 changes per move) and 4 times a second at the
  limit (333 per move).
* **Cost:** 1.0–1.06 database commits per landing (the submit's one, plus
  its share of its batch's): the gate (1.5) is met wherever batches fill.
  At 100/s each landing has its batch to itself, so it costs two; S12's
  deriver adds about 4 per batch in the background, as for a push.
  About 11 statements per landing.
* **p50 152–196 ms and p99 1.6–1.8 s at 1,000/s: the latency targets
  (150 ms, 1 s) are missed** (p50 by a little, p99 by about 0.7 s). Where the time goes: a landing waits for its submit (an API
  commit's checks and objects: about 6 ms of CPU and 7–9 objects written)
  and then for one to two batch cycles. **The object store is the limit**:
  13.3 storage writes per landing (about 7 at the submit, the new trees and
  snapshot and the submitter's projection in the batch), each a file written
  and synced on its own (`FsStore`), so 1,084 landings/s is about 14,500
  synced writes a second. At the limit a batch of 333 spends 296 ms storing
  its objects, 45 ms in its transaction and 0.3 ms of CPU per landing to
  build; the landing service itself (one core) is far from busy. **Packs
  (S28: one storage write per push or batch) are what raise it**; the
  landing service needs no change for that. With MinIO the same store limit
  is lower (376 landings/s across projects, §"Re-measured").
* **50 agents cannot keep 1,000/s:** each has one landing in flight, so 50
  agents land at most 50 per request time; the design's point is for
  thousands of agents.
* **Fairness:** every agent landed in every point (1,000 of 1,000 at
  1,000/s; 993–997 of 1,000 at 100/s and 9,975 of 10,000 at 1,000/s, where
  some had no turn in 15 s).

Raw results (not committed): `.scratch/bench-results/server-landing-d8cf2b2-20261107T143547Z*` (quiet), `…T150318Z*` (10,000 agents) and the `bench3` log.

**After the S17 review's fixes** (2026-11-07, on `integration` @ `9cddf93`
with S13's background fills; `docs/BUGS.md` BUG-1100 to 1109). The landing
service now keeps every view key of the project and never walks history,
bounds batches in bytes (8 MiB) and in changes (64), and its waiters stop
polling while it runs here (BUG-1108). The machine was shared and loaded
(load average 10–15 at the start of each point, often 80–260 during it),
so read the shape:

| Agents | Target (/s) | Landed (/s) | p50 (ms) | p99 (ms) | Landings per batch | Prepare (ms/batch) | Store objects (ms/batch) | Transaction (ms/batch) | DB commits per landing | DB statements per landing |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1,000 | 800 | 800 | 82 | 1,122 | 12.9 | 0.7 | 14.0 | 8.4 | 1.31 | 14.6 |
| 1,000 | 1,000 | **1,023** | 191 | **718** | 25.2 | 0.6 | 26.7 | 8.7 | **1.03** | 11.7 |
| 1,000 | 2,000 | 1,212 (the most) | 4,664 | 7,050 | 64.0 | 1.6 | 55.4 | 20.6 | 1.03 | 12.3 |
| 10,000 | 1,000 | 820 | 962 | 2,716 | 56.7 | 2.3 | 73.2 | 26.7 | 1.25 | 13.6 |

* **1,000/s into one `main` with 1,000 agents, p99 718 ms: under the 1 s
  target for the first time**, at 1.03 commits per landing.
* **Old and new side by side** (the server before the fixes, `76f337c`,
  run interleaved with the new one): their costs per landing are the same
  (build 0.27–0.4 ms of CPU, about 1 ms of object writes, 12–15
  statements), but which of two regimes a run settles in decides its p50:
  small batches (tens of ms) or, once behind, large ones (seconds). The old
  server too fell into the large one on a loaded machine (702/s, p50
  1.96 s at 800/s). Batches of at most 64 keep the service in the small
  regime (BUG-1109); at 10,000 agents, with the load rising to 115 during
  the run, it did not stay there.
* **The limit is still the object store** (about 14 synced writes per
  landing); packs (S28) are next.

**After the S17 review's second cycle** (2026-11-08, on `integration` @
`c446dd1`; `docs/BUGS.md` BUG-1110 to 1112, 1270 to 1275; load average 14
before each point, 24 before the 10,000-agent one, 8 after; `bench16`):

| Agents | Target (/s) | Landed (/s) | p50 (ms) | p99 (ms) | Agents that landed | Landings per batch | Prepare (ms/batch) | Build CPU (ms/landing) | Store objects (ms/batch) | Transaction (ms/batch) | DB commits per landing | DB statements per landing |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1,000 | 1,000 | **954** | 184 | **632** | 1,000 | 30.3 | 7.1 | 0.29 | 28.7 | 14.2 | **1.12** | 16.1 |
| 1,000 | 2,000 | 1,348 (the most) | 3,496 | 5,746 | 1,000 | 64.0 | 4.2 | 0.32 | 51.5 | 14.0 | 1.03 | 12.6 |
| 10,000 | 1,000 | **927** | 840 | 1,466 | 9,971 | 49.4 | 7.7 | 0.40 | 54.8 | 18.1 | **1.13** | 16.0 |

* **The first re-measurement after the cycle-2 fixes fell to 191/s with
  1,000 agents and 17/s with 10,000 (BUG-1275).** Every submit of edits now
  builds its stack (BUG-1112), and asked whether its base is on the branch
  through the derived graph (waiting for the deriver) or a walk. With
  10,000 agents on the setup tip and the deriver behind, each first submit
  queued a database read and a walk on the blocking pool, and starved the
  service's object writes (982 ms a batch) and the deriver. Now `landings`
  records each tip a batch moved from too, and a submit's base is found
  there in one indexed lookup; the graph and the walk are for other bases.
* **10,000 agents: 927/s at p99 1.47 s, against 820/s at 2.7 s after
  cycle 1;** 1,000 agents as before (954/s, p99 632 ms). About 4 more
  statements per landing than cycle 1 (the stack's lookup, the `landings`
  rows, the already-landed check). The 1 s p99 target is met at 1,000
  agents, missed at 10,000: batches of about 50 spend 55 ms storing their
  objects, so the object store is still the limit (packs, S28).

Raw results (not committed): `.scratch/bench-results/server-landing-9f1573e5-20261108T004444Z*` and `…T004755Z*`; the regressed run `…T002111Z*`, `…T002436Z*`.

**After the S17 review's third cycle: the redesign** (2026-11-08, on
`integration` @ `6fa552c`; `docs/BUGS.md` BUG-1300 to 1305; `HUB.md`
§13.19: the stack is the submitter's own history, every change lands as a
new snapshot, "on the branch" within the branch's lineage, a bounded base
lookup, retention while busy; load average 11 before the first point, 16
before the 10,000-agent one, 35 after; `bench18`):

| Agents | Target (/s) | Landed (/s) | p50 (ms) | p99 (ms) | Agents that landed | Landings per batch | Prepare (ms/batch) | Build CPU (ms/landing) | Store objects (ms/batch) | Transaction (ms/batch) | DB commits per landing | DB statements per landing | Storage writes per landing |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1,000 | 1,000 | **993** | **79** | **327** | 1,000 | 20.5 | 6.4 | 0.27 | 15.4 | 10.2 | **1.14** | 16.2 | 14.1 |
| 1,000 | 2,000 | 1,208 (the most) | 4,310 | 6,727 | 1,000 | 64.0 | 5.0 | 0.31 | 60.1 | 16.0 | 1.02 | 12.7 | 13.7 |
| 10,000 | 1,000 | **943** | 270 | 1,012 | 9,969 | 36.8 | 8.4 | 0.39 | 33.1 | 15.1 | **1.13** | 16.2 | 14.5 |

* **1,000 agents: 993/s at p50 79 ms and p99 327 ms, every target met**;
  10,000 agents: 943/s, p50 270 ms, p99 1.01 s (the 1 s target missed by
  12 ms). The same statements per landing as cycle 2 (16): the submit
  reads the branch's tip and lineage and looks its base up in `landings`
  (2 statements), the batch compares tip and lineage even when nothing
  moves, and retention adds 2 statements a branch every 5 s.
* **Caught here first:** an earlier run of the redesign stored each edits
  submit's objects twice (once before its stack was built, once before its
  commit): 20.8 storage writes a landing instead of 14, and at the
  2,000/s target the service fell into the large-batch regime (644/s,
  `bench17`). Fixed before commit: the objects are stored once, before the
  stack reads them.

Raw results (not committed): `.scratch/bench-results/server-landing-b1b10f37-20261108T064028Z*` and `…T064348Z*` (the label is the base commit; the binaries were the working tree), the double store `…T061236Z*`, `…T061440Z*`.

**After the redesign's review (the simplified rule, 2026-11-08,** on
`integration` @ `6b65ed6`; `docs/BUGS.md` BUG-1311 to 1315): the machine
never got quiet (load 15 at the start of each run, 30–160 during them), so
the redesign was measured against the commit before it (`b1509930`),
interleaved, two rounds:

| Agents | Target (/s) | Round 1: before → after (/s) | Round 2: before → after (/s) | Round 2 p99 (ms): before → after | DB statements per landing (round 2) |
|---:|---:|---:|---:|---:|---:|
| 1,000 | 1,000 | 964 → 870 | 941 → **1,052** | 1,280 → 1,290 | 14.5 → 15.0 |
| 10,000 | 1,000 | 707 → 328 | 846 → **888** | 2,774 → 2,029 | 17.0 → 16.9 |

* The cost per landing is unchanged (15–17 statements, about 14 storage
  writes, 1.0–1.2 commits). Every point is noisier than any run above: the
  object store took 50–90 ms a batch (15 ms when quiet), and two of the
  runs fell into the large-batch regime.
* **Round 1 at 10,000 agents (328/s, 2.7 commits per landing, half the
  agents finished) is not explained**: it ran at load 47, and the same
  build gave 888/s (1.16 commits) in round 2 and 905/s in a run before. A
  quiet re-measurement is owed.

Raw results (not committed): `.scratch/bench-ab7.log`, `.scratch/bench19.log`, `.scratch/bench20.log`.

**After the redesign's second review** (2026-11-08; BUG-1405 to 1409: the
line read as the submitter sees it, hidden runs stepped over by the graph,
"already landed" from the history; `bench21`). **The machine was not
quiet**: `bench-quiet.sh` waited 520 s for a load below 16, and the load
rose to 88 during the 10,000-agent point.

| Agents | Target (/s) | Landed (/s) | p50 (ms) | p99 (ms) | Agents that landed | DB commits per landing | DB statements per landing | Storage writes per landing |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1,000 | 1,000 | 853 | 1,592 | 2,297 | 1,000 | 1.11 | 14.2 | 14.4 |
| 1,000 | 2,000 | 1,092 | 4,596 | 8,063 | 1,000 | 1.02 | 15.7 | 13.7 |
| 10,000 | 1,000 | 508 | 3,219 | 8,149 | 7,553 | 2.00 | 23.1 | 20.6 |

* At 1,000 agents the cost per landing is that of every run above (14–16
  statements, 14 storage writes); the latencies follow the object store,
  66 ms a batch here against 15 ms when quiet.
* The 10,000-agent point has the overloaded signature seen before with
  both builds (`bench-ab7`: the earlier build gave 1.46 commits per
  landing at load 58): requests that time out are submitted again (2.0
  commits and 20.6 storage writes per landing; a quarter of the agents
  never finished). The quiet measurement is still owed.

Raw results (not committed): `.scratch/bench21.log`, `.scratch/bench-results/server-landing-e56f4848-20261108T142211Z*`, `…T142409Z*`.


## Gate runs on `22b9d837` (2026-11-12)

The gates of phases 2, 3 (blame) and 4 on the final code: `integration` @
`22b9d837`. The branch `gates` adds commits to the bench tool and one
test only (no product code), so the results are labelled `8148b427` to
`47d4f170`. Release builds, PostgreSQL 17 and MinIO in Docker, every run
through `~/.cache/veil-orch/bench-quiet.sh`, one at a time, alone on the
machine (32 threads, 30 GB) but for the one run marked "not alone". "Load" is the 1-minute load average the
script prints before and after; an "after" above 16 is the benchmark's own
(1,000 or 10,000 client threads) in every run below. "Before this week"
is a server built from `404ca2c1` (`integration` on 2026-11-11 02:01,
every milestone but S26 merged and none of the review's fixes), given to
the same bench as `SERVER_BIN`. Git beside Veil is in `OPENSCION.md`;
confirmed misses are `docs/BUGS.md` BUG-1940 to BUG-1949.

**The bench tool, changed for these runs** (`crates/veil-bench`):

* `load --protected`: `main` is a protected branch (`.veilrules`), its
  `[review]` rules at 0 approvals. **The benchmark cannot make a protected
  branch with approvals** (it opens no PRs): "protected" below always means
  this, the review checks of the landing path with nothing to approve.
* `load --mix`: 3 % of the landings change one line of a shared file read
  at the tip (`GET …/q/file`, then a landing on that tip: a content merge
  when another agent's line landed meanwhile), 2 % write one of 16 hot
  files on the agent's last landing (a conflict whenever someone wrote it
  since, then a new submit on the tip), the rest are a new file in the
  agent's own folder, as before.
* `load --people N`: the agents belong to N people in turn. They were all
  one person's, and the server serializes and bounds landings per person
  since S24 part B.
* `load --merge-every N` (`branches`): the agent lands its branch on `main`
  through the landing service after every N pushes.
* The server it starts gets `--max-connections 262144`: one address may
  open an eighth (S24), and 65,536 left 8,192 for 10,000 agents
  (BUG-1951). Idle agents stop at once at the end of a point: 10,000 took
  17 minutes (BUG-1952).

### G4: one `main`, 1,000 landings a second (phase 4 §7)

`OBJECTS=local LANDING_CLIENTS=1000,10000 LANDING_RATES=1000
scripts/bench-server.sh landing [-- flags]`: open loop at 1,000/s, 15 s a
point after a 3 s warm-up, objects in a local directory, as every run of
"The landing service" above. Gates: 1,000/s sustained, p50 under 150 ms,
p99 under 1 s, at most 1.5 database commits per landing, every agent
served. Latency is from the scheduled time, so a backlog shows.

| `main` | Server | People | Agents | Landed (/s) | p50 (ms) | p99 (ms) | Agents that landed | Landings per batch | Prepare (ms/batch) | Store objects (ms/batch) | Transaction (ms/batch) | DB commits per landing | DB statements per landing | Storage writes per landing | Load before / after |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| unprotected | before this week | 1 | 1,000 | 564 | 4,991 | 7,997 | 1,000 | 3.9 | 3.3 | 3.7 | 4.5 | 2.04 | 34.5 | 14.1 | 1.4 / 8.4 |
| unprotected | before this week | 1 | 10,000 | 496 | 5,384 | 9,183 | 7,410 | 2.8 | 0.9 | 3.3 | 4.6 | 2.88 | 43.1 | 14.1 | |
| unprotected | `22b9d837` | 1 | 1,000 | **464** | 7,222 | 10,353 | 1,000 | 4.4 | 4.0 | 3.9 | 6.8 | 2.25 | 46.3 | 14.1 | 3.6 / 7.2 |
| unprotected | `22b9d837` | 1 | 10,000 | **484** | 4,768 | 9,084 | 7,240 | 3.5 | 1.4 | 4.0 | 5.6 | 2.96 | 51.7 | 14.2 | |
| unprotected | before this week | 100 | 1,000 | 1,003 | 200 | 668 | 1,000 | 52.5 | 7.8 | 40.8 | 29.7 | 1.25 | 24.9 | 13.4 | 14.6 (waited 70 s) / 85.5 |
| unprotected | before this week | 100 | 10,000 | 974 | 197 | 588 | 9,975 | 46.7 | 3.2 | 34.5 | 28.0 | 1.88 | 29.9 | 14.2 | |
| unprotected | `22b9d837` | 100 | 1,000 | **924** | 205 | 1,289 | 1,000 | 57.3 | 12.5 | 47.8 | 35.6 | 1.41 | 36.8 | 14.3 | 2.1 / 49.5 |
| unprotected | `22b9d837` | 100 | 10,000 | **958** | 310 | 751 | 9,975 | 57.3 | 2.6 | 45.8 | 35.5 | 1.45 | 40.6 | 14.4 | |
| protected | before this week | 1 | 1,000 | 509 | 6,296 | 9,306 | 1,000 | 3.6 | 2.9 | 3.8 | 4.9 | 2.05 | 36.4 | 13.6 | 13.8 (waited 10 s) / 20.7 |
| protected | before this week | 1 | 10,000 | 414 | 5,883 | 10,145 | 6,174 | 2.8 | 1.0 | 3.7 | 5.5 | 4.41 | 49.5 | 14.2 | |
| protected | `22b9d837` | 1 | 1,000 | **441** | 6,934 | 10,089 | 1,000 | 7.5 | 9.0 | 5.4 | 13.1 | 2.10 | 50.4 | 13.9 | 14.9 / 17.7 |
| protected | `22b9d837` | 1 | 10,000 | **464** | 5,958 | 9,627 | 6,942 | 6.4 | 6.1 | 5.3 | 10.4 | 3.19 | 55.4 | 14.2 | |
| protected | before this week | 100 | 1,000 | 1,006 | 157 | 591 | 1,000 | 32.9 | 8.0 | 21.5 | 20.5 | 1.34 | 30.2 | 13.8 | 13.7 (waited 140 s) / 43.7 |
| protected | before this week | 100 | 10,000 | 1,009 | 270 | 699 | 9,981 | 58.3 | 3.1 | 43.8 | 34.6 | 1.73 | 32.5 | 13.8 | |
| protected | `22b9d837` | 100 | 1,000 | **721** | 2,743 | 4,666 | 1,000 | 64.0 | 43.5 | 42.9 | 64.3 | 1.58 | 46.2 | 14.3 | 14.1 (waited 110 s) / 135.3 |
| protected | `22b9d837` | 100 | 10,000 | **721** | 2,901 | 4,581 | 9,976 | 64.0 | 31.5 | 47.3 | 64.7 | 2.54 | 62.5 | 16.8 | |
| protected, `--mix` | `22b9d837` | 100 | 1,000 | **573** | 3,217 | 7,022 | 981 (212 landings failed: a file read at the tip answered `503 warming`, BUG-1949) | 20.3 | 14.7 | 14.5 | 21.7 | 1.84 | 45.2 | 13.4 | 13.9 (waited 70 s) / 16.2 |
| protected, `--mix` | `22b9d837` | 100 | 10,000 | **443** | 3,502 | 8,721 | 6,625 | 59.3 | 33.0 | 43.2 | 63.9 | 3.91 | 94.8 | 23.4 | |

Flags: `--people 100`, `--protected`, `--protected --mix --people 100`;
"before this week" adds `SERVER_BIN=<a build of 404ca2c1>`. The last
measurement of the same benchmark, one person and unprotected, was 993/s
(p99 327 ms) and 943/s (p99 1.01 s) on `6fa552c` (2026-11-08).

**Against the gates, on `22b9d837`:**

| What | Result | Target | |
|---|---|---|---|
| Landed/s, one person's agents, unprotected (the benchmark as it was) | 464 (1,000 agents), 484 (10,000) | 1,000 | **miss** (BUG-1940) |
| Landed/s, 100 people's agents, unprotected | 924, 958 | 1,000 | **miss by 4 to 8 %** (1,003 and 974 before this week) |
| Landed/s, 100 people's agents, protected (0 approvals) | 721, 721 | 1,000 | **miss** (BUG-1942; 1,006 and 1,009 before this week) |
| Landed/s, protected, 95 / 3 / 2 % mix, 10,000 agents of 100 people, 15 s | 443 | 1,000 | **miss** |
| The same for 10 minutes (the gate as designed) | 125 over the run, from about 190 down to about 40 | 1,000 sustained | **miss: the service does not hold** (BUG-1941; below) |
| 1,000/s offered for three minutes, 100 people, unprotected / protected | 220 / 106 an agent saw land (309 / 314 before this week) | 1,000 sustained | **miss** (BUG-1941); 500/s holds, 750/s does not |
| p50, the best case (100 people, unprotected) | 205 ms, 310 ms | under 150 ms | **miss** (200 and 197 ms before this week) |
| p99, the best case | 1,289 ms (1,000 agents), 751 ms (10,000) | under 1 s | **miss / pass** |
| Database commits per landing, the best case | 1.41, 1.45 | at most 1.5 | **pass**; 2.3 to 3.2 with one person (small batches) |
| Every agent served | 1,000 of 1,000; 9,975 of 10,000 in 15 s with 100 people; about 7,000 of 10,000 with one person | every agent | **pass** only with 100 people |

**Where the time goes, and what each of this week's changes costs.**

1. **One person's agents wait on each other** (BUG-1940; S24 part B,
   2026-11-10, not this week). Each submit locks its person's row
   (`SELECT id FROM people … FOR UPDATE`) for its whole transaction.
   `pg_stat_statements`: with one person a submit waits 83.5 ms for that
   lock before this week and 94.6 ms now; with 100 people 0.08 and
   0.03 ms. The transaction under the lock went from 1.77 to 2.15 ms
   (1/564 s, 1/464 s): this week's statements in it cost 0.4 ms, and 18 %
   of the rate. Batches hold 4 landings, so commits per landing are 2 to 3.
2. **This week's changes, on an unprotected `main`, 100 people** (per
   landing, from `pg_stat_statements`; database time in brackets). The
   rate went from 1,003 to 924/s (1,000 agents) and 974 to 958/s (10,000),
   p99 from 668 to 1,289 ms and 588 to 751 ms; statements per landing from
   24.9 to 36.8; a batch of about 55 from 7.8 to 12.5 ms of prepare and
   29.7 to 35.6 ms of transaction (0.2 ms a landing together).

   | Change | Statements added per landing | Where |
   |---|---:|---|
   | BUG-1881: the shared advisory lock and the row lock of the GC epoch, first in every root-writing transaction | 3.0 (0.07 ms): the guard 1.02, and 2.02 reads of the epoch it is compared with | every submit's transaction, and one per batch |
   | BUG-1884 and BUG-1921: "reverted twice" | 2.0 (0.05 ms): the lookup 1.00, the queued reverts settled 1.02 | every submit; once more per batch |
   | BUG-1880: the review rules | 1.0 (0.02 ms): the rules' state beside the branch | every submit (the rest only on a protected branch, below) |
   | BUG-1524 and BUG-1922: landed records for held snapshots | 0: the "already landed" lookup and the batch's `landings` read became statements with `NOT EXISTS`, and the branch read carries `changes_recorded` (0.02 ms each, as before; the batch's read 0.08 ms a landing, as before) | submit and batch |
   | BUG-1920: write access for every path a landed entry brings | 0: no statement; it runs in the batch's prepare on trees it already reads | part of prepare's 7.8 → 12.5 ms a batch (under 0.09 ms a landing, with the lookups above) |
   | Not on the list: the embargo fixes (BUG-1851 and the others) | 2.0 (0.01 ms): the project's unreleased embargo lines | every submit |

   None of these costs database time worth naming (0.15 ms a landing in
   all); they cost round trips, about 0.2 ms each on one connection, and
   those inside the submit's transaction are what item 1 multiplies.
3. **BUG-1880 on a protected `main`** (BUG-1942). The review gate of each
   entry is asked at the submit, again for every entry in the batch's
   prepare, and again for every entry inside the batch's commit
   transaction: the candidate PRs and the holds are read 2.94 times a
   landing where they were read once, and the reverted-twice lookup 2.94
   times (30.2 → 46.2 statements a landing in all). They run one entry after
   another, so a batch of 64 spends 43.5 ms in prepare (8.0 before) and
   64.3 ms in its transaction (20.5 before): **1,006 → 721/s, p99 0.59 →
   4.7 s** with 1,000 agents, 1,009 → 721/s with 10,000. The batches are
   full (64): this is the service's limit on a protected branch.
4. **The object store is no longer the first limit**, but it is the largest
   part of a batch: 41 to 48 ms to store a batch of about 55 (14 storage
   writes a landing, each a synced file, as before).

**Ten minutes: the gate as designed, as far as the tool can express it**
(`OBJECTS=local LANDING_CLIENTS=10000 LANDING_RATES=1000 DURATION=600
scripts/bench-server.sh landing -- --protected --mix --people 100`; load
14.9 before after a 20 s wait, 24.6 after, 20 to 63 during). Not run: the
1,000 thin pulls a second beside it (the tool's pulls are catch-up pulls
of one project it creates itself), and the failover run (one server).

| Measure | Result | Gate |
|---|---|---|
| Landed, by the server's records | 75,646 in 606 s: **125/s**; 172 to 285/s in the first minute, 26 to 91/s in the last three | 1,000/s sustained |
| Landings an agent saw finish within its 60 s | 28/s; p50 22.0 s, p99 44.0 s | p50 150 ms, p99 1 s |
| Requests that failed | 582,677: still queued after the server's 30 s wait, "you already have 1000 landings waiting in the queue" (`429`), and file reads at the tip answered `503 warming` | — |
| Submits accepted / refused at the person's bound | 183,853 / about 203,000 | — |
| Conflicts delivered per landing | 0.032 | 2 % of changes |
| Database commits / statements / storage writes per landing | 21.8 / 759 / 195 (work for landings that never finished) | 1.5 commits |
| Server memory | 1.0 GB after the first 40 s, 2.1 GB at the end | — |

It collapses because **each batch reads the whole queue** (BUG-1941): the
batch picker's statement returned 52 million rows in 2,601 calls: 1,257 a
call in the first minute, 10,191 by the fifth, 76,600 a call over the last
five (168 ms each in the database, before the server decodes them), to
choose 64. On a protected `main` with the mix the service lands under
600/s (the 15 s points), so at 1,000/s the queue grows from the first
second, each batch slows down further, agents whose 30 s wait ran out
submit again, and people reach their bound of 1,000 queued landings.
Before this week's fixes a protected `main` landed 1,006/s (15 s, no mix):
BUG-1880's cost is what puts the gate's rate above the service's capacity;
the collapse past capacity is S24 part B's.

**The database, before and after the 10 minutes** (sampled every 20 s:
`pg_database_size`, and rows from the statistics, `n_live_tup`; "before" is
the first sample of the measured window, 02:03:31, 7,605 landings in;
"after" 02:13:37; per landing = growth / 75,646 landed):

| | Before | After | Per landing |
|---|---:|---:|---:|
| Database size | 96.0 MB | 1,242.7 MB | 15.2 KB |
| Disk used (database, WAL, objects in the local store) | — | +18.9 GB | 250 KB |
| `projections` | 22,098 rows | 433,348 rows, 382 MB | 5.44 rows, 4.8 KB |
| `landing_queue` | 7,877 | 183,887, 157 MB | 2.33 rows, 1.9 KB |
| `view_graph` | 12,244 | 166,264, 141 MB | 2.04 rows, 1.7 KB |
| `view_file_history` | 12,254 | 166,274, 101 MB | 2.04 rows, 1.2 KB |
| `snapshots` | 15,713 | 270,795, 70 MB | 3.37 rows, 0.9 KB |
| `view_changes` | 12,244 | 166,264, 69 MB | 2.04 rows, 0.8 KB |
| `graph` | 7,642 | 83,250, 68 MB | 1.00 row, 0.8 KB |
| `change_refs` | 7,877 | 183,919, 46 MB | 2.33 rows, 0.6 KB |
| `landings` | 7,841 | 85,131, 45 MB | 1.02 rows, 0.5 KB |
| `landed_from` | 7,652 | 83,275, 34 MB | 1.00 row, 0.4 KB |
| `landed_changes` | 7,605 | 83,251, 34 MB | 1.00 row, 0.4 KB |
| `file_history` | 7,648 | 83,256, 31 MB | 1.00 row, 0.4 KB |
| `rule_history` | 7,643 | 83,251, 27 MB | 1.00 row, 0.3 KB |
| `audit_log` | 8,175 | 186,004, 25 MB | 2.35 rows, 0.3 KB |

This run's growth per landing is inflated by the 2.33 submits a landing
(queue rows, change refs, snapshots and projections of changes that never
landed) and by the mix's shared files (46 KB a version). The growth of
runs that hold their rate follows the next table.

**Three minutes at a time: what the service holds** (`OBJECTS=local
LANDING_CLIENTS=10000 LANDING_RATES=<offered> DURATION=180
scripts/bench-server.sh landing -- --people 100 [--protected] [--mix]`;
10,000 agents of 100 people). "Agents saw land" counts landings answered
within the agent's 60 s; the server's own rate is from its landed records,
sampled every 15 s.

| `main` | Server | Offered (/s) | Agents saw land (/s) | p50 | p99 | Failed requests | The server's landings/s, each 15 s | DB commits / statements per landing | Load before / after |
|---|---|---:|---:|---:|---:|---:|---|---|---|
| unprotected | before this week | 1,000 | 309 | 15.5 s | 70.6 s | 54,327 | 982, 524, 388, 354, 371, 341, 300, 345, 213 | 3.12 / 47.4 | 14.0 (waited 20 s) / 31.3 |
| unprotected | `22b9d837` | 1,000 | **220** | 10.0 s | 38.5 s | 70,557 | 644, 529, 405, 375, 208, 17, 0, 0, 0, 362, 366, 358, 388 | 3.70 / 79.7 | 2.3 / 19.1 |
| protected | before this week | 1,000 | 314 | 22.0 s | 64.7 s | 53,860 | 905, 605, 358, 392, 376, 401, 465, 324, 92 | 2.61 / 47.8 | 15.3 (waited 40 s) / 24.2 |
| protected | `22b9d837` | 1,000 | **106** | 3.8 s | 21.9 s | 91,231 | 472, 358, 93, 0, 166, 280, 328, 294, 332, 224 | 8.65 / 174.3 | 15.3 (waited 30 s) / 29.4 |
| protected, `--mix` | before this week | 1,000 | 111 | 20.4 s | 46.0 s | 90,305 | 319, 331, 297, 247, 258, 213, 169, 158, 0, 56, 144, 154, 195 | 7.49 / 114.9 | 16.0 (waited 20 s) / 27.1 |
| protected, `--mix` | `22b9d837` | 1,000 | 28 (the 10-minute run) | 22.0 s | 44.0 s | 582,677 | 172 to 285, then down to 26 to 91 | 21.8 / 759 | above |
| unprotected | `22b9d837` | 750 | 398 | 0.6 s | 42.8 s | 12,832 | 801, 760, 733, 612, 324, 351, 341, 316, 392 | 1.91 / 48.9 | 13.8 (waited 20 s) / 19.4 |
| unprotected | `22b9d837` | 500 | **500** | **104 ms** | **925 ms** | 0 | 467 to 558 throughout | 1.68 / 40.2 | 16.0 / 27.6 |
| protected, `--mix` | `22b9d837` | 300 | **300** | **41 ms** | **589 ms** | 4 (`warming`) | 284 to 312 throughout | 3.61 / 66.7 | 14.3 (waited 30 s) / 18.8 |
| protected | `22b9d837` | 500 | 459 | 173 ms | 12.9 s | 0 | 463 to 598, then 414, 345, 251 | 1.93 / 53.7 | 10.2 / 45.8, **not alone** (see below) |

* **No build holds 1,000/s for three minutes**, protected or not, this
  week's or last week's: each starts near its 15 s rate (982, 905, 644,
  472/s) and is at 200 to 400/s within a minute, with stretches of 15 to
  45 s in which nothing lands. The 15 s points of the first table end
  before the queue is long. The batch's read of the queue is what grows
  (BUG-1941): 43 to 110 rows a call in the first 15 s, 5,300 to 11,900 on
  average by the end of three minutes, on both builds.
* **This week's fixes make the fall deeper**: 309 → 220/s unprotected,
  314 → 106/s protected (BUG-1942), 111 → 28/s with the mix.
* **Under its capacity the service is fast**: 500/s unprotected for three
  minutes at p50 104 ms and p99 925 ms with nothing refused; 300/s on a
  protected `main` with the 95 / 3 / 2 mix at p50 41 ms and p99 589 ms
  (0.020 conflicts delivered per landing). 750/s did not hold, and a
  protected `main` offered 500/s fell behind in its last 45 s (459/s, p99
  12.9 s). That last run is the only one here that was not alone: another
  session's benchmark (`scripts/bench-server.sh 1g` in another worktree)
  held the benchmark lock from 03:30 to 03:42 UTC, this run started as it
  ended, and that session was still at work. So what is
  sustained today is between 500 and 750 landings a second on an
  unprotected `main`: 43 to 65 million a day, where the phase's number is
  86 million.

**Growth per landing, from the two runs that held their rate** (the
database sampled as above; before = the first sample of the run):

| | Unprotected, 500/s | Protected, `--mix`, 300/s |
|---|---:|---:|
| Landings between the samples | 87,586 in 198 s | 50,298 in 168 s |
| Database size | 61.4 → 907.8 MB: **9.7 KB a landing** (the deriver's rows were 14 % behind at the last sample) | 50.4 → 655.3 MB: **12.0 KB a landing** |
| Disk used: database, WAL and the local object store | +7.9 GB: 90 KB a landing | +5.1 GB: 101 KB a landing |
| Rows per landing: `projections` | 2.73 | 4.02 |
| `view_graph`, `view_file_history`, `view_changes` (each) | 1.41 | 2.00 |
| `snapshots` | 2.00 | 2.03 |
| `landings` / `audit_log` | 1.10 / 1.09 | 1.31 / 1.32 |
| `landing_queue`, `change_refs`, `landed_from`, `landed_changes` (each) | 1.00 | 1.00 to 1.02 |
| `graph`, `file_history`, `rule_history` (each) | 0.86 | 1.00 |
| Largest tables, bytes a landing | `projections` 2.6 KB, `view_graph` 1.2 KB, `landing_queue` 0.9 KB, `view_file_history` 0.8 KB | `projections` 3.3 KB, `view_graph` 1.7 KB, `view_file_history` 1.2 KB, `landing_queue` 1.1 KB |
| Server memory, first → last sample | 0.60 → 1.55 GB (peak) | 0.53 → 1.74 GB |

About 18 to 22 rows and 10 to 12 KB of database a landing with two view keys
(the admin's and the agents' group's), so a million landings a day is
about 10 to 12 GB of database a day; queue rows are kept (1 KB a landing)
while the branch is busy. The local object store takes most of the disk:
14 files a landing, a 4 KiB block each at least. The server's memory grew
by about 1 GB in three minutes in both runs and by 1.1 GB over the 10
minutes; whether it levels off was not measured.

**With 256 database connections** (`… landing -- --people 100
--db-connections 256`; the bench starts its server with 64, and S24 lets a
project run three quarters of them at once; load 14.3 before after a 20 s
wait, 40.6 after): 1,010/s, p50 132 ms, p99 666 ms, 1.33 commits per
landing with 1,000 agents: **every gate met**; 935/s, p50 317 ms, p99
1,135 ms, 1.82 commits with 10,000. So for 15 s an unprotected `main` and
many people's agents still reach the gate at 1,000 agents, and the 924/s
of the first table is within the spread between runs of one build; at
10,000 agents the latency gates are missed either way. It was not run for
three minutes.

### The other gates of phase 4 §7

| Gate | Measured | Target | | Load before / after |
|---|---|---|---|---|
| `veil-bench prs`: 100,000 PRs in 50 visibility classes, a viewer who may see 25 of them (50,000 PRs): list with its count | p50 6.3 ms, p99 20.3 ms | under 50 ms | **pass** | 0.95 / 1.26 |
| search | p50 22.4 ms, p99 26.9 ms | under 50 ms | **pass** | |
| open a PR | p50 8.7 ms; the slowest of 60, the first, 103 ms | under 100 ms | **pass** on the median | |
| update (a new revision) | p50 9.4 ms, p99 51.6 ms | under 100 ms | **pass** | |
| show | p50 5.8 ms, p99 9.1 ms | — | | |
| `veil-bench bisect`: a culprit among 10,000 landings in at most 4 rounds of 8 parallel checks | **not run: there is no such benchmark** (no `veil-bench bisect`, no test at that size) | | | |
| failover: the leaseholder killed every 30 s | **not run**: the bench starts one server | no ticket lost, at most 2 s of stall | | |
| 1,000 thin pulls a second and phase 3 queries beside the landings | **not run** as designed (below); the mix's one query, a file read at the tip, answered `503 warming` 212 times in 15 s at about 600 landings a second (BUG-1949) | | | |

There is no `veil-bench prs` either: the gate is `server_hub`
`prs::pr_speed` (ignored), run as `.scratch/gate-tests.sh prs::pr_speed
--ignored` (a release build of the test binary on a PostgreSQL 17 and
MinIO of its own). It could not run as written: it inserted a `prs.risk`
column that the schema keeps in `pr_revisions` (BUG-1950, fixed on this
branch). On bisect, by the design's own bound (`HUB.md` §13: at most
⌈log₉ N⌉ rounds with 8 parallel checks) 10,000 candidates need 5 rounds,
not 4: 9⁴ is 6,561. Only narrowing by path can bring it to 4.

### Many branches moving at once (the owner's extra shape)

`.scratch/bench-custom.sh custom -- --mode branches --projects 1 --clients
300,600 --rates max --duration 30 [--merge-every 5]` (a copy of
`scripts/bench-server.sh` with one more profile that passes its flags to
`veil-bench load`; objects in a local directory; the agents are one
person's). Each agent pulls `main`, then pushes one new file to a branch
of its own, in a closed loop. `--merge-every 5`, new on this branch: after
every fifth push the agent lands its branch on `main` through the landing
service (`POST …/land` with the branch's tip: the five changes that have
not landed yet land as new snapshots on `main`).

| Agents | Merges into `main` | Pushes (/s) | p50 (ms) | p99 (ms) | Branches landed on `main` (/s) | DB commits per push (the push's own) | DB statements per push | Storage writes per push | Server CPU (ms/push) | Errors | Load before / after |
|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| 100 (the `load` profile, MinIO) | none | 1,131 | 80 | 216 | — | 3.19 (1.18) | 39.1 | 2.6 | 8.2 | 0 | 5.8 / 81.6 |
| 300 | none | 739 | 392 | 751 | — | 3.50 (1.49) | 42.1 | 3.1 | 18.9 | 0 | 15.7 (waited 50 s) / 37.9 |
| 600 | none | 490 | 1,236 | 1,686 | — | 4.36 (2.34) | 45.8 | 3.3 | 35.6 | 0 | |
| 300 | every 5th push | 259 | 673 | 4,496 | 53 (1,589 in 30 s; 265 changes/s) | 4.75 (2.73) | 81.6 | 10.8 | 71.6 | 0 | 15.6 (waited 50 s) / 45.4 |
| 600 | every 5th push | 306 | 1,456 | 6,308 | 55 (1,653 in 30 s) | 4.64 (2.59) | 69.2 | 10.3 | 62.5 | 148: "the branch did not land on main", still queued after the server's 30 s wait | |

* **More agents push less**: 1,131 pushes a second with 100 agents, 739
  with 300, 490 with 600, at 19 and 36 ms of server CPU a push (8 ms at
  100): the server's cores are busy (14 to 17 of 32), and the
  cost of a push grows with the number of branches moving.
* **Branches merge into `main` at about 55 a second** whatever the number
  of agents, five changes each; the pushes fall to 260 to 310 a second
  beside them, and with 600 agents 148 merges were still queued after
  30 s. The agents are one person's, so their landings are serialized
  (BUG-1940).

### G2: the server's numbers (phase 2 §7 and §8, `storage-and-cost.md` §9)

`scripts/bench-server.sh load` (MinIO; load 5.8 before, 81.6 after), and
again with the server of before this week (0.6 before, 101.5 after);
`scripts/bench-server.sh cache` (15.7 before after a 100 s wait, 66.2
after); `scripts/bench-server.sh daemon` (2.8 before, 22.2 after);
`S8_BENCH_FILES` as given, `.scratch/gate-tests.sh
workspaces::s8_bench_ready_to_read --ignored`; `scripts/bench-server.sh
1g` twice (`OPENSCION.md`).

| Gate | Measured on `22b9d837` | Before this week | Target | |
|---|---|---|---|---|
| Pulls/s, up to date (`main` quiet), 10 / 100 / 1,000 agents | 13,355 / 27,348 / 25,862 | 14,121 / 27,365 / 26,738 | — | |
| Statements per up-to-date pull, warm caches | 3.0 | 3.0 | 5 or fewer | **pass** |
| Pulls/s, `main` moving 20/s, 10 / 100 agents | 14,002 / 13,371 | 14,044 / 13,707 | 10,000 | **pass** |
| Pulls/s, `main` moving 20/s, 1,000 agents | 1,467 (p50 664 ms; 59.8 statements a pull) | 1,527 (59.0) | 10,000 | **miss** (BUG-1947) |
| Pulls/s while `main` moves 1,000/s | **not run as designed**: the tool's one background agent landed 41/s (`--background 1000`); beside it 100 agents pulled 3,789/s (20 statements a pull), 1,000 agents 1,465/s | — | 1,000+ | |
| Object reads answered by the regional cache | 99.98 to 100 % (10, 100, 1,000 agents; `main` still and moving) | — | 99 % | **pass** |
| The regional cache's memory | 196 MiB at most | — | 512 MiB | **pass** |
| Fresh thin workspaces reading, through the cache / the server | 4,241 to 4,834/s / 4,266 to 4,569/s (100 and 1,000 agents) | — | — | |
| Database commits per push, one agent | 1.00 (push), 1.01 (API) | 1.00, 1.01 | 1 | **pass** |
| Database commits per push, pushes at once | 1.18 to 2.25 (10 and 100 agents on their own branches), 1.43 (100 projects), 2.40 (API, 100 projects) | 1.27 to 2.22, 1.48, 2.37 | 1 | **miss** (BUG-1946) |
| Storage writes per push | 2.0 | 2.0 | 2 or fewer | **pass** (3.1 to 3.4 where pushes into one `main` lose races) |
| Server peak memory, 1 GB profile | 965 MiB, 936 MiB | — | under 1 GB | **pass** |
| Landings/s across 100 projects | 1,323 (push), 617 (API) | 1,249, 589 | 4,000 | **miss** (BUG-1948) |
| Landings/s into one `main`, 50 agents, through the API | 20 at 20/s (p99 47 ms); 25 at 50/s (p99 11 s) | 20; 23 | 100, p99 under 500 ms | **miss** as on 2026-11-07 (35/s then); the landing service is what lands into one `main` now |
| Fresh workspace ready (`bench-server.sh daemon`: the tips, their grant, the root and top-level trees), 1,000 / 10,000 files | cold daemon 16.7 / 8.9 ms; warm 3.4 / 2.9 ms; no daemon 7.0 / 4.2 ms | — | 2 s cold, 300 ms warm | **pass** |
| Fresh mounted workspace to the first `ls` and `cat` (S8), 2,000 / 50,000 files | cold 255 / 242 ms; warm 117 / 160 ms; 1,000 files read cold in 307 / 297 ms | — | 2 s cold, 300 ms warm | **pass** (load 13.8 before after a 30 s wait, 11.7 after) |
| The same at 200,000 files (`S8_BENCH_FILES=200000`) | cold 288 ms; warm 259 ms; 1,000 files read cold in 272 ms | — | 2 s cold, 300 ms warm | **pass**, the warm one by 41 ms (load 2.8 before, 2.7 after) |

`veil-bench workspace --files 100k,1M --bytes 10G` of the design does not
exist; the two rows above are the nearest measurements.

**This week's fixes on the push and pull paths** (the two `load` runs):
nothing in rates, commits or storage writes beyond the spread between
runs. Statements per operation rose: a push 69.9 → 81.3 (one agent, its
deriver's included), 48.2 → 55.3 (10 projects), 39.2 → 43.8 (100
projects); an API commit 45.2 → 52.9, 31.1 → 37.0, 30.8 → 36.1; a push to
an own branch 65.8 → 76.8, 43.7 → 49.6, 34.9 → 39.1. That is 4 to 11
statements more per landing: BUG-1881's guard and epoch reads on every
transaction that adds roots, and the lookups of the landing path where a
push goes through it. Up-to-date pulls did not change (3.0 statements).
The commits above 1 per push, the pulls at 1,000 agents and the rate
across projects are the same before this week.

### The blame speed gate (G3; BUG-1214, after BUG-1893, 1895, 1896)

`server_hub` `blame::bug_1214_a_first_blame_costs_more_than_its_gate` and
`blame::blame_speed` with `VEIL_BLAME_BENCH_VERSIONS=10000`, release build:
`OBJECTS=local .scratch/gate-tests.sh blame::bug_1214…` (load 0.6 before,
2.3 after), `MINIO=shared .scratch/gate-tests.sh blame::bug_1214…` (8.4,
3.6), `MINIO=shared VEIL_BLAME_BENCH_VERSIONS=10000 .scratch/gate-tests.sh
blame::blame_speed` (15.8 after a 60 s wait, 3.5).

| Gate | Measured | Last time | Target | |
|---|---|---|---|---|
| The first blame of a 5,000-line file changed 10,000 times, objects in a local directory | **425 ms** (42.5 µs a version) | 430 ms (BUG-1214's row), 466 ms (the last run before this week's fix) | 1 s | **pass** |
| The same, objects in S3 (MinIO) | **528 ms** (52.8 µs a version) | 527 ms (BUG-1214's row), 982 ms (the last run before this week's fix) | 1 s | **pass** |
| `blame_speed` (20,000 snapshots, a hidden change between every two, MinIO): the first blame, admin / anyone on Earth | 544 ms / 545 ms, each in one request | — | 1 s | **pass** |
| Blame, precomputed, p50 / p99 | 20.3 / 25.0 ms (admin), 21.8 / 23.4 ms (anyone on Earth) | 18.1 / 21.3 and 25.4 / 40.4 ms (S14 cycle 3) | 50 ms | **pass** |
| `history --follow -n 50`, p50 / p99 | 1.0 / 1.8 ms, 1.3 / 1.9 ms | — | 50 ms | **pass** |

The stricter line maps of this week's blame fix do not show: 425 and
528 ms against 430 and 527 ms when S16 fixed BUG-1214, and under the 466 and 982 ms of the last run. With a MinIO container started for the run,
the two S3 runs failed in their setup instead: the test's own writes (32
at once, 165 KB each) got `S3 PUT: HTTP 499` twice out of tens of thousands,
and the blame then missed an object (BUG-1953). They passed on the
machine's long-lived MinIO (`veil-shared-minio`, a bucket of the run's),
which is how the gate was measured before.

## Holding the rate past capacity (BUG-1955, 2026-11-12, `landhold2`)

The same benchmark as G4 above, for three and ten minutes: `OBJECTS=local
LANDING_CLIENTS=10000 LANDING_RATES=1000 DURATION=180
scripts/bench-server.sh landing -- [--protected] [--mix] [--people 100]
[--steps RATE:SECONDS,…]`, 10,000 agents, open loop. Each run went
through `bench-quiet.sh` (load before under 16). `veil-bench load` now
prints a time series every 10 s (offered, landed by the service,
finished for an agent, the queue, p50/p99 from the scheduled time, the
accepted request's wait, answers that told the agent to wait, failures,
entries sent to a merge, landings per batch, commits per landing, and
the server's `landing_pick_statements`, `landing_pick_rows` and
`landing_review_asks`); `--steps` changes the offered rate during the
run. The profile is timing spans in a build kept off the branch
(`perf` is not allowed on this machine), the database's active backends
sampled every 0.2 s (`pg_stat_activity` wait events), `vmstat` and `top`.

**Two of the benchmark's own costs, removed.** (1) PostgreSQL ran with
its default 128 MB of shared buffers against a database of 1.5 GB after
three minutes: a third of the backends' active time was `DataFileWrite`
(writing out pages themselves), and the batch's statements took 70 to
120 µs a row. The deployment gives the database 4 GB
(`deploy/do/configure.sh`); the benchmark does too now. (2) The server
reached the database through Docker's published port: `docker-proxy`
took 3 of the 32 threads, every statement two more copies. It goes to the
container's address now, as to a database on its own host. Durability is
unchanged (`synchronous_commit = on`, every object `fsync`ed).

**What the profile showed** (protected, `--mix`, 1,000/s offered, 10,000
agents of 100 people; ms per batch of the service unless named):

| Build and harness | Finished (/s) | p50 / p99 (ms) | Batch cycle | Transaction | Store objects | Build | Prepare | Waiting for the batch before | A submit's work (`create_with`) | Its wait for the project's gate |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `af997c49`, default database | 703 | 10,191 / 57,001 | 70.0 | 48.7 | 26.4 | 24.9 | 21.7 | 18.7 | 45.9 | – |
| the same, 4 GB of shared buffers | 902 | 3,656 / 26,351 | 56.9 | 35.4 | 27.1 | 23.8 | 13.7 | 15.6 | 41.5 | – |
| + the objects stored during the transaction | 904 | 5,424 / 21,467 | 45.3 | 34.0 | 22.7 | 28.5 | 8.4 | 5.3 | 43.8 | – |
| + the database at its own address (120 s) | 970 | 235 / 3,571 | 40.7 | 30.4 | 20.7 | 23.7 | 9.4 | 4.6 | 35.2 | 354 |

- **The 80 ms of an overlapping build** (BUG-1955's row) was reading
  the branch's whole edit set since the change's base (every folder
  anyone landed in since, 10,000 of them for a base ten seconds old), on
  the batch's own thread: spans on the build before `touching`
  (`a1c4f691`'s profile) gave an entry sent to a merge 24.3 ms of the
  batch (23.2 ms of it that read), a conflict 61.2 ms (27.8 ms for the
  report's "landed since", 22.2 ms for the edit set), and the merge
  worker 66.5 ms more. `touching` reads only the change's own paths: an
  entry sent to a merge costs the batch 0.03 ms now, a conflict 2.8 ms,
  a merge run 28 ms on its worker.
- **The half-full batches** (36 of 64) were the service's own pace
  before BUG-1941's fix, and now the entries a batch sends to a merge:
  41 to 53 of 64 land, the others go to a merge worker or are answered
  conflict, and each overlapping change comes back up to three times
  (BUG-1956, below).
- **The 9.68 commits a landing** were commits for submits nobody waited
  for: 93,363 requests timed out and were sent again, each a commit, and
  the agents saw 96 landings a second of the 229 landed. With the
  answers below, nothing is done for a refused submit; what remains above
  1.0 is the batch (1/50), the deriver's pass (about 0.2) and the merge
  workers' commits (0.2 to 0.6 with the mix, more past capacity).
- **The batch's longest step** was storing its objects (2 × `fsync` per
  object, some 500 a batch) and then running its transaction, one after
  the other; the transaction now runs while they are written and waits
  for them only before `COMMIT` (HUB §13.32 item 10).
- **A submit's 35 to 45 ms** are mostly waiting: of a submit's build,
  1 ms is CPU (thread CPU time) and 12 ms wall; storing its 5 objects
  11 ms (`fsync`); reading its stack 8 to 12 ms; its transaction 6 to
  7 ms. During a run the machine is at 55 to 60 % CPU (25 % system) and
  25 to 30 % I/O wait (`vmstat`): the load tool's 10,000 agents, the
  server, the database and about 30,000 `fsync`s a second share 32
  threads. A submit holds one of its project's 48 gate places (¾ of 64
  database connections) for that time, so a project takes about 1,100
  submits a second here; past that, requests wait in the gate.

**Three-minute runs, before and after** (10,000 agents; finished: the
landings the agents saw land, per second; commits: database commits per
landing):

| Run | Build, harness | Finished (/s) | p50 (ms) | p99 (ms) | Commits | Failed requests |
|---|---|---:|---:|---:|---:|---:|
| unprotected, 100 people | `a2fff143`, old | 668 | 29,274 | 58,519 | 1.46 | 0 |
| | `af997c49`, old | 942 | 1,922 | 20,422 | 1.16 | 0 |
| | **`landhold2`, new** | **996** | **280** | **1,187** | **1.22** | 0 |
| protected, 100 people | `a2fff143`, old | 652 | 27,625 | 61,810 | 1.67 | 0 |
| | `af997c49`, old | 871 | 2,820 | 40,712 | 1.18 | 216 |
| | **`landhold2`, new** | **998** | **329** | **1,216** | **1.21** | 0 |
| protected, `--mix`, 100 people | `a2fff143`, old | 96 (229 landed) | 15,000 | 36,000 | 9.68 | 93,363 |
| | `a2fff143`, new | 133 (269 landed) | 12,980 | 36,628 | 7.58 | 86,726 |
| | `af997c49`, old | 734 | 10,287 | 54,032 | 1.40 | 4,328 |
| | **`landhold2`, new** | **935** | **1,224** | **10,781** | **1.82** | 1,365 |
| unprotected, one person | `a2fff143`, old | 643 | 22,111 | 63,647 | 1.20 | 5,624 |
| | `af997c49`, old | 985 | 1,545 | 7,747 | 1.16 | 0 |
| | **`landhold2`, new** | **995** | **293** | **1,156** | **1.19** | 0 |

"Old": the benchmark as it was (128 MB of shared buffers, `docker-proxy`);
"new": as now. `a2fff143` is the start of this work (BUG-1940 to 1942
fixed); `af997c49` the branch's first part (`touching`, read-ahead,
back-pressure, a random slot first). The `--mix` row of `a2fff143`, old,
is BUG-1955's own run. Per 10 s, the plain runs on `landhold2` hold 922
to 1,069/s for the whole three minutes, p99 400 to 1,270 ms; the mix
holds 980 to 1,076/s for 90 s, then 810 to 950/s with the queue at its
bound.

**Ten minutes, the mix** (`landhold2`; a row a minute of the series):

| t (s) | offered/s | landed/s | finished/s | queue | p50 ms | p99 ms | wait p50 | wait p99 | told to wait | failed | to merges | per batch | commits/landing | pick stmts | pick rows | review asks |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 60 | 1,000 | 1,013 | 1,013 | 747 | 769 | 4,154 | 760 | 1,666 | 0 | 0 | 2,322 | 50.1 | 1.67 | 326 | 54,097 | 808 |
| 120 | 1,000 | 1,026 | 1,026 | 2,038 | 2,655 | 6,268 | 2,219 | 2,846 | 7,558 | 197 | 1,421 | 53.4 | 1.21 | 234 | 59,904 | 768 |
| 180 | 1,000 | 822 | 822 | 1,714 | 7,827 | 15,324 | 7,820 | 8,771 | 0 | 13 | 3,192 | 46.0 | 3.16 | 307 | 60,360 | 716 |
| 240 | 1,000 | 779 | 779 | 2,414 | 17,527 | 18,268 | 10,009 | 10,748 | 629 | 209 | 1,350 | 52.3 | 5.01 | 150 | 38,400 | 600 |
| 300 | 1,000 | 752 | 751 | 2,008 | 33,107 | 33,837 | 9,859 | 11,822 | 624 | 507 | 1,775 | 48.8 | 3.63 | 154 | 39,424 | 616 |
| 360 | 1,000 | 607 | 607 | 1,945 | 46,963 | 53,322 | 10,664 | 12,127 | 31 | 472 | 1,720 | 47.8 | 6.15 | 127 | 32,026 | 508 |
| 420 | 1,000 | 629 | 629 | 868 | 60,398 | 62,422 | 10,948 | 12,080 | 0 | 1,042 | 1,695 | 47.8 | 2.23 | 257 | 63,227 | 526 |
| 480 | 1,000 | 802 | 802 | 138 | 70,817 | 72,841 | 11,967 | 12,807 | 0 | 2,009 | 1,041 | 53.9 | 1.35 | 148 | 22,115 | 592 |
| 540 | 1,000 | 773 | 773 | 116 | 71,934 | 74,490 | 11,972 | 12,543 | 0 | 2,257 | 931 | 52.8 | 1.30 | 146 | 12,956 | 584 |
| 600 | 997 | 814 | 814 | 154 | 72,016 | 74,556 | 12,123 | 12,826 | 0 | 1,833 | 853 | 56.5 | 1.30 | 145 | 22,283 | 580 |

Over the ten minutes: 808 finished a second, p50 27.7 s, p99 73 s from the scheduled time, 2.37 commits a landing, 45,222 landings the agents gave up on (each agent's own deadline), 128,450 answers that told an agent to wait.

**Past capacity: 1,500/s offered for 120 s, then 600/s** (`--protected --mix
--people 100 --steps 1500:120,600:60`, on the build before the gate's
early answer; every row of the series):

| t (s) | offered/s | landed/s | finished/s | queue | p50 ms | p99 ms | wait p50 | wait p99 | told to wait | failed | to merges | per batch | commits/landing | pick stmts | pick rows | review asks |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 10 | 1,500 | 1,185 | 1,185 | 152 | 192 | 2,005 | 189 | 1,979 | 0 | 0 | 1,106 | 51.6 | 1.45 | 230 | 21,046 | 920 |
| 20 | 1,500 | 770 | 770 | 89 | 4,028 | 6,758 | 3,994 | 6,637 | 0 | 0 | 986 | 51.7 | 1.24 | 149 | 23,646 | 596 |
| 30 | 1,500 | 1,017 | 1,017 | 1,574 | 9,561 | 10,019 | 9,540 | 10,002 | 36 | 0 | 663 | 48.9 | 1.38 | 207 | 38,887 | 828 |
| 40 | 1,500 | 1,170 | 1,170 | 1,232 | 11,163 | 11,957 | 7,675 | 8,051 | 0 | 0 | 1,091 | 57.6 | 1.28 | 408 | 104,448 | 816 |
| 50 | 1,500 | 1,190 | 1,190 | 2,124 | 13,393 | 14,647 | 8,143 | 8,457 | 15,481 | 0 | 1,199 | 56.6 | 1.44 | 290 | 74,240 | 836 |
| 60 | 1,500 | 1,107 | 1,107 | 2,120 | 13,589 | 22,017 | 1,893 | 4,323 | 43,604 | 0 | 1,187 | 56.2 | 1.36 | 198 | 50,688 | 792 |
| 70 | 1,500 | 1,103 | 1,103 | 1,813 | 17,532 | 32,042 | 2,243 | 4,460 | 15,741 | 74 | 1,111 | 56.0 | 1.30 | 196 | 50,176 | 784 |
| 80 | 1,500 | 1,072 | 1,072 | 2,535 | 20,904 | 35,096 | 8,013 | 8,331 | 15,180 | 145 | 1,606 | 55.2 | 1.45 | 320 | 81,920 | 778 |
| 90 | 1,500 | 829 | 829 | 2,022 | 21,180 | 29,943 | 2,120 | 2,609 | 61,316 | 290 | 1,283 | 52.5 | 1.46 | 314 | 80,384 | 630 |
| 100 | 1,500 | 1,050 | 1,050 | 394 | 29,830 | 40,708 | 2,831 | 7,385 | 16,129 | 214 | 845 | 56.3 | 1.20 | 193 | 49,408 | 746 |
| 110 | 1,500 | 1,065 | 1,065 | 2,189 | 30,992 | 41,606 | 8,002 | 8,781 | 45 | 50 | 2,755 | 41.5 | 2.36 | 262 | 35,977 | 1,026 |
| 120 | 1,498 | 866 | 866 | 1,960 | 33,170 | 37,401 | 8,481 | 8,881 | 24,671 | 335 | 1,347 | 50.5 | 1.97 | 202 | 51,712 | 686 |
| 130 | 600 | 1,049 | 1,049 | 1,985 | 35,385 | 45,685 | 3,590 | 5,433 | 31,064 | 458 | 1,701 | 53.3 | 1.40 | 200 | 51,200 | 790 |
| 140 | 600 | 897 | 892 | 2,092 | 40,360 | 52,491 | 2,910 | 6,871 | 26,993 | 351 | 1,317 | 53.0 | 1.40 | 168 | 43,008 | 672 |
| 150 | 600 | 971 | 976 | 2,097 | 41,430 | 58,438 | 2,011 | 2,998 | 33,147 | 631 | 1,901 | 51.4 | 1.32 | 199 | 50,944 | 760 |
| 160 | 600 | 875 | 875 | 1,923 | 47,781 | 61,761 | 3,649 | 6,443 | 25,970 | 1,013 | 1,993 | 49.4 | 1.80 | 215 | 55,040 | 708 |
| 170 | 600 | 908 | 908 | 1,513 | 51,472 | 63,842 | 5,197 | 8,230 | 760 | 280 | 624 | 57.8 | 1.12 | 168 | 43,008 | 628 |
| 180 | 598 | 809 | 805 | 2,105 | 53,358 | 61,885 | 9,019 | 10,407 | 41 | 108 | 3,127 | 46.0 | 2.69 | 350 | 89,600 | 702 |

The service landed 770 to 1,190/s (1,040 on average) throughout, and
every landing it made was one an agent saw finish (landed = finished);
the accepted request's wait stayed within the queue's 10 s bound (p50 2
to 9 s); commits per landing stayed 1.2 to 1.5 but for two rows of merge
storms (BUG-1956). The queue did not drain in the 60 s at 600/s: the
agents still held some 55,000 landings they had been told to bring back,
which drain at what the service lands beyond 600/s.

**Past capacity and back: 1,500/s for 90 s, then 300/s for 150 s**, with the gate's early answer (HUB §13.32 item 11; `--steps 1500:90,300:150`):

| t (s) | offered/s | landed/s | finished/s | queue | p50 ms | p99 ms | wait p50 | wait p99 | told to wait | failed | to merges | per batch | commits/landing | pick stmts | pick rows | review asks |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 10 | 1,500 | 1,070 | 1,070 | 146 | 367 | 2,707 | 331 | 2,692 | 1,870 | 0 | 727 | 38.5 | 1.44 | 279 | 17,357 | 1,114 |
| 20 | 1,500 | 686 | 686 | 73 | 3,425 | 10,191 | 3,142 | 6,955 | 31,210 | 0 | 506 | 23.8 | 1.19 | 329 | 16,154 | 1,152 |
| 30 | 1,500 | 964 | 964 | 139 | 10,471 | 15,085 | 3,262 | 10,954 | 43,257 | 0 | 598 | 36.1 | 1.29 | 288 | 18,050 | 1,070 |
| 40 | 1,500 | 1,016 | 1,016 | 244 | 13,636 | 20,722 | 5,158 | 9,521 | 46,813 | 0 | 901 | 50.2 | 1.37 | 202 | 16,678 | 808 |
| 50 | 1,500 | 1,187 | 1,187 | 302 | 16,116 | 22,821 | 4,781 | 7,880 | 37,616 | 0 | 1,033 | 56.5 | 1.35 | 210 | 30,830 | 840 |
| 60 | 1,500 | 1,000 | 1,000 | 182 | 18,778 | 26,555 | 5,482 | 9,055 | 45,366 | 0 | 1,180 | 43.1 | 1.43 | 233 | 16,246 | 928 |
| 70 | 1,500 | 952 | 952 | 245 | 22,087 | 33,271 | 5,671 | 9,680 | 49,599 | 85 | 1,109 | 48.7 | 1.40 | 195 | 12,508 | 780 |
| 80 | 1,500 | 1,112 | 1,112 | 351 | 24,795 | 32,755 | 4,052 | 9,725 | 38,404 | 86 | 1,594 | 50.3 | 1.43 | 221 | 23,189 | 884 |
| 90 | 1,497 | 1,000 | 1,000 | 328 | 27,358 | 35,360 | 4,630 | 8,363 | 34,672 | 111 | 1,218 | 54.4 | 1.43 | 184 | 21,342 | 736 |
| 100 | 300 | 1,056 | 1,056 | 338 | 29,976 | 37,336 | 4,377 | 8,805 | 32,981 | 103 | 1,556 | 54.1 | 1.40 | 213 | 46,792 | 780 |
| 110 | 300 | 942 | 942 | 375 | 33,650 | 40,321 | 4,081 | 9,911 | 37,506 | 184 | 1,857 | 50.2 | 1.54 | 187 | 36,157 | 750 |
| 120 | 300 | 880 | 880 | 794 | 38,216 | 45,214 | 6,064 | 10,280 | 43,005 | 298 | 1,791 | 50.6 | 1.62 | 175 | 30,573 | 698 |
| 130 | 300 | 993 | 993 | 531 | 40,911 | 46,864 | 5,009 | 7,891 | 37,275 | 260 | 1,764 | 52.7 | 1.47 | 196 | 47,257 | 752 |
| 140 | 300 | 932 | 932 | 503 | 42,492 | 51,252 | 6,248 | 9,235 | 38,965 | 307 | 2,019 | 50.5 | 1.61 | 200 | 38,997 | 736 |
| 150 | 300 | 906 | 906 | 461 | 22,978 | 46,185 | 6,149 | 9,652 | 22,308 | 636 | 1,907 | 50.3 | 1.64 | 202 | 44,329 | 724 |
| 160 | 300 | 624 | 624 | 507 | 3,689 | 56,077 | 1,370 | 6,265 | 1,786 | 220 | 3,697 | 19.4 | 3.28 | 323 | 19,074 | 1,292 |
| 170 | 300 | 354 | 354 | 6 | 73 | 55,767 | 72 | 3,860 | 0 | 32 | 3,569 | 6.7 | 3.71 | 527 | 8,287 | 2,096 |
| 180 | 300 | 300 | 300 | 1 | 25 | 365 | 25 | 352 | 0 | 0 | 81 | 1.7 | 1.73 | 2,203 | 3,084 | 6,922 |
| 190 | 300 | 300 | 300 | 2 | 26 | 86 | 24 | 79 | 0 | 0 | 316 | 1.5 | 2.10 | 2,436 | 3,310 | 7,740 |
| 200 | 300 | 299 | 299 | 5 | 29 | 424 | 26 | 353 | 0 | 0 | 393 | 1.9 | 3.48 | 1,989 | 3,394 | 6,390 |
| 210 | 300 | 300 | 300 | 2 | 57 | 311 | 54 | 302 | 0 | 0 | 226 | 2.8 | 2.60 | 1,218 | 3,228 | 4,228 |
| 220 | 300 | 300 | 300 | 3 | 37 | 137 | 35 | 123 | 0 | 0 | 137 | 2.2 | 2.89 | 1,646 | 3,142 | 5,576 |
| 230 | 300 | 299 | 299 | 4 | 35 | 483 | 29 | 469 | 0 | 0 | 425 | 2.0 | 3.30 | 1,831 | 3,418 | 6,042 |
| 240 | 300 | 300 | 300 | 1 | 34 | 170 | 29 | 166 | 0 | 0 | 338 | 1.9 | 3.30 | 1,982 | 3,338 | 6,346 |

While 1,500/s were offered the service landed 690 to 1,190/s (1,000 on average) and the agents saw every one of them finish; 31,000 to 50,000 answers per 10 s told an agent to come back (`503 busy` from the gate, `503 queue_full` from the queue); an accepted request waited 3 to 6 s at the median (8 to 9 s before the gate's answer: the same run on the build without it, `N-recover-mix`, had no answer telling anyone to wait until the queue filled at 90 s), at most about 11 s. When the offer fell to 300/s the service went on at capacity until the agents' backlog was landed (at 160 s); from 170 s on p50 was 25 to 73 ms, and from 180 s p99 was under 0.5 s. Commits per landing at 300/s are 1.7 to 3.7: batches of 2 landings, each with its own commit and the deriver's.

The same build at 1,000/s with the mix for three minutes: 951/s finished, p50 1,364 ms, p99 10.8 s, 1.64 commits a landing (935/s, 1,224 ms, 10.8 s and 1.82 without the gate's answer).

**What still misses, and what sets it.**

- **p99 under 1 s at 1,000/s**: 1,156 to 1,216 ms for the plain runs
  (p99 per 10 s under 1 s in most rows), 10.8 s with the mix. The
  service lands about 1,000 to 1,100 a second here, so 1,000 offered is
  at its capacity, and the queue swings. What sets it, per landing on
  this machine: a submit's 35 ms in its project's gate (48 places: about
  1,100/s), mostly waiting for CPU and `fsync` on a machine the load tool
  shares; and the service's 41 ms batch cycle, whose largest steps are
  its build (24 ms, 17 ms of it CPU on one thread: each entry is built on
  the tip the last one made) and its transaction (30 ms). What would move
  it: the load tool on another machine (its 10,000 agents and their TLS
  are most of the system time); objects in S3 rather than `fsync`ed
  files (14 to 15 object writes a landing, 2 `fsync`s each); preparing
  the next batch while this one builds (its reads, 9 ms, and the pick,
  2 ms: not done, since it reads review rules and memos at a tip not yet
  final, which the byte-for-byte check would have to cover); more
  database connections (the gate is ¾ of them).
- **Commits per landing with the mix**: 1.82 over three minutes (gate
  1.5), 2.37 over ten; 1.2 without the mix. The rest is merge workers
  re-merging overlapping changes, more the longer the queue (BUG-1956).
- **Ten minutes**: the rate falls from 1,000 to 650 to 800/s after three
  minutes: the server's CPU per landing rises (9.7 to 12.3 ms), the
  deriver falls 300 s behind and works through what it missed, and the
  merge storms of BUG-1956 take a third of the batches' places. At the
  end the landing queue is short (150) and requests wait 11 to 12 s in
  the project's gate: the submit path, not the service, sets the rate.

## What would raise each ceiling (not built)

| Ceiling | Bound by | What raises it |
|---|---|---|
| Pulls, about 2,500/s here | CPU per pull: 46 statements, mostly per-request permission lookups and per-snapshot resolution | **built (S4):** permission, session and resolution caches; 1 statement per request. Next: fewer requests per pull (S3) |
| Merges across projects, about 2,000/s here | the database's WAL: about 8 commits per landing | **built (S4):** 1 commit for the push; S12's deriver adds about 4 in the background, and holds the pool at 100 projects (BUG-911) |
| One project's `main`, 20–30/s with many agents | collisions: a catch-up pull is longer than the gap between landings | **built (S17):** batched landing, 1,084/s here (above); next: packs (S28), since the object store's synced writes are its limit |
