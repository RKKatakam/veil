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
every database connection (BUG-911). Across 1 and 10 projects: LANDING_AB.

**Notices.** PostgreSQL delivers the push's `NOTIFY`: another server saw a
push 5–15 ms later in the tests. YugabyteDB 2025.2 does not by default, and
the server falls back to the 100 ms expiry.

## What would raise each ceiling (not built)

| Ceiling | Bound by | What raises it |
|---|---|---|
| Pulls, about 2,500/s here | CPU per pull: 46 statements, mostly per-request permission lookups and per-snapshot resolution | **built (S4):** permission, session and resolution caches; 1 statement per request. Next: fewer requests per pull (S3) |
| Merges across projects, about 2,000/s here | the database's WAL: about 8 commits per landing | **built (S4):** 1 commit for the push; S12's deriver adds about 4 in the background, and holds the pool at 100 projects (BUG-911) |
| One project's `main`, 20–30/s with many agents | collisions: a catch-up pull is longer than the gap between landings | batched landing (phase 4); cheaper catch-up pulls |
