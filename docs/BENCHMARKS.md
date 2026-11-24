# Veil Benchmarks & Design Trade-offs

Full measured results, misses, methodology, and architectural trade-offs behind the summary charts in the [README](../README.md#measured-at-agent-scale).

Two sets of numbers: a deployment across up to twelve machines on Google Cloud (2026-11-20 and 21, the current code), and one 32-core machine running everything (2026-11-12 and 14, older code). Misses are listed with the passes. The kits in `deploy/` set up the deployment and run the benchmarks ([DEPLOY.md §12](DEPLOY.md#12-google-cloud-deploygcp)); the two nights' runs cost about $39. The run log is [DEPLOY.md §12.11](DEPLOY.md#1211-the-runs-on-google-cloud-2026-11-20-and-21).

---

## Across machines (Google Cloud, 2026-11-20 and 21)

**The deployment** (every machine a Spot VM, one zone, `us-central1-a`):
- 3 Veil servers (`e2-standard-32`) behind one HAProxy balancer (`e2-standard-8`);
- the database, one of:
  - PostgreSQL 17 on **one `c2d-standard-56`** (56 vCPUs);
  - YugabyteDB 2025.2 on **3 or 6 `c2d-standard-8` nodes** (8 vCPUs each), with the **hash layout** (every table split across the nodes, one repository included), or the colocated layout as a baseline;
- a 500 GB `pd-ssd` disk for each database machine;
- MinIO for the file contents (`c2d-standard-16` with a local NVMe SSD);
- one load machine (`n2d-standard-16`).

The server build was `8efc94ab`. Some PostgreSQL rows were measured the night before on `da8ab108`, which differs only in the landing service: pulls, `land`, the API, branches, and PostgreSQL's columns in the many-projects and one-busy-repository tables. File contents are stored one object per file version, and nothing is deleted (append-only storage, the only layout in this version).

**Core counts differ.** PostgreSQL had 56 vCPUs; YugabyteDB had 24 or 48. The YugabyteDB nodes were kept small to fit the cloud project's CPU quota, and because the point of a distributed database is to grow by adding cheap machines.

### YugabyteDB: adding nodes

**One busy repository:** 300 agents, each pushing to a branch of its own in one project, as fast as it is answered, with some merges onto `main`:

| | YugabyteDB 3 nodes, colocated | YugabyteDB 3 nodes, hash | YugabyteDB 6 nodes, hash | PostgreSQL, one machine |
|---|---|---|---|---|
| Pushes a second | 19.9 | 30.3 | **48.9** | 392 |
| p50 (a push) | 13.5 s | 8.7 s | 5.2 s | 0.76 s |
| Merges onto `main` a second | 1.7 | 4.0 | **6.8** | 28.1 |
| Busiest database node's share of the work | **79 %** | 33 % | 17 % | (one machine) |
| Errors | 0 | 0 | 0 | 0 |

- **From 3 to 6 nodes: 1.62× the pushes (`30.3 → 48.9/s`) and 1.70× the merges onto `main` (`4.0 → 6.8/s`; 1.63× pushes in the merge curve, `25.9 → 42.3/s`).** The target is 1.6×, so this **passes**.
- **The hash layout spreads one repository over every node.** Colocated puts it on one node, which did 79 % of the work while the others idled; adding nodes can't help that layout.

**Agents at a coding agent's pace.** Each agent:
- thinks 2 minutes between steps on average;
- pushes to its own branch;
- forks 3 subagents on branches off its own, which push 3 times each and are merged into it;
- lands its branch on `main`.

The thinking is compressed 20 times, so 1,000 agents put the load of about 20,000 agents at the real pace on the servers.

| 1,000 agents (about 20,000 at the real pace) | YugabyteDB 3 nodes | **YugabyteDB 6 nodes** | PostgreSQL, one machine |
|---|---|---|---|
| Pushes to their own branch, a second (p50) | 70 (4.0 s) | **162 (0.25 s)** | 163 (0.10 s) |
| Subagent merges into their agent's branch | 5.9 a second | **16.0** | 16.3 |
| Branches landed on `main` | 2.4 a second | **5.2** | 3.8 |
| Pulls and workspace starts (p50) | 10 a second (2.1 s) | **23 (0.13 s)** | 23 (19 ms) |
| Errors, all operations | 42 | **0** | 118 |

| 3,000 agents (about 60,000; past every setup's capacity) | YugabyteDB 3 nodes | YugabyteDB 6 nodes | PostgreSQL, one machine |
|---|---|---|---|
| Pushes a second | 64 | **138** | 130 |
| Subagent merges a second | 2.5 | **9.0** | 8.3 |
| Branches landed on `main` a second | 2.9 | **4.6** | 3.1 |
| Errors, all operations | 3,729 | **231** | 959 |

- **From 3 to 6 nodes, every operation at 1,000 agents did 2.2 to 2.7 times as much,** and the waits fell from seconds to a fraction of a second.
- **Six 8-vCPU nodes keep up with one 56-vCPU PostgreSQL machine.** Per-request waits are longer, but they land more often on `main`, and past capacity they carry more with fewer errors.

**Many projects at once** (60 projects; 300 agents, 120 for the last two rows):

| | PostgreSQL | YugabyteDB 3, colocated | YugabyteDB 3, hash | YugabyteDB 6, hash | 3 → 6 nodes |
|---|---|---|---|---|---|
| Pushes to branches a second | 333 | 336 | 250 | 318 | 1.27× |
| Landings (the landing service) a second | 243 | 148 | 141 | 211 | 1.50× |
| Pulls a second | 11,244 | 10,855 | 11,068 | 11,828 | 1.07× |
| API commits a second | 259 | 236 | 247 | 291 | 1.18× |
| `land` straight onto `main` a second | 234 | 17 | 28 | 44 | 1.58× |

- **Miss: the 3 → 6 target of 1.6× in every row.** 0 errors anywhere.
- **The likely reason, not yet proven, is the benchmark's fixed load.** It keeps the same 300 agents, each waiting for its answer. On 6 nodes the database ran at about half its CPU (a median of 3.5 to 4.7 of 8 cores a node), and the writes' waits fell 16 to 36 % instead of the work doubling. A run that adds agents until 6 nodes are full has not been done.
- **On 3 nodes, colocated is faster for plain pushes** (336 against 250 a second). It keeps a write on one node, while the hash layout pays for transactions across nodes. It can't grow past that node.

**What YugabyteDB costs.** Below its limit, a push uses 6 to 10 times the database CPU it uses on PostgreSQL. Measured on the development machine, that is 32 to 53 ms against 4 to 5 ms: about 195 calls between nodes, 93 replicated writes and 3 distributed transactions a push. When the nodes' CPUs are full, retries pile up and it collapses: 3 nodes took about 800 ms of database CPU a push for one busy repository. The fix is to tell agents to come back before the database is full, as Veil already does elsewhere; it is not built yet.

### PostgreSQL deployment

**Reads** (0 errors in every row):

| Agents | 10 | 100 | 1,000 |
|---|---|---|---|
| Pulls a second, PostgreSQL (p50) | 279 (45 ms) | 1,509 (66 ms) | 1,424 (716 ms) |
| The same on YugabyteDB, 3 nodes, hash | **1,644 (2.8 ms)** | **5,478 (7.6 ms)** | 1,425 (712 ms) |

- **Miss, cause not yet found:** with the same code, PostgreSQL's pulls at 10 and 100 agents were 3.6 to 6 times slower than YugabyteDB's. It lies in the PostgreSQL deployment, not in the permission checks.
- **At 1,000 agents both stop at the same rate,** limited by something they share (the load machine, the servers or MinIO).

**Commits** (0 errors in every row):

| | 10 projects | 100 projects |
|---|---|---|
| `land`: a push straight onto each project's `main`, a second | 181 | 372 |
| API commits a second | 249 | 470 |

**Agents on branches of their own in one project** (as fast as they are answered; with merges onto `main` in the second table):

| Agents | 1 | 10 | 100 |
|---|---|---|---|
| Pushes a second, PostgreSQL | 21 | 189 | **435** |
| The same, YugabyteDB 3 nodes, hash | 18 | 132 | 302 |

| Agents | 300 | 1,000 | 3,000 |
|---|---|---|---|
| Merges onto `main` a second, PostgreSQL | **31.3**, 0 errors | 25.5, 1,014 errors | **1.1, 8,823 errors** |
| The same, YugabyteDB 3 nodes, hash | 9.4, 0 errors | 14.4, 0 errors | 16.3, 2,160 errors |

- **Miss: PostgreSQL collapses at 3,000 agents** on one repository.

**One busy repository, against GitHub's figure of 7,200 pushes a second** (their internal test of 5,000 agents on one repository; each agent pushes to a branch of its own):

| Agents | Pushes a second | Of 7,200 | p50 / p99 | Errors |
|---|---|---|---|---|
| 1,000 | 393 | 5.5 % | 2.6 s / 3.1 s | 0 |
| 5,000 | 367 | 5.1 % | 12 s / 32 s | 0 (689,410 told to come back) |

- **Miss:** 5 % of the figure.
- **The limit is not yet known.** Neither the servers (5 to 7 of their 96 cores) nor the database (2 to 3 cores) was busy. The most likely limit is a push's chain of round trips (tips, upload, push) and its writes to MinIO, which were not measured in this run.

**Landing on one `main` past its capacity** (10,000 agents offering 1,000 a second):

| | 3 minutes | 10 minutes | The night before (`da8ab108`) |
|---|---|---|---|
| Plain | **207** a second | 198 | 169 and 171 |
| Protected `main` (review rules) | 185 | 175 | 182 and 183 |
| Protected, with 3 % overlapping and 2 % conflicting changes | 182 | 181 | 181 and 175 |

- **Waits:** the p50 is about 62 s, because the offered load is five times what one `main` lands. The rest are told to come back, or time out.
- **Change:** `8efc94ab` reads storage in parallel; it gained 16 to 22 % on plain landing. Each batch now waits about 150 ms for MinIO to store its objects.
- **YugabyteDB 3 nodes, hash:** 142 to 149 a second in the three 3-minute runs that finished. The run as a whole was voided when a Spot machine was reclaimed.

**Server count** (1, 2 and 3 servers; 1,000 agents; 0 errors):

| | 1 server | 2 servers | 3 servers |
|---|---|---|---|
| Pulls a second | 1,451 | 1,417 (0.98×) | 1,445 (1.00×) |
| Pushes to branches a second | 371 | 400 (1.08×) | 404 (1.09×) |
| Landings a second, 100 projects | 254 | 242 (0.95×) | **161 (0.63×)** |

- **Miss:** adding servers doesn't help here. They share one database and one MinIO, which set the pace.
- **The drop on 3 servers is not explained yet.**

**Failover: passed every integrity check.** The server holding `main`'s landing lease was stopped in the middle of a landing load:
- 10,473 changes landed, each exactly once on `main`.
- None was lost or landed twice.
- No agent was told "landed" for a change that isn't on `main`.
- Another server took the lease, and the first landing after the stop came **1.6 s** later.
- **Miss:** the longest pause in landings after the stop was 2.46 s, against a target of 2 s. In the 30 s before the stop, the longest was 4.05 s.

**Per day, beside Anthropic's reported load.** Anthropic's post on Scion ([Redesigning source control](https://www.anthropic.com/research/redesigning-source-control)) reports the load Scion **carries**: over 30,000 merges a day as of September 2026, and about 25 million CI checkouts a day. These are Anthropic's daily usage, **not Scion's maximum capacity**, which the post does not give. The figures below are Veil's measured rates held for a day:

| Veil, measured | A second | A day | Anthropic's reported load |
|---|---|---|---|
| Merges onto one `main`, agents on branches, PostgreSQL (300 agents, 0 errors) | 31.3 | **2.7 million** | over 30,000 merges a day |
| The same on YugabyteDB, 6 nodes, hash (one-repository run, 300 agents, 0 errors) | 6.8 | 590,000 | |
| Branches landed on `main` at a coding agent's pace, YugabyteDB 6 nodes (1,000 agents, about 20,000 at the real pace, 0 errors) | 5.2 | 450,000 | |
| Subagent merges into their agents' branches (same run) | 16.0 | 1.4 million | (Scion has few branches) |
| `land` across 100 projects, PostgreSQL | 372 | 32 million | |
| Landings on one `main` past capacity, PostgreSQL | 207 | 18 million | |
| Pulls (100 agents), YugabyteDB 3 nodes | 5,478 | 470 million | about 25 million CI checkouts a day |

**These figures don't say Veil out-scales Scion:**
- **Usage against capacity:** Anthropic's numbers are what Scion carries, not its ceiling.
- **Repository size:** Veil's runs used small synthetic projects. Anthropic's monorepo has almost 100 GB of history and a working copy over 25 GB.
- **Kind of work:** a Veil pull fetches a few objects, where a CI checkout is a whole workspace, and real merges are larger than the benchmark's changes.
- **Holding the rate:** each rate was held for 3 to 10 minutes, not a day.

What they show: on modest machines, Veil's design handles the merge rate that one of the busiest agent-driven repositories reported, with room to spare.

**What went wrong during the runs:**
- **Spot reclaims:** Google reclaimed Spot machines four times (the balancer three times, the database once). Each run they hit was rerun or voided.
- **MinIO's disk:** an earlier attempt filled MinIO's file system's inodes while 70 % of its space was free (BUG-2941, fixed in the kit). Those results were discarded.

**What the cloud runs did not show:**
- a project far bigger than 1 GB;
- more than one zone or region;
- YugabyteDB on nodes as large as PostgreSQL's;
- a load that grows until 6 YugabyteDB nodes are full.

The earlier runs on older code (Google Cloud, 2026-11-14 and 15, with a 1 GB project and a comparison with Git on a cloud machine) are in [DEPLOY.md §12.9](DEPLOY.md#129-the-runs-on-google-cloud-2026-11-14-and-15). They came before the added permission checks and append-only storage, so they are not comparable.

---

## On one machine (older code, 2026-11-12 and 14)

Landings measured on 2026-11-14 (`1e141f0b`), the comparison with Git on 2026-11-12: **older code**, before append-only storage and the added permission checks, and not measured again since. One 32-core machine also ran the load generator, PostgreSQL (with the deployment's settings) and the object store (a local directory). The load tool, the server and the database share 32 cores and 30 GB of memory, which runs short about 100 s into a 10,000-agent run (BUG-2363). The full tables, commands and misses are in [LOAD.md](design/scale/LOAD.md) (landings) and [OPENSCION.md](design/scale/OPENSCION.md) (beside Git).

**Landing changes on one `main`** (10,000 agents offering 1,000 a second, three minutes unless noted; target: 1,000/s held, p99 < 1 s, p50 < 150 ms):

| | Landed a second | p50 / p99 | Note |
|---|---|---|---|
| Agents of 100 people | **995** | 236 ms / 1.35 s | 1.09 database commits a landing; nothing failed. For comparison: 20 to 30 a second with pull, rebase, push and retry. |
| Protected `main` | **995** | 286 ms / 1.39 s | 1.08 commits a landing |
| All agents one person's | **997** | 652 ms / 6.15 s | 1.10 commits a landing; from 100 to 140 s, 45,270 answers told agents to come back (BUG-1955) |
| Protected `main`, 3 % overlapping and 2 % conflicting changes | **977 and 970** (two runs) | 447 ms / 4.3 s and 515 ms / 6.4 s | p99 **misses**; the queue reaches its bound about 150 s in, and 26 and 155 landings were given up |
| The same, ten minutes | 917 | 6.0 s / 50 s | **Misses**: 691 to 1,043 a second per 10 s; 8,804 landings given up (BUG-1955) |
| Offered 1.5 times what it can land for 90 s, then 300 a second | 1,089 on average while overloaded | p50 22 to 76 ms and p99 under 0.7 s once the backlog is gone (two 10 s stretches at 1.3 and 1.5 s) | Agents past capacity are told at once to come back; the backlog clears 60 s after the load drops |

**Many agents, each on its own branch**, pushing in a closed loop and landing the branch on `main` every 5th push (as many as they can; one person's agents):

| Agents, run | Pushes a second | Branches landed on `main` a second | p50 / p99 (a push) | Note |
|---|---|---|---|---|
| 300, three minutes | **382** | **76.6** | 737 ms / 1.64 s | **p99 misses 1 s**; 39 ms of server CPU a push; 1.00 database commit a push of its own; nothing told to come back |
| 1,000, three minutes | **266** | **53.7** | 3.9 s / 5.9 s | **p99 misses 1 s**; 4,166 requests told to come back, each waited out; none failed |
| 300, ten minutes | **251** | **50.4** | 1.07 s / 3.6 s | **p99 misses 1 s**; holds over ten minutes; 6.1 storage reads a push, 99.8 % object cache hits |

What still misses: p99 under 1 s at 1,000 landings a second (1.35 to 6.2 s), p50 under 150 ms (236 to 652 ms), the mix's p99, the mix at 1,000 a second for ten minutes (917), and p99 under 1 s in the many-branch shape (1.6 to 5.9 s). With the mix the batch bounds it: each batch's commit waits for its objects' `fsync`s on this machine's disk. The many-branch runs now pass the benchmark's cost gate of one database commit a push (BUG-2350, fixed).

**Beside Git**, on the same files (medians of 5 to 9):

| | Veil | Git |
|---|---|---|
| Import a 10,000-file folder | **282 to 326 ms** | 811 ms |
| Import a 1 GB project (35,000 files) | **4.2 s** | 10.9 s |
| Clone 1,000 files through the server | **159 to 163 ms** | 206 to 233 ms |
| Clone 10,000 files through the server | 566 to 621 ms | 569 to 573 ms |
| Commit one changed file among 10,000 | 9.2 to 10.0 ms | **8.1 to 8.6 ms** |
| Commit one changed file in the 1 GB project (watcher on) | **22 to 26 ms** | 26 to 28 ms (33 to 35 with `core.fsync=all`) |
| `status` in the 1 GB project (watcher on; 62.5–68.1 ms with daemon stopped) | **5.7 to 5.8 ms** | 30 to 33 ms |
| `log -n 20` in the 1 GB project (watcher on) | 8.0 to 8.2 ms | **1.5 to 2.4 ms** |
| Clone one folder of the 1 GB project (1,317 files) | **354 to 386 ms** | 401 to 414 ms |
| Default clone of the 1 GB project (Veil thin default vs. Git full default) | **9.4 s** | 29 s |

**Other gates:** blame over 10,000 versions answers in 425 to 528 ms the first time and 25 ms (p99) after; listing, searching, opening and updating among 100,000 pull requests take 6 to 22 ms (median); a workspace of 200,000 files starts in under 300 ms.

**Against OpenScion's targets.** Veil's speed gates are the four workloads published by OpenScion, an independent open implementation of the Scion design ([OVERVIEW.md](OVERVIEW.md)). OpenScion measures in one process, in memory: no disk, no `fsync`, no process start.

Measured the same way (`veil-bench openscion-memory`), Veil meets three of the four targets:

| Workload | 1,000 files: target, Veil | 10,000 files: target, Veil |
|---|---|---|
| Import a folder | 22 ms, **8.8 ms** | 245 ms, **86 ms** |
| Clone everything | 51 ms, **32 ms** | 544 ms, **303 ms** |
| Commit one file | 2.5 ms, **0.9 ms** | 22 ms, **7.4 ms** |

The fourth, cloning one folder, fetches from a server and has no in-memory form. As real `vl` commands on a real disk through a server, most of the targets are missed. That is why each gate also compares Veil with Git on the same machine (the tables above).

---

## Design trade-offs

Veil gives up some things on purpose. What each choice costs, and what it buys:

**Sharing goes through the server.**
- *Works offline:* editing, `vl status`, committing, splitting, squashing, `vl undo` and `vl redo`, and secret scanning. Local commits wait until you reconnect.
- *Costs:* sharing (push, pull, `vl land`, pull requests), cloning, files a thin clone hasn't fetched yet, and history, blame and search across the whole project need the server. Unlike Git, a clone isn't a full standalone copy.
- *Buys:* the server enforces every permission in every answer, does merges, history, blame and search for thin clients, and lands changes without anyone pulling or retrying.

**Durable commits.**
- *Costs:* Veil's commit `fsync`s its objects and its operation; Git's commit by default does not. That is most of why Git commits one file faster (about 8 against 9 to 15 ms).
- *Buys:* a commit that has returned survives a crash. Veil won't trade that for speed.

**Conflicts are checked before a change lands.**
- *Costs:* some database work on every landing.
- *Buys:* `main` never holds a conflict. A change that conflicts goes back to its agent, as data to resolve, never as markers in the tree. Scion lands first and has Claude fix conflicts afterwards.
- *Tests still run after landing:* `main@tested` and automatic bisect-and-revert follow the same land-first, test-after idea.
- *Measured:* at agent scale conflicts were rare (0.00 to 0.02 collisions a landing), and the check was not the bottleneck.

**Many branches.**
- *Costs:* more rows written per push.
- *Buys:* every agent and subagent has its own branch, which is how agents work. Scion discourages branches other than `main` and releases.
- *Fixed since the first cloud run:* the branch-tips answer no longer grows with the number of branches (BUG-2445), and a branch merged into another is deleted with the merge, so subagent branches don't pile up (BUG-2446).

**Permissions on every answer.**
- *Costs:* a permission lookup in each request (cached).
- *Buys:* nobody receives a file, a log line, a search hit or a diff from a folder they can't see.

**Metadata in a database, contents in object storage, nothing deleted.**
- *What goes where:* PostgreSQL or YugabyteDB hold branches, the history graph, indexes, permissions, the landing queue and pull requests. File contents go to S3-compatible storage, one object per file version, as Scion does.
- *Append-only:* this version never deletes stored history: no garbage collection and no background merging of objects.
- *Buys:* the database stays a small fraction of the repository's size, and no cleanup can race a writer.
- *Costs:* more storage and more storage requests than packing files together would need.

**PostgreSQL or YugabyteDB.**
- *PostgreSQL:* the most work for each core. One machine does a push with 6 to 10 times less database CPU, and it is the right choice for most teams, with a standby copy. It can't grow past one machine's writes.
- *YugabyteDB:* keeps working when a machine or a zone fails, and grows by adding machines. With the hash layout, one repository spreads over every node. 6 small nodes did 1.6 times the work of 3 on one busy repository, and matched one large PostgreSQL machine on the realistic-agents run.
- *Costs:* YugabyteDB needs more machines for the same load, and it collapses when its CPUs are full (above).

**Only secrets are encrypted.**
- *Costs:* the server can read the code, as GitHub can.
- *Buys:* the server can merge, index, search and blame it. Secret files (`.env`, keys) are encrypted on the client and follow the same permissions.

**One `main` row per project.**
- *Costs:* moving `main` is one compare-and-swap on one database row, done one at a time, as in Scion. No database removes that limit.
- *Buys:* Veil's landing service batches many changes into each move. Pushing straight onto one `main` without it fell to 8 a second with 50 agents racing; the landing service held 995 a second on one machine (older code, above), and about 200 a second on the cloud deployment above, where each batch waits for MinIO.
