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
| An agent runs on your machine with your SSH keys in reach | **Sandboxes, on Linux only** (bubblewrap): its own files, home folder, processes and ports; limits on memory, CPU and time. **On macOS there is no sandbox yet:** commands run with your user's full access. A secret's value copied into another file is refused, not recorded, on both. |
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
   --agent "claude-code" --task "TASK-812" -- my-agent "fix the login bug"   # sandboxed on Linux only
vl attempt drop fix-login@ --reason "locking order deadlocks"   # a dead end, kept with its reason
vl land fix-login@                  # the server puts it on main: no pull, no retry
```

On macOS, leave out `--private-ports` and `--memory`: the sandbox and its
limits are Linux-only for now, and `vl` refuses them there. Without them the
command runs **unconfined**, with everything your user can read and change.

Also built in: pull requests with risk-based approval rules, embargoes for
security fixes (hidden until a deadline), secrets encrypted automatically
(`.env`, keys), thin clones, a web client with passkey sign-in, and history,
blame and search answered by the server in milliseconds.

## Measured

Two sets of numbers: a deployment across up to twelve machines on Google
Cloud (2026-11-20 and 21, the current code), and one 32-core machine
running everything (2026-11-12 and 14, older code). Misses are listed with
the passes. The kits in `deploy/` set up the deployment and run the
benchmarks ([DEPLOY.md §12](docs/DEPLOY.md#12-google-cloud-deploygcp));
the two nights' runs cost about $39. The run log is
[DEPLOY.md §12.11](docs/DEPLOY.md#1211-the-runs-on-google-cloud-2026-11-20-and-21).

### Across machines (Google Cloud, 2026-11-20 and 21)

**The deployment** (every machine a Spot VM, one zone, us-central1-a):
- 3 Veil servers (e2-standard-32) behind one HAProxy balancer (e2-standard-8);
- the database, one of:
  - PostgreSQL 17 on **one c2d-standard-56** (56 vCPUs);
  - YugabyteDB 2025.2 on **3 or 6 c2d-standard-8 nodes** (8 vCPUs each), with the **hash layout** (every table split across the nodes, one repository included), or the colocated layout as a baseline;
- a 500 GB pd-ssd disk for each database machine;
- MinIO for the file contents (c2d-standard-16 with a local NVMe SSD);
- one load machine (n2d-standard-16).

The server build was `8efc94ab`. Some PostgreSQL rows were measured the
night before on `da8ab108`, which differs only in the landing service:
pulls, `land`, the API, branches, and PostgreSQL's columns in the
many-projects and one-busy-repository tables. File
contents are stored one object per file version, and nothing is deleted
(append-only storage, the only layout in this version).

**Core counts differ.** PostgreSQL had 56 vCPUs; YugabyteDB had 24 or 48.
The YugabyteDB nodes were kept small to fit the cloud project's CPU quota,
and because the point of a distributed database is to grow by adding cheap
machines.

#### YugabyteDB: adding nodes

**One busy repository:** 300 agents, each pushing to a branch of its own
in one project, as fast as it is answered, with some merges onto `main`:

| | YugabyteDB 3 nodes, colocated | YugabyteDB 3 nodes, hash | YugabyteDB 6 nodes, hash | PostgreSQL, one machine |
|---|---|---|---|---|
| Pushes a second | 19.9 | 30.3 | **48.9** | 392 |
| p50 (a push) | 13.5 s | 8.7 s | 5.2 s | 0.76 s |
| Merges onto `main` a second | 1.7 | 4.0 | **6.8** | 28.1 |
| Busiest database node's share of the work | **79 %** | 33 % | 17 % | (one machine) |
| Errors | 0 | 0 | 0 | 0 |

- **From 3 to 6 nodes: 1.62× the pushes and 1.63× the merges.** The target is 1.6×, so this **passes**.
- **The hash layout spreads one repository over every node.** Colocated puts it on one node, which did 79 % of the work while the others idled; adding nodes can't help that layout.

**Agents at a coding agent's pace.** Each agent:
- thinks 2 minutes between steps on average;
- pushes to its own branch;
- forks 3 subagents on branches off its own, which push 3 times each and are merged into it;
- lands its branch on `main`.

The thinking is compressed 20 times, so 1,000 agents put the load of about
20,000 agents at the real pace on the servers.

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

**What YugabyteDB costs.** Below its limit, a push uses 6 to 10 times the
database CPU it uses on PostgreSQL. Measured on the development machine,
that is 32 to 53 ms against 4 to 5 ms: about 195 calls between nodes, 93
replicated writes and 3 distributed transactions a push. When the nodes'
CPUs are full, retries pile up and it collapses: 3 nodes took about 800 ms
of database CPU a push for one busy repository. The fix is to tell agents
to come back before the database is full, as Veil already does elsewhere;
it is not built yet.

#### PostgreSQL deployment

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

**Agents on branches of their own in one project** (as fast as they are
answered; with merges onto `main` in the second table):

| Agents | 1 | 10 | 100 |
|---|---|---|---|
| Pushes a second, PostgreSQL | 21 | 189 | **435** |
| The same, YugabyteDB 3 nodes, hash | 18 | 132 | 302 |

| Agents | 300 | 1,000 | 3,000 |
|---|---|---|---|
| Merges onto `main` a second, PostgreSQL | **31.3**, 0 errors | 25.5, 1,014 errors | **1.1, 8,823 errors** |
| The same, YugabyteDB 3 nodes, hash | 9.4, 0 errors | 14.4, 0 errors | 16.3, 2,160 errors |

- **Miss: PostgreSQL collapses at 3,000 agents** on one repository.

**One busy repository, against GitHub's figure of 7,200 pushes a second**
(their internal test of 5,000 agents on one repository; each agent pushes
to a branch of its own):

| Agents | Pushes a second | Of 7,200 | p50 / p99 | Errors |
|---|---|---|---|---|
| 1,000 | 393 | 5.5 % | 2.6 s / 3.1 s | 0 |
| 5,000 | 367 | 5.1 % | 12 s / 32 s | 0 (689,410 told to come back) |

- **Miss:** 5 % of the figure.
- **The limit is not yet known.** Neither the servers (5 to 7 of their 96 cores) nor the database (2 to 3 cores) was busy. The most likely limit is a push's chain of round trips (tips, upload, push) and its writes to MinIO, which were not measured in this run.

**Landing on one `main` past its capacity** (10,000 agents offering 1,000
a second):

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

**Failover: passed every integrity check.** The server holding `main`'s
landing lease was stopped in the middle of a landing load:
- 10,473 changes landed, each exactly once on `main`.
- None was lost or landed twice.
- No agent was told "landed" for a change that isn't on `main`.
- Another server took the lease, and the first landing after the stop came **1.6 s** later.
- **Miss:** the longest pause in landings after the stop was 2.46 s, against a target of 2 s. In the 30 s before the stop, the longest was 4.05 s.

**Per day, beside Anthropic's reported load.** Anthropic's post on Scion
([Redesigning source control](https://www.anthropic.com/research/redesigning-source-control))
reports the load Scion **carries**: over 30,000 merges a day as of
September 2026, and about 25 million CI checkouts a day. These are
Anthropic's daily usage, **not Scion's maximum capacity**, which the post
does not give. The figures below are Veil's measured rates held for a day:

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

What they show: on modest machines, Veil's design handles the merge rate
that one of the busiest agent-driven repositories reported, with room to
spare.

**What went wrong during the runs:**
- **Spot reclaims:** Google reclaimed Spot machines four times (the balancer three times, the database once). Each run they hit was rerun or voided.
- **MinIO's disk:** an earlier attempt filled MinIO's file system's inodes while 70 % of its space was free (BUG-2941, fixed in the kit). Those results were discarded.

**What the cloud runs did not show:**
- a project far bigger than 1 GB;
- more than one zone or region;
- YugabyteDB on nodes as large as PostgreSQL's;
- a load that grows until 6 YugabyteDB nodes are full.

The earlier runs on older code (Google Cloud, 2026-11-14 and 15, with a
1 GB project and a comparison with Git on a cloud machine) are in
[DEPLOY.md §12.9](docs/DEPLOY.md#129-the-runs-on-google-cloud-2026-11-14-and-15).
They came before the added permission checks and append-only storage, so
they are not comparable.

### On one machine

Landings measured on 2026-11-14 (`1e141f0b`), the comparison with Git on
2026-11-12: **older code**, before append-only storage and the added
permission checks, and not measured again since. One 32-core machine also ran the load generator, PostgreSQL
(with the deployment's settings) and the object store (a local directory).
The load tool, the server and the database share 32 cores and 30 GB of
memory, which runs short about 100 s into a 10,000-agent run (BUG-2363).
The full tables, commands and misses are in
[LOAD.md](docs/design/scale/LOAD.md) (landings) and
[OPENSCION.md](docs/design/scale/OPENSCION.md) (beside Git).

**Landing changes on one `main`** (10,000 agents offering 1,000 a second,
three minutes unless noted; the target is 1,000 a second held, p99 under
1 s, p50 under 150 ms):

| | Landed a second | p50 / p99 | Note |
|---|---|---|---|
| Agents of 100 people | **995** | 236 ms / 1.35 s | 1.09 database commits a landing; nothing failed. For comparison: 20 to 30 a second with pull, rebase, push and retry. |
| Protected `main` | **995** | 286 ms / 1.39 s | 1.08 commits a landing |
| All agents one person's | **997** | 652 ms / 6.15 s | 1.10 commits a landing; from 100 to 140 s, 45,270 answers told agents to come back (BUG-1955) |
| Protected `main`, 3 % overlapping and 2 % conflicting changes | **977 and 970** (two runs) | 447 ms / 4.3 s and 515 ms / 6.4 s | p99 **misses**; the queue reaches its bound about 150 s in, and 26 and 155 landings were given up |
| The same, ten minutes | 917 | 6.0 s / 50 s | **Misses**: 691 to 1,043 a second per 10 s; 8,804 landings given up (BUG-1955) |
| Offered 1.5 times what it can land for 90 s, then 300 a second | 1,089 on average while overloaded | p50 22 to 76 ms and p99 under 0.7 s once the backlog is gone (two 10 s stretches at 1.3 and 1.5 s) | Agents past capacity are told at once to come back; the backlog clears 60 s after the load drops |

**Many agents, each on its own branch**, pushing in a closed loop and
landing the branch on `main` every 5th push (as many as they can; one
person's agents):

| Agents, run | Pushes a second | Branches landed on `main` a second | p50 / p99 (a push) | Note |
|---|---|---|---|---|
| 300, three minutes | **382** | **76.6** | 737 ms / 1.64 s | **p99 misses 1 s**; 39 ms of server CPU a push; 1.00 database commit a push of its own; nothing told to come back |
| 1,000, three minutes | **266** | **53.7** | 3.9 s / 5.9 s | **p99 misses 1 s**; 4,166 requests told to come back, each waited out; none failed |
| 300, ten minutes | **251** | **50.4** | 1.07 s / 3.6 s | **p99 misses 1 s**; holds over ten minutes; 6.1 storage reads a push, 99.8 % object cache hits |

What still misses: p99 under 1 s at 1,000 landings a second (1.35 to
6.2 s), p50 under 150 ms (236 to 652 ms), the mix's p99, the mix at 1,000
a second for ten minutes (917), and p99 under 1 s in the many-branch shape
(1.6 to 5.9 s). With the mix the batch bounds it: each batch's commit
waits for its objects' `fsync`s on this machine's disk. The many-branch
runs now pass the benchmark's cost gate of one database commit a push
(BUG-2350, fixed).

**Beside Git**, on the same files (medians of 5 to 9):

| | Veil | Git |
|---|---|---|
| Import a 10,000-file folder | **282 to 326 ms** | 811 ms |
| Import a 1 GB project (35,000 files) | **4.2 s** | 10.9 s |
| Clone 1,000 files through the server | **159 to 163 ms** | 206 to 233 ms |
| Clone 10,000 files through the server | 566 to 621 ms | 569 to 573 ms |
| Commit one changed file among 10,000 | 9.2 to 10.0 ms | **8.1 to 8.6 ms** |
| Commit one changed file in the 1 GB project | **22 to 26 ms** | 26 to 28 ms (33 to 35 with `core.fsync=all`) |
| `status` in the 1 GB project | **5.7 to 5.8 ms** | 30 to 33 ms |
| `log -n 20` in the 1 GB project | 8.0 to 8.2 ms | **1.5 to 2.4 ms** |
| Clone one folder of the 1 GB project (1,317 files) | **354 to 386 ms** | 401 to 414 ms |
| Default clone of the 1 GB project | **9.4 s** | 29 s |

**Other gates:** blame over 10,000 versions answers in 425 to 528 ms the
first time and 25 ms (p99) after; listing, searching, opening and updating
among 100,000 pull requests take 6 to 22 ms (median); a workspace of
200,000 files starts in under 300 ms.

**Against OpenScion's targets.** Veil's speed gates are the four workloads
published by OpenScion, an independent open implementation of the Scion
design ([OVERVIEW.md](docs/OVERVIEW.md)). OpenScion measures in one
process, in memory: no disk, no `fsync`, no process start.

Measured the same way (`veil-bench openscion-memory`), Veil meets three of
the four targets:

| Workload | 1,000 files: target, Veil | 10,000 files: target, Veil |
|---|---|---|
| Import a folder | 22 ms, **8.8 ms** | 245 ms, **86 ms** |
| Clone everything | 51 ms, **32 ms** | 544 ms, **303 ms** |
| Commit one file | 2.5 ms, **0.9 ms** | 22 ms, **7.4 ms** |

The fourth, cloning one folder, fetches from a server and has no in-memory
form. As real `vl` commands on a real disk through a server, most of the
targets are missed. That is why each gate also compares Veil with Git on
the same machine (the tables above).

## Design trade-offs

Veil gives up some things on purpose. What each choice costs, and what it
buys:

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
- *Buys:* Veil's landing service batches many changes into each move. Pushing straight onto one `main` without it fell to 8 a second with 50 agents racing; the landing service held 995 a second on one machine (older code, below), and about 200 a second on the cloud deployment above, where each batch waits for MinIO.

## Where it stands

Veil is a **pre-1.0 preview**. Every planned feature is built and has run
across several machines; the work left is speed and the open items below.

| Part | State |
|---|---|
| Client engine, workspaces, sandboxes | Built; the sandbox is Linux-only |
| Thin clones, caches, storage on S3 with PostgreSQL or YugabyteDB | Built; storage is append-only |
| YugabyteDB across nodes, one repository included (hash layout) | Built, and measured on 3 and 6 nodes (above) |
| History, blame and search answered by the server | Built, speed gate passed |
| Landing at agent scale, CI, pull requests, embargoes, web client | Built |
| Review of the whole code base (eight passes) | Done: about 75 bugs found, all but a handful fixed |
| A run across several machines | Done on Google Cloud, 2026-11-20 and 21 (above), and 2026-11-14 and 15 on older code |

The correctness suite is green: about 970 server tests, each run on
PostgreSQL and on YugabyteDB, and about 2,570 client and engine tests. Every
bug found is in [docs/BUGS.md](docs/BUGS.md) with the test that reproduces
it, the open ones included.

Not proven yet:
- projects far bigger than 1 GB;
- more than one zone or region;
- YugabyteDB under a load that fills 6 nodes or more;
- the gates that have no benchmark yet (bisect over 10,000 candidates, workspaces of a million files);
- the sandbox on macOS, where commands run unconfined for now.

By design, a clone is not a full standalone copy as in Git: you can edit,
commit, split, squash and undo offline, and everything shared goes
through the server.

**Next steps**, from the Google Cloud runs
([DEPLOY.md §12.11](docs/DEPLOY.md#1211-the-runs-on-google-cloud-2026-11-20-and-21)):
1. **Find why pulls on the PostgreSQL deployment are slower** than on YugabyteDB with the same code (279 against 1,644 a second at 10 agents).
2. **Find why landing drops on 3 servers** (254, 242, then 161 a second).
3. **Tell agents to come back before YugabyteDB's CPUs are full,** so retries can't make it collapse.
4. **Measure YugabyteDB with a load that grows until the nodes are full,** and record each node's statements in the cloud runs.
5. **Make the balancer an on-demand machine:** Spot reclaims of it voided two landing runs.
6. **Run again:** projects much bigger than 1 GB, and more than one zone.

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

**On macOS, everything works except the sandbox.** `vl ws exec` runs its
command unconfined: no separate files, home folder, processes or ports, and
no memory, CPU or time limits. The sandbox options are refused there. Run
agents you don't trust on Linux, or in a Linux virtual machine.

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

It makes a self-signed certificate in `~/veil-hub` and keeps running. Its
storage is append-only in v1: there is no garbage collection, and nothing a
project's history named is deleted later
([the server guide](docs/guide/the-server.md#running-a-server)). In
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
