# Scion for developers: the features Veil needs

> Status: **roadmap.** Veil is server-centric (`docs/OVERVIEW.md`): the `vl` client is always connected to the Veil server (the Hub), which stores the code as plain text and enforces every permission (`docs/VISIBILITY.md`). These features are built **on that server**, starting now. The client-side groundwork (lock-free op log, two-phase pushes, history index, background maintenance, scale benchmark) is built. The server design is `docs/HUB.md`.

## Summary
A "Scion for developers" is a source-control service where most of the work happens on a server:
- Commits are written without locks.
- The server answers history questions.
- Clients fetch only the files they read.
- Agents land work without a global merge-queue lock.

**The Veil Hub is built on this design,** for thousands of agents at once pulling, opening PRs and merging. Its design targets (`docs/OVERVIEW.md`, "Design targets") are the server's benchmark gates, listed in `docs/HUB.md` §9.2: thousands of agents (benchmarked at 1,000 and 10,000); a small pull and a PR open or update in under 100 ms of server time; thousands of merges per hour per project with no global lock; a fresh agent workspace in seconds; history, blame and search through the API in milliseconds to low hundreds of ms; permission checks a negligible share of request time.

Veil offers this to any team, not just one company's huge repo, on the Veil server. The server reads code, so it can merge, index and search it as Scion does. Only secrets and embargoed changes are encrypted; those few cases run where the keys are, on a device or machine with access (`docs/HUB.md` §7.5, §8.3).

## What Scion does
Scion took Anthropic from about 2,500 merges a day in May 2026 to more than 30,000 a day by September, mostly from agents. All of the following comes from [Anthropic's public post](https://www.anthropic.com/research/redesigning-source-control). The post doesn't say how merges onto `main` are ordered, how fine-grained conflict detection is, or how many writes per second it handles.

| Idea | How Scion does it |
|---|---|
| Commits without locks | A commit (a "changeset") is an entry in a write-ahead log, created on the server: the files changed relative to its first parent, each with a pointer to its compressed contents by hash. It is not a pointer to a whole tree, as a Git commit is. No locking, no coordination between servers. |
| One tiny step done one at a time | Moving `main` is a single atomic compare-and-swap on one database row (Spanner), separate from writing the commit. |
| No merge-queue lock | Concurrent changes may conflict. Testing happens after the merge and before deploy, and Claude fixes the conflicts. |
| Few branches | Only `main` and release branches. Others are discouraged because every server has to agree on them. |
| No packfiles, no gc | Each blob is stored on its own in cloud storage. "No repository maintenance is needed." |
| The server does the work | The server creates commits, does merges and rebases, and answers blame and history queries, so there is nothing to push. The client "can compute very little on its own" and assumes the server is always reachable. |
| Derived data | One generic mechanism: each index's value for a changeset is computed from its parents' values, either eagerly as the changeset lands or deferred until asked. Examples: blame, path history, skip lists over the commit graph, copy detection, path search. |
| Thin client | `scn` keeps a cache of limited size, fetches only the files it needs, and gives a partial checkout where files appear when read. |
| Layered caches | Client, then a daemon on each machine (which starts from a periodically refreshed snapshot), then a regional cache, then the server. All layers answer the same requests; each talks only to the next, so a failing cache can't overwhelm the servers. No layer keeps long-lived state, and over 99% of requests are answered by a cache at each layer. |
| API-first jobs | CI and agents ask for diffs, history or bisects through the API, often without checking anything out. |
| Fetch protocol | The client never sends a list of what it has: it starts from the root tree, asks for the trees it is missing, then the blobs. Every request names an object that never changes, so any cache can serve it, and a dropped download resumes. |
| Testing and operations | Hermetic simulations of the infrastructure, fuzzing, rate limiting, and Claude agents that watch each component's telemetry and logs, alongside ordinary alerts. |

Scale, from the post: almost 100 GB of history on `main`, a compressed working copy over 25 GB, and about 25 million checkouts a day from CI. Scion uses about 200 times less CPU and memory than the Git mirror fleet it replaced, and checkouts take seconds instead of minutes.

What Anthropic tried and dropped:
- several hundred Git mirrors and seeds, which were hard to run and fell behind `main`;
- shallow clones, sparse checkouts and promisor remotes, which "bought time" but did not solve the scaling problem;
- a global merge-queue lock.

Caveats from the post:
- Scion is "by no means a suitable replacement for git for general use". It is built for one very large monorepo. Veil takes Scion's always-connected design, but must also stay good for an ordinary, small project.
- "What we learned building Scion": agents "will sometimes violate core system constraints", and engineers had to "steer Claude away from over-engineering parts of the system". Often "the role of the engineers was to tell Claude 'no.'" Anthropic "makes extensive use of adversarial review", but one such review "was overly defensive about trusting another internal service". For Veil: adversarial passes stay, but a finding that asks for defence against a component Veil already trusts by design needs a stated threat before it is built.
- The post does not cover agent attribution, sandboxes, resource limits, latency or cache sizes. Veil's items for those (4.6, 4.7) are Veil's own designs, not taken from Scion.

## What Veil already has
Veil has about half of Scion's foundations, in the client engine. The other half is the server.

| Scion idea | In Veil today | Gap |
|---|---|---|
| Objects addressed by hash | Every object is addressed by its BLAKE3 hash | None |
| Writing a commit separate from moving the branch | Two-phase pushes: objects are staged without a lock, and the lock is taken only to move branches (built, stream P) | The server replaces the lock with a compare-and-swap on one database row |
| Partial checkouts | `vl ws exec --only` | Only for workspaces; no fetch on demand yet |
| Checkouts where files appear when read | `vl ws mount` (FUSE) and in-memory workspaces | They read from the local copy, not from the server |
| Write-ahead log | A lock-free op log with undo (built, stream O, format 6) | None |
| Stable change identity | Change ids instead of branches | None |
| Per-folder permissions | Today's client restricts paths by encrypting them | The server's permission model replaces this: admins, groups, folder access, `public` (`docs/VISIBILITY.md`) |
| History indexes | A local commit-graph index with generation numbers (built, stream I) | Server-side indexes for blame, file history and search |
| No maintenance | Incremental background maintenance and a safe prune (built, stream G2) | Retention-based cleanup on object storage |
| Server API, server merges, caches | None | All of it |

## 1. Writing and concurrency
Goal: the only step done one at a time is moving a branch, and it takes milliseconds. Everything else runs in parallel.

| # | Feature | What it does |
|---|---|---|
| 1.1 | Lock-free uploads | Objects are written to a holding area before any branch moves. An object nothing points to is invisible and harmless. |
| 1.2 | Compare-and-swap branch moves | A push says "move `main` from X to Y". The server does it atomically on one database row, or rejects it. |
| 1.3 | Lock-free op log | Concurrent operations add to the log and get merged. **Built** in the client (stream O). |
| 1.4 | Commits through the API | An agent sends "these files changed on top of revision R" and the server builds the snapshot. No clone needed. Secrets are encrypted by the client first. |
| 1.5 | Resumable pushes that are safe to retry | A retried push doesn't re-send what's already stored, and an upload resumes after a dropped connection. **Built** in the client (stream P); the server keeps the protocol shape. |
| 1.6 | Few server-side branches | Agents' work lives as change ids and short-lived proposals, not thousands of long-lived branches |

## 2. Storage and maintenance
Goal: a project never needs repacking or a stop-the-world `gc`, and any cache can serve any object without checking with anyone.

| # | Feature | What it does |
|---|---|---|
| 2.1 | Object store on S3-compatible storage | Each object is stored by its hash. Packs are used only to transfer data. |
| 2.2 | No routine `gc` | Objects nothing points to are cleaned up in the background by a retention rule. The client's incremental maintenance is **built** (stream G2). |
| 2.3 | Layered caches | A cache on each machine, a regional cache, the server. Objects are addressed by hash, so the caches never coordinate. A cache serves an object only to someone the server has allowed to see it. |
| 2.4 | Cache on each machine | One cache shared by every agent on the machine, so 30 agents fetch each object once |
| 2.5 | Large files | Files are split into chunks by content, so editing a 2 GB file uploads only the changed chunks |

## 3. Server queries and precomputed indexes
Goal: history questions are answered in milliseconds without a checkout.

| # | Feature | What it does |
|---|---|---|
| 3.1 | Index framework | Each index entry is computed from a commit and its parents' entries, when the commit lands or the first time someone asks. The client's commit-graph index (`docs/design/scale/3-history-index.md`, built) is the first such index; the framework generalises it. |
| 3.2 | Commit-graph index | `log`, ancestry and merge-base queries never walk the whole history |
| 3.3 | Blame and file history | Precomputed per file, so `vl blame` on a 10-year-old file is instant |
| 3.4 | Search by code and file path | File names and contents across history. Results and counts pass the same access check as every read. |
| 3.5 | Query API | Diff against the merge base, a file at a revision, log, blame and grep, over HTTP and through `vl` |
| 3.6 | Rename and copy detection | Worked out once per commit instead of by every client |

## 4. Client, checkouts and agents
Goal: an agent's sandbox is ready in seconds on a project of any size, and many jobs never check anything out.

| # | Feature | What it does |
|---|---|---|
| 4.1 | Fetch on demand | The client asks the server for the folders and files it wants, starting from the top folder. It never sends a list of what it has. |
| 4.2 | Cache of limited size | Old objects are evicted, so a laptop never holds the full history |
| 4.3 | Checkouts that fetch from the server | Extend `vl ws mount` so a file is fetched the first time it's read |
| 4.4 | Partial checkout | Check out one folder and recent history. The design (`docs/design/scale/6-partial-clone.md`) fetches each object by id, as Scion does; it is re-aimed at the server. |
| 4.5 | Agent sandboxes on the server | `vl ws exec` against a project: create a workspace, run, push the change, without a full clone. The agent sees what its person sees. |
| 4.6 | Agent identity and attribution | Each change records the agent, its task and a reference to its prompt, so a bad landing can be traced |
| 4.7 | Resource limits | CPU and memory caps for each sandbox, plus a shared build cache |

## 5. Merging at agent scale
Goal: 50 changes ready at once all land within seconds, and no developer has to retry a push by hand.

| # | Feature | What it does |
|---|---|---|
| 5.1 | Landing on the server | The server merges or rebases a change onto the latest `main` and moves `main` with a compare-and-swap |
| 5.2 | Batched landings | Ready changes land in batches, so thousands of agents don't contend on one branch |
| 5.3 | Fast path for changes that don't overlap | Changes to different files land by rewriting the folder listings, without merging contents |
| 5.4 | Land first, test after | No merge-queue lock. A broken `main` is fixed forward or reverted, as Scion does. |
| 5.5 | Agents that fix conflicts | A change that conflicts goes back to an agent with both versions and the test result, then lands again |
| 5.6 | Automatic bisect and revert | When `main` breaks, find the change that broke it and revert it, using the query API |
| 5.7 | Protected `main` | Developers and agents land only through 5.1. Direct pushes to `main` are refused. |
| 5.8 | Landings that need keys | A conflict inside a secret file, or an embargoed change before release, is landed by a device or machine with access, then pushed (`docs/HUB.md` §7.5) |

## 6. Review, CI, permissions and operations
Goal: people review what a change is for rather than every line, and the team can see whether the system keeps up.

| # | Feature | What it does |
|---|---|---|
| 6.1 | Review by intent | Changes are sorted by risk, for example a comment-only edit versus a change to login logic. People review what each change is for and sign off on the risky ones. |
| 6.2 | CI through the API | A CI job gets the diff against the merge base and only the files it needs, in seconds. A CI machine is added like a person, with the groups it needs. |
| 6.3 | Path permissions for agents | An agent may write only the paths its task names; the server refuses the rest |
| 6.4 | Health metrics | Per project: merges per hour, time to land, conflict rate, reverts, cache hit rate |
| 6.5 | Failure isolation | Caches and servers run as separate layers, so a cache outage slows reads but never blocks landing |
| 6.6 | Scale benchmark | A repeatable load test (N agents creating changes, landing them and running queries) before each release. The client's version is **built** (`crates/veil-bench`, `docs/design/scale/BASELINE.md`). |
| 6.7 | Rate limiting | Per-person and per-agent limits on requests and landings, so one runaway agent can't starve the rest |
| 6.8 | Simulation testing | Hermetic simulations of the server, its caches and many clients, with faults injected (dropped connections, cache outages, racing landings), checked for leaks of private folders, secrets and embargoed changes |

## Roadmap
The server is built now, with the permission model. Each later phase depends on the one before it.

- **Done: client groundwork.** Lock-free op log (1.3), two-phase resumable pushes (1.5), commit-graph index (3.2, first part of 3.1), background maintenance (2.2, client side), scale benchmark (6.6).

1. **Phase 1: the server and the permission model, together.** Object store on S3 (2.1), compare-and-swap branch moves (1.2), lock-free uploads (1.1), few branches (1.6), sign-in, admins, groups, managers, folder access and `public`, encrypted secrets, `vl` pushing and pulling through the server.
   - *Gate:* 50 simultaneous pushes land in about the time of the slowest upload; a small pull is under 100 ms of server time; permission checks are a negligible share; each person receives only what they may see.
2. **Then: a simplification pass** (`docs/OVERVIEW.md`). Remove SFTP and path remotes, offline assumptions, old formats and old jargon.
3. **Phase 2: fetch on demand and agent sandboxes.** Fetch on demand (4.1), limited cache (4.2), checkouts that fetch from the server and partial checkouts (4.3, 4.4), layered caches (2.3, 2.4), server sandboxes (4.5), commits through the API (1.4), agent attribution (4.6), resource limits (4.7), large-file chunking (2.5).
   - *Gate:* a fresh agent workspace on a large project is ready in seconds.
4. **Phase 3: history answered by the server.** Index framework (3.1), blame and file history (3.3), search (3.4), query API (3.5), rename and copy detection (3.6).
   - *Gate:* history, blame and search are answered through the API, with no checkout, in milliseconds to low hundreds of ms.
5. **Phase 4: landing at agent scale.** Landing on the server (5.1), batched landings (5.2), fast path (5.3), protected `main` (5.7), land first and test after (5.4), conflict-fixing agents (5.5), automatic bisect and revert (5.6), landings that need keys (5.8), review by intent, CI through the API, path permissions, metrics and isolation (6.1–6.5), rate limiting (6.7). PR review and hidden PRs (`docs/HUB.md` §7) land here too.
   - *Gate:* thousands of merges per hour per project with no agent waiting on a global lock; a PR open or update under 100 ms; benchmarked at 1,000 and 10,000 agents.

Simulation testing (6.8) starts in phase 1 and grows with each phase.

The designs of phases 2, 3 and 4, with their milestones (S3–S26), threat reviews and benchmarks, are in `docs/design/server/`.

The roadmap has no dates. Each gate is a benchmark result against the design targets in `docs/HUB.md` §9.2.

## Open questions
- What hardware do the 1,000- and 10,000-agent benchmarks run on?
- Land first and test after (5.4) clashes with embargoes: reverting an embargoed merge must not reveal the fix.
- Can a per-viewer projection (people who can't see a folder don't see its names) keep the fast path (5.3) and the shared caches (2.3) simple?

## Sources
- [Anthropic: Redesigning source control at Anthropic](https://www.anthropic.com/research/redesigning-source-control) (13 Oct 2026)
- [The Register on Scion](https://www.theregister.com/a/5302943)
- [Arize: Why Anthropic replaced Git, and whether you'll need to](https://arize.com/?p=33172)
- Checked against the Anthropic post on 2026-11-05.
- Veil repo: `docs/OVERVIEW.md`, `docs/VISIBILITY.md`, `docs/HUB.md` §4, §9, `docs/ARCHITECTURE.md` §8–10, `docs/BACKLOG.md`
