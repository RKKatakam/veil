# Scion for developers: the features Veil would need

> Status: **to do**. Scheduled for the scale round (owner, 2026-11-04): phase 0, plus agent attribution (4.6), sandbox resource limits (4.7), and partial clone / fetch on demand over SFTP (4.1, 4.4). The per-machine daemon cache (2.4) is deferred. This is a roadmap the owner added on 2026-11-04. None of it is built yet; Veil 1.0 is a client plus an SFTP remote. Phase 0 is scheduled with the scale round (after the Git-parity round). Phases 1–4 are built on the Veil Hub (`docs/HUB.md`).

## Summary
A "Scion for developers" is a source-control service where most of the work happens on a server:
- Commits are written without locks.
- The server answers history questions.
- Clients fetch only the files they read.
- Agents land work without a global merge-queue lock.

Veil could offer this to any team, not just one company's huge repo, by building it on the Veil Hub.

**Update, 2026-11-05 (`docs/VISIBILITY.md`):** company code is no longer encrypted. The Hub reads and serves it behind permission checks, so the split below applies only to the **secret** tier (`.env` and the like). Company code gets Scion's full server-side treatment. Original text: The catch is encryption. Scion is fast because its server can read everything: it merges, computes blame and indexes all content. The Veil Hub can't read cloaked files, so every server-side feature below splits in two:
- **Public content:** the Hub does it on the server, as Scion does.
- **Cloaked content:** it runs where the keys are, on the developer's machine or the team's own trusted runners. Any results that are stored go back as encrypted data.

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
- Scion is "by no means a suitable replacement for git for general use". It is built for one very large monorepo. Veil must stay good at the ordinary, Git-sized case and not take on Scion's always-online assumptions by default.
- "What we learned building Scion": agents "will sometimes violate core system constraints", and engineers had to "steer Claude away from over-engineering parts of the system". Often "the role of the engineers was to tell Claude 'no.'" Anthropic "makes extensive use of adversarial review", but one such review "was overly defensive about trusting another internal service". For Veil: adversarial passes stay, but a finding that asks for defence against a component Veil already trusts by design needs a stated threat before it is built.
- The post does not cover agent attribution, sandboxes, resource limits, offline work, latency or cache sizes. Veil's items for those (4.6, 4.7) are Veil's own designs, not taken from Scion.

## What Veil already has
Veil already has about half of Scion's foundations. The missing half is the server.

| Scion idea | In Veil today | Gap |
|---|---|---|
| Objects addressed by hash | Every object is addressed by its BLAKE3 hash | None |
| Writing a commit separate from moving the branch | Designed for the Hub: upload to a holding area, then a compare-and-swap in PostgreSQL | Not built. Today's SFTP push holds the remote's lock for the whole upload. |
| Partial checkouts | `vl ws exec --only` | Only for workspaces; no partial clone |
| Checkouts where files appear when read | `vl ws mount` (FUSE) and in-memory workspaces | They read from the local copy, not from a server |
| Write-ahead log | The op log, with undo | A single repository lock sits in front of it |
| Stable change identity | Change ids instead of branches | None |
| Per-directory permissions | Scopes, each with its own encryption | None. Stronger than Scion's, because keys enforce it. |
| History indexes | None yet | "History index" item in `docs/BACKLOG.md` |
| No maintenance | Packs plus `gc`, which loads the whole store into memory | Streaming `gc` is in the backlog |
| Server API, server merges, caches | None | All of it: Veil has no server yet |

## 1. Writing and concurrency
Goal: the only step done one at a time is moving a branch, and it takes milliseconds. Everything else runs in parallel.

| # | Feature | What it does | Cloaked content |
|---|---|---|---|
| 1.1 | Lock-free uploads | Objects and packs are written before any lock is taken. An object nothing points to is invisible and harmless. | Same: the server stores encrypted data it can't read |
| 1.2 | Compare-and-swap branch moves | A push says "move `main` from X to Y". The server does it atomically or rejects it. This replaces the repository lock as the one-at-a-time step. | Same: moving a branch needs no keys |
| 1.3 | Lock-free op log | Concurrent operations add to the log and get merged, instead of waiting for `.veil/lock` | Same |
| 1.4 | Commits through the API | An agent sends "these files changed on top of revision R" and the server builds the snapshot. No clone needed. | The client encrypts cloaked files first and sends them; the server records them |
| 1.5 | Resumable pushes that are safe to retry | A retried push doesn't re-send what's already stored, and an upload resumes after a dropped connection | Same |
| 1.6 | Few server-side branches | Agents' work lives as change ids and short-lived proposals, not thousands of long-lived branches | Same |
| 1.7 | Lock-free writes on SFTP | For today's remote: upload the pack first, then take the lock only to update the branches. A stop-gap until the Hub exists. | Same |

## 2. Storage and maintenance
Goal: a repository never needs repacking or a stop-the-world `gc`, and any cache can serve any object without checking with anyone.

| # | Feature | What it does | Cloaked content |
|---|---|---|---|
| 2.1 | Object store on S3-compatible storage | Each object is stored by its hash. Packs are used only to transfer data for clones. | Encrypted objects, unchanged |
| 2.2 | No routine `gc` | Objects nothing points to are cleaned up in the background by a retention policy, never by repacking the whole store | Same |
| 2.3 | Layered caches | A daemon on each machine, a regional cache, the server. Objects are addressed by hash, so the caches never need to coordinate. | Caches hold only encrypted data, so they're safe to share |
| 2.4 | Daemon on each machine | One cache shared by every agent on the machine, so 30 agents fetch each object once | Same; keys stay inside each agent's process |
| 2.5 | Large files | Files are split into chunks by content, so editing a 2 GB file uploads only the changed chunks | Each chunk is encrypted separately |

## 3. Server queries and precomputed indexes
Goal: history questions are answered in milliseconds without a checkout. Encryption hurts most here, because the server can't index what it can't read.

| # | Feature | What it does | Cloaked content |
|---|---|---|---|
| 3.1 | Index framework | Each index entry is computed from a commit and its parents' entries, either when the commit lands or the first time someone asks. Phase 0's local commit-graph index (`docs/design/scale/3-history-index.md`, generation numbers and Bloom filters computed from parents) is the first such index; the framework generalises it rather than replacing it | A runner holding the keys computes it and stores it encrypted for the scope |
| 3.2 | Commit-graph index | `log`, ancestry and merge-base queries no longer walk the whole history | The graph's shape needs no keys, so the server can do it |
| 3.3 | Blame and file history | Precomputed per file, so `vl blame` on a 10-year-old file is instant | An encrypted index, read by members' clients |
| 3.4 | Search by code and file path | Search file names and contents across history | Public: the server. Cloaked: an encrypted index that members search on their own machine, or search hosted on a runner |
| 3.5 | Query API | Diff against the merge base, a file at a given revision, log, blame and grep, over HTTP and through `vl` | The server returns encrypted data and indexes; the client decrypts |
| 3.6 | Rename and copy detection | Worked out once per commit instead of by every client | Same split as 3.1 |

## 4. Client, checkouts and agents
Goal: an agent's sandbox is ready in seconds on a repo of any size, and many jobs never check anything out.

| # | Feature | What it does | Cloaked content |
|---|---|---|---|
| 4.1 | Fetch on demand | The client asks for the folders and files it wants, starting from the top folder. It doesn't have to send a list of everything it already has. | Fetches encrypted data and decrypts it locally |
| 4.2 | Cache of limited size | Old objects are evicted, so a laptop never holds the full history | Same |
| 4.3 | Checkouts that fetch from the server | Extend `vl ws mount` so a file is fetched from the server the first time it's read | Decrypted inside the mount, never on the server |
| 4.4 | Partial clone | Clone one directory and only recent history. Phase 0's SFTP version (`docs/design/scale/6-partial-clone.md`) already fetches each object by hash with no list of what the client has, as Scion's protocol does. But it still copies the remote's pack indexes, and Anthropic found Git-style partial clones only bought time, so it is a stop-gap: the Hub's version uses 4.1 through the caches of 2.3 | Same |
| 4.5 | Agent sandboxes on the Hub | `vl ws exec` against a remote repo: create a workspace, run, push the change, all without a full clone | The agent gets keys only for the scopes its task needs |
| 4.6 | Agent identity and attribution | Each change records the agent, its task and a reference to its prompt, so a bad landing can be traced | Same |
| 4.7 | Resource limits | CPU and memory caps for each sandbox, plus a shared build cache | Not applicable |

## 5. Merging at agent scale
Goal: 50 changes ready at once all land within seconds, and no developer has to retry a push by hand. This is the hardest area for Veil, because the Hub can't merge files it can't read.

| # | Feature | What it does | Cloaked content |
|---|---|---|---|
| 5.1 | Landing on the server | The server merges or rebases a proposal onto the latest `main` and moves `main` with a compare-and-swap | Changes with only public files: the server. Others: 5.2 |
| 5.2 | Landing runners | Self-hosted runners that hold scope keys merge and push changes that touch cloaked files, on the team's own machines | Needed for anything cloaked |
| 5.3 | Fast path for changes that don't overlap | Changes to different files land by rewriting the folder listings, without merging any file contents | Possible while cloaked file names are visible. Open question once those names are hidden. |
| 5.4 | Land first, test after | No merge-queue lock. A broken `main` is fixed forward or reverted, as Scion does. | Same |
| 5.5 | Agents that fix conflicts | A change that conflicts goes back to an agent with both versions and the test result, then lands again | The agent needs the scope's key |
| 5.6 | Automatic bisect and revert | When `main` breaks, find the change that broke it and revert it, using the query API | Bisect runs on a runner that holds the keys |
| 5.7 | Protected `main` | Developers and agents land only through 5.1 or 5.2. Direct pushes to `main` are refused. | Same |

## 6. Review, CI, permissions and operations
Goal: people review what a change is for rather than every line, and the team can see whether the system keeps up.

| # | Feature | What it does | Cloaked content |
|---|---|---|---|
| 6.1 | Review by intent | Changes are sorted by risk, for example a comment-only edit versus a change to login logic. People review what each change is for and sign off on the risky ones. | Risk scoring of cloaked changes runs on a runner that holds the keys |
| 6.2 | CI through the API | A CI job gets the diff against the merge base and only the files it needs, in seconds | Runners are scope members, as designed in `docs/HUB.md` §7 |
| 6.3 | Path permissions for agents | An agent may write only the paths its task names; the server refuses the rest | Scopes already control who can read; this adds control over who can write |
| 6.4 | Health metrics | Per repo: merges per hour, time to land, conflict rate, reverts, cache hit rate | Metrics contain no file content |
| 6.5 | Failure isolation | Caches and servers run as separate layers, so a cache outage slows reads but never blocks landing | Same |
| 6.6 | Scale benchmark | A repeatable load test (N agents creating changes, landing them and running queries) run before each release. Phase 0's version is `crates/veil-bench` (`docs/design/scale/BASELINE.md`) | Includes a test profile with mostly cloaked files |
| 6.7 | Rate limiting | Per-account and per-agent limits on requests and landings, so one runaway agent can't starve the rest | Same |
| 6.8 | Simulation testing | Hermetic simulations of the Hub, its caches and many clients, with faults injected (dropped connections, cache outages, racing landings) | Includes cloaked and embargoed changes, checked for leaks |

## Roadmap
Phase 0 fits alongside the current 1.0 work and makes today's remote handle concurrent pushes. Each later phase depends on the one before it.

1. **Phase 0: Veil 1.0 client and SFTP remote (now).** Lock-free writes on SFTP (1.7), lock-free op log (1.3), history index (3.2), scale benchmark (6.6), background cleanup instead of whole-store `gc` (2.2).
   - *Gate:* the benchmark shows no waiting on the lock and no commands that walk the whole history.
2. **Phase 1: Hub core.** Object store on S3 (2.1), compare-and-swap branch moves (1.2), lock-free uploads (1.1), resumable pushes (1.5), few branches (1.6), layered caches (2.3), query API (3.5), large-file chunking (2.5).
   - *Gate:* 50 simultaneous pushes land in about the time of the slowest upload.
3. **Phase 2: Thin client and agent sandboxes.** Fetch on demand (4.1), limited cache (4.2), checkouts that fetch from the server and partial clones (4.3, 4.4), Hub sandboxes (4.5), commits through the API (1.4), per-machine daemon (2.4), agent attribution (4.6), resource limits (4.7).
   - *Gate:* an agent sandbox on a large repo is ready in seconds.
4. **Phase 3: History answered by the server.** Index framework (3.1), blame and file history (3.3), search (3.4), rename and copy detection (3.6), encrypted indexes for cloaked scopes computed by runners that hold the keys.
   - *Gate:* blame, log and diff are answered through the API with no checkout.
5. **Phase 4: Landing at agent scale.** Landing on the server (5.1), landing runners (5.2), fast path for non-overlapping changes (5.3), protected `main` (5.7), land first and test after (5.4), conflict-fixing agents (5.5), automatic bisect and revert (5.6), review by intent, CI through the API, path permissions, metrics and isolation (6.1–6.5), rate limiting (6.7).

Simulation testing (6.8) starts in phase 1 and grows with each phase.

The roadmap has no dates. Each gate is a benchmark result, and the target scale is still an open question.

## Open questions
- What's the target scale? How many merges a day per repository should the Hub sustain (1,000? 30,000?), and on what hardware?
- Once cloaked file names are hidden, can the server still use the fast path for non-overlapping changes (5.3), or does every cloaked landing have to go through a runner?
- Who runs landing runners for a solo developer or a small team with no servers of their own?
- How large do the encrypted blame and search indexes get, and how do members query them without downloading them whole?
- Landing first and testing after (5.4) clashes with embargoes: reverting an embargoed merge must not leak the fix.
- Should Veil keep working fully offline, given that Scion gave up offline work and assumes clients are always online?

## Sources
- [Anthropic: Redesigning source control at Anthropic](https://www.anthropic.com/research/redesigning-source-control) (13 Oct 2026)
- [The Register on Scion](https://www.theregister.com/a/5302943)
- [Arize: Why Anthropic replaced Git, and whether you'll need to](https://arize.com/?p=33172)
- Checked against the Anthropic post on 2026-11-05.
- Veil repo: `docs/ARCHITECTURE.md` §8–9, `docs/HUB.md` §2, §4, §5.7, §7, `docs/BACKLOG.md`
