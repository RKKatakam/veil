# Server phases 2–4: designs and build order

> **Owner, 2026-11-06:** all recommended product defaults are approved. Embargoes are permission-based; the server releases them at the deadline (no drand, no release machine).

> **Status: design** (2026-11-06). Base: `integration` @ `3851159`. Sources of truth: `docs/OVERVIEW.md` and `docs/VISIBILITY.md`. The server as built: `docs/HUB.md` §13 (milestone S1). Roadmap: `docs/design/scion-for-developers.md`.

| Document | Phase | Gate |
|---|---|---|
| [`phase-2-thin-clients.md`](phase-2-thin-clients.md) | Fetch on demand, bounded caches, mounts, the per-machine daemon and watcher, layered caches that serve only what the asker may see, workspaces in seconds, commits through the API, agent sessions and attribution | a fresh workspace on any size of project under 2 s cold, 300 ms warm; 10,000 pulls/s with caches; 100 landings/s into one `main` |
| [`phase-3-server-history.md`](phase-3-server-history.md) | Derived data per change, the query API (log, blame, diff, files, grep, search) projected per viewer | history, blame and search through the API in milliseconds to low hundreds of ms; answers identical to those on a project built from the viewer's view |
| [`storage-and-cost.md`](storage-and-cost.md) | Cost and speed across phases: one database commit per push, request caches, tips without a hot row, compressed objects, packs per push and their merging, cost gates in every benchmark | at most 2 storage writes and 1 database commit per push; 5 or fewer statements per warm pull; server under 1 GB on the 1 GB profile |
| [`phase-4-agent-scale.md`](phase-4-agent-scale.md) | Batched server-side landing, conflicts back to agents, protected `main`, land first and test after, bisect and revert, PRs and review, embargo release, CI, rate limits, metrics, the web client | 1,000 landings/s into one `main` with 10,000 agents, p99 under 1 s; PR open or update under 100 ms |

## The owner's numbers, phase by phase

| Number | Measured today (`LOAD.md`) | After phase 2 | After phase 3 | After phase 4 |
|---|---|---|---|---|
| Pulls/s, one project | 2,100–2,500 (`main` moving 20/s) | 10,000 with caches; 1,000+ while `main` moves 1,000/s | same; history no longer pulled | same, at 1,000 landings/s |
| Landings/s across projects | 2,094 | 4,000 | — | 10,000 on one machine; more with database nodes |
| Landings/s into one `main` | 20–30 with many agents | 100 | — | **1,000 sustained** (headroom about 5,000) |
| Merges per day, one project (capacity) | about 2 million in theory, less with peaks | about 8 million | — | about 86 million: **1 million a day with 10× peaks fits** |
| Agents at once | 2,000 simulated | 10,000 simulated | — | 10,000 landing into one `main` |

All "after" numbers are targets that each phase's gate run must prove.

## Milestones

S1 is built. **S2** (secrets at scale: keys per access rule, background wrapping, device removal; `HUB.md` §13.6, §13.9) and **the simplification pass** (removing path and SFTP remotes, offline assumptions, old jargon) are planned outside these documents and appear here only as dependencies.

| # | Phase | Milestone | Depends on |
|---|---|---|---|
| S3 | 2 | Fetch on demand in the client (thin clones, bounded cache, no full graph): **built**, `HUB.md` §13.21 | S1, simplification pass |
| S4 | 2 | **Built** (`HUB.md` §13.14). Request-path caches (permissions, sessions, snapshot resolution, tips invalidated without a hot row), **one database commit per push**, and the cost gates in `veil-bench load` (`storage-and-cost.md` §3–5, §9) | S1 |
| S5 | 2 | Read grants, the object routes, access epochs (built: `HUB.md` §13.16) | S1 |
| S6 | 2 | The Veil daemon: shared object cache | S3, S5 |
| S7 | 2 | The daemon's file watcher (`status`/`commit` without a scan) | S6 |
| S8 | 2 | Workspaces that fetch on first read; the workspace socket for sandboxes; private loopback and seeded layers for full-stack tests (phase 2 §4.9) | S3; phase 1's isolated sandboxes (S6 for the warm numbers) |
| S9 | 2 | Regional cache (built: `HUB.md` §13.18) | S5 |
| S10 | 2 | Commits through the API (with the server-side secret scan): **built** (`HUB.md` §13.13) | S1 |
| S11 | 2 | Agent sessions and attribution; attempts (recorded dead ends) on change records | S10, S8 |
| S27 | 2 | Compressed objects (zstd) in storage and transport (`storage-and-cost.md` §6). **Built** (`HUB.md` §13.15) | S1 |
| S28 | 2 | Packs: one storage write per push for small objects, index, range reads (`storage-and-cost.md` §7). **Built** (`HUB.md` §13.20), with staged uploads (BUG-930) and checks several at once (BUG-865) | S5, S27 |
| S29 | 2 | Merging packs and pack garbage collection (`storage-and-cost.md` §8) | S28 |
| G2 | 2 | Phase 2 gate run | S3–S11, S27–S29 |
| S12 | 3 | Derived-data framework, commit graph, changed paths, per-rule lists, eager projection memos at each branch move | S1 |
| S13 | 3 | Query API with per-viewer projection, and the projection-equivalence harness. **Built** (phase 3 §11) | S12 |
| S14 | 3 | Blame and file history | S13 |
| S15 | 3 | Search. **Built** (`HUB.md` §13.23, phase 3 §13) | S13 |
| S16 | 3 | `vl` over the query API; phase 3 gate run | S3, S13, S14, S15 |
| S17 | 4 | The landing service (batched, fast path, protected branches, `vl land`) | S4, S10, S12 |
| S18 | 4 | Content merges, conflicts back to agents, the event stream | S17 |
| S19 | 4 | CI through the API; land first, test after; `main@tested`; agents start from `main@tested` | S11, S13, S17 |
| S20 | 4 | Automatic bisect and revert | S14, S19 |
| S21 | 4 | PRs and review (visibility classes, risk, approvals) | S13 (S17 to land PRs) |
| S22 | 4 | Embargoes through the server; the release service | S2, S17 |
| S23 | 4 | Embargoed PRs | S21, S22 |
| S24 | 4 | Rate limits, health metrics, failure isolation | S17 |
| S25 | 4 | Web client, first version (no secrets) | S13, S21 |
| S26 | 4 | Secrets in the browser (only if the owner approves) | S25, S2 |
| G4 | 4 | Phase 4 gate run | S17–S24 |

**Phases overlap.** The dependencies are between milestones, not phases: phase 3's derived data (S12) and phase 4's landing service (S17) do not wait for the whole of phase 2.

## Build order: waves that can run in parallel

The owner allows many agents at once. Each wave's milestones touch different files, so they can run together; a milestone starts as soon as its dependencies have merged into `integration`.

| Wave | Milestones in parallel | Notes on shared code |
|---|---|---|
| **1** | **S3, S4, S5, S10, S12** | S4 and S10 both touch the push transaction in `veil-server/src/sync.rs`: S10 puts its code in a new `changes.rs` and calls the push checks; whichever merges second rebases. S5's chain check lives in `veil-core::hub` (WASM-safe), used by S6 and S9 later. |
| **2** | **S6, S8, S9, S13, S17, S27** | S6 and S8 both use S3's promisor, not each other's code. S17 needs S4, S10 and S12. S27 touches the object store encoding (`store.rs`) and the fetch protocol's framing only. |
| **3** | **S7, S11, S14, S15, S18, S21, S22, S24, S28** | S11 needs S8's workspace socket. S22 also needs S2. S14 and S15 are separate modules (`derive/blame.rs`, `search/`). |
| **4** | **S16, S19, S23, S25, S29, G2** | G2 runs when S3–S11 and S27–S29 are in. |
| **5** | **S20, S26 (if approved)** | G3 is part of S16. |
| **6** | **G4** | The landing part of G4 (1,000/s into one `main`) can run as soon as S17, S18 and S24 are in; the bisect part waits for S20. |

**Critical path to 1,000 landings/s into one `main`:** S4 + S10 → S17 → S18 and S24 → the landing part of G4. Four waves.

**Critical path to workspaces in seconds:** S3 + S5 → S6 + S8 → G2.

**Cost and speed work outside the milestones** (BUG-864 server memory, BUG-865 parallel push checks, commit and clone-one-folder speed): `storage-and-cost.md` §10.

**Memory on the build machine:** each agent's builds take several GB. The owner asked to watch RAM: run at most as many building agents as the machine's memory allows (use `bash ~/.cache/veil-orch/verify-fast.sh`, which deletes `target/` when done), and start the rest when one finishes.

## Plan to the DigitalOcean test (as of 2026-11-08)

The owner's goal: every milestone of phases 1–4 built, reviewed and merged, then one test on DigitalOcean (budget under $100, asked for before anything is rented). Each tier-A milestone goes through the review loop of `.claude/skills/veil-review/SKILL.md` (at most three cycles, then the approach is re-evaluated, as S3's names and fetching were).

### Where each milestone stands

| State | Milestones |
|---|---|
| **Merged into `integration`** | S1, S2 (phase 1); S3, S4, S5, S8, S9, S10, S27 (phase 2); S12, S13, S15 (phase 3); S24 part A (phase 4) |
| **Built, in final review or fixing** | S6, S11, S28 (phase 2); S14 (phase 3); S17, S21 (phase 4); the deployment kit |
| **Being built** | — (S25 part A paused) |
| **Not started** | S7, S29 (phase 2); S16 (phase 3); S18, S19, S20, S22, S23, S24 part B, S26 (phase 4); the gate runs G2, G3 (in S16), G4 |

### Remaining waves

| Wave | Starts when | Milestones | What each carries beyond its row |
|---|---|---|---|
| **A** | S3 merges | **S6, S8** | S8: `vl ws exec --private-ports` and `--seed SRC:DEST` (phase 2 §4.9, owner idea); S6: the promisor's tips refreshed after every pull (the S3 review's note) |
| **A** | S28 merges | **S29** | **a retention window for unreferenced objects** (thin clones made by S3 keep no anchors, so garbage collection must keep a deleted object long enough for any clone that still names it); unreferenced search segments (S15) |
| **A** | S17 merges | **S18, S24**, S21's landing follow-up | S24: BUG-1187 (the server buffers request bodies with no connection cap); S21 follow-up: `vl pr land` submits to S17, and **landing onto a protected branch meets the review rules** by every route (owner decision, `HUB.md` §13.24) |
| **B** | S6 / S8 merge | **S7, S11** | S11: **attempts, recorded dead ends** (`vl attempt drop --reason`, phase 2 §5.6, owner idea) |
| **B** | S3, S14, S15 merge | **S16 + G3** | `vl log`/`blame`/`grep` over the query API (thin clones stop paging history for them); BUG-1214 (first blame ≈ 0.8 ms per version, gate 1 s at 10,000: parallel line maps in a bounded pool, or stored line hashes); PR search through S15's index (S21's search misses its 50 ms p99) |
| **B** | S11, S17 merge | **S19** | **agents start from `main@tested` by default** (phase 4 §4.7, owner idea) |
| **B** | S17 + S2 | **S22** | |
| **B** | S21 merges | **S25** | |
| **C** | S21, S22 | **S23** | |
| **C** | S14, S19 | **S20** | |
| **C** | phase 2 in | **G2** | Git beside Veil on the 1 GB profile (thin and full clone, status, log), on a quiet machine |
| **D** | S17, S18, S24 (landing), S20 (bisect) | **G4** | |
| — | owner approves | S26 | not in the first web client unless approved (product decision 13) |

### Also on the plan (not milestones)

* **Phase 1's final security pass** over the client, after S3 merges (thin clones change the client's trust surface most).
* **The test sweep** (tests that pass when their action fails, the `CLAUDE.md` rule of 2026-11-08): run once over all tests, then held by review.
* **Guide recipe: fork and race** (`vl ws new try-a -r @` … `vl ws exec` in parallel; keep the winner, record the rest as attempts).
* **Clean-ups filed during reviews:** the search index resumed twice for one project at start (S15 cycle 2 note); the landing batch limit (64) re-measured once packs (S28) land.
* **The deployment kit, then the DigitalOcean test:** a server image, YugabyteDB or PostgreSQL, object storage, `vl` on agent machines; the gate benchmarks at the real scale. **Asked of the owner before anything is rented.**

## Product decisions for the owner (from all three documents)

Each document lists its own with the reasoning; in short:

| # | Decision | Recommendation | Document |
|---|---|---|---|
| 1 | Removal of access takes about 2 s (at most 5) at caches; immediate at the server | accept, and say so in `VISIBILITY.md` | phase 2 §10.1 |
| 2 | Agent sessions: short-lived, made automatically from the person's, at most as wide; not API keys | yes | phase 2 §10.2 |
| 3 | `vl clone` thin by default on server projects (`--full` for everything) | yes | phase 2 §10.3 |
| 4 | macOS: sparse checkouts by default; mounts only with macFUSE; "seconds on any size" is a Linux guarantee | yes | phase 2 §10.4 |
| 5 | The daemon runs by default and watches working copies | yes, with an off switch | phase 2 §10.5 |
| 6 | Descriptions of mixed changes are searchable only by people who see the whole change | yes | phase 3 §9.1 |
| 7 | Code search covers `main`, branch tips and open PRs; names across all history | yes | phase 3 §9.2 |
| 8 | Embargoed merges into a busy `main` live on a hidden embargo line and land on `main` at release | yes | phase 4 §11.1 |
| 9 | On-time embargo release with a public time-lock beacon (drand), or a release machine | time-lock by default, release machine as the alternative | phase 4 §11.2 |
| 10 | PRs named by short random ids, not numbers | yes | phase 4 §11.3 |
| 11 | Automatic revert of a confirmed culprit without asking | yes on protected `main` | phase 4 §11.4 |
| 12 | Which risks need a person's approval; whether agents' approvals count | low: checks only; normal: one approval; high: one person | phase 4 §11.5 |
| 13 | Secrets in the browser | not in the first web client | phase 4 §11.6 |
| 14 | Review and branch rules in a tracked `.veilrules`, changed only by admins | yes | phase 4 §11.7 |
| 15 | Protected `main` by default; `vl push` lands instead | yes | phase 4 §11.9 |
| 16 | Health metrics for admins only | yes | phase 4 §11.10 |
| 17 | **Paid gate hardware** (several machines, a three-node YugabyteDB cluster) for the 10,000-agent gates | needs approval before anything is rented | phase 2 §10.6, phase 4 §11.8 |
