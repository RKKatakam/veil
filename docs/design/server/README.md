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
| S3 | 2 | Fetch on demand in the client (thin clones, bounded cache, no full graph) | S1, simplification pass |
| S4 | 2 | Request-path caches (permissions, sessions, snapshot resolution, tips invalidated without a hot row), **one database commit per push**, and the cost gates in `veil-bench load` (`storage-and-cost.md` §3–5, §9) | S1 |
| S5 | 2 | Read grants, the object routes, access epochs | S1 |
| S6 | 2 | The Veil daemon: shared object cache | S3, S5 |
| S7 | 2 | The daemon's file watcher (`status`/`commit` without a scan) | S6 |
| S8 | 2 | Workspaces that fetch on first read; the workspace socket for sandboxes | S3; phase 1's isolated sandboxes (S6 for the warm numbers) |
| S9 | 2 | Regional cache | S5 |
| S10 | 2 | Commits through the API (with the server-side secret scan) | S1 |
| S11 | 2 | Agent sessions and attribution | S10, S8 |
| S27 | 2 | Compressed objects (zstd) in storage and transport (`storage-and-cost.md` §6). **Built** (`HUB.md` §13.13) | S1 |
| S28 | 2 | Packs: one storage write per push for small objects, index, range reads (`storage-and-cost.md` §7) | S5, S27 |
| S29 | 2 | Merging packs and pack garbage collection (`storage-and-cost.md` §8) | S28 |
| G2 | 2 | Phase 2 gate run | S3–S11, S27–S29 |
| S12 | 3 | Derived-data framework, commit graph, changed paths, per-rule lists, eager projection memos at each branch move | S1 |
| S13 | 3 | Query API with per-viewer projection, and the projection-equivalence harness | S12 |
| S14 | 3 | Blame and file history | S13 |
| S15 | 3 | Search | S13 |
| S16 | 3 | `vl` over the query API; phase 3 gate run | S3, S13, S14, S15 |
| S17 | 4 | The landing service (batched, fast path, protected branches, `vl land`) | S4, S10, S12 |
| S18 | 4 | Content merges, conflicts back to agents, the event stream | S17 |
| S19 | 4 | CI through the API; land first, test after; `main@tested` | S11, S13, S17 |
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
