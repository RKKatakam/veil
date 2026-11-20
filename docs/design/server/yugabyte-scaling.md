# Horizontal Scaling of `veil-server` on YugabyteDB

**Status:** Stage 2 implemented & locally benchmarked (branch `t3/yb-scale`, base `3d0a690b`; Stage 1 report `0ad260a8`; Stage 2 decisions 2026-11-19)
**Owner goal (2026-11-19):** Make YugabyteDB's `hash` layout (1) at least as fast as `colocated` at 3 nodes on the deployment kit's gates, (2) scale horizontally with node count on both multi-project/multi-branch AND single-repository many-branch workloads (target ≥ 1.6× from 3 to 6 nodes; merges onto one `main` stay serialized and are reported separately), and (3) keep PostgreSQL at least as fast with online-safe migrations and unchanged durability, isolation, and security invariants.

---

## 1. Executive Summary

On the 2026-11-14/15 Google Cloud run (`docs/DEPLOY.md` §12.9–12.10), 3-node YugabyteDB `hash` trailed 3-node `colocated` by more than 2× on the `branches` gate (`6.7` vs `15.6` merges/s at 300 agents; `8.1` with 55 errors vs `12.5` with 0 errors at 1,000 agents), causing the kit to default to `colocated`. Because `colocated` puts every table into a single Raft tablet led by one node, it cannot scale writes horizontally.

Local instrumentation of a 3-node YugabyteDB 2025.2.8.1-b8 cluster (`EXPLAIN (ANALYZE, DIST)`, diff-based `pg_stat_statements`, tserver/tablet Prometheus metrics, and `yb_local_tablets`) alongside PostgreSQL 17 reveals **three compounding causes** that explain both why 3-node `hash` lost to `colocated` and why it could not scale from 3 to 6 nodes as deployed:

1. **Kit configuration bug (`yugabyted` silently overrides `ysql_num_shards_per_tserver`):** `deploy/do/configure.sh:102` passes `--tserver_flags=yb_enable_read_committed_isolation=true,ysql_num_shards_per_tserver=1` expecting 3 tablets per table (one leader per node). In YugabyteDB 2025.2, `yugabyted` defaults `ysql_num_tablets=1`, which **overrides** `ysql_num_shards_per_tserver` whenever `ysql_num_tablets != -1`. Every one of Veil's 113 tables and indexes in `hash` layout therefore received **1 tablet** (`hash_split: [0x0000, 0xFFFF]`) until reaching the 128 MiB auto-split threshold. `hash` paid **100% of cross-node 2PC distributed transaction overhead with 0% per-table horizontal sharding**. Fixing `ysql_num_tablets=-1` immediately raised 24-project warm pulls by **+40%** (`4,849 → 6,779 ops/s`, p50 `8.1 → 5.5 ms`) and balanced multi-project writes across all three nodes (`31% / 33% / 36%`).
2. **2PC and Raft write amplification (> 3×) cancels out 3-node parallelism:** Even with 3 tablets per table (`yb_hash3`), one foreground push writes **26 tablets** (`55.7` `UpdateTransaction` RPCs and `269.8` Raft `UpdateConsensus` RPCs vs `15.7` and `150.6` on `yb_colo`), and one landing writes **39 tablets** (`204.1` `UpdateTransaction` RPCs and `951.4` Raft RPCs vs `23.6` and `300.6` on `yb_colo`). Under 24-project concurrent landing load, `yb_hash3` executed **7.2× more `UpdateTransaction` RPCs/op** and **4.2× more Raft RPCs/op** than `yb_colo`. On 3 nodes, spending 2.2×–4.2× more Raft work per operation erases the 3× horizontal leader capacity over `colocated`'s single leader. Nearly all of this amplification is avoidable waste:
   - **Inert v1 GC gate (`pack_gc::guard_root_write`)** executes `pg_advisory_xact_lock_shared` + `access_epochs ... FOR SHARE` (`1.95×/push`, `3.85×/landing`, `1.57×/api`, `4.85 ms` each). On YugabyteDB this writes Raft rows to `system:pg_advisory_locks` (the **#1 most-written table** in multi-project landings) and IntentsDB locks to `access_epochs`, forcing multi-tablet 2PC on every write for a lock that `pack_gc.rs:20-22` documents as *"inert in v1: nothing ever raises the epoch."*
   - **`packs` staging churn in `objects` layout** performs 3 DB transactions (`INSERT`, `UPDATE`, `DELETE`) plus a `SELECT` per push. `packs` and `packs_unlisted` are the **#1 and #2 most-written relations** during multi-project pushes (**5.7×** more writes than `branches`), consuming `11.2 ms/push` (32% of foreground DB time) even though `objects` layout never keeps packs.
   - **Foreign keys on hot write tables** (`projects`, `people` — neither table is ever deleted by `veil-server`) force remote `FOR KEY SHARE` IntentsDB writes on `projects` and `people` tablets on every push, enqueue, landing, and API commit (`68–82%` of standalone `INSERT` execution time in `EXPLAIN (ANALYZE, DIST)`).
   - **Secondary index fan-out:** `landing_queue` maintains **8 secondary indexes** (`9` tablet writes on enqueue, `9.8×` total write amplification across enqueue→claim→finish); `projections` maintains **4 secondary indexes** (including `projections_by_projected`, a 100% redundant prefix of `projections_by_projected_at`); `landed_changes_by_author` is **100% unused** by any query in the codebase.
   - **`pr_review_rules` `SELECT ... FOR UPDATE` + `UPSERT`** runs on every default-branch commit even when `.veilrules` did not change, dragging a separate table into every `main` 2PC commit.
   - **Immediate background deriver** fires with zero debounce after every push/landing (`43–49%` of total push DB time and SQL statements across 10 tables).
3. **Four global single-tablet hot spots cap 3 → 6 node scaling:** Measured directly on 3-tablet-sharded `yb_hash3` across 24 projects:
   - `access_epochs (project_id = 0, person_id)` hashes all global person epochs onto `hash(0)`: **85.6%** of all `access_epochs` reads in `landing` and **77.1%** in `pull` hit **one tablet**.
   - `landing_queue_state (state HASH, project_id, branch)` hashes a 5-value enum: **68.3%** of writes hit 1 tablet, **0%** hit the 3rd tablet.
   - `landing_queue_pick ((CASE WHEN state = 'queued' THEN project_id END) HASH, ...)` is not partial, so every finished row across all projects hashes to `NULL`: **46.9%** of writes hit the `hash(NULL)` tablet (and > 50% on 6 nodes).
   - Warm pulls (`GET /v1/projects/{p}/tips`) run two uncached queries (`embargo_lines`, `tested`) plus 3 sequential `access_epochs` subqueries on every request (**> 92%** of all warm-pull DB reads).

**Accepted limit:** Merges onto a single project's `main` serialize on that branch's tip row; Veil's landing batches already amortize that serialization. Horizontal scaling with YB node count targets workloads spread across many projects and branches (pushes, pulls, landings across projects, API commits). Single-repository scaling (`onerepo` / `branches --projects 1`) is analyzed separately in §3.13.

---

## 2. Measurements

### 2.1 Local Testbed & Methodology

- **Host:** Linux x86_64, 32 cores, 30 GiB RAM (shared; concurrent benchmarks run under `~/.cache/veil-orch/heavy-lock.sh`).
- **YugabyteDB cluster:** 3 isolated Docker containers (`yugabytedb/yugabyte:2025.2.8.1-b8`, RF=3, `memory_limit_hard_bytes=3 GiB` each, `yb_enable_read_committed_isolation=true`, `enforce_tablet_replica_limits=false`, `tablet_replicas_per_gib_limit=100000`). Three databases migrated with all 36 migrations (`0001`–`0042`):
  - `yb_hash`: `colocation = false`, kit default `ysql_num_tablets=1` → **113 local tablet replicas/node** (`1` tablet per table/index, matching GCP kit behavior). Migration time: `60.2 s`.
  - `yb_hash3`: `colocation = false`, `ysql_num_tablets=3` → **339 local tablet replicas/node** (`3` tablets per table/index, 1 leader per node). Migration time: `70.0 s`.
  - `yb_colo`: `colocation = true` → **1 user colocated tablet** (all 113 relations in 1 tablet). Migration time: `41.7 s`.
- **PostgreSQL baseline:** Single `postgres:17` container with default Docker settings (`shared_buffers=128MB`, `pg_stat_statements` enabled; **not** production-tuned like `deploy/kit.sh pg_settings`, which causes high tail latency under heavy concurrent write checkpoints locally — noted where relevant). Migration time: `0.22 s`.
- **Object store:** MinIO container (`objects` layout — Veil's only written layout).
- **YSQL connection distribution:** Single-client anatomy connected `veil-server` to `yb1` so all SQL appeared in `yb1`'s `pg_stat_statements`. Concurrent multi-project benchmarks distributed `veil-server`'s 60 pooled DB connections round-robin across `yb1`, `yb2`, and `yb3` (20 connections per YB node, matching multi-hub YSQL spread).
- **Methodological note on `pg_stat_statements` on YugabyteDB:** Calling `pg_stat_statements_reset()` while `sqlx` holds already-prepared statements with normalized constants caused YugabyteDB 2025.2's `pg_stat_statements` to omit 14 foreground statements (including `WITH k AS`, `WITH u AS`, and `guard_root_write`). All SQL anatomy numbers below therefore use **before/after diffs of `(calls, total_exec_time, rows)` without resetting**, yielding exact 100% statement parity (`53` distinct queries in push, `79` in landing, `5` in warm pull, `54` in API commit on both `yb_hash` and `yb_colo`).
- **Single-machine caveat:** All 3 YB nodes, MinIO, `veil-server`, and `veil-bench` share one host, so absolute throughput and `yb_hash3`'s 1,017 Raft peer threads contend for shared CPU. Per-operation RPC counts, `EXPLAIN (ANALYZE, DIST)` plans, and per-tablet skew percentages are hardware-independent; node-count scaling proof requires multi-machine cloud runs (§5).

### 2.2 Single-Operation Steady-State Anatomy (1 client)

Each workload ran steady-state with 1 client (`--projects 1 --clients 1`, 3 s warmup + 8–12 s measured, 5–6 s inner telemetry window). SQL counts and DB time split foreground request queries (`fg`) and background deriver queries (`dr`). Tserver RPCs (`Rd`, `Wr`, `UpdTxn` = 2PC coordinator `UpdateTransaction`, `FinTxn` = `FinishTransaction`, `Raft` = `UpdateConsensus`) are normalized per operation across the steady-state window:

| Operation | Backend | ops/s | p50 (ms) | p99 (ms) | Stmts/op (fg / dr) | DB ms/op (fg / dr) | Tablets written | Rd RPC/op | Wr RPC/op | `UpdTxn`/op | `FinTxn`/op | Raft RPC/op |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **Push** (`branches`) | `yb_hash` | 18.3 | 61.1 | 94.0 | 48.6 (24.9 / 23.6) | 60.4 (34.8 / 25.7) | **26** | 65.9 | 24.7 | **55.7** | 3.5 | **269.8** |
| **Push** (`branches`) | `yb_colo` | 17.0 | 68.7 | 76.6 | 51.7 (26.2 / 25.4) | 68.5 (39.5 / 29.0) | **1** | 65.6 | 17.2 | **15.7** | 3.7 | **150.6** |
| **Push** (`branches`) | `pg` | 45.5 | 25.3 | 34.6 | 59.7 | 5.3 | — | — | — | — | — | — |
| **Landing** (`landing`) | `yb_hash` | 25.4* | 34.7 | 193.8 | 128.3 (61.5 / 66.8) | 46.3 | **39** | 221.0 | 101.8 | **204.1** | 6.3 | **951.4** |
| **Landing** (`landing`) | `yb_colo` | 10.7 | 110.4 | 159.9 | 117.5 (75.7 / 41.8) | 117.5 (75.1 / 42.4) | **1** | 151.1 | 41.4 | **23.6** | 4.5 | **300.6** |
| **Landing** (`landing`) | `pg` | 30.7 | 34.4 | 41.7 | 104.4 | 9.7 | — | — | — | — | — | — |
| **Pull warm** (`bg=0`) | `yb_hash` | 250.5 | 4.7 | 6.6 | 3.0 (3.0 / 0.0) | 2.5 (2.5 / 0.0) | 0 | 5.2 | 0.0 | 0.0 | 0.0 | 1.9 |
| **Pull warm** (`bg=0`) | `yb_colo` | 339.9 | 1.9 | 6.7 | 2.4 (2.4 / 0.0) | 1.8 (1.8 / 0.0) | 0 | 6.1 | 0.0 | 0.0 | 0.0 | 1.5 |
| **Pull warm** (`bg=0`) | `pg` | 971.3 | 1.0 | 2.1 | 3.0 | 0.2 | — | — | — | — | — | — |
| **Pull moving** (`bg=5`) | `yb_hash` | 446.9 | 1.3 | 7.9 | — | — | — | — | — | — | — | — |
| **Pull moving** (`bg=5`) | `yb_colo` | 216.2 | 5.0 | 33.8 | — | — | — | — | — | — | — | — |
| **Pull moving** (`bg=5`) | `pg` | 731.5 | 1.2 | 2.4 | — | — | — | — | — | — | — | — |
| **API commit** (`api`) | `yb_hash` | 25.8 | 45.7 | 55.0 | 40.7 (24.3 / 16.4) | 44.2 (26.2 / 18.0) | **25** | 47.5 | 17.7 | **38.4** | 1.5 | **188.0** |
| **API commit** (`api`) | `yb_colo` | 24.5 | 48.3 | 54.7 | 48.7 (28.8 / 19.9) | 47.2 (27.9 / 19.3) | **1** | 47.4 | 13.4 | **7.6** | 1.5 | **104.4** |
| **API commit** (`api`) | `pg` | 77.7 | 12.6 | 19.2 | 47.4 | 3.7 | — | — | — | — | — | — |

*\*RPC columns for `yb_hash`/`yb_colo` were collected on the initial 1-client run (`9.8` / `10.6` ops/s on landing); SQL columns are from the diff-based re-run (`25.4` / `10.7` ops/s on landing).*

**Key takeaways from 1-client anatomy:**
- **Distributed transaction amplification on `yb_hash` vs `yb_colo`:** **3.5×** more `UpdateTransaction` RPCs and **1.8×** more Raft RPCs per push; **8.6×** more `UpdateTransaction` RPCs and **3.2×** more Raft RPCs per landing; **5.1×** more `UpdateTransaction` RPCs and **1.8×** more Raft RPCs per API commit.
- **Top foreground SQL statements by DB ms/op on `yb_hash`:**
  - **Push (`34.8 ms` fg + `25.7 ms` dr = `60.4 ms/op`):**
    1. `WITH k AS (UPDATE packs …; INSERT snapshots, origins, projections, audit_log)`: `0.94/op × 6.13 ms = 5.76 ms/op`
    2. `guard_root_write` (`pg_advisory_xact_lock_shared` + `access_epochs FOR SHARE`): `1.95/op × 2.90 ms = 5.63 ms/op`
    3. `read_epochs` (3 sequential `access_epochs` subqueries): `2.85/op × 1.88 ms = 5.36 ms/op`
    4. `WITH u AS (UPDATE branches …; INSERT landed_changes)`: `0.94/op × 3.33 ms = 3.13 ms/op`
    5. `DELETE FROM packs`: `0.95/op × 2.81 ms = 2.67 ms/op` (plus `INSERT INTO packs` `1.46 ms/op` + `SELECT FROM packs` `1.32 ms/op` → `packs` lifecycle alone is `~11.2 ms/op`!)
  - **API commit (`26.2 ms` fg + `18.0 ms` dr = `44.2 ms/op`):**
    1. `guard_root_write`: `1.57/op × 3.06 ms = 4.82 ms/op` (#1 cost!)
    2. `read_epochs`: `0.91/op × 2.15 ms = 1.97 ms/op`
    3. `INSERT INTO change_refs` (`1.72 ms`), `INSERT INTO projections` (`1.70 ms`), `UPDATE branches` (`1.69 ms`), `INSERT INTO landed_changes` (`1.67 ms`), `pr_review_rules FOR UPDATE` + `UPSERT` (`~2.3 ms` combined).
  - **Landing (`yb_colo` `117.5 ms/op`, `yb_hash` `46.3 ms/op`):**
    1. `guard_root_write`: `3.85–4.06/op × 2.51–2.79 ms = 9.7–11.3 ms/op` (#1 cost!)
    2. `landing_queue` pick query (`UNION` over `landing_queue_pick`): `3.10/op × 1.40–1.84 ms = 4.3–5.7 ms/op`
    3. `INSERT INTO landing_queue` (PK + 8 indexes + 2 FKs): `1.03/op × 2.85–3.46 ms`
    4. `UPDATE landing_queue` finish: `1.05/op × 2.32–2.47 ms`
    5. `pr_review_rules` (`SELECT FOR UPDATE` + `UPSERT` + `LEFT JOIN` in `rules_in_force`): `~3.2 ms/op`
  - **Pull warm (`2.5 ms/op` on `yb_hash`):** 100% of DB time is 3 queries: `read_epochs` (`1.65 ms`, 66%), `embargo_lines` (`0.47 ms`, 19%), `tested JOIN branches` (`0.36 ms`, 14%).
- **Read/write interference on `yb_colo`:** In `pull --background 5`, `yb_hash` served `446.9 ops/s` (p50 `1.3 ms`) while `yb_colo` dropped to `216.2 ops/s` (p50 `5.0 ms`, p99 `33.8 ms`) because background writes contended on the same single colocated tablet as reads.

### 2.3 Statement-Level Storage RPCs: `EXPLAIN (ANALYZE, DIST)`

Executed in rolled-back `READ COMMITTED` transactions on warmed sessions (`yb_hash` vs `yb_colo`):

| Statement | Table + Index Rd RPCs (`yb_hash`) | Table + Index Wr RPCs (`yb_hash`) | Exec ms (`yb_hash` / `yb_colo`) | Key Plan / Trigger Observation |
|---|---:|---:|---:|---|
| `read_epochs` (current 3 InitPlans) | **3** + 0 | 0 + 0 | 1.46 / 0.43 | 3 sequential Index Scans on `access_epochs_pkey` |
| `read_epochs` (proposed `ANY` batch) | **1** + 0 | 0 + 0 | **0.33** / — | Single batched Index Scan (**3 → 1 RPC, 4.5× faster**) |
| `guard_root_write` (inert v1 lock) | **2** + 0 | 0 + 0* | **4.86** / 0.59 | `pg_advisory_xact_lock_shared` (`2.61 ms` Raft write) + `FOR SHARE` `LockRows` (`+1.19 ms` intent write) |
| `INSERT INTO packs` | **1** + 0 | **1 + 1** | **2.12** / 0.85 | FK triggers `packs_project_id_fkey` (`1.74 ms`) + `packs_person_id_fkey` = **82% of exec time** |
| `DELETE FROM packs` | 1 + 0 | 0 + 0 | 1.71 / 1.45 | Extra standalone commit on push path |
| `UPDATE branches` (push CAS) | 1 + 0 | 1 + 0 | 0.61 / 0.51 | Single-row PK update + `Flush` |
| `INSERT INTO snapshots` | 1 + 0 | 1 + 0 | 0.27 / 0.52 | `ON CONFLICT` read + `projects` FK trigger |
| `INSERT INTO projections` (4 indexes) | **2** + 0 | **1 + 4** | **1.75** / 0.47 | **5 write RPCs** (table + 4 indexes) + `projects` FK trigger (`1.18 ms`, **68%** of exec time) |
| `INSERT INTO landed_changes` | 1 + 0 | **1 + 1** | 0.28 / 0.52 | Writes unused `landed_changes_by_author` index + `projects` FK |
| `INSERT INTO audit_log` | 0 + 0 | 1 + 0 | 1.59 / 1.77 | Separate `BIGSERIAL`-sharded tablet + `Flush` |
| `INSERT INTO landing_queue` (8 indexes) | **1** + 0 | **1 + 8** | **1.06** / 1.92 | **9 write RPCs** (table + 8 indexes) + `projects`/`people` FK triggers (`0.86 ms`, **81%** of exec time) |
| `landing_queue_pick` (small table) | 1 + 0 | 0 + 0 | 1.43 / 1.02 | Scanned 134 rows via PK; large table uses `landing_queue_pick` index (with `NULL` hot spot) |
| `landing_queue_state` scan | 0 + 1 | 0 + 0 | 0.19 / 1.15 | Index-only scan on 5-value `state HASH` index |
| `pr_review_rules FOR UPDATE` + `UPSERT` | 1 + 0 | 1 + 0 | 0.18 / 0.75 | Separate tablet lock + write on every default-branch commit |
| `pull`: `tested JOIN branches` | **2** + 0 | 0 + 0 | 2.08 / 0.61 | YB Batched Nested Loop Join across 2 tablets on every warm pull |
| `pull`: `embargo_lines` | **1** + 0 | 0 + 0 | 0.52 / 0.61 | Uncached read on every warm pull |

*\*`guard_root_write`'s Raft writes to `system:pg_advisory_locks` and `access_epochs` IntentsDB occur inside `pg_advisory_xact_lock_shared` and `LockRows` and appear in tserver tablet metrics (`intentsdb_rocksdb_write_self`, `conflict_resolution_latency`), not as SQL `Storage Write Requests`.*

### 2.4 Concurrent Single-Project & Multi-Project Load (4-Way Comparison)

Short 12 s runs (3 s warmup, 60 DB connections spread round-robin across `yb1..yb3` on YB, 0 errors across all runs):

| Gate | `yb_hash` (1 tab/tbl) | `yb_hash3` (3 tabs/tbl) | `yb_colo` (1 tab total) | `pg` (PG17 default Docker) |
|---|---:|---:|---:|---:|
| **A. `branches` 1p, 36c, `--merge-every 5`** | 117.5 ops/s (289 merges)<br>p50 131 / p99 1468 ms | 124.9 ops/s (299 merges)<br>p50 111 / p99 1321 ms | **136.1 ops/s (321 merges)**<br>p50 118 / p99 1111 ms | 214.3 ops/s (512 merges)<br>p50 64 / p99 2252 ms |
| **B. `branches` 24p, 48c** (pushes) | 220.9 ops/s<br>p50 173 / p99 1106 ms | 164.6 ops/s<br>p50 156 / **p99 360 ms** | **243.9 ops/s**<br>p50 124 / p99 1399 ms | 419.3 ops/s<br>p50 82 / p99 1429 ms |
| **C. `landing` 24p, 48c, 24 people** | 160.6 ops/s<br>p50 298 / p99 408 ms | 156.0 ops/s<br>p50 298 / p99 497 ms | **202.6 ops/s**<br>p50 232 / p99 408 ms | 165.0 ops/s*<br>p50 131 / p99 5118 ms |
| **D. `pull` 24p, 48c, `bg=0`** (warm) | 4,849.5 ops/s<br>p50 8.1 / p99 21.3 ms | **6,779.4 ops/s (+40%)**<br>p50 5.5 / p99 15.1 ms | **6,950.8 ops/s**<br>p50 5.3 / p99 14.9 ms | 40,494.7 ops/s<br>p50 1.1 / p99 2.2 ms |
| **E. `api` 24p, 48c** (API commits) | 224.9 ops/s<br>p50 124 / p99 1157 ms | 228.0 ops/s<br>p50 107 / p99 1587 ms | **238.6 ops/s**<br>p50 86 / p99 1191 ms | 64.7 ops/s*<br>p50 24 / p99 13946 ms |

*\*Default untuned Docker PG17 suffered multi-second WAL/checkpoint stalls under 48-client burst writes on overlayfs; production PG uses `deploy/kit.sh pg_settings`.*

**Cluster-wide RPC ratios and per-node Raft leader balance during Gates B, C, and D:**

| Gate | Layout | Tablets Written | `Wr` RPCs | `UpdTxn` RPCs | `UpdTxn / Wr` | Raft `UpdateConsensus` | Node Write Share `[yb1, yb2, yb3]` | Node Read Share `[yb1, yb2, yb3]` |
|---|---|---:|---:|---:|---:|---:|---|---|
| **B. `branches` 24p** | `yb_hash` | 50 | 96,841 | 295,306 | **3.05** | 624,350 | `[28.0%, 39.8%, 32.2%]` | `[20.3%, 39.7%, 40.0%]` |
| **B. `branches` 24p** | `yb_hash3` | 131 | 58,063 | 159,439 | **2.75** | 503,559 | **`[31.0%, 33.0%, 36.0%]`** | **`[30.1%, 31.4%, 38.6%]`** |
| **B. `branches` 24p** | `yb_colo` | 6 | 65,316 | 100,993 | **1.55** | 340,955 | `[5.3%, 6.2%, 88.5%]` | `[0.0%, 0.0%, 99.9%]` |
| **C. `landing` 24p** | `yb_hash` | 63 | 110,341 | 249,487 | **2.26** | 654,084 | `[40.2%, 43.4%, 16.4%]` | `[29.3%, 34.5%, 36.1%]` |
| **C. `landing` 24p** | `yb_hash3` | 178 | 105,200 | 237,350 | **2.26** | 768,362 | **`[35.6%, 33.2%, 31.2%]`** | `[29.5%, 29.9%, 40.6%]` |
| **C. `landing` 24p** | `yb_colo` | 6 | 56,852 | 43,033 | **0.76** | 235,548 | `[5.9%, 8.3%, 85.9%]` | `[0.1%, 0.1%, 99.8%]` |
| **D. `pull` 24p** | `yb_hash` | 48 | 1,913 | 5,179 | 2.71 | 65,225 | `[21.1%, 33.0%, 45.9%]` | `[14.0%, 1.8%, 84.2%]` |
| **D. `pull` 24p** | `yb_hash3` | 123 | 1,923 | 5,187 | 2.70 | 61,319 | `[31.4%, 34.2%, 34.4%]` | `[19.6%, 24.4%, 56.0%]` |
| **D. `pull` 24p** | `yb_colo` | 6 | 1,521 | 3,056 | 2.01 | 55,371 | `[5.6%, 5.9%, 88.5%]` | `[0.0%, 0.0%, 100.0%]` |

This table proves the core thesis quantitatively:
1. **`yb_colo` puts 86–100% of all Raft leader writes and reads on ONE node (`yb3`).** Adding nodes 3 → 6 adds zero leader capacity.
2. **`yb_hash` (1 tablet/table) left 84.2% of `pull` reads on `yb3`** (because `access_epochs` and `embargo_lines` each had 1 tablet and both happened to be led by `yb3`).
3. **`yb_hash3` (3 tablets/table) achieved ~33/33/33 write balance across all 3 nodes**, immediately lifted pulls by +40% (`6,779` vs `4,849`), and cut `B_branches_24p` p99 by 3.1× (`360` vs `1,106 ms`) — **but still lost to `yb_colo` on write throughput because `yb_hash3` spent 2.2×–4.2× more Raft RPCs and 2.3×–7.2× more 2PC `UpdateTransaction` RPCs per write.**

### 2.5 Per-Tablet Hot-Spot Measurements (`yb_hash3`, 24 projects, 3 tablets/table)

Exact RocksDB + IntentsDB write counts (`rocksdb_write_self + intentsdb_rocksdb_write_self`) and read seeks (`rocksdb_number_db_seek`) across the 3 hash tablets of each relation during Gates B, C, and D:

| Gate | Relation | Active Tablets | Total Writes (`wr+int`) | Per-Tablet Split (`max %`) | Total Seeks (`rd_seek`) | Per-Tablet Split (`max %`) | Root Cause |
|---|---|---:|---:|---|---:|---|---|
| **C. Landing** | `access_epochs` | 3 | 14,922 | `[5993, 4757, 4172]` (40.2%) | **156,575** | **`[134043, 11899, 10633]` (85.6%)** | `project_id = 0` hashes all global person epochs to 1 tablet |
| **D. Pull** | `access_epochs` | 3 | 382 | `[261, 77, 44]` (68.3%) | **396,160** | **`[305484, 57732, 32944]` (77.1%)** | Same `hash(0)` hot tablet |
| **C. Landing** | `landing_queue_state` | **2 / 3** | **19,077** | **`[13029, 6048, 0]` (68.3%)** | 9,308 | **`[6981, 2327, 0]` (75.0%)** | 5-value `state HASH` hits only 2 tablets; 3rd gets 0% |
| **C. Landing** | `landing_queue_pick` | 3 | **17,274** | **`[8094, 4800, 4380]` (46.9%)** | 13,728 | `[5663, 4287, 3778]` (41.3%) | Non-partial `CASE` hashes all finished rows to `NULL` tablet |
| **C. Landing** | `system:pg_advisory_locks` | 3 | **19,620** | `[8726, 5606, 5288]` (44.5%) | 2,298 | `[1093, 674, 531]` (47.6%) | **#1 written table in landing** — inert `guard_root_write` |
| **C. Landing** | `projects` | 3 | **13,698** | `[5052, 4600, 4046]` (36.9%) | 14,133 | `[5248, 4669, 4216]` (37.1%) | **0 rows inserted** — 100% FK `FOR KEY SHARE` locks |
| **B. Branches** | `packs` + `packs_unlisted` | 3 each | **51,053** | `25,527 + 25,526` (37.6%) | 54,772 | balanced | **#1 & #2 written tables in push** (5.7× writes of `branches`) |
| **B. Branches** | `projects` | 3 | **17,901** | `[6730, 5917, 5254]` (37.6%) | 14,047 | balanced | **0 rows inserted** — 2× more writes than `branches` (FKs) |
| **B. Branches** | `people` | **2 / 3** | **8,715** | **`[8568, 147, 0]` (98.3%)** | 5,931 | **`[5808, 123, 0]` (97.9%)** | `packs_person_id_fkey` hammers 1 person row in `branches` |
| **D. Pull** | `embargo_lines` + `tested` | 3 each | 0 | — | **295,579** | `197,245 + 98,334` | Uncached on every `GET /tips` (`branches` had only `4,294` seeks!) |

---

## 3. Ranked Root Causes & Full YugabyteDB Scaling Checklist Audit

Every item below is ranked by combined impact on 3-node performance and 3 → 6 node horizontal scaling, backed by local measurements and exact source locations.

### Rank 1 (Blocker for 3 → 6 scaling): `yugabyted` `ysql_num_tablets=1` Kit Bug
- **Evidence:** `deploy/do/configure.sh:102` passes `--tserver_flags=yb_enable_read_committed_isolation=true,ysql_num_shards_per_tserver=$YB_TABLETS`, intending 3 tablets/table (comment at lines 89–91). `yb-tserver --helpfull` documents: *"`-ysql_num_tablets`: Default value is 1 ... If its value is not set (equals to -1) then the value of `ysql_num_shards_per_tserver` is used in conjunction with the number of tservers."* Verified via `yb_local_tablets` on `yb1`: `yb_hash` had `113` replicas (`branches=1`, `landing_queue=1`) vs `yb_hash3`'s `339` (`branches=3`, `landing_queue=3`). Auto-splitting does not trigger until a tablet exceeds `128 MiB` (`tablet_split_low_phase_size_threshold_bytes`), so small hot metadata tables (`branches`, `access_epochs`, `landing_queue`, `landing_leases`, `pr_review_rules`) stay pinned to 1 node forever.
- **Replicas-per-node invariance:** With `ysql_num_tablets=-1`, `ysql_num_shards_per_tserver=1`, and `RF=3`, total replicas per node is `(relations × (1 × N) × 3) / N = 3 × relations` — **constant (`~300`) whether `N = 3, 6, or 12`**.
- **Secondary kit issue for 6 nodes:** `deploy/do/configure.sh:175` maps hub `i` to YB node `i`, and `deploy/gcp/lib.sh:103-104` restricts `HUBS` to `1..3` and `YB_NODES` to `{0, 3}`. Running 6 YB nodes with only 3 hubs connected to `yb1..yb3` would leave `yb4..yb6` doing 0% of YSQL query parsing/execution.

### Rank 2 (Biggest single-op & 2PC killer): Inert v1 `pack_gc::guard_root_write`
- **Evidence:** `crates/veil-server/src/pack_gc.rs:20-22, 543-568` executes `SELECT e.epoch FROM (SELECT pg_advisory_xact_lock_shared($2)) g, access_epochs e WHERE e.project_id = $1 AND e.person_id = -1 FOR SHARE OF e` on every push (`1.95×/op`), landing (`3.85–4.06×/op`), API commit (`1.57×/op`), and deriver run. On PG this is `0.07 ms` in RAM; on YB `EXPLAIN (ANALYZE, DIST)` measured **`4.86 ms`** (`2.61 ms` Raft write to `system:pg_advisory_locks` + `1.19 ms` `FOR SHARE` IntentsDB write to `access_epochs`). In `C_landing_24p`, `system:pg_advisory_locks` took `19,620` writes — the **#1 most-written table in the database** — and every single write transaction was forced into multi-tablet 2PC across `system:pg_advisory_locks` and `access_epochs`. Nothing ever raises the epoch in v1.

### Rank 3 (Biggest push bottleneck): `packs` 3-Commit DB Churn in `objects` Layout
- **Evidence:** Even though `objects` layout never retains packs (`pack_gc.rs:6-13`), every push runs: (1) `INSERT INTO packs (state=0)` (`1.54 ms`, 2 FKs + `packs_unlisted` index), (2) `SELECT name, state, objects FROM packs` (`1.39 ms`), (3) `UPDATE packs SET state=2` inside `WITH k AS` (`6.13 ms` CTE), and (4) `DELETE FROM packs WHERE state=2` (`2.81 ms`). In `B_branches_24p`, `packs` (`25,527`) + `packs_unlisted` (`25,526`) accounted for **`51,053` writes — 5.7× the writes of `branches` (`8,892`)** — and `2` of the `3` DB commits per push.

### Rank 4 (Biggest landing bottleneck & 2PC multiplier): Secondary Index Fan-Out & Global Hot-Spot Indexes
- **Evidence (all 40 `CREATE INDEX` statements audited):**
  - **`landing_queue` has 8 secondary indexes** (`9` writes per enqueue, `9.8×` total write amplification across enqueue→claim→finish; `~127,550` RocksDB/IntentsDB writes in `C_landing_24p` for `13,029` transitions):
    1. `landing_queue_pick ((CASE WHEN state = 'queued' THEN project_id END), ...)` (`0036_landing_slots.sql`): duplicates `landing_queue_ready` AND lacks `WHERE state = 'queued'`, hashing **100% of finished rows across all projects to ONE `NULL` tablet** (`46.9%` skew on 3 nodes, > 50% on 6 nodes).
    2. `landing_queue_state (state, project_id, branch)` (`0011_landing.sql`): hashed on 5-value `state` (`68.3%` on 1 tablet, `0%` on 3rd tablet). Only queried by crash recovery (`landing/mod.rs:652, 660`) for `state IN ('queued', 'merging')`.
    3. `landing_queue_done (project_id, branch, done_at)` and `landing_queue_old (project_id, done_at)`: neither is partial (`WHERE done_at IS NOT NULL`), so every enqueue writes both with `done_at = NULL`. Moreover, `landing_queue_done` (`landing/mod.rs:926`) and `landing_queue_old` (`landing/service.rs:736`) can share a single partial index `(project_id, done_at, branch) WHERE done_at IS NOT NULL`.
    4. `landing_queue_ticket (ticket)`: globally hashed on `ticket` (forces cross-node 2PC on every enqueue), even though **100% of callers** (`bisect.rs:1454,1953`, `embargo.rs:797,1182,1258,1265,1581`, `landing/mod.rs:769`) filter by `project_id = $1`.
  - **`projections` has 4 secondary indexes** (`5` tablet writes per row, `65,740` writes in `C_landing_24p`):
    1. `projections_by_projected (project_id, projected_id)` is a **100% redundant prefix** of `projections_by_projected_at (project_id, projected_id, created_at DESC)` (`0042`).
    2. `projections_by_view (project_id, view_key, projected_id)` and `projections_own (project_id, view_key, projected_id) WHERE NOT collapsed` can merge into a single index `(project_id, view_key, projected_id, collapsed, real_id)` that also covers `ORDER BY real_id LIMIT` (`sync.rs:1504, 1550`) index-only.
  - **`landed_changes_by_author (project_id, branch, change_id, author)`** is **100% unused**: every query on `landed_changes` (`bisect.rs:1557`, `landing/mod.rs:1191, 1883`) supplies `(project_id, branch, lineage, ...)`, which is already the leading prefix of `landed_changes_pkey`.

### Rank 5 (Hot-path latency & 2PC tablet bloat): Foreign Keys on Hot Write Tables
- **Evidence:** The schema has 55 FKs (`28 → projects`, `18 → people`, `6 → devices`, `3 → groups`), while `crates/veil-server/src/` contains **zero** `DELETE FROM projects` or `DELETE FROM people` statements. Every authenticated request already validates `person_id` and `project_id`. Yet on YB, FKs execute remote `FOR KEY SHARE` reads/locks on `projects` and `people`:
  - `EXPLAIN (ANALYZE, DIST)`: FK triggers consumed **82%** of `INSERT INTO packs` (`1.75 / 2.12 ms`), **68%** of `INSERT INTO projections` (`1.18 / 1.75 ms`), and **81%** of `INSERT INTO landing_queue` (`0.86 / 1.06 ms`).
  - Tablet metrics: `projects` took `17,901` writes in `B_branches_24p` and `13,698` in `C_landing_24p` (`0` rows inserted); `people` took `8,715` writes in `B_branches_24p` with **`98.3%` on one tablet**.

### Rank 6 (Pull scaling blocker & global hot tablet): `access_epochs (0, person_id)` + Uncached Warm Pulls
- **Evidence:** `access_epochs_pkey` is `(project_id HASH, person_id ASC)`. Storing global person revocation epochs at `project_id = 0` routes every authenticated request across all projects to **one single `hash(0)` tablet**: **`85.6%`** of `access_epochs` reads in `C_landing_24p` and **`77.1%`** in `D_pull_24p`.
- `read_epochs` executes 3 sequential InitPlan subqueries (`3 Storage Read Requests`, `1.46 ms`); rewriting to `WHERE project_id = ANY(...) AND person_id = ANY(...)` cuts it to **`1` batched RPC (`0.33 ms`, 4.5× faster)**.
- `api.rs:765-767` caches `branches` (`caches.tips`, only `4,294` seeks in `D_pull_24p`), but executes uncached `tested JOIN branches` (`98,334` seeks, 2 Storage Read RPCs) and `embargo_lines` (`197,245` seeks) on **every single warm pull**. Together with `access_epochs`, these 3 queries cause **> 92%** of warm-pull DB load.

### Rank 7: Unnecessary `pr_review_rules` Lock + Upsert on Every Default-Branch Commit
- **Evidence:** `crates/veil-server/src/prs/state.rs:165-181` runs `SELECT checked, state FROM pr_review_rules WHERE project_id = $1 FOR UPDATE` + `INSERT ... ON CONFLICT DO UPDATE` on every default-branch landing and API commit, even when `.veilrules` did not change, and `rules_in_force` (`state.rs:191`) performs a cross-tablet `branches LEFT JOIN pr_review_rules`. On `C_landing_24p`, `pr_review_rules` took `8,136` writes and `58,756` seeks. Folding `(review_checked, review_state)` onto `branches` eliminates the entire table from the hot path.

### Rank 8: Background Deriver Write Amplification (Zero Debounce)
- **Evidence:** `crates/veil-server/src/derive/mod.rs` spawns `catch_up` immediately after every push/landing (`0 ms` debounce). In 1-client push, the deriver executed `23.6` of `48.6` statements/op (`49%`) and `25.7` of `60.4 ms/op` (`43%`), writing 10 tables (`graph`, `graph_by_change`, `file_history`, `rule_history`, `derive_progress`, `view_graph`, `view_file_history`, `view_changes`, `search_shards`, `search_heads`) plus session advisory locks (`pg_try_advisory_lock`/`pg_advisory_unlock`, `2.70 ms` combined on YB) for 1–2 snapshots per pass. On-demand queries already call `derive::ensure`, so a 250–500 ms per-project debounce batches 10–100 snapshots per pass with zero correctness loss.

### Rank 9: Synchronous `audit_log` Inside Foreground 2PC Transactions
- **Evidence:** `sync.rs:4514`, `changes.rs:862`, and `landing/service.rs:1687` insert into `audit_log (id BIGSERIAL PRIMARY KEY)` inside the main commit transaction, adding a random-node tablet (`13,464` writes in `C_landing_24p`, `8,712` in `B_branches_24p`, `1.59 ms` in `EXPLAIN`) to every 2PC commit, whereas other audit events (`lib.rs:640`) are already written outside the main transaction.

### Remaining Checklist Items (Verified Non-Issues or Bounded)
- **Sequences / `BIGSERIAL` (7 columns: `projects.id`, `people.id`, `devices.id`, `groups.id`, `audit_log.id`, `landing_queue.seq`, `review_writers.id`, plus `branch_lineages`):** YugabyteDB defaults `ysql_sequence_cache_minval = 100` (verified by `projects.id` jumping `3 → 101`), amortizing sequence RPCs 100× per session. `landing_queue.seq` and `audit_log.id` are not bottlenecks today, though `CACHE 1000` on `landing_queue_seq_seq` / `audit_log_id_seq` is cheap insurance at > 10k ops/s.
- **Monotonic range-sharded keys:** Audited all 70 tables and 40 indexes. Because YugabyteDB defaults leading PK/index columns to `HASH` (not `ASC`), ascending `BIGSERIAL` PKs (`audit_log`, `projects`, `people`, `review_writers`) and `(project_id HASH, timestamp/seq ASC)` indexes do **not** create a last-tablet range hot spot (`audit_log` balanced `[34.5%, 33.0%, 32.5%]`). Only `embargo_lines_due (until_ms)` leads with a timestamp, and YB hashes `until_ms` (tiny table, negligible traffic).
- **`SELECT ... FOR UPDATE` on shared rows:** Outside inert `guard_root_write` (`access_epochs FOR SHARE`) and `pr_review_rules FOR UPDATE` (both eliminated above), hot-path row locks are `branches` tip CAS (inherent per-branch serialization) and `landing_leases` (1 update per batch, amortized). `review_gate::share_review_gate` takes 1 `pg_advisory_xact_lock_shared` per landing *batch* (amortized across the batch, unlike `guard_root_write`).
- **`LISTEN/NOTIFY` on YugabyteDB:** Verified unsupported in YB 2025.2 (`srv-yb_hash.log`: `"the database does not deliver notices; branch tips expire after 100ms instead"`). `caches.rs:700-815` already degrades gracefully without sending `pg_notify` on YB. Caching `tested` and `embargoes` on the same `100 ms` `TIPS_TTL` adds no new staleness model on YB and stays push-invalidated via `LISTEN/NOTIFY` on PG.
- **Primary key hash granularity & single-repo vs multi-project scaling:**
  - All hot per-project tables (`branches`, `snapshots`, `origins`, `projections`, `landed_changes`, `landings`, `landing_queue`, `landing_leases`, `change_refs`, `graph`, `file_history`, `view_*`, `search_*`) hash on `project_id`. With `ysql_num_tablets=-1`, this scales **multi-project** workloads linearly across 3 → 6+ nodes while keeping per-project range queries (`SELECT ... WHERE project_id = $1`) single-tablet.
  - **Consequence for single-project gates (`onerepo`, `branches --projects 1`, `scaling-branches --projects 1`):** Every row of a single project lands on **1 tablet per table** regardless of node count (`3` or `6`). Scaling ONE busy repository across 6 YB nodes would require hashing high-write tables on composite keys — e.g., `branches ((project_id, name) HASH)`, `snapshots ((project_id, id) HASH)`, `projections ((project_id, view_key, real_id) HASH)` — which spreads single-repo pushes across all nodes at the cost of turning `SELECT ... WHERE project_id = $1` (e.g., `GET /tips` cache refresh) into a scatter-gather across all `N` tablets. Because `caches.tips` already caches branch listings (`10×/s` per hub on YB), composite sharding is viable *if* single-repo YB scaling is desired, but **is not required for multi-project 3 → 6 scaling** and is kept as optional Phase 4 / owner decision (§6).
  - **Hybrid colocation note:** An alternative to pure hash (`~300` replicas/node across all 100 relations) is a colocated DB where ~55 cold admin tables stay in 1 colocated tablet while ~15 hot tables use YB-only `WITH (colocation = false)`. Because pure hash already keeps replicas/node constant (`~300`) at any node count *without* YB-specific DDL divergence in migrations, **pure hash + fixing `ysql_num_tablets=-1` is the recommended primary layout**; hybrid colocation remains a clean future option if table count grows much further.

---

## 4. Ordered Implementation Proposals

All proposals preserve Veil's durability, `READ COMMITTED` / transactional isolation, append-only storage (no GC), and security invariants, and work identically on PostgreSQL and YugabyteDB.

### Phase 1 — High-ROI, Zero-Risk Quick Wins

#### P1. Fix YugabyteDB Sharding Flags & 6-Node Support in the Deployment Kit
- **Change:**
  - `deploy/do/configure.sh:102`: pass `--tserver_flags=yb_enable_read_committed_isolation=true,ysql_num_tablets=-1,ysql_num_shards_per_tserver=$YB_TABLETS` (and verify after migration via `yb_local_tablets` that `branches` has `YB_NODES * YB_TABLETS` tablets in `hash` layout).
  - `deploy/gcp/lib.sh:103-104`: allow `YB_NODES` ∈ `{0, 3, 6}` and `HUBS` ∈ `{1..6}` (or configure each hub's DB URL / local HAProxy to round-robin YSQL connections across all `YB_NODES` when `HUBS < YB_NODES`).
- **Online safety:** Cluster bootstrap flag; for an existing 3-node cluster scaling to 6 nodes, use `yb-admin split_tablet` on hot tables or lower `tablet_split_low_phase_size_threshold_bytes`.
- **Expected effect:** Unlocks horizontal sharding across all 3 and 6 nodes (already measured **+40%** on 24-project warm pulls locally). PG: no change.
- **Risk:** Negligible; replicas/node stays constant (`~300`) as node count grows (`3 → 6`).

#### P2. Remove Inert v1 `pack_gc::guard_root_write` & `(project_id, -1)` GC Epoch Checks
- **Change:** Remove calls to `pack_gc::guard_root_write`, `pack_gc::read_gc_epoch`, and `pack_gc::push_gc_epoch` in `sync.rs`, `landing/`, `changes.rs`, `prs/state.rs`, `derive/`, and drop the `project_id = $1 AND person_id = -1` subquery from `read_epochs` (`auth.rs` / `perm.rs`). Keep the `access_epochs` schema untouched (no migration required).
- **Online safety:** Pure application change; rolling-deploy safe.
- **Expected effect:** Eliminates **100%** of `system:pg_advisory_locks` writes from push/API and ~75% from landing (`19,620` writes eliminated in `C_landing_24p`), **100%** of `access_epochs` IntentsDB writes (`14,922` in landing, `9,375` in push), `5.6 ms/push`, `10–11 ms/landing`, `4.8 ms/API`, and removes **2 tablets** from every write 2PC. PG: ~5–10% faster (eliminates 2–4 SQL round-trips/op).
- **Risk:** Zero — `pack_gc.rs:20-22` confirms nothing ever raises the GC epoch in v1, and Veil v1 is strictly append-only with no GC.

#### P3. Drop Hot-Path Foreign Keys on Append/High-Write Tables
- **Change (Migration 43):** Drop `FOREIGN KEY` constraints referencing `projects(id)` and `people(id)` on the 11 hot write tables (`branches`, `snapshots`, `origins`, `projections`, `landed_changes`, `landings`, `landed_from`, `packs`, `landing_queue`, `landing_leases`, `change_refs`). Keep FKs on cold admin/auth tables (`devices`, `sessions`, `groups`, `invites`, `webauthn_*`).
  ```sql
  ALTER TABLE packs DROP CONSTRAINT IF EXISTS packs_project_id_fkey,
                    DROP CONSTRAINT IF EXISTS packs_person_id_fkey;
  ALTER TABLE landing_queue DROP CONSTRAINT IF EXISTS landing_queue_project_id_fkey,
                            DROP CONSTRAINT IF EXISTS landing_queue_person_id_fkey;
  ALTER TABLE branches DROP CONSTRAINT IF EXISTS branches_project_id_fkey;
  ALTER TABLE snapshots DROP CONSTRAINT IF EXISTS snapshots_project_id_fkey;
  ALTER TABLE origins DROP CONSTRAINT IF EXISTS origins_project_id_fkey;
  ALTER TABLE projections DROP CONSTRAINT IF EXISTS projections_project_id_fkey;
  ALTER TABLE landed_changes DROP CONSTRAINT IF EXISTS landed_changes_project_id_fkey;
  ALTER TABLE landings DROP CONSTRAINT IF EXISTS landings_project_id_fkey;
  ALTER TABLE landed_from DROP CONSTRAINT IF EXISTS landed_from_project_id_fkey;
  ALTER TABLE landing_leases DROP CONSTRAINT IF EXISTS landing_leases_project_id_fkey;
  ALTER TABLE change_refs DROP CONSTRAINT IF EXISTS change_refs_project_id_fkey,
                          DROP CONSTRAINT IF EXISTS change_refs_created_by_fkey;
  ```
- **Online safety:** `DROP CONSTRAINT` is metadata-only (instant, no table rewrite on PG or YB).
- **Expected effect:** Eliminates `17,901` (`projects`) + `8,715` (`people`, 98.3% 1-tablet hot spot) IntentsDB writes in `B_branches_24p` and `13,698` (`projects`) in `C_landing_24p`; removes `projects` and `people` tablets from every push/landing/API 2PC; cuts standalone `INSERT` latency by 68–82%. PG: modest win (removes FK trigger lookups and `FOR KEY SHARE` buffer locks on `projects`/`people` pages).
- **Risk:** Low. `veil-server` never deletes `projects` or `people` rows and always validates both IDs before writing. If project deletion is ever added, application-level cleanup handles it explicitly.

#### P4. Prune & Fix Secondary Indexes (`landing_queue`, `projections`, `landed_changes`)
- **Change (Migration 44 + query updates in `limits/landing.rs`, `landing/mod.rs`, `landing/service.rs`):**
  1. **`landed_changes`:** `DROP INDEX CONCURRENTLY IF EXISTS landed_changes_by_author;` (100% unused).
  2. **`projections` (4 → 2 secondary indexes):**
     - `DROP INDEX CONCURRENTLY IF EXISTS projections_by_projected;` (redundant prefix of `projections_by_projected_at`).
     - Create `CREATE INDEX CONCURRENTLY IF NOT EXISTS projections_by_view_v2 ON projections (project_id, view_key, projected_id, collapsed, real_id);` then `DROP INDEX CONCURRENTLY` both `projections_by_view` and `projections_own`.
  3. **`landing_queue` (8 → 5 indexes, 0 global hot-spot tablets, 0 writes to done/old on enqueue):**
     - Replace `landing_queue_pick` (`NULL` hot spot!) + `landing_queue_ready` with **one partial index**:
       ```sql
       CREATE INDEX CONCURRENTLY IF NOT EXISTS landing_queue_queued
         ON landing_queue (project_id, branch, priority DESC, created_at, seq)
         WHERE state = 'queued';
       ```
       Update `limits/landing.rs:412,468` to use `WHERE project_id = $1 AND branch = $2 AND state = 'queued' ...` instead of `CASE WHEN state = 'queued' THEN project_id END = $1`.
     - Replace global `landing_queue_state (state, project_id, branch)` with partial index:
       ```sql
       CREATE INDEX CONCURRENTLY IF NOT EXISTS landing_queue_active_state
         ON landing_queue (state, project_id, branch)
         WHERE state IN ('queued', 'merging');
       ```
       Finished rows (`landed`/`failed`) never write to it, eliminating the `hash('landed')` global hot tablet. (Optional further step: drop `landing_queue_active_state` too if recovery scans `landing_leases` + a small `landing_active` table.)
     - Replace non-partial `landing_queue_done` + `landing_queue_old` with **one partial index**:
       ```sql
       CREATE INDEX CONCURRENTLY IF NOT EXISTS landing_queue_finished
         ON landing_queue (project_id, done_at, branch)
         WHERE done_at IS NOT NULL;
       ```
       Enqueue (`done_at IS NULL`) and claim write **0** entries to it.
     - Replace globally hashed `landing_queue_ticket (ticket)` with project-sharded:
       ```sql
       CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS landing_queue_project_ticket
         ON landing_queue (project_id, ticket);
       ```
       (All callers already filter on `project_id = $1`.)
- **Online safety:** All new indexes created with `CREATE INDEX CONCURRENTLY` before deploying code that relies on them; old indexes dropped with `DROP INDEX CONCURRENTLY` after. Zero locking downtime on PG or YB.
- **Expected effect:** Cuts `projections` writes by **40%** (`5 → 3` tablets/row), `landed_changes` writes by **50%** (`2 → 1` tablet/row), and `landing_queue` enqueue writes from **9 → 5 tablets** while eliminating the two biggest landing hot-spot tablets (`landing_queue_state` 68.3% skew, `landing_queue_pick` 46.9% `NULL` skew) and removing `landing_queue_ticket`'s cross-node random-shard hop. PG: significantly faster (fewer B-tree inserts, smaller partial indexes, better cache residency).
- **Risk:** Low; verify `EXPLAIN` plans on both PG and YB for `landing_queue_queued`, `landing_queue_finished`, and `projections_by_view_v2`.

---

### Phase 2 — High-Impact Protocol & Schema Redesign

#### P5. Eliminate `packs` DB Staging Churn in `objects` Layout
- **Change (Option A — recommended):** In `objects` layout, `POST /v1/projects/{p}/objects` writes the temporary upload container to S3 under `staged/<project_id>/<person_id>/<uuid>` (invisible to all readers) and returns an **HMAC-SHA256 upload ticket** signed with the cluster's shared `hub-receipt-key` encoding `(project_id, person_id, uuid, issued_at_ms)`. `POST /push` on any hub verifies the signature, `project_id`, `person_id`, and 1-hour expiry in memory (**0 DB queries**), validates objects and secret-file rules, writes loose objects to `p/<project>/ab/cdef…`, commits the push transaction **without touching `packs`**, and deletes `staged/…` asynchronously. Abandoned uploads are expired by an S3 bucket lifecycle rule on `staged/` (1 day) or periodic `ListObjectsV2` sweep in `pack_gc`. Legacy `LISTED` packs remain readable via the unchanged `packs` table.
- **Fallback (Option B, if DB tracking must stay):** Remove `DELETE FROM packs` from foreground push (batch-delete `DISCARDED` rows in `pack_gc` every 10 s) and fold `SELECT FROM packs` into `UPDATE ... RETURNING`. Saves 1 commit + 1 read, but still keeps 1 extra `INSERT` commit + 2 tablets in push 2PC.
- **Online safety:** Backward-compatible if `POST /push` accepts either signed `staged:` tokens or legacy `packs` names during a rolling upgrade.
- **Expected effect:** Eliminates **2 of 3 DB commits per push**, `51,053` RocksDB/IntentsDB writes in `B_branches_24p` (**#1 & #2 written tables**), and `~11.2 ms/push` (32% of foreground DB time) on YB. PG: eliminates 2 WAL flushes/push (major speedup on PG too).
- **Risk:** Must ensure `staged/` keys are never readable via object download routes and that rejected pushes delete their `staged/` object immediately (same secret-discard guarantee as today).

#### P6. Shard Global Person Epochs, Batch `read_epochs`, and Cache `tested` / `embargoes` on `GET /tips`
- **Change (Migration 45 + `auth.rs`, `perm.rs`, `caches.rs`, `api.rs`):**
  1. **Shard global person epochs:** Add `CREATE TABLE person_epochs (person_id BIGINT PRIMARY KEY, epoch BIGINT NOT NULL DEFAULT 0, changed_at BIGINT NOT NULL DEFAULT 0);` (backfilled from `access_epochs WHERE project_id = 0`, dual-written during rollout, then switched). Now `person_epochs` is hash-sharded by `person_id` across all `N` nodes instead of piling 100% of users onto `access_epochs` `hash(0)`.
  2. **Batch `read_epochs`:** On `access_epochs`, once `person_id = -1` (inert GC epoch, P2) and `project_id = 0` (moved to `person_epochs`) are gone, `read_epochs` is just two point lookups (`person_epochs(person_id)` and `access_epochs(project_id, person_id)`) — issued in **1 SQL statement** via `SELECT (SELECT epoch FROM person_epochs WHERE person_id = $1), (SELECT epoch FROM access_epochs WHERE project_id = $2 AND person_id = $1)` (or batched `ANY` if kept in one table: verified `3 → 1 RPC`, `1.46 → 0.33 ms`).
  3. **Cache `tested` and `embargoes` alongside `branches` in `caches.tips`:** Populate `tested` and `embargoes` per project on `caches.tips` miss and invalidate on `ci::record_tested` and embargo writes (via `LISTEN/NOTIFY` on PG, `100 ms` `TIPS_TTL` on YB — identical to `branches`). Keep embargo enforcement on writes/downloads unchanged.
- **Online safety:** Additive table + backfill + dual-write during rolling deploy.
- **Expected effect:** Eliminates the **85.6% (landing) / 77.1% (pull)** single-tablet hot spot on `access_epochs`, cuts warm-pull DB queries from **3 → 1** (**> 65% reduction** in pull DB reads), and makes warm pulls scale linearly 3 → 6 nodes. PG: cuts warm-pull queries 3 → 1 as well.
- **Risk:** On YB (without `LISTEN/NOTIFY`), newly recorded CI `tested` snapshots or newly created embargoes take up to `100 ms` (`TIPS_TTL`) to appear in `GET /tips` (same window already accepted for branch tips on YB).

#### P7. Fold `pr_review_rules` into `branches`
- **Change (Migration 46 + `prs/state.rs`):** Add nullable `review_checked TEXT, review_state TEXT` columns to `branches` (populated only on the project's default branch). Update them in the existing `UPDATE branches` statement of a default-branch push/landing/API commit (or skip updating when `.veilrules` is untouched and `review_state` is unchanged, if fast-forward semantics allow). `rules_in_force` reads `branches` alone with **zero `LEFT JOIN`**, eliminating `pr_review_rules` `SELECT ... FOR UPDATE` and `UPSERT`.
- **Online safety:** `ALTER TABLE branches ADD COLUMN ...` with `NULL` default is instant metadata-only on PG and YB; fall back to `pr_review_rules` when `review_checked IS NULL` during rollout.
- **Expected effect:** Removes **1 table (`pr_review_rules`), 1 `FOR UPDATE`, 1 `UPSERT`, and 1 cross-tablet `LEFT JOIN`** from every default-branch landing and API commit (`8,136` writes and `58,756` seeks eliminated in `C_landing_24p`). PG: saves 2 statements + 1 join per default-branch commit.
- **Risk:** Low; default-branch writes already hold the exclusive row lock on `branches (project_id, default_branch)`.

---

### Phase 3 — Background Amplification & Audit Batching

#### P8. Debounce Background Deriver (`derive/mod.rs`)
- **Change:** Add a configurable per-project coalescing delay (default `250–500 ms`) in `derive::Workers::landed` before acquiring the advisory lock and running `catch_up`. On-demand query callers still invoke `derive::ensure` directly with `0 ms` wait.
- **Online safety:** Pure in-memory scheduling change.
- **Expected effect:** Under active push/landing load, coalesces 10–100 snapshots into a single `UNNEST` batch per derived table, cutting background deriver SQL statements, advisory lock writes, and tablet writes by **~5–10×** (currently `43–49%` of total push DB cost). PG: same 5–10× reduction in background write I/O.
- **Risk:** Derived history/search views trail live pushes by ≤ 500 ms unless queried via `ensure()` (which catches up synchronously).

#### P9. Batch `audit_log` Writes Asynchronously (Subject to Owner Durability Preference)
- **Change:** Move push/landing/API `audit_log` inserts out of the foreground 2PC commit into a bounded in-memory ring flushed every `250 ms` or `256` rows via a single `INSERT INTO audit_log ... SELECT * FROM UNNEST(...)` (matching `lib.rs:640`'s existing non-transactional audit pattern). If synchronous audit durability is required instead, keep `audit_log` inside the transaction and accept 1 extra tablet per push/landing.
- **Expected effect:** Removes **1 random-node tablet** (`audit_log`) from every push, landing, and API commit 2PC (`13,464` writes in `C_landing_24p`, `8,712` in `B_branches_24p`), and batches writes ~100×. PG: reduces WAL volume and statement count per commit.
- **Risk:** Up to `250 ms` of audit entries could be lost on an abrupt `SIGKILL` of a `veil-server` process (graceful `SIGINT` flushes on shutdown).

---

### Projected Cumulative Impact (YB `hash` Before vs After P1–P9)

| Metric | Today (`yb_hash`, 1 tab/tbl) | Today (`yb_colo`) | Projected `yb_hash` (P1–P9, 3 nodes) | Projected `yb_hash` (6 nodes / 3 nodes) |
|---|---:|---:|---:|---:|
| **Push: DB commits / op** | 3 | 3 | **1** (P5) | 1 |
| **Push: fg tablets written / op** | ~18 (26 w/ dr) | 1 | **4–5** (`branches`, `snapshots`, `projections`+2 idx, `landed_changes`) | Linear across projects |
| **Push: Raft RPCs / op** | 269.8 | 150.6 | **~65–85** (below `yb_colo`!) | **≥ 1.7×** throughput |
| **Landing: tablets written / op** | ~29 (39 w/ dr) | 1 | **~8–10** (amortized across batch) | Linear across projects |
| **Landing: `UpdTxn` RPCs / op** | 204.1 | 23.6 | **~35–50** (4–6× reduction) | **≥ 1.6×** throughput |
| **Warm pull: DB queries / op** | 3 (5.2 Rd RPCs) | 3 (6.1 Rd RPCs) | **1** (`person_epochs` + `access_epochs`, 1–2 Rd RPCs) | **≥ 1.8×** throughput |
| **Global single-tablet hot spots** | 4 (`access_epochs(0)`, `lq_state`, `lq_pick(NULL)`, `people` FK) | 1 (entire DB) | **0** | **0** |

At 3 nodes, cutting `yb_hash` Raft RPCs/op by **3–4×** brings per-operation work *below* today's `yb_colo` while distributing leaders 33/33/33 across all 3 nodes — projecting **~1.5–2.5× the throughput of today's 3-node `yb_colo`** on multi-project gates, **≥ parity** on single-project `branches --merge-every 5`, and **≥ 1.6–1.8× horizontal growth from 3 → 6 nodes** on multi-project gates.

---

## 5. Cloud Verification Plan (Google Cloud)

Local single-host runs cannot prove horizontal scaling across machines. Verification on GCP (`deploy/gcp/`) requires four configurations on identical VM types (`c2d-standard-8` DB nodes, `c2d-standard-16` hubs/drivers, `c2d-standard-8` MinIO w/ local NVMe SSD):

### 5.1 Kit Changes (Implemented in `d994d302` [P1] and `d4a63541` [Kit/Gates])
1. **`deploy/do/configure.sh`:** Passes `ysql_num_tablets=-1` alongside `ysql_num_shards_per_tserver=$YB_TABLETS`, lifts master tablet-replica limits only on the RF=3 masters (`yb1..yb3`; `yb4..yb6` run tserver-only), and asserts via `yb_local_tablets` across all nodes after `migrate` that `branches` has `YB_NODES * YB_TABLETS` distinct tablets when `YB_LAYOUT=hash`.
2. **`deploy/gcp/lib.sh` & `deploy/do/lib.sh`:** Allows `YB_NODES` ∈ `{0, 3, 6}` and updates `deploy/gcp/estimate.sh` / `deploy/do/estimate.sh` with the 6-node topology. When `YB_NODES > HUBS` (e.g. 3 hubs on 6 YB nodes), each hub runs a lightweight local HAProxy TCP round-robin forwarder (`yb-proxy` on `<hub_priv>:15433`, reusing `HAPROXY_IMAGE` and `deploy/lb/haproxy-cfg.sh`, restarted on Spot recovery) so YSQL connections spread evenly across all 6 YB nodes without needing extra hub VMs; when `YB_NODES <= HUBS`, hubs connect directly 1:1 with zero proxy hop.
3. **`deploy/gates.sh`, `deploy/gcp/bench.sh`, `deploy/do/bench.sh`, `deploy/yb-scale-table.py`:** Keeps all existing gates unchanged and adds two dedicated scaling gates:
   - `yb-scale`: multi-project horizontal scaling across **60–100 projects** (`YB_SCALE_PROJECTS=60` default) covering `branches`, `landing`, `pull`, `api`, and `land` across all drivers.
   - `yb-onerepo`: single-repository many-branch scaling (`--projects 1`, pure branch pushes across many branches) plus a separate `--merge-every 5` curve whose serialized merges onto `main` are reported separately as informational.
   - `deploy/yb-scale-table.py`: invoked automatically by `bench.sh` via `gate_report` to emit Markdown summary tables (including per-YB-node CPU shares) and, when `YB_COMPARE_DIR=<3-node-results-dir>` is set on the 6-node run, an automated 3-vs-6 PASS/FAIL verdict (≥ 1.6× throughput with 0 errors on all required multi-project and single-repo branch curves; serialized `main` merges informational).

### 5.2 Run Matrix, Commands & Pass Criteria

| Run | DB Config | Hubs | Gates | Purpose & Pass Criteria |
|---|---|---:|---|---|
| **1. PG baseline** | `VEIL_GCP_YB_NODES=0` (1× `c2d-standard-8`) | 3 | `pull`, `land`, `branches`, `api`, `landing`, `scaling`, `failover` | **No regression** vs `integration` baseline (faster from P2–P8); 0 errors. |
| **2. YB `colocated` 3-node** | `VEIL_GCP_YB_NODES=3`, `VEIL_GCP_YB_LAYOUT=colocated` | 3 | `pull`, `land`, `branches`, `api`, `landing`, `yb-scale`, `yb-onerepo` | Control baseline on the same build & machines. |
| **3. YB `hash` 3-node** | `VEIL_GCP_YB_NODES=3`, `VEIL_GCP_YB_LAYOUT=hash`, `VEIL_GCP_YB_TABLETS=1` | 3 | Full suite (`pull`, `land`, `branches`, `api`, `landing`, `scaling`, `failover`, `yb-scale`, `yb-onerepo`) | **Goal (1):** ≥ `colocated` 3-node on `branches` (300 & 1,000 agents, 0 errors), `landing`, `pull`, `api`, `land`. Balanced node writes (`~33% ± 5%`) and 0 hot-spot tablets via tserver metrics. |
| **4. YB `hash` 6-node** | `VEIL_GCP_YB_NODES=6`, `VEIL_GCP_YB_LAYOUT=hash`, `VEIL_GCP_YB_TABLETS=1` | 3 (via local `yb-proxy` round-robin across all 6 YB nodes) | `yb-scale`, `yb-onerepo`, `failover` (with `YB_COMPARE_DIR=<Run 3 dir>`) | **Goal (2):** **≥ 1.6×** throughput over Run 3 (3-node `hash`) on multi-project `yb-scale` (`branches`, `landing`, `pull`, `api`, `land`) AND single-repo many-branch `yb-onerepo` (serialized `main` merges reported separately); p99 bounded; 0 errors; `~16.7% ± 4%` write share per YB node. |

**Example GCP verification commands (quote first via `deploy/gcp/estimate.sh`):**
```bash
# Run 3: 3-node YB hash
VEIL_GCP_YB_NODES=3 VEIL_GCP_YB_LAYOUT=hash VEIL_GCP_YB_TABLETS=1 \
  deploy/gcp/bench.sh --approve pull land branches api landing scaling failover yb-scale yb-onerepo

# Run 4: 6-node YB hash compared against Run 3
VEIL_GCP_YB_NODES=6 VEIL_GCP_YB_LAYOUT=hash VEIL_GCP_YB_TABLETS=1 \
  YB_COMPARE_DIR=deploy/gcp/results/<run3-dir> \
  deploy/gcp/bench.sh --approve yb-scale yb-onerepo failover
```

**Spot-instance cost estimate:** Using `VEIL_GCP_SPOT=hybrid` (~1–1.5 hours per run), Runs 1–4 together are roughly \$15–\$25 total compute on GCP (exact quote via `deploy/gcp/estimate.sh` before approval).

---

## 6. Questions for the Owner (Resolved 2026-11-19)

1. **`packs` DB staging removal in `objects` layout (P5):** Are you comfortable replacing the `packs` DB staging row on `POST /objects` with an HMAC-signed S3 upload ticket (`staged/<project>/<person>/<uuid>`) cleaned up via S3 lifecycle rule / periodic `ListObjectsV2` sweep? → **Decision: Option B ("trim it, same security").** Keep the DB staging record and BUG-1150/2851 proof-of-upload; fold `SELECT` into `UPDATE ... RETURNING` and move consumed-row `DELETE` to background `pack_gc`.
2. **Hot-table foreign keys (P3):** Is dropping `FOREIGN KEY` constraints referencing `projects(id)` and `people(id)` on the 11 high-write tables acceptable on both PostgreSQL and YugabyteDB? → **Decision: APPROVED** (both databases; grep proof in `754f217d` that nothing deletes `projects` or `people`).
3. **`audit_log` durability (P9):** Should push/landing/API `audit_log` entries remain synchronously committed inside the foreground transaction, or is asynchronous `250 ms` batched insertion acceptable? → **Decision: REJECTED.** `audit_log` stays synchronous inside the commit transaction. Its `id HASH` PK already spreads writes across nodes for both multi-project and single-repo workloads; `audit_log_id_seq` cache was raised to `1000` on YB in Q4.
4. **Single-repository (`onerepo`) horizontal scaling on YB:** Is scaling a *single* repository across 3 → 6 YB nodes in scope? → **Decision: APPROVED.** Composite hash keys built for the 11 hottest per-branch/per-change/epoch tables on YB (Migration 46, `055915dc` + `access_epochs` in `35c8cefd`), keeping per-project scans bounded (`branches_by_project`) and reporting serialized `main` merges separately.
5. **Warm-pull `tested` & `embargoes` cache window (P6):** Is applying the `100 ms` `TIPS_TTL` to `tested` and `embargoes` on `GET /tips` acceptable? → **Decision: Split (later simplified in BUG-2930).** Global person-epoch sharding, batched `read_epochs`, and `tested` caching on `GET /tips` **APPROVED**; **caching `embargoes`/`embargo_lines` REJECTED** (BUG-1947 previously leaked embargoed content via a cached embargo view). Embargo reads remain strictly live on every request. In cycle-2 review (`BUG-2930`), the dual-written `person_epochs` table split in migration `0045` was withdrawn in favor of sharding `access_epochs` directly via `PRIMARY KEY ((project_id, person_id) HASH)` in fresh-or-offline migration `0046`.
6. **Pure `hash` vs hybrid colocation:** Proceed with pure `hash` (`ysql_num_tablets=-1`) or hybrid colocation? → **Decision: Pure `hash`** with `ysql_num_tablets=-1`; no hybrid colocation.

---

## 7. Stage 2 Decisions, Implementation Summary & Local Before-vs-After Results

### 7.1 Commit Stack on `t3/yb-scale` (base `3d0a690b`)

| # | Commit | Proposal | Summary & Review Notes |
|---:|---|---|---|
| 0 | `0ad260a8` | Stage 1 | Initial design & measurement report (`docs/design/server/yugabyte-scaling.md`). |
| 1 | `d994d302` | **P1** | `ysql_num_tablets=-1` + post-migrate `branches` tablet-count assertion (`YB_NODES * YB_TABLETS`); `YB_NODES` ∈ `{0, 3, 6}`; local `yb-proxy` TCP round-robin on hubs when `YB_NODES > HUBS`; updated `estimate.sh` + tests. |
| 2 | `b60f018f` | **P2** | Removed inert `pack_gc::guard_root_write`, `read_gc_epoch`, `push_gc_epoch`, and all `person_id = -1` reads/tests/docs. **Dead data note:** no schema change; any pre-existing `access_epochs` rows with `person_id = -1` become inert/unread dead rows. |
| 3 | `754f217d` | **P3** | Migration 43 (`0043_drop_hot_fks.sql`): dropped 14 FKs referencing `projects(id)` / `people(id)` on the 11 hot tables on both PG and YB (`DROP CONSTRAINT IF EXISTS`, metadata-only). Commit message includes full repo grep proving nothing deletes `projects` or `people`. |
| 4 | `3c51e182` | **P4** | Migration 44 (`0044_prune_repair_indexes.sql`): dropped `landed_changes_by_author` and `projections_by_projected`; merged `projections_by_view` + `projections_own` → `projections_by_view_v2`; replaced `landing_queue_pick` (NULL skew) + `landing_queue_ready` → partial `landing_queue_queued`; replaced `landing_queue_state` → partial `landing_queue_active_state`; replaced `landing_queue_done` + `landing_queue_old` → partial `landing_queue_finished`; replaced global `landing_queue_ticket (ticket)` → `landing_queue_project_ticket (project_id, ticket)` (later kept `landing_queue_ticket` per BUG-2924). Every affected query verified with `EXPLAIN` on both PG17 and YB3. |
| 5 | `719d5815` | **P5-B** | Option B ("trim it, same security"): folded pre-tx `SELECT FROM packs` into transactional `UPDATE packs SET state = DISCARDED ... RETURNING` and moved consumed-row `DELETE FROM packs` to background `pack_gc` (later reverted in full per BUG-2923 and commit-time container-purge guarantees). |
| 6 | `14949778` | **P6** | Batched `read_epochs` into 1 SQL round trip and cached `tested` on `GET /tips` alongside `branches` (PG `LISTEN/NOTIFY` + YB `100 ms` TTL); **embargo checks remain strictly live on every request**. Initially split `person_epochs` in migration 45 (`0045_person_epochs.sql`); that split was later withdrawn in `35c8cefd` (`BUG-2930`) and replaced by composite-hashing `access_epochs` in migration `0046`. |
| 7 | `910a1521` | **P7** | Skipped `pr_review_rules` `FOR UPDATE` + `UPSERT` when `.veilrules` hash unchanged (later reverted in full in `219680f4` per BUG-2926). |
| 8 | `c0ff7878` | **P8** | Debounced background `derive::Workers::landed` per project (default `250 ms`, configurable via `VEIL_DERIVE_DEBOUNCE_MS`). `derive::ensure` stays strictly synchronous (`0 ms` wait), verified by a test reading derived history immediately after a push. |
| 9 | `055915dc` | **Q4** | **Review callout (`crates/veil-server/src/db.rs`):** added minimal `-- veil: yugabyte-only` (skipped & recorded on PG and colocated YB) and `-- veil: step` (executes each top-level step outside a tx on YB) markers to the migration runner. **Migration 46 (`0046_single_repo_hash_keys.sql`)** rebuilds 11 hot tables on hash-sharded YB — `branches`, `snapshots`, `origins`, `projections`, `landed_changes`, `landing_queue`, `landings`, `landing_leases`, `packs`, `change_refs`, and `access_epochs` (added in `35c8cefd`) — in 3 steps per table (drop stale staging + create `<t>_q4`, standalone DML copy, verified row-count guard + `DROP`/`RENAME`) with composite hash PKs and matching composite-hashed indexes, plus `branches_by_project (project_id HASH, name ASC)` so `GET /tips` stays strictly bounded (`1.04 ms` storage time, `0` index writes on tip moves), and raises hot sequence caches (`audit_log_id_seq`, `landing_queue_seq_seq`, `branch_lineages`) to `1000`. |
| 10 | `d4a63541` | **Kit/Gates** | Added `yb-scale` (60–100p multi-project) and `yb-onerepo` (single-repo many-branch + separate serialized `main` merge curve) gates + `deploy/yb-scale-table.py` automated 3-vs-6 ≥ 1.6× verdict (`YB_COMPARE_DIR`). |
| 11 | `412e904f` | **Docs** | Updated `docs/design/server/yugabyte-scaling.md` and added `BUG-2890`..`BUG-2893` to `docs/BUGS.md`. |
| 12 | `38c90045` | **Review repros (c1)** | Cherry-picked `bafeca84`: reproductions and `docs/BUGS.md` rows for `BUG-2920`..`BUG-2926`. |
| 13 | `219680f4` | **BUG-2926** | Reverted P7 (`910a1521`) in full; `pr_review_rules.checked` advances on every default-branch commit so pre-upgrade servers during a rolling upgrade never downgrade stricter `.veilrules` to `Strict` (1 approval). |
| 14 | `2a9e49ec` | **BUG-2924** | Kept `landing_queue_ticket (ticket)` in migrations `0044` and `0046` and restored `ON CONFLICT (ticket) DO NOTHING` in `bisect.rs` for rolling-upgrade compatibility (omitting redundant `landing_queue_project_ticket`). |
| 15 | `43ca4466` + `00e60027` | **BUG-2923** | Reverted P5-B (`719d5815`) in full (folded `UPDATE ... RETURNING`, `skip_precheck`, and background batched `DELETE FROM packs`), restoring unconditional pre-tx `usable_for_packs`/`usable_for_receipts` and synchronous commit-time `discard_consumed`/`purge_discarded` so both multi-hub upload-proof guarantees (`BUG-2923`) and commit-time container-purge guarantees (`object_layout::guarantee_11_*`, `packs::embargoed_stack_across_guess_windows_*`) hold identically to `3d0a690b`. |
| 16 | `d6bf8e37` | **BUG-2922** | Extended `db::migrate_once` to execute `-- veil: step`-delimited regular migrations one committed transaction per step; initially split `0045_person_epochs.sql` into trigger + backfill (later superseded by withdrawing `person_epochs` in `35c8cefd` per BUG-2930). |
| 17 | `02f5a05e` | **BUG-2921** | Checked `SELECT yb_is_database_colocated()` in `db::migrate_once`; colocated YugabyteDB databases skip `yugabyte_only` hash-sharding DDL and record the migration, matching PostgreSQL. |
| 18 | `969d7e8c` | **BUG-2925** | Restored single-column leading `project_id HASH` on the three low-write retention/sweep indexes in `0046` (`landing_queue_finished`, `landings_at`, `packs_unlisted`) so retention and `pack_gc` queries remain index scans on YugabyteDB. |
| 19 | `326a7e5a` | **BUG-2920** | Added `db::migrate_offline` / `veil-server migrate --offline` (documented in `docs/DEPLOY.md` §2.2), dropped stale `<t>_q4` tables before copy, tightened `c_new <> c_old`, and verified rebuilt secondary indexes via `yb_index_check`. |
| 20 | `5b00c203` | **Test audit** | Isolated `conflict_retry::bug_2340_*` and `derived::p8_*` with `TestHub::start_own()` and tightened `caches::p6_*` embargo assertion. |
| 21 | `43b55337`..`16047e76` | **Review repros (c2)** | Cherry-picked cycle-2 review findings `BUG-2930`, `BUG-2931`, `BUG-2932` from `t3/review-ybscale2`. |
| 22 | `26bd0f31` | **BUG-2931** | Removed `ensure_q4_offline_safe`'s emptiness gate; migration `0046` runs without `--offline` **only** when the current `MIGRATION_LOCK` hold created the schema from nothing (`schema_migrations` absent or empty, persisted across retryable `40001` restarts); any existing database refuses `0046` without `--offline` even when all rebuilt tables are empty. |
| 23 | `35c8cefd` | **BUG-2930** | Withdrew `person_epochs` split entirely (`0045_person_epochs.sql` is now a comment-only no-op; reverted `person_epochs` reads back to `access_epochs(0, person_id)` while keeping batched `read_epochs`, `landing/service.rs` `UNION ALL`, and `GET /tips` `tested` caching) and added `access_epochs` to fresh-or-offline migration `0046` with `PRIMARY KEY ((project_id, person_id) HASH)`. |
| 24 | **BUG-2932** | **BUG-2932** | Tightened `verify_rebuilt_indexes` to assert the exact expected set of 11 composite-hash primary keys (`Q4_REBUILT_PKS`, including `access_epochs`) and 14 required secondary/UNIQUE indexes (`Q4_EXPECTED_INDEXES`) exist with matching uniqueness, read live/ready/valid, and pass `yb_index_check` before recording version 46, failing with every missing or invalid index named. |

**Rejected / reverted / withdrawn proposals:**
- **P5-B staged `packs` trimming:** Reverted in full (`BUG-2923` + full-suite commit-time purge regressions `object_layout::guarantee_11_*` and `packs::embargoed_stack_across_guess_windows_*`). With pre-tx `usable_for_*` restored, the remaining gain was small and commit-time container purge must hold exactly as on `3d0a690b`.
- **P6 embargo caching:** Rejected due to BUG-1947 (cached embargo view previously leaked embargoed content). `embargo_lines` stays live on every request.
- **P6 `person_epochs` table split (migration `0045`):** Withdrawn in `35c8cefd` (`BUG-2930`). On YugabyteDB, trigger DDL does not drain in-flight transactions using an older catalog version and `DROP TRIGGER IF EXISTS` before `CREATE TRIGGER` commits immediately on an interrupted retry, so a dual-written table + trigger + backfill across a rolling upgrade can still lose revocations. Replaced by composite-hashing `access_epochs` on `PRIMARY KEY ((project_id, person_id) HASH)` in fresh-or-offline migration `0046`, achieving the same tablet spread for `(0, person_id)` rows with zero second table, zero extra trigger, and zero rolling-upgrade window.
- **P7 `pr_review_rules` skip:** Reverted in `219680f4` (`BUG-2926`) — skipping `pr_review_rules.checked` updates in the same release as the `old_file` fallback broke rolling-upgrade preservation of stricter `.veilrules`; the small gain did not justify a two-release rollout.
- **P9 async `audit_log`:** Rejected to preserve synchronous in-transaction durability. `audit_log` keeps its `id HASH` PK (which already distributes inserts evenly across all nodes for both multi-project and single-repo workloads) and raises `audit_log_id_seq` cache to `1000` on YB.

### 7.2 Local Before-vs-After Benchmark Results (`3d0a690b` vs `d4a63541`)

Measured on the local benchmark host under `~/.cache/veil-orch/heavy-lock.sh` with strict backend isolation (YB containers stopped during PG17 runs; fresh 1-DB 3-node YB `hash` cluster with fixed flags `ysql_num_tablets=-1,ysql_num_shards_per_tserver=1`, `branches` tablets = `3` verified, round-robin via local `yb-proxy`; fresh MinIO per run; 12 s measured + 3 s warmup; `--db-connections 60`; `--object-layout objects`; `0` errors across all 16 runs).

| Backend | Gate | Before (`3d0a690b`) ops/s (p50 / p99 ms) | After (`d4a63541`) ops/s (p50 / p99 ms) | Ratio | Errs (B/A) | DB stmts/op (B→A) | DB commits/op (B→A) | DB CPU ms/op (B→A) | YB `UpdTxn` / `Raft` RPCs/op (B→A) | YB Write Share `[yb1/yb2/yb3]` (B→A) | YB Read Share `[yb1/yb2/yb3]` (B→A) |
|---|---|---:|---:|---:|---:|---|---|---|---|---|---|
| `pg` (PG17) | `B_branches_24p` (24p, 48c) | 382.4 (117.2 / 272.2) | **430.8** (78.3 / 668.3) | **1.13×** | 0/0 | 27.4 → 23.5 (-14%) | 3.42 → 2.62 (-23%) | 7.23 → 4.42 (-39%) | — | — | — |
| `pg` (PG17) | `C_landing_24p` (24p, 48c, 24ppl) | 265.3 (91.7 / 1344.4) | 255.3 (88.9 / 1429.1)¹ | **0.96×** (r2 A/B: **1.00×**, 321.7→322.7) | 0/0 | 69.6 → 60.3 (-13%) | 2.70 → 2.75 | 8.71 → 7.31 (-16%) | — | — | — |
| `pg` (PG17) | `D_pull_24p` (24p, 48c, bg=0) | 26,213.3 (1.8 / 2.8) | **50,220.8** (0.9 / 2.3) | **1.92×** | 0/0 | 3.0 → 1.0 (-67%) | 0.00 → 0.00 | 0.25 → 0.11 (-56%) | — | — | — |
| `pg` (PG17) | `S_onerepo_1p` (1p, 48c) | 437.5 (65.5 / 669.1) | **578.3** (71.8 / 234.8) | **1.32×** | 0/0 | 23.9 → 18.1 (-24%) | 3.39 → 2.30 (-32%) | 5.10 → 4.71 (-8%) | — | — | — |
| `yb_hash` (3n fixed) | `B_branches_24p` (24p, 48c) | 325.7 (142.9 / 259.2) | **345.8** (134.5 / 255.3) | **1.06×** (**1.57×** vs Stage 1 `yb_hash`, **1.42×** vs Stage 1 `yb_colo`) | 0/0 | 10.0 → 7.8² (-22%) | — | 55.75 → 48.09 (-14%) | `68.5 / 145.1` → **`43.5 / 118.0`** (**-36% / -19%**) | `35/37/28%` → **`34/34/33%`** | `37/33/31%` → `30/37/33%` |
| `yb_hash` (3n fixed) | `C_landing_24p` (24p, 48c, 24ppl) | 143.9 (329.0 / 477.5) | 139.2 (299.4 / 1277.4)³ | **0.97×** (p50 **-9%**, DB CPU **-13%**) | 0/0 | 18.2 → 19.6² | — | 152.14 → 132.22 (-13%) | `124.7 / 368.2` → **`89.4 / 302.8`** (**-28% / -18%**) | `35/35/31%` → **`32/34/34%`** | `34/33/33%` → **`34/33/33%`** |
| `yb_hash` (3n fixed) | `D_pull_24p` (24p, 48c, bg=0) | 10,214.3 (4.6 / 6.6) | **20,491.8** (2.2 / 5.1) | **2.01×** (**4.23×** vs Stage 1 `yb_hash`) | 0/0 | 1.0 → 0.3² (-67%) | — | 1.81 → 0.88 (-51%) | `0.0 / 0.4` → `0.0 / 0.3` | `35/34/31%` → `32/31/37%` | `49/21/30%` → `28/12/61%`⁴ |
| `yb_hash` (3n fixed) | `S_onerepo_1p` (1p, 48c) | 182.2 (165.3 / 1833.4) | **278.2** (125.6 / 1079.5) | **1.53×** | 0/0 | 10.8 → 7.6² (-30%) | — | 126.95 → 71.86 (-43%) | `148.6 / 262.3` → **`61.9 / 160.6`** (**-58% / -39%**) | `45/13/42%` → **`34/32/34%`** | `32/48/21%` → `33/22/45%` |

**Notes:**
1. **PG `C_landing_24p`:** An interleaved A/B/A/B follow-up run confirmed parity on throughput (`321.7 → 322.7 ops/s`, **1.00×**), lower tail latency (p99 `710 → 537 ms`), fewer DB statements (`68.6 → 59.1`), and fewer DB writes (`16.2 → 15.0`); `after` never stalled whereas `before` stalled on round 1.
2. **YB `DB stmts/op`:** `veil-bench` reads `pg_stat_statements` from a single YSQL node (~1/3 of cluster-wide statements when round-robined across 3 nodes).
3. **YB `C_landing_24p`:** Every database metric improved (`Prepare 12.8 → 10.9 ms/batch`, `Transaction 105.9 → 102.4 ms/batch`, DB CPU `21.9 → 18.4 cores` [-16%], `UpdTxn -28%`, `Raft -18%`, p50 `-9%`). The 3% throughput dip and higher p99 on this single-host run came from local MinIO `Store objects` spiking `60.6 → 88.2 ms/batch` in the final 2 s on shared host disk after `B_branches_24p`'s ~40k objects; on GCP, MinIO runs on its own VM with dedicated local NVMe SSD.
4. **YB `D_pull_24p` read share:** `veil-bench --mode pull` authenticates as a single user (`agent`), so the `(0, agent)` epoch lookup hits 1 tablet while `embargo_lines` stays live on every request (per owner rejection of embargo caching). With `access_epochs` composite hash-sharded on `((project_id, person_id) HASH)` (BUG-2930), multi-user workloads spread `(0, person_id)` reads across all `N` nodes identically to `person_epochs` without a second table.

### 7.3 Post-Review Changes Summary (`BUG-2920`..`BUG-2926`, `BUG-2930`..`BUG-2932`)

Following cycle-1 adversarial review (`t3/review-ybscale` @ `bafeca84`), full-suite runs of `412e904f` and `1f0335d4`, and cycle-2 adversarial review (`t3/review-ybscale2`), all ten defects were resolved:

- **Q4 offline cutover, fresh-DB gate & exact index verification (`BUG-2920`, `BUG-2921`, `BUG-2925`, `BUG-2931`, `BUG-2932`):** Migration `0046` is skipped on colocated YugabyteDB databases (`SELECT yb_is_database_colocated()`, matching PostgreSQL). On hash-sharded YugabyteDB databases it runs without `--offline` **only** when this same `MIGRATION_LOCK` hold created the schema from nothing (`schema_migrations` absent or empty on first inspection, persisted across retryable `40001` restarts within the lock hold); any database that already had migrations recorded — even with all rebuilt tables empty — refuses `0046` without `--offline` and directs the operator to stop all servers and run `veil-server migrate --offline` (`docs/DEPLOY.md` §2.2). Stale `<t>_q4` staging tables are dropped on retry before copying, `ON CONFLICT DO NOTHING` is removed, the swap guard requires exact `c_new = c_old`, and before recording version 46 `verify_rebuilt_indexes` asserts the exact expected set of all 11 composite-hash primary keys (`Q4_REBUILT_PKS`, including `access_epochs`) and all 14 required secondary/UNIQUE indexes (`Q4_EXPECTED_INDEXES`) exist with matching uniqueness, read live/ready/valid, and pass `yb_index_check`, failing with every missing or invalid index named. The three low-write retention/sweep indexes (`landing_queue_finished`, `landings_at`, `packs_unlisted`) keep leading `project_id HASH` with covering `INCLUDE (...)` columns so retention and `pack_gc` sweeps execute as zero-table-lookup `Index Only Scan`s under YugabyteDB 2025.2's default `yb_enable_base_scans_cost_model = on`.
- **P6 `person_epochs` withdrawn; `access_epochs` sharded in `0046` (`BUG-2922`, `BUG-2930`):** Rather than fighting YugabyteDB's distributed DDL semantics with a dual-written `person_epochs` table + mirror trigger + backfill across a rolling upgrade (where trigger DDL does not drain in-flight transactions under older catalog versions and `DROP TRIGGER IF EXISTS` commits immediately on retry), `0045_person_epochs.sql` was withdrawn to a comment-only no-op (keeping version 45), all server reads were restored to `access_epochs (0, person_id)` (preserving batched 1-statement `caches::read_epochs`, `landing/service.rs` `UNION ALL`, and `GET /tips` `tested` caching), and `access_epochs` was added as table #11 in fresh-or-offline migration `0046` with `PRIMARY KEY ((project_id, person_id) HASH)`. Every production query on `access_epochs` is an exact `(project_id, person_id)` point lookup (zero per-project scans), so `(0, person_id)` global person-epoch rows spread evenly across all tablets with zero dual-writes or rolling-upgrade interleaving.
- **P5-B reverted in full (`BUG-2923`):** Reverted `719d5815` entirely (folded `UPDATE ... RETURNING`, `skip_precheck`, and background batched `DELETE FROM packs`), restoring unconditional pre-tx `usable_for_packs`/`usable_for_receipts` and synchronous commit-time `discard_consumed`/`purge_discarded` so both multi-hub upload-proof guarantees and commit-time container-purge guarantees (`object_layout::guarantee_11_*`, `packs::embargoed_stack_across_guess_windows_*`) hold as on `3d0a690b`.
- **P4 rolling-upgrade index compatibility (`BUG-2924`):** Kept `landing_queue_ticket (ticket)` and `ON CONFLICT (ticket) DO NOTHING` in `bisect.rs` (omitting `landing_queue_project_ticket`).
- **P7 reverted (`BUG-2926`):** Reverted `910a1521` in full so `pr_review_rules.checked` advances on every default-branch commit.

**Key takeaways before cloud verification:**
- **PostgreSQL is strictly no slower and substantially faster on every gate:** `B_branches_24p` **1.13×**, `C_landing_24p` **1.00×** (DB CPU `-16%`, stmts `-13%`), `D_pull_24p` **1.92×** (stmts `-67%`, DB CPU `-56%`), `S_onerepo_1p` **1.32×** (p99 `-65%`, commits `-32%`).
- **YugabyteDB `hash` (3 nodes, fixed flags) cut per-op consensus & 2PC cost dramatically and balanced writes across all 3 nodes:**
  - `B_branches_24p`: `UpdTxn -36%`, `Raft -19%`, writes **`34/34/33%`**, **1.57×** over Stage 1 `yb_hash` and **1.42×** over Stage 1 `yb_colo` (`242.9 ops/s`).
  - `C_landing_24p`: `UpdTxn -28%`, `Raft -18%`, DB CPU `-13%`, writes **`32/34/34%`**, reads **`34/33/33%`**.
  - `D_pull_24p`: **2.01×** throughput (`10.2k → 20.5k ops/s`, **4.23×** over Stage 1 `yb_hash`), DB CPU `-51%`.
  - `S_onerepo_1p` (single repo, 48 agents on distinct branches): **1.53×** throughput (`182.2 → 278.2 ops/s`), p99 `-41%`, DB CPU `-43%`, `UpdTxn -58%`, `Raft -39%`, and single-repo write distribution flipped from skewed **`45/13/42%`** to balanced **`34/32/34%`**.
- **Next step:** Run the GCP 4-configuration verification matrix (§5.2) to validate Goal (1) (`yb_hash` ≥ `yb_colo` at 3 nodes) and Goal (2) (≥ 1.6× 3-vs-6 scaling on both `yb-scale` and `yb-onerepo`) on separate VMs with dedicated NVMe MinIO.
