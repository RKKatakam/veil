# Change-sized GC cleanup and scheduled collection

> **Status: design, not built** (2026-11-18, revised after review cycle 1; branch `t3/design-change-sized-cleanup` from `integration` @ `7b9b9a07`). Closes **BUG-2623**, **BUG-2628**, **BUG-2629** and **BUG-2635**, and adds **scheduled collection** (`docs/HUB.md` §13.37) across both object storage layouts (`packs` and `objects`, `docs/design/server/object-layout.md` §3.2 and §9).
>
> **Sources of truth:** `docs/OVERVIEW.md`, `docs/VISIBILITY.md`, `docs/ARCHITECTURE.md` ("Threat model"), `docs/HUB.md` §13.20 (S28) and §13.37 (S29), `docs/design/server/object-layout.md`.
>
> **Numbers:** "measured" names where a number was measured in `docs/BUGS.md` or `docs/HUB.md`. "Estimate" is arithmetic from those measurements and query plans; nothing was measured for this document.

## 1. Summary

Today `pack_gc::run_project` (`crates/veil-server/src/pack_gc.rs`) is only run directly (`run_gc: true`); background tasks only merge small packs (`maybe_schedule`, `run_gc: false`) and sweep discarded or stale staged containers (`schedule_sweep`, `sweep_scan`). Three defects sit between S29 as merged on `integration` and safe, scheduled collection:

1. **Derived and memo writers outside the gate, and whole-table work inside it (BUG-2623, BUG-2628).** Projection memos (`sync::projected_inner`, `query::graph::project_tips_together`, `query::graph::write_prepared_memo`, `prs::embargo::projected`), projected grant trees (`grant::grant_root`, plus `grant::for_tips` reading cached `gc_epoch` and keying `hub.grants.stored` by root tree rather than projected snapshot), the real graph and its `changed` blobs (`derive::write_derive_tx`), viewer-graph and file-history caches (`query::graph::Walk::flush`, `query::files::Fill::flush`), blame caches (`query::files::Blamer::write`, `record_too_wide`) and log cursors (`query::keep_cursor`) write rows or objects without reading `gc_epoch` and calling `guard_root_write`, while `derive::Cx` and `query::graph::G` read/populate `hub.derive.rows` and `hub.query.rows` using `hub.caches.gc_epoch(P)` (which can lag on YugabyteDB where `LISTEN/NOTIFY` is off). When `t3/fable-open-bugs` (`914484bd`) tried to close BUG-2623 by adding `origins`, `projections` and `graph` to `STAMP_TABLES` and running chunk-scoped memo deletes, review found three flaws: (a) a chunk's memo cleanup advanced `gc.stamp` globally (even before rolling back an empty chunk) while purging only its own 256 objects, and ran a cached prepared delete on `projections.projected_id` (BUG-2467's plan skew); (b) unguarded writers of `view_*` and `graph` still committed rows for purged snapshots and cached them under the post-pass `gc_epoch`; and (c) hashing and re-reading whole `origins`, `projections` and `graph` tables under `lock_gc_epoch_tx` cost `O(rows)` at every switch and every 256-object loose chunk (0.5–1.5 s on PostgreSQL and 5–10 s on YugabyteDB at ~1.5 M rows), stalling every writer of the project.
2. **Re-recorded snapshots, rescued snapshot attachments, and multi-switch candidate state (BUG-2629).** `catch_up_round_in` skips `snapshots` rows that are in `gc.expired_unreferenced` even after the loose switch has purged `snapshots`, so a candidate snapshot re-pushed and then unbranched between the purge and a loose chunk keeps its `snapshots` row while losing its trees and blobs (breaking BUG-1780). Rescuing a previously unreferenced snapshot or deleted branch after the mark also needs its pre-existing `origins`, `projections`, `projection_trees`, `graph.changed`, and `search_shards` rows even when those rows sit at an older generation. And objects deleted by `delete_loose_chunk` stay in `gc.expired_unreferenced`, so a pack switch later in the same pass purges rows newly committed under the raised epoch.
3. **No collection scheduler, and background work left running at stop (BUG-2635).** `objects` layout leaves orphans from lost transactions and superseded projections as loose objects that wait for `run_gc` (`object-layout.md` §3.2, §9). Meanwhile `Running::stop` (`lib.rs:184`) does not drain spawned HTTP connections before stopping queue services, and does not stop or wait for `derive`, viewer-graph fills, blame jobs, `bisect` or `pack_gc` tasks (BUG-1990's class).

**The design, in six rules:**

1. **Every writer of a root, retained-history row, object-bearing memo, projected grant tree, client upload or derived row runs behind the GC epoch gate, with transparent internal retry on `GcEpochChanged`.** Each writer reads a fresh `gc_epoch` before checking or storing any object, checks `epoch == gc_epoch` under the shared gate as the first statement of its transaction, and tags every in-memory cache entry (`hub.caches`, `hub.derive.rows`, `hub.query.rows`, `hub.grants.stored`) with that explicit `gc_epoch` (`Cx::gc_epoch`, `put_committed_at`, `put_memo_at`). Background workers (`derive`, viewer-graph fills, blame jobs) and idempotent memo/grant/cursor transactions retry `GcEpochChanged` internally without triggering `limits::mark_committed()` (`503`) or leaking internal errors (`500`).
2. **Sharded per-project change counters (`gc_change_shards`, 32 shards) replace `STAMP_TABLES`.** Every guarded writer of a root or attachment table increments one random shard in the same CTE as `guard_root_write` **only when `gate.epoch = expected_epoch`** (zero extra SQL round-trips, zero phantom shard rows on mismatch, no single-row write hotspot). Reading the project's stamp (`SUM(changes)` over at most 32 rows) is `O(1)` (< 0.5 ms on PostgreSQL, < 1.5 ms on YugabyteDB).
3. **A monotonic per-project write generation (`access_epochs.write_gen`) makes catch-up and switch reads `O(Δ)`.** Before its mark snapshot (and before each non-quiet catch-up round), GC advances `write_gen` under the exclusive gate without changing `epoch` (~0.2 ms, aborting zero writers), and every `epoch` bump (`bump_gc_epoch_tx`) increments `write_gen` in the same upsert. Catch-up and `roots_at_switch` query `WHERE project_id = $1 AND gc_gen >= $2` (plus PK-indexed attachments of newly reached snapshots and `search_shards` of newly live branches), and update `(gc.covered_gen, gc.stamp)` strictly **after `COMMIT`**.
4. **Projected grant trees are recorded in `projection_trees` under the gate (BUG-2628), and re-recorded `snapshots` update `gc_gen` on conflict (BUG-2629).** `grant::for_tips` reads `read_gc_epoch` (`observe_gc_epoch`), keys `hub.grants.stored` by `(project, gc_epoch, projected_snapshot)`, and upserts `projection_trees` via `hub.db.begin()` under `guard_root_write`. `catch_up_round_in` clears `Marks::unread` for newly stored grant trees and pending client uploads (never bypassed when `pending_uploads` is non-empty), walks every Δ `snapshots` row unconditionally, and removes loose-deleted IDs from `expired_unreferenced`.
5. **Scheduled collection runs per project on its own small pool from garbage signals, bounded per pass and coordinated across servers by `LOCK_BASE ^ project`.** Projects accrue schedule hints without touching hot fast-forward commits; `gc_scan` runs on a dedicated `pack_gc` pool (never starving `DERIVERS = 4`), purges expired DB rows before slicing loose deletes (`BUG-1780`), and stops cleanly in a two-stage `Running::stop` that drains HTTP requests and `landing::stop` / `bisect::stop` before setting `hub.stopping`.
6. **Both layouts (`packs` and `objects`) use the same mark, gate, Δ catch-up and loose-chunk sweep.** In `objects` layout `select_batch` finds no new packs, merges leftover pre-switch packs down once, and collects all dead objects through `mark_and_sweep_loose`.

---

## 2. The guarantee and its proof

### 2.1 Statement of the two invariants

For every project `P`, across any interleaving of pushes, API commits, landing batches, PR/CI/bisect/embargo updates, uploads, read grants, deriver runs, viewer-graph/file/blame queries, pack merges and GC passes on one or more servers:

- **Invariant D (Durability of reachable objects).** No object in `P` that is in the object closure of any committed authoritative root (`GcRoot`), live search shard (`GcConditionalLeafRoot`), active client upload (`packs` with `person_id IS NOT NULL` and `state IN (STAGED, LISTED)`), retained `snapshots` row (BUG-1780), or committed attachment of a reachable snapshot (`origins`, `projections`, `projection_trees`, `graph.changed`), or for which a valid signed `Grant` has been issued, is absent from `P`'s store (`packs` ∪ loose keys).
- **Invariant M (No dangling memos or derived rows).** After any transaction or cache write completes, no committed row in `origins`, `projections`, `projection_trees`, `graph`, `file_history`, `rule_history`, `derive_progress`, `view_graph`, `view_changes`, `view_file_history`, `blame_memo`, `blame_ends`, `search_heads` or `log_cursors`, and no entry in `hub.caches`, `hub.query.rows`, `hub.derive.rows` or `hub.grants.stored` under the reader's observed `gc_epoch`, names a snapshot purged by GC or an object deleted by GC.

### 2.2 State variables, SQL guards and the generation fence

Each project `P` has a GC control row `access_epochs (project_id = P, person_id = -1)` (inserted at project creation in `api.rs:720` and backfilled for all existing projects in migration `0043`) holding:
- `epoch: i64` (`>= 0`): raised **only** when GC purges DB rows or deletes objects (`pack_switch`, `loose_purge_switch`, step 3a and step 3c of `delete_loose_chunk`, standalone purge switch). Raising `epoch` invalidates in-flight writers that checked or stored objects under an older `epoch` (`GcEpochChanged`) and invalidates epoch-keyed in-memory caches.
- `write_gen: i64` (`>= 1`): raised whenever GC establishes a generation fence (`advance_write_gen`), and **also incremented in lockstep whenever `epoch` is raised** (`bump_gc_epoch_tx`). Raising `write_gen` alone **does not** change `epoch` and never aborts an in-flight writer.

Alongside `access_epochs`, `gc_change_shards (project_id, shard, changes)` holds up to `GC_SHARDS = 32` rows per project (`shard ∈ 0..32`). The project's **change count** is `C(P) = COALESCE(SUM(changes)::BIGINT, 0)` over those rows.

Three transaction-first guard helpers share the advisory gate `gate_key(P) = GATE_BASE ^ P`:

1. **`guard_root_write(tx, P, expected_epoch) -> Result<i64>`** (used by every writer of a root, retained-history row or attachment row, returning `write_gen >= 1`):
   ```sql
   WITH gate AS (
       SELECT e.epoch, e.write_gen
       FROM (SELECT pg_advisory_xact_lock_shared($2)) l, access_epochs e
       WHERE e.project_id = $1 AND e.person_id = -1
       FOR SHARE OF e
   ),
   bump AS (
       INSERT INTO gc_change_shards (project_id, shard, changes)
       SELECT $1, $3, 1 FROM gate WHERE gate.epoch = $4
       ON CONFLICT (project_id, shard)
       DO UPDATE SET changes = gc_change_shards.changes + 1
   )
   SELECT epoch, write_gen FROM gate
   ```
   Because `bump` selects from `gate WHERE gate.epoch = $4` (rather than `VALUES (...) ... WHERE EXISTS`), **neither `INSERT` nor `DO UPDATE` executes** when `gate` has 0 rows or `gate.epoch != $4`: `bump` writes zero rows even if a caller inspects the mismatch before rolling back. When `gate` returns 0 rows (e.g. a test inserted directly into `projects` via SQL, bypassing `api.rs:720`), `guard_root_write` inserts `(P, -1, 0, 0, 1)` `ON CONFLICT DO NOTHING` and re-runs the CTE once. On `epoch != expected_epoch`, the caller returns `Err(GcEpochChanged)` and rolls back `tx`. Otherwise `tx` stamps `gc_gen = write_gen` (`>= 1`) on every root/attachment row it inserts or updates (including `ON CONFLICT DO UPDATE`).
2. **`guard_upload_stage(tx, P) -> Result<i64>`** (used in `Packs::record_staged_by` at `pack.rs:1188` **only when `person.is_some()`**):
   Client upload staging (`Objects::stage`, `store.rs:1103`) checks no existing project objects, whereas GC's own compaction packs (`Objects::put_job_pack`, `store.rs:1073`) pass `person = None` and must **not** bump `gc_change_shards` during `compact_batch`. When `person.is_some()`, `guard_upload_stage` ensures `(P, -1)` exists and runs the same `gate` + `bump` CTE without the `gate.epoch = $4` filter (`SELECT $1, $3, 1 FROM gate`), stamping `packs.gc_gen = write_gen` (`>= 1`, matching `packs_uploads_by_gen`). When `person.is_none()`, `record_staged_by` inserts `gc_gen = 0` without touching the gate or shards.
3. **`guard_derived_write(tx, P, expected_epoch) -> Result<()>`** (used by writers that touch *only* pure `DerivedOrEphemeralObjectRef` tables — `Fill::flush`, `Blamer::write`, `record_too_wide`, `keep_cursor` — which introduce no roots or object attachments):
   Runs the `gate` query (`pg_advisory_xact_lock_shared(gate_key(P))` + `access_epochs FOR SHARE OF e`) without `bump`, and aborts with `GcEpochChanged` if `epoch != expected_epoch`.

**Fence operation `advance_write_gen(hub, P) -> Result<i64>`** and **epoch bump `bump_gc_epoch_tx(tx, P) -> Result<(i64, i64)>`:**
- `advance_write_gen` acquires `pg_advisory_xact_lock(gate_key(P))` (exclusive) and upserts `(P, -1)`:
  ```sql
  INSERT INTO access_epochs (project_id, person_id, epoch, changed_at, write_gen)
  VALUES ($1, -1, 0, 0, 2)
  ON CONFLICT (project_id, person_id)
  DO UPDATE SET write_gen = access_epochs.write_gen + 1
  RETURNING write_gen
  ```
  and commits immediately (raising `write_gen` without changing `epoch`).
- `bump_gc_epoch_tx` (`pack_gc.rs:2402`, called under `lock_gc_epoch_tx`) replaces its `veil_bump_epoch($1, -1)` call (`migrations/0006_access_epochs.sql:35`, which updated only `epoch` and `changed_at`) with one upsert incrementing **both** `epoch` and `write_gen`:
  ```sql
  INSERT INTO access_epochs (project_id, person_id, epoch, changed_at, write_gen)
  VALUES ($1, -1, 1, (extract(epoch FROM clock_timestamp()) * 1000)::BIGINT, 2)
  ON CONFLICT (project_id, person_id)
  DO UPDATE SET epoch = access_epochs.epoch + 1,
                changed_at = EXCLUDED.changed_at,
                write_gen = access_epochs.write_gen + 1
  RETURNING epoch, write_gen
  ```
  Every deleting switch returns `(new_epoch, new_write_gen, next_stamp)` out of `gc_transaction` and assigns `gc.covered_gen = new_write_gen; gc.stamp = next_stamp;` **strictly after `COMMIT` succeeds** (so a failed/retried commit never advances `covered_gen` or `stamp` past rolled-back rows).

**Lemma 1 (Generation Fence under `READ COMMITTED`).** Suppose `advance_write_gen` (or `bump_gc_epoch_tx` under `lock_gc_epoch_tx`) commits and returns `G`. Then:
1. Every guarded transaction `T` that obtained `write_gen < G` from `guard_root_write` or `guard_upload_stage` acquired `pg_advisory_xact_lock_shared(gate_key(P))` and `FOR SHARE` on `(P, -1)` *before* `advance_write_gen` / `lock_gc_epoch_tx` could acquire `pg_advisory_xact_lock(gate_key(P))` and `FOR UPDATE` on `(P, -1)`. Because PostgreSQL and YugabyteDB hold transaction-scoped advisory locks and row locks until commit or rollback (and all root/derived writers run at `READ COMMITTED`), `T` **already committed or aborted** before `(P, -1)` was updated to `G`.
2. Consequently, any `Snapshot` (`REPEATABLE READ READ ONLY`) or `READ COMMITTED` query started *after* that commit observes **every** committed row with `gc_gen < G`. No row with `gc_gen < G` can ever become newly visible later.
3. Every guarded root/attachment/upload transaction `T'` that commits *after* `G` is committed acquired `pg_advisory_xact_lock_shared(gate_key(P))` *after* `G` committed, reads the new `(epoch, write_gen)` via `FOR SHARE`, writes `gc_gen >= G` (`>= 1`) on every row it inserts or updates, and increments `C(P)` by `+1` in `T'`'s atomic commit.

**Lemma 2 (Stamp Monotonicity).** Because `gc_change_shards.changes` is only ever incremented (`changes + 1`) by committed transactions and never decremented or deleted while the project exists, `C(P)` is strictly increasing across committed guarded root/attachment/upload transactions. Under the exclusive gate (`pg_advisory_lock(gate_key(P))` or `lock_gc_epoch_tx`), zero guarded transactions are in flight; therefore `C(P) == gc.stamp` implies **zero** guarded root/attachment/upload transactions committed since `gc.stamp` was read.

### 2.3 Complete inventory of roots, attachments, derived rows and their writers

Every column in `public` that can hold an `ObjectId` (`OBJECT_SCHEMA_COLUMNS`, audited by `pack_gc::audit_schema_columns` at `pack_gc.rs:2687`) falls into one of the rows below (line numbers verified on `integration` @ `7b9b9a07`):

| Kind / Table (columns) | Writers (`file:line` on `integration` @ `7b9b9a07`) | Behind gate today? | Under this design | How a pass sees writes after its mark (`G_cov`) |
|---|---|---|---|---|
| `branches` (`target`) | `sync::push_staged` (`sync.rs:3544,3576`), `changes::create` (`changes.rs:703`), `landing::Service::commit` (`landing/service.rs:1540`), `embargo::record_in_tx` (`embargo.rs:764`); `DELETE` in `branches::delete_held` (`branches.rs:192`) | Yes (`DELETE` removes root) | `guard_root_write` stamps `gc_gen = write_gen` on `INSERT`/`UPDATE` | `branches WHERE project_id = $1 AND gc_gen >= $2` → `walk_objects` (and non-embargo branch names trigger `search_shards` lookup below) |
| `change_refs` (`snapshot`) | `changes::create` (`changes.rs:789,807,826,847`) | Yes | `guard_root_write` stamps `gc_gen` on `INSERT`/`UPDATE` | `change_refs WHERE project_id = $1 AND gc_gen >= $2` → `walk_objects` |
| `landing_queue` (`stack`, `result`) | `landing::enqueue` (`landing/mod.rs:640`, called from `sync.rs`/`changes.rs`/`prs`), `bisect` (`bisect.rs:1814`), `landing::Service` (`landing/service.rs:903,1665`); non-object status updates (`limits/landing.rs:149`) | Yes | `guard_root_write` stamps `gc_gen` when `stack` or `result` is written | `landing_queue WHERE project_id = $1 AND gc_gen >= $2` → `walk_objects` |
| `landings` (`submitted`, `landed`) | `landing::Service::commit` (`landing/service.rs:1702`) | Yes | `guard_root_write` stamps `gc_gen` | `landings WHERE project_id = $1 AND gc_gen >= $2` → `walk_objects` |
| `pr_revisions` (`base`, `head`, `changes`) | `prs::write_revision` (`prs/mod.rs:470`, from `create_with` `:654,757` and `add_revision` `:987,1100`); `prs::land_with` (`prs/mod.rs:2249` reads/lands); rating metadata only (`prs/mod.rs:253`) | Yes | `guard_root_write` stamps `gc_gen` in `write_revision` | `pr_revisions WHERE project_id = $1 AND gc_gen >= $2` → `walk_objects` |
| `pr_review_rules` (`checked`) | `prs::state::record_landing` (`prs/state.rs:172,251,259`) | Yes | `guard_root_write` stamps `gc_gen` | `pr_review_rules WHERE project_id = $1 AND gc_gen >= $2` → `walk_objects` |
| `embargo_snapshots` (`snapshot`) | `changes::create` (`changes.rs:759`), `embargo::record_in_tx` (`embargo.rs:772`), `prs::embargo::projected` (`prs/embargo.rs:434`) | Yes (`prs/embargo.rs:429` via `idempotent_tx`) | `guard_root_write` stamps `gc_gen` (upsert updates `gc_gen`) | `embargo_snapshots WHERE project_id = $1 AND gc_gen >= $2` → `walk_objects` |
| `embargo_lines` (`record_json`) | `embargo::record_in_tx` (`embargo.rs:709,742`), `prs::create_with` (`prs/mod.rs:723`), `prs/embargo.rs:801`; status-only `record_embargo_status_inner` (`embargo.rs:905,944`); lease-only `release_one` (`embargo.rs:1203`) | Root writes yes; status/lease updates touch no IDs | Root writes stamp `gc_gen`; status/lease updates preserve existing `gc_gen` | `embargo_lines WHERE project_id = $1 AND gc_gen >= $2` → `walk_objects` |
| `checks` (`snapshot`), `tested` (`snapshot`) | `ci::post_check_route` (`ci.rs:165,251`; log pruning `:292,308`), `ci::advance_tested` (`ci.rs:713,857,859`) | Yes | `guard_root_write` stamps `gc_gen`; `advance_tested` runs via `idempotent_tx` | `checks`/`tested WHERE project_id = $1 AND gc_gen >= $2` → `walk_objects` |
| `bisects` (7 cols), `bisect_reverts` (`culprit`, `revert_snapshot`) | `bisect.rs:416` (`bisects`), `bisect.rs:1518,1796` (`bisect_reverts`; conflict state `:1473,1924`); `save_bisect` (`bisect.rs:1843,1858`) | Yes (stale `b.gc_epoch` across 6 s wait at `:1840-1858`) | `guard_root_write` stamps `gc_gen`; `put_committed_at` at `:1840`; `save_bisect` re-reads `gc_epoch` via `idempotent_tx` | `bisects`/`bisect_reverts WHERE project_id = $1 AND gc_gen >= $2` → `walk_objects` |
| `search_shards` (`segments`), `search_heads` (`snapshot`) | `search::index::apply_write` (`search/index.rs:290`) | Yes (`GUARD_SQL`, no shard bump) | Switch `apply_write` to `guard_root_write` (sharing tx's `write_gen` in `finish_landing_run`); stamp `gc_gen` on `search_shards` | `search_shards WHERE project_id = $1 AND gc_gen >= $2` (live non-embargo branch or `''`) **plus** `search_shards WHERE project_id = $1 AND kind = 'code' AND branch = ANY($live_delta_branches)` → `leaf_objects` |
| Client uploads in `packs` (`person_id IS NOT NULL`, both layouts) | `Packs::record_staged_by` (`pack.rs:1188`), listing `UPDATE packs` (`sync.rs:3679`) | Listing yes; staging `INSERT` **no** | `guard_upload_stage` when `person.is_some()` (job packs `person == None` stay `gc_gen = 0`); listing `UPDATE` stamps `gc_gen`; `pending_uploads` re-probed even when `C(P) == gc.stamp` | `packs WHERE project_id = $1 AND person_id IS NOT NULL AND gc_gen >= $2` + `pending_uploads` → `Marks::read_upload` (`staged_ids`) |
| `snapshots` (`id`) — retained history (BUG-1780, BUG-2629) | `sync::push_staged` (`sync.rs:3681`), `changes::create` (`changes.rs:751`), `landing::Service::commit` (`landing/service.rs:1691`), `bisect` (`bisect.rs:1787`); all non-test `put_committed_at` | Yes, but `ON CONFLICT` kept old row un-dated & `catch_up_round_in` skipped candidates | `ON CONFLICT (project_id, id) DO UPDATE SET gc_gen = EXCLUDED.gc_gen, ...`; Δ rounds seed **all** Δ `snapshots` unconditionally; `Caches::put_committed` gated to `#[cfg(test)]` in favor of `put_committed_at` | `snapshots WHERE project_id = $1 AND gc_gen >= $2` → walked unconditionally in `catch_up_round_in` |
| `origins` (`real_id`, `origin_id`) | `sync::push_staged` (`sync.rs:3683`) | Yes (not in `STAMP_TABLES`) | `guard_root_write` stamps `gc_gen` (`ON CONFLICT DO UPDATE SET gc_gen = EXCLUDED.gc_gen`) | `origins WHERE gc_gen >= $2` **plus** `origins WHERE real_id = ANY($newly_reached)` → `origin_id` walked |
| `projections` (`real_id`, `projected_id`) + `hub.caches` memos (BUG-2623) | Guarded: `sync.rs:3685`, `changes.rs:770`, `landing/service.rs:1732`, `prs/embargo.rs:438`. **Unguarded today:** `sync::projected_inner` (`sync.rs:488,625`), `project_tips_together` (`query/graph.rs:816,836`), `write_prepared_memo` (`query/graph.rs:1274,1289`, called by `derive::finish_landing_run` `derive/mod.rs:515,546`) | **No** (3 writers unguarded; unpinned `put_memo` in 6 callers) | Every writer reads `gc_epoch` before compute/put, runs `guard_root_write` (via `idempotent_tx` on memo paths), stamps `gc_gen` on insert/conflict, calls `put_memo_at(..., gc_epoch, ...)` (`put_memo` test-only) | `projections WHERE gc_gen >= $2` **plus** `projections WHERE real_id = ANY($newly_reached)` → `projected_id` (and `real_id`) walked |
| Projected grant trees — **new** `projection_trees` (`projected_id`, `root_tree`) (BUG-2628) | `grant::for_tips` (`grant.rs:132`) → `grant::grant_root` (`grant.rs:175`) | **No** (stale `gc_epoch`, cache by `root`, `exists_loose`, swallows errors) | `for_tips` reads fresh `read_gc_epoch` (`observe_gc_epoch`); `grant_root` retries `GcEpochChanged` internally via `hub.db.begin()`, `sync::put_all` + `guard_root_write` + upsert `projection_trees (..., gc_gen)`, then inserts `hub.grants.stored` keyed by `(project, gc_epoch, snap)` | Mark: `projection_trees` trees walked via `Snapshot.tree`. Δ: `projection_trees WHERE gc_gen >= $2` **plus** `WHERE projected_id = ANY($newly_reached)` clears `Marks::unread` and walks `root_tree` |
| `graph` (`changed` leaf + `snapshot`, `parents`, `skip`) + `hub.derive.rows` | `derive::write_derive_tx` (`derive/mod.rs:1436,1449`, called by `Batch::flush_with_progress` `:1344` and `finish_landing_run` `:545`); read-miss cache in `Cx::stored_row` (`:246`), `Cx::stored_rows` (`:276`) | **No** | `Cx` carries `gc_epoch` from `read_gc_epoch` (`derive::read`, `locked_landing`, `resume`); `write_derive_tx` always calls `guard_root_write` and stamps `graph.gc_gen`; `locked_landing`/`resume` retry `GcEpochChanged`; `hub.derive.rows` keyed by `(project, cx.gc_epoch, id)` | `graph WHERE changed IS NOT NULL AND gc_gen >= $2` **plus** `graph WHERE snapshot = ANY($newly_reached) AND changed IS NOT NULL` → `changed` added to `Marks::leaves` |
| `file_history`, `rule_history`, `derive_progress` | `derive::write_derive_tx` (`derive/mod.rs:1444,1471,1490`) | **No** | Same guarded transaction as `graph` (`guard_root_write` with `cx.gc_epoch`) | Purged at switch (`file_history` by PK from changed paths); stale runs retry on `GcEpochChanged` |
| `view_graph`, `view_changes`, `view_file_history` + `hub.query.rows` | `query::graph::Walk::flush` (`query/graph.rs:1129`: `FileFill::write_rows_tx` `:1147` + `G::write_rows_tx` `:1149`), `write_prepared_memo` (`:1318,1321`), `query::files::Fill::flush` (`query/files.rs:250,287`); cache in `G` (`query/graph.rs:234,260,274,307,1155`) | **No** | `leased_fill` / `walk_tips` build `Cx` with `read_gc_epoch` and retry `GcEpochChanged` internally; `Walk::flush` / `Fill::flush` run under `guard_derived_write` via `idempotent_tx`; `G` keys `hub.query.rows` by `cx.gc_epoch` | Purged at switch (`view_file_history` by PK); stale flushes retry cleanly without `500` |
| `blame_memo`, `blame_ends`, `blame_jobs` | `query::files::Blamer::write` (`query/files.rs:1565`), `record_too_wide` (`:2063`), `JobEnd::of` (`:1715`), `sweep_keys` (`:2125`) | **No** | Blame worker builds `Cx` with `read_gc_epoch`, runs `write` / `record_too_wide` under `guard_derived_write`, and retries `GcEpochChanged` internally; `JobEnd::of` logs `Error::Other` server-side and returns `"internal error"` (never `{e:?}`) | Purged at switch (`snapshot = ANY($2)`); stale blame runs retry cleanly without leaking Debug text |
| `log_cursors` (`frontier`) | `query::keep_cursor` (`query/mod.rs:474`), read by `query::kept_cursor` (`query/mod.rs:515`) | **No** (and not purged) | Add `gc_epoch BIGINT` column; `keep_cursor` runs via `idempotent_tx` + `guard_derived_write` with `ON CONFLICT DO UPDATE SET created_at = EXCLUDED.created_at, gc_epoch = EXCLUDED.gc_epoch`; `kept_cursor` requires `gc_epoch = current` | `purge_expired_db_records` deletes `WHERE project_id = $1` by PK prefix; repeated frontiers after loose chunks refresh `gc_epoch` |
| `landed_from`, `landed_changes` | `landing::Service::commit` (`landing/service.rs:1718`), `landing/mod.rs:255`, `sync::push_staged` (`sync.rs:3547`) | Yes | Unchanged (inside guarded transactions); purged at switch | Purged at switch |

### 2.4 Proof of Invariant D and Invariant M across every phase of a pass

A GC pass (`run_gc: true`) on project `P` executes five phases:
1. **Mark fence and snapshot:** Record `mark_started_ms = now_ms()`, run `G_0 = advance_write_gen(hub, P)`, and open a `Snapshot` (`REPEATABLE READ READ ONLY`) transaction `S_0`: read `stamp_0 = C(P)`, `roots_0 = collect_db_roots(S_0, P)` (including `projection_trees`), and `uploads_0 = upload_names(S_0, P)`. Walk `roots_0` (`walk_from_roots`) and read `STAGED` upload indexes into `marks` (recording any upload whose `read_index` is `None` in `marks.pending_uploads`); set `gc.covered_gen = G_0`, `gc.stamp = stamp_0`, and `mark_stamp = stamp_0`. List packed and loose objects, update `unreferenced_objects`, and form `expired_unreferenced` = stored objects `∉ marks.live` whose `since_ms <= now_ms - retention_window_ms` (`Marks::live = reachable ∪ leaves ∪ staged_ids ∪ unread`).
2. **Outer catch-up and bounded DB-purge / loose-purge switch (if any loose or DB-bearing candidate exists):**
   - **Outer `catch_up` (up to `CATCH_UP_ROUNDS = 6`):** First read `cur = read_change_stamp(&gc.db, P)` outside the gate; if `cur == gc.stamp && gc.marks.pending_uploads.is_empty()`, exit immediately without taking the exclusive gate (`0` writes on quiet passes). If `cur == gc.stamp && !gc.marks.pending_uploads.is_empty()`, re-probe `pending_uploads` via `Marks::read_upload` and walk any newly readable upload seeds. Otherwise run `G_next = advance_write_gen(hub, P)`, open `Snapshot` `S_k`, read `stamp_k = C(P)` and `collect_db_roots_since(S_k, P, gc.covered_gen)` + `pending_uploads`, walk from `marks` (expanding wave attachments on newly reached snapshots, see below), subtract `marks.live` from `expired_unreferenced`, and set `(gc.covered_gen, gc.stamp) = (G_next, stamp_k)`.
   - **Closure-safe DB purge before loose deletes (`S_db` first):** Partition `expired_unreferenced` into DB-bearing IDs `S_db` (snapshots, projections, origins, projection trees, and `graph.changed` blobs — typically $< 5\%$ of objects) and object-only loose trees/blobs `L_leaf`. Precompute `(path_key)` lists for `S_db` outside the gate (from `graph.changed` or tree diff while objects are still stored, §5.3). Drain `S_db` in bounded transactions of at most `MAX_PURGE_IDS_PER_TX = 2,048` IDs (yielding `derive_turn()` + `10 ms` between transactions if `|S_db| > 2,048`): each transaction acquires `lock_gc_epoch_tx`, runs `roots_at_switch` (aborting cleanly if it gives way), runs `purge_expired_db_records` on that `S_db` slice still in `expired_unreferenced`, calls `bump_gc_epoch_tx` (`epoch` `+1`, `write_gen` `+1`), commits, and **strictly after `COMMIT`** sets `(gc.covered_gen, gc.stamp) = (new_write_gen, next_stamp)`. No storage object is deleted during `S_db` purge batches.
3. **Chunked loose deletes (`delete_loose_chunk`, chunks of `LOOSE_DELETE_CHUNK = 256`, capped at `max_loose_deletes_per_pass = 4,096` for scheduled passes, ordered `S_db ∩ loose` before `L_leaf`):** Hold `pg_advisory_lock(gate_key(P))` on a dedicated `close_on_drop` connection across three substeps:
   - **3a (pre-delete transaction):** `lock_gc_epoch_tx`, `roots_at_switch` (fast-pathing **only** when `cur == gc.stamp && gc.marks.pending_uploads.is_empty()`), filter `chunk` to IDs still in `expired_unreferenced`, delete their `unreferenced_objects` rows, call `bump_gc_epoch_tx` (`E_a → E_b`, `write_gen → G_b`), commit, and **after `COMMIT`** update `(gc.covered_gen, gc.stamp)`.
   - **3b (storage deletes):** Delete `chunk`'s remaining IDs (`AT_ONCE = 32` concurrently, `LOOSE_DELETE_TIME = 10 s` budget checked between batches of 32, every batch joined before the next). Remove each deleted loose-only ID from `gc.expired_unreferenced`.
   - **3c (post-delete transaction):** Under `lock_gc_epoch_tx`, call `bump_gc_epoch_tx` (`E_b → E_c`, `write_gen → G_c`), commit, **after `COMMIT`** update `gc.covered_gen = G_c`, and unlock `gate_key(P)`.
4. **Pack compaction and dead-object switch (`compact_batch`, if `batch` non-empty):** Copy live entries of `batch` into staged job packs (`person = None`, `gc_gen = 0`) outside the gate, run `catch_up`, precompute changed paths for any remaining `S_db` IDs, then under `lock_gc_epoch_tx` run `roots_at_switch`; if any `id ∈ dead_ids` left `expired_unreferenced`, abort the switch and discard the staged job packs; otherwise run `purge_expired_db_records` on remaining `S_db` (at most `dead_ids` in `batch`), swap `LISTED`/`DISCARDED` pack states, delete `dead_ids` from `unreferenced_objects`, call `bump_gc_epoch_tx`, commit, and **after `COMMIT`** update `(gc.covered_gen, gc.stamp)`.
5. **Discarded pack sweep (`sweep_discarded`):** Delete `DISCARDED` packs whose `discarded_at <= now_ms - pack_grace_ms` (60 s).

**Wave attachment expansion on newly reached snapshots (`walk_from_roots` / `catch_up_round_in`):**
During any post-mark walk (`catch_up` or `roots_at_switch`), whenever snapshot IDs **newly join `marks.reachable`** in a BFS wave (`newly_reached`, bounded under the gate by `SWITCH_WALK_MAX = 256`), the walker batch-queries pre-existing attachments on the round's DB connection *regardless of their `gc_gen`*:
- `SELECT origin_id FROM origins WHERE project_id = $1 AND real_id = ANY($2)` (`origins_pkey`) → enqueue into `queue`;
- `SELECT projected_id FROM projections WHERE project_id = $1 AND real_id = ANY($2)` (`projections_by_real`, `.persistent(false)`) → enqueue into `queue`;
- `SELECT root_tree FROM projection_trees WHERE project_id = $1 AND projected_id = ANY($2)` (`projection_trees_pkey`) → remove `root_tree` from `marks.unread` and enqueue into `queue`;
- `SELECT changed FROM graph WHERE project_id = $1 AND snapshot = ANY($2) AND changed IS NOT NULL` (`graph_pkey`) → insert 64-hex `changed` IDs into `marks.leaves`,
repeating waves until `queue` is empty. And in `collect_db_roots_since(conn, P, covered_gen)`, for every non-embargo branch returned by `branches WHERE project_id = $1 AND gc_gen >= $2 AND hidden_for_embargo IS NULL`, it also executes `SELECT segments FROM search_shards WHERE project_id = $1 AND kind = 'code' AND branch = ANY($live_delta_branches)` (`search_shards_pkey` prefix).

**Proof of Invariant D (no reachable object is deleted):**

Consider any object `X` deleted either by a loose chunk (step 3b) or by a pack switch (step 4), and suppose for contradiction that `X` is in the closure of some committed root/attachment/upload/grant `R`.

- **Case 1: `R` (and, if `R` is an attachment or branch shard, its owning reachable snapshot `S` or live non-embargo branch `B`) was already committed and live before `G_0 = advance_write_gen` in Phase 1 and never overwritten.** By Lemma 1(2), `S_0` saw `R` (and `S`/`B`).
  - If all intermediate objects on `R →* X` were stored at Phase 1, `walk_from_roots` expanded `R →* X` (`Marks::leaves` is never treated as expanded, BUG-2622), placing `X ∈ marks.reachable ∪ marks.leaves`, so `X ∉ expired_unreferenced` — contradiction (`expired_unreferenced` only shrinks).
  - If an intermediate object `Y` on `R →* X` was absent from the store at Phase 1 (`Y ∈ marks.unread`), `Y` is either (1) an unpushed client object later uploaded via `Objects::stage` (`Packs::record_staged_by` with `person.is_some()`) or (2) a projected tree later materialized by `grant_root` into `projection_trees` (server-authored snapshots carry fresh timestamps and signatures, never colliding with `unread`). Both subcases fall under Case 2 below.
- **Case 2: `R` — or the root rescuing `R`'s owning snapshot `S` / branch `B`, or the client upload / `grant_root` supplying `Y ∈ marks.unread` — committed *after* `G_0` and *before* the deleting step acquired the exclusive gate** (before step 3a for loose delete of `X`, or before step 4's `lock_gc_epoch_tx` for pack drop of `X`).
  - **Direct root, re-pushed `snapshots` row (BUG-2629), or newly written attachment (`gc_gen >= G_0`):** By Rule 1 and Lemma 1(3), the writer stamped `gc_gen >= G_0` (including `ON CONFLICT DO UPDATE` on `snapshots`, `origins`, `projections`, `projection_trees`) and bumped `C(P)`. Because `(gc.covered_gen, gc.stamp)` are updated only *after* `COMMIT` of a fenced generation, an intervening `catch_up` round or `roots_at_switch` sees `C(P) != gc.stamp`, queries `collect_db_roots_since(conn, P, gc.covered_gen)`, seeds every returned root, `snapshots` row (unconditionally), `origins.origin_id`, `projections.projected_id`, `projection_trees.root_tree` (clearing `marks.unread`), and `graph.changed`, and walks to `X`.
  - **Pre-existing attachment `(S, A)` at `gc_gen < G_0` whose snapshot `S` was unreferenced at Phase 1 and rescued after `G_0` (B1):** Because `S` was unreferenced at Phase 1, `S ∉ marks.reachable` after Phase 1. Before `X` can be deleted, the rescuing root (`branches`, `pr_revisions`, `checks`, `change_refs`, …) has `gc_gen >= G_0` and walks `S`, adding `S` to `newly_reached` for the first time. Wave attachment expansion immediately queries `origins`, `projections`, `projection_trees`, and `graph.changed` for `S` by PK/index *independent of `gc_gen`*, enqueuing `A` (and in the next wave `A`'s `projection_trees` if `A` is a `projected_id`) and walking `A →* X`!
  - **Pre-existing `search_shards` at `gc_gen < G_0` on a branch `B` deleted or embargo-hidden before `G_0` and pushed/unhidden after `G_0` (B1):** Re-creating or unhiding `B` stamps `branches.gc_gen >= G_0` with `hidden_for_embargo IS NULL`; `collect_db_roots_since` queries `search_shards` (`kind = 'code'`) for `B` regardless of `search_shards.gc_gen` and adds `X` to `marks.leaves`.
  - **Client upload `U_1` (`person.is_some()`, B2):** `record_staged_by` commits `U_1` (`gc_gen >= G_0`, bumping `C(P)`) before `store.put(U_1)`. (a) If `store.put(U_1)` finishes before the deleting switch, either `C(P) != gc.stamp` or `!marks.pending_uploads.is_empty()` prevents `roots_at_switch` from taking the fast path; `Marks::read_upload` reads `U_1`'s index, adds its contents to `staged_ids`, moves any `Y ∈ marks.unread` into `seeds`, and walks `Y →* X`. (b) If `store.put(U_1)` is *still* in flight across the deleting switch (`read_index(U_1) == None`), `Objects::stage` (`store.rs:1103`) has not yet returned a receipt for `U_1`, so no push committed before the switch's `epoch` bump can list `U_1`; any later push naming `U_1` runs under the post-delete `epoch`, where `sync::complete` and `packs_to_list` (`sync.rs:3968-4015`) keep only objects whose snapshot/tree closures are verified present (`touched`) and reject missing `X`.
  - **Projected grant (`grant::for_tips` / `grant_root`, BUG-2628, B3):** `for_tips` calls `read_gc_epoch` (querying `access_epochs` and updating `observe_gc_epoch`, even on YugabyteDB without `NOTIFY`), and keys `hub.grants.stored` by `(P, gce, snap)` only *after* `projection_trees (P, snap, root_tree, gc_gen)` commits under `guard_root_write`. Thus even if live `P_1` shares `root_tree` with an expired `P_0` cached under an older epoch or a different `snap`, `grant_root` misses `hub.grants.stored`, runs `sync::put_all`, and commits `(P, P_1, root_tree, gc_gen >= G_0)` before signing the `Grant` (or retries on `GcEpochChanged` if a deleting switch overlapped).
  - In every subcase, `X` enters `marks.live` and leaves `expired_unreferenced` (if any earlier walk hit `SWITCH_WALK_MAX` / `SWITCH_WALK_TIME` or errored, `catch_up_round` cleared `expired_unreferenced` completely). Step 3a filters `X` out of `chunk`; step 4 aborts the pack switch when `X ∉ expired_unreferenced`. Contradiction.
- **Case 3: `R`'s writer `W` executes `guard_root_write` *after* the deleting step acquired the exclusive gate.**
  - **Pack drop (step 4):** `lock_gc_epoch_tx` swaps packs and calls `bump_gc_epoch_tx` (`E_k → E_{k+1}`). Any `W` that read `gc_epoch <= E_k` fails `guard_root_write` with `GcEpochChanged` and retries under `E_{k+1}`, where the old pack is `DISCARDED` and forgotten (`forget_packs`). Readers mid-flight on the old pack have `DEFAULT_PACK_GRACE_MS = 60 s` before `sweep_discarded`.
  - **Loose delete (step 3):** Holding `pg_advisory_lock(gate_key(P))` across 3a (`E_a → E_b`), 3b (`remove_file` / S3 `DELETE`), and 3c (`E_b → E_c`) forces every writer `W` that started before 3a (`<= E_a`) or during 3b (`E_b`, including `FsStore::put`'s `try_exists` check at `store.rs:171` or a racing S3 `PUT`) to block on `gate_key(P)` until **after 3c**, see `epoch == E_c > W.gc_epoch`, abort with `GcEpochChanged`, and re-upload `X` strictly after 3b's delete completed.

**Proof of Invariant M (no dangling memos, derived rows, or multi-server cache entries):**

1. **DB-first purge ordering (`S_db` before storage deletes, S4):** In Phase 2, `S_db` rows are purged from `snapshots`, `origins`, `projections`, `projection_trees`, `graph`, `file_history`, `rule_history`, `derive_progress`, `view_*`, `blame_*`, `search_heads`, and `log_cursors` *before* step 3b deletes any loose object from storage (and in Phase 4, inside the atomic pack-switch transaction). Purging DB rows while leaving all objects intact in storage never creates a DB row naming a missing object, even across slice boundaries or mid-pass shutdown (`BUG-1780`).
2. **Writers committing before a purge switch (`E_k → E_{k+1}`):** Object-bearing memos (`projections`, `projection_trees`, `origins`, `graph.changed`) keep their closures stored by Case 2 above; pure derived rows (`view_*`, `file_history`, `rule_history`, `blame_*`, `log_cursors`) for expired snapshots are deleted by `purge_expired_db_records` (including `DELETE FROM log_cursors WHERE project_id = $1`), while `bump_gc_epoch_tx` raises `epoch` to `E_{k+1}`.
3. **Writers reaching `guard_*_write` after an epoch raise:** Any writer `W` with `W.gc_epoch < current_epoch` aborts with `GcEpochChanged` before committing any DB row or populating any cache, and retries from a fresh `read_gc_epoch`. Loose-deleted IDs are removed from `gc.expired_unreferenced` in step 3b so a later `compact_batch` switch in the same pass never purges rows newly committed at `>= E_c`.
4. **Multi-server read-miss caches (`hub.derive.rows`, `hub.query.rows`, `hub.caches`, `hub.grants.stored`, B6):** Every `Cx` (`derive::read`, `locked_landing`, `resume`, `query::graph`, `query::files`), `for_tips`, `landing::Service`, and `bisect` obtains an explicit `gc_epoch` from `read_gc_epoch` (or `perm::open_at`) at start and uses that fixed `cx.gc_epoch` for both cache lookups and read-miss inserts (`Cx::stored_row`, `Cx::stored_rows`, `G::row`). Thus (a) on YugabyteDB (no `NOTIFY`), Server B never reads stale `(P, E_0, S_exp)` after Server A raises `epoch` to `E_1`, and (b) if `epoch` advances `E_0 → E_1` between a read-miss `SELECT` at `E_0` and the cache `insert`, the entry is inserted into the dead `(P, E_0, …)` keyspace and is invisible to all `>= E_1` callers. $\blacksquare$

---

## 3. The cost under the gate

### 3.1 Asymptotic and statement comparison

Let $N$ be the total rows of a project across root and attachment tables (dominated by `snapshots`, `projections`, `graph`, `file_history`, `view_graph`, `view_changes` and `view_file_history`), $\Delta$ be the number of root/attachment rows written since the pass's last `covered_gen` fence, and $E_{\text{db}} = |S_{\text{db}}|$ ($\le E = |\text{expired\_unreferenced}|$) be the number of expired DB-bearing candidates purged by the pass.

| Operation | `integration` (`7b9b9a07`) | `t3/fable-open-bugs` (`914484bd`) | This design |
|---|---|---|---|
| Guarded writer (`push_staged`, `changes::create`, `Service::commit`, memo flush) | 1 statement (`GUARD_SQL`: shared advisory lock + `access_epochs FOR SHARE`) | Same (1 statement) | **1 statement** (`GUARD_SQL` + conditional 1-shard upsert in `gc_change_shards` in one CTE; `gc_gen` bound on row writes) |
| Mark fence (`advance_write_gen`) | — | — | **1 statement** under exclusive gate (1-row `access_epochs` upsert incrementing `write_gen`; no `epoch` bump) |
| Stamp check (`read_ref_stamp` vs `read_change_stamp`) | 16-table `UNION ALL` digest (`snapshots` whole-table) + `packs` scan + 3 `information_schema` queries: **$O(|snapshots|)$** | 19-table `UNION ALL` digest (`snapshots`, `origins`, `projections`, `graph` whole-table) + `packs` + 3 catalog queries: **$O(N)$** | `SELECT COALESCE(SUM(changes)::BIGINT, 0) FROM gc_change_shards WHERE project_id = $1`: **at most 32 PK rows, $O(1)$** |
| `roots_at_switch` when nothing moved (`cur == gc.stamp && pending_uploads.is_empty()`) | 1 whole-table `read_ref_stamp`: **$O(|snapshots|)$** | 1 whole-table `read_ref_stamp`: **$O(N)$** | **1 statement** (`read_change_stamp`, $\le 32$ rows): **$O(1)$, 0 root reads, 0 store reads** |
| `roots_at_switch` when $\Delta$ rows moved since `catch_up` | `read_ref_stamp` + full `collect_db_roots` (7 queries + 6 catalog queries): **$O(N)$** | Same: **$O(N)$** on every switch and every 256-object loose chunk | `read_change_stamp` + **2 indexed `UNION ALL` queries** (`WHERE project_id = $1 AND gc_gen >= $2 AND gc_gen > 0`, 0 catalog queries) + PK/index attachment wave on newly reached snapshots + $\le 256$ object reads: **$O(\Delta)$** |
| `purge_expired_db_records` (at purge switch, bounded $\le 2{,}048$ `S_db` IDs/tx) | 16 `DELETE`s per 500-ID chunk; `OR` predicates and unindexed `snapshot`/`real_id`/`changed` force **`SeqScan` of `projections`, `graph`, `file_history`, `view_*`: $O(\lceil E/500 \rceil \cdot N)$** | Same, plus chunk memo deletes | PK deletes on `file_history`, `view_file_history`, `log_cursors` + single-key index-backed `DELETE`s (`.persistent(false)` on skewed columns): **$O(E_{\text{db}} \log N)$**, never per loose chunk |
| Per-chunk DB work in `delete_loose_chunk` (256 objects) | `O(|snapshots|)` stamp + `O(N)` re-read if active | `O(N)` stamp + `O(N)` re-read + cached `projections` delete | **$O(1)$** stamp + **$O(\Delta)$** re-read + `DELETE FROM unreferenced_objects` ($\le 256$ PK keys) + two 1-row `(epoch, write_gen)` upserts |

### 3.2 Expected latency under the gate on PostgreSQL and YugabyteDB

Reference project size from BUG-2623 cycle 2c and the 1 GB / busy-repo profiles (`docs/BUGS.md` BUG-2462, BUG-2602, BUG-2623; `object-layout.md` §6): ~100,000 `snapshots`, ~1.5 M `projections`, ~100,000 `graph` rows, ~1 M `file_history` rows, ~3 M `view_file_history` rows (with `ANALYZE` up to date on YugabyteDB).

| Step holding `gate_key(P)` | PostgreSQL (local NVMe, estimate) | YugabyteDB (3-tablet / DocDB RF=3, estimate) | Notes |
|---|---:|---:|---|
| `advance_write_gen` (before mark / before non-quiet `catch_up` round) | 0.2–0.5 ms | 1.0–3.0 ms | 1 single-row PK upsert; **does not raise `epoch`** (0 writers retried; skipped entirely when `C(P) == gc.stamp && pending_uploads.is_empty()`) |
| `roots_at_switch` when quiet ($\Delta = 0$, `pending_uploads` empty) | 0.2–0.5 ms | 1.0–2.5 ms | Range scan of $\le 32$ contiguous rows in `gc_change_shards` |
| `roots_at_switch` when busy ($\Delta \approx 10\text{–}50$ rows in last `catch_up` round, objects cached) | 1.5–5.0 ms | 6–18 ms | 1 shard-sum read + 2 `UNION ALL` partial-index scans + 1 wave of PK attachment lookups + in-memory cache hits |
| `roots_at_switch` worst allowed case ($\Delta$ requires uncached store reads up to `SWITCH_WALK_MAX = 256`) | 15–120 ms (capped at `SWITCH_WALK_TIME = 1 s`) | 20–150 ms (capped at `1 s`) | Past 256 store reads or 1 s, switch gives way cleanly (`Ok(false)`) |
| One `S_db` DB-purge transaction ($\le 2{,}048$ expired DB-bearing IDs; typical scheduled pass $\le 200$ snapshots) | 5–25 ms | 20–90 ms | PK deletes on `file_history`/`view_file_history`/`log_cursors` + `(project_id, …)` index scans |
| One `delete_loose_chunk` (`LOOSE_DELETE_CHUNK = 256` loose objects, `AT_ONCE = 32` concurrent deletes, `pack_gc.rs:123,169`) | 10–45 ms (local/MinIO); 35–120 ms (S3) | 15–55 ms (MinIO); 40–130 ms (S3) | Bounded by `LOOSE_DELETE_TIME = 10 s` (`pack_gc.rs:175`) checked between batches of 32 (BUG-2624 governs hung TCP sockets) |

Compare `t3/fable-open-bugs` (`914484bd`) on the same 1.5 M-row project: every switch and every 256-object chunk cost **500–1,500 ms on PostgreSQL** and **5,000–10,000 ms on YugabyteDB** in `read_ref_stamp` + `collect_db_roots` alone — 100× to 500× longer per gate hold.

### 3.3 Why writers are never starved, and why GC still makes progress under load (BUG-2602)

**1. Writer contention on `gc_change_shards` without GC running.**
`guard_root_write` takes `FOR SHARE` on `access_epochs (P, -1)` (shared across all writers, as on `integration` today) and `FOR NO KEY UPDATE` on one random row `(P, s)` of `gc_change_shards` (`s ∈ 0..32`). Two concurrent transactions on the same project only wait on each other if they hash to the same shard `s` during the remaining milliseconds before `COMMIT`.
- At BUG-2602's load (~105 pushes/s, ~3 ms transaction duration): per-shard arrival rate is $105 / 32 \approx 3.3\text{ s}^{-1}$, utilization $\rho \approx 3.3 \times 0.003 \approx 1\%$; probability of shard collision is $< 1\%$.
- At G4 (`1,000` landings/s batched at ~20 commits/s): $\rho < 0.2\%$.
- Even at the synthetic RAM-disk diagnosis peak (`2,600` pushes/s on one project, ~0.8 ms local transaction): $2{,}600 / 32 \approx 81\text{ s}^{-1}$ per shard, $\rho \approx 6.5\%$.

**2. Why BUG-2602's 0-of-90 pass starvation cannot recur.**
Before BUG-2602, any root write during the mark walk invalidated `RefStamp` and aborted the switch: at ~105 pushes/s (~1 push every 9.5 ms), 0 of 90 passes ever collected. With BUG-2602's `catch_up` + `roots_at_switch`, progress requires that the outer `catch_up` rounds converge faster than new objects arrive so that the final round under the gate sees $\le 256$ unwalked objects:
- On `t3/fable-open-bugs`, each outer `catch_up` round took **1–10 s** just to compute `read_ref_stamp` and stream `collect_db_roots` over 1.5 M rows. During a 5 s `catch_up` round on YugabyteDB at 105 pushes/s (~8 objects/push), writers created $5 \times 105 \times 8 \approx 4{,}200 > 256$ new objects! Thus `catch_up` *diverged*, and `roots_at_switch` always hit `SWITCH_WALK_MAX = 256` and gave way — reproducing BUG-2602's 0% collection rate on large repositories!
- Under this design, an outer `catch_up` round reads only `gc_gen >= covered_gen`. Round 1 walks what arrived during the full mark (say 2 s $\to$ ~210 pushes $\to$ ~1,680 objects, walked in ~30 ms). Round 2 walks only what arrived during those 30 ms (~3 pushes $\to$ ~24 objects $\le$ `SWITCH_WALK_MAX / 8 = 32`), and `catch_up` exits! When `roots_at_switch` immediately acquires the gate, $\Delta$ covers only the 1–5 ms since Round 2 (~0–1 push, 0–8 objects $\ll 256$), completing in **2–10 ms** and collecting on the first pass.

**3. Why writers are never starved during multi-chunk DB purges or loose sweeps.**
Note that on YugabyteDB 2025.2, if an exclusive `pg_advisory_lock` unlocks while *both* a shared `pg_advisory_xact_lock_shared` waiter and a second exclusive `pg_advisory_lock` waiter are queued, YugabyteDB wakes the exclusive waiter first. What prevents starvation here is that **at most one GC pass holds `LOCK_BASE ^ P` across the entire cluster**, and no other code path ever takes an exclusive lock on `gate_key(P)`. Between every two `2,048`-ID DB-purge transactions and between every two 256-object loose chunks, that single GC worker unlocks `gate_key(P)`, calls `hub.limits.derive_turn().await`, and sleeps `BG_CHUNK_GAP = 10 ms` with **zero exclusive `gate_key(P)` waiters queued**, so every waiting `pg_advisory_xact_lock_shared` writer wakes immediately and new writers run uncontested throughout the 10 ms gap before chunk $k+1$ requests `gate_key(P)`.

---

## 4. Scheduling, resource isolation and clean shutdown

### 4.1 Per-project scheduling state (`gc_schedule`)

Instead of polling object storage or scanning root tables on every project, the database tracks per-project GC eligibility in `gc_schedule` (no foreign key on `project_id`, matching `0015`/`0016` so YugabyteDB executes a single write per row):

```sql
CREATE TABLE IF NOT EXISTS gc_schedule (
    project_id       BIGINT PRIMARY KEY,
    dirty_since_ms   BIGINT,
    next_due_ms      BIGINT,
    last_run_ms      BIGINT NOT NULL DEFAULT 0,
    last_changes     BIGINT NOT NULL DEFAULT 0
);
```
with partial index `gc_schedule_due ON gc_schedule (next_due_ms, project_id) WHERE next_due_ms IS NOT NULL`. Clean, idle projects have `next_due_ms IS NULL` and are invisible to the index. When a project does not exist in `projects`, `gc_scan` deletes its `gc_schedule`, `gc_change_shards`, and `projection_trees` rows.

**How `next_due_ms` moves (and why garbage created during an active pass cannot leak):**

Phase 1 of `run_project` (`run_gc: true`) records `mark_started_ms = now_ms()` *before* `advance_write_gen` and `mark_stamp = stamp_0` inside `S_0`.

| Signal | Where raised | What it sets |
|---|---|---|
| **Garbage-creating event** (`pack_gc::note_garbage(hub, project)`): branch delete (`sync.rs`, `branches.rs`), force-push (`sync.rs`), `change_refs` amend (`changes.rs`), PR close (`prs/mod.rs`), embargo release (`embargo.rs`), search segment replacement (`search/index.rs`), stale view-key sweep (`query/files.rs`), or any write in `objects` layout that aborted/failed after writing loose objects (`sync.rs`, `changes.rs`, `landing/service.rs`, `grant.rs`, `derive/mod.rs`, `query/graph.rs`) | Coalesced in memory per project on `hub.pack_gc` (flushed asynchronously at most once per `NOTE_FLUSH_INTERVAL = 10 s`, never adding a statement to any request transaction) | `dirty_since_ms = COALESCE(dirty_since_ms, now)`, `next_due_ms = LEAST(COALESCE(next_due_ms, due), due)` where `due = GREATEST(now + GC_QUIET_DELAY_MS, last_run_ms + GC_MIN_INTERVAL_MS)` |
| **Ordinary fast-forward push, API commit, landing batch, read, pull** | Nowhere | **Nothing.** Fast-forward commits leave every ancestor reachable and generate zero garbage; hot push/landing benchmarks execute 0 scheduler writes. |
| **After a pass (`run_project` with `run_gc: true`) finishes** | End of `run_with_lock` | Always sets `last_run_ms = now` and `last_changes = mark_stamp` (**never** current `C(P)`, which may include garbage-creating root updates committed *after* `S_0`!). Sets `next_due_ms`:<br>1. If the pass stopped at `max_loose_deletes_per_pass` or `max_packs_per_run` (more expired garbage ready now) → `now + GC_SLICE_GAP_MS` (`5 s`).<br>2. Else if `roots_at_switch` gave way → `now + GC_GIVE_WAY_BACKOFF_MS` (`30 s` + jitter).<br>3. Else query `SELECT MIN(since_ms) FROM unreferenced_objects WHERE project_id = $1`: if `Some(t)` → `GREATEST(t + retention_window_ms + 1_000, now + GC_MIN_INTERVAL_MS)` (wakes right after the marked objects' retention window expires).<br>4. Else read `cur_changes = read_change_stamp(P)` and update `gc_schedule` atomically: **only** when `(dirty_since_ms IS NULL OR dirty_since_ms <= mark_started_ms) AND cur_changes == mark_stamp` does it clear `dirty_since_ms = NULL, next_due_ms = NULL`; otherwise (a root write or `note_garbage` arrived *during* the pass!) it preserves `dirty_since_ms` and sets `next_due_ms = GREATEST(COALESCE(next_due_ms, now + GC_MIN_INTERVAL_MS), now + GC_MIN_INTERVAL_MS)`. |
| **Crash-orphan backstop (committed and uncommitted `SIGKILL` writes)** | `gc_scan` every `GC_BACKSTOP_CHECK = 1 h` | (a) Projects whose `C(P) > last_changes` and `now - last_run_ms >= GC_PERIODIC_MS` (`24 h`) get `next_due_ms = COALESCE(next_due_ms, now)`.<br>(b) To catch loose objects written in `objects` layout right before a `SIGKILL` that crashed *before* `guard_root_write` committed (leaving `C(P) == last_changes`), `gc_scan` also schedules at most 4 `objects`-layout projects per hour whose `now - last_run_ms >= GC_UNCOMMITTED_SWEEP_MS` (`7 d`, staggered by `project_id`), adding 0 statements to foreground writes while bounding worst-case uncommitted crash-orphan residency. |

**Proposed timing constants (`pack_gc.rs`):**
- `GC_SCAN_TICK = 30 s`: how often `gc_scan` polls `gc_schedule_due` (woken immediately when local `note_garbage` flushes a due time $\le$ 30 s away).
- `GC_QUIET_DELAY_MS = 60_000` (1 min): coalesces bursts of branch deletes or force-pushes before the marking pass runs.
- `GC_MIN_INTERVAL_MS = 300_000` (5 min): minimum gap between full mark walks on the same project (unless draining ready slices via `GC_SLICE_GAP_MS = 5_000`).
- `DEFAULT_RETENTION_WINDOW_MS = 3_600_000` (1 h, existing): how long an unreferenced object stays marked before any pass can delete it.

### 4.2 Dedicated pool, closure-safe slicing, many projects and multiple servers

- **Dedicated `pack_gc` connection pool and worker bulkhead (preserving all `DERIVERS = 4`):** On `integration`, `derive::Workers` has `DERIVERS = 4` (`DERIVE_CONNECTIONS = 8`, 2 connections per deriver, `derive/mod.rs:95-98`), `run_locked` takes a permit and `lock_conn` from `hub.derive`, and `delete_loose_chunk` (`pack_gc.rs:2216`) borrows its session-gate connection from `hub.db`. Taking 2 GC workers out of `DERIVERS = 4` would halve landing-deriver throughput and borrow foreground connections during loose sweeps. Instead, `hub.pack_gc` owns its **own small lazy `PgPool`** (`min_connections = 0`, `max_connections = GC_CONNECTIONS = 6`, `idle_timeout = 60 s`) and `Semaphore::new(GC_WORKERS)` (`GC_WORKERS = 2`, 3 connections per worker: `lock_conn`, statement/tx connection, and `delete_loose_chunk`'s session-gate connection — all `close_on_drop` when holding session advisory locks). `DERIVERS = 4` and `hub.db` remain 100% dedicated to `derive` and foreground requests.
- **Closure-safe slicing of large backlogs (`DEFAULT_BG_LOOSE_DELETES = 4,096`, `SCHEDULED_GC_PACKS_PER_RUN = 16`):** Suppose 50,000 commits (~500,000 objects) expire at once on a project.
  - Truncating `expired_unreferenced` to 4,096 arbitrary IDs before purging would delete a loose tree while leaving its expired snapshot in `snapshots`/`projections` (breaking `BUG-1780`), while purging all 500,000 IDs in one transaction would hold `gate_key(P)` for seconds.
  - Instead (§2.4 Phase 2–3), `mark_and_sweep_loose` separates DB-bearing expired IDs `S_db` (`snapshots`, `projections`, `projection_trees`, `origins`, `graph.changed`, `search_heads`) from leaf loose trees/blobs `L_leaf`, purges `S_db` **first** in bounded transactions of `MAX_PURGE_IDS_PER_TX = 2,048` IDs (~15–60 ms each, yielding `derive_turn()` + `10 ms` between transactions and deleting **zero** storage objects yet, so every remaining DB row's closure stays intact in storage at every step), and then deletes at most `DEFAULT_BG_LOOSE_DELETES = 4,096` loose objects (`S_db ∩ loose` first, then `L_leaf`). The remaining `L_leaf` objects already have zero DB references and are swept in 4,096-object slices on subsequent `5 s` passes (whose `S_db` is now empty, so their DB-purge phase is a no-op).
  - Note: background pack merges (`maybe_schedule`, `run_gc: false`) keep their existing `BACKGROUND_PACKS_PER_RUN = 4,096` (`pack_gc.rs:116`), while scheduled GC passes (`run_gc: true`) cap pack compaction at `SCHEDULED_GC_PACKS_PER_RUN = 16` (`TIER_MIN_PACKS = 16`, `pack_gc.rs:134`; explicit `run_project` keeps `MAX_PACKS_PER_RUN = 64`, `pack_gc.rs:107`).
- **One pass per project across all servers:** `run_locked` acquires `pg_try_advisory_lock(LOCK_BASE ^ project)` on a dedicated `close_on_drop` connection from `hub.pack_gc.db`. Each server's `gc_scan` queries `SELECT project_id FROM gc_schedule WHERE next_due_ms <= $1 ORDER BY next_due_ms LIMIT 32`, shuffles the batch (`fastrand`), and calls `run_project`; if a peer server holds `LOCK_BASE ^ project`, `pg_try_advisory_lock` returns `false` (`Report { skipped: true }`) and leaves `next_due_ms` untouched.
- **Many projects (e.g. 10,000 projects, 500 due at once):** Ordering by `next_due_ms ASC` serves longest-overdue projects first (FIFO fairness), and `GC_SLICE_GAP_MS = 5 s` interleaves other due projects between a large backlog's 4,096-object slices.
- **Both layouts (`packs` and `objects`):** In `packs`, `maybe_schedule` merges small packs (`run_gc: false`) and `gc_scan` runs `run_gc: true` when due; in `objects`, `gc_scan` is the collector of dead loose objects (`mark_and_sweep_loose`) plus any leftover pre-switch pack holding expired dead objects.

### 4.3 Two-stage clean server stop (`Running::stop`, closing BUG-2635 while preserving BUG-1970)

`Running::stop` (`crates/veil-server/src/lib.rs:184`) today stops the TLS accept loop (`self.task`), `landing::stop` (BUG-1970), and `search::index::stop` (BUG-1990). Two subtleties govern the shutdown order:
1. `self.task` (`lib.rs:506-520`) is **only** the TCP accept loop; each accepted connection runs in an untracked `tokio::spawn` (`lib.rs:520`), and open HTTP handlers (`query::*`, `web::*`, `prs::diff`) as well as in-flight landing commits (`landing/mod.rs:1726-2102`, 7 `derive::read` sites) execute through `derive::Cx`. Setting `hub.stopping = true` *before* open HTTP requests and `landing::stop` finish would make `Cx::db` abort in-flight requests and landing commits immediately (breaking **BUG-1970**).
2. Background `derive::resume` / `locked_landing`, viewer-graph fills (`query::graph`), blame jobs (`query::files`), `bisect::resume`, and `pack_gc` tasks must all stop and join before `Running::stop` returns so dropping the Tokio runtime never panics a blocking thread (`Cx::db`'s `Handle::block_on` / timer wheel) or leaks advisory locks/leases.

**Two-stage shutdown design:**
- **Tracked HTTP connections in `serve` (`lib.rs:520`):** `serve` clones `stop` (`watch::Receiver<bool>`) and an active-connection tracker (`Mutex<usize>` + `Notify`) into each spawned connection task. In the connection's `tokio::select!` (`lib.rs:578`, and around the `limits.is_none()` branch at `lib.rs:572`), `stop.changed()` calls `conn.as_mut().graceful_shutdown()` immediately (closing idle keep-alive sockets at once while allowing any in-flight HTTP stream to finish answering, bounded by `IDLE_LIMIT`).
- **Stage A — Drain foreground HTTP requests and queue services (`hub.stopping` is still `false`, so `Cx` runs normally):**
  1. `self.shutdown.send(true)`; await `self.task` (accept loop exits) **and** await `connections.wait_zero()` (all open HTTP requests complete cleanly, registering any landing/derive/search kicks).
  2. `landing::stop(&self.hub).await` and `bisect::stop(&self.hub).await` (in-flight landing and bisect commits finish their `derive::read` / DB work, register any final kicks, and release `landing_leases` / `bisect_leases` — preserving **BUG-1970**).
- **Stage B — Stop background workers (`hub.stopping` set to `true`):**
  3. `self.hub.stopping.store(true, SeqCst)`. `derive::Cx::db` and `Cx::tick` check `hub.is_stopping()` before queries and retry sleeps, returning `Err(Error::stopping())` cleanly; `derive::resume` stops before starting the next project.
  4. `derive::stop(&self.hub).await`, `query::stop(&self.hub).await` (draining tracked viewer-graph fills and blame jobs and releasing `view_fills` / `blame_jobs` leases), and `search::index::stop(&self.hub).await`.
  5. `pack_gc::stop(&self.hub).await` (flushing pending `note_garbage` project IDs once with a 1 s timeout, and awaiting `sweep_scan`, `gc_scan`, and active per-project tasks — checking `hub.is_stopping()` *between* phases and *between* 256-object loose chunks, **never** between step 3b and step 3c so any chunk that started deleting finishes raising `epoch`), plus awaiting `caches::listen`, `caches::send_notices`, and `embargo::run_loop`.

### 4.4 Transparent `GcEpochChanged` retry without HTTP 500/503 or stalled workers

Guarding derived, memo, grant, and follow-up writers requires that an overlapping GC `epoch` bump never surfaces as an HTTP `500`/`503`, leaks internal `Debug` text in JSON, or stalls background workers:
- **Idempotent auxiliary transactions (`db::idempotent_tx`, no `limits::mark_committed()`):** `db::transaction` (`db.rs:938`) calls `limits::mark_committed()` on commit, causing `db::retry_requests` (`db.rs:1014`) to return `503 busy` if a *second* transaction in the same HTTP request hits `GcEpochChanged`. Multi-step routes (`GET tips`, `POST history`, `q/log`, PR create/push, `POST checks`) run their idempotent memo/grant/cursor/follow-up writes (`sync::projected_inner`, `project_tips_together`, `grant::grant_root`, `prs::embargo::projected`, `Walk::flush`, `Fill::flush`, `query::keep_cursor`, `ci::advance_tested`, `bisect::save_bisect`) via `db::idempotent_tx` — built directly on `hub.db.begin_with("BEGIN ISOLATION LEVEL READ COMMITTED")` inside a bounded retry loop (up to `TRANSACTION_DEADLINE`) on `e.is_retryable() || pack_gc::is_gc_epoch_changed(&e)` that re-reads `read_gc_epoch`, re-uploads objects, and **never** sets `limits::mark_committed()`.
- **Viewer-graph fills (`query/graph.rs:754, 1506, 1623, 1649`):** `walk_tips` and `leased_fill` wrap `read_gc_epoch` + `project_tips` + `Walk` in an internal retry loop on `is_gc_epoch_changed(&e)` (rebuilding `Cx` at the new epoch), and `start_or_join` / `filled` preserve structured `Error` kinds (`StoreUnavailable`, `IndexesFull`, `Stopping`) instead of erasing errors via `format!("{e:?}")` into `500`.
- **Blame jobs (`query/files.rs:1565, 1715, 2063`):** The blame job runner retries `read_gc_epoch` + `Blamer` internally on `is_gc_epoch_changed(&e)`. In `JobEnd::of` (`query/files.rs:1715-1721`), non-`Error::Api` failures log `{e:#}` server-side and record a generic `"internal error"` (or `"busy"` on transient resource exhaustion), **never** placing `format!("{e:?}")` into `Error::Api.message` JSON.
- **Background `derive` (`derive/mod.rs:404, 541, 608, 1344`) and `bisect` (`bisect.rs:1840-1858`):** `locked_landing` and `derive::resume` catch `is_gc_epoch_changed(&e)` from `Batch::flush_with_progress` or `finish_landing_run`, re-read `read_gc_epoch`, and re-run from `derive_progress` (re-uploading `changed` / projected snapshot objects) instead of dropping `branches`. In `bisect.rs:1840-1858`, `put_committed_at(project.id, b.gc_epoch, &revert_snap_id)` replaces unpinned `put_committed`, and `save_bisect` after the 6 s landing wait reads a fresh `read_gc_epoch` inside `idempotent_tx`.

---

## 5. Schema changes

Two migrations are added (`0043` and `0044`). Note that `db::migrate_with` (`db.rs:220-280`) enforces a **single shared 10-minute `MIGRATION_DEADLINE` across all unapplied migrations** (including YugabyteDB's `veil_settle_*` + `yb_index_check` verification at ~160k rows/s, BUG-2482, BUG-2570, BUG-2571, BUG-2625, BUG-2626). To stay comfortably inside that shared 10-minute budget even on multi-ten-million-row YugabyteDB deployments, `0043` uses zero-row partial indexes (`WHERE gc_gen > 0`) and `0044` adopts **Option B** (omitting full-table snapshot indexes on the two tallest tables, `file_history` and `view_file_history`, cutting `0044`'s `yb_index_check` row volume by $> 70\%$).

### 5.1 YugabyteDB and rolling-upgrade constraints

1. **Idempotent transactional DDL and `access_epochs` backfill (`startup::not_safe_to_run_again`, BUG-2570).** YugabyteDB does not roll back DDL when a transaction aborts mid-migration. Every statement in the transactional part uses `IF NOT EXISTS` or `ON CONFLICT DO NOTHING`, including backfilling `access_epochs (project_id, -1)` for any project created before migration `0027` (`0043` below). New high-write GC tables omit `REFERENCES projects(id)` foreign keys so YugabyteDB performs one tablet write per row (`0016_search.sql:5`).
2. **Metadata-only column additions (`BUG-1211`).** `ADD COLUMN IF NOT EXISTS gc_gen BIGINT NOT NULL DEFAULT 0` and `write_gen BIGINT NOT NULL DEFAULT 1` rewrite no existing rows in PostgreSQL 11+ or YugabyteDB; historical rows read `gc_gen = 0`.
3. **Zero-backfill partial generation indexes (`WHERE gc_gen > 0`) and YugabyteDB CBO statistics.** Because every pre-existing row has `gc_gen = 0`, partial online indexes `ON <table> (project_id, gc_gen) WHERE gc_gen > 0` index **zero historical rows** during upgrade (`yb_index_check` scans 0 rows per index in `0043`). Every `collect_db_roots_since` query includes `AND gc_gen >= $2 AND gc_gen > 0` (`$2 >= 1`), matching the partial index under generic and custom plans alike (`packs_listed` pattern, migration `0041`). On YugabyteDB 2025.2 (`yb_enable_cbo = on`), freshly bulk-loaded tables without statistics can cause CBO to pick `<table>_pkey` with a DocDB `Storage Filter: (gc_gen >= $2 AND gc_gen > 0)` (which displays zero `Seq Scan` nodes in `EXPLAIN` while scanning every PK row of the project); production tables are covered by YugabyteDB auto-analyze, and scale/plan tests run `ANALYZE` after bulk setup (`tests/server_hub/landing.rs:3180`).
4. **Online index section rules (`db::migration_parts`, `crates/veil-server/src/db.rs:410`).** Everything after `-- veil: online indexes` contains only full-line `--` comments and bare `CREATE INDEX CONCURRENTLY IF NOT EXISTS <name> ON …;` statements (no inline `--`, `/*` or `$`).
5. **Rolling-upgrade mixed-version rule.** During a rolling upgrade from pre-`0043` servers to post-`0043` servers, old servers still running write `gc_gen = 0` without bumping `gc_change_shards` (and pre-existing unreferenced objects $> 1\text{ h}$ old could be collected immediately if `gc_scan` ran mid-rollout). Either `gc_scan` lands enabled in the deploy *after* slices 1–5 are rolled out across all nodes, or server heartbeats/leases advertise their binary schema version so `gc_scan` waits until no pre-`0043` server is active (§9.3).

### 5.2 Migration `0043_gc_generations.sql`

```sql
-- Change-sized GC cleanup and scheduled collection (BUG-2623, BUG-2628, BUG-2629).
-- Idempotent (IF NOT EXISTS / ON CONFLICT DO NOTHING): YugabyteDB applies DDL non-transactionally.
-- No foreign keys on high-write GC tables (one write per row on YugabyteDB, as 0015/0016).

ALTER TABLE access_epochs ADD COLUMN IF NOT EXISTS write_gen BIGINT NOT NULL DEFAULT 1;

INSERT INTO access_epochs (project_id, person_id, epoch, changed_at, write_gen)
SELECT id, -1, 0, 0, 1 FROM projects
ON CONFLICT (project_id, person_id) DO NOTHING;

CREATE TABLE IF NOT EXISTS gc_change_shards (
    project_id BIGINT NOT NULL,
    shard      SMALLINT NOT NULL,
    changes    BIGINT NOT NULL,
    PRIMARY KEY (project_id, shard)
);

CREATE TABLE IF NOT EXISTS projection_trees (
    project_id   BIGINT NOT NULL,
    projected_id TEXT NOT NULL,
    root_tree    TEXT NOT NULL,
    gc_gen       BIGINT NOT NULL,
    PRIMARY KEY (project_id, projected_id)
);
CREATE INDEX IF NOT EXISTS projection_trees_by_gen ON projection_trees (project_id, gc_gen);
CREATE INDEX IF NOT EXISTS projection_trees_by_root ON projection_trees (project_id, root_tree);

CREATE TABLE IF NOT EXISTS gc_schedule (
    project_id     BIGINT PRIMARY KEY,
    dirty_since_ms BIGINT,
    next_due_ms    BIGINT,
    last_run_ms    BIGINT NOT NULL DEFAULT 0,
    last_changes   BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS gc_schedule_due ON gc_schedule (next_due_ms, project_id) WHERE next_due_ms IS NOT NULL;

ALTER TABLE branches          ADD COLUMN IF NOT EXISTS gc_gen BIGINT NOT NULL DEFAULT 0;
ALTER TABLE embargo_snapshots ADD COLUMN IF NOT EXISTS gc_gen BIGINT NOT NULL DEFAULT 0;
ALTER TABLE embargo_lines     ADD COLUMN IF NOT EXISTS gc_gen BIGINT NOT NULL DEFAULT 0;
ALTER TABLE change_refs       ADD COLUMN IF NOT EXISTS gc_gen BIGINT NOT NULL DEFAULT 0;
ALTER TABLE landing_queue     ADD COLUMN IF NOT EXISTS gc_gen BIGINT NOT NULL DEFAULT 0;
ALTER TABLE landings          ADD COLUMN IF NOT EXISTS gc_gen BIGINT NOT NULL DEFAULT 0;
ALTER TABLE checks            ADD COLUMN IF NOT EXISTS gc_gen BIGINT NOT NULL DEFAULT 0;
ALTER TABLE tested            ADD COLUMN IF NOT EXISTS gc_gen BIGINT NOT NULL DEFAULT 0;
ALTER TABLE pr_revisions      ADD COLUMN IF NOT EXISTS gc_gen BIGINT NOT NULL DEFAULT 0;
ALTER TABLE pr_review_rules   ADD COLUMN IF NOT EXISTS gc_gen BIGINT NOT NULL DEFAULT 0;
ALTER TABLE bisects           ADD COLUMN IF NOT EXISTS gc_gen BIGINT NOT NULL DEFAULT 0;
ALTER TABLE bisect_reverts    ADD COLUMN IF NOT EXISTS gc_gen BIGINT NOT NULL DEFAULT 0;
ALTER TABLE search_shards     ADD COLUMN IF NOT EXISTS gc_gen BIGINT NOT NULL DEFAULT 0;
ALTER TABLE packs             ADD COLUMN IF NOT EXISTS gc_gen BIGINT NOT NULL DEFAULT 0;
ALTER TABLE snapshots         ADD COLUMN IF NOT EXISTS gc_gen BIGINT NOT NULL DEFAULT 0;
ALTER TABLE origins           ADD COLUMN IF NOT EXISTS gc_gen BIGINT NOT NULL DEFAULT 0;
ALTER TABLE projections       ADD COLUMN IF NOT EXISTS gc_gen BIGINT NOT NULL DEFAULT 0;
ALTER TABLE graph             ADD COLUMN IF NOT EXISTS gc_gen BIGINT NOT NULL DEFAULT 0;

ALTER TABLE log_cursors       ADD COLUMN IF NOT EXISTS gc_epoch BIGINT NOT NULL DEFAULT 0;

-- Truly tiny per-project tables (`tested` <= 1 row/branch, `pr_review_rules`,
-- `embargo_lines`, `bisects`, `bisect_reverts`) have `project_id` first in
-- their primary keys; `branches`, `search_shards`, and `embargo_snapshots`
-- can reach 10^3-10^5 rows on branch-heavy or policy-heavy projects and get
-- zero-row partial `_by_gen` indexes alongside the unbounded history tables.
-- veil: online indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS snapshots_by_gen ON snapshots (project_id, gc_gen) WHERE gc_gen > 0;
CREATE INDEX CONCURRENTLY IF NOT EXISTS origins_by_gen ON origins (project_id, gc_gen) WHERE gc_gen > 0;
CREATE INDEX CONCURRENTLY IF NOT EXISTS projections_by_gen ON projections (project_id, gc_gen) WHERE gc_gen > 0;
CREATE INDEX CONCURRENTLY IF NOT EXISTS graph_changed_by_gen ON graph (project_id, gc_gen) WHERE changed IS NOT NULL AND gc_gen > 0;
CREATE INDEX CONCURRENTLY IF NOT EXISTS packs_uploads_by_gen ON packs (project_id, gc_gen) WHERE person_id IS NOT NULL AND gc_gen > 0;
CREATE INDEX CONCURRENTLY IF NOT EXISTS change_refs_by_gen ON change_refs (project_id, gc_gen) WHERE gc_gen > 0;
CREATE INDEX CONCURRENTLY IF NOT EXISTS pr_revisions_by_gen ON pr_revisions (project_id, gc_gen) WHERE gc_gen > 0;
CREATE INDEX CONCURRENTLY IF NOT EXISTS checks_by_gen ON checks (project_id, gc_gen) WHERE gc_gen > 0;
CREATE INDEX CONCURRENTLY IF NOT EXISTS landings_by_gen ON landings (project_id, gc_gen) WHERE gc_gen > 0;
CREATE INDEX CONCURRENTLY IF NOT EXISTS landing_queue_by_gen ON landing_queue (project_id, gc_gen) WHERE gc_gen > 0;
CREATE INDEX CONCURRENTLY IF NOT EXISTS branches_by_gen ON branches (project_id, gc_gen) WHERE gc_gen > 0;
CREATE INDEX CONCURRENTLY IF NOT EXISTS search_shards_by_gen ON search_shards (project_id, gc_gen) WHERE gc_gen > 0;
CREATE INDEX CONCURRENTLY IF NOT EXISTS embargo_snapshots_by_gen ON embargo_snapshots (project_id, gc_gen) WHERE gc_gen > 0;
```

### 5.3 Migration `0044_gc_purge_indexes.sql` and PK-based `file_history` / `view_file_history` purge

Eliminates full-project scans from `purge_expired_db_records` (and provides `projections_by_real` for `B1`'s wave attachment lookup) with **9 compact online indexes**, intentionally omitting `file_history` and `view_file_history` so neither write amplification nor `0044`'s `yb_index_check` touches the two tallest tables:

```sql
-- Indexes for O(expired) deletes in `pack_gc::purge_expired_db_records`
-- and `projections_by_real` for rescued-snapshot attachment lookups.
-- veil: online indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS origins_by_origin ON origins (project_id, origin_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS projections_by_real ON projections (project_id, real_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS graph_by_changed ON graph (project_id, changed) WHERE changed IS NOT NULL;
CREATE INDEX CONCURRENTLY IF NOT EXISTS landed_from_by_landed ON landed_from (project_id, landed);
CREATE INDEX CONCURRENTLY IF NOT EXISTS landed_changes_by_landed ON landed_changes (project_id, landed);
CREATE INDEX CONCURRENTLY IF NOT EXISTS rule_history_by_snapshot ON rule_history (project_id, snapshot);
CREATE INDEX CONCURRENTLY IF NOT EXISTS view_graph_by_snapshot ON view_graph (project_id, snapshot);
CREATE INDEX CONCURRENTLY IF NOT EXISTS view_graph_by_real ON view_graph (project_id, real_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS view_changes_by_snapshot ON view_changes (project_id, snapshot);
```

**How `purge_expired_db_records` deletes every table without scanning:**
1. **`file_history` and `view_file_history` via full Primary Keys (`(project_id, path_key, depth, snapshot)` and `(project_id, view_key, path_key, depth, snapshot)`):**
   - Outside the gate (before each `S_db` purge transaction or `compact_batch` switch, while all candidate objects are still stored), for each snapshot `S` in the slice, `pack_gc` computes `S`'s changed `path_key` set (including ancestor directory `path_key`s, matching `derive::file_history` and `FileFill`): from `graph.changed` when present and not `'many'`, else by diffing `S`'s stored tree against `S.parents[0]`'s tree.
   - Inside `purge_expired_db_records` (*before* deleting `graph` and `view_graph`), `SELECT snapshot, depth FROM graph WHERE project_id = $1 AND snapshot = ANY($2)` (`graph_pkey`) and `SELECT view_key, snapshot, depth FROM view_graph WHERE project_id = $1 AND snapshot = ANY($2)` (`view_graph_by_snapshot`) supply the exact `(depth)` / `(view_key, depth)` tuples; combining them with `S`'s `path_key`s issues batched `UNNEST` PK deletes on `file_history_pkey` and `view_file_history_pkey`! (Only if a synthetic test injected a `graph`/`view_graph` row whose snapshot object was never stored does it fall back to `DELETE … WHERE project_id = $1 AND snapshot = ANY($missing_objs)` for that missing ID.)
2. **Split `OR` predicates and `.persistent(false)` on skewed columns:** Every `OR` delete (`origins`, `projections`, `projection_trees`, `landed_from`, `graph`, `view_graph`) is split into two single-predicate indexed `DELETE`s, with `.persistent(false)` on `projections.projected_id`, `projections.real_id`, and `view_graph.real_id` (collapsed hidden runs, BUG-2467 / BUG-2510).
3. **`log_cursors` by PK prefix:** Right before `bump_gc_epoch_tx` raises `epoch`, every existing row in `log_cursors` has `gc_epoch < new_epoch`, so `DELETE FROM log_cursors WHERE project_id = $1` deletes them directly via the `(project_id, view_key, id)` primary-key prefix.

### 5.4 Schema column registry (`OBJECT_SCHEMA_COLUMNS` and `NON_OBJECT_SCHEMA_COLUMNS`)

To satisfy `audit_schema_columns` (`pack_gc.rs:2687`):
- `OBJECT_SCHEMA_COLUMNS` adds `("projection_trees", "projected_id", SchemaColumnRole::GcAttachmentOrRetainedHistory)` and `("projection_trees", "root_tree", SchemaColumnRole::GcAttachmentOrRetainedHistory)`.
- `NON_OBJECT_SCHEMA_COLUMNS` adds:
  - `"write_gen"` to `access_epochs`;
  - `("gc_change_shards", &["project_id", "shard", "changes"])`;
  - `("gc_schedule", &["project_id", "dirty_since_ms", "next_due_ms", "last_run_ms", "last_changes"])`;
  - `("projection_trees", &["project_id", "gc_gen"])`;
  - `"gc_gen"` to each of the 18 altered tables;
  - `"gc_epoch"` to `log_cursors`.

---

## 6. Tests

All tests join existing integration test binaries (`crates/veil-server/tests/server_hub/pack_gc.rs`, `rv_core2.rs`, `startup.rs`), never guard assertions behind `if ok` / `if status == 200`, and assert first that the action under test succeeded or was refused with the exact expected code (`CLAUDE.md`). Existing tests in `tests/server_hub/pack_gc.rs` that inject raw SQL roots in `before_switch` (`bug_1782`, `bug_2590`, `bug_2602`) use a `guarded_exec(&hub, pid, …)` helper so they exercise the real `guard_root_write` contract.

| # | Bug / Race | Deterministic test & fault/hook mechanism | What it asserts |
|---|---|---|---|
| 1 | **BUG-2623 base race & multi-tx routes** (`B5.3`) | Un-ignore `pack_gc::bug_2623_a_memo_whose_snapshot_gc_deleted_is_derived_again`, plus live-writer variants for `sync::projected_inner`, `project_tips_together`, `write_prepared_memo`, and `prs::embargo::projected`, **and** multi-tx routes (`GET tips`, `POST history`, `q/log`, PR create, `POST checks` → `advance_tested` → `bisect`) where GC raises `epoch` between step 1 and step 2 | Stale auxiliary tx fails `GcEpochChanged` inside `idempotent_tx`, retries from `read_gc_epoch` without triggering `limits::mark_committed()` (`0` `503 busy`, `0` `500`), re-stores `P_cand`, commits `projections`, and member `history` + `q/log` answer `200` |
| 2 | **BUG-2623 cycle 1 & rescued old-gen attachments** (`B1`) | (a) Commit a new memo `P_2` (`gc_gen >= covered_gen`) naming expired `P_1`/`T_1` in `before_switch` and `before_loose_delete`. (b) Pre-populate unreferenced `S_old` (`> 1 h`) with `origins`, `projections`, `projection_trees`, and `graph.changed` at `gc_gen = 0` whose referenced objects are in `expired_unreferenced`, then rescue `S_old` via `prs::create_with`, `ci`, `changes::create`, or `sync::push_staged` during the pass. (c) Delete indexed branch `feat` (`search_shards` at `gc_gen = 0`), expire its segment `Seg_1`, and push `feat` back during the pass | Wave attachment lookup on newly reached `S_old` and branch `search_shards` lookup on `feat` walk and keep `P_1`/`T_1`, `O_old`, `C_old`, and `Seg_1`; member `history`, `q/log`, provenance, and search return `200` |
| 3 | **BUG-2623 cycle 2a (i) & `pending_uploads` fast path** (`B2`) | (a) $> 256$ expired loose objects (`2` chunks); commit a memo naming chunk 2's object when chunk 1 deletes or rolls back on empty `ids`. (b) Stage client upload `U_1` holding unpushed predecessor `X` (`S_live → X → T_old`) so `record_staged_by` commits before outer `catch_up` while `store.put(U_1)` finishes *after* `catch_up` with zero further DB writes (`C(P) == gc.stamp`) | `!pending_uploads.is_empty()` bypasses the `cur == gc.stamp` shortcut in `roots_at_switch`, reads `U_1`, walks `X → T_old`, and keeps `T_old`; `bump_gc_epoch_tx` increments `write_gen`; rollback does not advance `(covered_gen, stamp)` |
| 4 | **BUG-2623 cycle 2a (ii)** (loose-deleted candidate vs later pack switch) | Pass has both an expired loose projection `P_0` and a pack batch with dead objects (`compact_batch` runs after `mark_and_sweep_loose`). After `delete_loose_chunk` deletes `P_0`, hook before `compact_batch`'s switch triggers a fresh `tips` request that re-stores and commits `P_0` under the new epoch | `P_0` left `expired_unreferenced` when deleted loose; `compact_batch`'s switch does **not** purge the new `projections` row, and `P_0` stays stored and readable (`200`) |
| 5 | **BUG-2623 cycle 2a (iii) & PK history purge** (`S3`) | Collapsed hidden run of 2,000 real snapshots sharing one `projected_id` after 6 single-row purges on the same connection, plus multi-branch `file_history` and `view_file_history` rows for expired snapshots | Skewed deletes use index scans via `.persistent(false)`; `file_history` and `view_file_history` rows are deleted completely via PK from precomputed changed paths (`0` leftover rows) |
| 6 | **BUG-2623 cycle 2b, retry & multi-server caches** (`B5`, `B6`, `S5`) | Subtests for `leased_fill`/`walk_tips`, `Fill::flush`, `derive::locked_landing`/`resume` (`objects.is_empty()` & `finish_landing_run`), `Blamer::write`/`record_too_wide`, `keep_cursor` (re-emitting same frontier after `delete_loose_chunk`), and a **2-server** test (`NOTIFY` off) where Server A purges `S_exp` (`E_0 → E_1`) and Server B runs `derive::read` / `Cx::stored_rows` / `G::row` | Fills, blames, and `derive` retry `GcEpochChanged` internally (`200`, `derive_progress` advances, `JobEnd::of` never puts `{e:?}` in JSON); `keep_cursor` refreshes `gc_epoch` (`200`); Server B reads `E_1` via `Cx::gc_epoch` and misses `(P, E_0, S_exp)` |
| 7 | **BUG-2628 (`grant::for_tips` / `grant_root`, static, racing & 2-server)** (`B3`) | Live `P_1` (`ptree_1` unstored) shares subtree `psub_a` or full `T_root` with expired `P_0`. Subtest A: grant before GC, run 2 passes. Subtest B: `GET …/tips` inside `before_switch`, `before_loose_delete`, and `during_loose_delete` (`FsStore` `try_exists` race). Subtest C: 2-server (`NOTIFY` off), `P_0` (`T_root`) cached in Server A's `hub.grants.stored` at `E_0`, Server B deletes `P_0` & `T_root` (`E_2`), push `b2 → P_1` (`T_root`), call `GET …/tips` on Server A | `for_tips` refreshes `read_gc_epoch`, misses `(P, E_2, P_1)`, retries `GcEpochChanged` internally (never dropping the branch's grant), uploads `T_root`/`psub_a`, writes `projection_trees`, and `/objects/<T_root>` + `<psub_a>` return `200` |
| 8 | **BUG-2629** (expired snapshot re-pushed and unbranched) | Expired loose `R_old` whose trees/blobs are already stored loose and in `expired_unreferenced`. In `before_loose_delete` (and in `before_switch`), upload `R_old` alone, push to branch `temp`, then delete `temp` before the chunk/switch runs | `snapshots` row for `R_old` remains, `snapshots.gc_gen` was bumped on conflict, `catch_up_round_in` walked `R_old` unconditionally, and **every** tree and blob in `R_old`'s closure remains stored (`200`) |
| 9 | **BUG-2590 & give-way** | Update `bug_2590_a_root_written_during_a_pass_does_not_cost_the_pass` (`2c06b640`): 1 pass with 1 guarded `change_refs` write in `before_switch` collects in 1 switch; `bug_2602_a_switch_gives_way_past_its_bound_and_the_next_pass_collects` writes $> 256$ new objects in `before_switch` | First test collects in 1 pass / 1 switch; second gives way cleanly with `since_ms` preserved and collects on the immediate next pass |
| 10 | **BUG-2635 & BUG-1970 two-stage clean stop** (`S2`) | Start `TestHub` while an open `q/log` HTTP stream, an in-flight `landing` commit (`derive::read`), `derive::resume`, a viewer-graph fill, a blame job, and a multi-chunk `pack_gc` pass are all active; call `Running::stop().await` and drop the runtime immediately | Open HTTP request answers `200` and in-flight landing commits in Stage A (`BUG-1970`); Stage B stops all background workers with `0` panics, `0` leaked locks/leases, and step 3c completed if step 3b started |
| 11 | **BUG-2602 busy project, completion race & slicing** (`S1`, `S4`) | (a) 10,000 `projections`/`graph` rows + 1,000 expired objects under ~100+ ops/s across `packs` and `objects` layouts. (b) Delete a branch *during* Pass 1 and go idle. (c) Expire $> 5{,}000$ objects across 300 snapshots (`max_loose_deletes_per_pass = 4,096`) | (a) `0` failed ops, collects on first pass. (b) Pass 1 preserves `dirty_since_ms` / re-arms `next_due_ms` (`last_changes = mark_stamp`), Pass 2 collects the branch. (c) Slice 1 purges all 300 `S_db` rows before loose deletes (`BUG-1780` holds after Slice 1) |
| 12 | **Cost & YugabyteDB `EXPLAIN (ANALYZE, DIST)` gate** (`S3.2`, `S3.3`) | Populate $N_1 = 500$ vs $N_2 = 50{,}000$ rows (incl. `branches`, `search_shards`, `embargo_snapshots`), run `ANALYZE` (`landing.rs:3180`), write $\Delta = 5$ guarded rows in `before_switch`, run 6+ times (custom & generic plans) under `EXPLAIN (ANALYZE, DIST, FORMAT JSON)` | Every unbounded/indexed table uses `<table>_by_gen` (never `<table>_pkey` with `Storage Filter` and never `Seq Scan`), with **`Storage Rows Scanned <= 25`** at both $N_1 = 500$ and $N_2 = 50{,}000$ on PostgreSQL and YugabyteDB |
| 13 | **SQL guard & migration checks** (`B4`, `S3.1`, `S6`) | Test `guard_root_write` on `epoch` mismatch (assert `0` rows in `gc_change_shards`) and on raw SQL-inserted projects without prior `read_gc_epoch`; extend `bug_1782`; run `startup::not_safe_to_run_again`, `bug_2482`, `bug_2571`, `bug_2626` over `0043` and `0044` | Zero phantom shard rows; pre-`0027` / SQL-seeded projects get `(P, -1)` with `write_gen >= 1`; no FKs on `gc_change_shards`/`projection_trees`/`gc_schedule`; replay and `yb_index_check` pass |

---

## 7. Implementation plan

The implementation is self-contained on `integration` and **independent of the `object-layout` branch** (`docs/design/server/object-layout.md` §3.2): `mark_and_sweep_loose` and `compact_batch` already exist on `integration` and dispatch by pack presence vs loose store keys. Per `object-layout.md` §9, shipping this design (specifically scheduled loose collection + bounded gate cost) is the prerequisite before flipping the default new-project layout from `packs` to `objects`.

### 7.1 Ordered slices

Each slice compiles and passes `scripts/verify-fast.sh` on its own; slices 1–5 land before enabling `gc_scan` in slice 6 so no scheduled pass ever runs without full guard coverage, internal `GcEpochChanged` retries, and `O(Δ)` switches.

| Slice | Files touched (verified on `7b9b9a07`) | Est. lines | What lands |
|---|---|---|---|
| **1. Schema & registry** | `crates/veil-server/migrations/0043_gc_generations.sql`, `0044_gc_purge_indexes.sql`, `crates/veil-server/src/pack_gc.rs` (`OBJECT_SCHEMA_COLUMNS`, `NON_OBJECT_SCHEMA_COLUMNS`), `tests/server_hub/startup.rs`, `tests/server_hub/pack_gc.rs` (`bug_1782`) | ~105 SQL + ~85 Rust + ~140 test | `access_epochs.write_gen` + backfill of `(project_id, -1)` rows; `gc_gen` on 18 tables; `log_cursors.gc_epoch`; FK-free `gc_change_shards`, `projection_trees`, `gc_schedule`; 13 zero-row partial `_by_gen` online indexes (`0043`) + 9 compact online purge indexes (`0044`, Option B); YugabyteDB replay + `yb_index_check` coverage |
| **2. Guard primitives, `idempotent_tx` & root/attachment writers** | `crates/veil-server/src/db.rs` (`idempotent_tx`), `pack_gc.rs` (`guard_root_write`, `guard_upload_stage`, `guard_derived_write`, `advance_write_gen`, `bump_gc_epoch_tx`), `sync.rs`, `changes.rs`, `landing/mod.rs`, `landing/service.rs`, `prs/mod.rs`, `prs/state.rs`, `prs/embargo.rs`, `embargo.rs`, `ci.rs`, `bisect.rs`, `pack.rs` (`Packs::record_staged_by`), `search/index.rs`, `grant.rs` (`for_tips`, `grant_root`), `derive/mod.rs` (`write_derive_tx`, `locked_landing`, `resume`), `query/graph.rs` (`project_tips_together`, `write_prepared_memo`), `caches.rs` | ~460 Rust + ~520 test | Zero-phantom-insert `guard_root_write` CTE; `guard_upload_stage` only when `person.is_some()`; `(epoch, write_gen)` upsert in `bump_gc_epoch_tx`; `idempotent_tx` avoiding `limits::mark_committed()` `503`s; all 19 root/attachment tables stamp `gc_gen`; `for_tips` fresh `read_gc_epoch` + `(project, gce, snap)` grant cache + `projection_trees` (**BUG-2628**); `derive`/`bisect` internal `GcEpochChanged` retries; all non-test cache writes via `put_committed_at` / `put_memo_at` |
| **3. Pure derived writers, sanitized errors & `Cx::gc_epoch` caches** | `crates/veil-server/src/derive/mod.rs` (`Workers`, `Cx::gc_epoch`, `stored_row`, `stored_rows`, `derive::read`), `query/graph.rs` (`G`, `Walk::flush`, `leased_fill`, `walk_tips`, `start_or_join`, `filled`), `query/files.rs` (`Fill::flush`, `Blamer::write`, `record_too_wide`, `JobEnd::of`), `query/mod.rs` (`keep_cursor`, `kept_cursor`) | ~220 Rust + ~340 test | `Cx` carries `gc_epoch` from `read_gc_epoch` (`hub.derive.rows` & `hub.query.rows` immune to multi-server stale epochs); `guard_derived_write` + internal `GcEpochChanged` retry in fills and blames; `JobEnd::of` sanitized (no `{e:?}` in JSON); `keep_cursor` refreshes `gc_epoch` on conflict (**BUG-2623 cycle 2b**) |
| **4. `O(1)` stamp, `O(Δ)` switch, wave attachments & PK history purge** | `crates/veil-server/src/pack_gc.rs` (`read_change_stamp`, `collect_db_roots_since`, `roots_at_switch`, `catch_up`, `catch_up_round_in`, `walk_from_roots`, `mark_and_sweep_loose`, `delete_loose_chunk`, `purge_expired_db_records`), `tests/server_hub/pack_gc.rs`, `tests/server_hub/rv_core2.rs` | ~380 Rust + ~480 test | Quiet-pass pre-check before `advance_write_gen`; `cur == gc.stamp && pending_uploads.is_empty()` gate; post-`COMMIT` `(covered_gen, stamp)`; wave attachment lookup on newly reached snapshots & resurrected branch `search_shards`; unconditional Δ `snapshots` walk + removing loose-deleted IDs from `expired_unreferenced` (**BUG-2623 cycle 1/2a**, **BUG-2629**); `S_db`-first bounded purge + PK deletes on `file_history`, `view_file_history`, `log_cursors`; `ANALYZE` + `Storage Rows Scanned` plan test |
| **5. Two-stage clean shutdown (BUG-2635 & BUG-1970)** | `crates/veil-server/src/lib.rs` (`Hub`, `serve`, `Running::stop`), `derive/mod.rs` (`stop`), `query/mod.rs`, `query/graph.rs`, `query/files.rs`, `bisect.rs` (`stop`), `pack_gc.rs` (`stop`) | ~170 Rust + ~160 test | Connection tracker + `graceful_shutdown()` in `serve`; Stage A drains active HTTP requests then `landing::stop` & `bisect::stop` while `Cx` runs (**BUG-1970**); Stage B sets `hub.stopping = true` and awaits `derive`, `query` (releasing `view_fills`/`blame_jobs` leases), `search::index`, `pack_gc` (completing step 3c if step 3b started), `caches`, and `embargo` |
| **6. Scheduled collection (`gc_scan`) & dedicated pool** | `crates/veil-server/src/pack_gc.rs` (`gc_scan`, `note_garbage`, `hub.pack_gc.db`), `sync.rs`, `branches.rs`, `changes.rs`, `prs/mod.rs`, `embargo.rs`, `search/index.rs`, `query/files.rs`, `lib.rs` | ~210 Rust + ~190 test | Lazy `pack_gc` pool (`GC_WORKERS = 2`, `GC_CONNECTIONS = 6`, leaving `DERIVERS = 4` untouched); `gc_schedule` with `mark_stamp` completion guard + committed/uncommitted crash-orphan backstops; `S_db`-first `4,096` loose slicing across `packs` and `objects` layouts; busy-project end-to-end test (**BUG-2602**) |

**Totals:** ~105 lines SQL, ~1,525 lines server Rust across 18 existing server files, ~1,830 lines integration tests across 3 test modules.

### 7.2 Verification & review tier

This change touches `pack_gc.rs`, `sync.rs`, `grant.rs`, `derive/mod.rs`, `db.rs` migrations, and `Running::stop` — **high-risk server persistence & concurrency code** under `CLAUDE.md`:
1. Full `scripts/verify-fast.sh` + `scripts/verify-server.sh` on both **PostgreSQL** and **YugabyteDB** (including `startup::`, `pack_gc::`, `rv_core2::`, `warm::`, `grants::`, `embargo::`, and `leaks::`).
2. Benchmark gate (`scripts/bench-server.sh quiet` and `load`) comparing push throughput (1 project and 100 projects), API commit latency, and `q/log` / `tips` latency against `integration` to confirm the zero-extra-round-trip CTE in `guard_root_write` stays within noise ($\le 2\%$).
3. Independent adversarial code review checking every table in `OBJECT_SCHEMA_COLUMNS` and every `hub.*` in-memory cache against Invariants D and M before merge.

---

## 8. Alternatives considered

### 8.1 Whole-table `STAMP_TABLES` + chunk-scoped memo cleanup (`t3/fable-open-bugs` @ `914484bd`)
Tried in cycle 2 of BUG-2623: adding `origins`, `projections`, and `graph` to `read_reference_stamp`'s `bit_xor(hashtext(…))` and `collect_db_roots`, plus deleting chunk-local memos when the stamp moved. Rejected for the three reasons Cycle 2 established:
1. Full-table `SeqScan`s of million-row `projections` / `graph` tables under `pg_advisory_xact_lock(gate_key)` hold every push and API commit for 0.5–1.5 s on PostgreSQL and **5–10 s on YugabyteDB** at every switch and every 256-object loose chunk, re-introducing BUG-2602 starvation.
2. Advancing the pass-wide stamp inside chunk 1 while only purging memos naming chunk 1's 256 objects lets chunk 2 delete an object named by a memo committed before chunk 1 (and rolling back an empty chunk left the in-memory stamp advanced).
3. Leaving `Walk::flush`, `Fill::flush`, object-less `derive::Batch`, `grant_root`, and `blame` outside the guard left derived tables and caches poisonable across the pass.

### 8.2 Lookup-time repair ("treat a `projections` row whose snapshot is missing as no memo and re-derive")
Suggested in BUG-2623's initial note as a narrow alternative for `projections`. Insufficient as the primary fix for four reasons:
1. **Does not close Cycle 1 (dangling interior pointers):** if `P_2` exists in storage and names deleted parent `P_1` or deleted tree `T_1`, looking up `P_2` finds `P_2`'s own snapshot bytes intact; the failure (`missing object`) happens later when `history`, `fetch`, or `q/file` walks `P_2`'s parent chain or tree.
2. **Does not close BUG-2628:** a `Grant` is signed and returned to the client; when the client fetches `/v1/projects/…/objects/<psub_a>` directly from storage or `/objects`, there is no projection lookup on that path to re-derive `psub_a`.
3. **Does not cover `graph.changed` (`derive`):** `graph` rows store `changed` object IDs (`Many(ObjectId)`), and `view_graph` / `file_history` / `blame_memo` trust `graph` without re-reading every historical real snapshot.
4. **Masks genuine storage corruption:** silently re-deriving whenever a memo's object returns `NotFound` would hide real object-store data loss on `projections` / `graph` behind slow silent recomputation instead of surfacing an invariant violation.

### 8.3 Database triggers to maintain `gc_gen` and `gc_change_shards`
A `BEFORE INSERT OR UPDATE` PL/pgSQL trigger on each of the 19 tables could read `write_gen` and bump `gc_change_shards` automatically. Rejected because row-level triggers fire **per inserted row** (e.g., 400 rows in `derive::Batch` or `Walk::flush` = 400 trigger invocations and shard updates), whereas `guard_root_write` runs **once per transaction** inside the lock-acquisition CTE with zero extra SQL round-trips, and Rust compile-time visibility (`guard_root_write` returning `write_gen`) makes forgetting the guard at a call site obvious in review.

### 8.4 Single per-project counter row instead of 32 `gc_change_shards`
Updating `access_epochs.changes = changes + 1` on `(project_id, -1)` directly inside `guard_root_write` would upgrade `SELECT … FOR SHARE` to `FOR NO KEY UPDATE` on that single row, serializing every concurrent push, API commit, landing, grant, and memo write on a busy project behind each other's transaction commits (collapsing 100+ concurrent writers to 1 at a time on YugabyteDB). `SELECT … FOR SHARE` on `(project_id, -1)` + `ON CONFLICT DO UPDATE` on `shard = random() % 32` keeps `(project_id, -1)` shared while spreading counter row locks across 32 keys.

### 8.5 Eagerly storing all rewritten projected trees in `project_one` (for BUG-2628)
Having `project_one` upload `pr.created` trees whenever any `projections` row is computed would eliminate `Marks::unread` for projected trees, at a prohibitive write amplification cost: `derive::memo_tips` (`derive/mod.rs:1518`) and `query::graph::prepare_memo` (`query/graph.rs:1180`, called from `derive::finish_landing_run` at `derive/mod.rs:519`) project landed commits across every distinct `view_key` of the project's people, most of whose intermediate commits no client ever checks out via a `Grant`. Keeping lazy tree materialization in `grant_root` and recording only granted tips in `projection_trees` preserves lazy tree storage while giving GC an exact, 1-row-per-granted-tip root record.

### 8.6 Secondary purge indexes vs PK deletes on `file_history` and `view_file_history`
`file_history` (`PRIMARY KEY (project_id, path_key, depth, snapshot)`) and `view_file_history` (`PRIMARY KEY (project_id, view_key, path_key, depth, snapshot)`) are the two tallest derived tables (one row per changed file × ancestor directory depth per commit). Adding `(project_id, snapshot)` indexes in `0044` (Option A) would make `purge_expired_db_records` a uniform 1-column delete, but adds +1 secondary index write per history row and forces `db::migrate_with` (`db.rs:220`) to run online backfill + `yb_index_check` (~160k rows/s, BUG-2626) across tens of millions of rows inside its single shared 10-minute `MIGRATION_DEADLINE`. Recomputing `(path_key)` from `graph.changed` / tree diff outside the gate before object deletion and deleting by full primary key (Option B, adopted in §5.3) avoids both costs for ~70 lines of Rust. Kept in §9.1 below for owner confirmation.

### 8.7 Prefix-sharded loose GC (`p/<project>/ab/`, `object-layout.md` §7)
Scanning and sweeping 1/256th of the loose keyspace per pass reduces S3 `LIST` calls and `all_stored` RAM on $10^8$-object repositories, but still requires every piece of this design (`O(1)` stamp, `O(Δ)` switch, guarded memo/tree/derived writers, and `gc_schedule`) because any shard sweep still walks roots and purges DB records under the gate. Prefix-sharded loose sweeping remains a clean, orthogonal follow-up once repositories approach $10^7$–$10^8$ loose objects.

---

## 9. Open questions for the owner

1. **Purging `file_history` and `view_file_history` (`0044_gc_purge_indexes.sql`, §5.3 & §8.6):**
   - **Option A:** Create online `(project_id, snapshot)` indexes on both tables (~48 bytes + 1 index write per history row in background `derive`/`Walk::flush`; uniform `DELETE … WHERE snapshot = ANY($2)`), accepting a much heavier one-time `yb_index_check` scan inside `migrate_with`'s 10-minute startup budget.
   - **Option B (adopted in §5.3):** Omit those two indexes from `0044` (keeping the 9 much smaller indexes) and delete `file_history` / `view_file_history` by full primary key from `graph.changed` / snapshot tree diff before deleting objects (~70 lines of Rust, $> 70\%$ smaller `0044` migration volume, zero ongoing index write amplification).
   - *Design author's recommendation:* **Option B** (revised from Option A in cycle 1 once weighed against `migrate_with`'s shared 10-minute `MIGRATION_DEADLINE`).
   - *Reviewer's recommendation:* **Option B** (saves write amplification and eliminates the main risk to the shared 10-minute migration deadline, `S3`).

2. **Default scheduling intervals, pool sizing, and slice budget (§4.1–§4.2):**
   - Proposed defaults: `GC_QUIET_DELAY_MS = 60 s`, `GC_MIN_INTERVAL_MS = 5 min`, `DEFAULT_RETENTION_WINDOW_MS = 1 h`, `GC_PERIODIC_MS = 24 h` (plus `GC_UNCOMMITTED_SWEEP_MS = 7 d` staggered for `objects` layout), `DEFAULT_BG_LOOSE_DELETES = 4,096` (purging `S_db` rows first before loose deletes), and `GC_WORKERS = 2` on a dedicated lazy `pack_gc` pool (`GC_CONNECTIONS = 6`, separate from `DERIVERS = 4`). Should any constant be tuned differently or exposed via CLI / env flags?
   - *Design author's recommendation:* Keep all constants internal (no new CLI/env flags, per `CLAUDE.md`) with the dedicated `pack_gc` pool and `S_db`-first `4,096` slicing in §4.2.
   - *Reviewer's recommendation:* Keep the timing constants internal with no new flags, isolate `GC_WORKERS` from `DERIVERS = 4` (`S6`), and enforce the `S_db`-first rule on the `4,096` slice cap (`S4`).

3. **Rolling-upgrade activation of `gc_scan` (§5.1 item 5):**
   - During a zero-downtime rolling upgrade from a pre-`0043` binary, an old node still running writes `gc_gen = 0` without bumping `gc_change_shards`, while pre-existing unreferenced objects already $> 1\text{ h}$ old would be eligible immediately if a new node ran `gc_scan` mid-rollout. How should deployments sequence activation?
   - *Design author's recommendation:* No permanent `--scheduled-gc` flag; ship slices 1–5 in one deploy (all nodes writing `gc_gen >= 1` and bumping `gc_change_shards`) and enable `gc_scan` (Slice 6) in the next deploy — or gate `gc_scan` automatically on a cluster-wide schema-version heartbeat so single-step upgrades are safe too.
   - *Reviewer's recommendation:* No permanent `--scheduled-gc` flag; either ship slices 1–5 in one deploy and enable `gc_scan` (Slice 6) in the next, or record each server's schema version on heartbeat/lease so `gc_scan` waits until no pre-`0043` server is active.

4. **Batched S3 `DeleteObjects` (`POST /?delete`) in `delete_loose_chunk`:**
   - `delete_loose_chunk` currently issues up to 256 `DELETE` requests in 8 batches (`AT_ONCE = 32`, `pack_gc.rs:123`, ~35–130 ms under the gate on S3). S3's `POST /?delete` deletes up to 256 keys in 1 HTTP round-trip (~10–25 ms), cutting loose-chunk gate hold time by ~3× (`object-layout.md` §7), at the cost of XML body signing, `Content-MD5`/SHA-256 headers, and per-key partial error parsing in `store.rs`. Include in Slice 4, or land as a separate follow-up?
   - *Design author's recommendation:* Keep as a separate follow-up PR after Slice 6 so Slice 4 touches zero S3 wire/signing code in `store.rs`.
   - *Reviewer's recommendation:* Keep as a separate follow-up so Slice 4's safety review stays small and decoupled from S3 XML `DeleteObjects` signing and partial-error handling.

---

## 10. Review cycle 1

Independent Tier A review of `90733dc3` against `integration` @ `7b9b9a07` raised 6 blocking (`B1`–`B6`), 6 should-fix (`S1`–`S6`), and 3 nit (`N1`–`N3`) findings. Every finding was resolved in the design and proofs above as follows:

| ID | Summary of finding | Resolution in this revision |
|---|---|---|
| **B1** | `collect_db_roots_since` missed pre-existing `origins`, `projections`, `projection_trees`, `graph.changed`, and branch `search_shards` (`gc_gen < covered_gen`) when an unreferenced snapshot or deleted/embargoed branch became live again during the pass | Added BFS wave attachment lookups by PK/index (`origins_pkey`, `projections_by_real`, `projection_trees_pkey`, `graph_pkey`) whenever snapshots newly enter `marks.reachable` in `catch_up` / `roots_at_switch` (bounded by `SWITCH_WALK_MAX = 256`), plus `search_shards` (`kind = 'code'`) PK-prefix lookup for non-embargo Δ `branches`; extended §2.3, §2.4 Case 2, and §6 test 2 |
| **B2** | `cur == gc.stamp` skipped `Marks::pending_uploads`; guarding `person == None` dirtied shards on GC job packs; `bump_gc_epoch_tx` (`veil_bump_epoch`) never incremented `write_gen`; `(covered_gen, stamp)` updated before `COMMIT` | Required `cur == gc.stamp && pending_uploads.is_empty()` in `read_stamp_and_roots` and `roots_at_switch` (and proved in-flight `Objects::stage` safety via `sync::complete` + `packs_to_list`); restricted `guard_upload_stage` to `person.is_some()`; replaced `bump_gc_epoch_tx` with one upsert incrementing both `epoch` and `write_gen`; moved `(covered_gen, stamp)` updates strictly after `COMMIT` (§2.2, §2.4, §6 test 3) |
| **B3** | `grant::for_tips` read cached `gc_epoch`, `hub.grants.stored` keyed by `T_root` could serve a deleted tree on a second server, and `for_tips` swallowed `GcEpochChanged` (`continue`), leaving BUG-2628 open | `for_tips` calls `pack_gc::read_gc_epoch` (`observe_gc_epoch` on YugabyteDB); `hub.grants.stored` is keyed by `(project, gc_epoch, snap)` *after* `projection_trees` commits; `grant_root` retries `GcEpochChanged` internally via `hub.db.begin()` and propagates hard errors (§2.3, §2.4 Case 2, §6 test 7) |
| **B4** | `guard_root_write`'s `bump` CTE (`VALUES … WHERE EXISTS`) inserted a phantom shard row on `epoch` mismatch; pre-`0027` / SQL-seeded projects lacked `access_epochs (project_id, -1)` | Rewrote `bump` as `INSERT … SELECT $1, $3, 1 FROM gate WHERE gate.epoch = $4 ON CONFLICT … DO UPDATE`; added `INSERT INTO access_epochs … SELECT id, -1, 0, 0, 1 FROM projects ON CONFLICT DO NOTHING` to `0043`; made `advance_write_gen` an upsert and handled 0-row `gate` in `guard_root_write` / `guard_upload_stage` (§2.2, §5.2, §6 test 13) |
| **B5** | `GcEpochChanged` on derived/memo/multi-tx paths caused `500` in fills/blames, `{e:?}` Debug text in blame JSON, `503 busy` after `limits::mark_committed()`, and stalled `derive` / `bisect` | Added `db::idempotent_tx` (no `limits::mark_committed()`) for idempotent memo/grant/cursor/follow-up writes; added internal `GcEpochChanged` retry loops in `leased_fill`/`walk_tips`, blame runner, `derive::locked_landing`/`resume`, and `bisect::save_bisect`; sanitized `JobEnd::of` and fill error mapping; replaced all non-test `put_committed`/`put_memo` calls with `put_committed_at`/`put_memo_at` (§2.3, §4.4, §6 tests 1 & 6) |
| **B6** | Multi-server stale `gc_epoch` in `derive::read` and post-`SELECT` epoch races in `Cx::stored_rows` (and `G::row`) poisoned `hub.derive.rows` / `hub.query.rows` | Stored explicit `gc_epoch` on `derive::Cx` (obtained from `read_gc_epoch` / `perm::open_at` when building `Cx`), used throughout `stored_row`, `stored_rows`, `cache_derive_rows`, and `query::graph::G` (§2.3, §2.4 Invariant M(4), §6 test 6) |
| **S1** | `gc_schedule` completion cleared `next_due_ms` and set `last_changes = C(P)`, leaking garbage created during an active pass and uncommitted `SIGKILL` loose writes | Recorded `(mark_started_ms, mark_stamp)` at Phase 1; set `last_changes = mark_stamp`; cleared `dirty_since_ms`/`next_due_ms` only when `(dirty_since_ms IS NULL OR dirty_since_ms <= mark_started_ms) AND C(P) == mark_stamp` (else re-armed); added staggered `GC_UNCOMMITTED_SWEEP_MS` backstop for `objects` layout (§4.1, §6 test 11) |
| **S2** | `Running::stop` set `hub.stopping = true` before open HTTP connections and `landing::stop` finished (breaking BUG-1970) and did not track spawned connection tasks in `serve` | Added connection tracking + `graceful_shutdown()` on `stop.changed()` in `serve` (`lib.rs:520`), and split `Running::stop` into Stage A (drain HTTP requests, `landing::stop`, `bisect::stop` with `stopping == false`) and Stage B (`stopping = true`, then `derive`, `query`, `search`, `pack_gc`, `caches`, `embargo`) (§4.3, §6 test 10) |
| **S3** | `0044` shared `migrate_with`'s single 10-minute `MIGRATION_DEADLINE` across 11 full-table index builds; YB 2025.2 scanned `<table>_pkey` without `ANALYZE`; `branches`, `search_shards`, `embargo_snapshots` lacked `_by_gen` indexes | Adopted Option B in `0044` (dropped `file_history_by_snapshot` and `view_file_history_by_snapshot`, deleting by PK from `graph.changed` / tree diff before object deletion); added `branches_by_gen`, `search_shards_by_gen`, `embargo_snapshots_by_gen` in `0043`; updated §5.1 and §6 test 12 to run `ANALYZE` and assert `<table>_by_gen` + `Storage Rows Scanned <= 25` |
| **S4** | `max_loose_deletes_per_pass = 4,096` either left `purge_expired_db_records` unbounded on 500k objects or broke BUG-1780 if sliced arbitrarily | Separated DB-bearing candidates `S_db` from leaf loose objects `L_leaf`: purge `S_db` first in bounded `2,048`-ID transactions (with `0` storage deletes yet), then delete up to `4,096` loose objects (`S_db ∩ loose` before `L_leaf`) (§2.4, §4.2, §6 test 11) |
| **S5** | `keep_cursor` `ON CONFLICT DO UPDATE` left old `gc_epoch` on repeated frontiers after `delete_loose_chunk`; `log_cursors` purge could use PK prefix | Updated `keep_cursor` conflict clause to `SET created_at = EXCLUDED.created_at, gc_epoch = EXCLUDED.gc_epoch`, and `purge_expired_db_records` to `DELETE FROM log_cursors WHERE project_id = $1` (§2.3, §5.3, §6 test 6) |
| **S6** | Cited `DERIVE_WORKERS = 8` instead of `DERIVERS = 4` (`DERIVE_CONNECTIONS = 8`) while `delete_loose_chunk` used `hub.db`; new tables had `REFERENCES projects(id)` FKs | Gave `pack_gc` its own lazy `PgPool` (`GC_WORKERS = 2`, `GC_CONNECTIONS = 6`), leaving `DERIVERS = 4` and `hub.db` untouched; dropped `REFERENCES projects(id)` from `gc_change_shards`, `projection_trees`, and `gc_schedule`, with orphan cleanup in `gc_scan` (§4.1, §4.2, §5.2) |
| **N1** | Wrong file/line/symbol/constant citations (`imports.rs`, `packs.rs`, `blame.rs`, `RowCache`, `AT_ONCE = 64`, `LOOSE_DELETE_TIME = 2 s`, writer sites in §2.3) | Re-audited and corrected every file path, line number, symbol name, writer list, and constant (`AT_ONCE = 32`, `LOOSE_DELETE_TIME = 10 s`) against `integration` @ `7b9b9a07` (§1, §2.3, §3.2, §7.1, §8.5, §9.4) |
| **N2** | §3.3 claimed YugabyteDB wakes shared xact waiters ahead of queued exclusive advisory waiters | Corrected §3.3 item 3: YugabyteDB wakes queued exclusive waiters first, and starvation is prevented because `LOCK_BASE ^ P` ensures at most one GC pass per project, leaving zero exclusive `gate_key(P)` waiters queued during `BG_CHUNK_GAP = 10 ms` |
| **N3** | Outer `catch_up` (§2.4) called `advance_write_gen` before checking whether the project was quiet | Checked `read_change_stamp == gc.stamp && pending_uploads.is_empty()` *before* `advance_write_gen` in outer `catch_up` (§2.4 Phase 2, §3.2, §7.1) |
