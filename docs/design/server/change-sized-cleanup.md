# Change-sized GC cleanup and scheduled collection

> **Status: design, not built** (2026-11-18, branch `t3/design-change-sized-cleanup` from `integration` @ `7b9b9a07`). Closes **BUG-2623**, **BUG-2628**, **BUG-2629** and **BUG-2635**, and adds **scheduled collection** (`docs/HUB.md` §13.37) across both object storage layouts (`packs` and `objects`, `docs/design/server/object-layout.md` §3.2 and §9).
>
> **Sources of truth:** `docs/OVERVIEW.md`, `docs/VISIBILITY.md`, `docs/ARCHITECTURE.md` ("Threat model"), `docs/HUB.md` §13.20 (S28) and §13.37 (S29), `docs/design/server/object-layout.md`.
>
> **Numbers:** "measured" names where a number was measured in `docs/BUGS.md` or `docs/HUB.md`. "Estimate" is arithmetic from those measurements and query plans; nothing was measured for this document.

## 1. Summary

Today `pack_gc::run_project` (`crates/veil-server/src/pack_gc.rs`) is only run directly (`run_gc: true`); background tasks only merge small packs (`maybe_schedule`, `run_gc: false`) and sweep discarded or stale staged containers (`schedule_sweep`, `sweep_scan`). Three defects sit between S29 as merged on `integration` and safe, scheduled collection:

1. **Derived and memo writers outside the gate, and whole-table work inside it (BUG-2623, BUG-2628).** Projection memos (`sync::projected_inner`, `query::graph::project_tips_together`, `query::graph::Walk::flush`, `derive::finish_landing_run`), projected grant trees (`grant::grant_root`), the real graph and its `changed` blobs (`derive::Batch::write_rows_tx`), viewer-graph and file-history caches (`Walk::flush`, `query::files::Fill::flush`), blame caches (`query::files::Blamer::write`, `record_too_wide`) and log cursors (`query::keep_cursor`) write rows or objects without reading `gc_epoch` and calling `guard_root_write`. When `t3/fable-open-bugs` (`914484bd`) tried to close BUG-2623 by adding `origins`, `projections` and `graph` to `STAMP_TABLES` and running chunk-scoped memo deletes, review found three flaws: (a) a chunk's memo cleanup advanced `gc.stamp` globally (even before rolling back an empty chunk) while purging only its own 256 objects, and ran a cached prepared delete on `projections.projected_id` (BUG-2467's plan skew); (b) unguarded writers of `view_*` and `graph` still committed rows for purged snapshots and cached them under the post-pass `gc_epoch`; and (c) hashing and re-reading whole `origins`, `projections` and `graph` tables under `lock_gc_epoch_tx` cost `O(rows)` at every switch and every 256-object loose chunk (0.5–1.5 s on PostgreSQL and 5–10 s on YugabyteDB at ~1.5 M rows), stalling every writer of the project.
2. **Re-recorded snapshots and multi-switch candidate state (BUG-2629).** `catch_up_round_in` skips `snapshots` rows that are in `gc.expired_unreferenced` even after the loose switch has purged `snapshots`, so a candidate snapshot re-pushed and then unbranched between the purge and a loose chunk keeps its `snapshots` row while losing its trees and blobs (breaking BUG-1780). Objects deleted by `delete_loose_chunk` also stay in `gc.expired_unreferenced`, so a pack switch later in the same pass purges rows newly committed under the raised epoch.
3. **No collection scheduler, and background work left running at stop (BUG-2635).** `objects` layout leaves orphans from lost transactions and superseded projections as loose objects that wait for `run_gc` (`object-layout.md` §3.2, §9). Meanwhile `Running::stop` (`lib.rs:184`) does not stop or wait for `derive`, viewer-graph fills, blame jobs or `pack_gc` tasks (BUG-1990's class).

**The design, in six rules:**

1. **Every writer of a root, retained-history row, object-bearing memo, projected grant tree, staged upload or derived row runs behind the GC epoch gate.** Each writer reads `gc_epoch` before checking or storing any object, checks `epoch == gc_epoch` under the shared gate as the first statement of its transaction, and tags any in-memory cache entry with that verified `gc_epoch` (never re-reading `hub.caches.gc_epoch` after commit).
2. **Sharded per-project change counters (`gc_change_shards`, 32 shards) replace `STAMP_TABLES`.** Every guarded writer of a root or attachment table increments one random shard in the same CTE as `guard_root_write` (zero extra SQL round-trips, no single-row write hotspot). Reading the project's stamp (`SUM(changes)` over at most 32 rows) is `O(1)` (< 0.5 ms on PostgreSQL, < 1.5 ms on YugabyteDB).
3. **A monotonic per-project write generation (`access_epochs.write_gen`) makes catch-up and switch reads `O(Δ)`.** Before its mark snapshot (and before each catch-up round), GC advances `write_gen` under the exclusive gate without changing `epoch` (~0.2 ms, aborting zero writers). Because the exclusive gate drains every transaction that read an older `write_gen`, every row committed after that fence carries `gc_gen >= G_mark`. Catch-up and `roots_at_switch` query only `WHERE project_id = $1 AND gc_gen >= $2`.
4. **Projected grant trees are recorded in `projection_trees` under the gate (BUG-2628), and re-recorded `snapshots` update `gc_gen` on conflict (BUG-2629).** `collect_db_roots_since` returns every new `projections`, `projection_trees`, `origins`, `graph.changed` and re-recorded `snapshots` row; `catch_up_round_in` clears `Marks::unread` for newly stored grant trees and walks every Δ `snapshots` row unconditionally. No chunk ever deletes committed memos; loose-deleted ids leave `expired_unreferenced` immediately.
5. **Scheduled collection runs per project from garbage signals, bounded per pass and coordinated across servers by `LOCK_BASE ^ project`.** Projects accrue debt counters (branch force-updates/deletes, discarded/lost writes, superseded memos/shards, age since last pass); a background loop (`gc_scan`, stopped cleanly by `Running::stop` alongside `derive`, fills, blames and sweeps) runs bounded passes under `derive_turn` and derive worker permits, yielding to writers if a switch's Δ walk exceeds 256 reads or 1 s.
6. **Both layouts (`packs` and `objects`) use the same mark, gate, Δ catch-up and loose-chunk sweep.** In `objects` layout `select_batch` finds no new packs, merges leftover pre-switch packs down once, and collects all dead objects through `mark_and_sweep_loose`.

---

## 2. The guarantee and its proof

### 2.1 Statement of the two invariants

For every project `P`, across any interleaving of pushes, API commits, landing batches, PR/CI/bisect/embargo updates, uploads, read grants, deriver runs, viewer-graph/file/blame queries, pack merges and GC passes on one or more servers:

- **Invariant D (Durability of reachable objects).** No object in `P` that is in the object closure of any committed authoritative root (`GcRoot`), live search shard (`GcConditionalLeafRoot`), active client upload (`packs` with `person_id IS NOT NULL` and `state IN (STAGED, LISTED)`), retained `snapshots` row (BUG-1780), or committed attachment of a reachable snapshot (`origins`, `projections`, `projection_trees`, `graph.changed`), or for which a valid signed `Grant` has been issued, is absent from `P`'s store (`packs` ∪ loose keys).
- **Invariant M (No dangling memos or derived rows).** After any transaction or cache write completes, no committed row in `origins`, `projections`, `projection_trees`, `graph`, `file_history`, `rule_history`, `derive_progress`, `view_graph`, `view_changes`, `view_file_history`, `blame_memo`, `blame_ends`, `search_heads` or `log_cursors`, and no entry in `hub.caches`, `hub.query.rows`, `hub.derive.rows` or `hub.grants.stored` under the current `gc_epoch`, names a snapshot purged by GC or an object deleted by GC.

### 2.2 State variables and the generation fence

Each project `P` has a GC control row `access_epochs (project_id = P, person_id = -1)` holding:
- `epoch: i64` (`>= 0`): raised **only** when GC purges DB rows or deletes objects (`pack_switch`, `loose_purge_switch`, step 1 and step 3 of `delete_loose_chunk`). Raising `epoch` invalidates in-flight writers that checked or stored objects under an older `epoch` (`GcEpochChanged`) and invalidates epoch-keyed in-memory caches.
- `write_gen: i64` (`>= 1`): raised whenever GC establishes a generation fence (`advance_write_gen`), and also whenever `epoch` is raised. Raising `write_gen` alone **does not** change `epoch` and never aborts an in-flight writer.

Alongside `access_epochs`, `gc_change_shards (project_id, shard, changes)` holds up to `GC_SHARDS = 32` rows per project (`shard ∈ 0..32`). The project's **change count** is `C(P) = COALESCE(SUM(changes), 0)` over those rows.

Two transaction-first guard helpers share the advisory gate `gate_key(P) = GATE_BASE ^ P`:

1. **`guard_root_write(tx, P, expected_epoch) -> Result<i64>`** (used by every writer of a root, staged upload, retained-history row or attachment row):
   ```sql
   WITH gate AS (
       SELECT e.epoch, e.write_gen
       FROM (SELECT pg_advisory_xact_lock_shared($2)) l, access_epochs e
       WHERE e.project_id = $1 AND e.person_id = -1
       FOR SHARE
   ),
   bump AS (
       INSERT INTO gc_change_shards (project_id, shard, changes)
       VALUES ($1, $3, 1)
       ON CONFLICT (project_id, shard)
       DO UPDATE SET changes = gc_change_shards.changes + 1
       WHERE EXISTS (SELECT 1 FROM gate WHERE gate.epoch = $4)
   )
   SELECT epoch, write_gen FROM gate
   ```
   If no row is returned or `epoch != expected_epoch`, `bump` writes nothing and the caller returns `Err(GcEpochChanged)`, rolling back `tx` and retrying from `read_gc_epoch` (`db::retry_requests` or worker loop). Otherwise `tx` stamps `gc_gen = write_gen` on every root/attachment row it inserts or updates (including `ON CONFLICT DO UPDATE`). Note that client upload staging (`Packs::record_staged` with `person_id IS NOT NULL`) checks no existing project objects; it runs the same shared-gate CTE without an `expected_epoch` comparison (`WHERE TRUE`), obtaining `write_gen` and bumping `gc_change_shards`.
2. **`guard_derived_write(tx, P, expected_epoch) -> Result<()>`** (used by writers that touch *only* pure `DerivedOrEphemeralObjectRef` tables — `Fill::flush`, `Blamer::write`, `record_too_wide`, `keep_cursor` — which introduce no roots or object attachments):
   Runs the `gate` query (`pg_advisory_xact_lock_shared(gate_key(P))` + `access_epochs FOR SHARE`) without `bump`, and aborts with `GcEpochChanged` if `epoch != expected_epoch`.

**Fence operation `advance_write_gen(hub, P) -> Result<i64>`:**
Acquires `pg_advisory_xact_lock(gate_key(P))` (exclusive) and executes:
```sql
UPDATE access_epochs
SET write_gen = write_gen + 1
WHERE project_id = $1 AND person_id = -1
RETURNING write_gen
```
and commits immediately.

**Lemma 1 (Generation Fence under `READ COMMITTED`).** Suppose `advance_write_gen` commits and returns `G`. Then:
1. Every guarded transaction `T` that obtained `write_gen < G` from `guard_root_write` acquired `pg_advisory_xact_lock_shared(gate_key(P))` and `FOR SHARE` on `(P, -1)` *before* `advance_write_gen` could acquire `pg_advisory_xact_lock(gate_key(P))` and `FOR UPDATE` on `(P, -1)`. Because PostgreSQL and YugabyteDB hold transaction-scoped advisory locks and row locks until commit or rollback, `T` **already committed or aborted** before `advance_write_gen` began its `UPDATE`.
2. Consequently, any `Snapshot` (`REPEATABLE READ READ ONLY`) or `READ COMMITTED` query started *after* `advance_write_gen` commits observes **every** committed row with `gc_gen < G`. No row with `gc_gen < G` can ever become newly visible later.
3. Every guarded root/attachment transaction `T'` that commits *after* `advance_write_gen` commits must have acquired `pg_advisory_xact_lock_shared(gate_key(P))` *after* `advance_write_gen` committed (or obtained `G` if `advance_write_gen` had just committed), and therefore writes `gc_gen >= G` on every row it inserts or updates and increments `C(P)` by `+1` in `T'`'s atomic commit.

**Lemma 2 (Stamp Monotonicity).** Because `gc_change_shards.changes` is only ever incremented (`changes + 1`) by committed transactions and never decremented or deleted while the project exists, `C(P)` is strictly increasing across committed guarded root/attachment transactions. Under the exclusive gate (`pg_advisory_lock(gate_key(P))` or `pg_advisory_xact_lock(gate_key(P))` + `lock_gc_epoch_tx`), zero guarded transactions are in flight; therefore `C(P) == gc.stamp` implies **zero** guarded root/attachment transactions committed since `gc.stamp` was read.

### 2.3 Complete inventory of roots, attachments, derived rows and their writers

Every column in `public` that can hold an `ObjectId` (`OBJECT_SCHEMA_COLUMNS`, audited by `pack_gc::audit_schema_columns`) falls into one of four classes below:

| Kind / Table (columns) | Writers (`file:line` on `integration`) | Behind gate today? | Under this design | How a pass sees writes after its mark (`G_cov`) |
|---|---|---|---|---|
| `branches` (`target`) | `sync::push_staged` (`sync.rs:3515`), `changes::create` (`changes.rs:694`), `landing::Service::commit` (`landing/service.rs:1496`); `DELETE` only in `branches::delete_held` (`branches.rs:180`); `hidden_for_embargo` in `embargo::record_in_tx` (`embargo.rs:764`, inside guarded `push_staged`) | Yes (`DELETE` removes root) | `guard_root_write` stamps `gc_gen = write_gen` on `INSERT`/`UPDATE` | `branches WHERE project_id = $1 AND gc_gen >= $2` → `walk_objects` |
| `change_refs` (`snapshot`) | `changes::create` (`changes.rs:694`), `sync::push_staged` (`sync.rs:3515`) | Yes | `guard_root_write` stamps `gc_gen` on `INSERT`/`UPDATE` | `change_refs WHERE project_id = $1 AND gc_gen >= $2` → `walk_objects` |
| `landing_queue` (`stack`, `result`) | `sync::push_staged` (`sync.rs:3516`), `changes::create` (`changes.rs:696`), `bisect::enqueue_revert` (`bisect.rs:1785`), `landing::Service::commit` (`landing/service.rs:1496`); state-only updates add no IDs | Yes | `guard_root_write` stamps `gc_gen` when `stack` or `result` is written | `landing_queue WHERE project_id = $1 AND gc_gen >= $2` → `walk_objects` |
| `landings` (`submitted`, `landed`) | `sync::push_staged`, `changes::create`, `landing::Service::commit` | Yes | `guard_root_write` stamps `gc_gen` | `landings WHERE project_id = $1 AND gc_gen >= $2` → `walk_objects` |
| `pr_revisions` (`base`, `head`, `changes`) | `prs::create` (`prs/mod.rs:720`), `prs::push_revision` (`prs/mod.rs:1077`), `prs::sync_from_push` (`prs/mod.rs:2326`) | Yes | `guard_root_write` stamps `gc_gen` | `pr_revisions WHERE project_id = $1 AND gc_gen >= $2` → `walk_objects` |
| `pr_review_rules` (`checked`) | `prs::state::record_landing` (`prs/state.rs:249` and inside guarded push/commit/landing) | Yes | `guard_root_write` stamps `gc_gen` | `pr_review_rules WHERE project_id = $1 AND gc_gen >= $2` → `walk_objects` |
| `embargo_snapshots` (`snapshot`) | `embargo::record_in_tx` (`embargo.rs:772`), `changes::create` (`changes.rs:759`), `prs/embargo.rs:434` | Yes | `guard_root_write` stamps `gc_gen` | `embargo_snapshots WHERE project_id = $1 AND gc_gen >= $2` → `walk_objects` |
| `embargo_lines` (`record_json`) | `embargo::record_in_tx` (`embargo.rs:709,742`), `prs/embargo.rs:801`, `embargo::release_one` (`embargo.rs:1203`); status-only `set_line_state` (`embargo.rs:944`, does not change snapshot IDs) | Root writes yes; `set_line_state` no | Root writes stamp `gc_gen`; `set_line_state` preserves existing `gc_gen` | `embargo_lines WHERE project_id = $1 AND gc_gen >= $2` → `walk_objects` |
| `checks` (`snapshot`), `tested` (`snapshot`) | `ci::report` (`ci.rs:165`), `ci::advance_tested` (`ci.rs:857`) | Yes | `guard_root_write` stamps `gc_gen` | `checks`/`tested WHERE project_id = $1 AND gc_gen >= $2` → `walk_objects` |
| `bisects` (7 cols), `bisect_reverts` (`culprit`, `revert_snapshot`) | `bisect.rs:399,416,1512,1518,1785` (`1473,1924` set `state = 'conflict'` only) | Yes | `guard_root_write` stamps `gc_gen` | `bisects`/`bisect_reverts WHERE project_id = $1 AND gc_gen >= $2` → `walk_objects` |
| `search_shards` (`segments`), `search_heads` (`snapshot`) | `search::index::apply_write` (`search/index.rs:290`) | Yes (`GUARD_SQL`, no shard bump) | Switch `apply_write` to `guard_root_write`; stamp `gc_gen` on `search_shards` | `search_shards WHERE project_id = $1 AND gc_gen >= $2` (filtered to `branch = ''` or live non-embargo branch) → `leaf_objects` |
| Client uploads in `packs` (`person_id IS NOT NULL`, both layouts) | `Packs::record_staged_by` (`pack.rs:1188`), `UPDATE packs` in `sync.rs:3679`, `changes.rs`, `landing/service.rs` | Listing yes; staging `INSERT` **no** | Staging `INSERT` and listing `UPDATE` take shared gate, bump shard, set `gc_gen`; unfinished S3 uploads tracked in `Marks::pending_uploads` | `packs WHERE project_id = $1 AND person_id IS NOT NULL AND gc_gen >= $2` + `pending_uploads` → `Marks::read_upload` (`staged_ids`) |
| `snapshots` (`id`) — retained history (BUG-1780, BUG-2629) | `sync::push_staged` (`sync.rs:3681`), `changes::create`, `landing::Service::commit`, `bisect::enqueue_revert` | Yes, but `ON CONFLICT` kept old row un-dated & `catch_up_round_in` skipped candidates | `ON CONFLICT (project_id, id) DO UPDATE SET gc_gen = EXCLUDED.gc_gen, ...`; Δ rounds seed **all** Δ `snapshots` unconditionally | `snapshots WHERE project_id = $1 AND gc_gen >= $2` → walked unconditionally in `catch_up_round_in` |
| `origins` (`real_id`, `origin_id`) | `sync::push_staged` (`sync.rs:3683`) | Yes (not in `STAMP_TABLES`) | `guard_root_write` stamps `gc_gen` (including `ON CONFLICT DO UPDATE SET gc_gen = EXCLUDED.gc_gen`) | `origins WHERE project_id = $1 AND gc_gen >= $2` → `origin_id` walked |
| `projections` (`real_id`, `projected_id`) + `hub.caches` memos (BUG-2623) | Guarded: `push_staged`, `changes::create`, `Service::commit`. **Unguarded today:** `sync::projected_inner` (`sync.rs:625`), `project_tips_together` (`query/graph.rs:836`), `Walk::flush` (`query/graph.rs:1289`), `derive::finish_landing_run` (`derive/mod.rs:856`) | **No** (4 writers unguarded; not stamped) | All 7 writers read `gc_epoch` before compute/put, run `guard_root_write`, stamp `gc_gen` (upsert updates `gc_gen`), call `put_memo_at(..., gc_epoch, ...)` | `projections WHERE project_id = $1 AND gc_gen >= $2` → `projected_id` (and `real_id`) walked unconditionally |
| Projected grant trees — **new** `projection_trees` (`projected_id`, `root_tree`) (BUG-2628) | `grant::grant_root` (`grant.rs:175`) | **No** (`exists_loose` + unguarded `put`) | Read `gc_epoch`, `sync::put_all` all `created` trees, `guard_root_write` + upsert `projection_trees (..., gc_gen)`, then insert `hub.grants.stored` at `gc_epoch` | At mark: `projection_trees` trees are stored and walked via `Snapshot.tree`. In Δ: `projection_trees WHERE gc_gen >= $2` removes `root_tree` from `Marks::unread` and walks `root_tree` |
| `graph` (`changed` leaf + `snapshot`, `parents`, `skip`) + `hub.derive.rows` | `derive::Batch::write_rows_tx` (`derive/mod.rs:1471`: `Batch::flush_with_progress`, `finish_landing_run`) | **No** | Read `gc_epoch` at run start; **every** `write_rows_tx` / `finish_landing_run` calls `guard_root_write` (even when `objects.is_empty()` or admin view), stamps `graph.gc_gen`, keys `hub.derive.rows` by `(project, gc_epoch, id)` | `graph WHERE project_id = $1 AND changed IS NOT NULL AND gc_gen >= $2` → `changed` added to `Marks::leaves` |
| `file_history`, `rule_history`, `derive_progress` | `derive::Batch::write_rows_tx` / `finish_landing_run` | **No** | Same guarded transaction as `graph` (`guard_root_write` with `gc_epoch` read before reading any snapshot) | Purged at switch; stale runs aborted by `GcEpochChanged` |
| `view_graph`, `view_changes`, `view_file_history` + `hub.query.rows` | `query::graph::Walk::flush` (`query/graph.rs:1265`), `query::files::Fill::flush` (`query/files.rs:250`), `derive::finish_landing_run` (`derive/mod.rs:878`) | **No** | `Walk` and `Fill` read `gc_epoch` before reading any row/object; `Walk::flush` uses `guard_root_write` (if memos written) or `guard_derived_write`; `Fill::flush` uses `guard_derived_write`; `hub.query.rows` inserts under verified `gc_epoch` | Purged at switch; stale flushes aborted by `GcEpochChanged` before DB commit or cache insert |
| `blame_memo`, `blame_ends`, `blame_jobs` | `query::files::Blamer::write` (`query/files.rs:1565`), `record_too_wide`, `Lease` | **No** | `Blamer` reads `gc_epoch` before walking; `write` and `record_too_wide` run under `guard_derived_write(..., gc_epoch)` | Purged at switch (`snapshot = ANY($2)`); stale blame runs aborted by `GcEpochChanged` |
| `log_cursors` (`frontier`) | `query::keep_cursor` (`query/mod.rs:474`) | **No** (and not in `purge_expired_db_records`) | Add `gc_epoch BIGINT` column; `keep_cursor` runs `guard_derived_write` with query's `gc_epoch`; `kept_cursor` requires `gc_epoch = current` (and `purge_expired_db_records` drops rows with `gc_epoch < new_epoch` on deleting switches) | Stale cursors invalidated on epoch raise and refused at `guard_derived_write` |
| `landed_from`, `landed_changes` | `sync::push_staged`, `changes::create`, `landing::Service::commit` | Yes | Unchanged (inside guarded transactions); purged at switch | Purged at switch |

### 2.4 Proof of Invariant D and Invariant M across every phase of a pass

A GC pass (`run_gc: true`) on project `P` executes five phases:
1. **Mark fence and snapshot:** `G_0 = advance_write_gen(hub, P)`. Open a `Snapshot` (`REPEATABLE READ READ ONLY`) transaction `S_0`: read `stamp_0 = C(P)`, `roots_0 = collect_db_roots(S_0, P)`, and `uploads_0 = upload_names(S_0, P)`. Walk `roots_0` (`walk_from_roots`) and read `STAGED` upload indexes into `marks`; set `gc.covered_gen = G_0` and `gc.stamp = stamp_0`. List packed and loose objects, update `unreferenced_objects`, and form `expired_unreferenced` = stored objects `∉ marks.live` whose `since_ms <= now_ms - retention_window_ms` (`Marks::live = reachable ∪ leaves ∪ staged_ids ∪ unread`).
2. **Loose catch-up and purge switch (if any loose candidate exists):** Outside the gate, `catch_up` loops up to `CATCH_UP_ROUNDS` (6): `G_next = advance_write_gen`, open `Snapshot` `S_k`, read `stamp_k = C(P)`; if `stamp_k == gc.stamp` and `marks.pending_uploads.is_empty()`, break; else read `collect_db_roots_since(S_k, P, gc.covered_gen)`, walk from `marks`, subtract `marks.live` from `expired_unreferenced`, and set `(gc.covered_gen, gc.stamp) = (G_next, stamp_k)`. Then, in one transaction under `lock_gc_epoch_tx` (exclusive gate + `FOR UPDATE` on `(P, -1)`): run `roots_at_switch`, purge DB rows for `expired_unreferenced` (`purge_expired_db_records`), raise `epoch` (`E_0 → E_1`) and `write_gen` (`→ G_purge`), commit, and **only after commit** set `(gc.covered_gen, gc.stamp)` in `gc`.
3. **Chunked loose deletes (`delete_loose_chunk`, chunks of 256):** Hold `pg_advisory_lock(gate_key(P))` on a dedicated `close_on_drop` connection across three substeps:
   - **3a (pre-delete transaction):** `lock_gc_epoch_tx`, `roots_at_switch` (reading `gc_gen >= gc.covered_gen`), filter `chunk` to ids still in `expired_unreferenced`, delete their `unreferenced_objects` rows, raise `epoch` (`E_a → E_b`) and `write_gen`, commit, and update `(gc.covered_gen, gc.stamp)`.
   - **3b (storage deletes):** Delete `chunk`'s remaining ids (`AT_ONCE` = 64 concurrently, every batch joined to completion before the next). Remove each deleted loose-only id from `gc.expired_unreferenced`.
   - **3c (post-delete transaction):** Raise `epoch` again (`E_b → E_c`) and commit before unlocking `gate_key(P)`.
4. **Pack compaction and dead-object switch (`compact_batch`, if `batch` non-empty):** Copy live entries of `batch` into staged job packs outside the gate, run `catch_up`, then under `lock_gc_epoch_tx` run `roots_at_switch`; if any `id ∈ dead_ids` left `expired_unreferenced`, abort the switch and discard the staged job packs; otherwise run `purge_expired_db_records` on remaining `expired_unreferenced`, swap `LISTED`/`DISCARDED` pack states, delete `dead_ids` from `unreferenced_objects`, raise `epoch` and `write_gen`, and commit. (If `batch` was empty and loose-only candidates had no loose files — e.g. expired DB-only rows — the standalone purge switch runs the same `catch_up` + `lock_gc_epoch_tx` + `roots_at_switch` + `purge_expired_db_records` + `bump_gc_epoch_tx`.)
5. **Discarded pack sweep (`sweep_discarded`):** Delete `DISCARDED` packs whose `discarded_at <= now_ms - pack_grace_ms` (60 s).

**Proof of Invariant D (no reachable object is deleted):**

Consider any object `X` deleted either by a loose chunk (step 3b) or by a pack switch (step 4), and suppose for contradiction that `X` is in the closure of some committed root/attachment/upload/grant `R`.

- **Case 1: `R` was committed before `G_0 = advance_write_gen` in Phase 1 and never overwritten.** By Lemma 1(2), `S_0` saw `R`.
  - If `R` is a walk root, retained `snapshots` row, or attachment of a reachable snapshot whose intermediate objects were all stored when Phase 1 walked, `walk_from_roots` expanded the path `R →* X` (note BUG-2622: `Marks::leaves` is never treated as expanded, so any tree/snapshot/tag on `R →* X` was expanded even if another entry named it as a file leaf). Thus `X ∈ marks.reachable ∪ marks.leaves`, so `X ∉ expired_unreferenced` — contradiction (`expired_unreferenced` only shrinks).
  - Could an intermediate object `Y` on `R →* X` have been missing (`Y ∈ marks.unread`) during Phase 1 and stored later? Only two kinds of objects can already be named by `R` while absent from the store:
    1. *A client-uploaded object* (e.g. an unpushed predecessor): stored only via `POST .../objects` (`Packs::record_staged`) and referenced via a guarded transaction. Before `X` can be deleted, `roots_at_switch` reads the upload's index (`staged_ids`) and moves `Y` from `marks.unread` into `seeds` (`pack_gc.rs:1199`), expanding `Y →* X`.
    2. *A server-computed projected tree* (`ptree_1`, BUG-2628): `Y` is not referenced by any `Grant` until `grant_root` runs. If `grant_root` already ran before `G_0`, `projection_trees` held `(P_1, ptree_1)` and `ptree_1` was already in the store when Phase 1 walked `P_1 → ptree_1 →* X`! If `grant_root` runs *after* `G_0`, Case 2 applies.
    (Server-authored snapshots — landings, merges, API commits — carry fresh timestamps and server signatures, so their `ObjectId`s never collide with a pre-existing `unread` ID.)
- **Case 2: `R` (or `grant_root` for `Y`, or a re-push of `R_old`) committed *after* `G_0` and *before* the deleting step acquired the exclusive gate** (before step 3a for loose delete of `X`, or before step 4's `lock_gc_epoch_tx` for pack drop of `X`).
  - By Rule 1 and Lemma 1(3), `R`'s transaction `T` executed `guard_root_write`, bumping `C(P)` and stamping `gc_gen >= G_0` on `R`'s row (including `ON CONFLICT DO UPDATE` on `snapshots`, `origins`, `projections`, `projection_trees`).
  - Either an intervening `catch_up` round or `roots_at_switch` in step 3a / step 4 sees `C(P) != gc.stamp` and queries `collect_db_roots_since(conn, P, gc.covered_gen)`. Because `gc.covered_gen` is only ever set to a `write_gen` fenced *before* the rows already folded into `marks`, `T`'s `gc_gen >= gc.covered_gen` is returned.
  - `catch_up_round_in` seeds every returned `walk_objects` root, every returned `snapshots` row (unconditionally — closing BUG-2629), every returned `origins.origin_id` and `projections.projected_id` (closing BUG-2623 Cycle 1), removes every returned `projection_trees.root_tree` from `marks.unread` and seeds it (closing BUG-2628), adds every returned `graph.changed` and live `search_shards` segment to `marks.leaves`, and reads every returned/pending client upload into `marks.staged_ids`.
  - Walking from those seeds stops only at `marks.reachable` (whose closures are already wholly in `marks` — if any earlier walk hit a read/time limit or error, `catch_up_round` cleared `expired_unreferenced` completely, preventing any deletion). Hence `X` enters `marks.live` and is removed from `expired_unreferenced`.
  - In step 3a, `X` is filtered out of `chunk` and is not deleted. In step 4, `dead_ids.iter().any(|id| !gc.expired_unreferenced.contains(id))` is true (`X ∉ expired_unreferenced`), so the pack switch aborts cleanly and discards its staged job packs without dropping `X`. Contradiction.
- **Case 3: `R`'s writer `W` executes `guard_root_write` *after* the deleting step acquired the exclusive gate.**
  - **For a pack drop (step 4):** `lock_gc_epoch_tx` holds the exclusive gate while swapping packs, purging DB rows, and raising `epoch` (`E_k → E_{k+1}`). If `W` read `gc_epoch <= E_k` (so `W` may have checked `exists(X)` against the old pack before the swap), `W` blocks on the gate until step 4 commits and then fails `guard_root_write` with `GcEpochChanged`. When `W` retries under `E_{k+1}`, the old pack is already `DISCARDED` and forgotten from lookup maps (`forget_packs` / `observe_gc_epoch`), so `X` is no longer visible as stored unless re-uploaded/re-stored. (Meanwhile readers already mid-flight on the old pack have `DEFAULT_PACK_GRACE_MS` = 60 s before `sweep_discarded` deletes the pack.)
  - **For a loose delete (step 3):** `delete_loose_chunk` holds the session gate continuously from before step 3a (`E_a → E_b`), across all storage deletes in step 3b, through step 3c (`E_b → E_c`).
    - Any writer `W` that started before step 3a committed read `gc_epoch <= E_a`.
    - Any writer `W` that started *during* step 3b (for instance, reading `gc_epoch = E_b` and calling `put(X)` in `FsStore` where `try_exists` still saw `X` milliseconds before `remove_file(X)`, or on S3 where `DELETE(X)` landed right after `PUT(X)`) blocks at `guard_root_write` until **after step 3c** raises `epoch` to `E_c`!
    - Therefore **every** writer `W` whose object checks or `put(X)` overlapped step 3b or preceded it sees `epoch == E_c > W.gc_epoch`, aborts with `GcEpochChanged`, and reruns its checks and `put(X)` *after* step 3b's delete has finished! (In `FsStore` `try_exists` is now `false` so `put(X)` writes and fsyncs a fresh file; on S3 `PUT(X)` executes strictly after `DELETE(X)`.)

**Proof of Invariant M (no dangling memos or derived rows):**

Suppose a writer `W` of a memo or derived row (or cache entry) references a snapshot or object `Z` that a pass purges or deletes:
1. By Rule 1, `W` read `W.gc_epoch` *before* looking up `Z` in DB/cache/storage or storing `Z`, and `W`'s DB transaction executes `guard_root_write` or `guard_derived_write` with `W.gc_epoch`.
2. **If `W` commits *before* the purge switch (`E_0 → E_1`):**
   - If `W` wrote an object-bearing memo (`projections`, `projection_trees`, `origins`, `graph.changed`), Case 2 above proves `Z` and its entire closure are walked in `roots_at_switch`, removed from `expired_unreferenced`, and **neither purged nor deleted**!
   - If `W` wrote a pure derived row (`view_graph`, `view_changes`, `view_file_history`, `file_history`, `rule_history`, `derive_progress`, `blame_memo`, `blame_ends`, `search_heads`, `log_cursors`) for an expired snapshot `S_exp` (e.g. `Fill::flush` finishing for a snapshot that has been unreferenced for > 1 hour), `purge_expired_db_records` runs *after* `W` committed (under the exclusive gate) and deletes `W`'s row for `S_exp`, while `bump_gc_epoch_tx` raises `epoch` to `E_1`, invalidating any cache entry `W` stored under `E_0`.
3. **If `W` reaches its guard *after* the purge switch (`E_1`) or loose-delete chunk (`E_c`):**
   - If `W` started before that epoch raise (`W.gc_epoch < current_epoch`), `guard_*_write` rejects `W` with `GcEpochChanged` before any DB row is committed and before any in-memory cache (`hub.caches`, `hub.query.rows`, `hub.derive.rows`, `hub.grants.stored`) is populated!
   - If `W` started *after* the purge switch (`W.gc_epoch >= E_1`), `S_exp` is already gone from `snapshots`, `branches`, `projections` and `view_graph`, so `W` cannot discover `S_exp` from any DB table or epoch-keyed cache. If `W` independently re-derives a projection `P_cand` of a *live* snapshot whose bytes happen to match an unreferenced loose file queued for a later chunk, `W` calls `put(P_cand)` and commits `projections` under `guard_root_write`; Case 2 and Case 3 above prove either the chunk's `roots_at_switch` sees `P_cand` and **keeps** it, or the chunk deletes `P_cand` first, raises `E_c`, and forces `W` to retry and re-upload `P_cand` after the delete!
4. **Across multiple switches in one pass (`mark_and_sweep_loose` followed by `compact_batch`):** Because step 3b removes every loose-only deleted ID from `gc.expired_unreferenced`, if `W` legitimately re-creates and commits `P_cand` under `E_c` after chunk `m` deleted it, `compact_batch`'s later switch will **not** include `P_cand` in `all_expired_hexes` and will not purge `W`'s newly committed row. $\blacksquare$

---

## 3. The cost under the gate

### 3.1 Asymptotic and statement comparison

Let $N$ be the total rows of a project across root and attachment tables (dominated by `snapshots`, `projections`, `graph`, `file_history`, `view_graph`, `view_changes` and `view_file_history`), $\Delta$ be the number of root/attachment rows written since the pass's last `covered_gen` fence, and $E = |\text{expired\_unreferenced}|$ be the number of expired dead objects collected by the pass.

| Operation | `integration` (`7b9b9a07`) | `t3/fable-open-bugs` (`914484bd`) | This design |
|---|---|---|---|
| Guarded writer (`push_staged`, `changes::create`, `Service::commit`, memo flush) | 1 statement (`GUARD_SQL`: shared advisory lock + `access_epochs FOR SHARE`) | Same (1 statement) | **1 statement** (`GUARD_SQL` + 1-shard upsert in `gc_change_shards` in one CTE; `gc_gen` bound on row writes) |
| Mark fence (`advance_write_gen`) | — | — | **1 statement** under exclusive gate (`UPDATE access_epochs SET write_gen = write_gen + 1`; no `epoch` bump) |
| Stamp check (`read_ref_stamp` vs `read_change_stamp`) | 16-table `UNION ALL` digest (`snapshots` whole-table) + `packs` scan + 3 `information_schema` queries: **$O(|snapshots|)$** | 19-table `UNION ALL` digest (`snapshots`, `origins`, `projections`, `graph` whole-table) + `packs` + 3 catalog queries: **$O(N)$** | `SELECT COALESCE(SUM(changes)::BIGINT, 0) FROM gc_change_shards WHERE project_id = $1`: **at most 32 PK rows, $O(1)$** |
| `roots_at_switch` when nothing moved since `catch_up` | 1 whole-table `read_ref_stamp`: **$O(|snapshots|)$** | 1 whole-table `read_ref_stamp`: **$O(N)$** | **1 statement** (`read_change_stamp`, $\le 32$ rows): **$O(1)$, 0 root reads, 0 store reads** |
| `roots_at_switch` when $\Delta$ rows moved since `catch_up` | `read_ref_stamp` + full `collect_db_roots` (7 queries + 6 catalog queries): **$O(N)$** | Same: **$O(N)$** on every switch and every 256-object loose chunk | `read_change_stamp` + **2 indexed `UNION ALL` queries** (`WHERE project_id = $1 AND gc_gen >= $2`, 0 catalog queries) + $\le 256$ object reads: **$O(\Delta)$** |
| `purge_expired_db_records` (once per pass, at purge switch) | 16 `DELETE`s per 500-ID chunk; `OR` predicates and unindexed `snapshot`/`real_id`/`changed` force **`SeqScan` of `projections`, `graph`, `file_history`, `view_*`: $O(\lceil E/500 \rceil \cdot N)$** | Same, plus chunk memo deletes | Single-key index-backed `DELETE`s (`.persistent(false)` on skewed columns): **$O(E \log N)$**, run **once** at the purge switch, never per chunk |
| Per-chunk DB work in `delete_loose_chunk` (256 objects) | `O(|snapshots|)` stamp + `O(N)` re-read if active | `O(N)` stamp + `O(N)` re-read + cached `projections` delete | **$O(1)$** stamp + **$O(\Delta)$** re-read + `DELETE FROM unreferenced_objects` ($\le 256$ PK keys) + two 1-row `epoch` bumps |

### 3.2 Expected latency under the gate on PostgreSQL and YugabyteDB

Reference project size from BUG-2623 cycle 2c and the 1 GB / busy-repo profiles (`docs/BUGS.md` BUG-2462, BUG-2602, BUG-2623; `object-layout.md` §6): ~100,000 `snapshots`, ~1.5 M `projections`, ~100,000 `graph` rows, ~1 M `file_history` rows, ~3 M `view_file_history` rows.

| Step holding `gate_key(P)` | PostgreSQL (local NVMe, estimate) | YugabyteDB (3-tablet / DocDB RF=3, estimate) | Notes |
|---|---:|---:|---|
| `advance_write_gen` (before mark / before each `catch_up` round) | 0.2–0.5 ms | 1.0–3.0 ms | 1 single-row PK update; **does not raise `epoch`** (0 writers retried) |
| `roots_at_switch` when quiet ($\Delta = 0$) | 0.2–0.5 ms | 1.0–2.5 ms | Range scan of $\le 32$ contiguous rows in `gc_change_shards` |
| `roots_at_switch` when busy ($\Delta \approx 10\text{–}50$ rows in last `catch_up` round, objects cached) | 1.5–4.0 ms | 5–15 ms | 1 shard-sum read + 2 `UNION ALL` index range scans at `gc_gen >= covered_gen` + in-memory cache hits |
| `roots_at_switch` worst allowed case ($\Delta$ requires uncached store reads up to `SWITCH_WALK_MAX = 256`) | 15–120 ms (capped at `SWITCH_WALK_TIME = 1 s`) | 20–150 ms (capped at `1 s`) | Past 256 store reads or 1 s, switch gives way cleanly (`Ok(false)`) |
| Loose-purge / pack switch DB purge ($E \le 4{,}096$ expired objects in scheduled pass, $\le 200$ expired snapshots) | 5–25 ms | 20–90 ms | Every `DELETE` uses a `(project_id, …)` index prefix; run once per pass |
| One `delete_loose_chunk` (256 loose objects, `AT_ONCE = 64` concurrent deletes, local/MinIO/S3) | 8–35 ms (local/MinIO); 25–90 ms (S3) | 12–45 ms (MinIO); 30–100 ms (S3) | Bounded by `LOOSE_DELETE_TIME = 2 s` between batches of 64 (BUG-2624 governs hung TCP connections) |

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

**3. Why writers are never starved during multi-chunk loose sweeps.**
In `objects` layout, all dead objects are loose. A scheduled pass deletes at most `DEFAULT_BG_LOOSE_DELETES = 4,096` loose objects (16 chunks of 256) per pass, and between every two chunks releases `gate_key(P)`, calls `hub.limits.derive_turn().await`, and sleeps `BG_CHUNK_GAP = 10 ms`. Because PostgreSQL and YugabyteDB grant queued `pg_advisory_xact_lock_shared` waiters ahead of a new `pg_advisory_lock` acquisition once unlocked, every writer that arrived during chunk $k$ drains completely during the 10 ms gap before chunk $k+1$ takes the gate.

---

## 4. Scheduling and clean shutdown

### 4.1 Per-project scheduling state (`gc_schedule`)

Instead of polling object storage or scanning root tables on every project, the database tracks per-project GC eligibility in a tiny table:

```sql
CREATE TABLE IF NOT EXISTS gc_schedule (
    project_id       BIGINT PRIMARY KEY REFERENCES projects(id),
    dirty_since_ms   BIGINT,
    next_due_ms      BIGINT,
    last_run_ms      BIGINT NOT NULL DEFAULT 0,
    last_changes     BIGINT NOT NULL DEFAULT 0
);
```
with partial index `gc_schedule_due ON gc_schedule (next_due_ms, project_id) WHERE next_due_ms IS NOT NULL`. Clean, idle projects have `next_due_ms IS NULL` and are invisible to the index.

**How `next_due_ms` moves:**

| Signal | Where raised | What it sets |
|---|---|---|
| **Garbage-creating event** (`pack_gc::note_garbage(hub, project)`): branch delete (`sync.rs`, `branches.rs`), force-push (`sync.rs`), `change_refs` amend (`changes.rs`), PR close (`prs/mod.rs`), embargo release (`embargo.rs`), search segment replacement (`search/index.rs`), stale view-key sweep (`query/files.rs`), or a push/commit/batch in `objects` layout whose transaction aborted after `Objects::keep` wrote loose objects | Coalesced in memory per project on `hub.pack_gc` (flushed asynchronously at most once per `NOTE_FLUSH_INTERVAL = 10 s`, never adding a statement to any request transaction) | `dirty_since_ms = COALESCE(dirty_since_ms, now)`, `next_due_ms = LEAST(COALESCE(next_due_ms, due), due)` where `due = GREATEST(now + GC_QUIET_DELAY_MS, last_run_ms + GC_MIN_INTERVAL_MS)` |
| **Ordinary fast-forward push, API commit, landing batch, read, pull** | Nowhere | **Nothing.** Fast-forward commits leave every ancestor reachable and generate zero garbage; hot push/landing benchmarks execute 0 scheduler writes. |
| **After a pass (`run_project` with `run_gc: true`) finishes** | End of `run_with_lock` | 1. If the pass stopped at `max_loose_deletes_per_pass` or `max_packs_per_run` (more expired garbage ready now) → `next_due_ms = now + GC_SLICE_GAP_MS` (`5 s`).<br>2. Else if `roots_at_switch` gave way → `next_due_ms = now + GC_GIVE_WAY_BACKOFF_MS` (`30 s` + jitter).<br>3. Else query `SELECT MIN(since_ms) FROM unreferenced_objects WHERE project_id = $1`: if `Some(t)` → `next_due_ms = GREATEST(t + retention_window_ms + 1_000, now + GC_MIN_INTERVAL_MS)` (wakes up right after the marked objects' retention window expires, as `sweep_due` does for `DISCARDED` packs!).<br>4. Else → `dirty_since_ms = NULL, next_due_ms = NULL`, `last_run_ms = now`, `last_changes = C(P)`. |
| **24-hour crash-orphan backstop** | `gc_scan` every `GC_BACKSTOP_CHECK = 1 h` | Projects whose `C(P) > last_changes` and `now - last_run_ms >= GC_PERIODIC_MS` (`24 h`) get `next_due_ms = COALESCE(next_due_ms, now)`: catches loose objects written just before a `SIGKILL` in `objects` layout where in-memory `note_garbage` never flushed. |

**Proposed timing constants (`pack_gc.rs`):**
- `GC_SCAN_TICK = 30 s`: how often `gc_scan` polls `gc_schedule_due` (woken immediately when local `note_garbage` flushes a due time $\le$ 30 s away).
- `GC_QUIET_DELAY_MS = 60_000` (1 min): coalesces bursts of branch deletes or force-pushes before the marking pass runs.
- `GC_MIN_INTERVAL_MS = 300_000` (5 min): minimum gap between full mark walks on the same project (unless draining ready slices via `GC_SLICE_GAP_MS = 5_000`).
- `DEFAULT_RETENTION_WINDOW_MS = 3_600_000` (1 h, existing): how long an unreferenced object stays marked before any pass can delete it.

### 4.2 Bounds, throttling, many projects and multiple servers

- **Dedicated concurrency bulkhead (`GC_WORKERS = 2`):** Today `run_locked` acquires `hub.derive.permit()` directly from `DERIVE_WORKERS` (`8`). Scheduled GC across many projects must never starve landing-triggered `derive` runs: `hub.pack_gc` holds its own `Semaphore::new(GC_WORKERS)` (`2`), and acquires a `gc_permit` *before* acquiring a `derive` permit and a connection from `hub.derive.db`. At most 2 scheduled GC passes run concurrently per server, leaving at least 6 of 8 `DERIVE_WORKERS` exclusively for `derive`. Explicit admin/test calls to `pack_gc::run_project` bypass the `gc_scan` queue and only acquire `derive.permit()` + `LOCK_BASE ^ project`, as today.
- **One pass per project across all servers:** `run_locked` acquires `pg_try_advisory_lock(LOCK_BASE ^ project)` on a dedicated connection with **`lock_conn.close_on_drop()`** (fixing a gap on `integration` where dropping `run_locked`'s future mid-await returned `lock_conn` to `derive.db` before `pg_advisory_unlock`). In a multi-server deployment:
  - Each server's `gc_scan` selects `SELECT project_id FROM gc_schedule WHERE next_due_ms <= $1 ORDER BY next_due_ms LIMIT 32`, shuffles the batch (`fastrand`) so $M$ servers do not all try the same first project, and calls `run_project`.
  - If another server already holds `LOCK_BASE ^ project` (for a pack merge, sweep, or GC pass), `pg_try_advisory_lock` returns `false` immediately (`Report { skipped: true }`) and the project's `next_due_ms` remains untouched in `gc_schedule` until the lock-holder updates it on completion (or another scan picks it up if the holder crashed).
- **Many projects (e.g. 10,000 projects, 500 due at once):** Ordering by `next_due_ms ASC` serves the longest-overdue projects first (FIFO fairness). Because each scheduled pass caps its work (`DEFAULT_BG_LOOSE_DELETES = 4,096`, `BACKGROUND_PACKS_PER_RUN = 16`) and advances `next_due_ms` by `GC_SLICE_GAP_MS = 5 s` when slicing a huge backlog, one project with 500,000 dead objects cannot monopolize `GC_WORKERS`: other due projects interleave between its 4,096-object slices.
- **Both layouts (`packs` and `objects`):**
  - In `packs`: `maybe_schedule` continues to merge small packs (`MERGE_MIN_PACKS = 64`, `run_gc: false`) right after pushes; `gc_scan` runs `run_gc: true` when `gc_schedule` is due, compacting packs that hold expired dead objects (`select_batch`) and sweeping expired loose projections/trees/search segments.
  - In `objects`: pushes list no packs, so `maybe_schedule` only runs once if leftover pre-switch packs $\ge 64$ are loaded (`object-layout.md` §5.1). `gc_scan` is the sole collector of dead objects (`mark_and_sweep_loose`), plus `compact_batch` on any leftover pre-switch pack that holds an expired dead object.

### 4.3 Clean server stop (`Running::stop`, closing BUG-2635 and BUG-1990)

`Running::stop` (`crates/veil-server/src/lib.rs:184`) today stops the TLS listener, `landing::stop` (BUG-1970), and `search::index::stop` (BUG-1990), leaving four classes of background work running while the caller drops the Tokio runtime:
1. `derive::resume` (iterating projects at startup) and `derive::locked_landing` (`derive/mod.rs`), whose blocking threads call `Cx::db` (`Handle::block_on` + timer retry sleeps) and `upload_objects`;
2. viewer-graph fills (`query::graph::extend` / `spawn_fill`) and background blame jobs (`query::files`), also on blocking threads calling `Cx::db`;
3. `bisect::resume` (`bisect.rs`);
4. `pack_gc` tasks: `sweep_scan`, the new `gc_scan` + `note_garbage` flusher, and per-project tasks spawned by `maybe_schedule`, `schedule_sweep` and scheduled GC.

**Shutdown design:**
- **Shared stop flag checked by blocking `Cx`:** `Hub` carries `stopping: AtomicBool` alongside the `shutdown: watch::Sender<bool>` channel. `derive::Cx::db` and `Cx::tick` (used by `derive`, `query::graph` fills, and `query::files` blames) check `hub.is_stopping()` before every query and before every retry `tokio::time::sleep`, returning `Err(Error::stopping())` cleanly instead of touching a shutting-down timer wheel. `derive::resume` checks `hub.is_stopping()` before starting the next project.
- **Task tracking per subsystem (matching `search::index::stop`, `605cf7c1`):**
  - `derive::Workers` counts active runs from the moment `locked_landing` or `resume` registers them (`active: Mutex<(bool, usize)>` + `Notify`); `derive::stop(&hub)` sets `closed = true` and awaits `active == 0`.
  - `query::graph::State` counts active fills and blame jobs the same way; `query::stop(&hub)` awaits them and releases their `view_fills` / `blame_jobs` leases on exit so a surviving peer server does not wait for lease expiry.
  - `bisect::stop(&hub)` awaits any in-flight `bisect` task and releases `bisect_leases`.
  - `pack_gc::State` tracks `sweep_scan`, `gc_scan`, the `note_garbage` flusher (which flushes pending dirty project IDs once if the DB is reachable, best-effort with a 1 s bound, before exiting), and all per-project `active` / `sweeping` / `collecting` tasks. **Crucial rule for `delete_loose_chunk`:** `pack_gc` checks `hub.is_stopping()` *between* phases and *between* 256-object loose chunks, **never** between step 3b (storage deletes) and step 3c (the post-delete `epoch` raise) of an active chunk. An in-flight chunk finishes its $\le 256$ deletes and raises `epoch` under its session gate before returning, preserving Invariant D across restarts.
- **Ordered `Running::stop(self)` sequence:**
  1. `self.shutdown.send(true)` and `self.hub.stopping.store(true, SeqCst)`; await `self.task` (listener stops accepting; open HTTP requests finish, registering any landing/derive/search triggers before returning).
  2. `landing::stop(&self.hub).await` and `bisect::stop(&self.hub).await` (queue services finish their current commit, register any final `derive`/`search` kick, and release leases).
  3. `derive::stop(&self.hub).await`, `query::stop(&self.hub).await`, `search::index::stop(&self.hub).await` (every blocking thread exits before `stop()` returns).
  4. `pack_gc::stop(&self.hub).await`, plus awaiting `caches::listen`, `caches::send_notices`, and `embargo::run_loop`.

---

## 5. Schema changes

Two migrations are added (`0043` and `0044`), split so each migration's `ONLINE_INDEXES` section stays at $\le 11$ concurrent index builds and comfortably clears YugabyteDB's 10-minute startup migration deadline and `veil_settle_*` + `yb_index_check` verification (`db::online_index_steps`, BUG-2482, BUG-2570, BUG-2571, BUG-2625, BUG-2626).

### 5.1 YugabyteDB and rolling-upgrade constraints

1. **Idempotent transactional DDL (`startup::not_safe_to_run_again`, BUG-2570).** YugabyteDB does not roll back DDL when a transaction aborts mid-migration. Every statement in the transactional part uses `CREATE TABLE IF NOT EXISTS`, `CREATE INDEX IF NOT EXISTS` (only on tables created in the *same* migration, which have no concurrent writers yet), and `ALTER TABLE … ADD COLUMN IF NOT EXISTS`.
2. **Metadata-only column additions (`BUG-1211`).** `ADD COLUMN IF NOT EXISTS gc_gen BIGINT NOT NULL DEFAULT 0` and `write_gen BIGINT NOT NULL DEFAULT 1` rewrite no existing rows in PostgreSQL 11+ or YugabyteDB; historical rows read `gc_gen = 0`.
3. **Zero-backfill partial generation indexes (`WHERE gc_gen > 0`).** Because every pre-existing row has `gc_gen = 0`, while every post-migration guarded write stamps `gc_gen = write_gen >= 1`, partial online indexes `ON <table> (project_id, gc_gen) WHERE gc_gen > 0` index **zero historical rows** during a rolling upgrade! On an existing deployment with tens of millions of `projections` or `snapshots` rows, both the online backfill and `yb_index_check` finish in seconds instead of hitting BUG-2626's ~90 M-row / 10-minute startup limit. Every pass's mark snapshot reads all rows (`gc_gen >= 0`) once outside the gate and sets `covered_gen >= 1`, so every `collect_db_roots_since` query includes `AND gc_gen >= $2 AND gc_gen > 0` (`$2 >= 1`), matching the partial index under generic and custom plans alike (`packs_listed` pattern, migration 41).
4. **Online index section rules (`db::migration_parts`, `crates/veil-server/src/db.rs:410`).** Everything after `-- veil: online indexes` contains only full-line `--` comments and bare `CREATE INDEX CONCURRENTLY IF NOT EXISTS <name> ON …;` statements (no inline `--`, `/*` or `$`). On YugabyteDB, `db::online_index_steps` builds each index, waits for every session via `veil_settle_<hex>` on `schema_migrations`, and verifies completeness with `yb_index_check` (rebuilding up to 5 times on incomplete catalog propagation, BUG-2626).
5. **Rolling-upgrade mixed-version rule.** During a rolling upgrade from pre-0043 servers to post-0043 servers, old servers still running do not populate `gc_gen` (`DEFAULT 0`) or `gc_change_shards`. As in `object-layout.md` §2, **`gc_scan` (scheduled `run_gc: true`) is enabled once every server in the deployment runs the new build** (or a deployment upgrades servers before turning on scheduled collection; manual `run_gc` is not run mid-rollout while pre-0043 binaries are still writing).

### 5.2 Migration `0043_gc_generations.sql`

```sql
-- Change-sized GC cleanup and scheduled collection (BUG-2623, BUG-2628, BUG-2629).
-- Idempotent (IF NOT EXISTS): YugabyteDB applies DDL non-transactionally.

ALTER TABLE access_epochs ADD COLUMN IF NOT EXISTS write_gen BIGINT NOT NULL DEFAULT 1;

CREATE TABLE IF NOT EXISTS gc_change_shards (
    project_id BIGINT NOT NULL REFERENCES projects(id),
    shard      SMALLINT NOT NULL,
    changes    BIGINT NOT NULL,
    PRIMARY KEY (project_id, shard)
);

CREATE TABLE IF NOT EXISTS projection_trees (
    project_id   BIGINT NOT NULL REFERENCES projects(id),
    projected_id TEXT NOT NULL,
    root_tree    TEXT NOT NULL,
    gc_gen       BIGINT NOT NULL,
    PRIMARY KEY (project_id, projected_id)
);
CREATE INDEX IF NOT EXISTS projection_trees_by_gen ON projection_trees (project_id, gc_gen);
CREATE INDEX IF NOT EXISTS projection_trees_by_root ON projection_trees (project_id, root_tree);

CREATE TABLE IF NOT EXISTS gc_schedule (
    project_id     BIGINT PRIMARY KEY REFERENCES projects(id),
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

-- Bounded per-project tables (`branches`, `tested`, `pr_review_rules`,
-- `embargo_lines`, `embargo_snapshots`, `bisects`, `bisect_reverts`,
-- `search_shards`) already have `project_id` first in their primary keys and
-- hold at most a few hundred rows per project; only unbounded tables need
-- `(project_id, gc_gen)` indexes.
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
```

### 5.3 Migration `0044_gc_purge_indexes.sql`

Eliminates full-project sequential scans from `purge_expired_db_records` (where `OR` predicates and trailing `snapshot` / `real_id` / `changed` / `landed` columns previously scanned millions of rows per 500-ID chunk under `lock_gc_epoch_tx`). None of the derived tables below (`graph`, `file_history`, `rule_history`, `view_*`) is written on the push, API-commit, or landing-commit critical path; only `origins`, `projections` and `landed_changes` / `landed_from` receive 1 row per commit/projection.

```sql
-- Indexes for O(expired) deletes in `pack_gc::purge_expired_db_records`.
-- veil: online indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS origins_by_origin ON origins (project_id, origin_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS projections_by_real ON projections (project_id, real_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS graph_by_changed ON graph (project_id, changed) WHERE changed IS NOT NULL;
CREATE INDEX CONCURRENTLY IF NOT EXISTS landed_from_by_landed ON landed_from (project_id, landed);
CREATE INDEX CONCURRENTLY IF NOT EXISTS landed_changes_by_landed ON landed_changes (project_id, landed);
CREATE INDEX CONCURRENTLY IF NOT EXISTS file_history_by_snapshot ON file_history (project_id, snapshot);
CREATE INDEX CONCURRENTLY IF NOT EXISTS rule_history_by_snapshot ON rule_history (project_id, snapshot);
CREATE INDEX CONCURRENTLY IF NOT EXISTS view_graph_by_snapshot ON view_graph (project_id, snapshot);
CREATE INDEX CONCURRENTLY IF NOT EXISTS view_graph_by_real ON view_graph (project_id, real_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS view_changes_by_snapshot ON view_changes (project_id, snapshot);
CREATE INDEX CONCURRENTLY IF NOT EXISTS view_file_history_by_snapshot ON view_file_history (project_id, snapshot);
```

In `purge_expired_db_records`:
- Every `OR` delete (`origins`, `projections`, `projection_trees`, `landed_from`, `graph`, `view_graph`) is split into two single-predicate statements so PostgreSQL and YugabyteDB use direct index scans rather than `BitmapOr` or `SeqScan`.
- Skewed non-unique lookups (`DELETE FROM projections WHERE project_id = $1 AND projected_id = ANY($2)` and `DELETE FROM view_graph WHERE project_id = $1 AND real_id = ANY($2)`, where collapsed hidden runs map 200,000 rows to one ID, BUG-2467 / BUG-2510) execute with `.persistent(false)`.

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
| 1 | **BUG-2623 base race** (stale memo insert across pass) | Un-ignore `pack_gc::bug_2623_a_memo_whose_snapshot_gc_deleted_is_derived_again`, plus live-writer variants for all 4 previously unguarded memo paths (`sync::projected_inner`, `project_tips_together`, `Walk::flush`, `derive::finish_landing_run`): hold the writer after `put(P_cand)` via a row lock or hook while GC purges and deletes `P_cand` (`E_0 → E_c`), then release | The stale transaction fails `GcEpochChanged`, retries from `read_gc_epoch` (`E_c`), re-stores `P_cand`, commits `projections`, and member `history` + `q/log` answer `200` with complete frames |
| 2 | **BUG-2623 cycle 1** (new memo naming expired parent projection or expired tree) | Commit a memo `P_2` (whose parent `P_1` or tree `T_1` is in `expired_unreferenced`) inside `Options::before_switch` and inside `Options::before_loose_delete`, for both `Memo::Tips` and `Memo::Fill` | `roots_at_switch` reads `projections WHERE gc_gen >= covered_gen`, walks `P_2 → P_1 / T_1`, keeps `P_1` and `T_1` stored, and member `history` + `q/log` return both snapshots (`200`) |
| 3 | **BUG-2623 cycle 2a (i)** (chunk 1 advancing stamp or rolling back while memo names object in chunk 2) | Create $> 256$ expired loose objects (`LOOSE_DELETE_CHUNK = 256`, forcing 2 chunks). In `before_loose_delete`, commit a memo naming a candidate sorted into **chunk 2** (variant A: chunk 1 deletes 256 other objects; variant B: all 256 objects in chunk 1 were also rescued so chunk 1 hits `ids.is_empty()` and rolls back!) | Chunk 1's `roots_at_switch` walks the memo and removes chunk 2's target from `expired_unreferenced` (and on rollback `covered_gen`/`stamp` is not advanced prematurely); chunk 2 keeps the object; `history` answers `200` |
| 4 | **BUG-2623 cycle 2a (ii)** (loose-deleted candidate purged again by later pack switch in same pass) | Pass has both an expired loose projection `P_0` and a pack batch with dead objects (`compact_batch` runs after `mark_and_sweep_loose`). After `delete_loose_chunk` deletes `P_0`, hook before `compact_batch`'s switch triggers a fresh `tips` request that re-stores and commits `P_0` under the new epoch | `P_0` left `expired_unreferenced` when deleted loose; `compact_batch`'s switch does **not** purge the new `projections` row, and `P_0` stays stored and readable (`200`) |
| 5 | **BUG-2623 cycle 2a (iii)** (skewed `projected_id` delete plan, BUG-2467) | Collapsed hidden run of 2,000 real snapshots sharing one `projected_id`, after 6 single-row `purge_expired_db_records` runs on the same connection | Delete completes in bounded time using index scan via `.persistent(false)` |
| 6 | **BUG-2623 cycle 2b** (unguarded derived writers & post-pass cache poisoning) | Six subtests — `Walk::flush` (`view_graph`, `view_changes`, `view_file_history`, `hub.query.rows`), `Fill::flush` (`view_file_history`), `derive::Batch::flush_with_progress` (`graph`, `file_history`, `rule_history` with `objects.is_empty()`), `derive::finish_landing_run` (admin view & pre-existing memos), `Blamer::write` / `record_too_wide` (`blame_memo`, `blame_ends`), and `keep_cursor` (`log_cursors`): pause each job after reading expired `S_exp` at `E_0`, run GC to purge and delete `S_exp` (`E_1`), resume | Flush fails `GcEpochChanged`; **0 rows** naming `S_exp` exist in any derived table; `hub.query.rows` and `hub.derive.rows` return `None` for `S_exp` at `E_1`; `q/resolve` and `q/log` return `200` (or `400 invalid cursor` for the pre-GC `frontier-…` token), never `missing object` |
| 7 | **BUG-2628 (static & racing, `FsStore` and S3)** (`grant::grant_root` projected trees) | Live `P_1` (`ptree_1` unstored, in `Marks::unread`) shares projected subtree `psub_a` with expired `P_0` (stored loose, past window). Subtest A: issue `tips` grant before GC, run 2 passes → `psub_a` never deleted. Subtest B: run `GET …/tips` inside `before_switch`, inside `before_loose_delete`, and concurrently inside `during_loose_delete` (specifically testing `FsStore` where `try_exists(psub_a)` is `true` right before unlink!) | `GET …/tips` returns `200` with a signed `Grant`; `GET /v1/projects/…/objects/<ptree_1>` and `<psub_a>` under that `Grant` both return `200` with valid tree bytes after GC completes |
| 8 | **BUG-2629** (expired snapshot re-pushed and unbranched after loose purge, or before loose switch) | Expired loose `R_old` whose trees/blobs are already stored loose and in `expired_unreferenced`. In `before_loose_delete` (and in a second subtest, in `before_switch`), upload `R_old` alone, push to branch `temp`, then delete `temp` before the chunk/switch runs | `snapshots` row for `R_old` remains, `snapshots.gc_gen` was bumped, `catch_up_round_in` walked `R_old` unconditionally, and **every** tree and blob in `R_old`'s closure remains stored (`200` on checkout/read) |
| 9 | **BUG-2590 & give-way** | Update `bug_2590_a_root_written_during_a_pass_does_not_cost_the_pass` (`2c06b640`): 1 pass with 1 guarded `change_refs` write in `before_switch` collects in 1 switch; `bug_2602_a_switch_gives_way_past_its_bound_and_the_next_pass_collects` writes $> 256$ new objects in `before_switch` | First test collects in 1 pass / 1 switch; second gives way cleanly with `since_ms` preserved and collects on the immediate next pass |
| 10 | **BUG-2635 clean stop** | Start `TestHub` with `catch_up_at_start: true` while `derive::resume`, `locked_landing`, a `query::graph` fill, a blame job, and a multi-chunk `pack_gc` pass are actively executing; call `Running::stop().await` and drop the runtime immediately | Zero panics on stderr/join, zero leaked `LOCK_BASE`/`GATE_BASE` advisory locks, `view_fills`/`blame_jobs` leases released, and any chunk that started step 3b finished step 3c's second `epoch` raise before stopping |
| 11 | **BUG-2602 busy project** (both `packs` and `objects` layouts) | Pre-populate 10,000 `projections` and `graph` rows + 1,000 expired dead objects; drive sustained concurrent pushes, API commits, `tips` grants and viewer-graph fills (~100+ ops/s) while scheduled GC runs | 0 failed pushes/reads (`0` `missing object`, `0` `500`), first scheduled pass past the window collects dead objects (not 0 of 90), and `gc_schedule.next_due_ms` clears to `NULL` once clean |
| 12 | **Cost & query-plan gate** | Populate $N_1 = 500$ vs $N_2 = 50{,}000$ rows in `snapshots`, `projections`, `origins`, `graph`, `file_history`, `view_graph`, `view_file_history`; write $\Delta = 5$ guarded rows in `before_switch`; inspect `EXPLAIN (FORMAT JSON)` and row/statement counters | Zero `Seq Scan` nodes on any unbounded table on both PostgreSQL and YugabyteDB; `roots_at_switch` executes $\le 3$ SELECT statements and reads $\le 25$ DB rows at both $N_1 = 500$ and $N_2 = 50{,}000$ |
| 13 | **Schema & migration checks** | Extend `bug_1782_every_schema_column_is_registered_and_root_tables_are_stamped`; run `startup::not_safe_to_run_again`, `bug_2482`, `bug_2571`, `bug_2626` over migrations `0043` and `0044` | Every `GcRoot` and `GcAttachmentOrRetainedHistory` table has `gc_gen` and a `collect_db_roots_since` arm; replay and YugabyteDB `yb_index_check` pass |
---

## 7. Implementation plan

The implementation is self-contained on `integration` and **independent of the `object-layout` branch** (`docs/design/server/object-layout.md` §3.2): `mark_and_sweep_loose` and `compact_batch` already exist on `integration` and dispatch by pack presence vs loose store keys. Per `object-layout.md` §9, shipping this design (specifically scheduled loose collection + bounded gate cost) is the prerequisite before flipping the default new-project layout from `packs` to `objects`.

### 7.1 Ordered slices

Each slice compiles and passes `scripts/verify-fast.sh` on its own; slices 1–4 land before enabling `gc_scan` in slice 6 so no scheduled pass ever runs without full guard coverage and `O(Δ)` switches.

| Slice | Files touched | Est. lines | What lands |
|---|---|---|---|
| **1. Schema & registry** | `crates/veil-server/migrations/0043_gc_generations.sql`, `0044_gc_purge_indexes.sql`, `crates/veil-server/src/pack_gc.rs` (`OBJECT_SCHEMA_COLUMNS`, `NON_OBJECT_SCHEMA_COLUMNS`), `tests/server_hub/startup.rs`, `tests/server_hub/pack_gc.rs` (`bug_1782`) | ~95 SQL + ~80 Rust + ~120 test | Additive columns (`access_epochs.write_gen`, `gc_gen` on 18 tables, `log_cursors.gc_epoch`), new tables (`gc_change_shards`, `gc_schedule`, `projection_trees`), partial online `(project_id, gc_gen) WHERE gc_gen > 0` indexes, online purge indexes (`0044`), YugabyteDB replay + `yb_index_check` coverage |
| **2. Guard primitives & root/attachment writers** | `crates/veil-server/src/pack_gc.rs` (`guard_root_write` → `(i64, i64)`, `guard_derived_write`, `advance_write_gen`), `sync.rs`, `changes.rs`, `landing/service.rs`, `embargo.rs`, `imports.rs`, `packs.rs`, `search/index.rs`, `grant.rs` (`grant_root` + `projection_trees`), `derive/mod.rs`, `query/graph.rs` | ~380 Rust + ~450 test | Single-CTE `guard_root_write` bumping `gc_change_shards` and returning `(epoch, write_gen)`; all 19 root/attachment tables stamp `gc_gen`; `Packs::record_staged` guarded (`pending_uploads`); `grant_root` guarded via `sync::put_all` + `projection_trees` (closes **BUG-2628**); all 7 `projections` writers + `derive::Batch` guarded + retry-safe |
| **3. Pure derived writers & epoch-scoped caches** | `crates/veil-server/src/query/graph.rs` (`Walk::flush`, `Fill::flush`), `blame.rs` (`Blamer::write`, `record_too_wide`), `query/mod.rs` (`keep_cursor`, `resolve_cursor`), `derive/mod.rs` (`RowCache`), `sync.rs` (`ProjectCaches`) | ~170 Rust + ~280 test | `guard_derived_write` on `Fill::flush`, `Blamer::write`, `record_too_wide`, `keep_cursor`; `log_cursors.gc_epoch` validation; `hub.derive.rows`, `hub.query.rows`, `hub.caches`, and `hub.grants.stored` populated strictly with the guard-verified `gc_epoch` (closes **BUG-2623 cycle 2b**) |
| **4. `O(1)` stamp, `O(Δ)` switch, loose-candidate tracking & `O(E)` purge** | `crates/veil-server/src/pack_gc.rs` (`read_change_stamp`, `collect_db_roots_since`, `roots_at_switch`, `catch_up_round_in`, `loose_chunk_under_gate`, `purge_expired_db_records`), `tests/server_hub/pack_gc.rs`, `tests/server_hub/rv_core2.rs` | ~290 Rust + ~420 test | Fence `advance_write_gen` before initial root read; `read_change_stamp` over `gc_change_shards`; 2-query `collect_db_roots_since` (`0` catalog queries under gate); `Marks::unread` cleared by Δ `projection_trees` & `pending_uploads`; unconditional Δ `snapshots` walk + removing loose-deleted IDs from `expired_unreferenced` (closes **BUG-2623 cycle 1 / 2a** & **BUG-2629**); single-column indexed deletes with `.persistent(false)` on skewed columns; `bug_2590` assertion update |
| **5. Clean shutdown of background tasks (BUG-2635)** | `crates/veil-server/src/lib.rs` (`Hub`, `start`, `Running::stop`), `derive/mod.rs`, `query/graph.rs`, `blame.rs`, `pack_gc.rs` | ~140 Rust + ~130 test | `Hub::stopping: CancellationToken` + `TaskTracker` covering `derive::resume`, `locked_landing`, `query::graph` fills, `blame::ensure_blame`, and `pack_gc`; `Cx::is_stopping` exits between batches without panicking on Tokio shutdown; `delete_loose_chunk` finishes step 3c's second `epoch` raise if step 3b started |
| **6. Scheduled collection (`gc_scan`)** | `crates/veil-server/src/pack_gc.rs` (`gc_scan`, `note_gc_candidates`, `run_scheduled_gc`), `sync.rs`, `landing/service.rs`, `embargo.rs`, `imports.rs`, `lib.rs` | ~180 Rust + ~160 test | `gc_schedule` hints on ref delete / non-FF / rewrite / release / failed import; `gc_scan` worker pool (`GC_WORKERS = 2`, bounded `max_loose_deletes = 4,096` per pass) across both `packs` and `objects` layouts; busy-project end-to-end test (**BUG-2602**) |

**Totals:** ~95 lines SQL, ~1,240 lines server Rust across 13 files, ~1,560 lines integration tests across 3 test modules.

### 7.2 Verification & review tier

This change touches `pack_gc.rs`, `sync.rs`, `grant.rs`, `derive/mod.rs`, `db.rs` migrations, and `Running::stop` — **high-risk server persistence & concurrency code** under `CLAUDE.md`:
1. Full `scripts/verify-fast.sh` + `scripts/verify-server.sh` on both **PostgreSQL** and **YugabyteDB** (including `startup::`, `pack_gc::`, `rv_core2::`, `warm::`, `grants::`, `embargo::`, and `leaks::`).
2. Benchmark gate (`scripts/bench-server.sh quiet` and `load`) comparing push throughput (1 project and 100 projects), API commit latency, and `q/log` / `tips` latency against `integration` to confirm the zero-extra-round-trip CTE in `guard_root_write` stays within noise ($\le 2\%$).
3. Independent adversarial code review checking every table in `OBJECT_SCHEMA_COLUMNS` and every `hub.*` in-memory cache against Invariants A–D before merge.

---

## 8. Alternatives considered

### 8.1 Whole-table `STAMP_TABLES` + chunk-scoped memo cleanup (`t3/fable-open-bugs` @ `914484bd`)
Tried in cycle 2 of BUG-2623: adding `origins`, `projections`, and `graph` to `read_reference_stamp`'s `bit_xor(hashtext(…))` and `collect_db_roots`, plus deleting chunk-local memos when the stamp moved. Rejected for the three reasons Cycle 2 established:
1. Full-table `SeqScan`s of百万-row `projections` / `graph` tables under `pg_advisory_xact_lock(gate_key)` hold every push and API commit for 0.5–1.5 s on PostgreSQL and **5–10 s on YugabyteDB** at every switch and every 256-object loose chunk, re-introducing BUG-2602 starvation.
2. Advancing the pass-wide stamp inside chunk 1 while only purging memos naming chunk 1's 256 objects lets chunk 2 delete an object named by a memo committed before chunk 1 (and rolling back an empty chunk left the in-memory stamp advanced).
3. Leaving `Walk::flush`, `Fill::flush`, object-less `derive::Batch`, `grant_root`, and `blame` outside the guard left derived tables and caches poisonable across the pass.

### 8.2 Lookup-time repair ("treat a `projections` row whose snapshot is missing as no memo and re-derive")
Suggested in BUG-2623's initial note as a narrow alternative for `projections`. Insufficient as the primary fix for four reasons:
1. **Does not close Cycle 1 (dangling interior pointers):** if `P_2` exists in storage and names deleted parent `P_1` or deleted tree `T_1`, looking up `P_2` finds `P_2`'s own snapshot bytes intact; the failure (`missing object`) happens later when `history`, `fetch`, or `q/file` walks `P_2`'s parent chain or tree.
2. **Does not close BUG-2628:** a `Grant` is signed and returned to the client; when the client fetches `/v1/projects/…/objects/<psub_a>` directly from storage or `/objects`, there is no projection lookup on that path to re-derive `psub_a`.
3. **Does not cover `graph.changed` (`derive`):** `graph` rows store `changed` object IDs (`Many(ObjectId)`), and `view_graph` / `file_history` / `blame_memo` trust `graph` without re-reading every historical real snapshot.
4. **Masks genuine storage corruption:** silently re-deriving whenever a memo's object returns `NotFound` would hide real object-store data loss on `projections` / `graph` behind slow silent recomputation instead of surfacing an invariant violation.

### 8.3 Database triggers to maintain `gc_gen` and `gc_change_shards`
A `BEFORE INSERT OR UPDATE` PL/pgSQL trigger on each of the 19 tables could read `write_gen` and bump `gc_change_shards` automatically. Rejected because row-level triggers fire **per inserted row** (e.g., 400 rows in `derive::Batch` or `Walk::flush` = 400 trigger invocations and shard updates), whereas `guard_root_write` runs **once per transaction** inside the lock-acquisition CTE with zero extra SQL round-trips, and Rust compile-time visibility (`guard_root_write` returning `(epoch, write_gen)`) makes forgetting the guard at a call site obvious in review.

### 8.4 Single per-project counter row instead of 32 `gc_change_shards`
Updating `access_epochs.changes = changes + 1` on `(project_id, -1)` directly inside `guard_root_write` would upgrade `SELECT … FOR SHARE` to `FOR NO KEY UPDATE` on that single row, serializing every concurrent push, API commit, landing, grant, and memo write on a busy project behind each other's transaction commits (collapsing 100+ concurrent writers to 1 at a time on YugabyteDB). `SELECT … FOR SHARE` on `(project_id, -1)` + `ON CONFLICT DO UPDATE` on `shard = random() % 32` keeps `(project_id, -1)` shared while spreading counter row locks across 32 keys.

### 8.5 Eagerly storing all rewritten projected trees in `project_one` (for BUG-2628)
Having `project_one` upload `pr.created` trees whenever any `projections` row is computed would eliminate `Marks::unread` for projected trees, at a prohibitive write amplification cost: `derive::finish_landing_run` projects every landed commit across up to 64 distinct active `view_key`s (`derive/mod.rs:369`), most of whose intermediate commits no client ever checks out via a `Grant`. Keeping lazy tree materialization in `grant_root` and recording only granted tips in `projection_trees` preserves lazy tree storage while giving GC an exact, 1-row-per-granted-tip root record.

### 8.6 Recomputing `(path_key, depth)` at purge time vs `0044` purge indexes on `file_history` and `view_file_history`
`file_history` (`PRIMARY KEY (project_id, path_key, depth, snapshot)`) and `view_file_history` (`PRIMARY KEY (project_id, view_key, path_key, depth, snapshot)`) are the two largest derived tables by row count (one row per changed file × ancestor directory depth per commit). Adding `(project_id, snapshot)` indexes in `0044` makes `purge_expired_db_records` uniform (`DELETE … WHERE project_id = $1 AND snapshot = ANY($2)` in `O(E)`), at the cost of +1 secondary index entry per row written by background `derive` and `Walk::flush` (zero cost on push or landing). The alternative is omitting those two indexes from `0044` and, during `purge_expired_db_records` (which runs *before* objects are deleted!), reading the expired snapshot's `graph.changed` path list (falling back to diffing the snapshot's tree against its parents when `changed` is `'many'` or absent) to compute exact `(path_key, depth)` keys and delete via the primary key. Kept as Open Question 1 below.

### 8.7 Prefix-sharded loose GC (`p/<project>/ab/`, `object-layout.md` §7)
Scanning and sweeping 1/256th of the loose keyspace per pass reduces S3 `LIST` calls and `all_stored` RAM on $10^8$-object repositories, but still requires every piece of this design (`O(1)` stamp, `O(Δ)` switch, guarded memo/tree/derived writers, and `gc_schedule`) because any shard sweep still walks roots and purges DB records under the gate. Prefix-sharded loose sweeping remains a clean, orthogonal follow-up once repositories approach $10^7$–$10^8$ loose objects.

---

## 9. Open questions for the owner

1. **Secondary purge indexes on `file_history` and `view_file_history` (`0044_gc_purge_indexes.sql`):**
   - **Option A (recommended in §5.3):** Create online `(project_id, snapshot)` indexes on both tables. Push and landing latency are untouched (both tables are written exclusively by background `derive` and `Walk::flush` / `Fill::flush`), and `purge_expired_db_records` stays a simple, uniform `O(E)` indexed delete. Storage/background-write cost is ~48 bytes + 1 index insert per `(commit, changed path, ancestor directory)`.
   - **Option B:** Omit those two indexes from `0044` (keeping the other 10 much smaller indexes on `projections`, `origins`, `graph`, `landed_changes`, `rule_history`, `view_graph`, and `view_changes`), and delete `file_history` / `view_file_history` via their primary keys by reading each expired snapshot's changed paths before deleting its objects. Slightly more code in `purge_expired_db_records` (~70 lines, plus a fallback scan only if an object was already missing), zero index overhead on the two tallest history tables.

2. **Default scheduling intervals and slice budget (§4.1–§4.2):**
   - Proposed defaults: `GC_QUIET_DELAY_MS = 60 s` after a root-dropping event, `GC_MIN_INTERVAL_MS = 5 min` between passes on the same project, `DEFAULT_RETENTION_WINDOW_MS = 1 h`, `GC_PERIODIC_MS = 24 h` safety sweep for unreferenced uploads/abandoned staging, `DEFAULT_BG_LOOSE_DELETES = 4,096` (16 chunks of 256 per pass before re-arming), and `GC_WORKERS = 2` background passes per server. Should any of these constants be tuned differently or exposed as server CLI / env flags?

3. **Rolling-upgrade activation of `gc_scan`:**
   - During a zero-downtime rolling upgrade from a pre-`0043` binary to this binary, an old node still running concurrently writes `gc_gen = 0` without bumping `gc_change_shards`. Should `gc_scan` be gated behind `--scheduled-gc` / `VEIL_SCHEDULED_GC` (defaulting to `false` for the migration release and flipped to `true` once all nodes run the new binary, or defaulting to `true` if deployments always complete rolling restarts well inside the 1-hour retention window before any new candidate expires)?

4. **Batched S3 `DeleteObjects` (`POST /?delete`) in `delete_loose_chunk`:**
   - `delete_loose_chunk` currently issues up to 256 concurrent `DELETE` requests in 4–8 batches (`LOOSE_DELETE_CONCURRENCY = 64`, ~20–60 ms under the gate on S3/MinIO). S3's `POST /?delete` deletes all 256 keys in **1 HTTP round-trip** (~10–20 ms), cutting the gate hold during loose deletes by ~3× (`object-layout.md` §7). Include in Slice 4 now, or keep separate so Slice 4 touches no `store.rs` S3 wire code?
