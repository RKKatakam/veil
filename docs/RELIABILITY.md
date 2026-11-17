# Veil Diff-Triggered Reliability Checklist

Modelled on the Claude Code team's practice: each item below pairs a **diff-readable trigger** with a **concrete yes/no check** and the **incidents (`docs/BUGS.md` rows or `CLAUDE.md` invariants)** that paid for it. Reviewers do not read all 36 items on every branch—`scripts/reliability-triggers.sh <range>` scans changed paths and added code lines, printing only the items whose trigger matches (typically 3–10 on a substantive stream, 1–2 on a narrow fix).

```bash
bash scripts/reliability-triggers.sh integration...HEAD
bash scripts/reliability-triggers.sh --self-test
```

Every item matched by `scripts/reliability-triggers.sh` must be answered **yes** (safe, with `file:line` evidence) or **no** (a finding) in `.claude/skills/veil-review/SKILL.md`.

---

## Area 1 — Core Invariants & Confidentiality

### R-01 — No Git interop, offline mode, or file/SFTP remotes
- **Trigger:** Added lines in `crates/{veil-core,vl,veil-server}/src/**/*.rs` matching `.git/`, `git2`, `gix`, `git_interop`, `ssh2`, `PathRemote`, `RemoteUrl::Path`, `file://`, or `sftp://`, or any edit to `crates/vl/src/test_remotes.rs`.
- **Check:** Does the change keep Veil strictly server-centric—proposing zero Git import/export/bridges, zero offline sync paths, and keeping path remotes confined to debug-only test fixtures (`test_remotes.rs`)?
- **Sources:**
  - `CLAUDE.md` ("What not to propose", "Core constraints"): Veil is server-centric and never interoperates with Git; path and SFTP remotes were removed in simplification part 1.
  - `BUG-072`: `vl upgrade --remote` passed `sftp://` URLs to `Path::new` instead of rejecting non-server remotes cleanly.

### R-02 — Only secret files encrypted; accepted-policy pin and personal-key refusal
- **Trigger:** Added lines in `crates/{veil-core,vl,veil-server}/src/**/*.rs` matching `effective_policy`, `accepted_policy`, `.veilpolicy`, `personal_key`, `identity.json`, `device_vouches`, `SealedObject`, `RingKey`, `web_secrets`, or `team_secret`.
- **Check:** Are only secret files encrypted (never ordinary code, paths, descriptions, tags, embargoes, or attribution), does every client command read `repo.effective_policy()` (the accepted pin) rather than raw working-copy `.veilpolicy` while refusing `personal_key` rules, do key-wrapping paths require an active device vouch, and does no surface ever accept a pasted `identity.json`?
- **Sources:**
  - `CLAUDE.md` ("Core constraints"): Visibility is enforced by the server; only secret files are encrypted; client policy uses the accepted-policy pin.
  - `BUG-827`: Key-ring wrapping accepted unvouched device keys instead of requiring a valid vouch chain.
  - `BUG-1800`: `vl change new` parsed raw unaccepted working-copy `.veilpolicy` and forgot to reject `personal_key` rules.
  - `BUG-1871`: A web secret view prompted users to paste `identity.json`, violating the device-bound private-key boundary.

### R-03 — Refusals, logs, and conflict reports omit hidden paths and content
- **Trigger:** Added lines in `crates/{veil-core,vl,veil-server}/src/{landing/*,prs/*,sync,error,conflict,merge,repo}.rs` matching `AccessDenied`, `ConflictReport`, `conflict_paths`, `conflicting_files`, `tracing::{info,warn,error}!`, or `eprintln!(`.
- **Check:** Are all error responses, conflict reports, and server/CLI log lines redacted so a caller without read access to a folder or outside an agent's narrowing never learns hidden file paths, line contents, or post-revocation edits?
- **Sources:**
  - `CLAUDE.md` ("Core constraints"): Private, secret, isolated, and embargoed paths/content must never leak via errors, logs, or JSON.
  - `BUG-1104`: Landing conflict responses exposed edits made to a restricted `billing/` folder after the caller lost access.
  - `BUG-1111`: Landing a stack named conflicting paths from another author's change in a folder hidden from the submitter.
  - `BUG-1392`: Refusals returned to a narrowed (`--only`) agent session named paths outside the session's narrowing.

### R-04 — Upload receipts on all referenced IDs and keyed/filtered scope hashes
- **Trigger:** Added lines in `crates/veil-server/src/{sync,grant,shares,perm,api}.rs` matching `upload_receipt`, `uploaded_ids`, `receipt`, `grant_token`, `rule-`, `secret_shares`, `blake3::keyed_hash`, or `/rings`.
- **Check:** Does every push/submit verify an upload receipt (or caller visibility) for every referenced blob/tree/conflict-term/fallback ID so callers cannot probe whether an `ObjectId` already exists on the server, and are scope/grant identifiers keyed or filtered to the caller's readable paths?
- **Sources:**
  - `BUG-824`: Pushing a tree referencing an unuploaded `ObjectId` acted as an existence oracle for hidden blobs.
  - `BUG-834`: Conflict terms and merge fallbacks bypassed the upload-receipt check that regular tree entries enforced.
  - `BUG-1080`: Unkeyed grant-view identifiers let callers brute-force restricted folder names offline.
  - `BUG-1853`: `GET /v1/projects/{p}/rings` returned unkeyed `rule-<hash>` scope names for folders the caller could not read.

### R-05 — Sealing and visibility derived from objects and lineage, never labels alone
- **Trigger:** Added lines in `crates/{veil-core,vl}/src/{repo,builder,merge,checkout,tree,secrets,render,history,confinement}.rs` matching `verify_sealing`, `verified_visibility`, `reconcile_sealing`, `diff_trees`, `diff_trees_hiding`, `EntryVisibility`, or `Visibility::Public`.
- **Check:** Is visibility/sealing verified from the stored object (`verified_visibility` / `verify_sealing`) and embargo lineage rather than trusting a tree entry's label, and does `reconcile_sealing` use `diff_trees_hiding` on refused/cloaked subtrees so sealed secrets are never downgraded or dropped?
- **Sources:**
  - `CLAUDE.md` ("Core constraints"): Never trust an entry label as authority where the object and policy pin govern sealing.
  - `BUG-005`: Auto-rebasing a 3-way merge downgraded a sealed secret file to `Public` by copying an unverified label.
  - `BUG-832`: Partial/sparse operations without root `.veilpolicy` materialised dropped sealed status on secret blobs.
  - `BUG-944` / `BUG-992`: JSON `vl ls`, `vl diff`, and `vl show` reported embargoed files as `"public"` by reading the tree entry label alone.
  - `BUG-1897`: `reconcile_sealing` called `diff_trees` instead of `diff_trees_hiding`, failing when a refused sibling folder's tree was absent locally.

### R-06 — Client embargo withholding keyed on `ChangeId` and rewrite descent
- **Trigger:** Added lines in `crates/{veil-core,vl}/src/{embargo,remote,blame,commands,repo,rewrite_cmd}.rs` matching `embargo`, `withheld`, `EmbargoRecord`, `embargoed_changes`, `--public`, or `is_embargoed`.
- **Check:** Does embargo withholding track `ChangeId` and rewrite/replacement ancestry (rather than snapshot `ObjectId`s) across squash, abandon, squash-into-fix, `undo --op`, and `blame --public`, so no rewrite path pushes or displays an unreleased fix?
- **Sources:**
  - `BUG-003`: Pushing an embargoed merge uploaded its plaintext fix parent to the public branch.
  - `BUG-942` / `BUG-943`: Squashing or abandoning an embargoed change allowed descendants carrying the fix bytes to push publicly.
  - `BUG-991`: `vl blame --public` rendered lines from an unreleased embargoed change.
  - `BUG-1015` / `BUG-1016` / `BUG-1040`: Squash-into-fix, `undo --op` to an earlier version, and squash-into-child changed snapshot IDs and bypassed snapshot-keyed embargo checks.

---

## Area 2 — Permissions, Agent Sessions & Server Embargoes

### R-07 — Full tip-to-tip write checks and default-tip comparison on access files
- **Trigger:** Added lines in `crates/veil-server/src/{sync,branches,changes,perm,landing/*,prs/*}.rs` matching `check_write`, `can_write`, `writable`, `writes_anything`, `.veilrules`, `.veilpolicy`, `rules.protected`, `protected_branch`, `default_tip`, or `check_access_files`.
- **Check:** Are write permissions checked across every path differing between the target branch's old tip and new tip (including zero-upload pushes and merges with older parents), and are `.veilrules`/`.veilpolicy` changes compared against the default branch's current tip?
- **Sources:**
  - `BUG-820`: Pushing a merge whose second parent held an older tree reverted files in folders where the pusher had read-only access.
  - `BUG-1102`: A merge commit kept an older `.veilrules` from a side branch, silently unprotecting `main` without admin rights.
  - `BUG-1858`: Zero-upload pushes moving a branch to an already-stored snapshot skipped the path write-permission check.
  - `BUG-1920`: Merging an unlanded side branch directly onto `main` checked only the merge's second-parent delta instead of the full diff against `main`.

### R-08 — Route permissions and CI check footprints scoped to caller access
- **Trigger:** Added lines in `crates/veil-server/src/{api,ci,perm,auth,query/*,search/*}.rs` matching `Router::new`, `.route(`, `readable_footprint`, `require_read`, `require_write`, or `CheckReport`.
- **Check:** Does every new or modified HTTP route enforce the viewer's project/folder read and write permissions, do CI check logs enforce `readable_footprint` against the viewer, and are non-writers barred from posting failing checks that drive automatic bisect/revert?
- **Sources:**
  - `BUG-821`: Creating a group after an access rule already named it left folder access bound to a matching username.
  - `BUG-1850`: CI check results exposed logs whose `readable_footprint` included private or admin-only folders to public viewers.
  - `BUG-1852` / `BUG-1860`: Read-only callers could submit failing CI check reports on `main` and trigger automated bisect reverts.

### R-09 — Narrowed agent sessions isolated on access files, `change_refs`, and `/health`
- **Trigger:** Added lines in `crates/veil-server/src/{auth,perm,sync,branches,changes,api,limits/health}.rs` matching `viewer.only`, `agent_sessions`, `AgentTip`, `agent_may_*`, `only_paths`, `change_refs`, or `narrowed`.
- **Check:** When `viewer.only` is `Some(_)`, does the server forbid editing `.veilpolicy`/`.veilrules` even if the owning person is an admin, block overwriting `change_refs` whose existing snapshot touches paths outside `only`, and refuse whole-project endpoints like `/health`?
- **Sources:**
  - `BUG-1377` / `BUG-1391`: An admin's narrowed agent session was allowed to modify `.veilpolicy` and `.veilrules` to widen access.
  - `BUG-1784`: A `--only` agent session overwrote the person's `change_id` ref pointing at a change with files outside the session's narrowing.
  - `BUG-1995`: An admin's narrowed agent session (`viewer.only.is_some()`) was served whole-project counts on `/v1/projects/{p}/health`.

### R-10 — Per-person rate/memory accounting, `merging`-aware queue cap, and counting check slots
- **Trigger:** Added lines in `crates/veil-server/src/{limits/*,ci,landing/service}.rs` matching `Key::Person`, `admit_queue`, `MAX_CHECKS`, `counts_for_gate`, `body::acquire`, `answers::prepay`, or `rate_limit`.
- **Check:** Are request rate limits, body/answer memory shares, and landing queue caps keyed by `Key::Person` (never per agent token), does `admit_queue` count `merging` rows alongside `queued`, and are non-counting checks isolated from the per-snapshot counting check cap?
- **Sources:**
  - `BUG-1667`: `admit_queue` counted only `queued` rows and ignored `merging` rows, letting callers exceed the per-project queue bound.
  - `BUG-1882`: Five agent sessions belonging to one person each received a separate share, consuming 100% of the server's body/answer memory pool.
  - `BUG-1925`: Informational (non-counting) CI checks consumed a snapshot's 64 check slots and blocked required gate checks from recording.

### R-11 — Server embargo filtering, stored `group_names`, review gates, and isolated `release_due`
- **Trigger:** Added lines in `crates/veil-server/src/{embargo,prs/embargo,derive/*,search/*,query/*,ci,limits/health}.rs` matching `hidden_for_embargo`, `embargo_ancestry`, `release_due`, `group_names`, or `embargo_id`.
- **Check:** Do all query/derive/search/CI/health reads filter `hidden_for_embargo IS NULL` (unless authorised via stored `group_names`), do API commits on embargo lines record `embargo_ancestry`, does embargo release enforce protected-branch review gates without deleting lines when a PR closes, and does `release_due` isolate failures per project?
- **Sources:**
  - `BUG-1666` / `BUG-1783`: Search shards, derived views, `/health`, and CI queries returned commits where `hidden_for_embargo` was non-null.
  - `BUG-1851`: Pushing with a caller-supplied embargo group released an embargo without checking the server's stored `group_names`.
  - `BUG-1855`: Server API commits built on an embargo tip omitted `embargo_ancestry` rows and became visible before release.
  - `BUG-1857`: One conflicted due embargo aborted `release_due` early and starved automatic embargo releases on every other project.
  - `BUG-1861` / `BUG-1875`: Embargo release bypassed protected-branch review rules, and closing an embargo PR deleted the unreleased embargo line.

---

## Area 3 — Database, Migrations & YugabyteDB

### R-12 — Online index DDL outside transactions with `indislive`/`indisready`/`indisvalid` check
- **Trigger:** Added lines in `crates/veil-server/{migrations/*.sql,src/{db,main}.rs,tests/server_hub/startup.rs}` matching `CREATE [UNIQUE] INDEX`, `DROP INDEX`, `veil: online indexes`, `pg_index`, or `indis(live|ready|valid)`.
- **Check:** Is every index on an existing table placed after `-- veil: online indexes` using `CREATE [UNIQUE] INDEX CONCURRENTLY IF NOT EXISTS` (outside the migration's transaction), does the runner verify `indislive AND indisready AND indisvalid` (dropping and rebuilding incomplete indexes), and do timeout errors print recovery DDL?
- **Sources:**
  - `BUG-838`: Uncoordinated DDL on startup caused `40001` catalog serialization failures when multiple servers booted together.
  - `BUG-2482`: In-transaction `CREATE INDEX` on populated tables blocked writes on PostgreSQL and risked missing concurrent writes on YugabyteDB.
  - `BUG-2520`: Online index timeouts failed without reporting the exact `CREATE INDEX CONCURRENTLY` recovery statement to the operator.
  - `BUG-2571`: YugabyteDB online index builds returned `Ok` while leaving the catalog row with `indisvalid = false` or `indisready = false`.

### R-13 — Migration DDL/DML idempotent on re-run after YugabyteDB partial failure
- **Trigger:** Added lines in `crates/veil-server/{migrations/*.sql,src/db.rs,tests/server_hub/startup.rs}` matching `CREATE TABLE`, `ALTER TABLE`, `DROP TABLE|COLUMN|CONSTRAINT`, `ADD COLUMN|CONSTRAINT`, `not_safe_to_run_again`, or DML (`INSERT INTO`, `UPDATE … SET`, `DELETE FROM`) in `migrations/*.sql`.
- **Check:** Because YugabyteDB commits DDL inside a `BEGIN … COMMIT` block statement-by-statement and `ROLLBACK` does not undo earlier DDL, is every statement in the transactional part of the migration safe to run a second time (`IF NOT EXISTS`, `IF EXISTS`, `ON CONFLICT DO NOTHING`) if a later statement times out or fails?
- **Sources:**
  - `BUG-2521`: A migration timing out halfway through on YugabyteDB left earlier schema changes applied and failed permanently on retry.
  - `BUG-2532`: `ROLLBACK` after a failed statement in a migration block did not roll back preceding `ALTER TABLE` / `CREATE TABLE` statements on YugabyteDB.
  - `BUG-2570`: Startup needed a structural `not_safe_to_run_again` audit verifying every transactional migration statement is re-runnable.

### R-14 — Skewed-column queries use `.persistent(false)` and bounded indexed `ORDER BY`
- **Trigger:** Added lines in `crates/veil-server/src/**/*.rs` matching `.persistent(false)`, `FROM (projections|view_commits|view_fills|branch_changes)`, `WHERE … projected_id`, or `ORDER BY … (projected_at|seq)`.
- **Check:** Do queries filtering skewed columns (such as `projections.projected_id`, where one snapshot may have 1 row or 100k rows) call `.persistent(false)` so PostgreSQL/YugabyteDB never switches after 5 executions to a table-scanning generic plan, and does every `ORDER BY` on a large table have both a `LIMIT` and a matching composite index?
- **Sources:**
  - `BUG-1468`: Hidden-run graph queries scanned unbounded candidate rows before applying visibility limits.
  - `BUG-2467` / `BUG-2481`: After 5 prepared executions, PostgreSQL cached a generic plan for `WHERE project_id = $1 AND projected_id = $2` and sequentially scanned 1.5M `projections` rows.
  - `BUG-2510`: `resolve_stored` sorted 200k `projections` rows on disk because it lacked `LIMIT` and the `(project_id, snapshot_id, projected_at DESC)` index.

### R-15 — Review-gate ordering, YB `review_writers`, lock hierarchy, and `READ COMMITTED` check
- **Trigger:** Added lines in `crates/veil-server/src/{prs/*,landing/*,perm,sync,branches,db}.rs` matching `pg_advisory_xact_lock`, `review_writers`, `review_gate`, `FOR [NO KEY] UPDATE|SHARE`, or `default_transaction_isolation`.
- **Check:** Are mutations to approvals, `.veilrules`, holds, and group memberships ordered against landing batches via both `review_writers` (for YugabyteDB) and negative writer advisory keys (`-project_id`), do parent-row locks follow a fixed table order using `FOR NO KEY UPDATE` without holding connections across awaits, and does startup reject YugabyteDB clusters where `READ COMMITTED` maps to repeatable read?
- **Sources:**
  - `BUG-1880` / `BUG-1886` / `BUG-2061` / `BUG-2111`: Approval revocations, rule edits, holds, and group removals raced in-flight landing batches.
  - `BUG-2110`: PostgreSQL advisory locks are local/no-op on YugabyteDB, requiring the `review_writers` table so batches step aside for writers.
  - `BUG-2130` / `BUG-2131` / `BUG-2132` / `BUG-2133`: Lock-order inversion on `projects` deadlocked, awaiting inside locks exhausted the DB pool, dropped futures leaked `review_writers` rows, and XOR advisory lock keys collided with positive IDs.
  - `BUG-2135`: YugabyteDB without `yb_enable_read_committed_isolation=true` ran `READ COMMITTED` as repeatable read and broke landing visibility assumptions.

### R-16 — Single DB commit per push, post-commit `pg_notify`, and retryable `sqlx::Error` unwrap
- **Trigger:** Added lines in `crates/veil-server/src/{sync,caches,events,db,derive/*,search/*,landing/*}.rs` matching `pg_notify`, `tips_moved`, `.commit().await`, `is_retryable`, `40001`, `40P01`, or `downcast_ref::<sqlx::Error>`.
- **Check:** Does a push execute at most one DB transaction commit (batching memos/fills rather than committing per tip), are `pg_notify` / `Caches::tips_moved` notices sent *after* `.commit().await` (never inside the write transaction), and does retry classification walk the full `anyhow::Error::chain()` to unwrap `40001`/`40P01`?
- **Sources:**
  - `BUG-890` / `BUG-2340`: `sqlx::Error` wrapped inside `anyhow::Error` missed `40001`/`40P01` retry detection and returned `500` under contention.
  - `BUG-2350` / `BUG-2390`: Per-tip projection memos and fill commits multiplied DB commits per push and broke the push throughput gate.
  - `BUG-2459`: Calling `pg_notify` inside the push transaction serialized commits across all projects on PostgreSQL's notification queue lock.

### R-17 — Database and S3 TLS configuration fails closed on unknown flags or HTTP
- **Trigger:** Added lines in `crates/veil-server/src/{db,tls,store,main}.rs` matching `sslmode`, `sslrootcert`, `PgConnectOptions`, `https_only`, `allow_http`, `database_url`, `VEIL_S3_CA`, or `verify-(ca|full)`, or any edit to `vendor/sqlx-core/src/net/tls/*.rs`.
- **Check:** Does connection-string parsing reject unknown or unsupported TLS query parameters (such as `ssl=true` or misspelt `sslmode`) instead of silently falling back to plaintext, verify server certificates under rustls (`verify-ca`/`verify-full`), and refuse plain `http://` S3 endpoints unless explicitly enabled for local test fixtures?
- **Sources:**
  - `BUG-1590` / `BUG-1928`: Unknown TLS query parameters (`?ssl=true` or typos) in `--database-url` were ignored by URL parsing, connecting without TLS.
  - `BUG-1909`: `sslmode=verify-ca` failed against YugabyteDB/PostgreSQL certificates under rustls 0.23 until `sqlx-core` certificate verification was fixed and tested.

---

## Area 4 — Object Store, Packs & Garbage Collection

### R-18 — GC root-writer gate (`guard_root_write`), `STAMP_TABLES` coverage, and gated S3 deletes
- **Trigger:** Added lines in `crates/veil-server/{migrations/*.sql,src/{pack_gc,sync,bisect,changes,search/*,embargo,prs/*,landing/*}.rs}` matching `guard_root_write`, `STAMP_TABLES`, `mark_and_sweep`, `gc_epoch`, `store.delete(`, `delete_object`, `LOOSE_DELETE_CHUNK`, `roots_at_switch`, `collect_roots`, or `GcEpochChanged`.
- **Check:** Does every transaction that writes an `ObjectId` reference into any DB table call `guard_root_write` and include that table in `collect_roots` + `STAMP_TABLES`, does push lock its staged upload pack `FOR UPDATE`, and does `pack_gc` delete S3 objects only in gated chunks that re-read roots and advance `gc_epoch` (never outside the gate after commit)?
- **Sources:**
  - `BUG-1782` / `BUG-1923`: `bisects` and `search_shards` stored snapshot/blob references without being registered in GC root collection and `STAMP_TABLES`.
  - `BUG-1881`: Root-writing endpoints wrote branch/PR pointers without `guard_root_write` while a GC switch purged unreferenced objects.
  - `BUG-2310`: An in-flight push re-listed a staged upload pack that concurrent GC had already swept.
  - `BUG-2621`: `pack_gc::mark_and_sweep_loose` deleted loose blobs from S3 *after* its switch transaction committed with no lock held, deleting blobs newly uploaded by concurrent API commits.

### R-19 — Entry/tag target `ObjectKind` verified, safe entry names, and separate leaf/tree GC marks
- **Trigger:** Added lines in `crates/{veil-core/src/{tree,tag_object,fsck,gc,object}.rs,veil-server/src/{sync,pack_gc,changes}.rs}` matching `EntryKind`, `ObjectKind`, `TreeEntry`, `walk_from_roots`, `validate_entry_name`, or `TagObject`.
- **Check:** Does ingestion (`sync::check_changes`, `Tree`, `TagObject`) verify that every tree entry or tag points to an object of the matching `ObjectKind` (File/Exec/Symlink → Blob, Dir → Tree, Tag → Snapshot) with canonical path-safe entry names (no `.`, `..`, `/`, NUL, or `.veil`), and does GC track leaf marks separately from expanded tree marks?
- **Sources:**
  - `BUG-001` / `BUG-002` / `BUG-029`: Crafted trees with `..`, `.veil`, or unsorted duplicate entry names escaped the working copy or corrupted tree diffs.
  - `BUG-030`: `vl tag set` accepted blob and tree IDs instead of verifying the target was a snapshot.
  - `BUG-2622`: `sync::check_changes` allowed a File tree entry to reference a directory's Tree `ObjectId`; `pack_gc::walk_from_roots` marked that `ObjectId` in a shared `reached` set as a leaf without expanding it, causing GC to delete the real directory's files.

### R-20 — Pack lookups rescan until `pack_gen` settles and compaction locks `STAGED` rows
- **Trigger:** Added lines in `crates/{veil-core/src/{store,pack,maintenance}.rs,veil-server/src/{pack,pack_gc,store}.rs}` matching `pack_gen`, `read_packed`, `has_main`, `refresh_in`, `rescan`, `STAGED`, or `replaced_by`.
- **Check:** When an object lookup misses in memory while pack compaction or GC may be swapping packs, does it loop/reload until a listing at an unchanged `pack_gen` (or `Packs::refresh_in` forgotten count) confirms absence before returning `Missing`, and does compaction lock its own `STAGED` pack row before switching `LISTED` packs?
- **Sources:**
  - `BUG-1898`: Server `Packs::refresh_in` skipped re-listing when two pack merges overlapped, returning false `Missing` errors during compaction.
  - `BUG-2270`: Background pack compaction switched old packs to `REPLACED` after another server's sweep had already discarded its `STAGED` replacement pack.
  - `BUG-2470`: Client `read_packed` and `has_main` rescanned `.veil/objects/pack` only once alongside concurrent GC and settled on `Missing` for live objects.

### R-21 — Background pack merges keep up under load and sweep replaced/crashed packs after grace
- **Trigger:** Added lines in `crates/veil-server/src/{pack,pack_gc,sync}.rs` matching `maybe_schedule`, `merge_tier`, `sweep_replaced`, `sweep_due`, `packs_listed`, `pack_merge`, `read_whole`, `FROM packs`, `Map::weight`, or `grace`.
- **Check:** Does push trigger `maybe_schedule` without O(packs) mutex contention, can background compaction drain small packs faster than sustained pushes create them (using indexed literal state predicates), and does a background sweep still reclaim `REPLACED` packs after the 60s grace period and abandoned `STAGED` packs when a project goes quiet?
- **Sources:**
  - `BUG-2230`: `maybe_schedule` was never wired into the push path, so small upload packs accumulated without bound.
  - `BUG-2280`: Projects that went quiet after a burst never ran a post-grace sweep, leaking `REPLACED` and crashed `STAGED` packs in S3 forever.
  - `BUG-2461` / `BUG-2462`: `Map::weight` scanned every pack under a mutex on each lookup and smallest-tier merges fell behind busy push rates.

### R-22 — In-memory caches hash full scopes with BLAKE3 and evict on GC sweep
- **Trigger:** Added lines in `crates/veil-server/src/{caches,grant,subtree,query/*,cache/*,pack_gc}.rs` matching `Caches`, `evict`, `invalidate`, `committed.`, `grants.stored`, `CacheKey`, or `blake3::Hasher`.
- **Check:** Are composite cache keys hashed with length-prefixed BLAKE3 over project ID, viewer scope, and revision (never XOR-combined hashes), and does every GC delete/sweep evict `hub.caches.committed`, `snapshots`, and `grants.stored` entries for swept objects?
- **Sources:**
  - `BUG-1780`: GC swept unreferenced objects without clearing `hub.caches.committed` and `snapshots`, causing re-pushes of those snapshots to skip uploading missing blobs.
  - `BUG-1781`: `grants.stored` cached object existence across GC sweeps and issued signed cache grants for blobs S3 had already deleted (`404`).
  - `BUG-1870`: Cache keys combined component hashes with XOR (`a ^ b`), allowing crafted inputs to collide across viewer scopes.

---

## Area 5 — Server Concurrency, HTTP & Resource Bounds

### R-23 — Multi-server races on embargo release, branch/bisect leases, and fenced `merging` claims
- **Trigger:** Added lines in `crates/veil-server/src/{embargo,bisect,landing/lease_lock,landing/service,landing/merge}.rs` matching `release_one`, `embargo_lines`, `released_at`, `"not_ready"`, `lease_lock`, `bisect_leases`, `lease_until`, `merging`, `already_released`, or `NotReady`.
- **Check:** If two servers race the same operation, does the loser observe the winner's committed state cleanly (`released_at IS NOT NULL` on `embargo_lines`, session-backed branch leases with prompt takeover notification, retry on held `bisect_leases`, and `(holder, token)` fencing on `merging` rows so dead servers never strand the queue)?
- **Sources:**
  - `BUG-1862` / `BUG-1899`: Bisect check reports were silently dropped when another server held `bisect_leases` or a GC epoch bump raced the step.
  - `BUG-1883`: Crashed servers left unfenced `state = 'merging'` rows in `landing_queue`, stranding branches forever.
  - `BUG-1970` / `BUG-2150`: Branch lease failover waited out stale timers or a 5s poll gap instead of waking as soon as the dead holder's DB session closed.
  - `BUG-2560`: Two servers racing `embargo::release_one` saw the winner land the approved PR and the loser fail with `409 not_ready` because the PR was no longer open.

### R-24 — HTTP/1.1 unread-body `Connection: close`, stream deadlines, and matching ALPN
- **Trigger:** Added lines in `crates/veil-server/src/{lib,main,api,tls,cache/*,limits/body}.rs` matching `CONNECTION.*close`, `Connection::close`, `Version::HTTP_`, `is_end_stream`, `http1`, `http2`, `alpn_protocols`, `accept_timeout`, `header_read_timeout`, `ConnectionLimits`, or `into_body`.
- **Check:** Does any HTTP/1.1 response returned before the request body reaches `is_end_stream()` set `Connection: close`, do pre-TLS sockets, HTTP/1.1 heads/bodies, and idle HTTP/2 streams all carry bounded deadlines, and does TLS ALPN advertise only protocols the listener actually serves?
- **Sources:**
  - `BUG-825` / `BUG-1337`: Idle pre-TLS TCP sockets and HTTP/2 connections answering PING frames without stream progress held connection slots indefinitely.
  - `BUG-1183`: Stalled batch request bodies held cache connection slots without a read-progress deadline.
  - `BUG-1592`: The HTTP/1.1-only object cache TLS listener advertised `h2` in ALPN, breaking TLS clients that negotiated HTTP/2.
  - `BUG-2531`: Answering an HTTP/1.1 request before reading its body omitted `Connection: close`; hyper closed the socket after the head, causing client `Broken pipe` errors on keep-alive reuse.

### R-25 — Buffers fit longest valid input (`HTTP_BUFFER >= MAX_CHAIN`) and `Range`/page answers prepay budget
- **Trigger:** Added lines in `crates/veil-server/src/{cache/*,limits/*,web/*,api,sync,store}.rs` matching `HTTP_BUFFER`, `MAX_CHAIN`, `MAX_HEADER`, `WEB_FILE_BYTES`, `header::RANGE`, `Range`, `prepay`, or `MAX_BODY`.
- **Check:** Is every read/header buffer (`HTTP_BUFFER`, `MAX_HEADER`) statically asserted large enough for the longest valid protocol message (e.g. `MAX_CHAIN` 64-hex-char IDs plus grant and signature), do web file views bound bytes as well as line counts, and do `Range` / batch responses prepay `limits::answers` without acquiring nested permits that can self-deadlock?
- **Sources:**
  - `BUG-1181` / `BUG-1184` / `BUG-1185`: Unbudgeted 64 MiB batch bodies, stalled responses, and nested semaphore acquisitions deadlocked the server's memory pools.
  - `BUG-1415` / `BUG-1420` / `BUG-2469`: Cache `HTTP_BUFFER` was 64 KiB while a valid `Veil-Chain` header of `MAX_CHAIN` IDs was 66.7 KiB, randomly failing `431` or resetting connections depending on TCP chunking.
  - `BUG-1785`: `Range: bytes=0-` object downloads bypassed `answers::prepay` memory accounting.
  - `BUG-1872`: A 600 KiB minified single-line file bypassed line-count pagination and blew past `WEB_FILE_BYTES_PER_PAGE`.

### R-26 — Spawned tasks carry `RequestLocals`, `WEB_CTX` fails closed, and `Origin` requires `https://`
- **Trigger:** Added lines in `crates/veil-server/src/**/*.rs` matching `tokio::spawn`, `spawn_blocking`, `in_request`, `RequestLocals`, `task_local!`, `WEB_CTX`, or `check_same_origin`.
- **Check:** Does every `tokio::spawn` inside a request wrap its future in `limits::in_request` so `BOUNDS`, `PLACES`, and `COMMITTED` task-locals propagate (preventing retries from re-executing an already-committed push), do task-locals like `WEB_CTX` fail closed when absent, and does `check_same_origin` require `https://` scheme equality as well as host equality?
- **Sources:**
  - `BUG-1668` / `BUG-1863`: `tokio::spawn` in `push_with` dropped `RequestLocals` (`BOUNDS`, `PLACES`, `COMMITTED`), losing memory bounds and re-running committed pushes on retry.
  - `BUG-1906` / `BUG-1927`: `check_same_origin` compared hostnames without requiring `https://`, accepting `http://` origins from MITM attackers.
  - `BUG-1926`: Reading `WEB_CTX` outside its task-local scope defaulted open instead of refusing the request.

### R-27 — 1 GB memory gates (client 512 MiB, server 1,024 MiB), first-entry batch flush, and daemon prefetch
- **Trigger:** Added lines in `crates/{veil-core/src/{prefetch,pack,remote,blob_stream}.rs,vl/src/{hub,thin,daemon/*}.rs,veil-server/src/{main,subtree,pack,landing/*}.rs}` matching `tikv_jemallocator`, `MALLOC_CONF`, `BATCH_BYTES`, `MAX_BATCH`, `prefetch`, `subtree`, `SUBTREE_REVISION`, or `dirty_decay_ms`, or any edit to `scripts/bench-{scale,server}.sh`.
- **Check:** Does the change keep 1 GB profile peak RSS within gate (`vl` ≤ 512 MiB in `scripts/bench-scale.sh 1g`, `veil-server` ≤ 1,024 MiB on merged `integration`), flush landing/pack batches even when the *first* entry's stack exceeds `BATCH_BYTES`, and avoid `subtree` prefetches that bypass a running local daemon's tree cache?
- **Sources:**
  - `BUG-800` / `BUG-813`: Streaming/transfer changes passed `small` benchmarks while regressing the 1 GB profile past the 512 MiB client RSS gate.
  - `BUG-1107` / `BUG-1272`: Batch loops checked `bytes > BATCH_BYTES` only when `count > 0`, letting a huge first stack allocate unbounded memory.
  - `BUG-2210`: Thin clone `subtree` prefetch bypassed the local daemon when running, leaving the daemon cache cold on subsequent clones.
  - `BUG-2456` / `BUG-2483`: Default allocator slab/decay retention pushed full-clone server RSS past 1,024 MiB (and un-rebased branches misread pre-fix peaks).

---

## Area 6 — Client Engine, Sandboxes, Portability & Formats

### R-28 — Op-log merges separate settler rebases from re-recorded command rewrites; `undo` scopes to `ChangeId`
- **Trigger:** Added lines in `crates/{veil-core/src/{oplog,settled,repo,commands}.rs,vl/src/{history,rewrite_cmd}.rs}` matching `shared_base`, `merge_plan`, `add_rebases`, `settler`, `OpRecord`, `rewritten_from`, or `undo`.
- **Check:** Do `shared_base`, `merge_plan`, and `add_rebases` treat an op-log merge's own rebase as a derived effect while never mistaking a command rewrite re-recorded inside a settler op for the settler's own rebase, and does `vl undo --op` carry forward working-copy edits only when the target op shares the same `ChangeId`?
- **Sources:**
  - `BUG-1041`: `vl undo --op` merged working-copy edits from an unrelated `ChangeId` into the restored snapshot.
  - `BUG-2464` / `BUG-2466`: `shared_base` and `merge_plan` treated a merge op's derived rebase as an independent user rewrite, leaving two visible versions of one commit.
  - `BUG-2550`: `add_rebases` treated a user command's rewrite re-recorded in a settler op as the settler's own rebase, dropping concurrent `describe` or tag updates.

### R-29 — Crash-safe publish order (`.pack` → `.idx` → op), live-tx GC lock, clone journal, `O_NOFOLLOW` barriers
- **Trigger:** Added lines in `crates/{veil-core/src/{transaction,gc,maintenance,checkout,working_copy,store,vfs/*}.rs,vl/src/{auto_gc,hub_cmd}.rs}` matching `sync_all`, `barrier_sync_dir`, `O_NOFOLLOW`, `O_DIRECTORY`, `prune_now`, `live_transactions`, `clone_journal`, or `.idx`.
- **Check:** Are packs written and fsynced in strict `.pack` → `.idx` → parent dir → op-head order, does `gc` respect active lock/transaction leases, does `vl clone` journal checkout completion so an interrupted clone never looks clean with missing files, and do directory barriers open components with `O_DIRECTORY | O_NOFOLLOW` without failing on valid symlinks?
- **Sources:**
  - `BUG-025` / `BUG-833`: Checkout directory fsync followed symlinks outside the workspace or failed with `ELOOP` when a directory became a symlink.
  - `BUG-811`: `vl gc --prune-now` under parallel load swept objects written by a live `vl ws exec` transaction before its op head published.
  - `BUG-830` / `BUG-837`: Killing `vl clone` mid-checkout left a valid-looking `.veil` repo where unmaterialised files appeared deleted in `vl status`.

### R-30 — Workspace sandbox overlays, full revset endpoint checks in `ws_socket`, and non-Linux warnings
- **Trigger:** Added lines in `crates/{veil-core/src/{sandbox,workspace,vfs/sandbox}.rs,vl/src/{sandbox,confine,ws_socket}.rs}` matching `bwrap`, `sandbox`, `ws_socket`, `ephemeral`, `unconfined`, `revset`, `overlay`, or `target_os = "linux"`.
- **Check:** Does `vl ws exec` hide unshared secrets while keeping tool dirs (`~/.cargo`, `~/.rustup`, `~/.claude`) usable via temporary overlays, does `ws_socket` verify confinement on *every* endpoint of revsets like `A..B` (not just `B`), does `--ephemeral` tolerate unreadable stray dirs in cleanup, and do non-Linux builds warn clearly when running unconfined?
- **Sources:**
  - `BUG-022` / `BUG-1025`: Sandboxes either exposed host secret files or mounted `$HOME` read-only without overlays, breaking `cargo` and `claude` inside `vl ws exec`.
  - `BUG-1786`: `ws_socket` validated confinement only on `B` in `vl log -r A..B`, letting a confined command inspect unconfined commits via `A`.
  - `BUG-2200`: A `chmod 000` directory left by a sandboxed command caused `--ephemeral` cleanup to fail after recording succeeded.
  - `BUG-2455`: Non-Linux `vl ws exec` ran commands without namespace confinement and without warning the user.

### R-31 — Quarantined secret files exit 3 across all commands and survive `--ephemeral`
- **Trigger:** Added lines in `crates/{veil-core/src/{secrets,wc_policy,workspace}.rs,vl/src/{main,cli,api,api/*,doctor,mount,sandbox,hub_cmd,confine,rewrite_cmd}.rs}` matching `quarantine`, `Quarantined`, `quarantine_kept`, `EXIT_QUARANTINE`, `ephemeral-kept`, `ephemeral_kept`, `LeftOut`, or `exit(3)`.
- **Check:** Whenever the secret scanner quarantines a file, do `vl commit`, `vl change new`, `vl push`, `vl land`, and `vl ws exec` all exit with status `3` (while recording the non-quarantined rest where specified), and does `vl ws exec --ephemeral` rescue quarantined files (with permissions and cross-filesystem fallback) into `.veil/local/ephemeral-kept/` even if a post-recording step fails?
- **Sources:**
  - `BUG-2140`: `vl commit`, `vl change new`, and `vl push` printed a warning for quarantined secret files but exited `0`, hiding left-out files from scripts.
  - `BUG-2170`: `vl land` exited `0` when the working copy held a quarantined file instead of matching `push`'s exit status `3`.
  - `BUG-2171`: `vl ws exec` exited `0` when its recording quarantined a secret-looking file, and `--ephemeral` deleted the sandbox directory along with the unrecorded file.

### R-32 — Format upgrades, `veil-core` WASM `#[cfg(feature = "os")]`, MSRV 1.88, and blessed CLI docs
- **Trigger:** Added lines in `crates/{veil-core/src/*,vl/src/{cli,docgen}}.rs` matching `REPO_FORMAT_VERSION`, `FORMAT_VERSION`, `upgrade_repo`, `std::{fs,process,net,os::unix}`, `#[command(`, or `#[arg(`, added lines in `crates/**/*.rs` matching `.try_update(` or `.extract_if(`, or dependency/MSRV edits in `Cargo.toml`.
- **Check:** Do disk/wire/JSON schema changes bump format/schema versions with a `vl upgrade` path covering renamed secrets and conflict sides, is OS-only code in `veil-core` behind `#[cfg(feature = "os")]` (`scripts/check-wasm.sh`), do all targets (including tests) compile on workspace MSRV `rust-version = "1.88"`, and were `docs/reference/` (`VEIL_BLESS_DOCS=1`) and `docs/HUB.md` updated?
- **Sources:**
  - `CLAUDE.md` ("Core constraints", "Conventions"): Format bumps require `vl upgrade`; `veil-core` compiles to `wasm32-unknown-unknown --no-default-features`; CLI changes regenerate `docs/reference/`.
  - `BUG-817` / `BUG-1873`: CLI flags and server wire documentation (`docs/reference/`, `docs/HUB.md`) drifted from the implementation.
  - `BUG-940` / `BUG-941`: Format 8 broke `/1` JSON consumers and `vl upgrade` missed renamed secret files and conflict sides.
  - `BUG-2610`: `AtomicUsize::try_update` (stabilised in Rust 1.95) in a `veil-core` durability test broke `cargo clippy --all-targets` under workspace MSRV 1.88.

---

## Area 7 — Tests & Harness Isolation

### R-33 — Tests avoid substring checks on random hex/`[k-z]` IDs, short leak needles, and `[k-z]` tags
- **Trigger:** Added lines in `crates/**/tests/**/*.rs` matching `.contains("<2–7 hex chars>")`, `.contains("<2–5 lowercase chars>")`, `"tag", "set", "<[k-z]+>"`, or `tag_set(…, "<[k-z]+>")`.
- **Check:** Do tests parse structured fields or match full IDs/markers (≥8 bytes for ciphertext/pack leak checks) rather than calling `.contains("5d2e")` or `.contains("two")` on bodies containing random `[0-9a-f]` snapshot/PR IDs or `[k-z]` change IDs, and do test tag names include characters outside `k–z`?
- **Sources:**
  - `CLAUDE.md` ("Tests"): Never substring-match random change/snapshot IDs; never name tags using only `k–z`; leak checks must grep for full markers (≥8 bytes).
  - `BUG-105`: Test tag names made solely of letters `k–z` parsed as short change IDs and flaked when prefixes collided.
  - `BUG-1127` / `BUG-1171`: Tests asserting `!out.contains("two")`, `"work"`, `"mount"`, or `"root"` flaked whenever a random `[k-z]` change ID contained that substring.
  - `BUG-2471`: Server tests asserting `!body.contains("5d2e")` and `!body.contains("e10")` flaked whenever random hex PR or snapshot IDs contained those substrings.

### R-34 — Server tests isolate DDL, `SERIALIZABLE` tx, custom stores, shared-table deletes, and row IDs
- **Trigger:** Added lines in `crates/veil-server/tests/**/*.rs` matching `ALTER TABLE`, `DROP INDEX|TABLE`, `CREATE INDEX|TABLE`, `SERIALIZABLE`, `DELETE FROM <table>`, `TRUNCATE`, `LocalStore`, `S3Store`, `start_with_store`, `own_database`, `start_own`, `setval`, `pg_get_serial_sequence`, or `INSERT INTO (groups|users|projects) (… id …)`.
- **Check:** Does any server test that alters schema, runs heavy `SERIALIZABLE` transactions, or mounts a custom `ObjectStore` use `TestHub::start_own` (`own_database` with serialized migrations and `projects.id` sequence offset > $2^{32}$ so S3 `p/<id>/` keys never collide with the shared DB's GC), scope every `DELETE`/`UPDATE` by `WHERE project_id = $1`, use `embargo::release_one` instead of global `release_due`, and avoid hardcoded `groups.id` / `users.id` constants?
- **Sources:**
  - `BUG-2134`: Parallel tests calling global `embargo::release_due` raced sibling tests' due embargoes on the shared database.
  - `BUG-2212` / `BUG-2341` / `BUG-2532`: Schema DDL and `SERIALIZABLE` stress transactions on the shared database aborted sibling tests on YugabyteDB.
  - `BUG-2457` / `BUG-2580` / `BUG-2582`: `TestHub` instances with custom stores shared the database (so their `embargo::run_loop` failed sibling embargoes with missing blobs), and concurrent `own_database` migrations wedged YugabyteDB catalog locks.
  - `BUG-2530` / `BUG-2600`: Unscoped `DELETE FROM view_fills` wiped sibling projects' rows, and hardcoded group IDs `900_001..` collided across tests.
  - `BUG-2620`: `own_database` numbered `projects.id` from `1`, colliding on shared S3 bucket `p/1/` keys with the run's shared database so one server's GC deleted the other's live objects.

### R-35 — Tests assert primary action outcome unconditionally (never guarded by `if ok` / `if status == 200`)
- **Trigger:** Added lines in `crates/**/tests/**/*.rs` matching `if let Ok(`, `if <resp>.status() ==`, `if <out>.status.success()`, or `if ok {`.
- **Check:** Does the test unconditionally assert that its primary action succeeded (`assert_eq!(r.status, 200)` / `.ok(...)`)—or failed with the exact expected refusal—*before* checking any side effects, with zero `if ok { assert!(…) }` guards that let the test pass vacuously when the action breaks?
- **Sources:**
  - `CLAUDE.md` ("Tests"): Every test must assert a positive outcome for the action under test before checking side effects.
  - `BUG-1103` / `BUG-1110`: Stack-landing tests wrapped their assertions in `if ok { … }`, staying green while every 2-change stack was being refused.
  - `BUG-2581`: A test built its expected JSON key set from an unchecked setup PR request that returned `429`/`503` under load, turning error fields into the expected schema.

### R-36 — Tests retry transient `503`/stamp-aborted GC passes and avoid wall-clock timing ratios
- **Trigger:** Added lines in `crates/**/tests/**/*.rs` matching `mark_and_sweep`, `gc_pass`, `.elapsed() <|>`, `as_{millis,micros,secs_f64}() *|/|<|>`, `503`, `"warming"`, or `"deadline"`.
- **Check:** Do tests running under parallel suite load retry legitimate transient `503` (`warming`, `deadline`, `busy`) responses and loop `gc_pass` when background `search_shards` / derive activity moves a `STAMP_TABLES` stamp, assert safety (no leak) before liveness, avoid wall-clock timing ratios, and run changed concurrency tests in parallel loops?
- **Sources:**
  - `BUG-758` / `BUG-831`: Wall-clock timing ratios and mid-race liveness assertions flaked whenever CPU scheduling shifted under suite load.
  - `BUG-811`: A GC/workspace concurrency test passed 10/10 alone and failed 1-in-3 only when 12×8 copies ran in parallel.
  - `BUG-2222` / `BUG-2468` / `BUG-2582`: Single-shot test requests failed sporadically when shared server gates returned transient `503 busy`/`warming`/`deadline`.
  - `BUG-2590`: Tests calling `pack_gc::mark_and_sweep` once expected immediate deletion even when background `search_shards` indexing moved the reference stamp and caused the pass to give way cleanly.

---

## Appendix: History Validation on `integration` Merges

Validated by running `bash scripts/reliability-triggers.sh <merge>^1..<merge>^2` across 18 historical merges on `integration` (plus sibling fix branch `64900fb9`). Note that `scripts/reliability-triggers.sh` normalizes two-dot `A..B` ranges to merge-base `A...B` so un-rebased feature branches are diffed strictly against their merge base without reverse-diff noise from unrelated merges on `integration`.

Across the 18 merges, match counts ranged from **1 to 10 items** (median **4.5**, mean **4.9**; **14 of 18** substantive merges matched **3–10 items**, while narrow 1–2 file fixes matched the **1–2** items for their exact subsystem).

| Merge | Stream / Summary | Count | Matched Items | Would Matched Checks Point at Review Findings / Later Escapes? |
|---|---|---:|---|---|
| `57052373` | `t3/bug-2464-2466-merge-rebase` (op-log merge rebases) | 1 | `R-28` | **Yes:** `R-28` directly asks whether `add_rebases` mistakes a command rewrite re-recorded inside a settler op for the settler's own rebase (`BUG-2550`, caught in review before merge). |
| `c3eaa053` | `t3/bug-2470-durability` (pack lookup rescan beside GC) | 2 | `R-20, R-32` | **Yes:** `R-20` checks the `pack_gen` rescan loop (`BUG-2470`), and **`R-32` directly catches escaped `BUG-2610`** (`AtomicUsize::try_update` added in `maintenance.rs` breaking MSRV 1.88). |
| `1478c769` | `t3/bug-2560-2531-2511` (`projected_id`, online idx 42, HTTP close, own DB) | 9 | `R-11, R-12, R-14, R-23, R-24, R-25, R-33, R-34, R-36` | **Yes:** Matches every class touched (`R-14` `BUG-2467/2510`, `R-12` migration 42 online index, `R-23` `BUG-2560`, `R-24` `BUG-2531`, `R-25` `BUG-2469`, `R-33` `BUG-2471`, `R-34` `BUG-2530/2580/2582`). |
| `7440a76a` | `t3/bug-2590-gc-retention` (online index runner, `start_own`, `gc_pass`) | 5 | `R-12, R-13, R-16, R-34, R-36` | **Yes:** Covers `R-12/R-13` (`BUG-2482/2532/2570/2571`) and `R-36` (`BUG-2590`), and **`R-34` directly points at escaped `BUG-2620` & `BUG-2600`** (`own_database` starting `projects.id` at 1 and colliding on S3 `p/1/` keys; fixed IDs). |
| `13abad48` | `t3/bug-2483-clone-memory` (`packs_listed` migration 41, pack merges) | 4 | `R-12, R-20, R-21, R-36` | **Yes:** **`R-12` directly catches `BUG-2482`**, filed right after this merge because migration 41 built `packs_listed` inside a transaction instead of `-- veil: online indexes`. |
| `f2ea7734` | `t3/one-repo-ceiling` (post-commit `pg_notify`, pack weights) | 4 | `R-16, R-22, R-26, R-36` | **Yes:** `R-16` checks post-commit `pg_notify` (`BUG-2459`); `R-22`/`R-26` check cache notice delivery and spawned tasks (`BUG-2460/2461/2463`). |
| `6bfadded` | `t3/server-push-cost-reduction` (push statements 30 → 13, GC epoch once) | 4 | `R-14, R-16, R-18, R-36` | **Yes:** `R-16` verifies single-commit push invariants and `R-18` verifies `guard_root_write` / `gc_epoch` safety when reading the GC epoch once per push. |
| `9d37eeab` | `t3/branch-tips-cost-cleanup` (`vl land --delete`, `FOR SHARE` onto lock) | 5 | `R-03, R-07, R-09, R-15, R-32` | **Yes:** `R-07` checks protected/default branch write rules, `R-09` checks narrowed agent branch-delete refusal, `R-15` checks `FOR SHARE` target locking (`BUG-2447/2450`), and `R-03` checks uniform `not_deleted` refusal wording. |
| `72bfdc21` | `commits2350` (one DB commit per push, batched fill memos) | 5 | `R-14, R-16, R-21, R-33, R-36` | **Yes:** `R-16` directly checks single-commit-per-push (`BUG-2350`, `BUG-2390`). |
| `eabf881a` | `packgc2` (quiet-project post-grace sweep, swept upload guard) | 5 | `R-12, R-15, R-20, R-21, R-26` | **Yes:** `R-21` checks quiet-project post-grace sweeps (`BUG-2280`) and literal partial-index state (`R-12`); `R-20` checks staged/swept upload coordination (`BUG-2310`). |
| `09e89391` | `packgc` (background small-pack merges, `STAGED` discard check) | 2 | `R-20, R-21` | **Yes:** `R-20` checks `STAGED` replacement locking (`BUG-2270`), and **`R-21` directly catches escaped `BUG-2280`** (quiet projects never sweeping replaced/crashed packs after the 60s grace). |
| `c9d6058a` | `wsexec-q` (`vl ws exec` exit 3 and `ephemeral-kept`) | 2 | `R-30, R-31` | **Yes:** **`R-31` & `R-30` directly point at `BUG-2200` and `rv-wsexec-q`**, checking cross-filesystem preservation if a post-recording step fails and unreadable stray dirs in `--ephemeral`. |
| `619b47d3` | `failover2` (session-tied branch lease takeover, YB `READ COMMITTED`) | 4 | `R-03, R-13, R-23, R-36` | **Yes:** `R-23` checks multi-server branch lease takeover (`BUG-1970`, `BUG-2150`); `R-13` checks migration 39 idempotence. |
| `8ac1c167` | `clifast3` (thin one-folder clone, `subtree` single-request fetch) | 3 | `R-08, R-27, R-33` | **Yes:** **`R-27` directly catches escaped `BUG-2210`** (`subtree` prefetch bypassing the running local daemon and leaving its cache cold). |
| `10ec528d` | `landbugs2` + `reviewgate` (`review_writers`, lock hierarchy) | 6 | `R-12, R-13, R-15, R-26, R-34, R-36` | **Yes:** **`R-15` catches `BUG-2130..2133` and points at `BUG-2135`** (YB `READ COMMITTED` startup check), while **`R-34` points at `BUG-2134`** (`release_due` vs `release_one` test race). |
| `2fadca98` | `rcsrv` (server re-check fixes `BUG-1920..1928`) | 10 | `R-03, R-07, R-09, R-12, R-13, R-17, R-18, R-19, R-26, R-34` | **Yes:** Broad 9-bug server security wave; matches write checks (`R-07` `BUG-1920`), `STAMP_TABLES` (`R-18` `BUG-1923`), `WEB_CTX`/`Origin` (`R-26` `BUG-1926/1927`), and DB TLS params (`R-17` `BUG-1928`). |
| `6fa56930` | `mfix2` (GC root writer lock and fenced `merging` claims) | 9 | `R-03, R-07, R-09, R-11, R-13, R-18, R-23, R-26, R-34` | **Yes:** Matches `R-18` (`BUG-1881` `guard_root_write` across GC switches) and `R-23` (`BUG-1883` fenced `merging` claims). |
| `606b89d6` | `s26fix` (browser secrets + review fixes `BUG-1900..1908`, `BUG-1871`) | 9 | `R-02, R-04, R-08, R-12, R-13, R-26, R-32, R-33, R-35` | **Yes:** Matches `R-02` (`BUG-1871` `identity.json` boundary), `R-26` (`BUG-1906` `https://` `Origin` check), `R-32` (WASM/docs), and `R-12/R-13` (migration 33). |

*(Additionally, running `bash scripts/reliability-triggers.sh integration..64900fb9` on the sibling open-bugs fix branch matched **5 items**—`R-18, R-19, R-21, R-34, R-36`—covering `BUG-2621`, `BUG-2622`, `BUG-2620`, `BUG-2600`, and `BUG-2590`.)*

### Trigger Tuning Notes
1. **Skipping prose and comments:** Every Veil merge updates `docs/BUGS.md` and Rust doc/inline comments with SQL and symbol names from past bugs; `scripts/reliability-triggers.sh` scopes code/SQL regexes to non-doc paths and strips `//` comment lines in `.rs` files so prose never triggers code checks.
2. **Tightening `R-36` against diagnostic timing logs:** Matching bare `Instant::now()` / `.elapsed()` fired on diagnostic `eprintln!` lines across unrelated tests; restricting `R-36` to `.elapsed() <|>`, `as_{millis,micros,secs_f64}() *|/|<|>`, `mark_and_sweep`/`gc_pass`, and `503`/`"warming"`/`"deadline"` removed test-log noise while keeping every real flake pattern.
3. **Normalizing two-dot `A..B` ranges to `A...B`:** Un-rebased branches diffed with `git diff M^1..M^2` include inverse diffs of sibling commits on `integration` (inflating a 1-item engine fix like `57052373` to 9 unrelated server items); converting `A..B` to merge-base `A...B` makes `<merge>^1..<merge>^2` and `integration..HEAD` match only what the branch itself changed while staying identical on linear ranges.
