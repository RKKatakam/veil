# 4. Background cleanup instead of whole-store `gc`; streaming pull

Status: **built** (streams G1 and G2, Scion 2.2; this is the design and threat review, with as-built notes; the backlog's "streaming / incremental gc" and "streaming pull" items). **No repository format change.** Pack and index bytes are unchanged; the gc lease and the maintenance log are new device-local files.

## The problem

- **`gc::gc` holds `RepoLock` for its whole run.** It lists every loose and packed object into a `HashSet` (the inventory), and reads every operation into a `HashMap`. It marks reachability into another set, writes **one** new pack of everything kept through `PackBuilder` (whose `buf: Vec<u8>` holds the whole pack in memory), and then deletes. On a 5 GB store that is gigabytes of RSS and a repository locked for minutes.
- **`PackBuilder::finish` writes with one `backend.write(&self.buf)`**, so every pack written anywhere (gc, push, pull) is held whole in memory first.
- **Pull:**
  - `PullSource::prefetch` downloads up to `PREFETCH_LIMIT` (2 GiB) of remote packs **into memory** (`MemoryBackend` per pack);
  - `pull_incremental` builds `local_ids` from `ObjectStore::list_objects()`, a set of every local object id;
  - the received objects go through `PackSink`, so through an in-memory `PackBuilder` again.
## Design sketch

### G1 (first milestone): streaming pack writing

- **`StorageBackend::create_stream(path, durable) -> Box<dyn StreamWriter>`** (`vfs/mod.rs`), with `write_all(&[u8])`, `write_at(offset, &[u8])` and `finish()`.
  - The default implementation buffers into memory and calls `write`, which keeps `MemoryBackend`, the plan sink and `SandboxFs` working.
  - **`DiskBackend`:** a temp file (`O_EXCL`), `pwrite`, fsync, rename, and a directory fsync when `durable`.
  - **`SftpBackend`:** a temp file (`O_EXCL`), pipelined `WRITE`s at offsets, `fsync@openssh.com`, `posix-rename@openssh.com`, as `write` does today.
- **`pack::PackWriter`** (beside `PackBuilder`, same byte format):
  - `PackWriter::new(stream, count: Option<u32>, level)` writes entries as they come;
  - it keeps only the `(id, offset, len)` table (48 bytes per object), the delta-base map and a bounded LRU of the last version at each path (64 MiB);
  - `finish()` patches `count` at offset 8 (`write_at`), writes the trailer and then the `.idx`.
  - **The trailer hash** covers the patched header. When `count` was given up front (gc knows it after marking) the hash is computed while streaming. Otherwise `finish` re-reads the file once to hash it: the file is a local spool or a staged file, read sequentially.
- **`PackBuilder` stays** for small packs and for WASM. `PackSink` (pull and push) and gc move to `PackWriter`.

**Implemented (BUG-800), with these differences from the sketch:**
- `create_stream(dir, durable)` names the file at `finish(name)`: a pack's name is its checksum, known last.
- The trailer hash is always computed while streaming, so nothing is read back (no second read over SFTP). The first BLAKE3 chunk (1 KiB, holding the count) is kept; the rest is hashed into the subtrees `[C, 2C)`, `[2C, 4C)`, … that BLAKE3's tree has at any final length (`blake3::hazmat`), merged at `finish`.
- Prefetch spools to `.veil/objects/incoming/pull` (item 2's staging does not exist yet), in 4 MiB pieces, removed when the pull ends. `PREFETCH_LIMIT` keeps its 2 GiB, now of disk; the pull fails first, naming the space needed, when `statvfs` shows less free. The download is checked as before (`Pack::open`, then every object re-hashed); `local_ids` and whole-pack adoption are unchanged.
- `PackSink` keeps the last version per path in a 64 MiB LRU (it was every path's, for the whole pack). Each pack is a durable stream of its own (fsync, rename, directory fsync), then the store's barrier, then the `.idx`.

### Incremental maintenance (`crates/veil-core/src/maintenance.rs`, `gc.rs`)

Three tasks. The first two never need reachability.

1. **Consolidate loose objects.**
   - Pack every loose object older than 10 minutes into one new pack (reachable or not; prune decides later).
   - Then, **in this order**: write the pack, write the `.idx` durably, remove each consolidated loose file.
   - It is cheap and can run often.
2. **Geometric merging.** Sort packs by size and merge the smallest run so that each remaining pack is at least twice the size of the next smaller one (Git's `repack --geometric=2`).
   - The big old pack is never rewritten.
   - Objects are copied as stored (no re-delta), except for delta chains whose base lies in a pack being dropped: those are rebased onto the base's new copy.
3. **Prune** (reachability; rare):
   - **Inventory**, as today and strictly before marking: every pack index plus the loose fan-out listings. Positions are assigned in a sorted merge of the index id arrays plus the loose ids, and they are never copied into one big vector: lookups binary-search each pack's `ids` and a sorted loose list.
   - **Mark into a bitmap**, one bit per inventory position. Roots are as today: the views of every retained operation and **every op head** (item 2), the universal root, `checkout.json`'s snapshots, keep markers, and `extra_roots`.
   - **Snapshots are walked through `GraphIndex`** (item 3) where indexed. Trees are walked iteratively, and a subtree whose bit is already set is not entered again. Memory is the bitmap, the walk stack, the per-pack tables and the cache limits; **never the objects' content**.
   - **The grace period and freshening are unchanged:** the pending list (`objects/gc/pending`), keep markers, and the read–delete–recheck step for loose objects.
   - **Packed garbage is removed by rewriting only packs whose garbage share is above 25 %**: their live objects are copied into a new pack by `PackWriter`, then the old pack goes, index first.
   - **"Refuse to guess" is unchanged:** an unreadable operation, snapshot or tree on the way means the run deletes nothing.
4. **Op-log pruning** (`--keep-ops-days`) is unchanged, except that every op head and its parents are always kept.

**Locking.** Maintenance and `vl gc` no longer take `.veil/lock`. They take a **gc lease**, `.veil/gc.lock`, implemented as a `RepoLock` on another path (`RepoLock::acquire_at`), with the same takeover and fencing rules. Only one gc runs at a time, and writers never wait for it. Concurrency with writers rests on what already makes gc safe beside a writer that started earlier:
- the inventory is taken before marking;
- staging from item 2 is invisible to gc, and published after its inventory;
- keep markers;
- the grace period.

**On a format-5 remote** (`vl -R origin gc`), gc also takes `.veil/lock` for the whole run. An older client's gc may be running, and it deletes the packs this gc would be merging.

**Background runs.**
- `Ctx::finish` (through the stub hook `maintenance::maybe_spawn`) starts `vl gc --auto` detached in its own process group, with `nice 10` and, on Linux, `ioprio` idle. That happens when:
  - more than 6,700 loose objects exist (Git's `gc.auto`), or
  - more than 50 packs exist, or
  - the prune estimate is reached: the operations since the last prune rewrote more than 10,000 snapshots (from `Operation::rewritten`, item 2), or 7 days have passed.
- `--auto` does consolidation and merging every time, and prune only on the estimate.
- Output goes to `.veil/local/maintenance.log` (0600, kept to 1 MiB).
- **Never:** inside `vl serve`'s request path, when `VEIL_GC_AUTO=0`, or (by default) when `CI` is set. Today's remotes are never maintained automatically; push phase B does not run gc. On the server, cleanup is a background retention rule on object storage (`docs/HUB.md` §9.1).
- `vl gc` (explicit) keeps today's flags and output, and runs all three tasks in the foreground.

### Streaming pull (`remote.rs`)

- **`PullSource::prefetch`** downloads each needed remote pack into the pull's staging directory (item 2: `.veil/objects/incoming/…/`) through `create_stream`.
  - It reads with `read_range` in 8 MiB pieces, several packs at a time (`par_map`).
  - It checks the trailer sum as it streams.
  - It refuses more bytes than the remote's `.idx` implies (`pack_len`).
  - The download is then opened with `Pack::open(&DiskBackend, …)`, whose reads are ranged.
- **`PREFETCH_LIMIT`** stops being a memory bound. It becomes a disk bound (default 2× the remote's indexed size, checked against free space before downloading, with the error naming the space needed).
- **Membership checks.** `local_ids: HashSet<ObjectId>` (from `list_objects`) is replaced by `ObjectStore::contains(id)`: pack index lookups, then a loose `metadata`, with no freshening.
- **Received objects** go through `PackSink` backed by a `PackWriter` into staging, published at commit (item 2). Downloaded remote packs are deleted after the pull.
- **Whole-pack adoption** (moving a downloaded remote pack into `pack/` as it is) is **not** done this round (open decision 3).

### Not in this item

- Streaming large-file read, hash and seal in the builder (backlog item): taken only if item 9's 5 GB numbers show the builder's peak RSS over the gate (see `PLAN.md`, conditional stream).
- Content-defined chunking.

## Threat review

1. **A loose file deleted before its pack is durable.** Consolidation deletes the loose copy, the new pack's `.idx` is lost at a power cut, and the object is gone.
   - *Invariant:* a loose object is removed only after the `.idx` naming its new pack returned from a durable write, and after a barrier covering the `.pack`.
   - *Test:* the `crash.rs` sweep over `maintenance::consolidate` and `merge_packs` in all three modes. Every object reachable before is readable after, and `fsck` passes.
2. **A reader misses an object during consolidation.** A reader with a cached pack list looks loose (gone), then in its known packs (not there yet), and reports `Missing`. **To the engine `Missing` means redacted** (`VeilError::is_unreadable`), so a builder could carry a "redacted" entry, a checkout could leave it out, and a push could skip it.
   - *Invariant:* `ObjectStore` returns `Missing` only after a loose probe **and** a reload of the pack list **and** a second loose probe.
   - *Test:* one thread consolidates and merges in a loop while 8 threads read random reachable objects. No read ever returns `Missing`.
3. **Prune beside lock-free writers.** Item 2 commits run during a prune. An operation published after the prune read the heads references an object the mark did not reach.
   - *Invariant:* such an object is at worst newly pending, never deleted in the same run; deletion requires being unreachable in two runs a full grace period apart, with roots read after the inventory each time. Adoption of a pending object writes a keep marker first.
   - *Test:* extend the gc race harness: random lock-free commits, abandons and gc runs with `SimClock` steps of 0–90 minutes. Every object reachable from any head stays present.
4. **Memory blow-up.** A hostile pull fills the store with 2²⁵ tiny objects, or a 5 GB store is pruned.
   - *Invariant:* gc memory is O(inventory bits + walk depth + cache limits).
   - *Test:* item 9's gate (`gc` peak RSS ≤ 512 MiB on the 5 GB profile), plus a unit test pruning 2²² synthetic ids with an RSS assertion.
5. **gc meets content it cannot read** (sealed for a scope it lacks, or withheld).
   - *Invariant:* unchanged: an unreadable operation, snapshot or tree deletes nothing in that run. With item 6 an unfetched tree is not unreadable: its whole subtree is on the remote, so it is skipped (item 6, threat 5).
   - *Test:* `gc.rs`'s existing refuse-to-guess cases, plus a store with a tree sealed for a scope this identity lacks.
6. **A hostile remote during a streaming pull:** a pack longer than its `.idx` says, a server that trickles bytes, a pack that fills the disk.
   - *Invariant:* a download stops at the `.idx`-implied length (plus nothing); a pull checks free space for the declared total first; a failed pull removes its staging.
   - *Test:* the hostile SFTP server from `adversarial3_sftp.rs` serves a pack 1 GiB longer than declared, and another that stalls. The pull fails, `incoming/` is empty afterwards, and RSS stays flat.
7. **Unverified objects entering the store** (via adoption, or the disk path skipping checks).
   - *Invariant:* every object entering the store from a remote passes `Transfer`'s checks (hash, decode, `check_storable`, depth, `allowed`), exactly as before.
   - *Test:* a remote pack holding a format-6-only object for a format-5 clone, and a tree deeper than `MAX_TREE_DEPTH`. The pull refuses both, as today.
10. **Maintenance during `vl upgrade`, `ws rm`, or a fix-up.**
    - *Invariant:* `vl upgrade` takes the gc lease as well as `.veil/lock`, and maintenance re-reads `repo.json`'s format under its lease, stopping if it changed.
    - *Test:* start an upgrade with maintenance paused mid-run. The upgrade waits for the lease, or maintenance stops; `fsck` passes.
11. **Surprise background activity.** Unexpected disk I/O on battery, in CI, or inside benchmarks.
    - *Invariant:* auto maintenance runs only from an interactive `vl` command (not `serve`, not `CI`, not `VEIL_GC_AUTO=0`), at idle priority, never in the foreground.
    - *Test:* the `vl` CLI test sets `CI=1` and checks that no maintenance process is spawned; the unset case spawns exactly one per threshold crossing (a second is refused by the lease).
12. **Partial clones.** The cache area of item 6 (`objects/cache/`) is evicted by its own policy.
    - *Invariant:* maintenance never consolidates `objects/cache/` into the main store, and never evicts the main store.
    - *Test:* item 6, threat 6.
13. **Interaction with sandboxes and mounts:**
    - a sandbox's `manifest.json` tree is not a root (documented: rebuilt);
    - a mount's `base` is the workspace's working copy, hence in the view.

    - *Invariant:* the same roots as today, plus all op heads.
    - *Test:* `gc` with a running mount and a persistent sandbox; both keep working, the sandbox rebuilds at most.
14. **Two gcs on a format-5 remote** (an older client's and ours).
    - *Invariant:* on a format-5 remote ours also holds `.veil/lock`.
    - *Test:* `remote_lock.rs`: our remote gc, with a simulated old-client lock present, waits.

## Open decisions

1. **Auto maintenance on by default.**
   - *Recommendation:* yes, off when `CI` is set or `VEIL_GC_AUTO=0`.
2. **Prune cadence.**
   - *Recommendation:* on the rewrite estimate or 7 days, whichever comes first.
3. **Adopting whole downloaded packs on pull** (saves writing every received object again).
   - *Recommendation:* not this round. It needs every object checked anyway, and it would let one remote's delta layout persist locally. Revisit with item 9's pull numbers.

## As built (G2: incremental maintenance)

Built on `integration` @ `2a337ee`, after BUG-811's fix (below). `gc.rs` (prune), `maintenance.rs` (the gc lease, the deletion fence, consolidation, geometric merging, crash debris, background runs), `crates/vl/src/auto_gc.rs` (the spawn and `vl gc --auto`).

### Decisions and differences from the sketch

- **BUG-811 came first, and changed the concurrency argument.** "Inventory before marking, staging invisible, keep markers, the grace period" did not make gc safe beside lock-free writers: a transaction renames its staged objects into the store before its op head names them, and reuses objects already present, so a gc in between saw them as garbage (and with grace 0 deleted them; the operation file itself too). Now every deletion runs under a **fence** that excludes live transactions (`maintenance.rs` module docs): transactions register before they read the heads; gc raises the fence only once none is registered (5 s for a quiet moment, then up to 60 s with the fence raised, else it deletes nothing that run), marks again from re-read roots, and prunes only the operations of its first listing. A **prune epoch** makes a transaction whose process read its view before gc last deleted check, at commit, the ids it brought in. Threat 3's "never deleted in the same run" is replaced by this for grace 0; with a grace period both hold.
- **The fence takes `.veil/lock` too** (stream G2 adversarial fixes, BUG-814): once no transaction is registered, for the re-marking and the deletion only. A bare hub collected with `vl -R ../hub gc` is opened as a lock-free repository, while pushes over SSH (and any transaction over a network backend) register nothing and hold `.veil/lock` instead. The prune epoch moves before the first deletion (BUG-815), so a gc that dies part-way has still told commands to check what they carried.
- **The gc lease is an `flock`** on `.veil/gc.lock`, not `RepoLock::acquire_at`: it only exists for lock-free (local) repositories, where the kernel releases it when its holder dies, so it needs no lease renewal, takeover or fencing. Remotes and format ≤ 5 keep `.veil/lock` for the whole run, as before (threat 14).
- **Snapshots are not walked through `GraphIndex`.** By its own trust rule the index holds neither trees nor parents (parents come from the objects), so it cannot save the snapshot reads; the bitmap, the bounded snapshot and tree caches and the iterative walk bound the memory anyway (measured: about 15 bytes per object beyond the pack index tables).
- **Pack rewrites for garbage**: above a quarter of the bytes as designed, and also for any deletable garbage in a pack of at most 16 MiB (cheap; after geometric merging, small packs mix garbage with live objects, and without this an explicit `vl gc` stopped deleting garbage a user expects gone) or with grace 0 (`--prune-now` deletes at once, e.g. an abandoned change holding a leaked secret). The big old pack keeps its garbage pending until the quarter is reached.
- **What a prune just found unreachable** is consolidated into a pack of its own (in an explicit `vl gc`, which knows), so that a later prune drops that pack whole instead of rewriting a live one.
- **Explicit `vl gc` consolidates every loose object** (age 0), as `vl gc` packed everything before; `--auto` waits the 10 minutes.
- **The spawn check is cheap** (17 directory listings, one small file): the rewrite estimate needs the op log, so `vl gc --auto` evaluates it itself; 10,000 rewrites leave more than 6,700 loose objects anyway. A repository never pruned has no week to count from, so the week starts at its first prune. No second background run starts within 10 minutes of the last (the log's age).
- **Temp files name their writer**: stream temp files are `.stream-<owner>.vltmp…`, so maintenance removes them only once the owner is provably gone; owner-less temp files (an interrupted atomic write, an older vl's stream) only after a day. Push journals are written as streams too (BUG-812).
- **Pull**: the remote's loose objects are spooled in pieces (`loose/<id>` in the pull's spool), checked as they stream; `PREFETCH_LIMIT` is gone, the free-space check before downloading is the bound.
- **Push staging expiry (BUG-810)**: by the cleaning host's own clock, from when it first saw a directory with its current `touched` stamp (`.veil/local/push-expiry/<host>.json` on the remote).

### Threats, mechanisms and tests

| # | threat | mechanism | test |
|---|---|---|---|
| 1 | loose file deleted before its pack is durable | `.pack` (durable stream), then `.idx` (durable write), then the loose files | `crash::{crash_during_gc, crash_during_gc_prune_now}` (all three modes), `maintenance::consolidation_removes_a_loose_copy_only_after_its_pack_and_index`, `maintenance::eio_at_any_step_of_maintenance_loses_nothing`, cli `adversarial_cli_crash::kill_9_mid_gc_never_loses_anything` |
| 2 | a reader takes an object for missing during maintenance | `Missing` only after a loose probe, a pack-list reload and a second loose probe; a pack whose index vanished while opening is removed, not broken | `maintenance::readers_never_take_an_object_for_missing_during_maintenance` (8 readers, own stores, `DiskBackend`) |
| 3 | prune beside lock-free writers, and beside writers that hold `.veil/lock` instead (a push over SSH into a hub collected with `vl -R`, BUG-814) | the deletion fence, then `.veil/lock` under it, re-marking under both, the prune epoch moved before anything is deleted (BUG-811, BUG-815); grace period and keep markers as before | `gc_concurrency::*` (9 deterministic interleavings), `maintenance::prune_with_clock_steps_beside_writers_keeps_everything_reachable`, cli `conformance_sync::gc::{gc_concurrent_with_commits_loses_nothing, gc_beside_commits_pushes_pulls_and_ws_exec_loses_nothing}` (12 × 8 under load) |
| 4 | memory blow-up | bitmap over the inventory, no id sets or paths per object | `maintenance::pruning_memory_is_the_inventory_bits_not_the_objects` (2^16 objects, ≤ 80 bytes each; 15 measured); the 1 GB benchmark (`BASELINE.md`) |
| 5 | content gc cannot read | unchanged: anything unreadable deletes nothing that run | `maintenance::gc_that_cannot_open_a_sealed_tree_deletes_nothing`, the existing refuse-to-guess cases |
| 6, 7 | hostile remote during a pull | stream P's checks, unchanged; loose objects now spooled and checked against their id as they stream | `maintenance::a_pulls_remote_loose_objects_are_spooled_and_checked` |
| 10 | maintenance during `vl upgrade` | `vl upgrade` takes the gc lease; gc re-reads the format under its hold and stops | `maintenance::{upgrade_waits_for_running_maintenance, gc_stops_if_the_repository_was_upgraded_since_it_opened}` |
| 11 | surprise background activity | only from a finished CLI command, not for remotes, not with `VEIL_GC_AUTO=0` or `CI`, low priority, own process group, not again within 10 minutes | cli `gc::background_maintenance_starts_only_where_allowed_and_once` |
| 12 | partial clones | consolidation lists only the `ab/` fan-outs, so a future `objects/cache/` is never consolidated | (item 6 not built yet) |
| 13 | sandboxes and mounts | same roots, plus all op heads | cli `mount_props::gc_beside_a_mount_and_a_kept_sandbox_breaks_neither` |
| 14 | two gcs on a format-5 repository | `.veil/lock` for the whole run there | `maintenance::gc_on_a_format_5_repository_waits_for_an_older_clients_lock` |
| — | the gc lease | `flock`; `--auto` never waits; `.veil/lock` not taken | `maintenance::the_gc_lease_lets_one_run_at_a_time` |
| — | crash debris, never a live owner's | owner-tagged temp files, `owner_gone`; owner-less after a day | `maintenance::{stale_temp_files_go_but_never_a_live_writers, a_dead_transactions_registration_neither_blocks_nor_stays}` |
