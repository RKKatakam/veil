# 1. Lock-free, resumable two-phase pushes

Status: **removed** with path and SFTP remotes (simplification pass, part 1, 2026-11-06); this is the record of what was built (stream P, Scion 1.1 and 1.5). **The server keeps the shape** (`docs/HUB.md` §4.5): objects go to a holding area without a lock, and only the branch move is done one at a time, as a compare-and-swap on one database row instead of under the remote's lock. This document is the design and threat review as it was built. **No repository format change.** A format-5 remote keeps working with format-5 clients, and with this release pushing beside them.

## The problem

`remote::push_with` (`remote.rs`) opens the remote's transaction (`remote.transaction(…)`, which takes the remote's fencing lock) **before** it does any work. Under that lock it then:
1. decides which tags are accepted (`accepted_tags`);
2. computes the closure (`push_closure`);
3. walks and uploads every object (`push_incremental`: `PackSink`, an in-memory `PackBuilder` flushed at `PACK_LIMIT` = 128 MiB with one `backend.write` per pack);
4. copies annotations (`copy_annotations`) and metadata (`publish_staged_releases`, `sync_meta`);
5. writes the operation (`Transaction::commit`).

The lock is held for the whole upload, which has three costs:
- **Pushers time out.** A second pusher waits up to the network lock's `wait` (90 s, `LockOptions::for_backend`) and then fails. Any upload longer than that makes concurrent pushes fail outright.
- **Renewals stall.** Lease renewals queue behind large pack writes on slow uplinks and fence the push (BACKLOG: "SFTP lease renewals can stall on slow uplinks").
- **No resume.** A dropped connection loses the whole upload: the half-written pack is a `.vltmp` file, and the next push starts again from zero.

## Design sketch

The push is split into two phases. Only the second takes the lock, and it does a bounded number of round trips whatever the pack size.

### Phase A: stage, without the lock

1. `open_or_init_remote` as today. Initialising an empty remote still happens under the lock (BUG-120), and that lock is released before staging.
2. Read the remote's **committed view without the lock** (`OpStore::head` and `get`). This *advisory view* is used only to plan.
3. `sendable_tags` (local), then `accepted_tags` against the advisory view. Tags rejected here are dropped before anything is sent, so BUG-288's guarantee holds when nobody else is pushing.
4. `push_closure` and `push_incremental` with a new sink, `StagedPackSink`:
   - Objects go into **chunk packs** of at most `VEIL_PUSH_CHUNK` (default 32 MiB of raw objects). Each pack is built by `pack::PackWriter` (item 4, milestone G1) into a local spool file, `.veil/local/spool/<push-id>/`, never into memory.
   - Each pack is uploaded into the remote's **staging directory**, `.veil/objects/incoming/<push-id>/`. The `.pack` is streamed (`StorageBackend::create_stream`, G1) with `fsync@openssh.com`, then the `.idx` is written durably.
   - The `.idx` is written last, so a staged pack is complete exactly when its `.idx` exists.
   - `push-id` is 128 random bits, hex.
5. The atag objects of the selected tags (`copy_annotations`) go into the last staged pack.
6. **Journal:** `.veil/local/push/<hash of remote URL>.json` holds `{version: 1, push_id, url, started, local_op, tips, staged: [{name, objects, raw_bytes}], boundary: [snapshot ids]}`. It is rewritten durably after each staged pack.

**Faster `known` (also used by item 6).** Today `known_objects` walks every tree of every boundary snapshot in full, which is O(tree size) per push. It is replaced by a path-aligned diff: each new snapshot's tree is compared with its boundary parents' trees, and a subtree whose id equals the one at the same path in a boundary tree is known without reading it. This is equivalent to today's rule: an equal id means an equal closure, and the boundary is in the receiver's committed closure. The difference is that only changed directories are read.

### Phase B: publish, under the lock

1. `RepoLock::acquire` (fencing) and reload the view. `push_with` waits up to 300 s here instead of 90 s, because holders now hold the lock for seconds.
2. `accepted_tags` again, **against the view read under the lock**. A tag that moved meanwhile is rejected with the usual non-fast-forward report.
3. **Boundary check.** Every snapshot in `boundary` (the known snapshots the sent ones build on) must still be in the committed closure of the fresh view: `GraphIndex::is_ancestor_of_any(b, fresh.refs())` from item 3, or `committed_closure` until item 3 lands.
   - If one is not (a forced rewind plus `gc --prune-now` in between), release the lock, run phase A again for the difference, and retry, at most 3 times.
4. **Verify staging.** List `incoming/<push-id>/` and check that every journalled pack's `.pack` and `.idx` exist and that the `.pack` has the size its `.idx` implies.
5. **Publish.** `ensure_held`, then for each staged pack, `rename(incoming/…/pack-X.pack → pack/pack-X.pack)` followed by the `.idx` (index last, as everywhere: readers find packs only through `.idx` files).
6. `publish_staged_releases` and `sync_meta` (read-modify-writes of rings, embargo records and team-vault records, as today).
7. Write the operation and `op_head` (`Transaction::commit`, with `ensure_held` before the head moves).
8. Release the lock, remove the empty staging directory, delete the journal and spool, and report `lock_held_ms` in `SyncReport`.

Phase B costs about `6 + 2 × packs` round trips. For a 1 GiB push in 32 MiB chunks that is about 70 RTTs, still independent of bandwidth. Item 9's gate measures it.

### Retries and resume

- **Crash or dropped connection in phase A.** The next `vl push` to the same remote finds the journal.
  - If `local_op`'s view still reaches the same tips, the push resumes: staged packs whose `.idx` exists are reused (their objects count as known), and `.vltmp` files in its own staging directory are removed.
  - Otherwise the journal is discarded and phase A starts afresh.
  - *As built (stream P adversarial fixes, BUG-808):* there is no tips check. A staged pack is reused, and published, only if the new attempt's own walk meets every object in it; otherwise its staging is removed and phase A starts afresh. Reusing staged packs as known objects whatever the plan (the sketch above) would publish what the plan no longer sends: a change embargoed, cloaked or withdrawn after the interrupted attempt.
- **Crash in phase B before the operation.** Published packs are invisible garbage until something references them. The retry counts the objects in packs named by its journal as known, after checking that those packs exist under `pack/` (step 4 covers both places).
- **Crash after the operation.** The retry finds the tags already at their targets, which is a no-op. The journal is then cleared.
- **`vl push --no-resume`** discards the journal. `vl push --dry-run` never reads or writes it.

### Staging lifetime

- **Rejected in phase B.**
  - Public remote: the staging directory is removed under the lock, so content that was not published stays unpublished.
  - Team remote: it is kept for reuse (the user pulls, merges and pushes again; most blobs are the same).
- **Abandoned.** Any phase B, and `vl -R <remote> gc`, removes staging directories whose newest file is more than 7 days old. A directory touched in the last 24 hours is never removed. `vl doctor --remotes` lists staging directories older than 24 hours with their size. *As built (BUG-810):* "7 days" is of the cleaning host's own clock, from when it first saw the directory with its current `touched` stamp (`.veil/local/push-expiry/<host>.json` on the remote): no other machine's clock is compared with ours.

### Compatibility

- **Older clients ignore staging.** They list only `objects/??/` and `objects/pack/`, so they never read, count or delete `incoming/`.
- **An older client pushing** holds the lock for its whole upload. Our phase B then waits for it, which is unavoidable and bounded by the 300 s wait.
- **An older client's `vl -R gc`** takes its inventory before it marks anything. A pack this release publishes after that inventory is not in it, so it is never deleted.
- **Path remotes** (`DiskBackend`) use the same code: rename is atomic and durable (`DiskBackend::write` syncs the directory).

## Threat review

1. **Two pushers both pass the advisory check.** A and B both see `main = X` and both stage. A publishes `main = Y`, then B's phase B moves `main = Z`, which is not a descendant of Y.
   - *Invariant:* a tag move is decided only under the lock, against the view read under the lock.
   - *Test:* `SyncOptions::pause_before_lock` (a test hook). Two threads push divergent `main` and are released together. Exactly one succeeds, the other reports non-fast-forward, and the remote passes `fsck`.
2. **The boundary disappears between the phases.** Someone force-pushes `main` back and runs `vl -R origin gc --prune-now`, so objects the push skipped as known are gone. Publishing would give the remote a view whose closure is incomplete, and every later clone fails.
   - *Invariant:* every snapshot the new operation references has its closure in the committed closure of the view read under the lock, or in packs published by this push.
   - *Test:* stage against view V1; rewind and prune from a second client; phase B detects it, re-sends, and the remote passes `fsck`; a fresh clone checks out.
3. **Crash at every point.** Cover the upload, each staged `.pack`/`.idx`, each rename, metadata, the operation and the journal.
   - *Invariant:* the `crash.rs` invariant on the remote (it opens; `fsck` passes; the operation appears zero times or once). The retry succeeds and never records two operations.
   - *Test:* extend `crash.rs`'s push sweep with `FaultyBackend` on the remote over the new mutations, including renames, in all three crash modes, then retry.
4. **Staged content on a public remote after a rejection.** Content uploaded to stage a push that is then rejected (the race in 1) sits where every reader of the remote can list it. Before this, BUG-288 meant rejected history was never uploaded.
   - *Invariant:* everything staged passed the same `allowed` filter as a published push to that remote, and on a public remote a rejected push's staging is removed under the lock.
   - *Test:* force the race on a public remote, then check that `incoming/` is empty afterwards and that no staged object was ever sealed (decode every staged object).
5. **Readers trust staging.** If `Inventory::load`, `ObjectStore::list_objects`, `fsck` or `gc` counted `incoming/`, an unpublished, possibly partial pack would count as present ("presence proves nothing").
   - *Invariant:* only `objects/??/` and `objects/pack/` are ever inventoried, and a push treats staged packs as known only if they are its own (named in its journal).
   - *Test:* plant a pack with a corrupt object in a foreign `incoming/<id>/`. Pull, clone, `fsck` and gc are unaffected, and another client's push does not skip its objects.
6. **A hostile or confused staging directory.** `incoming/<push-id>` could be a symlink, a file, or (vanishingly unlikely) another client's directory with the same id.
   - *Invariant:* staging is created with `create_dir` (it must not already exist) and checked to be a directory. Backends never follow symlinks (BUG-119 rule). A push writes only below its own directory.
   - *Test:* make `incoming` a symlink to `/tmp/x` on the SFTP test server; the push fails with a message and nothing is written outside.
7. **A stale journal.** The journal names staged packs that the 7-day cleanup or a hand `rm` removed.
   - *Invariant:* a journal entry counts only after phase B (or a resumed phase A) has seen its `.idx` and checked the `.pack` size.
   - *Test:* delete one staged pack between attempts; the retry re-sends exactly its objects, and the dry-run plan matches.
8. **The fencing window.** Phase B must not publish after its lease lapses.
   - *Invariant:* `ensure_held` runs before the renames and again before `op_head`. The residual window (a stall between the final check and the head write) is today's, but now only a few round trips long.
   - *Test:* `SimClock` suspends the holder after the renames. The push fails, no operation is recorded, the published packs are unreferenced, and the retry succeeds.
9. **Filling the remote's disk with staging.** Anyone with write access already can, so this adds no new authority, but abandoned pushes must not pile up.
   - *Invariant:* staging idle for more than 7 days is removed by phase B and by gc; staging touched in the last 24 hours never is.
   - *Test:* `SimClock`-aged staging directories (8 days, 1 hour, 0); only the first is removed.
10. **Embargo and withheld history between the phases.** A release staged locally during phase A, or an embargo created in another terminal.
    - *Invariant:* the withheld set (`embargo_withheld`) and the objects sent are computed once, from the local view at the start of the push. Releases are published only in phase B (`publish_staged_releases`), as today.
    - *Test:* `push_plan.rs`'s property test, run through the two-phase push with random releases between the phases. Nothing withheld is ever staged.
11. **Metadata read-modify-writes leave the lock.** A revocation racing a push could be lost if `sync_meta` moved into phase A.
    - *Invariant:* every ring, embargo-record and team-vault read-modify-write stays under `.veil/lock`, in phase B.
    - *Test:* `metadata_lock.rs`: a revoke on client 2 during client 1's phase A; after both, the remote ring has the revocation and the grant.
12. **The dry run drifts from the push.** `push_plan::plan_push` must still equal the push.
    - *Invariant:* the union of a push's staged packs equals `Sink::Plan`'s object list, and its tag actions equal the plan's when nobody else pushed.
    - *Test:* in `push_plan.rs`'s property test, compare the plan with the union of the chunk packs.
13. **Format and older clients.**
    - *Invariant:* a format-5 remote with staging opens, verifies and gcs cleanly with this release, and its layout outside `incoming/` is unchanged.
    - *Test:* `format_compat.rs` gains a format-5 remote fixture with an `incoming/` directory: `fsck` reports a note only, and `gc` neither touches nor counts it.
14. **Memory.** The in-memory `PackBuilder` buffer and `Vec` of pending objects go away.
    - *Invariant:* push peak RSS is bounded by the chunk size plus the delta window, not by the push size.
    - *Test:* item 9's gate (peak RSS ≤ 512 MiB pushing the 5 GB profile).
15. **Interaction with hooks.**
    - *Invariant:* `pre-push` hooks (`hooks.rs`) run before phase A, as now.
    - *Test:* the existing hook test: a hook that refuses stops the push before anything is staged (`incoming/` stays empty).

## Open decisions

1. **Resume granularity.**
   - *Recommendation:* 32 MiB chunk packs, with no byte-offset resume. The worst case re-sends 32 MiB, and the format and code stay unchanged.
   - A `.part` file resumed at an offset needs deterministic pack bytes across attempts, which zstd only gives within one library version.
2. **Staging after a rejection.**
   - *Recommendation:* remove it on public remotes, keep it on team remotes (7-day expiry).
3. **`vl -R <remote> gc` holds the lock for its whole run**, so it blocks phase B for minutes.
   - *Recommendation:* item 4's gc lease replaces it for format-6 remotes. On format-5 remotes it keeps the lock (an older client's gc may run at the same time).
4. **Phase B retries.**
   - *Recommendation:* 3, then fail with "the remote changed while pushing; run `vl push` again". The staging is kept, so the next attempt is cheap.
