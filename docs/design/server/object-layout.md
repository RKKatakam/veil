# Object layout: one object per key, beside packs

> **Status: design, not built** (2026-11-17, branch `t3/design-object-layout` from `integration` @ `24696b50`). It adds a second way for the server to keep new objects. The owner's decision (2026-11-17): add it as a **server setting** beside packs, **keep the pack code working**, **packs stay the default** until both are benchmarked side by side, and the higher storage-request cost is accepted.
>
> **Sources of truth:** `docs/OVERVIEW.md`, `docs/VISIBILITY.md`. It builds on `storage-and-cost.md` §7–§9 and `docs/HUB.md` §13.15 (S27), §13.20 (S28), §13.37 (S29; with BUG-2602, BUG-2621 and BUG-2622 as on `t3/fable-open-bugs`).
>
> **Numbers:** "measured" names where it was measured. "Estimate" is arithmetic from those, not a run. Nothing was measured for this document.

## 1. Summary

Scion stores each object under its own key: "There is no equivalent of packfiles… so no repository maintenance is needed", and a commit costs what the change costs, not what the repository holds. Veil stored objects that way before S28, and still does for what grants, the deriver and the search index store. Reads already look in listed packs and then under the object's own key.

**The design, in five rules:**

1. **A server setting, `--object-layout packs|objects`, decides only how new objects are kept.** Reads never depend on it: every server looks in listed packs, then under the object's key, as today. Nothing is converted, and servers with different settings can share a database and a store.
2. **In `objects`, everything a push, an API commit or a landing batch keeps is written under its own key, `p/<project>/ab/cdef…`,** after every check has passed and before the transaction that names it.
3. **An upload request is still staged as one container** (today's staged pack, unchanged: same receipts, same row). It is never listed, no read of the project touches it, and it is deleted when its push answers. So only content that passed a push's checks is ever written under a project key, and a refused upload is deleted by the push that refuses it, as today.
4. **No pack is listed, so nothing is merged** and no pack is rewritten for new objects. Existing packs are still read, merged down once, and collected by the pack path.
5. **An object under a project key is deleted only by GC's loose path:** the retention window, the root writers' gate and the epoch (BUG-2621). A writer never checks whether an object is stored before it writes it; it always writes.

Rule 3 is the one place this departs from "no packs on the write path": one pack-format blob per upload request lives for the length of a push. §4 says why, and §10 has the variant without it (it needs scheduled GC first, and keeps a refused plain-text secret in the store for at least the retention window). That choice is the owner's: question 1 of §11.

**Headline cost** (§6): a push to a branch of one's own makes about **10 storage writes in `objects` against 3.0 in `packs`**; at Amazon S3's and Google Cloud Storage's list prices that is about **$50 against $16 per million pushes**. In return the push path has no listing, no lookup map, no merge and no index budget.

## 2. The setting

| | |
|---|---|
| Name | `--object-layout packs\|objects` (and `VEIL_OBJECT_LAYOUT`); `Config::object_layout`. Default **`packs`**. |
| Scope | The server process. A deployment sets it on every server. Not per project: that needs a column, an admin route, a cache and a doubled test matrix, and nothing asks for it. |
| What it governs | How the objects a push, an API commit and a landing batch **keep** are written, and so whether pushes list packs. Nothing else. |
| What it never governs | Reads, permissions, receipts, the wire, `vl`, the database schema, GC's rules. |
| Switching | Change the flag and restart, one server at a time. Objects already written stay where they are. No migration, no conversion job, no tool. Switching back is the same. |
| Mixed deployments | Allowed: a `packs` server and an `objects` server on one database and store each read what the other wrote, since every server since S28 reads both. One rule: **GC runs only from a server that has BUG-2621's fix** (loose deletes under the gate); with every new object loose, deleting them outside the gate is no longer a rare case. |
| Shown | `stats.json` (the `SIGUSR1` counters): `"object_layout"`, plus new counters `storage_deletes`, `storage_lists` and `objects_kept`. The start-up line names it. `veil-bench` reads it from `stats.json` and prints it with every result. Per-project health (`GET …/health`) does not change: the layout is not a project's. |

**Why reads always look in both.** It is the code as it is (`Objects::load_encoding`: listed packs this server knows, then the object's key, then the listing again after a miss). A project with no listed pack answers the first step from memory, so an `objects` read is one `GET` by key. Making reads depend on the setting would add a way to answer "missing" for a stored object and gain nothing.

## 3. The write path in `objects`

| Step | `packs` (today) | `objects` |
|---|---|---|
| `POST …/objects` | Checks each frame; records a staged row; writes one staged pack; answers receipts `MAC(project ‖ person ‖ id ‖ pack) ‖ "." ‖ pack`. | **The same, unchanged.** The pack is the upload's staging container. |
| Push: checks | Reads staged objects from their pack only (`get_staged`), never from the project's store (BUG-1155). | The same. |
| Push: what it keeps | Lists a staged pack as it is when its checks read all of it; copies the rest and what the server made into one pack of its own (a row, a commit, a write). | **Writes each object its checks read, and each object the server made, under its key** (at most `PUTS_AT_ONCE`, 64, at once; every write answered before the transaction begins). No pack of its own, no row for it. |
| Push: transaction | Lists the packs (`state = listed`) in its merged statement. | The same statement marks the push's containers **discarded** (`discarded_at` set). One statement fewer than today in all (no own-pack row). |
| After the commit | Enters the packs in the lookup map; may schedule a merge. | Deletes the containers from the store, then their rows. Nothing to enter, nothing to schedule. |
| Refused by its checks | Discards its staged packs and its own pack. | Discards its containers. **Nothing was written under a project key:** the writes come after the checks. |
| Lost a race before its transaction | Nothing written; uploads stay staged for the retry (BUG-1157). | The same. |
| Lost a race in its transaction (409), or a crash between the writes and the commit | Its own pack is discarded. | The objects it wrote stay under their keys, unreferenced: content that passed every check, which the retry mostly names again. GC collects what nothing names (§3.2). The containers stay staged for the retry. |
| An upload no push follows | Swept after `staged_grace_ms` (1 h). | The same (`sweep_staged`). |
| API commit, landing batch | A pack its transaction lists (BUG-1948, BUG-1955, on `t3/fable-speed`). | Stored under their keys before the transaction, as on `integration` today (`sync::put_all`). |
| Deriver, grants, search index, projections | Under their keys. | The same. |

**Large files, chunking, compression: unchanged.** Each object is stored as its S27 encoding (compressed when smaller, the server's own encoding, BUG-1008), one object per key, at most `MAX_FRAME_OBJECT` (1 GiB). A plain object is read by range, a compressed one decoded whole. The one new cost: a large file's bytes are written twice (the container, then its key). §10 has the follow-up if that shows in the 1 GB profile.

### 3.1 Receipts

Unchanged: `MAC(project ‖ person ‖ id ‖ "staged in" ‖ container) ‖ "." ‖ container`. An object counts as uploaded only if its receipt's container holds it and that container is the pusher's and not discarded.

**A receipt without a container name would be a leak.** `MAC(project ‖ person ‖ id)` proves the person once had the bytes. It does not say where they are now, so the push would have to read the object from the project's store. A person could upload a guess of a hidden file's content, wait for GC to collect the upload, and push with the old receipt: the push succeeds only if someone else's history still names that content (BUG-1155's class). Any design that stores uploads under project keys therefore still needs a record of each upload (who, when, which ids) that receipts name and GC treats as a root: the same row, with the staging gone.

### 3.2 Unreferenced objects, and why nothing reachable is deleted

What can sit under a project key with nothing naming it: what a push or a batch wrote before a transaction that did not commit; what force-pushes, deleted branches and superseded derived data left (as today). All of it passed some writer's checks. None of it is served: every route reaches an object from a root.

It is removed by `mark_and_sweep_loose` as built on `t3/fable-open-bugs`, with no new rule:

- **Found** by listing `p/<project>/` and marking from every root (branches, hidden embargo lines, tags, PRs, the landing queue, attempts, CI results, change refs, memos, derived objects, and every staged upload's objects).
- **Kept for the retention window** (`unreferenced_objects.since_ms`, 1 hour by default) from when a pass first saw it unreferenced. An object written and committed between two passes is never a candidate; one written just before a pass is marked, found reachable by the next pass, and cleared.
- **Deleted in chunks of 256 under the root writers' gate**, the roots read again first, the epoch raised before the first delete and after the last (BUG-2621).

**The three facts durability rests on:**

1. A writer reads the GC epoch before it writes or checks anything, and its transaction's first statement compares it (`guard_root_write`). The push already does both (`push_gc_epoch` at the start of `push_staged`).
2. **A writer always writes each object it keeps; it never asks first whether the object is stored.** So an object GC is about to delete is either written again after the delete, or the writer's epoch is stale.
3. On a stale epoch **the whole request runs again** (`GcEpochChanged`, `db::retry_requests`), writes included. The transaction alone can never pass: its guard compares with the epoch the request read at its start.

Fact 3 holds today for API commits and landing batches, which already store before their transactions. The push joins them; a test pins it (§8, test 7).

**GC is still only run directly** (§13.37: "not built: scheduling"). In `packs` a lost transaction's pack is discarded at once; in `objects` its objects wait for a GC pass. Scheduled GC should come before the default switches (§7, §11 question 5).

## 4. Why uploads keep a staging container

The brief for this design asked for uploads stored under their keys, receipts without a pack name, and unreferenced uploads left to GC. That is variant B of §10. It was weighed and is not recommended, for three reasons that all come from one fact: **a content-addressed key is shared, so deleting under it needs the whole project's roots.**

| | Staging container (recommended) | Uploads straight to their keys (variant B) |
|---|---|---|
| A refused plain-text secret | Deleted by the push that refuses it (BUG-930), as today. | Stays under a project key until a GC pass after the retention window: at least an hour, and until someone runs GC. Against "secrets are only ever stored encrypted". The refusing push cannot delete it safely: another push may have landed the same bytes meanwhile. |
| What sits under project keys | Only content that passed a push's checks. | Whatever anyone with write access to any folder uploaded. |
| Receipts | Unchanged. | Need an upload ledger and an expiry (§3.1). |
| Storage writes a push | 1 + objects kept | objects uploaded + objects the server made |
| New code | The keep step of three writers. | Upload, receipts, staging reads, sweep, GC roots. |

The container costs one write, one delete, one row and one commit per upload request, whatever the repository holds. An API commit already works exactly this way on `integration` (staged upload, checks, objects stored under their keys, staged pack discarded), so the push adopts a path that is built, reviewed and tested.

## 5. Pack machinery, permissions and secrecy

### 5.1 Packs in `objects`

| Machinery | In `objects` |
|---|---|
| Background merges (BUG-2230, BUG-2462) | A push lists no pack, so `maybe_schedule` is never called by one. **Leftover packs are merged down once:** when a server loads a project's listing and finds `MERGE_MIN_PACKS` (64) small packs or more, it schedules the existing merge. With nothing new listed it ends, and never runs again. |
| Lookup maps, index budget (`Packs`, 128 MiB; `INDEXES_HELD`) | Hold only packs listed before the switch. A project created in `objects` has none: no walk, no paging, no `IndexesFull`. |
| Sweeps (`sweep_staged`, `sweep_discarded`, the 10-minute `sweep_scan`) | Unchanged. They take what a failed delete or a stopped server left of the containers. |
| Pack GC (`compact_batch`) | Runs only on packs that exist. New objects are never in one. |
| Loose GC (`mark_and_sweep_loose`) | The collector for every new object (§3.2). |
| `packs` table | Staged and discarded rows only (containers). No listed row is added. |

### 5.2 Permissions and secrecy: unchanged, and why

The trust boundary is `ARCHITECTURE.md`'s: participants, readers without access, and people racing them are outside; the server, its database and its store are trusted with code, never with a secret's plaintext.

| # | Threat | Why it does not arise in `objects` | Test (§8) |
|---|---|---|---|
| 1 | A reader receives an object of a folder they cannot see | Every route reads one object through `Objects` after the same path or grant check. The layout is below that check. | 8, and `grants`, `leaks`, `cache` run in `objects` |
| 2 | "Not found" and "not allowed" differ | The answer is made before the store is asked; a stored, unreferenced object gets the answer a random id gets. | 8 |
| 3 | Keys or listings leak a private object's id or existence | Keys are `p/<project>/<hash>`, as loose objects have today. No route lists keys; only the server holds the store's credentials. | — (no new surface) |
| 4 | Timing shows whether hidden content is already stored | **The always-write rule (§3.2, fact 2):** a push makes the same requests whether or not the project held the object. A "skip the write if it exists" optimisation would be this leak, and is ruled out. Uploads answer receipts either way, as today. | 1 |
| 5 | A push names hidden content it did not upload | "Known" is still: the pusher's receipt, or the entry at that path in a parent. The project's store is never asked. | `packs::bug_1155_…` in `objects` |
| 6 | A refused plain-text secret stays stored | It was never written under a project key; its container is discarded by the refusing push. | 2 |
| 7 | Embargoed content leaves early, or is collected early | Hidden lines are roots for GC, as today. Release moves no object. Withheld history is never sent. | `embargo` in `objects`; GC guarantee 3's twin |
| 8 | A sealed secret is stored or served differently | It is one more object: ciphertext under its key. The server never opens it. | `leaks`, `secrets2` in `objects` |
| 9 | GC deletes a reachable object | §3.2. | 7, 10 |
| 10 | One writer makes the server issue very many storage requests | New in size: a push now costs one write per object it keeps, so a writer who may write some folder can cost the store's owner up to the object count of each upload (bounded by the body limit, and by S24's rates). Follow-up, small: S24 counts objects kept per device. | — (follow-up) |

## 6. Cost model

**Prices used** (list prices, 2026-11; check before relying on them): Amazon S3 Standard: `PUT`/`COPY`/`POST`/`LIST` $0.005 per 1,000, `GET` $0.0004 per 1,000, `DELETE` free. Google Cloud Storage Standard: Class A (writes, lists) $0.005 per 1,000 in one region ($0.010 dual- or multi-region), Class B (reads) $0.0004 per 1,000, deletes free. DigitalOcean Spaces: no charge per request; **800 operations a second per bucket**, all kinds together, `503 Slow Down` beyond.

**Where the `objects` column comes from.** No server has run in `objects`. Its writes are the measured count from when every object was stored under its own key (`integration` @ `6fa552c4`, before S28: **9.0 storage writes per landing** in the own-branch load, the deriver's 1 included; `HUB.md` §13.20 "Measured"), plus the container.

### 6.1 Per operation

| Per push to a branch of one's own (`veil-bench load --mode branches`) | `packs` | `objects` |
|---|---:|---:|
| Storage writes, the push's own | 2.0 (measured: the upload's pack, its own pack) | about 9 (estimate: 1 container + about 8 objects) |
| Storage writes, all (with the deriver's 1) | 3.0 (measured) | about 10 (estimate) |
| Storage deletes | about 2 (estimate: the packs a merge replaced) | 1 (the container) |
| Storage reads | 0 for the push; about 2 to 4 for merges (4 a push measured in `readsperf`, before a merge read a small pack in one request) | 0 |
| All storage requests | about 7 to 9 | about 11 |
| Database statements, the push request | 13 (measured, BUG-2440) | 12 (no own-pack row) |
| Database commits before the push answers | about 3 (the push's 1, staged rows 2.04; measured) | 2 (the push's, the container's row) |
| `packs` rows | 2 listed rows that live until merged, then 60 s discarded | 1 row, discarded in the push's transaction, deleted after |

| Other operations | `packs` | `objects` |
|---|---|---|
| Push in the many-branch headline (landing every 5th push; landings, fills and the deriver included) | 11.0 writes, 5.9 to 8.6 reads (measured, `finalbench3`, `readsperf`). Lower once BUG-1955 and BUG-1948 merge (a batch and an API commit become one write each; not yet measured). | about 18 writes (estimate: 11.0 − 2.0 + 9), the same reads |
| Landing batch at the one-`main` gate | 1 write (BUG-1955, on `t3/fable-speed`) | one write per object the batch makes: **some 600 a batch** (BUG-1955's count) |
| First push of the 1 GB profile (10,022 snapshots, 327,017 objects) | 110 writes (measured) | about 327,000 writes + 110 containers; $1.64 on S3 |
| Full clone of it, server cache cold | index reads and ranged reads of neighbours, at most 2 MiB each: in the order of 1,000 requests (estimate) | 327,017 reads; $0.13 on S3 |
| The same, measured as time with every object loose (`6fa552c4`) and packed (S28) | full clone 59.8 s; one directory 8.0 s | full clone 68.5 s; one directory 4.7 s |
| Pull, on the server that took the push | 0 reads (measured: 99 % object cache hits) | 0 reads (a kept object enters the cache when written) |
| Pull of one push, on another server | 2 to 4 reads (each new pack's index, then a range) | about 8 reads (one per object) |
| GC pass | 1 index read per listed pack; the walk's reads; 1 read and 1 write per pack rewritten; the prefix listed | ⌈objects ÷ 1,000⌉ listings (328 for the 1 GB profile, $0.002; 100,000 for 100 million objects, $0.50); the walk's reads, one per tree or snapshot not cached; 1 delete per dead object, in chunks of 256 under the gate |

### 6.2 At rates

| | `packs` | `objects` |
|---|---:|---:|
| **Per million own-branch pushes**, S3 or Cloud Storage (one region) | about $16 | about $50 |
| the same, Cloud Storage dual- or multi-region | about $32 | about $100 |
| the same, Spaces | $0 | $0 |
| **Per million headline pushes**, S3 | about $58 | about $93 |
| **One busy repository, 2,600 pushes a second** (the rate measured in `packs`, MinIO on a RAM disk: a diagnosis, not a durable number): storage writes a second | 7,800 | about 26,000 |
| all storage requests a second | about 18,000 to 23,000 | about 28,600 |
| request charges a day, S3 | about $3,600 | about $11,200 |
| request charges a month, if held all month (6.7 billion pushes) | about $110,000 | about $337,000 |
| **1 million pushes a day**: request charges a month, S3 | about $490 | about $1,500 |
| **Headline at 250 pushes a second**: storage requests a second | 4,900 (measured, `DEPLOY.md` §2.3) | about 6,900 (estimate) |

**Spaces.** One bucket's 800 operations a second holds about 40 headline pushes a second in `packs` (`DEPLOY.md` §2.3) and about 29 in `objects`; own-branch pushes, about 90 to 115 against about 70. So `objects` lowers a Spaces deployment's ceiling by roughly a third, and costs nothing more in charges. The one-busy-repository rate needs 23 to 29 buckets' worth of operations in `packs` and 36 in `objects`: not a Spaces workload either way. The speed runs stay on MinIO or a hyperscaler's store, as decided for BUG-2290.

**S3 request limits per prefix.** S3 gives at least 3,500 writes and 5,500 reads a second per partitioned prefix, partitions by key prefix on its own under sustained load, and answers `503` while it does.

- `p/<project>/ab/cdef…` puts 256 evenly loaded prefixes under each project (the id is a BLAKE3 hash), and S3 may split inside them too. That is enough: 256 × 3,500 is 896,000 writes a second for one project. **No key change is proposed.**
- What the keys cannot do is skip the warm-up. A project that turns busy on one partition holds about 350 pushes a second in `objects` (10 writes each) against about 1,150 in `packs`, until S3 has split it; 2,600 pushes a second needs 8 partitions against 3. Meanwhile the store answers `503`, the server retries each request for up to 10 s (`S3_RETRY_FOR`) and then fails it; both are counted (`s3_slow_down`, `s3_gave_up`).
- Containers stay at `p/<project>/pack/<random name>`: one prefix that takes a write and a delete per push, splittable the same way.
- Cloud Storage scales a bucket on its own too; Google's guideline is to start near 1,000 writes and 5,000 reads a second and at most double every 20 minutes (from its request-rate guidance; check it before a run). The same warm-up, three times sooner in `objects`.

**The local benchmark machine measures its drive, not the layout.** With PostgreSQL and MinIO on one NVMe drive, about 2,840 flushes a second is the limit (`LOAD.md`, "One busy repository", item 5): 2.4 flushes a push in `packs`, about 11 or 12 in `objects` (estimate). So on this machine `objects` would hold a few hundred durable pushes a second where `packs` holds about 1,400: the 376 landings a second measured before S28, "bound by the object store", was this limit. §8.3 says how the comparison deals with it.

## 7. Scaling with the change

**Per push and per landing, `objects` costs nothing that depends on what the repository already holds:**

| Step | Cost in `objects` | Depends on |
|---|---|---|
| Upload | decode and check each frame; 1 row; 1 write | the objects uploaded |
| Checks | read the changed paths' trees and the parents' entries there | the change, times the depth of its paths |
| Keep | 1 write per object kept | the change |
| Transaction | the branch's compare-and-swap, the change's rows, the containers' rows | the change |
| After | 1 delete, 1 row delete | the upload requests |
| A read, later | 1 `GET` by key | nothing: no index to walk, load or page |
| Landing batch | 1 write per object it makes; one transaction | the batch |

In `packs` the same steps also touch state that grows with the project's pushes and is kept bounded only by a job that must keep up: each lookup walks the project's listed packs newest first, each push lists two more, and their indexes share one memory budget (BUG-2461, BUG-2462: 147,000 packs in a minute and a half before merges kept up). That job and that state are what `objects` removes.

**What still grows with the repository, in `objects`:**

| What | Grows with | Follow-up |
|---|---|---|
| A GC pass: the listing, the walk from every root, the set of stored ids in memory (about 50 bytes an object) | every object and every root | **Schedule GC** (not built in either layout), then **collect by shard**: one `ab/` prefix a pass (256 shards), which bounds a pass's listing, memory and time under the gate. A full cycle still reads every key; collecting only what a dropped root reached is a design of its own. |
| GC's deletes: one request per dead object, 256 a hold of the root writers' gate, with no time bound on a hung delete (BUG-2624, accepted) | the garbage; in `objects` all of it is loose | Delete a chunk in one request where the store has a multi-object delete. Measure push p99 during a pass (§8.3). |
| The deriver: one run per project at a time | pushes per second to one project | none new (BUG-2480 fixed its lag; the same in both layouts) |
| The branch's tip row: one compare-and-swap row per branch | landings on one branch | none new: batching (S17) |
| The GC epoch row and the root writers' gate: every root writer of a project takes both shared | writers per second to one project | none new; the same in both layouts |
| A cold clone: one read per object | the objects cloned | the daemon and regional caches absorb it, as designed; a clone-time batch read is not possible by key |
| Leftover packs from before a switch | nothing: they only shrink | merged once (§5.1) |

## 8. Tests and benchmarks

### 8.1 The server tests, without doubling `verify-server.sh`

- **How a test picks the layout.** `support.rs` builds `Config::object_layout` from `VEIL_TEST_OBJECT_LAYOUT` (default `packs`). A test whose assertions are about packs (one storage write a push, listed packs, merges) **pins `packs`** when it starts its server; the new tests below **pin `objects`**. No assertion is put behind an `if layout`.
- **One new step, PostgreSQL only: `objects-postgres`.** It runs, with `VEIL_TEST_OBJECT_LAYOUT=objects`, the modules where the layout can matter: `sync`, `packs`, `pack_gc`, `grants`, `leaks`, `changes`, `commits`, `embargo`, `embargo_prs`, `cache`, `thin`, `branch_landing`, `landing_hold`, `rv_core2`, and the new `object_layout`. By `TEST-SPEED.md` §1.4's per-module times that is about 2,000 to 2,400 of the suite's 9,137 test-seconds: **about 2 minutes** beside the suite's 6.6, on a run of 35.5.
- **Not in that step:** `landing` whole (1,885 test-seconds, its slowest tests in memory or about walk budgets), and every module that never stores an object.
- **YugabyteDB:** the same modules run in `objects` only when `store.rs`, `sync.rs`, `pack_gc.rs`, `changes.rs` or `landing/service.rs` changed (the trigger the hostile sets use). `objects` adds no table and one changed value in one statement.
- **Once, before the default could switch:** all of `server_hub` in `objects` on both databases, and the hostile sets, in a turn of their own under the heavy lock.
- If `TEST-SPEED.md`'s tiers are built first, `objects-postgres` joins tier 2.

**New tests** (`server_hub::object_layout`, each asserting first that its push, commit or pass succeeded, or was refused exactly as expected):

| # | Guarantee |
|---|---|
| 1 | A push keeps each object under its key, lists no pack, and its container is gone (row and storage). Its storage writes are exactly 1 + the objects kept, the same whether or not the project already held them. |
| 2 | A push refused for a plain-text secret, or a path the pusher may not write, leaves nothing under any project key, and its container is deleted (BUG-930's twin). |
| 3 | An upload a landing push names and never reads is not kept (threat 7 of §13.20). |
| 4 | Receipts hold only for their person and their container; a discarded container's receipt is worth nothing (BUG-1155's twin, a push and an API commit). |
| 5 | A push that lost a race pushes again with the same receipts and no new upload (BUG-1157's twin). |
| 6 | Two servers on one database and store, one `packs`, one `objects`: each reads what the other pushed, on every read (`get`, `get_many`, `get_range`, `fetch`), and after each restarts with the other setting. |
| 7 | A push whose object GC deletes between its write and its commit runs again and stores it again; the landed tip reads whole (the push's twin of BUG-2621's test). |
| 8 | Object routes over loose objects serve only what a grant reaches; a stored, unreferenced object, a hidden reachable one and a random id get byte-identical answers. |
| 9 | A landing batch keeps its objects under their keys; a batch that does not commit leaves only unreferenced objects, which a pass collects after the retention window. |
| 10 | A server stopped between a push's writes and its commit: after a restart nothing reachable is missing, the container is still staged for the retry, and a pass collects the rest after the window. An embargo's hidden line is never collected. |
| 11 | Pushes schedule no merge and list no pack; a project with leftover small packs is merged down once and every object still reads on two servers. `stats.json` names the layout. |

### 8.2 `veil-bench`

- Reads `object_layout` from the server's `stats.json`, prints it in every result and table, and refuses to compare two results of different layouts as a regression.
- **The storage gate, per layout.** `packs`: 2 writes a push, as today. `objects`: **the push's own writes are at most its upload requests plus the objects it kept** (`storage_own_writes ≤ uploads + objects_kept`): no object written twice, nothing written but objects and containers. The other gates (1 commit a push, statements a pull, peak memory under 1 GB) are the same in both.
- New columns: storage deletes and listings per push.
- `scripts/bench-server.sh` passes `--object-layout` from `OBJECT_LAYOUT` (default `packs`).

### 8.3 The side-by-side benchmark that decides the default

Each shape below, in each layout, **twice**, back to back, one run at a time under the heavy lock (`bench-quiet.sh`), same build, same harness. About 2.5 hours of lock time in all.

| Shape | Command (as in `LOAD.md`) | What it shows |
|---|---|---|
| 1 GB profile | `bench-server.sh 1g` | first push, clones, **the memory gate** (the push now reads its containers and writes 327,000 objects) |
| One busy repository | `--mode branches --projects 1 --rates max`, 1,000 agents | the push path at its limit; no listing or merge in `objects` |
| Many branches (the headline) | the same with `--merge-every 5`, 300 agents, 10 minutes | landings, fills and the deriver beside pushes; stability over minutes |
| One `main`, 1,000 landings a second (G4) | the G4 command | a batch's writes: some 600 against 1 |
| 100 projects | `--mode branches --projects 100` | many small projects |
| A GC pass under load | the headline shape with a `run_gc` pass over 100,000 unreferenced objects started mid-run | push p99 while chunks hold the gate |

**Compared per shape:** pushes (or landings) a second; p50 and p99; server and database CPU per operation; statements and commits per operation; storage writes, reads, deletes and listings per operation; peak memory; errors, `busy` answers, `s3_slow_down`; and, over the 10-minute runs, whether latency or memory climbs.

**The store.** On one drive the write-bound shapes are decided by the drive (§6.2), so local runs report two stores: MinIO on the shared drive (durable; the number that could be published) and MinIO on a RAM disk (a diagnosis that shows the layouts' own difference). The deciding comparison should run on a real object store, where a write is a request and not a flush: a paid run, which needs the owner's approval (§11, question 2).

**The rule proposed for "as fast and stable"** (the owner's to set, question 3): `objects` becomes the default only if, on the deciding store and in every shape, its throughput is within 5 % of `packs` (or the two runs' own spread, if larger), its p99 within 10 %, no gate is missed that `packs` meets, no error appears that `packs` does not show, and nothing climbs over 10 minutes; and scheduled GC is built.

## 9. Implementation plan

**Wait for both in-flight branches to merge first.** `t3/fable-speed` is editing every site this design changes (`sync.rs` `packs_to_list`, `changes.rs` `store_packed`, `landing/service.rs` `store`). `t3/fable-open-bugs` carries BUG-2621's gate, which `objects` relies on for every delete: on `integration` today loose objects are still deleted outside it.

| # | Step | Files | Size | Can start |
|---|---|---|---:|---|
| 1 | The setting, shown: `ObjectLayout`, `Config::object_layout`, the flag and variable, `stats.json`, the start-up line; counters for deletes, listings, objects kept | `lib.rs`, `main.rs`, `store.rs` | about 120 lines | now (one-line conflict with `t3/fable-speed` in `main.rs`) |
| 2 | One keep step, `Objects::keep`: a pack to list in `packs`; in `objects`, each object written under its key, a bounded number at once, always written, bytes in flight held under `DECODED_IN_FLIGHT` | `store.rs` | about 150 | after both merge |
| 3 | The three writers call it: the push (reads what it keeps from its containers, whole when small; marks them discarded in its transaction's statement; deletes them and their rows after the commit), the API commit, the landing batch | `sync.rs`, `changes.rs`, `landing/service.rs`, `pack.rs` | about 200 | after both merge |
| 4 | Leftover packs merged once: schedule the existing merge when a loaded listing has 64 small packs | `pack_gc.rs`, `pack.rs` | about 60 | after `t3/fable-open-bugs` |
| 5 | Tests: the layout in `support.rs`; pack-fact tests pinned to `packs`; `server_hub::object_layout` (11 tests); unit tests; the `objects-postgres` step | `tests/server_hub/*`, `store.rs`, `scripts/verify-server.sh` | about 1,100 | with 2 to 4 |
| 6 | `veil-bench`: the layout read and printed, the gate per layout, new columns; `bench-server.sh` passes it | `crates/veil-bench/src/load.rs`, `main.rs`, `scripts/bench-server.sh` | about 150 | now |
| 7 | `HUB.md` (a section, as built), `storage-and-cost.md` §7 and §9, `DEPLOY.md` | docs | — | with 5 |
| 8 | Review at the high-risk tier (`store.rs` and `sync.rs`: durability and secrecy), the hostile sets, `verify-server.sh` | — | — | after 5 |
| 9 | The side-by-side runs (§8.3), written up in `LOAD.md`; the decision | — | about 2.5 h of lock time, plus a paid run if approved | after 8 |

About 530 lines of server code, 1,100 of tests, 150 in the benchmark tool. No migration, no wire change, nothing in `vl` or `veil-core`.

**Risks.**

| Risk | What limits it |
|---|---|
| A reachable object lost to GC between a writer's write and its commit | §3.2's three facts; test 7; the review |
| The 1 GB push's memory: it now holds bytes it reads from containers and writes again | one container at a time, shares of `DECODED_IN_FLIGHT`; the memory gate in §8.3 |
| A landing batch's some 600 writes against the landing's 1 s store bound (BUG-1982) | measured by G4 in §8.3; it may simply be the cost of the layout, in which case G4 decides for `packs` |
| Local numbers say "four times slower" because of the drive | two stores reported; decide on a real object store |
| A project that turns busy meets S3's or Cloud Storage's warm-up three times sooner | counted (`s3_slow_down`, `s3_gave_up`); `DEPLOY.md` says so |
| Garbage from lost transactions waits for a GC nobody schedules | scheduled GC before the default switches |
| A writer multiplies storage requests (threat 10) | S24 counts objects kept (follow-up) |
| Two layouts to keep working | the `objects-postgres` step; one seam (`Objects::keep`) |

## 10. Alternatives

| Alternative | What it is | Why not |
|---|---|---|
| **B. Uploads straight to their keys** (the brief's sketch) | `POST …/objects` writes each object under its key; no container; unreferenced uploads left to GC | §4: a refused plain-text secret stays stored until GC, anything uploaded sits under project keys, receipts need a ledger and an expiry anyway. It saves one write a push. Possible later, **after** scheduled GC exists, if the container shows in the benchmark. |
| **C. One staging key per uploaded object** (`p/<project>/up/<upload>/<id>`, copied to its key when the push lands) | Literally no pack format on the write path, with staging kept | Two writes and a delete per object where the container costs one write and one delete per request. Same guarantees as the recommendation, at about twice its cost. |
| **Packs, a database index of objects, no merging** | A row per object (id → pack, offset); lookups by the index, so small packs never need merging | Moves the cost to the database, the resource the server design has been unloading (one commit a push, a handful of statements a pull): about 8 more rows in every push's transaction, a table of one row per object ever stored, a statement behind every uncached read. Dead objects still need packs rewritten. It is the opposite of the trade the owner chose. |
| **Tiny objects as database rows, written in the push's transaction** | Small objects live in a table; large ones in the store | **Its attraction is real:** objects and the push commit together, so there is no staged upload to clean up, no orphan, and no gap for GC to race. But objects arrive in an upload request before the push, so they must wait somewhere or the wire changes; every byte goes through the write-ahead log and replication (about 20 MB a second at the one-busy-repository rate); reads become statements; database storage costs several times object storage; and a size threshold makes it a third layout to test. Worth revisiting only if staging proves to be what holds `objects` back. |
| **A setting per project** | A column and an admin route | More surface, a doubled matrix, no need yet (§2). |
| **Skip the write when the object is already stored** | A `HEAD` or a conditional `PUT` first | A timing leak of hidden content (§5.2, threat 4), and it breaks fact 2 of §3.2. |

**Follow-ups this design leaves** (none needed for the setting): scheduled GC; GC by shard; multi-object deletes; S24 counting objects kept; copying a large object from its container inside the store (a ranged server-side copy) instead of writing its bytes twice.

## 11. Open questions for the owner

1. **The staging container.** Recommended: keep it (§4). The alternative with no pack-format blob at all on the write path is variant B, which keeps a refused plain-text secret in the store for at least the retention window and needs scheduled GC first. Is the container acceptable under "no packs on the write path"?
2. **Where the deciding benchmark runs.** Local runs are bound by one drive's flushes and will show `objects` about four times slower on write-bound shapes (an estimate, §6.2) whatever its code does. A run on a real object store is a paid action (about the size of the earlier Google Cloud runs). Approve one, or decide on local numbers with that caveat?
3. **What "as fast and stable" means in numbers.** §8.3 proposes within 5 % on throughput and 10 % on p99, no gate newly missed, no new error, nothing climbing over 10 minutes.
4. **Landing batches.** In `objects` a batch at the one-`main` gate makes some 600 writes where BUG-1955 makes it 1. That is inside "accept the higher storage-request cost" as written; confirm it covers the landing path, or should batches stay packed in both layouts (a mixed layout, more code, not recommended)?
5. **Scheduled GC as a condition.** Proposed: not needed to build and benchmark the setting, required before `objects` becomes the default.
