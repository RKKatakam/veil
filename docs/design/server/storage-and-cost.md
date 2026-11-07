# Storage, database and cost: keeping the server fast and cheap

> **Status: design, approved for the plan by the owner (2026-11-07).** It adds milestones S27–S29 and tightens S4 (`README.md`). It replaces `OVERVIEW.md`'s earlier "no repacking" promise: small objects are packed per push, and a background job merges packs.
>
> **Sources of truth:** `docs/OVERVIEW.md` and `docs/VISIBILITY.md`. Measurements: `docs/design/scale/LOAD.md`, `docs/design/scale/BASELINE.md`.

## 1. Goal

At the owner's scale (thousands of agents, toward 1 million merges a day), the server's cost is set by **request counts**, not bytes:
- storage writes and reads per push and pull;
- database commits and statements per push and pull.

Each of those is also time on the request path. So every item here makes Veil **cheaper and faster** at once. The gates in §9 stop the counts creeping back up.

## 2. Where we start (measured, 2026-11-06)

| | Today | Target |
|---|---|---|
| Storage writes per push | about 6 (one per new object) | **2 or fewer** (one pack, one index): **built** (S28: 1 for a `vl` push, one per 8 MiB upload request; 2 when the server completes the snapshot) |
| Database commits per push (landing) | about 8 | **1** |
| Database statements per pull | about 46 | **a handful**, most answered from memory |
| Landings/s across 100 projects, MinIO | 376 (bound by the object store) | 4,000 (phase 2 gate) |
| Landings/s into one `main` | about 20 | 100 (phase 2), 1,000 (phase 4, by batching) |
| Bytes stored and sent | uncompressed | compressed (zstd): **built in S27** (`HUB.md` §13.15) |
| Server memory, 1 GB project | push 2.4 GB, clone 2.9 GB peak (BUG-864: allocator arenas; fixed with jemalloc, 2026-11-07: push 0.98 GB, clone 1.58 GB, BUG-1000; S27 raised the push to 1.36 GB, BUG-1089) | under 1 GB: **built** (S28: push 0.88 GB, clone 0.94 GB; BUG-1000 and BUG-1089 fixed, `HUB.md` §13.18) |

## 3. One database commit per push (S4)

> **Built** (S4, `HUB.md` §13.14): one commit per landing, measured by `veil-bench load`.

- The push's transaction writes **everything at once:** the snapshot rows, the origin and audit rows, and the one-row compare-and-swap that moves the branch.
- **Per-viewer views are worked out after the commit, in the background** (as S12's deriver already runs after a landing).
  - **Rule:** a reader never receives an unprojected answer. If a view isn't ready yet, the request projects it on demand, exactly as today, and the background job only saves that work.
- `LOAD.md` measured about 8 commits per landing, spent on the database's write-ahead log. One commit is close to Git hosting's ref compare-and-swap.

## 4. Request-path caches (S4)

> **Built** (S4, `HUB.md` §13.14): versioned by access epochs that database triggers bump; every request reads its epochs, so staleness is zero. Tested with two servers on one database.

In each API server's memory, never in the database:
- **sessions:** sign-in token → person and device;
- **permissions:** `(person, project, access epoch)` → groups, admin, view key, readable rules;
- **snapshot resolution:** `(view key, projected id)` → real id;
- **branch tips.**

**Hard rule:** a cache never serves a decision that a permission change has made stale.
- Access changes, group membership, admin changes, device removal (S2's `device_bars`) and sign-out invalidate the cache or version it, **across every server**.
- A removed person's very next request, to any server, is refused.
- This is tested under load with several servers on one database.

## 5. "Nothing changed" without a hot row

> **Built** (S4, `HUB.md` §13.14) with `LISTEN`/`NOTIFY` on PostgreSQL. On YugabyteDB 2025.2 with default flags the server finds notices are not delivered and relies on the 100 ms expiry; the change feed is not used.

- Each server keeps each project's **tips in memory**. Every push tells every server to drop its copy.
- **Not a version counter per project:** one row that every push updates becomes a new hot spot, and database sequences can commit out of order.
- **How servers hear about pushes:**
  - **PostgreSQL:** `LISTEN`/`NOTIFY`.
  - **YugabyteDB:** `LISTEN`/`NOTIFY` is off by default (checked on 2025.2: it needs the runtime flag `ysql_yb_enable_listen_notify` on the master and tablet servers). Enable it in the deployment if it is reliable at load; otherwise use YugabyteDB's change feed (CDC).
  - **Either way, a fallback:** the tip cache also expires after at most **100 ms**, so a missed notice costs one stale read, never a wrong one.
- **Pushes never trust the cache:** a branch move is always the database compare-and-swap.
- A pull may see a tip up to 100 ms old, which `phase-2-thin-clients.md` §5.1 already allows.

## 6. Compressed objects (S27)

> **Built** (2026-11-07): `docs/HUB.md` §13.15 has the design as built, its threat review and the measurements.

- Objects are compressed with **zstd** (level 3) when stored and when sent. A server or cache may also keep them compressed in memory.
- **Object ids stay the hash of the uncompressed bytes,** so content addressing, deduplication and every signature are unchanged. Compression is a storage and transport encoding, recorded per object (one header byte), so old uncompressed objects stay readable.
- **What it buys:** most of the byte gap with Git's deltas. It is cheap in CPU, and faster on real networks.
- **Secrets** are ciphertext and don't compress. They are stored as they are (the encoder keeps whichever is smaller).
- **Deltas** (storing a file as a change against an earlier version) come later, only if large files that are edited often turn out to matter.
- **Transport:** responses carry only what the requester may see, so compression gives nobody a way to guess hidden content (a BREACH-style attack would need the attacker's guess and the hidden data in one compressed response).

## 7. Packs: one storage write per push (S28)

> **Built** (S28, `HUB.md` §13.18), with two changes from the text below: (1) **an upload request's objects, large ones included, go up as one pack** (staged: nobody reads it until the push that names it lists it, and a refused push deletes it, BUG-930), so a `vl` push's uploads cost one write per upload request (about 8 MiB) and the push lists them as they are, with no copy; a large object in a pack is read with one ranged `GET`, as a loose one is read with one `GET`. S29 merges only small packs. (2) The index is inside the pack, at its front (one write, never apart from its pack); the database lists each pack (one row, in the push's transaction).

**Change from the earlier design:** `OVERVIEW.md` said each file is stored once with no repacking. Packs bring back a background job (§8). In exchange, storage write requests per push fall from about 6 to 1–2. At object-storage prices, per-request charges dominate with millions of small files, and the object store is today's limit across projects (376 landings/s on MinIO).

- **What is packed:** a push uploads **one pack** holding its new *small* objects (folder listings, and files under 64 KiB), plus **a small index** of object id → offset and length.
- **What isn't:** large files stay single objects, as today. Most bytes are in large files and most requests in small ones, so this gets most of the gain with little read cost.
- **Where the index lives:** the index object sits beside the pack in storage. Each server keeps the indexes of the packs it has used in memory, and the database records, per project, which packs exist (one row per pack, written in the push's single transaction).
- **Reads:** one object is read out of a pack with a **range request**. The daemon, regional caches and the server's own cache absorb most of these.
- **Permission rule, unchanged and strict:** **a whole pack is never handed to anyone.** A pack can hold files from folders the reader can't see, so the server and the caches serve objects one at a time, after the same per-object checks as today (S5's object routes, grants and chain checks).
- **Existence:** "not found" and "not allowed" stay identical. Pack membership is never revealed.
- **Deduplication:** before uploading, the push asks the server which objects it already has, as today. An object already in an earlier pack isn't packed again.
- **Embargoes and secrets:** unchanged. Withheld history is never uploaded, and secrets are packed only as ciphertext.

## 8. Merging packs (S29)

- Once a project has many small packs, a lookup has to check many indexes. A **background job per project** merges small packs into larger ones when the pack count passes a limit (start at 64), as Git hosting compacts.
- **Garbage collection** uses the same job. Removing an object (gc, or a secret deleted from history by an admin) means rewriting the packs that hold it. A pack is never edited in place: the job writes the new pack and its index, switches the database rows in one transaction, and deletes the old pack only after a grace period, so readers mid-request still find their objects.
- **Crash safety:** a crash at any point leaves either the old packs or the new ones listed, never neither (the same write-then-switch-then-delete order as the client's G2 maintenance).

## 9. Cost gates in every benchmark run (S4, then each milestone)

> **Built** (S4): `veil-bench load --mode branches`, the cost columns, and the gates for commits per landing and statements per up-to-date pull. Storage writes are reported, not gated, until S28. **A pull that brings new snapshots** makes one request per tree level, and each request reads its access epochs (the hard rule of §4), so it costs about one statement per request: about 8 for the load test's agents. Meeting 5 for those pulls needs fewer requests per pull (S3), not a weaker check.

`veil-bench load` gains a mode where **many agents push to their own branches in one project**. It reports, per push and per pull:
- storage writes and reads;
- database commits and statements;
- bytes stored and sent.

**Gates** (a run fails if one is missed):

| Measure | Gate |
|---|---|
| Storage writes per push | 2 or fewer (once S28 is in; 1 per new object before): gated by `veil-bench load` for landings (the deriver's background writes aside, `storage_push_writes_per_op`) |
| Database commits per push | 1 (once S4 is in) |
| Database statements per pull, warm caches | 5 or fewer |
| Server peak memory, 1 GB profile | under 1 GB |

`scripts/bench-server.sh` prints these counts with every profile, so every performance round and every server milestone shows its cost next to its speed.

## 10. Other performance work in the plan

Found by the benchmarks of 2026-11-06. Each is a small fix round, not a milestone:

| Item | What | Where it's tracked |
|---|---|---|
| Server memory arenas | Done: glibc kept one memory arena per thread (2.4 GB push peak). `veil-server` now uses jemalloc with two arenas (push 984 MiB; measurements in `BASELINE.md`, "The server's allocator"). | BUG-864 (fixed) |
| Server memory during a clone | Done (S28): objects read from S3 were cached as slices of the HTTP client's read buffers, each pinning a whole buffer; now copied. The full clone peaks at 0.94 GB. | BUG-1000 (fixed) |
| Push checks one snapshot at a time | Done (S28): up to 8 at once on a guess that a wrong answer undoes. The 1 GB project's first push: 354 → 138 s. | BUG-865 (fixed) |
| Commit one file | Still 3–4× slower than Git: the scan of every file. Use the stat cache to skip unchanged files (performance round 3); the daemon's file watcher (S7) removes the scan entirely. | `OPENSCION.md` |
| Clone one folder | About 60 forced disk writes in sequence. Use one durability barrier, as the full clone already does. | `OPENSCION.md` |
| Merge base of distant branches | 0.7 s at 20,000 snapshots apart. Memoise merge bases, or use a better walk. | S13 |
| One busy `main` | About 20 landings/s. Batch landings. | S17 |

## 11. Open technical questions

1. **Pack size limits:** the size limit for a "small" object (64 KiB proposed) and the maximum pack size. Measure them on the 1 GB profile.
2. **YugabyteDB:** `LISTEN`/`NOTIFY` (preview flag) or the change feed. Decide by a load test of both.
3. **zstd dictionaries per project:** worth it for many tiny files? Measure before adding.
4. **Where pack indexes are cached:** in each API server's memory only, or also in the regional cache. Decide with S9.
