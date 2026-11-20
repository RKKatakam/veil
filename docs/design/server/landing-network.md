# Landing on networked machines: where a batch's time goes

> **Status: measured and built** (2026-11-20, branch `t3/landing-rtt-1`,
> from `integration` @ `da8ab108`). The question: how much of a landing
> batch's time on the cloud run was accidental waiting on the network
> (database round trips one after another, object-store requests one after
> another, stages that could overlap and do not), and how much real work.
> The accidental part is removed; every guarantee of the landing service is
> unchanged (§5).

## 1. The cloud's numbers

The cloud's second run (PostgreSQL deployment; three e2-standard-32
servers, the database and MinIO each on a machine of its own), `landing`
gate: one `main`, 10,000 agents of 100 people offered 1,000 landings a
second. On the lease's holder (hub1), the gate's own batches (its counters
less the earlier gates'):

| | batches | landings a batch | prepare | build (read ahead / projections / apply) | commit | store | landings/s |
|---|---:|---:|---:|---:|---:|---:|---:|
| cloud, hub1 | 5,607 | 63.6 | 174 ms | 157 ms (42 / 90 / 9) | 165 ms | 181 ms | 170–180 |

The service's loop chooses a batch, prepares it, builds it, then waits for
the batch before it to commit and hands this one to a commit task: the
pace is ready + prepare + build, or the commit when that is longer.
174 + 157 ms a batch of 63.6 is 190 landings a second, what the gate
measured; the commit (165 ms, the store's 181 ms inside it) ran beside it.

**Not hundreds of statements.** The orchestrator's guess was hundreds of
database statements a batch. The service makes about 27 round trips a
batch (§3), whatever its size: the transaction's writes are `unnest`
statements already. The time was in object-store reads one after another.

## 2. The rig: the rehearsal with a network in it

`deploy/compose/rehearsal.sh` takes `LATENCY_MS=…` (default 0, unchanged):
everything the database (or each YugabyteDB node) and MinIO send waits
that long, so every round trip from a server to them takes that much more.
`tc netem` runs in a helper container with `NET_ADMIN` in each one's
network namespace (built from the pinned Debian base with iproute2,
`versions.env` `NETEM_BASE`): no root on the host. The run prints hub1's
TCP connect time to each. The cloud's logs do not show its round trip;
0.5 ms (one Google Cloud zone) is used. With `DB=pg` each gate's
statements are counted from zero (`pg_stat_statements_reset` in the run's
own database) and kept as its `pg-stat-statements.txt`.

The landing check: one project, `--mode landing`, 3,000 agents of 100
people offering 1,000 landings a second, 2 servers, 60 s, PostgreSQL;
each server a 64-connection pool (the cloud's), MinIO with 4 GB of memory
(`MINIO_MEM=4g`, `HUB_MEM=2g`; at the rehearsal's default 512 MB MinIO sat
at its memory limit and 860% CPU, and every store read took several
milliseconds whatever the delay). One run at a time under the machine's
lock. Four counters were added to `stats.json` (relaxed atomic adds, kept):
`landing_ready_us` (choosing the batch), `landing_wait_us` (the loop
waiting for the batch before it to commit), `landing_tx_us` (the
transaction, every run of it), `landing_store_wait_us` (the transaction
waiting for the batch's objects to be stored). Sub-step timers, per-thread
store-miss counts and per-thread CPU time (`/proc/thread-self/schedstat`)
were in measuring builds only, never committed.

## 3. Where the time went (before)

Database round trips a batch, from `pg_stat_statements` (the service's own
statements; the same at 0 and 0.5 ms):

| Stage | Round trips | What |
|---|---:|---|
| ready | 2 (+2 every 5 s) | the merges reclaimed; the ready rows (`pick_batch`, one statement); retention's two deletes every 5 s |
| prepare | 6 | the access epochs; the review context's tip; the queued reverts; whether a change was reverted twice; the memos; the stack changes already landed |
| build | 1 | the default branch's tip |
| commit, before the transaction | 1 | the authors, in one statement |
| the transaction | 15 | BEGIN, the lease (fencing), the branch's compare-and-swap, the review gate, the rules read and recorded, the project epoch, whether a change was reverted twice, the queue rows, snapshots, landings, `landed_from`, `landed_changes`, projections, the audit row, COMMIT |
| after | 1 | the tips notice |

About 9 of them are on the loop's path (4.5 ms at 0.5 ms), 17 in the
commit. Neither is where the time went.

Object-store requests, and what waited on them (measuring builds, 0.5 ms):

- **prepare read the batch's stack snapshots one after another** on one
  thread: 35–41 reads a batch the server's memory missed (the submits the
  other server took), 59–86 ms of a 72–98 ms prepare. Even at 0 ms each
  read was about 2 ms (MinIO over TLS, loaded): 40–72 ms.
- **the read ahead** ran at least 8 entries a thread on at most 8 threads:
  110–125 reads a batch, 38–41 ms.
- **the projections read each kept view key's memo of every new snapshot's
  predecessor** (the submitted stack snapshot, whose projection the submit
  made on whichever server took it) one after another, on the build's one
  thread: 16–30 misses a batch, 21–28 ms of the projections' 26–55 ms. Of
  the rest, 8–15 ms was CPU; no lock or run-queue wait to speak of.
- **the store** writes a batch's objects (about 6 a landing: the new
  snapshot, its trees, the projected snapshot and tree) 64 at once
  already (`PUTS_AT_ONCE`): 150–190 ms a batch of 64 here. Real work: the
  `objects` layout's one write an object, and MinIO's write rate.

Stages that overlap: the batch's objects are stored while its transaction
runs (BUG-1955), and the next batch is chosen, prepared and built while
the batch before commits. Nothing else could overlap without holding more
than one batch's objects, which `BATCH_BYTES` bounds (BUG-1107).

## 4. What changed

Two commits (BUG-2942), each measured at 0.5 ms and at 0.

1. **prepare's snapshot reads at once** (`READ_THREADS` = 32 threads, at
   least 2 reads each, in `prepare`'s blocking step), and **the read ahead
   on the same threads** (2 entries a thread, not 8).
2. **The kept view keys' projections of the stack snapshots read at once
   in prepare**, after the memos: the build then finds them in memory.

Measuring builds, 0.5 ms (16-connection pools, MinIO 4 GB): prepare
72 → 27 ms, the projections 54 → 4 ms, the build 106 → 25 ms a batch. With
those small pools the submits bounded what landed at 0.5 ms (about 325 a
second either way); at 0 the second commit took 365 → 465. With MinIO at
its 512 MB default the first commit alone took 291 → 376 at 0.5 ms and
397 → 481 at 0. §6 has both commits against the service before them.

Not changed, and why:

- **The transaction's 13 statements as one CTE** would save about 12
  round trips, 6 ms at 0.5 ms, of a commit the store sets (100–190 ms), at
  the price of rewriting the one transaction that carries fencing, the
  review gate and the memo race; and its statements' order is what their
  checks rest on (the lease and the branch first). Not worth it at these
  numbers.
- **prepare's six reads at once** (they are independent): 2–3 round trips,
  1–2 ms at 0.5 ms, below what a 60 s run can tell apart.
- **The store**: real work. Fewer writes a landing is a question of the
  object layout (the owner's: `objects` is the default), not of
  waiting.
- **The submits.** At 0.5 ms a submit makes about 30 statements, one
  after another, and its objects' writes: with a 16-connection pool (the
  rehearsal's default) the submits, not the service, bounded what landed.

## 5. The guarantees, unchanged

The changes read objects earlier and at once; they decide nothing from
what they read that the code did not decide before:

- **Fencing**: untouched. Only the lease's holder moves the branch; the
  epoch is checked in the transaction that moves it.
- **Stored before named** (`STORE_IN_TRANSACTION`, BUG-1982): untouched;
  nothing new is written.
- **Permission, review-rule, embargo and memo-race checks**: the same
  checks on the same objects. A snapshot read in `prepare` fails or is
  missing exactly as before (skipped there, as it was); the projections
  read ahead are only read, so the build finds a missing or unreadable one
  itself and answers what it did. Every read is of the project's own store,
  checked against its id (`Objects::get`), into the server's own memory.
- **Landed exactly once**, **the audit row**: untouched.
- The read ahead is the batch built on one thread, byte for byte
  (`landing_hold::bug_1955_a_batch_read_on_several_threads_is_the_batch_built_on_one`).

No cross-server state, no new coordination.

## 6. Before and after

Release images built from commits (before: the counters commit, the
service as at `da8ab108`; after: this branch), the landing check of §2,
two runs each, before and after interleaved. Milliseconds a batch, the
service's counters; round trips from `pg_stat_statements`; store requests
from both servers' counters (the submits' included).

| Delay | Build | Landings/s (two runs) | Landings a batch | ready | prepare | build (read ahead / projections) | loop waits for the commit | commit (transaction / its wait for the store) | store | round trips a batch | store reads / writes a landing |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 0.5 ms | before | **286** (282, 291) | 63.8 | 6.5 | 75 | 113 (42 / 57) | 26 | 143 (140 / 97) | 166 | 27 | 5.9 / 14.0 |
| 0.5 ms | after | **402** (412, 393) | 63.8 | 5.5 | 33 | 35 (19 / 6) | 81 | 143 (141 / 104) | 218 | 27 | 5.9 / 14.0 |
| 0 ms | before | **358** (365, 351) | 63.8 | 3.3 | 48 | 67 (26 / 31) | 56 | 139 (137 / 111) | 191 | 27 | 5.9 / 14.0 |
| 0 ms | after | **397** (394, 401) | 63.8 | 3.3 | 32 | 30 (14 / 6) | 91 | 146 (145 / 117) | 232 | 27 | 5.8 / 14.0 |

- **At 0.5 ms: 286 → 402 landings a second (+40%)**; at 0: 358 → 397
  (+11%). The same statements and the same store requests a landing:
  the reads moved, none was added.
- prepare + build fell from 188 to 68 ms a batch at 0.5 ms. The loop now
  waits 81–91 ms a batch for the batch before it to commit: **the commit
  sets the pace**, and in it the transaction's wait for the batch's
  objects to be stored (97–117 ms of 140–145). The store took longer
  after (166 → 218 ms at 0.5 ms) because more landed a second on the one
  MinIO.
- What is left is real work: about 6 store reads and 14 writes a landing
  (submits and service, `objects` layout), MinIO's write rate, and the
  transaction's 15 round trips (7.5 ms at 0.5 ms).
- On the cloud's numbers (§1) the same reads were 174 ms of prepare and
  about 130 ms of the build's 157: the cloud's pace becomes its commit
  (165 ms with a store of 181 ms), roughly 63.6 / 0.17 s ≈ 370 landings a
  second, until the store is faster. That is a prediction, not a
  measurement: no cloud run was made (and that run's MinIO was filling
  up, §8).

## 7. The failover gate (BUG-2940)

On the cloud the gate paused its fixed 45 s, then took as the holder the
server whose `landing_batches` rose most in 3 s: `24314→24314`,
`2877→2877`, `281→282`. Those counters count every project's batches since
the server started (server 3 was still landing tickets the scaling gate
had left queued, in its own projects), the run's lease row was empty
(`lease_before=`), and it stopped server 3, which held nothing.

**Why nothing had landed:** the tool was still setting its 1,000 agents up.
The load began at 04:45:36, the first landing came at 04:46:48 (72 s;
the measured window began at 04:46:51). The `landing` gate's set-up of
10,000 agents took 22 s an hour earlier, the rehearsal's of 1,000 about
1 s. By the failover gate MinIO was answering PUTs 507 (BUG-2941; the
servers' stores took about 20 s a batch), and the set-up writes objects.
No server fault was found: once the lease was held, the failover itself
passed every check (no change lost or landed twice; longest pause 1,004 ms).

**Fixed:** after `FAILOVER_AFTER` the gate waits, at most `FAILOVER_WAIT`
(300 s) more, until the run's lease row is held and the run's landed
tickets rise between two looks 2 s apart (`deploy/checks/failover-held.sql`),
then stops the server whose `stats.json` `landing_holder` (new: its
lease-holder name) is the one the row names. No lease held, no landings
flowing, or no server with that name: it fails with that reason and stops
nothing. The batch counters are no longer used.

## 8. The cloud's 3-server landing drop (BUG-2941)

`scaling`: landing 246/s with 1 server, 224 with 2, 78 with 3 (212 errors,
1,212 tickets `still queued after the server's wait`), pull and branches
flat. The 3-server minute fell from 139 to 1 landings a second. The
servers restarted for 2 and 3 servers spent 3.9 s (hub2) and 30.7 s
(hub3) storing each batch, against 0.85 s on hub1 in the same gate.

At the end of the run every server's log was `S3 PUT answered HTTP 507`
and `a landing batch … failed: storing the batch's objects` (4,122–4,632
of each server's last 5,000 lines), MinIO logged `drive path full` on every
PutObject, and its drive was 102 G used of 369 G, its load average 12,767.
The local SSD was made by `mkfs.ext4` with its default of one inode per
16 KiB, about 24 million; MinIO keeps each object as a directory and its
`xl.meta`, and the `objects` layout keeps every snapshot, tree and file as
an object: about 12 million objects fill it. The servers had written about
14 million by the scaling gate. So the drop is the object store's drive
running out of inodes, not the servers or the gate's stop and start. (The
inode count is inferred: `df -i` was not recorded.)

**Fixed in the kit:** MinIO's file system gets one inode per 4 KiB
(`mkfs.ext4 -i 4096`, about 97 million), and `deploy/do/logs.sh` records
`df -i`. The 3-server step, `failover` and `agents` of that run are not
valid results.
