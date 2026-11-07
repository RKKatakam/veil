# Phase 3: history answered by the server

> **Status:** S12 built (2026-11-06, §10); S13 built (2026-11-07, §11); S15 built (2026-11-07, §12); S14 and S16 design. Base: `integration` @ `3851159` (S13: `d58a952`).
> Sources of truth: `docs/OVERVIEW.md` and `docs/VISIBILITY.md`; where this document disagrees with them, they win. The server as built is `docs/HUB.md` §13; projected history is §13.4. The roadmap is `docs/design/scion-for-developers.md`, phase 3 (items 3.1–3.6). The client's commit-graph index (`docs/design/scale/3-history-index.md`, built) is the model for the server's.

## 1. Goal

Every history question is answered **by the server, through the API, with no checkout, in milliseconds to low hundreds of milliseconds**: log, blame, file history, diff against the merge base, a file at a revision, and search by path and by code. Answers are **projected per viewer**: someone who cannot see a folder never learns its files' names or contents, not from results, counts, ranking, timing, or blame lines.

This phase is what lets thin clients (phase 2) hold no history, and what CI, review and bisect (phase 4) ask instead of checking anything out.

The design check:

| Rule | How this phase keeps it |
|---|---|
| Server-centric, always connected | History lives on the server; `vl log`, `blame`, `grep` in a thin clone ask it. |
| Code is plain text behind the server's checks | The server indexes plain-text code, and every answer passes the one access function (`HUB.md` §4.6). |
| Only secret files are encrypted | Secrets are never indexed in the clear: the server cannot open them, and does not try (§6, row 7). Unreleased embargoed content is not indexed until release (row 8). |
| Admins, groups, managers, folder access, public | Answers are filtered by the same rules; nothing here adds an access concept. |
| No Git, no offline mode, no SFTP | None. |

## 2. What people and agents see

### 2.1 Plain English

* `vl log`, `vl blame`, `vl show`, `vl diff`, `vl grep` and `vl cat -r` work the same in a thin clone as in a full one, and take about the same time on a ten-year-old project as on a new one.
* `vl search` finds files by name and code by content, across the project's `main` (and any branch tip asked for), in well under a second.
* **You see the history you may see.** A change that touched only folders you can't see is not in your log. A change that touched both shows only your part (`HUB.md` §13.4). Blame never names a hidden file. Search never counts, ranks or suggests anything from a hidden folder.
* **Agents and CI use the same API** over HTTP, with no `vl` and no checkout.

### 2.2 CLI (unchanged commands, now answered by the server in a thin clone)

```text
vl log [-n N] [REVSET] [-- PATH…]            pages from the server
vl log --follow -- PATH                      file history across renames
vl blame [-r REV] PATH [--agent]             precomputed
vl diff --from main --to @                   against the merge base by default for a change: vl diff -r CHANGE
vl show -r REV [-- PATH]                     a change, or a file at a revision
vl cat -r REV PATH
vl grep PATTERN [-r REV] [-- PATH…]          the index for main and branch tips, a scan for other revisions
vl search 'handler' [--path] [--lang rust]   new: ranked search over names and code
```

All of them also exist as JSON routes (§4.1), with the same `--json` schemas `docs/reference/json.md` defines.

## 3. Architecture

### 3.1 Derived data

Scion's one mechanism: **each index's value for a snapshot is computed from the snapshot and its parents' values.** The server runs it on real (unprojected) history, because it is trusted with code. Projection happens when an answer is served (§3.4), never when it is computed.

```text
Derive<T>:  value(S) = f(S, value(S.parents[0]), …, value(S.parents[n]))
            eager:  computed by the derive workers as soon as S lands
            lazy:   computed when first asked, from the parents' values (recursively, memoised)
```

| Index | Value per snapshot | When | Stored |
|---|---|---|---|
| **Commit graph** | generation (corrected commit date, as the client's), first-parent depth, parents, change id, flags (embargo, embargo line) | eager | database rows |
| **Skip list** | ancestors at first-parent distances 1, 16, 256, 4096 (a jump pointer table) | eager | database rows, with the graph |
| **Changed paths** | the paths changed against the first parent, with old and new entry ids, and each folder above them; capped at 100,000 paths (above: "many", and queries walk the trees instead) | eager | an object per snapshot |
| **Per-rule history** | for each access line of the accepted policy, the snapshots that changed a path it decides (§3.4) | eager | database rows |
| **Copies and renames** | for each added path: the deleted or unchanged path it came from, exact id match first, then a similarity check for files under 1 MiB, at most 1,000 candidates | eager | inside the changed-paths object |
| **File history** | for each changed path, the previous snapshot that changed that path (following renames) | eager | inside the changed-paths object |
| **Blame** | for a file at a snapshot: line ranges, each with the snapshot that introduced it and its line there | lazy, from the previous version's blame and one diff; memoised per file version | an object per (file version), content-addressed |
| **Search index** | trigram and path index of `main`'s tip and of other branch tips asked for, sharded by access line (§3.5) | eager, incremental per landed batch | segment objects in the object store, manifest in the database |

* **Derive workers** are the repo workers of `HUB.md` §2.1. They read each branch move from the database, compute the eager indexes for the new snapshots in order, and record how far they are (`derive_progress`). **Landing never waits for them.** A query on a snapshot not derived yet computes what it needs from the nearest derived ancestor, or answers `indexing` with a `retry_after_ms` when that would take longer than its deadline.
* **Values are immutable** (a snapshot never changes), so every derived object is addressed by its hash and cached like any object, and a worker that crashes half way recomputes the same bytes.
* **Format and versions:** each index has a version number in its objects; a new version is computed beside the old one and replaces it when complete. Derived data is a cache: it can be dropped and recomputed from the store. No repository format change.

### 3.2 The commit graph

Generations and skip lists give the queries that the client's index gives (`3-history-index.md`), on the server, for any history size:

* `is_ancestor(a, b)`: walk from `b` with generation cut-off at `gen(a)`, jumping by the skip list along first parents; typically tens of rows read.
* `merge_bases(a, b)`: paint-down with generation cut-off.
* `log -n N`: the client's lazy topological walk (`topo_iter`), producing exactly the order of `topo_children_first`.
* Range `A..B`, `descendants_among`.

### 3.3 The query API, and where projection happens

```text
query (viewer, request)
  1. viewer := (person, view key, policy version)   from the session (phase 2 permission cache)
  2. resolve revisions: projected id → real id     (only ids this viewer was given; else "no such revision")
  3. check paths against the access function BEFORE any lookup:   a hidden path and a missing path
     get the same answer, by the same code path
  4. compute on real derived data, restricted to the rules this viewer may read (§3.4)
  5. project the answer: real ids → the viewer's projected ids; drop what the viewer cannot see
```

| Route | Answers | Projection rule |
|---|---|---|
| `GET …/log?rev=&n=&path=&after=` | a page of the viewer's projected snapshots | only snapshots that changed something the viewer may read (§3.4); with `path`, a readable path only |
| `GET …/show?rev=&path=` | a snapshot's projected fields and the diff of the viewer's part, or a file | the diff lists only readable paths |
| `GET …/file?rev=&path=` | a file's bytes (ciphertext for a secret) | readable path only |
| `GET …/tree?rev=&path=` | a folder listing | the projected tree |
| `GET …/diff?from=&to=&base=merge` | the diff between two revisions, by default against their merge base | the merge base is computed on the viewer's projected graph (§3.4); only readable paths |
| `GET …/blame?rev=&path=` | line ranges, each with a projected snapshot id, author, time, agent, description | §3.6 |
| `GET …/history?path=&follow=1` | the snapshots that changed a path, across renames | renames are followed only between readable paths (§3.6) |
| `GET …/grep?rev=&pattern=&path=` | matches in a revision | readable files only; §3.5 |
| `GET …/search?q=` | ranked files and lines | §3.5 |
| `POST …/ancestry {pairs}` | `is_ancestor`, `merge_bases` for thin clients and the landing service | on projected ids |

Each answer is a page with a cursor; every route has a deadline (default 2 s) and a size limit.

### 3.4 Per-viewer history without per-viewer work

`HUB.md` §13.4 defines a viewer's history: a change that touched only what the viewer cannot see is not in it. Computing that by walking real history and testing each snapshot would take time that depends on how much hidden work there is, which leaks it (a timing channel) and does not scale.

**Per-rule history lists.** Every path is decided by exactly one access line of the accepted `.veilpolicy` (the last matching line, `HUB.md` §13.3), or by "no line" (admins only). For each line `L`, the derive workers keep the list of snapshots, in generation order, that changed some path `L` decides. A viewer may read a set of lines `R(v)` (admins: all). Then:

* **The viewer's log** is the merge, by generation, of the lists of the lines in `R(v)`, deduplicated. Work is proportional to the snapshots the viewer sees, and to `|R(v)|`, never to hidden snapshots.
* **`log -- PATH`**: the path's deciding line's list, filtered by the changed-paths objects for `PATH`.
* **Projected ids** come from the memo of `HUB.md` §13.4, or are computed from the nearest memoised ancestor along the viewer's merged list (phase 4 §5.3 covers the memo at 1,000 landings a second).

**Policy changes.** A new accepted policy changes which line decides some paths. The derive workers rebuild the per-rule lists for the lines whose paths changed, from the changed-paths objects (not from the trees), before the new policy version is used for queries. Until then, queries use the old version's lists **intersected with the new access function** (an answer may briefly miss a snapshot, never show a hidden one).

**Mixed changes.** A change that touched both readable and hidden paths is on both lists; the viewer sees it with only their part, with its description (`HUB.md` §13.4, a deliberate S1 decision).

### 3.5 Search

**Scope.** Code search covers the tips of `main` and of other branches when asked for (`vl search --rev`), and open PR heads (phase 4). Path search also covers every path that ever existed, from the changed-paths objects. `vl grep -r OLD` at an older revision scans that revision's readable files (no index), within its deadline. Whether to index all history is a product decision (§9, item 2).

**Sharded by access line.** The index is split into one shard per access line (and one for "no line"). A file is in the shard of the line that decides its path. A query from viewer `v` opens **only the shards of `R(v)`**:

* results come only from readable files;
* **counts** ("1,204 matches") are sums over those shards;
* **ranking** uses statistics (term frequencies, document counts) of the viewer's shards only, never of the whole project, so a score never reflects hidden files;
* **suggestions and "did you mean"** come from the viewer's shards;
* **time** depends on the viewer's shards only: a hidden folder full of matches costs the viewer nothing and tells them nothing.

**Updates.** Each landed batch (or push) re-indexes the changed files of its shards as a small new segment; segments are merged in the background, as the client's history index merges layers. A policy change moves the files whose deciding line changed into their new shards before the new policy version is used for search.

**What is never indexed in the clear:**

| Content | Indexed? |
|---|---|
| Plain-text code in any folder | yes, in its line's shard |
| **Secrets** (`.env`, keys, sealed files) | **content no**: the server holds ciphertext and no key. The **path** is indexed in its line's shard, because people with folder access already see that `billing/.env` exists (`HUB.md` §6.3) |
| **Personal keys** | never uploaded |
| **Unreleased embargoed content** | **no**: embargo lines are not indexed until release (§6, row 8). After release, the content is ordinary and is indexed |
| Binary files, files over 1 MiB, generated files the policy marks | paths only |

**Patterns.** Regular expressions use a linear-time engine (the `regex` crate, no backtracking), with a size limit; trigrams narrow the candidate files, and each candidate is confirmed against its content.

### 3.6 Blame, file history, copies and renames, projected

* **Blame** is computed on real history. Each line names the snapshot that introduced it; that snapshot changed this file, which the viewer can read, so it is in the viewer's history and has a projected id. Blame answers carry projected ids only.
* **Copies and renames across a hidden boundary are cut.** If a line came into readable `src/pay.rs` from hidden `billing/core.rs`, the viewer's blame attributes it to the change that brought it into `src/pay.rs`, and names no other path. Likewise, file history with `--follow` stops at a rename from a hidden path (it shows as an add), and a rename to a hidden path shows as a delete.
* **Descriptions** shown in blame are those the viewer's log shows (§3.4).
* **Agent attribution** (phase 2) is shown with each line when asked (`--agent`), under the same rule as the description.

### 3.7 Thin clients use it

The phase 2 thin clone answers its history commands through these routes (§2.2), and the phase 2 `history` pages become `log`. The engine walks of `3-history-index.md` that a thin clone cannot run locally (ancestry, merge bases, embargo checks) call `POST …/ancestry` or are the server's.

## 4. Data model and protocol changes

### 4.1 API

The routes of §3.3, under `/v1/projects/{p}/q/…`, with JSON answers in the schemas of `docs/reference/json.md` (`veil.log`, `veil.show`, `veil.blame`, `veil.grep`, new `veil.search`). Every answer carries `policy_version`, so a client knows when a cached answer is stale.

### 4.2 Database

```sql
CREATE TABLE IF NOT EXISTS graph (
    project_id BIGINT NOT NULL,
    snapshot TEXT NOT NULL,
    generation BIGINT NOT NULL,
    depth BIGINT NOT NULL,                 -- first-parent depth
    parents TEXT NOT NULL,                 -- JSON list
    change_id TEXT NOT NULL,
    flags INT NOT NULL,                    -- embargo, embargo line
    skip TEXT NOT NULL,                    -- JSON: first-parent ancestors at 1, 16, 256, 4096
    changed TEXT,                          -- object id of the changed-paths object (NULL: "many")
    PRIMARY KEY (project_id, snapshot)
);
CREATE INDEX IF NOT EXISTS graph_by_change ON graph (project_id, change_id);
-- Per-rule history lists (§3.4). line_key: a hash of the line's path, from the accepted policy.
CREATE TABLE IF NOT EXISTS rule_history (
    project_id BIGINT NOT NULL,
    policy_version BIGINT NOT NULL,
    line_key TEXT NOT NULL,
    generation BIGINT NOT NULL,
    snapshot TEXT NOT NULL,
    PRIMARY KEY (project_id, policy_version, line_key, generation, snapshot)
);
CREATE TABLE IF NOT EXISTS derive_progress (
    project_id BIGINT NOT NULL,
    index_name TEXT NOT NULL,
    index_version INT NOT NULL,
    through_snapshot TEXT NOT NULL,        -- every snapshot up to this one on each branch is derived
    PRIMARY KEY (project_id, index_name, index_version)
);
CREATE TABLE IF NOT EXISTS search_segments (
    project_id BIGINT NOT NULL,
    line_key TEXT NOT NULL,
    branch TEXT NOT NULL,
    segment TEXT NOT NULL,                 -- object id
    covers_snapshot TEXT NOT NULL,
    PRIMARY KEY (project_id, line_key, branch, segment)
);
```

At 1 million landings a day the `graph` and `rule_history` tables grow by about 1 million and a few million rows a day; both are keyed by project first, so they shard by project on YugabyteDB.

### 4.3 Object store

New derived objects under the project's key prefix (`p/<project id>/…`), addressed by hash: changed-paths objects, blame objects, search segments. They are never sent to clients as objects (answers are JSON), so they need no grant rules.

## 5. Performance targets and the benchmark

`veil-bench query` (new), on a generated project: 100,000 files, 1 million snapshots of history, a file changed 10,000 times over "ten years", 20 access lines with viewers of 1, 5 and 20 lines, and the admin. Measured server time, p50 and p99, with warm caches and after a cold start.

| Query | Target (p99) |
|---|---|
| `log -n 50` | 20 ms |
| `log -n 50 -- PATH` (a hot file) | 50 ms |
| `is_ancestor`, `merge_bases` on 1 million snapshots | 5 ms |
| `diff` against the merge base, 100 changed files | 50 ms |
| `file`, `tree` at any revision | 10 ms |
| `blame` of a 5,000-line file changed 10,000 times, precomputed | 50 ms; first time 1 s |
| `history --follow` | 50 ms |
| path search | 20 ms |
| code search over `main`, 10 GB of text | 200 ms |
| derive lag behind landing at 1,000 landings/s | under 1 s for the graph and changed paths; under 10 s for search |
| restricted viewer against admin, same query | within 10 % (work proportional to what each sees) |

**How this phase moves the owner's numbers.** It does not raise landings or pulls by itself; it removes history from the client:

| Number | Before | After phase 3 |
|---|---|---|
| Pull cost while `main` moves 1,000/s | phase 2: tip only | the same; history questions are separate, cheap requests |
| A fresh agent's first `vl log` or `blame` on a large project | fetches history objects | one request, milliseconds |
| CI and bisect without a checkout | not possible | diff, file and ancestry through the API (used by phase 4) |
| Landing at 1,000/s | not affected | derive workers keep up asynchronously; landing never waits |

**The leak check is a benchmark too:** `veil-bench query --projection-check` runs every query of the suite for every viewer against **a copy of the project built only from what that viewer may see** (their projected history, pushed into a fresh project where they are admin) and requires identical answers, counts and ranking (§6, row 1).

## 6. Threat review

| # | Attacker | Capability | Harm | Mitigation | Test |
|---|---|---|---|---|---|
| 1 | Person without access to `billing/` | any query: log, blame, history, diff, grep, search | learns a hidden name, content or change | one access function, paths checked before lookups, per-rule lists, sharded search, projection of every answer (§3.3–3.6) | **projection equivalence**: for random histories, policies and viewers, every route's answer for viewer `v` equals the answer on a project built only from `v`'s projected history (ids mapped). Any difference fails |
| 2 | Same | counts, totals, page sizes, "more results" | learns that hidden matches exist | counts are over the viewer's shards and lists only | covered by row 1 (counts are part of the answer) |
| 3 | Same | ranking, suggestions | infers hidden term frequencies | per-viewer statistics from the viewer's shards | row 1 compares ranking, not just sets |
| 4 | Same | timing of queries | infers how much hidden work or content exists | work is proportional to the viewer's lists and shards; a work counter (rows and postings read) is recorded per query | for one viewer, two projects that differ only in hidden content: identical work counters for every query |
| 5 | Same | `blame` of a readable file with lines copied from a hidden one | learns the hidden path or its history | copies and renames cut at the boundary (§3.6) | a property test with moves and copies across the boundary; no hidden path string in any answer |
| 6 | Same | asks for a path or revision that is hidden, then one that does not exist | tells them apart | same answer and same code path; projected ids only; real ids are never accepted from a viewer without full view | a grep of every answer for real snapshot ids not in the viewer's history: none; error bodies compared byte for byte |
| 7 | Someone who breaks into the server | reads the indexes | reads secrets | secrets are ciphertext, never decrypted or indexed; only their paths are | after a run with secrets, no index object contains any secret's plaintext (the test knows them) |
| 8 | Person outside an embargo's groups | searches, blames, logs | learns the fix before release | embargo lines are not indexed or listed until release; the per-rule lists skip embargoed snapshots for viewers outside the groups | embargoed fix with distinctive names and strings: no query by an outsider finds them before release; all do after |
| 9 | A person whose access was just removed | repeats a cached query | sees what they no longer may | caches keyed by view key and policy version; a group change bumps the epoch (phase 2) and voids the person's cached answers | remove, then re-query within a second: the hidden results are gone |
| 10 | Hostile pusher | a file with 10⁷ lines, a pathological regex, 10⁶ renames in one change | exhausts the derive workers or a query | caps (changed paths 100,000, similarity 1 MiB and 1,000 candidates, segment size), linear regex, per-query deadline and per-person query limits | generators of each; workers stay within 2× linear and other projects' queries keep their targets |
| 11 | — (a bug) | a derived value wrong after a crash or a race | wrong history | values are a function of immutable inputs; workers recompute deterministically; a sampled self-check compares derived answers with direct walks | kill workers mid-batch in a loop; every answer equals the direct walk |
| 12 | An agent given less (`--only src/api`) | queries files, grep or search outside its paths | reads outside its task | file answers (`file`, `tree`, `diff`, `blame`, `grep`, `search`) are narrowed to the session's paths after projection; history lists stay its person's (phase 2 §5.6); caches never share file answers across sessions with different paths | row 1's harness with narrowed sessions: no file content or line outside the session's paths |
| 13 | Admin changes the policy | old shards and lists still hold a moved folder | a viewer newly without access still finds it, or one newly with access misses it | the old version's answers are intersected with the new access function until the rebuild completes (§3.4, §3.5) | change a line during a query load: no result outside the new access, ever |

## 7. Milestones

| # | Milestone | Contents | Depends on | Touches |
|---|---|---|---|---|
| **S12** | Derived-data framework and the commit graph | `Derive` trait and workers, `derive_progress`, graph and skip lists, changed paths (with copies, renames and file history), per-rule lists, rebuild on policy change, eager projection memos for every view key at each branch move (phase 4 §4.5) | S1 | new `veil-server` `derive/`; `veil-core` diff code |
| **S13** | Query API with per-viewer projection | `log`, `show`, `file`, `tree`, `diff` (merge base), `ancestry`; the projection layer every route goes through; the projection-equivalence harness (§6, row 1) | S12 | new `veil-server` `query.rs` |
| **S14** | Blame and file history | lazy blame objects, `history --follow`, boundary cuts (§3.6) | S13 | `derive/blame.rs`, `veil-core` `blame.rs` |
| **S15** | Search | sharded trigram and path index, segments and merges, per-viewer ranking, `grep` at tips and scans at old revisions, `vl search` | S13 | new `veil-server` `search/` |
| **S16** | `vl` over the query API, and the phase 3 gate | thin clones answer `log`, `blame`, `show`, `diff`, `cat -r`, `grep` through the server; `vl log` lists history in the server's order, newest first by corrected generation, in full clones too (§11, decided 2026-11-07); `veil-bench query`; the gate run | S3, S13–S15 | `crates/vl`, `crates/veil-bench` |

## 8. Open technical questions

1. **Generation numbers on the server:** corrected commit dates (as the client's) need only that they decrease along every edge; a hostile timestamp only lengthens a walk. Keep the client's definition for one meaning everywhere.
2. **Per-rule lists for viewers with many lines** (an admin with 200 lines): merging 200 lists is slower than walking real history. Use the real walk for viewers who may read everything (admins, and any view key that covers every line); measure the crossover.
3. **Policy versions with many lines changing at once** (a reorganisation): the rebuild can take minutes on a large history; is the intersected answer (§3.4) good enough during it, or should the policy's acceptance wait?
4. **Blame memo size:** one object per file version can be large for generated files; cap by size and compute on demand above it.
5. **Purging.** When a secret is committed into an ordinary file by mistake (a scanner miss) and an admin purges it, its derived data (search segments, blame objects) must be purged too. The purge itself is not designed yet; the derived-data framework must support dropping every value that depends on an object.

## 9. Product decisions for the owner

1. **Descriptions of mixed changes in search and blame.** S1 shows a change's description to anyone who sees part of it (`HUB.md` §13.4). Search over descriptions would then find words describing hidden work. Recommendation: search descriptions only of changes the viewer sees whole (every path readable); show mixed changes' descriptions in log and blame as today.
2. **What code search covers.** Recommendation: `main`, branch tips and open PRs for content; every path ever for names. Indexing all history's content costs storage roughly proportional to history and is rarely needed; `vl grep -r REV` covers old revisions by scanning.

## 10. As built: S12, derived data (2026-11-06)

Code: `crates/veil-server/src/derive/` (`mod.rs` the worker, `graph.rs`, `changes.rs`, `lines.rs`, `view.rs`), migration `0004_derived.sql`, and one call in `sync::push` after its transaction commits. Tests: `crates/veil-server/tests/server_hub/derived.rs`. No query API (S13); no repository format change.

**The worker.** `derive::landed` runs after every landing in the background, for **the branches that landing moved** (the push never waits); `derive::ensure` derives one snapshot and what is below it when asked (on demand). Both run `catch_up` (a `Scope`: every branch, some branches, or one snapshot) under a per-project database advisory lock, so one deriver works per project across servers (the others wait up to 60 s, then leave it to the holder or the next landing). A run:
1. makes the lists the accepted policy needs complete (below);
2. derives every snapshot its scope reaches that has no value, parents first, in batches: written every 512 snapshots, 100,000 queued rows or 64 MiB of objects, whichever comes first, so a batch's memory is bounded whatever was pushed (BUG-867);
3. records the derived tip of each branch in its scope in `derive_progress` (one statement; one index, `history` v1, for the three, which are derived together);
4. after a landing, projects the moved branches' tips once for every view key of the project's people and of anyone on Earth (`memo_tips`, the eager memos of phase 4 §4.5).

A landing's work depends on what it moved, never on how many branches the project has (BUG-870). **What a landing leaves undone is resumed** (BUG-982): each landing's run also takes every branch whose `derive_progress` is not its target (one statement over the branches and their progress rows), so a run that was skipped behind another server's lock, failed on a busy database or was cut by a restart is done by the project's next landing, on any branch; and a server catches up at start (`derive::resume`, in the background), so a landing lost to a restart is done even when nothing else lands.

There is no `Derive` trait: the three indexes are three functions the one worker runs in order. A trait waits for a fourth (S14, S15).

**Idempotent and resumable.** A batch writes, in order, the changed-paths objects, the `file_history` and `rule_history` rows, and last the `graph` rows, which mark snapshots derived. Every insert is `ON CONFLICT DO NOTHING`, and every statement is retried on a retryable error. A crash anywhere leaves rows that the next run writes again identically; nothing is marked derived without its values. The run holds the lock in its own task, so a caller that stops waiting never leaves a lock on a pooled connection. At start, the server resumes every project with an underived branch, one at a time; after that the next landing, or the first query, resumes.

**Bounded, apart from requests (BUG-911).** Every run started when its landing committed, and held a connection of the server's one pool for its project's lock while it needed a second for each statement: a landing in more projects at once than the pool had connections left every connection held by a run waiting for another, and no landing or pull found one (none landed across 100 projects). Now at most **4 runs derive at once** in a server process (a semaphore; `derive::DERIVERS`), on the deriver's **own pool of 8 connections** (`derive::DERIVE_CONNECTIONS`, apart from `--db-connections`, opened when first needed): a run holds its lock's connection and at most one statement's. A run waiting its turn, or waiting for another server's deriver of its project, holds no connection (it gives back the permit and the connection between tries of the lock). Memoising the tips (`memo_tips`) runs on the requests' pool, as a pull's projection does, under a permit too, so at most 4 of its connections are in use at once. Queries' reads of derived data (`derive::read`) stay on the requests' pool; a derive run's statements go to its own (`Cx::pool`). Landings and pulls never wait for the deriver; the derived data lags instead, and catches up. A run's statements stay small on a busy YugabyteDB: the file-history lookup of a change of up to 100,000 paths is one statement per 1,000 paths (BUG-912).

**What is stored.**

| Value | Where | As built |
|---|---|---|
| Commit graph | `graph` rows | generation (the client's corrected commit date, with the timestamp clamped to `i64::MAX / 4` and additions saturating, so a hostile timestamp cannot overflow it: BUG-866), first-parent depth, parents, change id, flags (`1` embargo, `2` embargo line). The jump table (`skip`) holds the first parent and the first-parent ancestors at the multiple of 16, 256 and 4096 just below the snapshot's depth: each comes from the first parent's row alone, and `at_depth` reaches any depth in at most 15 steps a level plus one per 4096. `is_ancestor` tries the first-parent line through the table, then walks with the generation cut-off; `merge_bases` answers at once when one side is an ancestor of the other, and otherwise paints down by generation, as the client does. |
| Changed paths | one object per snapshot (`veil-derived changed-paths 1` then JSON), addressed by its hash in the project's object space | **leaves only** (files, links, conflicts, sealed directories), with old and new entries. Folders are not listed (the folders above a path are its prefixes), except **folders that changed with no leaf changing below them** (an empty folder added or removed, a folder entry's metadata): `dirs`, deepest only, listed under the lines that decide them, as `Projector` shows them (BUG-871). It is not an object encoding, so no upload can name it and `fetch` never serves it. A change of more than 100,000 paths and folders together is `many` (BUG-981): no object, its `file_history` rows like any change's (BUG-868), and its lists computed from the trees on a rebuild. `none` is only a change whose tree is its first parent's. |
| Copies and renames | in the object, per added file | sources are files the same change deleted or modified with the same object id (score 100), and, for plain-text files under 1 MiB that it deleted, those sharing at least 50 % of their lines. Unchanged files are not sources (there is no id-to-path index of a tree). **Every source is kept, ranked** (score, then a rename before a copy, then path), at most 16 a path (`capped`). A source in a hidden folder never decides what a reader sees. Similarity is skipped above 1,000 added or deleted files, 2·10⁷ line comparisons, 16 MiB of line-hash tables held (their memory) or 64 MiB read for one change (`similar: false`; the last two since BUG-1072 and BUG-1077, §11); at most 4 similarity passes run at once in the process. When a list is capped or similarity was skipped, a viewer's sources are computed on the part they may read, by the same function, exactly as a project holding only that part would compute them. |
| File history | `prev` in the object, and `file_history` rows (path hash, depth, snapshot) | `prev` is per parent: the snapshot that last changed the path along that parent's first parents, i.e. the one that introduced that parent's version (the blame input of S14). For an added file, a source's `prev` is the source's own entry in the same object. It is found from the path's rows at or above the parent's depth, deepest first, checked against the jump table (every changed path has a row, `many` snapshots' too, so no tree is read). Rows of the running batch on the line are final. |
| Per-rule lists | `rule_history` rows (line key, generation, snapshot), `rule_lines` (keys kept, `ready`) | a list per access line, named by the paths the line decides (its path, and the rule paths below it with whether each comes later), not by the policy version. A new policy keeps the lists of lines whose paths it left alone (a group renamed, a line added elsewhere), and builds only the others, from the changed-paths objects (`many` ones from the trees), before deriving anything under it. Paths no line decides, and sealed directories with a rule below them, are on the `none` list, which only admins read. Lists a policy no longer has stop being kept (their rows stay until a purge). |

**Secrets** are indexed by path only. Their entries name ciphertext, which the server cannot open and never decodes, compares or stores. **Embargo lines** (a snapshot with the embargo flag or an embargoed ancestor) get graph rows and nothing else (`changed = withheld`): no paths, no lists, no file history until release. S22 decides how a release lifts it.

**Reading as one viewer** (`derive::view::Reader`, the internal reads S13 serves from; answers are in real ids, which S13 maps to projected ids):
* `visible` decides from the lists and the graph alone exactly what `sync::projected` decides. A one-parent change is in the viewer's history when it is on one of their lists, or its tree is its parent's. A merge is in it when it is on a list, or when its parents stand for different snapshots of the viewer's history. `visible` and `rep` are iterative, with an explicit stack and memos, so no history (20,000 merges in a row) can overflow the thread's stack (BUG-869); one-parent snapshots are decided as the walk reaches them, and every snapshot walked keeps a pointer to where the walk ended, so each is walked once: a run of `k` hidden changes costs `k`, not `k²/2` (BUG-980).
* `changes` is the viewer's part of a change: sides they may not read are left out, and only sources they may read are kept.
* `merge_bases` gives the real merge bases' representatives in the viewer's history, reduced: the merge bases of the viewer's projected graph.

**Departures from §3–§4**, and what S13 must know:
* **Real generations are not shown, and must not order answers.** Hidden snapshots take part in them: a hidden change with a timestamp far ahead raises the generation of everything built on it. A log ordered by real generation is therefore not the order the viewer's own copy has (§6, row 1), and it hints at hidden work. S13 orders a log by what the viewer sees: their projected graph, and timestamps of visible snapshots. `Reader::listed_all` is unordered.
* **Not timing-safe yet** (row 4, S13): `visible` and `rep` walk hidden snapshots between visible ones, and `changes` decodes the whole object of a mixed change. Answers never depend on hidden data; their cost does.
* `rule_history` has no `policy_version` (line keys replace it). `derive_progress` has a `branch` column. The derived tables have no foreign keys (a cache; one write per row on YugabyteDB).
* **A root that differs from its parent's only in its encoding** is listed on the `none` list (admins only), while the S1 projection shows it to every reader as an empty change: under-shown, never over-shown. It needs a re-encoding push, which `vl` never makes.
* **Sealed directories** (pre-simplification cloaked folders) with a rule below them are seen by admins only, as `Projector` decides. A path's `prev` may then name the change that put such a directory there, which its other readers do not see. The simplification pass removes cloaked folders.

**Threat review (§6) for S12, and the tests** (`derived.rs`):

| Row | What S12 does | Test |
|---|---|---|
| 1, 2, 5 | lists per line; sources ranked so that each viewer gets the best they may read; viewer reads restricted to readable sides | `projection_equivalence`: random histories (merges both ways, renames and copies across the boundary, hidden-only and empty changes, far-future timestamps) and six viewers. For each viewer, the derived data of the real project read as that viewer answers exactly like the derived data of a copy built only from their projected history, read by its admin: visibility of every snapshot, list contents and sizes, every visible change's paths, entries, sources and per-parent file history, ancestry, merge bases, and file-history starts. No answer names a path the viewer may not read. Mutations caught: unfiltered sources, merges always visible, the `none` list readable by all. |
| 7 | secrets indexed by path, never content | `derived_on_landing`: through `vl` and the push route. Billing's `.env` is listed as a sealed entry, and its marker is in no derived object or row. |
| 8 | embargo lines withheld | `embargo_lines_are_withheld` |
| 10 | caps: 100,000 paths, 16 sources a path, similarity bounds, linear source collection | `hostile_changes_stay_bounded`: 3,000 identical files renamed at once (half hidden), and a change of 100,002 paths (`many`), whose file history stays exact |
| 11 | values a function of immutable inputs; marker rows last; one deriver per project | `derived_data_resumes_after_a_crash`: four crash-and-restart rounds, with racing derivers. The data equals the first run's, row for row and byte for byte. `derived_graph_matches_direct_walks`: ancestry, merge bases, depths, file-history starts and every `prev`, against direct walks. |
| 13 | lists of a new policy built before it is derived under | `policy_change_rebuilds_only_the_lines_that_moved`: the rebuilt lists equal those of a project derived under the new policy from scratch, and only moved lines were built |
| 10, 11 (adversarial pass) | timestamps clamped, batches bounded by rows and bytes, `many` rows by path, iterative reads, work per moved branch, `none` only for an equal tree | `s12_adversarial::bug_866`–`bug_871` (BUG-866 to BUG-871, `docs/BUGS.md`) |
| 3, 4, 6, 9, 12 | query-time rows: S13–S15 | — |

**Speed** (`derived_speed`; debug build on a shared, loaded development machine; 500 files, 5 lines, 1–4 files changed a landing, a merge every 50):

| | PostgreSQL 17 | YugabyteDB 2025.2 |
|---|---|---|
| Backfill of 20,000 snapshots (from nothing), two runs | 413 and 223 snapshots/s | 270 and 410 snapshots/s |
| One landing on top of 20,000 (40 landings), two runs | p50 9.6 / 7.1 ms, p90 22 / 9.2 ms | p50 61 / 16 ms, p90 110 / 27 ms |
| `is_ancestor(first, tip)`, `at_depth(tip, 1)` across 20,042 | 1.2 ms, 1.2 ms | 2.6 ms, 2.5 ms |
| `merge_bases(first, tip)` (one side below the other) | 1.2 ms | 1.7 ms |
| `merge_bases` of two branches whose base is 20,000 snapshots down | 707 ms | 661 ms |

After the adversarial pass's fixes (BUG-866 to BUG-871), a third run gave backfills of 359 and 410 snapshots/s, one landing p50 7.9 and 20 ms, `is_ancestor` 1.9 ms on both, and merge bases far apart 758 and 662 ms (PostgreSQL and YugabyteDB). The hostile cases, before and after:

| Case (`s12_adversarial`) | Before | After (PostgreSQL / YugabyteDB) |
|---|---|---|
| Memory deriving 48 / 96 snapshots of 50,000 changed paths each (BUG-867) | 1,156 / 2,247 MiB | 489 / 530 MiB (PostgreSQL), 466 MiB (YugabyteDB, 48): flat, the object and tree caches (256 MiB each) |
| One landing of 5,000 paths after 30 `many` changes (BUG-868) | 58 s (0.48 s with the folder just under the cap) | 191 ms / 479 ms, against 208 ms / 736 ms with the folder just under the cap |
| One landing with 3,001 branches (BUG-870) | 2.76 s (15 ms with one branch) | 36 ms / 16 ms, against 40 ms / 71 ms with one branch |
| 20,000 merges in a row, then `visible(tip)` (BUG-869) | stack overflow, the process aborts | answered |

The machine was shared with other agents' builds (load average 10–50), hence the spread between runs. The last row is the paint-down walking everything between the tips and the base. S13's target (5 ms on a million snapshots, §5) needs more for branches that far apart: a generation-ordered walk of the jump table on both sides, or merge bases memoised at branch tips.

The landing never waits for any of it. Deriving in batches is what keeps up: one run per landing reaches about 100–140 landings/s on PostgreSQL and 16–60/s on YugabyteDB (p50), while a batch derives 220–410 snapshots/s on either. Landings that arrive during a run are taken by the next run, so the worker batches itself under load. 1,000 landings/s into one project (phase 4) needs larger batches than that, or a faster per-snapshot path: S17 measures it. Release builds and a dedicated database are for the S16 gate run.

## 11. As built: S13, the query API (2026-11-07)

Code: `crates/veil-server/src/query/` (`mod.rs` the routes and answers, `graph.rs` the viewer graph, `trees.rs` projected trees), migration `0010_view_graph.sql`, six routes in `api.rs`, and one change in `derive::memo_tips` (as it memoises a landing's tips for every view key, it extends each view key's graph, the admins' included). Tests: `crates/veil-server/tests/server_hub/query.rs`. No repository format change.

**Routes** (`/v1/projects/{p}/q/…`; every answer carries `policy_version` and `work`, the rows and objects it read):

| Route | Answers |
|---|---|
| `GET log?rev=&n=&path=&after=` | a page of the viewer's history from `rev` (default: the default branch), newest first by generation (the corrected commit date), ties by id, so children before parents: `vl log`'s order (`topo_children_first`) wherever every snapshot is dated after its parents (BUG-1071, below); `n` ≤ 1,000 and about 8 MiB a page; `truncated` and `next`, a cursor naming the snapshots the rest of the log starts from. With `path`, only snapshots whose change against their first parent touches something the viewer may read at or under it |
| `GET show?rev=&path=&stat=` | a snapshot's fields and the viewer's part of its diff against its first parent (`veil.show/2`) |
| `GET tree?rev=&path=&after=` | a folder of the viewer's projected tree (`veil.tree/1`): entries with kind, id, size, executable, sealed; 10,000 a page |
| `GET file?rev=&path=` | a file's bytes: a blob's content, or for a secret (or a conflict) the stored object, which only key holders open; its entry in the `x-veil-file` header |
| `GET diff?from=&to=&base=&path=&stat=` | the diff to `to` from the merge base of `from` and `to` (`base=merge`, the default; the first by id when there are several) or from `from` (`base=from`): file diffs with renames and copies (`changes::sources` on the viewer's part), and unified hunks (`veil_core::hunks`, as `vl diff`) of plain-text files up to 1 MiB; secrets are never decoded. 10,000 files and 8 MiB of lines, then `truncated` / `content_truncated` |
| `POST ancestry {pairs}` | for up to 100 pairs of revisions: `is_ancestor` and the merge bases |

**The viewer graph** (departure from §3.2 and §3.4). Every query walks the commit graph of the viewer's projected history, never the real one: a `view_graph` row per (project, view key, projected snapshot), with the generation (the client's corrected commit date, as the real graph computes it), first-parent depth, parents, embargo flags, the jump table, `down` (the nearest snapshot below on the first-parent line that is a merge or the root) and one real snapshot it projects (where its trees come from). A row is a function of the projected snapshot objects alone, exactly what the viewer's own copy of the project would derive, so:
* **a log is ordered by what the viewer sees** (S12's item 1): real generations, which hidden snapshots raise, order nothing; the viewer's own generations order it (each `view_graph` row's generation is computed from the projected snapshot and its projected parents' rows; nothing in `query/` reads S12's `graph` table). `query_projection_equivalence` pages through every branch's log as each viewer and compares the order and every cursor with the copy's, and with the order computed straight from the copy's snapshots; a variant ordering by S12's real generations fails it at once. **Departure from §3.2** (BUG-1071): not the client's lazy Kahn walk (`topo_iter`, newest first by timestamp among snapshots whose children are all shown), whose one step may explore the whole history when a merge takes in a snapshot dated far behind; the log walks newest first by generation, which needs nothing but each emitted snapshot's parents, so a page's work is bounded by its budget at every step and the cursor is exactly the walk's frontier. The two orders are the same wherever every snapshot is dated after its parents (tested against brute force on histories with timestamps far ahead and far behind: children always first). **Decided** (the orchestrator, under the owner's delegation, 2026-11-07): the server keeps this order, and S16 makes `vl log` use it locally too (the client's history index already holds corrected generations), so thin and full clones list history alike. Each step reads one row: a snapshot's parents wait and are read one at a time, so a page stops between any two reads, also inside a wide merge (BUG-1078; and at push, a snapshot may have at most 64 parents);
* **a query's work is proportional to what the viewer sees** (S12's item 2): it reads viewer rows, projected snapshots and projected trees only. Hidden snapshots are walked once per view key, when the graph is filled from the projection memo (`graph::extend`): eagerly by `memo_tips` after each landing, and by a query that names a tip not in it yet (in the background: below).

**First fills are bounded, run once, and never inside a request.** Filling a view key's graph for a whole history costs what projecting it costs (80 s for anyone on Earth on 20,000 snapshots in a debug build, almost all of it S1's `sync::projected`). So:
* **once:** a fill is one background task per project and view key on a server (`graph::ensure`), registered and started the moment anyone needs it (BUG-1074); its task takes the view key's lease first (a row in `view_fills`, taken, renewed and given back by single statements: one server at a time, and no database connection held while a fill runs, BUG-1073), then one of the server's `MAX_FILLS` (4) slots (so a fill waiting for another server's lease holds no slot, BUG-1075), and runs its statements one at a time. Every query and landing that needs it joins it;
* **outside requests:** a query waits for it only until its own deadline, then gets `warming` (503) while the fill runs on to the end; no request's deadline bounds, or pays for, a first fill, and a hundred anonymous requests cost one fill;
* **warm at landing:** after each landing `memo_tips` queues the fill of every view key of the project's people, anyone on Earth's and the admins' (`graph::prefill`, as S12's eager memos) and does not wait for them: the deriver holds no connection, lock or slot while fills run, so a long first fill holds up no derivation (and BUG-911's deriver-pool permit, when it lands, is not held across them). After the first fill a landing adds a few rows per new snapshot and view key, and queries find the graph filled;
* **few view keys:** a view key is a function of the accepted policy and of who reads which access lines, which come from the server's records (admins, group members, people named on a line: `perm`), never from a request. Anyone can sign up, but someone with no access reads exactly what anyone on Earth reads, and has their key. So the keys, and the fills, anyone can cause are bounded by the distinct read sets of the project's people (at most one per person, and at most 2 to the number of lines) plus two; only admins and group managers, by changing who is in a group, make new ones. A new policy makes new keys, which its own landing warms.

Admins have a graph too (view key `admin`, of real history), so every viewer runs the same code. The per-rule lists of S12 (`derive::view::Reader`) are not used by these routes; they stay for blame, file history and search (S14, S15). `log -- PATH` walks the viewer's graph and compares the path's projected entries in each snapshot and its first parent (walked down both trees at once, stopping where they meet), within a work budget per page (20,000 reads, then a cursor): its cost depends only on the viewer's history.

**Revisions.** A branch name, or a snapshot id of the viewer's own history: one in their graph, or one the projection memo holds under their view key (then the graph is filled up to it). Admins may name any committed snapshot. Real ids are accepted from nobody else, so a hidden snapshot's id gets what a missing one gets (`no such revision that you can see`, by the same code path); a cursor names snapshots of the viewer's graph only. Paths are checked by syntax alone, then looked up in the projected tree, where a hidden path is simply absent: hidden and missing paths get the same error body.

**Embargo lines** (a snapshot with an embargo, or above one) are withheld from every viewer, admins included, until S22 decides releases: they cannot be named, and no walk from a snapshot off the line reaches one (the flag is inherited by children only). The server still refuses embargoed pushes, so only a history written into the database (the tests) has them.

**Merge bases of distant branches.** The paint-down (as the client's) passes over a snapshot painted by one side only while its generation is above the other tip's (nothing above it can be common), and along a merge-free first-parent run it jumps through the jump table (`run_end`: to `down` when the whole run is above the cut-off, else as far down as stays above it). On a line with a merge every 50 snapshots that is a few rows per merge instead of one per snapshot; on a linear line, tens of rows for any distance.

**Bounds** (row 10): `n`, page bytes, a log page's work budget (20,000 reads, checked at every step of the walk: a log filtered by path reaches it, others hardly can), rename detection in a diff (16 MiB of line-hash tables held, counted as the tables' memory, BUG-1077; 64 MiB read; every file read counted as work and checked against the deadline, BUG-1072; at most 4 passes at once in the process, the deriver's included, BUG-1077), concurrent first fills (4 a server: BUG-1073), a cursor of up to 1,000 snapshots in the request (a wider frontier is kept by the server and named by a token, `frontier-<hash>`, in `log_cursors`, keyed by the viewer's key and the hash of what it names, so the same frontier is one row and another view key cannot use it; a frontier wider than 10,000 ends the page before it, so a row is at most about 650 KB; BUG-1076). **Kept cursors are bounded** whatever anyone asks, anyone on Earth included: one row a request; a row lives an hour from its last writing and is never served after; and every write deletes the project's expired rows and then its oldest rows past 32 MiB in all, so a cursor may be dropped while someone pages (it is then refused, and the log is asked for again from its start), diff files and line bytes, listing size, 100 ancestry pairs, paths (4,096 bytes, no `.`/`..`/empty parts), revision length; every query has a 2 s deadline, past which it fails with `deadline` (never a shorter answer, whose length would depend on the machine). A cut by a bound is a function of the viewer's history, so the copy cuts at the same place.

**Departures and limits:**
* Answers use the field names of `docs/reference/json.md` where they apply server-side (no workspaces, tags or tiers); timestamps are milliseconds. S16 renders them as `vl` does.
* `blame`, `history`, `grep` and `search` are S14 and S15; narrowed agent sessions (row 12) wait for phase 2's sessions.
* Rows of a view key that no longer exists (a policy changed what someone reads) stay, like the projection memo; nothing purges either yet. Until a new view key's first fill is done, its queries answer `warming`.
* Residual timing (row 4): the projector reads the directories that hold an access rule (bounded by the policy, not by history), decoding a tree costs its hidden entries too, and a query that arrives before a landing's fill reached its view key gets `warming` for a time that grows with the hidden snapshots that landing brought (the fill walks them): a duration, once per landing and view key, the same quantity S1's pull already shows (a pull right after a landing waits for that projection too). The `work` counter counts the viewer-visible reads only, so it shows none of these; their cost is bounded by the policy, by one tree's size and by one landing's snapshots.
* A log over more than 10,000 open lines at once (more than any cursor the server keeps) answers `this history is too wide to page` instead of a cursor that goes nowhere. Kept cursors of projects nobody pages again stay until that project's next write (at most 32 MiB a project).
* BUG-1070 (S1's `history` and `fetch` accept real ids of hidden snapshots) is recorded, not fixed here.

**Threat review (§6) for S13, and the tests** (`query.rs`):

| Row | What S13 does | Test |
|---|---|---|
| 1, 2, 5 | every answer computed on the viewer graph and projected trees; sources of renames from the viewer's part | `query_projection_equivalence`: random histories (S12's generator: merges both ways, renames and copies across the boundary, hidden-only and empty changes, empty folders, far-future timestamps) and six viewers; for each, about 1,100 answers (log pages followed to the end, with and without paths and small budgets, show, tree, file, diff with both bases and paths, ancestry) as the viewer equal **byte for byte, `work` included**, the copy's admin's answers on a project built from their projected history; no hidden path string and no real id of a snapshot they see differently in any answer. Mutations caught: real trees instead of projected, real ids accepted, hidden snapshots kept in the graph, work that depends on hidden content |
| 4 | work counted on viewer-visible reads only | `query_work_ignores_hidden_content`: two projects that differ only in hidden files and runs of hidden changes (dated far ahead) give a restricted viewer identical answers and work for every query; and row 1, which compares `work` |
| 6 | hidden and missing revisions and paths: one error, one code path | `query_hidden_and_withheld_are_missing`; over HTTPS, `query_routes_serve_each_person_their_part` compares the bodies byte for byte |
| 7 | the viewer graph holds ids and numbers; `file` serves a secret's ciphertext; no hunks of sealed content | `query_routes_serve_each_person_their_part`: finance's `file` of `billing/.env` has no plaintext marker |
| 8 | embargo lines withheld from everyone | `query_hidden_and_withheld_are_missing` (by branch, by id, from the log; for anyone and for admins) |
| 9 | no answer cache; the viewer and their view key come from the records on every request | `query_routes_serve_each_person_their_part`: removed from finance, the next query gets `billing/` as missing |
| 10 | the bounds above; a first fill once per view key, in the background, joined by every request (`warming` at their deadlines); view keys from records only | `query_hostile_inputs_are_bounded`; `query_first_fill_runs_once_in_the_background` (24 requests at once from anyone on Earth and from sign-ups without access, with a 5 ms deadline: one fill, which finishes after they gave up; mutation caught: a fill per request) ; `query_landing_fills_the_viewer_graphs`; `s13_adversarial::bug_1071`–`bug_1073` (a log page's budget at every step, a diff's rename detection at the caps, 24 cold fills at once on a pool of 16) |
| 11 | rows a function of projected objects, written parents first, `ON CONFLICT DO NOTHING` | `query_concurrent_extensions_agree` (six extenders per view key at once write what one writes); `query_graph_matches_direct_walks` (ancestry, merge bases and log order against brute force, 700-snapshot histories with long runs, merges every way and skewed timestamps) |
| 13 | a new policy gives new view keys, whose graphs are built from their own projections | `query_follows_policy_changes` |
| 3, 12 | ranking: S15; narrowed sessions: phase 2 | — |

**Speed** (`query_speed`, PostgreSQL 17, through `bench-quiet.sh`; 20,000 snapshots, 500 files, 1–4 changed a snapshot, a merge every 50, a hot file changed every 10th snapshot, two branches whose merge base is the 11th snapshot; anyone on Earth cannot see two fifths of the files; 20 rounds after a warm-up). Release build, load 14.3 before and 24.0 after; debug build in brackets, load 16.0 before and 8.3 after:

| Query | Target (p99) | admin p50 / p99 | anyone on Earth p50 / p99 | rows read (admin / anyone) |
|---|---|---|---|---|
| `log -n 50` | 20 ms | 0.5 / 0.7 ms (3.3 / 6.0) | 0.7 / 0.9 ms (4.6 / 8.9) | 103 / 123 |
| `log -n 50 -- PATH` (hot file) | 50 ms | 5.1 / 6.9 ms (44 / 55) | 5.8 / 8.3 ms (47 / 83) | 3,967 / 2,945 |
| merge bases 20,000 apart | 5 ms | 0.9 / 1.5 ms (5.8 / 11.7) | 1.0 / 1.6 ms (6.0 / 6.1) | 12,390 / 12,425 |
| `is_ancestor(root, tip)` | 5 ms | 0.03 / 0.04 ms | 0.02 / 0.05 ms | 26 / 22 |
| `diff` against the merge base, 100 files | 50 ms | 3.1 / 4.7 ms (21 / 29) | 3.2 / 5.3 ms (21 / 23) | 225 / 225 |
| `file` | 10 ms | 0.2 / 0.3 ms | 0.2 / 0.3 ms | 6 / 6 |
| `tree` | 10 ms | 0.3 / 0.3 ms | 0.3 / 0.4 ms | 5 / 5 |

S12's paint-down took 707 ms (debug) for the same merge bases. The merge-base walk still visits every merge on the line (here 400 of them, a few rows each); a line without merges costs tens of rows. Filling a view key's graph for the whole 20,000-snapshot history (once, in the background) took 3.3 s for the admins and 41 s for anyone on Earth in release (80 s in debug), almost all of it S1's projection of every snapshot for that key (what `tips` pays today); after that, a landing costs a few rows per new snapshot and view key.

## 12. As built: S15, search (2026-11-07)

Code: `crates/veil-server/src/search/` (`index.rs` the index and its updates, `segment.rs` segments and merges, `pattern.rs` words, regular expressions and the trigrams they need, `mod.rs` the routes), migration `0016_search.sql`, two routes in `api.rs`, one call at the end of `derive::landing` (the index follows the derived branches, in its own task), and `vl search` (`crates/vl/src/search_cmd.rs`, with one method `Client::query` in `crates/vl/src/hub.rs`). Tests: `crates/veil-server/tests/server_hub/search.rs`. No repository format change. `docs/HUB.md` §13.23 is the summary.

**Routes** (`/v1/projects/{p}/q/…`; every answer carries `policy_version` and `work`):

| Route | Answers |
|---|---|
| `GET search?q=&rev=&kind=code&path=&lang=&n=&after=` | files at the tip of branch `rev` (default: the default branch) holding every word (ASCII case folded), best first by BM25, with their first matching lines (`veil.search/1`); `files` (how many matched), `complete` (every candidate read), pages of `n` ≤ 100 with a cursor `after` (score and path) |
| `GET search?…&kind=path` | every path the project's history ever held whose name holds every word: a word in the file's name weighs more, a path at the tip of `rev` more still (`at_rev`), a long path less |
| `GET grep?pattern=&rev=&i=&path=&n=&after=` | the lines matching a regular expression (the `regex` crate: linear time, 1 MiB compiled, 4 KiB pattern), file by file in tree order, `n` ≤ 1,000 files a page, 1,000 lines a file, a cursor (the last path read) (`veil.hub-grep/1`). At a branch whose index is built: the index narrows the files read. At any other revision (a snapshot id of the viewer's history): a scan of the viewer's projected tree (S13's `Trees`) |

**Decided here (departures from §3.5, §4.2):**
* **Two indexes, sharded by S12's line keys** (`derive::lines`), not by policy version: `code`, per branch, every file at the tip (content trigrams for plain files of at most 1 MiB with no NUL byte; path only for secrets, binary files, links, conflicts and sealed folders); `names`, once per project, every path any branch's history held (its S12 changed-paths objects: the leaves each snapshot introduced), with path trigrams. Path search over all history is per project, not per branch: a branch's own history would need a walk of everything below every new branch.
* **Who reads a line is not part of its key** (S12's design): a group added to a line, or a line made `public`, changes no shard, and applies at the next request. A policy that changes which paths a line decides (a line added below another) gives new keys; their shards are built from the tip's tree (code) or from every old name (names) at the next landing or query, and the others are kept as they are (same segments). Until then the branch answers `indexing` (503, like S13's `warming`): never a result outside the new access (row 13). The table `search_segments` of §4.2 became `search_heads` and `search_shards` (one row per shard, its segments as a JSON list).
* **A new branch starts from the default branch's segments** (shared objects) and the diff of the two tips; a branch force-moved anywhere is a diff of trees too, so the code index never walks history.
* **Descriptions are not searched** (the S15 row has names and code). Product decision 1 of §9 therefore holds trivially; description search, when built, belongs on the viewer graph (a `log` filter, S16 or later), where whether a merge is in a viewer's history is known.
* **Open PRs** (product decision 2): PR heads are indexed when S21 makes them branches or adds a call to `index::landed`; nothing else is needed.

**How a query stays per viewer.** It opens only the shards of `Lines::readable(view)`. In each, a document of segment `i` is live unless a newer segment holds a document or a tombstone at its path. Every number of an answer is a function of the live documents of those shards alone:
* candidates: the live documents holding every trigram a match needs, in tree order; each read is one unit of `work`;
* the bounds that stop reading (4,000 files or 32 MiB for a ranked search, 100,000 names, 20,000 files or 256 MiB for a grep page; `complete: false` or a cursor), cut in that order;
* BM25's statistics: live text documents and their bytes (kept per shard, exact functions of the tip's tree), and, per word, the live documents holding its trigrams;
* scores (integers in millionths, ties by path), pages and cursors.

So the answer, `work` included, equals the one on a copy of the project built from the viewer's projected history (one shard, `none`), whose layout of segments is different. **What `work` does not show, and is the stated bound** (rows 4 and 10): the postings read (they include dead documents of the viewer's shards, at most half their live ones plus 64, and depend on how landings batched); the number of the viewer's shards; and decoding segments (cached, 256 MiB a process). None depends on hidden content: a hidden file is in a shard the viewer never opens. A hidden file's trigrams never touch a visible file's rank.

**Building, bounded** (row 10): a segment is written at 32 MiB of content, 4 million postings or 100,000 documents; the newest two segments of a shard merge while the older is at most twice the newer and together under 64 MiB (sizes stay geometric); more than 64 segments merge their smallest neighbours; a code shard whose dead documents pass half its live ones (and 64) is rewritten group by group (each under 64 MiB, newest first, shadowed by the paths after it). A name walk writes every 500,000 names. At most 2 updates run at once in a process, one per project, on the deriver's pool (BUG-911), coalescing landings like the deriver.

**Consistent across servers** (row 11): segments are immutable, content-addressed objects written before any row names them; a head and its shards change in one transaction that compares and swaps the head's version, so a loser starts again from the winner's state; readers read the head, the shards, then the head again. A crash leaves at most unreferenced segment objects.

**Limits:**
* Unreferenced segments (merged away, or written by a loser of a race) stay in the object store until S29's garbage collection; heads of deleted branches stay (a few rows) until a purge (§8, item 5).
* A first walk of a long history for names runs in one background update (its memory is the walk's visited set and up to 500,000 names); it is not resumable halfway (a crash restarts it).
* Timing residuals (row 4): `indexing` after a policy change, and an index behind its branch tip while the update after a landing runs (the answer names the snapshot it searched); both durations depend on how much the update does, hidden files included, once per landing, as S13's `warming` after a landing.

**Threat review (§6) for S15, and the tests** (`search.rs`):

| Row | What S15 does | Test |
|---|---|---|
| 1, 2, 3 | shards of the viewer's lines only; counts, statistics, scores, pages and `work` from their live documents | `search_projection_equivalence`: S12's random histories (merges both ways, renames and copies across the boundary, hidden-only and empty changes, far-future timestamps) and six viewers; for each, 56 queries (ranked code and name searches with words from every file and path, hidden ones included, folders, a language, page sizes and small bounds; greps by branch and by the viewer's own ids, case folded or not, with folders and bounds), each followed through every page, equal **byte for byte, `work` included**, the copy's admin's; no hidden path in any answer. Mutations caught: every shard opened, dead documents counted as live |
| 4 | work counts candidates read, a function of the viewer's live documents | `search_work_ignores_hidden_content`: two projects that differ only in hidden files full of the words searched for, and runs of hidden changes dated far ahead, give a restricted viewer identical answers and work for every query |
| 6 | a hidden match and no match: one answer; hidden and missing revisions: one error | `search_routes_serve_each_person_their_part` (bodies compared, the echoed query aside); the harness's revisions include a hidden real id |
| 7 | secrets by path only, objects never opened | `search_finds_secrets_by_name_only`: a secret's object holding plaintext (as a broken client might upload) is in no segment and found by no search or grep, admins included; its name is found by those who see its folder; over HTTPS with `vl`'s real sealed `.env`, no segment holds its marker |
| 8 | embargo lines never indexed or walked | `search_withholds_embargo_lines`: an embargoed fix's names and strings are found by nobody (admins included), its branch and ids are no revision, and no segment or head names them |
| 9 | no answer cache; the viewer's lines from the records at every request | `search_routes_serve_each_person_their_part`: removed from finance, the next search finds nothing of billing |
| 10 | the bounds above; linear regular expressions; a deadline that fails the query | `search_hostile_inputs_are_bounded`: refused queries and patterns, `(a*)*b` over 1 MiB, 100,000 matching lines in a file, files over 1 MiB and binary ones skipped, candidates past the bound (`complete: false`, the same each time), a grep paged past 40 pages, a zero deadline |
| 11 | immutable segments, compare-and-swap heads, merges and rewrites of dead documents | `search_increments_equal_a_fresh_build`: 70 landings (edits, renames and deletions across the boundary, merges, a second branch), each indexed by two servers at once, answer for three viewers exactly as an index built from nothing; shards stay under their segment and dead-document bounds |
| 13 | keys name paths, not readers; changed keys rebuilt, `indexing` until then | `search_follows_policy_changes`: a line made public needs no rebuild and is found at once; a line added below another answers `indexing`, then rebuilds only the changed keys (kept shards keep their segments) and answers as an index built from nothing |
| 5, 12 | blame (S14); narrowed sessions (phase 2) | — |

**Speed and size** (`search_speed`, release build, PostgreSQL 17, objects on local disk, through `bench-quiet.sh`, load 5.1 before and 6.0 after; 20,000 files of about 5.7 KiB of code-like text, 111 MiB, in five folders of which anyone on Earth reads two fifths, 30 snapshots; 20 rounds after a warm-up):

| | admin p50 / p99 | anyone on Earth p50 / p99 | work (admin / anyone) |
|---|---|---|---|
| first index (code and names), once | 1.17 s: 40,006 documents, 10 segments, 26.4 MiB of index for 111 MiB of content (**0.24 bytes a byte**) | | |
| one landing of 3 files (both indexes) | 9.4 ms p50, 12.6 ms max | | |
| code search, a common word (bound: 4,000 files read) | 72 / 78 ms | 64 / 72 ms | 4,000 / 4,000 |
| code search, two common words | 72 / 83 ms | 68 / 70 ms | 4,000 / 4,000 |
| code search, a rare word | 7.0 / 10 ms | 2.9 / 4.0 ms | 666 / 274 |
| path search (`file_1`: 11,111 / 4,444 names hold it) | 18 / 24 ms | 9.0 / 15 ms | 11,111 / 4,444 |
| grep at the tip, a rare word | 13 / 18 ms | 5.3 / 6.6 ms | 1,106 / 442 |
| grep at the tip, a page of 100 files | 5.2 / 7.6 ms | 2.9 / 5.3 ms | 100 / 100 |
| grep scan at an old revision, a rare word (a page: 20,000 files read) | 208 / 215 ms | 83 / 87 ms | 20,049 / 8,024 |

Against §5's targets: code search stays under 200 ms however large the project, because a ranked search reads at most 4,000 candidates (32 MiB) and says `complete: false` past them; the postings it intersects grow with the viewer's shards (26 MiB of index per 111 MiB here, so about 2.4 GB for 10 GB of text, decoded once into the 256 MiB segment cache per process: at that size the cache, not the query, is the limit, and the 10 GB gate run of S16 is what measures it). Path search meets 20 ms for a word in a few thousand names and takes 24 ms (p99) for one in 11,111; a narrower word is faster. Building is about 95 MiB of content a second; a landing's update costs milliseconds. An earlier run with a bound of 10,000 files gave 287 / 316 ms for the common word (load 78 after), hence the lower bound.
