# Phase 3: history answered by the server

> **Status: design, not built** (2026-11-06). Base: `integration` @ `3851159`.
> Sources of truth: `docs/OVERVIEW.md` and `docs/VISIBILITY.md`; where this document disagrees with them, they win. The server as built is `docs/HUB.md` §13; projected history is §13.4. The roadmap is `docs/design/scion-for-developers.md`, phase 3 (items 3.1–3.6). The client's commit-graph index (`docs/design/scale/3-history-index.md`, built) is the model for the server's.

## 1. Goal

Every history question is answered **by the server, through the API, with no checkout, in milliseconds to low hundreds of milliseconds**: log, blame, file history, diff against the merge base, a file at a revision, and search by path and by code. Answers are **projected per viewer**: someone who cannot see a folder never learns its files' names or contents, not from results, counts, ranking, timing, or blame lines.

This phase is what lets thin clients (phase 2) hold no history, and what CI, review and bisect (phase 4) ask instead of checking anything out.

The design check:

| Rule | How this phase keeps it |
|---|---|
| Server-centric, always connected | History lives on the server; `vl log`, `blame`, `grep` in a thin clone ask it. |
| Code is plain text behind the server's checks | The server indexes plain-text code, and every answer passes the one access function (`HUB.md` §4.6). |
| Only secrets and embargoes are encrypted | Secrets and unreleased embargoed content are never indexed in the clear: the server cannot open them, and does not try (§6, rows 7–8). |
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
| **Unreleased embargoed content** | **no**: wrapper trees are opaque to the server, and embargo lines are not indexed until release (§6, row 8). After release, the content is ordinary and is indexed |
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
| 8 | Person outside an embargo's groups | searches, blames, logs | learns the fix before release | wrappers are opaque; embargo lines are not indexed or listed until release; the per-rule lists skip embargoed snapshots for viewers outside the groups | embargoed fix with distinctive names and strings: no query by an outsider finds them before release; all do after |
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
| **S16** | `vl` over the query API, and the phase 3 gate | thin clones answer `log`, `blame`, `show`, `diff`, `cat -r`, `grep` through the server; `veil-bench query`; the gate run | S3, S13–S15 | `crates/vl`, `crates/veil-bench` |

## 8. Open technical questions

1. **Generation numbers on the server:** corrected commit dates (as the client's) need only that they decrease along every edge; a hostile timestamp only lengthens a walk. Keep the client's definition for one meaning everywhere.
2. **Per-rule lists for viewers with many lines** (an admin with 200 lines): merging 200 lists is slower than walking real history. Use the real walk for viewers who may read everything (admins, and any view key that covers every line); measure the crossover.
3. **Policy versions with many lines changing at once** (a reorganisation): the rebuild can take minutes on a large history; is the intersected answer (§3.4) good enough during it, or should the policy's acceptance wait?
4. **Blame memo size:** one object per file version can be large for generated files; cap by size and compute on demand above it.
5. **Purging.** When a secret is committed into an ordinary file by mistake (a scanner miss) and an admin purges it, its derived data (search segments, blame objects) must be purged too. The purge itself is not designed yet; the derived-data framework must support dropping every value that depends on an object.

## 9. Product decisions for the owner

1. **Descriptions of mixed changes in search and blame.** S1 shows a change's description to anyone who sees part of it (`HUB.md` §13.4). Search over descriptions would then find words describing hidden work. Recommendation: search descriptions only of changes the viewer sees whole (every path readable); show mixed changes' descriptions in log and blame as today.
2. **What code search covers.** Recommendation: `main`, branch tips and open PRs for content; every path ever for names. Indexing all history's content costs storage roughly proportional to history and is rarely needed; `vl grep -r REV` covers old revisions by scanning.
