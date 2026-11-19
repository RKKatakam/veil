# Purge: removing named content from a server, offline

> **Status: design, not built** (2026-11-19, branch `t3/design-purge-offline` from `integration` @ `a7ea62b5`). Building it is the owner's decision: it is a new command. §12 lists what the owner must decide.
>
> **Sources of truth:** `docs/OVERVIEW.md`, `docs/VISIBILITY.md`, `docs/ARCHITECTURE.md` ("Threat model"), and the repository rule "don't fight the distributed system" (`CLAUDE.md`).
>
> **Code citations** are `file:line` under `crates/veil-server/src/` unless a crate is named, as of `t3/batch-1` @ `ff47b2d8` (`integration` plus the `objects` layout). Lines move; the names beside them do not.
>
> **Nothing was run for this document.** Where the code was not read far enough to be sure, the text says "to confirm when building".

## 1. Summary

Veil v1's storage is append-only, with no garbage collection (owner, 2026-11-18). Nothing a project's history named is ever deleted. That still leaves one deletion somebody must be able to make on purpose: customer data committed by mistake, a credential in a file Veil did not recognise as a secret, content that must go for legal reasons.

**The design, in seven rules:**

1. **One command, run by the operator on the server's machine, with every server stopped:** `veil-server purge`. It is a dry run unless `--apply` is given.
2. **It removes file contents:** blob objects, named by id or found by path. File names, descriptions and people's comments are not removed in the first version (§3.3).
3. **It refuses while any server serves.** Serving servers hold a shared session lock in the database; the purge takes it exclusively (§8). There is no `veil-server gc` and no other offline step to borrow this from: it is the purge's own.
4. **A purged object leaves a tombstone:** a row saying that this id of this project was purged, when, and by which purge. Snapshot and tree ids do not change. A read of the content answers `purged`, never "missing", "corrupt" or a crash (§5).
5. **The content cannot come back by accident:** an upload that holds a purged id is refused (§5.3).
6. **What was derived from the content is dropped and rebuilt:** the project's code search index. Regional caches empty themselves when they see that a purge happened (§4).
7. **Every purge leaves a plain-text record** of who, what, when and why, without the content (§7).

**What a purge cannot do, said first** (§6): it cannot reach copies on people's machines, and for a leaked credential it is not the fix. **Rotate the credential. The purge only tidies.**

## 2. Why offline, and why that is enough

Every hard part of deleting from a running Veil server is about other writers. The code that exists for garbage collection shows the price: a gate that queues the transactions that add roots (`guard_root_write`, `pack_gc.rs:805`), an epoch that writers read and a delete raises twice (BUG-1881, BUG-2602, BUG-2621; `docs/HUB.md` §13.37), a second read of the roots under the lock. All of it answers one question: what if a push names the object while it is being deleted?

With every server stopped the question does not exist:

- no push, API commit or landing can add a reference to the object, or store it again, during the purge;
- no server process holds the content in memory: the processes are gone, and their caches (`caches.rs:305`, the object cache of `store.rs:604`) went with them;
- the tombstones change only while no server runs, so a server reads them once when it starts and keeps them in memory. No feed, no invalidation, no check per request against the database.

The cost is downtime: minutes for a project in the `objects` layout, longer where packs must be rewritten (§4.1). That is the kind of cost the repository rule tells us to accept. A purge is rare and deliberate; an hour of maintenance for it is fine.

## 3. What the admin names

### 3.1 The command

```text
veil-server purge --project NAME (--object ID … | --path PATH [--from SNAPSHOT] [--to SNAPSHOT])
                  --reason TEXT [--requested-by NAME] [--apply]
veil-server purge --resume          # finish a purge that was interrupted
veil-server purge --list            # the record of every purge, without content
```

It takes the database URL and the storage settings as `veil-server` does (`main.rs:250`), so it runs where a server runs, with the credentials a server has.

- **`--object ID`**: one blob id, as trees name it. Repeatable.
- **`--path PATH`**: the command finds the ids itself. It walks every snapshot the project's roots reach and collects each id that `PATH` named. The walk and its roots exist: `collect_db_roots` (`pack_gc.rs:2750`) reads every table that names a snapshot (branches, change refs, the landing queue, PR revisions, embargo lines, checks, bisects: `STAMP_TABLES`, `pack_gc.rs:688`), and `walk_from_roots` (`pack_gc.rs:2935`) reads snapshots and trees from them. `--from` and `--to` narrow it to the snapshots between two points of one line, for "the versions that held the key", when later versions are fine.
- **`--reason`** is required. It is the operator's words for the record: "customer export committed by mistake, ticket 4411". The command refuses a reason longer than 500 bytes, and the record shows it as typed, so the operator must not paste the content into it.

### 3.2 How the content is found without exposing it further

The project's admin already sees everything in the project (`docs/VISIBILITY.md`, the roles table). They tell the operator a project and a path, or an object id. Neither is the content.

The dry run prints, for each id it would remove:

- the id, its size, and where it is stored (its key, or the packs that hold it);
- how many snapshots name it, and at which paths. An id is content, not a place: the same bytes at another path are the same object, and go too. The operator sees that before applying;
- which branch tips still name it (§3.4).

The dry run never prints a byte of the content. Its output does name paths, some of which may be hidden from most people (private folders, embargo lines). The operator is trusted with the whole store; the dry run's output is theirs to handle, and is not what is recorded (§7).

### 3.3 What the first version does not remove

- **File names.** A name lives in a tree object. Removing a tree makes a whole directory unreadable at those snapshots, and the names index of search holds every path any snapshot held (`search/index.rs:12`). Not in the first version.
- **Descriptions.** A description is inside its snapshot object, and every later snapshot names that object as a parent. Not in the first version.
- **Text people or runners wrote:** PR titles, bodies and comments (`migrations/0017_prs.sql:28`, `:89`), check summaries and logs (`migrations/0025_ci_and_tested.sql:23`, `:25`), branch names. The server did not derive these from the file, and cannot know whether someone pasted the secret into a comment. The dry run prints how many of each the project has and says to read them.
- **Other projects.** Every object key starts with its project (`store.rs:129`, `pack.rs:94`), so another project that holds the same bytes has its own copy. A purge is of one project; run it for each.

### 3.4 Branch tips

A purge removes history's copies. It should not break the line everyone works on.

- **The default branch's tip still names the id: the purge refuses.** Remove or replace the file with an ordinary change first. That takes a minute and leaves a normal record.
- **Other branches' tips still name it: the purge goes on, and says so.** An agent's stale branch must not be able to block a legal removal. The dry run lists those branches. After the purge, a checkout of one of them answers `purged` for that file until the branch is rebased onto a line where the file is fixed. A rebase of a branch that never touched the file needs none of the purged content.

## 4. Every place the server holds the content

| Place | What it holds | What the purge does |
|---|---|---|
| Object storage, `objects` layout | the object under its own key, `p/<project>/<2 hex>/<62 hex>` (`store.rs:129`) | deletes the key (`delete_key`, `store.rs:1969`) |
| Object storage, `packs` layout | the object inside one or more listed packs, `p/<project>/pack/<name>` (`pack.rs:94`); a pack holds many objects | rewrites each pack that holds it without it, then deletes the old pack (§4.1) |
| Upload containers | an upload request is staged as one pack-format container until a push keeps it (`stage`, `store.rs:1301`; states `STAGED`, `DISCARDED`: `pack.rs:89`, `:91`) | discards every staged and discarded container of the project (§4.2) |
| The code search index | trigrams of each plain-text file's content at each branch tip, in segment objects (`search/segment.rs:3`, `search/index.rs:8`); a dead document stays in old segments until its shard is rewritten (`search/segment.rs:10`) | drops the project's code index; it is rebuilt from the tips (§4.3) |
| Blame, changed paths, file history | no content: a kept blame holds origins, line ranges and change summaries (`derive/blame.rs:125`); a changed-paths object holds "only paths, entries and scores" (`derive/changes.rs:28`) | nothing |
| Projections per view | snapshots and trees made for a view, and rows mapping real ids to projected ones (`migrations/0001_initial.sql:86`). A projected tree names the same blob ids | nothing: the tombstone covers the blob under every tree that names it |
| Database rows | ids, paths, people's text. No file content: the schema inventory lists every column of every table (`OBJECT_SCHEMA_COLUMNS` and `NON_OBJECT_SCHEMA_COLUMNS`, `pack_gc.rs:2559`, `:2621`) | the tombstones and the record are added (§5.1, §7) |
| Server memory | decoded objects, trees, sessions (`caches.rs:305`) | nothing: the servers are stopped |
| The servers' data directories | identity, keys, `stats.json`; objects only when storage is a local directory (`main.rs:244`), which goes through the same store interface | nothing more |
| Regional caches (`veil-server cache`) | every object that passed through, on disk, served under a grant without asking the server again (`cache/mod.rs:5`, `cache/disk.rs:124`) | each cache empties its store when it sees that a purge happened (§4.4) |
| Logs | the server prints errors to stderr (`error.rs:102`–`:149`); the invariant is that no content reaches a log | not edited; §6 |
| The bucket's own history, backups | old versions if the bucket has versioning on; backups of the bucket and of the database | not reachable by Veil; the command checks and warns (§6) |

### 4.1 Packs: rewrite, switch, delete

A pack is never edited in place. For each listed pack that holds a purged id (the pack indexes say which: `in_pack`, `store.rs:940`):

1. write a new pack with every other object of the old one;
2. in one database transaction, list the new pack and remove the old one's row;
3. delete the old pack from the store, at once.

This is the order `compact_batch` already uses to drop objects from packs (`pack_gc.rs:1478`), and the purge should call it with "drop these ids" in place of "drop what nothing reaches". Two things differ, both simpler because nobody serves: there is no gate and no epoch, and the old pack is deleted immediately, with no grace period for readers that might still hold its listing.

A stop between steps 2 and 3 leaves an old pack in the store that no row names. `--resume` deletes it: the purge's record lists the packs it is replacing before it starts (§9).

Cost: a pack holding a purged object is read and written whole. In the `objects` layout, the default, there is nothing to rewrite: one delete per object.

### 4.2 Upload containers

In both layouts an upload request sits in a container until the push that names it answers. When the servers were stopped, some may be left: uploads no push named yet, and discarded ones not yet swept. Any of them may hold the content, for example from someone's push of the same file an hour ago.

The purge discards every staged and discarded container of the project. Nothing is lost: a push that was between its upload and its answer when the servers stopped finds its receipts no longer good, and uploads again. To confirm when building: that `vl` does so without the person's help.

### 4.3 Search

The code index holds trigrams of content, and old segments keep dead documents. Editing segments in place would be new, delicate code for a rare command. Instead the purge deletes the project's code index: its `search_heads` and `search_shards` rows of kind `code` (`migrations/0016_search.sql:12`, `:28`) and the segment objects they named. When the servers start, the indexer builds the index again from the branch tips, and until then queries answer `indexing` (`search/index.rs:30`). To confirm when building: that deleting the rows is all the indexer needs to start again.

The default branch's tip never names a purged id (§3.4), and the indexer skips an object that answers `purged` on another branch's tip, as it skips a file too large to index.

The names index (paths) is kept: the first version does not purge names.

### 4.4 Regional caches and the Veil daemon

A regional cache holds no database and no authority, but it does hold bytes, and it serves an object from its own store to anyone whose grant reaches it (`cache/mod.rs:8`–`:15`). After a purge an old snapshot's tree still names the id, so a grant still reaches it. The cache must drop the bytes.

**The mechanism:** a purge number. Each purge that completes raises it by one (it is the id of the purge's record, §7). The feed the caches already poll every second, `POST /v1/cache/epochs` (`cache/feed.rs:37`, `cache/epochs.rs:30`), carries the server's current number. A cache keeps the number its store was filled under. If the server's number is different, the cache empties its whole store before it serves anything from it, and then keeps the new number.

- It is one number, and the reaction is the bluntest one: empty everything. The cost is a refill, which is cheap next to a missed copy.
- It needs nothing from the operator. A cache that was off during the purge learns the number at its first poll, before it serves: a cache that has not heard from the feed already serves nothing from its store (`cache/epochs.rs:16`).
- The cache never learns which objects were purged.

**The Veil daemon** (`crates/vl/src/daemon/store.rs:1`) is a cache on a person's machine. It is outside the server: §6. A later step can give it the same number and the same reaction.

## 5. History afterwards

### 5.1 Tombstones

```sql
CREATE TABLE purged_objects (
    project_id BIGINT NOT NULL,
    object_id  TEXT   NOT NULL,
    purge_id   BIGINT NOT NULL,     -- the record of §7
    PRIMARY KEY (project_id, object_id)
);
```

Snapshots and trees keep their ids: an id is the hash of the object's bytes, and those objects are not touched. The tree still says "at this path there was a file with this id". The tombstone says "and its content was removed, by purge 7 on 2026-12-02".

A server loads the table when it starts. It is small (a purge names a handful of objects), and it cannot change while the server runs (§2).

### 5.2 Reads

Today a stored object that is not in the store is a storage fault. `load_encoding` answers "none" (`store.rs:1029`), and the callers turn that into `500 internal` ("stored object … is missing", `sync.rs:223`; `error.rs:167`, BUG-2681) or, on the object routes, `404`. `vl` reads `404` as "hidden from you" and anything else as "unavailable, try again" (`crates/vl/src/thin.rs:8`, `:232`). Neither is true of a purged object.

**The change:** `Objects` checks the tombstones first, in `get`, `get_many`, `get_encoded`, `get_range` and `exists` (`store.rs:1061`–`:2055`). A purged id never reaches the store; the call answers a new error, `Purged`. On the wire that is **`410 Gone`, code `purged`**, with the purge's number and date and nothing else.

| Route or work | Today's code | Answer for a purged file |
|---|---|---|
| `GET /v1/objects/{p}/{id}` and the batch (`grant.rs:439`, `:498`); `fetch` (`sync.rs:1684`) | the object, or `404` | `410 purged` for the object; in a batch, the id in a `purged` list beside the objects sent. Only for a caller whose grant reaches the id: anyone else gets the `404` they get today, so a purge reveals nothing about a hidden path |
| `GET …/q/file` (`web/mod.rs:91`) | the file | `410 purged` |
| `GET …/q/diff`, a PR's diff (`query/mod.rs:1430`) | hunks | the file's entry says `purged`, with no hunks; the rest of the diff is served |
| `GET …/q/blame` (`query/mod.rs:1435`) | a line moves to the parent version that holds it; a parent that is "absent, a secret, binary, too large" holds no line (`derive/blame.rs:17`) | a purged version joins that list: it holds no line. Lines are attributed to the first readable version after it, and the answer says the history passed through a purge |
| `GET …/q/history`, `q/log`, `q/show`, `q/tree` | ids, paths, descriptions | unchanged: they read no file content. `q/tree` marks the entry `purged` |
| search, grep (`search/mod.rs:891`, `:896`) | the index, then the files | never meets one on the default branch; skipped elsewhere (§4.3) |
| a landing or an API commit that merges (`landing/merge.rs`) | a three-way merge reads the base | when the base of a file is purged, the merge is a conflict on that path, with a message that says why. It never fails as an internal error |
| the deriver's rename detection (`derive/changes.rs:16`) | compares the content of deleted and added files | a purged file is not compared, like one too large |
| a push or a pull | trees and what they name | unchanged, except §5.3 |

Old `vl` binaries read `410` as "unavailable", which is safe: they never treat it as hidden, and never as corruption. A new `vl` says what happened.

### 5.3 The content does not come back

Someone's clone still has the file. Their next push may upload it again: the server tells a client which objects it lacks, and it lacks this one.

`Objects` refuses to store a purged id, in `stage`, `keep`, `put` and `put_encoded` (`store.rs:1224`–`:1331`), from the same in-memory tombstones. A push that uploads one is refused before anything is written, as a push with a plain-text secret is, with code `purged`: "this file's content was purged from the project on DATE (purge N): remove it and commit again".

A push that only carries an old file forward (a branch made before the purge, file untouched, nothing uploaded) is accepted. It adds no content to the server.

### 5.4 In `vl`

- A command that needs the content of a purged file fails for that file, with the server's words: `docs/keys.txt: purged from the server on 2026-12-02 (purge 7)`. It never says "corrupt" and never retries.
- A checkout of a snapshot that holds a purged file refuses, naming the paths. It does not write the tree without the file: a working copy that silently lacks a file would commit its deletion. `--only` a folder that does not hold it works.
- `vl log`, `vl show`, `vl diff` on other files, `vl blame` (§5.2) work.
- A thin clone already tells a gap in the server's history ("not fetched") from lost work (`docs/HUB.md` §13.21). A purged object is a third answer the server gives when asked. No change to the repository format is proposed. To confirm when building: `vl clone --full` of a project with purged objects, and `vl fsck` in it.

## 6. What a purge cannot do

This section belongs in the command's own output, before it asks for `--apply`.

- **Copies on people's machines stay.** Every clone that fetched the file has it: in its store, in its working copy, and in the machine's Veil daemon. So does anyone's editor, backup or chat window. Veil cannot reach them and does not pretend to.
- **A leaked credential is leaked.** Rotate it. A purge shortens how long the old value sits in history; it does not make the value secret again.
- **The bucket's own history.** If the bucket keeps versions, a delete leaves the old version behind. The command asks the store whether versioning is on and stops with an explanation if it is; the operator removes the versions with the provider's tools, or turns versioning off, and runs it again.
- **Backups** of the bucket and of the database are the operator's. The command prints the reminder.
- **Logs** are not edited. No content should be in them (an invariant). If the path itself is sensitive, it may be in the operator's proxy logs.
- **Names, descriptions and comments** (§3.3).

## 7. The record

```sql
CREATE TABLE purges (
    id           BIGSERIAL PRIMARY KEY,   -- the purge number of §4.4
    project_id   BIGINT NOT NULL,
    started_at   BIGINT NOT NULL,
    finished_at  BIGINT,                  -- NULL: not finished (§9)
    operator     TEXT NOT NULL,           -- the OS user and host that ran it
    requested_by TEXT NOT NULL,           -- as typed: the admin who asked
    reason       TEXT NOT NULL,           -- as typed
    selector     TEXT NOT NULL,           -- the command line's --object or --path, as typed
    objects      BIGINT NOT NULL,         -- how many ids
    bytes        BIGINT NOT NULL,
    work         TEXT NOT NULL            -- JSON: the packs being replaced, for --resume
);
```

- The record has ids, counts, names and dates. It never has content, and the command has no option that would put content in it.
- The same facts go to the project's `audit_log` (`audit`, `lib.rs:628`; action `purge`), where its other administrative actions are.
- `veil-server purge --list` prints the records. The command also prints the record when it finishes, for the operator to file with the request.
- A path typed as the selector is recorded as typed. If the path itself must not be recorded, the operator runs the dry run with `--path`, then applies with the `--object` ids it printed.

## 8. The offline step

There is no `veil-server gc` to borrow a fence from, so the purge has its own. It is one lock.

- **A serving server holds it, shared.** `veil_server::start` (`lib.rs:239`) opens one connection of its own, outside the pool, and takes `pg_try_advisory_lock_shared(PURGE_LOCK)` on it before it listens. It keeps the connection, and the lock, for as long as it runs. If the lock is refused, a purge is running: the server exits and says so.
- **The purge takes it, exclusive:** `pg_try_advisory_lock(PURGE_LOCK)` on its own connection, held until it finishes. If it is refused, a server is serving. The command prints which sessions hold it (their client addresses, from `pg_locks` and `pg_stat_activity`) and exits. It changes nothing first.
- **A session lock, because it frees itself.** A server that is killed loses its connection, and the database frees the lock at once. There is no row to go stale and no timeout to tune. The code base already relies on this twice: the migration lock (`db.rs:181`–`:242`, "both databases support session advisory locks") and the landing lease's liveness lock, a session lock on a dedicated connection (`landing/lease_lock.rs:1`–`:32`).
- **A server whose lock session ends stops serving.** The database may end a live server's session (a failover, an administrator). The server watches that connection and exits when it closes; its supervisor starts it again, and the start takes the lock or refuses.

**What the lock is and is not.** The procedure is: the operator stops the servers. The lock is there to catch the mistake of leaving one running, and it catches it without any cooperation from that server beyond holding a connection. It is not a way to purge under load, and the design asks for none.

Two limits, stated:

- A connection pooler in transaction mode does not keep a session, so a session lock means nothing through it. The lock connection must go to the database directly, or through a pooler in session mode. A server that cannot tell should refuse to start; to confirm when building how to detect it.
- Between a database ending a server's session and that server exiting there is a moment, under a second, in which the lock is free and the server still answers. Only an operator who has not stopped the servers can meet it.

Regional caches hold no database connection and are not behind the lock. They do not need to be: §4.4.

## 9. The steps, and stopping part-way

1. Take the lock (§8). Refuse if an earlier purge is unfinished, unless this is `--resume`.
2. Find the ids (§3.1). Print the dry run. Without `--apply`, stop here.
3. **In one transaction:** insert the record (`finished_at` NULL, with the list of packs to replace) and the tombstones. From here on the objects are purged as far as any server is concerned.
4. Delete from the store: keys, packs (§4.1), upload containers (§4.2).
5. Drop the code search index (§4.3).
6. Set `finished_at`, write the audit row, print the record. Release the lock.

Every step after 3 can be run twice without harm: deleting a key that is gone is not an error, and a pack that was already replaced is no longer listed. So **`--resume` runs steps 4 to 6 again** for the unfinished record.

**A server refuses to start while a purge is unfinished.** Otherwise it could serve search results from an index that still holds the content's trigrams. It says: "purge N did not finish: run `veil-server purge --resume`".

## 10. Who may run it

The operator: whoever can run `veil-server` on the server's machine with its database URL and storage credentials. That person can already delete any object by hand. The command gives them no new power; it gives them a way to do it that leaves history readable and a record behind.

There is no route for it and no `vl` command. A purge over the network would be a destructive request any stolen admin session could send, and it would have to run beside writers, which is the coordination §2 avoids.

**Project admins** (`docs/VISIBILITY.md`: the creator and whoever they make admin) decide who sees what. They do not delete history, and this design does not change that. An admin asks the operator; `--requested-by` records who asked. Where the admin and the operator are the same people, as on a team's own server, that is one person typing two names.

## 11. Tests, and the first version

### 11.1 Tests (`server_hub`, a new module `purge`)

Each asserts first that the purge it runs succeeded, or was refused exactly as stated.

| # | Guarantee |
|---|---|
| 1 | `objects` layout: after a purge the object's key is gone from the store, its tombstone is there, and every other object of the project still reads. |
| 2 | `packs` layout: the same for an object inside a listed pack shared with others; the old pack is gone from the store, and no row names it. |
| 3 | An object stored both ways (a project that changed layout) is gone from both. |
| 4 | Staged and discarded upload containers that hold the content are gone. |
| 5 | Every read route answers `410 purged` for a caller who could read the path, and the unchanged `404` for one who could not: the answers of a hidden purged object, a hidden stored object and a random id are byte-identical. |
| 6 | Diff, blame, file history, log and tree answer for a history that passes through a purged version, each as §5.2 says. None answers `500`. |
| 7 | A push that uploads the purged content again is refused with `purged`, and nothing of it is in the store afterwards. A push that carries the old file forward without uploading it is accepted. |
| 8 | A landing whose merge needs a purged base answers a conflict on that path. |
| 9 | Search: after the purge and a restart, a query for a string only the purged content held finds nothing on any branch, and the store holds no segment made before the purge. |
| 10 | The purge refuses while a server runs, naming it, and changes nothing. A server refuses to start while a purge holds the lock, and while a purge is unfinished. |
| 11 | A purge stopped after each of its steps: `--resume` finishes it, and tests 1, 2 and 9 hold afterwards. |
| 12 | The default branch's tip names the id: refused, nothing changed. Another branch's tip names it: purged, and that branch's checkout of the file answers `purged`. |
| 13 | The record and the audit row hold the ids, the operator, the reason and the dates, and no byte of the content (the content is a marker string the test then searches every table and every stored object for). |
| 14 | A regional cache that held the object serves it before the purge and, after the servers start again, answers `410` from the server and holds nothing from before. |
| 15 | The schema inventory (`pack_gc.rs:2621`) classifies the two new tables; a new column anywhere still fails that test until someone says whether it can hold content. |

`vl` (`cli_security`): the messages of §5.4, a checkout that refuses rather than writing a tree without the file, and an old `vl` that reports "unavailable" and nothing worse.

### 11.2 The smallest first version worth building

Blob contents only, by id or path, in one project. Both layouts. Tombstones, `410 purged` on the object routes, `fetch` and `q/file`, and the refusal of re-uploads. Upload containers discarded. The code search index dropped. The lock, the record, `--resume`. The purge number on the caches' feed.

Left for later, each on its own: diff and blame answers that carry on through a purged version (the first version may answer `410` for the whole request, which is clear, though less useful); the Veil daemon reacting to the purge number; file names and descriptions; several projects in one run.

Not in any version: a purge while servers run.

## 12. Decisions for the owner

1. **Build it at all, and when.** It is a new command and two new tables.
2. **Offline only, by this lock** (§8): servers hold a shared session lock, the purge an exclusive one. This adds one connection per server and a reason for a server to refuse to start.
3. **Refuse while the default branch's tip holds the content** (§3.4), or allow it with a flag.
4. **`410 Gone`, code `purged`**, as a new answer on the wire (§5.2). Old clients read it as "unavailable".
5. **Caches empty themselves on a purge number** (§4.4), or the operator wipes each cache by hand in the first version.
6. **A server refuses to start while a purge is unfinished** (§9).
7. **Scope of the first version** (§11.2): contents only. Names and descriptions need their own design: removing them changes what history can show, not only what a file read answers.
8. **Does `docs/VISIBILITY.md` say it?** One line would do: "Admins cannot delete history. The server's operator can remove a file's content from it, offline, and the project's audit log records it."
9. **Bucket versioning** (§6): stop, as proposed, or warn and continue.
