# 6. Partial clone and fetch on demand over SFTP

Status: design and threat review (Scion 4.1, 4.2 and 4.4). **Requires format 6:**
- `repo.json` gains the `partial` marker;
- an older vl would read every object not yet fetched as `Missing`, which **the engine treats as redacted** (`VeilError::is_unreadable`, `error.rs`). It would check out fallbacks, skip history on push and gc nothing (threat 1).

**The highest-risk feature of the round.**

## Scope

- **In:**
  - a content horizon (recent history only: trees and blobs of snapshots newer than a date or than the newest N);
  - a subtree (`--only`, a sparse working copy);
  - objects fetched when read (checkout, mount, `blame`, `diff`, `log -p`);
  - a bounded local cache;
  - push and pull from a partial clone.
- **Out:**
  - true shallow history (dropping snapshot objects past a depth). **Every snapshot object is always fetched**, as Git's blobless/treeless clones keep every commit: snapshots are small, and keeping the graph complete keeps embargo, confinement, `embargo_withheld`, the history index and push closures exact (threats 4 and 9);
  - colocated Git mode together with a partial clone (refused this round: the export needs every exported commit's blobs).

## Design sketch

### CLI

```text
vl clone URL [DIR] --since 90d | --recent N     content horizon (default with --partial: --recent 1)
vl clone URL [DIR] --only PATH…                 sparse working copy; other paths fetched only if read
vl clone … --cache-size 4G                      bound for objects fetched on demand (default 4 GiB)
vl fetch [REV…] [-- PATH…]                      fetch now (e.g. before going offline); --all: everything
vl partial status | widen PATH… | narrow PATH… | full
```

`vl partial full` fetches everything and removes the marker, so the repository becomes an ordinary clone.

### State

- **`repo.json`** gains `partial: { remote, since?, recent?, only?: [paths], cache_limit }` (`deny_unknown_fields`, format 6, device-local like `colocated`).
- **`.veil/objects/cache/`** holds objects fetched on demand, as loose files and packs. It is **the only area ever evicted** (threat 6). The main store (`objects/??/`, `objects/pack/`) holds what this repository created, plus the horizon fetched at clone and pull.
- **`.veil/local/promisor/`** holds the remote's inventory: copies of its `.idx` files and the loose listing, refreshed by each pull. It also holds `anchors.json` (below) and `atime` (an append-only access log for LRU, compacted by maintenance).

### Read path (`promisor.rs`)

When the store misses an object (after the loose probe, the pack reload and the second probe of item 4, threat 2), `ObjectStore::read_raw` calls `Promisor::fetch(id)`:
1. **Look the id up in the remote's inventory.** If it is absent there, return `Missing` (a true redaction, as today).
2. **If it is present, read it** with a ranged read from the remote pack, or as a loose object.
   - Check its hash and `check_storable`, and run the same decoding and depth checks as `Transfer`.
   - Write it into `objects/cache/` and return it.
3. **If the remote cannot be reached** (a connection error or a timeout), return the new error **`VeilError::Unavailable { remote }`**. It is **not** `is_unreadable()`: every caller that treats `Missing` as "redacted" must fail instead (threat 1).

Fetches are **batched**:
- checkout and `ws exec` sync collect the ids of a directory's changed entries and fetch them in parallel (`par_map`, pipelined ranged reads, adjacent ranges merged);
- the mount prefetches a directory's small files on `opendir`.

### Which objects, and what the remote learns (the confidentiality decision)

The SFTP server's operator already sees:
- which account connects, and when;
- every plaintext tree, so the names of cloaked files, and which sealed object each entry names;
- the key rings, and so which members each scope has;
- every request's path and byte range. A range inside a pack maps to an object id through the `.idx` the server also holds.

A full clone reveals nothing about what a member *reads*. Fetching per file would reveal exactly that. The rules:

1. **Sealed objects are never fetched one at a time.**
   - When any sealed object of scope `S` is needed for snapshot `R`, the client fetches **the scope batch**: every sealed object of `S` that `R`'s tree names (within `--only` if set, through the plaintext trees, so without decrypting). Embargo-sealed objects are batched per embargo in the same way.
   - The remote learns "this account read something under `S` at `R`", which is no more than "is a member of `S` and was active", already visible from the ring and the connection.
2. **At clone and pull, the horizon's sealed objects** for every scope the identity holds a key for are fetched eagerly with the horizon. Cloaked content is typically small (configuration, keys, notes), so most sessions never fetch sealed content lazily at all.
3. **Scopes the identity has no key for are never fetched.** They could not be read, and non-membership is visible from the rings anyway.
4. **Public objects are fetched individually, batched per directory.** Documented: *the operator of the remote can see which public files you read, and when.*
5. **No cover traffic or padding** this round (open decision 1).

### Horizon, pull, push

- **Clone:**
  - every snapshot (the commit graph);
  - for the horizon's snapshots, every tree, and every blob inside `--only` (or all of them without it);
  - every sealed object per rule 2;
  - the rings and records, as a clone takes them today.
- **Pull** does the same for new snapshots (they are in the horizon by definition).
- **Push** (item 1) to the promisor remote computes `known` by the path-aligned diff against the boundary trees (item 1, "Faster `known`"):
  - a subtree with an unchanged id at an unchanged path is known without fetching it;
  - an entry that differs is sent, and **fetched first if it is not local** (for instance `vl restore --from <old>` brought back a blob from outside the horizon).
  - So the receiver's committed closure stays complete without fetching the boundary.
- **Push to another remote** (a public mirror) fetches whatever it must send that is not local, then filters it as usual. It is slower, never incomplete.

### Anchors: the remote must keep what we did not fetch

- **The hazard.** Objects we never fetched are safe only while the remote keeps them. The remote keeps exactly the committed closure of its view. If a tag is rewound with `--force` and `vl -R origin gc --prune-now` runs, objects that only our history still reaches are gone **for good**.
- **`anchors.json`** records, for each remote tag, the snapshot whose closure we rely on.
- **Before a pull moves a remote tag in a way that is not a fast-forward,** it computes with the history index the local snapshots that reach the old target region but not the new one (`range(local refs, new remote refs)` restricted to the old closure). It fetches every object of their trees that is not local into the **main** store (pinned) **before** updating the remote tag.
- `vl partial status` reports pinned bytes.

### Cache bound and eviction

- **What is evicted:** only `objects/cache/`, least recently used first, down to 80 % of `cache_limit`, during maintenance (item 4) and when a fetch would exceed the limit.
- **What is never evicted:**
  - the trees and blobs of each workspace's working copy (`checkout.json` `snapshot` and `pending`);
  - sandbox manifests' trees;
  - mount `base`s;
  - anything in the main store.
- **Locally created objects never go to the cache area:** `write_if_absent` always writes into the main store. An object that exists only in the cache is promoted (copied into the main store) when a transaction references it.

### Sparse working copy (`--only`)

- **Recording.** The project directory is recorded with `SnapshotOptions::only` (the `SparseView` path that sparse sandboxes and colocated mode use), and checked out with `restrict(tree, set)`, which always includes `.veilpolicy`.
- **Paths outside the set** keep the working copy's recorded entries by id and are never fetched.
- **A policy edit or a scanner upgrade** turns the hints off, so the builder reads the outside files to reclassify them (exact, as for sandboxes). In a partial clone that fetches them: `vl` prints the number and size and asks for `--fetch` when more than 1,000 files or 1 GiB would be fetched.

### Other commands

- **`fsck`** reports objects that are present on the remote but not fetched as `not fetched`, a note. A missing plaintext object that the remote also lacks is corrupt, as today.
- **`gc`** never descends into an unfetched tree. Everything below it is on the remote, and nothing local can sit only under a remote-only tree (threat 5).
- **The history index** marks snapshots whose trees are not local as `BLOOM_UNKNOWN`. Generations stay exact.

## Threat review

1. **An unfetched object read as redacted** (the top risk). Every `Missing` match in the engine reads "redacted":
   - `remote::committed_closure`, `push_closure`, `ancestors_in`, `known_objects` and `unusable_target` skip it;
   - `Transaction::indexed`'s `tolerated` keeps it;
   - `fsck` classifies it as expected redaction;
   - `gc` refuses to guess;
   - checkout writes the fallback, and `Materialised` records it as hidden;
   - the builder's `carry_unreadable` carries it.

   An unreachable remote would then give a member an old public fallback in place of their cloaked file, and a push that silently drops history.
   - *Invariant:* `Missing` is returned only when the remote's inventory lacks the object. A failed or impossible fetch is `Unavailable`, which every one of those sites propagates as an error, before writing anything.
   - *Test:* `partial_clone.rs`:
     - a cloaked-file checkout and a push, each run with the SFTP server killed half way: both fail, and the view, the working copy and `checkout.json` are unchanged;
     - a grep of `veil-core` asserting that every `is_unreadable()`/`Missing` match site is listed in an audit table in the test, with its `Unavailable` handling.
2. **The fetch pattern leaks which sealed file a member opened.**
   - *Invariant:* sealed objects are requested only as complete scope (or embargo) batches for a snapshot, never alone.
   - *Test:* the SFTP test server logs every request, and a member opens one cloaked file through `cat`, the mount and `blame`. The sealed ids requested each time equal the scope batch of that snapshot.
3. **Requests for scopes the identity cannot read.**
   - *Invariant:* none: no sealed object of a scope without a key is ever requested.
   - *Test:* a non-member clone, then a checkout and a mount `find`. The server log shows no sealed object of that scope.
4. **The remote hides an object to downgrade content.** The remote claims a sealed object is absent, so the client renders the public fallback. If the next snapshot recorded the fallback, the cloaked content would be reverted.
   - *Invariant:* a file materialised from a fallback is recorded in `Materialised.fallback` and never recorded as an edit; it is filled in when the object appears (unchanged rules). A missing **plaintext** object referenced by a reachable tree is `Corrupt`, never redacted.
   - *Test:* the server hides one sealed blob and one public blob. The sealed one checks out as its fallback, the next snapshot keeps the tree unchanged, and the public one fails with `Corrupt`.
5. **gc in a partial clone.**
   - *Invariant:* an unfetched tree's subtree is entirely on the remote, so skipping it during the mark loses nothing local. It holds because locally created objects are only ever referenced from local trees.
   - *Test:* a property test with random local edits, restores from outside the horizon, and `gc --prune-now` with an empty cache. Then `vl partial full` succeeds, and the full store passes `fsck`.
6. **Eviction of something only this machine has.**
   - *Invariant:* only `objects/cache/` is evicted; transactions write to the main store and promote cache objects they reference.
   - *Test:* make edits, then evict with `cache_limit = 0`. Disconnect the remote: everything this repository created is readable.
7. **The remote prunes what we relied on** (a forced rewind plus remote gc).
   - *Invariant:* before a pull applies a remote tag move that is not a fast-forward, every object reachable from local refs, and only from the old target region, is local (pinned in the main store).
   - *Test:* a second client force-rewinds `main` and runs `gc --prune-now` on the remote. After our pull, our old commits' content is fully readable offline.
8. **Eviction racing readers.** A mount reads a cache pack that maintenance evicts.
   - *Invariant:* a reader whose cache pack vanished retries through the promisor; it never reports `Missing`.
   - *Test:* eviction in a loop while a mount reads files; reads all succeed or fail with `Unavailable` only when offline.
9. **Push from a partial clone leaves the receiver incomplete.**
   - *Invariant:* every object the new snapshots reference is either sent, or at an unchanged path with an unchanged id under the boundary.
   - *Test:* restore an old file from outside the horizon and push. The remote passes `fsck`, and a fresh **full** clone checks out every snapshot.
10. **Push to a public mirror from a partial clone.**
    - *Invariant:* what is sent passes the same filter as from a full clone; nothing is skipped as "redacted" because it was unfetched.
    - *Test:* `push_plan.rs`'s property test, run from a partial clone. The plan and the pushed objects equal those of a full clone.
11. **Fetch storms.** `find`, `grep -r` or an IDE indexer through the mount fetches everything; a cache smaller than the working set thrashes.
    - *Invariant:* `readdir` and `stat` never fetch blobs (sizes come from tree entries); fetching stops at `cache_limit` minus the pinned set and then fails with a clear message rather than evicting in a loop.
    - *Test:* `ls -lR` over the mount fetches no blob. `cat` of every file with a small cache fails cleanly once the limit is reached.
12. **Offline.**
    - *Invariant:* commands that need no new content work offline (status on an unchanged directory, `log`, `show` of horizon commits), and every other command fails with `Unavailable` before writing anything.
    - *Test:* offline matrix of `status`, `log`, `diff`, `commit`, `ws exec`, `blame` on an old file and `push`.
13. **Embargo release in a partial clone.**
    - *Invariant:* released content becomes readable when the release reaches the remote's records and the objects are fetched, exactly as filled in today.
    - *Test:* `embargo_release.rs` flow on a partial clone.
14. **Format and older vl.**
    - *Invariant:* a `partial` marker below format 6 is refused as corrupt, and format 6 makes an older vl refuse the directory.
    - *Test:* `format_compat.rs`: a format-5 `repo.json` with `partial` is refused; the format-6 fixture includes a partial clone.
15. **Interactions:**
    - **sandboxes:** `ws exec` sync fetches through `vl`, never from inside the command;
    - **mount:** fetching happens in the FUSE request thread, with `VEIL_SFTP_TIMEOUT`, and a failure is `EIO`, never wrong content;
    - **colocated Git:** refused together;
    - **the team vault:** unchanged (metadata is not objects);
    - **the history index:** `BLOOM_UNKNOWN`.
    - **SSH from inside agents:** a `vl blame` started by an agent harness may need the user's ssh agent; `Unavailable` names the remote and the SSH error.

    - *Invariant:* each subsystem sees either the right bytes or an error.
    - *Test:* one test per subsystem with the remote stopped.

## Open decisions

1. **Cover traffic** (fetch random extra objects, pad batches).
   - *Recommendation:* no. Scope batches already reduce the leak to what rings reveal; padding public reads costs bandwidth and still leaks timing.
2. **Batch granularity for sealed objects**: per snapshot and scope (above), per scope across the horizon, or never lazily.
   - *Recommendation:* per snapshot and scope, with the eager horizon fetch making lazy sealed fetches rare.
3. **True shallow history.**
   - *Recommendation:* defer. It breaks the complete-graph assumption that embargo, confinement and push safety rely on.
4. **Default horizon.**
   - *Recommendation:* `--recent 1` (the checked-out snapshot's content), with `--since` for agents that run `blame`.
5. **Colocated + partial.**
   - *Recommendation:* refuse this round.
