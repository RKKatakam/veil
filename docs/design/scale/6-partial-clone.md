# 6. Fetch on demand from the server

Status: **built as amended, as milestone S3** (`docs/HUB.md` §13.21: no full graph, format 9, the cache at `.veil/cache/`; anchors.json and promotion deferred until the server has a gc). Re-aimed at the server (Scion 4.1, 4.2 and 4.4; `docs/HUB.md` §4.4, §9.1). Veil is server-centric (`docs/OVERVIEW.md`): the client fetches from the Veil server, which checks access on every request and serves each object by id through the caches. The client-side mechanics below (the marker, the cache area, `Unavailable`, eviction, push from a partial checkout) carry over unchanged. **Requires format 6:**
- `repo.json` gains the `partial` marker;
- an older vl would read every object not yet fetched as `Missing`, which **the engine treats as redacted** (`VeilError::is_unreadable`, `error.rs`). It would leave files out of checkouts, skip history on push and gc nothing (threat 1).

**The highest-risk client feature of the scale work.**

## What it covers

- **In:**
  - a content horizon (recent history only: trees and blobs of snapshots newer than a date or than the newest N);
  - a subtree (`--only`, a sparse working copy);
  - objects fetched from the server when read (checkout, mount, `blame`, `diff`, `log -p`), starting from the top folder down;
  - a bounded local cache;
  - push and pull from a partial checkout.
- **Out:**
  - true shallow history (dropping snapshot objects past a depth). **Every snapshot object the person may see is always fetched**: snapshots are small, and keeping the graph complete keeps embargo, confinement, `embargo_withheld`, the history index and push closures exact (threats 4 and 9). Once the server answers history through its API (`docs/HUB.md` §9.1), this can be revisited.

## Design sketch

### CLI

```text
vl clone PROJECT [DIR] --since 90d | --recent N     content horizon (default with --partial: --recent 1)
vl clone PROJECT [DIR] --only PATH…                 sparse working copy; other paths fetched only if read
vl clone … --cache-size 4G                          bound for objects fetched on demand (default 4 GiB)
vl fetch [REV…] [-- PATH…]                          fetch now; --all: everything
vl partial status | widen PATH… | narrow PATH… | full
```

`vl partial full` fetches everything and removes the marker, so the checkout becomes an ordinary clone.

### State

- **`repo.json`** gains `partial: { remote, since?, recent?, only?: [paths], cache_limit }` (`deny_unknown_fields`, format 6, device-local).
- **`.veil/objects/cache/`** holds objects fetched on demand, as loose files and packs. It is **the only area ever evicted** (threat 6). The main store (`objects/??/`, `objects/pack/`) holds what this repository created, plus the horizon fetched at clone and pull.
- **`.veil/local/promisor/`** holds `anchors.json` (below) and `atime` (an append-only access log for LRU, compacted by maintenance).

### Read path (`promisor.rs`)

When the store misses an object (after the loose probe, the pack reload and the second probe of item 4, threat 2), `ObjectStore::read_raw` calls `Promisor::fetch(id)`:
1. **Ask the server for the id** (`get`, `docs/HUB.md` §4.2), through the caches. If the server answers that the object is not there or not visible to this person, return `Missing` (a true redaction, as today).
2. **If it is returned,** take it.
   - Check its hash and `check_storable`, and run the same decoding and depth checks as `Transfer`.
   - Write it into `objects/cache/` and return it.
3. **If the server cannot be reached** (a connection error or a timeout), return the new error **`VeilError::Unavailable { remote }`**. It is **not** `is_unreadable()`: every caller that treats `Missing` as "redacted" must fail instead (threat 1).

Fetches are **batched**:
- checkout and `ws exec` sync collect the ids of a directory's changed entries and fetch them in one request;
- the mount prefetches a directory's small files on `opendir`.

### What the server sees

The server stores code as plain text and decides who may see each path (`docs/VISIBILITY.md`), so what a person reads is not a secret from it. The rules are about access, not about hiding the fetch pattern:

1. **The server sends only what the person may see,** by path, on every request (`docs/HUB.md` §4.6). Caches serve an object only after that check.
2. **Secrets and embargoed content arrive as ciphertext,** and are opened on the device. A person without access never receives them.

### Horizon, pull, push

- **Clone:**
  - every snapshot (the commit graph);
  - for the horizon's snapshots, every tree, and every blob inside `--only` (or all of them without it);
  - the secrets and embargoed objects the person may open, as ciphertext;
  - the rings and records, as a clone takes them today.
- **Pull** does the same for new snapshots (they are in the horizon by definition).
- **Push** (item 1) to the promisor remote computes `known` by the path-aligned diff against the boundary trees (item 1, "Faster `known`"):
  - a subtree with an unchanged id at an unchanged path is known without fetching it;
  - an entry that differs is sent, and **fetched first if it is not local** (for instance `vl restore --from <old>` brought back a blob from outside the horizon).
  - So the receiver's committed closure stays complete without fetching the boundary.

### Anchors: the remote must keep what we did not fetch

- **The hazard.** Objects we never fetched are safe only while the server keeps them. The server keeps the committed closure of its branches, plus a retention window. If a branch is rewound with `--force` and the retention window passes, objects that only our history still reaches are gone **for good**.
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

- **Recording.** The project directory is recorded through a `SparseView` (the path sparse sandboxes use), and checked out with `restrict(tree, set)`, which always includes `.veilpolicy`.
- **Paths outside the set** keep the working copy's recorded entries by id and are never fetched.
- **A policy edit or a scanner upgrade** turns the hints off, so the builder reads the outside files to reclassify them (exact, as for sandboxes). In a partial clone that fetches them: `vl` prints the number and size and asks for `--fetch` when more than 1,000 files or 1 GiB would be fetched.

### Other commands

- **`fsck`** reports objects that the server has but that are not fetched as `not fetched`, a note. A missing plaintext object that the server also lacks is corrupt, as today.
- **`gc`** never descends into an unfetched tree. Everything below it is on the server, and nothing local can sit only under a remote-only tree (threat 5).
- **The history index** marks snapshots whose trees are not local as `BLOOM_UNKNOWN`. Generations stay exact.

## Threat review

1. **An unfetched object read as redacted** (the top risk). Every `Missing` match in the engine reads "redacted":
   - `remote::committed_closure`, `push_closure`, `ancestors_in`, `known_objects` and `unusable_target` skip it;
   - `Transaction::indexed`'s `tolerated` keeps it;
   - `fsck` classifies it as expected redaction;
   - `gc` refuses to guess;
   - checkout leaves it out, and `Materialised` records it as hidden;
   - the builder's `carry_unreadable` carries it.

   An unreachable server would then leave out a file a person may read, and a push would silently drop history.
   - *Invariant:* `Missing` is returned only when the server says the object is absent or not visible to this person. A failed or impossible fetch is `Unavailable`, which every one of those sites propagates as an error, before writing anything.
   - *Test:* `partial_clone.rs`:
     - a checkout and a push, each run with the server stopped half way: both fail, and the view, the working copy and `checkout.json` are unchanged;
     - a grep of `veil-core` asserting that every `is_unreadable()`/`Missing` match site is listed in an audit table in the test, with its `Unavailable` handling.
2. **The server sends something the person may not see.**
   - *Invariant:* every object fetched on demand passes the server's access check for that person; secrets and embargoed objects arrive only as ciphertext, and only for people with access.
   - *Test:* a person without access to `billing/` opens files through `cat`, the mount and `blame`, and runs a mount `find`. The server's request log shows no object under `billing/`, and no name from it reaches the client.
3. *(Covered by threat 2.)*
4. **A missing object downgrades content.** The fallback versions this threat was about were removed in repository format 8 (only secret files are encrypted).
   - *Invariant:* a missing **plaintext** object referenced by a reachable tree is `Corrupt`, never redacted.
5. **gc in a partial clone.**
   - *Invariant:* an unfetched tree's subtree is entirely on the server, so skipping it during the mark loses nothing local. It holds because locally created objects are only ever referenced from local trees.
   - *Test:* a property test with random local edits, restores from outside the horizon, and `gc --prune-now` with an empty cache. Then `vl partial full` succeeds, and the full store passes `fsck`.
6. **Eviction of something only this machine has.**
   - *Invariant:* only `objects/cache/` is evicted; transactions write to the main store and promote cache objects they reference.
   - *Test:* make edits, then evict with `cache_limit = 0`. Stop the server: everything this repository created is readable.
7. **The server prunes what we relied on** (a forced rewind plus the end of the retention window).
   - *Invariant:* before a pull applies a remote tag move that is not a fast-forward, every object reachable from local refs, and only from the old target region, is local (pinned in the main store).
   - *Test:* a second client force-rewinds `main` and the server prunes. After our pull, our old commits' content is fully readable without the server.
8. **Eviction racing readers.** A mount reads a cache pack that maintenance evicts.
   - *Invariant:* a reader whose cache pack vanished retries through the promisor; it never reports `Missing`.
   - *Test:* eviction in a loop while a mount reads files; reads all succeed, or fail with `Unavailable` only when the server is unreachable.
9. **Push from a partial clone leaves the receiver incomplete.**
   - *Invariant:* every object the new snapshots reference is either sent, or at an unchanged path with an unchanged id under the boundary.
   - *Test:* restore an old file from outside the horizon and push. The server's copy passes `fsck`, and a fresh **full** clone checks out every snapshot.
10. *(Not applicable: the server is the only remote.)*
11. **Fetch storms.** `find`, `grep -r` or an IDE indexer through the mount fetches everything; a cache smaller than the working set thrashes.
    - *Invariant:* `readdir` and `stat` never fetch blobs (sizes come from tree entries); fetching stops at `cache_limit` minus the pinned set and then fails with a clear message rather than evicting in a loop.
    - *Test:* `ls -lR` over the mount fetches no blob. `cat` of every file with a small cache fails cleanly once the limit is reached.
12. **The server is unreachable.** Veil has no offline mode; this is about failing safely.
    - *Invariant:* a command that needs an object it does not have fails with `Unavailable` before writing anything; it never writes a partial result.
    - *Test:* a matrix of `status`, `log`, `diff`, `commit`, `ws exec`, `blame` on an old file and `push` with the server stopped.
13. **Embargo release in a partial clone.**
    - *Invariant:* released content becomes readable when the release reaches the server's records and the objects are fetched, exactly as filled in today.
    - *Test:* `embargo_release.rs` flow on a partial clone.
14. **Format and older vl.**
    - *Invariant:* a `partial` marker below format 6 is refused as corrupt, and format 6 makes an older vl refuse the directory.
    - *Test:* `format_compat.rs`: a format-5 `repo.json` with `partial` is refused; the format-6 fixture includes a partial clone.
15. **Interactions:**
    - **sandboxes:** `ws exec` sync fetches through `vl`, never from inside the command;
    - **mount:** fetching happens in the FUSE request thread, with a timeout, and a failure is `EIO`, never wrong content;
    - **secrets:** fetched as ciphertext with the files they sit in, opened on the device;
    - **the history index:** `BLOOM_UNKNOWN`.
    - **agents:** a `vl blame` started by an agent uses its person's device identity; `Unavailable` names the server and the error.

    - *Invariant:* each subsystem sees either the right bytes or an error.
    - *Test:* one test per subsystem with the server stopped.

## Open decisions

1. **True shallow history.**
   - *Recommendation:* defer until the server answers history through its API. It breaks the complete-graph assumption that embargo, confinement and push safety rely on.
2. **Default horizon.**
   - *Recommendation:* `--recent 1` (the checked-out snapshot's content), with `--since` for agents that run `blame`.
