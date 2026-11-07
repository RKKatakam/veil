# Phase 2: thin clients, caches and agent workspaces

> **Status: design, not built** (2026-11-06). Base: `integration` @ `3851159`.
> Sources of truth: `docs/OVERVIEW.md` and `docs/VISIBILITY.md`; where this document disagrees with them, they win. The server as built is `docs/HUB.md` §13. The roadmap is `docs/design/scion-for-developers.md`, phase 2. The client mechanics of fetch on demand come from `docs/design/scale/6-partial-clone.md`, which this document re-aims at the server and does not repeat.

## 1. Goal

An agent gets a working copy of a project of any size **in seconds**, reads only the files it touches, and lands a change **without a clone**. Thousands of agents on one machine fleet share one copy of each object. The server sees few requests, because caches answer most of them, and **no cache ever gives anyone a file they may not see**.

The design check, applied throughout:

| Rule | How this phase keeps it |
|---|---|
| Server-centric, always connected | Every read starts at the server: tips and read grants come only from it. A cache that cannot reach the server stops serving private objects. Nothing works offline. |
| Code is plain text behind the server's checks | Caches hold plain-text objects, and serve one only to someone the server has allowed to read it (§4.3). |
| Only secret files are encrypted | Caches pass secret files through as ciphertext. Nothing here adds encryption to anything else. Key rings stay for secrets only. |
| Admins, groups, managers, folder access, public | Grants are made from the same one access function (`HUB.md` §4.6). No new kind of access. |
| No Git, no offline mode, no SFTP | None used or added. Fetch on demand assumes the simplification pass removed path and SFTP remotes. |

## 2. Where we start (measured)

From `docs/design/scale/LOAD.md` and `OPENSCION.md`, one machine, PostgreSQL:

| What | Today | Bound by |
|---|---|---|
| Pulls per second, `main` moving 20/s | 2,100–2,500 | CPU per pull: 46 statements, mostly permission lookups per request and per-snapshot resolution |
| Landings per second across 100 projects | 2,094 | the database's write-ahead log: about 8 commits per landing |
| Landings per second into one `main`, many agents | 20–30 (bends between 20 and 40) | collisions: a catch-up pull takes longer than the gap between landings |
| Commit one changed file, 10k files | 43–49 ms (Git 27–38 ms) | the scan of the working copy and the transaction's durability |
| Clone one directory | 55–69 / 69–92 ms (Git 50–56) | about 60 sequential `fsync`s of `init`, the pull and the checkout record |
| Fresh agent workspace on a large project | a full or `--only` clone | no fetch on first read |

## 3. What people and agents see

### 3.1 Plain English

* **`vl clone` is thin by default on a server project.** It fetches the tip's top folder and the folders and files it checks out. Everything else arrives the first time something reads it. A laptop never holds the whole history.
* **A thin clone holds no history.** `vl log`, `vl blame` and `vl show` ask the server (a small history request in this phase; the full query API in phase 3). Nothing a command needs is ever read as "hidden" because it was not fetched: if the server cannot be reached, the command fails before it writes anything.
* **The local cache has a size limit** (default 4 GiB per repository, `--cache-size`). Old objects are evicted. What this machine created is never evicted.
* **A workspace can be mounted** so files appear when read: `vl ws new agent-17 --mount DIR` is ready in well under a second, and a build fetches only what it reads.
* **One cache per machine.** A small background process, the **Veil daemon** (`vl daemon`), keeps one shared object cache for every `vl` and every agent on the machine. Thirty agents read each object from the network once. It also watches working copies, so `vl status` and `vl commit` no longer rescan the project.
* **Agents can commit through the API.** A job sends "these files changed on top of revision R" and gets back a change, with no clone at all.
* **Every change records which agent made it**, its task and a reference to its prompt.

### 3.2 CLI

```text
vl clone hub:acme/app [DIR]                  thin by default: the tip, and the folders checked out
vl clone hub:acme/app --only src/api         check out only src/api; other folders fetched only if read
vl clone hub:acme/app --full                 fetch every object you may see (the old behaviour)
vl clone … --cache-size 8G                   bound for fetched objects (default 4 GiB)
vl fetch [REV…] [-- PATH…]                   fetch now (for a flight or a slow link: still needs the server)
vl partial status | widen PATH… | narrow PATH… | full

vl ws new NAME [--rev R] --mount DIR         a workspace whose files appear when read
vl ws exec NAME [--mount] --agent A [--task T] [--prompt-ref R] -- CMD
                                             runs CMD in its isolated sandbox over a mounted workspace

vl daemon status                             cache size, hit rate, watched working copies, upstream
vl daemon stop | start                       the daemon starts itself when vl needs it; these are for tests
vl doctor                                    reports the daemon, the watcher and the mount support

vl change new --onto main --edits FILE.json  commit through the API (scripts, CI); see §5.5
```

`vl clone --full` keeps today's behaviour. `--only` keeps its S1 meaning and loses its S1 limit (moving to a revision that changed other folders works, because they are fetched on demand).

## 4. Architecture

```text
 sandbox (agent) ──► workspace vl (keys, session) ──► Veil daemon ──► regional cache ──► Veil server
   no keys            FUSE mount, recording            one per machine   per region          tips, grants,
   no device key      the agent's vl requests          objects only      objects only        checks, objects
                        │                              no keys           no keys                │
                        └──────────── tips, grants, history, pushes, API commits ──────────────►┘
```

### 4.1 What each layer holds and decides

| Layer | Holds | Decides access by | Trusted with |
|---|---|---|---|
| **Veil server** | everything | the one access function (`HUB.md` §4.6), on every request | plain-text code; never secrets' keys |
| **Regional cache** | immutable objects of many projects, by `(project, id)` | a read grant signed by the server, plus the path the client met the object at (§4.3) | plain-text code, as the server is: run by the server's operator, inside the same trust boundary |
| **Veil daemon** (one per machine) | immutable objects fetched by anyone on the machine | the same grant and path check, per request | what its machine's people may read (the machine is theirs) |
| **Client cache** (per repository) | objects this repository fetched or created | nothing: it holds only what this person was given | this person's device |
| **Workspace `vl`** | the device identity, secret keys, the session | — | everything its person may do |

**Only immutable objects are cached.** Tips, history answers, grants, key rings, pushes and API commits always go to the server. A cache never answers "what is `main`".

**Each layer talks only to the next one,** with the same requests. A failing cache is skipped: the layer below asks the next one up. A cache outage slows reads; it never blocks a landing, which never goes through a cache.

### 4.2 Fetch on demand

Scion's protocol, which the S1 server already follows (`HUB.md` §13.5):

1. The client asks the server for the **tips** and receives, for each branch it may see, its projected snapshot id and a **read grant** for that snapshot (§4.3).
2. It asks for the **root tree**, then the trees it lacks, level by level, then the files it needs. Every request names an object by id. **The client never sends a list of what it has.**
3. Each request is for an immutable object, so **any cache can answer it**, and **a dropped download resumes**: single objects by `Range`, batches by asking again for the ids that did not arrive.
4. A thin client fetches **only the tip snapshot** it works on, not the history below it. History is asked for when needed (§5.4).

The client side is `6-partial-clone.md` as designed (the `partial` marker, the cache area that alone is evicted, `VeilError::Unavailable`, anchors, promotion of cached objects a transaction references), with two changes:

* **No full snapshot graph.** `6-partial-clone.md` kept every snapshot "until the server answers history through its API". At 1,000 landings a second, `main` gains about 86 million snapshots a day, so a thin clone keeps only the snapshots it uses. The engine walks that needed the whole graph run on the server instead (§5.4 lists them).
* **The promisor reads through the daemon** when one runs, then straight from the server.

### 4.3 Caches only serve what the asker may see

The server cannot be asked on every cache hit, or caches would save nothing. Instead **the server hands out its decision in a form each cache can check by itself**.

**The read grant.** With the tips, and whenever a client asks, the server returns

```text
grant = Ed25519(server grant key, "hub-grant" ‖ JSON {
          project, person, device,         // who it was issued to
          view: "<view key>",              // HUB.md §13.4: a hash of what this viewer may read
          root: "<projected tree id>",     // the viewer's projected root tree of one snapshot
          epoch: <access epoch>,           // §4.4
          expires: <unix ms>               // 10 minutes
        })
```

**Reachability is the authority.** A projected tree contains exactly what its viewer may read: hidden entries are left out, names included, and a subtree with no access line below it is kept by id (`HUB.md` §13.4). So **every object reachable from the projected root of a grant is one its holder may read**, and nothing else is.

A request through any cache names, for each object, **the path where the client met it**: the chain of tree ids from the grant's root down to the object (S1's `fetch` already asks for the path; this makes it checkable without the database). A cache serves object `O` only if:

1. the grant's signature verifies under the server's grant key (each cache is configured with it, as `vl login` pins the server's identity);
2. the grant has not expired, and its epoch is current (§4.4);
3. the request is signed by the grant's device (§4.5);
4. the chain starts at the grant's root, each tree in it holds an entry naming the next (the cache reads those trees from its own store, each re-hashed against its id), and the last entry names `O`.

Otherwise it answers exactly what an absent object gets. It does not look the object up first, so a refusal takes the same path whether the cache holds the object or not.

**Why this is enough.** The check needs no database, no policy and no group list at the cache: only the server's public key and objects addressed by hash. The server's single access function made the decision once, when it built the projected tree. A cache cannot be talked into a wider view, because a wider grant would need the server's signature.

| Layer | Enforced by | Can it serve someone without access? |
|---|---|---|
| Server | the access function, on every request | no |
| Regional cache | grant + chain, per object | no: needs a server-signed grant whose projected root reaches the object |
| Veil daemon | grant + chain, per object, for each requester | no, for the same reason; a sandboxed agent presents its own narrower grant (§4.6) |
| Client cache | holds only its person's objects | it is that person's |

**Public folders** have a grant anyone can get without signing in: the public view's root. Objects reachable from it may also be served by any HTTP cache or CDN under a URL that carries the chain (`/v1/public/{project}/{root}/{tree…}/{id}`); the origin checks the chain once, and the cache key is the whole URL.

**Projects never share objects** (S1 stores them under `p/<project id>/`), and caches key by `(project, id)`. Knowing an object's id in one project tells nothing about another.

### 4.4 Removing access: the epoch

`VISIBILITY.md`: removing access takes effect on the next request. At the server it still does. At caches:

* Every access change (a group change, a person removed, an accepted `.veilpolicy`, a device removed) **bumps an epoch**: per person for a group or device change, per project for a policy change.
* The server publishes changed epochs on a small feed (`GET /v1/epochs?since=N`). Regional caches poll it every second; daemons poll their regional cache (or the server).
* A grant older than its person's or project's current epoch is refused. The client asks the server for a new one, and the server applies the new access.
* **A cache that cannot read the feed for 5 seconds stops serving private objects** and only passes requests up. It fails closed.

So removal is immediate at the server and **takes about 2 seconds at caches** (5 at most). This is a product decision for the owner (§10, item 1).

### 4.5 Who may use a grant

A grant names the device it was issued to. A request through a cache carries a signature by that device's key over `(grant hash, the ids asked for, a timestamp)`, using the per-request signing context `HUB.md` §4.3 already planned (`hub-request`). A grant copied to another machine is useless without the device key. Inside one machine, see §4.6.

### 4.6 The Veil daemon, the workspace `vl` and isolated sandboxes

**Processes and their keys.**

| Process | Runs | Holds |
|---|---|---|
| The **workspace `vl`** (`vl ws exec`, `vl ws mount`, any `vl` command) | outside the sandbox, as the person | the device identity, secret keys it opens, its session and grants |
| The **Veil daemon** | outside every sandbox, one per OS user | objects (plain-text code, ciphertext of secrets), its watch state. **No device key, no session, no secret key, no decrypted secret** |
| The **command in the sandbox** (the agent) | inside the isolated sandbox (`OVERVIEW.md`) | the files of its workspace, and the secrets `vl ws exec` injected for it; nothing else |

"Keys stay in each agent's process" means: in the workspace `vl` that runs the agent, never in the shared daemon and never inside the sandbox.

**Reads.** The agent reads a file in its mounted workspace. The FUSE handler in the workspace `vl` looks in the repository's cache, then asks the daemon over its socket with the agent's grant, the chain and a device signature. The daemon checks them (§4.3) and serves from its store, or forwards the same signed request upstream and keeps the answer. **The sandbox never sees the daemon's socket or its store**: both live under `$XDG_RUNTIME_DIR/veil/` and `~/.cache/veil/` (0700), which the sandbox hides with the rest of `HOME`.

**An agent that runs `vl` itself.** Inside the sandbox there is no device key, so `vl` there cannot sign in. `vl ws exec` gives the sandbox one socket, `$VEIL_WORKSPACE_SOCKET`, served by the workspace `vl` outside. A `vl` inside the sandbox sends its command there: `status`, `diff`, `log`, `show`, `blame`, `commit`, `describe`, `new`, `land` (phase 4), `fetch`. The workspace `vl` runs it with the agent's session (§5.6) on that workspace only. Commands that change access, identity, groups or other workspaces are refused through this socket.

**"Or less."** An agent given less than its person (`vl ws exec --only src/api`) gets an **agent session** with that narrower view (§5.6), and so a grant whose projected root holds only `src/api`. The daemon serves it nothing outside, even objects other agents on the machine fetched.

**Warm start.** The daemon follows the tips of the projects its machine uses (one tips request a second per project, from the server) and keeps the top levels of `main`'s trees fetched (by default the trees down to depth 3, and every tree read in the last day). A new workspace finds its first trees on the machine. This is Scion's "daemon that starts from a periodically refreshed snapshot", without a snapshot file to ship.

**Size.** Default 20 GiB or 10 % of the disk, whichever is less (`vl daemon --cache-size`); least recently used first; the objects of mounted workspaces' current trees are pinned.

### 4.7 The file watcher: `vl status` and `vl commit` without a scan

Commit one changed file costs 43–49 ms at 10,000 files, against Git's 27–38 ms; 14–20 ms of it is the scan of the working copy (`OPENSCION.md`). The fix OPENSCION named is a watcher.

* **What the daemon watches:** working copies that asked (`vl` registers a working copy the first time it runs there, unless `watch = false` in `.veil/local/config.toml`). It uses inotify on Linux and FSEvents on macOS.
* **The protocol.** `vl status` and `vl commit` ask the daemon "what changed under this working copy since token T", where T is what the last scan or snapshot recorded in `checkout.json`. The daemon answers a set of paths and a new token, or **"unknown: rescan"**.
* **It never misses a change silently.** The daemon answers "unknown" when: it started after T was issued; the kernel queue overflowed (`IN_Q_OVERFLOW`, FSEvents' `MustScanSubDirs`); a watch could not be added (the inotify limit); the working copy was moved, or a directory under it was replaced by a mount; or the token is not one it issued. `vl` then scans as today, and the scan's result gives the next token.
* **The stat cache still decides.** The watcher only narrows which paths `vl` looks at; each of them goes through the existing stat-cache and racy-window rules, so a file written in the same instant as the commit is still read.
* **Mounted and sandboxed workspaces need no watcher.** The FUSE handler sees every write, and so does the sandbox's write layer; their dirty set is exact and free.

### 4.8 Fresh agent workspaces in seconds

| Step | Cold machine | Warm daemon |
|---|---:|---:|
| `vl ws new NAME --mount DIR`: tips, grant, the projected tip snapshot | 1 request, about 10 ms | the same (tips always go to the server) |
| root and top-level trees | 1–3 requests | 0 requests |
| FUSE mount, sandbox start (namespaces, no copying) | 10–50 ms | 10–50 ms |
| **ready: the agent can `ls` and read** | **under 2 s** | **under 300 ms** |
| a build reading 10,000 files | fetched by folder, 8 requests at once | from the daemon's disk |

**Independent of the project's size:** nothing is proportional to the number of files or the length of history, except what the agent reads. On opening a folder, the mount fetches its small files in one request (`6-partial-clone.md`, batching). `readdir` and `stat` never fetch file contents: sizes are in the tree entries.

**Without FUSE** (macOS without macFUSE, a container without `/dev/fuse`): the workspace is a sparse checkout of the folders the task names (`--only`), fetched on demand at each `vl` command. Seconds, but not independent of how much is checked out. This is a product decision for the owner (§10, item 4).

## 5. Data model and protocol changes

### 5.1 API

| Route | Change |
|---|---|
| `GET /v1/projects/{p}/tips` | adds a read grant per tip; served from an in-memory copy of the tips refreshed on every branch move (a pull may see a tip up to 100 ms old; no push depends on it) |
| `POST …/grants {snapshot}` | a grant for a projected snapshot the caller may see (an older revision, for `vl log -p`, `blame`) |
| `GET /v1/objects/{project}/{id}` | one object; headers `Veil-Grant`, `Veil-Chain` (tree ids), `Veil-Signature`. `Range` supported. Answered by the server or any cache |
| `POST /v1/objects/{project}:batch {grant, wants: [{chain, id}], sig}` | many objects as S1's object frames; answered by the server or any cache; what does not arrive is asked for again |
| `GET /v1/epochs?since=N` | changed access epochs: `[{person}|{project}, epoch]`, and the current N |
| `POST …/history {tips, stop, limit}` | gains `limit` (one page of the caller's projected snapshots, newest first) for `vl log` in a thin clone; ancestry and merge-base questions (§5.4) |
| `POST …/changes` | commits through the API (§5.5) |
| `POST /v1/sessions/agent` | a session for one agent run (§5.6) |

S1's `fetch` route stays for old clients; it becomes the server's own implementation of `:batch`.

### 5.2 Database

```sql
-- Access epochs (§4.4). A grant carries both; either one newer voids it.
CREATE TABLE IF NOT EXISTS access_epochs (
    project_id BIGINT NOT NULL,          -- 0 for a person-wide change
    person_id BIGINT NOT NULL,           -- 0 for a project-wide change
    epoch BIGINT NOT NULL,
    changed_at BIGINT NOT NULL,
    PRIMARY KEY (project_id, person_id)
);
-- Agent sessions (§5.6): a session row with a narrower view and the attribution.
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS parent_token_hash TEXT;    -- the person's session that made it
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS only_paths TEXT;           -- JSON list, or NULL for the person's view
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS attribution TEXT;          -- JSON {agent, task?, prompt?, run?}
-- Changes made through the API and not yet on a branch (§5.5).
CREATE TABLE IF NOT EXISTS change_refs (
    project_id BIGINT NOT NULL,
    change_id TEXT NOT NULL,
    snapshot TEXT NOT NULL,
    created_by BIGINT NOT NULL,          -- the session's person
    created_at BIGINT NOT NULL,
    PRIMARY KEY (project_id, change_id)
);
```

A **permission cache** in each API server (in memory, not in the database) holds `(person, project, epoch) → groups, admin, view key, readable rules`; an epoch change voids it. This removes the 4 statements per request `LOAD.md` measured. A **snapshot-resolution cache** holds `(view key, projected id) → real id`. Both are caches: a miss reads the database as today.

### 5.3 Object store

Objects keep their keys and ids. Small objects of a push are stored together in one pack with an index, and every object is compressed (S27–S29, `storage-and-cost.md` §6–8); readers still receive objects one at a time, after the same checks. The server's grant key is a new Ed25519 key in the data directory beside `hub-identity.json` (0600). Caches store objects by `(project, id)` as the server does, re-hash every object they read, and hold no other state: losing a cache loses nothing.

### 5.4 What moves from a thin client to the server

The engine walks that today read the whole local graph (`docs/design/scale/3-history-index.md`, "the walks that read all history") run on the server for a thin clone:

| Walk | In a thin clone |
|---|---|
| `log`, `log -- PATH` | pages of `history` (phase 3: the query API) |
| `is_ancestor`, `merge_bases` (rebase, `check_current`) | `history` asks the server (phase 3: the commit-graph index answers in milliseconds; until then the server walks its own store) |
| `embargo_withheld`, confinement | the server's: it knows every embargo's record and lines |
| push closure | the server checks closure itself (receipts, `HUB.md` §13.5) |

A thin clone that needs one of these and cannot reach the server fails with `Unavailable`; it never guesses.

### 5.5 Commits through the API

```text
POST /v1/projects/{p}/changes
{
  "base": "<projected snapshot id the caller may see>",
  "change_id": "<optional: a new revision of an existing change>",
  "description": "…",
  "edits": [
    {"path": "src/api/handler.rs", "put": {"object": "<id>"} },          // uploaded first (receipt)
    {"path": "src/api/new.rs",     "put": {"text": "…", "executable": false} },
    {"path": "src/api/old.rs",     "delete": true }
  ],
  "onto": {"branch": "main", "expected": "<id>" | "rebase"}        // optional
}
→ {"change_id": "…", "snapshot": "<projected id>", "branch": {"status": "ok" | "rejected", …}}
```

* **The server builds the snapshot** on its full tree of `base` (the graft of `HUB.md` §13.4, from a list of edits instead of a projected tree), signs it with its key, and stores it on a change ref. `author` is the session's person; the agent attribution is the session's (§5.6).
* **The same checks as a push** (`HUB.md` §4.5): write access for every edited path; `.veilpolicy` edits from admins only; the object checks; **secrets must arrive as ciphertext**, sealed by the caller's `vl` (`vl change new` does it), and a plain-text file at a secret path is refused; personal keys are refused. **The server-side secret scan (check 9, not built in S1) is built here**, because content from the API has not passed a `vl` scanner.
* **`onto`** moves a branch in the same request. `expected` is the S1 compare-and-swap. `"rebase"` lets the server retry on its own: if the branch moved, it reapplies the edits onto the new tip when no edited path changed in between (the entry at each edited path, and each folder above it, is the same in `base` and in the new tip), up to 5 times, then answers `rejected: moved`. This is the first step toward phase 4's landing, without batching.
* **Size limits:** 10,000 edits and 64 MiB of inline text per request; larger changes upload objects first.

### 5.6 Agent sessions and attribution

* **An agent session is not an API key.** `vl ws exec` (or `vl session agent` for a harness) asks the server for one with the person's session: it lasts for the run (at most 12 hours), sees at most what the person sees, and may be narrowed (`--only PATH…`). Nobody creates, stores or rotates it. The server refuses a session wider than its parent's, and every request on it is checked as the person's, then narrowed.
* **Narrowing applies to files:** trees, grants, reads and writes. The session's history (which changes it sees in `vl log`, with their descriptions) is its person's projection. So narrowed sessions create no new view keys for projected history, which keeps projection work proportional to the people in a project, not to its agents (phase 4 §4.5).
* **Attribution** follows `docs/design/scale/7-agent-attribution.md`: the snapshot field `agent: {agent, task?, prompt?, run?}`, covered by the snapshot's signature. It is set **only** by the workspace `vl` from its own arguments and environment, or by the server from the agent session's record for API commits. A command inside the sandbox cannot set it: the workspace socket stamps every commit with the session's attribution and ignores any the caller sends.
* **Visibility:** `task` and `prompt` are seen by exactly the people who see the change, as its description is; under an unreleased embargo they are withheld with it (`7-agent-attribution.md`, threats 1 and 2).
* **Format:** the field needs the repository format that `FORMAT.md` lists for it ("Not yet built: snapshot attribution"). If format 6 has shipped without it, it becomes format 7 with a `vl upgrade` path (technical question 1).

## 6. Threat review

Attackers are those of `HUB.md` §3.2. The server is trusted with code, never with secrets (§3.1). A regional cache is run by the server's operator and is inside the same boundary; the Veil daemon is part of the machine it runs on.

| # | Attacker | Capability | Harm | Mitigation | Test |
|---|---|---|---|---|---|
| 1 | Person without access to `billing/` | asks a cache for an object id they learned (a log, a guess, an old grant) | receives a hidden file | grant + chain: the object must be reachable from the projected root of a server-signed grant (§4.3); refused before any lookup | `cache_access`: for each layer, a viewer without `billing/` asks for every object id under `billing/`, with their own grant and every chain they can build from trees they hold: all refused, and the layer's log shows no hit |
| 2 | Same | presents a real grant with a chain that passes through a tree of another snapshot | escapes their projection | the chain must start at the grant's root, and each step is read from the cache's own hash-checked store | forged chains (wrong root, a tree not containing the next id, a real tree of the admin's view): all refused |
| 3 | Anyone who copies a grant | replays it from another machine | reads as someone else | grants name a device; requests are signed by it (§4.5); grants expire in 10 minutes | a grant used with another device key, and without a signature: refused |
| 4 | A person just removed from `finance` | keeps using a grant at a cache | reads `billing/` after removal | per-person and per-project epochs on a feed; caches fail closed without it (§4.4) | remove a person; within 5 s every layer refuses their old grant; with the feed blocked, the cache stops serving private objects within 5 s |
| 5 | A sandboxed agent given less (`--only src/api`) | asks the daemon, through any socket it can reach, for objects other agents fetched | reads outside its task | the sandbox cannot see the daemon's socket or store; the workspace `vl` asks with the agent session's narrower grant | `sandbox_daemon`: an agent with `--only src/api` tries `cat`, `find`, a raw connect to every socket path, and reads of `~/.cache/veil`: nothing outside `src/api` |
| 6 | A command inside the sandbox | sets `VEIL_AGENT`, sends attribution through the workspace socket, runs `vl describe --agent` | forges attribution | attribution comes from the workspace `vl`'s own arguments or the agent session's record; the socket ignores the caller's | extend `7-agent-attribution.md` threat 3 to the socket: the recorded snapshot carries the harness's attribution |
| 7 | A command inside the sandbox | sends `vl access`, `vl group add`, `vl identity` through the workspace socket | changes access with its person's identity | the socket accepts only workspace commands (§4.6) | every other command through the socket is refused |
| 8 | A local process on the machine | writes a bad object into the daemon's store or answers on its socket | serves wrong content | every object is re-hashed against its id by every reader; the socket is in a 0700 directory of the user | flip bytes in the daemon's store: the read fails over to upstream; never wrong bytes |
| 9 | A failing or partitioned cache | answers "absent" for an object that exists | `vl` leaves out a file or drops history (the redaction confusion) | "absent" from a cache is not authority: `vl` asks the next layer, and only the server's answer "not there or not yours" is `Missing`; anything else is `Unavailable` (`6-partial-clone.md`, threat 1) | a cache that lies "absent": the read succeeds from the server; with the server stopped: `Unavailable`, nothing written |
| 10 | — (a bug) | the watcher misses an event | a commit silently leaves out an edit | the daemon answers "unknown: rescan" on overflow, restart, a failed watch, a moved tree or a foreign token; the stat cache still applies (§4.7) | `watcher`: overflow the queue, kill the daemon between edits, exceed the watch limit, replace a folder by a mount, edit within the racy window: every edit is committed |
| 11 | Hostile API client | sends a plain-text secret, a personal key, an edit outside its folders, a `.veilpolicy` edit | stores a secret in the clear, or writes where it may not | the push checks, plus the server-side secret scan (§5.5) | `api_changes`: each case refused, and nothing is stored on a ref |
| 12 | Hostile API client | an edit list with `..`, NUL, `.veil`, 10⁶ entries, deep paths | corrupts the tree or exhausts the server | the tree builder's name checks; the request limits | the hostile-names corpus through `POST …/changes` |
| 13 | Same | `onto: rebase` races another landing | loses a change or lands on a stale tree | the rebase reapplies edits on the new tip only if each edited path is unchanged, inside the compare-and-swap transaction | 50 agents rebasing onto one `main`: every change lands once, and each landed snapshot's diff against its parent equals its edits |
| 14 | Person without access | times cache hits and misses | learns that someone read a hidden object | the grant is checked before the lookup; only objects the asker may read can be timed | residual: they learn that someone else recently read a file they may read. Accepted, documented |
| 15 | Anyone | crafts a grant, or re-uses a grant of one project in another | reads another project | grants name the project; caches key by `(project, id)`; a new signing context `hub-grant` | cross-project and cross-context grants refused |
| 16 | — (an old `vl`) | opens a thin clone | reads unfetched objects as redacted | the `partial` marker and its format gate (`6-partial-clone.md`, threat 14) | `format_compat` with a thin-clone fixture |
| 17 | A compromised regional cache | reads what it stores | reads plain-text code | inside the server's boundary by design; secrets and embargoed content reach it only as ciphertext | the cache's store holds no plaintext secret (grep test, as for the server) |
| 18 | `find`, `grep -r`, an IDE indexer in a mount | reads everything | fetch storm, a cache that thrashes | `readdir`/`stat` fetch no contents; fetching stops at the cache limit with a clear error (`6-partial-clone.md`, threat 11); per-device request limits | `ls -lR` fetches no file; `cat` of everything with a small cache fails cleanly |

## 7. How this phase moves the owner's numbers

| Number | Before (measured) | After phase 2 (target) | Why |
|---|---|---|---|
| Pulls/s, one project, `main` moving 20/s | 2,100–2,500 (one machine) | **10,000** on the same machine, with over 99 % of object reads answered by caches | per-person permission cache and snapshot-resolution cache (46 → about 6 statements per pull); thin pulls fetch the tip, not every snapshot since; objects from caches |
| Pulls/s while `main` moves 1,000/s | not measured; catch-up pulls fetch every new snapshot | **1,000+**, cost per pull independent of the landing rate | thin pulls never fetch intermediate snapshots |
| Landings/s across projects | 2,094 | **4,000** | one database commit per landing (the snapshot, memo, origin and audit rows in the push's transaction: 8 → 1; `storage-and-cost.md` §3), and one storage write per push for small objects (S28) |
| Landings/s into one `main`, 50 agents | 20–30 | **100** | API commits with `onto: rebase`: one request per landing, and a lost race costs a server-side retry, not a catch-up pull |
| Merges per day, one project | about 2 million at 20–30/s in theory; less with peaks | **about 8 million** at 100/s, so 1 million a day with 8× peaks | as above |
| Agents at once | 2,000 simulated | **10,000** simulated, with caches | daemons and regional caches take the reads |
| Fresh workspace, any size | a clone | **under 2 s cold, under 300 ms warm** | §4.8 |
| Commit one changed file, 10k files | 43–49 ms (Git 27–38) | **beat Git on the same machine** | no scan with the watcher (14–20 ms less) |

Phase 4's batched landing takes one `main` from 100 to 1,000+ a second.

## 8. Benchmarks that prove it

All in `crates/veil-bench`, on the development machine of `OPENSCION.md` (never under `/tmp`), then on the gate hardware (§10, item 6).

| Benchmark | Measures | Gate |
|---|---|---|
| `veil-bench workspace --files 100k,1M --bytes 10G` (new) | `vl ws new --mount` to the first `ls` and `cat`; then reading 10,000 files under one folder; cold daemon, warm daemon, no daemon | ready under 2 s cold, 300 ms warm, at both sizes; reading 10,000 files under 3 s warm |
| `veil-bench load --mode pull --thin --caches regional,daemon` (extended) | pulls/s, p50/p99, statements per pull, cache hit rate per layer; `main` moving 20/s and 1,000/s | 10,000 pulls/s at 20/s; 1,000 pulls/s at 1,000/s; 99 % of object reads from caches |
| `veil-bench load --mode land --api --rebase` (extended) | landings/s into one `main` with 50 and 1,000 agents; across 100 projects | 100/s into one `main` with p99 under 500 ms; 4,000/s across projects; 1 database commit and at most 2 storage writes per landing (`storage-and-cost.md` §9) |
| `veil-bench openscion` (existing) | commit one changed file with the watcher; clone one directory as a thin clone | commit one changed file beats Git at 1k and 10k; clone one directory beats Git |
| `veil-bench cache-access` (new, a correctness run at load) | the leak checks of §6 rows 1–5 under load, with access changes during the run | zero objects served outside a requester's view; removal effective within 5 s at every layer |

## 9. Milestones

Each is small enough for one agent. Dependencies and parallel work are in `docs/design/server/README.md`.

| # | Milestone | Contents | Depends on | Touches |
|---|---|---|---|---|
| **S3** | Fetch on demand in the client | `6-partial-clone.md` as amended here: `partial` marker, promisor, `Unavailable`, bounded cache and eviction, anchors; thin clone by default with no full graph; `vl log`/ancestry through `history` pages; `--full`, `vl partial`; uses S1's `fetch` | S1; the simplification pass (or S3 refuses partial clones of path and SFTP remotes) | `veil-core` store and remote, `crates/vl/src/hub.rs` |
| **S4** (**built**, `HUB.md` §13.14) | Request-path caches and one commit per landing | permission cache per person and project, session cache, snapshot-resolution cache, in-memory tips invalidated by notification (no per-project counter); the snapshot, memo, origin and audit rows in the push transaction; cost gates in `veil-bench load` (`storage-and-cost.md`) | S1 | `veil-server` `auth.rs`, `perm.rs`, `sync.rs` |
| **S5** (built, `HUB.md` §13.16) | Read grants and the object routes | grant key, `hub-grant` and `hub-request` contexts, grants with tips, `GET /v1/objects`, `:batch`, the chain check as a `veil-core::hub` function (WASM-safe, shared by every layer), access epochs and their feed | S1 | `veil-core/src/hub/`, new `veil-server` `grant.rs` |
| **S6** | The Veil daemon: shared object cache | `vl daemon`, socket, store, LRU and pinning, grant and chain checks per request, forwarding signed requests upstream, epoch polling, warm trees of followed projects; the promisor reads through it | S3, S5 | new `crates/vl/src/daemon/` |
| **S7** | The file watcher | inotify and FSEvents, tokens in `checkout.json`, "unknown: rescan" rules, `vl status`/`commit` asking the daemon | S6 (its process and socket) | `daemon/watch.rs`, the scan in `veil-core` |
| **S8** | Workspaces that fetch on first read | `vl ws mount` and `ws exec --mount` over the promisor, folder prefetch, exact dirty sets from FUSE, the workspace socket for a `vl` inside the sandbox, the sparse fallback without FUSE | S3 (S6 for the warm numbers); the isolated sandboxes of phase 1 | `crates/vl/src/sandbox.rs`, mount code |
| **S9** (**built** 2026-11-07, `HUB.md` §13.18) | Regional cache | `veil-server cache --upstream URL`: the same object routes, grant and chain checks, epoch feed, fail closed, no database | S5 | new `veil-server` `cache/` |
| **S10** | Commits through the API (**built** 2026-11-07, `HUB.md` §13.13) | `POST …/changes`, edit-list graft, server-side secret scan (check 9), change refs, `onto` with `expected` and `rebase`, `vl change new` | S1 (S4 for the numbers) | new `veil-server` `changes.rs`, `veil-core` builder |
| **S11** | Agent sessions and attribution | `POST /v1/sessions/agent`, narrowing, `Snapshot.agent` (format per technical question 1), stamping by the workspace `vl` and the server, `vl log --agent`, `agent()` revset | S10; S8 for the socket | `veil-core` object and transaction, `veil-server` `auth.rs` |
| **G2** | Phase 2 gate run | the benchmarks of §8 on the development machine and the gate hardware; results in `docs/design/scale/` | S3–S11 | `crates/veil-bench` |

## 10. Product decisions for the owner

1. **Removal at caches takes about 2 seconds** (5 at most), and is immediate at the server. `VISIBILITY.md` says "the next request is refused". Recommendation: accept 5 seconds as the bound and say so in `VISIBILITY.md`. The alternative, a server check on every cache hit, removes most of what caches save.
2. **Agent sessions.** An agent run gets a short-lived session made automatically by `vl` from its person's, at most as wide, optionally narrower. It is not an API key: nobody makes, stores or rotates one. Recommendation: yes; it is how "or less, if it's given less" and trustworthy attribution are enforced.
3. **`vl clone` thin by default** on server projects, with `--full` for the old behaviour. Recommendation: yes.
4. **macOS mounts.** FUSE on macOS needs macFUSE, a third-party kernel extension. Recommendation: on macOS, use sparse checkouts fetched on demand by default and a mount only where macFUSE is installed; document that "workspace in seconds, independent of size" is a Linux guarantee.
5. **The daemon runs by default** (started by `vl` when needed, one per OS user), and watches working copies. Recommendation: yes, with `watch = false` and `vl daemon stop` for people who don't want it.
6. **Gate hardware.** The 10,000-agent runs need several machines (paid cloud, e.g. DigitalOcean). Needs the owner's approval before anything is rented.

## 11. Open technical questions

1. **Format for `Snapshot.agent` and the `partial` marker.** `FORMAT.md` lists both under format 6 as not built, but format 6 shipped (1.1.0) without them. An older format-6 `vl` would drop `agent` when it rewrites a snapshot. Likely format 7; `FORMAT.md` and a `vl upgrade` path decide.
2. **Chain size.** A chain is one tree id per level (32 bytes each); a batch shares prefixes. Is a compact encoding (the chain once per folder in a batch) worth it before measurement shows it matters?
3. **Grant lifetime against epoch traffic.** 10 minutes and a 1-second poll are first guesses; the gate run sets them.
4. **inotify limits on a machine with many large working copies** (one watch per directory). The rescan fallback is correct; how often it fires on a CI fleet decides whether fanotify (privileged) is worth offering.
5. **Warm-start set.** Depth 3 plus the last day's trees is a guess; the daemon could learn the set from its own reads.
6. **Pinning on a machine running many workspaces of one project:** pinned bytes can exceed the daemon's limit. Refuse new mounts, or evict pins of idle workspaces first?
