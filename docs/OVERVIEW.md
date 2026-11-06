# What Veil is

> **Read this first.** It is the owner's design (2026-11-05) and the top-level source of truth.
> - Access and permissions: `docs/VISIBILITY.md`.
> - Anything elsewhere that contradicts these two documents is out of date.

## In one paragraph

Veil is a new version control system built around a **central server**, the **Veil Hub**. The `vl` command-line client is **always connected** to the server. It is not Git, and it is not offline-first. The server holds every project and is the one place that decides who can see what. Veil is built for teams and for **AI agents at scale**, thousands working on one codebase at once, following the ideas of Anthropic's Scion.

## Access (details in `docs/VISIBILITY.md`)

1. Whoever creates a project is its **admin**. Everything is **private** by default.
2. Admins create **groups**, add people, and choose who **manages** each group.
3. Admins give groups or people **access to folders** (`vl access billing/ finance`).
4. **Public** folders are visible to everyone on Earth.
5. **Code is plain text on the server.** The server simply never gives a folder to anyone without access.
6. **Secrets** (`.env`, keys) are the only encrypted content. Encryption is automatic, and secrets follow the same folder access.
7. **Personal private keys** (`id_rsa`) never leave the machine they're on.

Also:
- **Hidden changes (embargoes):** a fix goes to chosen groups now, and becomes public later.
- **PRs** are visible only to people who can see every file they touch. Hidden PRs don't exist for anyone else.
- **Agents** see what their person sees, using the same secrets. Nobody makes new API keys for agents.

## How it scales: the Scion design

The Hub follows **the design of Anthropic's Scion**, which handles tens of thousands of merges a day, mostly from agents. It is built for **thousands of agents at once pulling, opening PRs and merging**.

- **Changes are written without locks.** Uploading a change is just storing its files. **Moving `main` is one tiny atomic step**: a compare-and-swap on one database row.
- **The server does the work:** merges, rebases, history, blame and search all run on the server. Agents ask through the API, often without a checkout.
- **Precomputed history:** blame, file history and the commit graph are computed once per change as it lands, so queries are instant.
- **Fetch on demand:** a client asks only for the folders and files it needs, starting from the top folder. An agent working in `src/api/` never downloads the rest.
- **Layered caches:** the client, then a cache daemon on each machine, then regional caches, then the server. Files are addressed by their hash, so any cache can serve them with no coordination; Scion serves over 99% of reads from caches. Caches only ever hold what the asker is allowed to see.
- **No locked merge queue:** ready changes that don't overlap are **merged in batches** (500 ready PRs become one move of `main`). Conflicts go back to an agent to fix. Tests run after merging and before deploy.
- **Few branches:** work lives as changes and PRs, not thousands of long-lived branches.
- **No maintenance:** each file is stored once in S3-style object storage; there is no repacking.
- **Horizontal scaling:** stateless API servers, **YugabyteDB** for metadata (Spanner-style; PostgreSQL for development and CI), and object storage. Capacity grows by adding machines.
- **Permissions on every request,** cached per person and folder, so access control never becomes the bottleneck.

### Design targets (the server's benchmark must prove them)

| What | Target |
|---|---|
| Agents working at once | **Thousands** (benchmark at 1,000 and 10,000) |
| Pull of a small change | **Under 100 ms** of server time; mostly served from cache |
| Opening or updating a PR | **Under 100 ms** |
| Merges | **Thousands per hour per project**, with no agent waiting on a global lock. Landing batches change by change. |
| A fresh agent workspace on a large project | **Seconds**, fetching on demand |
| History, blame or search through the API | **Milliseconds to low hundreds of ms**, with no checkout |
| Permission checks | A negligible share of request time |

### Speed gates: the OpenScion workloads (owner, 2026-11-06)

The owner adopted the four synthetic workloads published by OpenScion, an independent open implementation of the Scion design, as Veil's speed gates. The repositories are made of 4 KiB files; times are medians.

| Workload | 1,000 files: target | 10,000 files: target | Veil on 2026-11-06 (1k / 10k) |
|---|---:|---:|---|
| Import a directory (first snapshot) | **22 ms** | **245 ms** | 51 / 316 ms |
| Clone everything | **51 ms** | **544 ms** | 50 / 483 ms ✅ |
| Commit one changed file | **2.5 ms** | **22 ms** | 12.8 / 27 ms (Git: 4.6 / 8.9 ms) |
| Clone one directory | **6.1 ms** | **25 ms** | not built (fetch on demand) |

- The Veil numbers were measured on the development machine with a release build, the median of 5 runs, and Git as a same-machine reference. Absolute numbers depend on the machine, so each gate also requires **beating Git on the same machine**.
- **The biggest gap is committing one file:** fixed per-command overhead (opening the repository, keys, the op log, the working-copy scan).
- **These run in `crates/veil-bench` as a permanent profile,** re-run on every stream that touches the client or the server. Once the server exists, clone is also measured over the network.

## What exists today, and what's next

- **Built: the client engine.**
  - snapshots and change ids, undo, workspaces and agent sandboxes;
  - blame, bisect, cherry-pick;
  - a lock-free op log (64 agents at once, no waits);
  - a history index;
  - streaming storage, safe gc, secret scanning, embargoes.
- **Next: the server and the permission model, built together.** That covers the server, the database, storage, sign-in, groups, admins, folder access, public, encrypted secrets, and `vl` pushing and pulling through the server, with each person receiving only what they may see.
- **Then: a simplification pass.** Remove what the server makes unnecessary: plain-file (SFTP and path) remotes, offline assumptions, old storage formats and old jargon.
- **Then: the server's features, in stages.**
  - fetch on demand;
  - server-side history and search;
  - landing changes at agent scale;
  - PR review and hidden PRs.

## Non-goals

- **Git interop.** No import, export, sync, colocation, submodules or Git-format patches. This is permanent.
- **Offline use, or plain-file remotes** (SFTP, shared drives).
- **Encrypting code.** Only secrets and embargoed changes are encrypted.
