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
- **Cheap storage:** each file is stored once, compressed, in S3-style object storage. A push's small files go up together as **one pack** (one storage write per push instead of one per file), and a background job merges small packs, as Git hosting does. Readers still get files one at a time, only those they may see (`docs/design/server/storage-and-cost.md`).
- **One database commit per push,** and sign-ins, permissions and branch tips answered from each server's memory, so the database is never the bottleneck.
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
| Cost per push | **1 database commit, at most 2 storage writes**; a warm pull is 5 or fewer database statements |

### Speed gates: the OpenScion workloads (owner, 2026-11-06)

The owner adopted the four synthetic workloads published by OpenScion, an independent open implementation of the Scion design, as Veil's speed gates. The repositories are made of 4 KiB files; times are medians.

| Workload | 1,000 files: target | 10,000 files: target | Veil, real disk, through the server (1k / 10k) |
|---|---:|---:|---|
| Import a directory (first snapshot) | **22 ms** | **245 ms** | 48–58 / 202–208 ms after performance round 1 (Git: 87–94 / 763–764 ms) |
| Clone everything | **51 ms** | **544 ms** | 114–119 / **437–449 ms** after performance round 2: **10k meets its target** (Git: 169–192 / 563–589 ms) |
| Commit one changed file | **2.5 ms** | **22 ms** | 15.3 / 22.3 ms after performance round 3 (Git: 8.2 / 9.9 ms; 21.8 / 39.7 ms before the round) |
| Clone one directory | **6.1 ms** | **25 ms** | 55–69 / 69–92 ms after performance round 2 (Git: 50–51 / 52–56 ms) |

- **Measured by the S1 server milestone** on an ext4 NVMe disk: release builds, the median of 5, PostgreSQL, with Git as the same-machine reference. Absolute numbers depend on the machine, so each gate also requires **beating Git on the same machine**. **No gate is met yet.**
- **Correction:** an earlier table here (51 / 316, 50 / 483, 12.8 / 27 ms) was measured under `/tmp`, which is a tmpfs on the development machine, where `fsync` costs nothing. Those numbers were invalid. **Never benchmark under `/tmp` on that machine.**
- **BUG-818 fixed** (one durability barrier per checkout): clones are 2.5–10× faster. The rest of a 10k clone is the transfer plus about 16 `openat` calls per file from checkout's no-follow path walks.
- **Performance round 1** (`docs/design/scale/OPENSCION.md`): import beats Git (1.7× at 1k, 3.7× at 10k); commit one file does not yet (Git does no fsync; Veil's commit is two durable transactions). **Measured as OpenScion measures** (in one process, in memory, no disk or process start), Veil meets the import, clone-everything and commit targets: 8.8 / 86 ms, 32 / 303 ms, 0.9 / 7.4 ms.
- **Performance round 2** (`docs/design/scale/OPENSCION.md`): clone everything is 2.3× faster at 10k (beats Git 1.3×, meets 544 ms); `vl commit` is one operation; the server's load curves are in `docs/design/scale/LOAD.md` (about 2,500 pulls/s and 2,000 landings/s across projects on one machine).
- **Performance round 3** (`docs/design/scale/OPENSCION.md`, 2026-11-07): commit one file is 1.4× (1k) and 1.8× (10k) faster, still about 2× slower than Git (which makes no fsync). Its transaction makes its objects, operation and head durable with four barriers in sequence instead of about twenty; the scanner compiles its rules only for text that could hold a token; large working copies are listed, stat'ed and classified ahead of the walk on other threads.
- **Through the server** (`scripts/bench-server.sh`, 2026-11-06, `docs/design/scale/BASELINE.md`): after the server bench fixes (BUG-857 to BUG-861) the 1 GB profile passes the 512 MiB memory gate: its initial push is accepted in one push (401 MiB, was 2,410 MiB and refused) and its full clone peaks at 433 MiB (was 918–979 MiB). The server still grows past its bounded caches, now mostly glibc's per-thread arenas (BUG-864), and checks a long history's snapshots one at a time (BUG-865). Landings with MinIO stop at about 376/s, limited by the object store; a reset S3 connection is now tried again (BUG-861).
- **Next costs:** clone one directory's ~60 sequential `fsync`s, checkout's path walks, the commit's walk of the working copy on one thread (about 1 µs a file) and its six barriers in sequence.
- **Performance rounds continue until every gate is met.** The profile runs in `crates/veil-bench` (`docs/design/scale/OPENSCION.md`) and is re-run on every stream that touches the client or the server.

## What exists today, and what's next

- **Built: the client engine.**
  - snapshots and change ids, undo, workspaces and agent sandboxes;
  - blame, bisect, cherry-pick;
  - a lock-free op log (64 agents at once, no waits);
  - a history index;
  - streaming storage, safe gc, secret scanning, embargoes.
- **Built (milestone S1, 2026-11-06): the server and the permission model, together** (`docs/HUB.md` §13). The server, the database (PostgreSQL, YugabyteDB), object storage (S3), sign-in, groups, admins, folder access, public, secrets encrypted on the device, and `vl` pushing, pulling and cloning (one directory too) through the server, with each person receiving only what they may see.
- **Required for phase 1: isolated agent sandboxes** (owner, 2026-11-06). Every `vl ws exec` runs the agent in an isolated view of the machine, not just a separate folder.
  - **Built on Linux (2026-11-06)** with bubblewrap, default on, with the limits (`docs/design/scale/9-confinement.md`, the guide's "Confinement and limits"). A confined run starts about 5 ms slower than an unconfined one; a limit that needs a systemd scope adds about 40 ms. **Not built yet:** macOS and `--container`.
  - **Linux:**
    - kernel namespaces, with no Docker image and no copying, starting in milliseconds and needing no root;
    - the computer's own tools (`/usr`, `/bin`, `/lib`, toolchains) are visible **read-only and live**;
    - the sandbox appears **at the project's real path**, starting in the same sub-folder, so directories and absolute paths behave as in the real project, while every write goes to the sandbox;
    - `HOME` and `/tmp` are private; `~/.ssh`, personal keys and other projects are hidden;
    - toolchains and the agent's own configuration (`~/.cargo`, `~/.claude`) are writable through a layer of the workspace's own, so downloads and sessions persist for that workspace, and the real folders are never changed;
    - the agent sees only its own processes;
    - **CPU, memory, process and time limits** apply.
  - **Network:** on by default, because agents need their model's API; `--no-network` for runs that shouldn't call out.
  - **macOS:** Apple's sandbox profiles; weaker, and documented as such.
  - **Optional `--container IMAGE`** (Docker or Podman) for a fully separate environment, with the sandbox mounted at the same path.
  - **Tests prove** an agent can't read `~/.ssh` or write outside its sandbox.
- **Then: a simplification pass.** Remove what the server makes unnecessary: plain-file (SFTP and path) remotes, offline assumptions, old storage formats and old jargon.
- **Then: the server's features, in stages.**
  - fetch on demand;
  - server-side history and search;
  - landing changes at agent scale;
  - PR review and hidden PRs.

## Non-goals

- **Git interop.** No import, export, sync, colocation, submodules or Git-format patches. This is permanent.
- **Offline use, or plain-file remotes** (SFTP, shared drives).
- **Encrypting code.** Only secrets (`.env`, keys) are encrypted. Embargoed changes are protected by the server's permissions and made public by the server at their deadline.
