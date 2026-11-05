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

## How it scales

- **YugabyteDB** for the server's metadata: open source, with Spanner-style scaling. Plain **PostgreSQL** for development and CI.
- **S3-style object storage** for file contents, served through caches.
- **Commits never wait on a lock.** Moving `main` is one tiny atomic step on the server.
- **Clients fetch only what they need** from the server, instead of cloning everything.
- **The server does the heavy work:** merges, history, blame and search.
- **Landings are batched,** so huge numbers of agents don't contend on one branch.

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
