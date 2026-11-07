# Who can see what: Veil's permission model

> **Status:** decided by the owner on 2026-11-05. Milestone S1 of the server builds it (2026-11-06), and S2 finishes its secrets (invites, a key per folder, keys shared in the background, device removal): see "As built" below.
>
> **This document is the source of truth.** Where `ARCHITECTURE.md`, `HUB.md`, a guide or an older design doc disagrees with it, this document wins, and the other one needs updating. **Keep it this simple:** it is the ordinary permission model everyone already knows.

## The model

1. **You create a project, and you are its admin.** Everything in it is **private**: only admins can see it.
2. **Admins create groups** (`finance`, `ops`, `security`) and **add people** to them.
3. **Admins decide who may manage each group,** that is, who may add or remove its people. Example: carol manages `finance`.
4. **Admins give a group, or one person, access to a folder or file.** Example: `finance` can see `billing/`.
5. **`public`** folders can be seen by **everyone on Earth**.

That's all. Nobody sees anything they weren't given, and making something public is always a deliberate step.

```
vl init                               # you are the admin; everything is private
vl group create finance
vl group add finance alice bob
vl group manager finance carol        # carol may add people to finance
vl access billing/ finance            # finance can see billing/
vl access src/ public                 # everyone on Earth can see src/
vl access billing/                    # show who can see billing/, and why
```

The rules live in the project's `.veilpolicy`, like any other file, with the most specific rule winning:

```
src/          public
docs/         public
billing/      finance
infra/        ops carol
```

## Two things Veil does automatically

- **Secrets are encrypted.**
  - `.env`, `.env.*`, API keys and similar files are stored **encrypted**, and decrypted only on the devices of people who have access to them.
  - **They follow the same permissions as any file.** If finance can see `billing/`, finance can open `billing/.env`.
  - The server, and anyone who breaks into it, sees only ciphertext.
  - Everything else is stored as normal files, so it costs nothing extra for agents, and the server can merge, search and blame it.
- **Personal private keys never leave your machine.** `id_rsa`, `id_ed25519` and private `*.pem` keys stay on the device they're on: never uploaded, never given to anyone. Whoever holds a copy can impersonate you.

The secret scanner also stops anything that looks like a password or token from being committed in an ordinary file.

## Who can do what

| Role | Can |
|---|---|
| **Admin** (the creator, and anyone they make admin) | See everything; create and delete groups; choose group managers; give and take away access to any folder; make things public; add admins |
| **Group manager** | Add and remove people in the groups they manage |
| **Member of a group** | See the folders their groups were given (plus anything public) |
| **Anyone on Earth** | See `public` folders only |
| **An agent** | Exactly what the person running it can see, or less if it's given less |

**Every change is checked:** only admins can change who can see a folder, and only a group's managers or admins can change its people. The server checks this on every push, so nobody can give themselves access by editing `.veilpolicy`.

## Agents and secrets

- **One secret, many readers.** An API key is stored once. Everyone with access to it, people and agents, uses that same key. **Nobody makes new API keys for agents.**
- **Agents on your computer** (`vl ws exec`) see what you see, including secrets you have access to. If an agent writes a secret into some other file, Veil refuses to commit it and removes it after the run.
- **A cloud machine or CI server** is added like a person. Give it the groups it needs; every agent on it shares that access. Veil creates the machine's identity automatically.
- **Over SSH** (planned): borrow your laptop's access for a session, like `ssh -A`, without storing secrets on the remote machine.
- **Isolation (built on Linux; macOS to come):** each agent's `vl ws exec` runs in an isolated view of the machine. It sees the project at its real path and the computer's tools read-only; your `~/.ssh`, personal keys and other projects are hidden; CPU, memory and time are limited. See `docs/OVERVIEW.md`.
- **The limit:** an agent that's given a secret can use it while it runs. Give risky agents test keys.

## Hidden changes (embargoes)

Some changes must reach some people now, and the public later. A security fix is the typical case.

```
vl merge fix --into main --embargo-for security distro-partners --until 2026-12-01
```

- The groups named get the fix right away: code, message and history. Everyone else, the public included, sees nothing of it until it's released.
- Anything built on top of it stays hidden too.
- `vl embargo release`, or the deadline, makes it public.
- **Embargoes are permissions, not encryption** (owner, 2026-11-06). An embargoed change is plain text on the server, visible only to the groups and people named. **The server makes it public at the deadline,** or when someone with the right runs `vl embargo release`. Outside partners (e.g. distro maintainers) get accounts and are named like anyone else.

## Who can see a PR

- **A PR is visible only to people who can see every file it touches.** There is no partial view, because the title and comments describe the change.
- **An embargoed PR doesn't exist** for anyone outside its groups: no title, no count, no placeholder.
- **The same check applies everywhere:** search, notifications, counts, the API, agents and CI.

## What is encrypted: secrets only

**The only thing Veil encrypts is secret files:** `.env`, `.env.*`, keys and similar files (owner, 2026-11-06, firmly). **Nothing else is encrypted:**
- code, in any folder;
- embargoed changes and hidden PRs;
- change descriptions, tag and branch names, release notes;
- agent attribution;
- PRs, reviews and comments.

All of that is plain text, protected by the server's permissions.

**Not exceptions:** HTTPS (TLS) between `vl` and the server protects the network connection, and a device's own private key may be protected at rest by a passphrase or the OS keychain. Neither encrypts project data.

## Veil always works through its server

**Veil is server-centric, not Git and not offline-first** (owner, 2026-11-05).
- The `vl` client is always connected to the Veil server (the Hub).
- **The server stores the code and checks every permission.**
- **Restricted folders like `billing/` are plain text on the server,** and the server only gives them to the people and groups with access.
- **There are no plain-file remotes** (SFTP, shared drives) and no offline mode, so no other way of enforcing access is needed.
- **Encryption is used only for secrets** (`.env`, keys).

## What the server sees

| | public | private folders | secrets and embargoes | personal keys |
|---|---|---|---|---|
| Anyone on Earth | ✅ | ❌ | ❌ | ❌ |
| People and agents with access | ✅ | ✅ | ✅ decrypted on their device | ❌ |
| The server (and anyone who breaks in) | ✅ | ✅ | ❌ ciphertext only | ❌ never uploaded |
| A public mirror | ✅ | ❌ never sent | ❌ never sent | ❌ |

## As built (milestone S1, 2026-11-06)

What the server and `vl` do today; `docs/HUB.md` §13 has the details.

- **`.veilpolicy` access lines** are `PATH  public` and `PATH  group-or-person…`, with **the last matching line winning**. Paths are folders or files from the project root (a line with `*` or `?` grants nothing on the server). Anything no line matches is private to admins.
  ```
  vl access billing/ finance      # writes the line; push it (admins only)
  vl access billing/              # asks the server who can see billing/, and which line decides
  vl group create finance; vl group add finance alice; vl group manager finance carol
  ```
- **Folder access means read and write; `public` means read for everyone on Earth.** Writing a public folder needs a named group or person (`src/  public devs`).
- **Folders under access lines are plain text** in snapshots and on the server. The server's check is what protects them, on every request: clone, pull, the fetch API and every listing. Nobody receives a file, or a name, from a folder they cannot see.
- **History without access:** you do not see the folder's files or names in any snapshot, and a change that touched only such folders is not in your history at all. A change that touched both shows only your part (and its description). Every snapshot you receive carries a signature that verifies: its author's, or the server's on the part it left out.
- **Only admins change access.** The server refuses a push that changes access lines, on any branch, unless an admin made it; the authority is the policy accepted on the default branch, never a label inside a snapshot. Names bind to the project's group first, also when the group is created after the line, so nobody gains access by signing up under a group's name.
- **Managers** add and remove other people in their groups, never themselves.
- **Secrets** (`HUB.md` §13.11, §13.12):
  - new repositories encrypt `.env`, `.env.*`, `.envrc` and Terraform state on the device and sync them; only devices holding the key open them;
  - **each access line's secrets have their own key**, held by the people the line gives the folder to and by the admins: finance opens `billing/.env`, never `infra/.env`. A secret no line gives anyone is the admins';
  - personal private keys and credentials (`id_rsa`, `id_ed25519`, `*.pem`, `*.key`, `.netrc`, …) never leave the device, and the server refuses them;
  - existing repositories switch only with `vl upgrade --sync-secrets`, which lists the files first; a project from S1 (one key for every secret) moves to a key per folder only with an admin's `vl upgrade --rule-keys`, which lists every secret and who will hold its key first;
  - **a hacked server can never hand out a key.** Keys go only to **confirmed devices**: a person's first device is confirmed by an **invite** (`vl invite alice --to finance` prints a one-time link, valid 7 days, whose secret the server never sees; alice runs `vl join -` and pastes it) or by the admin comparing its fingerprint with them (`vl group add … --confirm 4F2A-…`), and their later devices by the person from a device they already use (`vl identity confirm`). The key ring itself checks every device it receives, by signatures the server cannot make; the server's lists are never enough. **Every key ring belongs to one project,** and a device trusts a project's keys only once it knows the project's fingerprint from outside the server (the invite link carries it; otherwise the person compares it with an admin, or with another of their devices, and runs `vl identity confirm` in the clone), so a hacked server can hand out neither another project's keys nor keys of its own;
  - **keys are shared in the background:** a teammate's device that holds a key gives it to a newly confirmed device within seconds of its next `vl` command; an admin's `vl group add` still grants it at once. A manager's addition, or anything the server does on its own, gives folder access but no key;
  - **removing someone rotates only the keys they lose** (an admin's `vl group remove`; a manager's says it did not rotate and asks an admin). **A lost device** is removed with `vl identity remove FINGERPRINT`: by its person, everywhere (it can no longer sign in); by an admin, from their project only. Either way the project's keys it held rotate.
- **Anyone on Earth** (not signed in) receives `public` folders only, and does not see a project with nothing public.
- **Removing access takes effect at the very next request, on every server** (S4, `HUB.md` §13.14). Servers keep sessions and permissions in memory for speed, but every request checks them against access epochs that each access change renews in the database, so no server ever answers from a decision that change made stale.
- **Read grants** (S5, `HUB.md` §13.16): with the tips, the server signs what each person may read, so caches can check it without asking. Taking access away voids them at the server's next request; caches (built later) take about 2 seconds, 5 at most (owner-approved).

## For the design: open technical questions (not product questions)

- **What history shows** someone without access to a folder: proposed, they don't see its files or even their names. Snapshot signatures must still verify (a per-viewer projection served by the server).
- **The authority:** the server enforces access from the accepted `.veilpolicy` and its own group and admin records, by path, never from labels inside a snapshot.
- **What the client keeps locally:** a cache of what the user may see. Fetch on demand from the server comes from the scale plan.
- **Existing repositories:**
  - `.env` files start syncing (encrypted) only after an explicit upgrade step that lists them;
  - a repository written before format 8 (when `vl` could still encrypt descriptions, tags, embargoes and folders) is upgraded only if it holds none of that; otherwise `vl upgrade` refuses and names each thing (`docs/FORMAT.md`). Nothing is ever made public, decrypted or dropped silently.
- **Commands:** `vl access` decides who sees a folder. `vl cloak` seals secret files only (it refuses anything else); a `cloak` line in `.veilpolicy` on a path that is not a secret file keeps that path on the device (`isolate`), with a warning. `vl isolate` and `vl expose` write plain `isolate` and `public` rules.
