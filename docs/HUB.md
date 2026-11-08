# Veil Hub: the server design

> **Sources of truth:** `docs/OVERVIEW.md` (what Veil is) and `docs/VISIBILITY.md` (who can see what). This document is how the server implements them. Where it disagrees with either, they win.

Status: **milestone S1 is built** (`crates/veil-server`, the `vl` client
commands, 2026-11-06): the server core, sign-in, the permission model,
sync with fetch on demand, enforcement and secrets sealed on the device.
**§13 records what was built and every decision S1 made**; where §1–§12
propose something §13 decided otherwise, §13 is what runs. Later
milestones are in §13.9; **S12** (derived history data: commit graph,
changed paths, per-rule lists) and **S13** (the query API: log, show,
tree, file, diff and ancestry, answered on each viewer's projected
history) are built too, recorded in
`docs/design/server/phase-3-server-history.md` §10 and §11. Statements about what Veil does today cite the
document or source file they come from; everything else is a proposal and
is worded as one.

Contents:

1. [What the Hub is](#1-what-the-hub-is)
2. [Architecture](#2-architecture)
3. [Security model](#3-security-model)
4. [The sync protocol](#4-the-sync-protocol)
5. [Permissions](#5-permissions)
6. [Secrets](#6-secrets)
7. [Pull requests and review](#7-pull-requests-and-review)
8. [Embargoes](#8-embargoes)
9. [Scale](#9-scale)
10. [The web client](#10-the-web-client)
11. [Build order](#11-build-order)
12. [Open questions and risks](#12-open-questions-and-risks)
13. [As built: milestone S1](#13-as-built-milestone-s1)

---

## 1. What the Hub is

### 1.1 Goals

* **One server that holds every project and decides who sees what.** The
  `vl` client is always connected to it. It is not Git and not
  offline-first.
* **The ordinary permission model** (VISIBILITY.md): the creator is the
  admin; everything is private by default; admins create groups, add
  people and choose group managers; admins give groups or people access to
  folders; `public` folders are visible to everyone on Earth.
* **Code is plain text on the server,** so the server can merge, search,
  blame and index it. It simply never sends a file to someone without
  access.
* **Secrets are encrypted** (`.env`, keys), automatically, and follow the
  same folder access. The server never holds a key that opens them.
  Nothing else is encrypted: embargoed changes are plain text, hidden by
  the server's permissions until release.
* **Personal private keys** (`id_rsa`, `id_ed25519`, private `*.pem`) are
  never uploaded.
* **Pull requests on change ids**, visible only to people who can see every
  file they touch.
* **Built on the Scion design,** for thousands of agents at once pulling,
  opening PRs and merging: lock-free commits, an atomic one-row branch
  move, fetch on demand, layered caches, server-side merges, history and
  search, batched landings, with benchmark gates for each (§9).

### 1.2 Non-goals

* **Git interop** of any kind. Permanent (owner, 2026-11-05).
* **Offline use, or plain-file remotes** (SFTP, shared drives). The server
  is the only remote.
* **Encrypting code.** Only secret files (`.env`, keys) are encrypted.
* **Protecting code from the server's operator.** The server is trusted
  with plain-text code (§3.1).
* **Protecting a user from their own compromised device.** A device that
  can read a file can leak it.

### 1.3 Who uses it

| Who | Typical use |
|---|---|
| Admin | Creates the project, groups and folder access; makes things public |
| Group manager | Adds and removes people in their groups |
| Developer | Pushes, pulls, reviews PRs on what they can see |
| Agent | Works with exactly its person's access (or less), many at once |
| Machine (CI, a cloud host) | Added like a person, with the groups it needs |
| Anyone on Earth | Reads `public` folders, without signing in |

---

## 2. Architecture

### 2.1 Components

```text
 vl / agents ────────► API server ─────────► metadata DB (YugabyteDB; PostgreSQL in dev and CI)
 (device keys,           │ sync protocol         people, devices, groups, managers, admins,
  secret keys)           │ permission checks     folder access, branches, PRs, audit log
                         │ push validation
 browser ──────────────► │
  web client             ▼
                      repo workers ────────► object storage (S3-style; immutable objects)
                         │ merges, landings        ▲
                         │ history and search      │ caches (per machine, regional)
                         │ indexes                 │
                         └── deadline worker (embargo release, §8.2; not built)
```

| Component | Does | Built from |
|---|---|---|
| **API server** | Sign-in, the sync protocol (§4), the JSON API, permission checks on every request, push validation | Rust, running `veil-core` |
| **Repo workers** | Land changes (merge or rebase onto the latest branch, then move it), compute indexes, run history and search queries | `veil-core` (`merge.rs`, `transaction.rs`, `graph_index.rs`, `blame.rs`, `search.rs`) over object storage |
| **Metadata DB** | People, devices, groups, managers, admins, folder access, branch tips, PRs, review threads, approvals, CI jobs, the audit log | **YugabyteDB** (owner, 2026-11-05: open source, Spanner-style scaling). The schema is PostgreSQL-compatible, so plain **PostgreSQL** runs it for development and CI. A branch move is one conditional `UPDATE` |
| **Object storage** | File contents, trees and snapshots, each by its BLAKE3 id | S3-compatible; immutable objects, served through caches |
| **Web client** | Browsing, review, administration | TypeScript UI; `veil-core` in WASM only where a secret is opened (§10) |
| **Deadline worker** | Makes embargoes public at their deadline (not built, not in this round) | §8.2 |

### 2.2 What each part can see

| | public | private folders | secrets and embargoed changes | personal keys |
|---|---|---|---|---|
| Anyone on Earth | ✅ | ❌ | ❌ | ❌ |
| People and agents with access | ✅ | ✅ (their folders) | ✅ decrypted on their device | ❌ |
| The server (and anyone who breaks in) | ✅ | ✅ | ❌ ciphertext only | ❌ never uploaded |
| A public mirror | ✅ | ❌ never sent | ❌ never sent | ❌ |

This is VISIBILITY.md's table; the rest of this document keeps it true.

### 2.3 Data flows

**Push** (§4 has the messages):

```text
vl (alice)                                API server                     repo worker / storage
  │ snapshot; secrets encrypted locally     │                                 │
  │── hello, sign in (device signature) ──►│                                 │
  │◄─ branch tips alice may see ───────────│                                 │
  │── upload objects (holding area) ──────►│ validate (§4.5), check access   │
  │── push {main: X → Y} ─────────────────►│── accept ──────────────────────►│ atomic branch move
  │◄─ result ──────────────────────────────│                                 │
```

**Reading a file:** the client asks for a path at a revision; the server
checks access, then sends the objects (or answers from a cache). A secret
arrives as ciphertext and is opened on the device.

**Anyone on Earth:** the server serves `public` folders only, with no
sign-in.

---

## 3. Security model

### 3.1 Trust boundary

*Trusted:*

* **the server** with plain-text code, branch tips, permissions and
  metadata. It enforces every access rule. Anyone who breaks into it can
  read the code; that is accepted (OVERVIEW.md, non-goals);
* each person's device and OS account, and their own deliberate commands;
* the OS, the file system and the toolchain `vl` was built with.

*Not trusted:*

* **the server, with secrets, embargoed changes before release, and
  personal keys.** It stores only ciphertext of the first two and never
  receives the third. A key that opens a secret exists only on the devices
  of people with access (§6);
* anyone outside a folder's access, including other people in the same
  project;
* content that arrives in a push or a pull: trees, names, descriptions,
  hooks and metadata are hostile input, checked as today (ARCHITECTURE.md
  §2, §8, §15);
* the network (TLS, plus signed requests, §4.3).

A finding that needs a trusted part to be hostile (for example "a
compromised server reads `billing/`") is out of scope and recorded as such.

### 3.2 Attackers

| Attacker | Can | Cannot | Mitigations |
|---|---|---|---|
| **Someone who breaks into the server** | Read all code and metadata; deny service; change permissions in the DB | Read secrets; forge snapshot signatures | Ordinary server hardening, audit log, backups. Secrets' keys never reach it (§6). Unreleased embargoed changes are plain text there, protected by its permissions like any private folder (§8) |
| **A person without access to a folder** | Read what they were given and `public` | Receive the folder's files, names, history or PRs | Server-side checks on every request (§5.3); one check used everywhere (search, counts, API, agents) |
| **A person who loses access** | Keep what they already pulled, including secret values | Receive anything new | Server stops serving at once; secret keys rotate; the server lists the secrets to change (§6.4) |
| **A group manager** | Add and remove people in their groups | Change folder access, make anything public, manage other groups | Server checks role on every change (§5.3) |
| **A hostile pusher** | Send any bytes | Get them accepted unchecked, or give themselves access by editing `.veilpolicy` | Push validation (§4.5); policy changes need an admin (§5.2) |
| **A compromised device** | Everything its person can do | More than its person can do | Remove the device (§5.6); rotate the secrets it could open |
| **A compromised agent** | Use the secrets its person gave it while it runs | Commit a secret into an ordinary file | The scanner and the sandbox checks (ARCHITECTURE.md §4, §6); give risky agents test keys |
| **Network attacker** | See traffic sizes and timing | Read or change traffic | TLS, signed requests (§4.3) |

### 3.3 What the server knows

Everything except secret values, unreleased embargoed content and personal
keys: code, file names, history, who did what and when, group membership,
PR text and comments. For a secret it knows its path, size, who may open it
and when it changed. For an embargo it knows that it exists, its groups,
its deadline and the ciphertext sizes (as today, ARCHITECTURE.md threat
model, "Embargo metadata that remains visible").

---

## 4. The sync protocol

Today's `vl` syncs by reading and writing a remote repository's files
(`remote.rs`, ARCHITECTURE.md §8). The server needs its own protocol for
three things file access cannot do: check permissions before anything is
sent or accepted, move a branch atomically, and send each person only what
they may see. The protocol keeps Veil's objects, encodings, pack format and
merge rules; only who runs the checks changes.

### 4.1 Transports and framing

* **HTTPS** (HTTP/2): `POST https://hub.example/v1/projects/{project}/rpc/{name}`.
* **SSH**: `ssh hub.example vl-serve {project}`, with the same frames over
  stdin and stdout.

```text
frame    = len u32be | type u8 | payload[len - 1]
type     0x01 control    one JSON object
         0x02 pack-data  raw bytes of a VEILPAK1 pack (may span frames)
         0x03 progress   JSON {phase, done, total}
         0x04 error      JSON {code, message, retry_after_ms?}
         0x05 end        empty
limits   control frame ≤ 1 MiB; pack-data frame ≤ 4 MiB
```

Packs on the wire are the on-disk format (ARCHITECTURE.md §10). Single
objects are also served by id over plain `GET`, so any cache can answer
(§9).

### 4.2 Messages

```text
hello     C→S {protocol: 1, client: "vl x.y", repo_format_max: 6, features: [...]}
          S→C {protocol: 1, repo_format: 6, features: [...], challenge: "<32 random bytes>"}

tips      C→S {}
          S→C {branches: {"main": "<id>", ...}, embargoes: [...]}   // only what the caller may see

get       C→S {ids: ["<object id>", ...]}                          // fetch on demand (§4.4)
          S→C pack-data*, end

upload    C→S pack-data*                → S→C {upload: "<id>"}       // holding area, resumable

push      C→S {expected: {"main": "<old>"}, updates: [{branch: "main", new: "<id>"}],
               upload: "<id>", records: [...]}
          S→C {results: [{branch: "main", status: "ok"} | {status: "rejected", code, message}]}

land      C→S {change: "<change id>", onto: "main"}                // server-side landing (§9.1)
          S→C {status: "queued" | "landed" | "conflict", ...}
```

### 4.3 Sign-in and request signing

* **Each device has its own identity** (an Ed25519 signing key and an X25519
  key, CRYPTO.md C4), created on the device and registered to the person's
  account. The private keys never leave the device.
* Every request is signed: `Ed25519(device key, "hub-request" ‖ JSON {hub,
  method, path, body hash, ts, nonce})`, a new context in
  `crypto/domains.rs`. The server accepts `ts` within ±5 minutes and
  remembers nonces for 10 minutes. Long transfers get a short session
  token bound to the device and the project.
* **Browser sign-in** uses a passkey (WebAuthn); the session cookie is
  `HttpOnly`, `Secure`, `SameSite=Strict`.
* **Machines** (CI, a cloud host) are registered like a person's device;
  Veil creates the identity on the machine (VISIBILITY.md, "Agents and
  secrets").

### 4.4 Negotiation and fetch on demand

* **Fetch on demand.** The client never sends a list of what it has. It
  starts from a snapshot's root tree, asks for the trees it lacks, then the
  files it needs, each by id. Every request names an object that never
  changes, so any cache can serve it and a dropped download resumes. This
  is Scion's protocol, and the built partial-clone design already follows
  it (`docs/design/scale/6-partial-clone.md`).
* **What a client keeps:** a bounded cache of what its person may see
  (VISIBILITY.md, "What the client keeps locally").
* **Push.** The client reads the tips, works out what the server lacks on
  its own graph (as `push_incremental` does today) and uploads it. The
  server checks closure itself (§4.5), so a wrong guess gets a precise
  `missing: [...]` answer.

### 4.5 Push validation

Objects go to a holding area first; nothing is visible until every check
passes and the branch moves. Most checks are the ones a pulling client runs
today; **they must be the same code** on client and server.

| # | Check | Today |
|---|---|---|
| 1 | The person may push to this project and branch (branch rules, §7.4) | (new) |
| 2 | **Write access by path:** every file the push adds, changes or removes is in a folder the pusher has access to | (new) |
| 3 | **Policy changes:** a push that changes `.veilpolicy` access rules comes from an admin (§5.2) | (new) |
| 4 | Pack integrity: checksums, every object re-hashed against its id | `pack.rs` |
| 5 | Canonical decoding; safe names (`..`, `/`, NUL, `.veil`); tree depth | `Object::decode`, `remote.rs` |
| 6 | Objects allowed by the repository format | `ObjectStore::check_storable` |
| 7 | Closure: every object the new tips reference is uploaded or already stored, except the redacted parents of an unreleased embargoed merge | the closure walk of pull |
| 8 | **Secrets are ciphertext:** a file the secret rules cover (§6.1) arrives encrypted; personal keys are refused outright | the builder's rules (ARCHITECTURE.md §4) |
| 9 | **Secret scan** of every new plain-text file; a hit rejects the push | `secrets.rs` |
| 10 | Snapshot signatures verify; the signer is the pusher's device or a known one | `Snapshot::unsigned_id` |
| 11 | Embargo records are well formed and signed by someone in the embargo's groups | `Keychain::merge_embargo` |
| 12 | Branch moves are fast-forward unless forced by someone allowed to | `push_with` |
| 13 | Quotas and limits (§4.7) | (new) |

Then the branch moves with one compare-and-swap in the DB (§9.1), and the
push is recorded in the project's audit log.

**What exists today and carries over:** `vl push` is already two-phase. It
uploads objects to a staging area on the remote without a lock, then takes
the lock only to check and move the branches, and resumes an interrupted
upload (`docs/design/scale/1-lock-free-push.md`, built as stream P). The
server keeps the shape and replaces the lock with the compare-and-swap.

### 4.6 Serving each person what they may see

* **One function decides** whether a person (or an agent acting for them)
  may see a path, from the accepted `.veilpolicy` and the DB's group and
  admin records (§5). Every read goes through it: files, trees, history,
  search, blame, PRs, notifications, counts, the API.
* **Trees for people without full access** are served as a per-viewer
  projection: entries they cannot see are left out, so they learn neither
  the files nor their names. Snapshot signatures must still verify; how is
  an open question (§12.1, VISIBILITY.md).
* **Public** readers get only `public` folders.
* **Removing access takes effect at once:** the next request is refused.

### 4.7 Limits

| Limit | Default | Why |
|---|---|---|
| Requests per device / per IP | 60 / s burst, 5,000 / h | abuse |
| Pack size per upload | 2 GiB (larger: split) | memory |
| Single object | 4 GiB | `VEIL_MAX_OBJECT` today |
| Tree depth | 1,024 | `MAX_TREE_DEPTH` |
| Parents of one snapshot | 64 (built: `sync::MAX_PARENTS`, refused at push and at API commits) | a walk of history reads every parent of a snapshot in one step (BUG-1078) |
| Landings per agent | per project setting | one runaway agent can't starve the rest |

`error` frames carry `retry_after_ms`. Anonymous reads of `public` folders
have their own, lower limits. Built in S24 (§13.25): per device and per
address, request bodies under a budget, per-project bulkheads, shedding.

### 4.8 Resumability

* Uploads are identified by the pack's BLAKE3 sum, resumable by offset and
  kept 24 hours. Validation starts only at `push`, so a broken upload never
  becomes visible.
* Downloads are of immutable objects or packs, so a retry resumes with a
  `Range` request.
* Crash safety keeps the engine's order: objects first, then the branch
  move (ARCHITECTURE.md §9).

### 4.9 What changes for today's client

* `vl clone`, `vl push` and `vl pull` talk to the server; `hub:` URLs
  (`hub:acme/app`, `https://hub.example/acme/app`) name a project.
* Path and SFTP remotes were removed in the simplification pass, part 1
  (OVERVIEW.md).
* **Moving an existing repository** onto the server is a push, with the
  upgrade steps of §5.7.

---

## 5. Permissions

### 5.1 What the DB holds

```text
Person    { id, name, email, devices: [Device], kind: person | machine }
Device    { id, person, signing key, encryption key, added_at, removed_at? }
Project   { id, name, admins: [Person] }               // the creator is the first admin
Group     { project, name, members: [Person], managers: [Person] }
Access    { project, path, who: Group | Person | public }   // mirrors the accepted .veilpolicy
AuditLog  { project, at, actor, device, action, details }
```

Admins see everything; nobody else sees anything they were not given
(VISIBILITY.md, "The model").

### 5.2 `.veilpolicy` is the folder-access file

* The access rules live in the project's `.veilpolicy`, like any other
  file, with the most specific rule winning (VISIBILITY.md):

  ```
  src/          public
  billing/      finance
  infra/        ops carol
  ```

* `vl access billing/ finance` edits it and pushes the change;
  `vl access billing/` shows who can see a path, and why.
* **Only admins can change access.** The server refuses a push that
  changes an access rule unless the pusher is an admin (§4.5, check 3), so
  nobody can give themselves access by editing the file.
* **Groups and managers live in the DB**, not in the file:
  `vl group create`, `vl group add`, `vl group manager`. Only admins and the
  group's managers may change a group's people.
* **The authority is the server**, from the accepted `.veilpolicy` and its
  own records, by path. Labels inside a snapshot are never authority (the
  same rule as today's `verify_sealing`, CLAUDE.md invariants).

### 5.3 The checks

| Action | Who may |
|---|---|
| Read a path | admins; members of a group given the path; people given it directly; anyone if `public` |
| Write a path | the same people as read, unless a branch rule says less (§7.4) |
| Change access, make public, add admins, create or delete groups, choose managers | admins |
| Add or remove people in a group | admins and that group's managers |
| Add or remove a device | the person (from an existing device), or an admin |

Every check is made by one function on the server, on every request.

### 5.4 History for people without access to a folder

* They don't see the folder's files, or even their names, in any snapshot.
* A change that touched only folders they can't see does not appear in
  their log. A change that touched both appears with only their part.
* How snapshot ids and signatures verify for such a projection is the
  first open technical question (§12.1).

### 5.5 Agents and machines

* **An agent sees what its person sees,** or less if it is given less
  (VISIBILITY.md). It acts with its person's device identity, through
  `vl ws exec` on the device or through the API; its changes record the
  agent (`docs/design/scale/7-agent-attribution.md`).
* **No new API keys for agents.** An agent uses the same secrets its person
  has (§6.6).
* **A machine** (CI, a cloud host) is added like a person, given the groups
  it needs, and every agent on it shares that access.
* **Over SSH** (planned): borrow a laptop's access for a session, like
  `ssh -A`, without storing secrets on the remote machine.

### 5.6 Removing someone

* Removing a person from a group, or a device from a person, takes effect
  on the next request.
* Every secret key they could open is rotated (§6.4), and the server lists
  the secret values to change, because they may have copied them.
* What they already pulled, they keep. That cannot be undone.

### 5.7 Moving an existing repository onto the server

From VISIBILITY.md, "Existing repositories":

* `.env` files start syncing, encrypted, only after an explicit upgrade
  step that lists them;
* a repository from before format 8 that holds encrypted folders,
  descriptions, tags or embargoes is not upgraded: `vl upgrade` names each
  thing (FORMAT.md §5);
* nothing is made public or decrypted silently;
* `vl cloak` seals secret files only; `vl access` gives folders to groups.

---

## 6. Secrets

### 6.1 What counts as a secret

* **Secrets** are `.env`, `.env.*`, API keys and similar files, found by
  the built-in rules today's builder already applies (ARCHITECTURE.md §4).
  Today's client keeps such files on the device; with the server they are
  encrypted on the device and then pushed.
* **Personal private keys** (`id_rsa`, `id_ed25519`, private `*.pem`) are
  never uploaded at all, by the client or through the server (§4.5, check
  8).
* **Everything else is ordinary code**, stored as plain text. The secret
  scanner refuses to commit anything that looks like a password or token in
  an ordinary file (`secrets.rs`).

### 6.2 Keys

* A secret follows the same access as any file: if `finance` can see
  `billing/`, `finance` can open `billing/.env`.
* **Each access rule that covers a secret has a secret key**, shared by
  everyone the rule gives access to, and by the admins.
* The key is wrapped (HPKE, CRYPTO.md C3) to the encryption key of **each
  device** of each of those people. The server stores the wraps and the
  ciphertext, never the key.
* The engine pieces exist: key generations, HPKE wraps to members and
  rotation are today's key rings (ARCHITECTURE.md §3, CRYPTO.md C3, C6), and
  encrypted, signed per-entry records are today's team vault (CRYPTO.md
  C12). The server keeps the generations and wraps; the client does the
  encryption.

### 6.3 Giving a new person access

The server can't wrap a key it doesn't hold, so **a device that already
holds it does the wrapping:**

1. An admin (or manager) adds carol to `finance`. From the next request,
   carol can read `billing/`'s code.
2. The server queues "wrap `finance`'s secret keys for carol's devices".
3. The next device online that holds those keys (any admin's, or any
   `finance` member's) wraps the keys for carol's **confirmed** devices and
   uploads the wraps. The key ring's own replay checks each device's proof,
   never the server's records alone (as built: §13.12). This is automatic;
   nobody runs a command.
4. Until then, carol sees that `billing/.env` exists and is waiting for a
   key.

The same happens when a person adds a new device: one of their existing
devices, or another key holder, wraps the keys for it.

**The risk:** a server that lies about carol's device key could have a
member wrap a key for the attacker. The defence is that device keys are
signed by the person's existing device (or, for the first device, checked
by fingerprint out of band); see §12.2.

### 6.4 Removing access

* The next write of each affected secret uses a new key generation wrapped
  only to the people who still have access (rotation, as `vl scope revoke`
  does today, ARCHITECTURE.md §3).
* The removed person keeps old generations, and any values they read. The
  server lists every secret they could open, so the owners can change the
  real values (passwords, API keys).

### 6.5 Personal keys

Never uploaded, never wrapped, never shared. Whoever holds a copy can
impersonate the person (VISIBILITY.md).

### 6.6 One secret, many readers

An API key is stored once. Everyone with access to it, people and agents,
uses that same key; nobody makes new keys for agents. An agent on a device
gets secrets through `vl ws exec` / `vl run`, which inject them and refuse
to commit them anywhere else (ARCHITECTURE.md §4, "injected secrets"). The
limit: an agent that is given a secret can use it while it runs.

---

## 7. Pull requests and review

### 7.1 Who can see a PR

* **A PR is visible only to people who can see every file it touches.**
  There is no partial view, because the title and comments describe the
  whole change.
* **An embargoed PR doesn't exist** for anyone outside its groups: no
  title, no number, no count, no placeholder.
* The server computes the files a PR touches by diffing trees (it can read
  them), and applies the same check (§4.6) in search, notifications,
  counts, the API, agents and CI.

### 7.2 Data model

```text
PullRequest {
  number, target: "main", author,
  title, body,                          // plain text, an embargoed PR's too
  stack: [ChangeId],                    // the changes under review, bottom first
  revisions: [Revision],                // one per push to the PR
  state: Open | Landed {at, by} | Closed,
}
Revision { n, base: SnapshotId, heads: {ChangeId → SnapshotId}, touched: [path], pushed_by, at }
Thread   { anchor: Anchor, state: Open | Resolved, comments: [Comment] }
```

* **Revisions follow change ids.** A rebase gives each change a new
  snapshot with the same change id (ARCHITECTURE.md §5), so the PR keeps
  its place; the evolution log links the new snapshot to the old.
* PR heads are server-side refs (`pr/<n>/<change id>`), not branches.

### 7.3 Comments anchored across rewrites

```text
Anchor { change: ChangeId, revision, path, side: Old | New, lines: [start, end],
         context: "<blake3 of the anchored lines>" }
```

If the file is unchanged between revisions the anchor moves as is;
otherwise the server maps the lines through a diff and checks `context`.
When it can't, the thread shows as outdated.

### 7.4 Approvals and branch rules

```toml
[branches."main"]
require_pr = true
approvals = 1
require_status = ["ci/build", "ci/test"]
allow_force = false
```

* An approval for a revision is recorded by the server, with the
  reviewer's device signature, and is dismissed by any later change to the
  files.
* **A reviewer can approve only what they can see,** which for a PR is
  everything it touches (§7.1).

### 7.5 Landing

The server lands PRs: it merges or rebases the stack onto the latest
target and moves the branch atomically (§9.1). Two cases need keys, and so
run on a device or machine that holds them:

* **a conflict inside a secret file** (`.env` changed on both sides);
* **an embargoed change** before its release (§8).

For these, the server hands the landing to a key holder's `vl`, or to a
machine in the right groups, which merges and pushes. Everything else lands
on the server.

---

## 8. Embargoes

Some changes must reach some people now and the public later; a security
fix is the typical case (VISIBILITY.md, "Hidden changes").

```
vl merge fix --into main --embargo-for security distro-partners --until 2026-12-01
```

### 8.1 What exists today

Embargoes are permissions, not encryption (owner, 2026-11-06;
`docs/VISIBILITY.md`). In the client (ARCHITECTURE.md §7):

* an embargoed merge is an ordinary merge with a plain record (its group,
  its deadline, its release);
* the merge, the history it brings in and anything built on it are
  withheld from every push until the release (`remote::embargo_withheld`),
  and copies out of the embargo are refused;
* the release is `vl embargo release`, or the deadline passing.

The server refuses embargoed merges in S1, so they stay on the device until
released. (Before format 8 the client encrypted embargoed content under an
embargo key; that is removed, FORMAT.md §5.)

### 8.2 On the server (not built)

* The groups named (`--embargo-for`) see the merge, its message and its
  history at once, as plain text behind the server's permissions.
  Everyone else, the public included, sees nothing of it until release:
  no snapshot, no name, no count.
* At the deadline the server makes it public. **A server-side deadline
  scheduler is not built yet**, and is not part of this round.
* An embargoed PR exists only for its groups (§7.1).

### 8.4 Coordinated disclosure

```text
reporter       → private report: creates a group for the advisory, adds the reporter
security team  → embargoed PR for that group (and distro-partners)
merge          → vl merge --embargo-for adv-12 distro-partners --until T
release (T)    → embargo released; advisory published; the group kept or removed
```

One unreleased embargo per line still applies (ARCHITECTURE.md §7).

---

## 9. Scale: the Scion design

**The Hub is built on the design of Anthropic's Scion** (OVERVIEW.md, "How
it scales"; `docs/design/scion-for-developers.md` cites the source), for
**thousands of agents at once pulling, opening PRs and merging**. Most of
the work happens on the server, and the only step done one at a time is
moving a branch.

### 9.1 The pieces

* **Lock-free change writes.** Uploading a change is just storing its
  objects in a holding area (§4.5); an object nothing points to is
  invisible and harmless. **Moving `main` is one atomic compare-and-swap
  on one DB row:** "move `main` from X to Y" succeeds or is rejected.
  Today's client already has the groundwork: a lock-free op log (stream O,
  format 6) and two-phase pushes that lock only for the branch move
  (stream P).
* **The server does the work:** merges, rebases, history, blame and search
  run on the server, through the API, often with no checkout.
* **Precomputed history:** blame, file history and the commit graph are
  computed once per change as it lands (each index value from its parents'
  values), so queries are instant. Today's local commit-graph index
  (`graph_index.rs`, stream I) is the first such index.
* **Fetch on demand,** from the top folder down (§4.4). An agent working in
  `src/api/` never downloads the rest. The client's cache is bounded, and
  files appear when read (extending today's `vl ws mount`).
* **Layered caches:** the client, a cache daemon on each machine (shared by
  every agent on it), regional caches, then the server. Objects are
  addressed by hash, so any cache serves them with no coordination, and a
  failing cache slows reads but never blocks landing. **Caches hold only
  what the asker may see:** a cache serves an object only after the
  server's access check for that person (§4.6).
* **No locked merge queue.** Ready changes that don't overlap land **in
  batches**: 500 ready PRs become one move of `main`, by rewriting folder
  listings without merging contents. A change that conflicts goes back to
  an agent with both versions and the test result. Tests run after merging
  and before deploy; a broken `main` is fixed forward or reverted (with
  automatic bisect through the API). Changes that need keys land as in
  §7.5.
* **Few branches:** work lives as changes and PRs, not thousands of
  long-lived branches.
* **No repacking:** each object is stored once in S3-style object storage;
  unreferenced objects are removed in the background by a retention rule.
  Packs are used only to transfer data.
* **Horizontal scaling:** stateless API servers, **YugabyteDB** for metadata
  (PostgreSQL for development and CI), and object storage. Capacity grows
  by adding machines.
* **Permission checks on every request, cached per person and folder,** so
  access control never becomes the bottleneck. A change to a group or to
  `.veilpolicy` invalidates the affected cache entries before it takes
  effect.

### 9.2 Benchmark gates

The design targets from OVERVIEW.md. **The server's benchmark must prove
each one** before the feature that serves it is called done; today's
`crates/veil-bench` is extended to drive the server.

| What | Gate |
|---|---|
| Agents working at once | **Thousands**: benchmark at 1,000 and 10,000 |
| Pull of a small change | **Under 100 ms** of server time; mostly served from cache |
| Opening or updating a PR | **Under 100 ms** of server time |
| Merges | **Thousands per hour per project**, with no agent waiting on a global lock; landing batches change by change |
| A fresh agent workspace on a large project | **Seconds**, fetching on demand |
| History, blame or search through the API | **Milliseconds to low hundreds of ms**, with no checkout |
| Permission checks | **A negligible share** of request time |

### 9.3 Operations

* Health metrics per project: merges per hour, time to land, conflict
  rate, reverts, cache hit rate.
* Rate limits per person and per agent (§4.7).
* Simulation testing of the server, its caches and many clients, with
  faults injected (dropped connections, cache outages, racing landings),
  checked for leaks of private folders, secrets and embargoed changes.

---

## 10. The web client

* **Code is rendered by the server,** like any code host: the server reads
  plain text and serves it behind the same access check. Anonymous readers
  get `public` folders, including server-rendered pages for search
  engines.
* **Secrets in the browser** are opened only by `veil-core` compiled to
  WASM in a Web Worker (ARCHITECTURE.md §13), with a browser device identity
  whose keys are stored encrypted under a passkey. The decrypted value goes
  to the page only to be shown. A first version may leave secrets to `vl`.
* **Repository content is hostile:** rendered Markdown, notebooks and HTML
  are shown from a separate, sandboxed origin with no session, and the app
  uses a strict CSP and Trusted Types.

---

## 11. Build order

From OVERVIEW.md:

1. **Next: the server and the permission model, together.**
   * the API server, the sync protocol (§4) and push validation (§4.5);
   * YugabyteDB (PostgreSQL in dev and CI), object storage;
   * sign-in, devices, machines;
   * admins, groups, managers, folder access, `public` (§5);
   * encrypted secrets with device wraps (§6);
   * `vl` pushing and pulling through the server, each person receiving only
     what they may see (§4.6);
   * moving existing repositories onto the server (§5.7).
2. **Then: a simplification pass.** Remove what the server makes
   unnecessary: plain-file (SFTP and path) remotes and offline assumptions
   (**part 1, done**), old storage formats (still readable for
   `vl upgrade`) and old jargon (cloak, scope, isolate).
3. **Then: the server's features, in stages.**
   * fetch on demand (§9.1);
   * server-side history and search (§9.1);
   * landing changes at agent scale (§9.1), proved by the gates of §9.2;
   * PR review and hidden PRs (§7);
   * the deadline worker (§8.2), CI on machines (§5.5), the web
     client (§10).

What must carry over from today's engine, unchanged in meaning: the object
format and ids, change ids and the evolution log, the op log and undo,
embargoes, the secret scanner, the sandbox checks, and the rule that labels
inside a snapshot are claims, never authority.

---

## 12. Open questions and risks

### 12.1 Open technical questions

1. **History without a folder** (§5.4): a per-viewer projection that hides
   files and names but still lets snapshot signatures verify.
2. **Secret keys per access rule or per group** (§6.2): per rule is simple
   to explain; per group means fewer keys when many rules name the same
   group.
3. **Write access separate from read access:** VISIBILITY.md gives one kind
   of access. Branch rules (§7.4) and agent path limits may need a
   narrower "may write".
4. **Hardware for the gates** (§9.2): what machines the 1,000- and
   10,000-agent benchmarks run on.
5. **Land first, test after, with embargoes:** reverting an embargoed merge
   must not reveal the fix.

### 12.2 Top risks

| Risk | Mitigation |
|---|---|
| **A break-in at the server** reads all code | Accepted by design. Harden the server, keep secrets and embargoes out of its reach, audit log |
| **Device-key substitution:** a lying server gets a member to wrap a secret key for an attacker (§6.3) | Device keys signed by the person's existing device; fingerprints shown in the UI; key transparency later |
| **One access check, missed somewhere:** a search count, a notification or an agent API that leaks a name | One function for every read (§4.6); tests that compare every endpoint's answer for people with and without access |
| **Validation divergence:** server and client disagree on what is valid | One validation library used by both (§4.5) |
| **Rotation not done:** a removed person keeps working secret values | The rotation list on removal (§5.6); reminders until each is marked changed |

---

## 13. As built: milestone S1

Built on `integration` @ `cbfe9ee` (2026-11-06). Code: `crates/veil-server`
(the server), `crates/veil-core/src/hub/` (the permission model and wire
protocol as pure functions, shared with `vl`; they build for WASM),
`crates/vl/src/hub.rs` and `hub_cmd.rs` (the client).

### 13.1 Components

| Part | Built with | Notes |
|---|---|---|
| HTTPS API | tokio, axum, hyper, rustls (ring) | TLS on every connection; `--tls-cert/--tls-key`, or a self-signed certificate (rcgen) for `localhost`/`127.0.0.1` created in the data directory, which `vl login --ca FILE` pins for that server |
| Metadata | sqlx, PostgreSQL 17 (development, CI) and YugabyteDB 2025.2 | portable SQL only; read-check-write transactions are SERIALIZABLE through `db::serializable`, except where unique keys and row locks decide the races (branch moves, sign-in, project and group creation, group changes: READ COMMITTED, because on YugabyteDB a SERIALIZABLE read blocks every insert into the table it read until it commits, BUG-847); retried with capped exponential backoff on `40001`/`40P01` (YugabyteDB reports conflicts as both) |
| Migrations | `db::migrate`, `migrations/0001_initial.sql`, `0002_device_vouches.sql` (pending devices, vouches: §13.11), `0003_invites_and_key_sharing.sql` (invites, key requests, pending devices by fingerprint and the fingerprints a person waits for, devices barred from one project: §13.12), `0006_access_epochs.sql` (access epochs and the triggers that bump them: §13.14) | each in its own transaction, recorded in `schema_migrations`; servers starting together race on its primary key and the loser re-checks. On PostgreSQL DDL is transactional; on YugabyteDB DDL inside a transaction block is applied statement by statement unless transactional DDL is enabled, so **migration files are idempotent** (`IF NOT EXISTS`) and a half-applied one is completed by the next start |
| Object storage | `store::BlobStore`: `FsStore` (a directory; unit tests, development) and `S3Store` (rusty-s3 request signing + reqwest; tested against MinIO) | key `p/<project id>/ab/cdef…`: projects never share an object; objects are stored compressed (zstd) when that is smaller, under the id of the uncompressed object (S27, §13.15); every read is decoded, bounded, and re-hashed against its id; an in-memory cache of objects (as stored) and decoded trees (256 MiB each, decoded trees weighed by the memory they hold: BUG-860). Every S3 request is idempotent (GET, HEAD, PUT of a key naming its content) and is tried again for up to 10 s, with jittered waits doubling from 25 ms to 1 s, when its connection closes or resets or the store answers 5xx or 429 (BUG-1005, BUG-1053); idle connections are dropped after 15 s, before S3 services drop them (BUG-861) |
| Memory allocator | jemalloc (`tikv-jemallocator`, pinned), the `veil-server` binary's only | two arenas, background purging, 1 s decay (`src/main.rs`; `_RJEM_MALLOC_CONF` overrides them): glibc's arena per thread held 2-3x the server's data (BUG-864; `docs/design/scale/BASELINE.md`, "The server's allocator"). **Building the server needs `make` and a C compiler** (jemalloc is built from source) |
| Server identity | an Ed25519 `Identity` in `<data>/hub-identity.json` (0600); a random secret in `<data>/hub-receipt-key` (0600) | signs projected snapshots (§13.4); its key is shown by `vl login`. The secret keys upload receipts (§13.5); servers sharing the data directory accept each other's |

**YugabyteDB's licence (checked 2026-11-06).** The `LICENSE.md` shipped in
the official image `yugabytedb/yugabyte:2025.2.8.1-b8` (`/licenses/`) and
the repository say: the **database core** (`src/yb`, `src/postgres`, the
client libraries and tools) is **Apache-2.0**; **YugabyteDB Anywhere**
(`managed/`, the management platform, and `troubleshoot/`) is under the
**Polyform Free Trial License 1.0.0** (32 days' evaluation). The
`yugabytedb/yugabyte` image and the download at download.yugabyte.com are
the Apache-2.0 core; Veil uses only that, never YugabyteDB Anywhere or a
`-managed` build.

**MinIO** no longer publishes images on Docker Hub or anonymously on
quay.io; the tests use the MinIO server binary packaged as
`bitnamilegacy/minio`. Any S3-compatible store works.

### 13.2 Sign-in (§4.3, decided)

* `POST /v1/auth/challenge {key}` returns 32 random bytes, valid 60 s,
  stored with the key.
* `POST /v1/auth/login` carries the key, the challenge, the server's name
  as dialled (`host:port`), an Ed25519 signature under the new context
  `hub-login` (`crypto/domains.rs`) over `hub ‖ 0 ‖ challenge`, and the
  device's full public identity (`veil1<x25519><ed25519><binding>`).
  * The challenge is deleted in the statement that checks it: **a replayed
    login finds nothing.**
  * `hub` must be a name the server's TLS certificate is valid for (the
    check the client made before signing), and equal the request's `Host`:
    a signature a client made for another server (one relaying our
    challenges, which also writes the `Host` header) is refused (BUG-819).
    Two servers on one machine that share a certificate's names (the
    self-signed `localhost` one) are not told apart.
  * The identity's Ed25519 part must be the key, with a valid binding: a
    device cannot register someone else's X25519 key.
* An unknown key with `name` registers a new person (names are unique,
  lowercase, never a tier word); without `name` it is refused. Under a
  name somebody has, the key becomes one of their **pending** devices: no
  session, its signatures not accepted, until one of their devices vouches
  for it (§13.11).
* The **session token** is 32 random bytes; the database keeps only its
  BLAKE3 hash, the device and an expiry (`--session-seconds`, 12 h). A
  bad or expired token is **401, never downgraded to anyone-on-Earth**;
  `vl` then signs in again with the device key, without asking.
* Per-request signatures (§4.3) are not built: TLS plus short sessions
  bound to a device cover S1.

### 13.3 The permission model on the server (§5, decided)

* **Records:** people, devices, projects, project admins, groups, members,
  managers, branches, committed snapshots, projections, origins, key
  rings, an audit log (`migrations/0001_initial.sql`).
* **Access lines** (`veil_core::hub::access`): a line of `.veilpolicy` whose
  fields after the path are `public` and/or group or person names
  (`billing/  finance`, `src/  public devs`). Decided for S1:
  * paths are **literal folders or files, from the project root**; a line
    with glob syntax grants nothing on the server (the push says so);
  * **the last matching line decides**; a path no line matches is private
    (admins only), and so is the project root;
  * **folder access is read and write**; `public` is read-only for everyone
    (writing a public folder needs a named group or person);
  * on the device an access line is a plain-text rule like `public`: it
    never seals and never weakens a secret's protection.
* **The authority is the accepted policy**: the `.veilpolicy` of the
  project's default branch (`main`), as last accepted from an **admin's**
  push, plus the server's own records. Labels inside snapshots are never
  consulted, and a permissive `.veilpolicy` on another branch grants
  nothing.
* **Names are bound when a policy is accepted**, and stored with it: a
  name binds to the project's group of that name if one exists (**a group
  always wins**), else to the person of that name, else the push is
  refused. A person who signs up under a group's name takes over nothing:
  creating a group rebinds an accepted line that names it to the new group
  (BUG-821), and a group deleted later grants nothing. Between an admin's
  push of a line naming a person and the creation of a group of that name,
  the person has the folder, as the push listed. The admin's push lists every
  binding and every public line ("access accepted: billing/ → group
  finance"), so nothing becomes public or shared silently.
* **Who may do what** (`api.rs`, `sync.rs`):

  | Action | Who |
  |---|---|
  | create a project | anyone signed in (`vl push` to a new project creates it; they are its admin) |
  | read a path | admins; groups and people its deciding line names; anyone if `public` |
  | write a path | admins; groups and people its deciding line names |
  | change access lines (on any branch), make public | admins |
  | create or delete groups, choose managers | admins |
  | add or remove a group's people | admins and that group's managers; **a manager never adds themselves** |
  | upload objects, push, read key rings | participants: admins, group members, people named on a rule |
  | force a branch move, delete a branch | admins |

* **Every check is on the server, on every request**; removing someone
  takes effect on their next request, on every server: servers cache
  sessions and permissions, but check them against the access epochs on
  every request (§13.14).

### 13.4 History for someone without access: projected history (§5.4, §12.1 Q1, decided)

For a viewer `v`, real snapshot `S` maps to `P(S)` (`sync::projected`):

* `P(S).tree`: `S.tree` with every entry `v` may not read left out, names
  included (`hub::project::Projector`). Because access lines name literal
  paths, a subtree with no rule below it is kept by id (no walk) or
  dropped whole; only directories holding a rule are rewritten. Empty
  directories are dropped.
* `P(S).parents`: the projections of `S.parents`, duplicates removed;
  `conflicts` keeps only paths `v` may read; `predecessors` are projected
  too: a stored predecessor becomes `v`'s version of that change, or is left
  out if `v`'s history has no version of it (BUG-826); one the server never
  stored is kept.
* **A change that touched only what `v` cannot see is not in `v`'s history
  at all**: `P(S) = P(parent)`, and its description never reaches `v`. A
  change that touched both appears with only `v`'s part, **with its
  description** (as one commit, its message describes the whole change;
  write descriptions accordingly).
* **Signatures still verify.** If `P(S)` equals `S` field for field, `v`
  gets `S` with its author's signature. If `S` was completed by the server
  from a pusher's own snapshot `N` (below) and `P(S)` equals `N`, `v` gets
  `N`, again with its author's signature. Otherwise `P(S)` is a new
  snapshot **signed by the server's key** (`vl log` shows it as
  `?signer`). The server is trusted with code (§3.1), so its signature on
  a projection is within the trust boundary. Projections are deterministic
  (Ed25519 signatures are), memoised per view key (a hash of what the
  viewer may read), and identical for viewers who read the same paths.
* **Pushing from a projection (the graft).** A pusher's snapshot `N` has
  their projected tree. The server rebuilds the full tree
  (`hub::project::Graft`): unchanged subtrees keep the real ones, hidden
  entries come from the real first parent, and every changed path is
  checked. It stores the full snapshot (its own signature) and records `N`
  as its origin, so the pusher (and anyone who sees the same) gets `N` back
  with their own signature. A merge whose parents differ in what the
  pusher cannot see is refused ("ask someone with access to merge it");
  server-side merges are a later milestone.
* **Old history follows today's policy**: making a folder public shows its
  history; removing someone's access hides it from their next request.
  Their projected history may then change ids where it touched folders
  whose access changed (like a rewrite); their own unchanged work keeps
  its ids.

### 13.5 Sync (§4, as built)

| Route | |
|---|---|
| `GET /v1/projects/{p}/tips` | branches → tips as the caller sees them (projections); the branch rows may be up to 100 ms old (§13.14) |
| `POST …/history {tips, stop}` | the caller's projected snapshots from `tips` down to `stop`, as object frames (`id ‖ len u32be ‖ object`); to a caller that accepts encoded frames, each object as stored, compressed or not (§13.15) |
| `POST …/fetch {snapshot, objects: [{path, id, snapshot?}]}` | objects by id, each with the path where the client met it under that snapshot (its own `snapshot`, or the request's); the server walks the viewer's projection of that snapshot to that path and serves the object only if it is there (as stored, to a caller that accepts encoded frames: §13.15). No list of what the client has; each request names an immutable object, so a per-viewer cache can serve it |
| `POST …/objects` | upload object frames, plain or encoded (§13.15): decoded (bounded), re-hashed, canonically decoded, format-checked, stored compressed when that is smaller; invisible until a push reaches them. Answers a **receipt** per object (a server MAC over project ‖ person ‖ id) |
| `POST …/push {updates: [{branch, expected, new}], force, receipts}` | complete and check every new snapshot, then move the branches in **one serialisable transaction of compare-and-swaps** (`UPDATE branches SET target = new WHERE … AND target = expected`); one lost race rejects the whole push with 409 and `vl` retries |
| `POST …/changes {base, edits, onto?, change_id?, receipts}` | a commit through the API, without a checkout (S10, §13.13) |
| `GET …/access?path=` | the deciding line and who it names; only for a path the caller may read |
| `…/groups`, `GET|POST …/rings/{scope}`, `GET /v1/people/{name}/devices` | groups; key rings of secret scopes; a person's devices (active, the newest pending, removed), the vouches and invite joins the server stores, which devices check before sharing a key (§13.11, §13.12) |
| `POST /v1/devices/vouch {device, signature}` | the signed-in device vouches for another device of its person; a pending one becomes active |
| `GET /v1/people/{me}/pending/{fingerprint}` | one of the caller's own pending devices, by fingerprint; if none waits, the fingerprint is kept for the person for an hour, so the bound on pending devices never pushes that device out (§13.12) |
| `POST /v1/devices/remove {device, project?}` | remove a device: its person, from another device, everywhere (its sessions end); or an admin of `project` where the person takes part, from that project only (§13.12, BUG-843) |
| `POST …/invites {key, person, group, expires_at}`, `POST …/invites/join {key, device, signature}` | an admin records an invite's public key; the signed-in device joins under it, once, before it expires (§13.12) |
| `GET …/keys/pending` | the people whose devices may wait for keys, with their devices, vouches, joins and removed devices: a hint for the devices that share keys (§13.12) |
| `GET …/q/log`, `…/q/show`, `…/q/tree`, `…/q/file`, `…/q/diff`, `POST …/q/ancestry` | history answered by the server, on the caller's projected history only (S13: `docs/design/server/phase-3-server-history.md` §11) |

* **Fetch on demand (Scion):** `vl` asks for the tips, the snapshots it
  lacks, then trees from the root down and the files it needs, one request
  per tree level for every new snapshot at once, skipping what it already
  has. **Revision 1** (`Tips::revision`, performance round 2): a want may
  name its own snapshot, so a pull behind by many landings asks once per
  level instead of once per snapshot and level; `vl` asks a server of
  revision 0 the old way. A level is fetched in parts of at most 2,500
  objects and about 8 MiB (by the sizes tree entries carry), a snapshot's
  wants together, up to 8 requests at once; each part's objects are
  written as the part arrives, so a clone's memory does not grow with a
  level (`Client::fetch_each`, BUG-859). The server checks every want of
  a request first, a snapshot at a time (that snapshot's projected trees
  are dropped before the next), then streams the answer, reading 64
  objects or about 8 MiB at a time (BUG-860); an answer that fails part
  way ends in an error, never as a shorter whole. From 16 objects a pull
  stores what it received as one pack, compressed on several threads (one
  fsync instead of one, a rename and a directory sync per object). `vl clone URL --only DIR`
  fetches the root, the trees on the way to `DIR`, and `DIR`'s subtree
  only; it checks out `DIR` and records the rest as never materialised, so
  every snapshot keeps it unchanged. **S1 limit:** moving such a clone to
  a revision that changed folders outside `DIR` needs the full fetch on
  demand of milestone S3.
* **Push validation** (§4.5): checks 1 (participant), 2 (write access per
  changed path; a merge may take a path unchanged from another parent
  whose side changed it since a common ancestor, never the version the
  first parent replaced: BUG-820),
  3 (access lines), 4–6 (hash, canonical decoding, format), 7 (closure:
  every object a push introduces carries the pusher's upload receipt,
  unless the entry at the same path in one of the snapshot's parents names
  it; that is every object an entry names: its own and a conflict's
  terms, which `fetch` also serves at that path (BUG-834);
  anything else, stored or not, gets the answer a missing object gets, so a
  push never confirms a guess of a hidden file or folder: BUG-824),
  8 (§13.6), 10 (every
  new snapshot signed by a registered device key) and 12 (fast-forward
  unless an admin forces) are built. Embargoed merges are refused in S1.
  9 (the server-side secret scan) is built by S10 (§13.13), for pushes and
  commits through the API alike. Not built: 11, 13.
* **What a push uploads** (`hub::push`, `hub::Introduced`): every new
  snapshot and, at each path where its tree differs from all of its
  parents' trees, the trees down to that path and what the entry there
  names that no parent's entry at that path names: exactly what check 7
  asks a receipt for. A tree is walked once for each set of parent trees
  it is compared with (BUG-857: walked once per push, a tree reused by a
  later snapshot hid the files an earlier one introduced, and the server
  refused the push). Objects go up as the walk finds them, about 8 MiB
  per request (BUG-858).
* **The default branch's move accepts its policy** in the same
  transaction, admins only.
* **Objects first, then the branch move:** a crash leaves only
  unreferenced objects.

### 13.6 Secrets (§6): the server is trusted with code, never with secrets

* **New repositories seal shared secrets and sync them:** `vl init` writes
  `.veilpolicy` lines that cloak `.env`, `.env.*`, `.envrc` and Terraform
  state under the `team` scope (`policy::SYNCED_SECRETS_POLICY`). They are
  encrypted on the device with the existing sealing (AES-SIV envelopes,
  CRYPTO.md) and decrypted only on devices holding the key.
* **Personal keys and credentials stay on the device** (`id_rsa`,
  `id_ed25519`, `*.pem`, `*.key`, `.netrc`, …: the other built-in secret
  rules). The server refuses `id_rsa`/`id_dsa`/`id_ecdsa`/`id_ed25519`
  even sealed, refuses a path its policy keeps on the device, and refuses
  a secret that arrives in plain text.
* **Existing repositories switch only through `vl upgrade
  --sync-secrets`**, which lists the files that would start syncing
  (`--dry-run` lists only).
* **Key rings are for secrets (and embargoes) only.** Group membership and
  folder access for code are plain server records: no rings, no keys.
  Secret keys stay in the existing signed rings **because the server must
  not be able to hand out secrets**: a compromised server could add an
  attacker's device to a group, and a member's device would then wrap the
  key for it. So:
  * **granting secret access is an admin-signed ring change**: when an
    admin runs `vl group add`, their `vl` grants the secret scopes (those
    the project's `cloak` lines name) to every registered device of the
    people added, signed by the admin's device, and sends the ring;
  * a manager's (or a compromised server's) group change gives folder
    access but **no key**: the secret stays closed until a ring admin
    signs (`vl group add` says so);
  * **the devices a key is wrapped for are vouched for outside the
    server** (BUG-827, fixed; §13.11): a person's first device is
    confirmed by the admin by its fingerprint, and their later devices by
    one of their own. The server's device list alone never wraps a key;
  * removing someone from their last group **rotates** the key away from
    their devices (as `vl scope revoke` does) when a ring admin removes
    them; a manager's removal says the key was not rotated and asks an
    admin to remove them too (BUG-828);
  * only an admin of the project starts a scope's ring on the server (its
    first change); later changes verify against its signed log (BUG-822).
  * The server stores rings, verifies each change with the engine's own
    replay (`Keychain::merge_ring`) and keeps the longest log that
    verifies; it cannot open them and is not their authority.
* **S1 limit: one key for every secret.** All sealed secrets use the
  `team` key, so someone granted it for one folder could open another
  folder's secret *if* they received its ciphertext, which the server
  never sends them without folder access (a compromised server could).
  Per-rule keys (below) close this.

**S2 (built, §13.12): keys per access rule, shared in the background.**
The plan as it was written, with what was built in its place:
1. Each access line that covers a secret gets its own scope
   (`rule-<hash of the path>`), and the builder seals a shared secret under
   the scope of the line that decides its path (this needs a new
   classification input, the accepted access lines; FORMAT.md entry for the
   scope name).
2. When an admin adds someone to a group, the server queues "wrap the
   scopes of the rules naming this group for these devices". **The next
   online device of a ring admin** (or of a member holding the key) checks
   the request against an **admin-signed membership statement**, never
   against the server's group list alone: the admin's `vl group add` signs
   `(project, group, person, device keys, time)` with the admin's device
   key, the server stores it, and the wrapping device verifies the
   signature, that the signer is a current ring admin, and that the device
   keys are bound to the person (§6.3, §12.2).
3. A new device of an existing member is wrapped the same way, on a
   statement signed by one of the person's existing devices (**built**,
   §13.11; the wrapping still waits for a ring admin's `vl group add`).
4. Removal rotates every scope the person could open and lists the
   secrets to change (§6.4).

As built (§13.12): the scope is `rule-<hash of the line's path>` for the
lines that name someone, the `cloak rule` policy word selects it, and the
admin-signed statement of step 2 is the key ring itself: a member's device
adds a device (`share`) only with a proof the ring's replay checks, an
invite join or the person's own vouch. Server lists are hints.

### 13.7 Concurrency

* Branch moves are one conditional `UPDATE` per branch inside one
  serialisable transaction; `server_hub` checks no update is lost with 12
  concurrent pushers × 6 pushes (with server-side grafts), that exactly
  one of 12 racing branch creations wins, and that separate branches never
  wait on each other, on PostgreSQL and on YugabyteDB, and under load
  (`scripts/verify-server.sh` runs 8 copies at once on PostgreSQL, 3 on
  YugabyteDB).

* **Migrations and retries** (BUG-838): `veil-server migrate` applies
  the schema migrations once; a server starting on a schema that is not
  current applies them itself while holding a database advisory lock,
  other servers waiting for it, and a server that finds the schema current
  runs no DDL at all (it can run as a role without DDL rights). Every
  request that fails on a retryable database error (`40001`, a restarted
  read, a catalog changed by DDL on YugabyteDB) before anything it did was
  committed runs again, with capped and jittered backoff, until a 45 s
  deadline, then answers `busy` (`db::retry_requests`).

### 13.8 Known limits of S1 (deliberate)

* **Branch names** are visible to everyone who may read anything in the
  project (branch rules, §7.4, decide later who sees which branch).
* **Existence by probing:** a writer refused at a path learns that a rule
  restricts it (they must guess the name). Errors never name anything the
  caller did not send.
* **Descriptions** of changes that touched both visible and hidden paths
  are shown with the visible part (§13.4).
* **One secret key** per project (§13.6): fixed in S2, a key per access
  line (§13.12).
* **Open findings** (`docs/BUGS.md`): HTTP/2 connections idle between
  requests are not timed out (BUG-825 bounds handshakes and HTTP/1 request
  heads).
* **Upload timing:** an upload answers the same whether the project held
  an object or not, but a store may take another time to write over an
  existing key.
* **Devices** (fixed in S2, §13.12): a confirmed device receives its keys
  from any member's device, in the background; devices are removed with
  `vl identity remove`; pending devices are found by fingerprint, so others
  made under a name never hide the real one, and are bounded per person.
* **Embargoed merges** cannot be pushed to the server yet.
* **`--only` clones** cannot move to revisions that changed folders outside
  their directory (§13.5).
* **A working copy without the project's `.veilpolicy`** (someone who cannot
  read it, the project root being private by default; an `--only` clone)
  classifies files by the built-in rules: a shared secret it holds sealed is
  kept as recorded, never deleted, and an edit of it stays local (`vl status`
  says so) until someone who reads the policy records it (BUG-832).
* **Moving a repository with history onto the server** works by pushing it;
  its first accepted policy is listed back to the admin (§13.3). Every
  pushed snapshot must be signed by a device registered on the server, so
  history signed by teammates who have not signed in yet is refused until
  they do.
* The team vault (`vl secret --scope`) does not sync through the server.
* `vl push --dry-run` and `--delete` were removed with path remotes (the
  simplification pass, part 1); `pre-push` hooks run before a push to the
  server.

### 13.9 Later milestones (not in S1)

The designs for phases 2–4, with milestones S3–S26 in build order, are in
`docs/design/server/` (`README.md` lists them, their dependencies and what
can run in parallel).

1. **S2: secrets at scale** (built, §13.12) — invites, keys per access
   rule, sharing in the background for new members and devices, device
   removal.
   Person-to-person secret shares (`vl secret share`, §13.17) close
   phase 1.
2. **S3: fetch on demand in the client** — the partial-clone design
   (`docs/design/scale/6-partial-clone.md`): bounded cache, objects fetched
   when read, `vl ws mount` over the server; layered caches (per-machine
   daemon, regional caches) serving objects only after the server's check.
3. **The PR and review service** (§7), hidden PRs.
4. **Server-side merges and batched landings** (§9.1), with the gates of
   §9.2.
5. **Precomputed history and search APIs** (blame, file history, graph,
   search through the API).
6. **Embargoes through the server** (permissions, §8.2; the deadline
   worker is not built yet).
7. **The web client** (§10).
8. **The simplification pass:** remove SFTP and path remotes (part 1,
   done), every encryption but secret files' (part 2, done: format 8),
   offline assumptions, cloak/scope jargon (OVERVIEW.md).

### 13.10 Speed (the OpenScion gates, first measurement)

`veil-bench openscion` (`crates/veil-bench/src/openscion.rs`) measures the
four OpenScion workloads with release builds, the server on `127.0.0.1`
over TLS with PostgreSQL in Docker, and Git on the same machine as the
reference. Results are in `docs/design/scale/OPENSCION.md`: cloning
through the server takes what cloning from a path remote takes on the same
machine (the server adds nothing measurable). Both were dominated by the
checkout's per-file `fsync` (BUG-818, pre-existing); with one barrier per
checkout the 10k clone takes 1,014 ms instead of 10,044 ms. Clone one
directory stays flat from 1k to 10k files (62 and 74 ms). Performance
round 2 (parallel staging and barriers, packed and parallel fetches):
437–449 ms at 10k, faster than Git. The server under load:
`docs/design/scale/LOAD.md` (`veil-bench load`).

### 13.11 Confirmed devices: who a secret key is wrapped for (BUG-827)

**The problem.** The server is trusted with code, never with secrets
(§3.1). Before this fix an admin's `vl group add` wrapped the secret key
for every device `GET /v1/people/{name}/devices` returned, so a
compromised server listed its own device under the person being added and
received the key (BUG-827). **The server's word about whose device a key
is can never be enough:** every device a key is wrapped for must be vouched
for by someone outside the server.

**The design.**

* **A device fingerprint** is what people compare: 20 hex digits in five
  groups (`4F2A-9C1E-77B0-D3E5-A1C2`), the first 80 bits of a BLAKE3
  `derive_key` (context `veil 2026 hub device-fingerprint v1`) over the
  device's Ed25519 and X25519 public keys (`hub::wire::device_fingerprint`).
  `vl login` and `vl identity show` print it.
* **A person's first device is confirmed by the admin, out of band.**
  `vl group add finance alice` shows `confirm alice's device:
  4F2A-9C1E-…` for each of alice's devices nothing vouches for yet, and
  grants no key to it. The admin compares it with what alice reads from
  her screen (in person, on a call), then runs `vl group add finance alice
  --confirm 4F2A-9C1E-77B0-D3E5-A1C2` (one person at a time: with several,
  the server could list the device under another of them, BUG-835). A
  `--confirm` that matches none of
  alice's listed devices fails loudly: the server is listing a device that
  is not the one alice has.
* **A person's later devices are confirmed by the person (cross-signing).**
  The new device signs in with `vl login URL --name alice`: the server
  records it as **pending** (no session, its signatures are not accepted)
  and `vl` prints its fingerprint. On a device alice already uses she runs
  `vl identity confirm 7C1B-…`: her `vl` finds the pending device with that
  fingerprint in her own device list and signs a **vouch** (Ed25519,
  signature context `hub-device`, over the new device's X25519 and Ed25519
  keys) with her device key. The server checks the vouch, activates the
  device and stores the vouch; the new device's next `vl login` signs in.
  A pending device waits 24 hours (signing in again renews it), and `vl
  identity confirm` looks it up by its fingerprint (§13.12); a person has at
  most 32 pending devices, and one they looked for is never pushed out.
* **What an admin's `vl` wraps for.** For each person being added it takes
  the server's list of their devices *and the vouches*, and grants the
  secret scopes only to devices in this chain, built entirely from things
  the server cannot forge:
  1. devices already in a key ring this device verifies (signed by a ring
     admin), under the person's name: confirmed before;
  2. devices whose fingerprint the admin gave with `--confirm`;
  3. devices with a vouch that verifies under the signing key of a device
     in 1–3 (repeated until nothing changes);
  4. since S2 (§13.12): devices whose join verifies under an invite for the
     person (one a ring holds, or one this admin's device made), and devices
     this admin's device confirmed by fingerprint in an earlier command. A
     device a ring took the key from is given it back only on 1 or 2.

  Every other listed device gets `confirm alice's device: …` and no key.
  Since S2 (§13.12) a device alice confirms receives the keys from her
  confirming device at once, or from any member's device in the
  background; re-running `vl group add` also grants them.
* **Removal rotates by the ring, not the list:** `vl group remove` revokes
  every ring member recorded under the person's name as well as their
  listed devices, so a server that hides a device does not keep it the key.
  Whether the person left their last group is the server's word: a removal
  that leaves them in another group says so (`keys: fin is still in
  security: the secret key was not rotated away from them`, BUG-836).

**Threat review** (attackers outside the boundary for secrets, §3.1):

| Attacker | Tries | Result |
|---|---|---|
| Compromised server | lists its own device under alice when an admin adds her | not confirmed: shown as `confirm alice's device: <its fingerprint>`, no key. Alice reads a different fingerprint, so the admin's `--confirm` matches nothing and fails |
| Compromised server | forges a vouch for its device | the vouch must verify under a key in the chain; the server holds none |
| Compromised server | replays alice's real vouch for her device D2 onto its own device | the vouch signs D2's keys, not its device's: it does not verify |
| Compromised server | makes a device whose fingerprint equals alice's | a second preimage of 80 bits: about 2^80 key generations |
| Compromised server | renames people, so bob's confirmed device is listed under alice | bob's device already holds the key; nothing new is wrapped |
| Compromised server | hides one of alice's devices at removal | rotation also revokes every ring member named alice |
| Anyone on Earth | `vl login --name alice` with their own key | a pending device only: no session, no access, no key, until one of alice's devices vouches for it; since S2 it cannot hide alice's own pending device either (looked up by fingerprint, §13.12) |
| Alice herself | vouches for a device that is not hers | trusted: her own deliberate command (§3.1) |
| Admin | confirms without comparing | the human check is the boundary; the fingerprint is shown once, with what to compare it against |

**Remaining (not needed to close the class):** all built in S2 (§13.12):
keys per access rule, sharing when a new device is vouched, removing a
device, and invites as the way to confirm a first device.

### 13.12 S2: invites, keys per access rule, background key sharing, device removal

**Goal** (owner, 2026-11-06): secrets reach the right devices on their
own, and **a hacked server can never hand out a secret key**. Admins only
ever need `vl invite`, `vl group add|remove`, `vl access` and, rarely,
`vl identity remove`.

#### The design

* **The key ring is the only authority for who holds a key.** Every rule
  below is checked by the ring's replay (`KeyRing::verify`), so every reader
  (the server's `merge_ring`, every device that pulls the ring, the device
  about to append) refuses a change that breaks it. Nothing a device decides
  from the server's lists can widen a ring: it can only make a device *try*
  a change that the replay then refuses.
* **Keys per access rule.** The `.veilpolicy` lines that seal shared secrets
  say `cloak rule` (`vl init` writes them). A secret under `cloak rule` is
  sealed under the scope of **the access line that decides its path**:
  `rule-<20 hex of BLAKE3 derive_key("veil 2026 policy rule-scope v1",
  path)>`. A path no access line decides, or one decided by a line that
  names nobody (`docs/ public`), uses `team`, which on the server holds the
  project's admins only. Someone with `billing/` therefore holds
  `rule-<billing>` and nothing that opens `infra/.env`, even if a
  compromised server sends them its ciphertext.
* **Each rule's ring holds** the admins and the confirmed devices of the
  people the rule gives the folder to (its groups' members and the people it
  names). An admin's `vl access`, `vl group add` and `vl group remove`
  create the rings and grant or revoke against that list, and print every
  name they act on.
* **New ring operations (ring format 4, repository format 7):**
  * `invite {person, key, expires_at}`, signed by a ring admin: the public
    Ed25519 key derived from an invite's secret;
  * `uninvite {key}`, signed by a ring admin;
  * `share {member, proof}`, signed by **any current member** holding the
    key. The replay accepts it only if all of these hold:
    * the new member is named after a person the ring already trusts (one
      of their devices is a current member, or a live invite names them);
    * it is a bound identity (signing key and binding), at the current
      generation, never a member of this ring before, and its signing key
      never belonged to anyone in the ring (so a removed device is never
      shared to again);
    * the proof is one of:
      * an **invite join**: a signature (context `hub-invite`) over `person
        ‖ 0 ‖ X25519 ‖ Ed25519` of the new device, under the key of an
        unused, unexpired `invite` for that person. The ring marks the
        invite used: **one invite, one device, in the ring itself**;
      * a **vouch**: the person's own signature (context `hub-device`, as
        in §13.11) over the new device's keys, by the signing key of a
        current member *with the same name*.
  * `revoke_own {member, rotation}`: a current member revokes another of
    **their own** devices (same name) and rotates the key; revoking anyone
    else's device stays an admin's change.
* **Invites.** `vl invite alice --to finance` (an admin) makes 32 random
  bytes on the admin's device. It derives the invite key from them, appends
  `invite` to the rings of the rules naming `finance`, tells the server
  (person, group, public key, expiry: 7 days) and prints
  `veil://host/project#invite=alice:<64 hex>:<20 hex>`: the secret, then
  **the project's fingerprint** (below). **The secret is only in the
  link.** The fragment is never sent to the server by `vl`; the server sees
  only the public key. `vl join <link>` (or `vl join -`, reading the link on
  standard input, where other users of the machine cannot see it) signs in
  (a new name registers alice; a name somebody has must sign in from one of
  its devices first), signs the join for this device with the invite key,
  and sends it. The server checks it, marks the invite used, adds alice to
  `finance` (folder access) and queues "share keys for alice". `vl join`
  then checks that the server's `team` ring has the link's project
  fingerprint and records it: the anchor of every ring alice's device takes
  from this project. The fingerprint flow
  (`--confirm`) stays as the fallback. **Removing** alice from the group
  (`vl group remove finance alice`, also before she has an account) takes
  back her invites to it that were not used, on the server and in the
  rings (BUG-842).
* **Background sharing.** After a `vl` command in a clone of a server
  project (at most every 10 s; `VEIL_KEY_SHARE=0` turns it off), a detached
  `vl` asks the server whose devices are waiting (`GET …/keys/pending`: a
  hint only). For every ring this device holds the current key of, it
  appends `share` for each listed device that has a proof, then sends the
  ring. The ring's replay decides, never the list. `vl identity confirm`
  shares from the confirming device at once, and `vl group add` by an admin
  still grants directly.
* **Every ring is bound to its project** (BUG-845). A project's id is the
  hash of its `team` ring's genesis change (32 hex digits); every other ring
  carries it in its signed genesis (`project`). The **project fingerprint**
  people compare is the first 80 bits of BLAKE3 `derive_key("veil 2026 hub
  project-fingerprint v1", id)`, shown as `9D3E-51A0-C7F2-0B64-E18D`.
  Every replay that decides about keys (`Keychain::bound`: sealing, opening,
  taking a ring, an admin's or member's change, the server's merge) refuses
  a ring that names another project, and in a clone of a server project one
  that names none.
* **Which rings a device takes from the server.** Only rings of a project
  whose fingerprint this device **anchored**, from outside the server:
  * the device that created the project (its own `team` ring);
  * `vl join`, from the invite link;
  * `vl identity confirm PROJECT-FINGERPRINT` in a clone, after the person
    compared it with an admin, or with `vl identity show` in a clone on
    another of their devices (it prints `project  9D3E-…`). This is how an
    admin's new laptop, or a device an admin confirmed with `--confirm`,
    anchors a project: `vl group add … --confirm` prints the project's
    fingerprint to tell the person, and an unanchored clone prints the one
    the server claims, to compare.

  The anchor is kept per device and project (`$VEIL_HOME/hub.json`) and in
  each clone (`.veil/local/project-anchor`). Until a clone has one, it takes
  no ring at all (code still arrives: it is plain text, and the server's
  access check protects it), so it seals and opens no secret. With one, it
  takes only the `team` ring with that fingerprint, and then only rings
  naming that project. A ring of a scope the device does not hold yet must
  also be started by a current member of its `team` ring (the admins'),
  so the server cannot put up a ring of its own, for any scope, that
  confirms its devices to an admin or seals a rule's secrets under its key
  (BUG-840, BUG-841). The server, for its part, stores a new ring only if
  it names the project's `team` ring, sent first.
* **Why not in the vouch.** A new device cannot check a vouch's signer by
  itself: a hacked server can show it a made-up "device of yours" vouching
  for anchors of the server's choosing. So a later device anchors through
  the person's own comparison of the project fingerprint (or an invite), not
  through the vouch.
* **Every ring change is decided on the server's latest ring.** It is built
  in memory, sent, and stored locally only once the server accepted it as
  a fast-forward. On a race (409) the device fetches the ring and decides
  again from scratch: a removal racing a share can never resurrect a removed
  device, and no device ever keeps a key the server refused.
* **Device removal** (BUG-843). `vl identity remove FINGERPRINT`:
  * **by the person**, from another of their devices: the device is removed
    on the server everywhere (it can no longer sign in, its sessions stop);
  * **by an admin**, of someone else's device: the device is **barred from
    that project only** (`device_bars`): every request of it to the project
    is refused, and nothing reaches the person's other projects. Only the
    person removes a device everywhere.

  Either way `vl` revokes it in every ring of this project, found by its
  fingerprint among the **ring's** members, not the server's list. The
  server reports it as removed in the projects it no longer may use (a
  global removal: all of them; a bar: that one), and the person's other
  devices, or admins, revoke it there in the background. Revoking is
  conservative, so trusting that report gives a hacked server nothing.
* **Pending devices** (§13.8's limit). Each expires after 24 h, and `vl
  identity confirm` looks a device up **by its fingerprint** (`GET
  /v1/people/{me}/pending/{fp}`, for its person only). A person has at most
  32 pending devices: a new one pushes out the oldest, **except one whose
  fingerprint the person looked for** in the last hour (`device_expected`,
  at most 8 per person, written only by the person's own lookup). So the
  table stays bounded, and no number of made-up pending devices hides the
  real one: if a flood pushed it out before the person looked, `vl identity
  confirm` says so, the new device signs in again, and from then on nobody
  can push it out.
* **Migration from S1's one key** (explicit and listed): `vl upgrade` moves
  each clone to format 7. Then an admin runs `vl upgrade --rule-keys`
  (`--dry-run` lists only). It lists every secret with its new key and who
  will hold it. It rewrites the S1 lines (`.env cloak team`, …) to
  `cloak rule`, creates the rule rings and grants them, and revokes every
  non-admin from `team`. The admin's next commit re-seals each secret under
  its rule's key. Running it again (after a run that stopped midway) brings
  the rings up to date the same way (BUG-844). Old versions stay readable with the old `team`
  generations; nothing is decrypted or made public.

#### Threat review

The attacker is **whoever controls the server** (outside the boundary for
secrets, §3.1), unless a row says otherwise. Each row is tested in
`server_hub` (`adversarial`, `secrets2`, `adversarial_s2`, `projects`) and
`core_security` (`ring_shares`).

| # | Tries | Result |
|---|---|---|
| 1 | **Forged join:** a join for its own device under an invite | The join must verify under the invite key, derived from the link's secret, which never reaches the server. Brute force: 2^256 |
| 2 | **Substitutes the invite key** in its own records, so `vl join` signs for a key the server made | The ring's `invite` (signed by the admin) names the real key; a share proved by any other key is refused by every replay |
| 3 | **Server-chosen codes:** hands the admin an invite secret | The admin's device makes the secret; the server is never asked for one |
| 4 | **Replays alice's join for another device** (device swap) | The join signs the device's X25519 and Ed25519 keys; on another device it does not verify |
| 5 | **Reuses an invite** (a second device, or after alice's) | The ring marks the invite used at the first share; a second share proved by it is refused. The server also refuses a second join |
| 6 | **Keeps an invite alive past its expiry** | The replay compares the share's signed time with the admin-signed `expires_at` |
| 7 | **Lists its own device under alice**, with a vouch it signed or one moved from another device | A vouch must verify under the key of a current ring member *named alice*; the server holds none (§13.11) |
| 8 | **Renames people** (bob's device listed under alice) | Ring names come from admin-signed changes; a share must carry the name its proof is for |
| 9 | **Replays a grant after a removal** (shares alice's new device after `vl group remove`) | The ring's own current membership is the grant: after the removal no member is named alice and her invites are revoked, so nothing proves a device of hers |
| 10 | **Re-lists a removed device** (with the old, valid vouch) | The replay refuses a share to any id or signing key the ring ever held. An admin's device gives such a device a key back only after a new `--confirm` in that command, or while another ring holds it now (`may_grant`) |
| 11 | **Hides a device at removal** | `vl group remove` revokes every ring member named after the person; `vl identity remove` finds the device among the ring's members |
| 12 | **Serves an old ring** to a sharing device | That device then holds only an old generation, which the person already had. A change built on it forks the server's log and is refused; the device decides again on the latest ring |
| 13 | **Races a share against a removal** | The log is linear (compare-and-swap on the ring row, fast-forward only); each change is decided on the latest ring. Tested with many sharers under load |
| 14 | **Sends `infra/.env`'s ciphertext** to someone with `billing/` only | Sealed under `rule-<infra>`, which they never hold |
| 15 | **Misreports a group's members** to an admin's `vl access` or `vl group add` | Only confirmed devices are granted, so the server's own devices never are. The command lists every person it granted. A lying list can make an admin grant a *real teammate* a rule's key, never the server |
| 16 | **Misreports membership at a removal** (keeps someone listed in another group) | The removal says who kept a key and why (BUG-836) |
| 17 | **Floods pending devices** under alice's name (also in parallel) | Lookup is by fingerprint (80 bits, a second preimage); each pending device expires after 24 h; at most 32 per person, the oldest pushed out, never one alice looked for (`device_expected`, written only by her own lookup). A flood before she looks pushes hers out once: `vl identity confirm` says so, the device signs in again, and is kept from then on |
| 18 | **Turns a leaked or replayed invite into an account** (a device signs in as an existing person) | A join never makes a device someone's: under a name somebody has, `vl join` needs a session of that person's |
| 19 | *A member* (insider) shares to a device that is not the person's | They hold the key and could leak it anyway: trusted (§3.1). Still, the replay lets them add only devices with a proof |
| 20 | *A compromised member device* revokes others or takes over the ring | `revoke_own` only reaches the same person's devices; anything else needs an admin's signature |
| 21 | *Someone who reads the invite link* (a leaked Slack message) | Before alice uses it: they can join as alice (first use wins), and alice's own `vl join` then fails ("used"), so it is noticed. The admin removes the device (`vl identity remove`) and invites again. After use, or after 7 days: nothing. `vl join -` reads the link on standard input, so other users of a shared machine cannot read it from the command line |
| 22 | **Serves another project's ring** for the same rule path (`rule-<billing>` is the same name everywhere; the same admin started both) | The ring's signed genesis names its project; every replay that decides about keys refuses another project's ring (BUG-845) |
| 23 | **Renames a ring** (another project's ring served under another scope name) | The scope is in every signed change: the replay fails |
| 24 | **Replays a change** of one project's ring onto another's | Each change signs its scope and the previous change's hash: it does not link |
| 25 | **Serves another project's `team`** (or one it made) to a device's first clone | The device takes no ring until it anchored the project's fingerprint (the invite link, its own creation of the project, or the person's comparison); then only the `team` with that fingerprint. `vl identity confirm` checks a typed fingerprint against the server's `team` ring, so a substituted one cannot be confirmed |
| 26 | **Substitutes `team` before a join** (or the link's fingerprint was changed) | `vl join` fails loudly ("not the one your invite names") and records nothing: the device trusts none of the project's rings |
| 27 | **Gives an admin's new laptop** (vouched, holding project A's keys) project A's ring as B's | The laptop anchors B separately (B's fingerprint, compared with the admin's first device); A's ring names A and is refused in B |
| 28 | **Shows a made-up vouching device** with anchors of its choosing to a new device | Anchors never come from a vouch (the new device cannot check its signer): only from an invite link or the person's comparison |
| 29 | *An admin of any project* (anyone can make one and add a person to a group) removes the person's device | It is barred from that admin's project only; the person's other projects never list it as removed; only the person removes a device everywhere (BUG-843) |

**Residual risks** (not closed here; recorded):
* **Freshness:** a server can withhold a rotation from a member's device,
  so that device keeps sealing new secrets under a generation a removed
  person still holds. This needs both the server and the removed person,
  and was already so in S1. A signed freshness check is later work.
* A rule that names no rule-specific people (`docs/ public`) uses `team`;
  adding names to it re-seals its secrets under a new rule key at that
  policy edit.
* **Reported removals:** a server can report devices as removed, and the
  devices that may revoke them do (an admin's, or the same person's).
  Revoking is never a grant, so the server gains no key, only denial of
  service (which it can cause anyway). A device revoked that way gets its
  key back only with a new `--confirm` (row 10).
* Invites name the invited person in the rings of their group's folders,
  which every participant of the project may read.
* **A person who confirms a project fingerprint without comparing it**
  (like an admin who confirms a device fingerprint without comparing it)
  trusts what the server shows: the human comparison is the boundary. An
  invite link needs no comparison.
* **A clone made before its device anchored the project** opens no secret
  until the person confirms the fingerprint; this is the price of never
  trusting a ring on the server's word.

### 13.13 S10: commits through the API

Built 2026-11-07 (`crates/veil-server/src/changes.rs`; the messages in
`veil_core::hub::changes`; `vl change new`). Design: phase 2 §5.5
(`docs/design/server/phase-2-thin-clients.md`).

```text
POST /v1/projects/{p}/changes
{ "base": "<snapshot id as the caller sees it>",
  "change_id": "<optional: a new revision of a change of yours made here>",
  "description": "…",
  "edits": [ {"path": "src/a.rs", "put": {"text": "…", "executable": false}},
             {"path": "src/b.bin", "put": {"object": "<id>"}},          // uploaded first, with its receipt
             {"path": "src/old.rs", "delete": true} ],
  "receipts": {"<id>": "<receipt>"},
  "onto": {"branch": "main", "expected": "<tip id>" | "rebase"} }      // optional
→ { "change_id", "snapshot": "<as the caller sees it>",
    "branch": {"branch", "status": "ok" | "rejected", "message"?, "tip"?, "rebased": n},
    "warnings": […] }                                                     // an admin's access change, listed
```

* **The same checks as a push, by the same code.** The server applies the
  edits to the caller's projection of `base` (the tree their own `vl` would
  push), then runs the push's per-snapshot checks on it
  (`sync::complete`): the graft onto the full tree, so nothing the caller
  cannot see is touched; write access for every edited path; access lines
  changed only by admins, against the actual parent (the authority is the
  accepted policy); closure (an object that is not the caller's upload, nor
  the entry at that path in the caller's **view** of `base`, gets the answer
  a missing one gets, before anything reads it, so a guess of a hidden
  file's content is never confirmed: BUG-1050); personal keys refused;
  secret paths only as ciphertext; check 9 below. A move of the default
  branch accepts its policy only when the branch moves and only from an
  admin, with the same listing of who can now see what; anyone else's
  change of access lines is kept, `rejected` (BUG-1051).
* **Check 9, the server-side secret scan** (also for pushes): every new
  plain-text file, symlink and conflict term is scanned with the scanner `vl` uses
  (`veil_core::secrets::scan`); a hit refuses the change. The error names
  the path, the rule and the line, never the text. `public!` turns it off
  only where the **accepted** policy (an admin's) says so, or in an admin's
  own change: anyone may turn `public` into `public!`, which is the same
  access. A push of old history recorded under an older scanner can now be
  refused where today's scanner finds something.
* **Inline text is held in memory until every check passed** (`Source::pending`),
  so a refused plain-text secret is never stored. (An object uploaded
  through `POST …/objects` is stored at upload, as for pushes: BUG-930.)
* **Labels are claims:** an uploaded object's entry takes its kind, size and
  label from the object (a sealed envelope is a secret of its scope, a blob
  is plain); anything else is refused. As in every push (format 8), a sealed
  object is accepted only as a secret: at a secret file's path, or as
  content that descends from a secret (a renamed secret, which `vl` keeps
  sealed), by the rule `vl upgrade` checks (`policy::sealed_secret`).
* **The snapshot** is signed by the server's key; its author is the caller.
  Other viewers get the same projections as for any pushed snapshot (§13.4);
  the caller's own projection is worked out before the commit and recorded
  with it.
* **One database commit per API commit** (`storage-and-cost.md` §3): the
  snapshot row, the caller's projection memo, the change ref, the audit row
  and, with `onto`, the one-row compare-and-swap of the branch (and an
  admin's policy) are one READ COMMITTED transaction. Objects are stored
  before it, at most 64 at a time (BUG-1053). A non-admin's one-file change stores 6 objects (the blob, the
  full trees on its path, the snapshot and the caller's projection).
* **Change refs** (`change_refs`, migration 5): every change made this way
  is kept under its change id, whether or not a branch moved, and is a
  `base` like any snapshot. Only its creator makes a new revision of it
  (`change_id`); the new snapshot names the previous one as predecessor.
* **`onto`.** `expected` is the push's compare-and-swap, judged on the
  caller's view: the move is refused (the change is still kept) unless the
  branch's tip is that snapshot as the caller sees it, and `base` is that
  tip or a stack of up to 64 of the caller's own unlanded changes on it,
  each writing only paths they may still write. When changes the caller
  cannot see landed under the stack, the server makes the caller's changes
  again on the real tip (each their view grafted onto the new parent, with
  the push's checks); the caller sees them with the same ids, so nothing
  tells them a hidden change landed (BUG-1054). `"rebase"`: when the tip
  is not `base`, the server applies the edits to the tip instead, provided the
  entry at every edited path, and whether each folder above it is a folder,
  is the same in `base` and the tip; it tries again on a lost race, up to 5
  times, then answers `rejected`. Each try reads the accepted policy and
  the caller's access again. **The change is its edits:** applied to
  another tip, it never carries what `base` had and the tip has not (to
  stack on an unlanded change, use `expected`).
* **Limits:** 10,000 edits, 64 MiB of inline text (and the 64 MiB body
  limit), paths of at most 4,096 bytes with at most 1,024 folders above the
  file (`MAX_TREE_DEPTH`, a tree's own limit; every server thread has a
  stack for walks that deep: BUG-1052), in Unicode NFC,
  each component a valid entry name (no `..`, `.`, empty, NUL or any
  spelling of `.veil`); two edits of one path, or of a file and something
  below it, are refused; a delete names an existing file.
* **`vl change new [PROJECT] --edits FILE.json [--base ID] [-m MSG]
  [--onto BRANCH [--expected ID]] [--change ID]`** sends the list. In a
  clone of the project it seals secret files with the clone's keys
  first (outside one, it refuses to send them), and it scans every
  ordinary file itself, so a secret never leaves the device.
* **Measured** (`docs/design/scale/LOAD.md`, "Commits through the API"):
  one file by one agent, p50 7.4 ms as the client sees it, 2.7 ms of
  server CPU, 13 statements and 1 commit (a push: 10.7 ms, 34 statements,
  3 commits); 1,000 landings/s across 100 projects (pushes: 283–547);
  into one `main` with 50 agents, 20/s at p99 95 ms, peaking near 35/s,
  short of phase 2's 100/s (each lost race rebuilds the change; S17
  batches).

Threat review (phase 2 §6, rows 11–13, and what S10 adds):

| # | Attacker | Capability | Harm | Mitigation | Test (`server_hub` `changes`) |
|---|---|---|---|---|---|
| 1 | A member | edits outside their folders, at the private root, in a nested hidden folder; deletes a hidden file | writes where they may not, or learns a hidden name exists | the push's graft and write check; a hidden file and a missing one get the same "nothing at" | `an_api_commit_is_refused_whatever_a_push_refuses_and_stores_nothing` |
| 2 | A member | edits `.veilpolicy`'s access lines; turns `public` into `public!` | gains access, or turns the scan off | the push's access-line check against the parents; the scan's exemption needs the accepted policy or an admin | same, and `the_secret_scan_is_off_only_where_the_accepted_policy_says_public_bang` |
| 3 | A member, or a hostile API client | sends a plain-text `.env`, a token in an ordinary file, a personal key | a secret stored in the clear, or echoed in an error, log or JSON | checks 8 and 9; inline text is stored only after the checks; errors name the rule and line only | same (the blobs are not in the store; the answers lack the secret) |
| 4 | A member | `put.object` names a hidden blob's id (from an old grant, a log) | copies a hidden file into their folder, or confirms it exists | an object without the caller's receipt that is not the entry at that path in `base` gets the missing answer, before it is read | same (a hidden id and a random one get the same answer) |
| 5 | A member | `base` is the real id of a snapshot they see only part of | a graft on content they cannot see, or a confirmation of the real id | `base` must equal the caller's projection of the real snapshot it resolves to | same (404) |
| 6 | Hostile API client | `..`, NUL, `.veil` and its spellings, non-NFC names, 1,100 levels, 10,001 edits, 64 MiB + 1 of text, overlapping or duplicate edits, unknown fields, a snapshot id as a file | a corrupt tree, or work quadratic in the input | the request limits; each component checked with the tree's own name check; one pass per path for overlaps and rebases | `hostile_edit_lists_are_refused` |
| 7 | Racing agents | `rebase` onto one `main` | a change lost, landed twice, or applied over a newer edit of its file | reapplied only when every edited path is unchanged; the branch moves only by the compare-and-swap, in the same transaction as the change's rows | `rebase_lands_every_racing_change_once_with_exactly_its_edits` (50 agents: each landed once, each landed snapshot's diff is exactly its edit) |
| 8 | Another person | `change_id` of someone else's change | rewrites their change | revisions only by the change ref's creator (also in the upsert itself) | `expected_tips_and_revisions_of_a_change` |
| 9 | Anyone on Earth | calls the route signed out | commits | 401; a participant is required | `an_api_commit_is_refused_…` |

### 13.14 S4: request-path caches and one commit per push (as built)

Milestone S4 (`docs/design/server/phase-2-thin-clients.md` §9,
`storage-and-cost.md` §3–5, §9). Code: `caches.rs`, `auth.rs` (`Caller`),
`perm.rs` (`open`), `sync.rs` (`projected`, `resolve`, `tips`, `push`),
`migrations/0006_access_epochs.sql`.

**What each server keeps in memory** (LRU caches with byte budgets; never
in the database):

| Cache | Key → value | Kept fresh by |
|---|---|---|
| sessions | token hash → person, device, expiry | the person's access epoch, read on every request; the expiry |
| projects | name → accepted policy, bindings, default branch | the project's access epoch, read on every request |
| permissions | (project, person, device) → admin, groups, device barred | both epochs |
| snapshot resolution | (project, id) → committed; (project, view key, real) → projected; (project, view key, projected) → real | nothing: these facts never change (rows are never deleted or rewritten; a view key is a hash of what its viewer may read) |
| branch tips | project → branch rows | a notice from every push (`NOTIFY`), or at most 100 ms |

**Access epochs: never stale, on any server.** `access_epochs` holds an
epoch per person (`(0, person)`: their sessions, devices, admin rights,
group memberships, device bars) and per project (`(project, 0)`: its
accepted policy, bindings and groups). **Each change sets its key's epoch
to a fresh random value** (60 bits from `gen_random_uuid()`, never 0 and
never the previous value), not a count: an epoch carried to a client shows
neither how many changes happened nor when (BUG-1081). Only equality is
compared. A bump writes only its own key's row; there is no server-wide
row. S5's read grants use the same epochs (void unless equal to the
current ones). **Triggers** on `group_members`,
`project_admins`, `sessions`, `people`, `devices`, `device_bars`,
`projects` and `groups` bump them in the transaction of the change itself,
whatever route (or operator) makes it, so a route written later cannot
forget. **Every request reads its two epochs** in one statement of two
primary-key lookups (the session check reads them; it learns the project's
id from the path), and a cached session or permission is used only if it
was built under exactly those epochs. An entry is built by reading the
epochs first and the records after, or both in one statement, so it is
never tagged with an epoch set after what it holds was read.

*What a read grant can rely on (S5):* (1) an entry records the epochs read
before its rows, and `perm::open_at` returns them with the view, so a grant
made from it carries those, never a later read of the epochs; (2) an entry
is used only while its person's and project's epochs equal its recorded
ones; (3) permission entries are per device (a bar is the device's);
(4) nothing else that decides a view (policy text and bindings, groups,
admin rows, devices, sessions) is cached outside such an entry
(`a_view_carries_the_epochs_it_was_built_under`).

*How staleness is bounded:* a change commits together with its new epoch;
any request that starts after the commit reads it, misses every entry
built under an earlier one (a random value repeats an earlier one with
negligible odds: 2^-60 for each pair), and reads the database. So a cached decision is the
one the database gives at the moment of the request: **staleness is zero**,
for removals from a group, policy changes, deleted groups, admin rights,
device bars and removals, and ended sessions (there is no sign-out route;
deleting a session row, as device removal does, is one). A request already
running when the change commits finishes as it would have without caches.
Tested with two servers on one database (`server_hub` `caches`): each kind
of change through either server or straight in the database, and readers
hammering both servers while an admin removes them (every request started
after the removal returned was refused). Dropping one trigger makes both
tests fail.

**Snapshot resolution** answers from memory what never changes; every
answer is still projected for the asker's current view, so it grants
nothing. **A resolution is per view:** for a viewer, a projected id
stands for a real snapshot whose projection *for that viewer's view key*
is that id (any of them gives that viewer the same tree and history);
another view's real snapshot for the same id is never used, since the
same projected id can stand for different real snapshots in different
views (BUG-915). Without one for the asker's view, the database lists every
real snapshot the id stands for. A push resolves parents from the database
(newest first) or from the branch tips it reads.

**Bounded by bytes, and by limits** (BUG-913). Every entry is weighed by
what it holds (strings, a parsed policy's rules, a view's group set, branch
rows, plus the cache's own bookkeeping), never counted as one, since its
size is the asker's to choose. Budgets: sessions 16 MiB, projects 32 MiB,
permissions 32 MiB, snapshot resolution 64 MiB, branch tips 32 MiB (about
176 MiB in all); an entry heavier than its cache's budget is not kept.
Expired tip rows are freed as time passes. Server limits that bound what
one entry can hold: **10,000 branches per project** and **1,000 branch
updates per push** (`sync::MAX_BRANCHES`, `MAX_PUSH_UPDATES`), and **1,000
groups per project** (`perm::MAX_GROUPS`); each is checked against the
records when the request begins, so concurrent requests may each add up to
the bound.

**Branch tips.** A pull may see a tip up to **100 ms** old, as
`phase-2-thin-clients.md` §5.1 allows; rows read before a push's notice are
never kept after it. A push never trusts the cache: it reads the branches
and compares and swaps in the database. Notices: PostgreSQL delivers
`NOTIFY` (another server saw a push within 5–15 ms in the tests);
**YugabyteDB 2025.2 does not by default** (`ysql_yb_enable_listen_notify`
is off), which the server detects at start (it sends itself a notice), and
tips then expire after 100 ms only. Its change feed is not used.

**One database commit per push.** The push's transaction writes the branch
compare-and-swaps, the accepted policy, the snapshot and origin rows, the
pusher's projection memo of what it moved (worked out before the
transaction, as it will read after the commit) and the audit row, and sends
the notice. A push whose every update is refused commits nothing
(BUG-910), and a push records only the snapshots of the updates that land
(BUG-914). Other viewers' projections are worked out when they first ask,
as before; a reader never gets an unprojected answer. A push reads only the
signing keys its snapshots name, not every device.

**Cost** (`veil-bench load`, `docs/design/scale/LOAD.md`): a landing's
push is 1 commit (3 before) and its request path 15 statements (34 before);
S12's deriver adds about 4 commits and 16 statements in the background. An
up-to-date pull is 1 statement (6); a request with warm caches 1 statement
(its epochs). **Gates** in
`veil-bench load`: at most 1 commit per landing, at most 5 statements per
up-to-date pull. A pull that brings new snapshots makes one request per
tree level (7 for the load test's agents), each reading its epochs, so it
costs about 8 statements: under the hard rule that every request is decided
on current access, fewer statements per such pull needs fewer requests per
pull (S3), not a staler check.

`veil-server` writes its counters (storage writes and reads, cache hits and
misses) to `DATA/stats.json` at start and on `SIGUSR1`, for the benchmarks.

### 13.15 S27: compressed objects in storage and on the wire

Built on `integration` @ `f7e9aac` (2026-11-07), as
`docs/design/server/storage-and-cost.md` §6 asks. Code:
`veil_core::hub::encoding`, `crates/veil-server/src/store.rs`
(`Objects`), the `history`, `fetch` and `objects` routes, and `vl`'s
client (`crates/vl/src/hub.rs`).

#### The design

* **An object's encoding** is how the server stores it and sends it. Its
  first byte says which:

  ```text
  'v' …          the canonical encoding itself (every object starts `veil:`);
                 every object stored before S27 is one, so they stay readable
  'z' ‖ frame    one zstd frame (level 3) of the canonical encoding, declaring its size
  ```

  **Object ids stay the BLAKE3 of the uncompressed canonical encoding**, so
  content addressing, deduplication, upload receipts and signatures don't
  change, and the storage key is the same (`p/<project>/ab/cdef…`).
* **The encoder keeps whichever is smaller** (`encoding::encode`). Secrets
  are ciphertext and don't shrink: they are stored and sent as they are.
  Objects are compressed **one at a time, never together**, and only after
  a secret is sealed on its device (never compress-then-encrypt).
* **The server's store** (`Objects`) writes the encoding, and keeps
  encodings in its object cache (so the cache holds more objects), each
  checked against its id when it was read from the store or received.
  `vl`'s fetch threads hand on answers as sent (compressed); the receiving
  thread checks the ids and decodes one answer at a time, on up to 8
  threads. Decoding on the fetch threads instead held 8 decoded answers at
  once and broke the 1 GB clone's 512 MiB gate (549–559 MiB).
  `get` returns the canonical encoding (the projection, push checks and
  older clients use it); `get_encoded` returns what is stored, for the wire.
  Every object the store answers is decoded, bounded, and re-hashed before
  it is cached or served, as before.
* **The wire.** An *encoded frame* is `id ‖ len u32be ‖ encoding`. A body of
  plain frames (S1's) is also a body of encoded frames.
  * `vl` sends `Accept: application/x-veil-encoded-frames` and reads every
    answer as encoded frames. The server answers `history` and `fetch` with
    each object **as stored** (no compression on the request path) to a
    caller that accepts them, and plain frames to anyone else. Projected
    trees made for one viewer are sent as they are.
  * **Uploads:** the server reads every upload as encoded frames (so a `vl`
    from before S27 still uploads), decodes and checks each, and **stores
    its own encoding** of what it decoded (`encoding::encode`), never the
    client's frame: no client chooses the stored bytes of an object others
    share (BUG-1008; an S3 PUT replaces what a key held). `vl` compresses
    each object as the push's walk finds it, within the ratio below
    (`encode_to_send`), and only for a server of **revision 2**
    (`Tips::revision`); to an older server it sends plain frames.
* **Compatibility, both ways.** An older `vl` sends no `Accept` and gets
  plain frames; its plain uploads are compressed by the server. A newer
  `vl` and an older server: the server ignores `Accept` and answers plain
  frames, which `vl` reads; `vl` uploads plain frames to it. Were encoded
  frames ever sent to an older server, it would refuse them (their bytes
  don't hash to their ids), never misread them.
* **Bounded decoding** (`encoding::decode`): a `z` frame must be exactly one
  zstd frame that declares its size (no trailing bytes, no second or
  skippable frame), that size must be at most the object size limit
  (`wire::MAX_FRAME_OBJECT`, as for a plain frame), and its window at most
  2^27 bytes (`MAX_WINDOW`: what every decoder reads, the web client's
  pure decoder included; libzstd's one-shot decoder does not check it,
  BUG-1008), before anything is decoded. The decoder never produces more than the declared size, objects
  above 64 MiB are hashed while streaming before they are held in memory
  (BUG-490's rule), and the result must hash to the id. An upload's objects
  together may decode to at most the request body limit (2 GiB).
* **What a client sends expands at most 64 times** (`encoding::within_ratio`;
  any frame decoding to at most 64 KiB may expand more): the server refuses
  anything else before decoding it, and `vl` sends such an object plain, so
  its size is the sender's to pay, as before S27. What the server stores
  is as small as it gets (no ratio). **Decoding in uploads holds a
  server-wide budget** of 256 MiB of decoded bytes at once
  (`sync::DECODING_IN_FLIGHT`, a semaphore by bytes; an object larger than
  that takes all of it), across every request (BUG-1009).
* **What it does not change:** the client's local store (pulled objects
  already go into zstd packs; loose objects stay as they are until
  `vl gc`), the repository format, and the per-object permission checks.

#### Measured (2026-11-07)

`scripts/bench-server.sh` with MinIO, release builds, before (`f7e9aac` plus
the byte counters) and after (S27), the bytes being what the server wrote
(`/proc/PID/io`: to MinIO during a push, to the client during a clone). The
machine was shared and often loaded (15–70); times are within noise or
better.

| | before | after |
|---|---:|---:|
| 1 GB profile: bytes stored, initial push | 2,462 MiB | **1,191 MiB (−52%)** |
| 1 GB: bytes sent, full clone | 2,352 MiB | **1,057 MiB (−55%)** |
| 1 GB: bytes sent, clone of one directory | 82.8 MiB | 42.2 MiB (−49%) |
| 1 GB: push / full clone | 286 s / 58.4 s | 272 s / 46.8 s |
| 1 GB: client peak, push / clone (gate 512 MiB) | 341 / 453 MiB | 319 / 448 MiB |
| 1 GB: server peak, push / clone | 2,550 / 2,958 MiB | 1,999 / 2,984 MiB |
| OpenScion 10k: bytes stored / sent by a clone | 46.0 / 41.9 MB | 27.2 / 23.1 MB (random hex: −41% / −45%) |
| OpenScion clone everything, 1k / 10k | 101.8 / 622.8 ms | 100.7 / 501.6 ms |
| load: server CPU per landing (1 / 10 / 100 projects) | 4.0 / 3.8 / 2.9 ms | 3.6 / 4.0 / 3.4 ms |
| load: database statements per landing | 34 | 34 |

#### Threat review

Attackers outside the trust boundary (§3.1): a participant uploading
crafted frames, a reader without access to a folder, a network observer
(TLS everywhere). The server and its object store are trusted with code.

| # | Threat | Defence | Test |
|---|---|---|---|
| 1 | **Zip bomb:** a small upload that expands past the object size limit, or a request that decodes to gigabytes | size declared, checked against the limit before decoding; the decoder stops at the declared size; per-request total ≤ the body limit | `encoding::tests::a_zip_bomb_is_refused_before_it_expands`, `server_hub::sync::hostile_compressed_uploads_are_refused` |
| 2 | **A frame that decodes to other content** than its id (to plant one object under another's id) | every decoded object is re-hashed against its id, on upload and on every read from the store | `decoding_refuses_wrong_ids_and_unknown_markers`, `hostile_compressed_uploads_are_refused`, `store::tests::objects_are_stored_compressed_and_old_ones_stay_readable` |
| 3 | **Malformed frames:** no declared size, trailing bytes or a second frame (hidden data riding along in storage), an unknown marker, truncation | refused; the whole request is refused, with no receipt | `malformed_frames_are_refused`, `hostile_compressed_uploads_are_refused` |
| 4 | **Compression as an oracle** (BREACH-style: a guess and hidden data compressed together) | each object is compressed alone; answers carry only objects the viewer may read at their path; projected trees hold only what the viewer may see | `compressed_answers_hold_nothing_the_viewer_may_not_see` |
| 5 | **Secrets**: plaintext compressed, or compressed before encryption | secrets are sealed on the device before upload; the server sees and stores ciphertext, kept as it is | `objects_are_compressed_in_storage_and_for_clients_that_read_them` (the `.env` is stored uncompressed), `leaks::…` (the server never holds the secret's plaintext, decoded) |
| 6 | **Mixed versions misread each other's frames** | negotiated (`Accept`, revision 2); a plain frame is an encoded frame; encoded frames sent to an older server fail its hash check | `objects_are_compressed_in_storage_and_for_clients_that_read_them`, `hub::tests::answers_of_plain_and_encoded_frames` |
| 7 | **Tests that scan the server's files** for leaked plaintext miss it once objects are compressed | the scan decodes object files first (`support::stored_bytes`) | `secrets2::…` |
| 8 | **A frame some reader can't decode** stored over another folder's object (a 2 GiB window: BUG-1008) | `decode` refuses windows above 2^27 on every path; the server stores only its own encoding | `encoding::tests::bug_1008_a_frame_every_decoder_reads_or_none`, `server_hub` `sync::bug_1008_…`, `sync::an_uploaded_frame_of_raw_blocks_round_trips_to_its_id` |
| 9 | **Small uploads that exhaust the server's memory** (4 KiB decoding to 128 MiB, many at once: BUG-1009) | at most 64:1 above 64 KiB, refused before decoding; 256 MiB decoded in flight server-wide; no copy of a blob for its check | `encoding::tests::what_is_sent_expands_at_most_the_ratio`, `sync::bug_1009_…`, `sync::compressed_uploads_decode_within_a_server_wide_bound` (16 × 48 MiB at once: +301 MiB, 821 MiB without the budget) |

**Left as it is (low, accepted):** a participant can still make the
server decode more than they send: up to 64 times a frame's size (or
64 KiB from a tiny frame), up to the 2 GiB a request may decode. It is
**bounded server-wide**: at most 256 MiB is decoded at once across every
request, so memory stays bounded however many requests arrive; the cost
left is CPU (zstd decodes at about 1 GB/s), which per-person rate limits
(later work, §4.7) bound.

#### Reverting

Revert the merge **only if no server ran it on real data**: an older
server cannot read objects stored compressed (they fail its hash check,
"stored object … does not match its id"). Once a server has stored
compressed objects:

1. **Stop writing them:** make `encoding::encode` return its input (one
   line). Every object the server writes is then plain, uploads included
   (an upload is always stored as the server's own encoding, never as the
   client's frame), and the server keeps reading both kinds. Clients may
   go on sending compressed frames: the server decodes them and stores
   them plain.
2. **To stop clients sending compressed frames too,** set `wire::REVISION`
   back to 1: `vl` then uploads plain frames (it still accepts compressed
   answers, which a server writing only plain objects no longer sends,
   except for objects already stored compressed).
3. **To run a server from before S27** on the same store, every object
   stored compressed must first be rewritten plain; no tool does that yet.
### 13.17 Person-to-person secret shares (phase 1)

**Goal** (owner, 2026-11-06): any member shares **their own** secret with
any other member, **without an admin**. It is wrapped (HPKE) to that
person's **confirmed** devices only, and only the sharer and the recipient
can open it. Admins see that a share exists, never what it holds.

```
vl secret share billing/.env.stripe-test --with bob    # seal a copy for bob's confirmed devices
vl secret share billing/.env.stripe-test --with bob --confirm 4F2A-…   # bob is in no key ring yet
vl secret shares                                        # mine (admins: every share), never contents
vl secret unshare billing/.env.stripe-test --from bob  # no later version reaches bob
```

#### Decisions (delegated to the orchestrator)

1. **What a secret is: one secret file.** A share is a copy of one file
   that is a secret by its name (`.env`, `.env.*`, `.envrc`, Terraform
   state) or that the project's policy seals, never code (code is shared
   with `vl access`) and never a personal key (`id_rsa` & co. never leave
   the device). Each version has its **own random key**, wrapped (HPKE,
   C3) to the recipient's confirmed devices and to the sharing device,
   and the file is sealed under it (C2): the share holds no key of the
   access line that covers the file, so sharing `billing/.env` with someone
   outside `billing/` gives them that file and nothing else of `billing/`
   (CRYPTO.md C14). The vault entries of `vl secret set` are not shared
   this way: a secret that people use together belongs in a file.
2. **Updates and revocation: run `vl secret share` again to send a new
   version; devices the recipient adds receive the current version
   automatically** (owner's delegate, 2026-11-07, review cycle 3). A new
   content is sealed only by that explicit command ("send what I have
   now"): an edit of the file sends nothing, so no checkout, workspace,
   rewrite or concurrent pass can ever send an older or another value
   (BUG-1064, BUG-1065). The **clone that ran `vl secret share`** keeps
   only the shares it records itself (`.veil/local/secret-shares.json`: the
   share's id and the last version it sealed), never the server's listing
   (BUG-1060, BUG-1063). After any `vl` command there (the background pass
   of §13.12, at most every 10 s) it seals **the same content** again when
   the recipient's confirmed devices changed (a new one is added; one no
   longer confirmed is left out of every later version), taking it from its
   own signed last version (the sharing device is sealed for it), never
   from the working copy. Running `vl secret share` in another clone makes
   that one the source (the first sees the version move on and stops).
   Every change of the record is made under its lock, re-read and applied
   only for that command, never bringing back an entry another command
   removed, nor an older version (BUG-1066). `vl secret unshare` **ends**
   the share: the clone forgets it first, then the server stores or serves
   no later version. **It cannot take back what the recipient already
   received** (the command says so, and suggests rotating the secret). A
   share the server lists as ended, paused or shared again elsewhere is
   forgotten by the clone too: only a new `vl secret share` starts it again.
3. **Device confirmation, as S2 requires.** The sharing device seals only
   for devices confirmed outside the server, with the same rules an admin's
   `vl group add` uses (§13.11; `hub_keys::person_devices`): a device a
   verified ring of this project records under the person's name, one the
   sharer compared by fingerprint (`--confirm`, remembered on the device),
   one with a join under an invite for the person, or one vouched for by one
   of these; a device a ring once held and revoked counts only if a ring
   holds it now or the sharer compares it again. The server's device list
   is never enough. Listed devices nothing confirms are printed with their
   fingerprints (`confirm bob's device: …`).
4. **The admins' audit.** In plain text on the server, never contents:
   who shares which path with whom, when it started, when it last changed,
   when it ended, and its version. `vl secret shares` lists them (admins:
   every share of the project; others: the shares they make or receive);
   ended shares keep their row, without the record. Each share and unshare
   is also in the server's audit log.
5. **Agents.** The recipient's `vl pull` (and `vl secret shares`, and the
   background pass once the clone took part in a share) writes the file at
   its path, where it **stays on their device**: an isolated file, never
   recorded, backed up in the local vault like any local-only secret. Their
   agents get it as they get the person's other secrets, with `vl ws exec
   --with-isolated`. A copy is written only if nothing at all is at the
   path, or a regular file holding exactly the version this clone wrote
   before (the person's own edit, link, folder or special file, and a file
   that cannot be read, are never written over: BUG-1062), and only where
   this device would **not** record it: a device that holds the key of the
   file's folder (an admin's, say) would seal it into history for everyone
   in that folder, so the copy is not written there and the command says
   why. The same check runs before every snapshot: a copy this device would
   now record (it gained the folder's key since) is moved to
   `.veil/local/secret-shares-held/` instead, under a new name each time
   (never over a copy held before), and the path is then no longer
   "received": a file the person puts there later is theirs to record
   (BUG-1067). A one-directory clone
   (`--only`) writes nothing outside its directory. A version is refused if
   it is older than the newest genuine one this clone saw, written or not.
6. **Format and wire.** No repository format change (format 8) and no new
   ring kind: shares are server records, not ring changes. New: the signed
   share record (`veil_core::secret_share`, record format 1, FORMAT.md), the
   routes below, migration `0009_secret_shares` (the shares and a quota
   row per person and project), and the device-local
   `.veil/local/secret-shares.json` (the shares this clone made, and what it
   received; changed under `.veil/local/secret-shares.lock`).

#### The server

* `GET /v1/projects/{p}/shares`: participants only. Admins get every
  share's metadata; others the shares they make or receive. The record
  (ciphertext) goes only to its sharer and its recipient, and only while the
  share is **active**: not ended, the sharer may still read its path, and the
  recipient still takes part in the project. Otherwise it is listed as
  paused, with why (`fin may no longer read billing/.env`; `bob no longer
  takes part in this project`). It is served again if that changes, until
  it is ended; its sharing clone, which forgot it when it saw it paused,
  seals it for no new device until its person shares it again.
* `POST /v1/projects/{p}/shares` (`SharePut {expect, reshare, record}`):
  the record must verify, be signed by the device sending it under its
  person's name, be of a path the caller may read that the accepted policy
  seals (never a personal key), be for another participant, and carry
  version `expect + 1`. One statement with a compare-and-swap on the
  version; a background update (`reshare: false`) never brings back an
  ended share; at most 256 shares per person and project, reserved on a
  quota row in the transaction that inserts, so requests sent together
  never pass it (BUG-1061).
* `POST /v1/projects/{p}/shares/remove`: the sharer ends a share (its
  version moves on, its record is dropped, its row stays for the audit).
  Ending an ended share again changes nothing.

#### Threat review

The attacker is **whoever controls the server** (outside the boundary for
secrets, §3.1), unless a row says otherwise. Tests: `server_hub` `shares`,
`veil-core` `secret_share`.

| # | Tries | Result | Test |
|---|---|---|---|
| 1 | **Reads a share** (the database, the object store, the routes) | Ciphertext only: the version key is wrapped to devices' X25519 keys; the server holds none | `a_share_reaches_its_recipient_only` (the row holds no marker, in text or hex) |
| 2 | **Lists its own device under the recipient**, with a vouch it signed | Not confirmed (§13.11): not sealed for, and shown as `confirm bob's device: <its fingerprint>`; bob reads a different one, so a `--confirm` of it fails and shares nothing | `a_server_cannot_redirect_a_share_to_its_device` |
| 3 | **Moves another person's device under the recipient's name** | Rings record it under its real name: not confirmed for the recipient | same |
| 4 | **The recipient is in no ring** | Nothing confirms a device of theirs: the share is refused until the sharer compares a fingerprint (`--confirm`) | same |
| 5 | **Adds a wrap, swaps the sealed file, changes the path, recipient, sharer, version or project** of a stored record | The signature fails, or the labels (share id, version) do not match: refused, nothing written | `a_server_cannot_forge_change_replay_or_move_a_share`, `secret_share::tests` |
| 6 | **Signs a record of its own** in the sharer's name (hostile content into the recipient's tree) | Its key is no current ring member named as the sharer: refused | same |
| 7 | **Replays an older version** | The recipient's device refuses a version older than the last it received | same |
| 8 | **Serves a genuine record of another project** (the sharer shares the same path there) | The record names its project; the recipient compares it with the project it anchored (BUG-845) | same |
| 9 | **Moves a share to another path or recipient** (its own row) | The record's path and recipient are signed; the other recipient cannot open it either | same |
| 10 | **Lists a removed device again**, with its genuine old vouch | Rings revoked it: it counts only through a ring holding it now or a new `--confirm`; every later version leaves it out | `removed_devices_people_and_access` |
| 11 | **Withholds a new version**, or a revocation, from the sharing device | The recipient keeps an older version (freshness is TOFU, as for rings, §13.12); a device the sharer's rings still hold stays sealed for until they are fresh | residual |
| 12 | **Races an update against an unshare** | Compare-and-swap on the version; an unshare moves it on, and an update never revives an ended share | `concurrency_share_updates_and_unshares_under_load`, `the_share_routes_refuse_what_may_not_be_shared` |
| 12a | **Forgets an unshare**: lists the last genuine record as active again, then the sharer rotates the secret (BUG-1060) | The sharing clone forgot the share when it unshared it; its pass updates only shares it records | `bug_1060_an_unshare_the_server_forgets_never_seals_a_later_version` |
| 12b | *Another clone on the sharing device* (an older checkout, an agent's) seals its own copy (BUG-1063); a workspace switch or an earlier version of a change brings an older value back (BUG-1064, BUG-1065) | Only the clone that ran `vl secret share` touches it, and its pass never sends a new content: only the same one, again, for new devices | `bug_1063_another_clone_on_the_sharing_device_never_rolls_the_share_back`, `bug_1064_switching_the_directory_to_an_older_workspace_never_rolls_the_share_back`, `bug_1065_an_earlier_version_of_the_same_change_is_an_older_revision`, `content_updates_are_explicit` |
| 12d | **Delays its answer to a pass** until the sharer unshared, so the pass writes back the record it read before (BUG-1066) | Every change of the record is made under its lock and re-read there; a pass never re-inserts an entry another command removed | `bug_1066_a_pass_in_flight_never_brings_back_an_unshare`, `concurrency_the_share_record_under_concurrent_commands` |
| 12c | *A member* sends many new shares at once (BUG-1061) | The limit is reserved on a quota row in the inserting transaction | `bug_1061_concurrent_new_shares_never_pass_the_limit` |
| 13 | *A member without the folder* shares its secret, or anyone shares code or a personal key | Refused by the route (the caller's access to the path; the accepted policy); the client refuses first | `the_share_routes_refuse_what_may_not_be_shared` |
| 14 | *A member* shares to a device that is not the person's (by `--confirm`) | Trusted: they hold the file and could leak it anyway (§3.1) | — |
| 15 | *A sharer who loses the folder* keeps updating | Their updates are refused and the share is no longer served (paused) | `removed_devices_people_and_access` |
| 16 | *A recipient who leaves the project* | Not served; no update is sealed for them while they are out | same |
| 17 | *An admin's device* receives a share of a file its folder does not have | Not written: that device would seal it into history for the folder's people | `a_share_reaches_its_recipient_only` |
| 18 | *The recipient's own edit* of the received file, or a link, folder, FIFO or unreadable file at its path (BUG-1062) | Never written over; a later version waits until they remove theirs | `updates_and_unsharing`, `bug_1062_a_share_never_replaces_the_recipients_symlink` |
| 18a | **Serves an older genuine version** after the recipient removed their copy | Refused: older than the newest version the clone saw, written or not | `a_version_seen_but_not_written_still_refuses_older_ones` |
| 18b | *The recipient's device gains the folder's key* after receiving a copy | Before any snapshot, the copy moves to `.veil/local/secret-shares-held/` (a new name each time) instead of being sealed for the folder's people; the path is then the person's again (BUG-1067) | `a_received_copy_is_never_recorded_after_the_device_gains_the_key`, `bug_1067_holding_back_a_received_copy_never_loses_what_it_held` |
| 19 | **Hostile input**: paths with `..`, huge records, many devices, many shares, malformed bodies, no session | Refused (400, 422, 401), never stored; at most 64 KiB, 64 devices, 256 shares per person and project | `the_share_routes_refuse_what_may_not_be_shared` |

**Residual risks** (recorded, not closed here):
* **An unshare from another device of the sharer's** reaches the sharing
  clone only through the server (it then forgets the share); a compromised
  server that hides it keeps that clone updating the share. Unshare from
  the clone that shared it.
* **A recipient who leaves the project** is known to the sharing clone only
  from the server's listing; if no key ring records their devices (they
  were confirmed by `--confirm`), a compromised server that hides the
  departure keeps them sealed for. Unshare when someone leaves.
* **What was received stays received.** An unshare, a removed device or a
  person leaving stops later versions only; rotate the secret.
* **Freshness** (row 11), as for rings.
* **The recipient learns the path's name** (a file of a folder they may not
  see): the sharer chose to give them that file.
* **A sharer's insider choices** (row 14), and what the file holds: a
  shared `.envrc` is a shell script that direnv runs once the person allows
  it. A share never writes over an existing file.


### 13.16 S5: read grants, the object routes, access epochs (built)

Design: `docs/design/server/phase-2-thin-clients.md` §4.3–§4.5, §5.1. Code:
`veil_core::hub::grant` (the grant, request signatures and the chain
check: pure, WASM-safe, for the server, the Veil daemon (S6) and regional
caches (S9)), `crates/veil-server/src/grant.rs` (issuing, the routes, the
feed); the access epochs are S4's (§13.14, `migrations/0006_access_epochs.sql`). Nothing new is encrypted:
grants are **signed**.

* **The grant.** `GET …/tips` (revision 3) returns, per branch, a grant
  and the server's grant key (`Tips::grants`, `Tips::grant_key`). A grant
  is `hex(JSON body) . hex(signature)`: Ed25519 by the server's **grant
  key** (`<data>/hub-grant-key`, an Ed25519 seed, 0600; servers sharing the
  data directory share it), context `hub-grant`, over the body bytes as
  sent (verified before they are parsed; never re-encoded). The body is
  `{project, device, root, epoch, person_epoch, expires}`: the project's
  name, the caller's device's Ed25519 key, their projected root tree of
  the tip, the access epochs of the project and of the person, and an
  expiry 10 minutes on. **No database id:** project and person ids are
  sequential and would count the server's projects and people
  (BUG-1088); checking a grant looks the project up by name and the
  person by the device's key, with both epochs, in one statement. It holds nothing its holder could not see
  otherwise: **no view key** (an unkeyed hash of every access line, hidden
  ones included, would confirm guesses of hidden folder names: BUG-1080),
  and epochs that are opaque. Unknown
  fields are refused, so a layer that does not know a later restriction
  refuses the grant instead of ignoring it. Anyone on Earth's grant names
  no person and no device.
* **Projected trees are stored.** The trees a projection rewrites existed
  only in memory in S1. Issuing a grant stores them, so a chain through
  them can be checked from the store alone, by any layer. They hold only
  what their viewer reads, and no route serves an object by id without a
  path or chain check.
* **Requests.** `GET /v1/objects/{p}/{id}` with headers `Veil-Grant`,
  `Veil-Chain` (the tree ids from the grant's root to the tree naming the
  object, comma-separated; empty for the root) and `Veil-Signature`
  (`<unix ms>.<signature>`), `Range` supported; `POST
  /v1/objects/{p}:batch {grant, ts, signature, wants: [{chain, id}]}`
  answers object frames of what it serves and leaves the rest out. The
  device signs `grant hash ‖ ts ‖ BLAKE3(ids)` (context `hub-request`,
  72 bytes); the server accepts `ts` within ±5 minutes. A copied grant is
  useless without the device key.
* **Checks, in order:** the grant's signature, its project (the route's),
  its expiry, the request's signature, then the project by name, the
  device (still active) and the current epochs of the project and of the
  device's person (one statement; both must be equal to the grant's): any
  failure is `401
  grant_invalid`, which says nothing about any object. Then each object's
  chain (`Chains::allows`): `chain[0]` is the grant's root, each tree has
  a directory entry naming the next, and the last tree has an entry whose
  object is the id (or the last element is a conflict object
  named by a conflict entry, and the id is one of its terms: S1's `fetch`
  serves the same). The check reads only objects it already reached from
  the root, and an object is read only after its own check, so "not
  reachable" and "not there" are the same `404` (the same body), and in a
  batch both are left out; a batch sends each id once. Every object,
  trees included, is read through `store::Objects`, one at a time
  (`grant::read`, and `Objects::get_range` for a `Range`), and decoded
  from S27's encoding (§13.15) and checked against its id: when small
  objects move into packs (S28), only those change, and a pack is never
  handed out.
* **`Range`** answers bytes of the object, never of what is stored. An
  object stored as it is (S27's plain encoding) is read for those bytes
  only (`BlobStore::get_range`: a file's seek, an S3 ranged `GET`, an open
  range sent open; past the end, 416 with the length, from a `HEAD` on S3:
  BUG-1086). A compressed one is decoded whole, its decoded bytes counted
  in the server-wide budget below, then sliced.
* **Read-ahead is bounded by sizes the server can trust** (BUG-1087), in
  the batch route and in S1's `fetch` alike: at most 64 objects and about
  8 MiB ahead of what a request has sent, and, across every request,
  `store::DECODED_IN_FLIGHT` (256 MiB, the budget S27's uploads decode
  under). An object's cost is the size its entry or conflict term records
  plus 4 KiB (`store::SIZE_SLACK`): **a push or an API commit whose entry
  records less than its object holds is refused** (`sync::check_changes`,
  which reads every new object for the secret checks anyway; an API
  commit records a sealed secret's stored length). An object that records
  no size (a tree, a conflict) costs what its encoding declares: S27's
  frames declare their size in their first bytes, read from the cache or
  the store. A read waits for the budget only when its request holds none
  of it, so requests never wait on each other in a cycle; an id asked for
  more than once is read once.
  **An error making a grant** (the store failing to read or write the
  projected trees) is logged, and that branch gets no grant: the tips and
  every pull still answer (BUG-1083).
* **Access epochs** are S4's (§13.14): each project and each person has
  an epoch, a random value that database triggers replace at every access
  change, in the transaction of the change itself; there is no
  server-wide row. A grant carries the two epochs its view was built
  under (`perm::open_at`): random values compared only for equality, they
  show neither a count, a time nor a rate of changes (BUG-1081). The
  server reads the current epochs on every object request and refuses a
  grant with others: a change committed after the view was built voids
  it, and one committed before is in the view. **Revocation at the server is at the next request**
  (tested: group removal or deletion, a policy change, a name rebound to a
  new group, a device removed or barred, and a grant racing a removal).
* **The feed.** `GET /v1/epochs?projects=a,b` needs a session: it answers
  `{person, projects: {name: epoch}}`, the caller's own person epoch and
  the current epoch of each named project the caller can see; a project
  they cannot see is left out exactly as one that does not exist. Every
  key asked for gets its current epoch, read from S4's table of each key's
  current one (no paging and no log, so no change is passed over:
  BUG-1082). The Veil daemon (S6) polls it for its people and
  projects, and refuses a grant whose epochs are not those; a project
  left out voids the caller's grants of it. Regional caches (S9) will
  authenticate as the server's own.

**Threat review** (design §6 rows 1–4, 14, 15, plus this milestone's):

| # | Attacker | Tries | Result | Test (`server_hub::grants`) |
|---|---|---|---|---|
| 1 | Person without access to a folder | asks for every real object id (the admin's), with their own grant and every chain they can build: their own trees, the admin's real chain, the admin's chain from their root, the admin's root | nothing served; one at a time, the same `404` as a random id | `object_routes_serve_only_what_a_grant_reaches` (5 viewers, anyone on Earth included) |
| 2 | Same | a real grant with a chain through another snapshot's or the admin's trees | the chain must start at the grant's root, each step read from the store | same, and the unit test `chains_reach_only_what_the_root_reaches` (which also checks that only reached objects are read) |
| 3 | Anyone holding a copy of a grant | uses it from another device, unsigned, with a signature over other ids, six minutes old, an hour ahead | `grant_invalid` | `grants_hold_only_for_their_device_project_key_and_time` |
| 4 | Person removed from a group; a project whose policy changed; a device an admin removed | keeps using a grant | refused at the next request; the feed lists the change | `access_changes_void_grants_at_the_next_request` |
| 5 | Person without access | asks for a secret's ciphertext (`billing/.env`) | served only to those who read the folder | test 1 |
| 6 | Same | an object at a visible and a hidden path | served through the visible chain only (the same bytes); refused through the hidden one | test 1 |
| 7 | Anyone | a grant re-signed by the server's identity key, a body changed under its signature (a wider root), a grant for another project's URL, an expired one, one older than the project's epoch | `grant_invalid` | test 3 |
| 8 | Anyone | malformed grants (non-hex, 10 KB), chains of `MAX_CHAIN + 5`, non-hex chains and signatures, more than `MAX_WANTS` wants, bad routes, bad JSON, a `Range` past the end or on a hidden object | refused cleanly (400/401/404/416); a hidden object's `Range` is the same 404 | test 3 |
| 9 | Person without access | times answers | the grant is checked before any object, and only checked objects are looked up (the batch prefetches after the check) | by construction; residual as design row 14 |
| 10 | Anyone holding a grant (anyone on Earth, for a project with something public) | tests guesses of the hidden access lines offline against a value it carries | no value a client receives (tips, grants, epochs, errors) is a view key | `bug_1080_…` (BUG-1080) |
| 11 | Anyone on Earth; a signed-in person outside a project | reads the epoch feed, or counts epochs across grants | the feed needs a session and answers only for the caller and projects they see; epochs are random per key | `bug_1081_…` (BUG-1081) |
| 12 | — (a cache falling behind) | reads the feed after many changes, one key changing twice | every key's current epoch | `bug_1082_…` (BUG-1082) |
| 13 | — (an outage) | the store refuses writes | tips still answer; the branch has no grant | `bug_1083_…` (BUG-1083) |

**Residual:** someone who holds grants of a project at two times learns
whether its access (or their own) changed in between, not how often. A
signed request can be replayed within ±5 minutes
by whoever saw it (inside TLS: a cache, which is inside the boundary); it
returns the same objects. Grants are made per branch at every tips request
(one signature each). Not built (later milestones): `POST …/grants` for
older snapshots, the Veil daemon, `vl` reading through these routes (S3,
S6). Regional caches: S9, §13.18.

### 13.18 S9: the regional cache (built)

Design: `docs/design/server/phase-2-thin-clients.md` §4.1–§4.4, the S9 row
of §9, and product decision 1 (removal at caches takes about 2 s, at most
5). Code: `crates/veil-server/src/cache/` (`mod.rs` the routes and the
decision, `epochs.rs` what the cache knows of access epochs, `disk.rs` its
store, `relay.rs` passing the server's answers on, `feed.rs` the server's
side); `veil-server cache` in `main.rs`. Touched elsewhere, minimally:
`api.rs` (one route), `lib.rs` (the caches' token, `serve_tls` shared),
`grant.rs` (`skip`, and its header parsers shared), and
`veil_core::hub::grant::BatchRequest` (`skip`).

```text
veil-server cache --upstream https://hub:8443 --token-file TOKEN --dir DIR
                  [--listen 127.0.0.1:8444] [--size 10G] [--memory 128M]
                  [--max-connections 1024] [--upstream-ca PEM] [--tls-cert C --tls-key K]
```

* **What it answers.** S5's object routes only, as the server answers
  them: `GET /v1/objects/{p}/{id}` (with `Range`) and `POST
  /v1/objects/{p}:batch`, the same headers, bodies, statuses and order.
  Tips, grants, history, pushes and every other route go to the server; a
  cache never says what `main` is. It holds **no database, no session, no
  key and no permission authority**: only objects, the server's grant key
  (public) and the caches' token.
* **When it serves from its store** (in this order, nothing looked up
  before its turn): the grant verifies under the server's grant key, for
  this project, not expired; the request is signed by the grant's device
  (§13.16); the grant's project epoch and its device's person epoch were
  confirmed current by the server at most 5 s ago; the want's chain starts
  at the grant's root and each step is an entry of a tree in the store
  (`veil_core::hub::grant::Chains`, the server's own check), and only then
  is the object looked up. An invalid grant or signature is `401
  grant_invalid`, and a chain the root does not reach is `404` or left out
  of a batch, as at the server; both are final, since trees are addressed
  by their content and the cache reads only those it reached. **Everything
  else goes to the server, with the client's own signed request:** the
  grant key not known yet, epochs not confirmed (a first request, a stale
  feed, an epoch other than the grant's), a tree of the chain or the object
  not in the store. A batch is forwarded once, with `skip` naming the
  objects the cache sends itself (unsigned: it only makes the answer
  smaller; optional, so no protocol revision: a server that does not know
  it sends everything, and the cache drops what it already sent), and the
  answer merges both in the request's order. An id wanted again after a
  want only the server can decide sends the whole batch to the server,
  answered unchanged, since where the server places it depends on which of
  its wants the server allows (BUG-1182). What the
  server sends is kept (whole objects of at most 16 MiB, each checked
  against its id). A refusal from the server is passed on as it is; a
  server the cache cannot reach is `503 unavailable`. **Concurrent misses are
  coalesced:** a request fetching objects whose chain checked and that the
  store keeps (at most 16 MiB) marks them in flight (at most 256 a request,
  65,536 in all), and a later request needing one of them waits for that
  fetch (at most 2 s), then decides again from the store, so every agent
  reading a new tree after a landing costs the server one request (tested:
  24 readers at once, 1 request). A mark is let go once its object is kept,
  all of them once the server's answer has passed, and all of them before
  the request waits for the budget, or for its client past 100 ms: a client
  that stalls holds none for longer (BUG-1180). A local object lost
  between the check and the read (evicted, damaged) is left out of a batch
  (the client asks again; the cache, which removed it, then asks the
  server).
* **Access epochs: the feed for caches.** `POST /v1/cache/epochs {projects,
  devices}` (`feed.rs`), with the header `Veil-Cache-Token`, answers the
  grant key, each named project's epoch and each named device's person
  epoch, and leaves out a project that does not exist and a device that is
  removed or pending (both void their grants), the same values
  `Grants::current` reads for the server's own check, in two statements.
  **Only the server's caches may ask:** the token is `<data>/hub-cache-token`
  (32 random bytes, 0600, made at the first start; servers sharing a data
  directory share it), compared by hash; a session, even an admin's, is
  refused, since epochs tell who had an access change (BUG-1081). The cache
  polls it every second for every project and device a grant named in the
  last 15 minutes (a grant's life and the request skew; at most 100,000 of
  each, 50,000 keys a request), and at once (within 50 ms) when a grant
  names a new one.
* **Removal within the bound.** A key's confirmation is the time its poll
  was *sent*, so an access change committed at time R is in every poll sent
  after R: the cache serves under a grant it voided only until R + 5 s at
  the latest, and in practice within one poll (tested: a person removed from
  a group, a policy that stopped `src/` being public, a device an admin
  removed; refused at the cache 26–232 ms after the change returned, the
  bound asserted). **Without the feed it fails closed:** 5 s after its last
  answer nothing is served from the store, public objects included (a
  policy change can make a public folder private), and every request goes
  to the server (or gets `503`); it serves again at the next answer.
* **The store** (`disk.rs`): objects as the server sends them (canonical
  encodings; secret files stay ciphertext), keyed by a hash of the
  project's name and the id (so projects never share an entry, and the
  directory names no project), least recently used out first within
  `--size` bytes and an entry count from `--memory`. Every object is checked
  against its id when written and each time it is read: one that does not
  match is removed and read as absent. A restart keeps the store.
* **Memory** (`--memory`, default 128 MiB): a quarter for decoded trees, a
  quarter for the store's index (128 bytes an object), an eighth (at least
  12 MiB) for batch requests and three eighths for answers. **Answers**
  (BUG-1181): every chunk of every answer (from the store, passed on from
  the server, an error) and every object being kept takes its share of the
  budget, and the share travels inside the bytes handed to the connection
  (`Bytes::from_owner`), given back only once they are written. Answers go
  out in 64 KiB slices, **each with its own share**, and an object of the
  store larger than a slice is read a slice at a time, its hash checked as
  the slices go and its last slice sent only once the whole matched (one
  that does not is removed and its answer ends unfinished, an error to the
  client, never a whole answer with wrong bytes), so a slow client holds a
  slice or two of the budget whatever the object's size (BUG-1186). **No
  answer waits for the budget while holding any of it** (BUG-1185): it
  sends what it gathered first, and gives up keeping an object it is
  collecting (its bytes and share: it is then not kept, and nobody waits
  for it) before it waits, and before it waits for its client past 100 ms,
  so every share taken is free or on its way to a client, answers never
  wait on each other, and a slow client never holds an object's share; a
  `GET` from the store sends its head at once and its bytes once their
  shares are free. **Batch
  requests** (BUG-1184): a body is read only under a share of the
  requests' pool, three times its length (the parsed request, the copy sent
  to the server, the answer's plan), taken in one step before reading for
  the length it declares (a body of unknown length starts with a slice's
  share and grows it only while it is free), and held until its answer
  ends. The pool is always taken before the answers' budget, never while
  holding it. The cache decides bodies of at most 4 MiB (about 20,000 wants
  two folders deep); a larger body, or one whose share is not free, goes to
  the server as it arrives, a chunk at a time, and the server's answer is
  passed on as it is (its own 64 MiB limit and checks apply), so the cache
  never holds it and its answers stay the server's at any size. **Outside
  `--memory`, per connection, by its buffers' limits:** to the client, TLS
  records being received (one record of 16 KiB being assembled, and up to
  32 KiB decrypted ahead: 50 KiB), TLS records to send (one record, 16 KiB:
  the cache sets rustls's 64 KiB default down) and the HTTP read buffer
  (64 KiB; the HTTP write side holds only slices under the budget: HTTP/1.1
  only, since HTTP/2 keeps a send buffer per stream), about 130 KiB; to the
  server, for an answer passed on, its TLS records received (50 KiB) and its
  HTTP read buffer, which holds the chunk the answer is waiting to send
  (records arrive at most two per read, so it stays within 64 KiB, and
  128 KiB while a chunk is out), or, for a body passed on as it arrives,
  two chunks of it (64 KiB each) and the TLS records to send (80 KiB):
  about 220 KiB. **So a connection holds at most about 352 KiB beyond
  `--memory`,** and at most `--max-connections` (default 1,024) are open,
  the next waiting in the listener's queue: **the cache holds at most
  `--memory` + 352 KiB × `--max-connections`, about 480 MiB with the
  defaults,** besides its fixed costs and the kernel's socket buffers
  (measured: 192 clients stalled on cold answers grow it by 6 MiB, about
  32 KiB each, since the kernel's buffers take most of each answer; 8
  bodies of 56 MiB that stop before their end, by 9 MiB).
* **Every connection slot comes back in bounded time** (BUG-1183): a TLS
  handshake within 20 s, a request's head within 20 s (and an idle
  keep-alive connection is closed after 20 s), and its body due at an
  average of 16 KiB/s (128 kbit/s, a slow mobile link) after a 20 s grace,
  checked before each read, so a body of `n` bytes takes at most 20 s +
  `n` / 16 KiB/s (at most 4 min 36 s for the largest the cache decides,
  68 min for the server's 64 MiB limit), else `408` and the connection is
  closed. The answer: a write pending for 30 s closes the connection, and
  so does one that would bring the time its writes have waited, over the
  connection, past 30 s plus a second per 16 KiB written, so a client
  reading at 16 KiB/s or faster is never cut off, and an answer of `n` bytes
  holds its slot (and its shares) for at most 30 s + `n` / 16 KiB/s of a
  slow client's reading, besides waits for the budget, which are bounded
  by the same limits on the answers holding it.
* **Only `https://` upstreams:** the caches' token and the grant key never
  cross the network in clear; any other `--upstream` is refused at start.
* **Counters:** `SIGUSR1` writes `DIR/stats.json` (requests, objects from
  the store and from the server, refusals, requests forwarded and why,
  polls), for `veil-bench load --mode objects --via server,cache`
  (`scripts/bench-server.sh cache`).

**Measured** (`scripts/bench-server.sh cache` on `s9-cycle3`, after cycle
3's fixes, release builds, the cache at its defaults, `--memory 128M` and
1,024 connections; the server, the cache, PostgreSQL, MinIO and the agents
on one 32-thread machine; load 14.8 at the start, 71 at the end, so
throughputs are noisy). A read is a fresh thin workspace's: the tips, then
the root, `w/`, `w/seed/` and 100 of its 4 KiB files (103 objects, 4
requests), signed:

| `main` | Agents | Via | Reads/s | p50 / p99 (ms) | Server CPU per read | Cache hits | Cache requests to the server per read | Cache CPU per read | Cache peak |
|---|---:|---|---:|---|---:|---:|---:|---:|---:|
| still | 10 | server | 2,564 | 3.8 / 5.7 | 2.52 ms | | | | |
| still | 10 | cache | 2,513 | 3.9 / 5.7 | 0.19 ms | 100 % | 0.00 | 2.50 ms | 39 MiB |
| still | 100 | server | 4,570 | 21.4 / 34.0 | 2.48 ms | | | | |
| still | 100 | cache | 3,818 | 25.5 / 43.3 | 0.19 ms | 100 % | 0.00 | 2.94 ms | 98 MiB |
| still | 1,000 | server | 3,693 | 263 / 439 | 2.53 ms | | | | |
| still | 1,000 | cache | 4,062 | 241 / 400 | 0.20 ms | 100 % | 0.00 | 3.13 ms | 185 MiB |
| 20 landings/s | 10 | server | 2,334 | 4.2 / 6.7 | 2.66 ms | | | | |
| 20 landings/s | 10 | cache | 2,605 | 3.7 / 6.4 | 0.22 ms | 99.99 % | 0.02 | 2.44 ms | 36 MiB |
| 20 landings/s | 100 | server | 3,674 | 24.0 / 125 | 2.54 ms | | | | |
| 20 landings/s | 100 | cache | 4,389 | 22.3 / 34.3 | 0.22 ms | 99.99 % | 0.01 | 3.02 ms | 100 MiB |
| 20 landings/s | 1,000 | server | 3,686 | 265 / 481 | 2.53 ms | | | | |
| 20 landings/s | 1,000 | cache | 3,837 | 254 / 454 | 0.24 ms | 99.98 % | 0.02 | 3.16 ms | 179 MiB |

Gates met: at least 99 % of objects from the cache's store, its peak at
most 512 MiB (the defaults' bound is about 480 MiB; before cycle 3, at
`--memory 256M`, 221–281 MiB at 1,000 agents). The server's CPU per read
falls about 11× (it answers the tips only); the cache spends about what the
server did. Neither the slices with a share each, the smaller pools nor
the time limits cost throughput measurable here (cycle 2, at `9b66cff`:
3,814–4,555 reads/s at 100 and 1,000 agents, as noisy; a run of this branch
before BUG-1186's fix: 4,388–5,035). On one machine the cache competes with
the server for the same cores, so throughput and latency through it are not
a regional win; what it removes is the server's work. Coalescing keeps
requests to the server at 0.02 per read while `main` moves 20 times a
second.

**Threat review** (design §6 rows 1–4, 8, 9, 14, 15, 17, plus this
milestone's):

| # | Attacker | Tries | Result | Test (`server_hub::cache`) |
|---|---|---|---|---|
| 1 | Person without access to a folder | asks the cache, which holds every object of the project (the admin read them through it), for every real object id with every chain they can build: their trees, the admin's chain, the admin's chain from their root, the admin's root | nothing served; one at a time the server's own `404`; no request answered from the store | `the_cache_serves_only_what_a_grant_reaches` (5 viewers, anyone on Earth included, cold and warm) |
| 2 | Same | a real grant with a chain through another snapshot's or the admin's trees | refused: chains start at the grant's root, each step from the hash-checked store | same |
| 3 | Anyone holding a copy of a grant | uses it at the cache unsigned, from another device, over other ids, 6 minutes old, re-signed by the server's identity key, with a wider root, expired | `grant_invalid`, the object in the store untouched | `grants_at_the_cache_hold_only_for_their_device_and_time` |
| 4 | A person removed from a group; a project whose policy changed; a device an admin removed | keeps using a grant at the cache, which holds the objects | refused within 5 s (measured 26–232 ms), and never served again | `a_removed_person_is_refused_at_the_cache_within_the_bound` |
| 5 | Same, with the feed cut (a partition, a dead server) | keeps using a grant | 5 s after the last answer nothing from the store, public included; `503`; served again once the feed is back | `the_cache_fails_closed_without_the_feed` |
| 6 | A local process, a torn write | changes bytes in the store | the object fails its id check, is removed, and comes from the server; never wrong bytes; a large one read in slices ends its answer unfinished (`GET`, a range, a batch) | `a_damaged_object_in_the_cache_is_never_served`, `s9_cycle2::a_large_damaged_object_ends_its_answer_unfinished`; unit tests in `disk.rs` |
| 7 | Anyone | a grant of one project at another project's URL | `grant_invalid`; entries are per project | test 1 |
| 8 | Anyone on Earth; a signed-in person, an admin | reads the feed for caches (no token, a wrong one, a session) | `401`, naming nothing | `the_epoch_feed_for_caches_needs_the_caches_token` |
| 9 | Hostile input | malformed grants (non-hex, 10 KB), chains of `MAX_CHAIN + 5`, non-hex chains and signatures, more than `MAX_WANTS` wants, bad JSON, routes the cache does not serve, a `Range` past the end or on a hidden object; a feed request with 50,001 keys, unknown fields, wrong types | refused cleanly (400/401/404/416), as at the server | tests 3 and 8 |
| 10 | — (a cache that loses an object) | an object evicted or damaged between check and read | left out of a batch; the client asks again and the server sends it | `the_cache_store_keeps_to_its_size` (a 64 KiB store under 200 files of 4 KiB) |
| 11 | A compromised regional cache | reads what it stores, serves it to anyone | plain-text code, as the server holds it (inside its boundary, design §4.1; `ARCHITECTURE.md` "Threat model"): as trusted as the object store; secret files only as ciphertext; it cannot sign a grant | the store holds no plaintext of `billing/.env` (test 1) |
| 12 | — (load) | every agent reads a new tree after a landing | one request to the server per object, not one per reader | `concurrent_readers_of_a_new_object_cost_the_server_one_request` |
| 13 | Anyone on Earth | stalls many answers (a 15 MiB public object, 16 clients that never read); opens many connections | the budget holds: 2 answers read at a time at `--memory 64M`; connections past `--max-connections` wait | `s9_adversarial::bug_1181_…`, `connections_past_the_cap_wait_for_one_to_close` |
| 14 | Anyone on Earth | fills the in-flight marks (a 70,000-want batch, a 17 MiB object, a client that never reads) | nothing marked that no one can use; coalescing holds for others | `s9_adversarial::bug_1180_…` (both) |
| 15 | Anyone | a batch naming an id twice, through a tree the cache lacks and then held ones; random batches over random caches | the server's answer, byte for byte | `s9_adversarial::bug_1182_…`, `…::the_caches_answers_are_the_servers_byte_for_byte` |
| 16 | An operator's mistake | `--upstream http://…` | refused at start | `cache::tests::an_upstream_that_is_not_https_is_refused` |
| 17 | Anyone on Earth | sends a batch's head and a few bytes of its body, then stops; reads an answer a few bytes at a time | `408` after 20 s, the slot given back (a third client served at 20 s with a cap of 2); writes cut off below 16 KiB/s after a 30 s grace | `s9_cycle2::bug_1183_…`; `cache::deadline::tests::a_client_reading_below_the_minimum_rate_is_cut_off` |
| 18 | Anyone on Earth | 8 batch bodies of 56 MiB that stop before their end | the cache's process grows 9 MiB at `--memory 64M` (466 MiB before) | `s9_cycle2::bug_1184_…` (the cache as its own process) |
| 19 | Anyone on Earth, clients reading normally | many large cold reads at once (four of 10 MiB through a 20 MiB budget; 16 `GET`s and batches of 40 MiB) | every answer completes; a small `GET` afterwards in 5–13 ms (before: 0 of 4 within 60 s, and the cache stuck) | `s9_cycle2::bug_1185_…`, `…::many_large_cold_reads_at_once_all_complete` |
| 20 | Anyone on Earth, given a large public file | reads it from the store slowly (two clients of 15 MiB at 32 KiB/s, above the minimum) | each holds a slice or two of the budget; a `GET` of the root beside them in 8 ms (before: still waiting after 20 s) | `s9_cycle2::bug_1186_…` |

**Residual:** the cache answers a request it can decide faster than one it
forwards, so timing tells whether trees and objects the asker may read are
in its store (that someone recently read a file they may read; design row
14, accepted). A grant voided by an access change is still served from the
store for up to one poll after the change (about a second, at most 5 s: the
owner's bound). Not built: `vl` reading through the
cache (S3), the Veil daemon (S6), the public CDN URLs of design §4.3.

older snapshots, caches, `vl` reading through these routes (S3, S6).

### 13.23 S15: search (built)

Design: `docs/design/server/phase-3-server-history.md` §3.5 and its §13
(as built, with the threat review and the measurements). Code:
`crates/veil-server/src/search/` (`index.rs` builds the index, `segment.rs`
its pieces, `pattern.rs` what a query asks, `mod.rs` the routes), migration
`0016_search.sql`, two routes in `api.rs`, one call after each landing's
derivation (`derive::landing`), and `vl search`. No repository format
change; nothing new is encrypted.

* **Routes** (`/v1/projects/{p}/q/…`, answers carry `policy_version` and
  `work`): `GET search?q=&rev=&kind=&path=&lang=&n=&after=` ranks files by
  their content at a branch tip (`kind=code`, `veil.search/1`) or by name
  over every path the project's history held (`kind=path`);
  `GET grep?pattern=&rev=&i=&path=&n=&after=` lists the lines matching a
  regular expression (linear-time `regex`), file by file in tree order,
  through the index at a branch tip and by a scan of the viewer's tree at
  any other revision (`veil.hub-grep/1`; S16 renders it as `vl grep`).
* **Sharded by access line.** The index is derived data on real history,
  in shards named by S12's line keys: a file's document is in the shard of
  the line deciding its path. A query opens only the shards of the lines
  its viewer reads, so every hit, count, ranking statistic (BM25 over the
  viewer's shards), page and `work` counter is computed from what the
  viewer may read: the same, byte for byte, as on a copy of the project
  holding only their projected history.
* **Secrets** are indexed by path only (their objects are never opened);
  **embargo lines** are never indexed or walked; who reads a line is not
  part of its key, so access changes apply at the next request, and a new
  policy that changes which paths a line decides answers `indexing` (503)
  until the shards whose keys changed are rebuilt.
* **Every branch, always caught up** (BUG-1231): each update also takes
  every branch whose index is behind its tip, and the server resumes them
  at start; an answer from an index still catching up says so (`behind`,
  with `tip_id`, in the viewer's ids).
* **Bounded** (BUG-1230, BUG-1232): candidates are streamed (postings
  intersected as decoded, segments merged in tree order) and a query stops
  at its bound; the deadline is checked inside every loop and before each
  line a grep searches; a line longer than the pattern's size allows is not
  searched (`long_lines_skipped`).
* `vl search WORDS… [--path] [--lang LANG] [-r BRANCH] [-n N] [--json] [-- PATH]`
  prints the server's answer (exit 1 when nothing matched).

### 13.25 S24, part A: rate limits, request bodies under a budget, bulkheads, shedding, health (built)

Design: `docs/design/server/phase-4-agent-scale.md` §4.11, the S24 row of
§8, threat rows 13 and 20; §4.7 here. Code: `crates/veil-server/src/limits/`
(`mod.rs` the middleware, `bucket.rs` token buckets, `body.rs` request
bodies, `gate.rs` bulkheads, `health.rs` the metrics); the listener in
`lib.rs` (`serve`); one route and one layer in `api.rs`; `vl stats`
(`crates/vl/src/stats_cmd.rs`). Everything is in each server's memory: no
database work per request, no migration. The landing-specific parts
(outstanding landings per agent session, a person's fair share of a batch,
landing counters) come with the landing service (S17): it gets its own
class in the gates, buckets keyed by agent session, and its counters in
`health::Counts`.

```text
veil-server … [--device-rate 60/5000] [--anonymous-rate 20/1000]
              [--max-connections 1024] [--request-memory 512M]
vl stats [--json]
GET /v1/projects/{p}/health        (the project's admins)
```

Every request passes through `limits::admit` before any route, in this order:

1. **Who it counts against.** The device of a session this server knows
   (the session cache, memory only), or of a read grant whose signature
   verifies (the object routes: the `Veil-Grant` header, or a batch's
   body); anyone else by address (IPv4, or the IPv6 /64). A bearer token
   this server does not know yet (a restart, an evicted entry, or not a
   session) first takes a token from its **address**, then is looked up
   once as the route would (which caches it for both): made-up tokens reach
   the database no faster than the address's rate.
2. **Rate** (token buckets, `bucket.rs`): a burst of `per_second` refilled
   at that rate, within `per_hour` an hour: devices 60/s and 5,000/h,
   addresses without a session 20/s and 1,000/h. Past it, **`429
   rate_limited`** with `retry_after_ms` (and `Retry-After`): the time until
   the caller's own next token, the same for every project, hidden or not,
   naming nothing. Idle buckets (full ones) are forgotten; a shard keeps at
   most 16,384 keys. The regional caches' epoch feed (by the caches' token)
   counts against nobody.
3. **The body, under a memory budget** (`body.rs`, BUG-1187). Every request
   body is counted, in KiB, against one of two pools of `--request-memory`:
   the signed-in pool, and the anonymous pool (an eighth, at least 4 MiB).
   A body of declared length takes its whole share in one step before any
   byte is read (waiting at most 10 s, else `503 busy`); a chunked one twice
   what it has received, as its buffer grows, and `busy` the moment there is
   no more. **One client (device or address) holds at most a quarter of its
   pool**: an anonymous body is at most a quarter of the anonymous pool
   (16 MiB by default); a signed-in body larger than its quarter (a large
   file's upload, up to the route's 2 GiB) only while its device holds
   nothing else, and it takes at most the whole pool. **A body must arrive
   at 16 KiB/s on average after 20 s** (the cache's rule, BUG-1183), else
   `408` and the connection is closed. The share is held until the answer is
   made.
4. **Bulkheads** (`gate.rs`): a gate per project, then one for the server.
   A project runs at most half of `--db-connections` requests at once (so
   another project always finds a connection), the server twice
   `--db-connections`; names the server does not know yet share one gate
   (made-up names cannot multiply gates), routes of no project another. A
   gate has a queue per class and hands a free place to the **landings
   first** (`push`, `changes`, uploads, every other change), then pulls and
   reads, then **search and grep last**; a request waits at most 10 s, 2 s
   and 250 ms by class, then `503 busy` with `retry_after_ms` (0.5–1.5 s,
   jittered). **Shedding order** (design §4.11): search and grep give up
   first, then **derive work** (a derive run waits while requests wait for
   the server's gate, at most 10 s a run, so derived history lags but always
   progresses), then pulls, and landings last. Gates exist only while a
   request is in or waiting.
5. **The route**, its status and its cache hits (tips, permissions) added
   to its project's counts.

**The listener** (`serve`): at most `--max-connections` (1,024) open, the
next waiting in the listener's queue; **an address opens at most an eighth
of them** (past that a connection is closed at once). The TLS handshake and
a request's head within 20 s, and an idle HTTP/1.1 connection closed after
20 s (BUG-825); **answers** must keep up (the cache's `WriteDeadline`,
BUG-1183): a write pending 30 s closes the connection, and so does one that
brings the time writes waited past 30 s plus a second per 16 KiB written.
HTTP/2 is offered with at most 16 streams, a 256 KiB connection window, a
64 KiB stream window and 32 KiB queued per stream, and pings an idle
connection every 20 s.

**What the server holds, however many requests arrive:** request bodies at
most `--request-memory` (512 MiB), except one signed-in body larger than its
pool, which holds what it is while it is read; per connection, its TLS
records (about 50 KiB in, 16 KiB out), the HTTP/1.1 buffer (128 KiB) or
HTTP/2's windows and queues (at most about 0.8 MiB), so about 200 KiB for
HTTP/1.1 times `--max-connections`: about 0.7 GiB with the defaults,
besides answers being written (bounded in time by the rule above; not by a
budget: BUG-1330) and the server's caches. **Every connection slot comes
back in bounded time:** a handshake or head within 20 s, a body of `n` bytes
within 20 s + `n` / 16 KiB/s, an answer of `n` bytes within 30 s + `n` /
16 KiB/s of a stalled client, a place in a gate within 10 s.

**Health metrics** (`health.rs`): per project, this server's counts since
it started and over the last whole minute: requests, `429`s, `503`s, `408`s,
tips and permission cache hits and misses, and how many branches' derived
history (S12) is not at their tip (read from the database when asked). **For
the project's admins only:** anyone else who can see the project gets
`403`, someone who cannot gets what a project that does not exist gets, and
anyone on Earth `401`. The answer names no person, device, path or other
project. With several servers each counts what it served.

**Threat review** (design §6 rows 13 and 20, plus this milestone's):

| # | Attacker | Tries | Result | Test (`server_hub::limits`, unit tests in `limits/`) |
|---|---|---|---|---|
| 1 | Anyone on Earth, no session | 8 request bodies of 56 MiB that stop before their end (BUG-1187); any number of them | refused past a quarter of the anonymous pool (16 MiB by default); all of them together hold at most the anonymous pool | `bug_1187_request_bodies_are_buffered_without_a_bound_on_how_many` (and 8 signed-in uploads beside: the accounting never past 64 MiB; RSS +23 MiB, before +470 MiB); `body::tests::*` |
| 2 | Anyone on Earth | sends a body slowly, or a head and nothing | `408` after 20 s + `n` / 16 KiB/s, the slot given back | `every_connection_slot_comes_back_in_bounded_time`; `body::tests::a_body_that_stops_is_refused_in_bounded_time` |
| 3 | Anyone on Earth, one address | opens every connection | an eighth of them at most; the next closed at once | `every_connection_slot_comes_back_in_bounded_time` |
| 4 | A signed-in device, or an address | floods requests | `429` past its rate; other devices, on the same address too, are served | `past_its_limits_a_client_is_refused_and_told_when_naming_nothing` |
| 5 | Anyone | made-up session tokens or grants, to get fresh buckets | a token not known here pays its address first; a grant counts for its device only if its signature verifies | same |
| 6 | A refused client | reads its refusal for projects it cannot see, or that do not exist | the same answer, naming nothing but its own wait | same |
| 7 | A runaway agent, or a project's crowd | floods one project | that project runs at most half the connections; another project's p99 stays put (1.1 ms alone, 1.3 ms beside 64 flooding clients) | `a_flooded_project_does_not_starve_a_quiet_one` |
| 8 | — (overload) | more requests than the server can run | search and grep shed first, derive pauses (at most 10 s a run), pulls next, landings last | `gate::tests::landings_are_let_in_first_and_search_last`, `…::search_is_shed_first_and_landings_last`, `limits::tests::derive_work_waits_while_the_server_sheds_but_not_for_ever` |
| 9 | A client that goes away while waiting for a place | (a cancelled wait) | its place is never lost: a place handed over just then is given back | `gate::tests::*` (the `Ticket` drop) |
| 10 | A member, someone outside, anyone on Earth | reads a project's health | `403`, the not-found answer for a hidden project, `401`; an admin's answer counts this project's requests only and names nothing | `health_metrics_are_for_admins_only_and_name_nothing_hidden` |
| 11 | A client within its limits | its burst at once, then 40/s; sign-in from one address | never refused | `a_client_within_its_limits_is_never_refused`; `bucket::tests::a_client_within_its_rate_is_never_refused` |

**Residual, and open:** one signed-in device can hold the signed-in pool with
one slow upload larger than its quarter (accountable; for 20 s + `n` /
16 KiB/s); people behind one address share its anonymous rate and an eighth
of the connections; a regional cache's forwarded requests count against the
cache's address (BUG-1332); answers are bounded in time, not by a memory
budget (BUG-1330); `vl` does not wait out `retry_after_ms` yet (BUG-1331).
